// =============================================================================
// Kernel Zxyphor — Power Management Framework
// =============================================================================
// Centralized power management for the Zxyphor kernel, coordinating:
//   - CPU power states (C-states: C0=active, C1=halt, C2=stop-clock, C3=sleep)
//   - CPU performance states (P-states: frequency/voltage scaling)
//   - Device power states (D0=active, D1/D2=intermediate, D3=off)
//   - System sleep states (S0=working, S3=suspend, S4=hibernate, S5=off)
//   - Thermal management (throttling when temperature exceeds thresholds)
//
// The power manager runs a governor that periodically evaluates system load
// and adjusts power states to balance performance vs. power consumption.
//
// Governors:
//   - Performance: Always run at maximum frequency
//   - Powersave: Always run at minimum frequency
//   - Ondemand: Scale frequency based on CPU utilization
//   - Conservative: Like ondemand but changes frequency more gradually
// =============================================================================

const main = @import("../main.zig");
const cpu = @import("../arch/x86_64/cpu.zig");

// =============================================================================
// CPU power states (C-states)
// =============================================================================

pub const CState = enum(u8) {
    c0_active = 0, // CPU is executing instructions
    c1_halt = 1, // CPU halted (HLT), fastest wake-up
    c1e_enhanced = 2, // Enhanced halt (Intel SpeedStep)
    c2_stop_clock = 3, // Clock stopped, moderate wake latency
    c3_sleep = 4, // Caches flushed, deep sleep
    c6_deep_power_down = 5, // Voltage reduced, longest wake
};

pub const CStateInfo = struct {
    state: CState,
    name: []const u8,
    power_mw: u32, // Power consumption in milliwatts
    latency_us: u32, // Worst-case exit latency in microseconds
    residency_us: u32, // Minimum residency for efficiency
    supported: bool,
};

// Default C-state table (values are architecture-specific)
pub const c_state_table: [6]CStateInfo = .{
    .{ .state = .c0_active, .name = "C0 (Active)", .power_mw = 35000, .latency_us = 0, .residency_us = 0, .supported = true },
    .{ .state = .c1_halt, .name = "C1 (Halt)", .power_mw = 15000, .latency_us = 1, .residency_us = 1, .supported = true },
    .{ .state = .c1e_enhanced, .name = "C1E (Enhanced)", .power_mw = 10000, .latency_us = 10, .residency_us = 20, .supported = true },
    .{ .state = .c2_stop_clock, .name = "C2 (Stop-Clock)", .power_mw = 5000, .latency_us = 100, .residency_us = 500, .supported = true },
    .{ .state = .c3_sleep, .name = "C3 (Sleep)", .power_mw = 1000, .latency_us = 500, .residency_us = 2000, .supported = true },
    .{ .state = .c6_deep_power_down, .name = "C6 (Deep Power Down)", .power_mw = 100, .latency_us = 5000, .residency_us = 20000, .supported = false },
};

// =============================================================================
// CPU performance states (P-states)
// =============================================================================

pub const PState = struct {
    frequency_mhz: u32,
    voltage_mv: u32,
    power_mw: u32,
    index: u8,
};

pub const MAX_P_STATES: usize = 16;

var p_states: [MAX_P_STATES]PState = undefined;
var p_state_count: usize = 0;
var current_p_state: usize = 0;

// =============================================================================
// Power governor
// =============================================================================

pub const Governor = enum(u8) {
    performance = 0,
    powersave = 1,
    ondemand = 2,
    conservative = 3,
};

pub const GovernorInfo = struct {
    governor: Governor,
    name: []const u8,
    description: []const u8,
};

pub const governor_descriptions: [4]GovernorInfo = .{
    .{ .governor = .performance, .name = "performance", .description = "Always run at maximum frequency" },
    .{ .governor = .powersave, .name = "powersave", .description = "Always run at minimum frequency" },
    .{ .governor = .ondemand, .name = "ondemand", .description = "Scale frequency based on CPU load" },
    .{ .governor = .conservative, .name = "conservative", .description = "Gradually scale frequency" },
};

var current_governor: Governor = .ondemand;

// =============================================================================
// Device power management
// =============================================================================

pub const DevicePowerState = enum(u8) {
    d0_active = 0, // Fully operational
    d1_standby = 1, // Device-specific low power
    d2_sleep = 2, // Device-specific lower power
    d3_off = 3, // Device powered off
};

pub const MAX_PM_DEVICES: usize = 64;

pub const PowerManagedDevice = struct {
    name: [32]u8,
    name_len: u8,
    state: DevicePowerState,
    supports_d1: bool,
    supports_d2: bool,
    wake_capable: bool,
    power_mw: [4]u32, // Power for each D-state
    active: bool,
    suspend_fn: ?*const fn () void,
    resume_fn: ?*const fn () void,
};

var pm_devices: [MAX_PM_DEVICES]PowerManagedDevice = undefined;
var pm_device_count: usize = 0;

// =============================================================================
// Thermal management
// =============================================================================

pub const ThermalZone = struct {
    name: [16]u8,
    name_len: u8,
    current_temp_mc: i32, // Current temperature in millidegrees Celsius
    trip_passive_mc: i32, // Passive cooling trip point
    trip_active_mc: i32, // Active cooling trip point (fan)
    trip_critical_mc: i32, // Critical temperature (emergency shutdown)
    throttle_percent: u8, // Current throttle percentage (0 = none, 100 = max)
    active: bool,
};

pub const MAX_THERMAL_ZONES: usize = 8;

var thermal_zones: [MAX_THERMAL_ZONES]ThermalZone = undefined;
var thermal_zone_count: usize = 0;

// =============================================================================
// Power management statistics
// =============================================================================

pub const PowerStats = struct {
    // C-state residency time (ticks)
    c_state_time: [6]u64,
    // Number of C-state transitions
    c_state_transitions: u64,
    // P-state change count
    p_state_changes: u64,
    // Total idle time (ticks)
    total_idle_ticks: u64,
    // Total active time (ticks)
    total_active_ticks: u64,
    // Current CPU utilization (0-100)
    cpu_utilization: u8,
    // Current power estimate (milliwatts)
    estimated_power_mw: u32,
};

var power_stats: PowerStats = std.mem.zeroes(PowerStats);
var pm_initialized: bool = false;

// =============================================================================
// Governor logic
// =============================================================================

/// Evaluate CPU load and adjust P-state according to the current governor
pub fn governorTick(cpu_utilization: u8) void {
    power_stats.cpu_utilization = cpu_utilization;

    switch (current_governor) {
        .performance => {
            // Always max frequency
            if (current_p_state != 0) {
                setPState(0);
            }
        },
        .powersave => {
            // Always min frequency
            if (p_state_count > 0 and current_p_state != p_state_count - 1) {
                setPState(p_state_count - 1);
            }
        },
        .ondemand => {
            // High load → max freq, low load → min freq
            if (cpu_utilization > 80) {
                setPState(0); // Max frequency
            } else if (cpu_utilization < 20) {
                if (p_state_count > 0) setPState(p_state_count - 1); // Min frequency
            }
        },
        .conservative => {
            // Gradually step up/down
            if (cpu_utilization > 75) {
                if (current_p_state > 0) setPState(current_p_state - 1); // Step up
            } else if (cpu_utilization < 25) {
                if (current_p_state + 1 < p_state_count) setPState(current_p_state + 1); // Step down
            }
        },
    }
}

/// Set the CPU performance state
fn setPState(index: usize) void {
    if (index >= p_state_count) return;
    if (index == current_p_state) return;

    // Write MSR to change frequency (architecture-specific)
    // Intel: MSR_IA32_PERF_CTL (0x199)
    // AMD: MSR C001_0062
    const target = p_states[index];
    _ = target;

    // In a real implementation, this would write to the appropriate MSR:
    // cpu.writeMsr(0x199, desired_ratio << 8);

    current_p_state = index;
    power_stats.p_state_changes += 1;
}

// =============================================================================
// Thermal governor
// =============================================================================

/// Check thermal zones and apply throttling if needed
pub fn thermalCheck() void {
    for (0..thermal_zone_count) |i| {
        var zone = &thermal_zones[i];
        if (!zone.active) continue;

        if (zone.current_temp_mc >= zone.trip_critical_mc) {
            // CRITICAL: Emergency shutdown to prevent hardware damage
            main.klog(.emergency, "THERMAL: Critical temperature {d}°C in zone {d}! Emergency shutdown!", .{
                zone.current_temp_mc / 1000,
                i,
            });
            // In a real kernel, this would trigger immediate power-off
            @import("acpi.zig").shutdown();
        } else if (zone.current_temp_mc >= zone.trip_passive_mc) {
            // Passive cooling: throttle CPU
            const excess = zone.current_temp_mc - zone.trip_passive_mc;
            const range = zone.trip_critical_mc - zone.trip_passive_mc;
            if (range > 0) {
                zone.throttle_percent = @truncate(@min(100, @as(u32, @intCast(excess)) * 100 / @as(u32, @intCast(range))));
            }
            main.klog(.warning, "THERMAL: Throttling to {d}% (temp: {d}°C)", .{
                100 - zone.throttle_percent,
                zone.current_temp_mc / 1000,
            });
        } else {
            zone.throttle_percent = 0; // No throttling needed
        }
    }
}

// =============================================================================
// Device power management
// =============================================================================

/// Register a device for power management
pub fn registerDevice(
    name: []const u8,
    supports_d1: bool,
    supports_d2: bool,
    wake_capable: bool,
    suspend_fn: ?*const fn () void,
    resume_fn: ?*const fn () void,
) ?usize {
    if (pm_device_count >= MAX_PM_DEVICES) return null;

    var dev = &pm_devices[pm_device_count];
    const copy_len = @min(name.len, 31);
    @memcpy(dev.name[0..copy_len], name[0..copy_len]);
    dev.name_len = @truncate(copy_len);
    dev.state = .d0_active;
    dev.supports_d1 = supports_d1;
    dev.supports_d2 = supports_d2;
    dev.wake_capable = wake_capable;
    dev.active = true;
    dev.suspend_fn = suspend_fn;
    dev.resume_fn = resume_fn;

    const idx = pm_device_count;
    pm_device_count += 1;
    return idx;
}

/// Suspend a device to a given power state
pub fn suspendDevice(device_id: usize, target_state: DevicePowerState) bool {
    if (device_id >= pm_device_count) return false;

    var dev = &pm_devices[device_id];
    if (!dev.active) return false;

    // Validate that the device supports the target state
    if (target_state == .d1_standby and !dev.supports_d1) return false;
    if (target_state == .d2_sleep and !dev.supports_d2) return false;

    // Call the device's suspend handler
    if (dev.suspend_fn) |sfn| {
        sfn();
    }

    dev.state = target_state;
    return true;
}

/// Resume a device to D0 (active)
pub fn resumeDevice(device_id: usize) bool {
    if (device_id >= pm_device_count) return false;

    var dev = &pm_devices[device_id];
    if (!dev.active) return false;
    if (dev.state == .d0_active) return true; // Already active

    // Call the device's resume handler
    if (dev.resume_fn) |rfn| {
        rfn();
    }

    dev.state = .d0_active;
    return true;
}

/// Suspend all devices (for system sleep)
pub fn suspendAllDevices() void {
    // Suspend in reverse registration order (LIFO)
    var i: usize = pm_device_count;
    while (i > 0) {
        i -= 1;
        if (pm_devices[i].active and pm_devices[i].state == .d0_active) {
            _ = suspendDevice(i, .d3_off);
        }
    }
}

/// Resume all devices (for system wake)
pub fn resumeAllDevices() void {
    // Resume in registration order (FIFO)
    for (0..pm_device_count) |i| {
        if (pm_devices[i].active and pm_devices[i].state != .d0_active) {
            _ = resumeDevice(i);
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Initialize the power management framework
pub fn initialize() void {
    // Initialize P-state table with defaults
    p_states[0] = .{ .frequency_mhz = 3600, .voltage_mv = 1200, .power_mw = 35000, .index = 0 };
    p_states[1] = .{ .frequency_mhz = 3000, .voltage_mv = 1100, .power_mw = 28000, .index = 1 };
    p_states[2] = .{ .frequency_mhz = 2400, .voltage_mv = 1000, .power_mw = 20000, .index = 2 };
    p_states[3] = .{ .frequency_mhz = 1800, .voltage_mv = 900, .power_mw = 14000, .index = 3 };
    p_states[4] = .{ .frequency_mhz = 1200, .voltage_mv = 800, .power_mw = 8000, .index = 4 };
    p_states[5] = .{ .frequency_mhz = 800, .voltage_mv = 700, .power_mw = 5000, .index = 5 };
    p_state_count = 6;
    current_p_state = 0;

    // Initialize thermal zones with defaults
    thermal_zones[0] = .{
        .name = "cpu-thermal\x00\x00\x00\x00\x00".*,
        .name_len = 11,
        .current_temp_mc = 45000, // 45°C
        .trip_passive_mc = 85000, // 85°C
        .trip_active_mc = 75000, // 75°C
        .trip_critical_mc = 105000, // 105°C
        .throttle_percent = 0,
        .active = true,
    };
    thermal_zone_count = 1;

    // Initialize device arrays
    for (&pm_devices) |*dev| {
        dev.* = std.mem.zeroes(PowerManagedDevice);
    }
    pm_device_count = 0;

    power_stats = std.mem.zeroes(PowerStats);
    pm_initialized = true;

    main.klog(.info, "Power management initialized — governor: {s}", .{
        governor_descriptions[@intFromEnum(current_governor)].name,
    });
}

/// Get current governor
pub fn getGovernor() Governor {
    return current_governor;
}

/// Set governor
pub fn setGovernor(gov: Governor) void {
    current_governor = gov;
    main.klog(.info, "Power governor changed to: {s}", .{
        governor_descriptions[@intFromEnum(gov)].name,
    });
}

/// Get power statistics
pub fn getStats() PowerStats {
    return power_stats;
}

/// Check if power management is initialized
pub fn isInitialized() bool {
    return pm_initialized;
}

const std = @import("std");
