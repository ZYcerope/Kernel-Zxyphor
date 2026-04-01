// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Power Supply / Battery / ACPI Power Driver (Zig)
//
// Manages power supply devices (battery, AC adapter, UPS):
// - Battery state machine (charging, discharging, full, not-present)
// - Capacity estimation (coulomb counting, voltage-based)
// - AC adapter detection and switching
// - Thermal throttling integration
// - Power profiles (performance, balanced, powersave)
// - Wake-on-events (WOL, USB, RTC alarm)
// - Suspend/Resume state transitions (S0→S3→S4→S5)
// - ACPI power button / lid switch handling
// - Power budget and constraint management

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_SUPPLIES: usize = 16;
const MAX_NAME_LEN: usize = 32;
const MAX_PROPERTIES: usize = 32;
const MAX_WAKE_SOURCES: usize = 32;
const HISTORY_DEPTH: usize = 64;

// ─────────────────── Supply Type ────────────────────────────────────

pub const SupplyType = enum(u8) {
    battery = 0,
    ups = 1,
    mains_ac = 2,
    usb_charger = 3,
    wireless_charger = 4,
    unknown = 255,
};

// ─────────────────── Battery Status ─────────────────────────────────

pub const BatteryStatus = enum(u8) {
    unknown = 0,
    charging = 1,
    discharging = 2,
    not_charging = 3,
    full = 4,
    critical = 5,
    dead = 6,
};

// ─────────────────── Battery Health ─────────────────────────────────

pub const BatteryHealth = enum(u8) {
    unknown = 0,
    good = 1,
    overheat = 2,
    dead = 3,
    over_voltage = 4,
    unspecified_failure = 5,
    cold = 6,
    watchdog_expired = 7,
    safety_timer_expired = 8,
    overcurrent = 9,
};

// ─────────────────── Battery Technology ─────────────────────────────

pub const BatteryTech = enum(u8) {
    unknown = 0,
    nimh = 1,
    lion = 2,
    lipo = 3,
    life = 4,
    nicd = 5,
    limn = 6,
};

// ─────────────────── Power Profile ──────────────────────────────────

pub const PowerProfile = enum(u8) {
    performance = 0,
    balanced = 1,
    powersave = 2,
    ultra_powersave = 3,
};

// ─────────────────── Sleep State ────────────────────────────────────

pub const SleepState = enum(u8) {
    s0_working = 0,
    s1_standby = 1,    // CPU stops, RAM refreshed
    s2_sleep = 2,       // CPU off, RAM refreshed
    s3_suspend = 3,     // Suspend to RAM
    s4_hibernate = 4,   // Suspend to disk
    s5_off = 5,         // Soft off
    s0ix_idle = 6,      // Modern standby (S0i3)
};

// ─────────────────── Property ───────────────────────────────────────

pub const PropertyId = enum(u8) {
    status = 0,
    health = 1,
    present = 2,
    online = 3,
    technology = 4,
    voltage_now = 5,       // µV
    voltage_min = 6,
    voltage_max = 7,
    current_now = 8,       // µA
    current_max = 9,
    charge_full = 10,      // µAh
    charge_now = 11,
    charge_full_design = 12,
    capacity = 13,         // percent 0-100
    capacity_level = 14,
    temp = 15,             // 0.1°C
    time_to_empty = 16,    // seconds
    time_to_full = 17,
    energy_now = 18,       // µWh
    energy_full = 19,
    energy_full_design = 20,
    power_now = 21,        // µW
    cycle_count = 22,
    serial_number = 23,
    manufacturer = 24,
    model_name = 25,
};

pub const Property = struct {
    id: PropertyId = .status,
    value: i64 = 0,
    valid: bool = false,
};

// ─────────────────── Wake Source ─────────────────────────────────────

pub const WakeSourceType = enum(u8) {
    power_button = 0,
    lid_switch = 1,
    rtc_alarm = 2,
    usb_device = 3,
    network_wol = 4,
    keyboard_device = 5,
    timer = 6,
    gpio_pin = 7,
};

pub const WakeSource = struct {
    src_type: WakeSourceType = .power_button,
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    name_len: u8 = 0,
    enabled: bool = false,
    event_count: u32 = 0,
    active: bool = false,

    pub fn set_name(self: *WakeSource, n: []const u8) void {
        const len = @min(n.len, MAX_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @truncate(len);
    }
};

// ─────────────────── Capacity History ────────────────────────────────

pub const CapacityEntry = struct {
    timestamp: u64 = 0,    // ticks
    capacity: u8 = 0,      // percent
    voltage_mv: u32 = 0,
    current_ma: i32 = 0,
    charging: bool = false,
};

// ─────────────────── Power Supply ────────────────────────────────────

pub const PowerSupply = struct {
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    name_len: u8 = 0,
    supply_type: SupplyType = .unknown,
    properties: [MAX_PROPERTIES]Property = [_]Property{.{}} ** MAX_PROPERTIES,
    prop_count: u8 = 0,
    /// Battery specific
    status: BatteryStatus = .unknown,
    health: BatteryHealth = .unknown,
    technology: BatteryTech = .unknown,
    /// Capacity tracking
    capacity_percent: u8 = 0,
    voltage_uv: u32 = 0,
    current_ua: i32 = 0,
    power_uw: u32 = 0,
    temp_deci_c: i16 = 0,
    charge_full_uah: u32 = 0,
    charge_now_uah: u32 = 0,
    charge_design_uah: u32 = 0,
    energy_full_uwh: u32 = 0,
    energy_now_uwh: u32 = 0,
    cycle_count: u32 = 0,
    /// Capacity history ring buffer
    history: [HISTORY_DEPTH]CapacityEntry = [_]CapacityEntry{.{}} ** HISTORY_DEPTH,
    history_head: u8 = 0,
    history_count: u8 = 0,
    /// State
    present: bool = false,
    active: bool = false,
    /// Stats
    charge_cycles_total: u32 = 0,
    last_update_tick: u64 = 0,

    pub fn set_name(self: *PowerSupply, n: []const u8) void {
        const len = @min(n.len, MAX_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @truncate(len);
    }

    pub fn add_property(self: *PowerSupply, id: PropertyId, value: i64) bool {
        // Update existing
        for (0..self.prop_count) |i| {
            if (self.properties[i].id == id) {
                self.properties[i].value = value;
                self.properties[i].valid = true;
                return true;
            }
        }
        if (self.prop_count >= MAX_PROPERTIES) return false;
        self.properties[self.prop_count] = .{ .id = id, .value = value, .valid = true };
        self.prop_count += 1;
        return true;
    }

    pub fn get_property(self: *const PowerSupply, id: PropertyId) ?i64 {
        for (0..self.prop_count) |i| {
            if (self.properties[i].id == id and self.properties[i].valid) {
                return self.properties[i].value;
            }
        }
        return null;
    }

    pub fn record_capacity(self: *PowerSupply, tick: u64) void {
        const idx = self.history_head;
        self.history[idx] = .{
            .timestamp = tick,
            .capacity = self.capacity_percent,
            .voltage_mv = self.voltage_uv / 1000,
            .current_ma = @divTrunc(self.current_ua, 1000),
            .charging = self.status == .charging,
        };
        self.history_head = @truncate((@as(u16, self.history_head) + 1) % HISTORY_DEPTH);
        if (self.history_count < HISTORY_DEPTH) self.history_count += 1;
    }

    /// Estimate time to empty in seconds using coulomb counting
    pub fn estimate_time_to_empty(self: *const PowerSupply) ?u32 {
        if (self.current_ua >= 0) return null; // Not discharging
        if (self.charge_now_uah == 0) return null;
        const discharge_ua: u64 = @intCast(-self.current_ua);
        if (discharge_ua == 0) return null;
        // time_s = (charge_uah * 3600) / discharge_ua
        return @truncate((self.charge_now_uah * 3600) / discharge_ua);
    }

    /// Estimate time to full in seconds
    pub fn estimate_time_to_full(self: *const PowerSupply) ?u32 {
        if (self.current_ua <= 0) return null; // Not charging
        if (self.charge_full_uah <= self.charge_now_uah) return null;
        const remaining = self.charge_full_uah - self.charge_now_uah;
        const charge_ua: u64 = @intCast(self.current_ua);
        if (charge_ua == 0) return null;
        return @truncate((remaining * 3600) / charge_ua);
    }

    /// Update capacity based on voltage curve (simplified LiON)
    pub fn update_capacity_from_voltage(self: *PowerSupply) void {
        const mv = self.voltage_uv / 1000;
        self.capacity_percent = if (mv >= 4200) 100
            else if (mv >= 4100) 90
            else if (mv >= 4000) 80
            else if (mv >= 3900) 70
            else if (mv >= 3800) 55
            else if (mv >= 3700) 40
            else if (mv >= 3600) 25
            else if (mv >= 3500) 15
            else if (mv >= 3400) 8
            else if (mv >= 3300) 3
            else 0;
    }

    /// Update battery health assessment
    pub fn assess_health(self: *PowerSupply) void {
        if (self.temp_deci_c > 600) {
            self.health = .overheat;
        } else if (self.temp_deci_c < -100) {
            self.health = .cold;
        } else if (self.voltage_uv > 4300_000) {
            self.health = .over_voltage;
        } else if (self.charge_full_uah > 0 and self.charge_design_uah > 0) {
            const health_pct = (self.charge_full_uah * 100) / self.charge_design_uah;
            if (health_pct < 30) {
                self.health = .dead;
            } else {
                self.health = .good;
            }
        } else {
            self.health = .unknown;
        }
    }
};

// ─────────────────── Thermal Zone ────────────────────────────────────

pub const ThermalZone = struct {
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    name_len: u8 = 0,
    temp_milli_c: i32 = 0,       // millidegrees Celsius
    trip_passive: i32 = 85000,   // passive cooling trip
    trip_critical: i32 = 105000, // critical shutdown
    trip_hot: i32 = 95000,       // throttle aggressively
    cooling_state: u8 = 0,       // 0=off, 255=max
    active: bool = false,

    pub fn update_temp(self: *ThermalZone, temp: i32) void {
        self.temp_milli_c = temp;
        if (temp >= self.trip_critical) {
            self.cooling_state = 255; // Emergency
        } else if (temp >= self.trip_hot) {
            self.cooling_state = 200;
        } else if (temp >= self.trip_passive) {
            const above = temp - self.trip_passive;
            const range = self.trip_hot - self.trip_passive;
            if (range > 0) {
                self.cooling_state = @truncate(@min((@as(u64, @intCast(above)) * 200) / @as(u64, @intCast(range)), 200));
            }
        } else {
            self.cooling_state = 0;
        }
    }

    pub fn is_critical(self: *const ThermalZone) bool {
        return self.temp_milli_c >= self.trip_critical;
    }
};

// ─────────────────── Power Manager ──────────────────────────────────

pub const PowerManager = struct {
    supplies: [MAX_SUPPLIES]PowerSupply = undefined,
    supply_count: u8 = 0,
    wake_sources: [MAX_WAKE_SOURCES]WakeSource = [_]WakeSource{.{}} ** MAX_WAKE_SOURCES,
    wake_count: u8 = 0,
    thermal: [4]ThermalZone = [_]ThermalZone{.{}} ** 4,
    thermal_count: u8 = 0,
    /// System state
    current_state: SleepState = .s0_working,
    target_state: SleepState = .s0_working,
    profile: PowerProfile = .balanced,
    /// AC power
    ac_online: bool = false,
    lid_open: bool = true,
    power_button_pressed: bool = false,
    /// Constraints
    max_power_uw: u64 = 0,         // power budget
    current_power_uw: u64 = 0,
    /// Stats
    suspend_count: u32 = 0,
    resume_count: u32 = 0,
    ac_transitions: u32 = 0,
    total_ticks: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *PowerManager) void {
        for (0..MAX_SUPPLIES) |i| {
            self.supplies[i] = PowerSupply{};
        }

        // Default wake sources
        _ = self.add_wake_source(.power_button, "PWRB", true);
        _ = self.add_wake_source(.lid_switch, "LID0", true);
        _ = self.add_wake_source(.rtc_alarm, "RTC0", false);
        _ = self.add_wake_source(.network_wol, "ETH0", false);

        self.initialized = true;
    }

    pub fn register_supply(self: *PowerManager, name: []const u8, stype: SupplyType) ?u8 {
        if (self.supply_count >= MAX_SUPPLIES) return null;
        const idx = self.supply_count;
        self.supplies[idx] = PowerSupply{};
        self.supplies[idx].set_name(name);
        self.supplies[idx].supply_type = stype;
        self.supplies[idx].active = true;
        self.supply_count += 1;
        return idx;
    }

    pub fn unregister_supply(self: *PowerManager, idx: u8) bool {
        if (idx >= MAX_SUPPLIES) return false;
        if (!self.supplies[idx].active) return false;
        self.supplies[idx].active = false;
        return true;
    }

    pub fn update_battery(
        self: *PowerManager,
        idx: u8,
        voltage_uv: u32,
        current_ua: i32,
        charge_now: u32,
        temp_dc: i16,
    ) void {
        if (idx >= MAX_SUPPLIES or !self.supplies[idx].active) return;
        var bat = &self.supplies[idx];
        bat.voltage_uv = voltage_uv;
        bat.current_ua = current_ua;
        bat.charge_now_uah = charge_now;
        bat.temp_deci_c = temp_dc;

        // Derive status
        if (current_ua > 0) {
            bat.status = .charging;
        } else if (current_ua < 0) {
            if (bat.capacity_percent <= 5) {
                bat.status = .critical;
            } else {
                bat.status = .discharging;
            }
        } else {
            if (bat.capacity_percent >= 98) {
                bat.status = .full;
            } else {
                bat.status = .not_charging;
            }
        }

        // Calculate capacity
        if (bat.charge_full_uah > 0) {
            bat.capacity_percent = @truncate((charge_now * 100) / bat.charge_full_uah);
        } else {
            bat.update_capacity_from_voltage();
        }

        // Power
        if (current_ua < 0) {
            bat.power_uw = @as(u32, @intCast(-current_ua)) * (voltage_uv / 1_000_000);
        } else {
            bat.power_uw = @as(u32, @intCast(current_ua)) * (voltage_uv / 1_000_000);
        }

        bat.assess_health();
        bat.record_capacity(self.total_ticks);
        bat.last_update_tick = self.total_ticks;
    }

    pub fn set_ac_online(self: *PowerManager, online: bool) void {
        if (self.ac_online != online) {
            self.ac_online = online;
            self.ac_transitions += 1;
        }
    }

    pub fn add_wake_source(self: *PowerManager, src_type: WakeSourceType, name: []const u8, enabled: bool) ?u8 {
        if (self.wake_count >= MAX_WAKE_SOURCES) return null;
        const idx = self.wake_count;
        self.wake_sources[idx].src_type = src_type;
        self.wake_sources[idx].set_name(name);
        self.wake_sources[idx].enabled = enabled;
        self.wake_sources[idx].active = true;
        self.wake_count += 1;
        return idx;
    }

    pub fn enable_wake_source(self: *PowerManager, idx: u8, enable: bool) void {
        if (idx < self.wake_count) {
            self.wake_sources[idx].enabled = enable;
        }
    }

    pub fn add_thermal_zone(self: *PowerManager, name: []const u8, passive: i32, critical: i32) ?u8 {
        if (self.thermal_count >= 4) return null;
        const idx = self.thermal_count;
        const len = @min(name.len, MAX_NAME_LEN - 1);
        @memcpy(self.thermal[idx].name[0..len], name[0..len]);
        self.thermal[idx].name_len = @truncate(len);
        self.thermal[idx].trip_passive = passive;
        self.thermal[idx].trip_critical = critical;
        self.thermal[idx].active = true;
        self.thermal_count += 1;
        return idx;
    }

    /// Request sleep state transition
    pub fn request_suspend(self: *PowerManager, state: SleepState) bool {
        if (self.current_state != .s0_working) return false;

        // Check if any thermal zone critical
        for (0..self.thermal_count) |i| {
            if (self.thermal[i].is_critical()) return false;
        }

        self.target_state = state;
        // Freeze processes, sync filesystems... (would call scheduler)

        self.current_state = state;
        self.suspend_count += 1;
        return true;
    }

    /// Resume from sleep
    pub fn resume(self: *PowerManager) void {
        if (self.current_state == .s0_working) return;
        self.current_state = .s0_working;
        self.target_state = .s0_working;
        self.resume_count += 1;
    }

    pub fn set_profile(self: *PowerManager, profile: PowerProfile) void {
        self.profile = profile;
    }

    pub fn handle_power_button(self: *PowerManager) void {
        self.power_button_pressed = true;
        if (self.current_state == .s0_working) {
            _ = self.request_suspend(.s3_suspend);
        } else {
            self.resume();
        }
    }

    pub fn handle_lid_switch(self: *PowerManager, open: bool) void {
        self.lid_open = open;
        if (!open and self.current_state == .s0_working) {
            _ = self.request_suspend(.s3_suspend);
        } else if (open and self.current_state != .s0_working) {
            self.resume();
        }
    }

    pub fn tick(self: *PowerManager) void {
        self.total_ticks += 1;

        // Update thermal zones cooling
        for (0..self.thermal_count) |i| {
            if (self.thermal[i].is_critical()) {
                // Would trigger emergency shutdown
            }
        }
    }

    pub fn total_capacity_percent(self: *const PowerManager) u8 {
        var total: u32 = 0;
        var count: u32 = 0;
        for (0..self.supply_count) |i| {
            if (self.supplies[i].active and self.supplies[i].supply_type == .battery and self.supplies[i].present) {
                total += self.supplies[i].capacity_percent;
                count += 1;
            }
        }
        if (count == 0) return 0;
        return @truncate(total / count);
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var power_mgr = PowerManager{};

pub fn get_power_manager() *PowerManager {
    return &power_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_power_init() void {
    power_mgr.init();
}

export fn zxy_power_register_supply(name_ptr: [*]const u8, name_len: u32, stype: u8) i32 {
    if (name_len == 0 or name_len > 31) return -1;
    const name = name_ptr[0..name_len];
    const supply_type: SupplyType = @enumFromInt(stype);
    return if (power_mgr.register_supply(name, supply_type)) |idx| @as(i32, idx) else -1;
}

export fn zxy_power_supply_count() u8 {
    return power_mgr.supply_count;
}

export fn zxy_power_ac_online() bool {
    return power_mgr.ac_online;
}

export fn zxy_power_suspend(state: u8) bool {
    const sleep_state: SleepState = @enumFromInt(state);
    return power_mgr.request_suspend(sleep_state);
}

export fn zxy_power_resume() void {
    power_mgr.resume();
}

export fn zxy_power_profile_set(profile: u8) void {
    const p: PowerProfile = @enumFromInt(profile);
    power_mgr.set_profile(p);
}

export fn zxy_power_total_capacity() u8 {
    return power_mgr.total_capacity_percent();
}

export fn zxy_power_suspend_count() u32 {
    return power_mgr.suspend_count;
}

export fn zxy_power_thermal_count() u8 {
    return power_mgr.thermal_count;
}

export fn zxy_power_tick() void {
    power_mgr.tick();
}
