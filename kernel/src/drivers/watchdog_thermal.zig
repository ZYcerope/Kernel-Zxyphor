// =============================================================================
// Kernel Zxyphor — Watchdog + Thermal Zone Management
// =============================================================================
// Hardware watchdog:
//   - Intel TCO, iTCO compatible WDT
//   - Configurable timeout and pretimeout
//   - NMI-based pretimeout notification
//   - Magic close (write 'V' to disable)
//   - Identity registration
// Thermal zones:
//   - Multiple thermal zones with trip points
//   - Cooling devices (fans, CPU freq throttle, passive)
//   - Governor policies (step_wise, bang_bang, user_space, power_allocator)
//   - Hysteresis on trip points
//   - Critical / hot / passive / active trip types
//   - ACPI thermal zone integration
//   - Emergency shutdown on critical overheat
// =============================================================================

const std = @import("std");

// ===== WATCHDOG =====

pub const WatchdogStatus = enum(u8) {
    stopped,
    running,
    expired,
    disabled,
};

pub const WatchdogAction = enum(u8) {
    reset,    // System reset
    nmi,      // Non-maskable interrupt
    panic,    // Kernel panic
    poweroff, // Power off
};

pub const WDIOF_SETTIMEOUT: u32 = 0x0080;
pub const WDIOF_KEEPALIVEPING: u32 = 0x8000;
pub const WDIOF_MAGICCLOSE: u32 = 0x0100;
pub const WDIOF_PRETIMEOUT: u32 = 0x0200;
pub const WDIOF_ALARMONLY: u32 = 0x0400;

pub const WatchdogInfo = struct {
    identity: [32]u8,
    identity_len: u8,
    firmware_version: u32,
    options: u32,

    pub fn init() WatchdogInfo {
        return WatchdogInfo{
            .identity = [_]u8{0} ** 32,
            .identity_len = 0,
            .firmware_version = 0,
            .options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
        };
    }

    pub fn setIdentity(self: *WatchdogInfo, name: []const u8) void {
        const len = @min(name.len, 31);
        for (0..len) |i| {
            self.identity[i] = name[i];
        }
        self.identity_len = @intCast(len);
    }
};

pub const WatchdogDevice = struct {
    id: u8,
    info: WatchdogInfo,
    status: WatchdogStatus,
    timeout_sec: u32,
    pretimeout_sec: u32,
    min_timeout: u32,
    max_timeout: u32,
    last_keepalive: u64, // tick counter at last ping
    boot_status: u32,
    action: WatchdogAction,
    nowayout: bool,       // once started, can't stop
    magic_close: bool,    // 'V' written, allow close
    active: bool,

    // Hardware registers (MMIO or PIO)
    base_addr: u64,
    io_type: enum(u2) { mmio, pio, none },

    pub fn init() WatchdogDevice {
        return WatchdogDevice{
            .id = 0,
            .info = WatchdogInfo.init(),
            .status = .stopped,
            .timeout_sec = 60,
            .pretimeout_sec = 0,
            .min_timeout = 1,
            .max_timeout = 65535,
            .last_keepalive = 0,
            .boot_status = 0,
            .action = .reset,
            .nowayout = false,
            .magic_close = false,
            .active = false,
            .base_addr = 0,
            .io_type = .none,
        };
    }

    pub fn start(self: *WatchdogDevice, current_tick: u64) bool {
        if (self.status == .disabled) return false;
        self.status = .running;
        self.last_keepalive = current_tick;
        self.magic_close = false;
        // Program hardware timeout
        self.programHardware();
        return true;
    }

    pub fn stop(self: *WatchdogDevice) bool {
        if (self.nowayout and !self.magic_close) return false;
        self.status = .stopped;
        self.disableHardware();
        return true;
    }

    pub fn ping(self: *WatchdogDevice, current_tick: u64) void {
        if (self.status != .running) return;
        self.last_keepalive = current_tick;
        self.reloadHardware();
    }

    pub fn setTimeout(self: *WatchdogDevice, secs: u32) bool {
        if (secs < self.min_timeout or secs > self.max_timeout) return false;
        self.timeout_sec = secs;
        if (self.status == .running) self.programHardware();
        return true;
    }

    pub fn setPretimeout(self: *WatchdogDevice, secs: u32) bool {
        if (secs >= self.timeout_sec) return false;
        self.pretimeout_sec = secs;
        return true;
    }

    /// Check for expiry (called from timer interrupt)
    pub fn tick(self: *WatchdogDevice, current_tick: u64, ticks_per_sec: u64) void {
        if (self.status != .running) return;

        const elapsed = current_tick -| self.last_keepalive;
        const elapsed_sec = elapsed / ticks_per_sec;

        // Check pretimeout
        if (self.pretimeout_sec > 0) {
            const pre_threshold = self.timeout_sec - self.pretimeout_sec;
            if (elapsed_sec >= pre_threshold and elapsed_sec < self.timeout_sec) {
                // Issue NMI pretimeout notification
                self.pretimeoutNotify();
            }
        }

        // Check full timeout
        if (elapsed_sec >= self.timeout_sec) {
            self.status = .expired;
            self.handleExpiry();
        }
    }

    fn pretimeoutNotify(_: *WatchdogDevice) void {
        // In real hardware: trigger NMI or pretimeout interrupt
        // Placeholder for kernel panic traceback before reset
    }

    fn handleExpiry(self: *WatchdogDevice) void {
        switch (self.action) {
            .reset => {
                // Triple fault or ACPI reset
                if (self.base_addr != 0 and self.io_type == .mmio) {
                    const ptr: *volatile u32 = @ptrFromInt(self.base_addr);
                    ptr.* = 0x01; // trigger reset
                }
            },
            .nmi => {},      // Trigger NMI via APIC
            .panic => {},    // Call kernel panic
            .poweroff => {}, // ACPI poweroff
        }
    }

    fn programHardware(self: *WatchdogDevice) void {
        if (self.base_addr == 0) return;
        switch (self.io_type) {
            .mmio => {
                // TCO timer: write timeout value to reload register
                const reload: *volatile u32 = @ptrFromInt(self.base_addr + 0x00);
                const ctrl: *volatile u32 = @ptrFromInt(self.base_addr + 0x08);
                reload.* = self.timeout_sec;
                ctrl.* = ctrl.* | 0x01; // enable
            },
            .pio => {
                // Port-mapped IO variant
            },
            .none => {},
        }
    }

    fn reloadHardware(self: *WatchdogDevice) void {
        if (self.base_addr == 0) return;
        if (self.io_type == .mmio) {
            const reload: *volatile u32 = @ptrFromInt(self.base_addr + 0x00);
            reload.* = self.timeout_sec;
        }
    }

    fn disableHardware(self: *WatchdogDevice) void {
        if (self.base_addr == 0) return;
        if (self.io_type == .mmio) {
            const ctrl: *volatile u32 = @ptrFromInt(self.base_addr + 0x08);
            ctrl.* = ctrl.* & ~@as(u32, 0x01); // disable
        }
    }
};

// ===== THERMAL ======

pub const TripType = enum(u8) {
    active,
    passive,
    hot,
    critical,
};

pub const GovernorType = enum(u8) {
    step_wise,
    bang_bang,
    user_space,
    power_allocator,
};

pub const CoolingType = enum(u8) {
    fan,
    processor,  // CPU frequency throttling
    passive,    // Reduce performance
    active,     // Active cooling (fan etc)
    device,     // Device-specific
};

pub const MAX_TRIP_POINTS = 8;
pub const MAX_COOLING_DEVICES = 8;
pub const MAX_THERMAL_ZONES = 16;

pub const TripPoint = struct {
    type_: TripType,
    temp_millic: i32,     // millidegrees Celsius
    hysteresis: i32,      // millidegrees hysteresis
    active: bool,
    fired: bool,          // currently tripped
    cooling_device: u8,   // preferred cooling device index
    cooling_level: u8,    // target cooling level

    pub fn init() TripPoint {
        return TripPoint{
            .type_ = .active,
            .temp_millic = 0,
            .hysteresis = 2000, // 2°C default
            .active = false,
            .fired = false,
            .cooling_device = 0xFF,
            .cooling_level = 0,
        };
    }

    /// Check if trip point should fire (with hysteresis)
    pub fn shouldFire(self: *const TripPoint, current_temp: i32) bool {
        if (self.fired) {
            // Already fired: clear only when below (trip - hysteresis)
            return current_temp >= (self.temp_millic - self.hysteresis);
        } else {
            return current_temp >= self.temp_millic;
        }
    }
};

pub const CoolingDevice = struct {
    id: u8,
    type_: CoolingType,
    name: [32]u8,
    name_len: u8,
    max_state: u8,
    current_state: u8,
    active: bool,

    // For fan-type
    rpm_min: u16,
    rpm_max: u16,
    rpm_current: u16,

    // For processor-type
    freq_min_mhz: u32,
    freq_max_mhz: u32,
    freq_current_mhz: u32,

    pub fn init() CoolingDevice {
        return CoolingDevice{
            .id = 0,
            .type_ = .fan,
            .name = [_]u8{0} ** 32,
            .name_len = 0,
            .max_state = 10,
            .current_state = 0,
            .active = false,
            .rpm_min = 0,
            .rpm_max = 5000,
            .rpm_current = 0,
            .freq_min_mhz = 800,
            .freq_max_mhz = 4000,
            .freq_current_mhz = 4000,
        };
    }

    pub fn setName(self: *CoolingDevice, n: []const u8) void {
        const len = @min(n.len, 31);
        for (0..len) |i| self.name[i] = n[i];
        self.name_len = @intCast(len);
    }

    pub fn setState(self: *CoolingDevice, state: u8) bool {
        if (state > self.max_state) return false;
        self.current_state = state;
        self.applyCooling();
        return true;
    }

    fn applyCooling(self: *CoolingDevice) void {
        switch (self.type_) {
            .fan, .active => {
                if (self.max_state == 0) return;
                const range = self.rpm_max - self.rpm_min;
                self.rpm_current = self.rpm_min + @as(u16, @intCast(
                    (@as(u32, range) * @as(u32, self.current_state)) / @as(u32, self.max_state)
                ));
            },
            .processor, .passive => {
                if (self.max_state == 0) return;
                const range = self.freq_max_mhz - self.freq_min_mhz;
                // Higher cooling state = lower frequency
                const reduction = (range * @as(u32, self.current_state)) / @as(u32, self.max_state);
                self.freq_current_mhz = self.freq_max_mhz - reduction;
            },
            .device => {},
        }
    }
};

pub const ThermalZone = struct {
    id: u8,
    name: [32]u8,
    name_len: u8,
    enabled: bool,
    governor: GovernorType,

    // Temperature readings (millidegrees C)
    temp_current: i32,
    temp_last: i32,
    temp_trend: i32, // positive = heating, negative = cooling

    // Trip points
    trips: [MAX_TRIP_POINTS]TripPoint,
    trip_count: u8,

    // Bound cooling devices
    cooling_bindings: [MAX_TRIP_POINTS]u8, // cooling device index per trip

    // Statistics
    polling_delay_ms: u32,
    passive_delay_ms: u32,
    last_update_tick: u64,
    trip_violations: u64,

    // Power allocator governor params
    sustainable_power_mw: u32,
    k_p: i32,  // PID proportional
    k_i: i32,  // PID integral
    k_d: i32,  // PID derivative
    integral_term: i64,

    pub fn init() ThermalZone {
        return ThermalZone{
            .id = 0,
            .name = [_]u8{0} ** 32,
            .name_len = 0,
            .enabled = false,
            .governor = .step_wise,
            .temp_current = 25000, // 25°C
            .temp_last = 25000,
            .temp_trend = 0,
            .trips = [_]TripPoint{TripPoint.init()} ** MAX_TRIP_POINTS,
            .trip_count = 0,
            .cooling_bindings = [_]u8{0xFF} ** MAX_TRIP_POINTS,
            .polling_delay_ms = 1000,
            .passive_delay_ms = 250,
            .last_update_tick = 0,
            .trip_violations = 0,
            .sustainable_power_mw = 10000,
            .k_p = 1000,
            .k_i = 50,
            .k_d = 200,
            .integral_term = 0,
        };
    }

    pub fn setName(self: *ThermalZone, n: []const u8) void {
        const len = @min(n.len, 31);
        for (0..len) |i| self.name[i] = n[i];
        self.name_len = @intCast(len);
    }

    pub fn addTrip(self: *ThermalZone, trip_type: TripType, temp_mc: i32, hyst: i32) ?u8 {
        if (self.trip_count >= MAX_TRIP_POINTS) return null;
        const idx = self.trip_count;
        self.trips[idx] = TripPoint.init();
        self.trips[idx].type_ = trip_type;
        self.trips[idx].temp_millic = temp_mc;
        self.trips[idx].hysteresis = hyst;
        self.trips[idx].active = true;
        self.trip_count += 1;
        return idx;
    }

    pub fn bindCooling(self: *ThermalZone, trip_idx: u8, cooling_id: u8) void {
        if (trip_idx >= MAX_TRIP_POINTS) return;
        self.cooling_bindings[trip_idx] = cooling_id;
        self.trips[trip_idx].cooling_device = cooling_id;
    }

    /// Update temperature reading and run governor
    pub fn update(self: *ThermalZone, new_temp: i32, cooling_devices: []CoolingDevice) void {
        if (!self.enabled) return;

        self.temp_last = self.temp_current;
        self.temp_current = new_temp;
        self.temp_trend = new_temp - self.temp_last;

        // Evaluate trip points
        for (0..self.trip_count) |i| {
            const was_fired = self.trips[i].fired;
            const should_fire = self.trips[i].shouldFire(new_temp);
            self.trips[i].fired = should_fire;

            if (should_fire and !was_fired) {
                self.trip_violations += 1;
                self.handleTripFired(@intCast(i), cooling_devices);
            } else if (!should_fire and was_fired) {
                self.handleTripCleared(@intCast(i), cooling_devices);
            }
        }

        // Run governor for ongoing management
        self.runGovernor(cooling_devices);
    }

    fn handleTripFired(self: *ThermalZone, trip_idx: u8, cooling_devices: []CoolingDevice) void {
        if (trip_idx >= self.trip_count) return;
        const trip = &self.trips[trip_idx];

        switch (trip.type_) {
            .critical => {
                // Emergency shutdown
                _ = self;
                // In real kernel: initiate orderly poweroff
            },
            .hot => {
                // Throttle to maximum
                if (trip.cooling_device < cooling_devices.len) {
                    _ = cooling_devices[trip.cooling_device].setState(
                        cooling_devices[trip.cooling_device].max_state
                    );
                }
            },
            .passive => {
                // Gradual throttling
                if (trip.cooling_device < cooling_devices.len) {
                    const cd = &cooling_devices[trip.cooling_device];
                    const new_state = @min(cd.current_state + 1, cd.max_state);
                    _ = cd.setState(new_state);
                }
            },
            .active => {
                // Activate cooling (e.g., turn on fan)
                if (trip.cooling_device < cooling_devices.len) {
                    const level = trip.cooling_level;
                    _ = cooling_devices[trip.cooling_device].setState(level);
                }
            },
        }
    }

    fn handleTripCleared(self: *ThermalZone, trip_idx: u8, cooling_devices: []CoolingDevice) void {
        if (trip_idx >= self.trip_count) return;
        const trip = &self.trips[trip_idx];

        switch (trip.type_) {
            .active => {
                // Potentially reduce cooling
                if (trip.cooling_device < cooling_devices.len) {
                    const cd = &cooling_devices[trip.cooling_device];
                    if (cd.current_state > 0) {
                        _ = cd.setState(cd.current_state - 1);
                    }
                }
            },
            .passive => {
                if (trip.cooling_device < cooling_devices.len) {
                    const cd = &cooling_devices[trip.cooling_device];
                    if (cd.current_state > 0) {
                        _ = cd.setState(cd.current_state - 1);
                    }
                }
            },
            else => {},
        }
        _ = self;
    }

    fn runGovernor(self: *ThermalZone, cooling_devices: []CoolingDevice) void {
        switch (self.governor) {
            .step_wise => self.governorStepWise(cooling_devices),
            .bang_bang => self.governorBangBang(cooling_devices),
            .power_allocator => self.governorPowerAllocator(cooling_devices),
            .user_space => {}, // Userspace controls
        }
    }

    fn governorStepWise(self: *ThermalZone, cooling_devices: []CoolingDevice) void {
        // Gradually increase/decrease cooling based on trend
        for (0..self.trip_count) |i| {
            if (!self.trips[i].fired) continue;
            const cd_idx = self.cooling_bindings[i];
            if (cd_idx == 0xFF or cd_idx >= cooling_devices.len) continue;

            const cd = &cooling_devices[cd_idx];
            if (self.temp_trend > 0 and cd.current_state < cd.max_state) {
                _ = cd.setState(cd.current_state + 1);
            } else if (self.temp_trend < -1000 and cd.current_state > 0) {
                _ = cd.setState(cd.current_state - 1);
            }
        }
    }

    fn governorBangBang(self: *ThermalZone, cooling_devices: []CoolingDevice) void {
        // On/off: full cooling when hot, off when cool
        for (0..self.trip_count) |i| {
            const cd_idx = self.cooling_bindings[i];
            if (cd_idx == 0xFF or cd_idx >= cooling_devices.len) continue;

            const cd = &cooling_devices[cd_idx];
            if (self.trips[i].fired) {
                _ = cd.setState(cd.max_state);
            } else {
                _ = cd.setState(0);
            }
        }
    }

    fn governorPowerAllocator(self: *ThermalZone, cooling_devices: []CoolingDevice) void {
        // PID-based power allocation
        if (self.trip_count == 0) return;

        // Find passive trip as setpoint
        var setpoint: i32 = 80000; // default 80°C
        for (0..self.trip_count) |i| {
            if (self.trips[i].type_ == .passive) {
                setpoint = self.trips[i].temp_millic;
                break;
            }
        }

        const error_val = setpoint - self.temp_current;
        self.integral_term += @as(i64, error_val);

        // Clamp integral
        const max_integral: i64 = 1000000;
        if (self.integral_term > max_integral) self.integral_term = max_integral;
        if (self.integral_term < -max_integral) self.integral_term = -max_integral;

        const p = @as(i64, self.k_p) * @as(i64, error_val);
        const i_term = @as(i64, self.k_i) * self.integral_term;
        const d = @as(i64, self.k_d) * @as(i64, self.temp_trend);
        const output = (p + i_term - d) / 1000;

        // Map PID output to cooling state
        for (0..self.trip_count) |ti| {
            const cd_idx = self.cooling_bindings[ti];
            if (cd_idx == 0xFF or cd_idx >= cooling_devices.len) continue;

            const cd = &cooling_devices[cd_idx];
            if (output < 0) {
                // Cool: increase cooling
                const level: u8 = @intCast(@min(
                    @as(u64, @intCast(@max(-output, 0))) * @as(u64, cd.max_state) / 100000,
                    cd.max_state,
                ));
                _ = cd.setState(level);
            } else {
                // Warm enough: reduce cooling
                if (cd.current_state > 0) {
                    _ = cd.setState(cd.current_state -| 1);
                }
            }
        }
    }
};

// ===== SUBSYSTEM =====

pub const ThermalSubsystem = struct {
    zones: [MAX_THERMAL_ZONES]ThermalZone,
    zone_count: u8,
    cooling_devices: [MAX_COOLING_DEVICES]CoolingDevice,
    cooling_count: u8,
    watchdogs: [4]WatchdogDevice,
    watchdog_count: u8,

    pub fn init() ThermalSubsystem {
        return ThermalSubsystem{
            .zones = [_]ThermalZone{ThermalZone.init()} ** MAX_THERMAL_ZONES,
            .zone_count = 0,
            .cooling_devices = [_]CoolingDevice{CoolingDevice.init()} ** MAX_COOLING_DEVICES,
            .cooling_count = 0,
            .watchdogs = [_]WatchdogDevice{WatchdogDevice.init()} ** 4,
            .watchdog_count = 0,
        };
    }

    // Zone management
    pub fn registerZone(self: *ThermalSubsystem, name: []const u8) ?u8 {
        if (self.zone_count >= MAX_THERMAL_ZONES) return null;
        const id = self.zone_count;
        self.zones[id] = ThermalZone.init();
        self.zones[id].id = id;
        self.zones[id].setName(name);
        self.zones[id].enabled = true;
        self.zone_count += 1;
        return id;
    }

    pub fn registerCooling(self: *ThermalSubsystem, name: []const u8, ctype: CoolingType) ?u8 {
        if (self.cooling_count >= MAX_COOLING_DEVICES) return null;
        const id = self.cooling_count;
        self.cooling_devices[id] = CoolingDevice.init();
        self.cooling_devices[id].id = id;
        self.cooling_devices[id].setName(name);
        self.cooling_devices[id].type_ = ctype;
        self.cooling_devices[id].active = true;
        self.cooling_count += 1;
        return id;
    }

    pub fn registerWatchdog(self: *ThermalSubsystem, name: []const u8) ?u8 {
        if (self.watchdog_count >= 4) return null;
        const id = self.watchdog_count;
        self.watchdogs[id] = WatchdogDevice.init();
        self.watchdogs[id].id = id;
        self.watchdogs[id].info.setIdentity(name);
        self.watchdogs[id].active = true;
        self.watchdog_count += 1;
        return id;
    }

    /// Poll all thermal zones (called from timer interrupt)
    pub fn poll(self: *ThermalSubsystem) void {
        for (0..self.zone_count) |i| {
            if (!self.zones[i].enabled) continue;
            // In real kernel: read hardware sensor
            // Here: use last set temp
            const temp = self.zones[i].temp_current;
            self.zones[i].update(temp, self.cooling_devices[0..self.cooling_count]);
        }
    }

    /// Update a zone temperature (from sensor driver)
    pub fn updateZoneTemp(self: *ThermalSubsystem, zone_id: u8, temp_mc: i32) void {
        if (zone_id >= self.zone_count) return;
        self.zones[zone_id].update(temp_mc, self.cooling_devices[0..self.cooling_count]);
    }

    /// Tick all watchdogs
    pub fn tickWatchdogs(self: *ThermalSubsystem, current_tick: u64, ticks_per_sec: u64) void {
        for (0..self.watchdog_count) |i| {
            self.watchdogs[i].tick(current_tick, ticks_per_sec);
        }
    }

    /// Set up a basic x86 thermal configuration
    pub fn setupDefault(self: *ThermalSubsystem) void {
        // CPU thermal zone
        if (self.registerZone("x86_pkg_temp")) |zone_id| {
            // 70°C passive trip, 85°C hot, 95°C critical
            _ = self.zones[zone_id].addTrip(.passive, 70000, 2000);
            _ = self.zones[zone_id].addTrip(.hot, 85000, 3000);
            _ = self.zones[zone_id].addTrip(.critical, 95000, 0);

            // CPU fan cooling device
            if (self.registerCooling("cpu-fan", .fan)) |fan_id| {
                self.zones[zone_id].bindCooling(0, fan_id);
                self.zones[zone_id].bindCooling(1, fan_id);
            }

            // CPU throttle cooling device
            if (self.registerCooling("intel_cpufreq", .processor)) |throttle_id| {
                self.zones[zone_id].bindCooling(0, throttle_id);
            }
        }

        // PCH thermal zone
        if (self.registerZone("pch_skylake")) |zone_id| {
            _ = self.zones[zone_id].addTrip(.passive, 75000, 2000);
            _ = self.zones[zone_id].addTrip(.critical, 100000, 0);
        }

        // Default watchdog
        if (self.registerWatchdog("iTCO_wdt")) |wdt_id| {
            self.watchdogs[wdt_id].timeout_sec = 30;
            self.watchdogs[wdt_id].min_timeout = 2;
            self.watchdogs[wdt_id].max_timeout = 613;
            self.watchdogs[wdt_id].info.options |= WDIOF_PRETIMEOUT;
        }
    }

    pub fn getMaxTemp(self: *ThermalSubsystem) i32 {
        var max: i32 = -273000; // absolute zero
        for (0..self.zone_count) |i| {
            if (self.zones[i].temp_current > max) {
                max = self.zones[i].temp_current;
            }
        }
        return max;
    }
};

var thermal_subsystem: ThermalSubsystem = ThermalSubsystem.init();

pub fn getThermalSubsystem() *ThermalSubsystem {
    return &thermal_subsystem;
}
