// SPDX-License-Identifier: MIT
// Zxyphor Kernel — GPIO & Clock Framework
//
// Platform bus infrastructure:
// - GPIO controller abstraction (pin muxing, directions, IRQ)
// - GPIO chip with bank management
// - Clock tree: PLLs, dividers, gates, muxes
// - Clock rate propagation and parent selection
// - Regulator framework (voltage/current control)
// - Pin control (pinctrl) multiplexing
// - Platform device registration

const std = @import("std");

// ─────────────────── GPIO Pin State ─────────────────────────────────
pub const GpioDirection = enum(u8) {
    input = 0,
    output = 1,
};

pub const GpioPull = enum(u8) {
    none = 0,
    up = 1,
    down = 2,
    bus_keep = 3,
};

pub const GpioIrqType = enum(u8) {
    none = 0,
    rising_edge = 1,
    falling_edge = 2,
    both_edges = 3,
    level_high = 4,
    level_low = 5,
};

pub const GpioDriveStrength = enum(u8) {
    ma_2 = 0,
    ma_4 = 1,
    ma_8 = 2,
    ma_12 = 3,
    ma_16 = 4,
};

pub const GpioPin = struct {
    direction: GpioDirection = .input,
    value: bool = false,
    pull: GpioPull = .none,
    irq_type: GpioIrqType = .none,
    drive: GpioDriveStrength = .ma_4,
    active_low: bool = false,
    open_drain: bool = false,
    open_source: bool = false,
    debounce_us: u32 = 0,
    requested: bool = false,
    irq_enabled: bool = false,
    /// Label for the requesting consumer
    label: [16]u8 = [_]u8{0} ** 16,
    label_len: u8 = 0,
    /// Alt function number (for pinmux)
    alt_func: u8 = 0,

    pub fn setLabel(self: *GpioPin, l: []const u8) void {
        const len = @min(l.len, 15);
        @memcpy(self.label[0..len], l[0..len]);
        self.label_len = @intCast(len);
    }

    pub fn getValue(self: *const GpioPin) bool {
        if (self.active_low) return !self.value;
        return self.value;
    }

    pub fn setValue(self: *GpioPin, val: bool) void {
        if (self.direction != .output) return;
        self.value = if (self.active_low) !val else val;
    }
};

// ─────────────────── GPIO Chip (Controller) ─────────────────────────
pub const MAX_GPIO_PINS: usize = 128;

pub const GpioChip = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    base: u32 = 0,          // global GPIO number base
    ngpio: u32 = 0,         // number of GPIOs
    pins: [MAX_GPIO_PINS]GpioPin = [_]GpioPin{.{}} ** MAX_GPIO_PINS,
    /// IRQ domain
    irq_base: u32 = 0,
    irq_count: u32 = 0,
    active: bool = false,

    pub fn setName(self: *GpioChip, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn request(self: *GpioChip, offset: u32, label: []const u8) bool {
        if (offset >= self.ngpio) return false;
        if (self.pins[offset].requested) return false;
        self.pins[offset].requested = true;
        self.pins[offset].setLabel(label);
        return true;
    }

    pub fn free(self: *GpioChip, offset: u32) void {
        if (offset >= self.ngpio) return;
        self.pins[offset].requested = false;
        self.pins[offset].label_len = 0;
    }

    pub fn setDirection(self: *GpioChip, offset: u32, dir: GpioDirection) bool {
        if (offset >= self.ngpio or !self.pins[offset].requested) return false;
        self.pins[offset].direction = dir;
        return true;
    }

    pub fn get(self: *const GpioChip, offset: u32) ?bool {
        if (offset >= self.ngpio) return null;
        return self.pins[offset].getValue();
    }

    pub fn set(self: *GpioChip, offset: u32, val: bool) void {
        if (offset >= self.ngpio) return;
        self.pins[offset].setValue(val);
    }

    pub fn setIrqType(self: *GpioChip, offset: u32, irq_type: GpioIrqType) bool {
        if (offset >= self.ngpio or !self.pins[offset].requested) return false;
        self.pins[offset].irq_type = irq_type;
        self.pins[offset].irq_enabled = irq_type != .none;
        return true;
    }

    pub fn setPull(self: *GpioChip, offset: u32, pull: GpioPull) bool {
        if (offset >= self.ngpio or !self.pins[offset].requested) return false;
        self.pins[offset].pull = pull;
        return true;
    }

    pub fn setDebounce(self: *GpioChip, offset: u32, debounce_us: u32) bool {
        if (offset >= self.ngpio or !self.pins[offset].requested) return false;
        self.pins[offset].debounce_us = debounce_us;
        return true;
    }

    pub fn requestedCount(self: *const GpioChip) u32 {
        var count: u32 = 0;
        for (self.pins[0..self.ngpio]) |pin| {
            if (pin.requested) count += 1;
        }
        return count;
    }
};

// ─────────────────── Clock Tree ─────────────────────────────────────
pub const ClockType = enum(u8) {
    fixed,      // Fixed rate oscillator
    pll,        // Phase-locked loop
    divider,    // Rate = parent / divisor
    gate,       // Enable/disable gate
    mux,        // Parent selector
    fractional, // Fractional divider
};

pub const MAX_CLOCK_PARENTS: usize = 8;

pub const ClockNode = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    clock_type: ClockType = .fixed,
    /// Rate in Hz
    rate: u64 = 0,
    /// For fixed: the fixed rate
    fixed_rate: u64 = 0,
    /// For PLL: multiplier/divider
    pll_mult: u32 = 1,
    pll_div: u32 = 1,
    /// For divider
    div_ratio: u32 = 1,
    div_max: u32 = 256,
    /// For mux: selected parent index
    mux_sel: u8 = 0,
    /// For fractional: m/n
    frac_m: u32 = 1,
    frac_n: u32 = 1,
    /// Parent IDs
    parent_ids: [MAX_CLOCK_PARENTS]u16 = [_]u16{0xFFFF} ** MAX_CLOCK_PARENTS,
    parent_count: u8 = 0,
    /// State
    enabled: bool = false,
    enable_count: u32 = 0, // reference counting
    /// Flags
    is_critical: bool = false, // cannot be disabled
    read_only: bool = false,   // cannot change rate
    active: bool = false,

    pub fn setName(self: *ClockNode, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn addParent(self: *ClockNode, parent_id: u16) bool {
        if (self.parent_count >= MAX_CLOCK_PARENTS) return false;
        self.parent_ids[self.parent_count] = parent_id;
        self.parent_count += 1;
        return true;
    }

    pub fn enable(self: *ClockNode) void {
        self.enable_count += 1;
        self.enabled = true;
    }

    pub fn disable(self: *ClockNode) void {
        if (self.is_critical) return;
        if (self.enable_count > 0) self.enable_count -= 1;
        if (self.enable_count == 0) self.enabled = false;
    }

    pub fn recalcRate(self: *ClockNode, parent_rate: u64) void {
        self.rate = switch (self.clock_type) {
            .fixed => self.fixed_rate,
            .pll => (parent_rate * self.pll_mult) / @max(self.pll_div, 1),
            .divider => parent_rate / @max(self.div_ratio, 1),
            .gate => parent_rate,
            .mux => parent_rate,
            .fractional => (parent_rate * self.frac_m) / @max(self.frac_n, 1),
        };
    }

    pub fn setRate(self: *ClockNode, target_rate: u64, parent_rate: u64) bool {
        if (self.read_only) return false;
        switch (self.clock_type) {
            .divider => {
                if (target_rate == 0) return false;
                var div = parent_rate / target_rate;
                if (div == 0) div = 1;
                if (div > self.div_max) div = self.div_max;
                self.div_ratio = @intCast(div);
                self.recalcRate(parent_rate);
                return true;
            },
            .pll => {
                if (parent_rate == 0) return false;
                self.pll_mult = @intCast(target_rate / parent_rate);
                if (self.pll_mult == 0) self.pll_mult = 1;
                self.pll_div = 1;
                self.recalcRate(parent_rate);
                return true;
            },
            .fractional => {
                if (parent_rate == 0) return false;
                // Find best m/n approximation
                self.frac_m = @intCast(@min(target_rate, 0xFFFFFFFF));
                self.frac_n = @intCast(@min(parent_rate, 0xFFFFFFFF));
                // Simplify
                const g = gcd(self.frac_m, self.frac_n);
                if (g > 0) {
                    self.frac_m /= g;
                    self.frac_n /= g;
                }
                self.recalcRate(parent_rate);
                return true;
            },
            else => return false,
        }
    }
};

fn gcd(a: u32, b: u32) u32 {
    var x = a;
    var y = b;
    while (y != 0) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

// ─────────────────── Clock Manager ──────────────────────────────────
pub const MAX_CLOCKS: usize = 128;

pub const ClockManager = struct {
    clocks: [MAX_CLOCKS]ClockNode = [_]ClockNode{.{}} ** MAX_CLOCKS,
    clock_count: u16 = 0,

    pub fn registerClock(self: *ClockManager, clock: ClockNode) ?u16 {
        if (self.clock_count >= MAX_CLOCKS) return null;
        const id = self.clock_count;
        self.clocks[id] = clock;
        self.clocks[id].active = true;
        self.clock_count += 1;
        return id;
    }

    pub fn registerFixed(self: *ClockManager, name: []const u8, rate: u64) ?u16 {
        var clk = ClockNode{
            .clock_type = .fixed,
            .fixed_rate = rate,
            .rate = rate,
            .enabled = true,
            .is_critical = true,
        };
        clk.setName(name);
        return self.registerClock(clk);
    }

    pub fn registerPll(self: *ClockManager, name: []const u8, parent_id: u16, mult: u32, div: u32) ?u16 {
        var clk = ClockNode{
            .clock_type = .pll,
            .pll_mult = mult,
            .pll_div = div,
        };
        clk.setName(name);
        _ = clk.addParent(parent_id);
        return self.registerClock(clk);
    }

    pub fn registerDivider(self: *ClockManager, name: []const u8, parent_id: u16, div: u32, max_div: u32) ?u16 {
        var clk = ClockNode{
            .clock_type = .divider,
            .div_ratio = div,
            .div_max = max_div,
        };
        clk.setName(name);
        _ = clk.addParent(parent_id);
        return self.registerClock(clk);
    }

    pub fn registerGate(self: *ClockManager, name: []const u8, parent_id: u16) ?u16 {
        var clk = ClockNode{
            .clock_type = .gate,
        };
        clk.setName(name);
        _ = clk.addParent(parent_id);
        return self.registerClock(clk);
    }

    pub fn registerMux(self: *ClockManager, name: []const u8, parents: []const u16) ?u16 {
        var clk = ClockNode{
            .clock_type = .mux,
        };
        clk.setName(name);
        for (parents) |p| {
            if (!clk.addParent(p)) break;
        }
        return self.registerClock(clk);
    }

    pub fn enableClock(self: *ClockManager, id: u16) bool {
        if (id >= self.clock_count) return false;
        // Enable parent chain first
        if (self.clocks[id].parent_count > 0) {
            const parent_id = self.clocks[id].parent_ids[self.clocks[id].mux_sel];
            if (parent_id != 0xFFFF) {
                _ = self.enableClock(parent_id);
            }
        }
        self.clocks[id].enable();
        return true;
    }

    pub fn disableClock(self: *ClockManager, id: u16) void {
        if (id >= self.clock_count) return;
        self.clocks[id].disable();
    }

    pub fn getRate(self: *const ClockManager, id: u16) u64 {
        if (id >= self.clock_count) return 0;
        return self.clocks[id].rate;
    }

    pub fn setRate(self: *ClockManager, id: u16, target_rate: u64) bool {
        if (id >= self.clock_count) return false;
        var parent_rate: u64 = 0;
        if (self.clocks[id].parent_count > 0) {
            const pid = self.clocks[id].parent_ids[self.clocks[id].mux_sel];
            if (pid != 0xFFFF and pid < self.clock_count) {
                parent_rate = self.clocks[pid].rate;
            }
        }
        return self.clocks[id].setRate(target_rate, parent_rate);
    }

    /// Propagate rates from root (fixed) clocks down the tree
    pub fn propagateRates(self: *ClockManager) void {
        // Multi-pass: fixed clocks first, then their children
        for (self.clocks[0..self.clock_count]) |*clk| {
            if (clk.active and clk.clock_type == .fixed) {
                clk.rate = clk.fixed_rate;
            }
        }
        // Propagate to children (simple BFS-like: repeat a few times)
        var pass: u8 = 0;
        while (pass < 8) : (pass += 1) {
            for (self.clocks[0..self.clock_count]) |*clk| {
                if (!clk.active or clk.clock_type == .fixed) continue;
                if (clk.parent_count > 0) {
                    const pid = clk.parent_ids[clk.mux_sel];
                    if (pid != 0xFFFF and pid < self.clock_count) {
                        clk.recalcRate(self.clocks[pid].rate);
                    }
                }
            }
        }
    }

    pub fn selectMuxParent(self: *ClockManager, id: u16, parent_idx: u8) bool {
        if (id >= self.clock_count) return false;
        if (self.clocks[id].clock_type != .mux) return false;
        if (parent_idx >= self.clocks[id].parent_count) return false;
        self.clocks[id].mux_sel = parent_idx;
        self.propagateRates();
        return true;
    }
};

// ─────────────────── Regulator Framework ────────────────────────────
pub const MAX_REGULATORS: usize = 32;

pub const RegulatorMode = enum(u8) {
    fast,     // High performance
    normal,   // Standard operation
    idle,     // Low power when idle
    standby,  // Minimal power
};

pub const Regulator = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    /// Voltage in microvolts
    voltage_uv: u32 = 0,
    min_uv: u32 = 0,
    max_uv: u32 = 0,
    step_uv: u32 = 0,
    /// Current limit in microamps
    current_limit_ua: u32 = 0,
    max_ua: u32 = 0,
    /// State
    mode: RegulatorMode = .normal,
    enabled: bool = false,
    always_on: bool = false,
    use_count: u32 = 0,
    active: bool = false,

    pub fn setName(self: *Regulator, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn enable(self: *Regulator) void {
        self.use_count += 1;
        self.enabled = true;
    }

    pub fn disable(self: *Regulator) void {
        if (self.always_on) return;
        if (self.use_count > 0) self.use_count -= 1;
        if (self.use_count == 0) self.enabled = false;
    }

    pub fn setVoltage(self: *Regulator, target_uv: u32) bool {
        if (target_uv < self.min_uv or target_uv > self.max_uv) return false;
        if (self.step_uv > 0) {
            // Round to nearest step
            const steps = (target_uv - self.min_uv) / self.step_uv;
            self.voltage_uv = self.min_uv + steps * self.step_uv;
        } else {
            self.voltage_uv = target_uv;
        }
        return true;
    }

    pub fn setCurrentLimit(self: *Regulator, limit_ua: u32) bool {
        if (limit_ua > self.max_ua) return false;
        self.current_limit_ua = limit_ua;
        return true;
    }

    pub fn setMode(self: *Regulator, mode: RegulatorMode) void {
        self.mode = mode;
    }
};

// ─────────────────── Pin Controller ─────────────────────────────────
pub const MAX_PINCTRL_GROUPS: usize = 32;
pub const MAX_PINS_PER_GROUP: usize = 16;

pub const PinFunction = enum(u8) {
    gpio = 0,
    uart = 1,
    spi = 2,
    i2c = 3,
    pwm = 4,
    timer = 5,
    adc = 6,
    dac = 7,
    sdio = 8,
    ethernet = 9,
    usb = 10,
    pcie = 11,
    display = 12,
    audio = 13,
    jtag = 14,
};

pub const PinGroup = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    pins: [MAX_PINS_PER_GROUP]u16 = [_]u16{0} ** MAX_PINS_PER_GROUP,
    pin_count: u8 = 0,
    function: PinFunction = .gpio,
    active: bool = false,

    pub fn setName(self: *PinGroup, n: []const u8) void {
        const len = @min(n.len, 15);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn addPin(self: *PinGroup, pin: u16) bool {
        if (self.pin_count >= MAX_PINS_PER_GROUP) return false;
        self.pins[self.pin_count] = pin;
        self.pin_count += 1;
        return true;
    }
};

pub const PinController = struct {
    groups: [MAX_PINCTRL_GROUPS]PinGroup = [_]PinGroup{.{}} ** MAX_PINCTRL_GROUPS,
    group_count: u8 = 0,

    pub fn addGroup(self: *PinController, name: []const u8, func: PinFunction, pins: []const u16) ?u8 {
        if (self.group_count >= MAX_PINCTRL_GROUPS) return null;
        const idx = self.group_count;
        self.groups[idx] = .{
            .function = func,
            .active = true,
        };
        self.groups[idx].setName(name);
        for (pins) |p| {
            if (!self.groups[idx].addPin(p)) break;
        }
        self.group_count += 1;
        return idx;
    }

    pub fn selectFunction(self: *PinController, group_idx: u8, func: PinFunction) bool {
        if (group_idx >= self.group_count) return false;
        self.groups[group_idx].function = func;
        return true;
    }
};

// ─────────────────── Platform Manager ───────────────────────────────
pub const MAX_GPIO_CHIPS: usize = 8;

pub const PlatformManager = struct {
    gpio_chips: [MAX_GPIO_CHIPS]GpioChip = [_]GpioChip{.{}} ** MAX_GPIO_CHIPS,
    gpio_chip_count: u8 = 0,
    clock_mgr: ClockManager = .{},
    regulators: [MAX_REGULATORS]Regulator = [_]Regulator{.{}} ** MAX_REGULATORS,
    reg_count: u8 = 0,
    pinctrl: PinController = .{},
    next_gpio_base: u32 = 0,
    initialized: bool = false,

    pub fn init(self: *PlatformManager) void {
        // Register default clocks
        _ = self.clock_mgr.registerFixed("osc_24m", 24000000);    // 24 MHz main oscillator
        _ = self.clock_mgr.registerFixed("osc_32k", 32768);       // 32.768 kHz RTC
        _ = self.clock_mgr.registerPll("pll_cpu", 0, 50, 1);     // 1.2 GHz CPU PLL
        _ = self.clock_mgr.registerPll("pll_ddr", 0, 66, 1);     // 1.6 GHz DDR PLL
        _ = self.clock_mgr.registerDivider("cpu_clk", 2, 1, 16); // CPU clock
        _ = self.clock_mgr.registerDivider("ahb_clk", 2, 4, 16); // AHB bus
        _ = self.clock_mgr.registerDivider("apb_clk", 5, 2, 16); // APB bus
        _ = self.clock_mgr.registerGate("uart_gate", 6);
        _ = self.clock_mgr.registerGate("spi_gate", 6);
        _ = self.clock_mgr.registerGate("i2c_gate", 6);
        self.clock_mgr.propagateRates();

        self.initialized = true;
    }

    pub fn registerGpioChip(self: *PlatformManager, name: []const u8, ngpio: u32) ?u8 {
        if (self.gpio_chip_count >= MAX_GPIO_CHIPS) return null;
        const idx = self.gpio_chip_count;
        self.gpio_chips[idx] = .{
            .base = self.next_gpio_base,
            .ngpio = @min(ngpio, MAX_GPIO_PINS),
            .active = true,
        };
        self.gpio_chips[idx].setName(name);
        self.next_gpio_base += ngpio;
        self.gpio_chip_count += 1;
        return idx;
    }

    pub fn registerRegulator(self: *PlatformManager, name: []const u8, min_uv: u32, max_uv: u32, step_uv: u32) ?u8 {
        if (self.reg_count >= MAX_REGULATORS) return null;
        const idx = self.reg_count;
        self.regulators[idx] = .{
            .min_uv = min_uv,
            .max_uv = max_uv,
            .step_uv = step_uv,
            .voltage_uv = min_uv,
            .active = true,
        };
        self.regulators[idx].setName(name);
        self.reg_count += 1;
        return idx;
    }

    pub fn gpioRequest(self: *PlatformManager, global_pin: u32, label: []const u8) bool {
        // Find the right chip
        for (&self.gpio_chips[0..self.gpio_chip_count]) |*chip| {
            if (chip.active and global_pin >= chip.base and global_pin < chip.base + chip.ngpio) {
                return chip.request(global_pin - chip.base, label);
            }
        }
        return false;
    }

    pub fn gpioGet(self: *const PlatformManager, global_pin: u32) ?bool {
        for (self.gpio_chips[0..self.gpio_chip_count]) |chip| {
            if (chip.active and global_pin >= chip.base and global_pin < chip.base + chip.ngpio) {
                return chip.get(global_pin - chip.base);
            }
        }
        return null;
    }

    pub fn gpioSet(self: *PlatformManager, global_pin: u32, val: bool) void {
        for (&self.gpio_chips[0..self.gpio_chip_count]) |*chip| {
            if (chip.active and global_pin >= chip.base and global_pin < chip.base + chip.ngpio) {
                chip.set(global_pin - chip.base, val);
                return;
            }
        }
    }

    pub fn totalGpios(self: *const PlatformManager) u32 {
        return self.next_gpio_base;
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var platform_mgr: PlatformManager = .{};

pub fn initPlatform() void {
    platform_mgr.init();
}

pub fn getPlatformManager() *PlatformManager {
    return &platform_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_platform_init() void {
    initPlatform();
}

export fn zxy_gpio_chip_count() u8 {
    return platform_mgr.gpio_chip_count;
}

export fn zxy_gpio_total() u32 {
    return platform_mgr.totalGpios();
}

export fn zxy_gpio_request(pin: u32) bool {
    return platform_mgr.gpioRequest(pin, "ffi");
}

export fn zxy_gpio_set(pin: u32, val: bool) void {
    platform_mgr.gpioSet(pin, val);
}

export fn zxy_gpio_get(pin: u32) i32 {
    if (platform_mgr.gpioGet(pin)) |v| return if (v) 1 else 0;
    return -1;
}

export fn zxy_clock_count() u16 {
    return platform_mgr.clock_mgr.clock_count;
}

export fn zxy_clock_get_rate(id: u16) u64 {
    return platform_mgr.clock_mgr.getRate(id);
}

export fn zxy_clock_enable(id: u16) bool {
    return platform_mgr.clock_mgr.enableClock(id);
}

export fn zxy_regulator_count() u8 {
    return platform_mgr.reg_count;
}
