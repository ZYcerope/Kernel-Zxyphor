// =============================================================================
// Kernel Zxyphor — HPET (High Precision Event Timer) Driver
// =============================================================================
// Full HPET implementation per Intel IA-PC HPET specification:
//   - Timer discovery via ACPI HPET table
//   - Main counter read (femtosecond resolution)
//   - Periodic and one-shot timer comparators
//   - Per-timer IRQ routing via FSB or IOAPIC
//   - Nanosecond/microsecond/millisecond conversion
//   - Calibration against PIT/TSC for fallback timing
//   - High-resolution sleep support
//   - Up to 32 comparators per HPET block
// =============================================================================

// =============================================================================
// HPET register offsets
// =============================================================================

pub const HPET_CAP_ID: u64 = 0x000;
pub const HPET_CONFIG: u64 = 0x010;
pub const HPET_INT_STATUS: u64 = 0x020;
pub const HPET_MAIN_COUNTER: u64 = 0x0F0;
pub const HPET_TIMER_BASE: u64 = 0x100;
pub const HPET_TIMER_STRIDE: u64 = 0x20;

// Timer N register offsets (relative to timer base)
pub const TIMER_CONFIG: u64 = 0x00;
pub const TIMER_COMPARATOR: u64 = 0x08;
pub const TIMER_FSB_ROUTE: u64 = 0x10;

// Config register bits
pub const HPET_CFG_ENABLE: u64 = 1 << 0;
pub const HPET_CFG_LEGACY_REPLACE: u64 = 1 << 1;

// Timer config bits
pub const TIMER_CFG_INT_TYPE_LEVEL: u64 = 1 << 1;
pub const TIMER_CFG_INT_ENABLE: u64 = 1 << 2;
pub const TIMER_CFG_PERIODIC: u64 = 1 << 3;
pub const TIMER_CFG_PERIODIC_CAP: u64 = 1 << 4;
pub const TIMER_CFG_64BIT_CAP: u64 = 1 << 5;
pub const TIMER_CFG_SET_ACCUMULATOR: u64 = 1 << 6;
pub const TIMER_CFG_32BIT_MODE: u64 = 1 << 8;
pub const TIMER_CFG_FSB_ENABLE: u64 = 1 << 14;
pub const TIMER_CFG_FSB_CAP: u64 = 1 << 15;

// =============================================================================
// ACPI HPET table
// =============================================================================

pub const AcpiHpetTable = extern struct {
    signature: [4]u8,           // "HPET"
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
    // HPET-specific fields
    event_timer_block_id: u32,
    base_address_space: u8,     // 0=memory, 1=I/O
    base_register_bit_width: u8,
    base_register_bit_offset: u8,
    base_reserved: u8,
    base_address: u64,
    hpet_number: u8,
    min_clock_tick: u16,
    page_protection: u8,
};

// =============================================================================
// Timer comparator
// =============================================================================

pub const MAX_TIMERS: usize = 32;

pub const TimerMode = enum(u8) {
    disabled = 0,
    oneshot = 1,
    periodic = 2,
};

pub const Timer = struct {
    index: u8,
    mode: TimerMode,
    supports_periodic: bool,
    supports_64bit: bool,
    supports_fsb: bool,
    irq_routing_cap: u32,     // Bitmask of allowed IRQs
    current_irq: u8,
    comparator_value: u64,
    period_ticks: u64,
    callback: ?*const fn () void,
    active: bool,
    fires: u64,                // Number of times fired
};

fn newTimer() Timer {
    return Timer{
        .index = 0,
        .mode = .disabled,
        .supports_periodic = false,
        .supports_64bit = false,
        .supports_fsb = false,
        .irq_routing_cap = 0,
        .current_irq = 0,
        .comparator_value = 0,
        .period_ticks = 0,
        .callback = null,
        .active = false,
        .fires = 0,
    };
}

// =============================================================================
// HPET driver
// =============================================================================

pub const HpetDriver = struct {
    base_addr: u64,
    period_fs: u64,           // Counter period in femtoseconds
    frequency_hz: u64,        // Counter frequency
    num_timers: u8,
    is_64bit: bool,
    legacy_capable: bool,
    vendor_id: u16,
    revision: u8,
    enabled: bool,

    timers: [MAX_TIMERS]Timer,

    // Calibration
    tsc_ratio: u64,           // TSC ticks per HPET tick (fixed-point 32.32)
    calibrated: bool,

    // Monotonic tracking
    last_counter: u64,
    overflow_count: u64,

    /// Initialize from ACPI table
    pub fn initFromAcpi(self: *HpetDriver, table: *const AcpiHpetTable) bool {
        if (table.base_address_space != 0) return false; // Must be MMIO

        self.base_addr = table.base_address;
        if (self.base_addr == 0) return false;

        // Read capabilities
        const cap = self.readReg(HPET_CAP_ID);
        self.period_fs = cap >> 32;  // Upper 32 bits = period in femtoseconds
        if (self.period_fs == 0) return false;

        self.num_timers = @intCast(((cap >> 8) & 0x1F) + 1);
        self.is_64bit = (cap & (1 << 13)) != 0;
        self.legacy_capable = (cap & (1 << 15)) != 0;
        self.vendor_id = @truncate(cap >> 16);
        self.revision = @truncate(cap);

        // Calculate frequency: 10^15 fs/s / period_fs = Hz
        self.frequency_hz = 1_000_000_000_000_000 / self.period_fs;

        // Discover timer capabilities
        var i: u8 = 0;
        while (i < self.num_timers and i < MAX_TIMERS) : (i += 1) {
            self.timers[i] = newTimer();
            self.timers[i].index = i;
            const tcfg = self.readTimerConfig(i);
            self.timers[i].supports_periodic = (tcfg & TIMER_CFG_PERIODIC_CAP) != 0;
            self.timers[i].supports_64bit = (tcfg & TIMER_CFG_64BIT_CAP) != 0;
            self.timers[i].supports_fsb = (tcfg & TIMER_CFG_FSB_CAP) != 0;
            self.timers[i].irq_routing_cap = @truncate(tcfg >> 32);
        }

        // Stop counter, reset to 0
        self.disable();
        self.writeReg(HPET_MAIN_COUNTER, 0);

        // Clear any pending interrupts
        self.writeReg(HPET_INT_STATUS, 0xFFFFFFFF);

        // Enable counter
        self.enable();

        self.last_counter = 0;
        self.overflow_count = 0;
        self.calibrated = false;

        return true;
    }

    /// Enable the main HPET counter
    pub fn enable(self: *HpetDriver) void {
        var cfg = self.readReg(HPET_CONFIG);
        cfg |= HPET_CFG_ENABLE;
        self.writeReg(HPET_CONFIG, cfg);
        self.enabled = true;
    }

    /// Disable the main HPET counter
    pub fn disable(self: *HpetDriver) void {
        var cfg = self.readReg(HPET_CONFIG);
        cfg &= ~HPET_CFG_ENABLE;
        self.writeReg(HPET_CONFIG, cfg);
        self.enabled = false;
    }

    /// Enable legacy replacement mode (Timer 0→IRQ0, Timer 1→IRQ8)
    pub fn enableLegacy(self: *HpetDriver) void {
        if (!self.legacy_capable) return;
        var cfg = self.readReg(HPET_CONFIG);
        cfg |= HPET_CFG_LEGACY_REPLACE;
        self.writeReg(HPET_CONFIG, cfg);
    }

    /// Read the main counter value
    pub fn readCounter(self: *HpetDriver) u64 {
        const val = self.readReg(HPET_MAIN_COUNTER);
        // Track overflow for 32-bit counters
        if (!self.is_64bit) {
            if ((val & 0xFFFFFFFF) < (self.last_counter & 0xFFFFFFFF)) {
                self.overflow_count += 1;
            }
        }
        self.last_counter = val;
        return val;
    }

    /// Convert HPET ticks to nanoseconds
    pub fn ticksToNs(self: *const HpetDriver, ticks: u64) u64 {
        // ns = ticks * period_fs / 1_000_000
        return (ticks * self.period_fs) / 1_000_000;
    }

    /// Convert nanoseconds to HPET ticks
    pub fn nsToTicks(self: *const HpetDriver, ns: u64) u64 {
        return (ns * 1_000_000) / self.period_fs;
    }

    /// Convert HPET ticks to microseconds
    pub fn ticksToUs(self: *const HpetDriver, ticks: u64) u64 {
        return (ticks * self.period_fs) / 1_000_000_000;
    }

    /// Convert HPET ticks to milliseconds
    pub fn ticksToMs(self: *const HpetDriver, ticks: u64) u64 {
        return (ticks * self.period_fs) / 1_000_000_000_000;
    }

    /// Get elapsed time in nanoseconds since counter was reset
    pub fn elapsedNs(self: *HpetDriver) u64 {
        return self.ticksToNs(self.readCounter());
    }

    /// Set up a one-shot timer
    pub fn setupOneShot(self: *HpetDriver, timer_idx: u8, delay_ns: u64, irq: u8, callback: *const fn () void) bool {
        if (timer_idx >= self.num_timers) return false;

        const timer = &self.timers[timer_idx];
        _ = timer;

        // Check IRQ routing is allowed
        const irq_bit: u32 = @as(u32, 1) << @intCast(irq);
        if (self.timers[timer_idx].irq_routing_cap & irq_bit == 0) return false;

        const delay_ticks = self.nsToTicks(delay_ns);
        const target = self.readCounter() + delay_ticks;

        // Configure timer
        var tcfg: u64 = 0;
        tcfg |= TIMER_CFG_INT_ENABLE;
        tcfg |= TIMER_CFG_INT_TYPE_LEVEL;
        tcfg |= @as(u64, irq) << 9; // IRQ routing
        self.writeTimerConfig(timer_idx, tcfg);
        self.writeTimerComparator(timer_idx, target);

        self.timers[timer_idx].mode = .oneshot;
        self.timers[timer_idx].comparator_value = target;
        self.timers[timer_idx].current_irq = irq;
        self.timers[timer_idx].callback = callback;
        self.timers[timer_idx].active = true;

        return true;
    }

    /// Set up a periodic timer
    pub fn setupPeriodic(self: *HpetDriver, timer_idx: u8, period_ns: u64, irq: u8, callback: *const fn () void) bool {
        if (timer_idx >= self.num_timers) return false;
        if (!self.timers[timer_idx].supports_periodic) return false;

        const irq_bit: u32 = @as(u32, 1) << @intCast(irq);
        if (self.timers[timer_idx].irq_routing_cap & irq_bit == 0) return false;

        const period_ticks = self.nsToTicks(period_ns);

        // Stop the timer first
        self.writeTimerConfig(timer_idx, 0);

        // Configure as periodic
        var tcfg: u64 = 0;
        tcfg |= TIMER_CFG_INT_ENABLE;
        tcfg |= TIMER_CFG_PERIODIC;
        tcfg |= TIMER_CFG_SET_ACCUMULATOR; // Need to set accumulator for periodic
        tcfg |= TIMER_CFG_INT_TYPE_LEVEL;
        tcfg |= @as(u64, irq) << 9;
        self.writeTimerConfig(timer_idx, tcfg);

        // Set comparator (first fire point)
        const first_fire = self.readCounter() + period_ticks;
        self.writeTimerComparator(timer_idx, first_fire);

        // For periodic mode, second write sets the period
        self.writeTimerComparator(timer_idx, period_ticks);

        self.timers[timer_idx].mode = .periodic;
        self.timers[timer_idx].period_ticks = period_ticks;
        self.timers[timer_idx].comparator_value = first_fire;
        self.timers[timer_idx].current_irq = irq;
        self.timers[timer_idx].callback = callback;
        self.timers[timer_idx].active = true;

        return true;
    }

    /// Disable a timer
    pub fn disableTimer(self: *HpetDriver, timer_idx: u8) void {
        if (timer_idx >= self.num_timers) return;
        self.writeTimerConfig(timer_idx, 0);
        self.timers[timer_idx].mode = .disabled;
        self.timers[timer_idx].active = false;
    }

    /// Handle timer interrupt
    pub fn handleInterrupt(self: *HpetDriver) void {
        const status = self.readReg(HPET_INT_STATUS);

        var i: u8 = 0;
        while (i < self.num_timers) : (i += 1) {
            if (status & (@as(u64, 1) << @intCast(i)) != 0) {
                // Clear interrupt for this timer
                self.writeReg(HPET_INT_STATUS, @as(u64, 1) << @intCast(i));

                self.timers[i].fires += 1;

                if (self.timers[i].callback) |cb| {
                    cb();
                }

                // For one-shot, deactivate
                if (self.timers[i].mode == .oneshot) {
                    self.timers[i].active = false;
                    self.timers[i].mode = .disabled;
                }
            }
        }
    }

    /// Busy-wait for a specified duration (nanoseconds)
    pub fn busyWaitNs(self: *HpetDriver, ns: u64) void {
        const start = self.readCounter();
        const target_ticks = self.nsToTicks(ns);
        while (self.readCounter() - start < target_ticks) {
            asm volatile ("pause");
        }
    }

    /// Busy-wait for microseconds
    pub fn busyWaitUs(self: *HpetDriver, us: u64) void {
        self.busyWaitNs(us * 1000);
    }

    /// Busy-wait for milliseconds
    pub fn busyWaitMs(self: *HpetDriver, ms: u64) void {
        self.busyWaitNs(ms * 1_000_000);
    }

    /// Calibrate TSC against HPET
    pub fn calibrateTsc(self: *HpetDriver) void {
        const hpet_start = self.readCounter();
        const tsc_start = rdtsc();

        // Wait ~10ms using HPET
        self.busyWaitMs(10);

        const hpet_end = self.readCounter();
        const tsc_end = rdtsc();

        const hpet_delta = hpet_end - hpet_start;
        const tsc_delta = tsc_end - tsc_start;

        if (hpet_delta > 0) {
            // Fixed-point 32.32 ratio
            self.tsc_ratio = (tsc_delta << 32) / hpet_delta;
            self.calibrated = true;
        }
    }

    /// Get timer statistics
    pub fn getTimerStats(self: *const HpetDriver, timer_idx: u8) ?TimerStats {
        if (timer_idx >= self.num_timers) return null;
        const t = &self.timers[timer_idx];
        return TimerStats{
            .mode = t.mode,
            .active = t.active,
            .irq = t.current_irq,
            .fires = t.fires,
            .supports_periodic = t.supports_periodic,
            .supports_64bit = t.supports_64bit,
        };
    }

    // MMIO register access
    fn readReg(self: *const HpetDriver, offset: u64) u64 {
        const ptr: *volatile u64 = @ptrFromInt(self.base_addr + offset);
        return ptr.*;
    }

    fn writeReg(self: *const HpetDriver, offset: u64, value: u64) void {
        const ptr: *volatile u64 = @ptrFromInt(self.base_addr + offset);
        ptr.* = value;
    }

    fn readTimerConfig(self: *const HpetDriver, timer: u8) u64 {
        return self.readReg(HPET_TIMER_BASE + @as(u64, timer) * HPET_TIMER_STRIDE + TIMER_CONFIG);
    }

    fn writeTimerConfig(self: *const HpetDriver, timer: u8, value: u64) void {
        self.writeReg(HPET_TIMER_BASE + @as(u64, timer) * HPET_TIMER_STRIDE + TIMER_CONFIG, value);
    }

    fn writeTimerComparator(self: *const HpetDriver, timer: u8, value: u64) void {
        self.writeReg(HPET_TIMER_BASE + @as(u64, timer) * HPET_TIMER_STRIDE + TIMER_COMPARATOR, value);
    }
};

pub const TimerStats = struct {
    mode: TimerMode,
    active: bool,
    irq: u8,
    fires: u64,
    supports_periodic: bool,
    supports_64bit: bool,
};

// =============================================================================
// TSC helper
// =============================================================================

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

// =============================================================================
// Global HPET instance
// =============================================================================

var hpet_instance: HpetDriver = undefined;
var hpet_available: bool = false;

pub fn init(table: *const AcpiHpetTable) bool {
    hpet_instance = HpetDriver{
        .base_addr = 0,
        .period_fs = 0,
        .frequency_hz = 0,
        .num_timers = 0,
        .is_64bit = false,
        .legacy_capable = false,
        .vendor_id = 0,
        .revision = 0,
        .enabled = false,
        .timers = [_]Timer{newTimer()} ** MAX_TIMERS,
        .tsc_ratio = 0,
        .calibrated = false,
        .last_counter = 0,
        .overflow_count = 0,
    };

    if (hpet_instance.initFromAcpi(table)) {
        hpet_available = true;
        return true;
    }
    return false;
}

pub fn getDriver() ?*HpetDriver {
    if (hpet_available) return &hpet_instance;
    return null;
}

pub fn isAvailable() bool {
    return hpet_available;
}

/// Get current time in nanoseconds
pub fn nowNs() u64 {
    if (hpet_available) {
        return hpet_instance.elapsedNs();
    }
    return 0;
}

/// Sleep for nanoseconds (busy-wait)
pub fn sleepNs(ns: u64) void {
    if (hpet_available) {
        hpet_instance.busyWaitNs(ns);
    }
}

/// Sleep for microseconds
pub fn sleepUs(us: u64) void {
    sleepNs(us * 1000);
}

/// Sleep for milliseconds
pub fn sleepMs(ms: u64) void {
    sleepNs(ms * 1_000_000);
}
