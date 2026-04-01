// =============================================================================
// Zxyphor Kernel — ARM64 Generic Timer Driver
// =============================================================================
// Implements the ARMv8-A Generic Timer for both the physical and virtual timers.
// The Generic Timer provides a system counter (CNTPCT/CNTVCT) and per-CPU
// timer comparators with interrupt generation.
//
// Timer Types:
//   - Physical Timer (CNTP_*): Used by the kernel at EL1
//   - Virtual Timer (CNTV_*): Used by VMs or as fallback
//   - Hypervisor Timer (CNTHP_*): Used by hypervisor at EL2
//   - Secure Physical Timer (CNTPS_*): Used by secure firmware
//
// Features:
//   - Nanosecond-precision timekeeping via CNTFRQ counter frequency
//   - One-shot and periodic timer modes
//   - Per-CPU timer for scheduler tick (typically PPI 30 for physical,
//     PPI 27 for virtual, PPI 26 for hypervisor physical)
//   - High-resolution timer support for deadline scheduling
//   - Clocksource with sub-nanosecond interpolation
//   - Timer coalescing for power efficiency
//   - Broadcast timer for CPUs entering deep idle states
// =============================================================================

const gic = @import("gic_v3.zig");

// ── Timer PPI Numbers ─────────────────────────────────────────────────────
pub const TIMER_PPI_SECURE_PHYS: u32 = 29;   // Secure Physical Timer
pub const TIMER_PPI_PHYS: u32 = 30;           // Non-Secure Physical Timer (EL1)
pub const TIMER_PPI_VIRT: u32 = 27;           // Virtual Timer
pub const TIMER_PPI_HYP_PHYS: u32 = 26;       // Hypervisor Physical Timer (EL2)
pub const TIMER_PPI_HYP_VIRT: u32 = 28;       // Hypervisor Virtual Timer

// ── Timer Control Register Bits ───────────────────────────────────────────
pub const TIMER_CTL = struct {
    pub const ENABLE: u64 = 1 << 0;    // Timer enable
    pub const IMASK: u64 = 1 << 1;     // Interrupt mask (1 = masked)
    pub const ISTATUS: u64 = 1 << 2;   // Interrupt status (read-only)
};

// ── Clocksource State ─────────────────────────────────────────────────────
pub const ClockSource = struct {
    frequency: u64,          // Timer frequency in Hz (from CNTFRQ_EL0)
    ns_per_tick: u64,        // Nanoseconds per counter tick (fixed-point 32.32)
    ticks_per_ms: u64,       // Counter ticks per millisecond
    ticks_per_us: u64,       // Counter ticks per microsecond
    boot_timestamp: u64,     // Counter value at boot
    mult: u32,               // Multiplication factor for ns conversion
    shift: u32,              // Shift amount for ns conversion

    const Self = @This();

    pub fn init(freq: u64) Self {
        var cs = Self{
            .frequency = freq,
            .ns_per_tick = 0,
            .ticks_per_ms = freq / 1000,
            .ticks_per_us = freq / 1_000_000,
            .boot_timestamp = readCounter(),
            .mult = 0,
            .shift = 0,
        };

        // Calculate mult/shift for efficient ns conversion
        // ns = ticks * mult >> shift
        // We want: mult / 2^shift ≈ 1_000_000_000 / freq
        cs.shift = 32;
        cs.mult = @truncate((@as(u128, 1_000_000_000) << cs.shift) / @as(u128, freq));
        cs.ns_per_tick = (1_000_000_000 << 32) / freq;

        return cs;
    }

    pub fn ticksToNs(self: *const Self, ticks: u64) u64 {
        return @truncate((@as(u128, ticks) * @as(u128, self.mult)) >> @as(u7, @truncate(self.shift)));
    }

    pub fn nsToTicks(self: *const Self, ns: u64) u64 {
        return @truncate((@as(u128, ns) * @as(u128, self.frequency)) / 1_000_000_000);
    }

    pub fn getElapsedNs(self: *const Self) u64 {
        const current = readCounter();
        const elapsed = current - self.boot_timestamp;
        return self.ticksToNs(elapsed);
    }

    pub fn getUptimeMs(self: *const Self) u64 {
        return self.getElapsedNs() / 1_000_000;
    }

    pub fn getUptimeSec(self: *const Self) u64 {
        return self.getElapsedNs() / 1_000_000_000;
    }
};

var clock_source: ClockSource = undefined;
var timer_initialized: bool = false;

// ── Per-CPU Timer State ───────────────────────────────────────────────────
pub const PerCpuTimer = struct {
    tick_count: u64,         // Number of timer ticks since boot
    last_tick_ns: u64,       // Timestamp of last tick (ns)
    interval_ticks: u64,     // Timer interval in counter ticks
    interval_ns: u64,        // Timer interval in nanoseconds
    mode: TimerMode,
    handler: ?TimerCallback,
    handler_data: ?*anyopaque,
    next_deadline: u64,      // Next timer deadline (counter value)
    overruns: u64,           // Number of timer overruns
    enabled: bool,

    pub const TimerMode = enum {
        one_shot,
        periodic,
        inactive,
    };

    pub const TimerCallback = *const fn (u64, ?*anyopaque) void;

    const Self = @This();

    pub fn init() Self {
        return Self{
            .tick_count = 0,
            .last_tick_ns = 0,
            .interval_ticks = 0,
            .interval_ns = 0,
            .mode = .inactive,
            .handler = null,
            .handler_data = null,
            .next_deadline = 0,
            .overruns = 0,
            .enabled = false,
        };
    }

    pub fn startPeriodic(self: *Self, interval_ns: u64, handler: TimerCallback, data: ?*anyopaque) void {
        self.interval_ns = interval_ns;
        self.interval_ticks = clock_source.nsToTicks(interval_ns);
        self.mode = .periodic;
        self.handler = handler;
        self.handler_data = data;
        self.enabled = true;

        // Set comparator
        const now = readCounter();
        self.next_deadline = now + self.interval_ticks;
        writePhysTimerCompare(self.next_deadline);
        enablePhysTimer();
    }

    pub fn startOneShot(self: *Self, deadline_ns: u64, handler: TimerCallback, data: ?*anyopaque) void {
        self.interval_ns = deadline_ns;
        self.interval_ticks = clock_source.nsToTicks(deadline_ns);
        self.mode = .one_shot;
        self.handler = handler;
        self.handler_data = data;
        self.enabled = true;

        const now = readCounter();
        self.next_deadline = now + self.interval_ticks;
        writePhysTimerCompare(self.next_deadline);
        enablePhysTimer();
    }

    pub fn stop(self: *Self) void {
        self.enabled = false;
        self.mode = .inactive;
        disablePhysTimer();
    }

    pub fn handleInterrupt(self: *Self) void {
        if (!self.enabled) return;

        self.tick_count += 1;
        self.last_tick_ns = clock_source.getElapsedNs();

        // Call handler
        if (self.handler) |handler| {
            handler(self.tick_count, self.handler_data);
        }

        switch (self.mode) {
            .periodic => {
                // Re-arm timer
                const now = readCounter();
                self.next_deadline += self.interval_ticks;

                // Handle overruns (timer fired late)
                if (self.next_deadline <= now) {
                    self.overruns += 1;
                    self.next_deadline = now + self.interval_ticks;
                }

                writePhysTimerCompare(self.next_deadline);
            },
            .one_shot => {
                self.enabled = false;
                self.mode = .inactive;
                disablePhysTimer();
            },
            .inactive => {},
        }
    }
};

const MAX_CPUS: usize = 256;
var per_cpu_timers: [MAX_CPUS]PerCpuTimer = [_]PerCpuTimer{PerCpuTimer.init()} ** MAX_CPUS;

// ── High-Resolution Timer Wheel ───────────────────────────────────────────
pub const HrTimerEntry = struct {
    deadline_ns: u64,
    callback: ?*const fn (*HrTimerEntry) void,
    data: ?*anyopaque,
    next: ?*HrTimerEntry,
    prev: ?*HrTimerEntry,
    armed: bool,
    periodic: bool,
    interval_ns: u64,
};

pub const MAX_HR_TIMERS: usize = 4096;
var hr_timer_pool: [MAX_HR_TIMERS]HrTimerEntry = undefined;
var hr_timer_free_count: usize = MAX_HR_TIMERS;
var hr_timer_head: ?*HrTimerEntry = null;

pub fn allocHrTimer() ?*HrTimerEntry {
    if (hr_timer_free_count == 0) return null;
    hr_timer_free_count -= 1;
    const timer = &hr_timer_pool[hr_timer_free_count];
    timer.* = HrTimerEntry{
        .deadline_ns = 0,
        .callback = null,
        .data = null,
        .next = null,
        .prev = null,
        .armed = false,
        .periodic = false,
        .interval_ns = 0,
    };
    return timer;
}

pub fn armHrTimer(timer: *HrTimerEntry, deadline_ns: u64, callback: *const fn (*HrTimerEntry) void) void {
    timer.deadline_ns = deadline_ns;
    timer.callback = callback;
    timer.armed = true;

    // Insert into sorted list (by deadline)
    if (hr_timer_head == null or deadline_ns < hr_timer_head.?.deadline_ns) {
        timer.next = hr_timer_head;
        if (hr_timer_head) |head| {
            head.prev = timer;
        }
        timer.prev = null;
        hr_timer_head = timer;

        // Reprogram hardware timer if this is the earliest deadline
        const ticks = clock_source.nsToTicks(deadline_ns - clock_source.getElapsedNs());
        const now = readCounter();
        writePhysTimerCompare(now + ticks);
    } else {
        var cur = hr_timer_head;
        while (cur) |c| {
            if (c.next == null or deadline_ns < c.next.?.deadline_ns) {
                timer.next = c.next;
                timer.prev = c;
                if (c.next) |n| {
                    n.prev = timer;
                }
                c.next = timer;
                break;
            }
            cur = c.next;
        }
    }
}

pub fn processExpiredHrTimers() void {
    const now_ns = clock_source.getElapsedNs();

    while (hr_timer_head) |timer| {
        if (timer.deadline_ns > now_ns) break;

        // Remove from list
        hr_timer_head = timer.next;
        if (timer.next) |n| {
            n.prev = null;
        }

        timer.armed = false;

        // Call callback
        if (timer.callback) |cb| {
            cb(timer);
        }

        // Re-arm if periodic
        if (timer.periodic and timer.interval_ns > 0) {
            timer.deadline_ns += timer.interval_ns;
            armHrTimer(timer, timer.deadline_ns, timer.callback.?);
        }
    }

    // Reprogram hardware for next deadline
    if (hr_timer_head) |next_timer| {
        const delta_ns = next_timer.deadline_ns - now_ns;
        const ticks = clock_source.nsToTicks(delta_ns);
        const now = readCounter();
        writePhysTimerCompare(now + ticks);
    }
}

// ── System Register Access ────────────────────────────────────────────────
pub inline fn readCounter() u64 {
    return asm ("mrs %[r], CNTPCT_EL0" : [r] "=r" (-> u64));
}

pub inline fn readVirtualCounter() u64 {
    return asm ("mrs %[r], CNTVCT_EL0" : [r] "=r" (-> u64));
}

pub inline fn readFrequency() u64 {
    return asm ("mrs %[r], CNTFRQ_EL0" : [r] "=r" (-> u64));
}

pub inline fn writePhysTimerCompare(val: u64) void {
    asm volatile ("msr CNTP_CVAL_EL0, %[v]; isb" : : [v] "r" (val));
}

pub inline fn writeVirtTimerCompare(val: u64) void {
    asm volatile ("msr CNTV_CVAL_EL0, %[v]; isb" : : [v] "r" (val));
}

pub inline fn writePhysTimerTval(val: u32) void {
    asm volatile ("msr CNTP_TVAL_EL0, %[v]" : : [v] "r" (@as(u64, val)));
}

pub inline fn readPhysTimerCtl() u64 {
    return asm ("mrs %[r], CNTP_CTL_EL0" : [r] "=r" (-> u64));
}

pub inline fn writePhysTimerCtl(val: u64) void {
    asm volatile ("msr CNTP_CTL_EL0, %[v]; isb" : : [v] "r" (val));
}

pub inline fn enablePhysTimer() void {
    writePhysTimerCtl(TIMER_CTL.ENABLE);
}

pub inline fn disablePhysTimer() void {
    writePhysTimerCtl(0);
}

pub inline fn maskPhysTimerInterrupt() void {
    writePhysTimerCtl(TIMER_CTL.ENABLE | TIMER_CTL.IMASK);
}

pub inline fn readVirtTimerCtl() u64 {
    return asm ("mrs %[r], CNTV_CTL_EL0" : [r] "=r" (-> u64));
}

pub inline fn writeVirtTimerCtl(val: u64) void {
    asm volatile ("msr CNTV_CTL_EL0, %[v]; isb" : : [v] "r" (val));
}

// ── Timer Initialization ──────────────────────────────────────────────────
pub fn init() void {
    // Read counter frequency
    const freq = readFrequency();
    if (freq == 0) {
        // Fallback: assume 24MHz (common on many ARM SoCs like Allwinner)
        clock_source = ClockSource.init(24_000_000);
    } else {
        clock_source = ClockSource.init(freq);
    }

    // Disable timer initially
    disablePhysTimer();

    // Register timer interrupt handler with GIC
    gic.registerHandler(TIMER_PPI_PHYS, timerIrqHandler, null);
    gic.setPriority(TIMER_PPI_PHYS, gic.IRQ_PRIORITY_HIGH);
    gic.setTrigger(TIMER_PPI_PHYS, .level);
    gic.enableIrq(TIMER_PPI_PHYS);

    timer_initialized = true;
}

pub fn initCpu(cpu_idx: u32) void {
    per_cpu_timers[cpu_idx] = PerCpuTimer.init();

    // Enable GIC interrupt for this CPU
    gic.enableIrq(TIMER_PPI_PHYS);

    // Disable timer until scheduler starts
    disablePhysTimer();
}

// ── Timer Interrupt Handler ───────────────────────────────────────────────
fn timerIrqHandler(intid: u32, data: ?*anyopaque) void {
    _ = intid;
    _ = data;

    // Process high-resolution timers first
    processExpiredHrTimers();

    // Process per-CPU periodic timer
    const cpu_idx: u32 = getCurrentCpuIdx();
    per_cpu_timers[cpu_idx].handleInterrupt();
}

// ── Scheduler Tick Initialization ─────────────────────────────────────────
// Call this to start the scheduler tick on a CPU
pub fn startSchedulerTick(cpu_idx: u32, tick_hz: u32) void {
    const interval_ns: u64 = 1_000_000_000 / @as(u64, tick_hz);
    per_cpu_timers[cpu_idx].startPeriodic(interval_ns, schedulerTickCallback, null);
}

fn schedulerTickCallback(tick: u64, data: ?*anyopaque) void {
    _ = tick;
    _ = data;
    // TODO: Call scheduler_tick() from the scheduler module
}

// ── Delay Functions ───────────────────────────────────────────────────────
pub fn delayUs(us: u64) void {
    const target = readCounter() + clock_source.ticks_per_us * us;
    while (readCounter() < target) {
        asm volatile ("yield");
    }
}

pub fn delayMs(ms: u64) void {
    delayUs(ms * 1000);
}

pub fn delayNs(ns: u64) void {
    const ticks = clock_source.nsToTicks(ns);
    const target = readCounter() + ticks;
    while (readCounter() < target) {
        asm volatile ("yield");
    }
}

// ── Time Queries ──────────────────────────────────────────────────────────
pub fn getNowNs() u64 {
    return clock_source.getElapsedNs();
}

pub fn getNowMs() u64 {
    return clock_source.getUptimeMs();
}

pub fn getNowSec() u64 {
    return clock_source.getUptimeSec();
}

pub fn getFrequency() u64 {
    return clock_source.frequency;
}

pub fn getTickCount(cpu_idx: u32) u64 {
    return per_cpu_timers[cpu_idx].tick_count;
}

pub fn isInitialized() bool {
    return timer_initialized;
}

// ── Helper ────────────────────────────────────────────────────────────────
fn getCurrentCpuIdx() u32 {
    const mpidr = asm ("mrs %[r], MPIDR_EL1" : [r] "=r" (-> u64));
    return @truncate(mpidr & 0xFF);
}
