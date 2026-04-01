// =============================================================================
// Kernel Zxyphor - 8254 PIT (Programmable Interval Timer)
// =============================================================================
// The 8254 PIT generates periodic timer interrupts (IRQ 0). It's one of the
// oldest hardware timers on x86 and provides the basic heartbeat for the
// kernel scheduler, timekeeping, and sleep functions.
//
// The PIT has three independent channels:
//   Channel 0: System timer (connected to IRQ 0)
//   Channel 1: Legacy DRAM refresh (not useful)
//   Channel 2: PC speaker
//
// The PIT's base frequency is 1,193,182 Hz. We divide it to get our desired
// tick rate (e.g., 1000 Hz = 1ms ticks).
// =============================================================================

const main = @import("../../main.zig");
const cpu = @import("cpu.zig");

// =============================================================================
// PIT I/O ports
// =============================================================================
const PIT_CHANNEL0_DATA: u16 = 0x40; // Channel 0 data port
const PIT_CHANNEL1_DATA: u16 = 0x41; // Channel 1 data port
const PIT_CHANNEL2_DATA: u16 = 0x42; // Channel 2 data port
const PIT_CMD: u16 = 0x43; // Command port (mode/command register)

// =============================================================================
// PIT configuration constants
// =============================================================================
const PIT_BASE_FREQUENCY: u32 = 1193182; // Base oscillator frequency in Hz

// Command byte bits
const PIT_CMD_CHANNEL0: u8 = 0x00; // Select channel 0
const PIT_CMD_LOHI: u8 = 0x30; // Access mode: low byte then high byte
const PIT_CMD_RATE_GEN: u8 = 0x04; // Mode 2: rate generator (periodic)
const PIT_CMD_SQUARE_WAVE: u8 = 0x06; // Mode 3: square wave generator
const PIT_CMD_BINARY: u8 = 0x00; // Binary counting (vs. BCD)

// =============================================================================
// Timer state
// =============================================================================
var tick_count: u64 = 0; // Total ticks since boot
var tick_frequency: u32 = 0; // Configured tick rate in Hz
var seconds_since_boot: u64 = 0; // Seconds counter
var sub_second_ticks: u32 = 0; // Ticks within the current second

// Callbacks registered for timer events
const MAX_TIMER_CALLBACKS = 16;
const TimerCallback = *const fn (u64) void;

var timer_callbacks: [MAX_TIMER_CALLBACKS]?TimerCallback = [_]?TimerCallback{null} ** MAX_TIMER_CALLBACKS;
var callback_count: usize = 0;

// =============================================================================
// One-shot timers (sleeping, timeouts)
// =============================================================================
const MAX_ONESHOT_TIMERS = 64;

const OneshotTimer = struct {
    deadline_ticks: u64, // Tick count at which this timer fires
    callback: *const fn (*anyopaque) void,
    context: *anyopaque,
    active: bool,
};

var oneshot_timers: [MAX_ONESHOT_TIMERS]OneshotTimer = undefined;
var oneshot_count: usize = 0;

// =============================================================================
// Initialize the PIT with the desired frequency
// =============================================================================
pub fn initialize(frequency: u32) void {
    tick_frequency = frequency;
    tick_count = 0;
    seconds_since_boot = 0;
    sub_second_ticks = 0;

    // Calculate the divisor for the desired frequency
    const divisor: u16 = @truncate(PIT_BASE_FREQUENCY / frequency);

    // Configure channel 0: rate generator mode, binary counting, lo/hi access
    cpu.outb(PIT_CMD, PIT_CMD_CHANNEL0 | PIT_CMD_LOHI | PIT_CMD_RATE_GEN | PIT_CMD_BINARY);

    // Send the divisor (low byte first, then high byte)
    cpu.outb(PIT_CHANNEL0_DATA, @truncate(divisor));
    cpu.outb(PIT_CHANNEL0_DATA, @truncate(divisor >> 8));

    // Register our handler for IRQ 0
    main.idt.registerIrqHandler(0, timerIrqHandler);

    // Unmask IRQ 0 in the PIC
    main.pic.enableIrq(0);

    // Initialize the oneshot timer array
    for (&oneshot_timers) |*timer| {
        timer.active = false;
    }

    main.klog(.info, "PIT: Configured at {d} Hz (divisor={d})", .{ frequency, divisor });
}

// =============================================================================
// Timer IRQ handler (IRQ 0 → vector 32)
// =============================================================================
fn timerIrqHandler(_: u8) void {
    tick_count += 1;
    sub_second_ticks += 1;

    // Update seconds counter
    if (sub_second_ticks >= tick_frequency) {
        sub_second_ticks -= tick_frequency;
        seconds_since_boot += 1;
    }

    // Fire registered periodic callbacks
    for (timer_callbacks) |maybe_cb| {
        if (maybe_cb) |cb| {
            cb(tick_count);
        }
    }

    // Check one-shot timers
    for (&oneshot_timers) |*timer| {
        if (timer.active and tick_count >= timer.deadline_ticks) {
            timer.active = false;
            timer.callback(timer.context);
        }
    }

    // Notify the scheduler for preemption
    main.scheduler.timerTick();
}

// =============================================================================
// Public timer API
// =============================================================================

/// Get the total number of ticks since boot
pub fn getTicks() u64 {
    return tick_count;
}

/// Get the configured tick frequency
pub fn getFrequency() u32 {
    return tick_frequency;
}

/// Get seconds elapsed since boot
pub fn getUptime() u64 {
    return seconds_since_boot;
}

/// Get uptime in milliseconds
pub fn getUptimeMs() u64 {
    return (tick_count * 1000) / @as(u64, tick_frequency);
}

/// Convert milliseconds to tick count
pub fn msToTicks(ms: u64) u64 {
    return (ms * @as(u64, tick_frequency)) / 1000;
}

/// Convert ticks to milliseconds
pub fn ticksToMs(ticks: u64) u64 {
    return (ticks * 1000) / @as(u64, tick_frequency);
}

/// Register a periodic timer callback (called on every tick)
pub fn registerCallback(callback: TimerCallback) bool {
    for (&timer_callbacks) |*slot| {
        if (slot.* == null) {
            slot.* = callback;
            callback_count += 1;
            return true;
        }
    }
    return false; // No free slots
}

/// Unregister a periodic timer callback
pub fn unregisterCallback(callback: TimerCallback) void {
    for (&timer_callbacks) |*slot| {
        if (slot.* == callback) {
            slot.* = null;
            callback_count -= 1;
            return;
        }
    }
}

/// Schedule a one-shot timer to fire after the given number of milliseconds
pub fn scheduleOneshot(ms: u64, callback: *const fn (*anyopaque) void, ctx: *anyopaque) bool {
    for (&oneshot_timers) |*timer| {
        if (!timer.active) {
            timer.deadline_ticks = tick_count + msToTicks(ms);
            timer.callback = callback;
            timer.context = ctx;
            timer.active = true;
            return true;
        }
    }
    return false; // No free timer slots
}

/// Cancel a one-shot timer
pub fn cancelOneshot(callback: *const fn (*anyopaque) void, ctx: *anyopaque) void {
    for (&oneshot_timers) |*timer| {
        if (timer.active and timer.callback == callback and timer.context == ctx) {
            timer.active = false;
            return;
        }
    }
}

/// Busy-wait for the given number of milliseconds (blocking!)
/// Only use during early boot when the scheduler isn't running
pub fn busyWaitMs(ms: u32) void {
    const target = tick_count + msToTicks(ms);
    while (tick_count < target) {
        cpu.spinHint();
    }
}

/// Busy-wait for approximately the given number of microseconds
/// Uses I/O port delay for very short waits
pub fn busyWaitUs(us: u32) void {
    // Each I/O port read takes approximately 1μs
    var i: u32 = 0;
    while (i < us) : (i += 1) {
        cpu.ioWait();
    }
}
