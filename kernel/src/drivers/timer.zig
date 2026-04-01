// =============================================================================
// Kernel Zxyphor - Timer Abstraction Layer
// =============================================================================
// Provides a unified timer interface that abstracts over the hardware timer
// sources (PIT, APIC timer, HPET). Higher-level code uses this module
// instead of directly accessing PIT or APIC.
//
// Features:
//   - Monotonic system clock (ticks since boot)
//   - Wall-clock time (via RTC synchronization)
//   - One-shot and periodic software timers
//   - Sleep functionality
//   - Uptime tracking
//   - Timer wheel for efficient expiry management
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
const TICKS_PER_SECOND: u64 = 1000;
const MAX_TIMERS: usize = 256;
const TIMER_WHEEL_SLOTS: usize = 256;

// =============================================================================
// Timer sources
// =============================================================================
pub const TimerSource = enum {
    pit,
    apic,
    hpet,
    tsc,
};

// =============================================================================
// Software timer
// =============================================================================
pub const Timer = struct {
    id: u32 = 0,
    expires_at: u64 = 0, // Tick count at which this timer fires
    interval: u64 = 0, // For periodic timers, the repeat interval (0 = one-shot)
    callback: ?*const fn (data: ?*anyopaque) void = null,
    data: ?*anyopaque = null,
    active: bool = false,
    periodic: bool = false,
};

// =============================================================================
// State
// =============================================================================
var system_ticks: u64 = 0;
var boot_time_epoch: u64 = 0; // Unix timestamp at boot
var current_source: TimerSource = .pit;

// Timer pool
var timer_pool: [MAX_TIMERS]Timer = undefined;
var next_timer_id: u32 = 1;

// Timer wheel — each slot holds the index of the first timer in a linked chain
// This is a simplified version; real implementations use hierarchical wheels
var timer_wheel: [TIMER_WHEEL_SLOTS]?u32 = [_]?u32{null} ** TIMER_WHEEL_SLOTS;

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    system_ticks = 0;
    next_timer_id = 1;

    for (&timer_pool) |*t| {
        t.* = Timer{};
    }

    // Synchronize with RTC to get boot time
    syncWithRtc();

    main.klog(.info, "timer: initialized (source={s}, {d} Hz)", .{
        @tagName(current_source),
        TICKS_PER_SECOND,
    });
}

// =============================================================================
// Tick handler — called from the hardware timer IRQ
// =============================================================================
pub fn tick() void {
    system_ticks += 1;

    // Check the current wheel slot for expired timers
    const slot = system_ticks % TIMER_WHEEL_SLOTS;
    processSlot(slot);
}

fn processSlot(slot: usize) void {
    // Check all timers in this slot
    for (&timer_pool) |*t| {
        if (t.active and t.expires_at <= system_ticks) {
            // Timer expired — fire callback
            if (t.callback) |cb| {
                cb(t.data);
            }

            if (t.periodic and t.interval > 0) {
                // Reschedule periodic timer
                t.expires_at = system_ticks + t.interval;
            } else {
                // One-shot: deactivate
                t.active = false;
            }
        }
    }
    _ = slot;
}

// =============================================================================
// Create timers
// =============================================================================

/// Create a one-shot timer that fires after `delay_ms` milliseconds
pub fn createOneShotMs(delay_ms: u64, callback: *const fn (?*anyopaque) void, data: ?*anyopaque) ?u32 {
    return createTimer(delay_ms, 0, callback, data, false);
}

/// Create a periodic timer that fires every `interval_ms` milliseconds
pub fn createPeriodicMs(interval_ms: u64, callback: *const fn (?*anyopaque) void, data: ?*anyopaque) ?u32 {
    return createTimer(interval_ms, interval_ms, callback, data, true);
}

fn createTimer(
    delay_ms: u64,
    interval_ms: u64,
    callback: *const fn (?*anyopaque) void,
    data: ?*anyopaque,
    periodic: bool,
) ?u32 {
    for (&timer_pool) |*t| {
        if (!t.active) {
            t.id = next_timer_id;
            next_timer_id += 1;
            t.expires_at = system_ticks + delay_ms;
            t.interval = interval_ms;
            t.callback = callback;
            t.data = data;
            t.active = true;
            t.periodic = periodic;
            return t.id;
        }
    }
    return null; // No free timer slots
}

/// Cancel a timer by ID
pub fn cancel(timer_id: u32) bool {
    for (&timer_pool) |*t| {
        if (t.active and t.id == timer_id) {
            t.active = false;
            return true;
        }
    }
    return false;
}

// =============================================================================
// Time queries
// =============================================================================

/// Get the number of ticks since boot
pub fn getTicks() u64 {
    return system_ticks;
}

/// Get uptime in seconds
pub fn getUptimeSeconds() u64 {
    return system_ticks / TICKS_PER_SECOND;
}

/// Get uptime in milliseconds
pub fn getUptimeMs() u64 {
    return system_ticks;
}

/// Get the current Unix timestamp (approximate)
pub fn getUnixTimestamp() u64 {
    return boot_time_epoch + getUptimeSeconds();
}

/// Get uptime as hours:minutes:seconds
pub fn getUptime() struct { hours: u64, minutes: u64, seconds: u64 } {
    const total_secs = getUptimeSeconds();
    return .{
        .hours = total_secs / 3600,
        .minutes = (total_secs % 3600) / 60,
        .seconds = total_secs % 60,
    };
}

// =============================================================================
// Sleep (blocking)
// =============================================================================

/// Sleep for `ms` milliseconds (busy-wait)
pub fn sleepMs(ms: u64) void {
    const target = system_ticks + ms;
    while (system_ticks < target) {
        main.cpu.halt(); // Wait for next tick interrupt
    }
}

/// Sleep for `us` microseconds (approximate, busy-wait)
pub fn sleepUs(us: u64) void {
    // Convert to ticks (each tick = 1ms = 1000us)
    const ms = (us + 999) / 1000;
    sleepMs(ms);
}

// =============================================================================
// RTC synchronization
// =============================================================================
fn syncWithRtc() void {
    // TODO: Read the RTC to get the current date/time and convert to Unix epoch
    // For now, use a placeholder
    boot_time_epoch = 1735689600; // 2025-01-01 00:00:00 UTC (placeholder)
}

/// Set the timer source (e.g., switch from PIT to APIC timer)
pub fn setSource(source: TimerSource) void {
    current_source = source;
    main.klog(.info, "timer: switched to {s} source", .{@tagName(source)});
}

/// Get current timer source
pub fn getSource() TimerSource {
    return current_source;
}

/// Count of active timers
pub fn activeTimerCount() u32 {
    var count: u32 = 0;
    for (timer_pool) |t| {
        if (t.active) count += 1;
    }
    return count;
}
