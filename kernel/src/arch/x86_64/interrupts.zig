// =============================================================================
// Kernel Zxyphor - x86_64 Interrupt Handling Utilities
// =============================================================================
// Additional interrupt management beyond the IDT setup. Provides interrupt
// enable/disable tracking, deferred interrupt handling (bottom halves),
// and interrupt statistics.
// =============================================================================

const main = @import("../../main.zig");

// =============================================================================
// Interrupt disable depth counter
// =============================================================================
// Supports nested disabling: if code disables interrupts twice, they won't
// be re-enabled until both enables are called. This prevents accidental
// re-enabling in nested critical sections.
// =============================================================================
var interrupt_disable_depth: u32 = 0;

/// Disable interrupts with nesting support
pub fn disableNested() void {
    main.arch.disableInterrupts();
    interrupt_disable_depth += 1;
}

/// Enable interrupts with nesting support — only re-enables when depth reaches 0
pub fn enableNested() void {
    if (interrupt_disable_depth > 0) {
        interrupt_disable_depth -= 1;
    }
    if (interrupt_disable_depth == 0) {
        main.arch.enableInterrupts();
    }
}

/// Get the current nesting depth
pub fn nestingDepth() u32 {
    return interrupt_disable_depth;
}

// =============================================================================
// Interrupt statistics — track how many times each vector fires
// =============================================================================
var interrupt_counts: [256]u64 = [_]u64{0} ** 256;

/// Called from the interrupt handler to record a hit
pub fn recordInterrupt(vector: u8) void {
    interrupt_counts[vector] +%= 1;
}

/// Get the count for a specific vector
pub fn getInterruptCount(vector: u8) u64 {
    return interrupt_counts[vector];
}

/// Get total interrupt count across all vectors
pub fn totalInterruptCount() u64 {
    var total: u64 = 0;
    for (interrupt_counts) |count| {
        total +%= count;
    }
    return total;
}

/// Reset all interrupt counters
pub fn resetCounters() void {
    @memset(&interrupt_counts, 0);
}

// =============================================================================
// Deferred work (bottom-half / softirq mechanism)
// =============================================================================
// Some interrupt handlers need to do work that's too expensive for the
// top-half (which runs with interrupts disabled). The deferred work queue
// allows registering callbacks that run with interrupts enabled, after
// the top-half returns.
// =============================================================================

pub const DeferredWorkFn = *const fn () void;

const MAX_DEFERRED_WORK = 64;

var deferred_queue: [MAX_DEFERRED_WORK]?DeferredWorkFn = [_]?DeferredWorkFn{null} ** MAX_DEFERRED_WORK;
var deferred_head: usize = 0;
var deferred_tail: usize = 0;
var deferred_pending: bool = false;

/// Schedule a function to run after the current interrupt handler returns
pub fn scheduleDeferred(func: DeferredWorkFn) bool {
    const next_head = (deferred_head + 1) % MAX_DEFERRED_WORK;
    if (next_head == deferred_tail) {
        return false; // Queue full
    }

    deferred_queue[deferred_head] = func;
    deferred_head = next_head;
    deferred_pending = true;
    return true;
}

/// Process all pending deferred work items
/// Called after returning from interrupt context
pub fn processDeferredWork() void {
    if (!deferred_pending) return;

    // Re-enable interrupts for bottom-half processing
    main.arch.enableInterrupts();

    while (deferred_tail != deferred_head) {
        if (deferred_queue[deferred_tail]) |func| {
            func();
            deferred_queue[deferred_tail] = null;
        }
        deferred_tail = (deferred_tail + 1) % MAX_DEFERRED_WORK;
    }

    deferred_pending = false;
}

/// Check if there's deferred work pending
pub fn hasDeferredWork() bool {
    return deferred_pending;
}

// =============================================================================
// Critical section guard — RAII-style interrupt disable/enable
// =============================================================================
pub const CriticalSection = struct {
    interrupts_were_enabled: bool,

    pub fn enter() CriticalSection {
        const were_enabled = main.arch.interruptsEnabled();
        main.arch.disableInterrupts();
        return CriticalSection{
            .interrupts_were_enabled = were_enabled,
        };
    }

    pub fn leave(self: CriticalSection) void {
        if (self.interrupts_were_enabled) {
            main.arch.enableInterrupts();
        }
    }
};

/// Execute a function with interrupts disabled, then restore the previous state
pub fn withInterruptsDisabled(comptime func: fn () void) void {
    const cs = CriticalSection.enter();
    defer cs.leave();
    func();
}
