// =============================================================================
// Kernel Zxyphor - Spinlock
// =============================================================================
// A simple ticket-based spinlock for SMP-safe mutual exclusion with
// interrupt disabling. Spinlocks are the fundamental synchronization
// primitive used throughout the kernel (PMM, VMM, heap, scheduler,
// process table, etc).
//
// This is a ticket lock (not test-and-set) which guarantees FIFO ordering
// and avoids starvation. On single-CPU systems, we rely on interrupt
// disabling alone, but the spinlock structure is still used for uniformity.
//
// Usage:
//     var lock = SpinLock.init();
//     lock.acquire();
//     defer lock.release();
//     // critical section
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// SpinLock
// =============================================================================
pub const SpinLock = struct {
    /// Next ticket to be taken by a waiter
    next_ticket: u32 = 0,
    /// Currently serving ticket number
    now_serving: u32 = 0,
    /// Saved interrupt flags (RFLAGS) before acquisition
    saved_flags: u64 = 0,
    /// Whether interrupts were enabled before acquire
    interrupts_were_enabled: bool = false,
    /// For debugging: owning CPU / thread ID
    owner: u32 = 0,
    /// Recursion depth (for reentrant usage diagnostics, not reentrant lock)
    held: bool = false,

    /// Create a new unlocked spinlock
    pub fn init() SpinLock {
        return SpinLock{};
    }

    /// Acquire the spinlock (disables interrupts, spins until ticket is served)
    pub fn acquire(self: *SpinLock) void {
        // Save and disable interrupts to prevent deadlock from interrupt handlers
        const flags = readFlags();
        disableInterrupts();

        // Take a ticket
        const my_ticket = @atomicRmw(u32, &self.next_ticket, .Add, 1, .seq_cst);

        // Spin until our ticket is being served
        while (@atomicLoad(u32, &self.now_serving, .acquire) != my_ticket) {
            // Busy-wait with PAUSE hint to reduce contention on the bus
            asm volatile ("pause");
        }

        self.saved_flags = flags;
        self.interrupts_were_enabled = (flags & 0x200) != 0;
        self.held = true;
    }

    /// Release the spinlock (restores previous interrupt state)
    pub fn release(self: *SpinLock) void {
        self.held = false;
        const restore_ints = self.interrupts_were_enabled;

        // Advance to the next ticket
        _ = @atomicRmw(u32, &self.now_serving, .Add, 1, .release);

        // Restore interrupt state
        if (restore_ints) {
            enableInterrupts();
        }
    }

    /// Try to acquire without spinning. Returns true if lock was acquired.
    pub fn tryAcquire(self: *SpinLock) bool {
        const flags = readFlags();
        disableInterrupts();

        const current = @atomicLoad(u32, &self.now_serving, .acquire);
        const next = @atomicLoad(u32, &self.next_ticket, .acquire);

        if (current == next) {
            // Lock is free — try to take a ticket
            if (@cmpxchgWeak(u32, &self.next_ticket, next, next + 1, .seq_cst, .monotonic) == null) {
                self.saved_flags = flags;
                self.interrupts_were_enabled = (flags & 0x200) != 0;
                self.held = true;
                return true;
            }
        }

        // Failed — restore interrupts
        if ((flags & 0x200) != 0) enableInterrupts();
        return false;
    }

    /// Check if the lock is currently held (not reliable for synchronization)
    pub fn isLocked(self: *const SpinLock) bool {
        return @atomicLoad(u32, &self.now_serving, .acquire) !=
            @atomicLoad(u32, &self.next_ticket, .acquire);
    }
};

// =============================================================================
// Read-Write Spinlock
// =============================================================================
// Allows concurrent readers but exclusive writers. Readers are not blocked
// by other readers, only by a writer. A writer blocks until all readers exit.
// =============================================================================
pub const RwSpinLock = struct {
    /// Positive = number of active readers, -1 = writer holds lock, 0 = free
    state: i32 = 0,
    /// Interrupt state
    saved_flags: u64 = 0,
    interrupts_were_enabled: bool = false,

    pub fn init() RwSpinLock {
        return RwSpinLock{};
    }

    /// Acquire reader lock (shared)
    pub fn readLock(self: *RwSpinLock) void {
        const flags = readFlags();
        disableInterrupts();

        while (true) {
            const current = @atomicLoad(i32, &self.state, .acquire);
            if (current >= 0) {
                if (@cmpxchgWeak(i32, &self.state, current, current + 1, .acquire, .monotonic) == null) {
                    self.saved_flags = flags;
                    self.interrupts_were_enabled = (flags & 0x200) != 0;
                    return;
                }
            }
            asm volatile ("pause");
        }
    }

    /// Release reader lock
    pub fn readUnlock(self: *RwSpinLock) void {
        const restore = self.interrupts_were_enabled;
        _ = @atomicRmw(i32, &self.state, .Sub, 1, .release);
        if (restore) enableInterrupts();
    }

    /// Acquire writer lock (exclusive)
    pub fn writeLock(self: *RwSpinLock) void {
        const flags = readFlags();
        disableInterrupts();

        while (true) {
            if (@cmpxchgWeak(i32, &self.state, 0, -1, .acquire, .monotonic) == null) {
                self.saved_flags = flags;
                self.interrupts_were_enabled = (flags & 0x200) != 0;
                return;
            }
            asm volatile ("pause");
        }
    }

    /// Release writer lock
    pub fn writeUnlock(self: *RwSpinLock) void {
        const restore = self.interrupts_were_enabled;
        @atomicStore(i32, &self.state, 0, .release);
        if (restore) enableInterrupts();
    }
};

// =============================================================================
// Per-CPU spinlock variant (for things like per-CPU run queues)
// Uses simple test-and-set for lower overhead on uncontended paths.
// =============================================================================
pub const SimpleSpinLock = struct {
    locked: u32 = 0,
    saved_flags: u64 = 0,
    interrupts_were_enabled: bool = false,

    pub fn init() SimpleSpinLock {
        return SimpleSpinLock{};
    }

    pub fn acquire(self: *SimpleSpinLock) void {
        const flags = readFlags();
        disableInterrupts();

        while (@atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) != 0) {
            while (@atomicLoad(u32, &self.locked, .monotonic) != 0) {
                asm volatile ("pause");
            }
        }

        self.saved_flags = flags;
        self.interrupts_were_enabled = (flags & 0x200) != 0;
    }

    pub fn release(self: *SimpleSpinLock) void {
        const restore = self.interrupts_were_enabled;
        @atomicStore(u32, &self.locked, 0, .release);
        if (restore) enableInterrupts();
    }

    pub fn tryAcquire(self: *SimpleSpinLock) bool {
        const flags = readFlags();
        disableInterrupts();

        if (@atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) == 0) {
            self.saved_flags = flags;
            self.interrupts_were_enabled = (flags & 0x200) != 0;
            return true;
        }
        if ((flags & 0x200) != 0) enableInterrupts();
        return false;
    }
};

// =============================================================================
// Arch-specific helpers
// =============================================================================
inline fn readFlags() u64 {
    return asm volatile ("pushfq; pop %[flags]"
        : [flags] "=r" (-> u64),
    );
}

inline fn disableInterrupts() void {
    asm volatile ("cli");
}

inline fn enableInterrupts() void {
    asm volatile ("sti");
}
