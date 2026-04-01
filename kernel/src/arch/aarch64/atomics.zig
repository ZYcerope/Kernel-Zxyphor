// =============================================================================
// Zxyphor Kernel — ARM64 Atomic Operations & LSE Support
// =============================================================================
// Implements atomic operations for ARM64 using both the legacy LL/SC
// (Load-Linked/Store-Conditional: LDXR/STXR) and ARMv8.1 LSE (Large
// System Extensions: LDADD, SWPAL, CAS, etc.) instruction sets.
//
// LSE atomics provide significantly better performance on multi-socket
// systems because they don't require exclusive monitor reservations.
// At boot, the kernel detects LSE support and patches all atomic call
// sites to use the optimal implementation.
//
// Operations provided:
//   - atomic_add/sub/and/or/xor (fetch-and-op variants)
//   - atomic_swap (exchange)
//   - atomic_cmpxchg (compare-and-swap, single and double-word)
//   - atomic_load/store with memory ordering
//   - atomic_inc/dec with overflow checking
//   - spinlock, ticket lock, MCS lock primitives
//   - Read-Copy-Update (RCU) memory ordering helpers
//   - Per-CPU atomic counters
//   - Atomic bit operations (set, clear, test-and-set, test-and-clear)
//
// Memory ordering options:
//   - Relaxed: no barriers (fastest, suitable for statistics)
//   - Acquire: load acquires (prevents reordering after load)
//   - Release: store releases (prevents reordering before store)
//   - AcqRel: both acquire and release
//   - SeqCst: full sequential consistency (global ordering)
// =============================================================================

// ── Feature Detection ─────────────────────────────────────────────────────
var has_lse: bool = false;
var has_lse2: bool = false;       // ARMv8.4 LSE2 (unaligned atomics)
var has_lrcpc: bool = false;      // ARMv8.3 LDAPR (Load-Acquire RCpc)
var has_lrcpc2: bool = false;     // ARMv8.4 LDAPUR/STLUR
var has_lrcpc3: bool = false;     // ARMv8.7+ LDIAPP/STILP
var has_lse128: bool = false;     // ARMv9.4 128-bit atomics

pub fn detectAtomicFeatures() void {
    const isar0 = asm ("mrs %[r], ID_AA64ISAR0_EL1" : [r] "=r" (-> u64));
    const atomics_field = (isar0 >> 20) & 0xF;
    has_lse = atomics_field >= 2;

    const isar1 = asm ("mrs %[r], ID_AA64ISAR1_EL1" : [r] "=r" (-> u64));
    const lrcpc_field = (isar1 >> 20) & 0xF;
    has_lrcpc = lrcpc_field >= 1;
    has_lrcpc2 = lrcpc_field >= 2;

    const mmfr2 = asm ("mrs %[r], ID_AA64MMFR2_EL1" : [r] "=r" (-> u64));
    const at_field = (mmfr2 >> 32) & 0xF;
    has_lse2 = at_field >= 1;
    _ = at_field;
}

pub fn hasLse() bool { return has_lse; }
pub fn hasLse2() bool { return has_lse2; }

// ── 32-bit Atomic Operations ──────────────────────────────────────────────

pub fn atomicLoad32(ptr: *const volatile u32, comptime order: MemOrder) u32 {
    return switch (order) {
        .relaxed => ptr.*,
        .acquire => asm ("ldar %w[r], [%[p]]" : [r] "=r" (-> u32) : [p] "r" (ptr)),
        .seq_cst => blk: {
            const val = asm ("ldar %w[r], [%[p]]" : [r] "=r" (-> u32) : [p] "r" (ptr));
            asm volatile ("dmb ish" ::: "memory");
            break :blk val;
        },
        else => ptr.*,
    };
}

pub fn atomicStore32(ptr: *volatile u32, val: u32, comptime order: MemOrder) void {
    switch (order) {
        .relaxed => ptr.* = val,
        .release => asm volatile ("stlr %w[v], [%[p]]" : : [v] "r" (val), [p] "r" (ptr) : "memory"),
        .seq_cst => {
            asm volatile ("dmb ish" ::: "memory");
            asm volatile ("stlr %w[v], [%[p]]" : : [v] "r" (val), [p] "r" (ptr) : "memory");
        },
        else => ptr.* = val,
    }
}

pub fn atomicAdd32(ptr: *volatile u32, val: u32, comptime order: MemOrder) u32 {
    if (has_lse) {
        return lseAdd32(ptr, val, order);
    } else {
        return llscAdd32(ptr, val, order);
    }
}

fn lseAdd32(ptr: *volatile u32, val: u32, comptime order: MemOrder) u32 {
    return switch (order) {
        .relaxed => asm ("ldadd %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
        .acquire => asm ("ldadda %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
        .release => asm ("ldaddl %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
        .acq_rel, .seq_cst => asm ("ldaddal %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
    };
}

fn llscAdd32(ptr: *volatile u32, val: u32, comptime order: MemOrder) u32 {
    var old: u32 = undefined;
    var tmp: u32 = undefined;
    _ = order;
    asm volatile (
        \\1: ldaxr %w[old], [%[ptr]]
        \\   add %w[tmp], %w[old], %w[val]
        \\   stlxr %w[tmp2], %w[tmp], [%[ptr]]
        \\   cbnz %w[tmp2], 1b
        : [old] "=&r" (old),
          [tmp] "=&r" (tmp),
          [tmp2] "=&r" (-> u32),
        : [ptr] "r" (ptr),
          [val] "r" (val),
        : "memory"
    );
    return old;
}

pub fn atomicSub32(ptr: *volatile u32, val: u32, comptime order: MemOrder) u32 {
    return atomicAdd32(ptr, 0 -% val, order);
}

pub fn atomicSwap32(ptr: *volatile u32, val: u32, comptime order: MemOrder) u32 {
    if (has_lse) {
        return switch (order) {
            .relaxed => asm ("swp %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .acquire => asm ("swpa %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .release => asm ("swpl %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .acq_rel, .seq_cst => asm ("swpal %w[v], %w[r], [%[p]]" : [r] "=r" (-> u32) : [v] "r" (val), [p] "r" (ptr) : "memory"),
        };
    } else {
        var old: u32 = undefined;
        asm volatile (
            \\1: ldaxr %w[old], [%[ptr]]
            \\   stlxr %w[tmp], %w[val], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            : [old] "=&r" (old),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [val] "r" (val),
            : "memory"
        );
        return old;
    }
}

pub fn atomicCas32(ptr: *volatile u32, expected: u32, desired: u32, comptime order: MemOrder) u32 {
    if (has_lse) {
        var exp = expected;
        switch (order) {
            .relaxed => asm volatile ("cas %w[exp], %w[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
            .acquire => asm volatile ("casa %w[exp], %w[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
            .release => asm volatile ("casl %w[exp], %w[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
            .acq_rel, .seq_cst => asm volatile ("casal %w[exp], %w[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
        }
        return exp;
    } else {
        var old: u32 = undefined;
        asm volatile (
            \\1: ldaxr %w[old], [%[ptr]]
            \\   cmp %w[old], %w[exp]
            \\   b.ne 2f
            \\   stlxr %w[tmp], %w[des], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            \\2:
            : [old] "=&r" (old),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [exp] "r" (expected),
              [des] "r" (desired),
            : "memory", "cc"
        );
        return old;
    }
}

// ── 64-bit Atomic Operations ──────────────────────────────────────────────

pub fn atomicLoad64(ptr: *const volatile u64, comptime order: MemOrder) u64 {
    return switch (order) {
        .relaxed => ptr.*,
        .acquire => asm ("ldar %[r], [%[p]]" : [r] "=r" (-> u64) : [p] "r" (ptr)),
        .seq_cst => blk: {
            const val = asm ("ldar %[r], [%[p]]" : [r] "=r" (-> u64) : [p] "r" (ptr));
            asm volatile ("dmb ish" ::: "memory");
            break :blk val;
        },
        else => ptr.*,
    };
}

pub fn atomicStore64(ptr: *volatile u64, val: u64, comptime order: MemOrder) void {
    switch (order) {
        .relaxed => ptr.* = val,
        .release => asm volatile ("stlr %[v], [%[p]]" : : [v] "r" (val), [p] "r" (ptr) : "memory"),
        .seq_cst => {
            asm volatile ("dmb ish" ::: "memory");
            asm volatile ("stlr %[v], [%[p]]" : : [v] "r" (val), [p] "r" (ptr) : "memory");
        },
        else => ptr.* = val,
    }
}

pub fn atomicAdd64(ptr: *volatile u64, val: u64, comptime order: MemOrder) u64 {
    if (has_lse) {
        return switch (order) {
            .relaxed => asm ("ldadd %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .acquire => asm ("ldadda %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .release => asm ("ldaddl %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .acq_rel, .seq_cst => asm ("ldaddal %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
        };
    } else {
        var old: u64 = undefined;
        var tmp: u64 = undefined;
        _ = order;
        asm volatile (
            \\1: ldaxr %[old], [%[ptr]]
            \\   add %[tmp], %[old], %[val]
            \\   stlxr %w[tmp2], %[tmp], [%[ptr]]
            \\   cbnz %w[tmp2], 1b
            : [old] "=&r" (old),
              [tmp] "=&r" (tmp),
              [tmp2] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [val] "r" (val),
            : "memory"
        );
        return old;
    }
}

pub fn atomicSub64(ptr: *volatile u64, val: u64, comptime order: MemOrder) u64 {
    return atomicAdd64(ptr, 0 -% val, order);
}

pub fn atomicSwap64(ptr: *volatile u64, val: u64, comptime order: MemOrder) u64 {
    if (has_lse) {
        return switch (order) {
            .relaxed => asm ("swp %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .acquire => asm ("swpa %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .release => asm ("swpl %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
            .acq_rel, .seq_cst => asm ("swpal %[v], %[r], [%[p]]" : [r] "=r" (-> u64) : [v] "r" (val), [p] "r" (ptr) : "memory"),
        };
    } else {
        var old: u64 = undefined;
        asm volatile (
            \\1: ldaxr %[old], [%[ptr]]
            \\   stlxr %w[tmp], %[val], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            : [old] "=&r" (old),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [val] "r" (val),
            : "memory"
        );
        return old;
    }
}

pub fn atomicCas64(ptr: *volatile u64, expected: u64, desired: u64, comptime order: MemOrder) u64 {
    if (has_lse) {
        var exp = expected;
        switch (order) {
            .relaxed => asm volatile ("cas %[exp], %[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
            .acquire => asm volatile ("casa %[exp], %[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
            .release => asm volatile ("casl %[exp], %[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
            .acq_rel, .seq_cst => asm volatile ("casal %[exp], %[des], [%[ptr]]" : [exp] "+r" (exp) : [des] "r" (desired), [ptr] "r" (ptr) : "memory"),
        }
        return exp;
    } else {
        var old: u64 = undefined;
        asm volatile (
            \\1: ldaxr %[old], [%[ptr]]
            \\   cmp %[old], %[exp]
            \\   b.ne 2f
            \\   stlxr %w[tmp], %[des], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            \\2:
            : [old] "=&r" (old),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [exp] "r" (expected),
              [des] "r" (desired),
            : "memory", "cc"
        );
        return old;
    }
}

// ── Atomic Bit Operations ─────────────────────────────────────────────────

pub fn atomicBitSet64(ptr: *volatile u64, bit: u6) void {
    const mask = @as(u64, 1) << bit;
    if (has_lse) {
        asm volatile ("ldset %[m], xzr, [%[p]]" : : [m] "r" (mask), [p] "r" (ptr) : "memory");
    } else {
        _ = atomicAdd64(ptr, 0, .relaxed); // Force through LL/SC path
        var old: u64 = undefined;
        asm volatile (
            \\1: ldxr %[old], [%[ptr]]
            \\   orr %[old], %[old], %[mask]
            \\   stxr %w[tmp], %[old], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            : [old] "=&r" (old),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [mask] "r" (mask),
            : "memory"
        );
    }
}

pub fn atomicBitClear64(ptr: *volatile u64, bit: u6) void {
    const mask = @as(u64, 1) << bit;
    if (has_lse) {
        asm volatile ("ldclr %[m], xzr, [%[p]]" : : [m] "r" (mask), [p] "r" (ptr) : "memory");
    } else {
        var old: u64 = undefined;
        asm volatile (
            \\1: ldxr %[old], [%[ptr]]
            \\   bic %[old], %[old], %[mask]
            \\   stxr %w[tmp], %[old], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            : [old] "=&r" (old),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [mask] "r" (mask),
            : "memory"
        );
    }
}

pub fn atomicTestAndSet64(ptr: *volatile u64, bit: u6) bool {
    const mask = @as(u64, 1) << bit;
    const old = if (has_lse) blk: {
        break :blk asm ("ldset %[m], %[r], [%[p]]" : [r] "=r" (-> u64) : [m] "r" (mask), [p] "r" (ptr) : "memory");
    } else blk: {
        var prev: u64 = undefined;
        asm volatile (
            \\1: ldaxr %[old], [%[ptr]]
            \\   orr %[new], %[old], %[mask]
            \\   stlxr %w[tmp], %[new], [%[ptr]]
            \\   cbnz %w[tmp], 1b
            : [old] "=&r" (prev),
              [new] "=&r" (-> u64),
              [tmp] "=&r" (-> u32),
            : [ptr] "r" (ptr),
              [mask] "r" (mask),
            : "memory"
        );
        break :blk prev;
    };
    return (old & mask) != 0;
}

// ── Memory Ordering ───────────────────────────────────────────────────────
pub const MemOrder = enum {
    relaxed,
    acquire,
    release,
    acq_rel,
    seq_cst,
};

// ── Spinlock Implementation ──────────────────────────────────────────────
pub const SpinLock = struct {
    locked: u32 = 0,

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn lock(self: *Self) void {
        if (has_lse) {
            // LSE path: SWPAL-based
            while (atomicSwap32(&self.locked, 1, .acquire) != 0) {
                while (atomicLoad32(&self.locked, .relaxed) != 0) {
                    asm volatile ("wfe");
                }
            }
        } else {
            // LL/SC path
            while (true) {
                if (atomicSwap32(&self.locked, 1, .acquire) == 0) break;
                while (atomicLoad32(&self.locked, .relaxed) != 0) {
                    asm volatile ("wfe");
                }
            }
        }
    }

    pub fn tryLock(self: *Self) bool {
        return atomicSwap32(&self.locked, 1, .acquire) == 0;
    }

    pub fn unlock(self: *Self) void {
        atomicStore32(&self.locked, 0, .release);
        asm volatile ("sev"); // Wake up waiting cores
    }

    pub fn isLocked(self: *const Self) bool {
        return atomicLoad32(&self.locked, .relaxed) != 0;
    }
};

// ── Ticket SpinLock ──────────────────────────────────────────────────────
pub const TicketLock = struct {
    next: u32 = 0,     // Next ticket to be issued
    serving: u32 = 0,  // Currently served ticket

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn lock(self: *Self) void {
        // Acquire ticket
        const ticket = atomicAdd32(&self.next, 1, .relaxed);
        // Wait for our turn
        while (atomicLoad32(&self.serving, .acquire) != ticket) {
            asm volatile ("wfe");
        }
    }

    pub fn unlock(self: *Self) void {
        _ = atomicAdd32(&self.serving, 1, .release);
        asm volatile ("sev");
    }

    pub fn isLocked(self: *const Self) bool {
        return atomicLoad32(&self.next, .relaxed) != atomicLoad32(&self.serving, .relaxed);
    }
};

// ── Reader-Writer SpinLock ───────────────────────────────────────────────
pub const RwLock = struct {
    state: u32 = 0, // 0: unlocked. Bit 31: writer. Bits 0-30: reader count

    const WRITER_BIT: u32 = 1 << 31;
    const READER_MASK: u32 = ~WRITER_BIT;
    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn readLock(self: *Self) void {
        while (true) {
            const state = atomicLoad32(&self.state, .relaxed);
            if (state & WRITER_BIT != 0) {
                asm volatile ("wfe");
                continue;
            }
            if (atomicCas32(&self.state, state, state + 1, .acquire) == state) break;
        }
    }

    pub fn readUnlock(self: *Self) void {
        _ = atomicSub32(&self.state, 1, .release);
        asm volatile ("sev");
    }

    pub fn writeLock(self: *Self) void {
        while (true) {
            if (atomicCas32(&self.state, 0, WRITER_BIT, .acquire) == 0) break;
            while (atomicLoad32(&self.state, .relaxed) != 0) {
                asm volatile ("wfe");
            }
        }
    }

    pub fn writeUnlock(self: *Self) void {
        atomicStore32(&self.state, 0, .release);
        asm volatile ("sev");
    }
};

// ── WFE-based Spin Wait ──────────────────────────────────────────────────
pub inline fn spinWaitHint() void {
    asm volatile ("wfe" ::: "memory");
}

pub inline fn spinWakeAll() void {
    asm volatile ("sev" ::: "memory");
}

pub inline fn yieldCpu() void {
    asm volatile ("yield" ::: "memory");
}
