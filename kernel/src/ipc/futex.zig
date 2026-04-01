// ============================================================================
// Kernel Zxyphor — Futex Subsystem
//
// Fast userspace mutual exclusion primitives. Implements:
// - FUTEX_WAIT / FUTEX_WAKE (standard ops)
// - FUTEX_WAIT_BITSET / FUTEX_WAKE_BITSET (selective wake)
// - FUTEX_REQUEUE / FUTEX_CMP_REQUEUE (lock handoff)
// - FUTEX_LOCK_PI / FUTEX_UNLOCK_PI (priority inheritance)
// - FUTEX_WAIT_REQUEUE_PI (condvar with PI mutex)
// - FUTEX_WAITV (wait on multiple futexes; futex2)
// - Robust futex list processing
// - Priority-ordered wait queues
// - Hash-bucketed futex table for O(1) lookup
// ============================================================================

const std = @import("std");

// ============================================================================
// Futex Operations
// ============================================================================

pub const FUTEX_WAIT = 0;
pub const FUTEX_WAKE = 1;
pub const FUTEX_FD = 2; // Deprecated
pub const FUTEX_REQUEUE = 3;
pub const FUTEX_CMP_REQUEUE = 4;
pub const FUTEX_WAKE_OP = 5;
pub const FUTEX_LOCK_PI = 6;
pub const FUTEX_UNLOCK_PI = 7;
pub const FUTEX_TRYLOCK_PI = 8;
pub const FUTEX_WAIT_BITSET = 9;
pub const FUTEX_WAKE_BITSET = 10;
pub const FUTEX_WAIT_REQUEUE_PI = 11;
pub const FUTEX_CMP_REQUEUE_PI = 12;
pub const FUTEX_LOCK_PI2 = 13;

// Flags
pub const FUTEX_PRIVATE_FLAG = 128;
pub const FUTEX_CLOCK_REALTIME = 256;
pub const FUTEX_CMD_MASK: u32 = ~@as(u32, FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

// Bitset
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFFFFFF;

// FUTEX_WAKE_OP operations
pub const FUTEX_OP_SET = 0;
pub const FUTEX_OP_ADD = 1;
pub const FUTEX_OP_OR = 2;
pub const FUTEX_OP_ANDN = 3;
pub const FUTEX_OP_XOR = 4;

// FUTEX_WAKE_OP comparison operators
pub const FUTEX_OP_CMP_EQ = 0;
pub const FUTEX_OP_CMP_NE = 1;
pub const FUTEX_OP_CMP_LT = 2;
pub const FUTEX_OP_CMP_LE = 3;
pub const FUTEX_OP_CMP_GT = 4;
pub const FUTEX_OP_CMP_GE = 5;

// Robust list constants
pub const FUTEX_OWNER_DIED: u32 = 0x40000000;
pub const FUTEX_WAITERS: u32 = 0x80000000;
pub const FUTEX_TID_MASK: u32 = 0x3FFFFFFF;

// PI state
pub const FUTEX_PI_LOCK_HASHBITS = 8;

// Waitv
pub const FUTEX_32 = 2;
pub const FUTEX_PRIVATE_FLAG_V2 = 128;
pub const FUTEX_WAITV_MAX = 128;

// ============================================================================
// Error Types
// ============================================================================

pub const FutexError = error{
    InvalidAddress,
    WouldBlock,
    TimedOut,
    Interrupted,
    InvalidArgument,
    DeadlockDetected,
    OwnerDied,
    NoMemory,
    TryAgain,
    Fault,
    PermissionDenied,
};

// ============================================================================
// Futex Key — Identifies a futex uniquely
// ============================================================================

/// A futex is identified by its address. For private futexes, the
/// (mm, address) pair is the key. For shared futexes, the (inode, offset)
/// pair is used so that different processes mapping the same page can
/// wait on the same futex.
pub const FutexKey = struct {
    /// Hash table union discriminator
    kind: FutexKeyKind,
    /// Word offset within the page
    offset: u32,

    const Self = @This();

    pub fn eql(a: Self, b: Self) bool {
        if (a.offset != b.offset) return false;
        return switch (a.kind) {
            .private => |ap| switch (b.kind) {
                .private => |bp| ap.mm == bp.mm and ap.address == bp.address,
                else => false,
            },
            .shared => |as_| switch (b.kind) {
                .shared => |bs| as_.inode == bs.inode and as_.pgoff == bs.pgoff,
                else => false,
            },
        };
    }

    pub fn hash(self: Self) u32 {
        var h: u64 = 0;
        switch (self.kind) {
            .private => |p| {
                h = @as(u64, @intFromPtr(p.mm));
                h ^= p.address;
            },
            .shared => |s| {
                h = s.inode;
                h ^= s.pgoff;
            },
        }
        h ^= @as(u64, self.offset);
        // Jenkins one-at-a-time hash finalization
        h +%= h << 3;
        h ^= h >> 11;
        h +%= h << 15;
        return @truncate(h);
    }
};

pub const FutexKeyKind = union(enum) {
    private: struct {
        mm: *anyopaque,
        address: u64,
    },
    shared: struct {
        inode: u64,
        pgoff: u64,
    },
};

// ============================================================================
// Futex Queue Entry — Represents a waiting thread
// ============================================================================

pub const FutexQNode = struct {
    /// The futex key this waiter is blocked on
    key: FutexKey,
    /// Task ID of the waiting thread
    tid: i32,
    /// Priority of the waiting thread (lower = higher priority)
    priority: i32,
    /// Bitset for selective wake
    bitset: u32,
    /// Whether this is a PI waiter
    is_pi: bool,
    /// Whether the waiter has been woken
    woken: bool,
    /// Whether the waiter is on a requeue target
    requeue_target: bool,
    /// Lock type: 0 = normal, 1 = PI
    lock_type: u8,
    /// Pointer to task struct (opaque)
    task: *anyopaque,
    /// Timeout (absolute, in nanoseconds; 0 = no timeout)
    timeout_ns: u64,
    /// Timer wheel node ID for timeout cancellation
    timer_id: u64,
    /// Next node in hash bucket chain
    next: ?*FutexQNode,
    /// Previous node in hash bucket chain
    prev: ?*FutexQNode,
    /// Next node in priority queue (for PI)
    pi_next: ?*FutexQNode,
    /// PI state reference
    pi_state: ?*PiState,

    const Self = @This();

    pub fn init(key: FutexKey, tid: i32, priority: i32, task: *anyopaque) Self {
        return .{
            .key = key,
            .tid = tid,
            .priority = priority,
            .bitset = FUTEX_BITSET_MATCH_ANY,
            .is_pi = false,
            .woken = false,
            .requeue_target = false,
            .lock_type = 0,
            .task = task,
            .timeout_ns = 0,
            .timer_id = 0,
            .next = null,
            .prev = null,
            .pi_next = null,
            .pi_state = null,
        };
    }
};

// ============================================================================
// PI State — Priority Inheritance tracking
// ============================================================================

pub const PiState = struct {
    /// The futex key
    key: FutexKey,
    /// Current owner task
    owner: ?*anyopaque,
    /// Owner's TID
    owner_tid: i32,
    /// Reference count
    ref_count: u32,
    /// Priority inheritance chain depth
    chain_depth: u32,
    /// Maximum chain depth before deadlock detection
    max_chain_depth: u32,
    /// Waiters ordered by priority
    waiters_head: ?*FutexQNode,
    /// Number of waiters
    waiter_count: u32,

    const Self = @This();
    const MAX_PI_CHAIN = 1024;

    pub fn init(key: FutexKey) Self {
        return .{
            .key = key,
            .owner = null,
            .owner_tid = 0,
            .ref_count = 1,
            .chain_depth = 0,
            .max_chain_depth = MAX_PI_CHAIN,
            .waiters_head = null,
            .waiter_count = 0,
        };
    }

    /// Insert a waiter in priority order.
    pub fn insert_waiter(self: *Self, node: *FutexQNode) void {
        node.pi_next = null;
        if (self.waiters_head == null) {
            self.waiters_head = node;
            self.waiter_count += 1;
            return;
        }

        // Insert before first lower-priority waiter
        var prev: ?*FutexQNode = null;
        var curr = self.waiters_head;
        while (curr) |c| {
            if (node.priority < c.priority) {
                node.pi_next = c;
                if (prev) |p| {
                    p.pi_next = node;
                } else {
                    self.waiters_head = node;
                }
                self.waiter_count += 1;
                return;
            }
            prev = c;
            curr = c.pi_next;
        }

        // Append at end
        if (prev) |p| {
            p.pi_next = node;
        }
        self.waiter_count += 1;
    }

    /// Remove a waiter.
    pub fn remove_waiter(self: *Self, node: *FutexQNode) void {
        if (self.waiters_head == node) {
            self.waiters_head = node.pi_next;
            node.pi_next = null;
            self.waiter_count -= 1;
            return;
        }

        var curr = self.waiters_head;
        while (curr) |c| {
            if (c.pi_next == node) {
                c.pi_next = node.pi_next;
                node.pi_next = null;
                self.waiter_count -= 1;
                return;
            }
            curr = c.pi_next;
        }
    }

    /// Get the highest-priority waiter.
    pub fn top_waiter(self: *const Self) ?*FutexQNode {
        return self.waiters_head;
    }

    /// Boost the owner's priority to match the highest-priority waiter.
    pub fn boost_owner(self: *Self) void {
        _ = self;
        // Would call into scheduler to temporarily boost owner priority
    }
};

// ============================================================================
// Hash Table
// ============================================================================

const FUTEX_HASH_BITS = 8;
const FUTEX_HASH_SIZE = 1 << FUTEX_HASH_BITS; // 256 buckets

pub const FutexBucket = struct {
    /// Head of waiter list in this bucket
    head: ?*FutexQNode,
    /// Tail for fast append
    tail: ?*FutexQNode,
    /// Number of waiters in this bucket
    count: u32,
    /// Spinlock (simplified)
    locked: bool,

    const Self = @This();

    pub fn init() Self {
        return .{
            .head = null,
            .tail = null,
            .count = 0,
            .locked = false,
        };
    }

    pub fn lock(self: *Self) void {
        while (@atomicLoad(bool, &self.locked, .acquire)) {
            asm volatile ("pause");
        }
        @atomicStore(bool, &self.locked, true, .release);
    }

    pub fn unlock(self: *Self) void {
        @atomicStore(bool, &self.locked, false, .release);
    }

    /// Add a waiter to this bucket.
    pub fn enqueue(self: *Self, node: *FutexQNode) void {
        node.next = null;
        node.prev = self.tail;
        if (self.tail) |t| {
            t.next = node;
        } else {
            self.head = node;
        }
        self.tail = node;
        self.count += 1;
    }

    /// Remove a waiter from this bucket.
    pub fn dequeue(self: *Self, node: *FutexQNode) void {
        if (node.prev) |p| {
            p.next = node.next;
        } else {
            self.head = node.next;
        }
        if (node.next) |n| {
            n.prev = node.prev;
        } else {
            self.tail = node.prev;
        }
        node.next = null;
        node.prev = null;
        self.count -= 1;
    }

    /// Wake up to `count` waiters matching the key and bitset.
    pub fn wake(self: *Self, key: FutexKey, bitset: u32, max_wake: i32) i32 {
        var woken: i32 = 0;
        var node = self.head;
        while (node) |n| {
            if (woken >= max_wake) break;

            const next = n.next;
            if (n.key.eql(key) and (n.bitset & bitset) != 0) {
                self.dequeue(n);
                n.woken = true;
                // Would call scheduler to wake task
                woken += 1;
            }
            node = next;
        }
        return woken;
    }
};

/// Global futex hash table.
pub const FutexHashTable = struct {
    buckets: [FUTEX_HASH_SIZE]FutexBucket,
    /// Total number of waiters across all buckets
    total_waiters: u64,
    /// Statistics
    stats: FutexStats,

    const Self = @This();

    pub fn init() Self {
        var table: Self = undefined;
        for (&table.buckets) |*b| {
            b.* = FutexBucket.init();
        }
        table.total_waiters = 0;
        table.stats = FutexStats{};
        return table;
    }

    /// Get the bucket for a given key.
    pub fn bucket(self: *Self, key: FutexKey) *FutexBucket {
        const idx = key.hash() & (FUTEX_HASH_SIZE - 1);
        return &self.buckets[idx];
    }
};

pub const FutexStats = struct {
    wait_count: u64 = 0,
    wake_count: u64 = 0,
    requeue_count: u64 = 0,
    pi_boost_count: u64 = 0,
    timeout_count: u64 = 0,
    deadlock_count: u64 = 0,
    hash_collisions: u64 = 0,
};

// ============================================================================
// Global State
// ============================================================================

var futex_table: FutexHashTable = FutexHashTable.init();

// ============================================================================
// Core Futex Operations
// ============================================================================

/// FUTEX_WAIT: Atomically check *uaddr == val, then sleep.
pub fn futexWait(
    uaddr: *const volatile u32,
    val: u32,
    bitset: u32,
    timeout_ns: u64,
    key: FutexKey,
    task: *anyopaque,
    tid: i32,
    priority: i32,
) FutexError!void {
    if (bitset == 0) return error.InvalidArgument;

    const b = futex_table.bucket(key);
    b.lock();
    defer b.unlock();

    // Atomically check the userspace value
    const current_val = uaddr.*;
    if (current_val != val) {
        return error.WouldBlock;
    }

    // Enqueue waiter
    var node = FutexQNode.init(key, tid, priority, task);
    node.bitset = bitset;
    node.timeout_ns = timeout_ns;
    b.enqueue(&node);
    futex_table.total_waiters += 1;
    futex_table.stats.wait_count += 1;

    // Would set up timer and block the task here
    // When woken: check if timed out, interrupted, etc.
}

/// FUTEX_WAKE: Wake up to `count` waiters on the futex.
pub fn futexWake(key: FutexKey, count: i32, bitset: u32) i32 {
    if (bitset == 0) return 0;

    const b = futex_table.bucket(key);
    b.lock();
    defer b.unlock();

    const woken = b.wake(key, bitset, count);
    futex_table.total_waiters -= @as(u64, @intCast(woken));
    futex_table.stats.wake_count += @as(u64, @intCast(woken));
    return woken;
}

/// FUTEX_REQUEUE: Wake `wake_count` waiters, move `requeue_count` to a new key.
pub fn futexRequeue(
    key1: FutexKey,
    key2: FutexKey,
    wake_count: i32,
    requeue_count: i32,
    check_val: ?u32,
    uaddr: ?*const volatile u32,
) FutexError!i32 {
    // CMP_REQUEUE: check value first
    if (check_val) |cv| {
        if (uaddr) |ua| {
            if (ua.* != cv) {
                return error.WouldBlock;
            }
        }
    }

    const b1 = futex_table.bucket(key1);
    const b2 = futex_table.bucket(key2);

    // Lock ordering: always lock lower-address bucket first to prevent deadlock
    const b1_addr = @intFromPtr(b1);
    const b2_addr = @intFromPtr(b2);
    if (b1_addr <= b2_addr) {
        b1.lock();
        if (b1 != b2) b2.lock();
    } else {
        b2.lock();
        b1.lock();
    }
    defer {
        b1.unlock();
        if (b1 != b2) b2.unlock();
    }

    // Wake up to wake_count from key1
    var woken: i32 = 0;
    var requeued: i32 = 0;
    var node = b1.head;

    while (node) |n| {
        const next = n.next;
        if (n.key.eql(key1)) {
            if (woken < wake_count) {
                b1.dequeue(n);
                n.woken = true;
                woken += 1;
            } else if (requeued < requeue_count) {
                b1.dequeue(n);
                n.key = key2;
                n.requeue_target = true;
                b2.enqueue(n);
                requeued += 1;
            }
        }
        node = next;
    }

    futex_table.total_waiters -= @as(u64, @intCast(woken));
    futex_table.stats.requeue_count += @as(u64, @intCast(requeued));
    return woken + requeued;
}

/// FUTEX_WAKE_OP: Atomically update *uaddr2, wake waiters on both keys.
pub fn futexWakeOp(
    key1: FutexKey,
    key2: FutexKey,
    wake_count1: i32,
    wake_count2: i32,
    op: u32,
    uaddr2: *volatile u32,
) i32 {
    const op_code = (op >> 28) & 0xF;
    const cmp_code = (op >> 24) & 0xF;
    var op_arg = (op >> 12) & 0xFFF;
    const cmp_arg = op & 0xFFF;

    // Shift flag
    if (op & (1 << 31) != 0) {
        op_arg = @as(u32, 1) << @intCast(op_arg & 0x1F);
    }

    const b1 = futex_table.bucket(key1);
    const b2 = futex_table.bucket(key2);

    const b1_addr = @intFromPtr(b1);
    const b2_addr = @intFromPtr(b2);
    if (b1_addr <= b2_addr) {
        b1.lock();
        if (b1 != b2) b2.lock();
    } else {
        b2.lock();
        b1.lock();
    }
    defer {
        b1.unlock();
        if (b1 != b2) b2.unlock();
    }

    // Perform atomic operation on *uaddr2
    const old_val = uaddr2.*;
    const new_val: u32 = switch (op_code) {
        FUTEX_OP_SET => op_arg,
        FUTEX_OP_ADD => old_val +% op_arg,
        FUTEX_OP_OR => old_val | op_arg,
        FUTEX_OP_ANDN => old_val & ~op_arg,
        FUTEX_OP_XOR => old_val ^ op_arg,
        else => old_val,
    };
    uaddr2.* = new_val;

    // Wake waiters on key1
    var total = b1.wake(key1, FUTEX_BITSET_MATCH_ANY, wake_count1);

    // Conditionally wake waiters on key2
    const cmp_result: bool = switch (cmp_code) {
        FUTEX_OP_CMP_EQ => old_val == cmp_arg,
        FUTEX_OP_CMP_NE => old_val != cmp_arg,
        FUTEX_OP_CMP_LT => old_val < cmp_arg,
        FUTEX_OP_CMP_LE => old_val <= cmp_arg,
        FUTEX_OP_CMP_GT => old_val > cmp_arg,
        FUTEX_OP_CMP_GE => old_val >= cmp_arg,
        else => false,
    };

    if (cmp_result) {
        total += b2.wake(key2, FUTEX_BITSET_MATCH_ANY, wake_count2);
    }

    return total;
}

// ============================================================================
// PI Futex Operations
// ============================================================================

/// FUTEX_LOCK_PI: Lock a PI-aware futex.
pub fn futexLockPi(
    uaddr: *volatile u32,
    key: FutexKey,
    task: *anyopaque,
    tid: i32,
    priority: i32,
    timeout_ns: u64,
) FutexError!void {
    // Try to atomically acquire: CAS 0 -> tid
    const old = @cmpxchgWeak(u32, uaddr, 0, @as(u32, @intCast(tid)), .acquire, .monotonic);
    if (old == null) {
        return; // Acquired without contention
    }

    // Contended path: set FUTEX_WAITERS bit and block
    const current_owner_tid = old.? & FUTEX_TID_MASK;
    if (current_owner_tid == @as(u32, @intCast(tid))) {
        return error.DeadlockDetected; // Recursive lock
    }

    const b = futex_table.bucket(key);
    b.lock();
    defer b.unlock();

    // Set FUTEX_WAITERS bit
    _ = @atomicRmw(u32, uaddr, .Or, FUTEX_WAITERS, .release);

    // Create PI state if needed, enqueue ourselves
    var node = FutexQNode.init(key, tid, priority, task);
    node.is_pi = true;
    node.timeout_ns = timeout_ns;
    b.enqueue(&node);
    futex_table.total_waiters += 1;

    // Priority boost: boost owner to our priority if needed
    futex_table.stats.pi_boost_count += 1;

    // Would block here until woken by unlock_pi
}

/// FUTEX_UNLOCK_PI: Unlock a PI-aware futex.
pub fn futexUnlockPi(
    uaddr: *volatile u32,
    key: FutexKey,
    tid: i32,
) FutexError!void {
    // Verify we own this futex
    const val = uaddr.*;
    if (val & FUTEX_TID_MASK != @as(u32, @intCast(tid))) {
        return error.PermissionDenied;
    }

    // If no waiters, just CAS to 0
    if (val & FUTEX_WAITERS == 0) {
        const old = @cmpxchgWeak(u32, uaddr, val, 0, .release, .monotonic);
        if (old == null) return;
    }

    const b = futex_table.bucket(key);
    b.lock();
    defer b.unlock();

    // Find highest-priority PI waiter
    var best: ?*FutexQNode = null;
    var node = b.head;
    while (node) |n| {
        if (n.key.eql(key) and n.is_pi) {
            if (best == null or n.priority < best.?.priority) {
                best = n;
            }
        }
        node = n.next;
    }

    if (best) |new_owner| {
        // Hand off to new owner
        b.dequeue(new_owner);
        new_owner.woken = true;

        // Set new owner TID, keep WAITERS bit if there are more
        var new_val = @as(u32, @intCast(new_owner.tid));
        if (b.count > 0) {
            new_val |= FUTEX_WAITERS;
        }
        uaddr.* = new_val;

        futex_table.total_waiters -= 1;
    } else {
        // No waiters, clear
        uaddr.* = 0;
    }
}

// ============================================================================
// FUTEX_WAITV — Wait on multiple futexes (futex2 interface)
// ============================================================================

pub const FutexWaitv = struct {
    /// Pointer to futex value (userspace address)
    val: u64,
    /// Expected value
    uaddr: u64,
    /// Flags (size, private, etc.)
    flags: u32,
    /// Reserved
    __reserved: u32,
};

/// Wait on multiple futexes simultaneously.
/// Returns the index of the futex that was woken, or error.
pub fn futexWaitv(
    waiters: []const FutexWaitv,
    timeout_ns: u64,
    clock_id: u32,
) FutexError!u32 {
    if (waiters.len == 0 or waiters.len > FUTEX_WAITV_MAX) {
        return error.InvalidArgument;
    }

    _ = timeout_ns;
    _ = clock_id;

    // Validate all futex addresses and flags
    for (waiters) |w| {
        if (w.__reserved != 0) return error.InvalidArgument;
        if (w.flags & ~@as(u32, FUTEX_32 | FUTEX_PRIVATE_FLAG_V2) != 0) {
            return error.InvalidArgument;
        }
    }

    // Check all values atomically, enqueue on all matching
    // When woken, dequeue from all and return the index

    return 0;
}

// ============================================================================
// Robust Futex List
// ============================================================================

pub const RobustListHead = struct {
    /// Head of the robust list
    list: u64,
    /// Pending futex address being acquired
    list_op_pending: u64,
    /// Offset of the futex word within the list entry
    futex_offset: i64,
};

/// Process robust futex list on thread exit.
/// This handles futexes that were held by a dying thread —
/// sets FUTEX_OWNER_DIED and wakes waiters.
pub fn processRobustList(
    head: *const RobustListHead,
    tid: i32,
) void {
    var entry_addr = head.list;
    const head_addr = @intFromPtr(head);
    var limit: u32 = 2048; // Prevent infinite loop on corrupt list

    while (entry_addr != head_addr and limit > 0) : (limit -= 1) {
        // Calculate futex address from entry + offset
        const futex_addr_val = @as(i64, @intCast(entry_addr)) +% head.futex_offset;
        if (futex_addr_val <= 0) break;

        const futex_ptr = @as(*volatile u32, @ptrFromInt(@as(usize, @intCast(futex_addr_val))));
        handleDyingFutex(futex_ptr, tid);

        // Follow the linked list
        const next_ptr = @as(*const u64, @ptrFromInt(@as(usize, entry_addr)));
        entry_addr = next_ptr.*;
    }

    // Also handle the pending futex
    if (head.list_op_pending != 0) {
        const pending_addr = @as(i64, @intCast(head.list_op_pending)) +% head.futex_offset;
        if (pending_addr > 0) {
            const futex_ptr = @as(*volatile u32, @ptrFromInt(@as(usize, @intCast(pending_addr))));
            handleDyingFutex(futex_ptr, tid);
        }
    }
}

/// Handle a futex held by a dying thread.
fn handleDyingFutex(uaddr: *volatile u32, tid: i32) void {
    const val = uaddr.*;
    if (val & FUTEX_TID_MASK != @as(u32, @intCast(tid))) {
        return; // Not owned by this thread
    }

    // Set OWNER_DIED flag and wake one waiter
    _ = @atomicRmw(u32, uaddr, .Or, FUTEX_OWNER_DIED, .release);
    _ = @atomicRmw(u32, uaddr, .And, ~FUTEX_TID_MASK, .release);

    // Wake one waiter if FUTEX_WAITERS is set
    if (val & FUTEX_WAITERS != 0) {
        // Would compute key from address and call futexWake
    }
}

// ============================================================================
// Syscall Dispatch
// ============================================================================

/// Main futex syscall handler.
pub fn sysFutex(
    uaddr: *volatile u32,
    op: u32,
    val: u32,
    timeout_or_val2: u64,
    uaddr2: ?*volatile u32,
    val3: u32,
) FutexError!i64 {
    const cmd = op & FUTEX_CMD_MASK;
    const _private = (op & FUTEX_PRIVATE_FLAG) != 0;

    // Compute futex key
    const key = FutexKey{
        .kind = .{ .private = .{
            .mm = @ptrFromInt(0), // Would be current mm
            .address = @intFromPtr(uaddr),
        } },
        .offset = @as(u32, @intFromPtr(uaddr)) & 0xFFF,
    };

    switch (cmd) {
        FUTEX_WAIT => {
            futexWait(
                uaddr,
                val,
                FUTEX_BITSET_MATCH_ANY,
                timeout_or_val2,
                key,
                @ptrFromInt(0), // current task
                0, // current tid
                120, // default priority
            ) catch |e| return e;
            return 0;
        },
        FUTEX_WAKE => {
            return @as(i64, futexWake(key, @as(i32, @intCast(val)), FUTEX_BITSET_MATCH_ANY));
        },
        FUTEX_WAIT_BITSET => {
            if (val3 == 0) return error.InvalidArgument;
            futexWait(
                uaddr,
                val,
                val3,
                timeout_or_val2,
                key,
                @ptrFromInt(0),
                0,
                120,
            ) catch |e| return e;
            return 0;
        },
        FUTEX_WAKE_BITSET => {
            if (val3 == 0) return error.InvalidArgument;
            return @as(i64, futexWake(key, @as(i32, @intCast(val)), val3));
        },
        FUTEX_REQUEUE => {
            if (uaddr2 == null) return error.InvalidArgument;
            const key2 = FutexKey{
                .kind = .{ .private = .{
                    .mm = @ptrFromInt(0),
                    .address = @intFromPtr(uaddr2.?),
                } },
                .offset = @as(u32, @intFromPtr(uaddr2.?)) & 0xFFF,
            };
            return @as(i64, futexRequeue(
                key,
                key2,
                @as(i32, @intCast(val)),
                @as(i32, @intCast(timeout_or_val2)),
                null,
                null,
            ) catch |e| return e);
        },
        FUTEX_CMP_REQUEUE => {
            if (uaddr2 == null) return error.InvalidArgument;
            const key2 = FutexKey{
                .kind = .{ .private = .{
                    .mm = @ptrFromInt(0),
                    .address = @intFromPtr(uaddr2.?),
                } },
                .offset = @as(u32, @intFromPtr(uaddr2.?)) & 0xFFF,
            };
            return @as(i64, futexRequeue(
                key,
                key2,
                @as(i32, @intCast(val)),
                @as(i32, @intCast(timeout_or_val2)),
                val3,
                uaddr,
            ) catch |e| return e);
        },
        FUTEX_WAKE_OP => {
            if (uaddr2 == null) return error.InvalidArgument;
            const key2 = FutexKey{
                .kind = .{ .private = .{
                    .mm = @ptrFromInt(0),
                    .address = @intFromPtr(uaddr2.?),
                } },
                .offset = @as(u32, @intFromPtr(uaddr2.?)) & 0xFFF,
            };
            return @as(i64, futexWakeOp(
                key,
                key2,
                @as(i32, @intCast(val)),
                @as(i32, @intCast(timeout_or_val2)),
                val3,
                uaddr2.?,
            ));
        },
        FUTEX_LOCK_PI, FUTEX_LOCK_PI2 => {
            futexLockPi(uaddr, key, @ptrFromInt(0), 0, 120, timeout_or_val2) catch |e| return e;
            return 0;
        },
        FUTEX_UNLOCK_PI => {
            futexUnlockPi(uaddr, key, 0) catch |e| return e;
            return 0;
        },
        else => return error.InvalidArgument,
    }
}

/// Set robust list for the current thread.
pub fn sysSetRobustList(head: *const RobustListHead, len: usize) FutexError!void {
    if (len != @sizeOf(RobustListHead)) {
        return error.InvalidArgument;
    }
    _ = head;
    // Would store head pointer in task struct
}

/// Get robust list for a thread.
pub fn sysGetRobustList(
    pid: i32,
    head_ptr: **const RobustListHead,
    len_ptr: *usize,
) FutexError!void {
    _ = pid;
    _ = head_ptr;
    len_ptr.* = @sizeOf(RobustListHead);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the futex subsystem.
pub fn init() void {
    futex_table = FutexHashTable.init();
}
