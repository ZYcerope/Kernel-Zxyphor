// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - RBTree Detail, Hashtable, LockRef, Kfifo, PercpuRef
// Red-black tree operations, hash table, lockref, kfifo, percpu_ref,
// llist, static_key, jump_label, refcount_t

const std = @import("std");

// ============================================================================
// Red-Black Tree
// ============================================================================

pub const RbColor = enum(u1) {
    Red = 0,
    Black = 1,
};

pub const RbNode = struct {
    __rb_parent_color: u64,
    rb_right: ?*RbNode,
    rb_left: ?*RbNode,

    pub fn color(self: *const RbNode) RbColor {
        if (self.__rb_parent_color & 1 == 0) return .Red else return .Black;
    }

    pub fn parent(self: *const RbNode) ?*RbNode {
        const p = self.__rb_parent_color & ~@as(u64, 3);
        if (p == 0) return null;
        return @ptrFromInt(p);
    }
};

pub const RbRoot = struct {
    rb_node: ?*RbNode,
};

pub const RbRootCached = struct {
    rb_root: RbRoot,
    rb_leftmost: ?*RbNode,
};

/// Augmented rbtree callbacks
pub const RbAugmentCallbacks = struct {
    propagate: ?*const fn (node: *RbNode, stop: ?*RbNode) callconv(.C) void,
    copy: ?*const fn (old: *RbNode, new: *RbNode) callconv(.C) void,
    rotate: ?*const fn (old: *RbNode, new: *RbNode) callconv(.C) void,
};

pub const RbTreeOps = struct {
    pub fn rb_insert_color(node: *RbNode, root: *RbRoot) void {
        _ = node;
        _ = root;
        // Kernel rbtree rebalancing after insert
    }

    pub fn rb_erase(node: *RbNode, root: *RbRoot) void {
        _ = node;
        _ = root;
        // Kernel rbtree removal with rebalancing
    }

    pub fn rb_first(root: *const RbRoot) ?*RbNode {
        var n = root.rb_node;
        if (n == null) return null;
        while (n.?.rb_left != null) {
            n = n.?.rb_left;
        }
        return n;
    }

    pub fn rb_last(root: *const RbRoot) ?*RbNode {
        var n = root.rb_node;
        if (n == null) return null;
        while (n.?.rb_right != null) {
            n = n.?.rb_right;
        }
        return n;
    }

    pub fn rb_next(node: *const RbNode) ?*RbNode {
        if (node.rb_right) |right| {
            var n: *RbNode = right;
            while (n.rb_left) |left| {
                n = left;
            }
            return n;
        }
        // Walk up to find successor
        var current = node;
        var p = current.parent();
        while (p != null and current == p.?.rb_right) {
            current = p.?;
            p = current.parent();
        }
        return p;
    }

    pub fn rb_prev(node: *const RbNode) ?*RbNode {
        if (node.rb_left) |left| {
            var n: *RbNode = left;
            while (n.rb_right) |right| {
                n = right;
            }
            return n;
        }
        var current = node;
        var p = current.parent();
        while (p != null and current == p.?.rb_left) {
            current = p.?;
            p = current.parent();
        }
        return p;
    }
};

// ============================================================================
// Hash Table
// ============================================================================

pub const HashListHead = struct {
    first: ?*HashListNode,
};

pub const HashListNode = struct {
    next: ?*HashListNode,
    pprev: ?*?*HashListNode,
};

pub const HashListBlHead = struct {
    first: ?*HashListBlNode,
};

pub const HashListBlNode = struct {
    next: ?*HashListBlNode,
    pprev: ?*?*HashListBlNode,
};

/// Generic hash table with configurable bits (size = 1 << bits)
pub fn HashTable(comptime bits: u5) type {
    const size = @as(usize, 1) << bits;
    return struct {
        buckets: [size]HashListHead,

        pub fn init() @This() {
            return .{
                .buckets = [_]HashListHead{.{ .first = null }} ** size,
            };
        }

        pub fn hash_min(key: u64) usize {
            // Simple bit mixing hash
            var h = key;
            h ^= h >> 33;
            h *%= 0xff51afd7ed558ccd;
            h ^= h >> 33;
            h *%= 0xc4ceb9fe1a85ec53;
            h ^= h >> 33;
            return @intCast(h & (size - 1));
        }
    };
}

// ============================================================================
// LockRef
// ============================================================================

pub const LockRef = struct {
    lock: SpinLock,
    count: i32,

    pub fn init() LockRef {
        return .{ .lock = .{}, .count = 1 };
    }

    pub fn lockref_get(self: *LockRef) void {
        // In kernel: try cmpxchg loop first, fallback to lock
        self.count += 1;
    }

    pub fn lockref_put_return(self: *LockRef) bool {
        self.count -= 1;
        return self.count == 0;
    }

    pub fn lockref_get_not_zero(self: *LockRef) bool {
        if (self.count <= 0) return false;
        self.count += 1;
        return true;
    }

    pub fn lockref_put_not_zero(self: *LockRef) bool {
        if (self.count <= 1) return false;
        self.count -= 1;
        return true;
    }

    pub fn lockref_get_not_dead(self: *LockRef) bool {
        if (self.count < 0) return false;
        self.count += 1;
        return true;
    }

    pub fn lockref_mark_dead(self: *LockRef) void {
        self.count = -128;
    }
};

// ============================================================================
// Kfifo (Kernel FIFO)
// ============================================================================

pub const KfifoBase = struct {
    buffer: [*]u8,
    size: u32,     // must be power of 2
    in_idx: u32,
    out_idx: u32,
    esize: u32,    // element size

    pub fn init(buf: [*]u8, size: u32, esize: u32) KfifoBase {
        return .{
            .buffer = buf,
            .size = size,
            .in_idx = 0,
            .out_idx = 0,
            .esize = esize,
        };
    }

    pub fn len(self: *const KfifoBase) u32 {
        return self.in_idx -% self.out_idx;
    }

    pub fn avail(self: *const KfifoBase) u32 {
        return self.size - self.len();
    }

    pub fn is_empty(self: *const KfifoBase) bool {
        return self.in_idx == self.out_idx;
    }

    pub fn is_full(self: *const KfifoBase) bool {
        return self.len() >= self.size;
    }

    pub fn reset(self: *KfifoBase) void {
        self.in_idx = 0;
        self.out_idx = 0;
    }
};

/// Typed kfifo
pub fn Kfifo(comptime T: type, comptime count: u32) type {
    return struct {
        buf: [count]T,
        in_idx: u32,
        out_idx: u32,

        pub fn init() @This() {
            return .{
                .buf = undefined,
                .in_idx = 0,
                .out_idx = 0,
            };
        }

        pub fn put(self: *@This(), item: T) bool {
            if (self.len() >= count) return false;
            self.buf[self.in_idx & (count - 1)] = item;
            self.in_idx +%= 1;
            return true;
        }

        pub fn get(self: *@This()) ?T {
            if (self.is_empty()) return null;
            const item = self.buf[self.out_idx & (count - 1)];
            self.out_idx +%= 1;
            return item;
        }

        pub fn peek(self: *const @This()) ?T {
            if (self.is_empty()) return null;
            return self.buf[self.out_idx & (count - 1)];
        }

        pub fn len(self: *const @This()) u32 {
            return self.in_idx -% self.out_idx;
        }

        pub fn is_empty(self: *const @This()) bool {
            return self.in_idx == self.out_idx;
        }
    };
}

// ============================================================================
// Percpu Refcount
// ============================================================================

pub const PercpuRefFlags = packed struct(u32) {
    dead: bool = false,
    allow_reinit: bool = false,
    init_atomic: bool = false,
    init_dead: bool = false,
    _reserved: u28 = 0,
};

pub const PercpuRef = struct {
    percpu_count: [256]i64,   // per-CPU counters
    atomic_count: i64,
    flags: PercpuRefFlags,
    release: ?*const fn (ref_ptr: *PercpuRef) callconv(.C) void,
    confirm_switch: ?*const fn (ref_ptr: *PercpuRef) callconv(.C) void,
    nr_cpus: u32,

    pub fn init(nr_cpus: u32) PercpuRef {
        var pr = PercpuRef{
            .percpu_count = [_]i64{0} ** 256,
            .atomic_count = 1,
            .flags = .{},
            .release = null,
            .confirm_switch = null,
            .nr_cpus = nr_cpus,
        };
        // Distribute initial ref across per-CPU counters
        if (nr_cpus > 0) {
            pr.percpu_count[0] = 1;
        }
        return pr;
    }

    pub fn get(self: *PercpuRef, cpu: u32) void {
        if (cpu < self.nr_cpus and !self.flags.dead) {
            self.percpu_count[cpu] += 1;
        } else {
            self.atomic_count += 1;
        }
    }

    pub fn put(self: *PercpuRef, cpu: u32) bool {
        if (cpu < self.nr_cpus and !self.flags.dead) {
            self.percpu_count[cpu] -= 1;
        } else {
            self.atomic_count -= 1;
            if (self.atomic_count == 0) {
                return true; // last ref dropped
            }
        }
        return false;
    }
};

// ============================================================================
// Llist (Lock-Less List)
// ============================================================================

pub const LlistHead = struct {
    first: ?*LlistNode,
};

pub const LlistNode = struct {
    next: ?*LlistNode,
};

// ============================================================================
// Static Key / Jump Label
// ============================================================================

pub const StaticKeyType = enum(u8) {
    False = 0,     // default off
    True = 1,      // default on
};

pub const StaticKey = struct {
    enabled: i32,       // atomic counter
    key_type: StaticKeyType,
    entries: ?*JumpEntry,
    nr_entries: u32,
};

pub const JumpEntry = struct {
    code: u64,     // address of the NOP/JMP
    target: u64,   // branch target
    key: u64,      // pointer to static_key
};

pub const STATIC_KEY_INIT_FALSE = StaticKey{
    .enabled = 0,
    .key_type = .False,
    .entries = null,
    .nr_entries = 0,
};

pub const STATIC_KEY_INIT_TRUE = StaticKey{
    .enabled = 1,
    .key_type = .True,
    .entries = null,
    .nr_entries = 0,
};

// ============================================================================
// refcount_t (saturating reference counter)
// ============================================================================

pub const Refcount = struct {
    refs: i32,

    pub const REFCOUNT_SATURATED: i32 = @as(i32, @bitCast(@as(u32, 0xC0000000)));

    pub fn init(n: i32) Refcount {
        return .{ .refs = n };
    }

    pub fn refcount_inc(self: *Refcount) void {
        if (self.refs >= REFCOUNT_SATURATED) return;
        self.refs += 1;
    }

    pub fn refcount_dec_and_test(self: *Refcount) bool {
        if (self.refs >= REFCOUNT_SATURATED) return false;
        self.refs -= 1;
        return self.refs == 0;
    }

    pub fn refcount_inc_not_zero(self: *Refcount) bool {
        if (self.refs <= 0 or self.refs >= REFCOUNT_SATURATED) return false;
        self.refs += 1;
        return true;
    }

    pub fn read(self: *const Refcount) i32 {
        return self.refs;
    }

    pub fn set(self: *Refcount, val: i32) void {
        self.refs = val;
    }
};

// ============================================================================
// Notifier Chain
// ============================================================================

pub const NotifierBlock = struct {
    notifier_call: ?*const fn (nb: *NotifierBlock, action: u64, data: ?*anyopaque) callconv(.C) i32,
    next: ?*NotifierBlock,
    priority: i32,
};

pub const NotifierChainType = enum(u8) {
    Atomic = 0,
    Blocking = 1,
    Raw = 2,
    Srcu = 3,
};

pub const NOTIFY_DONE: i32 = 0x0000;
pub const NOTIFY_OK: i32 = 0x0001;
pub const NOTIFY_STOP: i32 = 0x8000;
pub const NOTIFY_BAD: i32 = 0x8002;

// ============================================================================
// Completion
// ============================================================================

pub const Completion = struct {
    done: u32,
    wait: WaitQueueHead,

    pub fn init_completion() Completion {
        return .{
            .done = 0,
            .wait = .{ .lock = .{}, .head = .{ .next = null, .prev = null } },
        };
    }

    pub fn complete(self: *Completion) void {
        self.done += 1;
    }

    pub fn complete_all(self: *Completion) void {
        self.done = 0xFFFFFFFF; // UINT_MAX
    }
};

// ============================================================================
// Helper types
// ============================================================================

pub const SpinLock = struct { raw: u32 = 0 };
pub const ListHead = struct { next: ?*ListHead = null, prev: ?*ListHead = null };
pub const WaitQueueHead = struct {
    lock: SpinLock,
    head: ListHead,
};

// ============================================================================
// Library Data Structure Manager
// ============================================================================

pub const LibDsManager = struct {
    rbtree_nodes: u64,
    hash_table_entries: u64,
    kfifo_instances: u32,
    percpu_ref_active: u32,
    static_keys_enabled: u32,
    notifier_chains: u32,
    completions_pending: u32,
    llist_nodes: u64,
    initialized: bool,

    pub fn init() LibDsManager {
        return .{
            .rbtree_nodes = 0,
            .hash_table_entries = 0,
            .kfifo_instances = 0,
            .percpu_ref_active = 0,
            .static_keys_enabled = 0,
            .notifier_chains = 0,
            .completions_pending = 0,
            .llist_nodes = 0,
            .initialized = true,
        };
    }
};
