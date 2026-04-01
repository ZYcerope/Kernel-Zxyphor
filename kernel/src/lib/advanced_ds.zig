// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Kernel Library Utilities
// Red-Black Tree, AVL Tree, XArray, Radix Tree, Wait Queue, Completion, Workqueue
const std = @import("std");

// ============================================================================
// Red-Black Tree (production implementation)
// ============================================================================

pub const RbColor = enum(u1) {
    black = 0,
    red = 1,
};

pub fn RbTree(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        pub const Node = struct {
            key: K,
            value: V,
            left: ?*Node = null,
            right: ?*Node = null,
            parent: ?*Node = null,
            color: RbColor = .red,
        };

        root: ?*Node = null,
        count: usize = 0,
        // Node pool for allocation-free operation
        pool: [4096]Node = undefined,
        pool_used: usize = 0,

        pub fn init() Self {
            return Self{};
        }

        pub fn allocNode(self: *Self, key: K, value: V) ?*Node {
            if (self.pool_used >= self.pool.len) return null;
            const idx = self.pool_used;
            self.pool_used += 1;
            self.pool[idx] = Node{
                .key = key,
                .value = value,
                .left = null,
                .right = null,
                .parent = null,
                .color = .red,
            };
            return &self.pool[idx];
        }

        pub fn insert(self: *Self, key: K, value: V) bool {
            const node = self.allocNode(key, value) orelse return false;

            if (self.root == null) {
                node.color = .black;
                self.root = node;
                self.count += 1;
                return true;
            }

            // BST insert
            var current = self.root;
            while (current) |c| {
                if (key < c.key) {
                    if (c.left) |_| {
                        current = c.left;
                    } else {
                        c.left = node;
                        node.parent = c;
                        break;
                    }
                } else if (key > c.key) {
                    if (c.right) |_| {
                        current = c.right;
                    } else {
                        c.right = node;
                        node.parent = c;
                        break;
                    }
                } else {
                    // Duplicate key - update value
                    c.value = value;
                    self.pool_used -= 1; // Return node to pool
                    return true;
                }
            }

            self.fixInsert(node);
            self.count += 1;
            return true;
        }

        pub fn find(self: *const Self, key: K) ?*Node {
            var current = self.root;
            while (current) |c| {
                if (key < c.key) {
                    current = c.left;
                } else if (key > c.key) {
                    current = c.right;
                } else {
                    return c;
                }
            }
            return null;
        }

        pub fn findMin(self: *const Self) ?*Node {
            var current = self.root orelse return null;
            while (current.left) |left| {
                current = left;
            }
            return current;
        }

        pub fn findMax(self: *const Self) ?*Node {
            var current = self.root orelse return null;
            while (current.right) |right| {
                current = right;
            }
            return current;
        }

        fn fixInsert(self: *Self, z_in: *Node) void {
            var z = z_in;
            while (z.parent) |p| {
                if (p.color != .red) break;
                const g = p.parent orelse break;

                if (p == g.left) {
                    const uncle = g.right;
                    if (uncle) |u| {
                        if (u.color == .red) {
                            p.color = .black;
                            u.color = .black;
                            g.color = .red;
                            z = g;
                            continue;
                        }
                    }
                    if (z == p.right) {
                        z = p;
                        self.rotateLeft(z);
                        continue;
                    }
                    if (z.parent) |pp| {
                        pp.color = .black;
                        if (pp.parent) |gg| {
                            gg.color = .red;
                            self.rotateRight(gg);
                        }
                    }
                } else {
                    const uncle = g.left;
                    if (uncle) |u| {
                        if (u.color == .red) {
                            p.color = .black;
                            u.color = .black;
                            g.color = .red;
                            z = g;
                            continue;
                        }
                    }
                    if (z == p.left) {
                        z = p;
                        self.rotateRight(z);
                        continue;
                    }
                    if (z.parent) |pp| {
                        pp.color = .black;
                        if (pp.parent) |gg| {
                            gg.color = .red;
                            self.rotateLeft(gg);
                        }
                    }
                }
            }
            if (self.root) |r| {
                r.color = .black;
            }
        }

        fn rotateLeft(self: *Self, x: *Node) void {
            const y = x.right orelse return;
            x.right = y.left;
            if (y.left) |yl| {
                yl.parent = x;
            }
            y.parent = x.parent;
            if (x.parent) |p| {
                if (x == p.left) {
                    p.left = y;
                } else {
                    p.right = y;
                }
            } else {
                self.root = y;
            }
            y.left = x;
            x.parent = y;
        }

        fn rotateRight(self: *Self, x: *Node) void {
            const y = x.left orelse return;
            x.left = y.right;
            if (y.right) |yr| {
                yr.parent = x;
            }
            y.parent = x.parent;
            if (x.parent) |p| {
                if (x == p.right) {
                    p.right = y;
                } else {
                    p.left = y;
                }
            } else {
                self.root = y;
            }
            y.right = x;
            x.parent = y;
        }
    };
}

// ============================================================================
// XArray (eXtensible Array) - Linux-style indexed data structure
// ============================================================================

pub const XA_CHUNK_SHIFT: u6 = 6;
pub const XA_CHUNK_SIZE: usize = 1 << XA_CHUNK_SHIFT;
pub const XA_CHUNK_MASK: usize = XA_CHUNK_SIZE - 1;
pub const XA_MAX_MARKS: usize = 3;

pub const XaMark = enum(u2) {
    mark0 = 0, // e.g. PageDirty
    mark1 = 1, // e.g. PageWriteback
    mark2 = 2, // e.g. PageToFree
};

pub const XaNode = struct {
    shift: u8,
    offset: u8,
    count: u8,
    nr_values: u16,
    parent: ?*XaNode,
    slots: [XA_CHUNK_SIZE]usize, // Tagged pointers
    marks: [XA_MAX_MARKS][XA_CHUNK_SIZE / 64 + 1]u64,
    tags: u8,

    pub fn init(shift: u8, parent: ?*XaNode, offset: u8) XaNode {
        return XaNode{
            .shift = shift,
            .offset = offset,
            .count = 0,
            .nr_values = 0,
            .parent = parent,
            .slots = [_]usize{0} ** XA_CHUNK_SIZE,
            .marks = [_][XA_CHUNK_SIZE / 64 + 1]u64{[_]u64{0} ** (XA_CHUNK_SIZE / 64 + 1)} ** XA_MAX_MARKS,
            .tags = 0,
        };
    }

    pub fn getSlotIndex(index: usize, shift: u8) usize {
        return (index >> shift) & XA_CHUNK_MASK;
    }

    pub fn setMark(self: *XaNode, slot: usize, mark: XaMark) void {
        const word = slot / 64;
        const bit = @as(u6, @intCast(slot % 64));
        self.marks[@intFromEnum(mark)][word] |= @as(u64, 1) << bit;
    }

    pub fn clearMark(self: *XaNode, slot: usize, mark: XaMark) void {
        const word = slot / 64;
        const bit = @as(u6, @intCast(slot % 64));
        self.marks[@intFromEnum(mark)][word] &= ~(@as(u64, 1) << bit);
    }

    pub fn getMark(self: *const XaNode, slot: usize, mark: XaMark) bool {
        const word = slot / 64;
        const bit = @as(u6, @intCast(slot % 64));
        return (self.marks[@intFromEnum(mark)][word] & (@as(u64, 1) << bit)) != 0;
    }
};

pub const XArray = struct {
    root: usize = 0, // Tagged pointer to XaNode or value
    flags: u32 = 0,
    // Node pool
    node_pool: [256]XaNode = undefined,
    node_pool_used: usize = 0,

    pub const XA_FLAGS_LOCK_IRQ: u32 = 1 << 0;
    pub const XA_FLAGS_LOCK_BH: u32 = 1 << 1;
    pub const XA_FLAGS_TRACK_FREE: u32 = 1 << 2;
    pub const XA_FLAGS_ALLOC: u32 = 1 << 3;
    pub const XA_FLAGS_ALLOC1: u32 = 1 << 4;

    pub fn init(flags: u32) XArray {
        return XArray{ .flags = flags };
    }

    fn allocNode(self: *XArray, shift: u8, parent: ?*XaNode, offset: u8) ?*XaNode {
        if (self.node_pool_used >= self.node_pool.len) return null;
        const idx = self.node_pool_used;
        self.node_pool_used += 1;
        self.node_pool[idx] = XaNode.init(shift, parent, offset);
        return &self.node_pool[idx];
    }

    /// Store a value at the given index
    pub fn store(self: *XArray, index: usize, value: usize) bool {
        if (self.root == 0) {
            // Need to create root node
            const node = self.allocNode(XA_CHUNK_SHIFT, null, 0) orelse return false;
            self.root = @intFromPtr(node) | 1; // Tag bit for internal node
        }

        // Walk tree, creating nodes as needed
        const max_shift = 30; // Support up to 2^36 entries
        var shift: u8 = XA_CHUNK_SHIFT;

        // Ensure tree is deep enough
        while (index >> shift >= XA_CHUNK_SIZE and shift < max_shift) {
            shift += XA_CHUNK_SHIFT;
        }

        var node_ptr = self.root & ~@as(usize, 3); // Clear tag bits
        var node: *XaNode = @ptrFromInt(node_ptr);
        var current_shift = node.shift;

        while (current_shift > 0) {
            const slot = XaNode.getSlotIndex(index, current_shift);
            if (node.slots[slot] == 0) {
                const child = self.allocNode(current_shift - XA_CHUNK_SHIFT, node, @intCast(slot)) orelse return false;
                node.slots[slot] = @intFromPtr(child) | 1;
                node.count += 1;
            }
            const child_ptr = node.slots[slot] & ~@as(usize, 3);
            node = @ptrFromInt(child_ptr);
            current_shift -= XA_CHUNK_SHIFT;
        }

        const slot = XaNode.getSlotIndex(index, 0);
        if (node.slots[slot] == 0) {
            node.count += 1;
            node.nr_values += 1;
        }
        node.slots[slot] = value;
        return true;
    }

    /// Load a value at the given index
    pub fn load(self: *const XArray, index: usize) ?usize {
        if (self.root == 0) return null;

        var node_ptr = self.root & ~@as(usize, 3);
        var node: *const XaNode = @ptrFromInt(node_ptr);
        var current_shift = node.shift;

        while (current_shift > 0) {
            const slot = XaNode.getSlotIndex(index, current_shift);
            if (node.slots[slot] == 0) return null;
            const child_ptr = node.slots[slot] & ~@as(usize, 3);
            node = @ptrFromInt(child_ptr);
            current_shift -= XA_CHUNK_SHIFT;
        }

        const slot = XaNode.getSlotIndex(index, 0);
        const val = node.slots[slot];
        if (val == 0) return null;
        return val;
    }
};

// ============================================================================
// Wait Queue
// ============================================================================

pub const WaitQueueEntry = struct {
    flags: u32 = 0,
    task_id: u32 = 0,
    func: ?*const fn (*WaitQueueEntry) void = null,
    next: ?*WaitQueueEntry = null,
    prev: ?*WaitQueueEntry = null,

    pub const WQ_FLAG_EXCLUSIVE: u32 = 1 << 0;
    pub const WQ_FLAG_WOKEN: u32 = 1 << 1;
    pub const WQ_FLAG_BOOKMARK: u32 = 1 << 2;
    pub const WQ_FLAG_CUSTOM: u32 = 1 << 3;
    pub const WQ_FLAG_DONE: u32 = 1 << 4;
};

pub const WaitQueue = struct {
    head: ?*WaitQueueEntry = null,
    tail: ?*WaitQueueEntry = null,
    count: u32 = 0,
    lock: u32 = 0, // Simple spinlock

    pub fn init() WaitQueue {
        return WaitQueue{};
    }

    pub fn addWait(self: *WaitQueue, entry: *WaitQueueEntry) void {
        entry.next = null;
        entry.prev = self.tail;
        if (self.tail) |t| {
            t.next = entry;
        } else {
            self.head = entry;
        }
        self.tail = entry;
        self.count += 1;
    }

    pub fn removeWait(self: *WaitQueue, entry: *WaitQueueEntry) void {
        if (entry.prev) |p| {
            p.next = entry.next;
        } else {
            self.head = entry.next;
        }
        if (entry.next) |n| {
            n.prev = entry.prev;
        } else {
            self.tail = entry.prev;
        }
        entry.next = null;
        entry.prev = null;
        if (self.count > 0) self.count -= 1;
    }

    /// Wake up one exclusive waiter (thundering herd avoidance)
    pub fn wakeUpExclusive(self: *WaitQueue) bool {
        var entry = self.head;
        while (entry) |e| {
            if (e.flags & WaitQueueEntry.WQ_FLAG_EXCLUSIVE != 0) {
                e.flags |= WaitQueueEntry.WQ_FLAG_WOKEN;
                if (e.func) |f| f(e);
                return true;
            }
            entry = e.next;
        }
        return false;
    }

    /// Wake up all non-exclusive waiters
    pub fn wakeUpAll(self: *WaitQueue) u32 {
        var woken: u32 = 0;
        var entry = self.head;
        while (entry) |e| {
            const next = e.next;
            if (e.flags & WaitQueueEntry.WQ_FLAG_EXCLUSIVE == 0) {
                e.flags |= WaitQueueEntry.WQ_FLAG_WOKEN;
                if (e.func) |f| f(e);
                woken += 1;
            }
            entry = next;
        }
        return woken;
    }

    /// Wake up a specific number of waiters
    pub fn wakeUpNr(self: *WaitQueue, nr: u32) u32 {
        var woken: u32 = 0;
        var entry = self.head;
        while (entry) |e| {
            if (woken >= nr) break;
            const next = e.next;
            e.flags |= WaitQueueEntry.WQ_FLAG_WOKEN;
            if (e.func) |f| f(e);
            woken += 1;
            entry = next;
        }
        return woken;
    }
};

// ============================================================================
// Completion
// ============================================================================

pub const Completion = struct {
    done: u32 = 0,
    wait: WaitQueue = WaitQueue.init(),

    pub fn init() Completion {
        return Completion{};
    }

    pub fn complete(self: *Completion) void {
        if (self.done < 0xFFFF_FFFE) {
            self.done += 1;
        }
        _ = self.wait.wakeUpExclusive();
    }

    pub fn completeAll(self: *Completion) void {
        self.done = 0xFFFF_FFFF;
        _ = self.wait.wakeUpAll();
    }

    pub fn isDone(self: *const Completion) bool {
        return self.done > 0;
    }

    pub fn tryWait(self: *Completion) bool {
        if (self.done > 0 and self.done < 0xFFFF_FFFF) {
            self.done -= 1;
            return true;
        }
        if (self.done == 0xFFFF_FFFF) return true;
        return false;
    }

    pub fn reinit(self: *Completion) void {
        self.done = 0;
    }
};

// ============================================================================
// Workqueue
// ============================================================================

pub const WorkFn = *const fn (*Work) void;

pub const Work = struct {
    func: ?WorkFn = null,
    data: usize = 0,
    next: ?*Work = null,
    flags: u32 = 0,
    pool_idx: u16 = 0,

    pub const WORK_STRUCT_PENDING: u32 = 1 << 0;
    pub const WORK_STRUCT_DELAYED: u32 = 1 << 1;
    pub const WORK_STRUCT_PWQ: u32 = 1 << 2;
    pub const WORK_STRUCT_LINKED: u32 = 1 << 3;

    pub fn init(func: WorkFn) Work {
        return Work{ .func = func };
    }
};

pub const DelayedWork = struct {
    work: Work = Work{},
    timer_expires_ns: u64 = 0,
};

pub const WorkqueueFlags = struct {
    pub const WQ_UNBOUND: u32 = 1 << 0;
    pub const WQ_FREEZABLE: u32 = 1 << 1;
    pub const WQ_MEM_RECLAIM: u32 = 1 << 2;
    pub const WQ_HIGHPRI: u32 = 1 << 3;
    pub const WQ_CPU_INTENSIVE: u32 = 1 << 4;
    pub const WQ_SYSFS: u32 = 1 << 5;
    pub const WQ_POWER_EFFICIENT: u32 = 1 << 6;
};

pub const Workqueue = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    flags: u32 = 0,
    max_active: u16 = 256,
    head: ?*Work = null,
    tail: ?*Work = null,
    pending: u32 = 0,
    active: u32 = 0,
    cpu_affinity: u64 = 0xFFFFFFFFFFFFFFFF,
    // Delayed work list
    delayed_head: ?*DelayedWork = null,
    delayed_count: u32 = 0,
    // Stats
    total_executed: u64 = 0,
    total_queued: u64 = 0,
    max_execution_ns: u64 = 0,
    total_wait_ns: u64 = 0,

    pub fn init(name: []const u8, flags: u32) Workqueue {
        var wq = Workqueue{};
        wq.flags = flags;
        const len = @min(name.len, 32);
        @memcpy(wq.name[0..len], name[0..len]);
        wq.name_len = @intCast(len);
        return wq;
    }

    pub fn queueWork(self: *Workqueue, work: *Work) bool {
        if (work.flags & Work.WORK_STRUCT_PENDING != 0) return false;
        work.flags |= Work.WORK_STRUCT_PENDING;
        work.next = null;

        if (self.tail) |t| {
            t.next = work;
        } else {
            self.head = work;
        }
        self.tail = work;
        self.pending += 1;
        self.total_queued += 1;
        return true;
    }

    pub fn dequeueWork(self: *Workqueue) ?*Work {
        const work = self.head orelse return null;
        self.head = work.next;
        if (self.head == null) self.tail = null;
        work.next = null;
        work.flags &= ~Work.WORK_STRUCT_PENDING;
        if (self.pending > 0) self.pending -= 1;
        return work;
    }

    pub fn processOne(self: *Workqueue) bool {
        const work = self.dequeueWork() orelse return false;
        self.active += 1;
        if (work.func) |f| {
            f(work);
        }
        if (self.active > 0) self.active -= 1;
        self.total_executed += 1;
        return true;
    }

    pub fn drain(self: *Workqueue) u32 {
        var processed: u32 = 0;
        while (self.processOne()) {
            processed += 1;
        }
        return processed;
    }

    pub fn flush(self: *Workqueue) void {
        _ = self.drain();
    }
};

// ============================================================================
// Notifier Chain (kernel notification framework)
// ============================================================================

pub const NotifierPriority = enum(i32) {
    lowest = -100,
    low = -50,
    normal = 0,
    high = 50,
    highest = 100,
};

pub const NotifierCallFn = *const fn (action: u64, data: usize) i32;

pub const NOTIFY_DONE: i32 = 0;
pub const NOTIFY_OK: i32 = 1;
pub const NOTIFY_STOP_MASK: i32 = 0x8000;
pub const NOTIFY_BAD: i32 = NOTIFY_STOP_MASK | 1;
pub const NOTIFY_STOP: i32 = NOTIFY_STOP_MASK | NOTIFY_OK;

pub const NotifierBlock = struct {
    callback: ?NotifierCallFn = null,
    priority: i32 = 0,
    next: ?*NotifierBlock = null,
};

pub const NotifierChain = struct {
    head: ?*NotifierBlock = null,
    count: u32 = 0,

    pub fn init() NotifierChain {
        return NotifierChain{};
    }

    pub fn register(self: *NotifierChain, block: *NotifierBlock) void {
        // Insert sorted by priority (highest first)
        if (self.head == null or block.priority > self.head.?.priority) {
            block.next = self.head;
            self.head = block;
        } else {
            var current = self.head;
            while (current) |c| {
                if (c.next == null or block.priority > c.next.?.priority) {
                    block.next = c.next;
                    c.next = block;
                    break;
                }
                current = c.next;
            }
        }
        self.count += 1;
    }

    pub fn unregister(self: *NotifierChain, block: *NotifierBlock) void {
        if (self.head == block) {
            self.head = block.next;
            self.count -= 1;
            return;
        }
        var current = self.head;
        while (current) |c| {
            if (c.next == block) {
                c.next = block.next;
                self.count -= 1;
                return;
            }
            current = c.next;
        }
    }

    pub fn callChain(self: *const NotifierChain, action: u64, data: usize) i32 {
        var ret: i32 = NOTIFY_DONE;
        var current = self.head;
        while (current) |c| {
            if (c.callback) |cb| {
                ret = cb(action, data);
                if (ret & NOTIFY_STOP_MASK != 0) break;
            }
            current = c.next;
        }
        return ret;
    }
};

// ============================================================================
// IDR (ID Radix tree - integer ID management)
// ============================================================================

pub const Idr = struct {
    bitmap: [128]u64 = [_]u64{0} ** 128, // 8192 IDs
    top: usize = 0,
    count: u32 = 0,

    pub fn init() Idr {
        return Idr{};
    }

    pub fn alloc(self: *Idr) ?u32 {
        for (self.bitmap, 0..) |word, i| {
            if (word != 0xFFFFFFFFFFFFFFFF) {
                // Find first zero bit
                const bit = @ctz(~word);
                if (bit < 64) {
                    const id: u32 = @intCast(i * 64 + bit);
                    self.bitmap[i] |= @as(u64, 1) << @intCast(bit);
                    self.count += 1;
                    return id;
                }
            }
        }
        return null; // Full
    }

    pub fn allocRange(self: *Idr, min: u32, max: u32) ?u32 {
        const start_word = min / 64;
        const end_word = @min(max / 64 + 1, 128);
        
        var i = start_word;
        while (i < end_word) : (i += 1) {
            if (self.bitmap[i] != 0xFFFFFFFFFFFFFFFF) {
                const bit = @ctz(~self.bitmap[i]);
                if (bit < 64) {
                    const id: u32 = @intCast(i * 64 + bit);
                    if (id >= min and id <= max) {
                        self.bitmap[i] |= @as(u64, 1) << @intCast(bit);
                        self.count += 1;
                        return id;
                    }
                }
            }
        }
        return null;
    }

    pub fn remove(self: *Idr, id: u32) void {
        const word = id / 64;
        const bit: u6 = @intCast(id % 64);
        if (word < 128) {
            self.bitmap[word] &= ~(@as(u64, 1) << bit);
            if (self.count > 0) self.count -= 1;
        }
    }

    pub fn contains(self: *const Idr, id: u32) bool {
        const word = id / 64;
        const bit: u6 = @intCast(id % 64);
        if (word >= 128) return false;
        return (self.bitmap[word] & (@as(u64, 1) << bit)) != 0;
    }
};

// ============================================================================
// Kref (Kernel Reference Counting)
// ============================================================================

pub const Kref = struct {
    refcount: u32 = 1,

    pub fn init() Kref {
        return Kref{ .refcount = 1 };
    }

    pub fn get(self: *Kref) void {
        self.refcount += 1;
    }

    pub fn put(self: *Kref, release: ?*const fn (*Kref) void) bool {
        if (self.refcount > 0) {
            self.refcount -= 1;
        }
        if (self.refcount == 0) {
            if (release) |rel| {
                rel(self);
            }
            return true;
        }
        return false;
    }

    pub fn readCount(self: *const Kref) u32 {
        return self.refcount;
    }
};

// ============================================================================
// Kernel Logging / printk-like
// ============================================================================

pub const LogLevel = enum(u3) {
    emerg = 0,   // System is unusable
    alert = 1,   // Action must be taken immediately
    crit = 2,    // Critical conditions
    err = 3,     // Error conditions
    warn = 4,    // Warning conditions
    notice = 5,  // Normal but significant
    info = 6,    // Informational
    debug = 7,   // Debug-level messages
};

pub const LogEntry = struct {
    timestamp_ns: u64,
    level: LogLevel,
    facility: u16,
    msg: [256]u8,
    msg_len: u16,
    cpu: u16,
    pid: u32,
    seq: u64,
};

pub const KernelLog = struct {
    buffer: [4096]LogEntry = undefined,
    head: usize = 0,
    tail: usize = 0,
    seq: u64 = 0,
    count: u32 = 0,
    dropped: u64 = 0,
    console_level: LogLevel = .warn,

    pub fn init() KernelLog {
        return KernelLog{};
    }

    pub fn log(self: *KernelLog, level: LogLevel, msg: []const u8, cpu: u16, pid: u32, ts: u64) void {
        if (@intFromEnum(level) > @intFromEnum(self.console_level)) return;

        const idx = self.head % self.buffer.len;
        var entry = &self.buffer[idx];
        entry.timestamp_ns = ts;
        entry.level = level;
        entry.cpu = cpu;
        entry.pid = pid;
        entry.seq = self.seq;
        
        const len = @min(msg.len, 256);
        @memcpy(entry.msg[0..len], msg[0..len]);
        entry.msg_len = @intCast(len);

        self.seq += 1;
        self.head += 1;
        if (self.count < self.buffer.len) {
            self.count += 1;
        } else {
            self.tail += 1; // Overwrite oldest
            self.dropped += 1;
        }
    }
};
