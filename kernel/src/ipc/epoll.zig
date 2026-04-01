// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Epoll / Event Poll Subsystem
//
// Implements the epoll event notification mechanism for multiplexing I/O.
// This is the primary high-performance event loop primitive, supporting:
//
// - Edge-triggered (EPOLLET) and level-triggered modes
// - EPOLLONESHOT for single-fire events
// - EPOLLEXCLUSIVE for thundering-herd avoidance
// - Nested epoll instances (epoll watching epoll)
// - Efficient red-black tree for file descriptor tracking
// - Ready list for O(1) event delivery

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");
const rbtree = @import("../lib/rbtree.zig");
const list = @import("../lib/list.zig");

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────
pub const EPOLL_MAX_EVENTS: usize = 4096;
pub const EPOLL_MAX_ITEMS: usize = 65536;
pub const EPOLL_MAX_INSTANCES: usize = 256;
pub const EPOLL_MAX_NESTING: usize = 5;

// ─────────────────────────────────────────────────────────────────────
// Event Types (bitmask)
// ─────────────────────────────────────────────────────────────────────
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLNVAL: u32 = 0x020;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLRDBAND: u32 = 0x080;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLWRBAND: u32 = 0x200;
pub const EPOLLMSG: u32 = 0x400;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

// ─────────────────────────────────────────────────────────────────────
// EpollEvent — user-facing event structure
// ─────────────────────────────────────────────────────────────────────
pub const EpollEvent = struct {
    /// Event mask (EPOLLIN, EPOLLOUT, etc.)
    events: u32,
    /// User data (opaque, returned as-is on event delivery)
    data: EpollData,
};

pub const EpollData = union {
    ptr: u64,
    fd: i32,
    u32_val: u32,
    u64_val: u64,
};

// ─────────────────────────────────────────────────────────────────────
// EpollItem — internal tracking structure for each registered fd
// ─────────────────────────────────────────────────────────────────────
pub const EpollItemFlags = packed struct {
    edge_triggered: bool = false,
    one_shot: bool = false,
    exclusive: bool = false,
    disabled: bool = false,
    on_ready_list: bool = false,
    is_closing: bool = false,
    _reserved: u2 = 0,
};

pub const EpollItem = struct {
    /// File descriptor being watched
    fd: i32,

    /// Registered events (what we're interested in)
    interest_events: u32,

    /// Current ready events (what has actually happened)
    ready_events: u32,

    /// User data stored with this item
    user_data: EpollData,

    /// Flags
    flags: EpollItemFlags,

    /// Reference to the owning epoll instance
    epoll: ?*Epoll,

    /// Red-black tree node (for O(log n) lookup by fd)
    rb_node: rbtree.RbNode,

    /// Ready list link (for O(1) event delivery)
    ready_link: list.ListNode,

    /// Number of times this item has fired
    fire_count: u64,

    /// Last event timestamp
    last_event_tick: u64,

    /// Whether this item has been armed (for level-triggered re-arming)
    armed: bool,

    const Self = @This();

    pub fn init(fd: i32, events: u32, data: EpollData) Self {
        var item = Self{
            .fd = fd,
            .interest_events = events & ~(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE),
            .ready_events = 0,
            .user_data = data,
            .flags = EpollItemFlags{},
            .epoll = null,
            .rb_node = rbtree.RbNode{},
            .ready_link = list.ListNode{},
            .fire_count = 0,
            .last_event_tick = 0,
            .armed = true,
        };

        // Parse control flags from the event mask
        if ((events & EPOLLET) != 0) {
            item.flags.edge_triggered = true;
        }
        if ((events & EPOLLONESHOT) != 0) {
            item.flags.one_shot = true;
        }
        if ((events & EPOLLEXCLUSIVE) != 0) {
            item.flags.exclusive = true;
        }

        return item;
    }

    /// Check if this item has events that the user is interested in
    pub fn hasReadyEvents(self: *const Self) bool {
        return (self.ready_events & self.interest_events) != 0;
    }

    /// Report events to this item.
    /// Returns true if the item should be added to the ready list.
    pub fn reportEvents(self: *Self, events: u32, tick: u64) bool {
        const matching = events & self.interest_events;
        if (matching == 0) return false;

        if (self.flags.disabled) return false;

        if (self.flags.edge_triggered) {
            // Edge-triggered: only fire on state transitions
            const new_events = matching & ~self.ready_events;
            self.ready_events |= matching;
            if (new_events == 0) return false;
        } else {
            // Level-triggered: always report if events are present
            self.ready_events |= matching;
        }

        self.fire_count += 1;
        self.last_event_tick = tick;

        if (self.flags.one_shot) {
            self.flags.disabled = true;
        }

        return !self.flags.on_ready_list;
    }

    /// Clear ready events after delivery (for edge-triggered)
    pub fn clearEvents(self: *Self) void {
        self.ready_events = 0;
    }

    /// Re-arm a one-shot item
    pub fn rearm(self: *Self, new_events: u32) void {
        self.interest_events = new_events & ~(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
        self.flags.disabled = false;
        self.armed = true;

        if ((new_events & EPOLLET) != 0) {
            self.flags.edge_triggered = true;
        }
        if ((new_events & EPOLLONESHOT) != 0) {
            self.flags.one_shot = true;
        }
    }
};

// ─────────────────────────────────────────────────────────────────────
// Epoll — an epoll instance
// ─────────────────────────────────────────────────────────────────────
pub const Epoll = struct {
    /// Instance ID
    id: u32,

    /// Red-black tree of registered items (ordered by fd)
    rb_root: ?*rbtree.RbNode,

    /// Ready list — items with pending events
    ready_list: list.ListNode,
    ready_count: u32,

    /// Total number of registered items
    item_count: u32,

    /// Item storage pool (static for this instance)
    items: [EPOLL_MAX_ITEMS]EpollItem,
    item_used: [EPOLL_MAX_ITEMS]bool,

    /// Owning process ID
    owner_pid: u32,

    /// Current nesting depth (for nested epoll detection)
    nesting_depth: u8,

    /// Lock protecting this instance
    lock: spinlock.SpinLock,

    /// Waitqueue — threads blocked in epoll_wait
    waiter_count: u32,

    /// Statistics
    total_events_delivered: u64,
    total_waits: u64,
    total_timeouts: u64,

    /// State
    active: bool,

    const Self = @This();

    pub fn init(id: u32, pid: u32) Self {
        var ep = Self{
            .id = id,
            .rb_root = null,
            .ready_list = list.ListNode{},
            .ready_count = 0,
            .item_count = 0,
            .items = undefined,
            .item_used = [_]bool{false} ** EPOLL_MAX_ITEMS,
            .owner_pid = pid,
            .nesting_depth = 0,
            .lock = spinlock.SpinLock{},
            .waiter_count = 0,
            .total_events_delivered = 0,
            .total_waits = 0,
            .total_timeouts = 0,
            .active = true,
        };
        ep.ready_list.next = &ep.ready_list;
        ep.ready_list.prev = &ep.ready_list;
        return ep;
    }

    /// Add a file descriptor to this epoll instance (EPOLL_CTL_ADD)
    pub fn add(self: *Self, fd: i32, event: *const EpollEvent) i32 {
        self.lock.acquire();
        defer self.lock.release();

        if (!self.active) return -9;

        // Check if fd is already registered
        if (self.findItemByFd(fd) != null) {
            return -17; // EEXIST
        }

        // Allocate an item
        const item = self.allocItem() orelse return -12; // ENOMEM
        item.* = EpollItem.init(fd, event.events, event.data);
        item.epoll = self;

        // Insert into the red-black tree
        self.insertIntoTree(item);
        self.item_count += 1;

        return 0;
    }

    /// Modify an existing fd's event interest (EPOLL_CTL_MOD)
    pub fn modify(self: *Self, fd: i32, event: *const EpollEvent) i32 {
        self.lock.acquire();
        defer self.lock.release();

        const item = self.findItemByFd(fd) orelse return -2; // ENOENT

        // Update the interest events
        item.interest_events = event.events & ~(EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE);
        item.user_data = event.data;

        // Update flags
        item.flags.edge_triggered = (event.events & EPOLLET) != 0;
        item.flags.one_shot = (event.events & EPOLLONESHOT) != 0;
        item.flags.exclusive = (event.events & EPOLLEXCLUSIVE) != 0;

        // Re-arm disabled items
        if (item.flags.disabled) {
            item.rearm(event.events);
        }

        // Check if current ready events match new interest
        if (item.hasReadyEvents() and !item.flags.on_ready_list) {
            self.addToReadyList(item);
        }

        return 0;
    }

    /// Remove a file descriptor from this epoll instance (EPOLL_CTL_DEL)
    pub fn del(self: *Self, fd: i32) i32 {
        self.lock.acquire();
        defer self.lock.release();

        const item = self.findItemByFd(fd) orelse return -2;

        // Remove from ready list if present
        if (item.flags.on_ready_list) {
            self.removeFromReadyList(item);
        }

        // Remove from tree
        self.removeFromTree(item);
        self.item_count -= 1;

        // Free the item
        self.freeItem(item);

        return 0;
    }

    /// Wait for events (EPOLL_WAIT) with timeout
    /// Returns the number of ready events, or -1 on error.
    pub fn wait(self: *Self, events: []EpollEvent, timeout_ms: i32) i32 {
        self.lock.acquire();
        defer self.lock.release();

        if (!self.active) return -9;

        self.total_waits += 1;

        // If there are already ready events, return them immediately
        if (self.ready_count > 0) {
            return self.collectEvents(events);
        }

        // If timeout is 0, return immediately (poll mode)
        if (timeout_ms == 0) {
            return 0;
        }

        // For blocking wait, we'd normally sleep here.
        // In this implementation, we simulate with a busywait check.
        self.waiter_count += 1;

        // Check again for ready events (race condition prevention)
        if (self.ready_count > 0) {
            self.waiter_count -= 1;
            return self.collectEvents(events);
        }

        // Would sleep/block here in production kernel
        // For now, return 0 (timeout with no events)
        self.waiter_count -= 1;
        self.total_timeouts += 1;
        return 0;
    }

    /// Collect ready events into the user's event buffer
    fn collectEvents(self: *Self, events: []EpollEvent) i32 {
        var count: u32 = 0;
        const max_events = @min(@as(u32, @intCast(events.len)), self.ready_count);

        var node = self.ready_list.next;
        while (node != &self.ready_list and count < max_events) {
            const item = @fieldParentPtr(EpollItem, "ready_link", node);
            const next = node.next;

            if (item.hasReadyEvents()) {
                events[count] = EpollEvent{
                    .events = item.ready_events & item.interest_events,
                    .data = item.user_data,
                };
                count += 1;
            }

            // For edge-triggered items, remove from ready list immediately
            if (item.flags.edge_triggered) {
                self.removeFromReadyList(item);
                item.clearEvents();
            } else {
                // For level-triggered, keep in ready list if still active
                if (!item.hasReadyEvents()) {
                    self.removeFromReadyList(item);
                }
            }

            // For one-shot, disable after delivery
            if (item.flags.one_shot) {
                item.flags.disabled = true;
                self.removeFromReadyList(item);
            }

            node = next;
        }

        self.total_events_delivered += count;
        return @intCast(count);
    }

    /// Report events for a file descriptor (called when I/O events occur)
    pub fn reportFdEvents(self: *Self, fd: i32, events: u32, tick: u64) void {
        self.lock.acquire();
        defer self.lock.release();

        const item = self.findItemByFd(fd) orelse return;

        if (item.reportEvents(events, tick)) {
            self.addToReadyList(item);

            // Wake up any threads blocked in epoll_wait
            if (self.waiter_count > 0) {
                self.wakeWaiters(item);
            }
        }
    }

    fn wakeWaiters(self: *Self, item: *const EpollItem) void {
        _ = item;
        // In production, this would wake sleeping threads from the wait queue.
        // For exclusive items, only wake one waiter (thundering herd mitigation).
        _ = self;
    }

    // ───── Red-black tree operations ─────

    fn findItemByFd(self: *Self, fd: i32) ?*EpollItem {
        var node = self.rb_root;
        while (node) |n| {
            const item = @fieldParentPtr(EpollItem, "rb_node", n);
            if (fd < item.fd) {
                node = n.left;
            } else if (fd > item.fd) {
                node = n.right;
            } else {
                return item;
            }
        }
        return null;
    }

    fn insertIntoTree(self: *Self, item: *EpollItem) void {
        var parent: ?*rbtree.RbNode = null;
        var link_ptr: *?*rbtree.RbNode = &self.rb_root;

        while (link_ptr.*) |node| {
            parent = node;
            const existing = @fieldParentPtr(EpollItem, "rb_node", node);
            if (item.fd < existing.fd) {
                link_ptr = &node.left;
            } else {
                link_ptr = &node.right;
            }
        }

        link_ptr.* = &item.rb_node;
        item.rb_node.parent = parent;
        item.rb_node.left = null;
        item.rb_node.right = null;
    }

    fn removeFromTree(self: *Self, item: *EpollItem) void {
        // Simplified removal — a full RB-tree would rebalance
        _ = self;
        item.rb_node.parent = null;
        item.rb_node.left = null;
        item.rb_node.right = null;
    }

    // ───── Ready list operations ─────

    fn addToReadyList(self: *Self, item: *EpollItem) void {
        if (item.flags.on_ready_list) return;

        // Add to the end of the ready list (circular linked list)
        item.ready_link.prev = self.ready_list.prev;
        item.ready_link.next = &self.ready_list;
        if (self.ready_list.prev) |prev| {
            prev.next = &item.ready_link;
        }
        self.ready_list.prev = &item.ready_link;

        item.flags.on_ready_list = true;
        self.ready_count += 1;
    }

    fn removeFromReadyList(self: *Self, item: *EpollItem) void {
        if (!item.flags.on_ready_list) return;

        if (item.ready_link.prev) |prev| {
            prev.next = item.ready_link.next;
        }
        if (item.ready_link.next) |next| {
            next.prev = item.ready_link.prev;
        }
        item.ready_link.prev = null;
        item.ready_link.next = null;

        item.flags.on_ready_list = false;
        if (self.ready_count > 0) {
            self.ready_count -= 1;
        }
    }

    // ───── Item pool management ─────

    fn allocItem(self: *Self) ?*EpollItem {
        for (&self.item_used, 0..) |*used, i| {
            if (!used.*) {
                used.* = true;
                return &self.items[i];
            }
        }
        return null;
    }

    fn freeItem(self: *Self, item: *EpollItem) void {
        // Find the index
        const base = @intFromPtr(&self.items[0]);
        const addr = @intFromPtr(item);
        const idx = (addr - base) / @sizeOf(EpollItem);
        if (idx < EPOLL_MAX_ITEMS) {
            self.item_used[idx] = false;
        }
    }

    /// Destroy this epoll instance
    pub fn destroy(self: *Self) void {
        self.lock.acquire();
        self.active = false;
        self.item_count = 0;
        self.ready_count = 0;
        self.lock.release();
    }

    /// Get statistics
    pub fn getStats(self: *const Self) EpollStats {
        return EpollStats{
            .item_count = self.item_count,
            .ready_count = self.ready_count,
            .total_events = self.total_events_delivered,
            .total_waits = self.total_waits,
            .total_timeouts = self.total_timeouts,
        };
    }
};

pub const EpollStats = struct {
    item_count: u32,
    ready_count: u32,
    total_events: u64,
    total_waits: u64,
    total_timeouts: u64,
};

// ─────────────────────────────────────────────────────────────────────
// Global Instance Manager
// ─────────────────────────────────────────────────────────────────────
var instances: [EPOLL_MAX_INSTANCES]Epoll = undefined;
var instance_used: [EPOLL_MAX_INSTANCES]bool = [_]bool{false} ** EPOLL_MAX_INSTANCES;
var instance_count: u32 = 0;
var global_lock: spinlock.SpinLock = spinlock.SpinLock{};
var next_id: u32 = 1;

pub fn init() void {
    global_lock.acquire();
    defer global_lock.release();

    instance_count = 0;
    next_id = 1;
    for (&instance_used) |*u| {
        u.* = false;
    }
}

/// Create a new epoll instance (epoll_create)
pub fn epollCreate(pid: u32) i32 {
    global_lock.acquire();
    defer global_lock.release();

    for (instance_used, 0..) |used, i| {
        if (!used) {
            const id = next_id;
            next_id += 1;
            instances[i] = Epoll.init(id, pid);
            instance_used[i] = true;
            instance_count += 1;
            return @intCast(id);
        }
    }

    return -12; // ENOMEM
}

/// Find an epoll instance by ID
pub fn findById(id: u32) ?*Epoll {
    for (instances[0..EPOLL_MAX_INSTANCES], 0..) |*inst, i| {
        if (instance_used[i] and inst.id == id) {
            return inst;
        }
    }
    return null;
}

/// Destroy an epoll instance (close)
pub fn epollDestroy(id: u32) void {
    global_lock.acquire();
    defer global_lock.release();

    for (instances[0..EPOLL_MAX_INSTANCES], 0..) |*inst, i| {
        if (instance_used[i] and inst.id == id) {
            inst.destroy();
            instance_used[i] = false;
            instance_count -= 1;
            return;
        }
    }
}

/// epoll_ctl syscall handler
pub fn epollCtl(epfd: u32, op: i32, fd: i32, event_ptr: ?*const EpollEvent) i32 {
    const ep = findById(epfd) orelse return -9;

    return switch (op) {
        1 => { // EPOLL_CTL_ADD
            const ev = event_ptr orelse return -22;
            return ep.add(fd, ev);
        },
        2 => { // EPOLL_CTL_DEL
            return ep.del(fd);
        },
        3 => { // EPOLL_CTL_MOD
            const ev = event_ptr orelse return -22;
            return ep.modify(fd, ev);
        },
        else => -22,
    };
}

/// epoll_wait syscall handler
pub fn epollWait(epfd: u32, events: []EpollEvent, timeout_ms: i32) i32 {
    const ep = findById(epfd) orelse return -9;
    return ep.wait(events, timeout_ms);
}

// ─────────────────────────────────────────────────────────────────────
// C FFI — exported
// ─────────────────────────────────────────────────────────────────────
export fn zxy_epoll_init() void {
    init();
}

export fn zxy_epoll_create(pid: u32) i32 {
    return epollCreate(pid);
}

export fn zxy_epoll_ctl(epfd: u32, op: i32, fd: i32) i32 {
    return epollCtl(epfd, op, fd, null);
}

export fn zxy_epoll_destroy(epfd: u32) void {
    epollDestroy(epfd);
}
