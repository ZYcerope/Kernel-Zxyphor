// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Hierarchical Timer Wheel
//
// Multi-level cascading timer wheel inspired by Linux kernel's timer infrastructure.
// Provides O(1) timer insertion and expiry with hierarchical cascading from coarse
// to fine granularity levels. Supports periodic timers, one-shot timers, timer
// modification, and high-resolution timer (hrtimer) emulation on top of the wheel.

const std = @import("std");

// ============================================================================
// Constants
// ============================================================================

/// Each wheel level has 256 slots (8 bits per level)
pub const TVN_BITS: u32 = 8;
pub const TVN_SIZE: u32 = 1 << TVN_BITS; // 256
pub const TVN_MASK: u64 = TVN_SIZE - 1; // 0xFF

/// Root level has 256 slots as well
pub const TVR_BITS: u32 = 8;
pub const TVR_SIZE: u32 = 1 << TVR_BITS; // 256
pub const TVR_MASK: u64 = TVR_SIZE - 1; // 0xFF

/// Number of cascading levels (tv1 + tv2 + tv3 + tv4 + tv5)
pub const WHEEL_LEVELS: u32 = 5;

/// Maximum timer expiry: 2^(8+8+8+8+8) - 1 = ~1.1 trillion ticks
/// In practice limited to u64 range
pub const MAX_TIMER_TICKS: u64 = (1 << (TVR_BITS + 4 * TVN_BITS)) - 1;

/// Timer tick frequency (ticks per second) — configurable, default 1000 Hz
pub const HZ: u64 = 1000;

/// Nanoseconds per tick
pub const NS_PER_TICK: u64 = 1_000_000_000 / HZ;

/// Maximum number of managed timers
pub const MAX_TIMERS: u32 = 2048;

/// Maximum number of high-resolution timers
pub const MAX_HRTIMERS: u32 = 256;

/// Timer states
pub const TIMER_INACTIVE: u8 = 0;
pub const TIMER_PENDING: u8 = 1;
pub const TIMER_RUNNING: u8 = 2;
pub const TIMER_MIGRATING: u8 = 3;

// ============================================================================
// Timer callback ID — identifies what to invoke on expiry
// ============================================================================

pub const TimerCallbackId = enum(u16) {
    none = 0,
    sched_tick = 1,
    watchdog = 2,
    tcp_retransmit = 3,
    tcp_keepalive = 4,
    tcp_delack = 5,
    arp_expire = 6,
    route_gc = 7,
    neigh_gc = 8,
    inode_cache_shrink = 9,
    dentry_cache_shrink = 10,
    writeback_wakeup = 11,
    journal_commit = 12,
    swap_scan = 13,
    oom_scan = 14,
    rcu_callback = 15,
    workqueue_delayed = 16,
    poll_timeout = 17,
    futex_timeout = 18,
    alarm_expire = 19,
    posix_timer = 20,
    itimer_expire = 21,
    hrtimer_wakeup = 22,
    net_bh_delayed = 23,
    blk_timeout = 24,
    device_timeout = 25,
    user_callback_0 = 100,
    user_callback_1 = 101,
    user_callback_2 = 102,
    user_callback_3 = 103,
    user_callback_4 = 104,
    _,
};

// ============================================================================
// Timer flags
// ============================================================================

pub const TimerFlags = packed struct {
    deferrable: bool = false, // Can be deferred for power saving
    pinned: bool = false, // Pinned to specific CPU
    irqsafe: bool = false, // Safe to run in IRQ context
    periodic: bool = false, // Auto-rescheduling periodic timer
    high_res: bool = false, // High resolution timer
    no_cascade: bool = false, // Do not cascade (internal)
    slack_aware: bool = false, // Group with nearby timers
    _pad: u1 = 0,
};

// ============================================================================
// Timer Entry
// ============================================================================

pub const TimerEntry = struct {
    /// Absolute expiry time in jiffies
    expires: u64,
    /// Callback identifier
    callback: TimerCallbackId,
    /// Opaque data passed to callback
    data: u64,
    /// Secondary data / context
    data2: u64,
    /// Timer flags
    flags: TimerFlags,
    /// Current state
    state: u8,
    /// CPU affinity (for pinned timers)
    cpu: u8,
    /// Period in ticks (for periodic timers)
    period: u64,
    /// Slack allowance in ticks (for grouping)
    slack: u64,
    /// Wheel level where this timer is queued (0xFF = not queued)
    wheel_level: u8,
    /// Slot index within that wheel level
    wheel_slot: u16,
    /// Linked list: next timer index in same slot (0xFFFF = end)
    next: u16,
    /// Linked list: prev timer index in same slot (0xFFFF = end)
    prev: u16,
    /// Number of times this timer has fired
    fire_count: u64,
    /// Creation time (jiffies)
    created_at: u64,

    pub fn init() TimerEntry {
        return TimerEntry{
            .expires = 0,
            .callback = .none,
            .data = 0,
            .data2 = 0,
            .flags = .{},
            .state = TIMER_INACTIVE,
            .cpu = 0,
            .period = 0,
            .slack = 0,
            .wheel_level = 0xFF,
            .wheel_slot = 0,
            .next = 0xFFFF,
            .prev = 0xFFFF,
            .fire_count = 0,
            .created_at = 0,
        };
    }

    pub fn is_pending(self: *const TimerEntry) bool {
        return self.state == TIMER_PENDING;
    }

    pub fn is_periodic(self: *const TimerEntry) bool {
        return self.flags.periodic and self.period > 0;
    }

    pub fn time_until(self: *const TimerEntry, now: u64) u64 {
        if (self.expires > now) return self.expires - now;
        return 0;
    }
};

// ============================================================================
// Wheel Slot — head of a linked list of timer indices
// ============================================================================

pub const WheelSlot = struct {
    head: u16, // Index into timer array, 0xFFFF = empty
    count: u16,

    pub fn init() WheelSlot {
        return WheelSlot{ .head = 0xFFFF, .count = 0 };
    }

    pub fn is_empty(self: *const WheelSlot) bool {
        return self.head == 0xFFFF;
    }
};

// ============================================================================
// High-Resolution Timer
// ============================================================================

pub const HrtimerMode = enum(u8) {
    abs = 0, // Absolute time
    rel = 1, // Relative to now
    abs_pinned = 2,
    rel_pinned = 3,
};

pub const HrtimerState = enum(u8) {
    inactive = 0,
    enqueued = 1,
    running = 2,
};

pub const Hrtimer = struct {
    /// Expiry time in nanoseconds (absolute, monotonic)
    expires_ns: u64,
    /// Softexpiry for slack-based grouping
    softexpires_ns: u64,
    /// Callback identifier
    callback: TimerCallbackId,
    /// Context data
    data: u64,
    /// State
    state: HrtimerState,
    /// Mode
    mode: HrtimerMode,
    /// Period in nanoseconds (0 = one-shot)
    period_ns: u64,
    /// Number of overruns (late fires)
    overrun_count: u64,
    /// Fire count
    fire_count: u64,

    pub fn init() Hrtimer {
        return Hrtimer{
            .expires_ns = 0,
            .softexpires_ns = 0,
            .callback = .none,
            .data = 0,
            .state = .inactive,
            .mode = .rel,
            .period_ns = 0,
            .overrun_count = 0,
            .fire_count = 0,
        };
    }

    pub fn is_active(self: *const Hrtimer) bool {
        return self.state != .inactive;
    }
};

// ============================================================================
// Timer Statistics
// ============================================================================

pub const TimerStats = struct {
    total_added: u64,
    total_deleted: u64,
    total_expired: u64,
    total_cascades: u64,
    total_periodic_refires: u64,
    total_hrtimer_fired: u64,
    total_hrtimer_overruns: u64,
    max_pending: u32,
    max_expired_per_tick: u32,
    current_pending: u32,
    cascade_count_by_level: [WHEEL_LEVELS]u64,
    longest_timer_ticks: u64,
    shortest_timer_ticks: u64,

    pub fn init() TimerStats {
        return TimerStats{
            .total_added = 0,
            .total_deleted = 0,
            .total_expired = 0,
            .total_cascades = 0,
            .total_periodic_refires = 0,
            .total_hrtimer_fired = 0,
            .total_hrtimer_overruns = 0,
            .max_pending = 0,
            .max_expired_per_tick = 0,
            .current_pending = 0,
            .cascade_count_by_level = [_]u64{0} ** WHEEL_LEVELS,
            .longest_timer_ticks = 0,
            .shortest_timer_ticks = ~@as(u64, 0),
        };
    }
};

// ============================================================================
// Timer Wheel — the main multi-level cascading wheel
// ============================================================================

pub const TimerWheel = struct {
    /// Current tick count (jiffies)
    jiffies: u64,

    /// Monotonic nanosecond counter
    monotonic_ns: u64,

    /// Level 0 (tv1): finest granularity, 256 slots, each 1 tick
    tv1: [TVR_SIZE]WheelSlot,

    /// Level 1 (tv2): 256 slots, each 256 ticks
    tv2: [TVN_SIZE]WheelSlot,

    /// Level 2 (tv3): 256 slots, each 65536 ticks
    tv3: [TVN_SIZE]WheelSlot,

    /// Level 3 (tv4): 256 slots, each 16M ticks
    tv4: [TVN_SIZE]WheelSlot,

    /// Level 4 (tv5): 256 slots, each 4G ticks
    tv5: [TVN_SIZE]WheelSlot,

    /// All timer entries pool
    timers: [MAX_TIMERS]TimerEntry,
    timer_count: u32,

    /// Free list head
    free_head: u16,

    /// High-resolution timers (sorted by expiry, simple array)
    hrtimers: [MAX_HRTIMERS]Hrtimer,
    hrtimer_count: u32,

    /// Statistics
    stats: TimerStats,

    /// Next timer expiry (cached for idle optimization)
    next_expiry: u64,

    /// Whether next_expiry is valid
    next_expiry_valid: bool,

    /// Tick accumulator for sub-tick precision
    tick_remainder_ns: u64,

    pub fn init() TimerWheel {
        var wheel = TimerWheel{
            .jiffies = 0,
            .monotonic_ns = 0,
            .tv1 = undefined,
            .tv2 = undefined,
            .tv3 = undefined,
            .tv4 = undefined,
            .tv5 = undefined,
            .timers = undefined,
            .timer_count = 0,
            .free_head = 0,
            .hrtimers = undefined,
            .hrtimer_count = 0,
            .stats = TimerStats.init(),
            .next_expiry = ~@as(u64, 0),
            .next_expiry_valid = false,
            .tick_remainder_ns = 0,
        };

        // Initialize all wheel slots
        for (&wheel.tv1) |*s| s.* = WheelSlot.init();
        for (&wheel.tv2) |*s| s.* = WheelSlot.init();
        for (&wheel.tv3) |*s| s.* = WheelSlot.init();
        for (&wheel.tv4) |*s| s.* = WheelSlot.init();
        for (&wheel.tv5) |*s| s.* = WheelSlot.init();

        // Initialize timer pool with free list chain
        var i: u16 = 0;
        while (i < MAX_TIMERS) : (i += 1) {
            wheel.timers[i] = TimerEntry.init();
            wheel.timers[i].next = if (i + 1 < MAX_TIMERS) i + 1 else 0xFFFF;
        }

        for (&wheel.hrtimers) |*h| h.* = Hrtimer.init();

        return wheel;
    }

    // ---- Timer pool allocation ----

    fn alloc_timer(self: *TimerWheel) ?u16 {
        if (self.free_head == 0xFFFF) return null;
        const idx = self.free_head;
        self.free_head = self.timers[idx].next;
        self.timers[idx].next = 0xFFFF;
        self.timers[idx].prev = 0xFFFF;
        self.timer_count += 1;
        return idx;
    }

    fn free_timer(self: *TimerWheel, idx: u16) void {
        self.timers[idx] = TimerEntry.init();
        self.timers[idx].next = self.free_head;
        self.free_head = idx;
        if (self.timer_count > 0) self.timer_count -= 1;
    }

    // ---- Slot operations (doubly-linked list) ----

    fn get_slot(self: *TimerWheel, level: u8, slot_idx: u16) *WheelSlot {
        return switch (level) {
            0 => &self.tv1[slot_idx],
            1 => &self.tv2[slot_idx],
            2 => &self.tv3[slot_idx],
            3 => &self.tv4[slot_idx],
            4 => &self.tv5[slot_idx],
            else => &self.tv1[0],
        };
    }

    fn insert_into_slot(self: *TimerWheel, level: u8, slot_idx: u16, timer_idx: u16) void {
        const slot = self.get_slot(level, slot_idx);
        self.timers[timer_idx].wheel_level = level;
        self.timers[timer_idx].wheel_slot = slot_idx;
        self.timers[timer_idx].prev = 0xFFFF;
        self.timers[timer_idx].next = slot.head;
        if (slot.head != 0xFFFF) {
            self.timers[slot.head].prev = timer_idx;
        }
        slot.head = timer_idx;
        slot.count += 1;
    }

    fn remove_from_slot(self: *TimerWheel, timer_idx: u16) void {
        const timer = &self.timers[timer_idx];
        if (timer.wheel_level == 0xFF) return;

        const slot = self.get_slot(timer.wheel_level, timer.wheel_slot);

        // Unlink from doubly-linked list
        if (timer.prev != 0xFFFF) {
            self.timers[timer.prev].next = timer.next;
        } else {
            slot.head = timer.next;
        }
        if (timer.next != 0xFFFF) {
            self.timers[timer.next].prev = timer.prev;
        }

        timer.wheel_level = 0xFF;
        timer.next = 0xFFFF;
        timer.prev = 0xFFFF;
        if (slot.count > 0) slot.count -= 1;
    }

    // ---- Calculate which level and slot a timer expires in ----

    fn calc_wheel_position(self: *const TimerWheel, expires: u64) struct { level: u8, slot: u16 } {
        const delta = if (expires > self.jiffies) expires - self.jiffies else 0;

        if (delta < TVR_SIZE) {
            // Level 0: within 256 ticks
            return .{ .level = 0, .slot = @intCast(expires & TVR_MASK) };
        } else if (delta < (1 << (TVR_BITS + TVN_BITS))) {
            // Level 1: within 65536 ticks
            const idx = (expires >> TVR_BITS) & TVN_MASK;
            return .{ .level = 1, .slot = @intCast(idx) };
        } else if (delta < (1 << (TVR_BITS + 2 * TVN_BITS))) {
            // Level 2: within ~16M ticks
            const idx = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
            return .{ .level = 2, .slot = @intCast(idx) };
        } else if (delta < (1 << (TVR_BITS + 3 * TVN_BITS))) {
            // Level 3: within ~4G ticks
            const idx = (expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK;
            return .{ .level = 3, .slot = @intCast(idx) };
        } else {
            // Level 4: everything else
            var adjusted = delta;
            if (adjusted > MAX_TIMER_TICKS) adjusted = MAX_TIMER_TICKS;
            const idx = (expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK;
            return .{ .level = 4, .slot = @intCast(idx) };
        }
    }

    // ---- Public API: Add a timer ----

    pub fn add_timer(self: *TimerWheel, callback: TimerCallbackId, expires_ticks: u64, data: u64, flags: TimerFlags) ?u16 {
        const idx = self.alloc_timer() orelse return null;

        var abs_expires = self.jiffies + expires_ticks;
        if (abs_expires < self.jiffies) abs_expires = ~@as(u64, 0); // overflow protection

        // Apply slack for deferrable/slack-aware timers
        if (flags.deferrable or flags.slack_aware) {
            const slack = expires_ticks / 32; // ~3% slack
            self.timers[idx].slack = slack;
            // Round up to group with nearby timers
            if (slack > 0) {
                abs_expires = ((abs_expires + slack - 1) / slack) * slack;
            }
        }

        self.timers[idx].expires = abs_expires;
        self.timers[idx].callback = callback;
        self.timers[idx].data = data;
        self.timers[idx].flags = flags;
        self.timers[idx].state = TIMER_PENDING;
        self.timers[idx].created_at = self.jiffies;

        if (flags.periodic) {
            self.timers[idx].period = expires_ticks;
        }

        // Place in wheel
        const pos = self.calc_wheel_position(abs_expires);
        self.insert_into_slot(pos.level, pos.slot, idx);

        // Update stats
        self.stats.total_added += 1;
        self.stats.current_pending += 1;
        if (self.stats.current_pending > self.stats.max_pending) {
            self.stats.max_pending = self.stats.current_pending;
        }

        // Track timing stats
        if (expires_ticks > self.stats.longest_timer_ticks) {
            self.stats.longest_timer_ticks = expires_ticks;
        }
        if (expires_ticks < self.stats.shortest_timer_ticks) {
            self.stats.shortest_timer_ticks = expires_ticks;
        }

        // Invalidate next_expiry cache if this fires sooner
        if (abs_expires < self.next_expiry) {
            self.next_expiry = abs_expires;
            self.next_expiry_valid = true;
        }

        return idx;
    }

    /// Add a periodic timer
    pub fn add_periodic_timer(self: *TimerWheel, callback: TimerCallbackId, period: u64, data: u64) ?u16 {
        var flags = TimerFlags{};
        flags.periodic = true;
        return self.add_timer(callback, period, data, flags);
    }

    /// Delete a timer by index
    pub fn del_timer(self: *TimerWheel, idx: u16) bool {
        if (idx >= MAX_TIMERS) return false;
        if (self.timers[idx].state == TIMER_INACTIVE) return false;

        self.remove_from_slot(idx);
        self.free_timer(idx);
        self.stats.total_deleted += 1;
        if (self.stats.current_pending > 0) self.stats.current_pending -= 1;
        self.next_expiry_valid = false;
        return true;
    }

    /// Modify timer expiry (del + re-add atomically)
    pub fn mod_timer(self: *TimerWheel, idx: u16, new_expires_ticks: u64) bool {
        if (idx >= MAX_TIMERS) return false;
        if (self.timers[idx].state != TIMER_PENDING) return false;

        // Remove from current slot
        self.remove_from_slot(idx);

        // Recalculate absolute expiry
        var abs_expires = self.jiffies + new_expires_ticks;
        if (abs_expires < self.jiffies) abs_expires = ~@as(u64, 0);

        self.timers[idx].expires = abs_expires;

        // Re-insert
        const pos = self.calc_wheel_position(abs_expires);
        self.insert_into_slot(pos.level, pos.slot, idx);

        self.next_expiry_valid = false;
        return true;
    }

    // ---- Cascade: migrate timers from higher level to lower ----

    fn cascade(self: *TimerWheel, level: u8) u32 {
        const slot_idx: u16 = switch (level) {
            1 => @intCast((self.jiffies >> TVR_BITS) & TVN_MASK),
            2 => @intCast((self.jiffies >> (TVR_BITS + TVN_BITS)) & TVN_MASK),
            3 => @intCast((self.jiffies >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK),
            4 => @intCast((self.jiffies >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK),
            else => return 0,
        };

        const slot = self.get_slot(level, slot_idx);
        var migrated: u32 = 0;

        // Collect all timers from this slot
        var current = slot.head;
        while (current != 0xFFFF) {
            const next = self.timers[current].next;

            // Detach from current slot
            self.timers[current].wheel_level = 0xFF;
            self.timers[current].next = 0xFFFF;
            self.timers[current].prev = 0xFFFF;

            // Re-insert based on new jiffies offset
            const pos = self.calc_wheel_position(self.timers[current].expires);
            self.insert_into_slot(pos.level, pos.slot, current);

            migrated += 1;
            current = next;
        }

        // Clear the source slot
        slot.head = 0xFFFF;
        slot.count = 0;

        if (migrated > 0) {
            self.stats.total_cascades += 1;
            if (level < WHEEL_LEVELS) {
                self.stats.cascade_count_by_level[level] += 1;
            }
        }

        return migrated;
    }

    // ---- Fire expired timers in level 0 ----

    fn run_expired_timers(self: *TimerWheel) u32 {
        const slot_idx: u16 = @intCast(self.jiffies & TVR_MASK);
        const slot = &self.tv1[slot_idx];
        var fired: u32 = 0;

        var current = slot.head;
        while (current != 0xFFFF) {
            const next = self.timers[current].next;
            const timer = &self.timers[current];

            if (timer.expires <= self.jiffies) {
                // Detach from slot
                timer.wheel_level = 0xFF;
                timer.prev = 0xFFFF;
                timer.next = 0xFFFF;

                // Mark running
                timer.state = TIMER_RUNNING;
                timer.fire_count += 1;

                // Execute callback (external dispatch)
                dispatch_timer_callback(timer.callback, timer.data, timer.data2);

                self.stats.total_expired += 1;
                fired += 1;

                // Handle periodic re-arm
                if (timer.is_periodic()) {
                    timer.expires = self.jiffies + timer.period;
                    timer.state = TIMER_PENDING;
                    const pos = self.calc_wheel_position(timer.expires);
                    self.insert_into_slot(pos.level, pos.slot, current);
                    self.stats.total_periodic_refires += 1;
                } else {
                    // One-shot: free the timer
                    self.free_timer(current);
                    if (self.stats.current_pending > 0) self.stats.current_pending -= 1;
                }
            }

            current = next;
        }

        // Clear slot (periodic timers already re-inserted elsewhere)
        if (fired > 0) {
            // Rebuild slot for any remaining timers
            slot.head = 0xFFFF;
            slot.count = 0;

            // Re-scan timers pool for any still in this slot
            // (periodic timers may have been re-inserted into same slot)
            var i: u16 = 0;
            while (i < MAX_TIMERS) : (i += 1) {
                if (self.timers[i].state == TIMER_PENDING and
                    self.timers[i].wheel_level == 0 and
                    self.timers[i].wheel_slot == slot_idx)
                {
                    // Already linked via insert_into_slot, just count
                }
            }
        }

        if (fired > self.stats.max_expired_per_tick) {
            self.stats.max_expired_per_tick = fired;
        }

        return fired;
    }

    // ---- Main tick handler: advance jiffies and process timers ----

    pub fn tick(self: *TimerWheel) u32 {
        self.jiffies += 1;
        self.monotonic_ns += NS_PER_TICK;

        // Check if we need to cascade from higher levels
        // Cascade when lower bits roll over
        const idx = self.jiffies;
        if ((idx & TVR_MASK) == 0) {
            // tv1 wrapped, cascade from tv2
            _ = self.cascade(1);

            if (((idx >> TVR_BITS) & TVN_MASK) == 0) {
                // tv2 wrapped, cascade from tv3
                _ = self.cascade(2);

                if (((idx >> (TVR_BITS + TVN_BITS)) & TVN_MASK) == 0) {
                    // tv3 wrapped, cascade from tv4
                    _ = self.cascade(3);

                    if (((idx >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK) == 0) {
                        // tv4 wrapped, cascade from tv5
                        _ = self.cascade(4);
                    }
                }
            }
        }

        // Run expired timers in tv1
        const fired = self.run_expired_timers();

        // Process high-resolution timers
        const hr_fired = self.process_hrtimers();
        _ = hr_fired;

        self.next_expiry_valid = false;

        return fired;
    }

    /// Advance multiple ticks at once (catch-up after idle)
    pub fn tick_multi(self: *TimerWheel, count: u64) u64 {
        var total_fired: u64 = 0;
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            total_fired += self.tick();
        }
        return total_fired;
    }

    // ---- High-resolution timer subsystem ----

    pub fn hrtimer_add(self: *TimerWheel, callback: TimerCallbackId, expires_ns: u64, data: u64, mode: HrtimerMode) ?u16 {
        if (self.hrtimer_count >= MAX_HRTIMERS) return null;

        var abs_ns = expires_ns;
        if (mode == .rel or mode == .rel_pinned) {
            abs_ns = self.monotonic_ns + expires_ns;
        }

        // Find insertion point (sorted by expires_ns)
        var insert_idx: u32 = self.hrtimer_count;
        var i: u32 = 0;
        while (i < self.hrtimer_count) : (i += 1) {
            if (self.hrtimers[i].state == .inactive) {
                insert_idx = i;
                break;
            }
            if (abs_ns < self.hrtimers[i].expires_ns and self.hrtimers[i].state == .enqueued) {
                // We'll store at the first inactive slot
            }
        }

        if (insert_idx >= MAX_HRTIMERS) return null;

        self.hrtimers[insert_idx] = Hrtimer{
            .expires_ns = abs_ns,
            .softexpires_ns = abs_ns,
            .callback = callback,
            .data = data,
            .state = .enqueued,
            .mode = mode,
            .period_ns = 0,
            .overrun_count = 0,
            .fire_count = 0,
        };
        self.hrtimer_count += 1;
        return @intCast(insert_idx);
    }

    pub fn hrtimer_add_periodic(self: *TimerWheel, callback: TimerCallbackId, period_ns: u64, data: u64) ?u16 {
        const idx = self.hrtimer_add(callback, period_ns, data, .rel) orelse return null;
        self.hrtimers[idx].period_ns = period_ns;
        return idx;
    }

    pub fn hrtimer_cancel(self: *TimerWheel, idx: u16) bool {
        if (idx >= MAX_HRTIMERS) return false;
        if (self.hrtimers[idx].state == .inactive) return false;
        self.hrtimers[idx].state = .inactive;
        if (self.hrtimer_count > 0) self.hrtimer_count -= 1;
        return true;
    }

    fn process_hrtimers(self: *TimerWheel) u32 {
        var fired: u32 = 0;
        for (&self.hrtimers) |*hr| {
            if (hr.state != .enqueued) continue;
            if (hr.expires_ns > self.monotonic_ns) continue;

            hr.state = .running;
            hr.fire_count += 1;

            // Check for overruns
            if (self.monotonic_ns > hr.expires_ns + NS_PER_TICK) {
                const late_ns = self.monotonic_ns - hr.expires_ns;
                if (hr.period_ns > 0) {
                    hr.overrun_count += late_ns / hr.period_ns;
                    self.stats.total_hrtimer_overruns += late_ns / hr.period_ns;
                }
            }

            dispatch_timer_callback(hr.callback, hr.data, 0);
            fired += 1;
            self.stats.total_hrtimer_fired += 1;

            // Re-arm periodic hrtimers
            if (hr.period_ns > 0) {
                hr.expires_ns = self.monotonic_ns + hr.period_ns;
                hr.softexpires_ns = hr.expires_ns;
                hr.state = .enqueued;
            } else {
                hr.state = .inactive;
                if (self.hrtimer_count > 0) self.hrtimer_count -= 1;
            }
        }
        return fired;
    }

    // ---- Query / utility ----

    /// Find the next scheduled expiry (for tickless idle)
    pub fn get_next_expiry(self: *TimerWheel) u64 {
        if (self.next_expiry_valid) return self.next_expiry;

        var min_expiry: u64 = ~@as(u64, 0);

        // Check level 0 forward from current slot
        const base = self.jiffies & TVR_MASK;
        var i: u32 = 0;
        while (i < TVR_SIZE) : (i += 1) {
            const slot_idx = (base + i) % TVR_SIZE;
            if (!self.tv1[slot_idx].is_empty()) {
                const candidate = self.jiffies + i;
                if (candidate < min_expiry) {
                    min_expiry = candidate;
                    break; // First non-empty slot is the earliest
                }
            }
        }

        // If nothing in tv1, check hrtimers
        for (&self.hrtimers) |*hr| {
            if (hr.state == .enqueued) {
                const jiffy_equiv = hr.expires_ns / NS_PER_TICK;
                if (jiffy_equiv < min_expiry) {
                    min_expiry = jiffy_equiv;
                }
            }
        }

        self.next_expiry = min_expiry;
        self.next_expiry_valid = true;
        return min_expiry;
    }

    /// Get timer info by index
    pub fn get_timer_expires(self: *const TimerWheel, idx: u16) u64 {
        if (idx >= MAX_TIMERS) return 0;
        return self.timers[idx].expires;
    }

    /// Check if a timer is active
    pub fn is_timer_pending(self: *const TimerWheel, idx: u16) bool {
        if (idx >= MAX_TIMERS) return false;
        return self.timers[idx].state == TIMER_PENDING;
    }

    /// Get remaining ticks for timer
    pub fn timer_remaining(self: *const TimerWheel, idx: u16) u64 {
        if (idx >= MAX_TIMERS) return 0;
        return self.timers[idx].time_until(self.jiffies);
    }

    /// Convert milliseconds to ticks
    pub fn ms_to_ticks(ms: u64) u64 {
        return (ms * HZ + 999) / 1000;
    }

    /// Convert ticks to milliseconds
    pub fn ticks_to_ms(ticks: u64) u64 {
        return (ticks * 1000) / HZ;
    }

    /// Convert nanoseconds to ticks
    pub fn ns_to_ticks(ns: u64) u64 {
        return (ns + NS_PER_TICK - 1) / NS_PER_TICK;
    }
};

// ============================================================================
// External callback dispatch (implemented by kernel core)
// ============================================================================

extern fn zxy_timer_dispatch(callback_id: u16, data: u64, data2: u64) void;
extern fn zxy_timer_get_ns() u64;
extern fn zxy_timer_get_cpu() u8;

fn dispatch_timer_callback(callback: TimerCallbackId, data: u64, data2: u64) void {
    zxy_timer_dispatch(@intFromEnum(callback), data, data2);
}

// ============================================================================
// Global timer wheel instance
// ============================================================================

var global_wheel: TimerWheel = TimerWheel.init();

// ============================================================================
// Convenience API: schedule timeouts
// ============================================================================

pub const Timeout = struct {
    timer_idx: u16,
    started_at: u64,
    duration_ticks: u64,

    pub fn is_expired(self: *const Timeout) bool {
        return !global_wheel.is_timer_pending(self.timer_idx);
    }

    pub fn remaining_ms(self: *const Timeout) u64 {
        const rem = global_wheel.timer_remaining(self.timer_idx);
        return TimerWheel.ticks_to_ms(rem);
    }

    pub fn cancel(self: *Timeout) void {
        _ = global_wheel.del_timer(self.timer_idx);
    }
};

pub fn schedule_timeout_ms(callback: TimerCallbackId, ms: u64, data: u64) ?Timeout {
    const ticks = TimerWheel.ms_to_ticks(ms);
    const idx = global_wheel.add_timer(callback, ticks, data, .{}) orelse return null;
    return Timeout{
        .timer_idx = idx,
        .started_at = global_wheel.jiffies,
        .duration_ticks = ticks,
    };
}

pub fn schedule_timeout_periodic_ms(callback: TimerCallbackId, ms: u64, data: u64) ?Timeout {
    const ticks = TimerWheel.ms_to_ticks(ms);
    const idx = global_wheel.add_periodic_timer(callback, ticks, data) orelse return null;
    return Timeout{
        .timer_idx = idx,
        .started_at = global_wheel.jiffies,
        .duration_ticks = ticks,
    };
}

// ============================================================================
// Process-sleep integration: sleep_on / wake_up helpers
// ============================================================================

pub const SleepEntry = struct {
    pid: u32,
    timer_idx: u16,
    woken: bool,
    reason: WakeReason,
};

pub const WakeReason = enum(u8) {
    none = 0,
    timeout = 1,
    signal = 2,
    explicit = 3,
    interrupt = 4,
};

var sleep_entries: [256]SleepEntry = init_sleep_entries();

fn init_sleep_entries() [256]SleepEntry {
    var entries: [256]SleepEntry = undefined;
    for (&entries) |*e| {
        e.* = SleepEntry{ .pid = 0, .timer_idx = 0xFFFF, .woken = true, .reason = .none };
    }
    return entries;
}

pub fn sleep_on_timeout(pid: u32, ms: u64) ?u8 {
    // Find free sleep entry
    for (&sleep_entries, 0..) |*entry, i| {
        if (entry.woken) {
            const idx = global_wheel.add_timer(
                .futex_timeout,
                TimerWheel.ms_to_ticks(ms),
                @as(u64, pid),
                .{},
            ) orelse return null;

            entry.pid = pid;
            entry.timer_idx = idx;
            entry.woken = false;
            entry.reason = .none;
            return @intCast(i);
        }
    }
    return null;
}

pub fn wake_up_sleeper(entry_idx: u8, reason: WakeReason) void {
    if (entry_idx >= 256) return;
    var entry = &sleep_entries[entry_idx];
    if (entry.woken) return;

    // Cancel the timer if still pending
    if (entry.timer_idx != 0xFFFF) {
        _ = global_wheel.del_timer(entry.timer_idx);
        entry.timer_idx = 0xFFFF;
    }
    entry.woken = true;
    entry.reason = reason;
}

// ============================================================================
// FFI Exports
// ============================================================================

export fn zxy_timer_wheel_init() void {
    global_wheel = TimerWheel.init();
}

export fn zxy_timer_wheel_tick() u32 {
    return global_wheel.tick();
}

export fn zxy_timer_wheel_tick_multi(count: u64) u64 {
    return global_wheel.tick_multi(count);
}

export fn zxy_timer_wheel_add(callback_id: u16, expires_ticks: u64, data: u64, periodic: u8) i32 {
    var flags = TimerFlags{};
    if (periodic != 0) flags.periodic = true;
    const idx = global_wheel.add_timer(@enumFromInt(callback_id), expires_ticks, data, flags) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_timer_wheel_add_ms(callback_id: u16, ms: u64, data: u64) i32 {
    const ticks = TimerWheel.ms_to_ticks(ms);
    const idx = global_wheel.add_timer(@enumFromInt(callback_id), ticks, data, .{}) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_timer_wheel_del(idx: u16) u8 {
    return if (global_wheel.del_timer(idx)) 1 else 0;
}

export fn zxy_timer_wheel_mod(idx: u16, new_ticks: u64) u8 {
    return if (global_wheel.mod_timer(idx, new_ticks)) 1 else 0;
}

export fn zxy_timer_wheel_remaining(idx: u16) u64 {
    return global_wheel.timer_remaining(idx);
}

export fn zxy_timer_wheel_is_pending(idx: u16) u8 {
    return if (global_wheel.is_timer_pending(idx)) 1 else 0;
}

export fn zxy_timer_wheel_jiffies() u64 {
    return global_wheel.jiffies;
}

export fn zxy_timer_wheel_monotonic_ns() u64 {
    return global_wheel.monotonic_ns;
}

export fn zxy_timer_wheel_next_expiry() u64 {
    return global_wheel.get_next_expiry();
}

export fn zxy_timer_wheel_pending_count() u32 {
    return global_wheel.stats.current_pending;
}

export fn zxy_timer_wheel_total_expired() u64 {
    return global_wheel.stats.total_expired;
}

export fn zxy_timer_wheel_total_cascades() u64 {
    return global_wheel.stats.total_cascades;
}

export fn zxy_timer_wheel_total_added() u64 {
    return global_wheel.stats.total_added;
}

export fn zxy_hrtimer_add(callback_id: u16, expires_ns: u64, data: u64, mode: u8) i32 {
    const m: HrtimerMode = @enumFromInt(mode);
    const idx = global_wheel.hrtimer_add(@enumFromInt(callback_id), expires_ns, data, m) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_hrtimer_add_periodic(callback_id: u16, period_ns: u64, data: u64) i32 {
    const idx = global_wheel.hrtimer_add_periodic(@enumFromInt(callback_id), period_ns, data) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_hrtimer_cancel(idx: u16) u8 {
    return if (global_wheel.hrtimer_cancel(idx)) 1 else 0;
}

export fn zxy_hrtimer_total_fired() u64 {
    return global_wheel.stats.total_hrtimer_fired;
}

export fn zxy_hrtimer_total_overruns() u64 {
    return global_wheel.stats.total_hrtimer_overruns;
}

export fn zxy_sleep_on_timeout(pid: u32, ms: u64) i32 {
    const idx = sleep_on_timeout(pid, ms) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_wake_up(entry_idx: u8, reason: u8) void {
    wake_up_sleeper(entry_idx, @enumFromInt(reason));
}
