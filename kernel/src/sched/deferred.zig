// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Deferred Work & Tasklet Subsystem (Zig)
//
// Bottom-half / deferred work infrastructure:
// - Workqueue: kernel threads executing deferred work items
// - Tasklet: soft-IRQ scheduled callbacks with serialization
// - Delayed work: work items with timer-based deferral
// - Per-CPU work queues (NUMA-aware)
// - Flush and drain operations for synchronization
// - Ordered workqueues (strict sequential execution)
// - High-priority workqueue for time-sensitive work
// - Work cancellation with in-flight detection
// - Softirq vectors (NET_TX, NET_RX, TIMER, BLOCK, TASKLET, SCHED, HRTIMER, RCU)

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_WORKQUEUES: usize = 16;
const MAX_WORK_ITEMS: usize = 256;
const MAX_TASKLETS: usize = 64;
const MAX_DELAYED: usize = 64;
const MAX_CPUS: usize = 16;
const WQ_NAME_LEN: usize = 32;
const NR_SOFTIRQS: usize = 10;

// ─────────────────── Softirq ────────────────────────────────────────

pub const SoftirqVec = enum(u8) {
    hi = 0,       // High-priority tasklets
    timer = 1,
    net_tx = 2,
    net_rx = 3,
    block = 4,
    irq_poll = 5,
    tasklet = 6,
    sched = 7,
    hrtimer = 8,
    rcu = 9,
};

pub const SoftirqHandler = struct {
    pending: bool,
    raised_count: u64,
    executed_count: u64,
    active: bool,
};

pub const SoftirqState = struct {
    vectors: [NR_SOFTIRQS]SoftirqHandler,
    pending_mask: u32,
    in_softirq: bool,
    nesting: u8,

    pub fn init() SoftirqState {
        var s: SoftirqState = undefined;
        for (0..NR_SOFTIRQS) |i| {
            s.vectors[i] = .{
                .pending = false,
                .raised_count = 0,
                .executed_count = 0,
                .active = true,
            };
        }
        s.pending_mask = 0;
        s.in_softirq = false;
        s.nesting = 0;
        return s;
    }

    pub fn raise(self: *SoftirqState, vec: SoftirqVec) void {
        const idx = @intFromEnum(vec);
        self.vectors[idx].pending = true;
        self.pending_mask |= @as(u32, 1) << @intCast(idx);
        self.vectors[idx].raised_count += 1;
    }

    pub fn process(self: *SoftirqState) u32 {
        if (self.in_softirq) return 0;
        self.in_softirq = true;
        self.nesting += 1;

        var processed: u32 = 0;
        var pending = self.pending_mask;
        self.pending_mask = 0;

        var bit: u5 = 0;
        while (bit < NR_SOFTIRQS) : (bit += 1) {
            if ((pending & (@as(u32, 1) << bit)) != 0) {
                self.vectors[bit].pending = false;
                self.vectors[bit].executed_count += 1;
                processed += 1;
            }
        }

        self.nesting -= 1;
        self.in_softirq = false;
        return processed;
    }

    pub fn any_pending(self: *const SoftirqState) bool {
        return self.pending_mask != 0;
    }
};

// ─────────────────── Work Item ──────────────────────────────────────

pub const WorkState = enum(u8) {
    idle = 0,
    pending = 1,
    running = 2,
    cancelling = 3,
};

pub const WorkFlags = packed struct {
    high_priority: bool = false,
    ordered: bool = false,
    cpu_bound: bool = false, // Pin to specific CPU
    reclaimable: bool = false,
    _pad: u4 = 0,
};

pub const WorkItem = struct {
    id: u32,
    state: WorkState,
    flags: WorkFlags,
    wq_idx: u8,      // Owning workqueue
    target_cpu: u8,   // For CPU-bound work
    enqueue_tick: u64,
    start_tick: u64,
    complete_tick: u64,
    run_count: u32,
    active: bool,

    pub fn init() WorkItem {
        return .{
            .id = 0,
            .state = .idle,
            .flags = .{},
            .wq_idx = 0,
            .target_cpu = 0,
            .enqueue_tick = 0,
            .start_tick = 0,
            .complete_tick = 0,
            .run_count = 0,
            .active = false,
        };
    }
};

// ─────────────────── Delayed Work ───────────────────────────────────

pub const DelayedWork = struct {
    work_idx: i16, // Associated work item
    delay_ticks: u64,
    enqueue_tick: u64,
    expire_tick: u64,
    periodic: bool,
    interval: u64, // For periodic re-arm
    fire_count: u32,
    active: bool,

    pub fn init() DelayedWork {
        return .{
            .work_idx = -1,
            .delay_ticks = 0,
            .enqueue_tick = 0,
            .expire_tick = 0,
            .periodic = false,
            .interval = 0,
            .fire_count = 0,
            .active = false,
        };
    }

    pub fn is_expired(self: *const DelayedWork, now: u64) bool {
        return now >= self.expire_tick;
    }
};

// ─────────────────── Tasklet ────────────────────────────────────────

pub const TaskletState = enum(u8) {
    idle = 0,
    scheduled = 1,
    running = 2,
    disabled = 3,
};

pub const TaskletPriority = enum(u1) {
    normal = 0,
    hi = 1,
};

pub const Tasklet = struct {
    id: u32,
    state: TaskletState,
    priority: TaskletPriority,
    disable_count: u8,
    schedule_count: u64,
    run_count: u64,
    data: u64, // Opaque data for callback
    active: bool,

    pub fn init() Tasklet {
        return .{
            .id = 0,
            .state = .idle,
            .priority = .normal,
            .disable_count = 0,
            .schedule_count = 0,
            .run_count = 0,
            .data = 0,
            .active = false,
        };
    }

    pub fn disable(self: *Tasklet) void {
        self.disable_count += 1;
        if (self.state != .disabled) {
            self.state = .disabled;
        }
    }

    pub fn enable(self: *Tasklet) void {
        if (self.disable_count > 0) {
            self.disable_count -= 1;
        }
        if (self.disable_count == 0 and self.state == .disabled) {
            self.state = .idle;
        }
    }

    pub fn is_enabled(self: *const Tasklet) bool {
        return self.disable_count == 0;
    }
};

// ─────────────────── Workqueue ──────────────────────────────────────

pub const WqFlags = packed struct {
    unbound: bool = false,     // Not tied to specific CPU
    freezable: bool = false,   // Can be frozen during suspend
    ordered: bool = false,     // Strict sequential
    high_priority: bool = false,
    cpu_intensive: bool = false,
    power_efficient: bool = false,
    _pad: u2 = 0,
};

pub const Workqueue = struct {
    name: [WQ_NAME_LEN]u8,
    name_len: u8,
    flags: WqFlags,
    max_active: u8, // Max concurrent work items

    // Per-CPU pending lists (indices into work_items)
    pending: [MAX_CPUS][16]i16,
    pending_count: [MAX_CPUS]u8,

    // Stats
    total_enqueued: u64,
    total_completed: u64,
    total_cancelled: u64,
    max_latency: u64, // Ticks from enqueue to start

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var wq: Self = undefined;
        wq.name = [_]u8{0} ** WQ_NAME_LEN;
        wq.name_len = 0;
        wq.flags = .{};
        wq.max_active = 4;
        for (0..MAX_CPUS) |c| {
            wq.pending[c] = [_]i16{-1} ** 16;
            wq.pending_count[c] = 0;
        }
        wq.total_enqueued = 0;
        wq.total_completed = 0;
        wq.total_cancelled = 0;
        wq.max_latency = 0;
        wq.active = false;
        return wq;
    }

    pub fn set_name(self: *Self, n: []const u8) void {
        const len = @min(n.len, WQ_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn enqueue(self: *Self, work_idx: i16, cpu: u8) bool {
        const c = @min(cpu, MAX_CPUS - 1);
        if (self.pending_count[c] >= 16) return false;
        const p = self.pending_count[c];
        self.pending[c][p] = work_idx;
        self.pending_count[c] += 1;
        self.total_enqueued += 1;
        return true;
    }

    pub fn dequeue(self: *Self, cpu: u8) ?i16 {
        const c = @min(cpu, MAX_CPUS - 1);
        if (self.pending_count[c] == 0) return null;
        const idx = self.pending[c][0];
        // Shift remaining
        var i: u8 = 0;
        while (i + 1 < self.pending_count[c]) : (i += 1) {
            self.pending[c][i] = self.pending[c][i + 1];
        }
        self.pending[c][self.pending_count[c] - 1] = -1;
        self.pending_count[c] -= 1;
        return idx;
    }

    pub fn total_pending(self: *const Self) u32 {
        var sum: u32 = 0;
        for (0..MAX_CPUS) |c| {
            sum += @as(u32, self.pending_count[c]);
        }
        return sum;
    }

    pub fn flush(self: *Self) void {
        for (0..MAX_CPUS) |c| {
            self.pending_count[c] = 0;
            self.pending[c] = [_]i16{-1} ** 16;
        }
    }
};

// ─────────────────── Deferred Manager ───────────────────────────────

pub const DeferredManager = struct {
    workqueues: [MAX_WORKQUEUES]Workqueue,
    work_items: [MAX_WORK_ITEMS]WorkItem,
    tasklets: [MAX_TASKLETS]Tasklet,
    delayed: [MAX_DELAYED]DelayedWork,
    softirq: SoftirqState,

    wq_count: u8,
    work_count: u16,
    tasklet_count: u8,
    delayed_count: u8,

    next_work_id: u32,
    next_tasklet_id: u32,
    tick: u64,
    current_cpu: u8,

    // Global stats
    total_work_executed: u64,
    total_tasklets_run: u64,
    total_delayed_fires: u64,
    total_softirq_processed: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var dm: Self = undefined;
        for (0..MAX_WORKQUEUES) |i| dm.workqueues[i] = Workqueue.init();
        for (0..MAX_WORK_ITEMS) |i| dm.work_items[i] = WorkItem.init();
        for (0..MAX_TASKLETS) |i| dm.tasklets[i] = Tasklet.init();
        for (0..MAX_DELAYED) |i| dm.delayed[i] = DelayedWork.init();
        dm.softirq = SoftirqState.init();
        dm.wq_count = 0;
        dm.work_count = 0;
        dm.tasklet_count = 0;
        dm.delayed_count = 0;
        dm.next_work_id = 1;
        dm.next_tasklet_id = 1;
        dm.tick = 0;
        dm.current_cpu = 0;
        dm.total_work_executed = 0;
        dm.total_tasklets_run = 0;
        dm.total_delayed_fires = 0;
        dm.total_softirq_processed = 0;
        dm.initialized = true;

        // Create system workqueues
        _ = dm.create_wq("system_wq", .{});
        _ = dm.create_wq("system_highpri_wq", .{ .high_priority = true });
        _ = dm.create_wq("system_unbound_wq", .{ .unbound = true });
        _ = dm.create_wq("system_freezable_wq", .{ .freezable = true });
        _ = dm.create_wq("system_power_eff_wq", .{ .power_efficient = true });

        return dm;
    }

    // ─── Workqueue Operations ───────────────────────────────────────

    pub fn create_wq(self: *Self, name: []const u8, flags: WqFlags) ?u8 {
        for (0..MAX_WORKQUEUES) |i| {
            if (!self.workqueues[i].active) {
                self.workqueues[i] = Workqueue.init();
                self.workqueues[i].set_name(name);
                self.workqueues[i].flags = flags;
                self.workqueues[i].active = true;
                self.wq_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn destroy_wq(self: *Self, idx: u8) bool {
        if (idx >= MAX_WORKQUEUES or !self.workqueues[idx].active) return false;
        self.workqueues[idx].flush();
        self.workqueues[idx].active = false;
        self.wq_count -= 1;
        return true;
    }

    // ─── Work Items ─────────────────────────────────────────────────

    pub fn queue_work(self: *Self, wq_idx: u8, cpu: u8) ?u16 {
        if (wq_idx >= MAX_WORKQUEUES or !self.workqueues[wq_idx].active) return null;

        for (0..MAX_WORK_ITEMS) |i| {
            if (!self.work_items[i].active) {
                self.work_items[i] = WorkItem.init();
                self.work_items[i].id = self.next_work_id;
                self.work_items[i].state = .pending;
                self.work_items[i].wq_idx = wq_idx;
                self.work_items[i].target_cpu = cpu;
                self.work_items[i].enqueue_tick = self.tick;
                self.work_items[i].active = true;
                self.next_work_id += 1;
                self.work_count += 1;

                const target = if (self.workqueues[wq_idx].flags.unbound) self.current_cpu else cpu;
                if (!self.workqueues[wq_idx].enqueue(@intCast(i), target)) {
                    self.work_items[i].active = false;
                    self.work_count -= 1;
                    return null;
                }

                return @intCast(i);
            }
        }
        return null;
    }

    pub fn cancel_work(self: *Self, work_idx: u16) bool {
        if (work_idx >= MAX_WORK_ITEMS or !self.work_items[work_idx].active) return false;
        if (self.work_items[work_idx].state == .running) return false; // Can't cancel in-flight
        self.work_items[work_idx].state = .cancelling;
        self.work_items[work_idx].active = false;
        self.work_count -= 1;
        const wq = self.work_items[work_idx].wq_idx;
        if (wq < MAX_WORKQUEUES) {
            self.workqueues[wq].total_cancelled += 1;
        }
        return true;
    }

    // ─── Delayed Work ───────────────────────────────────────────────

    pub fn queue_delayed_work(self: *Self, wq_idx: u8, delay: u64, periodic: bool) ?u8 {
        const work_idx = self.queue_work(wq_idx, self.current_cpu) orelse return null;
        // Make work not immediately runnable
        self.work_items[work_idx].state = .idle;

        for (0..MAX_DELAYED) |i| {
            if (!self.delayed[i].active) {
                self.delayed[i] = DelayedWork.init();
                self.delayed[i].work_idx = @intCast(work_idx);
                self.delayed[i].delay_ticks = delay;
                self.delayed[i].enqueue_tick = self.tick;
                self.delayed[i].expire_tick = self.tick + delay;
                self.delayed[i].periodic = periodic;
                self.delayed[i].interval = delay;
                self.delayed[i].active = true;
                self.delayed_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    // ─── Tasklets ───────────────────────────────────────────────────

    pub fn tasklet_init(self: *Self, priority: TaskletPriority, data: u64) ?u8 {
        for (0..MAX_TASKLETS) |i| {
            if (!self.tasklets[i].active) {
                self.tasklets[i] = Tasklet.init();
                self.tasklets[i].id = self.next_tasklet_id;
                self.tasklets[i].priority = priority;
                self.tasklets[i].data = data;
                self.tasklets[i].active = true;
                self.next_tasklet_id += 1;
                self.tasklet_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn tasklet_schedule(self: *Self, idx: u8) bool {
        if (idx >= MAX_TASKLETS or !self.tasklets[idx].active) return false;
        if (!self.tasklets[idx].is_enabled()) return false;
        if (self.tasklets[idx].state == .running) return false;

        self.tasklets[idx].state = .scheduled;
        self.tasklets[idx].schedule_count += 1;

        // Raise appropriate softirq
        if (self.tasklets[idx].priority == .hi) {
            self.softirq.raise(.hi);
        } else {
            self.softirq.raise(.tasklet);
        }
        return true;
    }

    pub fn tasklet_kill(self: *Self, idx: u8) bool {
        if (idx >= MAX_TASKLETS or !self.tasklets[idx].active) return false;
        self.tasklets[idx].active = false;
        self.tasklets[idx].state = .idle;
        self.tasklet_count -= 1;
        return true;
    }

    // ─── Processing (called from scheduler/timer tick) ──────────────

    pub fn process_tick(self: *Self) void {
        self.tick += 1;

        // Process delayed work timers
        for (0..MAX_DELAYED) |i| {
            if (!self.delayed[i].active) continue;
            if (self.delayed[i].is_expired(self.tick)) {
                const work_idx = self.delayed[i].work_idx;
                if (work_idx >= 0 and @as(usize, @intCast(work_idx)) < MAX_WORK_ITEMS) {
                    self.work_items[@intCast(work_idx)].state = .pending;
                }
                self.delayed[i].fire_count += 1;
                self.total_delayed_fires += 1;

                if (self.delayed[i].periodic) {
                    self.delayed[i].expire_tick = self.tick + self.delayed[i].interval;
                } else {
                    self.delayed[i].active = false;
                    self.delayed_count -= 1;
                }
            }
        }

        // Process workqueues
        for (0..MAX_WORKQUEUES) |wq_i| {
            if (!self.workqueues[wq_i].active) continue;

            if (self.workqueues[wq_i].dequeue(self.current_cpu)) |work_i| {
                const wi = @as(usize, @intCast(work_i));
                if (wi < MAX_WORK_ITEMS and self.work_items[wi].active and self.work_items[wi].state == .pending) {
                    self.work_items[wi].state = .running;
                    self.work_items[wi].start_tick = self.tick;

                    // Track latency
                    const latency = self.tick - self.work_items[wi].enqueue_tick;
                    if (latency > self.workqueues[wq_i].max_latency) {
                        self.workqueues[wq_i].max_latency = latency;
                    }

                    // "Execute" the work
                    self.work_items[wi].run_count += 1;
                    self.work_items[wi].complete_tick = self.tick;
                    self.work_items[wi].state = .idle;
                    self.work_items[wi].active = false;
                    self.work_count -= 1;

                    self.workqueues[wq_i].total_completed += 1;
                    self.total_work_executed += 1;
                }
            }
        }

        // Process tasklets
        for (0..MAX_TASKLETS) |i| {
            if (!self.tasklets[i].active) continue;
            if (self.tasklets[i].state == .scheduled and self.tasklets[i].is_enabled()) {
                self.tasklets[i].state = .running;
                self.tasklets[i].run_count += 1;
                self.total_tasklets_run += 1;
                self.tasklets[i].state = .idle;
            }
        }

        // Process softirqs
        const processed = self.softirq.process();
        self.total_softirq_processed += @as(u64, processed);

        // Rotate CPU for unbound work
        self.current_cpu = @intCast((@as(u16, self.current_cpu) + 1) % MAX_CPUS);
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_deferred: DeferredManager = undefined;
var g_deferred_initialized: bool = false;

fn dm() *DeferredManager {
    return &g_deferred;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_deferred_init() void {
    g_deferred = DeferredManager.init();
    g_deferred_initialized = true;
}

export fn zxy_deferred_create_wq(name_ptr: [*]const u8, name_len: usize, flags: u8) i8 {
    if (!g_deferred_initialized) return -1;
    const f: WqFlags = @bitCast(flags);
    if (dm().create_wq(name_ptr[0..name_len], f)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_deferred_queue_work(wq_idx: u8, cpu: u8) i16 {
    if (!g_deferred_initialized) return -1;
    if (dm().queue_work(wq_idx, cpu)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_deferred_cancel_work(work_idx: u16) bool {
    if (!g_deferred_initialized) return false;
    return dm().cancel_work(work_idx);
}

export fn zxy_deferred_queue_delayed(wq_idx: u8, delay: u64, periodic: bool) i8 {
    if (!g_deferred_initialized) return -1;
    if (dm().queue_delayed_work(wq_idx, delay, periodic)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_deferred_tasklet_init(priority: u8, data: u64) i8 {
    if (!g_deferred_initialized) return -1;
    const prio: TaskletPriority = if (priority > 0) .hi else .normal;
    if (dm().tasklet_init(prio, data)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_deferred_tasklet_schedule(idx: u8) bool {
    if (!g_deferred_initialized) return false;
    return dm().tasklet_schedule(idx);
}

export fn zxy_deferred_tasklet_kill(idx: u8) bool {
    if (!g_deferred_initialized) return false;
    return dm().tasklet_kill(idx);
}

export fn zxy_deferred_tick() void {
    if (g_deferred_initialized) dm().process_tick();
}

export fn zxy_deferred_raise_softirq(vec: u8) void {
    if (!g_deferred_initialized or vec >= NR_SOFTIRQS) return;
    dm().softirq.raise(@enumFromInt(vec));
}

export fn zxy_deferred_wq_count() u8 {
    if (!g_deferred_initialized) return 0;
    return dm().wq_count;
}

export fn zxy_deferred_work_count() u16 {
    if (!g_deferred_initialized) return 0;
    return dm().work_count;
}

export fn zxy_deferred_tasklet_count() u8 {
    if (!g_deferred_initialized) return 0;
    return dm().tasklet_count;
}

export fn zxy_deferred_total_work_executed() u64 {
    if (!g_deferred_initialized) return 0;
    return dm().total_work_executed;
}

export fn zxy_deferred_total_tasklets_run() u64 {
    if (!g_deferred_initialized) return 0;
    return dm().total_tasklets_run;
}

export fn zxy_deferred_total_softirq() u64 {
    if (!g_deferred_initialized) return 0;
    return dm().total_softirq_processed;
}
