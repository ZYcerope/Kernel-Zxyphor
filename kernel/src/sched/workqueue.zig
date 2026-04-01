// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Work Queue Subsystem
//
// Implements a kernel thread pool and deferred work execution mechanism
// similar to Linux's workqueue/cmwq system. Provides:
//
// - Per-CPU bound worker pools for locality-sensitive work
// - Unbound worker pools for long-running or CPU-agnostic work
// - Delayed work with timer-based scheduling
// - Ordered workqueues that guarantee serial execution
// - High-priority workqueues for interrupt bottom halves
// - Automatic pool sizing with concurrency management
// - Drain and flush semantics for safe teardown

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");
const list = @import("../lib/list.zig");

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────
pub const MAX_WORKERS_PER_POOL: usize = 64;
pub const MAX_WORK_QUEUE_SIZE: usize = 4096;
pub const MAX_WORKQUEUES: usize = 64;
pub const MAX_POOLS: usize = 32;
pub const MAX_CPUS: usize = 256;
pub const WORK_NAME_MAX: usize = 64;
pub const IDLE_WORKER_TIMEOUT_MS: u64 = 5 * 60 * 1000; // 5 minutes
pub const WORKER_STACK_SIZE: usize = 16384;

// ─────────────────────────────────────────────────────────────────────
// Work Item Flags
// ─────────────────────────────────────────────────────────────────────
pub const WorkFlags = packed struct {
    pending: bool = false,
    running: bool = false,
    cancelled: bool = false,
    delayed: bool = false,
    high_priority: bool = false,
    linked: bool = false,
    barrier: bool = false,
    _reserved: u1 = 0,
};

// ─────────────────────────────────────────────────────────────────────
// WorkFn — the function signature for work items
// ─────────────────────────────────────────────────────────────────────
pub const WorkFn = *const fn (work: *WorkItem) void;

// ─────────────────────────────────────────────────────────────────────
// WorkItem — a unit of deferred work
// ─────────────────────────────────────────────────────────────────────
pub const WorkItem = struct {
    /// The function to execute
    func: WorkFn,

    /// Private data passed to the function
    data: ?*anyopaque,

    /// Flags describing the state
    flags: WorkFlags,

    /// Link for the work queue's pending list
    link: list.ListNode,

    /// Which workqueue this work is submitted to
    workqueue: ?*Workqueue,

    /// For delayed work: the expiration time (kernel ticks)
    delay_until: u64,

    /// Name for debugging
    name: [WORK_NAME_MAX]u8,
    name_len: u8,

    /// Number of times this work item has been executed
    execution_count: u64,

    /// Whether the item can be re-submitted while running
    allow_resubmit: bool,

    const Self = @This();

    pub fn init(func: WorkFn, data: ?*anyopaque) Self {
        return Self{
            .func = func,
            .data = data,
            .flags = WorkFlags{},
            .link = list.ListNode{},
            .workqueue = null,
            .delay_until = 0,
            .name = [_]u8{0} ** WORK_NAME_MAX,
            .name_len = 0,
            .execution_count = 0,
            .allow_resubmit = false,
        };
    }

    pub fn setName(self: *Self, name: []const u8) void {
        const len = @min(name.len, WORK_NAME_MAX);
        @memcpy(self.name[0..len], name[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn isPending(self: *const Self) bool {
        return self.flags.pending;
    }

    pub fn isRunning(self: *const Self) bool {
        return self.flags.running;
    }

    pub fn cancel(self: *Self) bool {
        if (self.flags.running) return false;
        if (!self.flags.pending) return false;

        self.flags.cancelled = true;
        self.flags.pending = false;
        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────
// DelayedWork — a work item that fires after a specified delay
// ─────────────────────────────────────────────────────────────────────
pub const DelayedWork = struct {
    work: WorkItem,
    delay_ms: u64,
    periodic: bool,
    period_ms: u64,

    const Self = @This();

    pub fn init(func: WorkFn, data: ?*anyopaque, delay_ms: u64) Self {
        var dw = Self{
            .work = WorkItem.init(func, data),
            .delay_ms = delay_ms,
            .periodic = false,
            .period_ms = 0,
        };
        dw.work.flags.delayed = true;
        return dw;
    }

    pub fn initPeriodic(func: WorkFn, data: ?*anyopaque, period_ms: u64) Self {
        var dw = Self{
            .work = WorkItem.init(func, data),
            .delay_ms = period_ms,
            .periodic = true,
            .period_ms = period_ms,
        };
        dw.work.flags.delayed = true;
        return dw;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Worker — a kernel thread that executes work items
// ─────────────────────────────────────────────────────────────────────
pub const WorkerState = enum {
    idle,
    running,
    sleeping,
    exiting,
};

pub const Worker = struct {
    /// Worker ID (unique within a pool)
    id: u16,

    /// Current state
    state: WorkerState,

    /// The pool this worker belongs to
    pool: *WorkerPool,

    /// The work item currently being executed
    current_work: ?*WorkItem,

    /// CPU this worker is bound to (-1 for unbound)
    cpu: i32,

    /// Stack allocation
    stack_base: usize,
    stack_size: usize,

    /// Thread context pointer
    thread_context: ?*anyopaque,

    /// Statistics
    items_processed: u64,
    total_busy_time_ms: u64,
    last_active_tick: u64,

    /// Whether this worker is a "rescue" worker (guaranteed to exist)
    is_rescuer: bool,

    const Self = @This();

    pub fn init(id: u16, pool: *WorkerPool, cpu: i32) Self {
        return Self{
            .id = id,
            .state = .idle,
            .pool = pool,
            .current_work = null,
            .cpu = cpu,
            .stack_base = 0,
            .stack_size = WORKER_STACK_SIZE,
            .thread_context = null,
            .items_processed = 0,
            .total_busy_time_ms = 0,
            .last_active_tick = 0,
            .is_rescuer = false,
        };
    }

    /// Main worker loop — dequeues and executes work items
    pub fn run(self: *Self) void {
        while (self.state != .exiting) {
            // Try to dequeue a work item
            if (self.pool.dequeueWork()) |work| {
                self.state = .running;
                self.current_work = work;

                work.flags.running = true;
                work.flags.pending = false;

                // Execute the work function
                work.func(work);

                work.flags.running = false;
                work.execution_count += 1;
                self.current_work = null;
                self.items_processed += 1;
                self.state = .idle;

                // Notify anyone waiting for completion
                self.pool.notifyWorkComplete();
            } else {
                // No work available — sleep until woken
                self.state = .sleeping;
                self.pool.workerSleep(self);
            }
        }
    }

    /// Check if this worker has been idle too long and should exit
    pub fn shouldExit(self: *const Self, current_tick: u64) bool {
        if (self.is_rescuer) return false; // Rescuer never exits
        if (self.state != .idle) return false;
        if (current_tick - self.last_active_tick > IDLE_WORKER_TIMEOUT_MS) {
            return self.pool.activeWorkerCount() > 1; // Keep at least one
        }
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────
// WorkerPool — a pool of worker threads
// ─────────────────────────────────────────────────────────────────────
pub const PoolFlags = packed struct {
    bound: bool = false, // Bound to a specific CPU
    high_priority: bool = false,
    ordered: bool = false, // All work executed serially
    draining: bool = false,
    frozen: bool = false,
    _reserved: u3 = 0,
};

pub const WorkerPool = struct {
    /// Pool ID
    id: u16,

    /// Workers in this pool
    workers: [MAX_WORKERS_PER_POOL]Worker,
    worker_count: u16,
    active_workers: u16,

    /// Pending work items (FIFO queue)
    work_queue: [MAX_WORK_QUEUE_SIZE]?*WorkItem,
    queue_head: u16,
    queue_tail: u16,
    queue_count: u16,

    /// Delayed work items waiting for their timer
    delayed_queue: [512]?*DelayedWork,
    delayed_count: u16,

    /// Pool flags
    flags: PoolFlags,

    /// CPU affinity for bound pools (-1 for unbound)
    cpu: i32,

    /// Maximum concurrent workers allowed
    max_active: u16,

    /// Lock protecting the pool state
    lock: spinlock.SpinLock,

    /// Statistics
    stats: PoolStats,

    /// Flush/drain waiters count
    flush_waiters: u32,

    const Self = @This();

    pub fn init(id: u16, cpu: i32, max_active: u16) Self {
        var pool = Self{
            .id = id,
            .workers = undefined,
            .worker_count = 0,
            .active_workers = 0,
            .work_queue = [_]?*WorkItem{null} ** MAX_WORK_QUEUE_SIZE,
            .queue_head = 0,
            .queue_tail = 0,
            .queue_count = 0,
            .delayed_queue = [_]?*DelayedWork{null} ** 512,
            .delayed_count = 0,
            .flags = PoolFlags{},
            .cpu = cpu,
            .max_active = max_active,
            .lock = spinlock.SpinLock{},
            .stats = PoolStats.init(),
            .flush_waiters = 0,
        };

        if (cpu >= 0) {
            pool.flags.bound = true;
        }

        // Initialize workers
        var i: u16 = 0;
        while (i < MAX_WORKERS_PER_POOL) : (i += 1) {
            pool.workers[i] = Worker.init(i, &pool, cpu);
        }

        return pool;
    }

    /// Enqueue a work item to this pool
    pub fn enqueueWork(self: *Self, work: *WorkItem) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (self.flags.draining or self.flags.frozen) return false;
        if (work.flags.pending) return false;
        if (self.queue_count >= MAX_WORK_QUEUE_SIZE) return false;

        self.work_queue[self.queue_tail] = work;
        self.queue_tail = @intCast((@as(u32, self.queue_tail) + 1) % MAX_WORK_QUEUE_SIZE);
        self.queue_count += 1;
        work.flags.pending = true;

        self.stats.total_enqueued += 1;

        // Wake up a sleeping worker if available
        self.wakeWorker();

        return true;
    }

    /// Dequeue the next work item (called by workers)
    pub fn dequeueWork(self: *Self) ?*WorkItem {
        self.lock.acquire();
        defer self.lock.release();

        if (self.queue_count == 0) return null;

        const work = self.work_queue[self.queue_head] orelse return null;
        self.work_queue[self.queue_head] = null;
        self.queue_head = @intCast((@as(u32, self.queue_head) + 1) % MAX_WORK_QUEUE_SIZE);
        self.queue_count -= 1;

        self.stats.total_dequeued += 1;

        return work;
    }

    /// Enqueue a delayed work item
    pub fn enqueueDelayed(self: *Self, dwork: *DelayedWork, current_tick: u64) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (self.delayed_count >= 512) return false;

        dwork.work.delay_until = current_tick + dwork.delay_ms;
        self.delayed_queue[self.delayed_count] = dwork;
        self.delayed_count += 1;
        dwork.work.flags.pending = true;

        return true;
    }

    /// Process delayed work items (called on timer tick)
    pub fn processDelayed(self: *Self, current_tick: u64) void {
        self.lock.acquire();
        defer self.lock.release();

        var i: u16 = 0;
        while (i < self.delayed_count) {
            if (self.delayed_queue[i]) |dwork| {
                if (current_tick >= dwork.work.delay_until) {
                    // Time expired — move to active queue
                    dwork.work.flags.delayed = false;

                    // Enqueue without lock (we hold it)
                    if (self.queue_count < MAX_WORK_QUEUE_SIZE) {
                        self.work_queue[self.queue_tail] = &dwork.work;
                        self.queue_tail = @intCast((@as(u32, self.queue_tail) + 1) % MAX_WORK_QUEUE_SIZE);
                        self.queue_count += 1;
                    }

                    // Handle periodic work
                    if (dwork.periodic) {
                        dwork.work.delay_until = current_tick + dwork.period_ms;
                        dwork.work.flags.delayed = true;
                    } else {
                        // Remove from delayed queue
                        self.removeDelayedAt(i);
                        continue; // Don't increment i
                    }
                }
            }
            i += 1;
        }
    }

    fn removeDelayedAt(self: *Self, index: u16) void {
        if (index < self.delayed_count - 1) {
            self.delayed_queue[index] = self.delayed_queue[self.delayed_count - 1];
        }
        self.delayed_queue[self.delayed_count - 1] = null;
        self.delayed_count -= 1;
    }

    /// Wake a sleeping worker
    fn wakeWorker(self: *Self) void {
        // Find a sleeping worker
        for (self.workers[0..self.worker_count]) |*worker| {
            if (worker.state == .sleeping) {
                worker.state = .idle;
                return;
            }
        }

        // No sleeping workers — try to spawn a new one if below limit
        if (self.worker_count < self.max_active) {
            self.spawnWorker();
        }
    }

    /// Create a new worker in this pool
    fn spawnWorker(self: *Self) void {
        if (self.worker_count >= MAX_WORKERS_PER_POOL) return;
        if (self.worker_count >= self.max_active) return;

        self.workers[self.worker_count] = Worker.init(self.worker_count, self, self.cpu);
        self.worker_count += 1;
        self.active_workers += 1;
    }

    /// Worker sleep entry point
    pub fn workerSleep(self: *Self, worker: *Worker) void {
        _ = self;
        worker.state = .sleeping;
        // In a real implementation, this would block the thread
    }

    /// Notification that a work item completed
    pub fn notifyWorkComplete(self: *Self) void {
        self.stats.total_completed += 1;

        if (self.flush_waiters > 0 and self.queue_count == 0) {
            // All work drained — wake flush waiters
            self.flush_waiters = 0;
        }
    }

    /// Count active (non-sleeping, non-exiting) workers
    pub fn activeWorkerCount(self: *const Self) u16 {
        var count: u16 = 0;
        for (self.workers[0..self.worker_count]) |*worker| {
            if (worker.state == .running or worker.state == .idle) {
                count += 1;
            }
        }
        return count;
    }

    /// Drain the pool — wait for all pending work to complete
    pub fn drain(self: *Self) void {
        self.flags.draining = true;
        self.flush_waiters += 1;

        // In a real implementation, this would sleep until woken by
        // notifyWorkComplete when queue_count reaches 0
        while (self.queue_count > 0) {
            // Busy-wait (would be replaced with proper sleeping)
        }

        self.flags.draining = false;
    }

    /// Cancel all pending work in the queue
    pub fn cancelAll(self: *Self) u32 {
        self.lock.acquire();
        defer self.lock.release();

        var cancelled: u32 = 0;
        while (self.queue_count > 0) {
            if (self.work_queue[self.queue_head]) |work| {
                work.flags.pending = false;
                work.flags.cancelled = true;
                cancelled += 1;
            }
            self.work_queue[self.queue_head] = null;
            self.queue_head = @intCast((@as(u32, self.queue_head) + 1) % MAX_WORK_QUEUE_SIZE);
            self.queue_count -= 1;
        }

        self.stats.total_cancelled += cancelled;
        return cancelled;
    }

    /// Freeze the pool — prevent new work from being enqueued
    pub fn freeze(self: *Self) void {
        self.flags.frozen = true;
    }

    /// Thaw a frozen pool
    pub fn thaw(self: *Self) void {
        self.flags.frozen = false;
    }
};

pub const PoolStats = struct {
    total_enqueued: u64,
    total_dequeued: u64,
    total_completed: u64,
    total_cancelled: u64,
    peak_queue_depth: u32,
    peak_workers: u16,

    pub fn init() PoolStats {
        return PoolStats{
            .total_enqueued = 0,
            .total_dequeued = 0,
            .total_completed = 0,
            .total_cancelled = 0,
            .peak_queue_depth = 0,
            .peak_workers = 0,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// Workqueue — named abstraction over a worker pool
// ─────────────────────────────────────────────────────────────────────
pub const WorkqueueFlags = packed struct {
    unbound: bool = false,
    high_priority: bool = false,
    cpu_intensive: bool = false,
    ordered: bool = false,
    freezable: bool = false,
    mem_reclaim: bool = false,
    _reserved: u2 = 0,
};

pub const Workqueue = struct {
    /// Name of the workqueue
    name: [WORK_NAME_MAX]u8,
    name_len: u8,

    /// Flags
    flags: WorkqueueFlags,

    /// The underlying worker pool
    pool: *WorkerPool,

    /// Active state
    active: bool,

    /// Creation time (kernel ticks)
    created_at: u64,

    /// Statistics
    total_submitted: u64,

    const Self = @This();

    pub fn init(name: []const u8, pool: *WorkerPool, flags: WorkqueueFlags) Self {
        var wq = Self{
            .name = [_]u8{0} ** WORK_NAME_MAX,
            .name_len = 0,
            .flags = flags,
            .pool = pool,
            .active = true,
            .created_at = 0,
            .total_submitted = 0,
        };
        const len = @min(name.len, WORK_NAME_MAX);
        @memcpy(wq.name[0..len], name[0..len]);
        wq.name_len = @intCast(len);
        return wq;
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Submit a work item
    pub fn submit(self: *Self, work: *WorkItem) bool {
        if (!self.active) return false;

        work.workqueue = self;
        if (work.flags.high_priority) {
            work.flags.high_priority = true;
        }

        if (self.pool.enqueueWork(work)) {
            self.total_submitted += 1;
            return true;
        }
        return false;
    }

    /// Submit delayed work
    pub fn submitDelayed(self: *Self, dwork: *DelayedWork, current_tick: u64) bool {
        if (!self.active) return false;

        dwork.work.workqueue = self;
        if (self.pool.enqueueDelayed(dwork, current_tick)) {
            self.total_submitted += 1;
            return true;
        }
        return false;
    }

    /// Flush — wait for all currently pending work to complete
    pub fn flush(self: *Self) void {
        self.pool.drain();
    }

    /// Destroy this workqueue, draining all pending work first
    pub fn destroy(self: *Self) void {
        self.active = false;
        self.flush();
    }
};

// ─────────────────────────────────────────────────────────────────────
// Global State
// ─────────────────────────────────────────────────────────────────────
var pools: [MAX_POOLS]WorkerPool = undefined;
var pool_count: u8 = 0;

var workqueues: [MAX_WORKQUEUES]Workqueue = undefined;
var wq_count: u8 = 0;

var global_lock: spinlock.SpinLock = spinlock.SpinLock{};
var current_tick: u64 = 0;

/// System workqueue — used by default for most kernel work
var system_wq: ?*Workqueue = null;
/// High-priority workqueue — for bottom halves and time-critical work
var system_highpri_wq: ?*Workqueue = null;
/// Long-running workqueue — for work that may block for a long time
var system_long_wq: ?*Workqueue = null;
/// Unbound workqueue — for work that doesn't need CPU affinity
var system_unbound_wq: ?*Workqueue = null;

// ─────────────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────────────
pub fn init() void {
    global_lock.acquire();
    defer global_lock.release();

    pool_count = 0;
    wq_count = 0;

    // Create the default per-CPU bound pool
    const default_pool = createPoolInternal(-1, 16);

    // Create the high-priority pool
    const highpri_pool = createPoolInternal(-1, 8);
    if (highpri_pool) |p| {
        p.flags.high_priority = true;
    }

    // Create the unbound pool (for I/O-bound work)
    const unbound_pool = createPoolInternal(-1, 32);

    // Create the long-running pool
    const long_pool = createPoolInternal(-1, 4);

    // Create system workqueues
    if (default_pool) |pool| {
        system_wq = createWqInternal("events", pool, WorkqueueFlags{});
    }
    if (highpri_pool) |pool| {
        system_highpri_wq = createWqInternal("events_highpri", pool, WorkqueueFlags{ .high_priority = true });
    }
    if (unbound_pool) |pool| {
        system_unbound_wq = createWqInternal("events_unbound", pool, WorkqueueFlags{ .unbound = true });
    }
    if (long_pool) |pool| {
        system_long_wq = createWqInternal("events_long", pool, WorkqueueFlags{ .cpu_intensive = true });
    }
}

fn createPoolInternal(cpu: i32, max_active: u16) ?*WorkerPool {
    if (pool_count >= MAX_POOLS) return null;
    const idx = pool_count;
    pools[idx] = WorkerPool.init(idx, cpu, max_active);
    pool_count += 1;
    return &pools[idx];
}

fn createWqInternal(name: []const u8, pool: *WorkerPool, flags: WorkqueueFlags) ?*Workqueue {
    if (wq_count >= MAX_WORKQUEUES) return null;
    const idx = wq_count;
    workqueues[idx] = Workqueue.init(name, pool, flags);
    wq_count += 1;
    return &workqueues[idx];
}

// ─────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────

/// Create a new workqueue
pub fn createWorkqueue(name: []const u8, flags: WorkqueueFlags) ?*Workqueue {
    global_lock.acquire();
    defer global_lock.release();

    // Select or create an appropriate pool
    const pool = if (flags.unbound)
        findPoolByFlags(false, flags.high_priority)
    else
        findPoolByFlags(true, flags.high_priority);

    if (pool) |p| {
        return createWqInternal(name, p, flags);
    }

    return null;
}

fn findPoolByFlags(bound: bool, highpri: bool) ?*WorkerPool {
    for (pools[0..pool_count]) |*pool| {
        if (pool.flags.bound == bound and pool.flags.high_priority == highpri) {
            return pool;
        }
    }
    return null;
}

/// Submit work to the system workqueue
pub fn scheduleWork(work: *WorkItem) bool {
    if (system_wq) |wq| {
        return wq.submit(work);
    }
    return false;
}

/// Submit work to the high-priority system workqueue
pub fn scheduleHighPriWork(work: *WorkItem) bool {
    if (system_highpri_wq) |wq| {
        return wq.submit(work);
    }
    return false;
}

/// Submit delayed work to the system workqueue
pub fn scheduleDelayedWork(dwork: *DelayedWork) bool {
    if (system_wq) |wq| {
        return wq.submitDelayed(dwork, current_tick);
    }
    return false;
}

/// Flush the system workqueue — waits for all pending work
pub fn flushSystemWq() void {
    if (system_wq) |wq| {
        wq.flush();
    }
}

/// Timer tick — process delayed work across all pools
pub fn tick() void {
    current_tick += 1;

    for (pools[0..pool_count]) |*pool| {
        pool.processDelayed(current_tick);
    }
}

/// Cancel a work item if it hasn't started running yet
pub fn cancelWork(work: *WorkItem) bool {
    return work.cancel();
}

/// Cancel a delayed work item
pub fn cancelDelayedWork(dwork: *DelayedWork) bool {
    return dwork.work.cancel();
}

/// Get the system workqueue
pub fn getSystemWq() ?*Workqueue {
    return system_wq;
}

/// Get the high-priority system workqueue
pub fn getSystemHighPriWq() ?*Workqueue {
    return system_highpri_wq;
}

/// Freeze all freezable workqueues (for suspend/hibernate)
pub fn freezeWorkqueues() void {
    for (workqueues[0..wq_count]) |*wq| {
        if (wq.flags.freezable and wq.active) {
            wq.pool.freeze();
        }
    }
}

/// Thaw all frozen workqueues
pub fn thawWorkqueues() void {
    for (workqueues[0..wq_count]) |*wq| {
        if (wq.flags.freezable and wq.active) {
            wq.pool.thaw();
        }
    }
}

/// Get aggregate statistics
pub fn getStats() WorkqueueStats {
    var stats = WorkqueueStats{
        .total_pools = pool_count,
        .total_workqueues = wq_count,
        .total_workers = 0,
        .total_pending = 0,
        .total_completed = 0,
    };

    for (pools[0..pool_count]) |*pool| {
        stats.total_workers += pool.worker_count;
        stats.total_pending += pool.queue_count;
        stats.total_completed += pool.stats.total_completed;
    }

    return stats;
}

pub const WorkqueueStats = struct {
    total_pools: u8,
    total_workqueues: u8,
    total_workers: u16,
    total_pending: u32,
    total_completed: u64,
};

// ─────────────────────────────────────────────────────────────────────
// C FFI — exported symbols
// ─────────────────────────────────────────────────────────────────────
export fn zxy_workqueue_init() void {
    init();
}

export fn zxy_workqueue_tick() void {
    tick();
}

export fn zxy_workqueue_flush_system() void {
    flushSystemWq();
}
