// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Scheduler with CFS, EEVDF, Real-time, and Deadline classes

const std = @import("std");

/// Scheduling policies
pub const SchedPolicy = enum(u8) {
    /// Completely Fair Scheduler (default)
    SCHED_NORMAL = 0,
    /// FIFO real-time
    SCHED_FIFO = 1,
    /// Round-robin real-time
    SCHED_RR = 2,
    /// Batch processing
    SCHED_BATCH = 3,
    /// Idle priority
    SCHED_IDLE = 5,
    /// Deadline scheduling (EDF)
    SCHED_DEADLINE = 6,
    /// Zxyphor: Adaptive AI-driven scheduling
    SCHED_ADAPTIVE = 7,
    /// Zxyphor: GPU-aware scheduling
    SCHED_GPU_AWARE = 8,
    /// Zxyphor: Energy-efficient scheduling
    SCHED_ENERGY = 9,
};

/// Task state
pub const TaskState = enum(u8) {
    running = 0,
    interruptible = 1,
    uninterruptible = 2,
    stopped = 4,
    traced = 8,
    zombie = 16,
    dead = 32,
    wakekill = 64,
    parked = 128,
};

/// Nice value range
pub const NICE_MIN: i8 = -20;
pub const NICE_MAX: i8 = 19;
pub const DEFAULT_NICE: i8 = 0;
pub const MAX_RT_PRIO: u32 = 100;
pub const MAX_PRIO: u32 = 140;
pub const DEFAULT_PRIO: u32 = 120;

/// CPU load tracking
pub const LoadWeight = struct {
    weight: u64,
    inv_weight: u32,

    /// Nice-to-weight table (from Linux CFS)
    const nice_to_weight: [40]u64 = .{
        88761, 71755, 56483, 46273, 36291,
        29154, 23254, 18705, 14949, 11916,
        9548,  7620,  6100,  4904,  3906,
        3121,  2501,  1991,  1586,  1277,
        1024,  820,   655,   526,   423,
        335,   272,   215,   172,   137,
        110,   87,    70,    56,    45,
        36,    29,    23,    18,    15,
    };

    const nice_to_inv_weight: [40]u32 = .{
        48388, 59856, 76040, 92818, 118348,
        147320, 184698, 229616, 287308, 360437,
        449829, 563644, 704093, 875809, 1099582,
        1376151, 1717300, 2157191, 2708050, 3363326,
        4194304, 5237765, 6557202, 8165337, 10153587,
        12820798, 15790321, 19976592, 24970740, 31350126,
        39045157, 49367440, 61356676, 76695844, 95443717,
        119304647, 148102320, 186737708, 238609294, 286331153,
    };

    pub fn fromNice(nice: i8) LoadWeight {
        const idx: usize = @intCast(@as(i32, nice) - NICE_MIN);
        return .{
            .weight = nice_to_weight[idx],
            .inv_weight = nice_to_inv_weight[idx],
        };
    }
};

/// Scheduling entity for CFS (virtual runtime-based)
pub const SchedEntity = struct {
    /// Virtual runtime (nanoseconds, weighted)
    vruntime: u64,
    /// Sum of execution time
    sum_exec_runtime: u64,
    /// Previous sum for delta calculation
    prev_sum_exec_runtime: u64,
    /// Load weight based on nice value
    load: LoadWeight,
    /// Run node in the RB-tree
    rb_node_key: u64,
    /// Whether currently on the runqueue
    on_rq: bool,
    /// Scheduling statistics
    stats: SchedStats,
    /// EEVDF: eligible virtual time
    eligible_vtime: u64,
    /// EEVDF: deadline virtual time
    deadline_vtime: u64,
    /// EEVDF: requested time slice
    slice: u64,
    /// EEVDF: lag value
    lag: i64,

    pub fn init(nice: i8) SchedEntity {
        return .{
            .vruntime = 0,
            .sum_exec_runtime = 0,
            .prev_sum_exec_runtime = 0,
            .load = LoadWeight.fromNice(nice),
            .rb_node_key = 0,
            .on_rq = false,
            .stats = SchedStats.init(),
            .eligible_vtime = 0,
            .deadline_vtime = 0,
            .slice = 4_000_000, // 4ms default slice
            .lag = 0,
        };
    }

    /// Update virtual runtime after execution
    pub fn updateVruntime(self: *SchedEntity, delta_exec: u64) void {
        // vruntime += delta_exec * NICE_0_LOAD / weight
        const weighted_delta = (delta_exec * 1024) / self.load.weight;
        self.vruntime += weighted_delta;
        self.sum_exec_runtime += delta_exec;
    }

    /// EEVDF: calculate virtual deadline
    pub fn updateDeadline(self: *SchedEntity) void {
        self.deadline_vtime = self.eligible_vtime + (self.slice * 1024) / self.load.weight;
    }

    /// EEVDF: check if entity is eligible to run
    pub fn isEligible(self: *const SchedEntity, min_vruntime: u64) bool {
        return self.eligible_vtime <= min_vruntime;
    }
};

/// Real-time scheduling entity
pub const RtSchedEntity = struct {
    priority: u32,
    time_slice: u64,
    timeout: u64,
    on_rq: bool,
    policy: SchedPolicy,
    deadline: u64,
    period: u64,
    runtime: u64,
    remaining_runtime: u64,
    overrun_count: u32,

    pub fn init(policy: SchedPolicy, priority: u32) RtSchedEntity {
        return .{
            .priority = priority,
            .time_slice = if (policy == .SCHED_RR) 100_000_000 else 0, // 100ms for RR
            .timeout = 0,
            .on_rq = false,
            .policy = policy,
            .deadline = 0,
            .period = 0,
            .runtime = 0,
            .remaining_runtime = 0,
            .overrun_count = 0,
        };
    }
};

/// Deadline scheduling entity (EDF)
pub const DeadlineEntity = struct {
    deadline: u64,
    period: u64,
    runtime: u64,
    remaining_runtime: u64,
    absolute_deadline: u64,
    flags: u32,
    overrun: bool,
    on_rq: bool,

    pub const DL_FLAG_DL_THROTTLE: u32 = 1 << 0;
    pub const DL_FLAG_DL_BOOSTED: u32 = 1 << 1;
    pub const DL_FLAG_DL_SERVER: u32 = 1 << 2;

    pub fn init(runtime: u64, deadline: u64, period: u64) DeadlineEntity {
        return .{
            .deadline = deadline,
            .period = period,
            .runtime = runtime,
            .remaining_runtime = runtime,
            .absolute_deadline = 0,
            .flags = 0,
            .overrun = false,
            .on_rq = false,
        };
    }

    pub fn replenish(self: *DeadlineEntity, now: u64) void {
        self.remaining_runtime = self.runtime;
        self.absolute_deadline = now + self.deadline;
    }

    pub fn isExpired(self: *const DeadlineEntity, now: u64) bool {
        return now > self.absolute_deadline;
    }

    pub fn hasRuntime(self: *const DeadlineEntity) bool {
        return self.remaining_runtime > 0;
    }
};

/// Per-task scheduling statistics
pub const SchedStats = struct {
    wait_start: u64,
    wait_max: u64,
    wait_count: u64,
    wait_sum: u64,
    sleep_start: u64,
    sleep_max: u64,
    sleep_sum: u64,
    block_start: u64,
    block_max: u64,
    block_sum: u64,
    exec_max: u64,
    slice_max: u64,
    nr_migrations: u64,
    nr_forced_migrations: u64,
    nr_wakeups: u64,
    nr_wakeups_local: u64,
    nr_wakeups_remote: u64,
    nr_wakeups_affine: u64,

    pub fn init() SchedStats {
        return @as(SchedStats, .{
            .wait_start = 0,
            .wait_max = 0,
            .wait_count = 0,
            .wait_sum = 0,
            .sleep_start = 0,
            .sleep_max = 0,
            .sleep_sum = 0,
            .block_start = 0,
            .block_max = 0,
            .block_sum = 0,
            .exec_max = 0,
            .slice_max = 0,
            .nr_migrations = 0,
            .nr_forced_migrations = 0,
            .nr_wakeups = 0,
            .nr_wakeups_local = 0,
            .nr_wakeups_remote = 0,
            .nr_wakeups_affine = 0,
        });
    }
};

/// Task structure (the core of the scheduler)
pub const Task = struct {
    /// Process ID
    pid: u32,
    /// Thread group ID
    tgid: u32,
    /// Task state
    state: TaskState,
    /// Scheduling policy
    policy: SchedPolicy,
    /// Static priority (nice value)
    nice: i8,
    /// Dynamic priority
    prio: u32,
    /// CFS scheduling entity
    se: SchedEntity,
    /// RT scheduling entity
    rt: RtSchedEntity,
    /// Deadline scheduling entity
    dl: DeadlineEntity,
    /// CPU affinity mask
    cpus_allowed: CpuMask,
    /// CPU the task is running on
    cpu: u32,
    /// Flags
    flags: u32,
    /// Preempt count (0 = preemptible)
    preempt_count: u32,
    /// Time slice remaining (ns)
    time_slice: u64,
    /// Task name
    comm: [16]u8,
    /// NUMA node preference
    numa_preferred_node: i32,
    /// Migration disabled count
    migration_disabled: u32,
    /// Wake queue link
    wake_q_next: ?*Task,

    pub const FLAG_IDLE: u32 = 1 << 0;
    pub const FLAG_KTHREAD: u32 = 1 << 1;
    pub const FLAG_NEED_RESCHED: u32 = 1 << 2;
    pub const FLAG_FROZEN: u32 = 1 << 3;
    pub const FLAG_VCPU: u32 = 1 << 4;
    pub const FLAG_NO_CGROUP_MIGRATION: u32 = 1 << 5;

    pub fn init(pid: u32, nice: i8) Task {
        return .{
            .pid = pid,
            .tgid = pid,
            .state = .interruptible,
            .policy = .SCHED_NORMAL,
            .nice = nice,
            .prio = niceToStaticPrio(nice),
            .se = SchedEntity.init(nice),
            .rt = RtSchedEntity.init(.SCHED_NORMAL, 0),
            .dl = DeadlineEntity.init(0, 0, 0),
            .cpus_allowed = CpuMask.all(),
            .cpu = 0,
            .flags = 0,
            .preempt_count = 0,
            .time_slice = 4_000_000,
            .comm = [_]u8{0} ** 16,
            .numa_preferred_node = -1,
            .migration_disabled = 0,
            .wake_q_next = null,
        };
    }

    pub fn needsResched(self: *const Task) bool {
        return (self.flags & FLAG_NEED_RESCHED) != 0;
    }

    pub fn setNeedResched(self: *Task) void {
        self.flags |= FLAG_NEED_RESCHED;
    }

    pub fn clearNeedResched(self: *Task) void {
        self.flags &= ~FLAG_NEED_RESCHED;
    }

    pub fn isRealtime(self: *const Task) bool {
        return self.policy == .SCHED_FIFO or self.policy == .SCHED_RR;
    }

    pub fn isDeadline(self: *const Task) bool {
        return self.policy == .SCHED_DEADLINE;
    }

    pub fn isIdle(self: *const Task) bool {
        return (self.flags & FLAG_IDLE) != 0;
    }
};

fn niceToStaticPrio(nice: i8) u32 {
    return @intCast(@as(i32, nice) + 120);
}

/// CPU affinity mask
pub const CpuMask = struct {
    bits: [4]u64, // Support up to 256 CPUs

    pub fn init() CpuMask {
        return .{ .bits = [_]u64{0} ** 4 };
    }

    pub fn all() CpuMask {
        return .{ .bits = [_]u64{0xFFFFFFFFFFFFFFFF} ** 4 };
    }

    pub fn single(cpu: u32) CpuMask {
        var mask = CpuMask.init();
        mask.set(cpu);
        return mask;
    }

    pub fn set(self: *CpuMask, cpu: u32) void {
        if (cpu >= 256) return;
        const word = cpu / 64;
        const bit = @as(u6, @truncate(cpu % 64));
        self.bits[word] |= @as(u64, 1) << bit;
    }

    pub fn clear(self: *CpuMask, cpu: u32) void {
        if (cpu >= 256) return;
        const word = cpu / 64;
        const bit = @as(u6, @truncate(cpu % 64));
        self.bits[word] &= ~(@as(u64, 1) << bit);
    }

    pub fn isSet(self: *const CpuMask, cpu: u32) bool {
        if (cpu >= 256) return false;
        const word = cpu / 64;
        const bit = @as(u6, @truncate(cpu % 64));
        return (self.bits[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn count(self: *const CpuMask) u32 {
        var total: u32 = 0;
        for (self.bits) |word| {
            total += @popCount(word);
        }
        return total;
    }

    pub fn firstSet(self: *const CpuMask) ?u32 {
        for (0..4) |i| {
            if (self.bits[i] != 0) {
                return @as(u32, @intCast(i)) * 64 + @ctz(self.bits[i]);
            }
        }
        return null;
    }

    pub fn intersect(self: *const CpuMask, other: *const CpuMask) CpuMask {
        var result: CpuMask = undefined;
        for (0..4) |i| {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        return result;
    }
};

/// CFS Run Queue (Red-Black tree based)
pub const CfsRunQueue = struct {
    /// Number of runnable tasks
    nr_running: u32,
    /// Total load weight
    load: u64,
    /// Minimum virtual runtime
    min_vruntime: u64,
    /// Current task
    curr: ?*Task,
    /// Next task to run (EEVDF pick)
    next: ?*Task,
    /// Last preempted task
    last: ?*Task,
    /// Skip task
    skip: ?*Task,
    /// Tasks array (simplified - real impl uses RB-tree)
    tasks: [1024]?*Task,
    task_count: u32,
    /// Scheduling period
    sched_period: u64,
    /// Minimum granularity
    min_granularity: u64,
    /// Wakeup granularity
    wakeup_granularity: u64,

    pub fn init() CfsRunQueue {
        return .{
            .nr_running = 0,
            .load = 0,
            .min_vruntime = 0,
            .curr = null,
            .next = null,
            .last = null,
            .skip = null,
            .tasks = [_]?*Task{null} ** 1024,
            .task_count = 0,
            .sched_period = 6_000_000, // 6ms
            .min_granularity = 750_000, // 0.75ms
            .wakeup_granularity = 1_000_000, // 1ms
        };
    }

    /// Calculate ideal runtime for a task
    pub fn calcIdealRuntime(self: *const CfsRunQueue, se: *const SchedEntity) u64 {
        if (self.nr_running == 0) return self.sched_period;
        return (self.sched_period * se.load.weight) / self.load;
    }

    /// EEVDF: pick the eligible task with earliest virtual deadline
    pub fn pickEevdf(self: *CfsRunQueue) ?*Task {
        var best: ?*Task = null;
        var best_deadline: u64 = ~@as(u64, 0);

        for (0..self.task_count) |i| {
            if (self.tasks[i]) |task| {
                if (task.se.isEligible(self.min_vruntime)) {
                    if (task.se.deadline_vtime < best_deadline) {
                        best_deadline = task.se.deadline_vtime;
                        best = task;
                    }
                }
            }
        }

        return best;
    }

    /// Enqueue a task
    pub fn enqueue(self: *CfsRunQueue, task: *Task) void {
        if (self.task_count >= 1024) return;

        // Place vruntime
        if (task.se.vruntime == 0) {
            task.se.vruntime = self.min_vruntime;
        }

        task.se.eligible_vtime = task.se.vruntime;
        task.se.updateDeadline();
        task.se.on_rq = true;

        // Find slot
        for (0..1024) |i| {
            if (self.tasks[i] == null) {
                self.tasks[i] = task;
                self.task_count += 1;
                break;
            }
        }

        self.nr_running += 1;
        self.load += task.se.load.weight;
    }

    /// Dequeue a task
    pub fn dequeue(self: *CfsRunQueue, task: *Task) void {
        task.se.on_rq = false;

        for (0..1024) |i| {
            if (self.tasks[i] == task) {
                self.tasks[i] = null;
                self.task_count -= 1;
                break;
            }
        }

        self.nr_running -= 1;
        self.load -= task.se.load.weight;
    }

    /// Update minimum vruntime
    pub fn updateMinVruntime(self: *CfsRunQueue) void {
        var vruntime = self.min_vruntime;

        if (self.curr) |curr| {
            if (curr.se.on_rq) {
                vruntime = curr.se.vruntime;
            }
        }

        // Find minimum from all tasks
        for (0..self.task_count) |i| {
            if (self.tasks[i]) |task| {
                if (task.se.vruntime < vruntime) {
                    vruntime = task.se.vruntime;
                }
            }
        }

        // min_vruntime only moves forward
        if (vruntime > self.min_vruntime) {
            self.min_vruntime = vruntime;
        }
    }
};

/// Real-time Run Queue
pub const RtRunQueue = struct {
    /// Bitmap of active priority levels
    bitmap: [2]u64, // 128 priority levels
    /// Queue for each priority
    queues: [MAX_RT_PRIO][16]?*Task,
    queue_counts: [MAX_RT_PRIO]u32,
    /// Number of runnable RT tasks
    nr_running: u32,
    /// Highest priority ready to run
    highest_prio: u32,
    /// Total RT bandwidth (in ns per period)
    rt_time: u64,
    rt_runtime: u64, // Default 950ms per 1000ms
    rt_period: u64,
    overloaded: bool,

    pub fn init() RtRunQueue {
        var rq: RtRunQueue = undefined;
        rq.bitmap = [_]u64{0} ** 2;
        for (0..MAX_RT_PRIO) |i| {
            rq.queues[i] = [_]?*Task{null} ** 16;
            rq.queue_counts[i] = 0;
        }
        rq.nr_running = 0;
        rq.highest_prio = MAX_RT_PRIO;
        rq.rt_time = 0;
        rq.rt_runtime = 950_000_000; // 950ms
        rq.rt_period = 1_000_000_000; // 1s
        rq.overloaded = false;
        return rq;
    }

    pub fn enqueue(self: *RtRunQueue, task: *Task) void {
        const prio = task.rt.priority;
        if (prio >= MAX_RT_PRIO) return;

        if (self.queue_counts[prio] < 16) {
            self.queues[prio][self.queue_counts[prio]] = task;
            self.queue_counts[prio] += 1;
        }

        // Set bitmap
        const word = prio / 64;
        const bit = @as(u6, @truncate(prio % 64));
        self.bitmap[word] |= @as(u64, 1) << bit;

        self.nr_running += 1;
        if (prio < self.highest_prio) {
            self.highest_prio = prio;
        }
        task.rt.on_rq = true;
    }

    pub fn pickHighest(self: *RtRunQueue) ?*Task {
        if (self.nr_running == 0) return null;

        // Find highest priority (lowest number)
        for (0..2) |word_idx| {
            if (self.bitmap[word_idx] != 0) {
                const bit = @ctz(self.bitmap[word_idx]);
                const prio = @as(u32, @intCast(word_idx)) * 64 + bit;
                if (self.queue_counts[prio] > 0) {
                    return self.queues[prio][0];
                }
            }
        }
        return null;
    }
};

/// Deadline Run Queue
pub const DlRunQueue = struct {
    tasks: [256]?*Task,
    task_count: u32,
    nr_running: u32,
    earliest_deadline: u64,
    total_bw: u64, // Total bandwidth

    pub fn init() DlRunQueue {
        return .{
            .tasks = [_]?*Task{null} ** 256,
            .task_count = 0,
            .nr_running = 0,
            .earliest_deadline = ~@as(u64, 0),
            .total_bw = 0,
        };
    }

    /// Admission control - check if task can be admitted
    pub fn admissionCheck(self: *const DlRunQueue, runtime: u64, period: u64) bool {
        if (period == 0) return false;
        const new_bw = (runtime * 1_000_000) / period;
        // Total bandwidth must not exceed 100%
        return (self.total_bw + new_bw) <= 1_000_000;
    }

    pub fn pickEarliestDeadline(self: *DlRunQueue) ?*Task {
        var earliest: ?*Task = null;
        var earliest_dl: u64 = ~@as(u64, 0);

        for (0..self.task_count) |i| {
            if (self.tasks[i]) |task| {
                if (task.dl.absolute_deadline < earliest_dl and task.dl.hasRuntime()) {
                    earliest_dl = task.dl.absolute_deadline;
                    earliest = task;
                }
            }
        }

        return earliest;
    }
};

/// Per-CPU Run Queue
pub const RunQueue = struct {
    /// Total number of running tasks
    nr_running: u32,
    /// CFS run queue
    cfs: CfsRunQueue,
    /// Real-time run queue
    rt: RtRunQueue,
    /// Deadline run queue
    dl: DlRunQueue,
    /// Current running task
    curr: ?*Task,
    /// Idle task
    idle: ?*Task,
    /// CPU this runqueue belongs to
    cpu: u32,
    /// Clock (monotonic ns)
    clock: u64,
    /// Task clock
    clock_task: u64,
    /// Runqueue lock
    locked: bool,
    /// Load tracking
    cpu_load: [5]u64,
    /// Migration queue
    migration_queue: [32]?*Task,
    migration_count: u32,
    /// NUMA statistics
    nr_numa_running: u32,
    nr_preferred_running: u32,
    /// Context switches
    nr_switches: u64,
    /// Scheduler ticks
    nr_ticks: u64,

    pub fn init(cpu: u32) RunQueue {
        return .{
            .nr_running = 0,
            .cfs = CfsRunQueue.init(),
            .rt = RtRunQueue.init(),
            .dl = DlRunQueue.init(),
            .curr = null,
            .idle = null,
            .cpu = cpu,
            .clock = 0,
            .clock_task = 0,
            .locked = false,
            .cpu_load = [_]u64{0} ** 5,
            .migration_queue = [_]?*Task{null} ** 32,
            .migration_count = 0,
            .nr_numa_running = 0,
            .nr_preferred_running = 0,
            .nr_switches = 0,
            .nr_ticks = 0,
        };
    }

    /// Pick next task to run (priority: DL > RT > CFS > Idle)
    pub fn pickNext(self: *RunQueue) ?*Task {
        // 1. Check deadline tasks first
        if (self.dl.pickEarliestDeadline()) |task| {
            return task;
        }

        // 2. Check real-time tasks
        if (self.rt.pickHighest()) |task| {
            return task;
        }

        // 3. Check CFS tasks (EEVDF pick)
        if (self.cfs.pickEevdf()) |task| {
            return task;
        }

        // 4. Return idle task
        return self.idle;
    }

    /// Scheduler tick (called from timer interrupt)
    pub fn tick(self: *RunQueue, now: u64) void {
        self.clock = now;
        self.nr_ticks += 1;

        if (self.curr) |curr| {
            switch (curr.policy) {
                .SCHED_NORMAL, .SCHED_BATCH => {
                    self.tickCfs(curr, now);
                },
                .SCHED_FIFO => {
                    // FIFO never preempts on tick
                },
                .SCHED_RR => {
                    self.tickRr(curr, now);
                },
                .SCHED_DEADLINE => {
                    self.tickDeadline(curr, now);
                },
                else => {},
            }
        }
    }

    fn tickCfs(self: *RunQueue, task: *Task, now: u64) void {
        const delta = now - task.se.prev_sum_exec_runtime;
        task.se.updateVruntime(delta);
        task.se.prev_sum_exec_runtime = now;
        self.cfs.updateMinVruntime();

        // Check if should preempt
        const ideal_runtime = self.cfs.calcIdealRuntime(&task.se);
        const actual_runtime = task.se.sum_exec_runtime - task.se.prev_sum_exec_runtime;
        if (actual_runtime >= ideal_runtime) {
            task.setNeedResched();
        }
    }

    fn tickRr(self: *RunQueue, task: *Task, now: u64) void {
        _ = self;
        _ = now;
        if (task.rt.time_slice > 0) {
            task.rt.time_slice -= 1_000_000; // 1ms per tick
            if (task.rt.time_slice == 0) {
                task.rt.time_slice = 100_000_000; // Reset to 100ms
                task.setNeedResched();
            }
        }
    }

    fn tickDeadline(self: *RunQueue, task: *Task, now: u64) void {
        _ = self;
        if (task.dl.remaining_runtime > 1_000_000) {
            task.dl.remaining_runtime -= 1_000_000;
        } else {
            task.dl.remaining_runtime = 0;
            if (task.dl.isExpired(now)) {
                task.dl.replenish(now);
                task.dl.overrun = true;
                task.dl.overrun_count += 1;
            }
        }
    }

    /// Perform a context switch
    pub fn contextSwitch(self: *RunQueue, prev: *Task, next: *Task) void {
        self.nr_switches += 1;

        // Save current task state marker
        if (prev.state == .running) {
            prev.state = .interruptible;
        }

        // Set new current
        self.curr = next;
        next.state = .running;
        next.cpu = self.cpu;
    }
};

/// Load balancing domain (for multi-CPU scheduling)
pub const SchedDomain = struct {
    level: DomainLevel,
    span: CpuMask,
    child: ?*SchedDomain,
    parent: ?*SchedDomain,
    balance_interval: u64,
    last_balance: u64,
    imbalance_pct: u32,
    cache_nice_tries: u32,
    busy_factor: u32,
    flags: u32,

    pub const DomainLevel = enum(u8) {
        SMT = 0, // Hyper-threading
        MC = 1, // Multi-core (same die)
        DIE = 2, // Same package
        NUMA = 3, // NUMA node
        SYSTEM = 4, // System-wide
    };

    pub const SD_BALANCE_NEWIDLE: u32 = 1 << 0;
    pub const SD_BALANCE_EXEC: u32 = 1 << 1;
    pub const SD_BALANCE_FORK: u32 = 1 << 2;
    pub const SD_BALANCE_WAKE: u32 = 1 << 3;
    pub const SD_WAKE_AFFINE: u32 = 1 << 4;
    pub const SD_SHARE_CPUPOWER: u32 = 1 << 5;
    pub const SD_SHARE_PKG: u32 = 1 << 6;
    pub const SD_SERIALIZE: u32 = 1 << 7;
    pub const SD_PREFER_SIBLING: u32 = 1 << 8;
    pub const SD_NUMA: u32 = 1 << 9;

    pub fn init(level: DomainLevel, span: CpuMask) SchedDomain {
        const default_flags = switch (level) {
            .SMT => SD_BALANCE_NEWIDLE | SD_BALANCE_EXEC | SD_BALANCE_FORK | SD_WAKE_AFFINE | SD_SHARE_CPUPOWER,
            .MC => SD_BALANCE_NEWIDLE | SD_BALANCE_EXEC | SD_BALANCE_FORK | SD_BALANCE_WAKE | SD_WAKE_AFFINE | SD_SHARE_PKG,
            .DIE => SD_BALANCE_NEWIDLE | SD_BALANCE_EXEC | SD_BALANCE_FORK | SD_BALANCE_WAKE | SD_WAKE_AFFINE,
            .NUMA => SD_BALANCE_NEWIDLE | SD_BALANCE_EXEC | SD_BALANCE_FORK | SD_BALANCE_WAKE | SD_NUMA,
            .SYSTEM => SD_BALANCE_NEWIDLE | SD_BALANCE_EXEC | SD_BALANCE_FORK,
        };

        return .{
            .level = level,
            .span = span,
            .child = null,
            .parent = null,
            .balance_interval = switch (level) {
                .SMT => 1_000_000, // 1ms
                .MC => 4_000_000, // 4ms
                .DIE => 8_000_000, // 8ms
                .NUMA => 64_000_000, // 64ms
                .SYSTEM => 128_000_000, // 128ms
            },
            .last_balance = 0,
            .imbalance_pct = 125,
            .cache_nice_tries = switch (level) {
                .SMT, .MC => 1,
                .DIE => 2,
                .NUMA, .SYSTEM => 0,
            },
            .busy_factor = 32,
            .flags = default_flags,
        };
    }
};

/// Energy-Aware Scheduling (EAS)
pub const EnergyModel = struct {
    /// Performance states for a CPU
    pub const PerfState = struct {
        frequency: u32, // MHz
        power: u32, // mW
        capacity: u32, // Relative capacity (max 1024)
    };

    /// Per-CPU performance domain
    pub const PerfDomain = struct {
        states: [16]PerfState,
        nr_states: u8,
        cpus: CpuMask,
        current_state: u8,

        pub fn getPower(self: *const PerfDomain) u32 {
            return self.states[self.current_state].power;
        }

        pub fn getCapacity(self: *const PerfDomain) u32 {
            return self.states[self.current_state].capacity;
        }

        pub fn findOptimalState(self: *const PerfDomain, required_capacity: u32) u8 {
            for (0..self.nr_states) |i| {
                if (self.states[i].capacity >= required_capacity) {
                    return @truncate(i);
                }
            }
            return self.nr_states - 1;
        }

        /// Calculate energy cost for running a task
        pub fn energyCost(self: *const PerfDomain, util: u32) u64 {
            const state = self.findOptimalState(util);
            const power = self.states[state].power;
            const cap = self.states[state].capacity;
            if (cap == 0) return 0;
            return (@as(u64, power) * util) / cap;
        }
    };
};

/// Global scheduler state
pub const MAX_CPUS: u32 = 256;
var run_queues: [MAX_CPUS]RunQueue = undefined;
var num_cpus: u32 = 0;
var scheduler_initialized: bool = false;

/// Initialize scheduler for all CPUs
pub fn init(cpu_count: u32) void {
    num_cpus = @min(cpu_count, MAX_CPUS);
    for (0..num_cpus) |i| {
        run_queues[i] = RunQueue.init(@truncate(i));
    }
    scheduler_initialized = true;
}

/// Schedule on current CPU
pub fn schedule(cpu: u32) void {
    if (cpu >= num_cpus) return;
    var rq = &run_queues[cpu];

    const prev = rq.curr orelse return;
    const next = rq.pickNext() orelse return;

    if (prev != next) {
        rq.contextSwitch(prev, next);
    }

    prev.clearNeedResched();
}

/// Wake up a task
pub fn wakeUp(task: *Task) void {
    if (task.state == .running) return;

    task.state = .running;
    const cpu = selectCpu(task);

    switch (task.policy) {
        .SCHED_NORMAL, .SCHED_BATCH, .SCHED_IDLE => {
            run_queues[cpu].cfs.enqueue(task);
        },
        .SCHED_FIFO, .SCHED_RR => {
            run_queues[cpu].rt.enqueue(task);
        },
        else => {
            run_queues[cpu].cfs.enqueue(task);
        },
    }

    run_queues[cpu].nr_running += 1;
    task.se.stats.nr_wakeups += 1;
}

/// Select the best CPU for a task
fn selectCpu(task: *Task) u32 {
    var best_cpu: u32 = task.cpu;
    var best_load: u64 = ~@as(u64, 0);

    // Simple load-based selection
    for (0..num_cpus) |i| {
        const cpu = @as(u32, @intCast(i));
        if (!task.cpus_allowed.isSet(cpu)) continue;

        const load = run_queues[i].cfs.load;
        if (load < best_load) {
            best_load = load;
            best_cpu = cpu;
        }
    }

    return best_cpu;
}

/// Scheduler tick handler
pub fn tick(cpu: u32, now: u64) void {
    if (cpu >= num_cpus) return;
    run_queues[cpu].tick(now);
}

/// Get scheduler statistics for a CPU
pub fn getStats(cpu: u32) ?struct { switches: u64, ticks: u64, running: u32 } {
    if (cpu >= num_cpus) return null;
    const rq = &run_queues[cpu];
    return .{
        .switches = rq.nr_switches,
        .ticks = rq.nr_ticks,
        .running = rq.nr_running,
    };
}

pub fn isInitialized() bool {
    return scheduler_initialized;
}
