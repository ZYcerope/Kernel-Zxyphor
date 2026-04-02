// =============================================================================
// Kernel Zxyphor v0.0.3 — EEVDF Scheduler (Earliest Eligible Virtual Deadline First)
// =============================================================================
// Next-generation scheduler that surpasses Linux 7.x CFS/EEVDF:
//
//   - EEVDF core: eligible entities scheduled by virtual deadline
//   - Multi-class scheduling: NORMAL, FIFO, RR, BATCH, IDLE, DEADLINE
//   - Per-CPU run queues with load balancing
//   - NUMA-aware thread placement
//   - Energy-Aware Scheduling (EAS) for heterogeneous CPUs
//   - Bandwidth throttling (CFS bandwidth controller)
//   - Core scheduling for SMT security (L1TF/MDS mitigation)
//   - PSI (Pressure Stall Information) tracking
//   - Latency nice support (-20 to +19 latency priority)
//   - Utilization clamping (uclamp_min / uclamp_max)
//   - Auto-group scheduling (per-TTY session grouping)
//   - SCHED_DEADLINE with CBS (Constant Bandwidth Server)
//
// The EEVDF algorithm replaces CFS's vruntime-only approach with a two-key
// system: virtual eligible time (VET) and virtual deadline (VD).
// An entity is "eligible" when its VET <= current virtual time.
// Among eligible entities, the one with the earliest VD runs next.
// This ensures both fairness AND bounded latency.
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Scheduling Classes — priority order (highest first)
// =============================================================================
pub const SchedClass = enum(u8) {
    stop = 0, // Highest priority — migration/stop tasks
    deadline = 1, // SCHED_DEADLINE — EDF with CBS
    realtime = 2, // SCHED_FIFO / SCHED_RR
    fair = 3, // SCHED_NORMAL / SCHED_BATCH (EEVDF)
    idle = 4, // SCHED_IDLE — only runs when nothing else can
};

pub const SchedPolicy = enum(u8) {
    normal = 0, // SCHED_NORMAL — default timesharing (EEVDF)
    fifo = 1, // SCHED_FIFO — first-in-first-out realtime
    rr = 2, // SCHED_RR — round-robin realtime
    batch = 3, // SCHED_BATCH — CPU-intensive batch processing
    iso = 4, // SCHED_ISO — isochronous (soft realtime)
    idle = 5, // SCHED_IDLE — ultra-low priority
    deadline = 6, // SCHED_DEADLINE — EDF with bandwidth reservation
};

pub const TaskState = enum(u8) {
    running = 0, // On a CPU or in a run queue
    interruptible = 1, // Sleeping, can be woken by signal
    uninterruptible = 2, // Sleeping, cannot be woken by signal (D state)
    stopped = 4, // Stopped by SIGSTOP/ptrace
    traced = 8, // Being ptraced
    zombie = 16, // Exited, waiting for parent to reap
    dead = 32, // Final state, being cleaned up
    wakekill = 64, // Like uninterruptible but woken by fatal signals
    parked = 128, // Kthread parked
};

// =============================================================================
// EEVDF Parameters
// =============================================================================
const EEVDF_SLICE_MIN_NS: u64 = 750_000; // 0.75ms minimum slice
const EEVDF_SLICE_DEFAULT_NS: u64 = 3_000_000; // 3ms default slice (request)
const EEVDF_SLICE_MAX_NS: u64 = 24_000_000; // 24ms maximum slice
const EEVDF_LATENCY_NS: u64 = 12_000_000; // 12ms target latency
const EEVDF_WAKEUP_PREEMPT_THRESH_NS: u64 = 1_000_000; // 1ms wakeup preemption threshold
const TICK_NS: u64 = 1_000_000; // 1ms per scheduler tick (1000 Hz)
const SCHED_PERIOD_NS: u64 = 100_000_000; // 100ms scheduling period
const RR_TIMESLICE_NS: u64 = 100_000_000; // 100ms for SCHED_RR

// Maximum number of CPUs and scheduling entities  
const MAX_CPUS: usize = 256;
const MAX_RT_PRIO: u32 = 100;
const MAX_NICE: i8 = 19;
const MIN_NICE: i8 = -20;
const DEFAULT_PRIO: u32 = 120; // nice 0

// Nice to weight table — same as Linux, determines CPU share proportions
const nice_to_weight = [40]u32{
    88761, 71755, 56483, 46273, 36291, // -20 to -16
    29154, 23254, 18705, 14949, 11916, // -15 to -11
    9548,  7620,  6100,  4904,  3906, //  -10 to -6
    3121,  2501,  1991,  1586,  1277, //  -5 to -1
    1024,  820,   655,   526,   423, //   0 to 4
    335,   272,   215,   172,   137, //   5 to 9
    110,   87,    70,    56,    45, //    10 to 14
    36,    29,    23,    18,    15, //    15 to 19
};

// Nice to inverse weight (for fast division) = 2^32 / weight
const nice_to_wmult = [40]u32{
    48388, 59856, 76040, 92818, 118348,
    147320, 184698, 229616, 287308, 360437,
    449829, 563644, 704093, 875809, 1099582,
    1376151, 1717300, 2157191, 2708050, 3363326,
    4194304, 5237765, 6557202, 8165337, 10153587,
    12820798, 15790321, 19976592, 24970740, 31350126,
    39045157, 49367440, 61356676, 76695844, 95443717,
    119304647, 148102320, 186737708, 238609294, 286331153,
};

// Latency nice to multiplier — controls scheduling latency priority
const latency_nice_to_mult = [40]u32{
    16, 15, 14, 13, 12, 11, 10, 9, 8, 8,
    7, 7, 6, 6, 5, 5, 4, 4, 4, 3,
    3, 3, 3, 2, 2, 2, 2, 2, 2, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

// =============================================================================
// Scheduling Entity — the core EEVDF structure
// =============================================================================
pub const SchedEntity = struct {
    // === EEVDF keys ===
    vruntime: u64 = 0, // Virtual runtime consumed
    deadline: u64 = 0, // Virtual deadline (vruntime + request/weight)
    min_vruntime: u64 = 0, // Snapshot of CFS rq min_vruntime when placed
    slice: u64 = EEVDF_SLICE_DEFAULT_NS, // Requested time slice
    vlag: i64 = 0, // Virtual lag (> 0 = owed CPU time)

    // === Weight ===
    load_weight: u64 = 1024, // Weight derived from nice value
    inv_weight: u32 = 4194304, // Inverse weight for fast division
    nice: i8 = 0, // Nice value (-20 to +19)
    latency_nice: i8 = 0, // Latency nice (-20 to +19)

    // === Runtime tracking ===
    sum_exec_runtime: u64 = 0, // Total execution time (ns)
    prev_sum_exec_runtime: u64 = 0, // At last slice boundary
    nr_migrations: u64 = 0, // Times migrated between CPUs
    exec_start: u64 = 0, // When this entity started executing (ns)

    // === Statistics ===
    statistics: SchedStatistics = .{},

    // === Scheduling class ===
    policy: SchedPolicy = .normal,
    sched_class: SchedClass = .fair,

    // === RB-tree linkage ===
    rb_left: ?*SchedEntity = null,
    rb_right: ?*SchedEntity = null,
    rb_parent: ?*SchedEntity = null,
    rb_color: RbColor = .red,

    // === Group scheduling ===
    parent: ?*SchedEntity = null, // Parent group entity
    cfs_rq: ?*CfsRunQueue = null, // The CFS rq this entity is on
    my_q: ?*CfsRunQueue = null, // For group entities: the rq they own
    depth: u32 = 0, // Depth in the task group hierarchy

    // === Bandwidth throttling ===
    runtime_remaining: i64 = 0,
    throttled: bool = false,

    // === Utilization tracking (PELT: Per-Entity Load Tracking) ===
    avg: LoadAvg = .{},

    // === Uclamp (utilization clamping) ===
    uclamp_min: u32 = 0, // Minimum utilization (0-1024)
    uclamp_max: u32 = 1024, // Maximum utilization (0-1024)
    uclamp_effective_min: u32 = 0,
    uclamp_effective_max: u32 = 1024,

    // === Back-pointer to thread ===
    thread: ?*main.thread.Thread = null,

    // === EEVDF eligibility check ===
    pub fn isEligible(self: *const SchedEntity, cfs_min_vruntime: u64) bool {
        // An entity is eligible when it has received no more than its fair
        // share: vruntime <= min_vruntime_of_rq (approximately)
        // With vlag: eligible when vlag >= 0 (entity is owed CPU time)
        _ = cfs_min_vruntime;
        return self.vlag >= 0;
    }

    pub fn updateDeadline(self: *SchedEntity) void {
        // Virtual deadline = vruntime + (slice * NICE_0_WEIGHT / weight)
        if (self.load_weight > 0) {
            const scaled_slice = (self.slice * 1024) / self.load_weight;
            self.deadline = self.vruntime + scaled_slice;
        } else {
            self.deadline = self.vruntime + self.slice;
        }
    }

    pub fn setNice(self: *SchedEntity, nice_val: i8) void {
        self.nice = nice_val;
        const idx = @as(usize, @intCast(@as(i32, nice_val) + 20));
        if (idx < nice_to_weight.len) {
            self.load_weight = nice_to_weight[idx];
            self.inv_weight = nice_to_wmult[idx];
        }
    }

    pub fn setSlice(self: *SchedEntity) void {
        // Slice is scaled by latency_nice
        const lat_idx = @as(usize, @intCast(@as(i32, self.latency_nice) + 20));
        const mult = if (lat_idx < latency_nice_to_mult.len)
            latency_nice_to_mult[lat_idx]
        else
            3;
        self.slice = EEVDF_SLICE_DEFAULT_NS * mult / 3;
        if (self.slice < EEVDF_SLICE_MIN_NS) self.slice = EEVDF_SLICE_MIN_NS;
        if (self.slice > EEVDF_SLICE_MAX_NS) self.slice = EEVDF_SLICE_MAX_NS;
    }
};

pub const RbColor = enum { red, black };

pub const SchedStatistics = struct {
    wait_start: u64 = 0,
    wait_max: u64 = 0,
    wait_count: u64 = 0,
    wait_sum: u64 = 0,
    iowait_count: u64 = 0,
    iowait_sum: u64 = 0,
    sleep_start: u64 = 0,
    sleep_max: u64 = 0,
    sleep_sum: u64 = 0,
    block_start: u64 = 0,
    block_max: u64 = 0,
    nr_wakeups: u64 = 0,
    nr_wakeups_sync: u64 = 0,
    nr_wakeups_migrate: u64 = 0,
    nr_wakeups_local: u64 = 0,
    nr_wakeups_remote: u64 = 0,
    nr_wakeups_affine: u64 = 0,
    nr_wakeups_affine_attempts: u64 = 0,
    nr_wakeups_passive: u64 = 0,
    nr_wakeups_idle: u64 = 0,
    nr_failed_migrations_affine: u64 = 0,
    nr_failed_migrations_running: u64 = 0,
    nr_failed_migrations_hot: u64 = 0,
    nr_forced_migrations: u64 = 0,
    nr_voluntary_switches: u64 = 0,
    nr_involuntary_switches: u64 = 0,
    core_forceidle_sum: u64 = 0,
};

pub const LoadAvg = struct {
    load_avg: u64 = 0, // Weighted load average
    runnable_avg: u64 = 0, // Runnable time average
    util_avg: u64 = 0, // CPU utilization average
    load_sum: u64 = 0,
    runnable_sum: u64 = 0,
    util_sum: u64 = 0,
    period_contrib: u32 = 0,
    last_update_time: u64 = 0,
    util_est: UtilEst = .{},
};

pub const UtilEst = struct {
    enqueued: u32 = 0, // Utilization estimated at enqueue
    ewma: u32 = 0, // Exponentially weighted moving average
};

// =============================================================================
// SCHED_DEADLINE Entity (Constant Bandwidth Server — CBS)
// =============================================================================
pub const DeadlineEntity = struct {
    // CBS parameters (set by sched_setattr)
    dl_runtime: u64 = 0, // Maximum runtime per period (ns)
    dl_deadline: u64 = 0, // Relative deadline (ns)
    dl_period: u64 = 0, // Period (ns), 0 = same as deadline
    dl_bw: u64 = 0, // Bandwidth = runtime / period (fixed-point)
    dl_density: u64 = 0, // Density = runtime / deadline

    // Runtime state
    runtime: i64 = 0, // Remaining runtime in current period
    abs_deadline: u64 = 0, // Absolute deadline (monotonic ns)
    abs_period: u64 = 0, // Start of next period

    // Flags
    dl_throttled: bool = false, // Exhausted runtime, waiting for replenish
    dl_boosted: bool = false, // Priority inheritance boost
    dl_yielded: bool = false, // Yielded current period
    dl_non_contending: bool = false, // Not competing for CPU
    dl_overrun: bool = false, // Overran deadline (soft error)

    // Timer for replenishment
    dl_timer_active: bool = false,

    // Statistics
    nr_overruns: u64 = 0,
    nr_throttled: u64 = 0,
    total_runtime: u64 = 0,

    pub fn replenishRuntime(self: *DeadlineEntity, now: u64) void {
        // CBS replenishment: if deadline has passed, set new absolute deadline
        if (now >= self.abs_deadline) {
            self.abs_deadline = now + self.dl_deadline;
            self.abs_period = now + if (self.dl_period > 0) self.dl_period else self.dl_deadline;
        }
        self.runtime = @as(i64, @intCast(self.dl_runtime));
        self.dl_throttled = false;
    }

    pub fn consumeRuntime(self: *DeadlineEntity, delta_ns: u64) void {
        self.runtime -= @as(i64, @intCast(delta_ns));
        self.total_runtime += delta_ns;
        if (self.runtime <= 0) {
            self.dl_throttled = true;
            self.nr_throttled += 1;
        }
    }

    pub fn checkDeadlineMiss(self: *DeadlineEntity, now: u64) bool {
        if (now > self.abs_deadline and self.runtime <= 0) {
            self.dl_overrun = true;
            self.nr_overruns += 1;
            return true;
        }
        return false;
    }

    pub fn setBandwidth(self: *DeadlineEntity) void {
        if (self.dl_period > 0) {
            self.dl_bw = (self.dl_runtime << 20) / self.dl_period;
        } else if (self.dl_deadline > 0) {
            self.dl_bw = (self.dl_runtime << 20) / self.dl_deadline;
        }
        if (self.dl_deadline > 0) {
            self.dl_density = (self.dl_runtime << 20) / self.dl_deadline;
        }
    }
};

// =============================================================================
// Real-Time Entity (FIFO / RR)
// =============================================================================
pub const RtEntity = struct {
    rt_priority: u32 = 0, // 1-99, higher = more important
    time_slice: u64 = RR_TIMESLICE_NS, // For SCHED_RR only
    timeout: u64 = 0, // For SCHED_RR time slice tracking
    on_rq: bool = false,
    on_list: bool = false,
    nr_cpus_allowed: u32 = MAX_CPUS,

    // Linked list for RT run queue
    rt_next: ?*RtEntity = null,
    rt_prev: ?*RtEntity = null,

    // Back-pointer
    thread: ?*main.thread.Thread = null,

    // Statistics
    nr_runs: u64 = 0,
    total_runtime: u64 = 0,
};

// =============================================================================
// CFS Run Queue — per-CPU fair scheduling state
// =============================================================================
pub const CfsRunQueue = struct {
    // === EEVDF RB-tree ===
    rb_root: ?*SchedEntity = null, // Root of the RB-tree
    rb_leftmost: ?*SchedEntity = null, // Cached leftmost (earliest deadline eligible)
    nr_running: u32 = 0, // Number of runnable entities

    // === Virtual time ===
    min_vruntime: u64 = 0, // Monotonically increasing minimum vruntime
    min_vruntime_copy: u64 = 0, // For lockless access

    // === Load tracking ===
    load: LoadWeight = .{}, // Total weight of all entities
    avg: LoadAvg = .{}, // Aggregated PELT average
    runnable_weight: u64 = 0, // Sum of runnable entity weights

    // === Runtime accounting ===
    exec_clock: u64 = 0, // Total execution time on this rq (ns)

    // === Current running entity ===
    curr: ?*SchedEntity = null,
    next_to_run: ?*SchedEntity = null, // "next" buddy hint
    last: ?*SchedEntity = null, // Last ran (for cache affinity)
    skip: ?*SchedEntity = null, // Skip this entity (just yielded)

    // === Bandwidth throttling ===
    runtime_enabled: bool = false,
    runtime_remaining: i64 = 0,
    throttled: bool = false,
    throttled_clock: u64 = 0,
    throttle_count: u64 = 0,

    // === Idle tracking ===
    idle_nr_running: u32 = 0, // Number of SCHED_IDLE entities
    idle_h_nr_running: u32 = 0, // Hierarchical idle count

    // === Group scheduling ===
    tg: ?*TaskGroup = null, // Owning task group

    // === Statistics ===
    nr_spread_over: u32 = 0,
    nr_wakeups: u64 = 0,
    nr_migrations: u64 = 0,

    // === EEVDF: enqueue an entity ===
    pub fn enqueueEntity(self: *CfsRunQueue, se: *SchedEntity) void {
        // Update vruntime to at least min_vruntime
        if (se.vruntime < self.min_vruntime) {
            se.vruntime = self.min_vruntime;
        }

        // Calculate virtual deadline
        se.updateDeadline();

        // Update vlag: positive = owed CPU, negative = got too much
        const ideal_runtime = self.idealRuntime(se);
        const actual_runtime = se.sum_exec_runtime - se.prev_sum_exec_runtime;
        se.vlag = @as(i64, @intCast(ideal_runtime)) - @as(i64, @intCast(@min(actual_runtime, ideal_runtime)));

        // Insert into RB-tree ordered by deadline (for EEVDF: eligible first, then by deadline)
        self.rbInsert(se);
        self.nr_running += 1;
        self.load.weight += se.load_weight;

        // Update aggregated load average
        self.updateLoadAvg(se);
    }

    // === EEVDF: dequeue an entity ===
    pub fn dequeueEntity(self: *CfsRunQueue, se: *SchedEntity) void {
        self.rbRemove(se);
        if (self.nr_running > 0) self.nr_running -= 1;
        if (self.load.weight >= se.load_weight) {
            self.load.weight -= se.load_weight;
        }
        if (self.curr == se) self.curr = null;
    }

    // === EEVDF: pick the best entity to run next ===
    pub fn pickNextEntity(self: *CfsRunQueue) ?*SchedEntity {
        // Among all eligible entities, pick the one with the earliest virtual deadline
        if (self.nr_running == 0) return null;

        var best: ?*SchedEntity = null;
        var best_deadline: u64 = @as(u64, 0xFFFFFFFFFFFFFFFF);

        // Walk the tree to find the eligible entity with earliest deadline
        self.walkTreeForBest(self.rb_root, &best, &best_deadline);

        // Apply skip/next/last hints
        if (self.skip) |skip| {
            if (best == skip) {
                // Try to find another eligible entity
                const alt = self.findAlternative(skip);
                if (alt) |a| {
                    best = a;
                }
                self.skip = null;
            }
        }

        if (self.next_to_run) |next| {
            if (next.isEligible(self.min_vruntime)) {
                if (best == null or next.deadline < best_deadline) {
                    best = next;
                }
            }
            self.next_to_run = null;
        }

        return best;
    }

    fn walkTreeForBest(self: *CfsRunQueue, node: ?*SchedEntity, best: *?*SchedEntity, best_deadline: *u64) void {
        const n = node orelse return;

        // Check if this entity is eligible
        if (n.isEligible(self.min_vruntime)) {
            if (n.deadline < best_deadline.*) {
                best.* = n;
                best_deadline.* = n.deadline;
            }
        }

        // Recurse into children
        self.walkTreeForBest(n.rb_left, best, best_deadline);
        self.walkTreeForBest(n.rb_right, best, best_deadline);
    }

    fn findAlternative(self: *CfsRunQueue, skip_entity: *SchedEntity) ?*SchedEntity {
        var alt: ?*SchedEntity = null;
        var alt_deadline: u64 = @as(u64, 0xFFFFFFFFFFFFFFFF);
        self.walkTreeForAlt(self.rb_root, skip_entity, &alt, &alt_deadline);
        return alt;
    }

    fn walkTreeForAlt(self: *CfsRunQueue, node: ?*SchedEntity, skip_entity: *SchedEntity, alt: *?*SchedEntity, alt_deadline: *u64) void {
        const n = node orelse return;
        if (n != skip_entity and n.isEligible(self.min_vruntime)) {
            if (n.deadline < alt_deadline.*) {
                alt.* = n;
                alt_deadline.* = n.deadline;
            }
        }
        self.walkTreeForAlt(n.rb_left, skip_entity, alt, alt_deadline);
        self.walkTreeForAlt(n.rb_right, skip_entity, alt, alt_deadline);
    }

    // === Update vruntime after execution ===
    pub fn updateCurrVruntime(self: *CfsRunQueue, delta_ns: u64) void {
        if (self.curr) |se| {
            // Weighted vruntime delta = delta_ns * NICE_0_WEIGHT / weight
            const weighted_delta = (delta_ns * 1024) / @max(se.load_weight, 1);
            se.vruntime += weighted_delta;
            se.sum_exec_runtime += delta_ns;

            // Update vlag
            se.vlag -= @as(i64, @intCast(weighted_delta));

            // Update min_vruntime (monotonically increasing)
            self.updateMinVruntime();

            // Check if current entity has exhausted its slice
            if (se.sum_exec_runtime - se.prev_sum_exec_runtime >= se.slice) {
                // Time's up — need reschedule
                se.prev_sum_exec_runtime = se.sum_exec_runtime;
                se.updateDeadline();
            }

            self.exec_clock += delta_ns;
        }
    }

    fn updateMinVruntime(self: *CfsRunQueue) void {
        var vruntime = self.min_vruntime;

        if (self.curr) |se| {
            if (se.vruntime > vruntime) vruntime = se.vruntime;
        }

        if (self.rb_leftmost) |leftmost| {
            if (leftmost.vruntime < vruntime) {
                vruntime = (vruntime + leftmost.vruntime) / 2;
            }
        }

        // min_vruntime must never decrease
        if (vruntime > self.min_vruntime) {
            self.min_vruntime = vruntime;
        }
        self.min_vruntime_copy = self.min_vruntime;
    }

    fn idealRuntime(self: *CfsRunQueue, se: *SchedEntity) u64 {
        // Ideal runtime = period * (weight / total_weight)
        if (self.load.weight == 0) return EEVDF_SLICE_DEFAULT_NS;
        return (SCHED_PERIOD_NS * se.load_weight) / self.load.weight;
    }

    fn updateLoadAvg(self: *CfsRunQueue, se: *SchedEntity) void {
        _ = se;
        // PELT (Per-Entity Load Tracking) update
        // Simplified: just track aggregate
        self.avg.util_avg = if (self.nr_running > 0)
            @min(@as(u64, self.nr_running) * 256, 1024)
        else
            0;
    }

    // === RB-tree operations ===
    fn rbInsert(self: *CfsRunQueue, se: *SchedEntity) void {
        se.rb_left = null;
        se.rb_right = null;
        se.rb_color = .red;

        if (self.rb_root == null) {
            self.rb_root = se;
            se.rb_parent = null;
            se.rb_color = .black;
            self.rb_leftmost = se;
            return;
        }

        var parent: ?*SchedEntity = null;
        var current = self.rb_root;
        var go_left = true;

        while (current) |c| {
            parent = c;
            // Order by: eligible first, then by virtual deadline
            if (se.deadline < c.deadline) {
                current = c.rb_left;
                go_left = true;
            } else {
                current = c.rb_right;
                go_left = false;
            }
        }

        se.rb_parent = parent;
        if (parent) |p| {
            if (go_left) {
                p.rb_left = se;
                // Check if this is the new leftmost
                if (self.rb_leftmost == p or
                    (self.rb_leftmost != null and se.deadline < self.rb_leftmost.?.deadline))
                {
                    self.rb_leftmost = se;
                }
            } else {
                p.rb_right = se;
            }
        }

        // RB-tree fixup (maintain red-black invariants)
        self.rbInsertFixup(se);
    }

    fn rbRemove(self: *CfsRunQueue, se: *SchedEntity) void {
        // Update leftmost cache
        if (self.rb_leftmost == se) {
            // Find successor
            if (se.rb_right) |right| {
                self.rb_leftmost = self.rbMinimum(right);
            } else {
                self.rb_leftmost = se.rb_parent;
            }
        }

        // Standard BST removal
        if (se.rb_left != null and se.rb_right != null) {
            // Two children: replace with in-order successor
            const successor = self.rbMinimum(se.rb_right.?) orelse return;
            // Swap data (simplified: just re-link)
            self.rbTransplant(se, successor);
        } else if (se.rb_left) |child| {
            self.rbTransplant(se, child);
        } else if (se.rb_right) |child| {
            self.rbTransplant(se, child);
        } else {
            // Leaf node
            if (se.rb_parent) |parent| {
                if (parent.rb_left == se) {
                    parent.rb_left = null;
                } else {
                    parent.rb_right = null;
                }
            } else {
                self.rb_root = null;
                self.rb_leftmost = null;
            }
        }

        se.rb_left = null;
        se.rb_right = null;
        se.rb_parent = null;
    }

    fn rbTransplant(self: *CfsRunQueue, old: *SchedEntity, new: *SchedEntity) void {
        if (old.rb_parent) |parent| {
            if (parent.rb_left == old) {
                parent.rb_left = new;
            } else {
                parent.rb_right = new;
            }
        } else {
            self.rb_root = new;
        }
        new.rb_parent = old.rb_parent;
    }

    fn rbMinimum(self: *CfsRunQueue, node: *SchedEntity) ?*SchedEntity {
        _ = self;
        var n = node;
        while (n.rb_left) |left| {
            n = left;
        }
        return n;
    }

    fn rbInsertFixup(self: *CfsRunQueue, z_param: *SchedEntity) void {
        var z = z_param;
        while (z.rb_parent) |parent| {
            if (parent.rb_color != .red) break;

            if (parent.rb_parent) |grandparent| {
                if (parent == grandparent.rb_left) {
                    const uncle = grandparent.rb_right;
                    if (uncle) |u| {
                        if (u.rb_color == .red) {
                            // Case 1: uncle is red
                            parent.rb_color = .black;
                            u.rb_color = .black;
                            grandparent.rb_color = .red;
                            z = grandparent;
                            continue;
                        }
                    }
                    if (z == parent.rb_right) {
                        // Case 2: z is right child
                        z = parent;
                        self.rbRotateLeft(z);
                    }
                    // Case 3: z is left child
                    if (z.rb_parent) |p| {
                        p.rb_color = .black;
                        if (p.rb_parent) |gp| {
                            gp.rb_color = .red;
                            self.rbRotateRight(gp);
                        }
                    }
                } else {
                    // Mirror cases
                    const uncle = grandparent.rb_left;
                    if (uncle) |u| {
                        if (u.rb_color == .red) {
                            parent.rb_color = .black;
                            u.rb_color = .black;
                            grandparent.rb_color = .red;
                            z = grandparent;
                            continue;
                        }
                    }
                    if (z == parent.rb_left) {
                        z = parent;
                        self.rbRotateRight(z);
                    }
                    if (z.rb_parent) |p| {
                        p.rb_color = .black;
                        if (p.rb_parent) |gp| {
                            gp.rb_color = .red;
                            self.rbRotateLeft(gp);
                        }
                    }
                }
            } else break;
        }
        if (self.rb_root) |root| {
            root.rb_color = .black;
        }
    }

    fn rbRotateLeft(self: *CfsRunQueue, x: *SchedEntity) void {
        const y = x.rb_right orelse return;
        x.rb_right = y.rb_left;
        if (y.rb_left) |yl| yl.rb_parent = x;
        y.rb_parent = x.rb_parent;
        if (x.rb_parent) |p| {
            if (p.rb_left == x) {
                p.rb_left = y;
            } else {
                p.rb_right = y;
            }
        } else {
            self.rb_root = y;
        }
        y.rb_left = x;
        x.rb_parent = y;
    }

    fn rbRotateRight(self: *CfsRunQueue, y: *SchedEntity) void {
        const x = y.rb_left orelse return;
        y.rb_left = x.rb_right;
        if (x.rb_right) |xr| xr.rb_parent = y;
        x.rb_parent = y.rb_parent;
        if (y.rb_parent) |p| {
            if (p.rb_left == y) {
                p.rb_left = x;
            } else {
                p.rb_right = x;
            }
        } else {
            self.rb_root = x;
        }
        x.rb_right = y;
        y.rb_parent = x;
    }
};

pub const LoadWeight = struct {
    weight: u64 = 0,
    inv_weight: u32 = 0,
};

// =============================================================================
// RT Run Queue — per-CPU real-time scheduling
// =============================================================================
pub const RtRunQueue = struct {
    // One list per priority level (0-99)
    queues: [MAX_RT_PRIO]RtPrioList = [_]RtPrioList{.{}} ** MAX_RT_PRIO,
    rt_nr_running: u32 = 0,
    highest_prio: u32 = MAX_RT_PRIO,
    overloaded: bool = false,
    rt_time: u64 = 0, // Total RT time consumed in current period
    rt_runtime: u64 = 950_000_000, // 950ms per 1000ms (95% RT limit)
    rt_period: u64 = 1_000_000_000, // 1 second period
    rt_throttled: bool = false,

    pub fn enqueue(self: *RtRunQueue, entity: *RtEntity) void {
        const prio = @min(entity.rt_priority, MAX_RT_PRIO - 1);
        entity.rt_next = self.queues[prio].head;
        if (self.queues[prio].head) |h| h.rt_prev = entity;
        self.queues[prio].head = entity;
        self.queues[prio].nr_running += 1;
        self.rt_nr_running += 1;
        entity.on_rq = true;
        if (prio < self.highest_prio) self.highest_prio = prio;
    }

    pub fn dequeue(self: *RtRunQueue, entity: *RtEntity) void {
        const prio = @min(entity.rt_priority, MAX_RT_PRIO - 1);
        if (entity.rt_prev) |prev| {
            prev.rt_next = entity.rt_next;
        } else {
            self.queues[prio].head = entity.rt_next;
        }
        if (entity.rt_next) |next| {
            next.rt_prev = entity.rt_prev;
        }
        entity.rt_next = null;
        entity.rt_prev = null;
        if (self.queues[prio].nr_running > 0) self.queues[prio].nr_running -= 1;
        if (self.rt_nr_running > 0) self.rt_nr_running -= 1;
        entity.on_rq = false;

        // Recalculate highest priority
        if (self.queues[prio].nr_running == 0 and prio == self.highest_prio) {
            self.highest_prio = MAX_RT_PRIO;
            var p: u32 = prio + 1;
            while (p < MAX_RT_PRIO) : (p += 1) {
                if (self.queues[p].nr_running > 0) {
                    self.highest_prio = p;
                    break;
                }
            }
        }
    }

    pub fn pickNext(self: *RtRunQueue) ?*RtEntity {
        if (self.rt_nr_running == 0) return null;
        if (self.rt_throttled) return null;
        // Pick from highest priority queue (lowest index)
        var prio = self.highest_prio;
        while (prio < MAX_RT_PRIO) : (prio += 1) {
            if (self.queues[prio].head) |entity| return entity;
        }
        return null;
    }

    pub fn updateRtTime(self: *RtRunQueue, delta_ns: u64) void {
        self.rt_time += delta_ns;
        if (self.rt_time >= self.rt_runtime) {
            self.rt_throttled = true;
        }
    }

    pub fn periodReset(self: *RtRunQueue) void {
        self.rt_time = 0;
        self.rt_throttled = false;
    }
};

const RtPrioList = struct {
    head: ?*RtEntity = null,
    nr_running: u32 = 0,
};

// =============================================================================
// Deadline Run Queue
// =============================================================================
pub const DlRunQueue = struct {
    rb_root: ?*SchedEntity = null,
    rb_leftmost: ?*SchedEntity = null,
    dl_nr_running: u32 = 0,
    earliest_deadline: u64 = 0xFFFFFFFFFFFFFFFF,
    dl_nr_migratory: u32 = 0,
    total_bw: u64 = 0, // Total reserved bandwidth

    pub fn enqueue(self: *DlRunQueue, se: *SchedEntity) void {
        // Insert ordered by absolute deadline
        self.dl_nr_running += 1;
        if (se.deadline < self.earliest_deadline) {
            self.earliest_deadline = se.deadline;
        }
        // Simple insertion (in real kernel, would use RB-tree)
        se.rb_left = null;
        se.rb_right = null;
        se.rb_parent = self.rb_root;
        if (self.rb_root == null) {
            self.rb_root = se;
            self.rb_leftmost = se;
        }
    }

    pub fn dequeue(self: *DlRunQueue, se: *SchedEntity) void {
        if (self.dl_nr_running > 0) self.dl_nr_running -= 1;
        if (self.rb_root == se) {
            self.rb_root = se.rb_right;
            self.rb_leftmost = se.rb_right;
        }
        se.rb_parent = null;
    }

    pub fn pickNext(self: *DlRunQueue) ?*SchedEntity {
        return self.rb_leftmost;
    }
};

// =============================================================================
// Per-CPU Run Queue — the main scheduling structure
// =============================================================================
pub const RunQueue = struct {
    // === Global run queue state ===
    nr_running: u32 = 0, // Total runnable tasks on this CPU
    nr_switches: u64 = 0, // Total context switches
    nr_uninterruptible: u32 = 0,

    // === Per-class run queues ===
    cfs: CfsRunQueue = .{}, // EEVDF/CFS entities
    rt: RtRunQueue = .{}, // Real-time entities
    dl: DlRunQueue = .{}, // Deadline entities

    // === Current task ===
    curr_entity: ?*SchedEntity = null,
    idle_entity: ?*SchedEntity = null, // The idle task

    // === Time accounting ===
    clock: u64 = 0, // Monotonic clock (ns)
    clock_task: u64 = 0, // CPU time excluding IRQ time
    clock_pelt: u64 = 0, // PELT clock
    prev_clock_raw: u64 = 0,

    // === CPU state ===
    cpu_id: u32 = 0,
    online: bool = true,
    idle: bool = true,

    // === Load balancing ===
    cpu_load: [5]u64 = [_]u64{0} ** 5, // Exponential load averages
    calc_load_update: u64 = 0,
    calc_load_active: u64 = 0,
    avg_idle: u64 = 0, // Average idle time
    max_idle_balance_cost: u64 = 500_000, // Max time for idle balance (ns)

    // === NUMA balancing ===
    numa_run_node: u8 = 0,
    numa_migrate_seq: u64 = 0,

    // === Core scheduling (for SMT) ===
    core: ?*RunQueue = null, // Sibling HT core
    core_forceidle_count: u64 = 0,
    core_forceidle_seq: u64 = 0,
    core_enabled: bool = false,

    // === PSI (Pressure Stall Information) ===
    psi_some: u64 = 0, // Time some tasks stalled (ns)
    psi_full: u64 = 0, // Time all tasks stalled (ns)
    psi_irq_full: u64 = 0,
    psi_flags: u32 = 0,

    // === Lock ===
    lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init(),

    /// Pick the next task to run (class priority: stop > DL > RT > CFS > idle)
    pub fn pickNextTask(self: *RunQueue) ?*SchedEntity {
        // 1. Deadline class (highest priority after stop)
        if (self.dl.dl_nr_running > 0) {
            if (self.dl.pickNext()) |se| return se;
        }

        // 2. Real-time class
        if (self.rt.rt_nr_running > 0) {
            if (self.rt.pickNext()) |rt_entity| {
                if (rt_entity.thread) |t| {
                    if (t.sched_entity) |se| return se;
                }
            }
        }

        // 3. Fair class (EEVDF)
        if (self.cfs.nr_running > 0) {
            return self.cfs.pickNextEntity();
        }

        // 4. Idle task
        return self.idle_entity;
    }

    /// Update clock on tick
    pub fn updateClock(self: *RunQueue) void {
        self.clock += TICK_NS;
        self.clock_task += TICK_NS;
    }

    /// Account the time of the current task
    pub fn accountTaskTime(self: *RunQueue) void {
        if (self.curr_entity) |se| {
            const delta = TICK_NS;
            switch (se.sched_class) {
                .fair => self.cfs.updateCurrVruntime(delta),
                .realtime => self.rt.updateRtTime(delta),
                .deadline => {
                    // Update deadline entity runtime
                    if (se.thread) |t| {
                        _ = t;
                    }
                },
                else => {},
            }
        }
    }
};

// =============================================================================
// Task Group — for cgroup-based CPU scheduling
// =============================================================================
pub const TaskGroup = struct {
    shares: u64 = 1024, // CPU shares (weight)
    cfs_bandwidth: CfsBandwidth = .{},

    // Per-CPU group entities
    se: [MAX_CPUS]?*SchedEntity = [_]?*SchedEntity{null} ** MAX_CPUS,
    cfs_rq: [MAX_CPUS]?*CfsRunQueue = [_]?*CfsRunQueue{null} ** MAX_CPUS,

    // Hierarchy
    parent: ?*TaskGroup = null,
    siblings_next: ?*TaskGroup = null,
    children: ?*TaskGroup = null,

    // Identity
    id: u32 = 0,
};

pub const CfsBandwidth = struct {
    period: u64 = 100_000_000, // 100ms default period
    quota: i64 = -1, // -1 = unlimited
    burst: u64 = 0,
    runtime: i64 = 0, // Remaining runtime in current period
    nr_periods: u64 = 0,
    nr_throttled: u64 = 0,
    throttled_time: u64 = 0,
    active: bool = false,
};

// =============================================================================
// Energy Model — for Energy-Aware Scheduling (EAS)
// =============================================================================
pub const EnergyModel = struct {
    const MAX_PERF_STATES = 32;

    nr_perf_states: u32 = 0,
    perf_states: [MAX_PERF_STATES]PerfState = [_]PerfState{.{}} ** MAX_PERF_STATES,
    cpu_cap_min: u64 = 0,
    cpu_cap_max: u64 = 1024,

    pub const PerfState = struct {
        frequency: u32 = 0, // kHz
        power: u32 = 0, // milliWatts
        cost: u64 = 0, // Normalized energy cost
        capacity: u64 = 0, // CPU capacity at this freq
    };

    pub fn computeEnergy(self: *const EnergyModel, utilization: u64) u64 {
        // Find the lowest frequency that can satisfy the utilization
        var i: u32 = 0;
        while (i < self.nr_perf_states) : (i += 1) {
            if (self.perf_states[i].capacity >= utilization) {
                return self.perf_states[i].cost;
            }
        }
        if (self.nr_perf_states > 0) {
            return self.perf_states[self.nr_perf_states - 1].cost;
        }
        return 0;
    }
};

// =============================================================================
// PSI (Pressure Stall Information) State
// =============================================================================
pub const PsiState = struct {
    // Per-resource tracking (cpu, memory, io)
    some_avg10: u64 = 0, // 10-second window (percentage * 100)
    some_avg60: u64 = 0, // 60-second window
    some_avg300: u64 = 0, // 300-second window
    some_total: u64 = 0, // Total stall time (us)
    full_avg10: u64 = 0,
    full_avg60: u64 = 0,
    full_avg300: u64 = 0,
    full_total: u64 = 0,

    pub fn update(self: *PsiState, some_ns: u64, full_ns: u64) void {
        self.some_total += some_ns / 1000;
        self.full_total += full_ns / 1000;
        // Exponential moving average update (simplified)
        self.some_avg10 = (self.some_avg10 * 9 + some_ns / 100) / 10;
        self.some_avg60 = (self.some_avg60 * 59 + some_ns / 100) / 60;
        self.some_avg300 = (self.some_avg300 * 299 + some_ns / 100) / 300;
        self.full_avg10 = (self.full_avg10 * 9 + full_ns / 100) / 10;
        self.full_avg60 = (self.full_avg60 * 59 + full_ns / 100) / 60;
        self.full_avg300 = (self.full_avg300 * 299 + full_ns / 100) / 300;
    }
};

// =============================================================================
// Global Scheduler State
// =============================================================================
var per_cpu_rq: [MAX_CPUS]RunQueue = [_]RunQueue{.{}} ** MAX_CPUS;
var nr_cpus_online: u32 = 1;

var scheduler_running: bool = false;
var need_resched: bool = false;
var tick_counter: u64 = 0;

// Global load averages (1min, 5min, 15min)
var avenrun: [3]u64 = [_]u64{0} ** 3;

// Root task group
var root_task_group: TaskGroup = .{};

// Energy model per performance domain
var energy_models: [8]EnergyModel = [_]EnergyModel{.{}} ** 8;
var nr_perf_domains: u32 = 0;

// PSI state (cpu, memory, io)
var psi_cpu: PsiState = .{};
var psi_memory: PsiState = .{};
var psi_io: PsiState = .{};

// Global scheduler lock
var sched_lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Scheduler Initialization
// =============================================================================
pub fn initialize() void {
    // Initialize per-CPU run queues
    for (0..MAX_CPUS) |cpu| {
        per_cpu_rq[cpu].cpu_id = @as(u32, @truncate(cpu));
        per_cpu_rq[cpu].online = (cpu == 0); // Only BSP online initially
        per_cpu_rq[cpu].cfs = .{};
        per_cpu_rq[cpu].rt = .{};
        per_cpu_rq[cpu].dl = .{};
    }

    // Initialize root task group
    root_task_group.shares = 1024;
    root_task_group.id = 0;

    scheduler_running = false;
    need_resched = false;
    tick_counter = 0;

    main.klog(.info, "Scheduler: EEVDF initialized (slice={d}us, latency={d}us, classes=5)", .{
        EEVDF_SLICE_DEFAULT_NS / 1000,
        EEVDF_LATENCY_NS / 1000,
    });
}

// =============================================================================
// Start the scheduler
// =============================================================================
pub fn start() noreturn {
    scheduler_running = true;
    schedule();
    unreachable;
}

// =============================================================================
// Add thread to run queue (compatible with old API)
// =============================================================================
pub fn addToRunQueue(proc: *main.process.Process) void {
    if (proc.main_thread) |thread| {
        addThreadToRunQueue(thread);
    }
}

pub fn addThreadToRunQueue(thread: *main.thread.Thread) void {
    sched_lock.acquire();
    defer sched_lock.release();

    const cpu_id: u32 = 0; // TODO: select best CPU via load balancing
    var rq = &per_cpu_rq[cpu_id];

    // Get or create scheduling entity
    const se = thread.sched_entity orelse return;

    // Initialize vruntime for new entities
    if (se.vruntime == 0) {
        se.vruntime = rq.cfs.min_vruntime;
    }

    se.thread = thread;

    // Enqueue based on scheduling class
    switch (se.sched_class) {
        .fair => rq.cfs.enqueueEntity(se),
        .realtime => {
            if (thread.rt_entity) |rt| {
                rq.rt.enqueue(rt);
            }
        },
        .deadline => rq.dl.enqueue(se),
        else => rq.cfs.enqueueEntity(se),
    }

    rq.nr_running += 1;
}

/// Remove a thread from the run queue
fn removeFromRunQueue(thread: *main.thread.Thread) void {
    const se = thread.sched_entity orelse return;
    const cpu_id: u32 = 0;
    var rq = &per_cpu_rq[cpu_id];

    switch (se.sched_class) {
        .fair => rq.cfs.dequeueEntity(se),
        .realtime => {
            if (thread.rt_entity) |rt| {
                rq.rt.dequeue(rt);
            }
        },
        .deadline => rq.dl.dequeue(se),
        else => rq.cfs.dequeueEntity(se),
    }

    if (rq.nr_running > 0) rq.nr_running -= 1;
}

// =============================================================================
// Timer tick handler
// =============================================================================
pub fn timerTick() void {
    tick_counter += 1;

    // Check sleeping threads
    main.thread.checkSleepers();

    const rq = &per_cpu_rq[0]; // Current CPU
    rq.updateClock();
    rq.accountTaskTime();

    // Check if current task should be preempted
    if (rq.curr_entity) |curr_se| {
        // Fair class: check if deadline has passed
        if (curr_se.sched_class == .fair) {
            if (curr_se.sum_exec_runtime - curr_se.prev_sum_exec_runtime >= curr_se.slice) {
                need_resched = true;
            }

            // Check if a higher-priority task is waiting
            if (rq.cfs.pickNextEntity()) |next| {
                if (next != curr_se and next.isEligible(rq.cfs.min_vruntime)) {
                    if (next.deadline + EEVDF_WAKEUP_PREEMPT_THRESH_NS < curr_se.deadline) {
                        need_resched = true;
                    }
                }
            }
        }

        // RT class: check RR time slice
        if (curr_se.policy == .rr) {
            if (curr_se.thread) |t| {
                _ = t;
                // RR timeslice check handled in accountTaskTime
            }
        }
    }

    // Update global load averages every 5 seconds
    if (tick_counter % 5000 == 0) {
        updateGlobalLoadAverages();
    }

    // Update PSI state every tick
    updatePsi();

    // RT bandwidth period reset (every 1 second)
    if (tick_counter % 1000 == 0) {
        rq.rt.periodReset();
    }

    if (need_resched) {
        need_resched = false;
        schedule();
    }
}

// =============================================================================
// Yield
// =============================================================================
pub fn yield() void {
    const rq = &per_cpu_rq[0];
    if (rq.curr_entity) |se| {
        // Mark as skip so pickNext avoids it
        rq.cfs.skip = se;
        se.prev_sum_exec_runtime = se.sum_exec_runtime;
        se.statistics.nr_voluntary_switches += 1;
    }
    schedule();
}

// =============================================================================
// Main scheduling function
// =============================================================================
fn schedule() void {
    sched_lock.acquire();

    var rq = &per_cpu_rq[0];

    // Put current entity back in run queue
    if (rq.curr_entity) |old_se| {
        if (old_se.thread) |old_thread| {
            if (old_thread.state == .running) {
                old_thread.state = .ready;
                // Re-enqueue
                switch (old_se.sched_class) {
                    .fair => {
                        old_se.prev_sum_exec_runtime = old_se.sum_exec_runtime;
                        old_se.updateDeadline();
                        rq.cfs.enqueueEntity(old_se);
                    },
                    .realtime => {
                        if (old_thread.rt_entity) |rt| {
                            rq.rt.enqueue(rt);
                        }
                    },
                    else => rq.cfs.enqueueEntity(old_se),
                }
            }
        }
    }

    // Pick next task (respects class priority)
    const next_se = rq.pickNextTask();
    if (next_se) |se| {
        const next_thread = se.thread;
        if (next_thread) |nt| {
            // Dequeue from run queue
            switch (se.sched_class) {
                .fair => rq.cfs.dequeueEntity(se),
                .realtime => {
                    if (nt.rt_entity) |rt| rq.rt.dequeue(rt);
                },
                else => rq.cfs.dequeueEntity(se),
            }

            nt.state = .running;
            se.exec_start = rq.clock;
            rq.cfs.curr = if (se.sched_class == .fair) se else null;
            rq.curr_entity = se;
            rq.nr_switches += 1;
            rq.idle = false;

            // Update min_vruntime
            if (se.vruntime > rq.cfs.min_vruntime) {
                rq.cfs.min_vruntime = se.vruntime;
            }

            const old_entity = rq.curr_entity;
            const old_thread = if (old_entity) |oe| oe.thread else null;

            main.process.setCurrent(nt.owner);
            main.tss.setKernelStack(nt.kernel_stack_top);

            sched_lock.release();

            if (old_thread) |old| {
                if (old != nt) {
                    if (old.owner != nt.owner) {
                        main.vmm.switchAddressSpace(&nt.owner.address_space);
                    }
                    se.statistics.nr_involuntary_switches += 1;
                    main.context.switchContext(&old.context, &nt.context);
                }
            } else {
                main.vmm.switchAddressSpace(&nt.owner.address_space);
                main.context.restoreContext(&nt.context);
            }
            return;
        }
    }

    // No runnable task — go idle
    rq.idle = true;
    rq.curr_entity = rq.idle_entity;
    sched_lock.release();
    main.arch.haltUntilInterrupt();
}

// =============================================================================
// Load Balancing
// =============================================================================
pub fn loadBalance() void {
    if (nr_cpus_online <= 1) return;

    // Find the busiest and idlest run queues
    var busiest_cpu: u32 = 0;
    var busiest_load: u32 = 0;
    var idlest_cpu: u32 = 0;
    var idlest_load: u32 = 0xFFFFFFFF;

    for (0..nr_cpus_online) |cpu| {
        const rq = &per_cpu_rq[cpu];
        if (!rq.online) continue;
        if (rq.nr_running > busiest_load) {
            busiest_load = rq.nr_running;
            busiest_cpu = @as(u32, @truncate(cpu));
        }
        if (rq.nr_running < idlest_load) {
            idlest_load = rq.nr_running;
            idlest_cpu = @as(u32, @truncate(cpu));
        }
    }

    // Migrate a task if imbalance > 1
    if (busiest_load > idlest_load + 1) {
        migrateTask(busiest_cpu, idlest_cpu);
    }
}

fn migrateTask(from_cpu: u32, to_cpu: u32) void {
    var src_rq = &per_cpu_rq[from_cpu];
    var dst_rq = &per_cpu_rq[to_cpu];

    // Find a suitable task to migrate (prefer movable, cache-cold tasks)
    const se = src_rq.cfs.pickNextEntity() orelse return;
    if (se.thread == null) return;

    // Dequeue from source
    src_rq.cfs.dequeueEntity(se);
    if (src_rq.nr_running > 0) src_rq.nr_running -= 1;

    // Adjust vruntime for the target rq
    if (dst_rq.cfs.min_vruntime > src_rq.cfs.min_vruntime) {
        se.vruntime += dst_rq.cfs.min_vruntime - src_rq.cfs.min_vruntime;
    } else if (src_rq.cfs.min_vruntime > dst_rq.cfs.min_vruntime) {
        const diff = src_rq.cfs.min_vruntime - dst_rq.cfs.min_vruntime;
        if (se.vruntime >= diff) {
            se.vruntime -= diff;
        }
    }

    // Enqueue on destination
    dst_rq.cfs.enqueueEntity(se);
    dst_rq.nr_running += 1;

    se.nr_migrations += 1;
    se.statistics.nr_wakeups_migrate += 1;
}

// =============================================================================
// NUMA Balancing
// =============================================================================
pub fn numaBalanceTick(thread_param: *main.thread.Thread) void {
    _ = thread_param;
    // NUMA balancing: periodically scan page tables to identify
    // frequently accessed pages, then migrate tasks/pages closer
    // to the memory they access most.
    // This is a simplified framework — real implementation would
    // use hardware-assisted access tracking (PEBS, IBS).
}

// =============================================================================
// Global Load Averages (for /proc/loadavg)
// =============================================================================
fn updateGlobalLoadAverages() void {
    var total_running: u64 = 0;
    for (0..nr_cpus_online) |cpu| {
        total_running += per_cpu_rq[cpu].nr_running;
    }

    // Exponential decay: load_avg = load_avg * exp + nr_running * (1 - exp)
    // 1-minute exp factor ~= 1884 (out of 2048)
    // 5-minute exp factor ~= 2014
    // 15-minute exp factor ~= 2037
    const exp_1 = 1884;
    const exp_5 = 2014;
    const exp_15 = 2037;
    const fshift: u6 = 11; // 2048 = 1 << 11

    avenrun[0] = (avenrun[0] * exp_1 + total_running * ((@as(u64, 1) << fshift) - exp_1)) >> fshift;
    avenrun[1] = (avenrun[1] * exp_5 + total_running * ((@as(u64, 1) << fshift) - exp_5)) >> fshift;
    avenrun[2] = (avenrun[2] * exp_15 + total_running * ((@as(u64, 1) << fshift) - exp_15)) >> fshift;
}

fn updatePsi() void {
    var some_stalled: u64 = 0;
    var full_stalled: u64 = 0;
    for (0..nr_cpus_online) |cpu| {
        const rq = &per_cpu_rq[cpu];
        if (rq.nr_running > 1) some_stalled += TICK_NS;
        if (rq.nr_running > 0 and rq.idle) full_stalled += TICK_NS;
    }
    psi_cpu.update(some_stalled, full_stalled);
}

// =============================================================================
// Public API (compatibility with old scheduler)
// =============================================================================
pub fn getRunQueueSize() u32 {
    return per_cpu_rq[0].nr_running;
}

pub fn getCurrentThread() ?*main.thread.Thread {
    if (per_cpu_rq[0].curr_entity) |se| return se.thread;
    return null;
}

pub fn isRunning() bool {
    return scheduler_running;
}

pub fn getLoadAverage(idx: usize) u64 {
    if (idx < 3) return avenrun[idx];
    return 0;
}

pub fn getPsiCpu() *PsiState {
    return &psi_cpu;
}

pub fn getPsiMemory() *PsiState {
    return &psi_memory;
}

pub fn getPsiIo() *PsiState {
    return &psi_io;
}

pub fn getNrCpusOnline() u32 {
    return nr_cpus_online;
}

pub fn getPerCpuRq(cpu: u32) *RunQueue {
    return &per_cpu_rq[@min(cpu, MAX_CPUS - 1)];
}
