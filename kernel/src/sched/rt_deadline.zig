// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced Scheduler: Real-Time, Deadline, EAS, PSI, Load Balancing
// Linux 6.x compatible with Zxyphor enhancements

const std = @import("std");

// ============================================================================
// Scheduling Classes and Priorities
// ============================================================================

pub const SchedPolicy = enum(u32) {
    normal = 0,      // SCHED_NORMAL (CFS/EEVDF)
    fifo = 1,        // SCHED_FIFO
    rr = 2,          // SCHED_RR
    batch = 3,       // SCHED_BATCH
    idle = 5,        // SCHED_IDLE
    deadline = 6,    // SCHED_DEADLINE
    // Zxyphor extensions
    zxy_latency = 7,   // Ultra-low latency
    zxy_adaptive = 8,  // ML-guided adaptive
    zxy_realtime_safe = 9, // Guaranteed RT with admission control
};

pub const MAX_NICE: i32 = 19;
pub const MIN_NICE: i32 = -20;
pub const MAX_RT_PRIO: u32 = 100;
pub const MAX_PRIO: u32 = 140;
pub const DEFAULT_PRIO: u32 = 120;
pub const NICE_WIDTH: u32 = 40;

pub fn nice_to_prio(nice: i32) u32 {
    return @intCast(@as(i32, @intCast(DEFAULT_PRIO)) + nice);
}

pub fn prio_to_nice(prio: u32) i32 {
    return @as(i32, @intCast(prio)) - @as(i32, @intCast(DEFAULT_PRIO));
}

// ============================================================================
// EEVDF (Earliest Eligible Virtual Deadline First)
// ============================================================================

pub const EEVDF_SLICE_MIN_NS: u64 = 750_000;       // 0.75ms
pub const EEVDF_SLICE_DEFAULT_NS: u64 = 3_000_000;  // 3ms
pub const EEVDF_SLICE_MAX_NS: u64 = 24_000_000;     // 24ms
pub const EEVDF_LATENCY_NS: u64 = 12_000_000;       // 12ms target latency

// EEVDF Task Entity
pub const EevdfEntity = struct {
    // Virtual runtime tracking
    vruntime: u64,
    min_vruntime: u64,
    // Virtual deadline for EEVDF
    deadline: u64,
    // Slice parameters
    slice: u64,
    // Weight (from nice value)
    weight: u32,
    inv_weight: u32,
    // Run statistics
    sum_exec_runtime: u64,
    prev_sum_exec_runtime: u64,
    nr_migrations: u64,
    // Load tracking
    load_avg: u64,
    runnable_avg: u64,
    util_avg: u64,
    load_sum: u64,
    runnable_sum: u64,
    util_sum: u64,
    util_est: UtilEst,
    // Hierarchy
    depth: u32,
    on_rq: bool,
    lag: i64,

    pub fn calc_delta_fair(self: *const EevdfEntity, delta: u64) u64 {
        if (self.weight == NICE_0_WEIGHT) return delta;
        return delta * NICE_0_WEIGHT / self.weight;
    }

    pub fn update_deadline(self: *EevdfEntity, now: u64) void {
        if (now >= self.deadline) {
            self.deadline = now + self.slice;
        }
    }

    pub fn eligible(self: *const EevdfEntity, min_vruntime: u64) bool {
        return self.vruntime <= min_vruntime + self.lag_bound();
    }

    fn lag_bound(self: *const EevdfEntity) u64 {
        return self.slice;
    }
};

pub const UtilEst = struct {
    enqueued: u32,
    ewma: u32,
};

// Nice-to-weight table (Linux prio_to_weight)
pub const NICE_0_WEIGHT: u32 = 1024;

pub const sched_prio_to_weight = [40]u32{
    88761, 71755, 56483, 46273, 36291,
    29154, 23254, 18705, 14949, 11916,
    9548,  7620,  6100,  4904,  3906,
    3121,  2501,  1991,  1586,  1277,
    1024,  820,   655,   526,   423,
    335,   272,   215,   172,   137,
    110,   87,    70,    56,    45,
    36,    29,    23,    18,    15,
};

pub const sched_prio_to_wmult = [40]u32{
    48388,  59856,  76040,  92818,  118348,
    147320, 184698, 229616, 287308, 360437,
    449829, 563644, 704093, 875809, 1099582,
    1376151, 1717300, 2157191, 2708050, 3363326,
    4194304, 5237765, 6557202, 8165337, 10153587,
    12820798, 15790321, 19976592, 24970740, 31350126,
    39045157, 49367440, 61356676, 76695844, 95443717,
    119304647, 148102320, 186737708, 238609294, 286331153,
};

// ============================================================================
// CFS Run Queue
// ============================================================================

pub const CfsRq = struct {
    // RB-tree of runnable entities (sorted by vruntime)
    nr_running: u32,
    h_nr_running: u32,     // Hierarchical count
    idle_nr_running: u32,
    // Time accounting
    exec_clock: u64,
    min_vruntime: u64,
    // Load tracking
    load: LoadWeight,
    avg: SchedAvg,
    // EEVDF
    nr_queued: u32,
    // Bandwidth
    runtime_enabled: bool,
    runtime_remaining: i64,
    runtime_expires: u64,
    // Throttling
    throttled: bool,
    throttle_count: u32,
    throttled_clock: u64,
    throttled_clock_pelt: u64,
    // Propagation
    propagate: bool,
    prop_runnable_sum: i64,
    // NUMA
    nr_numa_running: u32,
    nr_preferred_running: u32,
    // Idle
    idle_h_nr_running: u32,

    pub fn update_min_vruntime(self: *CfsRq) void {
        // Track minimum vruntime for entity placement
        // In real implementation, this would walk the leftmost RB-tree node
    }

    pub fn pick_eevdf(self: *CfsRq) ?*EevdfEntity {
        // Pick the entity with the earliest eligible virtual deadline
        _ = self;
        return null;
    }
};

pub const LoadWeight = struct {
    weight: u64,
    inv_weight: u32,
};

pub const SchedAvg = struct {
    last_update_time: u64,
    load_sum: u64,
    runnable_sum: u64,
    util_sum: u64,
    period_contrib: u32,
    load_avg: u64,
    runnable_avg: u64,
    util_avg: u64,
    util_est: UtilEst,
};

// ============================================================================
// Real-Time Scheduling
// ============================================================================

pub const RtRq = struct {
    // Bitmap of active RT priorities
    active_bitmap: [4]u64,  // 256 bits for MAX_RT_PRIO priorities
    nr_running: u32,
    // Bandwidth
    rt_time: u64,
    rt_runtime: u64,       // Per-period allowance
    rt_period: u64,
    rt_throttled: bool,
    // Statistics
    pushable_tasks: u32,
    overloaded: bool,

    pub fn init() RtRq {
        return RtRq{
            .active_bitmap = [_]u64{0} ** 4,
            .nr_running = 0,
            .rt_time = 0,
            .rt_runtime = 950_000_000, // 950ms per 1s period
            .rt_period = 1_000_000_000,
            .rt_throttled = false,
            .pushable_tasks = 0,
            .overloaded = false,
        };
    }

    pub fn highest_prio(self: *const RtRq) ?u8 {
        for (self.active_bitmap, 0..) |word, word_idx| {
            if (word != 0) {
                const bit = @ctz(word);
                return @intCast(word_idx * 64 + bit);
            }
        }
        return null;
    }

    pub fn set_prio_active(self: *RtRq, prio: u8) void {
        const word_idx = prio / 64;
        const bit_idx: u6 = @intCast(prio % 64);
        self.active_bitmap[word_idx] |= @as(u64, 1) << bit_idx;
    }

    pub fn clear_prio_active(self: *RtRq, prio: u8) void {
        const word_idx = prio / 64;
        const bit_idx: u6 = @intCast(prio % 64);
        self.active_bitmap[word_idx] &= ~(@as(u64, 1) << bit_idx);
    }
};

// ============================================================================
// Deadline Scheduling (SCHED_DEADLINE)
// ============================================================================

pub const DlRq = struct {
    nr_running: u32,
    // Earliest deadline (RB-tree root)
    earliest_dl_time: u64,
    // Bandwidth
    bw: DlBandwidth,
    // Pushable/pullable
    pushable_dl_tasks_nr: u32,
    overloaded: bool,
    // Statistics
    dl_nr_migratory: u32,

    pub fn init() DlRq {
        return DlRq{
            .nr_running = 0,
            .earliest_dl_time = 0,
            .bw = DlBandwidth.init(),
            .pushable_dl_tasks_nr = 0,
            .overloaded = false,
            .dl_nr_migratory = 0,
        };
    }
};

pub const DlBandwidth = struct {
    dl_period: u64,
    dl_runtime: u64,
    dl_bw: u64,
    total_bw: u64,

    pub fn init() DlBandwidth {
        return DlBandwidth{
            .dl_period = 1_000_000_000,
            .dl_runtime = 0,
            .dl_bw = 0,
            .total_bw = 0,
        };
    }

    pub fn check_admission(self: *const DlBandwidth, new_bw: u64) bool {
        // CBS admission test: sum(runtime/period) <= total_bw
        return (self.total_bw + new_bw) <= self.dl_bw;
    }
};

pub const DlEntity = struct {
    // Deadline parameters (set by sched_setattr)
    dl_runtime: u64,      // Maximum execution time per period
    dl_deadline: u64,      // Relative deadline
    dl_period: u64,        // Period
    dl_bw: u64,           // Bandwidth (dl_runtime/dl_period)
    dl_density: u64,      // dl_runtime/dl_deadline
    // Current absolute deadline
    deadline: u64,
    // Remaining runtime in current period
    runtime: u64,
    // CBS fields
    dl_throttled: bool,
    dl_boosted: bool,
    dl_yielded: bool,
    dl_non_contending: bool,
    dl_overrun: bool,
    // Timer
    dl_timer_active: bool,
    dl_timer_period: u64,
    // GRUB reclamation
    dl_reclaim: bool,

    pub fn init(runtime: u64, deadline: u64, period: u64) DlEntity {
        return DlEntity{
            .dl_runtime = runtime,
            .dl_deadline = deadline,
            .dl_period = period,
            .dl_bw = if (period > 0) (runtime << 20) / period else 0,
            .dl_density = if (deadline > 0) (runtime << 20) / deadline else 0,
            .deadline = 0,
            .runtime = runtime,
            .dl_throttled = false,
            .dl_boosted = false,
            .dl_yielded = false,
            .dl_non_contending = false,
            .dl_overrun = false,
            .dl_timer_active = false,
            .dl_timer_period = period,
            .dl_reclaim = false,
        };
    }

    pub fn replenish(self: *DlEntity, now: u64) void {
        self.deadline = now + self.dl_deadline;
        self.runtime = self.dl_runtime;
        self.dl_throttled = false;
        self.dl_overrun = false;
    }

    pub fn update_runtime(self: *DlEntity, delta: u64) void {
        if (delta >= self.runtime) {
            self.runtime = 0;
            self.dl_throttled = true;
        } else {
            self.runtime -= delta;
        }
    }
};

// ============================================================================
// Per-CPU Run Queue
// ============================================================================

pub const MAX_CPUS: usize = 256;

pub const RunQueue = struct {
    // Active task
    nr_running: u32,
    nr_switches: u64,
    // Per-class run queues
    cfs: CfsRq,
    rt: RtRq,
    dl: DlRq,
    // Clock
    clock: u64,
    clock_task: u64,
    clock_pelt: u64,
    // CPU info
    cpu: u32,
    online: bool,
    idle_stamp: u64,
    avg_idle: u64,
    max_idle_balance_cost: u64,
    // Preemption
    skip_clock_update: bool,
    nr_uninterruptible: i32,
    // Load
    cpu_load: [5]u64,
    calc_load_update: u64,
    calc_load_active: u64,
    // Push/pull
    active_balance: bool,
    push_cpu: u32,
    migration_thread: ?*anyopaque,
    // IPI
    nohz_flags: u32,
    // NUMA balancing
    nr_numa_running: u32,
    nr_preferred_running: u32,
    numa_migrate_on: u32,
    // Core scheduling
    core_enabled: bool,
    core_pick: ?*anyopaque,
    core_cookie: u64,
    // Thermal pressure
    thermal_pressure: u64,

    pub fn init(cpu: u32) RunQueue {
        return RunQueue{
            .nr_running = 0,
            .nr_switches = 0,
            .cfs = std.mem.zeroes(CfsRq),
            .rt = RtRq.init(),
            .dl = DlRq.init(),
            .clock = 0,
            .clock_task = 0,
            .clock_pelt = 0,
            .cpu = cpu,
            .online = true,
            .idle_stamp = 0,
            .avg_idle = 0,
            .max_idle_balance_cost = 500_000, // 500us
            .skip_clock_update = false,
            .nr_uninterruptible = 0,
            .cpu_load = [_]u64{0} ** 5,
            .calc_load_update = 0,
            .calc_load_active = 0,
            .active_balance = false,
            .push_cpu = 0,
            .migration_thread = null,
            .nohz_flags = 0,
            .nr_numa_running = 0,
            .nr_preferred_running = 0,
            .numa_migrate_on = 0,
            .core_enabled = false,
            .core_pick = null,
            .core_cookie = 0,
            .thermal_pressure = 0,
        };
    }
};

// ============================================================================
// Scheduler Domains (Topology-aware load balancing)
// ============================================================================

pub const SchedDomainLevel = enum(u8) {
    smt = 0,       // Hyper-threading siblings
    mc = 1,        // Multi-core (same physical package)
    die = 2,       // Same die in multi-die package
    numa = 3,      // Same NUMA node
    numa2 = 4,     // 2 NUMA hops
    numa3 = 5,     // 3 NUMA hops
    system = 6,    // Entire system
};

pub const SchedDomainFlags = packed struct(u32) {
    load_balance: bool = true,
    balance_newidle: bool = true,
    balance_exec: bool = true,
    balance_fork: bool = true,
    balance_wake: bool = true,
    wake_affine: bool = true,
    asym_cpucapacity: bool = false,
    asym_cpucapacity_full: bool = false,
    share_cpucapacity: bool = false,
    share_pkg_resources: bool = false,
    serialize: bool = false,
    asym_packing: bool = false,
    prefer_sibling: bool = false,
    overlap: bool = false,
    numa: bool = false,
    _reserved: u17 = 0,
};

pub const SchedDomain = struct {
    level: SchedDomainLevel,
    flags: SchedDomainFlags,
    span: [MAX_CPUS / 64]u64, // CPU mask
    min_interval: u32,
    max_interval: u32,
    busy_factor: u32,
    imbalance_pct: u32,
    cache_nice_tries: u32,
    nohz_idle: u32,
    // Load balancing stats
    lb_count: [4]u64,  // Per-idle type
    lb_failed: [4]u64,
    lb_balanced: [4]u64,
    lb_imbalance: [4]u64,
    lb_gained: [4]u64,
    lb_hot_gained: [4]u64,
    lb_nobusyq: [4]u64,
    lb_nobusyg: [4]u64,
    // Balancing periods
    balance_interval: u32,
    nr_balance_failed: u32,
    max_newidle_lb_cost: u64,
    last_decay_max_lb_cost: u64,
    // Hierarchy
    child: ?*SchedDomain,
    parent: ?*SchedDomain,
    groups: ?*SchedGroup,

    pub fn cpu_in_span(self: *const SchedDomain, cpu: u32) bool {
        const word = cpu / 64;
        const bit: u6 = @intCast(cpu % 64);
        return (self.span[word] & (@as(u64, 1) << bit)) != 0;
    }
};

pub const SchedGroup = struct {
    cpumask: [MAX_CPUS / 64]u64,
    group_weight: u32,
    sgc: SchedGroupCapacity,
    next: ?*SchedGroup,
};

pub const SchedGroupCapacity = struct {
    capacity: u64,
    min_capacity: u64,
    max_capacity: u64,
    imbalance: u64,
    nr_running: u32,
};

// ============================================================================
// Load Balancing
// ============================================================================

pub const LoadBalanceType = enum(u8) {
    cpu_idle = 0,
    cpu_newly_idle = 1,
    cpu_not_idle = 2,
    cpu_active = 3,
};

pub const GroupType = enum(u8) {
    has_spare = 0,
    fully_busy = 1,
    misfit_task = 2,
    asym_packing = 3,
    imbalanced = 4,
    overloaded = 5,
};

pub const LoadBalanceStats = struct {
    avg_load: u64,
    group_load: u64,
    group_capacity: u64,
    group_util: u64,
    group_runnable: u64,
    sum_nr_running: u32,
    nr_numa_running: u32,
    nr_preferred_running: u32,
    group_type: GroupType,
    group_weight: u32,
    idle_cpus: u32,
    group_misfit_task_load: u64,
};

pub const LoadBalanceEnv = struct {
    sd: *SchedDomain,
    dst_cpu: u32,
    dst_rq: *RunQueue,
    src_cpu: u32,
    src_rq: *RunQueue,
    idle: LoadBalanceType,
    imbalance: u64,
    migration_type: MigrationType,
    flags: u32,
    loop_count: u32,
    loop_max: u32,
    busiest_nr_running: u32,

    pub fn need_active_balance(self: *const LoadBalanceEnv) bool {
        if (self.idle != .cpu_not_idle) return false;
        if (self.src_rq.nr_running <= 1) return false;
        return self.sd.nr_balance_failed > self.sd.cache_nice_tries + 2;
    }
};

pub const MigrationType = enum(u8) {
    load = 0,
    util = 1,
    task = 2,
    misfit = 3,
};

// ============================================================================
// Energy Aware Scheduling (EAS)
// ============================================================================

pub const MAX_CAPACITY: u64 = 1024;

pub const CapacityState = struct {
    cap: u64,       // CPU capacity at this OPP
    freq: u32,      // Frequency in KHz
    power: u32,     // Power consumption in mW
};

pub const EnergyModel = struct {
    nr_perf_states: u32,
    perf_states: [32]CapacityState,
    cpus: [MAX_CPUS / 64]u64,
    nr_cpus: u32,
    // Cost Table
    table: [32]EmPerfState,
    // Flags
    flags: u32,
    default_cost: u64,

    pub fn get_cost(self: *const EnergyModel, util: u64) u64 {
        var i: u32 = 0;
        while (i < self.nr_perf_states) : (i += 1) {
            if (util <= self.perf_states[i].cap) {
                return self.table[i].cost;
            }
        }
        if (self.nr_perf_states > 0) {
            return self.table[self.nr_perf_states - 1].cost;
        }
        return self.default_cost;
    }

    pub fn max_capacity(self: *const EnergyModel) u64 {
        if (self.nr_perf_states > 0) {
            return self.perf_states[self.nr_perf_states - 1].cap;
        }
        return MAX_CAPACITY;
    }
};

pub const EmPerfState = struct {
    frequency: u64,
    power: u64,
    cost: u64,
    flags: u32,
};

// EAS - Energy computation for task placement
pub const EasData = struct {
    em_perf_domain: [16]*EnergyModel,
    nr_perf_domains: u32,
    overutilized: bool,

    pub fn compute_energy(self: *const EasData, cpu: u32, util_delta: u64) u64 {
        _ = cpu;
        var total_energy: u64 = 0;
        var i: u32 = 0;
        while (i < self.nr_perf_domains) : (i += 1) {
            const em = self.em_perf_domain[i];
            total_energy += em.get_cost(util_delta);
        }
        return total_energy;
    }

    pub fn find_energy_efficient_cpu(self: *const EasData, util: u64) ?u32 {
        var best_cpu: ?u32 = null;
        var min_energy: u64 = std.math.maxInt(u64);

        var cpu: u32 = 0;
        while (cpu < MAX_CPUS) : (cpu += 1) {
            const energy = self.compute_energy(cpu, util);
            if (energy < min_energy) {
                min_energy = energy;
                best_cpu = cpu;
            }
        }
        return best_cpu;
    }
};

// ============================================================================
// Pressure Stall Information (PSI)
// ============================================================================

pub const PsiResource = enum(u8) {
    io = 0,
    memory = 1,
    cpu = 2,
    irq = 3,
};

pub const PsiState = enum(u8) {
    none = 0,
    some = 1,
    full = 2,
};

pub const PsiGroupCpu = struct {
    // Per-CPU state tracking
    state_mask: u32,
    times: [4][3]u64, // [resource][state] = cumulative time
    state_start: u64,
    // Tasks in stall states
    tasks: [4]u32, // Count per resource
};

pub const PsiGroup = struct {
    pcpu: [MAX_CPUS]PsiGroupCpu,
    // Aggregated
    total: [4][3]u64, // [resource][some/full/none]
    avg: [4][3]u64,   // 10s/60s/300s averages per resource
    avg_last_update: u64,
    avg_next_update: u64,
    // Triggers
    triggers: [16]PsiTrigger,
    nr_triggers: u32,

    pub fn update_averages(self: *PsiGroup, now: u64) void {
        if (now < self.avg_next_update) return;
        // PELT-style decay of averages
        const elapsed = now - self.avg_last_update;
        if (elapsed == 0) return;
        self.avg_last_update = now;
        self.avg_next_update = now + 2_000_000_000; // 2s
    }

    pub fn get_some_pct(self: *const PsiGroup, resource: PsiResource, window: u8) u64 {
        return self.avg[@intFromEnum(resource)][window];
    }

    pub fn get_full_pct(self: *const PsiGroup, resource: PsiResource, window: u8) u64 {
        return self.avg[@intFromEnum(resource)][window];
    }
};

pub const PsiTrigger = struct {
    state: PsiState,
    threshold: u64,    // Threshold in microseconds
    window: u64,       // Window in microseconds
    last_event_time: u64,
    event_count: u64,
};

// ============================================================================
// CPU Frequency Scaling (CPUFreq)
// ============================================================================

pub const CpufreqGovernor = enum(u8) {
    performance = 0,
    powersave = 1,
    userspace = 2,
    ondemand = 3,
    conservative = 4,
    schedutil = 5,
    // Zxyphor extensions
    zxy_ml_governor = 200,
    zxy_latency_governor = 201,
};

pub const CpufreqPolicy = struct {
    cpu: u32,
    cpus: [MAX_CPUS / 64]u64,
    min: u32,            // Min frequency in KHz
    max: u32,            // Max frequency in KHz
    cur: u32,            // Current frequency in KHz
    governor: CpufreqGovernor,
    // Frequency table
    freq_table: [64]CpufreqEntry,
    nr_freqs: u32,
    // Transition stats
    total_trans: u32,
    last_stat_time: u64,
    // schedutil integration
    last_freq_update_time: u64,
    transition_delay_us: u32,
    // Fast switch
    fast_switch_possible: bool,
    fast_switch_enabled: bool,

    pub fn get_next_freq(self: *const CpufreqPolicy, util: u64, max: u64) u32 {
        if (max == 0) return self.min;
        var target = (util * @as(u64, self.max)) / max;
        // Add headroom (1.25x)
        target = target + target / 4;
        if (target > self.max) return self.max;
        if (target < self.min) return self.min;
        return @intCast(target);
    }
};

pub const CpufreqEntry = struct {
    frequency: u32,  // KHz
    driver_data: u32,
    flags: u32,
};

// ============================================================================
// CPU Idle (cpuidle)
// ============================================================================

pub const CpuidleState = struct {
    name: [16]u8,
    desc: [32]u8,
    exit_latency_ns: u64,
    target_residency_ns: u64,
    power_usage: i32,
    flags: u32,
    disabled: bool,
    // Stats
    usage: u64,
    time: u64,
    above: u64,
    below: u64,
    rejected: u64,
    s2idle_usage: u64,
    s2idle_time: u64,
};

pub const CpuidleDevice = struct {
    enabled: bool,
    cpu: u32,
    last_state_idx: i32,
    last_residency_ns: u64,
    states_usage: [10]CpuidleStateUsage,
    state_count: u32,
    states: [10]CpuidleState,

    pub fn select_state(self: *const CpuidleDevice, predicted_ns: u64) i32 {
        var best_idx: i32 = -1;
        var best_residency: u64 = 0;

        var i: u32 = 0;
        while (i < self.state_count) : (i += 1) {
            if (self.states[i].disabled) continue;
            if (self.states[i].target_residency_ns > predicted_ns) continue;
            if (self.states[i].target_residency_ns > best_residency) {
                best_residency = self.states[i].target_residency_ns;
                best_idx = @intCast(i);
            }
        }
        return best_idx;
    }
};

pub const CpuidleStateUsage = struct {
    disable: u32,
    usage: u64,
    time_ns: u64,
    above: u64,
    below: u64,
    rejected: u64,
};

// ============================================================================
// NOHZ / Tick Management
// ============================================================================

pub const TickDep = enum(u8) {
    none = 0,
    posix_timer = 1,
    perf_events = 2,
    sched = 3,
    clock_unstable = 4,
    rcu = 5,
};

pub const NohzMode = enum(u8) {
    inactive = 0,
    low_res = 1,
    high_res = 2,
};

pub const TickSchedState = struct {
    mode: NohzMode,
    idle_active: bool,
    idle_entrytime: u64,
    idle_waketime: u64,
    idle_exittime: u64,
    idle_sleeptime: u64,
    iowait_sleeptime: u64,
    last_jiffies: u64,
    next_tick: u64,
    idle_expires: u64,
    idle_calls: u64,
    idle_sleeps: u64,
    tick_stopped: bool,
    do_timer_last: bool,
    got_idle_tick: bool,
};

// ============================================================================
// Bandwidth Control (CFS Bandwidth)
// ============================================================================

pub const CfsBandwidth = struct {
    period: u64,          // Period in ns
    quota: i64,           // Quota in ns (-1 for unlimited)
    runtime: i64,         // Remaining runtime
    burst: u64,           // Burst capacity
    runtime_snap: i64,    // Snapshot for reporting
    hierarchical_quota: i64,
    idle: bool,
    period_active: bool,
    nr_periods: u32,
    nr_throttled: u32,
    throttled_time: u64,
    nr_burst: u32,
    burst_time: u64,

    pub fn init(period: u64, quota: i64) CfsBandwidth {
        return CfsBandwidth{
            .period = period,
            .quota = quota,
            .runtime = quota,
            .burst = 0,
            .runtime_snap = 0,
            .hierarchical_quota = quota,
            .idle = true,
            .period_active = false,
            .nr_periods = 0,
            .nr_throttled = 0,
            .throttled_time = 0,
            .nr_burst = 0,
            .burst_time = 0,
        };
    }

    pub fn runtime_enabled(self: *const CfsBandwidth) bool {
        return self.quota >= 0;
    }

    pub fn start_period(self: *CfsBandwidth) void {
        self.runtime = self.quota;
        self.nr_periods += 1;
        self.period_active = true;
        self.idle = false;
    }

    pub fn account_runtime(self: *CfsBandwidth, delta: u64) bool {
        if (self.quota < 0) return true; // Unlimited
        self.runtime -= @intCast(delta);
        if (self.runtime <= 0) {
            self.nr_throttled += 1;
            return false; // Throttled
        }
        return true;
    }
};

// ============================================================================
// Utilization Clamping (uclamp)
// ============================================================================

pub const UCLAMP_MIN: u32 = 0;
pub const UCLAMP_MAX: u32 = 1;
pub const UCLAMP_CNT: u32 = 2;
pub const UCLAMP_BUCKET_CNT: u32 = 20;

pub const UclampValue = struct {
    value: u32,        // Percentage (0-1024)
    bucket_id: u8,
    user_defined: bool,
};

pub const UclampBucket = struct {
    value: u32,
    tasks: u32,
};

pub const UclampGroup = struct {
    buckets: [UCLAMP_BUCKET_CNT]UclampBucket,
};

pub const UclampRq = struct {
    groups: [UCLAMP_CNT]UclampGroup,

    pub fn init() UclampRq {
        return std.mem.zeroes(UclampRq);
    }

    pub fn effective_value(self: *const UclampRq, clamp_id: u32) u32 {
        const group = &self.groups[clamp_id];
        var max_val: u32 = 0;
        for (&group.buckets) |*bucket| {
            if (bucket.tasks > 0 and bucket.value > max_val) {
                max_val = bucket.value;
            }
        }
        return max_val;
    }
};

// ============================================================================
// Core Scheduling (for SMT security)
// ============================================================================

pub const CoreSchedCookie = struct {
    cookie: u64,
    refcount: u32,

    pub fn is_idle(self: *const CoreSchedCookie) bool {
        return self.cookie == 0;
    }

    pub fn compatible(self: *const CoreSchedCookie, other: *const CoreSchedCookie) bool {
        // Tasks with same cookie (or both idle) can share a core
        return self.cookie == other.cookie;
    }
};

// ============================================================================
// NUMA Balancing
// ============================================================================

pub const NumaStats = struct {
    nr_numa_faults: [64]u64,     // Per-node fault counts
    preferred_nid: i32,
    total_numa_faults: u64,
    numa_faults_locality: [3]u64, // local, remote, all
    numa_pages_migrated: u64,
    best_cpu: u32,
    last_task_numa_placement: u64,
    last_sum_exec_runtime: u64,
    numa_scan_seq: u32,
    numa_scan_period: u32,
    numa_scan_period_max: u32,
    numa_preferred_nid: i32,
    numa_migrate_retry: u64,
    numa_next_scan: u64,
    numa_next_reset: u64,
};

pub const NumaGroup = struct {
    refcount: u32,
    nr_tasks: u32,
    gid: u32,
    max_faults_cpu: u64,
    active_nodes: u32,
    faults: [64]u64,
    faults_cpu: [64]u64,
    total_faults: u64,

    pub fn preferred_nid(self: *const NumaGroup) i32 {
        var max_faults: u64 = 0;
        var best_nid: i32 = -1;
        for (self.faults, 0..) |faults, nid| {
            if (faults > max_faults) {
                max_faults = faults;
                best_nid = @intCast(nid);
            }
        }
        return best_nid;
    }
};

// ============================================================================
// Scheduler Statistics
// ============================================================================

pub const SchedStatistics = struct {
    // wait/run/iowait
    wait_start: u64,
    wait_max: u64,
    wait_count: u64,
    wait_sum: u64,
    run_delay: u64,
    // Sleep
    sleep_start: u64,
    sleep_max: u64,
    sum_sleep_runtime: u64,
    block_start: u64,
    block_max: u64,
    // Execution
    exec_max: u64,
    slice_max: u64,
    // NUMA
    nr_migrations_cold: u64,
    nr_failed_migrations_affine: u64,
    nr_failed_migrations_running: u64,
    nr_failed_migrations_hot: u64,
    nr_forced_migrations: u64,
    nr_wakeups: u64,
    nr_wakeups_sync: u64,
    nr_wakeups_migrate: u64,
    nr_wakeups_local: u64,
    nr_wakeups_remote: u64,
    nr_wakeups_affine: u64,
    nr_wakeups_affine_attempts: u64,
    nr_wakeups_passive: u64,
    nr_wakeups_idle: u64,
    // Latency
    core_forceidle_sum: u64,
};

// ============================================================================
// Autogroup
// ============================================================================

pub const AutogroupInfo = struct {
    id: u64,
    nice: i32,
    nr_members: u32,
    shares: u64,
};
