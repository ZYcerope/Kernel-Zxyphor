// Zxyphor Kernel - CFS (Completely Fair Scheduler) Internals
// Red-black tree scheduling, vruntime calculation
// Load weight tables, EEVDF (Earliest Eligible Virtual Deadline First)
// Bandwidth throttling, CPU frequency scaling integration
// sched_ext (extensible scheduler) BPF hooks
// Core scheduling for SMT security
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Scheduler Priority & Policy Constants
// ============================================================================

pub const NICE_MIN: i32 = -20;
pub const NICE_MAX: i32 = 19;
pub const NICE_WIDTH: u32 = 40;
pub const MAX_RT_PRIO: u32 = 100;
pub const MAX_PRIO: u32 = 140;
pub const DEFAULT_PRIO: u32 = 120;
pub const MAX_DL_PRIO: u32 = 0;

pub const SchedPolicy = enum(u32) {
    normal = 0,
    fifo = 1,
    rr = 2,
    batch = 3,
    iso = 4,    // reserved
    idle = 5,
    deadline = 6,
    ext = 7,    // sched_ext
};

pub const SchedFlags = packed struct(u64) {
    reset_on_fork: bool = false,
    reclaim: bool = false,
    dl_overrun: bool = false,
    keep_policy: bool = false,
    keep_params: bool = false,
    keep_all: bool = false,
    util_clamp: bool = false,
    util_clamp_min: bool = false,
    util_clamp_max: bool = false,
    _pad: u55 = 0,
};

// ============================================================================
// Load Weight Table (nice-to-weight conversion)
// ============================================================================

pub const SCHED_LOAD_SHIFT: u32 = 10;
pub const SCHED_LOAD_SCALE: u64 = 1 << SCHED_LOAD_SHIFT;

/// Precomputed weight table for nice values -20 to +19
/// Weight doubles (roughly) for each nice level decrease
pub const NICE_TO_WEIGHT: [40]u64 = .{
    88761, 71755, 56483, 46273, 36291,  // nice -20..-16
    29154, 23254, 18705, 14949, 11916,  // nice -15..-11
    9548,  7620,  6100,  4904,  3906,   // nice -10..-6
    3121,  2501,  1991,  1586,  1277,   // nice -5..-1
    1024,  820,   655,   526,   423,    // nice 0..4
    335,   272,   215,   172,   137,    // nice 5..9
    110,   87,    70,    56,    45,     // nice 10..14
    36,    29,    23,    18,    15,     // nice 15..19
};

/// Inverse weight table for O(1) vruntime calculation
pub const NICE_TO_WMULT: [40]u64 = .{
    48388,     59856,     76040,     92818,     118348,
    147320,    184698,    229616,    287308,    360437,
    449829,    563644,    704093,    875809,    1099582,
    1376151,   1717300,   2157191,   2708050,   3363326,
    4194304,   5237765,   6557202,   8165337,   10153587,
    12820798,  15790321,  19976592,  24970740,  31350126,
    39045157,  49367440,  61356676,  76695844,  95443717,
    119304647, 148102320, 186737708, 238609294, 286331153,
};

pub const LoadWeight = struct {
    weight: u64,
    inv_weight: u64,
};

// ============================================================================
// Scheduling Entity (CFS)
// ============================================================================

pub const SchedEntity = struct {
    load: LoadWeight,
    run_node: RBNode,     // red-black tree node
    on_rq: bool,
    exec_start: u64,      // nanoseconds
    sum_exec_runtime: u64,
    prev_sum_exec_runtime: u64,
    vruntime: u64,
    vdeadline: u64,       // EEVDF deadline
    slice: u64,           // requested time slice
    nr_migrations: u64,
    depth: u32,
    parent: ?*SchedEntity,
    cfs_rq: ?*CfsRunqueue,
    my_q: ?*CfsRunqueue,  // for group scheduling
    // PELT (Per-Entity Load Tracking)
    avg: SchedAvg,
    // Statistics
    statistics: SchedStatistics,
};

pub const RBNode = struct {
    parent_color: u64,
    left: ?*RBNode,
    right: ?*RBNode,
};

pub const RBRoot = struct {
    rb_node: ?*RBNode,
};

pub const RBRootCached = struct {
    rb_root: RBRoot,
    rb_leftmost: ?*RBNode,
};

// ============================================================================
// PELT (Per-Entity Load Tracking)
// ============================================================================

pub const PELT_LOAD_AVG_MAX: u64 = 47742;
pub const PELT_UTIL_AVG_MAX: u64 = 1024;

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

pub const UtilEst = struct {
    enqueued: u32,
    ewma: u32,
};

// ============================================================================
// CFS Run Queue
// ============================================================================

pub const CfsRunqueue = struct {
    load: LoadWeight,
    nr_running: u32,
    h_nr_running: u32, // hierarchical count
    exec_clock: u64,   // nanoseconds
    min_vruntime: u64,
    min_vruntime_fi: u64,
    // RB-tree
    tasks_timeline: RBRootCached,
    curr: ?*SchedEntity,
    next: ?*SchedEntity,
    last: ?*SchedEntity,
    skip: ?*SchedEntity,
    // Statistics
    nr_spread_over: u32,
    nr_wakeups: u64,
    nr_wakeups_sync: u64,
    nr_wakeups_migrate: u64,
    nr_wakeups_local: u64,
    nr_wakeups_remote: u64,
    nr_wakeups_affine: u64,
    nr_wakeups_affine_attempts: u64,
    nr_wakeups_passive: u64,
    nr_wakeups_idle: u64,
    // PELT
    avg: SchedAvg,
    // Throttling
    throttled: bool,
    throttle_count: u32,
    throttled_clock: u64,
    throttled_clock_task: u64,
    throttled_clock_task_time: u64,
    runtime_remaining: i64,
    runtime_enabled: bool,
    // Level
    on_list: bool,
    tg: ?*TaskGroup,
    rq: ?*Runqueue,
    idle_nr_running: u32,
    idle_h_nr_running: u32,
};

// ============================================================================
// Scheduling Statistics
// ============================================================================

pub const SchedStatistics = struct {
    wait_start: u64,
    wait_max: u64,
    wait_count: u64,
    wait_sum: u64,
    iowait_count: u64,
    iowait_sum: u64,
    sleep_start: u64,
    sleep_max: u64,
    sum_sleep_runtime: u64,
    block_start: u64,
    block_max: u64,
    exec_max: u64,
    slice_max: u64,
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
    core_forceidle_sum: u64,
};

// ============================================================================
// EEVDF (Earliest Eligible Virtual Deadline First)
// ============================================================================

pub const EevdfConfig = struct {
    base_slice: u64,        // base scheduling quantum (nanoseconds)
    min_slice: u64,         // minimum slice
    max_slice: u64,         // maximum slice
    latency_nice_to_slice: [40]u64,
    // eligibility tracking
    eligible_threshold: u64,
};

pub fn calculate_vdeadline(vruntime: u64, slice: u64, weight: u64) u64 {
    if (weight == 0) return vruntime;
    return vruntime + (slice * SCHED_LOAD_SCALE) / weight;
}

// ============================================================================
// Bandwidth Control (CFS bandwidth)
// ============================================================================

pub const CfsBandwidth = struct {
    period: u64,        // in nanoseconds
    quota: i64,         // -1 = unlimited
    burst: u64,
    runtime: i64,       // remaining runtime
    period_active: bool,
    distribute_running: bool,
    timer_active: bool,
    // statistics
    nr_periods: u64,
    nr_throttled: u64,
    throttled_time: u64,
    nr_burst: u64,
    burst_time: u64,
};

// ============================================================================
// Task Group (cgroup CPU controller)
// ============================================================================

pub const TaskGroup = struct {
    // CSS (cgroup subsystem state)
    css_id: u64,
    shares: u64,          // cpu.weight (shares)
    cfs_bandwidth: CfsBandwidth,
    // per-CPU cfs_rq pointers
    cfs_rq_count: u32,
    // RT bandwidth
    rt_bandwidth: RtBandwidth,
    // Hierarchy
    parent: ?*TaskGroup,
    siblings_count: u32,
    children_count: u32,
    // Idle
    idle: u32,
};

pub const RtBandwidth = struct {
    rt_period: u64,
    rt_runtime: i64,
    timer_active: bool,
};

// ============================================================================
// Run Queue (per-CPU)
// ============================================================================

pub const Runqueue = struct {
    // Raw lock
    lock: u64,
    nr_running: u32,
    nr_numa_running: u32,
    nr_preferred_running: u32,
    // CFS
    cfs: CfsRunqueue,
    // RT
    rt_nr_running: u32,
    rt_nr_migratory: u32,
    rt_nr_total: u32,
    // DL
    dl_nr_running: u32,
    dl_nr_migratory: u32,
    earliest_dl: EarliestDl,
    // Current task
    curr: u64,       // task_struct pointer
    idle: u64,
    stop: u64,
    // CPU info
    cpu: u32,
    online: bool,
    cpu_capacity: u64,
    cpu_capacity_orig: u64,
    // Scheduling domain
    sd: ?*SchedDomain,
    // Push/pull
    active_balance: bool,
    push_cpu: u32,
    push_flags: u32,
    // Clock
    clock: u64,
    clock_task: u64,
    clock_pelt: u64,
    lost_idle_time: u64,
    // PELT averages
    avg_idle: u64,
    max_idle_balance_cost: u64,
    avg_rt: SchedAvg,
    avg_dl: SchedAvg,
    avg_irq: SchedAvg,
    avg_thermal: SchedAvg,
    // Idle state
    idle_stamp: u64,
    avg_idle_ns: u64,
    wake_stamp: u64,
    wake_avg_idle: u64,
    // IPI
    nohz_tick_stopped: bool,
    nohz_flags: NohzFlags,
    // Core scheduling (SMT)
    core_enabled: bool,
    core: ?*Runqueue,
    core_pick: u64,   // task_struct
    core_cookie: u64,
    core_forceidle_count: u32,
    core_forceidle_seq: u32,
    core_forceidle_occupation: u32,
    // Misc stats
    nr_switches: u64,
    nr_involuntary_switches: u64,
    rq_cpu_time: u64,
    rq_wall_time: u64,
    calc_load_update: u64,
    calc_load_active: u64,
    prev_steal_time: u64,
    prev_steal_time_rq: u64,
    // Overloaded
    overload: bool,
    misfit_task_load: u64,
    cfs_overloaded: bool,
};

pub const EarliestDl = struct {
    curr: u64,
    next: u64,
};

pub const NohzFlags = packed struct(u8) {
    tick_stopped: bool = false,
    balance_kick: bool = false,
    stats_kick: bool = false,
    newilb_kick: bool = false,
    _pad: u4 = 0,
};

// ============================================================================
// Scheduling Domains
// ============================================================================

pub const SchedDomainLevel = enum(u8) {
    sibling = 0,     // SMT siblings
    mc = 1,          // multi-core (same LLC)
    die = 2,         // same die
    cluster = 3,     // cluster
    numa = 4,        // NUMA node
    numa2 = 5,       // 2 hops
    numa3 = 6,       // 3 hops
    system = 7,      // whole system
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
    share_pke: bool = false,
    serialize: bool = false,
    asym_packing: bool = false,
    prefer_sibling: bool = false,
    overlap: bool = false,
    numa: bool = false,
    _pad: u17 = 0,
};

pub const SchedDomain = struct {
    level: SchedDomainLevel,
    flags: SchedDomainFlags,
    span_weight: u32,
    // Tuning parameters
    min_interval: u32,
    max_interval: u32,
    busy_factor: u32,
    imbalance_pct: u32,
    cache_nice_tries: u32,
    nohz_idle: u32,
    forkexec_idx: u32,
    // Pointers
    parent: ?*SchedDomain,
    child: ?*SchedDomain,
    // Statistics
    lb_count: [4]u64,
    lb_failed: [4]u64,
    lb_balanced: [4]u64,
    lb_imbalance: [4]u64,
    lb_gained: [4]u64,
    lb_hot_gained: [4]u64,
    lb_nobusyq: [4]u64,
    lb_nobusyg: [4]u64,
    alb_count: u64,
    alb_failed: u64,
    alb_pushed: u64,
    sbe_count: u64,
    sbe_balanced: u64,
    sbe_pushed: u64,
    sbf_count: u64,
    sbf_balanced: u64,
    sbf_pushed: u64,
    ttwu_wake_remote: u64,
    ttwu_move_affine: u64,
    ttwu_move_balance: u64,
};

// ============================================================================
// Util Clamp
// ============================================================================

pub const UCLAMP_MIN: u8 = 0;
pub const UCLAMP_MAX: u8 = 1;
pub const UCLAMP_CNT: u8 = 2;

pub const UCLAMP_BUCKET_CNT: u32 = 20;
pub const UCLAMP_BUCKET_DELTA: u32 = 1024 / UCLAMP_BUCKET_CNT;

pub const UclampSe = struct {
    value: u32,
    bucket_id: u32,
    active: bool,
    user_defined: bool,
};

pub const UclampBucket = struct {
    value: u32,
    tasks: u32,
};

pub const UclampRq = struct {
    value: u32,
    bucket: [UCLAMP_BUCKET_CNT]UclampBucket,
};

// ============================================================================
// Sched_ext (Extensible Scheduler)
// ============================================================================

pub const ScxExitKind = enum(u8) {
    none = 0,
    done = 1,
    unreg = 2,
    unreg_kern = 3,
    unreg_bpf = 4,
    error = 5,
    error_bpf = 6,
    error_stall = 7,
};

pub const ScxOpsFlags = packed struct(u32) {
    keep_builtin_idle: bool = false,
    enq_last: bool = false,
    enq_exiting: bool = false,
    switch_partial: bool = false,
    _pad: u28 = 0,
};

pub const ScxDispatchFlags = packed struct(u32) {
    enq_wakeup: bool = false,
    enq_head: bool = false,
    enq_preempt: bool = false,
    enq_cpu_selected: bool = false,
    _pad: u28 = 0,
};

pub const ScxOps = struct {
    name: [128]u8,
    flags: ScxOpsFlags,
    timeout_ms: u32,
    exit_dump_len: u32,
    // BPF ops callbacks (function pointers)
    select_cpu: ?*const fn (u64, i32, u64) i32,
    enqueue: ?*const fn (u64, u64) void,
    dequeue: ?*const fn (u64, u64) void,
    dispatch: ?*const fn (u32, u64) void,
    tick: ?*const fn (u64) void,
    runnable: ?*const fn (u64, u64) void,
    running: ?*const fn (u64) void,
    stopping: ?*const fn (u64, bool) void,
    quiescent: ?*const fn (u64, u64) void,
    yield_task: ?*const fn (u64, u64) bool,
    core_sched_before: ?*const fn (u64, u64) bool,
    set_weight: ?*const fn (u64, u32) void,
    set_cpumask: ?*const fn (u64, u64) void,
    update_idle: ?*const fn (i32, bool) void,
    cpu_acquire: ?*const fn (i32, u64) void,
    cpu_release: ?*const fn (i32, u64) void,
    init_task: ?*const fn (u64, u64) i32,
    exit_task: ?*const fn (u64, u64) void,
    enable: ?*const fn (u64) void,
    disable: ?*const fn (u64) void,
    init: ?*const fn () i32,
    exit: ?*const fn (u64) void,
    dump: ?*const fn (u64) void,
    dump_cpu: ?*const fn (u64, i32, u64) void,
    dump_task: ?*const fn (u64, u64) void,
};

pub const ScxDsq = struct {
    id: u64,
    nr_queued: u32,
    nr_dispatched: u64,
};

pub const SCX_DSQ_LOCAL: u64 = @as(u64, @bitCast(@as(i64, -1)));
pub const SCX_DSQ_GLOBAL: u64 = @as(u64, @bitCast(@as(i64, -2)));
pub const SCX_DSQ_LOCAL_ON: u64 = @as(u64, @bitCast(@as(i64, -3)));

// ============================================================================
// Core Scheduling (SMT-aware security)
// ============================================================================

pub const CoreSchedConfig = struct {
    enabled: bool,
    // Cookie-based core scheduling
    active_cookies: u64,
    forced_idle_count: u64,
    forced_idle_total_time: u64,
};

pub const CoreCookie = struct {
    cookie: u64,
    refcount: u32,
};

// ============================================================================
// CPU Frequency Scaling Integration (schedutil)
// ============================================================================

pub const SchedUtilConfig = struct {
    enabled: bool,
    rate_limit_us: u32,
    hispeed_freq: u64,
    hispeed_load: u32,
};

pub const CpuFreqPolicy = struct {
    cpu: u32,
    min: u64,
    max: u64,
    cur: u64,
    governor: CpuFreqGovernor,
    cpuinfo_min_freq: u64,
    cpuinfo_max_freq: u64,
    cpuinfo_transition_latency: u32,
    transition_ongoing: bool,
    transition_task: u64,
    stats: CpuFreqStats,
};

pub const CpuFreqGovernor = enum(u8) {
    performance = 0,
    powersave = 1,
    userspace = 2,
    ondemand = 3,
    conservative = 4,
    schedutil = 5,
};

pub const CpuFreqStats = struct {
    total_trans: u64,
    last_time: u64,
    max_state: u32,
    time_in_state: [64]u64,
    freq_table: [64]u64,
};

// ============================================================================
// CFS Scheduler Subsystem Manager
// ============================================================================

pub const CfsSubsystemManager = struct {
    // Global config
    sched_min_granularity_ns: u64,
    sched_latency_ns: u64,
    sched_wakeup_granularity_ns: u64,
    sched_migration_cost_ns: u64,
    sched_nr_migrate: u32,
    sched_child_runs_first: bool,
    // EEVDF
    eevdf_config: EevdfConfig,
    // Util clamp
    sysctl_sched_uclamp_util_min: u32,
    sysctl_sched_uclamp_util_max: u32,
    sysctl_sched_uclamp_util_min_rt_default: u32,
    // Core scheduling
    core_sched: CoreSchedConfig,
    // sched_ext
    scx_enabled: bool,
    scx_ops: ?*ScxOps,
    scx_exit_kind: ScxExitKind,
    // CPU freq
    schedutil: SchedUtilConfig,
    // Stats
    nr_context_switches: u64,
    nr_load_balances: u64,
    nr_migrations: u64,
    nr_active_tasks: u64,
    initialized: bool,

    pub fn init() CfsSubsystemManager {
        return CfsSubsystemManager{
            .sched_min_granularity_ns = 750000,         // 0.75ms
            .sched_latency_ns = 6000000,                // 6ms
            .sched_wakeup_granularity_ns = 1000000,     // 1ms
            .sched_migration_cost_ns = 500000,          // 0.5ms
            .sched_nr_migrate = 32,
            .sched_child_runs_first = false,
            .eevdf_config = EevdfConfig{
                .base_slice = 3000000,     // 3ms
                .min_slice = 300000,       // 300us
                .max_slice = 24000000,     // 24ms
                .latency_nice_to_slice = [_]u64{0} ** 40,
                .eligible_threshold = 0,
            },
            .sysctl_sched_uclamp_util_min = 0,
            .sysctl_sched_uclamp_util_max = 1024,
            .sysctl_sched_uclamp_util_min_rt_default = 1024,
            .core_sched = CoreSchedConfig{
                .enabled = false,
                .active_cookies = 0,
                .forced_idle_count = 0,
                .forced_idle_total_time = 0,
            },
            .scx_enabled = false,
            .scx_ops = null,
            .scx_exit_kind = .none,
            .schedutil = SchedUtilConfig{
                .enabled = true,
                .rate_limit_us = 1000,
                .hispeed_freq = 0,
                .hispeed_load = 90,
            },
            .nr_context_switches = 0,
            .nr_load_balances = 0,
            .nr_migrations = 0,
            .nr_active_tasks = 0,
            .initialized = true,
        };
    }
};
