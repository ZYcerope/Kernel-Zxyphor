// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Energy-Aware Scheduling, PSI, CPU Accounting
// EAS, schedutil, cpufreq governor interaction, PSI states,
// cpu accounting, cputime, schedstat, CPU isolation

const std = @import("std");

// ============================================================================
// Energy-Aware Scheduling (EAS)
// ============================================================================

pub const EnergyModel = struct {
    nr_perf_states: u32,
    perf_states: [64]PerformanceState,
    cpus: CpuMask,
    capacity: u64,
    min_capacity: u64,
    max_capacity: u64,
    flags: EmFlags,
    pd: ?*PerfDomain,
};

pub const PerformanceState = struct {
    frequency: u64,   // kHz
    power: u64,       // mW
    cost: u64,        // normalized energy cost
    flags: u32,
    performance: u64, // DMIPS or other metric
};

pub const EmFlags = packed struct(u32) {
    no_artificial_cap: bool = false,
    pd_alive: bool = false,
    cpu_device: bool = false,
    _reserved: u29 = 0,
};

pub const PerfDomain = struct {
    em: ?*EnergyModel,
    next: ?*PerfDomain,
    nr_cpus: u32,
};

pub const EasDecision = enum(u8) {
    NoPd = 0,         // No perf domain
    DontMigrate = 1,  // Keep on current CPU
    MigrateEas = 2,   // EAS chose to migrate
    MigrateSis = 3,   // Select idle sibling
};

pub const EasConfig = struct {
    enabled: bool,
    overutilized: bool,
    overutilized_threshold_pct: u32,
    pd_count: u32,
    total_eas_decisions: u64,
    eas_migrations: u64,
    imbalance_migrations: u64,
};

// ============================================================================
// Schedutil Governor
// ============================================================================

pub const SchedutilPolicy = struct {
    cpu: u32,
    next_freq: u64,
    last_freq_update_time: u64,
    transition_delay_ns: u64,
    work_in_progress: bool,
    limits_changed: bool,
    need_freq_change: bool,
    cached_raw_freq: u64,
    freq_update_delay_ns: u64,
    hispeed_freq: u64,
    hispeed_load: u32,
};

pub const CpufreqGovernor = enum(u8) {
    Performance = 0,
    Powersave = 1,
    Ondemand = 2,
    Conservative = 3,
    Schedutil = 4,
    Userspace = 5,
};

pub const CpufreqPolicy = struct {
    cpu: u32,
    cpus: CpuMask,
    min: u64,       // kHz
    max: u64,
    cur: u64,
    governor: CpufreqGovernor,
    scaling_min_freq: u64,
    scaling_max_freq: u64,
    cpuinfo_min_freq: u64,
    cpuinfo_max_freq: u64,
    transition_latency: u64,   // ns
    last_stat_flush: u64,
    total_transitions: u64,
    boost_enabled: bool,
    fast_switch_possible: bool,
    fast_switch_enabled: bool,
    strict_target: bool,
    efficiencies_available: bool,
};

// ============================================================================
// Schedstat
// ============================================================================

pub const SchedStat = struct {
    run_delay: u64,       // ns waiting in runqueue
    time_slice: u64,      // ns running on CPU
    pcount: u64,          // total schedule count
    bkl_count: u64,       // not used anymore but kept for compat
    iowait_count: u64,
    iowait_sum: u64,
    nr_wakeups: u64,
    nr_wakeups_sync: u64,
    nr_wakeups_migrate: u64,
    nr_wakeups_local: u64,
    nr_wakeups_remote: u64,
    nr_wakeups_affine: u64,
    nr_wakeups_affine_attempts: u64,
    nr_wakeups_passive: u64,
    nr_wakeups_idle: u64,
};

pub const RqSchedStat = struct {
    yld_count: u64,       // sched_yield
    sched_count: u64,     // schedule() calls
    sched_goidle: u64,    // going idle
    ttwu_count: u64,      // try_to_wake_up
    ttwu_local: u64,      // local wakeups
};

// ============================================================================
// PSI (Pressure Stall Information)
// ============================================================================

pub const PsiResourceType = enum(u8) {
    Io = 0,
    Memory = 1,
    Cpu = 2,
    Irq = 3,
    NrResources = 4,
};

pub const PsiState = enum(u8) {
    None = 0,
    Some = 1,
    Full = 2,
};

pub const PsiGroupStats = struct {
    total: [3]u64,           // [some, full, none] in us
    avg10: [2]u32,           // [some, full] * 100
    avg60: [2]u32,
    avg300: [2]u32,
    total_stall_us: [2]u64,  // [some, full]
};

pub const PsiGroup = struct {
    cpu: PsiGroupStats,
    memory: PsiGroupStats,
    io: PsiGroupStats,
    irq: PsiGroupStats,
    poll_states: u32,
    poll_min_period: u32,  // us
    poll_timer_active: bool,
    nr_triggers: u32,
};

pub const PsiTrigger = struct {
    resource: PsiResourceType,
    state: PsiState,
    threshold_us: u64,
    window_us: u64,
    last_event_time: u64,
    event_count: u64,
    pending_event: bool,
};

// ============================================================================
// CPU Accounting / cputime
// ============================================================================

pub const CpuTimeType = enum(u8) {
    User = 0,
    Nice = 1,
    System = 2,
    Softirq = 3,
    Irq = 4,
    Idle = 5,
    Iowait = 6,
    Steal = 7,
    Guest = 8,
    GuestNice = 9,
};

pub const TaskCputime = struct {
    utime: u64,     // user time in ns
    stime: u64,     // system time in ns
    sum_exec_runtime: u64, // total on-CPU time in ns
};

pub const CpuAcct = struct {
    usage_ns: [10]u64,     // per CpuTimeType
    usage_percpu: [256]u64, // per CPU
    stat_user: u64,
    stat_system: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_time: u64,
};

pub const TickDepenAccounting = struct {
    stime: u64,
    utime: u64,
    gtime: u64,
    prev_cputime: PrevCputime,
};

pub const PrevCputime = struct {
    utime: u64,
    stime: u64,
    lock: SpinLock,
};

// ============================================================================
// CPU Isolation (cpusets for RT / nohz_full)
// ============================================================================

pub const CpuIsolationType = enum(u8) {
    None = 0,
    Domain = 1,       // isolated from SMP load balancing
    ManagedIrq = 2,   // no managed IRQ affinity
    NohzFull = 3,     // full nohz (tick offloaded)
    All = 4,          // fully isolated
};

pub const CpuIsolationConfig = struct {
    isolated_cpus: CpuMask,
    housekeeping_cpus: CpuMask,
    nohz_full_cpus: CpuMask,
    rcu_nocbs_cpus: CpuMask,
    isolation_flags: [256]CpuIsolationType,
};

pub const HousekeepingFlag = enum(u8) {
    Tick = 0,
    Timer = 1,
    Rcu = 2,
    Workqueue = 3,
    Sched = 4,
    Domain = 5,
    ManagedIrq = 6,
};

// ============================================================================
// Utilization Tracking (for EAS & schedutil)
// ============================================================================

pub const UtilAvg = struct {
    util_avg: u64,
    util_sum: u64,
    util_est_ewma: u32,
    util_est_enqueued: u32,
    runnable_avg: u64,
    runnable_sum: u64,
    load_avg: u64,
    load_sum: u64,
    period_contrib: u32,
    last_update_time: u64,
};

pub const CpuUtilInfo = struct {
    cpu: u32,
    capacity: u64,
    capacity_orig: u64,
    util_avg: u64,
    util_est: u64,
    irq_avg: u64,
    thermal_pressure_avg: u64,
    max_freq: u64,
    cur_freq: u64,
    nr_running: u32,
    cpu_overutilized: bool,
};

// ============================================================================
// Load Tracking Windows
// ============================================================================

pub const PeltConfig = struct {
    half_life_ms: u32,
    divider: u32,
    runnable_avg_y_inv: u32,
    decay_shift: u32,
    contrib_per_period: u32,
};

pub const PeltDecayTable = struct {
    /// Pre-computed geometric series sums for PELT
    pub const MAX_PERIODS: usize = 64;
    decay_factor: [MAX_PERIODS]u32,
    accumulated: [MAX_PERIODS]u64,
};

// ============================================================================
// Bandwidth Control for CFS
// ============================================================================

pub const CfsBandwidthConfig = struct {
    quota_us: i64,        // -1 for unlimited
    period_us: u64,
    burst_us: u64,
    runtime_us: i64,
    runtime_expires: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_time_ns: u64,
    nr_burst: u64,
    burst_time_ns: u64,
    idle: bool,
    period_active: bool,
    hierarchical_quota_us: i64,
    effective_runtime_us: i64,
};

// ============================================================================
// Deadline Bandwidth
// ============================================================================

pub const DlBandwidth = struct {
    bw: u64,              // max utilization (scaled)
    total_bw: u64,
    dl_period: u64,
    dl_runtime: u64,
    dl_deadline: u64,
    running_bw: u64,
    this_bw: u64,
    extra_bw: u64,
    bw_ratio: u64,
};

// ============================================================================
// CPU Topology for EAS
// ============================================================================

pub const CpuTopologyLevel = enum(u8) {
    Thread = 0,     // SMT
    Core = 1,
    Cluster = 2,
    Die = 3,
    Package = 4,
    NumLevels = 5,
};

pub const CpuTopologyInfo = struct {
    cpu_id: u32,
    core_id: u32,
    cluster_id: u32,
    die_id: u32,
    package_id: u32,
    thread_siblings: CpuMask,
    core_siblings: CpuMask,
    cluster_siblings: CpuMask,
    die_siblings: CpuMask,
    llc_shared: CpuMask,
    capacity_orig: u64,
    capacity_dmips_mhz: u64,
    freq_factor: u32,
};

// ============================================================================
// Helper types
// ============================================================================

pub const CpuMask = struct {
    bits: [4]u64,  // up to 256 CPUs
};

pub const SpinLock = struct { raw: u32 = 0 };

// ============================================================================
// EAS/PSI/Schedstat Manager
// ============================================================================

pub const EasPsiManager = struct {
    eas_config: EasConfig,
    psi_group: PsiGroup,
    global_schedstat: RqSchedStat,
    cpufreq_policies: [32]CpufreqPolicy,
    nr_cpufreq_policies: u32,
    isolation_config: CpuIsolationConfig,
    pelt_config: PeltConfig,
    cfs_bandwidth: CfsBandwidthConfig,
    dl_bandwidth: DlBandwidth,
    topology: [256]CpuTopologyInfo,
    cpu_util: [256]CpuUtilInfo,
    nr_cpus: u32,
    initialized: bool,

    pub fn init() EasPsiManager {
        return .{
            .eas_config = .{
                .enabled = true,
                .overutilized = false,
                .overutilized_threshold_pct = 80,
                .pd_count = 0,
                .total_eas_decisions = 0,
                .eas_migrations = 0,
                .imbalance_migrations = 0,
            },
            .psi_group = undefined,
            .global_schedstat = undefined,
            .cpufreq_policies = undefined,
            .nr_cpufreq_policies = 0,
            .isolation_config = undefined,
            .pelt_config = .{
                .half_life_ms = 32,
                .divider = 47742,
                .runnable_avg_y_inv = 0,
                .decay_shift = 0,
                .contrib_per_period = 1024,
            },
            .cfs_bandwidth = .{
                .quota_us = -1,
                .period_us = 100000,
                .burst_us = 0,
                .runtime_us = -1,
                .runtime_expires = 0,
                .nr_periods = 0,
                .nr_throttled = 0,
                .throttled_time_ns = 0,
                .nr_burst = 0,
                .burst_time_ns = 0,
                .idle = false,
                .period_active = false,
                .hierarchical_quota_us = -1,
                .effective_runtime_us = -1,
            },
            .dl_bandwidth = undefined,
            .topology = undefined,
            .cpu_util = undefined,
            .nr_cpus = 0,
            .initialized = true,
        };
    }
};
