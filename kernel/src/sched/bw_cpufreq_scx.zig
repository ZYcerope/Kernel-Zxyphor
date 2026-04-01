// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Bandwidth Throttling,
// Deadline Admission Control, CPU Accounting,
// CPU Frequency Governors, Energy Aware Scheduling Detail,
// sched_ext (Extensible Scheduler), SCHED_DEADLINE math,
// Core Scheduling, Cluster Scheduling
// More advanced than Linux 2026 scheduler

const std = @import("std");

// ============================================================================
// Bandwidth Throttling (CFS Bandwidth)
// ============================================================================

/// CFS bandwidth configuration
pub const CfsBandwidthConfig = struct {
    quota_us: i64 = -1,          // -1 = unlimited
    period_us: u64 = 100000,     // 100ms default
    burst_us: u64 = 0,
    hierarchical_quota: i64 = -1,
    // Runtime
    runtime_remaining_us: i64 = 0,
    nr_periods: u64 = 0,
    nr_throttled: u64 = 0,
    throttled_time_ns: u64 = 0,
    nr_burst: u64 = 0,
    burst_time_ns: u64 = 0,
};

/// RT bandwidth configuration
pub const RtBandwidthConfig = struct {
    rt_period_us: u64 = 1000000,     // 1 second
    rt_runtime_us: i64 = 950000,     // 950ms
    // Stats
    rt_time_ns: u64 = 0,
    nr_throttled: u64 = 0,
};

// ============================================================================
// SCHED_DEADLINE Internals
// ============================================================================

/// SCHED_DEADLINE parameters
pub const DeadlineParams = struct {
    runtime_ns: u64 = 0,
    deadline_ns: u64 = 0,
    period_ns: u64 = 0,
    flags: DeadlineFlags = .{},
};

pub const DeadlineFlags = packed struct(u32) {
    dl_overrun: bool = false,
    dl_new: bool = false,
    dl_boosted: bool = false,
    dl_yielded: bool = false,
    dl_non_contending: bool = false,
    dl_throttled: bool = false,
    // Zxyphor
    zxy_adaptive: bool = false,
    _padding: u25 = 0,
};

/// SCHED_DEADLINE admission control
pub const DeadlineAdmission = struct {
    bw_util: u64 = 0,          // total BW utilization (fixed point)
    bw_total: u64 = 0,         // total available BW
    bw_free: u64 = 0,
    global_rt_runtime: i64 = 950000,
    nr_dl_tasks: u32 = 0,
    dl_bw_ratio: u32 = 0,      // percentage (0-100)
    admission_strict: bool = true,
};

/// CBS (Constant Bandwidth Server) parameters
pub const CbsParams = struct {
    runtime: u64 = 0,
    deadline: u64 = 0,
    period: u64 = 0,
    budget_remaining: i64 = 0,
    absolute_deadline: u64 = 0,
    is_active: bool = false,
};

// ============================================================================
// CPU Accounting
// ============================================================================

/// CPU time accounting domains
pub const CpuAcctDomain = enum(u8) {
    user = 0,
    nice = 1,
    system = 2,
    idle = 3,
    iowait = 4,
    irq = 5,
    softirq = 6,
    steal = 7,
    guest = 8,
    guest_nice = 9,
};

/// Per-CPU accounting
pub const CpuAcctStats = struct {
    // Time in nanoseconds
    user: u64 = 0,
    nice: u64 = 0,
    system: u64 = 0,
    idle: u64 = 0,
    iowait: u64 = 0,
    irq: u64 = 0,
    softirq: u64 = 0,
    steal: u64 = 0,
    guest: u64 = 0,
    guest_nice: u64 = 0,
    // Additional
    nr_switches: u64 = 0,
    nr_voluntary_switches: u64 = 0,
    nr_involuntary_switches: u64 = 0,
    nr_running: u32 = 0,
    nr_uninterruptible: u32 = 0,
    // Pressure
    some_avg10: u32 = 0,        // PSI some avg 10s (fixed point)
    some_avg60: u32 = 0,
    some_avg300: u32 = 0,
    some_total: u64 = 0,
    full_avg10: u32 = 0,        // PSI full avg 10s
    full_avg60: u32 = 0,
    full_avg300: u32 = 0,
    full_total: u64 = 0,
};

/// IRQ time accounting config
pub const IrqTimeAcct = enum(u8) {
    none = 0,
    vtime = 1,          // virtual time accounting
    irqtime = 2,        // IRQ time accounting
    full = 3,           // full VIRT_CPU_ACCOUNTING
};

// ============================================================================
// CPU Frequency Governors
// ============================================================================

/// CPUFreq governor type
pub const CpufreqGovernor = enum(u8) {
    performance = 0,
    powersave = 1,
    userspace = 2,
    ondemand = 3,
    conservative = 4,
    schedutil = 5,
    // Zxyphor
    zxy_adaptive = 100,
    zxy_ml_driven = 101,
};

/// CPUFreq policy descriptor
pub const CpufreqPolicyDesc = struct {
    cpu: u32 = 0,
    min_freq: u32 = 0,          // kHz
    max_freq: u32 = 0,
    cur_freq: u32 = 0,
    cpuinfo_min_freq: u32 = 0,
    cpuinfo_max_freq: u32 = 0,
    cpuinfo_transition_latency: u32 = 0,   // ns
    governor: CpufreqGovernor = .schedutil,
    scaling_driver: CpufreqDriver = .acpi_cpufreq,
    boost_enabled: bool = false,
    fast_switch: bool = false,
    // Energy
    energy_perf_preference: EppPref = .balance_performance,
};

pub const CpufreqDriver = enum(u8) {
    acpi_cpufreq = 0,
    intel_pstate = 1,
    amd_pstate = 2,
    amd_pstate_epp = 3,
    cppc_cpufreq = 4,
    // Zxyphor
    zxy_native = 100,
};

pub const EppPref = enum(u8) {
    default = 0,
    performance = 1,
    balance_performance = 2,
    balance_power = 3,
    power = 4,
};

/// schedutil governor tunable
pub const SchedutilConfig = struct {
    rate_limit_us: u32 = 1000,
    // IOwait boost
    iowait_boost_enable: bool = true,
    iowait_boost_max: u32 = 0,       // 0 = max freq
};

/// Ondemand governor tunable
pub const OndemandConfig = struct {
    sampling_rate: u32 = 0,           // us
    up_threshold: u32 = 80,           // percent
    sampling_down_factor: u32 = 1,
    ignore_nice_load: bool = false,
    powersave_bias: u32 = 0,
    io_is_busy: bool = false,
};

// ============================================================================
// Energy Aware Scheduling Detail
// ============================================================================

/// Energy model descriptor (per performance domain)
pub const EnergyModelDesc = struct {
    nr_perf_states: u32 = 0,
    nr_cpus: u32 = 0,
    cpumask: u64 = 0,
    flags: EmFlags = .{},
};

pub const EmFlags = packed struct(u32) {
    milliwatts: bool = false,     // power in mW (vs abstract)
    artificial: bool = false,     // artificial EM
    // Zxyphor
    zxy_dynamic: bool = false,
    _padding: u29 = 0,
};

/// Performance state entry
pub const EmPerfState = struct {
    frequency: u64 = 0,          // kHz
    power: u64 = 0,              // mW or abstract
    cost: u64 = 0,               // cost coefficient
    flags: u32 = 0,
};

/// EAS domain (capacity-aware scheduling)
pub const EasDomain = struct {
    capacity_orig: u64 = 0,     // original CPU capacity
    capacity_curr: u64 = 0,     // current capacity (freq-dependent)
    max_util: u64 = 0,
    nr_running: u32 = 0,
    overutilized: bool = false,
    misfit_task_running: bool = false,
};

// ============================================================================
// sched_ext (Extensible Scheduler)
// ============================================================================

/// sched_ext ops flags
pub const ScxOpsFlags = packed struct(u64) {
    keep_builtin_idle: bool = false,
    enq_last: bool = false,
    enq_exiting: bool = false,
    switch_partial: bool = false,
    // Zxyphor
    zxy_priority_aware: bool = false,
    _padding: u59 = 0,
};

/// sched_ext task state
pub const ScxTaskState = enum(u8) {
    none = 0,
    init = 1,
    enabled = 2,
    draining = 3,
};

/// sched_ext DSQ (Dispatch Queue) ID
pub const ScxDsqId = enum(u64) {
    local = 0xFFFFFFFFFFFFFFFF,
    global = 0xFFFFFFFFFFFFFFFE,
    local_on = 0xFFFFFFFFFFFFFFFD,
    // Custom DSQs use normal u64 IDs
};

/// sched_ext dispatch flags
pub const ScxDispFlags = packed struct(u64) {
    enq_wakeup: bool = false,
    enq_head: bool = false,
    enq_preempt: bool = false,
    enq_cpu_selected: bool = false,
    _padding: u60 = 0,
};

// ============================================================================
// Core Scheduling
// ============================================================================

/// Core scheduling cookie
pub const CoreSchedCookie = struct {
    cookie: u64 = 0,
    task_count: u32 = 0,
};

/// Core scheduling config
pub const CoreSchedConfig = struct {
    enabled: bool = false,
    force_idle: bool = false,
    nr_cookies: u32 = 0,
    nr_forced_idle: u64 = 0,
};

// ============================================================================
// Cluster Scheduling
// ============================================================================

/// Cluster scheduling topology
pub const ClusterDesc = struct {
    cluster_id: u32 = 0,
    cpumask: u64 = 0,
    nr_cpus: u32 = 0,
    l2_cache_id: u32 = 0,
    capacity: u64 = 0,
    // Stats
    load: u64 = 0,
    nr_running: u32 = 0,
};

// ============================================================================
// Scheduler Features
// ============================================================================

/// Scheduler debug features (sched_features)
pub const SchedFeatures = packed struct(u64) {
    gentle_fair_sleepers: bool = true,
    start_debit: bool = true,
    next_buddy: bool = false,
    last_buddy: bool = true,
    cache_hot_buddy: bool = true,
    wakeup_preemption: bool = true,
    hrtick: bool = false,
    hrtick_dl: bool = false,
    double_tick: bool = false,
    nontask_capacity: bool = true,
    ttwu_queue: bool = true,
    smp_nice: bool = true,
    affine_wakeups: bool = true,
    rt_push_ipi: bool = true,
    rt_runtime_share: bool = false,
    lbf_all_pinned: bool = true,
    attach_age_load: bool = true,
    wf_fork: bool = true,
    wf_worker: bool = true,
    wf_current: bool = true,
    wf_last_wakee: bool = false,
    // Zxyphor
    zxy_predict_load: bool = false,
    zxy_smart_balance: bool = false,
    _padding: u41 = 0,
};

/// Scheduler statistics
pub const SchedGlobalStats = struct {
    nr_switches: u64 = 0,
    nr_load_balance: u64 = 0,
    nr_load_balance_fail: u64 = 0,
    nr_wakeups: u64 = 0,
    nr_wakeups_sync: u64 = 0,
    nr_wakeups_migrate: u64 = 0,
    nr_wakeups_local: u64 = 0,
    nr_wakeups_remote: u64 = 0,
    nr_wakeups_affine: u64 = 0,
    nr_wakeups_affine_attempts: u64 = 0,
    nr_wakeups_passive: u64 = 0,
    nr_wakeups_idle: u64 = 0,
    nr_migrations: u64 = 0,
    nr_migrations_cold: u64 = 0,
    avg_idle_ns: u64 = 0,
    max_idle_balance_cost_ns: u64 = 0,
};

// ============================================================================
// Scheduler Subsystem Manager
// ============================================================================

pub const SchedDetailSubsystem = struct {
    cfs_bw: CfsBandwidthConfig = .{},
    rt_bw: RtBandwidthConfig = .{},
    dl_admission: DeadlineAdmission = .{},
    irq_time_acct: IrqTimeAcct = .vtime,
    cpufreq_gov: CpufreqGovernor = .schedutil,
    eas_enabled: bool = false,
    scx_loaded: bool = false,
    core_sched: CoreSchedConfig = .{},
    features: SchedFeatures = .{},
    global_stats: SchedGlobalStats = .{},
    nr_clusters: u32 = 0,
    initialized: bool = false,

    pub fn init() SchedDetailSubsystem {
        return SchedDetailSubsystem{
            .initialized = true,
        };
    }
};
