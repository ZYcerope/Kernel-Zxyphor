// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - NUMA Balancing & Core Scheduling Detail
// NUMA memory policy, automatic page migration, NUMA hints,
// core scheduling tag, core scheduling cookie, SMT awareness

const std = @import("std");

// ============================================================================
// NUMA Memory Policy
// ============================================================================

pub const NumaPolicy = enum(u8) {
    Default = 0,
    Preferred = 1,
    Bind = 2,
    Interleave = 3,
    Local = 4,
    PreferredMany = 5,
    Weighted_Interleave = 6,
};

pub const NumaPolicyFlags = packed struct(u16) {
    static_nodes: bool,    // MPOL_F_STATIC_NODES
    relative_nodes: bool,  // MPOL_F_RELATIVE_NODES
    numa_balancing: bool,  // Enable automigration hints
    _reserved: u13,
};

pub const MempolicyStruct = struct {
    mode: NumaPolicy,
    flags: NumaPolicyFlags,
    refcnt: u32,
    nodes: NumaNodeMask,   // Allowed NUMA node mask
    home_node: i32,        // Preferred home node (-1 = none)
    weight_table: [64]u16, // Weights for weighted interleave
    il_prev: i32,          // Interleave previous node
    il_next: i32,          // Interleave next node
};

pub const NumaNodeMask = struct {
    bits: [64]u64,         // Supports up to 4096 NUMA nodes
};

pub const MAX_NUMNODES = 1024;
pub const NUMA_NO_NODE: i32 = -1;

// ============================================================================
// NUMA Balancing (Automatic Migration)
// ============================================================================

pub const NumaBalancingMode = packed struct(u8) {
    enabled: bool,
    memory_tiering: bool,
    _reserved: u6,
};

pub const NumaBalancingConfig = struct {
    mode: NumaBalancingMode,
    scan_delay_ms: u32,       // Initial scan delay
    scan_period_min_ms: u32,  // Min scan period
    scan_period_max_ms: u32,  // Max scan period
    scan_size_mb: u32,        // Pages scanned per period
    settle_count: u32,        // Settling threshold
    hot_threshold_ms: u32,    // Hot page threshold
    scan_period_reset: bool,  // Reset scan period on migration
};

pub const NumaGroupStats = struct {
    faults: [64]u64,          // Per-node fault counts
    total_faults: u64,
    group_faults: [64]u64,    // NUMA group faults
    preferred_nid: i32,       // Preferred NUMA node
    pages_migrated: u64,
    pte_updates: u64,
    huge_pte_updates: u64,
    hint_faults: u64,
    hint_faults_local: u64,
};

pub const NumaFaultType = enum(u8) {
    Cpu = 0,
    Mem = 1,
    GroupCpu = 2,
    GroupMem = 3,
};

pub const NumaHintFault = struct {
    addr: u64,
    node: i32,              // Faulting node
    last_cpu_node: i32,     // CPU node at fault time
    last_time_ns: u64,
    pid: u32,
    is_shared: bool,
    migrated: bool,
    page_nid: i32,          // Page's current node
};

// ============================================================================
// NUMA Group
// ============================================================================

pub const NumaGroup = struct {
    refcount: u32,
    nr_tasks: u32,
    gid: u64,               // Group ID
    max_faults_cpu: u64,
    total_faults: u64,
    faults_cpu: [64]u64,    // Per-node CPU faults
    faults: [64]u64,        // Per-node memory faults
    active_nodes: u32,
};

// ============================================================================
// NUMA Page Migration
// ============================================================================

pub const NumaMigrateDecision = enum(u8) {
    Stay = 0,
    Migrate = 1,
    MigrateToLocal = 2,
    MigrateToGroup = 3,
    TooRecent = 4,
    RateLimited = 5,
};

pub const NumaMigrateStats = struct {
    nr_migrated: u64,
    nr_failed: u64,
    nr_succeeded: u64,
    nr_thp_split: u64,
    nr_thp_failed: u64,
    nr_pages_scanned: u64,
    nr_pte_updates: u64,
    nr_pte_migrations: u64,
    nr_hint_faults: u64,
    nr_remote_access: u64,
    nr_local_access: u64,
    last_scan_start: u64,
    last_scan_end: u64,
};

pub const NumaPageScanConfig = struct {
    scan_offset: u64,       // Start of next scan
    scan_seq: u64,          // Scan sequence number
    scan_stamp: u64,        // Last scan timestamp
    total_scan_period: u64,
    scan_work: usize,       // Work_struct pointer
};

// ============================================================================
// Core Scheduling
// ============================================================================

pub const CoreCookie = struct {
    cookie_id: u64,         // 0 = default (no group)
    refcount: u32,
    is_idle: bool,
};

pub const CoreSchedConfig = struct {
    enabled: bool,
    sched_core_type: CoreSchedType,
    cookie_counter: u64,
    nr_cookies: u64,
    nr_core_switches: u64,
    nr_forced_idle: u64,
};

pub const CoreSchedType = enum(u8) {
    Disabled = 0,
    TaskLevel = 1,
    Cgroup = 2,
};

pub const CoreSchedCmd = enum(u8) {
    GetCookie = 0,
    CreateGroup = 1,
    ShareTo = 2,
    ShareFrom = 3,
};

pub const PR_SCHED_CORE: u32 = 62;

pub const CoreSchedSiblingState = struct {
    sibling_cpu: u32,
    cookie: u64,
    is_idle: bool,
    needs_resched: bool,
    force_idle: bool,
    pick_task_fn: ?*const fn (u32) ?*usize,
};

// ============================================================================
// SMT (Simultaneous Multi-Threading)
// ============================================================================

pub const SmtControl = enum(u8) {
    On = 0,
    Off = 1,
    ForceOff = 2,
    NotSupported = 3,
    NotImplemented = 4,
};

pub const SmtTopology = struct {
    smt_control: SmtControl,
    threads_per_core: u32,
    nr_cores: u32,
    nr_dies: u32,
    nr_packages: u32,
    smt_active: bool,
    smt_enabled: bool,
    booted_once: bool,
    // L1TF/MDS mitigation
    cpu_smt_possible: bool,
    l1tf_vmx_mitigation: u8,
    mds_mitigation: u8,
};

// ============================================================================
// CPU Cgroup
// ============================================================================

pub const CpuCgroupConfig = struct {
    cfs_quota_us: i64,       // Bandwidth limit (-1 = uncapped)
    cfs_period_us: u64,      // Bandwidth period
    cfs_burst_us: u64,       // Burst capacity
    weight: u32,             // cgroup v2 weight [1, 10000]
    weight_nice: i32,        // Nice-mapped weight
    rt_runtime_us: i64,      // RT bandwidth limit
    rt_period_us: u64,       // RT bandwidth period
    uclamp_min: u32,         // Minimum utilization clamp [0, 1024]
    uclamp_max: u32,         // Maximum utilization clamp [0, 1024]
    idle: u32,               // CPU idle hint
};

pub const CpuBandwidthTimer = struct {
    timer_active: bool,
    timer_slack_ns: u64,
    period_ns: u64,
    quota_ns: i64,
    runtime_ns: i64,
    runtime_expires_ns: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_time_ns: u64,
    nr_bursts: u64,
    burst_time_ns: u64,
};

// ============================================================================
// Uclamp (Utilization Clamping)
// ============================================================================

pub const UclampId = enum(u2) {
    Min = 0,
    Max = 1,
};

pub const UCLAMP_BUCKET_DELTA = 20;  // ~5% per bucket
pub const UCLAMP_BUCKETS = 21;       // (1024 / 50) + 1

pub const UclampSe = struct {
    value: u32,             // Clamp value [0, 1024]
    bucket_id: u8,
    active: bool,
    user_defined: bool,
};

pub const UclampBucket = struct {
    value: u32,
    tasks: u32,
};

pub const UclampRq = struct {
    value: u32,
    bucket: [21]UclampBucket,
};

// ============================================================================
// Scheduler Debug Statistics
// ============================================================================

pub const SchedDebugStats = struct {
    nr_running: u32,
    nr_uninterruptible: u32,
    nr_iowait: u32,
    nr_context_switches: u64,
    nr_migrations: u64,
    nr_migrations_cold: u64,
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
    exec_clock_ns: u64,
    wait_sum_ns: u64,
    wait_count: u64,
    iowait_sum_ns: u64,
    iowait_count: u64,
    sleep_sum_ns: u64,
    sleep_count: u64,
    block_sum_ns: u64,
    block_count: u64,
    total_runtime_ns: u64,
    sum_exec_runtime_ns: u64,
    avg_atom_ns: u64,
    avg_per_cpu_ns: u64,
    nr_switches: u64,
    nr_involuntary_switches: u64,
    nr_voluntary_switches: u64,
    core_sched_switches: u64,
    core_sched_forced_idle: u64,
};

// ============================================================================
// Energy-Aware Scheduling (EAS) Topology
// ============================================================================

pub const EasCpuCapacity = struct {
    cpu: u32,
    capacity: u32,          // [0, 1024]
    freq_factor: u32,
    efficiency: u32,
    thermal_cap: u32,       // Thermally constrained capacity
};

pub const PerfDomain = struct {
    nr_cpus: u32,
    cpu_mask: u64,
    table: [32]EmPerfState, // Energy model perf states
    nr_perf_states: u32,
    min_cap: u32,
    max_cap: u32,
    flags: u32,
};

pub const EmPerfState = struct {
    frequency: u64,        // kHz
    power: u64,            // mW
    cost: u64,             // Normalized cost
    performance: u32,
    flags: u32,
};

// ============================================================================
// Manager
// ============================================================================

pub const NumaCoreSchedManager = struct {
    numa_balancing: NumaBalancingConfig,
    numa_stats: NumaMigrateStats,
    core_sched: CoreSchedConfig,
    smt: SmtTopology,
    sched_stats: SchedDebugStats,
    total_numa_groups: u32,
    total_policies: u32,
    initialized: bool,

    pub fn init() NumaCoreSchedManager {
        return .{
            .numa_balancing = .{
                .mode = .{ .enabled = true, .memory_tiering = false, ._reserved = 0 },
                .scan_delay_ms = 1000,
                .scan_period_min_ms = 1000,
                .scan_period_max_ms = 60000,
                .scan_size_mb = 256,
                .settle_count = 4,
                .hot_threshold_ms = 1000,
                .scan_period_reset = true,
            },
            .numa_stats = std.mem.zeroes(NumaMigrateStats),
            .core_sched = .{
                .enabled = false,
                .sched_core_type = .Disabled,
                .cookie_counter = 0,
                .nr_cookies = 0,
                .nr_core_switches = 0,
                .nr_forced_idle = 0,
            },
            .smt = .{
                .smt_control = .On,
                .threads_per_core = 2,
                .nr_cores = 0,
                .nr_dies = 0,
                .nr_packages = 0,
                .smt_active = true,
                .smt_enabled = true,
                .booted_once = false,
                .cpu_smt_possible = true,
                .l1tf_vmx_mitigation = 0,
                .mds_mitigation = 0,
            },
            .sched_stats = std.mem.zeroes(SchedDebugStats),
            .total_numa_groups = 0,
            .total_policies = 0,
            .initialized = true,
        };
    }
};
