// Zxyphor Kernel - Scheduler Load Balancing Internals,
// Migration Mechanism, Idle Balancer, NOHZ Balancing,
// CPU Capacity & Asymmetric Packing, Load Tracking,
// PELT (Per-Entity Load Tracking), Scheduler Domains,
// NUMA Balancing Detail, Task Placement
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Scheduler Domain Topology
// ============================================================================

pub const SchedDomainLevel = enum(u8) {
    sibling = 0,       // SMT (Hyperthreading)
    mc = 1,            // Multi-Core (same LLC)
    die = 2,           // Die within package
    cluster = 3,       // Cluster (shared mid-level cache)
    pkg = 4,           // Package/Socket
    numa_1 = 5,        // NUMA distance 1
    numa_2 = 6,        // NUMA distance 2
    numa_3 = 7,        // NUMA distance 3
    system = 8,        // Entire system
};

pub const SchedDomainFlags = packed struct(u32) {
    load_balance: bool = true,
    balance_newidle: bool = true,
    balance_exec: bool = false,
    balance_fork: bool = false,
    balance_wake: bool = true,
    wake_affine: bool = true,
    asym_cpucapacity: bool = false,
    asym_cpucapacity_full: bool = false,
    share_cpucapacity: bool = false,
    share_powerdomain: bool = false,
    share_pkg_resources: bool = false,
    serialize: bool = false,
    asym_packing: bool = false,
    prefer_sibling: bool = false,
    overlap: bool = false,
    numa: bool = false,
    _reserved: u16 = 0,
};

pub const SchedDomain = struct {
    level: SchedDomainLevel,
    flags: SchedDomainFlags,
    span_weight: u32,                // Number of CPUs
    imbalance_pct: u32,              // Threshold (117 = 17% imbalance)
    cache_nice_tries: u32,
    min_interval: u32,
    max_interval: u32,
    busy_factor: u32,
    balance_interval: u32,           // Current interval (ms)
    nr_balance_failed: u32,
    // NUMA
    numa_distance: u16,
    // Statistics
    lb_count: [4]u64,                // By idle type
    lb_balanced: [4]u64,
    lb_failed: [4]u64,
    lb_imbalance: [4]u64,
    lb_gained: [4]u64,
    lb_hot_gained: [4]u64,
    lb_nobusyq: [4]u64,
    lb_nobusyg: [4]u64,
    alb_count: u64,                  // Active LB
    alb_failed: u64,
    alb_pushed: u64,
    sbe_count: u64,                  // SBE = sched_balance_exec
    sbe_balanced: u64,
    sbe_pushed: u64,
    sbf_count: u64,                  // SBF = sched_balance_fork
    sbf_balanced: u64,
    sbf_pushed: u64,
    ttwu_wake_remote: u64,
    ttwu_move_affine: u64,
    ttwu_move_balance: u64,
};

// ============================================================================
// Scheduler Group
// ============================================================================

pub const SchedGroup = struct {
    group_weight: u32,       // Number of CPUs in this group
    group_type: GroupType,
    capacity: u64,           // Total compute capacity
    capacity_orig: u64,      // Original capacity (no thermal)
    sgc_imbalance: i64,      // Imbalance (+ = overloaded)
    // PELT aggregated
    avg_load: u64,
    sum_nr_running: u32,
    sum_h_nr_running: u32,
    idle_cpus: u32,
};

pub const GroupType = enum(u8) {
    has_spare = 0,          // Group has spare capacity
    fully_busy = 1,         // All CPUs busy
    misfit_task = 2,        // Task doesn't fit
    asym_packing = 3,       // Asymmetric packing needed
    imbalanced = 4,         // Load imbalanced
    overloaded = 5,         // More tasks than CPUs
};

// ============================================================================
// PELT (Per-Entity Load Tracking)
// ============================================================================

pub const PeltEntity = struct {
    load_avg: u64,              // Load average (weighted)
    runnable_avg: u64,          // Runnable average
    util_avg: u64,              // Utilization average
    load_sum: u64,
    runnable_sum: u64,
    util_sum: u64,
    period_contrib: u32,        // Contribution to current period
    last_update_time: u64,      // In ns
};

pub const PeltConfig = struct {
    half_life_ms: u32,          // Default 32ms (PELT half-life)
    util_est_enabled: bool,     // Utilization estimation
    util_est_margin: u32,       // Margin for estimation
};

pub const PeltDecayFactors = struct {
    // Precomputed decay factors for 32ms half-life
    // y^n where y ≈ 0.978 for 1ms periods
    decay_1ms: u32,     // Fixed point
    decay_1period: u32,  // 1024us period
    runnable_avg_yN_inv: [32]u32,
    runnable_avg_yN_sum: [32]u32,
};

// ============================================================================
// Load Balance Algorithm
// ============================================================================

pub const LbIdleType = enum(u8) {
    cpu_idle = 0,
    cpu_not_idle = 1,
    cpu_newly_idle = 2,
};

pub const LbEnvFlags = packed struct(u32) {
    find_busiest_group: bool = true,
    find_busiest_queue: bool = true,
    move_tasks: bool = true,
    active_balance: bool = false,
    sd_balance_newidle: bool = false,
    sd_balance_exec: bool = false,
    sd_balance_fork: bool = false,
    sd_balance_wake: bool = false,
    _reserved: u24 = 0,
};

pub const LoadBalanceResult = struct {
    tasks_moved: u32,
    load_moved: u64,
    imbalance: i64,
    busiest_group_type: GroupType,
    local_group_type: GroupType,
    idle_type: LbIdleType,
    flags: LbResultFlags,
};

pub const LbResultFlags = packed struct(u16) {
    success: bool = false,
    failed: bool = false,
    all_pinned: bool = false,
    active_balance_needed: bool = false,
    misfit_handled: bool = false,
    redo: bool = false,
    _reserved: u10 = 0,
};

pub const MigrationRequest = struct {
    task_pid: u32,
    from_cpu: u32,
    to_cpu: u32,
    reason: MigrationReason,
    timestamp: u64,
};

pub const MigrationReason = enum(u8) {
    load_balance = 0,
    exec = 1,
    fork = 2,
    wake = 3,
    affinity = 4,
    active_balance = 5,
    nohz_kick = 6,
    thermal = 7,
    numa_migrate = 8,
    // Zxyphor
    zxy_latency = 100,
};

pub const MigrationStats = struct {
    migrations_total: u64,
    migrations_load_balance: u64,
    migrations_exec: u64,
    migrations_fork: u64,
    migrations_wake: u64,
    migrations_affinity: u64,
    migrations_active: u64,
    migrations_nohz: u64,
    migrations_numa: u64,
    migrations_failed: u64,
    // Per-type costs
    total_migration_cost_ns: u64,
    avg_migration_cost_ns: u64,
};

// ============================================================================
// NOHZ / Tick-less Idle
// ============================================================================

pub const NohzMode = enum(u8) {
    nohz_off = 0,
    nohz_idle = 1,          // tick-less when idle
    nohz_full = 2,          // tick-less even when running
};

pub const NohzFlags = packed struct(u32) {
    tick_stopped: bool = false,
    idle_active: bool = false,
    full_active: bool = false,
    balance_kick: bool = false,
    stats_kick: bool = false,
    nr_running: bool = false,
    _reserved: u26 = 0,
};

pub const NohzIdleBalance = struct {
    next_balance: u64,          // jiffies
    next_lifted_balance: u64,
    has_blocked: bool,
    needs_update: bool,
    idle_cpus_mask: [4]u64,     // Bitmask (up to 256 CPUs)
};

pub const NohzFullConfig = struct {
    enabled: bool,
    cpus: [4]u64,               // Bitmask of NOHZ_FULL CPUs
    posix_timer_off: bool,      // POSIX timer tick handling
    rcu_nocbs: bool,            // RCU callback offloading
    context_tracking: bool,
};

// ============================================================================
// NUMA Balancing Detail
// ============================================================================

pub const NumaBalancingConfig = struct {
    enabled: bool,
    scan_delay_ms: u32,         // Initial scan delay
    scan_period_min_ms: u32,    // Minimum scan period
    scan_period_max_ms: u32,    // Maximum scan period
    scan_size_mb: u32,          // Pages to scan at once
    hot_threshold_ms: u32,      // Hot page access threshold
};

pub const NumaPlacementHint = struct {
    preferred_node: i32,        // -1 = no preference
    preferred_cpu: i32,         // -1 = no preference
    numa_score: i64,
    scan_seq: u64,
    total_pages: u64,
    private_pages: u64,         // Pages accessed by this task only
    shared_pages: u64,          // Pages accessed by multiple tasks
    group_id: u64,              // NUMA group for shared pages
};

pub const NumaMigrateInfo = struct {
    src_node: i32,
    dst_node: i32,
    pages_scanned: u64,
    pages_moved: u64,
    pages_failed: u64,
    latency_gain_ns: i64,      // Estimated latency improvement
};

pub const NumaStats = struct {
    pages_migrated: u64,
    pages_migrated_fail: u64,
    hint_faults_local: u64,
    hint_faults_remote: u64,
    task_migrations: u64,
    group_formations: u64,
    group_merges: u64,
    group_splits: u64,
    swap_migrations: u64,
};

// ============================================================================
// Task Placement & Affinity
// ============================================================================

pub const TaskPlacementPolicy = enum(u8) {
    spread = 0,             // Spread across CPUs
    pack = 1,               // Pack onto fewest CPUs
    performance = 2,        // Use fastest CPUs
    power_save = 3,         // Use most efficient CPUs
    // Zxyphor
    zxy_adaptive = 100,     // Adapts based on load
};

pub const CpuAffinityType = enum(u8) {
    hard = 0,               // Strict CPU mask
    soft = 1,               // Preferred but not required
    numa_preferred = 2,     // NUMA node preference
};

pub const WakeupStats = struct {
    total_wakeups: u64,
    wakeup_local: u64,       // Same CPU
    wakeup_remote: u64,      // Different CPU
    wakeup_same_llc: u64,    // Same LLC
    wakeup_cross_numa: u64,
    wakeup_affine: u64,
    wakeup_new_cpu: u64,
    avg_wakeup_latency_ns: u64,
};

// ============================================================================
// Load Tracking Manager (Zxyphor)
// ============================================================================

pub const LoadBalancingManager = struct {
    nr_domains: u32,
    nr_groups: u32,
    nohz_config: NohzFullConfig,
    numa_config: NumaBalancingConfig,
    pelt_config: PeltConfig,
    migration_stats: MigrationStats,
    numa_stats: NumaStats,
    wakeup_stats: WakeupStats,
    placement_policy: TaskPlacementPolicy,
    balance_interval_ms: u32,
    initialized: bool,

    pub fn init() LoadBalancingManager {
        return .{
            .nr_domains = 0,
            .nr_groups = 0,
            .nohz_config = std.mem.zeroes(NohzFullConfig),
            .numa_config = .{
                .enabled = true,
                .scan_delay_ms = 1000,
                .scan_period_min_ms = 100,
                .scan_period_max_ms = 60000,
                .scan_size_mb = 256,
                .hot_threshold_ms = 1,
            },
            .pelt_config = .{
                .half_life_ms = 32,
                .util_est_enabled = true,
                .util_est_margin = 12,
            },
            .migration_stats = std.mem.zeroes(MigrationStats),
            .numa_stats = std.mem.zeroes(NumaStats),
            .wakeup_stats = std.mem.zeroes(WakeupStats),
            .placement_policy = .zxy_adaptive,
            .balance_interval_ms = 4,
            .initialized = true,
        };
    }
};
