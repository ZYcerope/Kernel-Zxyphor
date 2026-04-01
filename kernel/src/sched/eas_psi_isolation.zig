// SPDX-License-Identifier: MIT
// Zxyphor Kernel - CPU Isolation, Energy-Aware Scheduling,
// Pressure Stall Information (PSI), Utilization Clamping,
// Core Scheduling, NUMA Scheduling, Load Balancing
// More advanced than Linux 2026 scheduler features

const std = @import("std");

// ============================================================================
// CPU Isolation
// ============================================================================

/// CPU isolation flag
pub const CpuIsolationFlags = packed struct {
    nohz_full: bool = false,       // Tickless operation
    domain: bool = false,          // Remove from scheduling domains
    managed_irq: bool = false,     // No managed IRQs
    // Housekeeping flags
    hk_timer: bool = false,
    hk_kthread: bool = false,
    hk_sched: bool = false,
    hk_tick: bool = false,
    hk_domain: bool = false,
    hk_wq: bool = false,           // Workqueue affinity
    hk_managed_irq: bool = false,
    hk_rcug: bool = false,         // RCU grace period
    // Zxyphor
    zxy_full_isolation: bool = false,
    _padding: u4 = 0,
};

/// CPU isolation configuration
pub const CpuIsolationConfig = struct {
    // Isolated CPUs
    isolated_mask: [32]u8,     // CPU bitmask (up to 256 CPUs)
    nr_isolated: u32,
    // Nohz full CPUs
    nohz_full_mask: [32]u8,
    nr_nohz_full: u32,
    // Housekeeping CPUs
    housekeeping_mask: [32]u8,
    nr_housekeeping: u32,
    // Flags
    flags: CpuIsolationFlags,
};

// ============================================================================
// Energy-Aware Scheduling (EAS)
// ============================================================================

/// Performance domain
pub const PerfDomain = struct {
    // CPU mask
    cpu_mask: [32]u8,
    nr_cpus: u32,
    // Capacity
    max_capacity: u32,       // Relative to 1024
    // Energy model
    nr_perf_states: u32,
    perf_states: [64]EnergyPerfState,
    // Flags
    flags: EasFlags,
};

/// Energy performance state
pub const EnergyPerfState = struct {
    frequency: u32,          // kHz
    power: u32,              // mW (at max utilization)
    cost: u64,               // Energy cost (computed)
    capacity: u32,           // Normalized capacity
    // Efficiency
    efficiency: u32,         // Perf/watt ratio
};

/// EAS flags
pub const EasFlags = packed struct {
    enabled: bool = false,
    em_registered: bool = false,
    misfit_task: bool = false,
    asymmetric: bool = false,
    // Zxyphor
    zxy_ml_prediction: bool = false,
    zxy_thermal_aware: bool = false,
    _padding: u2 = 0,
};

/// EAS placement decision
pub const EasPlacement = struct {
    prev_cpu: u32,
    best_cpu: u32,
    best_energy: u64,
    prev_energy: u64,
    energy_diff: i64,
    // Overutilized
    overutilized: bool,
    // Zxyphor
    zxy_thermal_headroom: u32,
};

// ============================================================================
// Pressure Stall Information (PSI)
// ============================================================================

/// PSI resource type
pub const PsiResource = enum(u8) {
    cpu = 0,
    memory = 1,
    io = 2,
    irq = 3,
};

/// PSI state
pub const PsiState = enum(u8) {
    none = 0,
    some = 1,
    full = 2,
};

/// PSI group stats
pub const PsiGroupStats = struct {
    // Average pressure (scaled by 100)
    avg10: [3]u32,           // PSI_SOME, PSI_FULL avg10 for cpu/mem/io
    avg60: [3]u32,
    avg300: [3]u32,
    total_us: [3]u64,        // Total stall time
};

/// PSI trigger
pub const PsiTrigger = struct {
    resource: PsiResource,
    state: PsiState,
    threshold_us: u64,       // Threshold in microseconds
    window_us: u64,          // Window in microseconds
    // Event
    event_count: u64,
    last_event_time: u64,
};

/// PSI CPU stats
pub const PsiCpuStats = struct {
    some_avg10: u32,         // Scaled by PSI_FIXED_1
    some_avg60: u32,
    some_avg300: u32,
    some_total: u64,         // Microseconds
    full_avg10: u32,
    full_avg60: u32,
    full_avg300: u32,
    full_total: u64,
};

/// PSI memory stats
pub const PsiMemStats = struct {
    some_avg10: u32,
    some_avg60: u32,
    some_avg300: u32,
    some_total: u64,
    full_avg10: u32,
    full_avg60: u32,
    full_avg300: u32,
    full_total: u64,
};

/// PSI IO stats (same structure)
pub const PsiIoStats = PsiMemStats;

// ============================================================================
// Utilization Clamping (uclamp)
// ============================================================================

/// Uclamp ID
pub const UclampId = enum(u8) {
    min = 0,            // UCLAMP_MIN
    max = 1,            // UCLAMP_MAX
};

/// Uclamp value (0-1024)
pub const UclampValue = struct {
    value: u16,          // 0-1024 (SCHED_CAPACITY_SCALE)
    bucket_id: u8,       // Bucket in uclamp rq
    active: bool,
    user_defined: bool,
};

/// Uclamp config
pub const UclampConfig = struct {
    min: u16,            // UCLAMP_MIN
    max: u16,            // UCLAMP_MAX
    // Per-task
    task_min: u16,
    task_max: u16,
    // System limits
    sched_util_clamp_min: u16,    // sysctl
    sched_util_clamp_max: u16,    // sysctl
    // Zxyphor
    zxy_auto_clamp: bool,
};

// ============================================================================
// Core Scheduling
// ============================================================================

/// Core scheduling tag
pub const CoreSchedTag = struct {
    cookie: u64,         // Process cookie for grouping
};

/// Core scheduling commands (prctl interface)
pub const CoreSchedCmd = enum(u32) {
    get = 0,
    create = 1,
    share_to = 2,
    share_from = 3,
};

/// Core scheduling scope
pub const CoreSchedScope = enum(u32) {
    thread = 0,
    thread_group = 1,
    process_group = 2,
};

/// Core scheduling stats
pub const CoreSchedStats = struct {
    nr_switches: u64,
    nr_forced_idle: u64,
    forced_idle_time_ns: u64,
    nr_cookies: u32,
};

// ============================================================================
// NUMA Scheduling
// ============================================================================

/// NUMA balancing mode
pub const NumaBalancingMode = packed struct {
    enabled: bool = false,
    memory_tiering: bool = false,
    // Zxyphor
    zxy_aggressive: bool = false,
    zxy_ml_hint: bool = false,
    _padding: u4 = 0,
};

/// NUMA scan config
pub const NumaScanConfig = struct {
    scan_delay_ms: u32,         // Initial scan delay
    scan_period_min_ms: u32,    // Min scan period
    scan_period_max_ms: u32,    // Max scan period
    scan_size_mb: u32,          // Pages to scan per period
};

/// Per-task NUMA stats
pub const TaskNumaStats = struct {
    // Faults
    total_faults: u64,
    current_node_faults: u64,
    // Per-node faults (for placement)
    node_faults: [64]u32,
    preferred_node: i32,
    // Migrate
    nr_migrations: u64,
    // Group
    numa_group_id: u64,
    nr_group_members: u32,
    // Placement
    scan_seq: u64,
    last_scan_ns: u64,
};

/// NUMA group
pub const NumaGroup = struct {
    id: u64,
    nr_tasks: u32,
    // Aggregated faults
    total_faults: u64,
    faults_per_node: [64]u32,
    // Active nodes
    active_nodes: u8,
    max_faults_node: i32,
};

// ============================================================================
// Load Balancing
// ============================================================================

/// Scheduling domain level
pub const SchedDomainLevel = enum(u8) {
    sibling = 0,        // SMT
    mc = 1,             // Multi-Core (L2 cache)
    die = 2,            // Die (L3 cache)
    cluster = 3,        // Cluster
    numa = 4,           // NUMA node
    system = 5,         // System-wide
};

/// Scheduling domain flags
pub const SchedDomainFlags = packed struct {
    load_balance: bool = false,
    balance_newidle: bool = false,
    balance_exec: bool = false,
    balance_fork: bool = false,
    balance_wake: bool = false,
    wake_affine: bool = false,
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
};

/// Load balance stats
pub const LoadBalanceStats = struct {
    // Counters
    lb_count: [7]u64,         // Per idle type
    lb_balanced: [7]u64,
    lb_failed: [7]u64,
    lb_imbalance: [7]u64,
    lb_gained: [7]u64,
    lb_hot_gained: [7]u64,
    lb_nobusyq: [7]u64,
    lb_nobusyg: [7]u64,
    // Active balancing
    alb_count: u64,
    alb_failed: u64,
    alb_pushed: u64,
    // Scheduling
    sbe_count: u64,           // balance_exec
    sbe_balanced: u64,
    sbe_pushed: u64,
    sbf_count: u64,           // balance_fork
    sbf_balanced: u64,
    sbf_pushed: u64,
    // Task wakeup
    ttwu_wake_remote: u64,
    ttwu_move_affine: u64,
    ttwu_move_balance: u64,
};

/// Imbalance calculation type
pub const ImbalanceType = enum(u8) {
    load = 0,
    util = 1,
    task = 2,
    misfit = 3,
};

/// CPU capacity
pub const CpuCapacity = struct {
    raw: u32,                    // Original capacity
    capacity: u32,               // Current capacity (freq scaling)
    capacity_orig: u32,          // Maximum capacity
    // Factors
    freq_factor: u32,            // Current/Max frequency ratio
    arch_scale_factor: u32,      // Architecture scaling
    thermal_pressure: u32,       // Thermal throttling
    // Zxyphor
    zxy_efficiency: u32,         // Perf/watt metric
};

// ============================================================================
// sched_ext (Extensible Scheduler)
// ============================================================================

/// sched_ext ops flags
pub const SchedExtOpsFlags = packed struct {
    enq_last: bool = false,
    enq_exiting: bool = false,
    switch_partial: bool = false,
    keep_builtin_idle: bool = false,
    // Zxyphor
    zxy_numa_aware: bool = false,
    zxy_energy_aware: bool = false,
    _padding: u2 = 0,
};

/// sched_ext dispatch flags
pub const SchedExtDispFlags = packed struct {
    enq_wakeup: bool = false,
    enq_head: bool = false,
    enq_last: bool = false,
    enq_preempt: bool = false,
    _padding: u4 = 0,
};

/// sched_ext DSQ (Dispatch Queue) ID
pub const SchedExtDsq = struct {
    pub const GLOBAL: u64 = 0;
    pub const LOCAL: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    pub const LOCAL_ON: u64 = 0xFFFF_FFFF_FFFF_FFFE;
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const SchedAdvancedSubsystem = struct {
    // CPU isolation
    nr_isolated_cpus: u32,
    nr_nohz_full_cpus: u32,
    // EAS
    eas_enabled: bool,
    nr_perf_domains: u32,
    total_energy_savings: u64,
    // PSI
    psi_enabled: bool,
    psi_cpu_some: u32,
    psi_mem_some: u32,
    psi_io_some: u32,
    // Uclamp
    uclamp_enabled: bool,
    // Core scheduling
    core_sched_enabled: bool,
    nr_core_sched_cookies: u32,
    // NUMA
    numa_balancing: NumaBalancingMode,
    nr_numa_migrations: u64,
    // Load balancing
    nr_load_balances: u64,
    nr_active_balances: u64,
    // sched_ext
    sched_ext_enabled: bool,
    sched_ext_name: [64]u8,
    // Zxyphor
    zxy_ml_scheduler: bool,
    zxy_thermal_aware: bool,
    initialized: bool,

    pub fn init() SchedAdvancedSubsystem {
        return SchedAdvancedSubsystem{
            .nr_isolated_cpus = 0,
            .nr_nohz_full_cpus = 0,
            .eas_enabled = true,
            .nr_perf_domains = 0,
            .total_energy_savings = 0,
            .psi_enabled = true,
            .psi_cpu_some = 0,
            .psi_mem_some = 0,
            .psi_io_some = 0,
            .uclamp_enabled = true,
            .core_sched_enabled = false,
            .nr_core_sched_cookies = 0,
            .numa_balancing = .{ .enabled = true },
            .nr_numa_migrations = 0,
            .nr_load_balances = 0,
            .nr_active_balances = 0,
            .sched_ext_enabled = false,
            .sched_ext_name = [_]u8{0} ** 64,
            .zxy_ml_scheduler = true,
            .zxy_thermal_aware = true,
            .initialized = false,
        };
    }
};
