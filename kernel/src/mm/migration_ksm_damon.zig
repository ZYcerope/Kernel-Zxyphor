// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Page Migration, KSM (Kernel Samepage Merging),
// NUMA Memory Policy, Memory Compaction, Balloon page allocation,
// DAMON (Data Access Monitoring), Page Idle Tracking
// More advanced than Linux 2026 memory management

const std = @import("std");

// ============================================================================
// Page Migration
// ============================================================================

/// Migration reason
pub const MigrationReason = enum(u8) {
    compaction = 0,
    memory_failure = 1,
    memory_hotplug = 2,
    syscall = 3,         // move_pages/mbind/migrate_pages
    mempolicy_mbind = 4,
    numa_misplaced = 5,
    cma_alloc = 6,
    // Zxyphor
    zxy_proactive = 10,
    zxy_thermal = 11,
};

/// Migration mode
pub const MigrationMode = enum(u8) {
    async_mode = 0,
    sync_light = 1,      // Light synchronization
    sync = 2,            // Full synchronization
    sync_no_copy = 3,    // For page exchange
};

/// Migration stats
pub const MigrationStats = struct {
    nr_succeeded: u64,
    nr_failed_busy: u64,
    nr_failed_other: u64,
    nr_thp_succeeded: u64,
    nr_thp_failed: u64,
    nr_thp_split: u64,
    // NUMA balancing
    nr_numa_hints: u64,
    nr_numa_migrate: u64,
    nr_numa_migrate_fail: u64,
    // Time
    total_migrate_time_ns: u64,
    avg_migrate_time_ns: u64,
    // Zxyphor
    zxy_proactive_migrations: u64,
};

/// move_pages() status
pub const MovePageStatus = enum(i32) {
    success = 0,
    eacces = -13,
    ebusy = -16,
    efault = -14,
    einval = -22,
    enodev = -19,
    enosys = -38,
    enomem = -12,
};

// ============================================================================
// KSM (Kernel Samepage Merging)
// ============================================================================

/// KSM state
pub const KsmState = enum(u8) {
    disabled = 0,
    running = 1,
    sleeping = 2,
};

/// KSM configuration
pub const KsmConfig = struct {
    // Scanning
    pages_to_scan: u32,       // Pages per scan cycle
    sleep_millisecs: u32,     // Sleep between scans
    // Merge behavior
    merge_across_nodes: bool, // Merge across NUMA nodes
    use_zero_pages: bool,     // Merge zero pages
    max_page_sharing: u32,    // Max KSM copies per page (default 256)
    // Advisor (auto-tuning)
    advisor_mode: KsmAdvisorMode,
    advisor_min_pages_to_scan: u64,
    advisor_max_pages_to_scan: u64,
    advisor_target_scan_time: u32, // Milliseconds
    advisor_max_cpu: u8,           // Percentage
    // Smart scan
    smart_scan: bool,
    // Zxyphor
    zxy_adaptive_scan: bool,
    zxy_content_aware: bool,
};

/// KSM advisor mode (auto-tuning)
pub const KsmAdvisorMode = enum(u8) {
    none = 0,
    scan_time = 1,
    // Zxyphor
    zxy_ml = 10,
};

/// KSM stats
pub const KsmStats = struct {
    pages_shared: u64,         // Total KSM pages
    pages_sharing: u64,        // How many virtual pages point to KSM
    pages_unshared: u64,       // Unique pages, not yet shared
    pages_volatile: u64,       // Changed too quickly for merging
    full_scans: u64,
    // madvise stats
    pages_skipped: u64,
    // Virtual
    general_profit: i64,       // Bytes saved
    // Time
    stable_node_chains: u64,
    stable_node_dups: u64,
    // Zxyphor
    zxy_dedup_ratio: u32,      // Percentage * 100
};

/// KSM per-process info (prctl)
pub const KsmProcessInfo = struct {
    enabled: bool,               // MADV_MERGEABLE set
    nr_ksm_zero_pages: u64,
    nr_ksm_pages: u64,
    // madvise type
    merge_type: KsmMergeType,
};

pub const KsmMergeType = enum(u8) {
    none = 0,
    madvise = 1,              // MADV_MERGEABLE
    process_auto = 2,         // prctl KSM enable
};

// ============================================================================
// NUMA Memory Policy
// ============================================================================

/// NUMA memory policy type
pub const NumaPolicy = enum(u8) {
    default = 0,         // MPOL_DEFAULT
    preferred = 1,       // MPOL_PREFERRED
    bind = 2,            // MPOL_BIND
    interleave = 3,      // MPOL_INTERLEAVE
    local = 4,           // MPOL_LOCAL
    preferred_many = 5,  // MPOL_PREFERRED_MANY
    weighted_interleave = 6, // MPOL_WEIGHTED_INTERLEAVE
    // Zxyphor
    zxy_adaptive = 10,
};

/// NUMA policy flags
pub const NumaPolicyFlags = packed struct {
    static_nodes: bool = false,   // MPOL_F_STATIC_NODES
    relative_nodes: bool = false, // MPOL_F_RELATIVE_NODES
    numa_balancing: bool = false, // MPOL_F_NUMA_BALANCING
    _padding: u5 = 0,
};

/// NUMA policy mode flags (for get_mempolicy)
pub const NumaGetFlags = packed struct {
    node: bool = false,           // MPOL_F_NODE
    addr: bool = false,           // MPOL_F_ADDR
    mems_allowed: bool = false,   // MPOL_F_MEMS_ALLOWED
    _padding: u5 = 0,
};

/// NUMA node memory info
pub const NumaNodeMemInfo = struct {
    node_id: u32,
    total_pages: u64,
    free_pages: u64,
    used_pages: u64,
    // Types
    anon_pages: u64,
    file_pages: u64,
    shmem_pages: u64,
    kernel_stack_bytes: u64,
    page_tables_bytes: u64,
    slab_reclaimable: u64,
    slab_unreclaimable: u64,
    // Hugepages
    hugepages_total: u64,
    hugepages_free: u64,
    hugepages_surp: u64,
    // Distance
    distances: [64]u8,     // Distance to other nodes
    nr_nodes: u8,
    // CPU mask
    cpu_mask: [32]u8,      // CPUs on this node (bitmap)
    // Zxyphor
    zxy_tier: u8,          // Memory tier (0=fastest)
    zxy_bandwidth_mbps: u32,
    zxy_latency_ns: u32,
};

/// Weighted interleave weights
pub const WeightedInterleave = struct {
    weights: [64]u8,       // Weight per NUMA node
    nr_nodes: u8,
};

// ============================================================================
// Memory Compaction
// ============================================================================

/// Compaction mode
pub const CompactMode = enum(u8) {
    none = 0,
    deferred = 1,
    async_mode = 2,
    sync_light = 3,
    sync_full = 4,
};

/// Compaction result
pub const CompactResult = enum(u8) {
    not_suitable = 0,
    skipped = 1,
    deferred = 2,
    no_suitable_page = 3,
    continue_compact = 4,
    partial_skipped = 5,
    complete = 6,
    success = 7,
};

/// Compaction priority
pub const CompactPriority = enum(u8) {
    sync_full = 0,
    sync_light = 1,
    async_prio = 2,
};

/// Compaction stats
pub const CompactionStats = struct {
    // Per-zone
    nr_migrate_scanned: u64,
    nr_free_scanned: u64,
    compact_isolated: u64,
    compact_stall: u64,
    compact_fail: u64,
    compact_success: u64,
    // Proactive
    compact_daemon_wake: u64,
    compact_daemon_migrate_scanned: u64,
    compact_daemon_free_scanned: u64,
    // Fragmentation index
    extfrag_index: i32,      // -1000 to 1000
    // Zxyphor
    zxy_proactive_compactions: u64,
};

/// Proactive compaction config
pub const ProactiveCompactConfig = struct {
    enabled: bool,
    threshold: u32,           // Fragmentation threshold (0-100)
    interval_ms: u32,
    // Zxyphor
    zxy_smart_compact: bool,
};

// ============================================================================
// DAMON (Data Access Monitoring)
// ============================================================================

/// DAMON operation set
pub const DamonOpsType = enum(u8) {
    vaddr = 0,           // Virtual address space
    paddr = 1,           // Physical address space
    fvaddr = 2,          // Filtered virtual address space
};

/// DAMON target
pub const DamonTarget = struct {
    pid: i32,            // 0 for physical
    nr_regions: u32,
    // Initial monitoring regions
    regions: [256]DamonRegion,
};

/// DAMON region
pub const DamonRegion = struct {
    start: u64,
    end: u64,
    nr_accesses: u32,     // Access count in sampling interval
    age: u32,             // Number of aggregation intervals
};

/// DAMON sampling attributes
pub const DamonAttrs = struct {
    sample_interval_us: u64,      // Sampling interval
    aggr_interval_us: u64,        // Aggregation interval
    update_interval_us: u64,      // Regions update interval
    min_nr_regions: u32,
    max_nr_regions: u32,
};

/// DAMOS (DAMON Operation Scheme) action
pub const DamosAction = enum(u8) {
    willneed = 0,
    cold = 1,
    pageout = 2,
    hugepage = 3,
    nohugepage = 4,
    lru_prio = 5,
    lru_deprio = 6,
    stat = 7,
    migrate_hot = 8,
    migrate_cold = 9,
    // Zxyphor
    zxy_tier_promote = 20,
    zxy_tier_demote = 21,
};

/// DAMOS watermarks
pub const DamosWatermarks = struct {
    metric: DamosWmarkMetric,
    check_interval_us: u64,
    high: u64,           // Start at this percent
    mid: u64,            // If above, keep going
    low: u64,            // If below, stop
};

pub const DamosWmarkMetric = enum(u8) {
    none = 0,
    free_mem_rate = 1,
};

/// DAMOS quota
pub const DamosQuota = struct {
    ms: u64,             // Time quota in milliseconds
    bytes: u64,          // Size quota in bytes
    reset_interval_ms: u64,
    // Priorities
    weight_sz: u32,
    weight_nr_accesses: u32,
    weight_age: u32,
};

/// DAMOS filter
pub const DamosFilter = struct {
    filter_type: DamosFilterType,
    matching: bool,       // true = include, false = exclude
    // Type-specific
    memcg_path: [256]u8,
    memcg_path_len: u16,
    addr_start: u64,
    addr_end: u64,
    target_idx: u32,
};

pub const DamosFilterType = enum(u8) {
    anon = 0,
    memcg = 1,
    young = 2,
    addr = 3,
    target = 4,
};

// ============================================================================
// Page Idle Tracking
// ============================================================================

/// Page idle flags
pub const PageIdleFlags = packed struct {
    idle: bool = false,
    young: bool = false,
    _padding: u6 = 0,
};

/// Page idle info
pub const PageIdleInfo = struct {
    pfn: u64,
    idle: bool,
    young: bool,
    // Time since last access
    idle_age_ms: u64,
};

// ============================================================================
// Memory Tiering
// ============================================================================

/// Memory tier
pub const MemoryTier = struct {
    id: u32,
    dev_attribute: u32,   // Abstract distance
    // Nodes in this tier
    nodes: [64]bool,
    nr_nodes: u8,
    // Performance
    bandwidth_mbps: u32,
    latency_ns: u32,
};

/// Memory tier device attribute
pub const MemTierDevAttr = enum(u32) {
    adistance_default = 512,
    adistance_dram = 128,
    adistance_pmem = 170,
    adistance_cxl = 250,
    // Zxyphor
    zxy_hbm = 64,
    zxy_nvram = 300,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const MmAdvancedSubsystem = struct {
    // Migration
    total_migrations: u64,
    migration_succeeded: u64,
    migration_failed: u64,
    // KSM
    ksm_state: KsmState,
    ksm_pages_shared: u64,
    ksm_pages_sharing: u64,
    ksm_scans: u64,
    // NUMA
    nr_numa_nodes: u8,
    numa_balancing_enabled: bool,
    nr_numa_migrate: u64,
    // Compaction
    nr_compactions: u64,
    nr_compact_success: u64,
    compact_proactive: bool,
    // DAMON
    damon_enabled: bool,
    nr_damon_targets: u32,
    nr_damos_actions: u64,
    // Memory tiering
    nr_memory_tiers: u8,
    // Zxyphor
    zxy_proactive_mm: bool,
    zxy_ml_placement: bool,
    initialized: bool,

    pub fn init() MmAdvancedSubsystem {
        return MmAdvancedSubsystem{
            .total_migrations = 0,
            .migration_succeeded = 0,
            .migration_failed = 0,
            .ksm_state = .disabled,
            .ksm_pages_shared = 0,
            .ksm_pages_sharing = 0,
            .ksm_scans = 0,
            .nr_numa_nodes = 1,
            .numa_balancing_enabled = true,
            .nr_numa_migrate = 0,
            .nr_compactions = 0,
            .nr_compact_success = 0,
            .compact_proactive = true,
            .damon_enabled = true,
            .nr_damon_targets = 0,
            .nr_damos_actions = 0,
            .nr_memory_tiers = 1,
            .zxy_proactive_mm = true,
            .zxy_ml_placement = true,
            .initialized = false,
        };
    }
};
