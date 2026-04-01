// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Memory Cgroup, OOM Killer, KASAN, KMEMLEAK,
// Memory Hotplug, CMA (Contiguous Memory Allocator), HugeTLB
// More advanced than Linux 2026 memory management

const std = @import("std");

// ============================================================================
// Memory Cgroup (memcg)
// ============================================================================

/// Memory cgroup counters
pub const MemcgCounter = enum(u8) {
    cache = 0,           // Page cache
    rss = 1,             // Anonymous pages (RSS)
    rss_huge = 2,        // Anonymous huge pages
    shmem = 3,           // Shared memory
    mapped_file = 4,     // Mapped file pages
    dirty = 5,           // Dirty pages
    writeback = 6,       // Under writeback
    swap = 7,            // Swap usage
    pgpgin = 8,          // Pages charged
    pgpgout = 9,         // Pages uncharged
    pgfault = 10,        // Page faults
    pgmajfault = 11,     // Major page faults
    inactive_anon = 12,
    active_anon = 13,
    inactive_file = 14,
    active_file = 15,
    unevictable = 16,
    slab_reclaimable = 17,
    slab_unreclaimable = 18,
    kernel_stack = 19,
    pagetables = 20,
    sec_pagetables = 21,
    percpu = 22,
    sock = 23,
    // Zxyphor
    zxy_compressed = 50,
    zxy_deduped = 51,
};

/// Memory cgroup limits
pub const MemcgLimits = struct {
    memory_limit: u64,       // memory.max (bytes, u64 max = unlimited)
    memory_low: u64,         // memory.low (best-effort protection)
    memory_min: u64,         // memory.min (hard protection)
    memory_high: u64,        // memory.high (throttle)
    swap_limit: u64,         // memory.swap.max
    swap_high: u64,          // memory.swap.high
    // Zxyphor
    zxy_compression_limit: u64,
};

/// Memory cgroup stats
pub const MemcgStats = struct {
    // Current usage
    usage_bytes: u64,        // memory.current
    swap_usage_bytes: u64,   // memory.swap.current
    // Watermarks
    max_usage_bytes: u64,
    failcnt: u64,            // Limit hit count
    // Per counter (indexed by MemcgCounter)
    counters: [52]u64,
    // Events
    oom_kill_count: u64,
    oom_group_kill: u64,
    high_events: u64,
    max_events: u64,
    low_events: u64,
    // Pressure
    some_pressure_us: u64,
    full_pressure_us: u64,
};

/// Memory cgroup config
pub const MemcgConfig = struct {
    limits: MemcgLimits,
    stats: MemcgStats,
    // OOM
    oom_group: bool,         // Kill entire cgroup on OOM
    oom_priority: i32,       // OOM priority (-1000 to 1000)
    // NUMA
    numa_stat_enabled: bool,
    // Zxyphor
    zxy_adaptive_limit: bool,
    zxy_predictive_reclaim: bool,
};

// ============================================================================
// OOM Killer
// ============================================================================

/// OOM killer type
pub const OomType = enum(u8) {
    global = 0,          // System-wide OOM
    memcg = 1,           // Memory cgroup OOM
    cpuset = 2,          // CPUset constrained OOM
    mempolicy = 3,       // NUMA mempolicy OOM
};

/// OOM priority adjustment
pub const OomScoreAdj = struct {
    score_adj: i16,      // -1000 to 1000
    // Special values
    pub const OOM_SCORE_ADJ_MIN: i16 = -1000;
    pub const OOM_SCORE_ADJ_MAX: i16 = 1000;
    pub const OOM_DISABLE: i16 = -1000;  // Never kill
};

/// OOM victim info
pub const OomVictimInfo = struct {
    pid: u32,
    tgid: u32,
    comm: [16]u8,
    uid: u32,
    oom_score: u32,          // Computed OOM score
    oom_score_adj: i16,
    total_vm_pages: u64,     // Total virtual memory
    rss_pages: u64,          // Resident set size
    pgtable_pages: u64,      // Page table pages
    swap_pages: u64,
    // Memory cgroup
    memcg_id: u64,
    memcg_usage: u64,
    memcg_limit: u64,
};

/// OOM control
pub const OomControl = struct {
    oom_type: OomType,
    // Policy
    panic_on_oom: bool,       // Panic instead of killing
    // Reaper
    nr_victims: u32,
    total_oom_kills: u64,
    last_oom_time_ns: u64,
    // Stats
    total_oom_events: u64,
    total_oom_kill_events: u64,
    total_oom_group_kill_events: u64,
    // Zxyphor
    zxy_predictive_oom: bool,
    zxy_oom_score_ml: bool,   // ML-based OOM scoring
};

// ============================================================================
// KASAN (Kernel Address Sanitizer)
// ============================================================================

/// KASAN mode
pub const KasanMode = enum(u8) {
    disabled = 0,
    generic = 1,        // Shadow memory based
    sw_tags = 2,        // Software memory tagging
    hw_tags = 3,        // Hardware memory tagging (ARMv8.5 MTE)
};

/// KASAN error type
pub const KasanErrorType = enum(u8) {
    out_of_bounds = 0,
    use_after_free = 1,
    use_after_scope = 2,
    slab_out_of_bounds = 3,
    global_out_of_bounds = 4,
    stack_out_of_bounds = 5,
    alloc_size_too_large = 6,
    double_free = 7,
    invalid_free = 8,
    wild_access = 9,
    null_ptr_deref = 10,
    // Zxyphor
    zxy_temporal_violation = 50,
};

/// KASAN report info
pub const KasanReport = struct {
    error_type: KasanErrorType,
    ip: u64,                 // Instruction pointer
    access_addr: u64,        // Accessed address
    access_size: u32,        // Access size
    is_write: bool,          // Write or read
    // Allocation info
    alloc_ip: u64,
    alloc_size: u64,
    free_ip: u64,            // If use-after-free
    // Stack trace (first 16 entries)
    stack_entries: [16]u64,
    stack_depth: u32,
    // Process info
    pid: u32,
    comm: [16]u8,
};

/// KASAN stats
pub const KasanStats = struct {
    mode: KasanMode,
    total_reports: u64,
    total_oob: u64,
    total_uaf: u64,
    total_double_free: u64,
    total_invalid_free: u64,
    quarantine_size: u64,
    shadow_start: u64,
    shadow_end: u64,
};

// ============================================================================
// KMEMLEAK
// ============================================================================

/// Kmemleak object state
pub const KmemleakState = enum(u8) {
    unreferenced = 0,
    reported = 1,
    not_leak = 2,        // False positive
    ignored = 3,
};

/// Kmemleak report
pub const KmemleakReport = struct {
    addr: u64,
    size: u64,
    state: KmemleakState,
    // Allocation
    alloc_ip: u64,
    alloc_time_ns: u64,
    alloc_pid: u32,
    alloc_comm: [16]u8,
    // Stack trace
    stack_entries: [16]u64,
    stack_depth: u32,
    // Counts
    ref_count: u32,
    excess_ref: u32,
};

/// Kmemleak control
pub const KmemleakControl = struct {
    enabled: bool,
    scanning: bool,
    // Stats
    total_objects: u64,
    total_reported: u64,
    total_scans: u64,
    last_scan_time_ns: u64,
    last_scan_duration_ns: u64,
    // Config
    scan_interval_ms: u32,
    min_count: u32,          // Minimum scan cycles before reporting
};

// ============================================================================
// Memory Hotplug
// ============================================================================

/// Memory block state
pub const MemBlockState = enum(u8) {
    offline = 0,
    going_offline = 1,
    online = 2,
    going_online = 3,
};

/// Memory block online type
pub const MemOnlineType = enum(u8) {
    online_kernel = 0,   // Add to kernel zone (ZONE_NORMAL)
    online_movable = 1,  // Add to ZONE_MOVABLE
    online_keep = 2,     // Keep existing zone
};

/// Memory block descriptor
pub const MemoryBlock = struct {
    phys_index: u64,         // Physical section number
    state: MemBlockState,
    online_type: MemOnlineType,
    // Phys info
    start_phys_addr: u64,
    size_bytes: u64,
    nr_pages: u64,
    zone_id: u8,
    nid: u32,               // NUMA node ID
    // Flags
    removable: bool,
    // Stats
    nr_present_pages: u64,
    nr_managed_pages: u64,
};

/// Hotplug event type
pub const MemHotplugEvent = enum(u8) {
    going_online = 0,
    cancel_online = 1,
    online = 2,
    going_offline = 3,
    cancel_offline = 4,
    offline = 5,
};

/// Hotplug stats
pub const MemHotplugStats = struct {
    nr_sections_online: u32,
    nr_sections_offline: u32,
    total_online_events: u64,
    total_offline_events: u64,
    total_online_failures: u64,
    total_offline_failures: u64,
    last_event_time_ns: u64,
};

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

/// CMA area descriptor
pub const CmaArea = struct {
    name: [32]u8,
    base_pfn: u64,          // Base page frame number
    count: u64,             // Number of pages
    order_per_bit: u32,     // Granularity
    // Bitmap
    bitmap_count: u64,      // Number of bits in bitmap
    // Stats
    nr_pages_total: u64,
    nr_pages_used: u64,
    nr_pages_peak: u64,
    nr_alloc_success: u64,
    nr_alloc_fail: u64,
    nr_release: u64,
    // Zxyphor
    zxy_defrag_enabled: bool,
};

/// CMA stats
pub const CmaGlobalStats = struct {
    nr_areas: u32,
    total_pages: u64,
    total_used_pages: u64,
    total_allocs: u64,
    total_frees: u64,
    total_alloc_failures: u64,
};

// ============================================================================
// HugeTLB
// ============================================================================

/// Huge page size
pub const HugePageSize = enum(u8) {
    size_2mb = 0,
    size_1gb = 1,
    size_16kb = 2,       // ARM
    size_64kb = 3,       // ARM
    size_32mb = 4,       // ARM
    size_512mb = 5,      // ARM
    size_16gb = 6,       // PPC
};

/// HugeTLB pool info
pub const HugeTlbPool = struct {
    page_size: HugePageSize,
    page_size_bytes: u64,
    // Counts
    nr_hugepages: u64,       // Total in pool
    free_hugepages: u64,     // Free in pool
    resv_hugepages: u64,     // Reserved
    surplus_hugepages: u64,  // Over-allocated
    // Limits
    nr_overcommit_hugepages: u64,
    // NUMA
    per_node_hugepages: [256]u64,
    per_node_free: [256]u64,
    // Stats
    total_allocs: u64,
    total_frees: u64,
    total_alloc_failures: u64,
    total_fault_allocs: u64,
    total_fault_fallbacks: u64,
};

/// HugeTLB cgroup
pub const HugeTlbCgroup = struct {
    limit_bytes: u64,        // Max huge page usage
    usage_bytes: u64,        // Current usage
    max_usage_bytes: u64,    // Peak usage
    failcnt: u64,            // Limit hit count
    rsvd_limit_bytes: u64,
    rsvd_usage_bytes: u64,
    rsvd_max_usage_bytes: u64,
    rsvd_failcnt: u64,
};

// ============================================================================
// Transparent Huge Pages (THP)
// ============================================================================

/// THP defrag mode
pub const ThpDefragMode = enum(u8) {
    always = 0,
    defer_mode = 1,      // Defer + madvise
    defer_madvise = 2,
    madvise = 3,
    never = 4,
};

/// THP config
pub const ThpConfig = struct {
    enabled: ThpEnabledMode,
    defrag: ThpDefragMode,
    use_zero_page: bool,
    khugepaged_scan_sleep_ms: u32,
    khugepaged_alloc_sleep_ms: u32,
    khugepaged_pages_to_scan: u32,
    khugepaged_max_ptes_none: u32,
    khugepaged_max_ptes_swap: u32,
    khugepaged_max_ptes_shared: u32,
};

pub const ThpEnabledMode = enum(u8) {
    always = 0,
    madvise = 1,
    never = 2,
};

/// THP stats
pub const ThpStats = struct {
    nr_thp: u64,                // 2MB pages in use
    nr_thp_split: u64,          // Split events
    nr_thp_collapse: u64,       // Collapse events
    nr_thp_fault_alloc: u64,    // Fault allocations
    nr_thp_fault_fallback: u64, // Fault fallbacks
    nr_thp_collapse_alloc: u64,
    nr_thp_collapse_alloc_failed: u64,
    nr_thp_file: u64,           // File THP
    nr_thp_file_alloc: u64,
    nr_thp_file_fallback: u64,
    nr_thp_swpout: u64,         // THP swap out
    nr_thp_swpout_fallback: u64,
    // khugepaged
    khugepaged_pages_collapsed: u64,
    khugepaged_full_scans: u64,
    khugepaged_scan_pages: u64,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const MemMgmtSubsystem = struct {
    // Memcg
    nr_memcg: u32,
    // OOM
    oom_control: OomControl,
    // Sanitizers
    kasan_stats: KasanStats,
    kmemleak_control: KmemleakControl,
    // Hotplug
    hotplug_stats: MemHotplugStats,
    // CMA
    cma_stats: CmaGlobalStats,
    // HugeTLB
    nr_huge_page_pools: u32,
    // THP
    thp_config: ThpConfig,
    thp_stats: ThpStats,
    // Zxyphor
    zxy_predictive_reclaim: bool,
    zxy_ml_oom_scoring: bool,
    initialized: bool,

    pub fn init() MemMgmtSubsystem {
        return MemMgmtSubsystem{
            .nr_memcg = 0,
            .oom_control = std.mem.zeroes(OomControl),
            .kasan_stats = std.mem.zeroes(KasanStats),
            .kmemleak_control = std.mem.zeroes(KmemleakControl),
            .hotplug_stats = std.mem.zeroes(MemHotplugStats),
            .cma_stats = std.mem.zeroes(CmaGlobalStats),
            .nr_huge_page_pools = 0,
            .thp_config = std.mem.zeroes(ThpConfig),
            .thp_stats = std.mem.zeroes(ThpStats),
            .zxy_predictive_reclaim = true,
            .zxy_ml_oom_scoring = true,
            .initialized = false,
        };
    }
};
