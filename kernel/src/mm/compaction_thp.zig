// Zxyphor Kernel - Memory Compaction & THP (Transparent Huge Pages)
// Page compaction scanner (migration/free), compaction control
// THP allocation, defrag modes, split/collapse, khugepaged
// Page migration between zones/nodes, balloon compaction
// Proactive compaction, compaction events/tracing
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Compaction Zones & Migration Types
// ============================================================================

pub const CompactResult = enum(u8) {
    not_suitable_zone = 0,
    skipped = 1,
    deferred = 2,
    no_suitable_page = 3,
    continue_scan = 4,
    complete = 5,
    partial_skipped = 6,
    contended = 7,
    success = 8,
};

pub const CompactPriority = enum(u8) {
    async_compact = 0,     // background compaction
    sync_light = 1,        // most operations non-blocking
    sync_full = 2,         // all operations blocking (direct reclaim)
};

pub const MigrateMode = enum(u8) {
    async_mode = 0,
    sync_light = 1,
    sync = 2,
    sync_no_copy = 3,
};

pub const MigrateReason = enum(u8) {
    compaction = 0,
    memory_failure = 1,
    memory_hotplug = 2,
    syscall = 3,
    mempolicy = 4,
    numa_misplaced = 5,
    longterm_pin = 6,
    demotion = 7,
    contig_range = 8,
};

pub const PageMobilityType = enum(u8) {
    unmovable = 0,
    movable = 1,
    reclaimable = 2,
    highatomic = 3,
    cma = 4,
    isolate = 5,
};

// ============================================================================
// Compaction Control
// ============================================================================

pub const CompactControl = struct {
    // Scanner positions
    migrate_pfn: u64,
    free_pfn: u64,
    // Zone info
    zone_start_pfn: u64,
    zone_end_pfn: u64,
    zone_idx: u8,
    zone_name: [16]u8,
    node_id: u8,
    // Target
    order: u8,
    migratetype: PageMobilityType,
    gfp_mask: u32,
    priority: CompactPriority,
    // Results
    total_migrate_scanned: u64,
    total_free_scanned: u64,
    nr_migratepages: u32,
    nr_freepages: u32,
    contended: bool,
    // Settings
    whole_zone: bool,
    ignore_skip_hint: bool,
    ignore_block_suitable: bool,
    direct_compaction: bool,
    proactive_compaction: bool,
    alloc_flags: u32,
    classzone_idx: u8,
    // Tracing
    result: CompactResult,
    compact_start_time: u64,
    compact_end_time: u64,
};

// ============================================================================
// Compaction Scanner
// ============================================================================

pub const MigrationScanner = struct {
    pfn: u64,
    end_pfn: u64,
    nr_scanned: u64,
    nr_isolated: u32,
    skipped_pages: u64,
    pageblock_skip: bool,
    no_isolation: bool,
    fast_search_fail: u32,
    // scanner state
    scan_start: u64,
    scan_limit: u64,
    scan_order: u8,
};

pub const FreeScanner = struct {
    pfn: u64,
    end_pfn: u64,
    nr_scanned: u64,
    nr_isolated: u32,
    strict: bool,
    pageblock_skip: bool,
    fast_search_fail: u32,
    scan_start: u64,
    scan_order: u8,
};

pub const CompactStats = struct {
    compact_stall: u64,
    compact_success: u64,
    compact_fail: u64,
    compact_pages_moved: u64,
    compact_pagemigrate_failed: u64,
    compact_isolated: u64,
    compact_free_scanned: u64,
    compact_migrate_scanned: u64,
    compact_daemon_wake: u64,
    compact_daemon_migrate_scanned: u64,
    compact_daemon_free_scanned: u64,
    // proactive
    proactive_compact_trigger: u64,
    proactive_compact_success: u64,
};

// ============================================================================
// Proactive Compaction
// ============================================================================

pub const ProactiveCompaction = struct {
    enabled: bool,
    wakeup_kcompactd: bool,
    proactiveness: u32,    // sysctl value 0-100
    score: u32,            // fragmentation score
    score_threshold: u32,
    interval_ms: u64,
    last_compact_time: u64,
    // per-zone fragmentation scores
    zone_scores: [8]ZoneFragScore,
    zone_count: u8,
};

pub const ZoneFragScore = struct {
    zone_idx: u8,
    node_id: u8,
    score: u32,
    suitable: bool,
};

// ============================================================================
// Page Migration
// ============================================================================

pub const MigrationEntry = struct {
    old_pfn: u64,
    new_pfn: u64,
    mapping: u64,       // address_space pointer
    index: u64,         // page cache index
    page_flags: u64,
    success: bool,
    reason: MigrateReason,
    mode: MigrateMode,
};

pub const MigrationTargetControl = struct {
    nid: i32,
    nmask: ?*u64,      // nodemask
    gfp_mask: u32,
    reason: MigrateReason,
    alloc_flags: u32,
};

pub const NUMABalancingInfo = struct {
    total_numa_faults: u64,
    numa_faults_locality: [3]u64,
    numa_group_id: u32,
    last_task_numa_placement: u64,
    last_sum_exec_runtime: u64,
    numa_scan_seq: u32,
    numa_scan_period: u32,
    numa_scan_period_max: u32,
    numa_preferred_nid: i32,
    numa_migrate_retry: u64,
    total_numa_migrate_hot: u64,
    total_numa_migrate_fail: u64,
};

// ============================================================================
// THP (Transparent Huge Pages)
// ============================================================================

pub const ThpDefrag = enum(u8) {
    always = 0,
    defer = 1,
    defer_madvise = 2,
    madvise = 3,
    never = 4,
};

pub const ThpEnabled = enum(u8) {
    always = 0,
    madvise = 1,
    never = 2,
};

pub const ThpSwapEnabled = enum(u8) {
    always = 0,
    never = 1,
};

pub const ThpShmemEnabled = enum(u8) {
    always = 0,
    within_size = 1,
    advise = 2,
    never = 3,
    deny = 4,
    force = 5,
};

pub const HugepageSize = enum(u8) {
    size_2mb = 0,
    size_1gb = 1,
};

pub const ThpConfig = struct {
    enabled: ThpEnabled,
    defrag: ThpDefrag,
    shmem_enabled: ThpShmemEnabled,
    use_zero_page: bool,
    khugepaged_defrag: bool,
    scan_sleep_ms: u32,
    alloc_sleep_ms: u32,
    pages_to_scan: u32,
    max_ptes_none: u32,
    max_ptes_swap: u32,
    max_ptes_shared: u32,
    pages_collapsed: u64,
    full_scans: u64,
};

// ============================================================================
// khugepaged
// ============================================================================

pub const KhugepagedConfig = struct {
    // scanner config
    scan_sleep_millisecs: u32,
    alloc_sleep_millisecs: u32,
    pages_to_scan: u32,
    max_ptes_none: u32,
    max_ptes_swap: u32,
    max_ptes_shared: u32,
};

pub const KhugepagedScanState = struct {
    current_mm: u64,         // current mm_struct being scanned
    current_address: u64,    // address within current mm
    scan_progress: u64,
    // stats
    pages_scanned: u64,
    pages_collapsed: u64,
    full_scans: u64,
    hpage_alloc_failed: u64,
    scan_abort: u64,
    scan_pmd_mapped: u64,
    // collapse stats
    collapse_alloc: u64,
    collapse_alloc_failed: u64,
    collapse_mmap_locked: u64,
    result: CollapseResult,
};

pub const CollapseResult = enum(u8) {
    success = 0,
    again = 1,
    fail = 2,
    mmap_locked = 3,
    nohuge = 4,
    exceed_none_pte = 5,
    exceed_swap_pte = 6,
    exceed_shared_pte = 7,
    pfn_not_present = 8,
    no_mem = 9,
};

// ============================================================================
// THP Split / Collapse
// ============================================================================

pub const SplitReason = enum(u8) {
    unmap = 0,
    page_lock = 1,
    deferred_list = 2,
    truncate = 3,
    migration = 4,
    dirty_limit = 5,
    mremap = 6,
    mad_advise = 7,
    reclaim = 8,
    swap = 9,
    alloc_failed = 10,
    mm_huge_pmd = 11,
};

pub const SplitStats = struct {
    split_huge_page: u64,
    split_huge_page_failed: u64,
    split_huge_pmd: u64,
    split_deferred: u64,
    thp_fault_alloc: u64,
    thp_fault_fallback: u64,
    thp_fault_fallback_charge: u64,
    thp_collapse_alloc: u64,
    thp_collapse_alloc_failed: u64,
    thp_file_alloc: u64,
    thp_file_fallback: u64,
    thp_file_fallback_charge: u64,
    thp_file_mapped: u64,
    thp_swpout: u64,
    thp_swpout_fallback: u64,
    thp_zero_page_alloc: u64,
    thp_zero_page_alloc_failed: u64,
};

// ============================================================================
// Folio / Compound Page Management
// ============================================================================

pub const FolioOrder = enum(u8) {
    order_0 = 0,   // 4KB
    order_1 = 1,   // 8KB
    order_2 = 2,   // 16KB
    order_3 = 3,   // 32KB
    order_4 = 4,   // 64KB
    order_5 = 5,   // 128KB
    order_6 = 6,   // 256KB
    order_7 = 7,   // 512KB
    order_8 = 8,   // 1MB
    order_9 = 9,   // 2MB (PMD mapped)
    order_10 = 10, // 4MB
    order_18 = 18, // 1GB (PUD mapped)
};

pub const FolioFlags = packed struct(u64) {
    locked: bool = false,
    referenced: bool = false,
    uptodate: bool = false,
    dirty: bool = false,
    lru: bool = false,
    active: bool = false,
    workingset: bool = false,
    waiters: bool = false,
    error: bool = false,
    slab: bool = false,
    owner_priv1: bool = false,
    private: bool = false,
    private2: bool = false,
    writeback: bool = false,
    head: bool = false,
    mappedtodisk: bool = false,
    reclaim: bool = false,
    swapbacked: bool = false,
    unevictable: bool = false,
    mlocked: bool = false,
    uncached: bool = false,
    hwpoison: bool = false,
    young: bool = false,
    idle: bool = false,
    arch_1: bool = false,
    arch_2: bool = false,
    arch_3: bool = false,
    reported: bool = false,
    has_hpage_pin: bool = false,
    large_rmappable: bool = false,
    _pad: u34 = 0,
};

pub const FolioInfo = struct {
    pfn: u64,
    order: u8,
    flags: FolioFlags,
    mapping: u64,
    index: u64,
    mapcount: i32,
    refcount: i32,
    memcg: u64,
    lru_gen: u16,
    lru_refs: u8,
};

// ============================================================================
// Balloon Compaction (for virtio-balloon)
// ============================================================================

pub const BalloonCompaction = struct {
    enabled: bool,
    migrated_pages: u64,
    isolated_pages: u32,
    compacted_pages: u64,
    error_count: u32,
};

// ============================================================================
// Memory Hot-remove Compaction
// ============================================================================

pub const HotremoveCompaction = struct {
    target_pfn: u64,
    end_pfn: u64,
    migrated: u64,
    failed: u64,
    retries: u32,
    busy_pages: u32,
    unmovable_pages: u32,
    result: HotremoveResult,
};

pub const HotremoveResult = enum(u8) {
    success = 0,
    busy = 1,
    nosys = 2,
    nomem = 3,
    io = 4,
};

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

pub const CmaArea = struct {
    base_pfn: u64,
    count: u64,
    bitmap: u64,
    order_per_bit: u32,
    name: [64]u8,
    allocations_success: u64,
    allocations_fail: u64,
};

pub const CmaConfig = struct {
    area_count: u32,
    total_pages: u64,
    fixed_areas: bool,
};

// ============================================================================
// Memory Policy (mempolicy)
// ============================================================================

pub const MempolicyMode = enum(u8) {
    default = 0,
    preferred = 1,
    bind = 2,
    interleave = 3,
    local = 4,
    preferred_many = 5,
    weighted_interleave = 6,
};

pub const MempolicyFlags = packed struct(u8) {
    static_nodes: bool = false,
    relative_nodes: bool = false,
    f_moron: bool = false,
    _pad: u5 = 0,
};

pub const Mempolicy = struct {
    mode: MempolicyMode,
    flags: MempolicyFlags,
    nodemask: [4]u64,   // up to 256 nodes
    refcount: u32,
    home_node: i32,
    // weighted interleave
    interleave_weights: [64]u8,
    interleave_next: u8,
};

// ============================================================================
// Page Reclaim Watermarks
// ============================================================================

pub const WatermarkLevel = enum(u8) {
    min = 0,
    low = 1,
    high = 2,
    promo = 3,
};

pub const ZoneWatermarks = struct {
    min: u64,
    low: u64,
    high: u64,
    promo: u64,
    // boost
    watermark_boost: u32,
    // present/managed
    managed_pages: u64,
    present_pages: u64,
    lowmem_reserve: [8]u64,
};

// ============================================================================
// Compaction / THP Subsystem Manager
// ============================================================================

pub const CompactionSubsystemManager = struct {
    // THP config
    thp_config: ThpConfig,
    khugepaged_config: KhugepagedConfig,
    khugepaged_state: KhugepagedScanState,
    split_stats: SplitStats,
    // Compaction config
    compact_stats: CompactStats,
    proactive: ProactiveCompaction,
    // Memory policy
    default_policy: Mempolicy,
    // CMA
    cma_config: CmaConfig,
    // NUMA balancing
    numa_balancing_enabled: bool,
    numa_balancing_scan_delay_ms: u32,
    numa_balancing_scan_period_min_ms: u32,
    numa_balancing_scan_period_max_ms: u32,
    numa_balancing_scan_size_mb: u32,
    // State
    kcompactd_running: bool,
    khugepaged_running: bool,
    initialized: bool,

    pub fn init() CompactionSubsystemManager {
        return CompactionSubsystemManager{
            .thp_config = ThpConfig{
                .enabled = .always,
                .defrag = .madvise,
                .shmem_enabled = .never,
                .use_zero_page = true,
                .khugepaged_defrag = true,
                .scan_sleep_ms = 10000,
                .alloc_sleep_ms = 60000,
                .pages_to_scan = 4096,
                .max_ptes_none = 511,
                .max_ptes_swap = 64,
                .max_ptes_shared = 256,
                .pages_collapsed = 0,
                .full_scans = 0,
            },
            .khugepaged_config = KhugepagedConfig{
                .scan_sleep_millisecs = 10000,
                .alloc_sleep_millisecs = 60000,
                .pages_to_scan = 4096,
                .max_ptes_none = 511,
                .max_ptes_swap = 64,
                .max_ptes_shared = 256,
            },
            .khugepaged_state = KhugepagedScanState{
                .current_mm = 0,
                .current_address = 0,
                .scan_progress = 0,
                .pages_scanned = 0,
                .pages_collapsed = 0,
                .full_scans = 0,
                .hpage_alloc_failed = 0,
                .scan_abort = 0,
                .scan_pmd_mapped = 0,
                .collapse_alloc = 0,
                .collapse_alloc_failed = 0,
                .collapse_mmap_locked = 0,
                .result = .success,
            },
            .split_stats = std.mem.zeroes(SplitStats),
            .compact_stats = std.mem.zeroes(CompactStats),
            .proactive = ProactiveCompaction{
                .enabled = true,
                .wakeup_kcompactd = false,
                .proactiveness = 20,
                .score = 0,
                .score_threshold = 50,
                .interval_ms = 5000,
                .last_compact_time = 0,
                .zone_scores = [_]ZoneFragScore{.{
                    .zone_idx = 0,
                    .node_id = 0,
                    .score = 0,
                    .suitable = false,
                }} ** 8,
                .zone_count = 0,
            },
            .default_policy = Mempolicy{
                .mode = .default,
                .flags = .{},
                .nodemask = [_]u64{0} ** 4,
                .refcount = 1,
                .home_node = -1,
                .interleave_weights = [_]u8{1} ** 64,
                .interleave_next = 0,
            },
            .cma_config = CmaConfig{
                .area_count = 0,
                .total_pages = 0,
                .fixed_areas = false,
            },
            .numa_balancing_enabled = true,
            .numa_balancing_scan_delay_ms = 1000,
            .numa_balancing_scan_period_min_ms = 1000,
            .numa_balancing_scan_period_max_ms = 60000,
            .numa_balancing_scan_size_mb = 256,
            .kcompactd_running = false,
            .khugepaged_running = false,
            .initialized = true,
        };
    }
};
