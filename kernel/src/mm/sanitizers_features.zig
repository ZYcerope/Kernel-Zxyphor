// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Advanced Memory Management: KASAN, KMSAN, KCSAN,
// userfaultfd, CMA, HugeTLB, Memory Hotplug, DAMON, Memory Cgroup internals, zswap/zram
// More advanced than Linux 2026 memory subsystem sanitizers and features

const std = @import("std");

// ============================================================================
// KASAN (Kernel Address SANitizer)
// ============================================================================

pub const KASAN_SHADOW_SCALE_SHIFT: u32 = 3;
pub const KASAN_SHADOW_SCALE_SIZE: u64 = 1 << KASAN_SHADOW_SCALE_SHIFT;
pub const KASAN_SHADOW_OFFSET: u64 = 0xDFFF000000000000;
pub const KASAN_PAGE_FREE: u8 = 0xFF;
pub const KASAN_SLAB_FREE: u8 = 0xFB;
pub const KASAN_SLAB_REDZONE: u8 = 0xFC;
pub const KASAN_GLOBAL_REDZONE: u8 = 0xF9;
pub const KASAN_STACK_LEFT: u8 = 0xF1;
pub const KASAN_STACK_MID: u8 = 0xF2;
pub const KASAN_STACK_RIGHT: u8 = 0xF3;
pub const KASAN_USE_AFTER_SCOPE: u8 = 0xF8;
pub const KASAN_ALLOCA_LEFT: u8 = 0xCA;
pub const KASAN_ALLOCA_RIGHT: u8 = 0xCB;
pub const KASAN_SLAB_FREETRACK: u8 = 0xFA;
pub const KASAN_VMALLOC_INVALID: u8 = 0xF7;

pub const KasanMode = enum(u8) {
    disabled = 0,
    generic = 1,      // Shadow-based (compile-time)
    sw_tags = 2,      // Software tag-based
    hw_tags = 3,      // Hardware tag-based (MTE/ARM64)
};

pub const KasanReportType = enum(u8) {
    out_of_bounds = 0,
    slab_out_of_bounds = 1,
    use_after_free = 2,
    use_after_scope = 3,
    stack_out_of_bounds = 4,
    global_out_of_bounds = 5,
    vmalloc_out_of_bounds = 6,
    user_memory_access = 7,
    wild_memory_access = 8,
    double_free = 9,
    invalid_free = 10,
};

pub const KasanReport = struct {
    report_type: KasanReportType,
    access_addr: u64,
    access_size: u64,
    is_write: bool,
    ip: u64,           // Instruction pointer
    shadow_val: u8,
    alloc_track: KasanTrack,
    free_track: KasanTrack,
    // Context
    pid: u32,
    comm: [16]u8,
    timestamp: u64,
};

pub const KasanTrack = struct {
    pid: u32,
    stack_entries: [32]u64,
    nr_entries: u32,
    timestamp: u64,
};

pub const KasanState = struct {
    mode: KasanMode,
    enabled: bool,
    fault_mode: u8,     // 0=report, 1=panic
    multi_shot: bool,   // Report all or just first
    shadow_start: u64,
    shadow_end: u64,
    // Stats
    total_reports: u64,
    oob_reads: u64,
    oob_writes: u64,
    uaf_reads: u64,
    uaf_writes: u64,
    // Quarantine (delayed free)
    quarantine_size: u64,
    quarantine_max: u64,
};

// ============================================================================
// KMSAN (Kernel Memory SANitizer) - Uninitialized Memory Detector
// ============================================================================

pub const KMSAN_SHADOW_MASK: u64 = 0xDFFE000000000000;
pub const KMSAN_ORIGIN_MASK: u64 = 0xDFFD000000000000;

pub const KmsanOriginType = enum(u8) {
    invalid = 0,
    alloc = 1,         // Allocated but not initialized
    stack = 2,         // Stack variable
    instrumentation = 3,
};

pub const KmsanState = struct {
    enabled: bool,
    // Shadow: tracks which bytes are initialized (0=init, non-0=uninit)
    shadow_start: u64,
    shadow_end: u64,
    // Origin: tracks where uninit data came from
    origin_start: u64,
    origin_end: u64,
    // Stats
    total_reports: u64,
    use_of_uninit: u64,
    suppress_count: u64,
};

// ============================================================================
// KCSAN (Kernel Concurrency SANitizer) - Data Race Detector
// ============================================================================

pub const KCSAN_MAX_WATCHPOINTS: u32 = 65536;

pub const KcsanAccessType = enum(u8) {
    read = 0,
    write = 1,
    compound_read = 2,  // Read in compound (read-write)
    compound_write = 3,
    atomic = 4,
    scoped = 5,
};

pub const KcsanReport = struct {
    addr: u64,
    size: u32,
    access_type1: KcsanAccessType,
    access_type2: KcsanAccessType,
    ip1: u64,
    ip2: u64,
    cpu1: u32,
    cpu2: u32,
    pid1: u32,
    pid2: u32,
    timestamp: u64,
};

pub const KcsanWatchpoint = struct {
    addr: u64,
    size: u32,
    access_type: KcsanAccessType,
    cpu: u32,
    active: bool,
};

pub const KcsanState = struct {
    enabled: bool,
    watchpoints: [KCSAN_MAX_WATCHPOINTS]KcsanWatchpoint,
    nr_active: u32,
    // Config
    skip_rate: u32,     // Check 1 in N accesses
    udelay: u32,        // Delay to detect race (us)
    // Stats
    total_reports: u64,
    races_detected: u64,
    watchpoints_hit: u64,
};

// ============================================================================
// userfaultfd
// ============================================================================

pub const UFFD_API: u64 = 0xAA;

pub const UffdFeature = enum(u64) {
    pagefault_flag_wp = 1 << 0,
    event_fork = 1 << 1,
    event_remap = 1 << 2,
    event_remove = 1 << 3,
    event_unmap = 1 << 4,
    missing_hugetlbfs = 1 << 5,
    missing_shmem = 1 << 6,
    sigbus = 1 << 7,
    thread_id = 1 << 8,
    minor_hugetlbfs = 1 << 9,
    minor_shmem = 1 << 10,
    exact_address = 1 << 11,
    wp_hugetlbfs_shmem = 1 << 12,
    wp_unpopulated = 1 << 13,
    poison = 1 << 14,
    wp_async = 1 << 15,
    move = 1 << 16,
};

pub const UffdMsg = struct {
    event: UffdEvent,
    arg: UffdMsgArg,
};

pub const UffdEvent = enum(u8) {
    pagefault = 0x12,
    fork = 0x13,
    remap = 0x14,
    remove = 0x15,
    unmap = 0x16,
};

pub const UffdMsgArg = union {
    pagefault: UffdPagefault,
    fork: UffdFork,
    remap: UffdRemap,
    remove: UffdRemove,
};

pub const UffdPagefault = struct {
    flags: u64,
    address: u64,
    feat_tid: u32,
};

pub const UffdFork = struct {
    ufd: i32,
};

pub const UffdRemap = struct {
    from: u64,
    to: u64,
    len: u64,
};

pub const UffdRemove = struct {
    start: u64,
    end: u64,
};

pub const UffdCtx = struct {
    features: u64,
    registered_ranges: [64]UffdRange,
    nr_ranges: u32,
    msg_queue: [256]UffdMsg,
    msg_head: u32,
    msg_tail: u32,
    wp_mode: u8,     // 0=none, 1=sync, 2=async
    // Stats
    total_faults: u64,
    missing_faults: u64,
    minor_faults: u64,
    wp_faults: u64,
};

pub const UffdRange = struct {
    start: u64,
    end: u64,
    mode: u64,     // UFFDIO_REGISTER_MODE_*
};

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

pub const CMA_MAX_AREAS: u32 = 32;

pub const CmaArea = struct {
    name: [64]u8,
    name_len: u8,
    base_pfn: u64,
    count: u64,        // Pages
    order_per_bit: u32,
    bitmap: [*]u64,    // Allocation bitmap
    bitmap_len: u32,
    // Stats
    alloc_pages: u64,
    alloc_success: u64,
    alloc_fail: u64,
    release_pages: u64,
};

pub const CmaSubsystem = struct {
    areas: [CMA_MAX_AREAS]?CmaArea,
    nr_areas: u32,
    default_area: u32,

    pub fn total_pages(self: *const CmaSubsystem) u64 {
        var total: u64 = 0;
        for (self.areas) |maybe_area| {
            if (maybe_area) |area| {
                total += area.count;
            }
        }
        return total;
    }
};

// ============================================================================
// HugeTLB
// ============================================================================

pub const HPAGE_SHIFT: u32 = 21;  // 2MB
pub const HPAGE_SIZE: u64 = 1 << HPAGE_SHIFT;
pub const HPAGE_MASK: u64 = ~(HPAGE_SIZE - 1);

pub const HPAGE_PUD_SHIFT: u32 = 30;  // 1GB
pub const HPAGE_PUD_SIZE: u64 = 1 << HPAGE_PUD_SHIFT;

pub const HugePageSize = enum(u64) {
    size_2mb = 1 << 21,
    size_1gb = 1 << 30,
    size_16gb = 1 << 34,  // PowerPC/some x86
};

pub const HugePagePool = struct {
    page_size: u64,
    nr_hugepages: u64,
    free_hugepages: u64,
    resv_hugepages: u64,
    surplus_hugepages: u64,
    max_hugepages: u64,
    // Per-NUMA node
    nr_per_node: [64]u64,
    free_per_node: [64]u64,
    // Stats
    alloc_success: u64,
    alloc_fail: u64,
    fault_count: u64,
    fault_alloc: u64,
    fault_fallback: u64,
};

pub const HugetlbSubsystem = struct {
    pools: [3]HugePagePool,  // 2MB, 1GB, 16GB
    nr_pools: u32,
    default_pool: u32,
    overcommit_enabled: bool,
    shared_policy: u8,  // 0=vhost, 1=mempolicy
};

// ============================================================================
// Memory Hotplug
// ============================================================================

pub const MemoryBlockState = enum(u8) {
    offline = 0,
    online = 1,
    going_offline = 2,
    going_online = 3,
};

pub const MemoryBlock = struct {
    phys_device: u32,
    phys_index: u64,     // Block number
    state: MemoryBlockState,
    section_count: u32,
    online_type: u8,     // 0=kernel, 1=movable
    removable: bool,
    nr_pages: u64,
    nid: u32,            // NUMA node
};

pub const MemoryHotplug = struct {
    blocks: [256]MemoryBlock,
    nr_blocks: u32,
    auto_online_type: u8,
    // Stats
    total_online_pages: u64,
    total_offline_pages: u64,
    add_events: u64,
    remove_events: u64,
};

// ============================================================================
// DAMON (Data Access MONitor)
// ============================================================================

pub const DAMON_MAX_TARGETS: u32 = 256;
pub const DAMON_MAX_REGIONS: u32 = 8192;
pub const DAMON_MAX_SCHEMES: u32 = 64;

pub const DamonRegion = struct {
    start: u64,
    end: u64,
    nr_accesses: u64,     // Sampling-period access count
    age: u64,             // Aggregation periods since last access
    last_nr_accesses: u64,
};

pub const DamonTarget = struct {
    pid: u32,
    regions: [DAMON_MAX_REGIONS]DamonRegion,
    nr_regions: u32,
};

pub const DamonSchemeAction = enum(u8) {
    willneed = 0,     // madvise WILLNEED
    cold = 1,         // madvise COLD
    pageout = 2,      // madvise PAGEOUT
    hugepage = 3,     // madvise HUGEPAGE
    nohugepage = 4,   // madvise NOHUGEPAGE
    lru_prio = 5,     // LRU priority
    lru_deprio = 6,   // LRU deprioritize
    stat = 7,         // Statistics only
    // Zxyphor
    zxy_migrate_faster = 200,
    zxy_compress = 201,
};

pub const DamonScheme = struct {
    action: DamonSchemeAction,
    // Access pattern to match
    min_sz_region: u64,
    max_sz_region: u64,
    min_nr_accesses: u32,
    max_nr_accesses: u32,
    min_age_region: u64,
    max_age_region: u64,
    // Quotas
    quota_ms: u64,           // Time quota per cycle
    quota_bytes: u64,        // Size quota per cycle
    quota_reset_interval_ms: u64,
    // Weight-based prioritization
    weight_sz: u32,
    weight_nr_accesses: u32,
    weight_age: u32,
    // Apply filters
    target_nid: i32,         // NUMA node filter (-1=any)
    // Stats
    nr_tried: u64,
    sz_tried: u64,
    nr_applied: u64,
    sz_applied: u64,
    qt_exceeds: u64,
};

pub const DamonCtx = struct {
    // Monitoring parameters
    sample_interval_us: u64,
    aggr_interval_us: u64,
    update_interval_us: u64,
    min_nr_regions: u32,
    max_nr_regions: u32,
    // Operations
    ops_id: DamonOpsId,
    // Targets
    targets: [DAMON_MAX_TARGETS]?DamonTarget,
    nr_targets: u32,
    // Schemes (DAMOS)
    schemes: [DAMON_MAX_SCHEMES]?DamonScheme,
    nr_schemes: u32,
    // State
    enabled: bool,
    // Stats
    total_aggr_intervals: u64,
    total_regions_checked: u64,
};

pub const DamonOpsId = enum(u8) {
    vaddr = 0,    // Virtual address space
    paddr = 1,    // Physical address space
    fvaddr = 2,   // Filtered virtual address
};

// ============================================================================
// Memory Cgroup Internals
// ============================================================================

pub const MemcgStat = enum(u8) {
    cache = 0,
    rss = 1,
    rss_huge = 2,
    shmem = 3,
    mapped_file = 4,
    dirty = 5,
    writeback = 6,
    pgpgin = 7,
    pgpgout = 8,
    pgfault = 9,
    pgmajfault = 10,
    inactive_anon = 11,
    active_anon = 12,
    inactive_file = 13,
    active_file = 14,
    unevictable = 15,
    slab_reclaimable = 16,
    slab_unreclaimable = 17,
    // Advanced
    workingset_refault_anon = 18,
    workingset_refault_file = 19,
    workingset_activate_anon = 20,
    workingset_activate_file = 21,
    workingset_restore_anon = 22,
    workingset_restore_file = 23,
    workingset_nodereclaim = 24,
    pgsteal_anon = 25,
    pgsteal_file = 26,
    pgscan_anon = 27,
    pgscan_file = 28,
    pgactivate = 29,
    pgdeactivate = 30,
    pglazyfree = 31,
    pglazyfreed = 32,
    thp_fault_alloc = 33,
    thp_collapse_alloc = 34,
    nr_stats = 35,
};

pub const MemcgState = struct {
    // Limits
    memory_limit: i64,       // -1 = unlimited
    memsw_limit: i64,        // Memory+Swap limit
    high: i64,               // High watermark
    low: i64,                // Low protection
    min: i64,                // Min protection
    // Current usage
    memory_usage: u64,
    memsw_usage: u64,
    kmem_usage: u64,
    tcpmem_usage: u64,
    // Watermarks
    watermark_high: u64,     // Peak usage
    // Events
    memory_events: MemcgEvents,
    // Counters
    stats: [35]u64,  // Indexed by MemcgStat
    // OOM
    oom_group: bool,
    oom_kill_count: u64,
    under_oom: bool,
    // Swap
    swap_limit: i64,
    swap_usage: u64,
    // Soft limit (v1)
    soft_limit: i64,
    // NUMA
    per_node_usage: [64]u64,
    // State
    enabled: bool,
    use_hierarchy: bool,
};

pub const MemcgEvents = struct {
    low: u64,
    high: u64,
    max: u64,
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
};

// ============================================================================
// zswap
// ============================================================================

pub const ZswapCompressor = enum(u8) {
    lzo = 0,
    lzo_rle = 1,
    lz4 = 2,
    lz4hc = 3,
    zstd = 4,
    deflate = 5,
    _842 = 6,
};

pub const ZswapPool = struct {
    compressor: ZswapCompressor,
    zpool_type: [32]u8,    // "zbud", "z3fold", "zsmalloc"
    zpool_type_len: u8,
    // Limits
    max_pool_percent: u32,
    accept_threshold_percent: u32,
    // Stats
    stored_pages: u64,
    pool_pages: u64,
    duplicate_entry: u64,
    reject_alloc_fail: u64,
    reject_kmemcache_fail: u64,
    reject_compress_poor: u64,
    reject_reclaim_fail: u64,
    written_back_pages: u64,
    same_filled_pages: u64,
    pool_limit_hit: u64,
    // Compression ratio
    compressed_bytes: u64,
    original_bytes: u64,
};

pub const ZswapState = struct {
    enabled: bool,
    same_filled_pages_enabled: bool,
    non_same_filled_pages_enabled: bool,
    shrinker_enabled: bool,
    pool: ZswapPool,

    pub fn compression_ratio(self: *const ZswapState) u32 {
        if (self.pool.compressed_bytes == 0) return 0;
        return @intCast((self.pool.original_bytes * 100) / self.pool.compressed_bytes);
    }
};

// ============================================================================
// zram
// ============================================================================

pub const ZramState = struct {
    disk_size: u64,
    comp_algorithm: ZswapCompressor,
    // Stats
    num_reads: u64,
    num_writes: u64,
    failed_reads: u64,
    failed_writes: u64,
    invalid_io: u64,
    notify_free: u64,
    // Memory usage
    orig_data_size: u64,
    compr_data_size: u64,
    mem_used_total: u64,
    mem_limit: u64,
    mem_used_max: u64,
    same_pages: u64,
    huge_pages: u64,
    huge_pages_since: u64,
    pages_stored: u64,
    // Writeback
    bd_count: u64,      // Backing device pages
    bd_reads: u64,
    bd_writes: u64,
};

// ============================================================================
// Memory Sanitizers and Features Subsystem
// ============================================================================

pub const MemoryFeaturesSubsystem = struct {
    // Sanitizers
    kasan: KasanState,
    kmsan: KmsanState,
    kcsan: KcsanState,
    // userfaultfd
    uffd_enabled: bool,
    // CMA
    cma: CmaSubsystem,
    // HugeTLB
    hugetlb: HugetlbSubsystem,
    // Hotplug
    hotplug: MemoryHotplug,
    // DAMON
    damon: DamonCtx,
    // zswap/zram
    zswap: ZswapState,
    zram: ZramState,
    // Memcg
    memcg_enabled: bool,
    // Global state
    initialized: bool,

    pub fn total_sanitizer_overhead(self: *const MemoryFeaturesSubsystem) u64 {
        var overhead: u64 = 0;
        if (self.kasan.enabled) {
            // Shadow memory = 1/8 of physical
            overhead += (self.kasan.shadow_end - self.kasan.shadow_start);
        }
        if (self.kmsan.enabled) {
            overhead += (self.kmsan.shadow_end - self.kmsan.shadow_start);
            overhead += (self.kmsan.origin_end - self.kmsan.origin_start);
        }
        return overhead;
    }
};
