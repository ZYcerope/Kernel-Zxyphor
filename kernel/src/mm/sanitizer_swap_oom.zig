// Zxyphor Kernel - KASAN/KMSAN/KCSAN Internals,
// GUP (get_user_pages), Swap Subsystem Detail,
// Memory Error Handling (MCE/EDAC integration),
// Out-of-Memory Killer Detail, Memfd/Secretmem,
// DAMON Monitor Detail, Userfaultfd
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// KASAN (Kernel Address Sanitizer)
// ============================================================================

pub const KasanMode = enum(u8) {
    disabled = 0,
    generic = 1,        // Shadow memory based
    sw_tags = 2,        // Software tag-based (ARM64 MTE)
    hw_tags = 3,        // Hardware tag-based (ARM64 MTE)
};

pub const KasanShadowScale = enum(u8) {
    scale_8 = 3,        // 1 shadow byte per 8 real bytes (1/8)
    scale_16 = 4,       // 1 per 16
};

pub const KasanReportType = enum(u8) {
    out_of_bounds = 0,
    use_after_free = 1,
    use_after_scope = 2,
    wild_access = 3,
    double_free = 4,
    invalid_free = 5,
    slab_out_of_bounds = 6,
    global_out_of_bounds = 7,
    stack_out_of_bounds = 8,
    alloc_meta_corrupted = 9,
    // Zxyphor extended
    zxy_type_confusion = 100,
};

pub const KasanShadowVal = enum(u8) {
    accessible_0 = 0x00,    // All 8 bytes accessible
    accessible_1 = 0x01,    // 1 byte accessible
    accessible_2 = 0x02,
    accessible_3 = 0x03,
    accessible_4 = 0x04,
    accessible_5 = 0x05,
    accessible_6 = 0x06,
    accessible_7 = 0x07,
    // Negative = poisoned
    slab_redzone = 0xFC,
    slab_free = 0xFB,
    slab_padding = 0xFA,
    global_redzone = 0xF9,
    stack_left = 0xF1,
    stack_mid = 0xF2,
    stack_right = 0xF3,
    stack_after_return = 0xF5,
    stack_use_after_scope = 0xF8,
    alloc_free = 0xFF,
};

pub const KasanConfig = struct {
    mode: KasanMode,
    shadow_scale: KasanShadowScale,
    shadow_offset: u64,         // KASAN_SHADOW_OFFSET
    shadow_start: u64,
    shadow_end: u64,
    quarantine_size: u64,       // Bytes
    quarantine_size_max: u64,
    report_enabled: bool,
    multi_shot: bool,           // Report multiple bugs
    fault_enabled: bool,        // Inject faults for testing
    stack_enabled: bool,
    global_enabled: bool,
};

pub const KasanStats = struct {
    reports_total: u64,
    reports_oob: u64,
    reports_uaf: u64,
    reports_double_free: u64,
    reports_wild: u64,
    quarantine_puts: u64,
    quarantine_removes: u64,
    quarantine_max_bytes: u64,
    shadow_pages_allocated: u64,
};

// ============================================================================
// KMSAN (Kernel Memory Sanitizer) - Uninitialized memory
// ============================================================================

pub const KmsanMode = enum(u8) {
    disabled = 0,
    enabled = 1,
};

pub const KmsanOriginType = enum(u8) {
    instruction = 0,      // Created by LLVM instrumentation
    mem_alloc = 1,        // kmalloc/vmalloc
    stack_alloc = 2,      // Stack variable
    type_size = 3,        // Type-based
};

pub const KmsanConfig = struct {
    enabled: bool,
    report_enabled: bool,
    param_retval_check: bool,
    per_task_enabled: bool,
};

pub const KmsanStats = struct {
    reports_total: u64,
    reports_use_uninit: u64,
    reports_kmalloc_uninit: u64,
    reports_stack_uninit: u64,
    shadow_pages: u64,
    origin_pages: u64,
};

// ============================================================================
// KCSAN (Kernel Concurrency Sanitizer) - Data races
// ============================================================================

pub const KcsanMode = enum(u8) {
    disabled = 0,
    enabled = 1,
};

pub const KcsanReportType = enum(u8) {
    data_race = 0,
    assert_failure = 1,
    atomic_write_plain_read = 2,
    write_write = 3,
};

pub const KcsanConfig = struct {
    enabled: bool,
    report_value_change: bool,     // Only report if value changed
    report_one_shot: bool,
    skip_watch_rate: u32,          // Skip N accesses between watches
    udelay_task: u32,              // Delay for watching (microseconds)
    udelay_interrupt: u32,
};

pub const KcsanStats = struct {
    reports_total: u64,
    reports_races: u64,
    watchpoints_setup: u64,
    watchpoints_hit: u64,
    watchpoints_lost: u64,
    atomic_watches: u64,
};

// ============================================================================
// GUP (get_user_pages)
// ============================================================================

pub const GupFlags = packed struct(u32) {
    write: bool = false,           // Need write access
    longterm: bool = false,        // Pin will be held long-term
    force: bool = false,           // Like FOLL_FORCE
    fast_only: bool = false,       // Fail if can't do fast GUP
    no_interrupt: bool = false,    // Don't allow interrupts
    migration: bool = false,       // Pin for migration
    remote: bool = false,          // Access remote mm (ptrace)
    pin: bool = false,             // FOLL_PIN (vs FOLL_GET)
    try_get: bool = false,         // FOLL_TRY_GET
    touch: bool = false,           // FOLL_TOUCH
    nowait: bool = false,          // FOLL_NOWAIT
    unlockable: bool = false,      // Allow unlock-and-retry
    _reserved: u20 = 0,
};

pub const GupResult = struct {
    nr_pages_pinned: i64,    // Negative = error
    pages_compound: bool,    // Compound page encountered
    pages_fault: bool,       // Had to fault in pages
    pages_migrated: bool,    // Some pages were migrated
};

pub const GupStats = struct {
    fast_success: u64,
    slow_success: u64,
    fast_fail: u64,
    slow_fail: u64,
    pin_fast: u64,
    pin_slow: u64,
    pin_longterm: u64,
    unpin_total: u64,
    faults_triggered: u64,
};

// ============================================================================
// Swap Subsystem Detail
// ============================================================================

pub const SwapType = enum(u8) {
    partition = 0,
    file = 1,
    zram = 2,
    nbd = 3,
    // Zxyphor
    zxy_nvme_swap = 100,
};

pub const SwapFlags = packed struct(u32) {
    discard: bool = false,
    discard_once: bool = false,
    discard_pages: bool = false,
    prefer: bool = false,        // High priority
    // Zxyphor extended
    zxy_compressed: bool = false,
    zxy_encrypted: bool = false,
    _reserved: u26 = 0,
};

pub const SwapEntry = packed struct(u64) {
    type_index: u6,        // Swap area index
    offset: u50,           // Offset in swap area (pages)
    _flags: u8,            // Software flags
};

pub const SwapAreaInfo = struct {
    swap_type: SwapType,
    priority: i16,
    flags: SwapFlags,
    pages_total: u64,
    pages_used: u64,
    pages_bad: u64,
    // Clustering
    cluster_size: u32,
    nr_clusters: u32,
    cluster_next: u32,
    // Extents (for file-based swap)
    nr_extents: u32,
    max_extent_len: u64,
    // Statistics
    swapin_count: u64,
    swapout_count: u64,
    swapin_bytes: u64,
    swapout_bytes: u64,
};

pub const SwapCacheStats = struct {
    cache_hits: u64,
    cache_misses: u64,
    cache_add: u64,
    cache_del: u64,
    cache_find_total: u64,
    readahead_total: u64,
    readahead_wins: u64,
};

pub const SwapCluster = struct {
    count: u32,            // Pages in cluster
    flags: SwapClusterFlags,
    next_free: u32,        // Next free slot
};

pub const SwapClusterFlags = packed struct(u8) {
    full: bool = false,
    free: bool = false,
    frag: bool = false,    // Fragmented
    huge: bool = false,    // Used for THP swap
    _reserved: u4 = 0,
};

// ============================================================================
// Memory Error Handling (MCE/EDAC)
// ============================================================================

pub const MemoryErrorType = enum(u8) {
    corrected = 0,         // CE - Corrected Error
    uncorrected = 1,       // UE - Uncorrected Error
    fatal = 2,             // Fatal Machine Check
    deferred = 3,          // Deferred error (AMD)
    threshold = 4,         // Error threshold exceeded
    // Poison
    hardware_poison = 5,   // HWPOISON flag set
    soft_poison = 6,       // Software-detected
};

pub const MemoryErrorGranularity = enum(u8) {
    unknown = 0,
    page = 1,
    cacheline = 2,
    bank = 3,
    dimm = 4,
    channel = 5,
    controller = 6,
};

pub const MemoryErrorRecord = struct {
    error_type: MemoryErrorType,
    granularity: MemoryErrorGranularity,
    physical_addr: u64,
    page_pfn: u64,
    error_count: u32,
    first_seen: u64,       // timestamp
    last_seen: u64,
    // DIMM info
    socket: u8,
    channel: u8,
    dimm: u8,
    rank: u8,
    bank: u16,
    row: u32,
    column: u16,
    // Action taken
    page_offlined: bool,
    process_killed: bool,
    recovered: bool,
};

pub const HwPoisonFlags = packed struct(u32) {
    isolate_success: bool = false,
    migrate_success: bool = false,
    dissolve: bool = false,
    truncate: bool = false,
    invalidate: bool = false,
    soft_offline: bool = false,
    unpoison: bool = false,
    _reserved: u25 = 0,
};

pub const MemoryErrorStats = struct {
    ce_total: u64,
    ue_total: u64,
    fatal_total: u64,
    pages_offlined: u64,
    pages_recovered: u64,
    soft_offlines: u64,
    hw_poison_pages: u64,
};

// ============================================================================
// OOM Killer Detail
// ============================================================================

pub const OomPolicy = enum(u8) {
    kill_process = 0,
    kill_cgroup = 1,      // Kill entire cgroup
    panic = 2,
    // Zxyphor
    zxy_graceful = 100,   // Try graceful first
};

pub const OomPriority = enum(u8) {
    oom_disabled = 0,     // oom_score_adj = -1000
    low = 1,
    default = 2,
    high = 3,
    highest = 4,          // oom_score_adj = 1000
};

pub const OomVictimInfo = struct {
    pid: u32,
    uid: u32,
    comm: [16]u8,
    oom_score: u32,        // Computed score (0-1000+)
    oom_score_adj: i16,    // User-set adjustment
    total_vm: u64,         // Pages
    rss: u64,
    swap_used: u64,
    pgtables: u64,
    cgroup_id: u64,
};

pub const OomContext = struct {
    policy: OomPolicy,
    constraint: OomConstraint,
    // Trigger info
    gfp_mask: u32,
    order: u8,
    nodemask: u64,
    // Memcg
    memcg_oom: bool,
    memcg_id: u64,
    memcg_limit: u64,
    // Stats
    nr_killed: u32,
    freed_pages: u64,
};

pub const OomConstraint = enum(u8) {
    none = 0,
    cpuset = 1,
    mempolicy = 2,
    memcg = 3,
};

pub const OomStats = struct {
    oom_kills_total: u64,
    oom_kills_memcg: u64,
    oom_kills_global: u64,
    oom_reaps_total: u64,
    oom_panics: u64,
    victimless_oom: u64,    // No suitable victim found
};

// ============================================================================
// Memfd & Secretmem
// ============================================================================

pub const MemfdFlags = packed struct(u32) {
    cloexec: bool = false,
    allow_sealing: bool = false,
    hugetlb: bool = false,
    noexec_seal: bool = false,
    exec: bool = false,
    // Hugetlb size encoding (bits 26-31)
    _reserved: u27 = 0,
};

pub const MemfdSealFlags = packed struct(u32) {
    seal_seal: bool = false,       // F_SEAL_SEAL - can't add more seals
    seal_shrink: bool = false,     // F_SEAL_SHRINK
    seal_grow: bool = false,       // F_SEAL_GROW
    seal_write: bool = false,      // F_SEAL_WRITE
    seal_future_write: bool = false, // F_SEAL_FUTURE_WRITE
    seal_exec: bool = false,       // F_SEAL_EXEC
    _reserved: u26 = 0,
};

pub const SecretmemConfig = struct {
    enabled: bool,
    max_pages: u64,
    allocated_pages: u64,
    // secretmem pages are removed from direct map
    direct_map_removed: u64,
};

// ============================================================================
// DAMON (Data Access Monitor) Detail
// ============================================================================

pub const DamonOperationScheme = enum(u8) {
    pageout = 0,           // Swap out
    lru_deprioritize = 1,  // Move to inactive LRU
    lru_prioritize = 2,    // Move to active LRU
    huge_page = 3,         // Try to promote to THP
    noop = 4,              // Just monitor
    stat = 5,              // Collect statistics
    // Zxyphor
    zxy_compress = 100,    // Compress cold pages
    zxy_migrate = 101,     // Migrate to slow tier
};

pub const DamonTarget = struct {
    pid: u32,              // 0 = physical address space
    nr_regions: u32,
    regions_start: u64,    // Monitoring start
    regions_end: u64,      // Monitoring end
};

pub const DamonAttrs = struct {
    sample_interval_us: u64,
    aggr_interval_us: u64,
    update_interval_us: u64,
    min_nr_regions: u32,
    max_nr_regions: u32,
};

pub const DamonSchemeFilter = struct {
    filter_type: DamonFilterType,
    matching: bool,        // true = allow matching, false = deny matching
    memcg_id: u64,
    addr_start: u64,
    addr_end: u64,
    target_idx: u32,
};

pub const DamonFilterType = enum(u8) {
    anon = 0,
    memcg = 1,
    young = 2,
    addr = 3,
    target = 4,
};

pub const DamonSchemeAccess = struct {
    min_sz_region: u64,
    max_sz_region: u64,
    min_nr_accesses: u32,
    max_nr_accesses: u32,
    min_age_nr_regions: u32,
    max_age_nr_regions: u32,
};

pub const DamonSchemeQuota = struct {
    bytes_per_interval: u64,
    time_ms_per_interval: u64,
    reset_interval_ms: u64,
    weight_size: u32,
    weight_nr_accesses: u32,
    weight_age: u32,
};

pub const DamonStats = struct {
    nr_tried: u64,
    sz_tried: u64,
    nr_applied: u64,
    sz_applied: u64,
    qt_exceeds: u64,
};

// ============================================================================
// Userfaultfd
// ============================================================================

pub const UserfaultfdFeatures = packed struct(u64) {
    pagefault_flag_wp: bool = false,
    event_fork: bool = false,
    event_remap: bool = false,
    event_remove: bool = false,
    missing_hugetlbfs: bool = false,
    missing_shmem: bool = false,
    event_unmap: bool = false,
    sigbus: bool = false,
    thread_id: bool = false,
    minor_hugetlbfs: bool = false,
    minor_shmem: bool = false,
    exact_address: bool = false,
    wp_hugetlbfs: bool = false,
    wp_shmem: bool = false,
    wp_unpopulated: bool = false,
    poison: bool = false,
    wp_async: bool = false,
    move_uffd: bool = false,     // UFFDIO_MOVE
    _reserved: u46 = 0,
};

pub const UserfaultfdMode = packed struct(u8) {
    missing: bool = false,    // Handle missing pages
    wp: bool = false,         // Handle write-protect faults
    minor: bool = false,      // Handle minor faults
    _reserved: u5 = 0,
};

pub const UserfaultfdIoctl = enum(u32) {
    api = 0xAA00,
    register = 0xAA01,
    unregister = 0xAA02,
    wake = 0xAA03,
    copy = 0xAA04,
    zeropage = 0xAA05,
    writeprotect = 0xAA06,
    continue_uffd = 0xAA07,
    poison = 0xAA08,
    move_uffd = 0xAA09,
};

pub const UserfaultfdStats = struct {
    fault_missing: u64,
    fault_wp: u64,
    fault_minor: u64,
    copy_total: u64,
    zeropage_total: u64,
    move_total: u64,
    events_fork: u64,
    events_remap: u64,
    events_remove: u64,
};

// ============================================================================
// Memory Sanitizer Manager (Zxyphor)
// ============================================================================

pub const MemoryDebugManager = struct {
    kasan: KasanConfig,
    kasan_stats: KasanStats,
    kmsan: KmsanConfig,
    kmsan_stats: KmsanStats,
    kcsan: KcsanConfig,
    kcsan_stats: KcsanStats,
    gup_stats: GupStats,
    swap_cache_stats: SwapCacheStats,
    mem_error_stats: MemoryErrorStats,
    oom_stats: OomStats,
    damon_stats: DamonStats,
    uffd_stats: UserfaultfdStats,
    initialized: bool,

    pub fn init() MemoryDebugManager {
        return .{
            .kasan = std.mem.zeroes(KasanConfig),
            .kasan_stats = std.mem.zeroes(KasanStats),
            .kmsan = std.mem.zeroes(KmsanConfig),
            .kmsan_stats = std.mem.zeroes(KmsanStats),
            .kcsan = std.mem.zeroes(KcsanConfig),
            .kcsan_stats = std.mem.zeroes(KcsanStats),
            .gup_stats = std.mem.zeroes(GupStats),
            .swap_cache_stats = std.mem.zeroes(SwapCacheStats),
            .mem_error_stats = std.mem.zeroes(MemoryErrorStats),
            .oom_stats = std.mem.zeroes(OomStats),
            .damon_stats = std.mem.zeroes(DamonStats),
            .uffd_stats = std.mem.zeroes(UserfaultfdStats),
            .initialized = true,
        };
    }
};
