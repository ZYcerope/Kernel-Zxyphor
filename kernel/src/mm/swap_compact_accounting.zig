// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Swap Subsystem, Memory Accounting & Compaction Detail
// Complete: swap cache, swap slots, frontswap, zswap, memory cgroups accounting,
// memory compaction, page migration, balloon, memory tiering

const std = @import("std");

// ============================================================================
// Swap Types and Flags
// ============================================================================

pub const SwapFlags = packed struct(u32) {
    prefer: bool,           // SWP_USED
    writeok: bool,          // SWP_WRITEOK
    discardable: bool,      // SWP_DISCARDABLE
    discarding: bool,       // SWP_DISCARDING
    blkdev: bool,           // SWP_BLKDEV
    activated: bool,        // SWP_ACTIVATED
    continued: bool,        // SWP_CONTINUED
    file: bool,             // SWP_FILE
    area_discard: bool,     // SWP_AREA_DISCARD
    page_discard: bool,     // SWP_PAGE_DISCARD
    stable_writes: bool,    // SWP_STABLE_WRITES
    synchronous_io: bool,   // SWP_SYNCHRONOUS_IO
    _reserved: u20,
};

pub const SwapEntry = packed struct(u64) {
    offset: u50,
    swap_type: u5,
    present: bool,
    migration: bool,
    special: bool,
    write_protect: bool,
    exclusive: bool,
    hwpoison: bool,
    soft_dirty: bool,
    pte_marker: bool,
    _pad: u2,
};

pub const SwapInfo = struct {
    flags: SwapFlags,
    prio: i16,
    swap_map: ?[*]u8,       // Per-page usage counts
    cluster_info: ?[*]SwapCluster,
    free_clusters: u32,
    cluster_next: u32,
    cluster_nr: u32,
    lowest_bit: u64,
    highest_bit: u64,
    pages: u64,
    inuse_pages: u64,
    old_block_size: u32,
    bdev: ?*anyopaque,
    swap_file: ?*anyopaque,
    max: u64,                // Total slots
    swap_extent_root: u64,   // RB-tree root
    front_extent: u64,
    curr_swap_extent: u64,
    nr_extents: u32,
    swap_address_space: ?*anyopaque,
    avail_lists: [256]u64,   // Per-node avail list heads
};

pub const SwapCluster = struct {
    count: u32,
    flags: SwapClusterFlags,
    data: u32,
};

pub const SwapClusterFlags = packed struct(u8) {
    free: bool,
    contiguous: bool,
    huge: bool,
    nonfull: bool,
    _reserved: u4,
};

// ============================================================================
// Swap Cache
// ============================================================================

pub const SwapCache = struct {
    nr_entries: u64,
    nr_shadow: u64,
    add_total: u64,
    del_total: u64,
    find_success: u64,
    find_total: u64,
    noent: u64,
    exist: u64,
};

pub const SwapCacheResult = enum(u8) {
    Hit = 0,
    Miss = 1,
    Race = 2,
    Nomem = 3,
    Fault = 4,
};

// ============================================================================
// Frontswap / Zswap
// ============================================================================

pub const FrontswapOps = struct {
    init: ?*const fn (swap_type: u32) callconv(.C) void,
    store: ?*const fn (swap_type: u32, pgoff: u64, page: *anyopaque) callconv(.C) i32,
    load: ?*const fn (swap_type: u32, pgoff: u64, page: *anyopaque) callconv(.C) i32,
    invalidate_page: ?*const fn (swap_type: u32, pgoff: u64) callconv(.C) void,
    invalidate_area: ?*const fn (swap_type: u32) callconv(.C) void,
};

pub const ZswapPoolType = enum(u8) {
    Zbud = 0,
    Zsmalloc = 1,
    Z3fold = 2,
};

pub const ZswapCompressor = enum(u8) {
    Lzo = 0,
    LzoRle = 1,
    Lz4 = 2,
    Lz4hc = 3,
    Zstd = 4,
    Deflate = 5,
    Lz842 = 6,
};

pub const ZswapPool = struct {
    pool_type: ZswapPoolType,
    compressor: ZswapCompressor,
    nr_stored: u64,
    pool_total_size: u64,
    pool_limit_hit: u64,
    reject_reclaim_fail: u64,
    reject_alloc_fail: u64,
    reject_kmemcache_fail: u64,
    reject_compress_poor: u64,
    written_back_pages: u64,
    duplicate_entry: u64,
    same_filled_pages: u64,
    max_pool_percent: u32,
    same_filled_pages_enabled: bool,
    enabled: bool,
    shrinker_enabled: bool,
    accept_threshold_percent: u32,
};

pub const ZswapEntry = struct {
    rb_node: u64,
    offset: u64,
    refcount: i32,
    length: u32,
    pool: ?*ZswapPool,
    handle: u64,
    value: u64,
    objcg: ?*anyopaque,
    swpentry: SwapEntry,
};

// ============================================================================
// Memory Cgroup Accounting
// ============================================================================

pub const MemcgStat = enum(u32) {
    Cache = 0,
    Rss = 1,
    RssHuge = 2,
    Shmem = 3,
    MappedFile = 4,
    Dirty = 5,
    Writeback = 6,
    Swap = 7,
    PgPgIn = 8,
    PgPgOut = 9,
    PgFault = 10,
    PgMajFault = 11,
    InactiveAnon = 12,
    ActiveAnon = 13,
    InactiveFile = 14,
    ActiveFile = 15,
    Unevictable = 16,
    SlabReclaimable = 17,
    SlabUnreclaimable = 18,
    Sock = 19,
    ShmemPmdMapped = 20,
    FileMapped = 21,
    FileDirty = 22,
    FileWriteback = 23,
    AnonThp = 24,
    FileThp = 25,
    ShmemThp = 26,
    Kernel = 27,
    KernelStack = 28,
    PageTables = 29,
    SecPageTables = 30,
    WorkingsetRefault = 31,
    WorkingsetActivate = 32,
    WorkingsetRestore = 33,
    WorkingsetNodereclaim = 34,
    NrStatItems = 35,
};

pub const MemcgCounters = struct {
    usage: i64,
    memsw_usage: i64,
    kmem_usage: i64,
    tcpmem_usage: i64,
    limit: i64,
    memsw_limit: i64,
    kmem_limit: i64,
    tcpmem_limit: i64,
    soft_limit: i64,
    failcnt: u64,
    memsw_failcnt: u64,
    kmem_failcnt: u64,
    low: i64,
    high: i64,
    max: i64,
    min: i64,
    watermark: i64,
    stat: [36]i64,
    events: [8]u64,
    events_local: [8]u64,
    oom_group: bool,
    oom_kill_disable: bool,
    use_hierarchy: bool,
    memory_pressure: u32,
    swappiness: u32,
    move_charge_at_immigrate: u32,
};

pub const MemcgEvent = enum(u8) {
    Low = 0,
    High = 1,
    Max = 2,
    Oom = 3,
    OomKill = 4,
    OomGroupKill = 5,
    SwapHigh = 6,
    SwapMax = 7,
    SwapFail = 8,
};

pub const ObjCgroup = struct {
    memcg: ?*anyopaque,     // mem_cgroup pointer
    nr_charged_bytes: u64,
    nr_pages: u64,
    charge_stock: i64,
    refcnt: i32,
};

pub const MemcgChargeStat = struct {
    nr_charges: u64,
    nr_uncharges: u64,
    nr_charge_fails: u64,
    nr_migrations: u64,
    nr_reclaim_attempts: u64,
    nr_reclaim_success: u64,
    nr_oom_invocations: u64,
    nr_oom_kills: u64,
};

// ============================================================================
// Memory Compaction
// ============================================================================

pub const CompactMode = enum(u8) {
    Async = 0,
    Sync_Light = 1,
    Sync = 2,
    Sync_Full = 3,
};

pub const CompactResult = enum(u8) {
    Skipped = 0,
    Deferred = 1,
    Continue = 2,
    Partial_Skipped = 3,
    Complete = 4,
    No_Suitable_Page = 5,
    Not_Suitable_Zone = 6,
    Contended = 7,
    Success = 8,
};

pub const CompactPriority = enum(u8) {
    Prio_Sync_Full = 0,
    Prio_Sync_Light = 1,
    Prio_Async = 2,
};

pub const CompactControl = struct {
    nr_freepages: u64,
    nr_migratepages: u64,
    free_pfn: u64,
    migrate_pfn: u64,
    fast_start_pfn: u64,
    zone: ?*anyopaque,
    total_migrate_scanned: u64,
    total_free_scanned: u64,
    fast_search_fail: u16,
    search_order: i16,
    order: i32,
    gfp_mask: u32,
    mode: CompactMode,
    result: CompactResult,
    alloc_flags: u32,
    highest_zoneidx: i32,
    direct_compaction: bool,
    proactive_compaction: bool,
    whole_zone: bool,
    contended: bool,
    rescan: bool,
    finish_pageblock: bool,
};

pub const CompactStats = struct {
    nr_migrated: u64,
    nr_failed: u64,
    nr_scanned_migrate: u64,
    nr_scanned_free: u64,
    nr_deferred: u64,
    nr_succeeded: u64,
    nr_contended: u64,
    compact_stall: u64,
    compact_fail: u64,
    compact_success: u64,
    compact_daemon_wake: u64,
    compact_daemon_migrate_scanned: u64,
    compact_daemon_free_scanned: u64,
};

// ============================================================================
// Page Migration
// ============================================================================

pub const MigrationMode = enum(u8) {
    Async = 0,
    Sync_Light = 1,
    Sync = 2,
    Sync_No_Copy = 3,
};

pub const MigrationReason = enum(u8) {
    Compaction = 0,
    MemoryFailure = 1,
    MemoryHotplug = 2,
    Syscall = 3,       // move_pages / mbind
    MempolicyMbind = 4,
    Numa_Misplaced = 5,
    Contig_Range = 6,
    LongTerm_Pin = 7,
    Demote = 8,
};

pub const MigratePages = struct {
    from_list: ?*anyopaque,
    new_folio: ?*const fn (folio: *anyopaque, private: u64) callconv(.C) ?*anyopaque,
    free_folio: ?*const fn (folio: *anyopaque, private: u64) callconv(.C) void,
    private_data: u64,
    mode: MigrationMode,
    reason: MigrationReason,
    nr_succeeded: u64,
    nr_failed_pages: u64,
    nr_thp_succeeded: u64,
    nr_thp_failed: u64,
    nr_thp_split: u64,
};

// ============================================================================
// Memory Balloon
// ============================================================================

pub const BalloonDevInfo = struct {
    pages: u64,
    isolated_pages: u64,
    balloon_mutex: u64,
    pages_head: ?*anyopaque,
    migratepage: ?*const fn (bdi: *BalloonDevInfo, newpage: *anyopaque, page: *anyopaque, mode: MigrationMode) callconv(.C) i32,
};

// ============================================================================
// Memory Tiering (CXL / NUMA)
// ============================================================================

pub const MemoryTier = struct {
    id: u32,
    adistance_start: i32,
    node_mask: [256]bool,
    dev_mask: [256]bool,
};

pub const MemoryTierConfig = struct {
    default_dram_tier: u32,
    default_pmem_tier: u32,
    num_tiers: u32,
    tiers: [8]MemoryTier,
    demote_order: [256]i32,
    promote_order: [256]i32,
};

pub const DaxDevice = struct {
    id: u32,
    alive: bool,
    ops: DaxOps,
    pgmap: ?*anyopaque,
    flags: DaxFlags,
    nr_pages: u64,
    start_pfn: u64,
};

pub const DaxFlags = packed struct(u32) {
    synchronous: bool,
    static_page: bool,
    nocache: bool,
    nomc: bool,
    _reserved: u28,
};

pub const DaxOps = struct {
    direct_access: ?*const fn (dev: *DaxDevice, pgoff: u64, nr_pages: u64, mode: u32, kaddr: *?*anyopaque, pfn: *u64) callconv(.C) i64,
    zero_page_range: ?*const fn (dev: *DaxDevice, pgoff: u64, nr_pages: u64) callconv(.C) i32,
    recovery_write: ?*const fn (dev: *DaxDevice, pgoff: u64, addr: *anyopaque, bytes: usize, iter: *anyopaque) callconv(.C) usize,
};

// ============================================================================
// Manager
// ============================================================================

pub const SwapCompactManager = struct {
    total_swap_pages: u64,
    total_swap_used: u64,
    total_zswap_stored: u64,
    total_zswap_pool_size: u64,
    total_compactions: u64,
    total_migrations: u64,
    total_memcg_charges: u64,
    total_balloon_pages: u64,
    initialized: bool,

    pub fn init() SwapCompactManager {
        return .{
            .total_swap_pages = 0,
            .total_swap_used = 0,
            .total_zswap_stored = 0,
            .total_zswap_pool_size = 0,
            .total_compactions = 0,
            .total_migrations = 0,
            .total_memcg_charges = 0,
            .total_balloon_pages = 0,
            .initialized = true,
        };
    }
};
