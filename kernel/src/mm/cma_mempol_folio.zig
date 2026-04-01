// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - CMA (Contiguous Memory Allocator),
// Memory Policy (NUMA), Zswap/ZRAM internals,
// Folio Operations, Memory Compaction,
// Balloon Driver, Transparent Huge Pages (THP) detail,
// HugeTLB detail, Page Owner, Page Poison
// More advanced than Linux 2026 memory management

const std = @import("std");

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

/// CMA area descriptor
pub const CmaAreaDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    base_pfn: u64 = 0,
    count: u64 = 0,                 // nr pages
    order_per_bit: u32 = 0,
    bitmap_count: u64 = 0,
    // Stats
    alloc_pages_success: u64 = 0,
    alloc_pages_fail: u64 = 0,
    release_pages_success: u64 = 0,
    // Zxyphor
    zxy_priority: u8 = 0,
};

/// CMA allocation flags
pub const CmaAllocFlags = packed struct(u32) {
    no_warn: bool = false,
    gfp_dma: bool = false,
    gfp_dma32: bool = false,
    // Zxyphor
    zxy_aligned: bool = false,
    zxy_prefault: bool = false,
    _padding: u27 = 0,
};

// ============================================================================
// Memory Policy (NUMA)
// ============================================================================

/// NUMA memory policy mode
pub const MpolMode = enum(u8) {
    default = 0,
    preferred = 1,
    bind = 2,
    interleave = 3,
    local = 4,
    preferred_many = 5,
    weighted_interleave = 6,
    // Zxyphor
    zxy_adaptive = 100,
    zxy_latency_aware = 101,
};

/// Memory policy flags
pub const MpolFlags = packed struct(u32) {
    strict: bool = false,           // MPOL_F_STATIC_NODES
    relative_nodes: bool = false,   // MPOL_F_RELATIVE_NODES
    numa_balancing: bool = false,   // MPOL_F_NUMA_BALANCING
    // Zxyphor
    zxy_weight_auto: bool = false,
    _padding: u28 = 0,
};

/// Memory policy descriptor
pub const MpolDesc = struct {
    mode: MpolMode = .default,
    flags: MpolFlags = .{},
    nodemask: [64]u64 = [_]u64{0} ** 64,   // 4096 nodes max
    nr_nodes: u32 = 0,
    // Weighted interleave
    weights: [64]u8 = [_]u8{0} ** 64,
    home_node: i32 = -1,
    refcount: u32 = 0,
};

/// NUMA statistics
pub const NumaStats = struct {
    // Per-node
    node_id: u32 = 0,
    nr_active: u64 = 0,
    nr_inactive: u64 = 0,
    nr_free: u64 = 0,
    nr_slab: u64 = 0,
    nr_isolated: u64 = 0,
    nr_anon: u64 = 0,
    nr_file: u64 = 0,
    nr_dirty: u64 = 0,
    nr_writeback: u64 = 0,
    nr_shmem: u64 = 0,
    nr_shmem_hugepages: u64 = 0,
    nr_shmem_pmdmapped: u64 = 0,
    nr_kernel_stack: u64 = 0,
    nr_pagetable: u64 = 0,
    nr_sec_pagetable: u64 = 0,
    nr_bounce: u64 = 0,
    nr_vmscan_write: u64 = 0,
    nr_vmscan_immediate: u64 = 0,
    nr_dirtied: u64 = 0,
    nr_written: u64 = 0,
    numa_hit: u64 = 0,
    numa_miss: u64 = 0,
    numa_foreign: u64 = 0,
    numa_interleave: u64 = 0,
    numa_local: u64 = 0,
    numa_other: u64 = 0,
    // Zxyphor
    zxy_balanced_pages: u64 = 0,
};

// ============================================================================
// Zswap/ZRAM Internals (Zig side)
// ============================================================================

/// Zswap pool descriptor
pub const ZswapPool = struct {
    compressor: ZswapCompressor = .lzo,
    zpool: ZswapZpoolType = .zbud,
    nr_stored: u64 = 0,
    nr_pool_pages: u64 = 0,
    pool_limit_hit: u64 = 0,
    reject_reclaim_fail: u64 = 0,
    reject_alloc_fail: u64 = 0,
    reject_kmemcache_fail: u64 = 0,
    reject_compress_poor: u64 = 0,
    written_back_pages: u64 = 0,
    duplicate_entry: u64 = 0,
    same_filled: u64 = 0,
};

pub const ZswapCompressor = enum(u8) {
    lzo = 0,
    lzo_rle = 1,
    lz4 = 2,
    lz4hc = 3,
    zstd = 4,
    deflate = 5,
    // Zxyphor
    zxy_fast = 100,
};

pub const ZswapZpoolType = enum(u8) {
    zbud = 0,
    z3fold = 1,
    zsmalloc = 2,
};

/// ZRAM device descriptor (Zig side)
pub const ZramDevice = struct {
    disk_id: u32 = 0,
    disksize: u64 = 0,
    comp_algorithm: ZswapCompressor = .lzo_rle,
    max_comp_streams: u32 = 0,
    // Stats
    num_reads: u64 = 0,
    num_writes: u64 = 0,
    failed_reads: u64 = 0,
    failed_writes: u64 = 0,
    invalid_io: u64 = 0,
    notify_free: u64 = 0,
    zero_pages: u64 = 0,
    pages_stored: u64 = 0,
    compr_data_size: u64 = 0,
    mem_used_total: u64 = 0,
    mem_limit: u64 = 0,
    mem_used_max: u64 = 0,
    same_pages: u64 = 0,
    huge_pages: u64 = 0,
    huge_pages_since: u64 = 0,
    bd_count: u64 = 0,
    bd_reads: u64 = 0,
    bd_writes: u64 = 0,
};

// ============================================================================
// Folio Operations
// ============================================================================

/// Folio order sizes
pub const FolioOrder = enum(u8) {
    order_0 = 0,    // 4KB
    order_1 = 1,    // 8KB
    order_2 = 2,    // 16KB
    order_3 = 3,    // 32KB
    order_4 = 4,    // 64KB
    order_5 = 5,    // 128KB
    order_6 = 6,    // 256KB
    order_7 = 7,    // 512KB
    order_8 = 8,    // 1MB
    order_9 = 9,    // 2MB (PMD)
    order_10 = 10,  // 4MB
    order_12 = 12,  // 16MB
    order_18 = 18,  // 1GB (PUD)
};

/// Folio flags (PG_* flags)
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
    owner_priv_1: bool = false,
    arch_1: bool = false,
    reserved: bool = false,
    private: bool = false,
    private_2: bool = false,
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
    arch_2: bool = false,
    arch_3: bool = false,
    // Zxyphor
    zxy_pinned: bool = false,
    zxy_trusted: bool = false,
    zxy_compressed: bool = false,
    _padding: u33 = 0,
};

/// Folio descriptor
pub const FolioDesc = struct {
    flags: FolioFlags = .{},
    order: u8 = 0,
    mapping: u64 = 0,      // address_space
    index: u64 = 0,         // page cache index
    private: u64 = 0,
    refcount: u32 = 0,
    mapcount: i32 = 0,
    memcg: u64 = 0,         // memory cgroup
    lru_gen: u32 = 0,       // multi-gen LRU generation
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
    not_suitable_zone = 0,
    skipped = 1,
    deferred = 2,
    no_suitable_page = 3,
    continue_run = 4,
    partial_skipped = 5,
    complete = 6,
    success = 7,
};

/// Compaction statistics
pub const CompactStats = struct {
    nr_migrated: u64 = 0,
    nr_failed: u64 = 0,
    nr_scanned_free: u64 = 0,
    nr_scanned_migrate: u64 = 0,
    compact_stall: u64 = 0,
    compact_fail: u64 = 0,
    compact_success: u64 = 0,
    compact_isolated: u64 = 0,
    compact_migrate_scanned: u64 = 0,
    compact_free_scanned: u64 = 0,
    compact_daemon_wake: u64 = 0,
    compact_daemon_migrate_scanned: u64 = 0,
    compact_daemon_free_scanned: u64 = 0,
};

/// Compaction proactiveness
pub const CompactConfig = struct {
    proactiveness: u32 = 20,      // 0-100
    extfrag_threshold: u32 = 500,
    min_order: u8 = 0,
};

// ============================================================================
// THP (Transparent Huge Pages) Detail
// ============================================================================

/// THP enabled mode
pub const ThpEnabled = enum(u8) {
    always = 0,
    madvise = 1,
    never = 2,
};

/// THP defrag mode
pub const ThpDefrag = enum(u8) {
    always = 0,
    defer = 1,
    defer_madvise = 2,
    madvise = 3,
    never = 4,
};

/// THP allocation
pub const ThpAllocFlags = packed struct(u32) {
    pmd: bool = false,
    pud: bool = false,
    file: bool = false,
    shmem: bool = false,
    // Zxyphor
    zxy_adaptive: bool = false,
    _padding: u27 = 0,
};

/// THP statistics
pub const ThpStats = struct {
    thp_fault_alloc: u64 = 0,
    thp_fault_fallback: u64 = 0,
    thp_fault_fallback_charge: u64 = 0,
    thp_collapse_alloc: u64 = 0,
    thp_collapse_alloc_failed: u64 = 0,
    thp_file_alloc: u64 = 0,
    thp_file_fallback: u64 = 0,
    thp_file_fallback_charge: u64 = 0,
    thp_file_mapped: u64 = 0,
    thp_split_page: u64 = 0,
    thp_split_page_failed: u64 = 0,
    thp_deferred_split_page: u64 = 0,
    thp_split_pmd: u64 = 0,
    thp_scan_exceed_none_pte: u64 = 0,
    thp_scan_exceed_swap_pte: u64 = 0,
    thp_scan_exceed_share_pte: u64 = 0,
    thp_zero_page_alloc: u64 = 0,
    thp_zero_page_alloc_failed: u64 = 0,
    thp_swpout: u64 = 0,
    thp_swpout_fallback: u64 = 0,
    // Zxyphor
    zxy_thp_adaptive_up: u64 = 0,
    zxy_thp_adaptive_down: u64 = 0,
};

// ============================================================================
// HugeTLB Detail
// ============================================================================

/// HugeTLB page size
pub const HugeTlbSize = enum(u8) {
    size_2m = 0,     // x86 PMD
    size_1g = 1,     // x86 PUD
    size_512m = 2,   // other arch
    size_256m = 3,
    size_64k = 4,    // ARM
    size_32m = 5,
    size_16m = 6,
    size_16k = 7,
};

/// HugeTLB pool statistics
pub const HugeTlbPoolStats = struct {
    size: HugeTlbSize = .size_2m,
    nr_hugepages: u64 = 0,
    nr_overcommit: u64 = 0,
    free_hugepages: u64 = 0,
    resv_hugepages: u64 = 0,
    surplus_hugepages: u64 = 0,
};

/// HugeTLB fault type
pub const HugeTlbFaultType = enum(u8) {
    none = 0,
    cow = 1,
    anon = 2,
    truncate = 3,
    migration = 4,
    hwpoison = 5,
};

// ============================================================================
// Page Owner / Page Poison
// ============================================================================

/// Page owner info (CONFIG_PAGE_OWNER)
pub const PageOwnerInfo = struct {
    order: u8 = 0,
    gfp_mask: u32 = 0,
    handle: u32 = 0,          // stack depot handle
    ts_nsec: u64 = 0,
    free_ts_nsec: u64 = 0,
    pid: i32 = 0,
    tgid: i32 = 0,
    comm: [16]u8 = [_]u8{0} ** 16,
};

/// Page poison value
pub const PAGE_POISON_PATTERN: u8 = 0xAA;
pub const PAGE_ALLOC_TAG: u8 = 0x6B;

// ============================================================================
// Memory Balloon
// ============================================================================

/// Balloon driver type
pub const BalloonDriverType = enum(u8) {
    virtio = 0,
    vmware = 1,
    hyperv = 2,
    xen = 3,
    // Zxyphor
    zxy_native = 100,
};

/// Balloon state
pub const BalloonState = struct {
    driver: BalloonDriverType = .virtio,
    target_pages: u64 = 0,
    current_pages: u64 = 0,
    inflated: u64 = 0,
    deflated: u64 = 0,
    free_page_hint_supported: bool = false,
    stats_reporting: bool = false,
};

// ============================================================================
// Memory Management Subsystem Manager
// ============================================================================

pub const MmDetailSubsystem = struct {
    nr_cma_areas: u32 = 0,
    default_mpol: MpolMode = .default,
    zswap_enabled: bool = false,
    nr_zram_devices: u32 = 0,
    thp_enabled: ThpEnabled = .madvise,
    thp_defrag: ThpDefrag = .madvise,
    compact_proactiveness: u32 = 20,
    hugetlb_max_size: HugeTlbSize = .size_2m,
    page_owner_enabled: bool = false,
    page_poison_enabled: bool = false,
    balloon_active: bool = false,
    thp_stats: ThpStats = .{},
    compact_stats: CompactStats = .{},
    initialized: bool = false,

    pub fn init() MmDetailSubsystem {
        return MmDetailSubsystem{
            .initialized = true,
        };
    }
};
