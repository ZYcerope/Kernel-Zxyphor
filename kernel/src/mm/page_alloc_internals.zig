// Zxyphor Kernel - Page Allocator Internals Detail
// Buddy allocator, zone management, watermarks, kswapd,
// free area, page blocks, compaction triggers, GFP flags detail
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// GFP (Get Free Pages) Flags - Complete
// ============================================================================

pub const GfpFlags = packed struct(u32) {
    dma: bool = false,            // GFP_DMA
    highmem: bool = false,        // __GFP_HIGHMEM
    dma32: bool = false,          // __GFP_DMA32
    movable: bool = false,        // __GFP_MOVABLE
    reclaimable: bool = false,    // __GFP_RECLAIMABLE
    high: bool = false,           // __GFP_HIGH
    io: bool = false,             // __GFP_IO
    fs: bool = false,             // __GFP_FS
    zero: bool = false,           // __GFP_ZERO
    nofail: bool = false,         // __GFP_NOFAIL
    noretry: bool = false,        // __GFP_NORETRY
    memalloc: bool = false,       // __GFP_MEMALLOC
    comp: bool = false,           // __GFP_COMP
    nomemalloc: bool = false,     // __GFP_NOMEMALLOC
    hardwall: bool = false,       // __GFP_HARDWALL
    thisnode: bool = false,       // __GFP_THISNODE
    atomic: bool = false,         // __GFP_ATOMIC
    account: bool = false,        // __GFP_ACCOUNT
    direct_reclaim: bool = false, // __GFP_DIRECT_RECLAIM
    kswapd_reclaim: bool = false, // __GFP_KSWAPD_RECLAIM
    write: bool = false,          // __GFP_WRITE
    nowarn: bool = false,         // __GFP_NOWARN
    retry_mayfail: bool = false,  // __GFP_RETRY_MAYFAIL
    nolockdep: bool = false,      // __GFP_NOLOCKDEP
    no_kswapd: bool = false,      // __GFP_NO_KSWAPD
    _pad: u7 = 0,
};

// Common GFP combinations
pub const GFP_KERNEL: u32 = (1 << 6) | (1 << 7) | (1 << 18) | (1 << 19); // IO|FS|DIRECT_RECLAIM|KSWAPD
pub const GFP_ATOMIC: u32 = (1 << 5) | (1 << 16); // HIGH|ATOMIC
pub const GFP_USER: u32 = GFP_KERNEL | (1 << 14); // KERNEL|HARDWALL
pub const GFP_HIGHUSER: u32 = GFP_USER | (1 << 1); // USER|HIGHMEM
pub const GFP_HIGHUSER_MOVABLE: u32 = GFP_HIGHUSER | (1 << 3); // HIGHUSER|MOVABLE
pub const GFP_DMA: u32 = 1 << 0;
pub const GFP_DMA32: u32 = 1 << 2;
pub const GFP_NOWAIT: u32 = 1 << 19; // KSWAPD_RECLAIM only
pub const GFP_NOFS: u32 = (1 << 6) | (1 << 18) | (1 << 19); // IO|DIRECT_RECLAIM|KSWAPD

// ============================================================================
// Zone Types
// ============================================================================

pub const ZoneType = enum(u8) {
    zone_dma = 0,           // 0-16 MB
    zone_dma32 = 1,         // 0-4 GB
    zone_normal = 2,        // direct-mapped
    zone_highmem = 3,       // x86-32 only
    zone_movable = 4,       // for memory hotplug
    zone_device = 5,        // device memory (pmem, hmm)
    max_nr_zones = 6,
};

// ============================================================================
// Zone Structure
// ============================================================================

pub const Zone = struct {
    // Watermarks
    watermark: [4]u64,      // min, low, high, promo
    watermark_boost: u64,
    nr_reserved_highatomic: u64,
    // Long-lived dirty throttle
    dirty_limit_tstamp: u64,
    // Per-CPU page sets
    per_cpu_pageset: u64,
    per_cpu_zonestats: u64,
    // Free area (buddy system)
    free_area: [11]FreeArea, // MAX_ORDER = 10 (0..10)
    // Flags
    flags: ZoneFlags,
    // Lock (hot path)
    lock: u64,
    // Zone type
    zone_type: ZoneType,
    // Padding for cache line alignment
    // Zone stats
    vm_stat: [48]i64,       // NR_VM_ZONE_STAT_ITEMS
    vm_numa_event: [16]u64, // NR_VM_NUMA_EVENT_ITEMS
    // Pages
    zone_start_pfn: u64,
    managed_pages: u64,
    spanned_pages: u64,
    present_pages: u64,
    present_early_pages: u64,
    cma_pages: u64,
    // Name
    name: [16]u8,
    // Node
    node: u32,
    // NUMA balancing
    min_unmapped_pages: u64,
    min_slab_pages: u64,
    // Compaction
    compact_cached_free_pfn: u64,
    compact_cached_migrate_pfn: [2]u64,
    compact_init_free_pfn: u64,
    compact_init_migrate_pfn: u64,
    compact_considered: u32,
    compact_defer_shift: u32,
    compact_order_failed: i32,
    compact_blockskip_flush: bool,
    // Contiguous
    contiguous: bool,
    // Initialized
    initialized: bool,
    // Pagesets
    pageset_high_min: u32,
    pageset_high_max: u32,
    pageset_batch: u32,
};

pub const ZoneFlags = packed struct(u32) {
    reclaim_active: bool = false,
    boosted_watermark: bool = false,
    below_high: bool = false,
    waiter: bool = false,
    oom_locked: bool = false,
    _pad: u27 = 0,
};

// ============================================================================
// Free Area (Buddy Allocator Core)
// ============================================================================

pub const FreeArea = struct {
    free_list: [6]FreeList,  // MIGRATE_TYPES (unmovable, movable, reclaimable, pcptype, highatomic, isolate)
    nr_free: u64,
};

pub const FreeList = struct {
    head: u64,    // list_head -> struct page
    count: u64,
};

pub const MigrateType = enum(u8) {
    unmovable = 0,
    movable = 1,
    reclaimable = 2,
    pcptype = 3,
    highatomic = 4,
    isolate = 5,
    types = 6,
};

// ============================================================================
// Per-CPU Pagesets
// ============================================================================

pub const PerCpuPages = struct {
    count: u32,       // pages in per-cpu cache
    high: u32,        // high watermark (refill threshold)
    high_min: u32,
    high_max: u32,
    batch: u32,       // chunk size for buddy add/remove
    free_count: u32,  // free factor
    // Flags
    flags: PcpFlags,
    // Per migrate type lists
    lists: [6]PcpList, // MIGRATE_TYPES
    // Stat
    stat: PerCpuPagesStats,
};

pub const PcpFlags = packed struct(u8) {
    alloc_factor: u4 = 1,
    free_factor: u4 = 0,
};

pub const PcpList = struct {
    head: u64,
    count: u32,
};

pub const PerCpuPagesStats = struct {
    alloc_fast: u64,
    alloc_slow: u64,
    free_fast: u64,
    free_slow: u64,
    refills: u64,
    drains: u64,
};

// ============================================================================
// NUMA pgdat (Page Group Data)
// ============================================================================

pub const PglistData = struct {
    // Zones
    node_zones: [6]Zone,
    node_zonelists: [2]ZoneList,   // ZONELIST_FALLBACK, ZONELIST_NOFALLBACK
    nr_zones: u32,
    // Node info
    node_id: u32,
    node_start_pfn: u64,
    node_present_pages: u64,
    node_spanned_pages: u64,
    // kswapd
    kswapd_failures: u32,
    kswapd_order: u32,
    kswapd_highest_zoneidx: u32,
    kswapd_wait: u64,
    pfmemalloc_wait: u64,
    // Reclaim
    flags: PgdatFlags,
    reclaim_stat: RecvlaimStat,
    min_unmapped_pages: u64,
    min_slab_pages: u64,
    // LRU lists
    lruvec: LruVec,
    // Compaction
    kcompactd_max_order: u32,
    kcompactd_highest_zoneidx: u32,
    kcompactd_wait: u64,
    proactive_compact_trigger: bool,
    // Dirty throttle
    totalreserve_pages: u64,
    // Stats
    vm_stat: [48]i64,
    per_cpu_nodestats: u64,
    // Memory tier
    memtier: u64,
};

pub const PgdatFlags = packed struct(u32) {
    reclaim_active: bool = false,
    dirty_balanced: bool = false,
    kswapd_running: bool = false,
    oom_lock: bool = false,
    writeback_congested: bool = false,
    _pad: u27 = 0,
};

pub const ZoneList = struct {
    zoneref: [24]ZoneRef,  // MAX_NUMNODES * MAX_NR_ZONES
    count: u32,
};

pub const ZoneRef = struct {
    zone: ?*Zone,
    zone_idx: u8,
};

// ============================================================================
// LRU (Least Recently Used) Lists
// ============================================================================

pub const LruType = enum(u8) {
    inactive_anon = 0,
    active_anon = 1,
    inactive_file = 2,
    active_file = 3,
    unevictable = 4,
    nr_lru_lists = 5,
};

pub const LruVec = struct {
    lists: [5]LruList,    // NR_LRU_LISTS
    // MGLRU (Multi-Gen LRU)
    lrugen: LruGen,
    // Lock
    lru_lock: u64,
    // Non-resident
    nonresident_age: u64,
    // Refaults
    refaults: [2]u64,
    // Flags
    flags: LruVecFlags,
};

pub const LruList = struct {
    head: u64,
    count: u64,
};

pub const LruVecFlags = packed struct(u8) {
    mglru_enabled: bool = false,
    _pad: u7 = 0,
};

// ============================================================================
// Multi-Gen LRU (MGLRU)
// ============================================================================

pub const LruGen = struct {
    max_seq: u64,
    min_seq: [2]u64,          // anon, file
    timestamps: [4]u64,       // last access per gen (MAX_NR_GENS=4)
    // Folios
    folios: [4][2][2]u64,    // [gen][type][zone]
    nr_pages: [4][2][2]u64,  // counters
    // Promoted
    promoted: [2]u64,
    // Aging
    avg_total: [2]u64,
    avg_refaulted: [2]u64,
    // Eviction
    failed: u8,
    enabled: bool,
};

pub const MGLRU_MAX_NR_GENS: u32 = 4;
pub const MGLRU_MIN_NR_GENS: u32 = 2;

// ============================================================================
// Reclaim Statistics
// ============================================================================

pub const RecvlaimStat = struct {
    recent_rotated: [2]u64,   // anon, file
    recent_scanned: [2]u64,
};

// ============================================================================
// kswapd Control
// ============================================================================

pub const KswapdControl = struct {
    order: u32,
    highest_zoneidx: u32,
    // Priority (0 = highest)
    priority: u32,
    // Scan control
    scan_control: ScanControl,
    // Stats
    pages_scanned: u64,
    pages_reclaimed: u64,
    pages_written: u64,
    slabs_scanned: u64,
    wakeups: u64,
    sleeps: u64,
};

pub const ScanControl = struct {
    nr_to_reclaim: u64,
    gfp_mask: u32,
    order: u32,
    target_mem_cgroup: u64,
    // Flags
    may_writepage: bool,
    may_unmap: bool,
    may_swap: bool,
    memcg_low_reclaim: bool,
    memcg_low_skipped: bool,
    hibernation_mode: bool,
    compaction_ready: bool,
    cache_trim_mode: bool,
    file_is_tiny: bool,
    no_demotion: bool,
    // State
    priority: u32,
    nr_scanned: u64,
    nr_reclaimed: u64,
    nr_dirty: u64,
    nr_unqueued_dirty: u64,
    nr_congested: u64,
    nr_writeback: u64,
    nr_immediate: u64,
    nr_ref_keep: u64,
    nr_unmap_fail: u64,
    nr_lazyfree_fail: u64,
    nr_demoted: u64,
};

// ============================================================================
// Page Block Type
// ============================================================================

pub const PageBlockFlags = packed struct(u8) {
    skip: bool = false,       // skip during compaction
    migrate_type: u3 = 0,    // MigrateType
    _pad: u4 = 0,
};

pub const PAGES_PER_SECTION: u64 = 1 << 15; // 32768

// ============================================================================
// OOM (Out of Memory) Killer
// ============================================================================

pub const OomControl = struct {
    enabled: bool,
    totalpages: u64,
    badness_adj: i32,       // -1000 to 1000
    constraint: OomConstraint,
    // Stats
    oom_kill_count: u64,
    last_oom_kill_time_ns: u64,
    oom_score_adj_min: i32,
    panic_on_oom: u8,       // 0 = off, 1 = panic on oom, 2 = panic on global oom
    oom_kill_allocating_task: bool,
};

pub const OomConstraint = enum(u8) {
    none = 0,
    cpuset = 1,
    memcg = 2,
    memory_policy = 3,
};

// ============================================================================
// Page Allocator Manager
// ============================================================================

pub const PageAllocManager = struct {
    num_nodes: u32,
    num_zones: u32,
    total_pages: u64,
    free_pages: u64,
    // Orders
    max_order: u32,
    pageblock_order: u32,
    // Global stats
    total_allocs: u64,
    total_frees: u64,
    total_alloc_failures: u64,
    // Per-order stats
    order_allocs: [11]u64,
    order_frees: [11]u64,
    // kswapd
    kswapd_wakeups: u64,
    kswapd_pages_reclaimed: u64,
    // Direct reclaim
    direct_reclaim_events: u64,
    direct_reclaim_pages: u64,
    // Compaction
    compaction_stalls: u64,
    compaction_success: u64,
    compaction_fail: u64,
    // OOM
    oom_kill_count: u64,
    // MGLRU
    mglru_enabled: bool,
    initialized: bool,

    pub fn init() PageAllocManager {
        return PageAllocManager{
            .num_nodes = 1,
            .num_zones = 3,
            .total_pages = 0,
            .free_pages = 0,
            .max_order = 10,
            .pageblock_order = 9,
            .total_allocs = 0,
            .total_frees = 0,
            .total_alloc_failures = 0,
            .order_allocs = [_]u64{0} ** 11,
            .order_frees = [_]u64{0} ** 11,
            .kswapd_wakeups = 0,
            .kswapd_pages_reclaimed = 0,
            .direct_reclaim_events = 0,
            .direct_reclaim_pages = 0,
            .compaction_stalls = 0,
            .compaction_success = 0,
            .compaction_fail = 0,
            .oom_kill_count = 0,
            .mglru_enabled = true,
            .initialized = true,
        };
    }
};
