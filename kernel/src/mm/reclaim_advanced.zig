// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Advanced Swap and Page Reclaim
// Swap management, page reclaim heuristics, multi-generational LRU (MGLRU),
// folio management, workingset detection, page writeback, dirty throttling,
// transparent huge page (THP) collapse/split, memory compaction, OOM
// More advanced than Linux 2026 reclaim architecture

const std = @import("std");

// ============================================================================
// Page Flags (Extended)
// ============================================================================

pub const PageFlags = packed struct {
    locked: bool,
    referenced: bool,
    uptodate: bool,
    dirty: bool,
    lru: bool,
    active: bool,
    workingset: bool,
    waiters: bool,
    error: bool,
    slab: bool,
    owner_priv_1: bool,
    arch_1: bool,
    reserved: bool,
    private: bool,
    private_2: bool,
    writeback: bool,
    head: bool,          // Compound head
    reclaim: bool,
    swapbacked: bool,
    unevictable: bool,
    mlocked: bool,
    uncached: bool,
    hwpoison: bool,
    reported: bool,
    double_map: bool,
    idle: bool,
    young: bool,
    mappedtodisk: bool,
    // Zxyphor extensions
    zxy_pinned: bool,
    zxy_crypto: bool,
    zxy_compressed: bool,
    _padding: u1 = 0,
};

// ============================================================================
// LRU Lists
// ============================================================================

pub const LruType = enum(u8) {
    inactive_anon = 0,
    active_anon = 1,
    inactive_file = 2,
    active_file = 3,
    unevictable = 4,
};

pub const NR_LRU_LISTS: u8 = 5;

pub const LruList = struct {
    head: ?*LruEntry,
    tail: ?*LruEntry,
    nr_pages: u64,

    pub fn is_empty(self: *const LruList) bool {
        return self.nr_pages == 0;
    }
};

pub const LruEntry = struct {
    next: ?*LruEntry,
    prev: ?*LruEntry,
    flags: PageFlags,
    pfn: u64,
    mapping: ?*anyopaque,
    index: u64,
    refcount: u32,
    mapcount: i32,
};

pub const LruVec = struct {
    lists: [NR_LRU_LISTS]LruList,
    // MGLRU
    generations: [4]MglruGen,
    nr_generations: u32,
    min_seq: [2]u64,    // [anon, file]
    max_seq: u64,
    // Stats
    nr_scanned: [NR_LRU_LISTS]u64,
    nr_rotated: [NR_LRU_LISTS]u64,
    nr_pages_total: u64,

    pub fn total_inactive(self: *const LruVec) u64 {
        return self.lists[@intFromEnum(LruType.inactive_anon)].nr_pages +
            self.lists[@intFromEnum(LruType.inactive_file)].nr_pages;
    }

    pub fn total_active(self: *const LruVec) u64 {
        return self.lists[@intFromEnum(LruType.active_anon)].nr_pages +
            self.lists[@intFromEnum(LruType.active_file)].nr_pages;
    }
};

// ============================================================================
// Multi-Generational LRU (MGLRU) - Linux 6.1+
// ============================================================================

pub const MGLRU_MAX_GENS: u32 = 4;
pub const MGLRU_NR_TYPES: u32 = 2;  // anon, file

pub const MglruGen = struct {
    // Folios in this generation
    nr_pages: [MGLRU_NR_TYPES][4]u64,  // per-zone
    // Birth timestamp
    birth: u64,
    // Sequence number
    seq: u64,
    // Referenced bitmap
    mm_stats: [2]u64,  // [0]=walk, [1]=young
};

pub const MglruWalkState = struct {
    // Page table walking
    next_addr: u64,
    bitmap: [64]u64,    // 4096 pages
    nr_pages: u32,
    seq: u64,
    can_swap: bool,
    force_scan: bool,
    // Stats
    nr_walked: u64,
    nr_young: u64,
    nr_old: u64,
};

pub const MglruCtrl = struct {
    enabled: bool,
    min_ttl_ms: u32,
    // Aging
    max_gens: u32,
    // Eviction
    swappiness: u32,      // 0-200
    // Stats
    nr_aging: u64,
    nr_eviction: u64,
    nr_promotion: u64,
};

// ============================================================================
// Folio Management (Linux 5.16+)
// ============================================================================

pub const FolioOrder = u8;  // 0=4K, 1=8K, ..., 9=2M (THP)

pub const Folio = struct {
    flags: PageFlags,
    mapping: ?*anyopaque,
    index: u64,
    // Reference counting
    refcount: u32,
    mapcount: u32,
    // Size
    order: FolioOrder,
    // LRU
    lru_type: LruType,
    lru_gen: u32,
    // Writeback
    wb_list_next: ?*Folio,
    // Swap
    swap_entry: u64,
    // Memory cgroup
    memcg_data: u64,
    // Stats
    nr_pages_mapped: u32,
    nr_pages_dirty: u32,
    deferred_list: ?*Folio,
    // Private data
    priv: ?*anyopaque,

    pub fn nr_pages(self: *const Folio) u64 {
        return @as(u64, 1) << self.order;
    }

    pub fn size_bytes(self: *const Folio) u64 {
        return self.nr_pages() * 4096;
    }

    pub fn is_large(self: *const Folio) bool {
        return self.order > 0;
    }

    pub fn is_thp(self: *const Folio) bool {
        return self.order >= 9;  // 2MB
    }
};

// ============================================================================
// Swap Management
// ============================================================================

pub const SwapType = enum(u8) {
    partition = 0,
    file = 1,
    zswap = 2,
    zram = 3,
    nbd = 4,      // Network block device
    // Zxyphor
    zxy_nvme_swap = 5,
    zxy_remote = 6,
};

pub const SwapInfo = struct {
    swap_type: SwapType,
    flags: u32,
    prio: i16,
    pages: u64,
    inuse_pages: u64,
    lowest_bit: u64,
    highest_bit: u64,
    cluster_next: u64,
    cluster_nr: u64,
    // Device
    bdev: ?*anyopaque,
    swap_file: ?*anyopaque,
    // Clusters (SSD optimization)
    cluster_info: ?*SwapClusterInfo,
    nr_clusters: u32,
    free_clusters: u32,
    // Extent list (file-backed)
    nr_extents: u32,
    curr_swap_extent: u32,
    // Stats
    swap_ins: u64,
    swap_outs: u64,
    discard_pages: u64,

    pub fn usage_percent(self: *const SwapInfo) f64 {
        if (self.pages == 0) return 0.0;
        return @as(f64, @floatFromInt(self.inuse_pages)) * 100.0 /
            @as(f64, @floatFromInt(self.pages));
    }
};

pub const SwapClusterInfo = struct {
    flags: u32,
    data: u32,
    count: u32,
};

pub const SwapEntry = packed struct {
    val: u64,

    pub fn swap_type(self: SwapEntry) u8 {
        return @truncate(self.val & 0x1F);
    }

    pub fn swap_offset(self: SwapEntry) u64 {
        return self.val >> 5;
    }

    pub fn is_swap_entry(self: SwapEntry) bool {
        return self.val != 0;
    }
};

pub const MAX_SWAPFILES: u32 = 32;

pub const SwapSubsystem = struct {
    swap_info: [MAX_SWAPFILES]SwapInfo,
    nr_swapfiles: u32,
    total_swap_pages: u64,
    nr_swap_pages: u64,  // free
    // Swap cache
    swap_cache_info: SwapCacheInfo,
    // Readahead
    swap_ra_order: u32,
    swap_ra_win: u32,
    // Stats
    pswpin: u64,
    pswpout: u64,

    pub fn swap_free_percent(self: *const SwapSubsystem) f64 {
        if (self.total_swap_pages == 0) return 100.0;
        return @as(f64, @floatFromInt(self.nr_swap_pages)) * 100.0 /
            @as(f64, @floatFromInt(self.total_swap_pages));
    }
};

pub const SwapCacheInfo = struct {
    add_total: u64,
    del_total: u64,
    find_success: u64,
    find_total: u64,
    noent_race: u64,
    exist_race: u64,
};

// ============================================================================
// Page Reclaim
// ============================================================================

pub const ScanControl = struct {
    nr_to_reclaim: u64,
    nr_reclaimed: u64,
    nr_scanned: u64,
    gfp_mask: u32,
    order: u8,
    priority: i32,          // 0-12, lower = more desperate
    may_writepage: bool,
    may_unmap: bool,
    may_swap: bool,
    may_deactivate: u32,    // LRU_ACTIVE_ANON | LRU_ACTIVE_FILE
    proactive: bool,        // Proactive reclaim
    // Target memory cgroup
    target_mem_cgroup: ?*anyopaque,
    // File vs anon
    file_is_tiny: bool,
    no_demotion: bool,
    // Stats
    nr_taken: u64,
    nr_activate: [NR_LRU_LISTS]u64,
    nr_dirty: u64,
    nr_unqueued_dirty: u64,
    nr_congested: u64,
    nr_writeback: u64,
    nr_immediate: u64,
    nr_ref_keep: u64,
    nr_unmap_fail: u64,
    nr_lazyfree_fail: u64,
};

pub const ReclaimStat = struct {
    nr_dirty: u64,
    nr_unqueued_dirty: u64,
    nr_congested: u64,
    nr_writeback: u64,
    nr_immediate: u64,
    nr_activate: [NR_LRU_LISTS]u64,
    nr_ref_keep: u64,
    nr_unmap_fail: u64,
};

// ============================================================================
// Dirty Throttling
// ============================================================================

pub const DirtyThrottleControl = struct {
    // Global dirty limits
    dirty_background_ratio: u32,        // percent
    dirty_background_bytes: u64,
    dirty_ratio: u32,
    dirty_bytes: u64,
    dirty_writeback_interval: u32,      // centisecs
    dirty_expire_interval: u32,         // centisecs
    // Per-BDI dirty limit
    bdi_dirty: u64,
    bdi_thresh: u64,
    bdi_bg_thresh: u64,
    // Position
    pos_ratio: u64,
    // Balance
    write_bandwidth: u64,
    avg_write_bandwidth: u64,
    dirty_ratelimit: u64,
    balanced_dirty_ratelimit: u64,
    // Task-level
    nr_dirtied: u32,
    nr_dirtied_pause: u32,
    dirty_paused_when: u64,
    dirty_sleep_ms: u64,
    // Strictlimit
    strictlimit: bool,
};

// ============================================================================
// THP (Transparent Huge Pages)
// ============================================================================

pub const ThpMode = enum(u8) {
    always = 0,
    madvise = 1,
    never = 2,
};

pub const ThpDefragMode = enum(u8) {
    always = 0,
    defer = 1,
    defer_madvise = 2,
    madvise = 3,
    never = 4,
};

pub const ThpControl = struct {
    enabled: ThpMode,
    defrag: ThpDefragMode,
    use_zero_page: bool,
    // Shmem THP
    shmem_enabled: ThpMode,
    // Stats
    thp_fault_alloc: u64,
    thp_fault_fallback: u64,
    thp_fault_fallback_charge: u64,
    thp_collapse_alloc: u64,
    thp_collapse_alloc_failed: u64,
    thp_file_alloc: u64,
    thp_file_fallback: u64,
    thp_file_fallback_charge: u64,
    thp_file_mapped: u64,
    thp_split_page: u64,
    thp_split_page_failed: u64,
    thp_deferred_split_page: u64,
    thp_split_pmd: u64,
    thp_scan_exceed_none_pte: u64,
    thp_scan_exceed_swap_pte: u64,
    thp_scan_exceed_share_pte: u64,
    thp_zero_page_alloc: u64,
    thp_zero_page_alloc_failed: u64,
    thp_swpout: u64,
    thp_swpout_fallback: u64,
    // Khugepaged
    khugepaged_pages_collapsed: u64,
    khugepaged_pages_to_scan: u32,
    khugepaged_alloc_sleep_ms: u32,
    khugepaged_scan_sleep_ms: u32,
    khugepaged_full_scans: u64,
    khugepaged_defrag: bool,
    khugepaged_max_ptes_none: u32,
    khugepaged_max_ptes_swap: u32,
    khugepaged_max_ptes_shared: u32,
};

// ============================================================================
// Memory Compaction
// ============================================================================

pub const CompactResult = enum(u8) {
    not_suitable_zone = 0,
    skipped = 1,
    deferred = 2,
    no_suitable_page = 3,
    continue_compaction = 4,
    partial_skipped = 5,
    complete = 6,
    success = 7,
};

pub const CompactMode = enum(u8) {
    none = 0,
    light = 1,       // MIGRATE_ASYNC
    normal = 2,      // MIGRATE_SYNC_LIGHT
    heavy = 3,       // MIGRATE_SYNC
};

pub const CompactionControl = struct {
    order: i32,
    gfp_mask: u32,
    mode: CompactMode,
    zone: u32,
    // Migration scanner
    migrate_pfn: u64,
    // Free scanner
    free_pfn: u64,
    // Result
    result: CompactResult,
    // Stats
    nr_migrated: u64,
    nr_failed: u64,
    nr_freepages: u64,
    whole_zone: bool,
    contended: bool,
    // Proactive compaction
    proactive_threshold: u32,
    // Stats global
    compact_stall: u64,
    compact_fail: u64,
    compact_success: u64,
    compact_daemon_wake: u64,
    compact_daemon_migrate_scanned: u64,
    compact_daemon_free_scanned: u64,
    compact_isolated: u64,
};

// ============================================================================
// OOM Killer
// ============================================================================

pub const OomConstraint = enum(u8) {
    none = 0,
    cpuset = 1,
    memcg = 2,
    memory_policy = 3,
};

pub const OomControl = struct {
    // Policy
    panic_on_oom: u32,          // 0=off, 1=always, 2=default
    oom_kill_allocating_task: bool,
    oom_dump_tasks: bool,
    // Scoring
    oom_score_adj_min: i16,
    // Stats
    oom_kill_count: u64,
    last_oom_kill_time: u64,
    // Reaper
    oom_reaper_active: bool,
    oom_reaper_count: u64,
    // Memory cgroup OOM
    memcg_oom_count: u64,
};

pub const OomCandidate = struct {
    pid: i32,
    tgid: i32,
    uid: u32,
    oom_score: u64,
    oom_score_adj: i16,
    total_vm: u64,       // pages
    rss: u64,
    pgtables: u64,
    swap: u64,
    comm: [16]u8,
};

// ============================================================================
// Workingset Detection
// ============================================================================

pub const WorkingsetInfo = struct {
    // Shadow entries
    nr_shadow_nodes: u64,
    // Refault detection
    nr_refault_activate: [2]u64,  // [anon, file]
    nr_refault: [2]u64,
    // Nonresident age
    timestamp: u64,
    // Window
    prev_refault: u64,
    // Stats
    workingset_refault_anon: u64,
    workingset_refault_file: u64,
    workingset_activate_anon: u64,
    workingset_activate_file: u64,
    workingset_restore_anon: u64,
    workingset_restore_file: u64,
    workingset_nodereclaim: u64,
};

// ============================================================================
// Page Writeback
// ============================================================================

pub const WritebackState = enum(u8) {
    idle = 0,
    running = 1,
    sync = 2,
    kupdate = 3,
    fork = 4,
    background = 5,
    laptop_timer = 6,
};

pub const WritebackControl = struct {
    nr_to_write: u64,
    pages_skipped: u64,
    range_start: u64,
    range_end: u64,
    sync_mode: u8,     // 0=none, 1=data, 2=all
    tagged_writepages: bool,
    for_background: bool,
    for_kupdate: bool,
    for_reclaim: bool,
    for_sync: bool,
    range_cyclic: bool,
    no_cgroup_owner: bool,
    punt_to_cgroup: bool,
};

// ============================================================================
// Balloon / Memory Hotplug / Virtio-mem
// ============================================================================

pub const BalloonState = struct {
    target_pages: u64,
    inflated_pages: u64,
    // Stats
    inflate_count: u64,
    deflate_count: u64,
    total_inflated: u64,
    total_deflated: u64,
    // Free page reporting
    free_page_reporting_enabled: bool,
    reported_pages: u64,
};

pub const VirtioMemState = struct {
    addr: u64,
    region_size: u64,
    block_size: u64,
    nr_blocks: u64,
    // State bitmap
    plugged_size: u64,
    requested_size: u64,
    // Stats
    plugged_count: u64,
    unplugged_count: u64,
};

// ============================================================================
// Full Reclaim Subsystem Manager
// ============================================================================

pub const ReclaimSubsystem = struct {
    // LRU vectors (per-node)
    lru_vecs: [64]LruVec,    // per-NUMA-node
    nr_nodes: u32,
    // MGLRU
    mglru: MglruCtrl,
    // Swap
    swap: SwapSubsystem,
    // Dirty throttling
    dirty: DirtyThrottleControl,
    // THP
    thp: ThpControl,
    // Compaction
    compaction: CompactionControl,
    // OOM
    oom: OomControl,
    // Workingset
    workingset: WorkingsetInfo,
    // Balloon
    balloon: BalloonState,
    virtio_mem: VirtioMemState,
    // VM tuning knobs
    vm_swappiness: u32,          // 0-200 (Linux 6.x default 60)
    vm_vfs_cache_pressure: u32,  // Default 100
    vm_min_free_kbytes: u64,
    vm_watermark_boost_factor: u32,
    vm_watermark_scale_factor: u32,
    vm_overcommit_memory: u8,    // 0=heuristic, 1=always, 2=never
    vm_overcommit_ratio: u32,
    vm_dirty_background_ratio: u32,
    vm_dirty_ratio: u32,
    // Per-zone watermarks
    wmark_min: [4]u64,
    wmark_low: [4]u64,
    wmark_high: [4]u64,
    // Kswapd
    kswapd_order: u8,
    kswapd_highest_zoneidx: u8,
    kswapd_wake_count: u64,
    kswapd_run_count: u64,
    // Global stats
    nr_free_pages: u64,
    nr_zone_active_anon: u64,
    nr_zone_inactive_anon: u64,
    nr_zone_active_file: u64,
    nr_zone_inactive_file: u64,
    nr_zone_unevictable: u64,
    nr_zone_write_pending: u64,
    nr_mlock: u64,
    nr_bounce: u64,
    nr_zspages: u64,
    nr_free_cma: u64,
    nr_slab_reclaimable: u64,
    nr_slab_unreclaimable: u64,
    nr_page_table_pages: u64,
    nr_dirty: u64,
    nr_writeback: u64,
    nr_writeback_temp: u64,
    nr_anon_pages: u64,
    nr_mapped: u64,
    nr_file_pages: u64,
    nr_shmem: u64,
    nr_shmem_hugepages: u64,
    nr_shmem_pmdmapped: u64,
    nr_file_hugepages: u64,
    nr_file_pmdmapped: u64,
    nr_anon_transparent_hugepages: u64,
    nr_vmscan_write: u64,
    nr_vmscan_immediate_reclaim: u64,
    nr_dirtied: u64,
    nr_written: u64,
    nr_throttled_written: u64,
    nr_kernel_misc_reclaimable: u64,
    nr_foll_pin_acquired: u64,
    nr_foll_pin_released: u64,
    nr_kernel_stack: u64,
    // Zxyphor
    zxy_predictive_reclaim_enabled: bool,
    zxy_ai_swap_prefetch: bool,
    initialized: bool,

    pub fn memory_pressure_score(self: *const ReclaimSubsystem) u32 {
        // 0 = no pressure, 100 = extreme
        if (self.nr_free_pages == 0) return 100;
        const total = self.nr_free_pages + self.nr_zone_active_anon +
            self.nr_zone_inactive_anon + self.nr_zone_active_file +
            self.nr_zone_inactive_file;
        if (total == 0) return 100;
        const free_ratio = (self.nr_free_pages * 100) / total;
        if (free_ratio > 50) return 0;
        return @truncate(100 - (free_ratio * 2));
    }
};
