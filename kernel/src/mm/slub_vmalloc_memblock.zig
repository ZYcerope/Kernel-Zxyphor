// Zxyphor Kernel - SLUB Allocator Internals,
// kmalloc size classes, slab page metadata,
// object freelist, SLUB debug, memcg accounting,
// percpu partial lists, CPU slab caching,
// slab merging, slab_alloc fast/slow paths
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// SLUB Constants
// ============================================================================

pub const SLUB_MIN_SIZE: usize = 8;
pub const SLUB_MAX_SIZE: usize = 8192;
pub const SLUB_MIN_OBJECTS: usize = 4;
pub const SLUB_MAX_OBJECTS: usize = 32767;
pub const SLUB_RED_ZONE: u32 = 0xbb;
pub const SLUB_POISON_FREE: u8 = 0x6b;
pub const SLUB_POISON_ALLOC: u8 = 0xcc;
pub const SLUB_RED_ACTIVE: u32 = 0x170FC2A5;
pub const SLUB_RED_INACTIVE: u32 = 0x73E8A495;
pub const SLUB_CMPXCHG_DOUBLE: bool = true;

// ============================================================================
// Slab Flags
// ============================================================================

pub const SlabFlags = packed struct(u32) {
    consistency_checks: bool = false,
    red_zone: bool = false,
    poison: bool = false,
    hwcache_align: bool = false,
    cache_dma: bool = false,
    cache_dma32: bool = false,
    store_user: bool = false,
    panic: bool = false,
    typesafe_by_rcu: bool = false,
    trace: bool = false,
    debug_initial: bool = false,
    account: bool = false,
    no_merge: bool = false,
    reclaim_account: bool = false,
    destroy_by_rcu: bool = false,
    mhp_freeable: bool = false,
    no_user_copy: bool = false,
    ctor_called: bool = false,
    no_obj_ext: bool = false,
    kasan: bool = false,
    _reserved: u12 = 0,
};

// ============================================================================
// kmalloc Size Classes
// ============================================================================

pub const KmallocSizeIndex = enum(u8) {
    kmalloc_8 = 0,
    kmalloc_16 = 1,
    kmalloc_32 = 2,
    kmalloc_64 = 3,
    kmalloc_96 = 4,
    kmalloc_128 = 5,
    kmalloc_192 = 6,
    kmalloc_256 = 7,
    kmalloc_512 = 8,
    kmalloc_1k = 9,
    kmalloc_2k = 10,
    kmalloc_4k = 11,
    kmalloc_8k = 12,
    kmalloc_16k = 13,
    kmalloc_32k = 14,
    kmalloc_64k = 15,
    kmalloc_128k = 16,
    kmalloc_256k = 17,
    kmalloc_512k = 18,
    kmalloc_1m = 19,
    kmalloc_2m = 20,
};

pub const KmallocType = enum(u8) {
    normal = 0,
    cgroup = 1,
    dma = 2,
    reclaim = 3,
    random = 4,
};

pub const kmalloc_sizes = [_]usize{
    8, 16, 32, 64, 96, 128, 192, 256,
    512, 1024, 2048, 4096, 8192, 16384,
    32768, 65536, 131072, 262144, 524288,
    1048576, 2097152,
};

// ============================================================================
// Slab Cache (kmem_cache)
// ============================================================================

pub const KmemCache = struct {
    name: [64]u8,
    object_size: u32,
    size: u32,             // aligned size with metadata
    align_: u32,
    flags: SlabFlags,
    min_partial: u32,
    inuse: u32,            // offset of usable data
    offset: u32,           // free pointer offset
    oo: KmemCacheOrder,    // optimal order/objects
    max: KmemCacheOrder,   // max order/objects
    min: KmemCacheOrder,   // min order/objects
    allocflags: u32,       // GFP flags
    refcount: i32,
    red_left_pad: u32,
    useroffset: u32,
    usersize: u32,
    ctor: ?*const fn (*anyopaque) void,
    // Percpu data
    cpu_slab: [256]?*KmemCacheCpu,
    // Partial lists
    node: [64]?*KmemCacheNode,
    // Stats
    stats: SlabStats,
    // Debug
    debug: SlabDebugInfo,
    // Memcg
    memcg_params: SlabMemcgParams,
};

pub const KmemCacheOrder = packed struct(u32) {
    objects: u16,
    order: u16,
};

// ============================================================================
// Per-CPU Slab Cache
// ============================================================================

pub const KmemCacheCpu = struct {
    freelist: ?*anyopaque,
    tid: u64,              // transaction ID for cmpxchg
    slab: ?*SlabPage,
    partial: ?*SlabPage,
    partial_count: u32,
    stat: [16]u64,         // per-CPU stats
};

// ============================================================================
// Per-Node Slab Data
// ============================================================================

pub const KmemCacheNode = struct {
    partial: SlabList,
    nr_partial: u32,
    total_objects: u64,
    full: SlabList,
};

pub const SlabList = struct {
    head: ?*SlabPage,
    tail: ?*SlabPage,
    count: u32,
};

// ============================================================================
// Slab Page Metadata (struct slab)
// ============================================================================

pub const SlabPage = struct {
    flags: u64,
    slab_cache: ?*KmemCache,
    freelist: ?*anyopaque,
    objects: u16,
    inuse: u16,
    frozen: bool,
    pfmemalloc: bool,
    next: ?*SlabPage,
    slabs: ?*SlabList,
    // NUMA node
    node: u8,
    // Debug track
    alloc_tracks: ?[*]SlabTrack,
    free_tracks: ?[*]SlabTrack,
};

pub const SlabTrack = struct {
    addr: u64,         // allocation/free site
    handle: u64,       // stack trace handle
    when: u64,         // jiffies
    pid: u32,
    cpu: u16,
};

// ============================================================================
// Slab Allocation Path
// ============================================================================

pub const SlabAllocPath = enum(u8) {
    fast_cmpxchg = 0,      // cmpxchg on freelist (fastest)
    fast_irq_disable = 1,   // IRQ disable + freelist pop
    slow_new_slab = 2,      // allocate new slab page
    slow_partial = 3,       // get from partial list
    slow_node_partial = 4,  // get from node partial
    slow_page_alloc = 5,    // allocate new page(s)
    fallback = 6,           // order fallback
};

pub const SlabFreelistEncode = struct {
    random: u64,    // SLUB_FREELIST_RANDOM seed

    pub fn encode(self: *const SlabFreelistEncode, ptr: u64, ptr_addr: u64) u64 {
        return ptr ^ self.random ^ swab(ptr_addr);
    }

    pub fn decode(self: *const SlabFreelistEncode, encoded: u64, ptr_addr: u64) u64 {
        return encoded ^ self.random ^ swab(ptr_addr);
    }

    fn swab(val: u64) u64 {
        return @byteSwap(val);
    }
};

// ============================================================================
// Slab Debug
// ============================================================================

pub const SlabDebugFlags = packed struct(u32) {
    sanity_checks: bool = false,
    red_zone: bool = false,
    poison: bool = false,
    store_user: bool = false,
    trace: bool = false,
    consistency: bool = false,
    free_track: bool = false,
    alloc_track: bool = false,
    _reserved: u24 = 0,
};

pub const SlabDebugInfo = struct {
    flags: SlabDebugFlags,
    track_count: u32,
    alloc_fastpath: u64,
    alloc_slowpath: u64,
    free_fastpath: u64,
    free_slowpath: u64,
    corruption_detected: u64,
    double_free_detected: u64,
};

// ============================================================================
// Slab Statistics
// ============================================================================

pub const SlabStats = struct {
    alloc_total: u64,
    free_total: u64,
    alloc_fastpath: u64,
    alloc_slowpath: u64,
    free_fastpath: u64,
    free_slowpath: u64,
    alloc_from_partial: u64,
    alloc_slab: u64,
    free_slab: u64,
    free_frozen: u64,
    cpuslab_flush: u64,
    deactivate_full: u64,
    deactivate_empty: u64,
    deactivate_to_head: u64,
    deactivate_to_tail: u64,
    deactivate_remote_frees: u64,
    order_fallback: u64,
    cmpxchg_double_fail: u64,
    cmpxchg_double_cpu_fail: u64,
};

// ============================================================================
// Slab Memcg Accounting
// ============================================================================

pub const SlabMemcgParams = struct {
    memcg_caches: [256]?*KmemCache,   // per-memcg caches
    root_cache: ?*KmemCache,
    is_root_cache: bool,
    memcg: ?*anyopaque,
    charge_bytes: u64,
    uncharge_bytes: u64,
};

// ============================================================================
// vmalloc internals
// ============================================================================

pub const VmallocFlags = packed struct(u32) {
    vm_alloc: bool = false,
    vm_map: bool = false,
    vm_ioremap: bool = false,
    vm_usermap: bool = false,
    vm_dma_coherent: bool = false,
    vm_uninitialized: bool = false,
    vm_no_guard: bool = false,
    vm_kasan: bool = false,
    vm_flush_reset_perms: bool = false,
    vm_huge_pages: bool = false,
    vm_allow_huge_vmap: bool = false,
    _reserved: u21 = 0,
};

pub const VmallocArea = struct {
    addr: u64,
    size: usize,
    flags: VmallocFlags,
    pages: [*]?*anyopaque,
    nr_pages: u32,
    phys_addr: u64,        // for ioremap
    caller: u64,           // allocation site
    node: u8,              // NUMA node
};

pub const VmapBlock = struct {
    va: *VmallocArea,
    free: u32,
    dirty: u64,             // bitmap of dirty pages
    dirty_min: u32,
    dirty_max: u32,
};

pub const VmallocPurge = struct {
    start: u64,
    end: u64,
    area_count: u32,
    total_freed: usize,
    lazy_max_pages: u32,
    lazy_nr_pages: u64,
};

// ============================================================================
// memblock internals (early boot allocator)
// ============================================================================

pub const MemblockType = enum(u8) {
    memory = 0,
    reserved = 1,
    physmem = 2,
};

pub const MemblockFlags = packed struct(u32) {
    none: bool = true,
    hotplug: bool = false,
    mirror: bool = false,
    nomap: bool = false,
    driver_managed: bool = false,
    _reserved: u27 = 0,
};

pub const MemblockRegion = struct {
    base: u64,
    size: u64,
    flags: MemblockFlags,
    nid: i32,        // NUMA node ID
};

pub const Memblock = struct {
    bottom_up: bool,
    current_limit: u64,
    memory: MemblockTypeArr,
    reserved: MemblockTypeArr,
};

pub const MemblockTypeArr = struct {
    cnt: u32,
    max: u32,
    total_size: u64,
    regions: [128]MemblockRegion,
    name: [16]u8,
};

// ============================================================================
// Page Allocator Internals (Buddy System)
// ============================================================================

pub const MAX_ORDER: u8 = 11;       // MAX_ORDER (0..10, pages of order 2^n)
pub const MAX_NR_ZONES: u8 = 5;

pub const ZoneType = enum(u8) {
    zone_dma = 0,
    zone_dma32 = 1,
    zone_normal = 2,
    zone_highmem = 3,
    zone_movable = 4,
    zone_device = 5,
};

pub const MigrateType = enum(u8) {
    unmovable = 0,
    movable = 1,
    reclaimable = 2,
    pcptypes = 3,        // count of types on PCP
    highatomic = 3,
    cma = 4,
    isolate = 5,
    types = 6,
};

pub const FreeArea = struct {
    free_list: [6]ListHead,   // per-migrate-type
    nr_free: u64,
};

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,
};

pub const ZoneDescriptor = struct {
    watermark: [3]u64,         // min, low, high
    watermark_boost: u64,
    nr_reserved_highatomic: u64,
    lowmem_reserve: [6]i64,
    zone_start_pfn: u64,
    managed_pages: u64,
    spanned_pages: u64,
    present_pages: u64,
    name: [16]u8,
    free_area: [11]FreeArea,   // MAX_ORDER
    zone_pgdat: ?*anyopaque,
    // PCP (Per-CPU Page) lists
    per_cpu_pageset: [256]PerCpuPages,
    // Compaction
    compact_cached_free_pfn: u64,
    compact_cached_migrate_pfn: [2]u64,
    compact_considered: u32,
    compact_defer_shift: u32,
    compact_order_failed: i32,
    // VM stat
    vm_stat: [64]i64,
};

pub const PerCpuPages = struct {
    count: i32,
    high: i32,
    batch: i32,
    free_factor: i32,
    lists: [6]ListHead,    // per-migrate-type
    high_min: i32,
    high_max: i32,
};

pub const GfpFlags = packed struct(u32) {
    __gfp_dma: bool = false,
    __gfp_highmem: bool = false,
    __gfp_dma32: bool = false,
    __gfp_movable: bool = false,
    __gfp_reclaimable: bool = false,
    __gfp_high: bool = false,
    __gfp_io: bool = false,
    __gfp_fs: bool = false,
    __gfp_zero: bool = false,
    __gfp_atomic: bool = false,
    __gfp_direct_reclaim: bool = false,
    __gfp_kswapd_reclaim: bool = false,
    __gfp_write: bool = false,
    __gfp_nowarn: bool = false,
    __gfp_retry_mayfail: bool = false,
    __gfp_nofail: bool = false,
    __gfp_noretry: bool = false,
    __gfp_memalloc: bool = false,
    __gfp_comp: bool = false,
    __gfp_nomemalloc: bool = false,
    __gfp_hardwall: bool = false,
    __gfp_thisnode: bool = false,
    __gfp_account: bool = false,
    __gfp_nolockdep: bool = false,
    __gfp_no_kswapd: bool = false,
    _reserved: u7 = 0,
};

// ============================================================================
// KFENCE (Kernel Electric Fence)
// ============================================================================

pub const KFENCE_POOL_SIZE: usize = 2 * 1024 * 1024;
pub const KFENCE_NUM_OBJECTS: usize = 255;

pub const KfenceObjState = enum(u8) {
    unused = 0,
    allocated = 1,
    freed = 2,
};

pub const KfenceMetadata = struct {
    addr: u64,
    size: usize,
    cache: ?*KmemCache,
    state: KfenceObjState,
    alloc_stack_entries: [16]u64,
    alloc_stack_count: u8,
    free_stack_entries: [16]u64,
    free_stack_count: u8,
    alloc_track: SlabTrack,
    free_track: SlabTrack,
};

pub const KfenceErrorType = enum(u8) {
    oob_read = 0,
    oob_write = 1,
    use_after_free_read = 2,
    use_after_free_write = 3,
    invalid_free = 4,
    corruption = 5,
};

// ============================================================================
// Memory Hotplug Detail
// ============================================================================

pub const MemoryBlockState = enum(u8) {
    offline = 0,
    going_offline = 1,
    online = 2,
    going_online = 3,
};

pub const OnlineType = enum(u8) {
    online_keep = 0,
    online_movable = 1,
    online_kernel = 2,
};

pub const MemoryBlock = struct {
    start_section_nr: u64,
    state: MemoryBlockState,
    section_count: u32,
    online_type: OnlineType,
    nid: i32,
    phys_device: u32,
    removable: bool,
    zone: ZoneType,
};

pub const MemSection = struct {
    section_mem_map: u64,
    usage: ?*MemSectionUsage,
    pageblock_flags: ?*anyopaque,
};

pub const MemSectionUsage = struct {
    subsection_map: [4]u64,   // bitmap
    pageblock_flags: [0]u64,
};

// ============================================================================
// Slab Manager (Zxyphor)
// ============================================================================

pub const SlabSubsystemManager = struct {
    caches: [256]?*KmemCache,
    cache_count: u32,
    kmalloc_caches: [5][21]?*KmemCache, // [type][size_index]
    total_allocated: u64,
    total_freed: u64,
    total_slabs: u64,
    debug_flags: SlabDebugFlags,
    kfence_enabled: bool,
    initialized: bool,

    pub fn init() SlabSubsystemManager {
        return std.mem.zeroes(SlabSubsystemManager);
    }
};
