// SPDX-License-Identifier: MIT
// Zxyphor Kernel - vmalloc, vmap, ioremap, early memory, memblock,
// memory model, physical memory extent tracking
// More advanced than Linux 2026 virtual memory management

const std = @import("std");

// ============================================================================
// Memblock (Early boot memory allocator)
// ============================================================================

pub const MemblockFlags = packed struct {
    none: bool = false,
    hotplug: bool = false,
    mirror: bool = false,
    nomap: bool = false,
    driver_managed: bool = false,
    // Zxyphor
    zxy_persistent: bool = false,
    _padding: u2 = 0,
};

pub const MemblockRegion = struct {
    base: u64 = 0,
    size: u64 = 0,
    flags: MemblockFlags = .{},
    nid: i32 = 0,       // NUMA node id

    pub fn end(self: *const MemblockRegion) u64 {
        return self.base + self.size;
    }
    pub fn contains(self: *const MemblockRegion, addr: u64) bool {
        return addr >= self.base and addr < self.end();
    }
};

pub const MemblockType = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    nr_regions: u32 = 0,
    max_regions: u32 = 0,
    total_size: u64 = 0,
};

pub const MemblockState = struct {
    memory: MemblockType = .{},       // Available memory
    reserved: MemblockType = .{},     // Reserved memory
    bottom_up: bool = false,
    current_limit: u64 = 0xFFFFFFFFFFFFFFFF,
    // Stats
    total_alloc_bytes: u64 = 0,
    total_free_bytes: u64 = 0,
    nr_alloc_calls: u64 = 0,
    nr_free_calls: u64 = 0,
};

// ============================================================================
// E820 Memory Map
// ============================================================================

pub const E820Type = enum(u32) {
    ram = 1,
    reserved = 2,
    acpi = 3,
    nvs = 4,
    unusable = 5,
    pmem = 7,
    pram = 12,
    soft_reserved = 0xF0000,
    // Zxyphor
    zxy_secure = 0xF0001,
};

pub const E820Entry = struct {
    addr: u64 = 0,
    size: u64 = 0,
    entry_type: E820Type = .ram,

    pub fn end(self: *const E820Entry) u64 {
        return self.addr + self.size;
    }
};

pub const E820Table = struct {
    nr_entries: u32 = 0,
    max_entries: u32 = 128,
    // Derived
    total_ram: u64 = 0,
    total_reserved: u64 = 0,
    total_pmem: u64 = 0,
    highest_ram: u64 = 0,
};

// ============================================================================
// vmalloc / vmap
// ============================================================================

pub const VmFlags = packed struct {
    ioremap: bool = false,
    alloc: bool = false,
    map: bool = false,
    usermap: bool = false,
    dma_coherent: bool = false,
    flush_reset_perms: bool = false,
    huge_pages: bool = false,
    no_guard: bool = false,
    map_put_pages: bool = false,
    allow_huge: bool = false,
    // Zxyphor
    zxy_persistent: bool = false,
    _padding: u5 = 0,
};

pub const VmStruct = struct {
    addr: u64 = 0,           // Virtual address
    size: u64 = 0,
    flags: VmFlags = .{},
    nr_pages: u32 = 0,
    phys_addr: u64 = 0,      // For ioremap
    caller: u64 = 0,         // Return address of allocator
};

pub const VmallocInfo = struct {
    // Address space
    vmalloc_start: u64 = 0,
    vmalloc_end: u64 = 0,
    vmalloc_total: u64 = 0,
    // Usage
    vmalloc_used: u64 = 0,
    vmalloc_chunk: u64 = 0,   // Largest free chunk
    nr_vmalloc_areas: u32 = 0,
    // Huge pages
    nr_huge_pages_vmalloc: u64 = 0,
    // Stats
    total_vmalloc_calls: u64 = 0,
    total_vfree_calls: u64 = 0,
    total_vmap_calls: u64 = 0,
    total_vunmap_calls: u64 = 0,
    total_ioremap_calls: u64 = 0,
    total_iounmap_calls: u64 = 0,
    // Lazy free
    lazy_free_pages: u64 = 0,
    nr_lazy_max: u64 = 0,
    // Purge
    total_purge_calls: u64 = 0,
    total_purged_areas: u64 = 0,
};

// ============================================================================
// ioremap
// ============================================================================

pub const IoremapType = enum(u8) {
    uncacheable = 0,        // UC
    write_combining = 1,    // WC
    write_through = 2,      // WT
    write_back = 3,         // WB
    write_protect = 4,      // WP
    nocache = 5,            // Strong uncacheable
    cache = 6,              // Normal cacheable
    encrypted = 7,          // For SEV
};

pub const IoremapRegion = struct {
    phys_addr: u64 = 0,
    virt_addr: u64 = 0,
    size: u64 = 0,
    remap_type: IoremapType = .uncacheable,
    // Tracking
    caller: u64 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
};

// ============================================================================
// Memory Model
// ============================================================================

pub const MemoryModel = enum(u8) {
    flatmem = 0,          // Single flat array
    sparsemem = 1,        // Sparse sections
    sparsemem_vmemmap = 2, // Sparse with vmemmap
};

pub const MemSection = struct {
    section_mem_map: u64 = 0,
    usage: u64 = 0,
    page_ext: u64 = 0,
    // Section info
    section_nr: u64 = 0,
    present: bool = false,
    online: bool = false,
    early: bool = false,
    nid: i32 = 0,
};

// Section size: typically 128MB (27 bit)
pub const SECTION_SIZE_BITS: u6 = 27;
pub const PAGES_PER_SECTION: u64 = 1 << (SECTION_SIZE_BITS - 12);

// ============================================================================
// Page Extension (page_ext)
// ============================================================================

pub const PageExtFlags = packed struct {
    owner_tracking: bool = false,
    idle_tracking: bool = false,
    table_tracking: bool = false,
    _padding: u5 = 0,
};

pub const PageOwnerInfo = struct {
    order: u8 = 0,
    gfp_mask: u32 = 0,
    pid: i32 = 0,
    tgid: i32 = 0,
    ts_nsec: u64 = 0,
    free_ts_nsec: u64 = 0,
    comm: [16]u8 = [_]u8{0} ** 16,
    nr_entries: u8 = 0,
};

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

pub const CmaArea = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    base_pfn: u64 = 0,
    count: u64 = 0,            // Number of pages
    order_per_bit: u32 = 0,
    // Bitmap
    bitmap_pages: u64 = 0,
    // Stats
    nr_pages_succeeded: u64 = 0,
    nr_pages_failed: u64 = 0,
    nr_allocs_succeeded: u64 = 0,
    nr_allocs_failed: u64 = 0,
    // Alignment
    alignment: u64 = 0,
};

pub const CmaSubsystem = struct {
    nr_areas: u32 = 0,
    total_pages: u64 = 0,
    available_pages: u64 = 0,
    total_alloc_success: u64 = 0,
    total_alloc_fail: u64 = 0,
};

// ============================================================================
// HugeTLB
// ============================================================================

pub const HugePageSize = enum(u8) {
    size_2m = 0,            // 2MB
    size_1g = 1,            // 1GB
    size_512m = 2,          // 512MB (some arch)
    size_16m = 3,           // 16MB (powerpc)
    size_16g = 4,           // 16GB (powerpc)
};

pub const HugetlbPool = struct {
    page_size: u64 = 0,
    // Counts
    nr_hugepages: u64 = 0,
    free_hugepages: u64 = 0,
    resv_hugepages: u64 = 0,
    surplus_hugepages: u64 = 0,
    nr_overcommit_hugepages: u64 = 0,
    // NUMA distribution
    per_node_count: [64]u64 = [_]u64{0} ** 64,
    per_node_free: [64]u64 = [_]u64{0} ** 64,
    // Stats
    total_alloc: u64 = 0,
    total_free: u64 = 0,
    total_alloc_failed: u64 = 0,
    // vmemmap optimization
    nr_vmemmap_optimized: u64 = 0,
};

// ============================================================================
// Memory Hotplug
// ============================================================================

pub const MemHotplugState = enum(u8) {
    offline = 0,
    going_online = 1,
    online = 2,
    going_offline = 3,
};

pub const MemoryBlock = struct {
    id: u32 = 0,
    state: MemHotplugState = .offline,
    phys_index: u64 = 0,         // Section number
    nr_sections: u32 = 0,
    // NUMA
    nid: i32 = 0,
    // Zone
    zone_name: [16]u8 = [_]u8{0} ** 16,
    // Removable
    removable: bool = false,
};

pub const MemHotplugStats = struct {
    total_online: u64 = 0,
    total_offline: u64 = 0,
    total_online_failed: u64 = 0,
    total_offline_failed: u64 = 0,
    nr_memory_blocks: u32 = 0,
    nr_online_blocks: u32 = 0,
};

// ============================================================================
// Memory Tiering
// ============================================================================

pub const MemoryTier = enum(u8) {
    tier_0 = 0,    // Fastest (e.g., HBM)
    tier_1 = 1,    // Fast (e.g., DDR5)
    tier_2 = 2,    // Medium (e.g., CXL)
    tier_3 = 3,    // Slow (e.g., persistent memory)
    tier_4 = 4,    // Very slow (e.g., remote memory)
};

pub const MemoryTierConfig = struct {
    tier: MemoryTier = .tier_1,
    nid: i32 = 0,
    // Performance
    read_latency_ns: u32 = 0,
    write_latency_ns: u32 = 0,
    read_bandwidth_mbps: u32 = 0,
    write_bandwidth_mbps: u32 = 0,
    // Migration policy
    promote_threshold_ns: u32 = 0,
    demote_threshold_ns: u32 = 0,
    // Stats
    total_promotions: u64 = 0,
    total_demotions: u64 = 0,
    total_promotion_failures: u64 = 0,
};

// ============================================================================
// DAMON (Data Access Monitoring)
// ============================================================================

pub const DamonOpsType = enum(u8) {
    vaddr = 0,            // Virtual address
    paddr = 1,            // Physical address
    fvaddr = 2,           // Filtered virtual address
};

pub const DamonSamplingConfig = struct {
    sample_interval_us: u64 = 5000,
    aggr_interval_us: u64 = 100000,
    update_interval_us: u64 = 1000000,
    min_nr_regions: u32 = 10,
    max_nr_regions: u32 = 1000,
};

pub const DamonSchemeAction = enum(u8) {
    willneed = 0,
    cold = 1,
    pageout = 2,
    hugepage = 3,
    nohugepage = 4,
    lru_prio = 5,
    lru_deprio = 6,
    stat = 7,
    // Zxyphor
    zxy_tier_promote = 20,
    zxy_tier_demote = 21,
    zxy_compress = 22,
};

pub const DamonScheme = struct {
    action: DamonSchemeAction = .stat,
    // Pattern
    min_sz_region: u64 = 0,
    max_sz_region: u64 = 0xFFFFFFFFFFFFFFFF,
    min_nr_accesses: u32 = 0,
    max_nr_accesses: u32 = 0xFFFFFFFF,
    min_age_region: u32 = 0,
    max_age_region: u32 = 0xFFFFFFFF,
    // Quota
    ms_quota: u64 = 0,           // ms per aggr interval
    bytes_quota: u64 = 0,        // bytes per aggr interval
    reset_interval_ms: u64 = 0,
    // Stats
    nr_tried: u64 = 0,
    sz_tried: u64 = 0,
    nr_applied: u64 = 0,
    sz_applied: u64 = 0,
    qt_exceeds: u64 = 0,
};

// ============================================================================
// Zswap / Zram
// ============================================================================

pub const ZswapConfig = struct {
    enabled: bool = false,
    compressor: [16]u8 = [_]u8{0} ** 16,   // e.g. "lz4", "zstd"
    zpool: [16]u8 = [_]u8{0} ** 16,        // "zbud", "z3fold", "zsmalloc"
    max_pool_percent: u32 = 20,
    accept_threshold_percent: u32 = 90,
    same_filled_pages_enabled: bool = true,
    non_same_filled_pages_enabled: bool = true,
    exclusive_loads: bool = true,
    shrinker_enabled: bool = false,
    // Stats
    pool_total_size: u64 = 0,
    stored_pages: u64 = 0,
    pool_pages: u64 = 0,
    duplicate_entry: u64 = 0,
    written_back_pages: u64 = 0,
    reject_compress_poor: u64 = 0,
    reject_alloc_fail: u64 = 0,
    reject_reclaim_fail: u64 = 0,
    reject_kmemcache_fail: u64 = 0,
    same_filled_pages: u64 = 0,
};

pub const ZramConfig = struct {
    disksize: u64 = 0,
    comp_algorithm: [16]u8 = [_]u8{0} ** 16,
    max_comp_streams: u32 = 0,
    // Stats
    num_reads: u64 = 0,
    num_writes: u64 = 0,
    failed_reads: u64 = 0,
    failed_writes: u64 = 0,
    invalid_io: u64 = 0,
    notify_free: u64 = 0,
    compr_data_size: u64 = 0,
    mem_used_total: u64 = 0,
    mem_limit: u64 = 0,
    mem_used_max: u64 = 0,
    same_pages: u64 = 0,
    huge_pages: u64 = 0,
    huge_pages_since: u64 = 0,
    pages_stored: u64 = 0,
    bd_count: u64 = 0,
    bd_reads: u64 = 0,
    bd_writes: u64 = 0,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const VmmInternalsSubsystem = struct {
    // Memblock
    memblock: MemblockState = .{},
    // E820
    e820_entries: u32 = 0,
    // vmalloc
    vmalloc_info: VmallocInfo = .{},
    // Memory model
    model: MemoryModel = .sparsemem_vmemmap,
    total_sections: u64 = 0,
    online_sections: u64 = 0,
    // CMA
    cma: CmaSubsystem = .{},
    // HugeTLB
    nr_hugetlb_pools: u32 = 0,
    // Hotplug
    hotplug: MemHotplugStats = .{},
    // Tiering
    nr_tiers: u8 = 0,
    // DAMON
    nr_damon_contexts: u32 = 0,
    nr_damon_schemes: u32 = 0,
    // Zswap/Zram
    zswap: ZswapConfig = .{},
    // Zxyphor
    zxy_auto_tiering: bool = false,
    initialized: bool = false,
};
