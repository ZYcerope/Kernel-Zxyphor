// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Memory Hotplug, NUMA Balancing, Memory Tiering
// Online/offline, node management, NUMA hinting faults, page promotion/demotion

const std = @import("std");

// ============================================================================
// Memory Hotplug States
// ============================================================================

pub const MemoryBlockState = enum(u8) {
    Online = 0,
    Offline = 1,
    GoingOnline = 2,
    GoingOffline = 3,
};

pub const MemoryZoneTarget = enum(u8) {
    Default = 0,     // kernel chooses
    Normal = 1,
    Movable = 2,
    DMA32 = 3,
};

pub const HotplugAction = enum(u8) {
    Online = 0,
    OfflineRequest = 1,
    Offline = 2,
    OnlineMovable = 3,
    OnlineKernel = 4,
};

pub const MemoryBlock = struct {
    phys_index: u64,          // physical section number
    state: MemoryBlockState,
    phys_device: u32,
    nid: i32,                 // NUMA node ID (-1 if unset)
    zone: MemoryZoneTarget,
    nr_sections: u32,

    // Range
    start_section_nr: u64,
    end_section_nr: u64,
    start_pfn: u64,
    end_pfn: u64,

    // Size
    size_bytes: u64,          // typically 128MB per block

    // Flags
    removable: bool,
    early_added: bool,

    // Reference count
    online_type: u32,
};

// ============================================================================
// Memory Sections
// ============================================================================

pub const PAGES_PER_SECTION: u64 = 1 << 15; // 32768 pages = 128MB (4K pages)
pub const PFN_SECTION_SHIFT: u32 = 15;
pub const SECTION_SIZE_BITS: u32 = 27;     // 128MB

pub const MemSection = struct {
    section_mem_map: u64,     // encoded pointer + flags
    usage: u64,               // mem_section_usage *
    pageblock_flags: u64,
};

pub const MemSectionUsage = struct {
    subsection_map: [4]u64,   // bitmap of 2MB sub-sections
    pageblock_flags: [4096]u8,
};

// ============================================================================
// NUMA Node
// ============================================================================

pub const MAX_NUMNODES: u32 = 1024;
pub const NUMA_NO_NODE: i32 = -1;

pub const NumaNode = struct {
    nid: i32,
    // Memory ranges
    start_pfn: u64,
    end_pfn: u64,
    present_pages: u64,
    spanned_pages: u64,
    // Zones
    nr_zones: u32,
    // Distance to other nodes
    distance: [MAX_NUMNODES]u8,  // distance array, typically 10 = local
    // CPUs
    cpumask: [16]u64,         // up to 1024 CPUs
    nr_cpus: u32,
    // State
    online: bool,
    has_memory: bool,
    has_cpu: bool,
    // Memory tiering
    tier: MemoryTier,
    demotion_target: i32,     // nid of next-lower tier (-1 = none)
    promotion_target: i32,    // nid of next-higher tier (-1 = none)
    // Statistics
    stats: NumaNodeStats,
};

pub const NumaNodeStats = struct {
    total_pages: u64,
    free_pages: u64,
    active_pages: u64,
    inactive_pages: u64,
    dirty_pages: u64,
    writeback_pages: u64,
    slab_reclaimable: u64,
    slab_unreclaimable: u64,
    mapped_pages: u64,
    shmem_pages: u64,
    bounce_pages: u64,
    free_cma_pages: u64,
    // NUMA balancing stats
    numa_hit: u64,
    numa_miss: u64,
    numa_foreign: u64,
    numa_interleave: u64,
    numa_local: u64,
    numa_other: u64,
    // Page demotion/promotion
    pgdemote_kswapd: u64,
    pgdemote_direct: u64,
    pgpromote_success: u64,
    pgpromote_candidate: u64,
};

// ============================================================================
// Memory Tiering (Linux 6.x)
// ============================================================================

pub const MemoryTier = struct {
    tier_id: u32,
    adistance: i32,           // abstract distance (lower = faster)
    device_type: MemTierDeviceType,
    node_list: [MAX_NUMNODES]bool,  // nodes belonging to this tier
    bandwidth_mbps: u64,      // approximate bandwidth
    latency_ns: u64,          // approximate latency
};

pub const MemTierDeviceType = enum(u8) {
    Dram = 0,
    Pmem = 1,          // NVDIMM/SCM persistent memory
    CxlMem = 2,        // CXL-attached memory
    Hbm = 3,           // High Bandwidth Memory
    RemoteDram = 4,    // remote NUMA DRAM
    Unknown = 255,
};

pub const DEFAULT_DRAM_ADIST: i32 = 260;
pub const DEFAULT_PMEM_ADIST: i32 = 500;
pub const DEFAULT_CXL_ADIST: i32 = 400;

// ============================================================================
// NUMA Balancing (AutoNUMA)
// ============================================================================

pub const NumaBalancingConfig = struct {
    enabled: bool,
    scan_delay_ms: u32,       // initial delay (default: 1000)
    scan_period_min_ms: u32,  // min scan rate (default: 1000)
    scan_period_max_ms: u32,  // max scan rate (default: 60000)
    scan_size_mb: u32,        // pages to scan per period (default: 256)
    // Hot/cold thresholds
    hot_threshold: u32,       // access frequency for promotion
    // Settle down
    settle_count: u32,        // don't migrate on first fault
    // Mode (Linux 6.5+)
    mode: NumaBalancingMode,
};

pub const NumaBalancingMode = packed struct(u32) {
    normal: bool = true,
    memory_tiering: bool = false,
    _pad: u30 = 0,
};

pub const NumaHintFault = struct {
    addr: u64,               // faulting address
    pid: u32,                // process
    nid_src: i32,            // where page currently is
    nid_dst: i32,            // where task is running
    nid_cpu: i32,            // CPU node
    // Decision
    migrated: bool,
    reason: MigrationReason,
};

pub const MigrationReason = enum(u8) {
    Migrated = 0,
    LocalNuma = 1,          // already local
    RemoteCpu = 2,          // CPU not on dst node
    GroupWeight = 3,        // group has more weight elsewhere
    Shared = 4,             // shared page, don't migrate
    NotMapped = 5,          // page not mapped anymore
    PteUpdate = 6,          // just updated PTE
};

// ============================================================================
// Page Demotion / Promotion
// ============================================================================

pub const DemotionPolicy = struct {
    // Nodes that can be demotion targets
    targets: [MAX_NUMNODES]i32,    // target nid for each source nid (-1 = none)
    enabled: bool,
    // Kswapd triggers
    watermark_level: WatermarkLevel,
    // Rate limiting
    max_pages_per_sec: u64,
    current_rate: u64,
};

pub const WatermarkLevel = enum(u8) {
    High = 0,
    Low = 1,
    Min = 2,
};

pub const PromotionPolicy = struct {
    targets: [MAX_NUMNODES]i32,   // target nid for each source nid
    enabled: bool,
    // Threshold
    hot_threshold: i32,
    // Rate limiting
    max_pages_per_sec: u64,
    current_rate: u64,
};

// ============================================================================
// Memory Hotplug Operations
// ============================================================================

pub const HotplugFlags = packed struct(u32) {
    allow_online: bool = false,
    allow_offline: bool = false,
    contains_kernel_data: bool = false,
    contains_boot_mem: bool = false,
    driver_managed: bool = false,  // CXL, etc.
    memmap_on_memory: bool = false,
    _pad: u26 = 0,
};

pub const OnlineResult = enum(u8) {
    Success = 0,
    AlreadyOnline = 1,
    BusyPages = 2,
    FailedMigrate = 3,
    NoZone = 4,
    Error = 255,
};

pub const OfflineResult = enum(u8) {
    Success = 0,
    AlreadyOffline = 1,
    BusyPages = 2,
    FailedMigrate = 3,
    KernelPages = 4,
    HugePages = 5,
    Timeout = 6,
    Error = 255,
};

pub const HotplugNotifier = struct {
    callback: u64,
    priority: i32,
    name: [32]u8,
};

// ============================================================================
// CXL Memory
// ============================================================================

pub const CxlMemRegion = struct {
    start_pfn: u64,
    end_pfn: u64,
    nid: i32,
    device_id: u32,
    // Performance
    read_latency_ns: u64,
    write_latency_ns: u64,
    read_bandwidth_mbps: u64,
    write_bandwidth_mbps: u64,
    // State
    online: bool,
    interleave_ways: u32,
    interleave_granularity: u32,
};

pub const CxlHmemType = enum(u8) {
    Volatile = 0,      // CXL.mem Type 2/3
    Persistent = 1,    // CXL PMEM
    Dynamic = 2,       // Dynamic Capacity Device (DCD)
};

// ============================================================================
// HMAT (Heterogeneous Memory Attribute Table)
// ============================================================================

pub const HmatEntry = struct {
    initiator_nid: i32,    // CPU / initiator proximity domain
    memory_nid: i32,       // memory proximity domain
    // Access characteristics
    read_lat_ns: u64,
    write_lat_ns: u64,
    read_bw_mbps: u64,
    write_bw_mbps: u64,
    // Memory side cache
    cache_size: u64,
    cache_associativity: u32,
    cache_write_policy: HmatCacheWPolicy,
    cache_line_size: u32,
};

pub const HmatCacheWPolicy = enum(u8) {
    Undefined = 0,
    WriteBack = 1,
    WriteThrough = 2,
};

// ============================================================================
// Memory Hotplug Statistics
// ============================================================================

pub const HotplugStats = struct {
    total_online_ops: u64,
    total_offline_ops: u64,
    online_failures: u64,
    offline_failures: u64,
    pages_onlined: u64,
    pages_offlined: u64,
    pages_migrated_for_offline: u64,
    migration_failures: u64,
    // Tiering
    promotions: u64,
    demotions: u64,
    promotion_failures: u64,
    demotion_failures: u64,
    // NUMA balancing
    numa_faults: u64,
    numa_migrations: u64,
    numa_migration_bytes: u64,
};

pub const MemHotplugManager = struct {
    nr_nodes_online: u32,
    nr_memory_blocks: u32,
    total_memory_bytes: u64,
    online_memory_bytes: u64,
    offline_memory_bytes: u64,
    stats: HotplugStats,
    numa_config: NumaBalancingConfig,
    demotion: DemotionPolicy,
    promotion: PromotionPolicy,
    initialized: bool,

    pub fn init() MemHotplugManager {
        return .{
            .nr_nodes_online = 0,
            .nr_memory_blocks = 0,
            .total_memory_bytes = 0,
            .online_memory_bytes = 0,
            .offline_memory_bytes = 0,
            .stats = std.mem.zeroes(HotplugStats),
            .numa_config = .{
                .enabled = true,
                .scan_delay_ms = 1000,
                .scan_period_min_ms = 1000,
                .scan_period_max_ms = 60000,
                .scan_size_mb = 256,
                .hot_threshold = 4,
                .settle_count = 4,
                .mode = .{ .normal = true },
            },
            .demotion = .{
                .targets = [_]i32{-1} ** MAX_NUMNODES,
                .enabled = false,
                .watermark_level = .Low,
                .max_pages_per_sec = 0,
                .current_rate = 0,
            },
            .promotion = .{
                .targets = [_]i32{-1} ** MAX_NUMNODES,
                .enabled = false,
                .hot_threshold = 4,
                .max_pages_per_sec = 0,
                .current_rate = 0,
            },
            .initialized = true,
        };
    }
};
