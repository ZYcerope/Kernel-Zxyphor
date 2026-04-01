// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Rust - vmalloc, percpu allocator, and memory policy
// vmalloc/vfree address space management, ioremap, percpu allocation,
// NUMA memory policies, memory tiering, CXL memory, demotion/promotion
// More advanced than Linux 2026 mm subsystem

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// ============================================================================
// vmalloc Address Space
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum VmallocFlags {
    None = 0,
    VM_ALLOC = 1 << 0,           // vmalloc()
    VM_MAP = 1 << 1,             // vmap()
    VM_IOREMAP = 1 << 2,         // ioremap()
    VM_USERMAP = 1 << 3,         // Map to userspace
    VM_DMA_COHERENT = 1 << 4,
    VM_UNINITIALIZED = 1 << 5,
    VM_NO_GUARD = 1 << 6,        // No guard page
    VM_KASAN = 1 << 7,           // KASAN shadow
    VM_FLUSH_RESET_PERMS = 1 << 8,
    VM_MAP_PUT_PAGES = 1 << 9,
    VM_ALLOW_HUGE_VMAP = 1 << 10,
    // Zxyphor
    VM_ZXY_ENCRYPTED = 1 << 20,
    VM_ZXY_FAST = 1 << 21,
}

pub struct VmallocArea {
    pub addr: u64,
    pub size: u64,           // Including guard page
    pub flags: u32,
    pub nr_pages: u64,
    pub phys_addr: u64,      // For ioremap
    // caller
    pub caller: u64,
    // NUMA
    pub node: i32,           // -1 for any
}

pub struct VmallocStats {
    pub nr_vmap_areas: u64,
    pub total_bytes: u64,
    pub largest_free_bytes: u64,
    // By type
    pub vmalloc_bytes: u64,
    pub vmap_bytes: u64,
    pub ioremap_bytes: u64,
    pub usermap_bytes: u64,
    // Pages
    pub total_pages: u64,
    pub huge_pages: u64,
    // Allocation stats
    pub alloc_count: u64,
    pub free_count: u64,
    pub alloc_failures: u64,
    pub purge_count: u64,
    pub lazy_free_pages: u64,
    // TLB
    pub tlb_flush_count: u64,
    pub tlb_flush_range_count: u64,
}

// ============================================================================
// ioremap Types
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IoremapType {
    Uncached = 0,        // UC
    WriteCombining = 1,  // WC
    WriteThrough = 2,    // WT
    WriteProtect = 3,    // WP
    WriteBack = 4,       // WB
    Encrypted = 5,       // SEV
    NpCache = 6,         // Non-posted combined
}

pub struct IoremapMapping {
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub size: u64,
    pub remap_type: IoremapType,
    pub resource_name: [64; u8],
    pub name_len: u8,
}

// ============================================================================
// Percpu Allocator
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PercpuAllocType {
    Static = 0,          // Compile-time percpu
    Dynamic = 1,         // alloc_percpu()
    Embedded = 2,        // Embedded in first chunk
}

pub struct PercpuChunk {
    pub base_addr: u64,
    pub nr_pages: u32,
    pub nr_populated: u32,
    pub nr_empty_pop_pages: u32,
    pub free_bytes: u32,
    pub contig_bytes: u32,       // Largest contiguous free
    pub map_used: u32,
    pub map_alloc: u32,
    // NUMA
    pub numa_node: i32,
    // Flags
    pub immutable: bool,
    pub needs_copy: bool,
    pub has_page: bool,
}

pub struct PercpuStats {
    pub nr_chunks: u32,
    pub nr_units: u32,
    pub unit_size: u32,          // Bytes per CPU unit
    pub atom_size: u32,          // Allocation atom
    pub nr_cpus: u32,
    // Memory usage
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub waste_bytes: u64,
    // Allocations
    pub alloc_count: u64,
    pub free_count: u64,
    pub alloc_failures: u64,
    // First chunk
    pub first_chunk_base: u64,
    pub first_chunk_size: u32,
    pub reserved_size: u32,
    pub dyn_size: u32,
    // Stats
    pub min_alloc_size: u32,
    pub max_alloc_size: u32,
    pub nr_allocs: [8; u64],     // By size class
}

// ============================================================================
// NUMA Memory Policy
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemPolicyMode {
    Default = 0,
    Preferred = 1,
    Bind = 2,
    Interleave = 3,
    Local = 4,
    PreferredMany = 5,
    Weighted = 6,            // Linux 6.x
    // Zxyphor
    ZxyAdaptive = 10,
    ZxyTiered = 11,
}

pub const MPOL_F_STATIC_NODES: u32 = 1 << 15;
pub const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
pub const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;

pub struct MemPolicy {
    pub mode: MemPolicyMode,
    pub flags: u32,
    pub nodemask: u64,          // Bitmask of allowed nodes
    // For interleave
    pub il_prev: u16,           // Previous interleave node
    pub il_next: u16,           // Next interleave node
    // For preferred/preferred_many
    pub preferred_nodes: u64,    // Bitmask
    // For weighted
    pub weights: [64; u8],       // Weight per node (0-255)
    // Reference count
    pub refcount: u32,
}

pub struct NumaBalanceConfig {
    pub enabled: bool,
    pub scan_delay_ms: u32,
    pub scan_period_min_ms: u32,
    pub scan_period_max_ms: u32,
    pub scan_size_mb: u32,
    // NUMA fault stats
    pub numa_faults_memory: u64,
    pub numa_faults_buffer: u64,
    pub numa_pages_migrated: u64,
    pub numa_pte_updates: u64,
    pub numa_hint_faults: u64,
    pub numa_hint_faults_local: u64,
    // Thresholds
    pub migrate_deferred: u64,
}

// ============================================================================
// Memory Tiering
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryTier {
    HBM = 0,            // Highest bandwidth (HBM)
    DRAM = 1,           // Standard DRAM
    CXL = 2,            // CXL-attached memory
    PMEM = 3,           // Persistent memory
    Remote = 4,          // Remote NUMA
    // Zxyphor
    ZxyAccelerator = 10,
}

pub struct MemoryTierConfig {
    pub tier: MemoryTier,
    pub adist_start: u32,        // Abstract distance start
    pub adist_end: u32,          // Abstract distance end
    pub nodes: u64,              // Node bitmask
    pub nr_nodes: u8,
    // Performance
    pub read_latency_ns: u32,
    pub write_latency_ns: u32,
    pub read_bandwidth_mbps: u32,
    pub write_bandwidth_mbps: u32,
    // Demotion
    pub demotion_target_tier: i8,  // -1 = no demotion
    pub promotion_source_tier: i8, // -1 = no promotion
}

pub struct DemotionConfig {
    pub enabled: bool,
    // Demotion targets per node
    pub targets: [64; i32],      // Target node for each node (-1 = no target)
    // Thresholds
    pub hot_threshold_ms: u32,   // Hot page detection threshold
    pub cold_threshold_ms: u32,  // Cold page detection threshold
    // Stats
    pub demoted_pages: u64,
    pub promoted_pages: u64,
    pub demotion_failures: u64,
    pub promotion_failures: u64,
    pub migration_latency_avg_us: u64,
}

// ============================================================================
// CXL Memory (Compute Express Link)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CxlMemType {
    Volatile = 0,        // CXL.mem Type 3 volatile
    Persistent = 1,      // CXL.mem Type 3 persistent
    Mixed = 2,
}

pub struct CxlMemRegion {
    pub id: u32,
    pub mem_type: CxlMemType,
    pub base_hpa: u64,          // Host Physical Address
    pub size: u64,
    // Performance
    pub read_latency_ns: u32,
    pub write_latency_ns: u32,
    pub read_bandwidth_mbps: u32,
    pub write_bandwidth_mbps: u32,
    // NUMA
    pub numa_node: i32,
    pub proximity_domain: u32,
    // Device
    pub cxl_port: u32,
    pub interleave_ways: u8,
    pub interleave_granularity: u32,
    // Features
    pub capable_volatile: bool,
    pub capable_persistent: bool,
    pub can_be_hot_added: bool,
    pub is_online: bool,
    // Stats
    pub pages_allocated: u64,
    pub pages_freed: u64,
    pub access_count: u64,
}

pub struct CxlTopology {
    pub nr_cxl_regions: u32,
    pub nr_cxl_ports: u32,
    pub nr_cxl_endpoints: u32,
    pub total_cxl_memory_mb: u64,
    pub total_cxl_volatile_mb: u64,
    pub total_cxl_persistent_mb: u64,
}

// ============================================================================
// DAX (Direct Access)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DaxMode {
    DevDax = 0,          // Character device (/dev/dax*)
    FsDax = 1,           // Filesystem DAX (ext4, xfs)
    SystemRam = 2,       // kmem - as system RAM
}

pub struct DaxDevice {
    pub id: u32,
    pub name: [32; u8],
    pub mode: DaxMode,
    pub size: u64,
    pub align: u64,
    pub numa_node: i32,
    // Target (for system-ram mode)
    pub target_node: i32,
    // Mapping
    pub nr_mappings: u32,
    pub mapped_bytes: u64,
    // Stats
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub fault_count: u64,
}

// ============================================================================
// Memory Hotplug
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MemoryBlockState {
    Offline = 0,
    GoingOffline = 1,
    Online = 2,
    GoingOnline = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MemoryOnlineType {
    Online = 0,
    OnlineKernel = 1,
    OnlineMovable = 2,
}

pub struct MemoryBlock {
    pub id: u32,
    pub phys_index: u64,
    pub state: MemoryBlockState,
    pub online_type: MemoryOnlineType,
    pub nr_pages: u64,
    pub numa_node: i32,
    pub removable: bool,
    // Zones
    pub zone_name: [16; u8],
    // Stats
    pub hotplug_count: u32,
}

pub struct MemoryHotplugStats {
    pub nr_online_blocks: u32,
    pub nr_offline_blocks: u32,
    pub total_hotplugged_bytes: u64,
    pub total_hotremoved_bytes: u64,
    pub online_events: u64,
    pub offline_events: u64,
    pub offline_failures: u64,
    pub probe_events: u64,
}

// ============================================================================
// DAMON (Data Access MONitor)
// ============================================================================

pub struct DamonRegion {
    pub start: u64,
    pub end: u64,
    pub nr_accesses: u32,        // Access frequency (per sample)
    pub age: u32,                // Age in aggregation intervals
}

pub struct DamonTarget {
    pub pid: i32,                // 0 for physical
    pub nr_regions: u32,
    pub regions: [4096; DamonRegion],
}

pub struct DamonSchemeAction {
    pub min_size_bytes: u64,
    pub max_size_bytes: u64,
    pub min_nr_accesses: u32,
    pub max_nr_accesses: u32,
    pub min_age: u32,
    pub max_age: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DamonAction {
    WillNeed = 0,
    Cold = 1,
    PageOut = 2,
    HugePages = 3,
    NoHugePages = 4,
    LruPrio = 5,
    LruDeprio = 6,
    Stat = 7,
    /// Zxyphor
    ZxyCompress = 10,
    ZxyMigrate = 11,
}

pub struct DamonScheme {
    pub action: DamonAction,
    pub access_pattern: DamonSchemeAction,
    pub quota_ms: u64,
    pub quota_bytes: u64,
    pub quota_reset_interval_ms: u64,
    pub watermarks_high: u64,
    pub watermarks_mid: u64,
    pub watermarks_low: u64,
    // Stats
    pub nr_tried: u64,
    pub sz_tried: u64,
    pub nr_applied: u64,
    pub sz_applied: u64,
    pub qt_exceeds: u64,
}

pub struct DamonContext {
    pub nr_targets: u32,
    pub nr_schemes: u32,
    pub sample_interval_us: u64,
    pub aggr_interval_us: u64,
    pub update_interval_us: u64,
    pub min_nr_regions: u32,
    pub max_nr_regions: u32,
    // Stats
    pub nr_aggregations: u64,
    pub nr_samples: u64,
}

// ============================================================================
// MM Subsystem Manager (Rust)
// ============================================================================

pub struct MmAdvancedSubsystem {
    // vmalloc
    pub vmalloc_stats: VmallocStats,
    // ioremap
    pub nr_ioremap_mappings: u32,
    pub total_ioremap_bytes: u64,
    // Percpu
    pub percpu_stats: PercpuStats,
    // NUMA policy
    pub default_policy: MemPolicyMode,
    pub numa_balance: NumaBalanceConfig,
    // Memory tiering
    pub nr_tiers: u8,
    pub demotion_config: DemotionConfig,
    // CXL
    pub cxl_topology: CxlTopology,
    // DAX
    pub nr_dax_devices: u32,
    pub total_dax_bytes: u64,
    // Hotplug
    pub hotplug_stats: MemoryHotplugStats,
    // DAMON
    pub damon_running: bool,
    pub nr_damon_contexts: u32,
    // ZSwap
    pub zswap_enabled: bool,
    pub zswap_pool_bytes: u64,
    pub zswap_stored_pages: u64,
    pub zswap_pool_limit_pct: u8,
    pub zswap_compressor: [16; u8],
    pub zswap_zpool: [16; u8],
    // KSM
    pub ksm_enabled: bool,
    pub ksm_pages_shared: u64,
    pub ksm_pages_sharing: u64,
    pub ksm_pages_unshared: u64,
    pub ksm_pages_volatile: u64,
    pub ksm_full_scans: u64,
    pub ksm_stable_node_dups: u64,
    // Zxyphor
    pub zxy_auto_tiering: bool,
    pub zxy_memory_compression: bool,
    pub zxy_adaptive_policy: bool,
    pub initialized: bool,
}
