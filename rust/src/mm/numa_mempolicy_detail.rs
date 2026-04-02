// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel (Rust) - Memory Policy & NUMA Optimization Detail
// Complete: mempolicy types, NUMA node distance, zone reclaim,
// weighted interleave, preferred many, VMA policy, process migration,
// automatic NUMA balancing, NUMA statistics, memory tiering policies

// ============================================================================
// NUMA Constants
// ============================================================================

pub const MAX_NUMNODES: usize = 1024;
pub const MAX_NUMANODE_DISTANCE: u8 = 255;
pub const LOCAL_DISTANCE: u8 = 10;
pub const REMOTE_DISTANCE: u8 = 20;
pub const RECLAIM_DISTANCE: u8 = 30;
pub const NUMA_NO_NODE: i32 = -1;
pub const MAX_ZONES_PER_NODE: usize = 6;

// ============================================================================
// Memory Policy
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpolicyMode {
    Default = 0,          // MPOL_DEFAULT: Allocate on local node
    Preferred = 1,        // MPOL_PREFERRED: Prefer specific node
    Bind = 2,             // MPOL_BIND: Allocate only from set
    Interleave = 3,       // MPOL_INTERLEAVE: Round-robin across set
    Local = 4,            // MPOL_LOCAL: Like Default but explicit
    PreferredMany = 5,    // MPOL_PREFERRED_MANY: Prefer from many
    WeightedInterleave = 6, // MPOL_WEIGHTED_INTERLEAVE
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MpolicyFlags {
    pub static_nodes: bool,     // MPOL_F_STATIC_NODES
    pub relative_nodes: bool,   // MPOL_F_RELATIVE_NODES
    pub numa_balancing: bool,   // MPOL_F_NUMA_BALANCING
}

#[derive(Debug, Clone, Copy)]
pub struct MbindFlags {
    pub strict: bool,      // MPOL_MF_STRICT: Move pages if possible
    pub move_pages: bool,  // MPOL_MF_MOVE: Move individual pages
    pub move_all: bool,    // MPOL_MF_MOVE_ALL: Move all pages regardless
    pub lazy: bool,        // MPOL_MF_LAZY: Don't move, fault on access
}

#[derive(Debug, Clone)]
pub struct Mempolicy {
    pub mode: MpolicyMode,
    pub flags: MpolicyFlags,
    pub refcount: u32,
    pub nodemask: NodeMask,
    pub preferred_node: i32,       // For MPOL_PREFERRED
    pub il_prev: u32,              // Interleave: previous node
    pub il_next: u32,              // Interleave: next node
    pub w_il_weights: [u8; MAX_NUMNODES],  // Weighted interleave
    pub home_node: i32,            // For preferred-many
}

#[derive(Debug, Clone)]
pub struct NodeMask {
    pub bits: [u64; MAX_NUMNODES / 64],
}

impl NodeMask {
    pub fn new() -> Self {
        Self {
            bits: [0u64; MAX_NUMNODES / 64],
        }
    }

    pub fn set(&mut self, node: usize) {
        if node < MAX_NUMNODES {
            self.bits[node / 64] |= 1 << (node % 64);
        }
    }

    pub fn clear(&mut self, node: usize) {
        if node < MAX_NUMNODES {
            self.bits[node / 64] &= !(1 << (node % 64));
        }
    }

    pub fn test(&self, node: usize) -> bool {
        if node < MAX_NUMNODES {
            (self.bits[node / 64] & (1 << (node % 64))) != 0
        } else {
            false
        }
    }

    pub fn empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    pub fn weight(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }
}

// ============================================================================
// NUMA Distance Matrix
// ============================================================================

#[derive(Debug)]
pub struct NumaDistanceMap {
    pub nr_nodes: u32,
    pub distance: [[u8; MAX_NUMNODES]; MAX_NUMNODES],
}

impl NumaDistanceMap {
    pub fn set_distance(&mut self, src: usize, dst: usize, dist: u8) {
        if src < MAX_NUMNODES && dst < MAX_NUMNODES {
            self.distance[src][dst] = dist;
        }
    }

    pub fn get_distance(&self, src: usize, dst: usize) -> u8 {
        if src < MAX_NUMNODES && dst < MAX_NUMNODES {
            self.distance[src][dst]
        } else {
            MAX_NUMANODE_DISTANCE
        }
    }
}

// ============================================================================
// NUMA Node Description
// ============================================================================

#[derive(Debug, Clone)]
pub struct NumaNodeInfo {
    pub node_id: i32,
    pub online: bool,
    pub has_memory: bool,
    pub has_cpu: bool,
    pub total_pages: u64,
    pub free_pages: u64,
    pub active_pages: u64,
    pub inactive_pages: u64,
    pub slab_pages: u64,
    pub zone_info: [NumaZoneInfo; MAX_ZONES_PER_NODE],
    pub nr_zones: u32,
    pub cpumask: CpuMask,
    pub pglist_data: PgListData,
}

#[derive(Debug, Clone, Default)]
pub struct NumaZoneInfo {
    pub zone_type: u8,
    pub zone_start_pfn: u64,
    pub spanned_pages: u64,
    pub present_pages: u64,
    pub managed_pages: u64,
    pub free_pages: u64,
    pub high: u64,
    pub low: u64,
    pub min: u64,
    pub boost: u64,
}

#[derive(Debug, Clone)]
pub struct CpuMask {
    pub bits: [u64; 16],   // Support up to 1024 CPUs
}

impl Default for CpuMask {
    fn default() -> Self {
        Self { bits: [0u64; 16] }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PgListData {
    pub node_id: i32,
    pub node_present_pages: u64,
    pub node_spanned_pages: u64,
    pub node_start_pfn: u64,
    pub kswapd_failures: u32,
    pub kswapd_wait: bool,
    pub kswapd_order: i32,
    pub kswapd_highest_zoneidx: i32,
    pub kcompactd_max_order: i32,
    pub kcompactd_highest_zoneidx: i32,
    pub totalreserve_pages: u64,
}

// ============================================================================
// NUMA Balancing
// ============================================================================

#[derive(Debug, Clone)]
pub struct NumaBalancingConfig {
    pub enabled: bool,
    pub scan_delay_ms: u32,              // Initial scan delay
    pub scan_period_min_ms: u32,         // Minimum scan period
    pub scan_period_max_ms: u32,         // Maximum scan period
    pub scan_size_mb: u32,               // Memory to scan per period
    pub hot_threshold_ms: u32,           // Threshold for hot page
    pub promote_rate_limit: u32,
    pub tiered_enabled: bool,
    pub memory_tiering_mode: MemoryTieringMode,
}

impl Default for NumaBalancingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_delay_ms: 1000,
            scan_period_min_ms: 1000,
            scan_period_max_ms: 60000,
            scan_size_mb: 256,
            hot_threshold_ms: 1000,
            promote_rate_limit: 65536,
            tiered_enabled: false,
            memory_tiering_mode: MemoryTieringMode::None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default)]
pub enum MemoryTieringMode {
    #[default]
    None = 0,
    Static = 1,
    Dynamic = 2,
}

#[derive(Debug, Clone, Default)]
pub struct NumaBalancingStats {
    pub numa_hit: u64,
    pub numa_miss: u64,
    pub numa_foreign: u64,
    pub interleave_hit: u64,
    pub local_node: u64,
    pub other_node: u64,
    pub pages_migrated: u64,
    pub migrate_success: u64,
    pub migrate_fail: u64,
    pub pte_updates: u64,
    pub huge_pte_updates: u64,
    pub hint_faults: u64,
    pub hint_faults_local: u64,
    pub task_numa_preferred_nid: i32,
    pub task_numa_group_id: u64,
}

// ============================================================================
// NUMA Task Placement
// ============================================================================

#[derive(Debug, Clone)]
pub struct TaskNumaInfo {
    pub preferred_nid: i32,
    pub migrate_seq: u32,
    pub scan_seq: u32,
    pub scan_period: u32,
    pub scan_offset: u32,
    pub total_faults: u64,
    pub current_faults: u64,
    pub faults_memory: Vec<u64>,     // Per-node memory faults
    pub faults_cpu: Vec<u64>,        // Per-node CPU faults
    pub faults_buffer_memory: Vec<u64>,
    pub faults_buffer_cpu: Vec<u64>,
    pub group: Option<Box<NumaGroup>>,
    pub last_task_numa_placement: u64,
    pub last_sum_exec_runtime: u64,
}

#[derive(Debug, Clone)]
pub struct NumaGroup {
    pub gid: u64,
    pub refcount: u32,
    pub nr_tasks: u32,
    pub max_faults_cpu: u64,
    pub faults: Vec<u64>,
    pub faults_cpu: Vec<u64>,
    pub total_faults: u64,
    pub active_nodes: u32,
}

// ============================================================================
// Page Migration
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MigrateMode {
    Async = 0,
    Sync = 1,
    SyncNoCompact = 2,
    SyncLight = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MigrateReason {
    Compaction = 0,
    MemoryFailure = 1,
    MemoryHotplug = 2,
    Syscall = 3,
    Mempolicy = 4,
    NumaMisplaced = 5,
    Longterm = 6,
    Demote = 7,
    Contig = 8,
}

#[derive(Debug, Clone, Default)]
pub struct MigrationStats {
    pub nr_migrate_pages: u64,
    pub nr_migrate_success: u64,
    pub nr_migrate_failed: u64,
    pub nr_migrate_thp: u64,
    pub nr_migrate_thp_success: u64,
    pub nr_demote_pages: u64,
    pub nr_promote_pages: u64,
    pub last_migration_time: u64,
}

// ============================================================================
// Zone Reclaim
// ============================================================================

#[derive(Debug, Clone)]
pub struct ZoneReclaimConfig {
    pub enabled: bool,
    pub mode: ZoneReclaimMode,
    pub min_unmapped_ratio: u32,     // Percentage
    pub min_slab_ratio: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ZoneReclaimMode {
    pub reclaim_zone: bool,
    pub reclaim_write: bool,
    pub reclaim_unmap: bool,
}

impl Default for ZoneReclaimMode {
    fn default() -> Self {
        Self {
            reclaim_zone: false,
            reclaim_write: false,
            reclaim_unmap: false,
        }
    }
}

// ============================================================================
// Memory Tiering
// ============================================================================

#[derive(Debug, Clone)]
pub struct MemoryTier {
    pub id: u32,
    pub adistance_start: u32,    // Abstract distance start
    pub adistance_end: u32,
    pub nodes: NodeMask,
    pub next_tier: Option<Box<MemoryTier>>,
    pub prev_tier: Option<Box<MemoryTier>>,
}

#[derive(Debug, Clone)]
pub struct DemoteTarget {
    pub src_node: i32,
    pub dst_node: i32,
    pub enabled: bool,
    pub max_rate_pages_sec: u64,
    pub current_rate: u64,
}

#[derive(Debug, Clone)]
pub struct PromoteTarget {
    pub src_node: i32,
    pub dst_node: i32,
    pub enabled: bool,
    pub hot_threshold: u64,
    pub max_rate_pages_sec: u64,
    pub current_rate: u64,
}

// ============================================================================
// Move Pages syscall
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MovePageFlags {
    MPOL_MF_STRICT = 1 << 0,
    MPOL_MF_MOVE = 1 << 1,
    MPOL_MF_MOVE_ALL = 1 << 2,
}

#[derive(Debug, Clone)]
pub struct MovePagesRequest {
    pub pid: i32,
    pub count: u64,
    pub pages: Vec<u64>,     // Virtual addresses
    pub nodes: Vec<i32>,     // Target nodes (or -1 for query)
    pub status: Vec<i32>,    // Return status per page
    pub flags: u32,
}

// ============================================================================  
// NUMA sysctl/procfs
// ============================================================================

#[derive(Debug, Clone)]
pub struct NumaSysctl {
    pub numa_balancing: bool,
    pub numa_balancing_scan_delay_ms: u32,
    pub numa_balancing_scan_period_min_ms: u32,
    pub numa_balancing_scan_period_max_ms: u32,
    pub numa_balancing_scan_size_mb: u32,
    pub numa_balancing_promote_rate_limit_MBps: u32,
    pub zone_reclaim_mode: u32,
    pub min_unmapped_ratio: u32,
    pub min_slab_ratio: u32,
    pub numa_stat: bool,
    pub watermark_boost_factor: u32,
    pub watermark_scale_factor: u32,
}

impl Default for NumaSysctl {
    fn default() -> Self {
        Self {
            numa_balancing: true,
            numa_balancing_scan_delay_ms: 1000,
            numa_balancing_scan_period_min_ms: 1000,
            numa_balancing_scan_period_max_ms: 60000,
            numa_balancing_scan_size_mb: 256,
            numa_balancing_promote_rate_limit_MBps: 65536,
            zone_reclaim_mode: 0,
            min_unmapped_ratio: 1,
            min_slab_ratio: 5,
            numa_stat: true,
            watermark_boost_factor: 15000,
            watermark_scale_factor: 10,
        }
    }
}

// ============================================================================
// NUMA Statistics Counters
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct NumaVmstat {
    pub numa_hit: u64,
    pub numa_miss: u64,
    pub numa_foreign: u64,
    pub numa_interleave: u64,
    pub numa_local: u64,
    pub numa_other: u64,
    pub numa_pte_updates: u64,
    pub numa_huge_pte_updates: u64,
    pub numa_hint_faults: u64,
    pub numa_hint_faults_local: u64,
    pub numa_pages_migrated: u64,
    pub pgmigrate_success: u64,
    pub pgmigrate_fail: u64,
    pub thp_migration_success: u64,
    pub thp_migration_fail: u64,
    pub pgdemote_kswapd: u64,
    pub pgdemote_direct: u64,
    pub pgdemote_khugepaged: u64,
    pub pgpromote_success: u64,
}

// ============================================================================
// Manager
// ============================================================================

#[derive(Debug, Default)]
pub struct NumaMempolicyManager {
    pub nr_online_nodes: u32,
    pub nr_possible_nodes: u32,
    pub has_memory_tiering: bool,
    pub balancing_config: NumaBalancingConfig,
    pub vmstat: NumaVmstat,
    pub migration_stats: MigrationStats,
    pub sysctl: NumaSysctl,
    pub initialized: bool,
}

impl NumaMempolicyManager {
    pub fn new() -> Self {
        Self {
            initialized: true,
            balancing_config: NumaBalancingConfig::default(),
            sysctl: NumaSysctl::default(),
            ..Default::default()
        }
    }
}
