// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust Memory Reclaim / Shrinker / Writeback Detail
//! Page reclaim internals, shrinker framework, direct reclaim, kswapd hooks,
//! writeback control, dirty throttle, memcg reclaim, folio reclaim

#![allow(dead_code)]

use core::sync::atomic::AtomicU64;

// ============================================================================
// Reclaim / Scan Control
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimMode {
    KswapdReclaim = 0,
    DirectReclaim = 1,
    MemcgReclaim = 2,
    KhugepagdReclaim = 3,
    ProactiveReclaim = 4,
}

#[repr(C)]
#[derive(Debug)]
pub struct ScanControl {
    pub nr_to_reclaim: u64,
    pub nr_reclaimed: u64,
    pub nr_scanned: u64,
    // Priority (0 = highest, 12 = lowest)
    pub priority: i32,
    pub may_writepage: bool,
    pub may_unmap: bool,
    pub may_swap: bool,
    pub may_deactivate: u32,
    pub may_thrash: bool,
    // Compaction readiness
    pub compaction_ready: bool,
    // Target
    pub target_mem_cgroup: u64,    // mem_cgroup *
    pub gfp_mask: u32,
    // NUMA
    pub reclaim_idx: i32,          // highest zone idx to reclaim from
    pub order: i32,                // allocation order
    // Mode
    pub mode: ReclaimMode,
    // No demotion
    pub no_demotion: bool,
    // File vs anon
    pub file_is_tiny: bool,
    pub swappiness: u32,           // 0-200 (default:60)
}

// ============================================================================
// LRU Lists
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LruList {
    InactiveAnon = 0,
    ActiveAnon = 1,
    InactiveFile = 2,
    ActiveFile = 3,
    Unevictable = 4,
}

impl LruList {
    pub const NR_LISTS: usize = 5;

    pub fn is_file(&self) -> bool {
        matches!(self, LruList::InactiveFile | LruList::ActiveFile)
    }

    pub fn is_active(&self) -> bool {
        matches!(self, LruList::ActiveAnon | LruList::ActiveFile)
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct LruVecState {
    pub nr_pages: [u64; LruList::NR_LISTS],
    pub anon_cost: u64,
    pub file_cost: u64,
    pub nonresident_age: u64,
    pub refaults: [u64; 2],  // anon, file
    pub flags: u64,
}

// ============================================================================
// MGLRU (Multi-Gen LRU)
// ============================================================================

pub const MAX_NR_GENS: usize = 4;
pub const MAX_NR_TIERS: usize = 4;

#[repr(C)]
#[derive(Debug, Default)]
pub struct LruGenFolio {
    pub max_seq: u64,
    pub min_seq: [u64; 2],       // anon, file
    pub timestamps: [u64; MAX_NR_GENS],
    pub folios: [[u64; MAX_NR_GENS]; 2],  // [type][gen] list_head
    pub nr_pages: [[u64; MAX_NR_GENS]; 2],
    pub avg_refaulted: [[u64; MAX_NR_GENS]; 2],
    pub avg_total: [[u64; MAX_NR_GENS]; 2],
    pub protected: [[u64; MAX_NR_TIERS]; 2],
    pub evicted: [[u64; MAX_NR_TIERS]; 2],
    pub enabled: bool,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct LruGenMmState {
    pub seq: u64,
    pub head: u64,
    pub tail: u64,
    pub nr_walkers: u32,
    pub filters: [u64; 2],       // bloom filters
}

#[repr(C)]
#[derive(Debug)]
pub struct MglruConfig {
    pub enabled: bool,
    pub min_ttl_ms: u64,
    pub can_swap: bool,
    pub aging_interval_ms: u64,
    pub eviction_min_seq_diff: u32,
}

impl Default for MglruConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_ttl_ms: 1000,
            can_swap: true,
            aging_interval_ms: 10000,
            eviction_min_seq_diff: 2,
        }
    }
}

// ============================================================================
// Shrinker Framework
// ============================================================================

#[repr(C)]
pub struct Shrinker {
    pub count_objects: u64,       // fn(*Shrinker, *ShrinkControl) -> u64
    pub scan_objects: u64,        // fn(*Shrinker, *ShrinkControl) -> u64
    pub batch: u64,               // min scan batch size
    pub seeks: i32,               // SEEK cost, DEFAULT_SEEKS = 2
    pub flags: ShrinkerFlags,
    pub nr_deferred: u64,         // per-node deferred work
    pub name: [32]u8,
    // Registration
    pub registered: bool,
    pub debugfs_id: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ShrinkerFlags {
    bits: u32,
}

impl ShrinkerFlags {
    pub const NUMA_AWARE: u32 = 1 << 0;
    pub const MEMCG_AWARE: u32 = 1 << 1;
    pub const NONSLAB: u32 = 1 << 2;
}

#[repr(C)]
#[derive(Debug)]
pub struct ShrinkControl {
    pub gfp_mask: u32,
    pub nid: i32,               // NUMA node to shrink
    pub nr_to_scan: u64,
    pub nr_scanned: u64,
    pub memcg: u64,             // mem_cgroup *
}

pub const DEFAULT_SEEKS: i32 = 2;
pub const SHRINK_EMPTY: u64 = u64::MAX;
pub const SHRINK_STOP: u64 = u64::MAX - 1;

// ============================================================================
// Well-known Shrinkers
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KnownShrinker {
    DentryShrink = 0,
    InodeShrink = 1,
    SlabShrink = 2,
    SuperBlockShrink = 3,
    VfsCacheShrink = 4,
    WorkingSetShrink = 5,
    ZsPoolShrink = 6,
    ZramShrink = 7,
    KsmShrink = 8,
    DrmTtmShrink = 9,
    Ext4EsShrink = 10,
    XfsInodeShrink = 11,
    BtrfsFreeSpaceShrink = 12,
    NfsDirCacheShrink = 13,
}

// ============================================================================
// Writeback Control
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbSyncMode {
    None = 0,       // WB_SYNC_NONE - writeback for sync
    All = 1,        // WB_SYNC_ALL - writeback everything
}

#[repr(C)]
#[derive(Debug)]
pub struct WritbackControl {
    pub nr_to_write: i64,
    pub pages_skipped: i64,
    pub range_start: u64,
    pub range_end: u64,
    pub sync_mode: WbSyncMode,
    // Flags
    pub for_kupdate: bool,
    pub for_background: bool,
    pub tagged_writepages: bool,
    pub for_reclaim: bool,
    pub range_cyclic: bool,
    pub for_sync: bool,
    pub unpinned_netfs_wb: bool,
    // Stats
    pub nr_written: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct BdiWriteback {
    pub bdi: u64,               // backing_dev_info *
    pub memcg_css: u64,         // cgroup_subsys_state *
    // Work items
    pub dwork: u64,             // delayed_work
    pub last_active: u64,
    // Dirty state
    pub dirty_ratelimit: u64,
    pub balanced_dirty_ratelimit: u64,
    pub written_stamp: u64,
    pub bw_time_stamp: u64,
    pub dirtied_stamp: u64,
    pub avg_write_bandwidth: u64,
    pub dirty_sleep: u64,
    // Lists
    pub b_dirty: u64,          // dirty inodes
    pub b_io: u64,             // parked for writeback
    pub b_more_io: u64,        // parked for more writeback
    pub b_dirty_time: u64,     // dirty time inodes
    // Stats
    pub stat: [WbStat; 4],
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum WbStatItem {
    Reclaimable = 0,
    DirtyThresh = 1,
    Writeback = 2,
    Written = 3,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct WbStat {
    pub count: u64,
}

// ============================================================================
// Dirty Throttling
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct DirtyThrottleControl {
    pub wb: u64,                // bdi_writeback *
    pub gdtc: u64,             // global dirty throttle control
    pub mdtc: u64,             // memory cgroup dirty throttle control
    // Thresholds
    pub dirty: u64,
    pub thresh: u64,
    pub bg_thresh: u64,
    pub wb_dirty: u64,
    pub wb_thresh: u64,
    pub wb_bg_thresh: u64,
    // Dirty position
    pub pos_ratio: u64,        // fixed-point
    pub wb_pos_ratio: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct DirtyThrottleGlobalConfig {
    pub dirty_ratio: u32,          // vm.dirty_ratio (default:20)
    pub dirty_background_ratio: u32, // vm.dirty_background_ratio (default:10)
    pub dirty_bytes: u64,          // vm.dirty_bytes (0 = use ratio)
    pub dirty_background_bytes: u64,
    pub dirty_expire_centisecs: u32, // default: 3000 = 30s
    pub dirty_writeback_centisecs: u32, // default: 500 = 5s
}

impl Default for DirtyThrottleGlobalConfig {
    fn default() -> Self {
        Self {
            dirty_ratio: 20,
            dirty_background_ratio: 10,
            dirty_bytes: 0,
            dirty_background_bytes: 0,
            dirty_expire_centisecs: 3000,
            dirty_writeback_centisecs: 500,
        }
    }
}

// ============================================================================
// Folio Reclaim
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct FolioReclaimState {
    pub total_folios_scanned: u64,
    pub total_folios_reclaimed: u64,
    pub total_folios_activated: u64,
    pub total_folios_deactivated: u64,
    pub total_folios_lazyfreed: u64,
    pub total_folios_referenced: u64,
    pub total_folios_writeback: u64,
    pub total_folios_dirty: u64,
    pub total_folios_mapped: u64,
    pub total_folios_faulted: u64,
    pub total_thp_scanned: u64,
    pub total_thp_split: u64,
    pub total_anon_reclaimed: u64,
    pub total_file_reclaimed: u64,
}

// ============================================================================
// Reclaim Manager
// ============================================================================

#[derive(Debug)]
pub struct ReclaimManager {
    pub mglru_config: MglruConfig,
    pub dirty_config: DirtyThrottleGlobalConfig,
    pub folio_state: FolioReclaimState,
    pub total_direct_reclaim: AtomicU64,
    pub total_kswapd_reclaim: AtomicU64,
    pub total_shrinker_runs: AtomicU64,
    pub total_shrinker_objects_freed: AtomicU64,
    pub total_writeback_pages: AtomicU64,
    pub nr_registered_shrinkers: u32,
    pub initialized: bool,
}

impl ReclaimManager {
    pub fn new() -> Self {
        Self {
            mglru_config: MglruConfig::default(),
            dirty_config: DirtyThrottleGlobalConfig::default(),
            folio_state: FolioReclaimState {
                total_folios_scanned: 0,
                total_folios_reclaimed: 0,
                total_folios_activated: 0,
                total_folios_deactivated: 0,
                total_folios_lazyfreed: 0,
                total_folios_referenced: 0,
                total_folios_writeback: 0,
                total_folios_dirty: 0,
                total_folios_mapped: 0,
                total_folios_faulted: 0,
                total_thp_scanned: 0,
                total_thp_split: 0,
                total_anon_reclaimed: 0,
                total_file_reclaimed: 0,
            },
            total_direct_reclaim: AtomicU64::new(0),
            total_kswapd_reclaim: AtomicU64::new(0),
            total_shrinker_runs: AtomicU64::new(0),
            total_shrinker_objects_freed: AtomicU64::new(0),
            total_writeback_pages: AtomicU64::new(0),
            nr_registered_shrinkers: 0,
            initialized: true,
        }
    }
}
