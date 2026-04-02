// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust: ZRAM/ZSWAP/Memory Failure/HWPoison Subsystem
// Complete zram device, zswap frontend/backend, writeback,
// memory_failure/hwpoison, soft/hard offline

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// ZRAM Device
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZramCompAlgorithm {
    Lzo = 0,
    LzoRle = 1,
    Lz4 = 2,
    Lz4hc = 3,
    Zstd = 4,
    Deflate = 5,
    Lz4Fast = 6,
    Lz4hcMax = 7,
    ZstdMax = 8,
}

#[repr(C)]
pub struct ZramStats {
    pub compr_data_size: AtomicU64,
    pub num_reads: AtomicU64,
    pub num_writes: AtomicU64,
    pub failed_reads: AtomicU64,
    pub failed_writes: AtomicU64,
    pub invalid_io: AtomicU64,
    pub notify_free: AtomicU64,
    pub same_pages: AtomicU64,
    pub huge_pages: AtomicU64,
    pub huge_pages_since: AtomicU64,
    pub pages_stored: AtomicU64,
    pub miss_free: AtomicU64,
    pub bd_count: AtomicU64,
    pub bd_reads: AtomicU64,
    pub bd_writes: AtomicU64,
    pub writestall: AtomicU64,
}

impl ZramStats {
    pub const fn new() -> Self {
        Self {
            compr_data_size: AtomicU64::new(0),
            num_reads: AtomicU64::new(0),
            num_writes: AtomicU64::new(0),
            failed_reads: AtomicU64::new(0),
            failed_writes: AtomicU64::new(0),
            invalid_io: AtomicU64::new(0),
            notify_free: AtomicU64::new(0),
            same_pages: AtomicU64::new(0),
            huge_pages: AtomicU64::new(0),
            huge_pages_since: AtomicU64::new(0),
            pages_stored: AtomicU64::new(0),
            miss_free: AtomicU64::new(0),
            bd_count: AtomicU64::new(0),
            bd_reads: AtomicU64::new(0),
            bd_writes: AtomicU64::new(0),
            writestall: AtomicU64::new(0),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ZramPageFlags: u32 {
        const SAME   = 1 << 0;
        const WB     = 1 << 1;
        const UNDER_WB = 1 << 2;
        const HUGE   = 1 << 3;
        const IDLE   = 1 << 4;
        const INCOMPRESSIBLE = 1 << 5;
        const WRITEBACK_DONE = 1 << 6;
    }
}

#[repr(C)]
pub struct ZramTableEntry {
    pub handle: u64,
    pub flags: u32, // ZramPageFlags
    pub element: u64,
}

#[repr(C)]
pub struct ZramDevice {
    pub table: u64, // *mut ZramTableEntry
    pub comp: u64,  // compression context
    pub disk: u64,  // struct gendisk *
    pub disksize: u64,
    pub comp_alg: ZramCompAlgorithm,
    pub limit_pages: u64,
    pub max_comp_streams: u32,
    pub stats: ZramStats,
    pub claim: AtomicBool,
    pub wb_limit_enable: bool,
    pub wb_limit: u64,
    pub bd_wb_limit: u64,
    pub backing_dev: u64,
    pub bitmap: u64,
    pub nr_pages: u64,
    pub huge_class_size: u32,
}

// ============================================================================
// ZSWAP Frontend
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZswapPoolType {
    Zbud = 0,
    Zsmalloc = 1,
    Z3fold = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZswapCompressor {
    Lzo = 0,
    LzoRle = 1,
    Lz4 = 2,
    Lz4hc = 3,
    Zstd = 4,
    Deflate = 5,
}

#[repr(C)]
pub struct ZswapEntry {
    pub rb_node: [u64; 3], // struct rb_node
    pub refcount: AtomicU32,
    pub offset: u64,
    pub length: u32,
    pub pool: u64,     // *mut ZswapPool
    pub handle: u64,
    pub value: u64,
    pub objcg: u64,
    pub swpentry: u64,
}

#[repr(C)]
pub struct ZswapTree {
    pub rb_root: u64,           // struct rb_root
    pub lock: u64,              // spinlock_t
    pub nr_stored: AtomicU64,
}

#[repr(C)]
pub struct ZswapPool {
    pub pool_type: ZswapPoolType,
    pub compressor: ZswapCompressor,
    pub zpool: u64,
    pub tfm: u64,  // crypto_comp per-cpu
    pub nr_stored: AtomicU64,
    pub list_node: [u64; 2],   // struct list_head
    pub kref: u32,
    pub work: u64,
}

#[repr(C)]
pub struct ZswapConfig {
    pub enabled: bool,
    pub shrinker_enabled: bool,
    pub same_filled_pages_enabled: bool,
    pub non_same_filled_pages_enabled: bool,
    pub exclusive_loads: bool,
    pub compressor: ZswapCompressor,
    pub zpool_type: ZswapPoolType,
    pub max_pool_percent: u32,
    pub accept_threshold_percent: u32,
    pub writeback_enabled: bool,
}

#[repr(C)]
pub struct ZswapStats {
    pub pool_total_size: AtomicU64,
    pub stored_pages: AtomicU64,
    pub written_back_pages: AtomicU64,
    pub rejected_compress_poor: AtomicU64,
    pub rejected_alloc_fail: AtomicU64,
    pub rejected_reclaim_fail: AtomicU64,
    pub rejected_kmemcache_fail: AtomicU64,
    pub duplicate_entry: AtomicU64,
    pub same_filled_pages: AtomicU64,
    pub pool_limit_hit: AtomicU64,
}

impl ZswapStats {
    pub const fn new() -> Self {
        Self {
            pool_total_size: AtomicU64::new(0),
            stored_pages: AtomicU64::new(0),
            written_back_pages: AtomicU64::new(0),
            rejected_compress_poor: AtomicU64::new(0),
            rejected_alloc_fail: AtomicU64::new(0),
            rejected_reclaim_fail: AtomicU64::new(0),
            rejected_kmemcache_fail: AtomicU64::new(0),
            duplicate_entry: AtomicU64::new(0),
            same_filled_pages: AtomicU64::new(0),
            pool_limit_hit: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Zsmalloc (zs_pool)
// ============================================================================

#[repr(C)]
pub struct ZsPoolStats {
    pub pages_compacted: AtomicU64,
    pub obj_allocated: AtomicU64,
    pub obj_used: AtomicU64,
    pub obj_stored: AtomicU64,
}

pub const ZS_MAX_PAGES_PER_ZSPAGE: usize = 4;
pub const ZS_SIZE_CLASSES: usize = 255;

#[repr(C)]
pub struct ZsPool {
    pub name: [u8; 64],
    pub size_class: [u64; ZS_SIZE_CLASSES], // *mut SizeClass
    pub stats: ZsPoolStats,
    pub shrinker: u64,
    pub destroying: bool,
    pub pages_allocated: AtomicU64,
    pub compaction_in_progress: AtomicBool,
}

#[repr(C)]
pub struct ZsSizeClass {
    pub index: u32,
    pub size: u32,             // Object size
    pub objs_per_zspage: u32,
    pub pages_per_zspage: u32,
    pub fullness_list: [u64; 4], // ZS_EMPTY..ZS_FULL
    pub stats: ZsSizeClassStats,
}

#[repr(C)]
pub struct ZsSizeClassStats {
    pub class_almost_full: u64,
    pub class_almost_empty: u64,
}

// ============================================================================
// Memory Failure / HWPoison
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryFailureAction {
    SoftOffline = 0,
    HardOffline = 1,
    Unpoison = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HwpoisonResult {
    Ignored = 0,        // Page not affected
    Delayed = 1,        // Deferred handling
    Recovered = 2,      // Successfully recovered
    Failed = 3,         // Recovery failed
    BuddyPage = 4,     // Page was free (buddy)
    HugePageFailed = 5, // THP split + recovery failed
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MfActionPage {
    Msg = 0,
    Delayed = 1,
    Failure = 2,
    Recovered = 3,
    AlreadyPoisoned = 4,
    BoundaryCrossed = 5,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct MfFlags: u32 {
        const COUNT_INCREASED = 1 << 0;
        const ACTION_REQUIRED = 1 << 1;
        const MUST_KILL = 1 << 2;
        const SOFT_OFFLINE = 1 << 3;
        const UNPOISON = 1 << 4;
        const SW_SIMULATED = 1 << 5;
        const NO_RETRY = 1 << 6;
        const MEM_PRE_REMOVE = 1 << 7;
    }
}

#[repr(C)]
pub struct HwpoisonPageAction {
    pub result: HwpoisonResult,
    pub page_type: &'static str,
    pub action: fn(u64, u64) -> HwpoisonResult,
}

#[repr(C)]
pub struct RawErrorInfo {
    pub pfn: u64,
    pub flags: MfFlags,
    pub error_type: u8,     // MCE SRAO, SRAR, UCNA
    pub severity: u8,
    pub bank: u8,
    pub status: u64,        // MCi_STATUS
    pub addr: u64,          // MCi_ADDR
    pub misc: u64,          // MCi_MISC
    pub count: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
pub struct MemoryFailureStats {
    pub total_events: AtomicU64,
    pub soft_offline_success: AtomicU64,
    pub soft_offline_fail: AtomicU64,
    pub hard_offline_success: AtomicU64,
    pub hard_offline_fail: AtomicU64,
    pub unpoison_success: AtomicU64,
    pub unpoison_fail: AtomicU64,
    pub pages_dissolved: AtomicU64,
    pub thp_split: AtomicU64,
    pub processes_killed: AtomicU64,
    pub processes_signaled: AtomicU64,
    pub buddy_page_recovered: AtomicU64,
}

impl MemoryFailureStats {
    pub const fn new() -> Self {
        Self {
            total_events: AtomicU64::new(0),
            soft_offline_success: AtomicU64::new(0),
            soft_offline_fail: AtomicU64::new(0),
            hard_offline_success: AtomicU64::new(0),
            hard_offline_fail: AtomicU64::new(0),
            unpoison_success: AtomicU64::new(0),
            unpoison_fail: AtomicU64::new(0),
            pages_dissolved: AtomicU64::new(0),
            thp_split: AtomicU64::new(0),
            processes_killed: AtomicU64::new(0),
            processes_signaled: AtomicU64::new(0),
            buddy_page_recovered: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Memory Error Recovery (ACPI EINJ / GHES)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GhesErrorSeverity {
    Recoverable = 0,
    Fatal = 1,
    Corrected = 2,
    None = 3,
}

#[repr(C)]
pub struct GhesRecord {
    pub severity: GhesErrorSeverity,
    pub section_count: u32,
    pub error_severity: u32,
    pub validation_bits: u32,
    pub record_length: u32,
    pub timestamp: u64,
    pub platform_id: [u8; 16],
    pub partition_id: [u8; 16],
    pub creator_id: [u8; 16],
    pub notification_type: [u8; 16],
    pub record_id: u64,
    pub flags: u32,
    pub persistence_info: u64,
}

#[repr(C)]
pub struct MemoryErrorSection {
    pub validation_bits: u64,
    pub error_status: u64,
    pub physical_address: u64,
    pub physical_address_mask: u64,
    pub node: u16,
    pub card: u16,
    pub module: u16,
    pub bank: u16,
    pub device: u16,
    pub row: u16,
    pub column: u16,
    pub bit_position: u16,
    pub requestor_id: u64,
    pub responder_id: u64,
    pub target_id: u64,
    pub error_type: u8,
    pub rank: u16,
    pub mem_array_handle: u16,
    pub mem_device_handle: u16,
}

// ============================================================================
// Combined Manager
// ============================================================================

#[repr(C)]
pub struct ZramZswapHwpoisonManager {
    pub zram_devices: [u64; 8],       // Pointers to ZramDevice
    pub num_zram_devices: u32,
    pub zswap_config: ZswapConfig,
    pub zswap_stats: ZswapStats,
    pub hwpoison_stats: MemoryFailureStats,
    pub total_compressed_bytes: AtomicU64,
    pub total_original_bytes: AtomicU64,
    pub compression_ratio_pct: AtomicU32,
    pub initialized: AtomicBool,
}

impl ZramZswapHwpoisonManager {
    pub const fn new() -> Self {
        Self {
            zram_devices: [0u64; 8],
            num_zram_devices: 0,
            zswap_config: ZswapConfig {
                enabled: true,
                shrinker_enabled: true,
                same_filled_pages_enabled: true,
                non_same_filled_pages_enabled: true,
                exclusive_loads: true,
                compressor: ZswapCompressor::LzoRle,
                zpool_type: ZswapPoolType::Zsmalloc,
                max_pool_percent: 20,
                accept_threshold_percent: 90,
                writeback_enabled: true,
            },
            zswap_stats: ZswapStats::new(),
            hwpoison_stats: MemoryFailureStats::new(),
            total_compressed_bytes: AtomicU64::new(0),
            total_original_bytes: AtomicU64::new(0),
            compression_ratio_pct: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
        }
    }
}
