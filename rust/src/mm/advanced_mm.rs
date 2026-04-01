// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Memory Manager (Rust)
// SLUB allocator, CMA, hugetlb, page compaction, memory hotplug, zram/zswap

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// Page Flags (Linux-compatible)
// ============================================================================

pub const PG_LOCKED: u64 = 1 << 0;
pub const PG_REFERENCED: u64 = 1 << 1;
pub const PG_UPTODATE: u64 = 1 << 2;
pub const PG_DIRTY: u64 = 1 << 3;
pub const PG_LRU: u64 = 1 << 4;
pub const PG_ACTIVE: u64 = 1 << 5;
pub const PG_WORKINGSET: u64 = 1 << 6;
pub const PG_WAITERS: u64 = 1 << 7;
pub const PG_ERROR: u64 = 1 << 8;
pub const PG_SLAB: u64 = 1 << 9;
pub const PG_OWNER_PRIV_1: u64 = 1 << 10;
pub const PG_ARCH_1: u64 = 1 << 11;
pub const PG_RESERVED: u64 = 1 << 12;
pub const PG_PRIVATE: u64 = 1 << 13;
pub const PG_PRIVATE_2: u64 = 1 << 14;
pub const PG_WRITEBACK: u64 = 1 << 15;
pub const PG_HEAD: u64 = 1 << 16;
pub const PG_MAPPEDTODISK: u64 = 1 << 17;
pub const PG_RECLAIM: u64 = 1 << 18;
pub const PG_SWAPBACKED: u64 = 1 << 19;
pub const PG_UNEVICTABLE: u64 = 1 << 20;
pub const PG_MLOCKED: u64 = 1 << 21;
pub const PG_HWPOISON: u64 = 1 << 22;
pub const PG_YOUNG: u64 = 1 << 23;
pub const PG_IDLE: u64 = 1 << 24;
pub const PG_ARCH_2: u64 = 1 << 25;
pub const PG_ARCH_3: u64 = 1 << 26;

// ============================================================================
// GFP Flags (Get Free Pages)
// ============================================================================

pub const GFP_ATOMIC: u32 = 0x00000020;           // Cannot sleep
pub const GFP_KERNEL: u32 = 0x000000D0;           // Normal kernel allocation
pub const GFP_NOWAIT: u32 = 0x00000000;
pub const GFP_NOIO: u32 = 0x00000010;
pub const GFP_NOFS: u32 = 0x00000030;
pub const GFP_USER: u32 = 0x000000D4;
pub const GFP_HIGHUSER: u32 = 0x000200D2;
pub const GFP_HIGHUSER_MOVABLE: u32 = 0x000A00D2;
pub const GFP_DMA: u32 = 0x00000001;
pub const GFP_DMA32: u32 = 0x00000004;
pub const GFP_MOVABLE: u32 = 0x00000008;
pub const GFP_ZERO: u32 = 0x00000100;
pub const GFP_COMP: u32 = 0x00004000;
pub const GFP_NOWARN: u32 = 0x00000200;
pub const GFP_RETRY_MAYFAIL: u32 = 0x00000400;
pub const GFP_NOFAIL: u32 = 0x00000800;
pub const GFP_NORETRY: u32 = 0x00001000;
pub const GFP_DIRECT_RECLAIM: u32 = 0x00000040;
pub const GFP_KSWAPD_RECLAIM: u32 = 0x00000080;
pub const GFP_TRANSHUGE: u32 = 0x000A00D2;
pub const GFP_TRANSHUGE_LIGHT: u32 = 0x000A0012;

// ============================================================================
// Zone Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ZoneType {
    Dma = 0,      // 0 - 16MB
    Dma32 = 1,    // 0 - 4GB
    Normal = 2,   // All available memory
    HighMem = 3,  // x86 only, above 896MB
    Movable = 4,  // Movable pages for compaction/hotplug
    Device = 5,   // Device memory (PMEM, GPU)
}

pub struct Zone {
    pub zone_type: ZoneType,
    pub name: [16; u8],
    pub name_len: u8,
    pub zone_start_pfn: u64,
    pub spanned_pages: u64,    // Total pages in zone
    pub present_pages: u64,    // Physical pages present
    pub managed_pages: u64,    // Pages managed by buddy allocator
    // Free area (buddy allocator)
    pub free_area: [11; FreeArea],  // Order 0-10 (4KB - 4MB)
    pub nr_free: AtomicU64,
    // Watermarks
    pub watermark_min: u64,
    pub watermark_low: u64,
    pub watermark_high: u64,
    pub watermark_boost: u64,
    // Per-CPU page caches
    pub per_cpu_pageset_batch: u32,
    pub per_cpu_pageset_high: u32,
    // Compaction
    pub compact_cached_free_pfn: u64,
    pub compact_cached_migrate_pfn: u64,
    pub compact_considered: AtomicU32,
    pub compact_defer_shift: u32,
    pub compact_order_failed: u32,
    // Statistics
    pub vm_stat: [40; AtomicU64],
    pub node_id: u8,
}

pub struct FreeArea {
    pub nr_free: u64,
    pub free_list: [6; PageList],  // Per migrate-type free lists
}

pub struct PageList {
    pub head: u64,  // Physical page frame number
    pub count: u64,
}

// Migrate types
pub const MIGRATE_UNMOVABLE: u8 = 0;
pub const MIGRATE_MOVABLE: u8 = 1;
pub const MIGRATE_RECLAIMABLE: u8 = 2;
pub const MIGRATE_PCPTYPES: u8 = 3;
pub const MIGRATE_HIGHATOMIC: u8 = 3;
pub const MIGRATE_CMA: u8 = 4;
pub const MIGRATE_ISOLATE: u8 = 5;

// ============================================================================
// NUMA Node
// ============================================================================

pub struct NumaNode {
    pub node_id: u8,
    pub node_present_pages: u64,
    pub node_spanned_pages: u64,
    pub node_start_pfn: u64,
    pub zones: [6; Zone],
    pub nr_zones: u8,
    // LRU lists
    pub lru_lists: [5; LruList],
    pub total_scan: AtomicU64,
    // NUMA distance
    pub distance: [8; u8],    // Distance to other nodes (10 = local)
    // Stats
    pub pages_scanned: AtomicU64,
    pub kswapd_nr_scanned: AtomicU64,
    pub kswapd_nr_reclaimed: AtomicU64,
}

// LRU list types
pub const LRU_INACTIVE_ANON: u8 = 0;
pub const LRU_ACTIVE_ANON: u8 = 1;
pub const LRU_INACTIVE_FILE: u8 = 2;
pub const LRU_ACTIVE_FILE: u8 = 3;
pub const LRU_UNEVICTABLE: u8 = 4;

pub struct LruList {
    pub head_pfn: u64,
    pub tail_pfn: u64,
    pub nr_pages: AtomicU64,
}

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

pub struct CmaRegion {
    pub name: [32; u8],
    pub name_len: u8,
    pub base_pfn: u64,
    pub count: u64,         // Total pages
    pub order_per_bit: u8,  // Pages per bitmap bit
    pub bitmap: [2048; u64], // Allocation bitmap
    pub bitmap_size: u32,
    pub allocated_pages: AtomicU64,
    pub available: bool,
}

impl CmaRegion {
    /// Try to allocate `count` pages from CMA
    pub fn alloc_pages(&mut self, count: u64) -> Option<u64> {
        let bits_needed = (count >> self.order_per_bit) as u32;
        if bits_needed == 0 { return None; }
        
        // Find consecutive free bits
        let total_bits = self.bitmap_size;
        let mut start_bit = 0u32;
        let mut found = 0u32;
        
        for bit in 0..total_bits {
            let word_idx = (bit / 64) as usize;
            let bit_pos = bit % 64;
            
            if word_idx >= self.bitmap.len() { break; }
            
            if self.bitmap[word_idx] & (1u64 << bit_pos) == 0 {
                if found == 0 { start_bit = bit; }
                found += 1;
                if found == bits_needed {
                    // Mark as allocated
                    for b in start_bit..start_bit + bits_needed {
                        let wi = (b / 64) as usize;
                        let bp = b % 64;
                        self.bitmap[wi] |= 1u64 << bp;
                    }
                    self.allocated_pages.fetch_add(count, Ordering::Relaxed);
                    let pfn = self.base_pfn + (start_bit as u64 << self.order_per_bit);
                    return Some(pfn);
                }
            } else {
                found = 0;
            }
        }
        None
    }

    /// Release CMA pages
    pub fn release_pages(&mut self, pfn: u64, count: u64) {
        if pfn < self.base_pfn { return; }
        let start_bit = ((pfn - self.base_pfn) >> self.order_per_bit) as u32;
        let bits = (count >> self.order_per_bit) as u32;
        
        for b in start_bit..start_bit + bits {
            let wi = (b / 64) as usize;
            let bp = b % 64;
            if wi < self.bitmap.len() {
                self.bitmap[wi] &= !(1u64 << bp);
            }
        }
        self.allocated_pages.fetch_sub(count, Ordering::Relaxed);
    }
}

// ============================================================================
// HugeTLB
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HugePageSize {
    Size2MB,
    Size1GB,
    Size16KB,  // ARM
    Size32MB,  // ARM
    Size512MB, // ARM
    Size16GB,  // PPC
}

impl HugePageSize {
    pub fn bytes(&self) -> u64 {
        match self {
            HugePageSize::Size2MB => 2 * 1024 * 1024,
            HugePageSize::Size1GB => 1024 * 1024 * 1024,
            HugePageSize::Size16KB => 16 * 1024,
            HugePageSize::Size32MB => 32 * 1024 * 1024,
            HugePageSize::Size512MB => 512 * 1024 * 1024,
            HugePageSize::Size16GB => 16u64 * 1024 * 1024 * 1024,
        }
    }
}

pub struct HugePagePool {
    pub page_size: HugePageSize,
    pub nr_hugepages: AtomicU64,
    pub free_hugepages: AtomicU64,
    pub resv_hugepages: AtomicU64,
    pub surplus_hugepages: AtomicU64,
    pub max_surplus: u64,
    pub nr_overcommit: u64,
    // Per-NUMA node pools
    pub node_free: [4; AtomicU64],
    pub node_total: [4; AtomicU64],
}

impl HugePagePool {
    pub fn alloc_page(&self, nid: i32) -> bool {
        if nid >= 0 && (nid as usize) < 4 {
            let free = self.node_free[nid as usize].load(Ordering::Relaxed);
            if free > 0 {
                self.node_free[nid as usize].fetch_sub(1, Ordering::Relaxed);
                self.free_hugepages.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
        }
        // Fallback to any node
        let free = self.free_hugepages.load(Ordering::Relaxed);
        if free > 0 {
            self.free_hugepages.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
        false
    }
}

// ============================================================================
// Page Compaction
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompactResult {
    NotSuitable,
    Skipped,
    Continue,
    Complete,
    PartialSkipped,
    Contended,
    NoSuitablePage,
    DeferredReset,
    Success,
}

pub struct CompactionControl {
    pub order: u32,
    pub migratetype: u8,
    pub zone: u8,
    pub mode: CompactionMode,
    // Page tracking
    pub migrate_pfn: u64,    // Scan migrateable pages from start
    pub free_pfn: u64,       // Scan free pages from end
    pub total_migrate_scanned: u64,
    pub total_free_scanned: u64,
    pub nr_migrated: u64,
    pub nr_failed: u64,
    // Proactive compaction
    pub proactive_defer: u32,
    pub whole_zone: bool,
    pub finishing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompactionMode {
    Sync,       // Full synchronous compaction
    SyncLight,  // Lighter sync (skip some pages)
    Async,      // Deferred compaction
}

pub struct CompactionStats {
    pub compact_stall: AtomicU64,
    pub compact_success: AtomicU64,
    pub compact_fail: AtomicU64,
    pub compact_pages_moved: AtomicU64,
    pub compact_pagemigrate_failed: AtomicU64,
    pub compact_isolated: AtomicU64,
    pub compact_free_scanned: AtomicU64,
    pub compact_migrate_scanned: AtomicU64,
}

// ============================================================================
// Memory Hotplug
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryBlockState {
    Offline,
    GoingOffline,
    Online,
    GoingOnline,
}

pub struct MemoryBlock {
    pub start_section_nr: u64,
    pub state: MemoryBlockState,
    pub phys_device: u32,
    pub nid: u8,            // NUMA node
    pub zone: ZoneType,
    pub removable: bool,
    pub nr_pages: u64,
}

pub const MEMORY_BLOCK_SIZE: u64 = 128 * 1024 * 1024; // 128MB per block

// ============================================================================
// zswap (Compressed Swap Cache)
// ============================================================================

pub struct ZswapPool {
    pub compressor: ZswapCompressor,
    pub zpool_type: ZpoolType,
    pub max_pool_percent: u8,    // Max % of memory for zswap
    pub accept_threshold_percent: u8,
    pub enabled: AtomicBool,
    // Stats
    pub stored_pages: AtomicU64,
    pub pool_total_size: AtomicU64,
    pub duplicate_entry: AtomicU64,
    pub written_back_pages: AtomicU64,
    pub reject_reclaim_fail: AtomicU64,
    pub reject_alloc_fail: AtomicU64,
    pub reject_kmemcache_fail: AtomicU64,
    pub reject_compress_poor: AtomicU64,
    pub same_filled_pages: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZswapCompressor {
    Lzo,
    Lz4,
    Deflate,
    Zstd,
    Lz4hc,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZpoolType {
    Zbud,       // 2-page per-block allocator
    Z3fold,     // 3-page per-block allocator
    Zsmalloc,   // Compressed slab allocator
}

pub struct ZswapEntry {
    pub offset: u64,         // Swap offset
    pub length: u32,         // Compressed length
    pub pool_handle: u64,    // Handle in zpool
    pub swpentry: u64,       // Swap page entry
    pub objcg: u32,          // memcg object cgroup
    pub same_filled: bool,
    pub fill_value: u64,     // If same_filled, the repeated value
}

// ============================================================================
// zram (Compressed RAM Block Device)
// ============================================================================

pub struct ZramDevice {
    pub disk_size: u64,      // Virtual disk size
    pub comp_algorithm: ZswapCompressor,
    pub mem_limit: u64,      // Max memory usage
    pub mem_used_total: AtomicU64,
    pub mem_used_max: u64,
    pub pages_stored: AtomicU64,
    pub zero_pages: AtomicU64,
    pub same_pages: AtomicU64,
    pub huge_pages: AtomicU64,
    pub compr_data_size: AtomicU64,
    pub num_reads: AtomicU64,
    pub num_writes: AtomicU64,
    pub failed_reads: AtomicU64,
    pub failed_writes: AtomicU64,
    pub notify_free: AtomicU64,
    pub bd_count: AtomicU64,  // Backing device writeback count
}

// ============================================================================
// Memory Cgroups (memcg)
// ============================================================================

pub struct MemoryCgroup {
    pub id: u64,
    pub parent_id: u64,
    // Limits
    pub memory_limit: u64,        // Hard limit
    pub memsw_limit: u64,         // Memory + swap limit
    pub soft_limit: u64,
    pub kmem_limit: u64,          // Kernel memory limit
    pub tcpmem_limit: u64,        // TCP memory limit
    // Counters
    pub memory_usage: AtomicU64,
    pub memsw_usage: AtomicU64,
    pub kmem_usage: AtomicU64,
    pub tcpmem_usage: AtomicU64,
    pub memory_max_usage: AtomicU64,
    pub memsw_max_usage: AtomicU64,
    // Watermarks
    pub memory_low: u64,
    pub memory_high: u64,
    pub memory_min: u64,
    // OOM
    pub oom_kill_disable: bool,
    pub under_oom: AtomicBool,
    pub oom_kills: AtomicU64,
    // Stats
    pub stat: MemcgStat,
    // Reclaim
    pub last_scanned_page: u64,
    pub reclaim_score: u32,      // Soft limit reclaim priority
}

pub struct MemcgStat {
    pub cache: AtomicU64,
    pub rss: AtomicU64,
    pub rss_huge: AtomicU64,
    pub shmem: AtomicU64,
    pub mapped_file: AtomicU64,
    pub dirty: AtomicU64,
    pub writeback: AtomicU64,
    pub swap: AtomicU64,
    pub pgpgin: AtomicU64,
    pub pgpgout: AtomicU64,
    pub pgfault: AtomicU64,
    pub pgmajfault: AtomicU64,
    pub inactive_anon: AtomicU64,
    pub active_anon: AtomicU64,
    pub inactive_file: AtomicU64,
    pub active_file: AtomicU64,
    pub unevictable: AtomicU64,
    pub workingset_refault_anon: AtomicU64,
    pub workingset_refault_file: AtomicU64,
    pub workingset_activate_anon: AtomicU64,
    pub workingset_activate_file: AtomicU64,
    pub workingset_restore_anon: AtomicU64,
    pub workingset_restore_file: AtomicU64,
    pub workingset_nodereclaim: AtomicU64,
    pub thp_fault_alloc: AtomicU64,
    pub thp_collapse_alloc: AtomicU64,
}

impl MemoryCgroup {
    pub fn charge_page(&self) -> bool {
        let current = self.memory_usage.fetch_add(4096, Ordering::Relaxed);
        if current + 4096 > self.memory_limit {
            self.memory_usage.fetch_sub(4096, Ordering::Relaxed);
            return false;
        }
        // Update max
        let mut max = self.memory_max_usage.load(Ordering::Relaxed);
        let new_total = current + 4096;
        while new_total > max {
            match self.memory_max_usage.compare_exchange_weak(
                max, new_total, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(m) => max = m,
            }
        }
        true
    }

    pub fn uncharge_page(&self) {
        self.memory_usage.fetch_sub(4096, Ordering::Relaxed);
    }

    pub fn at_limit(&self) -> bool {
        self.memory_usage.load(Ordering::Relaxed) >= self.memory_limit
    }

    pub fn over_high(&self) -> bool {
        self.memory_usage.load(Ordering::Relaxed) >= self.memory_high
    }
}

// ============================================================================
// vmstat counters (VM Statistics)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum VmStatItem {
    NrFreePagesI = 0,
    NrZoneInactiveAnon,
    NrZoneActiveAnon,
    NrZoneInactiveFile,
    NrZoneActiveFile,
    NrZoneUnevictable,
    NrZoneWritePending,
    NrMlock,
    NrBounce,
    NrZspages,
    NrFreeCmaPages,
    NrUnaccepted,
    NrAnonMapped,
    NrFilePages,
    NrFileMapped,
    NrDirtyPages,
    NrWriteback,
    NrWritebackTemp,
    NrShmem,
    NrShmemHugepages,
    NrShmemPmdmapped,
    NrFileHugepages,
    NrFilePmdmapped,
    NrAnonPages,
    NrVmscanWrite,
    NrVmscanImmediateReclaim,
    NrDirtied,
    NrWritten,
    NrThrottledWritten,
    NrKernelMiscReclaimable,
    NrPagetable,
    NrSecondaryPagetable,
    NrSlabReclaimable,
    NrSlabUnreclaimable,
    NrKernelStack,
    NumVmstatItems,
}
