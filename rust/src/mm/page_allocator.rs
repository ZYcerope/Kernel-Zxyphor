// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - Page Allocator, Memory Zones, Free Area,
// Page Flags, Buddy System, Watermarks, Page Compaction
// More advanced than Linux 2026 page frame management

/// Page flags (compound word for page descriptor)
pub const PG_LOCKED: u64 = 1 << 0;
pub const PG_REFERENCED: u64 = 1 << 2;
pub const PG_UPTODATE: u64 = 1 << 3;
pub const PG_DIRTY: u64 = 1 << 4;
pub const PG_LRU: u64 = 1 << 5;
pub const PG_ACTIVE: u64 = 1 << 6;
pub const PG_WORKINGSET: u64 = 1 << 7;
pub const PG_WAITERS: u64 = 1 << 8;
pub const PG_ERROR: u64 = 1 << 9;
pub const PG_SLAB: u64 = 1 << 10;
pub const PG_OWNER_PRIV_1: u64 = 1 << 11;
pub const PG_ARCH_1: u64 = 1 << 12;
pub const PG_RESERVED: u64 = 1 << 13;
pub const PG_PRIVATE: u64 = 1 << 14;
pub const PG_PRIVATE_2: u64 = 1 << 15;
pub const PG_WRITEBACK: u64 = 1 << 16;
pub const PG_HEAD: u64 = 1 << 17;
pub const PG_MAPPEDTODISK: u64 = 1 << 18;
pub const PG_RECLAIM: u64 = 1 << 19;
pub const PG_SWAPBACKED: u64 = 1 << 20;
pub const PG_UNEVICTABLE: u64 = 1 << 21;
pub const PG_MLOCKED: u64 = 1 << 22;
pub const PG_UNCACHED: u64 = 1 << 23;
pub const PG_HWPOISON: u64 = 1 << 24;
pub const PG_YOUNG: u64 = 1 << 25;
pub const PG_IDLE: u64 = 1 << 26;
pub const PG_ARCH_2: u64 = 1 << 27;
pub const PG_ARCH_3: u64 = 1 << 28;
// Zxyphor
pub const PG_ZXY_SECURE: u64 = 1 << 56;
pub const PG_ZXY_COMPRESSED: u64 = 1 << 57;
pub const PG_ZXY_DEDUP: u64 = 1 << 58;

/// GFP (Get Free Pages) flags
pub const __GFP_DMA: u32 = 0x01;
pub const __GFP_HIGHMEM: u32 = 0x02;
pub const __GFP_DMA32: u32 = 0x04;
pub const __GFP_MOVABLE: u32 = 0x08;
pub const __GFP_RECLAIMABLE: u32 = 0x10;
pub const __GFP_HIGH: u32 = 0x20;
pub const __GFP_IO: u32 = 0x40;
pub const __GFP_FS: u32 = 0x80;
pub const __GFP_ZERO: u32 = 0x100;
pub const __GFP_ATOMIC: u32 = 0x200;
pub const __GFP_DIRECT_RECLAIM: u32 = 0x400;
pub const __GFP_KSWAPD_RECLAIM: u32 = 0x800;
pub const __GFP_WRITE: u32 = 0x1000;
pub const __GFP_NOWARN: u32 = 0x2000;
pub const __GFP_RETRY_MAYFAIL: u32 = 0x4000;
pub const __GFP_NOFAIL: u32 = 0x8000;
pub const __GFP_NORETRY: u32 = 0x10000;
pub const __GFP_MEMALLOC: u32 = 0x20000;
pub const __GFP_COMP: u32 = 0x40000;
pub const __GFP_NOMEMALLOC: u32 = 0x80000;
pub const __GFP_HARDWALL: u32 = 0x100000;
pub const __GFP_THISNODE: u32 = 0x200000;
pub const __GFP_ACCOUNT: u32 = 0x400000;
pub const __GFP_NOLOCKDEP: u32 = 0x800000;

// Composite GFP masks
pub const GFP_ATOMIC: u32 = __GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM;
pub const GFP_KERNEL: u32 = __GFP_RECLAIMABLE | __GFP_IO | __GFP_FS | __GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM;
pub const GFP_KERNEL_ACCOUNT: u32 = GFP_KERNEL | __GFP_ACCOUNT;
pub const GFP_NOWAIT: u32 = __GFP_KSWAPD_RECLAIM;
pub const GFP_NOIO: u32 = __GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM;
pub const GFP_NOFS: u32 = __GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM | __GFP_IO;
pub const GFP_USER: u32 = __GFP_RECLAIMABLE | __GFP_IO | __GFP_FS | __GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM | __GFP_HARDWALL;
pub const GFP_DMA: u32 = __GFP_DMA;
pub const GFP_DMA32: u32 = __GFP_DMA32;
pub const GFP_HIGHUSER: u32 = GFP_USER | __GFP_HIGHMEM;
pub const GFP_HIGHUSER_MOVABLE: u32 = GFP_HIGHUSER | __GFP_MOVABLE;
pub const GFP_TRANSHUGE_LIGHT: u32 = GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN;
pub const GFP_TRANSHUGE: u32 = GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM;

/// Memory zone type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    Dma = 0,
    Dma32 = 1,
    Normal = 2,
    HighMem = 3,     // 32-bit only
    Movable = 4,
    Device = 5,
    // Zxyphor
    ZxySecure = 10,
}

/// Zone watermarks
#[derive(Debug, Clone)]
pub struct ZoneWatermarks {
    pub wmark_min: u64,        // pages
    pub wmark_low: u64,
    pub wmark_high: u64,
    pub wmark_promo: u64,      // promotion watermark
    // Boosted
    pub wmark_boost: u64,
    // Managed
    pub managed_pages: u64,
    pub spanned_pages: u64,
    pub present_pages: u64,
    pub cma_pages: u64,
}

/// Free area for buddy allocator
#[derive(Debug, Clone)]
pub struct FreeArea {
    pub nr_free: u64,
    // Per migrate type
    pub free_unmovable: u64,
    pub free_movable: u64,
    pub free_reclaimable: u64,
    pub free_highatomic: u64,
    pub free_cma: u64,
    pub free_isolate: u64,
}

/// Migrate type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateType {
    Unmovable = 0,
    Movable = 1,
    Reclaimable = 2,
    Pcptypes = 3,
    Highatomic = 3,
    Cma = 4,
    Isolate = 5,
}

/// Zone statistics
#[derive(Debug, Clone)]
pub struct ZoneStats {
    pub zone_type: ZoneType,
    // Page counts
    pub free_pages: u64,
    pub zone_min: u64,
    pub zone_low: u64,
    pub zone_high: u64,
    // Per-order free page counts (order 0-10)
    pub free_pages_order: [u64; 11],
    // LRU counts
    pub nr_inactive_anon: u64,
    pub nr_active_anon: u64,
    pub nr_inactive_file: u64,
    pub nr_active_file: u64,
    pub nr_unevictable: u64,
    pub nr_slab_reclaimable: u64,
    pub nr_slab_unreclaimable: u64,
    pub nr_isolated_anon: u64,
    pub nr_isolated_file: u64,
    pub nr_kernel_stack: u64,
    pub nr_kernel_misc_reclaimable: u64,
    pub nr_mapped: u64,
    pub nr_dirty: u64,
    pub nr_writeback: u64,
    pub nr_bounce: u64,
    pub nr_free_cma: u64,
    pub nr_anon_transparent_hugepages: u64,
    pub nr_file_transparent_hugepages: u64,
    pub nr_shmem_transparent_hugepages: u64,
    pub nr_file_pmdmapped: u64,
    pub nr_anon_pmdmapped: u64,
    // VM events
    pub pgalloc: u64,
    pub pgfree: u64,
    pub pgactivate: u64,
    pub pgdeactivate: u64,
    pub pglazyfree: u64,
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub pgsteal_kswapd: u64,
    pub pgsteal_direct: u64,
    pub pgscan_kswapd: u64,
    pub pgscan_direct: u64,
    pub compact_stall: u64,
    pub compact_success: u64,
    pub compact_fail: u64,
    pub compact_migrate_scanned: u64,
    pub compact_free_scanned: u64,
    pub htlb_buddy_alloc_success: u64,
    pub htlb_buddy_alloc_fail: u64,
}

/// Per-CPU page lists
#[derive(Debug, Clone)]
pub struct PerCpuPages {
    pub count: u32,
    pub high: u32,
    pub batch: u32,
    pub high_min: u32,
    pub high_max: u32,
    // Stats
    pub total_alloc: u64,
    pub total_free: u64,
    pub total_refill: u64,
    pub total_drain: u64,
}

/// Compaction control
#[derive(Debug, Clone)]
pub struct CompactionControl {
    pub order: u8,
    pub migrate_pfn: u64,
    pub free_pfn: u64,
    pub zone_end: u64,
    pub mode: CompactionMode,
    pub result: CompactionResult,
    // Stats
    pub nr_migrated: u64,
    pub nr_failed: u64,
    pub nr_freepages: u64,
}

/// Compaction mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionMode {
    Sync = 0,
    SyncLight = 1,
    Async = 2,
}

/// Compaction result
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionResult {
    NotSuitableZone = 0,
    Skipped = 1,
    Deferred = 2,
    NoSuitablePage = 3,
    Continue = 4,
    Partial = 5,
    Complete = 6,
    Contended = 7,
}

/// MGLRU (Multi-Gen LRU) state
#[derive(Debug, Clone)]
pub struct MglruState {
    pub enabled: bool,
    pub min_ttl_ms: u64,
    // Generation tracking
    pub nr_generations: u8,         // usually 4
    pub max_seq: u64,
    pub min_seq_anon: u64,
    pub min_seq_file: u64,
    // Stats
    pub nr_evicted: [u64; 4],       // Per generation
    pub nr_promoted: [u64; 4],
    pub nr_scanned: [u64; 4],
    pub total_evictions: u64,
    pub total_promotions: u64,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Page management subsystem
#[derive(Debug, Clone)]
pub struct PageAllocSubsystem {
    // Zones
    pub nr_zones: u8,
    pub total_pages: u64,
    pub free_pages: u64,
    pub reserved_pages: u64,
    // Buddy allocator
    pub max_order: u8,           // typically 10
    pub total_alloc_pages: u64,
    pub total_free_pages: u64,
    pub total_alloc_failures: u64,
    // Per-CPU
    pub nr_cpus: u32,
    // Compaction
    pub total_compactions: u64,
    pub total_compaction_success: u64,
    pub total_compaction_fail: u64,
    // MGLRU
    pub mglru: MglruState,
    // OOM
    pub total_oom_kills: u64,
    // Zxyphor
    pub zxy_predictive_reclaim: bool,
    pub initialized: bool,
}
