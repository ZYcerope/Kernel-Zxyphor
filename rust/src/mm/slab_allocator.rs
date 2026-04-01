// Zxyphor Kernel - Rust Slab Allocator, Per-CPU Allocator, 
// kmalloc/kfree interface, Memory Debugging, SLUB internals
// More advanced than Linux 2026 SLUB allocator

/// Slab cache flags
pub struct SlabCacheFlags;
impl SlabCacheFlags {
    /// Align objects to hardware cache line
    pub const HWCACHE_ALIGN: u32 = 0x00002000;
    /// Use SLAB_TYPESAFE_BY_RCU
    pub const TYPESAFE_BY_RCU: u32 = 0x00080000;
    /// Red zone around objects
    pub const RED_ZONE: u32 = 0x00000400;
    /// Poison objects on free
    pub const POISON: u32 = 0x00000800;
    /// Track allocation callers
    pub const STORE_USER: u32 = 0x00010000;
    /// Reclaim account
    pub const RECLAIM_ACCOUNT: u32 = 0x00020000;
    /// Panic on allocation failure
    pub const PANIC: u32 = 0x00040000;
    /// No sysfs entry
    pub const NO_SYSFS: u32 = 0x00000100;
    /// Account allocations to memcg
    pub const ACCOUNT: u32 = 0x04000000;
    /// No merge with similar caches
    pub const NO_MERGE: u32 = 0x08000000;
    /// Object is zero-initialised
    pub const ZERO_INIT: u32 = 0x10000000;
    /// DMA-accessible memory
    pub const DMA: u32 = 0x00000001;
    /// DMA32 zone
    pub const DMA32: u32 = 0x00000004;
    /// KASAN instrumented
    pub const KASAN: u32 = 0x20000000;
    /// No kmemleak tracking
    pub const NO_KMEMLEAK: u32 = 0x40000000;
    /// NUMA-aware allocations
    pub const NUMA: u32 = 0x00000002;
    /// Zxyphor: Predictive prefetch
    pub const ZXY_PREFETCH: u32 = 0x80000000;
}

/// Slab cache descriptor (SLUB-like)
#[repr(C)]
pub struct SlabCache {
    /// Cache name
    pub name: [u8; 64],
    /// Object size (including metadata)
    pub size: u32,
    /// Actual usable object size
    pub object_size: u32,
    /// Alignment
    pub align: u32,
    /// Cache flags
    pub flags: u32,
    /// Objects per slab
    pub oo_objects: u16,
    /// Order of pages per slab
    pub oo_order: u16,
    /// Min objects per slab
    pub min_objects: u16,
    pub min_order: u16,
    /// Offset of free pointer in object
    pub offset: u32,
    /// Red zone size
    pub red_left_pad: u32,
    /// Number of per-CPU partial slabs
    pub cpu_partial: u32,
    /// Min partial slabs before returning to page allocator
    pub min_partial: u32,
    /// NUMA node preference
    pub remote_node_defrag_ratio: u32,
    /// Allocation/free bit for random canaries
    pub random_seed: u64,
    /// Memcg parameters
    pub memcg_params: SlabMemcgParams,
    /// Runtime stats
    pub stats: SlabCacheStats,
    /// Zxyphor extensions
    pub zxy_prefetch_depth: u32,
    pub zxy_locality_tracking: bool,
}

/// Per-CPU slab cache (SLUB cpu_slab)
#[repr(C)]
pub struct SlabPerCpu {
    /// Pointer to free object (fastpath)
    pub freelist: u64,
    /// Transaction ID for cmpxchg
    pub tid: u64,
    /// Current slab page
    pub slab: u64,
    /// Partial slab list
    pub partial: u64,
    /// Stats
    pub stat_alloc_fastpath: u64,
    pub stat_alloc_slowpath: u64,
    pub stat_free_fastpath: u64,
    pub stat_free_slowpath: u64,
    pub stat_free_frozen: u64,
    pub stat_alloc_refill: u64,
}

/// Slab memcg parameters
#[repr(C)]
pub struct SlabMemcgParams {
    pub memcg_cache: bool,
    pub root_cache: u64,         // Pointer to root cache
    pub memcg_id: u32,
}

/// Slab cache statistics
#[repr(C)]
pub struct SlabCacheStats {
    /// Active objects
    pub active_objs: u64,
    /// Total objects (including free)
    pub total_objs: u64,
    /// Active slabs
    pub active_slabs: u64,
    /// Total slabs
    pub total_slabs: u64,
    /// Shared available
    pub shared_avail: u64,
    /// Number of allocations
    pub alloc_total: u64,
    /// Number of frees
    pub free_total: u64,
    /// Number of allocation errors
    pub alloc_errors: u64,
    /// Bytes used
    pub slab_size_bytes: u64,
    /// Objects per slab
    pub objs_per_slab: u32,
    /// Pages per slab
    pub pages_per_slab: u32,
    /// Batch count
    pub batchcount: u32,
    /// Per-CPU limit
    pub limit: u32,
    /// Deactivate full / empty / to_head / to_tail
    pub deactivate_full: u64,
    pub deactivate_empty: u64,
    pub deactivate_to_head: u64,
    pub deactivate_to_tail: u64,
    pub deactivate_remote_frees: u64,
    /// NUMA
    pub alloc_node_mismatch: u64,
    pub alloc_from_partial: u64,
    pub alloc_slab: u64,
    pub free_slab: u64,
    /// CPU slab flush
    pub cpuslab_flush: u64,
}

// ============================================================================
// kmalloc Interface
// ============================================================================

/// kmalloc size classes
pub struct KmallocSizeClasses;
impl KmallocSizeClasses {
    pub const SIZES: [u32; 14] = [
        8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192, 16384,
    ];
    
    pub const MAX_KMALLOC_SIZE: u32 = 8 * 1024 * 1024; // 8MB
    pub const MAX_KMALLOC_ORDER: u32 = 11;              // 2^11 pages = 8MB
}

/// kmalloc cache type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmallocType {
    Normal = 0,
    Dma = 1,
    Reclaim = 2,
    Cgroup = 3,
    Random = 4,          // Randomized slab
}

/// GFP flags for slab allocation
pub struct GfpSlabFlags;
impl GfpSlabFlags {
    pub const GFP_KERNEL: u32 = 0x000000D0;
    pub const GFP_ATOMIC: u32 = 0x00000200;
    pub const GFP_NOWAIT: u32 = 0x00000000;
    pub const GFP_NOIO: u32 = 0x00000010;
    pub const GFP_NOFS: u32 = 0x00000030;
    pub const GFP_USER: u32 = 0x000000D4;
    pub const GFP_DMA: u32 = 0x00000001;
    pub const GFP_DMA32: u32 = 0x00000004;
    pub const GFP_HIGHUSER: u32 = 0x000200D2;
    pub const __GFP_ZERO: u32 = 0x00008000;
    pub const __GFP_COMP: u32 = 0x00004000;
    pub const __GFP_NOWARN: u32 = 0x00000200;
    pub const __GFP_RETRY_MAYFAIL: u32 = 0x00080000;
    pub const __GFP_NOFAIL: u32 = 0x00000800;
    pub const __GFP_ACCOUNT: u32 = 0x00100000;
    pub const __GFP_RECLAIMABLE: u32 = 0x00000010;
    pub const __GFP_KSWAPD_RECLAIM: u32 = 0x02000000;
}

// ============================================================================
// Memory Debugging: KASAN/SLUB debug
// ============================================================================

/// Slab poison bytes
pub struct SlabPoison;
impl SlabPoison {
    pub const SLAB_RED_INACTIVE: u8 = 0xBB;
    pub const SLAB_RED_ACTIVE: u8 = 0xCC;
    pub const POISON_INUSE: u8 = 0x5A;
    pub const POISON_FREE: u8 = 0x6B;
    pub const POISON_END: u8 = 0xA5;
    pub const SLUB_RED_INACTIVE: u64 = 0xBB00BBBBBB00BBBB;
    pub const SLUB_RED_ACTIVE: u64 = 0xCC00CCCCCC00CCCC;
}

/// SLUB debug tracking info
#[repr(C)]
pub struct SlubTrackInfo {
    pub addr: u64,           // Allocation/free call site
    pub addrs: [u64; 16],   // Stack trace
    pub nr_entries: u32,
    pub cpu: u32,
    pub pid: u32,
    pub when: u64,           // jiffies at alloc/free
}

/// Slab object state (for debugging)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabObjState {
    Free = 0,
    Allocated = 1,
    RcuPending = 2,
    Poisoned = 3,
    RedZoned = 4,
}

/// Slab debug report
#[repr(C)]
pub struct SlabDebugReport {
    pub cache_name: [u8; 64],
    pub obj_addr: u64,
    pub state: SlabObjState,
    pub alloc_track: SlubTrackInfo,
    pub free_track: SlubTrackInfo,
    /// KASAN shadow byte at object
    pub kasan_shadow: u8,
    /// Red zone values
    pub left_redzone: u64,
    pub right_redzone: u64,
    /// Corruption details
    pub corruption_offset: i64,
    pub expected_value: u8,
    pub actual_value: u8,
}

// ============================================================================
// Per-CPU Allocator (mempool analog)
// ============================================================================

/// Per-CPU allocation pool
#[repr(C)]
pub struct PerCpuPool {
    pub name: [u8; 32],
    pub obj_size: u32,
    pub batch_size: u32,
    pub high_watermark: u32,
    pub nr_cpus: u32,
    /// Per-CPU stats
    pub total_alloc: u64,
    pub total_free: u64,
    pub total_refill: u64,
    pub total_flush: u64,
    pub current_count: [u32; 256],    // Per-CPU current count (max 256 CPUs)
}

/// Memory pool (fallback allocation)
#[repr(C)]
pub struct MemPool {
    pub min_nr: u32,
    pub curr_nr: u32,
    pub element_size: u32,
    pub pool_type: MemPoolType,
    /// Stats
    pub total_alloc: u64,
    pub total_free: u64,
    pub total_pool_hit: u64,
    pub total_fallback: u64,
    pub total_wait: u64,
}

/// Memory pool type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemPoolType {
    Slab = 0,
    Kmalloc = 1,
    Page = 2,
}

// ============================================================================
// kmem_cache_create / destroy interface
// ============================================================================

/// Cache creation parameters
#[repr(C)]
pub struct CacheCreateParams {
    pub name: [u8; 64],
    pub size: u32,
    pub align: u32,
    pub flags: u32,
    pub ctor: u64,           // Constructor function pointer
    pub useroffset: u32,     // Usercopy region offset
    pub usersize: u32,       // Usercopy region size
}

/// Cache destroy info
#[repr(C)]
pub struct CacheDestroyInfo {
    pub name: [u8; 64],
    pub total_allocs: u64,
    pub total_frees: u64,
    pub leaked_objects: u64,
    pub destroy_time_ns: u64,
}

// ============================================================================
// Slab shrinker interface
// ============================================================================

/// Shrinker priority
pub struct ShrinkerPriority;
impl ShrinkerPriority {
    pub const DEFAULT: i32 = 0;
    pub const FS_INODE: i32 = -10;
    pub const FS_DENTRY: i32 = -20;
    pub const VM: i32 = -30;
    pub const MINIMUM: i32 = -100;
}

/// Shrinker registration
#[repr(C)]
pub struct ShrinkerInfo {
    pub name: [u8; 64],
    pub seeks: u32,
    pub batch: u32,
    pub flags: u32,
    pub nr_deferred: u64,
    /// NUMA awareness
    pub numa_aware: bool,
    /// Stats
    pub total_scan_count: u64,
    pub total_free_count: u64,
    pub total_invocations: u64,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

pub struct SlabSubsystem {
    /// Total slab caches
    pub nr_slab_caches: u32,
    /// kmalloc caches
    pub nr_kmalloc_caches: u32,
    /// Active objects across all caches
    pub total_active_objs: u64,
    /// Total objects (including free)  
    pub total_objs: u64,
    /// Total slab pages
    pub total_slab_pages: u64,
    /// Total slab size in bytes
    pub total_slab_bytes: u64,
    /// Total allocations
    pub total_allocs: u64,
    /// Total frees
    pub total_frees: u64,
    /// Memory pools
    pub nr_mempools: u32,
    /// Shrinkers
    pub nr_shrinkers: u32,
    /// Debug
    pub kasan_quarantine_bytes: u64,
    pub total_debug_reports: u64,
    /// Zxyphor
    pub zxy_predictive_prefetch: bool,
    pub zxy_adaptive_sizing: bool,
    pub initialized: bool,
}

impl SlabSubsystem {
    pub fn new() -> Self {
        Self {
            nr_slab_caches: 0,
            nr_kmalloc_caches: 0,
            total_active_objs: 0,
            total_objs: 0,
            total_slab_pages: 0,
            total_slab_bytes: 0,
            total_allocs: 0,
            total_frees: 0,
            nr_mempools: 0,
            nr_shrinkers: 0,
            kasan_quarantine_bytes: 0,
            total_debug_reports: 0,
            zxy_predictive_prefetch: true,
            zxy_adaptive_sizing: true,
            initialized: false,
        }
    }
}
