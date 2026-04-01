// =============================================================================
// Kernel Zxyphor — Kernel Memory Allocator (Rust)
// =============================================================================
// Advanced memory allocation subsystem:
//   - Buddy allocator for page-granularity allocation
//   - kmalloc-style allocator with size classes
//   - Per-CPU page frame cache (PCP)
//   - Memory pool for fixed-size objects
//   - vmalloc for virtually contiguous large allocations
//   - Memory statistics and debugging
//   - Allocation flags (GFP)
//   - Memory pressure callbacks
// =============================================================================

/// Maximum buddy order (2^MAX_ORDER pages = 4 MiB block at order 10)
const MAX_ORDER: usize = 11;
/// Page size
const PAGE_SIZE: usize = 4096;
/// Maximum total pages managed
const MAX_PAGES: usize = 262144; // 1 GiB
/// Maximum number of per-CPU caches
const MAX_PCP: usize = 16;
/// PCP batch size
const PCP_BATCH: usize = 64;
/// PCP high watermark
const PCP_HIGH: usize = 384;
/// Number of kmalloc size classes
const KMALLOC_CLASSES: usize = 13;
/// Maximum memory pools
const MAX_POOLS: usize = 32;
/// Maximum vmalloc regions
const MAX_VMALLOC: usize = 256;
/// Maximum memory pressure callbacks
const MAX_SHRINKERS: usize = 16;

// ---------------------------------------------------------------------------
// GFP flags
// ---------------------------------------------------------------------------

pub const GFP_KERNEL: u32    = 0x000001;
pub const GFP_ATOMIC: u32   = 0x000002;
pub const GFP_DMA: u32      = 0x000004;
pub const GFP_DMA32: u32    = 0x000008;
pub const GFP_HIGHMEM: u32  = 0x000010;
pub const GFP_ZERO: u32     = 0x000020;
pub const GFP_NORETRY: u32  = 0x000040;
pub const GFP_NOWARN: u32   = 0x000080;
pub const GFP_COMP: u32     = 0x000100;
pub const GFP_MOVABLE: u32  = 0x000200;
pub const GFP_RECLAIM: u32  = 0x000400;
pub const GFP_IO: u32       = 0x000800;
pub const GFP_FS: u32       = 0x001000;
pub const GFP_HARDWALL: u32 = 0x002000;
pub const GFP_ACCOUNT: u32  = 0x004000;

// ---------------------------------------------------------------------------
// Page frame
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum PageState {
    Free      = 0,
    Allocated = 1,
    Slab      = 2,
    Compound  = 3,
    Reserved  = 4,
}

const PG_LOCKED: u32    = 0x0001;
const PG_DIRTY: u32     = 0x0002;
const PG_LRU: u32       = 0x0004;
const PG_ACTIVE: u32    = 0x0008;
const PG_SLAB: u32      = 0x0010;
const PG_BUDDY: u32     = 0x0020;
const PG_WRITEBACK: u32 = 0x0040;
const PG_RECLAIM: u32   = 0x0080;
const PG_SWAPBACKED: u32= 0x0100;
const PG_UNEVICTABLE: u32=0x0200;
const PG_MLOCKED: u32   = 0x0400;

#[derive(Clone, Copy)]
pub struct PageFrame {
    pub pfn: u32,
    pub state: PageState,
    pub flags: u32,
    pub order: u8,           // Buddy order if head of free block
    pub ref_count: u32,
    pub map_count: i32,      // Number of page table entries pointing here
    pub private: u64,        // For slab: pointer to slab descriptor
}

impl PageFrame {
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            state: PageState::Free,
            flags: 0,
            order: 0,
            ref_count: 0,
            map_count: 0,
            private: 0,
        }
    }

    pub fn get(&mut self) {
        self.ref_count += 1;
    }

    pub fn put(&mut self) -> bool {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count == 0
    }
}

// ---------------------------------------------------------------------------
// Free area (buddy system)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct FreeArea {
    /// Linked list heads: pfn of first free block at this order
    pub heads: [u32; 1024],
    pub count: u32,
}

impl FreeArea {
    pub const fn new() -> Self {
        Self {
            heads: [0u32; 1024],
            count: 0,
        }
    }

    pub fn push(&mut self, pfn: u32) {
        if (self.count as usize) < 1024 {
            self.heads[self.count as usize] = pfn;
            self.count += 1;
        }
    }

    pub fn pop(&mut self) -> Option<u32> {
        if self.count == 0 { return None; }
        self.count -= 1;
        Some(self.heads[self.count as usize])
    }

    pub fn remove(&mut self, pfn: u32) -> bool {
        for i in 0..self.count as usize {
            if self.heads[i] == pfn {
                let mut j = i;
                while j + 1 < self.count as usize {
                    self.heads[j] = self.heads[j + 1];
                    j += 1;
                }
                self.count -= 1;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Buddy allocator
// ---------------------------------------------------------------------------

pub struct BuddyAllocator {
    pages: [PageFrame; MAX_PAGES],
    free_areas: [FreeArea; MAX_ORDER],
    total_pages: u32,
    free_pages: u32,
    min_pfn: u32,
    max_pfn: u32,
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self {
            pages: [const { PageFrame::new() }; MAX_PAGES],
            free_areas: [const { FreeArea::new() }; MAX_ORDER],
            total_pages: 0,
            free_pages: 0,
            min_pfn: 0,
            max_pfn: 0,
        }
    }

    /// Initialize with a range of physical pages
    pub fn init_range(&mut self, start_pfn: u32, end_pfn: u32) {
        self.min_pfn = start_pfn;
        self.max_pfn = end_pfn;
        self.total_pages = end_pfn - start_pfn;

        // Initialize page frames
        for i in 0..self.total_pages as usize {
            if i < MAX_PAGES {
                self.pages[i].pfn = start_pfn + i as u32;
                self.pages[i].state = PageState::Free;
            }
        }

        // Build initial free list at highest possible orders
        let mut pfn = start_pfn;
        while pfn < end_pfn {
            let mut order = MAX_ORDER - 1;
            while order > 0 {
                let block_size = 1u32 << order;
                if pfn + block_size <= end_pfn && (pfn % block_size) == 0 {
                    break;
                }
                order -= 1;
            }
            let block_size = 1u32 << order;
            self.free_areas[order].push(pfn);
            let idx = (pfn - start_pfn) as usize;
            if idx < MAX_PAGES {
                self.pages[idx].order = order as u8;
                self.pages[idx].flags |= PG_BUDDY;
            }
            self.free_pages += block_size;
            pfn += block_size;
        }
    }

    /// Allocate 2^order contiguous pages
    pub fn alloc_pages(&mut self, order: usize, gfp: u32) -> Option<u32> {
        if order >= MAX_ORDER { return None; }

        // Find first available order >= requested
        let mut current_order = order;
        while current_order < MAX_ORDER {
            if self.free_areas[current_order].count > 0 {
                break;
            }
            current_order += 1;
        }
        if current_order >= MAX_ORDER { return None; }

        // Pop a block from this order
        let pfn = self.free_areas[current_order].pop()?;

        // Split down to requested order
        while current_order > order {
            current_order -= 1;
            let buddy_pfn = pfn + (1u32 << current_order);
            self.free_areas[current_order].push(buddy_pfn);

            let buddy_idx = (buddy_pfn - self.min_pfn) as usize;
            if buddy_idx < MAX_PAGES {
                self.pages[buddy_idx].order = current_order as u8;
                self.pages[buddy_idx].flags |= PG_BUDDY;
            }
        }

        // Mark allocated
        let block_pages = 1u32 << order;
        for i in 0..block_pages {
            let idx = (pfn + i - self.min_pfn) as usize;
            if idx < MAX_PAGES {
                self.pages[idx].state = PageState::Allocated;
                self.pages[idx].flags &= !PG_BUDDY;
                self.pages[idx].ref_count = 1;
            }
        }
        self.free_pages -= block_pages;

        // Zero if requested
        if gfp & GFP_ZERO != 0 {
            // In a real kernel, would zero the physical memory via virtual mapping
        }

        Some(pfn)
    }

    /// Free 2^order contiguous pages starting at pfn
    pub fn free_pages(&mut self, pfn: u32, order: usize) {
        if order >= MAX_ORDER { return; }
        if pfn < self.min_pfn || pfn >= self.max_pfn { return; }

        let block_pages = 1u32 << order;
        for i in 0..block_pages {
            let idx = (pfn + i - self.min_pfn) as usize;
            if idx < MAX_PAGES {
                self.pages[idx].state = PageState::Free;
                self.pages[idx].ref_count = 0;
            }
        }
        self.free_pages += block_pages;

        // Try to merge with buddy
        let mut current_pfn = pfn;
        let mut current_order = order;

        while current_order < MAX_ORDER - 1 {
            let buddy_pfn = current_pfn ^ (1u32 << current_order);
            if buddy_pfn < self.min_pfn || buddy_pfn >= self.max_pfn { break; }

            let buddy_idx = (buddy_pfn - self.min_pfn) as usize;
            if buddy_idx >= MAX_PAGES { break; }

            // Check buddy is free and at same order
            if self.pages[buddy_idx].state != PageState::Free
                || (self.pages[buddy_idx].flags & PG_BUDDY) == 0
                || self.pages[buddy_idx].order as usize != current_order
            {
                break;
            }

            // Remove buddy from free list
            self.free_areas[current_order].remove(buddy_pfn);
            self.pages[buddy_idx].flags &= !PG_BUDDY;

            // Merge: use lower pfn
            current_pfn = if current_pfn < buddy_pfn { current_pfn } else { buddy_pfn };
            current_order += 1;
        }

        // Add merged block to free list
        self.free_areas[current_order].push(current_pfn);
        let idx = (current_pfn - self.min_pfn) as usize;
        if idx < MAX_PAGES {
            self.pages[idx].order = current_order as u8;
            self.pages[idx].flags |= PG_BUDDY;
        }
    }

    pub fn free_page_count(&self) -> u32 {
        self.free_pages
    }
}

// ---------------------------------------------------------------------------
// Per-CPU page cache (PCP)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PerCpuPages {
    pub pages: [u32; PCP_HIGH],
    pub count: u32,
    pub high: u32,
    pub batch: u32,
    pub cpu_id: u8,
}

impl PerCpuPages {
    pub const fn new() -> Self {
        Self {
            pages: [0u32; PCP_HIGH],
            count: 0,
            high: PCP_HIGH as u32,
            batch: PCP_BATCH as u32,
            cpu_id: 0,
        }
    }

    pub fn alloc_page(&mut self) -> Option<u32> {
        if self.count == 0 { return None; }
        self.count -= 1;
        Some(self.pages[self.count as usize])
    }

    pub fn free_page(&mut self, pfn: u32) -> bool {
        if self.count >= self.high { return false; }
        self.pages[self.count as usize] = pfn;
        self.count += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// kmalloc size classes
// ---------------------------------------------------------------------------

/// Size classes: 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768
const KMALLOC_SIZES: [usize; KMALLOC_CLASSES] = [
    8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
];

const KMALLOC_MAX_OBJECTS: usize = 512;

#[derive(Clone, Copy)]
pub struct KmallocCache {
    pub size: usize,
    pub free_objects: [u64; KMALLOC_MAX_OBJECTS], // Virtual addresses
    pub free_count: u32,
    pub alloc_count: u64,
    pub free_total: u64,
}

impl KmallocCache {
    pub const fn new(size: usize) -> Self {
        Self {
            size,
            free_objects: [0u64; KMALLOC_MAX_OBJECTS],
            free_count: 0,
            alloc_count: 0,
            free_total: 0,
        }
    }

    pub fn alloc(&mut self) -> Option<u64> {
        if self.free_count > 0 {
            self.free_count -= 1;
            self.alloc_count += 1;
            Some(self.free_objects[self.free_count as usize])
        } else {
            None
        }
    }

    pub fn free(&mut self, addr: u64) -> bool {
        if self.free_count as usize >= KMALLOC_MAX_OBJECTS { return false; }
        self.free_objects[self.free_count as usize] = addr;
        self.free_count += 1;
        self.free_total += 1;
        true
    }
}

fn size_to_class(size: usize) -> Option<usize> {
    for i in 0..KMALLOC_CLASSES {
        if size <= KMALLOC_SIZES[i] {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Memory pool (fixed-size object allocator)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct MemPool {
    pub obj_size: usize,
    pub min_nr: u32,      // Minimum reserved
    pub curr_nr: u32,
    pub max_nr: u32,
    pub pool: [u64; 256],
    pub pool_count: u32,
    pub name: [u8; 32],
    pub name_len: u8,
    pub active: bool,
    pub allocs: u64,
    pub frees: u64,
}

impl MemPool {
    pub const fn new() -> Self {
        Self {
            obj_size: 0,
            min_nr: 0,
            curr_nr: 0,
            max_nr: 256,
            pool: [0u64; 256],
            pool_count: 0,
            name: [0u8; 32],
            name_len: 0,
            active: false,
            allocs: 0,
            frees: 0,
        }
    }

    pub fn alloc(&mut self) -> Option<u64> {
        if self.pool_count == 0 { return None; }
        self.pool_count -= 1;
        self.allocs += 1;
        Some(self.pool[self.pool_count as usize])
    }

    pub fn free(&mut self, addr: u64) -> bool {
        if self.pool_count >= self.max_nr { return false; }
        self.pool[self.pool_count as usize] = addr;
        self.pool_count += 1;
        self.frees += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// vmalloc region
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct VmallocRegion {
    pub vaddr: u64,
    pub size: usize,
    pub pages: [u32; 64],  // PFNs
    pub page_count: u32,
    pub flags: u32,
    pub active: bool,
}

impl VmallocRegion {
    pub const fn new() -> Self {
        Self {
            vaddr: 0,
            size: 0,
            pages: [0u32; 64],
            page_count: 0,
            flags: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory shrinker (reclaim callback)
// ---------------------------------------------------------------------------

pub type ShrinkerFn = fn(nr_to_scan: u64) -> u64;

#[derive(Clone, Copy)]
pub struct Shrinker {
    pub count_fn: Option<fn() -> u64>,
    pub scan_fn: Option<ShrinkerFn>,
    pub seeks: u32,
    pub batch: u32,
    pub active: bool,
}

impl Shrinker {
    pub const fn new() -> Self {
        Self {
            count_fn: None,
            scan_fn: None,
            seeks: 2,
            batch: 128,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory statistics
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct MemStats {
    pub total_pages: u64,
    pub free_pages: u64,
    pub slab_pages: u64,
    pub page_table_pages: u64,
    pub kernel_stack_pages: u64,
    pub kmalloc_bytes: u64,
    pub vmalloc_bytes: u64,
    pub pool_bytes: u64,
    pub buddy_splits: u64,
    pub buddy_merges: u64,
    pub alloc_fast: u64,
    pub alloc_slow: u64,
    pub alloc_fail: u64,
    pub pcp_alloc: u64,
    pub pcp_free: u64,
}

impl MemStats {
    pub const fn new() -> Self {
        Self {
            total_pages: 0, free_pages: 0,
            slab_pages: 0, page_table_pages: 0,
            kernel_stack_pages: 0,
            kmalloc_bytes: 0, vmalloc_bytes: 0, pool_bytes: 0,
            buddy_splits: 0, buddy_merges: 0,
            alloc_fast: 0, alloc_slow: 0, alloc_fail: 0,
            pcp_alloc: 0, pcp_free: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel allocator
// ---------------------------------------------------------------------------

pub struct KernelAllocator {
    pub buddy: BuddyAllocator,
    pub pcp: [PerCpuPages; MAX_PCP],
    pub kmalloc_caches: [KmallocCache; KMALLOC_CLASSES],
    pub pools: [MemPool; MAX_POOLS],
    pub pool_count: u32,
    pub vmalloc_regions: [VmallocRegion; MAX_VMALLOC],
    pub vmalloc_count: u32,
    pub vmalloc_base: u64,
    pub shrinkers: [Shrinker; MAX_SHRINKERS],
    pub shrinker_count: u32,
    pub stats: MemStats,
    pub initialized: bool,
}

impl KernelAllocator {
    pub const fn new() -> Self {
        Self {
            buddy: BuddyAllocator::new(),
            pcp: [const { PerCpuPages::new() }; MAX_PCP],
            kmalloc_caches: [
                KmallocCache::new(8),
                KmallocCache::new(16),
                KmallocCache::new(32),
                KmallocCache::new(64),
                KmallocCache::new(128),
                KmallocCache::new(256),
                KmallocCache::new(512),
                KmallocCache::new(1024),
                KmallocCache::new(2048),
                KmallocCache::new(4096),
                KmallocCache::new(8192),
                KmallocCache::new(16384),
                KmallocCache::new(32768),
            ],
            pools: [const { MemPool::new() }; MAX_POOLS],
            pool_count: 0,
            vmalloc_regions: [const { VmallocRegion::new() }; MAX_VMALLOC],
            vmalloc_count: 0,
            vmalloc_base: 0xFFFF_C000_0000_0000, // Linux vmalloc start
            shrinkers: [const { Shrinker::new() }; MAX_SHRINKERS],
            shrinker_count: 0,
            stats: MemStats::new(),
            initialized: false,
        }
    }

    /// Initialize buddy allocator with a memory range
    pub fn init(&mut self, start_pfn: u32, end_pfn: u32) {
        self.buddy.init_range(start_pfn, end_pfn);
        self.stats.total_pages = (end_pfn - start_pfn) as u64;
        self.stats.free_pages = self.buddy.free_pages as u64;
        self.initialized = true;

        // Initialize PCP caches
        for i in 0..MAX_PCP {
            self.pcp[i].cpu_id = i as u8;
        }
    }

    /// Allocate pages
    pub fn alloc_pages(&mut self, order: usize, gfp: u32) -> Option<u32> {
        // Try PCP for single-page allocation
        if order == 0 {
            let cpu = 0usize; // Would use actual CPU ID
            if let Some(pfn) = self.pcp[cpu].alloc_page() {
                self.stats.pcp_alloc += 1;
                self.stats.alloc_fast += 1;
                return Some(pfn);
            }
        }

        // Fall back to buddy
        let result = self.buddy.alloc_pages(order, gfp);
        if result.is_some() {
            self.stats.alloc_slow += 1;
            self.stats.free_pages = self.buddy.free_pages as u64;
        } else {
            self.stats.alloc_fail += 1;
        }
        result
    }

    /// Free pages
    pub fn free_pages(&mut self, pfn: u32, order: usize) {
        // Try PCP for single-page free
        if order == 0 {
            let cpu = 0usize;
            if self.pcp[cpu].free_page(pfn) {
                self.stats.pcp_free += 1;
                return;
            }
        }

        self.buddy.free_pages(pfn, order);
        self.stats.free_pages = self.buddy.free_pages as u64;
    }

    /// kmalloc: allocate memory by size
    pub fn kmalloc(&mut self, size: usize, _gfp: u32) -> Option<u64> {
        let class = size_to_class(size)?;
        let addr = self.kmalloc_caches[class].alloc();
        if addr.is_some() {
            self.stats.kmalloc_bytes += KMALLOC_SIZES[class] as u64;
        }
        addr
    }

    /// kfree: free kmalloc'd memory
    pub fn kfree(&mut self, addr: u64, size: usize) -> bool {
        if let Some(class) = size_to_class(size) {
            if self.kmalloc_caches[class].free(addr) {
                self.stats.kmalloc_bytes = self.stats.kmalloc_bytes.saturating_sub(KMALLOC_SIZES[class] as u64);
                return true;
            }
        }
        false
    }

    /// Create a memory pool
    pub fn create_pool(&mut self, obj_size: usize, min_nr: u32) -> Option<usize> {
        if self.pool_count as usize >= MAX_POOLS { return None; }
        let idx = self.pool_count as usize;
        self.pools[idx] = MemPool::new();
        self.pools[idx].obj_size = obj_size;
        self.pools[idx].min_nr = min_nr;
        self.pools[idx].active = true;
        self.pool_count += 1;
        Some(idx)
    }

    /// Register a shrinker
    pub fn register_shrinker(&mut self, count_fn: fn() -> u64, scan_fn: ShrinkerFn) -> bool {
        if self.shrinker_count as usize >= MAX_SHRINKERS { return false; }
        let idx = self.shrinker_count as usize;
        self.shrinkers[idx] = Shrinker {
            count_fn: Some(count_fn),
            scan_fn: Some(scan_fn),
            seeks: 2,
            batch: 128,
            active: true,
        };
        self.shrinker_count += 1;
        true
    }

    /// Attempt to reclaim memory via shrinkers
    pub fn shrink_all(&mut self, nr_to_scan: u64) -> u64 {
        let mut freed = 0u64;
        for i in 0..self.shrinker_count as usize {
            if self.shrinkers[i].active {
                if let Some(scan_fn) = self.shrinkers[i].scan_fn {
                    freed += scan_fn(nr_to_scan);
                }
            }
        }
        freed
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut KERNEL_ALLOC: KernelAllocator = KernelAllocator::new();

fn kernel_alloc() -> &'static mut KernelAllocator {
    unsafe { &mut KERNEL_ALLOC }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_alloc_init(start_pfn: u32, end_pfn: u32) {
    kernel_alloc().init(start_pfn, end_pfn);
}

#[no_mangle]
pub extern "C" fn zxyphor_alloc_pages(order: u32, gfp: u32) -> i64 {
    match kernel_alloc().alloc_pages(order as usize, gfp) {
        Some(pfn) => pfn as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_free_pages(pfn: u32, order: u32) {
    kernel_alloc().free_pages(pfn, order as usize);
}

#[no_mangle]
pub extern "C" fn zxyphor_kmalloc(size: usize, gfp: u32) -> u64 {
    kernel_alloc().kmalloc(size, gfp).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn zxyphor_kfree(addr: u64, size: usize) {
    kernel_alloc().kfree(addr, size);
}

#[no_mangle]
pub extern "C" fn zxyphor_alloc_free_pages() -> u64 {
    kernel_alloc().stats.free_pages
}

#[no_mangle]
pub extern "C" fn zxyphor_alloc_total_pages() -> u64 {
    kernel_alloc().stats.total_pages
}

#[no_mangle]
pub extern "C" fn zxyphor_shrink_all(nr: u64) -> u64 {
    kernel_alloc().shrink_all(nr)
}
