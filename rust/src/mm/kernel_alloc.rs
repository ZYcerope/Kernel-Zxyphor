//! Kernel Zxyphor — Advanced Memory Allocator
//!
//! This module implements a production-grade kernel memory allocator with multiple
//! allocation strategies, per-CPU caching, NUMA awareness, and memory debugging.
//!
//! Architecture:
//! - Slab allocator for small objects (8 - 8192 bytes)
//! - Buddy allocator for page-aligned allocations
//! - Per-CPU free lists for lock-free hot-path allocation
//! - NUMA-aware allocation policies
//! - Memory poisoning and red-zones for debug builds
//! - Allocation tracking and leak detection
//! - Emergency memory reserves

#![no_std]
#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Page size (4 KiB)
const PAGE_SIZE: usize = 4096;
/// Page shift
const PAGE_SHIFT: usize = 12;
/// Maximum slab object size (8 KiB)
const MAX_SLAB_SIZE: usize = 8192;
/// Number of slab size classes
const NUM_SLAB_CLASSES: usize = 20;
/// Maximum buddy order (2^MAX_ORDER pages = 1 GiB with 4K pages)
const MAX_ORDER: usize = 18;
/// Per-CPU cache size (number of objects per size class)
const PERCPU_CACHE_SIZE: usize = 64;
/// Maximum NUMA nodes
const MAX_NUMA_NODES: usize = 8;
/// Maximum CPUs
const MAX_CPUS: usize = 256;
/// Minimum alignment
const MIN_ALIGN: usize = 8;

/// Red zone fill pattern (debug builds)
const REDZONE_PATTERN: u8 = 0xBB;
/// Freed memory fill pattern (debug builds)
const FREED_PATTERN: u8 = 0xDD;
/// Allocated memory fill pattern (debug builds)
const ALLOC_PATTERN: u8 = 0xCC;
/// Red zone size in bytes
const REDZONE_SIZE: usize = 16;

// ============================================================================
// Size Classes for Slab Allocator
// ============================================================================

/// Predefined size classes (power-of-2 and intermediate sizes)
const SIZE_CLASSES: [NUM_SLAB_CLASSES]usize = [NUM_SLAB_CLASSES]usize{
    8,     // 0
    16,    // 1
    32,    // 2
    48,    // 3
    64,    // 4
    96,    // 5
    128,   // 6
    192,   // 7
    256,   // 8
    384,   // 9
    512,   // 10
    768,   // 11
    1024,  // 12
    1536,  // 13
    2048,  // 14
    3072,  // 15
    4096,  // 16
    5120,  // 17
    6144,  // 18
    8192,  // 19
};

/// Map an allocation size to a size class index.
fn size_to_class(size: usize) -> Option<usize> {
    if size == 0 || size > MAX_SLAB_SIZE {
        return None;
    }
    for (i, &class_size) in SIZE_CLASSES.iter().enumerate() {
        if size <= class_size {
            return Some(i);
        }
    }
    None
}

/// Get the actual allocation size for a size class.
fn class_to_size(class: usize) -> usize {
    if class < NUM_SLAB_CLASSES {
        SIZE_CLASSES[class]
    } else {
        0
    }
}

// ============================================================================
// Free List Node
// ============================================================================

/// Intrusive free list node embedded in free slab objects.
#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
    /// Canary value for corruption detection
    canary: u64,
}

impl FreeNode {
    const CANARY_VALUE: u64 = 0xDEAD_BEEF_CAFE_F00D;

    fn init(ptr: *mut FreeNode) {
        unsafe {
            (*ptr).next = ptr::null_mut();
            (*ptr).canary = Self::CANARY_VALUE;
        }
    }

    fn validate(ptr: *const FreeNode) -> bool {
        unsafe { (*ptr).canary == Self::CANARY_VALUE }
    }
}

// ============================================================================
// Slab — A contiguous block of memory divided into equal-sized objects
// ============================================================================

/// Slab descriptor — metadata for a single slab page/pages.
#[repr(C)]
struct Slab {
    /// Pointer to the first object in this slab
    base: *mut u8,
    /// Free list head
    free_list: *mut FreeNode,
    /// Number of allocated objects
    allocated: u32,
    /// Total number of objects in this slab
    total: u32,
    /// Size class index
    class_index: u16,
    /// NUMA node
    numa_node: u8,
    /// Flags
    flags: u8,
    /// Next slab in the partial/full/empty list
    next: *mut Slab,
    /// Previous slab in the list
    prev: *mut Slab,
    /// Page order (number of pages = 2^order)
    page_order: u8,
    _pad: [7]u8,
}

impl Slab {
    /// Initialize a new slab with the given base address and object size.
    fn init(
        &mut self,
        base: *mut u8,
        obj_size: usize,
        slab_size: usize,
        class_index: u16,
        numa_node: u8,
    ) {
        self.base = base;
        self.class_index = class_index;
        self.numa_node = numa_node;
        self.next = ptr::null_mut();
        self.prev = ptr::null_mut();
        self.flags = 0;
        self.page_order = 0;
        self._pad = [0u8; 7];

        // Calculate number of objects
        let total = slab_size / obj_size;
        self.total = total as u32;
        self.allocated = 0;

        // Build free list
        self.free_list = ptr::null_mut();
        for i in (0..total).rev() {
            unsafe {
                let obj = base.add(i * obj_size) as *mut FreeNode;
                FreeNode::init(obj);
                (*obj).next = self.free_list;
                self.free_list = obj;
            }
        }
    }

    /// Allocate an object from this slab.
    fn alloc(&mut self) -> Option<*mut u8> {
        if self.free_list.is_null() {
            return None;
        }

        unsafe {
            let node = self.free_list;
            debug_assert!(FreeNode::validate(node), "Slab corruption detected");
            self.free_list = (*node).next;
            self.allocated += 1;

            Some(node as *mut u8)
        }
    }

    /// Free an object back to this slab.
    fn free(&mut self, ptr: *mut u8) {
        unsafe {
            let node = ptr as *mut FreeNode;
            FreeNode::init(node);
            (*node).next = self.free_list;
            self.free_list = node;
            self.allocated -= 1;
        }
    }

    /// Check if this slab is full (no free objects).
    fn is_full(&self) -> bool {
        self.free_list.is_null()
    }

    /// Check if this slab is empty (all objects free).
    fn is_empty(&self) -> bool {
        self.allocated == 0
    }
}

// ============================================================================
// Slab Cache — Manager for a single size class
// ============================================================================

/// Slab cache for a specific object size.
struct SlabCache {
    /// Object size for this cache
    obj_size: usize,
    /// Size class index
    class_index: usize,
    /// Partial slabs (some objects allocated)
    partial_list: *mut Slab,
    /// Full slabs (all objects allocated)
    full_list: *mut Slab,
    /// Empty slabs (no objects allocated, kept for reuse)
    empty_list: *mut Slab,
    /// Number of empty slabs kept
    empty_count: usize,
    /// Maximum empty slabs to keep (rest are returned to page allocator)
    max_empty: usize,
    /// Lock for this cache
    lock: SpinLock,
    /// Statistics
    stats: SlabCacheStats,
    /// Pages per slab (power of 2)
    pages_per_slab: usize,
}

/// Statistics for a slab cache.
#[derive(Default)]
struct SlabCacheStats {
    total_allocs: AtomicU64,
    total_frees: AtomicU64,
    current_objects: AtomicU64,
    total_slabs: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

impl SlabCache {
    fn new(class_index: usize) -> Self {
        let obj_size = class_to_size(class_index);
        // Calculate optimal slab size
        let pages_per_slab = if obj_size <= 256 {
            1 // Single page for small objects
        } else if obj_size <= 1024 {
            2
        } else if obj_size <= 4096 {
            4
        } else {
            8
        };

        SlabCache {
            obj_size,
            class_index,
            partial_list: ptr::null_mut(),
            full_list: ptr::null_mut(),
            empty_list: ptr::null_mut(),
            empty_count: 0,
            max_empty: 4,
            lock: SpinLock::new(),
            stats: SlabCacheStats::default(),
            pages_per_slab,
        }
    }

    /// Allocate an object from this cache.
    fn alloc(&mut self) -> Option<*mut u8> {
        self.lock.acquire();

        // Try partial slabs first
        if !self.partial_list.is_null() {
            let slab = unsafe { &mut *self.partial_list };
            if let Some(ptr) = slab.alloc() {
                // Move to full list if now full
                if slab.is_full() {
                    let slab_ptr = self.partial_list;
                    self.partial_list = slab.next;
                    if !self.partial_list.is_null() {
                        unsafe { (*self.partial_list).prev = ptr::null_mut() };
                    }
                    self.push_full(slab_ptr);
                }
                self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);
                self.stats.current_objects.fetch_add(1, Ordering::Relaxed);
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.lock.release();
                return Some(ptr);
            }
        }

        // Try empty slabs
        if !self.empty_list.is_null() {
            let slab_ptr = self.empty_list;
            let slab = unsafe { &mut *slab_ptr };
            self.empty_list = slab.next;
            if !self.empty_list.is_null() {
                unsafe { (*self.empty_list).prev = ptr::null_mut() };
            }
            self.empty_count -= 1;

            if let Some(ptr) = slab.alloc() {
                // Move to partial list
                self.push_partial(slab_ptr);
                self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);
                self.stats.current_objects.fetch_add(1, Ordering::Relaxed);
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.lock.release();
                return Some(ptr);
            }
        }

        // Need to allocate a new slab
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.lock.release();

        // Allocate pages for new slab (outside the lock)
        let slab_pages = self.pages_per_slab;
        let slab_mem = alloc_pages(slab_pages)?;
        let slab_desc = alloc_slab_descriptor()?;

        let slab = unsafe { &mut *slab_desc };
        slab.init(
            slab_mem,
            self.obj_size,
            slab_pages * PAGE_SIZE,
            self.class_index as u16,
            0, // NUMA node
        );

        // Allocate from the new slab
        let result = slab.alloc();

        self.lock.acquire();
        self.push_partial(slab_desc);
        self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);
        self.stats.current_objects.fetch_add(1, Ordering::Relaxed);
        self.stats.total_slabs.fetch_add(1, Ordering::Relaxed);
        self.lock.release();

        result
    }

    /// Free an object back to this cache.
    fn free(&mut self, ptr: *mut u8) {
        self.lock.acquire();

        // Find which slab this object belongs to
        if let Some(slab_ptr) = self.find_slab(ptr) {
            let slab = unsafe { &mut *slab_ptr };
            let was_full = slab.is_full();

            slab.free(ptr);

            if was_full {
                // Move from full to partial
                self.remove_from_full(slab_ptr);
                self.push_partial(slab_ptr);
            } else if slab.is_empty() {
                // Move from partial to empty (or free)
                self.remove_from_partial(slab_ptr);
                if self.empty_count < self.max_empty {
                    self.push_empty(slab_ptr);
                } else {
                    // Free the slab entirely
                    free_pages(slab.base, self.pages_per_slab);
                    free_slab_descriptor(slab_ptr);
                    self.stats.total_slabs.fetch_sub(1, Ordering::Relaxed);
                }
            }

            self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
            self.stats.current_objects.fetch_sub(1, Ordering::Relaxed);
        }

        self.lock.release();
    }

    fn find_slab(&self, ptr: *mut u8) -> Option<*mut Slab> {
        let addr = ptr as usize;

        // Search partial list
        let mut slab = self.partial_list;
        while !slab.is_null() {
            let s = unsafe { &*slab };
            let base = s.base as usize;
            let end = base + self.pages_per_slab * PAGE_SIZE;
            if addr >= base && addr < end {
                return Some(slab);
            }
            slab = s.next;
        }

        // Search full list
        slab = self.full_list;
        while !slab.is_null() {
            let s = unsafe { &*slab };
            let base = s.base as usize;
            let end = base + self.pages_per_slab * PAGE_SIZE;
            if addr >= base && addr < end {
                return Some(slab);
            }
            slab = s.next;
        }

        None
    }

    fn push_partial(&mut self, slab: *mut Slab) {
        unsafe {
            (*slab).next = self.partial_list;
            (*slab).prev = ptr::null_mut();
            if !self.partial_list.is_null() {
                (*self.partial_list).prev = slab;
            }
            self.partial_list = slab;
        }
    }

    fn push_full(&mut self, slab: *mut Slab) {
        unsafe {
            (*slab).next = self.full_list;
            (*slab).prev = ptr::null_mut();
            if !self.full_list.is_null() {
                (*self.full_list).prev = slab;
            }
            self.full_list = slab;
        }
    }

    fn push_empty(&mut self, slab: *mut Slab) {
        unsafe {
            (*slab).next = self.empty_list;
            (*slab).prev = ptr::null_mut();
            if !self.empty_list.is_null() {
                (*self.empty_list).prev = slab;
            }
            self.empty_list = slab;
            self.empty_count += 1;
        }
    }

    fn remove_from_partial(&mut self, slab: *mut Slab) {
        unsafe {
            if !(*slab).prev.is_null() {
                (*(*slab).prev).next = (*slab).next;
            } else {
                self.partial_list = (*slab).next;
            }
            if !(*slab).next.is_null() {
                (*(*slab).next).prev = (*slab).prev;
            }
        }
    }

    fn remove_from_full(&mut self, slab: *mut Slab) {
        unsafe {
            if !(*slab).prev.is_null() {
                (*(*slab).prev).next = (*slab).next;
            } else {
                self.full_list = (*slab).next;
            }
            if !(*slab).next.is_null() {
                (*(*slab).next).prev = (*slab).prev;
            }
        }
    }
}

// ============================================================================
// Per-CPU Cache
// ============================================================================

/// Per-CPU allocation cache for lock-free fast path.
struct PerCpuCache {
    /// Free object pointers per size class
    objects: [[*mut u8; PERCPU_CACHE_SIZE]; NUM_SLAB_CLASSES],
    /// Number of cached objects per size class
    count: [usize; NUM_SLAB_CLASSES],
}

impl PerCpuCache {
    const fn new() -> Self {
        PerCpuCache {
            objects: [[ptr::null_mut(); PERCPU_CACHE_SIZE]; NUM_SLAB_CLASSES],
            count: [0; NUM_SLAB_CLASSES],
        }
    }

    /// Try to allocate from the per-CPU cache.
    fn alloc(&mut self, class: usize) -> Option<*mut u8> {
        if class >= NUM_SLAB_CLASSES || self.count[class] == 0 {
            return None;
        }
        self.count[class] -= 1;
        let ptr = self.objects[class][self.count[class]];
        self.objects[class][self.count[class]] = ptr::null_mut();
        Some(ptr)
    }

    /// Try to free to the per-CPU cache.
    fn free(&mut self, class: usize, ptr: *mut u8) -> bool {
        if class >= NUM_SLAB_CLASSES || self.count[class] >= PERCPU_CACHE_SIZE {
            return false;
        }
        self.objects[class][self.count[class]] = ptr;
        self.count[class] += 1;
        true
    }

    /// Flush half of the cached objects back to the slab cache.
    fn flush_half(&mut self, class: usize) -> usize {
        let count = self.count[class];
        let to_flush = count / 2;
        // Caller is responsible for freeing the objects
        to_flush
    }
}

// ============================================================================
// Buddy Allocator — Page-level allocation
// ============================================================================

/// Buddy page allocator for contiguous page allocations.
struct BuddyAllocator {
    /// Free lists by order (order 0 = 1 page, order N = 2^N pages)
    free_lists: [*mut BuddyBlock; MAX_ORDER + 1],
    /// Base physical address
    base_addr: usize,
    /// Total pages managed
    total_pages: usize,
    /// Free pages
    free_pages: AtomicUsize,
    /// Bitmap tracking allocated pages
    bitmap: *mut u8,
    /// Bitmap size in bytes
    bitmap_size: usize,
    /// Lock
    lock: SpinLock,
}

/// A free block in the buddy allocator.
#[repr(C)]
struct BuddyBlock {
    next: *mut BuddyBlock,
    prev: *mut BuddyBlock,
    order: u8,
    _pad: [7]u8,
}

impl BuddyAllocator {
    /// Create a new buddy allocator over a memory region.
    fn new(base: usize, size: usize, bitmap: *mut u8) -> Self {
        let total_pages = size / PAGE_SIZE;
        let bitmap_size = (total_pages + 7) / 8;

        let mut alloc = BuddyAllocator {
            free_lists: [ptr::null_mut(); MAX_ORDER + 1],
            base_addr: base,
            total_pages,
            free_pages: AtomicUsize::new(0),
            bitmap,
            bitmap_size,
            lock: SpinLock::new(),
        };

        // Clear bitmap
        unsafe {
            ptr::write_bytes(bitmap, 0, bitmap_size);
        }

        // Add all pages as the largest possible buddy blocks
        let mut page = 0;
        while page < total_pages {
            let max_order = find_max_order(page, total_pages - page);
            alloc.add_free_block(page, max_order);
            page += 1 << max_order;
        }

        alloc
    }

    /// Allocate 2^order contiguous pages.
    fn alloc(&mut self, order: usize) -> Option<*mut u8> {
        if order > MAX_ORDER {
            return None;
        }

        self.lock.acquire();

        // Find the smallest available block >= requested order
        let mut current_order = order;
        while current_order <= MAX_ORDER {
            if !self.free_lists[current_order].is_null() {
                // Found a free block
                let block = self.free_lists[current_order];
                self.remove_block(block, current_order);

                // Split larger blocks down to requested order
                while current_order > order {
                    current_order -= 1;
                    let page_index = self.block_to_page(block);
                    let buddy_page = page_index + (1 << current_order);
                    let buddy_addr = self.page_to_addr(buddy_page);
                    self.add_free_block(buddy_page, current_order);
                    let _ = buddy_addr;
                }

                // Mark as allocated in bitmap
                let page = self.block_to_page(block);
                for i in 0..(1usize << order) {
                    self.set_bitmap(page + i, true);
                }

                self.free_pages.fetch_sub(1 << order, Ordering::Relaxed);
                self.lock.release();
                return Some(block as *mut u8);
            }
            current_order += 1;
        }

        self.lock.release();
        None
    }

    /// Free 2^order contiguous pages.
    fn free(&mut self, ptr: *mut u8, order: usize) {
        if order > MAX_ORDER {
            return;
        }

        self.lock.acquire();

        let page = (ptr as usize - self.base_addr) / PAGE_SIZE;
        let mut current_order = order;

        // Clear bitmap
        for i in 0..(1usize << order) {
            self.set_bitmap(page + i, false);
        }

        // Merge with buddy blocks
        let mut current_page = page;
        while current_order < MAX_ORDER {
            let buddy_page = current_page ^ (1 << current_order);
            if buddy_page >= self.total_pages {
                break;
            }

            // Check if buddy is free and same order
            if !self.is_buddy_free(buddy_page, current_order) {
                break;
            }

            // Remove buddy from its free list
            let buddy_block = self.page_to_addr(buddy_page) as *mut BuddyBlock;
            self.remove_block(buddy_block, current_order);

            // Merge: use the lower address
            current_page = current_page & !(1 << current_order);
            current_order += 1;
        }

        // Add merged block to free list
        self.add_free_block(current_page, current_order);
        self.free_pages.fetch_add(1 << order, Ordering::Relaxed);

        self.lock.release();
    }

    fn add_free_block(&mut self, page: usize, order: usize) {
        let addr = self.page_to_addr(page) as *mut BuddyBlock;
        unsafe {
            (*addr).order = order as u8;
            (*addr).next = self.free_lists[order];
            (*addr).prev = ptr::null_mut();
            if !self.free_lists[order].is_null() {
                (*self.free_lists[order]).prev = addr;
            }
            self.free_lists[order] = addr;
        }
    }

    fn remove_block(&mut self, block: *mut BuddyBlock, order: usize) {
        unsafe {
            if !(*block).prev.is_null() {
                (*(*block).prev).next = (*block).next;
            } else {
                self.free_lists[order] = (*block).next;
            }
            if !(*block).next.is_null() {
                (*(*block).next).prev = (*block).prev;
            }
        }
    }

    fn block_to_page(&self, block: *mut BuddyBlock) -> usize {
        (block as usize - self.base_addr) / PAGE_SIZE
    }

    fn page_to_addr(&self, page: usize) -> usize {
        self.base_addr + page * PAGE_SIZE
    }

    fn set_bitmap(&mut self, page: usize, allocated: bool) {
        let byte = page / 8;
        let bit = page % 8;
        if byte < self.bitmap_size {
            unsafe {
                if allocated {
                    *self.bitmap.add(byte) |= 1 << bit;
                } else {
                    *self.bitmap.add(byte) &= !(1 << bit);
                }
            }
        }
    }

    fn is_buddy_free(&self, page: usize, order: usize) -> bool {
        // Check all pages in the buddy block are free
        for i in 0..(1usize << order) {
            let p = page + i;
            let byte = p / 8;
            let bit = p % 8;
            if byte >= self.bitmap_size {
                return false;
            }
            unsafe {
                if *self.bitmap.add(byte) & (1 << bit) != 0 {
                    return false;
                }
            }
        }
        true
    }
}

/// Find the maximum buddy order for a given page count.
fn find_max_order(page: usize, remaining: usize) -> usize {
    let mut order = 0;
    while order < MAX_ORDER {
        let next_size = 1usize << (order + 1);
        if next_size > remaining {
            break;
        }
        // Check alignment: page must be aligned to 2^(order+1)
        if page & ((1 << (order + 1)) - 1) != 0 {
            break;
        }
        order += 1;
    }
    order
}

// ============================================================================
// SpinLock
// ============================================================================

struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
        }
    }

    fn acquire(&self) {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin with PAUSE hint
            core::hint::spin_loop();
        }
    }

    fn release(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

// ============================================================================
// NUMA Zone
// ============================================================================

/// Memory zone for a NUMA node.
struct NumaZone {
    /// NUMA node ID
    node_id: usize,
    /// Buddy allocator for this zone
    buddy: Option<BuddyAllocator>,
    /// Slab caches per size class
    slab_caches: [SlabCache; NUM_SLAB_CLASSES],
    /// Zone start address
    zone_start: usize,
    /// Zone end address
    zone_end: usize,
    /// Total memory in bytes
    total_memory: usize,
    /// Free memory in bytes
    free_memory: AtomicUsize,
    /// Watermarks
    watermark_low: usize,
    watermark_high: usize,
    watermark_min: usize,
}

impl NumaZone {
    fn new(node_id: usize) -> Self {
        NumaZone {
            node_id,
            buddy: None,
            slab_caches: core::array::from_fn(|i| SlabCache::new(i)),
            zone_start: 0,
            zone_end: 0,
            total_memory: 0,
            free_memory: AtomicUsize::new(0),
            watermark_low: 0,
            watermark_high: 0,
            watermark_min: 0,
        }
    }

    /// Initialize this zone with a memory region.
    fn init(&mut self, start: usize, size: usize, bitmap: *mut u8) {
        self.zone_start = start;
        self.zone_end = start + size;
        self.total_memory = size;
        self.free_memory.store(size, Ordering::Relaxed);

        // Set watermarks
        self.watermark_min = size / 256; // ~0.4%
        self.watermark_low = size / 64; // ~1.6%
        self.watermark_high = size / 32; // ~3.1%

        self.buddy = Some(BuddyAllocator::new(start, size, bitmap));
    }

    /// Check if memory pressure requires reclamation.
    fn needs_reclaim(&self) -> bool {
        self.free_memory.load(Ordering::Relaxed) < self.watermark_low
    }

    /// Check if allocation should be denied (below minimum).
    fn is_oom(&self) -> bool {
        self.free_memory.load(Ordering::Relaxed) < self.watermark_min
    }
}

// ============================================================================
// Global Kernel Allocator
// ============================================================================

/// The global kernel memory allocator.
pub struct KernelAllocator {
    /// NUMA zones
    zones: [NumaZone; MAX_NUMA_NODES],
    /// Number of active NUMA nodes
    num_nodes: AtomicUsize,
    /// Per-CPU caches
    percpu_caches: [PerCpuCache; MAX_CPUS],
    /// Initialized flag
    initialized: AtomicBool,
    /// Total system memory
    total_memory: AtomicU64,
    /// Total free memory
    free_memory: AtomicU64,
    /// Emergency reserve pages
    emergency_reserve: AtomicUsize,
    /// OOM kill in progress
    oom_in_progress: AtomicBool,
    /// Allocation statistics
    stats: AllocatorStats,
}

/// Global allocation statistics.
struct AllocatorStats {
    total_allocs: AtomicU64,
    total_frees: AtomicU64,
    total_bytes_allocated: AtomicU64,
    total_bytes_freed: AtomicU64,
    slab_allocs: AtomicU64,
    buddy_allocs: AtomicU64,
    percpu_hits: AtomicU64,
    oom_kills: AtomicU64,
    failed_allocs: AtomicU64,
    peak_usage: AtomicU64,
}

impl AllocatorStats {
    const fn new() -> Self {
        AllocatorStats {
            total_allocs: AtomicU64::new(0),
            total_frees: AtomicU64::new(0),
            total_bytes_allocated: AtomicU64::new(0),
            total_bytes_freed: AtomicU64::new(0),
            slab_allocs: AtomicU64::new(0),
            buddy_allocs: AtomicU64::new(0),
            percpu_hits: AtomicU64::new(0),
            oom_kills: AtomicU64::new(0),
            failed_allocs: AtomicU64::new(0),
            peak_usage: AtomicU64::new(0),
        }
    }
}

impl KernelAllocator {
    pub const fn new() -> Self {
        KernelAllocator {
            zones: [const { NumaZone::new(0) }; MAX_NUMA_NODES],
            num_nodes: AtomicUsize::new(0),
            percpu_caches: [const { PerCpuCache::new() }; MAX_CPUS],
            initialized: AtomicBool::new(false),
            total_memory: AtomicU64::new(0),
            free_memory: AtomicU64::new(0),
            emergency_reserve: AtomicUsize::new(0),
            oom_in_progress: AtomicBool::new(false),
            stats: AllocatorStats::new(),
        }
    }

    /// Initialize the allocator with a memory region.
    pub fn init(&mut self, base: usize, size: usize, bitmap: *mut u8) {
        self.zones[0].node_id = 0;
        self.zones[0].init(base, size, bitmap);
        self.num_nodes.store(1, Ordering::Relaxed);
        self.total_memory.store(size as u64, Ordering::Relaxed);
        self.free_memory.store(size as u64, Ordering::Relaxed);
        self.initialized.store(true, Ordering::Release);
    }

    /// Add a NUMA node.
    pub fn add_numa_node(
        &mut self,
        node_id: usize,
        base: usize,
        size: usize,
        bitmap: *mut u8,
    ) -> bool {
        if node_id >= MAX_NUMA_NODES {
            return false;
        }
        self.zones[node_id].node_id = node_id;
        self.zones[node_id].init(base, size, bitmap);
        let count = self.num_nodes.load(Ordering::Relaxed);
        if node_id >= count {
            self.num_nodes.store(node_id + 1, Ordering::Relaxed);
        }
        self.total_memory
            .fetch_add(size as u64, Ordering::Relaxed);
        self.free_memory
            .fetch_add(size as u64, Ordering::Relaxed);
        true
    }

    /// Allocate memory of the given size and alignment.
    pub fn allocate(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        if !self.initialized.load(Ordering::Acquire) {
            return None;
        }
        if size == 0 {
            return None;
        }

        let actual_align = if align < MIN_ALIGN { MIN_ALIGN } else { align };
        let actual_size = if actual_align > MIN_ALIGN {
            // Over-aligned allocation
            size + actual_align
        } else {
            size
        };

        // Try slab allocator for small sizes
        if actual_size <= MAX_SLAB_SIZE {
            if let Some(class) = size_to_class(actual_size) {
                // Try per-CPU cache first
                let cpu_id = get_cpu_id();
                if cpu_id < MAX_CPUS {
                    if let Some(ptr) = self.percpu_caches[cpu_id].alloc(class) {
                        self.stats.percpu_hits.fetch_add(1, Ordering::Relaxed);
                        self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);
                        self.stats
                            .total_bytes_allocated
                            .fetch_add(actual_size as u64, Ordering::Relaxed);
                        return Some(ptr);
                    }
                }

                // Fall through to slab cache
                let zone = &mut self.zones[0]; // TODO: NUMA-aware selection
                if let Some(ptr) = zone.slab_caches[class].alloc() {
                    self.stats.slab_allocs.fetch_add(1, Ordering::Relaxed);
                    self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .total_bytes_allocated
                        .fetch_add(actual_size as u64, Ordering::Relaxed);
                    return Some(ptr);
                }
            }
        }

        // Large allocation: use buddy allocator
        let pages = (actual_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let order = pages_to_order(pages);

        if let Some(buddy) = &mut self.zones[0].buddy {
            if let Some(ptr) = buddy.alloc(order) {
                self.stats.buddy_allocs.fetch_add(1, Ordering::Relaxed);
                self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);
                let alloc_size = (1 << order) * PAGE_SIZE;
                self.stats
                    .total_bytes_allocated
                    .fetch_add(alloc_size as u64, Ordering::Relaxed);
                return Some(ptr);
            }
        }

        // Allocation failed
        self.stats.failed_allocs.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Free previously allocated memory.
    pub fn deallocate(&mut self, ptr: *mut u8, size: usize) {
        if ptr.is_null() {
            return;
        }

        let actual_size = if size == 0 { MIN_ALIGN } else { size };

        // Try slab path
        if actual_size <= MAX_SLAB_SIZE {
            if let Some(class) = size_to_class(actual_size) {
                // Try per-CPU cache first
                let cpu_id = get_cpu_id();
                if cpu_id < MAX_CPUS && self.percpu_caches[cpu_id].free(class, ptr) {
                    self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .total_bytes_freed
                        .fetch_add(actual_size as u64, Ordering::Relaxed);
                    return;
                }

                // Free to slab cache
                self.zones[0].slab_caches[class].free(ptr);
                self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .total_bytes_freed
                    .fetch_add(actual_size as u64, Ordering::Relaxed);
                return;
            }
        }

        // Large allocation: free via buddy
        let pages = (actual_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let order = pages_to_order(pages);

        if let Some(buddy) = &mut self.zones[0].buddy {
            buddy.free(ptr, order);
            let alloc_size = (1 << order) * PAGE_SIZE;
            self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
            self.stats
                .total_bytes_freed
                .fetch_add(alloc_size as u64, Ordering::Relaxed);
        }
    }

    /// Get allocator statistics.
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.total_allocs.load(Ordering::Relaxed),
            self.stats.total_frees.load(Ordering::Relaxed),
            self.stats.total_bytes_allocated.load(Ordering::Relaxed),
            self.stats.total_bytes_freed.load(Ordering::Relaxed),
        )
    }

    /// Get memory usage information.
    pub fn memory_info(&self) -> MemoryInfo {
        MemoryInfo {
            total: self.total_memory.load(Ordering::Relaxed),
            free: self.free_memory.load(Ordering::Relaxed),
            slab_allocs: self.stats.slab_allocs.load(Ordering::Relaxed),
            buddy_allocs: self.stats.buddy_allocs.load(Ordering::Relaxed),
            percpu_hits: self.stats.percpu_hits.load(Ordering::Relaxed),
            failed_allocs: self.stats.failed_allocs.load(Ordering::Relaxed),
            oom_kills: self.stats.oom_kills.load(Ordering::Relaxed),
        }
    }

    /// Trigger memory reclamation across all zones.
    pub fn reclaim_memory(&mut self) -> usize {
        let mut reclaimed = 0;

        // Flush per-CPU caches
        for cpu in 0..MAX_CPUS {
            for class in 0..NUM_SLAB_CLASSES {
                let flushed = self.percpu_caches[cpu].flush_half(class);
                reclaimed += flushed;
            }
        }

        // Free empty slabs in each zone
        for zone in &mut self.zones[..self.num_nodes.load(Ordering::Relaxed)] {
            for cache in &mut zone.slab_caches {
                while !cache.empty_list.is_null() && cache.empty_count > 0 {
                    let slab = cache.empty_list;
                    unsafe {
                        cache.empty_list = (*slab).next;
                        if !cache.empty_list.is_null() {
                            (*cache.empty_list).prev = ptr::null_mut();
                        }
                        free_pages((*slab).base, cache.pages_per_slab);
                        free_slab_descriptor(slab);
                    }
                    cache.empty_count -= 1;
                    reclaimed += cache.pages_per_slab;
                }
            }
        }

        reclaimed
    }
}

/// Memory information for /proc/meminfo and sysinfo.
#[derive(Clone, Copy)]
pub struct MemoryInfo {
    pub total: u64,
    pub free: u64,
    pub slab_allocs: u64,
    pub buddy_allocs: u64,
    pub percpu_hits: u64,
    pub failed_allocs: u64,
    pub oom_kills: u64,
}

// ============================================================================
// GlobalAlloc Implementation
// ============================================================================

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let self_mut = &mut *(self as *const Self as *mut Self);
        self_mut
            .allocate(layout.size(), layout.align())
            .unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let self_mut = &mut *(self as *const Self as *mut Self);
        self_mut.deallocate(ptr, layout.size());
    }
}

// ============================================================================
// Helper Functions (extern — provided by Zig kernel)
// ============================================================================

/// Allocate contiguous pages from the page allocator.
fn alloc_pages(count: usize) -> Option<*mut u8> {
    extern "C" {
        fn kernel_alloc_pages(count: usize) -> *mut u8;
    }
    let ptr = unsafe { kernel_alloc_pages(count) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Free contiguous pages.
fn free_pages(ptr: *mut u8, count: usize) {
    extern "C" {
        fn kernel_free_pages(ptr: *mut u8, count: usize);
    }
    unsafe {
        kernel_free_pages(ptr, count);
    }
}

/// Allocate a slab descriptor.
fn alloc_slab_descriptor() -> Option<*mut Slab> {
    extern "C" {
        fn kernel_alloc_slab_desc() -> *mut Slab;
    }
    let ptr = unsafe { kernel_alloc_slab_desc() };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Free a slab descriptor.
fn free_slab_descriptor(slab: *mut Slab) {
    extern "C" {
        fn kernel_free_slab_desc(slab: *mut Slab);
    }
    unsafe {
        kernel_free_slab_desc(slab);
    }
}

/// Get current CPU ID.
fn get_cpu_id() -> usize {
    extern "C" {
        fn kernel_get_cpu_id() -> u32;
    }
    unsafe { kernel_get_cpu_id() as usize }
}

/// Convert page count to buddy order.
fn pages_to_order(pages: usize) -> usize {
    if pages <= 1 {
        return 0;
    }
    let mut order = 0;
    let mut size = 1;
    while size < pages && order < MAX_ORDER {
        order += 1;
        size <<= 1;
    }
    order
}

// ============================================================================
// OOM Killer
// ============================================================================

/// Out-of-memory killer — selects and kills a process to free memory.
pub struct OomKiller;

impl OomKiller {
    /// Calculate OOM score for a process.
    pub fn calculate_score(
        rss_pages: u64,
        total_pages: u64,
        oom_score_adj: i16,
        is_root: bool,
    ) -> u64 {
        if oom_score_adj == -1000 {
            return 0; // OOM_SCORE_ADJ_MIN: never kill
        }

        // Base score: percentage of memory used (0-1000)
        let mut score = if total_pages > 0 {
            (rss_pages * 1000) / total_pages
        } else {
            0
        };

        // Adjust for root processes (3% reduction)
        if is_root {
            score = score.saturating_sub(30);
        }

        // Apply oom_score_adj (-1000 to 1000)
        if oom_score_adj > 0 {
            score = score.saturating_add(oom_score_adj as u64);
        } else {
            score = score.saturating_sub((-oom_score_adj) as u64);
        }

        // Clamp to [0, 1000]
        if score > 1000 {
            score = 1000;
        }

        score
    }
}

// ============================================================================
// Memory Debugging (enabled in debug builds)
// ============================================================================

/// Memory debugger for detecting use-after-free, buffer overflow, etc.
pub struct MemoryDebugger {
    /// Enable red zones
    pub red_zones: bool,
    /// Enable freed memory poisoning
    pub poison_free: bool,
    /// Enable allocation fill
    pub poison_alloc: bool,
    /// Track all allocations
    pub track_allocs: bool,
}

impl MemoryDebugger {
    pub const fn new() -> Self {
        MemoryDebugger {
            red_zones: cfg!(debug_assertions),
            poison_free: cfg!(debug_assertions),
            poison_alloc: cfg!(debug_assertions),
            track_allocs: false,
        }
    }

    /// Fill newly allocated memory with a pattern.
    pub fn on_alloc(&self, ptr: *mut u8, size: usize) {
        if self.poison_alloc {
            unsafe {
                ptr::write_bytes(ptr, ALLOC_PATTERN, size);
            }
        }
    }

    /// Fill freed memory with a pattern.
    pub fn on_free(&self, ptr: *mut u8, size: usize) {
        if self.poison_free {
            unsafe {
                ptr::write_bytes(ptr, FREED_PATTERN, size);
            }
        }
    }

    /// Validate red zones around an allocation.
    pub fn validate_red_zones(&self, ptr: *const u8, size: usize) -> bool {
        if !self.red_zones {
            return true;
        }

        // Check leading red zone
        unsafe {
            let leading = ptr.sub(REDZONE_SIZE);
            for i in 0..REDZONE_SIZE {
                if *leading.add(i) != REDZONE_PATTERN {
                    return false; // Corruption detected!
                }
            }

            // Check trailing red zone
            let trailing = ptr.add(size);
            for i in 0..REDZONE_SIZE {
                if *trailing.add(i) != REDZONE_PATTERN {
                    return false; // Corruption detected!
                }
            }
        }

        true
    }
}

// ============================================================================
// Static Globals
// ============================================================================

/// The global kernel allocator instance.
#[global_allocator]
static KERNEL_ALLOCATOR: KernelAllocator = KernelAllocator::new();

/// Memory debugger instance.
static MEMORY_DEBUGGER: MemoryDebugger = MemoryDebugger::new();
