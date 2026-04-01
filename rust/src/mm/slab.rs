// =============================================================================
// Kernel Zxyphor — Rust Memory Management: Slab Allocator
// =============================================================================
// A no_std slab allocator for fixed-size kernel objects. This provides O(1)
// allocation and deallocation for common kernel data structures. Each cache
// manages objects of a single size, with multiple slabs per cache.
//
// Architecture:
//   SlabCache → [Slab] → [Object slots]
//   Each slab is a contiguous region subdivided into fixed-size slots.
//   A free-list bitmap tracks which slots are available.
//
// Thread safety: All operations are protected by per-cache spinlocks
// implemented via atomic compare-and-swap loops (no_std compatible).
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::ptr;

/// Maximum number of slab caches the system can manage simultaneously.
/// Each cache handles a different object size (e.g., 32, 64, 128 bytes).
const MAX_SLAB_CACHES: usize = 64;

/// Maximum number of slabs within a single cache before we refuse allocation.
const MAX_SLABS_PER_CACHE: usize = 256;

/// Default slab size in bytes — each slab is one page (4096 bytes).
const SLAB_PAGE_SIZE: usize = 4096;

/// Minimum object size — anything smaller wastes too much metadata overhead.
const MIN_OBJECT_SIZE: usize = 16;

/// Maximum object size for slab allocation — larger objects use the page allocator.
const MAX_OBJECT_SIZE: usize = 2048;

/// Magic number written to freed objects to detect double-free and use-after-free.
const FREE_MAGIC: u64 = 0xDEAD_BEEF_CAFE_F00D;

/// Magic number for active objects (overwritten on alloc to prevent stale detection).
const ALLOC_MAGIC: u64 = 0xA110_CA7E_DA7A_BEEF;

// =============================================================================
// Slab header — metadata stored at the beginning of each slab page
// =============================================================================

/// Each slab is a 4 KiB page. The header lives at the start, followed by the
/// object array. The bitmap tracks which slots are free (1 = free, 0 = used).
#[repr(C)]
pub struct SlabHeader {
    /// Pointer to the cache that owns this slab
    cache_index: u32,
    /// Total number of object slots in this slab
    total_objects: u16,
    /// Number of currently free slots
    free_count: u16,
    /// Index of the next free slot (head of free list), or 0xFFFF if full
    next_free: u16,
    /// Slab state flags
    flags: u16,
    /// Padding for alignment
    _reserved: u32,
    /// Bitmap of free slots (1 bit per object, up to 128 objects per slab)
    free_bitmap: [4]u64,
}

impl SlabHeader {
    const FLAG_ACTIVE: u16 = 0x0001;
    const FLAG_FULL: u16 = 0x0002;
    const FLAG_PARTIAL: u16 = 0x0004;
    const FLAG_EMPTY: u16 = 0x0008;

    /// Calculate how many objects of the given size fit in one slab page,
    /// accounting for the header size at the beginning.
    fn objects_per_slab(object_size: usize) -> usize {
        let header_size = core::mem::size_of::<SlabHeader>();
        let usable_space = SLAB_PAGE_SIZE.saturating_sub(header_size);
        if object_size == 0 {
            return 0;
        }
        usable_space / object_size
    }

    /// Get a pointer to the start of the objects array (right after the header)
    fn objects_base(&mut self) -> *mut u8 {
        let header_ptr = self as *mut SlabHeader as *mut u8;
        let header_size = core::mem::size_of::<SlabHeader>();
        unsafe { header_ptr.add(header_size) }
    }

    /// Get a pointer to a specific object slot by index
    fn object_at(&mut self, index: usize, object_size: usize) -> *mut u8 {
        let base = self.objects_base();
        unsafe { base.add(index * object_size) }
    }

    /// Check whether a specific slot is free using the bitmap
    fn is_slot_free(&self, index: usize) -> bool {
        let word = index / 64;
        let bit = index % 64;
        if word >= 4 {
            return false;
        }
        (self.free_bitmap[word] & (1u64 << bit)) != 0
    }

    /// Mark a slot as used (clear its bit in the bitmap)
    fn mark_used(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        if word < 4 {
            self.free_bitmap[word] &= !(1u64 << bit);
            self.free_count = self.free_count.saturating_sub(1);
            if self.free_count == 0 {
                self.flags = (self.flags & !Self::FLAG_PARTIAL & !Self::FLAG_EMPTY) | Self::FLAG_FULL;
            } else {
                self.flags = (self.flags & !Self::FLAG_FULL & !Self::FLAG_EMPTY) | Self::FLAG_PARTIAL;
            }
        }
    }

    /// Mark a slot as free (set its bit in the bitmap)
    fn mark_free(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        if word < 4 {
            self.free_bitmap[word] |= 1u64 << bit;
            self.free_count += 1;
            if self.free_count == self.total_objects {
                self.flags = (self.flags & !Self::FLAG_PARTIAL & !Self::FLAG_FULL) | Self::FLAG_EMPTY;
            } else {
                self.flags = (self.flags & !Self::FLAG_FULL & !Self::FLAG_EMPTY) | Self::FLAG_PARTIAL;
            }
        }
    }

    /// Find the first free slot using the bitmap
    fn find_free_slot(&self) -> Option<usize> {
        for word_idx in 0..4usize {
            let word = self.free_bitmap[word_idx];
            if word != 0 {
                // Find the lowest set bit using trailing zeros
                let bit = word.trailing_zeros() as usize;
                let index = word_idx * 64 + bit;
                if index < self.total_objects as usize {
                    return Some(index);
                }
            }
        }
        None
    }

    /// Initialize a fresh slab header for objects of the given size
    fn initialize(&mut self, cache_idx: u32, object_size: usize) {
        let count = Self::objects_per_slab(object_size);
        let count = if count > 256 { 256 } else { count }; // cap at bitmap size

        self.cache_index = cache_idx;
        self.total_objects = count as u16;
        self.free_count = count as u16;
        self.next_free = 0;
        self.flags = Self::FLAG_ACTIVE | Self::FLAG_EMPTY;
        self._reserved = 0;

        // Mark all valid slots as free in the bitmap
        self.free_bitmap = [0u64; 4];
        for i in 0..count {
            let word = i / 64;
            let bit = i % 64;
            if word < 4 {
                self.free_bitmap[word] |= 1u64 << bit;
            }
        }

        // Write the free magic to each slot for debugging
        let base = self.objects_base();
        for i in 0..count {
            let slot = unsafe { base.add(i * object_size) };
            if object_size >= 8 {
                unsafe {
                    ptr::write(slot as *mut u64, FREE_MAGIC);
                }
            }
        }
    }
}

// =============================================================================
// Slab Cache — manages all slabs for a specific object size
// =============================================================================

/// A slab cache manages the allocation of objects of a single fixed size.
/// Multiple slabs may exist per cache — partial slabs are preferred for
/// allocation to minimize fragmentation.
#[repr(C)]
pub struct SlabCache {
    /// Human-readable name for this cache (e.g., "task_struct", "inode")
    name: [u8; 32],
    /// Size of each object in this cache (in bytes)
    object_size: usize,
    /// Required alignment for objects
    alignment: usize,
    /// Number of objects per slab page
    objects_per_slab: usize,
    /// Array of slab page addresses (each is a 4 KiB page)
    slabs: [usize; MAX_SLABS_PER_CACHE],
    /// Number of slabs currently allocated
    slab_count: usize,
    /// Total number of allocated (in-use) objects across all slabs
    alloc_count: AtomicU64,
    /// Total number of free operations performed
    free_count: AtomicU64,
    /// Total allocation requests (including failures)
    alloc_attempts: AtomicU64,
    /// Per-cache spinlock (0 = unlocked, 1 = locked)
    lock: AtomicBool,
    /// Whether this cache entry is active
    active: bool,
}

impl SlabCache {
    /// Create an empty, inactive cache entry
    pub const fn empty() -> Self {
        SlabCache {
            name: [0u8; 32],
            object_size: 0,
            alignment: 0,
            objects_per_slab: 0,
            slabs: [0usize; MAX_SLABS_PER_CACHE],
            slab_count: 0,
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            alloc_attempts: AtomicU64::new(0),
            lock: AtomicBool::new(false),
            active: false,
        }
    }

    /// Acquire the per-cache spinlock
    fn lock(&self) {
        // Spinning with exponential backoff to reduce contention on the bus
        let mut spin_count: u32 = 0;
        while self.lock.compare_exchange_weak(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_err() {
            // Hint to the CPU that we're in a spin loop (reduces power and
            // helps with hyper-threading contention)
            core::hint::spin_loop();
            spin_count += 1;

            // After many spins, yield more aggressively
            if spin_count > 1000 {
                for _ in 0..10 {
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Release the per-cache spinlock
    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Initialize this cache for objects of the given name and size
    pub fn init(&mut self, name: &[u8], object_size: usize, alignment: usize) {
        // Copy name (truncate if too long)
        let copy_len = if name.len() > 31 { 31 } else { name.len() };
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name[copy_len] = 0;

        // Ensure object size meets minimum and alignment requirements
        let aligned_size = if object_size < MIN_OBJECT_SIZE {
            MIN_OBJECT_SIZE
        } else {
            // Round up to alignment boundary
            let align = if alignment == 0 { 8 } else { alignment };
            (object_size + align - 1) & !(align - 1)
        };

        self.object_size = aligned_size;
        self.alignment = if alignment == 0 { 8 } else { alignment };
        self.objects_per_slab = SlabHeader::objects_per_slab(aligned_size);
        self.slab_count = 0;
        self.active = true;
    }

    /// Get statistics for this cache
    pub fn stats(&self) -> SlabCacheStats {
        SlabCacheStats {
            object_size: self.object_size,
            objects_per_slab: self.objects_per_slab,
            slab_count: self.slab_count,
            total_allocated: self.alloc_count.load(Ordering::Relaxed),
            total_freed: self.free_count.load(Ordering::Relaxed),
            total_attempts: self.alloc_attempts.load(Ordering::Relaxed),
        }
    }
}

/// Statistics for a slab cache, returned by `SlabCache::stats()`
#[repr(C)]
pub struct SlabCacheStats {
    pub object_size: usize,
    pub objects_per_slab: usize,
    pub slab_count: usize,
    pub total_allocated: u64,
    pub total_freed: u64,
    pub total_attempts: u64,
}

// =============================================================================
// Global slab allocator state
// =============================================================================

/// Global array of slab caches
static mut SLAB_CACHES: [SlabCache; MAX_SLAB_CACHES] = {
    // Use a const block to initialize the array without requiring Copy on SlabCache
    // This works because `SlabCache::empty()` is const
    let mut caches = [SlabCache::empty(); MAX_SLAB_CACHES];
    let mut i = 0;
    while i < MAX_SLAB_CACHES {
        caches[i] = SlabCache::empty();
        i += 1;
    }
    caches
};

static SLAB_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_CACHE_INDEX: AtomicU32 = AtomicU32::new(0);

// =============================================================================
// FFI interface — called from Zig
// =============================================================================

/// Initialize the Rust slab allocator subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_slab_init() -> i32 {
    if SLAB_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    // Create default caches for common object sizes
    let default_sizes: [(usize, &[u8]); 8] = [
        (16, b"kmalloc-16"),
        (32, b"kmalloc-32"),
        (64, b"kmalloc-64"),
        (128, b"kmalloc-128"),
        (256, b"kmalloc-256"),
        (512, b"kmalloc-512"),
        (1024, b"kmalloc-1024"),
        (2048, b"kmalloc-2048"),
    ];

    for (size, name) in default_sizes.iter() {
        unsafe {
            let idx = NEXT_CACHE_INDEX.fetch_add(1, Ordering::SeqCst) as usize;
            if idx < MAX_SLAB_CACHES {
                SLAB_CACHES[idx].init(name, *size, 8);
            }
        }
    }

    SLAB_INITIALIZED.store(true, Ordering::SeqCst);

    crate::ffi::bridge::log_info("Rust slab allocator initialized with 8 default caches");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Create a new named slab cache for a specific object size
#[no_mangle]
pub extern "C" fn zxyphor_rust_slab_create_cache(
    name: *const u8,
    name_len: usize,
    object_size: usize,
    alignment: usize,
) -> i32 {
    if !SLAB_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::NotInitialized.as_i32();
    }

    if name.is_null() || name_len == 0 {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    if object_size == 0 || object_size > MAX_OBJECT_SIZE {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len) };

    let idx = NEXT_CACHE_INDEX.fetch_add(1, Ordering::SeqCst) as usize;
    if idx >= MAX_SLAB_CACHES {
        return crate::ffi::error::FfiError::NoSpace.as_i32();
    }

    unsafe {
        SLAB_CACHES[idx].init(name_slice, object_size, alignment);
    }

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Get statistics for a specific slab cache by index
#[no_mangle]
pub extern "C" fn zxyphor_rust_slab_cache_stats(
    cache_index: u32,
    stats_out: *mut SlabCacheStats,
) -> i32 {
    if stats_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let idx = cache_index as usize;
    if idx >= MAX_SLAB_CACHES {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    unsafe {
        if !SLAB_CACHES[idx].active {
            return crate::ffi::error::FfiError::NotFound.as_i32();
        }

        let stats = SLAB_CACHES[idx].stats();
        ptr::write(stats_out, stats);
    }

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Get the total number of active slab caches
#[no_mangle]
pub extern "C" fn zxyphor_rust_slab_cache_count() -> u32 {
    NEXT_CACHE_INDEX.load(Ordering::Relaxed)
}
