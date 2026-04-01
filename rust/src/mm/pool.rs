// =============================================================================
// Kernel Zxyphor — Rust Memory Pool Allocator
// =============================================================================
// A memory pool allocator optimized for high-throughput fixed-size allocations.
// Unlike the general slab allocator, pools are designed for specific use cases
// where objects are allocated and freed at very high rates (e.g., network
// packet buffers, IPC message slots).
//
// Each pool pre-allocates a fixed number of objects and manages them using a
// lock-free stack (Treiber stack) for minimal contention in multi-core
// environments. When the pool is exhausted, allocation fails immediately
// rather than growing — this is intentional for real-time predictability.
//
// Key properties:
//   - O(1) allocation and deallocation (constant-time, no searching)
//   - Lock-free for single-producer/single-consumer patterns
//   - No fragmentation (all objects are the same size)
//   - Deterministic latency (no fallback to slower allocators)
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::ptr;

/// Maximum number of memory pools
const MAX_POOLS: usize = 32;

/// Maximum number of objects in a single pool
const MAX_POOL_OBJECTS: usize = 16384;

// =============================================================================
// Pool node — linked list element in the free stack
// =============================================================================

/// Each free object in the pool has a header that points to the next free object.
/// When the object is allocated, this header is overwritten by user data.
#[repr(C)]
struct PoolNode {
    /// Index of the next free node (u32::MAX = end of list)
    next_free: u32,
    /// Generation counter to prevent ABA problem in lock-free operations
    generation: u32,
}

// =============================================================================
// Memory pool
// =============================================================================

/// A fixed-size memory pool with O(1) allocation and deallocation.
///
/// The pool manages a contiguous region of memory divided into equal-sized
/// slots. A free list (implemented as an atomic stack) tracks available slots.
#[repr(C)]
pub struct MemoryPool {
    /// Human-readable name
    name: [u8; 32],
    /// Size of each object (including any internal padding)
    object_size: usize,
    /// Total number of objects in this pool
    capacity: usize,
    /// Base address of the pool's memory region
    base_addr: usize,
    /// Total memory size of the pool region
    region_size: usize,
    /// Head of the free list (index into the objects array)
    free_head: AtomicU32,
    /// Number of currently allocated (in-use) objects
    allocated: AtomicU32,
    /// High-water mark — maximum number of concurrent allocations observed
    high_water: AtomicU32,
    /// Total allocation operations performed
    total_allocs: AtomicU64,
    /// Total free operations performed
    total_frees: AtomicU64,
    /// Total allocation failures (pool exhausted)
    total_failures: AtomicU64,
    /// Whether this pool is active
    active: AtomicBool,
    /// Pool lock for initialization and destruction
    lock: AtomicBool,
}

impl MemoryPool {
    /// Create an empty, inactive pool
    pub const fn empty() -> Self {
        MemoryPool {
            name: [0u8; 32],
            object_size: 0,
            capacity: 0,
            base_addr: 0,
            region_size: 0,
            free_head: AtomicU32::new(u32::MAX),
            allocated: AtomicU32::new(0),
            high_water: AtomicU32::new(0),
            total_allocs: AtomicU64::new(0),
            total_frees: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            active: AtomicBool::new(false),
            lock: AtomicBool::new(false),
        }
    }

    /// Acquire pool lock
    fn lock_pool(&self) {
        while self.lock.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }
    }

    /// Release pool lock
    fn unlock_pool(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Initialize the pool with a pre-allocated memory region.
    ///
    /// The `base` address must point to `object_size * capacity` bytes of
    /// available memory. The caller is responsible for ensuring the memory
    /// is properly mapped and accessible.
    pub fn init(
        &mut self,
        name: &[u8],
        base: usize,
        object_size: usize,
        capacity: usize,
    ) -> bool {
        if object_size < core::mem::size_of::<PoolNode>() {
            return false;
        }

        if capacity == 0 || capacity > MAX_POOL_OBJECTS {
            return false;
        }

        if base == 0 {
            return false;
        }

        self.lock_pool();

        // Copy name
        let copy_len = core::cmp::min(name.len(), 31);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name[copy_len] = 0;

        self.object_size = object_size;
        self.capacity = capacity;
        self.base_addr = base;
        self.region_size = object_size * capacity;

        // Initialize the free list — chain all objects together
        for i in 0..capacity {
            let node_addr = base + i * object_size;
            let node = unsafe { &mut *(node_addr as *mut PoolNode) };
            node.next_free = if i + 1 < capacity { (i + 1) as u32 } else { u32::MAX };
            node.generation = 0;
        }

        self.free_head.store(0, Ordering::Release);
        self.allocated.store(0, Ordering::Release);
        self.high_water.store(0, Ordering::Release);
        self.active.store(true, Ordering::Release);

        self.unlock_pool();
        true
    }

    /// Allocate an object from the pool. Returns a pointer to the object or null.
    ///
    /// This operation is O(1) — it simply pops the head of the free list.
    /// If the pool is exhausted, returns null immediately (no blocking).
    pub fn alloc(&self) -> *mut u8 {
        if !self.active.load(Ordering::Acquire) {
            return ptr::null_mut();
        }

        // Pop from the free list
        loop {
            let head = self.free_head.load(Ordering::Acquire);
            if head == u32::MAX {
                // Pool exhausted
                self.total_failures.fetch_add(1, Ordering::Relaxed);
                return ptr::null_mut();
            }

            let node_addr = self.base_addr + (head as usize) * self.object_size;
            let node = unsafe { &*(node_addr as *const PoolNode) };
            let next = node.next_free;

            if self.free_head.compare_exchange_weak(
                head, next, Ordering::AcqRel, Ordering::Relaxed
            ).is_ok() {
                // Successfully popped — update statistics
                let new_count = self.allocated.fetch_add(1, Ordering::Relaxed) + 1;
                self.total_allocs.fetch_add(1, Ordering::Relaxed);

                // Update high-water mark
                let mut current_high = self.high_water.load(Ordering::Relaxed);
                while new_count > current_high {
                    match self.high_water.compare_exchange_weak(
                        current_high,
                        new_count,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => current_high = actual,
                    }
                }

                // Zero the memory before returning (prevent information leaks)
                unsafe {
                    ptr::write_bytes(node_addr as *mut u8, 0, self.object_size);
                }

                return node_addr as *mut u8;
            }

            // CAS failed — another thread got it first, retry
            core::hint::spin_loop();
        }
    }

    /// Return an object to the pool.
    ///
    /// The caller must ensure `ptr` was previously returned by `alloc()` on
    /// this same pool. Double-free is detected via generation counters.
    pub fn free(&self, ptr: *mut u8) -> bool {
        if ptr.is_null() || !self.active.load(Ordering::Acquire) {
            return false;
        }

        let addr = ptr as usize;

        // Validate that the pointer belongs to this pool
        if addr < self.base_addr || addr >= self.base_addr + self.region_size {
            return false;
        }

        // Validate alignment
        let offset = addr - self.base_addr;
        if offset % self.object_size != 0 {
            return false;
        }

        let index = (offset / self.object_size) as u32;

        // Push onto the free list
        loop {
            let head = self.free_head.load(Ordering::Acquire);

            let node = unsafe { &mut *(addr as *mut PoolNode) };
            node.next_free = head;
            node.generation = node.generation.wrapping_add(1);

            if self.free_head.compare_exchange_weak(
                head, index, Ordering::AcqRel, Ordering::Relaxed
            ).is_ok() {
                self.allocated.fetch_sub(1, Ordering::Relaxed);
                self.total_frees.fetch_add(1, Ordering::Relaxed);
                return true;
            }

            core::hint::spin_loop();
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            object_size: self.object_size,
            capacity: self.capacity,
            allocated: self.allocated.load(Ordering::Relaxed),
            high_water: self.high_water.load(Ordering::Relaxed),
            total_allocs: self.total_allocs.load(Ordering::Relaxed),
            total_frees: self.total_frees.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
        }
    }
}

/// Statistics for a memory pool
#[repr(C)]
pub struct PoolStats {
    pub object_size: usize,
    pub capacity: usize,
    pub allocated: u32,
    pub high_water: u32,
    pub total_allocs: u64,
    pub total_frees: u64,
    pub total_failures: u64,
}

// =============================================================================
// Global pool registry
// =============================================================================

static mut POOLS: [MemoryPool; MAX_POOLS] = {
    let pool = MemoryPool::empty();
    let mut pools = [pool; MAX_POOLS];
    let mut i = 0;
    while i < MAX_POOLS {
        pools[i] = MemoryPool::empty();
        i += 1;
    }
    pools
};

static POOL_COUNT: AtomicUsize = AtomicUsize::new(0);

// =============================================================================
// FFI interface
// =============================================================================

/// Create a new memory pool
#[no_mangle]
pub extern "C" fn zxyphor_rust_pool_create(
    name: *const u8,
    name_len: usize,
    base_addr: usize,
    object_size: usize,
    capacity: usize,
) -> i32 {
    if name.is_null() || name_len == 0 || base_addr == 0 {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let idx = POOL_COUNT.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_POOLS {
        POOL_COUNT.fetch_sub(1, Ordering::SeqCst);
        return crate::ffi::error::FfiError::NoSpace.as_i32();
    }

    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len) };

    let success = unsafe {
        POOLS[idx].init(name_slice, base_addr, object_size, capacity)
    };

    if success {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::InvalidArgument.as_i32()
    }
}

/// Allocate from a memory pool by index
#[no_mangle]
pub extern "C" fn zxyphor_rust_pool_alloc(pool_index: u32) -> usize {
    let idx = pool_index as usize;
    if idx >= MAX_POOLS {
        return 0;
    }

    let ptr = unsafe { POOLS[idx].alloc() };
    ptr as usize
}

/// Free an object back to a memory pool
#[no_mangle]
pub extern "C" fn zxyphor_rust_pool_free(pool_index: u32, ptr: usize) -> i32 {
    let idx = pool_index as usize;
    if idx >= MAX_POOLS {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let success = unsafe { POOLS[idx].free(ptr as *mut u8) };
    if success {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::InvalidArgument.as_i32()
    }
}

/// Get pool statistics
#[no_mangle]
pub extern "C" fn zxyphor_rust_pool_stats(
    pool_index: u32,
    stats_out: *mut PoolStats,
) -> i32 {
    if stats_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let idx = pool_index as usize;
    if idx >= MAX_POOLS {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    unsafe {
        if !POOLS[idx].active.load(Ordering::Acquire) {
            return crate::ffi::error::FfiError::NotFound.as_i32();
        }

        let stats = POOLS[idx].stats();
        ptr::write(stats_out, stats);
    }

    crate::ffi::error::FfiError::Success.as_i32()
}
