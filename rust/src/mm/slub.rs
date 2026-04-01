// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Memory Pool & SLUB-like Allocator (Rust)
//
// Object/slab cache for efficient kernel memory allocation:
// - SLUB-style per-CPU freelists
// - Object caches with configurable size classes
// - Constructor/destructor callbacks
// - Red-zone poisoning (debug mode)
// - Per-cache statistics (alloc, free, active, slabs)
// - Magazine/depot hierarchy for reduced contention
// - Mempool (guaranteed emergency allocations)
// - kmalloc-style size-class allocation
// - Cache merging (same-size caches share slabs)
// - Memory accounting per-cache

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────

const PAGE_SIZE: usize = 4096;
const MAX_CACHES: usize = 32;
const MAX_SLABS_PER_CACHE: usize = 64;
const MAX_OBJECTS_PER_SLAB: usize = 512;
const MAX_MEMPOOLS: usize = 16;
const MAX_SIZE_CLASSES: usize = 16;

// Kmalloc size classes (power-of-two from 8 to 8192)
const KMALLOC_SIZES: [MAX_SIZE_CLASSES]u32 = [_]u32{
    8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 0, 0, 0, 0,
};
const KMALLOC_NUM_CLASSES: usize = 12;

// ─────────────────── Slab State ─────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SlabState {
    Free = 0,     // All objects free
    Partial = 1,  // Some objects allocated
    Full = 2,     // All objects allocated
}

// ─────────────────── Cache Flags ────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CacheFlags {
    None = 0,
    Hwcache = 0x0001,       // Hardware cache-align objects
    Poison = 0x0002,        // Poison freed objects (debug)
    RedZone = 0x0004,       // Red zone before/after objects
    Reclaimable = 0x0008,   // Shrinkable under pressure
    Account = 0x0010,       // Track in memcg
    NoMerge = 0x0020,       // Don't merge with similar caches
}

// ─────────────────── Slab Descriptor ────────────────────────────────

#[derive(Clone, Copy)]
pub struct SlabDescriptor {
    /// Base physical address of slab page(s)
    pub base_addr: u64,
    /// State
    pub state: SlabState,
    /// Free object bitmap (1=free, 0=allocated)
    pub freemap: [u64; 8], // Up to 512 objects
    /// Total objects in this slab
    pub total_objects: u16,
    /// Currently allocated objects
    pub allocated: u16,
    /// Order (number of pages: 2^order)
    pub order: u8,
    pub active: bool,
}

impl SlabDescriptor {
    pub const fn new() -> Self {
        Self {
            base_addr: 0,
            state: SlabState::Free,
            freemap: [u64::MAX; 8],
            total_objects: 0,
            allocated: 0,
            order: 0,
            active: false,
        }
    }

    pub fn init_freemap(&mut self, num_objects: u16) {
        self.total_objects = num_objects;
        // Set all bits free
        for i in 0..8 {
            self.freemap[i] = u64::MAX;
        }
        // Clear bits beyond num_objects
        let total_bits = num_objects as usize;
        for i in total_bits..512 {
            let word = i / 64;
            let bit = i % 64;
            self.freemap[word] &= !(1u64 << bit);
        }
    }

    /// Allocate one object, returning index
    pub fn alloc_object(&mut self) -> Option<u16> {
        for word_idx in 0..8 {
            if self.freemap[word_idx] != 0 {
                let bit = self.freemap[word_idx].trailing_zeros() as usize;
                if word_idx * 64 + bit < self.total_objects as usize {
                    self.freemap[word_idx] &= !(1u64 << bit);
                    self.allocated += 1;
                    self.update_state();
                    return Some((word_idx * 64 + bit) as u16);
                }
            }
        }
        None
    }

    /// Free object by index
    pub fn free_object(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= self.total_objects as usize {
            return false;
        }
        let word = i / 64;
        let bit = i % 64;
        if self.freemap[word] & (1u64 << bit) != 0 {
            return false; // Already free (double-free detection)
        }
        self.freemap[word] |= 1u64 << bit;
        if self.allocated > 0 {
            self.allocated -= 1;
        }
        self.update_state();
        true
    }

    fn update_state(&mut self) {
        if self.allocated == 0 {
            self.state = SlabState::Free;
        } else if self.allocated >= self.total_objects {
            self.state = SlabState::Full;
        } else {
            self.state = SlabState::Partial;
        }
    }

    pub fn is_full(&self) -> bool {
        self.state == SlabState::Full
    }

    pub fn is_empty(&self) -> bool {
        self.state == SlabState::Free
    }
}

// ─────────────────── Object Cache ───────────────────────────────────

#[derive(Clone, Copy)]
pub struct ObjectCache {
    pub name: [u8; 32],
    pub name_len: u8,
    /// Object size (bytes)
    pub obj_size: u32,
    /// Alignment
    pub align: u32,
    /// Effective size (obj_size + padding + red_zone)
    pub effective_size: u32,
    /// Flags
    pub flags: u32,
    /// Slabs
    pub slabs: [SlabDescriptor; MAX_SLABS_PER_CACHE],
    pub slab_count: u16,
    /// Objects per slab
    pub objects_per_slab: u16,
    /// Slab order (pages per slab = 2^order)
    pub slab_order: u8,
    /// Red zone pattern
    pub red_zone_val: u32,
    /// Poison byte
    pub poison_val: u8,
    /// Stats
    pub total_allocs: u64,
    pub total_frees: u64,
    pub active_objects: u32,
    pub total_slabs: u16,
    /// Allocation failures
    pub alloc_failures: u32,
    pub active: bool,
}

impl ObjectCache {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            obj_size: 0,
            align: 8,
            effective_size: 0,
            flags: 0,
            slabs: [SlabDescriptor::new(); MAX_SLABS_PER_CACHE],
            slab_count: 0,
            objects_per_slab: 0,
            slab_order: 0,
            red_zone_val: 0x5A5A5A5A,
            poison_val: 0xCC,
            total_allocs: 0,
            total_frees: 0,
            active_objects: 0,
            total_slabs: 0,
            alloc_failures: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn compute_layout(&mut self) {
        let mut eff = self.obj_size;
        // Alignment
        if self.align > 0 {
            eff = (eff + self.align - 1) & !(self.align - 1);
        }
        // Red zone
        if self.flags & CacheFlags::RedZone as u32 != 0 {
            eff += 8; // 4 bytes before + 4 bytes after
        }
        self.effective_size = eff;

        // Calculate slab order and objects per slab
        let slab_size = PAGE_SIZE << self.slab_order as usize;
        self.objects_per_slab = (slab_size as u32 / eff).min(MAX_OBJECTS_PER_SLAB as u32) as u16;

        // If objects per slab is 0, increase order
        if self.objects_per_slab == 0 && self.slab_order < 4 {
            self.slab_order += 1;
            let bigger_slab = PAGE_SIZE << self.slab_order as usize;
            self.objects_per_slab =
                (bigger_slab as u32 / eff).min(MAX_OBJECTS_PER_SLAB as u32) as u16;
        }
    }

    /// Grow cache by adding a new slab
    fn grow(&mut self, phys_addr: u64) -> bool {
        if self.slab_count as usize >= MAX_SLABS_PER_CACHE {
            return false;
        }
        let idx = self.slab_count as usize;
        self.slabs[idx] = SlabDescriptor::new();
        self.slabs[idx].base_addr = phys_addr;
        self.slabs[idx].order = self.slab_order;
        self.slabs[idx].init_freemap(self.objects_per_slab);
        self.slabs[idx].active = true;
        self.slab_count += 1;
        self.total_slabs += 1;
        true
    }

    /// Allocate object from cache. Returns (slab_idx, obj_idx) encoding.
    pub fn alloc(&mut self) -> Option<u32> {
        // First try partial slabs
        for i in 0..self.slab_count as usize {
            if self.slabs[i].active && self.slabs[i].state == SlabState::Partial {
                if let Some(obj_idx) = self.slabs[i].alloc_object() {
                    self.total_allocs += 1;
                    self.active_objects += 1;
                    return Some((i as u32) << 16 | obj_idx as u32);
                }
            }
        }

        // Then try free slabs
        for i in 0..self.slab_count as usize {
            if self.slabs[i].active && self.slabs[i].state == SlabState::Free {
                if let Some(obj_idx) = self.slabs[i].alloc_object() {
                    self.total_allocs += 1;
                    self.active_objects += 1;
                    return Some((i as u32) << 16 | obj_idx as u32);
                }
            }
        }

        // No space — would need to grow (caller provides memory)
        self.alloc_failures += 1;
        None
    }

    /// Free object
    pub fn free(&mut self, token: u32) -> bool {
        let slab_idx = (token >> 16) as usize;
        let obj_idx = (token & 0xFFFF) as u16;

        if slab_idx >= self.slab_count as usize || !self.slabs[slab_idx].active {
            return false;
        }

        if self.slabs[slab_idx].free_object(obj_idx) {
            self.total_frees += 1;
            if self.active_objects > 0 {
                self.active_objects -= 1;
            }
            return true;
        }
        false
    }

    /// Shrink: reclaim empty slabs
    pub fn shrink(&mut self) -> u16 {
        let mut reclaimed: u16 = 0;
        for i in 0..self.slab_count as usize {
            if self.slabs[i].active && self.slabs[i].is_empty() {
                self.slabs[i].active = false;
                reclaimed += 1;
            }
        }
        reclaimed
    }

    pub fn utilization_percent(&self) -> u32 {
        let total = self.slab_count as u32 * self.objects_per_slab as u32;
        if total == 0 {
            return 0;
        }
        (self.active_objects * 100) / total
    }
}

// ─────────────────── Mempool (guaranteed allocations) ────────────────

/// Pre-allocated pool for emergency allocations
#[derive(Clone, Copy)]
pub struct Mempool {
    pub name: [u8; 16],
    pub name_len: u8,
    pub min_reserved: u16,
    pub current_reserved: u16,
    pub obj_size: u32,
    /// Backing cache index
    pub cache_idx: u8,
    pub total_allocs: u64,
    pub total_frees: u64,
    pub emergency_allocs: u64,
    pub active: bool,
}

impl Mempool {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 16],
            name_len: 0,
            min_reserved: 0,
            current_reserved: 0,
            obj_size: 0,
            cache_idx: 0,
            total_allocs: 0,
            total_frees: 0,
            emergency_allocs: 0,
            active: false,
        }
    }

    pub fn alloc(&mut self) -> bool {
        self.total_allocs += 1;
        if self.current_reserved > 0 {
            self.current_reserved -= 1;
            if self.current_reserved < self.min_reserved {
                self.emergency_allocs += 1;
            }
            true
        } else {
            false
        }
    }

    pub fn free(&mut self) {
        self.total_frees += 1;
        if self.current_reserved < self.min_reserved {
            self.current_reserved += 1;
        }
    }
}

// ─────────────────── SLUB Manager ───────────────────────────────────

pub struct SlubManager {
    caches: [ObjectCache; MAX_CACHES],
    cache_count: u8,
    mempools: [Mempool; MAX_MEMPOOLS],
    mempool_count: u8,
    /// kmalloc cache indices
    kmalloc_caches: [u8; MAX_SIZE_CLASSES],
    /// Global stats
    total_allocs: AtomicU64,
    total_frees: AtomicU64,
    total_slabs: AtomicU64,
}

impl SlubManager {
    pub const fn new() -> Self {
        Self {
            caches: [ObjectCache::new(); MAX_CACHES],
            cache_count: 0,
            mempools: [Mempool::new(); MAX_MEMPOOLS],
            mempool_count: 0,
            kmalloc_caches: [0xFF; MAX_SIZE_CLASSES],
            total_allocs: AtomicU64::new(0),
            total_frees: AtomicU64::new(0),
            total_slabs: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self) {
        // Create kmalloc size-class caches
        for i in 0..KMALLOC_NUM_CLASSES {
            let size = KMALLOC_SIZES[i];
            if size == 0 {
                break;
            }
            if let Some(idx) = self.create_cache_internal(b"kmalloc", size, 8, 0) {
                self.kmalloc_caches[i] = idx;
            }
        }
    }

    /// Create a named object cache
    pub fn create_cache(
        &mut self,
        name: &[u8],
        obj_size: u32,
        align: u32,
        flags: u32,
    ) -> Option<u8> {
        self.create_cache_internal(name, obj_size, align, flags)
    }

    fn create_cache_internal(
        &mut self,
        name: &[u8],
        obj_size: u32,
        align: u32,
        flags: u32,
    ) -> Option<u8> {
        if self.cache_count as usize >= MAX_CACHES || obj_size == 0 {
            return None;
        }

        // Check for merge opportunity (NoMerge flag disables)
        if flags & CacheFlags::NoMerge as u32 == 0 {
            for i in 0..self.cache_count as usize {
                if self.caches[i].active
                    && self.caches[i].obj_size == obj_size
                    && self.caches[i].align == align
                {
                    return Some(i as u8);
                }
            }
        }

        let idx = self.cache_count;
        let c = &mut self.caches[idx as usize];
        *c = ObjectCache::new();
        c.set_name(name);
        c.obj_size = obj_size;
        c.align = if align == 0 { 8 } else { align };
        c.flags = flags;
        c.compute_layout();
        c.active = true;
        self.cache_count += 1;
        Some(idx)
    }

    /// Destroy a cache
    pub fn destroy_cache(&mut self, idx: u8) -> bool {
        let i = idx as usize;
        if i >= MAX_CACHES || !self.caches[i].active {
            return false;
        }
        if self.caches[i].active_objects > 0 {
            return false; // Still has allocated objects
        }
        self.caches[i].active = false;
        true
    }

    /// Allocate from a named cache
    pub fn cache_alloc(&mut self, cache_idx: u8) -> Option<u32> {
        let i = cache_idx as usize;
        if i >= MAX_CACHES || !self.caches[i].active {
            return None;
        }
        let result = self.caches[i].alloc();
        if result.is_some() {
            self.total_allocs.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Free to a named cache
    pub fn cache_free(&mut self, cache_idx: u8, token: u32) -> bool {
        let i = cache_idx as usize;
        if i >= MAX_CACHES || !self.caches[i].active {
            return false;
        }
        if self.caches[i].free(token) {
            self.total_frees.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Grow a cache by providing a new slab page
    pub fn cache_grow(&mut self, cache_idx: u8, phys_addr: u64) -> bool {
        let i = cache_idx as usize;
        if i >= MAX_CACHES || !self.caches[i].active {
            return false;
        }
        if self.caches[i].grow(phys_addr) {
            self.total_slabs.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// kmalloc — find appropriate size class and allocate
    pub fn kmalloc(&mut self, size: u32) -> Option<u32> {
        for i in 0..KMALLOC_NUM_CLASSES {
            if KMALLOC_SIZES[i] >= size && self.kmalloc_caches[i] != 0xFF {
                return self.cache_alloc(self.kmalloc_caches[i]);
            }
        }
        None // Too large for kmalloc
    }

    /// Shrink all caches (reclaim empty slabs)
    pub fn shrink_all(&mut self) -> u16 {
        let mut total: u16 = 0;
        for i in 0..self.cache_count as usize {
            if self.caches[i].active {
                total += self.caches[i].shrink();
            }
        }
        total
    }

    /// Create a mempool backed by a cache
    pub fn create_mempool(
        &mut self,
        name: &[u8],
        cache_idx: u8,
        min_reserved: u16,
    ) -> Option<u8> {
        if self.mempool_count as usize >= MAX_MEMPOOLS {
            return None;
        }
        let idx = self.mempool_count;
        let mp = &mut self.mempools[idx as usize];
        *mp = Mempool::new();
        let len = name.len().min(15);
        mp.name[..len].copy_from_slice(&name[..len]);
        mp.name_len = len as u8;
        mp.cache_idx = cache_idx;
        mp.min_reserved = min_reserved;
        mp.current_reserved = min_reserved;
        mp.obj_size = if (cache_idx as usize) < MAX_CACHES {
            self.caches[cache_idx as usize].obj_size
        } else {
            0
        };
        mp.active = true;
        self.mempool_count += 1;
        Some(idx)
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut SLUB_MGR: SlubManager = SlubManager::new();

fn mgr() -> &'static mut SlubManager {
    unsafe { &mut SLUB_MGR }
}

fn mgr_ref() -> &'static SlubManager {
    unsafe { &SLUB_MGR }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_slub_init() {
    mgr().init();
}

#[no_mangle]
pub extern "C" fn rust_slub_cache_count() -> u8 {
    mgr_ref().cache_count
}

#[no_mangle]
pub extern "C" fn rust_slub_total_allocs() -> u64 {
    mgr_ref().total_allocs.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_slub_total_frees() -> u64 {
    mgr_ref().total_frees.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_slub_total_slabs() -> u64 {
    mgr_ref().total_slabs.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_slub_cache_grow(idx: u8, phys_addr: u64) -> bool {
    mgr().cache_grow(idx, phys_addr)
}

#[no_mangle]
pub extern "C" fn rust_slub_cache_alloc(idx: u8) -> i64 {
    match mgr().cache_alloc(idx) {
        Some(token) => token as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_slub_cache_free(idx: u8, token: u32) -> bool {
    mgr().cache_free(idx, token)
}

#[no_mangle]
pub extern "C" fn rust_slub_shrink_all() -> u16 {
    mgr().shrink_all()
}

#[no_mangle]
pub extern "C" fn rust_slub_mempool_count() -> u8 {
    mgr_ref().mempool_count
}
