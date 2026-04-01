// =============================================================================
// Kernel Zxyphor — Rust Memory Management: Page Frame Allocator
// =============================================================================
// A buddy allocator for physical page frames. Works in conjunction with the
// Zig PMM for cross-language memory management. The Rust side maintains its
// own free lists for pages allocated to Rust subsystems, reducing FFI overhead
// for frequent allocations.
//
// The buddy system splits memory into power-of-2 sized blocks:
//   Order 0 = 4 KiB (1 page)
//   Order 1 = 8 KiB (2 pages)
//   ...
//   Order 10 = 4 MiB (1024 pages)
//
// Allocation finds the smallest block that fits, splitting larger blocks as
// needed. Deallocation merges buddies back together to reduce fragmentation.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Page size in bytes (4 KiB on x86_64)
pub const PAGE_SIZE: usize = 4096;

/// Maximum buddy order (2^MAX_ORDER pages = 4 MiB blocks)
pub const MAX_ORDER: usize = 11;

/// Maximum number of memory zones (DMA, Normal, HighMem)
pub const MAX_ZONES: usize = 4;

/// Maximum number of free list entries per order
const MAX_FREE_ENTRIES: usize = 8192;

// =============================================================================
// Memory zone types
// =============================================================================

/// Physical memory is divided into zones based on address ranges and DMA
/// capabilities. This mirrors the Linux zone architecture.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryZone {
    /// DMA zone: first 16 MiB, accessible by legacy ISA DMA controllers
    Dma = 0,
    /// DMA32 zone: first 4 GiB, accessible by 32-bit DMA-capable devices
    Dma32 = 1,
    /// Normal zone: all memory above 4 GiB that is directly mapped
    Normal = 2,
    /// Movable zone: pages that can be migrated for compaction
    Movable = 3,
}

impl MemoryZone {
    /// Get the zone for a given physical address
    pub fn from_address(phys_addr: u64) -> Self {
        if phys_addr < 0x100_0000 {
            MemoryZone::Dma
        } else if phys_addr < 0x1_0000_0000 {
            MemoryZone::Dma32
        } else {
            MemoryZone::Normal
        }
    }

    /// Get the starting physical address of this zone
    pub fn start_address(self) -> u64 {
        match self {
            MemoryZone::Dma => 0,
            MemoryZone::Dma32 => 0x100_0000,
            MemoryZone::Normal => 0x1_0000_0000,
            MemoryZone::Movable => 0, // virtual zone, no fixed start
        }
    }

    /// Get the ending physical address of this zone
    pub fn end_address(self) -> u64 {
        match self {
            MemoryZone::Dma => 0x100_0000,
            MemoryZone::Dma32 => 0x1_0000_0000,
            MemoryZone::Normal => u64::MAX,
            MemoryZone::Movable => u64::MAX,
        }
    }
}

// =============================================================================
// Free list for a single buddy order within a zone
// =============================================================================

/// A free list entry — stores the physical address of a free block
#[repr(C)]
struct FreeBlock {
    /// Physical address of the first page in this free block
    phys_addr: u64,
    /// Whether this entry is valid
    valid: bool,
}

/// Free list for one order level. Contains an array of free block addresses
/// and a count of how many are valid.
struct FreeList {
    /// Array of free block entries
    blocks: [FreeBlock; MAX_FREE_ENTRIES],
    /// Number of valid entries
    count: usize,
}

impl FreeList {
    const fn new() -> Self {
        const EMPTY_BLOCK: FreeBlock = FreeBlock {
            phys_addr: 0,
            valid: false,
        };
        FreeList {
            blocks: [EMPTY_BLOCK; MAX_FREE_ENTRIES],
            count: 0,
        }
    }

    /// Add a free block to this list
    fn push(&mut self, phys_addr: u64) -> bool {
        if self.count >= MAX_FREE_ENTRIES {
            return false;
        }

        // Find the first empty slot
        for block in self.blocks.iter_mut() {
            if !block.valid {
                block.phys_addr = phys_addr;
                block.valid = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Remove and return a free block from this list
    fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        // Find the last valid entry (LIFO for cache locality)
        for block in self.blocks.iter_mut().rev() {
            if block.valid {
                let addr = block.phys_addr;
                block.valid = false;
                self.count -= 1;
                return Some(addr);
            }
        }
        None
    }

    /// Remove a specific address from the list (for buddy merging)
    fn remove(&mut self, phys_addr: u64) -> bool {
        for block in self.blocks.iter_mut() {
            if block.valid && block.phys_addr == phys_addr {
                block.valid = false;
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Check if a specific address exists in the list
    fn contains(&self, phys_addr: u64) -> bool {
        for block in self.blocks.iter() {
            if block.valid && block.phys_addr == phys_addr {
                return true;
            }
        }
        false
    }
}

// =============================================================================
// Zone allocator — manages free lists for all orders within one zone
// =============================================================================

/// Per-zone buddy allocator state
struct ZoneAllocator {
    /// Free lists indexed by order (0..MAX_ORDER)
    free_lists: [FreeList; MAX_ORDER],
    /// Zone type
    zone_type: MemoryZone,
    /// Total pages managed by this zone
    total_pages: u64,
    /// Currently free pages
    free_pages: AtomicU64,
    /// Zone lock
    lock: AtomicBool,
    /// Whether this zone is active
    active: bool,
}

impl ZoneAllocator {
    const fn new(zone_type: MemoryZone) -> Self {
        const EMPTY_LIST: FreeList = FreeList::new();
        ZoneAllocator {
            free_lists: [EMPTY_LIST; MAX_ORDER],
            zone_type,
            total_pages: 0,
            free_pages: AtomicU64::new(0),
            lock: AtomicBool::new(false),
            active: false,
        }
    }

    /// Acquire the zone lock
    fn lock(&self) {
        while self.lock.compare_exchange_weak(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_err() {
            core::hint::spin_loop();
        }
    }

    /// Release the zone lock
    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Calculate the buddy address for a block at the given address and order
    fn buddy_address(addr: u64, order: usize) -> u64 {
        addr ^ ((PAGE_SIZE as u64) << order)
    }

    /// Allocate a block of 2^order contiguous pages
    fn alloc_pages(&mut self, order: usize) -> Option<u64> {
        if order >= MAX_ORDER {
            return None;
        }

        self.lock();

        // Try to find a free block at the requested order or higher
        let result = self.alloc_pages_locked(order);

        self.unlock();

        if result.is_some() {
            let page_count = 1u64 << order;
            self.free_pages.fetch_sub(page_count, Ordering::Relaxed);
        }

        result
    }

    /// Internal allocation with lock held
    fn alloc_pages_locked(&mut self, target_order: usize) -> Option<u64> {
        // Search from the target order upwards
        for order in target_order..MAX_ORDER {
            if let Some(addr) = self.free_lists[order].pop() {
                // If we found a larger block, split it down to the target size
                let mut current_order = order;
                let mut current_addr = addr;

                while current_order > target_order {
                    current_order -= 1;
                    // The upper half becomes a new free block at the lower order
                    let buddy = current_addr + ((PAGE_SIZE as u64) << current_order);
                    self.free_lists[current_order].push(buddy);
                }

                return Some(current_addr);
            }
        }
        None
    }

    /// Free a block of 2^order contiguous pages, merging with buddy if possible
    fn free_pages(&mut self, phys_addr: u64, order: usize) {
        if order >= MAX_ORDER {
            return;
        }

        self.lock();

        let mut current_addr = phys_addr;
        let mut current_order = order;

        // Try to merge with buddies up to the maximum order
        while current_order < MAX_ORDER - 1 {
            let buddy = Self::buddy_address(current_addr, current_order);

            // Check if the buddy is free at this order
            if self.free_lists[current_order].remove(buddy) {
                // Merge: use the lower of the two addresses
                current_addr = core::cmp::min(current_addr, buddy);
                current_order += 1;
            } else {
                break;
            }
        }

        // Add the (possibly merged) block to the free list
        self.free_lists[current_order].push(current_addr);

        self.unlock();

        let page_count = 1u64 << order;
        self.free_pages.fetch_add(page_count, Ordering::Relaxed);
    }

    /// Get the number of free pages in this zone
    fn free_page_count(&self) -> u64 {
        self.free_pages.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Global allocator state
// =============================================================================

static ALLOCATOR_INITIALIZED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// Page flags — metadata for each physical page frame
// =============================================================================

/// Flags that describe the state and properties of a physical page frame
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFlags {
    /// Page is free and available for allocation
    Free = 0,
    /// Page is allocated and in use
    Allocated = 1,
    /// Page is reserved (e.g., BIOS, MMIO) and cannot be allocated
    Reserved = 2,
    /// Page is used by the kernel itself (code, data, stack)
    Kernel = 3,
    /// Page is part of a slab cache
    Slab = 4,
    /// Page is used for page tables
    PageTable = 5,
    /// Page is in the process of being migrated
    Migrating = 6,
    /// Page has been written to (dirty)
    Dirty = 7,
    /// Page is pinned and cannot be swapped or migrated
    Pinned = 8,
}

/// Metadata for a single physical page frame
#[repr(C)]
pub struct PageFrame {
    /// Physical address of this page
    pub phys_addr: u64,
    /// Current state flags
    pub flags: PageFlags,
    /// Reference count (how many mappings point to this page)
    pub ref_count: u32,
    /// The buddy order this page belongs to (if part of a compound page)
    pub order: u8,
    /// The zone this page belongs to
    pub zone: u8,
    /// Padding for alignment
    _padding: [u8; 2],
}

impl PageFrame {
    pub const fn empty() -> Self {
        PageFrame {
            phys_addr: 0,
            flags: PageFlags::Free,
            ref_count: 0,
            order: 0,
            zone: 0,
            _padding: [0; 2],
        }
    }
}

// =============================================================================
// FFI interface
// =============================================================================

/// Initialize the Rust page frame allocator
#[no_mangle]
pub extern "C" fn zxyphor_rust_page_allocator_init(
    total_memory_kb: u64,
) -> i32 {
    if ALLOCATOR_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    let total_pages = (total_memory_kb * 1024) / PAGE_SIZE as u64;
    let _ = total_pages;

    ALLOCATOR_INITIALIZED.store(true, Ordering::SeqCst);

    crate::ffi::bridge::log_info("Rust page frame allocator initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Get the page size in bytes
#[no_mangle]
pub extern "C" fn zxyphor_rust_page_size() -> usize {
    PAGE_SIZE
}

/// Get the maximum buddy order
#[no_mangle]
pub extern "C" fn zxyphor_rust_max_buddy_order() -> usize {
    MAX_ORDER
}
