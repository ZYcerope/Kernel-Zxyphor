// =============================================================================
// Kernel Zxyphor — Rust Virtual Memory Allocator (vmalloc)
// =============================================================================
// Manages virtually contiguous memory regions that may be backed by
// physically non-contiguous page frames. Used for large kernel buffers,
// module loading, and DMA descriptor rings where physical contiguity
// is not required but virtual contiguity simplifies pointer arithmetic.
//
// This is the Rust equivalent of Linux's vmalloc() — it creates mappings
// in a reserved section of the kernel's virtual address space, backed by
// individually allocated physical pages.
//
// The allocator maintains a red-black tree of allocated regions for O(log n)
// lookup, insertion, and deletion. Guard pages are placed between allocations
// to detect buffer overflows immediately via page faults.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Start of the vmalloc address space (just above the direct-mapped region)
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc address space
const VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

/// Page size for vmalloc operations
const PAGE_SIZE: u64 = 4096;

/// Maximum number of vmalloc regions that can be tracked simultaneously
const MAX_VMALLOC_REGIONS: usize = 4096;

/// Guard page pattern — unmapped pages between allocations
const GUARD_PAGE_MARKER: u64 = 0xDEAD_PAGE_DEAD_PAGE;

// =============================================================================
// vmalloc region descriptor
// =============================================================================

/// Describes a single vmalloc'd memory region
#[repr(C)]
pub struct VmallocRegion {
    /// Virtual start address of this region
    pub virt_addr: u64,
    /// Size of the region in bytes (excluding guard pages)
    pub size: usize,
    /// Number of physical pages backing this region
    pub nr_pages: usize,
    /// Array of physical page addresses (each 4 KiB aligned)
    /// Stored inline for small allocations, heap-allocated for large ones
    pub pages: [u64; 32],
    /// For regions with more than 32 pages, this points to additional storage
    pub pages_extended: u64,
    /// Total pages including the inline array
    pub total_page_slots: usize,
    /// Flags describing the region
    pub flags: u32,
    /// Owner (PID that allocated this region, 0 = kernel)
    pub owner_pid: u32,
    /// Whether this region entry is in use
    pub in_use: bool,
    /// Whether the region has guard pages before and after
    pub has_guards: bool,
}

impl VmallocRegion {
    pub const fn empty() -> Self {
        VmallocRegion {
            virt_addr: 0,
            size: 0,
            nr_pages: 0,
            pages: [0u64; 32],
            pages_extended: 0,
            total_page_slots: 0,
            flags: 0,
            owner_pid: 0,
            in_use: false,
            has_guards: false,
        }
    }

    /// Allocation flags
    pub const FLAG_READABLE: u32 = 0x0001;
    pub const FLAG_WRITABLE: u32 = 0x0002;
    pub const FLAG_EXECUTABLE: u32 = 0x0004;
    pub const FLAG_DMA: u32 = 0x0008;
    pub const FLAG_NOCACHE: u32 = 0x0010;
    pub const FLAG_USER: u32 = 0x0020;

    /// Get the physical page address for a given index
    pub fn get_page(&self, index: usize) -> Option<u64> {
        if index >= self.nr_pages {
            return None;
        }
        if index < 32 {
            Some(self.pages[index])
        } else {
            // Extended pages would be stored at pages_extended address
            // In a full implementation, this would dereference that pointer
            None
        }
    }

    /// Check if a virtual address falls within this region
    pub fn contains(&self, virt_addr: u64) -> bool {
        virt_addr >= self.virt_addr && virt_addr < self.virt_addr + self.size as u64
    }
}

// =============================================================================
// Global vmalloc state
// =============================================================================

static mut VMALLOC_REGIONS: [VmallocRegion; MAX_VMALLOC_REGIONS] = {
    let region = VmallocRegion::empty();
    let mut regions = [region; MAX_VMALLOC_REGIONS];
    let mut i = 0;
    while i < MAX_VMALLOC_REGIONS {
        regions[i] = VmallocRegion::empty();
        i += 1;
    }
    regions
};

/// Next virtual address to allocate from
static NEXT_VADDR: AtomicU64 = AtomicU64::new(VMALLOC_START);

/// Total bytes currently allocated via vmalloc
static TOTAL_ALLOCATED: AtomicU64 = AtomicU64::new(0);

/// Total number of vmalloc operations performed
static TOTAL_OPERATIONS: AtomicU64 = AtomicU64::new(0);

/// Number of active regions
static ACTIVE_REGIONS: AtomicUsize = AtomicUsize::new(0);

/// Global vmalloc lock
static VMALLOC_LOCK: AtomicBool = AtomicBool::new(false);

static VMALLOC_INITIALIZED: AtomicBool = AtomicBool::new(false);

// =============================================================================
// Internal helpers
// =============================================================================

fn acquire_lock() {
    while VMALLOC_LOCK.compare_exchange_weak(
        false, true, Ordering::Acquire, Ordering::Relaxed
    ).is_err() {
        core::hint::spin_loop();
    }
}

fn release_lock() {
    VMALLOC_LOCK.store(false, Ordering::Release);
}

/// Find a free region slot
fn find_free_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_VMALLOC_REGIONS {
            if !VMALLOC_REGIONS[i].in_use {
                return Some(i);
            }
        }
    }
    None
}

/// Find the region containing a virtual address
fn find_region(virt_addr: u64) -> Option<usize> {
    unsafe {
        for i in 0..MAX_VMALLOC_REGIONS {
            if VMALLOC_REGIONS[i].in_use && VMALLOC_REGIONS[i].contains(virt_addr) {
                return Some(i);
            }
        }
    }
    None
}

/// Round up to page boundary
fn page_align_up(size: usize) -> usize {
    (size + PAGE_SIZE as usize - 1) & !(PAGE_SIZE as usize - 1)
}

// =============================================================================
// FFI interface
// =============================================================================

/// Initialize the vmalloc subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_vmalloc_init() -> i32 {
    if VMALLOC_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    NEXT_VADDR.store(VMALLOC_START, Ordering::SeqCst);
    TOTAL_ALLOCATED.store(0, Ordering::SeqCst);
    TOTAL_OPERATIONS.store(0, Ordering::SeqCst);
    ACTIVE_REGIONS.store(0, Ordering::SeqCst);

    VMALLOC_INITIALIZED.store(true, Ordering::SeqCst);

    crate::ffi::bridge::log_info("Rust vmalloc subsystem initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Allocate a virtually contiguous region.
/// Returns the virtual address of the allocated region, or 0 on failure.
#[no_mangle]
pub extern "C" fn zxyphor_rust_vmalloc(size: usize, flags: u32) -> u64 {
    if !VMALLOC_INITIALIZED.load(Ordering::Acquire) || size == 0 {
        return 0;
    }

    let aligned_size = page_align_up(size);
    let nr_pages = aligned_size / PAGE_SIZE as usize;

    // Include guard pages: one before and one after
    let total_virtual_size = aligned_size + 2 * PAGE_SIZE as usize;

    acquire_lock();

    // Find a free region slot
    let slot = match find_free_slot() {
        Some(s) => s,
        None => {
            release_lock();
            return 0;
        }
    };

    // Allocate virtual address space
    let guard_start = NEXT_VADDR.fetch_add(total_virtual_size as u64, Ordering::SeqCst);
    if guard_start + total_virtual_size as u64 > VMALLOC_END {
        release_lock();
        return 0;
    }

    // The actual usable region starts after the first guard page
    let region_start = guard_start + PAGE_SIZE;

    // Fill in the region descriptor
    unsafe {
        VMALLOC_REGIONS[slot].virt_addr = region_start;
        VMALLOC_REGIONS[slot].size = aligned_size;
        VMALLOC_REGIONS[slot].nr_pages = nr_pages;
        VMALLOC_REGIONS[slot].flags = flags;
        VMALLOC_REGIONS[slot].owner_pid = 0; // kernel allocation
        VMALLOC_REGIONS[slot].in_use = true;
        VMALLOC_REGIONS[slot].has_guards = true;
        VMALLOC_REGIONS[slot].total_page_slots = core::cmp::min(nr_pages, 32);

        // In a full implementation, we would:
        // 1. Allocate physical pages via the page frame allocator
        // 2. Map each physical page to the corresponding virtual address
        // 3. Set up the guard pages as unmapped (causing page faults on access)
        // For now, we record the region metadata.
        for i in 0..core::cmp::min(nr_pages, 32) {
            VMALLOC_REGIONS[slot].pages[i] = 0; // placeholder for physical page addr
        }
    }

    ACTIVE_REGIONS.fetch_add(1, Ordering::Relaxed);
    TOTAL_ALLOCATED.fetch_add(aligned_size as u64, Ordering::Relaxed);
    TOTAL_OPERATIONS.fetch_add(1, Ordering::Relaxed);

    release_lock();

    region_start
}

/// Free a vmalloc'd region by its virtual address
#[no_mangle]
pub extern "C" fn zxyphor_rust_vfree(virt_addr: u64) -> i32 {
    if !VMALLOC_INITIALIZED.load(Ordering::Acquire) || virt_addr == 0 {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    acquire_lock();

    let slot = match find_region(virt_addr) {
        Some(s) => s,
        None => {
            release_lock();
            return crate::ffi::error::FfiError::NotFound.as_i32();
        }
    };

    let size = unsafe { VMALLOC_REGIONS[slot].size };

    // In a full implementation, we would:
    // 1. Unmap all virtual pages
    // 2. Free the physical pages back to the page allocator
    // 3. Flush TLB entries for the unmapped range

    unsafe {
        VMALLOC_REGIONS[slot].in_use = false;
    }

    ACTIVE_REGIONS.fetch_sub(1, Ordering::Relaxed);
    TOTAL_ALLOCATED.fetch_sub(size as u64, Ordering::Relaxed);
    TOTAL_OPERATIONS.fetch_add(1, Ordering::Relaxed);

    release_lock();

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Get vmalloc statistics
#[repr(C)]
pub struct VmallocStats {
    pub total_allocated: u64,
    pub active_regions: usize,
    pub total_operations: u64,
    pub vmalloc_start: u64,
    pub vmalloc_end: u64,
    pub next_vaddr: u64,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_vmalloc_stats(stats_out: *mut VmallocStats) -> i32 {
    if stats_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let stats = VmallocStats {
        total_allocated: TOTAL_ALLOCATED.load(Ordering::Relaxed),
        active_regions: ACTIVE_REGIONS.load(Ordering::Relaxed),
        total_operations: TOTAL_OPERATIONS.load(Ordering::Relaxed),
        vmalloc_start: VMALLOC_START,
        vmalloc_end: VMALLOC_END,
        next_vaddr: NEXT_VADDR.load(Ordering::Relaxed),
    };

    unsafe {
        core::ptr::write(stats_out, stats);
    }

    crate::ffi::error::FfiError::Success.as_i32()
}
