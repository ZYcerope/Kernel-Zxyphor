// =============================================================================
// Kernel Zxyphor — Block I/O (BIO) Layer
// =============================================================================
// The BIO layer provides the lowest-level I/O abstraction between filesystems
// and block devices:
//   - BIO structures represent a single I/O operation with scatter-gather
//   - BIO chaining for split I/O operations
//   - Completion callbacks for async I/O
//   - Page-based I/O vectors (bio_vec) for zero-copy transfers
//   - BIO pool for pre-allocated structures (avoids allocation in I/O path)
//   - Error propagation and retry logic
//   - I/O accounting and statistics
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =============================================================================
// BIO vector (scatter-gather element)
// =============================================================================

/// A single page-based I/O vector
#[derive(Clone, Copy)]
pub struct BioVec {
    pub page_addr: u64,   // Physical address of the page
    pub offset: u16,      // Offset within the page
    pub length: u16,      // Number of bytes
}

impl BioVec {
    pub const fn new() -> Self {
        Self {
            page_addr: 0,
            offset: 0,
            length: 0,
        }
    }

    pub fn from_page(page_addr: u64, offset: u16, length: u16) -> Self {
        Self {
            page_addr,
            offset,
            length,
        }
    }

    /// End address within the page
    pub fn end_offset(&self) -> u16 {
        self.offset + self.length
    }

    /// Physical address of the start of data
    pub fn data_addr(&self) -> u64 {
        self.page_addr + self.offset as u64
    }
}

// =============================================================================
// BIO operation types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BioOp {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    WriteZeroes = 4,
    SecureErase = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BioFlags {
    None = 0x00,
    Sync = 0x01,       // Synchronous I/O
    Meta = 0x02,       // Metadata I/O
    Prio = 0x04,       // High priority
    Fua = 0x08,        // Force Unit Access
    Preflush = 0x10,   // Flush before write
    Rahead = 0x20,     // Read-ahead
    NoBounce = 0x40,   // Don't bounce buffer
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BioStatus {
    Pending = 0,
    InFlight = 1,
    Complete = 2,
    Error = 3,
}

// =============================================================================
// BIO structure
// =============================================================================

pub const MAX_BIO_VECS: usize = 16;

/// Completion callback type
pub type BioEndFn = extern "C" fn(bio_idx: u32, status: i32);

/// Block I/O request
pub struct Bio {
    pub op: BioOp,
    pub flags: u8,
    pub status: BioStatus,
    pub device_id: u16,
    pub sector: u64,          // Starting sector on the device
    pub size: u32,            // Total bytes to transfer
    pub vecs: [BioVec; MAX_BIO_VECS],
    pub vec_count: u8,
    pub vec_done: u8,         // Number of completed vecs
    pub error: i32,
    pub end_fn: Option<BioEndFn>,  // Completion callback
    pub private: u64,         // Private data for the callback
    pub chain_next: Option<u32>,   // Index of next BIO in chain
    pub submit_tsc: u64,      // TSC at submission
    pub complete_tsc: u64,    // TSC at completion
    pub retry_count: u8,
    pub max_retries: u8,
}

impl Bio {
    pub const fn new() -> Self {
        Self {
            op: BioOp::Read,
            flags: 0,
            status: BioStatus::Pending,
            device_id: 0,
            sector: 0,
            size: 0,
            vecs: [const { BioVec::new() }; MAX_BIO_VECS],
            vec_count: 0,
            vec_done: 0,
            error: 0,
            end_fn: None,
            private: 0,
            chain_next: None,
            submit_tsc: 0,
            complete_tsc: 0,
            retry_count: 0,
            max_retries: 3,
        }
    }

    /// Create a read BIO
    pub fn read(device_id: u16, sector: u64, page_addr: u64, size: u32) -> Self {
        let mut bio = Self::new();
        bio.op = BioOp::Read;
        bio.device_id = device_id;
        bio.sector = sector;
        bio.size = size;
        bio.add_page(page_addr, 0, size as u16);
        bio
    }

    /// Create a write BIO
    pub fn write(device_id: u16, sector: u64, page_addr: u64, size: u32) -> Self {
        let mut bio = Self::new();
        bio.op = BioOp::Write;
        bio.device_id = device_id;
        bio.sector = sector;
        bio.size = size;
        bio.add_page(page_addr, 0, size as u16);
        bio
    }

    /// Add a page to the scatter-gather list
    pub fn add_page(&mut self, page_addr: u64, offset: u16, length: u16) -> bool {
        if self.vec_count as usize >= MAX_BIO_VECS {
            return false;
        }
        self.vecs[self.vec_count as usize] = BioVec::from_page(page_addr, offset, length);
        self.vec_count += 1;
        true
    }

    /// Get the number of sectors this BIO covers
    pub fn sector_count(&self) -> u32 {
        (self.size + 511) / 512
    }

    /// Mark as completed with status
    pub fn complete(&mut self, error: i32, tsc: u64) {
        self.error = error;
        self.complete_tsc = tsc;
        self.status = if error == 0 {
            BioStatus::Complete
        } else {
            BioStatus::Error
        };
    }

    /// Check if a retry should be attempted
    pub fn should_retry(&self) -> bool {
        self.status == BioStatus::Error && self.retry_count < self.max_retries
    }

    /// Latency in TSC ticks
    pub fn latency(&self) -> u64 {
        if self.complete_tsc > self.submit_tsc {
            self.complete_tsc - self.submit_tsc
        } else {
            0
        }
    }

    /// Total scatter-gather byte count
    pub fn total_bytes(&self) -> u32 {
        let mut total: u32 = 0;
        for i in 0..self.vec_count as usize {
            total += self.vecs[i].length as u32;
        }
        total
    }

    /// Check if this is a write operation (including flush)
    pub fn is_write(&self) -> bool {
        matches!(self.op, BioOp::Write | BioOp::Flush)
    }
}

// =============================================================================
// BIO pool (pre-allocated BIO structures)
// =============================================================================

pub const BIO_POOL_SIZE: usize = 256;

pub struct BioPool {
    bios: [Bio; BIO_POOL_SIZE],
    free_bitmap: [u64; BIO_POOL_SIZE / 64],
    allocated: AtomicU32,
    completed: AtomicU64,
    errors: AtomicU64,
}

impl BioPool {
    pub const fn new() -> Self {
        Self {
            bios: [const { Bio::new() }; BIO_POOL_SIZE],
            free_bitmap: [u64::MAX; BIO_POOL_SIZE / 64],  // All bits set = all free
            allocated: AtomicU32::new(0),
            completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    /// Allocate a BIO from the pool
    pub fn alloc(&mut self) -> Option<u32> {
        for (word_idx, word) in self.free_bitmap.iter_mut().enumerate() {
            if *word == 0 {
                continue;
            }
            // Find first set bit
            let bit = (*word).trailing_zeros();
            if bit >= 64 {
                continue;
            }
            *word &= !(1u64 << bit);
            let idx = word_idx * 64 + bit as usize;
            if idx >= BIO_POOL_SIZE {
                return None;
            }
            self.bios[idx] = Bio::new();
            self.allocated.fetch_add(1, Ordering::Relaxed);
            return Some(idx as u32);
        }
        None
    }

    /// Free a BIO back to the pool
    pub fn free(&mut self, idx: u32) {
        let i = idx as usize;
        if i >= BIO_POOL_SIZE {
            return;
        }
        let word_idx = i / 64;
        let bit = i % 64;
        self.free_bitmap[word_idx] |= 1u64 << bit;
        self.allocated.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get a reference to a BIO by index
    pub fn get(&self, idx: u32) -> Option<&Bio> {
        let i = idx as usize;
        if i >= BIO_POOL_SIZE {
            return None;
        }
        // Check if allocated (bit should be 0)
        let word_idx = i / 64;
        let bit = i % 64;
        if self.free_bitmap[word_idx] & (1u64 << bit) != 0 {
            return None;  // Not allocated
        }
        Some(&self.bios[i])
    }

    /// Get a mutable reference to a BIO by index
    pub fn get_mut(&mut self, idx: u32) -> Option<&mut Bio> {
        let i = idx as usize;
        if i >= BIO_POOL_SIZE {
            return None;
        }
        let word_idx = i / 64;
        let bit = i % 64;
        if self.free_bitmap[word_idx] & (1u64 << bit) != 0 {
            return None;
        }
        Some(&mut self.bios[i])
    }

    /// Submit a BIO for processing
    pub fn submit(&mut self, idx: u32, tsc: u64) -> bool {
        if let Some(bio) = self.get_mut(idx) {
            bio.status = BioStatus::InFlight;
            bio.submit_tsc = tsc;
            true
        } else {
            false
        }
    }

    /// Complete a BIO
    pub fn complete_bio(&mut self, idx: u32, error: i32, tsc: u64) {
        if let Some(bio) = self.get_mut(idx) {
            bio.complete(error, tsc);

            if error == 0 {
                self.completed.fetch_add(1, Ordering::Relaxed);
            } else {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }

            // Call completion callback
            if let Some(end_fn) = bio.end_fn {
                end_fn(idx, error);
            }

            // Handle chain
            if let Some(next_idx) = bio.chain_next {
                if error == 0 {
                    self.submit(next_idx, tsc);
                } else {
                    // Propagate error to chain
                    self.complete_bio(next_idx, error, tsc);
                }
            }
        }
    }

    /// Retry a failed BIO
    pub fn retry(&mut self, idx: u32, tsc: u64) -> bool {
        if let Some(bio) = self.get_mut(idx) {
            if bio.should_retry() {
                bio.retry_count += 1;
                bio.status = BioStatus::Pending;
                bio.error = 0;
                self.submit(idx, tsc);
                return true;
            }
        }
        false
    }

    /// Number of currently allocated BIOs
    pub fn in_use(&self) -> u32 {
        self.allocated.load(Ordering::Relaxed)
    }

    /// Total completed BIOs
    pub fn total_completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    /// Total errored BIOs
    pub fn total_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
}

// =============================================================================
// BIO merge logic
// =============================================================================

/// Check if two BIOs can be merged (adjacent sectors, same operation)
pub fn can_merge(a: &Bio, b: &Bio) -> bool {
    if a.device_id != b.device_id {
        return false;
    }
    if a.op as u8 != b.op as u8 {
        return false;
    }
    // Check if sectors are adjacent
    let a_end = a.sector + a.sector_count() as u64;
    if a_end == b.sector {
        return true;
    }
    let b_end = b.sector + b.sector_count() as u64;
    if b_end == a.sector {
        return true;
    }
    false
}

/// Merge two BIOs (b is appended to a if adjacent)
pub fn try_merge(a: &mut Bio, b: &Bio) -> bool {
    if !can_merge(a, b) {
        return false;
    }

    // Only merge if we have room for more vecs
    let total_vecs = a.vec_count as usize + b.vec_count as usize;
    if total_vecs > MAX_BIO_VECS {
        return false;
    }

    let a_end = a.sector + a.sector_count() as u64;
    if a_end == b.sector {
        // Append b's vecs to a
        for i in 0..b.vec_count as usize {
            a.vecs[a.vec_count as usize] = b.vecs[i];
            a.vec_count += 1;
        }
        a.size += b.size;
        true
    } else {
        false
    }
}

// =============================================================================
// Global BIO pool
// =============================================================================

static mut BIO_POOL: BioPool = BioPool::new();

/// Get the global BIO pool
///
/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn pool() -> &'static mut BioPool {
    &mut *core::ptr::addr_of_mut!(BIO_POOL)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_bio_alloc() -> i32 {
    unsafe {
        match pool().alloc() {
            Some(idx) => idx as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_bio_free(idx: u32) {
    unsafe {
        pool().free(idx);
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_bio_submit(idx: u32, tsc: u64) -> i32 {
    unsafe {
        if pool().submit(idx, tsc) { 0 } else { -1 }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_bio_complete(idx: u32, error: i32, tsc: u64) {
    unsafe {
        pool().complete_bio(idx, error, tsc);
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_bio_in_use() -> u32 {
    unsafe { pool().in_use() }
}
