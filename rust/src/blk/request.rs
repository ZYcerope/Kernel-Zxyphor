// =============================================================================
// Kernel Zxyphor — Block I/O Request Queue
// =============================================================================
// Manages block I/O requests: bio submission, merging, splitting, completion.
// Implements bio-to-request conversion, request plugging, and I/O accounting.
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =============================================================================
// Constants
// =============================================================================

pub const MAX_BIO_SEGMENTS: usize = 128;
pub const MAX_REQUESTS: usize = 256;
pub const MAX_DEVICES: usize = 16;
pub const SECTOR_SIZE: u64 = 512;
pub const PAGE_SIZE: u64 = 4096;
pub const SECTORS_PER_PAGE: u64 = PAGE_SIZE / SECTOR_SIZE;

// =============================================================================
// Bio operation flags
// =============================================================================

pub const BIO_READ: u32 = 0;
pub const BIO_WRITE: u32 = 1;
pub const BIO_FLUSH: u32 = 1 << 1;
pub const BIO_FUA: u32 = 1 << 2;       // Force Unit Access
pub const BIO_DISCARD: u32 = 1 << 3;
pub const BIO_SECURE_ERASE: u32 = 1 << 4;
pub const BIO_WRITE_ZEROES: u32 = 1 << 5;
pub const BIO_PREFLUSH: u32 = 1 << 6;
pub const BIO_SYNC: u32 = 1 << 7;
pub const BIO_META: u32 = 1 << 8;      // Metadata I/O
pub const BIO_PRIO: u32 = 1 << 9;      // High priority
pub const BIO_NOMERGE: u32 = 1 << 10;  // Don't merge

// =============================================================================
// I/O priority classes (matching Linux IOPRIO)
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum IoPriority {
    None = 0,
    RealTime = 1,    // RT class (highest)
    BestEffort = 2,  // BE class (default)
    Idle = 3,         // Idle class (lowest)
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum BioStatus {
    Pending = 0,
    InFlight = 1,
    Complete = 2,
    Error = 3,
    Timeout = 4,
}

// =============================================================================
// Bio segment (scatter-gather entry)
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BioVec {
    pub page_phys: u64,      // Physical page address
    pub offset: u32,          // Offset within page
    pub len: u32,             // Length in bytes
}

impl BioVec {
    pub const fn new() Self {
        Self {
            page_phys: 0,
            offset: 0,
            len: 0,
        }
    }

    pub fn sector_count(&self) u64 {
        (self.len as u64 + SECTOR_SIZE - 1) / SECTOR_SIZE
    }
}

// =============================================================================
// Bio (block I/O operation)
// =============================================================================

#[repr(C)]
pub struct Bio {
    pub sector: u64,             // Starting sector
    pub nr_sectors: u64,         // Number of sectors
    pub op_flags: u32,           // Operation + flags
    pub status: BioStatus,
    pub priority: IoPriority,
    pub ioprio_value: u8,        // 0-7 within class

    // Scatter-gather list
    pub bi_vec: [BioVec; MAX_BIO_SEGMENTS],
    pub bi_vcnt: u16,            // Number of segments
    pub bi_idx: u16,             // Current segment index

    // Tracking
    pub bi_size: u32,            // Remaining bytes
    pub bi_max_vecs: u16,
    pub device_id: u16,

    // Completion
    pub bi_end_io: Option<extern "C" fn(bio_id: u32, status: i32)>,
    pub bi_private: u64,

    // Chain / split
    pub bi_next: u32,            // Index of next bio (0xFFFFFFFF = none)
    pub bi_parent: u32,          // Parent bio if split

    // Timestamps
    pub submit_ns: u64,
    pub complete_ns: u64,
}

impl Bio {
    pub const fn new() Self {
        Self {
            sector: 0,
            nr_sectors: 0,
            op_flags: 0,
            status: BioStatus::Pending,
            priority: IoPriority::BestEffort,
            ioprio_value: 4,
            bi_vec: [BioVec::new(); MAX_BIO_SEGMENTS],
            bi_vcnt: 0,
            bi_idx: 0,
            bi_size: 0,
            bi_max_vecs: MAX_BIO_SEGMENTS as u16,
            device_id: 0,
            bi_end_io: None,
            bi_private: 0,
            bi_next: 0xFFFFFFFF,
            bi_parent: 0xFFFFFFFF,
            submit_ns: 0,
            complete_ns: 0,
        }
    }

    pub fn is_read(&self) -> bool {
        (self.op_flags & BIO_WRITE) == 0
    }

    pub fn is_write(&self) -> bool {
        (self.op_flags & BIO_WRITE) != 0
    }

    pub fn is_flush(&self) -> bool {
        (self.op_flags & (BIO_FLUSH | BIO_PREFLUSH)) != 0
    }

    pub fn is_discard(&self) -> bool {
        (self.op_flags & BIO_DISCARD) != 0
    }

    pub fn is_fua(&self) -> bool {
        (self.op_flags & BIO_FUA) != 0
    }

    pub fn end_sector(&self) -> u64 {
        self.sector + self.nr_sectors
    }

    /// Add a segment to the bio
    pub fn add_page(&mut self, phys: u64, offset: u32, len: u32) -> bool {
        if self.bi_vcnt >= self.bi_max_vecs {
            return false;
        }

        // Try to merge with last segment
        if self.bi_vcnt > 0 {
            let last = &mut self.bi_vec[self.bi_vcnt as usize - 1];
            if last.page_phys + last.offset as u64 + last.len as u64 == phys + offset as u64 {
                last.len += len;
                self.bi_size += len;
                self.nr_sectors = (self.bi_size as u64 + SECTOR_SIZE - 1) / SECTOR_SIZE;
                return true;
            }
        }

        let idx = self.bi_vcnt as usize;
        self.bi_vec[idx] = BioVec {
            page_phys: phys,
            offset,
            len,
        };
        self.bi_vcnt += 1;
        self.bi_size += len;
        self.nr_sectors = (self.bi_size as u64 + SECTOR_SIZE - 1) / SECTOR_SIZE;
        true
    }

    /// Split a bio at a given sector boundary
    pub fn split_at(&mut self, sector: u64) -> Bio {
        let mut new_bio = Bio::new();
        new_bio.sector = self.sector + sector;
        new_bio.nr_sectors = self.nr_sectors - sector;
        new_bio.op_flags = self.op_flags;
        new_bio.priority = self.priority;
        new_bio.ioprio_value = self.ioprio_value;
        new_bio.device_id = self.device_id;
        new_bio.bi_parent = 0xFFFFFFFF;

        self.nr_sectors = sector;
        self.bi_size = (sector * SECTOR_SIZE) as u32;

        new_bio
    }
}

// =============================================================================
// Block I/O request (merged bios)
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum RequestState {
    Free = 0,
    Pending = 1,
    InFlight = 2,
    Complete = 3,
    Error = 4,
}

#[repr(C)]
pub struct Request {
    pub id: u32,
    pub state: RequestState,
    pub sector: u64,
    pub nr_sectors: u64,
    pub op_flags: u32,
    pub priority: IoPriority,
    pub ioprio_value: u8,

    // Bio chain
    pub bio_head: u32,  // First bio index
    pub bio_tail: u32,  // Last bio index
    pub bio_count: u16,

    // Queue linkage
    pub next: u32,
    pub prev: u32,

    // Tag for blk-mq
    pub tag: u16,
    pub hw_queue: u8,

    // Timing
    pub start_ns: u64,
    pub io_start_ns: u64,
    pub deadline_ns: u64,

    // Stats
    pub nr_phys_segments: u16,
    pub errors: u16,
}

impl Request {
    pub const fn new() Self {
        Self {
            id: 0,
            state: RequestState::Free,
            sector: 0,
            nr_sectors: 0,
            op_flags: 0,
            priority: IoPriority::BestEffort,
            ioprio_value: 4,
            bio_head: 0xFFFFFFFF,
            bio_tail: 0xFFFFFFFF,
            bio_count: 0,
            next: 0xFFFFFFFF,
            prev: 0xFFFFFFFF,
            tag: 0xFFFF,
            hw_queue: 0,
            start_ns: 0,
            io_start_ns: 0,
            deadline_ns: 0,
            nr_phys_segments: 0,
            errors: 0,
        }
    }

    pub fn is_read(&self) -> bool {
        (self.op_flags & BIO_WRITE) == 0
    }

    pub fn is_write(&self) -> bool {
        (self.op_flags & BIO_WRITE) != 0
    }

    pub fn end_sector(&self) -> u64 {
        self.sector + self.nr_sectors
    }

    /// Check if a bio can be merged into this request (back merge)
    pub fn can_back_merge(&self, bio: &Bio) -> bool {
        if self.state != RequestState::Pending {
            return false;
        }
        if (bio.op_flags & BIO_NOMERGE) != 0 {
            return false;
        }
        if self.op_flags != bio.op_flags {
            return false;
        }
        self.end_sector() == bio.sector
    }

    /// Check if a bio can be merged (front merge)
    pub fn can_front_merge(&self, bio: &Bio) -> bool {
        if self.state != RequestState::Pending {
            return false;
        }
        if (bio.op_flags & BIO_NOMERGE) != 0 {
            return false;
        }
        if self.op_flags != bio.op_flags {
            return false;
        }
        bio.end_sector() == self.sector
    }

    /// Merge a bio at the back
    pub fn back_merge(&mut self, bio: &Bio) {
        self.nr_sectors += bio.nr_sectors;
        self.bio_count += 1;
    }

    /// Merge a bio at the front
    pub fn front_merge(&mut self, bio: &Bio) {
        self.sector = bio.sector;
        self.nr_sectors += bio.nr_sectors;
        self.bio_count += 1;
    }
}

// =============================================================================
// I/O accounting
// =============================================================================

#[repr(C)]
pub struct IoStats {
    pub read_ios: AtomicU64,
    pub read_sectors: AtomicU64,
    pub read_ticks_ms: AtomicU64,
    pub write_ios: AtomicU64,
    pub write_sectors: AtomicU64,
    pub write_ticks_ms: AtomicU64,
    pub discard_ios: AtomicU64,
    pub flush_ios: AtomicU64,
    pub in_flight: AtomicU32,
    pub io_ticks_ms: AtomicU64,
    pub time_in_queue_ms: AtomicU64,
}

impl IoStats {
    pub const fn new() Self {
        Self {
            read_ios: AtomicU64::new(0),
            read_sectors: AtomicU64::new(0),
            read_ticks_ms: AtomicU64::new(0),
            write_ios: AtomicU64::new(0),
            write_sectors: AtomicU64::new(0),
            write_ticks_ms: AtomicU64::new(0),
            discard_ios: AtomicU64::new(0),
            flush_ios: AtomicU64::new(0),
            in_flight: AtomicU32::new(0),
            io_ticks_ms: AtomicU64::new(0),
            time_in_queue_ms: AtomicU64::new(0),
        }
    }

    pub fn account_start(&self, req: &Request) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        if req.is_read() {
            self.read_ios.fetch_add(1, Ordering::Relaxed);
            self.read_sectors.fetch_add(req.nr_sectors, Ordering::Relaxed);
        } else if req.is_write() {
            self.write_ios.fetch_add(1, Ordering::Relaxed);
            self.write_sectors.fetch_add(req.nr_sectors, Ordering::Relaxed);
        }
    }

    pub fn account_end(&self, _req: &Request, duration_ms: u64) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.io_ticks_ms.fetch_add(duration_ms, Ordering::Relaxed);
        self.time_in_queue_ms.fetch_add(duration_ms, Ordering::Relaxed);
    }
}

// =============================================================================
// Block device descriptor
// =============================================================================

#[repr(C)]
pub struct BlockDevice {
    pub id: u16,
    pub active: bool,
    pub name: [u8; 16],
    pub sector_size: u32,
    pub nr_sectors: u64,         // Total device size in sectors
    pub max_sectors: u32,        // Max sectors per request
    pub max_segments: u16,       // Max scatter-gather segments
    pub max_segment_size: u32,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub alignment_offset: u32,
    pub discard_max_sectors: u64,
    pub write_zeroes_max: u64,

    // Features
    pub rotational: bool,        // HDD=true, SSD=false
    pub supports_discard: bool,
    pub supports_fua: bool,
    pub supports_flush: bool,
    pub read_only: bool,
    pub removable: bool,

    // Queue
    pub queue_depth: u16,
    pub nr_hw_queues: u8,

    // Stats
    pub stats: IoStats,
}

impl BlockDevice {
    pub const fn new() Self {
        Self {
            id: 0,
            active: false,
            name: [0u8; 16],
            sector_size: 512,
            nr_sectors: 0,
            max_sectors: 256,
            max_segments: 128,
            max_segment_size: 65536,
            logical_block_size: 512,
            physical_block_size: 512,
            alignment_offset: 0,
            discard_max_sectors: 0,
            write_zeroes_max: 0,
            rotational: true,
            supports_discard: false,
            supports_fua: false,
            supports_flush: true,
            read_only: false,
            removable: false,
            queue_depth: 32,
            nr_hw_queues: 1,
            stats: IoStats::new(),
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.nr_sectors * self.sector_size as u64
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > 15 { 15 } else { name.len() };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;
    }
}

// =============================================================================
// Request queue
// =============================================================================

pub const MAX_BIO_POOL: usize = 512;

pub struct RequestQueue {
    // Request pool
    pub requests: [Request; MAX_REQUESTS],
    pub request_count: u32,

    // Bio pool
    pub bios: [Bio; MAX_BIO_POOL],
    pub bio_count: u32,

    // Pending request list (sorted by sector for merging)
    pub pending_head: u32,
    pub pending_count: u32,

    // Dispatch queue (ready for hardware)
    pub dispatch_head: u32,
    pub dispatch_count: u32,

    // Plugging state
    pub plugged: bool,
    pub plug_count: u32,
    pub unplug_threshold: u32,

    // Devices
    pub devices: [BlockDevice; MAX_DEVICES],
    pub device_count: u16,

    // Global stats
    pub total_submitted: u64,
    pub total_completed: u64,
    pub total_merged: u64,
}

impl RequestQueue {
    pub const fn new() Self {
        Self {
            requests: [const { Request::new() }; MAX_REQUESTS],
            request_count: 0,
            bios: [const { Bio::new() }; MAX_BIO_POOL],
            bio_count: 0,
            pending_head: 0xFFFFFFFF,
            pending_count: 0,
            dispatch_head: 0xFFFFFFFF,
            dispatch_count: 0,
            plugged: false,
            plug_count: 0,
            unplug_threshold: 16,
            devices: [const { BlockDevice::new() }; MAX_DEVICES],
            device_count: 0,
            total_submitted: 0,
            total_completed: 0,
            total_merged: 0,
        }
    }

    /// Register a block device
    pub fn register_device(&mut self, name: &[u8], nr_sectors: u64, rotational: bool) -> Option<u16> {
        if self.device_count >= MAX_DEVICES as u16 {
            return None;
        }
        let id = self.device_count;
        self.devices[id as usize].id = id;
        self.devices[id as usize].active = true;
        self.devices[id as usize].set_name(name);
        self.devices[id as usize].nr_sectors = nr_sectors;
        self.devices[id as usize].rotational = rotational;
        if !rotational {
            self.devices[id as usize].supports_discard = true;
        }
        self.device_count += 1;
        Some(id)
    }

    /// Allocate a bio from the pool
    pub fn alloc_bio(&mut self) -> Option<u32> {
        for i in 0..MAX_BIO_POOL {
            if self.bios[i].status == BioStatus::Complete || 
               (self.bios[i].status == BioStatus::Pending && self.bios[i].bi_size == 0 && self.bios[i].sector == 0) {
                self.bios[i] = Bio::new();
                self.bio_count += 1;
                return Some(i as u32);
            }
        }
        None
    }

    /// Allocate a request from the pool
    fn alloc_request(&mut self) -> Option<u32> {
        for i in 0..MAX_REQUESTS {
            if self.requests[i].state == RequestState::Free {
                self.requests[i] = Request::new();
                self.requests[i].id = i as u32;
                self.requests[i].state = RequestState::Pending;
                self.request_count += 1;
                return Some(i as u32);
            }
        }
        None
    }

    /// Submit a bio for processing
    pub fn submit_bio(&mut self, bio_idx: u32) -> bool {
        if bio_idx >= MAX_BIO_POOL as u32 {
            return false;
        }
        let bio = &self.bios[bio_idx as usize];
        if bio.bi_size == 0 && !bio.is_flush() {
            return false;
        }

        self.total_submitted += 1;

        // Try to merge with existing pending request
        if (bio.op_flags & BIO_NOMERGE) == 0 {
            if self.try_merge(bio_idx) {
                self.total_merged += 1;
                return true;
            }
        }

        // Create new request
        if let Some(req_idx) = self.alloc_request() {
            let bio = &self.bios[bio_idx as usize];
            let req = &mut self.requests[req_idx as usize];
            req.sector = bio.sector;
            req.nr_sectors = bio.nr_sectors;
            req.op_flags = bio.op_flags;
            req.priority = bio.priority;
            req.ioprio_value = bio.ioprio_value;
            req.bio_head = bio_idx;
            req.bio_tail = bio_idx;
            req.bio_count = 1;
            req.nr_phys_segments = bio.bi_vcnt;

            // Add to pending queue
            self.add_to_pending(req_idx);

            // Auto-unplug if threshold reached
            if self.plugged {
                self.plug_count += 1;
                if self.plug_count >= self.unplug_threshold {
                    self.unplug();
                }
            }
            return true;
        }
        false
    }

    /// Try to merge bio with existing request
    fn try_merge(&mut self, bio_idx: u32) -> bool {
        let bio_sector = self.bios[bio_idx as usize].sector;
        let bio_end = self.bios[bio_idx as usize].end_sector();
        let bio_flags = self.bios[bio_idx as usize].op_flags;

        let mut req_idx = self.pending_head;
        while req_idx != 0xFFFFFFFF {
            let next = self.requests[req_idx as usize].next;

            // Back merge check
            if self.requests[req_idx as usize].end_sector() == bio_sector 
                && self.requests[req_idx as usize].op_flags == bio_flags
                && self.requests[req_idx as usize].state == RequestState::Pending
            {
                let bio = &self.bios[bio_idx as usize];
                self.requests[req_idx as usize].back_merge(bio);
                return true;
            }

            // Front merge check
            if self.requests[req_idx as usize].sector == bio_end
                && self.requests[req_idx as usize].op_flags == bio_flags
                && self.requests[req_idx as usize].state == RequestState::Pending
            {
                let bio = &self.bios[bio_idx as usize];
                self.requests[req_idx as usize].front_merge(bio);
                return true;
            }

            req_idx = next;
        }
        false
    }

    /// Add request to pending list (sorted by sector)
    fn add_to_pending(&mut self, req_idx: u32) {
        let sector = self.requests[req_idx as usize].sector;

        if self.pending_head == 0xFFFFFFFF {
            self.pending_head = req_idx;
            self.requests[req_idx as usize].next = 0xFFFFFFFF;
            self.requests[req_idx as usize].prev = 0xFFFFFFFF;
        } else {
            // Find insertion point (sorted by sector)
            let mut cur = self.pending_head;
            let mut prev = 0xFFFFFFFF;
            while cur != 0xFFFFFFFF && self.requests[cur as usize].sector < sector {
                prev = cur;
                cur = self.requests[cur as usize].next;
            }

            self.requests[req_idx as usize].next = cur;
            self.requests[req_idx as usize].prev = prev;

            if cur != 0xFFFFFFFF {
                self.requests[cur as usize].prev = req_idx;
            }
            if prev != 0xFFFFFFFF {
                self.requests[prev as usize].next = req_idx;
            } else {
                self.pending_head = req_idx;
            }
        }
        self.pending_count += 1;
    }

    /// Plug the queue (batch requests)
    pub fn plug(&mut self) {
        self.plugged = true;
        self.plug_count = 0;
    }

    /// Unplug the queue (flush pending to dispatch)
    pub fn unplug(&mut self) {
        self.plugged = false;
        self.plug_count = 0;

        // Move all pending requests to dispatch queue
        let mut req_idx = self.pending_head;
        while req_idx != 0xFFFFFFFF {
            let next = self.requests[req_idx as usize].next;

            // Move to dispatch
            self.requests[req_idx as usize].next = self.dispatch_head;
            self.dispatch_head = req_idx;
            self.dispatch_count += 1;

            req_idx = next;
        }
        self.pending_head = 0xFFFFFFFF;
        self.pending_count = 0;
    }

    /// Get next request from dispatch queue
    pub fn fetch_request(&mut self) -> Option<u32> {
        if self.dispatch_head == 0xFFFFFFFF {
            // Auto-unplug if there are pending requests
            if self.pending_count > 0 {
                self.unplug();
                if self.dispatch_head != 0xFFFFFFFF {
                    let idx = self.dispatch_head;
                    self.dispatch_head = self.requests[idx as usize].next;
                    self.dispatch_count -= 1;
                    self.requests[idx as usize].state = RequestState::InFlight;
                    return Some(idx);
                }
            }
            return None;
        }

        let idx = self.dispatch_head;
        self.dispatch_head = self.requests[idx as usize].next;
        self.dispatch_count -= 1;
        self.requests[idx as usize].state = RequestState::InFlight;
        Some(idx)
    }

    /// Complete a request
    pub fn complete_request(&mut self, req_idx: u32) {
        if req_idx >= MAX_REQUESTS as u32 {
            return;
        }
        self.requests[req_idx as usize].state = RequestState::Complete;
        self.total_completed += 1;

        // Notify bio completion callbacks
        let bio_head = self.requests[req_idx as usize].bio_head;
        if bio_head != 0xFFFFFFFF && (bio_head as usize) < MAX_BIO_POOL {
            let bio = &mut self.bios[bio_head as usize];
            bio.status = BioStatus::Complete;
            if let Some(callback) = bio.bi_end_io {
                callback(bio_head, 0); // 0 = success
            }
        }

        // Free the request
        self.requests[req_idx as usize].state = RequestState::Free;
        self.request_count -= 1;
    }

    /// Error a request
    pub fn error_request(&mut self, req_idx: u32, error: i32) {
        if req_idx >= MAX_REQUESTS as u32 {
            return;
        }
        self.requests[req_idx as usize].state = RequestState::Error;
        self.requests[req_idx as usize].errors += 1;

        let bio_head = self.requests[req_idx as usize].bio_head;
        if bio_head != 0xFFFFFFFF && (bio_head as usize) < MAX_BIO_POOL {
            let bio = &mut self.bios[bio_head as usize];
            bio.status = BioStatus::Error;
            if let Some(callback) = bio.bi_end_io {
                callback(bio_head, error);
            }
        }

        self.requests[req_idx as usize].state = RequestState::Free;
        self.request_count -= 1;
    }
}

// =============================================================================
// Global request queue
// =============================================================================

static mut REQUEST_QUEUE: RequestQueue = RequestQueue::new();

fn queue() -> &'static mut RequestQueue {
    unsafe { &mut REQUEST_QUEUE }
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_blk_register_device(
    name_ptr: *const u8,
    name_len: u32,
    nr_sectors: u64,
    rotational: bool,
) -> i32 {
    let q = queue();
    let name = if !name_ptr.is_null() && name_len > 0 {
        unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) }
    } else {
        b"unknown"
    };
    match q.register_device(name, nr_sectors, rotational) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_alloc_bio() -> i32 {
    match queue().alloc_bio() {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_bio_set_sector(bio_id: u32, sector: u64) {
    let q = queue();
    if (bio_id as usize) < MAX_BIO_POOL {
        q.bios[bio_id as usize].sector = sector;
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_bio_set_op(bio_id: u32, op_flags: u32) {
    let q = queue();
    if (bio_id as usize) < MAX_BIO_POOL {
        q.bios[bio_id as usize].op_flags = op_flags;
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_bio_add_page(bio_id: u32, phys: u64, offset: u32, len: u32) -> i32 {
    let q = queue();
    if (bio_id as usize) < MAX_BIO_POOL {
        if q.bios[bio_id as usize].add_page(phys, offset, len) {
            return 0;
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_submit_bio(bio_id: u32) -> i32 {
    if queue().submit_bio(bio_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_fetch_request() -> i32 {
    match queue().fetch_request() {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_complete_request(req_id: u32) {
    queue().complete_request(req_id);
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_plug() {
    queue().plug();
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_unplug() {
    queue().unplug();
}

#[no_mangle]
pub extern "C" fn zxyphor_blk_stats(device_id: u16) -> u64 {
    let q = queue();
    if (device_id as usize) < MAX_DEVICES {
        q.devices[device_id as usize].stats.read_ios.load(Ordering::Relaxed)
            + q.devices[device_id as usize].stats.write_ios.load(Ordering::Relaxed)
    } else {
        0
    }
}
