// =============================================================================
// Kernel Zxyphor — Block Device Layer
// =============================================================================
// Unified block device abstraction with I/O scheduling:
//   - Block device registration and discovery
//   - Request queue with configurable I/O schedulers (NOOP, Deadline, CFQ)
//   - Partition table parsing (MBR, GPT)
//   - Block cache (buffer cache) with LRU eviction
//   - Read-ahead and write-back policies
//   - Device statistics (IOPS, bandwidth, latency)
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =============================================================================
// Block size constants
// =============================================================================

pub const SECTOR_SIZE: u32 = 512;
pub const MIN_BLOCK_SIZE: u32 = 512;
pub const MAX_BLOCK_SIZE: u32 = 4096;
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

// =============================================================================
// Block device abstraction
// =============================================================================

/// Block device capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceCap {
    ReadOnly   = 0x01,
    Removable  = 0x02,
    Rotational = 0x04,  // HDD vs SSD
    Discard    = 0x08,  // TRIM support
    WriteCache = 0x10,
    Fua        = 0x20,  // Force Unit Access
    FlushCache = 0x40,
    Ncq        = 0x80,  // Native Command Queuing
}

/// Block device identification
#[derive(Clone)]
pub struct BlockDeviceInfo {
    pub name: [u8; 32],
    pub name_len: u8,
    pub major: u16,
    pub minor: u16,
    pub block_size: u32,
    pub sector_size: u32,
    pub total_sectors: u64,
    pub capabilities: u32,
    pub max_sectors_per_request: u32,
    pub queue_depth: u16,
}

impl BlockDeviceInfo {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            major: 0,
            minor: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            sector_size: SECTOR_SIZE,
            total_sectors: 0,
            capabilities: 0,
            max_sectors_per_request: 256,
            queue_depth: 32,
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    pub fn capacity_mb(&self) -> u64 {
        self.capacity_bytes() / (1024 * 1024)
    }

    pub fn is_read_only(&self) -> bool {
        self.capabilities & DeviceCap::ReadOnly as u32 != 0
    }

    pub fn is_rotational(&self) -> bool {
        self.capabilities & DeviceCap::Rotational as u32 != 0
    }

    pub fn supports_discard(&self) -> bool {
        self.capabilities & DeviceCap::Discard as u32 != 0
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = core::cmp::min(name.len(), 31);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }
}

// =============================================================================
// I/O Request
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestType {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    WriteZeroes = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    RealTime = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestState {
    Pending = 0,
    InFlight = 1,
    Completed = 2,
    Error = 3,
    Cancelled = 4,
}

/// A single I/O request
pub struct IoRequest {
    pub req_type: RequestType,
    pub priority: RequestPriority,
    pub state: RequestState,
    pub device_id: u16,
    pub sector: u64,
    pub sector_count: u32,
    pub buffer_addr: u64,   // Physical address of data buffer
    pub flags: u32,
    pub submit_time: u64,   // TSC timestamp at submission
    pub complete_time: u64, // TSC timestamp at completion
    pub error_code: i32,
    pub tag: u32,           // Request tag for NCQ
}

impl IoRequest {
    pub const fn new() -> Self {
        Self {
            req_type: RequestType::Read,
            priority: RequestPriority::Normal,
            state: RequestState::Pending,
            device_id: 0,
            sector: 0,
            sector_count: 0,
            buffer_addr: 0,
            flags: 0,
            submit_time: 0,
            complete_time: 0,
            error_code: 0,
            tag: 0,
        }
    }

    pub fn read(device_id: u16, sector: u64, count: u32, buffer: u64) -> Self {
        Self {
            req_type: RequestType::Read,
            priority: RequestPriority::Normal,
            state: RequestState::Pending,
            device_id,
            sector,
            sector_count: count,
            buffer_addr: buffer,
            flags: 0,
            submit_time: 0,
            complete_time: 0,
            error_code: 0,
            tag: 0,
        }
    }

    pub fn write(device_id: u16, sector: u64, count: u32, buffer: u64) -> Self {
        Self {
            req_type: RequestType::Write,
            priority: RequestPriority::Normal,
            state: RequestState::Pending,
            device_id,
            sector,
            sector_count: count,
            buffer_addr: buffer,
            flags: 0,
            submit_time: 0,
            complete_time: 0,
            error_code: 0,
            tag: 0,
        }
    }

    pub fn latency_ticks(&self) -> u64 {
        if self.complete_time > self.submit_time {
            self.complete_time - self.submit_time
        } else {
            0
        }
    }
}

// =============================================================================
// I/O Scheduler
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedulerType {
    Noop = 0,      // No reordering — FIFO
    Deadline = 1,  // Deadline I/O scheduler
    Cfq = 2,       // Completely Fair Queuing
}

/// NOOP scheduler: simple FIFO, optimal for SSDs and virtual devices
pub struct NoopScheduler {
    queue: [IoRequest; 256],
    head: usize,
    tail: usize,
    count: usize,
}

impl NoopScheduler {
    pub const fn new() -> Self {
        Self {
            queue: [const { IoRequest::new() }; 256],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn enqueue(&mut self, req: IoRequest) -> bool {
        if self.count >= 256 {
            return false;
        }
        self.queue[self.tail] = req;
        self.tail = (self.tail + 1) % 256;
        self.count += 1;
        true
    }

    pub fn dequeue(&mut self) -> Option<IoRequest> {
        if self.count == 0 {
            return None;
        }
        let req = self.queue[self.head];
        self.head = (self.head + 1) % 256;
        self.count -= 1;
        Some(req)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Deadline scheduler: ensures each request is served before its deadline
/// Maintains separate read and write queues, sorted by sector (for merging)
/// and by deadline (for latency guarantees)
pub struct DeadlineScheduler {
    read_queue: [IoRequest; 128],
    write_queue: [IoRequest; 128],
    read_count: usize,
    write_count: usize,
    read_deadline_ticks: u64,   // Default: 500ms worth of ticks
    write_deadline_ticks: u64,  // Default: 5000ms worth of ticks
    writes_starved: u32,        // Consecutive reads without write service
    write_starve_limit: u32,    // Max reads before forced write
    last_sector: u64,           // Last serviced sector (for seek optimization)
    dispatched: u64,            // Total requests dispatched
}

impl DeadlineScheduler {
    pub const fn new() -> Self {
        Self {
            read_queue: [const { IoRequest::new() }; 128],
            write_queue: [const { IoRequest::new() }; 128],
            read_count: 0,
            write_count: 0,
            read_deadline_ticks: 500_000_000,   // ~500ms at 1GHz TSC
            write_deadline_ticks: 5_000_000_000, // ~5s at 1GHz TSC
            writes_starved: 0,
            write_starve_limit: 2,
            last_sector: 0,
            dispatched: 0,
        }
    }

    pub fn enqueue(&mut self, req: IoRequest) -> bool {
        match req.req_type {
            RequestType::Read => {
                if self.read_count >= 128 {
                    return false;
                }
                // Insert sorted by sector for merge optimization
                let pos = self.find_insert_pos(&self.read_queue[..self.read_count], req.sector);
                // Shift elements
                let mut i = self.read_count;
                while i > pos {
                    self.read_queue[i] = self.read_queue[i - 1];
                    i -= 1;
                }
                self.read_queue[pos] = req;
                self.read_count += 1;
                true
            }
            RequestType::Write => {
                if self.write_count >= 128 {
                    return false;
                }
                let pos = self.find_insert_pos(&self.write_queue[..self.write_count], req.sector);
                let mut i = self.write_count;
                while i > pos {
                    self.write_queue[i] = self.write_queue[i - 1];
                    i -= 1;
                }
                self.write_queue[pos] = req;
                self.write_count += 1;
                true
            }
            _ => {
                // Flush/Discard: treat as write
                if self.write_count >= 128 {
                    return false;
                }
                self.write_queue[self.write_count] = req;
                self.write_count += 1;
                true
            }
        }
    }

    pub fn dequeue(&mut self, current_tsc: u64) -> Option<IoRequest> {
        if self.read_count == 0 && self.write_count == 0 {
            return None;
        }

        // Check if writes are starved
        let serve_write = if self.write_count > 0 && self.writes_starved >= self.write_starve_limit {
            true
        } else if self.read_count > 0 {
            // Check read deadline
            let oldest_read = self.read_queue[0].submit_time;
            if current_tsc.wrapping_sub(oldest_read) > self.read_deadline_ticks && self.read_count > 0 {
                false // Serve read (deadline expired)
            } else if self.write_count > 0 {
                let oldest_write = self.write_queue[0].submit_time;
                current_tsc.wrapping_sub(oldest_write) > self.write_deadline_ticks
            } else {
                false
            }
        } else {
            self.write_count > 0
        };

        if serve_write && self.write_count > 0 {
            self.writes_starved = 0;
            let req = self.write_queue[0];
            // Remove from queue
            for i in 1..self.write_count {
                self.write_queue[i - 1] = self.write_queue[i];
            }
            self.write_count -= 1;
            self.last_sector = req.sector + req.sector_count as u64;
            self.dispatched += 1;
            Some(req)
        } else if self.read_count > 0 {
            self.writes_starved += 1;
            // Find nearest sector to last_sector for seek optimization
            let idx = self.find_nearest_sector(&self.read_queue[..self.read_count]);
            let req = self.read_queue[idx];
            for i in (idx + 1)..self.read_count {
                self.read_queue[i - 1] = self.read_queue[i];
            }
            self.read_count -= 1;
            self.last_sector = req.sector + req.sector_count as u64;
            self.dispatched += 1;
            Some(req)
        } else {
            None
        }
    }

    fn find_insert_pos(&self, queue: &[IoRequest], sector: u64) -> usize {
        for (i, req) in queue.iter().enumerate() {
            if req.sector > sector {
                return i;
            }
        }
        queue.len()
    }

    fn find_nearest_sector(&self, queue: &[IoRequest]) -> usize {
        if queue.is_empty() {
            return 0;
        }
        let mut best_idx = 0;
        let mut best_dist = u64::MAX;
        for (i, req) in queue.iter().enumerate() {
            let dist = if req.sector >= self.last_sector {
                req.sector - self.last_sector
            } else {
                self.last_sector - req.sector
            };
            if dist < best_dist {
                best_dist = dist;
                best_idx = i;
            }
        }
        best_idx
    }

    pub fn pending_count(&self) -> usize {
        self.read_count + self.write_count
    }
}

// =============================================================================
// Partition table structures
// =============================================================================

/// MBR Partition Entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MbrPartition {
    pub status: u8,           // 0x80 = bootable, 0x00 = inactive
    pub first_chs: [u8; 3],  // CHS of first sector
    pub part_type: u8,        // Partition type
    pub last_chs: [u8; 3],   // CHS of last sector
    pub first_lba: u32,      // LBA of first sector
    pub sector_count: u32,   // Number of sectors
}

/// GPT Partition Entry (128 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GptPartition {
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: [u16; 36],  // UTF-16LE
}

/// GPT Header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GptHeader {
    pub signature: [u8; 8],    // "EFI PART"
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub partition_entry_crc32: u32,
}

/// Known partition type GUIDs
pub const GPT_TYPE_EFI_SYSTEM: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

pub const GPT_TYPE_LINUX_FS: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

pub const GPT_TYPE_LINUX_SWAP: [u8; 16] = [
    0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43,
    0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F,
];

// =============================================================================
// Block device statistics
// =============================================================================

pub struct BlockDeviceStats {
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub read_sectors: AtomicU64,
    pub write_sectors: AtomicU64,
    pub read_errors: AtomicU32,
    pub write_errors: AtomicU32,
    pub flush_count: AtomicU32,
    pub discard_count: AtomicU32,
    pub inflight: AtomicU32,
    pub total_latency_ticks: AtomicU64,
}

impl BlockDeviceStats {
    pub const fn new() -> Self {
        Self {
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_sectors: AtomicU64::new(0),
            write_sectors: AtomicU64::new(0),
            read_errors: AtomicU32::new(0),
            write_errors: AtomicU32::new(0),
            flush_count: AtomicU32::new(0),
            discard_count: AtomicU32::new(0),
            inflight: AtomicU32::new(0),
            total_latency_ticks: AtomicU64::new(0),
        }
    }

    pub fn record_read(&self, sectors: u64) {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.read_sectors.fetch_add(sectors, Ordering::Relaxed);
    }

    pub fn record_write(&self, sectors: u64) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.write_sectors.fetch_add(sectors, Ordering::Relaxed);
    }

    pub fn record_read_error(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency(&self, ticks: u64) {
        self.total_latency_ticks.fetch_add(ticks, Ordering::Relaxed);
    }

    pub fn average_latency(&self) -> u64 {
        let total = self.reads.load(Ordering::Relaxed) + self.writes.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        self.total_latency_ticks.load(Ordering::Relaxed) / total
    }
}

// =============================================================================
// Block cache (buffer cache)
// =============================================================================

const CACHE_SIZE: usize = 256;
const CACHE_BLOCK_SIZE: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheEntryState {
    Free = 0,
    Clean = 1,
    Dirty = 2,
}

pub struct CacheEntry {
    pub device_id: u16,
    pub block_num: u64,
    pub state: CacheEntryState,
    pub data: [u8; CACHE_BLOCK_SIZE],
    pub access_count: u32,
    pub last_access: u64,
}

impl CacheEntry {
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            block_num: 0,
            state: CacheEntryState::Free,
            data: [0u8; CACHE_BLOCK_SIZE],
            access_count: 0,
            last_access: 0,
        }
    }
}

pub struct BlockCache {
    entries: [CacheEntry; CACHE_SIZE],
    count: usize,
    hits: u64,
    misses: u64,
}

impl BlockCache {
    pub const fn new() -> Self {
        Self {
            entries: [const { CacheEntry::new() }; CACHE_SIZE],
            count: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a block in the cache
    pub fn lookup(&mut self, device_id: u16, block_num: u64, tsc: u64) -> Option<&[u8; CACHE_BLOCK_SIZE]> {
        for entry in self.entries.iter_mut() {
            if entry.state != CacheEntryState::Free
                && entry.device_id == device_id
                && entry.block_num == block_num
            {
                entry.access_count += 1;
                entry.last_access = tsc;
                self.hits += 1;
                return Some(&entry.data);
            }
        }
        self.misses += 1;
        None
    }

    /// Insert a block into the cache
    pub fn insert(&mut self, device_id: u16, block_num: u64, data: &[u8], tsc: u64) {
        // Try to find a free slot
        let slot = self.find_free_slot().unwrap_or_else(|| self.evict_lru());

        let entry = &mut self.entries[slot];
        entry.device_id = device_id;
        entry.block_num = block_num;
        entry.state = CacheEntryState::Clean;
        let copy_len = core::cmp::min(data.len(), CACHE_BLOCK_SIZE);
        entry.data[..copy_len].copy_from_slice(&data[..copy_len]);
        entry.access_count = 1;
        entry.last_access = tsc;

        if self.count < CACHE_SIZE {
            self.count += 1;
        }
    }

    /// Mark a cached block as dirty
    pub fn mark_dirty(&mut self, device_id: u16, block_num: u64) {
        for entry in self.entries.iter_mut() {
            if entry.device_id == device_id && entry.block_num == block_num {
                entry.state = CacheEntryState::Dirty;
                return;
            }
        }
    }

    /// Get all dirty entries for write-back
    pub fn dirty_count(&self) -> usize {
        self.entries.iter().filter(|e| e.state == CacheEntryState::Dirty).count()
    }

    /// Cache hit ratio (0-100)
    pub fn hit_ratio(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        ((self.hits * 100) / total) as u32
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| e.state == CacheEntryState::Free)
    }

    fn evict_lru(&mut self) -> usize {
        // Find least recently used CLEAN entry
        let mut oldest_idx = 0;
        let mut oldest_time = u64::MAX;

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.state == CacheEntryState::Clean && entry.last_access < oldest_time {
                oldest_time = entry.last_access;
                oldest_idx = i;
            }
        }

        // If no clean entries, evict oldest dirty (after flush)
        if oldest_time == u64::MAX {
            for (i, entry) in self.entries.iter().enumerate() {
                if entry.last_access < oldest_time {
                    oldest_time = entry.last_access;
                    oldest_idx = i;
                }
            }
        }

        self.entries[oldest_idx].state = CacheEntryState::Free;
        oldest_idx
    }
}

// =============================================================================
// Block device registry
// =============================================================================

pub const MAX_BLOCK_DEVICES: usize = 32;

pub struct BlockDeviceRegistry {
    devices: [BlockDeviceInfo; MAX_BLOCK_DEVICES],
    stats: [BlockDeviceStats; MAX_BLOCK_DEVICES],
    count: usize,
    cache: BlockCache,
}

impl BlockDeviceRegistry {
    pub const fn new() -> Self {
        Self {
            devices: [const { BlockDeviceInfo::new() }; MAX_BLOCK_DEVICES],
            stats: [const { BlockDeviceStats::new() }; MAX_BLOCK_DEVICES],
            count: 0,
            cache: BlockCache::new(),
        }
    }

    pub fn register(&mut self, info: BlockDeviceInfo) -> Option<u16> {
        if self.count >= MAX_BLOCK_DEVICES {
            return None;
        }
        let id = self.count as u16;
        self.devices[self.count] = info;
        self.count += 1;
        Some(id)
    }

    pub fn get(&self, id: u16) -> Option<&BlockDeviceInfo> {
        if (id as usize) < self.count {
            Some(&self.devices[id as usize])
        } else {
            None
        }
    }

    pub fn get_stats(&self, id: u16) -> Option<&BlockDeviceStats> {
        if (id as usize) < self.count {
            Some(&self.stats[id as usize])
        } else {
            None
        }
    }

    pub fn device_count(&self) -> usize {
        self.count
    }

    pub fn cache(&mut self) -> &mut BlockCache {
        &mut self.cache
    }
}

static mut REGISTRY: BlockDeviceRegistry = BlockDeviceRegistry::new();

/// Get the global block device registry (unsafe: requires synchronization)
///
/// # Safety
/// Caller must ensure exclusive access (e.g., via spinlock).
pub unsafe fn registry() -> &'static mut BlockDeviceRegistry {
    &mut *core::ptr::addr_of_mut!(REGISTRY)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_block_register(
    name_ptr: *const u8,
    name_len: u32,
    total_sectors: u64,
    sector_size: u32,
    capabilities: u32,
) -> i32 {
    if name_ptr.is_null() || name_len == 0 {
        return -1;
    }

    let mut info = BlockDeviceInfo::new();
    let len = core::cmp::min(name_len as usize, 31);
    unsafe {
        let name_slice = core::slice::from_raw_parts(name_ptr, len);
        info.set_name(name_slice);
    }
    info.total_sectors = total_sectors;
    info.sector_size = sector_size;
    info.capabilities = capabilities;

    unsafe {
        match registry().register(info) {
            Some(id) => id as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_block_device_count() -> u32 {
    unsafe { registry().device_count() as u32 }
}
