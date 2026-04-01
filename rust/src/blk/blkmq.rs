// =============================================================================
// Kernel Zxyphor — Multi-Queue Block Layer (blk-mq)
// =============================================================================
// Hardware dispatch queues with tag-based request tracking, per-CPU software
// queues, and hardware queue mapping for NVMe-style parallel I/O.
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =============================================================================
// Constants
// =============================================================================

pub const MAX_HW_QUEUES: usize = 16;
pub const MAX_SW_QUEUES: usize = 64;      // Per-CPU
pub const MAX_TAGS: usize = 256;
pub const MAX_QUEUE_REQUESTS: usize = 128;
pub const TAG_FREE: u32 = 0xFFFFFFFF;

// =============================================================================
// Tag set
// =============================================================================

pub struct TagSet {
    // Bitmap for tag allocation
    bitmap: [u64; MAX_TAGS / 64],
    nr_tags: u32,
    reserved_tags: u32,  // Tags reserved for internal use

    // Stats
    allocated: AtomicU32,
    starved: AtomicU64,
}

impl TagSet {
    pub const fn new() Self {
        Self {
            bitmap: [0u64; MAX_TAGS / 64],
            nr_tags: MAX_TAGS as u32,
            reserved_tags: 4,
            allocated: AtomicU32::new(0),
            starved: AtomicU64::new(0),
        }
    }

    /// Allocate a free tag
    pub fn alloc_tag(&mut self, reserved: bool) -> Option<u16> {
        let start = if reserved { 0 } else { self.reserved_tags as usize };
        let end = self.nr_tags as usize;

        for i in start..end {
            let word = i / 64;
            let bit = i % 64;
            if (self.bitmap[word] & (1u64 << bit)) == 0 {
                self.bitmap[word] |= 1u64 << bit;
                self.allocated.fetch_add(1, Ordering::Relaxed);
                return Some(i as u16);
            }
        }
        self.starved.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Free a tag
    pub fn free_tag(&mut self, tag: u16) {
        let i = tag as usize;
        if i < self.nr_tags as usize {
            let word = i / 64;
            let bit = i % 64;
            self.bitmap[word] &= !(1u64 << bit);
            self.allocated.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Check if a tag is allocated
    pub fn is_allocated(&self, tag: u16) -> bool {
        let i = tag as usize;
        if i < self.nr_tags as usize {
            let word = i / 64;
            let bit = i % 64;
            (self.bitmap[word] & (1u64 << bit)) != 0
        } else {
            false
        }
    }

    /// Number of free tags
    pub fn free_count(&self) -> u32 {
        self.nr_tags - self.allocated.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Hardware queue entry
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HwQueueEntry {
    pub tag: u16,
    pub sector: u64,
    pub nr_sectors: u32,
    pub op_flags: u32,
    pub data_phys: u64,      // Physical address of data buffer
    pub data_len: u32,
    pub status: u8,           // 0=pending, 1=complete, 2=error
    pub error_code: i16,
    pub submit_ns: u64,
    pub complete_ns: u64,
}

impl HwQueueEntry {
    pub const fn new() Self {
        Self {
            tag: 0xFFFF,
            sector: 0,
            nr_sectors: 0,
            op_flags: 0,
            data_phys: 0,
            data_len: 0,
            status: 0,
            error_code: 0,
            submit_ns: 0,
            complete_ns: 0,
        }
    }
}

// =============================================================================
// Hardware queue
// =============================================================================

pub struct HardwareQueue {
    pub id: u8,
    pub active: bool,
    pub irq: u16,             // MSI-X interrupt vector

    // Ring buffer
    pub entries: [HwQueueEntry; MAX_QUEUE_REQUESTS],
    pub head: u32,             // Producer (submit)
    pub tail: u32,             // Consumer (complete)
    pub depth: u32,

    // Doorbell addresses (MMIO)
    pub submit_db: u64,
    pub complete_db: u64,

    // Stats
    pub submitted: AtomicU64,
    pub completed: AtomicU64,
    pub errors: AtomicU64,
    pub max_latency_ns: AtomicU64,
    pub total_latency_ns: AtomicU64,
}

impl HardwareQueue {
    pub const fn new() Self {
        Self {
            id: 0,
            active: false,
            irq: 0,
            entries: [const { HwQueueEntry::new() }; MAX_QUEUE_REQUESTS],
            head: 0,
            tail: 0,
            depth: MAX_QUEUE_REQUESTS as u32,
            submit_db: 0,
            complete_db: 0,
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
        }
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        ((self.head + 1) % self.depth) == self.tail
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Available slots
    pub fn available(&self) -> u32 {
        if self.head >= self.tail {
            self.depth - (self.head - self.tail) - 1
        } else {
            self.tail - self.head - 1
        }
    }

    /// Submit an entry to the hardware queue
    pub fn submit(&mut self, entry: HwQueueEntry) -> bool {
        if self.is_full() {
            return false;
        }
        self.entries[self.head as usize] = entry;
        self.head = (self.head + 1) % self.depth;
        self.submitted.fetch_add(1, Ordering::Relaxed);

        // Ring doorbell (write to MMIO)
        if self.submit_db != 0 {
            unsafe {
                let db = self.submit_db as *mut u32;
                core::ptr::write_volatile(db, self.head);
            }
        }
        true
    }

    /// Process completions
    pub fn process_completions(&mut self) -> u32 {
        let mut count = 0u32;
        while self.tail != self.head {
            let entry = &self.entries[self.tail as usize];
            if entry.status == 0 {
                break; // Not yet completed by hardware
            }

            self.completed.fetch_add(1, Ordering::Relaxed);
            if entry.status == 2 {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }

            if entry.complete_ns > entry.submit_ns {
                let latency = entry.complete_ns - entry.submit_ns;
                self.total_latency_ns.fetch_add(latency, Ordering::Relaxed);

                let cur_max = self.max_latency_ns.load(Ordering::Relaxed);
                if latency > cur_max {
                    self.max_latency_ns.store(latency, Ordering::Relaxed);
                }
            }

            self.tail = (self.tail + 1) % self.depth;
            count += 1;
        }
        count
    }

    /// Get average latency in nanoseconds
    pub fn avg_latency_ns(&self) -> u64 {
        let completed = self.completed.load(Ordering::Relaxed);
        if completed == 0 {
            return 0;
        }
        self.total_latency_ns.load(Ordering::Relaxed) / completed
    }
}

// =============================================================================
// Software queue (per-CPU staging area)
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SwQueueEntry {
    pub tag: u16,
    pub sector: u64,
    pub nr_sectors: u32,
    pub op_flags: u32,
    pub data_phys: u64,
    pub data_len: u32,
    pub hw_queue: u8,         // Target hardware queue
}

impl SwQueueEntry {
    pub const fn new() Self {
        Self {
            tag: 0xFFFF,
            sector: 0,
            nr_sectors: 0,
            op_flags: 0,
            data_phys: 0,
            data_len: 0,
            hw_queue: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tag == 0xFFFF
    }
}

pub struct SoftwareQueue {
    pub cpu_id: u32,
    pub entries: [SwQueueEntry; 64],
    pub count: u32,
    pub flushed: u64,
}

impl SoftwareQueue {
    pub const fn new() Self {
        Self {
            cpu_id: 0,
            entries: [const { SwQueueEntry::new() }; 64],
            count: 0,
            flushed: 0,
        }
    }

    /// Add entry to software queue
    pub fn enqueue(&mut self, entry: SwQueueEntry) -> bool {
        if self.count >= 64 {
            return false;
        }
        self.entries[self.count as usize] = entry;
        self.count += 1;
        true
    }

    /// Flush software queue to hardware queue
    pub fn flush(&mut self, hw_queues: &mut [HardwareQueue]) -> u32 {
        let mut flushed = 0u32;
        for i in 0..self.count as usize {
            let sw_entry = &self.entries[i];
            let hw_idx = sw_entry.hw_queue as usize;
            if hw_idx < hw_queues.len() && hw_queues[hw_idx].active {
                let hw_entry = HwQueueEntry {
                    tag: sw_entry.tag,
                    sector: sw_entry.sector,
                    nr_sectors: sw_entry.nr_sectors,
                    op_flags: sw_entry.op_flags,
                    data_phys: sw_entry.data_phys,
                    data_len: sw_entry.data_len,
                    status: 0,
                    error_code: 0,
                    submit_ns: 0, // Would use a timestamp here
                    complete_ns: 0,
                };
                if hw_queues[hw_idx].submit(hw_entry) {
                    flushed += 1;
                }
            }
        }
        self.count = 0;
        self.flushed += flushed as u64;
        flushed
    }
}

// =============================================================================
// Multi-queue block device
// =============================================================================

pub struct BlkMq {
    pub tag_set: TagSet,
    pub hw_queues: [HardwareQueue; MAX_HW_QUEUES],
    pub sw_queues: [SoftwareQueue; MAX_SW_QUEUES],
    pub nr_hw_queues: u8,
    pub nr_sw_queues: u32,

    // CPU-to-queue mapping
    pub cpu_to_hw: [u8; MAX_SW_QUEUES],

    // Global stats
    pub total_submitted: AtomicU64,
    pub total_completed: AtomicU64,
}

impl BlkMq {
    pub const fn new() Self {
        Self {
            tag_set: TagSet::new(),
            hw_queues: [const { HardwareQueue::new() }; MAX_HW_QUEUES],
            sw_queues: [const { SoftwareQueue::new() }; MAX_SW_QUEUES],
            nr_hw_queues: 0,
            nr_sw_queues: 0,
            cpu_to_hw: [0u8; MAX_SW_QUEUES],
            total_submitted: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
        }
    }

    /// Initialize with given number of HW queues
    pub fn init(&mut self, nr_hw: u8, nr_cpus: u32) {
        self.nr_hw_queues = if nr_hw as usize > MAX_HW_QUEUES {
            MAX_HW_QUEUES as u8
        } else {
            nr_hw
        };

        self.nr_sw_queues = if nr_cpus as usize > MAX_SW_QUEUES {
            MAX_SW_QUEUES as u32
        } else {
            nr_cpus
        };

        // Initialize HW queues
        for i in 0..self.nr_hw_queues as usize {
            self.hw_queues[i].id = i as u8;
            self.hw_queues[i].active = true;
        }

        // Map CPUs to HW queues (round-robin)
        for i in 0..self.nr_sw_queues as usize {
            self.sw_queues[i].cpu_id = i as u32;
            self.cpu_to_hw[i] = (i % self.nr_hw_queues as usize) as u8;
        }
    }

    /// Submit I/O from a specific CPU
    pub fn submit_io(
        &mut self,
        cpu: u32,
        sector: u64,
        nr_sectors: u32,
        op_flags: u32,
        data_phys: u64,
        data_len: u32,
    ) -> Option<u16> {
        let tag = self.tag_set.alloc_tag(false)?;
        let hw_q = self.cpu_to_hw[cpu as usize % MAX_SW_QUEUES];

        let sw_entry = SwQueueEntry {
            tag,
            sector,
            nr_sectors,
            op_flags,
            data_phys,
            data_len,
            hw_queue: hw_q,
        };

        let sw_idx = cpu as usize % MAX_SW_QUEUES;
        if self.sw_queues[sw_idx].enqueue(sw_entry) {
            self.total_submitted.fetch_add(1, Ordering::Relaxed);

            // If SW queue is getting full, flush it
            if self.sw_queues[sw_idx].count >= 32 {
                self.sw_queues[sw_idx].flush(&mut self.hw_queues);
            }

            Some(tag)
        } else {
            self.tag_set.free_tag(tag);
            None
        }
    }

    /// Flush all software queues to hardware
    pub fn flush_all(&mut self) {
        for i in 0..self.nr_sw_queues as usize {
            if self.sw_queues[i].count > 0 {
                self.sw_queues[i].flush(&mut self.hw_queues);
            }
        }
    }

    /// Process completions on all HW queues
    pub fn poll_completions(&mut self) -> u32 {
        let mut total = 0u32;
        for i in 0..self.nr_hw_queues as usize {
            let count = self.hw_queues[i].process_completions();
            total += count;
            self.total_completed.fetch_add(count as u64, Ordering::Relaxed);
        }
        total
    }

    /// Free a tag after I/O completion
    pub fn complete_tag(&mut self, tag: u16) {
        self.tag_set.free_tag(tag);
    }
}

// =============================================================================
// Global instance
// =============================================================================

static mut BLK_MQ: BlkMq = BlkMq::new();

fn blkmq() -> &'static mut BlkMq {
    unsafe { &mut BLK_MQ }
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_blkmq_init(nr_hw_queues: u8, nr_cpus: u32) {
    blkmq().init(nr_hw_queues, nr_cpus);
}

#[no_mangle]
pub extern "C" fn zxyphor_blkmq_submit(
    cpu: u32,
    sector: u64,
    nr_sectors: u32,
    op_flags: u32,
    data_phys: u64,
    data_len: u32,
) -> i32 {
    match blkmq().submit_io(cpu, sector, nr_sectors, op_flags, data_phys, data_len) {
        Some(tag) => tag as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_blkmq_flush() {
    blkmq().flush_all();
}

#[no_mangle]
pub extern "C" fn zxyphor_blkmq_poll() -> u32 {
    blkmq().poll_completions()
}

#[no_mangle]
pub extern "C" fn zxyphor_blkmq_complete(tag: u16) {
    blkmq().complete_tag(tag);
}

#[no_mangle]
pub extern "C" fn zxyphor_blkmq_free_tags() -> u32 {
    blkmq().tag_set.free_count()
}
