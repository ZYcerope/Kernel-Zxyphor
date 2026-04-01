// =============================================================================
// Kernel Zxyphor — I/O Elevator (Scheduler)
// =============================================================================
// Block I/O scheduling algorithms:
//   - Noop: FIFO passthrough
//   - Deadline: Per-request deadline with read/write batching
//   - CFQ-like: Per-process fair queuing
//   - MQ-Deadline: Multi-queue aware deadline scheduler
// =============================================================================

use core::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// Constants
// =============================================================================

pub const MAX_ELEV_REQUESTS: usize = 256;
pub const MAX_PROCESS_QUEUES: usize = 64;
pub const DEFAULT_READ_EXPIRE_MS: u64 = 500;
pub const DEFAULT_WRITE_EXPIRE_MS: u64 = 5000;
pub const DEFAULT_FIFO_BATCH: u32 = 16;

// =============================================================================
// Elevator type
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ElevatorType {
    Noop = 0,
    Deadline = 1,
    Cfq = 2,
    MqDeadline = 3,
    Kyber = 4,    // Latency-targeted (SSD-optimized)
    Bfq = 5,      // Budget Fair Queueing
}

// =============================================================================
// Elevator request entry
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElevEntry {
    pub req_id: u32,
    pub sector: u64,
    pub nr_sectors: u32,
    pub is_write: bool,
    pub deadline_ns: u64,
    pub submit_ns: u64,
    pub process_id: u32,
    pub batch_id: u16,
    pub dispatched: bool,
}

impl ElevEntry {
    pub const fn new() Self {
        Self {
            req_id: 0xFFFFFFFF,
            sector: 0,
            nr_sectors: 0,
            is_write: false,
            deadline_ns: 0,
            submit_ns: 0,
            process_id: 0,
            batch_id: 0,
            dispatched: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.req_id == 0xFFFFFFFF
    }
}

// =============================================================================
// Deadline data
// =============================================================================

pub struct DeadlineData {
    // Sorted by sector
    pub read_sorted: [u32; MAX_ELEV_REQUESTS],  // indices into entries
    pub write_sorted: [u32; MAX_ELEV_REQUESTS],
    pub read_count: u32,
    pub write_count: u32,

    // FIFO queues (sorted by deadline)
    pub read_fifo: [u32; MAX_ELEV_REQUESTS],
    pub write_fifo: [u32; MAX_ELEV_REQUESTS],
    pub read_fifo_count: u32,
    pub write_fifo_count: u32,

    // Configuration
    pub read_expire_ns: u64,
    pub write_expire_ns: u64,
    pub fifo_batch: u32,
    pub writes_starved: u32,     // Write starvation counter
    pub writes_starved_limit: u32,

    // Batching state
    pub current_batch: u16,
    pub batch_count: u32,
    pub last_sector: u64,
    pub data_dir: bool,          // false=read, true=write

    // Stats
    pub read_dispatched: AtomicU64,
    pub write_dispatched: AtomicU64,
    pub read_expired: AtomicU64,
    pub write_expired: AtomicU64,
}

impl DeadlineData {
    pub const fn new() Self {
        Self {
            read_sorted: [0xFFFFFFFF; MAX_ELEV_REQUESTS],
            write_sorted: [0xFFFFFFFF; MAX_ELEV_REQUESTS],
            read_count: 0,
            write_count: 0,
            read_fifo: [0xFFFFFFFF; MAX_ELEV_REQUESTS],
            write_fifo: [0xFFFFFFFF; MAX_ELEV_REQUESTS],
            read_fifo_count: 0,
            write_fifo_count: 0,
            read_expire_ns: DEFAULT_READ_EXPIRE_MS * 1_000_000,
            write_expire_ns: DEFAULT_WRITE_EXPIRE_MS * 1_000_000,
            fifo_batch: DEFAULT_FIFO_BATCH,
            writes_starved: 0,
            writes_starved_limit: 2,
            current_batch: 0,
            batch_count: 0,
            last_sector: 0,
            data_dir: false,
            read_dispatched: AtomicU64::new(0),
            write_dispatched: AtomicU64::new(0),
            read_expired: AtomicU64::new(0),
            write_expired: AtomicU64::new(0),
        }
    }
}

// =============================================================================
// Per-process queue (for CFQ)
// =============================================================================

pub struct ProcessQueue {
    pub pid: u32,
    pub active: bool,
    pub weight: u32,           // IO weight (100-1000, default 500)
    pub budget: i64,           // Time budget in ns
    pub budget_charge: u64,
    pub slice_start: u64,
    pub slice_end: u64,
    pub entries: [u32; 32],    // Request indices
    pub count: u32,
    pub dispatched: u64,
    pub sectors: u64,
}

impl ProcessQueue {
    pub const fn new() Self {
        Self {
            pid: 0,
            active: false,
            weight: 500,
            budget: 0,
            budget_charge: 0,
            slice_start: 0,
            slice_end: 0,
            entries: [0xFFFFFFFF; 32],
            count: 0,
            dispatched: 0,
            sectors: 0,
        }
    }
}

// =============================================================================
// Kyber latency target data
// =============================================================================

pub struct KyberData {
    pub read_target_ns: u64,       // Target read latency
    pub write_target_ns: u64,      // Target write latency
    pub discard_target_ns: u64,
    pub read_tokens: u32,           // Admission tokens
    pub write_tokens: u32,
    pub discard_tokens: u32,
    pub read_depth: u32,            // Current dispatch depth
    pub write_depth: u32,
    pub min_depth: u32,
    pub max_depth: u32,

    // Latency tracking (histogram bins: <1us, <10us, <100us, <1ms, <10ms, >=10ms)
    pub read_latency: [AtomicU64; 6],
    pub write_latency: [AtomicU64; 6],
}

impl KyberData {
    pub const fn new() Self {
        Self {
            read_target_ns: 2_000_000,     // 2ms
            write_target_ns: 10_000_000,   // 10ms
            discard_target_ns: 5_000_000_000, // 5s
            read_tokens: 32,
            write_tokens: 16,
            discard_tokens: 4,
            read_depth: 32,
            write_depth: 16,
            min_depth: 1,
            max_depth: 256,
            read_latency: [const { AtomicU64::new(0) }; 6],
            write_latency: [const { AtomicU64::new(0) }; 6],
        }
    }

    /// Get histogram bucket for latency
    pub fn latency_bucket(ns: u64) -> usize {
        if ns < 1_000 { 0 }
        else if ns < 10_000 { 1 }
        else if ns < 100_000 { 2 }
        else if ns < 1_000_000 { 3 }
        else if ns < 10_000_000 { 4 }
        else { 5 }
    }

    /// Adjust depths based on latency
    pub fn adjust_depths(&mut self) {
        // Check P99 read latency (bucket 4+5 ratio)
        let total_reads: u64 = self.read_latency.iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum();
        
        if total_reads > 100 {
            let slow_reads = self.read_latency[4].load(Ordering::Relaxed)
                + self.read_latency[5].load(Ordering::Relaxed);
            let ratio = (slow_reads * 100) / total_reads;

            if ratio > 10 {
                // Too many slow reads, reduce depth
                self.read_depth = (self.read_depth * 3 / 4).max(self.min_depth);
            } else if ratio < 2 {
                // Very few slow reads, can increase depth
                self.read_depth = (self.read_depth * 5 / 4).min(self.max_depth);
            }
        }

        // Similar for writes
        let total_writes: u64 = self.write_latency.iter()
            .map(|b| b.load(Ordering::Relaxed))
            .sum();

        if total_writes > 100 {
            let slow_writes = self.write_latency[4].load(Ordering::Relaxed)
                + self.write_latency[5].load(Ordering::Relaxed);
            let ratio = (slow_writes * 100) / total_writes;

            if ratio > 10 {
                self.write_depth = (self.write_depth * 3 / 4).max(self.min_depth);
            } else if ratio < 2 {
                self.write_depth = (self.write_depth * 5 / 4).min(self.max_depth);
            }
        }
    }
}

// =============================================================================
// I/O Elevator
// =============================================================================

pub struct Elevator {
    pub elevator_type: ElevatorType,
    pub entries: [ElevEntry; MAX_ELEV_REQUESTS],
    pub entry_count: u32,

    // Deadline scheduler data
    pub deadline: DeadlineData,

    // CFQ data
    pub process_queues: [ProcessQueue; MAX_PROCESS_QUEUES],
    pub active_queue: u32,     // Currently active process queue idx
    pub cfq_slice_ns: u64,    // Time slice per process

    // Kyber data
    pub kyber: KyberData,

    // Stats
    pub total_dispatched: AtomicU64,
    pub total_requeued: AtomicU64,
    pub total_merged: AtomicU64,
}

impl Elevator {
    pub const fn new() Self {
        Self {
            elevator_type: ElevatorType::MqDeadline,
            entries: [const { ElevEntry::new() }; MAX_ELEV_REQUESTS],
            entry_count: 0,
            deadline: DeadlineData::new(),
            process_queues: [const { ProcessQueue::new() }; MAX_PROCESS_QUEUES],
            active_queue: 0xFFFFFFFF,
            cfq_slice_ns: 100_000_000, // 100ms
            kyber: KyberData::new(),
            total_dispatched: AtomicU64::new(0),
            total_requeued: AtomicU64::new(0),
            total_merged: AtomicU64::new(0),
        }
    }

    /// Set elevator type
    pub fn set_type(&mut self, etype: ElevatorType) {
        self.elevator_type = etype;
    }

    /// Add a request to the elevator
    pub fn add_request(
        &mut self,
        req_id: u32,
        sector: u64,
        nr_sectors: u32,
        is_write: bool,
        process_id: u32,
        now_ns: u64,
    ) -> bool {
        // Find free slot
        let mut slot = None;
        for i in 0..MAX_ELEV_REQUESTS {
            if self.entries[i].is_empty() {
                slot = Some(i);
                break;
            }
        }

        let idx = match slot {
            Some(i) => i,
            None => return false,
        };

        let deadline_ns = if is_write {
            now_ns + self.deadline.write_expire_ns
        } else {
            now_ns + self.deadline.read_expire_ns
        };

        self.entries[idx] = ElevEntry {
            req_id,
            sector,
            nr_sectors,
            is_write,
            deadline_ns,
            submit_ns: now_ns,
            process_id,
            batch_id: self.deadline.current_batch,
            dispatched: false,
        };
        self.entry_count += 1;
        true
    }

    /// Dispatch next request based on elevator type
    pub fn dispatch(&mut self, now_ns: u64) -> Option<u32> {
        match self.elevator_type {
            ElevatorType::Noop => self.dispatch_noop(),
            ElevatorType::Deadline | ElevatorType::MqDeadline => self.dispatch_deadline(now_ns),
            ElevatorType::Cfq | ElevatorType::Bfq => self.dispatch_cfq(now_ns),
            ElevatorType::Kyber => self.dispatch_kyber(now_ns),
        }
    }

    /// Noop: FIFO dispatch
    fn dispatch_noop(&mut self) -> Option<u32> {
        let mut oldest_ns = u64::MAX;
        let mut oldest_idx = None;

        for i in 0..MAX_ELEV_REQUESTS {
            if !self.entries[i].is_empty() && !self.entries[i].dispatched {
                if self.entries[i].submit_ns < oldest_ns {
                    oldest_ns = self.entries[i].submit_ns;
                    oldest_idx = Some(i);
                }
            }
        }

        if let Some(idx) = oldest_idx {
            self.entries[idx].dispatched = true;
            self.entry_count -= 1;
            let req_id = self.entries[idx].req_id;
            self.entries[idx].req_id = 0xFFFFFFFF;
            self.total_dispatched.fetch_add(1, Ordering::Relaxed);
            Some(req_id)
        } else {
            None
        }
    }

    /// Deadline: dispatch expired requests first, then sorted
    fn dispatch_deadline(&mut self, now_ns: u64) -> Option<u32> {
        // Check for expired reads
        let mut expired_read = None;
        let mut expired_write = None;
        let mut best_read_sector = u64::MAX;
        let mut best_write_sector = u64::MAX;
        let mut best_read_idx = None;
        let mut best_write_idx = None;

        for i in 0..MAX_ELEV_REQUESTS {
            if self.entries[i].is_empty() || self.entries[i].dispatched {
                continue;
            }
            let entry = &self.entries[i];

            if !entry.is_write {
                if entry.deadline_ns <= now_ns && expired_read.is_none() {
                    expired_read = Some(i);
                }
                // Find closest to last_sector for C-SCAN
                let dist = if entry.sector >= self.deadline.last_sector {
                    entry.sector - self.deadline.last_sector
                } else {
                    u64::MAX - self.deadline.last_sector + entry.sector
                };
                if dist < best_read_sector {
                    best_read_sector = dist;
                    best_read_idx = Some(i);
                }
            } else {
                if entry.deadline_ns <= now_ns && expired_write.is_none() {
                    expired_write = Some(i);
                }
                let dist = if entry.sector >= self.deadline.last_sector {
                    entry.sector - self.deadline.last_sector
                } else {
                    u64::MAX - self.deadline.last_sector + entry.sector
                };
                if dist < best_write_sector {
                    best_write_sector = dist;
                    best_write_idx = Some(i);
                }
            }
        }

        // Priority: expired reads > expired writes > batched sorted
        let dispatch_idx = if let Some(idx) = expired_read {
            self.deadline.read_expired.fetch_add(1, Ordering::Relaxed);
            idx
        } else if let Some(idx) = expired_write {
            self.deadline.write_expired.fetch_add(1, Ordering::Relaxed);
            idx
        } else if !self.deadline.data_dir {
            // Reading direction
            if let Some(idx) = best_read_idx { idx }
            else if let Some(idx) = best_write_idx { idx }
            else { return None; }
        } else {
            // Writing direction, but check starvation
            if self.deadline.writes_starved >= self.deadline.writes_starved_limit {
                self.deadline.writes_starved = 0;
                self.deadline.data_dir = false;
                if let Some(idx) = best_read_idx { idx }
                else if let Some(idx) = best_write_idx { idx }
                else { return None; }
            } else {
                if let Some(idx) = best_write_idx { idx }
                else if let Some(idx) = best_read_idx { idx }
                else { return None; }
            }
        };

        let entry = &self.entries[dispatch_idx];
        let req_id = entry.req_id;
        self.deadline.last_sector = entry.sector + entry.nr_sectors as u64;

        if entry.is_write {
            self.deadline.write_dispatched.fetch_add(1, Ordering::Relaxed);
            self.deadline.writes_starved += 1;
        } else {
            self.deadline.read_dispatched.fetch_add(1, Ordering::Relaxed);
            self.deadline.writes_starved = 0;
        }

        self.entries[dispatch_idx] = ElevEntry::new();
        self.entry_count -= 1;
        self.total_dispatched.fetch_add(1, Ordering::Relaxed);

        self.deadline.batch_count += 1;
        if self.deadline.batch_count >= self.deadline.fifo_batch {
            self.deadline.batch_count = 0;
            self.deadline.current_batch += 1;
            self.deadline.data_dir = !self.deadline.data_dir;
        }

        Some(req_id)
    }

    /// CFQ-like: per-process fair queuing
    fn dispatch_cfq(&mut self, now_ns: u64) -> Option<u32> {
        // Find active process queue or pick next one
        if self.active_queue == 0xFFFFFFFF || now_ns > self.process_queues[self.active_queue as usize].slice_end {
            self.select_next_queue(now_ns);
        }

        if self.active_queue == 0xFFFFFFFF {
            return self.dispatch_noop(); // Fallback
        }

        let pq = &self.process_queues[self.active_queue as usize];
        let pid = pq.pid;

        // Find a request from this process
        for i in 0..MAX_ELEV_REQUESTS {
            if !self.entries[i].is_empty() && !self.entries[i].dispatched && self.entries[i].process_id == pid {
                let req_id = self.entries[i].req_id;
                self.entries[i] = ElevEntry::new();
                self.entry_count -= 1;
                self.total_dispatched.fetch_add(1, Ordering::Relaxed);
                return Some(req_id);
            }
        }

        // No requests from active process, try another
        self.active_queue = 0xFFFFFFFF;
        self.dispatch_noop()
    }

    /// Select next CFQ process queue
    fn select_next_queue(&mut self, now_ns: u64) {
        let mut best_weight = 0u32;
        let mut best_idx = 0xFFFFFFFF;

        for i in 0..MAX_PROCESS_QUEUES {
            if self.process_queues[i].active && self.process_queues[i].count > 0 {
                if self.process_queues[i].weight > best_weight {
                    best_weight = self.process_queues[i].weight;
                    best_idx = i as u32;
                }
            }
        }

        if best_idx != 0xFFFFFFFF {
            self.active_queue = best_idx;
            let slice = self.cfq_slice_ns * self.process_queues[best_idx as usize].weight as u64 / 500;
            self.process_queues[best_idx as usize].slice_start = now_ns;
            self.process_queues[best_idx as usize].slice_end = now_ns + slice;
        }
    }

    /// Kyber: latency-targeted dispatch
    fn dispatch_kyber(&mut self, now_ns: u64) -> Option<u32> {
        // Adjust depths periodically
        self.kyber.adjust_depths();

        // Dispatch reads first (up to read_depth), then writes  
        let mut read_count = 0u32;
        for i in 0..MAX_ELEV_REQUESTS {
            if read_count >= self.kyber.read_depth { break; }
            if !self.entries[i].is_empty() && !self.entries[i].dispatched && !self.entries[i].is_write {
                let req_id = self.entries[i].req_id;
                self.entries[i] = ElevEntry::new();
                self.entry_count -= 1;
                self.total_dispatched.fetch_add(1, Ordering::Relaxed);
                read_count += 1;
                return Some(req_id);
            }
        }

        // Writes
        for i in 0..MAX_ELEV_REQUESTS {
            if !self.entries[i].is_empty() && !self.entries[i].dispatched && self.entries[i].is_write {
                let req_id = self.entries[i].req_id;
                self.entries[i] = ElevEntry::new();
                self.entry_count -= 1;
                self.total_dispatched.fetch_add(1, Ordering::Relaxed);
                let _ = now_ns;
                return Some(req_id);
            }
        }

        None
    }
}

// =============================================================================
// Global instance
// =============================================================================

static mut ELEVATOR: Elevator = Elevator::new();

fn elevator() -> &'static mut Elevator {
    unsafe { &mut ELEVATOR }
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_elevator_set_type(etype: u8) {
    let e = elevator();
    e.set_type(match etype {
        0 => ElevatorType::Noop,
        1 => ElevatorType::Deadline,
        2 => ElevatorType::Cfq,
        3 => ElevatorType::MqDeadline,
        4 => ElevatorType::Kyber,
        5 => ElevatorType::Bfq,
        _ => ElevatorType::MqDeadline,
    });
}

#[no_mangle]
pub extern "C" fn zxyphor_elevator_add(
    req_id: u32,
    sector: u64,
    nr_sectors: u32,
    is_write: bool,
    pid: u32,
    now_ns: u64,
) -> i32 {
    if elevator().add_request(req_id, sector, nr_sectors, is_write, pid, now_ns) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_elevator_dispatch(now_ns: u64) -> i32 {
    match elevator().dispatch(now_ns) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_elevator_pending() -> u32 {
    elevator().entry_count
}

#[no_mangle]
pub extern "C" fn zxyphor_elevator_dispatched() -> u64 {
    elevator().total_dispatched.load(Ordering::Relaxed)
}
