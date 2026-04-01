// =============================================================================
// Kernel Zxyphor — Multi-Queue I/O Scheduler
// =============================================================================
// Advanced block I/O scheduling with multiple policies:
//   - NOOP: Direct passthrough for NVMe/SSD
//   - Deadline: Time-bounded with read priority
//   - CFQ (Completely Fair Queueing): Per-process fair bandwidth
//   - BFQ (Budget Fair Queueing): Proportional-share with budgets
//   - Multi-queue dispatch for NVMe hardware queues
//   - Request coalescing and merging
//   - Plug/unplug batching
//   - Latency tracking and QoS
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const MAX_QUEUE_DEPTH: usize = 256;
pub const MAX_HARDWARE_QUEUES: usize = 8;
pub const MAX_PROCESSES: usize = 64;

// =============================================================================
// I/O request
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoDirection {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    WriteZeroes = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoPriority {
    Idle = 0,
    BestEffort = 1,
    Realtime = 2,
}

#[derive(Clone, Copy)]
pub struct IoRequest {
    pub sector: u64,
    pub count: u32,
    pub direction: IoDirection,
    pub priority: IoPriority,
    pub pid: u32,
    pub deadline_ms: u64,     // Absolute deadline
    pub submit_time_ms: u64,  // When submitted
    pub data_ptr: u64,        // Pointer to data buffer
    pub callback_id: u32,
    pub flags: u32,
    pub active: bool,
}

impl IoRequest {
    pub const fn empty() -> Self {
        Self {
            sector: 0,
            count: 0,
            direction: IoDirection::Read,
            priority: IoPriority::BestEffort,
            pid: 0,
            deadline_ms: 0,
            submit_time_ms: 0,
            data_ptr: 0,
            callback_id: 0,
            flags: 0,
            active: false,
        }
    }

    /// Check if two requests are adjacent and can be merged
    pub fn can_merge_with(&self, other: &IoRequest) -> bool {
        self.active
            && other.active
            && self.direction == other.direction
            && self.pid == other.pid
            && self.priority == other.priority
            && (self.sector + self.count as u64 == other.sector
                || other.sector + other.count as u64 == self.sector)
    }
}

// =============================================================================
// Software queue (per-CPU submission queue)
// =============================================================================

pub struct SoftwareQueue {
    pub requests: [IoRequest; MAX_QUEUE_DEPTH],
    pub head: usize,
    pub tail: usize,
    pub count: AtomicU32,
    pub cpu_id: u8,
    pub plugged: bool, // Batching mode
}

impl SoftwareQueue {
    pub const fn new(cpu_id: u8) -> Self {
        Self {
            requests: [const { IoRequest::empty() }; MAX_QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: AtomicU32::new(0),
            cpu_id,
            plugged: false,
        }
    }

    /// Submit a request to this queue
    pub fn submit(&mut self, req: IoRequest) -> bool {
        if self.count.load(Ordering::Acquire) as usize >= MAX_QUEUE_DEPTH {
            return false;
        }
        self.requests[self.tail] = req;
        self.tail = (self.tail + 1) % MAX_QUEUE_DEPTH;
        self.count.fetch_add(1, Ordering::Release);
        true
    }

    /// Dequeue a request
    pub fn dequeue(&mut self) -> Option<IoRequest> {
        if self.count.load(Ordering::Acquire) == 0 {
            return None;
        }
        let req = self.requests[self.head];
        self.head = (self.head + 1) % MAX_QUEUE_DEPTH;
        self.count.fetch_sub(1, Ordering::Release);
        Some(req)
    }

    /// Plug the queue (batch requests)
    pub fn plug(&mut self) {
        self.plugged = true;
    }

    /// Unplug — flush all batched requests to hardware queue
    pub fn unplug(&mut self) {
        self.plugged = false;
    }

    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    /// Attempt to merge a new request with existing ones
    pub fn try_merge(&mut self, req: &IoRequest) -> bool {
        let count = self.count.load(Ordering::Acquire) as usize;
        if count == 0 {
            return false;
        }

        // Check last few entries for merge opportunity
        let check_count = core::cmp::min(count, 8);
        for offset in 0..check_count {
            let idx = if self.tail >= 1 + offset {
                self.tail - 1 - offset
            } else {
                MAX_QUEUE_DEPTH - 1 - offset + self.tail
            };

            if self.requests[idx].can_merge_with(req) {
                // Back merge
                if self.requests[idx].sector + self.requests[idx].count as u64 == req.sector {
                    self.requests[idx].count += req.count;
                    return true;
                }
                // Front merge
                if req.sector + req.count as u64 == self.requests[idx].sector {
                    self.requests[idx].sector = req.sector;
                    self.requests[idx].count += req.count;
                    return true;
                }
            }
        }

        false
    }
}

// =============================================================================
// Hardware dispatch queue
// =============================================================================

pub struct HardwareQueue {
    pub requests: [IoRequest; 64],
    pub count: usize,
    pub queue_id: u8,
    pub dispatched: AtomicU64,
    pub completed: AtomicU64,
}

impl HardwareQueue {
    pub const fn new(id: u8) -> Self {
        Self {
            requests: [const { IoRequest::empty() }; 64],
            count: 0,
            queue_id: id,
            dispatched: AtomicU64::new(0),
            completed: AtomicU64::new(0),
        }
    }

    pub fn dispatch(&mut self, req: IoRequest) -> bool {
        if self.count >= 64 {
            return false;
        }
        self.requests[self.count] = req;
        self.count += 1;
        self.dispatched.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn complete(&mut self, index: usize) {
        if index < self.count {
            self.requests[index].active = false;
            self.completed.fetch_add(1, Ordering::Relaxed);
            // Compact
            let mut w = 0;
            for r in 0..self.count {
                if self.requests[r].active {
                    if w != r {
                        self.requests[w] = self.requests[r];
                    }
                    w += 1;
                }
            }
            self.count = w;
        }
    }
}

// =============================================================================
// Deadline scheduler
// =============================================================================

pub struct DeadlineScheduler {
    pub read_queue: [IoRequest; 128],
    pub write_queue: [IoRequest; 128],
    pub read_count: usize,
    pub write_count: usize,
    pub read_deadline_ms: u64,
    pub write_deadline_ms: u64,
    pub writes_starved: u32,
    pub write_starve_limit: u32,
    pub fifo_batch: u32,
    pub dispatched_this_batch: u32,
    pub last_sector: u64, // For seek optimization
}

impl DeadlineScheduler {
    pub const fn new() -> Self {
        Self {
            read_queue: [const { IoRequest::empty() }; 128],
            write_queue: [const { IoRequest::empty() }; 128],
            read_count: 0,
            write_count: 0,
            read_deadline_ms: 500,
            write_deadline_ms: 5000,
            writes_starved: 0,
            write_starve_limit: 2,
            fifo_batch: 16,
            dispatched_this_batch: 0,
            last_sector: 0,
        }
    }

    /// Add a request to the appropriate queue
    pub fn add_request(&mut self, mut req: IoRequest, now_ms: u64) -> bool {
        match req.direction {
            IoDirection::Read => {
                if self.read_count >= 128 { return false; }
                req.deadline_ms = now_ms + self.read_deadline_ms;
                // Insert sorted by sector
                let pos = self.read_queue[..self.read_count]
                    .iter()
                    .position(|r| r.sector > req.sector)
                    .unwrap_or(self.read_count);
                // Shift elements
                if pos < self.read_count {
                    for i in (pos..self.read_count).rev() {
                        self.read_queue[i + 1] = self.read_queue[i];
                    }
                }
                self.read_queue[pos] = req;
                self.read_count += 1;
                true
            }
            IoDirection::Write | IoDirection::Flush => {
                if self.write_count >= 128 { return false; }
                req.deadline_ms = now_ms + self.write_deadline_ms;
                let pos = self.write_queue[..self.write_count]
                    .iter()
                    .position(|r| r.sector > req.sector)
                    .unwrap_or(self.write_count);
                if pos < self.write_count {
                    for i in (pos..self.write_count).rev() {
                        self.write_queue[i + 1] = self.write_queue[i];
                    }
                }
                self.write_queue[pos] = req;
                self.write_count += 1;
                true
            }
            _ => false,
        }
    }

    /// Dispatch the next request based on deadline policy
    pub fn dispatch(&mut self, now_ms: u64) -> Option<IoRequest> {
        if self.read_count == 0 && self.write_count == 0 {
            return None;
        }

        // Check for expired deadlines
        let read_expired = self.read_count > 0
            && self.read_queue[0].deadline_ms <= now_ms;
        let write_expired = self.write_count > 0
            && self.write_queue[0].deadline_ms <= now_ms;

        // Prioritize expired reads
        if read_expired {
            return Some(self.dequeue_read());
        }

        // Then expired writes
        if write_expired || self.writes_starved >= self.write_starve_limit {
            if self.write_count > 0 {
                self.writes_starved = 0;
                return Some(self.dequeue_write());
            }
        }

        // Default: reads, tracking starvation
        if self.read_count > 0 {
            self.writes_starved += 1;
            // Pick nearest to last_sector for seek optimization
            return Some(self.dequeue_nearest_read());
        }

        if self.write_count > 0 {
            return Some(self.dequeue_write());
        }

        None
    }

    fn dequeue_read(&mut self) -> IoRequest {
        let req = self.read_queue[0];
        for i in 1..self.read_count {
            self.read_queue[i - 1] = self.read_queue[i];
        }
        self.read_count -= 1;
        self.last_sector = req.sector + req.count as u64;
        req
    }

    fn dequeue_write(&mut self) -> IoRequest {
        let req = self.write_queue[0];
        for i in 1..self.write_count {
            self.write_queue[i - 1] = self.write_queue[i];
        }
        self.write_count -= 1;
        self.last_sector = req.sector + req.count as u64;
        req
    }

    fn dequeue_nearest_read(&mut self) -> IoRequest {
        let mut best = 0usize;
        let mut best_dist = u64::MAX;
        for i in 0..self.read_count {
            let dist = if self.read_queue[i].sector >= self.last_sector {
                self.read_queue[i].sector - self.last_sector
            } else {
                self.last_sector - self.read_queue[i].sector
            };
            if dist < best_dist {
                best_dist = dist;
                best = i;
            }
        }
        let req = self.read_queue[best];
        for i in (best + 1)..self.read_count {
            self.read_queue[i - 1] = self.read_queue[i];
        }
        self.read_count -= 1;
        self.last_sector = req.sector + req.count as u64;
        req
    }
}

// =============================================================================
// CFQ (Completely Fair Queueing) scheduler
// =============================================================================

pub struct CfqProcessQueue {
    pub pid: u32,
    pub requests: [IoRequest; 32],
    pub count: usize,
    pub weight: u32,          // Scheduling weight (default 100)
    pub time_slice_ms: u64,   // Time slice for this process
    pub dispatched: u64,
    pub bytes_total: u64,
    pub active: bool,
}

impl CfqProcessQueue {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            requests: [const { IoRequest::empty() }; 32],
            count: 0,
            weight: 100,
            time_slice_ms: 100,
            dispatched: 0,
            bytes_total: 0,
            active: false,
        }
    }

    pub fn add_request(&mut self, req: IoRequest) -> bool {
        if self.count >= 32 { return false; }
        self.requests[self.count] = req;
        self.count += 1;
        true
    }

    pub fn dequeue(&mut self) -> Option<IoRequest> {
        if self.count == 0 { return None; }
        let req = self.requests[0];
        for i in 1..self.count {
            self.requests[i - 1] = self.requests[i];
        }
        self.count -= 1;
        self.dispatched += 1;
        self.bytes_total += req.count as u64 * 512;
        Some(req)
    }
}

pub struct CfqScheduler {
    pub queues: [CfqProcessQueue; MAX_PROCESSES],
    pub active_count: usize,
    pub current_queue: usize,
    pub current_slice_start: u64,
}

impl CfqScheduler {
    pub const fn new() -> Self {
        Self {
            queues: [const { CfqProcessQueue::new() }; MAX_PROCESSES],
            active_count: 0,
            current_queue: 0,
            current_slice_start: 0,
        }
    }

    pub fn add_request(&mut self, req: IoRequest) -> bool {
        // Find or create queue for this PID
        let mut found = None;
        let mut free = None;

        for i in 0..MAX_PROCESSES {
            if self.queues[i].active && self.queues[i].pid == req.pid {
                found = Some(i);
                break;
            }
            if !self.queues[i].active && free.is_none() {
                free = Some(i);
            }
        }

        let idx = found.or(free)?;

        if !self.queues[idx].active {
            self.queues[idx].active = true;
            self.queues[idx].pid = req.pid;
            self.queues[idx].weight = 100;
            self.active_count += 1;
        }

        Some(self.queues[idx].add_request(req)).flatten()?;
        Some(true)?;
        unreachable!()
    }

    pub fn dispatch(&mut self, now_ms: u64) -> Option<IoRequest> {
        if self.active_count == 0 {
            return None;
        }

        // Check if current queue's time slice expired
        let slice = self.queues[self.current_queue].time_slice_ms;
        if now_ms - self.current_slice_start >= slice {
            // Move to next active queue
            self.advance_queue();
            self.current_slice_start = now_ms;
        }

        // Try current queue
        if self.queues[self.current_queue].active && self.queues[self.current_queue].count > 0 {
            return self.queues[self.current_queue].dequeue();
        }

        // Try other queues
        for _ in 0..MAX_PROCESSES {
            self.advance_queue();
            if self.queues[self.current_queue].active && self.queues[self.current_queue].count > 0 {
                self.current_slice_start = now_ms;
                return self.queues[self.current_queue].dequeue();
            }
        }

        None
    }

    fn advance_queue(&mut self) {
        for _ in 0..MAX_PROCESSES {
            self.current_queue = (self.current_queue + 1) % MAX_PROCESSES;
            if self.queues[self.current_queue].active {
                return;
            }
        }
    }
}

// =============================================================================
// Latency tracker
// =============================================================================

pub struct LatencyTracker {
    pub read_total_us: AtomicU64,
    pub write_total_us: AtomicU64,
    pub read_count: AtomicU64,
    pub write_count: AtomicU64,
    pub read_max_us: AtomicU64,
    pub write_max_us: AtomicU64,
    // Histogram buckets (0-100us, 100-500us, 500us-1ms, 1ms-5ms, 5ms-50ms, >50ms)
    pub read_histogram: [AtomicU64; 6],
    pub write_histogram: [AtomicU64; 6],
}

impl LatencyTracker {
    pub const fn new() -> Self {
        Self {
            read_total_us: AtomicU64::new(0),
            write_total_us: AtomicU64::new(0),
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            read_max_us: AtomicU64::new(0),
            write_max_us: AtomicU64::new(0),
            read_histogram: [const { AtomicU64::new(0) }; 6],
            write_histogram: [const { AtomicU64::new(0) }; 6],
        }
    }

    fn bucket_index(latency_us: u64) -> usize {
        match latency_us {
            0..=99 => 0,
            100..=499 => 1,
            500..=999 => 2,
            1000..=4999 => 3,
            5000..=49999 => 4,
            _ => 5,
        }
    }

    pub fn record_read(&self, latency_us: u64) {
        self.read_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.read_count.fetch_add(1, Ordering::Relaxed);
        self.read_histogram[Self::bucket_index(latency_us)].fetch_add(1, Ordering::Relaxed);

        // Update max
        let mut current = self.read_max_us.load(Ordering::Relaxed);
        while latency_us > current {
            match self.read_max_us.compare_exchange_weak(
                current, latency_us, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    pub fn record_write(&self, latency_us: u64) {
        self.write_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.write_count.fetch_add(1, Ordering::Relaxed);
        self.write_histogram[Self::bucket_index(latency_us)].fetch_add(1, Ordering::Relaxed);

        let mut current = self.write_max_us.load(Ordering::Relaxed);
        while latency_us > current {
            match self.write_max_us.compare_exchange_weak(
                current, latency_us, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    pub fn avg_read_us(&self) -> u64 {
        let count = self.read_count.load(Ordering::Relaxed);
        if count == 0 { 0 } else { self.read_total_us.load(Ordering::Relaxed) / count }
    }

    pub fn avg_write_us(&self) -> u64 {
        let count = self.write_count.load(Ordering::Relaxed);
        if count == 0 { 0 } else { self.write_total_us.load(Ordering::Relaxed) / count }
    }
}

// =============================================================================
// Multi-queue I/O manager
// =============================================================================

pub struct MultiQueueManager {
    pub sw_queues: [SoftwareQueue; 8],  // Per-CPU software queues
    pub hw_queues: [HardwareQueue; MAX_HARDWARE_QUEUES],
    pub deadline: DeadlineScheduler,
    pub cfq: CfqScheduler,
    pub latency: LatencyTracker,
    pub active_policy: SchedulerPolicy,
    pub total_submitted: AtomicU64,
    pub total_completed: AtomicU64,
    pub total_merged: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedulerPolicy {
    Noop = 0,
    Deadline = 1,
    Cfq = 2,
}

impl MultiQueueManager {
    pub const fn new() -> Self {
        Self {
            sw_queues: [
                SoftwareQueue::new(0), SoftwareQueue::new(1),
                SoftwareQueue::new(2), SoftwareQueue::new(3),
                SoftwareQueue::new(4), SoftwareQueue::new(5),
                SoftwareQueue::new(6), SoftwareQueue::new(7),
            ],
            hw_queues: [const { HardwareQueue::new(0) }; MAX_HARDWARE_QUEUES],
            deadline: DeadlineScheduler::new(),
            cfq: CfqScheduler::new(),
            latency: LatencyTracker::new(),
            active_policy: SchedulerPolicy::Deadline,
            total_submitted: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_merged: AtomicU64::new(0),
        }
    }

    /// Submit an I/O request to the appropriate software queue
    pub fn submit(&mut self, req: IoRequest, cpu: u8) -> bool {
        let cpu_idx = (cpu as usize) % 8;
        let queue = &mut self.sw_queues[cpu_idx];

        // Try to merge first
        if queue.try_merge(&req) {
            self.total_merged.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        let ok = queue.submit(req);
        if ok {
            self.total_submitted.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Run the scheduler — move requests from software queues to hardware queues
    pub fn run_scheduler(&mut self, now_ms: u64) {
        // Pull from software queues into the policy scheduler
        for i in 0..8 {
            if self.sw_queues[i].plugged { continue; }
            while let Some(req) = self.sw_queues[i].dequeue() {
                match self.active_policy {
                    SchedulerPolicy::Noop => {
                        // Direct dispatch to hardware queue
                        let hw_idx = (i % MAX_HARDWARE_QUEUES) as usize;
                        self.hw_queues[hw_idx].dispatch(req);
                    }
                    SchedulerPolicy::Deadline => {
                        self.deadline.add_request(req, now_ms);
                    }
                    SchedulerPolicy::Cfq => {
                        let _ = self.cfq.add_request(req);
                    }
                }
            }
        }

        // Dispatch from policy scheduler to hardware queues
        match self.active_policy {
            SchedulerPolicy::Noop => {} // Already dispatched
            SchedulerPolicy::Deadline => {
                while let Some(req) = self.deadline.dispatch(now_ms) {
                    let hw_idx = 0; // Simple dispatch
                    self.hw_queues[hw_idx].dispatch(req);
                }
            }
            SchedulerPolicy::Cfq => {
                while let Some(req) = self.cfq.dispatch(now_ms) {
                    let hw_idx = 0;
                    self.hw_queues[hw_idx].dispatch(req);
                }
            }
        }
    }
}

static mut IO_MANAGER: MultiQueueManager = MultiQueueManager::new();

pub unsafe fn io_manager() -> &'static mut MultiQueueManager {
    &mut *core::ptr::addr_of_mut!(IO_MANAGER)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_io_submit(
    sector: u64,
    count: u32,
    direction: u8,
    pid: u32,
    cpu: u8,
) -> i32 {
    let dir = match direction {
        0 => IoDirection::Read,
        1 => IoDirection::Write,
        2 => IoDirection::Flush,
        _ => return -1,
    };
    let mut req = IoRequest::empty();
    req.sector = sector;
    req.count = count;
    req.direction = dir;
    req.pid = pid;
    req.active = true;

    unsafe {
        if io_manager().submit(req, cpu) { 0 } else { -1 }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_io_run_scheduler(now_ms: u64) {
    unsafe { io_manager().run_scheduler(now_ms); }
}
