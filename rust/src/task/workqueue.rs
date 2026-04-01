// =============================================================================
// Kernel Zxyphor — Deferred Work Queue Engine
// =============================================================================
// A work queue (inspired by Linux's workqueue/tasklet mechanism) for deferring
// non-urgent work from interrupt context to a schedulable kernel thread context.
//
// In a kernel, many operations triggered by interrupts (e.g., network packet
// processing, disk I/O completion) cannot be fully handled in interrupt context
// because they may need to sleep or acquire sleeping locks. Work queues solve
// this by queuing a work item to be processed later by a kernel thread.
//
// Design:
//   - Fixed-size work queue (no dynamic allocation)
//   - Lock-free MPSC (multi-producer, single-consumer) ring buffer
//   - Each work item is a function pointer + opaque context pointer
//   - Multiple named queues for different priorities
//   - Statistics tracking for monitoring
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Maximum work items per queue
const MAX_WORK_ITEMS: usize = 1024;
const WORK_ITEM_MASK: usize = MAX_WORK_ITEMS - 1;

/// Maximum number of work queues
const MAX_WORK_QUEUES: usize = 8;

/// Work function type (called with an opaque context pointer)
pub type WorkFn = extern "C" fn(context: usize);

// =============================================================================
// Work item
// =============================================================================

/// A single deferred work item
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WorkItem {
    /// The function to execute
    pub func: Option<WorkFn>,
    /// Opaque context passed to the function
    pub context: usize,
    /// Priority (higher = more important)
    pub priority: u8,
    /// Whether this item is pending execution
    pub pending: bool,
    /// Timestamp when queued
    pub queued_at: u64,
}

impl WorkItem {
    pub const fn empty() -> Self {
        WorkItem {
            func: None,
            context: 0,
            priority: 0,
            pending: false,
            queued_at: 0,
        }
    }
}

// =============================================================================
// Work queue
// =============================================================================

/// A named work queue with its own ring buffer
pub struct WorkQueue {
    /// Queue name (for debugging/logging)
    name: [u8; 32],
    name_len: usize,
    /// Ring buffer of work items
    items: [WorkItem; MAX_WORK_ITEMS],
    /// Write position (producer)
    write_head: AtomicU32,
    /// Read position (consumer)
    read_tail: AtomicU32,
    /// Whether this queue is active
    active: AtomicBool,
    /// Statistics
    total_queued: AtomicU64,
    total_executed: AtomicU64,
    total_dropped: AtomicU64,
    max_latency_ticks: AtomicU64,
}

impl WorkQueue {
    pub const fn new() -> Self {
        WorkQueue {
            name: [0u8; 32],
            name_len: 0,
            items: [WorkItem::empty(); MAX_WORK_ITEMS],
            write_head: AtomicU32::new(0),
            read_tail: AtomicU32::new(0),
            active: AtomicBool::new(false),
            total_queued: AtomicU64::new(0),
            total_executed: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            max_latency_ticks: AtomicU64::new(0),
        }
    }

    /// Initialize this work queue with a name
    pub fn init(&mut self, name: &[u8]) {
        let copy_len = if name.len() > 31 { 31 } else { name.len() };
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;
        self.active.store(true, Ordering::Release);
    }

    /// Enqueue a work item. Returns true on success.
    ///
    /// This is safe to call from interrupt context — it never blocks.
    pub fn enqueue(&mut self, func: WorkFn, context: usize, priority: u8) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }

        let head = self.write_head.load(Ordering::Acquire);
        let tail = self.read_tail.load(Ordering::Acquire);

        // Check if full
        let next_head = (head + 1) & (MAX_WORK_ITEMS as u32 - 1);
        if next_head == tail {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let idx = head as usize & WORK_ITEM_MASK;
        self.items[idx] = WorkItem {
            func: Some(func),
            context,
            priority,
            pending: true,
            queued_at: 0, // Would use kernel tick counter
        };

        self.write_head.store(next_head, Ordering::Release);
        self.total_queued.fetch_add(1, Ordering::Relaxed);

        true
    }

    /// Dequeue and execute the next work item. Returns true if work was done.
    pub fn process_one(&mut self) -> bool {
        let head = self.write_head.load(Ordering::Acquire);
        let tail = self.read_tail.load(Ordering::Acquire);

        if head == tail {
            return false; // Empty
        }

        let idx = tail as usize & WORK_ITEM_MASK;
        let item = self.items[idx];

        let next_tail = (tail + 1) & (MAX_WORK_ITEMS as u32 - 1);
        self.read_tail.store(next_tail, Ordering::Release);

        if let Some(func) = item.func {
            if item.pending {
                func(item.context);
                self.total_executed.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        false
    }

    /// Process all pending work items (up to a maximum to prevent starvation)
    pub fn flush(&mut self, max_items: usize) -> usize {
        let mut processed = 0;
        for _ in 0..max_items {
            if !self.process_one() {
                break;
            }
            processed += 1;
        }
        processed
    }

    /// Get the number of pending items
    pub fn pending_count(&self) -> u32 {
        let head = self.write_head.load(Ordering::Relaxed);
        let tail = self.read_tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail) & (MAX_WORK_ITEMS as u32 - 1)
    }
}

// =============================================================================
// Global work queue pool
// =============================================================================

static mut WORK_QUEUES: [WorkQueue; MAX_WORK_QUEUES] = [
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
    WorkQueue::new(),
];

static WQ_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Predefined queue indices
const WQ_DEFAULT: usize = 0;
const WQ_HIGH_PRIORITY: usize = 1;
const WQ_NETWORK: usize = 2;
const WQ_DISK_IO: usize = 3;
const WQ_MAINTENANCE: usize = 4;

// =============================================================================
// FFI exports
// =============================================================================

/// Initialize the work queue subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_workqueue_init() -> i32 {
    if WQ_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    unsafe {
        WORK_QUEUES[WQ_DEFAULT].init(b"default");
        WORK_QUEUES[WQ_HIGH_PRIORITY].init(b"high-priority");
        WORK_QUEUES[WQ_NETWORK].init(b"network");
        WORK_QUEUES[WQ_DISK_IO].init(b"disk-io");
        WORK_QUEUES[WQ_MAINTENANCE].init(b"maintenance");
    }

    WQ_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust work queue subsystem initialized (5 queues)");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Enqueue a work item to a specific queue
#[no_mangle]
pub extern "C" fn zxyphor_rust_workqueue_enqueue(
    queue_id: u32,
    func: WorkFn,
    context: usize,
    priority: u8,
) -> i32 {
    if queue_id as usize >= MAX_WORK_QUEUES {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let queue = unsafe { &mut WORK_QUEUES[queue_id as usize] };

    if queue.enqueue(func, context, priority) {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::NoMemory.as_i32()
    }
}

/// Process work items from a queue
#[no_mangle]
pub extern "C" fn zxyphor_rust_workqueue_process(
    queue_id: u32,
    max_items: u32,
) -> u32 {
    if queue_id as usize >= MAX_WORK_QUEUES {
        return 0;
    }

    let queue = unsafe { &mut WORK_QUEUES[queue_id as usize] };
    queue.flush(max_items as usize) as u32
}

/// Get pending count for a queue
#[no_mangle]
pub extern "C" fn zxyphor_rust_workqueue_pending(queue_id: u32) -> u32 {
    if queue_id as usize >= MAX_WORK_QUEUES {
        return 0;
    }

    let queue = unsafe { &WORK_QUEUES[queue_id as usize] };
    queue.pending_count()
}

/// Get work queue statistics
#[repr(C)]
pub struct WorkQueueStats {
    pub total_queued: u64,
    pub total_executed: u64,
    pub total_dropped: u64,
    pub pending: u32,
    pub active: bool,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_workqueue_stats(
    queue_id: u32,
    out: *mut WorkQueueStats,
) -> i32 {
    if out.is_null() || queue_id as usize >= MAX_WORK_QUEUES {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let queue = unsafe { &WORK_QUEUES[queue_id as usize] };
    let stats = WorkQueueStats {
        total_queued: queue.total_queued.load(Ordering::Relaxed),
        total_executed: queue.total_executed.load(Ordering::Relaxed),
        total_dropped: queue.total_dropped.load(Ordering::Relaxed),
        pending: queue.pending_count(),
        active: queue.active.load(Ordering::Relaxed),
    };

    unsafe { core::ptr::write(out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}
