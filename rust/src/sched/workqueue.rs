// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Workqueue Framework (Rust)
//
// Kernel deferred work execution:
// - Single-threaded and multi-threaded workqueues
// - Delayed work scheduling with timer integration
// - Ordered workqueue (serialized execution)
// - High-priority workqueues
// - CPU-bound work affinity
// - Work cancellation and flush
// - Per-CPU workqueues
// - Concurrency managed workqueues (cmwq)
// - Drain support for shutdown
// - Statistics and debugging

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

/// Maximum workqueues
const MAX_WORKQUEUES: usize = 32;
/// Maximum work items per queue
const MAX_WORK_ITEMS: usize = 256;
/// Maximum worker threads per pool
const MAX_WORKERS: usize = 16;
/// Maximum delayed work items
const MAX_DELAYED: usize = 64;
/// Number of CPU pools
const MAX_CPUS: usize = 16;

// ─────────────────── Work Function Types ────────────────────────────

/// Work function pointer (C ABI compatible)
pub type WorkFn = extern "C" fn(data: u64);

// ─────────────────── Work Item States ───────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum WorkState {
    Idle = 0,
    Pending = 1,
    Running = 2,
    Cancelled = 3,
}

// ─────────────────── Work Flags ─────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WorkFlags {
    bits: u16,
}

impl WorkFlags {
    pub const NONE: Self = Self { bits: 0 };
    pub const HIGHPRI: Self = Self { bits: 1 << 0 };
    pub const CPU_INTENSIVE: Self = Self { bits: 1 << 1 };
    pub const UNBOUND: Self = Self { bits: 1 << 2 };
    pub const FREEZABLE: Self = Self { bits: 1 << 3 };
    pub const MEM_RECLAIM: Self = Self { bits: 1 << 4 };
    pub const SYSFS: Self = Self { bits: 1 << 5 };

    pub fn has(self, flag: WorkFlags) -> bool {
        self.bits & flag.bits != 0
    }

    pub fn or(self, other: WorkFlags) -> Self {
        Self { bits: self.bits | other.bits }
    }
}

// ─────────────────── Work Item ──────────────────────────────────────

#[repr(C)]
pub struct WorkItem {
    pub func: Option<WorkFn>,
    pub data: u64,
    pub state: WorkState,
    pub flags: WorkFlags,
    pub name: [u8; 32],
    pub name_len: u8,
    /// Target CPU (-1 = any)
    pub cpu: i8,
    /// Priority within queue (lower = higher priority)
    pub priority: u8,
    /// Sequence number for ordering
    pub seq: u64,
    /// Execution statistics
    pub exec_count: u32,
    pub last_exec_us: u64,
    pub total_exec_us: u64,
    pub valid: bool,
}

impl WorkItem {
    pub const EMPTY: Self = Self {
        func: None,
        data: 0,
        state: WorkState::Idle,
        flags: WorkFlags::NONE,
        name: [0u8; 32],
        name_len: 0,
        cpu: -1,
        priority: 128,
        seq: 0,
        exec_count: 0,
        last_exec_us: 0,
        total_exec_us: 0,
        valid: false,
    };

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn execute(&mut self) {
        if let Some(f) = self.func {
            self.state = WorkState::Running;
            f(self.data);
            self.exec_count += 1;
            self.state = WorkState::Idle;
        }
    }

    pub fn cancel(&mut self) -> bool {
        if self.state == WorkState::Pending {
            self.state = WorkState::Cancelled;
            true
        } else {
            false
        }
    }
}

// ─────────────────── Delayed Work ───────────────────────────────────

#[repr(C)]
pub struct DelayedWork {
    pub work: WorkItem,
    /// Delay in ticks before executing
    pub delay_ticks: u64,
    /// When this was scheduled (tick count)
    pub scheduled_at: u64,
    pub active: bool,
}

impl DelayedWork {
    pub const EMPTY: Self = Self {
        work: WorkItem::EMPTY,
        delay_ticks: 0,
        scheduled_at: 0,
        active: false,
    };

    pub fn is_ready(&self, now: u64) -> bool {
        self.active && now >= self.scheduled_at + self.delay_ticks
    }
}

// ─────────────────── Worker Thread ──────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum WorkerState {
    Idle = 0,
    Busy = 1,
    Sleeping = 2,
}

#[repr(C)]
pub struct Worker {
    pub id: u8,
    pub cpu: u8,
    pub state: WorkerState,
    pub current_work: Option<u16>,  // index into work items
    pub tasks_completed: u64,
    pub active: bool,
}

impl Worker {
    pub const EMPTY: Self = Self {
        id: 0,
        cpu: 0,
        state: WorkerState::Idle,
        current_work: None,
        tasks_completed: 0,
        active: false,
    };
}

// ─────────────────── Worker Pool ────────────────────────────────────

#[repr(C)]
pub struct WorkerPool {
    pub cpu: u8,
    pub workers: [Worker; MAX_WORKERS],
    pub worker_count: u8,
    pub nr_idle: u8,
    pub nr_running: u8,
    /// Concurrency management
    pub max_active: u8,
    pub active: bool,

    /// Manage concurrency: wake idle worker if needed
    pub fn maybe_create_worker(&mut self) -> bool {
        if self.nr_idle == 0 && (self.worker_count as usize) < MAX_WORKERS {
            let idx = self.worker_count as usize;
            self.workers[idx] = Worker {
                id: self.worker_count,
                cpu: self.cpu,
                state: WorkerState::Idle,
                current_work: None,
                tasks_completed: 0,
                active: true,
            };
            self.worker_count += 1;
            self.nr_idle += 1;
            return true;
        }
        false
    }

    pub fn get_idle_worker(&mut self) -> Option<usize> {
        for i in 0..self.worker_count as usize {
            if self.workers[i].active && self.workers[i].state == WorkerState::Idle {
                return Some(i);
            }
        }
        None
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self {
            cpu: 0,
            workers: [Worker::EMPTY; MAX_WORKERS],
            worker_count: 0,
            nr_idle: 0,
            nr_running: 0,
            max_active: 4,
            active: false,
        }
    }
}

// ─────────────────── Workqueue ──────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum WqType {
    /// Normal concurrent workqueue
    Normal = 0,
    /// Ordered (serialized) workqueue
    Ordered = 1,
    /// Unbound (no CPU affinity)
    Unbound = 2,
    /// High priority
    HighPri = 3,
    /// Freezable (suspended during system freeze)
    Freezable = 4,
}

#[repr(C)]
pub struct Workqueue {
    pub name: [u8; 32],
    pub name_len: u8,
    pub wq_type: WqType,
    pub flags: WorkFlags,
    /// Work items
    pub items: [WorkItem; MAX_WORK_ITEMS],
    pub item_count: u16,
    /// Delayed work
    pub delayed: [DelayedWork; MAX_DELAYED],
    pub delayed_count: u16,
    /// Next sequence number
    pub next_seq: AtomicU64,
    /// Per-CPU pools (for bound queues)
    pub pools: [WorkerPool; MAX_CPUS],
    pub pool_count: u8,
    /// Queue statistics
    pub total_queued: AtomicU64,
    pub total_executed: AtomicU64,
    pub total_cancelled: AtomicU32,
    pub max_queue_depth: AtomicU32,
    /// State
    pub draining: AtomicBool,
    pub frozen: AtomicBool,
    pub id: u8,
    pub active: bool,
}

impl Workqueue {
    pub fn new(id: u8, wq_type: WqType) -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            wq_type,
            flags: WorkFlags::NONE,
            items: [WorkItem::EMPTY; MAX_WORK_ITEMS],
            item_count: 0,
            delayed: [DelayedWork::EMPTY; MAX_DELAYED],
            delayed_count: 0,
            next_seq: AtomicU64::new(0),
            pools: {
                let mut pools = [WorkerPool::default(); MAX_CPUS];
                let mut i = 0;
                while i < MAX_CPUS {
                    pools[i].cpu = i as u8;
                    i += 1;
                }
                pools
            },
            pool_count: 0,
            total_queued: AtomicU64::new(0),
            total_executed: AtomicU64::new(0),
            total_cancelled: AtomicU32::new(0),
            max_queue_depth: AtomicU32::new(0),
            draining: AtomicBool::new(false),
            frozen: AtomicBool::new(false),
            id,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    /// Queue a work item
    pub fn queue_work(&mut self, func: WorkFn, data: u64, flags: WorkFlags) -> bool {
        if self.draining.load(Ordering::Relaxed) { return false; }
        if self.frozen.load(Ordering::Relaxed) && flags.has(WorkFlags::FREEZABLE) { return false; }

        // Find free slot
        let slot = self.find_free_slot();
        let idx = match slot {
            Some(i) => i,
            None => return false,
        };

        self.items[idx] = WorkItem::EMPTY;
        self.items[idx].func = Some(func);
        self.items[idx].data = data;
        self.items[idx].flags = flags;
        self.items[idx].state = WorkState::Pending;
        self.items[idx].seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.items[idx].valid = true;

        if flags.has(WorkFlags::HIGHPRI) {
            self.items[idx].priority = 0;
        }

        self.item_count += 1;
        self.total_queued.fetch_add(1, Ordering::Relaxed);

        // Update max depth
        let depth = self.pending_count() as u32;
        let mut max = self.max_queue_depth.load(Ordering::Relaxed);
        while depth > max {
            match self.max_queue_depth.compare_exchange_weak(
                max, depth, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(v) => max = v,
            }
        }

        true
    }

    /// Queue delayed work
    pub fn queue_delayed_work(&mut self, func: WorkFn, data: u64, delay_ticks: u64, now: u64) -> bool {
        if self.delayed_count as usize >= MAX_DELAYED { return false; }

        for dw in self.delayed.iter_mut() {
            if !dw.active {
                dw.work = WorkItem::EMPTY;
                dw.work.func = Some(func);
                dw.work.data = data;
                dw.work.state = WorkState::Pending;
                dw.work.valid = true;
                dw.delay_ticks = delay_ticks;
                dw.scheduled_at = now;
                dw.active = true;
                self.delayed_count += 1;
                return true;
            }
        }
        false
    }

    /// Process ready delayed work items
    pub fn process_delayed(&mut self, now: u64) -> u32 {
        let mut promoted = 0u32;
        for dw in self.delayed.iter_mut() {
            if dw.is_ready(now) {
                // Move to normal queue
                if let Some(f) = dw.work.func {
                    if self.queue_work(f, dw.work.data, dw.work.flags) {
                        promoted += 1;
                    }
                }
                dw.active = false;
                if self.delayed_count > 0 {
                    self.delayed_count -= 1;
                }
            }
        }
        promoted
    }

    /// Execute pending work items
    pub fn process_work(&mut self) -> u32 {
        let mut executed = 0u32;

        match self.wq_type {
            WqType::Ordered => {
                // Execute in sequence order, one at a time
                if let Some(idx) = self.find_next_ordered() {
                    self.items[idx].execute();
                    self.items[idx].valid = false;
                    if self.item_count > 0 { self.item_count -= 1; }
                    executed = 1;
                }
            }
            _ => {
                // Execute all pending, high priority first
                // First pass: high priority
                for i in 0..MAX_WORK_ITEMS {
                    if self.items[i].valid
                        && self.items[i].state == WorkState::Pending
                        && self.items[i].priority == 0
                    {
                        self.items[i].execute();
                        self.items[i].valid = false;
                        if self.item_count > 0 { self.item_count -= 1; }
                        executed += 1;
                    }
                }
                // Second pass: normal priority
                for i in 0..MAX_WORK_ITEMS {
                    if self.items[i].valid
                        && self.items[i].state == WorkState::Pending
                    {
                        self.items[i].execute();
                        self.items[i].valid = false;
                        if self.item_count > 0 { self.item_count -= 1; }
                        executed += 1;
                    }
                }
            }
        }

        self.total_executed.fetch_add(executed as u64, Ordering::Relaxed);
        executed
    }

    fn find_next_ordered(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_seq = u64::MAX;
        for i in 0..MAX_WORK_ITEMS {
            if self.items[i].valid
                && self.items[i].state == WorkState::Pending
                && self.items[i].seq < best_seq
            {
                best = Some(i);
                best_seq = self.items[i].seq;
            }
        }
        best
    }

    fn find_free_slot(&self) -> Option<usize> {
        for i in 0..MAX_WORK_ITEMS {
            if !self.items[i].valid {
                return Some(i);
            }
        }
        None
    }

    /// Cancel all pending work
    pub fn cancel_all(&mut self) -> u32 {
        let mut cancelled = 0u32;
        for item in self.items.iter_mut() {
            if item.valid && item.state == WorkState::Pending {
                item.cancel();
                item.valid = false;
                cancelled += 1;
            }
        }
        for dw in self.delayed.iter_mut() {
            if dw.active {
                dw.active = false;
                cancelled += 1;
            }
        }
        self.delayed_count = 0;
        self.item_count = 0;
        self.total_cancelled.fetch_add(cancelled, Ordering::Relaxed);
        cancelled
    }

    /// Drain: execute all pending then disallow new work
    pub fn drain(&mut self) -> u32 {
        self.draining.store(true, Ordering::Release);
        let mut total = 0u32;
        loop {
            let processed = self.process_work();
            if processed == 0 { break; }
            total += processed;
        }
        total
    }

    /// Freeze: stop processing freezable work
    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
    }

    pub fn thaw(&self) {
        self.frozen.store(false, Ordering::Release);
    }

    fn pending_count(&self) -> u16 {
        let mut count = 0u16;
        for item in self.items.iter() {
            if item.valid && item.state == WorkState::Pending {
                count += 1;
            }
        }
        count
    }
}

// ─────────────────── Workqueue Manager ──────────────────────────────

pub struct WorkqueueManager {
    pub queues: [Workqueue; MAX_WORKQUEUES],
    pub queue_count: u8,
    /// System workqueues
    pub system_wq: u8,       // default
    pub system_highpri_wq: u8,
    pub system_unbound_wq: u8,
    pub system_long_wq: u8,
    /// Global tick
    pub tick: AtomicU64,
    pub initialized: AtomicBool,
}

impl WorkqueueManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            queues: unsafe { core::mem::zeroed() },
            queue_count: 0,
            system_wq: 0,
            system_highpri_wq: 0,
            system_unbound_wq: 0,
            system_long_wq: 0,
            tick: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        };

        // Initialize each queue
        for i in 0..MAX_WORKQUEUES {
            mgr.queues[i] = Workqueue::new(i as u8, WqType::Normal);
        }

        mgr
    }

    pub fn init(&mut self) {
        // Create system workqueues
        self.system_wq = self.create_workqueue(b"system_wq", WqType::Normal);
        self.system_highpri_wq = self.create_workqueue(b"system_highpri", WqType::HighPri);
        self.system_unbound_wq = self.create_workqueue(b"system_unbound", WqType::Unbound);
        self.system_long_wq = self.create_workqueue(b"system_long", WqType::Normal);
        self.initialized.store(true, Ordering::Release);
    }

    pub fn create_workqueue(&mut self, name: &[u8], wq_type: WqType) -> u8 {
        if self.queue_count as usize >= MAX_WORKQUEUES { return 0xFF; }
        let id = self.queue_count;
        self.queues[id as usize] = Workqueue::new(id, wq_type);
        self.queues[id as usize].set_name(name);
        self.queues[id as usize].active = true;
        self.queue_count += 1;
        id
    }

    pub fn destroy_workqueue(&mut self, id: u8) -> bool {
        if id as usize >= MAX_WORKQUEUES { return false; }
        if !self.queues[id as usize].active { return false; }
        self.queues[id as usize].drain();
        self.queues[id as usize].active = false;
        true
    }

    /// Schedule work on system workqueue
    pub fn schedule_work(&mut self, func: WorkFn, data: u64) -> bool {
        let wq = self.system_wq as usize;
        if wq >= MAX_WORKQUEUES { return false; }
        self.queues[wq].queue_work(func, data, WorkFlags::NONE)
    }

    /// Schedule high-priority work
    pub fn schedule_highpri(&mut self, func: WorkFn, data: u64) -> bool {
        let wq = self.system_highpri_wq as usize;
        if wq >= MAX_WORKQUEUES { return false; }
        self.queues[wq].queue_work(func, data, WorkFlags::HIGHPRI)
    }

    /// Schedule delayed work on system wq
    pub fn schedule_delayed(&mut self, func: WorkFn, data: u64, delay: u64) -> bool {
        let wq = self.system_wq as usize;
        if wq >= MAX_WORKQUEUES { return false; }
        let now = self.tick.load(Ordering::Relaxed);
        self.queues[wq].queue_delayed_work(func, data, delay, now)
    }

    /// Tick: process delayed work, execute pending
    pub fn tick_all(&mut self) -> u32 {
        let now = self.tick.fetch_add(1, Ordering::Relaxed);
        let mut total = 0u32;
        for i in 0..self.queue_count as usize {
            if self.queues[i].active {
                self.queues[i].process_delayed(now);
                total += self.queues[i].process_work();
            }
        }
        total
    }

    /// Freeze all freezable workqueues
    pub fn freeze_all(&self) {
        for i in 0..self.queue_count as usize {
            if self.queues[i].active && self.queues[i].wq_type == WqType::Freezable {
                self.queues[i].freeze();
            }
        }
    }

    pub fn thaw_all(&self) {
        for i in 0..self.queue_count as usize {
            if self.queues[i].active {
                self.queues[i].thaw();
            }
        }
    }

    pub fn active_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.queue_count as usize {
            if self.queues[i].active { count += 1; }
        }
        count
    }

    pub fn total_pending(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.queue_count as usize {
            if self.queues[i].active {
                total += self.queues[i].total_queued.load(Ordering::Relaxed)
                    - self.queues[i].total_executed.load(Ordering::Relaxed);
            }
        }
        total
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut WQ_MGR: Option<WorkqueueManager> = None;

fn wq_mgr() -> &'static mut WorkqueueManager {
    unsafe {
        if WQ_MGR.is_none() {
            let mut mgr = WorkqueueManager::new();
            mgr.init();
            WQ_MGR = Some(mgr);
        }
        WQ_MGR.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_wq_init() {
    let _ = wq_mgr();
}

#[no_mangle]
pub extern "C" fn rust_wq_create(name_ptr: *const u8, name_len: u32, wq_type: u8) -> u8 {
    if name_ptr.is_null() || name_len == 0 || name_len > 31 { return 0xFF; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let wt = match wq_type {
        0 => WqType::Normal,
        1 => WqType::Ordered,
        2 => WqType::Unbound,
        3 => WqType::HighPri,
        4 => WqType::Freezable,
        _ => WqType::Normal,
    };
    wq_mgr().create_workqueue(name, wt)
}

#[no_mangle]
pub extern "C" fn rust_wq_destroy(id: u8) -> i32 {
    if wq_mgr().destroy_workqueue(id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_wq_schedule(func: WorkFn, data: u64) -> i32 {
    if wq_mgr().schedule_work(func, data) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_wq_schedule_highpri(func: WorkFn, data: u64) -> i32 {
    if wq_mgr().schedule_highpri(func, data) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_wq_schedule_delayed(func: WorkFn, data: u64, delay: u64) -> i32 {
    if wq_mgr().schedule_delayed(func, data, delay) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_wq_tick() -> u32 {
    wq_mgr().tick_all()
}

#[no_mangle]
pub extern "C" fn rust_wq_count() -> u32 {
    wq_mgr().active_count()
}

#[no_mangle]
pub extern "C" fn rust_wq_pending() -> u64 {
    wq_mgr().total_pending()
}

#[no_mangle]
pub extern "C" fn rust_wq_freeze_all() {
    wq_mgr().freeze_all();
}

#[no_mangle]
pub extern "C" fn rust_wq_thaw_all() {
    wq_mgr().thaw_all();
}
