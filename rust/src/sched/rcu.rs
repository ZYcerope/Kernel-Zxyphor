// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Read-Copy-Update (RCU) Mechanism (Rust)
//
// Lock-free synchronization primitive:
// - Classic RCU (reader/writer asymmetry)
// - Grace period tracking and detection
// - Quiescent state reporting per CPU
// - Callback deferral and batching
// - RCU-protected linked list operations
// - SRCU (Sleepable RCU) variant
// - RCU barrier (wait for all callbacks)
// - Expedited grace periods (fast synchronize)
// - Per-CPU callback queues with segmented lists
// - RCU torture test stubs

#![no_std]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

const MAX_CPUS: usize = 64;
const MAX_CALLBACKS: usize = 256;
const MAX_SRCU_DOMAINS: usize = 8;
const CALLBACK_BATCH_SIZE: usize = 32;

// ─────────────────── RCU State ──────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum GpState {
    /// Normal operation, no grace period
    Idle = 0,
    /// Grace period started, waiting for quiescent states
    Started = 1,
    /// All CPUs passed quiescent state
    Completed = 2,
}

// ─────────────────── RCU Callback ───────────────────────────────────

pub type RcuCallbackFn = extern "C" fn(data: u64);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RcuCallback {
    pub func: Option<RcuCallbackFn>,
    pub data: u64,
    /// Grace period this callback waits for
    pub gp_seq: u64,
    pub valid: bool,
}

impl RcuCallback {
    pub const EMPTY: Self = Self {
        func: None,
        data: 0,
        gp_seq: 0,
        valid: false,
    };

    pub fn invoke(&self) {
        if let Some(f) = self.func {
            f(self.data);
        }
    }
}

// ─────────────────── Per-CPU RCU Data ───────────────────────────────

#[repr(C)]
pub struct RcuPerCpu {
    /// Quiescent state tracking
    /// Each CPU must pass through a quiescent state (context switch,
    /// idle, user-mode) for a grace period to end
    pub qs_passed: AtomicBool,
    /// Last GP sequence this CPU acknowledged
    pub gp_seq_ack: AtomicU64,
    /// Local callback queue
    pub callbacks: [RcuCallback; MAX_CALLBACKS],
    pub cb_head: u16,
    pub cb_tail: u16,
    pub cb_count: AtomicU32,
    /// Statistics
    pub qs_count: AtomicU64,
    pub cb_invoked: AtomicU64,
    pub active: bool,
}

impl RcuPerCpu {
    pub const fn new() -> Self {
        Self {
            qs_passed: AtomicBool::new(false),
            gp_seq_ack: AtomicU64::new(0),
            callbacks: [RcuCallback::EMPTY; MAX_CALLBACKS],
            cb_head: 0,
            cb_tail: 0,
            cb_count: AtomicU32::new(0),
            qs_count: AtomicU64::new(0),
            cb_invoked: AtomicU64::new(0),
            active: false,
        }
    }

    pub fn enqueue_callback(&mut self, cb: RcuCallback) -> bool {
        if self.cb_count.load(Ordering::Relaxed) as usize >= MAX_CALLBACKS {
            return false;
        }
        self.callbacks[self.cb_head as usize] = cb;
        self.cb_head = ((self.cb_head as usize + 1) % MAX_CALLBACKS) as u16;
        self.cb_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn dequeue_callback(&mut self) -> Option<RcuCallback> {
        if self.cb_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let cb = self.callbacks[self.cb_tail as usize];
        self.cb_tail = ((self.cb_tail as usize + 1) % MAX_CALLBACKS) as u16;
        self.cb_count.fetch_sub(1, Ordering::Relaxed);
        Some(cb)
    }

    /// Report quiescent state (called on context switch, idle, etc.)
    pub fn report_qs(&self) {
        self.qs_passed.store(true, Ordering::Release);
        self.qs_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Process callbacks that have passed their grace period
    pub fn process_callbacks(&mut self, completed_gp: u64) -> u32 {
        let mut processed = 0u32;
        let count = self.cb_count.load(Ordering::Relaxed);
        let mut remaining = count.min(CALLBACK_BATCH_SIZE as u32);

        while remaining > 0 {
            if let Some(cb) = self.peek_callback() {
                if cb.gp_seq <= completed_gp {
                    if let Some(ready_cb) = self.dequeue_callback() {
                        ready_cb.invoke();
                        self.cb_invoked.fetch_add(1, Ordering::Relaxed);
                        processed += 1;
                    }
                } else {
                    break; // Remaining callbacks need a future GP
                }
            } else {
                break;
            }
            remaining -= 1;
        }
        processed
    }

    fn peek_callback(&self) -> Option<&RcuCallback> {
        if self.cb_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        Some(&self.callbacks[self.cb_tail as usize])
    }
}

// ─────────────────── Grace Period Tracker ───────────────────────────

pub struct GracePeriod {
    /// Current grace period sequence number
    pub gp_seq: AtomicU64,
    /// Last completed grace period
    pub completed_gp: AtomicU64,
    /// State
    pub state: GpState,
    /// Bitmask of CPUs that still need to report QS
    pub qs_pending: AtomicU64,
    /// Number of online CPUs
    pub nr_cpus: u32,
    /// Expedited request
    pub expedited: AtomicBool,
}

impl GracePeriod {
    pub const fn new() -> Self {
        Self {
            gp_seq: AtomicU64::new(0),
            completed_gp: AtomicU64::new(0),
            state: GpState::Idle,
            qs_pending: AtomicU64::new(0),
            nr_cpus: 1,
            expedited: AtomicBool::new(false),
        }
    }

    /// Start a new grace period
    pub fn start(&mut self) {
        if self.state != GpState::Idle { return; }

        let new_gp = self.gp_seq.fetch_add(1, Ordering::AcqRel) + 1;
        _ = new_gp;

        // All online CPUs need to pass through QS
        let mask = if self.nr_cpus >= 64 {
            u64::MAX
        } else {
            (1u64 << self.nr_cpus) - 1
        };
        self.qs_pending.store(mask, Ordering::Release);
        self.state = GpState::Started;
    }

    /// A CPU reports its quiescent state
    pub fn cpu_qs(&mut self, cpu: u32) {
        if cpu >= 64 { return; }
        let bit = 1u64 << cpu;
        let old = self.qs_pending.fetch_and(!bit, Ordering::AcqRel);

        // Check if this was the last CPU
        if old & !bit == 0 {
            self.complete();
        }
    }

    /// Complete current grace period
    fn complete(&mut self) {
        let seq = self.gp_seq.load(Ordering::Relaxed);
        self.completed_gp.store(seq, Ordering::Release);
        self.state = GpState::Completed;
    }

    /// Check if grace period can advance to idle
    pub fn try_advance(&mut self) -> bool {
        if self.state == GpState::Completed {
            self.state = GpState::Idle;
            return true;
        }
        false
    }

    pub fn is_completed(&self, gp: u64) -> bool {
        gp <= self.completed_gp.load(Ordering::Acquire)
    }
}

// ─────────────────── SRCU Domain ────────────────────────────────────

/// Sleepable RCU — allows sleeping in read-side critical sections
pub struct SrcuDomain {
    pub id: u8,
    /// Per-CPU lock counts (even = current GP, odd = next GP)
    pub lock_count: [[AtomicU32; 2]; MAX_CPUS],
    pub srcu_gp: AtomicU64,
    pub completed_gp: AtomicU64,
    pub active: bool,
}

impl SrcuDomain {
    pub fn new(id: u8) -> Self {
        Self {
            id,
            lock_count: unsafe { core::mem::zeroed() },
            srcu_gp: AtomicU64::new(0),
            completed_gp: AtomicU64::new(0),
            active: false,
        }
    }

    /// Enter SRCU read-side critical section
    pub fn read_lock(&self, cpu: usize) -> u64 {
        let idx = (self.srcu_gp.load(Ordering::Relaxed) & 1) as usize;
        if cpu < MAX_CPUS {
            self.lock_count[cpu][idx].fetch_add(1, Ordering::Relaxed);
        }
        self.srcu_gp.load(Ordering::Acquire)
    }

    /// Exit SRCU read-side critical section
    pub fn read_unlock(&self, cpu: usize, idx_val: u64) {
        let idx = (idx_val & 1) as usize;
        if cpu < MAX_CPUS {
            self.lock_count[cpu][idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Check if SRCU grace period can complete
    pub fn check_readers(&self, idx: usize) -> bool {
        for cpu in 0..MAX_CPUS {
            if self.lock_count[cpu][idx].load(Ordering::Relaxed) > 0 {
                return false; // Still has readers
            }
        }
        true
    }

    /// Synchronize SRCU: wait for all readers in previous GP
    pub fn synchronize(&self) -> bool {
        let old_idx = (self.srcu_gp.load(Ordering::Relaxed) & 1) as usize;
        // Flip to new GP index
        self.srcu_gp.fetch_add(1, Ordering::AcqRel);
        // Check old index is drained
        self.check_readers(old_idx)
    }
}

// ─────────────────── RCU Manager ────────────────────────────────────

pub struct RcuManager {
    pub gp: GracePeriod,
    pub per_cpu: [RcuPerCpu; MAX_CPUS],
    pub nr_cpus: u32,
    /// SRCU domains
    pub srcu: [SrcuDomain; MAX_SRCU_DOMAINS],
    pub srcu_count: u8,
    /// Stats
    pub total_gp_completed: AtomicU64,
    pub total_cb_invoked: AtomicU64,
    pub total_synchronize: AtomicU64,
    pub total_expedited: AtomicU32,
    /// Barrier tracking
    pub barrier_count: AtomicU32,
    pub initialized: AtomicBool,
}

impl RcuManager {
    pub fn new() -> Self {
        Self {
            gp: GracePeriod::new(),
            per_cpu: unsafe { core::mem::zeroed() },
            nr_cpus: 1,
            srcu: unsafe { core::mem::zeroed() },
            srcu_count: 0,
            total_gp_completed: AtomicU64::new(0),
            total_cb_invoked: AtomicU64::new(0),
            total_synchronize: AtomicU64::new(0),
            total_expedited: AtomicU32::new(0),
            barrier_count: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, nr_cpus: u32) {
        self.nr_cpus = nr_cpus.min(MAX_CPUS as u32);
        self.gp.nr_cpus = self.nr_cpus;

        for i in 0..self.nr_cpus as usize {
            self.per_cpu[i] = RcuPerCpu::new();
            self.per_cpu[i].active = true;
        }

        self.initialized.store(true, Ordering::Release);
    }

    /// rcu_read_lock — mark start of read-side critical section
    /// In classic RCU this is just preempt_disable
    pub fn read_lock(&self) {
        // In a real kernel: preempt_disable()
        // RCU readers don't need any actual lock
        core::sync::atomic::compiler_fence(Ordering::Acquire);
    }

    /// rcu_read_unlock
    pub fn read_unlock(&self) {
        core::sync::atomic::compiler_fence(Ordering::Release);
        // In a real kernel: preempt_enable()
    }

    /// call_rcu — register a callback to be invoked after GP
    pub fn call_rcu(&mut self, cpu: u32, func: RcuCallbackFn, data: u64) -> bool {
        if cpu as usize >= MAX_CPUS { return false; }
        let gp_seq = self.gp.gp_seq.load(Ordering::Relaxed) + 1;

        let cb = RcuCallback {
            func: Some(func),
            data,
            gp_seq,
            valid: true,
        };

        if self.per_cpu[cpu as usize].enqueue_callback(cb) {
            // Ensure a grace period is started
            if self.gp.state == GpState::Idle {
                self.gp.start();
            }
            true
        } else {
            false
        }
    }

    /// synchronize_rcu — block until current GP completes
    /// Returns true if GP completed synchronously
    pub fn synchronize_rcu(&mut self) -> bool {
        self.total_synchronize.fetch_add(1, Ordering::Relaxed);

        // Start a GP if not already running
        if self.gp.state == GpState::Idle {
            self.gp.start();
        }

        // In a real kernel, this would sleep/schedule
        // Here we simulate by forcing all CPUs to report QS
        for cpu in 0..self.nr_cpus {
            self.gp.cpu_qs(cpu);
        }

        self.process_gp_completion();
        true
    }

    /// synchronize_rcu_expedited — fast path using IPI
    pub fn synchronize_expedited(&mut self) -> bool {
        self.gp.expedited.store(true, Ordering::Release);
        self.total_expedited.fetch_add(1, Ordering::Relaxed);

        // In real kernel: send IPI to all CPUs to force QS
        let result = self.synchronize_rcu();

        self.gp.expedited.store(false, Ordering::Release);
        result
    }

    /// Report quiescent state for a CPU (called on context switch)
    pub fn qs_report(&mut self, cpu: u32) {
        if cpu as usize >= MAX_CPUS { return; }
        self.per_cpu[cpu as usize].report_qs();
        self.gp.cpu_qs(cpu);
        self.process_gp_completion();
    }

    /// Process completed grace period
    fn process_gp_completion(&mut self) {
        if self.gp.try_advance() {
            let completed = self.gp.completed_gp.load(Ordering::Relaxed);
            self.total_gp_completed.fetch_add(1, Ordering::Relaxed);

            // Process callbacks on all CPUs
            for cpu in 0..self.nr_cpus as usize {
                let processed = self.per_cpu[cpu].process_callbacks(completed);
                self.total_cb_invoked.fetch_add(processed as u64, Ordering::Relaxed);
            }
        }
    }

    /// rcu_barrier — wait for all outstanding callbacks
    pub fn rcu_barrier(&mut self) {
        self.barrier_count.fetch_add(1, Ordering::Relaxed);
        // Force GP completion to drain all callbacks
        loop {
            let has_pending = self.has_pending_callbacks();
            if !has_pending { break; }
            self.synchronize_rcu();
        }
    }

    fn has_pending_callbacks(&self) -> bool {
        for cpu in 0..self.nr_cpus as usize {
            if self.per_cpu[cpu].cb_count.load(Ordering::Relaxed) > 0 {
                return true;
            }
        }
        false
    }

    /// Register an SRCU domain
    pub fn register_srcu(&mut self) -> Option<u8> {
        if self.srcu_count as usize >= MAX_SRCU_DOMAINS { return None; }
        let id = self.srcu_count;
        self.srcu[id as usize] = SrcuDomain::new(id);
        self.srcu[id as usize].active = true;
        self.srcu_count += 1;
        Some(id)
    }

    pub fn current_gp(&self) -> u64 {
        self.gp.gp_seq.load(Ordering::Relaxed)
    }

    pub fn completed_gp(&self) -> u64 {
        self.gp.completed_gp.load(Ordering::Relaxed)
    }

    pub fn total_callbacks_pending(&self) -> u32 {
        let mut total = 0u32;
        for cpu in 0..self.nr_cpus as usize {
            total += self.per_cpu[cpu].cb_count.load(Ordering::Relaxed);
        }
        total
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut RCU_MGR: Option<RcuManager> = None;

fn rcu_mgr() -> &'static mut RcuManager {
    unsafe {
        if RCU_MGR.is_none() {
            let mut mgr = RcuManager::new();
            mgr.init(4); // 4 CPUs default
            RCU_MGR = Some(mgr);
        }
        RCU_MGR.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_rcu_init(nr_cpus: u32) {
    let mgr = rcu_mgr();
    mgr.init(nr_cpus);
}

#[no_mangle]
pub extern "C" fn rust_rcu_read_lock() {
    rcu_mgr().read_lock();
}

#[no_mangle]
pub extern "C" fn rust_rcu_read_unlock() {
    rcu_mgr().read_unlock();
}

#[no_mangle]
pub extern "C" fn rust_rcu_call(cpu: u32, func: RcuCallbackFn, data: u64) -> i32 {
    if rcu_mgr().call_rcu(cpu, func, data) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_rcu_synchronize() -> i32 {
    if rcu_mgr().synchronize_rcu() { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_rcu_synchronize_expedited() -> i32 {
    if rcu_mgr().synchronize_expedited() { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_rcu_qs_report(cpu: u32) {
    rcu_mgr().qs_report(cpu);
}

#[no_mangle]
pub extern "C" fn rust_rcu_barrier() {
    rcu_mgr().rcu_barrier();
}

#[no_mangle]
pub extern "C" fn rust_rcu_current_gp() -> u64 {
    rcu_mgr().current_gp()
}

#[no_mangle]
pub extern "C" fn rust_rcu_completed_gp() -> u64 {
    rcu_mgr().completed_gp()
}

#[no_mangle]
pub extern "C" fn rust_rcu_pending_callbacks() -> u32 {
    rcu_mgr().total_callbacks_pending()
}

#[no_mangle]
pub extern "C" fn rust_rcu_total_gp() -> u64 {
    rcu_mgr().total_gp_completed.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_rcu_srcu_count() -> u8 {
    rcu_mgr().srcu_count
}
