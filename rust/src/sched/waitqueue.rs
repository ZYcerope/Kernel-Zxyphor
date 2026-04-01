// =============================================================================
// Kernel Zxyphor — Wait Queue
// =============================================================================
// Blocking wait queue infrastructure:
//   - Sleep/wake primitives for kernel synchronization
//   - Exclusive vs non-exclusive waiters
//   - Timed waits with configurable timeout
//   - Wake-one and wake-all semantics
//   - Condition variable pattern support
//   - Priority-ordered waiting (optional)
//   - Wait queue statistics and deadlock detection
//   - Poll/select support via wait queue heads
//   - Event-driven notification pattern
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

pub const MAX_WAITQUEUE_HEADS: usize = 256;
pub const MAX_WAITERS_PER_QUEUE: usize = 64;
pub const WAIT_TIMEOUT_INFINITE: u64 = u64::MAX;

// =============================================================================
// Wait entry (per-thread)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitState {
    Inactive = 0,
    Waiting = 1,
    Woken = 2,
    TimedOut = 3,
    Interrupted = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitFlags {
    NonExclusive = 0,
    Exclusive = 1,
    Interruptible = 2,
    Killable = 3,
}

pub struct WaitEntry {
    pub pid: u32,
    pub tid: u32,
    pub state: WaitState,
    pub flags: WaitFlags,
    pub priority: i16,        // For priority-ordered queues
    pub enqueue_time_ns: u64,
    pub timeout_ns: u64,      // Absolute timeout (0 = no timeout)
    pub wake_reason: u32,     // Application-specific wake reason
    pub active: bool,
}

impl WaitEntry {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            tid: 0,
            state: WaitState::Inactive,
            flags: WaitFlags::NonExclusive,
            priority: 0,
            enqueue_time_ns: 0,
            timeout_ns: 0,
            wake_reason: 0,
            active: false,
        }
    }
}

// =============================================================================
// Wait queue head
// =============================================================================

pub struct WaitQueueHead {
    pub id: u32,
    pub name: [u8; 16],
    pub name_len: usize,
    pub waiters: [WaitEntry; MAX_WAITERS_PER_QUEUE],
    pub nr_waiters: u32,
    pub nr_exclusive: u32,
    pub total_wakes: AtomicU64,
    pub total_waits: AtomicU64,
    pub total_timeouts: AtomicU64,
    pub max_wait_time_ns: u64,
    pub priority_ordered: bool,
    pub active: bool,
    pub lock: AtomicU32,  // Spinlock
}

impl WaitQueueHead {
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; 16],
            name_len: 0,
            waiters: [const { WaitEntry::new() }; MAX_WAITERS_PER_QUEUE],
            nr_waiters: 0,
            nr_exclusive: 0,
            total_wakes: AtomicU64::new(0),
            total_waits: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            max_wait_time_ns: 0,
            priority_ordered: false,
            active: false,
            lock: AtomicU32::new(0),
        }
    }

    fn acquire_lock(&self) {
        loop {
            match self.lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return,
                Err(_) => core::hint::spin_loop(),
            }
        }
    }

    fn release_lock(&self) {
        self.lock.store(0, Ordering::Release);
    }

    /// Add a waiter to the queue
    pub fn add_waiter(
        &mut self,
        pid: u32,
        tid: u32,
        flags: WaitFlags,
        priority: i16,
        now_ns: u64,
        timeout_ns: u64,
    ) -> bool {
        self.acquire_lock();

        if self.nr_waiters as usize >= MAX_WAITERS_PER_QUEUE {
            self.release_lock();
            return false;
        }

        let idx = self.nr_waiters as usize;
        self.waiters[idx] = WaitEntry {
            pid,
            tid,
            state: WaitState::Waiting,
            flags,
            priority,
            enqueue_time_ns: now_ns,
            timeout_ns: if timeout_ns == WAIT_TIMEOUT_INFINITE { 0 } else { now_ns + timeout_ns },
            wake_reason: 0,
            active: true,
        };
        self.nr_waiters += 1;

        if matches!(flags, WaitFlags::Exclusive) {
            self.nr_exclusive += 1;
        }

        self.total_waits.fetch_add(1, Ordering::Relaxed);

        // Sort by priority if enabled
        if self.priority_ordered && self.nr_waiters > 1 {
            self.sort_by_priority();
        }

        self.release_lock();
        true
    }

    /// Remove a specific waiter
    pub fn remove_waiter(&mut self, pid: u32, tid: u32) {
        self.acquire_lock();

        for i in 0..self.nr_waiters as usize {
            if self.waiters[i].pid == pid && self.waiters[i].tid == tid {
                if matches!(self.waiters[i].flags, WaitFlags::Exclusive) {
                    self.nr_exclusive = self.nr_exclusive.saturating_sub(1);
                }
                for j in i..(self.nr_waiters as usize - 1) {
                    self.waiters[j] = self.waiters[j + 1];
                }
                self.waiters[self.nr_waiters as usize - 1] = WaitEntry::new();
                self.nr_waiters -= 1;
                break;
            }
        }

        self.release_lock();
    }

    /// Wake one waiter (first exclusive or first non-exclusive)
    pub fn wake_one(&mut self, reason: u32) -> Option<(u32, u32)> {
        self.acquire_lock();

        for i in 0..self.nr_waiters as usize {
            if self.waiters[i].state == WaitState::Waiting {
                self.waiters[i].state = WaitState::Woken;
                self.waiters[i].wake_reason = reason;
                let result = (self.waiters[i].pid, self.waiters[i].tid);
                self.total_wakes.fetch_add(1, Ordering::Relaxed);
                self.release_lock();
                return Some(result);
            }
        }

        self.release_lock();
        None
    }

    /// Wake all non-exclusive waiters + exactly one exclusive waiter
    pub fn wake_up(&mut self, reason: u32) -> u32 {
        self.acquire_lock();

        let mut woken = 0u32;
        let mut exclusive_woken = false;

        for i in 0..self.nr_waiters as usize {
            if self.waiters[i].state != WaitState::Waiting { continue; }

            match self.waiters[i].flags {
                WaitFlags::NonExclusive | WaitFlags::Interruptible | WaitFlags::Killable => {
                    self.waiters[i].state = WaitState::Woken;
                    self.waiters[i].wake_reason = reason;
                    woken += 1;
                }
                WaitFlags::Exclusive => {
                    if !exclusive_woken {
                        self.waiters[i].state = WaitState::Woken;
                        self.waiters[i].wake_reason = reason;
                        woken += 1;
                        exclusive_woken = true;
                    }
                }
            }
        }

        self.total_wakes.fetch_add(woken as u64, Ordering::Relaxed);
        self.release_lock();
        woken
    }

    /// Wake all waiters unconditionally
    pub fn wake_all(&mut self, reason: u32) -> u32 {
        self.acquire_lock();

        let mut woken = 0u32;
        for i in 0..self.nr_waiters as usize {
            if self.waiters[i].state == WaitState::Waiting {
                self.waiters[i].state = WaitState::Woken;
                self.waiters[i].wake_reason = reason;
                woken += 1;
            }
        }

        self.total_wakes.fetch_add(woken as u64, Ordering::Relaxed);
        self.release_lock();
        woken
    }

    /// Wake waiters matching a specific condition bitmask
    pub fn wake_matching(&mut self, reason: u32, pid_match: u32) -> u32 {
        self.acquire_lock();
        let mut woken = 0u32;

        for i in 0..self.nr_waiters as usize {
            if self.waiters[i].state == WaitState::Waiting && self.waiters[i].pid == pid_match {
                self.waiters[i].state = WaitState::Woken;
                self.waiters[i].wake_reason = reason;
                woken += 1;
            }
        }

        self.total_wakes.fetch_add(woken as u64, Ordering::Relaxed);
        self.release_lock();
        woken
    }

    /// Process timeouts — mark timed-out waiters
    pub fn process_timeouts(&mut self, now_ns: u64) -> u32 {
        self.acquire_lock();
        let mut timed_out = 0u32;

        for i in 0..self.nr_waiters as usize {
            if self.waiters[i].state == WaitState::Waiting
                && self.waiters[i].timeout_ns > 0
                && now_ns >= self.waiters[i].timeout_ns
            {
                self.waiters[i].state = WaitState::TimedOut;
                timed_out += 1;
                self.total_timeouts.fetch_add(1, Ordering::Relaxed);

                let wait_time = now_ns - self.waiters[i].enqueue_time_ns;
                if wait_time > self.max_wait_time_ns {
                    self.max_wait_time_ns = wait_time;
                }
            }
        }

        self.release_lock();
        timed_out
    }

    /// Compact the queue (remove woken/timed-out entries)
    pub fn compact(&mut self) {
        self.acquire_lock();

        let mut write_idx = 0usize;
        for read_idx in 0..self.nr_waiters as usize {
            match self.waiters[read_idx].state {
                WaitState::Waiting => {
                    if write_idx != read_idx {
                        self.waiters[write_idx] = self.waiters[read_idx];
                    }
                    write_idx += 1;
                }
                _ => {
                    if matches!(self.waiters[read_idx].flags, WaitFlags::Exclusive) {
                        self.nr_exclusive = self.nr_exclusive.saturating_sub(1);
                    }
                }
            }
        }
        // Clear trailing entries
        for i in write_idx..self.nr_waiters as usize {
            self.waiters[i] = WaitEntry::new();
        }
        self.nr_waiters = write_idx as u32;

        self.release_lock();
    }

    fn sort_by_priority(&mut self) {
        // Insertion sort by priority (higher first)
        for i in 1..self.nr_waiters as usize {
            let key = self.waiters[i];
            let mut j = i;
            while j > 0 && self.waiters[j - 1].priority < key.priority {
                self.waiters[j] = self.waiters[j - 1];
                j -= 1;
            }
            self.waiters[j] = key;
        }
    }
}

// =============================================================================
// Completion (one-shot event)
// =============================================================================

pub struct Completion {
    pub done: AtomicBool,
    pub wq: WaitQueueHead,
}

impl Completion {
    pub const fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            wq: WaitQueueHead::new(),
        }
    }

    pub fn complete(&mut self) {
        self.done.store(true, Ordering::Release);
        self.wq.wake_all(1);
    }

    pub fn complete_all(&mut self) {
        self.done.store(true, Ordering::Release);
        self.wq.wake_all(1);
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    pub fn reset(&mut self) {
        self.done.store(false, Ordering::Release);
    }
}

// =============================================================================
// Event notifier (reusable signaling)
// =============================================================================

pub struct EventNotifier {
    pub event_mask: AtomicU32,
    pub wq: WaitQueueHead,
}

impl EventNotifier {
    pub const fn new() -> Self {
        Self {
            event_mask: AtomicU32::new(0),
            wq: WaitQueueHead::new(),
        }
    }

    pub fn signal(&mut self, events: u32) {
        self.event_mask.fetch_or(events, Ordering::Release);
        self.wq.wake_all(events);
    }

    pub fn clear(&self, events: u32) {
        self.event_mask.fetch_and(!events, Ordering::Release);
    }

    pub fn poll(&self) -> u32 {
        self.event_mask.load(Ordering::Acquire)
    }

    pub fn check_and_clear(&self, events: u32) -> u32 {
        let current = self.event_mask.load(Ordering::Acquire);
        let matched = current & events;
        if matched != 0 {
            self.event_mask.fetch_and(!matched, Ordering::Release);
        }
        matched
    }
}

// =============================================================================
// Wait queue registry
// =============================================================================

pub struct WaitQueueRegistry {
    pub queues: [WaitQueueHead; MAX_WAITQUEUE_HEADS],
    pub count: usize,
    pub next_id: AtomicU32,
}

impl WaitQueueRegistry {
    pub const fn new() -> Self {
        Self {
            queues: [const { WaitQueueHead::new() }; MAX_WAITQUEUE_HEADS],
            count: 0,
            next_id: AtomicU32::new(1),
        }
    }

    pub fn create(&mut self, name: &[u8], priority_ordered: bool) -> Option<u32> {
        if self.count >= MAX_WAITQUEUE_HEADS { return None; }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let idx = self.count;
        self.queues[idx] = WaitQueueHead::new();
        self.queues[idx].id = id;
        self.queues[idx].active = true;
        self.queues[idx].priority_ordered = priority_ordered;
        let len = name.len().min(16);
        self.queues[idx].name[..len].copy_from_slice(&name[..len]);
        self.queues[idx].name_len = len;
        self.count += 1;
        Some(id)
    }

    pub fn find(&mut self, id: u32) -> Option<&mut WaitQueueHead> {
        self.queues[..self.count].iter_mut().find(|q| q.id == id && q.active)
    }

    pub fn destroy(&mut self, id: u32) {
        if let Some(q) = self.queues[..self.count].iter_mut().find(|q| q.id == id) {
            q.wake_all(0);
            q.active = false;
        }
    }

    // Global timeout scan
    pub fn process_all_timeouts(&mut self, now_ns: u64) {
        for i in 0..self.count {
            if self.queues[i].active {
                self.queues[i].process_timeouts(now_ns);
                self.queues[i].compact();
            }
        }
    }
}

static mut WQ_REGISTRY: WaitQueueRegistry = WaitQueueRegistry::new();

pub unsafe fn wq_registry() -> &'static mut WaitQueueRegistry {
    &mut *core::ptr::addr_of_mut!(WQ_REGISTRY)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_wq_create(name_ptr: *const u8, name_len: usize, priority: bool) -> i32 {
    if name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len.min(16)) };
    unsafe {
        match wq_registry().create(name, priority) {
            Some(id) => id as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_wq_wait(
    wq_id: u32, pid: u32, tid: u32, exclusive: bool, timeout_ns: u64, now_ns: u64,
) -> i32 {
    let flags = if exclusive { WaitFlags::Exclusive } else { WaitFlags::NonExclusive };
    unsafe {
        if let Some(wq) = wq_registry().find(wq_id) {
            if wq.add_waiter(pid, tid, flags, 0, now_ns, timeout_ns) { 0 } else { -1 }
        } else { -1 }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_wq_wake_one(wq_id: u32, reason: u32) -> i32 {
    unsafe {
        if let Some(wq) = wq_registry().find(wq_id) {
            match wq.wake_one(reason) {
                Some((pid, _)) => pid as i32,
                None => 0,
            }
        } else { -1 }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_wq_wake_all(wq_id: u32, reason: u32) -> i32 {
    unsafe {
        if let Some(wq) = wq_registry().find(wq_id) {
            wq.wake_all(reason) as i32
        } else { -1 }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_wq_process_timeouts(now_ns: u64) {
    unsafe { wq_registry().process_all_timeouts(now_ns); }
}
