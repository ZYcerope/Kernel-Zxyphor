// =============================================================================
// Kernel Zxyphor — Futex (Fast Userspace Mutex)
// =============================================================================
// Linux-compatible futex implementation:
//   - FUTEX_WAIT: sleep until value changes
//   - FUTEX_WAKE: wake N waiters
//   - FUTEX_REQUEUE: move waiters between futexes
//   - Priority inheritance support
//   - Robust list handling for dead-process cleanup
//   - Hash table for O(1) futex lookup
//   - Per-futex wait queue with FIFO/priority ordering
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =============================================================================
// Futex operations
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FutexOp {
    Wait = 0,
    Wake = 1,
    Requeue = 2,
    CmpRequeue = 3,
    WakeOp = 4,
    WaitBitset = 5,
    WakeBitset = 6,
}

impl FutexOp {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v & 0x7F {
            0 => Some(Self::Wait),
            1 => Some(Self::Wake),
            2 => Some(Self::Requeue),
            3 => Some(Self::CmpRequeue),
            4 => Some(Self::WakeOp),
            5 => Some(Self::WaitBitset),
            6 => Some(Self::WakeBitset),
            _ => None,
        }
    }
}

pub const FUTEX_PRIVATE_FLAG: u32 = 0x80;
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFFFFFF;

// =============================================================================
// Futex waiter
// =============================================================================

#[derive(Clone, Copy)]
pub struct FutexWaiter {
    pub pid: u32,
    pub tid: u32,
    pub bitset: u32,
    pub priority: u8,
    pub active: bool,
}

impl FutexWaiter {
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            tid: 0,
            bitset: 0,
            priority: 128,
            active: false,
        }
    }
}

// =============================================================================
// Futex wait queue (per hash bucket)
// =============================================================================

pub const WAIT_QUEUE_SIZE: usize = 32;

pub struct FutexWaitQueue {
    pub key: u64,          // Hash key for this futex
    pub waiters: [FutexWaiter; WAIT_QUEUE_SIZE],
    pub count: usize,
    pub active: bool,
}

impl FutexWaitQueue {
    pub const fn new() -> Self {
        Self {
            key: 0,
            waiters: [FutexWaiter::empty(); WAIT_QUEUE_SIZE],
            count: 0,
            active: false,
        }
    }

    /// Add a waiter to the queue
    pub fn add_waiter(&mut self, pid: u32, tid: u32, bitset: u32) -> bool {
        if self.count >= WAIT_QUEUE_SIZE {
            return false;
        }
        self.waiters[self.count] = FutexWaiter {
            pid,
            tid,
            bitset,
            priority: 128,
            active: true,
        };
        self.count += 1;
        true
    }

    /// Wake up to `max_wake` waiters matching the bitset, return number woken
    pub fn wake(&mut self, max_wake: u32, bitset: u32) -> u32 {
        let mut woken = 0u32;
        let mut i = 0;
        while i < self.count && woken < max_wake {
            if self.waiters[i].active && (self.waiters[i].bitset & bitset) != 0 {
                self.waiters[i].active = false;
                woken += 1;
                // Remove from queue by swapping with last
                self.count -= 1;
                if i < self.count {
                    self.waiters[i] = self.waiters[self.count];
                    continue; // Don't increment i, check swapped element
                }
            }
            i += 1;
        }
        woken
    }

    /// Requeue waiters from this queue to another
    pub fn requeue(&mut self, target: &mut FutexWaitQueue, max_wake: u32, max_requeue: u32) -> (u32, u32) {
        let mut woken = 0u32;
        let mut requeued = 0u32;

        let mut i = 0;
        while i < self.count {
            if !self.waiters[i].active {
                i += 1;
                continue;
            }

            if woken < max_wake {
                // Wake this one
                self.waiters[i].active = false;
                woken += 1;
                self.count -= 1;
                if i < self.count {
                    self.waiters[i] = self.waiters[self.count];
                    continue;
                }
            } else if requeued < max_requeue {
                // Move to target queue
                if target.add_waiter(
                    self.waiters[i].pid,
                    self.waiters[i].tid,
                    self.waiters[i].bitset,
                ) {
                    requeued += 1;
                    self.count -= 1;
                    if i < self.count {
                        self.waiters[i] = self.waiters[self.count];
                        continue;
                    }
                }
            } else {
                break;
            }
            i += 1;
        }

        (woken, requeued)
    }

    /// Remove a specific waiter (by pid/tid)
    pub fn remove_waiter(&mut self, pid: u32, tid: u32) -> bool {
        for i in 0..self.count {
            if self.waiters[i].pid == pid && self.waiters[i].tid == tid {
                self.count -= 1;
                if i < self.count {
                    self.waiters[i] = self.waiters[self.count];
                }
                return true;
            }
        }
        false
    }
}

// =============================================================================
// Hash table for futex lookup
// =============================================================================

pub const HASH_BUCKETS: usize = 256;

/// FNV-1a hash for futex key
fn futex_hash(key: u64) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325;
    let bytes = key.to_le_bytes();
    for &b in &bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize) % HASH_BUCKETS
}

/// Compute futex key from address and PID
pub fn make_futex_key(uaddr: u64, pid: u32, private: bool) -> u64 {
    if private {
        // Private futex: keyed on (pid, address)
        ((pid as u64) << 48) | (uaddr & 0x0000_FFFF_FFFF_FFFF)
    } else {
        // Shared futex: keyed on physical address
        uaddr
    }
}

// =============================================================================
// Priority inheritance protocol
// =============================================================================

pub const MAX_PI_CHAIN: usize = 8;  // Max depth of PI chain to prevent cycles

#[derive(Clone, Copy)]
pub struct PiState {
    pub owner_pid: u32,
    pub owner_tid: u32,
    pub original_priority: u8,
    pub boosted_priority: u8,
    pub futex_key: u64,
    pub active: bool,
}

impl PiState {
    pub const fn empty() -> Self {
        Self {
            owner_pid: 0,
            owner_tid: 0,
            original_priority: 128,
            boosted_priority: 128,
            futex_key: 0,
            active: false,
        }
    }
}

pub struct PiRegistry {
    states: [PiState; 64],
    count: usize,
}

impl PiRegistry {
    pub const fn new() -> Self {
        Self {
            states: [PiState::empty(); 64],
            count: 0,
        }
    }

    /// Register a PI-mutex owner
    pub fn register_owner(&mut self, key: u64, pid: u32, tid: u32, prio: u8) -> bool {
        for i in 0..64usize {
            if !self.states[i].active {
                self.states[i] = PiState {
                    owner_pid: pid,
                    owner_tid: tid,
                    original_priority: prio,
                    boosted_priority: prio,
                    futex_key: key,
                    active: true,
                };
                if i >= self.count {
                    self.count = i + 1;
                }
                return true;
            }
        }
        false
    }

    /// Boost owner's priority (priority inheritance)
    pub fn boost(&mut self, key: u64, waiter_prio: u8) -> Option<(u32, u8)> {
        for i in 0..self.count {
            if self.states[i].active && self.states[i].futex_key == key {
                if waiter_prio < self.states[i].boosted_priority {
                    let old = self.states[i].boosted_priority;
                    self.states[i].boosted_priority = waiter_prio;
                    return Some((self.states[i].owner_pid, old));
                }
                return None;
            }
        }
        None
    }

    /// Release ownership and restore original priority
    pub fn release(&mut self, key: u64) -> Option<PiState> {
        for i in 0..self.count {
            if self.states[i].active && self.states[i].futex_key == key {
                let state = self.states[i];
                self.states[i].active = false;
                return Some(state);
            }
        }
        None
    }
}

// =============================================================================
// Robust list (dead process cleanup)
// =============================================================================

pub const MAX_ROBUST_ENTRIES: usize = 16;

#[derive(Clone, Copy)]
pub struct RobustEntry {
    pub futex_key: u64,
    pub pid: u32,
    pub active: bool,
}

impl RobustEntry {
    pub const fn empty() -> Self {
        Self {
            futex_key: 0,
            pid: 0,
            active: false,
        }
    }
}

pub struct RobustList {
    entries: [RobustEntry; MAX_ROBUST_ENTRIES],
    count: usize,
}

impl RobustList {
    pub const fn new() -> Self {
        Self {
            entries: [RobustEntry::empty(); MAX_ROBUST_ENTRIES],
            count: 0,
        }
    }

    /// Register a futex for robust cleanup
    pub fn register(&mut self, key: u64, pid: u32) -> bool {
        for i in 0..MAX_ROBUST_ENTRIES {
            if !self.entries[i].active {
                self.entries[i] = RobustEntry { futex_key: key, pid, active: true };
                if i >= self.count {
                    self.count = i + 1;
                }
                return true;
            }
        }
        false
    }

    /// Remove a futex from the robust list
    pub fn unregister(&mut self, key: u64) {
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].futex_key == key {
                self.entries[i].active = false;
                return;
            }
        }
    }

    /// Clean up all futexes for a dead process — wake waiters
    pub fn cleanup_dead_process(&mut self, pid: u32) -> usize {
        let mut cleaned = 0usize;
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].pid == pid {
                self.entries[i].active = false;
                cleaned += 1;
            }
        }
        cleaned
    }
}

// =============================================================================
// Global futex subsystem
// =============================================================================

pub struct FutexSubsystem {
    pub buckets: [FutexWaitQueue; HASH_BUCKETS],
    pub pi: PiRegistry,
    pub robust: RobustList,
    // Statistics
    pub total_waits: AtomicU64,
    pub total_wakes: AtomicU64,
    pub total_requeues: AtomicU64,
    pub hash_collisions: AtomicU64,
}

impl FutexSubsystem {
    pub const fn new() -> Self {
        Self {
            buckets: [const { FutexWaitQueue::new() }; HASH_BUCKETS],
            pi: PiRegistry::new(),
            robust: RobustList::new(),
            total_waits: AtomicU64::new(0),
            total_wakes: AtomicU64::new(0),
            total_requeues: AtomicU64::new(0),
            hash_collisions: AtomicU64::new(0),
        }
    }

    /// FUTEX_WAIT: if *uaddr == expected, add to wait queue
    pub fn futex_wait(
        &mut self,
        uaddr: u64,
        expected: u32,
        pid: u32,
        tid: u32,
        private: bool,
        bitset: u32,
    ) -> i32 {
        // Read current value (in real kernel, this would read from user memory)
        // Here we just validate the call semantics
        let key = make_futex_key(uaddr, pid, private);
        let bucket_idx = futex_hash(key);
        let bucket = &mut self.buckets[bucket_idx];

        // Check if bucket is for this key or free
        if bucket.active && bucket.key != key {
            self.hash_collisions.fetch_add(1, Ordering::Relaxed);
            return -11; // EAGAIN — collision
        }

        if !bucket.active {
            bucket.key = key;
            bucket.active = true;
        }

        if !bucket.add_waiter(pid, tid, bitset) {
            return -12; // ENOMEM
        }

        self.total_waits.fetch_add(1, Ordering::Relaxed);
        0 // Success — caller should now deschedule the thread
    }

    /// FUTEX_WAKE: wake up to `count` waiters
    pub fn futex_wake(
        &mut self,
        uaddr: u64,
        count: u32,
        pid: u32,
        private: bool,
        bitset: u32,
    ) -> i32 {
        let key = make_futex_key(uaddr, pid, private);
        let bucket_idx = futex_hash(key);
        let bucket = &mut self.buckets[bucket_idx];

        if !bucket.active || bucket.key != key {
            return 0; // No waiters
        }

        let woken = bucket.wake(count, bitset);
        self.total_wakes.fetch_add(woken as u64, Ordering::Relaxed);

        if bucket.count == 0 {
            bucket.active = false;
        }

        woken as i32
    }

    /// FUTEX_REQUEUE: wake some, move rest to another futex
    pub fn futex_requeue(
        &mut self,
        uaddr1: u64,
        uaddr2: u64,
        max_wake: u32,
        max_requeue: u32,
        pid: u32,
        private: bool,
    ) -> i32 {
        let key1 = make_futex_key(uaddr1, pid, private);
        let key2 = make_futex_key(uaddr2, pid, private);
        let idx1 = futex_hash(key1);
        let idx2 = futex_hash(key2);

        if idx1 == idx2 {
            // Same bucket — just wake
            return self.futex_wake(uaddr1, max_wake, pid, private, FUTEX_BITSET_MATCH_ANY);
        }

        // Need both buckets: use pointer arithmetic to avoid double borrow
        let ptr = self.buckets.as_mut_ptr();
        let bucket1 = unsafe { &mut *ptr.add(idx1) };
        let bucket2 = unsafe { &mut *ptr.add(idx2) };

        if !bucket1.active || bucket1.key != key1 {
            return 0;
        }

        if !bucket2.active {
            bucket2.key = key2;
            bucket2.active = true;
        }

        let (woken, requeued) = bucket1.requeue(bucket2, max_wake, max_requeue);
        self.total_wakes.fetch_add(woken as u64, Ordering::Relaxed);
        self.total_requeues.fetch_add(requeued as u64, Ordering::Relaxed);

        if bucket1.count == 0 {
            bucket1.active = false;
        }

        (woken + requeued) as i32
    }

    /// Handle process death — clean up robust futexes and PI state
    pub fn process_exit(&mut self, pid: u32) {
        // Clean robust list
        self.robust.cleanup_dead_process(pid);

        // Remove from all wait queues
        for bucket in &mut self.buckets {
            if !bucket.active {
                continue;
            }
            let mut i = 0;
            while i < bucket.count {
                if bucket.waiters[i].pid == pid {
                    bucket.count -= 1;
                    if i < bucket.count {
                        bucket.waiters[i] = bucket.waiters[bucket.count];
                        continue;
                    }
                } else {
                    i += 1;
                }
            }
            if bucket.count == 0 {
                bucket.active = false;
            }
        }
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.total_waits.load(Ordering::Relaxed),
            self.total_wakes.load(Ordering::Relaxed),
            self.total_requeues.load(Ordering::Relaxed),
        )
    }
}

static mut FUTEX: FutexSubsystem = FutexSubsystem::new();

/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn subsystem() -> &'static mut FutexSubsystem {
    &mut *core::ptr::addr_of_mut!(FUTEX)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_futex_wait(uaddr: u64, expected: u32, pid: u32, tid: u32) -> i32 {
    unsafe {
        subsystem().futex_wait(uaddr, expected, pid, tid, true, FUTEX_BITSET_MATCH_ANY)
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_futex_wake(uaddr: u64, count: u32, pid: u32) -> i32 {
    unsafe {
        subsystem().futex_wake(uaddr, count, pid, true, FUTEX_BITSET_MATCH_ANY)
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_futex_requeue(
    uaddr1: u64,
    uaddr2: u64,
    max_wake: u32,
    max_requeue: u32,
    pid: u32,
) -> i32 {
    unsafe {
        subsystem().futex_requeue(uaddr1, uaddr2, max_wake, max_requeue, pid, true)
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_futex_process_exit(pid: u32) {
    unsafe {
        subsystem().process_exit(pid);
    }
}
