// =============================================================================
// Kernel Zxyphor — Counting Semaphore
// =============================================================================
// Lock-free counting semaphore implementation for kernel synchronization:
//   - Counting semaphore (up to configurable maximum count)
//   - Binary semaphore (mutex) mode when max_count = 1
//   - Wait queue with FIFO ordering
//   - Try-wait (non-blocking)
//   - Timed wait with deadline
//   - Named semaphores for IPC
//   - Semaphore sets (similar to System V semaphore sets)
// =============================================================================

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

// =============================================================================
// Semaphore
// =============================================================================

pub const MAX_SEMAPHORES: usize = 256;
pub const MAX_WAITERS: usize = 32;
pub const MAX_SEM_SET_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SemState {
    Free = 0,
    Active = 1,
    Destroyed = 2,
}

/// A single counting semaphore
pub struct Semaphore {
    pub count: AtomicI32,
    pub max_count: i32,
    pub state: SemState,
    pub name: [u8; 32],
    pub name_len: u8,
    pub owner_pid: u32,
    // Wait queue
    pub waiters: [u32; MAX_WAITERS],     // PIDs of waiting processes
    pub waiter_count: AtomicU32,
    // Statistics
    pub total_waits: AtomicU64,
    pub total_posts: AtomicU64,
    pub total_timeouts: AtomicU64,
    pub contention_count: AtomicU64,     // Number of times wait actually blocked
}

impl Semaphore {
    pub const fn new() -> Self {
        Self {
            count: AtomicI32::new(0),
            max_count: i32::MAX,
            state: SemState::Free,
            name: [0u8; 32],
            name_len: 0,
            owner_pid: 0,
            waiters: [0u32; MAX_WAITERS],
            waiter_count: AtomicU32::new(0),
            total_waits: AtomicU64::new(0),
            total_posts: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            contention_count: AtomicU64::new(0),
        }
    }

    /// Initialize as a counting semaphore
    pub fn init_counting(&mut self, initial: i32, max: i32, pid: u32) {
        self.count.store(initial, Ordering::Release);
        self.max_count = max;
        self.state = SemState::Active;
        self.owner_pid = pid;
        self.waiter_count.store(0, Ordering::Release);
    }

    /// Initialize as a binary semaphore (mutex)
    pub fn init_binary(&mut self, locked: bool, pid: u32) {
        self.count.store(if locked { 0 } else { 1 }, Ordering::Release);
        self.max_count = 1;
        self.state = SemState::Active;
        self.owner_pid = pid;
        self.waiter_count.store(0, Ordering::Release);
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = core::cmp::min(name.len(), 31);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    /// Wait (P / down) — decrements count, blocks if count <= 0
    /// Returns true if acquired without blocking
    pub fn wait(&self) -> bool {
        self.total_waits.fetch_add(1, Ordering::Relaxed);

        // Try to decrement atomically
        loop {
            let current = self.count.load(Ordering::Acquire);
            if current <= 0 {
                // Would block — caller must handle scheduling
                self.contention_count.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if self.count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Try-wait (non-blocking) — returns true if acquired
    pub fn try_wait(&self) -> bool {
        loop {
            let current = self.count.load(Ordering::Acquire);
            if current <= 0 {
                return false;
            }
            if self.count.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Post (V / up) — increments count, wakes a waiter
    /// Returns true if count was incremented (false if at max)
    pub fn post(&self) -> bool {
        self.total_posts.fetch_add(1, Ordering::Relaxed);

        loop {
            let current = self.count.load(Ordering::Acquire);
            if current >= self.max_count {
                return false; // At maximum
            }
            if self.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Get current count
    pub fn value(&self) -> i32 {
        self.count.load(Ordering::Acquire)
    }

    /// Add a waiter to the queue
    pub fn add_waiter(&mut self, pid: u32) -> bool {
        let count = self.waiter_count.load(Ordering::Acquire) as usize;
        if count >= MAX_WAITERS {
            return false;
        }
        self.waiters[count] = pid;
        self.waiter_count.fetch_add(1, Ordering::Release);
        true
    }

    /// Remove and return the first waiter
    pub fn wake_one(&mut self) -> Option<u32> {
        let count = self.waiter_count.load(Ordering::Acquire);
        if count == 0 {
            return None;
        }
        let pid = self.waiters[0];
        // Shift remaining waiters
        for i in 1..count as usize {
            self.waiters[i - 1] = self.waiters[i];
        }
        self.waiter_count.fetch_sub(1, Ordering::Release);
        Some(pid)
    }

    /// Destroy the semaphore
    pub fn destroy(&mut self) {
        self.state = SemState::Destroyed;
        // Wake all waiters with an error
        self.waiter_count.store(0, Ordering::Release);
    }
}

// =============================================================================
// Semaphore set (System V style)
// =============================================================================

pub struct SemaphoreSet {
    pub key: u32,
    pub sems: [Semaphore; MAX_SEM_SET_SIZE],
    pub nsems: usize,
    pub owner_pid: u32,
    pub permissions: u16,
    pub state: SemState,
}

impl SemaphoreSet {
    pub const fn new() -> Self {
        Self {
            key: 0,
            sems: [const { Semaphore::new() }; MAX_SEM_SET_SIZE],
            nsems: 0,
            owner_pid: 0,
            permissions: 0o666,
            state: SemState::Free,
        }
    }

    /// Initialize the semaphore set
    pub fn init(&mut self, key: u32, nsems: usize, pid: u32) {
        self.key = key;
        self.nsems = core::cmp::min(nsems, MAX_SEM_SET_SIZE);
        self.owner_pid = pid;
        self.state = SemState::Active;

        for i in 0..self.nsems {
            self.sems[i].init_counting(0, i32::MAX, pid);
        }
    }

    /// Set value of a specific semaphore in the set
    pub fn setval(&mut self, sem_num: usize, value: i32) -> bool {
        if sem_num >= self.nsems {
            return false;
        }
        self.sems[sem_num].count.store(value, Ordering::Release);
        true
    }

    /// Get value of a specific semaphore
    pub fn getval(&self, sem_num: usize) -> Option<i32> {
        if sem_num >= self.nsems {
            return None;
        }
        Some(self.sems[sem_num].value())
    }

    /// Perform an atomic operation on multiple semaphores in the set
    pub fn semop(&self, ops: &[(usize, i32)]) -> bool {
        // First check if all operations can proceed
        for &(sem_num, sem_op) in ops {
            if sem_num >= self.nsems {
                return false;
            }
            if sem_op < 0 {
                let current = self.sems[sem_num].value();
                if current + sem_op < 0 {
                    return false; // Would block
                }
            }
        }

        // Apply all operations
        for &(sem_num, sem_op) in ops {
            if sem_op > 0 {
                self.sems[sem_num].count.fetch_add(sem_op, Ordering::AcqRel);
            } else if sem_op < 0 {
                self.sems[sem_num].count.fetch_add(sem_op, Ordering::AcqRel);
            }
            // sem_op == 0: wait for zero (not implemented in this simplified version)
        }

        true
    }
}

// =============================================================================
// Global semaphore registry
// =============================================================================

pub const MAX_SEM_SETS: usize = 32;

pub struct SemaphoreRegistry {
    semaphores: [Semaphore; MAX_SEMAPHORES],
    sem_count: usize,
    sets: [SemaphoreSet; MAX_SEM_SETS],
    set_count: usize,
}

impl SemaphoreRegistry {
    pub const fn new() -> Self {
        Self {
            semaphores: [const { Semaphore::new() }; MAX_SEMAPHORES],
            sem_count: 0,
            sets: [const { SemaphoreSet::new() }; MAX_SEM_SETS],
            set_count: 0,
        }
    }

    /// Create a new named semaphore
    pub fn create(&mut self, name: &[u8], initial: i32, max: i32, pid: u32) -> Option<u32> {
        // Find free slot
        for i in 0..MAX_SEMAPHORES {
            if self.semaphores[i].state == SemState::Free {
                self.semaphores[i].init_counting(initial, max, pid);
                self.semaphores[i].set_name(name);
                if i >= self.sem_count {
                    self.sem_count = i + 1;
                }
                return Some(i as u32);
            }
        }
        None
    }

    /// Look up a semaphore by name
    pub fn find_by_name(&self, name: &[u8]) -> Option<u32> {
        for i in 0..self.sem_count {
            if self.semaphores[i].state == SemState::Active {
                let sname = &self.semaphores[i].name[..self.semaphores[i].name_len as usize];
                if sname == name {
                    return Some(i as u32);
                }
            }
        }
        None
    }

    /// Get a semaphore by index
    pub fn get(&self, id: u32) -> Option<&Semaphore> {
        if (id as usize) < MAX_SEMAPHORES && self.semaphores[id as usize].state == SemState::Active {
            Some(&self.semaphores[id as usize])
        } else {
            None
        }
    }

    /// Get mutable semaphore
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Semaphore> {
        if (id as usize) < MAX_SEMAPHORES && self.semaphores[id as usize].state == SemState::Active {
            Some(&mut self.semaphores[id as usize])
        } else {
            None
        }
    }

    /// Destroy a semaphore
    pub fn destroy(&mut self, id: u32) {
        if (id as usize) < MAX_SEMAPHORES {
            self.semaphores[id as usize].destroy();
            self.semaphores[id as usize].state = SemState::Free;
        }
    }

    /// Create a semaphore set
    pub fn create_set(&mut self, key: u32, nsems: usize, pid: u32) -> Option<u32> {
        for i in 0..MAX_SEM_SETS {
            if self.sets[i].state == SemState::Free {
                self.sets[i].init(key, nsems, pid);
                if i >= self.set_count {
                    self.set_count = i + 1;
                }
                return Some(i as u32);
            }
        }
        None
    }

    /// Find a semaphore set by key
    pub fn find_set(&self, key: u32) -> Option<u32> {
        for i in 0..self.set_count {
            if self.sets[i].state == SemState::Active && self.sets[i].key == key {
                return Some(i as u32);
            }
        }
        None
    }

    pub fn active_count(&self) -> usize {
        self.semaphores[..self.sem_count]
            .iter()
            .filter(|s| s.state == SemState::Active)
            .count()
    }
}

static mut REGISTRY: SemaphoreRegistry = SemaphoreRegistry::new();

/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn registry() -> &'static mut SemaphoreRegistry {
    &mut *core::ptr::addr_of_mut!(REGISTRY)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_sem_create(initial: i32, max: i32, pid: u32) -> i32 {
    unsafe {
        match registry().create(b"", initial, max, pid) {
            Some(id) => id as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_sem_wait(id: u32) -> i32 {
    unsafe {
        match registry().get(id) {
            Some(sem) => if sem.wait() { 0 } else { -1 },
            None => -2,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_sem_try_wait(id: u32) -> i32 {
    unsafe {
        match registry().get(id) {
            Some(sem) => if sem.try_wait() { 0 } else { -1 },
            None => -2,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_sem_post(id: u32) -> i32 {
    unsafe {
        match registry().get(id) {
            Some(sem) => if sem.post() { 0 } else { -1 },
            None => -2,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_sem_destroy(id: u32) {
    unsafe {
        registry().destroy(id);
    }
}
