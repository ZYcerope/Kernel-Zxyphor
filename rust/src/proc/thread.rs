// =============================================================================
// Kernel Zxyphor — Thread Management (Rust)
// =============================================================================
// Kernel and user threads with full lifecycle management:
//   - Thread control block (TCB)
//   - Thread states and transitions
//   - Thread-local storage (TLS) regions
//   - CPU context (register state)
//   - Kernel stack management
//   - Thread groups
//   - Futex-like synchronization
//   - Robust futex list
//   - Work queue threads
// =============================================================================

/// Maximum threads
const MAX_THREADS: usize = 2048;
/// Maximum TLS regions per thread
const MAX_TLS: usize = 8;
/// Maximum work queue entries
const MAX_WORK_QUEUE: usize = 256;
/// Maximum futex waiters
const MAX_FUTEX_WAITERS: usize = 128;
/// Kernel stack size
const KERNEL_STACK_SIZE: usize = 16384; // 16 KiB
/// Maximum thread name length
const MAX_THREAD_NAME: usize = 16;

// ---------------------------------------------------------------------------
// Thread state
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ThreadState {
    Created     = 0,
    Runnable    = 1,
    Running     = 2,
    Blocked     = 3,
    Sleeping    = 4,
    Stopped     = 5,
    Dead        = 6,
    FutexWait   = 7,
    IoWait      = 8,
}

// ---------------------------------------------------------------------------
// Thread type
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ThreadType {
    User   = 0,
    Kernel = 1,
    Idle   = 2,
    Worker = 3,
}

// ---------------------------------------------------------------------------
// CPU context (x86_64 register state)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,        // FS base (TLS)
    pub gs: u64,        // GS base (per-CPU)
    pub cr3: u64,       // Page table base
    pub fpu_state: [u8; 512], // FXSAVE area
    pub fpu_initialized: bool,
}

impl CpuContext {
    pub const fn new() -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rflags: 0x200, // IF=1
            cs: 0x08, ss: 0x10,
            ds: 0x10, es: 0x10,
            fs: 0, gs: 0,
            cr3: 0,
            fpu_state: [0u8; 512],
            fpu_initialized: false,
        }
    }

    /// Set up for kernel thread
    pub fn setup_kernel(&mut self, entry: u64, stack_top: u64) {
        self.rip = entry;
        self.rsp = stack_top;
        self.rbp = stack_top;
        self.cs = 0x08;  // Kernel code segment
        self.ss = 0x10;  // Kernel data segment
        self.rflags = 0x200; // IF=1
    }

    /// Set up for user thread
    pub fn setup_user(&mut self, entry: u64, stack_top: u64, cr3: u64) {
        self.rip = entry;
        self.rsp = stack_top;
        self.rbp = stack_top;
        self.cs = 0x23;  // User code segment (RPL=3)
        self.ss = 0x1B;  // User data segment (RPL=3)
        self.ds = 0x1B;
        self.es = 0x1B;
        self.cr3 = cr3;
        self.rflags = 0x200; // IF=1
    }
}

// ---------------------------------------------------------------------------
// TLS region
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct TlsRegion {
    pub base: u64,
    pub size: u32,
    pub active: bool,
}

impl TlsRegion {
    pub const fn new() -> Self {
        Self { base: 0, size: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// Kernel stack
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct KernelStack {
    pub base: u64,       // Bottom of stack
    pub size: u32,
    pub top: u64,        // Current stack pointer (grows down)
    pub guard_page: u64, // Guard page address
    pub allocated: bool,
}

impl KernelStack {
    pub const fn new() -> Self {
        Self {
            base: 0,
            size: KERNEL_STACK_SIZE as u32,
            top: 0,
            guard_page: 0,
            allocated: false,
        }
    }

    pub fn setup(&mut self, base_addr: u64) {
        self.base = base_addr;
        self.top = base_addr + KERNEL_STACK_SIZE as u64;
        self.guard_page = base_addr.wrapping_sub(4096);
        self.allocated = true;
    }
}

// ---------------------------------------------------------------------------
// Thread Control Block
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ThreadControlBlock {
    pub tid: u32,
    pub pid: u32,            // Owning process
    pub state: ThreadState,
    pub thread_type: ThreadType,
    pub active: bool,

    // Name
    pub name: [u8; MAX_THREAD_NAME],
    pub name_len: u8,

    // CPU context
    pub ctx: CpuContext,

    // Stacks
    pub kernel_stack: KernelStack,
    pub user_stack_base: u64,
    pub user_stack_size: u64,

    // Scheduling
    pub priority: i16,
    pub nice: i8,
    pub cpu_affinity: u64,   // Bitmask of allowed CPUs
    pub last_cpu: u8,
    pub preempt_count: u32,  // Nesting of preemption disable
    pub time_slice: u32,     // Remaining time slice (ticks)
    pub vruntime: u64,

    // TLS
    pub tls: [TlsRegion; MAX_TLS],
    pub tls_count: u8,

    // Synchronization
    pub futex_addr: u64,     // futex wait address
    pub futex_val: u32,      // Expected value

    // Accounting
    pub total_ticks: u64,
    pub user_ticks: u64,
    pub kernel_ticks: u64,
    pub block_count: u64,    // Times blocked
    pub wake_count: u64,     // Times woken

    // Cleanup
    pub clear_child_tid: u64,
    pub robust_list: u64,    // Robust futex list head
    pub robust_list_len: u32,

    // Exit
    pub exit_code: i32,
}

impl ThreadControlBlock {
    pub const fn new() -> Self {
        Self {
            tid: 0,
            pid: 0,
            state: ThreadState::Created,
            thread_type: ThreadType::User,
            active: false,
            name: [0u8; MAX_THREAD_NAME],
            name_len: 0,
            ctx: CpuContext::new(),
            kernel_stack: KernelStack::new(),
            user_stack_base: 0,
            user_stack_size: 0,
            priority: 120,
            nice: 0,
            cpu_affinity: u64::MAX, // All CPUs
            last_cpu: 0,
            preempt_count: 0,
            time_slice: 100,
            vruntime: 0,
            tls: [const { TlsRegion::new() }; MAX_TLS],
            tls_count: 0,
            futex_addr: 0,
            futex_val: 0,
            total_ticks: 0,
            user_ticks: 0,
            kernel_ticks: 0,
            block_count: 0,
            wake_count: 0,
            clear_child_tid: 0,
            robust_list: 0,
            robust_list_len: 0,
            exit_code: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > MAX_THREAD_NAME - 1 { MAX_THREAD_NAME - 1 } else { name.len() };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;
        self.name_len = len as u8;
    }

    pub fn is_kernel(&self) -> bool {
        self.thread_type == ThreadType::Kernel || self.thread_type == ThreadType::Idle
    }

    pub fn can_preempt(&self) -> bool {
        self.preempt_count == 0
    }

    pub fn disable_preemption(&mut self) {
        self.preempt_count += 1;
    }

    pub fn enable_preemption(&mut self) {
        self.preempt_count = self.preempt_count.saturating_sub(1);
    }

    pub fn add_tls(&mut self, base: u64, size: u32) -> bool {
        if self.tls_count as usize >= MAX_TLS { return false; }
        let idx = self.tls_count as usize;
        self.tls[idx] = TlsRegion { base, size, active: true };
        self.tls_count += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Futex
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct FutexWaiter {
    pub addr: u64,
    pub tid: u32,
    pub bitset: u32,
    pub active: bool,
}

impl FutexWaiter {
    pub const fn new() -> Self {
        Self { addr: 0, tid: 0, bitset: 0, active: false }
    }
}

pub struct FutexTable {
    waiters: [FutexWaiter; MAX_FUTEX_WAITERS],
    count: u32,
}

impl FutexTable {
    pub const fn new() -> Self {
        Self {
            waiters: [const { FutexWaiter::new() }; MAX_FUTEX_WAITERS],
            count: 0,
        }
    }

    /// Add a futex waiter
    pub fn wait(&mut self, addr: u64, tid: u32, bitset: u32) -> bool {
        for i in 0..MAX_FUTEX_WAITERS {
            if !self.waiters[i].active {
                self.waiters[i] = FutexWaiter {
                    addr, tid, bitset, active: true,
                };
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Wake up to `count` waiters on address
    pub fn wake(&mut self, addr: u64, count: u32) -> u32 {
        let mut woken = 0u32;
        for i in 0..MAX_FUTEX_WAITERS {
            if woken >= count { break; }
            if self.waiters[i].active && self.waiters[i].addr == addr {
                self.waiters[i].active = false;
                self.count -= 1;
                woken += 1;
            }
        }
        woken
    }

    /// Wake waiters matching bitset
    pub fn wake_bitset(&mut self, addr: u64, count: u32, bitset: u32) -> u32 {
        let mut woken = 0u32;
        for i in 0..MAX_FUTEX_WAITERS {
            if woken >= count { break; }
            if self.waiters[i].active && self.waiters[i].addr == addr
                && (self.waiters[i].bitset & bitset) != 0
            {
                self.waiters[i].active = false;
                self.count -= 1;
                woken += 1;
            }
        }
        woken
    }

    /// Requeue waiters from one address to another
    pub fn requeue(&mut self, old_addr: u64, new_addr: u64, wake_count: u32, requeue_count: u32) -> u32 {
        let mut woken = 0u32;
        let mut requeued = 0u32;
        for i in 0..MAX_FUTEX_WAITERS {
            if self.waiters[i].active && self.waiters[i].addr == old_addr {
                if woken < wake_count {
                    self.waiters[i].active = false;
                    self.count -= 1;
                    woken += 1;
                } else if requeued < requeue_count {
                    self.waiters[i].addr = new_addr;
                    requeued += 1;
                }
            }
        }
        woken
    }
}

// ---------------------------------------------------------------------------
// Work queue
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct WorkItem {
    pub func: u64,     // Function pointer
    pub data: u64,     // Argument
    pub priority: u8,
    pub active: bool,
}

impl WorkItem {
    pub const fn new() -> Self {
        Self { func: 0, data: 0, priority: 0, active: false }
    }
}

pub struct WorkQueue {
    items: [WorkItem; MAX_WORK_QUEUE],
    head: usize,
    tail: usize,
    count: u32,
    name: [u8; 16],
    name_len: u8,
    worker_tid: u32,
    max_active: u32,
}

impl WorkQueue {
    pub const fn new() -> Self {
        Self {
            items: [const { WorkItem::new() }; MAX_WORK_QUEUE],
            head: 0, tail: 0, count: 0,
            name: [0u8; 16], name_len: 0,
            worker_tid: 0,
            max_active: 1,
        }
    }

    pub fn enqueue(&mut self, func: u64, data: u64, priority: u8) -> bool {
        if self.count as usize >= MAX_WORK_QUEUE { return false; }
        self.items[self.tail] = WorkItem { func, data, priority, active: true };
        self.tail = (self.tail + 1) % MAX_WORK_QUEUE;
        self.count += 1;
        true
    }

    pub fn dequeue(&mut self) -> Option<WorkItem> {
        if self.count == 0 { return None; }
        let item = self.items[self.head];
        self.items[self.head].active = false;
        self.head = (self.head + 1) % MAX_WORK_QUEUE;
        self.count -= 1;
        Some(item)
    }

    pub fn pending(&self) -> u32 {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Thread table
// ---------------------------------------------------------------------------

pub struct ThreadTable {
    threads: [ThreadControlBlock; MAX_THREADS],
    count: u32,
    next_tid: u32,
    futex: FutexTable,
    work_queues: [WorkQueue; 4],
    wq_count: u8,
}

impl ThreadTable {
    pub const fn new() -> Self {
        Self {
            threads: [const { ThreadControlBlock::new() }; MAX_THREADS],
            count: 0,
            next_tid: 1,
            futex: FutexTable::new(),
            work_queues: [const { WorkQueue::new() }; 4],
            wq_count: 0,
        }
    }

    fn alloc_tid(&mut self) -> Option<u32> {
        let start = self.next_tid;
        loop {
            let tid = self.next_tid;
            self.next_tid = if self.next_tid >= 65535 { 1 } else { self.next_tid + 1 };
            let mut in_use = false;
            for i in 0..MAX_THREADS {
                if self.threads[i].active && self.threads[i].tid == tid {
                    in_use = true;
                    break;
                }
            }
            if !in_use { return Some(tid); }
            if self.next_tid == start { return None; }
        }
    }

    fn find_slot(&self) -> Option<usize> {
        for i in 0..MAX_THREADS {
            if !self.threads[i].active { return Some(i); }
        }
        None
    }

    pub fn find_by_tid(&self, tid: u32) -> Option<usize> {
        for i in 0..MAX_THREADS {
            if self.threads[i].active && self.threads[i].tid == tid {
                return Some(i);
            }
        }
        None
    }

    /// Create a kernel thread
    pub fn create_kernel_thread(&mut self, name: &[u8], entry: u64, stack_base: u64) -> Option<u32> {
        let slot = self.find_slot()?;
        let tid = self.alloc_tid()?;

        self.threads[slot] = ThreadControlBlock::new();
        self.threads[slot].tid = tid;
        self.threads[slot].pid = 0;
        self.threads[slot].thread_type = ThreadType::Kernel;
        self.threads[slot].state = ThreadState::Runnable;
        self.threads[slot].active = true;
        self.threads[slot].set_name(name);
        self.threads[slot].ctx.setup_kernel(entry, stack_base + KERNEL_STACK_SIZE as u64);
        self.threads[slot].kernel_stack.setup(stack_base);
        self.count += 1;

        Some(tid)
    }

    /// Create a user thread
    pub fn create_user_thread(
        &mut self,
        pid: u32,
        entry: u64,
        user_stack: u64,
        user_stack_size: u64,
        kernel_stack_base: u64,
        cr3: u64,
    ) -> Option<u32> {
        let slot = self.find_slot()?;
        let tid = self.alloc_tid()?;

        self.threads[slot] = ThreadControlBlock::new();
        self.threads[slot].tid = tid;
        self.threads[slot].pid = pid;
        self.threads[slot].thread_type = ThreadType::User;
        self.threads[slot].state = ThreadState::Runnable;
        self.threads[slot].active = true;
        self.threads[slot].user_stack_base = user_stack;
        self.threads[slot].user_stack_size = user_stack_size;
        self.threads[slot].ctx.setup_user(entry, user_stack + user_stack_size, cr3);
        self.threads[slot].kernel_stack.setup(kernel_stack_base);
        self.count += 1;

        Some(tid)
    }

    /// Exit a thread
    pub fn exit_thread(&mut self, tid: u32, code: i32) -> bool {
        let slot = match self.find_by_tid(tid) {
            Some(s) => s,
            None => return false,
        };
        self.threads[slot].state = ThreadState::Dead;
        self.threads[slot].exit_code = code;
        self.threads[slot].active = false;
        self.count -= 1;

        // Process robust futex list
        if self.threads[slot].robust_list != 0 {
            // Wake any futex waiters on the robust list entries
            self.futex.wake(self.threads[slot].robust_list, u32::MAX);
        }

        true
    }

    /// Block a thread (for mutex/futex wait)
    pub fn block_thread(&mut self, tid: u32) -> bool {
        let slot = match self.find_by_tid(tid) {
            Some(s) => s,
            None => return false,
        };
        self.threads[slot].state = ThreadState::Blocked;
        self.threads[slot].block_count += 1;
        true
    }

    /// Wake a thread
    pub fn wake_thread(&mut self, tid: u32) -> bool {
        let slot = match self.find_by_tid(tid) {
            Some(s) => s,
            None => return false,
        };
        if self.threads[slot].state == ThreadState::Blocked
            || self.threads[slot].state == ThreadState::Sleeping
            || self.threads[slot].state == ThreadState::FutexWait
            || self.threads[slot].state == ThreadState::IoWait
        {
            self.threads[slot].state = ThreadState::Runnable;
            self.threads[slot].wake_count += 1;
            true
        } else {
            false
        }
    }

    /// Futex wait
    pub fn futex_wait(&mut self, tid: u32, addr: u64, expected: u32) -> bool {
        let slot = match self.find_by_tid(tid) {
            Some(s) => s,
            None => return false,
        };
        self.threads[slot].state = ThreadState::FutexWait;
        self.threads[slot].futex_addr = addr;
        self.threads[slot].futex_val = expected;
        self.futex.wait(addr, tid, u32::MAX)
    }

    /// Futex wake
    pub fn futex_wake(&mut self, addr: u64, count: u32) -> u32 {
        let woken = self.futex.wake(addr, count);
        // Also update thread states
        for i in 0..MAX_THREADS {
            if self.threads[i].active
                && self.threads[i].state == ThreadState::FutexWait
                && self.threads[i].futex_addr == addr
            {
                self.threads[i].state = ThreadState::Runnable;
            }
        }
        woken
    }

    /// Get threads for a process
    pub fn threads_for_pid(&self, pid: u32) -> u32 {
        let mut count = 0u32;
        for i in 0..MAX_THREADS {
            if self.threads[i].active && self.threads[i].pid == pid {
                count += 1;
            }
        }
        count
    }

    pub fn get(&self, tid: u32) -> Option<&ThreadControlBlock> {
        self.find_by_tid(tid).map(|i| &self.threads[i])
    }

    pub fn get_mut(&mut self, tid: u32) -> Option<&mut ThreadControlBlock> {
        self.find_by_tid(tid).map(move |i| &mut self.threads[i])
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut THREAD_TABLE: ThreadTable = ThreadTable::new();

fn thread_table() -> &'static mut ThreadTable {
    unsafe { &mut THREAD_TABLE }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_thread_create_kernel(entry: u64, stack_base: u64) -> i32 {
    match thread_table().create_kernel_thread(b"kthread", entry, stack_base) {
        Some(tid) => tid as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_thread_create_user(
    pid: u32, entry: u64, user_stack: u64, user_stack_size: u64,
    kernel_stack_base: u64, cr3: u64,
) -> i32 {
    match thread_table().create_user_thread(pid, entry, user_stack, user_stack_size, kernel_stack_base, cr3) {
        Some(tid) => tid as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_thread_exit(tid: u32, code: i32) -> i32 {
    if thread_table().exit_thread(tid, code) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_thread_block(tid: u32) -> i32 {
    if thread_table().block_thread(tid) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_thread_wake(tid: u32) -> i32 {
    if thread_table().wake_thread(tid) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_futex_wait(tid: u32, addr: u64, expected: u32) -> i32 {
    if thread_table().futex_wait(tid, addr, expected) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_futex_wake(addr: u64, count: u32) -> u32 {
    thread_table().futex_wake(addr, count)
}

#[no_mangle]
pub extern "C" fn zxyphor_thread_count() -> u32 {
    thread_table().count
}

#[no_mangle]
pub extern "C" fn zxyphor_threads_for_pid(pid: u32) -> u32 {
    thread_table().threads_for_pid(pid)
}
