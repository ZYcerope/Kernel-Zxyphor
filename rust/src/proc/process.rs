// =============================================================================
// Kernel Zxyphor — Process Management (Rust)
// =============================================================================
// Linux-quality process control blocks and lifecycle management:
//   - ProcessControlBlock with full state tracking
//   - File descriptor table per process
//   - Memory map regions (VMAs)
//   - Process tree (parent/children)
//   - Signal handling disposition
//   - Resource limits (rlimit)
//   - Credentials (uid/gid/caps)
//   - Namespaces (mount/pid/net/user)
//   - Process state machine
//   - Fork/clone semantics
//   - Exit and wait
// =============================================================================

/// Maximum processes supported
const MAX_PROCESSES: usize = 1024;
/// Maximum open file descriptors per process
const MAX_FDS: usize = 256;
/// Maximum memory map areas per process
const MAX_VMAS: usize = 128;
/// Maximum children per process
const MAX_CHILDREN: usize = 64;
/// Maximum signal handlers
const MAX_SIGNALS: usize = 64;
/// Maximum environment variables
const MAX_ENV: usize = 64;
/// Maximum argv entries
const MAX_ARGV: usize = 32;
/// Maximum resource limit entries
const MAX_RLIMITS: usize = 16;
/// Maximum supplementary groups
const MAX_GROUPS: usize = 32;

// ---------------------------------------------------------------------------
// Process state
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ProcessState {
    Created   = 0,
    Ready     = 1,
    Running   = 2,
    Sleeping  = 3,
    Stopped   = 4,
    Zombie    = 5,
    Dead      = 6,
    TraceStopped = 7,
    DiskSleep = 8,  // Uninterruptible sleep
}

// ---------------------------------------------------------------------------
// Clone flags (Linux-compatible)
// ---------------------------------------------------------------------------

pub const CLONE_VM: u32        = 0x00000100;
pub const CLONE_FS: u32        = 0x00000200;
pub const CLONE_FILES: u32     = 0x00000400;
pub const CLONE_SIGHAND: u32   = 0x00000800;
pub const CLONE_PTRACE: u32    = 0x00002000;
pub const CLONE_VFORK: u32     = 0x00004000;
pub const CLONE_PARENT: u32    = 0x00008000;
pub const CLONE_THREAD: u32    = 0x00010000;
pub const CLONE_NEWNS: u32     = 0x00020000;
pub const CLONE_SYSVSEM: u32   = 0x00040000;
pub const CLONE_SETTLS: u32    = 0x00080000;
pub const CLONE_NEWPID: u32    = 0x20000000;
pub const CLONE_NEWNET: u32    = 0x40000000;
pub const CLONE_NEWUSER: u32   = 0x10000000;

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum RlimitResource {
    Cpu         = 0,
    Fsize       = 1,
    Data        = 2,
    Stack       = 3,
    Core        = 4,
    Rss         = 5,
    Nproc       = 6,
    Nofile      = 7,
    Memlock     = 8,
    As          = 9,
    Locks       = 10,
    Sigpending  = 11,
    Msgqueue    = 12,
    Nice        = 13,
    Rtprio      = 14,
    Rttime      = 15,
}

#[derive(Clone, Copy)]
pub struct Rlimit {
    pub cur: u64,  // Soft limit
    pub max: u64,  // Hard limit
}

impl Rlimit {
    pub const fn new(cur: u64, max: u64) -> Self {
        Self { cur, max }
    }

    pub const fn unlimited() -> Self {
        Self { cur: u64::MAX, max: u64::MAX }
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub groups: [u32; MAX_GROUPS],
    pub ngroups: u8,
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_bounding: u64,
    pub cap_ambient: u64,
    pub securebits: u32,
}

impl Credentials {
    pub const fn new() -> Self {
        Self {
            uid: 0, gid: 0,
            euid: 0, egid: 0,
            suid: 0, sgid: 0,
            fsuid: 0, fsgid: 0,
            groups: [0u32; MAX_GROUPS],
            ngroups: 0,
            cap_inheritable: 0,
            cap_permitted: 0,
            cap_effective: 0,
            cap_bounding: u64::MAX,
            cap_ambient: 0,
            securebits: 0,
        }
    }

    pub fn is_root(&self) -> bool {
        self.euid == 0
    }

    pub fn has_capability(&self, cap: u8) -> bool {
        if cap >= 64 { return false; }
        (self.cap_effective & (1u64 << cap)) != 0
    }

    pub fn in_group(&self, gid: u32) -> bool {
        if self.gid == gid || self.egid == gid { return true; }
        for i in 0..self.ngroups as usize {
            if self.groups[i] == gid { return true; }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// File descriptor entry
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum FdType {
    None    = 0,
    File    = 1,
    Pipe    = 2,
    Socket  = 3,
    Epoll   = 4,
    Timer   = 5,
    Signal  = 6,
    Event   = 7,
    Dir     = 8,
}

pub const FD_CLOEXEC: u32 = 0x01;
pub const FD_NONBLOCK: u32 = 0x02;
pub const FD_APPEND: u32 = 0x04;
pub const FD_SYNC: u32 = 0x08;

#[derive(Clone, Copy)]
pub struct FileDescriptor {
    pub fd_type: FdType,
    pub flags: u32,
    pub offset: u64,
    pub inode: u64,
    pub dev_id: u32,
    pub ref_count: u32,
    pub active: bool,
}

impl FileDescriptor {
    pub const fn new() -> Self {
        Self {
            fd_type: FdType::None,
            flags: 0,
            offset: 0,
            inode: 0,
            dev_id: 0,
            ref_count: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Virtual memory area (VMA)
// ---------------------------------------------------------------------------

pub const VMA_READ: u32    = 0x01;
pub const VMA_WRITE: u32   = 0x02;
pub const VMA_EXEC: u32    = 0x04;
pub const VMA_SHARED: u32  = 0x08;
pub const VMA_GROWSDOWN: u32 = 0x10; // Stack
pub const VMA_DENYWRITE: u32 = 0x20;
pub const VMA_LOCKED: u32   = 0x40;
pub const VMA_HUGETLB: u32  = 0x80;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum VmaType {
    Anonymous = 0,
    FileBacked = 1,
    Stack = 2,
    Heap = 3,
    SharedMem = 4,
    DeviceMap = 5,
    Vdso = 6,
}

#[derive(Clone, Copy)]
pub struct VirtualMemoryArea {
    pub start: u64,
    pub end: u64,
    pub flags: u32,
    pub vma_type: VmaType,
    pub file_inode: u64,
    pub file_offset: u64,
    pub active: bool,
}

impl VirtualMemoryArea {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            flags: 0,
            vma_type: VmaType::Anonymous,
            file_inode: 0,
            file_offset: 0,
            active: false,
        }
    }

    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

// ---------------------------------------------------------------------------
// Signal disposition
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SignalAction {
    Default  = 0,
    Ignore   = 1,
    Handler  = 2,
    SigInfo  = 3,
}

#[derive(Clone, Copy)]
pub struct SignalDisposition {
    pub action: SignalAction,
    pub handler: u64,       // Handler function address
    pub mask: u64,          // Blocked signals during handler
    pub flags: u32,         // SA_RESTART, SA_NOCLDSTOP, etc
    pub restorer: u64,      // Signal return trampoline
}

impl SignalDisposition {
    pub const fn new() -> Self {
        Self {
            action: SignalAction::Default,
            handler: 0,
            mask: 0,
            flags: 0,
            restorer: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Namespace IDs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct NamespaceIds {
    pub mnt_ns: u32,
    pub pid_ns: u32,
    pub net_ns: u32,
    pub user_ns: u32,
    pub uts_ns: u32,
    pub ipc_ns: u32,
    pub cgroup_ns: u32,
    pub time_ns: u32,
}

impl NamespaceIds {
    pub const fn new() -> Self {
        Self {
            mnt_ns: 0, pid_ns: 0, net_ns: 0, user_ns: 0,
            uts_ns: 0, ipc_ns: 0, cgroup_ns: 0, time_ns: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Process times (accounting)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ProcessTimes {
    pub utime: u64,          // User mode ticks
    pub stime: u64,          // Kernel mode ticks
    pub cutime: u64,         // Children user time
    pub cstime: u64,         // Children kernel time
    pub start_time: u64,     // Monotonic start
    pub real_start_time: u64, // Wall clock start
    pub min_flt: u64,        // Minor page faults
    pub maj_flt: u64,        // Major page faults
    pub cmin_flt: u64,       // Children minor faults
    pub cmaj_flt: u64,       // Children major faults
    pub inblock: u64,        // Block input operations
    pub oublock: u64,        // Block output operations
    pub nvcsw: u64,          // Voluntary context switches
    pub nivcsw: u64,         // Involuntary context switches
}

impl ProcessTimes {
    pub const fn new() -> Self {
        Self {
            utime: 0, stime: 0, cutime: 0, cstime: 0,
            start_time: 0, real_start_time: 0,
            min_flt: 0, maj_flt: 0, cmin_flt: 0, cmaj_flt: 0,
            inblock: 0, oublock: 0, nvcsw: 0, nivcsw: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory map summary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct MmStruct {
    pub vmas: [VirtualMemoryArea; MAX_VMAS],
    pub vma_count: u32,
    pub pgd: u64,             // Page global directory physical address
    pub total_vm: u64,        // Total pages mapped
    pub locked_vm: u64,       // Locked (mlock'd) pages
    pub pinned_vm: u64,       // Pinned pages
    pub data_vm: u64,         // Data + BSS pages
    pub exec_vm: u64,         // Executable pages
    pub stack_vm: u64,        // Stack pages
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub map_count: u32,
    pub hiwater_rss: u64,     // Peak RSS
    pub hiwater_vm: u64,      // Peak virtual mem
}

impl MmStruct {
    pub const fn new() -> Self {
        Self {
            vmas: [const { VirtualMemoryArea::new() }; MAX_VMAS],
            vma_count: 0,
            pgd: 0,
            total_vm: 0, locked_vm: 0, pinned_vm: 0,
            data_vm: 0, exec_vm: 0, stack_vm: 0,
            start_code: 0, end_code: 0,
            start_data: 0, end_data: 0,
            start_brk: 0, brk: 0,
            start_stack: 0,
            arg_start: 0, arg_end: 0,
            env_start: 0, env_end: 0,
            map_count: 0,
            hiwater_rss: 0, hiwater_vm: 0,
        }
    }

    /// Find VMA containing an address
    pub fn find_vma(&self, addr: u64) -> Option<usize> {
        for i in 0..self.vma_count as usize {
            if self.vmas[i].active && self.vmas[i].contains(addr) {
                return Some(i);
            }
        }
        None
    }

    /// Insert a new VMA
    pub fn insert_vma(&mut self, start: u64, end: u64, flags: u32, vma_type: VmaType) -> Option<usize> {
        if self.vma_count as usize >= MAX_VMAS { return None; }

        // Check for overlap
        for i in 0..self.vma_count as usize {
            if self.vmas[i].active && self.vmas[i].overlaps(start, end) {
                return None;
            }
        }

        let idx = self.vma_count as usize;
        self.vmas[idx] = VirtualMemoryArea {
            start, end, flags, vma_type,
            file_inode: 0, file_offset: 0,
            active: true,
        };
        self.vma_count += 1;
        self.total_vm += (end - start) / 4096;
        Some(idx)
    }

    /// Remove a VMA
    pub fn remove_vma(&mut self, idx: usize) -> bool {
        if idx >= self.vma_count as usize { return false; }
        if !self.vmas[idx].active { return false; }
        let pages = self.vmas[idx].size() / 4096;
        self.total_vm = self.total_vm.saturating_sub(pages);
        self.vmas[idx].active = false;
        true
    }

    /// Extend the brk (heap)
    pub fn do_brk(&mut self, new_brk: u64) -> bool {
        if new_brk < self.start_brk { return false; }
        self.brk = new_brk;
        true
    }
}

// ---------------------------------------------------------------------------
// Process Control Block
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ProcessControlBlock {
    pub pid: u32,
    pub tgid: u32,              // Thread group ID (= PID of group leader)
    pub ppid: u32,
    pub pgid: u32,              // Process group ID
    pub sid: u32,               // Session ID
    pub state: ProcessState,
    pub exit_code: i32,
    pub exit_signal: i32,
    pub active: bool,

    // Name
    pub comm: [u8; 16],
    pub comm_len: u8,

    // Scheduling
    pub priority: i16,
    pub static_prio: i16,
    pub normal_prio: i16,
    pub rt_priority: u8,
    pub policy: u8,             // SCHED_NORMAL, SCHED_FIFO, etc
    pub cpu: u8,
    pub on_rq: bool,
    pub vruntime: u64,

    // Credentials
    pub cred: Credentials,

    // File descriptors
    pub fds: [FileDescriptor; MAX_FDS],
    pub fd_count: u32,
    pub fd_next: u32,

    // Memory
    pub mm: MmStruct,

    // Signals
    pub sig_disposition: [SignalDisposition; MAX_SIGNALS],
    pub sig_pending: u64,
    pub sig_blocked: u64,

    // Resource limits
    pub rlimits: [Rlimit; MAX_RLIMITS],

    // Namespaces
    pub ns: NamespaceIds,

    // Accounting
    pub times: ProcessTimes,

    // Process tree
    pub children: [u32; MAX_CHILDREN],
    pub child_count: u32,

    // Flags
    pub flags: u32,

    // Thread-related
    pub thread_count: u32,
    pub clear_child_tid: u64,
    pub set_child_tid: u64,
}

pub const PF_EXITING: u32    = 0x00000004;
pub const PF_VCPU: u32       = 0x00000010;
pub const PF_FORKNOEXEC: u32 = 0x00000040;
pub const PF_SUPERPRIV: u32  = 0x00000100;
pub const PF_DUMPCORE: u32   = 0x00000200;
pub const PF_SIGNALED: u32   = 0x00000400;
pub const PF_MEMALLOC: u32   = 0x00000800;
pub const PF_KTHREAD: u32    = 0x00200000;

impl ProcessControlBlock {
    pub const fn new() -> Self {
        Self {
            pid: 0, tgid: 0, ppid: 0, pgid: 0, sid: 0,
            state: ProcessState::Created,
            exit_code: 0, exit_signal: 0,
            active: false,
            comm: [0u8; 16], comm_len: 0,
            priority: 120, static_prio: 120, normal_prio: 120,
            rt_priority: 0, policy: 0, cpu: 0,
            on_rq: false, vruntime: 0,
            cred: Credentials::new(),
            fds: [const { FileDescriptor::new() }; MAX_FDS],
            fd_count: 0, fd_next: 0,
            mm: MmStruct::new(),
            sig_disposition: [const { SignalDisposition::new() }; MAX_SIGNALS],
            sig_pending: 0, sig_blocked: 0,
            rlimits: [const { Rlimit::unlimited() }; MAX_RLIMITS],
            ns: NamespaceIds::new(),
            times: ProcessTimes::new(),
            children: [0u32; MAX_CHILDREN],
            child_count: 0,
            flags: 0,
            thread_count: 1,
            clear_child_tid: 0,
            set_child_tid: 0,
        }
    }

    pub fn set_comm(&mut self, name: &[u8]) {
        let len = if name.len() > 15 { 15 } else { name.len() };
        self.comm[..len].copy_from_slice(&name[..len]);
        self.comm[len] = 0;
        self.comm_len = len as u8;
    }

    /// Allocate a file descriptor
    pub fn alloc_fd(&mut self) -> Option<u32> {
        for i in self.fd_next as usize..MAX_FDS {
            if !self.fds[i].active {
                self.fds[i].active = true;
                self.fds[i].ref_count = 1;
                self.fd_count += 1;
                self.fd_next = i as u32 + 1;
                return Some(i as u32);
            }
        }
        // Wrap around search
        for i in 0..self.fd_next as usize {
            if !self.fds[i].active {
                self.fds[i].active = true;
                self.fds[i].ref_count = 1;
                self.fd_count += 1;
                self.fd_next = i as u32 + 1;
                return Some(i as u32);
            }
        }
        None
    }

    /// Close a file descriptor
    pub fn close_fd(&mut self, fd: u32) -> bool {
        let idx = fd as usize;
        if idx >= MAX_FDS { return false; }
        if !self.fds[idx].active { return false; }
        self.fds[idx].ref_count = self.fds[idx].ref_count.saturating_sub(1);
        if self.fds[idx].ref_count == 0 {
            self.fds[idx] = FileDescriptor::new();
        }
        self.fd_count = self.fd_count.saturating_sub(1);
        if fd < self.fd_next { self.fd_next = fd; }
        true
    }

    /// Duplicate a file descriptor
    pub fn dup_fd(&mut self, old_fd: u32) -> Option<u32> {
        let old_idx = old_fd as usize;
        if old_idx >= MAX_FDS || !self.fds[old_idx].active { return None; }

        let new_fd = self.alloc_fd()?;
        let new_idx = new_fd as usize;
        self.fds[new_idx] = self.fds[old_idx];
        self.fds[new_idx].ref_count = 1;
        Some(new_fd)
    }

    /// Duplicate fd to a specific target fd
    pub fn dup2_fd(&mut self, old_fd: u32, new_fd: u32) -> bool {
        let old_idx = old_fd as usize;
        let new_idx = new_fd as usize;
        if old_idx >= MAX_FDS || new_idx >= MAX_FDS { return false; }
        if !self.fds[old_idx].active { return false; }

        if self.fds[new_idx].active {
            self.close_fd(new_fd);
        }
        self.fds[new_idx] = self.fds[old_idx];
        self.fds[new_idx].ref_count = 1;
        self.fds[new_idx].active = true;
        self.fd_count += 1;
        true
    }

    /// Add a child process
    pub fn add_child(&mut self, child_pid: u32) -> bool {
        if self.child_count as usize >= MAX_CHILDREN { return false; }
        self.children[self.child_count as usize] = child_pid;
        self.child_count += 1;
        true
    }

    /// Remove a child
    pub fn remove_child(&mut self, child_pid: u32) -> bool {
        for i in 0..self.child_count as usize {
            if self.children[i] == child_pid {
                // Shift
                let mut j = i;
                while j + 1 < self.child_count as usize {
                    self.children[j] = self.children[j + 1];
                    j += 1;
                }
                self.child_count -= 1;
                return true;
            }
        }
        false
    }

    /// Send a signal to this process
    pub fn send_signal(&mut self, sig: u8) -> bool {
        if sig == 0 || sig as usize >= MAX_SIGNALS { return false; }
        let mask = 1u64 << sig;
        if self.sig_blocked & mask != 0 { return false; } // blocked
        self.sig_pending |= mask;
        // Wake up if sleeping
        if self.state == ProcessState::Sleeping {
            self.state = ProcessState::Ready;
        }
        true
    }

    /// Dequeue a pending signal
    pub fn dequeue_signal(&mut self) -> Option<u8> {
        let deliverable = self.sig_pending & !self.sig_blocked;
        if deliverable == 0 { return None; }
        // Find lowest set bit
        let sig = deliverable.trailing_zeros() as u8;
        self.sig_pending &= !(1u64 << sig);
        Some(sig)
    }

    /// Check if process can be reaped (wait())
    pub fn is_reapable(&self) -> bool {
        self.state == ProcessState::Zombie
    }

    /// Transition to zombie
    pub fn do_exit(&mut self, code: i32) {
        self.exit_code = code;
        self.state = ProcessState::Zombie;
        self.flags |= PF_EXITING;
        // Close all FDs
        for i in 0..MAX_FDS {
            if self.fds[i].active {
                self.fds[i] = FileDescriptor::new();
            }
        }
        self.fd_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Process table
// ---------------------------------------------------------------------------

pub struct ProcessTable {
    procs: [ProcessControlBlock; MAX_PROCESSES],
    count: u32,
    next_pid: u32,
    init_pid: u32,
}

impl ProcessTable {
    pub const fn new() -> Self {
        Self {
            procs: [const { ProcessControlBlock::new() }; MAX_PROCESSES],
            count: 0,
            next_pid: 1,
            init_pid: 0,
        }
    }

    /// Allocate PID (monotonically increasing with wraparound)
    fn alloc_pid(&mut self) -> Option<u32> {
        let start = self.next_pid;
        loop {
            let pid = self.next_pid;
            self.next_pid = if self.next_pid >= 32768 { 1 } else { self.next_pid + 1 };

            // Check PID not in use
            let mut in_use = false;
            for i in 0..MAX_PROCESSES {
                if self.procs[i].active && self.procs[i].pid == pid {
                    in_use = true;
                    break;
                }
            }
            if !in_use { return Some(pid); }
            if self.next_pid == start { return None; } // Full
        }
    }

    /// Find a free slot
    fn find_slot(&self) -> Option<usize> {
        for i in 0..MAX_PROCESSES {
            if !self.procs[i].active { return Some(i); }
        }
        None
    }

    /// Create init process (PID 1)
    pub fn create_init(&mut self) -> Option<u32> {
        let slot = self.find_slot()?;
        self.procs[slot] = ProcessControlBlock::new();
        self.procs[slot].pid = 1;
        self.procs[slot].tgid = 1;
        self.procs[slot].ppid = 0;
        self.procs[slot].state = ProcessState::Running;
        self.procs[slot].active = true;
        self.procs[slot].set_comm(b"init");
        self.procs[slot].cred = Credentials::new(); // root
        self.next_pid = 2;
        self.init_pid = 1;
        self.count = 1;

        // Setup standard FDs (stdin/stdout/stderr)
        for _ in 0..3 {
            self.procs[slot].alloc_fd();
        }

        Some(1)
    }

    /// Fork a process
    pub fn fork(&mut self, parent_pid: u32, clone_flags: u32) -> Option<u32> {
        let parent_slot = self.find_by_pid(parent_pid)?;
        let child_slot = self.find_slot()?;
        let child_pid = self.alloc_pid()?;

        // Copy parent PCB
        self.procs[child_slot] = self.procs[parent_slot];

        // Set child-specific fields
        self.procs[child_slot].pid = child_pid;
        self.procs[child_slot].ppid = parent_pid;
        self.procs[child_slot].state = ProcessState::Ready;
        self.procs[child_slot].active = true;
        self.procs[child_slot].child_count = 0;
        self.procs[child_slot].exit_code = 0;
        self.procs[child_slot].sig_pending = 0;
        self.procs[child_slot].times = ProcessTimes::new();

        if clone_flags & CLONE_THREAD != 0 {
            self.procs[child_slot].tgid = self.procs[parent_slot].tgid;
            self.procs[parent_slot].thread_count += 1;
        } else {
            self.procs[child_slot].tgid = child_pid;
        }

        if clone_flags & CLONE_PARENT != 0 {
            self.procs[child_slot].ppid = self.procs[parent_slot].ppid;
        }

        if clone_flags & CLONE_FILES == 0 {
            // Copy FD table (COW semantics — here just a copy)
            // Already copied via struct copy; reset ref counts
            for i in 0..MAX_FDS {
                if self.procs[child_slot].fds[i].active {
                    self.procs[child_slot].fds[i].ref_count = 1;
                }
            }
        }

        if clone_flags & CLONE_VM == 0 {
            // New address space — zero out VMAs (would COW in real impl)
            self.procs[child_slot].mm.vma_count = 0;
            for i in 0..MAX_VMAS {
                self.procs[child_slot].mm.vmas[i] = VirtualMemoryArea::new();
            }
        }

        if clone_flags & CLONE_SIGHAND == 0 {
            // Reset signal dispositions to default
            for i in 0..MAX_SIGNALS {
                self.procs[child_slot].sig_disposition[i] = SignalDisposition::new();
            }
        }

        // Add child to parent's children list
        self.procs[parent_slot].add_child(child_pid);
        self.count += 1;

        Some(child_pid)
    }

    /// Wait for a child (blocking semantics — returns immediately if zombie found)
    pub fn waitpid(&mut self, parent_pid: u32, target_pid: i32) -> Option<(u32, i32)> {
        let parent_slot = self.find_by_pid(parent_pid)?;

        for i in 0..self.procs[parent_slot].child_count as usize {
            let cpid = self.procs[parent_slot].children[i];
            if target_pid > 0 && cpid != target_pid as u32 { continue; }

            if let Some(cslot) = self.find_by_pid(cpid) {
                if self.procs[cslot].is_reapable() {
                    let exit_code = self.procs[cslot].exit_code;

                    // Accumulate child times
                    let pslot = self.find_by_pid(parent_pid).unwrap();
                    self.procs[pslot].times.cutime += self.procs[cslot].times.utime;
                    self.procs[pslot].times.cstime += self.procs[cslot].times.stime;
                    self.procs[pslot].times.cmin_flt += self.procs[cslot].times.min_flt;
                    self.procs[pslot].times.cmaj_flt += self.procs[cslot].times.maj_flt;

                    // Reap
                    self.procs[cslot].state = ProcessState::Dead;
                    self.procs[cslot].active = false;
                    self.procs[pslot].remove_child(cpid);
                    self.count -= 1;

                    return Some((cpid, exit_code));
                }
            }
        }
        None
    }

    /// Exit a process
    pub fn exit_process(&mut self, pid: u32, code: i32) -> bool {
        let slot = match self.find_by_pid(pid) {
            Some(s) => s,
            None => return false,
        };

        self.procs[slot].do_exit(code);

        // Re-parent orphaned children to init
        let children_copy: [u32; MAX_CHILDREN] = self.procs[slot].children;
        let cc = self.procs[slot].child_count;
        for i in 0..cc as usize {
            let cpid = children_copy[i];
            if let Some(cslot) = self.find_by_pid(cpid) {
                self.procs[cslot].ppid = self.init_pid;
                // Add to init's children
                if let Some(init_slot) = self.find_by_pid(self.init_pid) {
                    self.procs[init_slot].add_child(cpid);
                }
            }
        }
        self.procs[slot].child_count = 0;

        true
    }

    /// Find process slot by PID
    pub fn find_by_pid(&self, pid: u32) -> Option<usize> {
        for i in 0..MAX_PROCESSES {
            if self.procs[i].active && self.procs[i].pid == pid {
                return Some(i);
            }
        }
        None
    }

    /// Get a reference to a PCB
    pub fn get(&self, pid: u32) -> Option<&ProcessControlBlock> {
        self.find_by_pid(pid).map(|i| &self.procs[i])
    }

    /// Get a mutable reference to a PCB
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessControlBlock> {
        self.find_by_pid(pid).map(move |i| &mut self.procs[i])
    }

    /// Count running processes
    pub fn running_count(&self) -> u32 {
        let mut c = 0u32;
        for i in 0..MAX_PROCESSES {
            if self.procs[i].active && self.procs[i].state == ProcessState::Running {
                c += 1;
            }
        }
        c
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut PROCESS_TABLE: ProcessTable = ProcessTable::new();

fn process_table() -> &'static mut ProcessTable {
    unsafe { &mut PROCESS_TABLE }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_proc_create_init() -> i32 {
    match process_table().create_init() {
        Some(pid) => pid as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_fork(parent_pid: u32, clone_flags: u32) -> i32 {
    match process_table().fork(parent_pid, clone_flags) {
        Some(pid) => pid as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_exit(pid: u32, code: i32) -> i32 {
    if process_table().exit_process(pid, code) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_waitpid(parent_pid: u32, target_pid: i32, status: *mut i32) -> i32 {
    match process_table().waitpid(parent_pid, target_pid) {
        Some((cpid, code)) => {
            if !status.is_null() {
                unsafe { *status = code; }
            }
            cpid as i32
        }
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_send_signal(pid: u32, sig: u8) -> i32 {
    match process_table().get_mut(pid) {
        Some(pcb) => if pcb.send_signal(sig) { 0 } else { -1 },
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_alloc_fd(pid: u32) -> i32 {
    match process_table().get_mut(pid) {
        Some(pcb) => match pcb.alloc_fd() {
            Some(fd) => fd as i32,
            None => -1,
        },
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_close_fd(pid: u32, fd: u32) -> i32 {
    match process_table().get_mut(pid) {
        Some(pcb) => if pcb.close_fd(fd) { 0 } else { -1 },
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_get_state(pid: u32) -> i32 {
    match process_table().get(pid) {
        Some(pcb) => pcb.state as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_count() -> u32 {
    process_table().count
}

#[no_mangle]
pub extern "C" fn zxyphor_proc_running_count() -> u32 {
    process_table().running_count()
}
