// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Task Management (Rust)
// Thread groups, PID namespaces, work queues, kthreads, wait queues, CPU affinity

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicI32, AtomicBool, Ordering};

// ============================================================================
// Thread States
// ============================================================================

pub const TASK_RUNNING: u32 = 0x00000000;
pub const TASK_INTERRUPTIBLE: u32 = 0x00000001;
pub const TASK_UNINTERRUPTIBLE: u32 = 0x00000002;
pub const TASK_STOPPED: u32 = 0x00000004;
pub const TASK_TRACED: u32 = 0x00000008;
pub const EXIT_DEAD: u32 = 0x00000010;
pub const EXIT_ZOMBIE: u32 = 0x00000020;
pub const TASK_PARKED: u32 = 0x00000040;
pub const TASK_DEAD: u32 = 0x00000080;
pub const TASK_WAKEKILL: u32 = 0x00000100;
pub const TASK_WAKING: u32 = 0x00000200;
pub const TASK_NOLOAD: u32 = 0x00000400;
pub const TASK_NEW: u32 = 0x00000800;
pub const TASK_RTLOCK_WAIT: u32 = 0x00001000;
pub const TASK_FREEZABLE: u32 = 0x00002000;

pub const TASK_KILLABLE: u32 = TASK_WAKEKILL | TASK_UNINTERRUPTIBLE;
pub const TASK_IDLE: u32 = TASK_UNINTERRUPTIBLE | TASK_NOLOAD;

// ============================================================================
// Clone Flags
// ============================================================================

pub const CSIGNAL: u64 = 0x000000ff;
pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_FS: u64 = 0x00000200;
pub const CLONE_FILES: u64 = 0x00000400;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_PIDFD: u64 = 0x00001000;
pub const CLONE_PTRACE: u64 = 0x00002000;
pub const CLONE_VFORK: u64 = 0x00004000;
pub const CLONE_PARENT: u64 = 0x00008000;
pub const CLONE_THREAD: u64 = 0x00010000;
pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_SYSVSEM: u64 = 0x00040000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_DETACHED: u64 = 0x00400000;
pub const CLONE_UNTRACED: u64 = 0x00800000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_IO: u64 = 0x80000000;
// Zxyphor extensions
pub const CLONE_NEWTIME: u64 = 0x0000000080;
pub const CLONE_INTO_CGROUP: u64 = 0x0000200000000000;

// ============================================================================
// Task Struct (Full Linux-compatible)
// ============================================================================

pub struct TaskStruct {
    pub state: AtomicU32,
    pub flags: u32,
    pub on_cpu: AtomicBool,
    pub wake_cpu: i32,
    pub on_rq: AtomicBool,
    
    // Identity
    pub pid: i32,
    pub tgid: i32,
    pub comm: [u8; 16],     // Task name
    pub comm_len: u8,
    
    // Scheduling
    pub prio: i32,           // Dynamic priority
    pub static_prio: i32,    // Set by nice
    pub normal_prio: i32,    // Computed from static_prio
    pub rt_priority: u32,
    pub policy: SchedPolicy,
    pub nr_cpus_allowed: u32,
    pub cpus_mask: CpuMask,
    
    // Time accounting
    pub utime: u64,          // User mode time (ns)
    pub stime: u64,          // System mode time (ns)
    pub gtime: u64,          // Guest mode time (ns)
    pub start_time: u64,     // Boot-based time
    pub start_boottime: u64, // Wall time
    pub nvcsw: u64,          // Voluntary context switches
    pub nivcsw: u64,         // Involuntary context switches
    
    // Memory
    pub mm_id: u64,          // Memory map ID
    pub active_mm_id: u64,
    pub total_vm: u64,       // Total VM pages
    pub locked_vm: u64,      // mlock'd pages
    pub pinned_vm: u64,      // pinned pages
    pub stack_vm: u64,
    pub data_vm: u64,
    pub exec_vm: u64,
    pub hiwater_rss: u64,    // peak RSS
    pub hiwater_vm: u64,     // peak VM
    pub min_flt: u64,        // Minor page faults
    pub maj_flt: u64,        // Major page faults
    
    // File system
    pub fs_root: u64,        // Root dentry
    pub fs_pwd: u64,         // Current working directory
    pub files_fdtable: u64,  // File descriptor table pointer
    pub umask: u16,
    
    // Signals
    pub signal_pending: AtomicU64,
    pub blocked: u64,        // Blocked signal mask
    pub real_blocked: u64,
    pub saved_sigmask: u64,
    
    // Credentials
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_bset: u64,
    pub cap_ambient: u64,
    pub securebits: u32,
    
    // Namespaces
    pub nsproxy_id: u64,
    
    // cgroups
    pub cgroup_id: u64,
    
    // Perf events
    pub perf_event_ctxp: u64,
    
    // IO accounting
    pub ioac_read_bytes: AtomicU64,
    pub ioac_write_bytes: AtomicU64,
    pub ioac_cancelled_write_bytes: AtomicU64,
    pub ioac_rchar: AtomicU64,
    pub ioac_wchar: AtomicU64,
    pub ioac_syscr: AtomicU64,
    pub ioac_syscw: AtomicU64,
    
    // Process tree
    pub parent_pid: i32,
    pub real_parent_pid: i32,
    pub group_leader_pid: i32,
    pub exit_code: i32,
    pub exit_signal: i32,
    pub pdeath_signal: i32,
    
    // Timers
    pub real_timer_interval: u64,
    pub virtual_timer_interval: u64,
    pub prof_timer_interval: u64,
    
    // seccomp
    pub seccomp_mode: u8,
    pub seccomp_filter_count: u32,
    
    // Tracing
    pub ptrace: u32,
    pub ptrace_message: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum SchedPolicy {
    Normal = 0,      // SCHED_NORMAL (CFS)
    Fifo = 1,        // SCHED_FIFO (RT)
    Rr = 2,          // SCHED_RR (RT round robin)
    Batch = 3,       // SCHED_BATCH
    Idle = 5,        // SCHED_IDLE
    Deadline = 6,    // SCHED_DEADLINE
    Ext = 7,         // SCHED_EXT (BPF extensible)
}

// ============================================================================
// CPU Mask
// ============================================================================

pub struct CpuMask {
    pub bits: [4; u64],  // Support up to 256 CPUs
}

impl CpuMask {
    pub fn new() -> Self {
        CpuMask { bits: [0; 4] }
    }

    pub fn all() -> Self {
        CpuMask { bits: [u64::MAX; 4] }
    }

    pub fn set_cpu(&mut self, cpu: u32) {
        if cpu < 256 {
            self.bits[(cpu / 64) as usize] |= 1u64 << (cpu % 64);
        }
    }

    pub fn clear_cpu(&mut self, cpu: u32) {
        if cpu < 256 {
            self.bits[(cpu / 64) as usize] &= !(1u64 << (cpu % 64));
        }
    }

    pub fn test_cpu(&self, cpu: u32) -> bool {
        if cpu < 256 {
            self.bits[(cpu / 64) as usize] & (1u64 << (cpu % 64)) != 0
        } else {
            false
        }
    }

    pub fn count(&self) -> u32 {
        let mut total = 0u32;
        for word in &self.bits {
            total += word.count_ones();
        }
        total
    }

    pub fn first_set(&self) -> Option<u32> {
        for (i, word) in self.bits.iter().enumerate() {
            if *word != 0 {
                return Some(i as u32 * 64 + word.trailing_zeros());
            }
        }
        None
    }

    pub fn and(&self, other: &CpuMask) -> CpuMask {
        CpuMask {
            bits: [
                self.bits[0] & other.bits[0],
                self.bits[1] & other.bits[1],
                self.bits[2] & other.bits[2],
                self.bits[3] & other.bits[3],
            ],
        }
    }

    pub fn or(&self, other: &CpuMask) -> CpuMask {
        CpuMask {
            bits: [
                self.bits[0] | other.bits[0],
                self.bits[1] | other.bits[1],
                self.bits[2] | other.bits[2],
                self.bits[3] | other.bits[3],
            ],
        }
    }
}

// ============================================================================
// Wait Queue
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WaitMode {
    Exclusive,
    NonExclusive,
}

pub struct WaitQueueEntry {
    pub flags: u32,
    pub mode: WaitMode,
    pub task_pid: i32,
    pub func: WakeupFunc,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WakeupFunc {
    DefaultWake,
    AutoremoveWake,
    WokenWake,
    BookmarkWake,
    PollWake,
    EpollWake,
}

pub struct WaitQueueHead {
    pub lock: AtomicU32,
    pub entries: [WaitQueueEntry; 64],
    pub count: u32,
}

impl WaitQueueHead {
    pub fn init() -> Self {
        WaitQueueHead {
            lock: AtomicU32::new(0),
            entries: [WaitQueueEntry {
                flags: 0,
                mode: WaitMode::NonExclusive,
                task_pid: 0,
                func: WakeupFunc::DefaultWake,
            }; 64],
            count: 0,
        }
    }

    pub fn add_wait(&mut self, entry: WaitQueueEntry) -> bool {
        if self.count as usize >= self.entries.len() {
            return false;
        }
        self.entries[self.count as usize] = entry;
        self.count += 1;
        true
    }

    pub fn wake_up(&self, nr: u32) -> u32 {
        let mut woken = 0u32;
        for i in 0..self.count as usize {
            if woken >= nr { break; }
            // Would actually wake the task via scheduler
            woken += 1;
            if self.entries[i].mode == WaitMode::Exclusive {
                break;
            }
        }
        woken
    }

    pub fn wake_up_all(&self) -> u32 {
        self.wake_up(u32::MAX)
    }
}

// ============================================================================
// Completion
// ============================================================================

pub struct Completion {
    pub done: AtomicU32,
    pub wait: WaitQueueHead,
}

impl Completion {
    pub fn new() -> Self {
        Completion {
            done: AtomicU32::new(0),
            wait: WaitQueueHead::init(),
        }
    }

    pub fn complete(&self) {
        self.done.fetch_add(1, Ordering::Release);
        self.wait.wake_up(1);
    }

    pub fn complete_all(&self) {
        self.done.store(u32::MAX / 2, Ordering::Release);
        self.wait.wake_up_all();
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire) > 0
    }
}

// ============================================================================
// Work Queue
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WqFlags {
    Unbound,         // Not bound to specific CPU
    Freezable,       // Frozen during suspend
    MemReclaim,      // Guaranteed forward progress for memory reclaim
    Highpri,         // High priority
    CpuIntensive,    // CPU intensive, managed concurrency
    Sysfs,           // Visible in sysfs
    PowerEfficient,  // Prefer unbound on multi-core
    Ordered,         // Serialized execution
}

pub struct WorkqueueStruct {
    pub name: [u8; 24],
    pub name_len: u8,
    pub flags: u32,
    pub max_active: u32,
    pub work_color: u32,
    pub flush_color: u32,
    pub nr_active: AtomicU32,
    pub refcount: AtomicU32,
    // Per-CPU pools
    pub cpu_pools: [WorkerPool; 8],
    pub nr_pools: u8,
    // Stats
    pub stats_executed: AtomicU64,
    pub stats_queued: AtomicU64,
    pub stats_max_queue_depth: AtomicU32,
}

pub struct WorkerPool {
    pub cpu: i32,
    pub node: i32,
    pub id: u32,
    pub flags: u32,
    pub nr_workers: AtomicU32,
    pub nr_idle: AtomicU32,
    pub nr_running: AtomicU32,
    pub max_workers: u32,
    // Work items
    pub pending: [WorkItem; 256],
    pub pending_count: AtomicU32,
    pub pending_head: AtomicU32,
    pub pending_tail: AtomicU32,
}

pub struct WorkItem {
    pub func_id: u64,       // Work function identifier
    pub data: u64,          // Work data pointer
    pub flags: u32,
    pub cpu: i32,
    pub color: u32,
}

// ============================================================================
// Kernel Thread (kthread)
// ============================================================================

pub struct KthreadCreateInfo {
    pub thread_fn_id: u64,   // Kernel function to run
    pub data: u64,           // Function data
    pub name: [u8; 16],
    pub name_len: u8,
    pub cpu: i32,            // -1 for any CPU
    pub full_name: bool,
}

pub struct KthreadWorker {
    pub task_pid: i32,
    pub work_list: [KthreadWork; 32],
    pub work_count: u32,
    pub current_work: i32,   // -1 if idle
    pub delayed_work_list: [KthreadDelayedWork; 16],
    pub delayed_count: u32,
}

pub struct KthreadWork {
    pub func_id: u64,
    pub data: u64,
}

pub struct KthreadDelayedWork {
    pub work: KthreadWork,
    pub delay_ns: u64,
    pub scheduled_at: u64,
}

// ============================================================================
// PID Namespace + PID Allocation
// ============================================================================

pub struct PidNamespace {
    pub level: u32,          // Nesting level (0 = root)
    pub parent_ns_id: u64,
    pub pid_allocated: AtomicU32,
    pub pid_max: u32,        // Default: 32768, max: 4194304
    pub nr_hashed: AtomicU32,
    pub hide_pid: HidePid,
    pub reboot: bool,
    // PID map (bitmap)
    pub pidmap: [u64; 512],  // 32768 PIDs bitmap (512 * 64 = 32768)
    pub last_pid: AtomicI32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HidePid {
    Off = 0,          // Default - everyone can see all PIDs
    NoPtrace = 1,     // Hide PIDs from non-ptrace processes
    Invisible = 2,    // Full hiding
    NotImplemented = 4,
}

impl PidNamespace {
    pub fn alloc_pid(&mut self) -> Option<i32> {
        let start = (self.last_pid.load(Ordering::Relaxed) + 1) as u32;
        let max = self.pid_max;
        
        // Search from last_pid to max, then wrap to 300 (skip reserved PIDs)
        for offset in 0..max {
            let pid = if start + offset < max {
                start + offset
            } else {
                300 + ((start + offset - max) % (max - 300))
            };
            
            let word = (pid / 64) as usize;
            let bit = pid % 64;
            
            if word >= self.pidmap.len() { continue; }
            
            if self.pidmap[word] & (1u64 << bit) == 0 {
                self.pidmap[word] |= 1u64 << bit;
                self.last_pid.store(pid as i32, Ordering::Relaxed);
                self.pid_allocated.fetch_add(1, Ordering::Relaxed);
                return Some(pid as i32);
            }
        }
        None
    }

    pub fn free_pid(&mut self, pid: i32) {
        if pid <= 0 { return; }
        let pid = pid as u32;
        let word = (pid / 64) as usize;
        let bit = pid % 64;
        
        if word < self.pidmap.len() {
            self.pidmap[word] &= !(1u64 << bit);
            self.pid_allocated.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// Thread Group / Process Group / Session
// ============================================================================

pub struct ThreadGroup {
    pub tgid: i32,
    pub leader_pid: i32,
    pub nr_threads: AtomicU32,
    pub thread_pids: [i32; 256],  // Thread PIDs
    pub group_exit_code: i32,
    pub group_stop_count: AtomicU32,
    pub flags: u32,
    // Timers
    pub real_timer: u64,
    pub leader_start_time: u64,
    pub cputime_utime: AtomicU64,
    pub cputime_stime: AtomicU64,
    pub cputime_sum_exec_runtime: AtomicU64,
    // Resource limits
    pub rlimits: [RlimitPair; 16],
}

pub struct RlimitPair {
    pub cur: u64,
    pub max: u64,
}

pub struct ProcessGroup {
    pub pgid: i32,
    pub session_id: i32,
    pub member_pids: [i32; 128],
    pub nr_members: u32,
}

pub struct Session {
    pub sid: i32,
    pub leader_pid: i32,
    pub tty_device: u32,     // Controlling terminal
    pub foreground_pgrp: i32,
}

// ============================================================================
// RCU (Read-Copy-Update)
// ============================================================================

pub struct RcuState {
    pub gp_seq: AtomicU64,           // Grace period sequence number
    pub gp_start: u64,               // GP start timestamp
    pub gp_flags: AtomicU32,
    pub gp_completed: AtomicU64,     // Last completed GP
    pub expedited_sequence: AtomicU64,
    // Per-CPU data
    pub per_cpu: [RcuPerCpu; 64],
    // Callback stats
    pub cb_queued: AtomicU64,
    pub cb_invoked: AtomicU64,
}

pub struct RcuPerCpu {
    pub gp_seq_needed: u64,
    pub gp_seq: u64,
    pub passed_quiesce: AtomicBool,
    pub qs_pending: AtomicBool,
    pub callbacks_head: u32,
    pub callbacks_tail: u32,
    pub callbacks_count: AtomicU32,
}

// ============================================================================
// Per-CPU Variables
// ============================================================================

pub struct PerCpuArea {
    pub cpu_id: u32,
    pub node_id: u32,
    // CPU-local counters
    pub preempt_count: AtomicU32,
    pub irq_count: u32,
    pub softirq_count: u32,
    pub hardirq_count: u32,
    pub nmi_count: u32,
    pub in_idle: AtomicBool,
    // Current task
    pub current_task_pid: i32,
    pub idle_task_pid: i32,
    // Timestamps
    pub irq_time: AtomicU64,
    pub softirq_time: AtomicU64,
    pub idle_time: AtomicU64,
    pub iowait_time: AtomicU64,
    pub steal_time: AtomicU64,
    pub guest_time: AtomicU64,
    // CPU stats
    pub user_time: AtomicU64,
    pub system_time: AtomicU64,
    pub nice_time: AtomicU64,
    // Page allocator per-cpu cache
    pub pcp_count: AtomicU32,
    pub pcp_high: u32,
    pub pcp_batch: u32,
}

// ============================================================================
// Futex (Fast Userspace Mutex)
// ============================================================================

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_FD: u32 = 2;
pub const FUTEX_REQUEUE: u32 = 3;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_WAKE_OP: u32 = 5;
pub const FUTEX_LOCK_PI: u32 = 6;
pub const FUTEX_UNLOCK_PI: u32 = 7;
pub const FUTEX_TRYLOCK_PI: u32 = 8;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
pub const FUTEX_CMP_REQUEUE_PI: u32 = 12;
pub const FUTEX_LOCK_PI2: u32 = 13;

pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFFFFFF;

pub struct FutexQueue {
    pub key_word: u64,     // Address of futex word
    pub key_offset: u32,
    pub key_mm_id: u64,
    pub waiters: [FutexWaiter; 64],
    pub nr_waiters: u32,
}

pub struct FutexWaiter {
    pub task_pid: i32,
    pub bitset: u32,
    pub prio: i32,
    pub requeue_target: u64,
    pub locked: bool,
    pub pi_owner: i32,     // For PI futexes
}

// Hash table for futex lookup
pub struct FutexHashTable {
    pub buckets: [FutexQueue; 256],
}

impl FutexHashTable {
    pub fn hash_key(addr: u64, mm_id: u64) -> usize {
        let h = addr.wrapping_mul(0x9E3779B97F4A7C15) ^ mm_id.wrapping_mul(0x517CC1B727220A95);
        (h as usize) % 256
    }

    pub fn lookup(&self, addr: u64, mm_id: u64) -> &FutexQueue {
        let idx = Self::hash_key(addr, mm_id);
        &self.buckets[idx]
    }

    pub fn lookup_mut(&mut self, addr: u64, mm_id: u64) -> &mut FutexQueue {
        let idx = Self::hash_key(addr, mm_id);
        &mut self.buckets[idx]
    }
}

// ============================================================================
// Robust Futex List
// ============================================================================

#[repr(C)]
pub struct RobustListHead {
    pub list_head: u64,      // Pointer to first entry
    pub futex_offset: i64,   // Offset of futex word within entry
    pub list_op_pending: u64, // Entry being modified
}

// ============================================================================
// POSIX Timers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum ClockId {
    Realtime = 0,
    Monotonic = 1,
    ProcessCputimeId = 2,
    ThreadCputimeId = 3,
    MonotonicRaw = 4,
    RealtimeCoarse = 5,
    MonotonicCoarse = 6,
    Boottime = 7,
    RealtimeAlarm = 8,
    BoottimeAlarm = 9,
    Tai = 11,
}

pub struct PosixTimer {
    pub timer_id: i32,
    pub clock_id: ClockId,
    pub task_pid: i32,
    pub signal: i32,
    pub overrun: AtomicI32,
    pub interval_sec: u64,
    pub interval_nsec: u64,
    pub value_sec: u64,
    pub value_nsec: u64,
    pub expire_count: AtomicU64,
}

// ============================================================================
// Process Accounting
// ============================================================================

#[repr(C)]
pub struct Acct {
    pub ac_flag: u8,     // Flags
    pub ac_version: u8,  // Accounting version
    pub ac_tty: u16,     // Controlling terminal
    pub ac_exitcode: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,   // Process creation time
    pub ac_etime: f32,   // Elapsed time
    pub ac_utime: u32,   // User time
    pub ac_stime: u32,   // System time
    pub ac_mem: u32,     // Average memory usage
    pub ac_io: u64,      // Characters transferred
    pub ac_rw: u64,      // Blocks read/written
    pub ac_minflt: u64,  // Minor page faults
    pub ac_majflt: u64,  // Major page faults
    pub ac_swaps: u64,   // Number of swaps
    pub ac_comm: [u8; 16], // Command name
}

pub const AFORK: u8 = 0x01;    // Has forked but not execed
pub const ASU: u8 = 0x02;      // Used superuser privileges
pub const ACOMPAT: u8 = 0x04;  // Used compatibility mode
pub const ACORE: u8 = 0x08;    // Dumped core
pub const AXSIG: u8 = 0x10;    // Killed by a signal
