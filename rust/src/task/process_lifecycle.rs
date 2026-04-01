// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Rust - Advanced Task Management and Scheduling
// Complete process/thread lifecycle, clone flags, signals,
// ptrace, process groups, sessions, cred management,
// CPU affinity, NUMA balancing, load balancing
// More advanced than Linux 2026 task subsystem

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// ============================================================================
// Process States
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaskState {
    Running = 0,
    Interruptible = 1,
    Uninterruptible = 2,
    Stopped = 4,
    Traced = 8,
    ExitDead = 16,
    ExitZombie = 32,
    Parked = 64,
    Dead = 128,
    // Idle/WakeKill combinations
    Idle = 0x42,
    KillableWait = 0x22,
}

// ============================================================================
// Clone Flags (Linux ABI compatible)
// ============================================================================

pub const CLONE_VM: u64          = 0x00000100;
pub const CLONE_FS: u64          = 0x00000200;
pub const CLONE_FILES: u64       = 0x00000400;
pub const CLONE_SIGHAND: u64     = 0x00000800;
pub const CLONE_PIDFD: u64       = 0x00001000;
pub const CLONE_PTRACE: u64      = 0x00002000;
pub const CLONE_VFORK: u64       = 0x00004000;
pub const CLONE_PARENT: u64      = 0x00008000;
pub const CLONE_THREAD: u64      = 0x00010000;
pub const CLONE_NEWNS: u64       = 0x00020000;
pub const CLONE_SYSVSEM: u64     = 0x00040000;
pub const CLONE_SETTLS: u64      = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_DETACHED: u64    = 0x00400000;
pub const CLONE_UNTRACED: u64    = 0x00800000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
pub const CLONE_NEWCGROUP: u64   = 0x02000000;
pub const CLONE_NEWUTS: u64      = 0x04000000;
pub const CLONE_NEWIPC: u64      = 0x08000000;
pub const CLONE_NEWUSER: u64     = 0x10000000;
pub const CLONE_NEWPID: u64      = 0x20000000;
pub const CLONE_NEWNET: u64      = 0x40000000;
pub const CLONE_IO: u64          = 0x80000000;
// clone3 flags
pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;
pub const CLONE_INTO_CGROUP: u64 = 0x200000000;
pub const CLONE_NEWTIME: u64     = 0x400000000;

// ============================================================================
// clone3 Args
// ============================================================================

#[repr(C)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

// ============================================================================
// Signal Definitions
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGIO = 29,
    SIGPWR = 30,
    SIGSYS = 31,
    // RT signals: 32-64
    SIGRTMIN = 32,
    SIGRTMAX = 64,
}

pub const NSIG: u32 = 65;

pub type SigsetT = u64;

#[repr(C)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: SigsetT,
}

// Signal action flags
pub const SA_NOCLDSTOP: u64  = 0x00000001;
pub const SA_NOCLDWAIT: u64  = 0x00000002;
pub const SA_SIGINFO: u64    = 0x00000004;
pub const SA_ONSTACK: u64    = 0x08000000;
pub const SA_RESTART: u64    = 0x10000000;
pub const SA_NODEFER: u64    = 0x40000000;
pub const SA_RESETHAND: u64  = 0x80000000;
pub const SA_RESTORER: u64   = 0x04000000;

#[repr(C)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    // Union fields
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    pub si_addr: u64,
    pub si_value: u64,
    pub si_band: i64,
    pub si_fd: i32,
    // Timer
    pub si_timerid: i32,
    pub si_overrun: i32,
}

// ============================================================================
// Ptrace
// ============================================================================

pub const PTRACE_TRACEME: u32       = 0;
pub const PTRACE_PEEKTEXT: u32      = 1;
pub const PTRACE_PEEKDATA: u32      = 2;
pub const PTRACE_PEEKUSR: u32       = 3;
pub const PTRACE_POKETEXT: u32      = 4;
pub const PTRACE_POKEDATA: u32      = 5;
pub const PTRACE_POKEUSR: u32       = 6;
pub const PTRACE_CONT: u32          = 7;
pub const PTRACE_KILL: u32          = 8;
pub const PTRACE_SINGLESTEP: u32    = 9;
pub const PTRACE_GETREGS: u32       = 12;
pub const PTRACE_SETREGS: u32       = 13;
pub const PTRACE_GETFPREGS: u32     = 14;
pub const PTRACE_SETFPREGS: u32     = 15;
pub const PTRACE_ATTACH: u32        = 16;
pub const PTRACE_DETACH: u32        = 17;
pub const PTRACE_SYSCALL: u32       = 24;
pub const PTRACE_SETOPTIONS: u32    = 0x4200;
pub const PTRACE_GETEVENTMSG: u32   = 0x4201;
pub const PTRACE_GETSIGINFO: u32    = 0x4202;
pub const PTRACE_SETSIGINFO: u32    = 0x4203;
pub const PTRACE_GETREGSET: u32     = 0x4204;
pub const PTRACE_SETREGSET: u32     = 0x4205;
pub const PTRACE_SEIZE: u32         = 0x4206;
pub const PTRACE_INTERRUPT: u32     = 0x4207;
pub const PTRACE_LISTEN: u32        = 0x4208;
pub const PTRACE_PEEKSIGINFO: u32   = 0x4209;
pub const PTRACE_GETSIGMASK: u32    = 0x420A;
pub const PTRACE_SETSIGMASK: u32    = 0x420B;
pub const PTRACE_SECCOMP_GET_FILTER: u32 = 0x420C;
pub const PTRACE_SECCOMP_GET_METADATA: u32 = 0x420D;
pub const PTRACE_GET_SYSCALL_INFO: u32 = 0x420E;
pub const PTRACE_GET_RSEQ_CONFIGURATION: u32 = 0x420F;

// Ptrace options
pub const PTRACE_O_TRACESYSGOOD: u32   = 0x00000001;
pub const PTRACE_O_TRACEFORK: u32      = 0x00000002;
pub const PTRACE_O_TRACEVFORK: u32     = 0x00000004;
pub const PTRACE_O_TRACECLONE: u32     = 0x00000008;
pub const PTRACE_O_TRACEEXEC: u32      = 0x00000010;
pub const PTRACE_O_TRACEVFORKDONE: u32 = 0x00000020;
pub const PTRACE_O_TRACEEXIT: u32      = 0x00000040;
pub const PTRACE_O_TRACESECCOMP: u32   = 0x00000080;
pub const PTRACE_O_EXITKILL: u32       = 0x00100000;
pub const PTRACE_O_SUSPEND_SECCOMP: u32 = 0x00200000;

// ============================================================================
// Credentials
// ============================================================================

#[derive(Debug, Clone)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    // Supplementary groups
    pub groups: [32]u32,
    pub nr_groups: u32,
    // POSIX capabilities
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_bset: u64,       // Bounding set
    pub cap_ambient: u64,
    // Securebits
    pub securebits: u32,
    // Keyring
    pub session_keyring: u64,
    pub process_keyring: u64,
    pub thread_keyring: u64,
    // User namespace
    pub user_ns: u64,
    // LSM
    pub security: u64,
    // Reference count
    pub usage: u32,
}

impl Cred {
    pub fn is_root(&self) -> bool {
        self.euid == 0
    }

    pub fn has_cap(&self, cap: u32) -> bool {
        if cap >= 64 { return false; }
        (self.cap_effective & (1u64 << cap)) != 0
    }

    pub fn in_group(&self, gid: u32) -> bool {
        if self.gid == gid || self.egid == gid { return true; }
        for i in 0..self.nr_groups as usize {
            if self.groups[i] == gid { return true; }
        }
        false
    }
}

// ============================================================================
// Scheduling Parameters
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedPolicy {
    Normal = 0,       // SCHED_NORMAL/OTHER
    Fifo = 1,         // SCHED_FIFO
    RoundRobin = 2,   // SCHED_RR
    Batch = 3,        // SCHED_BATCH
    Idle = 5,         // SCHED_IDLE
    Deadline = 6,     // SCHED_DEADLINE
    // Zxyphor
    ZxyAdaptive = 7,
    ZxyRealtime = 8,
}

#[repr(C)]
pub struct SchedParam {
    pub sched_priority: i32,
}

#[repr(C)]
pub struct SchedAttr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    // Nice value
    pub sched_nice: i32,
    // FIFO/RR priority
    pub sched_priority: u32,
    // SCHED_DEADLINE parameters
    pub sched_runtime: u64,    // ns
    pub sched_deadline: u64,   // ns
    pub sched_period: u64,     // ns
    // Utilization hints
    pub sched_util_min: u32,
    pub sched_util_max: u32,
}

// SCHED_FLAG_*
pub const SCHED_FLAG_RESET_ON_FORK: u64  = 0x01;
pub const SCHED_FLAG_RECLAIM: u64        = 0x02;
pub const SCHED_FLAG_DL_OVERRUN: u64     = 0x04;
pub const SCHED_FLAG_KEEP_POLICY: u64    = 0x08;
pub const SCHED_FLAG_KEEP_PARAMS: u64    = 0x10;
pub const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
pub const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;

// ============================================================================
// CPU Affinity / NUMA
// ============================================================================

pub const CPU_SETSIZE: usize = 1024;
pub const CPUMASK_WORDS: usize = CPU_SETSIZE / 64;

#[derive(Clone)]
pub struct CpuSet {
    pub bits: [CPUMASK_WORDS; u64],
}

impl CpuSet {
    pub fn new() -> Self {
        CpuSet { bits: [0u64; CPUMASK_WORDS] }
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }

    pub fn clear(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / 64] &= !(1u64 << (cpu % 64));
        }
    }

    pub fn is_set(&self, cpu: usize) -> bool {
        if cpu >= CPU_SETSIZE { return false; }
        (self.bits[cpu / 64] & (1u64 << (cpu % 64))) != 0
    }

    pub fn count(&self) -> u32 {
        let mut c = 0u32;
        for word in &self.bits {
            c += word.count_ones();
        }
        c
    }

    pub fn set_all(&mut self) {
        for word in &mut self.bits {
            *word = !0u64;
        }
    }
}

// ============================================================================
// Resource Limits (rlimit)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Resource {
    RLIMIT_CPU = 0,
    RLIMIT_FSIZE = 1,
    RLIMIT_DATA = 2,
    RLIMIT_STACK = 3,
    RLIMIT_CORE = 4,
    RLIMIT_RSS = 5,
    RLIMIT_NPROC = 6,
    RLIMIT_NOFILE = 7,
    RLIMIT_MEMLOCK = 8,
    RLIMIT_AS = 9,
    RLIMIT_LOCKS = 10,
    RLIMIT_SIGPENDING = 11,
    RLIMIT_MSGQUEUE = 12,
    RLIMIT_NICE = 13,
    RLIMIT_RTPRIO = 14,
    RLIMIT_RTTIME = 15,
}

pub const RLIM_NLIMITS: u32 = 16;
pub const RLIM_INFINITY: u64 = !0u64;

#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

// ============================================================================
// Rusage (Resource Usage)
// ============================================================================

#[repr(C)]
pub struct Rusage {
    pub ru_utime_sec: i64,
    pub ru_utime_usec: i64,
    pub ru_stime_sec: i64,
    pub ru_stime_usec: i64,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

// ============================================================================
// Task I/O Accounting
// ============================================================================

pub struct TaskIoAccounting {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
}

// ============================================================================
// Task (Process/Thread) Struct
// ============================================================================

pub struct TaskProcess {
    // Identity
    pub pid: i32,
    pub tgid: i32,         // Thread group ID
    pub ppid: i32,
    pub pgid: i32,         // Process group ID
    pub sid: i32,           // Session ID
    pub comm: [16; u8],     // Process name
    // State
    pub state: TaskState,
    pub exit_state: u8,
    pub exit_code: i32,
    pub exit_signal: i32,
    // Flags
    pub flags: u32,
    // Credentials
    pub cred: Cred,
    // Scheduling
    pub sched_policy: SchedPolicy,
    pub sched_attr: SchedAttr,
    pub prio: i32,           // Dynamic priority
    pub static_prio: i32,    // Nice-based
    pub normal_prio: i32,
    pub rt_priority: u32,
    // CPU affinity
    pub cpus_allowed: CpuSet,
    pub nr_cpus_allowed: u32,
    pub recent_used_cpu: i32,
    pub wake_cpu: i32,
    pub on_cpu: u32,
    // NUMA
    pub numa_preferred_nid: i32,
    pub numa_scan_seq: u64,
    pub total_numa_faults: u64,
    // Resource limits
    pub rlim: [Rlimit; RLIM_NLIMITS as usize],
    // Memory
    pub mm_rss_anon: u64,
    pub mm_rss_file: u64,
    pub mm_rss_shmem: u64,
    pub total_vm: u64,
    // File system
    pub fs_root: u64,       // Root directory
    pub fs_pwd: u64,        // Working directory
    pub umask: u32,
    pub max_fds: u32,
    pub nr_open_fds: u32,
    // Signals
    pub signal_pending: SigsetT,
    pub signal_blocked: SigsetT,
    pub sigaction: [SigAction; NSIG as usize],
    pub signal_struct: u64,
    // Timing
    pub utime: u64,         // User time (ns)
    pub stime: u64,         // System time (ns)
    pub start_time: u64,    // Monotonic
    pub start_boottime: u64,
    // I/O accounting
    pub io_accounting: TaskIoAccounting,
    // Audit
    pub loginuid: u32,
    pub sessionid: u32,
    // Seccomp
    pub seccomp_mode: u8,
    pub seccomp_filter_count: u32,
    // Namespaces
    pub nsproxy: NsProxy,
    // Cgroups
    pub cgroup_css_set: u64,
    // Perf
    pub perf_event_ctxp: [2; u64],
    // RCU
    pub rcu_read_lock_nesting: i32,
    pub rcu_blocked_node: u64,
    // Ptrace
    pub ptrace: u32,
    pub ptrace_message: u64,
    // Restart block
    pub restart_block: RestartBlock,
    // Robust futex list
    pub robust_list: u64,
    pub robust_list_compat: u64,
    // PI (Priority Inheritance)
    pub pi_blocked_on: u64,
    pub pi_top_task: u64,
    // Journal info (for filesystem transactions)
    pub journal_info: u64,
    // Thread info
    pub thread_flags: u32,
    pub stack_canary: u64,
    // Zxyphor
    pub zxy_priority_class: u8,
    pub zxy_deadline_ns: u64,
    pub zxy_energy_aware: bool,
}

// Process flags
pub const PF_IDLE: u32           = 0x00000002;
pub const PF_EXITING: u32       = 0x00000004;
pub const PF_POSTCOREDUMP: u32  = 0x00000008;
pub const PF_IO_WORKER: u32     = 0x00000010;
pub const PF_WQ_WORKER: u32     = 0x00000020;
pub const PF_FORKNOEXEC: u32    = 0x00000040;
pub const PF_MCE_PROCESS: u32   = 0x00000080;
pub const PF_SUPERPRIV: u32     = 0x00000100;
pub const PF_DUMPCORE: u32      = 0x00000200;
pub const PF_SIGNALED: u32      = 0x00000400;
pub const PF_MEMALLOC: u32      = 0x00000800;
pub const PF_NPROC_EXCEEDED: u32 = 0x00001000;
pub const PF_USED_MATH: u32     = 0x00002000;
pub const PF_USER_WORKER: u32   = 0x00004000;
pub const PF_NOFREEZE: u32      = 0x00008000;
pub const PF_KSWAPD: u32        = 0x00020000;
pub const PF_MEMALLOC_NOFS: u32 = 0x00040000;
pub const PF_MEMALLOC_NOIO: u32 = 0x00080000;
pub const PF_LOCAL_THROTTLE: u32 = 0x00100000;
pub const PF_KTHREAD: u32       = 0x00200000;
pub const PF_RANDOMIZE: u32     = 0x00400000;
pub const PF_NO_SETAFFINITY: u32 = 0x04000000;
pub const PF_MCE_EARLY: u32     = 0x08000000;
pub const PF_MEMALLOC_PIN: u32  = 0x10000000;

// ============================================================================
// Namespace Proxy
// ============================================================================

pub struct NsProxy {
    pub count: u32,
    pub uts_ns: u64,
    pub ipc_ns: u64,
    pub mnt_ns: u64,
    pub pid_ns_for_children: u64,
    pub net_ns: u64,
    pub time_ns: u64,
    pub time_ns_for_children: u64,
    pub cgroup_ns: u64,
}

// ============================================================================
// Restart Block
// ============================================================================

pub struct RestartBlock {
    pub restart_fn: u64,
    // Union for different restart types
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
}

// ============================================================================
// Wait4/Waitpid Options
// ============================================================================

pub const WNOHANG: u32     = 0x00000001;
pub const WUNTRACED: u32   = 0x00000002;
pub const WSTOPPED: u32    = WUNTRACED;
pub const WEXITED: u32     = 0x00000004;
pub const WCONTINUED: u32  = 0x00000008;
pub const WNOWAIT: u32     = 0x01000000;
pub const __WNOTHREAD: u32 = 0x20000000;
pub const __WALL: u32      = 0x40000000;
pub const __WCLONE: u32    = 0x80000000;

// ============================================================================
// Prctl
// ============================================================================

pub const PR_SET_PDEATHSIG: u32   = 1;
pub const PR_GET_PDEATHSIG: u32   = 2;
pub const PR_GET_DUMPABLE: u32    = 3;
pub const PR_SET_DUMPABLE: u32    = 4;
pub const PR_GET_UNALIGN: u32     = 5;
pub const PR_SET_UNALIGN: u32     = 6;
pub const PR_GET_KEEPCAPS: u32    = 7;
pub const PR_SET_KEEPCAPS: u32    = 8;
pub const PR_GET_FPEMU: u32       = 9;
pub const PR_SET_FPEMU: u32       = 10;
pub const PR_GET_FPEXC: u32       = 11;
pub const PR_SET_FPEXC: u32       = 12;
pub const PR_GET_TIMING: u32      = 13;
pub const PR_SET_TIMING: u32      = 14;
pub const PR_SET_NAME: u32        = 15;
pub const PR_GET_NAME: u32        = 16;
pub const PR_GET_ENDIAN: u32      = 19;
pub const PR_SET_ENDIAN: u32      = 20;
pub const PR_GET_SECCOMP: u32     = 21;
pub const PR_SET_SECCOMP: u32     = 22;
pub const PR_CAPBSET_READ: u32    = 23;
pub const PR_CAPBSET_DROP: u32    = 24;
pub const PR_GET_TSC: u32         = 25;
pub const PR_SET_TSC: u32         = 26;
pub const PR_GET_SECUREBITS: u32  = 27;
pub const PR_SET_SECUREBITS: u32  = 28;
pub const PR_SET_TIMERSLACK: u32  = 29;
pub const PR_GET_TIMERSLACK: u32  = 30;
pub const PR_SET_CHILD_SUBREAPER: u32 = 36;
pub const PR_GET_CHILD_SUBREAPER: u32 = 37;
pub const PR_SET_NO_NEW_PRIVS: u32 = 38;
pub const PR_GET_NO_NEW_PRIVS: u32 = 39;
pub const PR_GET_TID_ADDRESS: u32 = 40;
pub const PR_SET_THP_DISABLE: u32 = 41;
pub const PR_GET_THP_DISABLE: u32 = 42;
pub const PR_SET_PTRACER: u32     = 0x59616d61;
pub const PR_CAP_AMBIENT: u32     = 47;
pub const PR_SET_SPECULATION_CTRL: u32 = 53;
pub const PR_GET_SPECULATION_CTRL: u32 = 54;
pub const PR_PAC_RESET_KEYS: u32  = 54;
pub const PR_SET_TAGGED_ADDR_CTRL: u32 = 55;
pub const PR_GET_TAGGED_ADDR_CTRL: u32 = 56;
pub const PR_SET_IO_FLUSHER: u32  = 57;
pub const PR_GET_IO_FLUSHER: u32  = 58;
pub const PR_SET_SYSCALL_USER_DISPATCH: u32 = 59;
pub const PR_SET_MDWE: u32        = 65;
pub const PR_GET_MDWE: u32        = 66;

// ============================================================================
// Load Balancing / NUMA
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NumaBalanceMode {
    Disabled = 0,
    Enabled = 1,
    MemoryTiering = 2,
}

pub struct LoadBalanceStats {
    pub nr_balance_failed: u64,
    pub nr_balance_success: u64,
    pub nr_migrations: u64,
    pub nr_failed_migrations_affine: u64,
    pub nr_failed_migrations_running: u64,
    pub nr_failed_migrations_hot: u64,
    pub nr_forced_migrations: u64,
    pub nr_wakeups: u64,
    pub nr_wakeups_sync: u64,
    pub nr_wakeups_migrate: u64,
    pub nr_wakeups_local: u64,
    pub nr_wakeups_remote: u64,
    pub nr_wakeups_affine: u64,
    pub nr_wakeups_affine_attempts: u64,
    pub nr_wakeups_passive: u64,
    pub nr_wakeups_idle: u64,
}

// ============================================================================
// Process Accounting
// ============================================================================

pub struct ProcAccounting {
    pub ac_flag: u8,
    pub ac_version: u8,
    pub ac_tty: u16,
    pub ac_exitcode: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    // Time
    pub ac_btime: u32,     // Creation time
    pub ac_etime: u64,     // Elapsed time (us)
    pub ac_utime: u64,     // User CPU (us)
    pub ac_stime: u64,     // System CPU (us)
    // Memory
    pub ac_mem: u64,       // Average memory usage (KB)
    pub ac_rss: u64,       // Resident set size (KB)
    pub ac_vm: u64,        // VM size (KB)
    // I/O
    pub ac_io: u64,        // Chars transferred
    pub ac_rw: u64,        // Blocks read/written
    // Minor/Major faults
    pub ac_minflt: u64,
    pub ac_majflt: u64,
    // Swaps
    pub ac_swaps: u64,
    // Command name
    pub ac_comm: [16; u8],
}

// ============================================================================
// Process Manager
// ============================================================================

pub struct ProcessManager {
    pub pid_max: i32,
    pub threads_max: u64,
    pub max_threads_per_process: u64,
    // Counts
    pub nr_processes: u64,
    pub nr_threads: u64,
    pub nr_running: u64,
    pub nr_sleeping: u64,
    pub nr_stopped: u64,
    pub nr_zombie: u64,
    // Load average
    pub loadavg_1: u64,   // Fixed point * 2048
    pub loadavg_5: u64,
    pub loadavg_15: u64,
    // Forks
    pub total_forks: u64,
    // Context switches
    pub total_ctxt: u64,
    // Boot time
    pub boot_time: u64,
    // NUMA
    pub numa_balance_mode: NumaBalanceMode,
    // Load balancing
    pub lb_stats: LoadBalanceStats,
    // Zxyphor
    pub zxy_adaptive_scheduling: bool,
    pub zxy_energy_aware: bool,
    pub initialized: bool,
}
