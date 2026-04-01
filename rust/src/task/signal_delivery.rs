// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - Task Signals, Signal Delivery, Signal Queues,
// POSIX Timers, Interval Timers, Robust Futex List
// More advanced than Linux 2026 signal handling

/// Signal numbers (POSIX + Linux-specific)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalNumber {
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
    // Real-time signals: 32-64
    SIGRTMIN = 32,
    SIGRTMAX = 64,
    // Zxyphor
    ZXY_SIGNOTIFY = 65,
    ZXY_SIGWATCHDOG = 66,
}

/// Signal action flags (sa_flags)
pub const SA_NOCLDSTOP: u64 = 0x00000001;
pub const SA_NOCLDWAIT: u64 = 0x00000002;
pub const SA_SIGINFO: u64 = 0x00000004;
pub const SA_ONSTACK: u64 = 0x08000000;
pub const SA_RESTART: u64 = 0x10000000;
pub const SA_NODEFER: u64 = 0x40000000;
pub const SA_RESETHAND: u64 = 0x80000000;
pub const SA_RESTORER: u64 = 0x04000000;
pub const SA_EXPOSE_TAGBITS: u64 = 0x00000800;
// Zxyphor
pub const SA_ZXY_PRECISE: u64 = 1 << 48;

/// Signal handler type
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHandler {
    Default = 0,        // SIG_DFL
    Ignore = 1,         // SIG_IGN
    Error = !0u64,      // SIG_ERR
}

/// sigaction structure
#[derive(Debug, Clone)]
pub struct Sigaction {
    pub handler: u64,       // sa_handler or sa_sigaction
    pub flags: u64,         // sa_flags
    pub restorer: u64,      // sa_restorer
    pub mask: SigSet,       // sa_mask
}

/// Signal set (64 signals = 1 u64, RT signals in second word)
#[derive(Debug, Clone, Copy, Default)]
pub struct SigSet {
    pub sig: [2; u64],
}

impl SigSet {
    pub fn empty() -> Self {
        Self { sig: [0, 0] }
    }

    pub fn full() -> Self {
        Self { sig: [!0u64, !0u64] }
    }

    pub fn add(&mut self, signum: u8) {
        if signum == 0 || signum > 128 { return; }
        let idx = ((signum - 1) / 64) as usize;
        let bit = (signum - 1) % 64;
        self.sig[idx] |= 1u64 << bit;
    }

    pub fn del(&mut self, signum: u8) {
        if signum == 0 || signum > 128 { return; }
        let idx = ((signum - 1) / 64) as usize;
        let bit = (signum - 1) % 64;
        self.sig[idx] &= !(1u64 << bit);
    }

    pub fn is_member(&self, signum: u8) -> bool {
        if signum == 0 || signum > 128 { return false; }
        let idx = ((signum - 1) / 64) as usize;
        let bit = (signum - 1) % 64;
        (self.sig[idx] & (1u64 << bit)) != 0
    }
}

/// siginfo_t - Signal information
#[derive(Debug, Clone)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    // Union fields based on signal type
    pub fields: SigInfoFields,
    // Timestamp
    pub timestamp_ns: u64,
}

/// Signal info union fields
#[derive(Debug, Clone)]
pub enum SigInfoFields {
    Kill {
        pid: i32,
        uid: u32,
    },
    Timer {
        tid: i32,
        overrun: i32,
        sigval: u64,
    },
    Rt {
        pid: i32,
        uid: u32,
        sigval: u64,
    },
    Sigchld {
        pid: i32,
        uid: u32,
        status: i32,
        utime: u64,
        stime: u64,
    },
    Sigfault {
        addr: u64,
        addr_lsb: u16,
        addr_bnd_lower: u64,
        addr_bnd_upper: u64,
        addr_pkey: u32,
        trapno: u32,
        // Perf
        perf_data: u64,
        perf_type: u32,
        perf_flags: u32,
    },
    Sigpoll {
        band: i64,
        fd: i32,
    },
    Sigsys {
        call_addr: u64,
        syscall: i32,
        arch: u32,
    },
    None,
}

/// SI_CODE values for SIGSEGV
pub const SEGV_MAPERR: i32 = 1;  // Address not mapped
pub const SEGV_ACCERR: i32 = 2;  // Invalid permisions
pub const SEGV_BNDERR: i32 = 3;  // MPX bounds check
pub const SEGV_PKUERR: i32 = 4;  // Protection key error
pub const SEGV_MTEAERR: i32 = 8; // MTE async fault (ARM)
pub const SEGV_MTESERR: i32 = 9; // MTE sync fault (ARM)
pub const SEGV_CPERR: i32 = 10;  // CHERI capability fault

/// SI_CODE values for SIGBUS
pub const BUS_ADRALN: i32 = 1;   // Invalid address alignment
pub const BUS_ADRERR: i32 = 2;   // Non-existent physical address
pub const BUS_OBJERR: i32 = 3;   // Object-specific error
pub const BUS_MCEERR_AR: i32 = 4; // Machine check: action required
pub const BUS_MCEERR_AO: i32 = 5; // Machine check: action optional

/// SI_CODE values for SIGFPE
pub const FPE_INTDIV: i32 = 1;
pub const FPE_INTOVF: i32 = 2;
pub const FPE_FLTDIV: i32 = 3;
pub const FPE_FLTOVF: i32 = 4;
pub const FPE_FLTUND: i32 = 5;
pub const FPE_FLTRES: i32 = 6;
pub const FPE_FLTINV: i32 = 7;
pub const FPE_FLTSUB: i32 = 8;
pub const FPE_CONDTRAP: i32 = 10;

/// SI_CODE values for SIGTRAP
pub const TRAP_BRKPT: i32 = 1;   // Breakpoint
pub const TRAP_TRACE: i32 = 2;   // Single step
pub const TRAP_BRANCH: i32 = 3;  // Branch trap
pub const TRAP_HWBKPT: i32 = 4;  // Hardware breakpoint/watchpoint
pub const TRAP_UNK: i32 = 5;     // Unknown
pub const TRAP_PERF: i32 = 6;    // Perf event

/// SI_CODE values for SIGCHLD
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_TRAPPED: i32 = 4;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

// ============================================================================
// Signal Queues
// ============================================================================

/// Signal queue entry
#[derive(Debug, Clone)]
pub struct SignalQueueEntry {
    pub info: SigInfo,
    pub user_ns: u64,    // User namespace for uid/gid translation
}

/// Pending signals per-thread
#[derive(Debug, Clone)]
pub struct SigPending {
    pub signal: SigSet,
    // Queue for real-time and siginfo signals
    pub queue_len: u32,
    pub max_queue: u32,
}

/// Shared pending signals (per-process)
#[derive(Debug, Clone)]
pub struct SharedPending {
    pub signal: SigSet,
    pub queue_len: u32,
}

// ============================================================================
// Signal Stack
// ============================================================================

/// Alternate signal stack
#[derive(Debug, Clone)]
pub struct SigAltStack {
    pub ss_sp: u64,
    pub ss_flags: u32,
    pub ss_size: u64,
}

/// Signal stack flags
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;

/// Minimum alt stack size
pub const MINSIGSTKSZ: usize = 2048;
pub const SIGSTKSZ: usize = 8192;

// ============================================================================
// Signal Frame (for signal delivery on x86_64)
// ============================================================================

/// Signal frame layout on stack
#[derive(Debug, Clone)]
pub struct SignalFrame {
    pub pretcode: u64,
    // ucontext
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: SigAltStack,
    // Machine context
    pub uc_mcontext: MachineContext,
    pub uc_sigmask: SigSet,
}

/// Machine context (sigcontext for x86_64)
#[derive(Debug, Clone)]
pub struct MachineContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    // FPU state pointer
    pub fpstate: u64,
    // Reserved
    pub reserved: [8; u64],
}

// ============================================================================
// POSIX Timers
// ============================================================================

/// POSIX timer
#[derive(Debug, Clone)]
pub struct PosixTimer {
    pub id: i32,
    pub clock_id: ClockId,
    pub signo: i32,
    pub sigval: u64,
    // Notification
    pub notify: TimerNotify,
    // Interval
    pub interval_sec: i64,
    pub interval_nsec: i64,
    // Expiry
    pub it_value_sec: i64,
    pub it_value_nsec: i64,
    // Overrun
    pub overrun: i32,
    pub overrun_last: i32,
    // Status
    pub armed: bool,
    pub pending: bool,
    // Stats
    pub total_expirations: u64,
    pub total_overruns: u64,
}

/// Clock ID
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockId {
    Realtime = 0,
    Monotonic = 1,
    ProcessCputime = 2,
    ThreadCputime = 3,
    MonotonicRaw = 4,
    RealtimeCoarse = 5,
    MonotonicCoarse = 6,
    Boottime = 7,
    RealtimeAlarm = 8,
    BoottimeAlarm = 9,
    Tai = 11,
}

/// Timer notification type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerNotify {
    Signal = 0,        // SIGEV_SIGNAL
    None = 1,          // SIGEV_NONE
    Thread = 2,        // SIGEV_THREAD
    ThreadId = 4,      // SIGEV_THREAD_ID
}

/// Interval timer (setitimer/getitimer)
#[derive(Debug, Clone)]
pub struct IntervalTimer {
    pub which: ItimerWhich,
    pub interval_sec: i64,
    pub interval_usec: i64,
    pub value_sec: i64,
    pub value_usec: i64,
    pub total_expirations: u64,
}

/// Interval timer type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItimerWhich {
    Real = 0,       // ITIMER_REAL (SIGALRM)
    Virtual = 1,    // ITIMER_VIRTUAL (SIGVTALRM)
    Prof = 2,       // ITIMER_PROF (SIGPROF)
}

// ============================================================================
// Robust Futex List
// ============================================================================

/// Robust list head
#[derive(Debug, Clone)]
pub struct RobustListHead {
    pub list: u64,           // Pointer to robust_list
    pub futex_offset: i64,   // Offset of futex in list entry
    pub list_op_pending: u64, // Currently being modified
}

/// Robust futex entry
#[derive(Debug, Clone)]
pub struct RobustFutexEntry {
    pub next: u64,           // Next entry
    pub futex_addr: u64,     // Address of the futex word
    /// Owner TID is stored in the futex word
    pub pi: bool,            // Priority inheritance
}

// ============================================================================
// Process Group / Session
// ============================================================================

/// Process group
#[derive(Debug, Clone)]
pub struct ProcessGroup {
    pub pgid: i32,
    pub session_id: i32,
    pub nr_members: u32,
    // Job control
    pub foreground: bool,
    pub orphaned: bool,
}

/// Session
#[derive(Debug, Clone)]
pub struct Session {
    pub sid: i32,
    pub leader_pid: i32,
    // Controlling terminal
    pub ctty_dev: u64,      // dev_t
    pub ctty_name: [64; u8],
    // Groups
    pub nr_pgroups: u32,
}

/// Wait options
pub const WNOHANG: u32 = 0x00000001;
pub const WUNTRACED: u32 = 0x00000002;
pub const WSTOPPED: u32 = 0x00000002;
pub const WEXITED: u32 = 0x00000004;
pub const WCONTINUED: u32 = 0x00000008;
pub const WNOWAIT: u32 = 0x01000000;
pub const __WNOTHREAD: u32 = 0x20000000;
pub const __WALL: u32 = 0x40000000;
pub const __WCLONE: u32 = 0x80000000;

/// waitid which
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitidWhich {
    P_ALL = 0,
    P_PID = 1,
    P_PGID = 2,
    P_PIDFD = 3,
}

// ============================================================================
// Thread Credentials
// ============================================================================

/// Credential set
#[derive(Debug, Clone)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    // Supplementary groups
    pub nr_groups: u32,
    pub groups: [65536; u32],   // Max NGROUPS_MAX
    // Capabilities
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_bset: u64,          // Bounding set
    pub cap_ambient: u64,
    // Securebits
    pub securebits: u32,
    // User namespace
    pub user_ns_id: u64,
    // LSM context
    pub security_label: [256; u8],
    // Keyring
    pub session_keyring: u64,
    pub process_keyring: u64,
    pub thread_keyring: u64,
}

/// Securebits flags
pub const SECUREBITS_NOROOT: u32 = 0x01;
pub const SECUREBITS_NOROOT_LOCKED: u32 = 0x02;
pub const SECUREBITS_NO_SETUID_FIXUP: u32 = 0x04;
pub const SECUREBITS_NO_SETUID_FIXUP_LOCKED: u32 = 0x08;
pub const SECUREBITS_KEEP_CAPS: u32 = 0x10;
pub const SECUREBITS_KEEP_CAPS_LOCKED: u32 = 0x20;
pub const SECUREBITS_NO_CAP_AMBIENT_RAISE: u32 = 0x40;
pub const SECUREBITS_NO_CAP_AMBIENT_RAISE_LOCKED: u32 = 0x80;

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Signal subsystem
#[derive(Debug, Clone)]
pub struct SignalSubsystem {
    // Signals
    pub max_signal: u8,
    pub nr_rt_signals: u8,
    // Queue limits
    pub max_queued_signals: u32,
    pub current_queued: u32,
    // POSIX timers
    pub max_timers: u32,
    pub current_timers: u32,
    // Stats
    pub total_signals_sent: u64,
    pub total_signals_delivered: u64,
    pub total_signals_ignored: u64,
    pub total_signals_blocked: u64,
    pub total_coredumps: u64,
    pub total_sigkills: u64,
    pub total_timer_expirations: u64,
    pub total_timer_overruns: u64,
    // Zxyphor
    pub zxy_fast_signal_delivery: bool,
    pub zxy_signal_tracing: bool,
    pub initialized: bool,
}
