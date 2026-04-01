// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Signal Handling Detail
// Comprehensive signal types, delivery, queuing, action, sigframe, sigreturn,
// real-time signals, POSIX semantics, signalfd, pidfd, sigtimedwait, SA_RESTART

const std = @import("std");

// ============================================================================
// Signal Numbers (x86_64 / generic)
// ============================================================================

pub const SignalNumber = enum(u8) {
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
    // RT signals 32-64
    SIGRTMIN = 32,
    SIGRTMAX = 64,

    pub fn isRealtime(self: SignalNumber) return bool {
        return @intFromEnum(self) >= 32;
    }

    pub fn isStopSignal(self: SignalNumber) bool {
        return self == .SIGSTOP or self == .SIGTSTP or self == .SIGTTIN or self == .SIGTTOU;
    }

    pub fn isIgnoredByDefault(self: SignalNumber) bool {
        return switch (self) {
            .SIGCHLD, .SIGURG, .SIGWINCH => true,
            else => false,
        };
    }

    pub fn isFatal(self: SignalNumber) bool {
        return switch (self) {
            .SIGKILL, .SIGSTOP => true,
            else => false,
        };
    }

    pub fn defaultAction(self: SignalNumber) DefaultAction {
        return switch (self) {
            .SIGHUP, .SIGINT, .SIGPIPE, .SIGALRM, .SIGTERM,
            .SIGUSR1, .SIGUSR2, .SIGSTKFLT, .SIGIO, .SIGPWR,
            .SIGPROF, .SIGVTALRM => .Terminate,
            .SIGQUIT, .SIGILL, .SIGTRAP, .SIGABRT, .SIGBUS,
            .SIGFPE, .SIGSEGV, .SIGXCPU, .SIGXFSZ, .SIGSYS => .CoreDump,
            .SIGSTOP, .SIGTSTP, .SIGTTIN, .SIGTTOU => .Stop,
            .SIGCONT => .Continue,
            .SIGCHLD, .SIGURG, .SIGWINCH => .Ignore,
            else => .Terminate,
        };
    }
};

pub const DefaultAction = enum(u8) {
    Terminate,
    CoreDump,
    Stop,
    Continue,
    Ignore,
};

pub const NSIG: u32 = 64;
pub const RT_SIG_MIN: u32 = 32;
pub const RT_SIG_MAX: u32 = 64;
pub const NR_RT_SIGNALS: u32 = RT_SIG_MAX - RT_SIG_MIN + 1;

// ============================================================================
// Signal Set (sigset_t)
// ============================================================================

pub const SigSet = struct {
    bits: [2]u64,

    pub const EMPTY: SigSet = .{ .bits = .{ 0, 0 } };
    pub const FULL: SigSet = .{ .bits = .{ 0xFFFFFFFF_FFFFFFFF, 0xFFFFFFFF_FFFFFFFF } };

    pub fn hasSig(self: *const SigSet, sig: u8) bool {
        if (sig == 0 or sig > NSIG) return false;
        const idx: usize = if (sig <= 64) 0 else 1;
        const bit: u6 = @truncate((sig - 1) % 64);
        return (self.bits[idx] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn addSig(self: *SigSet, sig: u8) void {
        if (sig == 0 or sig > NSIG) return;
        const idx: usize = if (sig <= 64) 0 else 1;
        const bit: u6 = @truncate((sig - 1) % 64);
        self.bits[idx] |= @as(u64, 1) << bit;
    }

    pub fn delSig(self: *SigSet, sig: u8) void {
        if (sig == 0 or sig > NSIG) return;
        const idx: usize = if (sig <= 64) 0 else 1;
        const bit: u6 = @truncate((sig - 1) % 64);
        self.bits[idx] &= ~(@as(u64, 1) << bit);
    }

    pub fn orSet(self: *SigSet, other: *const SigSet) void {
        self.bits[0] |= other.bits[0];
        self.bits[1] |= other.bits[1];
    }

    pub fn andSet(self: *SigSet, other: *const SigSet) void {
        self.bits[0] &= other.bits[0];
        self.bits[1] &= other.bits[1];
    }

    pub fn notSet(self: *SigSet) SigSet {
        return .{ .bits = .{ ~self.bits[0], ~self.bits[1] } };
    }

    pub fn isEmpty(self: *const SigSet) bool {
        return self.bits[0] == 0 and self.bits[1] == 0;
    }

    pub fn countPending(self: *const SigSet) u32 {
        var count: u32 = 0;
        count += @popCount(self.bits[0]);
        count += @popCount(self.bits[1]);
        return count;
    }
};

// ============================================================================
// sigaction (struct k_sigaction)
// ============================================================================

pub const SaFlags = packed struct(u32) {
    nocldstop: bool = false,  // SA_NOCLDSTOP
    nocldwait: bool = false,  // SA_NOCLDWAIT
    siginfo: bool = false,    // SA_SIGINFO
    _pad1: u1 = 0,
    onstack: bool = false,    // SA_ONSTACK
    restart: bool = false,    // SA_RESTART
    nodefer: bool = false,    // SA_NODEFER
    resethand: bool = false,  // SA_RESETHAND
    restorer: bool = false,   // SA_RESTORER
    _pad2: u23 = 0,
};

pub const SA_NOCLDSTOP: u32 = 0x00000001;
pub const SA_NOCLDWAIT: u32 = 0x00000002;
pub const SA_SIGINFO: u32 = 0x00000004;
pub const SA_ONSTACK: u32 = 0x08000000;
pub const SA_RESTART: u32 = 0x10000000;
pub const SA_NODEFER: u32 = 0x40000000;
pub const SA_RESETHAND: u32 = 0x80000000;
pub const SA_RESTORER: u32 = 0x04000000;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const SIG_ERR: u64 = @bitCast(@as(i64, -1));

pub const KSigaction = struct {
    handler: u64,             // sa_handler or sa_sigaction
    flags: SaFlags,
    restorer: u64,            // sa_restorer
    mask: SigSet,

    pub fn isDefault(self: *const KSigaction) bool {
        return self.handler == SIG_DFL;
    }

    pub fn isIgnored(self: *const KSigaction) bool {
        return self.handler == SIG_IGN;
    }

    pub fn useSiginfo(self: *const KSigaction) bool {
        return self.flags.siginfo;
    }
};

// ============================================================================
// siginfo_t
// ============================================================================

pub const SiCode = enum(i32) {
    SI_USER = 0,
    SI_KERNEL = 0x80,
    SI_QUEUE = -1,
    SI_TIMER = -2,
    SI_MESGQ = -3,
    SI_ASYNCIO = -4,
    SI_SIGIO = -5,
    SI_TKILL = -6,
    SI_DETHREAD = -7,
    SI_ASYNCNL = -60,
    // SIGILL
    ILL_ILLOPC = 1,
    ILL_ILLOPN = 2,
    ILL_ILLADR = 3,
    ILL_ILLTRP = 4,
    ILL_PRVOPC = 5,
    ILL_PRVREG = 6,
    ILL_COPROC = 7,
    ILL_BADSTK = 8,
    // SIGFPE
    FPE_INTDIV = 1,
    FPE_INTOVF = 2,
    FPE_FLTDIV = 3,
    FPE_FLTOVF = 4,
    FPE_FLTUND = 5,
    FPE_FLTRES = 6,
    FPE_FLTINV = 7,
    FPE_FLTSUB = 8,
    FPE_FLTUNK = 14,
    FPE_CONDTRAP = 15,
    // SIGSEGV
    SEGV_MAPERR = 1,
    SEGV_ACCERR = 2,
    SEGV_BNDERR = 3,
    SEGV_PKUERR = 4,
    SEGV_MTEAERR = 8,
    SEGV_MTESERR = 9,
    // SIGBUS
    BUS_ADRALN = 1,
    BUS_ADRERR = 2,
    BUS_OBJERR = 3,
    BUS_MCEERR_AR = 4,
    BUS_MCEERR_AO = 5,
    // SIGTRAP
    TRAP_BRKPT = 1,
    TRAP_TRACE = 2,
    TRAP_BRANCH = 3,
    TRAP_HWBKPT = 4,
    TRAP_UNK = 5,
    TRAP_PERF = 6,
    // SIGCHLD
    CLD_EXITED = 1,
    CLD_KILLED = 2,
    CLD_DUMPED = 3,
    CLD_TRAPPED = 4,
    CLD_STOPPED = 5,
    CLD_CONTINUED = 6,
    // SIGSYS (seccomp)
    SYS_SECCOMP = 1,
    SYS_USER_DISPATCH = 2,
    _,
};

pub const SigInfo = extern struct {
    signo: i32,
    errno_val: i32,
    code: i32,
    _pad0: i32 = 0,
    // Union area (128 bytes total minus header)
    fields: SigInfoFields,
};

pub const SigInfoFields = extern union {
    kill: SigInfoKill,
    timer: SigInfoTimer,
    rt: SigInfoRt,
    sigchld: SigInfoChld,
    sigfault: SigInfoFault,
    sigpoll: SigInfoPoll,
    sigsys: SigInfoSys,
    _pad: [28]u32,
};

pub const SigInfoKill = extern struct {
    pid: i32,
    uid: u32,
};

pub const SigInfoTimer = extern struct {
    tid: i32,
    overrun: i32,
    sigval: u64,
};

pub const SigInfoRt = extern struct {
    pid: i32,
    uid: u32,
    sigval: u64,
};

pub const SigInfoChld = extern struct {
    pid: i32,
    uid: u32,
    status: i32,
    _pad: u32 = 0,
    utime: u64,
    stime: u64,
};

pub const SigInfoFault = extern struct {
    addr: u64,
    addr_lsb: i16,
    _pad0: i16 = 0,
    _pad1: i32 = 0,
    bounds: SigInfoBounds,
};

pub const SigInfoBounds = extern union {
    addr_bnd: extern struct {
        lower: u64,
        upper: u64,
    },
    pkey: u32,
};

pub const SigInfoPoll = extern struct {
    band: i64,
    fd: i32,
};

pub const SigInfoSys = extern struct {
    call_addr: u64,
    syscall: i32,
    arch: u32,
};

// ============================================================================
// Signal Queue
// ============================================================================

pub const SigQueue = struct {
    list_next: ?*SigQueue,
    info: SigInfo,
    flags: SigQueueFlags,
    user: u64,  // user_struct *

    pub const SigQueueFlags = packed struct(u32) {
        allocated: bool = false,
        free_after_deliver: bool = false,
        _pad: u30 = 0,
    };
};

pub const SigPending = struct {
    list_head: u64,       // list_head for sigqueue chain
    signal: SigSet,

    pub fn init() SigPending {
        return .{
            .list_head = 0,
            .signal = SigSet.EMPTY,
        };
    }
};

// ============================================================================
// Signal Struct (shared between threads in a thread group)
// ============================================================================

pub const SignalStruct = struct {
    sigcnt: u64,              // atomic refcount
    nr_threads: u32,
    live: u32,                // atomic

    // Shared pending signals
    shared_pending: SigPending,

    // Group stop / job control
    group_exit_code: i32,
    group_exit_task: u64,     // task_struct *
    group_stop_count: u32,
    group_stop_flags: GroupStopFlags,
    notify_count: u32,

    // Thread group leader
    leader: u64,              // task_struct * (always tgid leader)
    tty: u64,                 // tty_struct *

    // Timers
    real_timer: u64,          // hrtimer (ITIMER_REAL)
    it_real_incr: u64,        // ktime_t
    cputimer: CpuTimer,

    // POSIX timers
    posix_timers: u64,        // list_head
    posix_cputimers: PosixCputimers,

    // Process accounting
    utime: u64,
    stime: u64,
    cutime: u64,
    cstime: u64,
    gtime: u64,
    cgtime: u64,
    maxrss: u64,
    cmaxrss: u64,

    // I/O accounting
    ioac: IoAccounting,

    // Signal action table
    action: [NSIG]KSigaction,

    // Resource limits
    rlim: [16]RLimit,

    // Various
    audit_tty: u32,
    oom_score_adj: i16,
    oom_score_adj_min: i16,
    has_child_subreaper: bool,
    is_child_subreaper: bool,
};

pub const GroupStopFlags = packed struct(u32) {
    group_stop_wanted: bool = false,
    group_stop_in_progress: bool = false,
    group_exit: bool = false,
    notify: bool = false,
    _pad: u28 = 0,
};

pub const CpuTimer = struct {
    cputime: [3]u64,          // prof, virt, sched
    running: bool,
};

pub const PosixCputimers = struct {
    bases: [3]PosixTimerBase,
    expiry_active: bool,
};

pub const PosixTimerBase = struct {
    next_expiry: u64,
    cpu_timer_list: u64,
};

pub const IoAccounting = struct {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    syscw: u64,
    read_bytes: u64,
    write_bytes: u64,
    cancelled_write_bytes: u64,
};

pub const RLimit = struct {
    cur: u64,     // soft limit
    max: u64,     // hard limit
};

// ============================================================================
// Signal Frame (x86_64)
// ============================================================================

pub const UContext = extern struct {
    uc_flags: u64,
    uc_link: u64,             // ucontext *
    uc_stack: StackT,
    uc_mcontext: MContext,
    uc_sigmask: SigSet,
};

pub const StackT = extern struct {
    ss_sp: u64,              // void *
    ss_flags: i32,
    _pad: i32 = 0,
    ss_size: u64,
};

pub const MContext = extern struct {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    eflags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: u64,            // _fpstate *
    reserved1: [8]u64,
};

pub const RtSigframe = extern struct {
    pretcode: u64,            // return trampoline
    uc: UContext,
    info: SigInfo,
    // FPU state follows
};

// ============================================================================
// signalfd
// ============================================================================

pub const SignalfdSiginfo = extern struct {
    ssi_signo: u32,
    ssi_errno: i32,
    ssi_code: i32,
    ssi_pid: u32,
    ssi_uid: u32,
    ssi_fd: i32,
    ssi_tid: u32,
    ssi_band: u32,
    ssi_overrun: u32,
    ssi_trapno: u32,
    ssi_status: i32,
    ssi_int: i32,
    ssi_ptr: u64,
    ssi_utime: u64,
    ssi_stime: u64,
    ssi_addr: u64,
    ssi_addr_lsb: u16,
    _pad2: u16 = 0,
    ssi_syscall: i32,
    ssi_call_addr: u64,
    ssi_arch: u32,
    _pad: [28]u8,
};

pub const SFD_CLOEXEC: u32 = 0o2000000;
pub const SFD_NONBLOCK: u32 = 0o4000;

// ============================================================================
// pidfd (signal delivery via pidfd_send_signal)
// ============================================================================

pub const PidfdSignalFlags = packed struct(u32) {
    thread: bool = false,       // PIDFD_SIGNAL_THREAD
    thread_group: bool = false, // PIDFD_SIGNAL_THREAD_GROUP
    process_group: bool = false,// PIDFD_SIGNAL_PROCESS_GROUP
    _pad: u29 = 0,
};

// ============================================================================
// Signal Delivery Engine
// ============================================================================

pub const DeliveryResult = enum(u8) {
    Delivered,
    Ignored,
    Queued,
    QueueFull,
    KilledProcess,
    StoppedProcess,
    ContinuedProcess,
    CoredumpStarted,
    Error,
};

pub const SignalDeliveryStats = struct {
    total_signals_sent: u64,
    total_signals_delivered: u64,
    total_signals_ignored: u64,
    total_signals_queued: u64,
    total_queue_overflows: u64,
    total_coredumps: u64,
    total_group_stops: u64,
    total_fatal_signals: u64,
    rt_signals_queued: u64,
    signalfd_notifications: u64,
    per_signal_count: [NSIG]u64,
};

pub const SignalSubsystemManager = struct {
    stats: SignalDeliveryStats,
    max_pending: u32,    // RLIMIT_SIGPENDING per user
    default_max: u32,
    initialized: bool,

    pub fn init() SignalSubsystemManager {
        return .{
            .stats = std.mem.zeroes(SignalDeliveryStats),
            .max_pending = 65536,
            .default_max = 65536,
            .initialized = true,
        };
    }
};
