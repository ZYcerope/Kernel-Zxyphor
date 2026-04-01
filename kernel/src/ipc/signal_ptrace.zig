// =============================================================================
// Kernel Zxyphor — Signal & Ptrace Subsystem
// =============================================================================
// POSIX-compliant signal handling + ptrace debugging interface:
//   - 64 standard + real-time signals
//   - Signal masks (block/unblock/pending)
//   - Signal actions (default/ignore/catch with handler)
//   - Signal queuing (real-time signals queued, standard coalesced)
//   - Process groups and sessions for signal delivery
//   - Ptrace: TRACEME, ATTACH, PEEKDATA, POKEDATA, CONT, SINGLESTEP
//   - Breakpoint management (software INT3 breakpoints)
//   - Register inspection/modification
//   - waitpid/wait4 status integration
//   - Core dump generation metadata
// =============================================================================

const std = @import("std");

// =============================================================================
// Signal numbers (Linux-compatible)
// =============================================================================

pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGSTKFLT: u8 = 16;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;
pub const SIGURG: u8 = 23;
pub const SIGXCPU: u8 = 24;
pub const SIGXFSZ: u8 = 25;
pub const SIGVTALRM: u8 = 26;
pub const SIGPROF: u8 = 27;
pub const SIGWINCH: u8 = 28;
pub const SIGIO: u8 = 29;
pub const SIGPWR: u8 = 30;
pub const SIGSYS: u8 = 31;
pub const SIGRTMIN: u8 = 32;
pub const SIGRTMAX: u8 = 64;
pub const MAX_SIGNALS: usize = 64;

// =============================================================================
// Signal action types
// =============================================================================

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const SA_NOCLDSTOP: u32 = 0x00000001;
pub const SA_NOCLDWAIT: u32 = 0x00000002;
pub const SA_SIGINFO: u32 = 0x00000004;
pub const SA_ONSTACK: u32 = 0x08000000;
pub const SA_RESTART: u32 = 0x10000000;
pub const SA_NODEFER: u32 = 0x40000000;
pub const SA_RESETHAND: u32 = 0x80000000;

// Signal disposition for default action
pub const SigDefault = enum(u8) {
    terminate = 0,
    ignore = 1,
    core_dump = 2,
    stop = 3,
    @"continue" = 4,
};

fn defaultDisposition(sig: u8) SigDefault {
    return switch (sig) {
        SIGHUP, SIGINT, SIGPIPE, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGSTKFLT, SIGIO, SIGPWR, SIGPROF, SIGVTALRM, SIGXCPU, SIGXFSZ => .terminate,
        SIGQUIT, SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGSYS => .core_dump,
        SIGCHLD, SIGURG, SIGWINCH => .ignore,
        SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU => .stop,
        SIGCONT => .@"continue",
        else => .terminate,
    };
}

// =============================================================================
// Signal mask (64-bit bitmask)
// =============================================================================

pub const SignalSet = struct {
    bits: u64,

    pub const empty = SignalSet{ .bits = 0 };
    pub const full = SignalSet{ .bits = 0xFFFFFFFFFFFFFFFF };

    pub fn add(self: SignalSet, sig: u8) SignalSet {
        if (sig < 1 or sig > MAX_SIGNALS) return self;
        return .{ .bits = self.bits | (@as(u64, 1) << @intCast(sig - 1)) };
    }

    pub fn remove(self: SignalSet, sig: u8) SignalSet {
        if (sig < 1 or sig > MAX_SIGNALS) return self;
        return .{ .bits = self.bits & ~(@as(u64, 1) << @intCast(sig - 1)) };
    }

    pub fn contains(self: SignalSet, sig: u8) bool {
        if (sig < 1 or sig > MAX_SIGNALS) return false;
        return (self.bits & (@as(u64, 1) << @intCast(sig - 1))) != 0;
    }

    pub fn @"union"(self: SignalSet, other: SignalSet) SignalSet {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn intersect(self: SignalSet, other: SignalSet) SignalSet {
        return .{ .bits = self.bits & other.bits };
    }

    pub fn complement(self: SignalSet) SignalSet {
        return .{ .bits = ~self.bits };
    }

    pub fn isEmpty(self: SignalSet) bool {
        return self.bits == 0;
    }

    /// Find lowest pending signal
    pub fn firstSignal(self: SignalSet) ?u8 {
        if (self.bits == 0) return null;
        const bit = @ctz(self.bits);
        return @intCast(bit + 1);
    }

    /// Unblockable signals mask
    pub const unblockable = SignalSet.empty.add(SIGKILL).add(SIGSTOP);
};

// =============================================================================
// Signal info (extended signal data)
// =============================================================================

pub const SignalCode = enum(i32) {
    si_user = 0,       // kill()
    si_kernel = 0x80,  // Kernel-generated
    si_queue = -1,     // sigqueue()
    si_timer = -2,     // Timer expired
    si_mesgq = -3,     // Msg queue change
    si_asyncio = -4,   // AIO completed
    si_sigio = -5,     // SIGIO
    si_tkill = -6,     // tkill/tgkill
    _,
};

pub const SigInfo = struct {
    signo: u8,
    code: SignalCode,
    errno_val: i32,
    sender_pid: u32,
    sender_uid: u32,
    value: u64,           // sigval (int or pointer)
    fault_addr: u64,      // For SIGSEGV/SIGBUS
    timer_id: u32,        // For timer signals
    band: i32,            // For SIGIO
    status: i32,          // For SIGCHLD (child exit status)
};

// =============================================================================
// Signal action
// =============================================================================

pub const SigAction = struct {
    handler: u64,          // SIG_DFL, SIG_IGN, or function pointer
    flags: u32,
    mask: SignalSet,       // Signals to block during handler
    restorer: u64,         // Signal trampoline address

    pub const default_action = SigAction{
        .handler = SIG_DFL,
        .flags = 0,
        .mask = SignalSet.empty,
        .restorer = 0,
    };
};

// =============================================================================
// Per-process signal state
// =============================================================================

pub const MAX_QUEUED_SIGNALS: usize = 32;

pub const QueuedSignal = struct {
    info: SigInfo,
    valid: bool,
};

pub const SignalState = struct {
    // Signal actions
    actions: [MAX_SIGNALS]SigAction,

    // Pending signals
    pending: SignalSet,
    shared_pending: SignalSet, // Group-wide pending

    // Blocked signals
    blocked: SignalSet,
    saved_blocked: SignalSet,  // For sigsuspend

    // Real-time signal queue
    queue: [MAX_QUEUED_SIGNALS]QueuedSignal,
    queue_count: u32,

    // Alternate signal stack
    alt_stack_ptr: u64,
    alt_stack_size: u64,
    alt_stack_flags: u32,

    // Statistics
    signals_delivered: u64,
    signals_ignored: u64,
    signals_caught: u64,

    pub fn init() SignalState {
        var state: SignalState = undefined;
        for (0..MAX_SIGNALS) |i| {
            state.actions[i] = SigAction.default_action;
        }
        state.pending = SignalSet.empty;
        state.shared_pending = SignalSet.empty;
        state.blocked = SignalSet.empty;
        state.saved_blocked = SignalSet.empty;
        state.queue_count = 0;
        for (0..MAX_QUEUED_SIGNALS) |i| {
            state.queue[i].valid = false;
        }
        state.alt_stack_ptr = 0;
        state.alt_stack_size = 0;
        state.alt_stack_flags = 0;
        state.signals_delivered = 0;
        state.signals_ignored = 0;
        state.signals_caught = 0;
        return state;
    }

    /// Send a signal to this process
    pub fn sendSignal(self: *SignalState, info: SigInfo) SignalError!void {
        const sig = info.signo;
        if (sig < 1 or sig > MAX_SIGNALS) return SignalError.InvalidSignal;

        // Check if signal is ignored (but SIGKILL/SIGSTOP can't be)
        if (sig != SIGKILL and sig != SIGSTOP) {
            const action = self.actions[sig - 1];
            if (action.handler == SIG_IGN) {
                self.signals_ignored += 1;
                return;
            }
            if (action.handler == SIG_DFL and defaultDisposition(sig) == .ignore) {
                self.signals_ignored += 1;
                return;
            }
        }

        // Standard signals: coalesce (only one pending per signal)
        if (sig < SIGRTMIN) {
            self.pending = self.pending.add(sig);
        } else {
            // Real-time signals: queue
            if (self.queue_count < MAX_QUEUED_SIGNALS) {
                for (0..MAX_QUEUED_SIGNALS) |i| {
                    if (!self.queue[i].valid) {
                        self.queue[i] = .{ .info = info, .valid = true };
                        self.queue_count += 1;
                        break;
                    }
                }
            }
            self.pending = self.pending.add(sig);
        }
    }

    /// Dequeue next deliverable signal
    pub fn dequeueSignal(self: *SignalState) ?SigInfo {
        // Find signals that are pending and not blocked
        const deliverable = self.pending.intersect(self.blocked.complement());
        if (deliverable.isEmpty()) return null;

        // Prefer standard signals over real-time
        const sig = deliverable.firstSignal() orelse return null;

        // Check real-time queue first
        if (sig >= SIGRTMIN) {
            for (0..MAX_QUEUED_SIGNALS) |i| {
                if (self.queue[i].valid and self.queue[i].info.signo == sig) {
                    const info = self.queue[i].info;
                    self.queue[i].valid = false;
                    self.queue_count -= 1;

                    // Check if more of this signal queued
                    var more = false;
                    for (0..MAX_QUEUED_SIGNALS) |j| {
                        if (self.queue[j].valid and self.queue[j].info.signo == sig) {
                            more = true;
                            break;
                        }
                    }
                    if (!more) {
                        self.pending = self.pending.remove(sig);
                    }
                    self.signals_delivered += 1;
                    return info;
                }
            }
        }

        // Standard signal
        self.pending = self.pending.remove(sig);
        self.signals_delivered += 1;
        return SigInfo{
            .signo = sig,
            .code = .si_kernel,
            .errno_val = 0,
            .sender_pid = 0,
            .sender_uid = 0,
            .value = 0,
            .fault_addr = 0,
            .timer_id = 0,
            .band = 0,
            .status = 0,
        };
    }

    /// Set signal action (sigaction)
    pub fn setAction(self: *SignalState, sig: u8, action: SigAction) SignalError!SigAction {
        if (sig < 1 or sig > MAX_SIGNALS) return SignalError.InvalidSignal;
        if (sig == SIGKILL or sig == SIGSTOP) return SignalError.CannotCatch;

        const old = self.actions[sig - 1];
        self.actions[sig - 1] = action;
        // Force-clear unblockable signals from mask
        self.actions[sig - 1].mask = action.mask.intersect(SignalSet.unblockable.complement());
        return old;
    }

    /// Modify blocked signal mask
    pub fn sigprocmask(self: *SignalState, how: SigMaskHow, set: SignalSet) SignalSet {
        const old = self.blocked;
        switch (how) {
            .block => {
                self.blocked = self.blocked.@"union"(set).intersect(SignalSet.unblockable.complement());
            },
            .unblock => {
                self.blocked = self.blocked.intersect(set.complement());
            },
            .setmask => {
                self.blocked = set.intersect(SignalSet.unblockable.complement());
            },
        }
        return old;
    }

    pub fn hasPendingSignals(self: *const SignalState) bool {
        const deliverable = self.pending.intersect(self.blocked.complement());
        return !deliverable.isEmpty();
    }
};

pub const SigMaskHow = enum(u32) {
    block = 0,
    unblock = 1,
    setmask = 2,
};

pub const SignalError = error{
    InvalidSignal,
    CannotCatch,
    QueueFull,
    ProcessNotFound,
    PermissionDenied,
};

// =============================================================================
// Signal delivery engine
// =============================================================================

pub const MAX_PROCESSES: usize = 512;

pub const SignalEngine = struct {
    process_states: [MAX_PROCESSES]SignalState,
    process_pids: [MAX_PROCESSES]u32,
    process_count: u32,

    pub fn init() SignalEngine {
        var engine: SignalEngine = undefined;
        for (0..MAX_PROCESSES) |i| {
            engine.process_states[i] = SignalState.init();
            engine.process_pids[i] = 0;
        }
        engine.process_count = 0;
        return engine;
    }

    pub fn registerProcess(self: *SignalEngine, pid: u32) bool {
        if (self.process_count >= MAX_PROCESSES) return false;
        for (0..MAX_PROCESSES) |i| {
            if (self.process_pids[i] == 0) {
                self.process_pids[i] = pid;
                self.process_states[i] = SignalState.init();
                self.process_count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn unregisterProcess(self: *SignalEngine, pid: u32) void {
        for (0..MAX_PROCESSES) |i| {
            if (self.process_pids[i] == pid) {
                self.process_pids[i] = 0;
                self.process_count -= 1;
                return;
            }
        }
    }

    fn findProcess(self: *SignalEngine, pid: u32) ?*SignalState {
        for (0..MAX_PROCESSES) |i| {
            if (self.process_pids[i] == pid) {
                return &self.process_states[i];
            }
        }
        return null;
    }

    /// Send signal to a specific process (kill)
    pub fn kill(self: *SignalEngine, target_pid: u32, sig: u8, sender_pid: u32) SignalError!void {
        const state = self.findProcess(target_pid) orelse return SignalError.ProcessNotFound;
        const info = SigInfo{
            .signo = sig,
            .code = .si_user,
            .errno_val = 0,
            .sender_pid = sender_pid,
            .sender_uid = 0,
            .value = 0,
            .fault_addr = 0,
            .timer_id = 0,
            .band = 0,
            .status = 0,
        };
        try state.sendSignal(info);
    }

    /// Send signal to all processes in a process group
    pub fn killProcessGroup(self: *SignalEngine, pgid: u32, sig: u8, sender_pid: u32) u32 {
        var sent: u32 = 0;
        for (0..MAX_PROCESSES) |i| {
            if (self.process_pids[i] != 0) {
                // In a real impl, we'd check pgid
                _ = pgid;
                self.kill(self.process_pids[i], sig, sender_pid) catch continue;
                sent += 1;
            }
        }
        return sent;
    }

    /// Deliver pending signals for a process (called on return to userspace)
    pub fn deliverSignals(self: *SignalEngine, pid: u32) ?SigInfo {
        const state = self.findProcess(pid) orelse return null;
        return state.dequeueSignal();
    }
};

// =============================================================================
// Ptrace types and constants
// =============================================================================

pub const PtraceRequest = enum(u32) {
    traceme = 0,
    peek_text = 1,
    peek_data = 2,
    peek_user = 3,
    poke_text = 4,
    poke_data = 5,
    poke_user = 6,
    cont = 7,
    kill = 8,
    single_step = 9,
    getregs = 12,
    setregs = 13,
    getfpregs = 14,
    setfpregs = 15,
    attach = 16,
    detach = 17,
    syscall = 24,
    setoptions = 0x4200,
    geteventmsg = 0x4201,
    getsiginfo = 0x4202,
    setsiginfo = 0x4203,
};

pub const PtraceEvent = enum(u32) {
    none = 0,
    fork = 1,
    vfork = 2,
    clone = 3,
    exec = 4,
    exit = 6,
    stop = 128,
};

pub const PtraceOptions = struct {
    trace_fork: bool = false,
    trace_vfork: bool = false,
    trace_clone: bool = false,
    trace_exec: bool = false,
    trace_exit: bool = false,
    trace_syscall: bool = false,
    exit_kill: bool = false,
};

// =============================================================================
// Register set for ptrace
// =============================================================================

pub const PtraceRegs = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// =============================================================================
// Breakpoint management
// =============================================================================

pub const MAX_BREAKPOINTS: usize = 32;

pub const Breakpoint = struct {
    address: u64,
    original_byte: u8,    // Original byte at breakpoint location
    enabled: bool,
    hw_breakpoint: bool,  // Hardware debug register breakpoint
    hit_count: u32,
    condition: u64,       // Conditional breakpoint expression (0 = unconditional)
};

// =============================================================================
// Ptrace session
// =============================================================================

pub const MAX_PTRACE_SESSIONS: usize = 64;

pub const PtraceSession = struct {
    tracer_pid: u32,
    tracee_pid: u32,
    active: bool,
    stopped: bool,
    single_stepping: bool,
    syscall_tracing: bool,
    options: PtraceOptions,
    last_event: PtraceEvent,
    event_msg: u64,
    stop_signal: u8,
    regs: PtraceRegs,
    breakpoints: [MAX_BREAKPOINTS]Breakpoint,
    bp_count: u32,

    pub fn init(tracer: u32, tracee: u32) PtraceSession {
        var session: PtraceSession = undefined;
        session.tracer_pid = tracer;
        session.tracee_pid = tracee;
        session.active = true;
        session.stopped = false;
        session.single_stepping = false;
        session.syscall_tracing = false;
        session.options = PtraceOptions{};
        session.last_event = .none;
        session.event_msg = 0;
        session.stop_signal = 0;
        session.regs = @import("std").mem.zeroes(PtraceRegs);
        session.bp_count = 0;
        for (0..MAX_BREAKPOINTS) |i| {
            session.breakpoints[i] = .{
                .address = 0,
                .original_byte = 0,
                .enabled = false,
                .hw_breakpoint = false,
                .hit_count = 0,
                .condition = 0,
            };
        }
        return session;
    }

    /// Add a software breakpoint at address
    pub fn addBreakpoint(self: *PtraceSession, address: u64, original_byte: u8) bool {
        if (self.bp_count >= MAX_BREAKPOINTS) return false;
        for (0..MAX_BREAKPOINTS) |i| {
            if (!self.breakpoints[i].enabled) {
                self.breakpoints[i] = .{
                    .address = address,
                    .original_byte = original_byte,
                    .enabled = true,
                    .hw_breakpoint = false,
                    .hit_count = 0,
                    .condition = 0,
                };
                self.bp_count += 1;
                return true;
            }
        }
        return false;
    }

    /// Remove breakpoint at address
    pub fn removeBreakpoint(self: *PtraceSession, address: u64) ?u8 {
        for (0..MAX_BREAKPOINTS) |i| {
            if (self.breakpoints[i].enabled and self.breakpoints[i].address == address) {
                const original = self.breakpoints[i].original_byte;
                self.breakpoints[i].enabled = false;
                self.bp_count -= 1;
                return original;
            }
        }
        return null;
    }

    /// Check if address has a breakpoint
    pub fn hasBreakpoint(self: *const PtraceSession, address: u64) bool {
        for (0..MAX_BREAKPOINTS) |i| {
            if (self.breakpoints[i].enabled and self.breakpoints[i].address == address) {
                return true;
            }
        }
        return false;
    }
};

// =============================================================================
// Ptrace engine
// =============================================================================

pub const PtraceError = error{
    AlreadyTraced,
    NotTraced,
    NotStopped,
    PermissionDenied,
    InvalidAddress,
    SessionFull,
};

pub const PtraceEngine = struct {
    sessions: [MAX_PTRACE_SESSIONS]PtraceSession,
    count: u32,

    pub fn init() PtraceEngine {
        var engine: PtraceEngine = undefined;
        engine.count = 0;
        for (0..MAX_PTRACE_SESSIONS) |i| {
            engine.sessions[i].active = false;
        }
        return engine;
    }

    /// PTRACE_ATTACH: Attach tracer to tracee
    pub fn attach(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32) PtraceError!void {
        // Check not already traced
        for (0..MAX_PTRACE_SESSIONS) |i| {
            if (self.sessions[i].active and self.sessions[i].tracee_pid == tracee_pid) {
                return PtraceError.AlreadyTraced;
            }
        }

        // Find free slot
        for (0..MAX_PTRACE_SESSIONS) |i| {
            if (!self.sessions[i].active) {
                self.sessions[i] = PtraceSession.init(tracer_pid, tracee_pid);
                self.count += 1;
                return;
            }
        }

        return PtraceError.SessionFull;
    }

    /// PTRACE_DETACH: Detach from tracee
    pub fn detach(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32) PtraceError!void {
        const session = self.findSession(tracer_pid, tracee_pid) orelse return PtraceError.NotTraced;

        // Remove all breakpoints (in real impl, restore original bytes)
        for (0..MAX_BREAKPOINTS) |i| {
            session.breakpoints[i].enabled = false;
        }
        session.active = false;
        self.count -= 1;
    }

    /// PTRACE_CONT: Continue execution
    pub fn cont(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32, signal: u8) PtraceError!void {
        const session = self.findSession(tracer_pid, tracee_pid) orelse return PtraceError.NotTraced;
        if (!session.stopped) return PtraceError.NotStopped;

        session.stopped = false;
        session.single_stepping = false;
        session.stop_signal = signal;
    }

    /// PTRACE_SINGLESTEP: Execute one instruction
    pub fn singleStep(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32) PtraceError!void {
        const session = self.findSession(tracer_pid, tracee_pid) orelse return PtraceError.NotTraced;
        if (!session.stopped) return PtraceError.NotStopped;

        session.stopped = false;
        session.single_stepping = true;
    }

    /// PTRACE_GETREGS: Get register state
    pub fn getRegs(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32) PtraceError!PtraceRegs {
        const session = self.findSession(tracer_pid, tracee_pid) orelse return PtraceError.NotTraced;
        if (!session.stopped) return PtraceError.NotStopped;
        return session.regs;
    }

    /// PTRACE_SETREGS: Set register state
    pub fn setRegs(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32, regs: PtraceRegs) PtraceError!void {
        const session = self.findSession(tracer_pid, tracee_pid) orelse return PtraceError.NotTraced;
        if (!session.stopped) return PtraceError.NotStopped;
        session.regs = regs;
    }

    /// PTRACE_SETOPTIONS: Set tracing options
    pub fn setOptions(self: *PtraceEngine, tracer_pid: u32, tracee_pid: u32, opts: PtraceOptions) PtraceError!void {
        const session = self.findSession(tracer_pid, tracee_pid) orelse return PtraceError.NotTraced;
        session.options = opts;
    }

    /// Handle tracee stop (from breakpoint, signal, or single step)
    pub fn reportStop(self: *PtraceEngine, tracee_pid: u32, signal: u8, regs: PtraceRegs) void {
        for (0..MAX_PTRACE_SESSIONS) |i| {
            if (self.sessions[i].active and self.sessions[i].tracee_pid == tracee_pid) {
                self.sessions[i].stopped = true;
                self.sessions[i].stop_signal = signal;
                self.sessions[i].regs = regs;

                // Check if it hit a breakpoint
                for (0..MAX_BREAKPOINTS) |b| {
                    if (self.sessions[i].breakpoints[b].enabled and
                        self.sessions[i].breakpoints[b].address == regs.rip - 1)
                    {
                        self.sessions[i].breakpoints[b].hit_count += 1;
                        self.sessions[i].last_event = .stop;
                        return;
                    }
                }
                return;
            }
        }
    }

    /// Handle tracee event (fork, exec, exit)
    pub fn reportEvent(self: *PtraceEngine, tracee_pid: u32, event: PtraceEvent, msg: u64) void {
        for (0..MAX_PTRACE_SESSIONS) |i| {
            if (self.sessions[i].active and self.sessions[i].tracee_pid == tracee_pid) {
                self.sessions[i].last_event = event;
                self.sessions[i].event_msg = msg;
                self.sessions[i].stopped = true;
                return;
            }
        }
    }

    /// Check if a process is being traced
    pub fn isTraced(self: *const PtraceEngine, pid: u32) bool {
        for (0..MAX_PTRACE_SESSIONS) |i| {
            if (self.sessions[i].active and self.sessions[i].tracee_pid == pid) {
                return true;
            }
        }
        return false;
    }

    fn findSession(self: *PtraceEngine, tracer: u32, tracee: u32) ?*PtraceSession {
        for (0..MAX_PTRACE_SESSIONS) |i| {
            if (self.sessions[i].active and
                self.sessions[i].tracer_pid == tracer and
                self.sessions[i].tracee_pid == tracee)
            {
                return &self.sessions[i];
            }
        }
        return null;
    }
};

// =============================================================================
// Core dump metadata
// =============================================================================

pub const CoreDumpInfo = struct {
    pid: u32,
    signal: u8,
    regs: PtraceRegs,
    timestamp_ns: u64,
    file_size: u64,
    elfcore_valid: bool,

    pub fn format(self: *const CoreDumpInfo, buf: []u8) usize {
        // Write minimal info header
        const header = "CORE";
        if (buf.len < header.len + 4) return 0;
        @memcpy(buf[0..header.len], header);
        buf[header.len] = self.signal;
        const pid_bytes = @as([4]u8, @bitCast(self.pid));
        @memcpy(buf[header.len + 1 ..][0..4], &pid_bytes);
        return header.len + 5;
    }
};

// =============================================================================
// Global instances
// =============================================================================

var signal_engine: SignalEngine = SignalEngine.init();
var ptrace_engine: PtraceEngine = PtraceEngine.init();

pub fn getSignalEngine() *SignalEngine {
    return &signal_engine;
}

pub fn getPtraceEngine() *PtraceEngine {
    return &ptrace_engine;
}
