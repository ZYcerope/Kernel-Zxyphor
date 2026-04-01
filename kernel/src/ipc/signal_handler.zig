// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Signal Delivery & Handling (Zig)
//
// POSIX-compatible signal infrastructure:
// - Standard signals (1-31) + real-time signals (32-64)
// - Signal masks (blocked, pending, caught)
// - Signal actions (SIG_DFL, SIG_IGN, user handler)
// - sigprocmask, sigaction, kill, raise
// - Signal queue with siginfo_t-like metadata
// - Process group signals (killpg)
// - SIGCHLD / wait status
// - Core dump signal classification
// - Signal stack (sigaltstack)
// - Restartable system calls (SA_RESTART)
// - Signal coalescing (standard) vs queuing (real-time)

const std = @import("std");

// ─────────────────── Signal Numbers ─────────────────────────────────

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
pub const MAX_PENDING: usize = 128;
pub const MAX_PROCESSES: usize = 256;

// ─────────────────── Signal Set (bitmask) ───────────────────────────

pub const SigSet = struct {
    bits: u64,

    pub const EMPTY: SigSet = .{ .bits = 0 };
    pub const FULL: SigSet = .{ .bits = 0xFFFFFFFFFFFFFFFF };

    pub fn contains(self: SigSet, sig: u8) bool {
        if (sig < 1 or sig > 64) return false;
        return (self.bits & (@as(u64, 1) << @intCast(sig - 1))) != 0;
    }

    pub fn add(self: *SigSet, sig: u8) void {
        if (sig < 1 or sig > 64) return;
        self.bits |= @as(u64, 1) << @intCast(sig - 1);
    }

    pub fn remove(self: *SigSet, sig: u8) void {
        if (sig < 1 or sig > 64) return;
        self.bits &= ~(@as(u64, 1) << @intCast(sig - 1));
    }

    pub fn union_with(self: SigSet, other: SigSet) SigSet {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn intersect(self: SigSet, other: SigSet) SigSet {
        return .{ .bits = self.bits & other.bits };
    }

    pub fn complement(self: SigSet) SigSet {
        return .{ .bits = ~self.bits };
    }

    pub fn is_empty(self: SigSet) bool {
        return self.bits == 0;
    }

    /// Count set bits
    pub fn count(self: SigSet) u8 {
        var n: u8 = 0;
        var b = self.bits;
        while (b != 0) {
            n += 1;
            b &= b - 1;
        }
        return n;
    }

    /// Get lowest pending signal
    pub fn first_set(self: SigSet) ?u8 {
        if (self.bits == 0) return null;
        var bit: u6 = 0;
        while (bit < 64) : (bit += 1) {
            if ((self.bits & (@as(u64, 1) << bit)) != 0) {
                return bit + 1;
            }
        }
        return null;
    }
};

// ─────────────────── Default Action ─────────────────────────────────

pub const SigDefault = enum(u8) {
    terminate = 0,
    core_dump = 1,
    stop = 2,
    cont = 3,
    ignore = 4,
};

pub fn default_action(sig: u8) SigDefault {
    return switch (sig) {
        SIGHUP, SIGINT, SIGPIPE, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGSTKFLT, SIGIO, SIGPWR, SIGPROF, SIGVTALRM, SIGXCPU, SIGXFSZ => .terminate,
        SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGSYS => .core_dump,
        SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU => .stop,
        SIGCONT => .cont,
        SIGCHLD, SIGURG, SIGWINCH => .ignore,
        else => .terminate,
    };
}

pub fn is_fatal(sig: u8) bool {
    return switch (default_action(sig)) {
        .terminate, .core_dump => true,
        else => false,
    };
}

pub fn generates_core(sig: u8) bool {
    return default_action(sig) == .core_dump;
}

// ─────────────────── Signal Action ──────────────────────────────────

pub const SA_RESTART: u32 = 0x10000000;
pub const SA_NOCLDSTOP: u32 = 0x00000001;
pub const SA_NOCLDWAIT: u32 = 0x00000002;
pub const SA_SIGINFO: u32 = 0x00000004;
pub const SA_ONSTACK: u32 = 0x08000000;
pub const SA_NODEFER: u32 = 0x40000000;
pub const SA_RESETHAND: u32 = 0x80000000;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SigAction = struct {
    handler: u64, // 0=default, 1=ignore, or user handler address
    mask: SigSet, // Additional signals to block during handler
    flags: u32,

    pub fn is_default(self: *const SigAction) bool {
        return self.handler == SIG_DFL;
    }

    pub fn is_ignore(self: *const SigAction) bool {
        return self.handler == SIG_IGN;
    }

    pub fn is_user(self: *const SigAction) bool {
        return self.handler > SIG_IGN;
    }
};

// ─────────────────── Signal Info ────────────────────────────────────

pub const SiCode = enum(i32) {
    si_user = 0, // kill(2)
    si_kernel = 128, // Kernel-generated
    si_queue = -1, // sigqueue(2)
    si_timer = -2, // POSIX timer
    si_mesgq = -3, // POSIX message queue
    si_asyncio = -4, // AIO completion
    si_tkill = -6, // tkill/tgkill
    // SIGCHLD codes
    cld_exited = 1,
    cld_killed = 2,
    cld_dumped = 3,
    cld_trapped = 4,
    cld_stopped = 5,
    cld_continued = 6,
    // SIGSEGV/SIGBUS codes
    segv_maperr = 1,
    segv_accerr = 2,
    bus_adraln = 1,
    bus_adrerr = 2,
    // SIGFPE codes
    fpe_intdiv = 1,
    fpe_intovf = 2,
    fpe_fltdiv = 3,
    fpe_fltovf = 4,
    fpe_fltund = 5,
    fpe_fltres = 6,
    fpe_fltinv = 7,
};

pub const SigInfo = struct {
    signo: u8,
    code: SiCode,
    sender_pid: u32,
    sender_uid: u32,
    // Union-like data depending on signal
    value: u64, // si_value (for RT signals)
    addr: u64, // Fault address (SIGSEGV, SIGBUS)
    status: i32, // Exit status (SIGCHLD)
    band: i32, // SIGIO band event
    timestamp: u64, // Kernel timestamp when signal was generated
};

// ─────────────────── Pending Signal Queue ───────────────────────────

pub const PendingQueue = struct {
    entries: [MAX_PENDING]SigInfo,
    count: u16,
    signal_set: SigSet, // Quick bitmask of what's pending

    pub fn init() PendingQueue {
        var q: PendingQueue = undefined;
        q.count = 0;
        q.signal_set = SigSet.EMPTY;
        return q;
    }

    /// Enqueue a signal. For standard signals, coalesces (ignores duplicates).
    /// For real-time signals (>= SIGRTMIN), queues multiple.
    pub fn enqueue(self: *PendingQueue, info: SigInfo) bool {
        if (info.signo < SIGRTMIN) {
            // Standard signal: coalesce
            if (self.signal_set.contains(info.signo)) {
                return true; // Already pending — coalesced
            }
        }

        if (self.count >= MAX_PENDING) return false;

        self.entries[self.count] = info;
        self.count += 1;
        self.signal_set.add(info.signo);
        return true;
    }

    /// Dequeue highest-priority pending signal not in `blocked`
    pub fn dequeue(self: *PendingQueue, blocked: SigSet) ?SigInfo {
        // Standard signals first (lower numbers = higher priority)
        var best_idx: ?usize = null;
        var best_sig: u8 = 255;

        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const sig = self.entries[i].signo;
            if (!blocked.contains(sig) and sig < best_sig) {
                best_sig = sig;
                best_idx = i;
            }
        }

        if (best_idx) |idx| {
            const info = self.entries[idx];
            // Remove by swapping with last
            self.count -= 1;
            if (idx < self.count) {
                self.entries[idx] = self.entries[self.count];
            }
            // Recalculate signal set
            self.rebuild_set();
            return info;
        }

        return null;
    }

    /// Remove all pending instances of a signal
    pub fn flush_signal(self: *PendingQueue, sig: u8) void {
        var i: usize = 0;
        while (i < self.count) {
            if (self.entries[i].signo == sig) {
                self.count -= 1;
                if (i < self.count) {
                    self.entries[i] = self.entries[self.count];
                }
            } else {
                i += 1;
            }
        }
        self.signal_set.remove(sig);
    }

    fn rebuild_set(self: *PendingQueue) void {
        self.signal_set = SigSet.EMPTY;
        for (0..self.count) |j| {
            self.signal_set.add(self.entries[j].signo);
        }
    }

    pub fn has_pending(self: *const PendingQueue, blocked: SigSet) bool {
        const deliverable = self.signal_set.intersect(blocked.complement());
        return !deliverable.is_empty();
    }
};

// ─────────────────── Signal Alternate Stack ─────────────────────────

pub const SigStack = struct {
    base: u64, // Stack base address
    size: u64, // Stack size
    flags: u32, // SS_DISABLE, SS_ONSTACK
    active: bool,
};

pub const SS_DISABLE: u32 = 1;
pub const SS_ONSTACK: u32 = 2;

// ─────────────────── Process Signal State ───────────────────────────

pub const ProcessSignals = struct {
    pid: u32,
    actions: [MAX_SIGNALS]SigAction,
    blocked: SigSet,
    pending: PendingQueue,
    alt_stack: SigStack,

    // Stats
    signals_received: u64,
    signals_delivered: u64,
    signals_ignored: u64,

    active: bool,

    const Self = @This();

    pub fn init(pid: u32) Self {
        var ps: Self = undefined;
        ps.pid = pid;
        // All actions default
        for (0..MAX_SIGNALS) |i| {
            ps.actions[i] = .{
                .handler = SIG_DFL,
                .mask = SigSet.EMPTY,
                .flags = 0,
            };
        }
        ps.blocked = SigSet.EMPTY;
        ps.pending = PendingQueue.init();
        ps.alt_stack = .{
            .base = 0,
            .size = 0,
            .flags = SS_DISABLE,
            .active = false,
        };
        ps.signals_received = 0;
        ps.signals_delivered = 0;
        ps.signals_ignored = 0;
        ps.active = true;
        return ps;
    }

    /// Set signal action (sigaction)
    pub fn set_action(self: *Self, sig: u8, act: *const SigAction) bool {
        if (sig < 1 or sig > 64) return false;
        // SIGKILL and SIGSTOP cannot be caught or ignored
        if (sig == SIGKILL or sig == SIGSTOP) return false;
        self.actions[sig - 1] = act.*;
        return true;
    }

    /// Get signal action
    pub fn get_action(self: *const Self, sig: u8) ?*const SigAction {
        if (sig < 1 or sig > 64) return null;
        return &self.actions[sig - 1];
    }

    /// Block/unblock signals (sigprocmask)
    pub fn sigprocmask(self: *Self, how: u8, set: SigSet) SigSet {
        const old = self.blocked;
        switch (how) {
            0 => { // SIG_BLOCK
                self.blocked = self.blocked.union_with(set);
            },
            1 => { // SIG_UNBLOCK
                self.blocked.bits &= ~set.bits;
            },
            2 => { // SIG_SETMASK
                self.blocked = set;
            },
            else => {},
        }
        // SIGKILL and SIGSTOP can never be blocked
        self.blocked.remove(SIGKILL);
        self.blocked.remove(SIGSTOP);
        return old;
    }

    /// Send a signal to this process
    pub fn send_signal(self: *Self, sig: u8, info: SigInfo) bool {
        if (sig < 1 or sig > 64) return false;

        self.signals_received += 1;

        const act = &self.actions[sig - 1];

        // Check if signal is ignored
        if (act.is_ignore()) {
            self.signals_ignored += 1;
            return true;
        }

        // Check default action = ignore
        if (act.is_default() and default_action(sig) == .ignore) {
            self.signals_ignored += 1;
            return true;
        }

        return self.pending.enqueue(info);
    }

    /// Try to deliver next pending signal. Returns signal info if delivered.
    pub fn deliver_next(self: *Self) ?SigInfo {
        const info = self.pending.dequeue(self.blocked) orelse return null;
        self.signals_delivered += 1;
        return info;
    }

    /// Check if there are deliverable signals
    pub fn has_pending_signals(self: *const Self) bool {
        return self.pending.has_pending(self.blocked);
    }
};

// ─────────────────── Signal Manager ─────────────────────────────────

pub const SignalManager = struct {
    processes: [MAX_PROCESSES]ProcessSignals,
    process_count: u16,

    total_signals_sent: u64,
    total_signals_delivered: u64,

    const Self = @This();

    pub fn init() Self {
        var mgr: Self = undefined;
        for (0..MAX_PROCESSES) |i| {
            mgr.processes[i].active = false;
        }
        mgr.process_count = 0;
        mgr.total_signals_sent = 0;
        mgr.total_signals_delivered = 0;
        return mgr;
    }

    /// Register a process for signal handling
    pub fn register_process(self: *Self, pid: u32) bool {
        for (0..MAX_PROCESSES) |i| {
            if (!self.processes[i].active) {
                self.processes[i] = ProcessSignals.init(pid);
                self.process_count += 1;
                return true;
            }
        }
        return false;
    }

    /// Unregister a process
    pub fn unregister_process(self: *Self, pid: u32) void {
        for (0..MAX_PROCESSES) |i| {
            if (self.processes[i].active and self.processes[i].pid == pid) {
                self.processes[i].active = false;
                self.process_count -= 1;
                return;
            }
        }
    }

    fn find_process(self: *Self, pid: u32) ?*ProcessSignals {
        for (0..MAX_PROCESSES) |i| {
            if (self.processes[i].active and self.processes[i].pid == pid) {
                return &self.processes[i];
            }
        }
        return null;
    }

    /// Send signal to a specific process (kill)
    pub fn kill(self: *Self, target_pid: u32, sig: u8, sender_pid: u32, sender_uid: u32) bool {
        const proc = self.find_process(target_pid) orelse return false;

        const info = SigInfo{
            .signo = sig,
            .code = .si_user,
            .sender_pid = sender_pid,
            .sender_uid = sender_uid,
            .value = 0,
            .addr = 0,
            .status = 0,
            .band = 0,
            .timestamp = 0, // Would be filled by clock
        };

        self.total_signals_sent += 1;
        return proc.send_signal(sig, info);
    }

    /// Send signal to a process group (killpg)
    pub fn killpg(self: *Self, _pgrp: u32, sig: u8, sender_pid: u32, sender_uid: u32) u32 {
        var count: u32 = 0;
        for (0..MAX_PROCESSES) |i| {
            if (self.processes[i].active) {
                // In a real kernel, we'd check process group membership
                const info = SigInfo{
                    .signo = sig,
                    .code = .si_user,
                    .sender_pid = sender_pid,
                    .sender_uid = sender_uid,
                    .value = 0,
                    .addr = 0,
                    .status = 0,
                    .band = 0,
                    .timestamp = 0,
                };
                if (self.processes[i].send_signal(sig, info)) {
                    count += 1;
                }
            }
        }
        self.total_signals_sent += count;
        return count;
    }

    /// Generate a kernel signal (e.g. SIGSEGV from page fault)
    pub fn force_signal(self: *Self, pid: u32, sig: u8, code: SiCode, addr: u64) bool {
        const proc = self.find_process(pid) orelse return false;

        const info = SigInfo{
            .signo = sig,
            .code = code,
            .sender_pid = 0, // Kernel
            .sender_uid = 0,
            .value = 0,
            .addr = addr,
            .status = 0,
            .band = 0,
            .timestamp = 0,
        };

        // Force signals bypass blocking (for fatal signals)
        if (is_fatal(sig)) {
            proc.blocked.remove(sig);
            // Reset handler to default for uncatchable situations
            if (sig == SIGKILL) {
                proc.actions[sig - 1].handler = SIG_DFL;
            }
        }

        self.total_signals_sent += 1;
        return proc.send_signal(sig, info);
    }

    /// Set signal action for a process
    pub fn sigaction(self: *Self, pid: u32, sig: u8, act: *const SigAction) bool {
        const proc = self.find_process(pid) orelse return false;
        return proc.set_action(sig, act);
    }

    /// Deliver pending signals for a process (called on return to userspace)
    pub fn do_signal(self: *Self, pid: u32) ?SigInfo {
        const proc = self.find_process(pid) orelse return null;
        if (proc.deliver_next()) |info| {
            self.total_signals_delivered += 1;
            return info;
        }
        return null;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var g_signal_mgr: SignalManager = undefined;
var g_signal_initialized: bool = false;

fn sig_mgr() *SignalManager {
    return &g_signal_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_signal_init() void {
    g_signal_mgr = SignalManager.init();
    g_signal_initialized = true;
}

export fn zxy_signal_register(pid: u32) bool {
    if (!g_signal_initialized) return false;
    return sig_mgr().register_process(pid);
}

export fn zxy_signal_unregister(pid: u32) void {
    if (g_signal_initialized) sig_mgr().unregister_process(pid);
}

export fn zxy_signal_kill(target: u32, sig: u8, sender: u32, uid: u32) bool {
    if (!g_signal_initialized) return false;
    return sig_mgr().kill(target, sig, sender, uid);
}

export fn zxy_signal_force(pid: u32, sig: u8, addr: u64) bool {
    if (!g_signal_initialized) return false;
    return sig_mgr().force_signal(pid, sig, .si_kernel, addr);
}

export fn zxy_signal_deliver(pid: u32) u8 {
    if (!g_signal_initialized) return 0;
    if (sig_mgr().do_signal(pid)) |info| return info.signo;
    return 0;
}

export fn zxy_signal_total_sent() u64 {
    if (!g_signal_initialized) return 0;
    return sig_mgr().total_signals_sent;
}

export fn zxy_signal_total_delivered() u64 {
    if (!g_signal_initialized) return 0;
    return sig_mgr().total_signals_delivered;
}

export fn zxy_signal_process_count() u16 {
    if (!g_signal_initialized) return 0;
    return sig_mgr().process_count;
}
