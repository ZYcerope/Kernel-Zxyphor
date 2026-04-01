// =============================================================================
// Kernel Zxyphor - Signal Handling
// =============================================================================
// POSIX-compatible signal delivery mechanism. Signals are asynchronous
// notifications sent to processes to indicate events like:
//   - SIGKILL (9):  Force-kill a process
//   - SIGTERM (15): Request termination
//   - SIGSEGV (11): Segmentation fault
//   - SIGINT (2):   Interrupt from keyboard (Ctrl+C)
//   - SIGCHLD (17): Child process stopped or terminated
//   - SIGPIPE (13): Write to pipe with no readers
//
// Signal disposition:
//   - Default: terminate, ignore, stop, or continue
//   - Custom handler: user-space function called on signal delivery
//   - Ignored: signal is discarded
//
// Signals are queued per-process and delivered when the process returns
// to user mode (checked in the syscall return path).
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Signal numbers (POSIX-compatible)
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

pub const MAX_SIGNAL: u8 = 64;

// =============================================================================
// Signal actions/dispositions
// =============================================================================
pub const SigAction = enum {
    default,
    ignore,
    handler,
    terminate,
    stop,
    core_dump,
};

// Default actions for each signal
const default_actions = [32]SigAction{
    .terminate, // 0: unused
    .terminate, // 1: SIGHUP
    .terminate, // 2: SIGINT
    .core_dump, // 3: SIGQUIT
    .core_dump, // 4: SIGILL
    .core_dump, // 5: SIGTRAP
    .core_dump, // 6: SIGABRT
    .core_dump, // 7: SIGBUS
    .core_dump, // 8: SIGFPE
    .terminate, // 9: SIGKILL (cannot be caught)
    .terminate, // 10: SIGUSR1
    .core_dump, // 11: SIGSEGV
    .terminate, // 12: SIGUSR2
    .terminate, // 13: SIGPIPE
    .terminate, // 14: SIGALRM
    .terminate, // 15: SIGTERM
    .terminate, // 16: SIGSTKFLT
    .ignore, //    17: SIGCHLD
    .ignore, //    18: SIGCONT (but also resumes stopped process)
    .stop, //      19: SIGSTOP (cannot be caught)
    .stop, //      20: SIGTSTP
    .stop, //      21: SIGTTIN
    .stop, //      22: SIGTTOU
    .ignore, //    23: SIGURG
    .core_dump, // 24: SIGXCPU
    .core_dump, // 25: SIGXFSZ
    .terminate, // 26: SIGVTALRM
    .terminate, // 27: SIGPROF
    .ignore, //    28: SIGWINCH
    .terminate, // 29: SIGIO
    .terminate, // 30: SIGPWR
    .core_dump, // 31: SIGSYS
};

// =============================================================================
// Per-process signal state
// =============================================================================
pub const SignalState = struct {
    // Bitmask of pending signals
    pending: u64 = 0,

    // Bitmask of blocked signals
    blocked: u64 = 0,

    // Signal handlers (null = use default action)
    handlers: [MAX_SIGNAL]?u64 = [_]?u64{null} ** MAX_SIGNAL,

    // Signal action overrides
    actions: [MAX_SIGNAL]SigAction = [_]SigAction{.default} ** MAX_SIGNAL,

    /// Send a signal to this process
    pub fn send(self: *SignalState, signum: u8) void {
        if (signum == 0 or signum >= MAX_SIGNAL) return;
        self.pending |= @as(u64, 1) << @intCast(signum);
    }

    /// Check if any deliverable signals are pending
    pub fn hasPending(self: *const SignalState) bool {
        // Deliverable = pending & ~blocked
        return (self.pending & ~self.blocked) != 0;
    }

    /// Get the next deliverable signal number (0 if none)
    pub fn nextPending(self: *const SignalState) u8 {
        const deliverable = self.pending & ~self.blocked;
        if (deliverable == 0) return 0;

        // Find lowest set bit
        var i: u8 = 1;
        while (i < MAX_SIGNAL) : (i += 1) {
            if ((deliverable & (@as(u64, 1) << @intCast(i))) != 0) return i;
        }
        return 0;
    }

    /// Clear a pending signal
    pub fn clearPending(self: *SignalState, signum: u8) void {
        if (signum >= MAX_SIGNAL) return;
        self.pending &= ~(@as(u64, 1) << @intCast(signum));
    }

    /// Block a signal
    pub fn block(self: *SignalState, signum: u8) void {
        if (signum >= MAX_SIGNAL) return;
        // SIGKILL and SIGSTOP cannot be blocked
        if (signum == SIGKILL or signum == SIGSTOP) return;
        self.blocked |= @as(u64, 1) << @intCast(signum);
    }

    /// Unblock a signal
    pub fn unblock(self: *SignalState, signum: u8) void {
        if (signum >= MAX_SIGNAL) return;
        self.blocked &= ~(@as(u64, 1) << @intCast(signum));
    }

    /// Set a signal handler
    pub fn setHandler(self: *SignalState, signum: u8, handler_addr: u64) bool {
        if (signum >= MAX_SIGNAL) return false;
        // SIGKILL and SIGSTOP cannot have custom handlers
        if (signum == SIGKILL or signum == SIGSTOP) return false;

        if (handler_addr == 0) {
            self.actions[signum] = .default;
            self.handlers[signum] = null;
        } else if (handler_addr == 1) {
            self.actions[signum] = .ignore;
            self.handlers[signum] = null;
        } else {
            self.actions[signum] = .handler;
            self.handlers[signum] = handler_addr;
        }
        return true;
    }

    /// Get the effective action for a signal
    pub fn getAction(self: *const SignalState, signum: u8) SigAction {
        if (signum >= MAX_SIGNAL) return .terminate;

        if (self.actions[signum] != .default) {
            return self.actions[signum];
        }

        if (signum < default_actions.len) {
            return default_actions[signum];
        }

        return .terminate;
    }
};

// =============================================================================
// Initialize signal subsystem
// =============================================================================
pub fn initialize() void {
    main.klog(.info, "signal: initialized ({d} signals)", .{MAX_SIGNAL});
}

// =============================================================================
// Send a signal to a process by PID
// =============================================================================
pub fn sendSignal(pid: u32, signum: u8) bool {
    if (main.process.findByPid(pid)) |proc| {
        proc.signals.send(signum);

        // SIGCONT: also resume if stopped
        if (signum == SIGCONT) {
            if (proc.state == .blocked) {
                main.process.unblockProcess(proc);
            }
        }

        return true;
    }
    return false;
}

/// Send a signal to the current process
pub fn sendToSelf(signum: u8) void {
    if (main.process.getCurrent()) |proc| {
        proc.signals.send(signum);
    }
}

// =============================================================================
// Deliver pending signals (called when returning to user mode)
// =============================================================================
pub fn deliverPendingSignals(proc: *main.process.Process) void {
    while (proc.signals.hasPending()) {
        const signum = proc.signals.nextPending();
        if (signum == 0) break;

        proc.signals.clearPending(signum);

        const action = proc.signals.getAction(signum);
        switch (action) {
            .ignore => continue,
            .terminate => {
                main.klog(.info, "signal: process {d} killed by signal {d}", .{ proc.pid, signum });
                main.process.killProcess(proc);
                return;
            },
            .core_dump => {
                main.klog(.info, "signal: process {d} core dumped (signal {d})", .{ proc.pid, signum });
                main.process.killProcess(proc);
                return;
            },
            .stop => {
                main.process.blockProcess(proc);
                return;
            },
            .handler => {
                // Call user-space signal handler
                if (proc.signals.handlers[signum]) |handler_addr| {
                    deliverToUserHandler(proc, signum, handler_addr);
                    return;
                }
            },
            .default => {
                // Should not reach here (getAction resolves default)
            },
        }
    }
}

/// Set up user-space signal handler delivery
fn deliverToUserHandler(proc: *main.process.Process, signum: u8, handler_addr: u64) void {
    // To deliver a signal to a user-space handler, we need to:
    // 1. Save the current user-space context
    // 2. Set up a signal frame on the user stack
    // 3. Set RIP to the handler address
    // 4. Set RDI to the signal number (first argument)
    //
    // When the handler returns, it should execute sigreturn() which
    // restores the saved context.
    _ = proc;
    _ = signum;
    _ = handler_addr;

    // TODO: implement full signal frame setup
}

/// Get signal name
pub fn signalName(signum: u8) []const u8 {
    return switch (signum) {
        SIGHUP => "SIGHUP",
        SIGINT => "SIGINT",
        SIGQUIT => "SIGQUIT",
        SIGILL => "SIGILL",
        SIGTRAP => "SIGTRAP",
        SIGABRT => "SIGABRT",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGUSR1 => "SIGUSR1",
        SIGSEGV => "SIGSEGV",
        SIGUSR2 => "SIGUSR2",
        SIGPIPE => "SIGPIPE",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        SIGCHLD => "SIGCHLD",
        SIGCONT => "SIGCONT",
        SIGSTOP => "SIGSTOP",
        else => "UNKNOWN",
    };
}
