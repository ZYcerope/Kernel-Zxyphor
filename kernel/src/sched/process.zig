// =============================================================================
// Kernel Zxyphor - Process Management
// =============================================================================
// Manages process lifecycle: creation, destruction, state transitions.
// Each process has its own virtual address space, file descriptor table,
// signal handlers, and resource limits.
//
// Process states:
//   CREATED  → READY → RUNNING → { READY | BLOCKED | ZOMBIE }
//   BLOCKED  → READY (when unblocked)
//   RUNNING  → ZOMBIE (on exit)
// =============================================================================

const main = @import("../main.zig");
const paging = @import("../arch/x86_64/paging.zig");

// =============================================================================
// Process ID type and limits
// =============================================================================
pub const Pid = u32;
pub const MAX_PROCESSES = 4096;
pub const MAX_FDS = 256; // File descriptors per process
pub const MAX_THREADS = 64; // Threads per process

// =============================================================================
// Process state machine
// =============================================================================
pub const ProcessState = enum {
    created, // Process structure allocated but not yet scheduled
    ready, // Ready to run (in the scheduler's queue)
    running, // Currently executing on a CPU
    blocked, // Waiting for an event (I/O, mutex, etc.)
    zombie, // Exited but not yet waited on by parent
    dead, // Resources fully reclaimed
};

// =============================================================================
// Exit reason — how/why a process terminated
// =============================================================================
pub const ExitReason = enum {
    normal, // Exited normally via exit()
    segfault, // Segmentation fault
    exception, // Unhandled CPU exception
    killed, // Killed by a signal
    abort, // Called abort()
};

// =============================================================================
// Process Control Block (PCB) — the kernel's representation of a process
// =============================================================================
pub const Process = struct {
    // Identity
    pid: Pid,
    parent_pid: Pid,
    name: [64]u8,
    name_len: usize,

    // State
    state: ProcessState,
    exit_code: i32,
    exit_reason: ExitReason,

    // Memory
    address_space: main.vmm.AddressSpace,
    heap_break: u64, // Current program break (for brk/sbrk)

    // Threads
    threads: [MAX_THREADS]?*main.thread.Thread,
    thread_count: u32,
    main_thread: ?*main.thread.Thread,

    // File descriptors
    fd_table: [MAX_FDS]?FileDescriptor,
    fd_count: u32,

    // Process hierarchy
    children: [64]Pid, // PIDs of child processes
    child_count: u32,

    // Scheduling
    priority: i8, // Nice value (-20 to 19)
    cpu_time_us: u64, // Total CPU time in microseconds
    start_time: u64, // Creation timestamp (ticks)
    time_slice_remaining: u32, // Remaining time slice in ticks

    // Security
    uid: u32, // User ID
    gid: u32, // Group ID
    euid: u32, // Effective user ID
    egid: u32, // Effective group ID
    capabilities: main.capabilities.CapabilitySet,

    // Signal handling
    signal_mask: u64, // Blocked signals bitmask
    pending_signals: u64, // Pending signals bitmask
    signal_handlers: [32]SignalHandler,

    // Current working directory
    cwd: [256]u8,
    cwd_len: usize,

    // Resource limits
    max_memory: u64, // Maximum virtual memory (bytes)
    max_files: u32, // Maximum open files
    max_cpu_time: u64, // Maximum CPU time (seconds, 0=unlimited)
};

pub const FileDescriptor = struct {
    inode: ?*anyopaque, // VFS inode reference
    offset: u64, // Current read/write position
    flags: u32, // O_RDONLY, O_WRONLY, O_RDWR, etc.
    ref_count: u32, // Reference count (for dup/fork)
};

pub const SignalHandler = union {
    default: void,
    ignore: void,
    handler: *const fn (u32) void,
};

// =============================================================================
// Process table
// =============================================================================
var process_table: [MAX_PROCESSES]?Process = [_]?Process{null} ** MAX_PROCESSES;
var next_pid: Pid = 0;
var process_count: u32 = 0;

var lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Current running process (per-CPU; for now single CPU)
// =============================================================================
var current_process: ?*Process = null;

// =============================================================================
// Create a new kernel process (runs in kernel mode / ring 0)
// =============================================================================
pub fn createKernelProcess(name: []const u8, entry: *const fn () callconv(.C) noreturn) !*Process {
    lock.acquire();
    defer lock.release();

    const pid = allocPid() orelse return error.TooManyProcesses;
    var proc = &(process_table[pid] orelse unreachable);

    // Initialize the process structure
    proc.pid = pid;
    proc.parent_pid = if (current_process) |p| p.pid else 0;
    proc.state = .created;
    proc.exit_code = 0;
    proc.exit_reason = .normal;
    proc.priority = 0;
    proc.cpu_time_us = 0;
    proc.start_time = main.pit.getTicks();
    proc.time_slice_remaining = 10; // 10ms default time slice
    proc.uid = 0; // Kernel processes run as root
    proc.gid = 0;
    proc.euid = 0;
    proc.egid = 0;
    proc.capabilities = main.capabilities.CapabilitySet.all();
    proc.signal_mask = 0;
    proc.pending_signals = 0;
    proc.heap_break = main.vmm.USER_HEAP_START;
    proc.fd_count = 0;
    proc.child_count = 0;
    proc.thread_count = 0;
    proc.max_memory = 0; // Unlimited for kernel processes
    proc.max_files = MAX_FDS;
    proc.max_cpu_time = 0;

    // Set name
    const copy_len = @min(name.len, proc.name.len);
    @memcpy(proc.name[0..copy_len], name[0..copy_len]);
    proc.name_len = copy_len;

    // Set working directory to "/"
    proc.cwd[0] = '/';
    proc.cwd_len = 1;

    // Initialize FD table
    for (&proc.fd_table) |*fd| {
        fd.* = null;
    }

    // Initialize signal handlers to default
    for (&proc.signal_handlers) |*handler| {
        handler.* = SignalHandler{ .default = {} };
    }

    // Initialize children array
    @memset(&proc.children, 0);

    // Use the kernel's address space
    proc.address_space = main.vmm.AddressSpace.init(main.vmm.getKernelPml4());

    // Create the main thread for this process
    const thread_result = main.thread.createKernelThread(proc, entry) catch return error.ThreadCreationFailed;
    proc.main_thread = thread_result;
    proc.threads[0] = thread_result;
    proc.thread_count = 1;

    // Mark as ready for scheduling
    proc.state = .ready;
    process_count += 1;

    main.klog(.info, "Process: Created kernel process '{s}' (PID {d})", .{
        proc.name[0..proc.name_len],
        pid,
    });

    return proc;
}

// =============================================================================
// Create a user process (future: load ELF binary)
// =============================================================================
pub fn createUserProcess(name: []const u8, parent: *Process) !*Process {
    lock.acquire();
    defer lock.release();

    const pid = allocPid() orelse return error.TooManyProcesses;
    var proc = &(process_table[pid] orelse unreachable);

    proc.pid = pid;
    proc.parent_pid = parent.pid;
    proc.state = .created;
    proc.exit_code = 0;
    proc.exit_reason = .normal;
    proc.priority = parent.priority;
    proc.cpu_time_us = 0;
    proc.start_time = main.pit.getTicks();
    proc.time_slice_remaining = 10;
    proc.uid = parent.uid;
    proc.gid = parent.gid;
    proc.euid = parent.euid;
    proc.egid = parent.egid;
    proc.capabilities = main.capabilities.CapabilitySet.none();
    proc.signal_mask = 0;
    proc.pending_signals = 0;
    proc.heap_break = main.vmm.USER_HEAP_START;
    proc.fd_count = 0;
    proc.child_count = 0;
    proc.thread_count = 0;
    proc.max_memory = 256 * 1024 * 1024; // 256MB default
    proc.max_files = MAX_FDS;
    proc.max_cpu_time = 0;

    // Copy name
    const copy_len = @min(name.len, proc.name.len);
    @memcpy(proc.name[0..copy_len], name[0..copy_len]);
    proc.name_len = copy_len;

    // Copy working directory from parent
    @memcpy(proc.cwd[0..parent.cwd_len], parent.cwd[0..parent.cwd_len]);
    proc.cwd_len = parent.cwd_len;

    // Create new address space
    proc.address_space = main.vmm.createAddressSpace() orelse return error.OutOfMemory;

    // Initialize FD table (inherit stdin/stdout/stderr from parent)
    for (&proc.fd_table, 0..) |*fd, i| {
        if (i < 3 and parent.fd_table[i] != null) {
            fd.* = parent.fd_table[i];
            if (fd.*) |*f| {
                f.ref_count += 1;
            }
        } else {
            fd.* = null;
        }
    }

    // Add to parent's children
    if (parent.child_count < parent.children.len) {
        parent.children[parent.child_count] = pid;
        parent.child_count += 1;
    }

    process_count += 1;
    return proc;
}

// =============================================================================
// Process state transitions
// =============================================================================

/// Terminate the currently running process
pub fn killCurrent(reason: ExitReason) void {
    if (current_process) |proc| {
        proc.state = .zombie;
        proc.exit_reason = reason;
        proc.exit_code = switch (reason) {
            .normal => 0,
            .segfault => -11,
            .exception => -6,
            .killed => -9,
            .abort => -6,
        };

        main.klog(.info, "Process: PID {d} '{s}' terminated ({s})", .{
            proc.pid,
            proc.name[0..proc.name_len],
            @tagName(reason),
        });

        // Notify parent (send SIGCHLD)
        if (getProcess(proc.parent_pid)) |parent| {
            parent.pending_signals |= (1 << 17); // SIGCHLD
        }

        main.scheduler.yield();
    }
}

/// Exit the current process normally
pub fn exitProcess(code: i32) void {
    if (current_process) |proc| {
        proc.exit_code = code;
        killCurrent(.normal);
    }
}

/// Block a process (waiting for I/O, mutex, etc.)
pub fn blockProcess(proc: *Process) void {
    proc.state = .blocked;
}

/// Unblock a process (wake it up)
pub fn unblockProcess(proc: *Process) void {
    if (proc.state == .blocked) {
        proc.state = .ready;
        main.scheduler.addToRunQueue(proc);
    }
}

// =============================================================================
// Process lookup
// =============================================================================

/// Get a process by PID
pub fn getProcess(pid: Pid) ?*Process {
    if (pid >= MAX_PROCESSES) return null;
    if (process_table[pid]) |*proc| {
        return proc;
    }
    return null;
}

/// Get the currently running process
pub fn getCurrent() ?*Process {
    return current_process;
}

/// Set the currently running process (called by scheduler)
pub fn setCurrent(proc: ?*Process) void {
    current_process = proc;
}

// =============================================================================
// Process listing (for the 'ps' command)
// =============================================================================
pub fn listProcesses(w: anytype) void {
    for (process_table, 0..) |maybe_proc, i| {
        if (maybe_proc) |proc| {
            _ = i;
            w.print("  {d:<4} {s:<8} {s}\n", .{
                proc.pid,
                @tagName(proc.state),
                proc.name[0..proc.name_len],
            }) catch {};
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================
fn allocPid() ?Pid {
    var checked: u32 = 0;
    while (checked < MAX_PROCESSES) : (checked += 1) {
        if (process_table[next_pid] == null) {
            const pid = next_pid;
            // Initialize the slot
            process_table[pid] = Process{
                .pid = pid,
                .parent_pid = 0,
                .name = [_]u8{0} ** 64,
                .name_len = 0,
                .state = .created,
                .exit_code = 0,
                .exit_reason = .normal,
                .address_space = undefined,
                .heap_break = 0,
                .threads = [_]?*main.thread.Thread{null} ** MAX_THREADS,
                .thread_count = 0,
                .main_thread = null,
                .fd_table = [_]?FileDescriptor{null} ** MAX_FDS,
                .fd_count = 0,
                .children = [_]Pid{0} ** 64,
                .child_count = 0,
                .priority = 0,
                .cpu_time_us = 0,
                .start_time = 0,
                .time_slice_remaining = 0,
                .uid = 0,
                .gid = 0,
                .euid = 0,
                .egid = 0,
                .capabilities = main.capabilities.CapabilitySet.none(),
                .signal_mask = 0,
                .pending_signals = 0,
                .signal_handlers = undefined,
                .cwd = [_]u8{0} ** 256,
                .cwd_len = 0,
                .max_memory = 0,
                .max_files = 0,
                .max_cpu_time = 0,
            };
            next_pid = (next_pid + 1) % MAX_PROCESSES;
            return pid;
        }
        next_pid = (next_pid + 1) % MAX_PROCESSES;
    }
    return null;
}

/// Get total process count
pub fn getProcessCount() u32 {
    return process_count;
}
