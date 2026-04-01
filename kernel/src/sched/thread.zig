// =============================================================================
// Kernel Zxyphor - Thread Management
// =============================================================================
// Threads are the schedulable units in Zxyphor. Each process has at least
// one thread (the main thread). Threads within a process share the same
// address space but have their own stack, register state, and TLS area.
//
// Thread model:
//   - 1:1 threading (one kernel thread per user thread)
//   - Preemptive scheduling with voluntary yield
//   - Per-thread kernel stack (for syscall/interrupt handling)
// =============================================================================

const main = @import("../main.zig");
const paging = @import("../arch/x86_64/paging.zig");

// =============================================================================
// Thread ID
// =============================================================================
pub const Tid = u32;
pub const MAX_THREADS = 8192;

// =============================================================================
// Thread states
// =============================================================================
pub const ThreadState = enum {
    created,
    ready,
    running,
    blocked,
    sleeping,
    dead,
};

// =============================================================================
// Thread priorities
// =============================================================================
pub const MIN_PRIORITY: i8 = -20;
pub const MAX_PRIORITY: i8 = 19;
pub const DEFAULT_PRIORITY: i8 = 0;

// =============================================================================
// Stack sizes
// =============================================================================
const KERNEL_STACK_SIZE: usize = 16384; // 16 KB kernel stack per thread
const USER_STACK_SIZE: usize = 2 * 1024 * 1024; // 2 MB user stack default

// =============================================================================
// CPU register context — saved/restored during context switch
// =============================================================================
pub const CpuContext = extern struct {
    // Callee-saved registers (preserved across function calls)
    r15: u64 = 0,
    r14: u64 = 0,
    r13: u64 = 0,
    r12: u64 = 0,
    rbp: u64 = 0,
    rbx: u64 = 0,

    // Instruction pointer (set to entry point for new threads)
    rip: u64 = 0,

    // Stack pointer
    rsp: u64 = 0,

    // Segment selectors (for user/kernel transition)
    cs: u64 = 0,
    ss: u64 = 0,

    // Flags register
    rflags: u64 = 0x202, // IF=1 (interrupts enabled)

    // FPU/SSE state (saved separately via FXSAVE)
    fpu_state: [512]u8 align(16) = [_]u8{0} ** 512,
    fpu_initialized: bool = false,
};

// =============================================================================
// Thread Control Block (TCB)
// =============================================================================
pub const Thread = struct {
    tid: Tid,
    owner: *main.process.Process, // Process this thread belongs to
    state: ThreadState,

    // CPU context (register state)
    context: CpuContext,

    // Kernel stack (for handling interrupts/syscalls while in user mode)
    kernel_stack_base: u64,
    kernel_stack_top: u64,

    // User stack (in the process's virtual address space)
    user_stack_base: u64,
    user_stack_top: u64,

    // Scheduling parameters
    priority: i8,
    time_slice: u32, // Time slice in ticks
    time_used: u32, // Ticks used in current quantum
    total_cpu_time: u64, // Total ticks consumed

    // Virtual runtime for CFS
    vruntime: u64,

    // Blocking
    wait_channel: u64, // What this thread is waiting on
    wake_time: u64, // Tick count to wake up (for sleep)

    // Thread-local storage
    tls_base: u64,

    // Linked list for scheduler queues
    sched_next: ?*Thread,
    sched_prev: ?*Thread,

    // Linked list for wait queues
    wait_next: ?*Thread,
    wait_prev: ?*Thread,
};

// =============================================================================
// Thread table
// =============================================================================
var thread_table: [MAX_THREADS]?*Thread = [_]?*Thread{null} ** MAX_THREADS;
var next_tid: Tid = 0;
var thread_count: u32 = 0;

var lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Create a kernel thread (runs in ring 0)
// =============================================================================
pub fn createKernelThread(
    proc: *main.process.Process,
    entry: *const fn () callconv(.C) noreturn,
) !*Thread {
    lock.acquire();
    defer lock.release();

    const tid = allocTid() orelse return error.TooManyThreads;

    // Allocate kernel stack
    const stack_pages = KERNEL_STACK_SIZE / @as(usize, @truncate(paging.PAGE_SIZE));
    const kernel_stack = main.vmm.allocKernelPages(@as(u64, stack_pages)) orelse return error.OutOfMemory;
    const stack_base = @as(u64, @truncate(@as(usize, @truncate(kernel_stack))));
    const stack_top = stack_base + KERNEL_STACK_SIZE;

    // Allocate thread structure from the heap
    const thread_mem = main.heap.alloc(@sizeOf(Thread)) orelse return error.OutOfMemory;
    const thread = @as(*Thread, @ptrCast(@alignCast(thread_mem)));

    thread.* = Thread{
        .tid = tid,
        .owner = proc,
        .state = .created,
        .context = CpuContext{
            .rip = @intFromPtr(entry),
            .rsp = stack_top - 8, // Space for the return address
            .cs = 0x08, // Kernel code segment
            .ss = 0x10, // Kernel data segment
            .rflags = 0x202, // Interrupts enabled
        },
        .kernel_stack_base = stack_base,
        .kernel_stack_top = stack_top,
        .user_stack_base = 0,
        .user_stack_top = 0,
        .priority = proc.priority,
        .time_slice = 10, // 10ms default
        .time_used = 0,
        .total_cpu_time = 0,
        .vruntime = 0,
        .wait_channel = 0,
        .wake_time = 0,
        .tls_base = 0,
        .sched_next = null,
        .sched_prev = null,
        .wait_next = null,
        .wait_prev = null,
    };

    thread_table[tid] = thread;
    thread_count += 1;

    // Mark thread as ready for scheduling
    thread.state = .ready;

    main.klog(.debug, "Thread: Created kernel thread TID {d} for PID {d}", .{
        tid,
        proc.pid,
    });

    return thread;
}

/// Create a user thread within a process
pub fn createUserThread(
    proc: *main.process.Process,
    entry_point: u64,
    user_stack_top: u64,
) !*Thread {
    lock.acquire();
    defer lock.release();

    const tid = allocTid() orelse return error.TooManyThreads;

    // Allocate kernel stack (every user thread needs a kernel stack too)
    const stack_pages = KERNEL_STACK_SIZE / @as(usize, @truncate(paging.PAGE_SIZE));
    const kernel_stack = main.vmm.allocKernelPages(@as(u64, stack_pages)) orelse return error.OutOfMemory;
    const kstack_base = @as(u64, @truncate(@as(usize, @truncate(kernel_stack))));
    const kstack_top = kstack_base + KERNEL_STACK_SIZE;

    const thread_mem = main.heap.alloc(@sizeOf(Thread)) orelse return error.OutOfMemory;
    const thread = @as(*Thread, @ptrCast(@alignCast(thread_mem)));

    thread.* = Thread{
        .tid = tid,
        .owner = proc,
        .state = .created,
        .context = CpuContext{
            .rip = entry_point,
            .rsp = user_stack_top,
            .cs = 0x18 | 3, // User code segment with RPL=3
            .ss = 0x20 | 3, // User data segment with RPL=3
            .rflags = 0x202, // Interrupts enabled
        },
        .kernel_stack_base = kstack_base,
        .kernel_stack_top = kstack_top,
        .user_stack_base = user_stack_top - USER_STACK_SIZE,
        .user_stack_top = user_stack_top,
        .priority = proc.priority,
        .time_slice = 10,
        .time_used = 0,
        .total_cpu_time = 0,
        .vruntime = 0,
        .wait_channel = 0,
        .wake_time = 0,
        .tls_base = 0,
        .sched_next = null,
        .sched_prev = null,
        .wait_next = null,
        .wait_prev = null,
    };

    thread_table[tid] = thread;
    thread_count += 1;
    thread.state = .ready;

    return thread;
}

// =============================================================================
// Thread operations
// =============================================================================

/// Get a thread by TID
pub fn getThread(tid: Tid) ?*Thread {
    if (tid >= MAX_THREADS) return null;
    return thread_table[tid];
}

/// Destroy a thread and free its resources
pub fn destroyThread(thread: *Thread) void {
    lock.acquire();
    defer lock.release();

    thread.state = .dead;
    thread_table[thread.tid] = null;

    // Free kernel stack
    const stack_pages = KERNEL_STACK_SIZE / @as(usize, @truncate(paging.PAGE_SIZE));
    main.vmm.freeKernelPages(thread.kernel_stack_base, @as(u64, stack_pages));

    // Free the thread structure
    main.heap.free(@as([*]u8, @ptrCast(thread)));
    thread_count -= 1;
}

/// Put a thread to sleep for the given number of milliseconds
pub fn sleep(thread: *Thread, ms: u64) void {
    thread.state = .sleeping;
    thread.wake_time = main.pit.getTicks() + main.pit.msToTicks(ms);
}

/// Block a thread on a wait channel
pub fn block(thread: *Thread, channel: u64) void {
    thread.state = .blocked;
    thread.wait_channel = channel;
}

/// Wake all threads blocked on a specific wait channel
pub fn wakeAll(channel: u64) void {
    for (thread_table) |maybe_thread| {
        if (maybe_thread) |thread| {
            if (thread.state == .blocked and thread.wait_channel == channel) {
                thread.state = .ready;
                thread.wait_channel = 0;
            }
        }
    }
}

/// Wake one thread blocked on a specific wait channel
pub fn wakeOne(channel: u64) void {
    for (thread_table) |maybe_thread| {
        if (maybe_thread) |thread| {
            if (thread.state == .blocked and thread.wait_channel == channel) {
                thread.state = .ready;
                thread.wait_channel = 0;
                return;
            }
        }
    }
}

/// Check sleeping threads and wake any whose timer has expired
pub fn checkSleepers() void {
    const current_ticks = main.pit.getTicks();
    for (thread_table) |maybe_thread| {
        if (maybe_thread) |thread| {
            if (thread.state == .sleeping and current_ticks >= thread.wake_time) {
                thread.state = .ready;
                thread.wake_time = 0;
            }
        }
    }
}

// =============================================================================
// Internal
// =============================================================================
fn allocTid() ?Tid {
    var checked: u32 = 0;
    while (checked < MAX_THREADS) : (checked += 1) {
        if (thread_table[next_tid] == null) {
            const tid = next_tid;
            next_tid = (next_tid + 1) % MAX_THREADS;
            return tid;
        }
        next_tid = (next_tid + 1) % MAX_THREADS;
    }
    return null;
}

pub fn getThreadCount() u32 {
    return thread_count;
}
