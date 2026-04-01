// =============================================================================
// Kernel Zxyphor - CFS (Completely Fair Scheduler)
// =============================================================================
// Implements a scheduler inspired by Linux's CFS (Completely Fair Scheduler).
// The core idea: every thread should receive a fair share of CPU time,
// proportional to its weight (derived from nice value/priority).
//
// Key concept: "virtual runtime" (vruntime)
//   - Each thread has a vruntime that tracks how much CPU time it has
//     received, weighted by priority
//   - The scheduler always picks the thread with the LOWEST vruntime
//   - Higher priority threads accumulate vruntime slower, so they get
//     scheduled more often
//   - This naturally balances CPU time across all runnable threads
//
// For simplicity, we use a sorted linked list instead of a red-black tree
// (which Linux uses). This is O(n) for insertion but works fine for
// reasonable process counts. The RB-tree optimization can be added later.
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Scheduler parameters
// =============================================================================
const MIN_GRANULARITY_TICKS: u32 = 1; // Minimum time slice: 1ms
const DEFAULT_TIMESLICE_TICKS: u32 = 10; // Default time slice: 10ms
const SCHED_PERIOD_TICKS: u32 = 100; // Scheduling period: 100ms
const WAKEUP_GRANULARITY: u64 = 1000; // Min vruntime advantage for preemption

// Nice to weight conversion table (matches Linux CFS behavior)
// nice=-20 → weight=88761, nice=0 → weight=1024, nice=19 → weight=15
const nice_to_weight = [40]u32{
    88761, 71755, 56483, 46273, 36291, // -20 to -16
    29154, 23254, 18705, 14949, 11916, // -15 to -11
    9548,  7620,  6100,  4904,  3906, //  -10 to -6
    3121,  2501,  1991,  1586,  1277, //  -5 to -1
    1024,  820,   655,   526,   423, //   0 to 4
    335,   272,   215,   172,   137, //   5 to 9
    110,   87,    70,    56,    45, //    10 to 14
    36,    29,    23,    18,    15, //    15 to 19
};

// =============================================================================
// Run queue — sorted by vruntime (lowest first)
// =============================================================================
var run_queue_head: ?*main.thread.Thread = null;
var run_queue_tail: ?*main.thread.Thread = null;
var run_queue_size: u32 = 0;

// Current running thread
var current_thread: ?*main.thread.Thread = null;

// Minimum vruntime seen (used for new thread initialization)
var min_vruntime: u64 = 0;

// Scheduler state
var scheduler_running: bool = false;
var need_resched: bool = false;
var tick_counter: u64 = 0;

var lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Initialize the scheduler
// =============================================================================
pub fn initialize() void {
    run_queue_head = null;
    run_queue_tail = null;
    run_queue_size = 0;
    current_thread = null;
    min_vruntime = 0;
    scheduler_running = false;

    main.klog(.info, "Scheduler: CFS initialized (period={d}ms, granularity={d}ms)", .{
        SCHED_PERIOD_TICKS,
        MIN_GRANULARITY_TICKS,
    });
}

// =============================================================================
// Start the scheduler — called once during boot, never returns
// =============================================================================
pub fn start() noreturn {
    scheduler_running = true;
    schedule();
    unreachable;
}

// =============================================================================
// Add a thread to the run queue
// =============================================================================
pub fn addToRunQueue(proc: *main.process.Process) void {
    if (proc.main_thread) |thread| {
        addThreadToRunQueue(thread);
    }
}

pub fn addThreadToRunQueue(thread: *main.thread.Thread) void {
    lock.acquire();
    defer lock.release();

    // Initialize vruntime for new threads to min_vruntime (so they get
    // a chance to run soon but don't starve existing threads)
    if (thread.vruntime == 0) {
        thread.vruntime = min_vruntime;
    }

    // Insert in sorted order (by vruntime, lowest first)
    if (run_queue_head == null) {
        // Empty queue
        thread.sched_prev = null;
        thread.sched_next = null;
        run_queue_head = thread;
        run_queue_tail = thread;
    } else {
        // Find insertion point
        var current = run_queue_head;
        while (current) |c| {
            if (thread.vruntime < c.vruntime) {
                // Insert before c
                thread.sched_next = c;
                thread.sched_prev = c.sched_prev;
                if (c.sched_prev) |prev| {
                    prev.sched_next = thread;
                } else {
                    run_queue_head = thread;
                }
                c.sched_prev = thread;
                run_queue_size += 1;
                return;
            }
            current = c.sched_next;
        }

        // Insert at end
        thread.sched_prev = run_queue_tail;
        thread.sched_next = null;
        if (run_queue_tail) |tail| {
            tail.sched_next = thread;
        }
        run_queue_tail = thread;
    }

    run_queue_size += 1;
}

/// Remove a thread from the run queue
fn removeFromRunQueue(thread: *main.thread.Thread) void {
    if (thread.sched_prev) |prev| {
        prev.sched_next = thread.sched_next;
    } else {
        run_queue_head = thread.sched_next;
    }

    if (thread.sched_next) |next_thread| {
        next_thread.sched_prev = thread.sched_prev;
    } else {
        run_queue_tail = thread.sched_prev;
    }

    thread.sched_prev = null;
    thread.sched_next = null;

    if (run_queue_size > 0) {
        run_queue_size -= 1;
    }
}

// =============================================================================
// Timer tick handler — called from the PIT IRQ handler
// =============================================================================
pub fn timerTick() void {
    tick_counter += 1;

    // Check sleeping threads
    main.thread.checkSleepers();

    if (current_thread) |thread| {
        thread.time_used += 1;
        thread.total_cpu_time += 1;

        // Update vruntime based on weight
        const weight = getWeight(thread.priority);
        const delta_vruntime = (@as(u64, 1024) * 1) / @as(u64, weight);
        thread.vruntime += @max(delta_vruntime, 1);

        // Check if time slice is exhausted
        if (thread.time_used >= thread.time_slice) {
            need_resched = true;
        }

        // Also check if another thread has significantly lower vruntime
        if (run_queue_head) |next_ready| {
            if (next_ready.vruntime + WAKEUP_GRANULARITY < thread.vruntime) {
                need_resched = true;
            }
        }
    }

    // Perform reschedule if needed
    if (need_resched) {
        need_resched = false;
        schedule();
    }
}

// =============================================================================
// Voluntary yield — give up remaining time slice
// =============================================================================
pub fn yield() void {
    if (current_thread) |thread| {
        thread.time_used = thread.time_slice; // Exhaust time slice
        schedule();
    }
}

// =============================================================================
// Main scheduling function — pick the next thread to run
// =============================================================================
fn schedule() void {
    lock.acquire();

    // Put current thread back in the run queue (if still runnable)
    if (current_thread) |old_thread| {
        if (old_thread.state == .running) {
            old_thread.state = .ready;
            old_thread.time_used = 0;

            // Re-insert into run queue sorted by vruntime
            lock.release();
            addThreadToRunQueue(old_thread);
            lock.acquire();
        }
    }

    // Pick the thread with the lowest vruntime (head of the sorted queue)
    if (run_queue_head) |next_thread| {
        removeFromRunQueue(next_thread);
        next_thread.state = .running;
        next_thread.time_used = 0;
        next_thread.time_slice = calculateTimeSlice(next_thread);

        // Update min_vruntime
        if (next_thread.vruntime > min_vruntime) {
            min_vruntime = next_thread.vruntime;
        }

        const old_thread = current_thread;
        current_thread = next_thread;

        // Update the process's current pointer
        main.process.setCurrent(next_thread.owner);

        // Update TSS kernel stack (for interrupts from user mode)
        main.tss.setKernelStack(next_thread.kernel_stack_top);

        lock.release();

        // Perform the actual context switch
        if (old_thread) |old| {
            if (old != next_thread) {
                // Switch address space if the processes are different
                if (old.owner != next_thread.owner) {
                    main.vmm.switchAddressSpace(&next_thread.owner.address_space);
                }
                main.context.switchContext(&old.context, &next_thread.context);
            }
        } else {
            // First thread — jump directly to it
            main.vmm.switchAddressSpace(&next_thread.owner.address_space);
            main.context.restoreContext(&next_thread.context);
        }
    } else {
        lock.release();
        // No runnable threads — enter idle
        main.arch.haltUntilInterrupt();
    }
}

// =============================================================================
// Calculate time slice based on weight and run queue size
// =============================================================================
fn calculateTimeSlice(thread: *main.thread.Thread) u32 {
    if (run_queue_size == 0) return DEFAULT_TIMESLICE_TICKS;

    const weight = getWeight(thread.priority);
    const total_weight = calculateTotalWeight();

    if (total_weight == 0) return DEFAULT_TIMESLICE_TICKS;

    // Time slice = (period * weight) / total_weight
    const slice = (SCHED_PERIOD_TICKS * weight) / @as(u32, @truncate(total_weight));
    return @max(slice, MIN_GRANULARITY_TICKS);
}

/// Calculate total weight of all threads in the run queue
fn calculateTotalWeight() u64 {
    var total: u64 = 0;
    var thread = run_queue_head;
    while (thread) |t| {
        total += getWeight(t.priority);
        thread = t.sched_next;
    }
    if (current_thread) |ct| {
        total += getWeight(ct.priority);
    }
    return total;
}

/// Convert a priority (nice value) to a weight
fn getWeight(priority: i8) u32 {
    const idx = @as(usize, @intCast(@as(i32, priority) + 20));
    if (idx >= nice_to_weight.len) return 1024;
    return nice_to_weight[idx];
}

// =============================================================================
// Scheduler statistics
// =============================================================================
pub fn getRunQueueSize() u32 {
    return run_queue_size;
}

pub fn getCurrentThread() ?*main.thread.Thread {
    return current_thread;
}

pub fn isRunning() bool {
    return scheduler_running;
}

pub fn getTickCount() u64 {
    return tick_counter;
}
