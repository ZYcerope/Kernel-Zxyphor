// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Locking Primitives, RCU, Per-CPU, Work Queues
// Comprehensive concurrency primitives more advanced than Linux 2026

const std = @import("std");

// ============================================================================
// Mutex
// ============================================================================

pub const MutexState = enum(u32) {
    unlocked = 0,
    locked = 1,
    locked_contended = 2,
};

pub const MutexFlags = packed struct {
    adaptive: bool = false,        // Adaptive spinning before sleep
    pi: bool = false,              // Priority inheritance
    interruptible: bool = false,   // Can be interrupted by signals
    killable: bool = false,        // Only killable signals interrupt
    nested: bool = false,          // Lockdep: nested locking allowed
    _padding: u3 = 0,
};

pub const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    owner: ?*anyopaque = null,
    wait_count: u32 = 0,
    flags: MutexFlags = .{},
    // Lockdep
    dep_map_class: u32 = 0,
    dep_map_name: [32]u8 = [_]u8{0} ** 32,
    // Stats
    total_acquisitions: u64 = 0,
    total_contentions: u64 = 0,
    total_wait_ns: u64 = 0,
    max_hold_ns: u64 = 0,
    // Adaptive spin config
    spin_threshold: u32 = 100,

    pub fn is_locked(self: *const Mutex) bool {
        return self.state.load(.acquire) != 0;
    }
    pub fn is_contended(self: *const Mutex) bool {
        return self.state.load(.acquire) == @intFromEnum(MutexState.locked_contended);
    }
};

// ============================================================================
// RW Lock
// ============================================================================

pub const RwLockState = enum(u32) {
    unlocked = 0,
    read_locked = 1,
    write_locked = 2,
};

pub const RwLock = struct {
    cnts: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    wait_lock: u32 = 0,
    // Reader bias for read-heavy workloads
    reader_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    writer_owner: ?*anyopaque = null,
    // Stats
    total_read_acquisitions: u64 = 0,
    total_write_acquisitions: u64 = 0,
    total_read_contentions: u64 = 0,
    total_write_contentions: u64 = 0,
    max_readers: u32 = 0,

    // Constants for count field
    const READER_BIAS: u32 = 0x100;
    const WRITER_LOCKED: u32 = 0x01;
    const WRITER_WAITING: u32 = 0x02;
    const READER_MASK: u32 = 0xFFFFFF00;

    pub fn reader_count_val(self: *const RwLock) u32 {
        return (self.cnts.load(.acquire) & READER_MASK) >> 8;
    }
    pub fn is_write_locked(self: *const RwLock) bool {
        return (self.cnts.load(.acquire) & WRITER_LOCKED) != 0;
    }
};

// ============================================================================
// RW Semaphore
// ============================================================================

pub const RwSemaphore = struct {
    count: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    owner: ?*anyopaque = null,
    wait_count: u32 = 0,
    // Optimistic spinning
    osq_tail: u32 = 0,
    // Handoff
    handoff_pending: bool = false,
    // Stats
    total_read_lock: u64 = 0,
    total_write_lock: u64 = 0,
    total_downgrade: u64 = 0,

    const RWSEM_READER_OWNED: i64 = 0x01;
    const RWSEM_WRITER_LOCKED: i64 = 0x02;
    const RWSEM_BIAS: i64 = 0x100;

    pub fn is_write_locked(self: *const RwSemaphore) bool {
        return (self.count.load(.acquire) & RWSEM_WRITER_LOCKED) != 0;
    }
    pub fn is_read_locked(self: *const RwSemaphore) bool {
        return self.count.load(.acquire) > 0 and !self.is_write_locked();
    }
};

// ============================================================================
// Seqlock / Seqcount
// ============================================================================

pub const Seqcount = struct {
    sequence: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    // Lockdep associated lock type
    assoc_lock_type: SeqcountLockType = .none,

    pub fn read_begin(self: *const Seqcount) u32 {
        return self.sequence.load(.acquire);
    }
    pub fn read_retry(self: *const Seqcount, start: u32) bool {
        // Odd value means writer is active, or value changed
        return (start & 1) != 0 or self.sequence.load(.acquire) != start;
    }
};

pub const SeqcountLockType = enum(u8) {
    none = 0,
    spinlock = 1,
    rwlock = 2,
    mutex = 3,
    ww_mutex = 4,
};

pub const Seqlock = struct {
    seqcount: Seqcount = .{},
    lock: u32 = 0,       // underlying spinlock
};

// ============================================================================
// RCU (Read-Copy-Update)
// ============================================================================

pub const RcuFlavorType = enum(u8) {
    rcu_preempt = 0,     // Preemptible RCU
    rcu_sched = 1,       // Non-preemptible RCU
    rcu_bh = 2,          // Bottom-half RCU
    srcu = 3,            // Sleepable RCU
    tasks = 4,           // Tasks RCU
    tasks_rude = 5,      // Tasks Rude RCU
    tasks_trace = 6,     // Tasks Trace RCU
};

pub const RcuState = struct {
    gp_seq: u64 = 0,              // Grace period sequence number
    gp_start: u64 = 0,            // Grace period start time (ns)
    gp_completed: u64 = 0,        // Last completed GP
    gp_activity: u64 = 0,         // Last GP activity timestamp
    // Expedited GP
    expedited_seq: u64 = 0,
    expedited_need_qs: bool = false,
    // QS (Quiescent State) tracking
    nr_cpus_snap: u32 = 0,        // CPUs at start of GP
    qs_mask: u64 = 0,             // CPUs that haven't reported QS
    // Boost
    boost_enabled: bool = false,
    boost_prio: i32 = 0,
    // Callbacks
    nr_callbacks: u64 = 0,
    nr_lazy_callbacks: u64 = 0,
    // Stall detection
    jiffies_stall: u64 = 0,
    stall_warning_seconds: u32 = 21,
    nr_stall_warnings: u32 = 0,
    // Nocb (no-callback offloading)
    nocb_enabled: bool = false,
    nr_nocb_cpus: u32 = 0,
};

pub const RcuPerCpu = struct {
    gp_seq: u64 = 0,
    gp_seq_needed: u64 = 0,
    qs_pending: bool = false,
    qs_completed: bool = false,
    // Callbacks
    nr_callbacks: u32 = 0,
    callbacks_invoked: u64 = 0,
    lazy_callbacks: u32 = 0,
    // RCU read lock nesting
    lock_nesting: i32 = 0,
    // Nocb
    nocb_bypass_count: u32 = 0,
};

pub const SrcuState = struct {
    per_cpu_ref: [256]SrcuPerCpu = [_]SrcuPerCpu{.{}} ** 256,
    gp_seq: u64 = 0,
    completed: u64 = 0,
    nr_cpus: u32 = 0,
};

pub const SrcuPerCpu = struct {
    lock_count: [2]u64 = [_]u64{0} ** 2,
    unlock_count: [2]u64 = [_]u64{0} ** 2,
};

// ============================================================================
// Per-CPU Variables
// ============================================================================

pub const PerCpuFlags = packed struct {
    first_chunk: bool = false,
    dynamic: bool = false,
    embedded: bool = false,
    _padding: u5 = 0,
};

pub const PerCpuChunk = struct {
    base_addr: u64 = 0,
    nr_pages: u32 = 0,
    nr_populated: u32 = 0,
    free_bytes: u32 = 0,
    contig_hint: u32 = 0,
    nr_alloc: u32 = 0,
    flags: PerCpuFlags = .{},
};

pub const PerCpuAllocator = struct {
    nr_chunks: u32 = 0,
    nr_cpus: u32 = 0,
    unit_size: u64 = 0,
    atom_size: u64 = 0,
    // Reserved area
    reserved_size: u64 = 0,
    reserved_offset: u64 = 0,
    // Dynamic area
    dyn_size: u64 = 0,
    // Stats
    total_alloc: u64 = 0,
    total_free: u64 = 0,
    total_bytes_used: u64 = 0,
};

// ============================================================================
// Workqueue
// ============================================================================

pub const WorkqueueFlags = packed struct {
    unbound: bool = false,
    freezable: bool = false,
    mem_reclaim: bool = false,
    highpri: bool = false,
    cpu_intensive: bool = false,
    sysfs: bool = false,
    power_efficient: bool = false,
    ordered: bool = false,
    bh: bool = false,
    _padding: u7 = 0,
};

pub const WorkqueueType = enum(u8) {
    bound = 0,           // Per-CPU workers
    unbound = 1,         // Shared pool
    ordered = 2,         // Single-threaded
    system = 3,          // Built-in system WQ
};

pub const WorkItem = struct {
    func_id: u64 = 0,
    data: u64 = 0,
    // Status
    pending: bool = false,
    running: bool = false,
    canceling: bool = false,
    // Timing
    queue_time_ns: u64 = 0,
    start_time_ns: u64 = 0,
    end_time_ns: u64 = 0,
};

pub const DelayedWork = struct {
    work: WorkItem = .{},
    delay_ns: u64 = 0,
    timer_pending: bool = false,
};

pub const Workqueue = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    flags: WorkqueueFlags = .{},
    wq_type: WorkqueueType = .bound,
    max_active: u32 = 256,
    // Stats
    nr_active: u32 = 0,
    nr_pending: u32 = 0,
    nr_running: u32 = 0,
    total_executed: u64 = 0,
    total_reschedules: u64 = 0,
    max_execution_ns: u64 = 0,
    avg_execution_ns: u64 = 0,
    // CPU affinity for unbound
    cpumask: u64 = 0,
    numa_node: i32 = -1,
    // Nice value
    nice: i32 = 0,
};

pub const WorkerPool = struct {
    id: u32 = 0,
    cpu: i32 = -1,
    nr_workers: u32 = 0,
    nr_idle: u32 = 0,
    nr_running: u32 = 0,
    // Manager
    manager_active: bool = false,
    // Stats
    total_workers_created: u64 = 0,
    total_workers_destroyed: u64 = 0,
};

// ============================================================================
// Completion
// ============================================================================

pub const Completion = struct {
    done: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    // Waiters
    nr_waiters: u32 = 0,

    pub fn is_done(self: *const Completion) bool {
        return self.done.load(.acquire) != 0;
    }
};

// ============================================================================
// Wait Queue
// ============================================================================

pub const WaitQueueFlags = packed struct {
    exclusive: bool = false,
    woken: bool = false,
    bookmark: bool = false,
    custom: bool = false,
    priority: bool = false,
    _padding: u3 = 0,
};

pub const WaitQueueEntry = struct {
    flags: WaitQueueFlags = .{},
    task: ?*anyopaque = null,
    func_id: u64 = 0,    // wake function
    // Priority (for priority wait queues)
    priority: i32 = 0,
};

pub const WaitQueueHead = struct {
    nr_waiters: u32 = 0,
    nr_exclusive: u32 = 0,
    // Stats
    total_wakes: u64 = 0,
    total_waits: u64 = 0,
};

// ============================================================================
// Lockdep (Lock Dependency Validator)
// ============================================================================

pub const LockdepClass = struct {
    key: u64 = 0,
    name: [64]u8 = [_]u8{0} ** 64,
    // Lock usage
    usage_mask: u32 = 0,
    // Dependency tracking
    nr_forward_deps: u32 = 0,
    nr_backward_deps: u32 = 0,
    // Statistics
    nr_contentions: u64 = 0,
    avg_hold_time_ns: u64 = 0,
    max_hold_time_ns: u64 = 0,
};

pub const LockdepUsage = packed struct {
    hardirq: bool = false,
    hardirq_read: bool = false,
    softirq: bool = false,
    softirq_read: bool = false,
    hardirq_enabled: bool = false,
    softirq_enabled: bool = false,
    ever_held: bool = false,
    ever_contended: bool = false,
};

pub const LockdepStats = struct {
    nr_lock_classes: u32 = 0,
    nr_chain_hlocks: u32 = 0,
    nr_chain_entries: u32 = 0,
    nr_hardirq_chain_hlocks: u32 = 0,
    nr_softirq_chain_hlocks: u32 = 0,
    nr_process_chain_hlocks: u32 = 0,
    nr_stack_trace_entries: u32 = 0,
    nr_list_entries: u32 = 0,
    nr_dependencies: u32 = 0,
    max_lock_depth: u32 = 0,
    nr_circular_detected: u32 = 0,
    debug_enabled: bool = true,
};

// ============================================================================
// KCSAN (Kernel Concurrency Sanitizer)
// ============================================================================

pub const KcsanConfig = struct {
    enabled: bool = false,
    report_once: bool = true,
    skip_watch: u32 = 0,
    udelay_task: u32 = 80,
    udelay_interrupt: u32 = 20,
    // Stats
    nr_data_races: u64 = 0,
    nr_race_unknown_origin: u64 = 0,
    nr_watchpoints_setup: u64 = 0,
    nr_watchpoints_hit: u64 = 0,
    nr_scoped_accesses: u64 = 0,
};

// ============================================================================
// Lock Statistics (for CONFIG_LOCK_STAT)
// ============================================================================

pub const LockStat = struct {
    nr_acquisitions: u64 = 0,
    nr_contentions: u64 = 0,
    total_wait_time_ns: u64 = 0,
    max_wait_time_ns: u64 = 0,
    total_hold_time_ns: u64 = 0,
    max_hold_time_ns: u64 = 0,
    nr_bounces: u64 = 0,        // Cross-CPU lock migration
    nr_read_acquisitions: u64 = 0,
    nr_write_acquisitions: u64 = 0,
};

// ============================================================================
// Atomic / Bit operations
// ============================================================================

pub const AtomicOp = enum(u8) {
    read = 0,
    set = 1,
    add = 2,
    sub = 3,
    inc = 4,
    dec = 5,
    and_op = 6,
    or_op = 7,
    xor_op = 8,
    add_return = 9,
    sub_return = 10,
    inc_return = 11,
    dec_return = 12,
    fetch_add = 13,
    fetch_sub = 14,
    fetch_and = 15,
    fetch_or = 16,
    fetch_xor = 17,
    cmpxchg = 18,
    xchg = 19,
    try_cmpxchg = 20,
    add_unless = 21,
    inc_not_zero = 22,
    dec_if_positive = 23,
    sub_and_test = 24,
    dec_and_test = 25,
};

pub const MemoryOrder = enum(u8) {
    relaxed = 0,
    acquire = 1,
    release = 2,
    acq_rel = 3,
    seq_cst = 4,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const ConcurrencySubsystem = struct {
    // Mutex stats
    nr_mutexes: u64 = 0,
    total_mutex_contentions: u64 = 0,
    // RW lock stats
    nr_rwlocks: u64 = 0,
    nr_rwsems: u64 = 0,
    // RCU stats
    rcu_state: RcuState = .{},
    // Per-CPU
    percpu_allocator: PerCpuAllocator = .{},
    // Workqueue stats
    nr_workqueues: u32 = 0,
    nr_worker_pools: u32 = 0,
    total_work_items: u64 = 0,
    // Lockdep
    lockdep: LockdepStats = .{},
    // KCSAN
    kcsan: KcsanConfig = .{},
    // Seqlock
    nr_seqlocks: u32 = 0,
    // Wait queue
    nr_wait_queues: u32 = 0,
    // Zxyphor
    zxy_adaptive_rcu_enabled: bool = false,
    initialized: bool = false,
};
