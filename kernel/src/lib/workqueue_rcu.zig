// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Workqueue Internals, Kthread Framework,
// RCU (Read-Copy-Update) Subsystem, SRCU,
// Per-CPU Variables, Completion Framework,
// Atomic Operations, Memory Barriers
// More advanced than Linux 2026 kernel concurrency

const std = @import("std");

// ============================================================================
// Workqueue Framework
// ============================================================================

/// Workqueue type
pub const WorkqueueType = enum(u8) {
    bound = 0,            // WQ_UNBOUND=0, per-CPU
    unbound = 1,          // WQ_UNBOUND
    freezable = 2,        // WQ_FREEZABLE
    mem_reclaim = 3,      // WQ_MEM_RECLAIM
    highpri = 4,          // WQ_HIGHPRI
    cpu_intensive = 5,    // WQ_CPU_INTENSIVE
    sysfs = 6,            // WQ_SYSFS
    power_efficient = 7,  // WQ_POWER_EFFICIENT
    // Zxyphor
    zxy_deadline = 100,
    zxy_realtime = 101,
};

/// Workqueue flags
pub const WorkqueueFlags = packed struct(u32) {
    unbound: bool = false,
    freezable: bool = false,
    mem_reclaim: bool = false,
    highpri: bool = false,
    cpu_intensive: bool = false,
    sysfs: bool = false,
    power_efficient: bool = false,
    ordered: bool = false,
    // Zxyphor
    zxy_numa_affine: bool = false,
    zxy_low_latency: bool = false,
    _padding: u22 = 0,
};

/// Work item state
pub const WorkItemState = enum(u8) {
    idle = 0,
    pending = 1,
    running = 2,
    cancelled = 3,
    delayed = 4,
};

/// Work item descriptor
pub const WorkItemDesc = struct {
    callback: u64 = 0,         // function pointer
    data: u64 = 0,
    state: WorkItemState = .idle,
    on_cpu: i32 = -1,
    wq_id: u32 = 0,
    flags: u32 = 0,
    timer_expires_ns: u64 = 0, // for delayed_work
    last_queued_ns: u64 = 0,
    last_run_ns: u64 = 0,
};

/// Worker pool descriptor
pub const WorkerPoolDesc = struct {
    id: u32 = 0,
    cpu: i32 = -1,             // -1 for unbound
    node: i32 = -1,            // NUMA node
    nr_workers: u32 = 0,
    nr_idle: u32 = 0,
    nr_running: u32 = 0,
    flags: WorkqueueFlags = .{},
    refcnt: u32 = 0,
    nr_in_flight: [16]u32 = [_]u32{0} ** 16,
    watchdog_ts: u64 = 0,
    max_active: u32 = 0,
    min_active: u32 = 0,
};

/// System workqueues constants
pub const SystemWq = enum(u8) {
    system_wq = 0,
    system_highpri_wq = 1,
    system_long_wq = 2,
    system_unbound_wq = 3,
    system_freezable_wq = 4,
    system_power_efficient_wq = 5,
    system_freezable_power_efficient_wq = 6,
};

/// Workqueue statistics
pub const WorkqueueStats = struct {
    nr_active: u32 = 0,
    max_active: u32 = 0,
    nr_pending: u64 = 0,
    nr_running: u64 = 0,
    nr_completed: u64 = 0,
    nr_cancelled: u64 = 0,
    total_exec_time_ns: u64 = 0,
    max_exec_time_ns: u64 = 0,
    avg_wait_time_ns: u64 = 0,
    max_wait_time_ns: u64 = 0,
};

// ============================================================================
// Kthread Framework
// ============================================================================

/// Kthread creation parameters
pub const KthreadCreateParams = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    cpu: i32 = -1,              // -1 for any CPU
    node: i32 = -1,             // NUMA node preference
    priority: i32 = 0,
    sched_policy: KthreadSchedPolicy = .normal,
    flags: KthreadFlags = .{},
    stack_size: u32 = 0,        // 0 for default
};

pub const KthreadSchedPolicy = enum(u8) {
    normal = 0,
    fifo = 1,
    rr = 2,
    batch = 3,
    idle = 5,
    deadline = 6,
};

/// Kthread flags
pub const KthreadFlags = packed struct(u32) {
    should_stop: bool = false,
    should_park: bool = false,
    is_parked: bool = false,
    is_per_cpu: bool = false,
    no_freeze: bool = false,
    // Zxyphor
    zxy_critical: bool = false,
    zxy_monitoring: bool = false,
    _padding: u25 = 0,
};

/// Kthread worker descriptor
pub const KthreadWorkerDesc = struct {
    task_pid: i32 = 0,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    nr_work_pending: u32 = 0,
    nr_work_completed: u64 = 0,
    flags: KthreadFlags = .{},
    cpu: i32 = -1,
};

// ============================================================================
// RCU - Read-Copy-Update
// ============================================================================

/// RCU flavor type
pub const RcuFlavor = enum(u8) {
    rcu_preempt = 0,    // preemptible RCU
    rcu_sched = 1,      // non-preemptible RCU (scheduler)
    rcu_bh = 2,         // bottom-half RCU
    srcu = 3,           // sleepable RCU
    tasks = 4,          // RCU-tasks (voluntary context switch)
    tasks_rude = 5,     // RCU-tasks-rude
    tasks_trace = 6,    // RCU-tasks-trace
    // Zxyphor
    zxy_expedited = 100,
};

/// RCU grace period state
pub const RcuGpState = enum(u8) {
    idle = 0,
    started = 1,
    wait_fqs = 2,      // waiting for force-quiescent-state
    cleanup = 3,
    completed = 4,
};

/// RCU node descriptor (hierarchical)
pub const RcuNodeDesc = struct {
    level: u8 = 0,
    grplo: u16 = 0,
    grphi: u16 = 0,
    qsmask: u64 = 0,           // CPUs needing quiescent state
    qsmaskinit: u64 = 0,
    grpmask: u64 = 0,
    gp_seq: u64 = 0,
    completedqs: u64 = 0,
    exp_need_qs: u64 = 0,
    boost_tasks: u32 = 0,
    boost_time_ns: u64 = 0,
};

/// RCU callback descriptor
pub const RcuCallbackDesc = struct {
    func: u64 = 0,              // callback function
    next: u64 = 0,              // next in list
    gp_seq_needed: u64 = 0,
    queued_ns: u64 = 0,
};

/// RCU statistics
pub const RcuStats = struct {
    gp_count: u64 = 0,
    gp_duration_ns_total: u64 = 0,
    gp_duration_ns_max: u64 = 0,
    expedited_gp_count: u64 = 0,
    callbacks_invoked: u64 = 0,
    callbacks_pending: u64 = 0,
    callbacks_offloaded: u64 = 0,
    fqs_count: u64 = 0,
    jiffies_stall: u64 = 0,
    stall_count: u64 = 0,
    nocb_bypass_count: u64 = 0,
    lazy_count: u64 = 0,
};

/// SRCU - Sleepable RCU descriptor
pub const SrcuDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    per_cpu_ref: u64 = 0,
    gp_seq: u64 = 0,
    gp_state: RcuGpState = .idle,
    work_pending: bool = false,
    nr_readers: u64 = 0,
    nr_completed_gp: u64 = 0,
};

// ============================================================================
// Per-CPU Variables
// ============================================================================

/// Per-CPU allocation type
pub const PerCpuAllocType = enum(u8) {
    first_chunk = 0,    // embedding/page allocator
    dynamic = 1,        // pcpu_alloc
    reserved = 2,
};

/// Per-CPU area descriptor
pub const PerCpuAreaDesc = struct {
    base_addr: u64 = 0,
    unit_size: u32 = 0,
    nr_units: u32 = 0,       // == nr CPUs typically
    atom_size: u32 = 0,
    static_size: u32 = 0,
    reserved_size: u32 = 0,
    dyn_size: u32 = 0,
    nr_groups: u32 = 0,
    alloc_type: PerCpuAllocType = .first_chunk,
};

/// Per-CPU stats
pub const PerCpuStats = struct {
    nr_alloc: u64 = 0,
    nr_free: u64 = 0,
    bytes_allocated: u64 = 0,
    bytes_freed: u64 = 0,
    nr_chunks: u32 = 0,
    free_size: u64 = 0,
    min_alloc_size: u32 = 0,
    max_alloc_size: u32 = 0,
};

// ============================================================================
// Completion Framework
// ============================================================================

/// Completion descriptor
pub const CompletionDesc = struct {
    done: u32 = 0,
    wait_count: u32 = 0,
};

/// Completion states
pub const CompletionState = enum(u8) {
    not_done = 0,
    done = 1,
    done_all = 2,       // complete_all called
};

// ============================================================================
// Atomic Operations
// ============================================================================

/// Memory ordering
pub const MemoryOrder = enum(u8) {
    relaxed = 0,
    consume = 1,
    acquire = 2,
    release = 3,
    acq_rel = 4,
    seq_cst = 5,
};

/// Atomic operation type
pub const AtomicOp = enum(u8) {
    load = 0,
    store = 1,
    exchange = 2,
    compare_exchange = 3,
    fetch_add = 4,
    fetch_sub = 5,
    fetch_and = 6,
    fetch_or = 7,
    fetch_xor = 8,
    fetch_nand = 9,
};

/// Memory barrier type
pub const BarrierType = enum(u8) {
    mb = 0,              // full barrier
    rmb = 1,             // read barrier
    wmb = 2,             // write barrier
    smp_mb = 3,          // SMP-only full barrier
    smp_rmb = 4,         // SMP-only read barrier
    smp_wmb = 5,         // SMP-only write barrier
    smp_store_mb = 6,    // store + full barrier
    smp_mb__before_atomic = 7,
    smp_mb__after_atomic = 8,
    io_mb = 9,           // I/O barrier
    dma_mb = 10,         // DMA barrier
    acquire_barrier = 11,
    release_barrier = 12,
};

// ============================================================================
// Locking Primitives (Internal Types)
// ============================================================================

/// Lock type
pub const LockType = enum(u8) {
    spinlock = 0,
    raw_spinlock = 1,
    rwlock = 2,
    mutex = 3,
    rt_mutex = 4,
    rw_semaphore = 5,
    semaphore = 6,
    seqlock = 7,
    percpu_rwsem = 8,
    ww_mutex = 9,
    local_lock = 10,
    // Zxyphor
    zxy_adaptive = 100,
    zxy_ticket = 101,
};

/// Lock class (for lockdep)
pub const LockClassDesc = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    key: u64 = 0,
    lock_type: LockType = .spinlock,
    nr_acquired: u64 = 0,
    nr_contended: u64 = 0,
    max_hold_ns: u64 = 0,
    avg_hold_ns: u64 = 0,
    max_wait_ns: u64 = 0,
    avg_wait_ns: u64 = 0,
    dep_gen_id: u32 = 0,
    usage_mask: u32 = 0,
};

/// Lockdep statistics
pub const LockdepStats = struct {
    nr_lock_classes: u32 = 0,
    nr_dependencies: u32 = 0,
    nr_chains: u32 = 0,
    nr_chain_hlocks: u32 = 0,
    nr_stack_traces: u32 = 0,
    nr_find_usage_forwards: u64 = 0,
    nr_find_usage_backwards: u64 = 0,
    nr_cyclic_checks: u64 = 0,
    nr_redundant: u64 = 0,
    max_lock_depth: u32 = 0,
    debug_locks: bool = true,
};

// ============================================================================
// Kernel Concurrency Subsystem Manager
// ============================================================================

pub const ConcurrencySubsystem = struct {
    nr_workqueues: u32 = 0,
    nr_worker_pools: u32 = 0,
    nr_workers_total: u32 = 0,
    nr_kthreads: u32 = 0,
    rcu_flavor_count: u8 = 0,
    rcu_gp_count: u64 = 0,
    rcu_callback_count: u64 = 0,
    srcu_instances: u32 = 0,
    per_cpu_areas: u32 = 0,
    per_cpu_total_size: u64 = 0,
    lockdep_enabled: bool = false,
    lockdep_classes: u32 = 0,
    initialized: bool = false,

    pub fn init() ConcurrencySubsystem {
        return ConcurrencySubsystem{
            .rcu_flavor_count = 7,
            .lockdep_enabled = true,
            .initialized = true,
        };
    }
};
