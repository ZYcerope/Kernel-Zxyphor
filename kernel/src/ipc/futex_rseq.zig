// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced Futex and Restartable Sequences (rseq)
// Futex operations (wait/wake/pi/requeue), futex2, rseq per-CPU critical sections,
// robust futexes, priority inheritance, adaptive spinning
// More advanced than Linux 2026 futex subsystem

const std = @import("std");

// ============================================================================
// Futex Operations
// ============================================================================

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_FD: u32 = 2;
pub const FUTEX_REQUEUE: u32 = 3;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_WAKE_OP: u32 = 5;
pub const FUTEX_LOCK_PI: u32 = 6;
pub const FUTEX_UNLOCK_PI: u32 = 7;
pub const FUTEX_TRYLOCK_PI: u32 = 8;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
pub const FUTEX_CMP_REQUEUE_PI: u32 = 12;
pub const FUTEX_LOCK_PI2: u32 = 13;

// Futex flags
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;

// Futex bitset
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFFFFFF;

// Futex wake op
pub const FUTEX_OP_SET: u32 = 0;
pub const FUTEX_OP_ADD: u32 = 1;
pub const FUTEX_OP_OR: u32 = 2;
pub const FUTEX_OP_ANDN: u32 = 3;
pub const FUTEX_OP_XOR: u32 = 4;

pub const FUTEX_OP_CMP_EQ: u32 = 0;
pub const FUTEX_OP_CMP_NE: u32 = 1;
pub const FUTEX_OP_CMP_LT: u32 = 2;
pub const FUTEX_OP_CMP_LE: u32 = 3;
pub const FUTEX_OP_CMP_GT: u32 = 4;
pub const FUTEX_OP_CMP_GE: u32 = 5;

// ============================================================================
// Futex2 (New API)
// ============================================================================

pub const FUTEX2_SIZE_U8: u32 = 0x00;
pub const FUTEX2_SIZE_U16: u32 = 0x01;
pub const FUTEX2_SIZE_U32: u32 = 0x02;
pub const FUTEX2_SIZE_U64: u32 = 0x03;
pub const FUTEX2_NUMA: u32 = 0x04;
pub const FUTEX2_PRIVATE: u32 = FUTEX_PRIVATE_FLAG;

pub const Futex2Waitv = struct {
    val: u64,
    uaddr: u64,
    flags: u32,
    _reserved: u32,
};

// ============================================================================
// Futex Key
// ============================================================================

pub const FutexKeyType = enum(u8) {
    private = 0,         // Process-private mapping
    shared = 1,          // Shared (file-backed or shmem)
};

pub const FutexKey = struct {
    key_type: FutexKeyType,
    // Private key
    mm: u64,             // mm_struct pointer
    address: u64,        // Virtual address
    // Shared key
    inode: u64,          // Inode pointer
    pgoff: u64,          // Page offset
    // Offset within page
    offset: u32,

    pub fn matches(self: *const FutexKey, other: *const FutexKey) bool {
        if (self.key_type != other.key_type) return false;
        if (self.key_type == .private) {
            return self.mm == other.mm and self.address == other.address;
        } else {
            return self.inode == other.inode and self.pgoff == other.pgoff and self.offset == other.offset;
        }
    }
};

// ============================================================================
// Futex Queue Entry (Waiter)
// ============================================================================

pub const FutexWaiterState = enum(u8) {
    queued = 0,
    woken = 1,
    requeued = 2,
    timeout = 3,
    signal = 4,
    dead = 5,
};

pub const FutexWaiter = struct {
    // Key identifying the futex
    key: FutexKey,
    // List linkage
    next: ?*FutexWaiter,
    prev: ?*FutexWaiter,
    // Task
    task_pid: i32,
    task: u64,           // Pointer to task_struct
    // State
    state: FutexWaiterState,
    // Bitset
    bitset: u32,
    // Priority inheritance
    pi_state: ?*FutexPiState,
    // Timeout
    timeout_ns: u64,      // 0 = no timeout
    enqueue_time_ns: u64,
    // Requeue target
    requeue_key: ?*FutexKey,
    // Stats
    wake_latency_ns: u64,
};

// ============================================================================
// Hash Bucket (Futex Queue)
// ============================================================================

pub const FutexHashBucket = struct {
    // Chain of waiters
    chain_head: ?*FutexWaiter,
    chain_tail: ?*FutexWaiter,
    nr_waiters: u32,
    // Lock
    lock: u64,           // Spinlock
    // Stats
    total_enqueues: u64,
    total_dequeues: u64,
    max_chain_len: u32,
    contention_count: u64,
};

// Default hash table size
pub const FUTEX_HASH_BITS: u32 = 8;
pub const FUTEX_HASH_SIZE: u32 = 1 << FUTEX_HASH_BITS;

// ============================================================================
// Priority Inheritance (PI) Futex
// ============================================================================

pub const FutexPiState = struct {
    // Owner
    owner_pid: i32,
    owner_task: u64,
    // Key
    key: FutexKey,
    // RT mutex
    rt_mutex: u64,       // Pointer to rt_mutex
    // Waiters
    nr_waiters: u32,
    // Reference count
    refcount: u32,

    pub fn has_owner(self: *const FutexPiState) bool {
        return self.owner_pid != 0;
    }
};

// TID flags (stored in futex word for PI)
pub const FUTEX_TID_MASK: u32 = 0x3FFFFFFF;
pub const FUTEX_OWNER_DIED: u32 = 0x40000000;
pub const FUTEX_WAITERS: u32 = 0x80000000;

// ============================================================================
// Robust Futex List
// ============================================================================

pub const RobustListHead = struct {
    list: u64,           // Pointer to first entry (or self for empty)
    futex_offset: i64,   // Offset from entry start to futex word
    list_op_pending: u64, // Currently being added/removed
};

pub const RobustList = struct {
    next: u64,           // Pointer to next entry
};

pub const RobustFutexStats = struct {
    nr_robust_lists: u64,
    nr_robust_dead_handles: u64,
    nr_owner_died_wakeups: u64,
};

// ============================================================================
// Futex Wake Op Encoding
// ============================================================================

pub const FutexWakeOp = struct {
    op: u32,

    pub fn op_type(self: FutexWakeOp) u32 {
        return (self.op >> 28) & 0xF;
    }

    pub fn cmp_type(self: FutexWakeOp) u32 {
        return (self.op >> 24) & 0xF;
    }

    pub fn op_arg(self: FutexWakeOp) u32 {
        return (self.op >> 12) & 0xFFF;
    }

    pub fn cmp_arg(self: FutexWakeOp) u32 {
        return self.op & 0xFFF;
    }

    pub fn encode(op_t: u32, cmp_t: u32, op_a: u32, cmp_a: u32) FutexWakeOp {
        return FutexWakeOp{
            .op = (op_t << 28) | (cmp_t << 24) | (op_a << 12) | cmp_a,
        };
    }
};

// ============================================================================
// Restartable Sequences (rseq) - Linux 4.18+
// ============================================================================

pub const RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT: u32 = 1 << 0;
pub const RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL: u32 = 1 << 1;
pub const RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE: u32 = 1 << 2;

pub const RSEQ_SIG: u32 = 0x53053053;  // x86 signature

pub const RseqCriticalSection = struct {
    // Version
    version: u32,
    // Flags
    flags: u32,
    // Addresses
    start_ip: u64,       // Start of critical section
    post_commit_offset: u64, // Length of CS
    abort_ip: u64,       // Abort handler address

    pub fn end_ip(self: *const RseqCriticalSection) u64 {
        return self.start_ip + self.post_commit_offset;
    }

    pub fn contains(self: *const RseqCriticalSection, ip: u64) bool {
        return ip >= self.start_ip and ip < self.end_ip();
    }
};

pub const Rseq = struct {
    // CPU ID (set by kernel)
    cpu_id_start: u32,
    cpu_id: u32,
    // Critical section pointer
    rseq_cs: u64,        // Pointer to current rseq_cs
    // Flags
    flags: u32,
    // Node ID (NUMA)
    node_id: u32,
    // MM CID (memory management CPU ID)
    mm_cid: u32,
    // Padding for alignment
    _padding: [3]u32,

    pub fn on_cpu(self: *const Rseq) u32 {
        return self.cpu_id;
    }

    pub fn on_node(self: *const Rseq) u32 {
        return self.node_id;
    }

    pub fn is_registered(self: *const Rseq) bool {
        return self.cpu_id != @as(u32, 0xFFFFFFFF);
    }
};

// ============================================================================
// rseq Per-CPU Memory Allocator
// ============================================================================

pub const RseqMempool = struct {
    name: [64]u8,
    // Size
    element_size: u32,
    nr_cpus: u32,
    // Allocation
    nr_allocated: u64,
    nr_freed: u64,
    // Memory
    total_bytes: u64,
    used_bytes: u64,
};

// ============================================================================
// Adaptive Spinning (Futex Optimization)
// ============================================================================

pub const AdaptiveSpinConfig = struct {
    // Enable
    enabled: bool,
    // Thresholds
    max_spin_iterations: u32,
    spin_threshold_ns: u64,
    // Adaptive
    adaptive_spin: bool,
    history_depth: u8,
    // MCS spinlock-like behavior
    mcs_nodes: u32,
    // Stats
    spin_successes: u64,
    spin_failures: u64,
    total_spin_ns: u64,
    avg_spin_ns: u64,
};

// ============================================================================
// Lock Proxy (Futex → Kernel Lock Mapping)
// ============================================================================

pub const LockProxyType = enum(u8) {
    mutex = 0,
    rwlock_read = 1,
    rwlock_write = 2,
    semaphore = 3,
    pi_mutex = 4,
    // Zxyphor
    zxy_adaptive_lock = 10,
};

pub const LockProxy = struct {
    lock_type: LockProxyType,
    futex_addr: u64,
    kernel_lock: u64,
    owner_pid: i32,
    // Stats
    acquire_count: u64,
    contention_count: u64,
    wait_time_ns: u64,
    hold_time_ns: u64,
};

// ============================================================================
// Futex Statistics
// ============================================================================

pub const FutexOpStats = struct {
    wait_calls: u64,
    wake_calls: u64,
    wait_bitset_calls: u64,
    wake_bitset_calls: u64,
    requeue_calls: u64,
    cmp_requeue_calls: u64,
    wake_op_calls: u64,
    lock_pi_calls: u64,
    unlock_pi_calls: u64,
    trylock_pi_calls: u64,
    wait_requeue_pi_calls: u64,
    cmp_requeue_pi_calls: u64,
    // Futex2
    waitv_calls: u64,
    // Timeouts
    timeout_count: u64,
    // Signals
    signal_interrupts: u64,
    // Wake statistics
    total_woken: u64,
    max_woken_per_call: u32,
    avg_wake_latency_ns: u64,
    max_wake_latency_ns: u64,
    // Hash
    hash_collisions: u64,
    max_bucket_depth: u32,
    // PI
    pi_boost_count: u64,
    pi_deboost_count: u64,
    // Errors
    invalid_address: u64,
    permission_denied: u64,
    deadlock_detected: u64,
};

pub const RseqStats = struct {
    nr_registrations: u64,
    nr_unregistrations: u64,
    nr_preempt_aborts: u64,
    nr_signal_aborts: u64,
    nr_migrate_aborts: u64,
    nr_successful_commits: u64,
    abort_ratio_pct: u32,
};

// ============================================================================
// Futex Subsystem
// ============================================================================

pub const FutexSubsystem = struct {
    // Hash table
    nr_hash_buckets: u32,
    // Waiters
    nr_total_waiters: u64,
    nr_pi_waiters: u64,
    // Robust
    robust_stats: RobustFutexStats,
    // Adaptive spinning
    spin_config: AdaptiveSpinConfig,
    // Operation stats
    op_stats: FutexOpStats,
    // rseq
    rseq_supported: bool,
    rseq_stats: RseqStats,
    nr_rseq_registrations: u64,
    // Futex2
    futex2_supported: bool,
    // Lock debugging
    lock_debug_enabled: bool,
    nr_lock_proxies: u32,
    // Configuration
    max_waiters_per_futex: u32,
    hash_bits: u8,
    // Zxyphor
    zxy_fast_path: bool,
    zxy_numa_aware: bool,
    zxy_lock_elision: bool,
    initialized: bool,
};
