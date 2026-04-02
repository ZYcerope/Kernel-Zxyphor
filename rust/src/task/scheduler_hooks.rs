// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust Task / Scheduler Hooks
//! Sched class callbacks, context switch hooks, preemption,
//! CPU accounting, nohz, tick-less scheduling, load tracking

#![allow(dead_code)]

use core::sync::atomic::AtomicU64;

// ============================================================================
// Scheduler Policies
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    Normal = 0,        // SCHED_NORMAL (CFS/EEVDF)
    Fifo = 1,          // SCHED_FIFO
    Rr = 2,            // SCHED_RR
    Batch = 3,         // SCHED_BATCH
    Idle = 5,          // SCHED_IDLE
    Deadline = 6,      // SCHED_DEADLINE
    Ext = 7,           // SCHED_EXT (sched_ext / BPF)
}

// ============================================================================
// Scheduler Class
// ============================================================================

#[repr(C)]
pub struct SchedClass {
    // Selection
    pub enqueue_task: u64,       // fn(*rq, *task, flags)
    pub dequeue_task: u64,       // fn(*rq, *task, flags)
    pub yield_task: u64,         // fn(*rq)
    pub yield_to_task: u64,      // fn(*rq, *task) -> bool

    // Running
    pub check_preempt_curr: u64, // fn(*rq, *task, flags)
    pub pick_next_task: u64,     // fn(*rq) -> *task
    pub put_prev_task: u64,      // fn(*rq, *task)
    pub set_next_task: u64,      // fn(*rq, *task, first: bool)

    // Accounting
    pub task_tick: u64,          // fn(*rq, *task, queued: i32)
    pub task_fork: u64,          // fn(*task)
    pub task_dead: u64,          // fn(*task)

    // Priority
    pub prio_changed: u64,       // fn(*rq, *task, old_prio: i32)
    pub switched_from: u64,      // fn(*rq, *task)
    pub switched_to: u64,        // fn(*rq, *task)

    // Migration
    pub select_task_rq: u64,     // fn(*task, cpu: i32, flags: i32) -> i32
    pub migrate_task_rq: u64,    // fn(*task, new_cpu: i32)
    pub task_woken: u64,         // fn(*rq, *task)
    pub set_cpus_allowed: u64,   // fn(*task, *cpumask, flags: u32)

    // Balance
    pub balance: u64,            // fn(*rq, *task, *rf) -> *task
    pub select_task_rq_fair: u64,

    // NUMA
    pub task_change_group: u64,  // fn(*task, type: i32)

    // Update current
    pub update_curr: u64,        // fn(*rq)
}

// ============================================================================
// PELT (Per-Entity Load Tracking)
// ============================================================================

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct SchedAvg {
    pub last_update_time: u64,     // ns timestamp
    pub load_sum: u64,
    pub runnable_sum: u64,
    pub util_sum: u32,
    pub period_contrib: u32,
    pub load_avg: u64,             // geometric weighted average
    pub runnable_avg: u64,
    pub util_avg: u64,
    pub util_est: UtilEst,
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct UtilEst {
    pub enqueued: u32,
    pub ewma: u32,
}

// ============================================================================
// CFS Bandwidth
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct CfsBandwidth {
    pub quota: i64,             // max runtime per period (-1 = unlimited)
    pub period: u64,            // period in ns (default: 100ms)
    pub runtime: i64,           // remaining runtime this period
    pub burst: u64,             // burst capacity ns
    pub runtime_snap: i64,
    pub hierarchical_quota: i64,
    // Timer
    pub period_active: bool,
    pub slack_started: bool,
    pub distribute_running: bool,
    // Stats
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_time: u64,
    pub nr_burst: u64,
    pub burst_time: u64,
}

// ============================================================================
// RT Bandwidth
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct RtBandwidth {
    pub rt_period: u64,        // default: 1s
    pub rt_runtime: i64,       // default: 0.95s (950ms)
    pub rt_period_active: bool,
    pub rt_period_timer: u64,  // hrtimer
}

// ============================================================================
// DEADLINE Parameters
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct SchedDlEntity {
    pub dl_runtime: u64,       // max runtime per period (ns)
    pub dl_deadline: u64,      // relative deadline (ns)
    pub dl_period: u64,        // period (ns)
    pub dl_bw: u64,            // bandwidth (runtime/period)
    pub dl_density: u64,       // runtime/deadline
    pub runtime: i64,          // remaining runtime this period
    pub deadline: u64,         // absolute deadline
    pub flags: DlFlags,
    // Timer
    pub dl_timer: u64,         // hrtimer
    pub dl_boosted: bool,
    pub dl_throttled: bool,
    pub dl_yielded: bool,
    pub dl_non_contending: bool,
    pub dl_overrun: bool,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct DlFlags {
    bits: u32,
}

impl DlFlags {
    pub const SCHED_FLAG_RECLAIM: u32 = 0x02;
    pub const SCHED_FLAG_DL_OVERRUN: u32 = 0x04;
    pub const SCHED_FLAG_KEEP_POLICY: u32 = 0x08;
    pub const SCHED_FLAG_KEEP_PARAMS: u32 = 0x10;
    pub const SCHED_FLAG_UTIL_CLAMP_MIN: u32 = 0x20;
    pub const SCHED_FLAG_UTIL_CLAMP_MAX: u32 = 0x40;
}

// ============================================================================
// sched_ext (BPF extensible scheduler)
// ============================================================================

#[repr(C)]
pub struct SchedExtOps {
    pub name: [128]u8,
    pub select_cpu: u64,        // BPF prog ptr
    pub enqueue: u64,
    pub dequeue: u64,
    pub dispatch: u64,
    pub tick: u64,
    pub runnable: u64,
    pub running: u64,
    pub stopping: u64,
    pub quiescent: u64,
    pub yield_task: u64,
    pub core_sched_before: u64,
    pub set_weight: u64,
    pub set_cpumask: u64,
    pub update_idle: u64,
    pub cpu_acquire: u64,
    pub cpu_release: u64,
    pub init_task: u64,
    pub exit_task: u64,
    pub enable: u64,
    pub disable: u64,
    pub init: u64,
    pub exit: u64,
    pub dispatch_max_batch: u32,
    pub flags: u64,
    pub timeout_ms: u32,
    pub exit_dump_len: u32,
    pub hotplug_seq: u64,
}

// ============================================================================
// Util Clamp (uclamp)
// ============================================================================

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct UclampSe {
    pub value: u32,           // clamp value (0..1024)
    pub bucket_id: u32,
    pub active: bool,
    pub user_defined: bool,
}

pub const UCLAMP_MIN: usize = 0;
pub const UCLAMP_MAX: usize = 1;
pub const UCLAMP_CNT: usize = 2;
pub const SCHED_CAPACITY_SCALE: u32 = 1024;

// ============================================================================
// Preemption
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreemptModel {
    None = 0,            // CONFIG_PREEMPT_NONE
    Voluntary = 1,       // CONFIG_PREEMPT_VOLUNTARY
    Full = 2,            // CONFIG_PREEMPT
    Rt = 3,              // CONFIG_PREEMPT_RT (PREEMPT_RT)
    Lazy = 4,            // CONFIG_PREEMPT_LAZY (6.12+)
}

#[repr(C)]
#[derive(Debug)]
pub struct PreemptState {
    pub model: PreemptModel,
    pub count: u32,          // preempt_count (nest depth)
    pub need_resched: bool,
    pub need_resched_lazy: bool,
}

// ============================================================================
// Context Switch
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct ContextSwitchStats {
    pub total_voluntary: AtomicU64,
    pub total_involuntary: AtomicU64,
    pub total_idle_switches: AtomicU64,
    // Per-CPU
    pub per_cpu_switches: [u64; 256],
    // Latency
    pub avg_switch_ns: u64,
    pub max_switch_ns: u64,
    pub min_switch_ns: u64,
}

// ============================================================================
// Nohz / Tick-less
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NohzMode {
    Inactive = 0,
    LowRes = 1,
    HighRes = 2,
}

#[repr(C)]
#[derive(Debug)]
pub struct NohzState {
    pub mode: NohzMode,
    pub tick_stopped: bool,
    pub idle_active: bool,
    pub idle_entrytime: u64,
    pub idle_sleeptime: u64,
    pub idle_exittime: u64,
    pub idle_jiffies: u64,
    pub idle_calls: u64,
    pub idle_sleeps: u64,
    pub sleep_length: u64,
    pub last_jiffies: u64,
    pub next_tick: u64,
    pub nohz_full: bool,     // full dynticks for this CPU
}

// ============================================================================
// CPU Accounting
// ============================================================================

#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuAccounting {
    pub utime: u64,          // user time (ns)
    pub stime: u64,          // system time (ns)
    pub gtime: u64,          // guest time (ns)
    pub sum_exec_runtime: u64, // total runtime (ns)
    pub prev_cputime_utime: u64,
    pub prev_cputime_stime: u64,
    pub prev_cputime_gtime: u64,
    pub nr_switches: u64,    // context switch count
    pub nr_voluntary_switches: u64,
    pub nr_involuntary_switches: u64,
}

// ============================================================================
// Scheduler Manager (Rust side)
// ============================================================================

#[derive(Debug)]
pub struct SchedHooksManager {
    pub preempt_model: PreemptModel,
    pub hz: u32,                  // CONFIG_HZ
    pub nohz_full_enabled: bool,
    pub sched_ext_loaded: bool,
    pub context_stats: ContextSwitchStats,
    pub total_forks: AtomicU64,
    pub total_execs: AtomicU64,
    pub initialized: bool,
}

impl SchedHooksManager {
    pub fn new() -> Self {
        Self {
            preempt_model: PreemptModel::Voluntary,
            hz: 1000,
            nohz_full_enabled: false,
            sched_ext_loaded: false,
            context_stats: ContextSwitchStats {
                total_voluntary: AtomicU64::new(0),
                total_involuntary: AtomicU64::new(0),
                total_idle_switches: AtomicU64::new(0),
                per_cpu_switches: [0u64; 256],
                avg_switch_ns: 0,
                max_switch_ns: 0,
                min_switch_ns: u64::MAX,
            },
            total_forks: AtomicU64::new(0),
            total_execs: AtomicU64::new(0),
            initialized: true,
        }
    }
}
