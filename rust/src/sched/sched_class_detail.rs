// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust Scheduler Classes & CFS/EEVDF Detail
// Complete: sched_class operations, CFS entities, EEVDF virtual deadline,
// RT scheduling, deadline scheduling, bandwidth control, load tracking

use core::fmt;

// ============================================================================
// Scheduler Classes
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub enum SchedClassPriority {
    Stop = 0,       // Highest priority
    Deadline = 1,
    Rt = 2,
    Fair = 3,
    Idle = 4,       // Lowest priority
}

pub struct SchedClassOps {
    pub enqueue_task: Option<fn(rq: u64, task: u64, flags: u32)>,
    pub dequeue_task: Option<fn(rq: u64, task: u64, flags: u32)>,
    pub yield_task: Option<fn(rq: u64)>,
    pub yield_to_task: Option<fn(rq: u64, task: u64) -> bool>,
    pub check_preempt_curr: Option<fn(rq: u64, task: u64, flags: u32)>,
    pub pick_next_task: Option<fn(rq: u64) -> u64>,
    pub put_prev_task: Option<fn(rq: u64, task: u64)>,
    pub set_next_task: Option<fn(rq: u64, task: u64, first: bool)>,
    pub balance: Option<fn(rq: u64, prev: u64, rf: u64) -> u64>,
    pub select_task_rq: Option<fn(task: u64, cpu: i32, flags: i32) -> i32>,
    pub migrate_task_rq: Option<fn(task: u64, new_cpu: i32)>,
    pub task_woken: Option<fn(rq: u64, task: u64)>,
    pub task_waking: Option<fn(task: u64)>,
    pub set_cpus_allowed: Option<fn(task: u64, mask: u64, flags: u32)>,
    pub rq_online: Option<fn(rq: u64)>,
    pub rq_offline: Option<fn(rq: u64)>,
    pub find_lock_rq: Option<fn(task: u64, rq: u64) -> u64>,
    pub task_tick: Option<fn(rq: u64, task: u64, queued: i32)>,
    pub task_fork: Option<fn(task: u64)>,
    pub task_dead: Option<fn(task: u64)>,
    pub switched_from: Option<fn(rq: u64, task: u64)>,
    pub switched_to: Option<fn(rq: u64, task: u64)>,
    pub prio_changed: Option<fn(rq: u64, task: u64, oldprio: i32)>,
    pub get_rr_interval: Option<fn(rq: u64, task: u64) -> u64>,
    pub update_curr: Option<fn(rq: u64)>,
    pub task_change_group: Option<fn(task: u64)>,
}

// ============================================================================
// CFS Runqueue & Entity
// ============================================================================

pub struct CfsRq {
    pub load: LoadWeight,
    pub nr_running: u32,
    pub h_nr_running: u32,
    pub idle_nr_running: u32,
    pub idle_h_nr_running: u32,
    pub exec_clock: u64,
    pub min_vruntime: u64,
    pub avg_vruntime: i64,
    pub avg_load: u64,
    pub spread0: i64,
    pub runnable_sum: u64,
    pub runnable_avg: u64,
    pub avg: SchedAvg,
    pub removed: CfsRqRemoved,
    pub throttled: bool,
    pub throttle_count: u32,
    pub throttled_clock: u64,
    pub throttled_clock_pelt: u64,
    pub throttled_clock_pelt_time: u64,
    pub nr_throttled: u32,
    pub runtime_remaining: i64,
    pub runtime_snap: u64,
    pub tg: u64,            // task_group pointer
    pub on_rq: i32,
    pub rq: u64,            // rq pointer
    pub last_update_time: u64,
    pub propagate: i32,
    pub prop_runnable_sum: i64,
}

pub struct CfsRqRemoved {
    pub nr: u32,
    pub load_avg: u64,
    pub util_avg: u64,
    pub runnable_avg: u64,
}

// ============================================================================
// Sched Entity (CFS/EEVDF)
// ============================================================================

pub struct SchedEntity {
    pub load: LoadWeight,
    pub run_node: u64,      // rb_node
    pub deadline: u64,      // EEVDF virtual deadline
    pub min_deadline: u64,  // augmented tree min_deadline
    pub group_node: u64,
    pub on_rq: u32,
    pub exec_start: u64,
    pub sum_exec_runtime: u64,
    pub prev_sum_exec_runtime: u64,
    pub vruntime: u64,
    pub vlag: i64,          // EEVDF virtual lag
    pub slice: u64,         // EEVDF time slice
    pub nr_migrations: u64,
    pub depth: u32,
    pub parent: u64,        // parent sched_entity
    pub cfs_rq: u64,        // CFS runqueue this entity runs on
    pub my_q: u64,          // CFS runqueue owned by this group entity
    pub avg: SchedAvg,
    pub runnable_weight: u64,
    pub statistics: SchedStatistics,
}

// ============================================================================
// EEVDF Parameters
// ============================================================================

pub struct EevdfParams {
    pub base_slice_ns: u64,           // Default 3ms (3_000_000)
    pub sysctl_sched_base_slice: u64,
    pub sched_nr_latency: u32,        // Target latency
    pub sched_min_granularity: u64,
    pub ideal_runtime: u64,
    pub eligible_check_enabled: bool,
}

impl EevdfParams {
    pub const fn default_config() -> Self {
        Self {
            base_slice_ns: 3_000_000,
            sysctl_sched_base_slice: 3_000_000,
            sched_nr_latency: 8,
            sched_min_granularity: 750_000,
            ideal_runtime: 750_000,
            eligible_check_enabled: true,
        }
    }
}

// ============================================================================
// Load Weight
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LoadWeight {
    pub weight: u64,
    pub inv_weight: u32,
}

pub const NICE_0_LOAD: u64 = 1024;

pub const SCHED_PRIO_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291,
    29154, 23254, 18705, 14949, 11916,
    9548, 7620, 6100, 4904, 3906,
    3121, 2501, 1991, 1586, 1277,
    1024, 820, 655, 526, 423,
    335, 272, 215, 172, 137,
    110, 87, 70, 56, 45,
    36, 29, 23, 18, 15,
];

pub const SCHED_PRIO_TO_WMULT: [u32; 40] = [
    48388, 59856, 76040, 92818, 118348,
    147320, 184698, 229616, 287308, 360437,
    449829, 563644, 704093, 875809, 1099582,
    1376151, 1717300, 2157191, 2708050, 3363326,
    4194304, 5237765, 6557202, 8165337, 10153587,
    12820798, 15790321, 19976592, 24970740, 31350126,
    39045157, 49367440, 61356676, 76695844, 95443717,
    119304647, 148102320, 186737708, 238609294, 286331153,
];

// ============================================================================
// PELT (Per-Entity Load Tracking)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SchedAvg {
    pub last_update_time: u64,
    pub load_sum: u64,
    pub runnable_sum: u64,
    pub util_sum: u32,
    pub period_contrib: u32,
    pub load_avg: u64,
    pub runnable_avg: u64,
    pub util_avg: u64,
    pub util_est: UtilEst,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UtilEst {
    pub enqueued: u32,
    pub ewma: u32,
}

// ============================================================================
// RT Scheduling
// ============================================================================

pub struct RtRq {
    pub active: RtPrioArray,
    pub rt_nr_running: u32,
    pub rr_nr_running: u32,
    pub highest_prio: RtHighestPrio,
    pub rt_nr_migratory: u32,
    pub rt_nr_total: u32,
    pub overloaded: bool,
    pub pushable_tasks: u32,
    pub rt_throttled: bool,
    pub rt_time: u64,
    pub rt_runtime: u64,
    pub rt_period_timer: u64,
}

pub struct RtPrioArray {
    pub bitmap: [u64; 2],    // 100 RT priorities (MAX_RT_PRIO = 100)
    pub queue: [u64; 100],   // list heads per priority
}

pub struct RtHighestPrio {
    pub curr: i32,
    pub next: i32,
}

pub struct SchedRtEntity {
    pub run_list: u64,
    pub timeout: u64,
    pub watchdog_stamp: u64,
    pub time_slice: u32,
    pub on_rq: u16,
    pub on_list: u16,
    pub back: u64,
    pub parent: u64,
    pub my_q: u64,
    pub rt_rq: u64,
    pub nr_cpus_allowed: u32,
}

pub const MAX_RT_PRIO: i32 = 100;
pub const MAX_USER_RT_PRIO: i32 = 100;
pub const DEFAULT_PRIO: i32 = 120;
pub const MAX_PRIO: i32 = 140;
pub const MAX_NICE: i32 = 19;
pub const MIN_NICE: i32 = -20;

// ============================================================================
// Deadline Scheduling
// ============================================================================

pub struct DlRq {
    pub root: u64,          // rb_root
    pub rb_leftmost: u64,
    pub nr_running: u32,
    pub dl_nr_migratory: u32,
    pub earliest_dl: DlEarliestDl,
    pub overloaded: bool,
    pub pushable_dl_tasks_root: u64,
    pub pushable_dl_tasks_leftmost: u64,
    pub running_bw: u64,
    pub this_bw: u64,
    pub extra_bw: u64,
    pub bw_ratio: u64,
}

pub struct DlEarliestDl {
    pub curr: u64,
    pub next: u64,
}

pub struct SchedDlEntity {
    pub rb_node: u64,
    pub dl_runtime: u64,    // Maximum runtime per period (ns)
    pub dl_deadline: u64,   // Relative deadline (ns)
    pub dl_period: u64,     // Period (ns)
    pub dl_bw: u64,         // dl_runtime / dl_period
    pub dl_density: u64,    // dl_runtime / dl_deadline
    pub runtime: i64,       // Remaining runtime in current period
    pub deadline: u64,      // Absolute deadline
    pub flags: u32,
    pub dl_throttled: bool,
    pub dl_yielded: bool,
    pub dl_non_contending: bool,
    pub dl_overrun: bool,
    pub dl_boosted: bool,
    pub dl_server: bool,
    pub dl_defer: bool,
    pub dl_defer_armed: bool,
    pub dl_defer_running: bool,
    pub pi_se: u64,         // PI sched_dl_entity pointer
}

pub const SCHED_FLAG_DL_OVERRUN: u64 = 0x04;

// ============================================================================
// Bandwidth Control
// ============================================================================

pub struct CfsBandwidth {
    pub period: u64,
    pub quota: i64,
    pub runtime: i64,
    pub burst: i64,
    pub runtime_snap: i64,
    pub hierarchical_quota: i64,
    pub idle: bool,
    pub period_active: bool,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_time: u64,
    pub nr_burst: u64,
    pub burst_time: u64,
    pub period_timer: u64,
    pub slack_timer: u64,
    pub distribute_running: bool,
}

// ============================================================================
// Sched Statistics
// ============================================================================

pub struct SchedStatistics {
    pub wait_start: u64,
    pub wait_max: u64,
    pub wait_count: u64,
    pub wait_sum: u64,
    pub iowait_count: u64,
    pub iowait_sum: u64,
    pub sleep_start: u64,
    pub sleep_max: u64,
    pub sum_sleep_runtime: u64,
    pub block_start: u64,
    pub block_max: u64,
    pub nr_migrations_cold: u64,
    pub nr_failed_migrations_affine: u64,
    pub nr_failed_migrations_running: u64,
    pub nr_failed_migrations_hot: u64,
    pub nr_forced_migrations: u64,
    pub nr_wakeups: u64,
    pub nr_wakeups_sync: u64,
    pub nr_wakeups_migrate: u64,
    pub nr_wakeups_local: u64,
    pub nr_wakeups_remote: u64,
    pub nr_wakeups_affine: u64,
    pub nr_wakeups_affine_attempts: u64,
    pub nr_wakeups_passive: u64,
    pub nr_wakeups_idle: u64,
    pub core_forceidle_sum: u64,
}

impl SchedStatistics {
    pub const fn zeroed() -> Self {
        Self {
            wait_start: 0,
            wait_max: 0,
            wait_count: 0,
            wait_sum: 0,
            iowait_count: 0,
            iowait_sum: 0,
            sleep_start: 0,
            sleep_max: 0,
            sum_sleep_runtime: 0,
            block_start: 0,
            block_max: 0,
            nr_migrations_cold: 0,
            nr_failed_migrations_affine: 0,
            nr_failed_migrations_running: 0,
            nr_failed_migrations_hot: 0,
            nr_forced_migrations: 0,
            nr_wakeups: 0,
            nr_wakeups_sync: 0,
            nr_wakeups_migrate: 0,
            nr_wakeups_local: 0,
            nr_wakeups_remote: 0,
            nr_wakeups_affine: 0,
            nr_wakeups_affine_attempts: 0,
            nr_wakeups_passive: 0,
            nr_wakeups_idle: 0,
            core_forceidle_sum: 0,
        }
    }
}

// ============================================================================
// Global Stats
// ============================================================================

pub struct SchedClassStats {
    pub total_context_switches: u64,
    pub total_voluntary_switches: u64,
    pub total_involuntary_switches: u64,
    pub total_migrations: u64,
    pub total_rt_throttled: u64,
    pub total_dl_throttled: u64,
    pub total_cfs_throttled: u64,
    pub total_wakeups: u64,
}

impl SchedClassStats {
    pub const fn new() -> Self {
        Self {
            total_context_switches: 0,
            total_voluntary_switches: 0,
            total_involuntary_switches: 0,
            total_migrations: 0,
            total_rt_throttled: 0,
            total_dl_throttled: 0,
            total_cfs_throttled: 0,
            total_wakeups: 0,
        }
    }
}
