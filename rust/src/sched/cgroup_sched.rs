// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - Cgroup v2 Controllers, Process Accounting,
// CPU Scheduling Parameters, Task Priority Management
// More advanced than Linux 2026 cgroup/sched subsystem

/// Cgroup v2 controller types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController {
    Cpu = 0,
    Cpuset = 1,
    Memory = 2,
    Io = 3,
    Pids = 4,
    Rdma = 5,
    HugeTlb = 6,
    Cpuacct = 7,
    Devices = 8,
    Freezer = 9,
    NetCls = 10,
    NetPrio = 11,
    PerfEvent = 12,
    Misc = 13,
    // Zxyphor
    ZxyGpu = 50,
    ZxyNetwork = 51,
    ZxyStorage = 52,
}

/// Cgroup v2 CPU controller configuration
#[derive(Debug, Clone)]
pub struct CgroupCpuController {
    // cpu.max - bandwidth control
    pub quota_us: i64,           // -1 for unlimited
    pub period_us: u64,          // default 100000 (100ms)
    // cpu.weight
    pub weight: u32,             // 1-10000, default 100
    pub weight_nice: i32,        // -20 to +19 equivalent
    // cpu.max.burst
    pub burst_us: u64,
    // UCLAMP
    pub uclamp_min: u32,         // 0-1024
    pub uclamp_max: u32,         // 0-1024
    // cpu.pressure (PSI)
    pub psi_some_total_us: u64,
    pub psi_some_avg10: f32,
    pub psi_some_avg60: f32,
    pub psi_some_avg300: f32,
    pub psi_full_total_us: u64,
    pub psi_full_avg10: f32,
    pub psi_full_avg60: f32,
    pub psi_full_avg300: f32,
    // Stats
    pub usage_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    pub nr_bursts: u64,
    pub burst_usec: u64,
}

/// Cgroup v2 memory controller
#[derive(Debug, Clone)]
pub struct CgroupMemoryController {
    // Limits
    pub min: i64,             // memory.min (hard protection)
    pub low: i64,             // memory.low (best-effort protection)
    pub high: i64,            // memory.high (throttle)
    pub max: i64,             // memory.max (hard limit)
    pub swap_max: i64,
    pub swap_high: i64,
    pub zswap_max: i64,
    // Current usage
    pub current: u64,
    pub swap_current: u64,
    pub zswap_current: u64,
    pub peak: u64,
    pub swap_peak: u64,
    // Stats
    pub anon: u64,
    pub file: u64,
    pub kernel: u64,
    pub kernel_stack: u64,
    pub pagetables: u64,
    pub sec_pagetables: u64,
    pub percpu: u64,
    pub sock: u64,
    pub vmalloc: u64,
    pub shmem: u64,
    pub zswap: u64,
    pub zswapped: u64,
    pub file_mapped: u64,
    pub file_dirty: u64,
    pub file_writeback: u64,
    pub swapcached: u64,
    pub anon_thp: u64,
    pub file_thp: u64,
    pub shmem_thp: u64,
    pub inactive_anon: u64,
    pub active_anon: u64,
    pub inactive_file: u64,
    pub active_file: u64,
    pub unevictable: u64,
    pub slab_reclaimable: u64,
    pub slab_unreclaimable: u64,
    // Events
    pub low_events: u64,
    pub high_events: u64,
    pub max_events: u64,
    pub oom_events: u64,
    pub oom_kill_events: u64,
    pub oom_group_kill: u64,
    // PSI
    pub psi_some_total_us: u64,
    pub psi_full_total_us: u64,
    // NUMA stats
    pub numa_stat_enabled: bool,
    // OOM
    pub oom_group: bool,
}

/// Cgroup v2 IO controller
#[derive(Debug, Clone)]
pub struct CgroupIoController {
    // io.max (rate limits per device)
    pub rbps_max: u64,        // Read bytes/sec max
    pub wbps_max: u64,        // Write bytes/sec max
    pub riops_max: u64,       // Read IOPS max
    pub wiops_max: u64,       // Write IOPS max
    // io.weight
    pub weight: u32,          // 1-10000, default 100
    // io.latency
    pub latency_target_us: u64,
    // io.cost (cost model)
    pub cost_model_enabled: bool,
    pub cost_weight: u32,
    pub qos_rpct: u32,       // read latency percentile
    pub qos_rlat: u32,       // read latency target us
    pub qos_wpct: u32,
    pub qos_wlat: u32,
    pub qos_min: u32,
    pub qos_max: u32,
    // Stats
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
    pub dbytes: u64,          // discard bytes
    pub dios: u64,            // discard ios
    // PSI
    pub psi_some_total_us: u64,
    pub psi_full_total_us: u64,
}

/// Cgroup v2 cpuset controller
#[derive(Debug, Clone)]
pub struct CgroupCpusetController {
    pub cpus: [u8; 32],            // CPU bitmask
    pub cpus_effective: [u8; 32],
    pub mems: [u8; 32],            // Memory node bitmask
    pub mems_effective: [u8; 32],
    // Partition
    pub cpus_partition: CpusetPartition,
    // Flags
    pub cpu_exclusive: bool,
    pub mem_exclusive: bool,
    pub mem_hardwall: bool,
    pub memory_migrate: bool,
    pub sched_load_balance: bool,
    pub sched_relax_domain_level: i32,
    // Pressure stall
    pub nr_domain_migrations: u64,
}

/// Cpuset partition type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpusetPartition {
    Member = 0,
    Root = 1,
    Isolated = 2,
}

/// Cgroup v2 PIDs controller
#[derive(Debug, Clone)]
pub struct CgroupPidsController {
    pub max: i64,              // -1 for unlimited
    pub current: u64,
    pub peak: u64,
    pub events_max: u64,
}

/// Cgroup v2 HugeTLB controller
#[derive(Debug, Clone)]
pub struct CgroupHugetlbController {
    // Per huge page size limits
    pub limit_2mb: i64,
    pub limit_1gb: i64,
    pub current_2mb: u64,
    pub current_1gb: u64,
    pub max_events_2mb: u64,
    pub max_events_1gb: u64,
    pub rsvd_current_2mb: u64,
    pub rsvd_current_1gb: u64,
    pub rsvd_max_2mb: i64,
    pub rsvd_max_1gb: i64,
}

/// Cgroup v2 RDMA controller
#[derive(Debug, Clone)]
pub struct CgroupRdmaController {
    pub hca_handle_max: i32,
    pub hca_object_max: i32,
    pub hca_handle_current: u32,
    pub hca_object_current: u32,
}

/// Cgroup freezer state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupFreezerState {
    Running = 0,
    Freezing = 1,
    Frozen = 2,
}

// ============================================================================
// Process Accounting
// ============================================================================

/// Process accounting data (taskstats)
#[derive(Debug, Clone)]
pub struct TaskStats {
    pub version: u16,
    pub ac_exitcode: u32,
    pub ac_flag: u8,
    pub ac_nice: u8,
    // CPU statistics
    pub cpu_count: u64,
    pub cpu_delay_total: u64,      // ns
    pub blkio_count: u64,
    pub blkio_delay_total: u64,
    pub swapin_count: u64,
    pub swapin_delay_total: u64,
    // Time
    pub ac_btime: u64,             // Begin time (epoch seconds)
    pub ac_etime: u64,             // Elapsed time (us)
    pub ac_utime: u64,             // User CPU time (us)
    pub ac_stime: u64,             // System CPU time (us)
    // Memory
    pub coremem: u64,              // Accumulated RSS-time (MB-usec)
    pub virtmem: u64,              // Accumulated VM-time (MB-usec)
    pub hiwater_rss: u64,          // High-water RSS (KB)
    pub hiwater_vm: u64,           // High-water VM (KB)
    // IO
    pub read_char: u64,
    pub write_char: u64,
    pub read_syscalls: u64,
    pub write_syscalls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
    // Voluntary/involuntary switches
    pub nvcsw: u64,
    pub nivcsw: u64,
    // Timestamps
    pub ac_utimescaled: u64,
    pub ac_stimescaled: u64,
    pub cpu_scaled_run_real_total: u64,
    // Freepages delay
    pub freepages_count: u64,
    pub freepages_delay_total: u64,
    // Thrashing delay
    pub thrashing_count: u64,
    pub thrashing_delay_total: u64,
    // Compact delay
    pub compact_count: u64,
    pub compact_delay_total: u64,
    // IRQ delay
    pub irq_count: u64,
    pub irq_delay_total: u64,
    // Command
    pub ac_comm: [u8; 32],
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
}

/// Process scheduling parameters
#[derive(Debug, Clone)]
pub struct SchedAttr {
    pub size: u32,
    pub sched_policy: SchedPolicy,
    pub sched_flags: u64,
    // Nice / Priority
    pub sched_nice: i32,
    pub sched_priority: u32,
    // Deadline scheduling
    pub sched_runtime: u64,        // ns
    pub sched_deadline: u64,       // ns
    pub sched_period: u64,         // ns
    // UCLAMP
    pub sched_util_min: u32,       // 0-1024
    pub sched_util_max: u32,       // 0-1024
}

/// Scheduling policy
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    Normal = 0,
    Fifo = 1,
    Rr = 2,
    Batch = 3,
    Idle = 5,
    Deadline = 6,
    // Zxyphor
    ZxyAdaptive = 100,
}

/// Scheduling flags
pub const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
pub const SCHED_FLAG_RECLAIM: u64 = 0x02;
pub const SCHED_FLAG_DL_OVERRUN: u64 = 0x04;
pub const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
pub const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
pub const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
pub const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
pub const SCHED_FLAG_KEEP_ALL: u64 = SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS;
pub const SCHED_FLAG_UTIL_CLAMP: u64 = SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_UTIL_CLAMP_MAX;

// ============================================================================
// PSI (Pressure Stall Information)
// ============================================================================

/// PSI resource type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiResource {
    Cpu = 0,
    Memory = 1,
    Io = 2,
    Irq = 3,
}

/// PSI state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiState {
    Some = 0,
    Full = 1,
}

/// PSI data
#[derive(Debug, Clone)]
pub struct PsiData {
    pub resource: PsiResource,
    // Some (at least one task stalled)
    pub some_avg10: f32,
    pub some_avg60: f32,
    pub some_avg300: f32,
    pub some_total_us: u64,
    // Full (all tasks stalled)
    pub full_avg10: f32,
    pub full_avg60: f32,
    pub full_avg300: f32,
    pub full_total_us: u64,
}

/// PSI trigger
#[derive(Debug, Clone)]
pub struct PsiTrigger {
    pub resource: PsiResource,
    pub state: PsiState,
    pub threshold_us: u64,
    pub window_us: u64,
    pub nr_events: u64,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[derive(Debug, Clone)]
pub struct CgroupSchedSubsystem {
    // Cgroup hierarchy
    pub nr_cgroups: u64,
    pub nr_dying_cgroups: u64,
    // Controllers enabled
    pub enabled_controllers: u32,
    // Memory controller totals
    pub total_memory_usage: u64,
    pub total_memory_limit: u64,
    pub total_swap_usage: u64,
    pub total_oom_kills: u64,
    // CPU controller
    pub total_cpu_throttled: u64,
    pub total_cpu_burst: u64,
    // IO controller
    pub total_io_throttled: u64,
    // PIDs
    pub total_pids_limit_hit: u64,
    // Freezer
    pub nr_frozen_cgroups: u32,
    // Process accounting
    pub total_tasks_accounted: u64,
    // PSI
    pub psi_enabled: bool,
    pub global_psi_cpu: PsiData,
    pub global_psi_memory: PsiData,
    pub global_psi_io: PsiData,
    // Zxyphor
    pub zxy_adaptive_limits: bool,
    pub initialized: bool,
}
