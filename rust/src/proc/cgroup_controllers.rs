// Zxyphor Kernel - Cgroup v2 Controllers Advanced,
// CPU Controller, Memory Controller, IO Controller,
// PID Controller, RDMA Controller, HugeTLB Controller,
// Misc Controller, Freezer, Cpuset
// More advanced than Linux 2026 cgroup subsystem

use core::fmt;

// ============================================================================
// Cgroup v2 Core Types
// ============================================================================

/// Cgroup controller type
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController {
    Cpu = 0,
    Memory = 1,
    Io = 2,
    Pids = 3,
    Cpuset = 4,
    Rdma = 5,
    HugeTlb = 6,
    Misc = 7,
    Perf = 8,
    Freezer = 9,
    // Cgroup v1 only
    Devices = 10,
    NetCls = 11,
    NetPrio = 12,
    Blkio = 13,
    // Zxyphor native
    ZxyIsolation = 100,
    ZxyEnergy = 101,
    ZxyQos = 102,
}

/// Cgroup type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CgroupType {
    Domain = 0,
    DomainThreaded = 1,
    Threaded = 2,
    DomainInvalid = 3,
}

/// Cgroup subtree control mask
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct CgroupSubtreeControl(pub u32);

impl CgroupSubtreeControl {
    pub const CPU: Self = Self(1 << 0);
    pub const MEMORY: Self = Self(1 << 1);
    pub const IO: Self = Self(1 << 2);
    pub const PIDS: Self = Self(1 << 3);
    pub const CPUSET: Self = Self(1 << 4);
    pub const RDMA: Self = Self(1 << 5);
    pub const HUGETLB: Self = Self(1 << 6);
    pub const MISC: Self = Self(1 << 7);
}

/// Cgroup stat
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CgroupStat {
    pub nr_descendants: u32,
    pub nr_dying_descendants: u32,
}

/// Cgroup events
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CgroupEvents {
    pub populated: bool,
    pub frozen: bool,
}

/// Cgroup freezer state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CgroupFreezerState {
    Thawed = 0,
    Freezing = 1,
    Frozen = 2,
}

// ============================================================================
// CPU Controller
// ============================================================================

/// CPU controller configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CpuControllerConfig {
    pub weight: u32,               // [1, 10000] default 100
    pub weight_nice: i32,          // [-20, 19] mapped to weight
    pub max_quota_us: i64,         // max bandwidth quota (-1 for unlimited)
    pub max_period_us: u64,        // bandwidth period (default 100000)
    pub burst_us: u64,             // burst bandwidth
    pub uclamp_min: u32,           // utilization clamp min [0, 1024]
    pub uclamp_max: u32,           // utilization clamp max [0, 1024]
    pub idle: bool,                // idle hint
}

/// CPU controller stats
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CpuControllerStats {
    pub usage_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    pub nr_bursts: u64,
    pub burst_usec: u64,
    // PSI
    pub psi_some_total_us: u64,
    pub psi_full_total_us: u64,
    pub psi_some_avg10: f32,
    pub psi_some_avg60: f32,
    pub psi_some_avg300: f32,
    pub psi_full_avg10: f32,
    pub psi_full_avg60: f32,
    pub psi_full_avg300: f32,
}

// ============================================================================
// Memory Controller
// ============================================================================

/// Memory controller configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemControllerConfig {
    pub min: i64,                  // memory.min (hard minimum, -1 for default)
    pub low: i64,                  // memory.low (best-effort minimum)
    pub high: i64,                 // memory.high (throttle above this)
    pub max: i64,                  // memory.max (hard limit, -1 for max)
    pub swap_high: i64,
    pub swap_max: i64,
    pub zswap_max: i64,
    pub zswap_writeback: bool,
    pub oom_group: bool,
}

/// Memory controller stats
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemControllerStats {
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
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub pgrefill: u64,
    pub pgscan: u64,
    pub pgsteal: u64,
    pub pgactivate: u64,
    pub pgdeactivate: u64,
    pub pglazyfree: u64,
    pub pglazyfreed: u64,
    pub thp_fault_alloc: u64,
    pub thp_collapse_alloc: u64,
    // Watermark
    pub workingset_refault_anon: u64,
    pub workingset_refault_file: u64,
    pub workingset_activate_anon: u64,
    pub workingset_activate_file: u64,
    pub workingset_restore_anon: u64,
    pub workingset_restore_file: u64,
    pub workingset_nodereclaim: u64,
    // NUMA
    pub numa_pages_migrated: u64,
    pub numa_pte_updates: u64,
    pub numa_hint_faults: u64,
    // PSI
    pub psi_some_total_us: u64,
    pub psi_full_total_us: u64,
}

/// Memory events
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

// ============================================================================
// IO Controller
// ============================================================================

/// IO controller weight configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IoWeightConfig {
    pub default_weight: u32,
    pub nr_device_weights: u32,
    pub device_weights: [IoDeviceWeight; 16],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct IoDeviceWeight {
    pub major: u32,
    pub minor: u32,
    pub weight: u32,
}

/// IO controller max configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IoMaxConfig {
    pub major: u32,
    pub minor: u32,
    pub rbps: i64,
    pub wbps: i64,
    pub riops: i64,
    pub wiops: i64,
}

/// IO controller stats
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IoControllerStats {
    pub major: u32,
    pub minor: u32,
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
    pub dbytes: u64,
    pub dios: u64,
    pub cost_usage: u64,
    pub cost_wait: u64,
    pub cost_indebt: u64,
    pub cost_indelay: u64,
}

/// IO latency target
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IoLatencyTarget {
    pub major: u32,
    pub minor: u32,
    pub target_us: u64,
}

// ============================================================================
// PID Controller
// ============================================================================

/// PID controller configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PidControllerConfig {
    pub max: i64,     // -1 for max (no limit), otherwise the limit
}

/// PID controller stats
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PidControllerStats {
    pub current: u64,
    pub events_max: u64,
}

// ============================================================================
// Cpuset Controller
// ============================================================================

/// Cpuset partition type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CpusetPartition {
    Member = 0,
    Root = 1,
    Isolated = 2,
}

/// Cpuset controller configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CpusetConfig {
    pub cpus: [u64; 4],        // bitmask for up to 256 CPUs
    pub cpus_effective: [u64; 4],
    pub mems: [u64; 4],        // NUMA node bitmask
    pub mems_effective: [u64; 4],
    pub partition: CpusetPartition,
    pub cpu_exclusive: bool,
    pub mem_exclusive: bool,
    pub mem_hardwall: bool,
    pub memory_migrate: bool,
    pub sched_load_balance: bool,
    pub memory_pressure_enabled: bool,
    pub memory_spread_page: bool,
    pub memory_spread_slab: bool,
    pub sched_relax_domain_level: i32,
}

// ============================================================================
// RDMA Controller
// ============================================================================

/// RDMA resource limits
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RdmaResourceLimits {
    pub hca_handle_max: u32,
    pub hca_object_max: u32,
}

/// RDMA resource usage
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RdmaResourceUsage {
    pub hca_handle_current: u32,
    pub hca_object_current: u32,
}

// ============================================================================
// HugeTLB Controller
// ============================================================================

/// HugeTLB controller limits per size
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HugeTlbLimits {
    pub page_size_kb: u64,
    pub max: i64,
    pub rsvd_max: i64,
    pub current: u64,
    pub rsvd_current: u64,
    pub events_max: u64,
}

// ============================================================================
// Misc Controller
// ============================================================================

/// Misc resource type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MiscResourceType {
    SevPages = 0,
    SevEsPages = 1,
    TdxPages = 2,
}

/// Misc resource config
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MiscResourceConfig {
    pub res_type: MiscResourceType,
    pub max: i64,
    pub current: u64,
    pub events_max: u64,
}

// ============================================================================
// Cgroup Pressure Stall Information (PSI)
// ============================================================================

/// PSI trigger configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CgroupPsiTrigger {
    pub resource: CgroupPsiResource,
    pub threshold_us: u64,
    pub window_us: u64,
    pub full: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CgroupPsiResource {
    Cpu = 0,
    Memory = 1,
    Io = 2,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct CgroupAdvancedSubsystem {
    pub v2_enabled: bool,
    pub unified_hierarchy: bool,
    pub nr_cgroups: u64,
    pub nr_controllers: u32,
    pub active_controllers: CgroupSubtreeControl,
    pub nr_frozen: u32,
    pub nr_psi_triggers: u32,
    pub default_cpu_weight: u32,
    pub default_io_weight: u32,
    pub initialized: bool,
}

impl CgroupAdvancedSubsystem {
    pub const fn new() -> Self {
        Self {
            v2_enabled: true,
            unified_hierarchy: true,
            nr_cgroups: 0,
            nr_controllers: 0,
            active_controllers: CgroupSubtreeControl(0),
            nr_frozen: 0,
            nr_psi_triggers: 0,
            default_cpu_weight: 100,
            default_io_weight: 100,
            initialized: false,
        }
    }
}
