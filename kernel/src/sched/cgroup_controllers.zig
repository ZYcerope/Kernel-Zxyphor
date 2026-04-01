// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Cgroup v2 Controllers and Resource Management
// CPU, memory, IO, PID, RDMA, HugeTLB, cpuset, misc controllers
// PSI (Pressure Stall Information), delegation, threaded cgroups
// More advanced than Linux 2026 cgroup v2 architecture

const std = @import("std");

// ============================================================================
// Cgroup v2 Hierarchy
// ============================================================================

pub const CGROUP_MAX_DEPTH: u32 = 32;
pub const CGROUP_MAX_CHILDREN: u32 = 4096;

pub const CgroupType = enum(u8) {
    domain = 0,
    domain_threaded = 1,
    domain_invalid = 2,
    threaded = 3,
};

pub const CgroupSubsysId = enum(u8) {
    cpu = 0,
    memory = 1,
    io = 2,
    pids = 3,
    rdma = 4,
    hugetlb = 5,
    cpuset = 6,
    misc = 7,
    perf_event = 8,
    freezer = 9,
    // Zxyphor
    zxy_energy = 10,
    zxy_network = 11,
};

pub const NR_CGROUP_SUBSYS: u32 = 12;

pub const CgroupFlags = packed struct {
    populate_frozen: bool,
    frozen: bool,
    kill: bool,
    // Controller-specific
    cpu_enabled: bool,
    memory_enabled: bool,
    io_enabled: bool,
    pids_enabled: bool,
    rdma_enabled: bool,
    hugetlb_enabled: bool,
    cpuset_enabled: bool,
    misc_enabled: bool,
    perf_event_enabled: bool,
    freezer_enabled: bool,
    zxy_energy_enabled: bool,
    zxy_network_enabled: bool,
    _padding: u1 = 0,
};

pub const CgroupNode = struct {
    // Identity
    id: u64,
    name: [256]u8,
    name_len: u16,
    // Hierarchy
    parent: ?*CgroupNode,
    children: [CGROUP_MAX_CHILDREN]?*CgroupNode,
    nr_children: u32,
    depth: u32,
    // Type
    cgroup_type: CgroupType,
    flags: CgroupFlags,
    // Subtree control
    subtree_control: u16,
    // Processes
    nr_procs: u32,
    nr_threads: u32,
    nr_dying_descendants: u32,
    nr_populated_csets: u32,
    // Freezer
    frozen: bool,
    // Events
    events_populated: u64,
    events_frozen: u64,
    // Pressure
    psi: PsiGroup,
    // Controllers
    cpu_ctrl: CpuController,
    memory_ctrl: MemoryController,
    io_ctrl: IoController,
    pids_ctrl: PidsController,
    cpuset_ctrl: CpusetController,
    hugetlb_ctrl: HugeTlbController,
};

// ============================================================================
// CPU Controller
// ============================================================================

pub const CpuController = struct {
    // cpu.weight (1-10000, default 100)
    weight: u32,
    weight_nice: i32,
    // cpu.max (quota period)
    max_quota_us: i64,    // -1 = max
    max_period_us: u64,   // Default 100000 (100ms)
    // cpu.max.burst
    burst_us: u64,
    // Statistics
    usage_usec: u64,
    user_usec: u64,
    system_usec: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_usec: u64,
    nr_bursts: u64,
    burst_usec: u64,
    // Uclamp
    uclamp_min: u32,     // 0-1024
    uclamp_max: u32,     // 0-1024
    // EEVDF/CFS
    idle: bool,           // cpu.idle (deprioritize)
    // Pressure
    pressure_some: u64,
    pressure_full: u64,

    pub fn is_throttled(self: *const CpuController) bool {
        return self.max_quota_us > 0 and self.throttled_usec > 0;
    }

    pub fn throttle_ratio(self: *const CpuController) f64 {
        if (self.nr_periods == 0) return 0.0;
        return @as(f64, @floatFromInt(self.nr_throttled)) /
            @as(f64, @floatFromInt(self.nr_periods));
    }
};

// ============================================================================
// Memory Controller
// ============================================================================

pub const MemoryController = struct {
    // Limits
    min: u64,             // memory.min (hard protection)
    low: u64,             // memory.low (best-effort protection)
    high: u64,            // memory.high (throttle)
    max: u64,             // memory.max (hard limit)
    // Swap
    swap_max: u64,        // memory.swap.max
    swap_high: u64,       // memory.swap.high
    // zswap
    zswap_max: u64,       // memory.zswap.max
    zswap_writeback: bool, // memory.zswap.writeback
    // Current usage
    current: u64,         // memory.current
    swap_current: u64,    // memory.swap.current
    zswap_current: u64,   // memory.zswap.current
    // Peak
    peak: u64,            // memory.peak
    swap_peak: u64,       // memory.swap.peak
    // Statistics (memory.stat)
    anon: u64,
    file: u64,
    kernel: u64,
    kernel_stack: u64,
    pagetables: u64,
    sec_pagetables: u64,
    percpu: u64,
    sock: u64,
    vmalloc: u64,
    shmem: u64,
    zswap: u64,
    zswapped: u64,
    file_mapped: u64,
    file_dirty: u64,
    file_writeback: u64,
    swapcached: u64,
    anon_thp: u64,
    file_thp: u64,
    shmem_thp: u64,
    inactive_anon: u64,
    active_anon: u64,
    inactive_file: u64,
    active_file: u64,
    unevictable: u64,
    slab_reclaimable: u64,
    slab_unreclaimable: u64,
    pgfault: u64,
    pgmajfault: u64,
    workingset_refault_anon: u64,
    workingset_refault_file: u64,
    workingset_activate_anon: u64,
    workingset_activate_file: u64,
    workingset_restore_anon: u64,
    workingset_restore_file: u64,
    workingset_nodereclaim: u64,
    pgrefill: u64,
    pgscan: u64,
    pgsteal: u64,
    pgactivate: u64,
    pgdeactivate: u64,
    pglazyfree: u64,
    pglazyfreed: u64,
    thp_fault_alloc: u64,
    thp_collapse_alloc: u64,
    // Events (memory.events)
    events_low: u64,
    events_high: u64,
    events_max: u64,
    events_oom: u64,
    events_oom_kill: u64,
    events_oom_group_kill: u64,
    // NUMA stats
    numa_stat: [64]MemcgNuma,
    nr_numa_nodes: u32,
    // OOM
    oom_group: bool,
    // Reclaim
    reclaim_active: u64,   // memory.reclaim
    // Pressure
    pressure_some: u64,
    pressure_full: u64,
};

pub const MemcgNuma = struct {
    node_id: u32,
    anon: u64,
    file: u64,
    kernel_stack: u64,
    pagetables: u64,
    shmem: u64,
    file_mapped: u64,
    file_dirty: u64,
    file_writeback: u64,
    swapcached: u64,
    anon_thp: u64,
    file_thp: u64,
    shmem_thp: u64,
    inactive_anon: u64,
    active_anon: u64,
    inactive_file: u64,
    active_file: u64,
    unevictable: u64,
};

// ============================================================================
// IO Controller (io.max / io.weight)
// ============================================================================

pub const IoController = struct {
    // io.weight (1-10000, default 100)
    default_weight: u32,
    // Per-device configs
    devices: [64]IoDeviceConfig,
    nr_devices: u32,
    // io.stat (per-device statistics)
    stats: [64]IoStat,
    nr_stats: u32,
    // io.pressure
    pressure_some: u64,
    pressure_full: u64,
};

pub const IoDeviceConfig = struct {
    major: u32,
    minor: u32,
    // io.max settings
    rbps: u64,        // Read bytes per second (0=max)
    wbps: u64,        // Write bytes per second
    riops: u64,       // Read I/O operations per second
    wiops: u64,       // Write I/O operations per second
    // io.weight
    weight: u32,
    // io.latency
    target_latency_us: u64,
};

pub const IoStat = struct {
    major: u32,
    minor: u32,
    rbytes: u64,
    wbytes: u64,
    rios: u64,
    wios: u64,
    dbytes: u64,       // Discard
    dios: u64,
    cost_usage: u64,
    cost_wait: u64,
    cost_indebt: u64,
    cost_indelay: u64,
};

// ============================================================================
// PIDs Controller
// ============================================================================

pub const PidsController = struct {
    max: i64,           // pids.max (-1 = max)
    current: u64,       // pids.current
    peak: u64,          // pids.peak
    events_max: u64,    // pids.events max-exceeded count
};

// ============================================================================
// Cpuset Controller
// ============================================================================

pub const CpusetController = struct {
    // cpuset.cpus
    cpus: [16]u64,      // CPU bitmask (1024 CPUs max)
    // cpuset.cpus.effective
    cpus_effective: [16]u64,
    // cpuset.mems
    mems: [16]u64,      // NUMA node bitmask
    // cpuset.mems.effective
    mems_effective: [16]u64,
    // cpuset.cpus.partition
    partition: CpusetPartition,
    // cpuset.cpus.exclusive
    cpus_exclusive: [16]u64,
    cpus_exclusive_effective: [16]u64,
    // Flags
    cpu_exclusive: bool,
    mem_exclusive: bool,
    mem_hardwall: bool,
    memory_migrate: bool,
    sched_load_balance: bool,
    spread_page: bool,
    spread_slab: bool,
    memory_pressure_enabled: bool,
    // Stats
    memory_pressure: u64,

    pub fn cpu_count(self: *const CpusetController) u32 {
        var count: u32 = 0;
        for (self.cpus) |word| {
            count += @popCount(word);
        }
        return count;
    }

    pub fn mem_count(self: *const CpusetController) u32 {
        var count: u32 = 0;
        for (self.mems) |word| {
            count += @popCount(word);
        }
        return count;
    }
};

pub const CpusetPartition = enum(u8) {
    member = 0,
    root = 1,
    isolated = 2,
};

// ============================================================================
// HugeTLB Controller
// ============================================================================

pub const HugeTlbController = struct {
    // Per page-size limits
    sizes: [4]HugeTlbSizeConfig,
    nr_sizes: u32,
};

pub const HugeTlbSizeConfig = struct {
    page_size: u64,        // e.g., 2MB, 1GB
    max: u64,              // Max bytes
    current: u64,
    rsvd_max: u64,         // Reserved max
    rsvd_current: u64,
    events_max: u64,
};

// ============================================================================
// PSI (Pressure Stall Information)
// ============================================================================

pub const PsiResource = enum(u8) {
    cpu = 0,
    memory = 1,
    io = 2,
    irq = 3,
};

pub const PsiState = enum(u8) {
    some = 0,
    full = 1,
};

pub const PsiGroup = struct {
    // Averages (fixed-point, *100)
    avg10: [4][2]u64,    // [resource][some/full]
    avg60: [4][2]u64,
    avg300: [4][2]u64,
    total: [4][2]u64,    // Total stall time (us)

    pub fn get_avg10(self: *const PsiGroup, resource: PsiResource, state: PsiState) f64 {
        return @as(f64, @floatFromInt(self.avg10[@intFromEnum(resource)][@intFromEnum(state)])) / 100.0;
    }

    pub fn get_avg60(self: *const PsiGroup, resource: PsiResource, state: PsiState) f64 {
        return @as(f64, @floatFromInt(self.avg60[@intFromEnum(resource)][@intFromEnum(state)])) / 100.0;
    }
};

pub const PsiTrigger = struct {
    state: PsiState,
    threshold_us: u64,
    window_us: u64,
    // Growth since window start
    growth: u64,
    pending: bool,
    last_event_time: u64,
};

// ============================================================================
// Misc Controller
// ============================================================================

pub const MiscResource = enum(u8) {
    sev = 0,           // AMD SEV
    sev_es = 1,
    sev_snp = 2,
    tdx = 3,           // Intel TDX
    // Zxyphor
    zxy_accel = 4,
};

pub const MiscController = struct {
    resources: [8]MiscResourceConfig,
    nr_resources: u32,
};

pub const MiscResourceConfig = struct {
    res_type: MiscResource,
    max: u64,
    current: u64,
    events_max: u64,
    capacity: u64,      // System-wide capacity
};

// ============================================================================
// Cgroup BPF
// ============================================================================

pub const CgroupBpfAttachType = enum(u8) {
    ingress = 0,
    egress = 1,
    sock_create = 2,
    sock_ops = 3,
    device = 4,
    bind4 = 5,
    bind6 = 6,
    post_bind4 = 7,
    post_bind6 = 8,
    connect4 = 9,
    connect6 = 10,
    sendmsg4 = 11,
    sendmsg6 = 12,
    recvmsg4 = 13,
    recvmsg6 = 14,
    getsockopt = 15,
    setsockopt = 16,
    getpeername4 = 17,
    getpeername6 = 18,
    getsockname4 = 19,
    getsockname6 = 20,
    sysctl = 21,
    inet_ingress = 22,
    inet_egress = 23,
    inet4_lookup = 24,
    inet6_lookup = 25,
    lsm = 26,
};

// ============================================================================
// Cgroup v2 Delegation and Notifications
// ============================================================================

pub const CgroupDelegation = struct {
    // Delegated subtree root
    cgroup: ?*CgroupNode,
    // Delegatee
    delegate_pid: i32,
    // Which controllers are delegated
    delegated_controllers: u16,
    // File permissions
    delegate_files: u64,  // Bitmask of which files
};

pub const CgroupEvent = struct {
    event_type: CgroupEventType,
    cgroup_id: u64,
    timestamp: u64,
    data: u64,
};

pub const CgroupEventType = enum(u8) {
    populated = 0,
    not_populated = 1,
    frozen = 2,
    thawed = 3,
    oom = 4,
    memory_high = 5,
    memory_max = 6,
    pids_max = 7,
    io_latency = 8,
};

// ============================================================================
// Cgroup v2 Subsystem Manager
// ============================================================================

pub const CgroupSubsystem = struct {
    // Root cgroup
    root: ?*CgroupNode,
    // Stats
    nr_cgroups: u64,
    nr_dying_cgroups: u64,
    // Configuration
    default_cpu_weight: u32,
    default_io_weight: u32,
    // Unified hierarchy mount path
    mount_path: [256]u8,
    // PSI (system-wide)
    system_psi: PsiGroup,
    // Available controllers
    available_controllers: u16,
    // Delegation
    default_delegation: CgroupDelegation,
    // Events
    total_events: u64,
    // BPF
    nr_bpf_programs: u32,
    // Zxyphor
    zxy_auto_tuning: bool,
    zxy_energy_controller: bool,
    initialized: bool,

    pub fn pressure_cpu_some(self: *const CgroupSubsystem) f64 {
        return self.system_psi.get_avg10(.cpu, .some);
    }

    pub fn pressure_memory_some(self: *const CgroupSubsystem) f64 {
        return self.system_psi.get_avg10(.memory, .some);
    }

    pub fn pressure_io_some(self: *const CgroupSubsystem) f64 {
        return self.system_psi.get_avg10(.io, .some);
    }
};
