// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Cgroup v2 Resource Controllers Detail
// Complete: cpu, memory, io, pids, cpuset, hugetlb, rdma, misc, freezer
// Advanced: PSI (Pressure Stall Information), delegation, threaded mode

const std = @import("std");

// ============================================================================
// Cgroup v2 Core
// ============================================================================

pub const CgroupSubsysId = enum(u8) {
    Cpuset = 0,
    Cpu = 1,
    Cpuacct = 2,
    Io = 3,
    Memory = 4,
    Devices = 5,
    Freezer = 6,
    NetCls = 7,
    PerfEvent = 8,
    NetPrio = 9,
    HugeTlb = 10,
    Pids = 11,
    Rdma = 12,
    Misc = 13,
};

pub const CgroupType = enum(u8) {
    Domain = 0,
    DomainThreaded = 1,
    Threaded = 2,
    DomainInvalid = 3,
};

pub const CgroupFlags = packed struct(u32) {
    populated: bool,
    frozen: bool,
    killed: bool,
    dying: bool,
    dead: bool,
    release_agent_path: bool,
    _reserved: u26,
};

pub const Cgroup = struct {
    self_css: CgroupSubsysState,
    id: u64,
    level: u32,
    max_depth: u32,
    nr_descendants: u32,
    nr_dying_descendants: u32,
    max_descendants: u32,
    nr_populated_csets: u32,
    nr_populated_domain_children: u32,
    nr_populated_threaded_children: u32,
    nr_threaded_children: u32,
    flags: CgroupFlags,
    cgroup_type: CgroupType,
    subtree_control: u32,
    subtree_ss_mask: u32,
    old_subtree_control: u32,
    old_subtree_ss_mask: u32,
    child_ss_mask: u32,
    dom_cgrp: ?*Cgroup,
    parent: ?*Cgroup,
    psi: ?*PsiGroup,
    freeze_cnt: u32,
};

pub const CgroupSubsysState = struct {
    cgroup: ?*Cgroup,
    subsys: ?*CgroupSubsys,
    parent: ?*CgroupSubsysState,
    sibling: ?*CgroupSubsysState,
    children: ?*CgroupSubsysState,
    id: u64,
    flags: u32,
    serial_nr: u64,
    online_cnt: u32,
    refcnt: u32,
};

pub const CgroupSubsys = struct {
    css_alloc: ?*const fn (?*CgroupSubsysState) callconv(.C) ?*CgroupSubsysState,
    css_online: ?*const fn (*CgroupSubsysState) callconv(.C) i32,
    css_offline: ?*const fn (*CgroupSubsysState) callconv(.C) void,
    css_released: ?*const fn (*CgroupSubsysState) callconv(.C) void,
    css_free: ?*const fn (*CgroupSubsysState) callconv(.C) void,
    css_reset: ?*const fn (*CgroupSubsysState) callconv(.C) void,
    css_rstat_flush: ?*const fn (*CgroupSubsysState, i32) callconv(.C) void,
    css_extra_stat_show: ?*const fn (*anyopaque, *CgroupSubsysState) callconv(.C) i32,
    can_attach: ?*const fn (*CgroupTaskset) callconv(.C) i32,
    cancel_attach: ?*const fn (*CgroupTaskset) callconv(.C) void,
    attach: ?*const fn (*CgroupTaskset) callconv(.C) void,
    post_attach: ?*const fn () callconv(.C) void,
    can_fork: ?*const fn (*anyopaque, *CgroupSubsysState) callconv(.C) i32,
    cancel_fork: ?*const fn (*anyopaque, *CgroupSubsysState) callconv(.C) void,
    fork: ?*const fn (*anyopaque) callconv(.C) void,
    exit: ?*const fn (*anyopaque) callconv(.C) void,
    release: ?*const fn (*anyopaque) callconv(.C) void,
    bind: ?*const fn (*CgroupSubsysState) callconv(.C) void,
    id: CgroupSubsysId,
    name: [64]u8,
    root: ?*anyopaque,
    implicit_on_dfl: bool,
    threaded: bool,
    early_init: bool,
    broken_hierarchy: bool,
    warned_broken_hierarchy: bool,
};

pub const CgroupTaskset = struct {
    src_csets: ?*anyopaque,
    dst_csets: ?*anyopaque,
    nr_tasks: u32,
    ssid: u32,
};

// ============================================================================
// CPU Controller
// ============================================================================

pub const CpuCgroupData = struct {
    weight: u32,
    weight_nice: i32,
    max_period: u64,
    max_quota: i64,
    max_burst: u64,
    idle: bool,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_time: u64,
    nr_bursts: u64,
    burst_time: u64,
    cfs_bandwidth: CfsBandwidth,
    rt_bandwidth: RtBandwidth,
};

pub const CPU_WEIGHT_MIN: u32 = 1;
pub const CPU_WEIGHT_DEFAULT: u32 = 100;
pub const CPU_WEIGHT_MAX: u32 = 10000;
pub const CPU_WEIGHT_IDLE: u32 = 0;

pub const CfsBandwidth = struct {
    period: u64,
    quota: i64,
    burst: u64,
    runtime: i64,
    runtime_snap: i64,
    hierarchical_quota: i64,
    idle: bool,
    period_active: bool,
    slack_started: bool,
    distribute_running: bool,
    timer_active: bool,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_time: u64,
    nr_bursts: u64,
    burst_time: u64,
};

pub const RtBandwidth = struct {
    rt_period: u64,
    rt_runtime: i64,
    rt_period_timer: u64,
    rt_runtime_lock: u64,
};

// ============================================================================
// Memory Controller
// ============================================================================

pub const MemoryCgroupData = struct {
    memory_current: u64,
    memory_min: u64,
    memory_low: u64,
    memory_high: u64,
    memory_max: u64,
    swap_current: u64,
    swap_high: u64,
    swap_max: u64,
    zswap_current: u64,
    zswap_max: u64,
    zswap_writeback: bool,
    oom_group: bool,
    oom_kill_disable: bool,
    use_hierarchy: bool,
    tcpmem_active: bool,
    soft_limit: u64,
    stats: MemcgStats,
    events: MemcgEvents,
    watermark: MemcgWatermark,
    charging_css: ?*CgroupSubsysState,
    vmstats: ?*MemcgVmstats,
};

pub const MEMORY_MIN_DEFAULT: u64 = 0;
pub const MEMORY_LOW_DEFAULT: u64 = 0;
pub const MEMORY_HIGH_DEFAULT: u64 = 0xFFFF_FFFF_FFFF_FFFF;
pub const MEMORY_MAX_DEFAULT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub const MemcgStats = struct {
    cache: u64,
    rss: u64,
    rss_huge: u64,
    shmem: u64,
    mapped_file: u64,
    dirty: u64,
    writeback: u64,
    pgpgin: u64,
    pgpgout: u64,
    pgfault: u64,
    pgmajfault: u64,
    inactive_anon: u64,
    active_anon: u64,
    inactive_file: u64,
    active_file: u64,
    unevictable: u64,
    slab_reclaimable: u64,
    slab_unreclaimable: u64,
    kernel_stack: u64,
    pagetables: u64,
    sec_pagetables: u64,
    sock: u64,
    shmem_pmdmapped: u64,
    file_pmdmapped: u64,
    file_thp: u64,
    shmem_thp: u64,
    anon_thp: u64,
    file_writeback: u64,
    zswap: u64,
    zswapped: u64,
    thp_fault_alloc: u64,
    thp_collapse_alloc: u64,
    workingset_refault_anon: u64,
    workingset_refault_file: u64,
    workingset_activate_anon: u64,
    workingset_activate_file: u64,
    workingset_restore_anon: u64,
    workingset_restore_file: u64,
    workingset_nodereclaim: u64,
    pgscan: u64,
    pgsteal: u64,
    pgscan_kswapd: u64,
    pgscan_direct: u64,
    pgsteal_kswapd: u64,
    pgsteal_direct: u64,
    pgactivate: u64,
    pgdeactivate: u64,
    pglazyfree: u64,
    pglazyfreed: u64,
};

pub const MemcgEvents = struct {
    low: u64,
    high: u64,
    max: u64,
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
};

pub const MemcgWatermark = struct {
    high_watermark: u64,
    failcnt: u64,
};

pub const MemcgVmstats = struct {
    state: [48]i64,
    state_local: [48]i64,
    events: [32]u64,
    events_local: [32]u64,
    state_pending: [48]i64,
    events_pending: [32]u64,
};

// ============================================================================
// IO Controller
// ============================================================================

pub const IoCgroupData = struct {
    model: IoModel,
    qos_params: IoQosParams,
    cost_model: IoCostModelParams,
    weight: u32,
    stats: IoCgroupStats,
};

pub const IO_WEIGHT_MIN: u32 = 1;
pub const IO_WEIGHT_DEFAULT: u32 = 100;
pub const IO_WEIGHT_MAX: u32 = 10000;

pub const IoModel = enum(u8) {
    None = 0,
    Cost = 1,
    Weight = 2,
};

pub const IoQosParams = struct {
    enable: bool,
    rlat: u64,      // Read latency target (us)
    wlat: u64,      // Write latency target (us)
    rpct: u32,       // Read latency percentile
    wpct: u32,       // Write latency percentile
    min: u32,        // Min vrate
    max: u32,        // Max vrate
};

pub const IoCostModelParams = struct {
    rbps: u64,
    rseqiops: u64,
    rrandiops: u64,
    wbps: u64,
    wseqiops: u64,
    wrandiops: u64,
};

pub const IoCgroupStats = struct {
    rbytes: u64,
    wbytes: u64,
    rios: u64,
    wios: u64,
    dbytes: u64,
    dios: u64,
    cost: u64,
    usage: u64,
    wait: u64,
    indebt: u64,
    indelay: u64,
};

// ============================================================================
// PIDs Controller
// ============================================================================

pub const PidsCgroupData = struct {
    current: u64,
    limit: u64,
    events_max: u64,
};

pub const PIDS_MAX_DEFAULT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// ============================================================================
// Cpuset Controller
// ============================================================================

pub const CpusetCgroupData = struct {
    cpus: [16]u64,          // CPU affinity mask (1024 CPUs max)
    mems: [16]u64,          // Memory node mask
    cpus_effective: [16]u64,
    mems_effective: [16]u64,
    partition_type: CpusetPartitionType,
    spread_page: bool,
    spread_slab: bool,
    memory_migrate: bool,
    sched_load_balance: bool,
    sched_relax_domain_level: i32,
    memory_pressure_enabled: bool,
    memory_pressure: u32,
    subparts_cpus: [16]u64,
    nr_subparts_cpus: u32,
    nr_subparts: u32,
};

pub const CpusetPartitionType = enum(u8) {
    Member = 0,
    Root = 1,
    Isolated = 2,
    InvalidRoot = 3,
    InvalidIsolated = 4,
};

// ============================================================================
// HugeTLB Controller
// ============================================================================

pub const HugetlbCgroupData = struct {
    rsvd_current: [3]u64,    // Index by page size (2MB, 1GB, etc.)
    rsvd_max: [3]u64,
    current: [3]u64,
    max: [3]u64,
    events_max: [3]u64,
};

// ============================================================================
// RDMA Controller
// ============================================================================

pub const RdmaCgroupData = struct {
    hca_handle_max: u32,
    hca_object_max: u32,
    hca_handle_current: u32,
    hca_object_current: u32,
};

// ============================================================================
// Misc Controller
// ============================================================================

pub const MiscCgroupType = enum(u8) {
    SevAsid = 0,
    SevEsAsid = 1,
    TdxGuest = 2,
};

pub const MiscCgroupData = struct {
    current: [3]u64,
    max: [3]u64,
    events_max: [3]u64,
};

// ============================================================================
// PSI (Pressure Stall Information)
// ============================================================================

pub const PsiResource = enum(u8) {
    Cpu = 0,
    Memory = 1,
    Io = 2,
    Irq = 3,
};

pub const PsiState = enum(u8) {
    None = 0,
    Some = 1,
    Full = 2,
};

pub const PsiGroup = struct {
    pcpu: ?*PsiGroupCpu,
    total: [4][3]u64,           // [resource][state] total stall time
    avg: [4][3]PsiAvg,          // [resource][state] exponential moving averages
    avg_total: [4][3]u64,       // Total time for average computation
    avg_last_update: u64,
    avg_next_update: u64,
    poll_task: ?*anyopaque,
    poll_timer: u64,
    poll_wait: u64,
    triggers: ?*PsiTrigger,
    nr_triggers: [4]u32,
    poll_states: u32,
    poll_min_period: u64,
    polling_total: [4]u64,
    polling_next_update: u64,
    polling_until: u64,
};

pub const PsiGroupCpu = struct {
    state_mask: u32,
    times: [4][3]u32,           // Per-cpu stall times
    state_start: u64,
    times_prev: [4]u64,
};

pub const PsiAvg = struct {
    avg10: u64,
    avg60: u64,
    avg300: u64,
    total: u64,
};

pub const PsiTrigger = struct {
    state: PsiState,
    resource: PsiResource,
    threshold: u64,             // Threshold in us
    win_size: u64,              // Window size in us
    event: u64,
    last_event_time: u64,
    pending_event: bool,
    next: ?*PsiTrigger,
};

// ============================================================================
// Cgroup File Types
// ============================================================================

pub const CgroupFileType = enum(u16) {
    // Core
    CgroupType_ = 0,
    CgroupProcs = 1,
    CgroupThreads = 2,
    CgroupControllers = 3,
    SubtreeControl = 4,
    CgroupEvents = 5,
    CgroupStat = 6,
    CgroupFreeze = 7,
    CgroupKill = 8,
    CgroupPressure = 9,
    // CPU
    CpuWeight = 100,
    CpuWeightNice = 101,
    CpuMax = 102,
    CpuMaxBurst = 103,
    CpuIdle = 104,
    CpuStat = 105,
    CpuPressure = 106,
    // Memory
    MemCurrent = 200,
    MemMin = 201,
    MemLow = 202,
    MemHigh = 203,
    MemMax = 204,
    MemEvents = 205,
    MemEventsLocal = 206,
    MemStat = 207,
    MemNumaStat = 208,
    MemSwapCurrent = 209,
    MemSwapHigh = 210,
    MemSwapMax = 211,
    MemSwapEvents = 212,
    MemZswapCurrent = 213,
    MemZswapMax = 214,
    MemZswapWriteback = 215,
    MemOomGroup = 216,
    MemPressure = 217,
    // IO
    IoStat = 300,
    IoWeight = 301,
    IoMax = 302,
    IoLatency = 303,
    IoCostModel = 304,
    IoCostQos = 305,
    IoPressure = 306,
    // PIDs
    PidsCurrent = 400,
    PidsMax = 401,
    PidsEvents = 402,
    PidsPeak = 403,
    // Cpuset
    CpusetCpus = 500,
    CpusetCpusEffective = 501,
    CpusetMems = 502,
    CpusetMemsEffective = 503,
    CpusetCpusPartition = 504,
    // HugeTLB
    HugetlbMax = 600,
    HugetlbCurrent = 601,
    HugetlbRsvdMax = 602,
    HugetlbRsvdCurrent = 603,
    HugetlbEvents = 604,
    // RDMA
    RdmaMax = 700,
    RdmaCurrent = 701,
    // Misc
    MiscMax = 800,
    MiscCurrent = 801,
    MiscEvents = 802,
};

// ============================================================================
// Cgroup Namespace
// ============================================================================

pub const CgroupNamespace = struct {
    user_ns: ?*anyopaque,
    ucounts: ?*anyopaque,
    root_cset: ?*anyopaque,
};

// ============================================================================
// Manager
// ============================================================================

pub const CgroupV2Manager = struct {
    total_cgroups_created: u64,
    total_cgroups_destroyed: u64,
    total_migrations: u64,
    total_oom_events: u64,
    total_psi_triggers: u64,
    nr_active_cgroups: u32,
    nr_controllers: u32,
    hierarchy_depth_max: u32,
    initialized: bool,

    pub fn init() CgroupV2Manager {
        return .{
            .total_cgroups_created = 0,
            .total_cgroups_destroyed = 0,
            .total_migrations = 0,
            .total_oom_events = 0,
            .total_psi_triggers = 0,
            .nr_active_cgroups = 0,
            .nr_controllers = 14,
            .hierarchy_depth_max = 0,
            .initialized = true,
        };
    }
};
