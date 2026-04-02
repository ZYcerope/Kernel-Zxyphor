// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - TLB Management and CPU Topology Detail
// Complete TLB flush, shootdown, PCID/ASID, TLB batch,
// CPU topology, die/cluster/core/thread, sched domains

const std = @import("std");

// ============================================================================
// TLB Types
// ============================================================================

pub const TlbType = enum(u8) {
    Data = 0,
    Instruction = 1,
    Unified = 2,
};

pub const TlbLevel = enum(u8) {
    L1 = 0,
    L2 = 1,
    L3 = 2,
};

pub const TlbEntryInfo = struct {
    tlb_type: TlbType,
    level: TlbLevel,
    entries: u32,
    associativity: u32,
    page_sizes: TlbPageSize,
};

pub const TlbPageSize = packed struct(u32) {
    page_4k: bool = false,
    page_2m: bool = false,
    page_4m: bool = false,
    page_1g: bool = false,
    _reserved: u28 = 0,
};

// ============================================================================
// PCID / ASID (Address Space Identifier)
// ============================================================================

pub const MAX_ASID_AVAILABLE = 4096; // 12-bit PCID on x86_64

pub const PcidState = struct {
    cr3_pcid_mask: u64,
    tlb_gen: u64,
    active_asid: u16,
    asid_available: bool,
    need_flush: bool,
};

pub const AsidInfo = struct {
    asid: u16,
    generation: u64,
    mm: u64, // struct mm_struct *
};

pub const TlbState = struct {
    loaded_mm: u64, // Currently loaded mm
    next_asid: u16,
    asid_generation: u64,
    ctxs: [MAX_ASID_AVAILABLE]AsidCtx,
    invalidate_other: bool,
    is_lazy: bool,
    cr4_value: u64,
};

pub const AsidCtx = struct {
    ctx_id: u64,
    tlb_gen: u64,
};

// ============================================================================
// TLB Flush Operations
// ============================================================================

pub const FlushTlbReason = enum(u8) {
    ContextSwitch = 0,
    KernelRange = 1,
    UserRange = 2,
    RemoteShootdown = 3,
    LocalShootdown = 4,
    MovePageTable = 5,
    Munmap = 6,
    Mprotect = 7,
    HugePageCoalesce = 8,
    Ksm = 9,
    Thp = 10,
    Migration = 11,
    Compaction = 12,
};

pub const FlushTlbInfo = struct {
    mm: u64, // struct mm_struct *
    start: u64, // Virtual address start
    end: u64, // Virtual address end
    stride_shift: u64,
    freed_tables: bool,
    new_tlb_gen: u64,
    initiating_cpu: u32,
    trim_cpumask: bool,
};

pub const TlbBatchFlush = struct {
    mm: u64,
    cpumask: [4]u64, // Up to 256 CPUs
    start: u64,
    end: u64,
    stride_shift: u64,
    freed_tables: bool,
    batch_count: u32,
};

// ============================================================================
// TLB Shootdown IPI
// ============================================================================

pub const TlbShootdownStats = struct {
    total_ipi_sent: u64,
    total_ipi_received: u64,
    total_pages_flushed: u64,
    total_full_flushes: u64,
    total_partial_flushes: u64,
    total_lazy_flushes: u64,
    shootdown_latency_ns_total: u64,
    shootdown_count: u64,
};

pub const ShootdownMode = enum(u8) {
    All = 0, // Full TLB flush
    Range = 1, // Range-based flush
    Single = 2, // Single page flush
    Lazy = 3, // Deferred/lazy flush
};

// ============================================================================
// Page Global Enable / Large Pages TLB
// ============================================================================

pub const PgeConfig = struct {
    pge_supported: bool,
    pge_enabled: bool,
    global_pages_kernel: bool,
    pat_supported: bool,
    invpcid_supported: bool,
    invlpg_supported: bool,
    invpcid_single: bool,
    invpcid_all_nonglobal: bool,
    invpcid_all: bool,
    invpcid_pcid_ctx: bool,
};

// ============================================================================
// CPU Topology
// ============================================================================

pub const CpuTopologyLevel = enum(u8) {
    Thread = 0, // SMT thread
    Core = 1,
    Module = 2,
    Tile = 3,
    Die = 4,
    Cluster = 5,
    Package = 6,
    NumaNode = 7,
    System = 8,
};

pub const CpuTopology = struct {
    x2apic_id: u32,
    initial_apic_id: u32,
    phys_pkg_id: u32,
    logical_pkg_id: u32,
    die_id: u32,
    cluster_id: u32,
    core_id: u32,
    logical_core_id: u32,
    smt_id: u32,
    cu_id: u32, // Compute unit (AMD)
    llc_id: u32, // Last-level cache ID
    amd_node_id: u32,
    // Masks
    core_cpumask: [4]u64, // CPUs in same core
    die_cpumask: [4]u64, // CPUs in same die
    pkg_cpumask: [4]u64, // CPUs in same package
    llc_shared_map: [4]u64, // CPUs sharing LLC
    cluster_cpumask: [4]u64, // CPUs in same cluster
};

pub const X86CpuidTopology = struct {
    smt_bits: u8,
    core_bits: u8,
    module_bits: u8,
    tile_bits: u8,
    die_bits: u8,
    pkg_bits: u8,
    smt_mask: u32,
    core_mask: u32,
    die_mask: u32,
    pkg_mask: u32,
};

// ============================================================================
// NUMA Topology
// ============================================================================

pub const MAX_NUMNODES = 64;
pub const MAX_NUMDISTANCES = MAX_NUMNODES * MAX_NUMNODES;

pub const NumaTopology = struct {
    num_nodes: u32,
    num_online_nodes: u32,
    node_online_map: [MAX_NUMNODES / 64]u64,
    node_possible_map: [MAX_NUMNODES / 64]u64,
    distances: [MAX_NUMDISTANCES]u8,
    node_data: [MAX_NUMNODES]?*NumaNodeData,
};

pub const NumaNodeData = struct {
    node_id: i32,
    node_start_pfn: u64,
    node_present_pages: u64,
    node_spanned_pages: u64,
    node_zones: [4]ZoneInfo, // DMA, DMA32, Normal, Movable
    totalram_pages: u64,
    freeram_pages: u64,
    active_pages: u64,
    inactive_pages: u64,
    kswapd_order: u8,
    kswapd_highest_zoneidx: u8,
};

pub const ZoneInfo = struct {
    name: [16]u8,
    zone_start_pfn: u64,
    managed_pages: u64,
    spanned_pages: u64,
    present_pages: u64,
    watermark: [3]u64, // min, low, high
    nr_reserved_highatomic: u64,
    lowmem_reserve: [4]u64,
    percpu_drift_mark: u64,
};

// ============================================================================
// Scheduler Domains (topology-aware scheduling)
// ============================================================================

pub const SchedDomainLevel = enum(u8) {
    Sibling = 0, // SMT
    MC = 1, // Multi-core
    Die = 2,
    Cluster = 3,
    Numa = 4,
    NumaDist = 5,
    NumaFar = 6,
};

pub const SchedDomainFlags = packed struct(u64) {
    sd_load_balance: bool = false,
    sd_balance_newidle: bool = false,
    sd_balance_exec: bool = false,
    sd_balance_fork: bool = false,
    sd_balance_wake: bool = false,
    sd_wake_affine: bool = false,
    sd_asym_cpucapacity: bool = false,
    sd_asym_cpucapacity_full: bool = false,
    sd_share_cpucapacity: bool = false,
    sd_share_pkg_resources: bool = false,
    sd_serialize: bool = false,
    sd_asym_packing: bool = false,
    sd_prefer_sibling: bool = false,
    sd_overlap: bool = false,
    sd_numa: bool = false,
    _reserved: u49 = 0,
};

pub const SchedDomainParams = struct {
    level: SchedDomainLevel,
    flags: SchedDomainFlags,
    min_interval: u32,
    max_interval: u32,
    busy_factor: u32,
    imbalance_pct: u32,
    cache_nice_tries: u32,
    balance_interval: u32,
    nr_balance_failed: u32,
    max_newidle_lb_cost: u64,
    last_decay_max_lb_cost: u64,
};

pub const SchedGroup = struct {
    next: ?*SchedGroup,
    ref_count: u32,
    group_weight: u32,
    cpumask: [4]u64,
    sgc: ?*SchedGroupCapacity,
    asym_prefer_cpu: i32,
    flags: u32,
};

pub const SchedGroupCapacity = struct {
    ref_count: u32,
    capacity: u64,
    min_capacity: u64,
    max_capacity: u64,
    next_update: u64,
    imbalance: u64,
    id: u32,
};

// ============================================================================
// CPU Hotplug
// ============================================================================

pub const CpuhpState = enum(u32) {
    Invalid = 0,
    Offline = 1,
    CreateThreads = 2,
    PerfPrepare = 3,
    WorkqueuePrep = 4,
    HrtimersPrep = 5,
    SmpcfdPrepare = 6,
    RcutreePrepare = 7,
    SchedulerPrep = 8,
    BringupCpu = 9,
    ApIdleDead = 10,
    ApOffline = 11,
    ApSchedStarting = 12,
    ApRcutreeOnline = 13,
    ApWorkqueueOnline = 14,
    ApActive = 15,
    ApOnline = 16,
    ApOnlineDyn = 17,
    ApOnlineIdle = 18,
    Online = 19,
};

pub const CpuhpCpuState = struct {
    state: CpuhpState,
    target: CpuhpState,
    fail: CpuhpState,
    thread: u64,
    should_run: bool,
    rollback: bool,
    single: bool,
    bringup: bool,
    booted_once: bool,
    cb_state: u32,
    result: i32,
    done_up: u64,
    done_down: u64,
};

pub const CpuHotplugOps = struct {
    name: [64]u8,
    startup: ?*const fn (u32) i32,
    teardown: ?*const fn (u32) i32,
    multi_instance: bool,
};

// ============================================================================
// CPU Features (x86)
// ============================================================================

pub const CpuFeatureCapability = packed struct(u64) {
    sse3: bool = false,
    pclmulqdq: bool = false,
    dtes64: bool = false,
    monitor: bool = false,
    ds_cpl: bool = false,
    vmx: bool = false,
    smx: bool = false,
    est: bool = false,
    tm2: bool = false,
    ssse3: bool = false,
    cid: bool = false,
    sdbg: bool = false,
    fma: bool = false,
    cx16: bool = false,
    xptr: bool = false,
    pdcm: bool = false,
    pcid: bool = false,
    dca: bool = false,
    sse4_1: bool = false,
    sse4_2: bool = false,
    x2apic: bool = false,
    movbe: bool = false,
    popcnt: bool = false,
    tsc_deadline: bool = false,
    aes_ni: bool = false,
    xsave: bool = false,
    osxsave: bool = false,
    avx: bool = false,
    f16c: bool = false,
    rdrand: bool = false,
    hypervisor: bool = false,
    // Extended features
    fsgsbase: bool = false,
    tsc_adjust: bool = false,
    sgx: bool = false,
    bmi1: bool = false,
    hle: bool = false,
    avx2: bool = false,
    smep: bool = false,
    bmi2: bool = false,
    erms: bool = false,
    invpcid: bool = false,
    rtm: bool = false,
    cqm: bool = false,
    mpx: bool = false,
    rdt_a: bool = false,
    avx512f: bool = false,
    avx512dq: bool = false,
    rdseed: bool = false,
    adx: bool = false,
    smap: bool = false,
    avx512ifma: bool = false,
    clflushopt: bool = false,
    clwb: bool = false,
    avx512pf: bool = false,
    avx512er: bool = false,
    avx512cd: bool = false,
    sha: bool = false,
    avx512bw: bool = false,
    avx512vl: bool = false,
    _reserved: u7 = 0,
};

// ============================================================================
// TLB/Topology Manager
// ============================================================================

pub const TlbTopologyManager = struct {
    tlb_entries: [6]TlbEntryInfo, // Various TLB levels/types
    num_tlb_entries: u8,
    pcid_state: PcidState,
    pge_config: PgeConfig,
    shootdown_stats: TlbShootdownStats,
    cpu_topology: [256]CpuTopology, // Per-CPU topology
    numa_topo: NumaTopology,
    cpuid_topo: X86CpuidTopology,
    num_cpus_online: u32,
    num_cpus_present: u32,
    num_cpus_possible: u32,
    features: CpuFeatureCapability,
    initialized: bool,

    pub fn init() TlbTopologyManager {
        return .{
            .tlb_entries = std.mem.zeroes([6]TlbEntryInfo),
            .num_tlb_entries = 0,
            .pcid_state = std.mem.zeroes(PcidState),
            .pge_config = std.mem.zeroes(PgeConfig),
            .shootdown_stats = std.mem.zeroes(TlbShootdownStats),
            .cpu_topology = std.mem.zeroes([256]CpuTopology),
            .numa_topo = std.mem.zeroes(NumaTopology),
            .cpuid_topo = std.mem.zeroes(X86CpuidTopology),
            .num_cpus_online = 0,
            .num_cpus_present = 0,
            .num_cpus_possible = 0,
            .features = std.mem.zeroes(CpuFeatureCapability),
            .initialized = true,
        };
    }
};
