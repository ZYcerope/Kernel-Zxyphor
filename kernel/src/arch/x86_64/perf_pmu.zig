// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Perf Events Hardware Counters,
// Performance Monitoring Unit (PMU), IBS (AMD),
// PEBS (Intel), LBR, BTS, Intel PT,
// Software Events, Tracepoint Events, HW Breakpoints
// More advanced than Linux 2026 perf subsystem

const std = @import("std");

// ============================================================================
// Perf Event Type
// ============================================================================

/// Perf event type (top-level)
pub const PerfType = enum(u32) {
    hardware = 0,
    software = 1,
    tracepoint = 2,
    hw_cache = 3,
    raw = 4,
    breakpoint = 5,
    // Zxyphor
    zxy_custom = 100,
};

/// Hardware event IDs
pub const PerfHwId = enum(u64) {
    cpu_cycles = 0,
    instructions = 1,
    cache_references = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    bus_cycles = 6,
    stalled_cycles_frontend = 7,
    stalled_cycles_backend = 8,
    ref_cpu_cycles = 9,
    // Zxyphor extensions
    zxy_ipc = 100,
    zxy_memory_bandwidth = 101,
    zxy_cache_utilization = 102,
};

/// Software event IDs
pub const PerfSwId = enum(u64) {
    cpu_clock = 0,
    task_clock = 1,
    page_faults = 2,
    context_switches = 3,
    cpu_migrations = 4,
    page_faults_minor = 5,
    page_faults_major = 6,
    alignment_faults = 7,
    emulation_faults = 8,
    dummy = 9,
    bpf_output = 10,
    cgroup_switches = 11,
};

/// HW cache event config
pub const PerfCacheId = enum(u8) {
    l1d = 0,
    l1i = 1,
    ll = 2,
    dtlb = 3,
    itlb = 4,
    bpu = 5,       // branch prediction unit
    node = 6,      // NUMA node
};

pub const PerfCacheOp = enum(u8) {
    read = 0,
    write = 1,
    prefetch = 2,
};

pub const PerfCacheOpResult = enum(u8) {
    access = 0,
    miss = 1,
};

// ============================================================================
// Perf Event Attributes
// ============================================================================

/// perf_event_attr structure
pub const PerfEventAttr = extern struct {
    type_id: PerfType,
    size: u32,
    config: u64,                   // HW/SW event ID or raw config
    sample_period_or_freq: u64,
    sample_type: PerfSampleType,
    read_format: PerfReadFormat,
    flags: PerfAttrFlags,
    wakeup_events_or_watermark: u32,
    bp_type: u32,                  // for breakpoints
    bp_addr_or_kprobe: u64,
    bp_len_or_kprobe_func: u64,
    branch_sample_type: PerfBranchSampleType,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
    aux_sample_size: u32,
    __reserved_3: u32,
    sig_data: u64,
    config3: u64,
};

/// perf_event_attr flags
pub const PerfAttrFlags = packed struct(u64) {
    disabled: bool = false,
    inherit: bool = false,
    pinned: bool = false,
    exclusive: bool = false,
    exclude_user: bool = false,
    exclude_kernel: bool = false,
    exclude_hv: bool = false,
    exclude_idle: bool = false,
    mmap: bool = false,
    comm: bool = false,
    freq: bool = false,
    inherit_stat: bool = false,
    enable_on_exec: bool = false,
    task: bool = false,
    watermark: bool = false,
    precise_ip_lo: bool = false,
    precise_ip_hi: bool = false,
    mmap_data: bool = false,
    sample_id_all: bool = false,
    exclude_host: bool = false,
    exclude_guest: bool = false,
    exclude_callchain_kernel: bool = false,
    exclude_callchain_user: bool = false,
    mmap2: bool = false,
    comm_exec: bool = false,
    use_clockid: bool = false,
    context_switch: bool = false,
    write_backward: bool = false,
    namespaces: bool = false,
    ksymbol: bool = false,
    bpf_event: bool = false,
    aux_output: bool = false,
    cgroup: bool = false,
    text_poke: bool = false,
    build_id: bool = false,
    inherit_thread: bool = false,
    remove_on_exec: bool = false,
    sigtrap: bool = false,
    _padding: u26 = 0,
};

/// Sample type bitmask
pub const PerfSampleType = packed struct(u64) {
    ip: bool = false,
    tid: bool = false,
    time: bool = false,
    addr: bool = false,
    read: bool = false,
    callchain: bool = false,
    id: bool = false,
    cpu: bool = false,
    period: bool = false,
    stream_id: bool = false,
    raw: bool = false,
    branch_stack: bool = false,
    regs_user: bool = false,
    stack_user: bool = false,
    weight: bool = false,
    data_src: bool = false,
    identifier: bool = false,
    transaction: bool = false,
    regs_intr: bool = false,
    phys_addr: bool = false,
    aux: bool = false,
    cgroup: bool = false,
    data_page_size: bool = false,
    code_page_size: bool = false,
    weight_struct: bool = false,
    _padding: u39 = 0,
};

/// Read format
pub const PerfReadFormat = packed struct(u64) {
    total_time_enabled: bool = false,
    total_time_running: bool = false,
    id: bool = false,
    group: bool = false,
    lost: bool = false,
    _padding: u59 = 0,
};

/// Branch sample type
pub const PerfBranchSampleType = packed struct(u64) {
    user: bool = false,
    kernel: bool = false,
    hv: bool = false,
    any: bool = false,
    any_call: bool = false,
    any_return: bool = false,
    ind_call: bool = false,
    abort_tx: bool = false,
    in_tx: bool = false,
    no_tx: bool = false,
    cond: bool = false,
    call_stack: bool = false,
    ind_jump: bool = false,
    call: bool = false,
    no_flags: bool = false,
    no_cycles: bool = false,
    type_save: bool = false,
    hw_index: bool = false,
    priv_save: bool = false,
    counters: bool = false,
    _padding: u44 = 0,
};

// ============================================================================
// Intel PEBS (Precise Event Based Sampling)
// ============================================================================

/// PEBS configuration
pub const PebsConfig = struct {
    enabled: bool = false,
    precise_ip: u2 = 0,          // 0-3
    pebs_buffer_size: u32 = 0,
    pebs_record_size: u32 = 0,
    counter_reset: [4]u64 = [_]u64{0} ** 4,
    data_cfg: PebsDataCfg = .{},
    adaptive_pebs: bool = false,
    nr_counters_pebs: u8 = 0,
};

pub const PebsDataCfg = packed struct(u64) {
    mem_info: bool = false,
    gp_regs: bool = false,
    xmm_regs: bool = false,
    lbr: bool = false,
    _padding: u60 = 0,
};

// ============================================================================
// Intel PT (Processor Trace)
// ============================================================================

/// Intel PT configuration
pub const IntelPtConfig = struct {
    enabled: bool = false,
    trace_user: bool = true,
    trace_kernel: bool = true,
    branch_en: bool = true,
    mtc_en: bool = false,
    tsc_en: bool = true,
    no_retcomp: bool = false,
    ptwrite_en: bool = false,
    power_event_en: bool = false,
    event_en: bool = false,
    mtc_freq: u4 = 0,
    cyc_thresh: u4 = 0,
    psb_freq: u4 = 0,
    addr_ranges: u8 = 0,
    addr_cfg: [4]IntelPtAddrCfg = [_]IntelPtAddrCfg{.{}} ** 4,
};

pub const IntelPtAddrCfg = struct {
    start: u64 = 0,
    end: u64 = 0,
    filter_type: IntelPtAddrFilter = .disabled,
};

pub const IntelPtAddrFilter = enum(u8) {
    disabled = 0,
    filter = 1,        // trace only in range
    stop = 2,          // stop trace in range
};

/// Intel PT capabilities
pub const IntelPtCaps = packed struct(u64) {
    cr3_filtering: bool = false,
    psb_cyc: bool = false,
    ip_filtering: bool = false,
    mtc: bool = false,
    ptwrite: bool = false,
    power_event_trace: bool = false,
    tnt_disable: bool = false,
    event_trace: bool = false,
    single_range_output: bool = false,
    output_subsys: bool = false,
    num_addr_ranges: u3 = 0,
    _padding: u51 = 0,
};

// ============================================================================
// AMD IBS (Instruction-Based Sampling)
// ============================================================================

/// IBS fetch configuration
pub const IbsFetchConfig = struct {
    enabled: bool = false,
    rand_en: bool = false,
    max_cnt: u20 = 0,
    cur_cnt: u20 = 0,
    l2_miss: bool = false,
    l1_miss: bool = false,
    l1_tlb_miss: bool = false,
    l2_tlb_miss: bool = false,
    phys_addr_valid: bool = false,
    ic_miss: bool = false,
};

/// IBS op configuration
pub const IbsOpConfig = struct {
    enabled: bool = false,
    cnt_ctl: bool = false,
    max_cnt: u27 = 0,
    cur_cnt: u27 = 0,
    branch_retired: bool = false,
    branch_misp: bool = false,
    branch_taken: bool = false,
    return_op: bool = false,
    rip_invalid: bool = false,
    ld_op: bool = false,
    st_op: bool = false,
    dc_miss: bool = false,
    dc_l2_miss: bool = false,
    data_src: u3 = 0,
    ld_lat: u16 = 0,
    ld_lat_valid: bool = false,
};

// ============================================================================
// LBR (Last Branch Record)
// ============================================================================

/// LBR entry
pub const LbrEntry = struct {
    from: u64 = 0,
    to: u64 = 0,
    info: LbrInfo = .{},
};

pub const LbrInfo = packed struct(u64) {
    mispredict: bool = false,
    predicted: bool = false,
    in_tx: bool = false,
    abort: bool = false,
    cycles: u16 = 0,
    branch_type: u4 = 0,
    _padding: u40 = 0,
};

/// LBR configuration
pub const LbrConfig = struct {
    nr_entries: u32 = 0,
    max_entries: u32 = 32,
    call_stack: bool = false,
    kernel: bool = true,
    user: bool = true,
    cond: bool = true,
    ind_call: bool = true,
    ind_jmp: bool = true,
    call: bool = true,
    ret: bool = true,
    far_branch: bool = true,
};

// ============================================================================
// BTS (Branch Trace Store)
// ============================================================================

/// BTS record
pub const BtsRecord = struct {
    from: u64 = 0,
    to: u64 = 0,
    misc: u64 = 0,
};

/// BTS configuration
pub const BtsConfig = struct {
    enabled: bool = false,
    buffer_size: u32 = 0,
    buffer_base: u64 = 0,
    index: u64 = 0,
    abs_max: u64 = 0,
    interrupt_threshold: u64 = 0,
};

// ============================================================================
// HW Breakpoints
// ============================================================================

/// HW breakpoint type
pub const HwBpType = packed struct(u32) {
    empty: bool = false,
    r: bool = false,      // read
    w: bool = false,      // write
    x: bool = false,      // execute
    _padding: u28 = 0,
};

/// HW breakpoint length
pub const HwBpLen = enum(u8) {
    len_1 = 1,
    len_2 = 2,
    len_4 = 4,
    len_8 = 8,
};

/// HW breakpoint descriptor
pub const HwBreakpointDesc = struct {
    address: u64 = 0,
    len: HwBpLen = .len_4,
    bp_type: HwBpType = .{},
    enabled: bool = false,
    slot: u8 = 0,           // debug register slot (0-3 on x86)
    cpu: i32 = -1,          // -1 for task-bound
    task_pid: i32 = -1,
    hit_count: u64 = 0,
};

/// HW breakpoint limits per architecture
pub const HwBpLimits = struct {
    max_exec: u8 = 4,       // x86: DR0-DR3
    max_data: u8 = 4,
    max_total: u8 = 4,
    variable_length: bool = true,
};

// ============================================================================
// Perf Events Subsystem Manager
// ============================================================================

pub const PerfSubsystem = struct {
    nr_events: u64 = 0,
    nr_mmap_pages: u32 = 0,
    max_sample_rate: u32 = 100000,
    max_stack_depth: u32 = 127,
    nr_pmu: u32 = 0,
    pebs_supported: bool = false,
    intel_pt_supported: bool = false,
    ibs_supported: bool = false,
    lbr_entries: u32 = 0,
    bts_supported: bool = false,
    hw_bp_max: u8 = 4,
    paranoid_level: i32 = 2,
    kptr_restrict: u8 = 1,
    total_samples: u64 = 0,
    total_lost: u64 = 0,
    initialized: bool = false,

    pub fn init() PerfSubsystem {
        return PerfSubsystem{
            .initialized = true,
        };
    }
};
