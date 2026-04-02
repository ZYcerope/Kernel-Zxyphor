// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Perf Events & Performance Monitoring Detail
// Complete: perf_event_attr, hardware counters, software counters,
// tracepoints, sampling, branch profiling, LBR, PEBS, Intel PT,
// cgroup profiling, event groups, ring buffer, aux area

const std = @import("std");

// ============================================================================
// Perf Event Types
// ============================================================================

pub const PerfTypeId = enum(u32) {
    Hardware = 0,
    Software = 1,
    Tracepoint = 2,
    HwCache = 3,
    Raw = 4,
    Breakpoint = 5,
};

pub const PerfHwId = enum(u64) {
    CpuCycles = 0,
    Instructions = 1,
    CacheReferences = 2,
    CacheMisses = 3,
    BranchInstructions = 4,
    BranchMisses = 5,
    BusCycles = 6,
    StalledCyclesFrontend = 7,
    StalledCyclesBackend = 8,
    RefCpuCycles = 9,
};

pub const PerfSwId = enum(u64) {
    CpuClock = 0,
    TaskClock = 1,
    PageFaults = 2,
    ContextSwitches = 3,
    CpuMigrations = 4,
    PageFaultsMin = 5,
    PageFaultsMaj = 6,
    AlignmentFaults = 7,
    EmulationFaults = 8,
    Dummy = 9,
    BpfOutput = 10,
    CgroupSwitches = 11,
};

pub const PerfHwCacheId = enum(u64) {
    L1D = 0,
    L1I = 1,
    LL = 2,
    DTLB = 3,
    ITLB = 4,
    BPU = 5,   // Branch Prediction Unit
    NODE = 6,
};

pub const PerfHwCacheOpId = enum(u64) {
    Read = 0,
    Write = 1,
    Prefetch = 2,
};

pub const PerfHwCacheOpResultId = enum(u64) {
    Access = 0,
    Miss = 1,
};

// ============================================================================
// perf_event_attr
// ============================================================================

pub const PerfEventAttr = struct {
    type_field: PerfTypeId,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: PerfSampleType,
    read_format: PerfReadFormat,
    flags: PerfEventAttrFlags,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    config1_or_bp_addr: u64,
    config2_or_bp_len: u64,
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

pub const PerfSampleType = packed struct(u64) {
    ip: bool,
    tid: bool,
    time: bool,
    addr: bool,
    read: bool,
    callchain: bool,
    id: bool,
    cpu: bool,
    period: bool,
    stream_id: bool,
    raw: bool,
    branch_stack: bool,
    regs_user: bool,
    stack_user: bool,
    weight: bool,
    data_src: bool,
    identifier: bool,
    transaction: bool,
    regs_intr: bool,
    phys_addr: bool,
    aux: bool,
    cgroup: bool,
    data_page_size: bool,
    code_page_size: bool,
    weight_struct: bool,
    _reserved: u39,
};

pub const PerfReadFormat = packed struct(u64) {
    total_time_enabled: bool,
    total_time_running: bool,
    id: bool,
    group: bool,
    lost: bool,
    _reserved: u59,
};

pub const PerfEventAttrFlags = packed struct(u64) {
    disabled: bool,
    inherit: bool,
    pinned: bool,
    exclusive: bool,
    exclude_user: bool,
    exclude_kernel: bool,
    exclude_hv: bool,
    exclude_idle: bool,
    mmap: bool,
    comm: bool,
    freq: bool,
    inherit_stat: bool,
    enable_on_exec: bool,
    task: bool,
    watermark: bool,
    precise_ip_1: bool,
    precise_ip_2: bool,
    mmap_data: bool,
    sample_id_all: bool,
    exclude_host: bool,
    exclude_guest: bool,
    exclude_callchain_kernel: bool,
    exclude_callchain_user: bool,
    mmap2: bool,
    comm_exec: bool,
    use_clockid: bool,
    context_switch: bool,
    write_backward: bool,
    namespaces: bool,
    ksymbol: bool,
    bpf_event: bool,
    aux_output: bool,
    cgroup: bool,
    text_poke: bool,
    build_id: bool,
    inherit_thread: bool,
    remove_on_exec: bool,
    sigtrap: bool,
    _reserved: u26,
};

pub const PerfBranchSampleType = packed struct(u64) {
    user: bool,
    kernel: bool,
    hv: bool,
    any: bool,
    any_call: bool,
    any_return: bool,
    ind_call: bool,
    abort_tx: bool,
    in_tx: bool,
    no_tx: bool,
    cond: bool,
    call_stack: bool,
    ind_jump: bool,
    call: bool,
    no_flags: bool,
    no_cycles: bool,
    type_save: bool,
    hw_index: bool,
    priv_save: bool,
    counters: bool,
    _reserved: u44,
};

// ============================================================================
// Perf Event Header (ring buffer records)
// ============================================================================

pub const PerfEventType = enum(u32) {
    PERF_RECORD_MMAP = 1,
    PERF_RECORD_LOST = 2,
    PERF_RECORD_COMM = 3,
    PERF_RECORD_EXIT = 4,
    PERF_RECORD_THROTTLE = 5,
    PERF_RECORD_UNTHROTTLE = 6,
    PERF_RECORD_FORK = 7,
    PERF_RECORD_READ = 8,
    PERF_RECORD_SAMPLE = 9,
    PERF_RECORD_MMAP2 = 10,
    PERF_RECORD_AUX = 11,
    PERF_RECORD_ITRACE_START = 12,
    PERF_RECORD_LOST_SAMPLES = 13,
    PERF_RECORD_SWITCH = 14,
    PERF_RECORD_SWITCH_CPU_WIDE = 15,
    PERF_RECORD_NAMESPACES = 16,
    PERF_RECORD_KSYMBOL = 17,
    PERF_RECORD_BPF_EVENT = 18,
    PERF_RECORD_CGROUP = 19,
    PERF_RECORD_TEXT_POKE = 20,
    PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
};

pub const PerfEventHeader = packed struct {
    type_field: u32,
    misc: u16,
    size: u16,
};

// ============================================================================
// Ring Buffer
// ============================================================================

pub const PerfMmapPage = struct {
    version: u32,
    compat_version: u32,
    lock: u32,
    index: u32,
    offset: i64,
    time_enabled: u64,
    time_running: u64,
    capabilities: PerfMmapCap,
    pmc_width: u16,
    time_shift: u16,
    time_mult: u32,
    time_offset: u64,
    time_zero: u64,
    size: u32,
    __reserved_1: u32,
    time_cycles: u64,
    time_mask: u64,
    __reserved: [116 * 8]u8,
    data_head: u64,
    data_tail: u64,
    data_offset: u64,
    data_size: u64,
    aux_head: u64,
    aux_tail: u64,
    aux_offset: u64,
    aux_size: u64,
};

pub const PerfMmapCap = packed struct(u64) {
    user_rdpmc: bool,
    user_time: bool,
    user_time_zero: bool,
    user_time_short: bool,
    _reserved: u60,
};

// ============================================================================
// Branch Record (LBR)
// ============================================================================

pub const PerfBranchEntry = packed struct {
    from: u64,
    to: u64,
    flags: PerfBranchFlags,
};

pub const PerfBranchFlags = packed struct(u64) {
    mispred: bool,
    predicted: bool,
    in_tx: bool,
    abort: bool,
    cycles: u16,
    branch_type: u4,
    spec: u2,
    new_type: u4,
    priv_level: u2,
    counter: bool,
    _reserved: u31,
};

pub const PerfBranchType = enum(u4) {
    Unknown = 0,
    Cond = 1,
    Uncond = 2,
    IndCall = 3,
    Call = 4,
    IndJmp = 5,
    Ret = 6,
    SysCall = 7,
    SysRet = 8,
    CondCall = 9,
    CondRet = 10,
    Eret = 11,
    Irq = 12,
    SerjIlz = 13,
    ExtLong = 14,
};

// ============================================================================
// PEBS (Precise Event Based Sampling) - Intel
// ============================================================================

pub const PebsRecord = struct {
    flags: u64,
    ip: u64,
    ax: u64,
    bx: u64,
    cx: u64,
    dx: u64,
    si: u64,
    di: u64,
    bp: u64,
    sp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    status: u64,
    dla: u64,          // Data Linear Address
    dse: u64,          // Data Source Encoding
    lat: u64,          // Latency value
    eventing_ip: u64,
    tsc: u64,
    applicable_counters: u64,
};

pub const PebsDataSrc = packed struct(u64) {
    mem_op: u5,
    mem_lvl: u14,
    mem_snoop: u5,
    mem_lock: u2,
    mem_dtlb: u7,
    mem_lvl_num: u4,
    mem_remote: bool,
    mem_snoopx: u2,
    mem_blk: u3,
    mem_hops: u3,
    _reserved: u18,
};

// ============================================================================
// Intel PT (Processor Trace)
// ============================================================================

pub const IntelPtCap = packed struct(u64) {
    cr3_filter: bool,
    psb_cyc: bool,
    ip_filter: bool,
    mtc: bool,
    ptwrite: bool,
    power_event: bool,
    topa_output: bool,
    topa_multi_entry: bool,
    single_range_output: bool,
    output_subsys: bool,
    payloads_lip: bool,
    num_addr_ranges: u3,
    _reserved: u50,
};

pub const IntelPtConfig = struct {
    enabled: bool,
    branch: bool,          // Branch trace
    tsc: bool,             // Timestamp
    no_retcomp: bool,      // No return compression
    call_stack: bool,
    mtc: bool,             // Mini Timestamp Counter
    cyc: bool,             // Cycle-Accurate Mode
    ptw: bool,             // PTWRITE
    fup_on_ptw: bool,
    pwr_evt: bool,
    cr3_filter: u64,
    addr_ranges: [4]IntelPtAddrRange,
    nr_addr_ranges: u8,
    mtc_freq: u8,
    cyc_thresh: u8,
    psb_freq: u8,
};

pub const IntelPtAddrRange = struct {
    start: u64,
    end: u64,
    cfg: u8,
};

pub const IntelPtPacketType = enum(u8) {
    Padding = 0,
    Psb = 1,       // Packet Stream Boundary
    PsbEnd = 2,
    Cbr = 3,       // Core Bus Ratio
    Tnt = 4,       // Taken/Not-Taken
    Tip = 5,       // Target IP
    TipPge = 6,    // Target IP - PGE
    TipPgd = 7,    // Target IP - PGD
    Fup = 8,       // Flow Update
    Mode = 9,
    Tsc = 10,
    Mtc = 11,      // Mini Timestamp Counter
    Cyc = 12,
    Ovf = 13,      // Overflow
    Ptw = 14,      // PTWRITE
    Exstop = 15,
    Mwait = 16,
    Pwre = 17,     // Power Entry
    Pwrx = 18,     // Power Exit
    Bbp = 19,      // Block Begin
    Bip = 20,      // Block Item
    Bep = 21,      // Block End
    Cfe = 22,      // Control Flow Event
    Evd = 23,      // Event Data
};

// ============================================================================
// PMU (Performance Monitoring Unit)
// ============================================================================

pub const PmuType = enum(u8) {
    Core = 0,
    Uncore = 1,
    Software = 2,
    Tracepoint = 3,
    Breakpoint = 4,
    Auxiliary = 5,
};

pub const PmuInfo = struct {
    name: [64]u8,
    pmu_type: PmuType,
    type_id: u32,
    nr_counters: u32,
    counter_width: u32,
    fixed_counters: u32,
    fixed_counter_width: u32,
    caps: PmuCaps,
    format: [16]PmuFormatEntry,
    nr_format: u32,
    events: [128]PmuEventEntry,
    nr_events: u32,
};

pub const PmuCaps = packed struct(u64) {
    full_width_write: bool,
    pebs_baseline: bool,
    pebs_metrics_avail: bool,
    pebs_output_pt: bool,
    anythread: bool,
    perf_metrics: bool,
    ext_leaf_09_ecx: u32,
    _reserved: u26,
};

pub const PmuFormatEntry = struct {
    name: [32]u8,
    value: u64,
    field: [16]u8,
};

pub const PmuEventEntry = struct {
    name: [64]u8,
    event: u64,
    umask: u64,
    desc: [128]u8,
};

// ============================================================================
// Uncore PMU
// ============================================================================

pub const UncorePmuType = enum(u8) {
    Cbox = 0,      // Core-accessible home agent
    Arb = 1,       // Arbitration
    Cha = 2,       // Caching/Home Agent
    Imc = 3,       // Integrated Memory Controller
    M2m = 4,       // Mesh to Memory
    M3upi = 5,     // Mesh to UPI
    Upi = 6,       // Ultra Path Interconnect
    Iio = 7,       // Integrated IO
    Irp = 8,       // IIO Ring Port
    Pcu = 9,       // Power Control Unit
    Mdf = 10,      // Mesh to Die Filter
};

pub const UncorePmuOps = struct {
    init_box: ?*const fn (box_: *anyopaque) callconv(.C) void,
    exit_box: ?*const fn (box_: *anyopaque) callconv(.C) void,
    enable_box: ?*const fn (box_: *anyopaque) callconv(.C) void,
    disable_box: ?*const fn (box_: *anyopaque) callconv(.C) void,
    enable_event: ?*const fn (box_: *anyopaque, event: *anyopaque) callconv(.C) void,
    disable_event: ?*const fn (box_: *anyopaque, event: *anyopaque) callconv(.C) void,
    read_counter: ?*const fn (box_: *anyopaque, event: *anyopaque) callconv(.C) u64,
};

// ============================================================================
// Event Group
// ============================================================================

pub const PerfEventGroup = struct {
    leader: ?*PerfEventAttr,
    nr_siblings: u32,
    siblings: [16]?*PerfEventAttr,
    on_cpu: i32,
    state: PerfEventState,
    total_time_enabled: u64,
    total_time_running: u64,
};

pub const PerfEventState = enum(i8) {
    Dead = -4,
    ExitDead = -3,
    Revoked = -2,
    Off = -1,
    Inactive = 0,
    Active = 1,
    Error = 2,
};

// ============================================================================
// cgroup Profiling
// ============================================================================

pub const PerfCgroupInfo = struct {
    css: ?*anyopaque,    // cgroup_subsys_state
    timestamp: u64,
    info: u32,
};

// ============================================================================
// Data Source
// ============================================================================

pub const PerfMemOp = packed struct(u5) {
    na: bool,
    load: bool,
    store: bool,
    pfetch: bool,
    exec: bool,
};

pub const PerfMemLvl = packed struct(u14) {
    na: bool,
    hit: bool,
    miss: bool,
    l1: bool,
    lfb: bool,
    l2: bool,
    l3: bool,
    loc_ram: bool,
    rem_ram1: bool,
    rem_ram2: bool,
    rem_cce1: bool,
    rem_cce2: bool,
    io: bool,
    unc: bool,
};

// ============================================================================
// Manager
// ============================================================================

pub const PerfEventsManager = struct {
    total_events_created: u64,
    total_events_destroyed: u64,
    total_samples: u64,
    total_lost_samples: u64,
    total_context_switches: u64,
    total_mmap_records: u64,
    nr_active_events: u32,
    nr_groups: u32,
    initialized: bool,

    pub fn init() PerfEventsManager {
        return .{
            .total_events_created = 0,
            .total_events_destroyed = 0,
            .total_samples = 0,
            .total_lost_samples = 0,
            .total_context_switches = 0,
            .total_mmap_records = 0,
            .nr_active_events = 0,
            .nr_groups = 0,
            .initialized = true,
        };
    }
};
