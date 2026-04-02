// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Tracepoints, Ftrace, and Kernel Probes Detail
// Complete: ftrace ring buffer, function tracer, kprobes, uprobes,
// tracepoints, trace events, BPF tracing, dynamic ftrace, fgraph

const std = @import("std");

// ============================================================================
// Ring Buffer
// ============================================================================

pub const RING_BUFFER_PAGE_SIZE: usize = 4096;
pub const RING_BUFFER_MAX_PAGES: usize = 1024 * 1024;

pub const RingBufferType = enum(u8) {
    Padding = 29,
    TimeExtend = 30,
    TimeStamp = 31,
    Data = 0,
};

pub const RingBufferEvent = packed struct {
    type_len: u5,
    time_delta: u27,
    // array data follows for type_len=0; actual length in first 4 bytes
};

pub const RingBufferPage = struct {
    time_stamp: u64,
    local_commit: u64,
    commit: u64,
    entries: u32,
    overrun: u32,
    read: u32,
    data: [RING_BUFFER_PAGE_SIZE - 64]u8,
};

pub const RingBufferPerCpu = struct {
    cpu: u32,
    nr_pages: u32,
    entries: u64,
    overrun: u64,
    commit_overrun: u64,
    dropped_events: u64,
    read: u64,
    bytes_read: u64,
    head_page: ?*RingBufferPage,
    tail_page: ?*RingBufferPage,
    commit_page: ?*RingBufferPage,
    reader_page: ?*RingBufferPage,
    nr_pages_to_update: u32,
    write_stamp: u64,
    before_stamp: u64,
    event_stamp: [5]u64,
    pages_touched: u64,
    pages_lost: u64,
    pages_read: u64,
};

pub const RingBuffer = struct {
    flags: RingBufferFlags,
    cpus: u32,
    nr_pages: u32,
    clock: ?*const fn () callconv(.C) u64,
    buffers: [256]?*RingBufferPerCpu,   // MAX_CPUS
    record_disabled: u32,
    resize_disabled: u32,
    time_stamp_abs: bool,
};

pub const RingBufferFlags = packed struct(u32) {
    overwrite: bool,
    time_abs: bool,
    _reserved: u30,
};

// ============================================================================
// Ftrace
// ============================================================================

pub const FtraceOps = struct {
    func: ?*const fn (ip: u64, parent_ip: u64, ops: *FtraceOps, fregs: *anyopaque) callconv(.C) void,
    next: ?*FtraceOps,
    flags: FtraceOpsFlags,
    private_data: ?*anyopaque,
    saved_func: ?*const fn (ip: u64, parent_ip: u64, ops: *FtraceOps, fregs: *anyopaque) callconv(.C) void,
    local_hash: FtraceOpsHash,
    func_hash: ?*FtraceOpsHash,
    trampoline: u64,
    trampoline_size: u64,
    nr_trampolines: u32,
};

pub const FtraceOpsFlags = packed struct(u64) {
    enabled: bool,
    dynamic: bool,
    save_regs: bool,
    save_regs_if_supported: bool,
    recursion: bool,
    stub: bool,
    initialized: bool,
    deleted: bool,
    adding: bool,
    removing: bool,
    modifying: bool,
    alloc_tramp: bool,
    ipmodify: bool,
    pid: bool,
    rcu: bool,
    trace_array: bool,
    permanent: bool,
    direct: bool,
    subop: bool,
    _reserved: u45,
};

pub const FtraceOpsHash = struct {
    notrace_hash: ?*FtraceHash,
    filter_hash: ?*FtraceHash,
};

pub const FtraceHash = struct {
    size_bits: u64,
    count: u64,
    buckets: [256]?*FtraceFunc,
    flags: u64,
};

pub const FtraceFunc = struct {
    ip: u64,
    next: ?*FtraceFunc,
    flags: u64,
    direct: u64,
    ops: ?*FtraceOps,
    parent_ops: ?*FtraceOps,
};

pub const FtraceRecFlags = packed struct(u32) {
    enabled: bool,
    regs: bool,
    regs_en: bool,
    ipmodify: bool,
    disabled: bool,
    direct: bool,
    direct_en: bool,
    call_ops: bool,
    call_ops_en: bool,
    ops_disabled: bool,
    touched: bool,
    modified: bool,
    _reserved: u20,
};

// ============================================================================
// Function Graph Tracer
// ============================================================================

pub const FgraphOps = struct {
    entryfunc: ?*const fn (ip: u64, parent_ip: u64, fp: *anyopaque, ret_ptr: *u64) callconv(.C) i32,
    retfunc: ?*const fn (ret: *FgraphRet) callconv(.C) void,
    ops: FtraceOps,
    private_data: ?*anyopaque,
    idx: u32,
};

pub const FgraphRet = struct {
    ret: u64,
    func: u64,
    calltime: u64,
    rettime: u64,
    overrun: u64,
    depth: i32,
    fp: u64,
};

pub const FTRACE_RETFUNC_DEPTH: u32 = 50;
pub const FTRACE_GRAPH_MAX_FUNCS: u32 = 32;

// ============================================================================
// Kprobes
// ============================================================================

pub const KprobeState = enum(u8) {
    Disabled = 0,
    Registered = 1,
    Gone = 2,
    Ftrace = 3,
};

pub const Kprobe = struct {
    hlist: ?*anyopaque,
    list: ?*anyopaque,
    nmissed: u64,
    addr: u64,
    symbol_name: ?[*]const u8,
    offset: u32,
    pre_handler: ?*const fn (p: *Kprobe, regs: *anyopaque) callconv(.C) i32,
    post_handler: ?*const fn (p: *Kprobe, regs: *anyopaque, flags: u64) callconv(.C) void,
    opcode: KprobeInsn,
    ainsn: ArchSpecificInsn,
    flags: KprobeFlags,
    state: KprobeState,
};

pub const KprobeInsn = struct {
    bytes: [16]u8,
    len: u8,
};

pub const ArchSpecificInsn = struct {
    insn: ?*u8,
    boostable: bool,
    tp_len: u8,
    emulate_op: ?*const fn (p: *Kprobe, regs: *anyopaque) callconv(.C) void,
};

pub const KprobeFlags = packed struct(u32) {
    gone: bool,
    disabled: bool,
    optimized: bool,
    ftrace: bool,
    on_func_entry: bool,
    on_optimized_list: bool,
    _reserved: u26,
};

pub const Kretprobe = struct {
    kp: Kprobe,
    handler: ?*const fn (ri: *KretprobeInstance, regs: *anyopaque) callconv(.C) i32,
    entry_handler: ?*const fn (ri: *KretprobeInstance, regs: *anyopaque) callconv(.C) i32,
    maxactive: i32,
    nmissed: i32,
    data_size: u64,
    free_instances: ?*KretprobeInstance,
    rph: ?*anyopaque,
};

pub const KretprobeInstance = struct {
    rph: ?*anyopaque,
    next: ?*KretprobeInstance,
    kprobe: ?*Kprobe,
    ret_addr: u64,
    fp: u64,
    entry_stamp: u64,
    data: [128]u8,
};

// ============================================================================
// Uprobes
// ============================================================================

pub const UprobeState = enum(u8) {
    Disabled = 0,
    Registered = 1,
    Active = 2,
};

pub const Uprobe = struct {
    rb_node: [24]u8,       // Red-black tree node
    ref_ctr_offset: u64,
    ref_ctr: u64,
    consumers: ?*UprobeConsumer,
    inode: ?*anyopaque,
    offset: u64,
    lnode: ?*anyopaque,
    flags: UprobeFlags,
};

pub const UprobeFlags = packed struct(u32) {
    copy_insn: bool,
    skip_sstep: bool,
    _reserved: u30,
};

pub const UprobeConsumer = struct {
    handler: ?*const fn (self: *UprobeConsumer, regs: *anyopaque) callconv(.C) i32,
    ret_handler: ?*const fn (self: *UprobeConsumer, func: u64, regs: *anyopaque) callconv(.C) i32,
    filter: ?*const fn (self: *UprobeConsumer, task: *anyopaque) callconv(.C) bool,
    next: ?*UprobeConsumer,
};

pub const UprobeTask = struct {
    autask: UprobeTaskArch,
    vaddr: u64,
    xol_vaddr: u64,
    dup_xol_work: ?*anyopaque,
    dup_xol_addr: u64,
    return_instances: ?*ReturnInstance,
    depth: u32,
};

pub const UprobeTaskArch = struct {
    saved_trap_nr: u32,
    saved_tf: u32,
};

pub const ReturnInstance = struct {
    uprobe: ?*Uprobe,
    func: u64,
    stack: u64,
    orig_ret_vaddr: u64,
    chained: bool,
    next: ?*ReturnInstance,
};

// ============================================================================
// Tracepoints
// ============================================================================

pub const Tracepoint = struct {
    name: [128]u8,
    key: TracepointKey,
    static_call_key: ?*anyopaque,
    static_call_tramp: ?*anyopaque,
    it_func_ptr: ?*anyopaque,
    regfunc: ?*const fn () callconv(.C) i32,
    unregfunc: ?*const fn () callconv(.C) void,
    funcs: ?*TracepointFunc,
};

pub const TracepointKey = struct {
    enabled: i32,
};

pub const TracepointFunc = struct {
    func: ?*const fn () callconv(.C) void,
    data: ?*anyopaque,
    prio: i32,
};

// ============================================================================
// Trace Events
// ============================================================================

pub const TraceEventClass = struct {
    system: [64]u8,
    fields: ?*TraceEventField,
    get_fields: ?*const fn (call: *TraceEventCall) callconv(.C) ?*TraceEventField,
    reg: ?*const fn (call: *TraceEventCall, mode: TraceRegMode, data: ?*anyopaque) callconv(.C) i32,
    raw_init: ?*const fn (call: *TraceEventCall) callconv(.C) i32,
    probe: ?*const fn () callconv(.C) void,
    perf_probe: ?*const fn () callconv(.C) void,
};

pub const TraceRegMode = enum(u8) {
    Register = 0,
    Unregister = 1,
    PerfRegister = 2,
    PerfUnregister = 3,
    PerfOpen = 4,
    PerfClose = 5,
    PerfAdd = 6,
    PerfDel = 7,
};

pub const TraceEventField = struct {
    next: ?*TraceEventField,
    name: [64]u8,
    type_name: [64]u8,
    filter_type: u32,
    offset: i32,
    size: i32,
    is_signed: bool,
};

pub const TraceEventCall = struct {
    class: ?*TraceEventClass,
    tp: ?*Tracepoint,
    event: TraceEvent,
    print_fmt: [256]u8,
    filter: ?*anyopaque,
    flags: TraceEventFlags,
    nr_args: u32,
    args: [16]TraceEventArg,
    perf_perm: ?*const fn (te: *TraceEventCall, p: *anyopaque) callconv(.C) i32,
};

pub const TraceEvent = struct {
    type_field: u16,
    flags: u16,
};

pub const TraceEventFlags = packed struct(u32) {
    has_filter: bool,
    filtered: bool,
    trigger_cond: bool,
    ignore_enable: bool,
    was_enabled: bool,
    use_call_filter: bool,
    tracepoint: bool,
    kprobe: bool,
    uprobe: bool,
    _reserved: u23,
};

pub const TraceEventArg = struct {
    name: [64]u8,
    type_name: [32]u8,
};

// ============================================================================
// Trace Array
// ============================================================================

pub const TraceArray = struct {
    name: [128]u8,
    array_buffer: TraceBuffer,
    max_buffer: TraceBuffer,
    allocated_snapshot: bool,
    max_latency: u64,
    d_max_latency: ?*anyopaque,
    trace_flags: TraceIterFlags,
    current_trace: ?*Tracer,
    nr_topts: u32,
    topts: [32]?*anyopaque,
    clock_id: i32,
    nr_event_systems: u32,
    trace_marker_file: ?*anyopaque,
    cpumask: [4]u64,
    buffer_disabled: u32,
    sys_refcount_enter: u32,
    sys_refcount_exit: u32,
    stop_count: u32,
    time_start: u64,
    last_time: u64,
    total_ref: u32,
};

pub const TraceBuffer = struct {
    buffer: ?*RingBuffer,
    data: [256]?*TraceArrayCpu,
    time_start: u64,
    cpu: i32,
};

pub const TraceArrayCpu = struct {
    disabled: u32,
    entries: u64,
    saved_latency: u64,
    critical_start: u64,
    critical_end: u64,
    critical_sequence: u64,
    nice: u32,
    policy: u32,
    rt_priority: u32,
    skipped_entries: u64,
};

pub const TraceIterFlags = packed struct(u32) {
    print_parent: bool,
    sym_offset: bool,
    sym_addr: bool,
    verbose: bool,
    raw: bool,
    hex: bool,
    bin: bool,
    block: bool,
    printk: bool,
    annotate: bool,
    userstacktrace: bool,
    sym_userobj: bool,
    context_info: bool,
    latency_format: bool,
    record_cmd: bool,
    record_tgid: bool,
    overwrite: bool,
    stop_on_free: bool,
    irq_info: bool,
    markers: bool,
    event_fork: bool,
    pause_on_trace: bool,
    hash_no_bufs: bool,
    func_fork: bool,
    _reserved: u8,
};

// ============================================================================
// Tracer
// ============================================================================

pub const Tracer = struct {
    name: [64]u8,
    init: ?*const fn (tr: *TraceArray) callconv(.C) i32,
    reset: ?*const fn (tr: *TraceArray) callconv(.C) void,
    start: ?*const fn (tr: *TraceArray) callconv(.C) void,
    stop: ?*const fn (tr: *TraceArray) callconv(.C) void,
    update_thresh: ?*const fn (tr: *TraceArray) callconv(.C) i32,
    open: ?*const fn (iter: *anyopaque) callconv(.C) void,
    pipe_open: ?*const fn (iter: *anyopaque) callconv(.C) void,
    close: ?*const fn (iter: *anyopaque) callconv(.C) void,
    pipe_close: ?*const fn (iter: *anyopaque) callconv(.C) void,
    read: ?*const fn (iter: *anyopaque, s: ?*anyopaque, cnt: u64, ppos: *u64) callconv(.C) i64,
    splice_read: ?*const fn (fp: *anyopaque, ppos: *u64, pipe: *anyopaque, len: u64, flags: u32) callconv(.C) i64,
    print_header: ?*const fn (s: *anyopaque) callconv(.C) void,
    print_line: ?*const fn (iter: *anyopaque) callconv(.C) i32,
    set_flag: ?*const fn (tr: *TraceArray, old_flags: u32, bit: i32, set: i32) callconv(.C) i32,
    flag_changed: ?*const fn (tr: *TraceArray, mask: u32, set: i32) callconv(.C) i32,
    flags: ?*TracerFlags,
    allow_instances: bool,
    use_max_tr: bool,
    noboot: bool,
};

pub const TracerFlags = struct {
    val: u32,
    opts: [16]TracerOpt,
    nr_opts: u32,
    trace: ?*Tracer,
};

pub const TracerOpt = struct {
    name: [32]u8,
    bit: u32,
};

// ============================================================================
// Dynamic Events
// ============================================================================

pub const DynamicEventType = enum(u8) {
    Kprobe = 0,
    Kretprobe = 1,
    Uprobe = 2,
    Uretprobe = 3,
    Synth = 4,
    Eprobe = 5,
    Fprobe = 6,
    Fretprobe = 7,
};

pub const DynEvent = struct {
    event_type: DynamicEventType,
    ops: ?*DynEventOps,
    next: ?*DynEvent,
};

pub const DynEventOps = struct {
    create: ?*const fn (argv: [*]const [*]const u8, argc: i32) callconv(.C) i32,
    show: ?*const fn (s: *anyopaque, ev: *DynEvent) callconv(.C) i32,
    is_busy: ?*const fn (ev: *DynEvent) callconv(.C) bool,
    free: ?*const fn (ev: *DynEvent) callconv(.C) void,
    match_event: ?*const fn (system: [*]const u8, event: [*]const u8, pf: i32, ev: *DynEvent) callconv(.C) bool,
};

// ============================================================================
// Trace Triggers
// ============================================================================

pub const TraceTriggerType = enum(u8) {
    Snapshot = 0,
    Stacktrace = 1,
    Enable = 2,
    Disable = 3,
    TraceonCount = 4,
    TraceoffCount = 5,
    Hist = 6,
};

pub const EventTriggerData = struct {
    trigger_type: TraceTriggerType,
    count: i64,
    filter: ?*anyopaque,
    trigger: ?*const fn (data: *EventTriggerData, buffer: *anyopaque, rec: *anyopaque, event: *anyopaque) callconv(.C) void,
    init: ?*const fn (data: *EventTriggerData) callconv(.C) i32,
    free: ?*const fn (data: *EventTriggerData) callconv(.C) void,
    print: ?*const fn (s: *anyopaque, data: *EventTriggerData) callconv(.C) i32,
    private_data: ?*anyopaque,
    paused: bool,
    named_data: ?*anyopaque,
    next: ?*EventTriggerData,
};

// ============================================================================
// Manager
// ============================================================================

pub const TracingManager = struct {
    total_events_traced: u64,
    total_ring_buffer_bytes: u64,
    total_kprobes_registered: u64,
    total_kprobes_hit: u64,
    total_uprobes_registered: u64,
    total_uprobes_hit: u64,
    total_tracepoints: u32,
    total_dynamic_events: u32,
    nr_active_tracers: u32,
    nr_trace_arrays: u32,
    ring_buffer_overruns: u64,
    ring_buffer_drops: u64,
    initialized: bool,

    pub fn init() TracingManager {
        return .{
            .total_events_traced = 0,
            .total_ring_buffer_bytes = 0,
            .total_kprobes_registered = 0,
            .total_kprobes_hit = 0,
            .total_uprobes_registered = 0,
            .total_uprobes_hit = 0,
            .total_tracepoints = 0,
            .total_dynamic_events = 0,
            .nr_active_tracers = 0,
            .nr_trace_arrays = 0,
            .ring_buffer_overruns = 0,
            .ring_buffer_drops = 0,
            .initialized = true,
        };
    }
};
