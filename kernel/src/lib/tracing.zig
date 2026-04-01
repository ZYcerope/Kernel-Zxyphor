// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Tracing & Profiling: ftrace, perf events, kprobes, tracepoints
// Linux 6.x compatible with Zxyphor enhancements

const std = @import("std");

// ============================================================================
// ftrace Infrastructure
// ============================================================================

pub const FTRACE_ENTRY_SIZE: usize = 256;
pub const FTRACE_BUFFER_SIZE: usize = 1024 * 1024; // 1MB per CPU
pub const FTRACE_MAX_CPUS: usize = 256;

pub const FtraceEventType = enum(u8) {
    function_entry = 0,
    function_exit = 1,
    function_graph_entry = 2,
    function_graph_exit = 3,
    context_switch = 4,
    wakeup = 5,
    irq_entry = 6,
    irq_exit = 7,
    softirq_entry = 8,
    softirq_exit = 9,
    sched_switch = 10,
    sched_wakeup = 11,
    sched_migrate = 12,
    syscall_entry = 13,
    syscall_exit = 14,
    page_fault = 15,
    kmalloc = 16,
    kfree = 17,
    mm_page_alloc = 18,
    mm_page_free = 19,
    block_rq_issue = 20,
    block_rq_complete = 21,
    net_dev_xmit = 22,
    net_dev_receive = 23,
    writeback_dirty = 24,
    writeback_written = 25,
    workqueue_activate = 26,
    workqueue_execute = 27,
    timer_expire = 28,
    hrtimer_expire = 29,
    // Zxyphor custom events
    zxy_ipc_send = 200,
    zxy_ipc_receive = 201,
    zxy_cap_check = 202,
    zxy_virt_vmenter = 203,
    zxy_virt_vmexit = 204,
};

pub const FtraceEntry = struct {
    timestamp: u64,        // Nanoseconds
    event_type: FtraceEventType,
    cpu: u16,
    pid: u32,
    tgid: u32,
    preempt_count: u8,
    flags: FtraceFlags,
    // Event-specific data
    data: FtraceEventData,
};

pub const FtraceFlags = packed struct(u8) {
    irqs_off: bool = false,
    need_resched: bool = false,
    hardirq: bool = false,
    softirq: bool = false,
    preempt_need_resched: bool = false,
    branch: bool = false,
    _reserved: u2 = 0,
};

pub const FtraceEventData = extern union {
    function: FunctionEvent,
    function_graph: FunctionGraphEvent,
    sched_switch: SchedSwitchEvent,
    sched_wakeup: SchedWakeupEvent,
    syscall: SyscallEvent,
    kmalloc: KmallocEvent,
    page_alloc: PageAllocEvent,
    block_rq: BlockRqEvent,
    net_xmit: NetXmitEvent,
    irq: IrqEvent,
    raw: [192]u8,
};

pub const FunctionEvent = extern struct {
    ip: u64,           // Instruction pointer
    parent_ip: u64,    // Caller
};

pub const FunctionGraphEvent = extern struct {
    func: u64,
    depth: u32,
    duration_ns: u64,  // Only for exit
    overrun: bool,
};

pub const SchedSwitchEvent = extern struct {
    prev_comm: [16]u8,
    prev_pid: u32,
    prev_prio: u32,
    prev_state: u64,
    next_comm: [16]u8,
    next_pid: u32,
    next_prio: u32,
};

pub const SchedWakeupEvent = extern struct {
    comm: [16]u8,
    pid: u32,
    prio: u32,
    target_cpu: u32,
    success: bool,
};

pub const SyscallEvent = extern struct {
    nr: u32,
    args: [6]u64,
    ret: i64,          // Only for exit
};

pub const KmallocEvent = extern struct {
    call_site: u64,
    ptr: u64,
    bytes_req: u64,
    bytes_alloc: u64,
    gfp_flags: u32,
};

pub const PageAllocEvent = extern struct {
    pfn: u64,
    order: u32,
    gfp_flags: u32,
    migratetype: u32,
};

pub const BlockRqEvent = extern struct {
    dev: u64,
    sector: u64,
    nr_sector: u32,
    rwbs: [8]u8,
    comm: [16]u8,
};

pub const NetXmitEvent = extern struct {
    skb_addr: u64,
    len: u32,
    dev_name: [16]u8,
    rc: i32,
};

pub const IrqEvent = extern struct {
    irq: u32,
    name: [16]u8,
    handler: u64,
    ret: u32,          // IRQ_NONE, IRQ_HANDLED, IRQ_WAKE_THREAD
};

// ============================================================================
// Ring Buffer (per-CPU trace buffer)
// ============================================================================

pub const RingBufferPage = struct {
    timestamp: u64,
    data_size: u32,
    commit: u32,
    entries: u32,
    data: [4096 - 24]u8,
};

pub const RingBuffer = struct {
    pages: [1024]*RingBufferPage,
    nr_pages: u32,
    head: u32,
    tail: u32,
    overrun: u64,
    entries: u64,
    bytes_written: u64,
    // Reader state
    reader_page: u32,
    reader_lock: bool,

    pub fn init(nr_pages: u32) RingBuffer {
        return RingBuffer{
            .pages = undefined,
            .nr_pages = nr_pages,
            .head = 0,
            .tail = 0,
            .overrun = 0,
            .entries = 0,
            .bytes_written = 0,
            .reader_page = 0,
            .reader_lock = false,
        };
    }

    pub fn write_event(self: *RingBuffer, entry: *const FtraceEntry) bool {
        const size = @sizeOf(FtraceEntry);
        const page = self.pages[self.head];
        if (page.data_size + size > page.data.len) {
            // Advance to next page
            self.head = (self.head + 1) % self.nr_pages;
            if (self.head == self.tail) {
                self.overrun += self.pages[self.tail].entries;
                self.tail = (self.tail + 1) % self.nr_pages;
            }
            self.pages[self.head].data_size = 0;
            self.pages[self.head].entries = 0;
        }
        // Write entry
        const dst = self.pages[self.head].data[page.data_size..][0..size];
        @memcpy(dst, std.mem.asBytes(entry));
        self.pages[self.head].data_size += @intCast(size);
        self.pages[self.head].entries += 1;
        self.entries += 1;
        self.bytes_written += size;
        return true;
    }

    pub fn is_empty(self: *const RingBuffer) bool {
        return self.entries == 0;
    }

    pub fn available_entries(self: *const RingBuffer) u64 {
        return self.entries;
    }
};

// Per-CPU buffer management
pub const TraceBuffer = struct {
    per_cpu: [FTRACE_MAX_CPUS]RingBuffer,
    nr_cpus: u32,
    buffer_size_kb: u32,
    total_entries: u64,
    total_overrun: u64,
    enabled: bool,
    // Global clock source
    clock_id: TraceClockId,
    // Snapshot
    snapshot_buffer: ?*TraceBuffer,

    pub fn init(nr_cpus: u32) TraceBuffer {
        var buf = TraceBuffer{
            .per_cpu = undefined,
            .nr_cpus = nr_cpus,
            .buffer_size_kb = 1024, // 1MB default
            .total_entries = 0,
            .total_overrun = 0,
            .enabled = false,
            .clock_id = .local,
            .snapshot_buffer = null,
        };
        var i: u32 = 0;
        while (i < nr_cpus) : (i += 1) {
            buf.per_cpu[i] = RingBuffer.init(256);
        }
        return buf;
    }
};

pub const TraceClockId = enum(u8) {
    local = 0,       // per-CPU TSC
    global = 1,      // synchronized TSC
    counter = 2,     // simple counter
    uptime = 3,      // boot clock
    perf = 4,        // perf_clock
    mono = 5,        // CLOCK_MONOTONIC
    mono_raw = 6,    // CLOCK_MONOTONIC_RAW
    boot = 7,        // CLOCK_BOOTTIME
    tai = 8,         // CLOCK_TAI
};

// ============================================================================
// Tracer Types
// ============================================================================

pub const TracerType = enum(u8) {
    nop = 0,
    function = 1,
    function_graph = 2,
    blk = 3,
    irqsoff = 4,
    preemptoff = 5,
    preemptirqsoff = 6,
    wakeup = 7,
    wakeup_rt = 8,
    wakeup_dl = 9,
    hwlat = 10,
    osnoise = 11,
    timerlat = 12,
    // Zxyphor custom tracers
    zxy_scheduler = 200,
    zxy_memory_pressure = 201,
    zxy_io_latency = 202,
};

pub const TracerOps = struct {
    name: [32]u8,
    tracer_type: TracerType,
    init: ?*const fn (*TraceBuffer) i32,
    reset: ?*const fn (*TraceBuffer) void,
    start: ?*const fn (*TraceBuffer) i32,
    stop: ?*const fn (*TraceBuffer) void,
    update_thresh: ?*const fn (*TraceBuffer, u64) void,
};

// ============================================================================
// Kprobes
// ============================================================================

pub const KprobeType = enum(u8) {
    kprobe = 0,
    kretprobe = 1,
    jprobe = 2, // Deprecated but kept for compatibility
};

pub const KprobeState = enum(u8) {
    disabled = 0,
    registered = 1,
    armed = 2,
    gone = 3,
};

pub const Kprobe = struct {
    addr: u64,
    symbol: [128]u8,
    symbol_len: u8,
    offset: u32,
    probe_type: KprobeType,
    state: KprobeState,
    // Original instruction
    opcode: [16]u8,
    opcode_len: u8,
    // Handler
    pre_handler: ?*const fn (*Kprobe, *KprobeRegs) i32,
    post_handler: ?*const fn (*Kprobe, *KprobeRegs, u64) void,
    fault_handler: ?*const fn (*Kprobe, *KprobeRegs, i32) i32,
    // Stats
    nmissed: u64,
    nhit: u64,
    // Flags
    flags: u32,

    pub const KPROBE_FLAG_DISABLED: u32 = 1;
    pub const KPROBE_FLAG_OPTIMIZED: u32 = 2;
    pub const KPROBE_FLAG_FTRACE: u32 = 4;
    pub const KPROBE_FLAG_GONE: u32 = 8;
};

pub const KprobeRegs = struct {
    // x86_64 register state at probe point
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

pub const Kretprobe = struct {
    kp: Kprobe,
    handler: ?*const fn (*KretprobeInstance, *KprobeRegs) i32,
    entry_handler: ?*const fn (*Kretprobe, *KprobeRegs) i32,
    maxactive: u32,
    nmissed: u64,
    data_size: u32,
};

pub const KretprobeInstance = struct {
    rp: ?*Kretprobe,
    ret_addr: u64,
    entry_stamp: u64,
    task: ?*anyopaque,
};

// ============================================================================
// Uprobes (User-space probes)
// ============================================================================

pub const Uprobe = struct {
    inode: ?*anyopaque,
    offset: u64,
    ref_count: u32,
    state: UprobeState,
    // Original instruction
    insn: [16]u8,
    insn_len: u8,
    // Filter
    filter_fn: ?*const fn (*Uprobe, u64) bool,
    // Handlers chain
    handler: ?*const fn (*Uprobe, *KprobeRegs) i32,
    ret_handler: ?*const fn (*Uprobe, u64, *KprobeRegs) i32,
    // Stats
    nhit: u64,
};

pub const UprobeState = enum(u8) {
    registered = 0,
    armed = 1,
    disabled = 2,
    deleted = 3,
};

// ============================================================================
// Perf Events
// ============================================================================

pub const PerfEventAttr = struct {
    event_type: PerfEventType,
    size: u32,
    config: u64,
    sample_period: u64,       // Or sample_freq
    sample_type: PerfSampleType,
    read_format: PerfReadFormat,
    flags: PerfEventFlags,
    wakeup_events: u32,       // Or wakeup_watermark
    bp_type: u32,
    bp_addr: u64,             // Or kprobe_func or uprobe_path
    bp_len: u64,              // Or kprobe_addr or probe_offset
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    aux_sample_size: u32,
    sig_data: u64,
};

pub const PerfEventType = enum(u32) {
    hardware = 0,
    software = 1,
    tracepoint = 2,
    hw_cache = 3,
    raw = 4,
    breakpoint = 5,
};

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
    _reserved: u39 = 0,
};

pub const PerfReadFormat = packed struct(u64) {
    total_time_enabled: bool = false,
    total_time_running: bool = false,
    id: bool = false,
    group: bool = false,
    lost: bool = false,
    _reserved: u59 = 0,
};

pub const PerfEventFlags = packed struct(u64) {
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
    precise_ip: u2 = 0,
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
    _reserved: u26 = 0,
};

// Perf event mmap page (shared between kernel and userspace)
pub const PerfEventMmapPage = struct {
    version: u32,
    compat_version: u32,
    lock: u32,
    index: u32,
    offset: i64,
    time_enabled: u64,
    time_running: u64,
    capabilities: u64,
    pmc_width: u16,
    time_shift: u16,
    time_mult: u32,
    time_offset: u64,
    time_zero: u64,
    size: u32,
    aux_head: u64,
    aux_tail: u64,
    aux_offset: u64,
    aux_size: u64,
    data_head: u64,
    data_tail: u64,
    data_offset: u64,
    data_size: u64,
};

// ============================================================================
// Tracepoints (static)
// ============================================================================

pub const MAX_TRACEPOINTS: usize = 4096;

pub const Tracepoint = struct {
    name: [128]u8,
    name_len: u8,
    key: u32,      // Static key (branch prediction)
    enabled: bool,
    regfunc: ?*const fn () i32,
    unregfunc: ?*const fn () void,
    // Callback list
    callbacks: [16]TracepointCallback,
    nr_callbacks: u8,
    // Metadata
    subsystem: [32]u8,
    event_id: u32,
};

pub const TracepointCallback = struct {
    func: *const fn (?*anyopaque, ...) void,
    data: ?*anyopaque,
    priority: i32,
};

// ============================================================================
// Event Categories (tracepoint subsystems)
// ============================================================================

pub const TraceSubsystem = enum(u8) {
    sched = 0,
    irq = 1,
    block = 2,
    net = 3,
    mm = 4,
    fs = 5,
    power = 6,
    timer = 7,
    syscalls = 8,
    workqueue = 9,
    signal = 10,
    sock = 11,
    rcu = 12,
    tlb = 13,
    lock = 14,
    kvm = 15,
    writeback = 16,
    compaction = 17,
    kmem = 18,
    huge_memory = 19,
    migrate = 20,
    task = 21,
    // Zxyphor
    zxy_ipc = 200,
    zxy_security = 201,
    zxy_virt = 202,
    zxy_sched = 203,
};

// ============================================================================
// Hardware Latency Detector
// ============================================================================

pub const HwlatDetector = struct {
    enabled: bool,
    threshold_ns: u64,
    width_us: u64,       // Sample width
    window_us: u64,      // Sample window
    // Results
    count: u64,
    max_ns: u64,
    total_ns: u64,
    // NMI-based detection
    nmi_count: u64,
    nmi_total_ns: u64,
};

// ============================================================================
// OS Noise Tracer
// ============================================================================

pub const OsnoiseTracer = struct {
    enabled: bool,
    period_us: u64,      // Measurement period
    runtime_us: u64,     // How long to run per period
    threshold_us: u64,   // reporting threshold
    // Results per CPU
    per_cpu: [FTRACE_MAX_CPUS]OsnoiseResult,
};

pub const OsnoiseResult = struct {
    runtime_us: u64,
    noise_us: u64,
    max_single_noise_us: u64,
    hw_noise_us: u64,
    nmi_count: u64,
    nmi_total_us: u64,
    irq_count: u64,
    irq_total_us: u64,
    softirq_count: u64,
    softirq_total_us: u64,
    thread_count: u64,
    thread_total_us: u64,
};

// ============================================================================
// Timer Latency Tracer
// ============================================================================

pub const TimerlatTracer = struct {
    enabled: bool,
    threshold_us: u64,
    // Results per CPU
    per_cpu: [FTRACE_MAX_CPUS]TimerlatResult,
};

pub const TimerlatResult = struct {
    count: u64,
    max_latency_us: u64,
    min_latency_us: u64,
    total_latency_us: u64,
    histogram: [1000]u64,  // Histogram buckets (1us each)
};

// ============================================================================
// Stack Trace
// ============================================================================

pub const MAX_STACK_DEPTH: usize = 64;

pub const StackTrace = struct {
    nr_entries: u32,
    entries: [MAX_STACK_DEPTH]u64,
    skip: u32,

    pub fn init() StackTrace {
        return StackTrace{
            .nr_entries = 0,
            .entries = [_]u64{0} ** MAX_STACK_DEPTH,
            .skip = 0,
        };
    }

    pub fn push(self: *StackTrace, addr: u64) bool {
        if (self.nr_entries >= MAX_STACK_DEPTH) return false;
        self.entries[self.nr_entries] = addr;
        self.nr_entries += 1;
        return true;
    }
};

// Stack tracer (tracks deepest kernel stack usage)
pub const StackTracer = struct {
    enabled: bool,
    max_stack_size: u64,
    max_stack_trace: StackTrace,
    per_cpu_max: [FTRACE_MAX_CPUS]u64,
};

// ============================================================================
// Dynamic Debug
// ============================================================================

pub const DynamicDebugEntry = struct {
    filename: [128]u8,
    function: [64]u8,
    format: [256]u8,
    lineno: u32,
    module: [64]u8,
    flags: DynamicDebugFlags,
};

pub const DynamicDebugFlags = packed struct(u32) {
    enabled: bool = false,
    print: bool = false,
    prefix_timestamp: bool = false,
    prefix_module: bool = false,
    prefix_function: bool = false,
    prefix_line: bool = false,
    prefix_thread_id: bool = false,
    _reserved: u25 = 0,
};

// ============================================================================
// Trace Event Filter
// ============================================================================

pub const TraceFilterOp = enum(u8) {
    eq = 0,
    ne = 1,
    lt = 2,
    le = 3,
    gt = 4,
    ge = 5,
    glob = 6,
    band = 7, // &
};

pub const TraceFilter = struct {
    field: [64]u8,
    field_len: u8,
    op: TraceFilterOp,
    val: u64,
    str_val: [256]u8,
    str_val_len: u16,
    is_string: bool,
};

pub const TraceEventFilter = struct {
    filter_string: [512]u8,
    filter_len: u16,
    predicates: [16]TraceFilter,
    nr_predicates: u8,
    logic: [15]u8,  // AND=0, OR=1 between predicates
};

// ============================================================================
// Trace Pipe Output
// ============================================================================

pub const TraceOutputFormat = enum(u8) {
    default = 0,
    raw = 1,
    hex = 2,
    bin = 3,
    latency = 4,
    block = 5,
    function = 6,
    function_graph = 7,
};

pub const TraceOptions = struct {
    print_parent: bool,
    sym_offset: bool,
    sym_addr: bool,
    verbose: bool,
    raw: bool,
    hex: bool,
    bin: bool,
    block: bool,
    trace_printk: bool,
    annotate: bool,
    userstacktrace: bool,
    sym_userobj: bool,
    printk_msg_only: bool,
    context_info: bool,
    latency_format: bool,
    sleep_time: bool,
    graph_time: bool,
    record_cmd: bool,
    record_tgid: bool,
    overwrite: bool,
    disable_on_free: bool,
    irq_info: bool,
    markers: bool,
    event_fork: bool,
    pause_on_trace: bool,
    hash_ptr: bool,
    function_fork: bool,
    display_graph: bool,
    stacktrace: bool,
};

// ============================================================================
// BPF Tracing
// ============================================================================

pub const BpfTracingProgType = enum(u8) {
    kprobe = 0,
    tracepoint = 1,
    perf_event = 2,
    raw_tracepoint = 3,
    raw_tracepoint_writable = 4,
    fentry = 5,
    fexit = 6,
    fmod_ret = 7,
    lsm = 8,
    // Zxyphor extensions
    zxy_kretprobe = 200,
    zxy_struct_ops = 201,
};

pub const BpfTracingLink = struct {
    prog_type: BpfTracingProgType,
    prog_id: u32,
    target_name: [128]u8,
    target_len: u8,
    attach_type: u32,
    target_btf_id: u32,
    cookie: u64,
};

// ============================================================================
// Trace Instance Management
// ============================================================================

pub const MAX_TRACE_INSTANCES: usize = 64;

pub const TraceInstance = struct {
    name: [64]u8,
    name_len: u8,
    buffer: TraceBuffer,
    current_tracer: TracerType,
    event_filter: [256]TraceEventFilter,
    nr_filters: u32,
    // Tracepoint enable mask
    enabled_events: [MAX_TRACEPOINTS / 64]u64,
    // Active kprobes for this instance
    kprobes: [256]Kprobe,
    nr_kprobes: u32,
    // Options
    options: TraceOptions,
    output_format: TraceOutputFormat,
    // Clock
    clock_id: TraceClockId,
    // Snapshot
    has_snapshot: bool,
    // Stats
    entries_total: u64,
    overrun_total: u64,

    pub fn is_event_enabled(self: *const TraceInstance, event_id: u32) bool {
        if (event_id >= MAX_TRACEPOINTS) return false;
        const word = event_id / 64;
        const bit: u6 = @intCast(event_id % 64);
        return (self.enabled_events[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn enable_event(self: *TraceInstance, event_id: u32) void {
        if (event_id >= MAX_TRACEPOINTS) return;
        const word = event_id / 64;
        const bit: u6 = @intCast(event_id % 64);
        self.enabled_events[word] |= @as(u64, 1) << bit;
    }

    pub fn disable_event(self: *TraceInstance, event_id: u32) void {
        if (event_id >= MAX_TRACEPOINTS) return;
        const word = event_id / 64;
        const bit: u6 = @intCast(event_id % 64);
        self.enabled_events[word] &= ~(@as(u64, 1) << bit);
    }
};

// ============================================================================
// Profiling Statistics
// ============================================================================

pub const ProfilingStats = struct {
    // CPU
    cpu_cycles: u64,
    instructions: u64,
    ipc: u64,            // Instructions per cycle * 1000
    cache_references: u64,
    cache_misses: u64,
    cache_miss_rate: u32, // Per mille
    branch_instructions: u64,
    branch_misses: u64,
    branch_miss_rate: u32,
    // Memory
    page_faults: u64,
    minor_faults: u64,
    major_faults: u64,
    context_switches: u64,
    cpu_migrations: u64,
    // Timing
    task_clock_ns: u64,
    wall_clock_ns: u64,
    cpu_utilization: u32,  // Per mille
};
