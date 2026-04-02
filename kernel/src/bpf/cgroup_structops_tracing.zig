// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - BPF Cgroup, Struct_Ops & Tracing Detail
// Complete cgroup BPF programs, struct_ops registration,
// BPF tracing (kprobe/uprobe/tracepoint/raw_tracepoint),
// perf event attachment, BPF iterators, BPF token

const std = @import("std");

// ============================================================================
// BPF Cgroup Types
// ============================================================================

pub const BpfCgroupAttachType = enum(u8) {
    CgroupInetIngress = 0,
    CgroupInetEgress = 1,
    CgroupInetSockCreate = 2,
    CgroupSockOps = 3,
    CgroupDevice = 4,
    CgroupInet4Bind = 5,
    CgroupInet6Bind = 6,
    CgroupInet4Connect = 7,
    CgroupInet6Connect = 8,
    CgroupInet4PostBind = 9,
    CgroupInet6PostBind = 10,
    CgroupUdp4Sendmsg = 11,
    CgroupUdp6Sendmsg = 12,
    CgroupSysctl = 13,
    CgroupUdp4Recvmsg = 14,
    CgroupUdp6Recvmsg = 15,
    CgroupGetsockopt = 16,
    CgroupSetsockopt = 17,
    CgroupInet4Getpeername = 18,
    CgroupInet6Getpeername = 19,
    CgroupInet4Getsockname = 20,
    CgroupInet6Getsockname = 21,
    CgroupInetSockRelease = 22,
    CgroupUnixConnect = 23,
    CgroupUnixSendmsg = 24,
    CgroupUnixRecvmsg = 25,
    CgroupUnixGetpeername = 26,
    CgroupUnixGetsockname = 27,
};

pub const BpfCgroupAttachFlags = packed struct(u32) {
    allow_override: bool,   // Only one prog per type
    allow_multi: bool,      // Multiple progs per type
    replace: bool,          // Replace existing prog
    _reserved: u29,
};

pub const BpfCgroupProgEntry = struct {
    prog_id: u32,
    attach_type: BpfCgroupAttachType,
    flags: BpfCgroupAttachFlags,
    link_id: u32,           // 0 if not link-based
};

pub const BpfCgroupStorage = struct {
    cgroup_id: u64,
    attach_type: BpfCgroupAttachType,
    map_fd: i32,
    key_size: u32,
    value_size: u32,
};

// ============================================================================
// BPF Sock Ops Context
// ============================================================================

pub const BpfSockOpsOp = enum(u32) {
    TimeoutInit = 0,
    RwndInit = 1,
    TcpConnectCb = 2,
    ActiveEstablishedCb = 3,
    PassiveEstablishedCb = 4,
    NeedsCongestionCtl = 5,
    BaseRtt = 6,
    RtoReTrans = 7,
    RetransMitTimeout = 8,
    CbReturn = 9,
    ActiveEstablishedRtt = 10,
    ParseHdrOpt = 11,
    HdrOptLen = 12,
    WriteHdrOpt = 13,
};

pub const BpfSockOpsContext = struct {
    op: BpfSockOpsOp,
    reply: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [4]u32,
    local_ip6: [4]u32,
    remote_port: u32,
    local_port: u32,
    is_fullsock: u32,
    snd_cwnd: u32,
    srtt_us: u32,
    bpf_sock_ops_cb_flags: u32,
    state: u32,
    rtt_min: u32,
    snd_ssthresh: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    mss_cache: u32,
    ecn_flags: u32,
    rate_delivered: u32,
    rate_interval_us: u32,
    packets_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    segs_in: u32,
    data_segs_in: u32,
    segs_out: u32,
    data_segs_out: u32,
    lost_out: u32,
    sacked_out: u32,
    sk_txhash: u32,
    bytes_received: u64,
    bytes_acked: u64,
    skb_data: u64,
    skb_data_end: u64,
    skb_len: u32,
    skb_tcp_flags: u32,
};

pub const BpfSockOpsCbFlags = packed struct(u32) {
    timestamp_cb: bool,
    retrans_cb: bool,
    state_cb: bool,
    rtt_cb: bool,
    parse_all_hdr_opt_cb: bool,
    all_flags: bool,
    write_hdr_opt_cb: bool,
    _reserved: u25,
};

// ============================================================================
// BPF Struct Ops
// ============================================================================

pub const BpfStructOpsState = enum(u8) {
    Init = 0,
    Inuse = 1,
    Tobefree = 2,
    Ready = 3,
};

pub const BpfStructOpsMap = struct {
    map_id: u32,
    btf_vmlinux_id: u32,
    struct_ops_type: [64]u8,   // e.g., "tcp_congestion_ops"
    state: BpfStructOpsState,
    num_members: u32,
    member_progs: [32]BpfStructOpsMember,
    image: u64,                // JIT image address
    image_size: u32,
    kern_vdata: u64,
};

pub const BpfStructOpsMember = struct {
    member_name: [64]u8,
    member_idx: u32,
    prog_id: u32,
    prog_fd: i32,
    is_mandatory: bool,
    btf_func_type_id: u32,
};

pub const BpfStructOpsType = struct {
    name: [64]u8,
    btf_id: u32,
    owner: usize,              // Module pointer
    num_members: u32,
    value_size: u32,
    init: ?*const fn (u64, u64) i32,
    unreg: ?*const fn (u64) void,
    reg: ?*const fn (u64) i32,
    update: ?*const fn (u64, u64) i32,
    validate: ?*const fn (u64) i32,
    init_member: ?*const fn (u64, u32, u64, u64) i32,
    cfi_stubs: u64,
};

// ============================================================================
// BPF Tracing Programs
// ============================================================================

pub const BpfTracingType = enum(u8) {
    Kprobe = 0,
    Kretprobe = 1,
    Uprobe = 2,
    Uretprobe = 3,
    Tracepoint = 4,
    RawTracepoint = 5,
    RawTracepointWritable = 6,
    FEntry = 7,
    FExit = 8,
    Modify_Return = 9,
    Lsm = 10,
    Iter = 11,
};

pub const BpfKprobeOpts = struct {
    retprobe: bool,
    bpf_cookie: u64,
    offset: u64,
    func_name: [128]u8,
    attach_mode: BpfProbeAttachMode,
};

pub const BpfUprobeOpts = struct {
    retprobe: bool,
    bpf_cookie: u64,
    ref_ctr_offset: u64,
    func_name: [128]u8,
    pid: i32,
    binary_path: [256]u8,
};

pub const BpfProbeAttachMode = enum(u8) {
    Default = 0,
    Legacy = 1,
    Perf = 2,
    Link = 3,
};

pub const BpfTracingLink = struct {
    link_id: u32,
    prog_id: u32,
    tracing_type: BpfTracingType,
    target_btf_id: u32,
    cookie: u64,
    attach_type: u32,
};

// ============================================================================
// BPF Perf Event
// ============================================================================

pub const BpfPerfEventType = enum(u8) {
    Hardware = 0,
    Software = 1,
    Tracepoint = 2,
    HwCache = 3,
    Raw = 4,
    Breakpoint = 5,
};

pub const BpfPerfEventAttr = struct {
    pe_type: BpfPerfEventType,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: BpfPerfEventFlags,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr_config1: u64,
    bp_len_config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
};

pub const BpfPerfEventFlags = packed struct(u64) {
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
    precise_ip: u2,
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

// ============================================================================
// BPF Iterator
// ============================================================================

pub const BpfIterTarget = enum(u8) {
    BpfMap = 0,
    BpfMapElem = 1,
    BpfProg = 2,
    BpfTask = 3,
    BpfTaskFile = 4,
    BpfTaskVma = 5,
    BpfNetlink = 6,
    BpfSkStorage = 7,
    BpfIpv6Route = 8,
    BpfNetdev = 9,
    BpfUnixSocket = 10,
    BpfUdpSocket = 11,
    BpfTcpSocket = 12,
    BpfKsym = 13,
    BpfCgroup = 14,
};

pub const BpfIterLinkInfo = struct {
    target: BpfIterTarget,
    target_name: [64]u8,
    prog_id: u32,
    link_id: u32,
    // Union info based on target
    map_id: u32,
    cgroup_id: u64,
    cgroup_attach_type: u32,
    task_tid: u32,
    task_pid: u32,
};

pub const BpfIterOps = struct {
    name: [64]u8,
    target: BpfIterTarget,
    init: ?*const fn (*BpfIterPriv, *BpfIterAux) i32,
    fini: ?*const fn (*BpfIterPriv) void,
    seq_start: ?*const fn (*BpfIterPriv, *u64) ?*anyopaque,
    seq_next: ?*const fn (*BpfIterPriv, ?*anyopaque, *u64) ?*anyopaque,
    seq_stop: ?*const fn (*BpfIterPriv, ?*anyopaque) void,
    seq_show: ?*const fn (*BpfIterPriv, *SeqFile) i32,
    fill_link_info: ?*const fn (*BpfIterLinkInfo) i32,
};

pub const BpfIterPriv = struct {
    target: BpfIterTarget,
    prog: u64,
    session_id: u64,
    seq_num: u64,
};

pub const BpfIterAux = struct {
    map: u64,
    cgroup: u64,
    task: u64,
};

pub const SeqFile = struct {
    buf: [*]u8,
    size: usize,
    from: usize,
    count: usize,
    pad_until: usize,
    index: u64,
    read_pos: u64,
    version: u64,
    private_data: usize,
};

// ============================================================================
// BPF Token (Delegation)
// ============================================================================

pub const BpfTokenCapMask = packed struct(u64) {
    map_create: bool,
    prog_load: bool,
    btf_load: bool,
    link_create: bool,
    _reserved: u60,
};

pub const BpfToken = struct {
    token_id: u32,
    allowed_cmds: u64,
    allowed_map_types: u64,
    allowed_prog_types: u64,
    allowed_attach_types: u64,
    security_token: u64,
    userns: u64,           // User namespace
};

// ============================================================================
// BPF Ring Buffer
// ============================================================================

pub const BpfRingbufHdr = packed struct(u32) {
    len: u24,
    pg_off: u5,
    discarded: bool,
    busy: bool,
    _reserved: u1,
};

pub const BpfRingbuf = struct {
    mask: u64,
    consumer_pos: u64,     // Consumer position (cacheline-aligned)
    producer_pos: u64,     // Producer position (cacheline-aligned)
    pending_pos: u64,
    data: [*]u8,
    pages: u64,
    nr_pages: u32,
    map_fd: i32,
    epoll_fd: i32,
};

pub const BpfRingbufOpts = struct {
    sz: u64,               // Ring buffer size (must be power of 2)
    map_flags: u32,
    numa_node: u32,
};

// ============================================================================
// BPF Bloom Filter & Timer
// ============================================================================

pub const BpfBloomFilterOpts = struct {
    nr_hash_funcs: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    seed: u32,
};

pub const BpfTimerState = enum(u8) {
    Init = 0,
    Set = 1,
    Running = 2,
    Cancelled = 3,
};

pub const BpfTimer = struct {
    timer_state: BpfTimerState,
    callback_fn: u64,
    map: u64,
    key: u64,
    flags: u32,
    nsec: u64,             // Expiry in nanoseconds (absolute)
};

// ============================================================================
// BPF Arena
// ============================================================================

pub const BpfArena = struct {
    map_fd: i32,
    user_vm_start: u64,
    kern_vm_start: u64,
    size: u64,
    max_entries: u32,
    flags: u32,
};

// ============================================================================
// Manager
// ============================================================================

pub const BpfCgroupStructOpsManager = struct {
    total_cgroup_progs: u32,
    total_struct_ops: u32,
    total_kprobes: u32,
    total_uprobes: u32,
    total_tracepoints: u32,
    total_fentry: u32,
    total_fexit: u32,
    total_iterators: u32,
    total_perf_events: u32,
    total_tokens: u32,
    total_ringbufs: u32,
    total_timers: u32,
    total_arenas: u32,
    initialized: bool,

    pub fn init() BpfCgroupStructOpsManager {
        return .{
            .total_cgroup_progs = 0,
            .total_struct_ops = 0,
            .total_kprobes = 0,
            .total_uprobes = 0,
            .total_tracepoints = 0,
            .total_fentry = 0,
            .total_fexit = 0,
            .total_iterators = 0,
            .total_perf_events = 0,
            .total_tokens = 0,
            .total_ringbufs = 0,
            .total_timers = 0,
            .total_arenas = 0,
            .initialized = true,
        };
    }
};
