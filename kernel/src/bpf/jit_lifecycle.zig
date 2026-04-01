// SPDX-License-Identifier: MIT
// Zxyphor Kernel - BPF JIT Compiler, Program Lifecycle,
// BPF Tracing, BPF Networking (XDP/TC), BPF Cgroup,
// BPF Iterator, BPF LSM, BPF Struct Ops
// More advanced than Linux 2026 BPF subsystem

const std = @import("std");

// ============================================================================
// BPF Instruction Set
// ============================================================================

/// BPF instruction opcodes (eBPF v4+ with Zxyphor extensions)
pub const BpfInsn = struct {
    code: u8,
    dst_reg: u4,
    src_reg: u4,
    off: i16,
    imm: i32,
};

/// BPF instruction classes
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;
pub const BPF_ATOMIC: u8 = 0xDB;

/// BPF ALU operations
pub const BpfAluOp = enum(u8) {
    add = 0x00,
    sub = 0x10,
    mul = 0x20,
    div = 0x30,
    bor = 0x40,
    band = 0x50,
    lsh = 0x60,
    rsh = 0x70,
    neg = 0x80,
    mod = 0x90,
    xor = 0xA0,
    mov = 0xB0,
    arsh = 0xC0,
    end = 0xD0,
    // Zxyphor extensions
    zxy_sdiv = 0xE0,
    zxy_smod = 0xF0,
};

/// BPF JMP operations
pub const BpfJmpOp = enum(u8) {
    ja = 0x00,
    jeq = 0x10,
    jgt = 0x20,
    jge = 0x30,
    jset = 0x40,
    jne = 0x50,
    jsgt = 0x60,
    jsge = 0x70,
    call = 0x80,
    exit = 0x90,
    jlt = 0xA0,
    jle = 0xB0,
    jslt = 0xC0,
    jsle = 0xD0,
    // Zxyphor
    zxy_jcall = 0xE0, // Conditional call
};

/// BPF atomic operations
pub const BpfAtomicOp = enum(u32) {
    add = 0x00,
    bor = 0x40,
    band = 0x50,
    bxor = 0xA0,
    xchg = 0xE1,
    cmpxchg = 0xF1,
    // With fetch flag (0x01)
    fetch_add = 0x01,
    fetch_or = 0x41,
    fetch_and = 0x51,
    fetch_xor = 0xA1,
};

/// BPF register set
pub const BPF_REG_0: u4 = 0; // Return value
pub const BPF_REG_1: u4 = 1; // Arg 1 / ctx
pub const BPF_REG_2: u4 = 2; // Arg 2
pub const BPF_REG_3: u4 = 3; // Arg 3
pub const BPF_REG_4: u4 = 4; // Arg 4
pub const BPF_REG_5: u4 = 5; // Arg 5
pub const BPF_REG_6: u4 = 6; // Callee saved
pub const BPF_REG_7: u4 = 7; // Callee saved
pub const BPF_REG_8: u4 = 8; // Callee saved
pub const BPF_REG_9: u4 = 9; // Callee saved
pub const BPF_REG_10: u4 = 10; // Frame pointer (read-only)
// Zxyphor
pub const BPF_REG_11: u4 = 11; // Extended register
pub const BPF_REG_12: u4 = 12; // Extended register

// ============================================================================
// BPF Program Types
// ============================================================================

/// Program type (Linux-compatible + Zxyphor extras)
pub const BpfProgType = enum(u32) {
    unspec = 0,
    socket_filter = 1,
    kprobe = 2,
    sched_cls = 3,
    sched_act = 4,
    tracepoint = 5,
    xdp = 6,
    perf_event = 7,
    cgroup_skb = 8,
    cgroup_sock = 9,
    lwt_in = 10,
    lwt_out = 11,
    lwt_xmit = 12,
    sock_ops = 13,
    sk_skb = 14,
    cgroup_device = 15,
    sk_msg = 16,
    raw_tracepoint = 17,
    cgroup_sock_addr = 18,
    lwt_seg6local = 19,
    lirc_mode2 = 20,
    sk_reuseport = 21,
    flow_dissector = 22,
    cgroup_sysctl = 23,
    raw_tracepoint_writable = 24,
    cgroup_sockopt = 25,
    tracing = 26,
    struct_ops = 27,
    ext = 28,
    lsm = 29,
    sk_lookup = 30,
    syscall = 31,
    netfilter = 32,
    // Zxyphor extensions
    zxy_irq_handler = 100,
    zxy_sched_ext = 101,
    zxy_mm_hook = 102,
    zxy_fs_hook = 103,
    zxy_driver_hook = 104,
    zxy_virt_hook = 105,
};

/// BPF attach type
pub const BpfAttachType = enum(u32) {
    cgroup_inet_ingress = 0,
    cgroup_inet_egress = 1,
    cgroup_inet_sock_create = 2,
    cgroup_sock_ops = 3,
    sk_skb_stream_parser = 4,
    sk_skb_stream_verdict = 5,
    cgroup_device = 6,
    sk_msg_verdict = 7,
    cgroup_inet4_bind = 8,
    cgroup_inet6_bind = 9,
    cgroup_inet4_connect = 10,
    cgroup_inet6_connect = 11,
    cgroup_inet4_post_bind = 12,
    cgroup_inet6_post_bind = 13,
    cgroup_udp4_sendmsg = 14,
    cgroup_udp6_sendmsg = 15,
    lirc_mode2 = 16,
    flow_dissector = 17,
    cgroup_sysctl = 18,
    cgroup_udp4_recvmsg = 19,
    cgroup_udp6_recvmsg = 20,
    cgroup_getsockopt = 21,
    cgroup_setsockopt = 22,
    trace_raw_tp = 23,
    trace_fentry = 24,
    trace_fexit = 25,
    modify_return = 26,
    lsm_mac = 27,
    trace_iter = 28,
    cgroup_inet4_getpeername = 29,
    cgroup_inet6_getpeername = 30,
    cgroup_inet4_getsockname = 31,
    cgroup_inet6_getsockname = 32,
    xdp_devmap = 33,
    cgroup_inet_sock_release = 34,
    xdp_cpumap = 35,
    sk_lookup = 36,
    xdp = 37,
    sk_skb_verdict = 38,
    sk_reuseport_select = 39,
    sk_reuseport_select_or_migrate = 40,
    perf_event = 41,
    trace_kprobe_multi = 42,
    lsm_cgroup = 43,
    struct_ops = 44,
    netfilter = 45,
    tcx_ingress = 46,
    tcx_egress = 47,
    trace_uprobe_multi = 48,
    cgroup_unix_connect = 49,
    cgroup_unix_sendmsg = 50,
    cgroup_unix_recvmsg = 51,
    cgroup_unix_getpeername = 52,
    cgroup_unix_getsockname = 53,
    netkit_primary = 54,
    netkit_peer = 55,
    // Zxyphor
    zxy_irq_entry = 200,
    zxy_sched_tick = 201,
    zxy_page_fault = 202,
    zxy_syscall_enter = 203,
    zxy_syscall_exit = 204,
};

// ============================================================================
// BPF JIT Compiler
// ============================================================================

/// JIT backend type
pub const JitBackend = enum(u8) {
    interpreter = 0,  // Fallback interpreter
    x86_64 = 1,
    arm64 = 2,
    riscv64 = 3,
    s390x = 4,
    mips64 = 5,
    loongarch64 = 6,
    // Zxyphor
    zxy_optimizing = 10,  // Multi-pass optimizing JIT
};

/// JIT compilation flags
pub const JitFlags = packed struct {
    enable: bool = false,
    hardened: bool = false,      // Constant blinding, random offsets
    kallsyms: bool = false,      // Add to kallsyms
    dump: bool = false,          // Dump JIT code
    limit: bool = false,         // Limit JIT memory
    // Zxyphor
    zxy_superblock: bool = false, // Superblock optimization
    zxy_specialize: bool = false, // Map key specialization
    zxy_vectorize: bool = false,  // SIMD vectorization
    _padding: u8 = 0,
};

/// JIT emit context
pub const JitEmitCtx = struct {
    // Image
    image: ?[*]u8,
    image_size: u32,
    // Offsets
    insn_offsets: ?[*]u32,
    nr_insns: u32,
    // Code generation
    code_len: u32,
    prologue_len: u32,
    epilogue_len: u32,
    // Constant pool
    const_pool: ?[*]u8,
    const_pool_size: u32,
    // Register allocation
    callee_regs_used: u16,
    // Cleanup function list
    nr_cleanup_fns: u32,
    // Architecture specific
    arch_ctx: [128]u8,
    // Stats
    nr_passes: u32,
    compile_time_ns: u64,
    // Zxyphor
    zxy_optimization_level: u8,
    zxy_nr_superblocks: u32,
};

/// x86_64 JIT register mapping
pub const X64JitRegs = struct {
    pub const RAX: u8 = 0; // BPF_REG_0 (return)
    pub const RDI: u8 = 7; // BPF_REG_1 (arg1)
    pub const RSI: u8 = 6; // BPF_REG_2 (arg2)
    pub const RDX: u8 = 2; // BPF_REG_3 (arg3)
    pub const RCX: u8 = 1; // BPF_REG_4 (arg4)
    pub const R8: u8 = 8;  // BPF_REG_5 (arg5)
    pub const RBX: u8 = 3; // BPF_REG_6 (callee saved)
    pub const R13: u8 = 13; // BPF_REG_7
    pub const R14: u8 = 14; // BPF_REG_8
    pub const R15: u8 = 15; // BPF_REG_9
    pub const RBP: u8 = 5;  // BPF_REG_10 (frame pointer)
    // Scratch regs
    pub const R9: u8 = 9;
    pub const R10: u8 = 10;
    pub const R11: u8 = 11;
    pub const R12: u8 = 12;
};

// ============================================================================
// BPF Program Lifecycle
// ============================================================================

/// Program state
pub const BpfProgState = enum(u8) {
    unloaded = 0,
    loaded = 1,
    verified = 2,
    jit_compiled = 3,
    attached = 4,
    running = 5,
    frozen = 6,        // Cannot change after freeze
    detached = 7,
    defunct = 8,
};

/// Program info
pub const BpfProgInfo = struct {
    prog_type: BpfProgType,
    attach_type: BpfAttachType,
    state: BpfProgState,
    id: u32,
    tag: [8]u8,         // SHA hash of instructions
    name: [16]u8,
    // Instructions
    nr_insns: u32,
    insns: ?[*]const BpfInsn,
    // JIT
    jited: bool,
    jited_prog_len: u32,
    jited_prog: ?[*]const u8,
    // Maps
    nr_map_ids: u32,
    map_ids: ?[*]const u32,
    // BTF
    btf_id: u32,
    func_info_rec_size: u32,
    nr_func_info: u32,
    nr_line_info: u32,
    nr_jited_line_info: u32,
    // License
    gpl_compatible: bool,
    // Stats
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    // Timestamps
    created_by_uid: u32,
    nr_pinned: u32,
    // Zxyphor
    zxy_verified_depth: u32,
    zxy_optimization_stats: BpfOptStats,
};

/// BPF optimization stats (Zxyphor)
pub const BpfOptStats = struct {
    dead_code_eliminated: u32,
    constant_folded: u32,
    branches_simplified: u32,
    maps_inlined: u32,
    helpers_inlined: u32,
    vectorized_ops: u32,
};

// ============================================================================
// BPF Tracing
// ============================================================================

/// Tracing program subtype
pub const BpfTracingType = enum(u8) {
    kprobe = 0,
    kretprobe = 1,
    uprobe = 2,
    uretprobe = 3,
    tracepoint = 4,
    raw_tracepoint = 5,
    fentry = 6,
    fexit = 7,
    fmod_ret = 8,
    // Multi-attach
    kprobe_multi = 9,
    uprobe_multi = 10,
    // Iterator
    iter = 11,
    // Zxyphor
    zxy_hardware_breakpoint = 20,
    zxy_pmu = 21,
};

/// Kprobe BPF context
pub const BpfKprobeCtx = struct {
    regs: *anyopaque,   // pt_regs
    func_addr: u64,
    func_name_off: u32, // Offset in BTF
    retval: u64,        // For kretprobe
};

/// BPF perf event output
pub const BpfPerfEventOutput = struct {
    cpu: u32,
    size: u32,
    data: [*]const u8,
    lost_events: u64,
};

/// BPF ring buffer event
pub const BpfRingbufEvent = struct {
    len: u32,
    pg_off: u32,
    data: [*]const u8,
};

// ============================================================================
// XDP (eXpress Data Path)
// ============================================================================

/// XDP action
pub const XdpAction = enum(u32) {
    aborted = 0,
    drop = 1,
    pass = 2,
    tx = 3,
    redirect = 4,
    // Zxyphor
    zxy_encap = 10,   // Hardware encapsulation
    zxy_decap = 11,   // Hardware decapsulation
};

/// XDP context
pub const XdpMd = struct {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
};

/// XDP features
pub const XdpFeatures = packed struct {
    basic: bool = false,
    redirect: bool = false,
    ndo_xmit: bool = false,
    ndo_xmit_sg: bool = false,
    rx_sg: bool = false,
    hw_offload: bool = false,
    // Zxyphor
    zxy_zero_copy: bool = false,
    zxy_multi_buffer: bool = false,
    _padding: u8 = 0,
};

/// XDP metadata
pub const XdpMetaFlags = packed struct {
    timestamp: bool = false,
    hash: bool = false,
    vlan_tag: bool = false,
    rx_hash_type: u2 = 0,
    _padding: u3 = 0,
};

// ============================================================================
// TC (Traffic Control) BPF
// ============================================================================

/// TC action result
pub const TcActResult = enum(i32) {
    ok = 0,            // TC_ACT_OK
    reclassify = 1,    // TC_ACT_RECLASSIFY
    shot = 2,          // TC_ACT_SHOT (drop)
    pipe = 3,          // TC_ACT_PIPE
    stolen = 4,        // TC_ACT_STOLEN
    redirect = 7,      // TC_ACT_REDIRECT
};

/// tcx (TC eXpress) link info
pub const TcxLinkInfo = struct {
    prog_id: u32,
    ifindex: u32,
    attach_type: BpfAttachType,
    // Ordering
    expected_revision: u64,
    // Flags
    flags: TcxFlags,
};

/// TCX flags
pub const TcxFlags = packed struct {
    replace: bool = false,
    before: bool = false,
    after: bool = false,
    _padding: u5 = 0,
};

// ============================================================================
// BPF Cgroup
// ============================================================================

/// Cgroup BPF attach flags
pub const CgroupBpfFlags = packed struct {
    allow_override: bool = false,
    allow_multi: bool = false,
    replace: bool = false,
    _padding: u5 = 0,
};

/// Cgroup effective programs
pub const CgroupBpfEffective = struct {
    prog_type: BpfProgType,
    attach_type: BpfAttachType,
    nr_progs: u32,
    flags: CgroupBpfFlags,
};

// ============================================================================
// BPF Iterator
// ============================================================================

/// Iterator target type
pub const BpfIterTarget = enum(u32) {
    bpf_map_elem = 0,
    bpf_sk_storage_map = 1,
    bpf_sock = 2,
    bpf_task = 3,
    bpf_task_file = 4,
    bpf_task_vma = 5,
    bpf_map = 6,
    bpf_prog = 7,
    bpf_link = 8,
    cgroup = 9,
    css_task = 10,
    // Zxyphor
    zxy_bpf_netdev = 100,
    zxy_bpf_module = 101,
};

/// Iterator link info
pub const BpfIterLinkInfo = struct {
    target: BpfIterTarget,
    // Optional target-specific
    map_fd: i32,
    cgroup_fd: i32,
    cgroup_id: u64,
    order: u8,          // BPF_ITER_ORDER_UNSPEC = 0
    // Zxyphor
    zxy_filter: u64,
};

// ============================================================================
// BPF Struct Ops
// ============================================================================

/// Struct ops state
pub const BpfStructOpsState = enum(u8) {
    init = 0,
    inuse = 1,
    tobefree = 2,
    ready = 3,
};

/// Struct ops map value
pub const BpfStructOpsValue = struct {
    state: BpfStructOpsState,
    refcnt: u32,
    // The kernel struct being replaced
    kern_func_off: [64]u32,     // Offsets of function pointers
    nr_kern_funcs: u32,
    // BPF programs implementing each function
    links: [64]u32,             // BPF link IDs
    // Metadata
    btf_vmlinux_value_type_id: u32,
};

/// Known struct ops types
pub const StructOpsType = enum(u32) {
    tcp_congestion_ops = 0,
    bpf_dummy_ops = 1,
    sched_ext_ops = 2,        // sched_ext
    // Zxyphor
    zxy_fs_ops = 100,
    zxy_net_ops = 101,
    zxy_mm_ops = 102,
};

// ============================================================================
// BPF Links
// ============================================================================

/// BPF link type
pub const BpfLinkType = enum(u32) {
    unspec = 0,
    raw_tracepoint = 1,
    tracing = 2,
    cgroup = 3,
    iter = 4,
    netns = 5,
    xdp = 6,
    perf_event = 7,
    kprobe_multi = 8,
    struct_ops = 9,
    netfilter = 10,
    tcx = 11,
    uprobe_multi = 12,
    netkit = 13,
    // Zxyphor
    zxy_irq = 100,
    zxy_sched = 101,
};

/// BPF link info
pub const BpfLinkInfo = struct {
    link_type: BpfLinkType,
    id: u32,
    prog_id: u32,
    // Type-specific
    union_data: [128]u8,
};

// ============================================================================
// BPF Token
// ============================================================================

/// BPF token
pub const BpfToken = struct {
    allowed_cmds: u64,           // Bitmask of allowed BPF commands
    allowed_map_types: u64,      // Bitmask of map types
    allowed_prog_types: u64,     // Bitmask of prog types
    allowed_attach_types: u64,   // Bitmask of attach types
};

// ============================================================================
// BPF Subsystem Manager
// ============================================================================

pub const BpfJitSubsystem = struct {
    // Programs
    nr_loaded_progs: u64,
    nr_verified_progs: u64,
    nr_jitted_progs: u64,
    nr_attached_progs: u64,
    // JIT
    jit_backend: JitBackend,
    jit_flags: JitFlags,
    jit_memory_used: u64,
    jit_memory_limit: u64,
    // Verifier
    total_verifier_time_ns: u64,
    total_verification_states: u64,
    // XDP
    nr_xdp_progs: u32,
    // TC
    nr_tc_progs: u32,
    // Tracing
    nr_tracing_progs: u32,
    nr_kprobes: u32,
    // Struct ops
    nr_struct_ops: u32,
    // Maps
    nr_maps: u64,
    map_memory_used: u64,
    // Zxyphor
    zxy_optimization_enabled: bool,
    zxy_total_optimizations: u64,
    initialized: bool,

    pub fn init() BpfJitSubsystem {
        return BpfJitSubsystem{
            .nr_loaded_progs = 0,
            .nr_verified_progs = 0,
            .nr_jitted_progs = 0,
            .nr_attached_progs = 0,
            .jit_backend = .x86_64,
            .jit_flags = .{ .enable = true, .hardened = true, .kallsyms = true },
            .jit_memory_used = 0,
            .jit_memory_limit = 256 * 1024 * 1024, // 256MB
            .total_verifier_time_ns = 0,
            .total_verification_states = 0,
            .nr_xdp_progs = 0,
            .nr_tc_progs = 0,
            .nr_tracing_progs = 0,
            .nr_kprobes = 0,
            .nr_struct_ops = 0,
            .nr_maps = 0,
            .map_memory_used = 0,
            .zxy_optimization_enabled = true,
            .zxy_total_optimizations = 0,
            .initialized = false,
        };
    }
};
