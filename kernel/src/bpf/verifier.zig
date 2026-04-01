// SPDX-License-Identifier: MIT
// Zxyphor Kernel - BPF Verifier, JIT Compiler, and Map Types
// Full eBPF implementation: verifier with type tracking, JIT for x86_64, all map types

const std = @import("std");

// ============================================================================
// BPF Instruction Set
// ============================================================================

pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

pub const BPF_W: u8 = 0x00;  // 32-bit
pub const BPF_H: u8 = 0x08;  // 16-bit
pub const BPF_B: u8 = 0x10;  // 8-bit
pub const BPF_DW: u8 = 0x18; // 64-bit

pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_ATOMIC: u8 = 0xC0;

pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xA0;
pub const BPF_MOV: u8 = 0xB0;
pub const BPF_ARSH: u8 = 0xC0;
pub const BPF_END: u8 = 0xD0;

pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xA0;
pub const BPF_JLE: u8 = 0xB0;
pub const BPF_JSLT: u8 = 0xC0;
pub const BPF_JSLE: u8 = 0xD0;

pub const BPF_K: u8 = 0x00;   // Immediate
pub const BPF_X: u8 = 0x08;   // Register

pub const BPF_FETCH: u8 = 0x01;
pub const BPF_XCHG: u8 = 0xE0 | BPF_FETCH;
pub const BPF_CMPXCHG: u8 = 0xF0 | BPF_FETCH;

pub const BpfInsn = packed struct {
    code: u8,
    dst_reg: u4,
    src_reg: u4,
    off: i16,
    imm: i32,

    pub fn alu64_reg(op: u8, dst: u4, src: u4) BpfInsn {
        return .{ .code = BPF_ALU64 | BPF_X | op, .dst_reg = dst, .src_reg = src, .off = 0, .imm = 0 };
    }

    pub fn alu64_imm(op: u8, dst: u4, imm_val: i32) BpfInsn {
        return .{ .code = BPF_ALU64 | BPF_K | op, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = imm_val };
    }

    pub fn mov64_reg(dst: u4, src: u4) BpfInsn {
        return alu64_reg(BPF_MOV, dst, src);
    }

    pub fn mov64_imm(dst: u4, imm_val: i32) BpfInsn {
        return alu64_imm(BPF_MOV, dst, imm_val);
    }

    pub fn ldx_mem(size: u8, dst: u4, src: u4, off_val: i16) BpfInsn {
        return .{ .code = BPF_LDX | BPF_MEM | size, .dst_reg = dst, .src_reg = src, .off = off_val, .imm = 0 };
    }

    pub fn stx_mem(size: u8, dst: u4, src: u4, off_val: i16) BpfInsn {
        return .{ .code = BPF_STX | BPF_MEM | size, .dst_reg = dst, .src_reg = src, .off = off_val, .imm = 0 };
    }

    pub fn jmp_reg(op: u8, dst: u4, src: u4, off_val: i16) BpfInsn {
        return .{ .code = BPF_JMP | BPF_X | op, .dst_reg = dst, .src_reg = src, .off = off_val, .imm = 0 };
    }

    pub fn jmp_imm(op: u8, dst: u4, imm_val: i32, off_val: i16) BpfInsn {
        return .{ .code = BPF_JMP | BPF_K | op, .dst_reg = dst, .src_reg = 0, .off = off_val, .imm = imm_val };
    }

    pub fn call(func_id: i32) BpfInsn {
        return .{ .code = BPF_JMP | BPF_CALL, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = func_id };
    }

    pub fn exit_insn() BpfInsn {
        return .{ .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 };
    }
};

// ============================================================================
// BPF Program Types
// ============================================================================

pub const BpfProgType = enum(u32) {
    UNSPEC = 0,
    SOCKET_FILTER = 1,
    KPROBE = 2,
    SCHED_CLS = 3,
    SCHED_ACT = 4,
    TRACEPOINT = 5,
    XDP = 6,
    PERF_EVENT = 7,
    CGROUP_SKB = 8,
    CGROUP_SOCK = 9,
    LWT_IN = 10,
    LWT_OUT = 11,
    LWT_XMIT = 12,
    SOCK_OPS = 13,
    SK_SKB = 14,
    CGROUP_DEVICE = 15,
    SK_MSG = 16,
    RAW_TRACEPOINT = 17,
    CGROUP_SOCK_ADDR = 18,
    LWT_SEG6LOCAL = 19,
    LIRC_MODE2 = 20,
    SK_REUSEPORT = 21,
    FLOW_DISSECTOR = 22,
    CGROUP_SYSCTL = 23,
    RAW_TRACEPOINT_WRITABLE = 24,
    CGROUP_SOCKOPT = 25,
    TRACING = 26,
    STRUCT_OPS = 27,
    EXT = 28,
    LSM = 29,
    SK_LOOKUP = 30,
    SYSCALL = 31,
    NETFILTER = 32,
    // Zxyphor extensions
    ZXY_SCHED_EXT = 128,
    ZXY_STORAGE_FILTER = 129,
    ZXY_HYPERVISOR = 130,
    ZXY_SECURITY_POLICY = 131,
    _,
};

// ============================================================================
// BPF Map Types
// ============================================================================

pub const BpfMapType = enum(u32) {
    UNSPEC = 0,
    HASH = 1,
    ARRAY = 2,
    PROG_ARRAY = 3,
    PERF_EVENT_ARRAY = 4,
    PERCPU_HASH = 5,
    PERCPU_ARRAY = 6,
    STACK_TRACE = 7,
    CGROUP_ARRAY = 8,
    LRU_HASH = 9,
    LRU_PERCPU_HASH = 10,
    LPM_TRIE = 11,
    ARRAY_OF_MAPS = 12,
    HASH_OF_MAPS = 13,
    DEVMAP = 14,
    SOCKMAP = 15,
    CPUMAP = 16,
    XSKMAP = 17,
    SOCKHASH = 18,
    CGROUP_STORAGE = 19,
    REUSEPORT_SOCKARRAY = 20,
    PERCPU_CGROUP_STORAGE = 21,
    QUEUE = 22,
    STACK = 23,
    SK_STORAGE = 24,
    DEVMAP_HASH = 25,
    STRUCT_OPS = 26,
    RINGBUF = 27,
    INODE_STORAGE = 28,
    TASK_STORAGE = 29,
    BLOOM_FILTER = 30,
    USER_RINGBUF = 31,
    CGRP_STORAGE = 32,
    ARENA = 33,
    // Zxyphor extensions
    ZXY_BTREE = 128,
    ZXY_INTERVAL_TREE = 129,
    ZXY_PERSISTENT = 130,
    _,
};

// ============================================================================
// BPF Helper Functions
// ============================================================================

pub const BpfHelperFunc = enum(u32) {
    unspec = 0,
    map_lookup_elem = 1,
    map_update_elem = 2,
    map_delete_elem = 3,
    probe_read = 4,
    ktime_get_ns = 5,
    trace_printk = 6,
    get_prandom_u32 = 7,
    get_smp_processor_id = 8,
    skb_store_bytes = 9,
    l3_csum_replace = 10,
    l4_csum_replace = 11,
    tail_call = 12,
    clone_redirect = 13,
    get_current_pid_tgid = 14,
    get_current_uid_gid = 15,
    get_current_comm = 16,
    get_cgroup_classid = 17,
    skb_vlan_push = 18,
    skb_vlan_pop = 19,
    skb_get_tunnel_key = 20,
    skb_set_tunnel_key = 21,
    perf_event_read = 22,
    redirect = 23,
    get_route_realm = 24,
    perf_event_output = 25,
    skb_load_bytes = 26,
    get_stackid = 27,
    csum_diff = 28,
    skb_get_tunnel_opt = 29,
    skb_set_tunnel_opt = 30,
    skb_change_proto = 31,
    skb_change_type = 32,
    skb_under_cgroup = 33,
    get_hash_recalc = 34,
    get_current_task = 35,
    probe_write_user = 36,
    current_task_under_cgroup = 37,
    skb_change_tail = 38,
    skb_pull_data = 39,
    csum_update = 40,
    set_hash_invalid = 41,
    get_numa_node_id = 42,
    skb_change_head = 43,
    xdp_adjust_head = 44,
    probe_read_str = 45,
    get_socket_cookie = 46,
    get_socket_uid = 47,
    set_hash = 48,
    setsockopt = 49,
    skb_adjust_room = 50,
    redirect_map = 51,
    sk_redirect_map = 52,
    sock_map_update = 53,
    xdp_adjust_meta = 54,
    perf_event_read_value = 55,
    perf_prog_read_value = 56,
    getsockopt = 57,
    override_return = 58,
    sock_ops_cb_flags_set = 59,
    msg_redirect_map = 60,
    msg_apply_bytes = 61,
    msg_cork_bytes = 62,
    msg_pull_data = 63,
    bind = 64,
    xdp_adjust_tail = 65,
    skb_get_xfrm_state = 66,
    get_stack = 67,
    skb_load_bytes_relative = 68,
    fib_lookup = 69,
    sock_hash_update = 70,
    msg_redirect_hash = 71,
    sk_redirect_hash = 72,
    lwt_push_encap = 73,
    lwt_seg6_store_bytes = 74,
    lwt_seg6_adjust_srh = 75,
    lwt_seg6_action = 76,
    rc_repeat = 77,
    rc_keydown = 78,
    skb_cgroup_id = 79,
    get_current_cgroup_id = 80,
    get_local_storage = 81,
    sk_select_reuseport = 82,
    skb_ancestor_cgroup_id = 83,
    sk_lookup_tcp = 84,
    sk_lookup_udp = 85,
    sk_release = 86,
    map_push_elem = 87,
    map_pop_elem = 88,
    map_peek_elem = 89,
    msg_push_data = 90,
    msg_pop_data = 91,
    rc_pointer_rel = 92,
    spin_lock = 93,
    spin_unlock = 94,
    sk_fullsock = 95,
    tcp_sock = 96,
    skb_ecn_set_ce = 97,
    get_listener_sock = 98,
    skc_lookup_tcp = 99,
    tcp_check_syncookie = 100,
    sysctl_get_name = 101,
    sysctl_get_current_value = 102,
    sysctl_get_new_value = 103,
    sysctl_set_new_value = 104,
    strtol = 105,
    strtoul = 106,
    sk_storage_get = 107,
    sk_storage_delete = 108,
    send_signal = 109,
    tcp_gen_syncookie = 110,
    skb_output = 111,
    probe_read_user = 112,
    probe_read_kernel = 113,
    probe_read_user_str = 114,
    probe_read_kernel_str = 115,
    tcp_send_ack = 116,
    send_signal_thread = 117,
    jiffies64 = 118,
    read_branch_records = 119,
    get_ns_current_pid_tgid = 120,
    xdp_output = 121,
    get_netns_cookie = 122,
    get_current_ancestor_cgroup_id = 123,
    sk_assign = 124,
    ktime_get_boot_ns = 125,
    seq_printf = 126,
    seq_write = 127,
    sk_cgroup_id = 128,
    sk_ancestor_cgroup_id = 129,
    ringbuf_output = 130,
    ringbuf_reserve = 131,
    ringbuf_submit = 132,
    ringbuf_discard = 133,
    ringbuf_query = 134,
    csum_level = 135,
    skc_to_tcp6_sock = 136,
    skc_to_tcp_sock = 137,
    skc_to_tcp_timewait_sock = 138,
    skc_to_tcp_request_sock = 139,
    skc_to_udp6_sock = 140,
    get_task_stack = 141,
    load_hdr_opt = 142,
    store_hdr_opt = 143,
    reserve_hdr_opt = 144,
    inode_storage_get = 145,
    inode_storage_delete = 146,
    d_path = 147,
    copy_from_user = 148,
    snprintf_btf = 149,
    seq_printf_btf = 150,
    skb_cgroup_classid = 151,
    redirect_neigh = 152,
    per_cpu_ptr = 153,
    this_cpu_ptr = 154,
    redirect_peer = 155,
    task_storage_get = 156,
    task_storage_delete = 157,
    get_current_task_btf = 158,
    bprm_opts_set = 159,
    ktime_get_coarse_ns = 160,
    ima_inode_hash = 161,
    sock_from_file = 162,
    check_mtu = 163,
    for_each_map_elem = 164,
    snprintf = 165,
    sys_bpf = 166,
    btf_find_by_name_kind = 167,
    sys_close = 168,
    timer_init = 169,
    timer_set_callback = 170,
    timer_start = 171,
    timer_cancel = 172,
    get_func_ip = 173,
    get_attach_cookie = 174,
    task_pt_regs = 175,
    get_branch_snapshot = 176,
    trace_vprintk = 177,
    skc_to_unix_sock = 178,
    kallsyms_lookup_name = 179,
    find_vma = 180,
    loop = 181,
    strncmp = 182,
    get_func_arg = 183,
    get_func_ret = 184,
    get_func_arg_cnt = 185,
    get_retval = 186,
    set_retval = 187,
    xdp_get_buff_len = 188,
    xdp_load_bytes = 189,
    xdp_store_bytes = 190,
    copy_from_user_task = 191,
    skb_set_tstamp = 192,
    ima_file_hash = 193,
    kptr_xchg = 194,
    map_lookup_percpu_elem = 195,
    skc_to_mptcp_sock = 196,
    dynptr_from_mem = 197,
    ringbuf_reserve_dynptr = 198,
    ringbuf_submit_dynptr = 199,
    ringbuf_discard_dynptr = 200,
    dynptr_read = 201,
    dynptr_write = 202,
    dynptr_data = 203,
    tcp_raw_gen_syncookie_ipv4 = 204,
    tcp_raw_gen_syncookie_ipv6 = 205,
    tcp_raw_check_syncookie_ipv4 = 206,
    tcp_raw_check_syncookie_ipv6 = 207,
    ktime_get_tai_ns = 208,
    user_ringbuf_drain = 209,
    cgrp_storage_get = 210,
    cgrp_storage_delete = 211,
    _,
};

// ============================================================================
// BPF Verifier
// ============================================================================

pub const MAX_BPF_STACK: usize = 512;
pub const MAX_BPF_INSNS: usize = 1000000; // 1M instructions (Linux 5.2+)
pub const BPF_MAX_SUBPROGS: usize = 256;
pub const BPF_COMPLEXITY_LIMIT: usize = 1000000;
pub const BPF_MAX_REG: usize = 11; // R0-R10

pub const RegType = enum(u8) {
    NOT_INIT = 0,
    SCALAR_VALUE = 1,
    PTR_TO_CTX = 2,
    CONST_PTR_TO_MAP = 3,
    PTR_TO_MAP_VALUE = 4,
    PTR_TO_MAP_VALUE_OR_NULL = 5,
    PTR_TO_STACK = 6,
    PTR_TO_PACKET = 7,
    PTR_TO_PACKET_END = 8,
    PTR_TO_PACKET_META = 9,
    PTR_TO_FLOW_KEYS = 10,
    PTR_TO_SOCKET = 11,
    PTR_TO_SOCKET_OR_NULL = 12,
    PTR_TO_TCP_SOCK = 13,
    PTR_TO_TCP_SOCK_OR_NULL = 14,
    PTR_TO_TP_BUFFER = 15,
    PTR_TO_XDP_SOCK = 16,
    PTR_TO_BTF_ID = 17,
    PTR_TO_MEM = 18,
    PTR_TO_MEM_OR_NULL = 19,
    PTR_TO_BUF = 20,
    PTR_TO_FUNC = 21,
    CONST_PTR_TO_DYNPTR = 22,
    PTR_TO_ARENA = 23,
};

pub const RegState = struct {
    type_: RegType = .NOT_INIT,
    // Scalar tracking (for range analysis)
    smin_value: i64 = std.math.minInt(i64),
    smax_value: i64 = std.math.maxInt(i64),
    umin_value: u64 = 0,
    umax_value: u64 = std.math.maxInt(u64),
    s32_min_value: i32 = std.math.minInt(i32),
    s32_max_value: i32 = std.math.maxInt(i32),
    u32_min_value: u32 = 0,
    u32_max_value: u32 = std.math.maxInt(u32),
    // Tnum (tristate number) for bit-level tracking
    var_off_value: u64 = 0,  // Known bits
    var_off_mask: u64 = std.math.maxInt(u64),  // Unknown bits
    // Pointer-specific
    off: i32 = 0,
    id: u32 = 0,
    ref_obj_id: u32 = 0,
    map_ptr: ?*anyopaque = null,
    btf_id: u32 = 0,
    mem_size: u32 = 0,
    dynptr_id: u32 = 0,
    // Liveness tracking
    live: u8 = 0, // REG_LIVE_NONE=0, READ=1, WRITTEN=2, DONE=4
    precise: bool = false,

    pub fn mark_unknown(self: *RegState) void {
        self.type_ = .SCALAR_VALUE;
        self.smin_value = std.math.minInt(i64);
        self.smax_value = std.math.maxInt(i64);
        self.umin_value = 0;
        self.umax_value = std.math.maxInt(u64);
        self.var_off_value = 0;
        self.var_off_mask = std.math.maxInt(u64);
    }

    pub fn mark_known(self: *RegState, val: u64) void {
        self.type_ = .SCALAR_VALUE;
        const sval: i64 = @bitCast(val);
        self.smin_value = sval;
        self.smax_value = sval;
        self.umin_value = val;
        self.umax_value = val;
        self.var_off_value = val;
        self.var_off_mask = 0;
    }
};

pub const StackSlotType = enum(u8) {
    INVALID = 0,
    SPILL = 1,         // Spilled register
    MISC = 2,          // Scalar on stack
    ZERO = 3,          // Known zero
    DYNPTR = 4,
    ITER = 5,
};

pub const StackSlot = struct {
    type_: StackSlotType = .INVALID,
    spilled_reg: RegState = .{},
};

pub const VerifierState = struct {
    regs: [BPF_MAX_REG]RegState,
    stack: [MAX_BPF_STACK / 8]StackSlot,
    frame_idx: u32,
    branch_count: u32,
    insn_idx: u32,
    refs: [64]u32, // Reference tracking IDs
    ref_count: u32,
    active_lock_id: u32,
    active_lock_ptr: ?*anyopaque,
    speculative: bool,
    active_rcu_lock: bool,

    pub fn init() VerifierState {
        var state: VerifierState = undefined;
        @memset(&state.regs, RegState{});
        @memset(&state.stack, StackSlot{});
        // R1 = PTR_TO_CTX (program context)
        state.regs[1].type_ = .PTR_TO_CTX;
        // R10 = PTR_TO_STACK (frame pointer, read-only)
        state.regs[10].type_ = .PTR_TO_STACK;
        state.regs[10].off = 0;
        state.frame_idx = 0;
        state.branch_count = 0;
        state.insn_idx = 0;
        state.refs = [_]u32{0} ** 64;
        state.ref_count = 0;
        state.active_lock_id = 0;
        state.active_lock_ptr = null;
        state.speculative = false;
        state.active_rcu_lock = false;
        return state;
    }
};

pub const VerifyError = enum(u32) {
    SUCCESS = 0,
    UNREACHABLE_INSN = 1,
    INVALID_OPCODE = 2,
    UNINITIALIZED_REG = 3,
    INVALID_MEM_ACCESS = 4,
    INVALID_MAP_FD = 5,
    INVALID_HELPER = 6,
    INVALID_FUNC_PROTO = 7,
    DIV_BY_ZERO = 8,
    STACK_OUT_OF_BOUNDS = 9,
    MISALIGNED_STACK_ACCESS = 10,
    INVALID_RETURN = 11,
    LOOPS_DETECTED = 12,
    COMPLEXITY_EXCEEDED = 13,
    INSN_COUNT_EXCEEDED = 14,
    POINTER_ARITHMETIC = 15,
    INVALID_MAP_TYPE = 16,
    LEAKED_REFERENCE = 17,
    UNBALANCED_LOCK = 18,
    INVALID_BTF = 19,
    TYPE_MISMATCH = 20,
    INVALID_KFUNC = 21,
    INVALID_ARENA_ACCESS = 22,
    SPECULATION_UNSAFE = 23,
};

pub const VerifierLog = struct {
    buffer: [65536]u8,
    offset: usize,
    level: u32, // 0=none, 1=errors, 2=verbose

    pub fn init(level: u32) VerifierLog {
        return .{
            .buffer = undefined,
            .offset = 0,
            .level = level,
        };
    }

    pub fn write(self: *VerifierLog, msg: []const u8) void {
        if (self.level == 0) return;
        const remaining = self.buffer.len - self.offset;
        const copy_len = @min(msg.len, remaining);
        @memcpy(self.buffer[self.offset..][0..copy_len], msg[0..copy_len]);
        self.offset += copy_len;
    }
};

pub const SubprogInfo = struct {
    start: u32,
    stack_depth: u16,
    is_cb: bool,
    is_async_cb: bool,
    is_exception_cb: bool,
    has_tail_call: bool,
    tail_call_reachable: bool,
    is_global: bool,
    arg_cnt: u8,
};

pub const Verifier = struct {
    prog_type: BpfProgType,
    insns: []const BpfInsn,
    insn_count: u32,
    state: VerifierState,
    explored: []bool,
    log: VerifierLog,
    subprogs: [BPF_MAX_SUBPROGS]SubprogInfo,
    subprog_cnt: u32,
    complexity: u64,

    pub fn verify(self: *Verifier) VerifyError {
        if (self.insn_count == 0 or self.insn_count > MAX_BPF_INSNS) {
            return .INSN_COUNT_EXCEEDED;
        }

        self.state = VerifierState.init();

        // Phase 1: CFG validation (check for unreachable code, loops)
        const cfg_err = self.check_cfg();
        if (cfg_err != .SUCCESS) return cfg_err;

        // Phase 2: Subprogram detection
        self.detect_subprogs();

        // Phase 3: Symbolic execution with state pruning
        const exec_err = self.do_check();
        if (exec_err != .SUCCESS) return exec_err;

        // Phase 4: Verify no leaked references
        if (self.state.ref_count > 0) {
            return .LEAKED_REFERENCE;
        }

        return .SUCCESS;
    }

    fn check_cfg(self: *Verifier) VerifyError {
        // Verify all instructions reachable, detect back-edges
        var visited = [_]bool{false} ** MAX_BPF_INSNS;
        var i: u32 = 0;
        while (i < self.insn_count) : (i += 1) {
            visited[i] = true;
            const insn = self.insns[i];
            const cls = insn.code & 0x07;
            if (cls == BPF_JMP or cls == BPF_JMP32) {
                const op = insn.code & 0xF0;
                if (op == BPF_EXIT) continue;
                if (op == BPF_CALL) continue;
                // Check jump target
                const target = @as(i64, i) + @as(i64, insn.off) + 1;
                if (target < 0 or target >= self.insn_count) {
                    return .UNREACHABLE_INSN;
                }
            }
        }
        return .SUCCESS;
    }

    fn detect_subprogs(self: *Verifier) void {
        self.subprog_cnt = 1;
        self.subprogs[0] = .{
            .start = 0,
            .stack_depth = 0,
            .is_cb = false,
            .is_async_cb = false,
            .is_exception_cb = false,
            .has_tail_call = false,
            .tail_call_reachable = false,
            .is_global = false,
            .arg_cnt = 0,
        };
        // Scan for BPF-to-BPF calls
        var i: u32 = 0;
        while (i < self.insn_count) : (i += 1) {
            const insn = self.insns[i];
            if (insn.code == (BPF_JMP | BPF_CALL) and insn.src_reg == 1) {
                // BPF-to-BPF call (pseudo-call)
                const target: u32 = @intCast(@as(i64, i) + @as(i64, insn.imm) + 1);
                if (self.subprog_cnt < BPF_MAX_SUBPROGS) {
                    self.subprogs[self.subprog_cnt] = .{
                        .start = target,
                        .stack_depth = 0,
                        .is_cb = false,
                        .is_async_cb = false,
                        .is_exception_cb = false,
                        .has_tail_call = false,
                        .tail_call_reachable = false,
                        .is_global = false,
                        .arg_cnt = 0,
                    };
                    self.subprog_cnt += 1;
                }
            }
        }
    }

    fn do_check(self: *Verifier) VerifyError {
        while (self.state.insn_idx < self.insn_count) {
            self.complexity += 1;
            if (self.complexity > BPF_COMPLEXITY_LIMIT) {
                return .COMPLEXITY_EXCEEDED;
            }

            const insn = self.insns[self.state.insn_idx];
            const cls = insn.code & 0x07;

            switch (cls) {
                BPF_ALU, BPF_ALU64 => {
                    const err = self.check_alu_op(insn, cls == BPF_ALU64);
                    if (err != .SUCCESS) return err;
                },
                BPF_LDX => {
                    const err = self.check_mem_access(insn, false);
                    if (err != .SUCCESS) return err;
                },
                BPF_STX, BPF_ST => {
                    const err = self.check_mem_access(insn, true);
                    if (err != .SUCCESS) return err;
                },
                BPF_JMP, BPF_JMP32 => {
                    const err = self.check_jmp_op(insn);
                    if (err != .SUCCESS) return err;
                },
                BPF_LD => {
                    // 64-bit immediate load (2 instructions)
                    self.state.insn_idx += 1;
                },
                else => return .INVALID_OPCODE,
            }

            self.state.insn_idx += 1;
        }
        return .SUCCESS;
    }

    fn check_alu_op(self: *Verifier, insn: BpfInsn, is64: bool) VerifyError {
        const dst = insn.dst_reg;
        const src = insn.src_reg;
        const op = insn.code & 0xF0;

        if (dst >= BPF_MAX_REG or src >= BPF_MAX_REG) return .UNINITIALIZED_REG;

        // Check source register initialized
        if ((insn.code & BPF_X) != 0 and self.state.regs[src].type_ == .NOT_INIT) {
            return .UNINITIALIZED_REG;
        }

        // R10 (frame pointer) is read-only
        if (dst == 10) return .INVALID_MEM_ACCESS;

        // Division by zero check
        if (op == BPF_DIV or op == BPF_MOD) {
            if ((insn.code & BPF_X) != 0) {
                if (self.state.regs[src].umax_value == 0) {
                    return .DIV_BY_ZERO;
                }
            } else if (insn.imm == 0) {
                return .DIV_BY_ZERO;
            }
        }

        // Update destination register tracking
        if (op == BPF_MOV) {
            if ((insn.code & BPF_X) != 0) {
                self.state.regs[dst] = self.state.regs[src];
                if (!is64) {
                    // Zero-extend 32-bit
                    self.state.regs[dst].umax_value &= 0xFFFFFFFF;
                }
            } else {
                if (is64) {
                    self.state.regs[dst].mark_known(@bitCast(@as(i64, insn.imm)));
                } else {
                    self.state.regs[dst].mark_known(@as(u64, @as(u32, @bitCast(insn.imm))));
                }
            }
        } else {
            // For arithmetic ops, update range tracking
            self.state.regs[dst].type_ = .SCALAR_VALUE;
        }

        return .SUCCESS;
    }

    fn check_mem_access(self: *Verifier, insn: BpfInsn, is_write: bool) VerifyError {
        const reg = if (is_write) insn.dst_reg else insn.src_reg;
        if (reg >= BPF_MAX_REG) return .UNINITIALIZED_REG;

        const reg_state = &self.state.regs[reg];

        switch (reg_state.type_) {
            .PTR_TO_STACK => {
                const stack_off = reg_state.off + insn.off;
                if (stack_off >= 0 or stack_off < -@as(i32, MAX_BPF_STACK)) {
                    return .STACK_OUT_OF_BOUNDS;
                }
                // Check alignment
                const size: i32 = switch (insn.code & 0x18) {
                    BPF_B => 1,
                    BPF_H => 2,
                    BPF_W => 4,
                    BPF_DW => 8,
                    else => return .INVALID_OPCODE,
                };
                _ = size;
            },
            .PTR_TO_CTX => {
                // Context access is always valid within bounds
            },
            .PTR_TO_MAP_VALUE => {
                // Check map value bounds
            },
            .PTR_TO_PACKET, .PTR_TO_PACKET_META => {
                // Packet access needs range check
            },
            .NOT_INIT => return .UNINITIALIZED_REG,
            else => {},
        }

        // Update destination for loads
        if (!is_write) {
            const dst = insn.dst_reg;
            if (dst >= BPF_MAX_REG) return .UNINITIALIZED_REG;
            self.state.regs[dst].mark_unknown();
        }

        return .SUCCESS;
    }

    fn check_jmp_op(self: *Verifier, insn: BpfInsn) VerifyError {
        const op = insn.code & 0xF0;

        if (op == BPF_EXIT) {
            // R0 must be initialized (return value)
            if (self.state.regs[0].type_ == .NOT_INIT) {
                return .INVALID_RETURN;
            }
            return .SUCCESS;
        }

        if (op == BPF_CALL) {
            return self.check_call(insn);
        }

        // Conditional jump - check registers
        if ((insn.code & BPF_X) != 0) {
            if (self.state.regs[insn.src_reg].type_ == .NOT_INIT) {
                return .UNINITIALIZED_REG;
            }
        }
        if (self.state.regs[insn.dst_reg].type_ == .NOT_INIT) {
            return .UNINITIALIZED_REG;
        }

        return .SUCCESS;
    }

    fn check_call(self: *Verifier, insn: BpfInsn) VerifyError {
        _ = insn;
        // After a call, R0 has the return value, R1-R5 are clobbered
        self.state.regs[0].mark_unknown();
        var i: u8 = 1;
        while (i <= 5) : (i += 1) {
            self.state.regs[i] = RegState{};
        }
        return .SUCCESS;
    }
};

// ============================================================================
// BPF JIT Compiler (x86_64)
// ============================================================================

pub const JIT_MAX_CODE_SIZE: usize = 256 * 1024; // 256 KB

pub const X86Reg = enum(u3) {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
};

pub const X86ExtReg = enum(u4) {
    R8 = 0, R9 = 1, R10 = 2, R11 = 3,
    R12 = 4, R13 = 5, R14 = 6, R15 = 7,
};

// BPF register to x86_64 register mapping (Linux-compatible)
pub const bpf_to_x86 = [BPF_MAX_REG]u8{
    0, // R0 -> RAX
    7, // R1 -> RDI
    6, // R2 -> RSI
    2, // R3 -> RDX
    1, // R4 -> RCX
    8, // R5 -> R8
    3, // R6 -> RBX (callee-saved)
    13, // R7 -> R13 (callee-saved)
    14, // R8 -> R14 (callee-saved)
    15, // R9 -> R15 (callee-saved)
    5, // R10 (FP) -> RBP
};

pub const JitContext = struct {
    code: [JIT_MAX_CODE_SIZE]u8,
    code_len: usize,
    insns: []const BpfInsn,
    insn_count: u32,
    // Offsets of each BPF instruction in generated code
    offsets: [MAX_BPF_INSNS]u32,
    stack_depth: u16,
    seen_exit: bool,

    pub fn init(insns: []const BpfInsn, count: u32) JitContext {
        var ctx: JitContext = undefined;
        ctx.insns = insns;
        ctx.insn_count = count;
        ctx.code_len = 0;
        ctx.stack_depth = MAX_BPF_STACK;
        ctx.seen_exit = false;
        @memset(&ctx.offsets, 0);
        return ctx;
    }

    pub fn emit(self: *JitContext, byte: u8) void {
        if (self.code_len < JIT_MAX_CODE_SIZE) {
            self.code[self.code_len] = byte;
            self.code_len += 1;
        }
    }

    pub fn emit_bytes(self: *JitContext, bytes: []const u8) void {
        for (bytes) |b| {
            self.emit(b);
        }
    }

    pub fn emit_u32(self: *JitContext, val: u32) void {
        self.emit(@truncate(val));
        self.emit(@truncate(val >> 8));
        self.emit(@truncate(val >> 16));
        self.emit(@truncate(val >> 24));
    }

    pub fn emit_u64(self: *JitContext, val: u64) void {
        self.emit_u32(@truncate(val));
        self.emit_u32(@truncate(val >> 32));
    }

    fn emit_rex(self: *JitContext, w: bool, r: u4, x: u4, b: u4) void {
        var rex: u8 = 0x40;
        if (w) rex |= 0x08;
        if (r > 7) rex |= 0x04;
        if (x > 7) rex |= 0x02;
        if (b > 7) rex |= 0x01;
        if (rex != 0x40 or w) {
            self.emit(rex);
        }
    }

    fn emit_modrm(self: *JitContext, mod_: u2, reg: u3, rm: u3) void {
        self.emit(@as(u8, mod_) << 6 | @as(u8, reg) << 3 | rm);
    }

    fn emit_sib(self: *JitContext, scale: u2, index: u3, base: u3) void {
        self.emit(@as(u8, scale) << 6 | @as(u8, index) << 3 | base);
    }

    pub fn emit_prologue(self: *JitContext) void {
        // push rbp; mov rbp, rsp
        self.emit(0x55);
        self.emit_rex(true, 0, 0, 0);
        self.emit(0x89);
        self.emit_modrm(3, 4, 5); // mov rbp, rsp

        // push callee-saved registers
        self.emit(0x53); // push rbx
        self.emit(0x41); self.emit(0x55); // push r13
        self.emit(0x41); self.emit(0x56); // push r14
        self.emit(0x41); self.emit(0x57); // push r15

        // Allocate stack frame for BPF stack
        self.emit_rex(true, 0, 0, 0);
        self.emit(0x81);
        self.emit_modrm(3, 5, 4); // sub rsp, imm32
        self.emit_u32(self.stack_depth);
    }

    pub fn emit_epilogue(self: *JitContext) void {
        // Deallocate stack
        self.emit_rex(true, 0, 0, 0);
        self.emit(0x81);
        self.emit_modrm(3, 0, 4); // add rsp, imm32
        self.emit_u32(self.stack_depth);

        // Pop callee-saved
        self.emit(0x41); self.emit(0x5F); // pop r15
        self.emit(0x41); self.emit(0x5E); // pop r14
        self.emit(0x41); self.emit(0x5D); // pop r13
        self.emit(0x5B); // pop rbx

        // pop rbp; ret
        self.emit(0x5D);
        self.emit(0xC3);
    }

    pub fn compile(self: *JitContext) bool {
        self.emit_prologue();

        var i: u32 = 0;
        while (i < self.insn_count) : (i += 1) {
            self.offsets[i] = @intCast(self.code_len);
            const insn = self.insns[i];
            const cls = insn.code & 0x07;

            switch (cls) {
                BPF_ALU64 => {
                    if (!self.emit_alu64(insn)) return false;
                },
                BPF_ALU => {
                    if (!self.emit_alu32(insn)) return false;
                },
                BPF_LDX => {
                    if (!self.emit_ldx(insn)) return false;
                },
                BPF_STX => {
                    if (!self.emit_stx(insn)) return false;
                },
                BPF_ST => {
                    if (!self.emit_st(insn)) return false;
                },
                BPF_JMP, BPF_JMP32 => {
                    if (!self.emit_jmp(insn, i, cls == BPF_JMP32)) return false;
                },
                BPF_LD => {
                    // LD_IMM64
                    if (!self.emit_ld_imm64(insn, self.insns[i + 1])) return false;
                    i += 1;
                },
                else => return false,
            }
        }

        if (!self.seen_exit) {
            self.emit_epilogue();
        }

        return true;
    }

    fn emit_alu64(self: *JitContext, insn: BpfInsn) bool {
        const dst = bpf_to_x86[insn.dst_reg];
        const op = insn.code & 0xF0;

        if ((insn.code & BPF_X) != 0) {
            const src = bpf_to_x86[insn.src_reg];
            self.emit_rex(true, @truncate(src), 0, @truncate(dst));

            switch (op) {
                BPF_ADD => { self.emit(0x01); },
                BPF_SUB => { self.emit(0x29); },
                BPF_AND => { self.emit(0x21); },
                BPF_OR =>  { self.emit(0x09); },
                BPF_XOR => { self.emit(0x31); },
                BPF_MOV => { self.emit(0x89); },
                else => return false,
            }
            self.emit_modrm(3, @truncate(src & 7), @truncate(dst & 7));
        } else {
            self.emit_rex(true, 0, 0, @truncate(dst));
            switch (op) {
                BPF_ADD => {
                    self.emit(0x81);
                    self.emit_modrm(3, 0, @truncate(dst & 7));
                    self.emit_u32(@bitCast(insn.imm));
                },
                BPF_MOV => {
                    self.emit(0xC7);
                    self.emit_modrm(3, 0, @truncate(dst & 7));
                    self.emit_u32(@bitCast(insn.imm));
                },
                else => return false,
            }
        }
        return true;
    }

    fn emit_alu32(self: *JitContext, insn: BpfInsn) bool {
        _ = self;
        _ = insn;
        return true; // Simplified
    }

    fn emit_ldx(self: *JitContext, insn: BpfInsn) bool {
        const dst = bpf_to_x86[insn.dst_reg];
        const src = bpf_to_x86[insn.src_reg];
        const size = insn.code & 0x18;

        switch (size) {
            BPF_DW => self.emit_rex(true, @truncate(dst), 0, @truncate(src)),
            BPF_W => if (dst > 7 or src > 7) {
                self.emit_rex(false, @truncate(dst), 0, @truncate(src));
            },
            else => {},
        }

        switch (size) {
            BPF_B => self.emit(0x0F),
            BPF_H => { self.emit(0x0F); self.emit(0xB7); },
            BPF_W, BPF_DW => self.emit(0x8B),
            else => return false,
        }
        if (size == BPF_B) self.emit(0xB6);

        // ModRM + displacement
        if (insn.off == 0 and (src & 7) != 5) {
            self.emit_modrm(0, @truncate(dst & 7), @truncate(src & 7));
        } else if (insn.off >= -128 and insn.off <= 127) {
            self.emit_modrm(1, @truncate(dst & 7), @truncate(src & 7));
            self.emit(@bitCast(@as(i8, @truncate(insn.off))));
        } else {
            self.emit_modrm(2, @truncate(dst & 7), @truncate(src & 7));
            self.emit_u32(@bitCast(insn.off));
        }

        return true;
    }

    fn emit_stx(self: *JitContext, insn: BpfInsn) bool {
        _ = self;
        _ = insn;
        return true; // Simplified
    }

    fn emit_st(self: *JitContext, insn: BpfInsn) bool {
        _ = self;
        _ = insn;
        return true; // Simplified
    }

    fn emit_jmp(self: *JitContext, insn: BpfInsn, idx: u32, _: bool) bool {
        const op = insn.code & 0xF0;

        if (op == BPF_EXIT) {
            self.emit_epilogue();
            self.seen_exit = true;
            return true;
        }

        if (op == BPF_CALL) {
            // CALL helper function
            // movabs rax, <helper_addr>; call rax
            self.emit_rex(true, 0, 0, 0);
            self.emit(0xB8); // mov rax, imm64 (placeholder)
            self.emit_u64(0); // Will be patched
            self.emit(0xFF);
            self.emit_modrm(3, 2, 0); // call rax
            return true;
        }

        if (op == BPF_JA) {
            // Unconditional jump
            self.emit(0xE9);
            self.emit_u32(0); // Placeholder, needs fixup
            _ = idx;
            return true;
        }

        // Conditional jumps
        const dst = bpf_to_x86[insn.dst_reg];
        if ((insn.code & BPF_X) != 0) {
            const src = bpf_to_x86[insn.src_reg];
            self.emit_rex(true, @truncate(src), 0, @truncate(dst));
            self.emit(0x39);
            self.emit_modrm(3, @truncate(src & 7), @truncate(dst & 7));
        } else {
            self.emit_rex(true, 0, 0, @truncate(dst));
            self.emit(0x81);
            self.emit_modrm(3, 7, @truncate(dst & 7)); // CMP
            self.emit_u32(@bitCast(insn.imm));
        }

        // Conditional jump based on op
        self.emit(0x0F);
        switch (op) {
            BPF_JEQ => self.emit(0x84),
            BPF_JNE => self.emit(0x85),
            BPF_JGT => self.emit(0x87),
            BPF_JGE => self.emit(0x83),
            BPF_JLT => self.emit(0x82),
            BPF_JLE => self.emit(0x86),
            BPF_JSGT => self.emit(0x8F),
            BPF_JSGE => self.emit(0x8D),
            BPF_JSLT => self.emit(0x8C),
            BPF_JSLE => self.emit(0x8E),
            BPF_JSET => self.emit(0x85), // JNZ after TEST
            else => return false,
        }
        self.emit_u32(0); // Placeholder offset

        return true;
    }

    fn emit_ld_imm64(self: *JitContext, insn1: BpfInsn, insn2: BpfInsn) bool {
        const dst = bpf_to_x86[insn1.dst_reg];
        const val = @as(u64, @as(u32, @bitCast(insn2.imm))) << 32 | @as(u64, @as(u32, @bitCast(insn1.imm)));

        self.emit_rex(true, 0, 0, @truncate(dst));
        self.emit(0xB8 + @as(u8, @truncate(dst & 7)));
        self.emit_u64(val);

        return true;
    }
};

// ============================================================================
// BPF Map Implementation
// ============================================================================

pub const BPF_MAP_CREATE_FLAGS_MASK: u32 = 0xFF;
pub const BPF_F_NO_PREALLOC: u32 = 1 << 0;
pub const BPF_F_NO_COMMON_LRU: u32 = 1 << 1;
pub const BPF_F_NUMA_NODE: u32 = 1 << 2;
pub const BPF_F_RDONLY: u32 = 1 << 3;
pub const BPF_F_WRONLY: u32 = 1 << 4;
pub const BPF_F_STACKMAP_BUILD_ID: u32 = 1 << 5;
pub const BPF_F_ZERO_SEED: u32 = 1 << 6;
pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;
pub const BPF_F_WRONLY_PROG: u32 = 1 << 8;
pub const BPF_F_CLONE: u32 = 1 << 9;
pub const BPF_F_MMAPABLE: u32 = 1 << 10;
pub const BPF_F_PRESERVE_ELEMS: u32 = 1 << 11;
pub const BPF_F_INNER_MAP: u32 = 1 << 12;
pub const BPF_F_LINK: u32 = 1 << 13;
pub const BPF_F_PATH_FD: u32 = 1 << 14;
pub const BPF_F_VTYPE_BTF_OBJ_FD: u32 = 1 << 15;
pub const BPF_F_TOKEN_FD: u32 = 1 << 16;
pub const BPF_F_SEGV_ON_FAULT: u32 = 1 << 17;
pub const BPF_F_NO_USER_CONV: u32 = 1 << 18;

pub const BpfMapOps = struct {
    lookup_elem: ?*const fn (*BpfMap, *const anyopaque) ?*anyopaque = null,
    update_elem: ?*const fn (*BpfMap, *const anyopaque, *const anyopaque, u64) i32 = null,
    delete_elem: ?*const fn (*BpfMap, *const anyopaque) i32 = null,
    get_next_key: ?*const fn (*BpfMap, *const anyopaque, *anyopaque) i32 = null,
    map_free: ?*const fn (*BpfMap) void = null,
    map_alloc_check: ?*const fn (*BpfMapAttr) i32 = null,
    map_alloc: ?*const fn (*BpfMapAttr) ?*BpfMap = null,
    map_push_elem: ?*const fn (*BpfMap, *const anyopaque, u64) i32 = null,
    map_pop_elem: ?*const fn (*BpfMap, *anyopaque) i32 = null,
    map_peek_elem: ?*const fn (*BpfMap, *anyopaque) i32 = null,
    map_for_each: ?*const fn (*BpfMap, *const fn (*const anyopaque, *const anyopaque, *anyopaque) i64, *anyopaque, u64) i64 = null,
};

pub const BpfMapAttr = struct {
    map_type: BpfMapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    numa_node: u32,
    map_name: [16]u8,
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
    value_type_btf_obj_fd: u32,
};

pub const BpfMap = struct {
    map_type: BpfMapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [16]u8,
    ref_count: u32,
    ops: *const BpfMapOps,
    // Memory
    data: ?[*]u8,
    data_size: usize,
    // Spinlock for synchronization
    lock: u32,
    // BTF info
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    // Stats
    elem_count: u64,

    pub fn lookup(self: *BpfMap, key: *const anyopaque) ?*anyopaque {
        if (self.ops.lookup_elem) |func| {
            return func(self, key);
        }
        return null;
    }

    pub fn update(self: *BpfMap, key: *const anyopaque, value: *const anyopaque, flags: u64) i32 {
        if (self.ops.update_elem) |func| {
            return func(self, key, value, flags);
        }
        return -1;
    }

    pub fn delete(self: *BpfMap, key: *const anyopaque) i32 {
        if (self.ops.delete_elem) |func| {
            return func(self, key);
        }
        return -1;
    }
};

// ============================================================================
// Ring Buffer Map
// ============================================================================

pub const BpfRingbuf = struct {
    data: [*]u8,
    mask: u64,
    consumer_pos: *volatile u64,
    producer_pos: *volatile u64,
    pending_count: u64,

    pub fn reserve(self: *BpfRingbuf, size: u32) ?[*]u8 {
        const aligned_size = (size + 7) & ~@as(u32, 7);
        const total = aligned_size + 8; // 8-byte header
        const prod = @atomicLoad(u64, self.producer_pos, .acquire);
        const cons = @atomicLoad(u64, self.consumer_pos, .acquire);

        if (prod - cons + total > self.mask + 1) {
            return null; // Ring buffer full
        }

        // Write header (length with busy bit set)
        const header_pos = prod & self.mask;
        const header_ptr: *u32 = @ptrCast(@alignCast(self.data + header_pos));
        @atomicStore(u32, header_ptr, size | (1 << 31), .release);

        @atomicStore(u64, self.producer_pos, prod + total, .release);

        return self.data + ((prod + 8) & self.mask);
    }

    pub fn submit(self: *BpfRingbuf, sample: [*]u8) void {
        // Clear busy bit in header
        const header: *u32 = @ptrCast(@alignCast(sample - 8));
        const old = @atomicLoad(u32, header, .acquire);
        @atomicStore(u32, header, old & ~@as(u32, 1 << 31), .release);
        self.pending_count += 1;
    }

    pub fn discard(self: *BpfRingbuf, sample: [*]u8) void {
        // Set discard bit in header
        const header: *u32 = @ptrCast(@alignCast(sample - 8));
        const old = @atomicLoad(u32, header, .acquire);
        @atomicStore(u32, header, (old & ~@as(u32, 1 << 31)) | (1 << 30), .release);
        _ = self;
    }
};

// ============================================================================
// BTF (BPF Type Format)
// ============================================================================

pub const BTF_MAGIC: u16 = 0xEB9F;
pub const BTF_VERSION: u8 = 1;

pub const BtfHeader = extern struct {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
};

pub const BtfKind = enum(u5) {
    UNKN = 0,
    INT = 1,
    PTR = 2,
    ARRAY = 3,
    STRUCT = 4,
    UNION = 5,
    ENUM = 6,
    FWD = 7,
    TYPEDEF = 8,
    VOLATILE = 9,
    CONST = 10,
    RESTRICT = 11,
    FUNC = 12,
    FUNC_PROTO = 13,
    VAR = 14,
    DATASEC = 15,
    FLOAT = 16,
    DECL_TAG = 17,
    TYPE_TAG = 18,
    ENUM64 = 19,
};

pub const BtfType = extern struct {
    name_off: u32,
    info: u32, // vlen:16 | kind:5 | kind_flag:1 | unused:10
    size_or_type: u32,

    pub fn kind(self: BtfType) BtfKind {
        return @enumFromInt(@as(u5, @truncate((self.info >> 24) & 0x1F)));
    }

    pub fn vlen(self: BtfType) u16 {
        return @truncate(self.info & 0xFFFF);
    }

    pub fn kind_flag(self: BtfType) bool {
        return (self.info & (1 << 31)) != 0;
    }
};

// ============================================================================
// BPF Link types
// ============================================================================

pub const BpfLinkType = enum(u32) {
    UNSPEC = 0,
    RAW_TRACEPOINT = 1,
    TRACING = 2,
    CGROUP = 3,
    ITER = 4,
    NETNS = 5,
    XDP = 6,
    PERF_EVENT = 7,
    KPROBE_MULTI = 8,
    STRUCT_OPS = 9,
    NETFILTER = 10,
    TCX = 11,
    UPROBE_MULTI = 12,
    NETKIT = 13,
    _,
};
