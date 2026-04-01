// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - BPF Program Types Detail,
// BPF Networking Hooks, BPF Cgroup,
// BPF Tracing Programs, BPF Iterators,
// BPF Struct Ops, BPF LSM, BPF Timer,
// BPF Arena, BPF Token
// More advanced than Linux 2026 BPF subsystem

const std = @import("std");

// ============================================================================
// BPF Program Types
// ============================================================================

/// BPF program type (comprehensive)
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
    // Zxyphor
    zxy_scheduler = 100,
    zxy_mm_hook = 101,
    zxy_device_filter = 102,
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
    zxy_sched_hook = 100,
    zxy_mm_fault = 101,
};

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
    zxy_custom = 100,
};

// ============================================================================
// BPF Networking Hooks
// ============================================================================

/// XDP action
pub const XdpAction = enum(u32) {
    aborted = 0,
    drop = 1,
    pass = 2,
    tx = 3,
    redirect = 4,
};

/// XDP flags
pub const XdpFlags = packed struct(u32) {
    update_if_noexist: bool = false,
    skb_mode: bool = false,
    drv_mode: bool = false,
    hw_mode: bool = false,
    replace: bool = false,
    _padding: u27 = 0,
};

/// TC (traffic control) BPF flags
pub const TcBpfFlags = packed struct(u32) {
    direct_action: bool = false,
    replace: bool = false,
    _padding: u30 = 0,
};

/// Socket filter context
pub const BpfSockFilterCtx = struct {
    protocol: u32 = 0,
    mark: u32 = 0,
    priority: u32 = 0,
    ifindex: u32 = 0,
    family: u16 = 0,
    is_bound_dev: bool = false,
};

/// sk_msg context
pub const BpfSkMsgCtx = struct {
    family: u32 = 0,
    remote_ip4: u32 = 0,
    local_ip4: u32 = 0,
    remote_ip6: [4]u32 = [_]u32{0} ** 4,
    local_ip6: [4]u32 = [_]u32{0} ** 4,
    remote_port: u32 = 0,
    local_port: u32 = 0,
    size: u32 = 0,
    sk: u64 = 0,
};

/// sock_ops context fields
pub const BpfSockOpsOp = enum(u32) {
    timeout_init = 0,
    rwnd_init = 1,
    tcp_connect_cb = 2,
    active_established_cb = 3,
    passive_established_cb = 4,
    needs_ecn = 6,
    base_rtt = 7,
    rto_cb = 8,
    retrans_cb = 9,
    state_cb = 10,
    tcp_listen_cb = 11,
    rtt_cb = 12,
    parse_hdr_opt_cb = 13,
    hdr_opt_len_cb = 14,
    write_hdr_opt_cb = 15,
};

/// sk_lookup context
pub const BpfSkLookupCtx = struct {
    family: u32 = 0,
    protocol: u32 = 0,
    remote_ip4: u32 = 0,
    remote_ip6: [4]u32 = [_]u32{0} ** 4,
    remote_port: u32 = 0,
    local_ip4: u32 = 0,
    local_ip6: [4]u32 = [_]u32{0} ** 4,
    local_port: u32 = 0,
    ingress_ifindex: u32 = 0,
};

// ============================================================================
// BPF Cgroup
// ============================================================================

/// Cgroup BPF attach flags
pub const CgroupBpfFlags = packed struct(u32) {
    allow_override: bool = false,
    allow_multi: bool = false,
    replace: bool = false,
    _padding: u29 = 0,
};

/// Cgroup sysctl context
pub const BpfSysctlCtx = struct {
    write: bool = false,
    file_pos: u32 = 0,
};

/// Cgroup sockopt context
pub const BpfSockoptCtx = struct {
    sk: u64 = 0,
    level: i32 = 0,
    optname: i32 = 0,
    optlen: i32 = 0,
    retval: i32 = 0,
};

// ============================================================================
// BPF Tracing Programs
// ============================================================================

/// BPF tracing subtype
pub const BpfTracingType = enum(u8) {
    fentry = 0,
    fexit = 1,
    fmod_ret = 2,
    lsm = 3,
    iter = 4,
    // Zxyphor
    zxy_custom = 100,
};

/// BPF kprobe/uprobe flags
pub const BpfProbeFlags = packed struct(u32) {
    is_return: bool = false,
    is_multi: bool = false,
    is_uprobe: bool = false,
    session: bool = false,
    _padding: u28 = 0,
};

/// BPF iterator target
pub const BpfIterTarget = enum(u16) {
    bpf_map = 0,
    bpf_map_elem = 1,
    bpf_prog = 2,
    bpf_link = 3,
    task = 4,
    task_file = 5,
    task_vma = 6,
    netlink = 7,
    tcp = 8,
    udp = 9,
    unix = 10,
    sockmap = 11,
    bpf_sk_storage = 12,
    cgroup = 13,
    ksym = 14,
    // Zxyphor
    zxy_sched = 100,
    zxy_mm = 101,
};

// ============================================================================
// BPF Struct Ops
// ============================================================================

/// Struct ops state
pub const BpfStructOpsState = enum(u32) {
    init = 0,
    inuse = 1,
    tobefree = 2,
    ready = 3,
};

/// Known struct_ops
pub const BpfStructOpsType = enum(u8) {
    tcp_congestion_ops = 0,
    bpf_dummy_ops = 1,
    sched_ext_ops = 2,     // sched_ext
    // Zxyphor
    zxy_sched_ops = 100,
    zxy_mm_ops = 101,
};

// ============================================================================
// BPF LSM
// ============================================================================

/// BPF LSM program flags
pub const BpfLsmFlags = packed struct(u32) {
    sleepable: bool = false,
    _padding: u31 = 0,
};

// ============================================================================
// BPF Timer & Arena
// ============================================================================

/// BPF timer flags
pub const BpfTimerFlags = packed struct(u64) {
    abstime: bool = false,
    pinned_cpu: bool = false,
    // Zxyphor
    zxy_high_res: bool = false,
    _padding: u61 = 0,
};

/// BPF arena flags
pub const BpfArenaFlags = packed struct(u64) {
    allow_resize: bool = false,
    // Zxyphor
    zxy_persistent: bool = false,
    _padding: u62 = 0,
};

// ============================================================================
// BPF Token
// ============================================================================

/// BPF token permissions
pub const BpfTokenPerms = packed struct(u32) {
    prog_load: bool = false,
    map_create: bool = false,
    btf_load: bool = false,
    link_create: bool = false,
    _padding: u28 = 0,
};

// ============================================================================
// BPF Helper Functions (subset)
// ============================================================================

/// BPF helper function IDs (most commonly used)
pub const BpfFunc = enum(u32) {
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
    // More recent
    ktime_get_coarse_ns = 160,
    copy_from_user = 168,
    snprintf_btf = 169,
    per_cpu_ptr = 172,
    this_cpu_ptr = 173,
    redirect_peer = 174,
    task_storage_get = 175,
    task_storage_delete = 176,
    get_current_task_btf = 177,
    bprm_opts_set = 178,
    ktime_get_coarse_ns_2 = 179,
    ima_inode_hash = 180,
    sock_from_file = 181,
    check_mtu = 182,
    for_each_map_elem = 183,
    snprintf = 184,
    sys_bpf = 185,
    btf_find_by_name_kind = 186,
    sys_close = 187,
    timer_init = 188,
    timer_set_callback = 189,
    timer_start = 190,
    timer_cancel = 191,
    get_func_ip = 192,
    get_attach_cookie = 193,
    task_pt_regs = 194,
    get_branch_snapshot = 195,
    trace_vprintk = 196,
    skc_to_unix_sock = 197,
    kallsyms_lookup_name = 198,
    find_vma = 199,
    loop = 200,
    strncmp = 201,
    get_func_arg = 202,
    get_func_ret = 203,
    get_func_arg_cnt = 204,
    get_retval = 205,
    set_retval = 206,
    xdp_get_buff_len = 207,
    xdp_load_bytes = 208,
    xdp_store_bytes = 209,
    copy_from_user_task = 210,
    skb_set_tstamp = 211,
    ima_file_hash = 212,
    kptr_xchg = 213,
    map_lookup_percpu_elem = 214,
    skc_to_mptcp_sock = 215,
    dynptr_from_mem = 216,
    ringbuf_reserve_dynptr = 217,
    ringbuf_submit_dynptr = 218,
    ringbuf_discard_dynptr = 219,
    dynptr_read = 220,
    dynptr_write = 221,
    dynptr_data = 222,
    tcp_raw_gen_syncookie_ipv4 = 223,
    tcp_raw_gen_syncookie_ipv6 = 224,
    tcp_raw_check_syncookie_ipv4 = 225,
    tcp_raw_check_syncookie_ipv6 = 226,
    ktime_get_tai_ns = 227,
    user_ringbuf_drain = 228,
    cgrp_storage_get = 229,
    cgrp_storage_delete = 230,
};

// ============================================================================
// BPF Subsystem Manager
// ============================================================================

pub const BpfSubsystem = struct {
    nr_progs_loaded: u64 = 0,
    nr_maps_created: u64 = 0,
    nr_links_active: u64 = 0,
    nr_btf_loaded: u32 = 0,
    jit_enabled: bool = true,
    jit_harden: u8 = 0,
    jit_kallsyms: bool = false,
    jit_limit: u64 = 0,
    unprivileged_disabled: u8 = 0,
    stats_enabled: bool = false,
    struct_ops_count: u32 = 0,
    lsm_hooks_count: u32 = 0,
    arena_count: u32 = 0,
    token_count: u32 = 0,
    initialized: bool = false,

    pub fn init() BpfSubsystem {
        return BpfSubsystem{
            .initialized = true,
        };
    }
};
