// Zxyphor Kernel - MPTCP (Multipath TCP) Implementation,
// AF_PACKET Raw Socket Layer,
// Network Namespace Detail,
// Socket BPF Hooks,
// XDP (eXpress Data Path) Internals,
// TC (Traffic Control) Internals
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// MPTCP (Multipath TCP) - RFC 8684
// ============================================================================

pub const MPTCP_VERSION: u8 = 1;

pub const MptcpSubtype = enum(u4) {
    mp_capable = 0,
    mp_join = 1,
    dss = 2,
    add_addr = 3,
    remove_addr = 4,
    mp_prio = 5,
    mp_fail = 6,
    mp_fastclose = 7,
    mp_tcprst = 8,
};

pub const MptcpCapableFlags = packed struct(u8) {
    checksum_required: bool = false,
    extensibility: bool = false,
    deny_join_id0: bool = false,
    hmac_sha256: bool = true,
    _reserved: u4 = 0,
};

pub const MptcpAddrFlags = packed struct(u8) {
    backup: bool = false,
    ipv6: bool = false,
    has_port: bool = false,
    has_hmac: bool = false,
    echo: bool = false,
    _reserved: u3 = 0,
};

pub const MptcpScheduler = enum(u8) {
    default = 0,
    round_robin = 1,
    redundant = 2,
    blest = 3,
    ecf = 4,
    custom_zxyphor = 5,
};

pub const MptcpPmType = enum(u8) {
    kernel = 0,
    userspace = 1,
    bpf = 2,
};

pub const MptcpPathState = enum(u8) {
    initial = 0,
    established = 1,
    close_wait = 2,
    degraded = 3,
    reset = 4,
};

pub const MptcpSockInfo = struct {
    local_key: u64,
    remote_key: u64,
    token: u32,
    subflows: u8,
    add_addr_signal: u8,
    rm_addr_signal: u8,
    scheduler: MptcpScheduler,
    pm_type: MptcpPmType,
    flags: MptcpCapableFlags,
    max_subflows: u8,
    max_add_addr_accepted: u8,
    backup_subflows: u8,
};

pub const MptcpDssFlags = packed struct(u16) {
    data_fin: bool = false,
    dsn_is_8: bool = false,
    dsn_present: bool = false,
    ack_is_8: bool = false,
    ack_present: bool = false,
    has_checksum: bool = false,
    _reserved: u10 = 0,
};

// ============================================================================
// AF_PACKET Raw Socket Layer
// ============================================================================

pub const AF_PACKET: u16 = 17;

pub const PacketType = enum(u16) {
    host = 0,
    broadcast = 1,
    multicast = 2,
    otherhost = 3,
    outgoing = 4,
    loopback = 5,
    fastroute = 6,
};

pub const PacketSocketType = enum(u32) {
    raw = 3,          // SOCK_RAW
    dgram = 2,        // SOCK_DGRAM
};

pub const PacketMmapVersion = enum(u32) {
    v1 = 0,
    v2 = 1,
    v3 = 2,
};

pub const TpacketHdrV1 = extern struct {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_usec: u32,
};

pub const TpacketHdrV3 = extern struct {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    hv1: extern struct {
        tp_rxhash: u32,
        tp_vlan_tci: u32,
        tp_vlan_tpid: u16,
        tp_padding: u16,
    },
};

pub const TpacketBdHdrU = extern struct {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: extern struct {
        ts_sec: u32,
        ts_nsec_or_usec: u32,
    },
    ts_last_pkt: extern struct {
        ts_sec: u32,
        ts_nsec_or_usec: u32,
    },
};

pub const PacketReq3 = extern struct {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
};

pub const PacketFanoutType = enum(u16) {
    hash = 0,
    lb = 1,
    cpu = 2,
    rollover = 3,
    rnd = 4,
    qm = 5,
    cbpf = 6,
    ebpf = 7,
};

pub const PacketFanoutFlags = packed struct(u16) {
    defrag: bool = false,
    rollover: bool = false,
    uniqueid: bool = false,
    _reserved: u13 = 0,
};

// ============================================================================
// Network Namespace Detail
// ============================================================================

pub const NetNsFlags = packed struct(u32) {
    has_ipv4: bool = true,
    has_ipv6: bool = true,
    has_netfilter: bool = true,
    has_xfrm: bool = true,
    has_nf_conntrack: bool = false,
    has_unix: bool = true,
    has_packet: bool = true,
    has_netlink: bool = true,
    loopback_created: bool = false,
    _reserved: u23 = 0,
};

pub const NetNs = struct {
    id: u32,
    flags: NetNsFlags,
    ifindex_head: u32,
    dev_count: u32,
    rules_count: u32,
    netns_id: i32,
    user_ns_owner: u64,
    refcount: u32,
    // Subsystem pointers
    proc_net: ?*anyopaque,
    ipv4_sysctl: ?*anyopaque,
    ipv6_sysctl: ?*anyopaque,
    ct_net: ?*anyopaque,
    nf_tables_net: ?*anyopaque,
};

pub const NsOperation = enum(u8) {
    create = 0,
    enter = 1,
    bind = 2,
    connect = 3,
    move_netdev = 4,
    set_nsid = 5,
    get_nsid = 6,
    delete = 7,
};

// ============================================================================
// Socket BPF Hooks
// ============================================================================

pub const SkBpfAttachType = enum(u32) {
    sk_filter = 0,
    sk_reuseport = 1,
    sk_msg_verdict = 2,
    sk_skb_stream_parser = 3,
    sk_skb_stream_verdict = 4,
    sk_skb_verdict = 5,
    cgroup_inet_ingress = 6,
    cgroup_inet_egress = 7,
    cgroup_inet4_bind = 8,
    cgroup_inet6_bind = 9,
    cgroup_inet4_connect = 10,
    cgroup_inet6_connect = 11,
    cgroup_inet4_post_bind = 12,
    cgroup_inet6_post_bind = 13,
    cgroup_udp4_sendmsg = 14,
    cgroup_udp6_sendmsg = 15,
    cgroup_udp4_recvmsg = 16,
    cgroup_udp6_recvmsg = 17,
    cgroup_getsockopt = 18,
    cgroup_setsockopt = 19,
    cgroup_inet4_getpeername = 20,
    cgroup_inet6_getpeername = 21,
    cgroup_inet4_getsockname = 22,
    cgroup_inet6_getsockname = 23,
    cgroup_inet_sock_create = 24,
    cgroup_inet_sock_release = 25,
    cgroup_sysctl = 26,
    cgroup_device = 27,
};

pub const SockMapFlags = packed struct(u32) {
    bpf_f_ingress: bool = false,
    bpf_f_no_prealloc: bool = false,
    bpf_f_numa_node: bool = false,
    bpf_f_rdonly: bool = false,
    bpf_f_wronly: bool = false,
    bpf_f_stack_build_id: bool = false,
    bpf_f_zero_seed: bool = false,
    bpf_f_rdonly_prog: bool = false,
    bpf_f_wronly_prog: bool = false,
    bpf_f_clone: bool = false,
    bpf_f_mmapable: bool = false,
    bpf_f_preserve_elems: bool = false,
    bpf_f_inner_map: bool = false,
    bpf_f_link: bool = false,
    bpf_f_path_fd: bool = false,
    _reserved: u17 = 0,
};

pub const SkBpfVerdict = enum(i32) {
    ok = 0,
    drop = 2,
    redirect = 7,
    sk_drop = 0x80000000 + 2,
    sk_pass = 0x80000000 + 0,
};

// ============================================================================
// XDP (eXpress Data Path) Internals
// ============================================================================

pub const XdpAction = enum(u32) {
    aborted = 0,
    drop = 1,
    pass = 2,
    tx = 3,
    redirect = 4,
};

pub const XdpFlags = packed struct(u32) {
    update_if_noexist: bool = false,
    skb_mode: bool = false,
    drv_mode: bool = false,
    hw_mode: bool = false,
    replace: bool = false,
    _reserved: u27 = 0,
};

pub const XdpMd = extern struct {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
};

pub const XdpDesc = extern struct {
    addr: u64,
    len: u32,
    options: u32,
};

pub const XdpUmemReg = extern struct {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
};

pub const XskRingProd = extern struct {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *u32,
    consumer: *u32,
    flags: *u32,
    ring: [*]XdpDesc,
};

pub const XskRingCons = extern struct {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *u32,
    consumer: *u32,
    flags: *u32,
    ring: [*]XdpDesc,
};

pub const XdpRxqInfo = struct {
    dev: ?*anyopaque,
    queue_index: u32,
    reg_state: XdpRxqState,
    mem_type: XdpMemType,
    napi_id: u32,
    frag_size: u32,
};

pub const XdpRxqState = enum(u8) {
    unused = 0,
    registered = 1,
    active = 2,
};

pub const XdpMemType = enum(u8) {
    page_shared = 0,
    page_order0 = 1,
    page_pool = 2,
    xsk_buff_pool = 3,
};

pub const XdpBuff = struct {
    data: [*]u8,
    data_end: [*]u8,
    data_meta: [*]u8,
    data_hard_start: [*]u8,
    rxq: *XdpRxqInfo,
    frame_sz: u32,
    flags: u32,
};

pub const XdpFeatures = packed struct(u64) {
    xdp_basic: bool = false,
    redirect: bool = false,
    ndo_xmit: bool = false,
    xsk_zerocopy: bool = false,
    hw_offload: bool = false,
    rx_sg: bool = false,
    ndo_xmit_sg: bool = false,
    _reserved: u57 = 0,
};

// ============================================================================
// TC (Traffic Control) Internals
// ============================================================================

pub const TcHandleMajor = enum(u16) {
    root = 0xFFFF,
    unspec = 0,
    ingress = 0xFFF1,
    clsact = 0xFFF2,
};

pub const TcQdiscType = enum(u8) {
    // Classless
    pfifo_fast = 0,
    tbf = 1,
    sfq = 2,
    red = 3,
    fq = 4,
    fq_codel = 5,
    cake = 6,
    netem = 7,
    pfifo = 8,
    bfifo = 9,
    noqueue = 10,
    mq = 11,
    // Classful
    htb = 20,
    hfsc = 21,
    prio = 22,
    cbq = 23,
    drr = 24,
    qfq = 25,
    ets = 26,
    mqprio = 27,
    taprio = 28,
};

pub const TcFilterType = enum(u8) {
    u32_filter = 0,
    flower = 1,
    bpf = 2,
    matchall = 3,
    cgroup = 4,
    route = 5,
    fw = 6,
    basic = 7,
};

pub const TcActionType = enum(u8) {
    gact = 0,
    mirred = 1,
    pedit = 2,
    nat_act = 3,
    tunnel_key = 4,
    vlan = 5,
    sample = 6,
    police = 7,
    connmark = 8,
    ct_act = 9,
    skbedit = 10,
    mpls = 11,
    gate = 12,
};

pub const TcActionVerdict = enum(i32) {
    ok = 0,
    reclassify = 1,
    shot = 2,
    pipe = 3,
    stolen = 4,
    queued = 5,
    repeat = 6,
    redirect = 7,
    trap = 8,
};

pub const TcHtbClassParams = struct {
    rate: u64,              // bytes/sec
    ceil: u64,              // bytes/sec (ceil)
    burst: u32,             // bytes
    cburst: u32,            // bytes
    quantum: u32,           // bytes
    priority: u32,
    level: u32,
};

pub const TcCakeParams = struct {
    bandwidth: u64,
    target_us: u32,
    interval_us: u32,
    diffserv_mode: CakeDiffservMode,
    flow_mode: CakeFlowMode,
    nat: bool,
    wash: bool,
    ingress: bool,
    ack_filter: CakeAckFilter,
    overhead: i32,
    mpu: u32,
    atm: CakeAtmMode,
};

pub const CakeDiffservMode = enum(u8) {
    diffserv3 = 0,
    diffserv4 = 1,
    diffserv8 = 2,
    besteffort = 3,
    precedence = 4,
};

pub const CakeFlowMode = enum(u8) {
    none = 0,
    src_ip = 1,
    dst_ip = 2,
    hosts = 3,
    flows = 4,
    dual_src = 5,
    dual_dst = 6,
    triple = 7,
};

pub const CakeAckFilter = enum(u8) {
    no = 0,
    yes = 1,
    aggressive = 2,
};

pub const CakeAtmMode = enum(u8) {
    none = 0,
    atm = 1,
    ptm = 2,
};

pub const TcFqCodelParams = struct {
    target: u32,        // usec
    interval: u32,      // usec
    quantum: u32,       // bytes
    limit: u32,         // packets
    flows: u32,
    ecn: bool,
    ce_threshold: u32,  // usec
    memory_limit: u32,  // bytes
};

pub const TcFlowerMatch = packed struct(u64) {
    src_ip: bool = false,
    dst_ip: bool = false,
    src_port: bool = false,
    dst_port: bool = false,
    ip_proto: bool = false,
    vlan_id: bool = false,
    vlan_prio: bool = false,
    eth_type: bool = false,
    eth_dst: bool = false,
    eth_src: bool = false,
    ip_tos: bool = false,
    ip_ttl: bool = false,
    tcp_flags: bool = false,
    ct_state: bool = false,
    ct_zone: bool = false,
    ct_mark: bool = false,
    ct_label: bool = false,
    enc_dst_ip: bool = false,
    enc_src_ip: bool = false,
    enc_key_id: bool = false,
    enc_dst_port: bool = false,
    mpls_label: bool = false,
    mpls_tc: bool = false,
    mpls_bos: bool = false,
    _reserved: u40 = 0,
};

// ============================================================================
// Network Subsystem Manager
// ============================================================================

pub const NetworkAdvancedManager = struct {
    mptcp_enabled: bool,
    xdp_mode: XdpFlags,
    net_ns_count: u32,
    packet_sockets: u32,
    tc_qdiscs: u32,
    sk_bpf_programs: u32,
    initialized: bool,

    pub fn init() NetworkAdvancedManager {
        return std.mem.zeroes(NetworkAdvancedManager);
    }
};
