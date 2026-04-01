// SPDX-License-Identifier: MIT
// Zxyphor Kernel - DCCP Protocol, Multicast Routing, AF_UNIX Internals,
// Netlink Advanced, Network Namespace Internals, XDP Programs
// More advanced than Linux 2026 advanced networking

const std = @import("std");

// ============================================================================
// DCCP (Datagram Congestion Control Protocol) - RFC 4340
// ============================================================================

pub const DccpPacketType = enum(u4) {
    request = 0,
    response = 1,
    data = 2,
    ack = 3,
    dataack = 4,
    closereq = 5,
    close = 6,
    reset = 7,
    sync = 8,
    syncack = 9,
    listen = 10,
    // 11-15 reserved
};

pub const DccpResetCode = enum(u8) {
    unspecified = 0,
    closed = 1,
    aborted = 2,
    no_connection = 3,
    packet_error = 4,
    option_error = 5,
    mandatory_error = 6,
    connection_refused = 7,
    bad_service_code = 8,
    too_busy = 9,
    bad_init_cookie = 10,
    aggression_penalty = 11,
};

pub const DccpState = enum(u8) {
    closed = 0,
    listen = 1,
    request = 2,
    respond = 3,
    partopen = 4,
    open = 5,
    closereq = 6,
    closing = 7,
    timewait = 8,
};

pub const DccpOptionType = enum(u8) {
    padding = 0,
    mandatory = 1,
    slow_receiver = 2,
    change_l = 32,
    confirm_l = 33,
    change_r = 34,
    confirm_r = 35,
    init_cookie = 36,
    ndp_count = 37,
    ack_vector_0 = 38,
    ack_vector_1 = 39,
    data_dropped = 40,
    timestamp = 41,
    timestamp_echo = 42,
    elapsed_time = 43,
    multipath = 44,
};

pub const DccpCcid = enum(u8) {
    ccid2 = 2,    // TCP-like congestion control
    ccid3 = 3,    // TFRC (TCP Friendly Rate Control)
};

pub const DccpHeader = struct {
    src_port: u16 = 0,
    dst_port: u16 = 0,
    data_offset: u8 = 0,
    ccval: u4 = 0,
    cscov: u4 = 0,          // Checksum coverage
    checksum: u16 = 0,
    pkt_type: DccpPacketType = .data,
    x: bool = false,         // Extended sequence number
    seq_high: u16 = 0,
    seq_low: u32 = 0,
};

pub const DccpSocket = struct {
    state: DccpState = .closed,
    ccid: DccpCcid = .ccid2,
    service_code: u32 = 0,
    // Sequence numbers
    iss: u48 = 0,     // Initial Send Sequence
    isr: u48 = 0,     // Initial Recv Sequence
    gss: u48 = 0,     // Greatest Seq Sent
    gsr: u48 = 0,     // Greatest Seq Received
    gar: u48 = 0,     // Greatest Ack Received
    // Features
    ack_ratio: u16 = 2,
    send_ack_vector: bool = true,
    send_ndp_count: bool = true,
    // CCID3 TFRC
    tfrc_rtt: u32 = 0,
    tfrc_p: u32 = 0,        // Loss event rate
    tfrc_x_recv: u32 = 0,   // Receive rate
    tfrc_x: u32 = 0,        // Sending rate
    // Stats
    total_sent: u64 = 0,
    total_recv: u64 = 0,
    total_retrans: u64 = 0,
};

// ============================================================================
// Multicast Routing
// ============================================================================

pub const McastProto = enum(u8) {
    igmpv1 = 1,
    igmpv2 = 2,
    igmpv3 = 3,
    mld1 = 4,       // MLDv1 (IPv6)
    mld2 = 5,       // MLDv2 (IPv6)
};

pub const MrouteType = enum(u8) {
    pim_sm = 0,     // Protocol Independent Multicast - Sparse Mode
    pim_dm = 1,     // PIM Dense Mode
    pim_ssm = 2,    // PIM Source-Specific Multicast
    pim_bidir = 3,  // PIM Bidirectional
    dvmrp = 4,      // Distance Vector Multicast Routing
};

pub const MfcEntry = struct {
    origin: u32 = 0,         // Source IP
    group: u32 = 0,          // Group IP
    parent_vif: u16 = 0,     // Incoming VIF
    ttls: [32]u8 = [_]u8{0} ** 32,  // Per-VIF TTL thresholds
    // Stats
    pkt_cnt: u64 = 0,
    byte_cnt: u64 = 0,
    wrong_if: u64 = 0,
    last_assert: u64 = 0,
    // Expiry
    expires: u64 = 0,
};

pub const Vif = struct {
    vif_index: u16 = 0,
    flags: u32 = 0,
    threshold: u8 = 1,
    rate_limit: u32 = 0,
    local_addr: u32 = 0,
    remote_addr: u32 = 0,
    dev_index: u32 = 0,
    // Stats
    in_pkts: u64 = 0,
    in_bytes: u64 = 0,
    out_pkts: u64 = 0,
    out_bytes: u64 = 0,
};

// ============================================================================
// AF_UNIX (Unix Domain Socket) Internals
// ============================================================================

pub const UnixSocketType = enum(u8) {
    stream = 1,
    dgram = 2,
    seqpacket = 5,
};

pub const UnixState = enum(u8) {
    unconnected = 0,
    connecting = 1,
    connected = 2,
    disconnecting = 3,
};

pub const UnixFlags = packed struct {
    accepts: bool = false,
    candidate_for_gc: bool = false,
    wait_data: bool = false,
    msg_peek: bool = false,
    _padding: u4 = 0,
};

pub const UnixSocket = struct {
    sock_type: UnixSocketType = .stream,
    state: UnixState = .unconnected,
    flags: UnixFlags = .{},
    // Path
    path: [108]u8 = [_]u8{0} ** 108,
    path_len: u8 = 0,
    is_abstract: bool = false,
    // Peer
    peer_pid: i32 = 0,
    peer_uid: u32 = 0,
    peer_gid: u32 = 0,
    // Buffers
    sndbuf: u32 = 212992,
    rcvbuf: u32 = 212992,
    sk_rmem_alloc: u32 = 0,
    sk_wmem_alloc: u32 = 0,
    sk_wmem_queued: u32 = 0,
    // Credential passing
    passcred: bool = false,
    passnsfd: bool = false,
    // SCM_RIGHTS tracking
    nr_fds_in_flight: u32 = 0,
    // Stats
    total_sent: u64 = 0,
    total_recv: u64 = 0,
    total_sent_bytes: u64 = 0,
    total_recv_bytes: u64 = 0,
};

// ============================================================================
// Netlink Advanced
// ============================================================================

pub const NetlinkFamily = enum(u8) {
    route = 0,
    unused = 1,
    usersock = 2,
    firewall = 3,
    sock_diag = 4,
    nflog = 5,
    xfrm = 6,
    selinux = 7,
    iscsi = 8,
    audit = 9,
    fib_lookup = 10,
    connector = 11,
    netfilter = 12,
    ip6_fw = 13,
    dnrtmsg = 14,
    kobject_uevent = 15,
    generic = 16,
    scsitransport = 18,
    ecryptfs = 19,
    rdma = 20,
    crypto = 21,
    // Zxyphor
    zxy_kernel_event = 30,
};

pub const NlMsgType = enum(u16) {
    noop = 1,
    error = 2,
    done = 3,
    overrun = 4,
    // RTM types
    rtm_newlink = 16,
    rtm_dellink = 17,
    rtm_getlink = 18,
    rtm_setlink = 19,
    rtm_newaddr = 20,
    rtm_deladdr = 21,
    rtm_getaddr = 22,
    rtm_newroute = 24,
    rtm_delroute = 25,
    rtm_getroute = 26,
    rtm_newneigh = 28,
    rtm_delneigh = 29,
    rtm_getneigh = 30,
    rtm_newrule = 32,
    rtm_delrule = 33,
    rtm_getrule = 34,
    rtm_newqdisc = 36,
    rtm_delqdisc = 37,
    rtm_getqdisc = 38,
    rtm_newtclass = 40,
    rtm_deltclass = 41,
    rtm_gettclass = 42,
    rtm_newtfilter = 44,
    rtm_deltfilter = 45,
    rtm_gettfilter = 46,
    rtm_newaction = 48,
    rtm_delaction = 49,
    rtm_getaction = 50,
    rtm_newprefix = 52,
    rtm_getmulticast = 58,
    rtm_getanycast = 62,
    rtm_newnsid = 68,
    rtm_delnsid = 69,
    rtm_getnsid = 70,
    rtm_newstats = 92,
    rtm_getstats = 94,
    rtm_newchain = 100,
    rtm_delchain = 101,
    rtm_getchain = 102,
    rtm_newvlan = 112,
    rtm_delvlan = 113,
    rtm_getvlan = 114,
    rtm_newnexthop = 104,
    rtm_delnexthop = 105,
    rtm_getnexthop = 106,
    rtm_newtunnel = 120,
    rtm_deltunnel = 121,
    rtm_gettunnel = 122,
};

pub const NlFlags = packed struct {
    request: bool = false,
    multi: bool = false,
    ack: bool = false,
    echo: bool = false,
    dump_intr: bool = false,
    dump_filtered: bool = false,
    // GET-specific
    root: bool = false,
    match_: bool = false,
    atomic: bool = false,
    // NEW-specific
    replace: bool = false,
    excl: bool = false,
    create: bool = false,
    append: bool = false,
    // Bulk
    bulk: bool = false,
    _padding: u2 = 0,
};

pub const NlMsgHeader = struct {
    nlmsg_len: u32 = 0,
    nlmsg_type: u16 = 0,
    nlmsg_flags: u16 = 0,
    nlmsg_seq: u32 = 0,
    nlmsg_pid: u32 = 0,
};

pub const GenericNetlinkFamily = struct {
    id: u16 = 0,
    name: [16]u8 = [_]u8{0} ** 16,
    version: u8 = 0,
    maxattr: u16 = 0,
    nr_ops: u16 = 0,
    nr_mcast_groups: u8 = 0,
};

// ============================================================================
// Network Namespace Internals
// ============================================================================

pub const NetNsFlags = packed struct {
    loopback_up: bool = false,
    vlan_filtering: bool = false,
    ipv6_enabled: bool = false,
    // Zxyphor
    zxy_isolated: bool = false,
    _padding: u4 = 0,
};

pub const NetNs = struct {
    nsid: u32 = 0,
    count: u32 = 0,       // Reference count
    flags: NetNsFlags = .{},
    // Devices
    nr_net_devices: u32 = 0,
    // Routing
    nr_routes_v4: u32 = 0,
    nr_routes_v6: u32 = 0,
    // Firewall rules
    nr_nftables_rules: u32 = 0,
    // IP addresses
    nr_addrs_v4: u32 = 0,
    nr_addrs_v6: u32 = 0,
    // Sockets
    nr_tcp_sockets: u32 = 0,
    nr_udp_sockets: u32 = 0,
    nr_unix_sockets: u32 = 0,
    // Neighbors
    nr_neigh_entries: u32 = 0,
    // Stats
    total_rx_packets: u64 = 0,
    total_tx_packets: u64 = 0,
    total_rx_bytes: u64 = 0,
    total_tx_bytes: u64 = 0,
};

// ============================================================================
// XDP (Express Data Path) Programs
// ============================================================================

pub const XdpAction = enum(u32) {
    aborted = 0,
    drop = 1,
    pass = 2,
    tx = 3,
    redirect = 4,
};

pub const XdpAttachMode = enum(u8) {
    none = 0,
    skb = 1,          // Generic/SKB mode
    drv = 2,          // Driver/native mode
    hw = 3,           // Hardware offload
};

pub const XdpFlags = packed struct {
    update_if_noexist: bool = false,
    skb_mode: bool = false,
    drv_mode: bool = false,
    hw_mode: bool = false,
    replace: bool = false,
    _padding: u3 = 0,
};

pub const XdpProgramInfo = struct {
    prog_id: u32 = 0,
    prog_tag: [8]u8 = [_]u8{0} ** 8,
    attach_mode: XdpAttachMode = .none,
    ifindex: u32 = 0,
    // Stats
    rx_dropped: u64 = 0,
    rx_passed: u64 = 0,
    rx_redirected: u64 = 0,
    rx_errors: u64 = 0,
    tx_xmit: u64 = 0,
    // Timing
    total_run_ns: u64 = 0,
    total_runs: u64 = 0,
};

pub const XdpUmemConfig = struct {
    fill_size: u32 = 0,
    comp_size: u32 = 0,
    frame_size: u32 = 4096,
    frame_headroom: u32 = 0,
    flags: u32 = 0,
};

pub const XskSocket = struct {
    ifindex: u32 = 0,
    queue_id: u32 = 0,
    // Rings
    rx_ring_size: u32 = 0,
    tx_ring_size: u32 = 0,
    fill_ring_size: u32 = 0,
    comp_ring_size: u32 = 0,
    // Umem
    umem_size: u64 = 0,
    umem_chunk_size: u32 = 0,
    nr_umem_frames: u32 = 0,
    // Stats
    rx_dropped: u64 = 0,
    rx_invalid_descs: u64 = 0,
    tx_invalid_descs: u64 = 0,
    rx_ring_full: u64 = 0,
    rx_fill_ring_empty: u64 = 0,
    tx_ring_empty: u64 = 0,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const AdvancedNetSubsystem = struct {
    // DCCP
    nr_dccp_sockets: u32 = 0,
    total_dccp_sent: u64 = 0,
    total_dccp_recv: u64 = 0,
    // Multicast
    nr_mfc_entries: u32 = 0,
    nr_vifs: u16 = 0,
    total_mcast_pkts: u64 = 0,
    // UNIX
    nr_unix_sockets: u64 = 0,
    total_unix_fds_in_flight: u64 = 0,
    // Netlink
    nr_netlink_families: u16 = 0,
    nr_genetlink_families: u16 = 0,
    total_netlink_messages: u64 = 0,
    // Net namespaces
    nr_net_ns: u32 = 0,
    // XDP
    nr_xdp_programs: u32 = 0,
    nr_xsk_sockets: u32 = 0,
    total_xdp_redirects: u64 = 0,
    // Zxyphor
    zxy_zero_copy_networking: bool = false,
    initialized: bool = false,
};
