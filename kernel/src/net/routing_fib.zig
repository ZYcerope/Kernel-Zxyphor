// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Multipath Routing, Policy Routing,
// Routing Cache, FIB (Forwarding Information Base),
// AF_KEY / PF_KEY, L2TP, GRE/IPIP/SIT Tunnels,
// Network Namespaces Routing, VRF
// More advanced than Linux 2026 routing

const std = @import("std");

// ============================================================================
// FIB (Forwarding Information Base)
// ============================================================================

/// FIB table IDs
pub const FibTableId = enum(u32) {
    unspec = 0,
    compat = 252,
    default = 253,
    main = 254,
    local = 255,
    // Zxyphor extra tables
    zxy_fast_path = 500,
    zxy_multipath = 501,
};

/// FIB entry type
pub const FibEntryType = enum(u8) {
    unspec = 0,
    unicast = 1,
    local = 2,
    broadcast = 3,
    anycast = 4,
    multicast = 5,
    blackhole = 6,
    unreachable = 7,
    prohibit = 8,
    throw = 9,
    nat = 10,
    xresolve = 11,
    // Zxyphor
    zxy_redirect = 100,
    zxy_loadbalance = 101,
};

/// FIB protocol origin
pub const FibProtocol = enum(u8) {
    unspec = 0,
    redirect = 1,
    kernel = 2,
    boot = 3,
    static = 4,
    gated = 8,
    ra = 9,
    mrt = 10,
    zebra = 11,
    bird = 12,
    dnrouted = 13,
    xorp = 14,
    ntk = 15,
    dhcp = 16,
    mrouted = 17,
    keepalived = 18,
    babel = 42,
    bgp = 186,
    isis = 187,
    ospf = 188,
    rip = 189,
    eigrp = 192,
    // Zxyphor
    zxy_ai_route = 200,
};

/// FIB scope
pub const FibScope = enum(u8) {
    universe = 0,
    site = 200,
    link = 253,
    host = 254,
    nowhere = 255,
};

/// FIB entry flags
pub const FibEntryFlags = packed struct(u32) {
    dead: bool = false,
    notify: bool = false,
    cloned: bool = false,
    equalize: bool = false,
    prefix: bool = false,
    lookup_table: bool = false,
    fib_match: bool = false,
    offload: bool = false,
    trap: bool = false,
    offload_failed: bool = false,
    // Zxyphor
    zxy_priority: bool = false,
    zxy_cached: bool = false,
    _padding: u20 = 0,
};

/// FIB next-hop descriptor
pub const FibNextHop = struct {
    gateway: [16]u8 = [_]u8{0} ** 16,   // IPv4 or IPv6
    is_ipv6: bool = false,
    ifindex: u32 = 0,
    weight: u8 = 1,
    flags: FibNhFlags = .{},
    scope: FibScope = .universe,
    encap_type: FibEncapType = .none,
    nh_id: u32 = 0,
    realm: u32 = 0,
    via_table: u32 = 0,
};

pub const FibNhFlags = packed struct(u32) {
    dead: bool = false,
    pervasive: bool = false,
    onlink: bool = false,
    offload: bool = false,
    linkdown: bool = false,
    unresolved: bool = false,
    trap: bool = false,
    // Zxyphor
    zxy_preferred: bool = false,
    _padding: u24 = 0,
};

/// FIB encapsulation type
pub const FibEncapType = enum(u16) {
    none = 0,
    mpls = 1,
    ip = 2,
    ila = 3,
    bpf = 4,
    seg6 = 5,
    seg6_local = 6,
    rpl = 7,
    ioam6 = 8,
    // Zxyphor
    zxy_custom = 100,
};

/// FIB rule action
pub const FibRuleAction = enum(u8) {
    unspec = 0,
    to_tbl = 1,
    goto = 2,
    nop = 3,
    blackhole = 6,
    unreachable = 7,
    prohibit = 8,
};

/// FIB rule descriptor
pub const FibRuleDesc = struct {
    priority: u32 = 0,
    action: FibRuleAction = .to_tbl,
    table: u32 = 0,
    flags: u32 = 0,
    src: [16]u8 = [_]u8{0} ** 16,
    src_len: u8 = 0,
    dst: [16]u8 = [_]u8{0} ** 16,
    dst_len: u8 = 0,
    tos: u8 = 0,
    fwmark: u32 = 0,
    fwmask: u32 = 0,
    ifname: [16]u8 = [_]u8{0} ** 16,
    ifname_len: u8 = 0,
    suppress_prefixlen: i32 = -1,
    suppress_ifgroup: i32 = -1,
    uid_start: u32 = 0,
    uid_end: u32 = 0xFFFFFFFF,
    ip_proto: u8 = 0,
    sport_range: [2]u16 = [_]u16{0, 0xFFFF},
    dport_range: [2]u16 = [_]u16{0, 0xFFFF},
};

// ============================================================================
// Multipath Routing
// ============================================================================

/// Multipath algorithm
pub const MultipathAlgo = enum(u8) {
    wrandom = 0,         // weighted random
    drr = 1,             // deficit round robin
    random = 2,
    ecmp = 3,            // equal cost multi-path
    l3 = 4,              // hash on L3
    l4 = 5,              // hash on L3+L4
    // Zxyphor
    zxy_adaptive = 100,
    zxy_latency_aware = 101,
};

/// Multipath hash fields (sysctl)
pub const MultipathHashField = packed struct(u32) {
    src_ip: bool = true,
    dst_ip: bool = true,
    src_port: bool = false,
    dst_port: bool = false,
    ip_proto: bool = false,
    flowlabel: bool = false,
    inner_src_ip: bool = false,
    inner_dst_ip: bool = false,
    inner_src_port: bool = false,
    inner_dst_port: bool = false,
    inner_ip_proto: bool = false,
    // Zxyphor
    zxy_conntrack: bool = false,
    _padding: u20 = 0,
};

/// Multipath next-hop group
pub const NhGroupDesc = struct {
    id: u32 = 0,
    group_type: NhGroupType = .mpath,
    nr_nh: u16 = 0,
    resilient: bool = false,
    hash_threshold: u32 = 0,
    fdb: bool = false,
    // Stats
    packets: u64 = 0,
    bytes: u64 = 0,
};

pub const NhGroupType = enum(u16) {
    mpath = 0,       // multipath
    resilient = 1,
};

// ============================================================================
// Policy Routing (PBR)
// ============================================================================

/// Policy routing selector
pub const PbrSelector = struct {
    src_addr: [16]u8 = [_]u8{0} ** 16,
    src_mask: u8 = 0,
    dst_addr: [16]u8 = [_]u8{0} ** 16,
    dst_mask: u8 = 0,
    tos: u8 = 0,
    fwmark: u32 = 0,
    fwmask: u32 = 0,
    iif: u32 = 0,
    oif: u32 = 0,
    ip_proto: u8 = 0,
    sport: [2]u16 = .{ 0, 65535 },
    dport: [2]u16 = .{ 0, 65535 },
    uid_range: [2]u32 = .{ 0, 0xFFFFFFFF },
    priority: u32 = 0,
    table: u32 = 0,
    action: FibRuleAction = .to_tbl,
};

// ============================================================================
// AF_KEY / PF_KEY (IPsec SA management)
// ============================================================================

pub const PFKEY_VERSION = 2;

/// SADB message types
pub const SadbMsgType = enum(u8) {
    reserved = 0,
    getspi = 1,
    update = 2,
    add = 3,
    delete = 4,
    get = 5,
    acquire = 6,
    register = 7,
    expire = 8,
    flush = 9,
    dump = 10,
    x_promisc = 11,
    x_pchange = 12,
    x_spdupdate = 13,
    x_spdadd = 14,
    x_spddelete = 15,
    x_spdget = 16,
    x_spdacquire = 17,
    x_spddump = 18,
    x_spdflush = 19,
    x_spdsetidx = 20,
    x_spdexpire = 21,
    x_spddelete2 = 22,
    x_nat_t_new_mapping = 23,
    x_migrate = 24,
};

/// SADB SA type
pub const SadbSaType = enum(u8) {
    unspec = 0,
    ah = 2,
    esp = 3,
    rsvp = 5,
    ospfv2 = 6,
    ripv2 = 7,
    mip = 8,
    ipcomp = 9,
    // Zxyphor
    zxy_custom = 100,
};

/// SADB header
pub const SadbMsgHeader = extern struct {
    version: u8,
    msg_type: u8,
    errno: u8,
    satype: u8,
    len: u16,
    reserved: u16,
    seq: u32,
    pid: u32,
};

/// SADB extension types
pub const SadbExtType = enum(u16) {
    reserved = 0,
    sa = 1,
    lifetime_current = 2,
    lifetime_hard = 3,
    lifetime_soft = 4,
    address_src = 5,
    address_dst = 6,
    address_proxy = 7,
    key_auth = 8,
    key_encrypt = 9,
    identity_src = 10,
    identity_dst = 11,
    sensitivity = 12,
    proposal = 13,
    supported_auth = 14,
    supported_encrypt = 15,
    spirange = 16,
    x_kmprivate = 17,
    x_policy = 18,
    x_sa2 = 19,
    x_nat_t_type = 20,
    x_nat_t_sport = 21,
    x_nat_t_dport = 22,
    x_nat_t_oa = 23,
    x_sec_ctx = 24,
    x_kmaddress = 25,
    x_filter = 26,
};

// ============================================================================
// L2TP (Layer 2 Tunneling Protocol)
// ============================================================================

/// L2TP version
pub const L2tpVersion = enum(u8) {
    v2 = 2,
    v3 = 3,
};

/// L2TP encapsulation
pub const L2tpEncap = enum(u8) {
    udp = 0,
    ip = 1,
};

/// L2TP pseudowire type
pub const L2tpPwType = enum(u16) {
    ppp = 0x0001,
    ppp_ac = 0x0002,
    ethernet = 0x0005,
    ethernet_vlan = 0x0006,
    hdlc = 0x0007,
    // Zxyphor
    zxy_raw = 0x8000,
};

/// L2TP tunnel descriptor
pub const L2tpTunnelDesc = struct {
    tunnel_id: u32 = 0,
    peer_tunnel_id: u32 = 0,
    version: L2tpVersion = .v3,
    encap: L2tpEncap = .udp,
    fd: i32 = -1,
    local_addr: [16]u8 = [_]u8{0} ** 16,
    peer_addr: [16]u8 = [_]u8{0} ** 16,
    local_port: u16 = 0,
    peer_port: u16 = 0,
    recv_seq: bool = false,
    send_seq: bool = false,
    debug: u32 = 0,
    nr_sessions: u32 = 0,
    stats: L2tpStats = .{},
};

/// L2TP session descriptor
pub const L2tpSessionDesc = struct {
    session_id: u32 = 0,
    peer_session_id: u32 = 0,
    tunnel_id: u32 = 0,
    pw_type: L2tpPwType = .ethernet,
    recv_seq: bool = false,
    send_seq: bool = false,
    cookie: [8]u8 = [_]u8{0} ** 8,
    cookie_len: u8 = 0,
    peer_cookie: [8]u8 = [_]u8{0} ** 8,
    peer_cookie_len: u8 = 0,
    l2spec_type: u8 = 0,
    ifname: [16]u8 = [_]u8{0} ** 16,
    ifname_len: u8 = 0,
    mtu: u32 = 1500,
};

/// L2TP statistics
pub const L2tpStats = struct {
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
    tx_errors: u64 = 0,
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    rx_seq_discards: u64 = 0,
    rx_oos_packets: u64 = 0,
};

// ============================================================================
// GRE / IPIP / SIT Tunnels
// ============================================================================

/// Tunnel type
pub const TunnelType = enum(u8) {
    ipip = 0,       // IP-in-IP (proto 4)
    gre = 1,        // GRE (proto 47)
    sit = 2,        // IPv6-in-IPv4 (proto 41)
    ip6tnl = 3,     // IPv6 tunnel
    ip6gre = 4,     // GRE over IPv6
    vti = 5,        // Virtual Tunnel Interface
    vti6 = 6,       // VTI over IPv6
    geneve = 7,     // GENEVE
    vxlan = 8,      // VXLAN
    erspan = 9,     // ERSPAN
    // Zxyphor
    zxy_smart = 100,
};

/// GRE header flags
pub const GreFlags = packed struct(u16) {
    checksum: bool = false,
    routing: bool = false,
    key: bool = false,
    sequence: bool = false,
    strict_src_route: bool = false,
    recursion_control: u3 = 0,
    ack: bool = false,
    _reserved: u4 = 0,
    version: u3 = 0,
};

/// Tunnel parameters
pub const TunnelParams = struct {
    tunnel_type: TunnelType = .gre,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    local: [16]u8 = [_]u8{0} ** 16,
    remote: [16]u8 = [_]u8{0} ** 16,
    is_ipv6: bool = false,
    link: u32 = 0,              // underlying interface index
    ttl: u8 = 64,
    tos: u8 = 0,
    pmtudisc: bool = true,
    // GRE specific
    gre_flags: GreFlags = .{},
    gre_key: u32 = 0,
    // VXLAN specific
    vni: u32 = 0,
    vxlan_port: u16 = 4789,
    // GENEVE specific
    geneve_port: u16 = 6081,
    // Encapsulation
    encap_type: u16 = 0,       // FOU, GUE
    encap_sport: u16 = 0,
    encap_dport: u16 = 0,
    mtu: u32 = 0,
    ifindex: u32 = 0,
};

// ============================================================================
// VRF (Virtual Routing and Forwarding)
// ============================================================================

/// VRF descriptor
pub const VrfDesc = struct {
    table_id: u32 = 0,
    ifindex: u32 = 0,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    strict_mode: bool = false,
    tcp_l3mdev_accept: bool = false,
    // Stats
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
};

// ============================================================================
// Routing Subsystem Manager
// ============================================================================

pub const RoutingSubsystem = struct {
    nr_fib_tables: u32 = 0,
    nr_fib_rules: u32 = 0,
    nr_routes: u64 = 0,
    nr_nexthops: u32 = 0,
    nr_nh_groups: u32 = 0,
    nr_tunnels: u32 = 0,
    nr_vrfs: u32 = 0,
    nr_l2tp_tunnels: u32 = 0,
    multipath_algo: MultipathAlgo = .l4,
    gc_interval_ms: u32 = 600000,
    gc_timeout_ms: u32 = 300000,
    fib_multipath_hash_fields: MultipathHashField = .{},
    initialized: bool = false,

    pub fn init() RoutingSubsystem {
        return RoutingSubsystem{
            .initialized = true,
        };
    }
};
