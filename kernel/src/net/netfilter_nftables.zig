// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Netfilter / nf_tables / iptables Complete
// nf_conntrack, nf_tables, iptables chains/rules/matches/targets,
// NAT, MASQUERADE, DNAT, SNAT, connection tracking, zones

const std = @import("std");

// ============================================================================
// Netfilter Hooks
// ============================================================================

pub const NfProtoFamily = enum(u8) {
    Unspec = 0,
    Inet = 1,
    Ipv4 = 2,
    Arp = 3,
    Netdev = 5,
    Bridge = 7,
    Ipv6 = 10,
    Decnet = 12,
    NumProto = 13,
};

pub const NfHookNum = enum(u8) {
    PreRouting = 0,
    LocalIn = 1,
    Forward = 2,
    LocalOut = 3,
    PostRouting = 4,
    Ingress = 5,
    NumHooks = 6,
};

pub const NfVerdict = enum(i32) {
    Drop = 0,
    Accept = 1,
    Stolen = 2,
    Queue = 3,
    Repeat = 4,
    Stop = 5,
};

pub const NfHookOps = struct {
    hook: ?*const fn (priv: ?*anyopaque, skb: ?*anyopaque, state: *NfHookState) callconv(.C) u32,
    dev: ?*anyopaque,
    priv_data: ?*anyopaque,
    pf: NfProtoFamily,
    hooknum: NfHookNum,
    priority: i32,
};

pub const NfHookState = struct {
    hook: NfHookNum,
    pf: NfProtoFamily,
    in_dev: ?*anyopaque,
    out_dev: ?*anyopaque,
    sk: ?*anyopaque,
    net: ?*anyopaque,
};

// ============================================================================
// Connection Tracking (nf_conntrack)
// ============================================================================

pub const NfConntrackStatus = packed struct(u32) {
    expected: bool = false,
    seen_reply: bool = false,
    assured: bool = false,
    confirmed: bool = false,
    src_nat: bool = false,
    dst_nat: bool = false,
    seq_adjust: bool = false,
    src_nat_done: bool = false,
    dst_nat_done: bool = false,
    dying: bool = false,
    fixed_timeout: bool = false,
    template: bool = false,
    helper: bool = false,
    offloaded: bool = false,
    hw_offloaded: bool = false,
    _reserved: u17 = 0,
};

pub const NfConntrackL4Proto = enum(u8) {
    Tcp = 6,
    Udp = 17,
    Udplite = 136,
    Icmp = 1,
    Icmpv6 = 58,
    Dccp = 33,
    Sctp = 132,
    Gre = 47,
};

pub const NfConntrackTuple = struct {
    src: NfConntrackTupleSrc,
    dst: NfConntrackTupleDst,
};

pub const NfConntrackTupleSrc = struct {
    ip: u32,        // IPv4 or lower 32 of v6
    ipv6: [16]u8,   // full IPv6
    l4proto: NfConntrackL4Proto,
    port: u16,
    icmp_id: u16,
};

pub const NfConntrackTupleDst = struct {
    ip: u32,
    ipv6: [16]u8,
    l4proto: NfConntrackL4Proto,
    port: u16,
    icmp_type: u8,
    icmp_code: u8,
    protonum: u8,
    dir: u8,
};

pub const NfConn = struct {
    ct_net: ?*anyopaque,
    tuplehash: [2]NfConntrackTupleHash,
    status: NfConntrackStatus,
    timeout: u32,
    mark: u32,
    secmark: u32,
    zone: NfConntrackZone,
    master: ?*NfConn,
    nat: ?*NfConnNat,
    ext: ?*anyopaque,
    ct_general: NfConnCounters,
    proto: NfConnProto,
};

pub const NfConntrackTupleHash = struct {
    hnnode: HashListNode,
    tuple: NfConntrackTuple,
};

pub const NfConntrackZone = struct {
    id: u16,
    flags: u8,
    dir: u8,
};

pub const NfConnNat = struct {
    nat_type: NatType,
    manip_src: NatRange2,
    manip_dst: NatRange2,
};

pub const NatType = enum(u8) {
    None = 0,
    Snat = 1,
    Dnat = 2,
    Masquerade = 3,
    Redirect = 4,
};

pub const NatRange2 = struct {
    flags: NatRangeFlags,
    min_ip: u32,
    max_ip: u32,
    min_port: u16,
    max_port: u16,
    base_port: u16,
};

pub const NatRangeFlags = packed struct(u32) {
    map_ips: bool = false,
    proto_specified: bool = false,
    proto_random: bool = false,
    persistent: bool = false,
    proto_random_fully: bool = false,
    proto_offset: bool = false,
    netmap: bool = false,
    _reserved: u25 = 0,
};

pub const NfConnCounters = struct {
    bytes: [2]u64,     // original / reply
    packets: [2]u64,
};

pub const NfConnProto = union {
    tcp: NfConnTcpState,
    udp: NfConnUdpState,
    sctp: NfConnSctpState,
    dccp: NfConnDccpState,
    gre: NfConnGreState,
};

pub const NfConnTcpState = struct {
    state: TcpConntrackState,
    last_dir: u8,
    retrans: u8,
    last_index: u8,
    last_seq: u32,
    last_ack: u32,
    last_end: u32,
    last_win: u16,
    last_wscale: u8,
    last_flags: u16,
    seen: [2]TcpConntrackSeen,
};

pub const TcpConntrackState = enum(u8) {
    None = 0,
    SynSent = 1,
    SynRecv = 2,
    Established = 3,
    FinWait = 4,
    CloseWait = 5,
    LastAck = 6,
    TimeWait = 7,
    Close = 8,
    SynSent2 = 9,
    Max = 10,
};

pub const TcpConntrackSeen = struct {
    td_end: u32,
    td_maxend: u32,
    td_maxwin: u32,
    td_maxack: u32,
    flags: u16,
    td_scale: u8,
};

pub const NfConnUdpState = struct {
    stream_timeout: u32,
};

pub const NfConnSctpState = struct {
    state: u8,
    vtag: [2]u32,
};

pub const NfConnDccpState = struct {
    state: u8,
    role: u8,
    handshake_seq: u64,
};

pub const NfConnGreState = struct {
    stream_timeout: u32,
    timeout: u32,
    keymap_list: ListHead,
};

// ============================================================================
// nf_tables (nftables)
// ============================================================================

pub const NftObjType = enum(u32) {
    Counter = 0,
    Quota = 1,
    CtHelper = 2,
    Limit = 3,
    ConnLimit = 4,
    Tunnel = 5,
    CtTimeout = 6,
    Secmark = 7,
    CtExpect = 8,
    Synproxy = 9,
};

pub const NftChainType = enum(u8) {
    Filter = 0,
    Route = 1,
    Nat = 2,
};

pub const NftChainPolicy = enum(u8) {
    Accept = 0,
    Drop = 1,
};

pub const NftChainFlags = packed struct(u32) {
    base: bool = false,
    hw_offload: bool = false,
    binding: bool = false,
    _reserved: u29 = 0,
};

pub const NftChain = struct {
    rules: ListHead,
    table: ?*NftTable,
    name: [64]u8,
    handle: u64,
    use_count: u32,
    flags: NftChainFlags,
    chain_type: NftChainType,
    policy: NftChainPolicy,
    hook: NfHookNum,
    priority: i32,
};

pub const NftTable = struct {
    chains: ListHead,
    sets: ListHead,
    objects: ListHead,
    flowtables: ListHead,
    name: [64]u8,
    handle: u64,
    family: NfProtoFamily,
    flags: u32,
    use_count: u32,
    nlpid: u32,
};

pub const NftRuleExprType = enum(u8) {
    Immediate = 0,
    Cmp = 1,
    Lookup = 2,
    Bitwise = 3,
    Byteorder = 4,
    Payload = 5,
    Meta = 6,
    Ct = 7,
    Log = 8,
    Limit = 9,
    Counter = 10,
    Nat = 11,
    Reject = 12,
    Queue = 13,
    Masq = 14,
    Redir = 15,
    Dup = 16,
    Fwd = 17,
    Objref = 18,
    Map = 19,
    Range = 20,
    Connlimit = 21,
    Tunnel = 22,
    Quota = 23,
    Synproxy = 24,
    Hash = 25,
    Rt = 26,
    Socket = 27,
    Osf = 28,
    Xfrm = 29,
    Tproxy = 30,
    FlowOffload = 31,
    Numgen = 32,
    Last = 33,
};

pub const NftSetType = enum(u8) {
    Hash = 0,
    Rbtree = 1,
    Bitmap = 2,
    Concatenation = 3,
    PipahashFast = 4,
};

// ============================================================================
// iptables (legacy but still used)
// ============================================================================

pub const IptEntry = struct {
    ip: IptIp,
    nfcache: u32,
    target_offset: u16,
    next_offset: u16,
    comefrom: u32,
    counters: XtCounters,
};

pub const IptIp = struct {
    src: u32,
    dst: u32,
    smsk: u32,
    dmsk: u32,
    iniface: [16]u8,
    outiface: [16]u8,
    iniface_mask: [16]u8,
    outiface_mask: [16]u8,
    proto: u16,
    flags: u8,
    invflags: u8,
};

pub const XtCounters = struct {
    pcnt: u64,
    bcnt: u64,
};

pub const IptStandardTarget = enum(i32) {
    Accept = -1,
    Drop = -2,
    Return = -3,
    Queue = -4,
};

// ============================================================================
// Common iptables/nftables match extensions
// ============================================================================

pub const MatchExtType = enum(u8) {
    Tcp = 0,
    Udp = 1,
    Icmp = 2,
    Mark = 3,
    Conntrack = 4,
    State = 5,
    Mac = 6,
    Limit = 7,
    Multiport = 8,
    IpRange = 9,
    Owner = 10,
    Tos = 11,
    Time = 12,
    Addrtype = 13,
    Hashlimit = 14,
    String = 15,
    Comment = 16,
    Connmark = 17,
    Dscp = 18,
    Ecn = 19,
    Helper = 20,
    Length = 21,
    Physdev = 22,
    Pkttype = 23,
    Policy = 24,
    Realm = 25,
    Sctp = 26,
    Statistic = 27,
    Tcpmss = 28,
    Ttl = 29,
    U32 = 30,
    Cgroup = 31,
    Bpf = 32,
    Nfacct = 33,
    Rpfilter = 34,
    Cpu = 35,
    DevGroup = 36,
    Socket = 37,
    Cluster = 38,
    Connbytes = 39,
    Connlabel = 40,
};

pub const TargetExtType = enum(u8) {
    Accept = 0,
    Drop = 1,
    Return = 2,
    Log = 3,
    Reject = 4,
    Snat = 5,
    Dnat = 6,
    Masquerade = 7,
    Redirect = 8,
    Mark = 9,
    Connmark = 10,
    TcpMss = 11,
    Tos = 12,
    Ttl = 13,
    Classify = 14,
    Checksum = 15,
    Dscp = 16,
    Ecn = 17,
    Idletimer = 18,
    Led = 19,
    Nflog = 20,
    Nfqueue = 21,
    Notrack = 22,
    RateEst = 23,
    Tproxy = 24,
    Audit = 25,
    Ct = 26,
    Hmark = 27,
    SecMark = 28,
    Synproxy = 29,
    Netmap = 30,
    Trace = 31,
};

// ============================================================================
// Conntrack Helpers
// ============================================================================

pub const NfCtHelperType = enum(u8) {
    Ftp = 0,
    Tftp = 1,
    Irc = 2,
    Sip = 3,
    H323 = 4,
    Amanda = 5,
    Pptp = 6,
    Snmp = 7,
    SaneTcp = 8,
    Netbios = 9,
};

pub const NfConnExpectation = struct {
    tuple: NfConntrackTuple,
    mask: NfConntrackTuple,
    master: ?*NfConn,
    dir: u8,
    class: u8,
    flags: u32,
    helper: NfCtHelperType,
};

// ============================================================================
// Flow Offload
// ============================================================================

pub const NfFlowState = enum(u8) {
    New = 0,
    Established = 1,
    TearDown = 2,
};

pub const NfFlowEntry = struct {
    tuplehash: [2]NfConntrackTupleHash,
    flags: u32,
    state: NfFlowState,
    timeout: u32,
    stats: NfFlowStats,
};

pub const NfFlowStats = struct {
    pkts: u64,
    bytes: u64,
    last_used: u64,
};

// ============================================================================
// Helper types
// ============================================================================

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,
};

pub const HashListNode = struct {
    next: ?*HashListNode,
    pprev: ?*?*HashListNode,
};

// ============================================================================
// Netfilter Manager
// ============================================================================

pub const NetfilterManager = struct {
    nf_conntrack_max: u32,
    nf_conntrack_count: u32,
    nf_conntrack_hash_size: u32,
    nf_conntrack_buckets: u32,
    nft_tables: u32,
    nft_chains: u32,
    nft_rules: u32,
    nft_sets: u32,
    nft_objects: u32,
    nat_entries: u32,
    total_packets_filtered: u64,
    total_packets_dropped: u64,
    total_packets_accepted: u64,
    total_conntrack_inserts: u64,
    total_conntrack_deletes: u64,
    total_conntrack_early_drops: u64,
    flow_offload_count: u32,
    helpers_registered: u32,
    expectations: u32,
    initialized: bool,

    pub fn init() NetfilterManager {
        return .{
            .nf_conntrack_max = 262144,
            .nf_conntrack_count = 0,
            .nf_conntrack_hash_size = 65536,
            .nf_conntrack_buckets = 65536,
            .nft_tables = 0,
            .nft_chains = 0,
            .nft_rules = 0,
            .nft_sets = 0,
            .nft_objects = 0,
            .nat_entries = 0,
            .total_packets_filtered = 0,
            .total_packets_dropped = 0,
            .total_packets_accepted = 0,
            .total_conntrack_inserts = 0,
            .total_conntrack_deletes = 0,
            .total_conntrack_early_drops = 0,
            .flow_offload_count = 0,
            .helpers_registered = 0,
            .expectations = 0,
            .initialized = true,
        };
    }
};
