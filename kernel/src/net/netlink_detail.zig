// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Netlink Protocol Detail & Generic Netlink
// Complete: netlink message format, routing netlink, generic netlink families,
// multicast groups, netlink policies, dumpit/doit callbacks, netlink sockets

const std = @import("std");

// ============================================================================
// Netlink Message Format
// ============================================================================

pub const NlmsghdrStruct = packed struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
};

pub const NlmsgType = enum(u16) {
    Noop = 0x1,
    Error = 0x2,
    Done = 0x3,
    Overrun = 0x4,
    // rtnetlink types
    NewLink = 16,
    DelLink = 17,
    GetLink = 18,
    SetLink = 19,
    NewAddr = 20,
    DelAddr = 21,
    GetAddr = 22,
    NewRoute = 24,
    DelRoute = 25,
    GetRoute = 26,
    NewNeigh = 28,
    DelNeigh = 29,
    GetNeigh = 30,
    NewRule = 32,
    DelRule = 33,
    GetRule = 34,
    NewQdisc = 36,
    DelQdisc = 37,
    GetQdisc = 38,
    NewTclass = 40,
    DelTclass = 41,
    GetTclass = 42,
    NewTfilter = 44,
    DelTfilter = 45,
    GetTfilter = 46,
    NewAction = 48,
    DelAction = 49,
    GetAction = 50,
    NewPrefix = 52,
    GetMulticast = 58,
    GetAnycast = 62,
    NewNeightbl = 64,
    GetNeightbl = 66,
    SetNeightbl = 67,
    NewNdUserOpt = 68,
    NewAddrlabel = 72,
    DelAddrlabel = 73,
    GetAddrlabel = 74,
    GetDcb = 78,
    SetDcb = 79,
    NewNetconf = 80,
    DelNetconf = 81,
    GetNetconf = 82,
    NewMdb = 84,
    DelMdb = 85,
    GetMdb = 86,
    NewNsid = 88,
    DelNsid = 89,
    GetNsid = 90,
    NewStats = 92,
    GetStats = 94,
    DelStats = 95,
    NewChain = 100,
    DelChain = 101,
    GetChain = 102,
    NewNexthop = 104,
    DelNexthop = 105,
    GetNexthop = 106,
    NewLinkprop = 108,
    DelLinkprop = 109,
    GetLinkprop = 110,
    NewVlan = 112,
    DelVlan = 113,
    GetVlan = 114,
    NewNexthopBucket = 116,
    DelNexthopBucket = 117,
    GetNexthopBucket = 118,
    NewTunnel = 120,
    DelTunnel = 121,
    GetTunnel = 122,
};

pub const NlmsgFlags = packed struct(u16) {
    request: bool,       // NLM_F_REQUEST
    multi: bool,         // NLM_F_MULTI
    ack: bool,           // NLM_F_ACK
    echo: bool,          // NLM_F_ECHO
    dump_intr: bool,     // NLM_F_DUMP_INTR
    dump_filtered: bool, // NLM_F_DUMP_FILTERED
    // GET flags
    root: bool,          // NLM_F_ROOT
    match_flag: bool,    // NLM_F_MATCH
    atomic: bool,        // NLM_F_ATOMIC
    // NEW flags
    replace: bool,       // NLM_F_REPLACE
    excl: bool,          // NLM_F_EXCL
    create: bool,        // NLM_F_CREATE
    append: bool,        // NLM_F_APPEND
    // Modifying flags
    no_recurse: bool,    // NLM_F_NONREC
    bulk: bool,          // NLM_F_BULK
    capped: bool,        // NLM_F_CAPPED
};

pub const NlAttr = packed struct {
    nla_len: u16,
    nla_type: u16,
    // Payload follows
};

pub const NlAttrType = packed struct(u16) {
    attr_type: u14,
    net_byteorder: bool,
    nested: bool,
};

pub const NlErr = packed struct {
    error_code: i32,
    msg: NlmsghdrStruct,
};

// ============================================================================
// Netlink Protocols
// ============================================================================

pub const NetlinkProtocol = enum(u8) {
    Route = 0,           // NETLINK_ROUTE
    Unused = 1,
    Usersock = 2,
    Firewall = 3,
    SockDiag = 4,
    Nflog = 5,
    Xfrm = 6,
    Selinux = 7,
    Iscsi = 8,
    Audit = 9,
    FibLookup = 10,
    Connector = 11,
    Netfilter = 12,
    Ip6Fw = 13,
    DnrtMsg = 14,
    KobjUevent = 15,
    Generic = 16,
    SCSITransport = 18,
    Ecryptfs = 19,
    Rdma = 20,
    Crypto = 21,
    Smc = 22,
};

// ============================================================================
// Generic Netlink
// ============================================================================

pub const GenlmsghdrStruct = packed struct {
    cmd: u8,
    version: u8,
    reserved: u16,
};

pub const GenlFamily = struct {
    id: u16,
    hdrsize: u32,
    name: [16]u8,
    version: u32,
    maxattr: u32,
    module: ?*anyopaque,
    ops: [32]GenlOps,
    n_ops: u8,
    small_ops: [16]GenlSmallOps,
    n_small_ops: u8,
    split_ops: [16]GenlSplitOps,
    n_split_ops: u8,
    mcgrps: [8]GenlMulticastGroup,
    n_mcgrps: u8,
    resv_start_op: u32,
    policy: [64]NlaPolicy,
    parallel_ops: bool,
    netnsok: bool,
    pre_doit: ?*const fn (ops: *const GenlOps, skb: *anyopaque, info: *GenlInfo) callconv(.C) i32,
    post_doit: ?*const fn (ops: *const GenlOps, skb: *anyopaque, info: *GenlInfo) callconv(.C) void,
    sock_priv_size: u32,
    sock_priv_init: ?*const fn (priv: *anyopaque) callconv(.C) void,
    sock_priv_destroy: ?*const fn (priv: *anyopaque) callconv(.C) void,
};

pub const GenlOps = struct {
    cmd: u8,
    internal_flags: u8,
    flags: GenlOpsFlags,
    policy: ?[*]const NlaPolicy,
    maxattr: u32,
    doit: ?*const fn (skb: *anyopaque, info: *GenlInfo) callconv(.C) i32,
    start: ?*const fn (cb: *NetlinkCallback) callconv(.C) i32,
    dumpit: ?*const fn (skb: *anyopaque, cb: *NetlinkCallback) callconv(.C) i32,
    done: ?*const fn (cb: *NetlinkCallback) callconv(.C) i32,
    validate: u32,
};

pub const GenlSmallOps = struct {
    cmd: u8,
    internal_flags: u8,
    flags: GenlOpsFlags,
    validate: u32,
    doit: ?*const fn (skb: *anyopaque, info: *GenlInfo) callconv(.C) i32,
    dumpit: ?*const fn (skb: *anyopaque, cb: *NetlinkCallback) callconv(.C) i32,
};

pub const GenlSplitOps = struct {
    cmd: u8,
    internal_flags: u8,
    flags: GenlOpsFlags,
    validate: u32,
    policy: ?[*]const NlaPolicy,
    maxattr: u32,
    doit: ?*const fn (skb: *anyopaque, info: *GenlInfo) callconv(.C) i32,
    start: ?*const fn (cb: *NetlinkCallback) callconv(.C) i32,
    dumpit: ?*const fn (skb: *anyopaque, cb: *NetlinkCallback) callconv(.C) i32,
    done: ?*const fn (cb: *NetlinkCallback) callconv(.C) i32,
};

pub const GenlOpsFlags = packed struct(u32) {
    admin_perm: bool,
    cmd_cap_do: bool,
    cmd_cap_dump: bool,
    cmd_cap_haspol: bool,
    uns_admin_perm: bool,
    _reserved: u27,
};

pub const GenlMulticastGroup = struct {
    name: [16]u8,
    flags: u8,
    cap_sys_admin: bool,
};

pub const GenlInfo = struct {
    snd_seq: u32,
    snd_portid: u32,
    genlhdr: ?*GenlmsghdrStruct,
    userhdr: ?*anyopaque,
    attrs: [64]?*NlAttr,
    family: ?*GenlFamily,
    nlhdr: ?*NlmsghdrStruct,
    extack: ?*NlExtAck,
    ctx: ?*anyopaque,
};

// ============================================================================
// Netlink Policy (NLA validation)
// ============================================================================

pub const NlaPolicyType = enum(u8) {
    Unspec = 0,
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    S8 = 5,
    S16 = 6,
    S32 = 7,
    S64 = 8,
    String = 9,
    Flag = 10,
    Msecs = 11,
    Nested = 12,
    NestedArray = 13,
    Binary = 14,
    Sint = 15,
    Uint = 16,
    Be16 = 17,
    Be32 = 18,
    Bitfield32 = 19,
    Reject = 20,
};

pub const NlaPolicy = struct {
    policy_type: NlaPolicyType,
    len: u16,
    min: i64,
    max: i64,
    nested_policy: ?[*]const NlaPolicy,
    nested_maxattr: u32,
    validate: NlaPolicyValidation,
    strict_start_type: u16,
};

pub const NlaPolicyValidation = packed struct(u32) {
    range: bool,
    range_warn_only: bool,
    min_len: bool,
    max_len: bool,
    mask: bool,
    _reserved: u27,
};

// ============================================================================
// Netlink Callback & Dumpit
// ============================================================================

pub const NetlinkCallback = struct {
    nlh: ?*NlmsghdrStruct,
    dump: ?*const fn (skb: *anyopaque, cb: *NetlinkCallback) callconv(.C) i32,
    done: ?*const fn (cb: *NetlinkCallback) callconv(.C) i32,
    data: ?*anyopaque,
    module: ?*anyopaque,
    family: u16,
    min_dump_alloc: u16,
    strict_check: bool,
    answer_flags: u16,
    extack: ?*NlExtAck,
    args: [6]u64,     // cb->args[0..5]
};

pub const NlExtAck = struct {
    msg: [256]u8,
    msg_len: u32,
    bad_attr: ?*NlAttr,
    policy: ?*const NlaPolicy,
    cookie: [20]u8,
    cookie_len: u8,
    miss_type: u32,
    miss_nest: ?*NlAttr,
};

// ============================================================================
// Netlink Socket
// ============================================================================

pub const NetlinkSock = struct {
    sk: ?*anyopaque,     // struct sock
    portid: u32,
    dst_portid: u32,
    dst_group: u32,
    flags: u32,
    subscriptions: u32,
    ngroups: u32,
    groups: [32]u32,     // Multicast group subscriptions
    state: NetlinkSockState,
    max_recvmsg_len: u32,
    cb: ?*NetlinkCallback,
    cb_running: bool,
    bound: bool,
    netlink_rcv: ?*const fn (skb: *anyopaque) callconv(.C) void,
    netlink_bind: ?*const fn (sock: *NetlinkSock, group: u32) callconv(.C) i32,
    netlink_unbind: ?*const fn (sock: *NetlinkSock, group: u32) callconv(.C) void,
    module: ?*anyopaque,
};

pub const NetlinkSockState = packed struct(u32) {
    recv_pktinfo: bool,
    broadcast_error: bool,
    no_enobufs: bool,
    listen_all_nsid: bool,
    cap_ack: bool,
    ext_ack: bool,
    strict_chk: bool,
    _reserved: u25,
};

// ============================================================================
// rtnetlink types
// ============================================================================

pub const IfinfomsgStruct = packed struct {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
};

pub const IfaddrmsgStruct = packed struct {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
};

pub const RtmsgStruct = packed struct {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
};

pub const NdmsgStruct = packed struct {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
};

pub const IflaType = enum(u16) {
    Unspec = 0,
    Address = 1,
    Broadcast = 2,
    Ifname = 3,
    Mtu = 4,
    Link = 5,
    Qdisc = 6,
    Stats = 7,
    Cost = 8,
    Priority = 9,
    Master = 10,
    Wireless = 11,
    Protinfo = 12,
    TxQLen = 13,
    Map = 14,
    Weight = 15,
    Operstate = 16,
    Linkmode = 17,
    Linkinfo = 18,
    NetNsPid = 19,
    Ifalias = 20,
    NumVf = 21,
    VfinfoList = 22,
    Stats64 = 23,
    VfPorts = 24,
    PortSelf = 25,
    AfSpec = 26,
    Group = 27,
    NetNsFd = 28,
    ExtMask = 29,
    Promiscuity = 30,
    NumTxQueues = 31,
    NumRxQueues = 32,
    Carrier = 33,
    PhysPortId = 34,
    CarrierChanges = 35,
    PhysSwithId = 36,
    LinkNetnsid = 37,
    PhysPortName = 38,
    ProtoDown = 39,
    GsoMaxSegs = 40,
    GsoMaxSize = 41,
    Pad = 42,
    Xdp = 43,
    Event = 44,
    NewNetnsid = 45,
    TargetNetnsid = 46,
    CarrierUpCount = 47,
    CarrierDownCount = 48,
    NewIfindex = 49,
    MinMtu = 50,
    MaxMtu = 51,
    PropList = 52,
    AltIfname = 53,
    PermAddress = 54,
    ProtoDownReason = 55,
    ParentDevName = 56,
    ParentDevBusName = 57,
    GroMaxSize = 58,
    TsoMaxSize = 59,
    TsoMaxSegs = 60,
    Allmulti = 61,
    Devlink = 62,
    GsoIpv4MaxSize = 63,
    GroIpv4MaxSize = 64,
};

// ============================================================================
// Netlink Notify / Event
// ============================================================================

pub const NetlinkNotify = struct {
    portid: u32,
    protocol: u8,
};

pub const RtnlLinkOps = struct {
    kind: [16]u8,
    maxtype: u32,
    policy: ?[*]const NlaPolicy,
    priv_size: usize,
    alloc: ?*const fn (tb: [*]?*NlAttr, name: [*:0]const u8, name_assign_type: u8) callconv(.C) ?*anyopaque,
    setup: ?*const fn (dev: *anyopaque) callconv(.C) void,
    validate: ?*const fn (tb: [*]?*NlAttr, data: [*]?*NlAttr, extack: ?*NlExtAck) callconv(.C) i32,
    newlink: ?*const fn (net: *anyopaque, dev: *anyopaque, tb: [*]?*NlAttr, data: [*]?*NlAttr, extack: ?*NlExtAck) callconv(.C) i32,
    changelink: ?*const fn (dev: *anyopaque, tb: [*]?*NlAttr, data: [*]?*NlAttr, extack: ?*NlExtAck) callconv(.C) i32,
    dellink: ?*const fn (dev: *anyopaque, head: *anyopaque) callconv(.C) void,
    get_size: ?*const fn (dev: *anyopaque) callconv(.C) usize,
    fill_info: ?*const fn (skb: *anyopaque, dev: *anyopaque) callconv(.C) i32,
    get_xstats_size: ?*const fn (dev: *anyopaque) callconv(.C) usize,
    fill_xstats: ?*const fn (skb: *anyopaque, dev: *anyopaque) callconv(.C) i32,
    get_num_tx_queues: ?*const fn () callconv(.C) u32,
    get_num_rx_queues: ?*const fn () callconv(.C) u32,
    slave_maxtype: u32,
    slave_policy: ?[*]const NlaPolicy,
    slave_changelink: ?*const fn (dev: *anyopaque, slave: *anyopaque, tb: [*]?*NlAttr, data: [*]?*NlAttr, extack: ?*NlExtAck) callconv(.C) i32,
    get_slave_size: ?*const fn (dev: *anyopaque, slave: *anyopaque) callconv(.C) usize,
    fill_slave_info: ?*const fn (skb: *anyopaque, dev: *anyopaque, slave: *anyopaque) callconv(.C) i32,
    get_link_net: ?*const fn (dev: *anyopaque) callconv(.C) ?*anyopaque,
    get_linkxstats_size: ?*const fn (dev: *anyopaque, attr: i32) callconv(.C) usize,
    fill_linkxstats: ?*const fn (skb: *anyopaque, dev: *anyopaque, prividx: *i32, attr: i32) callconv(.C) i32,
    peer_type: u32,
};

// ============================================================================
// Manager
// ============================================================================

pub const NetlinkManager = struct {
    total_families: u32,
    total_sockets: u32,
    total_messages_sent: u64,
    total_messages_recv: u64,
    total_multicast_sent: u64,
    total_dumps: u64,
    total_errors: u64,
    initialized: bool,

    pub fn init() NetlinkManager {
        return .{
            .total_families = 0,
            .total_sockets = 0,
            .total_messages_sent = 0,
            .total_messages_recv = 0,
            .total_multicast_sent = 0,
            .total_dumps = 0,
            .total_errors = 0,
            .initialized = true,
        };
    }
};
