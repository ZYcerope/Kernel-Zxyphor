// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Raw Socket, Packet Socket & TIPC
// Raw sockets (IPPROTO_RAW), packet sockets (AF_PACKET),
// TIPC (Transparent Inter-Process Communication),
// Packet MMAP ring buffers, fanout

const std = @import("std");

// ============================================================================
// Raw Socket
// ============================================================================

pub const RawSocketType = enum(u8) {
    IpRaw = 0,          // SOCK_RAW + IPPROTO_RAW
    Icmp = 1,           // SOCK_RAW + IPPROTO_ICMP
    Icmpv6 = 2,         // SOCK_RAW + IPPROTO_ICMPV6
    Custom = 3,          // Any protocol number
};

pub const RawSockFlags = packed struct(u32) {
    hdrincl: bool,       // IP_HDRINCL - user provides IP header
    checksum: bool,
    no_check_sum: bool,
    broadcast: bool,
    multicast_loop: bool,
    multicast_ttl: bool,
    recvtos: bool,
    recvttl: bool,
    recvopts: bool,
    recvorigdstaddr: bool,
    pktinfo: bool,
    _reserved: u21,
};

pub const RawSocketOpt = enum(u32) {
    IpHdrincl = 3,       // IP_HDRINCL
    IpTos = 1,
    IpTtl = 2,
    IpOptions = 4,
    IpRecvTos = 13,
    IpRecvTtl = 12,
    IpRecvOpts = 6,
    IpPktinfo = 8,
    IpRecvOrigDstaddr = 20,
    IpRecverr = 11,
    IpMulticastTtl = 33,
    IpMulticastLoop = 34,
    IpAddMembership = 35,
    IpDropMembership = 36,
    IpMulticastIf = 32,
    IpFreebind = 15,
    IpTransparent = 19,
    IpBindAddressNoPort = 24,
};

pub const IcmpFilter = struct {
    data: u32,             // Bitmask of ICMP types to reject
};

// ============================================================================
// Packet Socket (AF_PACKET)
// ============================================================================

pub const PacketSocketType = enum(u16) {
    PacketHost = 0,
    PacketBroadcast = 1,
    PacketMulticast = 2,
    PacketOtherhost = 3,
    PacketOutgoing = 4,
    PacketLoopback = 5,
    PacketUser = 6,
    PacketKernel = 7,
};

pub const PacketVersion = enum(u32) {
    TpacketV1 = 0,
    TpacketV2 = 1,
    TpacketV3 = 2,
};

pub const SocklinkAddr = struct {
    sll_family: u16,       // AF_PACKET
    sll_protocol: u16,     // Physical-layer protocol (ETH_P_*)
    sll_ifindex: i32,
    sll_hatype: u16,       // ARP hardware type
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,       // Physical-layer address
};

pub const EthProto = enum(u16) {
    ETH_P_LOOP = 0x0060,
    ETH_P_PUP = 0x0200,
    ETH_P_PUPAT = 0x0201,
    ETH_P_TSN = 0x22F0,
    ETH_P_ERSPAN2 = 0x22EB,
    ETH_P_IP = 0x0800,
    ETH_P_X25 = 0x0805,
    ETH_P_ARP = 0x0806,
    ETH_P_BPQ = 0x08FF,
    ETH_P_IEEEPUP = 0x0A00,
    ETH_P_IEEEPUPAT = 0x0A01,
    ETH_P_DEC = 0x6000,
    ETH_P_DNA_DL = 0x6001,
    ETH_P_DNA_RC = 0x6002,
    ETH_P_DNA_RT = 0x6003,
    ETH_P_LAT = 0x6004,
    ETH_P_DIAG = 0x6005,
    ETH_P_CUST = 0x6006,
    ETH_P_SCA = 0x6007,
    ETH_P_TEB = 0x6558,
    ETH_P_RARP = 0x8035,
    ETH_P_ATALK = 0x809B,
    ETH_P_AARP = 0x80F3,
    ETH_P_8021Q = 0x8100,
    ETH_P_IPX = 0x8137,
    ETH_P_IPV6 = 0x86DD,
    ETH_P_PAUSE = 0x8808,
    ETH_P_SLOW = 0x8809,
    ETH_P_WCCP = 0x883E,
    ETH_P_MPLS_UC = 0x8847,
    ETH_P_MPLS_MC = 0x8848,
    ETH_P_ATMMPOA = 0x884C,
    ETH_P_PPP_DISC = 0x8863,
    ETH_P_PPP_SES = 0x8864,
    ETH_P_LINK_CTL = 0x886C,
    ETH_P_ATMFATE = 0x8884,
    ETH_P_PAE = 0x888E,
    ETH_P_PROFINET = 0x8892,
    ETH_P_REALTEK = 0x8899,
    ETH_P_AOE = 0x88A2,
    ETH_P_ETHERCAT = 0x88A4,
    ETH_P_8021AD = 0x88A8,
    ETH_P_802_EX1 = 0x88B5,
    ETH_P_PREAUTH = 0x88C7,
    ETH_P_TIPC = 0x88CA,
    ETH_P_LLDP = 0x88CC,
    ETH_P_MRP = 0x88E3,
    ETH_P_MACSEC = 0x88E5,
    ETH_P_8021AH = 0x88E7,
    ETH_P_MVRP = 0x88F5,
    ETH_P_1588 = 0x88F7,
    ETH_P_NCSI = 0x88F8,
    ETH_P_PRP = 0x88FB,
    ETH_P_CFM = 0x8902,
    ETH_P_FCOE = 0x8906,
    ETH_P_TDLS = 0x890D,
    ETH_P_FIP = 0x8914,
    ETH_P_IBOE = 0x8915,
    ETH_P_80221 = 0x8917,
    ETH_P_HSR = 0x892F,
    ETH_P_NSH = 0x894F,
    ETH_P_LOOPBACK = 0x9000,
    ETH_P_QINQ1 = 0x9100,
    ETH_P_QINQ2 = 0x9200,
    ETH_P_QINQ3 = 0x9300,
    ETH_P_EDSA = 0xDADA,
    ETH_P_DSA_8021Q = 0xDADB,
    ETH_P_DSA_A5PSW = 0xE001,
    ETH_P_IFE = 0xED3E,
    ETH_P_AF_IUCV = 0xFBFB,
    ETH_P_802_3_MIN = 0x0600,
    ETH_P_ALL = 0x0003,
    ETH_P_802_3 = 0x0001,
    ETH_P_802_2 = 0x0004,
};

// ============================================================================
// Packet MMAP Ring Buffer (TPACKET)
// ============================================================================

pub const TpacketReq = struct {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
};

pub const TpacketReq3 = struct {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,    // Block retire timeout (ms)
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
};

pub const TpacketHdrV1 = struct {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_usec: u32,
};

pub const TpacketHdr3 = struct {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [4]u8,
};

pub const TpacketStatus = packed struct(u32) {
    kernel: bool,          // TP_STATUS_KERNEL
    user: bool,            // TP_STATUS_USER
    copy: bool,            // TP_STATUS_COPY
    losing: bool,          // TP_STATUS_LOSING
    csumnotready: bool,    // TP_STATUS_CSUMNOTREADY
    vlan_valid: bool,
    blk_tmout: bool,
    vlan_tpid_valid: bool,
    csum_valid: bool,
    _reserved: u23,
};

// ============================================================================
// Packet FANOUT
// ============================================================================

pub const PacketFanoutType = enum(u16) {
    Hash = 0,
    Lb = 1,
    Cpu = 2,
    Rollover = 3,
    Rnd = 4,
    Qm = 5,
    Cbpf = 6,
    Ebpf = 7,
};

pub const PacketFanoutFlags = packed struct(u16) {
    defrag: bool,
    rollover: bool,
    uniqueid: bool,
    _reserved: u13,
};

pub const PacketFanout = struct {
    fanout_type: PacketFanoutType,
    flags: PacketFanoutFlags,
    id: u16,
    num_members: u16,
    max_num_members: u16,
    prot_hook: usize,
};

// ============================================================================
// TIPC (Transparent Inter-Process Communication)
// ============================================================================

pub const TipcAddrType = enum(u8) {
    NameSeq = 1,         // {type, lower, upper}
    Name = 2,            // {type, instance}
    Id = 3,              // {node, ref}
};

pub const TipcAddr = struct {
    family: u16,          // AF_TIPC
    addrtype: TipcAddrType,
    scope: TipcScope,
    addr: TipcAddrUnion,
};

pub const TipcAddrUnion = struct {
    // Name/NameSeq
    name_type: u32,
    name_instance: u32,
    name_domain: u32,
    // Id
    id_node: u32,
    id_ref: u32,
};

pub const TipcScope = enum(u8) {
    Zone = 1,
    Cluster = 2,
    Node = 3,
};

pub const TipcMsgType = enum(u8) {
    LowImportance = 0,
    MediumImportance = 1,
    HighImportance = 2,
    CriticalImportance = 3,
    ConnMsg = 4,
    DirectMsg = 5,
    NamedMsg = 6,
    MulticastMsg = 7,
};

pub const TipcSocketType = enum(u8) {
    SockStream = 1,      // Reliable stream
    SockSeqpacket = 2,   // Reliable sequenced
    SockDgram = 3,       // Unreliable datagram
    SockRdm = 4,         // Reliable datagram
};

pub const TipcNodeId = struct {
    node_addr: u32,       // <zone.cluster.node>
    node_id: [16]u8,      // 128-bit node identity
    hash: u32,
};

pub const TipcLinkState = enum(u8) {
    Idle = 0,
    Establishing = 1,
    Established = 2,
    Resetting = 3,
    PeerReset = 4,
};

pub const TipcLink = struct {
    name: [68]u8,         // <self_z.c.n:peer_z.c.n>
    peer_node: u32,
    self_node: u32,
    state: TipcLinkState,
    session: u16,
    peer_session: u16,
    priority: u32,
    tolerance: u32,       // Link tolerance (ms)
    window: u32,          // Transmit window
    backlog_limit: u32,
    snd_nxt: u16,
    rcv_nxt: u16,
    stats: TipcLinkStats,
};

pub const TipcLinkStats = struct {
    sent_pkts: u64,
    recv_pkts: u64,
    sent_nacks: u64,
    recv_nacks: u64,
    sent_acks: u64,
    recv_acks: u64,
    retransmitted: u64,
    duplicates: u64,
    link_congs: u64,
    max_queue_sz: u32,
    accu_queue_sz: u64,
    queue_sz_counts: u32,
    msg_lengths_total: u64,
    msg_length_counts: u32,
    msg_length_profile: [7]u32, // Distribution buckets
};

pub const TipcGroupMember = struct {
    node: u32,
    port: u32,
    instance: u32,
    scope: TipcScope,
    state: TipcGroupState,
};

pub const TipcGroupState = enum(u8) {
    Joined = 0,
    Leaving = 1,
    Lost = 2,
};

pub const TipcBearerType = enum(u8) {
    Udp = 0,
    Eth = 1,
    Ib = 2,             // InfiniBand
};

pub const TipcBearer = struct {
    name: [32]u8,
    bearer_type: TipcBearerType,
    identity: u32,
    priority: u32,
    window: u32,
    tolerance: u32,
    domain: u32,
    mtu: u32,
    blocked: bool,
};

pub const TipcMediaAddr = struct {
    media_id: u8,
    broadcast: bool,
    value: [20]u8,
};

pub const TipcMon = struct {
    dom_member_cnt: u32,
    gen: u32,
    peer_cnt: u32,
    up_cnt: u32,
};

// ============================================================================
// Netlink Socket (detail for raw/packet interaction)
// ============================================================================

pub const NetlinkSockType = enum(u32) {
    NETLINK_ROUTE = 0,
    NETLINK_UNUSED = 1,
    NETLINK_USERSOCK = 2,
    NETLINK_FIREWALL = 3,
    NETLINK_SOCK_DIAG = 4,
    NETLINK_NFLOG = 5,
    NETLINK_XFRM = 6,
    NETLINK_SELINUX = 7,
    NETLINK_ISCSI = 8,
    NETLINK_AUDIT = 9,
    NETLINK_FIB_LOOKUP = 10,
    NETLINK_CONNECTOR = 11,
    NETLINK_NETFILTER = 12,
    NETLINK_IP6_FW = 13,
    NETLINK_DNRTMSG = 14,
    NETLINK_KOBJECT_UEVENT = 15,
    NETLINK_GENERIC = 16,
    NETLINK_SCSITRANSPORT = 18,
    NETLINK_ECRYPTFS = 19,
    NETLINK_RDMA = 20,
    NETLINK_CRYPTO = 21,
    NETLINK_SMC = 22,
};

pub const NlmsghdrFlags = packed struct(u16) {
    request: bool,         // NLM_F_REQUEST
    multi: bool,           // NLM_F_MULTI
    ack: bool,             // NLM_F_ACK
    echo: bool,            // NLM_F_ECHO
    dump_intr: bool,
    dump_filtered: bool,
    // GET
    root: bool,
    match_flag: bool,
    atomic: bool,
    // NEW
    replace: bool,
    excl: bool,
    create: bool,
    append: bool,
    _reserved: u3,
};

// ============================================================================
// Manager
// ============================================================================

pub const RawPacketTipcManager = struct {
    total_raw_sockets: u32,
    total_packet_sockets: u32,
    total_tipc_sockets: u32,
    total_tipc_links: u32,
    total_tipc_bearers: u32,
    total_raw_sent: u64,
    total_raw_recv: u64,
    total_packet_sent: u64,
    total_packet_recv: u64,
    total_tipc_sent: u64,
    total_tipc_recv: u64,
    total_fanout_groups: u32,
    total_mmap_rings: u32,
    initialized: bool,

    pub fn init() RawPacketTipcManager {
        return .{
            .total_raw_sockets = 0,
            .total_packet_sockets = 0,
            .total_tipc_sockets = 0,
            .total_tipc_links = 0,
            .total_tipc_bearers = 0,
            .total_raw_sent = 0,
            .total_raw_recv = 0,
            .total_packet_sent = 0,
            .total_packet_recv = 0,
            .total_tipc_sent = 0,
            .total_tipc_recv = 0,
            .total_fanout_groups = 0,
            .total_mmap_rings = 0,
            .initialized = true,
        };
    }
};
