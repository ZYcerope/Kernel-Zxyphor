// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust Socket Advanced Module
//! TCP/UDP socket internals, socket buffer (sk_buff) detail,
//! protocol family operations, socket options, sendmsg/recvmsg,
//! scatter-gather, zerocopy, cork, sockmap/BPF hooks

#![allow(dead_code)]

// ============================================================================
// Socket State
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Free = 0,
    Unconnected = 1,
    Connecting = 2,
    Connected = 3,
    Disconnecting = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockType {
    Stream = 1,
    Dgram = 2,
    Raw = 3,
    Rdm = 4,
    Seqpacket = 5,
    Dccp = 6,
    Packet = 10,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Unspec = 0,
    Unix = 1,
    Inet = 2,
    Ax25 = 3,
    Ipx = 4,
    Appletalk = 5,
    Netrom = 6,
    Bridge = 7,
    Atmpvc = 8,
    X25 = 9,
    Inet6 = 10,
    Rose = 11,
    Decnet = 12,
    Netbeui = 13,
    Security = 14,
    Key = 15,
    Netlink = 16,
    Packet = 17,
    Econet = 19,
    Atmsvc = 20,
    Rds = 21,
    Irda = 23,
    Pppox = 24,
    Wanpipe = 25,
    Llc = 26,
    Ib = 27,
    Mpls = 28,
    Can = 29,
    Tipc = 30,
    Bluetooth = 31,
    Iucv = 32,
    Rxrpc = 33,
    Isdn = 34,
    Phonet = 35,
    Ieee802154 = 36,
    Caif = 37,
    Alg = 38,
    Nfc = 39,
    Vsock = 40,
    Kcm = 41,
    Qipcrtr = 42,
    Smc = 43,
    Xdp = 44,
    Mctp = 45,
}

// ============================================================================
// Socket Structure
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct Socket {
    pub state: SocketState,
    pub sock_type: SockType,
    pub flags: SocketFlags,
    pub file: u64, // struct file *
    pub sk: u64,   // struct sock *
    pub ops: u64,  // struct proto_ops *
    pub wq: u64,   // socket_wq
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SocketFlags {
    bits: u32,
}

impl SocketFlags {
    pub const ASYNC: u32 = 1 << 0;
    pub const NOSPACE: u32 = 1 << 1;
    pub const PASSCRED: u32 = 1 << 2;
    pub const PASSSEC: u32 = 1 << 3;
    pub const ACCEPTCONN: u32 = 1 << 4;
}

// ============================================================================
// Sock (Protocol-Independent Socket)
// ============================================================================

#[repr(C)]
pub struct Sock {
    // Common
    pub sk_family: u16,
    pub sk_type: u16,
    pub sk_protocol: u16,
    pub sk_state: u8,
    pub sk_reuse: u8,
    pub sk_reuseport: u8,
    pub sk_bound_dev_if: i32,
    // Addressing
    pub sk_rcv_saddr: u32,
    pub sk_daddr: u32,
    pub sk_dport: u16,
    pub sk_num: u16,
    // Buffer sizes
    pub sk_sndbuf: i32,
    pub sk_rcvbuf: i32,
    pub sk_wmem_queued: i32,
    pub sk_rmem_alloc: i32,
    pub sk_wmem_alloc: i32,
    pub sk_fwd_alloc: i32,
    pub sk_tsq_flags: u32,
    // Timestamps
    pub sk_stamp: i64,
    // Socket options
    pub sk_no_check_tx: bool,
    pub sk_no_check_rx: bool,
    pub sk_userlocks: u8,
    pub sk_mark: u32,
    pub sk_priority: u32,
    pub sk_rcvlowat: i32,
    // Timeouts
    pub sk_rcvtimeo: i64,
    pub sk_sndtimeo: i64,
    pub sk_lingertime: i64,
    // Errors
    pub sk_err: i32,
    pub sk_err_soft: i32,
    // Shutdown
    pub sk_shutdown: u8,
    // Flags
    pub sk_flags: SockFlags,
    // Allocation mask
    pub sk_allocation: u32,
    // Route cached
    pub sk_dst_cache: u64,
    // Security
    pub sk_security: u64,
    // Callbacks
    pub sk_state_change: u64,
    pub sk_data_ready: u64,
    pub sk_write_space: u64,
    pub sk_error_report: u64,
    pub sk_backlog_rcv: u64,
    pub sk_destruct: u64,
    // Cgroup / BPF
    pub sk_cgrp_data: SockCgroupData,
    // Memcg
    pub sk_memcg: u64,
    // Accounting
    pub sk_drops: u64,
    pub sk_ack_backlog: u32,
    pub sk_max_ack_backlog: u32,
    // Network namespace
    pub sk_net: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SockFlags {
    bits: u64,
}

impl SockFlags {
    pub const DEAD: u64 = 1 << 0;
    pub const DONE: u64 = 1 << 1;
    pub const URGINLINE: u64 = 1 << 2;
    pub const KEEPOPEN: u64 = 1 << 3;
    pub const LINGER: u64 = 1 << 4;
    pub const DESTROY: u64 = 1 << 5;
    pub const BROADCAST: u64 = 1 << 6;
    pub const TIMESTAMP: u64 = 1 << 7;
    pub const RCVTSTAMP: u64 = 1 << 8;
    pub const TIMESTAMPING_TX_HARDWARE: u64 = 1 << 9;
    pub const TIMESTAMPING_TX_SOFTWARE: u64 = 1 << 10;
    pub const TIMESTAMPING_RX_HARDWARE: u64 = 1 << 11;
    pub const TIMESTAMPING_RX_SOFTWARE: u64 = 1 << 12;
    pub const WIFI_STATUS: u64 = 1 << 13;
    pub const NOFCS: u64 = 1 << 14;
    pub const ZEROCOPY: u64 = 1 << 15;
    pub const TXTIME: u64 = 1 << 16;
    pub const XDP: u64 = 1 << 17;
    pub const TSTAMP_NEW: u64 = 1 << 18;
    pub const RCVMARK: u64 = 1 << 19;
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SockCgroupData {
    pub cgroup: u64,    // cgroup v2
    pub classid: u32,   // net_cls
    pub prioidx: u32,   // net_prio
}

// ============================================================================
// sk_buff (Socket Buffer)
// ============================================================================

#[repr(C)]
pub struct SkBuff {
    // List management
    pub next: u64,
    pub prev: u64,
    // Timestamps
    pub tstamp: u64,
    pub skb_mstamp_ns: u64,
    // Ownership
    pub sk: u64,        // struct sock *
    pub dev: u64,       // struct net_device *
    // Character device
    pub cb: [48]u8,     // control buffer
    // Destructor
    pub destructor: u64,
    // Headers
    pub transport_header: u16,
    pub network_header: u16,
    pub mac_header: u16,
    // Data pointers
    pub head: u64,
    pub data: u64,
    pub tail: u32,
    pub end: u32,
    // Length
    pub len: u32,
    pub data_len: u32,
    pub mac_len: u16,
    pub hdr_len: u16,
    // Checksum
    pub csum: u32,
    pub csum_start: u16,
    pub csum_offset: u16,
    // Priority & mark
    pub priority: u32,
    pub mark: u32,
    // Protocol
    pub protocol: u16,
    // Flags / bits
    pub pkt_type: u8,
    pub ip_summed: u8,
    pub ooo_okay: bool,
    pub ignore_df: bool,
    pub nf_trace: bool,
    pub ndisc_nodetype: u8,
    pub ipvs_property: bool,
    pub inner_protocol_type: u8,
    pub remcsum_offload: bool,
    pub redirected: bool,
    pub nf_skip_egress: bool,
    pub slow_gro: bool,
    pub csum_complete_sw: bool,
    pub csum_level: u8,
    pub dst_pending_confirm: bool,
    // Hash
    pub hash: u32,
    // VLAN
    pub vlan_proto: u16,
    pub vlan_tci: u16,
    // Queue mapping
    pub queue_mapping: u16,
    // Reference count
    pub users: u32,
    // TC/XDP
    pub tc_index: u16,
    pub alloc_cpu: u16,
    // Fragments
    pub truesize: u32,
    pub napi_id: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PktType {
    Host = 0,
    Broadcast = 1,
    Multicast = 2,
    OtherHost = 3,
    Outgoing = 4,
    Loopback = 5,
    FastRoute = 6,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CsumType {
    None = 0,
    Unnecessary = 1,
    Complete = 2,
    Partial = 3,
}

// ============================================================================
// sk_buff Shared Info (for fragments)
// ============================================================================

#[repr(C)]
pub struct SkbSharedInfo {
    pub flags: u8,
    pub meta_len: u8,
    pub nr_frags: u8,
    pub gso_size: u16,
    pub gso_segs: u16,
    pub gso_type: u32,
    pub frag_list: u64,
    pub hwtstamps: SkbHwTstamps,
    pub tskey: u32,
    pub xdp_frags_size: u32,
    pub xdp_frags_truesize: u32,
    pub destructor_arg: u64,
    pub frags: [17]SkbFragStruct,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct SkbHwTstamps {
    pub hwtstamp: u64,
}

#[repr(C)]
pub struct SkbFragStruct {
    pub bv_page: u64,
    pub bv_len: u32,
    pub bv_offset: u32,
}

// ============================================================================
// GSO (Generic Segmentation Offload) types
// ============================================================================

pub struct GsoType;
impl GsoType {
    pub const TCPV4: u32 = 1 << 0;
    pub const DODGY: u32 = 1 << 1;
    pub const TCP_ECN: u32 = 1 << 2;
    pub const TCP_FIXEDID: u32 = 1 << 3;
    pub const TCPV6: u32 = 1 << 4;
    pub const FCOE: u32 = 1 << 5;
    pub const GRE: u32 = 1 << 6;
    pub const GRE_CSUM: u32 = 1 << 7;
    pub const IPXIP4: u32 = 1 << 8;
    pub const IPXIP6: u32 = 1 << 9;
    pub const UDP_TUNNEL: u32 = 1 << 10;
    pub const UDP_TUNNEL_CSUM: u32 = 1 << 11;
    pub const PARTIAL: u32 = 1 << 12;
    pub const TUNNEL_REMCSUM: u32 = 1 << 13;
    pub const SCTP: u32 = 1 << 14;
    pub const ESP: u32 = 1 << 15;
    pub const UDP: u32 = 1 << 16;
    pub const UDP_L4: u32 = 1 << 17;
    pub const FRAGLIST: u32 = 1 << 18;
}

// ============================================================================
// Socket Options (SOL_SOCKET level)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolSocketOpt {
    SoDebug = 1,
    SoReuseaddr = 2,
    SoType = 3,
    SoError = 4,
    SoDontroute = 5,
    SoBroadcast = 6,
    SoSndbuf = 7,
    SoRcvbuf = 8,
    SoSndbufforce = 32,
    SoRcvbufforce = 33,
    SoKeepalive = 9,
    SoOobinline = 10,
    SoNoCheck = 11,
    SoPriority = 12,
    SoLinger = 13,
    SoBsdcompat = 14,
    SoReuseport = 15,
    SoPasscred = 16,
    SoPeercred = 17,
    SoRcvlowat = 18,
    SoSndlowat = 19,
    SoRcvtimeoOld = 20,
    SoSndtimeoOld = 21,
    SoTimestampOld = 29,
    SoTimestampnsOld = 35,
    SoTimestampingOld = 37,
    SoMarkVal = 36,
    SoAcceptconn = 30,
    SoPeersec = 31,
    SoPasssec = 34,
    SoAttachFilter = 26,
    SoDetachFilter = 27,
    SoLockFilter = 44,
    SoAttachBpf = 50,
    SoAttachReuseportCbpf = 51,
    SoAttachReuseportEbpf = 52,
    SoBusyPoll = 46,
    SoMaxPacingRate = 47,
    SoIncomingCpu = 49,
    SoCookie = 57,
    SoPeergroups = 59,
    SoZerocopy = 60,
    SoTxtime = 61,
    SoBindtoifindex = 62,
    SoTimestampNew = 63,
    SoTimestampnsNew = 64,
    SoTimestampingNew = 65,
    SoRcvtimeoNew = 66,
    SoSndtimeoNew = 67,
    SoDetachReuseportBpf = 68,
    SoPreferBusyPoll = 69,
    SoBusyPollBudget = 70,
    SoNetnsCooke = 71,
    SoBufLock = 72,
    SoReserveMem = 73,
    SoTxrehash = 74,
    SoRcvmark = 75,
    SoPasspidfd = 76,
    SoPeerpidfd = 77,
}

// ============================================================================
// TCP Socket Options
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSockOpt {
    TcpNodelay = 1,
    TcpMaxseg = 2,
    TcpCork = 3,
    TcpKeepidle = 4,
    TcpKeepintvl = 5,
    TcpKeepcnt = 6,
    TcpSyncnt = 7,
    TcpLinger2 = 8,
    TcpDeferAccept = 9,
    TcpWindowClamp = 10,
    TcpInfo = 11,
    TcpQuickack = 12,
    TcpCongestion = 13,
    TcpMd5sig = 14,
    TcpThinLinearTimeouts = 16,
    TcpThinDupack = 17,
    TcpUserTimeout = 18,
    TcpRepairQueue = 20,
    TcpRepairQueueSeq = 21,
    TcpQueueSeq = 21,
    TcpRepair = 19,
    TcpRepairOptions = 22,
    TcpFastopen = 23,
    TcpTimestamp = 24,
    TcpNotsent = 25,
    TcpCcInfo = 26,
    TcpSaveSync = 27,
    TcpFastopenConnect = 30,
    TcpFastopenNoCooke = 34,
    TcpZerocopyReceive = 35,
    TcpInpTimestamp = 36,
    TcpTxDelay = 37,
    TcpAoAddKey = 38,
    TcpAoDelKey = 39,
    TcpAoInfo = 40,
    TcpAoGetKeys = 41,
    TcpAoRepair = 42,
}

// ============================================================================
// TCP Info Structure
// ============================================================================

#[repr(C)]
#[derive(Debug, Default)]
pub struct TcpInfo {
    pub state: u8,
    pub ca_state: u8,
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    pub snd_wscale_rcv_wscale: u8,
    pub delivery_rate_app_limited: u8,
    pub rto: u32,
    pub ato: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub fackets: u32,
    // Times
    pub last_data_sent: u32,
    pub last_ack_sent: u32,
    pub last_data_recv: u32,
    pub last_ack_recv: u32,
    // Metrics
    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    pub rtt: u32,
    pub rttvar: u32,
    pub snd_ssthresh: u32,
    pub snd_cwnd: u32,
    pub advmss: u32,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub total_retrans: u32,
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    pub notsent_bytes: u32,
    pub min_rtt: u32,
    pub data_segs_in: u32,
    pub data_segs_out: u32,
    pub delivery_rate: u64,
    pub busy_time: u64,
    pub rwnd_limited: u64,
    pub sndbuf_limited: u64,
    pub delivered: u32,
    pub delivered_ce: u32,
    pub bytes_sent: u64,
    pub bytes_retrans: u64,
    pub dsack_dups: u32,
    pub reord_seen: u32,
    pub rcv_ooopack: u32,
    pub snd_wnd: u32,
    pub rcv_wnd: u32,
    pub rehash: u32,
    pub total_rto: u16,
    pub total_rto_recoveries: u16,
    pub total_rto_time: u32,
}

// ============================================================================
// Zerocopy & Cork
// ============================================================================

#[repr(C)]
#[derive(Debug)]
pub struct MsgZerocopy {
    pub status: u32,
    pub id: u32,
    pub num: u32,
    pub lo: u32,
    pub hi: u32,
    pub flags: u16,
}

#[repr(C)]
pub struct InetCork {
    pub flags: u32,
    pub addr: u32,
    pub opt: u64,
    pub fragsize: u32,
    pub length: i32,
    pub dst: u64,
    pub fl4: u64,
    pub base: u64,
    pub tx_flags: u32,
    pub ttl: u8,
    pub tos: u8,
    pub priority: u32,
    pub gso_size: u16,
}

// ============================================================================
// Socket Advanced Manager
// ============================================================================

#[derive(Debug)]
pub struct SocketAdvancedManager {
    pub active_sockets: u64,
    pub total_created: u64,
    pub total_closed: u64,
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub total_tx_packets: u64,
    pub total_rx_packets: u64,
    pub skb_allocs: u64,
    pub skb_frees: u64,
    pub zerocopy_sends: u64,
    pub gso_segments: u64,
    pub gro_packets: u64,
    pub initialized: bool,
}

impl SocketAdvancedManager {
    pub fn new() -> Self {
        Self {
            active_sockets: 0,
            total_created: 0,
            total_closed: 0,
            total_tx_bytes: 0,
            total_rx_bytes: 0,
            total_tx_packets: 0,
            total_rx_packets: 0,
            skb_allocs: 0,
            skb_frees: 0,
            zerocopy_sends: 0,
            gso_segments: 0,
            gro_packets: 0,
            initialized: true,
        }
    }
}
