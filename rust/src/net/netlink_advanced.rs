// Zxyphor Kernel - Netlink Advanced Protocol, Generic Netlink,
// rtnetlink Messages, XFRM Netlink, Audit Netlink,
// Connector, Netlink Multicast Groups
// More advanced than Linux 2026 netlink subsystem

use core::fmt;

// ============================================================================
// Netlink Protocol Families
// ============================================================================

/// Netlink protocol family
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NlProtoFamily {
    Route = 0,             // NETLINK_ROUTE
    Unused = 1,
    Usersock = 2,          // NETLINK_USERSOCK
    Firewall = 3,
    SockDiag = 4,          // NETLINK_SOCK_DIAG
    Nflog = 5,
    Xfrm = 6,
    Selinux = 7,
    Iscsi = 8,
    Audit = 9,
    FibLookup = 10,
    Connector = 11,
    Netfilter = 12,
    Generic = 16,          // NETLINK_GENERIC
    Rdma = 20,
    Crypto = 21,
    Smc = 22,
    // Zxyphor
    ZxyKernel = 100,
}

/// Netlink message header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHeader {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

/// Netlink message flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgFlagsVal(pub u16);

impl NlMsgFlagsVal {
    pub const REQUEST: Self = Self(0x01);
    pub const MULTI: Self = Self(0x02);
    pub const ACK: Self = Self(0x04);
    pub const ECHO: Self = Self(0x08);
    pub const DUMP_INTR: Self = Self(0x10);
    pub const DUMP_FILTERED: Self = Self(0x20);
    pub const ROOT: Self = Self(0x100);
    pub const MATCH: Self = Self(0x200);
    pub const ATOMIC: Self = Self(0x400);
    pub const DUMP: Self = Self(0x300);
    pub const REPLACE: Self = Self(0x100);
    pub const EXCL: Self = Self(0x200);
    pub const CREATE: Self = Self(0x400);
    pub const APPEND: Self = Self(0x800);
}

/// Standard netlink message types
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum NlMsgStdType {
    Noop = 0x1,
    Error = 0x2,
    Done = 0x3,
    Overrun = 0x4,
}

/// Netlink error message
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgError {
    pub error: i32,
    pub msg: NlMsgHeader,
}

/// Netlink attribute header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlAttribute {
    pub nla_len: u16,
    pub nla_type: u16,
}

// ============================================================================
// rtnetlink Messages
// ============================================================================

/// rtnetlink message types
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum RtNlMsgKind {
    Newlink = 16,
    Dellink = 17,
    Getlink = 18,
    Setlink = 19,
    Newaddr = 20,
    Deladdr = 21,
    Getaddr = 22,
    Newroute = 24,
    Delroute = 25,
    Getroute = 26,
    Newneigh = 28,
    Delneigh = 29,
    Getneigh = 30,
    Newrule = 32,
    Delrule = 33,
    Getrule = 34,
    Newqdisc = 36,
    Delqdisc = 37,
    Getqdisc = 38,
    Newtclass = 40,
    Deltclass = 41,
    Gettclass = 42,
    Newtfilter = 44,
    Deltfilter = 45,
    Gettfilter = 46,
    Newaction = 48,
    Delaction = 49,
    Getaction = 50,
    Newprefix = 52,
    Getmulticast = 58,
    Getanycast = 62,
    Newneightbl = 64,
    Getneightbl = 66,
    Setneightbl = 67,
    Newnduseropt = 68,
    Newnetconf = 80,
    Delnetconf = 81,
    Getnetconf = 82,
    Newnsid = 88,
    Delnsid = 89,
    Getnsid = 90,
    Newstats = 92,
    Getstats = 94,
    Newnexthop = 104,
    Delnexthop = 105,
    Getnexthop = 106,
    Newvlan = 112,
    Delvlan = 113,
    Getvlan = 114,
}

/// Interface info message
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfInfoMessage {
    pub ifi_family: u8,
    pub _pad: u8,
    pub ifi_type: u16,
    pub ifi_index: i32,
    pub ifi_flags: u32,
    pub ifi_change: u32,
}

/// Interface address message
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfAddrMessage {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

/// Route message
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RouteMessage {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

/// Route type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RouteType {
    Unspec = 0,
    Unicast = 1,
    Local = 2,
    Broadcast = 3,
    Anycast = 4,
    Multicast = 5,
    Blackhole = 6,
    Unreachable = 7,
    Prohibit = 8,
    Throw = 9,
    Nat = 10,
}

/// Route protocol origin
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RouteProtocol {
    Unspec = 0,
    Kernel = 2,
    Boot = 3,
    Static = 4,
    Dhcp = 16,
    Babel = 42,
    Bgp = 186,
    Isis = 187,
    Ospf = 188,
    Rip = 189,
    Eigrp = 192,
}

/// Neighbor state
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct NeighborState(pub u16);

impl NeighborState {
    pub const INCOMPLETE: Self = Self(0x01);
    pub const REACHABLE: Self = Self(0x02);
    pub const STALE: Self = Self(0x04);
    pub const DELAY: Self = Self(0x08);
    pub const PROBE: Self = Self(0x10);
    pub const FAILED: Self = Self(0x20);
    pub const NOARP: Self = Self(0x40);
    pub const PERMANENT: Self = Self(0x80);
}

// ============================================================================
// Generic Netlink
// ============================================================================

/// Generic netlink header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GenlMsgHeader {
    pub cmd: u8,
    pub version: u8,
    pub reserved: u16,
}

/// Generic netlink control commands
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum GenlControlCmd {
    Unspec = 0,
    NewFamily = 1,
    DelFamily = 2,
    GetFamily = 3,
    NewOps = 4,
    DelOps = 5,
    GetOps = 6,
    NewMcastGrp = 7,
    DelMcastGrp = 8,
    GetMcastGrp = 9,
    GetPolicy = 10,
}

/// Generic netlink family descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct GenlFamilyDesc {
    pub id: u16,
    pub name: [u8; 16],
    pub name_len: u8,
    pub version: u32,
    pub maxattr: u32,
    pub hdrsize: u32,
    pub nr_ops: u32,
    pub nr_mcgrps: u32,
    pub parallel_ops: bool,
    pub netnsok: bool,
    // Policy
    pub policy_kind: GenlPolicyKind,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum GenlPolicyKind {
    Unspec = 0,
    Exact = 1,
    PerOp = 2,
}

/// Well-known generic netlink family IDs
pub const GENL_ID_CTRL_VAL: u16 = 0x10;

/// Netlink socket options
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum NlSockOption {
    AddMembership = 1,
    DropMembership = 2,
    PktInfo = 3,
    BroadcastError = 4,
    NoEnobufs = 5,
    ListenAllNsid = 8,
    ListMemberships = 9,
    CapAck = 10,
    ExtAck = 11,
    GetStrictChk = 12,
}

/// Connector callback ID
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnectorId {
    pub idx: u32,
    pub val: u32,
}

/// Connector message
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnectorMsg {
    pub id: ConnectorId,
    pub seq: u32,
    pub ack: u32,
    pub len: u16,
    pub flags: u16,
}

/// Well-known connector IDs
pub const CN_IDX_PROC_VAL: u32 = 1;
pub const CN_IDX_CIFS_VAL: u32 = 2;
pub const CN_IDX_W1_VAL: u32 = 3;

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct NetlinkAdvSubsystem {
    pub nr_sockets: u64,
    pub nr_kernel_sockets: u64,
    pub total_msgs_sent: u64,
    pub total_msgs_received: u64,
    pub total_msgs_dropped: u64,
    pub nr_genl_families: u32,
    pub nr_genl_ops: u32,
    pub nr_mcgrps: u32,
    pub nr_rtnl_dumps: u64,
    pub nr_connector_cbs: u32,
    pub zxy_priority_scheduling: bool,
    pub initialized: bool,
}

impl NetlinkAdvSubsystem {
    pub const fn new() -> Self {
        Self {
            nr_sockets: 0,
            nr_kernel_sockets: 0,
            total_msgs_sent: 0,
            total_msgs_received: 0,
            total_msgs_dropped: 0,
            nr_genl_families: 0,
            nr_genl_ops: 0,
            nr_mcgrps: 0,
            nr_rtnl_dumps: 0,
            nr_connector_cbs: 0,
            zxy_priority_scheduling: true,
            initialized: false,
        }
    }
}
