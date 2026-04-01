// Zxyphor Rust - IPv6 Stack Internals
// IPv6 header, extension headers, ICMPv6
// NDP (Neighbor Discovery Protocol), SLAAC
// IPv6 routing, flow labels, fragmentation
// IPv6 socket options, multicast, anycast
// RFC 8200, RFC 4861, RFC 4862
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

#![allow(dead_code)]

// ============================================================================
// IPv6 Header
// ============================================================================

#[repr(C, packed)]
pub struct Ipv6Header {
    pub version_tc_flow: u32,   // version(4) | TC(8) | flow(20)
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

impl Ipv6Header {
    pub fn version(&self) -> u8 {
        (self.version_tc_flow.to_be() >> 28) as u8
    }

    pub fn traffic_class(&self) -> u8 {
        ((self.version_tc_flow.to_be() >> 20) & 0xFF) as u8
    }

    pub fn flow_label(&self) -> u32 {
        self.version_tc_flow.to_be() & 0xFFFFF
    }
}

// ============================================================================
// Extension Header Types (Next Header values)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NextHeader {
    HopByHop = 0,
    Tcp = 6,
    Udp = 17,
    Ipv6Route = 43,
    Ipv6Frag = 44,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58,
    NoNextHeader = 59,
    Ipv6Opts = 60,    // destination options
    Mobility = 135,
    Hip = 139,
    Shim6 = 140,
    Test1 = 253,
    Test2 = 254,
}

// ============================================================================
// Hop-by-Hop & Destination Options
// ============================================================================

#[repr(C, packed)]
pub struct Ipv6OptHeader {
    pub next_header: u8,
    pub hdr_ext_len: u8,  // in 8-byte units, not counting first 8 bytes
    // Options follow (TLV encoded)
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Ipv6OptionType {
    Pad1 = 0,
    PadN = 1,
    RouterAlert = 5,
    Jumbo = 194,
    HomeAddress = 201,
    Calipso = 7,
    Smf = 8,
    Rpl = 0x63,
    Ioam = 0x31,
    AltDst = 0x32,
}

#[repr(C, packed)]
pub struct RouterAlertOption {
    pub option_type: u8,   // 5
    pub option_len: u8,    // 2
    pub value: u16,
}

pub const ROUTER_ALERT_MLD: u16 = 0;
pub const ROUTER_ALERT_RSVP: u16 = 1;
pub const ROUTER_ALERT_ACTIVE_NET: u16 = 2;

// ============================================================================
// Routing Header
// ============================================================================

#[repr(C, packed)]
pub struct Ipv6RtHeader {
    pub next_header: u8,
    pub hdr_ext_len: u8,
    pub routing_type: u8,
    pub segments_left: u8,
    // Type-specific data follows
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RoutingType {
    Source = 0,       // deprecated
    Type2 = 2,       // Mobile IPv6
    Rpl = 3,         // RPL Source Route
    Srh = 4,         // Segment Routing Header
    Crh16 = 5,       // Compact Routing Header 16
    Crh32 = 6,       // Compact Routing Header 32
}

#[repr(C, packed)]
pub struct SegmentRoutingHeader {
    pub next_header: u8,
    pub hdr_ext_len: u8,
    pub routing_type: u8,   // 4
    pub segments_left: u8,
    pub last_entry: u8,
    pub flags: u8,
    pub tag: u16,
    // segment_list: [u8; 16] * (last_entry + 1)
}

// ============================================================================
// Fragment Header
// ============================================================================

#[repr(C, packed)]
pub struct Ipv6FragHeader {
    pub next_header: u8,
    pub reserved: u8,
    pub frag_off_m: u16,    // offset(13) | res(2) | M(1)
    pub identification: u32,
}

impl Ipv6FragHeader {
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be(self.frag_off_m) >> 3
    }

    pub fn more_fragments(&self) -> bool {
        u16::from_be(self.frag_off_m) & 1 != 0
    }
}

// ============================================================================
// ICMPv6
// ============================================================================

#[repr(C, packed)]
pub struct Icmpv6Header {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Icmpv6Type {
    // Error messages
    DestUnreach = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParamProblem = 4,
    // Informational
    EchoRequest = 128,
    EchoReply = 129,
    // MLD
    MldQuery = 130,
    MldReport = 131,
    MldDone = 132,
    MldV2Report = 143,
    // NDP
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
    // Other
    RouterRenumbering = 138,
    InformationQuery = 139,
    InformationResponse = 140,
    InverseSolicitation = 141,
    InverseAdvertisement = 142,
    HomeAgentAddressDiscoveryReq = 144,
    HomeAgentAddressDiscoveryReply = 145,
    MobilePrefixSolicitation = 146,
    MobilePrefixAdvertisement = 147,
    CertPathSolicitation = 148,
    CertPathAdvertisement = 149,
    Rpl = 155,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DestUnreachCode {
    NoRoute = 0,
    AdminProhibited = 1,
    BeyondScope = 2,
    AddrUnreachable = 3,
    PortUnreachable = 4,
    SourceAddressFailed = 5,
    RejectRoute = 6,
    SourceRoutingHeader = 7,
}

// ============================================================================
// NDP (Neighbor Discovery Protocol) - RFC 4861
// ============================================================================

#[repr(C, packed)]
pub struct NdpRouterSolicitation {
    pub icmpv6_hdr: Icmpv6Header,
    pub reserved: u32,
    // Options follow
}

#[repr(C, packed)]
pub struct NdpRouterAdvertisement {
    pub icmpv6_hdr: Icmpv6Header,
    pub cur_hop_limit: u8,
    pub flags: u8,        // M(1)|O(1)|H(1)|Prf(2)|P(1)|R(1)|reserved(1)
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    // Options follow
}

impl NdpRouterAdvertisement {
    pub fn managed_flag(&self) -> bool { self.flags & 0x80 != 0 }
    pub fn other_config_flag(&self) -> bool { self.flags & 0x40 != 0 }
    pub fn home_agent_flag(&self) -> bool { self.flags & 0x20 != 0 }
    pub fn default_router_pref(&self) -> u8 { (self.flags >> 3) & 0x03 }
}

#[repr(C, packed)]
pub struct NdpNeighborSolicitation {
    pub icmpv6_hdr: Icmpv6Header,
    pub reserved: u32,
    pub target_address: [u8; 16],
    // Options follow
}

#[repr(C, packed)]
pub struct NdpNeighborAdvertisement {
    pub icmpv6_hdr: Icmpv6Header,
    pub flags: u32,       // R(1)|S(1)|O(1)|reserved(29)
    pub target_address: [u8; 16],
    // Options follow
}

impl NdpNeighborAdvertisement {
    pub fn router_flag(&self) -> bool { u32::from_be(self.flags) & 0x80000000 != 0 }
    pub fn solicited_flag(&self) -> bool { u32::from_be(self.flags) & 0x40000000 != 0 }
    pub fn override_flag(&self) -> bool { u32::from_be(self.flags) & 0x20000000 != 0 }
}

#[repr(C, packed)]
pub struct NdpRedirect {
    pub icmpv6_hdr: Icmpv6Header,
    pub reserved: u32,
    pub target_address: [u8; 16],
    pub destination_address: [u8; 16],
    // Options follow
}

// ============================================================================
// NDP Options
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum NdpOptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    RedirectedHeader = 4,
    Mtu = 5,
    RouteInformation = 24,
    RecursiveDnsServer = 25,
    DnsSearchList = 31,
    Nonce = 14,
    Pref64 = 38,
}

#[repr(C, packed)]
pub struct NdpOptionHeader {
    pub option_type: u8,
    pub length: u8,   // in units of 8 bytes
}

#[repr(C, packed)]
pub struct NdpPrefixInfo {
    pub option_type: u8,     // 3
    pub length: u8,          // 4
    pub prefix_length: u8,
    pub flags: u8,           // L(1)|A(1)|R(1)|reserved(5)
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub reserved2: u32,
    pub prefix: [u8; 16],
}

impl NdpPrefixInfo {
    pub fn on_link_flag(&self) -> bool { self.flags & 0x80 != 0 }
    pub fn autonomous_flag(&self) -> bool { self.flags & 0x40 != 0 }
    pub fn router_address_flag(&self) -> bool { self.flags & 0x20 != 0 }
}

#[repr(C, packed)]
pub struct NdpMtuOption {
    pub option_type: u8,     // 5
    pub length: u8,          // 1
    pub reserved: u16,
    pub mtu: u32,
}

#[repr(C, packed)]
pub struct NdpRdnssOption {
    pub option_type: u8,     // 25
    pub length: u8,
    pub reserved: u16,
    pub lifetime: u32,
    // followed by one or more 128-bit IPv6 addresses
}

#[repr(C, packed)]
pub struct NdpRouteInfo {
    pub option_type: u8,     // 24
    pub length: u8,
    pub prefix_length: u8,
    pub flags: u8,           // reserved(3)|Prf(2)|reserved(3)
    pub route_lifetime: u32,
    // prefix follows (variable length, padded to 8-byte boundary)
}

// ============================================================================
// SLAAC (Stateless Address Autoconfiguration) - RFC 4862
// ============================================================================

pub struct SlaacState {
    pub dad_transmits: u32,
    pub dad_retransmit_timer_ms: u32,
    pub temp_valid_lft: u32,
    pub temp_preferred_lft: u32,
    pub regen_advance: u32,
    pub max_desync_factor: u32,
    pub max_addresses: u32,
    pub use_tempaddr: SlaacTempAddrMode,
    pub optimistic_dad: bool,
    pub use_optimistic: bool,
    pub enhanced_dad: bool,
    pub addr_gen_mode: AddrGenMode,
    pub stable_secret: [u8; 16],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum SlaacTempAddrMode {
    Disabled = 0,
    Enabled = 1,
    PreferPublic = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum AddrGenMode {
    Eui64 = 0,
    None = 1,
    StablePrivacy = 2,
    Random = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DadState {
    None = 0,
    Tentative = 1,
    Optimistic = 2,
    Duplicate = 3,
    Succeeded = 4,
}

// ============================================================================
// IPv6 Address Types
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Ipv6AddrScope {
    InterfaceLocal = 0x01,
    LinkLocal = 0x02,
    SiteLocal = 0x05,     // deprecated
    OrganizationLocal = 0x08,
    Global = 0x0E,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum Ipv6AddrType {
    Unicast = 0,
    Multicast = 1,
    Anycast = 2,
    LinkLocal = 3,
    SiteLocal = 4,
    Loopback = 5,
    Unspecified = 6,
}

pub struct Ipv6IfAddr {
    pub addr: [u8; 16],
    pub prefix_len: u8,
    pub scope: Ipv6AddrScope,
    pub addr_type: Ipv6AddrType,
    pub flags: Ipv6AddrFlags,
    pub valid_lft: u32,
    pub preferred_lft: u32,
    pub creation_time: u64,
    pub dad_state: DadState,
    pub dad_nonce: u64,
    pub stable_privacy_retry: u8,
}

#[derive(Clone, Copy)]
pub struct Ipv6AddrFlags {
    pub temporary: bool,
    pub deprecated: bool,
    pub tentative: bool,
    pub optimistic: bool,
    pub dadfailed: bool,
    pub homeaddress: bool,
    pub nodad: bool,
    pub managetempaddr: bool,
    pub noprefixroute: bool,
    pub mcautojoin: bool,
    pub stable_privacy: bool,
}

// ============================================================================
// IPv6 Multicast
// ============================================================================

pub struct Ipv6McastGroup {
    pub group_addr: [u8; 16],
    pub source_count: u32,
    pub filter_mode: McastFilterMode,
    pub users: u32,
    pub timer_running: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum McastFilterMode {
    Include = 0,
    Exclude = 1,
}

// Well-known multicast addresses
pub const ALL_NODES_ADDR: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
pub const ALL_ROUTERS_ADDR: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
pub const ALL_MLDV2_ROUTERS: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16];
pub const SOLICITED_NODE_PREFIX: [u8; 13] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff];

// ============================================================================
// IPv6 Routing Table
// ============================================================================

pub struct Ipv6RouteEntry {
    pub destination: [u8; 16],
    pub prefix_len: u8,
    pub gateway: [u8; 16],
    pub metric: u32,
    pub flags: Ipv6RouteFlags,
    pub protocol: RouteProtocol,
    pub ifindex: u32,
    pub expires: u64,
    pub mtu: u32,
    pub preference: u8,
}

#[derive(Clone, Copy)]
pub struct Ipv6RouteFlags {
    pub up: bool,
    pub gateway: bool,
    pub host: bool,
    pub reject: bool,
    pub dynamic: bool,
    pub modified: bool,
    pub default: bool,
    pub address: bool,
    pub cache: bool,
    pub flow: bool,
    pub policy: bool,
    pub pref_src: bool,
    pub onlink: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum RouteProtocol {
    Unspec = 0,
    Redirect = 1,
    Kernel = 2,
    Boot = 3,
    Static = 4,
    Ra = 9,
    Mrt = 10,
    Zebra = 11,
    Bird = 12,
    Dnrouted = 13,
    Xorp = 14,
    Ntk = 15,
    Dhcp = 16,
    Mrouted = 17,
    Keepalived = 18,
    Babel = 42,
    Bgp = 186,
    Isis = 187,
    Ospf = 188,
    Rip = 189,
    Eigrp = 192,
}

// ============================================================================
// IPv6 Socket Options
// ============================================================================

#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum Ipv6SockOpt {
    Ipv6V6Only = 26,
    RecvPktinfo = 49,
    Pktinfo = 50,
    RecvHopLimit = 51,
    HopLimit = 52,
    RecvHopOpts = 53,
    HopOpts = 54,
    RecvDstOpts = 55,
    DstOpts = 57,
    RecvRthdr = 56,
    Rthdr = 58,
    RecvTclass = 66,
    Tclass = 67,
    RecvPathmtu = 43,
    Pathmtu = 44,
    Dontfrag = 62,
    RecvDstOpts2 = 58,
    Multicasthops = 18,
    MulticastLoop = 19,
    UnicastHops = 16,
    JoinGroup = 20,
    LeaveGroup = 21,
    RouterAlert = 22,
    Flowinfo = 11,
    FlowlabelMgr = 32,
    Flowinfo2 = 33,
    Transparent = 75,
    Freebind = 78,
    RecvOrigDstaddr = 74,
    OrigDstaddr = 74,
    MinHopcount = 73,
    AddrPreferences = 72,
}

// ============================================================================
// IPv6 Network Stack Manager
// ============================================================================

pub struct Ipv6StackManager {
    // Interface config
    pub forwarding: bool,
    pub accept_ra: u8,          // 0=off, 1=if not forwarding, 2=always
    pub accept_ra_defrtr: bool,
    pub accept_ra_pinfo: bool,
    pub accept_ra_rtr_pref: bool,
    pub accept_ra_rt_info_min_plen: u8,
    pub accept_ra_rt_info_max_plen: u8,
    pub accept_source_route: bool,
    pub autoconf: bool,
    pub use_tempaddr: SlaacTempAddrMode,
    pub max_addresses: u32,
    pub router_solicitations: i32,
    pub router_solicitation_interval: u32,
    pub router_solicitation_max_interval: u32,
    pub router_solicitation_delay: u32,
    pub dad_transmits: u32,
    pub hop_limit: u8,
    pub mtu: u32,
    pub disable_ipv6: bool,
    // Neighbor cache
    pub neighbor_cache_entries: u64,
    pub neighbor_cache_gc_thresh1: u32,
    pub neighbor_cache_gc_thresh2: u32,
    pub neighbor_cache_gc_thresh3: u32,
    // Stats
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub mcast_packets: u64,
    pub forwarded_packets: u64,
    pub fragmented_packets: u64,
    pub reassembled_packets: u64,
    pub reassembly_fails: u64,
    pub no_routes: u64,
    pub truncated_packets: u64,
    // State
    pub initialized: bool,
}

impl Ipv6StackManager {
    pub fn new() -> Self {
        Self {
            forwarding: false,
            accept_ra: 1,
            accept_ra_defrtr: true,
            accept_ra_pinfo: true,
            accept_ra_rtr_pref: true,
            accept_ra_rt_info_min_plen: 0,
            accept_ra_rt_info_max_plen: 0,
            accept_source_route: false,
            autoconf: true,
            use_tempaddr: SlaacTempAddrMode::Disabled,
            max_addresses: 16,
            router_solicitations: 3,
            router_solicitation_interval: 4000,
            router_solicitation_max_interval: 3600000,
            router_solicitation_delay: 1000,
            dad_transmits: 1,
            hop_limit: 64,
            mtu: 1500,
            disable_ipv6: false,
            neighbor_cache_entries: 0,
            neighbor_cache_gc_thresh1: 128,
            neighbor_cache_gc_thresh2: 512,
            neighbor_cache_gc_thresh3: 1024,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            mcast_packets: 0,
            forwarded_packets: 0,
            fragmented_packets: 0,
            reassembled_packets: 0,
            reassembly_fails: 0,
            no_routes: 0,
            truncated_packets: 0,
            initialized: true,
        }
    }
}
