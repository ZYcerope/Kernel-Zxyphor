// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Neighbor Subsystem / ARP / NDP
// Complete neighbor table, ARP protocol, IPv6 NDP, NDISC,
// neighbor discovery options, proxy ARP, gratuitous ARP

const std = @import("std");

// ============================================================================
// Neighbor States (NUD - Neighbor Unreachability Detection)
// ============================================================================

pub const NudState = packed struct(u16) {
    incomplete: bool = false,
    reachable: bool = false,
    stale: bool = false,
    delay: bool = false,
    probe: bool = false,
    failed: bool = false,
    noarp: bool = false,
    permanent: bool = false,
    none: bool = false,
    _reserved: u7 = 0,
};

pub const NUD_INCOMPLETE: u16 = 0x01;
pub const NUD_REACHABLE: u16 = 0x02;
pub const NUD_STALE: u16 = 0x04;
pub const NUD_DELAY: u16 = 0x08;
pub const NUD_PROBE: u16 = 0x10;
pub const NUD_FAILED: u16 = 0x20;
pub const NUD_NOARP: u16 = 0x40;
pub const NUD_PERMANENT: u16 = 0x80;
pub const NUD_NONE: u16 = 0x100;
pub const NUD_VALID = NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE | NUD_DELAY;
pub const NUD_CONNECTED = NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE;

// ============================================================================
// Neighbor Entry
// ============================================================================

pub const NeighEntry = struct {
    next: ?*NeighEntry,
    tbl: u64,                // struct neigh_table *
    parms: ?*NeighParms,
    confirmed: u64,          // jiffies of last confirmation
    updated: u64,            // jiffies of last update
    lock: u64,               // rwlock
    refcnt: u32,
    arp_queue_len_bytes: u32,
    arp_queue: u64,          // sk_buff_head
    timer: u64,              // timer_list
    used: u64,               // jiffies of last use
    probes: u32,
    flags: NeighFlags,
    nud_state: u16,
    type_: u8,
    dead: bool,
    seqlock: u64,
    ha_lock: u64,            // read_mostly
    ha: [32]u8,              // Hardware address (max ALIGN(MAX_ADDR_LEN, 8))
    primary_key: [16]u8,     // Protocol address (up to sizeof(struct in6_addr))
    dev: u64,                // struct net_device *
    dev_tracker: u64,
    output: ?*const fn (*NeighEntry, u64) i32,
    ops: ?*const NeighOps,
};

pub const NeighFlags = packed struct(u32) {
    permanent: bool = false,
    proxy: bool = false,
    router: bool = false,
    noprobe: bool = false,
    managed: bool = false,
    ext_learned: bool = false,
    app_probe: bool = false,
    use: bool = false,
    _reserved: u24 = 0,
};

pub const NeighOps = struct {
    family: u16,
    solicit: ?*const fn (*NeighEntry, u64) void,
    error_report: ?*const fn (*NeighEntry, u64) void,
    output: ?*const fn (*NeighEntry, u64) i32,
    connected_output: ?*const fn (*NeighEntry, u64) i32,
};

// ============================================================================
// Neighbor Table
// ============================================================================

pub const NeighTable = struct {
    family: u16,
    entry_size: u32,
    key_len: u32,
    protocol: u16,
    hash_buckets: u64,
    hash_shift: u32,
    hash_chain_gc: u64,
    parms: NeighParms,
    gc_interval: u64,
    gc_thresh1: i32,
    gc_thresh2: i32,
    gc_thresh3: i32,
    last_flush: u64,
    proxy_timer: u64,
    proxy_queue: u64,
    entries: u32,
    stats: ?*NeighStatistics,
    id: [32]u8,
    phash_buckets: u64,
    nht: u64,
    gc_work: u64,
};

pub const NeighParms = struct {
    reachable_time: u32,
    retrans_time: u32,       // ms
    base_reachable_time: u32,
    gc_staletime: u32,
    delay_probe_time: u32,
    ucast_probes: u32,
    app_probes: u32,
    mcast_probes: u32,
    mcast_reprobes: u32,
    anycast_delay: u32,
    proxy_delay: u32,
    proxy_qlen: u32,
    locktime: u32,
    queue_len_bytes: u32,
    interval_probe_time_ms: u32,
};

pub const NeighStatistics = struct {
    lookups: u64,
    hits: u64,
    res_failed: u64,
    rcv_probes_mcast: u64,
    rcv_probes_ucast: u64,
    periodic_gc_runs: u64,
    forced_gc_runs: u64,
    unres_discards: u64,
    table_fulls: u64,
    destroys: u64,
    allocs: u64,
};

// ============================================================================
// ARP Protocol
// ============================================================================

pub const ArpOpcode = enum(u16) {
    Request = 1,
    Reply = 2,
    ReverseRequest = 3,
    ReverseReply = 4,
    InRequest = 8,
    InReply = 9,
    Nak = 10,
};

pub const ArpHardwareType = enum(u16) {
    Ethernet = 1,
    Expermental = 2,
    AX25 = 3,
    ProNet = 4,
    Chaos = 5,
    IEEE802 = 6,
    Arcnet = 7,
    Appletalk = 8,
    Dlci = 15,
    Atm = 19,
    Metricom = 23,
    IEEE1394 = 24,
    Eui64 = 27,
    Infiniband = 32,
    Slip = 256,
    Cslip = 257,
    Slip6 = 258,
    Cslip6 = 259,
    Rsrvd = 260,
    Adapt = 264,
    Rose = 270,
    X25 = 271,
    Hwx25 = 272,
    Can = 280,
    Ppp = 512,
    Cisco = 513,
    Lapb = 516,
    Ddcmp = 517,
    Rawhdlc = 518,
    RawIp = 519,
    Tunnel = 768,
    Tunnel6 = 769,
    Frad = 770,
    Skip = 771,
    Loopback = 772,
    Localtlk = 773,
    Fddi = 774,
    Bif = 775,
    Sit = 776,
    Ipddp = 777,
    Ipgre = 778,
    Pimreg = 779,
    Hippi = 780,
    Ash = 781,
    Econet = 782,
    Irda = 783,
    Fcpp = 784,
    Fcal = 785,
    Fcpl = 786,
    FcFabric = 787,
    Ieee80211 = 801,
    Ieee80211Prism = 802,
    Ieee80211Radiotap = 803,
    Ieee802154 = 804,
    Ieee802154Monitor = 805,
    Phonet = 820,
    PhoneTPipe = 821,
    Caif = 822,
    IpGre6 = 823,
    Netlink = 824,
    SixlowPan = 825,
    Vsockmon = 826,
    Void = 65535,
    None = 65534,
};

pub const ArpHeader = packed struct {
    ar_hrd: u16,   // Hardware type
    ar_pro: u16,   // Protocol type
    ar_hln: u8,    // Hardware address length
    ar_pln: u8,    // Protocol address length
    ar_op: u16,    // ARP opcode
    // Followed by variable-length fields:
    // ar_sha: sender hardware address
    // ar_sip: sender protocol address
    // ar_tha: target hardware address
    // ar_tip: target protocol address
};

pub const ArpConfig = struct {
    arp_accept: u8,
    arp_announce: u8,       // 0, 1, or 2
    arp_filter: bool,
    arp_ignore: u8,         // 0-8
    arp_notify: bool,
    proxy_arp: bool,
    proxy_arp_pvlan: bool,
    arp_evict_nocarrier: bool,
    gratuitous_arp_interval: u32,
};

// ============================================================================
// IPv6 Neighbor Discovery (NDP / NDISC)
// ============================================================================

pub const NdiscType = enum(u8) {
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
};

pub const NdiscOptionType = enum(u8) {
    SourceLinkLayerAddr = 1,
    TargetLinkLayerAddr = 2,
    PrefixInfo = 3,
    RedirectedHeader = 4,
    Mtu = 5,
    NonceSt = 14,
    RdnssInfo = 25,
    DnsSearchList = 31,
    CaptivePortal = 37,
    Pref64 = 38,
};

pub const NdiscRouterSolicit = packed struct {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_cksum: u16,
    reserved: u32,
};

pub const NdiscRouterAdvert = packed struct {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_cksum: u16,
    cur_hop_limit: u8,
    flags: NdiscRaFlags,
    router_lifetime: u16,   // seconds
    reachable_time: u32,    // ms
    retransmit_timer: u32,  // ms
};

pub const NdiscRaFlags = packed struct(u8) {
    _reserved: u2 = 0,
    proxy: bool = false,
    prf: u2 = 0,          // Router preference
    home_agent: bool = false,
    other: bool = false,
    managed: bool = false,
};

pub const NdiscNeighSolicit = packed struct {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_cksum: u16,
    reserved: u32,
    target_addr: [16]u8,
};

pub const NdiscNeighAdvert = packed struct {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_cksum: u16,
    flags: NdiscNaFlags,
    target_addr: [16]u8,
};

pub const NdiscNaFlags = packed struct(u32) {
    _reserved: u29 = 0,
    override_: bool = false,
    solicited: bool = false,
    router: bool = false,
};

pub const NdiscPrefixInfo = packed struct {
    option_type: u8,
    length: u8,           // In units of 8 bytes
    prefix_len: u8,
    flags: NdiscPrefixFlags,
    valid_lifetime: u32,  // seconds
    preferred_lifetime: u32,
    reserved2: u32,
    prefix: [16]u8,
};

pub const NdiscPrefixFlags = packed struct(u8) {
    _reserved: u5 = 0,
    router_address: bool = false,
    autoconf: bool = false,
    on_link: bool = false,
};

pub const NdiscRdnss = packed struct {
    option_type: u8,
    length: u8,
    reserved: u16,
    lifetime: u32,
    // Followed by IPv6 addresses
};

pub const NdiscRedirect = packed struct {
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_cksum: u16,
    reserved: u32,
    target_addr: [16]u8,
    dest_addr: [16]u8,
};

// ============================================================================
// IPv6 Neighbor Config
// ============================================================================

pub const Ipv6NeighConfig = struct {
    accept_ra: u8,             // 0=disabled, 1=if forwarding disabled, 2=always
    accept_ra_defrtr: bool,
    accept_ra_min_hop_limit: u8,
    autoconf: bool,
    dad_transmits: u32,        // Duplicate Address Detection retransmits
    force_mld_version: u8,
    force_tllao: bool,
    enhanced_dad: bool,
    optimistic_dad: bool,
    use_optimistic: bool,
    accept_ra_from_local: bool,
    accept_ra_rt_info_min_plen: u8,
    accept_ra_rt_info_max_plen: u8,
    accept_ra_pinfo: bool,
    ndisc_notify: bool,
    use_tempaddr: i8,
    temp_valid_lft: u32,
    temp_prefered_lft: u32,
    regen_max_retry: u32,
    max_desync_factor: u32,
    max_addresses: u32,
    accept_dad: u8,
    suppress_frag_ndisc: bool,
};

// ============================================================================
// Neighbor Manager
// ============================================================================

pub const NeighborManager = struct {
    arp_table: ?*NeighTable,
    nd_table: ?*NeighTable,
    total_arp_entries: u64,
    total_nd_entries: u64,
    total_arp_requests_sent: u64,
    total_arp_replies_received: u64,
    total_nd_solicitations: u64,
    total_nd_advertisements: u64,
    total_proxy_arp_responses: u64,
    total_gratuitous_arps: u64,
    total_gc_runs: u64,
    total_entries_reaped: u64,
    arp_config: ArpConfig,
    ndp_config: Ipv6NeighConfig,
    initialized: bool,

    pub fn init() NeighborManager {
        return .{
            .arp_table = null,
            .nd_table = null,
            .total_arp_entries = 0,
            .total_nd_entries = 0,
            .total_arp_requests_sent = 0,
            .total_arp_replies_received = 0,
            .total_nd_solicitations = 0,
            .total_nd_advertisements = 0,
            .total_proxy_arp_responses = 0,
            .total_gratuitous_arps = 0,
            .total_gc_runs = 0,
            .total_entries_reaped = 0,
            .arp_config = .{
                .arp_accept = 0,
                .arp_announce = 0,
                .arp_filter = false,
                .arp_ignore = 0,
                .arp_notify = false,
                .proxy_arp = false,
                .proxy_arp_pvlan = false,
                .arp_evict_nocarrier = true,
                .gratuitous_arp_interval = 0,
            },
            .ndp_config = .{
                .accept_ra = 1,
                .accept_ra_defrtr = true,
                .accept_ra_min_hop_limit = 1,
                .autoconf = true,
                .dad_transmits = 1,
                .force_mld_version = 0,
                .force_tllao = false,
                .enhanced_dad = true,
                .optimistic_dad = false,
                .use_optimistic = false,
                .accept_ra_from_local = false,
                .accept_ra_rt_info_min_plen = 0,
                .accept_ra_rt_info_max_plen = 0,
                .accept_ra_pinfo = true,
                .ndisc_notify = false,
                .use_tempaddr = -1,
                .temp_valid_lft = 604800,
                .temp_prefered_lft = 86400,
                .regen_max_retry = 3,
                .max_desync_factor = 600,
                .max_addresses = 16,
                .accept_dad = 1,
                .suppress_frag_ndisc = true,
            },
            .initialized = true,
        };
    }
};
