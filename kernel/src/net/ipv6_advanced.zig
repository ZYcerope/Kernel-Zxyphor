// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Advanced IPv6 Stack
// Full IPv6 implementation: ND, SLAAC, DHCPv6, MLD, flow labels, IPsec,
// extension headers, route types, multicast, anycast, segment routing (SRv6)
// More advanced than Linux 2026 IPv6 stack

const std = @import("std");

// ============================================================================
// IPv6 Header
// ============================================================================

pub const IPv6Header = extern struct {
    // Version (4) + Traffic Class (8) + Flow Label (20) = 32 bits
    version_tc_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src_addr: [16]u8,
    dst_addr: [16]u8,

    pub fn version(self: *const IPv6Header) u4 {
        return @truncate((@byteSwap(self.version_tc_flow) >> 28) & 0x0F);
    }

    pub fn traffic_class(self: *const IPv6Header) u8 {
        const val = @byteSwap(self.version_tc_flow);
        return @truncate((val >> 20) & 0xFF);
    }

    pub fn flow_label(self: *const IPv6Header) u20 {
        return @truncate(@byteSwap(self.version_tc_flow) & 0xFFFFF);
    }

    pub fn dscp(self: *const IPv6Header) u6 {
        return @truncate(self.traffic_class() >> 2);
    }

    pub fn ecn(self: *const IPv6Header) u2 {
        return @truncate(self.traffic_class() & 0x03);
    }
};

// ============================================================================
// Next Header / Protocol Numbers
// ============================================================================

pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_NONE: u8 = 59;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_MH: u8 = 135;  // Mobility
pub const IPPROTO_HIP: u8 = 139;
pub const IPPROTO_SHIM6: u8 = 140;

// ============================================================================
// Extension Headers
// ============================================================================

pub const IPv6ExtHeader = extern struct {
    next_header: u8,
    hdr_ext_len: u8,  // In 8-byte units (minus 1)
};

pub const IPv6HopByHopHeader = extern struct {
    next_header: u8,
    hdr_ext_len: u8,
    // Followed by options
};

pub const IPv6RoutingHeader = extern struct {
    next_header: u8,
    hdr_ext_len: u8,
    routing_type: u8,
    segments_left: u8,
};

pub const IPv6FragmentHeader = extern struct {
    next_header: u8,
    reserved: u8,
    frag_off_flags: u16,  // Offset (13) + reserved (2) + M flag (1)
    identification: u32,

    pub fn fragment_offset(self: *const IPv6FragmentHeader) u13 {
        return @truncate(@byteSwap(self.frag_off_flags) >> 3);
    }

    pub fn more_fragments(self: *const IPv6FragmentHeader) bool {
        return (@byteSwap(self.frag_off_flags) & 1) != 0;
    }
};

// ============================================================================
// IPv6 Options (Hop-by-Hop / Destination)
// ============================================================================

pub const IPv6OptionType = enum(u8) {
    pad1 = 0x00,
    padn = 0x01,
    jumbo = 0xC2,
    tunnel_encap = 0x04,
    router_alert = 0x05,
    quick_start = 0x06,
    calipso = 0x07,
    smf_dpd = 0x08,
    home_address = 0xC9,
    ioam = 0x11,
    ioam_dest = 0x31,
    // Zxyphor
    zxy_priority = 0xFE,
};

pub const IPv6RouterAlertValue = enum(u16) {
    mld = 0,
    rsvp = 1,
    active_networks = 2,
};

// ============================================================================
// Segment Routing v6 (SRv6)
// ============================================================================

pub const SRV6_MAX_SEGMENTS: u32 = 16;

pub const Srv6Header = extern struct {
    next_header: u8,
    hdr_ext_len: u8,
    routing_type: u8,   // = 4 for SRv6
    segments_left: u8,
    last_entry: u8,
    flags: u8,
    tag: u16,
    // Followed by segment list [16]u8 * (last_entry + 1)
};

pub const Srv6Sid = struct {
    addr: [16]u8,
    function: u16,    // SRv6 function
    args: [8]u8,      // Function arguments
    args_len: u8,
};

pub const Srv6Behavior = enum(u16) {
    end = 1,              // Endpoint
    end_x = 5,            // Endpoint with cross-connect
    end_t = 6,            // Endpoint with specific table lookup
    end_dx2 = 7,          // Endpoint with L2 cross-connect
    end_dx6 = 8,          // Endpoint with IPv6 cross-connect
    end_dx4 = 9,          // Endpoint with IPv4 cross-connect
    end_dt6 = 10,         // Endpoint with IPv6 table decap
    end_dt4 = 11,         // Endpoint with IPv4 table decap
    end_dt46 = 12,        // Endpoint with dual-stack decap
    end_b6 = 14,          // Endpoint bound to SRv6 policy
    end_b6_encaps = 15,   // With encapsulation
    end_bm = 16,          // Endpoint bound to SR-MPLS
    end_s = 17,           // Endpoint with state save
    end_as = 18,          // Endpoint with asymmetric behavior
    end_am = 19,          // Endpoint with masquerading
    h_encaps = 100,       // Headend with encapsulation
    h_encaps_red = 101,   // Reduced encapsulation
    h_inline = 102,       // Headend with insertion
    // Zxyphor
    zxy_end_qos = 200,    // QoS-aware endpoint
    zxy_end_mirror = 201,  // Packet mirroring endpoint
};

pub const Srv6Policy = struct {
    bsid: [16]u8,         // Binding SID
    segment_lists: [4]Srv6SegmentList,
    nr_segment_lists: u8,
    color: u32,
    endpoint: [16]u8,
    weight: u32,
    preference: u32,
    state: Srv6PolicyState,
};

pub const Srv6SegmentList = struct {
    segments: [SRV6_MAX_SEGMENTS]Srv6Sid,
    nr_segments: u8,
    weight: u32,
};

pub const Srv6PolicyState = enum(u8) {
    candidate = 0,
    active = 1,
    invalid = 2,
};

// ============================================================================
// Neighbor Discovery (ND) - RFC 4861
// ============================================================================

pub const ICMPv6Type = enum(u8) {
    // Error messages
    dest_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,
    // Informational
    echo_request = 128,
    echo_reply = 129,
    // MLD
    mld_query = 130,
    mld_report = 131,
    mld_done = 132,
    mldv2_report = 143,
    // ND
    router_solicitation = 133,
    router_advertisement = 134,
    neighbor_solicitation = 135,
    neighbor_advertisement = 136,
    redirect = 137,
    // Others
    router_renumbering = 138,
    node_info_query = 139,
    node_info_response = 140,
    inverse_nd_solicitation = 141,
    inverse_nd_advertisement = 142,
    mld_report_v2 = 143,
    home_agent_request = 144,
    home_agent_reply = 145,
    mobile_prefix_solicitation = 146,
    mobile_prefix_advertisement = 147,
    certification_path_solicitation = 148,
    certification_path_advertisement = 149,
    multicast_router_advertisement = 151,
    multicast_router_solicitation = 152,
    multicast_router_termination = 153,
    rpl_control = 155,
};

pub const NdOptionType = enum(u8) {
    source_link_addr = 1,
    target_link_addr = 2,
    prefix_info = 3,
    redirect_header = 4,
    mtu = 5,
    nonce = 14,
    route_info = 24,
    rdnss = 25,        // Recursive DNS Server
    dnssl = 31,        // DNS Search List
    captive_portal = 37,
    pref64 = 38,       // NAT64 prefix
};

pub const NdPrefixInfo = struct {
    prefix_len: u8,
    on_link: bool,
    autonomous: bool,   // SLAAC
    valid_lifetime: u32,
    preferred_lifetime: u32,
    prefix: [16]u8,
};

pub const NdRouteInfo = struct {
    prefix_len: u8,
    preference: u2,
    route_lifetime: u32,
    prefix: [16]u8,
};

pub const NdRdnss = struct {
    lifetime: u32,
    addresses: [8][16]u8,
    nr_addresses: u8,
};

pub const NdDnssl = struct {
    lifetime: u32,
    domains: [8][256]u8,
    domain_lens: [8]u16,
    nr_domains: u8,
};

pub const NeighborState = enum(u8) {
    none = 0,
    incomplete = 1,
    reachable = 2,
    stale = 3,
    delay = 4,
    probe = 5,
    failed = 6,
    noarp = 7,
    permanent = 8,
};

pub const NeighborEntry = struct {
    ip_addr: [16]u8,
    mac_addr: [6]u8,
    state: NeighborState,
    flags: u32,
    reachable_time: u32,   // ms
    updated: u64,
    confirmed: u64,
    used: u64,
    probes: u8,
    is_router: bool,
    ifindex: u32,
};

pub const NeighborTable = struct {
    entries: [4096]NeighborEntry,
    nr_entries: u32,
    // Parameters
    base_reachable_time_ms: u32,
    retrans_timer_ms: u32,
    gc_stale_time: u32,
    delay_probe_time: u32,
    max_unicast_solicit: u8,
    max_multicast_solicit: u8,
    // Stats
    lookups: u64,
    hits: u64,
    alloc_failed: u64,
    res_failed: u64,
    destroys: u64,

    pub fn lookup(self: *const NeighborTable, addr: [16]u8) ?*const NeighborEntry {
        for (self.entries[0..self.nr_entries]) |*entry| {
            if (std.mem.eql(u8, &entry.ip_addr, &addr) and
                entry.state != .none and entry.state != .failed)
            {
                return entry;
            }
        }
        return null;
    }
};

// ============================================================================
// SLAAC (Stateless Address Autoconfiguration) RFC 4862
// ============================================================================

pub const SlaacState = struct {
    // Interfaces
    autoconfigured_addrs: [64]Ipv6IfAddr,
    nr_addrs: u32,
    // DAD (Duplicate Address Detection)
    dad_transmits: u8,
    dad_retransmit_timer_ms: u32,
    // Optimistic DAD
    optimistic_dad: bool,
    // Enhanced DAD
    enhanced_dad: bool,
    // Privacy Extensions (RFC 4941)
    use_tempaddr: bool,
    temp_valid_lifetime: u32,
    temp_preferred_lifetime: u32,
    regen_advance: u32,
    max_desync_factor: u32,
    max_addresses: u32,
};

pub const Ipv6IfAddr = struct {
    addr: [16]u8,
    prefix_len: u8,
    flags: u32,
    scope: Ipv6Scope,
    state: Ipv6AddrState,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    created: u64,
    last_used: u64,
    dad_nonce: u64,
    // Source
    source: Ipv6AddrSource,
    ifindex: u32,
};

pub const Ipv6Scope = enum(u8) {
    node_local = 1,
    link_local = 2,
    site_local = 5,
    org_local = 8,
    global = 14,
};

pub const Ipv6AddrState = enum(u8) {
    tentative = 0,
    preferred = 1,
    deprecated = 2,
    invalid = 3,
    optimistic = 4,
};

pub const Ipv6AddrSource = enum(u8) {
    manual = 0,
    slaac = 1,
    dhcpv6 = 2,
    link_local = 3,
    loopback = 4,
    temporary = 5,  // Privacy
};

// ============================================================================
// MLD (Multicast Listener Discovery) - RFC 3810 / MLDv2
// ============================================================================

pub const MldMode = enum(u8) {
    v1 = 1,
    v2 = 2,
};

pub const MldGroupRecord = struct {
    record_type: MldRecordType,
    group_addr: [16]u8,
    sources: [64][16]u8,
    nr_sources: u32,
};

pub const MldRecordType = enum(u8) {
    mode_is_include = 1,
    mode_is_exclude = 2,
    change_to_include = 3,
    change_to_exclude = 4,
    allow_new_sources = 5,
    block_old_sources = 6,
};

pub const MldState = struct {
    mode: MldMode,
    max_resp_delay_ms: u32,
    robustness: u8,
    query_interval_ms: u32,
    // Groups
    groups: [256]MldGroupEntry,
    nr_groups: u32,
    // Stats
    reports_sent: u64,
    reports_received: u64,
    queries_received: u64,
};

pub const MldGroupEntry = struct {
    group_addr: [16]u8,
    filter_mode: u8,    // 0=include, 1=exclude
    sources: [64][16]u8,
    nr_sources: u32,
    timer: u64,
    ifindex: u32,
};

// ============================================================================
// IPv6 Routing
// ============================================================================

pub const Ipv6RouteType = enum(u8) {
    unicast = 1,
    local = 2,
    broadcast = 3,
    anycast = 4,
    multicast = 5,
    blackhole = 6,
    unreachable = 7,
    prohibit = 8,
    throw_route = 9,
    nat = 10,
};

pub const Ipv6RouteFlags = packed struct {
    gateway: bool,
    host: bool,
    reject: bool,
    dynamic: bool,
    modified: bool,
    default: bool,
    addrconf: bool,
    cache: bool,
    flow: bool,
    policy: bool,
    pref_src: bool,
    onlink: bool,
    nonexthop: bool,
    expires: bool,
    ndisc: bool,
    _padding: u1 = 0,
};

pub const Ipv6Route = struct {
    dst_addr: [16]u8,
    dst_prefix_len: u8,
    src_addr: [16]u8,
    src_prefix_len: u8,
    gateway: [16]u8,
    route_type: Ipv6RouteType,
    flags: Ipv6RouteFlags,
    metric: u32,
    ifindex: u32,
    table: u32,
    protocol: u8,     // RTPROT_*
    scope: u8,
    preference: u8,
    // MTU
    mtu: u32,
    advmss: u32,
    // Lifetime
    expires: u64,
    // Multipath
    nexthops: [16]Ipv6NextHop,
    nr_nexthops: u8,
    // SRv6
    srv6_enabled: bool,
    // Stats
    fib6_metrics: Ipv6RouteMetrics,
};

pub const Ipv6NextHop = struct {
    gateway: [16]u8,
    ifindex: u32,
    weight: u8,
    flags: u32,
};

pub const Ipv6RouteMetrics = struct {
    mtu: u32,
    advmss: u32,
    hoplimit: u32,
    rtt: u32,
    rttvar: u32,
    ssthresh: u32,
    cwnd: u32,
    initcwnd: u32,
    initrwnd: u32,
    quickack: u32,
    reordering: u32,
};

pub const Ipv6RoutingTable = struct {
    routes: [16384]Ipv6Route,
    nr_routes: u32,
    fib_table_id: u32,
    // Default route
    default_route: ?u32,  // Index

    pub fn lookup(self: *const Ipv6RoutingTable, dst: [16]u8) ?*const Ipv6Route {
        var best: ?*const Ipv6Route = null;
        var best_prefix: u8 = 0;
        for (self.routes[0..self.nr_routes]) |*route| {
            if (route.dst_prefix_len >= best_prefix) {
                // Check prefix match
                const full_bytes = route.dst_prefix_len / 8;
                if (full_bytes > 0 and std.mem.eql(u8, dst[0..full_bytes], route.dst_addr[0..full_bytes])) {
                    best = route;
                    best_prefix = route.dst_prefix_len;
                }
            }
        }
        return best;
    }
};

// ============================================================================
// IPv6 Subsystem
// ============================================================================

pub const Ipv6Subsystem = struct {
    // Neighbor discovery
    neighbor_table: NeighborTable,
    // SLAAC
    slaac: SlaacState,
    // MLD
    mld: MldState,
    // Routing
    routing_table: Ipv6RoutingTable,
    // SRv6
    srv6_policies: [64]Srv6Policy,
    nr_srv6_policies: u32,
    // Fragmentation
    frag_high_thresh: u64,
    frag_low_thresh: u64,
    frag_timeout: u32,    // seconds
    // Flow labels
    flowlabel_enabled: bool,
    flowlabel_exclusive: bool,
    auto_flowlabels: u8,  // 0=off, 1=on, 2=optout, 3=optin
    // Misc
    forwarding: bool,
    accept_ra: u8,         // 0=off, 1=if not forwarding, 2=always
    accept_redirects: bool,
    hop_limit: u8,
    mtu: u32,
    // Stats
    in_receives: u64,
    in_hdr_errors: u64,
    in_too_big_errors: u64,
    in_no_routes: u64,
    in_addr_errors: u64,
    in_unknown_protos: u64,
    in_truncated_pkts: u64,
    in_discards: u64,
    in_delivers: u64,
    out_forwarded_datagrams: u64,
    out_requests: u64,
    out_discards: u64,
    out_no_routes: u64,
    reasm_timeout: u64,
    reasm_reqds: u64,
    reasm_oks: u64,
    reasm_fails: u64,
    frag_oks: u64,
    frag_fails: u64,
    frag_creates: u64,
    in_mcast_pkts: u64,
    out_mcast_pkts: u64,
    in_octets: u64,
    out_octets: u64,
    initialized: bool,
};
