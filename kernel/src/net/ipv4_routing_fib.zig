// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - IPv4 Routing & FIB Detail
// Complete FIB structures, route lookup, policy routing,
// multipath, ECMP, route caching, nexthop objects, GRO/GSO routing

const std = @import("std");

// ============================================================================
// IPv4 Address & Route Types
// ============================================================================

pub const Ipv4Addr = packed struct(u32) {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
};

pub const RtScope = enum(u8) {
    Universe = 0,
    Site = 200,
    Link = 253,
    Host = 254,
    Nowhere = 255,
};

pub const RtType = enum(u8) {
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
    ExternalResolve = 11,
};

pub const RtProtocol = enum(u8) {
    Unspec = 0,
    IcmpRedirect = 1,
    Kernel = 2,
    Boot = 3,
    Static = 4,
    Gated = 8,
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
};

pub const RtTableId = enum(u32) {
    Unspec = 0,
    Compat = 252,
    Default = 253,
    Main = 254,
    Local = 255,
};

// ============================================================================
// FIB Info
// ============================================================================

pub const FibInfo = struct {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    protocol: RtProtocol,
    scope: RtScope,
    rt_type: RtType,
    flags: u32,
    table_id: u32,
    priority: u32,
    prefsrc: Ipv4Addr,
    metrics: [16]u32,       // RTAX_MAX metrics
    nhs: u32,               // Number of nexthops
    nh: [*]FibNhEntry,
    fib_net: usize,         // Network namespace pointer
    fib_treeref: u32,       // Reference count in FIB tree
    fib_clntref: u32,       // Client reference count
    fib_dead: bool,
    fib_hash: u32,
};

pub const FibNhEntry = struct {
    nh_dev_index: u32,
    nh_flags: u32,
    nh_scope: RtScope,
    nh_weight: u8,
    nh_upper_bound: u32,
    nh_gw_family: u8,
    nh_gw: Ipv4Addr,
    nh_gw6: [16]u8,        // IPv6 gateway (128-bit)
    nh_via: [16]u8,         // Via address for MPLS etc.
    nh_encap_type: u16,
    nh_oif: u32,            // Output interface
    nh_lwtstate: ?*LwtState,
    nh_tclassid: u32,       // TC class id for classification
};

pub const LwtState = struct {
    lwttype: LwtEncapType,
    headroom: u16,
    flags: u32,
};

pub const LwtEncapType = enum(u16) {
    None = 0,
    Mpls = 1,
    Ip = 2,
    Ila = 3,
    Seg6 = 4,
    Bpf = 5,
    Seg6Local = 6,
    Rpl = 7,
    Ioam6 = 8,
    Xfrm = 9,
};

// ============================================================================
// FIB Lookup Result
// ============================================================================

pub const FibResult = struct {
    prefix: Ipv4Addr,
    prefixlen: u8,
    nh_sel: u32,            // Selected nexthop
    rt_type: RtType,
    scope: RtScope,
    table: ?*FibTable,
    fi: ?*FibInfo,
    fa_head: ?*FibAliasHead,
};

pub const FibAliasHead = struct {
    first: ?*FibAlias,
};

pub const FibAlias = struct {
    next: ?*FibAlias,
    fi: ?*FibInfo,
    fa_tos: u8,
    fa_type: RtType,
    fa_state: u32,
    fa_slen: u8,
    fa_scope: RtScope,
    fa_default: u8,
    offload: bool,
    trap: bool,
    offload_failed: bool,
    tb_id: u32,
};

// ============================================================================
// FIB Table (LC-trie based)
// ============================================================================

pub const FibTable = struct {
    tb_id: u32,
    tb_num_default: u32,
    tb_data: usize,         // struct trie pointer
    tb_fib_flush: bool,
};

pub const TrieKeyVector = struct {
    pos: u32,               // Bit position of key
    bits: u32,              // Log2 of number of children
    slen: u32,              // Suffix length
    full_children: u32,
    empty_children: u32,
    tnode: [*]?*TrieKeyVector,
};

pub const FibTrieLeaf = struct {
    key: u32,               // IP prefix
    slen: u32,
    hlist: ?*FibAlias,
};

// ============================================================================
// Route Metrics
// ============================================================================

pub const RtaxMetric = enum(u8) {
    Unspec = 0,
    Lock = 1,
    Mtu = 2,
    Window = 3,
    Rtt = 4,
    Rttvar = 5,
    Ssthresh = 6,
    Cwnd = 7,
    Advmss = 8,
    Reordering = 9,
    Hoplimit = 10,
    Initcwnd = 11,
    Features = 12,
    RtoMin = 13,
    Initrwnd = 14,
    QuickAck = 15,
};

pub const DstMetrics = struct {
    metrics: [16]u32,
    refcnt: u32,
};

// ============================================================================
// Policy Routing (FIB Rules)
// ============================================================================

pub const FibRuleAction = enum(u8) {
    Unspec = 0,
    ToTable = 1,
    Goto = 2,
    Nop = 3,
    Unreachable = 6,
    Blackhole = 7,
    Prohibit = 8,
};

pub const FibRule = struct {
    pref: u32,              // Priority
    action: FibRuleAction,
    table: u32,
    flags: u32,
    mark: u32,
    mark_mask: u32,
    iifindex: u32,
    oifindex: u32,
    iifname: [16]u8,
    oifname: [16]u8,
    uid_range_start: u32,
    uid_range_end: u32,
    ip_proto: u8,
    sport_range: [2]u16,
    dport_range: [2]u16,
    // IPv4-specific
    src: Ipv4Addr,
    src_len: u8,
    dst: Ipv4Addr,
    dst_len: u8,
    tos: u8,
    tun_id: u64,
    l3mdev: bool,
    suppress_ifgroup: i32,
    suppress_prefixlen: i32,
    goto_target: ?*FibRule,
    protocol: u8,
    fwmark_set: bool,
};

// ============================================================================
// Nexthop Objects (Modern Routing)
// ============================================================================

pub const NexthopGrpType = enum(u8) {
    Mpath = 0,      // Multipath (ECMP)
    Resilient = 1,  // Resilient hashing
};

pub const NexthopGroup = struct {
    grp_type: NexthopGrpType,
    num_nh: u16,
    is_fdb: bool,
    hash_threshold: bool,
    resilient: bool,
    has_v4: bool,
    entries: [32]NexthopGrpEntry,
    spare_buckets: u16,
    idle_timer: u32,
    unbalanced_timer: u32,
    stats: NexthopGroupStats,
};

pub const NexthopGrpEntry = struct {
    nh_id: u32,
    weight: u8,
    upper_bound: u32,
    nh: ?*Nexthop,
};

pub const Nexthop = struct {
    id: u32,
    protocol: u8,
    is_group: bool,
    is_fdb_nh: bool,
    is_blackhole: bool,
    fib_flags: u32,
    dev_index: u32,
    gw: Ipv4Addr,
    gw6: [16]u8,
    encap_type: LwtEncapType,
    refcnt: u32,
};

pub const NexthopGroupStats = struct {
    packets: u64,
    bytes: u64,
    hw_packets: u64,
    hw_bytes: u64,
};

// ============================================================================
// ECMP / Multipath
// ============================================================================

pub const EcmpHashPolicy = enum(u8) {
    Layer3 = 0,
    Layer4 = 1,
    Layer34 = 2,
    EncapEnabled = 3,
};

pub const EcmpHashFields = packed struct(u32) {
    src_addr: bool,
    dst_addr: bool,
    ip_proto: bool,
    flow_label: bool,
    src_port: bool,
    dst_port: bool,
    inner_src: bool,
    inner_dst: bool,
    inner_ip_proto: bool,
    inner_flow_label: bool,
    inner_src_port: bool,
    inner_dst_port: bool,
    _reserved: u20,
};

pub const MultiPathConfig = struct {
    hash_policy: EcmpHashPolicy,
    hash_fields: EcmpHashFields,
    multipath_hash_seed: u32,
    l3_hash_fields: u32,
    l4_hash_fields: u32,
    fib_multipath_use_neigh: bool,
    fib_multipath_hash_policy: u8,
};

// ============================================================================
// Route Cache / dst_entry
// ============================================================================

pub const DstEntry = struct {
    dev: usize,             // Net device pointer
    ops: ?*DstOps,
    _metrics: usize,
    expires: u64,
    xfrm: usize,           // XFRM state pointer
    input_fn: ?*const fn (*DstEntry) void,
    output_fn: ?*const fn (*DstEntry) void,
    flags: u16,
    obsolete: i16,
    header_len: u16,
    trailer_len: u16,
    __refcnt: i32,
    __use: i32,
    lastuse: u64,
    lwtstate: ?*LwtState,
    error: i32,
    next: ?*DstEntry,
    tclassid: u32,
};

pub const DstOps = struct {
    family: u16,
    gc_thresh: u32,
    gc: ?*const fn () i32,
    check: ?*const fn (*DstEntry, u32) ?*DstEntry,
    default_advmss: ?*const fn (*DstEntry) u32,
    mtu: ?*const fn (*DstEntry) u32,
    cow_metrics: ?*const fn (*DstEntry, u64) ?*u32,
    destroy: ?*const fn (*DstEntry) void,
    ifdown: ?*const fn (*DstEntry, i32) void,
    negative_advice: ?*const fn (*DstEntry) ?*DstEntry,
    link_failure: ?*const fn (*DstEntry) void,
    update_pmtu: ?*const fn (*DstEntry, u32, bool) void,
    redirect: ?*const fn (*DstEntry, usize) void,
    local_out: ?*const fn (*DstEntry) i32,
    neigh_lookup: ?*const fn (*DstEntry, usize) ?*usize,
    confirm_neigh: ?*const fn (*DstEntry, usize) void,
};

// ============================================================================
// RtEntry for IPv4
// ============================================================================

pub const RtableEntry = struct {
    dst: DstEntry,
    rt_genid: i32,
    rt_flags: u32,
    rt_is_input: bool,
    rt_uses_gateway: bool,
    rt_gw_family: u8,
    rt_gw4: Ipv4Addr,
    rt_gw6: [16]u8,
    rt_mtu_locked: bool,
    rt_pmtu: u32,
    rt_type: RtType,
    rt_iif: u32,
    from: ?*FibInfo,
};

pub const RT_CONN_FLAGS = packed struct(u8) {
    rt_tos: u4,
    rt_tos_mask: u4,
};

// ============================================================================
// FIB Notification
// ============================================================================

pub const FibEventType = enum(u8) {
    EntryReplace = 0,
    EntryAppend = 1,
    EntryAdd = 2,
    EntryDel = 3,
    RuleAdd = 4,
    RuleDel = 5,
    NhAdd = 6,
    NhDel = 7,
    NhReplace = 8,
    VifAdd = 9,
    VifDel = 10,
};

pub const FibNotifierInfo = struct {
    family: u8,
    event_type: FibEventType,
    table_id: u32,
    dst: Ipv4Addr,
    dst_len: u8,
    tos: u8,
    rt_type: RtType,
    fi: ?*FibInfo,
};

// ============================================================================
// IP Route Sysctl
// ============================================================================

pub const IpRouteConfig = struct {
    ip_fwd_use_pmtu: bool,
    ip_fwd_update_priority: bool,
    ip_default_ttl: u8,
    ip_no_pmtu_disc: bool,
    ip_rt_gc_timeout: u32,
    ip_rt_gc_interval: u32,
    ip_rt_gc_min_interval: u32,
    ip_rt_gc_elasticity: u32,
    ip_rt_mtu_expires: u32,
    ip_rt_min_pmtu: u32,
    ip_rt_min_advmss: u32,
    ip_rt_redirect_number: u32,
    ip_rt_redirect_load: u32,
    ip_rt_redirect_silence: u32,
    ip_rt_error_cost: u32,
    ip_rt_error_burst: u32,
    fib_multipath_use_neigh: bool,
    fib_multipath_hash_policy: u8,
    fib_notify_on_flag_change: u8,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const Ipv4RoutingManager = struct {
    total_routes: u64,
    total_lookups: u64,
    total_misses: u64,
    total_gc_runs: u64,
    total_rules: u32,
    total_nexthops: u32,
    total_nexthop_groups: u32,
    total_tables: u32,
    total_notifications: u64,
    ecmp_config: MultiPathConfig,
    route_config: IpRouteConfig,
    initialized: bool,

    pub fn init() Ipv4RoutingManager {
        return .{
            .total_routes = 0,
            .total_lookups = 0,
            .total_misses = 0,
            .total_gc_runs = 0,
            .total_rules = 0,
            .total_nexthops = 0,
            .total_nexthop_groups = 0,
            .total_tables = 0,
            .total_notifications = 0,
            .ecmp_config = .{
                .hash_policy = .Layer4,
                .hash_fields = @bitCast(@as(u32, 0x3F)),
                .multipath_hash_seed = 0,
                .l3_hash_fields = 0x3,
                .l4_hash_fields = 0x30,
                .fib_multipath_use_neigh = true,
                .fib_multipath_hash_policy = 1,
            },
            .route_config = .{
                .ip_fwd_use_pmtu = false,
                .ip_fwd_update_priority = true,
                .ip_default_ttl = 64,
                .ip_no_pmtu_disc = false,
                .ip_rt_gc_timeout = 300,
                .ip_rt_gc_interval = 60,
                .ip_rt_gc_min_interval = 0,
                .ip_rt_gc_elasticity = 8,
                .ip_rt_mtu_expires = 600,
                .ip_rt_min_pmtu = 552,
                .ip_rt_min_advmss = 256,
                .ip_rt_redirect_number = 9,
                .ip_rt_redirect_load = 0,
                .ip_rt_redirect_silence = 0,
                .ip_rt_error_cost = 1000,
                .ip_rt_error_burst = 5000,
                .fib_multipath_use_neigh = true,
                .fib_multipath_hash_policy = 1,
                .fib_notify_on_flag_change = 0,
            },
            .initialized = true,
        };
    }
};
