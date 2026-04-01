// Zxyphor Kernel - Conntrack Advanced, Netfilter Tables Internals,
// Connection Tracking Helpers, NAT Engine, Netfilter Hooks Deep,
// nf_tables Expressions, Sets, Chains, Flowtable/Offload,
// Conntrack Zones, Expectation Framework
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Conntrack States & Flags
// ============================================================================

pub const ConntrackState = enum(u8) {
    new = 0,
    established = 1,
    related = 2,
    invalid = 3,
    untracked = 4,
    snat = 5,
    dnat = 6,
    related_reply = 7,
};

pub const ConntrackStatus = packed struct(u32) {
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
    untracked: bool = false,
    helper: bool = false,
    offloaded: bool = false,
    hw_offloaded: bool = false,
    _reserved: u16 = 0,
};

pub const ConntrackProto = enum(u8) {
    tcp = 6,
    udp = 17,
    icmp = 1,
    icmpv6 = 58,
    sctp = 132,
    dccp = 33,
    gre = 47,
    udplite = 136,
    esp = 50,
    ah = 51,
    generic = 255,
};

// ============================================================================
// Connection Tracking Tuple
// ============================================================================

pub const ConntrackTuple = struct {
    src_ip: u128,         // IPv6-capable (v4 mapped)
    dst_ip: u128,
    src_port: u16,
    dst_port: u16,
    protocol: ConntrackProto,
    zone_id: u16,
    direction: TupleDirection,
};

pub const TupleDirection = enum(u1) {
    original = 0,
    reply = 1,
};

pub const ConntrackEntry = struct {
    original: ConntrackTuple,
    reply: ConntrackTuple,
    status: ConntrackStatus,
    timeout: u64,             // jiffies
    mark: u32,
    secmark: u32,
    use_count: u32,
    ct_labels: [4]u32,        // 128-bit label
    helper_name: [32]u8,
    helper_name_len: u8,
    nat_type: NatType,
    nat_range: NatRange,
    // Statistics
    packets_orig: u64,
    bytes_orig: u64,
    packets_reply: u64,
    bytes_reply: u64,
    start_time: u64,
};

pub const NatType = enum(u8) {
    none = 0,
    src = 1,
    dst = 2,
    masquerade = 3,
    redirect = 4,
    full_cone = 5,
    restricted_cone = 6,
    port_restricted = 7,
    symmetric = 8,
};

pub const NatRange = struct {
    min_ip: u128,
    max_ip: u128,
    min_port: u16,
    max_port: u16,
    flags: NatRangeFlags,
};

pub const NatRangeFlags = packed struct(u16) {
    map_ips: bool = false,
    map_ports: bool = false,
    persistent: bool = false,
    proto_random: bool = false,
    proto_random_fully: bool = false,
    proto_offset: bool = false,
    netmap: bool = false,
    _reserved: u9 = 0,
};

// ============================================================================
// Conntrack Zones
// ============================================================================

pub const ConntrackZone = struct {
    id: u16,
    direction: ZoneDirection,
    flags: ZoneFlags,
};

pub const ZoneDirection = enum(u8) {
    both = 0,
    original = 1,
    reply = 2,
};

pub const ZoneFlags = packed struct(u8) {
    override_default: bool = false,
    per_device: bool = false,
    isolated: bool = false,
    _reserved: u5 = 0,
};

// ============================================================================
// Conntrack Expectation
// ============================================================================

pub const ConntrackExpectation = struct {
    master: ConntrackTuple,
    expected_tuple: ConntrackTuple,
    mask: ConntrackTuple,
    class: ExpectationClass,
    flags: ExpectationFlags,
    timeout: u64,
    helper_name: [32]u8,
    helper_name_len: u8,
};

pub const ExpectationClass = enum(u8) {
    default = 0,
    signalling = 1,
    data = 2,
};

pub const ExpectationFlags = packed struct(u8) {
    permanent: bool = false,
    inactive: bool = false,
    userspace: bool = false,
    _reserved: u5 = 0,
};

// ============================================================================
// Conntrack Helpers
// ============================================================================

pub const ConntrackHelper = struct {
    name: [32]u8,
    name_len: u8,
    proto: ConntrackProto,
    port: u16,
    flags: HelperFlags,
    max_expected: u32,
    timeout: u32,
};

pub const HelperFlags = packed struct(u8) {
    auto_assign: bool = false,
    userspace: bool = false,
    _reserved: u6 = 0,
};

pub const BuiltinHelper = enum(u8) {
    ftp = 0,
    tftp = 1,
    irc = 2,
    sip = 3,
    h323 = 4,
    pptp = 5,
    snmp = 6,
    amanda = 7,
    sane = 8,
    // Zxyphor
    zxy_quic = 100,
};

// ============================================================================
// nf_tables Subsystem
// ============================================================================

pub const NftFamily = enum(u8) {
    ipv4 = 2,
    ipv6 = 10,
    inet = 1,
    arp = 7,
    bridge = 3,
    netdev = 5,
};

pub const NftChainType = enum(u8) {
    filter = 0,
    nat = 1,
    route = 2,
};

pub const NftHookNum = enum(u8) {
    prerouting = 0,
    input = 1,
    forward = 2,
    output = 3,
    postrouting = 4,
    ingress = 5,
    egress = 6,
};

pub const NftChainPolicy = enum(u8) {
    accept = 0,
    drop = 1,
};

pub const NftChain = struct {
    name: [64]u8,
    name_len: u8,
    table_name: [64]u8,
    table_name_len: u8,
    family: NftFamily,
    chain_type: NftChainType,
    hook: NftHookNum,
    priority: i32,
    policy: NftChainPolicy,
    flags: NftChainFlags,
    nr_rules: u32,
    use_count: u32,
};

pub const NftChainFlags = packed struct(u16) {
    base_chain: bool = false,
    hw_offload: bool = false,
    dormant: bool = false,
    _reserved: u13 = 0,
};

// ============================================================================
// nf_tables Rules
// ============================================================================

pub const NftRule = struct {
    handle: u64,
    position: u64,
    chain_name: [64]u8,
    chain_name_len: u8,
    nr_expressions: u16,
    comment: [256]u8,
    comment_len: u16,
    flags: NftRuleFlags,
};

pub const NftRuleFlags = packed struct(u8) {
    stateful: bool = false,
    compat: bool = false,
    _reserved: u6 = 0,
};

// ============================================================================
// nf_tables Expressions
// ============================================================================

pub const NftExprType = enum(u16) {
    immediate = 0,
    compare = 1,
    meta = 2,
    payload = 3,
    bitwise = 4,
    byteorder = 5,
    counter = 6,
    ct = 7,          // conntrack
    limit = 8,
    log_expr = 9,
    nat = 10,
    lookup = 11,     // set lookup
    dynset = 12,
    range = 13,
    hash_expr = 14,
    numgen = 15,
    quota = 16,
    reject = 17,
    masquerade = 18,
    redirect = 19,
    dup = 20,
    fwd = 21,
    queue = 22,
    notrack = 23,
    flow_offload = 24,
    connlimit = 25,
    synproxy = 26,
    tproxy = 27,
    objref = 28,
    osf = 29,        // OS fingerprinting
    xfrm = 30,
    socket = 31,
    tunnel = 32,
    fib = 33,
    last = 34,
    // Zxyphor
    zxy_dpi = 100,      // deep packet inspection
    zxy_classify = 101,
    zxy_ratelimit = 102,
};

pub const NftCmpOp = enum(u8) {
    eq = 0,
    neq = 1,
    lt = 2,
    lte = 3,
    gt = 4,
    gte = 5,
};

pub const NftMetaKey = enum(u8) {
    len = 0,
    protocol = 1,
    priority = 2,
    mark = 3,
    iif = 4,
    oif = 5,
    iifname = 6,
    oifname = 7,
    iiftype = 8,
    oiftype = 9,
    skuid = 10,
    skgid = 11,
    nftrace = 12,
    rtclassid = 13,
    secmark = 14,
    nfproto = 15,
    l4proto = 16,
    bri_iifname = 17,
    bri_oifname = 18,
    pkttype = 19,
    cpu = 20,
    iifgroup = 21,
    oifgroup = 22,
    cgroup = 23,
    prandom = 24,
    secpath = 25,
    iifkind = 26,
    oifkind = 27,
    bri_iifpvid = 28,
    bri_iifvproto = 29,
    time_ns = 30,
    time_day = 31,
    time_hour = 32,
    sdif = 33,
    sdifname = 34,
};

// ============================================================================
// nf_tables Sets
// ============================================================================

pub const NftSetType = enum(u8) {
    hash_set = 0,
    rbtree = 1,
    bitmap = 2,
    pipapo = 3,       // PIle PAcker POlice
    concat = 4,
};

pub const NftSet = struct {
    name: [64]u8,
    name_len: u8,
    table_name: [64]u8,
    table_name_len: u8,
    family: NftFamily,
    set_type: NftSetType,
    key_type: u32,
    key_len: u32,
    data_type: u32,
    data_len: u32,
    flags: NftSetFlags,
    policy: NftSetPolicy,
    nr_elements: u32,
    size: u32,           // max elements (0 = unlimited)
    timeout: u64,
    gc_interval: u32,
};

pub const NftSetFlags = packed struct(u16) {
    anonymous: bool = false,
    constant: bool = false,
    interval: bool = false,
    map: bool = false,
    timeout_flag: bool = false,
    eval: bool = false,
    object: bool = false,
    concat: bool = false,
    _reserved: u8 = 0,
};

pub const NftSetPolicy = enum(u8) {
    performance = 0,
    memory = 1,
};

// ============================================================================
// nf_tables Objects
// ============================================================================

pub const NftObjType = enum(u8) {
    counter = 0,
    quota = 1,
    ct_helper = 2,
    limit = 3,
    connlimit = 4,
    tunnel = 5,
    ct_timeout = 6,
    secmark = 7,
    ct_expect = 8,
    synproxy = 9,
};

pub const NftCounter = struct {
    packets: u64,
    bytes: u64,
};

pub const NftQuota = struct {
    bytes: u64,
    used: u64,
    flags: QuotaFlags,
};

pub const QuotaFlags = packed struct(u8) {
    depleted: bool = false,
    inverse: bool = false,
    _reserved: u6 = 0,
};

pub const NftLimit = struct {
    rate: u64,
    unit: LimitUnit,
    burst: u32,
    limit_type: LimitType,
    flags: LimitFlags,
};

pub const LimitUnit = enum(u8) {
    second = 0,
    minute = 1,
    hour = 2,
    day = 3,
    week = 4,
};

pub const LimitType = enum(u8) {
    pkts = 0,
    bytes = 1,
};

pub const LimitFlags = packed struct(u8) {
    inverse: bool = false,
    _reserved: u7 = 0,
};

// ============================================================================
// Flow/Hardware Offload
// ============================================================================

pub const NftFlowtable = struct {
    name: [64]u8,
    name_len: u8,
    table_name: [64]u8,
    table_name_len: u8,
    family: NftFamily,
    hook: NftHookNum,
    priority: i32,
    flags: FlowtableFlags,
    nr_devices: u32,
    device_names: [16][16]u8,
    device_name_lens: [16]u8,
};

pub const FlowtableFlags = packed struct(u16) {
    hw_offload: bool = false,
    counter: bool = false,
    _reserved: u14 = 0,
};

// ============================================================================
// Netfilter Verdict
// ============================================================================

pub const NfVerdict = enum(i32) {
    drop = 0,
    accept = 1,
    stolen = 2,
    queue = 3,
    repeat = 4,
    stop = 5,
    // nf_tables extended verdicts (negative)
    nft_continue = -1,
    nft_break = -2,
    nft_jump = -3,
    nft_goto = -4,
    nft_return = -5,
};

// ============================================================================
// Conntrack Hash Table
// ============================================================================

pub const ConntrackHashConfig = struct {
    hash_size: u32,        // number of buckets
    max_entries: u32,
    expect_max: u32,
    acct_enabled: bool,
    timestamp_enabled: bool,
    ecache_enabled: bool,
    helper_auto_assign: bool,
    tcp_loose: bool,
    tcp_be_liberal: bool,
    tcp_max_retrans: u8,
    tcp_timeout_syn_sent: u32,
    tcp_timeout_syn_recv: u32,
    tcp_timeout_established: u32,
    tcp_timeout_fin_wait: u32,
    tcp_timeout_close_wait: u32,
    tcp_timeout_last_ack: u32,
    tcp_timeout_time_wait: u32,
    tcp_timeout_close: u32,
    tcp_timeout_unack: u32,
    udp_timeout: u32,
    udp_timeout_stream: u32,
    icmp_timeout: u32,
    generic_timeout: u32,
};

impl ConntrackHashConfig {
    pub const DEFAULT: ConntrackHashConfig = .{
        .hash_size = 16384,
        .max_entries = 262144,
        .expect_max = 1024,
        .acct_enabled = true,
        .timestamp_enabled = false,
        .ecache_enabled = true,
        .helper_auto_assign = false,
        .tcp_loose = true,
        .tcp_be_liberal = false,
        .tcp_max_retrans = 3,
        .tcp_timeout_syn_sent = 120,
        .tcp_timeout_syn_recv = 60,
        .tcp_timeout_established = 432000,
        .tcp_timeout_fin_wait = 120,
        .tcp_timeout_close_wait = 60,
        .tcp_timeout_last_ack = 30,
        .tcp_timeout_time_wait = 120,
        .tcp_timeout_close = 10,
        .tcp_timeout_unack = 300,
        .udp_timeout = 30,
        .udp_timeout_stream = 180,
        .icmp_timeout = 30,
        .generic_timeout = 600,
    };
};

// ============================================================================
// Conntrack Statistics
// ============================================================================

pub const ConntrackStats = struct {
    found: u64,
    invalid: u64,
    insert: u64,
    insert_failed: u64,
    drop: u64,
    early_drop: u64,
    error: u64,
    search_restart: u64,
    clash_resolve: u64,
    // nf_tables stats
    nft_chain_evaluated: u64,
    nft_rule_matched: u64,
    nft_set_lookup: u64,
    nft_set_lookup_miss: u64,
    nft_flowtable_offloaded: u64,
};

impl ConntrackStats {
    pub const ZERO: ConntrackStats = .{
        .found = 0,
        .invalid = 0,
        .insert = 0,
        .insert_failed = 0,
        .drop = 0,
        .early_drop = 0,
        .error = 0,
        .search_restart = 0,
        .clash_resolve = 0,
        .nft_chain_evaluated = 0,
        .nft_rule_matched = 0,
        .nft_set_lookup = 0,
        .nft_set_lookup_miss = 0,
        .nft_flowtable_offloaded = 0,
    };
};

// ============================================================================
// Netfilter Conntrack Manager (Zxyphor)
// ============================================================================

pub const ConntrackManager = struct {
    config: ConntrackHashConfig,
    stats: ConntrackStats,
    nr_entries: u32,
    nr_expect: u32,
    nr_zones: u16,
    nr_helpers: u16,
    nr_tables: u16,
    nr_chains: u32,
    nr_rules: u64,
    nr_sets: u32,
    nr_flowtables: u16,
    initialized: bool,

    pub fn init(config: ConntrackHashConfig) -> ConntrackManager {
        return .{
            .config = config,
            .stats = ConntrackStats.ZERO,
            .nr_entries = 0,
            .nr_expect = 0,
            .nr_zones = 1,
            .nr_helpers = 0,
            .nr_tables = 0,
            .nr_chains = 0,
            .nr_rules = 0,
            .nr_sets = 0,
            .nr_flowtables = 0,
            .initialized = true,
        };
    }
};
