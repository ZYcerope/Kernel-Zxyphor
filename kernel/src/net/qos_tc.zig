// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Network QoS, Traffic Control, Packet Scheduling,
// Classful/Classless Qdiscs, Traffic Policing, Shaping, ECN
// More advanced than Linux 2026 traffic control

const std = @import("std");

// ============================================================================
// Qdisc Types
// ============================================================================

/// Qdisc type
pub const QdiscType = enum(u16) {
    // Classless
    pfifo_fast = 0,
    bfifo = 1,
    pfifo = 2,
    fq_codel = 3,
    sfq = 4,
    tbf = 5,
    red = 6,
    netem = 7,
    noqueue = 8,
    pfifo_head_drop = 9,
    multiq = 10,
    plug = 11,
    cake = 12,
    // Classful
    htb = 20,
    hfsc = 21,
    prio = 22,
    cbq = 23,
    drr = 24,
    qfq = 25,
    ets = 26,
    // Zxyphor
    zxy_adaptive = 100,
    zxy_ml_sched = 101,
    zxy_deadline = 102,
};

/// Qdisc handle (major:minor)
pub const QdiscHandle = struct {
    major: u16,
    minor: u16,

    pub fn fromU32(handle: u32) QdiscHandle {
        return .{
            .major = @intCast(handle >> 16),
            .minor = @intCast(handle & 0xFFFF),
        };
    }

    pub fn toU32(self: QdiscHandle) u32 {
        return (@as(u32, self.major) << 16) | @as(u32, self.minor);
    }

    pub const TC_H_ROOT: u32 = 0xFFFFFFFF;
    pub const TC_H_INGRESS: u32 = 0xFFFFFFF1;
    pub const TC_H_CLSACT: u32 = 0xFFFFFFF2;
};

/// Qdisc flags
pub const QdiscFlags = packed struct {
    noparent: bool = false,
    ingress: bool = false,
    offloaded: bool = false,
    no_percpu_stats: bool = false,
    running: bool = false,
    warn_nonforced_dequeue: bool = false,
    // Zxyphor
    zxy_priority_boost: bool = false,
    zxy_adaptive: bool = false,
    _padding: u8 = 0,
};

// ============================================================================
// HTB (Hierarchical Token Bucket)
// ============================================================================

/// HTB global parameters
pub const HtbGlobal = struct {
    version: u32,         // 3
    rate2quantum: u32,    // Default 10
    defcls: u32,          // Default class
    direct_pkts: u32,
    debug: u32,
};

/// HTB class parameters
pub const HtbClassOpt = struct {
    // Rate parameters
    rate: TcRateSpec,     // Guaranteed rate
    ceil: TcRateSpec,     // Maximum rate
    // Buffer/cbuffer (in usec)
    buffer: u32,
    cbuffer: u32,
    // Quantum
    quantum: u32,
    // Priority (0-7, lower = higher)
    prio: u32,
    // Level in hierarchy
    level: u32,
};

/// TC rate specification
pub const TcRateSpec = struct {
    cell_log: u8,
    linklayer: u8,        // TC_LINKLAYER_*
    overhead: u16,
    cell_align: i16,
    mpu: u16,
    rate: u32,            // Bytes per second
};

/// HTB class stats
pub const HtbClassStats = struct {
    lends: u32,
    borrows: u32,
    giants: u32,
    tokens: i32,
    ctokens: i32,
};

// ============================================================================
// CAKE (Common Applications Kept Enhanced)
// ============================================================================

/// CAKE bandwidth mode
pub const CakeBandwidthMode = enum(u8) {
    unlimited = 0,
    rate = 1,
    autorate_ingress = 2,
};

/// CAKE flow mode
pub const CakeFlowMode = enum(u8) {
    none = 0,
    src_ip = 1,
    dst_ip = 2,
    hosts = 3,
    flows = 4,
    dual_src = 5,
    dual_dst = 6,
    triple = 7,
};

/// CAKE diffserv mode
pub const CakeDiffservMode = enum(u8) {
    diffserv3 = 0,
    diffserv4 = 1,
    diffserv8 = 2,
    besteffort = 3,
    precedence = 4,
};

/// CAKE NAT mode
pub const CakeNatMode = enum(u8) {
    no_nat = 0,
    nat = 1,
    no_wash = 2,
    wash = 3,
};

/// CAKE ATM mode
pub const CakeAtmMode = enum(u8) {
    no_atm = 0,
    atm = 1,
    ptm = 2,
};

/// CAKE parameters
pub const CakeConfig = struct {
    bandwidth: u64,       // Bits per second (0 = unlimited)
    bandwidth_mode: CakeBandwidthMode,
    flow_mode: CakeFlowMode,
    diffserv_mode: CakeDiffservMode,
    nat_mode: CakeNatMode,
    atm_mode: CakeAtmMode,
    // RTT estimate
    rtt: u32,             // Microseconds
    // Overhead
    overhead: i32,        // Bytes
    mpu: u32,             // Minimum packet unit
    // Split GSO
    split_gso: bool,
    // Zxyphor
    zxy_adaptive_rtt: bool,
    zxy_ecn_threshold: u32,
};

/// CAKE statistics
pub const CakeStats = struct {
    // Per-tin stats
    capacity_estimate: u64,
    memory_usage: u32,
    memory_limit: u32,
    // Drops
    drop_overlimit: u32,
    ecn_mark: u32,
    // Delays
    base_delay_ns: u64,
    peak_delay_ns: u64,
    avg_delay_ns: u64,
    // Sparse flows
    sparse_flows: u32,
    bulk_flows: u32,
    unresponsive_flows: u32,
    // Cobalt (AQM)
    cobalt_count: u32,
    cobalt_drop_count: u32,
    cobalt_blue_drop: u32,
};

// ============================================================================
// FQ-CoDel (Fair Queuing Controlled Delay)
// ============================================================================

/// FQ-CoDel parameters
pub const FqCodelConfig = struct {
    target: u32,          // CoDel target delay (microseconds, default 5000)
    limit: u32,           // Queue limit (packets, default 10240)
    interval: u32,        // CoDel interval (microseconds, default 100000)
    ecn: bool,            // ECN marking enabled
    quantum: u32,         // DRR quantum (default: interface MTU)
    flows: u32,           // Number of flow queues (default 1024)
    memory_limit: u32,    // Memory limit (bytes)
    ce_threshold: u32,    // CE marking threshold (microseconds)
    drop_batch_size: u32, // Drop batch size
};

/// FQ-CoDel flow stats
pub const FqCodelFlowStats = struct {
    flow_index: u32,
    qlen: u32,
    backlog: u32,
    drop_overlimit: u32,
    drop_next: u32,
    dropping: bool,
    new_flow: bool,
    delay: u32,           // Current delay estimate
};

/// FQ-CoDel global stats
pub const FqCodelGlobalStats = struct {
    maxpacket: u32,
    ecn_mark: u32,
    new_flow_count: u32,
    new_flows_len: u32,
    old_flows_len: u32,
    ce_mark: u32,
    memory_usage: u32,
    drop_overmemory: u32,
};

// ============================================================================
// RED (Random Early Detection)
// ============================================================================

/// RED parameters
pub const RedConfig = struct {
    limit: u32,           // Hard queue limit (bytes)
    qth_min: u32,         // Min threshold (bytes)
    qth_max: u32,         // Max threshold (bytes)
    wlog: u8,             // log2(W) - bandwidth filter
    plog: u8,             // log2(1/Pmax)
    scell_log: u8,        // Cell size for idle damping
    flags: RedFlags,
};

/// RED flags
pub const RedFlags = packed struct {
    ecn: bool = false,
    harddrop: bool = false,
    adaptative: bool = false,
    nodrop: bool = false,
    _padding: u4 = 0,
};

// ============================================================================
// NETEM (Network Emulator)
// ============================================================================

/// Netem parameters
pub const NetemConfig = struct {
    // Latency
    latency: u32,         // Added delay (microseconds)
    jitter: u32,          // Jitter (microseconds)
    // Loss
    loss: u32,            // Loss probability (0-100%)
    loss_correlation: u32,
    // Duplication
    duplicate: u32,       // Duplicate probability
    dup_correlation: u32,
    // Reordering
    reorder: u32,         // Reorder probability
    reorder_correlation: u32,
    gap: u32,             // Reorder gap
    // Corruption
    corrupt: u32,         // Corruption probability
    corrupt_correlation: u32,
    // Rate
    rate: u64,            // Rate limit (bytes/sec)
    packet_overhead: i32,
    cell_size: u32,
    cell_overhead: i32,
    // Slot
    slot_min_delay: u64,
    slot_max_delay: u64,
    slot_max_packets: u32,
    slot_max_bytes: u32,
    // Distribution
    dist_type: NetemDistType,
};

/// Netem distribution type
pub const NetemDistType = enum(u8) {
    uniform = 0,
    normal = 1,
    pareto = 2,
    paretonormal = 3,
    experimental = 4,
};

// ============================================================================
// TBF (Token Bucket Filter)
// ============================================================================

/// TBF parameters
pub const TbfConfig = struct {
    rate: TcRateSpec,
    peak: TcRateSpec,     // Peak rate (optional)
    limit: u32,           // Bytes
    buffer: u32,          // Bucket depth (bytes)
    mtu: u32,             // Maximum token unit
};

// ============================================================================
// ECN (Explicit Congestion Notification)
// ============================================================================

/// ECN codepoint (IP header)
pub const EcnCodepoint = enum(u2) {
    not_ect = 0b00,
    ect1 = 0b01,
    ect0 = 0b10,
    ce = 0b11,
};

/// ECN statistics (per interface)
pub const EcnStats = struct {
    ect0_received: u64,
    ect1_received: u64,
    ce_received: u64,
    not_ect_received: u64,
    ce_marked: u64,       // Packets we marked CE
    // TCP ECN
    tcp_ece_sent: u64,
    tcp_cwr_sent: u64,
    tcp_ece_received: u64,
    tcp_cwr_received: u64,
    // L4S/AccECN
    accecn_capable: u64,
    accecn_bytes_ce: u64,
};

// ============================================================================
// TC Filters
// ============================================================================

/// TC filter type
pub const TcFilterType = enum(u8) {
    u32_filter = 0,
    flower = 1,
    bpf = 2,
    matchall = 3,
    fw = 4,
    route = 5,
    cgroup = 6,
    basic = 7,
    // Zxyphor
    zxy_ml = 100,
};

/// TC flower key flags
pub const FlowerKeyFlags = packed struct {
    eth_dst: bool = false,
    eth_src: bool = false,
    vlan_id: bool = false,
    vlan_prio: bool = false,
    ip_proto: bool = false,
    ipv4_src: bool = false,
    ipv4_dst: bool = false,
    ipv6_src: bool = false,
    ipv6_dst: bool = false,
    tcp_src: bool = false,
    tcp_dst: bool = false,
    udp_src: bool = false,
    udp_dst: bool = false,
    tcp_flags: bool = false,
    ip_tos: bool = false,
    ip_ttl: bool = false,
    // Additional
    ct_state: bool = false,
    ct_zone: bool = false,
    ct_mark: bool = false,
    ct_labels: bool = false,
    // MPLS
    mpls_label: bool = false,
    mpls_tc: bool = false,
    mpls_bos: bool = false,
    mpls_ttl: bool = false,
    // L2TP
    l2tpv3_sid: bool = false,
    // PPPoE
    pppoe_sid: bool = false,
    // GTP
    gtp_teid: bool = false,
    // Zxyphor
    zxy_app_id: bool = false,
    _padding: u4 = 0,
};

// ============================================================================
// TC Actions
// ============================================================================

/// TC action type
pub const TcActionType = enum(u8) {
    gact = 0,            // Generic action
    mirred = 1,          // Mirror/redirect
    pedit = 2,           // Packet edit
    nat = 3,             // NAT
    vlan = 4,            // VLAN push/pop
    tunnel_key = 5,      // Tunnel encap
    ct = 6,              // Conntrack
    csum = 7,            // Checksum
    skbedit = 8,         // skb edit
    mpls = 9,            // MPLS push/pop
    gate = 10,           // TSN gate
    sample = 11,         // Packet sampling
    police = 12,         // Policing
    connmark = 13,       // Connection mark
    ctinfo = 14,         // CT info
    skbmod = 15,         // SKB modification
    // Zxyphor
    zxy_qos_mark = 100,
};

/// TC police parameters
pub const TcPoliceConfig = struct {
    rate: TcRateSpec,
    peakrate: TcRateSpec,
    burst: u32,           // Bytes
    mtu: u32,
    // Actions
    action: TcPoliceAction,
    // Conform/exceed
    conform_action: TcPoliceAction,
    exceed_action: TcPoliceAction,
    // Counters
    bytes_conform: u64,
    bytes_exceed: u64,
    pkts_conform: u64,
    pkts_exceed: u64,
};

/// TC police action
pub const TcPoliceAction = enum(i32) {
    unspec = -1,
    ok = 0,
    reclassify = 1,
    shot = 2,
    pipe = 3,
};

// ============================================================================
// DiffServ
// ============================================================================

/// DSCP values
pub const DscpValue = enum(u8) {
    // Default
    cs0 = 0,             // Best Effort
    // Class Selector
    cs1 = 8,
    cs2 = 16,
    cs3 = 24,
    cs4 = 32,
    cs5 = 40,
    cs6 = 48,
    cs7 = 56,
    // Assured Forwarding
    af11 = 10,
    af12 = 12,
    af13 = 14,
    af21 = 18,
    af22 = 20,
    af23 = 22,
    af31 = 26,
    af32 = 28,
    af33 = 30,
    af41 = 34,
    af42 = 36,
    af43 = 38,
    // Expedited Forwarding
    ef = 46,
    // Voice Admit
    voice_admit = 44,
    // LE (Lower Effort)
    le = 1,
};

// ============================================================================
// QoS Subsystem Manager
// ============================================================================

pub const QosSubsystem = struct {
    // Qdiscs
    nr_qdiscs: u64,
    nr_classes: u64,
    nr_filters: u64,
    nr_actions: u64,
    // Per-type counts
    nr_htb: u32,
    nr_fq_codel: u32,
    nr_cake: u32,
    nr_tbf: u32,
    nr_red: u32,
    nr_netem: u32,
    // Statistics
    total_enqueued: u64,
    total_dequeued: u64,
    total_dropped: u64,
    total_overlimits: u64,
    total_requeues: u64,
    total_backlog_bytes: u64,
    // ECN
    total_ecn_marks: u64,
    // Offload
    nr_offloaded: u32,
    // Zxyphor
    zxy_adaptive_enabled: bool,
    zxy_ml_sched_enabled: bool,
    initialized: bool,

    pub fn init() QosSubsystem {
        return QosSubsystem{
            .nr_qdiscs = 0,
            .nr_classes = 0,
            .nr_filters = 0,
            .nr_actions = 0,
            .nr_htb = 0,
            .nr_fq_codel = 0,
            .nr_cake = 0,
            .nr_tbf = 0,
            .nr_red = 0,
            .nr_netem = 0,
            .total_enqueued = 0,
            .total_dequeued = 0,
            .total_dropped = 0,
            .total_overlimits = 0,
            .total_requeues = 0,
            .total_backlog_bytes = 0,
            .total_ecn_marks = 0,
            .nr_offloaded = 0,
            .zxy_adaptive_enabled = true,
            .zxy_ml_sched_enabled = true,
            .initialized = false,
        };
    }
};
