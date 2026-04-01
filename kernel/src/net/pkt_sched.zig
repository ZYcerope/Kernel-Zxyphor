// SPDX-License-Identifier: MIT
// Zxyphor Kernel - AF_PACKET, Packet Scheduler (tc), Traffic Control,
// qdisc, class, filter, BPF socket filter, raw sockets
// More advanced than Linux 2026 traffic control

const std = @import("std");

// ============================================================================
// AF_PACKET - Raw Packet Access
// ============================================================================

/// Packet socket type
pub const PacketSocketType = enum(u8) {
    raw = 0, // SOCK_RAW
    dgram = 1, // SOCK_DGRAM (cooked)
};

/// Packet version
pub const PacketVersion = enum(u8) {
    v1 = 0, // TPACKET_V1
    v2 = 1, // TPACKET_V2
    v3 = 2, // TPACKET_V3
};

/// Packet flags
pub const PacketFlags = packed struct {
    copy_thresh: bool = false,
    origdev: bool = false,
    auxdata: bool = false,
    fanout: bool = false,
    tx_ring: bool = false,
    rx_ring: bool = false,
    qdisc_bypass: bool = false,
    timestamp: bool = false,
    loss: bool = false,
    vnet_hdr: bool = false,
    // Zxyphor
    zxy_zero_copy: bool = false,
    zxy_hw_timestamp: bool = false,
    _padding: u4 = 0,
};

/// Packet fanout type
pub const PacketFanout = enum(u8) {
    hash = 0,
    lb = 1,
    cpu = 2,
    rollover = 3,
    rnd = 4,
    qm = 5,
    cbpf = 6,
    ebpf = 7,
    // Zxyphor
    zxy_flow_aware = 10,
};

/// TPACKET header V3
pub const TpacketHdrV3 = struct {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    // V3 specific
    hv1_rxhash: u32,
    tp_vlan_tci: u32,
    tp_vlan_tpid: u16,
    tp_padding: u16,
};

/// Packet ring request
pub const TpacketReq3 = struct {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
};

/// Packet socket stats
pub const PacketSocketStats = struct {
    // RX
    rx_packets: u64,
    rx_bytes: u64,
    rx_drops: u64,
    rx_freeze_q_cnt: u64,
    // TX
    tx_packets: u64,
    tx_bytes: u64,
    tx_drops: u64,
    // Ring
    rx_ring_full: u64,
    tx_ring_empty: u64,
    // Fanout
    fanout_rebalance: u64,
};

// ============================================================================
// Traffic Control - Queueing Disciplines
// ============================================================================

/// Qdisc type
pub const QdiscType = enum(u8) {
    // Classless
    pfifo = 0,
    bfifo = 1,
    pfifo_fast = 2,
    fq = 3, // Fair Queuing
    fq_codel = 4, // Fair Queuing with CoDel
    sfq = 5, // Stochastic Fairness
    tbf = 6, // Token Bucket Filter
    netem = 7, // Network Emulator
    cake = 8, // Common Applications Kept Enhanced
    noqueue = 9,
    red = 10, // Random Early Detection
    gred = 11, // Generalized RED
    sfb = 12, // Stochastic Fair Blue
    choke = 13,
    pie = 14, // Proportional Integral controller Enhanced
    hhf = 15, // Heavy Hitter Filter
    fq_pie = 16,
    // Classful
    prio = 20,
    htb = 21, // Hierarchy Token Bucket
    hfsc = 22, // Hierarchical Fair Service Curve
    cbq = 23, // Class Based Queueing
    drr = 24, // Deficit Round Robin
    qfq = 25, // Quick Fair Queueing
    mqprio = 26, // Multi-Queue Priority
    ets = 27, // Enhanced Transmission Selection
    taprio = 28, // Time-Aware Priority Shaper (TSN)
    // Multiqueue
    mq = 30,
    multiq = 31,
    // Ingress
    ingress = 40,
    clsact = 41,
    // Zxyphor
    zxy_adaptive = 50, // ML-based adaptive qdisc
    zxy_deadline = 51, // Deadline-aware scheduling
    zxy_latency = 52, // Ultra-low latency
};

/// TC handle (major:minor)
pub const TcHandle = struct {
    major: u16,
    minor: u16,

    pub fn from_u32(handle: u32) TcHandle {
        return .{
            .major = @intCast(handle >> 16),
            .minor = @intCast(handle & 0xFFFF),
        };
    }

    pub fn to_u32(self: TcHandle) u32 {
        return (@as(u32, self.major) << 16) | @as(u32, self.minor);
    }

    pub fn root() TcHandle {
        return .{ .major = 0xFFFF, .minor = 0xFFFF };
    }

    pub fn ingress_handle() TcHandle {
        return .{ .major = 0xFFFF, .minor = 0xFFF1 };
    }
};

/// Qdisc statistics
pub const QdiscStats = struct {
    // Basic
    bytes: u64,
    packets: u64,
    drops: u64,
    overlimits: u64,
    requeues: u64,
    // Queue
    qlen: u32,
    backlog: u32,
    // Rate
    bps: u64,
    pps: u64,
};

/// Qdisc basic stats2
pub const QdiscStats2 = struct {
    bytes: u64,
    packets: u64,
    qlen: u32,
    backlog: u32,
    drops: u64,
    requeues: u64,
    overlimits: u64,
    // ECN
    ecn_mark: u64,
    // Detailed
    hw_offloaded: bool,
};

// ============================================================================
// Specific Qdisc Configurations
// ============================================================================

/// FQ (Fair Queuing) config
pub const FqConfig = struct {
    plimit: u32, // Queue limit
    flow_plimit: u32,
    quantum: u32,
    initial_quantum: u32,
    rate_enable: bool,
    flow_default_rate: u64,
    flow_max_rate: u64,
    buckets_log: u8,
    low_rate_threshold: u64,
    ce_threshold: u64,
    timer_slack: u64,
    // Pacing
    pacing_enabled: bool,
    pacing_shift: u8,
    // Horizon
    horizon: u64,
    horizon_drop: bool,
    // Stats
    gc_flows: u64,
    highprio_packets: u64,
    fastpath_packets: u64,
    stat_band_drops: [3]u64,
    stat_ce_mark: u64,
    stat_flows_plimit: u64,
    stat_pkts_too_long: u64,
    stat_allocation_errors: u64,
    stat_flows: u64,
    stat_inactive_flows: u64,
    stat_throttled: u64,
};

/// FQ-CoDel config
pub const FqCodelConfig = struct {
    target: u32, // microseconds (default 5000)
    limit: u32,
    interval: u32,
    ecn: bool,
    quantum: u32,
    ce_threshold: u32,
    drop_batch_size: u32,
    memory_limit: u32,
    flows: u32,
    // Stats
    maxpacket: u32,
    drop_overlimit: u64,
    ecn_mark: u64,
    new_flow_count: u64,
    new_flows_len: u32,
    old_flows_len: u32,
    ce_mark: u64,
    memory_usage: u64,
    drop_overmemory: u64,
};

/// CAKE (Common Applications Kept Enhanced) config
pub const CakeConfig = struct {
    bandwidth: u64, // bytes/sec
    tin_mode: CakeTinMode,
    flow_mode: CakeFlowMode,
    ack_filter: CakeAckFilter,
    nat: bool,
    wash: bool,
    ingress: bool,
    split_gso: bool,
    fwmark: u32,
    // ATM compensation
    atm: CakeAtm,
    overhead: i32,
    mpu: u32,
    // RTT
    rtt: u32, // microseconds
    // Memory
    memory_limit: u64,
    memory_used: u64,
    // Stats (per tin)
    tin_stats: [8]CakeTinStats,
    nr_tins: u8,
};

/// CAKE tin mode
pub const CakeTinMode = enum(u8) {
    diffserv3 = 0,
    diffserv4 = 1,
    diffserv8 = 2,
    besteffort = 3,
    precedence = 4,
    // Zxyphor
    zxy_adaptive = 10,
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

/// CAKE ACK filter
pub const CakeAckFilter = enum(u8) {
    no = 0,
    yes = 1,
    aggressive = 2,
};

/// CAKE ATM compensation
pub const CakeAtm = enum(u8) {
    nocomp = 0,
    atm = 1,
    ptm = 2,
};

/// CAKE per-tin statistics
pub const CakeTinStats = struct {
    threshold_rate: u64,
    sent_bytes: u64,
    sent_packets: u64,
    dropped_bytes: u64,
    dropped_packets: u64,
    ecn_marked_packets: u64,
    ack_drops: u64,
    peak_delay_us: u32,
    avg_delay_us: u32,
    base_delay_us: u32,
    way_indirect_hits: u64,
    way_misses: u64,
    way_collisions: u64,
    sparse_flows: u32,
    bulk_flows: u32,
    unresponsive_flows: u32,
};

/// HTB (Hierarchy Token Bucket) config
pub const HtbConfig = struct {
    rate: u64,         // bytes/sec
    ceil: u64,         // max rate
    burst: u32,        // bytes
    cburst: u32,       // ceil burst
    quantum: u32,
    prio: u8,
    level: u8,
    // Direct queueing
    direct_qlen: u32,
    direct_pkts: u64,
    // Stats
    tokens: i64,
    ctokens: i64,
    lends: u64,
    borrows: u64,
    giants: u64,
};

/// TBF (Token Bucket Filter) config
pub const TbfConfig = struct {
    rate: u64,         // bytes/sec
    burst: u32,        // bytes
    limit: u32,
    mtu: u32,
    peakrate: u64,
    minburst: u32,
    // Stats
    tokens: i64,
    ptokens: i64,
};

/// netem (Network Emulator) config
pub const NetemConfig = struct {
    // Delay
    latency_us: u32,
    jitter_us: u32,
    // Loss
    loss_pct: u32, // 0-100000 (0.001% granularity)
    loss_correlation_pct: u32,
    // Duplicate
    duplicate_pct: u32,
    duplicate_correlation_pct: u32,
    // Reorder
    reorder_pct: u32,
    reorder_correlation_pct: u32,
    // Corrupt
    corrupt_pct: u32,
    corrupt_correlation_pct: u32,
    // Gap
    gap: u32,
    // Rate
    rate: u64,
    rate_packet_overhead: i32,
    rate_cell_size: u32,
    rate_cell_overhead: i32,
    // Slot
    slot_min_delay_us: u32,
    slot_max_delay_us: u32,
    slot_max_packets: u32,
    slot_max_bytes: u32,
    // Distribution
    dist_type: NetemDist,
};

/// netem distribution
pub const NetemDist = enum(u8) {
    uniform = 0,
    normal = 1,
    pareto = 2,
    paretonormal = 3,
    custom = 4,
};

/// TAPRIO (Time-Aware Priority Shaper) for TSN
pub const TaprioConfig = struct {
    // Schedule
    base_time: i64,     // nanoseconds
    cycle_time: i64,
    cycle_time_extension: i64,
    // Entries
    nr_entries: u32,
    // Flags
    txtime_delay: u32,
    flags: TaprioFlags,
    // Clock
    clockid: i32,
};

/// TAPRIO schedule entry
pub const TaprioEntry = struct {
    command: TaprioCommand,
    gate_mask: u32,     // one bit per traffic class
    interval: u32,      // nanoseconds
};

/// TAPRIO command
pub const TaprioCommand = enum(u8) {
    set_gate_states = 0,
    set_and_hold = 1,
    set_and_release = 2,
};

/// TAPRIO flags
pub const TaprioFlags = packed struct {
    txtime_assist: bool = false,
    full_offload: bool = false,
    _padding: u6 = 0,
};

// ============================================================================
// TC Filters
// ============================================================================

/// TC filter type
pub const TcFilterType = enum(u8) {
    u32_filter = 0,
    flower = 1,
    bpf = 2,
    cgroup = 3,
    fw = 4,
    route = 5,
    basic = 6,
    matchall = 7,
    // Zxyphor
    zxy_ml = 10, // ML-based classifier
};

/// TC flower filter match
pub const FlowerKey = struct {
    eth_type: u16,
    ip_proto: u8,
    // L2
    src_mac: [6]u8,
    dst_mac: [6]u8,
    vlan_id: u16,
    vlan_prio: u8,
    cvlan_id: u16,
    // L3 (IPv4)
    src_ip: u32,
    dst_ip: u32,
    src_ip_mask: u32,
    dst_ip_mask: u32,
    // L3 (IPv6)
    src_ip6: [16]u8,
    dst_ip6: [16]u8,
    src_ip6_mask: [16]u8,
    dst_ip6_mask: [16]u8,
    // L4
    src_port: u16,
    dst_port: u16,
    src_port_mask: u16,
    dst_port_mask: u16,
    // TCP flags
    tcp_flags: u16,
    tcp_flags_mask: u16,
    // TOS / DSCP
    ip_tos: u8,
    ip_tos_mask: u8,
    ip_ttl: u8,
    ip_ttl_mask: u8,
    // MPLS
    mpls_lse: [4]MplsLse,
    nr_mpls: u8,
    // GRE/tunnel
    enc_key_id: u32,
    enc_src_ip: u32,
    enc_dst_ip: u32,
    enc_src_port: u16,
    enc_dst_port: u16,
    // Conntrack
    ct_state: u16,
    ct_zone: u16,
    ct_mark: u32,
    ct_labels: [16]u8,
    // Metadata
    meta_priority: u32,
};

/// MPLS Label Stack Entry
pub const MplsLse = struct {
    label: u32,
    tc: u3,
    bos: u1,
    ttl: u8,
};

/// TC action type
pub const TcActionType = enum(u8) {
    ok = 0,
    reclassify = 1,
    shot = 2,
    pipe = 3,
    stolen = 4,
    queued = 5,
    repeat = 6,
    redirect = 7,
    trap = 8,
};

/// TC action
pub const TcAction = enum(u8) {
    gact = 0,       // Generic action
    mirred = 1,     // Mirror/redirect
    pedit = 2,      // Packet edit
    vlan = 3,       // VLAN push/pop
    tunnel_key = 4, // Tunnel encap/decap
    csum = 5,       // Checksum
    nat = 6,        // NAT
    ct = 7,         // Conntrack
    police = 8,     // Rate policing
    sample = 9,     // Packet sampling
    skbedit = 10,   // sk_buff editing
    mpls = 11,      // MPLS
    gate = 12,      // Time gate (TSN)
    connmark = 13,
    ctinfo = 14,
    // Zxyphor
    zxy_classify = 50,
};

/// TC police action
pub const TcPolice = struct {
    rate: u64,       // bytes/sec
    burst: u32,      // bytes
    mtu: u32,
    peakrate: u64,
    // Action
    exceed_action: TcActionType,
    notexceed_action: TcActionType,
    // Mark
    conform_dscp: u8,
    exceed_dscp: u8,
    // Stats
    conform_packets: u64,
    conform_bytes: u64,
    exceed_packets: u64,
    exceed_bytes: u64,
};

// ============================================================================
// BPF Socket Filter
// ============================================================================

/// BPF socket attach type
pub const BpfSocketAttachType = enum(u8) {
    filter = 0,        // SO_ATTACH_FILTER
    reuseport = 1,     // SO_ATTACH_REUSEPORT_EBPF
    // TC
    tc_ingress = 10,
    tc_egress = 11,
    tc_act = 12,
    // XDP
    xdp = 20,
    xdp_devmap = 21,
    xdp_cpumap = 22,
    // Cgroup
    cgroup_inet_ingress = 30,
    cgroup_inet_egress = 31,
    cgroup_sock = 32,
    cgroup_sock_addr = 33,
    cgroup_sock_ops = 34,
    // Socket ops
    sk_skb_stream_parser = 40,
    sk_skb_stream_verdict = 41,
    sk_msg_verdict = 42,
    sk_skb_verdict = 43,
    // Flow dissector
    flow_dissector = 50,
    // Perf event
    perf_event = 60,
    // Struct ops
    struct_ops = 70,
    // Zxyphor
    zxy_packet_ai = 80,
};

/// Classic BPF instruction
pub const SockFilterInsn = struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// Classic BPF program
pub const SockFprog = struct {
    len: u16,
    // filter: [*]SockFilterInsn
};

/// BPF socket filter stats
pub const BpfSocketFilterStats = struct {
    // Program
    prog_id: u32,
    attach_type: BpfSocketAttachType,
    // Counts
    run_count: u64,
    run_time_ns: u64,
    // Packets
    filtered_packets: u64,
    passed_packets: u64,
    dropped_packets: u64,
};

// ============================================================================
// Hardware Offload
// ============================================================================

/// TC hardware offload flags
pub const TcHwOffloadFlags = packed struct {
    // Flow offload
    flow_offload: bool = false,
    // Actions
    act_police: bool = false,
    act_pedit: bool = false,
    act_vlan: bool = false,
    act_tunnel: bool = false,
    act_ct: bool = false,
    act_sample: bool = false,
    act_goto: bool = false,
    // Stats
    hw_stats: bool = false,
    hw_stats_immediate: bool = false,
    hw_stats_delayed: bool = false,
    hw_stats_disabled: bool = false,
    // Zxyphor
    zxy_full_offload: bool = false,
    _padding: u3 = 0,
};

/// TC hardware stats
pub const TcHwStats = struct {
    // Flags
    request_type: TcHwStatsType,
    used_type: TcHwStatsType,
    // Counts
    hw_packets: u64,
    hw_bytes: u64,
    hw_drops: u64,
    hw_overlimits: u64,
    // Timestamps
    lastuse_jiffies: u64,
};

/// TC hardware stats type
pub const TcHwStatsType = enum(u8) {
    any = 0,
    immediate = 1,
    delayed = 2,
    disabled = 3,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Packet scheduling subsystem
pub const PktSchedSubsystem = struct {
    // Qdiscs
    nr_qdiscs: u32,
    nr_classes: u32,
    nr_filters: u32,
    nr_actions: u32,
    // Stats
    total_enqueues: u64,
    total_dequeues: u64,
    total_drops: u64,
    total_overlimits: u64,
    total_requeues: u64,
    // TC flower
    total_flower_rules: u64,
    total_flower_hw_offloaded: u64,
    // AF_PACKET
    nr_packet_sockets: u32,
    packet_rx_total: u64,
    packet_tx_total: u64,
    // BPF socket filters
    nr_bpf_filters: u32,
    bpf_total_runs: u64,
    // HW offload
    hw_offload_capable: bool,
    total_hw_offloads: u64,
    // Zxyphor
    zxy_adaptive_qos: bool,
    zxy_ml_classification: bool,
    initialized: bool,

    pub fn init() PktSchedSubsystem {
        return PktSchedSubsystem{
            .nr_qdiscs = 0,
            .nr_classes = 0,
            .nr_filters = 0,
            .nr_actions = 0,
            .total_enqueues = 0,
            .total_dequeues = 0,
            .total_drops = 0,
            .total_overlimits = 0,
            .total_requeues = 0,
            .total_flower_rules = 0,
            .total_flower_hw_offloaded = 0,
            .nr_packet_sockets = 0,
            .packet_rx_total = 0,
            .packet_tx_total = 0,
            .nr_bpf_filters = 0,
            .bpf_total_runs = 0,
            .hw_offload_capable = false,
            .total_hw_offloads = 0,
            .zxy_adaptive_qos = true,
            .zxy_ml_classification = true,
            .initialized = false,
        };
    }
};
