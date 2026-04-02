// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Socket Buffer (SKB) Pools & Network Queues
// Complete: sk_buff allocator, socket buffer pools, network device queues,
// TX/RX ring buffers, NAPI polling, GRO/GSO, traffic shaping queues

const std = @import("std");

// ============================================================================
// SKB Allocation
// ============================================================================

pub const SkbAllocCloneFlag = enum(u8) {
    None = 0,
    Clone = 1,
    ForceClone = 2,
    Orphan = 3,
};

pub const GfpFlags = packed struct(u32) {
    wait: bool,
    io: bool,
    fs: bool,
    cold: bool,
    nowarn: bool,
    retry_mayfail: bool,
    nofail: bool,
    noretry: bool,
    memalloc: bool,
    comp: bool,
    zero: bool,
    nomemalloc: bool,
    hardwall: bool,
    thisnode: bool,
    atomic: bool,
    _reserved: u17,
};

pub const SkbPool = struct {
    name: [32]u8,
    pool_size: u32,
    item_size: u32,
    nr_allocated: u64,
    nr_freed: u64,
    nr_active: u64,
    nr_recycled: u64,
    high_watermark: u32,
    low_watermark: u32,
    batch_count: u32,
    local_list_head: ?*anyopaque,
    magazine_size: u32,
    magazines: [256]?*SkbMagazine,
};

pub const SkbMagazine = struct {
    rounds: u32,
    entries: [64]?*anyopaque,
    next: ?*SkbMagazine,
};

// ============================================================================
// Network Device Queues
// ============================================================================

pub const NetdevQueueState = packed struct(u32) {
    started: bool,
    frozen: bool,
    xoff: bool,
    _reserved: u29,
};

pub const NetdevQueue = struct {
    dev: ?*anyopaque,
    dev_tracker: u64,
    qdisc: ?*anyopaque,
    qdisc_sleeping: ?*anyopaque,
    state: NetdevQueueState,
    num_tx_queued: u64,
    trans_start: u64,
    trans_timeout: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_dropped: u64,
    tx_maxrate: u64,
    dql: DynamicQueueLimit,
};

pub const DynamicQueueLimit = struct {
    num_queued: u32,
    adj_limit: u32,
    last_obj_cnt: u32,
    limit: u32,
    num_completed: u32,
    prev_ovlimit: u32,
    prev_num_queued: u32,
    prev_last_obj_cnt: u32,
    lowest_slack: u32,
    slack_start_time: u64,
    max_limit: u32,
    min_limit: u32,
    slack_hold_time: u32,
};

// ============================================================================
// RX Queue
// ============================================================================

pub const NetdevRxQueue = struct {
    dev: ?*anyopaque,
    rps_map: ?*RpsMap,
    rps_flow_table: ?*RpsDevFlowTable,
    first: ?*anyopaque,
    napi: ?*NapiStruct,
    xdp_rxq_info: ?*XdpRxqInfo,
};

pub const RpsMap = struct {
    len: u32,
    cpus: [256]u16,       // RPS CPU map
    rcu: u64,
};

pub const RpsDevFlowTable = struct {
    mask: u32,
    rcu: u64,
    flows: [4096]RpsDevFlow,
};

pub const RpsDevFlow = struct {
    cpu: u16,
    filter: u16,
    last_qtail: u32,
};

pub const XdpRxqInfo = struct {
    dev: ?*anyopaque,
    queue_index: u32,
    reg_state: u32,
    mem: XdpMemInfo,
    napi_id: u32,
    frag_size: u32,
};

pub const XdpMemInfo = struct {
    mem_type: XdpMemType,
    id: u32,
    allocator: ?*anyopaque,
};

pub const XdpMemType = enum(u8) {
    PageShared = 0,
    PageOrder0 = 1,
    MqXskZc = 2,
    DmabufsDevice = 3,
};

// ============================================================================
// NAPI
// ============================================================================

pub const NapiState = packed struct(u32) {
    sched: bool,           // NAPI_STATE_SCHED
    disable: bool,
    npsvc: bool,
    listed: bool,
    no_busy_poll: bool,
    in_busy_poll: bool,
    prefer_busy_poll: bool,
    threaded: bool,
    sched_pending: bool,
    _reserved: u23,
};

pub const NapiStruct = struct {
    poll_list_next: ?*NapiStruct,
    poll_list_prev: ?*NapiStruct,
    state: NapiState,
    weight: i32,
    defer_hard_irqs_count: i32,
    gro_bitmask: u64,
    poll: ?*const fn (napi: *NapiStruct, budget: i32) callconv(.C) i32,
    poll_owner: i32,
    list_owner: i32,
    dev: ?*anyopaque,
    gro_hash: [8]GroBucket,
    skb: ?*anyopaque,
    rx_list: u64,
    rx_count: u32,
    timer: u64,
    dev_list_next: ?*NapiStruct,
    napi_id: u32,
    irq: i32,
    thread: ?*anyopaque,
    busy_poll_budget: i32,
};

pub const GroBucket = struct {
    list_head: ?*anyopaque,
    count: u32,
};

pub const NapiConfig = struct {
    budget: i32,              // Default 64
    weight: i32,              // Default 64
    busy_poll_usecs: u32,
    busy_poll_budget: u32,
    defer_hard_irqs: i32,
    gro_flush_timeout: u64,
};

// ============================================================================
// GRO (Generic Receive Offload)
// ============================================================================

pub const GroResult = enum(u8) {
    Normal = 0,
    Merged = 1,
    MergedFree = 2,
    Held = 3,
    Drop = 4,
    Consumed = 5,
};

pub const GroStats = struct {
    nr_frags: u64,
    nr_merged: u64,
    nr_held: u64,
    nr_dropped: u64,
    nr_too_small: u64,
    nr_coalesced: u64,
    nr_flushed: u64,
};

// ============================================================================
// GSO (Generic Segmentation Offload)
// ============================================================================

pub const GsoType = packed struct(u32) {
    tcpv4: bool,
    dodgy: bool,
    tcp_ecn: bool,
    tcp_fixedid: bool,
    tcpv6: bool,
    fcoe: bool,
    gre: bool,
    gre_csum: bool,
    ipxip4: bool,
    ipxip6: bool,
    udp_tunnel: bool,
    udp_tunnel_csum: bool,
    partial: bool,
    tunnel_remcsum: bool,
    sctp: bool,
    esp: bool,
    udp: bool,
    udp_l4: bool,
    flaglist: bool,
    _reserved: u13,
};

// ============================================================================
// Traffic Shaping
// ============================================================================

pub const QdiscState = packed struct(u32) {
    running: bool,
    sched: bool,
    deactivated: bool,
    missed: bool,
    draining: bool,
    _reserved: u27,
};

pub const QdiscClass = enum(u16) {
    Pfifo = 1,
    Bfifo = 2,
    Sfq = 3,
    Red = 4,
    Tbf = 5,
    Prio = 6,
    Cbq = 7,
    Htb = 8,
    Fq = 9,
    FqCodel = 10,
    Cake = 11,
    Mq = 12,
    Mqprio = 13,
    Ingress = 14,
    Clsact = 15,
    Multiq = 16,
    Netem = 17,
    Drr = 18,
    Qfq = 19,
    Cbs = 20,
    Etf = 21,
    Taprio = 22,
    Ets = 23,
    Pie = 24,
    Hhf = 25,
    Choke = 26,
    Sfb = 27,
};

pub const QdiscOps = struct {
    enqueue: ?*const fn (skb: *anyopaque, qdisc: *Qdisc, to_free: *?*anyopaque) callconv(.C) i32,
    dequeue: ?*const fn (qdisc: *Qdisc) callconv(.C) ?*anyopaque,
    peek: ?*const fn (qdisc: *Qdisc) callconv(.C) ?*anyopaque,
    init: ?*const fn (qdisc: *Qdisc, opt: ?*anyopaque, extack: ?*anyopaque) callconv(.C) i32,
    reset: ?*const fn (qdisc: *Qdisc) callconv(.C) void,
    destroy: ?*const fn (qdisc: *Qdisc) callconv(.C) void,
    change: ?*const fn (qdisc: *Qdisc, opt: ?*anyopaque, extack: ?*anyopaque) callconv(.C) i32,
    attach: ?*const fn (qdisc: *Qdisc) callconv(.C) void,
    change_tx_queue_len: ?*const fn (qdisc: *Qdisc, new_len: u32) callconv(.C) i32,
    change_real_num_tx: ?*const fn (qdisc: *Qdisc, new_real_tx: u32) callconv(.C) void,
    dump: ?*const fn (qdisc: *Qdisc, skb: *anyopaque) callconv(.C) i32,
    dump_stats: ?*const fn (qdisc: *Qdisc, b: *anyopaque) callconv(.C) i32,
    ingress_block_set: ?*const fn (qdisc: *Qdisc, block_index: u32) callconv(.C) void,
    egress_block_set: ?*const fn (qdisc: *Qdisc, block_index: u32) callconv(.C) void,
    ingress_block_get: ?*const fn (qdisc: *Qdisc) callconv(.C) u32,
    egress_block_get: ?*const fn (qdisc: *Qdisc) callconv(.C) u32,
    id: [16]u8,
    priv_size: u32,
    flags: u32,
};

pub const Qdisc = struct {
    enqueue: ?*const fn (skb: *anyopaque, qdisc: *Qdisc, to_free: *?*anyopaque) callconv(.C) i32,
    dequeue: ?*const fn (qdisc: *Qdisc) callconv(.C) ?*anyopaque,
    flags: u32,
    limit: u32,
    ops: ?*QdiscOps,
    stab: ?*anyopaque,
    hash: [16]u64,
    handle: u32,
    parent: u32,
    dev_queue: ?*NetdevQueue,
    rate_est: ?*anyopaque,
    state: QdiscState,
    state2: u32,
    pad: u32,
    q: QdiscSkbHead,
    gso_skb: QdiscSkbHead,
    skb_bad_txq: QdiscSkbHead,
    qstats: GnetStats,
    bstats: GnetStats,
    busylock: u64,
    seqlock: u64,
    running: bool,
    owner: i32,
};

pub const QdiscSkbHead = struct {
    head: ?*anyopaque,
    tail: ?*anyopaque,
    qlen: u32,
};

pub const GnetStats = struct {
    bytes: u64,
    packets: u64,
    drops: u64,
    overlimits: u64,
    requeues: u64,
    backlog: u32,
    qlen: u32,
};

// ============================================================================
// Manager
// ============================================================================

pub const SkbQueueManager = struct {
    total_skb_allocs: u64,
    total_skb_frees: u64,
    total_skb_clones: u64,
    total_gro_merges: u64,
    total_gso_segments: u64,
    total_napi_polls: u64,
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    total_tx_packets: u64,
    total_rx_packets: u64,
    initialized: bool,

    pub fn init() SkbQueueManager {
        return .{
            .total_skb_allocs = 0,
            .total_skb_frees = 0,
            .total_skb_clones = 0,
            .total_gro_merges = 0,
            .total_gso_segments = 0,
            .total_napi_polls = 0,
            .total_tx_bytes = 0,
            .total_rx_bytes = 0,
            .total_tx_packets = 0,
            .total_rx_packets = 0,
            .initialized = true,
        };
    }
};
