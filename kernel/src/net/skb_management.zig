// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Socket Buffer Management (sk_buff)
// Complete sk_buff structure, headroom/tailroom, clone, linearize,
// GSO/GRO, checksum offload, SKB queues, frag list, page pool

const std = @import("std");

// ============================================================================
// SKB Shared Info
// ============================================================================

pub const MAX_SKB_FRAGS = 17;

pub const SkbFrag = struct {
    page: u64,           // struct page pointer
    offset: u32,
    size: u32,
};

pub const SkbGsoType = packed struct(u32) {
    tcpv4: bool = false,
    udp: bool = false,
    dodgy: bool = false,
    tcp_ecn: bool = false,
    tcp_fixedid: bool = false,
    tcpv6: bool = false,
    fcoe: bool = false,
    gre: bool = false,
    gre_csum: bool = false,
    ipxip4: bool = false,
    ipxip6: bool = false,
    udp_tunnel: bool = false,
    udp_tunnel_csum: bool = false,
    partial: bool = false,
    tunnel_remcsum: bool = false,
    sctp: bool = false,
    esp: bool = false,
    udp_l4: bool = false,
    fraglist: bool = false,
    _reserved: u13 = 0,
};

pub const SkbSharedInfo = struct {
    meta_len: u8,
    nr_frags: u8,
    gso_size: u16,
    gso_segs: u16,
    gso_type: SkbGsoType,
    frag_list: ?*SkBuff,
    hwtstamps: SkbHwTimestamps,
    tskey: u32,
    tx_flags: u16,
    destructor_arg: u64,
    frags: [MAX_SKB_FRAGS]SkbFrag,
    dataref: u32,
    xdp_frags_size: u32,
};

pub const SkbHwTimestamps = struct {
    hwtstamp: u64,    // nanoseconds
};

// ============================================================================
// SKB Checksum
// ============================================================================

pub const SkbCsumType = enum(u2) {
    None = 0,          // No checksum needed
    Unnecessary = 1,   // HW verified checksum
    Complete = 2,      // HW provided raw checksum
    Partial = 3,       // Only header checksummed
};

// ============================================================================
// SKB Packet Type
// ============================================================================

pub const SkbPktType = enum(u3) {
    Host = 0,
    Broadcast = 1,
    Multicast = 2,
    OtherHost = 3,
    Outgoing = 4,
    Loopback = 5,
    User = 6,
    Kernel = 7,
};

// ============================================================================
// Core sk_buff Structure
// ============================================================================

pub const SkBuff = struct {
    // Linked list pointers
    next: ?*SkBuff,
    prev: ?*SkBuff,

    // Socket/device association
    sk: u64,              // struct sock *
    dev: u64,             // struct net_device *
    dev_scratch: u64,

    // Timestamps
    tstamp: u64,          // ktime_t

    // Routing
    cb: [48]u8,           // Control buffer (protocol-specific)
    dst: u64,             // struct dst_entry *

    // Security
    sp: u64,              // struct sec_path *
    secmark: u32,

    // Headers
    head: [*]u8,
    data: [*]u8,
    tail: u32,            // Offset from head
    end: u32,             // Offset from head

    // Length
    len: u32,             // Total data length
    data_len: u32,        // Paged data length
    mac_len: u16,
    hdr_len: u16,

    // Offsets
    transport_header: u16,
    network_header: u16,
    mac_header: u16,
    inner_transport_header: u16,
    inner_network_header: u16,
    inner_mac_header: u16,

    // Queue mapping
    queue_mapping: u16,
    tc_index: u16,

    // Flags (packed for space efficiency)
    ip_summed: SkbCsumType,
    pkt_type: SkbPktType,
    cloned: bool,
    nohdr: bool,
    fclone: u2,
    peeked: bool,
    head_frag: bool,
    pfmemalloc: bool,
    pp_recycle: bool,

    // Extended flags
    nf_trace: bool,
    redirected: bool,
    from_ingress: bool,
    nf_skip_egress: bool,
    slow_gro: bool,
    csum_not_inet: bool,
    scm_io_uring: bool,
    mono_delivery_time: bool,

    // Checksum
    csum: u32,
    csum_start: u16,
    csum_offset: u16,

    // Priority / marks
    priority: u32,
    mark: u32,
    hash: u32,
    vlan_proto: u16,
    vlan_tci: u16,

    // Protocol
    protocol: u16,        // __be16
    tc_classid: u16,

    // References
    users: u32,
    extensions: u64,

    // Destructor
    destructor: ?*const fn (*SkBuff) void,
    truesize: u32,

    // SKB shared info (at end of data area)
    pub fn sharedInfo(self: *SkBuff) *SkbSharedInfo {
        return @ptrFromInt(@intFromPtr(self.head) + self.end);
    }

    pub fn headroom(self: *const SkBuff) u32 {
        return @intCast(@intFromPtr(self.data) - @intFromPtr(self.head));
    }

    pub fn tailroom(self: *const SkBuff) u32 {
        return self.end - self.tail;
    }

    pub fn linearLen(self: *const SkBuff) u32 {
        return self.len - self.data_len;
    }

    pub fn isNonlinear(self: *const SkBuff) bool {
        return self.data_len != 0;
    }
};

// ============================================================================
// SKB Queue (sk_buff_head)
// ============================================================================

pub const SkBuffHead = struct {
    next: ?*SkBuff,
    prev: ?*SkBuff,
    qlen: u32,
    lock: u64,  // spinlock

    pub fn init() SkBuffHead {
        return .{
            .next = null,
            .prev = null,
            .qlen = 0,
            .lock = 0,
        };
    }

    pub fn isEmpty(self: *const SkBuffHead) bool {
        return self.qlen == 0;
    }
};

// ============================================================================
// GRO (Generic Receive Offload)
// ============================================================================

pub const GroType = enum(u8) {
    Normal = 0,
    TcpCoalesce = 1,
    UdpCoalesce = 2,
    Flush = 3,
    FlushId = 4,
    Consumed = 5,
};

pub const NapiGro = struct {
    gro_hash: [8]GroBucket,
    bitmask: u8,
    count: u32,
};

pub const GroBucket = struct {
    list: ?*SkBuff,
    count: u8,
};

pub const GroCbFlags = packed struct(u16) {
    flush: bool = false,
    flush_id: bool = false,
    count: u6 = 0,
    is_ipv6: bool = false,
    is_atomic: bool = false,
    is_flist: bool = false,
    free: u2 = 0,
    encap_mark: bool = false,
    recursion_counter: u3 = 0,
};

// ============================================================================
// GSO (Generic Segmentation Offload)
// ============================================================================

pub const NetdevFeatures = packed struct(u64) {
    sg: bool = false,
    ip_csum: bool = false,
    no_csum: bool = false,
    hw_csum: bool = false,
    ipv6_csum: bool = false,
    highdma: bool = false,
    fraglist: bool = false,
    hw_vlan_ctag_tx: bool = false,
    hw_vlan_ctag_rx: bool = false,
    hw_vlan_ctag_filter: bool = false,
    vlan_challenged: bool = false,
    gso: bool = false,
    lro: bool = false,
    netns_local: bool = false,
    gro: bool = false,
    gro_hw: bool = false,
    lltx: bool = false,
    ntuple: bool = false,
    rxhash: bool = false,
    rxcsum: bool = false,
    nocache_copy: bool = false,
    loopback: bool = false,
    fcoe_crc: bool = false,
    fcoe_mtu: bool = false,
    gso_tcpv4: bool = false,
    gso_udp: bool = false,
    gso_tcpv6: bool = false,
    gso_gre: bool = false,
    gso_gre_csum: bool = false,
    gso_ipxip4: bool = false,
    gso_ipxip6: bool = false,
    gso_udp_tunnel: bool = false,
    gso_udp_tunnel_csum: bool = false,
    gso_partial: bool = false,
    gso_tunnel_remcsum: bool = false,
    gso_sctp: bool = false,
    gso_esp: bool = false,
    gso_udp_l4: bool = false,
    gso_fraglist: bool = false,
    tso: bool = false,
    ufo: bool = false,
    hw_tls_tx: bool = false,
    hw_tls_rx: bool = false,
    hw_tls_record: bool = false,
    rx_gro_list: bool = false,
    rx_udp_gro_forwarding: bool = false,
    _reserved: u18 = 0,
};

// ============================================================================
// Page Pool (XDP)
// ============================================================================

pub const PagePoolParams = struct {
    flags: PagePoolFlags,
    order: u32,
    pool_size: u32,
    nid: i32,
    dev: u64,
    napi: u64,
    netdev: u64,
    dma_dir: u32,
    max_len: u32,
    offset: u32,
};

pub const PagePoolFlags = packed struct(u32) {
    dma_map: bool = false,
    dma_sync: bool = false,
    _reserved: u30 = 0,
};

pub const PagePoolStats = struct {
    alloc_fast: u64,
    alloc_slow: u64,
    alloc_slow_high_order: u64,
    alloc_empty: u64,
    alloc_refill: u64,
    alloc_waive: u64,
    recycle_cached: u64,
    recycle_ring: u64,
    recycle_ring_full: u64,
    recycle_released_refcnt: u64,
};

pub const PagePool = struct {
    params: PagePoolParams,
    frag_users: u32,
    frag_page: u64,
    frag_offset: u32,
    pages_state_hold_cnt: u32,
    ring_size: u32,
    alloc_count: u64,
    stats: PagePoolStats,
    user_cnt: u32,
    destroy_cnt: u32,
    has_init_callback: bool,
};

// ============================================================================
// SKB Extensions
// ============================================================================

pub const SkbExtType = enum(u8) {
    Bridge = 0,
    SecPath = 1,
    Mptcp = 2,
    McTP = 3,
};

pub const SkbExt = struct {
    refcnt: u32,
    offset: [4]u8,  // Per extension-type offsets
    chunks: u8,
};

pub const SkbBridgeInfo = struct {
    br_mcast_ctx: u64,
    pkt_is_unicast: bool,
    vlan_tunnel_id: u16,
    is_sticky: bool,
};

pub const SkbSecPath = struct {
    len: u8,
    olen: u8,
    xvec: [6]u64,   // struct xfrm_state pointers
};

// ============================================================================
// SKB Allocation / Cloning
// ============================================================================

pub const SkbAllocFlags = packed struct(u32) {
    gfp_atomic: bool = false,
    gfp_kernel: bool = false,
    gfp_dma: bool = false,
    no_fclone: bool = false,
    _reserved: u28 = 0,
};

pub const SkbCloneType = enum(u8) {
    None = 0,
    Original = 1,
    Clone = 2,
    Unavailable = 3,
};

// ============================================================================
// NAPI & Polling
// ============================================================================

pub const NapiState = packed struct(u32) {
    sched: bool = false,
    missed: bool = false,
    disable: bool = false,
    no_busy_poll: bool = false,
    listed: bool = false,
    prefer_busy_poll: bool = false,
    threaded: bool = false,
    _reserved: u25 = 0,
};

pub const NapiStruct = struct {
    state: NapiState,
    weight: i32,
    poll_list_next: u64,
    poll: u64,           // poll function pointer
    dev: u64,
    rx_list: SkBuffHead,
    rx_count: u32,
    budget: i32,
    gro: NapiGro,
    skbs_handled: u64,   // stats
    poll_cnt: u64,
};

pub const NAPI_POLL_WEIGHT = 64;
pub const NAPI_GRO_BUCKETS = 8;

// ============================================================================
// Traffic Control Integration
// ============================================================================

pub const TcPrioMap = struct {
    priomap: [16]u8,
    num_tc: u8,
    tc: [16]TcBandMapping,
};

pub const TcBandMapping = struct {
    count: u16,
    offset: u16,
};

pub const SkbPriorityMapping = struct {
    dscp_to_prio: [64]u8,    // DSCP value -> priority
    vlan_to_prio: [8]u8,     // VLAN PCP -> priority
};

// ============================================================================
// SKB Manager
// ============================================================================

pub const SkbManager = struct {
    total_allocated: u64,
    total_freed: u64,
    total_cloned: u64,
    total_linearized: u64,
    total_gso_segments: u64,
    total_gro_merged: u64,
    total_page_pool_allocs: u64,
    total_page_pool_recycles: u64,
    current_skbs: u64,
    peak_skbs: u64,
    cache_hits: u64,
    cache_misses: u64,
    initialized: bool,

    pub fn init() SkbManager {
        return .{
            .total_allocated = 0,
            .total_freed = 0,
            .total_cloned = 0,
            .total_linearized = 0,
            .total_gso_segments = 0,
            .total_gro_merged = 0,
            .total_page_pool_allocs = 0,
            .total_page_pool_recycles = 0,
            .current_skbs = 0,
            .peak_skbs = 0,
            .cache_hits = 0,
            .cache_misses = 0,
            .initialized = true,
        };
    }
};
