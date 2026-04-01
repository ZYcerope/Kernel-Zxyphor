// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Network Stack
// TCP/IP tuning, socket options, netfilter hooks, QoS, neighbor cache
const std = @import("std");

// ============================================================================
// Network Namespace
// ============================================================================

pub const NetDevice = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    ifindex: u32 = 0,
    mtu: u32 = 1500,
    flags: u32 = 0,
    mac_addr: [6]u8 = [_]u8{0} ** 6,
    // State
    state: NetDevState = .down,
    carrier: bool = false,
    promisc_count: u32 = 0,
    allmulti_count: u32 = 0,
    // Traffic
    tx_queue_len: u32 = 1000,
    tx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_errors: u64 = 0,
    tx_dropped: u64 = 0,
    rx_bytes: u64 = 0,
    rx_packets: u64 = 0,
    rx_errors: u64 = 0,
    rx_dropped: u64 = 0,
    // Multiqueue
    num_tx_queues: u16 = 1,
    num_rx_queues: u16 = 1,
    real_num_tx_queues: u16 = 1,
    real_num_rx_queues: u16 = 1,
    // Features
    features: u64 = 0,
    hw_features: u64 = 0,
    // Offload
    gso_max_size: u32 = 65536,
    gso_max_segs: u16 = 64,
    tso_max_size: u32 = 65536,
    tso_max_segs: u16 = 64,
    // NAPI
    napi_budget: u32 = 64,
    napi_weight: u32 = 64,
    // Ethtool stats
    speed_mbps: u32 = 0,
    duplex: Duplex = .unknown,
    autoneg: bool = false,
    // Qdisc
    qdisc_type: QdiscType = .pfifo_fast,
    
    pub const IFF_UP: u32 = 1 << 0;
    pub const IFF_BROADCAST: u32 = 1 << 1;
    pub const IFF_LOOPBACK: u32 = 1 << 3;
    pub const IFF_POINTOPOINT: u32 = 1 << 4;
    pub const IFF_NOARP: u32 = 1 << 7;
    pub const IFF_PROMISC: u32 = 1 << 8;
    pub const IFF_ALLMULTI: u32 = 1 << 9;
    pub const IFF_MULTICAST: u32 = 1 << 12;
    pub const IFF_LOWER_UP: u32 = 1 << 16;
    pub const IFF_DORMANT: u32 = 1 << 17;
    
    pub const NETIF_F_SG: u64 = 1 << 0;
    pub const NETIF_F_IP_CSUM: u64 = 1 << 1;
    pub const NETIF_F_HW_CSUM: u64 = 1 << 2;
    pub const NETIF_F_GSO: u64 = 1 << 3;
    pub const NETIF_F_TSO: u64 = 1 << 4;
    pub const NETIF_F_TSO6: u64 = 1 << 5;
    pub const NETIF_F_RXHASH: u64 = 1 << 6;
    pub const NETIF_F_RXCSUM: u64 = 1 << 7;
    pub const NETIF_F_GRO: u64 = 1 << 8;
    pub const NETIF_F_LRO: u64 = 1 << 9;
    pub const NETIF_F_HW_VLAN_CTAG_TX: u64 = 1 << 10;
    pub const NETIF_F_HW_VLAN_CTAG_RX: u64 = 1 << 11;
    pub const NETIF_F_NTUPLE: u64 = 1 << 12;
    pub const NETIF_F_HIGHDMA: u64 = 1 << 13;
    pub const NETIF_F_HW_TC: u64 = 1 << 14;
    pub const NETIF_F_XDP: u64 = 1 << 15;
};

pub const NetDevState = enum(u8) {
    down,
    up,
    testing,
    dormant,
    not_present,
    lower_layer_down,
};

pub const Duplex = enum(u8) {
    half = 0,
    full = 1,
    unknown = 0xFF,
};

pub const QdiscType = enum(u8) {
    noqueue,
    pfifo_fast,
    pfifo,
    bfifo,
    tbf,
    sfq,
    fq,
    fq_codel,
    cake,
    htb,
    hfsc,
    netem,
    mqprio,
};

// ============================================================================
// Routing Table
// ============================================================================

pub const RouteType = enum(u8) {
    unspec = 0,
    unicast = 1,
    local = 2,
    broadcast = 3,
    anycast = 4,
    multicast = 5,
    blackhole = 6,
    unreachable = 7,
    prohibit = 8,
    throw_rt = 9,
    nat = 10,
};

pub const RouteScope = enum(u8) {
    universe = 0,
    site = 200,
    link = 253,
    host = 254,
    nowhere = 255,
};

pub const RouteEntry = struct {
    // Destination
    dst_addr: u32 = 0,
    dst_prefix_len: u8 = 0,
    // Source
    src_addr: u32 = 0,
    src_prefix_len: u8 = 0,
    // Gateway
    gateway: u32 = 0,
    // Interface
    oif_index: u32 = 0,
    iif_index: u32 = 0,
    // Type & Scope
    route_type: RouteType = .unicast,
    scope: RouteScope = .universe,
    // Metrics
    metric: u32 = 0,
    pref_src: u32 = 0,
    mtu: u32 = 0,
    window: u32 = 0,
    rtt: u32 = 0,   // microseconds
    // Table
    table: u32 = 254, // RT_TABLE_MAIN
    // Protocol
    protocol: u8 = 0, // RTPROT_UNSPEC
    // Flags
    flags: u32 = 0,
    // Multipath (ECMP)
    nexthops: [8]Nexthop = [_]Nexthop{Nexthop{}} ** 8,
    nexthop_count: u8 = 0,
    // Timestamps
    created_ns: u64 = 0,
    last_used_ns: u64 = 0,
    expires_ns: u64 = 0,

    pub const RTF_UP: u32 = 0x0001;
    pub const RTF_GATEWAY: u32 = 0x0002;
    pub const RTF_HOST: u32 = 0x0004;
    pub const RTF_DYNAMIC: u32 = 0x0010;
    pub const RTF_MODIFIED: u32 = 0x0020;
    pub const RTF_REJECT: u32 = 0x0200;
    pub const RTF_CACHE: u32 = 0x01000000;

    pub fn matches(self: *const RouteEntry, dst: u32) bool {
        if (self.dst_prefix_len == 0) return true; // Default route
        const mask = if (self.dst_prefix_len >= 32) 0xFFFFFFFF
                     else (~@as(u32, 0)) << @intCast(32 - @as(u6, @intCast(self.dst_prefix_len)));
        return (dst & mask) == (self.dst_addr & mask);
    }
};

pub const Nexthop = struct {
    gateway: u32 = 0,
    ifindex: u32 = 0,
    weight: u8 = 1,
    flags: u8 = 0,
};

pub const RoutingTable = struct {
    entries: [512]RouteEntry = [_]RouteEntry{RouteEntry{}} ** 512,
    count: u32 = 0,
    
    pub fn init() RoutingTable {
        return RoutingTable{};
    }
    
    /// Add a route
    pub fn addRoute(self: *RoutingTable, entry: RouteEntry) bool {
        if (self.count >= 512) return false;
        self.entries[self.count] = entry;
        self.count += 1;
        return true;
    }
    
    /// Longest-prefix match lookup
    pub fn lookup(self: *const RoutingTable, dst: u32) ?*const RouteEntry {
        var best: ?*const RouteEntry = null;
        var best_prefix: u8 = 0;
        
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const entry = &self.entries[i];
            if (entry.matches(dst)) {
                if (entry.dst_prefix_len >= best_prefix) {
                    best = entry;
                    best_prefix = entry.dst_prefix_len;
                }
            }
        }
        return best;
    }
    
    /// Delete a route
    pub fn delRoute(self: *RoutingTable, dst: u32, prefix_len: u8) bool {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].dst_addr == dst and self.entries[i].dst_prefix_len == prefix_len) {
                var j = i;
                while (j + 1 < self.count) : (j += 1) {
                    self.entries[j] = self.entries[j + 1];
                }
                self.count -= 1;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// Neighbor Table (ARP cache)
// ============================================================================

pub const NeighState = enum(u8) {
    incomplete = 0x01,
    reachable = 0x02,
    stale = 0x04,
    delay = 0x08,
    probe = 0x10,
    failed = 0x20,
    noarp = 0x40,
    permanent = 0x80,
    none = 0x00,
};

pub const NeighEntry = struct {
    ip_addr: u32 = 0,
    mac_addr: [6]u8 = [_]u8{0} ** 6,
    state: NeighState = .none,
    ifindex: u32 = 0,
    confirmed_ns: u64 = 0,
    updated_ns: u64 = 0,
    used_ns: u64 = 0,
    probes: u8 = 0,
    flags: u8 = 0,
    // Queued packets while resolving
    queue_len: u8 = 0,
    
    pub const NTF_USE: u8 = 0x01;
    pub const NTF_SELF: u8 = 0x02;
    pub const NTF_MASTER: u8 = 0x04;
    pub const NTF_PROXY: u8 = 0x08;
    pub const NTF_ROUTER: u8 = 0x80;
};

pub const NeighTable = struct {
    entries: [256]NeighEntry = [_]NeighEntry{NeighEntry{}} ** 256,
    count: u32 = 0,
    // Timers (in ms)
    base_reachable_time_ms: u32 = 30000,
    retrans_time_ms: u32 = 1000,
    gc_stale_time_ms: u32 = 60000,
    delay_probe_time_ms: u32 = 5000,
    ucast_probes: u8 = 3,
    mcast_probes: u8 = 3,
    // Stats
    lookups: u64 = 0,
    hits: u64 = 0,
    res_failed: u64 = 0,
    gc_runs: u64 = 0,
    
    pub fn init() NeighTable {
        return NeighTable{};
    }
    
    pub fn lookup(self: *NeighTable, ip: u32) ?*NeighEntry {
        self.lookups += 1;
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].ip_addr == ip) {
                self.hits += 1;
                return &self.entries[i];
            }
        }
        return null;
    }
    
    pub fn addEntry(self: *NeighTable, ip: u32, mac: [6]u8, ifindex: u32, now_ns: u64) bool {
        // Update existing
        if (self.lookup(ip)) |entry| {
            entry.mac_addr = mac;
            entry.state = .reachable;
            entry.confirmed_ns = now_ns;
            entry.updated_ns = now_ns;
            return true;
        }
        if (self.count >= 256) return false;
        const idx = self.count;
        self.count += 1;
        self.entries[idx] = NeighEntry{
            .ip_addr = ip,
            .mac_addr = mac,
            .ifindex = ifindex,
            .state = .reachable,
            .confirmed_ns = now_ns,
            .updated_ns = now_ns,
        };
        return true;
    }
    
    /// Garbage collect stale entries
    pub fn gc(self: *NeighTable, now_ns: u64) u32 {
        self.gc_runs += 1;
        var removed: u32 = 0;
        const stale_threshold = @as(u64, self.gc_stale_time_ms) * 1_000_000;
        
        var i: u32 = 0;
        while (i < self.count) {
            const entry = &self.entries[i];
            if (entry.state == .stale or entry.state == .failed) {
                if (now_ns - entry.updated_ns > stale_threshold) {
                    // Remove
                    var j = i;
                    while (j + 1 < self.count) : (j += 1) {
                        self.entries[j] = self.entries[j + 1];
                    }
                    self.count -= 1;
                    removed += 1;
                    continue;
                }
            }
            i += 1;
        }
        return removed;
    }
};

// ============================================================================
// Socket Options (TCP tuning)
// ============================================================================

pub const TcpCongestion = enum(u8) {
    reno,
    cubic,
    bbr,
    bbr2,
    dctcp,
    westwood,
    vegas,
    htcp,
    hybla,
    illinois,
    lp,
    scalable,
    zxy_adaptive, // Zxyphor ML-based
};

pub const TcpSockOptions = struct {
    // Congestion
    congestion: TcpCongestion = .cubic,
    // Keepalive
    keepalive_time_sec: u32 = 7200,
    keepalive_intvl_sec: u32 = 75,
    keepalive_probes: u8 = 9,
    // Timeouts
    retries1: u8 = 3,
    retries2: u8 = 15,
    syn_retries: u8 = 6,
    fin_timeout_sec: u32 = 60,
    // Buffers
    sndbuf: u32 = 87380,
    rcvbuf: u32 = 87380,
    sndbuf_max: u32 = 6291456,
    rcvbuf_max: u32 = 6291456,
    // Window scaling
    window_clamp: u32 = 0,
    // Path MTU
    mtu_discover: u8 = 1, // IP_PMTUDISC_WANT
    // Quick Ack
    quickack: bool = false,
    // Timestamps
    timestamps: bool = true,
    // SACK
    sack: bool = true,
    dsack: bool = true,
    // ECN
    ecn: u8 = 2, // 0=off, 1=on, 2=server
    // TCP Fast Open
    fastopen: u8 = 0,
    fastopen_key: [16]u8 = [_]u8{0} ** 16,
    // Cork / Nodelay
    nodelay: bool = false,
    cork: bool = false,
    // Thin streams
    thin_linear: bool = false,
    thin_dupack: bool = false,
    // Repair mode
    repair: bool = false,
    // User timeout
    user_timeout_ms: u32 = 0,
    // Multipath TCP
    mptcp: bool = false,
    mptcp_scheduler: MptcpScheduler = .default,
};

pub const MptcpScheduler = enum(u8) {
    default,
    round_robin,
    redundant,
    blest,
};

pub const SysctlNetIpv4 = struct {
    // TCP
    tcp_timestamps: bool = true,
    tcp_window_scaling: bool = true,
    tcp_sack: bool = true,
    tcp_dsack: bool = true,
    tcp_ecn: u8 = 2,
    tcp_fack: bool = false,
    tcp_reordering: u32 = 3,
    tcp_max_reordering: u32 = 300,
    tcp_retries1: u8 = 3,
    tcp_retries2: u8 = 15,
    tcp_syn_retries: u8 = 6,
    tcp_synack_retries: u8 = 5,
    tcp_max_syn_backlog: u32 = 4096,
    tcp_abort_on_overflow: bool = false,
    tcp_max_tw_buckets: u32 = 262144,
    tcp_tw_reuse: u8 = 2,
    tcp_fin_timeout: u32 = 60,
    tcp_keepalive_time: u32 = 7200,
    tcp_keepalive_probes: u8 = 9,
    tcp_keepalive_intvl: u32 = 75,
    tcp_rmem: [3]u32 = [_]u32{4096, 87380, 6291456},
    tcp_wmem: [3]u32 = [_]u32{4096, 16384, 4194304},
    tcp_mem: [3]u64 = [_]u64{94500, 126000, 189000},
    tcp_fastopen: u8 = 3,
    tcp_slow_start_after_idle: bool = true,
    tcp_no_metrics_save: bool = false,
    tcp_mtu_probing: u8 = 0,
    tcp_base_mss: u32 = 1024,
    tcp_min_snd_mss: u32 = 48,
    tcp_congestion_control: TcpCongestion = .cubic,
    tcp_available_congestion: u32 = 0xFFFF, // bitmask
    tcp_autocorking: bool = true,
    tcp_pacing: bool = true,
    // IP
    ip_forward: bool = false,
    ip_default_ttl: u8 = 64,
    ip_local_port_range: [2]u16 = [_]u16{32768, 60999},
    ip_no_pmtu_disc: bool = false,
    ip_nonlocal_bind: bool = false,
    // ICMP
    icmp_echo_ignore_all: bool = false,
    icmp_echo_ignore_broadcasts: bool = true,
    icmp_ratelimit: u32 = 1000,
    // Conntrack
    nf_conntrack_max: u32 = 262144,
    nf_conntrack_tcp_timeout_established: u32 = 432000,
    nf_conntrack_udp_timeout: u32 = 30,
    nf_conntrack_udp_timeout_stream: u32 = 180,
    
    pub fn init() SysctlNetIpv4 {
        return SysctlNetIpv4{};
    }
};

// ============================================================================
// Network Statistics
// ============================================================================

pub const NetStats = struct {
    // IP
    ip_in_receives: u64 = 0,
    ip_in_hdr_errors: u64 = 0,
    ip_in_addr_errors: u64 = 0,
    ip_forw_datagrams: u64 = 0,
    ip_in_unknown_protos: u64 = 0,
    ip_in_discards: u64 = 0,
    ip_in_delivers: u64 = 0,
    ip_out_requests: u64 = 0,
    ip_out_discards: u64 = 0,
    ip_out_no_routes: u64 = 0,
    ip_reasm_timeout: u64 = 0,
    ip_reasm_reqds: u64 = 0,
    ip_reasm_oks: u64 = 0,
    ip_reasm_fails: u64 = 0,
    ip_frag_oks: u64 = 0,
    ip_frag_fails: u64 = 0,
    ip_frag_creates: u64 = 0,
    // TCP
    tcp_active_opens: u64 = 0,
    tcp_passive_opens: u64 = 0,
    tcp_attempt_fails: u64 = 0,
    tcp_estab_resets: u64 = 0,
    tcp_curr_estab: u64 = 0,
    tcp_in_segs: u64 = 0,
    tcp_out_segs: u64 = 0,
    tcp_retrans_segs: u64 = 0,
    tcp_in_errs: u64 = 0,
    tcp_out_rsts: u64 = 0,
    tcp_in_csum_errors: u64 = 0,
    // UDP
    udp_in_datagrams: u64 = 0,
    udp_no_ports: u64 = 0,
    udp_in_errors: u64 = 0,
    udp_out_datagrams: u64 = 0,
    udp_rcvbuf_errors: u64 = 0,
    udp_sndbuf_errors: u64 = 0,
    udp_in_csum_errors: u64 = 0,
    // ICMP
    icmp_in_msgs: u64 = 0,
    icmp_in_errors: u64 = 0,
    icmp_out_msgs: u64 = 0,
    icmp_out_errors: u64 = 0,
};
