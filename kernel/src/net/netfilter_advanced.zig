// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced Netfilter: nftables, Connection Tracking, NAT, IPsec/XFRM
// Production-quality packet filtering and network security framework

const std = @import("std");

// ============================================================================
// Netfilter Hook Points
// ============================================================================

pub const NfHookPoint = enum(u8) {
    pre_routing = 0,
    local_in = 1,
    forward = 2,
    local_out = 3,
    post_routing = 4,
    // Zxyphor extensions
    ingress = 5,
    egress = 6,
};

pub const NfProto = enum(u8) {
    unspec = 0,
    inet = 1,
    ipv4 = 2,
    arp = 3,
    netdev = 5,
    bridge = 7,
    ipv6 = 10,
    decnet = 12,
};

pub const NfVerdict = enum(i32) {
    drop = 0,
    accept = 1,
    stolen = 2,
    queue = 3,
    repeat = 4,
    stop = 5,
    // nftables extended verdicts
    @"continue" = -1,
    @"break" = -2,
    jump = -3,
    goto = -4,
    @"return" = -5,
};

// ============================================================================
// nftables Core
// ============================================================================

pub const NftRegister = enum(u8) {
    verdict = 0,
    reg1 = 1,
    reg2 = 2,
    reg3 = 3,
    reg4 = 4,
    // 16-byte registers (Linux 4.1+)
    reg_0 = 0x08,
    reg_1 = 0x09,
    reg_2 = 0x0a,
    reg_3 = 0x0b,
    reg_4 = 0x0c,
    reg_5 = 0x0d,
    reg_6 = 0x0e,
    reg_7 = 0x0f,
    reg_8 = 0x10,
    reg_9 = 0x11,
    reg_10 = 0x12,
    reg_11 = 0x13,
    reg_12 = 0x14,
    reg_13 = 0x15,
    reg_14 = 0x16,
    reg_15 = 0x17,
};

pub const NftExprType = enum(u8) {
    immediate = 0,
    cmp = 1,
    lookup = 2,
    bitwise = 3,
    byteorder = 4,
    payload = 5,
    exthdr = 6,
    meta = 7,
    ct = 8,
    limit = 9,
    counter = 10,
    log = 11,
    nat = 12,
    reject = 13,
    masq = 14,
    redir = 15,
    queue = 16,
    quota = 17,
    range = 18,
    numgen = 19,
    hash = 20,
    fib = 21,
    rt = 22,
    socket = 23,
    osf = 24,
    tproxy = 25,
    synproxy = 26,
    notrack = 27,
    flow_offload = 28,
    connlimit = 29,
    dup = 30,
    fwd = 31,
    objref = 32,
    map = 33,
    dynset = 34,
    last = 35,
    // Zxyphor extensions
    zxy_dpi = 200,
    zxy_geoip = 201,
    zxy_ratelimit = 202,
    zxy_ml_classify = 203,
};

pub const NftCmpOp = enum(u8) {
    eq = 0,
    neq = 1,
    lt = 2,
    lte = 3,
    gt = 4,
    gte = 5,
};

pub const NftPayloadBase = enum(u8) {
    ll_header = 0,
    network_header = 1,
    transport_header = 2,
    inner_header = 3,
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

pub const NftCtKey = enum(u8) {
    state = 0,
    direction = 1,
    status = 2,
    mark = 3,
    secmark = 4,
    expiration = 5,
    helper = 6,
    l3protocol = 7,
    src = 8,
    dst = 9,
    protocol = 10,
    proto_src = 11,
    proto_dst = 12,
    labels = 13,
    pkts = 14,
    bytes = 15,
    avgpkt = 16,
    zone = 17,
    eventmask = 18,
    src_ip = 19,
    dst_ip = 20,
    id = 21,
};

// nftables Table
pub const NftTable = struct {
    name: [128]u8,
    name_len: u8,
    family: NfProto,
    flags: u32,
    handle: u64,
    chain_count: u32,
    set_count: u32,
    obj_count: u32,
    use_count: u32,
    chains: [256]*NftChain,
    sets: [128]*NftSet,

    pub fn lookup_chain(self: *const NftTable, name: []const u8) ?*NftChain {
        var i: u32 = 0;
        while (i < self.chain_count) : (i += 1) {
            const chain = self.chains[i];
            if (std.mem.eql(u8, chain.name[0..chain.name_len], name)) {
                return chain;
            }
        }
        return null;
    }
};

// nftables Chain
pub const NftChainType = enum(u8) {
    filter = 0,
    nat = 1,
    route = 2,
};

pub const NftChainPolicy = enum(u8) {
    accept = 0,
    drop = 1,
};

pub const NftChain = struct {
    name: [128]u8,
    name_len: u8,
    chain_type: NftChainType,
    hook: NfHookPoint,
    priority: i32,
    policy: NftChainPolicy,
    flags: u32,
    handle: u64,
    use_count: u32,
    rule_count: u32,
    rules: [1024]*NftRule,
    stats: NftChainStats,

    pub fn evaluate(self: *const NftChain, pkt: *PacketInfo) NfVerdict {
        var i: u32 = 0;
        while (i < self.rule_count) : (i += 1) {
            const rule = self.rules[i];
            const verdict = rule.evaluate(pkt);
            switch (verdict) {
                .accept, .drop, .queue, .stolen => return verdict,
                .@"continue" => continue,
                .@"break" => break,
                .@"return" => return self.policy_verdict(),
                else => continue,
            }
        }
        return self.policy_verdict();
    }

    fn policy_verdict(self: *const NftChain) NfVerdict {
        return switch (self.policy) {
            .accept => .accept,
            .drop => .drop,
        };
    }
};

pub const NftChainStats = struct {
    pkts: u64,
    bytes: u64,
};

// nftables Rule
pub const NftRule = struct {
    handle: u64,
    position: u64,
    expr_count: u32,
    expressions: [64]NftExpression,
    user_data: [256]u8,
    user_data_len: u16,

    pub fn evaluate(self: *const NftRule, pkt: *PacketInfo) NfVerdict {
        var regs: NftRegisters = std.mem.zeroes(NftRegisters);
        var i: u32 = 0;
        while (i < self.expr_count) : (i += 1) {
            const expr = &self.expressions[i];
            const result = expr.execute(pkt, &regs);
            if (!result) {
                return .@"continue"; // Rule didn't match
            }
        }
        return regs.verdict;
    }
};

// nftables Register File
pub const NftRegisters = struct {
    verdict: NfVerdict,
    data: [16][16]u8, // 16 registers of 16 bytes each

    pub fn load_u32(self: *const NftRegisters, reg: u8) u32 {
        const idx = reg & 0x0F;
        return std.mem.readInt(u32, self.data[idx][0..4], .little);
    }

    pub fn store_u32(self: *NftRegisters, reg: u8, val: u32) void {
        const idx = reg & 0x0F;
        std.mem.writeInt(u32, self.data[idx][0..4], val, .little);
    }

    pub fn load_u16(self: *const NftRegisters, reg: u8) u16 {
        const idx = reg & 0x0F;
        return std.mem.readInt(u16, self.data[idx][0..2], .little);
    }

    pub fn store_u16(self: *NftRegisters, reg: u8, val: u16) void {
        const idx = reg & 0x0F;
        std.mem.writeInt(u16, self.data[idx][0..2], val, .little);
    }
};

// nftables Expression (unified)
pub const NftExpression = struct {
    expr_type: NftExprType,
    // Expression-specific data stored in a union
    data: ExprData,

    pub const ExprData = extern union {
        immediate: ImmediateExpr,
        cmp: CmpExpr,
        payload: PayloadExpr,
        meta: MetaExpr,
        ct: CtExpr,
        counter: CounterExpr,
        limit: LimitExpr,
        nat: NatExpr,
        log: LogExpr,
        bitwise: BitwiseExpr,
        lookup: LookupExpr,
    };

    pub fn execute(self: *const NftExpression, pkt: *PacketInfo, regs: *NftRegisters) bool {
        switch (self.expr_type) {
            .immediate => {
                regs.store_u32(self.data.immediate.dreg, self.data.immediate.value);
                return true;
            },
            .cmp => return self.execute_cmp(regs),
            .payload => return self.execute_payload(pkt, regs),
            .meta => return self.execute_meta(pkt, regs),
            .counter => {
                self.data.counter.packets +|= 1;
                self.data.counter.bytes +|= pkt.len;
                return true;
            },
            else => return true,
        }
    }

    fn execute_cmp(self: *const NftExpression, regs: *NftRegisters) bool {
        const cmp = &self.data.cmp;
        const reg_val = regs.load_u32(cmp.sreg);
        return switch (cmp.op) {
            .eq => reg_val == cmp.value,
            .neq => reg_val != cmp.value,
            .lt => reg_val < cmp.value,
            .lte => reg_val <= cmp.value,
            .gt => reg_val > cmp.value,
            .gte => reg_val >= cmp.value,
        };
    }

    fn execute_payload(self: *const NftExpression, pkt: *PacketInfo, regs: *NftRegisters) bool {
        const pl = &self.data.payload;
        const base_offset: u32 = switch (pl.base) {
            .ll_header => pkt.mac_header_offset,
            .network_header => pkt.network_header_offset,
            .transport_header => pkt.transport_header_offset,
            .inner_header => pkt.inner_header_offset,
        };
        const offset = base_offset + pl.offset;
        if (offset + pl.len > pkt.len) return false;

        // Load payload data into register
        var val: u32 = 0;
        if (pl.len >= 1 and offset < pkt.len) val = pkt.data[offset];
        if (pl.len >= 2 and offset + 1 < pkt.len) val |= @as(u32, pkt.data[offset + 1]) << 8;
        if (pl.len >= 4 and offset + 3 < pkt.len) {
            val |= @as(u32, pkt.data[offset + 2]) << 16;
            val |= @as(u32, pkt.data[offset + 3]) << 24;
        }
        regs.store_u32(pl.dreg, val);
        return true;
    }

    fn execute_meta(self: *const NftExpression, pkt: *PacketInfo, regs: *NftRegisters) bool {
        const m = &self.data.meta;
        const val: u32 = switch (m.key) {
            .len => pkt.len,
            .protocol => pkt.protocol,
            .mark => pkt.mark,
            .iif => pkt.iif_index,
            .oif => pkt.oif_index,
            .nfproto => @intFromEnum(pkt.nfproto),
            .l4proto => pkt.l4proto,
            else => 0,
        };
        regs.store_u32(m.dreg, val);
        return true;
    }
};

pub const ImmediateExpr = extern struct {
    dreg: u8,
    value: u32,
    _pad: [3]u8 = .{ 0, 0, 0 },
};

pub const CmpExpr = extern struct {
    op: NftCmpOp,
    sreg: u8,
    value: u32,
    _pad: [2]u8 = .{ 0, 0 },
};

pub const PayloadExpr = extern struct {
    base: NftPayloadBase,
    dreg: u8,
    offset: u32,
    len: u32,
};

pub const MetaExpr = extern struct {
    key: NftMetaKey,
    dreg: u8,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
};

pub const CtExpr = extern struct {
    key: NftCtKey,
    dreg: u8,
    direction: u8,
    _pad: [5]u8 = .{ 0, 0, 0, 0, 0 },
};

pub const CounterExpr = extern struct {
    packets: u64,
    bytes: u64,
};

pub const LimitExpr = extern struct {
    rate: u64,
    unit: u32,
    burst: u32,
    limit_type: u8,
    flags: u8,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
};

pub const NatExpr = extern struct {
    nat_type: u8, // 0=snat, 1=dnat, 2=masq, 3=redirect
    family: u8,
    reg_addr_min: u8,
    reg_addr_max: u8,
    reg_proto_min: u8,
    reg_proto_max: u8,
    flags: u16,
};

pub const LogExpr = extern struct {
    prefix: [64]u8,
    prefix_len: u8,
    group: u16,
    level: u8,
    flags: u32,
};

pub const BitwiseExpr = extern struct {
    sreg: u8,
    dreg: u8,
    len: u8,
    mask: u32,
    xor_val: u32,
};

pub const LookupExpr = extern struct {
    sreg: u8,
    dreg: u8,
    set_id: u32,
    flags: u16,
};

// ============================================================================
// Connection Tracking (conntrack)
// ============================================================================

pub const ConntrackState = enum(u8) {
    new = 0,
    established = 1,
    related = 2,
    invalid = 3,
    untracked = 4,
    // Zxyphor extensions
    snat = 5,
    dnat = 6,
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
    helper: bool = false,
    offload: bool = false,
    hw_offload: bool = false,
    _reserved: u17 = 0,
};

pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    gre = 47,
    icmpv6 = 58,
    sctp = 132,
    udplite = 136,
    dccp = 33,
};

pub const ConntrackTuple = struct {
    src_addr: [16]u8, // IPv4 in first 4 bytes or full IPv6
    dst_addr: [16]u8,
    src_port: u16,
    dst_port: u16,
    l3proto: u16, // AF_INET or AF_INET6
    l4proto: IpProtocol,
    zone: u16,
};

pub const ConntrackEntry = struct {
    original: ConntrackTuple,
    reply: ConntrackTuple,
    status: ConntrackStatus,
    state: ConntrackState,
    timeout: u64,
    mark: u32,
    secmark: u32,
    use_count: u32,
    // Counters
    orig_packets: u64,
    orig_bytes: u64,
    reply_packets: u64,
    reply_bytes: u64,
    // NAT info
    nat_type: u8,
    nat_addr: [16]u8,
    nat_port: u16,
    // Sequence number adjustment (for FTP, SIP, etc.)
    seq_offset_before: u32,
    seq_offset_after: u32,
    // Helper reference
    helper_name: [32]u8,
    helper_name_len: u8,
    // Timestamp
    start_time: u64,
    // Labels (for ct label matching)
    labels: [128]u8,

    pub fn is_confirmed(self: *const ConntrackEntry) bool {
        return self.status.confirmed;
    }

    pub fn is_dying(self: *const ConntrackEntry) bool {
        return self.status.dying;
    }

    pub fn is_natted(self: *const ConntrackEntry) bool {
        return self.status.src_nat or self.status.dst_nat;
    }

    pub fn has_seen_reply(self: *const ConntrackEntry) bool {
        return self.status.seen_reply;
    }

    pub fn total_packets(self: *const ConntrackEntry) u64 {
        return self.orig_packets + self.reply_packets;
    }

    pub fn total_bytes(self: *const ConntrackEntry) u64 {
        return self.orig_bytes + self.reply_bytes;
    }
};

// Conntrack Table
pub const CONNTRACK_TABLE_SIZE: usize = 65536;
pub const CONNTRACK_MAX_ENTRIES: usize = 262144;

pub const ConntrackTable = struct {
    buckets: [CONNTRACK_TABLE_SIZE]?*ConntrackEntry,
    count: u64,
    max_entries: u64,
    hash_rnd: u32,
    // Per-protocol timeouts
    tcp_timeout_established: u32,
    tcp_timeout_syn_sent: u32,
    tcp_timeout_syn_recv: u32,
    tcp_timeout_fin_wait: u32,
    tcp_timeout_close_wait: u32,
    tcp_timeout_last_ack: u32,
    tcp_timeout_time_wait: u32,
    tcp_timeout_close: u32,
    udp_timeout: u32,
    udp_timeout_stream: u32,
    icmp_timeout: u32,
    generic_timeout: u32,

    pub fn init() ConntrackTable {
        return ConntrackTable{
            .buckets = [_]?*ConntrackEntry{null} ** CONNTRACK_TABLE_SIZE,
            .count = 0,
            .max_entries = CONNTRACK_MAX_ENTRIES,
            .hash_rnd = 0x5bd1e995,
            .tcp_timeout_established = 432000,
            .tcp_timeout_syn_sent = 120,
            .tcp_timeout_syn_recv = 60,
            .tcp_timeout_fin_wait = 120,
            .tcp_timeout_close_wait = 60,
            .tcp_timeout_last_ack = 30,
            .tcp_timeout_time_wait = 120,
            .tcp_timeout_close = 10,
            .udp_timeout = 30,
            .udp_timeout_stream = 180,
            .icmp_timeout = 30,
            .generic_timeout = 600,
        };
    }

    pub fn hash_tuple(self: *const ConntrackTable, tuple: *const ConntrackTuple) u32 {
        var h: u32 = self.hash_rnd;
        // Mix source and destination addresses
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            h = h *% 0x5bd1e995;
            h ^= @as(u32, tuple.src_addr[i]);
            h ^= @as(u32, tuple.dst_addr[i]) << 8;
        }
        h ^= @as(u32, tuple.src_port) << 16;
        h ^= @as(u32, tuple.dst_port);
        h ^= @intFromEnum(tuple.l4proto);
        h ^= h >> 13;
        h *%= 0x5bd1e995;
        h ^= h >> 15;
        return h % CONNTRACK_TABLE_SIZE;
    }

    pub fn lookup(self: *ConntrackTable, tuple: *const ConntrackTuple) ?*ConntrackEntry {
        const idx = self.hash_tuple(tuple);
        return self.buckets[idx];
    }

    pub fn insert(self: *ConntrackTable, entry: *ConntrackEntry) bool {
        if (self.count >= self.max_entries) return false;
        const idx = self.hash_tuple(&entry.original);
        self.buckets[idx] = entry;
        self.count += 1;
        return true;
    }

    pub fn remove(self: *ConntrackTable, tuple: *const ConntrackTuple) bool {
        const idx = self.hash_tuple(tuple);
        if (self.buckets[idx] != null) {
            self.buckets[idx] = null;
            self.count -= 1;
            return true;
        }
        return false;
    }
};

// ============================================================================
// NAT Engine
// ============================================================================

pub const NatType = enum(u8) {
    snat = 0,
    dnat = 1,
    masquerade = 2,
    redirect = 3,
    fullcone = 4,
    cgnat = 5,     // Carrier-Grade NAT
    nat64 = 6,     // NAT64 translation
};

pub const NatRange = struct {
    flags: u32,
    min_addr: [16]u8,
    max_addr: [16]u8,
    min_port: u16,
    max_port: u16,
};

pub const NatMapping = struct {
    nat_type: NatType,
    original_src: [16]u8,
    original_dst: [16]u8,
    original_sport: u16,
    original_dport: u16,
    translated_src: [16]u8,
    translated_dst: [16]u8,
    translated_sport: u16,
    translated_dport: u16,
    protocol: IpProtocol,
    timeout: u64,
    use_count: u32,
};

pub const NAT_TABLE_SIZE: usize = 16384;

pub const NatTable = struct {
    mappings: [NAT_TABLE_SIZE]?NatMapping,
    count: u32,
    port_range_min: u16,
    port_range_max: u16,

    pub fn init() NatTable {
        return NatTable{
            .mappings = [_]?NatMapping{null} ** NAT_TABLE_SIZE,
            .count = 0,
            .port_range_min = 1024,
            .port_range_max = 65535,
        };
    }

    pub fn allocate_port(self: *NatTable, protocol: IpProtocol) ?u16 {
        _ = protocol;
        var port = self.port_range_min;
        while (port <= self.port_range_max) : (port += 1) {
            var in_use = false;
            for (&self.mappings) |*m| {
                if (m.*) |mapping| {
                    if (mapping.translated_sport == port) {
                        in_use = true;
                        break;
                    }
                }
            }
            if (!in_use) return port;
        }
        return null;
    }
};

// ============================================================================
// IPsec / XFRM Framework
// ============================================================================

pub const XfrmMode = enum(u8) {
    transport = 0,
    tunnel = 1,
    beet = 4,
    route_optimization = 2,
    in_trigger = 3,
};

pub const XfrmProto = enum(u8) {
    esp = 50,
    ah = 51,
    comp = 108,
    ipip = 4,
    ipv6 = 41,
    routing = 43,
    dstopts = 60,
};

pub const XfrmDir = enum(u8) {
    in_dir = 0,
    out_dir = 1,
    fwd = 2,
};

pub const XfrmSelector = struct {
    daddr: [16]u8,
    saddr: [16]u8,
    dport: u16,
    dport_mask: u16,
    sport: u16,
    sport_mask: u16,
    family: u16,
    prefixlen_d: u8,
    prefixlen_s: u8,
    proto: u8,
    ifindex: u32,
    user: u32,
};

pub const XfrmLifetimeCfg = struct {
    soft_byte_limit: u64,
    hard_byte_limit: u64,
    soft_packet_limit: u64,
    hard_packet_limit: u64,
    soft_add_expires_seconds: u64,
    hard_add_expires_seconds: u64,
    soft_use_expires_seconds: u64,
    hard_use_expires_seconds: u64,
};

pub const XfrmLifetimeCur = struct {
    bytes: u64,
    packets: u64,
    add_time: u64,
    use_time: u64,
};

pub const XfrmId = struct {
    daddr: [16]u8,
    spi: u32,
    proto: XfrmProto,
};

// XFRM/IPsec State (Security Association)
pub const XfrmState = struct {
    id: XfrmId,
    sel: XfrmSelector,
    lft: XfrmLifetimeCfg,
    curlft: XfrmLifetimeCur,
    mode: XfrmMode,
    replay_window: u32,
    flags: u32,
    family: u16,
    reqid: u32,
    // Algorithm information
    aalg_name: [64]u8,
    aalg_key: [512]u8,
    aalg_key_len: u32,
    ealg_name: [64]u8,
    ealg_key: [512]u8,
    ealg_key_len: u32,
    calg_name: [64]u8,
    // Replay detection
    replay_seq: u32,
    replay_seq_hi: u32,
    replay_oseq: u32,
    replay_oseq_hi: u32,
    replay_bitmap: [32]u32,  // 1024-bit replay window
    // Encapsulation
    encap_type: u16,
    encap_sport: u16,
    encap_dport: u16,
    encap_oa: [16]u8,
    // Statistics
    stats_replay_window: u64,
    stats_replay: u64,
    stats_integrity_failed: u64,
};

// XFRM Policy
pub const XfrmPolicy = struct {
    sel: XfrmSelector,
    lft: XfrmLifetimeCfg,
    curlft: XfrmLifetimeCur,
    dir: XfrmDir,
    action: u8, // 0=allow, 1=block
    flags: u32,
    priority: u32,
    index: u32,
    share: u8,
    template_count: u8,
    templates: [6]XfrmTemplate,
};

pub const XfrmTemplate = struct {
    id: XfrmId,
    saddr: [16]u8,
    reqid: u32,
    mode: XfrmMode,
    share: u8,
    optional: u8,
    aalgos: u32,
    ealgos: u32,
    calgos: u32,
};

// XFRM State Database
pub const XFRM_STATE_TABLE_SIZE: usize = 4096;

pub const XfrmStateDb = struct {
    states: [XFRM_STATE_TABLE_SIZE]?XfrmState,
    count: u32,

    pub fn init() XfrmStateDb {
        return XfrmStateDb{
            .states = [_]?XfrmState{null} ** XFRM_STATE_TABLE_SIZE,
            .count = 0,
        };
    }

    pub fn lookup_by_spi(self: *XfrmStateDb, spi: u32, proto: XfrmProto) ?*XfrmState {
        for (&self.states) |*s| {
            if (s.*) |*state| {
                if (state.id.spi == spi and state.id.proto == proto) {
                    return state;
                }
            }
        }
        return null;
    }

    pub fn add_state(self: *XfrmStateDb, state: XfrmState) bool {
        for (&self.states) |*s| {
            if (s.* == null) {
                s.* = state;
                self.count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn delete_state(self: *XfrmStateDb, spi: u32, proto: XfrmProto) bool {
        for (&self.states) |*s| {
            if (s.*) |state| {
                if (state.id.spi == spi and state.id.proto == proto) {
                    s.* = null;
                    self.count -= 1;
                    return true;
                }
            }
        }
        return false;
    }
};

// ============================================================================
// Packet Info (for evaluation)
// ============================================================================

pub const PacketInfo = struct {
    data: [*]const u8,
    len: u32,
    mark: u32,
    protocol: u32,
    nfproto: NfProto,
    l4proto: u32,
    iif_index: u32,
    oif_index: u32,
    mac_header_offset: u32,
    network_header_offset: u32,
    transport_header_offset: u32,
    inner_header_offset: u32,
    ct_state: ConntrackState,
    ct_entry: ?*ConntrackEntry,
    sec_mark: u32,
    cgroup_id: u64,
    skb_priority: u32,
    tos: u8,
    ttl: u8,
};

// ============================================================================
// nftables Sets
// ============================================================================

pub const NftSetType = enum(u8) {
    hash = 0,
    rbtree = 1,
    bitmap = 2,
    concat = 3,
    pipapo = 4,  // PIle PAcket POlicies
};

pub const NftSet = struct {
    name: [128]u8,
    name_len: u8,
    set_type: NftSetType,
    key_type: u32,
    key_len: u32,
    data_type: u32,
    data_len: u32,
    flags: u32,
    size: u32,
    timeout: u64,
    gc_interval: u32,
    policy: u32,
    handle: u64,
    element_count: u32,
    elements: [4096]NftSetElement,
};

pub const NftSetElement = struct {
    key: [64]u8,
    key_len: u8,
    data: [64]u8,
    data_len: u8,
    flags: u32,
    timeout: u64,
    expiration: u64,
};

// ============================================================================
// Flow Offload
// ============================================================================

pub const FlowOffloadType = enum(u8) {
    software = 0,
    hardware = 1,
};

pub const FlowOffloadEntry = struct {
    offload_type: FlowOffloadType,
    src_addr: [16]u8,
    dst_addr: [16]u8,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    family: u8,
    iif_index: u32,
    oif_index: u32,
    // Translated addresses for NAT offload
    nat_src_addr: [16]u8,
    nat_dst_addr: [16]u8,
    nat_src_port: u16,
    nat_dst_port: u16,
    // Stats
    packets: u64,
    bytes: u64,
    last_used: u64,
    timeout: u64,
};

pub const FLOW_OFFLOAD_TABLE_SIZE: usize = 32768;

pub const FlowOffloadTable = struct {
    entries: [FLOW_OFFLOAD_TABLE_SIZE]?FlowOffloadEntry,
    count: u32,
    hw_offload_count: u32,

    pub fn init() FlowOffloadTable {
        return FlowOffloadTable{
            .entries = [_]?FlowOffloadEntry{null} ** FLOW_OFFLOAD_TABLE_SIZE,
            .count = 0,
            .hw_offload_count = 0,
        };
    }
};

// ============================================================================
// Conntrack Helpers
// ============================================================================

pub const CtHelperType = enum(u8) {
    ftp = 0,
    tftp = 1,
    irc = 2,
    sip = 3,
    h323 = 4,
    pptp = 5,
    snmp = 6,
    amanda = 7,
    netbios_ns = 8,
    broadcast = 9,
    // Zxyphor extensions
    zxy_quic = 200,
    zxy_wireguard = 201,
};

pub const CtHelper = struct {
    name: [32]u8,
    name_len: u8,
    helper_type: CtHelperType,
    tuple_protocol: IpProtocol,
    tuple_port: u16,
    max_expected: u32,
    timeout: u32,
    flags: u32,

    pub fn matches_tuple(self: *const CtHelper, tuple: *const ConntrackTuple) bool {
        if (@intFromEnum(self.tuple_protocol) != @intFromEnum(tuple.l4proto)) return false;
        if (self.tuple_port != 0 and self.tuple_port != tuple.dst_port) return false;
        return true;
    }
};

// ============================================================================
// Synproxy
// ============================================================================

pub const SynproxyInfo = struct {
    isn: u32,
    its: u32,
    wscale: u8,
    mss: u16,
    options: u32,
    tsoff: u32,
};

// ============================================================================
// Rate Limiting / Token Bucket
// ============================================================================

pub const RateLimitType = enum(u8) {
    packets = 0,
    bytes = 1,
};

pub const RateLimiter = struct {
    rate: u64,
    burst: u64,
    limit_type: RateLimitType,
    tokens: u64,
    last_update: u64,
    packets_matched: u64,
    bytes_matched: u64,
    packets_dropped: u64,

    pub fn init(rate: u64, burst: u64, limit_type: RateLimitType) RateLimiter {
        return RateLimiter{
            .rate = rate,
            .burst = burst,
            .limit_type = limit_type,
            .tokens = burst,
            .last_update = 0,
            .packets_matched = 0,
            .bytes_matched = 0,
            .packets_dropped = 0,
        };
    }

    pub fn check(self: *RateLimiter, now: u64, cost: u64) bool {
        const elapsed = now -| self.last_update;
        const new_tokens = elapsed *| self.rate / 1_000_000_000;
        self.tokens = @min(self.tokens +| new_tokens, self.burst);
        self.last_update = now;

        if (self.tokens >= cost) {
            self.tokens -= cost;
            return true;
        }
        return false;
    }
};

// ============================================================================
// Network Namespace Firewall Rules
// ============================================================================

pub const NetnsFirewall = struct {
    tables: [32]?*NftTable,
    table_count: u32,
    ct_table: ConntrackTable,
    nat_table: NatTable,
    flow_table: FlowOffloadTable,
    xfrm_state_db: XfrmStateDb,
    default_policy_in: NfVerdict,
    default_policy_out: NfVerdict,
    default_policy_fwd: NfVerdict,

    pub fn init() NetnsFirewall {
        return NetnsFirewall{
            .tables = [_]?*NftTable{null} ** 32,
            .table_count = 0,
            .ct_table = ConntrackTable.init(),
            .nat_table = NatTable.init(),
            .flow_table = FlowOffloadTable.init(),
            .xfrm_state_db = XfrmStateDb.init(),
            .default_policy_in = .accept,
            .default_policy_out = .accept,
            .default_policy_fwd = .drop,
        };
    }

    pub fn process_packet(self: *NetnsFirewall, pkt: *PacketInfo, hook: NfHookPoint) NfVerdict {
        // 1. Check flow offload table first
        // 2. Connection tracking lookup
        if (self.ct_table.lookup(&ConntrackTuple{
            .src_addr = undefined,
            .dst_addr = undefined,
            .src_port = 0,
            .dst_port = 0,
            .l3proto = 0,
            .l4proto = .tcp,
            .zone = 0,
        })) |ct| {
            pkt.ct_entry = ct;
            pkt.ct_state = ct.state;
        }

        // 3. Evaluate nftables chains
        var verdict: NfVerdict = .accept;
        var i: u32 = 0;
        while (i < self.table_count) : (i += 1) {
            if (self.tables[i]) |table| {
                var j: u32 = 0;
                while (j < table.chain_count) : (j += 1) {
                    const chain = table.chains[j];
                    if (chain.hook == hook) {
                        verdict = chain.evaluate(pkt);
                        if (verdict == .drop) return .drop;
                    }
                }
            }
        }

        return verdict;
    }
};
