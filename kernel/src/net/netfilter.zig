// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Zig Network Filter / Firewall
//
// Implements a Linux-like netfilter framework:
// - Hook points (PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING)
// - Rule chains with priority ordering
// - Match criteria (IP src/dst, port, protocol, interface, state)
// - Target actions (ACCEPT, DROP, REJECT, LOG, SNAT, DNAT, MASQUERADE)
// - Connection tracking (conntrack)
// - NAT table
// - Rate limiting
// - CIDR matching

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_RULES = 256;
pub const MAX_CHAINS = 32;
pub const MAX_CONNTRACK = 4096;
pub const MAX_NAT_ENTRIES = 512;
pub const MAX_IFACE_NAME = 16;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ANY: u8 = 0;

// ─────────────────── Hook Points ────────────────────────────────────
pub const Hook = enum(u8) {
    pre_routing = 0,
    local_in = 1,
    forward = 2,
    local_out = 3,
    post_routing = 4,
};

// ─────────────────── Verdict / Target ───────────────────────────────
pub const Verdict = enum(u8) {
    accept = 0,
    drop = 1,
    reject = 2,
    log = 3,
    queue = 4,
    @"return" = 5,
    jump = 6,
    // NAT targets
    snat = 10,
    dnat = 11,
    masquerade = 12,
    redirect = 13,
};

// ─────────────────── Connection State ───────────────────────────────
pub const ConnState = enum(u8) {
    new = 0,
    established = 1,
    related = 2,
    invalid = 3,
    untracked = 4,
};

// ─────────────────── IPv4 Address ───────────────────────────────────
pub const Ipv4Addr = packed struct {
    a: u8 = 0,
    b: u8 = 0,
    c: u8 = 0,
    d: u8 = 0,

    pub fn from_u32(v: u32) Ipv4Addr {
        return .{
            .a = @intCast((v >> 24) & 0xFF),
            .b = @intCast((v >> 16) & 0xFF),
            .c = @intCast((v >> 8) & 0xFF),
            .d = @intCast(v & 0xFF),
        };
    }

    pub fn to_u32(self: Ipv4Addr) u32 {
        return (@as(u32, self.a) << 24) |
            (@as(u32, self.b) << 16) |
            (@as(u32, self.c) << 8) |
            @as(u32, self.d);
    }

    pub fn matches_cidr(self: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) bool {
        if (prefix_len == 0) return true;
        if (prefix_len > 32) return false;
        const mask: u32 = if (prefix_len == 32) 0xFFFFFFFF else ~((@as(u32, 1) << @intCast(32 - prefix_len)) - 1);
        return (self.to_u32() & mask) == (network.to_u32() & mask);
    }

    pub fn is_any(self: Ipv4Addr) bool {
        return self.to_u32() == 0;
    }
};

// ─────────────────── Port Range ─────────────────────────────────────
pub const PortRange = struct {
    min: u16 = 0,
    max: u16 = 65535,

    pub fn matches(self: *const PortRange, port: u16) bool {
        return port >= self.min and port <= self.max;
    }

    pub fn any() PortRange {
        return .{ .min = 0, .max = 65535 };
    }

    pub fn single(port: u16) PortRange {
        return .{ .min = port, .max = port };
    }
};

// ─────────────────── Match Criteria ─────────────────────────────────
pub const MatchFlags = packed struct {
    src_ip: bool = false,
    dst_ip: bool = false,
    src_port: bool = false,
    dst_port: bool = false,
    protocol: bool = false,
    in_iface: bool = false,
    out_iface: bool = false,
    conn_state: bool = false,
    /// Invert the match
    negate_src_ip: bool = false,
    negate_dst_ip: bool = false,
    negate_protocol: bool = false,
    _pad: u5 = 0,
};

pub const RuleMatch = struct {
    flags: MatchFlags = .{},
    src_ip: Ipv4Addr = .{},
    src_prefix: u8 = 0,
    dst_ip: Ipv4Addr = .{},
    dst_prefix: u8 = 0,
    src_port: PortRange = PortRange.any(),
    dst_port: PortRange = PortRange.any(),
    protocol: u8 = PROTO_ANY,
    in_iface: [MAX_IFACE_NAME]u8 = [_]u8{0} ** MAX_IFACE_NAME,
    in_iface_len: u8 = 0,
    out_iface: [MAX_IFACE_NAME]u8 = [_]u8{0} ** MAX_IFACE_NAME,
    out_iface_len: u8 = 0,
    conn_state_mask: u8 = 0, // bitmask of ConnState values
};

// ─────────────────── Rule ───────────────────────────────────────────
pub const Rule = struct {
    id: u16 = 0,
    chain_id: u16 = 0,
    priority: i16 = 0,
    match_criteria: RuleMatch = .{},
    target: Verdict = .accept,
    /// For SNAT/DNAT: new address
    nat_addr: Ipv4Addr = .{},
    /// For SNAT/DNAT: new port
    nat_port: u16 = 0,
    /// For jump: target chain
    jump_chain: u16 = 0,
    /// Rate limit: packets per second
    rate_limit: u32 = 0,
    rate_burst: u32 = 0,
    /// Statistics
    packet_count: u64 = 0,
    byte_count: u64 = 0,
    /// Enabled
    enabled: bool = true,
    /// Log prefix
    log_prefix: [32]u8 = [_]u8{0} ** 32,
    log_prefix_len: u8 = 0,
};

// ─────────────────── Chain ──────────────────────────────────────────
pub const ChainType = enum(u8) {
    filter = 0,
    nat = 1,
    mangle = 2,
    raw = 3,
};

pub const Chain = struct {
    id: u16 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    hook: Hook = .local_in,
    chain_type: ChainType = .filter,
    policy: Verdict = .accept,
    priority: i16 = 0,
    rule_count: u16 = 0,
    enabled: bool = true,

    pub fn set_name(self: *Chain, n: []const u8) void {
        const len = @min(n.len, 32);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn get_name(self: *const Chain) []const u8 {
        return self.name[0..self.name_len];
    }
};

// ─────────────────── Connection Tracking ────────────────────────────
pub const ConntrackTuple = struct {
    src_ip: Ipv4Addr = .{},
    dst_ip: Ipv4Addr = .{},
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: u8 = 0,

    pub fn hash(self: *const ConntrackTuple) u32 {
        var h: u32 = 0x811c9dc5;
        h ^= self.src_ip.to_u32();
        h *%= 0x01000193;
        h ^= self.dst_ip.to_u32();
        h *%= 0x01000193;
        h ^= @as(u32, self.src_port) << 16 | @as(u32, self.dst_port);
        h *%= 0x01000193;
        h ^= self.protocol;
        h *%= 0x01000193;
        return h;
    }

    pub fn equals(self: *const ConntrackTuple, other: *const ConntrackTuple) bool {
        return self.src_ip.to_u32() == other.src_ip.to_u32() and
            self.dst_ip.to_u32() == other.dst_ip.to_u32() and
            self.src_port == other.src_port and
            self.dst_port == other.dst_port and
            self.protocol == other.protocol;
    }

    /// Create the reverse tuple
    pub fn reverse(self: *const ConntrackTuple) ConntrackTuple {
        return .{
            .src_ip = self.dst_ip,
            .dst_ip = self.src_ip,
            .src_port = self.dst_port,
            .dst_port = self.src_port,
            .protocol = self.protocol,
        };
    }
};

pub const ConntrackEntry = struct {
    original: ConntrackTuple = .{},
    reply: ConntrackTuple = .{},
    state: ConnState = .new,
    /// Timestamp of last packet (kernel ticks)
    last_seen: u64 = 0,
    /// Creation timestamp
    created: u64 = 0,
    /// Timeout in ticks
    timeout: u64 = 0,
    /// Packet/byte counters for original direction
    orig_packets: u64 = 0,
    orig_bytes: u64 = 0,
    /// Packet/byte counters for reply direction
    reply_packets: u64 = 0,
    reply_bytes: u64 = 0,
    /// NAT applied?
    nat_type: u8 = 0, // 0=none, 1=snat, 2=dnat
    nat_addr: Ipv4Addr = .{},
    nat_port: u16 = 0,
    /// Mark
    mark: u32 = 0,
    /// Valid
    valid: bool = false,
};

// ─────────────────── NAT Entry ──────────────────────────────────────
pub const NatEntry = struct {
    original_addr: Ipv4Addr = .{},
    original_port: u16 = 0,
    translated_addr: Ipv4Addr = .{},
    translated_port: u16 = 0,
    protocol: u8 = 0,
    nat_type: u8 = 0, // 1=snat, 2=dnat
    valid: bool = false,
};

// ─────────────────── Rate Limiter ───────────────────────────────────
pub const RateLimiter = struct {
    tokens: u32 = 0,
    max_tokens: u32 = 0,
    refill_rate: u32 = 0, // tokens per second
    last_refill: u64 = 0,

    pub fn init(rate: u32, burst: u32) RateLimiter {
        return .{
            .tokens = burst,
            .max_tokens = burst,
            .refill_rate = rate,
            .last_refill = 0,
        };
    }

    pub fn allow(self: *RateLimiter, now: u64) bool {
        // Refill tokens
        if (now > self.last_refill) {
            const elapsed = now - self.last_refill;
            const new_tokens = @as(u32, @intCast(@min(elapsed * self.refill_rate, 0xFFFFFFFF)));
            self.tokens = @min(self.tokens + new_tokens, self.max_tokens);
            self.last_refill = now;
        }
        if (self.tokens > 0) {
            self.tokens -= 1;
            return true;
        }
        return false;
    }
};

// ─────────────────── Packet Info ────────────────────────────────────
pub const PacketInfo = struct {
    src_ip: Ipv4Addr = .{},
    dst_ip: Ipv4Addr = .{},
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: u8 = 0,
    length: u32 = 0,
    in_iface: [MAX_IFACE_NAME]u8 = [_]u8{0} ** MAX_IFACE_NAME,
    in_iface_len: u8 = 0,
    out_iface: [MAX_IFACE_NAME]u8 = [_]u8{0} ** MAX_IFACE_NAME,
    out_iface_len: u8 = 0,
    /// Connection state (set by conntrack)
    conn_state: ConnState = .new,
    /// Mark
    mark: u32 = 0,
};

// ─────────────────── Firewall Engine ────────────────────────────────
pub const Firewall = struct {
    chains: [MAX_CHAINS]?Chain = [_]?Chain{null} ** MAX_CHAINS,
    chain_count: u16 = 0,
    rules: [MAX_RULES]?Rule = [_]?Rule{null} ** MAX_RULES,
    rule_count: u16 = 0,
    conntrack: [MAX_CONNTRACK]ConntrackEntry = [_]ConntrackEntry{.{}} ** MAX_CONNTRACK,
    conntrack_count: u32 = 0,
    nat_table: [MAX_NAT_ENTRIES]NatEntry = [_]NatEntry{.{}} ** MAX_NAT_ENTRIES,
    nat_count: u16 = 0,
    rate_limiters: [MAX_RULES]?RateLimiter = [_]?RateLimiter{null} ** MAX_RULES,
    /// Global statistics
    total_packets: u64 = 0,
    total_dropped: u64 = 0,
    total_accepted: u64 = 0,
    total_rejected: u64 = 0,
    total_logged: u64 = 0,
    /// Current tick
    current_tick: u64 = 0,
    /// Connection timeout defaults (in ticks)
    tcp_established_timeout: u64 = 432000, // 5 days
    tcp_syn_timeout: u64 = 120,
    udp_timeout: u64 = 30,
    icmp_timeout: u64 = 30,
    /// Enable connection tracking
    conntrack_enabled: bool = true,
    /// Enable NAT
    nat_enabled: bool = false,
    /// Initialized
    initialized: bool = false,

    pub fn init(self: *Firewall) void {
        // Create default chains
        self.create_builtin_chains();
        self.initialized = true;
    }

    fn create_builtin_chains(self: *Firewall) void {
        // INPUT chain (filter)
        self.add_chain("INPUT", .local_in, .filter, 0);
        // FORWARD chain (filter)
        self.add_chain("FORWARD", .forward, .filter, 0);
        // OUTPUT chain (filter)
        self.add_chain("OUTPUT", .local_out, .filter, 0);
        // PREROUTING chain (nat)
        self.add_chain("PREROUTING", .pre_routing, .nat, -100);
        // POSTROUTING chain (nat)
        self.add_chain("POSTROUTING", .post_routing, .nat, 100);
    }

    pub fn add_chain(self: *Firewall, name: []const u8, hook: Hook, chain_type: ChainType, priority: i16) ?u16 {
        if (self.chain_count >= MAX_CHAINS) return null;
        var chain = Chain{};
        chain.id = self.chain_count;
        chain.set_name(name);
        chain.hook = hook;
        chain.chain_type = chain_type;
        chain.priority = priority;
        self.chains[self.chain_count] = chain;
        const id = self.chain_count;
        self.chain_count += 1;
        return id;
    }

    pub fn set_chain_policy(self: *Firewall, chain_id: u16, policy: Verdict) void {
        if (chain_id < MAX_CHAINS) {
            if (self.chains[chain_id]) |*chain| {
                chain.policy = policy;
            }
        }
    }

    pub fn add_rule(self: *Firewall, chain_id: u16, match_criteria: RuleMatch, target: Verdict, priority: i16) ?u16 {
        if (self.rule_count >= MAX_RULES) return null;

        var rule = Rule{};
        rule.id = self.rule_count;
        rule.chain_id = chain_id;
        rule.match_criteria = match_criteria;
        rule.target = target;
        rule.priority = priority;

        self.rules[self.rule_count] = rule;
        const id = self.rule_count;
        self.rule_count += 1;

        // Update chain rule count
        if (chain_id < MAX_CHAINS) {
            if (self.chains[chain_id]) |*chain| {
                chain.rule_count += 1;
            }
        }

        return id;
    }

    pub fn set_rule_nat(self: *Firewall, rule_id: u16, addr: Ipv4Addr, port: u16) void {
        if (rule_id < MAX_RULES) {
            if (self.rules[rule_id]) |*rule| {
                rule.nat_addr = addr;
                rule.nat_port = port;
            }
        }
    }

    pub fn set_rule_rate_limit(self: *Firewall, rule_id: u16, rate: u32, burst: u32) void {
        if (rule_id < MAX_RULES) {
            if (self.rules[rule_id]) |*rule| {
                rule.rate_limit = rate;
                rule.rate_burst = burst;
                self.rate_limiters[rule_id] = RateLimiter.init(rate, burst);
            }
        }
    }

    pub fn delete_rule(self: *Firewall, rule_id: u16) void {
        if (rule_id < MAX_RULES) {
            if (self.rules[rule_id]) |*rule| {
                if (rule.chain_id < MAX_CHAINS) {
                    if (self.chains[rule.chain_id]) |*chain| {
                        if (chain.rule_count > 0) chain.rule_count -= 1;
                    }
                }
                rule.enabled = false;
            }
        }
    }

    /// Process a packet through the firewall
    pub fn process_packet(self: *Firewall, pkt: *PacketInfo, hook: Hook) Verdict {
        self.total_packets += 1;
        self.current_tick += 1;

        // Connection tracking lookup
        if (self.conntrack_enabled) {
            self.conntrack_lookup(pkt);
        }

        // Find all chains for this hook, sorted by priority
        var chain_ids: [MAX_CHAINS]u16 = undefined;
        var chain_count: u16 = 0;

        for (self.chains[0..self.chain_count]) |maybe_chain| {
            if (maybe_chain) |chain| {
                if (chain.hook == hook and chain.enabled) {
                    if (chain_count < MAX_CHAINS) {
                        chain_ids[chain_count] = chain.id;
                        chain_count += 1;
                    }
                }
            }
        }

        // Sort chains by priority (simple insertion sort)
        for (1..chain_count) |i| {
            const key = chain_ids[i];
            var j = i;
            while (j > 0) {
                const chain_j = self.chains[chain_ids[j - 1]] orelse break;
                const chain_key = self.chains[key] orelse break;
                if (chain_j.priority <= chain_key.priority) break;
                chain_ids[j] = chain_ids[j - 1];
                j -= 1;
            }
            chain_ids[j] = key;
        }

        // Evaluate each chain
        for (chain_ids[0..chain_count]) |cid| {
            const verdict = self.evaluate_chain(cid, pkt);
            switch (verdict) {
                .accept => {
                    self.total_accepted += 1;
                    return .accept;
                },
                .drop => {
                    self.total_dropped += 1;
                    return .drop;
                },
                .reject => {
                    self.total_rejected += 1;
                    return .reject;
                },
                .@"return" => continue,
                else => {},
            }
        }

        // Check default policy of first matching chain
        if (chain_count > 0) {
            if (self.chains[chain_ids[0]]) |chain| {
                return chain.policy;
            }
        }

        return .accept;
    }

    fn evaluate_chain(self: *Firewall, chain_id: u16, pkt: *PacketInfo) Verdict {
        for (self.rules[0..self.rule_count]) |*maybe_rule| {
            if (maybe_rule.*) |*rule| {
                if (rule.chain_id != chain_id or !rule.enabled) continue;
                if (!self.match_rule(rule, pkt)) continue;

                // Rate limiting check
                if (rule.rate_limit > 0) {
                    if (self.rate_limiters[rule.id]) |*limiter| {
                        if (!limiter.allow(self.current_tick)) continue;
                    }
                }

                // Update statistics
                rule.packet_count += 1;
                rule.byte_count += pkt.length;

                switch (rule.target) {
                    .log => {
                        self.total_logged += 1;
                        // Continue processing after LOG
                        continue;
                    },
                    .jump => {
                        const sub_verdict = self.evaluate_chain(rule.jump_chain, pkt);
                        if (sub_verdict != .@"return") return sub_verdict;
                        continue;
                    },
                    .snat => {
                        self.apply_snat(pkt, rule);
                        return .accept;
                    },
                    .dnat => {
                        self.apply_dnat(pkt, rule);
                        return .accept;
                    },
                    .masquerade => {
                        // Masquerade = SNAT with outgoing interface IP
                        self.apply_snat(pkt, rule);
                        return .accept;
                    },
                    else => return rule.target,
                }
            }
        }

        // No rule matched, use chain policy
        if (chain_id < MAX_CHAINS) {
            if (self.chains[chain_id]) |chain| {
                return chain.policy;
            }
        }
        return .accept;
    }

    fn match_rule(self: *const Firewall, rule: *const Rule, pkt: *const PacketInfo) bool {
        _ = self;
        const m = &rule.match_criteria;
        const f = m.flags;

        // Source IP match
        if (f.src_ip) {
            const matched = pkt.src_ip.matches_cidr(m.src_ip, m.src_prefix);
            if (f.negate_src_ip) {
                if (matched) return false;
            } else {
                if (!matched) return false;
            }
        }

        // Destination IP match
        if (f.dst_ip) {
            const matched = pkt.dst_ip.matches_cidr(m.dst_ip, m.dst_prefix);
            if (f.negate_dst_ip) {
                if (matched) return false;
            } else {
                if (!matched) return false;
            }
        }

        // Protocol match
        if (f.protocol) {
            const matched = m.protocol == PROTO_ANY or m.protocol == pkt.protocol;
            if (f.negate_protocol) {
                if (matched) return false;
            } else {
                if (!matched) return false;
            }
        }

        // Source port match
        if (f.src_port) {
            if (!m.src_port.matches(pkt.src_port)) return false;
        }

        // Destination port match
        if (f.dst_port) {
            if (!m.dst_port.matches(pkt.dst_port)) return false;
        }

        // Input interface
        if (f.in_iface) {
            if (m.in_iface_len != pkt.in_iface_len) return false;
            if (!std.mem.eql(u8, m.in_iface[0..m.in_iface_len], pkt.in_iface[0..pkt.in_iface_len])) return false;
        }

        // Output interface
        if (f.out_iface) {
            if (m.out_iface_len != pkt.out_iface_len) return false;
            if (!std.mem.eql(u8, m.out_iface[0..m.out_iface_len], pkt.out_iface[0..pkt.out_iface_len])) return false;
        }

        // Connection state match
        if (f.conn_state) {
            const state_bit = @as(u8, 1) << @intFromEnum(pkt.conn_state);
            if ((m.conn_state_mask & state_bit) == 0) return false;
        }

        return true;
    }

    // ──────── Connection Tracking ────────
    fn conntrack_lookup(self: *Firewall, pkt: *PacketInfo) void {
        const tuple = ConntrackTuple{
            .src_ip = pkt.src_ip,
            .dst_ip = pkt.dst_ip,
            .src_port = pkt.src_port,
            .dst_port = pkt.dst_port,
            .protocol = pkt.protocol,
        };

        const idx = tuple.hash() % MAX_CONNTRACK;

        // Check original direction
        if (self.conntrack[idx].valid and self.conntrack[idx].original.equals(&tuple)) {
            self.conntrack[idx].last_seen = self.current_tick;
            self.conntrack[idx].orig_packets += 1;
            self.conntrack[idx].orig_bytes += pkt.length;

            if (self.conntrack[idx].state == .new) {
                self.conntrack[idx].state = .established;
            }
            pkt.conn_state = self.conntrack[idx].state;
            return;
        }

        // Check reply direction
        const reply = tuple.reverse();
        const ridx = reply.hash() % MAX_CONNTRACK;
        if (self.conntrack[ridx].valid and self.conntrack[ridx].original.equals(&reply)) {
            self.conntrack[ridx].last_seen = self.current_tick;
            self.conntrack[ridx].reply_packets += 1;
            self.conntrack[ridx].reply_bytes += pkt.length;
            self.conntrack[ridx].state = .established;
            pkt.conn_state = .established;
            return;
        }

        // Create new connection
        self.conntrack[idx] = .{
            .original = tuple,
            .reply = tuple.reverse(),
            .state = .new,
            .last_seen = self.current_tick,
            .created = self.current_tick,
            .timeout = switch (pkt.protocol) {
                PROTO_TCP => self.tcp_syn_timeout,
                PROTO_UDP => self.udp_timeout,
                PROTO_ICMP => self.icmp_timeout,
                else => 60,
            },
            .valid = true,
        };
        self.conntrack_count += 1;
        pkt.conn_state = .new;
    }

    fn apply_snat(self: *Firewall, pkt: *PacketInfo, rule: *const Rule) void {
        if (self.nat_count >= MAX_NAT_ENTRIES) return;
        self.nat_table[self.nat_count] = .{
            .original_addr = pkt.src_ip,
            .original_port = pkt.src_port,
            .translated_addr = rule.nat_addr,
            .translated_port = if (rule.nat_port != 0) rule.nat_port else pkt.src_port,
            .protocol = pkt.protocol,
            .nat_type = 1,
            .valid = true,
        };
        self.nat_count += 1;
        pkt.src_ip = rule.nat_addr;
        if (rule.nat_port != 0) pkt.src_port = rule.nat_port;
    }

    fn apply_dnat(self: *Firewall, pkt: *PacketInfo, rule: *const Rule) void {
        if (self.nat_count >= MAX_NAT_ENTRIES) return;
        self.nat_table[self.nat_count] = .{
            .original_addr = pkt.dst_ip,
            .original_port = pkt.dst_port,
            .translated_addr = rule.nat_addr,
            .translated_port = if (rule.nat_port != 0) rule.nat_port else pkt.dst_port,
            .protocol = pkt.protocol,
            .nat_type = 2,
            .valid = true,
        };
        self.nat_count += 1;
        pkt.dst_ip = rule.nat_addr;
        if (rule.nat_port != 0) pkt.dst_port = rule.nat_port;
    }

    /// Clean expired connections
    pub fn conntrack_gc(self: *Firewall) u32 {
        var cleaned: u32 = 0;
        for (&self.conntrack) |*entry| {
            if (entry.valid) {
                if (self.current_tick - entry.last_seen > entry.timeout) {
                    entry.valid = false;
                    cleaned += 1;
                    if (self.conntrack_count > 0) self.conntrack_count -= 1;
                }
            }
        }
        return cleaned;
    }

    /// Get statistics
    pub fn get_stats(self: *const Firewall) FirewallStats {
        return .{
            .total_packets = self.total_packets,
            .total_accepted = self.total_accepted,
            .total_dropped = self.total_dropped,
            .total_rejected = self.total_rejected,
            .total_logged = self.total_logged,
            .active_connections = self.conntrack_count,
            .nat_entries = self.nat_count,
            .rule_count = self.rule_count,
            .chain_count = self.chain_count,
        };
    }
};

pub const FirewallStats = struct {
    total_packets: u64,
    total_accepted: u64,
    total_dropped: u64,
    total_rejected: u64,
    total_logged: u64,
    active_connections: u32,
    nat_entries: u16,
    rule_count: u16,
    chain_count: u16,
};

// ─────────────────── Global Instance ────────────────────────────────
var firewall: Firewall = .{};

pub fn initFirewall() void {
    firewall.init();
}

pub fn getFirewall() *Firewall {
    return &firewall;
}

// ─────────────────── Helper: Build match for common rules ───────────
pub fn matchTcpDstPort(port: u16) RuleMatch {
    var m = RuleMatch{};
    m.flags.protocol = true;
    m.flags.dst_port = true;
    m.protocol = PROTO_TCP;
    m.dst_port = PortRange.single(port);
    return m;
}

pub fn matchFromSubnet(ip: Ipv4Addr, prefix: u8) RuleMatch {
    var m = RuleMatch{};
    m.flags.src_ip = true;
    m.src_ip = ip;
    m.src_prefix = prefix;
    return m;
}

pub fn matchEstablished() RuleMatch {
    var m = RuleMatch{};
    m.flags.conn_state = true;
    m.conn_state_mask = (1 << @intFromEnum(ConnState.established)) | (1 << @intFromEnum(ConnState.related));
    return m;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_firewall_init() void {
    initFirewall();
}

export fn zxy_firewall_add_rule(chain_id: u16, src_ip: u32, src_prefix: u8, dst_ip: u32, dst_prefix: u8, protocol: u8, dst_port_min: u16, dst_port_max: u16, target: u8) i32 {
    var m = RuleMatch{};
    if (src_ip != 0) {
        m.flags.src_ip = true;
        m.src_ip = Ipv4Addr.from_u32(src_ip);
        m.src_prefix = src_prefix;
    }
    if (dst_ip != 0) {
        m.flags.dst_ip = true;
        m.dst_ip = Ipv4Addr.from_u32(dst_ip);
        m.dst_prefix = dst_prefix;
    }
    if (protocol != 0) {
        m.flags.protocol = true;
        m.protocol = protocol;
    }
    if (dst_port_min != 0 or dst_port_max != 0) {
        m.flags.dst_port = true;
        m.dst_port = .{ .min = dst_port_min, .max = dst_port_max };
    }

    const verdict: Verdict = @enumFromInt(target);
    if (firewall.add_rule(chain_id, m, verdict, 0)) |id| {
        return @intCast(id);
    }
    return -1;
}

export fn zxy_firewall_process(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8, length: u32, hook: u8) u8 {
    var pkt = PacketInfo{};
    pkt.src_ip = Ipv4Addr.from_u32(src_ip);
    pkt.dst_ip = Ipv4Addr.from_u32(dst_ip);
    pkt.src_port = src_port;
    pkt.dst_port = dst_port;
    pkt.protocol = protocol;
    pkt.length = length;

    const h: Hook = @enumFromInt(hook);
    const verdict = firewall.process_packet(&pkt, h);
    return @intFromEnum(verdict);
}

export fn zxy_firewall_stats_packets() u64 {
    return firewall.total_packets;
}

export fn zxy_firewall_stats_dropped() u64 {
    return firewall.total_dropped;
}

export fn zxy_firewall_conntrack_gc() u32 {
    return firewall.conntrack_gc();
}
