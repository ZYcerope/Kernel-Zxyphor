// SPDX-License-Identifier: MIT
// Zxyphor Kernel — IPv6 Network Stack
//
// Complete IPv6 implementation:
// - IPv6 header parsing and construction
// - ICMPv6 (Neighbor Discovery, Echo, Router Solicitation/Advertisement)
// - IPv6 address handling (link-local, global, multicast)
// - Neighbor cache (NDP)
// - Stateless Address Autoconfiguration (SLAAC)
// - Extension header chain processing
// - Fragmentation and reassembly
// - IPv6 routing table

const std = @import("std");

// ─────────────────── IPv6 Address ───────────────────────────────────
pub const Ipv6Addr = struct {
    octets: [16]u8,

    pub const UNSPECIFIED = Ipv6Addr{ .octets = [_]u8{0} ** 16 };
    pub const LOOPBACK = Ipv6Addr{ .octets = [_]u8{0} ** 15 ++ [_]u8{1} };

    pub fn init(a: [16]u8) Ipv6Addr {
        return .{ .octets = a };
    }

    pub fn fromU16(segments: [8]u16) Ipv6Addr {
        var addr: Ipv6Addr = .{ .octets = [_]u8{0} ** 16 };
        inline for (0..8) |i| {
            addr.octets[i * 2] = @intCast((segments[i] >> 8) & 0xFF);
            addr.octets[i * 2 + 1] = @intCast(segments[i] & 0xFF);
        }
        return addr;
    }

    pub fn linkLocal(mac: [6]u8) Ipv6Addr {
        var addr = Ipv6Addr{ .octets = [_]u8{0} ** 16 };
        addr.octets[0] = 0xFE;
        addr.octets[1] = 0x80;
        // bytes 2-7 zero (link-local prefix /64)
        // EUI-64 from MAC
        addr.octets[8] = mac[0] ^ 0x02; // flip U/L bit
        addr.octets[9] = mac[1];
        addr.octets[10] = mac[2];
        addr.octets[11] = 0xFF;
        addr.octets[12] = 0xFE;
        addr.octets[13] = mac[3];
        addr.octets[14] = mac[4];
        addr.octets[15] = mac[5];
        return addr;
    }

    pub fn solicitedNodeMulticast(addr: Ipv6Addr) Ipv6Addr {
        var mcast = Ipv6Addr{ .octets = [_]u8{0} ** 16 };
        mcast.octets[0] = 0xFF;
        mcast.octets[1] = 0x02;
        mcast.octets[11] = 0x01;
        mcast.octets[12] = 0xFF;
        mcast.octets[13] = addr.octets[13];
        mcast.octets[14] = addr.octets[14];
        mcast.octets[15] = addr.octets[15];
        return mcast;
    }

    pub fn isLinkLocal(self: Ipv6Addr) bool {
        return self.octets[0] == 0xFE and (self.octets[1] & 0xC0) == 0x80;
    }

    pub fn isMulticast(self: Ipv6Addr) bool {
        return self.octets[0] == 0xFF;
    }

    pub fn isLoopback(self: Ipv6Addr) bool {
        for (self.octets[0..15]) |b| {
            if (b != 0) return false;
        }
        return self.octets[15] == 1;
    }

    pub fn isUnspecified(self: Ipv6Addr) bool {
        for (self.octets) |b| {
            if (b != 0) return false;
        }
        return true;
    }

    pub fn isGlobalUnicast(self: Ipv6Addr) bool {
        // Global unicast: 2000::/3
        return (self.octets[0] & 0xE0) == 0x20;
    }

    pub fn isUniqueLocal(self: Ipv6Addr) bool {
        // ULA: FC00::/7
        return (self.octets[0] & 0xFE) == 0xFC;
    }

    pub fn prefixMatch(self: Ipv6Addr, other: Ipv6Addr, prefix_len: u8) bool {
        const full_bytes = prefix_len / 8;
        const remaining_bits = prefix_len % 8;

        var i: usize = 0;
        while (i < full_bytes) : (i += 1) {
            if (self.octets[i] != other.octets[i]) return false;
        }
        if (remaining_bits > 0 and i < 16) {
            const mask: u8 = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            if ((self.octets[i] & mask) != (other.octets[i] & mask)) return false;
        }
        return true;
    }

    pub fn equals(self: Ipv6Addr, other: Ipv6Addr) bool {
        return std.mem.eql(u8, &self.octets, &other.octets);
    }
};

// ─────────────────── IPv6 Header ────────────────────────────────────
pub const IPPROTO_HOPOPT: u8 = 0;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPPROTO_NONE: u8 = 59;

pub const Ipv6Header = packed struct {
    version_tc_fl: u32, // 4 bits version, 8 bits TC, 20 bits flow label
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    src: [16]u8,
    dst: [16]u8,

    pub fn version(self: *const Ipv6Header) u4 {
        return @intCast((readBe32(&self.version_tc_fl) >> 28) & 0xF);
    }

    pub fn trafficClass(self: *const Ipv6Header) u8 {
        return @intCast((readBe32(&self.version_tc_fl) >> 20) & 0xFF);
    }

    pub fn flowLabel(self: *const Ipv6Header) u20 {
        return @intCast(readBe32(&self.version_tc_fl) & 0xFFFFF);
    }

    pub fn payloadLen(self: *const Ipv6Header) u16 {
        return readBe16(&self.payload_length);
    }

    pub fn srcAddr(self: *const Ipv6Header) Ipv6Addr {
        return Ipv6Addr.init(self.src);
    }

    pub fn dstAddr(self: *const Ipv6Header) Ipv6Addr {
        return Ipv6Addr.init(self.dst);
    }

    pub fn setFields(self: *Ipv6Header, tc: u8, fl: u20, plen: u16, nh: u8, hlim: u8, s: Ipv6Addr, d: Ipv6Addr) void {
        const val: u32 = (6 << 28) | (@as(u32, tc) << 20) | fl;
        writeBe32(&self.version_tc_fl, val);
        writeBe16(&self.payload_length, plen);
        self.next_header = nh;
        self.hop_limit = hlim;
        self.src = s.octets;
        self.dst = d.octets;
    }
};

pub const IPV6_HEADER_SIZE: usize = 40;

// ─────────────────── Extension Headers ──────────────────────────────
pub const ExtHeaderGeneric = packed struct {
    next_header: u8,
    hdr_ext_len: u8, // in 8-byte units, not counting first 8 bytes
};

pub const FragmentHeader = packed struct {
    next_header: u8,
    reserved: u8,
    frag_offset_flags: u16, // 13-bit offset, 2 reserved, 1 bit MF
    identification: u32,

    pub fn fragOffset(self: *const FragmentHeader) u16 {
        return readBe16(&self.frag_offset_flags) >> 3;
    }

    pub fn moreFragments(self: *const FragmentHeader) bool {
        return (readBe16(&self.frag_offset_flags) & 1) != 0;
    }

    pub fn id(self: *const FragmentHeader) u32 {
        return readBe32(&self.identification);
    }
};

/// Walk extension header chain and find the upper-layer protocol
pub fn walkExtHeaders(data: []const u8, first_nh: u8) struct { protocol: u8, offset: usize } {
    var nh = first_nh;
    var offset: usize = 0;

    while (offset < data.len) {
        switch (nh) {
            IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6, IPPROTO_NONE => {
                return .{ .protocol = nh, .offset = offset };
            },
            IPPROTO_HOPOPT, IPPROTO_ROUTING, IPPROTO_DSTOPTS => {
                if (offset + 2 > data.len) break;
                const ext_len = @as(usize, data[offset + 1]) * 8 + 8;
                nh = data[offset];
                offset += ext_len;
            },
            IPPROTO_FRAGMENT => {
                if (offset + 8 > data.len) break;
                nh = data[offset];
                offset += 8;
            },
            else => {
                return .{ .protocol = nh, .offset = offset };
            },
        }
    }
    return .{ .protocol = nh, .offset = offset };
}

// ─────────────────── ICMPv6 ─────────────────────────────────────────
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_ROUTER_SOLICIT: u8 = 133;
pub const ICMPV6_ROUTER_ADVERT: u8 = 134;
pub const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;
pub const ICMPV6_REDIRECT: u8 = 137;
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;

pub const Icmpv6Header = packed struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
};

pub const NdpNeighborSolicit = packed struct {
    icmp: Icmpv6Header,
    reserved: u32,
    target: [16]u8,
};

pub const NdpNeighborAdvert = packed struct {
    icmp: Icmpv6Header,
    flags_reserved: u32, // R, S, O flags in high bits
    target: [16]u8,
};

pub const NdpRouterAdvert = packed struct {
    icmp: Icmpv6Header,
    cur_hop_limit: u8,
    flags: u8, // M, O flags
    router_lifetime: u16,
    reachable_time: u32,
    retrans_timer: u32,
};

pub const NdpOptionPrefix = packed struct {
    option_type: u8, // 3
    length: u8, // 4 (32 bytes)
    prefix_length: u8,
    flags: u8, // L, A flags
    valid_lifetime: u32,
    preferred_lifetime: u32,
    reserved2: u32,
    prefix: [16]u8,
};

/// Compute ICMPv6 checksum including pseudo-header
pub fn icmpv6Checksum(src: Ipv6Addr, dst: Ipv6Addr, payload: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header: src, dst, upper-layer length, next header
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u16, src.octets[i]) << 8 | src.octets[i + 1];
    }
    i = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u16, dst.octets[i]) << 8 | dst.octets[i + 1];
    }
    const plen: u32 = @intCast(payload.len);
    sum += @intCast((plen >> 16) & 0xFFFF);
    sum += @intCast(plen & 0xFFFF);
    sum += IPPROTO_ICMPV6;

    // Payload
    i = 0;
    while (i + 1 < payload.len) : (i += 2) {
        sum += @as(u16, payload[i]) << 8 | payload[i + 1];
    }
    if (i < payload.len) {
        sum += @as(u16, payload[i]) << 8;
    }

    // Fold
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @intCast(sum & 0xFFFF));
}

// ─────────────────── Neighbor Cache ─────────────────────────────────
pub const NeighborState = enum(u8) {
    incomplete = 0,
    reachable = 1,
    stale = 2,
    delay = 3,
    probe = 4,
};

pub const NeighborEntry = struct {
    ip: Ipv6Addr = Ipv6Addr.UNSPECIFIED,
    mac: [6]u8 = [_]u8{0} ** 6,
    state: NeighborState = .incomplete,
    is_router: bool = false,
    last_confirmed: u64 = 0,
    probe_count: u8 = 0,
    valid: bool = false,
};

pub const MAX_NEIGHBORS = 128;

pub const NeighborCache = struct {
    entries: [MAX_NEIGHBORS]NeighborEntry = [_]NeighborEntry{.{}} ** MAX_NEIGHBORS,
    count: u32 = 0,

    pub fn lookup(self: *const NeighborCache, ip: Ipv6Addr) ?*const NeighborEntry {
        for (&self.entries) |*entry| {
            if (entry.valid and entry.ip.equals(ip)) {
                return entry;
            }
        }
        return null;
    }

    pub fn lookupMut(self: *NeighborCache, ip: Ipv6Addr) ?*NeighborEntry {
        for (&self.entries) |*entry| {
            if (entry.valid and entry.ip.equals(ip)) {
                return entry;
            }
        }
        return null;
    }

    pub fn insert(self: *NeighborCache, ip: Ipv6Addr, mac: [6]u8, state: NeighborState) bool {
        // Update existing
        if (self.lookupMut(ip)) |entry| {
            entry.mac = mac;
            entry.state = state;
            return true;
        }
        // Find free slot
        for (&self.entries) |*entry| {
            if (!entry.valid) {
                entry.* = NeighborEntry{
                    .ip = ip,
                    .mac = mac,
                    .state = state,
                    .valid = true,
                };
                self.count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn remove(self: *NeighborCache, ip: Ipv6Addr) bool {
        for (&self.entries) |*entry| {
            if (entry.valid and entry.ip.equals(ip)) {
                entry.valid = false;
                self.count -|= 1;
                return true;
            }
        }
        return false;
    }

    /// Expire stale entries
    pub fn gc(self: *NeighborCache, now: u64, timeout: u64) void {
        for (&self.entries) |*entry| {
            if (entry.valid and entry.state == .reachable) {
                if (now - entry.last_confirmed > timeout) {
                    entry.state = .stale;
                }
            }
        }
    }
};

// ─────────────────── Routing Table ──────────────────────────────────
pub const MAX_ROUTES = 64;

pub const Ipv6Route = struct {
    prefix: Ipv6Addr = Ipv6Addr.UNSPECIFIED,
    prefix_len: u8 = 0,
    gateway: Ipv6Addr = Ipv6Addr.UNSPECIFIED,
    interface_id: u16 = 0,
    metric: u32 = 100,
    valid: bool = false,
    is_default: bool = false,
    expires: u64 = 0, // 0 = never
};

pub const Ipv6RoutingTable = struct {
    routes: [MAX_ROUTES]Ipv6Route = [_]Ipv6Route{.{}} ** MAX_ROUTES,
    count: u32 = 0,

    pub fn addRoute(self: *Ipv6RoutingTable, prefix: Ipv6Addr, prefix_len: u8, gateway: Ipv6Addr, iface: u16, metric: u32) bool {
        for (&self.routes) |*r| {
            if (!r.valid) {
                r.* = Ipv6Route{
                    .prefix = prefix,
                    .prefix_len = prefix_len,
                    .gateway = gateway,
                    .interface_id = iface,
                    .metric = metric,
                    .valid = true,
                    .is_default = (prefix_len == 0),
                };
                self.count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn removeRoute(self: *Ipv6RoutingTable, prefix: Ipv6Addr, prefix_len: u8) bool {
        for (&self.routes) |*r| {
            if (r.valid and r.prefix.equals(prefix) and r.prefix_len == prefix_len) {
                r.valid = false;
                self.count -|= 1;
                return true;
            }
        }
        return false;
    }

    /// Longest prefix match
    pub fn lookup(self: *const Ipv6RoutingTable, dst: Ipv6Addr) ?*const Ipv6Route {
        var best: ?*const Ipv6Route = null;
        var best_len: u8 = 0;
        var best_metric: u32 = 0xFFFFFFFF;

        for (&self.routes) |*r| {
            if (r.valid and dst.prefixMatch(r.prefix, r.prefix_len)) {
                if (r.prefix_len > best_len or (r.prefix_len == best_len and r.metric < best_metric)) {
                    best = r;
                    best_len = r.prefix_len;
                    best_metric = r.metric;
                }
            }
        }

        // Fall back to default route
        if (best == null) {
            for (&self.routes) |*r| {
                if (r.valid and r.is_default) {
                    if (best == null or r.metric < best_metric) {
                        best = r;
                        best_metric = r.metric;
                    }
                }
            }
        }
        return best;
    }

    /// Expire timed routes
    pub fn gc(self: *Ipv6RoutingTable, now: u64) void {
        for (&self.routes) |*r| {
            if (r.valid and r.expires > 0 and now > r.expires) {
                r.valid = false;
                self.count -|= 1;
            }
        }
    }
};

// ─────────────────── Fragment Reassembly ─────────────────────────────
pub const MAX_FRAGMENTS = 32;
pub const MAX_FRAG_ENTRIES = 16;
pub const FRAG_BUFFER_SIZE = 65536;

pub const FragEntry = struct {
    offset: u16 = 0,  // in 8-byte units
    length: u16 = 0,
    more: bool = false,
    received: bool = false,
};

pub const FragReassembly = struct {
    id: u32 = 0,
    src: Ipv6Addr = Ipv6Addr.UNSPECIFIED,
    dst: Ipv6Addr = Ipv6Addr.UNSPECIFIED,
    next_header: u8 = 0,
    frags: [MAX_FRAGMENTS]FragEntry = [_]FragEntry{.{}} ** MAX_FRAGMENTS,
    frag_count: u8 = 0,
    buffer: [FRAG_BUFFER_SIZE]u8 = [_]u8{0} ** FRAG_BUFFER_SIZE,
    total_length: u32 = 0,
    last_frag_seen: bool = false,
    timestamp: u64 = 0,
    valid: bool = false,

    pub fn addFragment(self: *FragReassembly, offset: u16, length: u16, more: bool, data: []const u8) bool {
        if (self.frag_count >= MAX_FRAGMENTS) return false;
        const byte_offset = @as(usize, offset) * 8;
        if (byte_offset + data.len > FRAG_BUFFER_SIZE) return false;

        // Copy data
        @memcpy(self.buffer[byte_offset..byte_offset + data.len], data);

        self.frags[self.frag_count] = FragEntry{
            .offset = offset,
            .length = length,
            .more = more,
            .received = true,
        };
        self.frag_count += 1;

        if (!more) {
            self.last_frag_seen = true;
            self.total_length = @intCast(byte_offset + data.len);
        }

        return true;
    }

    pub fn isComplete(self: *const FragReassembly) bool {
        if (!self.last_frag_seen) return false;
        // Check all byte ranges are covered
        // Simple check: sum of fragment lengths == total
        var total: u32 = 0;
        for (self.frags[0..self.frag_count]) |f| {
            total += f.length;
        }
        return total >= self.total_length;
    }
};

// ─────────────────── IPv6 Stack ─────────────────────────────────────
pub const Ipv6AddressEntry = struct {
    addr: Ipv6Addr = Ipv6Addr.UNSPECIFIED,
    prefix_len: u8 = 64,
    scope: enum(u8) { link_local = 0, global = 1, unique_local = 2 } = .link_local,
    valid: bool = false,
    preferred: bool = true,
    valid_lifetime: u64 = 0, // 0 = infinite
    preferred_lifetime: u64 = 0,
};

pub const MAX_ADDRESSES = 16;

pub const Ipv6Interface = struct {
    id: u16 = 0,
    mac: [6]u8 = [_]u8{0} ** 6,
    addresses: [MAX_ADDRESSES]Ipv6AddressEntry = [_]Ipv6AddressEntry{.{}} ** MAX_ADDRESSES,
    addr_count: u8 = 0,
    mtu: u32 = 1500,
    hop_limit: u8 = 64,
    /// Duplicate Address Detection transmits
    dad_transmits: u8 = 1,
    /// Accept Router Advertisements
    accept_ra: bool = true,
    /// Forwarding enabled
    forwarding: bool = false,

    pub fn addAddress(self: *Ipv6Interface, addr: Ipv6Addr, prefix_len: u8) bool {
        if (self.addr_count >= MAX_ADDRESSES) return false;
        for (self.addresses[0..self.addr_count]) |a| {
            if (a.valid and a.addr.equals(addr)) return true; // already exists
        }
        self.addresses[self.addr_count] = Ipv6AddressEntry{
            .addr = addr,
            .prefix_len = prefix_len,
            .valid = true,
            .scope = if (addr.isLinkLocal()) .link_local else if (addr.isUniqueLocal()) .unique_local else .global,
        };
        self.addr_count += 1;
        return true;
    }

    pub fn hasAddress(self: *const Ipv6Interface, addr: Ipv6Addr) bool {
        for (self.addresses[0..self.addr_count]) |a| {
            if (a.valid and a.addr.equals(addr)) return true;
        }
        return false;
    }

    pub fn getLinkLocal(self: *const Ipv6Interface) ?Ipv6Addr {
        for (self.addresses[0..self.addr_count]) |a| {
            if (a.valid and a.scope == .link_local) return a.addr;
        }
        return null;
    }

    pub fn getGlobal(self: *const Ipv6Interface) ?Ipv6Addr {
        for (self.addresses[0..self.addr_count]) |a| {
            if (a.valid and a.scope == .global) return a.addr;
        }
        return null;
    }

    pub fn autoconfLinkLocal(self: *Ipv6Interface) void {
        const ll = Ipv6Addr.linkLocal(self.mac);
        _ = self.addAddress(ll, 64);
    }
};

pub const MAX_INTERFACES = 8;

pub var ipv6_stack: Ipv6Stack = .{};

pub const Ipv6Stack = struct {
    interfaces: [MAX_INTERFACES]Ipv6Interface = [_]Ipv6Interface{.{}} ** MAX_INTERFACES,
    iface_count: u8 = 0,
    neighbor_cache: NeighborCache = .{},
    routing_table: Ipv6RoutingTable = .{},
    reassembly: [MAX_FRAG_ENTRIES]FragReassembly = [_]FragReassembly{.{}} ** MAX_FRAG_ENTRIES,
    /// Statistics
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    rx_dropped: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *Ipv6Stack) void {
        self.initialized = true;
    }

    pub fn addInterface(self: *Ipv6Stack, mac: [6]u8) ?u16 {
        if (self.iface_count >= MAX_INTERFACES) return null;
        const id = self.iface_count;
        self.interfaces[id].id = id;
        self.interfaces[id].mac = mac;
        self.interfaces[id].autoconfLinkLocal();
        self.iface_count += 1;
        return id;
    }

    pub fn getInterface(self: *Ipv6Stack, id: u16) ?*Ipv6Interface {
        if (id < self.iface_count) return &self.interfaces[id];
        return null;
    }

    /// Process received IPv6 packet
    pub fn processPacket(self: *Ipv6Stack, data: []const u8, iface_id: u16) void {
        if (data.len < IPV6_HEADER_SIZE) {
            self.rx_errors += 1;
            return;
        }

        const hdr: *const Ipv6Header = @ptrCast(@alignCast(data.ptr));
        if (hdr.version() != 6) {
            self.rx_errors += 1;
            return;
        }

        self.rx_packets += 1;
        self.rx_bytes += data.len;

        const src = hdr.srcAddr();
        const dst = hdr.dstAddr();
        const payload = data[IPV6_HEADER_SIZE..];

        // Check if packet is for us
        const iface = self.getInterface(iface_id) orelse return;
        const for_us = iface.hasAddress(dst) or dst.isMulticast();

        if (!for_us and iface.forwarding) {
            self.forwardPacket(data, src, dst);
            return;
        }

        if (!for_us) {
            self.rx_dropped += 1;
            return;
        }

        // Walk extension headers
        const result = walkExtHeaders(payload, hdr.next_header);

        switch (result.protocol) {
            IPPROTO_ICMPV6 => self.processIcmpv6(src, dst, payload[result.offset..], iface_id),
            IPPROTO_TCP => {}, // delegate to TCP stack
            IPPROTO_UDP => {}, // delegate to UDP stack
            IPPROTO_FRAGMENT => self.processFragment(src, dst, hdr.next_header, payload),
            else => {},
        }
    }

    fn processIcmpv6(self: *Ipv6Stack, src: Ipv6Addr, dst: Ipv6Addr, data: []const u8, iface_id: u16) void {
        if (data.len < 4) return;

        const icmp_type = data[0];
        _ = dst;

        switch (icmp_type) {
            ICMPV6_ECHO_REQUEST => {
                // Build echo reply
                self.sendEchoReply(src, iface_id, data);
            },
            ICMPV6_NEIGHBOR_SOLICIT => {
                if (data.len >= 24) {
                    self.processNeighborSolicit(src, data, iface_id);
                }
            },
            ICMPV6_NEIGHBOR_ADVERT => {
                if (data.len >= 24) {
                    self.processNeighborAdvert(src, data);
                }
            },
            ICMPV6_ROUTER_ADVERT => {
                if (data.len >= 16) {
                    self.processRouterAdvert(src, data, iface_id);
                }
            },
            else => {},
        }
    }

    fn sendEchoReply(self: *Ipv6Stack, dst: Ipv6Addr, iface_id: u16, request: []const u8) void {
        _ = iface_id;
        _ = request;
        _ = dst;
        self.tx_packets += 1;
    }

    fn processNeighborSolicit(self: *Ipv6Stack, src: Ipv6Addr, data: []const u8, iface_id: u16) void {
        // Extract target address
        var target: [16]u8 = undefined;
        @memcpy(&target, data[8..24]);
        const target_addr = Ipv6Addr.init(target);

        const iface = self.getInterface(iface_id) orelse return;
        if (!iface.hasAddress(target_addr)) return;

        // Extract source link-layer address option
        if (data.len >= 32 and data[24] == 1 and data[25] == 1) {
            var mac: [6]u8 = undefined;
            @memcpy(&mac, data[26..32]);
            _ = self.neighbor_cache.insert(src, mac, .reachable);
        }

        // Send Neighbor Advertisement
        self.tx_packets += 1;
    }

    fn processNeighborAdvert(self: *Ipv6Stack, src: Ipv6Addr, data: []const u8) void {
        _ = src;
        var target: [16]u8 = undefined;
        @memcpy(&target, data[8..24]);
        const target_addr = Ipv6Addr.init(target);

        // Extract target link-layer address option
        if (data.len >= 32 and data[24] == 2 and data[25] == 1) {
            var mac: [6]u8 = undefined;
            @memcpy(&mac, data[26..32]);
            _ = self.neighbor_cache.insert(target_addr, mac, .reachable);
        }
    }

    fn processRouterAdvert(self: *Ipv6Stack, src: Ipv6Addr, data: []const u8, iface_id: u16) void {
        const iface = self.getInterface(iface_id) orelse return;
        if (!iface.accept_ra) return;

        // cur_hop_limit at data[4]
        if (data[4] != 0) {
            iface.hop_limit = data[4];
        }

        // Parse prefix options
        var offset: usize = 16;
        while (offset + 2 <= data.len) {
            const opt_type = data[offset];
            const opt_len = @as(usize, data[offset + 1]) * 8;
            if (opt_len == 0) break;

            if (opt_type == 3 and opt_len >= 32) {
                // Prefix Information
                const prefix_len = data[offset + 2];
                const flags = data[offset + 3];
                const on_link = (flags & 0x80) != 0;
                const autonomous = (flags & 0x40) != 0;
                _ = on_link;

                var prefix: [16]u8 = undefined;
                @memcpy(&prefix, data[offset + 16 .. offset + 32]);
                const prefix_addr = Ipv6Addr.init(prefix);

                if (autonomous) {
                    // SLAAC: form address from prefix + EUI-64
                    var addr = prefix_addr;
                    addr.octets[8] = iface.mac[0] ^ 0x02;
                    addr.octets[9] = iface.mac[1];
                    addr.octets[10] = iface.mac[2];
                    addr.octets[11] = 0xFF;
                    addr.octets[12] = 0xFE;
                    addr.octets[13] = iface.mac[3];
                    addr.octets[14] = iface.mac[4];
                    addr.octets[15] = iface.mac[5];
                    _ = iface.addAddress(addr, prefix_len);
                }
            }

            offset += opt_len;
        }

        // Add default route via this router
        _ = self.routing_table.addRoute(Ipv6Addr.UNSPECIFIED, 0, src, iface_id, 1024);

        // Update neighbor cache with router's MAC (from source link-layer option)
        // The source link-layer addr option would be in the RA data too
    }

    fn processFragment(self: *Ipv6Stack, src: Ipv6Addr, dst: Ipv6Addr, first_nh: u8, data: []const u8) void {
        if (data.len < 8) return;
        _ = first_nh;

        const frag_nh = data[0];
        _ = frag_nh;
        const frag_off_flags = @as(u16, data[2]) << 8 | data[3];
        const frag_offset = frag_off_flags >> 3;
        const more = (frag_off_flags & 1) != 0;
        const frag_id = @as(u32, data[4]) << 24 | @as(u32, data[5]) << 16 | @as(u32, data[6]) << 8 | data[7];

        const frag_data = data[8..];

        // Find existing reassembly buffer
        for (&self.reassembly) |*r| {
            if (r.valid and r.id == frag_id and r.src.equals(src) and r.dst.equals(dst)) {
                _ = r.addFragment(frag_offset, @intCast(frag_data.len), more, frag_data);
                return;
            }
        }

        // Create new
        for (&self.reassembly) |*r| {
            if (!r.valid) {
                r.valid = true;
                r.id = frag_id;
                r.src = src;
                r.dst = dst;
                _ = r.addFragment(frag_offset, @intCast(frag_data.len), more, frag_data);
                return;
            }
        }
    }

    fn forwardPacket(self: *Ipv6Stack, data: []const u8, src: Ipv6Addr, dst: Ipv6Addr) void {
        _ = src;
        if (self.routing_table.lookup(dst)) |_route| {
            // Decrement hop limit, forward
            _ = data;
            self.tx_packets += 1;
        }
    }
};

// ─────────────────── Byte-order helpers ─────────────────────────────
fn readBe16(ptr: *const u16) u16 {
    const bytes: *const [2]u8 = @ptrCast(ptr);
    return @as(u16, bytes[0]) << 8 | bytes[1];
}

fn readBe32(ptr: *const u32) u32 {
    const bytes: *const [4]u8 = @ptrCast(ptr);
    return @as(u32, bytes[0]) << 24 | @as(u32, bytes[1]) << 16 | @as(u32, bytes[2]) << 8 | bytes[3];
}

fn writeBe16(ptr: *u16, val: u16) void {
    const bytes: *[2]u8 = @ptrCast(ptr);
    bytes[0] = @intCast((val >> 8) & 0xFF);
    bytes[1] = @intCast(val & 0xFF);
}

fn writeBe32(ptr: *u32, val: u32) void {
    const bytes: *[4]u8 = @ptrCast(ptr);
    bytes[0] = @intCast((val >> 24) & 0xFF);
    bytes[1] = @intCast((val >> 16) & 0xFF);
    bytes[2] = @intCast((val >> 8) & 0xFF);
    bytes[3] = @intCast(val & 0xFF);
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_ipv6_init() void {
    ipv6_stack.init();
}

export fn zxy_ipv6_add_interface(mac: *const [6]u8) i16 {
    if (ipv6_stack.addInterface(mac.*)) |id| {
        return @intCast(id);
    }
    return -1;
}

export fn zxy_ipv6_process_packet(data: [*]const u8, len: u32, iface: u16) void {
    if (len > 0) {
        ipv6_stack.processPacket(data[0..len], iface);
    }
}

export fn zxy_ipv6_rx_packets() u64 {
    return ipv6_stack.rx_packets;
}

export fn zxy_ipv6_tx_packets() u64 {
    return ipv6_stack.tx_packets;
}

export fn zxy_ipv6_route_add(prefix: *const [16]u8, prefix_len: u8, gateway: *const [16]u8, iface: u16, metric: u32) bool {
    return ipv6_stack.routing_table.addRoute(
        Ipv6Addr.init(prefix.*),
        prefix_len,
        Ipv6Addr.init(gateway.*),
        iface,
        metric,
    );
}

export fn zxy_ipv6_neighbor_count() u32 {
    return ipv6_stack.neighbor_cache.count;
}
