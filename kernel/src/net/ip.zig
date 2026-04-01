// =============================================================================
// Kernel Zxyphor - IPv4 Protocol (RFC 791)
// =============================================================================
// Internet Protocol version 4 implementation. Handles IP packet parsing,
// construction, routing, fragmentation/reassembly, and ICMP. Provides
// the core network-layer multiplexing between transport protocols.
//
// IPv4 Header (20-60 bytes):
//   Version(4) | IHL(4) | DSCP(6) | ECN(2) | Total Length(16)
//   Identification(16) | Flags(3) | Fragment Offset(13)
//   TTL(8) | Protocol(8) | Header Checksum(16)
//   Source IP(32) | Destination IP(32) | [Options]
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// IP Protocol Constants
// =============================================================================
pub const IP_VERSION: u8 = 4;
pub const IP_MIN_HEADER_LEN: usize = 20;
pub const IP_MAX_HEADER_LEN: usize = 60;
pub const IP_MAX_PACKET_LEN: usize = 65535;
pub const IP_DEFAULT_TTL: u8 = 64;

// Protocol numbers (IANA)
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_GRE: u8 = 47;
pub const PROTO_ESP: u8 = 50;
pub const PROTO_AH: u8 = 51;
pub const PROTO_ICMPV6: u8 = 58;

// IP flags
pub const IP_FLAG_RESERVED: u16 = 0x8000;
pub const IP_FLAG_DF: u16 = 0x4000; // Don't Fragment
pub const IP_FLAG_MF: u16 = 0x2000; // More Fragments
pub const IP_OFFSET_MASK: u16 = 0x1FFF;

// Special addresses
pub const ADDR_ANY: u32 = 0x00000000; // 0.0.0.0
pub const ADDR_BROADCAST: u32 = 0xFFFFFFFF; // 255.255.255.255
pub const ADDR_LOOPBACK: u32 = 0x7F000001; // 127.0.0.1

// =============================================================================
// IPv4 Header
// =============================================================================
pub const Ipv4Header = struct {
    version_ihl: u8 = (IP_VERSION << 4) | 5,
    dscp_ecn: u8 = 0,
    total_length: u16 = 0,
    identification: u16 = 0,
    flags_fragment: u16 = 0,
    ttl: u8 = IP_DEFAULT_TTL,
    protocol: u8 = 0,
    checksum: u16 = 0,
    src_addr: u32 = 0,
    dst_addr: u32 = 0,

    pub fn version(self: *const Ipv4Header) u8 {
        return self.version_ihl >> 4;
    }

    pub fn headerLen(self: *const Ipv4Header) usize {
        return @as(usize, self.version_ihl & 0x0F) * 4;
    }

    pub fn payloadLen(self: *const Ipv4Header) usize {
        const total = @as(usize, self.total_length);
        const hlen = self.headerLen();
        if (total < hlen) return 0;
        return total - hlen;
    }

    pub fn dontFragment(self: *const Ipv4Header) bool {
        return (self.flags_fragment & IP_FLAG_DF) != 0;
    }

    pub fn moreFragments(self: *const Ipv4Header) bool {
        return (self.flags_fragment & IP_FLAG_MF) != 0;
    }

    pub fn fragmentOffset(self: *const Ipv4Header) u16 {
        return (self.flags_fragment & IP_OFFSET_MASK) * 8;
    }

    pub fn parse(data: []const u8) ?Ipv4Header {
        if (data.len < IP_MIN_HEADER_LEN) return null;

        var hdr = Ipv4Header{};
        hdr.version_ihl = data[0];
        hdr.dscp_ecn = data[1];
        hdr.total_length = readU16BE(data, 2);
        hdr.identification = readU16BE(data, 4);
        hdr.flags_fragment = readU16BE(data, 6);
        hdr.ttl = data[8];
        hdr.protocol = data[9];
        hdr.checksum = readU16BE(data, 10);
        hdr.src_addr = readU32BE(data, 12);
        hdr.dst_addr = readU32BE(data, 16);

        // Validate
        if (hdr.version() != IP_VERSION) return null;
        if (hdr.headerLen() < IP_MIN_HEADER_LEN) return null;
        if (hdr.headerLen() > data.len) return null;
        if (hdr.total_length < @as(u16, @truncate(hdr.headerLen()))) return null;

        return hdr;
    }

    pub fn serialize(self: *const Ipv4Header, buf: []u8) bool {
        if (buf.len < IP_MIN_HEADER_LEN) return false;

        buf[0] = self.version_ihl;
        buf[1] = self.dscp_ecn;
        writeU16BE(buf, 2, self.total_length);
        writeU16BE(buf, 4, self.identification);
        writeU16BE(buf, 6, self.flags_fragment);
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        writeU16BE(buf, 10, 0); // Checksum zeroed for calculation
        writeU32BE(buf, 12, self.src_addr);
        writeU32BE(buf, 16, self.dst_addr);

        // Calculate and write checksum
        const cksum = ipChecksum(buf[0..IP_MIN_HEADER_LEN]);
        writeU16BE(buf, 10, cksum);

        return true;
    }
};

// =============================================================================
// ICMP (Internet Control Message Protocol) — RFC 792
// =============================================================================
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_SOURCE_QUENCH: u8 = 4;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_PARAM_PROBLEM: u8 = 12;
pub const ICMP_TIMESTAMP_REQUEST: u8 = 13;
pub const ICMP_TIMESTAMP_REPLY: u8 = 14;

pub const IcmpHeader = struct {
    icmp_type: u8 = 0,
    code: u8 = 0,
    checksum: u16 = 0,
    id: u16 = 0,
    sequence: u16 = 0,

    pub fn parse(data: []const u8) ?IcmpHeader {
        if (data.len < 8) return null;
        return IcmpHeader{
            .icmp_type = data[0],
            .code = data[1],
            .checksum = readU16BE(data, 2),
            .id = readU16BE(data, 4),
            .sequence = readU16BE(data, 6),
        };
    }

    pub fn serialize(self: *const IcmpHeader, buf: []u8) bool {
        if (buf.len < 8) return false;
        buf[0] = self.icmp_type;
        buf[1] = self.code;
        writeU16BE(buf, 2, 0); // Checksum zeroed
        writeU16BE(buf, 4, self.id);
        writeU16BE(buf, 6, self.sequence);
        return true;
    }
};

// =============================================================================
// Routing Table
// =============================================================================
pub const MAX_ROUTES: usize = 64;

pub const RouteEntry = struct {
    network: u32 = 0, // Destination network
    netmask: u32 = 0, // Network mask
    gateway: u32 = 0, // Next hop (0 = directly connected)
    iface_index: u8 = 0, // Output interface
    metric: u16 = 0, // Route metric (lower = better)
    flags: RouteFlags = .{},
    is_valid: bool = false,
};

pub const RouteFlags = packed struct {
    up: bool = false,
    gateway: bool = false,
    host: bool = false,
    reject: bool = false,
    dynamic: bool = false,
    modified: bool = false,
    _pad: u10 = 0,
};

var routing_table: [MAX_ROUTES]RouteEntry = undefined;

// =============================================================================
// IP Statistics
// =============================================================================
var ip_stats: IpStats = .{};

pub const IpStats = struct {
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    forwarded: u64 = 0,
    dropped: u64 = 0,
    checksum_errors: u64 = 0,
    ttl_exceeded: u64 = 0,
    fragments_received: u64 = 0,
    fragments_created: u64 = 0,
    reassembled: u64 = 0,
    icmp_sent: u64 = 0,
    icmp_received: u64 = 0,
};

var next_packet_id: u16 = 1;

// IP forwarding enable
var forwarding_enabled: bool = false;

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&routing_table) |*r| {
        r.* = RouteEntry{};
    }
    ip_stats = IpStats{};
    next_packet_id = 1;
    forwarding_enabled = false;

    // Add loopback route: 127.0.0.0/8 via lo
    addRoute(
        main.ethernet.ipv4(127, 0, 0, 0),
        main.ethernet.ipv4(255, 0, 0, 0),
        0, // Direct
        0, // Loopback interface
        0, // Metric
    );

    main.klog(.info, "ipv4: protocol initialized (TTL={d})", .{IP_DEFAULT_TTL});
}

// =============================================================================
// Receive IP Packet (called from ethernet layer)
// =============================================================================
pub fn receivePacket(iface: *main.ethernet.NetworkInterface, data: []const u8) void {
    const hdr = Ipv4Header.parse(data) orelse {
        ip_stats.rx_errors += 1;
        return;
    };

    // Verify checksum
    if (!verifyChecksum(data[0..hdr.headerLen()])) {
        ip_stats.checksum_errors += 1;
        return;
    }

    ip_stats.rx_packets += 1;
    ip_stats.rx_bytes += data.len;

    // Is it for us?
    const for_us = (hdr.dst_addr == iface.ipv4_addr) or
        (hdr.dst_addr == ADDR_BROADCAST) or
        (hdr.dst_addr == (iface.ipv4_addr | ~iface.ipv4_netmask)) or
        ((hdr.dst_addr >> 24) == 127);

    if (for_us) {
        deliverLocally(&hdr, data[hdr.headerLen()..]);
    } else if (forwarding_enabled) {
        forwardPacket(&hdr, data);
    } else {
        ip_stats.dropped += 1;
    }
}

// =============================================================================
// Deliver packet to upper-layer protocol
// =============================================================================
fn deliverLocally(hdr: *const Ipv4Header, payload: []const u8) void {
    switch (hdr.protocol) {
        PROTO_ICMP => {
            ip_stats.icmp_received += 1;
            handleIcmp(hdr, payload);
        },
        PROTO_TCP => {
            main.tcp.receiveSegment(hdr, payload);
        },
        PROTO_UDP => {
            main.udp.receivePacket(hdr, payload);
        },
        else => {
            // Unsupported protocol — send ICMP Protocol Unreachable
            ip_stats.dropped += 1;
        },
    }
}

// =============================================================================
// ICMP Handling
// =============================================================================
fn handleIcmp(ip_hdr: *const Ipv4Header, data: []const u8) void {
    const icmp = IcmpHeader.parse(data) orelse return;

    switch (icmp.icmp_type) {
        ICMP_ECHO_REQUEST => {
            // Respond with echo reply
            sendIcmpEchoReply(ip_hdr, &icmp, data);
        },
        ICMP_ECHO_REPLY => {
            // Process ping reply (TODO: notify waiting process)
        },
        else => {},
    }
}

fn sendIcmpEchoReply(orig_ip: *const Ipv4Header, orig_icmp: *const IcmpHeader, data: []const u8) void {
    _ = data;
    var reply_icmp = IcmpHeader{
        .icmp_type = ICMP_ECHO_REPLY,
        .code = 0,
        .id = orig_icmp.id,
        .sequence = orig_icmp.sequence,
    };

    var icmp_buf: [64]u8 = [_]u8{0} ** 64;
    if (!reply_icmp.serialize(&icmp_buf)) return;

    // Fill checksum for ICMP
    const cksum = ipChecksum(icmp_buf[0..8]);
    writeU16BE(&icmp_buf, 2, cksum);

    // Send IP packet back to sender
    _ = sendPacket(orig_ip.src_addr, PROTO_ICMP, icmp_buf[0..8]);
    ip_stats.icmp_sent += 1;
}

// =============================================================================
// Send IP Packet
// =============================================================================
pub fn sendPacket(dst_ip: u32, protocol: u8, payload: []const u8) bool {
    if (payload.len > IP_MAX_PACKET_LEN - IP_MIN_HEADER_LEN) return false;

    // Route lookup
    const route = lookupRoute(dst_ip) orelse return false;
    const iface = main.ethernet.getInterface(route.iface_index) orelse return false;

    // Determine next hop
    const next_hop = if (route.flags.gateway) route.gateway else dst_ip;

    // Build IP header
    var hdr = Ipv4Header{
        .total_length = @truncate(IP_MIN_HEADER_LEN + payload.len),
        .identification = next_packet_id,
        .flags_fragment = IP_FLAG_DF,
        .ttl = IP_DEFAULT_TTL,
        .protocol = protocol,
        .src_addr = iface.ipv4_addr,
        .dst_addr = dst_ip,
    };
    next_packet_id +%= 1;

    // Serialize
    var buf: [main.ethernet.MAX_PACKET_SIZE]u8 = undefined;
    if (!hdr.serialize(&buf)) return false;

    // Copy payload
    @memcpy(buf[IP_MIN_HEADER_LEN .. IP_MIN_HEADER_LEN + payload.len], payload);

    const total_len = IP_MIN_HEADER_LEN + payload.len;

    // Resolve MAC address via ARP
    const dst_mac = main.arp.resolve(next_hop, iface) orelse {
        // ARP request sent, packet will need to be retried
        return false;
    };

    // Send via Ethernet
    _ = main.ethernet.sendFrame(iface, dst_mac, main.ethernet.ETHERTYPE_IPV4, buf[0..total_len]);
    ip_stats.tx_packets += 1;
    ip_stats.tx_bytes += total_len;

    return true;
}

// =============================================================================
// IP Forwarding
// =============================================================================
fn forwardPacket(hdr: *const Ipv4Header, data: []const u8) void {
    // Check TTL
    if (hdr.ttl <= 1) {
        ip_stats.ttl_exceeded += 1;
        // TODO: send ICMP Time Exceeded
        return;
    }

    // Route lookup
    const route = lookupRoute(hdr.dst_addr) orelse {
        ip_stats.dropped += 1;
        return;
    };

    const iface = main.ethernet.getInterface(route.iface_index) orelse return;
    const next_hop = if (route.flags.gateway) route.gateway else hdr.dst_addr;

    // Decrement TTL and recompute checksum
    var frame: [main.ethernet.MAX_PACKET_SIZE]u8 = undefined;
    const copy_len = @min(data.len, frame.len);
    @memcpy(frame[0..copy_len], data[0..copy_len]);
    frame[8] -= 1; // Decrement TTL

    // Recompute checksum
    writeU16BE(&frame, 10, 0);
    const cksum = ipChecksum(frame[0..hdr.headerLen()]);
    writeU16BE(&frame, 10, cksum);

    // ARP resolve and send
    const dst_mac = main.arp.resolve(next_hop, iface) orelse return;
    _ = main.ethernet.sendFrame(iface, dst_mac, main.ethernet.ETHERTYPE_IPV4, frame[0..copy_len]);
    ip_stats.forwarded += 1;
}

// =============================================================================
// Routing Table Management
// =============================================================================
pub fn addRoute(network: u32, netmask: u32, gateway: u32, iface_index: u8, metric: u16) bool {
    for (&routing_table) |*route| {
        if (!route.is_valid) {
            route.* = RouteEntry{
                .network = network & netmask,
                .netmask = netmask,
                .gateway = gateway,
                .iface_index = iface_index,
                .metric = metric,
                .is_valid = true,
                .flags = .{
                    .up = true,
                    .gateway = gateway != 0,
                },
            };
            return true;
        }
    }
    return false;
}

pub fn removeRoute(network: u32, netmask: u32) void {
    for (&routing_table) |*route| {
        if (route.is_valid and route.network == network and route.netmask == netmask) {
            route.is_valid = false;
            return;
        }
    }
}

pub fn lookupRoute(dst_ip: u32) ?*const RouteEntry {
    var best: ?*const RouteEntry = null;
    var best_prefix_len: u32 = 0;

    for (&routing_table) |*route| {
        if (!route.is_valid or !route.flags.up) continue;
        if (route.flags.reject) continue;

        if ((dst_ip & route.netmask) == route.network) {
            const prefix_len = @popCount(route.netmask);
            if (best == null or prefix_len > best_prefix_len or
                (prefix_len == best_prefix_len and route.metric < best.?.metric))
            {
                best = route;
                best_prefix_len = prefix_len;
            }
        }
    }

    return best;
}

pub fn setForwarding(enabled: bool) void {
    forwarding_enabled = enabled;
    main.klog(.info, "ipv4: forwarding {s}", .{if (enabled) "enabled" else "disabled"});
}

pub fn getStats() IpStats {
    return ip_stats;
}

// =============================================================================
// IP Checksum (RFC 1071)
// =============================================================================
pub fn ipChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | data[i + 1];
    }

    // Handle odd byte
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

fn verifyChecksum(data: []const u8) bool {
    return ipChecksum(data) == 0;
}

// =============================================================================
// Network byte order helpers
// =============================================================================
fn readU16BE(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) << 8 | data[offset + 1];
}

fn readU32BE(data: []const u8, offset: usize) u32 {
    return @as(u32, data[offset]) << 24 | @as(u32, data[offset + 1]) << 16 |
        @as(u32, data[offset + 2]) << 8 | data[offset + 3];
}

fn writeU16BE(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @truncate(val >> 8);
    buf[offset + 1] = @truncate(val & 0xFF);
}

fn writeU32BE(buf: []u8, offset: usize, val: u32) void {
    buf[offset] = @truncate(val >> 24);
    buf[offset + 1] = @truncate((val >> 16) & 0xFF);
    buf[offset + 2] = @truncate((val >> 8) & 0xFF);
    buf[offset + 3] = @truncate(val & 0xFF);
}
