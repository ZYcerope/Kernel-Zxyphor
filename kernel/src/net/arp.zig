// =============================================================================
// Kernel Zxyphor - ARP (Address Resolution Protocol)
// =============================================================================
// RFC 826 implementation. Maps IPv4 addresses to MAC (Ethernet) addresses.
// Maintains an ARP cache with aging/expiry, handles ARP request/reply
// packets, and supports gratuitous ARP for IP conflict detection.
//
// ARP packet format (for Ethernet/IPv4):
//   Hardware Type (2) | Protocol Type (2) | HLEN (1) | PLEN (1) |
//   Operation (2) | Sender MAC (6) | Sender IP (4) |
//   Target MAC (6) | Target IP (4)
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const ARP_HEADER_LEN: usize = 28; // For Ethernet/IPv4
pub const ARP_CACHE_SIZE: usize = 512;
pub const ARP_CACHE_TIMEOUT: u64 = 300; // 5 minutes (seconds)
pub const ARP_REQUEST_TIMEOUT: u64 = 3; // 3 seconds
pub const ARP_MAX_RETRIES: u32 = 3;

// Hardware types
pub const HW_ETHERNET: u16 = 1;

// Operations
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const RARP_REQUEST: u16 = 3;
pub const RARP_REPLY: u16 = 4;

// Protocol type
pub const PROTO_IPV4: u16 = 0x0800;

// =============================================================================
// ARP Packet
// =============================================================================
pub const ArpPacket = struct {
    hw_type: u16 = HW_ETHERNET,
    proto_type: u16 = PROTO_IPV4,
    hw_len: u8 = 6,
    proto_len: u8 = 4,
    operation: u16 = 0,
    sender_mac: main.ethernet.MacAddress = .{},
    sender_ip: u32 = 0,
    target_mac: main.ethernet.MacAddress = .{},
    target_ip: u32 = 0,

    pub fn parse(data: []const u8) ?ArpPacket {
        if (data.len < ARP_HEADER_LEN) return null;

        var pkt = ArpPacket{};
        pkt.hw_type = readU16BE(data, 0);
        pkt.proto_type = readU16BE(data, 2);
        pkt.hw_len = data[4];
        pkt.proto_len = data[5];
        pkt.operation = readU16BE(data, 6);

        // Validate: we only handle Ethernet/IPv4
        if (pkt.hw_type != HW_ETHERNET or pkt.proto_type != PROTO_IPV4) return null;
        if (pkt.hw_len != 6 or pkt.proto_len != 4) return null;

        @memcpy(&pkt.sender_mac.octets, data[8..14]);
        pkt.sender_ip = readU32BE(data, 14);
        @memcpy(&pkt.target_mac.octets, data[18..24]);
        pkt.target_ip = readU32BE(data, 24);

        return pkt;
    }

    pub fn serialize(self: *const ArpPacket, buf: []u8) bool {
        if (buf.len < ARP_HEADER_LEN) return false;

        writeU16BE(buf, 0, self.hw_type);
        writeU16BE(buf, 2, self.proto_type);
        buf[4] = self.hw_len;
        buf[5] = self.proto_len;
        writeU16BE(buf, 6, self.operation);
        @memcpy(buf[8..14], &self.sender_mac.octets);
        writeU32BE(buf, 14, self.sender_ip);
        @memcpy(buf[18..24], &self.target_mac.octets);
        writeU32BE(buf, 24, self.target_ip);

        return true;
    }
};

// =============================================================================
// ARP Cache Entry
// =============================================================================
pub const ArpEntryState = enum(u8) {
    free,
    incomplete, // Request sent, waiting for reply
    reachable, // Valid entry
    stale, // Timed out, needs re-validation
    permanent, // Static entry, never expires
};

pub const ArpEntry = struct {
    ip_addr: u32 = 0,
    mac_addr: main.ethernet.MacAddress = .{},
    state: ArpEntryState = .free,
    timestamp: u64 = 0,
    retries: u32 = 0,
    iface_index: u8 = 0,

    pub fn isExpired(self: *const ArpEntry, now: u64) bool {
        if (self.state == .permanent) return false;
        if (self.state == .free) return true;
        return (now - self.timestamp) >= ARP_CACHE_TIMEOUT;
    }
};

// =============================================================================
// ARP Cache
// =============================================================================
var cache: [ARP_CACHE_SIZE]ArpEntry = undefined;
var stats: ArpStats = .{};

pub const ArpStats = struct {
    requests_sent: u64 = 0,
    requests_received: u64 = 0,
    replies_sent: u64 = 0,
    replies_received: u64 = 0,
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
};

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&cache) |*entry| {
        entry.* = ArpEntry{};
    }
    stats = ArpStats{};
    main.klog(.info, "arp: cache initialized ({d} entries)", .{ARP_CACHE_SIZE});
}

// =============================================================================
// ARP Lookup — resolve IPv4 to MAC address
// =============================================================================
pub fn resolve(ip: u32, iface: *main.ethernet.NetworkInterface) ?main.ethernet.MacAddress {
    // Check for broadcast
    if (ip == 0xFFFFFFFF) return main.ethernet.MacAddress.BROADCAST;

    // Loopback
    if ((ip >> 24) == 127) return main.ethernet.MacAddress.ZERO;

    // Look in cache
    for (&cache) |*entry| {
        if (entry.state == .reachable or entry.state == .permanent) {
            if (entry.ip_addr == ip) {
                stats.cache_hits += 1;
                return entry.mac_addr;
            }
        }
    }

    stats.cache_misses += 1;

    // Not found — send ARP request
    sendRequest(iface, ip);
    return null;
}

// =============================================================================
// Receive ARP packet (called from ethernet layer)
// =============================================================================
pub fn receivePacket(iface: *main.ethernet.NetworkInterface, data: []const u8) void {
    const pkt = ArpPacket.parse(data) orelse return;

    switch (pkt.operation) {
        ARP_REQUEST => {
            stats.requests_received += 1;
            handleRequest(iface, &pkt);
        },
        ARP_REPLY => {
            stats.replies_received += 1;
            handleReply(&pkt);
        },
        else => {},
    }
}

// =============================================================================
// Handle incoming ARP request
// =============================================================================
fn handleRequest(iface: *main.ethernet.NetworkInterface, pkt: *const ArpPacket) void {
    // Update/create cache entry for sender (merge flag per RFC 826)
    updateCache(pkt.sender_ip, pkt.sender_mac, .reachable);

    // Is the request for our IP?
    if (pkt.target_ip == iface.ipv4_addr and iface.ipv4_addr != 0) {
        sendReply(iface, pkt);
    }
}

// =============================================================================
// Handle incoming ARP reply
// =============================================================================
fn handleReply(pkt: *const ArpPacket) void {
    updateCache(pkt.sender_ip, pkt.sender_mac, .reachable);
}

// =============================================================================
// Send ARP request
// =============================================================================
fn sendRequest(iface: *main.ethernet.NetworkInterface, target_ip: u32) void {
    var pkt = ArpPacket{
        .operation = ARP_REQUEST,
        .sender_mac = iface.mac,
        .sender_ip = iface.ipv4_addr,
        .target_mac = main.ethernet.MacAddress.ZERO,
        .target_ip = target_ip,
    };

    var buf: [ARP_HEADER_LEN]u8 = undefined;
    if (pkt.serialize(&buf)) {
        _ = main.ethernet.sendFrame(iface, main.ethernet.MacAddress.BROADCAST, main.ethernet.ETHERTYPE_ARP, &buf);
        stats.requests_sent += 1;
    }

    // Add incomplete entry
    addIncompleteEntry(target_ip);
}

// =============================================================================
// Send ARP reply
// =============================================================================
fn sendReply(iface: *main.ethernet.NetworkInterface, request: *const ArpPacket) void {
    var reply = ArpPacket{
        .operation = ARP_REPLY,
        .sender_mac = iface.mac,
        .sender_ip = iface.ipv4_addr,
        .target_mac = request.sender_mac,
        .target_ip = request.sender_ip,
    };

    var buf: [ARP_HEADER_LEN]u8 = undefined;
    if (reply.serialize(&buf)) {
        _ = main.ethernet.sendFrame(iface, request.sender_mac, main.ethernet.ETHERTYPE_ARP, &buf);
        stats.replies_sent += 1;
    }
}

// =============================================================================
// Send Gratuitous ARP (announce our presence)
// =============================================================================
pub fn sendGratuitous(iface: *main.ethernet.NetworkInterface) void {
    var pkt = ArpPacket{
        .operation = ARP_REQUEST,
        .sender_mac = iface.mac,
        .sender_ip = iface.ipv4_addr,
        .target_mac = main.ethernet.MacAddress.ZERO,
        .target_ip = iface.ipv4_addr, // Target = our own IP
    };

    var buf: [ARP_HEADER_LEN]u8 = undefined;
    if (pkt.serialize(&buf)) {
        _ = main.ethernet.sendFrame(iface, main.ethernet.MacAddress.BROADCAST, main.ethernet.ETHERTYPE_ARP, &buf);
    }
}

// =============================================================================
// Cache Management
// =============================================================================
fn updateCache(ip: u32, mac: main.ethernet.MacAddress, state: ArpEntryState) void {
    const now = main.timer.getUnixTimestamp();

    // Try to update existing entry first
    for (&cache) |*entry| {
        if (entry.ip_addr == ip and entry.state != .free) {
            entry.mac_addr = mac;
            entry.state = state;
            entry.timestamp = now;
            return;
        }
    }

    // Find free or oldest entry
    var oldest_idx: usize = 0;
    var oldest_time: u64 = @as(u64, 0) -% 1;

    for (&cache, 0..) |*entry, i| {
        if (entry.state == .free) {
            oldest_idx = i;
            break;
        }
        if (entry.timestamp < oldest_time) {
            oldest_time = entry.timestamp;
            oldest_idx = i;
        }
    }

    cache[oldest_idx] = ArpEntry{
        .ip_addr = ip,
        .mac_addr = mac,
        .state = state,
        .timestamp = now,
    };
}

fn addIncompleteEntry(ip: u32) void {
    // Check if already pending
    for (&cache) |*entry| {
        if (entry.ip_addr == ip and entry.state == .incomplete) return;
    }
    updateCache(ip, main.ethernet.MacAddress.ZERO, .incomplete);
}

/// Add a static ARP entry
pub fn addStatic(ip: u32, mac: main.ethernet.MacAddress) void {
    updateCache(ip, mac, .permanent);
}

/// Remove an ARP entry
pub fn removeEntry(ip: u32) void {
    for (&cache) |*entry| {
        if (entry.ip_addr == ip and entry.state != .free) {
            entry.state = .free;
            return;
        }
    }
}

/// Flush all non-permanent entries
pub fn flushCache() void {
    for (&cache) |*entry| {
        if (entry.state != .permanent) {
            entry.state = .free;
        }
    }
}

/// Age cache entries
pub fn ageCache() void {
    const now = main.timer.getUnixTimestamp();
    for (&cache) |*entry| {
        if (entry.state == .reachable and entry.isExpired(now)) {
            entry.state = .stale;
        }
    }
}

pub fn getStats() ArpStats {
    return stats;
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
