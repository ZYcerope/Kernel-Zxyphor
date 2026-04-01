// =============================================================================
// Kernel Zxyphor - UDP (User Datagram Protocol) — RFC 768
// =============================================================================
// Connectionless, unreliable datagram delivery protocol. Provides port-based
// multiplexing and optional checksum verification over IP.
//
// UDP Header (8 bytes):
//   Source Port(16) | Destination Port(16)
//   Length(16) | Checksum(16)
//
// Used by: DNS, DHCP, NTP, TFTP, syslog, and many real-time applications.
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const UDP_HEADER_LEN: usize = 8;
pub const UDP_MAX_PAYLOAD: usize = 65527; // 65535 - 8
pub const MAX_UDP_SOCKETS: usize = 256;
pub const UDP_RX_BUFFER_SIZE: usize = 65536;
pub const MAX_DGRAM_QUEUE: usize = 64;

// =============================================================================
// UDP Header
// =============================================================================
pub const UdpHeader = struct {
    src_port: u16 = 0,
    dst_port: u16 = 0,
    length: u16 = 0,
    checksum: u16 = 0,

    pub fn payloadLen(self: *const UdpHeader) usize {
        if (self.length < UDP_HEADER_LEN) return 0;
        return @as(usize, self.length) - UDP_HEADER_LEN;
    }

    pub fn parse(data: []const u8) ?UdpHeader {
        if (data.len < UDP_HEADER_LEN) return null;
        return UdpHeader{
            .src_port = readU16BE(data, 0),
            .dst_port = readU16BE(data, 2),
            .length = readU16BE(data, 4),
            .checksum = readU16BE(data, 6),
        };
    }

    pub fn serialize(self: *const UdpHeader, buf: []u8) bool {
        if (buf.len < UDP_HEADER_LEN) return false;
        writeU16BE(buf, 0, self.src_port);
        writeU16BE(buf, 2, self.dst_port);
        writeU16BE(buf, 4, self.length);
        writeU16BE(buf, 6, 0); // Checksum zeroed for calculation
        return true;
    }
};

// =============================================================================
// Received Datagram (queued for reading)
// =============================================================================
pub const Datagram = struct {
    src_addr: u32 = 0,
    src_port: u16 = 0,
    data: [1500]u8 = [_]u8{0} ** 1500,
    len: u16 = 0,
    is_valid: bool = false,
};

// =============================================================================
// UDP Socket
// =============================================================================
pub const UdpSocket = struct {
    // Binding
    local_addr: u32 = 0,
    local_port: u16 = 0,

    // Default destination (for connected UDP)
    remote_addr: u32 = 0,
    remote_port: u16 = 0,
    is_connected: bool = false,

    // Receive queue
    rx_queue: [MAX_DGRAM_QUEUE]Datagram = undefined,
    rx_head: u16 = 0,
    rx_tail: u16 = 0,
    rx_count: u16 = 0,

    // Options
    broadcast: bool = false,

    // State
    is_valid: bool = false,

    pub fn hasData(self: *const UdpSocket) bool {
        return self.rx_count > 0;
    }

    fn enqueue(self: *UdpSocket, dgram: *const Datagram) bool {
        if (self.rx_count >= MAX_DGRAM_QUEUE) return false;

        self.rx_queue[self.rx_tail] = dgram.*;
        self.rx_tail = (self.rx_tail + 1) % MAX_DGRAM_QUEUE;
        self.rx_count += 1;
        return true;
    }

    fn dequeue(self: *UdpSocket) ?Datagram {
        if (self.rx_count == 0) return null;

        const dgram = self.rx_queue[self.rx_head];
        self.rx_head = (self.rx_head + 1) % MAX_DGRAM_QUEUE;
        self.rx_count -= 1;
        return dgram;
    }
};

// =============================================================================
// Socket Table
// =============================================================================
var sockets: [MAX_UDP_SOCKETS]UdpSocket = undefined;
var next_ephemeral_port: u16 = 49152;

var udp_stats: UdpStats = .{};

pub const UdpStats = struct {
    rx_datagrams: u64 = 0,
    tx_datagrams: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    no_port: u64 = 0,
    checksum_errors: u64 = 0,
    queue_overflow: u64 = 0,
};

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&sockets) |*s| {
        s.* = UdpSocket{};
        for (&s.rx_queue) |*d| {
            d.* = Datagram{};
        }
    }
    next_ephemeral_port = 49152;
    udp_stats = UdpStats{};
    main.klog(.info, "udp: protocol initialized ({d} max sockets)", .{MAX_UDP_SOCKETS});
}

// =============================================================================
// Socket-level API
// =============================================================================

/// Create a new UDP socket
pub fn create() ?u16 {
    for (&sockets, 0..) |*s, i| {
        if (!s.is_valid) {
            s.* = UdpSocket{};
            for (&s.rx_queue) |*d| {
                d.* = Datagram{};
            }
            s.is_valid = true;
            return @truncate(i);
        }
    }
    return null;
}

/// Bind to a local address and port
pub fn bind(sock_id: u16, addr: u32, port: u16) bool {
    if (sock_id >= MAX_UDP_SOCKETS) return false;
    var s = &sockets[sock_id];
    if (!s.is_valid) return false;

    // Check port availability
    for (sockets) |existing| {
        if (existing.is_valid and existing.local_port == port and
            (existing.local_addr == addr or existing.local_addr == 0 or addr == 0))
        {
            return false;
        }
    }

    s.local_addr = addr;
    s.local_port = port;
    return true;
}

/// Connect (set default destination for send/recv)
pub fn connectSocket(sock_id: u16, remote_addr: u32, remote_port: u16) bool {
    if (sock_id >= MAX_UDP_SOCKETS) return false;
    var s = &sockets[sock_id];
    if (!s.is_valid) return false;

    s.remote_addr = remote_addr;
    s.remote_port = remote_port;
    s.is_connected = true;

    // Auto-bind if needed
    if (s.local_port == 0) {
        s.local_port = allocateEphemeralPort();
    }

    return true;
}

/// Send a datagram to a specific address
pub fn sendto(sock_id: u16, data: []const u8, dst_addr: u32, dst_port: u16) i32 {
    if (sock_id >= MAX_UDP_SOCKETS) return -1;
    var s = &sockets[sock_id];
    if (!s.is_valid) return -1;
    if (data.len > UDP_MAX_PAYLOAD) return -1;

    // Check broadcast permission
    if (dst_addr == 0xFFFFFFFF and !s.broadcast) return -1;

    // Auto-bind if needed
    if (s.local_port == 0) {
        s.local_port = allocateEphemeralPort();
    }

    // Determine source address
    var src_addr = s.local_addr;
    if (src_addr == 0) {
        if (main.ethernet.getInterface(1)) |iface| {
            src_addr = iface.ipv4_addr;
        }
    }

    // Build UDP header
    var buf: [1500]u8 = undefined;
    const udp_len: u16 = @truncate(UDP_HEADER_LEN + data.len);
    const hdr = UdpHeader{
        .src_port = s.local_port,
        .dst_port = dst_port,
        .length = udp_len,
    };

    if (!hdr.serialize(&buf)) return -1;

    // Copy payload
    @memcpy(buf[UDP_HEADER_LEN .. UDP_HEADER_LEN + data.len], data);

    // Calculate UDP checksum with pseudo-header
    const cksum = udpChecksum(src_addr, dst_addr, buf[0..udp_len]);
    writeU16BE(&buf, 6, if (cksum == 0) 0xFFFF else cksum);

    // Send via IP
    if (main.ip.sendPacket(dst_addr, main.ip.PROTO_UDP, buf[0..udp_len])) {
        udp_stats.tx_datagrams += 1;
        udp_stats.tx_bytes += data.len;
        return @intCast(data.len);
    }
    return -1;
}

/// Send using connected destination
pub fn send(sock_id: u16, data: []const u8) i32 {
    if (sock_id >= MAX_UDP_SOCKETS) return -1;
    const s = &sockets[sock_id];
    if (!s.is_valid or !s.is_connected) return -1;
    return sendto(sock_id, data, s.remote_addr, s.remote_port);
}

/// Receive a datagram (returns source address info)
pub fn recvfrom(sock_id: u16, buf: []u8, src_addr: *u32, src_port: *u16) i32 {
    if (sock_id >= MAX_UDP_SOCKETS) return -1;
    var s = &sockets[sock_id];
    if (!s.is_valid) return -1;

    const dgram = s.dequeue() orelse return -1; // Would block

    const copy_len = @min(buf.len, @as(usize, dgram.len));
    @memcpy(buf[0..copy_len], dgram.data[0..copy_len]);
    src_addr.* = dgram.src_addr;
    src_port.* = dgram.src_port;

    return @intCast(copy_len);
}

/// Receive using connected filter
pub fn recv(sock_id: u16, buf: []u8) i32 {
    var src_addr: u32 = 0;
    var src_port: u16 = 0;
    return recvfrom(sock_id, buf, &src_addr, &src_port);
}

/// Close a UDP socket
pub fn closeSocket(sock_id: u16) void {
    if (sock_id >= MAX_UDP_SOCKETS) return;
    sockets[sock_id].is_valid = false;
}

/// Set broadcast option
pub fn setBroadcast(sock_id: u16, enabled: bool) bool {
    if (sock_id >= MAX_UDP_SOCKETS) return false;
    var s = &sockets[sock_id];
    if (!s.is_valid) return false;
    s.broadcast = enabled;
    return true;
}

// =============================================================================
// Receive UDP packet (called from IP layer)
// =============================================================================
pub fn receivePacket(ip_hdr: *const main.ip.Ipv4Header, data: []const u8) void {
    const hdr = UdpHeader.parse(data) orelse {
        udp_stats.rx_errors += 1;
        return;
    };

    // Validate length
    if (hdr.length < UDP_HEADER_LEN or hdr.length > data.len) {
        udp_stats.rx_errors += 1;
        return;
    }

    // Verify checksum (if non-zero)
    if (hdr.checksum != 0) {
        const cksum = udpChecksum(ip_hdr.src_addr, ip_hdr.dst_addr, data[0..hdr.length]);
        if (cksum != 0) {
            udp_stats.checksum_errors += 1;
            return;
        }
    }

    udp_stats.rx_datagrams += 1;

    const payload = data[UDP_HEADER_LEN..hdr.length];
    udp_stats.rx_bytes += payload.len;

    // Find matching socket
    var found = false;
    for (&sockets) |*s| {
        if (!s.is_valid) continue;
        if (s.local_port != hdr.dst_port) continue;
        if (s.local_addr != 0 and s.local_addr != ip_hdr.dst_addr) continue;

        // If connected, filter by remote
        if (s.is_connected) {
            if (s.remote_addr != ip_hdr.src_addr or s.remote_port != hdr.src_port) continue;
        }

        var dgram = Datagram{
            .src_addr = ip_hdr.src_addr,
            .src_port = hdr.src_port,
            .len = @truncate(payload.len),
            .is_valid = true,
        };
        const copy_len = @min(payload.len, dgram.data.len);
        @memcpy(dgram.data[0..copy_len], payload[0..copy_len]);

        if (!s.enqueue(&dgram)) {
            udp_stats.queue_overflow += 1;
        }
        found = true;
    }

    if (!found) {
        udp_stats.no_port += 1;
        // TODO: send ICMP Port Unreachable
    }
}

// =============================================================================
// Helpers
// =============================================================================
fn allocateEphemeralPort() u16 {
    const port = next_ephemeral_port;
    next_ephemeral_port +%= 1;
    if (next_ephemeral_port < 49152) next_ephemeral_port = 49152;
    return port;
}

/// UDP checksum with pseudo-header
fn udpChecksum(src_ip: u32, dst_ip: u32, udp_data: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header
    sum += src_ip >> 16;
    sum += src_ip & 0xFFFF;
    sum += dst_ip >> 16;
    sum += dst_ip & 0xFFFF;
    sum += @as(u32, main.ip.PROTO_UDP);
    sum += @as(u32, @truncate(udp_data.len));

    // UDP header + data
    var i: usize = 0;
    while (i + 1 < udp_data.len) : (i += 2) {
        sum += @as(u32, udp_data[i]) << 8 | udp_data[i + 1];
    }
    if (i < udp_data.len) {
        sum += @as(u32, udp_data[i]) << 8;
    }

    // Fold
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return @truncate(~sum);
}

pub fn getStats() UdpStats {
    return udp_stats;
}

// =============================================================================
// Network byte order helpers
// =============================================================================
fn readU16BE(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) << 8 | data[offset + 1];
}

fn writeU16BE(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @truncate(val >> 8);
    buf[offset + 1] = @truncate(val & 0xFF);
}
