// =============================================================================
// Kernel Zxyphor - Ethernet Frame Layer (IEEE 802.3)
// =============================================================================
// Handles raw Ethernet frame construction, parsing, and dispatch to
// upper-layer protocols (ARP, IPv4, IPv6). Manages MAC addresses and
// network interface abstraction.
//
// Frame format (DIX/Ethernet II):
//   Destination MAC (6) | Source MAC (6) | EtherType (2) | Payload (46-1500) | FCS (4)
//
// Supported EtherTypes:
//   0x0800 = IPv4
//   0x0806 = ARP
//   0x86DD = IPv6
//   0x8100 = 802.1Q VLAN
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants & EtherTypes
// =============================================================================
pub const ETHER_ADDR_LEN: usize = 6;
pub const ETHER_HEADER_LEN: usize = 14;
pub const ETHER_MIN_PAYLOAD: usize = 46;
pub const ETHER_MAX_PAYLOAD: usize = 1500;
pub const ETHER_MIN_FRAME: usize = 64;
pub const ETHER_MAX_FRAME: usize = 1518;
pub const ETHER_FCS_LEN: usize = 4;
pub const ETHER_JUMBO_MAX: usize = 9000;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_LLDP: u16 = 0x88CC;

// =============================================================================
// MAC Address
// =============================================================================
pub const MacAddress = struct {
    octets: [6]u8 = [_]u8{0} ** 6,

    pub const BROADCAST: MacAddress = .{ .octets = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };
    pub const ZERO: MacAddress = .{ .octets = .{ 0, 0, 0, 0, 0, 0 } };

    pub fn eql(self: MacAddress, other: MacAddress) bool {
        return self.octets[0] == other.octets[0] and
            self.octets[1] == other.octets[1] and
            self.octets[2] == other.octets[2] and
            self.octets[3] == other.octets[3] and
            self.octets[4] == other.octets[4] and
            self.octets[5] == other.octets[5];
    }

    pub fn isBroadcast(self: MacAddress) bool {
        return self.eql(BROADCAST);
    }

    pub fn isMulticast(self: MacAddress) bool {
        return (self.octets[0] & 0x01) != 0;
    }

    pub fn isLocal(self: MacAddress) bool {
        return (self.octets[0] & 0x02) != 0;
    }

    pub fn isZero(self: MacAddress) bool {
        return self.eql(ZERO);
    }
};

// =============================================================================
// Ethernet Header
// =============================================================================
pub const EthernetHeader = struct {
    dst_mac: MacAddress = .{},
    src_mac: MacAddress = .{},
    ether_type: u16 = 0,

    pub fn parse(data: []const u8) ?EthernetHeader {
        if (data.len < ETHER_HEADER_LEN) return null;

        var hdr = EthernetHeader{};
        @memcpy(&hdr.dst_mac.octets, data[0..6]);
        @memcpy(&hdr.src_mac.octets, data[6..12]);
        hdr.ether_type = @as(u16, data[12]) << 8 | data[13];
        return hdr;
    }

    pub fn serialize(self: *const EthernetHeader, buf: []u8) bool {
        if (buf.len < ETHER_HEADER_LEN) return false;

        @memcpy(buf[0..6], &self.dst_mac.octets);
        @memcpy(buf[6..12], &self.src_mac.octets);
        buf[12] = @truncate(self.ether_type >> 8);
        buf[13] = @truncate(self.ether_type & 0xFF);
        return true;
    }

    pub fn payloadOffset(self: *const EthernetHeader) usize {
        // Handle 802.1Q VLAN tag (adds 4 bytes)
        if (self.ether_type == ETHERTYPE_VLAN) {
            return ETHER_HEADER_LEN + 4;
        }
        return ETHER_HEADER_LEN;
    }
};

// =============================================================================
// Network Interface
// =============================================================================
pub const InterfaceFlags = packed struct {
    up: bool = false,
    broadcast: bool = false,
    loopback: bool = false,
    point_to_point: bool = false,
    running: bool = false,
    multicast: bool = false,
    promisc: bool = false,
    _pad: u9 = 0,
};

pub const NetworkInterface = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    mac: MacAddress = .{},
    flags: InterfaceFlags = .{},
    mtu: u16 = 1500,

    // IP configuration
    ipv4_addr: u32 = 0,
    ipv4_netmask: u32 = 0,
    ipv4_gateway: u32 = 0,

    // Statistics
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    tx_errors: u64 = 0,
    rx_dropped: u64 = 0,
    tx_dropped: u64 = 0,

    // State
    is_valid: bool = false,
    link_up: bool = false,

    // Transmit callback (set by driver)
    tx_callback: ?*const fn (iface: *NetworkInterface, frame: []const u8) bool = null,

    pub fn setName(self: *NetworkInterface, name: []const u8) void {
        const len = @min(name.len, 15);
        @memcpy(self.name[0..len], name[0..len]);
        self.name[len] = 0;
        self.name_len = @truncate(len);
    }

    pub fn getName(self: *const NetworkInterface) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn transmit(self: *NetworkInterface, frame: []const u8) bool {
        if (!self.flags.up or !self.link_up) return false;
        if (self.tx_callback) |cb| {
            const ok = cb(self, frame);
            if (ok) {
                self.tx_packets += 1;
                self.tx_bytes += frame.len;
            } else {
                self.tx_errors += 1;
            }
            return ok;
        }
        self.tx_dropped += 1;
        return false;
    }
};

// =============================================================================
// Interface Table
// =============================================================================
pub const MAX_INTERFACES: usize = 16;
var interfaces: [MAX_INTERFACES]NetworkInterface = undefined;

// Loopback interface
var loopback: NetworkInterface = undefined;

// =============================================================================
// Packet Buffer (for RX/TX)
// =============================================================================
pub const MAX_PACKET_SIZE: usize = 2048;
pub const PACKET_POOL_SIZE: usize = 256;

pub const PacketBuffer = struct {
    data: [MAX_PACKET_SIZE]u8 = [_]u8{0} ** MAX_PACKET_SIZE,
    len: usize = 0,
    iface_index: u8 = 0,
    in_use: bool = false,

    pub fn payload(self: *PacketBuffer) []u8 {
        return self.data[0..self.len];
    }
};

var packet_pool: [PACKET_POOL_SIZE]PacketBuffer = undefined;

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    // Clear interfaces
    for (&interfaces) |*iface| {
        iface.* = NetworkInterface{};
    }

    // Initialize loopback
    loopback = NetworkInterface{};
    loopback.setName("lo");
    loopback.mac = MacAddress.ZERO;
    loopback.ipv4_addr = ipv4(127, 0, 0, 1);
    loopback.ipv4_netmask = ipv4(255, 0, 0, 0);
    loopback.flags.up = true;
    loopback.flags.running = true;
    loopback.flags.loopback = true;
    loopback.link_up = true;
    loopback.is_valid = true;
    loopback.mtu = 65535;

    // loopback goes in slot 0
    interfaces[0] = loopback;

    // Clear packet pool
    for (&packet_pool) |*pkt| {
        pkt.* = PacketBuffer{};
    }

    main.klog(.info, "ethernet: initialized ({d} interfaces, lo at 127.0.0.1)", .{MAX_INTERFACES});
}

// =============================================================================
// Interface Management
// =============================================================================
pub fn registerInterface(name: []const u8, mac: MacAddress) ?*NetworkInterface {
    for (&interfaces, 0..) |*iface, i| {
        if (i == 0) continue; // Skip loopback slot
        if (!iface.is_valid) {
            iface.* = NetworkInterface{};
            iface.setName(name);
            iface.mac = mac;
            iface.is_valid = true;
            return iface;
        }
    }
    return null;
}

pub fn findInterface(name: []const u8) ?*NetworkInterface {
    for (&interfaces) |*iface| {
        if (iface.is_valid and iface.name_len == name.len) {
            if (memEql(iface.name[0..iface.name_len], name)) return iface;
        }
    }
    return null;
}

pub fn getInterface(index: usize) ?*NetworkInterface {
    if (index >= MAX_INTERFACES) return null;
    if (!interfaces[index].is_valid) return null;
    return &interfaces[index];
}

pub fn getLoopback() *NetworkInterface {
    return &interfaces[0];
}

// =============================================================================
// Frame Reception (called by NIC driver)
// =============================================================================
pub fn receiveFrame(iface: *NetworkInterface, frame: []const u8) void {
    if (frame.len < ETHER_HEADER_LEN) {
        iface.rx_errors += 1;
        return;
    }

    iface.rx_packets += 1;
    iface.rx_bytes += frame.len;

    // Parse header
    const hdr = EthernetHeader.parse(frame) orelse {
        iface.rx_errors += 1;
        return;
    };

    // Check if frame is for us (unicast, broadcast, or promisc)
    if (!hdr.dst_mac.isBroadcast() and !hdr.dst_mac.isMulticast() and
        !hdr.dst_mac.eql(iface.mac) and !iface.flags.promisc)
    {
        iface.rx_dropped += 1;
        return;
    }

    const payload_data = frame[hdr.payloadOffset()..];

    // Dispatch by EtherType
    switch (hdr.ether_type) {
        ETHERTYPE_IPV4 => {
            main.ip.receivePacket(iface, payload_data);
        },
        ETHERTYPE_ARP => {
            main.arp.receivePacket(iface, payload_data);
        },
        else => {
            // Unknown protocol
        },
    }
}

// =============================================================================
// Frame Transmission
// =============================================================================
pub fn sendFrame(iface: *NetworkInterface, dst_mac: MacAddress, ether_type: u16, payload_data: []const u8) bool {
    if (payload_data.len > ETHER_MAX_PAYLOAD) return false;

    // Allocate a packet buffer
    const pkt = allocPacket() orelse return false;
    defer freePacket(pkt);

    // Build Ethernet header
    const hdr = EthernetHeader{
        .dst_mac = dst_mac,
        .src_mac = iface.mac,
        .ether_type = ether_type,
    };
    _ = hdr.serialize(&pkt.data);

    // Copy payload
    const offset = ETHER_HEADER_LEN;
    if (offset + payload_data.len > MAX_PACKET_SIZE) return false;
    @memcpy(pkt.data[offset .. offset + payload_data.len], payload_data);

    // Pad if necessary
    var total = offset + payload_data.len;
    if (total < ETHER_MIN_FRAME) {
        @memset(pkt.data[total..ETHER_MIN_FRAME], 0);
        total = ETHER_MIN_FRAME;
    }

    pkt.len = total;

    return iface.transmit(pkt.data[0..total]);
}

// =============================================================================
// Packet Pool Management
// =============================================================================
fn allocPacket() ?*PacketBuffer {
    for (&packet_pool) |*pkt| {
        if (!pkt.in_use) {
            pkt.in_use = true;
            pkt.len = 0;
            return pkt;
        }
    }
    return null;
}

fn freePacket(pkt: *PacketBuffer) void {
    pkt.in_use = false;
}

// =============================================================================
// Utility: Build IPv4 address from octets
// =============================================================================
pub fn ipv4(a: u8, b: u8, c: u8, d: u8) u32 {
    return @as(u32, a) << 24 | @as(u32, b) << 16 | @as(u32, c) << 8 | @as(u32, d);
}

pub fn ipv4Str(addr: u32) [4]u8 {
    return .{
        @truncate(addr >> 24),
        @truncate((addr >> 16) & 0xFF),
        @truncate((addr >> 8) & 0xFF),
        @truncate(addr & 0xFF),
    };
}

// =============================================================================
// CRC-32 for FCS (Ethernet CRC polynomial 0x04C11DB7)
// =============================================================================
const crc32_table: [256]u32 = blk: {
    var table: [256]u32 = [_]u32{0} ** 256;
    for (0..256) |i| {
        var crc: u32 = @truncate(i);
        for (0..8) |_| {
            if ((crc & 1) != 0) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    break :blk table;
};

pub fn crc32(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        const index: u8 = @truncate((crc ^ byte) & 0xFF);
        crc = (crc >> 8) ^ crc32_table[index];
    }
    return ~crc;
}

fn memEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}
