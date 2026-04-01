// =============================================================================
// Kernel Zxyphor — Rust Network Packet Buffer Management
// =============================================================================
// Network packets flow through the kernel as PacketBuffer objects. This module
// provides a zero-copy packet buffer implementation with headroom and tailroom
// for header prepending and trailer appending without memory copies.
//
// The design is inspired by Linux's sk_buff but simplified for clarity:
//   - Each packet has a contiguous data region with head/tail pointers
//   - Headroom allows protocols to prepend headers in place
//   - Reference counting enables zero-copy packet sharing
//   - Metadata fields track protocol headers and routing decisions
//
// Memory layout of a PacketBuffer:
//   [headroom] [data ........... tail] [tailroom]
//   ^head      ^data            ^tail            ^end
// =============================================================================

use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum packet size including all headers (jumbo frame support)
pub const MAX_PACKET_SIZE: usize = 9216;

/// Default headroom reserved for header prepending
pub const DEFAULT_HEADROOM: usize = 128;

/// Default tailroom reserved for trailer (e.g., FCS) appending
pub const DEFAULT_TAILROOM: usize = 64;

/// Maximum number of packet buffers in the global pool
const PACKET_POOL_SIZE: usize = 4096;

/// Size of the packet data buffer including headroom and tailroom
const PACKET_BUFFER_DATA_SIZE: usize = MAX_PACKET_SIZE + DEFAULT_HEADROOM + DEFAULT_TAILROOM;

// =============================================================================
// Protocol identifiers
// =============================================================================

/// Network layer protocol type
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
    Vlan = 0x8100,
    Unknown = 0xFFFF,
}

impl EtherType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::Ipv6,
            0x8100 => EtherType::Vlan,
            _ => EtherType::Unknown,
        }
    }
}

/// Transport layer protocol type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
    Unknown = 255,
}

impl IpProtocol {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            _ => IpProtocol::Unknown,
        }
    }
}

// =============================================================================
// Packet direction and status
// =============================================================================

/// Direction of packet flow
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    /// Packet received from the network
    Incoming = 0,
    /// Packet being sent to the network
    Outgoing = 1,
    /// Packet generated locally (loopback)
    Local = 2,
    /// Packet being forwarded between interfaces
    Forwarding = 3,
}

/// Packet processing status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketStatus {
    /// Packet is new and unprocessed
    New = 0,
    /// Packet headers have been parsed
    Parsed = 1,
    /// Packet has passed firewall checks
    Accepted = 2,
    /// Packet has been dropped by firewall
    Dropped = 3,
    /// Packet has been delivered to a socket
    Delivered = 4,
    /// Packet has been transmitted on the wire
    Transmitted = 5,
    /// Packet processing encountered an error
    Error = 6,
}

// =============================================================================
// MAC address type
// =============================================================================

/// A 6-byte Ethernet MAC address
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddress {
    pub octets: [u8; 6],
}

impl MacAddress {
    pub const BROADCAST: MacAddress = MacAddress { octets: [0xFF; 6] };
    pub const ZERO: MacAddress = MacAddress { octets: [0; 6] };

    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddress {
            octets: [a, b, c, d, e, f],
        }
    }

    pub fn is_broadcast(&self) -> bool {
        self.octets == [0xFF; 6]
    }

    pub fn is_multicast(&self) -> bool {
        (self.octets[0] & 0x01) != 0
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast() && !self.is_broadcast()
    }

    pub fn is_zero(&self) -> bool {
        self.octets == [0; 6]
    }
}

// =============================================================================
// IPv4 address type
// =============================================================================

/// A 4-byte IPv4 address
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address {
    pub octets: [u8; 4],
}

impl Ipv4Address {
    pub const ZERO: Ipv4Address = Ipv4Address { octets: [0; 4] };
    pub const BROADCAST: Ipv4Address = Ipv4Address { octets: [255; 4] };
    pub const LOOPBACK: Ipv4Address = Ipv4Address { octets: [127, 0, 0, 1] };

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Address { octets: [a, b, c, d] }
    }

    pub fn from_u32(val: u32) -> Self {
        Ipv4Address {
            octets: val.to_be_bytes(),
        }
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.octets)
    }

    pub fn is_loopback(&self) -> bool {
        self.octets[0] == 127
    }

    pub fn is_private(&self) -> bool {
        match self.octets[0] {
            10 => true,
            172 => (self.octets[1] & 0xF0) == 16,
            192 => self.octets[1] == 168,
            _ => false,
        }
    }

    pub fn is_multicast(&self) -> bool {
        (self.octets[0] & 0xF0) == 224
    }

    pub fn is_broadcast(&self) -> bool {
        self.octets == [255; 4]
    }

    /// Apply a subnet mask and check if two addresses are in the same network
    pub fn same_subnet(&self, other: &Ipv4Address, mask: &Ipv4Address) -> bool {
        for i in 0..4 {
            if (self.octets[i] & mask.octets[i]) != (other.octets[i] & mask.octets[i]) {
                return false;
            }
        }
        true
    }
}

// =============================================================================
// IPv6 address type
// =============================================================================

/// A 16-byte IPv6 address
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Address {
    pub octets: [u8; 16],
}

impl Ipv6Address {
    pub const ZERO: Ipv6Address = Ipv6Address { octets: [0; 16] };
    pub const LOOPBACK: Ipv6Address = Ipv6Address {
        octets: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };

    pub fn is_loopback(&self) -> bool {
        *self == Ipv6Address::LOOPBACK
    }

    pub fn is_multicast(&self) -> bool {
        self.octets[0] == 0xFF
    }

    pub fn is_link_local(&self) -> bool {
        self.octets[0] == 0xFE && (self.octets[1] & 0xC0) == 0x80
    }

    pub fn is_global_unicast(&self) -> bool {
        // Global unicast addresses: 2000::/3
        (self.octets[0] & 0xE0) == 0x20
    }
}

// =============================================================================
// Packet buffer metadata
// =============================================================================

/// Metadata associated with each network packet. Stored separately from the
/// packet data to allow efficient metadata-only operations (filtering, routing
/// decisions) without touching the data cache lines.
#[repr(C)]
pub struct PacketMeta {
    /// Source MAC address (from Ethernet header)
    pub src_mac: MacAddress,
    /// Destination MAC address (from Ethernet header)
    pub dst_mac: MacAddress,
    /// Source IPv4 address (from IP header)
    pub src_ip: Ipv4Address,
    /// Destination IPv4 address (from IP header)
    pub dst_ip: Ipv4Address,
    /// Source port (from TCP/UDP header)
    pub src_port: u16,
    /// Destination port (from TCP/UDP header)
    pub dst_port: u16,
    /// EtherType from the Ethernet header
    pub ether_type: EtherType,
    /// IP protocol number
    pub ip_protocol: IpProtocol,
    /// Packet direction
    pub direction: PacketDirection,
    /// Packet processing status
    pub status: PacketStatus,
    /// IP Time To Live / Hop Limit
    pub ttl: u8,
    /// IP Type of Service / Traffic Class
    pub tos: u8,
    /// Offset to the L3 (network) header within the packet data
    pub l3_offset: u16,
    /// Offset to the L4 (transport) header within the packet data
    pub l4_offset: u16,
    /// Offset to the payload within the packet data
    pub payload_offset: u16,
    /// Interface index this packet arrived on or will be sent from
    pub interface_id: u16,
    /// VLAN tag (0 = untagged)
    pub vlan_id: u16,
    /// Timestamp when the packet was received (in nanoseconds from boot)
    pub timestamp_ns: u64,
    /// Packet checksum state
    pub checksum_valid: bool,
    /// Whether this packet should bypass the firewall
    pub bypass_firewall: bool,
    /// Mark value (for policy routing and firewall rules)
    pub mark: u32,
}

impl PacketMeta {
    pub const fn empty() -> Self {
        PacketMeta {
            src_mac: MacAddress { octets: [0; 6] },
            dst_mac: MacAddress { octets: [0; 6] },
            src_ip: Ipv4Address { octets: [0; 4] },
            dst_ip: Ipv4Address { octets: [0; 4] },
            src_port: 0,
            dst_port: 0,
            ether_type: EtherType::Unknown,
            ip_protocol: IpProtocol::Unknown,
            direction: PacketDirection::Incoming,
            status: PacketStatus::New,
            ttl: 0,
            tos: 0,
            l3_offset: 0,
            l4_offset: 0,
            payload_offset: 0,
            interface_id: 0,
            vlan_id: 0,
            timestamp_ns: 0,
            checksum_valid: false,
            bypass_firewall: false,
            mark: 0,
        }
    }
}

// =============================================================================
// Packet buffer
// =============================================================================

/// A network packet buffer with headroom/tailroom for zero-copy header
/// manipulation. The data region is a fixed-size array embedded in the struct
/// to avoid heap allocation in no_std environments.
#[repr(C)]
pub struct PacketBuffer {
    /// The raw data storage (headroom + data + tailroom)
    data: [u8; PACKET_BUFFER_DATA_SIZE],
    /// Offset of the first valid data byte within `data`
    data_start: usize,
    /// Offset past the last valid data byte within `data`
    data_end: usize,
    /// Reference count for zero-copy sharing
    ref_count: AtomicU32,
    /// Packet metadata
    pub meta: PacketMeta,
    /// Whether this buffer is in use
    in_use: bool,
    /// Pool index (if allocated from the packet pool)
    pool_index: u32,
}

impl PacketBuffer {
    /// Create a new empty packet buffer with default headroom
    pub const fn new() -> Self {
        PacketBuffer {
            data: [0u8; PACKET_BUFFER_DATA_SIZE],
            data_start: DEFAULT_HEADROOM,
            data_end: DEFAULT_HEADROOM,
            ref_count: AtomicU32::new(1),
            meta: PacketMeta::empty(),
            in_use: false,
            pool_index: u32::MAX,
        }
    }

    /// Reset the buffer for reuse
    pub fn reset(&mut self) {
        self.data_start = DEFAULT_HEADROOM;
        self.data_end = DEFAULT_HEADROOM;
        self.ref_count.store(1, Ordering::Release);
        self.meta = PacketMeta::empty();
    }

    /// Get the current data length
    pub fn len(&self) -> usize {
        self.data_end - self.data_start
    }

    /// Check if the buffer contains no data
    pub fn is_empty(&self) -> bool {
        self.data_start == self.data_end
    }

    /// Get a slice of the current data
    pub fn data(&self) -> &[u8] {
        &self.data[self.data_start..self.data_end]
    }

    /// Get a mutable slice of the current data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.data_start..self.data_end]
    }

    /// Available headroom (space before the data for prepending headers)
    pub fn headroom(&self) -> usize {
        self.data_start
    }

    /// Available tailroom (space after the data for appending trailers)
    pub fn tailroom(&self) -> usize {
        PACKET_BUFFER_DATA_SIZE - self.data_end
    }

    /// Prepend data at the beginning (expand into headroom).
    /// Used by protocol layers to prepend their headers.
    pub fn push_front(&mut self, len: usize) -> Option<&mut [u8]> {
        if len > self.headroom() {
            return None;
        }
        self.data_start -= len;
        Some(&mut self.data[self.data_start..self.data_start + len])
    }

    /// Append data at the end (expand into tailroom).
    /// Used for adding payload or trailers.
    pub fn push_back(&mut self, len: usize) -> Option<&mut [u8]> {
        if len > self.tailroom() {
            return None;
        }
        let start = self.data_end;
        self.data_end += len;
        Some(&mut self.data[start..self.data_end])
    }

    /// Remove data from the beginning (shrink from front).
    /// Used after a protocol layer has finished processing its header.
    pub fn pull_front(&mut self, len: usize) -> bool {
        if len > self.len() {
            return false;
        }
        self.data_start += len;
        true
    }

    /// Remove data from the end (shrink from back).
    pub fn trim_back(&mut self, len: usize) -> bool {
        if len > self.len() {
            return false;
        }
        self.data_end -= len;
        true
    }

    /// Copy data into the packet starting at the current data_end position
    pub fn append(&mut self, src: &[u8]) -> bool {
        if src.len() > self.tailroom() {
            return false;
        }
        let start = self.data_end;
        self.data[start..start + src.len()].copy_from_slice(src);
        self.data_end += src.len();
        true
    }

    /// Increment the reference count (for zero-copy sharing)
    pub fn add_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Decrement the reference count. Returns true if this was the last reference.
    pub fn release_ref(&self) -> bool {
        self.ref_count.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Get the current reference count
    pub fn ref_count(&self) -> u32 {
        self.ref_count.load(Ordering::Acquire)
    }

    // =========================================================================
    // Protocol header access helpers
    // =========================================================================

    /// Get the Ethernet header (first 14 bytes of data)
    pub fn ethernet_header(&self) -> Option<&[u8]> {
        if self.len() >= 14 {
            Some(&self.data[self.data_start..self.data_start + 14])
        } else {
            None
        }
    }

    /// Get the IP header (starts at L3 offset)
    pub fn ip_header(&self) -> Option<&[u8]> {
        let offset = self.data_start + self.meta.l3_offset as usize;
        if offset < self.data_end && self.data_end - offset >= 20 {
            let ihl = ((self.data[offset] & 0x0F) as usize) * 4;
            if ihl >= 20 && offset + ihl <= self.data_end {
                Some(&self.data[offset..offset + ihl])
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get the transport header (starts at L4 offset)
    pub fn transport_header(&self) -> Option<&[u8]> {
        let offset = self.data_start + self.meta.l4_offset as usize;
        if offset < self.data_end {
            Some(&self.data[offset..self.data_end])
        } else {
            None
        }
    }

    /// Parse the Ethernet header and populate metadata fields
    pub fn parse_ethernet(&mut self) -> bool {
        if self.len() < 14 {
            return false;
        }

        let base = self.data_start;

        // Destination MAC (bytes 0-5)
        self.meta.dst_mac.octets.copy_from_slice(&self.data[base..base + 6]);

        // Source MAC (bytes 6-11)
        self.meta.src_mac.octets.copy_from_slice(&self.data[base + 6..base + 12]);

        // EtherType (bytes 12-13, big-endian)
        let ether_type = u16::from_be_bytes([self.data[base + 12], self.data[base + 13]]);

        // Handle VLAN tag (802.1Q)
        if ether_type == 0x8100 {
            if self.len() < 18 {
                return false;
            }
            self.meta.vlan_id = u16::from_be_bytes([
                self.data[base + 14],
                self.data[base + 15],
            ]) & 0x0FFF;
            let real_ether_type = u16::from_be_bytes([
                self.data[base + 16],
                self.data[base + 17],
            ]);
            self.meta.ether_type = EtherType::from_u16(real_ether_type);
            self.meta.l3_offset = 18;
        } else {
            self.meta.ether_type = EtherType::from_u16(ether_type);
            self.meta.l3_offset = 14;
        }

        self.meta.status = PacketStatus::Parsed;
        true
    }

    /// Parse the IPv4 header and populate metadata fields
    pub fn parse_ipv4(&mut self) -> bool {
        let l3_start = self.data_start + self.meta.l3_offset as usize;

        if l3_start + 20 > self.data_end {
            return false;
        }

        let version_ihl = self.data[l3_start];
        let version = (version_ihl >> 4) & 0x0F;
        let ihl = ((version_ihl & 0x0F) as usize) * 4;

        if version != 4 || ihl < 20 || l3_start + ihl > self.data_end {
            return false;
        }

        self.meta.tos = self.data[l3_start + 1];
        self.meta.ttl = self.data[l3_start + 8];
        self.meta.ip_protocol = IpProtocol::from_u8(self.data[l3_start + 9]);

        // Source IP (bytes 12-15)
        self.meta.src_ip.octets.copy_from_slice(&self.data[l3_start + 12..l3_start + 16]);

        // Destination IP (bytes 16-19)
        self.meta.dst_ip.octets.copy_from_slice(&self.data[l3_start + 16..l3_start + 20]);

        self.meta.l4_offset = (self.meta.l3_offset as usize + ihl) as u16;

        true
    }

    /// Parse TCP/UDP port numbers from the transport header
    pub fn parse_transport_ports(&mut self) -> bool {
        let l4_start = self.data_start + self.meta.l4_offset as usize;

        if l4_start + 4 > self.data_end {
            return false;
        }

        self.meta.src_port = u16::from_be_bytes([
            self.data[l4_start],
            self.data[l4_start + 1],
        ]);

        self.meta.dst_port = u16::from_be_bytes([
            self.data[l4_start + 2],
            self.data[l4_start + 3],
        ]);

        // Calculate payload offset based on protocol
        match self.meta.ip_protocol {
            IpProtocol::Tcp => {
                if l4_start + 12 <= self.data_end {
                    let data_offset = ((self.data[l4_start + 12] >> 4) as u16) * 4;
                    self.meta.payload_offset = self.meta.l4_offset + data_offset;
                }
            }
            IpProtocol::Udp => {
                self.meta.payload_offset = self.meta.l4_offset + 8;
            }
            _ => {
                self.meta.payload_offset = self.meta.l4_offset;
            }
        }

        true
    }

    /// Full packet parse: Ethernet → IP → Transport
    pub fn parse_all(&mut self) -> bool {
        if !self.parse_ethernet() {
            return false;
        }

        if self.meta.ether_type == EtherType::Ipv4 {
            if !self.parse_ipv4() {
                return false;
            }

            match self.meta.ip_protocol {
                IpProtocol::Tcp | IpProtocol::Udp => {
                    if !self.parse_transport_ports() {
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
    }
}

// =============================================================================
// FFI interface
// =============================================================================

/// Create a packet buffer with the given data
#[no_mangle]
pub extern "C" fn zxyphor_rust_packet_create(
    data: *const u8,
    data_len: usize,
    packet_out: *mut PacketBuffer,
) -> i32 {
    if data.is_null() || packet_out.is_null() || data_len > MAX_PACKET_SIZE {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let mut pkt = PacketBuffer::new();
    let src = unsafe { core::slice::from_raw_parts(data, data_len) };

    if !pkt.append(src) {
        return crate::ffi::error::FfiError::BufferTooSmall.as_i32();
    }

    pkt.in_use = true;

    unsafe {
        core::ptr::write(packet_out, pkt);
    }

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Parse all protocol headers in a packet buffer
#[no_mangle]
pub extern "C" fn zxyphor_rust_packet_parse(packet: *mut PacketBuffer) -> i32 {
    if packet.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let pkt = unsafe { &mut *packet };
    if pkt.parse_all() {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::Corruption.as_i32()
    }
}

/// Get the data length of a packet
#[no_mangle]
pub extern "C" fn zxyphor_rust_packet_len(packet: *const PacketBuffer) -> usize {
    if packet.is_null() {
        return 0;
    }
    unsafe { (*packet).len() }
}

/// Get a pointer to the packet's data
#[no_mangle]
pub extern "C" fn zxyphor_rust_packet_data(packet: *const PacketBuffer) -> *const u8 {
    if packet.is_null() {
        return core::ptr::null();
    }
    unsafe { (*packet).data().as_ptr() }
}
