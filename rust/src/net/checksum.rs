// =============================================================================
// Kernel Zxyphor — Rust Network Checksum Computation
// =============================================================================
// Implements RFC 1071 Internet checksum algorithm used by IPv4, TCP, UDP, and
// ICMP. The one's complement checksum is computed over the header bytes and
// verified on receive. This is a critical hot path in networking — the
// implementation uses 32-bit accumulation with deferred carry folding for
// performance.
//
// Also provides pseudo-header checksum computation required by TCP and UDP
// per RFC 793 and RFC 768, where the checksum covers a "pseudo-header"
// prepended to the transport data containing source/destination IP.
// =============================================================================

use crate::net::packet::Ipv4Address;

// =============================================================================
// One's complement checksum (RFC 1071)
// =============================================================================

/// Compute the Internet checksum over a byte slice.
///
/// The algorithm:
///   1. Accumulate all 16-bit words into a 32-bit sum
///   2. Handle any trailing odd byte
///   3. Fold the 32-bit sum into 16 bits by adding carries
///   4. Return the one's complement of the result
///
/// On a valid received packet, computing the checksum over the entire header
/// (including the checksum field) should yield 0x0000.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Process 16-bit words (main loop)
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // Handle the trailing odd byte (if any) by padding with zero
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum into 16 bits (add upper 16 bits to lower 16 bits)
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !(sum as u16)
}

/// Verify a checksum by computing over the data (including checksum field).
/// Returns true if the checksum is valid (result is 0 or 0xFFFF).
pub fn verify_checksum(data: &[u8]) -> bool {
    let result = internet_checksum(data);
    result == 0 || result == 0xFFFF
}

/// Compute an incremental checksum update when a 16-bit field changes.
///
/// Per RFC 1624, when a single 16-bit value in the header changes from
/// `old_value` to `new_value`, we can efficiently update the checksum
/// without recomputing over the entire header.
///
///   new_checksum = ~(~old_checksum + ~old_value + new_value)
///
/// This is critical for routers that decrement the TTL and must update
/// the IP header checksum on every forwarded packet.
pub fn incremental_update(old_checksum: u16, old_value: u16, new_value: u16) -> u16 {
    // Work with one's complement arithmetic in 32 bits
    let mut sum: u32 = (!old_checksum) as u32;
    sum += (!old_value) as u32;
    sum += new_value as u32;

    // Fold carries
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// =============================================================================
// TCP/UDP pseudo-header checksum
// =============================================================================

/// Compute the pseudo-header checksum for TCP/UDP.
///
/// The pseudo-header consists of:
///   - Source IP address (4 bytes)
///   - Destination IP address (4 bytes)
///   - Reserved byte (0x00)
///   - Protocol number (1 byte)
///   - TCP/UDP segment length (2 bytes)
///
/// The pseudo-header checksum is added to the transport data checksum
/// to form the final TCP or UDP checksum.
pub fn pseudo_header_checksum(
    src_ip: &Ipv4Address,
    dst_ip: &Ipv4Address,
    protocol: u8,
    transport_len: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source IP address (2 × 16-bit words)
    sum += u16::from_be_bytes([src_ip.octets[0], src_ip.octets[1]]) as u32;
    sum += u16::from_be_bytes([src_ip.octets[2], src_ip.octets[3]]) as u32;

    // Destination IP address (2 × 16-bit words)
    sum += u16::from_be_bytes([dst_ip.octets[0], dst_ip.octets[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip.octets[2], dst_ip.octets[3]]) as u32;

    // Reserved + Protocol
    sum += protocol as u32;

    // Transport segment length
    sum += transport_len as u32;

    sum
}

/// Compute the complete TCP checksum including the pseudo-header.
///
/// This combines the pseudo-header checksum with the checksum of the
/// actual TCP segment data (header + payload).
pub fn tcp_checksum(
    src_ip: &Ipv4Address,
    dst_ip: &Ipv4Address,
    tcp_segment: &[u8],
) -> u16 {
    let pseudo = pseudo_header_checksum(src_ip, dst_ip, 6, tcp_segment.len() as u16);

    let mut sum = pseudo;
    let mut i = 0;

    // Add TCP segment data
    while i + 1 < tcp_segment.len() {
        let word = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // Handle odd trailing byte
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // Fold and complement
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Compute the complete UDP checksum including the pseudo-header.
///
/// Per RFC 768, the UDP checksum is optional for IPv4 (a checksum of
/// zero means "no checksum"). However, it is mandatory for IPv6.
pub fn udp_checksum(
    src_ip: &Ipv4Address,
    dst_ip: &Ipv4Address,
    udp_segment: &[u8],
) -> u16 {
    let pseudo = pseudo_header_checksum(src_ip, dst_ip, 17, udp_segment.len() as u16);

    let mut sum = pseudo;
    let mut i = 0;

    while i + 1 < udp_segment.len() {
        let word = u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !(sum as u16);

    // Per RFC 768: if the computed checksum is zero, transmit 0xFFFF instead
    // (since zero means "no checksum" in UDP over IPv4)
    if result == 0 { 0xFFFF } else { result }
}

/// Verify a received TCP checksum
pub fn verify_tcp_checksum(
    src_ip: &Ipv4Address,
    dst_ip: &Ipv4Address,
    tcp_segment: &[u8],
) -> bool {
    tcp_checksum(src_ip, dst_ip, tcp_segment) == 0
}

/// Verify a received UDP checksum
pub fn verify_udp_checksum(
    src_ip: &Ipv4Address,
    dst_ip: &Ipv4Address,
    udp_segment: &[u8],
) -> bool {
    // A UDP checksum of 0x0000 means "not computed" — accept it
    if udp_segment.len() >= 8 {
        let stored = u16::from_be_bytes([udp_segment[6], udp_segment[7]]);
        if stored == 0 {
            return true;
        }
    }
    udp_checksum(src_ip, dst_ip, udp_segment) == 0
}

// =============================================================================
// ICMP checksum
// =============================================================================

/// Compute the ICMP checksum. ICMP uses the standard Internet checksum
/// algorithm over the entire ICMP message (header + data).
pub fn icmp_checksum(icmp_message: &[u8]) -> u16 {
    internet_checksum(icmp_message)
}

/// Verify a received ICMP checksum
pub fn verify_icmp_checksum(icmp_message: &[u8]) -> bool {
    verify_checksum(icmp_message)
}

// =============================================================================
// Optimized checksum for 20-byte IPv4 headers (common fast path)
// =============================================================================

/// Specialized checksum for standard 20-byte IPv4 headers with no options.
/// This unrolled version avoids loop overhead for the most common case.
pub fn ipv4_header_checksum_fast(header: &[u8; 20]) -> u16 {
    let mut sum: u32 = 0;

    // Unrolled: 10 16-bit words
    sum += u16::from_be_bytes([header[0], header[1]]) as u32;
    sum += u16::from_be_bytes([header[2], header[3]]) as u32;
    sum += u16::from_be_bytes([header[4], header[5]]) as u32;
    sum += u16::from_be_bytes([header[6], header[7]]) as u32;
    sum += u16::from_be_bytes([header[8], header[9]]) as u32;
    // Skip bytes 10-11 (the checksum field itself — treated as zero)
    sum += u16::from_be_bytes([header[12], header[13]]) as u32;
    sum += u16::from_be_bytes([header[14], header[15]]) as u32;
    sum += u16::from_be_bytes([header[16], header[17]]) as u32;
    sum += u16::from_be_bytes([header[18], header[19]]) as u32;

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// =============================================================================
// FFI interface
// =============================================================================

/// Compute Internet checksum over a buffer
#[no_mangle]
pub extern "C" fn zxyphor_rust_checksum_compute(
    data: *const u8,
    len: usize,
) -> u16 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    internet_checksum(slice)
}

/// Verify Internet checksum
#[no_mangle]
pub extern "C" fn zxyphor_rust_checksum_verify(
    data: *const u8,
    len: usize,
) -> i32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    if verify_checksum(slice) { 1 } else { 0 }
}

/// Incremental checksum update
#[no_mangle]
pub extern "C" fn zxyphor_rust_checksum_incremental(
    old_checksum: u16,
    old_value: u16,
    new_value: u16,
) -> u16 {
    incremental_update(old_checksum, old_value, new_value)
}

/// Compute TCP checksum including pseudo-header
#[no_mangle]
pub extern "C" fn zxyphor_rust_tcp_checksum(
    src_ip: u32,
    dst_ip: u32,
    tcp_data: *const u8,
    tcp_len: usize,
) -> u16 {
    if tcp_data.is_null() || tcp_len == 0 {
        return 0;
    }
    let src = Ipv4Address::from_u32(src_ip);
    let dst = Ipv4Address::from_u32(dst_ip);
    let slice = unsafe { core::slice::from_raw_parts(tcp_data, tcp_len) };
    tcp_checksum(&src, &dst, slice)
}

/// Compute UDP checksum including pseudo-header
#[no_mangle]
pub extern "C" fn zxyphor_rust_udp_checksum(
    src_ip: u32,
    dst_ip: u32,
    udp_data: *const u8,
    udp_len: usize,
) -> u16 {
    if udp_data.is_null() || udp_len == 0 {
        return 0;
    }
    let src = Ipv4Address::from_u32(src_ip);
    let dst = Ipv4Address::from_u32(dst_ip);
    let slice = unsafe { core::slice::from_raw_parts(udp_data, udp_len) };
    udp_checksum(&src, &dst, slice)
}
