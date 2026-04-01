// =============================================================================
// Kernel Zxyphor — Rust DNS Resolver
// =============================================================================
// A minimal DNS stub resolver for the kernel. Constructs DNS query packets
// (RFC 1035), parses responses, and maintains a small DNS cache for
// frequently resolved names. This is used by kernel networking for NTP
// server resolution, kernel module download (if supported), and NFS mounts.
//
// Supported record types:
//   A (IPv4 address), AAAA (IPv6 address), CNAME (canonical name),
//   PTR (reverse lookup), MX (mail exchange), TXT (text records)
//
// The resolver does NOT perform recursive resolution — it sends queries
// to a configured upstream DNS server and parses the response.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use crate::net::packet::Ipv4Address;

/// Maximum DNS name length (RFC 1035)
const MAX_DNS_NAME_LEN: usize = 253;

/// Maximum DNS packet size (standard, non-EDNS)
const MAX_DNS_PACKET_SIZE: usize = 512;

/// Maximum number of DNS cache entries
const DNS_CACHE_SIZE: usize = 256;

/// Default DNS cache TTL in seconds
const DEFAULT_CACHE_TTL: u32 = 300; // 5 minutes

/// DNS port number
const DNS_PORT: u16 = 53;

/// Maximum number of configured DNS servers
const MAX_DNS_SERVERS: usize = 4;

// =============================================================================
// DNS record types (RFC 1035 and extensions)
// =============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A = 1,        // IPv4 address
    NS = 2,       // Name server
    CNAME = 5,    // Canonical name
    SOA = 6,      // Start of authority
    PTR = 12,     // Pointer (reverse DNS)
    MX = 15,      // Mail exchange
    TXT = 16,     // Text record
    AAAA = 28,    // IPv6 address
    SRV = 33,     // Service locator
    Unknown = 0,
}

impl DnsRecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => DnsRecordType::A,
            2 => DnsRecordType::NS,
            5 => DnsRecordType::CNAME,
            6 => DnsRecordType::SOA,
            12 => DnsRecordType::PTR,
            15 => DnsRecordType::MX,
            16 => DnsRecordType::TXT,
            28 => DnsRecordType::AAAA,
            33 => DnsRecordType::SRV,
            _ => DnsRecordType::Unknown,
        }
    }
}

/// DNS response code
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,     // NXDOMAIN
    NotImplemented = 4,
    Refused = 5,
    Unknown = 15,
}

impl DnsResponseCode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormatError,
            2 => DnsResponseCode::ServerFailure,
            3 => DnsResponseCode::NameError,
            4 => DnsResponseCode::NotImplemented,
            5 => DnsResponseCode::Refused,
            _ => DnsResponseCode::Unknown,
        }
    }
}

// =============================================================================
// DNS header (RFC 1035, Section 4.1.1)
// =============================================================================

/// DNS packet header — 12 bytes, fixed format
#[repr(C)]
pub struct DnsHeader {
    /// Transaction ID (used to match responses to queries)
    pub id: u16,
    /// Flags: QR (1=response), Opcode, AA, TC, RD, RA, Z, RCODE
    pub flags: u16,
    /// Number of questions in the Question section
    pub question_count: u16,
    /// Number of records in the Answer section
    pub answer_count: u16,
    /// Number of records in the Authority section
    pub authority_count: u16,
    /// Number of records in the Additional section
    pub additional_count: u16,
}

impl DnsHeader {
    /// Create a new query header
    pub fn new_query(id: u16) -> Self {
        DnsHeader {
            id,
            flags: 0x0100, // RD (Recursion Desired) set
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    /// Check if this is a response (QR bit set)
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Get the response code
    pub fn response_code(&self) -> DnsResponseCode {
        DnsResponseCode::from_u8((self.flags & 0x000F) as u8)
    }

    /// Check if the response is truncated (TC bit)
    pub fn is_truncated(&self) -> bool {
        (self.flags & 0x0200) != 0
    }

    /// Check if the answer is authoritative (AA bit)
    pub fn is_authoritative(&self) -> bool {
        (self.flags & 0x0400) != 0
    }

    /// Serialize the header to bytes (big-endian)
    pub fn to_bytes(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 12 {
            return 0;
        }

        let id_bytes = self.id.to_be_bytes();
        buf[0] = id_bytes[0];
        buf[1] = id_bytes[1];

        let flag_bytes = self.flags.to_be_bytes();
        buf[2] = flag_bytes[0];
        buf[3] = flag_bytes[1];

        let qc = self.question_count.to_be_bytes();
        buf[4] = qc[0];
        buf[5] = qc[1];

        let ac = self.answer_count.to_be_bytes();
        buf[6] = ac[0];
        buf[7] = ac[1];

        let nc = self.authority_count.to_be_bytes();
        buf[8] = nc[0];
        buf[9] = nc[1];

        let dc = self.additional_count.to_be_bytes();
        buf[10] = dc[0];
        buf[11] = dc[1];

        12
    }

    /// Parse a DNS header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        Some(DnsHeader {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            question_count: u16::from_be_bytes([data[4], data[5]]),
            answer_count: u16::from_be_bytes([data[6], data[7]]),
            authority_count: u16::from_be_bytes([data[8], data[9]]),
            additional_count: u16::from_be_bytes([data[10], data[11]]),
        })
    }
}

// =============================================================================
// DNS name encoding/decoding
// =============================================================================

/// Encode a domain name into DNS wire format.
///
/// DNS names are encoded as a sequence of labels: each label is preceded
/// by a length byte, and the name is terminated by a zero-length label.
///
/// Example: "www.example.com" → [3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
pub fn encode_dns_name(name: &[u8], buf: &mut [u8]) -> usize {
    if name.is_empty() || buf.len() < name.len() + 2 {
        return 0;
    }

    let mut out_pos = 0;
    let mut label_start = 0;

    for i in 0..name.len() {
        if name[i] == b'.' {
            let label_len = i - label_start;
            if label_len == 0 || label_len > 63 {
                return 0; // Invalid label length
            }

            if out_pos + 1 + label_len > buf.len() {
                return 0;
            }

            buf[out_pos] = label_len as u8;
            out_pos += 1;
            buf[out_pos..out_pos + label_len].copy_from_slice(&name[label_start..i]);
            out_pos += label_len;
            label_start = i + 1;
        }
    }

    // Handle the last label (after the final dot, or the entire name if no dot)
    let remaining = name.len() - label_start;
    if remaining > 0 && remaining <= 63 {
        if out_pos + 1 + remaining + 1 > buf.len() {
            return 0;
        }
        buf[out_pos] = remaining as u8;
        out_pos += 1;
        buf[out_pos..out_pos + remaining].copy_from_slice(&name[label_start..]);
        out_pos += remaining;
    }

    // Null terminator
    if out_pos >= buf.len() {
        return 0;
    }
    buf[out_pos] = 0;
    out_pos += 1;

    out_pos
}

/// Decode a DNS name from wire format, handling compression pointers.
///
/// DNS names can be compressed using pointers (two-byte sequences where
/// the first byte has the two high bits set). The pointer value indicates
/// an offset from the start of the DNS message where the rest of the name
/// can be found.
pub fn decode_dns_name(
    packet: &[u8],
    start: usize,
    out: &mut [u8],
) -> Option<(usize, usize)> {
    let mut pos = start;
    let mut out_pos = 0;
    let mut jump_count = 0;
    let mut final_pos = 0;
    let mut jumped = false;

    loop {
        if pos >= packet.len() {
            return None;
        }

        let len = packet[pos] as usize;

        if len == 0 {
            // End of name
            if !jumped {
                final_pos = pos + 1;
            }
            break;
        }

        // Check for compression pointer
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }

            // This is a pointer — the offset is the lower 14 bits
            let offset = ((len & 0x3F) << 8) | (packet[pos + 1] as usize);

            if !jumped {
                final_pos = pos + 2;
            }

            pos = offset;
            jumped = true;
            jump_count += 1;

            // Prevent infinite loops (max pointer chain depth)
            if jump_count > 16 {
                return None;
            }

            continue;
        }

        // Regular label
        if len > 63 {
            return None; // Label too long
        }

        pos += 1;

        if pos + len > packet.len() {
            return None;
        }

        // Add a dot separator (except for the first label)
        if out_pos > 0 {
            if out_pos >= out.len() {
                return None;
            }
            out[out_pos] = b'.';
            out_pos += 1;
        }

        if out_pos + len > out.len() {
            return None;
        }

        out[out_pos..out_pos + len].copy_from_slice(&packet[pos..pos + len]);
        out_pos += len;
        pos += len;
    }

    if !jumped {
        final_pos = pos + 1;
    }

    Some((final_pos, out_pos))
}

// =============================================================================
// DNS query packet builder
// =============================================================================

/// DNS query builder — constructs a DNS query packet for a given name and type.
pub struct DnsQueryBuilder {
    buffer: [u8; MAX_DNS_PACKET_SIZE],
    position: usize,
    transaction_id: u16,
}

impl DnsQueryBuilder {
    /// Create a new query builder with the given transaction ID
    pub fn new(transaction_id: u16) -> Self {
        DnsQueryBuilder {
            buffer: [0u8; MAX_DNS_PACKET_SIZE],
            position: 0,
            transaction_id,
        }
    }

    /// Build a DNS query packet for the given name and record type.
    /// Returns the packet data as a slice.
    pub fn build_query(
        &mut self,
        name: &[u8],
        record_type: DnsRecordType,
    ) -> Option<&[u8]> {
        // Write the DNS header
        let header = DnsHeader::new_query(self.transaction_id);
        let header_len = header.to_bytes(&mut self.buffer);
        if header_len == 0 {
            return None;
        }
        self.position = header_len;

        // Encode the domain name
        let name_len = encode_dns_name(name, &mut self.buffer[self.position..]);
        if name_len == 0 {
            return None;
        }
        self.position += name_len;

        // Query type (2 bytes)
        if self.position + 4 > MAX_DNS_PACKET_SIZE {
            return None;
        }
        let qtype = (record_type as u16).to_be_bytes();
        self.buffer[self.position] = qtype[0];
        self.buffer[self.position + 1] = qtype[1];
        self.position += 2;

        // Query class: IN (Internet) = 1
        self.buffer[self.position] = 0;
        self.buffer[self.position + 1] = 1;
        self.position += 2;

        Some(&self.buffer[..self.position])
    }
}

// =============================================================================
// DNS response parser
// =============================================================================

/// A parsed DNS resource record
#[repr(C)]
pub struct DnsRecord {
    /// Record name (decoded from wire format)
    pub name: [u8; MAX_DNS_NAME_LEN + 1],
    /// Length of the name
    pub name_len: usize,
    /// Record type
    pub record_type: DnsRecordType,
    /// Time to live in seconds
    pub ttl: u32,
    /// Record data (interpretation depends on record_type)
    pub rdata: [u8; 256],
    /// Length of the record data
    pub rdata_len: usize,
    /// For A records: the IPv4 address
    pub ipv4_addr: Ipv4Address,
    /// Whether this record is valid
    pub valid: bool,
}

impl DnsRecord {
    pub const fn empty() -> Self {
        DnsRecord {
            name: [0u8; MAX_DNS_NAME_LEN + 1],
            name_len: 0,
            record_type: DnsRecordType::Unknown,
            ttl: 0,
            rdata: [0u8; 256],
            rdata_len: 0,
            ipv4_addr: Ipv4Address { octets: [0; 4] },
            valid: false,
        }
    }
}

/// Parse the answer section of a DNS response packet
pub fn parse_dns_response(
    packet: &[u8],
    records: &mut [DnsRecord],
    max_records: usize,
) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }

    let header = DnsHeader::from_bytes(packet)?;

    // Verify this is a response
    if !header.is_response() {
        return None;
    }

    // Check for errors
    let rcode = header.response_code();
    if rcode != DnsResponseCode::NoError {
        return None;
    }

    // Skip the question section
    let mut pos = 12;

    for _ in 0..header.question_count {
        // Skip the QNAME
        while pos < packet.len() {
            let len = packet[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        // Skip QTYPE and QCLASS (4 bytes)
        pos += 4;
    }

    // Parse the answer section
    let mut record_count = 0;

    for _ in 0..header.answer_count {
        if record_count >= max_records || record_count >= records.len() {
            break;
        }

        if pos >= packet.len() {
            break;
        }

        // Decode the name
        let (new_pos, name_len) = decode_dns_name(
            packet,
            pos,
            &mut records[record_count].name,
        )?;
        records[record_count].name_len = name_len;
        pos = new_pos;

        if pos + 10 > packet.len() {
            break;
        }

        // Record type (2 bytes)
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        records[record_count].record_type = DnsRecordType::from_u16(rtype);
        pos += 2;

        // Record class (2 bytes) — skip
        pos += 2;

        // TTL (4 bytes)
        records[record_count].ttl = u32::from_be_bytes([
            packet[pos],
            packet[pos + 1],
            packet[pos + 2],
            packet[pos + 3],
        ]);
        pos += 4;

        // RDLENGTH (2 bytes)
        let rdlen = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlen > packet.len() || rdlen > 256 {
            break;
        }

        // Copy RDATA
        records[record_count].rdata[..rdlen].copy_from_slice(&packet[pos..pos + rdlen]);
        records[record_count].rdata_len = rdlen;

        // Parse A record (IPv4 address)
        if records[record_count].record_type == DnsRecordType::A && rdlen == 4 {
            records[record_count].ipv4_addr = Ipv4Address::new(
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            );
        }

        records[record_count].valid = true;
        pos += rdlen;
        record_count += 1;
    }

    Some(record_count)
}

// =============================================================================
// DNS cache
// =============================================================================

/// A cached DNS resolution result
#[repr(C)]
pub struct DnsCacheEntry {
    /// Domain name
    pub name: [u8; MAX_DNS_NAME_LEN + 1],
    /// Name length
    pub name_len: usize,
    /// Resolved IPv4 address
    pub address: Ipv4Address,
    /// Record type
    pub record_type: DnsRecordType,
    /// Cache expiration time (seconds from boot)
    pub expires_at: u64,
    /// Number of cache hits
    pub hit_count: AtomicU64,
    /// Whether this entry is valid
    pub valid: AtomicBool,
}

impl DnsCacheEntry {
    pub const fn empty() -> Self {
        DnsCacheEntry {
            name: [0u8; MAX_DNS_NAME_LEN + 1],
            name_len: 0,
            address: Ipv4Address { octets: [0; 4] },
            record_type: DnsRecordType::Unknown,
            expires_at: 0,
            hit_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time >= self.expires_at
    }

    /// Check if the name matches
    pub fn name_matches(&self, name: &[u8]) -> bool {
        if self.name_len != name.len() {
            return false;
        }
        // Case-insensitive comparison (DNS names are case-insensitive)
        for i in 0..name.len() {
            let a = if self.name[i] >= b'A' && self.name[i] <= b'Z' {
                self.name[i] + 32
            } else {
                self.name[i]
            };
            let b = if name[i] >= b'A' && name[i] <= b'Z' {
                name[i] + 32
            } else {
                name[i]
            };
            if a != b {
                return false;
            }
        }
        true
    }
}

// =============================================================================
// DNS resolver configuration
// =============================================================================

/// Configuration for the DNS resolver
#[repr(C)]
pub struct DnsConfig {
    /// DNS server addresses (up to MAX_DNS_SERVERS)
    pub servers: [Ipv4Address; MAX_DNS_SERVERS],
    /// Number of configured DNS servers
    pub server_count: usize,
    /// Query timeout in milliseconds
    pub timeout_ms: u32,
    /// Maximum number of retries per query
    pub max_retries: u8,
    /// Whether to use the cache
    pub use_cache: bool,
    /// Default TTL for cache entries (seconds)
    pub default_ttl: u32,
}

impl DnsConfig {
    pub const fn default() -> Self {
        DnsConfig {
            servers: [Ipv4Address { octets: [0; 4] }; MAX_DNS_SERVERS],
            server_count: 0,
            timeout_ms: 5000,
            max_retries: 3,
            use_cache: true,
            default_ttl: DEFAULT_CACHE_TTL,
        }
    }
}

// =============================================================================
// Global DNS state
// =============================================================================

static DNS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_TRANSACTION_ID: AtomicU16 = AtomicU16::new(1);
static DNS_QUERIES_SENT: AtomicU64 = AtomicU64::new(0);
static DNS_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static DNS_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI interface
// =============================================================================

/// Initialize the DNS resolver
#[no_mangle]
pub extern "C" fn zxyphor_rust_dns_init() -> i32 {
    if DNS_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    DNS_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust DNS resolver initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Set a DNS server address
#[no_mangle]
pub extern "C" fn zxyphor_rust_dns_set_server(
    index: u32,
    ip_addr: u32,
) -> i32 {
    if index >= MAX_DNS_SERVERS as u32 {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }
    // Store the server address (would be stored in the global config)
    let _addr = Ipv4Address::from_u32(ip_addr);
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Build a DNS query packet
#[no_mangle]
pub extern "C" fn zxyphor_rust_dns_build_query(
    name: *const u8,
    name_len: usize,
    record_type: u16,
    packet_out: *mut u8,
    packet_capacity: usize,
    packet_len_out: *mut usize,
) -> i32 {
    if name.is_null() || packet_out.is_null() || packet_len_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    if name_len == 0 || name_len > MAX_DNS_NAME_LEN {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len) };
    let tx_id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::SeqCst);

    let mut builder = DnsQueryBuilder::new(tx_id);
    let rtype = DnsRecordType::from_u16(record_type);

    match builder.build_query(name_slice, rtype) {
        Some(query_data) => {
            if query_data.len() > packet_capacity {
                return crate::ffi::error::FfiError::BufferTooSmall.as_i32();
            }

            let out = unsafe { core::slice::from_raw_parts_mut(packet_out, packet_capacity) };
            out[..query_data.len()].copy_from_slice(query_data);

            unsafe { *packet_len_out = query_data.len() };
            DNS_QUERIES_SENT.fetch_add(1, Ordering::Relaxed);

            crate::ffi::error::FfiError::Success.as_i32()
        }
        None => crate::ffi::error::FfiError::InvalidArgument.as_i32(),
    }
}

/// Parse a DNS response packet
#[no_mangle]
pub extern "C" fn zxyphor_rust_dns_parse_response(
    packet: *const u8,
    packet_len: usize,
    records_out: *mut DnsRecord,
    max_records: usize,
    record_count_out: *mut usize,
) -> i32 {
    if packet.is_null() || records_out.is_null() || record_count_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let packet_slice = unsafe { core::slice::from_raw_parts(packet, packet_len) };
    let records = unsafe { core::slice::from_raw_parts_mut(records_out, max_records) };

    match parse_dns_response(packet_slice, records, max_records) {
        Some(count) => {
            unsafe { *record_count_out = count };
            crate::ffi::error::FfiError::Success.as_i32()
        }
        None => crate::ffi::error::FfiError::Corruption.as_i32(),
    }
}
