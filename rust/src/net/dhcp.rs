// =============================================================================
// Kernel Zxyphor — Rust DHCP Client Implementation
// =============================================================================
// A DHCP client for automatic network interface configuration. Implements the
// DHCP protocol state machine per RFC 2131, including DISCOVER, OFFER, REQUEST,
// and ACK message exchange. Supports lease renewal and rebinding.
//
// DHCP state machine:
//   INIT → SELECTING → REQUESTING → BOUND → RENEWING → REBINDING → INIT
//
// This module constructs DHCP packets, parses server responses, and notifies
// the Zig kernel of the assigned IP configuration through the FFI bridge.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use crate::net::packet::Ipv4Address;

/// DHCP server port
const DHCP_SERVER_PORT: u16 = 67;

/// DHCP client port
const DHCP_CLIENT_PORT: u16 = 68;

/// Maximum DHCP message size
const MAX_DHCP_SIZE: usize = 576;

/// DHCP magic cookie (RFC 2131)
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// =============================================================================
// DHCP message types (RFC 2131, Section 9.6)
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    Unknown = 0,
}

impl DhcpMessageType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            8 => DhcpMessageType::Inform,
            _ => DhcpMessageType::Unknown,
        }
    }
}

// =============================================================================
// DHCP client state machine states
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Initial state, no lease
    Init = 0,
    /// DISCOVER sent, waiting for OFFERs
    Selecting = 1,
    /// REQUEST sent, waiting for ACK
    Requesting = 2,
    /// Lease obtained, network configured
    Bound = 3,
    /// Lease renewal in progress (T1 expired)
    Renewing = 4,
    /// Lease rebinding (T2 expired, trying any server)
    Rebinding = 5,
    /// Lease expired, returning to INIT
    InitReboot = 6,
    /// Rebooting with previous lease
    Rebooting = 7,
}

impl DhcpState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => DhcpState::Init,
            1 => DhcpState::Selecting,
            2 => DhcpState::Requesting,
            3 => DhcpState::Bound,
            4 => DhcpState::Renewing,
            5 => DhcpState::Rebinding,
            6 => DhcpState::InitReboot,
            7 => DhcpState::Rebooting,
            _ => DhcpState::Init,
        }
    }
}

// =============================================================================
// DHCP option codes (RFC 2132)
// =============================================================================

/// Common DHCP option codes
pub struct DhcpOption;

impl DhcpOption {
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS_SERVER: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const BROADCAST_ADDR: u8 = 28;
    pub const NTP_SERVER: u8 = 42;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_REQUEST: u8 = 55;
    pub const RENEWAL_TIME: u8 = 58; // T1
    pub const REBINDING_TIME: u8 = 59; // T2
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
    pub const PAD: u8 = 0;
}

// =============================================================================
// DHCP packet structure (RFC 2131, Section 2)
// =============================================================================

/// DHCP packet — the fixed header portion (240 bytes before options)
#[repr(C)]
pub struct DhcpPacket {
    /// Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY
    pub op: u8,
    /// Hardware address type: 1 = Ethernet
    pub htype: u8,
    /// Hardware address length: 6 for Ethernet
    pub hlen: u8,
    /// Hops (clients set to 0, incremented by relay agents)
    pub hops: u8,
    /// Transaction ID (random, used to match responses)
    pub xid: u32,
    /// Seconds elapsed since start of DHCP process
    pub secs: u16,
    /// Flags: bit 15 = broadcast flag
    pub flags: u16,
    /// Client IP address (only if client has a valid IP)
    pub ciaddr: Ipv4Address,
    /// 'Your' IP address (server assigns this in OFFER/ACK)
    pub yiaddr: Ipv4Address,
    /// Server IP address (next server in bootstrap)
    pub siaddr: Ipv4Address,
    /// Relay agent IP address
    pub giaddr: Ipv4Address,
    /// Client hardware address (MAC)
    pub chaddr: [u8; 16],
    /// Server host name (optional, zero-terminated)
    pub sname: [u8; 64],
    /// Boot file name (optional, zero-terminated)
    pub file: [u8; 128],
    /// Options (variable length, starts with magic cookie)
    pub options: [u8; 312],
    /// Actual length of options data
    pub options_len: usize,
}

impl DhcpPacket {
    pub const fn empty() -> Self {
        DhcpPacket {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Address { octets: [0; 4] },
            yiaddr: Ipv4Address { octets: [0; 4] },
            siaddr: Ipv4Address { octets: [0; 4] },
            giaddr: Ipv4Address { octets: [0; 4] },
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: [0u8; 312],
            options_len: 0,
        }
    }

    /// Create a DHCP DISCOVER packet
    pub fn new_discover(xid: u32, mac: &[u8; 6]) -> Self {
        let mut pkt = DhcpPacket::empty();
        pkt.op = 1; // BOOTREQUEST
        pkt.htype = 1; // Ethernet
        pkt.hlen = 6;
        pkt.xid = xid;
        pkt.flags = 0x8000; // Broadcast flag
        pkt.chaddr[..6].copy_from_slice(mac);

        // Build options
        let mut opt_pos = 0;

        // Magic cookie
        pkt.options[opt_pos..opt_pos + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        opt_pos += 4;

        // Message type: DISCOVER
        pkt.options[opt_pos] = DhcpOption::MESSAGE_TYPE;
        pkt.options[opt_pos + 1] = 1;
        pkt.options[opt_pos + 2] = DhcpMessageType::Discover as u8;
        opt_pos += 3;

        // Parameter request list
        pkt.options[opt_pos] = DhcpOption::PARAM_REQUEST;
        pkt.options[opt_pos + 1] = 7; // 7 requested options
        pkt.options[opt_pos + 2] = DhcpOption::SUBNET_MASK;
        pkt.options[opt_pos + 3] = DhcpOption::ROUTER;
        pkt.options[opt_pos + 4] = DhcpOption::DNS_SERVER;
        pkt.options[opt_pos + 5] = DhcpOption::DOMAIN_NAME;
        pkt.options[opt_pos + 6] = DhcpOption::BROADCAST_ADDR;
        pkt.options[opt_pos + 7] = DhcpOption::NTP_SERVER;
        pkt.options[opt_pos + 8] = DhcpOption::LEASE_TIME;
        opt_pos += 9;

        // Client identifier (MAC address)
        pkt.options[opt_pos] = DhcpOption::CLIENT_ID;
        pkt.options[opt_pos + 1] = 7;
        pkt.options[opt_pos + 2] = 1; // Hardware type: Ethernet
        pkt.options[opt_pos + 3..opt_pos + 9].copy_from_slice(mac);
        opt_pos += 9;

        // End option
        pkt.options[opt_pos] = DhcpOption::END;
        opt_pos += 1;

        pkt.options_len = opt_pos;
        pkt
    }

    /// Create a DHCP REQUEST packet
    pub fn new_request(
        xid: u32,
        mac: &[u8; 6],
        requested_ip: Ipv4Address,
        server_ip: Ipv4Address,
    ) -> Self {
        let mut pkt = DhcpPacket::empty();
        pkt.op = 1;
        pkt.htype = 1;
        pkt.hlen = 6;
        pkt.xid = xid;
        pkt.flags = 0x8000;
        pkt.chaddr[..6].copy_from_slice(mac);

        let mut opt_pos = 0;

        // Magic cookie
        pkt.options[opt_pos..opt_pos + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        opt_pos += 4;

        // Message type: REQUEST
        pkt.options[opt_pos] = DhcpOption::MESSAGE_TYPE;
        pkt.options[opt_pos + 1] = 1;
        pkt.options[opt_pos + 2] = DhcpMessageType::Request as u8;
        opt_pos += 3;

        // Requested IP address
        pkt.options[opt_pos] = DhcpOption::REQUESTED_IP;
        pkt.options[opt_pos + 1] = 4;
        pkt.options[opt_pos + 2..opt_pos + 6].copy_from_slice(&requested_ip.octets);
        opt_pos += 6;

        // Server identifier
        pkt.options[opt_pos] = DhcpOption::SERVER_ID;
        pkt.options[opt_pos + 1] = 4;
        pkt.options[opt_pos + 2..opt_pos + 6].copy_from_slice(&server_ip.octets);
        opt_pos += 6;

        // End option
        pkt.options[opt_pos] = DhcpOption::END;
        opt_pos += 1;

        pkt.options_len = opt_pos;
        pkt
    }

    /// Create a DHCP RELEASE packet
    pub fn new_release(
        xid: u32,
        mac: &[u8; 6],
        client_ip: Ipv4Address,
        server_ip: Ipv4Address,
    ) -> Self {
        let mut pkt = DhcpPacket::empty();
        pkt.op = 1;
        pkt.htype = 1;
        pkt.hlen = 6;
        pkt.xid = xid;
        pkt.ciaddr = client_ip;
        pkt.chaddr[..6].copy_from_slice(mac);

        let mut opt_pos = 0;

        pkt.options[opt_pos..opt_pos + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        opt_pos += 4;

        pkt.options[opt_pos] = DhcpOption::MESSAGE_TYPE;
        pkt.options[opt_pos + 1] = 1;
        pkt.options[opt_pos + 2] = DhcpMessageType::Release as u8;
        opt_pos += 3;

        pkt.options[opt_pos] = DhcpOption::SERVER_ID;
        pkt.options[opt_pos + 1] = 4;
        pkt.options[opt_pos + 2..opt_pos + 6].copy_from_slice(&server_ip.octets);
        opt_pos += 6;

        pkt.options[opt_pos] = DhcpOption::END;
        opt_pos += 1;

        pkt.options_len = opt_pos;
        pkt
    }

    /// Serialize a DHCP packet to bytes. Returns the number of bytes written.
    pub fn to_bytes(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 240 + self.options_len {
            return 0;
        }

        buf[0] = self.op;
        buf[1] = self.htype;
        buf[2] = self.hlen;
        buf[3] = self.hops;

        let xid_bytes = self.xid.to_be_bytes();
        buf[4..8].copy_from_slice(&xid_bytes);

        let secs_bytes = self.secs.to_be_bytes();
        buf[8..10].copy_from_slice(&secs_bytes);

        let flags_bytes = self.flags.to_be_bytes();
        buf[10..12].copy_from_slice(&flags_bytes);

        buf[12..16].copy_from_slice(&self.ciaddr.octets);
        buf[16..20].copy_from_slice(&self.yiaddr.octets);
        buf[20..24].copy_from_slice(&self.siaddr.octets);
        buf[24..28].copy_from_slice(&self.giaddr.octets);

        buf[28..44].copy_from_slice(&self.chaddr);
        buf[44..108].copy_from_slice(&self.sname);
        buf[108..236].copy_from_slice(&self.file);

        // Options start at byte 236 in the UDP payload
        let opt_start = 236;
        buf[opt_start..opt_start + self.options_len]
            .copy_from_slice(&self.options[..self.options_len]);

        opt_start + self.options_len
    }

    /// Parse a DHCP packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 240 {
            return None;
        }

        let mut pkt = DhcpPacket::empty();

        pkt.op = data[0];
        pkt.htype = data[1];
        pkt.hlen = data[2];
        pkt.hops = data[3];

        pkt.xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        pkt.secs = u16::from_be_bytes([data[8], data[9]]);
        pkt.flags = u16::from_be_bytes([data[10], data[11]]);

        pkt.ciaddr.octets.copy_from_slice(&data[12..16]);
        pkt.yiaddr.octets.copy_from_slice(&data[16..20]);
        pkt.siaddr.octets.copy_from_slice(&data[20..24]);
        pkt.giaddr.octets.copy_from_slice(&data[24..28]);

        pkt.chaddr.copy_from_slice(&data[28..44]);
        pkt.sname.copy_from_slice(&data[44..108]);
        pkt.file.copy_from_slice(&data[108..236]);

        // Parse options
        let opt_data = &data[236..];
        let opt_len = core::cmp::min(opt_data.len(), 312);
        pkt.options[..opt_len].copy_from_slice(&opt_data[..opt_len]);
        pkt.options_len = opt_len;

        // Verify magic cookie
        if opt_len >= 4 && pkt.options[..4] != DHCP_MAGIC_COOKIE {
            return None;
        }

        Some(pkt)
    }

    /// Extract the DHCP message type from options
    pub fn message_type(&self) -> DhcpMessageType {
        self.find_option(DhcpOption::MESSAGE_TYPE)
            .map(|data| {
                if !data.is_empty() {
                    DhcpMessageType::from_u8(data[0])
                } else {
                    DhcpMessageType::Unknown
                }
            })
            .unwrap_or(DhcpMessageType::Unknown)
    }

    /// Find an option by code and return its data
    pub fn find_option(&self, code: u8) -> Option<&[u8]> {
        if self.options_len < 4 {
            return None;
        }

        let mut pos = 4; // Skip magic cookie

        while pos < self.options_len {
            let opt_code = self.options[pos];

            if opt_code == DhcpOption::END {
                break;
            }

            if opt_code == DhcpOption::PAD {
                pos += 1;
                continue;
            }

            if pos + 1 >= self.options_len {
                break;
            }

            let opt_len = self.options[pos + 1] as usize;

            if pos + 2 + opt_len > self.options_len {
                break;
            }

            if opt_code == code {
                return Some(&self.options[pos + 2..pos + 2 + opt_len]);
            }

            pos += 2 + opt_len;
        }

        None
    }

    /// Extract the subnet mask from options
    pub fn subnet_mask(&self) -> Option<Ipv4Address> {
        self.find_option(DhcpOption::SUBNET_MASK)
            .filter(|d| d.len() == 4)
            .map(|d| Ipv4Address::new(d[0], d[1], d[2], d[3]))
    }

    /// Extract the default gateway from options
    pub fn gateway(&self) -> Option<Ipv4Address> {
        self.find_option(DhcpOption::ROUTER)
            .filter(|d| d.len() >= 4)
            .map(|d| Ipv4Address::new(d[0], d[1], d[2], d[3]))
    }

    /// Extract the DNS server from options
    pub fn dns_server(&self) -> Option<Ipv4Address> {
        self.find_option(DhcpOption::DNS_SERVER)
            .filter(|d| d.len() >= 4)
            .map(|d| Ipv4Address::new(d[0], d[1], d[2], d[3]))
    }

    /// Extract the lease time in seconds
    pub fn lease_time(&self) -> Option<u32> {
        self.find_option(DhcpOption::LEASE_TIME)
            .filter(|d| d.len() == 4)
            .map(|d| u32::from_be_bytes([d[0], d[1], d[2], d[3]]))
    }

    /// Extract the server identifier
    pub fn server_identifier(&self) -> Option<Ipv4Address> {
        self.find_option(DhcpOption::SERVER_ID)
            .filter(|d| d.len() == 4)
            .map(|d| Ipv4Address::new(d[0], d[1], d[2], d[3]))
    }
}

// =============================================================================
// DHCP lease information
// =============================================================================

/// Information about the current DHCP lease
#[repr(C)]
pub struct DhcpLease {
    /// Assigned IP address
    pub ip_address: Ipv4Address,
    /// Subnet mask
    pub subnet_mask: Ipv4Address,
    /// Default gateway
    pub gateway: Ipv4Address,
    /// DNS server
    pub dns_server: Ipv4Address,
    /// DHCP server that granted the lease
    pub server_ip: Ipv4Address,
    /// Lease duration in seconds
    pub lease_time: u32,
    /// T1 (renewal time) in seconds from lease start
    pub renewal_time: u32,
    /// T2 (rebinding time) in seconds from lease start
    pub rebinding_time: u32,
    /// Time when the lease was obtained (seconds from boot)
    pub lease_start: u64,
    /// Current DHCP state
    pub state: DhcpState,
    /// Whether a valid lease is held
    pub valid: bool,
}

impl DhcpLease {
    pub const fn empty() -> Self {
        DhcpLease {
            ip_address: Ipv4Address { octets: [0; 4] },
            subnet_mask: Ipv4Address { octets: [0; 4] },
            gateway: Ipv4Address { octets: [0; 4] },
            dns_server: Ipv4Address { octets: [0; 4] },
            server_ip: Ipv4Address { octets: [0; 4] },
            lease_time: 0,
            renewal_time: 0,
            rebinding_time: 0,
            lease_start: 0,
            state: DhcpState::Init,
            valid: false,
        }
    }

    /// Check if the lease has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        if !self.valid {
            return true;
        }
        current_time >= self.lease_start + self.lease_time as u64
    }

    /// Check if it's time to renew (T1 expired)
    pub fn needs_renewal(&self, current_time: u64) -> bool {
        if !self.valid {
            return false;
        }
        current_time >= self.lease_start + self.renewal_time as u64
    }

    /// Check if it's time to rebind (T2 expired)
    pub fn needs_rebinding(&self, current_time: u64) -> bool {
        if !self.valid {
            return false;
        }
        current_time >= self.lease_start + self.rebinding_time as u64
    }
}

// =============================================================================
// Global DHCP state
// =============================================================================

static DHCP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static DHCP_TRANSACTION_ID: AtomicU32 = AtomicU32::new(0);

// =============================================================================
// FFI interface
// =============================================================================

/// Initialize the DHCP client
#[no_mangle]
pub extern "C" fn zxyphor_rust_dhcp_init() -> i32 {
    if DHCP_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    DHCP_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust DHCP client initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Build a DHCP DISCOVER packet
#[no_mangle]
pub extern "C" fn zxyphor_rust_dhcp_discover(
    mac: *const u8,
    packet_out: *mut u8,
    packet_capacity: usize,
    packet_len_out: *mut usize,
) -> i32 {
    if mac.is_null() || packet_out.is_null() || packet_len_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let mac_bytes: [u8; 6] = unsafe {
        let slice = core::slice::from_raw_parts(mac, 6);
        [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]
    };

    let xid = DHCP_TRANSACTION_ID.fetch_add(1, Ordering::SeqCst);
    let pkt = DhcpPacket::new_discover(xid, &mac_bytes);

    let out = unsafe { core::slice::from_raw_parts_mut(packet_out, packet_capacity) };
    let written = pkt.to_bytes(out);

    if written == 0 {
        return crate::ffi::error::FfiError::BufferTooSmall.as_i32();
    }

    unsafe { *packet_len_out = written };

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Parse a DHCP response and extract lease information
#[no_mangle]
pub extern "C" fn zxyphor_rust_dhcp_parse_response(
    data: *const u8,
    data_len: usize,
    lease_out: *mut DhcpLease,
) -> i32 {
    if data.is_null() || lease_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let slice = unsafe { core::slice::from_raw_parts(data, data_len) };

    match DhcpPacket::from_bytes(slice) {
        Some(pkt) => {
            let msg_type = pkt.message_type();

            let mut lease = DhcpLease::empty();

            match msg_type {
                DhcpMessageType::Offer | DhcpMessageType::Ack => {
                    lease.ip_address = pkt.yiaddr;

                    if let Some(mask) = pkt.subnet_mask() {
                        lease.subnet_mask = mask;
                    }
                    if let Some(gw) = pkt.gateway() {
                        lease.gateway = gw;
                    }
                    if let Some(dns) = pkt.dns_server() {
                        lease.dns_server = dns;
                    }
                    if let Some(server) = pkt.server_identifier() {
                        lease.server_ip = server;
                    }
                    if let Some(lt) = pkt.lease_time() {
                        lease.lease_time = lt;
                        // Default T1 = 50% of lease time, T2 = 87.5%
                        lease.renewal_time = lt / 2;
                        lease.rebinding_time = (lt * 7) / 8;
                    }

                    if msg_type == DhcpMessageType::Ack {
                        lease.state = DhcpState::Bound;
                        lease.valid = true;
                    } else {
                        lease.state = DhcpState::Selecting;
                    }

                    unsafe { core::ptr::write(lease_out, lease) };
                    crate::ffi::error::FfiError::Success.as_i32()
                }
                DhcpMessageType::Nak => {
                    crate::ffi::error::FfiError::PermissionDenied.as_i32()
                }
                _ => {
                    crate::ffi::error::FfiError::NotSupported.as_i32()
                }
            }
        }
        None => crate::ffi::error::FfiError::Corruption.as_i32(),
    }
}
