//! Kernel Zxyphor — Advanced Network Protocol Stack
//!
//! Full TCP/IP stack implementation with:
//! - IPv4/IPv6 dual-stack
//! - TCP congestion control (Cubic, BBR, Reno)
//! - Socket buffer management
//! - Network device abstraction
//! - Packet queuing disciplines
//! - Network namespace support
//! - Connection tracking
//! - NAT support
//! - Quality of Service (QoS)
//! - Multicast/broadcast
//! - VLAN support
//! - Checksum offloading

#![no_std]
#![allow(dead_code)]

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Network Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum NetError {
    PermissionDenied = -1,
    NoBuffer = -2,
    NoMemory = -3,
    InvalidAddress = -4,
    ConnectionRefused = -5,
    ConnectionReset = -6,
    ConnectionAborted = -7,
    NotConnected = -8,
    AlreadyConnected = -9,
    TimedOut = -10,
    NetworkUnreachable = -11,
    HostUnreachable = -12,
    AddressInUse = -13,
    AddressNotAvailable = -14,
    NetworkDown = -15,
    MessageTooLong = -16,
    ProtocolNotSupported = -17,
    SocketTypeNotSupported = -18,
    OperationNotSupported = -19,
    WouldBlock = -20,
    InProgress = -21,
    Interrupted = -22,
    InvalidArgument = -23,
    BadFileDescriptor = -24,
    Shutdown = -25,
}

pub type NetResult<T> = Result<T, NetError>;

// ============================================================================
// Network Address Types
// ============================================================================

/// IPv4 address (network byte order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Ipv4Addr {
    pub octets: [u8; 4],
}

impl Ipv4Addr {
    pub const UNSPECIFIED: Self = Ipv4Addr {
        octets: [0, 0, 0, 0],
    };
    pub const LOCALHOST: Self = Ipv4Addr {
        octets: [127, 0, 0, 1],
    };
    pub const BROADCAST: Self = Ipv4Addr {
        octets: [255, 255, 255, 255],
    };

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr {
            octets: [a, b, c, d],
        }
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.octets)
    }

    pub fn from_u32(addr: u32) -> Self {
        Ipv4Addr {
            octets: addr.to_be_bytes(),
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.octets[0] == 127
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    pub fn is_multicast(&self) -> bool {
        self.octets[0] >= 224 && self.octets[0] <= 239
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    pub fn is_private(&self) -> bool {
        match self.octets[0] {
            10 => true,
            172 => self.octets[1] >= 16 && self.octets[1] <= 31,
            192 => self.octets[1] == 168,
            _ => false,
        }
    }

    pub fn is_link_local(&self) -> bool {
        self.octets[0] == 169 && self.octets[1] == 254
    }
}

/// IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Ipv6Addr {
    pub segments: [u16; 8],
}

impl Ipv6Addr {
    pub const UNSPECIFIED: Self = Ipv6Addr { segments: [0; 8] };
    pub const LOCALHOST: Self = Ipv6Addr {
        segments: [0, 0, 0, 0, 0, 0, 0, 1],
    };

    pub fn is_loopback(&self) -> bool {
        *self == Self::LOCALHOST
    }

    pub fn is_multicast(&self) -> bool {
        self.segments[0] & 0xFF00 == 0xFF00
    }

    pub fn is_link_local(&self) -> bool {
        self.segments[0] & 0xFFC0 == 0xFE80
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    /// Check if this is an IPv4-mapped IPv6 address (::ffff:x.x.x.x).
    pub fn is_ipv4_mapped(&self) -> bool {
        self.segments[0] == 0
            && self.segments[1] == 0
            && self.segments[2] == 0
            && self.segments[3] == 0
            && self.segments[4] == 0
            && self.segments[5] == 0xFFFF
    }

    /// Extract the mapped IPv4 address.
    pub fn to_ipv4_mapped(&self) -> Option<Ipv4Addr> {
        if self.is_ipv4_mapped() {
            let hi = self.segments[6].to_be_bytes();
            let lo = self.segments[7].to_be_bytes();
            Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]))
        } else {
            None
        }
    }
}

/// MAC (Ethernet) address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct MacAddr {
    pub octets: [u8; 6],
}

impl MacAddr {
    pub const ZERO: Self = MacAddr { octets: [0; 6] };
    pub const BROADCAST: Self = MacAddr {
        octets: [0xFF; 6],
    };

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    pub fn is_multicast(&self) -> bool {
        self.octets[0] & 0x01 != 0
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_multicast() && !self.is_broadcast()
    }
}

/// Socket address for IPv4.
#[repr(C)]
pub struct SockAddrIn {
    pub family: u16, // AF_INET = 2
    pub port: u16,   // Network byte order
    pub addr: Ipv4Addr,
    pub zero: [u8; 8],
}

/// Socket address for IPv6.
#[repr(C)]
pub struct SockAddrIn6 {
    pub family: u16,   // AF_INET6 = 10
    pub port: u16,     // Network byte order
    pub flowinfo: u32, // Traffic class & flow label
    pub addr: Ipv6Addr,
    pub scope_id: u32,
}

/// Generic socket address (for syscall interface).
#[repr(C)]
pub struct SockAddr {
    pub family: u16,
    pub data: [u8; 126],
}

// ============================================================================
// Address Family & Socket Types
// ============================================================================

pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_NETLINK: u16 = 16;
pub const AF_PACKET: u16 = 17;

pub const SOCK_STREAM: u32 = 1; // TCP
pub const SOCK_DGRAM: u32 = 2; // UDP
pub const SOCK_RAW: u32 = 3;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_NONBLOCK: u32 = 0o4000;
pub const SOCK_CLOEXEC: u32 = 0o2000000;

pub const IPPROTO_IP: u32 = 0;
pub const IPPROTO_ICMP: u32 = 1;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const IPPROTO_IPV6: u32 = 41;
pub const IPPROTO_ICMPV6: u32 = 58;
pub const IPPROTO_RAW: u32 = 255;

// ============================================================================
// Socket Options
// ============================================================================

pub mod sockopt {
    pub const SOL_SOCKET: i32 = 1;
    pub const SOL_IP: i32 = 0;
    pub const SOL_TCP: i32 = 6;
    pub const SOL_UDP: i32 = 17;
    pub const SOL_IPV6: i32 = 41;

    // SOL_SOCKET options
    pub const SO_DEBUG: i32 = 1;
    pub const SO_REUSEADDR: i32 = 2;
    pub const SO_TYPE: i32 = 3;
    pub const SO_ERROR: i32 = 4;
    pub const SO_DONTROUTE: i32 = 5;
    pub const SO_BROADCAST: i32 = 6;
    pub const SO_SNDBUF: i32 = 7;
    pub const SO_RCVBUF: i32 = 8;
    pub const SO_KEEPALIVE: i32 = 9;
    pub const SO_OOBINLINE: i32 = 10;
    pub const SO_LINGER: i32 = 13;
    pub const SO_REUSEPORT: i32 = 15;
    pub const SO_RCVTIMEO: i32 = 20;
    pub const SO_SNDTIMEO: i32 = 21;
    pub const SO_BINDTODEVICE: i32 = 25;
    pub const SO_TIMESTAMP: i32 = 29;
    pub const SO_ACCEPTCONN: i32 = 30;
    pub const SO_MARK: i32 = 36;
    pub const SO_PROTOCOL: i32 = 38;
    pub const SO_DOMAIN: i32 = 39;
    pub const SO_BUSY_POLL: i32 = 46;

    // TCP options
    pub const TCP_NODELAY: i32 = 1;
    pub const TCP_MAXSEG: i32 = 2;
    pub const TCP_CORK: i32 = 3;
    pub const TCP_KEEPIDLE: i32 = 4;
    pub const TCP_KEEPINTVL: i32 = 5;
    pub const TCP_KEEPCNT: i32 = 6;
    pub const TCP_SYNCNT: i32 = 7;
    pub const TCP_LINGER2: i32 = 8;
    pub const TCP_DEFER_ACCEPT: i32 = 9;
    pub const TCP_WINDOW_CLAMP: i32 = 10;
    pub const TCP_INFO: i32 = 11;
    pub const TCP_QUICKACK: i32 = 12;
    pub const TCP_CONGESTION: i32 = 13;
    pub const TCP_FASTOPEN: i32 = 23;
    pub const TCP_NOTSENT_LOWAT: i32 = 25;
}

// ============================================================================
// Packet Buffer (sk_buff equivalent)
// ============================================================================

/// Network packet buffer — the fundamental unit of networking.
#[repr(C)]
pub struct SkBuff {
    /// Next buffer in queue
    pub next: *mut SkBuff,
    /// Previous buffer in queue
    pub prev: *mut SkBuff,
    /// Owning socket
    pub sk: *mut Socket,
    /// Timestamp (nanoseconds)
    pub timestamp: u64,
    /// Network device
    pub dev: *mut NetDevice,
    /// Start of packet data
    pub data: *mut u8,
    /// End of data
    pub tail: *mut u8,
    /// Start of buffer
    pub head: *mut u8,
    /// End of buffer
    pub end: *mut u8,
    /// Total data length (including fragments)
    pub len: u32,
    /// Header length (data - head)
    pub data_len: u32,
    /// MAC header offset
    pub mac_header: u16,
    /// Network header offset
    pub network_header: u16,
    /// Transport header offset
    pub transport_header: u16,
    /// Protocol (ETH_P_*)
    pub protocol: u16,
    /// Packet type (unicast, broadcast, multicast, etc.)
    pub pkt_type: u8,
    /// IP summed status
    pub ip_summed: u8,
    /// Priority (for QoS)
    pub priority: u32,
    /// Mark (for netfilter)
    pub mark: u32,
    /// VLAN tag
    pub vlan_tag: u16,
    /// VLAN present flag
    pub vlan_present: bool,
    /// Checksum
    pub csum: u32,
    /// Checksum offset
    pub csum_offset: u16,
    /// Cloned flag
    pub cloned: bool,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Hash (for RSS/RPS)
    pub hash: u32,
    /// Queue mapping
    pub queue_mapping: u16,
    /// Traffic class
    pub tc_index: u16,
    /// Connection tracking info
    pub ct_info: u32,
}

unsafe impl Send for SkBuff {}
unsafe impl Sync for SkBuff {}

impl SkBuff {
    /// Get the amount of data in the buffer.
    pub fn data_len(&self) -> usize {
        unsafe { self.tail.offset_from(self.data) as usize }
    }

    /// Get total headroom.
    pub fn headroom(&self) -> usize {
        unsafe { self.data.offset_from(self.head) as usize }
    }

    /// Get total tailroom.
    pub fn tailroom(&self) -> usize {
        unsafe { self.end.offset_from(self.tail) as usize }
    }

    /// Reserve headroom before data starts.
    pub fn reserve(&mut self, len: usize) {
        unsafe {
            self.data = self.data.add(len);
            self.tail = self.data;
        }
    }

    /// Push data at the front (grow header).
    pub fn push(&mut self, len: usize) -> *mut u8 {
        unsafe {
            self.data = self.data.sub(len);
            self.len += len as u32;
            self.data
        }
    }

    /// Pull data from the front (shrink header).
    pub fn pull(&mut self, len: usize) -> *mut u8 {
        unsafe {
            self.data = self.data.add(len);
            self.len -= len as u32;
            self.data
        }
    }

    /// Put data at the tail (append data).
    pub fn put(&mut self, len: usize) -> *mut u8 {
        let old_tail = self.tail;
        unsafe {
            self.tail = self.tail.add(len);
        }
        self.len += len as u32;
        old_tail
    }

    /// Trim data from the tail.
    pub fn trim(&mut self, len: usize) {
        if (len as u32) < self.len {
            self.len -= len as u32;
            unsafe {
                self.tail = self.tail.sub(len);
            }
        }
    }
}

/// Ethernet protocol types.
pub mod eth_type {
    pub const ETH_P_IP: u16 = 0x0800;
    pub const ETH_P_ARP: u16 = 0x0806;
    pub const ETH_P_IPV6: u16 = 0x86DD;
    pub const ETH_P_8021Q: u16 = 0x8100;
    pub const ETH_P_8021AD: u16 = 0x88A8;
    pub const ETH_P_LLDP: u16 = 0x88CC;
}

// ============================================================================
// Protocol Headers
// ============================================================================

/// Ethernet header.
#[repr(C, packed)]
pub struct EthHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16, // Network byte order
}

/// IPv4 header.
#[repr(C, packed)]
pub struct Ipv4Header {
    pub version_ihl: u8, // Version (4 bits) + IHL (4 bits)
    pub tos: u8,          // Type of Service / DSCP + ECN
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16, // Flags (3 bits) + Fragment Offset (13 bits)
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

impl Ipv4Header {
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    pub fn header_length(&self) -> usize {
        (self.ihl() as usize) * 4
    }

    pub fn dscp(&self) -> u8 {
        self.tos >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.tos & 0x03
    }

    pub fn dont_fragment(&self) -> bool {
        u16::from_be(self.flags_fragment) & 0x4000 != 0
    }

    pub fn more_fragments(&self) -> bool {
        u16::from_be(self.flags_fragment) & 0x2000 != 0
    }

    pub fn fragment_offset(&self) -> u16 {
        u16::from_be(self.flags_fragment) & 0x1FFF
    }

    /// Calculate IPv4 header checksum.
    pub fn calculate_checksum(&self) -> u16 {
        let data = unsafe {
            core::slice::from_raw_parts(self as *const _ as *const u16, self.header_length() / 2)
        };
        let mut sum: u32 = 0;
        for &word in data {
            sum += u16::from_be(word) as u32;
        }
        // Subtract the checksum field itself
        sum -= u16::from_be(self.checksum) as u32;
        // Fold 32-bit sum to 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }
}

/// IPv6 header.
#[repr(C, packed)]
pub struct Ipv6Header {
    pub version_tc_fl: u32, // Version (4) + Traffic Class (8) + Flow Label (20)
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

impl Ipv6Header {
    pub fn version(&self) -> u8 {
        (u32::from_be(self.version_tc_fl) >> 28) as u8
    }

    pub fn traffic_class(&self) -> u8 {
        ((u32::from_be(self.version_tc_fl) >> 20) & 0xFF) as u8
    }

    pub fn flow_label(&self) -> u32 {
        u32::from_be(self.version_tc_fl) & 0xFFFFF
    }
}

/// TCP header.
#[repr(C, packed)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16, // Data offset (4) + Reserved (3) + Flags (9)
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn data_offset(&self) -> u8 {
        (u16::from_be(self.data_offset_flags) >> 12) as u8
    }

    pub fn header_length(&self) -> usize {
        self.data_offset() as usize * 4
    }

    pub fn flags(&self) -> u16 {
        u16::from_be(self.data_offset_flags) & 0x01FF
    }

    pub fn fin(&self) -> bool {
        self.flags() & 0x001 != 0
    }
    pub fn syn(&self) -> bool {
        self.flags() & 0x002 != 0
    }
    pub fn rst(&self) -> bool {
        self.flags() & 0x004 != 0
    }
    pub fn psh(&self) -> bool {
        self.flags() & 0x008 != 0
    }
    pub fn ack(&self) -> bool {
        self.flags() & 0x010 != 0
    }
    pub fn urg(&self) -> bool {
        self.flags() & 0x020 != 0
    }
    pub fn ece(&self) -> bool {
        self.flags() & 0x040 != 0
    }
    pub fn cwr(&self) -> bool {
        self.flags() & 0x080 != 0
    }
}

/// UDP header.
#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// ICMP header.
#[repr(C, packed)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32, // Type-specific data
}

/// ARP header.
#[repr(C, packed)]
pub struct ArpHeader {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_len: u8,
    pub proto_len: u8,
    pub operation: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

// ============================================================================
// TCP State Machine
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
    NewSynRecv = 11, // Fast-path SYN-cookie state
}

/// TCP congestion control algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Reno,
    Cubic,
    BBR,
    Vegas,
    Westwood,
}

/// TCP congestion control state.
pub struct TcpCongestionState {
    /// Congestion window (bytes)
    pub cwnd: u32,
    /// Slow start threshold
    pub ssthresh: u32,
    /// Round-trip time (microseconds)
    pub rtt: u32,
    /// RTT variance
    pub rtt_var: u32,
    /// Smoothed RTT
    pub srtt: u32,
    /// Min RTT observed
    pub min_rtt: u32,
    /// Last RTT sample
    pub last_rtt: u32,
    /// Retransmission timeout (microseconds)
    pub rto: u32,
    /// Number of duplicate ACKs received
    pub dup_acks: u32,
    /// Fast recovery flag
    pub in_recovery: bool,
    /// Recovery sequence number
    pub recovery_seq: u32,
    /// Algorithm
    pub algorithm: CongestionAlgorithm,
    /// Cubic-specific: W_max
    pub cubic_wmax: u32,
    /// Cubic-specific: epoch start
    pub cubic_epoch: u64,
    /// Cubic-specific: origin point
    pub cubic_origin: u32,
    /// BBR-specific: bottleneck bandwidth
    pub bbr_bw: u64,
    /// BBR-specific: min RTT probe time
    pub bbr_min_rtt_stamp: u64,
    /// BBR-specific: pacing rate
    pub bbr_pacing_rate: u64,
    /// BBR-specific: mode
    pub bbr_mode: u8,
}

impl TcpCongestionState {
    pub fn new(algorithm: CongestionAlgorithm) -> Self {
        TcpCongestionState {
            cwnd: 10 * 1460, // 10 segments (RFC 6928)
            ssthresh: u32::MAX,
            rtt: 0,
            rtt_var: 0,
            srtt: 0,
            min_rtt: u32::MAX,
            last_rtt: 0,
            rto: 1_000_000, // 1 second initial RTO
            dup_acks: 0,
            in_recovery: false,
            recovery_seq: 0,
            algorithm,
            cubic_wmax: 0,
            cubic_epoch: 0,
            cubic_origin: 0,
            bbr_bw: 0,
            bbr_min_rtt_stamp: 0,
            bbr_pacing_rate: 0,
            bbr_mode: 0,
        }
    }

    /// Update RTT estimate.
    pub fn update_rtt(&mut self, sample_rtt: u32) {
        if self.srtt == 0 {
            // First measurement
            self.srtt = sample_rtt;
            self.rtt_var = sample_rtt / 2;
        } else {
            // Exponential weighted moving average (RFC 6298)
            let delta = if sample_rtt > self.srtt {
                sample_rtt - self.srtt
            } else {
                self.srtt - sample_rtt
            };
            self.rtt_var = (3 * self.rtt_var + delta) / 4;
            self.srtt = (7 * self.srtt + sample_rtt) / 8;
        }
        self.last_rtt = sample_rtt;
        if sample_rtt < self.min_rtt {
            self.min_rtt = sample_rtt;
        }

        // Update RTO: SRTT + max(G, 4*RTTVAR), minimum 200ms
        self.rto = self.srtt + core::cmp::max(1000, 4 * self.rtt_var);
        if self.rto < 200_000 {
            self.rto = 200_000; // Min 200ms
        }
        if self.rto > 120_000_000 {
            self.rto = 120_000_000; // Max 120s
        }
    }

    /// Handle a new ACK (congestion control).
    pub fn on_ack(&mut self, bytes_acked: u32, mss: u32) {
        match self.algorithm {
            CongestionAlgorithm::Reno => self.reno_on_ack(bytes_acked, mss),
            CongestionAlgorithm::Cubic => self.cubic_on_ack(bytes_acked, mss),
            CongestionAlgorithm::BBR => self.bbr_on_ack(bytes_acked),
            _ => self.reno_on_ack(bytes_acked, mss),
        }
    }

    /// Handle packet loss.
    pub fn on_loss(&mut self, mss: u32) {
        match self.algorithm {
            CongestionAlgorithm::Reno => self.reno_on_loss(mss),
            CongestionAlgorithm::Cubic => self.cubic_on_loss(),
            CongestionAlgorithm::BBR => self.bbr_on_loss(),
            _ => self.reno_on_loss(mss),
        }
    }

    // Reno implementation
    fn reno_on_ack(&mut self, bytes_acked: u32, mss: u32) {
        if self.cwnd < self.ssthresh {
            // Slow start: increase cwnd by bytes_acked
            self.cwnd += bytes_acked;
        } else {
            // Congestion avoidance: increase cwnd by MSS^2/cwnd
            self.cwnd += mss * mss / self.cwnd;
        }
    }

    fn reno_on_loss(&mut self, mss: u32) {
        self.ssthresh = core::cmp::max(self.cwnd / 2, 2 * mss);
        self.cwnd = self.ssthresh;
    }

    // CUBIC implementation (simplified)
    fn cubic_on_ack(&mut self, bytes_acked: u32, mss: u32) {
        if self.cwnd < self.ssthresh {
            self.cwnd += bytes_acked;
        } else {
            // CUBIC window growth
            // W(t) = C*(t-K)^3 + W_max
            // C = 0.4, K = (W_max * beta / C)^(1/3)
            // beta = 0.7
            let wmax = self.cubic_wmax as u64;
            let cwnd = self.cwnd as u64;
            let target = if cwnd < wmax {
                // Below W_max: concave region
                wmax - ((wmax - cwnd) * 7 / 10)
            } else {
                // Above W_max: convex region
                cwnd + (cwnd / 100) // Simplified growth
            };
            self.cwnd = core::cmp::max(target as u32, self.cwnd + mss / self.cwnd * mss);
        }
    }

    fn cubic_on_loss(&mut self) {
        self.cubic_wmax = self.cwnd;
        self.ssthresh = self.cwnd * 7 / 10; // beta = 0.7
        self.cwnd = self.ssthresh;
    }

    // BBR implementation (simplified)
    fn bbr_on_ack(&mut self, _bytes_acked: u32) {
        // BBR uses pacing rate and doesn't directly control cwnd
        // Simplified: maintain cwnd = 2 * BDP
        if self.bbr_bw > 0 && self.min_rtt < u32::MAX {
            let bdp = self.bbr_bw * self.min_rtt as u64 / 1_000_000;
            self.cwnd = (2 * bdp) as u32;
        }
    }

    fn bbr_on_loss(&mut self) {
        // BBR handles loss differently — doesn't reduce cwnd
        // It only adjusts pacing rate
    }
}

// ============================================================================
// Socket — User-facing network endpoint
// ============================================================================

/// Socket structure.
#[repr(C)]
pub struct Socket {
    /// Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
    pub sock_type: u32,
    /// Address family
    pub family: u16,
    /// Protocol
    pub protocol: u16,
    /// Socket state
    pub state: AtomicU32,
    /// Flags
    pub flags: AtomicU32,
    /// Local address
    pub local_addr: SockAddr,
    /// Remote address
    pub remote_addr: SockAddr,
    /// Local port
    pub local_port: AtomicU16,
    /// Remote port
    pub remote_port: u16,
    /// Send buffer
    pub send_buf: SocketBuffer,
    /// Receive buffer
    pub recv_buf: SocketBuffer,
    /// Socket options
    pub options: SocketOptions,
    /// Operations
    pub ops: *const SocketOps,
    /// Owning process PID
    pub owner_pid: u32,
    /// Reference count
    pub ref_count: AtomicU32,
    /// TCP state (only for TCP sockets)
    pub tcp_state: TcpState,
    /// TCP congestion control
    pub congestion: TcpCongestionState,
    /// Backlog queue (for listening sockets)
    pub backlog: *mut Socket,
    /// Backlog count
    pub backlog_count: AtomicU32,
    /// Maximum backlog
    pub max_backlog: u32,
    /// Network namespace
    pub net_ns: *mut u8,
    /// Bound device
    pub bound_dev: *mut NetDevice,
    /// Error code
    pub error: AtomicI32,
    /// Timestamp of last activity
    pub last_activity: AtomicU64,
}

unsafe impl Send for Socket {}
unsafe impl Sync for Socket {}

/// Socket states.
pub const SS_UNCONNECTED: u32 = 0;
pub const SS_CONNECTING: u32 = 1;
pub const SS_CONNECTED: u32 = 2;
pub const SS_DISCONNECTING: u32 = 3;
pub const SS_LISTENING: u32 = 4;

/// Socket buffer for send/receive queues.
pub struct SocketBuffer {
    /// Head of the sk_buff queue
    pub head: *mut SkBuff,
    /// Tail of the sk_buff queue
    pub tail: *mut SkBuff,
    /// Number of bytes in buffer
    pub len: AtomicUsize,
    /// Maximum buffer size
    pub max_len: usize,
    /// Number of packets
    pub count: AtomicU32,
}

impl SocketBuffer {
    pub const fn new(max_len: usize) -> Self {
        SocketBuffer {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
            len: AtomicUsize::new(0),
            max_len,
            count: AtomicU32::new(0),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Relaxed) == 0
    }

    pub fn is_full(&self) -> bool {
        self.len.load(Ordering::Relaxed) >= self.max_len
    }
}

/// Socket options.
pub struct SocketOptions {
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub keepalive: bool,
    pub broadcast: bool,
    pub no_delay: bool,
    pub cork: bool,
    pub linger: Option<u32>,
    pub send_buffer_size: u32,
    pub recv_buffer_size: u32,
    pub send_timeout: u64,
    pub recv_timeout: u64,
    pub mark: u32,
    pub priority: u32,
    pub tos: u8,
    pub ttl: u8,
}

impl SocketOptions {
    pub fn default_tcp() -> Self {
        SocketOptions {
            reuse_addr: false,
            reuse_port: false,
            keepalive: false,
            broadcast: false,
            no_delay: false,
            cork: false,
            linger: None,
            send_buffer_size: 87380,
            recv_buffer_size: 87380,
            send_timeout: 0,
            recv_timeout: 0,
            mark: 0,
            priority: 0,
            tos: 0,
            ttl: 64,
        }
    }

    pub fn default_udp() -> Self {
        SocketOptions {
            reuse_addr: false,
            reuse_port: false,
            keepalive: false,
            broadcast: false,
            no_delay: false,
            cork: false,
            linger: None,
            send_buffer_size: 212992,
            recv_buffer_size: 212992,
            send_timeout: 0,
            recv_timeout: 0,
            mark: 0,
            priority: 0,
            tos: 0,
            ttl: 64,
        }
    }
}

/// Socket operations vtable.
#[repr(C)]
pub struct SocketOps {
    pub bind: Option<fn(sk: *mut Socket, addr: *const SockAddr, addrlen: u32) -> NetResult<()>>,
    pub connect: Option<fn(sk: *mut Socket, addr: *const SockAddr, addrlen: u32, flags: u32) -> NetResult<()>>,
    pub listen: Option<fn(sk: *mut Socket, backlog: u32) -> NetResult<()>>,
    pub accept: Option<fn(sk: *mut Socket, flags: u32) -> NetResult<*mut Socket>>,
    pub sendmsg: Option<fn(sk: *mut Socket, msg: *const MsgHdr, flags: u32) -> NetResult<usize>>,
    pub recvmsg: Option<fn(sk: *mut Socket, msg: *mut MsgHdr, flags: u32) -> NetResult<usize>>,
    pub shutdown: Option<fn(sk: *mut Socket, how: u32) -> NetResult<()>>,
    pub close: Option<fn(sk: *mut Socket) -> NetResult<()>>,
    pub poll: Option<fn(sk: *mut Socket) -> u32>,
    pub ioctl: Option<fn(sk: *mut Socket, cmd: u32, arg: u64) -> NetResult<i64>>,
    pub setsockopt: Option<fn(sk: *mut Socket, level: i32, optname: i32, optval: *const u8, optlen: u32) -> NetResult<()>>,
    pub getsockopt: Option<fn(sk: *mut Socket, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> NetResult<()>>,
}

/// Message header for sendmsg/recvmsg.
#[repr(C)]
pub struct MsgHdr {
    pub name: *mut SockAddr,
    pub namelen: u32,
    pub iov: *mut IoVec,
    pub iovlen: usize,
    pub control: *mut u8,
    pub controllen: usize,
    pub flags: u32,
}

/// I/O vector.
#[repr(C)]
pub struct IoVec {
    pub base: *mut u8,
    pub len: usize,
}

// ============================================================================
// Network Device
// ============================================================================

/// Network device flags.
pub const IFF_UP: u32 = 1 << 0;
pub const IFF_BROADCAST: u32 = 1 << 1;
pub const IFF_DEBUG: u32 = 1 << 2;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const IFF_POINTOPOINT: u32 = 1 << 4;
pub const IFF_RUNNING: u32 = 1 << 6;
pub const IFF_NOARP: u32 = 1 << 7;
pub const IFF_PROMISC: u32 = 1 << 8;
pub const IFF_ALLMULTI: u32 = 1 << 9;
pub const IFF_MULTICAST: u32 = 1 << 12;

/// Network device structure.
#[repr(C)]
pub struct NetDevice {
    /// Device name (e.g., "eth0")
    pub name: [u8; 16],
    /// Interface index
    pub ifindex: u32,
    /// Device flags
    pub flags: AtomicU32,
    /// Device state
    pub state: AtomicU32,
    /// MTU (Maximum Transmission Unit)
    pub mtu: AtomicU32,
    /// Hardware address
    pub hw_addr: MacAddr,
    /// Broadcast address
    pub broadcast: MacAddr,
    /// Number of TX queues
    pub num_tx_queues: u16,
    /// Number of RX queues
    pub num_rx_queues: u16,
    /// TX queue length
    pub tx_queue_len: u32,
    /// Device operations
    pub ops: *const NetDeviceOps,
    /// Driver private data
    pub priv_data: *mut u8,
    /// Statistics
    pub stats: NetDeviceStats,
    /// QoS queuing discipline
    pub qdisc: *mut u8,
    /// Network namespace
    pub net_ns: *mut u8,
    /// Features (checksum offload, TSO, etc.)
    pub features: u64,
    /// Hardware features
    pub hw_features: u64,
    /// Wanted features
    pub wanted_features: u64,
    /// Next device in list
    pub next: *mut NetDevice,
    /// Reference count
    pub ref_count: AtomicU32,
}

unsafe impl Send for NetDevice {}
unsafe impl Sync for NetDevice {}

/// Network device feature flags.
pub mod net_features {
    pub const NETIF_F_RXCSUM: u64 = 1 << 0;
    pub const NETIF_F_TXCSUM: u64 = 1 << 1;
    pub const NETIF_F_SG: u64 = 1 << 2;
    pub const NETIF_F_TSO: u64 = 1 << 3;
    pub const NETIF_F_TSO6: u64 = 1 << 4;
    pub const NETIF_F_GRO: u64 = 1 << 5;
    pub const NETIF_F_GSO: u64 = 1 << 6;
    pub const NETIF_F_VLAN: u64 = 1 << 7;
    pub const NETIF_F_RXHASH: u64 = 1 << 8;
    pub const NETIF_F_NTUPLE: u64 = 1 << 9;
    pub const NETIF_F_LRO: u64 = 1 << 10;
}

/// Network device operations.
#[repr(C)]
pub struct NetDeviceOps {
    pub open: Option<fn(dev: *mut NetDevice) -> NetResult<()>>,
    pub stop: Option<fn(dev: *mut NetDevice) -> NetResult<()>>,
    pub start_xmit: Option<fn(skb: *mut SkBuff, dev: *mut NetDevice) -> NetResult<()>>,
    pub set_mac_address: Option<fn(dev: *mut NetDevice, addr: *const MacAddr) -> NetResult<()>>,
    pub set_mtu: Option<fn(dev: *mut NetDevice, mtu: u32) -> NetResult<()>>,
    pub get_stats: Option<fn(dev: *mut NetDevice) -> *const NetDeviceStats>,
    pub do_ioctl: Option<fn(dev: *mut NetDevice, cmd: u32, data: *mut u8) -> NetResult<i32>>,
    pub change_mtu: Option<fn(dev: *mut NetDevice, new_mtu: u32) -> NetResult<()>>,
    pub set_features: Option<fn(dev: *mut NetDevice, features: u64) -> NetResult<()>>,
    pub ndo_poll: Option<fn(dev: *mut NetDevice, budget: i32) -> i32>,
}

/// Network device statistics.
#[repr(C)]
pub struct NetDeviceStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
    pub multicast: AtomicU64,
    pub collisions: AtomicU64,
    pub rx_crc_errors: AtomicU64,
    pub rx_frame_errors: AtomicU64,
    pub rx_fifo_errors: AtomicU64,
    pub tx_fifo_errors: AtomicU64,
    pub tx_carrier_errors: AtomicU64,
}

impl NetDeviceStats {
    pub const fn new() -> Self {
        NetDeviceStats {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
            multicast: AtomicU64::new(0),
            collisions: AtomicU64::new(0),
            rx_crc_errors: AtomicU64::new(0),
            rx_frame_errors: AtomicU64::new(0),
            rx_fifo_errors: AtomicU64::new(0),
            tx_fifo_errors: AtomicU64::new(0),
            tx_carrier_errors: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Routing Table
// ============================================================================

/// Routing table entry.
#[repr(C)]
pub struct RouteEntry {
    /// Destination network
    pub dst: Ipv4Addr,
    /// Network mask
    pub mask: Ipv4Addr,
    /// Gateway address
    pub gateway: Ipv4Addr,
    /// Output device
    pub dev: *mut NetDevice,
    /// Metric
    pub metric: u32,
    /// Route flags
    pub flags: u32,
    /// Route type
    pub route_type: u8,
    /// Protocol (how the route was learned)
    pub protocol: u8,
    /// Scope
    pub scope: u8,
    /// Next entry
    pub next: *mut RouteEntry,
}

pub const RTF_UP: u32 = 0x0001;
pub const RTF_GATEWAY: u32 = 0x0002;
pub const RTF_HOST: u32 = 0x0004;
pub const RTF_REJECT: u32 = 0x0200;
pub const RTF_DYNAMIC: u32 = 0x0010;
pub const RTF_DEFAULT: u32 = 0x8000;

// ============================================================================
// ARP Cache
// ============================================================================

/// ARP cache entry.
#[repr(C)]
pub struct ArpEntry {
    /// IP address
    pub ip: Ipv4Addr,
    /// MAC address
    pub mac: MacAddr,
    /// State
    pub state: u8,
    /// Timestamp
    pub timestamp: u64,
    /// Retries remaining
    pub retries: u8,
    /// Network device
    pub dev: *mut NetDevice,
    /// Queued packets (waiting for resolution)
    pub queue: *mut SkBuff,
    /// Next entry
    pub next: *mut ArpEntry,
}

pub const ARP_STATE_INCOMPLETE: u8 = 0;
pub const ARP_STATE_REACHABLE: u8 = 1;
pub const ARP_STATE_STALE: u8 = 2;
pub const ARP_STATE_DELAY: u8 = 3;
pub const ARP_STATE_PROBE: u8 = 4;
pub const ARP_STATE_FAILED: u8 = 5;

// ============================================================================
// Checksum Computation
// ============================================================================

/// Compute a ones-complement checksum over a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute TCP/UDP pseudo-header checksum for IPv4.
pub fn pseudo_header_checksum_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    length: u16,
) -> u32 {
    let mut sum: u32 = 0;
    let src_bytes = src.octets;
    let dst_bytes = dst.octets;

    sum += ((src_bytes[0] as u32) << 8) | src_bytes[1] as u32;
    sum += ((src_bytes[2] as u32) << 8) | src_bytes[3] as u32;
    sum += ((dst_bytes[0] as u32) << 8) | dst_bytes[1] as u32;
    sum += ((dst_bytes[2] as u32) << 8) | dst_bytes[3] as u32;
    sum += protocol as u32;
    sum += length as u32;

    sum
}

// ============================================================================
// Network Stack Initialization
// ============================================================================

/// Initialize the network stack.
#[no_mangle]
pub extern "C" fn net_stack_init() -> i32 {
    // Initialize protocol handlers
    // Initialize routing table
    // Initialize ARP cache
    // Register loopback device
    0
}

/// Process an incoming packet.
#[no_mangle]
pub extern "C" fn net_rx_packet(_dev: *mut NetDevice, _skb: *mut SkBuff) -> i32 {
    // TODO: Dispatch based on ethertype
    0
}

/// Transmit a packet.
#[no_mangle]
pub extern "C" fn net_tx_packet(_skb: *mut SkBuff) -> i32 {
    // TODO: Route lookup, ARP resolution, device xmit
    0
}
