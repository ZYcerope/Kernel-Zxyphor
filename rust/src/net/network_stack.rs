// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Networking (Rust)
// Full TCP/IP stack types, WiFi, Bluetooth, InfiniBand, RDMA, netdev features

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// Socket Types and Families
// ============================================================================

pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_AX25: u16 = 3;
pub const AF_IPX: u16 = 4;
pub const AF_APPLETALK: u16 = 5;
pub const AF_NETROM: u16 = 6;
pub const AF_BRIDGE: u16 = 7;
pub const AF_ATMPVC: u16 = 8;
pub const AF_X25: u16 = 9;
pub const AF_INET6: u16 = 10;
pub const AF_ROSE: u16 = 11;
pub const AF_DECNET: u16 = 12;
pub const AF_NETBEUI: u16 = 13;
pub const AF_SECURITY: u16 = 14;
pub const AF_KEY: u16 = 15;
pub const AF_NETLINK: u16 = 16;
pub const AF_PACKET: u16 = 17;
pub const AF_ASH: u16 = 18;
pub const AF_ECONET: u16 = 19;
pub const AF_ATMSVC: u16 = 20;
pub const AF_RDS: u16 = 21;
pub const AF_SNA: u16 = 22;
pub const AF_IRDA: u16 = 23;
pub const AF_PPPOX: u16 = 24;
pub const AF_WANPIPE: u16 = 25;
pub const AF_LLC: u16 = 26;
pub const AF_IB: u16 = 27;
pub const AF_MPLS: u16 = 28;
pub const AF_CAN: u16 = 29;
pub const AF_TIPC: u16 = 30;
pub const AF_BLUETOOTH: u16 = 31;
pub const AF_IUCV: u16 = 32;
pub const AF_RXRPC: u16 = 33;
pub const AF_ISDN: u16 = 34;
pub const AF_PHONET: u16 = 35;
pub const AF_IEEE802154: u16 = 36;
pub const AF_CAIF: u16 = 37;
pub const AF_ALG: u16 = 38;
pub const AF_NFC: u16 = 39;
pub const AF_VSOCK: u16 = 40;
pub const AF_KCM: u16 = 41;
pub const AF_QIPCRTR: u16 = 42;
pub const AF_SMC: u16 = 43;
pub const AF_XDP: u16 = 44;
pub const AF_MCTP: u16 = 45;
pub const AF_MAX: u16 = 46;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_RDM: u32 = 4;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_DCCP: u32 = 6;
pub const SOCK_PACKET: u32 = 10;

// ============================================================================
// IPv4
// ============================================================================

#[repr(C, packed)]
pub struct Ipv4Header {
    pub version_ihl: u8,     // Version (4 bits) + IHL (4 bits)
    pub tos: u8,              // DSCP (6 bits) + ECN (2 bits)
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,  // Flags (3 bits) + Fragment Offset (13 bits)
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

impl Ipv4Header {
    pub fn version(&self) -> u8 { self.version_ihl >> 4 }
    pub fn ihl(&self) -> u8 { self.version_ihl & 0x0F }
    pub fn header_len(&self) -> usize { (self.ihl() as usize) * 4 }
    pub fn dscp(&self) -> u8 { self.tos >> 2 }
    pub fn ecn(&self) -> u8 { self.tos & 0x03 }
    pub fn flags(&self) -> u8 { (u16::from_be(self.flags_fragment) >> 13) as u8 }
    pub fn fragment_offset(&self) -> u16 { u16::from_be(self.flags_fragment) & 0x1FFF }
    
    pub fn compute_checksum(&self) -> u16 {
        let words: [u16; 10] = [
            ((self.version_ihl as u16) << 8) | self.tos as u16,
            self.total_length,
            self.identification,
            self.flags_fragment,
            ((self.ttl as u16) << 8) | self.protocol as u16,
            0, // checksum field set to 0
            (self.src_addr >> 16) as u16,
            self.src_addr as u16,
            (self.dst_addr >> 16) as u16,
            self.dst_addr as u16,
        ];
        let mut sum: u32 = 0;
        for w in &words {
            sum += u16::from_be(*w) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

// IP protocols
pub const IPPROTO_IP: u8 = 0;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_IGMP: u8 = 2;
pub const IPPROTO_IPIP: u8 = 4;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_EGP: u8 = 8;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_IPV6: u8 = 41;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_GRE: u8 = 47;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_NONE: u8 = 59;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPPROTO_MH: u8 = 135;
pub const IPPROTO_MPTCP: u8 = 262; // MPTCP subtype
pub const IPPROTO_SCTP: u8 = 132;
pub const IPPROTO_UDPLITE: u8 = 136;
pub const IPPROTO_RAW: u8 = 255;

// ============================================================================
// IPv6
// ============================================================================

#[repr(C, packed)]
pub struct Ipv6Header {
    pub version_tc_fl: u32,   // Version(4) + TC(8) + Flow Label(20)
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
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

// ============================================================================
// TCP
// ============================================================================

#[repr(C, packed)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16, // DataOffset(4) + Reserved(3) + Flags(9)
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

pub const TCP_FLAG_FIN: u16 = 0x001;
pub const TCP_FLAG_SYN: u16 = 0x002;
pub const TCP_FLAG_RST: u16 = 0x004;
pub const TCP_FLAG_PSH: u16 = 0x008;
pub const TCP_FLAG_ACK: u16 = 0x010;
pub const TCP_FLAG_URG: u16 = 0x020;
pub const TCP_FLAG_ECE: u16 = 0x040;
pub const TCP_FLAG_CWR: u16 = 0x080;
pub const TCP_FLAG_NS: u16 = 0x100;

impl TcpHeader {
    pub fn data_offset(&self) -> u8 {
        (u16::from_be(self.data_offset_flags) >> 12) as u8
    }
    pub fn flags(&self) -> u16 {
        u16::from_be(self.data_offset_flags) & 0x1FF
    }
    pub fn header_len(&self) -> usize {
        (self.data_offset() as usize) * 4
    }
}

// TCP socket options
pub const TCP_NODELAY: u32 = 1;
pub const TCP_MAXSEG: u32 = 2;
pub const TCP_CORK: u32 = 3;
pub const TCP_KEEPIDLE: u32 = 4;
pub const TCP_KEEPINTVL: u32 = 5;
pub const TCP_KEEPCNT: u32 = 6;
pub const TCP_SYNCNT: u32 = 7;
pub const TCP_LINGER2: u32 = 8;
pub const TCP_DEFER_ACCEPT: u32 = 9;
pub const TCP_WINDOW_CLAMP: u32 = 10;
pub const TCP_INFO: u32 = 11;
pub const TCP_QUICKACK: u32 = 12;
pub const TCP_CONGESTION: u32 = 13;
pub const TCP_MD5SIG: u32 = 14;
pub const TCP_THIN_LINEAR_TIMEOUTS: u32 = 16;
pub const TCP_THIN_DUPACK: u32 = 17;
pub const TCP_USER_TIMEOUT: u32 = 18;
pub const TCP_REPAIR: u32 = 19;
pub const TCP_REPAIR_QUEUE: u32 = 20;
pub const TCP_QUEUE_SEQ: u32 = 21;
pub const TCP_REPAIR_OPTIONS: u32 = 22;
pub const TCP_FASTOPEN: u32 = 23;
pub const TCP_TIMESTAMP: u32 = 24;
pub const TCP_NOTSENT_LOWAT: u32 = 25;
pub const TCP_CC_INFO: u32 = 26;
pub const TCP_SAVE_SYN: u32 = 27;
pub const TCP_SAVED_SYN: u32 = 28;
pub const TCP_REPAIR_WINDOW: u32 = 29;
pub const TCP_FASTOPEN_CONNECT: u32 = 30;
pub const TCP_ULP: u32 = 31;
pub const TCP_MD5SIG_EXT: u32 = 32;
pub const TCP_FASTOPEN_KEY: u32 = 33;
pub const TCP_FASTOPEN_NO_COOKIE: u32 = 34;
pub const TCP_ZEROCOPY_RECEIVE: u32 = 35;
pub const TCP_INQ: u32 = 36;
pub const TCP_TX_DELAY: u32 = 37;
pub const TCP_AO_ADD_KEY: u32 = 38;
pub const TCP_AO_DEL_KEY: u32 = 39;
pub const TCP_AO_INFO: u32 = 40;
pub const TCP_AO_GET_KEYS: u32 = 41;
pub const TCP_AO_REPAIR: u32 = 42;

// ============================================================================
// UDP
// ============================================================================

#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

// ============================================================================
// WiFi (IEEE 802.11)
// ============================================================================

#[repr(C, packed)]
pub struct Ieee80211Header {
    pub frame_control: u16,
    pub duration_id: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
    // addr4 present if ToDS and FromDS are both set
}

// Frame control bits
pub const IEEE80211_FCTL_VERSION: u16 = 0x0003;
pub const IEEE80211_FCTL_FTYPE: u16 = 0x000C;
pub const IEEE80211_FCTL_STYPE: u16 = 0x00F0;
pub const IEEE80211_FCTL_TODS: u16 = 0x0100;
pub const IEEE80211_FCTL_FROMDS: u16 = 0x0200;
pub const IEEE80211_FCTL_MOREFRAGS: u16 = 0x0400;
pub const IEEE80211_FCTL_RETRY: u16 = 0x0800;
pub const IEEE80211_FCTL_PM: u16 = 0x1000;
pub const IEEE80211_FCTL_MOREDATA: u16 = 0x2000;
pub const IEEE80211_FCTL_PROTECTED: u16 = 0x4000;
pub const IEEE80211_FCTL_ORDER: u16 = 0x8000;

// Frame types
pub const IEEE80211_FTYPE_MGMT: u16 = 0x0000;
pub const IEEE80211_FTYPE_CTL: u16 = 0x0004;
pub const IEEE80211_FTYPE_DATA: u16 = 0x0008;
pub const IEEE80211_FTYPE_EXT: u16 = 0x000C;

// Management subtypes
pub const IEEE80211_STYPE_ASSOC_REQ: u16 = 0x0000;
pub const IEEE80211_STYPE_ASSOC_RESP: u16 = 0x0010;
pub const IEEE80211_STYPE_REASSOC_REQ: u16 = 0x0020;
pub const IEEE80211_STYPE_REASSOC_RESP: u16 = 0x0030;
pub const IEEE80211_STYPE_PROBE_REQ: u16 = 0x0040;
pub const IEEE80211_STYPE_PROBE_RESP: u16 = 0x0050;
pub const IEEE80211_STYPE_BEACON: u16 = 0x0080;
pub const IEEE80211_STYPE_ATIM: u16 = 0x0090;
pub const IEEE80211_STYPE_DISASSOC: u16 = 0x00A0;
pub const IEEE80211_STYPE_AUTH: u16 = 0x00B0;
pub const IEEE80211_STYPE_DEAUTH: u16 = 0x00C0;
pub const IEEE80211_STYPE_ACTION: u16 = 0x00D0;

// WiFi standards
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WifiStandard {
    Wifi4,    // 802.11n (HT)
    Wifi5,    // 802.11ac (VHT)
    Wifi6,    // 802.11ax (HE)
    Wifi6E,   // 802.11ax 6GHz
    Wifi7,    // 802.11be (EHT)
}

pub struct WifiInterface {
    pub iftype: WifiIfType,
    pub standard: WifiStandard,
    pub mac_addr: [u8; 6],
    pub bssid: [u8; 6],
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    pub channel: u16,
    pub frequency: u32,      // MHz
    pub bandwidth: WifiBandwidth,
    pub signal_dbm: i8,
    pub noise_dbm: i8,
    pub tx_power_dbm: u8,
    pub rssi: i8,
    pub connected: bool,
    pub security: WifiSecurity,
    // Stats
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_retries: AtomicU64,
    pub tx_failed: AtomicU64,
    pub rx_dropped: AtomicU64,
    // Rate info
    pub tx_bitrate_100kbps: u32,
    pub rx_bitrate_100kbps: u32,
    pub mcs_index: u8,
    pub nss: u8,            // Number of spatial streams
    pub short_gi: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WifiIfType {
    Station,
    Ap,
    ApVlan,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WifiBandwidth {
    Bw20,
    Bw40,
    Bw80,
    Bw160,
    Bw320,     // WiFi 7
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WifiSecurity {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3Sae,
    Wpa3Enterprise,
    Owe,         // Opportunistic Wireless Encryption
    EnhancedOpen,
}

// ============================================================================
// Bluetooth
// ============================================================================

pub struct BluetoothDevice {
    pub addr: [u8; 6],       // BD_ADDR
    pub addr_type: BtAddrType,
    pub name: [u8; 248],
    pub name_len: u8,
    pub class_of_device: u32,
    pub paired: bool,
    pub connected: bool,
    pub trusted: bool,
    pub blocked: bool,
    pub rssi: i8,
    pub tx_power: i8,
    pub appearance: u16,
    pub le_supported: bool,
    pub bredr_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BtAddrType {
    BrEdr,      // Classic Bluetooth
    LePublic,
    LeRandom,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BtVersion {
    V40,
    V41,
    V42,
    V50,
    V51,
    V52,
    V53,
    V54,
    V60,      // Bluetooth 6.0 (2025+)
}

// HCI packet types
pub const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_ACLDATA_PKT: u8 = 0x02;
pub const HCI_SCODATA_PKT: u8 = 0x03;
pub const HCI_EVENT_PKT: u8 = 0x04;
pub const HCI_ISODATA_PKT: u8 = 0x05;

// L2CAP
pub const L2CAP_CID_SIGNALING: u16 = 0x0001;
pub const L2CAP_CID_CONNLESS: u16 = 0x0002;
pub const L2CAP_CID_ATT: u16 = 0x0004;
pub const L2CAP_CID_LE_SIGNALING: u16 = 0x0005;
pub const L2CAP_CID_SMP: u16 = 0x0006;
pub const L2CAP_CID_SMP_BREDR: u16 = 0x0007;

// ============================================================================
// InfiniBand / RDMA
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RdmaTransport {
    Ib,        // InfiniBand
    IWarp,     // iWARP
    RoCEv1,    // RDMA over Converged Ethernet v1
    RoCEv2,    // RDMA over Converged Ethernet v2
    Usnic,     // Cisco usNIC
}

pub struct RdmaDevice {
    pub name: [u8; 64],
    pub name_len: u8,
    pub node_type: RdmaNodeType,
    pub transport: RdmaTransport,
    pub node_guid: u64,
    pub sys_image_guid: u64,
    pub fw_ver: [u8; 64],
    pub fw_ver_len: u8,
    pub num_ports: u8,
    pub num_comp_vectors: u32,
    pub phys_port_cnt: u8,
    pub local_dma_lkey: u32,
    pub max_mr_size: u64,
    pub page_size_cap: u64,
    pub max_qp: u32,
    pub max_qp_wr: u32,
    pub max_sge: u32,
    pub max_sge_rd: u32,
    pub max_cq: u32,
    pub max_cqe: u32,
    pub max_mr: u32,
    pub max_pd: u32,
    pub max_qp_rd_atom: u32,
    pub max_ee_rd_atom: u32,
    pub max_res_rd_atom: u32,
    pub max_qp_init_rd_atom: u32,
    pub max_srq: u32,
    pub max_srq_wr: u32,
    pub max_srq_sge: u32,
    pub atomic_cap: AtomicCap,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RdmaNodeType {
    Ca,        // Channel Adapter
    Switch,
    Router,
    Rnic,      // RDMA NIC
    UsnicUdp,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AtomicCap {
    None,
    Hca,
    Glob,
}

pub struct QueuePair {
    pub qp_num: u32,
    pub qp_type: QpType,
    pub state: QpState,
    pub max_send_wr: u32,
    pub max_recv_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_inline_data: u32,
    pub sq_sig_type: SignalType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QpType {
    Rc,      // Reliable Connected
    Uc,      // Unreliable Connected
    Ud,      // Unreliable Datagram
    RawIpv4,
    RawPacket,
    Xrc,     // Extended Reliable Connected
    XrcSend,
    XrcRecv,
    Driver,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QpState {
    Reset,
    Init,
    Rtr,     // Ready to Receive
    Rts,     // Ready to Send
    Sqd,     // Send Queue Drained
    Sqe,     // Send Queue Error
    Err,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignalType {
    AllWr,
    ReqWr,
}

// RDMA verbs
pub struct RdmaWorkRequest {
    pub wr_id: u64,
    pub opcode: RdmaOpcode,
    pub send_flags: u32,
    pub imm_data: u32,
    pub remote_addr: u64,
    pub rkey: u32,
    pub sg_list: [ScatterGatherEntry; 16],
    pub num_sge: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RdmaOpcode {
    Send,
    SendWithImm,
    Write,
    WriteWithImm,
    Read,
    AtomicCmpSwp,
    AtomicFetchAdd,
    BindMw,
    LocalInv,
    Recv,
    SendWithInv,
}

pub struct ScatterGatherEntry {
    pub addr: u64,
    pub length: u32,
    pub lkey: u32,
}

// ============================================================================
// Network Device Features
// ============================================================================

pub const NETIF_F_SG: u64 = 1 << 0;            // Scatter/gather I/O
pub const NETIF_F_IP_CSUM: u64 = 1 << 1;       // IPv4 checksum offload
pub const NETIF_F_HW_CSUM: u64 = 1 << 2;       // Hardware checksum
pub const NETIF_F_IPV6_CSUM: u64 = 1 << 3;
pub const NETIF_F_HIGHDMA: u64 = 1 << 4;       // DMA to high memory
pub const NETIF_F_FRAGLIST: u64 = 1 << 5;
pub const NETIF_F_HW_VLAN_CTAG_TX: u64 = 1 << 6;
pub const NETIF_F_HW_VLAN_CTAG_RX: u64 = 1 << 7;
pub const NETIF_F_HW_VLAN_CTAG_FILTER: u64 = 1 << 8;
pub const NETIF_F_VLAN_CHALLENGED: u64 = 1 << 9;
pub const NETIF_F_GSO: u64 = 1 << 10;          // Generic Segmentation Offload
pub const NETIF_F_LLTX: u64 = 1 << 11;         // Lockless TX
pub const NETIF_F_NETNS_LOCAL: u64 = 1 << 12;
pub const NETIF_F_GRO: u64 = 1 << 13;          // Generic Receive Offload
pub const NETIF_F_GRO_HW: u64 = 1 << 14;       // Hardware GRO
pub const NETIF_F_TSO: u64 = 1 << 15;          // TCP Segmentation Offload
pub const NETIF_F_TSO6: u64 = 1 << 16;
pub const NETIF_F_GSO_GRE: u64 = 1 << 17;
pub const NETIF_F_GSO_UDP_TUNNEL: u64 = 1 << 18;
pub const NETIF_F_LRO: u64 = 1 << 19;          // Large Receive Offload
pub const NETIF_F_RXHASH: u64 = 1 << 20;       // Receive hashing offload
pub const NETIF_F_RXCSUM: u64 = 1 << 21;       // Receive checksum offload
pub const NETIF_F_NOCACHE_COPY: u64 = 1 << 22;
pub const NETIF_F_LOOPBACK: u64 = 1 << 23;
pub const NETIF_F_RXFCS: u64 = 1 << 24;
pub const NETIF_F_RXALL: u64 = 1 << 25;
pub const NETIF_F_HW_L2FW_DOFFLOAD: u64 = 1 << 26;
pub const NETIF_F_HW_TC: u64 = 1 << 27;        // TC offload
pub const NETIF_F_HW_ESP: u64 = 1 << 28;       // IPsec ESP offload
pub const NETIF_F_GSO_ESP: u64 = 1 << 29;
pub const NETIF_F_HW_TLS_TX: u64 = 1 << 30;    // kTLS TX offload
pub const NETIF_F_HW_TLS_RX: u64 = 1 << 31;    // kTLS RX offload
pub const NETIF_F_GRO_FRAGLIST: u64 = 1u64 << 32;
pub const NETIF_F_HW_MACSEC: u64 = 1u64 << 33;
pub const NETIF_F_GSO_UDP_L4: u64 = 1u64 << 34;

// ============================================================================
// Network Namespace
// ============================================================================

pub struct NetNamespace {
    pub id: u64,
    pub refcount: AtomicU32,
    // Loopback device
    pub loopback_dev_id: u64,
    // Network configuration
    pub ipv4_conf_default_forwarding: bool,
    pub ipv6_conf_default_forwarding: bool,
    pub ipv4_fib_max_size: u32,
    pub ipv6_fib_max_size: u32,
    // Sysctl tunables
    pub tcp_mem: [u64; 3],    // Min/pressure/max pages
    pub udp_mem: [u64; 3],
    pub tcp_rmem: [u32; 3],   // Min/default/max bytes
    pub tcp_wmem: [u32; 3],
    pub ip_default_ttl: u32,
    pub ipv6_hop_limit: u32,
    pub tcp_keepalive_time: u32,
    pub tcp_keepalive_intvl: u32,
    pub tcp_keepalive_probes: u32,
    pub tcp_fin_timeout: u32,
    pub tcp_max_syn_backlog: u32,
    pub tcp_syncookies: bool,
    pub tcp_timestamps: bool,
    pub tcp_window_scaling: bool,
    pub tcp_sack: bool,
    pub tcp_ecn: u32,
    pub tcp_congestion_control: [u8; 16],
    pub tcp_congestion_len: u8,
    // Stats
    pub dev_count: AtomicU32,
}

// ============================================================================
// IPsec / XFRM
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XfrmProto {
    EspV4,
    AhV4,
    CompV4,
    EspV6,
    AhV6,
    CompV6,
    RouteOptV6,
    Dstopts,
}

pub struct XfrmState {
    pub id_spi: u32,
    pub id_proto: XfrmProto,
    pub id_daddr: [u8; 16],
    pub saddr: [u8; 16],
    pub family: u16,       // AF_INET or AF_INET6
    pub mode: XfrmMode,
    pub reqid: u32,
    pub replay_window: u32,
    pub flags: u32,
    // Lifetime
    pub lifetime_bytes_hard: u64,
    pub lifetime_bytes_soft: u64,
    pub lifetime_packets_hard: u64,
    pub lifetime_packets_soft: u64,
    pub lifetime_add_time_hard: u64,
    pub lifetime_add_time_soft: u64,
    pub lifetime_use_time_hard: u64,
    pub lifetime_use_time_soft: u64,
    // Current stats
    pub cur_bytes: AtomicU64,
    pub cur_packets: AtomicU64,
    pub cur_add_time: u64,
    pub cur_use_time: AtomicU64,
    // Algorithms
    pub aead_algo: [u8; 64],
    pub aead_algo_len: u8,
    pub aead_key_len: u32,
    pub aead_icv_len: u32,
    pub enc_algo: [u8; 64],
    pub enc_algo_len: u8,
    pub auth_algo: [u8; 64],
    pub auth_algo_len: u8,
    pub comp_algo: [u8; 64],
    pub comp_algo_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XfrmMode {
    Transport,
    Tunnel,
    RouteOptimization,
    InTrigger,
    Beet,
}
