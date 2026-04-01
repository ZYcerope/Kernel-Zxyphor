// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Rust - Network Device Model and Driver Framework
// netdev_ops, ethtool, NAPI, XPS/RPS, net_device features,
// traffic control (tc), qdisc, netlink, devlink
// More advanced than Linux 2026 network device stack

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// ============================================================================
// Net Device Flags
// ============================================================================

pub const IFF_UP: u32           = 1 << 0;
pub const IFF_BROADCAST: u32   = 1 << 1;
pub const IFF_DEBUG: u32       = 1 << 2;
pub const IFF_LOOPBACK: u32    = 1 << 3;
pub const IFF_POINTOPOINT: u32 = 1 << 4;
pub const IFF_NOTRAILERS: u32  = 1 << 5;
pub const IFF_RUNNING: u32     = 1 << 6;
pub const IFF_NOARP: u32       = 1 << 7;
pub const IFF_PROMISC: u32     = 1 << 8;
pub const IFF_ALLMULTI: u32    = 1 << 9;
pub const IFF_MASTER: u32      = 1 << 10;
pub const IFF_SLAVE: u32       = 1 << 11;
pub const IFF_MULTICAST: u32   = 1 << 12;
pub const IFF_PORTSEL: u32     = 1 << 13;
pub const IFF_AUTOMEDIA: u32   = 1 << 14;
pub const IFF_DYNAMIC: u32     = 1 << 15;
pub const IFF_LOWER_UP: u32    = 1 << 16;
pub const IFF_DORMANT: u32     = 1 << 17;
pub const IFF_ECHO: u32        = 1 << 18;

// ============================================================================
// Net Device Features
// ============================================================================

pub const NETIF_F_SG: u64              = 1 << 0;
pub const NETIF_F_IP_CSUM: u64        = 1 << 1;
pub const NETIF_F_HW_CSUM: u64        = 1 << 2;
pub const NETIF_F_IPV6_CSUM: u64      = 1 << 3;
pub const NETIF_F_HIGHDMA: u64        = 1 << 4;
pub const NETIF_F_FRAGLIST: u64       = 1 << 5;
pub const NETIF_F_TSO: u64            = 1 << 6;
pub const NETIF_F_TSO6: u64           = 1 << 7;
pub const NETIF_F_TSO_ECN: u64        = 1 << 8;
pub const NETIF_F_UFO: u64            = 1 << 9;
pub const NETIF_F_GSO: u64            = 1 << 10;
pub const NETIF_F_GRO: u64            = 1 << 11;
pub const NETIF_F_GRO_HW: u64         = 1 << 12;
pub const NETIF_F_LRO: u64            = 1 << 13;
pub const NETIF_F_RXHASH: u64         = 1 << 14;
pub const NETIF_F_RXCSUM: u64         = 1 << 15;
pub const NETIF_F_VLAN_CHALLENGED: u64 = 1 << 16;
pub const NETIF_F_HW_VLAN_CTAG_TX: u64 = 1 << 17;
pub const NETIF_F_HW_VLAN_CTAG_RX: u64 = 1 << 18;
pub const NETIF_F_HW_VLAN_CTAG_FILTER: u64 = 1 << 19;
pub const NETIF_F_VLAN_OFFLOAD: u64   = 1 << 20;
pub const NETIF_F_GSO_GRE: u64        = 1 << 21;
pub const NETIF_F_GSO_UDP_TUNNEL: u64 = 1 << 22;
pub const NETIF_F_GSO_IPXIP4: u64     = 1 << 23;
pub const NETIF_F_GSO_IPXIP6: u64     = 1 << 24;
pub const NETIF_F_GSO_UDP_L4: u64     = 1 << 25;
pub const NETIF_F_GSO_PARTIAL: u64    = 1 << 26;
pub const NETIF_F_GSO_TUNNEL_REMCSUM: u64 = 1 << 27;
pub const NETIF_F_HW_TLS_TX: u64      = 1 << 28;
pub const NETIF_F_HW_TLS_RX: u64      = 1 << 29;
pub const NETIF_F_GRO_FRAGLIST: u64   = 1 << 30;
pub const NETIF_F_HW_MACSEC: u64      = 1u64 << 31;
pub const NETIF_F_GRO_UDP_FWD: u64    = 1u64 << 32;
pub const NETIF_F_HW_HSR_TAG_INS: u64 = 1u64 << 33;
pub const NETIF_F_HW_HSR_TAG_RM: u64  = 1u64 << 34;
pub const NETIF_F_HW_HSR_FWD: u64     = 1u64 << 35;
pub const NETIF_F_HW_HSR_DUP: u64     = 1u64 << 36;

// ============================================================================
// Link Speed / Duplex
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LinkSpeed {
    Speed10 = 10,
    Speed100 = 100,
    Speed1000 = 1000,
    Speed2500 = 2500,
    Speed5000 = 5000,
    Speed10000 = 10000,
    Speed14000 = 14000,
    Speed20000 = 20000,
    Speed25000 = 25000,
    Speed40000 = 40000,
    Speed50000 = 50000,
    Speed56000 = 56000,
    Speed100000 = 100000,
    Speed200000 = 200000,
    Speed400000 = 400000,
    Speed800000 = 800000,
    Unknown = 0xFFFFFFFF,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Duplex {
    Half = 0,
    Full = 1,
    Unknown = 0xFF,
}

// ============================================================================
// Ethtool
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum EthtoolCmd {
    GSET = 0x01,
    SSET = 0x02,
    GDRVINFO = 0x03,
    GREGS = 0x04,
    GWOL = 0x05,
    SWOL = 0x06,
    GMSGLVL = 0x07,
    SMSGLVL = 0x08,
    NWAY_RST = 0x09,
    GLINK = 0x0A,
    GEEPROM = 0x0B,
    SEEPROM = 0x0C,
    GCOALESCE = 0x0E,
    SCOALESCE = 0x0F,
    GRINGPARAM = 0x10,
    SRINGPARAM = 0x11,
    GPAUSEPARAM = 0x12,
    SPAUSEPARAM = 0x13,
    GRXCSUM = 0x14,
    SRXCSUM = 0x15,
    GTXCSUM = 0x16,
    STXCSUM = 0x17,
    GSG = 0x18,
    SSG = 0x19,
    GETTSO = 0x1E,
    SETTSO = 0x1F,
    GFLAGS = 0x25,
    SFLAGS = 0x26,
    GPFLAGS = 0x27,
    SPFLAGS = 0x28,
    GSTATS = 0x1D,
    GRXFH = 0x29,
    SRXFH = 0x2A,
    GRXRINGS = 0x2D,
    GRXCLSRLCNT = 0x2E,
    GRXCLSRULE = 0x2F,
    GRXCLSRLALL = 0x30,
    SRXCLSRLDEL = 0x31,
    SRXCLSRLINS = 0x32,
    GCHANNELS = 0x3C,
    SCHANNELS = 0x3D,
    GFECPARAM = 0x50,
    SFECPARAM = 0x51,
    GLINKSETTINGS = 0x4C,
    SLINKSETTINGS = 0x4D,
}

pub struct EthtoolCoalesce {
    pub rx_coalesce_usecs: u32,
    pub rx_max_coalesced_frames: u32,
    pub rx_coalesce_usecs_irq: u32,
    pub rx_max_coalesced_frames_irq: u32,
    pub tx_coalesce_usecs: u32,
    pub tx_max_coalesced_frames: u32,
    pub tx_coalesce_usecs_irq: u32,
    pub tx_max_coalesced_frames_irq: u32,
    pub stats_block_coalesce_usecs: u32,
    pub use_adaptive_rx_coalesce: bool,
    pub use_adaptive_tx_coalesce: bool,
    pub pkt_rate_low: u32,
    pub rx_coalesce_usecs_low: u32,
    pub rx_max_coalesced_frames_low: u32,
    pub tx_coalesce_usecs_low: u32,
    pub tx_max_coalesced_frames_low: u32,
    pub pkt_rate_high: u32,
    pub rx_coalesce_usecs_high: u32,
    pub rx_max_coalesced_frames_high: u32,
    pub tx_coalesce_usecs_high: u32,
    pub tx_max_coalesced_frames_high: u32,
    pub rate_sample_interval: u32,
    pub cqe_mode_rx: bool,
    pub cqe_mode_tx: bool,
    pub tx_aggr_max_bytes: u32,
    pub tx_aggr_max_frames: u32,
    pub tx_aggr_time_usecs: u32,
}

pub struct EthtoolRingParam {
    pub rx_max_pending: u32,
    pub rx_mini_max_pending: u32,
    pub rx_jumbo_max_pending: u32,
    pub tx_max_pending: u32,
    pub rx_pending: u32,
    pub rx_mini_pending: u32,
    pub rx_jumbo_pending: u32,
    pub tx_pending: u32,
    pub rx_buf_len: u32,
    pub cqe_size: u32,
    pub tx_push: bool,
    pub rx_push: bool,
    pub tx_push_buf_len: u32,
    pub tx_push_buf_len_max: u32,
}

pub struct EthtoolChannels {
    pub max_rx: u32,
    pub max_tx: u32,
    pub max_other: u32,
    pub max_combined: u32,
    pub rx_count: u32,
    pub tx_count: u32,
    pub other_count: u32,
    pub combined_count: u32,
}

// ============================================================================
// NAPI
// ============================================================================

pub struct NapiStruct {
    pub state: u32,
    pub weight: i32,
    pub gro_bitmask: u64,
    pub gro_count: u32,
    pub poll_owner: i32,
    pub defer_hard_irqs_count: u32,
    pub rx_count: u64,
    pub budget: i32,
    // NAPI busy poll
    pub prefer_busy_poll: bool,
    pub napi_id: u32,
    // GRO
    pub gro_hash_buckets: [8; u64],
    pub gro_list_count: u32,
}

pub const NAPI_STATE_SCHED: u32     = 0;
pub const NAPI_STATE_DISABLE: u32   = 1;
pub const NAPI_STATE_NPSVC: u32     = 2;
pub const NAPI_STATE_LISTED: u32    = 3;
pub const NAPI_STATE_NO_BUSY_POLL: u32 = 4;
pub const NAPI_STATE_IN_BUSY_POLL: u32 = 5;
pub const NAPI_STATE_PREFER_BUSY_POLL: u32 = 6;
pub const NAPI_STATE_THREADED: u32  = 7;
pub const NAPI_STATE_SCHED_THREADED: u32 = 8;

// ============================================================================
// Traffic Control (tc) - Qdisc
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QdiscType {
    Pfifo = 0,
    PfifoFast = 1,
    Bfifo = 2,
    Sfq = 3,         // Stochastic Fair Queuing
    Tbf = 4,         // Token Bucket Filter
    Htb = 5,         // Hierarchical Token Bucket
    Cbq = 6,         // Class Based Queuing
    Prio = 7,
    Red = 8,         // Random Early Detection
    Fq = 9,          // Fair Queuing
    FqCodel = 10,    // FQ + CoDel
    Codel = 11,      // Controlled Delay
    Cake = 12,       // Common Applications Kept Enhanced
    Netem = 13,      // Network Emulator
    Ingress = 14,
    Clsact = 15,
    Mq = 16,         // Multi-queue
    Mqprio = 17,     // Multi-queue Priority
    Drr = 18,        // Deficit Round Robin
    Ets = 19,        // Enhanced Transmission Selection
    Taprio = 20,     // Time-Aware Priority Shaper (TSN)
    // Zxyphor
    ZxyAdaptive = 21,
}

pub struct QdiscStats {
    pub qlen: u32,
    pub backlog: u32,
    pub drops: u64,
    pub requeues: u64,
    pub overlimits: u64,
    pub enqueued: u64,
    pub dequeued: u64,
}

pub struct FqCodelParams {
    pub target: u32,          // Target delay (us)
    pub interval: u32,        // Width of moving time window (us)
    pub quantum: u32,         // Bytes for round-robin
    pub limit: u32,           // Max number of packets
    pub flows: u32,           // Number of flow queues
    pub ecn: bool,
    pub ce_threshold: u32,
    pub drop_batch_size: u32,
    pub memory_limit: u32,
}

pub struct HtbParams {
    pub rate: u64,            // bps
    pub ceil: u64,            // bps
    pub burst: u32,           // bytes
    pub cburst: u32,          // bytes
    pub quantum: u32,
    pub prio: u8,
    pub level: u8,
    pub direct_pkts: u64,
}

pub struct CakeParams {
    pub bandwidth: u64,       // bps
    pub atm_compensation: bool,
    pub overhead: i32,
    pub mpu: u32,
    pub nat: bool,
    pub wash: bool,
    pub split_gso: bool,
    pub ack_filter: u8,
    pub fwmark: u32,
    pub diffserv_mode: u8,
    pub flow_mode: u8,
    pub rtt: u32,             // us
    pub target: u32,          // us
    pub interval: u32,        // us
}

pub struct TaprioEntry {
    pub command: u8,          // SetGateStates
    pub gate_mask: u8,        // TC bitmask
    pub interval: u32,        // ns
}

pub struct TaprioParams {
    pub base_time: i64,       // ns since epoch
    pub cycle_time: i64,      // ns
    pub cycle_time_extension: i64,
    pub entries: [64; TaprioEntry],
    pub nr_entries: u32,
    pub txtime_delay: u32,
    pub flags: u32,
}

// ============================================================================
// XPS/RPS (Transmit/Receive Packet Steering)
// ============================================================================

pub struct XpsConfig {
    pub cpus_map: [64; u64],      // Per-queue CPU bitmask
    pub rxqs_map: [64; u64],      // Per-queue RX queue mapping
    pub nr_queues: u32,
}

pub struct RpsConfig {
    pub cpu_map: [64; u64],       // Per-queue CPU bitmask
    pub flow_table_size: u32,     // Power of 2
    pub nr_queues: u32,
}

pub struct RfsConfig {
    pub global_table_size: u32,
    pub per_queue_table_size: u32,
}

// ============================================================================
// Devlink
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DevlinkInfoVersionType {
    Fixed = 0,
    Running = 1,
    Stored = 2,
}

pub struct DevlinkPort {
    pub index: u32,
    pub port_type: DevlinkPortType,
    pub flavour: DevlinkPortFlavour,
    pub number: u32,
    pub split_count: u32,
    pub split_group: u32,
    pub pci_pf_number: u32,
    pub pci_vf_number: u32,
    pub pci_sf_number: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DevlinkPortType {
    NotSet = 0,
    Auto = 1,
    Eth = 2,
    Ib = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DevlinkPortFlavour {
    Physical = 0,
    Cpu = 1,
    Dsa = 2,
    PciPf = 3,
    PciVf = 4,
    Virtual = 5,
    Unused = 6,
    PciSf = 7,
}

pub struct DevlinkParams {
    pub name: [32; u8],
    pub generic: bool,
    pub param_type: u8,
    pub supported_cmodes: u8,
}

// ============================================================================
// Net Device Stats
// ============================================================================

pub struct RtnlLinkStats64 {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
    // Detailed rx errors
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    // Detailed tx errors
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    // Compression
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,
    // Additional
    pub rx_otherhost_dropped: u64,
}

// ============================================================================
// Net Device - Core Structure
// ============================================================================

pub struct NetDevice {
    pub name: [16; u8],
    pub ifindex: i32,
    pub iflink: i32,
    // Addresses
    pub dev_addr: [32; u8],
    pub addr_len: u8,
    pub broadcast: [32; u8],
    // Type
    pub dev_type: u16,       // ARPHRD_*
    pub flags: u32,          // IFF_*
    pub priv_flags: u64,
    // Features
    pub features: u64,
    pub hw_features: u64,
    pub vlan_features: u64,
    pub hw_enc_features: u64,
    pub mpls_features: u64,
    pub gso_max_size: u32,
    pub gso_max_segs: u16,
    pub gso_min_segs: u32,
    pub tso_max_size: u32,
    pub tso_max_segs: u16,
    // MTU
    pub mtu: u32,
    pub min_mtu: u32,
    pub max_mtu: u32,
    // Link
    pub link_speed: LinkSpeed,
    pub duplex: Duplex,
    // Queues
    pub num_tx_queues: u32,
    pub real_num_tx_queues: u32,
    pub num_rx_queues: u32,
    pub real_num_rx_queues: u32,
    // NAPI
    pub napi_list_count: u32,
    // Stats
    pub stats: RtnlLinkStats64,
    // Ethtool
    pub ethtool_coalesce: EthtoolCoalesce,
    pub ethtool_ring: EthtoolRingParam,
    pub ethtool_channels: EthtoolChannels,
    // XDP
    pub xdp_prog: u64,
    pub xdp_features: u64,
    // TC/Qdisc
    pub qdisc_type: QdiscType,
    pub tc_num_queues: u32,
    // VLAN
    pub vlan_id: u16,
    pub nested_level: u8,
    // Bonding/Teaming
    pub master_ifindex: i32,
    // Network namespace
    pub net_ns: u64,
    // Power management
    pub wol_enabled: bool,
    // Carrier
    pub carrier: bool,
    pub carrier_changes: u32,
    pub carrier_up_count: u32,
    pub carrier_down_count: u32,
    // Timestamps
    pub last_rx: u64,
    // Watchdog
    pub watchdog_timeo: u64,
    pub trans_start: u64,
    // Zxyphor
    pub zxy_offload_engine: bool,
    pub zxy_hw_timestamp: bool,
}

// ============================================================================
// Network Subsystem Manager
// ============================================================================

pub struct NetworkDeviceManager {
    pub nr_devices: u32,
    pub nr_namespaces: u32,
    // Counters
    pub total_rx_packets: u64,
    pub total_tx_packets: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub total_rx_errors: u64,
    pub total_tx_errors: u64,
    // Configuration
    pub default_qdisc: QdiscType,
    pub busy_poll_us: u32,
    pub busy_read_us: u32,
    pub gro_flush_timeout: u64,
    pub napi_defer_hard_irqs: u32,
    // XPS/RPS
    pub rps_sock_flow_entries: u32,
    // Devlink
    pub nr_devlink_ports: u32,
    // Zxyphor
    pub zxy_smart_offload: bool,
    pub initialized: bool,
}
