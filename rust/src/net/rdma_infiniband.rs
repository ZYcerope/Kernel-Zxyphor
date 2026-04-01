// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - InfiniBand/RDMA verbs, RoCE, iWARP,
// Socket Direct Protocol, RDMA CM, Mellanox ConnectX driver model
// More advanced than Linux 2026 RDMA stack

/// IB transport type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdmaTransport {
    Ib = 0,
    RoCEv1 = 1,
    RoCEv2 = 2,
    Iwarp = 3,
    // Zxyphor
    ZxyDirect = 10,
}

/// IB node type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdmaNodeType {
    Unknown = 0,
    Ca = 1,           // Channel Adapter
    Switch = 2,
    Router = 3,
    Rnic = 4,         // RDMA NIC (iWARP)
    UsnicUdp = 5,
    Unspecified = 6,
}

/// QP type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpType {
    Rc = 2,                // Reliable Connected
    Uc = 3,                // Unreliable Connected
    Ud = 4,                // Unreliable Datagram
    RawIpv6 = 5,
    RawEthertype = 6,
    XrcIni = 9,
    XrcTgt = 10,
    RawPacket = 11,
    // Zxyphor
    ZxyReliableMulticast = 50,
    ZxyOrderedDatagram = 51,
}

/// QP state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpState {
    Reset = 0,
    Init = 1,
    Rtr = 2,
    Rts = 3,
    Sqd = 4,
    Sqe = 5,
    Error = 6,
}

/// Send WR opcode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrOpcode {
    RdmaWrite = 0,
    RdmaWriteWithImm = 1,
    Send = 2,
    SendWithImm = 3,
    RdmaRead = 4,
    AtomicCmpAndSwp = 5,
    AtomicFetchAndAdd = 6,
    BindMw = 8,
    SendWithInv = 9,
    Tso = 10,
    DriverSpecific = 11,
    LocalInv = 7,
    MaskedAtomicCmpSwp = 14,
    MaskedAtomicFetchAdd = 15,
    RegMr = 17,
    Flush = 18,
    AtomicWrite = 19,
}

/// Completion status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WcStatus {
    Success = 0,
    LocLenErr = 1,
    LocQpOpErr = 2,
    LocEecOpErr = 3,
    LocProtErr = 4,
    WrFlushErr = 5,
    MwBindErr = 6,
    BadRespErr = 7,
    LocAccessErr = 8,
    RemInvReqErr = 9,
    RemAccessErr = 10,
    RemOpErr = 11,
    RetryExcErr = 12,
    RnrRetryExcErr = 13,
    LocRddViolErr = 14,
    RemInvRdReqErr = 15,
    RemAbortErr = 16,
    InvEecnErr = 17,
    InvEecStateErr = 18,
    FatalErr = 19,
    RespTimeoutErr = 20,
    GeneralErr = 21,
}

/// Access flags
pub const ACCESS_LOCAL_WRITE: u32 = 1 << 0;
pub const ACCESS_REMOTE_WRITE: u32 = 1 << 1;
pub const ACCESS_REMOTE_READ: u32 = 1 << 2;
pub const ACCESS_REMOTE_ATOMIC: u32 = 1 << 3;
pub const ACCESS_MW_BIND: u32 = 1 << 4;
pub const ACCESS_ZERO_BASED: u32 = 1 << 5;
pub const ACCESS_ON_DEMAND: u32 = 1 << 6;
pub const ACCESS_HUGETLB: u32 = 1 << 7;
pub const ACCESS_FLUSH_LOCAL: u32 = 1 << 8;
pub const ACCESS_FLUSH_REMOTE: u32 = 1 << 9;

/// RDMA device capabilities
#[derive(Debug, Clone)]
pub struct RdmaDeviceCaps {
    pub fw_ver: [u8; 64],
    pub node_guid: u64,
    pub sys_image_guid: u64,
    pub max_mr_size: u64,
    pub page_size_cap: u64,
    pub vendor_id: u32,
    pub vendor_part_id: u32,
    pub hw_ver: u32,
    pub max_qp: u32,
    pub max_qp_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_sge_rd: u32,
    pub max_cq: u32,
    pub max_cqe: u32,
    pub max_mr: u32,
    pub max_pd: u32,
    pub max_qp_rd_atom: u32,
    pub max_res_rd_atom: u32,
    pub max_qp_init_rd_atom: u32,
    pub max_mcast_grp: u32,
    pub max_mcast_qp_attach: u32,
    pub max_total_mcast_qp_attach: u32,
    pub max_ah: u32,
    pub max_srq: u32,
    pub max_srq_wr: u32,
    pub max_srq_sge: u32,
    pub max_pkeys: u16,
    pub local_ca_ack_delay: u8,
    // Extended caps
    pub odp_supported: bool,
    pub rss_supported: bool,
    pub timestamp_supported: bool,
    pub raw_scatter_fcs: bool,
    pub sig_handover: bool,
    pub tag_matching: bool,
    pub pci_atomic: bool,
}

/// RDMA port info
#[derive(Debug, Clone)]
pub struct RdmaPortInfo {
    pub state: PortState,
    pub max_mtu: IbMtu,
    pub active_mtu: IbMtu,
    pub gid_tbl_len: u32,
    pub pkey_tbl_len: u16,
    pub lid: u16,
    pub sm_lid: u16,
    pub lmc: u8,
    pub max_vl_num: u8,
    pub sm_sl: u8,
    pub subnet_timeout: u8,
    pub active_width: PortWidth,
    pub active_speed: PortSpeed,
    pub phys_state: u8,
    pub transport: RdmaTransport,
    pub link_layer: LinkLayer,
}

/// Port state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Nop = 0,
    Down = 1,
    Init = 2,
    Armed = 3,
    Active = 4,
    ActiveDefer = 5,
}

/// Port width
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortWidth {
    W1x = 1,
    W2x = 16,
    W4x = 2,
    W8x = 4,
    W12x = 8,
}

/// Port speed
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpeed {
    Sdr = 1,          // 2.5 Gbps
    Ddr = 2,          // 5 Gbps
    Qdr = 4,          // 10 Gbps
    Fdr10 = 8,        // 10.3 Gbps
    Fdr = 16,         // 14 Gbps
    Edr = 32,         // 25 Gbps
    Hdr = 64,         // 50 Gbps
    Ndr = 128,        // 100 Gbps
    Xdr = 256,        // 250 Gbps
    Zdr = 512,        // 500 Gbps (Zxyphor)
}

/// IB MTU
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbMtu {
    Mtu256 = 1,
    Mtu512 = 2,
    Mtu1024 = 3,
    Mtu2048 = 4,
    Mtu4096 = 5,
}

/// Link layer
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    Unspecified = 0,
    InfiniBand = 1,
    Ethernet = 2,
}

// ============================================================================
// RoCE (RDMA over Converged Ethernet)
// ============================================================================

/// RoCE version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoceVersion {
    V1 = 1,
    V2 = 2,
}

/// RoCE congestion control
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoceCcAlgorithm {
    Dcqcn = 0,        // Data Center QCN
    Dctcp = 1,
    Timely = 2,        // RTT-based
    Hpcc = 3,          // High Precision CC
    Swift = 4,
    PowerTcp = 5,
    // Zxyphor
    ZxyAdaptive = 10,
}

/// RoCE configuration
#[derive(Debug, Clone)]
pub struct RoceConfig {
    pub version: RoceVersion,
    pub cc_algorithm: RoceCcAlgorithm,
    pub dscp: u8,
    pub ecn_enabled: bool,
    pub pfc_enabled: bool,
    pub priority: u8,
    // DCQCN parameters
    pub dcqcn_ai_rate: u32,
    pub dcqcn_hai_rate: u32,
    pub dcqcn_alpha_update_period: u32,
    pub dcqcn_rate_reduce_monitor_period: u32,
    pub dcqcn_cnp_dscp: u8,
    pub dcqcn_cnp_prio: u8,
    // Stats
    pub total_cnp_sent: u64,
    pub total_cnp_received: u64,
    pub total_ecn_marked: u64,
    pub total_rate_reductions: u64,
}

// ============================================================================
// RDMA CM (Connection Manager)
// ============================================================================

/// RDMA CM event type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdmaCmEventType {
    AddrResolved = 0,
    AddrError = 1,
    RouteResolved = 2,
    RouteError = 3,
    ConnectRequest = 4,
    ConnectResponse = 5,
    ConnectError = 6,
    Unreachable = 7,
    Rejected = 8,
    Established = 9,
    Disconnected = 10,
    DeviceRemoval = 11,
    MulticastJoin = 12,
    MulticastError = 13,
    AddrChange = 14,
    TimewaitExit = 15,
}

/// RDMA CM connection parameters
#[derive(Debug, Clone)]
pub struct RdmaCmConnParam {
    pub private_data: [u8; 256],
    pub private_data_len: u8,
    pub responder_resources: u8,
    pub initiator_depth: u8,
    pub flow_control: u8,
    pub retry_count: u8,
    pub rnr_retry_count: u8,
    pub srq: u8,
    pub qp_num: u32,
}

// ============================================================================
// GPUDirect RDMA
// ============================================================================

/// GPUDirect capabilities
#[derive(Debug, Clone)]
pub struct GpuDirectRdma {
    pub supported: bool,
    pub p2p_enabled: bool,
    pub bar_mapping_type: GpuBarMapping,
    pub gpu_vendor: GpuVendor,
    pub gpu_id: u32,
    // Stats
    pub total_gpu_direct_reads: u64,
    pub total_gpu_direct_writes: u64,
    pub total_gpu_direct_bytes: u64,
}

/// GPU BAR mapping type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuBarMapping {
    None = 0,
    Bar1 = 1,
    Bar2 = 2,
    Peer2Peer = 3,
}

/// GPU vendor for GPUDirect
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVendor {
    Unknown = 0,
    Nvidia = 1,
    Amd = 2,
    Intel = 3,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// RDMA subsystem state
#[derive(Debug, Clone)]
pub struct RdmaSubsystem {
    // Devices
    pub nr_devices: u32,
    pub nr_ib_devices: u32,
    pub nr_roce_devices: u32,
    pub nr_iwarp_devices: u32,
    // Resources
    pub total_qps: u64,
    pub total_cqs: u64,
    pub total_mrs: u64,
    pub total_pds: u64,
    pub total_ahs: u64,
    pub total_srqs: u64,
    // Performance
    pub total_send_bytes: u64,
    pub total_recv_bytes: u64,
    pub total_rdma_read_bytes: u64,
    pub total_rdma_write_bytes: u64,
    pub total_atomic_ops: u64,
    // Errors
    pub total_qp_errors: u64,
    pub total_cqe_errors: u64,
    pub total_mr_errors: u64,
    // Connections
    pub total_connections: u64,
    pub total_disconnections: u64,
    pub total_connection_errors: u64,
    // RoCE
    pub total_ecn_events: u64,
    pub total_cnp_events: u64,
    // GPUDirect
    pub gpu_direct_enabled: bool,
    pub total_gpu_direct_bytes: u64,
    // Zxyphor
    pub zxy_smart_routing: bool,
    pub initialized: bool,
}
