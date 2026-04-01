// Zxyphor Kernel - MPTCP (Multipath TCP), SMC-R/SMC-D,
// TCP Congestion Control Algorithms, TCP Fast Open,
// TCP MD5/AO Signatures, TCP Metrics, TCP Repair
// More advanced than Linux 2026 transport layer

use core::fmt;

// ============================================================================
// MPTCP - Multipath TCP (RFC 8684)
// ============================================================================

/// MPTCP version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MptcpVersion {
    V0 = 0,  // RFC 6824
    V1 = 1,  // RFC 8684
}

/// MPTCP subflow flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct MptcpSubflowFlags(pub u32);

impl MptcpSubflowFlags {
    pub const BACKUP: Self = Self(1 << 0);
    pub const FULLMESH: Self = Self(1 << 1);
    pub const SIGNAL: Self = Self(1 << 2);
    pub const SUBFLOW: Self = Self(1 << 3);
    pub const CONNECTED: Self = Self(1 << 4);
    pub const VALID: Self = Self(1 << 5);
    // Zxyphor extensions
    pub const ZXY_LOW_LATENCY: Self = Self(1 << 16);
    pub const ZXY_HIGH_BANDWIDTH: Self = Self(1 << 17);
    pub const ZXY_FAILOVER_ONLY: Self = Self(1 << 18);
}

/// MPTCP path manager type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MptcpPmType {
    Default = 0,
    Userspace = 1,
    // Zxyphor extensions
    ZxyAdaptive = 100,
    ZxyMLBased = 101,
}

/// MPTCP scheduler type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MptcpScheduler {
    Default = 0,          // round-robin
    Redundant = 1,
    // Zxyphor
    ZxyLatencyAware = 100,
    ZxyWeighted = 101,
    ZxyBandwidthAgg = 102,
}

/// MPTCP socket option
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum MptcpSockOpt {
    Info = 1,
    FullMesh = 2,
    Subflow = 3,
    RcvBufSize = 4,
    Scheduler = 5,
}

/// MPTCP connection info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MptcpInfo {
    pub mptcpi_subflows: u8,
    pub mptcpi_add_addr_signal: u8,
    pub mptcpi_add_addr_accepted: u8,
    pub mptcpi_subflows_max: u8,
    pub mptcpi_add_addr_signal_max: u8,
    pub mptcpi_add_addr_accepted_max: u8,
    pub mptcpi_flags: u32,
    pub mptcpi_token: u32,
    pub mptcpi_write_seq: u64,
    pub mptcpi_snd_una: u64,
    pub mptcpi_rcv_nxt: u64,
    pub mptcpi_local_addr_used: u8,
    pub mptcpi_local_addr_max: u8,
    pub mptcpi_csum_enabled: u8,
    pub mptcpi_retransmits: u32,
    pub mptcpi_bytes_sent: u64,
    pub mptcpi_bytes_received: u64,
    pub mptcpi_bytes_retrans: u64,
    pub mptcpi_subflows_total: u32,
    pub mptcpi_last_data_sent: u64,
    pub mptcpi_last_data_recv: u64,
}

/// MPTCP address info for path management
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MptcpAddrInfo {
    pub id: u8,
    pub flags: MptcpSubflowFlags,
    pub family: u16,
    pub port: u16,
    pub addr4: u32,
    pub addr6: [u8; 16],
    pub if_index: i32,
}

/// MPTCP path manager limits
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MptcpPmLimits {
    pub subflows_max: u32,
    pub add_addr_accepted_max: u32,
    pub add_addr_signal_max: u32,
    pub local_addr_max: u32,
}

// ============================================================================
// SMC - Shared Memory Communications
// ============================================================================

/// SMC type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SmcType {
    SmcR = 0,    // SMC-R over RDMA
    SmcD = 1,    // SMC-D over ISM
}

/// SMC state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SmcState {
    Init = 0,
    Active = 1,
    PeerCloseWait = 2,
    AppFinCloseWait = 3,
    Closed = 4,
    ListenStopped = 5,
}

/// SMC-R connection info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SmcRConnInfo {
    pub peer_gid: [u8; 16],
    pub link_type: SmcRLinkType,
    pub link_state: SmcRLinkState,
    pub link_uid: u32,
    pub net_cookie: u64,
    pub sndbuf_size: u32,
    pub rmbe_size: u32,
    pub peer_rmbe_size: u32,
    pub tx_prod_flags_addr: u64,
    pub rx_cons_flags_addr: u64,
    pub peer_conn_idx: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SmcRLinkType {
    RoCEv1 = 0,
    RoCEv2 = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SmcRLinkState {
    Inactive = 0,
    Activating = 1,
    Active = 2,
}

/// SMC-D connection info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SmcDConnInfo {
    pub ism_dev_gid: u64,
    pub ism_chid: u16,
    pub peer_gid: u64,
    pub conn_state: SmcState,
    pub token: u64,
    pub sndbuf_size: u32,
    pub dmbe_size: u32,
}

/// SMC statistics
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SmcStats {
    pub clnt_hshake_err_cnt: u64,
    pub srv_hshake_err_cnt: u64,
    pub clnt_v1_succ_cnt: u64,
    pub clnt_v2_succ_cnt: u64,
    pub srv_v1_succ_cnt: u64,
    pub srv_v2_succ_cnt: u64,
    pub sendpg_cnt: u64,
    pub urg_data_cnt: u64,
    pub splice_cnt: u64,
    pub cork_cnt: u64,
    pub sendmsg_cnt: u64,
    pub recvmsg_cnt: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_cnt: u64,
    pub tx_cnt: u64,
    pub buf_alloc_cnt: u64,
    pub buf_reuse_cnt: u64,
}

// ============================================================================
// TCP Congestion Control
// ============================================================================

/// TCP congestion control algorithm
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpCongAlgo {
    Reno = 0,
    Cubic = 1,
    Bbr = 2,
    BbrV2 = 3,
    BbrV3 = 4,
    Dctcp = 5,
    Vegas = 6,
    Westwood = 7,
    Htcp = 8,
    Hybla = 9,
    Illinois = 10,
    Scalable = 11,
    Veno = 12,
    Yeah = 13,
    Cdg = 14,
    Nv = 15,
    Lp = 16,
    // Zxyphor
    ZxyAdaptive = 100,
    ZxyMultipath = 101,
    ZxyUltraLow = 102,
}

/// TCP congestion state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TcpCaState {
    Open = 0,
    Disorder = 1,
    Cwr = 2,
    Recovery = 3,
    Loss = 4,
}

/// BBR mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BbrMode {
    Startup = 0,
    Drain = 1,
    ProbeBw = 2,
    ProbeRtt = 3,
}

/// BBR parameters
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BbrParams {
    pub pacing_gain: u32,
    pub cwnd_gain: u32,
    pub full_bw_cnt: u32,
    pub full_bw_reached: bool,
    pub round_start: bool,
    pub rtt_cnt: u32,
    pub next_rtt_delivered: u64,
    pub prior_cwnd: u32,
    pub probe_rtt_round_done: bool,
    pub probe_rtt_done_stamp: u64,
    pub extra_acked: [u32; 2],
    pub lt_bw: u32,
    pub lt_rtt_cnt: u32,
    pub lt_last_delivered: u64,
    pub lt_last_stamp: u64,
    pub lt_last_lost: u32,
    pub lt_use_bw: bool,
    pub mode: BbrMode,
}

/// BBRv2 inflight params
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Bbrv2InflightParams {
    pub ecn_factor: u16,      // inflight_hi = inflight * ecn_factor
    pub loss_thresh: u16,     // loss-based inflight reduction
    pub headroom: u16,
    pub bw_probe_rtt_gain: u16,
    pub bw_probe_max_rounds: u8,
}

/// DCTCP parameters
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DctcpParams {
    pub ce_state: bool,
    pub alpha: u32,
    pub delayed_ack_reserved: u32,
    pub ece_bytes: u64,
    pub total_bytes: u64,
    pub next_seq: u32,
    pub dctcp_alpha: u32,
    pub shift_g: u32,
}

/// TCP congestion ops
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpCongOps {
    pub name: [u8; 16],
    pub name_len: u8,
    pub flags: TcpCongFlags,
    pub key: u32,
    pub owner_module: u32,
    pub required_features: u32,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct TcpCongFlags(pub u32);

impl TcpCongFlags {
    pub const NON_RESTRICTED: Self = Self(1 << 0);
    pub const NEEDS_ECN: Self = Self(1 << 1);
    pub const HAS_CWND_EVENT: Self = Self(1 << 2);
}

// ============================================================================
// TCP Fast Open
// ============================================================================

/// TFO cookie
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TfoCookieVal {
    pub cookie: [u8; 16],
    pub len: u8,
    pub exp: bool,
}

/// TFO options
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct TfoFlags(pub u32);

impl TfoFlags {
    pub const CLIENT_ENABLE: Self = Self(1);
    pub const SERVER_ENABLE: Self = Self(2);
    pub const CLIENT_NO_COOKIE: Self = Self(4);
    pub const SERVER_COOKIE_NOT_REQD: Self = Self(0x200);
    pub const SERVER_WO_SOCKOPT1: Self = Self(0x400);
    pub const SERVER_WO_SOCKOPT2: Self = Self(0x800);
}

/// TFO statistics
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TfoStats {
    pub cookie_req_cnt: u64,
    pub cookie_rcv_cnt: u64,
    pub cookie_fback_cnt: u64,
    pub syn_data_cnt: u64,
    pub syn_data_acked_cnt: u64,
    pub listen_overflow_cnt: u64,
    pub passive_fail_cnt: u64,
}

// ============================================================================
// TCP Authentication - MD5/AO
// ============================================================================

/// TCP-MD5 key entry
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpMd5Key {
    pub family: u16,
    pub addr4: u32,
    pub addr6: [u8; 16],
    pub prefixlen: u8,
    pub key: [u8; 80],
    pub keylen: u8,
    pub l3mdev: bool,
    pub flags: u8,
}

/// TCP-AO (Authentication Option, RFC 5925) key
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpAoKey {
    pub sndid: u8,
    pub rcvid: u8,
    pub algo: TcpAoAlgo,
    pub key: [u8; 80],
    pub keylen: u8,
    pub maclen: u8,
    pub family: u16,
    pub addr4: u32,
    pub addr6: [u8; 16],
    pub prefixlen: u8,
    pub ifindex: i32,
    pub current_key: bool,
    pub rnext_key: bool,
    pub flags: TcpAoKeyFlags,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TcpAoAlgo {
    HmacSha1_96 = 0,
    AesCmac_96 = 1,
    HmacSha256_128 = 2,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct TcpAoKeyFlags(pub u8);

impl TcpAoKeyFlags {
    pub const LOCK_NONE: Self = Self(0);
    pub const LOCK_AO: Self = Self(1);
    pub const LOCK_NOT: Self = Self(2);
}

/// TCP-AO info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpAoInfo {
    pub set_current: bool,
    pub set_rnext: bool,
    pub ao_required: bool,
    pub current_key: u8,
    pub rnext: u8,
    pub pkt_good: u64,
    pub pkt_bad: u64,
    pub pkt_key_not_found: u64,
    pub pkt_ao_required: u64,
    pub pkt_dropped_icmp: u64,
}

// ============================================================================
// TCP Metrics
// ============================================================================

/// TCP metrics storage attributes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TcpMetricAttr {
    Unspec = 0,
    Addr4 = 1,
    Addr6 = 2,
    Age = 3,
    TwTimeout = 4,
    RecvRtt = 5,
    Rtt = 6,
    RttVar = 7,
    Ssthresh = 8,
    Cwnd = 9,
    Reodering = 10,
    Fopen = 11,
}

/// TCP metrics entry
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpMetricsEntry {
    pub dest_addr4: u32,
    pub dest_addr6: [u8; 16],
    pub family: u16,
    pub age_ms: u64,
    pub rtt_us: u32,
    pub rttvar_us: u32,
    pub ssthresh: u32,
    pub cwnd: u32,
    pub reordering: u32,
    pub recv_rtt_us: u32,
    pub tw_ts_stamp: u32,
    pub tfo_cookie: TfoCookieVal,
    pub tfo_syn_loss_count: u32,
}

// ============================================================================
// TCP Repair
// ============================================================================

/// TCP repair socket options
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum TcpRepairOpt {
    Off = 0,
    On = 1,
    OffNoWp = 2,
}

/// TCP repair queue type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TcpRepairQueue {
    NoQueue = 0,
    RecvQueue = 1,
    SendQueue = 2,
}

/// TCP repair window
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpRepairWindow {
    pub snd_wl1: u32,
    pub snd_wnd: u32,
    pub max_window: u32,
    pub rcv_wnd: u32,
    pub rcv_wup: u32,
}

/// TCP state for repair
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TcpStateRepair {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynRecv = 12,
}

// ============================================================================
// TCP Socket Options
// ============================================================================

/// TCP socket option level constants
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum TcpSockOpt {
    Nodelay = 1,
    MaxSeg = 2,
    Cork = 3,
    Keepidle = 4,
    Keepintvl = 5,
    Keepcnt = 6,
    Syncnt = 7,
    LingerTimeout = 8,
    DeferAccept = 9,
    WindowClamp = 10,
    Info = 11,
    Quickack = 12,
    Congestion = 13,
    Md5sig = 14,
    ThinLinearTimeouts = 16,
    ThinDuplex = 17,
    UserTimeout = 18,
    Repair = 19,
    RepairQueue = 20,
    QueueSeq = 21,
    RepairOptions = 22,
    Fastopen = 23,
    Timestamp = 24,
    NotsentLowat = 25,
    CcInfo = 26,
    SaveSyn = 27,
    SavedSyn = 28,
    RepairWindow = 29,
    FastopenConnect = 30,
    UlpInfo = 31,
    ZeroCopyReceive = 32,
    TxDelay = 37,
    AoAddKey = 38,
    AoDelKey = 39,
    AoInfo = 40,
    AoGetKeys = 41,
    AoRepair = 42,
}

/// TCP info from getsockopt
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpInfoFull {
    pub state: u8,
    pub ca_state: u8,
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    pub snd_wscale_rcv_wscale: u8,
    pub delivery_rate_app_limited: u8,
    pub rto: u32,
    pub ato: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub fackets: u32,
    // Times
    pub last_data_sent: u32,
    pub last_ack_sent: u32,
    pub last_data_recv: u32,
    pub last_ack_recv: u32,
    // Metrics
    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    pub rtt: u32,
    pub rttvar: u32,
    pub snd_ssthresh: u32,
    pub snd_cwnd: u32,
    pub advmss: u32,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub total_retrans: u32,
    // Extended
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    pub notsent_bytes: u32,
    pub min_rtt: u32,
    pub data_segs_in: u32,
    pub data_segs_out: u32,
    pub delivery_rate: u64,
    pub busy_time: u64,
    pub rwnd_limited: u64,
    pub sndbuf_limited: u64,
    pub delivered: u32,
    pub delivered_ce: u32,
    pub bytes_sent: u64,
    pub bytes_retrans: u64,
    pub dsack_dups: u32,
    pub reord_seen: u32,
    pub rcv_ooopack: u32,
    pub snd_wnd: u32,
    pub rcv_wnd: u32,
    pub rehash: u32,
    pub total_rto: u16,
    pub total_rto_recoveries: u16,
    pub total_rto_time: u32,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct MptcpSmcSubsystem {
    pub mptcp_enabled: bool,
    pub mptcp_version: MptcpVersion,
    pub mptcp_pm_type: MptcpPmType,
    pub mptcp_scheduler: MptcpScheduler,
    pub mptcp_connections: u64,
    pub mptcp_subflows: u64,
    pub smc_enabled: bool,
    pub smc_r_connections: u64,
    pub smc_d_connections: u64,
    pub default_ca: TcpCongAlgo,
    pub tfo_enabled: bool,
    pub tfo_client_cnt: u64,
    pub tfo_server_cnt: u64,
    pub tcp_ao_enabled: bool,
    pub tcp_ao_keys: u32,
    pub tcp_metrics_entries: u64,
    pub initialized: bool,
}

impl MptcpSmcSubsystem {
    pub const fn new() -> Self {
        Self {
            mptcp_enabled: true,
            mptcp_version: MptcpVersion::V1,
            mptcp_pm_type: MptcpPmType::Default,
            mptcp_scheduler: MptcpScheduler::Default,
            mptcp_connections: 0,
            mptcp_subflows: 0,
            smc_enabled: false,
            smc_r_connections: 0,
            smc_d_connections: 0,
            default_ca: TcpCongAlgo::Cubic,
            tfo_enabled: true,
            tfo_client_cnt: 0,
            tfo_server_cnt: 0,
            tcp_ao_enabled: false,
            tcp_ao_keys: 0,
            tcp_metrics_entries: 0,
            initialized: false,
        }
    }
}
