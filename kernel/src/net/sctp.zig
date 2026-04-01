// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - SCTP (Stream Control Transmission Protocol)
// RFC 9260, multi-homing, multi-streaming, SCTP AUTH, PR-SCTP,
// SCTP over UDP, CMT, NR-SACK, SCTP extensions
// More advanced than Linux 2026 networking stack

const std = @import("std");

// ============================================================================
// SCTP Header & Chunks
// ============================================================================

pub const SCTP_HEADER_SIZE: u32 = 12;

pub const SctpHeader = packed struct {
    src_port: u16,
    dst_port: u16,
    vtag: u32,           // Verification Tag
    checksum: u32,       // CRC-32c
};

pub const SctpChunkType = enum(u8) {
    data = 0,
    init = 1,
    init_ack = 2,
    sack = 3,
    heartbeat = 4,
    heartbeat_ack = 5,
    abort = 6,
    shutdown = 7,
    shutdown_ack = 8,
    error = 9,
    cookie_echo = 10,
    cookie_ack = 11,
    ecne = 12,           // ECN Echo
    cwr = 13,            // Congestion Window Reduced
    shutdown_complete = 14,
    // Extensions
    auth = 15,            // RFC 4895
    nr_sack = 16,         // NR-SACK
    i_data = 64,          // Interleaving data (RFC 8260)
    asconf_ack = 0x80,
    re_config = 130,       // RFC 6525
    pad = 132,
    forward_tsn = 192,    // PR-SCTP (RFC 3758)
    asconf = 193,          // RFC 5061
    i_forward_tsn = 194,   // I-Forward-TSN
    _,
};

pub const SctpChunkFlags = packed struct(u8) {
    bit0: bool = false,    // T-bit for ABORT, U-bit for DATA, etc
    bit1: bool = false,    // B (beginning) for DATA
    bit2: bool = false,    // E (ending) for DATA
    bit3: bool = false,    // I (immediate) for SACK
    _reserved: u4 = 0,
};

pub const SctpChunkHeader = packed struct {
    chunk_type: u8,
    chunk_flags: u8,
    length: u16,
};

// ============================================================================
// DATA / I-DATA Chunks
// ============================================================================

pub const SctpDataChunk = packed struct {
    header: SctpChunkHeader,
    tsn: u32,
    stream_id: u16,
    stream_seq: u16,
    ppid: u32,           // Payload Protocol Identifier
    // Variable-length user data follows
};

pub const SctpIDataChunk = packed struct {
    header: SctpChunkHeader,
    tsn: u32,
    stream_id: u16,
    _reserved: u16,
    mid: u32,            // Message Identifier
    ppid_or_fsn: u32,    // PPID (first fragment) or FSN
};

// Well-known PPIDs
pub const SCTP_PPID_IUA: u32 = 1;
pub const SCTP_PPID_M2UA: u32 = 2;
pub const SCTP_PPID_M3UA: u32 = 3;
pub const SCTP_PPID_SUA: u32 = 4;
pub const SCTP_PPID_M2PA: u32 = 5;
pub const SCTP_PPID_V5UA: u32 = 6;
pub const SCTP_PPID_H248: u32 = 7;
pub const SCTP_PPID_BICC: u32 = 8;
pub const SCTP_PPID_TALI: u32 = 9;
pub const SCTP_PPID_DUA: u32 = 10;
pub const SCTP_PPID_ASAP: u32 = 11;
pub const SCTP_PPID_ENRP: u32 = 12;
pub const SCTP_PPID_H323: u32 = 13;
pub const SCTP_PPID_DIAMETER: u32 = 46;
pub const SCTP_PPID_S1AP: u32 = 18;
pub const SCTP_PPID_X2AP: u32 = 27;
pub const SCTP_PPID_NGAP: u32 = 60;
pub const SCTP_PPID_XNAP: u32 = 61;
pub const SCTP_PPID_WEBRTC_DCEP: u32 = 50;
pub const SCTP_PPID_WEBRTC_STRING: u32 = 51;
pub const SCTP_PPID_WEBRTC_BINARY: u32 = 53;

// ============================================================================
// INIT Chunk
// ============================================================================

pub const SctpInitChunk = packed struct {
    header: SctpChunkHeader,
    initiate_tag: u32,
    a_rwnd: u32,
    num_outbound_streams: u16,
    num_inbound_streams: u16,
    initial_tsn: u32,
    // Optional/variable parameters follow
};

// INIT/INIT-ACK Parameter Types
pub const SctpParamType = enum(u16) {
    heartbeat_info = 1,
    ipv4_addr = 5,
    ipv6_addr = 6,
    state_cookie = 7,
    unrecognized_param = 8,
    cookie_preservative = 9,
    hostname_addr = 11,
    supported_addr_types = 12,
    ecn_capable = 0x8000,
    forward_tsn_supported = 0xc000,
    supported_extensions = 0x8008,
    random = 0x8002,
    chunk_list = 0x8003,
    hmac_algo = 0x8004,
    // Zxyphor
    zxy_quantum_auth = 0xff01,
    _,
};

// ============================================================================
// SACK Chunk
// ============================================================================

pub const SctpSackChunk = packed struct {
    header: SctpChunkHeader,
    cum_tsn_ack: u32,
    a_rwnd: u32,
    num_gap_ack_blocks: u16,
    num_dup_tsns: u16,
    // Variable: gap ack blocks + dup TSNs
};

pub const SctpGapAckBlock = packed struct {
    start: u16,
    end: u16,
};

// NR-SACK (Non-Renegable SACK)
pub const SctpNrSackChunk = packed struct {
    header: SctpChunkHeader,
    cum_tsn_ack: u32,
    a_rwnd: u32,
    num_gap_ack_blocks: u16,
    num_nr_gap_ack_blocks: u16,
    num_dup_tsns: u16,
    _reserved: u16,
};

// ============================================================================
// Association State Machine
// ============================================================================

pub const SctpState = enum(u8) {
    closed = 0,
    cookie_wait = 1,
    cookie_echoed = 2,
    established = 3,
    shutdown_pending = 4,
    shutdown_sent = 5,
    shutdown_received = 6,
    shutdown_ack_sent = 7,
};

// ============================================================================
// Transport / Path
// ============================================================================

pub const SctpTransportState = enum(u8) {
    active = 0,
    inactive = 1,
    pf = 2,               // Potentially Failed
    unconfirmed = 3,
};

pub const SctpTransport = struct {
    // Address
    addr_type: u8,           // AF_INET or AF_INET6
    addr_v4: u32,
    addr_v6: [16]u8,
    port: u16,
    // State
    state: SctpTransportState,
    active: bool,
    hb_active: bool,
    // RTO
    rto_ms: u32,
    srtt_ms: u32,
    rttvar_ms: u32,
    rto_min_ms: u32,
    rto_max_ms: u32,
    rto_initial_ms: u32,
    // Congestion
    cwnd: u32,
    ssthresh: u32,
    flight_size: u32,
    partial_bytes_acked: u32,
    // Counters
    error_count: u32,
    max_retrans: u32,
    // Heartbeat
    hb_interval_ms: u32,
    last_hb_sent_ns: u64,
    last_hb_recv_ns: u64,
    // PMTU
    pmtu: u32,
    // Stats
    tx_bytes: u64,
    rx_bytes: u64,
    tx_count: u64,
    rx_count: u64,
    retransmit_count: u64,
    // Timestamps
    last_time_used_ns: u64,
    last_time_heard_ns: u64,
    // ECN
    ecn_capable: bool,
    ecn_ce_count: u32,
};

// ============================================================================
// Association
// ============================================================================

pub const SctpAssociation = struct {
    // Identification
    assoc_id: u32,
    // State
    state: SctpState,
    // Tags
    my_vtag: u32,
    peer_vtag: u32,
    // Ports
    local_port: u16,
    peer_port: u16,
    // Streams
    num_ostreams: u16,
    num_istreams: u16,
    max_ostreams: u16,
    max_istreams: u16,
    // TSN tracking
    next_tsn: u32,
    cumulative_tsn_ack: u32,
    advanced_peer_ack: u32,
    highest_sacked: u32,
    last_cwr_tsn: u32,
    // Receive window
    a_rwnd: u32,
    peer_rwnd: u32,
    // PMTU
    pmtu: u32,
    frag_point: u32,
    // Timeouts & Retransmission
    max_retrans: u32,
    max_init_retrans: u32,
    init_retries: u32,
    shutdown_retries: u32,
    // Heartbeat
    hb_interval_ms: u32,
    // Cookie lifetime
    cookie_life_ms: u32,
    // Bundling
    max_burst: u32,
    // SACK delay
    sack_delay_ms: u32,
    sack_freq: u32,
    // Auth (RFC 4895)
    auth_capable: bool,
    auth_hmac_id: u16,        // HMAC-SHA1=1, HMAC-SHA256=3
    auth_active_key_id: u16,
    // PR-SCTP
    pr_sctp_capable: bool,
    // Stream interleaving
    intl_capable: bool,
    // ECN
    ecn_capable: bool,
    // Multi-path (CMT-SCTP)
    cmt_enabled: bool,
    nr_transports: u8,
    primary_transport_idx: u8,
    // Streams with I-DATA
    interleave_enabled: bool,
    // SCTP over UDP
    encap_port: u16,
    // Partial Delivery API
    pd_mode: bool,
    pd_point: u32,
    // Peeloff
    peeloff_assoc_id: u32,
    // Stats
    total_tx_data_chunks: u64,
    total_rx_data_chunks: u64,
    total_tx_ctrl_chunks: u64,
    total_rx_ctrl_chunks: u64,
    total_retransmissions: u64,
    total_gap_ack_blocks_received: u64,
    total_t3_timeouts: u64,
    total_fast_retransmissions: u64,
    bytes_sent: u64,
    bytes_received: u64,
    // Timestamps
    creation_time_ns: u64,
    last_send_ns: u64,
    last_recv_ns: u64,
};

// ============================================================================
// Stream
// ============================================================================

pub const SctpStream = struct {
    stream_id: u16,
    // Outbound
    out_seq: u16,
    out_mid: u32,          // Message ID for I-DATA
    // Inbound
    in_seq: u16,
    in_mid: u32,
    // Priority (RFC 7765)
    priority: u16,
    // Scheduling
    scheduler: StreamScheduler,
    // Stats
    tx_msgs: u64,
    rx_msgs: u64,
    tx_bytes: u64,
    rx_bytes: u64,
};

pub const StreamScheduler = enum(u8) {
    fcfs = 0,              // First Come First Served
    round_robin = 1,
    priority = 2,
    fair_queuing = 3,
    weighted_fair = 4,
};

// ============================================================================
// Socket Options (SOL_SCTP)
// ============================================================================

pub const SCTP_RTOINFO = 0;
pub const SCTP_ASSOCINFO = 1;
pub const SCTP_INITMSG = 2;
pub const SCTP_NODELAY = 3;
pub const SCTP_AUTOCLOSE = 4;
pub const SCTP_SET_PEER_PRIMARY_ADDR = 5;
pub const SCTP_PRIMARY_ADDR = 6;
pub const SCTP_ADAPTATION_LAYER = 7;
pub const SCTP_DISABLE_FRAGMENTS = 8;
pub const SCTP_PEER_ADDR_PARAMS = 9;
pub const SCTP_DEFAULT_SEND_PARAM = 10;
pub const SCTP_EVENTS = 11;
pub const SCTP_I_WANT_MAPPED_V4_ADDR = 12;
pub const SCTP_MAXSEG = 13;
pub const SCTP_STATUS = 14;
pub const SCTP_GET_PEER_ADDR_INFO = 15;
pub const SCTP_DELAYED_SACK = 16;
pub const SCTP_CONTEXT = 17;
pub const SCTP_FRAGMENT_INTERLEAVE = 18;
pub const SCTP_PARTIAL_DELIVERY_POINT = 19;
pub const SCTP_MAX_BURST = 20;
pub const SCTP_AUTH_CHUNK = 21;
pub const SCTP_HMAC_IDENT = 22;
pub const SCTP_AUTH_KEY = 23;
pub const SCTP_AUTH_ACTIVE_KEY = 24;
pub const SCTP_AUTH_DELETE_KEY = 25;
pub const SCTP_PEER_AUTH_CHUNKS = 26;
pub const SCTP_LOCAL_AUTH_CHUNKS = 27;
pub const SCTP_GET_ASSOC_NUMBER = 28;
pub const SCTP_GET_ASSOC_ID_LIST = 29;
pub const SCTP_AUTO_ASCONF = 30;
pub const SCTP_PEER_ADDR_THLDS = 31;
pub const SCTP_RECVRCVINFO = 32;
pub const SCTP_RECVNXTINFO = 33;
pub const SCTP_DEFAULT_SNDINFO = 34;
pub const SCTP_AUTH_DEACTIVATE_KEY = 35;
pub const SCTP_REUSE_PORT = 36;
pub const SCTP_PEER_ADDR_THLDS_V2 = 37;
pub const SCTP_PR_SUPPORTED = 113;
pub const SCTP_DEFAULT_PRINFO = 114;
pub const SCTP_PR_ASSOC_STATUS = 115;
pub const SCTP_PR_STREAM_STATUS = 116;
pub const SCTP_RECONFIG_SUPPORTED = 117;
pub const SCTP_ENABLE_STREAM_RESET = 118;
pub const SCTP_RESET_STREAMS = 119;
pub const SCTP_RESET_ASSOC = 120;
pub const SCTP_ADD_STREAMS = 121;
pub const SCTP_INTERLEAVING_SUPPORTED = 122;
pub const SCTP_ENCAP_PORT = 123;
pub const SCTP_STREAM_SCHEDULER = 124;
pub const SCTP_STREAM_SCHEDULER_VALUE = 125;
pub const SCTP_ASCONF_SUPPORTED = 126;
pub const SCTP_ECN_SUPPORTED = 127;
pub const SCTP_EXPOSE_POTENTIALLY_FAILED = 128;

// ============================================================================
// SCTP Events
// ============================================================================

pub const SctpEventType = enum(u16) {
    data_io = 0x0001,
    association = 0x0002,
    address = 0x0003,
    send_failure = 0x0004,
    peer_error = 0x0005,
    shutdown = 0x0006,
    partial_delivery = 0x0007,
    adaptation = 0x0008,
    authentication = 0x0009,
    sender_dry = 0x000a,
    stream_reset = 0x000b,
    assoc_reset = 0x000c,
    stream_change = 0x000d,
    send_failure_event = 0x000e,
    _,
};

// ============================================================================
// PR-SCTP (Partially Reliable SCTP)
// ============================================================================

pub const SctpPrPolicy = enum(u16) {
    none = 0,              // Reliable
    ttl = 1,               // Time-to-Live
    rtx = 2,               // Max retransmissions
    prio = 3,              // Priority
    buf = 4,               // Buffer
};

pub const SctpPrInfo = struct {
    policy: SctpPrPolicy,
    value: u32,
};

// ============================================================================
// Dynamic Address Reconfiguration (RFC 5061)
// ============================================================================

pub const AsconfParamType = enum(u16) {
    add_ip = 0xc001,
    del_ip = 0xc002,
    error_cause = 0xc003,
    set_primary = 0xc004,
    success = 0xc005,
    adaptation = 0xc006,
    _,
};

// ============================================================================
// Stream Reconfiguration (RFC 6525)
// ============================================================================

pub const ReconfigParamType = enum(u16) {
    outgoing_reset = 13,
    incoming_reset = 14,
    ssn_tsn_reset = 15,
    resp = 16,
    add_outgoing = 17,
    add_incoming = 18,
    _,
};

pub const ReconfigResult = enum(u32) {
    success_nothing = 0,
    success_performed = 1,
    denied = 2,
    error_wrong_ssn = 3,
    request_in_progress = 4,
    bad_sequence = 5,
    in_progress = 6,
};

// ============================================================================
// Congestion Control
// ============================================================================

pub const SctpCongAlg = enum(u8) {
    rfc4960 = 0,           // Standard
    htcp = 1,              // Hamilton TCP
    cmtrpv1 = 2,          // CMT-RPv1
    cmtrpv2 = 3,          // CMT-RPv2
    // Zxyphor
    zxy_adaptive = 10,
};

pub const SctpCongState = struct {
    algorithm: SctpCongAlg,
    cwnd: u32,
    ssthresh: u32,
    flight_size: u32,
    partial_bytes_acked: u32,
    // Fast recovery
    in_fast_recovery: bool,
    fast_recovery_exit_tsn: u32,
    // ECN
    ecn_ce_count: u32,
    ecn_cwr_sent: bool,
};

// ============================================================================
// SCTP Auth (RFC 4895)
// ============================================================================

pub const SctpHmacAlgo = enum(u16) {
    sha1 = 1,
    sha256 = 3,
    // Zxyphor
    zxy_blake3 = 100,
};

pub const SctpAuthCaps = struct {
    enabled: bool,
    active_key_id: u16,
    nr_keys: u8,
    hmac_algo: SctpHmacAlgo,
    // Chunks requiring auth
    auth_chunks: [16]u8,
    nr_auth_chunks: u8,
};

// ============================================================================
// SCTP over DTLS (RFC 8261 - for WebRTC)
// ============================================================================

pub const SctpOverDtls = struct {
    dtls_enabled: bool,
    dtls_state: u8,
    // Data channels (WebRTC)
    nr_data_channels: u16,
    max_data_channels: u16,
    // Extensions
    unreliable_enabled: bool,
    ordered_delivery: bool,
};

// ============================================================================
// Statistics
// ============================================================================

pub const SctpStats = struct {
    // Global
    total_associations: u64,
    active_associations: u32,
    // Chunks
    data_chunks_sent: u64,
    data_chunks_received: u64,
    ctrl_chunks_sent: u64,
    ctrl_chunks_received: u64,
    // Retransmissions
    total_retransmissions: u64,
    fast_retransmissions: u64,
    t1_init_timeouts: u64,
    t1_cookie_timeouts: u64,
    t2_shutdown_timeouts: u64,
    t3_rtx_timeouts: u64,
    t4_rto_timeouts: u64,
    t5_shutdown_guard_timeouts: u64,
    // Errors
    abort_sent: u64,
    abort_received: u64,
    checksum_errors: u64,
    ootb_packets: u64,        // Out of the blue
    // SACK
    sack_sent: u64,
    sack_received: u64,
    gap_ack_blocks_received: u64,
    dup_tsns_received: u64,
    // Bytes
    total_bytes_sent: u64,
    total_bytes_received: u64,
    // Handshakes
    init_sent: u64,
    init_received: u64,
    init_ack_sent: u64,
    cookie_echo_sent: u64,
    cookie_ack_sent: u64,
    // Shutdown
    shutdown_sent: u64,
    shutdown_received: u64,
    graceful_shutdowns: u64,
    // Auth
    auth_failures: u64,
    // PR-SCTP
    pr_abandoned_sent: u64,
    pr_abandoned_unsent: u64,
    // CMT
    cmt_on_paths: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const SctpSubsystem = struct {
    // Configuration
    rto_initial_ms: u32,
    rto_min_ms: u32,
    rto_max_ms: u32,
    max_retrans_association: u32,
    max_retrans_path: u32,
    max_retrans_init: u32,
    max_init_timeo_ms: u32,
    valid_cookie_life_ms: u32,
    max_burst: u32,
    hb_interval_ms: u32,
    sack_timeout_ms: u32,
    // Streams
    default_num_ostreams: u16,
    max_instreams: u16,
    // Auth
    auth_enable: bool,
    // PR-SCTP
    pr_enable: bool,
    // Interleaving
    intl_enable: bool,
    // CMT
    cmt_enable: bool,
    // SCTP over UDP encapsulation
    encap_port: u16,
    // Congestion
    default_cong_alg: SctpCongAlg,
    // Stats
    stats: SctpStats,
    // Zxyphor
    zxy_quantum_auth: bool,
    initialized: bool,
};
