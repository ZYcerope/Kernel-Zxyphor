// Zxyphor Kernel - SCTP Protocol Internals
// SCTP: association, endpoint, chunk types, state machine
// Stream scheduling, path management, multihoming
// CRC32c, HMAC-SHA1, congestion control
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// SCTP Chunk Types (RFC 9260)
// ============================================================================

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
    sctp_error = 9,
    cookie_echo = 10,
    cookie_ack = 11,
    ecne = 12,
    cwr = 13,
    shutdown_complete = 14,
    // AUTH chunk (RFC 4895)
    auth = 15,
    // I-DATA (RFC 8260)
    i_data = 64,
    // ASCONF (RFC 5061)
    asconf_ack = 0x80,
    // PAD chunk
    pad = 0x84,
    // FORWARD-TSN (RFC 3758)
    forward_tsn = 0xC0,
    asconf = 0xC1,
    // RE-CONFIG (RFC 6525)
    re_config = 130,
    _,
};

pub const SctpChunkFlags = packed struct(u8) {
    bit0: bool = false, // DATA: unordered; ABORT: T-bit
    bit1: bool = false, // DATA: beginning fragment
    bit2: bool = false, // DATA: ending fragment
    bit3: bool = false, // DATA: I-bit
    _pad: u4 = 0,
};

pub const SctpChunkHeader = extern struct {
    chunk_type: u8,
    chunk_flags: u8,
    chunk_length: u16,
};

pub const SctpCommonHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    vtag: u32,
    checksum: u32,
};

// ============================================================================
// SCTP State Machine
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

pub const SctpEvent = enum(u8) {
    // Chunk events
    chunk_data = 0,
    chunk_init = 1,
    chunk_init_ack = 2,
    chunk_sack = 3,
    chunk_heartbeat = 4,
    chunk_heartbeat_ack = 5,
    chunk_abort = 6,
    chunk_shutdown = 7,
    chunk_shutdown_ack = 8,
    chunk_error = 9,
    chunk_cookie_echo = 10,
    chunk_cookie_ack = 11,
    chunk_ecne = 12,
    chunk_cwr = 13,
    chunk_shutdown_complete = 14,
    chunk_auth = 15,
    chunk_i_data = 16,
    chunk_asconf = 17,
    chunk_asconf_ack = 18,
    chunk_forward_tsn = 19,
    chunk_re_config = 20,
    // Timeout events
    timeout_t1_cookie = 30,
    timeout_t1_init = 31,
    timeout_t2_shutdown = 32,
    timeout_t3_rtx = 33,
    timeout_t4_rto = 34,
    timeout_t5_shutdown_guard = 35,
    timeout_heartbeat = 36,
    timeout_sack = 37,
    timeout_autoclose = 38,
    // Primitive events
    primitive_associate = 50,
    primitive_shutdown = 51,
    primitive_abort = 52,
    primitive_send = 53,
    primitive_requestheartbeat = 54,
    primitive_asconf = 55,
    // Other
    other_no_pending_tsn = 60,
    other_icmp_proto_unreach = 61,
};

// ============================================================================
// SCTP Association
// ============================================================================

pub const SctpAssociation = struct {
    // Peer info
    peer_vtag: u32,
    peer_rwnd: u32,
    peer_init_tsn: u32,
    peer_cookie: [256]u8,
    peer_cookie_len: u32,
    // Local info
    my_vtag: u32,
    my_rwnd: u32,
    // TSN tracking
    next_tsn: u32,
    ctsn_ack_point: u32,    // cumulative TSN ack point
    adv_peer_ack_point: u32,
    highest_sacked: u32,
    last_cwr_tsn: u32,
    // Reassembly
    next_ssn: [65536]u16,   // per-stream SSN
    // Timeouts (milliseconds)
    rto_initial: u32,
    rto_min: u32,
    rto_max: u32,
    rto_alpha: u32,     // 1/8
    rto_beta: u32,      // 1/4
    max_burst: u32,
    cookie_life: u32,
    // Protocol parameters
    max_retrans: u32,
    max_init_retrans: u32,
    max_init_timeo: u32,
    hb_interval: u32,
    sack_timeout: u32,
    sack_freq: u32,
    // State
    state: SctpState,
    ep: ?*SctpEndpoint,
    // Counters
    init_retries: u32,
    shutdown_retries: u32,
    overall_error_count: u32,
    data_chunks_retransmitted: u64,
    // Streams
    num_ostreams: u16,
    num_istreams: u16,
    max_inbound_streams: u16,
    // Features
    prsctp_enable: bool,
    reconf_enable: bool,
    intl_enable: bool,   // interleaving
    auth_enable: bool,
    ecn_capable: bool,
    asconf_capable: bool,
    // Congestion control
    cc: SctpCongestionControl,
    // Partial reliability
    pr_policy: SctpPrPolicy,
    pr_value: u32,
    // Statistics
    stats: SctpAssocStats,
};

pub const SctpEndpoint = struct {
    base_port: u16,
    num_addrs: u32,
    addrs: [16]SctpTransportAddress,
    secret_key: [32]u8,
    last_key: [32]u8,
    key_changed_at: u64,
    // Socket options
    nodelay: bool,
    disable_fragments: bool,
    v4mapped: bool,
    frag_interleave: u32,
    pf_expose: SctpPfExpose,
    adaptation_ind: u32,
    default_stream: u16,
    default_flags: u32,
    default_ppid: u32,
    default_context: u32,
    default_timetolive: u32,
    // Subscription events
    subscribe: SctpEventSubscribe,
};

pub const SctpTransportAddress = struct {
    addr_type: SctpAddrType,
    ip4: u32,
    ip6: [16]u8,
    port: u16,
};

pub const SctpAddrType = enum(u8) {
    ipv4 = 5,
    ipv6 = 6,
};

pub const SctpPfExpose = enum(u8) {
    disabled = 0,
    enabled = 1,
    usrsctp_compat = 2,
};

pub const SctpEventSubscribe = packed struct(u16) {
    data_io: bool = false,
    association: bool = false,
    address: bool = false,
    send_failure: bool = false,
    peer_error: bool = false,
    shutdown: bool = false,
    partial_delivery: bool = false,
    adaptation_layer: bool = false,
    authentication: bool = false,
    sender_dry: bool = false,
    stream_reset: bool = false,
    assoc_reset: bool = false,
    stream_change: bool = false,
    send_failure_event: bool = false,
    _pad: u2 = 0,
};

// ============================================================================
// SCTP Transport (Path Management / Multihoming)
// ============================================================================

pub const SctpTransport = struct {
    peer_addr: SctpTransportAddress,
    // RTO estimation
    rto: u32,
    srtt: u32,          // smoothed RTT
    rttvar: u32,        // RTT variance
    rtt: u32,           // latest RTT measurement
    // Cwnd
    cwnd: u32,
    ssthresh: u32,
    flight_size: u32,
    partial_bytes_acked: u32,
    // Path management
    state: SctpTransportState,
    error_count: u32,
    error_threshold: u32,
    ps_retrans: u32,
    // Heartbeat
    hb_sent: bool,
    hb_nonce: u64,
    last_time_heard: u64,
    last_time_sent: u64,
    last_time_ecne_reduced: u64,
    // PMTU
    pathmtu: u32,
    pmtu_pending: bool,
    // Stats
    bytes_sent: u64,
    bytes_received: u64,
    data_chunks_sent: u64,
    data_chunks_received: u64,
    retransmitted_chunks: u64,
    heartbeats_sent: u64,
    heartbeats_acked: u64,
};

pub const SctpTransportState = enum(u8) {
    active = 0,
    inactive = 1,
    disabled = 2,
    unconfirmed = 3,
    pf = 4,            // potentially failed
};

// ============================================================================
// Congestion Control
// ============================================================================

pub const SctpCcAlgo = enum(u8) {
    rfc2960 = 0,       // basic
    htcp = 1,
    hstcp = 2,          // high-speed TCP CC
    rfc4960 = 3,        // updated RFC
};

pub const SctpCongestionControl = struct {
    algo: SctpCcAlgo,
    cwnd: u32,
    ssthresh: u32,
    mtu: u32,
    // RFC 4960 slow start
    flight_size: u32,
    partial_bytes_acked: u32,
    // Fast retransmit state
    fast_retransmit: bool,
    fast_recovery: bool,
    fast_recovery_exit: u32,
    // Stats
    slow_start_events: u64,
    congestion_avoidance_events: u64,
    fast_retransmit_events: u64,
    timeout_events: u64,
};

// ============================================================================
// Partial Reliability (PR-SCTP, RFC 3758)
// ============================================================================

pub const SctpPrPolicy = enum(u8) {
    none = 0,
    ttl = 1,           // timed reliability
    buf = 2,           // buffer based
    rtx = 3,           // limited retransmissions
    prio = 4,          // priority based
};

// ============================================================================
// SCTP Stream Schedulers (RFC 8260)
// ============================================================================

pub const SctpStreamScheduler = enum(u8) {
    fcfs = 0,           // first come first serve
    round_robin = 1,
    round_robin_pkt = 2,
    priority = 3,
    fair_bandwidth = 4,
    weighted_fair = 5,
};

pub const SctpStream = struct {
    sid: u16,
    ssn: u16,           // stream sequence number
    mid: u32,           // message ID (I-DATA)
    // Ordering
    next_ssn: u16,
    // Scheduling
    priority: u16,
    weight: u16,
    // PR
    abandoned: u64,
    // Stats
    chunks_sent: u64,
    chunks_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
};

// ============================================================================
// SCTP Authentication (RFC 4895)
// ============================================================================

pub const SctpAuthChunk = struct {
    shared_key_id: u16,
    hmac_id: SctpHmacId,
    hmac: [32]u8,       // HMAC value
};

pub const SctpHmacId = enum(u16) {
    sha1 = 1,
    sha256 = 3,
};

pub const SctpAuthKeyId = struct {
    assoc_id: u32,
    key_id: u16,
    key_len: u16,
    key: [256]u8,
};

// ============================================================================
// SCTP Notifications
// ============================================================================

pub const SctpNotificationType = enum(u16) {
    assoc_change = 0x0001,
    peer_addr_change = 0x0002,
    send_failed = 0x0004,
    remote_error = 0x0008,
    shutdown_event = 0x0010,
    partial_delivery = 0x0020,
    adaptation_indication = 0x0040,
    authentication_event = 0x0080,
    sender_dry = 0x0100,
    stream_reset_event = 0x0200,
    assoc_reset_event = 0x0400,
    stream_change_event = 0x0800,
    send_failed_event = 0x1000,
};

pub const SctpAssocChangeState = enum(u16) {
    comm_up = 0,
    comm_lost = 1,
    restart = 2,
    shutdown_comp = 3,
    cant_str_assoc = 4,
};

pub const SctpPaddrChangeState = enum(u32) {
    addr_available = 0,
    addr_unreachable = 1,
    addr_removed = 2,
    addr_added = 3,
    addr_made_prim = 4,
    addr_confirmed = 5,
    addr_potentially_failed = 6,
};

// ============================================================================
// SCTP Socket Options
// ============================================================================

pub const SctpSockOpt = enum(u32) {
    rtoinfo = 0,
    associnfo = 1,
    initmsg = 2,
    nodelay = 3,
    autoclose = 4,
    set_peer_primary_addr = 5,
    primary_addr = 6,
    adaptation_layer = 7,
    disable_fragments = 8,
    peer_addr_params = 9,
    default_send_param = 10,
    events = 11,
    i_want_mapped_v4_addr = 12,
    maxseg = 13,
    status = 14,
    get_peer_addr_info = 15,
    delayed_ack_time = 16,
    context = 17,
    fragment_interleave = 18,
    partial_delivery_point = 19,
    max_burst = 20,
    auth_chunk = 21,
    hmac_ident = 22,
    auth_key = 23,
    auth_active_key = 24,
    auth_delete_key = 25,
    peer_auth_chunks = 26,
    local_auth_chunks = 27,
    get_assoc_number = 28,
    get_assoc_id_list = 29,
    auto_asconf = 30,
    peer_addr_thlds = 31,
    recvrcvinfo = 32,
    recvnxtinfo = 33,
    default_sndinfo = 34,
    auth_deactivate_key = 35,
    reuse_port = 36,
    encap_port = 37,
    plpmtud_probe = 38,
    pr_supported = 100,
    default_prinfo = 101,
    pr_assoc_status = 102,
    enable_stream_reset = 118,
    reset_streams = 119,
    reset_assoc = 120,
    add_streams = 121,
    interleaving_supported = 125,
    scheduler = 123,
    scheduler_value = 124,
    reconfig_supported = 126,
    ecn_supported = 127,
    expose_potentially_failed = 128,
    stream_scheduler = 129,
    stream_scheduler_value = 130,
};

// ============================================================================
// SCTP Init Parameters
// ============================================================================

pub const SctpInitMsg = struct {
    num_ostreams: u16,
    max_instreams: u16,
    max_attempts: u16,
    max_init_timeo: u16,
};

pub const SctpAssocStats = struct {
    // Data stats
    data_chunks_sent: u64,
    data_chunks_received: u64,
    ctrl_chunks_sent: u64,
    ctrl_chunks_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    // Retransmissions
    retransmissions: u64,
    t1_init_expirations: u64,
    t2_shutdown_expirations: u64,
    t3_rtx_expirations: u64,
    // Errors
    sack_received: u64,
    sack_sent: u64,
    ootb_packets: u64,           // out of the blue
    abort_sent: u64,
    abort_received: u64,
    // Path changes
    primary_path_changes: u64,
    // PMTU
    pmtu_changes: u64,
    // Fast retransmit
    fast_retransmits: u64,
    // Partial delivery
    partial_deliveries: u64,
    // Duplicate TSN
    dup_tsn_received: u64,
};

// ============================================================================
// SCTP Subsystem Manager
// ============================================================================

pub const SctpSubsystemManager = struct {
    active_associations: u32,
    total_associations: u64,
    active_endpoints: u32,
    total_data_chunks: u64,
    total_ctrl_chunks: u64,
    total_bytes: u64,
    total_ootb: u64,
    total_aborts: u64,
    total_t3_expirations: u64,
    max_assoc_retransmits: u32,
    max_path_retransmits: u32,
    default_rto_initial: u32,
    default_rto_min: u32,
    default_rto_max: u32,
    default_hb_interval: u32,
    default_sack_timeout: u32,
    cookie_hmac_alg: SctpHmacId,
    initialized: bool,

    pub fn init() SctpSubsystemManager {
        return SctpSubsystemManager{
            .active_associations = 0,
            .total_associations = 0,
            .active_endpoints = 0,
            .total_data_chunks = 0,
            .total_ctrl_chunks = 0,
            .total_bytes = 0,
            .total_ootb = 0,
            .total_aborts = 0,
            .total_t3_expirations = 0,
            .max_assoc_retransmits = 10,
            .max_path_retransmits = 5,
            .default_rto_initial = 3000,
            .default_rto_min = 1000,
            .default_rto_max = 60000,
            .default_hb_interval = 30000,
            .default_sack_timeout = 200,
            .cookie_hmac_alg = .sha256,
            .initialized = true,
        };
    }
};
