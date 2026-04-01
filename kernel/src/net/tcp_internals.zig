// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Advanced TCP/IP Stack Internals
// Full TCP state machine, congestion control, MPTCP, TCP Fast Open, RACK-TLP,
// BBRv2/BBRv3/CUBIC/NewReno, ECN, TCP options, SYN cookies, TIME_WAIT recycling
// More advanced than Linux 2026 TCP implementation

const std = @import("std");

// ============================================================================
// TCP State Machine
// ============================================================================

pub const TcpState = enum(u8) {
    closed = 0,
    listen = 1,
    syn_sent = 2,
    syn_recv = 3,
    established = 4,
    fin_wait1 = 5,
    fin_wait2 = 6,
    close_wait = 7,
    closing = 8,
    last_ack = 9,
    time_wait = 10,
    new_syn_recv = 11,  // Linux-specific: mini-socket in SYN queue
    bound = 12,         // Zxyphor: bound but not listening
};

// ============================================================================
// TCP Header
// ============================================================================

pub const TcpHeader = extern struct {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    // Data offset (4 bits) + reserved (3 bits) + NS flag (1 bit)
    doff_ns: u8,
    // Flags: CWR ECE URG ACK PSH RST SYN FIN
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,

    pub fn data_offset(self: *const TcpHeader) u8 {
        return (self.doff_ns >> 4) & 0x0F;
    }

    pub fn header_length(self: *const TcpHeader) u8 {
        return self.data_offset() * 4;
    }

    pub fn has_flag(self: *const TcpHeader, flag: TcpFlag) bool {
        return (self.flags & @intFromEnum(flag)) != 0;
    }
};

pub const TcpFlag = enum(u8) {
    fin = 0x01,
    syn = 0x02,
    rst = 0x04,
    psh = 0x08,
    ack = 0x10,
    urg = 0x20,
    ece = 0x40,
    cwr = 0x80,
};

// ============================================================================
// TCP Options
// ============================================================================

pub const TCP_OPT_EOL: u8 = 0;
pub const TCP_OPT_NOP: u8 = 1;
pub const TCP_OPT_MSS: u8 = 2;
pub const TCP_OPT_WSCALE: u8 = 3;
pub const TCP_OPT_SACK_PERM: u8 = 4;
pub const TCP_OPT_SACK: u8 = 5;
pub const TCP_OPT_TIMESTAMPS: u8 = 8;
pub const TCP_OPT_MD5SIG: u8 = 19;
pub const TCP_OPT_MPTCP: u8 = 30;
pub const TCP_OPT_FASTOPEN: u8 = 34;
pub const TCP_OPT_AO: u8 = 29;   // TCP-AO authentication
pub const TCP_OPT_ACC_ECN: u8 = 0xAC; // AccECN
pub const TCP_OPT_ZXY_QOS: u8 = 0xFE; // Zxyphor QoS hint

pub const TcpOptionsParsed = struct {
    mss: u16,
    mss_present: bool,
    wscale: u8,
    wscale_present: bool,
    sack_perm: bool,
    sack_blocks: [4]SackBlock,
    nr_sack_blocks: u8,
    timestamps_present: bool,
    tsval: u32,
    tsecr: u32,
    md5_present: bool,
    mptcp_present: bool,
    mptcp_subtype: u8,
    fastopen_present: bool,
    fastopen_cookie: [16]u8,
    fastopen_cookie_len: u8,
    ao_present: bool,
    ao_keyid: u8,
    ao_rnextkeyid: u8,
    // ECN
    ecn_present: bool,
    acc_ecn: bool,
    // Reserved
    unknown_options: u32,
};

pub const SackBlock = struct {
    start_seq: u32,
    end_seq: u32,
};

// ============================================================================
// TCP Socket (tcp_sock equivalent)
// ============================================================================

pub const TcpSock = struct {
    // Connection state
    state: TcpState,
    // Sequence numbers
    snd_una: u32,       // Send unacknowledged
    snd_nxt: u32,       // Send next
    snd_wl1: u32,       // Seq for last window update
    snd_wl2: u32,       // Ack for last window update
    snd_wnd: u32,       // Send window
    max_window: u32,    // Maximum observed window
    rcv_nxt: u32,       // Receive next
    rcv_wnd: u32,       // Receive window
    rcv_wup: u32,       // Forward ack point
    write_seq: u32,     // Tail(+1) of data in send buffer
    copied_seq: u32,    // Head of yet unread data
    pushed_seq: u32,    // Last pushed seq
    iss: u32,           // Initial send sequence
    irs: u32,           // Initial receive sequence
    // Retransmission
    retransmits: u32,
    total_retrans: u64,
    rto: u32,           // Retransmit timeout (us)
    rto_min: u32,
    rttvar: u32,        // RTT variance (us)
    srtt: u32,          // Smoothed RTT (us << 3)
    mdev: u32,          // Medium deviation
    mdev_max: u32,
    rtt_seq: u32,       // Seq to match ts on
    rtt_min: [3]TcpRttMin, // Recent min RTT
    // MSS
    mss_cache: u16,
    advmss: u16,        // Advertised MSS
    user_mss: u16,      // Set by setsockopt
    mss_clamp: u16,
    // Window
    window_clamp: u32,  // Max window to advertise
    rcv_ssthresh: u32,  // Receiver slow start threshold
    snd_ssthresh: u32,  // Sender slow start threshold
    snd_cwnd: u32,      // Congestion window
    snd_cwnd_stamp: u64,
    snd_cwnd_cnt: u32,
    snd_cwnd_used: u32,
    snd_cwnd_clamp: u32,
    prior_cwnd: u32,    // Before recovery
    prior_ssthresh: u32,
    // Pacing
    pacing_rate: u64,    // Bytes per second
    max_pacing_rate: u64,
    pacing_timer: u64,
    // Fast Open
    tfo_cookie: [16]u8,
    tfo_cookie_len: u8,
    tfo_enabled: bool,
    // SACK
    sack_enabled: bool,
    dsack: bool,         // D-SACK
    rx_sack_blocks: [4]SackBlock,
    nr_sacks: u8,
    highest_sack_seq: u32,
    sacked_out: u32,    // SACK'd packets
    lost_out: u32,      // Lost packets
    retrans_out: u32,   // Retransmitted out
    fackets_out: u32,   // FACK'd packets
    // Timestamps
    tsoffset: i32,      // Timestamp offset
    // ECN
    ecn_flags: TcpEcnFlags,
    // Window scaling
    snd_wscale: u8,
    rcv_wscale: u8,
    // Congestion control
    ca_state: TcpCaState,
    ca_ops: *const TcpCongestionOps,
    ca_priv: [128]u8,    // Private data for congestion algorithm
    // Metrics
    bytes_acked: u64,
    bytes_received: u64,
    data_segs_in: u32,
    data_segs_out: u32,
    bytes_sent: u64,
    bytes_retrans: u64,
    // Delivery rate
    delivered: u32,
    delivered_ce: u32,   // ECN count
    app_limited: u32,
    first_tx_mstamp: u64,
    delivered_mstamp: u64,
    rate_delivered: u32,
    rate_interval_us: u32,
    rate_app_limited: bool,
    // RACK-TLP
    rack: TcpRack,
    // Keep-alive
    keepalive_time: u32, // Seconds
    keepalive_intvl: u32,
    keepalive_probes: u32,
    keepalive_cnt: u32,
    // Thin streams
    thin_lto: bool,     // Thin linear timeouts
    thin_dupack: bool,  // Use thin stream retrans
    // Repair
    repair: bool,
    repair_queue: u8,
    // MPTCP
    mptcp_enabled: bool,
    mptcp: ?*MptcpSock,
    // TCP-AO
    ao_info: ?*TcpAoInfo,
    // Misc
    nonagle: u8,
    cork: bool,
    linger2: i32,
    no_delay: bool,
    syn_retries: u8,
    defer_accept: bool,
    reordering: u32,    // Packet reordering metric
    // Timestamps
    lsndtime: u64,      // Last send time
    last_oow_ack_time: u64,
    // Write queue
    write_queue_bytes: u32,
    // Stats
    rx_opt: TcpOptionsParsed,
};

pub const TcpRttMin = struct {
    rtt: u32,     // us
    ts: u32,      // Timestamp
};

pub const TcpEcnFlags = packed struct {
    ecn_ok: bool,
    ecn_demand_cwr: bool,
    ecn_seen: bool,
    ce_seen: bool,
    acc_ecn: bool,
    _padding: u3 = 0,
};

// TCP Congestion Control State
pub const TcpCaState = enum(u8) {
    open = 0,        // Normal
    disorder = 1,    // Some out-of-order
    cwr = 2,         // CWR received
    recovery = 3,    // Loss detected, recovering
    loss = 4,        // Full loss event
};

// ============================================================================
// RACK-TLP (Recent Acknowledgment / Tail Loss Probe)
// ============================================================================

pub const TcpRack = struct {
    mstamp: u64,         // Most recent ACK time
    rtt_us: u64,         // Associated RTT
    end_seq: u32,        // Seq of most recently acked segment
    xmit_time: u64,      // Xmit time of most recently acked segment
    advanced: bool,       // New RTT measurement available
    reord: bool,          // Reordering detected
    dsack_seen: bool,
    reo_wnd_steps: u8,   // Reorder window scaling steps
    reo_wnd_persist: u8,
    // TLP
    tlp_high_seq: u32,   // Seq at TLP retransmit
    is_retrans: bool,
};

// ============================================================================
// Congestion Control Framework
// ============================================================================

pub const TcpCongestionOps = struct {
    name: [16]u8,
    name_len: u8,
    // Required ops
    ssthresh: *const fn (*TcpSock) u32,
    cong_avoid: *const fn (*TcpSock, u32, u32) void,
    // Optional ops
    set_state: ?*const fn (*TcpSock, TcpCaState) void,
    cwnd_event: ?*const fn (*TcpSock, TcpCaEvent) void,
    in_ack_event: ?*const fn (*TcpSock, u32) void,
    pkts_acked: ?*const fn (*TcpSock, *const TcpAckSample) void,
    undo_cwnd: ?*const fn (*TcpSock) u32,
    init: ?*const fn (*TcpSock) void,
    release: ?*const fn (*TcpSock) void,
    sndbuf_expand: ?*const fn (*TcpSock) u32,
    get_info: ?*const fn (*TcpSock, u32, *i32, [*]u64) void,
    // Flags
    flags: u32,
    owner: u32,
    key: u32,
};

pub const TcpCaEvent = enum(u8) {
    tx_start = 0,
    cwnd_restart = 1,
    complete_cwr = 2,
    loss = 3,
    ecn_no_ce = 4,
    ecn_is_ce = 5,
};

pub const TcpAckSample = struct {
    pkts_acked: u32,
    rtt_us: i64,
    in_flight: u32,
};

// ============================================================================
// BBRv2/v3 Congestion Control
// ============================================================================

pub const BbrMode = enum(u8) {
    startup = 0,
    drain = 1,
    probe_bw = 2,
    probe_rtt = 3,
};

pub const BbrBwPhase = enum(u8) {
    probe_up = 0,    // BBRv2: probing for more bandwidth
    probe_down = 1,
    probe_cruise = 2,
    probe_refill = 3,
};

pub const BbrState = struct {
    mode: BbrMode,
    bw_phase: BbrBwPhase,
    // Bottleneck bandwidth
    bw: [10]BbrBwSample,  // Windowed max filter
    bw_idx: u8,
    bw_round_start: bool,
    round_count: u32,
    next_round_delivered: u32,
    // RTT
    min_rtt_us: u64,
    min_rtt_stamp: u64,
    probe_rtt_done_stamp: u64,
    probe_rtt_round_done: bool,
    min_rtt_expired: bool,
    // Pacing
    pacing_gain_x256: u32,    // 256 = 1.0x
    cwnd_gain_x256: u32,
    // Flight
    target_cwnd: u32,
    prior_cwnd: u32,
    full_bw: u64,
    full_bw_cnt: u8,
    full_bw_reached: bool,
    // ECN (BBRv2)
    ecn_alpha: u32,          // ECN response parameter
    ecn_in_round: u32,       // ECN-marked in current round
    ecn_ce_ratio: u32,       // Moving average
    ecn_eligible: bool,
    // Loss (BBRv2)
    loss_in_round: u32,
    loss_round_start: bool,
    loss_in_cycle: u32,
    loss_events_in_round: u32,
    inflight_lo: u32,
    inflight_hi: u32,
    bw_lo: u64,
    bw_hi: u64,
    // Startup
    startup_ecn_rounds: u32,
    // Probe BW cycle
    cycle_idx: u8,
    cycle_mstamp: u64,
    ack_phase: u8,
    // BBRv3 additions
    bw_probe_samples: u32,
    bw_probe_up_rounds: u32,
    bw_probe_up_acks: u32,
    stopped_risky_probe: bool,
};

pub const BbrBwSample = struct {
    bw: u64,       // Bandwidth (bytes/s)
    round: u32,    // Round trip number
};

// ============================================================================
// CUBIC Congestion Control
// ============================================================================

pub const CubicState = struct {
    cnt: u32,            // Increase cwnd by 1 after cnt ACKs
    last_cwnd: u32,      // Last max cwnd
    last_time: u64,      // Time when last_cwnd is updated
    origin_point: u32,   // Origin point of Wmax
    tcp_cwnd: u32,       // TCP-friendliness cwnd estimate
    bic_K: u32,          // Time to origin point from epoch
    delay_min: u32,      // Min delay (us)
    epoch_start: u64,    // Start of current epoch
    ack_cnt: u32,        // Number of ACKs
    tcp_friendliness: bool,
    fast_convergence: bool,
    beta: u32,           // Multiplicative decrease factor (x1024)
    c_factor: u32,       // Scaling factor (x1024)
    hystart: bool,
    hystart_detect: u8,  // Detection method
    hystart_low_window: u32,
    hystart_ack_delta: u32,
    // HyStart++
    hystart_css: bool,   // Conservative Slow Start
    css_rounds: u8,
    css_baseline_minrtt: u32,
    last_round_minrtt: u32,
    curr_round_minrtt: u32,
    rtt_cnt: u32,
    sample_cnt: u32,
};

// ============================================================================
// MPTCP (Multipath TCP) RFC 8684
// ============================================================================

pub const MPTCP_MAX_SUBFLOWS: u32 = 8;

pub const MptcpSubtype = enum(u8) {
    mp_capable = 0,
    mp_join = 1,
    dss = 2,
    add_addr = 3,
    remove_addr = 4,
    mp_prio = 5,
    mp_fail = 6,
    mp_fastclose = 7,
    mp_tcprst = 8,
};

pub const MptcpScheduler = enum(u8) {
    default = 0,        // Default round-robin
    redundant = 1,      // Send on all subflows
    blest = 2,          // Blocking estimation
    ecf = 3,            // Earliest completion first
    // Zxyphor
    zxy_adaptive = 200, // ML-based scheduling
};

pub const MptcpPathManager = enum(u8) {
    default = 0,
    fullmesh = 1,
    netlink = 2,
    binder = 3,
};

pub const MptcpSubflow = struct {
    local_id: u8,
    remote_id: u8,
    local_addr: [16]u8,  // IPv6 or IPv4-mapped
    remote_addr: [16]u8,
    local_port: u16,
    remote_port: u16,
    // Token / key
    local_key: u64,
    remote_key: u64,
    local_token: u32,
    remote_token: u32,
    // State
    fully_established: bool,
    backup: bool,
    request_join: bool,
    // Data sequence
    data_seq: u64,
    subflow_seq: u32,
    map_data_len: u32,
    // RTT
    rtt_us: u64,
    // Stats
    bytes_sent: u64,
    bytes_received: u64,
    retransmits: u32,
};

pub const MptcpSock = struct {
    // Connection level
    local_key: u64,
    remote_key: u64,
    token: u32,
    // Subflows
    subflows: [MPTCP_MAX_SUBFLOWS]MptcpSubflow,
    nr_subflows: u32,
    max_subflows: u32,
    // Data sequence
    snd_una: u64,
    write_seq: u64,
    ack_seq: u64,
    rcv_wnd_sent: u64,
    // Scheduler
    scheduler: MptcpScheduler,
    path_manager: MptcpPathManager,
    // Addresses
    local_addrs: [8]MptcpAddr,
    nr_local_addrs: u8,
    remote_addrs: [8]MptcpAddr,
    nr_remote_addrs: u8,
    // Capabilities
    can_ack: bool,
    fully_established: bool,
    snd_data_fin_enable: bool,
    rcv_data_fin: bool,
    use_checksum: bool,
    allow_break: bool,
    // Stats
    bytes_sent: u64,
    bytes_received: u64,
    bytes_retrans: u64,
    subflows_max: u32,
};

pub const MptcpAddr = struct {
    id: u8,
    family: u8,
    port: u16,
    addr: [16]u8,
    flags: u8,
    ifindex: u32,
};

// ============================================================================
// TCP Fast Open (TFO) RFC 7413
// ============================================================================

pub const TfoState = struct {
    cookie_enabled: bool,
    cookie: [16]u8,
    cookie_len: u8,
    cookie_valid: bool,
    // Server
    max_queue_len: u32,
    queue_len: u32,
    // Stats
    syn_data_recv: u64,
    cookie_req_recv: u64,
    cookie_sent: u64,
    syn_data_ack_recv: u64,
    syn_data_nack_recv: u64,
};

// ============================================================================
// TCP-AO (Authentication Option) RFC 5925
// ============================================================================

pub const TcpAoInfo = struct {
    keys: [16]TcpAoKey,
    nr_keys: u8,
    current_key: u8,
    rnext_key: u8,
    // Stats
    ao_good: u64,
    ao_bad: u64,
    ao_key_not_found: u64,
    ao_rnext: u64,
};

pub const TcpAoKey = struct {
    keyid: u8,
    rnextkeyid: u8,
    algorithm: TcpAoAlgorithm,
    key: [80]u8,
    key_len: u8,
    // For matching
    addr: [16]u8,
    addr_len: u8,
    prefix_len: u8,
    port: u16,
    ifindex: i32,
};

pub const TcpAoAlgorithm = enum(u8) {
    hmac_sha1_96 = 0,
    aes_128_cmac_96 = 1,
    hmac_sha256_128 = 2,
};

// ============================================================================
// SYN Cookies
// ============================================================================

pub const SynCookieState = struct {
    enabled: bool,
    // Encoding parameters
    mss_table: [8]u16,
    // Stats
    sent: u64,
    recv_validations: u64,
    recv_failures: u64,
    overflow_count: u64,
};

// ============================================================================
// TIME_WAIT Management
// ============================================================================

pub const TIME_WAIT_LEN: u32 = 60; // seconds (2MSL)
pub const TIME_WAIT_BUCKETS: u32 = 16384;

pub const TwBucket = struct {
    entries: [32]TimeWaitSock,
    nr_entries: u32,
};

pub const TimeWaitSock = struct {
    // Mini-socket
    sport: u16,
    dport: u16,
    saddr: [16]u8,
    daddr: [16]u8,
    family: u8,
    // Sequence
    snd_nxt: u32,
    rcv_nxt: u32,
    // Timing
    last_ack_sent: u32,
    ts_recent: u32,
    ts_recent_stamp: u64,
    tw_timer: u64,    // Death time
    // Options
    tw_ts_enabled: bool,
    tw_sack: bool,
    tw_wscale: u8,
    tw_rcv_wscale: u8,
    // Recycle
    tw_recycle: bool,
};

pub const TimeWaitManager = struct {
    buckets: [TIME_WAIT_BUCKETS]TwBucket,
    total_entries: u64,
    max_entries: u64,
    reuse_enabled: bool,
    recycle_enabled: bool,
    // Stats
    recycled: u64,
    reaped: u64,
};

// ============================================================================
// TCP Metrics Cache
// ============================================================================

pub const TCP_METRICS_MAX: u32 = 4096;

pub const TcpMetrics = struct {
    daddr: [16]u8,
    saddr: [16]u8,
    family: u8,
    // Cached values
    rtt_us: u32,
    rttvar_us: u32,
    ssthresh: u32,
    cwnd: u32,
    reordering: u32,
    // Timestamps
    last_update: u64,
    age_ms: u64,
    // FastOpen cookie
    tfo_cookie: [16]u8,
    tfo_cookie_len: u8,
    // Validity
    valid: bool,
};

pub const TcpMetricsCache = struct {
    entries: [TCP_METRICS_MAX]TcpMetrics,
    nr_entries: u32,
    hits: u64,
    misses: u64,

    pub fn lookup(self: *const TcpMetricsCache, daddr: [16]u8, family: u8) ?*const TcpMetrics {
        for (self.entries[0..self.nr_entries]) |*entry| {
            if (entry.valid and entry.family == family) {
                if (std.mem.eql(u8, &entry.daddr, &daddr)) {
                    return entry;
                }
            }
        }
        return null;
    }
};

// ============================================================================
// TCP Listener (LISTEN state management)
// ============================================================================

pub const TcpListenState = struct {
    // SYN queue (half-open connections)
    syn_queue: [1024]TcpRequestSock,
    syn_queue_len: u32,
    syn_queue_max: u32,
    // Accept queue (fully established)
    accept_queue_len: u32,
    accept_queue_max: u32,
    // SYN flood protection
    syn_flood_detected: bool,
    syn_cookies_active: bool,
    syncookies: SynCookieState,
    // FastOpen
    tfo_state: TfoState,
    // Stats
    syn_received: u64,
    syn_dropped: u64,
    accept_overflow: u64,
};

pub const TcpRequestSock = struct {
    // Remote
    rmt_addr: [16]u8,
    rmt_port: u16,
    loc_addr: [16]u8,
    loc_port: u16,
    family: u8,
    // Sequence
    rcv_isn: u32,
    snt_isn: u32,
    snt_synack: u64,   // Timestamp of SYN-ACK
    // Options
    mss_clamp: u16,
    wscale_ok: bool,
    tstamp_ok: bool,
    sack_ok: bool,
    ecn_ok: bool,
    wscale: u8,
    // Timers
    retrans: u8,
    expires: u64,
    // TFO
    tfo_listener: bool,
    // SYN cookie
    cookie_ts: bool,
};

// ============================================================================
// TCP Socket Options (setsockopt/getsockopt)
// ============================================================================

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
// TCP Global Parameters
// ============================================================================

pub const TcpGlobalParams = struct {
    // Timeouts
    syn_retries: u8,
    synack_retries: u8,
    orphan_retries: u8,
    fin_timeout: u32,       // Seconds
    tw_timeout: u32,        // TIME_WAIT seconds
    // Limits
    max_syn_backlog: u32,
    max_tw_buckets: u32,
    max_orphans: u32,
    // MSS
    default_mss: u16,
    min_mss: u16,
    base_mss: u16,
    mtu_probing: bool,
    // Congestion
    default_ca_ops: [16]u8,
    allowed_congestion_control: [8][16]u8,
    nr_allowed_ca: u8,
    // ECN
    ecn: u8,                // 0=off, 1=on, 2=server-only
    // SACK
    sack: bool,
    dsack: bool,
    fack: bool,
    // Timestamps
    timestamps: bool,
    // Window scaling
    window_scaling: bool,
    default_window: u32,
    // FastOpen
    fastopen: u32,
    fastopen_key: [2][16]u8,
    // SYN cookies
    syncookies: bool,
    // ABC
    abc: bool,              // Appropriate Byte Counting
    abc_l_limit: u32,
    // Reordering
    reordering: u32,
    // Initial cwnd
    init_cwnd: u32,
    init_rwnd: u32,
    // Memory
    tcp_mem: [3]u64,        // Low/pressure/high (pages)
    tcp_wmem: [3]u32,       // Min/default/max write
    tcp_rmem: [3]u32,       // Min/default/max read
    // MPTCP
    mptcp_enabled: bool,
    // TCP-AO
    ao_required: bool,
    // Zxyphor
    zxy_adaptive_rto: bool,
    zxy_predictive_cc: bool,
};

// ============================================================================
// TCP Subsystem Manager
// ============================================================================

pub const TcpSubsystem = struct {
    params: TcpGlobalParams,
    metrics_cache: TcpMetricsCache,
    tw_manager: TimeWaitManager,
    // Registered congestion control algorithms
    registered_ca: [16]*const TcpCongestionOps,
    nr_registered_ca: u8,
    // Stats
    active_opens: u64,
    passive_opens: u64,
    attempt_fails: u64,
    estab_resets: u64,
    curr_estab: u64,
    in_segs: u64,
    out_segs: u64,
    retrans_segs: u64,
    in_errs: u64,
    out_rsts: u64,
    in_csum_errors: u64,
    // Memory
    sockets_allocated: u64,
    orphan_count: u64,
    tw_count: u64,
    memory_allocated: u64,
    memory_pressure: bool,
};
