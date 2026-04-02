// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - TCP Congestion Control Framework
// Complete congestion control algorithms: CUBIC, BBR, DCTCP, Reno,
// Vegas, Westwood+, HTCP, Illinois, Scalable, BIC, CDG, NV, BBRv2

const std = @import("std");

// ============================================================================
// TCP Congestion State Machine
// ============================================================================

pub const TcpCaState = enum(u8) {
    Open = 0,
    Disorder = 1,
    Cwr = 2,
    Recovery = 3,
    Loss = 4,
};

pub const TcpCaEvent = enum(u8) {
    TxStart = 0,
    CwndRestart = 1,
    CompleteAck = 2,
    LossDetected = 3,
    EcnNotification = 4,
    EcnIsEce = 5,
    DelayedAck = 6,
    NonDelayedAck = 7,
};

pub const TcpCaAckType = enum(u8) {
    Normal = 0,
    Slow = 1,
    Ecn = 2,
};

// ============================================================================
// Congestion Control Operations
// ============================================================================

pub const TcpCongestionOps = struct {
    name: [16]u8,
    owner_module: u64,
    key: u32,
    flags: TcpCaFlags,

    // Core callbacks
    init: ?*const fn (*TcpSock) void,
    release: ?*const fn (*TcpSock) void,
    ssthresh: ?*const fn (*TcpSock) u32,
    cong_avoid: ?*const fn (*TcpSock, u32, u32) void,
    set_state: ?*const fn (*TcpSock, TcpCaState) void,
    cwnd_event: ?*const fn (*TcpSock, TcpCaEvent) void,
    in_ack_event: ?*const fn (*TcpSock, u32) void,
    pkts_acked: ?*const fn (*TcpSock, *const AckSample) void,
    min_tso_segs: ?*const fn (*TcpSock) u32,
    cong_control: ?*const fn (*TcpSock, *const RateSample) void,
    undo_cwnd: ?*const fn (*TcpSock) u32,
    sndbuf_expand: ?*const fn (*TcpSock) u32,
    get_info: ?*const fn (*TcpSock, u32, *[256]u8) void,
};

pub const TcpCaFlags = packed struct(u32) {
    requires_ecn: bool = false,
    not_safe_to_use: bool = false,
    requires_tso: bool = false,
    _reserved: u29 = 0,
};

// ============================================================================
// Rate Sample (for BBR and modern CCs)
// ============================================================================

pub const RateSample = struct {
    prior_mstamp: u64,     // Time of prior delivered count
    prior_delivered: u32,  // Number delivered at prior_mstamp
    prior_delivered_ce: u32,
    delivered: i32,        // Delivered in this interval
    delivered_ce: i32,     // ECN-marked packets delivered
    interval_us: i64,      // Interval in microseconds
    snd_interval_us: i64,
    rcv_interval_us: i64,
    rtt_us: i64,           // RTT of sample
    losses: i32,           // Losses in this interval
    acked_sacked: u32,
    prior_in_flight: u32,
    last_end_seq: u32,
    is_app_limited: bool,
    is_retrans: bool,
    is_ack_delayed: bool,
};

pub const AckSample = struct {
    pkts_acked: u32,
    rtt_us: i64,
    in_flight: u32,
};

pub const TcpSock = struct {
    // Congestion control state
    snd_cwnd: u32,
    snd_cwnd_cnt: u32,
    snd_cwnd_clamp: u32,
    snd_cwnd_stamp: u32,
    snd_ssthresh: u32,
    prior_cwnd: u32,
    prior_ssthresh: u32,

    // RTT state
    srtt_us: u32,          // Smoothed RTT (us << 3)
    mdev_us: u32,          // Medium deviation
    mdev_max_us: u32,      // Max deviation
    rttvar_us: u32,        // Smoothed mdev_max
    rtt_seq: u32,          // Sequence number for RTT
    rtt_min: [3]u32,       // Windowed min RTT (3 buckets)

    // Pacing
    pacing_rate: u64,      // Bits/sec
    max_pacing_rate: u64,
    pacing_timer_armed: bool,

    // Loss & ECN
    lost_out: u32,
    sacked_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    ecn_flags: u8,
    delivered: u32,
    delivered_ce: u32,
    app_limited: u32,

    // Flow state
    bytes_acked: u64,
    bytes_received: u64,
    snd_nxt: u32,
    snd_una: u32,
    write_seq: u32,
    packets_out: u32,
    max_packets_out: u32,
    rate_delivered: u32,
    rate_interval_us: u32,

    // CA state
    ca_state: TcpCaState,
    icsk_ca_ops: ?*const TcpCongestionOps,
    ca_priv: [128]u8,      // Private CC data
};

// ============================================================================
// CUBIC Congestion Control
// ============================================================================

pub const CubicState = struct {
    cnt: u32,
    last_cwnd: u32,
    last_time: u32,
    origin_point: u32,
    bic_K: u64,            // Time to reach W_max from origin
    tcp_cwnd: u32,         // TCP-friendly cwnd
    ack_cnt: u32,
    W_last_max: u32,       // Last W_max before reduction
    epoch_start: u32,
    found_slow_start: bool,
    delay_min: u32,
    bic_target: u32,
    // HyStart parameters
    hystart_detect: u8,
    hystart_found: u8,
    last_ack: u32,
    curr_rtt: u32,
    round_start: u32,
    end_seq: u32,
    sample_cnt: u32,
    delay_min_stamp: u32,
};

pub const CUBIC_BETA = 717;       // 0.7 * 1024
pub const CUBIC_BETA_SCALE = 1024;
pub const CUBIC_C = 410;
pub const CUBIC_HZ = 10;
pub const HYSTART_ACK_TRAIN = 0x1;
pub const HYSTART_DELAY = 0x2;
pub const HYSTART_MIN_SAMPLES = 8;
pub const HYSTART_DELAY_MIN = 4000;
pub const HYSTART_DELAY_MAX = 16000;
pub const HYSTART_DELAY_THRESH = fn(x: u32) u32 {
    return @min(HYSTART_DELAY_MAX, @max(HYSTART_DELAY_MIN, x >> 4));
};

pub fn cubicReset(ca: *CubicState) void {
    ca.cnt = 0;
    ca.last_cwnd = 0;
    ca.last_time = 0;
    ca.origin_point = 0;
    ca.bic_K = 0;
    ca.tcp_cwnd = 0;
    ca.ack_cnt = 0;
    ca.found_slow_start = false;
    ca.epoch_start = 0;
}

pub fn cubicSsthresh(sk: *TcpSock) u32 {
    const ca: *CubicState = @ptrCast(@alignCast(&sk.ca_priv));
    ca.epoch_start = 0;
    if (sk.snd_cwnd < ca.last_cwnd) {
        ca.W_last_max = (sk.snd_cwnd * (CUBIC_BETA_SCALE + CUBIC_BETA)) / (2 * CUBIC_BETA_SCALE);
    } else {
        ca.W_last_max = sk.snd_cwnd;
    }
    return @max((sk.snd_cwnd * CUBIC_BETA) / CUBIC_BETA_SCALE, 2);
}

// ============================================================================
// BBR Congestion Control (v2)
// ============================================================================

pub const BbrPhase = enum(u8) {
    Startup = 0,
    Drain = 1,
    ProbeBW = 2,
    ProbeRTT = 3,
};

pub const BbrCyclePhase = enum(u8) {
    Up = 0,
    Down = 1,
    Cruise = 2,
    Refill = 3,
};

pub const BbrBwFilterLen = 10; // Number of RTTs in BW filter window

pub const BbrState = struct {
    // Model parameters
    bw_lo: u64,           // Lower bound bandwidth
    bw_hi: u64,           // Upper bound bandwidth
    bw: u64,              // Max filter of delivered BW
    min_rtt_us: u32,      // Min RTT in us
    min_rtt_stamp: u32,   // Timestamp of min RTT

    // Phase state
    phase: BbrPhase,
    cycle_phase: BbrCyclePhase,
    cycle_len: u8,
    cycle_idx: u8,
    full_bw_cnt: u8,
    full_bw_reached: bool,

    // Pacing and cwnd
    pacing_gain: u32,
    cwnd_gain: u32,
    prior_cwnd: u32,
    target_cwnd: u32,
    rtt_cnt: u32,

    // ProbeRTT state
    probe_rtt_done_stamp: u32,
    probe_rtt_round_done: bool,
    probe_rtt_min_us: u32,
    probe_rtt_min_stamp: u32,

    // BBRv2 additions
    ecn_eligible: bool,
    ecn_alpha: u32,        // ECN-awareness (BBRv2)
    ecn_in_round: u32,
    ecn_in_cycle: u32,
    loss_in_round: u32,
    loss_in_cycle: u32,
    bw_probe_samples: u32,
    bw_probe_up_cnt: u32,
    bw_probe_up_acks: u32,
    inflight_lo: u32,
    inflight_hi: u32,
    bw_probe_wait: u32,

    // Startup parameters
    startup_pacing_gain: u32,
    startup_cwnd_gain: u32,

    // Round tracking
    round_start: bool,
    next_round_delivered: u32,
};

pub const BBR_STARTUP_PACING_GAIN = 277;  // 2.77x (scaled by 100)
pub const BBR_DRAIN_PACING_GAIN = 35;     // 0.35x
pub const BBR_CWND_GAIN = 200;            // 2.0x
pub const BBR_PROBE_RTT_CWND = 4;
pub const BBR_PROBE_RTT_DURATION_MS = 200;
pub const BBR_MIN_CWND = 4;

pub fn bbrInit(sk: *TcpSock) void {
    const bbr: *BbrState = @ptrCast(@alignCast(&sk.ca_priv));
    bbr.phase = .Startup;
    bbr.cycle_phase = .Up;
    bbr.pacing_gain = BBR_STARTUP_PACING_GAIN;
    bbr.cwnd_gain = BBR_CWND_GAIN;
    bbr.full_bw_reached = false;
    bbr.full_bw_cnt = 0;
    bbr.min_rtt_us = 0xFFFFFFFF;
    bbr.probe_rtt_round_done = false;
    bbr.ecn_eligible = true;
    bbr.ecn_alpha = 0;
    bbr.inflight_lo = 0xFFFFFFFF;
    bbr.inflight_hi = 0xFFFFFFFF;
    bbr.round_start = false;
    bbr.bw = 0;
    bbr.bw_lo = 0xFFFFFFFFFFFFFFFF;
    bbr.bw_hi = 0;
    sk.pacing_rate = 0;
}

// ============================================================================
// DCTCP (Data Center TCP)
// ============================================================================

pub const DctcpState = struct {
    old_delivered: u32,
    old_delivered_ce: u32,
    next_seq: u32,
    ce_state: bool,
    delayed_ack_reserved: bool,
    loss_cwnd: u32,
    alpha: u32,            // ECN-marking rate (0-1024)
    dctcp_alpha: u32,
    ece_acked: u32,
    num_acked: u32,
};

pub const DCTCP_MAX_ALPHA = 1024;
pub const DCTCP_SHIFT_G = 4;     // g = 1/16

pub fn dctcpInit(sk: *TcpSock) void {
    const ca: *DctcpState = @ptrCast(@alignCast(&sk.ca_priv));
    ca.alpha = DCTCP_MAX_ALPHA;
    ca.dctcp_alpha = DCTCP_MAX_ALPHA;
    ca.ce_state = false;
    ca.delayed_ack_reserved = false;
    ca.loss_cwnd = 0;
    ca.ece_acked = 0;
    ca.num_acked = 0;
}

pub fn dctcpSsthresh(sk: *TcpSock) u32 {
    const ca: *DctcpState = @ptrCast(@alignCast(&sk.ca_priv));
    _ = ca;
    const dctcp_alpha = @as(*DctcpState, @ptrCast(@alignCast(&sk.ca_priv))).dctcp_alpha;
    return @max(sk.snd_cwnd -| ((sk.snd_cwnd * dctcp_alpha) >> 11), 2);
}

// ============================================================================
// Vegas
// ============================================================================

pub const VegasState = struct {
    beg_snd_nxt: u32,
    beg_snd_una: u32,
    beg_snd_cwnd: u32,
    baseRTT: u32,         // Minimum observed RTT (us)
    minRTT: u32,          // Min RTT in current window
    cntRTT: u32,          // Number of RTT samples
    doing_vegas_now: bool,
};

pub const VEGAS_ALPHA = 2;
pub const VEGAS_BETA = 4;
pub const VEGAS_GAMMA = 1;

pub fn vegasInit(sk: *TcpSock) void {
    const v: *VegasState = @ptrCast(@alignCast(&sk.ca_priv));
    v.baseRTT = 0x7FFFFFFF;
    v.minRTT = 0x7FFFFFFF;
    v.cntRTT = 0;
    v.doing_vegas_now = true;
}

// ============================================================================
// Westwood+
// ============================================================================

pub const WestwoodState = struct {
    bw_ns_est: u32,      // First bandwidth estimate (B/s)
    bw_est: u32,          // Second bandwidth estimate (B/s)
    rtt_win: u32,         // RTT window (us)
    bk: u32,              // Bytes acked
    snd_una: u32,         // Copy of snd_una
    cumul_ack: u32,       // Cumulative ACK count
    accounted: u32,
    rtt: u32,
    rtt_min: u32,
    count: u8,
    first_ack: bool,
    reset_rtt_min: bool,
};

pub fn westwoodInit(sk: *TcpSock) void {
    const w: *WestwoodState = @ptrCast(@alignCast(&sk.ca_priv));
    w.bw_ns_est = 0;
    w.bw_est = 0;
    w.rtt_win = 0;
    w.bk = 0;
    w.rtt_min = 0x7FFFFFFF;
    w.first_ack = true;
    w.reset_rtt_min = false;
}

// ============================================================================
// HTCP (Hamilton TCP)
// ============================================================================

pub const HtcpState = struct {
    alpha: u32,
    beta: u32,
    modeswitch: bool,
    last_cong: u32,
    undo_last_cong: u32,
    undo_maxB: u32,
    minB: u32,
    maxB: u32,
    Bi: u32,
    lasttime: u32,
    minRTT: u32,
    maxRTT: u32,
    t_start: u32,
    pkts_acked: u32,
};

pub const HTCP_BETA_MIN = 128;
pub const HTCP_BETA_MAX = 512;

// ============================================================================
// Illinois
// ============================================================================

pub const IllinoisState = struct {
    sum_rtt: u64,
    end_seq: u32,
    alpha: u32,
    beta: u32,
    base_rtt: u32,
    max_rtt: u32,
    cnt_rtt: u32,
    acked: u32,
};

pub const ILLINOIS_ALPHA_MAX = 819;   // scaled 0.8
pub const ILLINOIS_ALPHA_MIN = 51;    // scaled 0.05
pub const ILLINOIS_BETA_MAX = 819;    // scaled 0.8
pub const ILLINOIS_BETA_MIN = 205;    // scaled 0.2

// ============================================================================
// CDG (CAIA Delay-Gradient)
// ============================================================================

pub const CdgState = struct {
    shadow_wnd: u32,
    backoff_cnt: u32,
    backoff_factor: u32,
    rtt_seq: u32,
    rtt_prev: u32,
    undo_cwnd: u32,
    delay_min: u32,
    delay_max: u32,
    tail: i32,
    gradients: [8]i32,
    gsum: i32,
    state: CdgPhase,
};

pub const CdgPhase = enum(u8) {
    Unknown = 0,
    NoBkoff = 1,
    BackOff = 2,
    Full = 3,
};

// ============================================================================
// Scalable TCP
// ============================================================================

pub const ScalableState = struct {
    ai_cnt: u32,
    // Scalable uses simple cwnd increase: cwnd + 0.01 * cwnd each RTT
    // and cwnd * 0.875 on loss
};

pub const SCALABLE_AI = 50;   // cwnd increment: cwnd / 50
pub const SCALABLE_MD = 875;  // Multiplicative decrease: 0.875

// ============================================================================
// BIC (Binary Increase Congestion control)
// ============================================================================

pub const BicState = struct {
    cnt: u32,
    last_cwnd: u32,
    last_time: u32,
    last_max_cwnd: u32,
    epoch_start: u32,
    delayed_ack: u32,
};

pub const BIC_SCALE = 41;
pub const BIC_MAX_INCREMENT = 16;
pub const BIC_LOW_WINDOW = 14;
pub const BIC_BETA = 819;  // scaled 0.8

// ============================================================================
// NV (New Vegas - for datacenter)
// ============================================================================

pub const NvState = struct {
    min_rtt: u32,
    min_rtt_new: u32,
    nv_allow_cwnd_growth: bool,
    nv_reset: bool,
    nv_catchup: bool,
    nv_no_cong_cnt: u32,
    nv_rtt_cnt: u32,
    nv_last_rtt: u32,
    nv_rtt_max_rate: u32,
    nv_base_rtt: u32,
    nv_lower_bound_rtt: u32,
    cwnd_growth_factor: u32,
};

pub const NV_ALPHA = 2;
pub const NV_MIN_CWND = 2;
pub const NV_RTT_FACTOR = 128;

// ============================================================================
// Congestion Control Registry
// ============================================================================

pub const MAX_CC_ALGORITHMS = 32;

pub const CcRegistryEntry = struct {
    ops: *const TcpCongestionOps,
    refcount: u32,
    is_default: bool,
};

pub const TcpCcManager = struct {
    registry: [MAX_CC_ALGORITHMS]?CcRegistryEntry,
    num_registered: u32,
    default_cc_name: [16]u8,
    initialized: bool,

    pub fn init() TcpCcManager {
        var mgr = TcpCcManager{
            .registry = [_]?CcRegistryEntry{null} ** MAX_CC_ALGORITHMS,
            .num_registered = 0,
            .default_cc_name = [_]u8{0} ** 16,
            .initialized = true,
        };
        // Set default to "cubic"
        const name = "cubic";
        @memcpy(mgr.default_cc_name[0..name.len], name);
        return mgr;
    }

    pub fn register(self: *TcpCcManager, ops: *const TcpCongestionOps) bool {
        if (self.num_registered >= MAX_CC_ALGORITHMS) return false;
        self.registry[self.num_registered] = .{
            .ops = ops,
            .refcount = 0,
            .is_default = false,
        };
        self.num_registered += 1;
        return true;
    }

    pub fn findByName(self: *const TcpCcManager, name: []const u8) ?*const TcpCongestionOps {
        for (self.registry[0..self.num_registered]) |entry| {
            if (entry) |e| {
                const ops_name = std.mem.sliceTo(&e.ops.name, 0);
                if (std.mem.eql(u8, ops_name, name)) {
                    return e.ops;
                }
            }
        }
        return null;
    }
};
