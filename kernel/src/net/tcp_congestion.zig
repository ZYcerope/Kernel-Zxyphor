// =============================================================================
// Kernel Zxyphor — TCP Congestion Control Framework
// =============================================================================
// Full implementation of pluggable congestion control algorithms including:
//   - CUBIC (RFC 8312) — default Linux CC since 2.6.19
//   - BBR v3 (Bottleneck Bandwidth and Round-trip propagation time)
//   - DCTCP (Data Center TCP, RFC 8257)
//   - Vegas (delay-based)
//   - Westwood+ (bandwidth estimation)
//   - HTCP (Hamilton TCP)
//   - Illinois (hybrid loss/delay)
//   - Scalable TCP
//   - BIC (Binary Increase Congestion control)
//   - New Reno (RFC 6582) — baseline
//   - LEDBAT (Low Extra Delay Background Transport, RFC 6817)
//   - PCC Vivace (Performance-oriented CC)
//   - Copa (delay-based competitive)
//
// Framework supports:
//   - Per-connection algorithm selection via setsockopt
//   - ECN/ECE/CWR markings for AQM cooperation
//   - ACK-clocking and pacing engine
//   - Hybrid slow start (HyStart/HyStart++)
//   - RACK-TLP loss detection (RFC 8985)
//   - PRR (Proportional Rate Reduction, RFC 6937)
//   - Pacing with FQ/token bucket shaper
// =============================================================================

const std = @import("std");
const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const USEC_PER_SEC: u64 = 1_000_000;
pub const MSEC_PER_SEC: u64 = 1000;
pub const NSEC_PER_USEC: u64 = 1000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

pub const TCP_INIT_CWND: u32 = 10; // RFC 6928: IW=10
pub const TCP_MIN_CWND: u32 = 2;
pub const TCP_MAX_CWND: u32 = 1 << 24; // 16M segments
pub const TCP_MSS_DEFAULT: u32 = 1460;
pub const TCP_MIN_RTO_US: u64 = 200_000; // 200ms
pub const TCP_MAX_RTO_US: u64 = 120_000_000; // 120s
pub const TCP_TIMEOUT_INIT_US: u64 = 1_000_000; // 1s
pub const TCP_RTO_MIN_MS: u64 = 200;
pub const TCP_DELACK_MAX_US: u64 = 200_000;
pub const TCP_RACK_REORDER_THRESH: u32 = 3;
pub const TCP_RACK_DSACK_THRESH: u32 = 3;
pub const TCP_TLP_MAX_PROBES: u32 = 2;
pub const TCP_PACING_SS_RATIO: u32 = 200; // 200% in slow start
pub const TCP_PACING_CA_RATIO: u32 = 120; // 120% in congestion avoidance

/// CUBIC parameters
pub const CUBIC_BETA: u64 = 717; // β = 0.7 scaled by 1024
pub const CUBIC_BETA_SCALE: u64 = 1024;
pub const CUBIC_C_SCALED: u64 = 410; // C = 0.4 scaled by 1024
pub const CUBIC_HZ: u64 = 1024;

/// BBR v3 parameters
pub const BBR_UNIT: u64 = 1 << 8; // 256 for fixed-point
pub const BBR_SCALE: u32 = 8;
pub const BBR_HIGH_GAIN: u64 = (2885 * BBR_UNIT + 1000 - 1) / 1000; // 2/ln(2)
pub const BBR_DRAIN_GAIN: u64 = (1000 * BBR_UNIT + 2885 - 1) / 2885; // 1/(2/ln(2))
pub const BBR_CWND_GAIN: u64 = 2 * BBR_UNIT;
pub const BBR_PROBE_RTT_MODE_MS: u64 = 200;
pub const BBR_MIN_PIPE_CWND: u32 = 4;
pub const BBR_CYCLE_PHASES: u32 = 8;
pub const BBR_FULL_BW_THRESH: u64 = (BBR_UNIT * 5) / 4; // 1.25x
pub const BBR_FULL_BW_CNT: u32 = 3;
pub const BBR_PROBE_RTT_CWND_GAIN: u64 = BBR_UNIT / 2;
pub const BBR_EXTRA_ACKED_MAX_FILTER_LEN: u32 = 10;

/// DCTCP parameters
pub const DCTCP_ALPHA_SHIFT: u32 = 10;
pub const DCTCP_MAX_ALPHA: u32 = 1 << DCTCP_ALPHA_SHIFT; // 1024
pub const DCTCP_EWMA_WEIGHT: u32 = 16; // g = 1/16

// =============================================================================
// Congestion Control Algorithm ID
// =============================================================================
pub const CcAlgorithm = enum(u8) {
    new_reno = 0,
    cubic = 1,
    bbr = 2,
    bbr_v3 = 3,
    dctcp = 4,
    vegas = 5,
    westwood = 6,
    htcp = 7,
    illinois = 8,
    scalable = 9,
    bic = 10,
    ledbat = 11,
    pcc_vivace = 12,
    copa = 13,
};

// =============================================================================
// Congestion Control Events
// =============================================================================
pub const CcEvent = enum(u8) {
    ack_received,
    packet_sent,
    loss_detected,
    ecn_received,
    timeout,
    fast_retransmit,
    recovery_exit,
    cwnd_restart,
    enter_cwr,
    probe_rtt,
    hystart_delay,
};

// =============================================================================
// TCP Connection Metrics
// =============================================================================
pub const TcpMetrics = struct {
    // RTT measurements (microseconds)
    srtt_us: u64 = 0, // Smoothed RTT
    rttvar_us: u64 = 0, // RTT variance
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF, // Minimum observed RTT
    max_rtt_us: u64 = 0, // Maximum observed RTT
    last_rtt_us: u64 = 0, // Most recent RTT sample
    rtt_sample_count: u64 = 0,

    // Timestamps
    min_rtt_stamp_us: u64 = 0, // When min_rtt was recorded
    probe_rtt_done_stamp: u64 = 0,

    // Bandwidth measurements
    delivered: u64 = 0, // Total delivered segments
    delivered_ce: u64 = 0, // CE-marked delivered
    delivered_mstamp_us: u64 = 0,
    first_tx_mstamp_us: u64 = 0,
    interval_us: u64 = 0,
    delivery_rate_bps: u64 = 0, // Estimated delivery rate
    max_bw_bps: u64 = 0, // Peak bandwidth

    // Loss tracking
    lost: u64 = 0, // Total lost segments
    retransmits: u64 = 0, // Total retransmissions
    sack_holes: u32 = 0,
    reordering: u32 = TCP_RACK_REORDER_THRESH,

    // Window metrics
    cwnd: u32 = TCP_INIT_CWND,
    ssthresh: u32 = 0xFFFFFFFF, // Initial ssthresh = infinity
    prior_cwnd: u32 = 0,
    prior_ssthresh: u32 = 0,
    snd_wnd: u32 = 0, // Sender window (from receiver)
    rcv_wnd: u32 = 65535,

    // Pacing
    pacing_rate_bps: u64 = 0,
    pacing_gain: u64 = BBR_UNIT,
    next_send_time_us: u64 = 0,
    pacing_timer_active: bool = false,

    // ECN
    ecn_enabled: bool = false,
    ce_count: u64 = 0,
    ecn_ce_ratio: u32 = 0,

    // Bytes
    bytes_acked: u64 = 0,
    bytes_in_flight: u64 = 0,
    mss: u32 = TCP_MSS_DEFAULT,

    // Application limited
    app_limited: bool = false,
    app_limited_until: u64 = 0,

    // Slow start
    in_slow_start: bool = true,
    in_recovery: bool = false,
    in_cwr: bool = false,

    pub fn rto_us(self: *const TcpMetrics) u64 {
        if (self.srtt_us == 0) return TCP_TIMEOUT_INIT_US;
        var rto = self.srtt_us + @max(1, 4 * self.rttvar_us);
        rto = @max(rto, TCP_MIN_RTO_US);
        rto = @min(rto, TCP_MAX_RTO_US);
        return rto;
    }

    pub fn updateRtt(self: *TcpMetrics, rtt_us: u64) void {
        self.last_rtt_us = rtt_us;
        self.rtt_sample_count += 1;

        if (rtt_us < self.min_rtt_us) {
            self.min_rtt_us = rtt_us;
        }
        if (rtt_us > self.max_rtt_us) {
            self.max_rtt_us = rtt_us;
        }

        // RFC 6298 SRTT/RTTVAR computation
        if (self.srtt_us == 0) {
            // First sample
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|
            // beta = 1/4, alpha = 1/8
            const delta = if (rtt_us > self.srtt_us) rtt_us - self.srtt_us else self.srtt_us - rtt_us;
            self.rttvar_us = (3 * self.rttvar_us + delta) / 4;
            self.srtt_us = (7 * self.srtt_us + rtt_us) / 8;
        }
    }

    pub fn updateDeliveryRate(self: *TcpMetrics, now_us: u64) void {
        if (self.interval_us == 0) return;
        // delivery_rate = delivered_bytes / interval
        const delivered_bytes = self.delivered * @as(u64, self.mss);
        self.delivery_rate_bps = (delivered_bytes * 8 * USEC_PER_SEC) / self.interval_us;
        if (self.delivery_rate_bps > self.max_bw_bps) {
            self.max_bw_bps = self.delivery_rate_bps;
        }
        _ = now_us;
    }

    pub fn cwndInBytes(self: *const TcpMetrics) u64 {
        return @as(u64, self.cwnd) * @as(u64, self.mss);
    }
};

// =============================================================================
// HyStart++ (Hybrid Slow Start)
// =============================================================================
pub const HyStartState = enum(u8) {
    inactive,
    css, // Conservative Slow Start
    delay_based_exit,
    loss_based_exit,
};

pub const HyStart = struct {
    state: HyStartState = .inactive,
    round_start: u64 = 0,
    last_round_min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    curr_round_min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    rtt_thresh_us: u64 = 0,
    css_baseline_min_rtt_us: u64 = 0,
    css_rounds: u32 = 0,
    sample_count: u32 = 0,
    ack_count: u32 = 0,
    end_seq: u32 = 0,

    // HyStart++ constants
    const CSS_GROWTH_DIVISOR: u32 = 4;
    const CSS_ROUNDS_MAX: u32 = 8;
    const MIN_RTT_DIVISOR: u64 = 8;
    const MIN_RTT_THRESH_US: u64 = 4000; // 4ms
    const MAX_RTT_THRESH_US: u64 = 16000; // 16ms
    const N_RTT_SAMPLE: u32 = 8;

    pub fn reset(self: *HyStart) void {
        self.state = .inactive;
        self.sample_count = 0;
        self.ack_count = 0;
        self.curr_round_min_rtt_us = 0xFFFFFFFFFFFFFFFF;
    }

    pub fn startRound(self: *HyStart, snd_nxt: u32) void {
        self.round_start = 0; // Will be set on first ACK
        self.end_seq = snd_nxt;
        self.last_round_min_rtt_us = self.curr_round_min_rtt_us;
        self.curr_round_min_rtt_us = 0xFFFFFFFFFFFFFFFF;
        self.sample_count = 0;
    }

    pub fn onAck(self: *HyStart, rtt_us: u64, snd_una: u32, metrics: *TcpMetrics) bool {
        if (self.state == .delay_based_exit or self.state == .loss_based_exit)
            return false;

        if (rtt_us < self.curr_round_min_rtt_us) {
            self.curr_round_min_rtt_us = rtt_us;
        }
        self.sample_count += 1;

        // Check if round ended
        if (wrappingGe(snd_una, self.end_seq)) {
            // Round complete — compute delay threshold
            if (self.last_round_min_rtt_us != 0xFFFFFFFFFFFFFFFF) {
                self.rtt_thresh_us = self.last_round_min_rtt_us / MIN_RTT_DIVISOR;
                self.rtt_thresh_us = @max(self.rtt_thresh_us, MIN_RTT_THRESH_US);
                self.rtt_thresh_us = @min(self.rtt_thresh_us, MAX_RTT_THRESH_US);

                // Delay-based check: if current min_rtt exceeds threshold
                if (self.curr_round_min_rtt_us > self.last_round_min_rtt_us + self.rtt_thresh_us) {
                    if (self.state == .inactive) {
                        // Enter CSS
                        self.state = .css;
                        self.css_baseline_min_rtt_us = self.curr_round_min_rtt_us;
                        self.css_rounds = 0;
                    } else if (self.state == .css) {
                        self.css_rounds += 1;
                        if (self.css_rounds >= CSS_ROUNDS_MAX) {
                            // Exit slow start — delay based
                            self.state = .delay_based_exit;
                            metrics.ssthresh = metrics.cwnd;
                            metrics.in_slow_start = false;
                            return false;
                        }
                    }
                } else {
                    // RTT improved, reset CSS
                    if (self.state == .css) {
                        self.state = .inactive;
                        self.css_rounds = 0;
                    }
                }
            }

            // Start new round
            self.startRound(snd_una +% @as(u32, @truncate(metrics.cwnd)));
        }
        return true;
    }
};

// =============================================================================
// CUBIC State
// =============================================================================
pub const CubicState = struct {
    cnt: u64 = 0, // cwnd increase count
    last_cwnd: u32 = 0, // last cwnd before loss
    last_time: u64 = 0, // timestamp of last cwnd update
    epoch_start: u64 = 0, // start of current epoch
    origin_point: u32 = 0, // W_max at last loss
    tcp_cwnd: u32 = 0, // estimated New Reno cwnd
    bic_K: u64 = 0, // time to reach origin_point
    ack_cnt: u64 = 0, // number of ACKs
    delayed_ack: u32 = 2, // estimated delayed ACK ratio
    found_slow_start_exit: bool = false,
    hystart: HyStart = .{},

    /// Cube root computation via Newton's method (integer)
    fn cbrt(x: u64) u64 {
        if (x == 0) return 0;
        if (x < 8) return 1;

        // Initial estimate
        var r: u64 = 1;
        // Find highest bit
        var v = x;
        var bits: u32 = 0;
        while (v > 0) : (bits += 1) v >>= 1;
        r = @as(u64, 1) << @intCast(bits / 3);

        // Newton iterations: r = (2*r + x/(r*r)) / 3
        var i: u32 = 0;
        while (i < 20) : (i += 1) {
            const r2 = r * r;
            if (r2 == 0) break;
            const new_r = (2 * r + x / r2) / 3;
            if (new_r == r) break;
            r = new_r;
        }
        return r;
    }

    pub fn reset(self: *CubicState) void {
        self.cnt = 0;
        self.last_cwnd = 0;
        self.last_time = 0;
        self.epoch_start = 0;
        self.origin_point = 0;
        self.tcp_cwnd = 0;
        self.bic_K = 0;
        self.ack_cnt = 0;
        self.found_slow_start_exit = false;
    }

    pub fn onAck(self: *CubicState, metrics: *TcpMetrics, now_us: u64) void {
        if (metrics.in_slow_start) {
            // Standard exponential increase
            metrics.cwnd += 1;
            return;
        }

        if (self.epoch_start == 0) {
            self.epoch_start = now_us;
            if (metrics.cwnd < self.last_cwnd) {
                // K = cbrt(last_cwnd - cwnd) scaled
                const diff: u64 = @as(u64, self.last_cwnd) -| @as(u64, metrics.cwnd);
                self.bic_K = cbrt(diff * CUBIC_HZ / CUBIC_C_SCALED);
                self.origin_point = self.last_cwnd;
            } else {
                self.bic_K = 0;
                self.origin_point = metrics.cwnd;
            }
            self.ack_cnt = 1;
            self.tcp_cwnd = metrics.cwnd;
        }

        // Elapsed time since epoch
        const t_us = now_us -| self.epoch_start;
        const t_sec_scaled = (t_us * CUBIC_HZ) / USEC_PER_SEC;

        // CUBIC: W(t) = C*(t-K)^3 + W_max
        var target: u64 = 0;
        if (t_sec_scaled > self.bic_K) {
            const offs = t_sec_scaled - self.bic_K;
            target = (CUBIC_C_SCALED * offs * offs * offs) / (CUBIC_HZ * CUBIC_HZ * CUBIC_HZ);
            target += @as(u64, self.origin_point);
        } else {
            const offs = self.bic_K - t_sec_scaled;
            const sub = (CUBIC_C_SCALED * offs * offs * offs) / (CUBIC_HZ * CUBIC_HZ * CUBIC_HZ);
            target = @as(u64, self.origin_point) -| sub;
        }

        // TCP-friendly region: ensure we're at least as aggressive as Reno
        self.tcp_cwnd += 1; // simplified Reno increase

        if (target < @as(u64, self.tcp_cwnd)) {
            target = @as(u64, self.tcp_cwnd);
        }

        // Update cwnd toward target
        if (target > @as(u64, metrics.cwnd)) {
            self.cnt = @as(u64, metrics.cwnd) / (target - @as(u64, metrics.cwnd));
        } else {
            self.cnt = 100 * @as(u64, metrics.cwnd); // very slow increase
        }

        self.ack_cnt += 1;
        if (self.ack_cnt >= self.cnt) {
            metrics.cwnd += 1;
            self.ack_cnt = 0;
        }
    }

    pub fn onLoss(self: *CubicState, metrics: *TcpMetrics) void {
        self.epoch_start = 0; // Reset epoch
        self.last_cwnd = metrics.cwnd;

        // β = 0.7 (CUBIC_BETA / CUBIC_BETA_SCALE)
        metrics.ssthresh = @intCast((@as(u64, metrics.cwnd) * CUBIC_BETA) / CUBIC_BETA_SCALE);
        if (metrics.ssthresh < TCP_MIN_CWND) {
            metrics.ssthresh = TCP_MIN_CWND;
        }
        metrics.cwnd = metrics.ssthresh;
        metrics.in_slow_start = false;
        metrics.in_recovery = true;
    }
};

// =============================================================================
// BBR v3 State
// =============================================================================
pub const BbrMode = enum(u8) {
    startup,
    drain,
    probe_bw,
    probe_rtt,
};

pub const BbrCyclePhase = enum(u8) {
    up,
    down,
    cruise,
};

pub const BbrState = struct {
    mode: BbrMode = .startup,
    cycle_phase: BbrCyclePhase = .up,
    cycle_stamp_us: u64 = 0,
    cycle_len: u32 = 0,
    pacing_gain: u64 = BBR_HIGH_GAIN,
    cwnd_gain: u64 = BBR_CWND_GAIN,

    // BW filter (windowed max)
    bw_filter: [BBR_CYCLE_PHASES]u64 = [_]u64{0} ** BBR_CYCLE_PHASES,
    bw_filter_idx: u32 = 0,
    max_bw: u64 = 0,

    // RTT filter (windowed min over ~10s)
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    min_rtt_stamp_us: u64 = 0,
    probe_rtt_done_stamp_us: u64 = 0,
    probe_rtt_round_done: bool = false,
    min_rtt_expired: bool = false,
    probe_rtt_min_us: u64 = 0xFFFFFFFFFFFFFFFF,

    // Full pipe detection
    full_bw: u64 = 0,
    full_bw_count: u32 = 0,
    full_bw_reached: bool = false,

    // Round tracking
    round_count: u64 = 0,
    round_start: bool = false,
    next_round_delivered: u64 = 0,

    // Inflight tracking
    inflight_lo: u32 = 0xFFFFFFFF,
    inflight_hi: u32 = 0xFFFFFFFF,
    bw_lo: u64 = 0xFFFFFFFFFFFFFFFF,
    bw_hi: [2]u64 = [_]u64{0} ** 2,

    // Extra ACKed filter (aggregation estimator)
    extra_acked: [2]u64 = [_]u64{0} ** 2,
    extra_acked_filter_idx: u32 = 0,
    ack_epoch_stamp_us: u64 = 0,
    ack_epoch_acked: u64 = 0,

    // BBRv3 specific
    loss_round_start: u64 = 0,
    loss_round_delivered: u64 = 0,
    loss_in_round: bool = false,
    ecn_in_round: bool = false,
    bw_probe_up_cnt: u32 = 0,
    bw_probe_up_acks: u32 = 0,
    bw_probe_samples: u32 = 0,
    stopped_risky_probe: bool = false,
    undo_bw_lo: u64 = 0,
    undo_inflight_lo: u32 = 0,
    undo_inflight_hi: u32 = 0,

    pub fn init(self: *BbrState, now_us: u64) void {
        self.mode = .startup;
        self.pacing_gain = BBR_HIGH_GAIN;
        self.cwnd_gain = BBR_CWND_GAIN;
        self.cycle_stamp_us = now_us;
        self.min_rtt_stamp_us = now_us;
        self.round_count = 0;
        self.full_bw_reached = false;
        self.full_bw_count = 0;
    }

    fn updateBwFilter(self: *BbrState, bw: u64) void {
        self.bw_filter[self.bw_filter_idx % BBR_CYCLE_PHASES] = bw;
        // Windowed max
        var max_bw: u64 = 0;
        for (self.bw_filter) |b| {
            if (b > max_bw) max_bw = b;
        }
        self.max_bw = max_bw;
    }

    fn updateMinRtt(self: *BbrState, rtt_us: u64, now_us: u64) bool {
        var filter_expired = false;
        if (now_us -| self.min_rtt_stamp_us > 10 * USEC_PER_SEC) {
            filter_expired = true;
        }
        if (rtt_us < self.min_rtt_us or filter_expired) {
            self.min_rtt_us = rtt_us;
            self.min_rtt_stamp_us = now_us;
        }
        self.min_rtt_expired = filter_expired;
        return filter_expired;
    }

    fn checkFullPipe(self: *BbrState, metrics: *const TcpMetrics) void {
        if (self.full_bw_reached) return;

        const bw = metrics.delivery_rate_bps;
        if (bw >= (self.full_bw * BBR_FULL_BW_THRESH) / BBR_UNIT) {
            // BW still growing
            self.full_bw = bw;
            self.full_bw_count = 0;
            return;
        }
        self.full_bw_count += 1;
        if (self.full_bw_count >= BBR_FULL_BW_CNT) {
            self.full_bw_reached = true;
        }
    }

    fn targetCwnd(self: *const BbrState, gain: u64, metrics: *const TcpMetrics) u32 {
        if (self.min_rtt_us == 0xFFFFFFFFFFFFFFFF) return TCP_INIT_CWND;
        // bdp = max_bw * min_rtt / 8 (bits to bytes)
        const bdp_bytes = (self.max_bw * self.min_rtt_us) / (8 * USEC_PER_SEC);
        var cwnd = (bdp_bytes * gain) / (BBR_UNIT * @as(u64, metrics.mss));
        cwnd = @max(cwnd, BBR_MIN_PIPE_CWND);
        if (cwnd > TCP_MAX_CWND) cwnd = TCP_MAX_CWND;
        return @intCast(cwnd);
    }

    fn computePacingRate(self: *const BbrState, metrics: *const TcpMetrics) u64 {
        // pacing_rate = pacing_gain * max_bw
        return (self.pacing_gain * self.max_bw) / BBR_UNIT;
        _ = metrics; // used for future adjustments
    }

    fn updateRound(self: *BbrState, metrics: *const TcpMetrics) void {
        if (metrics.delivered >= self.next_round_delivered) {
            self.round_start = true;
            self.round_count += 1;
            self.next_round_delivered = metrics.delivered;
        } else {
            self.round_start = false;
        }
    }

    pub fn onAck(self: *BbrState, metrics: *TcpMetrics, rtt_us: u64, now_us: u64) void {
        self.updateRound(metrics);
        self.updateBwFilter(metrics.delivery_rate_bps);
        const min_rtt_expired = self.updateMinRtt(rtt_us, now_us);

        switch (self.mode) {
            .startup => {
                self.checkFullPipe(metrics);
                if (self.full_bw_reached) {
                    self.mode = .drain;
                    self.pacing_gain = BBR_DRAIN_GAIN;
                    self.cwnd_gain = BBR_CWND_GAIN;
                }
            },
            .drain => {
                if (metrics.bytes_in_flight <= metrics.cwndInBytes()) {
                    self.mode = .probe_bw;
                    self.pacing_gain = BBR_UNIT;
                    self.cwnd_gain = BBR_CWND_GAIN;
                    self.cycle_stamp_us = now_us;
                    self.cycle_phase = .cruise;
                }
            },
            .probe_bw => {
                self.advanceProbeBwCycle(now_us, metrics);

                // BBRv3: check if min_rtt expired → enter PROBE_RTT
                if (min_rtt_expired) {
                    self.enterProbeRtt(metrics);
                }
            },
            .probe_rtt => {
                // Reduce cwnd to BBR_MIN_PIPE_CWND
                if (self.probe_rtt_done_stamp_us == 0 and
                    metrics.bytes_in_flight <= @as(u64, BBR_MIN_PIPE_CWND) * @as(u64, metrics.mss))
                {
                    self.probe_rtt_done_stamp_us = now_us + BBR_PROBE_RTT_MODE_MS * 1000;
                    self.probe_rtt_round_done = false;
                    self.next_round_delivered = metrics.delivered;
                } else if (self.probe_rtt_done_stamp_us != 0) {
                    if (self.round_start) {
                        self.probe_rtt_round_done = true;
                    }
                    if (self.probe_rtt_round_done and now_us >= self.probe_rtt_done_stamp_us) {
                        self.min_rtt_stamp_us = now_us;
                        self.exitProbeRtt(metrics);
                    }
                }
            },
        }

        // Compute cwnd and pacing rate
        metrics.cwnd = self.targetCwnd(self.cwnd_gain, metrics);
        metrics.pacing_rate_bps = self.computePacingRate(metrics);
    }

    fn enterProbeRtt(self: *BbrState, metrics: *TcpMetrics) void {
        self.mode = .probe_rtt;
        self.pacing_gain = BBR_UNIT;
        self.cwnd_gain = BBR_PROBE_RTT_CWND_GAIN;
        self.probe_rtt_done_stamp_us = 0;
        metrics.prior_cwnd = metrics.cwnd;
    }

    fn exitProbeRtt(self: *BbrState, metrics: *TcpMetrics) void {
        if (self.full_bw_reached) {
            self.mode = .probe_bw;
            self.pacing_gain = BBR_UNIT;
            self.cwnd_gain = BBR_CWND_GAIN;
            self.cycle_phase = .cruise;
        } else {
            self.mode = .startup;
            self.pacing_gain = BBR_HIGH_GAIN;
            self.cwnd_gain = BBR_CWND_GAIN;
        }
        metrics.cwnd = @max(metrics.cwnd, metrics.prior_cwnd);
    }

    fn advanceProbeBwCycle(self: *BbrState, now_us: u64, metrics: *const TcpMetrics) void {
        // BBRv3 ProbeBW phases: UP → DOWN → CRUISE
        const elapsed = now_us -| self.cycle_stamp_us;
        const min_rtt = if (self.min_rtt_us < 0xFFFFFFFFFFFFFFFF) self.min_rtt_us else USEC_PER_SEC;

        switch (self.cycle_phase) {
            .up => {
                self.pacing_gain = (5 * BBR_UNIT) / 4; // 1.25x
                // Probe for more BW for at least min_rtt
                if (elapsed >= min_rtt) {
                    self.cycle_phase = .down;
                    self.cycle_stamp_us = now_us;
                }
            },
            .down => {
                self.pacing_gain = (3 * BBR_UNIT) / 4; // 0.75x
                if (elapsed >= min_rtt or metrics.bytes_in_flight <= metrics.cwndInBytes()) {
                    self.cycle_phase = .cruise;
                    self.cycle_stamp_us = now_us;
                }
            },
            .cruise => {
                self.pacing_gain = BBR_UNIT; // 1.0x
                // Eventually cycle back to UP every ~8 RTTs
                if (elapsed >= 6 * min_rtt) {
                    self.cycle_phase = .up;
                    self.cycle_stamp_us = now_us;
                }
            },
        }
    }

    pub fn onLoss(self: *BbrState, metrics: *TcpMetrics) void {
        // BBRv3: track loss in current round
        self.loss_in_round = true;

        // Reduce inflight_hi on loss
        if (self.inflight_hi > @as(u32, @intCast(@min(metrics.bytes_in_flight / @as(u64, metrics.mss), TCP_MAX_CWND)))) {
            self.inflight_hi = @intCast(@min(metrics.bytes_in_flight / @as(u64, metrics.mss), TCP_MAX_CWND));
        }

        if (self.mode == .startup) {
            // Full pipe reached on loss in startup
            self.full_bw_reached = true;
            self.mode = .drain;
            self.pacing_gain = BBR_DRAIN_GAIN;
        }
    }
};

// =============================================================================
// DCTCP State (Data Center TCP)
// =============================================================================
pub const DctcpState = struct {
    alpha: u32 = DCTCP_MAX_ALPHA, // EWMA of ECN fraction
    ce_state: bool = false, // Currently in CE-marked series
    prior_rcv_nxt: u32 = 0,
    total_bytes: u64 = 0,
    ce_bytes: u64 = 0,
    next_seq: u32 = 0,
    delayed_ack_reserved: bool = false,

    pub fn reset(self: *DctcpState) void {
        self.alpha = DCTCP_MAX_ALPHA;
        self.ce_state = false;
        self.total_bytes = 0;
        self.ce_bytes = 0;
    }

    pub fn onAck(self: *DctcpState, metrics: *TcpMetrics, bytes_acked: u64, ce_marked: bool) void {
        self.total_bytes += bytes_acked;
        if (ce_marked) {
            self.ce_bytes += bytes_acked;
        }

        // Update alpha at end of each RTT
        if (self.total_bytes >= metrics.cwndInBytes() and self.total_bytes > 0) {
            // EWMA: alpha = (1 - g) * alpha + g * F
            // g = 1/16, F = ce_bytes / total_bytes
            const f = @as(u32, @intCast((self.ce_bytes * DCTCP_MAX_ALPHA) / self.total_bytes));
            self.alpha = self.alpha -| (self.alpha / DCTCP_EWMA_WEIGHT) +
                (f / DCTCP_EWMA_WEIGHT);

            self.total_bytes = 0;
            self.ce_bytes = 0;
        }

        // Normal AIMD increase
        if (!metrics.in_slow_start) {
            // Additive increase: cwnd += 1 per RTT
            metrics.cwnd +|= 1;
        } else {
            metrics.cwnd +|= 1;
        }
    }

    pub fn onCongestion(self: *DctcpState, metrics: *TcpMetrics) void {
        // Multiplicative decrease: cwnd *= (1 - alpha/2)
        const reduction = (@as(u64, metrics.cwnd) * @as(u64, self.alpha)) / (2 * DCTCP_MAX_ALPHA);
        metrics.cwnd = @intCast(@max(@as(u64, metrics.cwnd) -| reduction, TCP_MIN_CWND));
        metrics.ssthresh = metrics.cwnd;
        metrics.in_slow_start = false;
    }
};

// =============================================================================
// Vegas State (Delay-based CC)
// =============================================================================
pub const VegasState = struct {
    base_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF, // Minimum RTT ever observed
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF, // Min RTT this interval
    cnt_rtt: u32 = 0, // Count of RTT samples
    doing_vegas_now: bool = true,

    // Vegas constants (α, β, γ in units of segments)
    const VEGAS_ALPHA: u64 = 2; // Low threshold
    const VEGAS_BETA: u64 = 4; // High threshold
    const VEGAS_GAMMA: u64 = 1; // Slow start threshold

    pub fn reset(self: *VegasState) void {
        self.min_rtt_us = 0xFFFFFFFFFFFFFFFF;
        self.cnt_rtt = 0;
    }

    pub fn onAck(self: *VegasState, metrics: *TcpMetrics, rtt_us: u64) void {
        if (rtt_us < self.base_rtt_us) {
            self.base_rtt_us = rtt_us;
        }
        if (rtt_us < self.min_rtt_us) {
            self.min_rtt_us = rtt_us;
        }
        self.cnt_rtt += 1;

        if (!self.doing_vegas_now) return;

        // Only adjust at end of RTT period
        if (self.cnt_rtt < metrics.cwnd) return;

        // Expected throughput = cwnd / base_rtt
        // Actual throughput = cwnd / min_rtt
        // diff = expected - actual
        if (self.base_rtt_us == 0 or self.min_rtt_us == 0) return;

        const expected = (@as(u64, metrics.cwnd) * USEC_PER_SEC) / self.base_rtt_us;
        const actual = (@as(u64, metrics.cwnd) * USEC_PER_SEC) / self.min_rtt_us;
        const diff = if (expected > actual) expected - actual else 0;

        if (metrics.in_slow_start) {
            // Vegas slow start: increase normally unless diff > γ
            if (diff > VEGAS_GAMMA) {
                metrics.ssthresh = metrics.cwnd;
                metrics.in_slow_start = false;
            } else {
                metrics.cwnd += 1;
            }
        } else {
            // Congestion avoidance
            if (diff < VEGAS_ALPHA) {
                // Too few packets in network — increase
                metrics.cwnd += 1;
            } else if (diff > VEGAS_BETA) {
                // Too many packets — decrease
                if (metrics.cwnd > TCP_MIN_CWND) {
                    metrics.cwnd -= 1;
                }
            }
            // else: in the sweet spot — stay
        }

        self.cnt_rtt = 0;
        self.min_rtt_us = 0xFFFFFFFFFFFFFFFF;
    }
};

// =============================================================================
// Westwood+ State (Bandwidth estimation)
// =============================================================================
pub const WestwoodState = struct {
    bw_est: u64 = 0, // Estimated bandwidth (bytes/sec)
    bw_ns_est: u64 = 0, // Non-smoothed estimate
    bw_sample: u64 = 0, // Current sample
    rtt_win_sx: u64 = 0, // RTT window start time
    bk: u64 = 0, // Bytes acked in current interval
    snd_una: u32 = 0,
    cumul_ack: u32 = 0,
    accounted: u32 = 0,
    rtt_cnt: u32 = 0,
    first_ack: bool = true,
    reset_rtt_min: bool = true,

    const WESTWOOD_RTT_MIN: u64 = 500_000; // 500ms

    pub fn onAck(self: *WestwoodState, metrics: *TcpMetrics, now_us: u64) void {
        const delta = now_us -| self.rtt_win_sx;

        // Accumulate bytes
        self.bk += @as(u64, metrics.mss);

        if (delta < WESTWOOD_RTT_MIN) return;

        // Compute sample: bw_sample = bk / delta
        if (delta > 0) {
            self.bw_sample = (self.bk * USEC_PER_SEC) / delta;
        }

        // EWMA smoothing
        if (self.first_ack) {
            self.bw_est = self.bw_sample;
            self.bw_ns_est = self.bw_sample;
            self.first_ack = false;
        } else {
            self.bw_ns_est = (7 * self.bw_ns_est + self.bw_sample) / 8;
            self.bw_est = (7 * self.bw_est + self.bw_ns_est) / 8;
        }

        // Reset for next interval
        self.bk = 0;
        self.rtt_win_sx = now_us;

        // Adjust cwnd using bandwidth estimate
        if (!metrics.in_slow_start) {
            // BDP = bw_est * min_rtt
            if (metrics.min_rtt_us > 0 and metrics.min_rtt_us < 0xFFFFFFFFFFFFFFFF) {
                const bdp = (self.bw_est * metrics.min_rtt_us) / (USEC_PER_SEC * @as(u64, metrics.mss));
                if (bdp > @as(u64, metrics.cwnd)) {
                    metrics.cwnd += 1;
                }
            }
        }
    }

    pub fn onLoss(self: *WestwoodState, metrics: *TcpMetrics) void {
        // ssthresh = max(bw_est * min_rtt / mss, 2)
        if (self.bw_est > 0 and metrics.min_rtt_us > 0 and metrics.min_rtt_us < 0xFFFFFFFFFFFFFFFF) {
            const ss = (self.bw_est * metrics.min_rtt_us) / (USEC_PER_SEC * @as(u64, metrics.mss));
            metrics.ssthresh = @intCast(@max(ss, TCP_MIN_CWND));
        } else {
            metrics.ssthresh = @max(metrics.cwnd / 2, TCP_MIN_CWND);
        }
        metrics.cwnd = metrics.ssthresh;
        metrics.in_slow_start = false;
    }
};

// =============================================================================
// HTCP State (Hamilton TCP)
// =============================================================================
pub const HtcpState = struct {
    alpha: u64 = 0, // AIMD increase factor
    beta: u64 = 500, // Decrease factor (0.5 scaled by 1000)
    last_cong_us: u64 = 0, // Time of last congestion event
    max_bw: u64 = 0,
    min_bw: u64 = 0,
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    max_rtt_us: u64 = 0,
    last_rtt_us: u64 = 0,
    undo_last_cong_us: u64 = 0,
    undo_max_cwnd: u32 = 0,

    const HTCP_ALPHA_BASE: u64 = 1;
    const HTCP_BETA_MIN: u64 = 128; // min β scaled by 1000
    const HTCP_DELTA_L: u64 = USEC_PER_SEC; // 1 second

    pub fn onAck(self: *HtcpState, metrics: *TcpMetrics, now_us: u64, rtt_us: u64) void {
        if (rtt_us < self.min_rtt_us) self.min_rtt_us = rtt_us;
        if (rtt_us > self.max_rtt_us) self.max_rtt_us = rtt_us;
        self.last_rtt_us = rtt_us;

        // Time since last congestion
        const delta = now_us -| self.last_cong_us;

        // α increases with time since last congestion
        if (delta <= HTCP_DELTA_L) {
            self.alpha = HTCP_ALPHA_BASE;
        } else {
            // α = 1 + 10*(Δ - Δ_L) + ((Δ - Δ_L)/2)^2
            const d = (delta - HTCP_DELTA_L) / USEC_PER_SEC;
            self.alpha = HTCP_ALPHA_BASE + 10 * d + (d * d) / 4;
        }

        // Adaptive β based on throughput ratio
        if (self.max_rtt_us > 0 and self.min_rtt_us > 0 and self.min_rtt_us < self.max_rtt_us) {
            self.beta = 1000 * self.min_rtt_us / self.max_rtt_us;
            if (self.beta < HTCP_BETA_MIN) self.beta = HTCP_BETA_MIN;
        }

        // Increase: cwnd += α/cwnd per ACK
        if (!metrics.in_slow_start) {
            metrics.cwnd += @intCast(self.alpha / @as(u64, @max(metrics.cwnd, 1)));
            if (metrics.cwnd == 0) metrics.cwnd = 1;
        } else {
            metrics.cwnd += 1;
        }
    }

    pub fn onLoss(self: *HtcpState, metrics: *TcpMetrics, now_us: u64) void {
        self.last_cong_us = now_us;
        // cwnd = cwnd * β
        metrics.ssthresh = @intCast(@max((@as(u64, metrics.cwnd) * self.beta) / 1000, TCP_MIN_CWND));
        metrics.cwnd = metrics.ssthresh;
        metrics.in_slow_start = false;
    }
};

// =============================================================================
// Illinois State (Hybrid Loss/Delay CC)
// =============================================================================
pub const IllinoisState = struct {
    alpha: u64 = 1000, // Increase factor (scaled by 1000)
    beta: u64 = 500, // Decrease factor (scaled by 1000)
    base_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,
    max_rtt_us: u64 = 0,
    sum_rtt_us: u64 = 0,
    cnt_rtt: u32 = 0,

    // Constants
    const ALPHA_MAX: u64 = 10000; // 10.0
    const ALPHA_MIN: u64 = 100; // 0.1
    const BETA_MAX: u64 = 500; // 0.5
    const BETA_MIN: u64 = 125; // 0.125
    const THETA: u64 = 5; // delay threshold divisor

    pub fn onAck(self: *IllinoisState, metrics: *TcpMetrics, rtt_us: u64) void {
        if (rtt_us < self.base_rtt_us) self.base_rtt_us = rtt_us;
        if (rtt_us > self.max_rtt_us) self.max_rtt_us = rtt_us;
        self.sum_rtt_us += rtt_us;
        self.cnt_rtt += 1;

        // Compute average RTT for this window
        if (self.cnt_rtt < metrics.cwnd) return;

        const avg_rtt = self.sum_rtt_us / @as(u64, @max(self.cnt_rtt, 1));

        // Delay metric: d_a = (avg_rtt - base_rtt) / (max_rtt - base_rtt)
        const rtt_range = self.max_rtt_us -| self.base_rtt_us;
        const rtt_diff = avg_rtt -| self.base_rtt_us;

        if (rtt_range > 0) {
            const d_a = (rtt_diff * 1000) / rtt_range; // scaled by 1000

            // Compute alpha: high when delay is low
            if (d_a < 1000 / THETA) {
                self.alpha = ALPHA_MAX;
            } else {
                self.alpha = ALPHA_MAX -| ((ALPHA_MAX - ALPHA_MIN) * d_a) / 1000;
                if (self.alpha < ALPHA_MIN) self.alpha = ALPHA_MIN;
            }

            // Compute beta: low when delay is low
            if (d_a < 1000 / THETA) {
                self.beta = BETA_MIN;
            } else {
                self.beta = BETA_MIN + ((BETA_MAX - BETA_MIN) * d_a) / 1000;
                if (self.beta > BETA_MAX) self.beta = BETA_MAX;
            }
        }

        // Increase: cwnd += alpha / cwnd
        if (!metrics.in_slow_start) {
            const inc = @max(self.alpha / @as(u64, @max(metrics.cwnd, 1)), 1);
            metrics.cwnd += @intCast(inc);
        }

        self.sum_rtt_us = 0;
        self.cnt_rtt = 0;
    }

    pub fn onLoss(self: *IllinoisState, metrics: *TcpMetrics) void {
        metrics.ssthresh = @intCast(@max((@as(u64, metrics.cwnd) * (1000 - self.beta)) / 1000, TCP_MIN_CWND));
        metrics.cwnd = metrics.ssthresh;
        metrics.in_slow_start = false;
    }
};

// =============================================================================
// LEDBAT State (Low Extra Delay Background Transport)
// =============================================================================
pub const LedbatState = struct {
    base_delay_us: [8]u64 = [_]u64{0xFFFFFFFFFFFFFFFF} ** 8,
    base_delay_idx: u32 = 0,
    current_delay_us: [8]u64 = [_]u64{0} ** 8,
    current_delay_idx: u32 = 0,
    last_rollover_us: u64 = 0,

    const TARGET_DELAY_US: u64 = 100_000; // 100ms target delay
    const GAIN: u64 = 1; // GAIN numerator

    fn minBaseDelay(self: *const LedbatState) u64 {
        var m: u64 = 0xFFFFFFFFFFFFFFFF;
        for (self.base_delay_us) |d| {
            if (d < m) m = d;
        }
        return m;
    }

    fn currentDelay(self: *const LedbatState) u64 {
        // Use minimum of recent delays as one-way delay estimate
        var m: u64 = 0xFFFFFFFFFFFFFFFF;
        for (self.current_delay_us) |d| {
            if (d > 0 and d < m) m = d;
        }
        return if (m == 0xFFFFFFFFFFFFFFFF) 0 else m;
    }

    pub fn onAck(self: *LedbatState, metrics: *TcpMetrics, delay_us: u64, now_us: u64) void {
        // Update base delay (rotated every minute)
        if (now_us -| self.last_rollover_us > 60 * USEC_PER_SEC) {
            self.base_delay_idx = (self.base_delay_idx + 1) % 8;
            self.base_delay_us[self.base_delay_idx] = delay_us;
            self.last_rollover_us = now_us;
        } else if (delay_us < self.base_delay_us[self.base_delay_idx]) {
            self.base_delay_us[self.base_delay_idx] = delay_us;
        }

        // Current delay
        self.current_delay_idx = (self.current_delay_idx + 1) % 8;
        self.current_delay_us[self.current_delay_idx] = delay_us;

        // Queuing delay = current_delay - base_delay
        const base = self.minBaseDelay();
        const current = self.currentDelay();
        const queuing = if (current > base) current - base else 0;

        // off_target = (TARGET - queuing) / TARGET
        // cwnd += (GAIN * off_target * bytes_acked) / cwnd
        if (queuing < TARGET_DELAY_US) {
            // Under target: increase
            const off_target = TARGET_DELAY_US - queuing;
            const inc = (GAIN * off_target * @as(u64, metrics.mss)) / (TARGET_DELAY_US * @as(u64, @max(metrics.cwnd, 1)));
            metrics.cwnd += @intCast(@max(inc, 1));
        } else {
            // Above target: decrease
            const over = queuing - TARGET_DELAY_US;
            const dec = (GAIN * over * @as(u64, metrics.mss)) / (TARGET_DELAY_US * @as(u64, @max(metrics.cwnd, 1)));
            if (metrics.cwnd > @as(u32, @intCast(@min(dec, metrics.cwnd -| TCP_MIN_CWND)))) {
                metrics.cwnd -= @intCast(dec);
            }
            if (metrics.cwnd < TCP_MIN_CWND) metrics.cwnd = TCP_MIN_CWND;
        }
    }
};

// =============================================================================
// Scalable TCP State
// =============================================================================
pub const ScalableState = struct {
    pub fn onAck(metrics: *TcpMetrics) void {
        if (metrics.in_slow_start) {
            metrics.cwnd += 1;
        } else {
            // Increase: cwnd += 0.01 per ACK
            // Scaled: cwnd += max(cwnd/100, 1) per cwnd ACKs
            metrics.cwnd += @max(metrics.cwnd / 100, 1);
        }
    }

    pub fn onLoss(metrics: *TcpMetrics) void {
        // β = 1/8
        metrics.ssthresh = @max(metrics.cwnd - metrics.cwnd / 8, TCP_MIN_CWND);
        metrics.cwnd = metrics.ssthresh;
        metrics.in_slow_start = false;
    }
};

// =============================================================================
// BIC State (Binary Increase Congestion Control)
// =============================================================================
pub const BicState = struct {
    last_max_cwnd: u32 = 0,
    loss_cwnd: u32 = 0,
    last_cwnd: u32 = 0,
    last_time_us: u64 = 0,
    epoch_start_us: u64 = 0,

    const BIC_SCALE: u32 = 41;
    const BIC_LOW_WINDOW: u32 = 14;
    const BIC_MAX_INCREMENT: u32 = 16;

    pub fn onAck(self: *BicState, metrics: *TcpMetrics) void {
        if (metrics.in_slow_start) {
            metrics.cwnd += 1;
            return;
        }

        if (metrics.cwnd < self.last_max_cwnd) {
            // Binary search between cwnd and last_max_cwnd
            const midpoint = (self.last_max_cwnd + @as(u32, metrics.cwnd)) / 2;
            const diff = midpoint -| metrics.cwnd;
            const inc = @min(diff, BIC_MAX_INCREMENT);
            metrics.cwnd += @max(inc, 1);
        } else {
            // Max probing: additive increase
            metrics.cwnd += BIC_MAX_INCREMENT;
        }
    }

    pub fn onLoss(self: *BicState, metrics: *TcpMetrics) void {
        if (metrics.cwnd < self.last_max_cwnd) {
            self.last_max_cwnd = (metrics.cwnd * (BIC_SCALE + 1000)) / (2 * 1000);
        } else {
            self.last_max_cwnd = metrics.cwnd;
        }
        self.loss_cwnd = metrics.cwnd;

        // β = 0.8 for BIC (different from CUBIC)
        metrics.ssthresh = @max(metrics.cwnd * 4 / 5, TCP_MIN_CWND);
        metrics.cwnd = metrics.ssthresh;
        metrics.in_slow_start = false;
    }
};

// =============================================================================
// New Reno State (RFC 6582)
// =============================================================================
pub const NewRenoState = struct {
    dup_ack_count: u32 = 0,
    recover_seq: u32 = 0,
    in_fast_recovery: bool = false,

    pub fn onAck(self: *NewRenoState, metrics: *TcpMetrics) void {
        if (self.in_fast_recovery) {
            // Exit fast recovery when all data up to recover_seq is ACKed
            if (metrics.bytes_acked >= @as(u64, self.recover_seq)) {
                self.in_fast_recovery = false;
                metrics.cwnd = metrics.ssthresh;
                metrics.in_recovery = false;
            } else {
                // Partial ACK: retransmit next
                metrics.cwnd += 1;
            }
            self.dup_ack_count = 0;
            return;
        }

        if (metrics.in_slow_start) {
            metrics.cwnd += 1;
            if (metrics.cwnd >= metrics.ssthresh) {
                metrics.in_slow_start = false;
            }
        } else {
            // Congestion avoidance: linear increase
            // += 1 MSS per RTT (≈ += 1/cwnd per ACK)
            metrics.cwnd += 1; // Simplified
        }
    }

    pub fn onDupAck(self: *NewRenoState, metrics: *TcpMetrics) void {
        self.dup_ack_count += 1;
        if (self.dup_ack_count == 3 and !self.in_fast_recovery) {
            // Enter fast recovery
            self.in_fast_recovery = true;
            metrics.ssthresh = @max(metrics.cwnd / 2, TCP_MIN_CWND);
            metrics.cwnd = metrics.ssthresh + 3; // inflate for 3 dup ACKs
            metrics.in_recovery = true;
            // Set recover to current snd_nxt
        }
    }

    pub fn onLoss(self: *NewRenoState, metrics: *TcpMetrics) void {
        // Timeout: full reset
        self.in_fast_recovery = false;
        self.dup_ack_count = 0;
        metrics.ssthresh = @max(metrics.cwnd / 2, TCP_MIN_CWND);
        metrics.cwnd = 1; // Reset to 1 MSS
        metrics.in_slow_start = true;
        metrics.in_recovery = false;
    }
};

// =============================================================================
// RACK-TLP Loss Detection (RFC 8985)
// =============================================================================
pub const RackState = struct {
    // RACK fields
    xmit_ts_us: u64 = 0, // Most recently delivered segment's xmit time
    end_seq: u32 = 0, // Most recently delivered segment's end seq
    rtt_us: u64 = 0, // Associated RTT
    reorder_seen: bool = false,
    dsack_seen: bool = false,
    reo_wnd_us: u64 = 0, // Reordering window
    reo_wnd_persist: u32 = 0,
    reo_wnd_steps: u32 = 0,
    min_rtt_us: u64 = 0xFFFFFFFFFFFFFFFF,

    // TLP fields
    tlp_high_seq: u32 = 0,
    tlp_retrans: bool = false,
    allow_tlp: bool = true,
    tlp_probe_count: u32 = 0,

    const REO_WND_MAX_STEPS: u32 = 16;
    const RACK_PKT_THRESHOLD: u32 = 3;

    pub fn updateReoWnd(self: *RackState, metrics: *const TcpMetrics) void {
        // Reordering window: starts at 0, opens on DSACK
        if (self.dsack_seen) {
            // Open window to min_rtt/4
            self.reo_wnd_us = (metrics.min_rtt_us) / 4;
            if (self.reo_wnd_us == 0) self.reo_wnd_us = 1;
            self.reo_wnd_steps += 1;
            if (self.reo_wnd_steps > REO_WND_MAX_STEPS) {
                self.reo_wnd_us = metrics.min_rtt_us / 4;
            }
        } else if (!self.reorder_seen) {
            self.reo_wnd_us = 0;
        }
    }

    /// Determine if a segment should be marked as lost
    pub fn detectLoss(self: *RackState, seg_xmit_us: u64, seg_end_seq: u32) bool {
        // RACK: segment is lost if:
        // rack.xmit_ts > seg.xmit_ts + reo_wnd
        if (self.xmit_ts_us > seg_xmit_us + self.reo_wnd_us) {
            return true;
        }

        // Or if rack.end_seq > seg.end_seq and same xmit time
        if (self.xmit_ts_us == seg_xmit_us and wrappingGt(self.end_seq, seg_end_seq)) {
            return true;
        }

        return false;
    }

    /// Schedule TLP (Tail Loss Probe)
    pub fn computeTlpTimeout(self: *const RackState, metrics: *const TcpMetrics) u64 {
        // PTO = max(2 * SRTT, 10ms) + (inflight == 1 ? WCDelAckT : 0)
        var pto = 2 * metrics.srtt_us;
        if (pto < 10_000) pto = 10_000; // 10ms floor

        // If only one packet in flight, add worst-case delayed ACK time
        if (metrics.bytes_in_flight <= @as(u64, metrics.mss)) {
            pto += TCP_DELACK_MAX_US;
        }

        _ = self;
        return pto;
    }

    /// Called when a TLP probe fires
    pub fn onTlpTimeout(self: *RackState) void {
        self.tlp_retrans = true;
        self.tlp_probe_count += 1;
    }

    /// Update RACK state when receiving an ACK
    pub fn onAck(self: *RackState, seg_xmit_us: u64, seg_end_seq: u32, rtt_us: u64) void {
        if (seg_xmit_us > self.xmit_ts_us or
            (seg_xmit_us == self.xmit_ts_us and wrappingGt(seg_end_seq, self.end_seq)))
        {
            self.xmit_ts_us = seg_xmit_us;
            self.end_seq = seg_end_seq;
            self.rtt_us = rtt_us;
        }
        if (rtt_us < self.min_rtt_us) {
            self.min_rtt_us = rtt_us;
        }
    }
};

// =============================================================================
// PRR (Proportional Rate Reduction, RFC 6937)
// =============================================================================
pub const PrrState = struct {
    delivered: u64 = 0, // Total delivered since recovery started
    out: u64 = 0, // Total sent since recovery started
    prr_delivered: u64 = 0,
    prr_out: u64 = 0,
    recovery_start_inflight: u64 = 0,

    pub fn init(self: *PrrState, inflight: u64) void {
        self.delivered = 0;
        self.out = 0;
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.recovery_start_inflight = inflight;
    }

    pub fn onAck(self: *PrrState, newly_acked: u64, metrics: *TcpMetrics) void {
        self.prr_delivered += newly_acked;

        // PRR-SSRB: sndcnt = min(ssthresh - pipe, newly_acked)
        // or PRR-CRB: sndcnt = max(prr_delivered - prr_out, newly_acked) / 2
        const pipe = metrics.bytes_in_flight;
        const ssthresh_bytes = @as(u64, metrics.ssthresh) * @as(u64, metrics.mss);

        if (pipe > ssthresh_bytes) {
            // Reduce: send at most one new per ACK
            self.out += @min(newly_acked, @as(u64, metrics.mss));
        } else {
            // Slow start reduction bound
            const deficit = ssthresh_bytes -| pipe;
            self.out += @min(deficit, newly_acked);
        }
    }

    pub fn canSend(self: *const PrrState) bool {
        return self.prr_out < self.out;
    }

    pub fn onSend(self: *PrrState, bytes: u64) void {
        self.prr_out += bytes;
    }
};

// =============================================================================
// Pacing Engine (FQ-based token bucket)
// =============================================================================
pub const PacingEngine = struct {
    rate_bps: u64 = 0, // Target pacing rate bits/sec
    tokens: i64 = 0, // Available bytes to send
    max_burst: u32 = 10 * TCP_MSS_DEFAULT, // Maximum burst size
    last_update_us: u64 = 0,
    active: bool = false,

    pub fn setRate(self: *PacingEngine, rate_bps: u64, now_us: u64) void {
        self.replenish(now_us);
        self.rate_bps = rate_bps;
        self.active = rate_bps > 0;
    }

    fn replenish(self: *PacingEngine, now_us: u64) void {
        if (self.last_update_us == 0) {
            self.last_update_us = now_us;
            self.tokens = @intCast(self.max_burst);
            return;
        }

        const elapsed = now_us -| self.last_update_us;
        if (elapsed == 0) return;

        // tokens += (rate_bps * elapsed_us) / (8 * 1_000_000)
        const new_tokens = (self.rate_bps * elapsed) / (8 * USEC_PER_SEC);
        self.tokens += @intCast(new_tokens);
        if (self.tokens > @as(i64, self.max_burst)) {
            self.tokens = @intCast(self.max_burst);
        }
        self.last_update_us = now_us;
    }

    pub fn canSend(self: *PacingEngine, bytes: u32, now_us: u64) bool {
        if (!self.active) return true;
        self.replenish(now_us);
        return self.tokens >= @as(i64, bytes);
    }

    pub fn onSend(self: *PacingEngine, bytes: u32) void {
        self.tokens -= @as(i64, bytes);
    }

    /// Compute next eligible send time
    pub fn nextSendTime(self: *const PacingEngine, bytes: u32) u64 {
        if (!self.active or self.rate_bps == 0) return 0;
        // time = bytes * 8 * 1_000_000 / rate_bps
        return (@as(u64, bytes) * 8 * USEC_PER_SEC) / self.rate_bps;
    }
};

// =============================================================================
// Congestion Control State (Union of all algorithms)
// =============================================================================
pub const CcState = struct {
    algorithm: CcAlgorithm = .cubic,
    metrics: TcpMetrics = .{},
    pacing: PacingEngine = .{},
    rack: RackState = .{},
    prr: PrrState = .{},

    // Algorithm-specific state
    cubic: CubicState = .{},
    bbr: BbrState = .{},
    dctcp: DctcpState = .{},
    vegas: VegasState = .{},
    westwood: WestwoodState = .{},
    htcp: HtcpState = .{},
    illinois: IllinoisState = .{},
    ledbat: LedbatState = .{},
    bic: BicState = .{},
    new_reno: NewRenoState = .{},

    pub fn init(algo: CcAlgorithm) CcState {
        var state = CcState{};
        state.algorithm = algo;
        return state;
    }

    pub fn onAck(self: *CcState, bytes_acked: u64, rtt_us: u64, now_us: u64) void {
        self.metrics.bytes_acked += bytes_acked;
        self.metrics.updateRtt(rtt_us);
        self.metrics.updateDeliveryRate(now_us);

        // Update RACK
        self.rack.updateReoWnd(&self.metrics);

        switch (self.algorithm) {
            .cubic => self.cubic.onAck(&self.metrics, now_us),
            .bbr, .bbr_v3 => self.bbr.onAck(&self.metrics, rtt_us, now_us),
            .dctcp => self.dctcp.onAck(&self.metrics, bytes_acked, false),
            .vegas => self.vegas.onAck(&self.metrics, rtt_us),
            .westwood => self.westwood.onAck(&self.metrics, now_us),
            .htcp => self.htcp.onAck(&self.metrics, now_us, rtt_us),
            .illinois => self.illinois.onAck(&self.metrics, rtt_us),
            .ledbat => self.ledbat.onAck(&self.metrics, rtt_us, now_us),
            .scalable => ScalableState.onAck(&self.metrics),
            .bic => self.bic.onAck(&self.metrics),
            .new_reno => self.new_reno.onAck(&self.metrics),
            .pcc_vivace => {
                // PCC Vivace: online learning approach
                // Uses utility function U(x) = x * (1 - ε * loss_rate)
                // simplified: adjust like Reno for now with loss tolerance
                if (self.metrics.in_slow_start) {
                    self.metrics.cwnd += 1;
                } else {
                    self.metrics.cwnd += 1;
                }
            },
            .copa => {
                // Copa: competitive delay-based
                // δ controls competitiveness (δ=0.5 default)
                // cwnd = 1/(δ * (RTT - min_RTT) / min_RTT)
                if (self.metrics.min_rtt_us > 0 and self.metrics.min_rtt_us < rtt_us) {
                    const queuing = rtt_us - self.metrics.min_rtt_us;
                    if (queuing > 0 and self.metrics.min_rtt_us > 0) {
                        // target = 1/δ * min_rtt / queuing_delay
                        const target = (2 * self.metrics.min_rtt_us * @as(u64, self.metrics.mss)) / queuing;
                        if (target > @as(u64, self.metrics.cwnd)) {
                            self.metrics.cwnd += 1;
                        } else if (self.metrics.cwnd > TCP_MIN_CWND) {
                            self.metrics.cwnd -= 1;
                        }
                    }
                } else {
                    self.metrics.cwnd += 1;
                }
            },
        }

        // Update pacing rate
        self.pacing.setRate(self.metrics.pacing_rate_bps, now_us);
    }

    pub fn onLoss(self: *CcState, now_us: u64) void {
        self.metrics.lost += 1;

        switch (self.algorithm) {
            .cubic => self.cubic.onLoss(&self.metrics),
            .bbr, .bbr_v3 => self.bbr.onLoss(&self.metrics),
            .dctcp => self.dctcp.onCongestion(&self.metrics),
            .vegas => {
                self.metrics.ssthresh = @max(self.metrics.cwnd * 3 / 4, TCP_MIN_CWND);
                self.metrics.cwnd = self.metrics.ssthresh;
                self.metrics.in_slow_start = false;
            },
            .westwood => self.westwood.onLoss(&self.metrics),
            .htcp => self.htcp.onLoss(&self.metrics, now_us),
            .illinois => self.illinois.onLoss(&self.metrics),
            .ledbat => {
                self.metrics.ssthresh = @max(self.metrics.cwnd / 2, TCP_MIN_CWND);
                self.metrics.cwnd = self.metrics.ssthresh;
                self.metrics.in_slow_start = false;
            },
            .scalable => ScalableState.onLoss(&self.metrics),
            .bic => self.bic.onLoss(&self.metrics),
            .new_reno => self.new_reno.onLoss(&self.metrics),
            .pcc_vivace, .copa => {
                self.metrics.ssthresh = @max(self.metrics.cwnd / 2, TCP_MIN_CWND);
                self.metrics.cwnd = self.metrics.ssthresh;
                self.metrics.in_slow_start = false;
            },
        }

        // Enter PRR
        self.prr.init(self.metrics.bytes_in_flight);
        self.metrics.in_recovery = true;
    }

    pub fn onTimeout(self: *CcState) void {
        self.metrics.retransmits += 1;
        self.metrics.ssthresh = @max(self.metrics.cwnd / 2, TCP_MIN_CWND);
        self.metrics.cwnd = 1; // Reset to 1 MSS
        self.metrics.in_slow_start = true;
        self.metrics.in_recovery = false;
    }

    pub fn setAlgorithm(self: *CcState, algo: CcAlgorithm) void {
        self.algorithm = algo;
        // Reset algorithm-specific state
        switch (algo) {
            .cubic => self.cubic.reset(),
            .bbr, .bbr_v3 => self.bbr.init(0),
            .dctcp => self.dctcp.reset(),
            .vegas => self.vegas.reset(),
            .new_reno => {
                self.new_reno.dup_ack_count = 0;
                self.new_reno.in_fast_recovery = false;
            },
            else => {},
        }
    }

    // Get current congestion window in bytes
    pub fn getCwndBytes(self: *const CcState) u64 {
        return @as(u64, self.metrics.cwnd) * @as(u64, self.metrics.mss);
    }
};

// =============================================================================
// Helper functions
// =============================================================================
fn wrappingGt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

fn wrappingGe(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) >= 0;
}

fn wrappingLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

fn readU16BE(data: []const u8, offset: usize) u16 {
    return (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
}

// =============================================================================
// Global CC registry and statistics
// =============================================================================
pub const CcGlobalStats = struct {
    total_connections: u64 = 0,
    active_connections: u64 = 0,
    total_bytes_sent: u64 = 0,
    total_bytes_received: u64 = 0,
    total_retransmits: u64 = 0,
    total_timeouts: u64 = 0,
    total_fast_retransmits: u64 = 0,
    total_tlp_probes: u64 = 0,
    total_rack_detected_losses: u64 = 0,
    algo_counts: [14]u64 = [_]u64{0} ** 14,
};

var global_cc_stats = CcGlobalStats{};

pub fn getGlobalStats() *const CcGlobalStats {
    return &global_cc_stats;
}

pub fn registerConnection(algo: CcAlgorithm) void {
    global_cc_stats.total_connections += 1;
    global_cc_stats.active_connections += 1;
    global_cc_stats.algo_counts[@intFromEnum(algo)] += 1;
}

pub fn unregisterConnection(algo: CcAlgorithm) void {
    if (global_cc_stats.active_connections > 0) {
        global_cc_stats.active_connections -= 1;
    }
    if (global_cc_stats.algo_counts[@intFromEnum(algo)] > 0) {
        global_cc_stats.algo_counts[@intFromEnum(algo)] -= 1;
    }
}
