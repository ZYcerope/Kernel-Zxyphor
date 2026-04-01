// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust TCP Congestion Control Framework
//
// Implements multiple congestion control algorithms:
// - Reno (classic AIMD)
// - Cubic (Linux default)
// - BBR (model-based)
// - Vegas (delay-based)
// - Congestion controller trait and pluggable architecture
// - RTT estimation (Jacobson/Karels)
// - Selective Acknowledgment (SACK) support
// - Fast retransmit / fast recovery
// - Pacing engine

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────
pub const MSS: u32 = 1460;
pub const INIT_CWND: u32 = 10 * MSS;
pub const MIN_CWND: u32 = 2 * MSS;
pub const MAX_CWND: u32 = 256 * 65535; // ~16 MiB
pub const INIT_SSTHRESH: u32 = 0xFFFFFFFF; // effectively unlimited
pub const DUPACK_THRESH: u32 = 3;
pub const RTO_MIN_MS: u32 = 200;
pub const RTO_MAX_MS: u32 = 120_000;
pub const RTO_INIT_MS: u32 = 1000;

// ─────────────────── RTT Estimator ──────────────────────────────────
/// Jacobson/Karels RTT estimation
pub struct RttEstimator {
    /// Smoothed RTT (microseconds, fixed-point *8)
    pub srtt: i64,
    /// RTT variation (microseconds, fixed-point *4)
    pub rttvar: i64,
    /// Retransmission timeout (milliseconds)
    pub rto_ms: u32,
    /// Minimum observed RTT (microseconds)
    pub min_rtt: u64,
    /// Latest RTT sample
    pub latest_rtt: u64,
    /// Number of samples
    pub samples: u32,
}

impl RttEstimator {
    pub const fn new() -> Self {
        Self {
            srtt: 0,
            rttvar: 0,
            rto_ms: RTO_INIT_MS,
            min_rtt: u64::MAX,
            latest_rtt: 0,
            samples: 0,
        }
    }

    /// Update with a new RTT measurement (in microseconds)
    pub fn update(&mut self, rtt_us: u64) {
        self.latest_rtt = rtt_us;
        if rtt_us < self.min_rtt {
            self.min_rtt = rtt_us;
        }

        let rtt = rtt_us as i64;

        if self.samples == 0 {
            // First sample: SRTT = R, RTTVAR = R/2
            self.srtt = rtt << 3;
            self.rttvar = rtt << 1;
        } else {
            // RTTVAR = (1-beta) * RTTVAR + beta * |SRTT - R|
            // beta = 1/4
            let delta = ((self.srtt >> 3) - rtt).abs();
            self.rttvar = self.rttvar - (self.rttvar >> 2) + delta;

            // SRTT = (1-alpha) * SRTT + alpha * R
            // alpha = 1/8
            self.srtt = self.srtt - (self.srtt >> 3) + rtt;
        }

        self.samples += 1;

        // RTO = SRTT + max(G, 4*RTTVAR) where G = clock granularity
        let rto_us = (self.srtt >> 3) + (4 * self.rttvar);
        let rto_ms = (rto_us / 1000) as u32;
        self.rto_ms = rto_ms.clamp(RTO_MIN_MS, RTO_MAX_MS);
    }

    pub fn smoothed_rtt_us(&self) -> u64 {
        if self.samples == 0 {
            return 0;
        }
        (self.srtt >> 3) as u64
    }

    /// Back off RTO (exponential backoff on timeout)
    pub fn backoff(&mut self) {
        self.rto_ms = (self.rto_ms * 2).min(RTO_MAX_MS);
    }
}

// ─────────────────── SACK Blocks ────────────────────────────────────
pub const MAX_SACK_BLOCKS: usize = 4;

#[derive(Debug, Clone, Copy, Default)]
pub struct SackBlock {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SackState {
    pub blocks: [SackBlock; MAX_SACK_BLOCKS],
    pub count: usize,
    /// Number of bytes we know are lost based on SACK
    pub sacked_bytes: u32,
    pub lost_bytes: u32,
}

impl SackState {
    pub const fn new() -> Self {
        Self {
            blocks: [SackBlock { start: 0, end: 0 }; MAX_SACK_BLOCKS],
            count: 0,
            sacked_bytes: 0,
            lost_bytes: 0,
        }
    }

    pub fn add_block(&mut self, start: u32, end: u32) {
        if self.count < MAX_SACK_BLOCKS {
            self.blocks[self.count] = SackBlock { start, end };
            self.count += 1;
            self.recalculate();
        }
    }

    pub fn clear(&mut self) {
        self.count = 0;
        self.sacked_bytes = 0;
        self.lost_bytes = 0;
    }

    fn recalculate(&mut self) {
        self.sacked_bytes = 0;
        for i in 0..self.count {
            let blk = &self.blocks[i];
            self.sacked_bytes += blk.end.wrapping_sub(blk.start);
        }
    }

    pub fn is_sacked(&self, seq: u32) -> bool {
        for i in 0..self.count {
            let blk = &self.blocks[i];
            // Simple check: seq is within [start, end)
            if seq_ge(seq, blk.start) && seq_lt(seq, blk.end) {
                return true;
            }
        }
        false
    }
}

// Sequence number comparison helpers (mod 2^32)
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

// ─────────────────── Congestion State ───────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongState {
    Open,
    Disorder,
    CWR,         // Congestion Window Reduced (ECN)
    Recovery,    // Fast recovery
    Loss,        // Timeout loss
}

/// Common congestion control state shared by all algorithms
pub struct CcState {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub bytes_in_flight: u32,
    pub bytes_acked: u64,
    pub bytes_delivered: u64,
    pub cong_state: CongState,
    pub dup_ack_count: u32,
    pub recovery_point: u32,
    pub rtt: RttEstimator,
    pub sack: SackState,
    /// ECN support
    pub ecn_enabled: bool,
    pub ecn_ce_count: u32,
    /// Pacing rate (bytes per second)
    pub pacing_rate: u64,
    /// Send time of last packet
    pub last_send_time_us: u64,
}

impl CcState {
    pub const fn new() -> Self {
        Self {
            cwnd: INIT_CWND,
            ssthresh: INIT_SSTHRESH,
            bytes_in_flight: 0,
            bytes_acked: 0,
            bytes_delivered: 0,
            cong_state: CongState::Open,
            dup_ack_count: 0,
            recovery_point: 0,
            rtt: RttEstimator::new(),
            sack: SackState::new(),
            ecn_enabled: false,
            ecn_ce_count: 0,
            pacing_rate: 0,
            last_send_time_us: 0,
        }
    }

    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    pub fn available_window(&self) -> u32 {
        if self.cwnd > self.bytes_in_flight {
            self.cwnd - self.bytes_in_flight
        } else {
            0
        }
    }
}

// ─────────────────── Reno (Classic AIMD) ────────────────────────────
pub struct Reno;

impl Reno {
    pub fn on_ack(state: &mut CcState, acked_bytes: u32) {
        match state.cong_state {
            CongState::Open | CongState::Disorder => {
                if state.cwnd < state.ssthresh {
                    // Slow start: increase by acked_bytes
                    state.cwnd += acked_bytes;
                    if state.cwnd > MAX_CWND {
                        state.cwnd = MAX_CWND;
                    }
                } else {
                    // Congestion avoidance: increase by MSS*acked/cwnd
                    let inc = ((MSS as u64) * (acked_bytes as u64)) / (state.cwnd as u64);
                    state.cwnd += inc as u32;
                    if state.cwnd > MAX_CWND {
                        state.cwnd = MAX_CWND;
                    }
                }
                state.bytes_acked += acked_bytes as u64;
            }
            CongState::Recovery => {
                // In recovery, deflate window
                if acked_bytes > 0 {
                    state.cwnd = state.cwnd.saturating_sub(acked_bytes);
                    state.cwnd += MSS;
                }
            }
            _ => {}
        }
    }

    pub fn on_dup_ack(state: &mut CcState) {
        state.dup_ack_count += 1;
        if state.dup_ack_count >= DUPACK_THRESH && state.cong_state == CongState::Open {
            // Fast retransmit
            state.ssthresh = (state.cwnd / 2).max(MIN_CWND);
            state.cwnd = state.ssthresh + DUPACK_THRESH * MSS;
            state.cong_state = CongState::Recovery;
        } else if state.cong_state == CongState::Recovery {
            // Each additional dup ACK inflates window
            state.cwnd += MSS;
        }
    }

    pub fn on_loss(state: &mut CcState) {
        state.ssthresh = (state.cwnd / 2).max(MIN_CWND);
        state.cwnd = MSS;
        state.cong_state = CongState::Loss;
        state.rtt.backoff();
    }

    pub fn on_recovery_exit(state: &mut CcState) {
        state.cwnd = state.ssthresh;
        state.cong_state = CongState::Open;
        state.dup_ack_count = 0;
    }
}

// ─────────────────── Cubic ──────────────────────────────────────────
pub struct CubicState {
    /// Time of last congestion event (ms)
    pub epoch_start_ms: u64,
    /// Window size just before last reduction
    pub w_max: u32,
    /// Cubic constant C
    pub c: u32, // scaled by 1000 (0.4 => 400)
    /// Last max before fast convergence
    pub w_last_max: u32,
    /// Origin point of cubic function
    pub origin_point: u32,
    /// K value (time to reach W_max from origin)
    pub k_ms: u64,
    /// TCP-friendly cwnd
    pub tcp_cwnd: u32,
    /// Ack count for TCP-friendly mode
    pub ack_cnt: u32,
}

impl CubicState {
    pub const fn new() -> Self {
        Self {
            epoch_start_ms: 0,
            w_max: 0,
            c: 400, // C=0.4 scaled by 1000
            w_last_max: 0,
            origin_point: 0,
            k_ms: 0,
            tcp_cwnd: INIT_CWND,
            ack_cnt: 0,
        }
    }
}

pub struct Cubic;

impl Cubic {
    /// Cube root approximation using Newton's method
    fn cbrt(x: u64) -> u64 {
        if x == 0 {
            return 0;
        }
        let mut r: u64 = 1;
        // Start with rough estimate
        let mut shift = 0u32;
        let mut tmp = x;
        while tmp > 1 {
            tmp >>= 3;
            shift += 1;
        }
        r = 1u64 << shift;

        // Newton iterations
        for _ in 0..10 {
            let r2 = r * r;
            if r2 == 0 {
                break;
            }
            r = (2 * r + x / r2) / 3;
        }
        r
    }

    pub fn on_ack(cc: &mut CcState, cubic: &mut CubicState, now_ms: u64, acked_bytes: u32) {
        if cc.cwnd < cc.ssthresh {
            // Slow start
            cc.cwnd += acked_bytes;
            return;
        }

        if cubic.epoch_start_ms == 0 {
            cubic.epoch_start_ms = now_ms;
            if cc.cwnd < cubic.w_max {
                // K = cbrt(W_max - cwnd / C)
                let diff = (cubic.w_max - cc.cwnd) as u64;
                let scaled = diff * 1000 / (cubic.c as u64);
                cubic.k_ms = Self::cbrt(scaled * 1000); // rough
            } else {
                cubic.k_ms = 0;
            }
            cubic.origin_point = cubic.w_max;
        }

        let t_ms = now_ms.saturating_sub(cubic.epoch_start_ms);

        // W_cubic(t) = C*(t-K)^3 + W_max
        let t_diff = if t_ms > cubic.k_ms {
            (t_ms - cubic.k_ms) as i64
        } else {
            -((cubic.k_ms - t_ms) as i64)
        };

        let t_diff_abs = t_diff.unsigned_abs();
        let cube = t_diff_abs * t_diff_abs * t_diff_abs;
        let delta = (cube * (cubic.c as u64)) / (1000 * 1000 * 1000);

        let target = if t_diff >= 0 {
            cubic.origin_point.saturating_add(delta as u32)
        } else {
            cubic.origin_point.saturating_sub(delta as u32)
        };

        // TCP-friendly region
        cubic.tcp_cwnd += (acked_bytes * MSS) / cubic.tcp_cwnd.max(1);

        let new_cwnd = target.max(cubic.tcp_cwnd);
        if new_cwnd > cc.cwnd {
            let inc = ((new_cwnd - cc.cwnd) as u64 * acked_bytes as u64) / cc.cwnd as u64;
            cc.cwnd += inc.min(MSS as u64) as u32;
        }

        cc.cwnd = cc.cwnd.clamp(MIN_CWND, MAX_CWND);
    }

    pub fn on_loss(cc: &mut CcState, cubic: &mut CubicState) {
        cubic.epoch_start_ms = 0;

        // Fast convergence
        if cc.cwnd < cubic.w_last_max {
            cubic.w_last_max = cc.cwnd;
            cubic.w_max = (cc.cwnd as u64 * 170 / 200) as u32; // B_fast = 0.85
        } else {
            cubic.w_last_max = cc.cwnd;
            cubic.w_max = cc.cwnd;
        }

        cc.ssthresh = (cc.cwnd as u64 * 7 / 10) as u32; // beta = 0.7 for Cubic
        cc.ssthresh = cc.ssthresh.max(MIN_CWND);
        cc.cwnd = cc.ssthresh;
        cubic.tcp_cwnd = cc.cwnd;

        cc.rtt.backoff();
    }
}

// ─────────────────── BBR (Bottleneck Bandwidth and RTT) ─────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BbrState {
    Startup,
    Drain,
    ProbeBW,
    ProbeRTT,
}

pub struct BbrInner {
    pub state: BbrState,
    /// Estimated bottleneck bandwidth (bytes/sec)
    pub btl_bw: u64,
    /// Minimum RTT observed (microseconds)
    pub rt_prop: u64,
    /// Pacing gain (scaled by 100)
    pub pacing_gain: u32,
    /// CWND gain (scaled by 100)
    pub cwnd_gain: u32,
    /// Probe BW cycle index (0-7)
    pub cycle_index: u8,
    /// Round count
    pub round_count: u64,
    /// Delivered at start of round
    pub round_start_delivered: u64,
    /// Is this a new round?
    pub round_start: bool,
    /// Full pipe detection
    pub full_bw: u64,
    pub full_bw_count: u32,
    pub filled_pipe: bool,
    /// RTT probe window
    pub probe_rtt_done: bool,
    pub probe_rtt_round_done: bool,
    pub rt_prop_stamp_us: u64,
    /// Bandwidth window (10 rounds)
    pub bw_samples: [u64; 10],
    pub bw_idx: usize,
}

impl BbrInner {
    pub const fn new() -> Self {
        Self {
            state: BbrState::Startup,
            btl_bw: 0,
            rt_prop: u64::MAX,
            pacing_gain: 288, // 2.88x during startup
            cwnd_gain: 200,   // 2x
            cycle_index: 0,
            round_count: 0,
            round_start_delivered: 0,
            round_start: false,
            full_bw: 0,
            full_bw_count: 0,
            filled_pipe: false,
            probe_rtt_done: false,
            probe_rtt_round_done: false,
            rt_prop_stamp_us: 0,
            bw_samples: [0u64; 10],
            bw_idx: 0,
        }
    }
}

pub struct Bbr;

impl Bbr {
    const PROBE_BW_GAINS: [u32; 8] = [125, 75, 100, 100, 100, 100, 100, 100];
    const STARTUP_GAIN: u32 = 288;
    const DRAIN_GAIN: u32 = 35; // 1/2.88 ≈ 0.35

    pub fn on_ack(cc: &mut CcState, bbr: &mut BbrInner, _now_us: u64, delivered_bytes: u32) {
        // Update bandwidth estimate
        let rtt_us = cc.rtt.smoothed_rtt_us();
        if rtt_us > 0 {
            let bw = (delivered_bytes as u64 * 1_000_000) / rtt_us;
            bbr.bw_samples[bbr.bw_idx % 10] = bw;
            bbr.bw_idx += 1;

            // Max over window
            let mut max_bw: u64 = 0;
            for &sample in &bbr.bw_samples {
                if sample > max_bw {
                    max_bw = sample;
                }
            }
            bbr.btl_bw = max_bw;
        }

        // Update min RTT
        if rtt_us > 0 && rtt_us < bbr.rt_prop {
            bbr.rt_prop = rtt_us;
        }

        cc.bytes_delivered += delivered_bytes as u64;

        // State machine
        match bbr.state {
            BbrState::Startup => {
                bbr.pacing_gain = Self::STARTUP_GAIN;
                bbr.cwnd_gain = 200;

                // Check if pipe is full
                if bbr.btl_bw > 0 {
                    if bbr.btl_bw > bbr.full_bw * 5 / 4 {
                        bbr.full_bw = bbr.btl_bw;
                        bbr.full_bw_count = 0;
                    } else {
                        bbr.full_bw_count += 1;
                    }
                    if bbr.full_bw_count >= 3 {
                        bbr.filled_pipe = true;
                        bbr.state = BbrState::Drain;
                    }
                }
            }
            BbrState::Drain => {
                bbr.pacing_gain = Self::DRAIN_GAIN;
                bbr.cwnd_gain = 200;
                if cc.bytes_in_flight <= Self::target_cwnd(bbr) {
                    bbr.state = BbrState::ProbeBW;
                    bbr.cycle_index = 0;
                }
            }
            BbrState::ProbeBW => {
                bbr.pacing_gain = Self::PROBE_BW_GAINS[bbr.cycle_index as usize % 8];
                bbr.cwnd_gain = 200;
                bbr.cycle_index = (bbr.cycle_index + 1) % 8;
            }
            BbrState::ProbeRTT => {
                bbr.pacing_gain = 100;
                bbr.cwnd_gain = 100;
                // Hold low cwnd for at least one RTT
                if !bbr.probe_rtt_done {
                    bbr.probe_rtt_done = true;
                }
            }
        }

        // Set cwnd
        let target = Self::target_cwnd(bbr);
        cc.cwnd = target.clamp(MIN_CWND, MAX_CWND);

        // Set pacing rate
        let rate = (bbr.btl_bw * bbr.pacing_gain as u64) / 100;
        cc.pacing_rate = rate;
    }

    fn target_cwnd(bbr: &BbrInner) -> u32 {
        if bbr.rt_prop == u64::MAX || bbr.btl_bw == 0 {
            return INIT_CWND;
        }
        // BDP = btl_bw * rt_prop
        let bdp = (bbr.btl_bw * bbr.rt_prop) / 1_000_000;
        let cwnd = (bdp * bbr.cwnd_gain as u64) / 100;
        cwnd.min(MAX_CWND as u64) as u32
    }

    pub fn on_loss(cc: &mut CcState, bbr: &mut BbrInner) {
        // BBR doesn't reduce cwnd on loss in the same way
        // Just ensure we don't overshoot
        let target = Self::target_cwnd(bbr);
        if cc.cwnd > target {
            cc.cwnd = target;
        }
        _ = bbr;
    }
}

// ─────────────────── Vegas (Delay-Based) ────────────────────────────
pub struct VegasState {
    pub base_rtt: u64,     // minimum RTT seen (microseconds)
    pub alpha: u32,        // lower threshold (packets)
    pub beta: u32,         // upper threshold (packets)
    pub gamma: u32,        // threshold for switching from slow start
    pub cntRTT: u32,       // number of RTTs seen in this cycle
    pub min_rtt_this: u64, // min RTT in current cycle
}

impl VegasState {
    pub const fn new() -> Self {
        Self {
            base_rtt: u64::MAX,
            alpha: 2,
            beta: 4,
            gamma: 1,
            cntRTT: 0,
            min_rtt_this: u64::MAX,
        }
    }
}

pub struct Vegas;

impl Vegas {
    pub fn on_ack(cc: &mut CcState, vegas: &mut VegasState, rtt_us: u64, acked_bytes: u32) {
        if rtt_us == 0 {
            return;
        }

        // Track base RTT
        if rtt_us < vegas.base_rtt {
            vegas.base_rtt = rtt_us;
        }
        if rtt_us < vegas.min_rtt_this {
            vegas.min_rtt_this = rtt_us;
        }
        vegas.cntRTT += 1;

        // Only adjust once per RTT
        if vegas.cntRTT == 0 {
            return;
        }

        // Expected throughput = cwnd / base_rtt
        // Actual throughput = cwnd / rtt
        let expected = (cc.cwnd as u64 * 1_000_000) / vegas.base_rtt;
        let actual = (cc.cwnd as u64 * 1_000_000) / vegas.min_rtt_this;

        // diff = expected - actual (in MSS units)
        let diff = if expected > actual {
            ((expected - actual) * vegas.base_rtt / 1_000_000 / MSS as u64) as u32
        } else {
            0
        };

        if cc.cwnd < cc.ssthresh {
            // Slow start with Vegas gamma check
            if diff > vegas.gamma {
                cc.ssthresh = cc.cwnd;
            } else {
                cc.cwnd += acked_bytes;
            }
        } else {
            // Congestion avoidance
            if diff < vegas.alpha {
                // Not enough backlog, increase
                cc.cwnd += MSS;
            } else if diff > vegas.beta {
                // Too much backlog, decrease
                cc.cwnd = cc.cwnd.saturating_sub(MSS);
            }
            // else: in [alpha, beta], stay
        }

        cc.cwnd = cc.cwnd.clamp(MIN_CWND, MAX_CWND);

        // Reset per-RTT counters
        vegas.cntRTT = 0;
        vegas.min_rtt_this = u64::MAX;
    }

    pub fn on_loss(cc: &mut CcState, vegas: &mut VegasState) {
        cc.ssthresh = (cc.cwnd / 2).max(MIN_CWND);
        cc.cwnd = MIN_CWND;
        vegas.cntRTT = 0;
        vegas.min_rtt_this = u64::MAX;
    }
}

// ─────────────────── Pacing Engine ──────────────────────────────────
pub struct PacingEngine {
    /// Rate in bytes per second
    pub rate: u64,
    /// Time of last send (microseconds)
    pub last_send_us: u64,
    /// Tokens available for sending
    pub tokens: u32,
    /// Max burst tokens
    pub max_burst: u32,
}

impl PacingEngine {
    pub const fn new(rate: u64) -> Self {
        Self {
            rate,
            last_send_us: 0,
            tokens: INIT_CWND,
            max_burst: 10 * MSS,
        }
    }

    /// Update pacing with elapsed time
    pub fn update(&mut self, now_us: u64) {
        if self.last_send_us == 0 {
            self.last_send_us = now_us;
            return;
        }
        let elapsed = now_us.saturating_sub(self.last_send_us);
        if elapsed == 0 || self.rate == 0 {
            return;
        }

        // bytes = rate * elapsed / 1_000_000
        let new_tokens = (self.rate * elapsed / 1_000_000) as u32;
        self.tokens = (self.tokens + new_tokens).min(self.max_burst);
        self.last_send_us = now_us;
    }

    /// Check if we can send `bytes` now
    pub fn can_send(&self, bytes: u32) -> bool {
        self.tokens >= bytes
    }

    /// Consume tokens after sending
    pub fn on_send(&mut self, bytes: u32) {
        self.tokens = self.tokens.saturating_sub(bytes);
    }

    /// Time until next send is allowed (microseconds)
    pub fn next_send_time(&self, bytes: u32) -> u64 {
        if self.tokens >= bytes || self.rate == 0 {
            return 0;
        }
        let deficit = (bytes - self.tokens) as u64;
        (deficit * 1_000_000) / self.rate
    }

    pub fn set_rate(&mut self, bytes_per_sec: u64) {
        self.rate = bytes_per_sec;
    }
}

// ─────────────────── Unified Controller ─────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CcAlgorithm {
    Reno,
    Cubic,
    Bbr,
    Vegas,
}

/// Statistics for monitoring
#[repr(C)]
pub struct CcStats {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub bytes_in_flight: u32,
    pub rtt_us: u64,
    pub min_rtt_us: u64,
    pub pacing_rate: u64,
    pub bytes_acked: u64,
    pub algorithm: u8,
}

/// Pluggable congestion controller
pub struct CongestionController {
    pub algorithm: CcAlgorithm,
    pub state: CcState,
    pub cubic: CubicState,
    pub bbr: BbrInner,
    pub vegas: VegasState,
    pub pacer: PacingEngine,
}

impl CongestionController {
    pub fn new(algo: CcAlgorithm) -> Self {
        Self {
            algorithm: algo,
            state: CcState::new(),
            cubic: CubicState::new(),
            bbr: BbrInner::new(),
            vegas: VegasState::new(),
            pacer: PacingEngine::new(0),
        }
    }

    pub fn on_ack(&mut self, now_us: u64, acked_bytes: u32, rtt_us: u64) {
        self.state.rtt.update(rtt_us);

        match self.algorithm {
            CcAlgorithm::Reno => Reno::on_ack(&mut self.state, acked_bytes),
            CcAlgorithm::Cubic => Cubic::on_ack(&mut self.state, &mut self.cubic, now_us / 1000, acked_bytes),
            CcAlgorithm::Bbr => Bbr::on_ack(&mut self.state, &mut self.bbr, now_us, acked_bytes),
            CcAlgorithm::Vegas => Vegas::on_ack(&mut self.state, &mut self.vegas, rtt_us, acked_bytes),
        }

        self.pacer.set_rate(self.state.pacing_rate);
        self.state.bytes_in_flight = self.state.bytes_in_flight.saturating_sub(acked_bytes);
    }

    pub fn on_dup_ack(&mut self) {
        match self.algorithm {
            CcAlgorithm::Reno => Reno::on_dup_ack(&mut self.state),
            _ => {
                self.state.dup_ack_count += 1;
            }
        }
    }

    pub fn on_loss(&mut self) {
        match self.algorithm {
            CcAlgorithm::Reno => Reno::on_loss(&mut self.state),
            CcAlgorithm::Cubic => Cubic::on_loss(&mut self.state, &mut self.cubic),
            CcAlgorithm::Bbr => Bbr::on_loss(&mut self.state, &mut self.bbr),
            CcAlgorithm::Vegas => Vegas::on_loss(&mut self.state, &mut self.vegas),
        }
    }

    pub fn on_send(&mut self, bytes: u32, now_us: u64) {
        self.state.bytes_in_flight += bytes;
        self.state.last_send_time_us = now_us;
        self.pacer.on_send(bytes);
    }

    pub fn can_send(&self) -> bool {
        self.state.can_send()
    }

    pub fn available_window(&self) -> u32 {
        self.state.available_window()
    }

    pub fn stats(&self) -> CcStats {
        CcStats {
            cwnd: self.state.cwnd,
            ssthresh: self.state.ssthresh,
            bytes_in_flight: self.state.bytes_in_flight,
            rtt_us: self.state.rtt.smoothed_rtt_us(),
            min_rtt_us: self.state.rtt.min_rtt,
            pacing_rate: self.state.pacing_rate,
            bytes_acked: self.state.bytes_acked,
            algorithm: self.algorithm as u8,
        }
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────
static mut GLOBAL_CC: CongestionController = CongestionController {
    algorithm: CcAlgorithm::Cubic,
    state: CcState::new(),
    cubic: CubicState::new(),
    bbr: BbrInner::new(),
    vegas: VegasState::new(),
    pacer: PacingEngine::new(0),
};

#[no_mangle]
pub extern "C" fn rust_cc_init(algo: u8) {
    let a = match algo {
        0 => CcAlgorithm::Reno,
        1 => CcAlgorithm::Cubic,
        2 => CcAlgorithm::Bbr,
        3 => CcAlgorithm::Vegas,
        _ => CcAlgorithm::Cubic,
    };
    unsafe {
        GLOBAL_CC = CongestionController::new(a);
    }
}

#[no_mangle]
pub extern "C" fn rust_cc_on_ack(now_us: u64, acked_bytes: u32, rtt_us: u64) {
    unsafe {
        GLOBAL_CC.on_ack(now_us, acked_bytes, rtt_us);
    }
}

#[no_mangle]
pub extern "C" fn rust_cc_on_loss() {
    unsafe {
        GLOBAL_CC.on_loss();
    }
}

#[no_mangle]
pub extern "C" fn rust_cc_cwnd() -> u32 {
    unsafe { GLOBAL_CC.state.cwnd }
}

#[no_mangle]
pub extern "C" fn rust_cc_rtt_us() -> u64 {
    unsafe { GLOBAL_CC.state.rtt.smoothed_rtt_us() }
}

#[no_mangle]
pub extern "C" fn rust_cc_pacing_rate() -> u64 {
    unsafe { GLOBAL_CC.state.pacing_rate }
}

#[no_mangle]
pub extern "C" fn rust_cc_can_send() -> bool {
    unsafe { GLOBAL_CC.can_send() }
}
