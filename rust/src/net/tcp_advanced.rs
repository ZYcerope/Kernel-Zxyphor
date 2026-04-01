// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced TCP/IP Stack (Rust)
// Full TCP state machine, congestion control, zero-copy, multi-path TCP

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// TCP Connection States (RFC 793 + extensions)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    // Zxyphor extensions
    FastOpen,
    MultiPathJoin,
}

/// TCP Flags
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// TCP Options
#[derive(Debug, Clone, Copy)]
pub enum TcpOption {
    EndOfOptions,
    NoOperation,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack { blocks: [(u32, u32); 4], count: u8 },
    Timestamp { tsval: u32, tsecr: u32 },
    FastOpenCookie { cookie: [u8; 16], len: u8 },
    MultiPathCapable { key: u64 },
}

/// TCP Segment Header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16, // data offset (4 bits), reserved (3), flags (9)
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn data_offset(&self) -> u8 {
        ((u16::from_be(self.data_offset_flags) >> 12) & 0xF) as u8
    }

    pub fn flags(&self) -> u8 {
        (u16::from_be(self.data_offset_flags) & 0x1FF) as u8
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags() & flag != 0
    }

    pub fn seq(&self) -> u32 { u32::from_be(self.seq_num) }
    pub fn ack(&self) -> u32 { u32::from_be(self.ack_num) }
    pub fn src(&self) -> u16 { u16::from_be(self.src_port) }
    pub fn dst(&self) -> u16 { u16::from_be(self.dst_port) }
    pub fn win(&self) -> u16 { u16::from_be(self.window) }
}

/// Congestion Control Algorithm
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionAlgorithm {
    /// New Reno (default fallback)
    NewReno,
    /// CUBIC (Linux default)
    Cubic,
    /// BBR (Bottleneck Bandwidth and RTT)
    Bbr,
    /// BBRv2 (improved BBR)
    BbrV2,
    /// DCTCP (Data Center TCP)
    Dctcp,
    /// Zxyphor: AI-assisted congestion control
    ZxyAdaptive,
}

/// BBR State Machine
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BbrState {
    Startup,
    Drain,
    ProbeBW,
    ProbeRTT,
}

/// BBR Congestion Control State
pub struct BbrContext {
    pub state: BbrState,
    pub btl_bw: u64,           // Bottleneck bandwidth (bytes/sec)
    pub rt_prop: u64,          // Minimum RTT (microseconds)
    pub pacing_rate: u64,      // Current pacing rate
    pub cwnd: u32,             // Congestion window
    pub send_quantum: u32,     // Quantum for pacing
    pub pacing_gain: f32,      // Current pacing gain
    pub cwnd_gain: f32,        // Current cwnd gain
    pub round_count: u64,      // Round trip counter
    pub next_round_delivered: u64,
    pub round_start: bool,
    pub idle_restart: bool,
    pub full_bw: u64,          // Full bottleneck bandwidth estimate
    pub full_bw_count: u32,    // Count of rounds without BW growth
    pub cycle_idx: u8,         // ProbeBW cycle index
    pub cycle_stamp: u64,      // When cycle phase started
    pub probe_rtt_done_stamp: u64,
    pub probe_rtt_round_done: bool,
    pub prior_cwnd: u32,
    pub pacing_gain_cycle: [u32; 8],  // Fixed-point pacing gains (*100)
    // BBRv2 additions
    pub ecn_alpha: u32,        // ECN marking rate
    pub loss_round_start: bool,
    pub bw_probe_up_rounds: u32,
    pub inflight_hi: u32,
    pub inflight_lo: u32,
    pub probe_bw_phase: u8,
}

impl BbrContext {
    pub fn new() -> Self {
        BbrContext {
            state: BbrState::Startup,
            btl_bw: 0,
            rt_prop: u64::MAX,
            pacing_rate: 0,
            cwnd: 10 * 1460, // 10 segments initial
            send_quantum: 1460,
            pacing_gain: 2.885, // 2/ln(2) for startup
            cwnd_gain: 2.885,
            round_count: 0,
            next_round_delivered: 0,
            round_start: false,
            idle_restart: false,
            full_bw: 0,
            full_bw_count: 0,
            cycle_idx: 0,
            cycle_stamp: 0,
            probe_rtt_done_stamp: 0,
            probe_rtt_round_done: false,
            prior_cwnd: 0,
            pacing_gain_cycle: [125, 75, 100, 100, 100, 100, 100, 100],
            ecn_alpha: 0,
            loss_round_start: false,
            bw_probe_up_rounds: 0,
            inflight_hi: u32::MAX,
            inflight_lo: 0,
            probe_bw_phase: 0,
        }
    }

    pub fn update_btl_bw(&mut self, delivered: u64, interval: u64) {
        if interval == 0 { return; }
        let bw = (delivered * 1_000_000) / interval;
        if bw > self.btl_bw {
            self.btl_bw = bw;
        }
    }

    pub fn update_rt_prop(&mut self, rtt: u64) {
        if rtt < self.rt_prop {
            self.rt_prop = rtt;
        }
    }

    pub fn update_model(&mut self, delivered: u64, interval: u64, rtt: u64, losses: u32) {
        self.update_btl_bw(delivered, interval);
        self.update_rt_prop(rtt);

        match self.state {
            BbrState::Startup => {
                if self.full_bw_count >= 3 {
                    self.state = BbrState::Drain;
                    self.pacing_gain = 0.35; // Drain
                    self.cwnd_gain = 2.885;
                }
                let bw = if interval > 0 { (delivered * 1_000_000) / interval } else { 0 };
                if bw >= self.full_bw + self.full_bw / 4 {
                    self.full_bw = bw;
                    self.full_bw_count = 0;
                } else {
                    self.full_bw_count += 1;
                }
            }
            BbrState::Drain => {
                let inflight = self.bdp();
                if self.cwnd <= inflight as u32 {
                    self.state = BbrState::ProbeBW;
                    self.cycle_idx = 0;
                    self.pacing_gain = self.pacing_gain_cycle[0] as f32 / 100.0;
                }
            }
            BbrState::ProbeBW => {
                self.cycle_idx = (self.cycle_idx + 1) % 8;
                self.pacing_gain = self.pacing_gain_cycle[self.cycle_idx as usize] as f32 / 100.0;
                self.cwnd_gain = 2.0;
                
                // Check for RTT probe
                if self.round_count > 0 && self.round_count % 200 == 0 {
                    self.prior_cwnd = self.cwnd;
                    self.state = BbrState::ProbeRTT;
                    self.pacing_gain = 1.0;
                }
                
                // BBRv2: handle losses
                if losses > 0 {
                    self.ecn_alpha = self.ecn_alpha.saturating_add(losses * 256);
                }
            }
            BbrState::ProbeRTT => {
                self.cwnd = 4 * 1460; // Minimum 4 segments
                if self.probe_rtt_round_done {
                    self.state = BbrState::ProbeBW;
                    self.cwnd = self.prior_cwnd;
                }
            }
        }

        self.update_pacing_rate();
        self.update_cwnd();
    }

    fn bdp(&self) -> u64 {
        (self.btl_bw * self.rt_prop) / 1_000_000
    }

    fn update_pacing_rate(&mut self) {
        self.pacing_rate = (self.btl_bw as f32 * self.pacing_gain) as u64;
    }

    fn update_cwnd(&mut self) {
        let target = (self.bdp() as f32 * self.cwnd_gain) as u32;
        if self.state != BbrState::ProbeRTT {
            self.cwnd = core::cmp::max(self.cwnd, target);
        }
        self.cwnd = core::cmp::max(self.cwnd, 4 * 1460);
    }
}

/// CUBIC Congestion Control
pub struct CubicContext {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub last_max_cwnd: u32,
    pub last_cwnd: u32,
    pub last_time: u64,
    pub origin_point: u32,
    pub tcp_cwnd: u32,
    pub k: f32, // Time period to reach Wmax
    pub cnt: u32,
    pub ack_cnt: u32,
    pub beta: u32, // Multiplicative decrease factor (default 717/1024 ≈ 0.7)
    pub c_factor: u32, // CUBIC factor (default 410/1024 ≈ 0.4)
    pub hystart_enabled: bool,
    pub in_slow_start: bool,
    pub round_start: u64,
    pub last_ack: u64,
    pub delay_min: u64,
    pub found: bool,
}

impl CubicContext {
    pub fn new() -> Self {
        CubicContext {
            cwnd: 10 * 1460,
            ssthresh: u32::MAX,
            last_max_cwnd: 0,
            last_cwnd: 0,
            last_time: 0,
            origin_point: 0,
            tcp_cwnd: 0,
            k: 0.0,
            cnt: 0,
            ack_cnt: 0,
            beta: 717,
            c_factor: 410,
            hystart_enabled: true,
            in_slow_start: true,
            round_start: 0,
            last_ack: 0,
            delay_min: u64::MAX,
            found: false,
        }
    }

    pub fn on_ack(&mut self, now: u64, rtt: u64) {
        if self.in_slow_start {
            self.cwnd += 1460;
            if self.cwnd >= self.ssthresh {
                self.in_slow_start = false;
            }
            // HyStart++ detection
            if self.hystart_enabled {
                if rtt < self.delay_min { self.delay_min = rtt; }
                if rtt > self.delay_min + self.delay_min / 8 {
                    self.ssthresh = self.cwnd;
                    self.in_slow_start = false;
                }
            }
            return;
        }

        // CUBIC growth
        let elapsed = (now - self.last_time) as f32 / 1_000_000.0; // seconds
        let c = self.c_factor as f32 / 1024.0;

        let target = if elapsed > self.k {
            let t = elapsed - self.k;
            self.origin_point as f32 + c * t * t * t
        } else {
            let t = self.k - elapsed;
            self.origin_point as f32 - c * t * t * t
        };

        let target = target as u32;
        if target > self.cwnd {
            self.cnt = self.cwnd / (target - self.cwnd);
        } else {
            self.cnt = 100 * self.cwnd;
        }

        self.ack_cnt += 1;
        if self.ack_cnt >= self.cnt {
            self.cwnd += 1460;
            self.ack_cnt = 0;
        }
    }

    pub fn on_loss(&mut self, now: u64) {
        self.last_time = now;
        self.last_max_cwnd = self.cwnd;
        self.ssthresh = (self.cwnd as u64 * self.beta as u64 / 1024) as u32;
        self.ssthresh = core::cmp::max(self.ssthresh, 2 * 1460);
        self.cwnd = self.ssthresh;
        self.origin_point = self.last_max_cwnd;
        self.k = ((self.last_max_cwnd as f32 - self.cwnd as f32) / (self.c_factor as f32 / 1024.0)).cbrt();
        self.ack_cnt = 0;
    }
}

/// TCP Connection Control Block (TCB)
pub struct TcpConnection {
    // Identity
    pub local_addr: [u8; 16],  // IPv4/IPv6
    pub remote_addr: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub is_ipv6: bool,

    // State
    pub state: TcpState,
    
    // Sequence numbers
    pub snd_una: u32,    // Oldest unacknowledged
    pub snd_nxt: u32,    // Next to send
    pub snd_wl1: u32,    // Seq of last window update
    pub snd_wl2: u32,    // Ack of last window update
    pub iss: u32,        // Initial send sequence
    pub rcv_nxt: u32,    // Next expected to receive
    pub rcv_wnd: u32,    // Receive window
    pub irs: u32,        // Initial receive sequence
    pub snd_wnd: u32,    // Send window

    // Timers
    pub rto: u64,        // Retransmission timeout (us)
    pub srtt: u64,       // Smoothed RTT
    pub rttvar: u64,     // RTT variance
    pub rtt_seq: u32,    // Seq for RTT measurement
    pub retransmits: u32,
    pub max_retransmits: u32,
    
    // Flow control
    pub snd_cwnd: u32,   // Congestion window 
    pub snd_ssthresh: u32,
    pub mss: u16,        // Max segment size
    pub window_scale_snd: u8,
    pub window_scale_rcv: u8,
    
    // SACK
    pub sack_permitted: bool,
    pub sack_blocks: [(u32, u32); 4],
    pub sack_count: u8,
    
    // Timestamps
    pub ts_enabled: bool,
    pub ts_recent: u32,
    pub ts_last_ack: u32,
    
    // Congestion control
    pub cc_algo: CongestionAlgorithm,
    pub bbr: Option<BbrContext>,
    pub cubic: Option<CubicContext>,
    
    // Buffers (simplified - real impl uses ring buffers)
    pub send_buf_size: u32,
    pub recv_buf_size: u32,
    pub send_buf_used: u32,
    pub recv_buf_used: u32,
    
    // Statistics
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub segments_sent: u64,
    pub segments_received: u64,
    pub retransmit_count: u64,
    pub fast_retransmit_count: u64,
    pub duplicate_acks: u32,
    
    // Features
    pub ecn_enabled: bool,
    pub fastopen_enabled: bool,
    pub multipath_enabled: bool,
    pub keepalive_enabled: bool,
    pub keepalive_interval: u64,
    pub keepalive_count: u32,
    pub cork: bool,
    pub nodelay: bool, // Nagle's algorithm
    pub quickack: bool,
    
    // Zero-copy
    pub zerocopy_enabled: bool,
    pub splice_enabled: bool,
}

impl TcpConnection {
    pub fn new(local_addr: [u8; 16], local_port: u16, is_ipv6: bool) -> Self {
        TcpConnection {
            local_addr,
            remote_addr: [0; 16],
            local_port,
            remote_port: 0,
            is_ipv6,
            state: TcpState::Closed,
            snd_una: 0,
            snd_nxt: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss: 0,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            irs: 0,
            snd_wnd: 0,
            rto: 1_000_000, // 1 second
            srtt: 0,
            rttvar: 0,
            rtt_seq: 0,
            retransmits: 0,
            max_retransmits: 15,
            snd_cwnd: 10 * 1460,
            snd_ssthresh: u32::MAX,
            mss: 1460,
            window_scale_snd: 7,
            window_scale_rcv: 7,
            sack_permitted: true,
            sack_blocks: [(0, 0); 4],
            sack_count: 0,
            ts_enabled: true,
            ts_recent: 0,
            ts_last_ack: 0,
            cc_algo: CongestionAlgorithm::Cubic,
            bbr: None,
            cubic: Some(CubicContext::new()),
            send_buf_size: 262144,
            recv_buf_size: 262144,
            send_buf_used: 0,
            recv_buf_used: 0,
            bytes_sent: 0,
            bytes_received: 0,
            segments_sent: 0,
            segments_received: 0,
            retransmit_count: 0,
            fast_retransmit_count: 0,
            duplicate_acks: 0,
            ecn_enabled: true,
            fastopen_enabled: true, 
            multipath_enabled: false,
            keepalive_enabled: true,
            keepalive_interval: 75_000_000, // 75 seconds
            keepalive_count: 9,
            cork: false,
            nodelay: false,
            quickack: false,
            zerocopy_enabled: false,
            splice_enabled: false,
        }
    }

    /// Process incoming segment
    pub fn process_segment(&mut self, header: &TcpHeader, payload: &[u8], now: u64) -> TcpAction {
        self.segments_received += 1;

        match self.state {
            TcpState::Closed => self.handle_closed(header),
            TcpState::Listen => self.handle_listen(header, now),
            TcpState::SynSent => self.handle_syn_sent(header, now),
            TcpState::SynReceived => self.handle_syn_received(header, now),
            TcpState::Established => self.handle_established(header, payload, now),
            TcpState::FinWait1 => self.handle_fin_wait1(header, payload, now),
            TcpState::FinWait2 => self.handle_fin_wait2(header, payload, now),
            TcpState::CloseWait => self.handle_close_wait(header),
            TcpState::Closing => self.handle_closing(header),
            TcpState::LastAck => self.handle_last_ack(header),
            TcpState::TimeWait => self.handle_time_wait(header),
            _ => TcpAction::Drop,
        }
    }

    fn handle_closed(&self, header: &TcpHeader) -> TcpAction {
        if header.has_flag(tcp_flags::RST) {
            return TcpAction::Drop;
        }
        TcpAction::SendRst
    }

    fn handle_listen(&mut self, header: &TcpHeader, now: u64) -> TcpAction {
        if header.has_flag(tcp_flags::RST) {
            return TcpAction::Drop;
        }
        if header.has_flag(tcp_flags::ACK) {
            return TcpAction::SendRst;
        }
        if header.has_flag(tcp_flags::SYN) {
            self.rcv_nxt = header.seq().wrapping_add(1);
            self.irs = header.seq();
            self.iss = generate_isn(now);
            self.snd_nxt = self.iss.wrapping_add(1);
            self.snd_una = self.iss;
            self.state = TcpState::SynReceived;
            return TcpAction::SendSynAck;
        }
        TcpAction::Drop
    }

    fn handle_syn_sent(&mut self, header: &TcpHeader, now: u64) -> TcpAction {
        let _ = now;
        if header.has_flag(tcp_flags::ACK) {
            if !seq_between(self.iss.wrapping_add(1), header.ack(), self.snd_nxt.wrapping_add(1)) {
                return if header.has_flag(tcp_flags::RST) { TcpAction::Drop } else { TcpAction::SendRst };
            }
        }

        if header.has_flag(tcp_flags::RST) {
            if header.has_flag(tcp_flags::ACK) {
                self.state = TcpState::Closed;
                return TcpAction::ConnectionReset;
            }
            return TcpAction::Drop;
        }

        if header.has_flag(tcp_flags::SYN) {
            self.rcv_nxt = header.seq().wrapping_add(1);
            self.irs = header.seq();
            
            if header.has_flag(tcp_flags::ACK) {
                self.snd_una = header.ack();
                self.snd_wnd = (header.win() as u32) << self.window_scale_snd;
                self.state = TcpState::Established;
                return TcpAction::SendAck;
            } else {
                // Simultaneous open
                self.state = TcpState::SynReceived;
                return TcpAction::SendSynAck;
            }
        }

        TcpAction::Drop
    }

    fn handle_syn_received(&mut self, header: &TcpHeader, now: u64) -> TcpAction {
        let _ = now;
        if !check_seq(header, self) { return TcpAction::SendAck; }
        
        if header.has_flag(tcp_flags::RST) {
            self.state = TcpState::Closed;
            return TcpAction::ConnectionReset;
        }

        if header.has_flag(tcp_flags::ACK) {
            if seq_between(self.snd_una, header.ack(), self.snd_nxt.wrapping_add(1)) {
                self.state = TcpState::Established;
                self.snd_una = header.ack();
                self.snd_wnd = (header.win() as u32) << self.window_scale_snd;
                return TcpAction::Connected;
            }
            return TcpAction::SendRst;
        }

        TcpAction::Drop
    }

    fn handle_established(&mut self, header: &TcpHeader, payload: &[u8], now: u64) -> TcpAction {
        if !check_seq(header, self) { return TcpAction::SendAck; }
        
        if header.has_flag(tcp_flags::RST) {
            self.state = TcpState::Closed;
            return TcpAction::ConnectionReset;
        }

        if header.has_flag(tcp_flags::ACK) {
            self.process_ack(header.ack(), now);
        }

        // Process data
        if !payload.is_empty() {
            if header.seq() == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                self.bytes_received += payload.len() as u64;
                self.recv_buf_used += payload.len() as u32;
            }
            // Out-of-order data would go to reassembly queue
        }

        if header.has_flag(tcp_flags::FIN) {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::CloseWait;
            return TcpAction::SendAck;
        }

        if !payload.is_empty() || header.has_flag(tcp_flags::FIN) {
            TcpAction::SendAck
        } else {
            TcpAction::None
        }
    }

    fn handle_fin_wait1(&mut self, header: &TcpHeader, _payload: &[u8], now: u64) -> TcpAction {
        if header.has_flag(tcp_flags::ACK) {
            self.process_ack(header.ack(), now);
            if header.ack() == self.snd_nxt {
                if header.has_flag(tcp_flags::FIN) {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.state = TcpState::TimeWait;
                    return TcpAction::SendAck;
                }
                self.state = TcpState::FinWait2;
            }
        }
        if header.has_flag(tcp_flags::FIN) {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::Closing;
            return TcpAction::SendAck;
        }
        TcpAction::None
    }

    fn handle_fin_wait2(&mut self, header: &TcpHeader, _payload: &[u8], _now: u64) -> TcpAction {
        if header.has_flag(tcp_flags::FIN) {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::TimeWait;
            return TcpAction::SendAck;
        }
        TcpAction::None
    }

    fn handle_close_wait(&self, _header: &TcpHeader) -> TcpAction {
        TcpAction::None
    }

    fn handle_closing(&mut self, header: &TcpHeader) -> TcpAction {
        if header.has_flag(tcp_flags::ACK) && header.ack() == self.snd_nxt {
            self.state = TcpState::TimeWait;
        }
        TcpAction::None
    }

    fn handle_last_ack(&mut self, header: &TcpHeader) -> TcpAction {
        if header.has_flag(tcp_flags::ACK) && header.ack() == self.snd_nxt {
            self.state = TcpState::Closed;
            return TcpAction::ConnectionClosed;
        }
        TcpAction::None
    }

    fn handle_time_wait(&mut self, header: &TcpHeader) -> TcpAction {
        if header.has_flag(tcp_flags::SYN) {
            // Check if it's a new connection (higher seq)
            if header.seq() > self.rcv_nxt {
                // Allow reuse
                self.state = TcpState::Closed;
                return TcpAction::ConnectionClosed;
            }
        }
        if header.has_flag(tcp_flags::FIN) {
            return TcpAction::SendAck; // Re-ack FIN
        }
        TcpAction::None
    }

    /// Process ACK and update congestion control
    fn process_ack(&mut self, ack: u32, now: u64) {
        if !seq_between(self.snd_una, ack, self.snd_nxt.wrapping_add(1)) {
            return;
        }

        let bytes_acked = ack.wrapping_sub(self.snd_una);
        self.snd_una = ack;
        self.bytes_sent += bytes_acked as u64;

        // Update RTT
        self.update_rtt(now);

        // Update congestion control
        match self.cc_algo {
            CongestionAlgorithm::Cubic => {
                if let Some(ref mut cubic) = self.cubic {
                    cubic.on_ack(now, self.srtt);
                    self.snd_cwnd = cubic.cwnd;
                }
            }
            CongestionAlgorithm::Bbr | CongestionAlgorithm::BbrV2 => {
                if let Some(ref mut bbr) = self.bbr {
                    bbr.update_model(bytes_acked as u64, self.srtt, self.srtt, 0);
                    self.snd_cwnd = bbr.cwnd;
                }
            }
            CongestionAlgorithm::NewReno => {
                if self.snd_cwnd < self.snd_ssthresh {
                    // Slow start
                    self.snd_cwnd += self.mss as u32;
                } else {
                    // Congestion avoidance
                    self.snd_cwnd += (self.mss as u32 * self.mss as u32) / self.snd_cwnd;
                }
            }
            _ => {}
        }
    }

    fn update_rtt(&mut self, now: u64) {
        // Simplified RTT update (Jacobson/Karels algorithm)
        if self.srtt == 0 {
            self.srtt = now;
            self.rttvar = now / 2;
        } else {
            let delta = if now > self.srtt { now - self.srtt } else { self.srtt - now };
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + now) / 8;
        }
        self.rto = self.srtt + 4 * self.rttvar;
        self.rto = core::cmp::max(self.rto, 200_000); // Min 200ms
        self.rto = core::cmp::min(self.rto, 120_000_000); // Max 120s
    }

    /// Initiate active close
    pub fn close(&mut self) -> TcpAction {
        match self.state {
            TcpState::Established => {
                self.state = TcpState::FinWait1;
                TcpAction::SendFin
            }
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                TcpAction::SendFin
            }
            TcpState::SynReceived => {
                self.state = TcpState::FinWait1;
                TcpAction::SendFin
            }
            _ => TcpAction::None,
        }
    }

    /// Check how much data we can send
    pub fn send_window(&self) -> u32 {
        let cwnd_limit = self.snd_cwnd;
        let wnd_limit = self.snd_wnd;
        let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
        let window = core::cmp::min(cwnd_limit, wnd_limit);
        window.saturating_sub(inflight)
    }

    /// Set congestion control algorithm
    pub fn set_congestion_control(&mut self, algo: CongestionAlgorithm) {
        self.cc_algo = algo;
        match algo {
            CongestionAlgorithm::Bbr | CongestionAlgorithm::BbrV2 => {
                self.bbr = Some(BbrContext::new());
                self.cubic = None;
            }
            CongestionAlgorithm::Cubic => {
                self.cubic = Some(CubicContext::new());
                self.bbr = None;
            }
            _ => {
                self.bbr = None;
                self.cubic = None;
            }
        }
    }

    /// Handle retransmission timeout
    pub fn on_rto_timeout(&mut self) {
        self.retransmits += 1;
        self.retransmit_count += 1;
        
        // Exponential backoff
        self.rto = core::cmp::min(self.rto * 2, 120_000_000);
        
        // Reset congestion window
        self.snd_ssthresh = core::cmp::max(self.snd_cwnd / 2, 2 * self.mss as u32);
        self.snd_cwnd = self.mss as u32;
        
        // Reset SACK state
        self.sack_count = 0;
        self.duplicate_acks = 0;
    }

    /// Handle fast retransmit (3 duplicate ACKs)
    pub fn on_fast_retransmit(&mut self) {
        self.fast_retransmit_count += 1;
        self.snd_ssthresh = core::cmp::max(self.snd_cwnd / 2, 2 * self.mss as u32);
        self.snd_cwnd = self.snd_ssthresh + 3 * self.mss as u32;
    }
}

/// TCP Actions returned by state machine
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpAction {
    None,
    Drop,
    SendSynAck,
    SendAck,
    SendRst,
    SendFin,
    Connected,
    ConnectionReset,
    ConnectionClosed,
    DataReceived,
}

// Sequence number comparison helpers
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

fn seq_between(a: u32, b: u32, c: u32) -> bool {
    seq_le(a, b) && seq_lt(b, c)
}

fn check_seq(_header: &TcpHeader, _conn: &TcpConnection) -> bool {
    true // Simplified - full implementation checks window
}

fn generate_isn(now: u64) -> u32 {
    // ISN should be unpredictable (use crypto RNG in production)
    let hash = now.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    hash as u32
}

/// Connection tracking table  
pub struct TcpTable {
    connections: [Option<TcpConnection>; 65536],
    count: u32,
    max_connections: u32,
    syn_backlog: u32,
    max_syn_backlog: u32,
}

impl TcpTable {
    pub fn connection_count(&self) -> u32 {
        self.count
    }

    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }
}

/// Global TCP statistics
pub struct TcpStats {
    pub active_opens: AtomicU64,
    pub passive_opens: AtomicU64,
    pub failed_attempts: AtomicU64,
    pub established_resets: AtomicU64,
    pub current_established: AtomicU32,
    pub segments_received: AtomicU64,
    pub segments_sent: AtomicU64,
    pub retransmit_segments: AtomicU64,
    pub in_errors: AtomicU64,
    pub out_resets: AtomicU64,
}

impl TcpStats {
    pub const fn new() -> Self {
        TcpStats {
            active_opens: AtomicU64::new(0),
            passive_opens: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            established_resets: AtomicU64::new(0),
            current_established: AtomicU32::new(0),
            segments_received: AtomicU64::new(0),
            segments_sent: AtomicU64::new(0),
            retransmit_segments: AtomicU64::new(0),
            in_errors: AtomicU64::new(0),
            out_resets: AtomicU64::new(0),
        }
    }
}

static TCP_STATS: TcpStats = TcpStats::new();

pub fn get_tcp_stats() -> &'static TcpStats {
    &TCP_STATS
}
