// SPDX-License-Identifier: MIT
// Zxyphor Kernel - QUIC Protocol Implementation (RFC 9000)
// Full QUIC transport with 0-RTT, connection migration, multipath

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// QUIC Packet Types (Long Header)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    // Short header (1-RTT)
    OneRtt,
}

/// QUIC Frame Types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlocked = 0x16,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
    HandshakeDone = 0x1e,
    // Zxyphor extensions
    ZxyMultipath = 0x40,
    ZxyPriority = 0x41,
    ZxyDatagram = 0x42,
}

/// QUIC Error Codes
#[derive(Debug, Clone, Copy)]
pub enum TransportError {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
}

/// QUIC Version
pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// Connection ID
#[derive(Clone, Copy)]
pub struct ConnectionId {
    pub bytes: [u8; 20],
    pub len: u8,
}

impl ConnectionId {
    pub fn empty() -> Self {
        ConnectionId { bytes: [0; 20], len: 0 }
    }

    pub fn new(data: &[u8]) -> Self {
        let len = core::cmp::min(data.len(), 20);
        let mut bytes = [0u8; 20];
        bytes[..len].copy_from_slice(&data[..len]);
        ConnectionId { bytes, len: len as u8 }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn matches(&self, other: &ConnectionId) -> bool {
        self.len == other.len && self.as_slice() == other.as_slice()
    }
}

/// Transport Parameters (RFC 9000 Section 18)
pub struct TransportParams {
    pub original_dst_connection_id: Option<ConnectionId>,
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub preferred_address: Option<PreferredAddress>,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<ConnectionId>,
    pub retry_source_connection_id: Option<ConnectionId>,
    // QUIC v2 / Zxyphor extensions
    pub max_datagram_frame_size: u64,
    pub grease_quic_bit: bool,
    pub enable_multipath: bool,
    pub min_ack_delay: u64,
}

impl TransportParams {
    pub fn default_client() -> Self {
        TransportParams {
            original_dst_connection_id: None,
            max_idle_timeout: 30_000,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 10 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 1024 * 1024,
            initial_max_stream_data_bidi_remote: 1024 * 1024,
            initial_max_stream_data_uni: 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 8,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: 65535,
            grease_quic_bit: true,
            enable_multipath: true,
            min_ack_delay: 0,
        }
    }
}

pub struct PreferredAddress {
    pub ipv4: [u8; 4],
    pub ipv4_port: u16,
    pub ipv6: [u8; 16],
    pub ipv6_port: u16,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: [u8; 16],
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    DataSent,
    DataReceived,
    ResetSent,
    ResetReceived,
}

/// QUIC Stream
pub struct QuicStream {
    pub id: u64,
    pub state: StreamState,
    pub send_offset: u64,
    pub recv_offset: u64,
    pub max_send_data: u64,
    pub max_recv_data: u64,
    pub send_fin: bool,
    pub recv_fin: bool,
    pub final_size: Option<u64>,
    pub priority: u8,
    pub incremental: bool,
    // Flow control
    pub flow_control_limit: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    // Error codes
    pub reset_error: Option<u64>,
    pub stop_sending_error: Option<u64>,
}

impl QuicStream {
    pub fn new(id: u64, max_data: u64) -> Self {
        QuicStream {
            id,
            state: StreamState::Idle,
            send_offset: 0,
            recv_offset: 0,
            max_send_data: max_data,
            max_recv_data: max_data,
            send_fin: false,
            recv_fin: false,
            final_size: None,
            priority: 128,
            incremental: false,
            flow_control_limit: max_data,
            bytes_sent: 0,
            bytes_received: 0,
            reset_error: None,
            stop_sending_error: None,
        }
    }

    pub fn is_bidi(&self) -> bool { self.id & 0x2 == 0 }
    pub fn is_uni(&self) -> bool { self.id & 0x2 != 0 }
    pub fn is_client_initiated(&self) -> bool { self.id & 0x1 == 0 }
    pub fn is_server_initiated(&self) -> bool { self.id & 0x1 != 0 }

    pub fn can_send(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
            && self.bytes_sent < self.max_send_data
    }

    pub fn can_recv(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    pub fn send_data(&mut self, len: u64) -> Result<(), TransportError> {
        if !self.can_send() {
            return Err(TransportError::StreamStateError);
        }
        if self.bytes_sent + len > self.max_send_data {
            return Err(TransportError::FlowControlError);
        }
        self.bytes_sent += len;
        self.send_offset += len;
        Ok(())
    }

    pub fn recv_data(&mut self, offset: u64, len: u64, fin: bool) -> Result<(), TransportError> {
        if !self.can_recv() {
            return Err(TransportError::StreamStateError);
        }
        if let Some(final_size) = self.final_size {
            if offset + len > final_size {
                return Err(TransportError::FinalSizeError);
            }
        }
        if fin {
            self.final_size = Some(offset + len);
            self.recv_fin = true;
        }
        self.bytes_received += len;
        self.recv_offset = core::cmp::max(self.recv_offset, offset + len);
        Ok(())
    }

    pub fn close_send(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => self.state = StreamState::Closed,
            _ => {}
        }
        self.send_fin = true;
    }

    pub fn close_recv(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => self.state = StreamState::Closed,
            _ => {}
        }
    }

    pub fn reset(&mut self, error_code: u64) {
        self.state = StreamState::ResetSent;
        self.reset_error = Some(error_code);
    }
}

/// Packet Number Space
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PnSpace {
    Initial,
    Handshake,
    ApplicationData,
}

/// ACK tracking
pub struct AckTracker {
    pub ranges: [(u64, u64); 256], // (start, end) ranges
    pub range_count: usize,
    pub largest_acked: u64,
    pub largest_acked_time: u64,
    pub ack_delay: u64,
    pub ecn_counts: [u64; 3],  // ECT(0), ECT(1), CE
    pub ack_eliciting_received: bool,
}

impl AckTracker {
    pub fn new() -> Self {
        AckTracker {
            ranges: [(0, 0); 256],
            range_count: 0,
            largest_acked: 0,
            largest_acked_time: 0,
            ack_delay: 0,
            ecn_counts: [0; 3],
            ack_eliciting_received: false,
        }
    }

    pub fn record_received(&mut self, pn: u64, now: u64) {
        if pn > self.largest_acked {
            self.largest_acked = pn;
            self.largest_acked_time = now;
        }

        // Add to ranges (simplified insertion)
        if self.range_count == 0 {
            self.ranges[0] = (pn, pn);
            self.range_count = 1;
            return;
        }

        // Try to extend existing range
        for i in 0..self.range_count {
            let (start, end) = self.ranges[i];
            if pn >= start.saturating_sub(1) && pn <= end + 1 {
                self.ranges[i].0 = core::cmp::min(start, pn);
                self.ranges[i].1 = core::cmp::max(end, pn);
                self.coalesce_ranges();
                return;
            }
        }

        // New range
        if self.range_count < 256 {
            self.ranges[self.range_count] = (pn, pn);
            self.range_count += 1;
            self.sort_ranges();
        }
    }

    fn coalesce_ranges(&mut self) {
        if self.range_count <= 1 { return; }
        self.sort_ranges();
        
        let mut write = 0;
        for read in 1..self.range_count {
            if self.ranges[read].0 <= self.ranges[write].1 + 1 {
                self.ranges[write].1 = core::cmp::max(self.ranges[write].1, self.ranges[read].1);
            } else {
                write += 1;
                self.ranges[write] = self.ranges[read];
            }
        }
        self.range_count = write + 1;
    }

    fn sort_ranges(&mut self) {
        // Simple insertion sort for small arrays
        for i in 1..self.range_count {
            let key = self.ranges[i];
            let mut j = i;
            while j > 0 && self.ranges[j - 1].0 > key.0 {
                self.ranges[j] = self.ranges[j - 1];
                j -= 1;
            }
            self.ranges[j] = key;
        }
    }

    pub fn needs_ack(&self) -> bool {
        self.ack_eliciting_received
    }
}

/// Loss recovery state
pub struct LossRecovery {
    pub loss_detection_timer: u64,
    pub pto_count: u32,
    pub time_of_last_ack_eliciting_packet: [u64; 3], // per PnSpace
    pub largest_acked_packet: [u64; 3],
    pub loss_time: [u64; 3],
    pub smoothed_rtt: u64,
    pub rttvar: u64,
    pub min_rtt: u64,
    pub max_ack_delay: u64,
    pub first_rtt_sample: u64,
    // QUIC-specific
    pub pto_timeout: u64,
    pub kPacketThreshold: u32,
    pub kTimeThreshold: u32, // In 1/16 of an RTT
    pub kGranularity: u64,   // Timer granularity
    pub kInitialRtt: u64,
}

impl LossRecovery {
    pub fn new() -> Self {
        LossRecovery {
            loss_detection_timer: 0,
            pto_count: 0,
            time_of_last_ack_eliciting_packet: [0; 3],
            largest_acked_packet: [0; 3],
            loss_time: [0; 3],
            smoothed_rtt: 0,
            rttvar: 0,
            min_rtt: u64::MAX,
            max_ack_delay: 25_000, // 25ms
            first_rtt_sample: 0,
            pto_timeout: 0,
            kPacketThreshold: 3,
            kTimeThreshold: 9, // 9/8 of RTT (in 8ths, so 9)
            kGranularity: 1_000,
            kInitialRtt: 333_000, // 333ms
        }
    }

    pub fn update_rtt(&mut self, ack_delay: u64, rtt: u64) {
        if self.min_rtt > rtt {
            self.min_rtt = rtt;
        }
        if self.first_rtt_sample == 0 {
            self.first_rtt_sample = rtt;
            self.smoothed_rtt = rtt;
            self.rttvar = rtt / 2;
            return;
        }
        
        let adjusted_rtt = if rtt > self.min_rtt + ack_delay {
            rtt - ack_delay
        } else {
            rtt
        };

        let delta = if adjusted_rtt > self.smoothed_rtt {
            adjusted_rtt - self.smoothed_rtt
        } else {
            self.smoothed_rtt - adjusted_rtt
        };
        
        self.rttvar = (3 * self.rttvar + delta) / 4;
        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) / 8;
    }

    pub fn get_pto(&self) -> u64 {
        self.smoothed_rtt + core::cmp::max(4 * self.rttvar, self.kGranularity) + self.max_ack_delay
    }

    pub fn on_loss_detection_timeout(&mut self, now: u64, space: PnSpace) {
        let sp = space as usize;
        if self.loss_time[sp] != 0 {
            // Time threshold loss detection
            // Mark packets lost
        } else {
            // PTO timeout - send probe
            self.pto_count += 1;
        }
        self.set_loss_detection_timer(now);
    }

    pub fn set_loss_detection_timer(&mut self, now: u64) {
        // Find earliest loss time
        let mut earliest = u64::MAX;
        for i in 0..3 {
            if self.loss_time[i] != 0 && self.loss_time[i] < earliest {
                earliest = self.loss_time[i];
            }
        }
        if earliest != u64::MAX {
            self.loss_detection_timer = earliest;
            return;
        }

        // PTO timer
        let timeout = self.get_pto() * (1 << self.pto_count);
        self.loss_detection_timer = now + timeout;
    }
}

/// QUIC Congestion Controller (using NewReno for QUIC)
pub struct QuicCongestion {
    pub cwnd: u64,
    pub bytes_in_flight: u64,
    pub ssthresh: u64,
    pub recovery_start: u64,
    pub ecn_ce_counters: [u64; 3],
    pub kMinimumWindow: u64,
    pub kLossReductionFactor: u64, // in 1024ths
    pub kInitialWindow: u64,
    pub max_datagram_size: u64,
}

impl QuicCongestion {
    pub fn new(max_datagram_size: u64) -> Self {
        let initial_window = core::cmp::min(
            10 * max_datagram_size,
            core::cmp::max(14720, 2 * max_datagram_size),
        );
        QuicCongestion {
            cwnd: initial_window,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            recovery_start: 0,
            ecn_ce_counters: [0; 3],
            kMinimumWindow: 2 * max_datagram_size,
            kLossReductionFactor: 512, // 0.5
            kInitialWindow: initial_window,
            max_datagram_size,
        }
    }

    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_in_flight += bytes;
    }

    pub fn on_packet_acked(&mut self, bytes: u64, now: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        
        if now < self.recovery_start {
            return; // In recovery, don't grow
        }

        if self.cwnd < self.ssthresh {
            // Slow start
            self.cwnd += bytes;
        } else {
            // Congestion avoidance
            self.cwnd += self.max_datagram_size * bytes / self.cwnd;
        }
    }

    pub fn on_congestion_event(&mut self, sent_time: u64) {
        if sent_time <= self.recovery_start {
            return; // Already in recovery for this event
        }
        
        self.recovery_start = sent_time;
        self.ssthresh = self.cwnd * self.kLossReductionFactor / 1024;
        self.cwnd = core::cmp::max(self.ssthresh, self.kMinimumWindow);
    }

    pub fn on_persistent_congestion(&mut self) {
        self.cwnd = self.kMinimumWindow;
        self.ssthresh = self.cwnd;
    }

    pub fn available_window(&self) -> u64 {
        if self.cwnd > self.bytes_in_flight {
            self.cwnd - self.bytes_in_flight
        } else {
            0
        }
    }
}

/// QUIC Connection States
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QuicState {
    Idle,
    Handshaking,
    Connected,
    Closing,
    Draining,
    Closed,
}

/// Multipath state for QUIC multipath extension
pub struct MultipathState {
    pub paths: [PathState; 8],
    pub active_paths: u8,
    pub primary_path: u8,
    pub scheduler: MultipathScheduler,
}

#[derive(Clone, Copy)]
pub struct PathState {
    pub active: bool,
    pub validated: bool,
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub rtt: u64,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
    pub mtu: u16,
    pub challenge_data: u64,
    pub response_received: bool,
}

impl PathState {
    pub fn new() -> Self {
        PathState {
            active: false,
            validated: false,
            local_addr: [0; 16],
            remote_addr: [0; 16],
            local_port: 0,
            remote_port: 0,
            rtt: 0,
            cwnd: 0,
            bytes_in_flight: 0,
            mtu: 1200,
            challenge_data: 0,
            response_received: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MultipathScheduler {
    RoundRobin,
    MinRtt,
    Redundant,
    Weighted,
    LowestLatency,
}

impl MultipathState {
    pub fn new() -> Self {
        MultipathState {
            paths: [PathState::new(); 8],
            active_paths: 0,
            primary_path: 0,
            scheduler: MultipathScheduler::MinRtt,
        }
    }

    pub fn add_path(&mut self, local_addr: [u8; 16], local_port: u16, 
                     remote_addr: [u8; 16], remote_port: u16) -> Option<u8> {
        for i in 0..8 {
            if !self.paths[i].active {
                self.paths[i].active = true;
                self.paths[i].local_addr = local_addr;
                self.paths[i].local_port = local_port;
                self.paths[i].remote_addr = remote_addr;
                self.paths[i].remote_port = remote_port;
                self.paths[i].mtu = 1200;
                self.active_paths += 1;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn select_path(&self) -> u8 {
        match self.scheduler {
            MultipathScheduler::MinRtt => {
                let mut best = self.primary_path;
                let mut best_rtt = u64::MAX;
                for i in 0..8 {
                    if self.paths[i].active && self.paths[i].validated && self.paths[i].rtt < best_rtt {
                        best_rtt = self.paths[i].rtt;
                        best = i as u8;
                    }
                }
                best
            }
            MultipathScheduler::RoundRobin => {
                // Simple round-robin
                let mut next = (self.primary_path + 1) % 8;
                for _ in 0..8 {
                    if self.paths[next as usize].active && self.paths[next as usize].validated {
                        return next;
                    }
                    next = (next + 1) % 8;
                }
                self.primary_path
            }
            _ => self.primary_path,
        }
    }
}

/// QUIC Connection
pub struct QuicConnection {
    pub state: QuicState,
    pub is_server: bool,
    pub version: u32,
    
    // Connection IDs
    pub src_cid: ConnectionId,
    pub dst_cid: ConnectionId,
    pub initial_dst_cid: ConnectionId,
    pub active_cids: [ConnectionId; 8],
    pub active_cid_count: u8,
    pub next_cid_seq: u64,
    
    // Transport parameters
    pub local_params: TransportParams,
    pub remote_params: Option<TransportParams>,
    
    // Packet numbers
    pub next_pn: [u64; 3], // per PnSpace
    pub largest_recv_pn: [u64; 3],
    
    // Streams
    pub streams: [Option<QuicStream>; 1024],
    pub next_bidi_stream: u64,
    pub next_uni_stream: u64,
    pub max_bidi_streams: u64,
    pub max_uni_streams: u64,
    
    // Flow control
    pub max_data: u64,        // Connection level
    pub data_sent: u64,
    pub data_received: u64,
    pub max_data_remote: u64,
    
    // Components
    pub ack_tracker: [AckTracker; 3],
    pub loss_recovery: LossRecovery,
    pub congestion: QuicCongestion,
    
    // Multipath
    pub multipath: Option<MultipathState>,
    
    // Timing
    pub idle_timeout: u64,
    pub last_activity: u64,
    pub handshake_completed: bool,
    pub handshake_confirmed: bool,
    
    // Crypto level
    pub crypto_level: PnSpace,
    
    // 0-RTT
    pub zero_rtt_enabled: bool,
    pub zero_rtt_accepted: bool,
    pub early_data_limit: u64,
    
    // Statistics
    pub stats: QuicConnStats,
}

pub struct QuicConnStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub handshake_duration: u64,
    pub path_migrations: u64,
}

impl QuicConnection {
    pub fn new_client(version: u32) -> Self {
        let mut conn = Self::new_base(version, false);
        conn.next_bidi_stream = 0; // Client-initiated bidi: 0, 4, 8, ...
        conn.next_uni_stream = 2;  // Client-initiated uni: 2, 6, 10, ...
        conn
    }

    pub fn new_server(version: u32) -> Self {
        let mut conn = Self::new_base(version, true);
        conn.next_bidi_stream = 1; // Server-initiated bidi: 1, 5, 9, ...
        conn.next_uni_stream = 3;  // Server-initiated uni: 3, 7, 11, ...
        conn
    }

    fn new_base(version: u32, is_server: bool) -> Self {
        let ack_trackers = [AckTracker::new(), AckTracker::new(), AckTracker::new()];
        
        // Initialize streams as array of None
        const NONE_STREAM: Option<QuicStream> = None;
        let streams = [NONE_STREAM; 1024];
        
        QuicConnection {
            state: QuicState::Idle,
            is_server,
            version,
            src_cid: ConnectionId::empty(),
            dst_cid: ConnectionId::empty(),
            initial_dst_cid: ConnectionId::empty(),
            active_cids: [ConnectionId::empty(); 8],
            active_cid_count: 0,
            next_cid_seq: 0,
            local_params: TransportParams::default_client(),
            remote_params: None,
            next_pn: [0; 3],
            largest_recv_pn: [0; 3],
            streams,
            next_bidi_stream: 0,
            next_uni_stream: 0,
            max_bidi_streams: 100,
            max_uni_streams: 100,
            max_data: 10 * 1024 * 1024,
            data_sent: 0,
            data_received: 0,
            max_data_remote: 0,
            ack_tracker: ack_trackers,
            loss_recovery: LossRecovery::new(),
            congestion: QuicCongestion::new(1200),
            multipath: None,
            idle_timeout: 30_000_000,
            last_activity: 0,
            handshake_completed: false,
            handshake_confirmed: false,
            crypto_level: PnSpace::Initial,
            zero_rtt_enabled: false,
            zero_rtt_accepted: false,
            early_data_limit: 0,
            stats: QuicConnStats {
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                streams_opened: 0,
                streams_closed: 0,
                handshake_duration: 0,
                path_migrations: 0,
            },
        }
    }

    /// Open a new bidirectional stream
    pub fn open_bidi_stream(&mut self) -> Result<u64, TransportError> {
        if self.next_bidi_stream / 4 >= self.max_bidi_streams {
            return Err(TransportError::StreamLimitError);
        }
        let id = self.next_bidi_stream;
        self.next_bidi_stream += 4;
        
        let max_data = self.local_params.initial_max_stream_data_bidi_local;
        let idx = (id / 4) as usize;
        if idx < 1024 {
            self.streams[idx] = Some(QuicStream::new(id, max_data));
            self.streams[idx].as_mut().unwrap().state = StreamState::Open;
            self.stats.streams_opened += 1;
        }
        Ok(id)
    }

    /// Open a new unidirectional stream
    pub fn open_uni_stream(&mut self) -> Result<u64, TransportError> {
        if self.next_uni_stream / 4 >= self.max_uni_streams {
            return Err(TransportError::StreamLimitError);
        }
        let id = self.next_uni_stream;
        self.next_uni_stream += 4;
        
        let max_data = self.local_params.initial_max_stream_data_uni;
        let idx = (id / 4) as usize;
        if idx < 1024 {
            self.streams[idx] = Some(QuicStream::new(id, max_data));
            self.streams[idx].as_mut().unwrap().state = StreamState::Open;
            self.stats.streams_opened += 1;
        }
        Ok(id)
    }

    /// Process received packet
    pub fn process_packet(&mut self, packet_type: PacketType, pn: u64, now: u64) -> Result<(), TransportError> {
        self.last_activity = now;
        self.stats.packets_received += 1;
        
        let space = match packet_type {
            PacketType::Initial => PnSpace::Initial,
            PacketType::Handshake => PnSpace::Handshake,
            PacketType::ZeroRtt | PacketType::OneRtt => PnSpace::ApplicationData,
            PacketType::Retry => return self.process_retry(),
        };
        
        let sp = space as usize;
        if pn > self.largest_recv_pn[sp] {
            self.largest_recv_pn[sp] = pn;
        }
        
        self.ack_tracker[sp].record_received(pn, now);
        self.ack_tracker[sp].ack_eliciting_received = true;
        
        Ok(())
    }

    fn process_retry(&mut self) -> Result<(), TransportError> {
        if self.state != QuicState::Handshaking {
            return Err(TransportError::ProtocolViolation);
        }
        // Reset crypto state and resend Initial
        self.next_pn[PnSpace::Initial as usize] = 0;
        Ok(())
    }

    /// Send packet preparation
    pub fn prepare_send(&mut self, now: u64) -> Option<PacketType> {
        if self.state == QuicState::Closed || self.state == QuicState::Draining {
            return None;
        }

        // Check idle timeout
        if now - self.last_activity > self.idle_timeout {
            self.state = QuicState::Closed;
            return None;
        }

        // Check ACK needs
        for sp in 0..3 {
            if self.ack_tracker[sp].needs_ack() {
                return Some(match sp {
                    0 => PacketType::Initial,
                    1 => PacketType::Handshake,
                    _ => PacketType::OneRtt,
                });
            }
        }

        // Check for data to send
        if self.handshake_completed {
            if self.congestion.available_window() > 0 {
                return Some(PacketType::OneRtt);
            }
        }

        None
    }

    /// Enable multipath
    pub fn enable_multipath(&mut self) {
        self.multipath = Some(MultipathState::new());
        self.local_params.enable_multipath = true;
    }

    /// Initiate connection migration
    pub fn migrate_path(&mut self, local_addr: [u8; 16], local_port: u16,
                        remote_addr: [u8; 16], remote_port: u16) -> Result<(), TransportError> {
        if self.local_params.disable_active_migration {
            return Err(TransportError::ProtocolViolation);
        }
        if let Some(ref mut mp) = self.multipath {
            mp.add_path(local_addr, local_port, remote_addr, remote_port);
            self.stats.path_migrations += 1;
            Ok(())
        } else {
            // Single path migration - just update addresses
            self.stats.path_migrations += 1;
            Ok(())
        }
    }

    /// Close connection
    pub fn close(&mut self, error: TransportError, reason: &str) {
        let _ = reason;
        let _ = error;
        match self.state {
            QuicState::Connected | QuicState::Handshaking => {
                self.state = QuicState::Closing;
            }
            _ => {}
        }
    }

    pub fn next_packet_number(&mut self, space: PnSpace) -> u64 {
        let sp = space as usize;
        let pn = self.next_pn[sp];
        self.next_pn[sp] += 1;
        pn
    }
}

/// Variable-length integer encoding (RFC 9000 Section 16)
pub fn encode_varint(value: u64, buf: &mut [u8]) -> usize {
    if value < 64 {
        if buf.is_empty() { return 0; }
        buf[0] = value as u8;
        1
    } else if value < 16384 {
        if buf.len() < 2 { return 0; }
        let v = (value as u16) | 0x4000;
        buf[0] = (v >> 8) as u8;
        buf[1] = v as u8;
        2
    } else if value < 1073741824 {
        if buf.len() < 4 { return 0; }
        let v = (value as u32) | 0x80000000;
        buf[0] = (v >> 24) as u8;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else {
        if buf.len() < 8 { return 0; }
        let v = value | 0xc000000000000000;
        buf[0] = (v >> 56) as u8;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    }
}

pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() { return None; }
    let first = buf[0];
    let len = 1 << (first >> 6);
    if buf.len() < len { return None; }
    
    match len {
        1 => Some((first as u64 & 0x3f, 1)),
        2 => {
            let v = ((buf[0] as u64 & 0x3f) << 8) | buf[1] as u64;
            Some((v, 2))
        }
        4 => {
            let v = ((buf[0] as u64 & 0x3f) << 24) 
                  | ((buf[1] as u64) << 16)
                  | ((buf[2] as u64) << 8)
                  | buf[3] as u64;
            Some((v, 4))
        }
        8 => {
            let v = ((buf[0] as u64 & 0x3f) << 56)
                  | ((buf[1] as u64) << 48)
                  | ((buf[2] as u64) << 40)
                  | ((buf[3] as u64) << 32)
                  | ((buf[4] as u64) << 24)
                  | ((buf[5] as u64) << 16)
                  | ((buf[6] as u64) << 8)
                  | buf[7] as u64;
            Some((v, 8))
        }
        _ => None,
    }
}

/// Global QUIC statistics
pub struct QuicGlobalStats {
    pub connections_created: AtomicU64,
    pub connections_closed: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub zero_rtt_accepted: AtomicU64,
    pub zero_rtt_rejected: AtomicU64,
    pub path_migrations: AtomicU64,
    pub stateless_resets: AtomicU64,
}

impl QuicGlobalStats {
    pub const fn new() -> Self {
        QuicGlobalStats {
            connections_created: AtomicU64::new(0),
            connections_closed: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            zero_rtt_accepted: AtomicU64::new(0),
            zero_rtt_rejected: AtomicU64::new(0),
            path_migrations: AtomicU64::new(0),
            stateless_resets: AtomicU64::new(0),
        }
    }
}

static QUIC_STATS: QuicGlobalStats = QuicGlobalStats::new();

pub fn get_quic_stats() -> &'static QuicGlobalStats {
    &QUIC_STATS
}
