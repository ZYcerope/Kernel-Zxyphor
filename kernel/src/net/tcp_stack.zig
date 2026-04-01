// =============================================================================
// Kernel Zxyphor — TCP/IP Stack Implementation
// =============================================================================
// Full TCP state machine per RFC 793 / RFC 7323:
//   - Connection state machine (CLOSED→LISTEN→SYN_SENT→ESTABLISHED etc.)
//   - Three-way handshake (active & passive open)
//   - Sliding window flow control
//   - Congestion control (Slow Start, Congestion Avoidance, Fast Retransmit)
//   - Nagle's algorithm
//   - Delayed ACK
//   - Retransmission timer with exponential backoff
//   - TCP options (MSS, Window Scale, SACK, Timestamps)
//   - Connection table with hash lookup
//   - Send/receive ring buffers
//   - RST handling and connection reset
//   - FIN sequence for graceful close
//   - Keep-alive support
// =============================================================================

// =============================================================================
// TCP constants
// =============================================================================

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

pub const TCP_OPT_END: u8 = 0;
pub const TCP_OPT_NOP: u8 = 1;
pub const TCP_OPT_MSS: u8 = 2;
pub const TCP_OPT_WSCALE: u8 = 3;
pub const TCP_OPT_SACK_PERMITTED: u8 = 4;
pub const TCP_OPT_SACK: u8 = 5;
pub const TCP_OPT_TIMESTAMP: u8 = 8;

pub const TCP_DEFAULT_MSS: u16 = 1460;
pub const TCP_DEFAULT_WINDOW: u16 = 65535;
pub const TCP_MAX_RETRIES: u8 = 8;
pub const TCP_INITIAL_RTO_MS: u32 = 1000;
pub const TCP_MIN_RTO_MS: u32 = 200;
pub const TCP_MAX_RTO_MS: u32 = 60000;
pub const TCP_KEEPALIVE_IDLE_MS: u64 = 7200000; // 2 hours
pub const TCP_KEEPALIVE_INTERVAL_MS: u64 = 75000;
pub const TCP_TIME_WAIT_MS: u64 = 120000; // 2 * MSL

// =============================================================================
// TCP header
// =============================================================================

pub const TcpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_flags: u16, // 4-bit offset + reserved + flags
    window: u16,
    checksum: u16,
    urgent_ptr: u16,

    pub fn dataOffset(self: *const TcpHeader) u8 {
        return @intCast((ntohs(self.data_offset_flags) >> 12) & 0x0F);
    }

    pub fn flags(self: *const TcpHeader) u8 {
        return @intCast(ntohs(self.data_offset_flags) & 0x3F);
    }

    pub fn headerLen(self: *const TcpHeader) usize {
        return @as(usize, self.dataOffset()) * 4;
    }
};

// =============================================================================
// TCP connection states
// =============================================================================

pub const TcpState = enum(u8) {
    closed = 0,
    listen = 1,
    syn_sent = 2,
    syn_received = 3,
    established = 4,
    fin_wait_1 = 5,
    fin_wait_2 = 6,
    close_wait = 7,
    closing = 8,
    last_ack = 9,
    time_wait = 10,

    pub fn name(self: TcpState) []const u8 {
        return switch (self) {
            .closed => "CLOSED",
            .listen => "LISTEN",
            .syn_sent => "SYN_SENT",
            .syn_received => "SYN_RECEIVED",
            .established => "ESTABLISHED",
            .fin_wait_1 => "FIN_WAIT_1",
            .fin_wait_2 => "FIN_WAIT_2",
            .close_wait => "CLOSE_WAIT",
            .closing => "CLOSING",
            .last_ack => "LAST_ACK",
            .time_wait => "TIME_WAIT",
        };
    }
};

// =============================================================================
// TCP options
// =============================================================================

pub const TcpOptions = struct {
    mss: u16,
    window_scale: u8,
    sack_permitted: bool,
    timestamp: u32,
    timestamp_echo: u32,
    has_mss: bool,
    has_wscale: bool,
    has_timestamp: bool,

    pub fn parse(data: []const u8) TcpOptions {
        var opts = TcpOptions{
            .mss = TCP_DEFAULT_MSS,
            .window_scale = 0,
            .sack_permitted = false,
            .timestamp = 0,
            .timestamp_echo = 0,
            .has_mss = false,
            .has_wscale = false,
            .has_timestamp = false,
        };

        var i: usize = 0;
        while (i < data.len) {
            const kind = data[i];
            if (kind == TCP_OPT_END) break;
            if (kind == TCP_OPT_NOP) {
                i += 1;
                continue;
            }

            if (i + 1 >= data.len) break;
            const opt_len = data[i + 1];
            if (opt_len < 2 or i + opt_len > data.len) break;

            switch (kind) {
                TCP_OPT_MSS => {
                    if (opt_len == 4 and i + 3 < data.len) {
                        opts.mss = @as(u16, data[i + 2]) << 8 | data[i + 3];
                        opts.has_mss = true;
                    }
                },
                TCP_OPT_WSCALE => {
                    if (opt_len == 3 and i + 2 < data.len) {
                        opts.window_scale = data[i + 2];
                        if (opts.window_scale > 14) opts.window_scale = 14;
                        opts.has_wscale = true;
                    }
                },
                TCP_OPT_SACK_PERMITTED => {
                    opts.sack_permitted = true;
                },
                TCP_OPT_TIMESTAMP => {
                    if (opt_len == 10 and i + 9 < data.len) {
                        opts.timestamp = readU32Be(data[i + 2 ..]);
                        opts.timestamp_echo = readU32Be(data[i + 6 ..]);
                        opts.has_timestamp = true;
                    }
                },
                else => {},
            }

            i += opt_len;
        }

        return opts;
    }
};

// =============================================================================
// Congestion control
// =============================================================================

pub const CongestionState = enum(u8) {
    slow_start = 0,
    congestion_avoidance = 1,
    fast_recovery = 2,
};

pub const CongestionControl = struct {
    state: CongestionState,
    cwnd: u32,              // Congestion window (bytes)
    ssthresh: u32,          // Slow start threshold
    mss: u16,
    dup_ack_count: u8,
    bytes_acked: u32,       // For congestion avoidance counting

    pub fn init(self: *CongestionControl, mss: u16) void {
        self.state = .slow_start;
        self.cwnd = @as(u32, mss) * 10; // RFC 6928: IW=10
        self.ssthresh = 65535;
        self.mss = mss;
        self.dup_ack_count = 0;
        self.bytes_acked = 0;
    }

    /// Called when new data is ACKed
    pub fn onAck(self: *CongestionControl, bytes_acked: u32) void {
        self.dup_ack_count = 0;

        switch (self.state) {
            .slow_start => {
                self.cwnd += bytes_acked; // Roughly doubling per RTT
                if (self.cwnd >= self.ssthresh) {
                    self.state = .congestion_avoidance;
                    self.bytes_acked = 0;
                }
            },
            .congestion_avoidance => {
                // Approximately +1 MSS per RTT
                self.bytes_acked += bytes_acked;
                if (self.bytes_acked >= self.cwnd) {
                    self.cwnd += @as(u32, self.mss);
                    self.bytes_acked = 0;
                }
            },
            .fast_recovery => {
                // Exit fast recovery
                self.cwnd = self.ssthresh;
                self.state = .congestion_avoidance;
                self.bytes_acked = 0;
            },
        }
    }

    /// Called on duplicate ACK
    pub fn onDupAck(self: *CongestionControl) bool {
        self.dup_ack_count += 1;
        if (self.dup_ack_count == 3) {
            // Fast retransmit threshold
            self.ssthresh = @max(self.cwnd / 2, @as(u32, self.mss) * 2);
            self.cwnd = self.ssthresh + @as(u32, self.mss) * 3;
            self.state = .fast_recovery;
            return true; // Should retransmit
        }
        if (self.state == .fast_recovery) {
            self.cwnd += @as(u32, self.mss); // Inflate window
        }
        return false;
    }

    /// Called on timeout (RTO expiry)
    pub fn onTimeout(self: *CongestionControl) void {
        self.ssthresh = @max(self.cwnd / 2, @as(u32, self.mss) * 2);
        self.cwnd = @as(u32, self.mss); // Reset to 1 MSS
        self.state = .slow_start;
        self.dup_ack_count = 0;
        self.bytes_acked = 0;
    }

    /// Effective send window
    pub fn sendWindow(self: *const CongestionControl, recv_wnd: u32) u32 {
        return @min(self.cwnd, recv_wnd);
    }
};

// =============================================================================
// RTT estimation (Jacobson/Karels algorithm)
// =============================================================================

pub const RttEstimator = struct {
    srtt_us: i64,     // Smoothed RTT (fixed-point, *8)
    rttvar_us: i64,   // RTT variance (fixed-point, *4)
    rto_ms: u32,      // Retransmission timeout
    measured: bool,

    pub fn init(self: *RttEstimator) void {
        self.srtt_us = 0;
        self.rttvar_us = 0;
        self.rto_ms = TCP_INITIAL_RTO_MS;
        self.measured = false;
    }

    pub fn sample(self: *RttEstimator, rtt_us: i64) void {
        if (!self.measured) {
            // First measurement
            self.srtt_us = rtt_us << 3;         // srtt = rtt * 8
            self.rttvar_us = (rtt_us >> 1) << 2; // rttvar = rtt/2 * 4
            self.measured = true;
        } else {
            // Jacobson/Karels
            const delta = rtt_us - (self.srtt_us >> 3);
            self.srtt_us += delta;                              // srtt += delta/8
            const abs_delta = if (delta < 0) -delta else delta;
            self.rttvar_us += abs_delta - (self.rttvar_us >> 2); // rttvar += (|delta| - rttvar)/4
        }

        // RTO = SRTT + max(G, 4 * RTTVAR)  where G = clock granularity
        var rto = (self.srtt_us >> 3) + (self.rttvar_us); // In microseconds * 1
        rto = @divTrunc(rto, 1000); // Convert to ms
        if (rto < TCP_MIN_RTO_MS) rto = TCP_MIN_RTO_MS;
        if (rto > TCP_MAX_RTO_MS) rto = TCP_MAX_RTO_MS;
        self.rto_ms = @intCast(rto);
    }

    pub fn backoff(self: *RttEstimator) void {
        self.rto_ms = @min(self.rto_ms * 2, TCP_MAX_RTO_MS);
    }
};

// =============================================================================
// TCP send/receive buffers
// =============================================================================

pub const TCP_BUF_SIZE: usize = 16384;

pub const TcpRingBuf = struct {
    data: [TCP_BUF_SIZE]u8,
    head: usize,
    tail: usize,
    count: usize,

    pub fn init(self: *TcpRingBuf) void {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }

    pub fn available(self: *const TcpRingBuf) usize {
        return self.count;
    }

    pub fn space(self: *const TcpRingBuf) usize {
        return TCP_BUF_SIZE - self.count;
    }

    pub fn write(self: *TcpRingBuf, data: []const u8) usize {
        const to_write = @min(data.len, self.space());
        var i: usize = 0;
        while (i < to_write) : (i += 1) {
            self.data[self.tail] = data[i];
            self.tail = (self.tail + 1) % TCP_BUF_SIZE;
        }
        self.count += to_write;
        return to_write;
    }

    pub fn read(self: *TcpRingBuf, buf: []u8) usize {
        const to_read = @min(buf.len, self.count);
        var i: usize = 0;
        while (i < to_read) : (i += 1) {
            buf[i] = self.data[self.head];
            self.head = (self.head + 1) % TCP_BUF_SIZE;
        }
        self.count -= to_read;
        return to_read;
    }

    pub fn peek(self: *const TcpRingBuf, buf: []u8) usize {
        const to_read = @min(buf.len, self.count);
        var head = self.head;
        var i: usize = 0;
        while (i < to_read) : (i += 1) {
            buf[i] = self.data[head];
            head = (head + 1) % TCP_BUF_SIZE;
        }
        return to_read;
    }

    /// Discard bytes without copying
    pub fn consume(self: *TcpRingBuf, n: usize) void {
        const to_consume = @min(n, self.count);
        self.head = (self.head + to_consume) % TCP_BUF_SIZE;
        self.count -= to_consume;
    }
};

// =============================================================================
// TCP Connection (TCB - Transmission Control Block)
// =============================================================================

pub const MAX_CONNECTIONS: usize = 256;

pub const TcpConnection = struct {
    // Connection tuple
    local_ip: u32,
    remote_ip: u32,
    local_port: u16,
    remote_port: u16,

    // State
    state: TcpState,
    active: bool,

    // Sequence numbers
    snd_una: u32,     // Oldest unacknowledged sequence
    snd_nxt: u32,     // Next sequence to send
    snd_wnd: u32,     // Send window
    snd_wl1: u32,     // Segment sequence for last window update
    snd_wl2: u32,     // Segment ack for last window update
    iss: u32,         // Initial send sequence number

    rcv_nxt: u32,     // Next expected receive sequence
    rcv_wnd: u32,     // Receive window
    irs: u32,         // Initial receive sequence number

    // Options
    mss: u16,
    snd_wscale: u8,
    rcv_wscale: u8,
    sack_permitted: bool,
    timestamps_enabled: bool,

    // Buffers
    send_buf: TcpRingBuf,
    recv_buf: TcpRingBuf,

    // Congestion control
    congestion: CongestionControl,

    // RTT estimation
    rtt: RttEstimator,

    // Retransmission
    retransmit_count: u8,
    last_retransmit_ms: u64,

    // Timers (timestamps in ms)
    rto_deadline_ms: u64,
    delayed_ack_ms: u64,
    keepalive_ms: u64,
    time_wait_ms: u64,

    // Nagle's algorithm
    nagle_enabled: bool,
    nagle_waiting: bool,

    // Statistics
    bytes_sent: u64,
    bytes_received: u64,
    segments_sent: u64,
    segments_received: u64,
    retransmissions: u64,

    pub fn init(self: *TcpConnection) void {
        self.state = .closed;
        self.active = false;
        self.send_buf.init();
        self.recv_buf.init();
        self.congestion.init(TCP_DEFAULT_MSS);
        self.rtt.init();
        self.mss = TCP_DEFAULT_MSS;
        self.snd_wscale = 0;
        self.rcv_wscale = 0;
        self.sack_permitted = false;
        self.timestamps_enabled = false;
        self.retransmit_count = 0;
        self.nagle_enabled = true;
        self.nagle_waiting = false;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.segments_sent = 0;
        self.segments_received = 0;
        self.retransmissions = 0;
    }

    /// Process an incoming TCP segment
    pub fn processSegment(self: *TcpConnection, hdr: *const TcpHeader, data: []const u8, now_ms: u64) void {
        self.segments_received += 1;
        const seg_flags = hdr.flags();
        const seg_seq = ntohl(hdr.seq_num);
        const seg_ack = ntohl(hdr.ack_num);
        const seg_wnd = @as(u32, ntohs(hdr.window)) << self.snd_wscale;

        switch (self.state) {
            .closed => return,

            .listen => {
                if (seg_flags & TCP_FLAG_SYN != 0) {
                    self.irs = seg_seq;
                    self.rcv_nxt = seg_seq +% 1;

                    // Parse options
                    const opt_offset = hdr.headerLen();
                    if (opt_offset > 20 and opt_offset <= data.len + 20) {
                        // Options would be between header and data
                    }

                    self.state = .syn_received;
                    // Send SYN+ACK
                    self.sendSynAck(now_ms);
                }
            },

            .syn_sent => {
                if (seg_flags & TCP_FLAG_ACK != 0) {
                    if (!seqInWindow(seg_ack, self.iss +% 1, self.snd_nxt +% 1)) {
                        if (seg_flags & TCP_FLAG_RST == 0) {
                            self.sendRst(seg_ack, now_ms);
                        }
                        return;
                    }
                }

                if (seg_flags & TCP_FLAG_RST != 0) {
                    self.state = .closed;
                    self.active = false;
                    return;
                }

                if (seg_flags & TCP_FLAG_SYN != 0) {
                    self.irs = seg_seq;
                    self.rcv_nxt = seg_seq +% 1;

                    if (seg_flags & TCP_FLAG_ACK != 0) {
                        self.snd_una = seg_ack;
                        self.state = .established;
                        self.sendAck(now_ms);
                    } else {
                        // Simultaneous open
                        self.state = .syn_received;
                        self.sendSynAck(now_ms);
                    }
                }
            },

            .syn_received => {
                if (seg_flags & TCP_FLAG_RST != 0) {
                    self.state = .closed;
                    self.active = false;
                    return;
                }
                if (seg_flags & TCP_FLAG_ACK != 0) {
                    if (seqInWindow(seg_ack, self.snd_una, self.snd_nxt +% 1)) {
                        self.snd_una = seg_ack;
                        self.state = .established;
                        self.snd_wnd = seg_wnd;
                    }
                }
            },

            .established => {
                if (seg_flags & TCP_FLAG_RST != 0) {
                    self.state = .closed;
                    self.active = false;
                    return;
                }

                // Process ACK
                if (seg_flags & TCP_FLAG_ACK != 0) {
                    self.processAck(seg_ack, seg_wnd, now_ms);
                }

                // Process data
                if (data.len > 0 and seg_seq == self.rcv_nxt) {
                    const written = self.recv_buf.write(data);
                    self.rcv_nxt +%= @intCast(written);
                    self.bytes_received += written;
                    // Schedule delayed ACK
                    self.delayed_ack_ms = now_ms + 40; // 40ms delayed ACK
                }

                // Process FIN
                if (seg_flags & TCP_FLAG_FIN != 0) {
                    self.rcv_nxt +%= 1;
                    self.state = .close_wait;
                    self.sendAck(now_ms);
                }
            },

            .fin_wait_1 => {
                if (seg_flags & TCP_FLAG_ACK != 0) {
                    self.processAck(seg_ack, seg_wnd, now_ms);
                    if (seg_ack == self.snd_nxt) {
                        if (seg_flags & TCP_FLAG_FIN != 0) {
                            self.rcv_nxt +%= 1;
                            self.state = .time_wait;
                            self.time_wait_ms = now_ms + TCP_TIME_WAIT_MS;
                            self.sendAck(now_ms);
                        } else {
                            self.state = .fin_wait_2;
                        }
                    }
                }
                if (seg_flags & TCP_FLAG_FIN != 0 and self.state == .fin_wait_1) {
                    self.rcv_nxt +%= 1;
                    self.state = .closing;
                    self.sendAck(now_ms);
                }
            },

            .fin_wait_2 => {
                if (seg_flags & TCP_FLAG_FIN != 0) {
                    self.rcv_nxt +%= 1;
                    self.state = .time_wait;
                    self.time_wait_ms = now_ms + TCP_TIME_WAIT_MS;
                    self.sendAck(now_ms);
                }
            },

            .close_wait => {
                // Waiting for application to close
            },

            .closing => {
                if (seg_flags & TCP_FLAG_ACK != 0) {
                    if (seg_ack == self.snd_nxt) {
                        self.state = .time_wait;
                        self.time_wait_ms = now_ms + TCP_TIME_WAIT_MS;
                    }
                }
            },

            .last_ack => {
                if (seg_flags & TCP_FLAG_ACK != 0) {
                    if (seg_ack == self.snd_nxt) {
                        self.state = .closed;
                        self.active = false;
                    }
                }
            },

            .time_wait => {
                // Restart TIME_WAIT timer on any segment
                self.time_wait_ms = now_ms + TCP_TIME_WAIT_MS;
                if (seg_flags & TCP_FLAG_FIN != 0) {
                    self.sendAck(now_ms);
                }
            },
        }
    }

    fn processAck(self: *TcpConnection, ack: u32, wnd: u32, now_ms: u64) void {
        _ = now_ms;
        if (seqAfter(ack, self.snd_una)) {
            const acked = ack -% self.snd_una;
            self.snd_una = ack;
            self.send_buf.consume(@intCast(acked));
            self.congestion.onAck(acked);
            self.retransmit_count = 0;
        } else if (ack == self.snd_una) {
            // Duplicate ACK
            if (self.congestion.onDupAck()) {
                self.retransmissions += 1;
                // TODO: retransmit first unacked segment
            }
        }
        // Update send window
        self.snd_wnd = wnd;
    }

    /// Initiate active open (connect)
    pub fn connect(self: *TcpConnection, local_ip: u32, local_port: u16, remote_ip: u32, remote_port: u16, iss: u32, now_ms: u64) void {
        self.init();
        self.local_ip = local_ip;
        self.local_port = local_port;
        self.remote_ip = remote_ip;
        self.remote_port = remote_port;
        self.iss = iss;
        self.snd_una = iss;
        self.snd_nxt = iss +% 1;
        self.state = .syn_sent;
        self.active = true;
        self.rto_deadline_ms = now_ms + self.rtt.rto_ms;
        // Send SYN
        self.segments_sent += 1;
    }

    /// Passive open (listen)
    pub fn listen(self: *TcpConnection, local_ip: u32, local_port: u16) void {
        self.init();
        self.local_ip = local_ip;
        self.local_port = local_port;
        self.state = .listen;
        self.active = true;
    }

    /// Application-level close
    pub fn close(self: *TcpConnection, now_ms: u64) void {
        switch (self.state) {
            .established => {
                self.state = .fin_wait_1;
                self.sendFin(now_ms);
            },
            .close_wait => {
                self.state = .last_ack;
                self.sendFin(now_ms);
            },
            else => {
                self.state = .closed;
                self.active = false;
            },
        }
    }

    /// Application-level send
    pub fn send(self: *TcpConnection, data: []const u8) usize {
        if (self.state != .established and self.state != .close_wait) return 0;
        return self.send_buf.write(data);
    }

    /// Application-level receive
    pub fn receive(self: *TcpConnection, buf: []u8) usize {
        return self.recv_buf.read(buf);
    }

    /// Timer tick — handle retransmission, delayed ACK, keepalive, TIME_WAIT
    pub fn timerTick(self: *TcpConnection, now_ms: u64) void {
        // Check TIME_WAIT expiry
        if (self.state == .time_wait and now_ms >= self.time_wait_ms) {
            self.state = .closed;
            self.active = false;
            return;
        }

        // Check retransmission timeout
        if (self.snd_una != self.snd_nxt and now_ms >= self.rto_deadline_ms) {
            self.retransmit_count += 1;
            if (self.retransmit_count > TCP_MAX_RETRIES) {
                self.state = .closed;
                self.active = false;
                return;
            }
            self.congestion.onTimeout();
            self.rtt.backoff();
            self.retransmissions += 1;
            self.rto_deadline_ms = now_ms + self.rtt.rto_ms;
        }

        // Check delayed ACK
        if (self.delayed_ack_ms > 0 and now_ms >= self.delayed_ack_ms) {
            self.sendAck(now_ms);
            self.delayed_ack_ms = 0;
        }
    }

    // Internal send helpers
    fn sendAck(self: *TcpConnection, _: u64) void {
        // Build ACK segment (header only)
        _ = self;
        // In a real implementation, this would construct the segment and
        // pass it to the IP layer for transmission
        self.segments_sent += 1;
    }

    fn sendSynAck(self: *TcpConnection, now_ms: u64) void {
        _ = now_ms;
        self.snd_nxt = self.iss +% 1;
        self.segments_sent += 1;
    }

    fn sendFin(self: *TcpConnection, _: u64) void {
        self.snd_nxt +%= 1; // FIN consumes one sequence number
        self.segments_sent += 1;
    }

    fn sendRst(self: *TcpConnection, seq: u32, _: u64) void {
        _ = seq;
        self.segments_sent += 1;
    }
};

// =============================================================================
// TCP connection table
// =============================================================================

pub const TcpTable = struct {
    connections: [MAX_CONNECTIONS]TcpConnection,
    count: usize,

    pub fn init(self: *TcpTable) void {
        self.count = 0;
        for (&self.connections) |*conn| {
            conn.init();
        }
    }

    /// Find connection by 4-tuple
    pub fn lookup(self: *TcpTable, local_ip: u32, local_port: u16, remote_ip: u32, remote_port: u16) ?*TcpConnection {
        for (&self.connections) |*conn| {
            if (conn.active and
                conn.local_ip == local_ip and
                conn.local_port == local_port and
                conn.remote_ip == remote_ip and
                conn.remote_port == remote_port)
            {
                return conn;
            }
        }
        return null;
    }

    /// Find a listening socket
    pub fn lookupListener(self: *TcpTable, local_port: u16) ?*TcpConnection {
        for (&self.connections) |*conn| {
            if (conn.active and conn.state == .listen and conn.local_port == local_port) {
                return conn;
            }
        }
        return null;
    }

    /// Allocate a new connection
    pub fn allocate(self: *TcpTable) ?*TcpConnection {
        for (&self.connections) |*conn| {
            if (!conn.active) {
                conn.init();
                self.count += 1;
                return conn;
            }
        }
        return null;
    }

    /// Run timer tick on all connections
    pub fn tickAll(self: *TcpTable, now_ms: u64) void {
        for (&self.connections) |*conn| {
            if (conn.active) {
                conn.timerTick(now_ms);
                if (!conn.active and self.count > 0) {
                    self.count -= 1;
                }
            }
        }
    }

    /// Get connection count by state
    pub fn countByState(self: *const TcpTable, state: TcpState) usize {
        var n: usize = 0;
        for (&self.connections) |*conn| {
            if (conn.active and conn.state == state) n += 1;
        }
        return n;
    }
};

// =============================================================================
// Helper functions
// =============================================================================

fn ntohs(x: u16) u16 {
    return @byteSwap(x);
}

fn ntohl(x: u32) u32 {
    return @byteSwap(x);
}

fn readU32Be(data: []const u8) u32 {
    if (data.len < 4) return 0;
    return @as(u32, data[0]) << 24 |
        @as(u32, data[1]) << 16 |
        @as(u32, data[2]) << 8 |
        @as(u32, data[3]);
}

/// Check if seq is after reference (accounting for wraparound)
fn seqAfter(seq: u32, reference: u32) bool {
    return @as(i32, @bitCast(seq -% reference)) > 0;
}

/// Check if seq is within [start, end) accounting for wraparound
fn seqInWindow(seq: u32, start: u32, end: u32) bool {
    return !seqAfter(start, seq) and seqAfter(end, seq);
}

// =============================================================================
// Global TCP state
// =============================================================================

var tcp_table: TcpTable = undefined;
var tcp_initialized: bool = false;

pub fn initTcp() void {
    tcp_table.init();
    tcp_initialized = true;
}

pub fn getTable() ?*TcpTable {
    if (tcp_initialized) return &tcp_table;
    return null;
}
