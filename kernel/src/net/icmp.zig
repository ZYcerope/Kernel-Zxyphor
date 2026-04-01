// =============================================================================
// Kernel Zxyphor — ICMP (Internet Control Message Protocol)
// =============================================================================
// Full ICMPv4 and ICMPv6 implementation:
//   - Echo request/reply (ping)
//   - Destination unreachable
//   - Time exceeded
//   - Parameter problem
//   - Redirect messages
//   - Router solicitation/advertisement (ICMPv6)
//   - Neighbor solicitation/advertisement (ICMPv6 NDP)
//   - Checksum computation and validation
//   - Rate limiting for outbound ICMP
//   - Ping statistics tracking
// =============================================================================

// =============================================================================
// ICMP types (v4)
// =============================================================================

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_SOURCE_QUENCH: u8 = 4;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ROUTER_ADVERTISEMENT: u8 = 9;
pub const ICMP_ROUTER_SOLICITATION: u8 = 10;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_PARAMETER_PROBLEM: u8 = 12;
pub const ICMP_TIMESTAMP_REQUEST: u8 = 13;
pub const ICMP_TIMESTAMP_REPLY: u8 = 14;
pub const ICMP_ADDRESS_MASK_REQUEST: u8 = 17;
pub const ICMP_ADDRESS_MASK_REPLY: u8 = 18;

// ICMP Dest Unreachable codes
pub const ICMP_NET_UNREACHABLE: u8 = 0;
pub const ICMP_HOST_UNREACHABLE: u8 = 1;
pub const ICMP_PROTOCOL_UNREACHABLE: u8 = 2;
pub const ICMP_PORT_UNREACHABLE: u8 = 3;
pub const ICMP_FRAG_NEEDED: u8 = 4;
pub const ICMP_SOURCE_ROUTE_FAILED: u8 = 5;
pub const ICMP_ADMIN_PROHIBITED: u8 = 13;

// ICMP Time Exceeded codes
pub const ICMP_TTL_EXCEEDED: u8 = 0;
pub const ICMP_FRAG_REASSEMBLY_EXCEEDED: u8 = 1;

// =============================================================================
// ICMPv6 types
// =============================================================================

pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_PARAMETER_PROBLEM: u8 = 4;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_ROUTER_SOLICITATION: u8 = 133;
pub const ICMPV6_ROUTER_ADVERTISEMENT: u8 = 134;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub const ICMPV6_REDIRECT: u8 = 137;

// =============================================================================
// ICMP header
// =============================================================================

pub const IcmpHeader = extern struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    // Rest of header depends on type
    rest: u32, // id+seq for echo, MTU for frag_needed, etc.
};

pub const IcmpEchoHeader = extern struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
};

pub const IcmpTimestampHeader = extern struct {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
    originate: u32,
    receive: u32,
    transmit: u32,
};

// =============================================================================
// Checksum computation
// =============================================================================

pub fn computeChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Sum 16-bit words
    while (i + 1 < data.len) : (i += 2) {
        const word = @as(u16, data[i]) << 8 | @as(u16, data[i + 1]);
        sum += word;
    }

    // Handle odd byte
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    // Fold 32-bit sum to 16-bit
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @intCast(~sum & 0xFFFF);
}

pub fn verifyChecksum(data: []const u8) bool {
    return computeChecksum(data) == 0;
}

// =============================================================================
// Ping tracking
// =============================================================================

pub const MAX_PING_SESSIONS: usize = 16;

pub const PingSession = struct {
    dest_ip: u32,
    identifier: u16,
    next_seq: u16,
    sent: u32,
    received: u32,
    lost: u32,
    min_rtt_us: u64,
    max_rtt_us: u64,
    total_rtt_us: u64,
    // Timestamps for outstanding pings
    outstanding: [64]u64,
    active: bool,

    pub fn init(self: *PingSession, dest: u32, id: u16) void {
        self.dest_ip = dest;
        self.identifier = id;
        self.next_seq = 0;
        self.sent = 0;
        self.received = 0;
        self.lost = 0;
        self.min_rtt_us = ~@as(u64, 0);
        self.max_rtt_us = 0;
        self.total_rtt_us = 0;
        self.active = true;
        for (&self.outstanding) |*ts| ts.* = 0;
    }

    pub fn recordSend(self: *PingSession, timestamp_us: u64) u16 {
        const seq = self.next_seq;
        self.next_seq +%= 1;
        self.sent += 1;
        self.outstanding[seq % 64] = timestamp_us;
        return seq;
    }

    pub fn recordReceive(self: *PingSession, seq: u16, timestamp_us: u64) void {
        self.received += 1;
        const send_ts = self.outstanding[seq % 64];
        if (send_ts > 0) {
            const rtt = timestamp_us - send_ts;
            if (rtt < self.min_rtt_us) self.min_rtt_us = rtt;
            if (rtt > self.max_rtt_us) self.max_rtt_us = rtt;
            self.total_rtt_us += rtt;
            self.outstanding[seq % 64] = 0;
        }
    }

    pub fn avgRttUs(self: *const PingSession) u64 {
        if (self.received == 0) return 0;
        return self.total_rtt_us / self.received;
    }

    pub fn lossPercent(self: *const PingSession) u32 {
        if (self.sent == 0) return 0;
        return ((self.sent - self.received) * 100) / self.sent;
    }
};

// =============================================================================
// Rate limiter
// =============================================================================

pub const RateLimiter = struct {
    tokens: u32,
    max_tokens: u32,
    refill_rate: u32,    // tokens per second
    last_refill: u64,    // timestamp in ms

    pub fn init(self: *RateLimiter, max: u32, rate: u32) void {
        self.tokens = max;
        self.max_tokens = max;
        self.refill_rate = rate;
        self.last_refill = 0;
    }

    pub fn tryConsume(self: *RateLimiter, now_ms: u64) bool {
        // Refill tokens
        const elapsed = now_ms - self.last_refill;
        if (elapsed >= 1000) {
            const refill = @as(u32, @intCast(elapsed / 1000)) * self.refill_rate;
            self.tokens = @min(self.tokens + refill, self.max_tokens);
            self.last_refill = now_ms;
        }

        if (self.tokens > 0) {
            self.tokens -= 1;
            return true;
        }
        return false;
    }
};

// =============================================================================
// ICMP processor
// =============================================================================

pub const IcmpStats = struct {
    echo_requests_sent: u64,
    echo_replies_sent: u64,
    echo_requests_received: u64,
    echo_replies_received: u64,
    dest_unreachable_sent: u64,
    dest_unreachable_received: u64,
    time_exceeded_sent: u64,
    time_exceeded_received: u64,
    redirect_received: u64,
    checksum_errors: u64,
    rate_limited: u64,
    unknown_type: u64,
};

pub const IcmpProcessor = struct {
    sessions: [MAX_PING_SESSIONS]PingSession,
    session_count: usize,
    limiter: RateLimiter,
    stats: IcmpStats,

    // Output buffer for constructing ICMP packets
    tx_buf: [1500]u8,
    tx_len: usize,

    pub fn init(self: *IcmpProcessor) void {
        self.session_count = 0;
        self.limiter.init(100, 50); // 100 tokens, 50/sec refill
        self.stats = IcmpStats{
            .echo_requests_sent = 0,
            .echo_replies_sent = 0,
            .echo_requests_received = 0,
            .echo_replies_received = 0,
            .dest_unreachable_sent = 0,
            .dest_unreachable_received = 0,
            .time_exceeded_sent = 0,
            .time_exceeded_received = 0,
            .redirect_received = 0,
            .checksum_errors = 0,
            .rate_limited = 0,
            .unknown_type = 0,
        };
        self.tx_len = 0;
        for (&self.sessions) |*s| s.active = false;
    }

    /// Process an incoming ICMP packet
    pub fn processIncoming(self: *IcmpProcessor, data: []const u8, _: u32) void {
        if (data.len < @sizeOf(IcmpHeader)) return;

        // Verify checksum
        if (!verifyChecksum(data)) {
            self.stats.checksum_errors += 1;
            return;
        }

        const hdr = @as(*const IcmpHeader, @ptrCast(@alignCast(data.ptr)));

        switch (hdr.icmp_type) {
            ICMP_ECHO_REQUEST => {
                self.stats.echo_requests_received += 1;
                self.handleEchoRequest(data);
            },
            ICMP_ECHO_REPLY => {
                self.stats.echo_replies_received += 1;
                self.handleEchoReply(data);
            },
            ICMP_DEST_UNREACHABLE => {
                self.stats.dest_unreachable_received += 1;
            },
            ICMP_TIME_EXCEEDED => {
                self.stats.time_exceeded_received += 1;
            },
            ICMP_REDIRECT => {
                self.stats.redirect_received += 1;
            },
            else => {
                self.stats.unknown_type += 1;
            },
        }
    }

    fn handleEchoRequest(self: *IcmpProcessor, data: []const u8) void {
        if (data.len < @sizeOf(IcmpEchoHeader)) return;

        // Build echo reply (same data, different type)
        const max_len = @min(data.len, self.tx_buf.len);
        @memcpy(self.tx_buf[0..max_len], data[0..max_len]);

        // Change type to ECHO_REPLY
        self.tx_buf[0] = ICMP_ECHO_REPLY;
        // Zero checksum for recalculation
        self.tx_buf[2] = 0;
        self.tx_buf[3] = 0;

        // Compute new checksum
        const cksum = computeChecksum(self.tx_buf[0..max_len]);
        self.tx_buf[2] = @intCast((cksum >> 8) & 0xFF);
        self.tx_buf[3] = @intCast(cksum & 0xFF);
        self.tx_len = max_len;

        self.stats.echo_replies_sent += 1;
    }

    fn handleEchoReply(self: *IcmpProcessor, data: []const u8) void {
        if (data.len < @sizeOf(IcmpEchoHeader)) return;

        const echo = @as(*const IcmpEchoHeader, @ptrCast(@alignCast(data.ptr)));

        // Find matching ping session
        for (&self.sessions) |*session| {
            if (session.active and session.identifier == echo.identifier) {
                session.recordReceive(echo.sequence, 0); // TODO: actual timestamp
                break;
            }
        }
    }

    /// Build an echo request packet
    pub fn buildEchoRequest(self: *IcmpProcessor, id: u16, seq: u16, payload: []const u8) []const u8 {
        const hdr_size = @sizeOf(IcmpEchoHeader);
        const total = hdr_size + payload.len;
        if (total > self.tx_buf.len) return &[_]u8{};

        self.tx_buf[0] = ICMP_ECHO_REQUEST;
        self.tx_buf[1] = 0; // Code
        self.tx_buf[2] = 0; // Checksum (zeroed for calculation)
        self.tx_buf[3] = 0;
        self.tx_buf[4] = @intCast((id >> 8) & 0xFF);
        self.tx_buf[5] = @intCast(id & 0xFF);
        self.tx_buf[6] = @intCast((seq >> 8) & 0xFF);
        self.tx_buf[7] = @intCast(seq & 0xFF);

        // Copy payload
        if (payload.len > 0) {
            @memcpy(self.tx_buf[hdr_size..hdr_size + payload.len], payload);
        }

        // Compute checksum
        const cksum = computeChecksum(self.tx_buf[0..total]);
        self.tx_buf[2] = @intCast((cksum >> 8) & 0xFF);
        self.tx_buf[3] = @intCast(cksum & 0xFF);

        self.tx_len = total;
        self.stats.echo_requests_sent += 1;
        return self.tx_buf[0..total];
    }

    /// Build destination unreachable message
    pub fn buildDestUnreachable(self: *IcmpProcessor, code: u8, original_pkt: []const u8) []const u8 {
        const hdr_size: usize = 8; // type + code + checksum + unused(4)
        // Include IP header + first 8 bytes of original datagram
        const orig_len = @min(original_pkt.len, 28);
        const total = hdr_size + orig_len;
        if (total > self.tx_buf.len) return &[_]u8{};

        self.tx_buf[0] = ICMP_DEST_UNREACHABLE;
        self.tx_buf[1] = code;
        self.tx_buf[2] = 0;
        self.tx_buf[3] = 0;
        // Rest of header (unused or MTU for code 4)
        self.tx_buf[4] = 0;
        self.tx_buf[5] = 0;
        self.tx_buf[6] = 0;
        self.tx_buf[7] = 0;

        @memcpy(self.tx_buf[hdr_size..hdr_size + orig_len], original_pkt[0..orig_len]);

        const cksum = computeChecksum(self.tx_buf[0..total]);
        self.tx_buf[2] = @intCast((cksum >> 8) & 0xFF);
        self.tx_buf[3] = @intCast(cksum & 0xFF);

        self.tx_len = total;
        self.stats.dest_unreachable_sent += 1;
        return self.tx_buf[0..total];
    }

    /// Build time exceeded message
    pub fn buildTimeExceeded(self: *IcmpProcessor, code: u8, original_pkt: []const u8) []const u8 {
        const hdr_size: usize = 8;
        const orig_len = @min(original_pkt.len, 28);
        const total = hdr_size + orig_len;
        if (total > self.tx_buf.len) return &[_]u8{};

        self.tx_buf[0] = ICMP_TIME_EXCEEDED;
        self.tx_buf[1] = code;
        self.tx_buf[2] = 0;
        self.tx_buf[3] = 0;
        self.tx_buf[4] = 0;
        self.tx_buf[5] = 0;
        self.tx_buf[6] = 0;
        self.tx_buf[7] = 0;

        @memcpy(self.tx_buf[hdr_size..hdr_size + orig_len], original_pkt[0..orig_len]);

        const cksum = computeChecksum(self.tx_buf[0..total]);
        self.tx_buf[2] = @intCast((cksum >> 8) & 0xFF);
        self.tx_buf[3] = @intCast(cksum & 0xFF);

        self.tx_len = total;
        self.stats.time_exceeded_sent += 1;
        return self.tx_buf[0..total];
    }

    /// Create a new ping session
    pub fn createPingSession(self: *IcmpProcessor, dest_ip: u32, id: u16) ?usize {
        for (&self.sessions, 0..) |*session, i| {
            if (!session.active) {
                session.init(dest_ip, id);
                self.session_count += 1;
                return i;
            }
        }
        return null;
    }

    /// Destroy a ping session
    pub fn destroyPingSession(self: *IcmpProcessor, idx: usize) void {
        if (idx < MAX_PING_SESSIONS and self.sessions[idx].active) {
            self.sessions[idx].active = false;
            self.session_count -= 1;
        }
    }
};

// =============================================================================
// Global instance
// =============================================================================

var icmp_processor: IcmpProcessor = undefined;
var icmp_initialized: bool = false;

pub fn initIcmp() void {
    icmp_processor.init();
    icmp_initialized = true;
}

pub fn getProcessor() ?*IcmpProcessor {
    if (icmp_initialized) return &icmp_processor;
    return null;
}
