// =============================================================================
// Kernel Zxyphor - TCP (Transmission Control Protocol) — RFC 793/7414
// =============================================================================
// Full TCP state machine implementation with connection management,
// reliable delivery (sequence numbers, ACKs, retransmission), flow control
// (sliding window), congestion control (slow start, congestion avoidance,
// fast retransmit, fast recovery), and the standard 11-state FSM.
//
// TCP Header (20-60 bytes):
//   Source Port(16) | Destination Port(16)
//   Sequence Number(32)
//   Acknowledgment Number(32)
//   Data Offset(4) | Reserved(3) | Flags(9) | Window Size(16)
//   Checksum(16) | Urgent Pointer(16)
//   [Options]
//
// TCP Flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const TCP_HEADER_LEN: usize = 20;
pub const TCP_MAX_SEGMENT: usize = 1460; // MSS for Ethernet
pub const TCP_WINDOW_SIZE: u16 = 65535;
pub const TCP_DEFAULT_TTL: u8 = 64;
pub const MAX_TCP_CONNECTIONS: usize = 1024;
pub const TCP_MAX_BACKLOG: usize = 128;
pub const TCP_RETRANSMIT_MS: u64 = 1000;
pub const TCP_MAX_RETRIES: u32 = 8;
pub const TCP_KEEPALIVE_MS: u64 = 7200000; // 2 hours
pub const TCP_TIME_WAIT_MS: u64 = 120000; // 2 minutes (2*MSL)
pub const TCP_FIN_WAIT_MS: u64 = 60000; // 1 minute

// TCP Flags
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;
pub const ECE: u8 = 0x40;
pub const CWR: u8 = 0x80;

// TCP Options
pub const OPT_END: u8 = 0;
pub const OPT_NOP: u8 = 1;
pub const OPT_MSS: u8 = 2;
pub const OPT_WINDOW_SCALE: u8 = 3;
pub const OPT_SACK_PERMITTED: u8 = 4;
pub const OPT_SACK: u8 = 5;
pub const OPT_TIMESTAMP: u8 = 8;

// =============================================================================
// TCP States (RFC 793 FSM)
// =============================================================================
pub const TcpState = enum(u8) {
    closed,
    listen,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    closing,
    last_ack,
    time_wait,
};

// =============================================================================
// TCP Header
// =============================================================================
pub const TcpHeader = struct {
    src_port: u16 = 0,
    dst_port: u16 = 0,
    seq_num: u32 = 0,
    ack_num: u32 = 0,
    data_offset: u8 = 5, // In 32-bit words
    flags: u8 = 0,
    window: u16 = TCP_WINDOW_SIZE,
    checksum: u16 = 0,
    urgent_ptr: u16 = 0,

    pub fn headerLen(self: *const TcpHeader) usize {
        return @as(usize, self.data_offset) * 4;
    }

    pub fn hasFlag(self: *const TcpHeader, flag: u8) bool {
        return (self.flags & flag) != 0;
    }

    pub fn parse(data: []const u8) ?TcpHeader {
        if (data.len < TCP_HEADER_LEN) return null;

        var hdr = TcpHeader{};
        hdr.src_port = readU16BE(data, 0);
        hdr.dst_port = readU16BE(data, 2);
        hdr.seq_num = readU32BE(data, 4);
        hdr.ack_num = readU32BE(data, 8);
        hdr.data_offset = data[12] >> 4;
        hdr.flags = data[13];
        hdr.window = readU16BE(data, 14);
        hdr.checksum = readU16BE(data, 16);
        hdr.urgent_ptr = readU16BE(data, 18);

        if (hdr.data_offset < 5) return null;
        if (hdr.headerLen() > data.len) return null;

        return hdr;
    }

    pub fn serialize(self: *const TcpHeader, buf: []u8) bool {
        if (buf.len < TCP_HEADER_LEN) return false;

        writeU16BE(buf, 0, self.src_port);
        writeU16BE(buf, 2, self.dst_port);
        writeU32BE(buf, 4, self.seq_num);
        writeU32BE(buf, 8, self.ack_num);
        buf[12] = (self.data_offset << 4);
        buf[13] = self.flags;
        writeU16BE(buf, 14, self.window);
        writeU16BE(buf, 16, 0); // Checksum computed later
        writeU16BE(buf, 18, self.urgent_ptr);

        return true;
    }
};

// =============================================================================
// TCP Connection (Transmission Control Block — TCB)
// =============================================================================
pub const TcpConnection = struct {
    // Connection identity (4-tuple)
    local_addr: u32 = 0,
    local_port: u16 = 0,
    remote_addr: u32 = 0,
    remote_port: u16 = 0,

    // State machine
    state: TcpState = .closed,

    // Send sequence variables
    snd_una: u32 = 0, // Oldest unacknowledged seq
    snd_nxt: u32 = 0, // Next sequence to send
    snd_wnd: u16 = 0, // Send window (from receiver)
    snd_wl1: u32 = 0, // Seq for last window update
    snd_wl2: u32 = 0, // Ack for last window update
    iss: u32 = 0, // Initial send sequence number

    // Receive sequence variables
    rcv_nxt: u32 = 0, // Next expected sequence
    rcv_wnd: u16 = TCP_WINDOW_SIZE,
    irs: u32 = 0, // Initial receive sequence number

    // Congestion control
    cwnd: u32 = TCP_MAX_SEGMENT, // Congestion window
    ssthresh: u32 = 65535, // Slow start threshold
    duplicate_ack_count: u32 = 0,

    // Timekeeping
    rto_ms: u64 = TCP_RETRANSMIT_MS, // Retransmission timeout
    srtt_us: u64 = 0, // Smoothed RTT
    rttvar_us: u64 = 0, // RTT variance
    last_send_time: u64 = 0,
    retransmit_count: u32 = 0,

    // MSS (Maximum Segment Size)
    local_mss: u16 = TCP_MAX_SEGMENT,
    remote_mss: u16 = TCP_MAX_SEGMENT,

    // Receive buffer
    rx_buffer: [65536]u8 = [_]u8{0} ** 65536,
    rx_len: usize = 0,

    // Send buffer
    tx_buffer: [65536]u8 = [_]u8{0} ** 65536,
    tx_len: usize = 0,
    tx_sent: usize = 0, // How much of tx_buffer has been sent

    // Backlog (for listening sockets)
    backlog_queue: [16]u16 = [_]u16{0} ** 16, // Connection indices
    backlog_count: u8 = 0,
    backlog_max: u8 = 0,

    // State
    is_valid: bool = false,
    is_listening: bool = false,

    pub fn isReadable(self: *const TcpConnection) bool {
        return self.rx_len > 0 or self.state == .close_wait or self.state == .closed;
    }

    pub fn isWritable(self: *const TcpConnection) bool {
        return self.state == .established and self.tx_len < self.tx_buffer.len;
    }

    pub fn availableRxSpace(self: *const TcpConnection) usize {
        return self.rx_buffer.len - self.rx_len;
    }
};

// =============================================================================
// Connection Table
// =============================================================================
var connections: [MAX_TCP_CONNECTIONS]TcpConnection = undefined;
var next_ephemeral_port: u16 = 49152;

var tcp_stats: TcpStats = .{};

pub const TcpStats = struct {
    active_opens: u64 = 0,
    passive_opens: u64 = 0,
    established: u64 = 0,
    resets_sent: u64 = 0,
    resets_received: u64 = 0,
    segments_sent: u64 = 0,
    segments_received: u64 = 0,
    retransmits: u64 = 0,
    checksum_errors: u64 = 0,
};

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&connections) |*conn| {
        conn.* = TcpConnection{};
    }
    next_ephemeral_port = 49152;
    tcp_stats = TcpStats{};
    main.klog(.info, "tcp: protocol initialized ({d} max connections)", .{MAX_TCP_CONNECTIONS});
}

// =============================================================================
// Socket-level API
// =============================================================================

/// Create a new TCP connection (socket)
pub fn create() ?u16 {
    for (&connections, 0..) |*conn, i| {
        if (!conn.is_valid) {
            conn.* = TcpConnection{};
            conn.is_valid = true;
            conn.state = .closed;
            return @truncate(i);
        }
    }
    return null;
}

/// Bind to a local address and port
pub fn bind(conn_id: u16, addr: u32, port: u16) bool {
    if (conn_id >= MAX_TCP_CONNECTIONS) return false;
    var conn = &connections[conn_id];
    if (!conn.is_valid) return false;

    // Check if port is already in use
    for (connections) |c| {
        if (c.is_valid and c.local_port == port and c.local_addr == addr) return false;
    }

    conn.local_addr = addr;
    conn.local_port = port;
    return true;
}

/// Start listening for connections
pub fn listen(conn_id: u16, backlog: u8) bool {
    if (conn_id >= MAX_TCP_CONNECTIONS) return false;
    var conn = &connections[conn_id];
    if (!conn.is_valid or conn.local_port == 0) return false;

    conn.state = .listen;
    conn.is_listening = true;
    conn.backlog_max = @min(backlog, 16);
    tcp_stats.passive_opens += 1;
    return true;
}

/// Accept an incoming connection (returns new connection id)
pub fn accept(conn_id: u16) ?u16 {
    if (conn_id >= MAX_TCP_CONNECTIONS) return null;
    var conn = &connections[conn_id];
    if (!conn.is_valid or !conn.is_listening) return null;

    if (conn.backlog_count > 0) {
        conn.backlog_count -= 1;
        const new_id = conn.backlog_queue[conn.backlog_count];
        return new_id;
    }
    return null;
}

/// Initiate a connection (active open)
pub fn connect(conn_id: u16, remote_addr: u32, remote_port: u16) bool {
    if (conn_id >= MAX_TCP_CONNECTIONS) return false;
    var conn = &connections[conn_id];
    if (!conn.is_valid) return false;

    // Assign ephemeral port if not bound
    if (conn.local_port == 0) {
        conn.local_port = allocateEphemeralPort();
    }
    if (conn.local_addr == 0) {
        // Use first available interface address
        if (main.ethernet.getInterface(1)) |iface| {
            conn.local_addr = iface.ipv4_addr;
        }
    }

    conn.remote_addr = remote_addr;
    conn.remote_port = remote_port;

    // Generate ISS (Initial Send Sequence Number)
    conn.iss = generateISN();
    conn.snd_una = conn.iss;
    conn.snd_nxt = conn.iss + 1;

    // Send SYN
    sendSegment(conn, SYN, null);
    conn.state = .syn_sent;
    tcp_stats.active_opens += 1;

    return true;
}

/// Send data on an established connection
pub fn send(conn_id: u16, data: []const u8) i32 {
    if (conn_id >= MAX_TCP_CONNECTIONS) return -1;
    var conn = &connections[conn_id];
    if (!conn.is_valid or conn.state != .established) return -1;

    // Copy to send buffer
    const space = conn.tx_buffer.len - conn.tx_len;
    const to_copy = @min(data.len, space);
    if (to_copy == 0) return 0;

    @memcpy(conn.tx_buffer[conn.tx_len .. conn.tx_len + to_copy], data[0..to_copy]);
    conn.tx_len += to_copy;

    // Trigger send
    transmitData(conn);

    return @intCast(to_copy);
}

/// Receive data from a connection
pub fn recv(conn_id: u16, buf: []u8) i32 {
    if (conn_id >= MAX_TCP_CONNECTIONS) return -1;
    var conn = &connections[conn_id];
    if (!conn.is_valid) return -1;

    if (conn.rx_len == 0) {
        if (conn.state == .close_wait or conn.state == .closed) return 0; // EOF
        return -1; // Would block
    }

    const to_copy = @min(buf.len, conn.rx_len);
    @memcpy(buf[0..to_copy], conn.rx_buffer[0..to_copy]);

    // Shift remaining data
    if (to_copy < conn.rx_len) {
        const remaining = conn.rx_len - to_copy;
        var i: usize = 0;
        while (i < remaining) : (i += 1) {
            conn.rx_buffer[i] = conn.rx_buffer[to_copy + i];
        }
    }
    conn.rx_len -= to_copy;

    return @intCast(to_copy);
}

/// Close a connection (initiate graceful shutdown)
pub fn close(conn_id: u16) void {
    if (conn_id >= MAX_TCP_CONNECTIONS) return;
    var conn = &connections[conn_id];
    if (!conn.is_valid) return;

    switch (conn.state) {
        .established => {
            sendSegment(conn, FIN | ACK, null);
            conn.snd_nxt += 1;
            conn.state = .fin_wait_1;
        },
        .close_wait => {
            sendSegment(conn, FIN | ACK, null);
            conn.snd_nxt += 1;
            conn.state = .last_ack;
        },
        .listen, .syn_sent => {
            conn.state = .closed;
            conn.is_valid = false;
        },
        else => {},
    }
}

// =============================================================================
// Receive TCP segment (called from IP layer)
// =============================================================================
pub fn receiveSegment(ip_hdr: *const main.ip.Ipv4Header, data: []const u8) void {
    const hdr = TcpHeader.parse(data) orelse return;

    tcp_stats.segments_received += 1;

    // Find matching connection
    if (findConnection(ip_hdr.dst_addr, hdr.dst_port, ip_hdr.src_addr, hdr.src_port)) |conn| {
        processSegment(conn, ip_hdr, &hdr, data[hdr.headerLen()..]);
    } else if (findListener(ip_hdr.dst_addr, hdr.dst_port)) |listener| {
        // SYN to a listening socket
        if (hdr.hasFlag(SYN) and !hdr.hasFlag(ACK)) {
            handleSyn(listener, ip_hdr, &hdr);
        }
    } else {
        // No connection — send RST
        if (!hdr.hasFlag(RST)) {
            sendReset(ip_hdr, &hdr);
        }
    }
}

// =============================================================================
// TCP State Machine — main segment processing
// =============================================================================
fn processSegment(conn: *TcpConnection, ip_hdr: *const main.ip.Ipv4Header, hdr: *const TcpHeader, payload: []const u8) void {
    _ = ip_hdr;

    // RST handling
    if (hdr.hasFlag(RST)) {
        tcp_stats.resets_received += 1;
        conn.state = .closed;
        conn.is_valid = false;
        return;
    }

    switch (conn.state) {
        .syn_sent => {
            // Expecting SYN+ACK
            if (hdr.hasFlag(SYN) and hdr.hasFlag(ACK)) {
                conn.irs = hdr.seq_num;
                conn.rcv_nxt = hdr.seq_num + 1;
                conn.snd_una = hdr.ack_num;
                conn.snd_wnd = hdr.window;

                conn.state = .established;
                tcp_stats.established += 1;

                // Send ACK
                sendSegment(conn, ACK, null);
            }
        },

        .syn_received => {
            if (hdr.hasFlag(ACK)) {
                conn.snd_una = hdr.ack_num;
                conn.state = .established;
                tcp_stats.established += 1;
            }
        },

        .established => {
            // ACK processing
            if (hdr.hasFlag(ACK)) {
                processAck(conn, hdr);
            }

            // Data processing
            if (payload.len > 0 and hdr.seq_num == conn.rcv_nxt) {
                const space = conn.availableRxSpace();
                const to_copy = @min(payload.len, space);
                if (to_copy > 0) {
                    @memcpy(conn.rx_buffer[conn.rx_len .. conn.rx_len + to_copy], payload[0..to_copy]);
                    conn.rx_len += to_copy;
                    conn.rcv_nxt += @truncate(to_copy);
                }
                // Send ACK for received data
                sendSegment(conn, ACK, null);
            }

            // FIN processing
            if (hdr.hasFlag(FIN)) {
                conn.rcv_nxt += 1;
                conn.state = .close_wait;
                sendSegment(conn, ACK, null);
            }
        },

        .fin_wait_1 => {
            if (hdr.hasFlag(ACK)) {
                conn.snd_una = hdr.ack_num;
                if (hdr.hasFlag(FIN)) {
                    conn.rcv_nxt += 1;
                    conn.state = .time_wait;
                    sendSegment(conn, ACK, null);
                } else {
                    conn.state = .fin_wait_2;
                }
            }
        },

        .fin_wait_2 => {
            if (hdr.hasFlag(FIN)) {
                conn.rcv_nxt += 1;
                conn.state = .time_wait;
                sendSegment(conn, ACK, null);
            }
        },

        .closing => {
            if (hdr.hasFlag(ACK)) {
                conn.state = .time_wait;
            }
        },

        .last_ack => {
            if (hdr.hasFlag(ACK)) {
                conn.state = .closed;
                conn.is_valid = false;
            }
        },

        .time_wait => {
            // ACK any FIN retransmission
            if (hdr.hasFlag(FIN)) {
                sendSegment(conn, ACK, null);
            }
        },

        else => {},
    }
}

// =============================================================================
// ACK Processing & Congestion Control
// =============================================================================
fn processAck(conn: *TcpConnection, hdr: *const TcpHeader) void {
    if (seqAfter(hdr.ack_num, conn.snd_una)) {
        const acked = hdr.ack_num -% conn.snd_una;
        conn.snd_una = hdr.ack_num;
        conn.duplicate_ack_count = 0;

        // Remove acked data from send buffer
        if (acked <= conn.tx_sent) conn.tx_sent -= @as(usize, acked);

        // Update send window
        conn.snd_wnd = hdr.window;

        // Congestion control: increase cwnd
        if (conn.cwnd < conn.ssthresh) {
            // Slow start: increase by 1 MSS per ACK
            conn.cwnd += @as(u32, conn.remote_mss);
        } else {
            // Congestion avoidance: increase by MSS^2/cwnd per ACK
            const inc = (@as(u32, conn.remote_mss) * @as(u32, conn.remote_mss)) / conn.cwnd;
            conn.cwnd += @max(inc, 1);
        }

        // Send more data if available
        transmitData(conn);
    } else if (hdr.ack_num == conn.snd_una) {
        // Duplicate ACK
        conn.duplicate_ack_count += 1;
        if (conn.duplicate_ack_count == 3) {
            // Fast retransmit
            conn.ssthresh = @max(conn.cwnd / 2, 2 * @as(u32, conn.remote_mss));
            conn.cwnd = conn.ssthresh + 3 * @as(u32, conn.remote_mss);
            tcp_stats.retransmits += 1;
            retransmitOldest(conn);
        } else if (conn.duplicate_ack_count > 3) {
            // Fast recovery: inflate cwnd
            conn.cwnd += @as(u32, conn.remote_mss);
        }
    }
}

// =============================================================================
// Data Transmission
// =============================================================================
fn transmitData(conn: *TcpConnection) void {
    while (conn.tx_sent < conn.tx_len) {
        // How much can we send?
        const unsent = conn.tx_len - conn.tx_sent;
        const window_available = @as(usize, conn.snd_wnd) -| (conn.snd_nxt -% conn.snd_una);
        const cwnd_available = @as(usize, conn.cwnd) -| (conn.snd_nxt -% conn.snd_una);
        const can_send = @min(unsent, @min(window_available, cwnd_available));
        const segment_size = @min(can_send, @as(usize, conn.remote_mss));

        if (segment_size == 0) break;

        // Build and send segment with data
        const data = conn.tx_buffer[conn.tx_sent .. conn.tx_sent + segment_size];
        sendSegment(conn, ACK | PSH, data);
        conn.snd_nxt +%= @truncate(segment_size);
        conn.tx_sent += segment_size;
    }
}

fn retransmitOldest(conn: *TcpConnection) void {
    if (conn.tx_sent > 0) {
        const segment_size = @min(conn.tx_sent, @as(usize, conn.remote_mss));
        sendSegment(conn, ACK, conn.tx_buffer[0..segment_size]);
    }
}

// =============================================================================
// Segment Construction & Transmission
// =============================================================================
fn sendSegment(conn: *TcpConnection, flags: u8, payload: ?[]const u8) void {
    var buf: [1500]u8 = undefined;

    var hdr = TcpHeader{
        .src_port = conn.local_port,
        .dst_port = conn.remote_port,
        .seq_num = conn.snd_nxt,
        .ack_num = conn.rcv_nxt,
        .flags = flags,
        .window = conn.rcv_wnd,
    };

    if (!hdr.serialize(&buf)) return;

    // Copy payload if any
    var total: usize = TCP_HEADER_LEN;
    if (payload) |data| {
        const copy_len = @min(data.len, buf.len - TCP_HEADER_LEN);
        @memcpy(buf[TCP_HEADER_LEN .. TCP_HEADER_LEN + copy_len], data[0..copy_len]);
        total += copy_len;
    }

    // Compute TCP checksum using pseudo-header
    const cksum = tcpChecksum(conn.local_addr, conn.remote_addr, buf[0..total]);
    writeU16BE(&buf, 16, cksum);

    // Send via IP
    _ = main.ip.sendPacket(conn.remote_addr, main.ip.PROTO_TCP, buf[0..total]);
    tcp_stats.segments_sent += 1;
    conn.last_send_time = main.timer.getUnixTimestamp();
}

fn sendReset(ip_hdr: *const main.ip.Ipv4Header, tcp_hdr: *const TcpHeader) void {
    // Build a minimal connection context for sending
    var temp = TcpConnection{
        .local_addr = ip_hdr.dst_addr,
        .local_port = tcp_hdr.dst_port,
        .remote_addr = ip_hdr.src_addr,
        .remote_port = tcp_hdr.src_port,
        .is_valid = true,
    };

    if (tcp_hdr.hasFlag(ACK)) {
        temp.snd_nxt = tcp_hdr.ack_num;
        temp.rcv_nxt = 0;
        sendSegment(&temp, RST, null);
    } else {
        temp.snd_nxt = 0;
        temp.rcv_nxt = tcp_hdr.seq_num +% 1;
        sendSegment(&temp, RST | ACK, null);
    }
    tcp_stats.resets_sent += 1;
}

// =============================================================================
// SYN Handling (passive open)
// =============================================================================
fn handleSyn(listener: *TcpConnection, ip_hdr: *const main.ip.Ipv4Header, syn_hdr: *const TcpHeader) void {
    if (listener.backlog_count >= listener.backlog_max) return;

    // Create new connection for this client
    const conn_id = create() orelse return;
    var conn = &connections[conn_id];

    conn.local_addr = ip_hdr.dst_addr;
    conn.local_port = syn_hdr.dst_port;
    conn.remote_addr = ip_hdr.src_addr;
    conn.remote_port = syn_hdr.src_port;

    conn.irs = syn_hdr.seq_num;
    conn.rcv_nxt = syn_hdr.seq_num + 1;

    conn.iss = generateISN();
    conn.snd_nxt = conn.iss + 1;
    conn.snd_una = conn.iss;

    conn.snd_wnd = syn_hdr.window;

    // Send SYN+ACK
    conn.snd_nxt = conn.iss; // Will be incremented after sending
    sendSegment(conn, SYN | ACK, null);
    conn.snd_nxt = conn.iss + 1;

    conn.state = .syn_received;

    // Add to backlog
    listener.backlog_queue[listener.backlog_count] = conn_id;
    listener.backlog_count += 1;
}

// =============================================================================
// Connection Lookup
// =============================================================================
fn findConnection(local_addr: u32, local_port: u16, remote_addr: u32, remote_port: u16) ?*TcpConnection {
    for (&connections) |*conn| {
        if (conn.is_valid and !conn.is_listening and
            conn.local_port == local_port and conn.remote_port == remote_port and
            (conn.local_addr == local_addr or conn.local_addr == 0) and
            conn.remote_addr == remote_addr)
        {
            return conn;
        }
    }
    return null;
}

fn findListener(local_addr: u32, local_port: u16) ?*TcpConnection {
    for (&connections) |*conn| {
        if (conn.is_valid and conn.is_listening and conn.state == .listen and
            conn.local_port == local_port and
            (conn.local_addr == local_addr or conn.local_addr == 0))
        {
            return conn;
        }
    }
    return null;
}

// =============================================================================
// Helpers
// =============================================================================
fn allocateEphemeralPort() u16 {
    const port = next_ephemeral_port;
    next_ephemeral_port +%= 1;
    if (next_ephemeral_port < 49152) next_ephemeral_port = 49152;
    return port;
}

fn generateISN() u32 {
    // ISN should be based on a monotonically incrementing counter + random
    // Using timer ticks as pseudo-random source
    const ticks = main.timer.getTicks();
    return @truncate(ticks *% 0x9E3779B1);
}

fn seqAfter(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

/// TCP checksum with pseudo-header
fn tcpChecksum(src_ip: u32, dst_ip: u32, tcp_data: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header
    sum += src_ip >> 16;
    sum += src_ip & 0xFFFF;
    sum += dst_ip >> 16;
    sum += dst_ip & 0xFFFF;
    sum += @as(u32, main.ip.PROTO_TCP);
    sum += @as(u32, @truncate(tcp_data.len));

    // TCP header + data
    var i: usize = 0;
    while (i + 1 < tcp_data.len) : (i += 2) {
        sum += @as(u32, tcp_data[i]) << 8 | tcp_data[i + 1];
    }
    if (i < tcp_data.len) {
        sum += @as(u32, tcp_data[i]) << 8;
    }

    // Fold
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return @truncate(~sum);
}

pub fn getStats() TcpStats {
    return tcp_stats;
}

/// Timer tick — check for retransmissions and TIME_WAIT expiry
pub fn timerTick() void {
    const now = main.timer.getUnixTimestamp();
    for (&connections) |*conn| {
        if (!conn.is_valid) continue;

        switch (conn.state) {
            .time_wait => {
                if (now - conn.last_send_time >= TCP_TIME_WAIT_MS / 1000) {
                    conn.state = .closed;
                    conn.is_valid = false;
                }
            },
            .syn_sent, .established => {
                // Retransmission check
                if (conn.snd_una != conn.snd_nxt and
                    now - conn.last_send_time >= conn.rto_ms / 1000)
                {
                    if (conn.retransmit_count < TCP_MAX_RETRIES) {
                        retransmitOldest(conn);
                        conn.retransmit_count += 1;
                        conn.rto_ms *= 2; // Exponential backoff
                        tcp_stats.retransmits += 1;
                    } else {
                        // Connection timed out
                        conn.state = .closed;
                        conn.is_valid = false;
                    }
                }
            },
            else => {},
        }
    }
}

// =============================================================================
// Network byte order helpers
// =============================================================================
fn readU16BE(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) << 8 | data[offset + 1];
}

fn readU32BE(data: []const u8, offset: usize) u32 {
    return @as(u32, data[offset]) << 24 | @as(u32, data[offset + 1]) << 16 |
        @as(u32, data[offset + 2]) << 8 | data[offset + 3];
}

fn writeU16BE(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @truncate(val >> 8);
    buf[offset + 1] = @truncate(val & 0xFF);
}

fn writeU32BE(buf: []u8, offset: usize, val: u32) void {
    buf[offset] = @truncate(val >> 24);
    buf[offset + 1] = @truncate((val >> 16) & 0xFF);
    buf[offset + 2] = @truncate((val >> 8) & 0xFF);
    buf[offset + 3] = @truncate(val & 0xFF);
}
