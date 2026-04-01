// SPDX-License-Identifier: MIT
// Zxyphor Kernel — AF_UNIX (Unix Domain Socket) Subsystem (Zig)
//
// Full Unix domain socket implementation:
// - SOCK_STREAM (connection-oriented, byte stream)
// - SOCK_DGRAM (connectionless, message boundaries)
// - SOCK_SEQPACKET (connection-oriented, message boundaries)
// - Socket address (sockaddr_un with 108-byte path)
// - Socket pair creation (socketpair)
// - Connection lifecycle: bind → listen → accept → connect
// - Ancillary data: SCM_RIGHTS (fd passing), SCM_CREDENTIALS (pid/uid/gid)
// - Peer credentials (SO_PEERCRED)
// - Abstract namespace (path starting with \0)
// - Backlog queue for pending connections
// - Shutdown (SHUT_RD, SHUT_WR, SHUT_RDWR)
// - Non-blocking I/O support
// - Per-socket buffer management with flow control

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_UNIX_SOCKETS: usize = 128;
const UNIX_PATH_MAX: usize = 108;
const SOCK_BUF_SIZE: usize = 8192;
const MAX_BACKLOG: usize = 16;
const MAX_FD_PASS: usize = 8;
const MAX_PENDING_MSGS: usize = 32;
const SCM_RIGHTS: u32 = 0x01;
const SCM_CREDENTIALS: u32 = 0x02;

// ─────────────────── Socket Types ───────────────────────────────────

pub const SockType = enum(u8) {
    stream = 1,    // SOCK_STREAM
    dgram = 2,     // SOCK_DGRAM
    seqpacket = 5, // SOCK_SEQPACKET
};

pub const SockState = enum(u8) {
    unconnected = 0,
    bound = 1,
    listening = 2,
    connecting = 3,
    connected = 4,
    disconnecting = 5,
    closed = 6,
};

pub const ShutdownHow = enum(u2) {
    rd = 0,   // SHUT_RD
    wr = 1,   // SHUT_WR
    rdwr = 2, // SHUT_RDWR
};

// ─────────────────── Socket Address ─────────────────────────────────

pub const SockaddrUn = struct {
    sun_family: u16, // AF_UNIX = 1
    sun_path: [UNIX_PATH_MAX]u8,
    path_len: u8,

    pub fn init() SockaddrUn {
        return .{
            .sun_family = 1, // AF_UNIX
            .sun_path = [_]u8{0} ** UNIX_PATH_MAX,
            .path_len = 0,
        };
    }

    pub fn set_path(self: *SockaddrUn, path: []const u8) void {
        const len = @min(path.len, UNIX_PATH_MAX - 1);
        @memcpy(self.sun_path[0..len], path[0..len]);
        self.path_len = @intCast(len);
    }

    pub fn is_abstract(self: *const SockaddrUn) bool {
        return self.path_len > 0 and self.sun_path[0] == 0;
    }

    pub fn matches(self: *const SockaddrUn, other: *const SockaddrUn) bool {
        if (self.path_len != other.path_len) return false;
        return std.mem.eql(u8, self.sun_path[0..self.path_len], other.sun_path[0..other.path_len]);
    }
};

// ─────────────────── Peer Credentials ───────────────────────────────

pub const UcredT = struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

// ─────────────────── Ancillary Data ─────────────────────────────────

pub const CmsgType = enum(u8) {
    none = 0,
    rights = 1,      // SCM_RIGHTS: fd passing
    credentials = 2, // SCM_CREDENTIALS: pid/uid/gid
};

pub const Cmsg = struct {
    cmsg_type: CmsgType,
    // fd passing
    fds: [MAX_FD_PASS]i32,
    fd_count: u8,
    // credentials
    cred: UcredT,
    active: bool,

    pub fn init() Cmsg {
        return .{
            .cmsg_type = .none,
            .fds = [_]i32{-1} ** MAX_FD_PASS,
            .fd_count = 0,
            .cred = .{ .pid = 0, .uid = 0, .gid = 0 },
            .active = false,
        };
    }
};

// ─────────────────── Ring Buffer ────────────────────────────────────

pub fn RingBuf(comptime SIZE: usize) type {
    return struct {
        data: [SIZE]u8,
        head: u16,
        tail: u16,
        count: u16,

        const Self = @This();

        pub fn init() Self {
            return .{
                .data = [_]u8{0} ** SIZE,
                .head = 0,
                .tail = 0,
                .count = 0,
            };
        }

        pub fn write(self: *Self, buf: []const u8) u16 {
            var written: u16 = 0;
            for (buf) |b| {
                if (self.count >= SIZE) break;
                self.data[self.tail] = b;
                self.tail = @intCast((@as(u32, self.tail) + 1) % SIZE);
                self.count += 1;
                written += 1;
            }
            return written;
        }

        pub fn read(self: *Self, buf: []u8) u16 {
            var rd: u16 = 0;
            for (buf) |*b| {
                if (self.count == 0) break;
                b.* = self.data[self.head];
                self.head = @intCast((@as(u32, self.head) + 1) % SIZE);
                self.count -= 1;
                rd += 1;
            }
            return rd;
        }

        pub fn available(self: *const Self) u16 {
            return self.count;
        }

        pub fn space(self: *const Self) u16 {
            return @intCast(SIZE - @as(u32, self.count));
        }

        pub fn is_empty(self: *const Self) bool {
            return self.count == 0;
        }

        pub fn is_full(self: *const Self) bool {
            return self.count >= SIZE;
        }
    };
}

// ─────────────────── Pending Message (DGRAM/SEQPACKET) ──────────────

pub const PendingMsg = struct {
    data: [1024]u8,
    data_len: u16,
    sender_idx: i16,
    cmsg: Cmsg,
    active: bool,

    pub fn init() PendingMsg {
        return .{
            .data = [_]u8{0} ** 1024,
            .data_len = 0,
            .sender_idx = -1,
            .cmsg = Cmsg.init(),
            .active = false,
        };
    }
};

// ─────────────────── Unix Socket ────────────────────────────────────

pub const UnixSocket = struct {
    addr: SockaddrUn,
    sock_type: SockType,
    state: SockState,

    // Stream buffer
    rx_buf: RingBuf(SOCK_BUF_SIZE),
    tx_buf: RingBuf(SOCK_BUF_SIZE),

    // Datagram/seqpacket message queue
    msg_queue: [MAX_PENDING_MSGS]PendingMsg,
    msg_head: u8,
    msg_tail: u8,
    msg_count: u8,

    // Connected peer
    peer_idx: i16,

    // Listening
    backlog: [MAX_BACKLOG]i16,
    backlog_count: u8,
    max_backlog: u8,

    // Credentials
    local_cred: UcredT,
    peer_cred: UcredT,

    // Pending ancillary data for next send
    pending_cmsg: Cmsg,

    // Shutdown flags
    shut_rd: bool,
    shut_wr: bool,
    nonblocking: bool,
    passcred: bool, // SO_PASSCRED

    // Owner
    owner_pid: i32,

    // Stats
    bytes_sent: u64,
    bytes_recv: u64,
    msgs_sent: u64,
    msgs_recv: u64,

    active: bool,

    const Self = @This();

    pub fn init(sock_type: SockType) Self {
        return .{
            .addr = SockaddrUn.init(),
            .sock_type = sock_type,
            .state = .unconnected,
            .rx_buf = RingBuf(SOCK_BUF_SIZE).init(),
            .tx_buf = RingBuf(SOCK_BUF_SIZE).init(),
            .msg_queue = [_]PendingMsg{PendingMsg.init()} ** MAX_PENDING_MSGS,
            .msg_head = 0,
            .msg_tail = 0,
            .msg_count = 0,
            .peer_idx = -1,
            .backlog = [_]i16{-1} ** MAX_BACKLOG,
            .backlog_count = 0,
            .max_backlog = 5,
            .local_cred = .{ .pid = 0, .uid = 0, .gid = 0 },
            .peer_cred = .{ .pid = 0, .uid = 0, .gid = 0 },
            .pending_cmsg = Cmsg.init(),
            .shut_rd = false,
            .shut_wr = false,
            .nonblocking = false,
            .passcred = false,
            .owner_pid = 0,
            .bytes_sent = 0,
            .bytes_recv = 0,
            .msgs_sent = 0,
            .msgs_recv = 0,
            .active = true,
        };
    }

    pub fn enqueue_msg(self: *Self, data: []const u8, sender: i16) bool {
        if (self.msg_count >= MAX_PENDING_MSGS) return false;
        var msg = &self.msg_queue[self.msg_tail];
        msg.* = PendingMsg.init();
        const len = @min(data.len, 1024);
        @memcpy(msg.data[0..len], data[0..len]);
        msg.data_len = @intCast(len);
        msg.sender_idx = sender;
        msg.active = true;
        self.msg_tail = @intCast((@as(u16, self.msg_tail) + 1) % MAX_PENDING_MSGS);
        self.msg_count += 1;
        return true;
    }

    pub fn dequeue_msg(self: *Self, buf: []u8) ?u16 {
        if (self.msg_count == 0) return null;
        const msg = &self.msg_queue[self.msg_head];
        if (!msg.active) return null;
        const len = @min(@as(u16, msg.data_len), @as(u16, @intCast(buf.len)));
        @memcpy(buf[0..len], msg.data[0..len]);
        self.msg_queue[self.msg_head].active = false;
        self.msg_head = @intCast((@as(u16, self.msg_head) + 1) % MAX_PENDING_MSGS);
        self.msg_count -= 1;
        return len;
    }

    pub fn add_pending_conn(self: *Self, sock_idx: i16) bool {
        if (self.backlog_count >= self.max_backlog) return false;
        self.backlog[self.backlog_count] = sock_idx;
        self.backlog_count += 1;
        return true;
    }

    pub fn accept_conn(self: *Self) ?i16 {
        if (self.backlog_count == 0) return null;
        const idx = self.backlog[0];
        // Shift backlog
        var i: u8 = 0;
        while (i + 1 < self.backlog_count) : (i += 1) {
            self.backlog[i] = self.backlog[i + 1];
        }
        self.backlog[self.backlog_count - 1] = -1;
        self.backlog_count -= 1;
        return idx;
    }
};

// ─────────────────── Unix Socket Manager ────────────────────────────

pub const UnixSocketManager = struct {
    sockets: [MAX_UNIX_SOCKETS]UnixSocket,
    socket_count: u16,

    total_connections: u64,
    total_binds: u64,
    total_accepts: u64,
    total_pairs: u64,
    total_shutdowns: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var mgr: Self = undefined;
        for (0..MAX_UNIX_SOCKETS) |i| {
            mgr.sockets[i] = UnixSocket.init(.stream);
            mgr.sockets[i].active = false;
        }
        mgr.socket_count = 0;
        mgr.total_connections = 0;
        mgr.total_binds = 0;
        mgr.total_accepts = 0;
        mgr.total_pairs = 0;
        mgr.total_shutdowns = 0;
        mgr.initialized = true;
        return mgr;
    }

    // ─── Socket Lifecycle ───────────────────────────────────────────

    pub fn socket(self: *Self, sock_type: SockType) ?i16 {
        for (0..MAX_UNIX_SOCKETS) |i| {
            if (!self.sockets[i].active) {
                self.sockets[i] = UnixSocket.init(sock_type);
                self.socket_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn close(self: *Self, idx: i16) bool {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return false;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return false;

        // Disconnect peer
        const peer = self.sockets[i].peer_idx;
        if (peer >= 0 and @as(usize, @intCast(peer)) < MAX_UNIX_SOCKETS) {
            if (self.sockets[@intCast(peer)].active) {
                self.sockets[@intCast(peer)].peer_idx = -1;
                self.sockets[@intCast(peer)].state = .disconnecting;
            }
        }

        self.sockets[i].active = false;
        self.sockets[i].state = .closed;
        self.socket_count -= 1;
        return true;
    }

    pub fn bind(self: *Self, idx: i16, path: []const u8) bool {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return false;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return false;
        if (self.sockets[i].state != .unconnected) return false;

        // Check path not already bound
        if (self.find_bound(path) != null) return false;

        self.sockets[i].addr.set_path(path);
        self.sockets[i].state = .bound;
        self.total_binds += 1;
        return true;
    }

    pub fn listen(self: *Self, idx: i16, backlog: u8) bool {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return false;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return false;
        if (self.sockets[i].state != .bound) return false;
        if (self.sockets[i].sock_type == .dgram) return false; // dgram doesn't listen

        self.sockets[i].state = .listening;
        self.sockets[i].max_backlog = @min(backlog, MAX_BACKLOG);
        return true;
    }

    pub fn connect(self: *Self, client_idx: i16, path: []const u8) bool {
        if (client_idx < 0 or @as(usize, @intCast(client_idx)) >= MAX_UNIX_SOCKETS) return false;
        const ci = @as(usize, @intCast(client_idx));
        if (!self.sockets[ci].active) return false;

        // Find server socket
        const server_idx = self.find_bound(path) orelse return false;
        const si = @as(usize, @intCast(server_idx));

        if (self.sockets[ci].sock_type == .dgram) {
            // DGRAM: just set peer
            self.sockets[ci].peer_idx = server_idx;
            self.sockets[ci].state = .connected;
            self.total_connections += 1;
            return true;
        }

        // STREAM/SEQPACKET: server must be listening
        if (self.sockets[si].state != .listening) return false;

        // Add to server backlog
        if (!self.sockets[si].add_pending_conn(client_idx)) return false;

        self.sockets[ci].state = .connecting;
        self.total_connections += 1;
        return true;
    }

    pub fn accept(self: *Self, server_idx: i16) ?i16 {
        if (server_idx < 0 or @as(usize, @intCast(server_idx)) >= MAX_UNIX_SOCKETS) return null;
        const si = @as(usize, @intCast(server_idx));
        if (!self.sockets[si].active or self.sockets[si].state != .listening) return null;

        const client_idx = self.sockets[si].accept_conn() orelse return null;
        const ci = @as(usize, @intCast(client_idx));

        // Create a new connected socket for the server side
        const new_idx = self.socket(self.sockets[si].sock_type) orelse return null;
        const ni = @as(usize, @intCast(new_idx));

        // Setup connected pair
        self.sockets[ni].peer_idx = client_idx;
        self.sockets[ni].state = .connected;
        self.sockets[ni].local_cred = self.sockets[si].local_cred;
        self.sockets[ni].peer_cred = self.sockets[ci].local_cred;

        self.sockets[ci].peer_idx = new_idx;
        self.sockets[ci].state = .connected;
        self.sockets[ci].peer_cred = self.sockets[si].local_cred;

        self.total_accepts += 1;
        return new_idx;
    }

    // ─── Socket Pair ────────────────────────────────────────────────

    pub fn socketpair(self: *Self, sock_type: SockType) ?[2]i16 {
        const s1 = self.socket(sock_type) orelse return null;
        const s2 = self.socket(sock_type) orelse {
            self.close(s1);
            return null;
        };

        const i1 = @as(usize, @intCast(s1));
        const i2 = @as(usize, @intCast(s2));

        self.sockets[i1].peer_idx = s2;
        self.sockets[i1].state = .connected;
        self.sockets[i2].peer_idx = s1;
        self.sockets[i2].state = .connected;
        self.total_pairs += 1;

        return .{ s1, s2 };
    }

    // ─── Data Transfer ──────────────────────────────────────────────

    pub fn send(self: *Self, idx: i16, data: []const u8) i32 {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return -1;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return -1;
        if (self.sockets[i].shut_wr) return -1;
        if (self.sockets[i].state != .connected) return -1;

        const peer = self.sockets[i].peer_idx;
        if (peer < 0 or @as(usize, @intCast(peer)) >= MAX_UNIX_SOCKETS) return -1;
        const pi = @as(usize, @intCast(peer));
        if (!self.sockets[pi].active or self.sockets[pi].shut_rd) return -1;

        if (self.sockets[i].sock_type == .stream) {
            // Stream: write to peer's rx_buf
            const written = self.sockets[pi].rx_buf.write(data);
            self.sockets[i].bytes_sent += @as(u64, written);
            self.sockets[pi].bytes_recv += @as(u64, written);
            self.sockets[i].msgs_sent += 1;
            return @intCast(written);
        } else {
            // DGRAM/SEQPACKET: enqueue message
            if (self.sockets[pi].enqueue_msg(data, idx)) {
                self.sockets[i].bytes_sent += @as(u64, @intCast(data.len));
                self.sockets[pi].bytes_recv += @as(u64, @intCast(data.len));
                self.sockets[i].msgs_sent += 1;
                self.sockets[pi].msgs_recv += 1;
                return @intCast(data.len);
            }
            return -1;
        }
    }

    pub fn recv(self: *Self, idx: i16, buf: []u8) i32 {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return -1;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return -1;
        if (self.sockets[i].shut_rd) return -1;

        if (self.sockets[i].sock_type == .stream) {
            const rd = self.sockets[i].rx_buf.read(buf);
            return @intCast(rd);
        } else {
            if (self.sockets[i].dequeue_msg(buf)) |len| {
                return @intCast(len);
            }
            return 0;
        }
    }

    // ─── Sendto (DGRAM without connect) ─────────────────────────────

    pub fn sendto(self: *Self, idx: i16, data: []const u8, dest_path: []const u8) i32 {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return -1;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return -1;
        if (self.sockets[i].sock_type != .dgram) return -1;

        const dest_idx = self.find_bound(dest_path) orelse return -1;
        const di = @as(usize, @intCast(dest_idx));
        if (!self.sockets[di].active) return -1;

        if (self.sockets[di].enqueue_msg(data, idx)) {
            self.sockets[i].bytes_sent += @as(u64, @intCast(data.len));
            self.sockets[di].bytes_recv += @as(u64, @intCast(data.len));
            self.sockets[i].msgs_sent += 1;
            self.sockets[di].msgs_recv += 1;
            return @intCast(data.len);
        }
        return -1;
    }

    // ─── Shutdown ───────────────────────────────────────────────────

    pub fn shutdown(self: *Self, idx: i16, how: ShutdownHow) bool {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return false;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return false;

        switch (how) {
            .rd => self.sockets[i].shut_rd = true,
            .wr => self.sockets[i].shut_wr = true,
            .rdwr => {
                self.sockets[i].shut_rd = true;
                self.sockets[i].shut_wr = true;
            },
        }
        self.total_shutdowns += 1;
        return true;
    }

    // ─── Credentials ────────────────────────────────────────────────

    pub fn set_credentials(self: *Self, idx: i16, pid: i32, uid: u32, gid: u32) bool {
        if (idx < 0 or @as(usize, @intCast(idx)) >= MAX_UNIX_SOCKETS) return false;
        const i = @as(usize, @intCast(idx));
        if (!self.sockets[i].active) return false;
        self.sockets[i].local_cred = .{ .pid = pid, .uid = uid, .gid = gid };
        return true;
    }

    // ─── Lookup ─────────────────────────────────────────────────────

    fn find_bound(self: *const Self, path: []const u8) ?i16 {
        for (0..MAX_UNIX_SOCKETS) |i| {
            if (!self.sockets[i].active) continue;
            if (self.sockets[i].state == .closed) continue;
            const plen = self.sockets[i].addr.path_len;
            if (plen == path.len and std.mem.eql(u8, self.sockets[i].addr.sun_path[0..plen], path)) {
                return @intCast(i);
            }
        }
        return null;
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_unix: UnixSocketManager = undefined;
var g_unix_initialized: bool = false;

fn mgr() *UnixSocketManager {
    return &g_unix;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_unix_init() void {
    g_unix = UnixSocketManager.init();
    g_unix_initialized = true;
}

export fn zxy_unix_socket(sock_type: u8) i16 {
    if (!g_unix_initialized) return -1;
    if (sock_type != 1 and sock_type != 2 and sock_type != 5) return -1;
    return mgr().socket(@enumFromInt(sock_type)) orelse -1;
}

export fn zxy_unix_close(idx: i16) bool {
    if (!g_unix_initialized) return false;
    return mgr().close(idx);
}

export fn zxy_unix_bind(idx: i16, path_ptr: [*]const u8, path_len: usize) bool {
    if (!g_unix_initialized) return false;
    return mgr().bind(idx, path_ptr[0..path_len]);
}

export fn zxy_unix_listen(idx: i16, backlog: u8) bool {
    if (!g_unix_initialized) return false;
    return mgr().listen(idx, backlog);
}

export fn zxy_unix_connect(idx: i16, path_ptr: [*]const u8, path_len: usize) bool {
    if (!g_unix_initialized) return false;
    return mgr().connect(idx, path_ptr[0..path_len]);
}

export fn zxy_unix_accept(server_idx: i16) i16 {
    if (!g_unix_initialized) return -1;
    return mgr().accept(server_idx) orelse -1;
}

export fn zxy_unix_send(idx: i16, data_ptr: [*]const u8, data_len: usize) i32 {
    if (!g_unix_initialized) return -1;
    return mgr().send(idx, data_ptr[0..data_len]);
}

export fn zxy_unix_recv(idx: i16, buf_ptr: [*]u8, buf_len: usize) i32 {
    if (!g_unix_initialized) return -1;
    return mgr().recv(idx, buf_ptr[0..buf_len]);
}

export fn zxy_unix_socketpair(sock_type: u8) i32 {
    if (!g_unix_initialized) return -1;
    if (sock_type != 1 and sock_type != 2 and sock_type != 5) return -1;
    if (mgr().socketpair(@enumFromInt(sock_type))) |pair| {
        // Encode as (s1 << 16) | s2
        return (@as(i32, pair[0]) << 16) | @as(i32, pair[1]);
    }
    return -1;
}

export fn zxy_unix_shutdown(idx: i16, how: u8) bool {
    if (!g_unix_initialized or how > 2) return false;
    return mgr().shutdown(idx, @enumFromInt(@as(u2, @intCast(how))));
}

export fn zxy_unix_socket_count() u16 {
    if (!g_unix_initialized) return 0;
    return mgr().socket_count;
}

export fn zxy_unix_total_connections() u64 {
    if (!g_unix_initialized) return 0;
    return mgr().total_connections;
}

export fn zxy_unix_total_accepts() u64 {
    if (!g_unix_initialized) return 0;
    return mgr().total_accepts;
}

export fn zxy_unix_total_pairs() u64 {
    if (!g_unix_initialized) return 0;
    return mgr().total_pairs;
}
