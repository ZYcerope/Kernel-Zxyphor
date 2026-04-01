// =============================================================================
// Kernel Zxyphor - BSD Socket Interface
// =============================================================================
// Berkeley Socket API abstraction. Provides a unified, protocol-independent
// interface for network communication. Maps to underlying TCP and UDP
// implementations. This is the primary interface for userspace networking
// via system calls.
//
// Supported socket types:
//   SOCK_STREAM  — TCP (connection-oriented, reliable)
//   SOCK_DGRAM   — UDP (connectionless, unreliable)
//   SOCK_RAW     — Raw IP (for ICMP, custom protocols)
//
// Address families:
//   AF_INET      — IPv4
//   AF_UNIX      — Unix domain sockets (local IPC)
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Address Family constants
// =============================================================================
pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

// Socket type constants
pub const SOCK_STREAM: u16 = 1;
pub const SOCK_DGRAM: u16 = 2;
pub const SOCK_RAW: u16 = 3;

// Socket options
pub const SOL_SOCKET: u16 = 1;
pub const SO_REUSEADDR: u16 = 2;
pub const SO_BROADCAST: u16 = 6;
pub const SO_SNDBUF: u16 = 7;
pub const SO_RCVBUF: u16 = 8;
pub const SO_KEEPALIVE: u16 = 9;
pub const SO_LINGER: u16 = 13;
pub const SO_RCVTIMEO: u16 = 20;
pub const SO_SNDTIMEO: u16 = 21;

// TCP options
pub const IPPROTO_TCP: u16 = 6;
pub const TCP_NODELAY: u16 = 1;
pub const TCP_MAXSEG: u16 = 2;
pub const TCP_KEEPIDLE: u16 = 4;
pub const TCP_KEEPINTVL: u16 = 5;
pub const TCP_KEEPCNT: u16 = 6;

// Shutdown modes
pub const SHUT_RD: u8 = 0;
pub const SHUT_WR: u8 = 1;
pub const SHUT_RDWR: u8 = 2;

// MSG flags
pub const MSG_PEEK: u32 = 0x02;
pub const MSG_WAITALL: u32 = 0x100;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_NOSIGNAL: u32 = 0x4000;

// =============================================================================
// Socket Address Structures
// =============================================================================
pub const SockAddrIn = struct {
    family: u16 = AF_INET,
    port: u16 = 0, // Network byte order
    addr: u32 = 0, // Network byte order
    zero: [8]u8 = [_]u8{0} ** 8,
};

pub const SockAddr = struct {
    family: u16 = AF_UNSPEC,
    data: [14]u8 = [_]u8{0} ** 14,
};

// =============================================================================
// Socket descriptor
// =============================================================================
pub const MAX_SOCKETS: usize = 512;

pub const SocketProtocol = enum(u8) {
    none,
    tcp,
    udp,
    raw,
};

pub const Socket = struct {
    // Identity
    family: u16 = AF_UNSPEC,
    sock_type: u16 = 0,
    protocol: SocketProtocol = .none,

    // Protocol-specific handle
    proto_handle: u16 = 0, // Index into TCP/UDP socket table

    // Binding info
    local_addr: u32 = 0,
    local_port: u16 = 0,
    remote_addr: u32 = 0,
    remote_port: u16 = 0,

    // Options
    reuse_addr: bool = false,
    broadcast_enabled: bool = false,
    keepalive: bool = false,
    nodelay: bool = false,

    // State
    is_valid: bool = false,
    is_bound: bool = false,
    is_connected: bool = false,
    is_listening: bool = false,

    // Owner
    owner_pid: u32 = 0,
};

// =============================================================================
// Socket Table
// =============================================================================
var socket_table: [MAX_SOCKETS]Socket = undefined;

var socket_stats: SocketStats = .{};

pub const SocketStats = struct {
    created: u64 = 0,
    closed: u64 = 0,
    active: u64 = 0,
    tcp_sockets: u64 = 0,
    udp_sockets: u64 = 0,
};

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&socket_table) |*s| {
        s.* = Socket{};
    }
    socket_stats = SocketStats{};
    main.klog(.info, "socket: BSD socket interface initialized ({d} max)", .{MAX_SOCKETS});
}

// =============================================================================
// socket() — create a new socket
// =============================================================================
pub fn socketCreate(family: u16, sock_type: u16, protocol: u16) i32 {
    _ = protocol;

    if (family != AF_INET and family != AF_UNIX) return -1;

    // Determine protocol
    const proto: SocketProtocol = switch (sock_type) {
        SOCK_STREAM => .tcp,
        SOCK_DGRAM => .udp,
        SOCK_RAW => .raw,
        else => return -1,
    };

    // Find free slot
    for (&socket_table, 0..) |*s, i| {
        if (!s.is_valid) {
            s.* = Socket{};
            s.family = family;
            s.sock_type = sock_type;
            s.protocol = proto;
            s.is_valid = true;

            // Create underlying protocol socket
            switch (proto) {
                .tcp => {
                    if (main.tcp.create()) |handle| {
                        s.proto_handle = handle;
                    } else {
                        s.is_valid = false;
                        return -1;
                    }
                    socket_stats.tcp_sockets += 1;
                },
                .udp => {
                    if (main.udp.create()) |handle| {
                        s.proto_handle = handle;
                    } else {
                        s.is_valid = false;
                        return -1;
                    }
                    socket_stats.udp_sockets += 1;
                },
                else => {},
            }

            socket_stats.created += 1;
            socket_stats.active += 1;
            return @intCast(i);
        }
    }
    return -1; // No free sockets
}

// =============================================================================
// bind() — bind to a local address
// =============================================================================
pub fn socketBind(fd: i32, addr: *const SockAddrIn) i32 {
    const s = getSocket(fd) orelse return -1;
    if (s.is_bound) return -1;

    const local_addr = ntohl(addr.addr);
    const local_port = ntohs(addr.port);

    switch (s.protocol) {
        .tcp => {
            if (!main.tcp.bind(s.proto_handle, local_addr, local_port)) return -1;
        },
        .udp => {
            if (!main.udp.bind(s.proto_handle, local_addr, local_port)) return -1;
        },
        else => return -1,
    }

    s.local_addr = local_addr;
    s.local_port = local_port;
    s.is_bound = true;
    return 0;
}

// =============================================================================
// listen() — start listening for connections (TCP only)
// =============================================================================
pub fn socketListen(fd: i32, backlog: u32) i32 {
    const s = getSocket(fd) orelse return -1;
    if (s.protocol != .tcp) return -1;
    if (!s.is_bound) return -1;

    if (!main.tcp.listen(s.proto_handle, @truncate(backlog))) return -1;

    s.is_listening = true;
    return 0;
}

// =============================================================================
// accept() — accept a connection (TCP only)
// =============================================================================
pub fn socketAccept(fd: i32, addr: ?*SockAddrIn) i32 {
    const s = getSocket(fd) orelse return -1;
    if (s.protocol != .tcp or !s.is_listening) return -1;

    const new_handle = main.tcp.accept(s.proto_handle) orelse return -1;

    // Create new socket for the accepted connection
    for (&socket_table, 0..) |*ns, i| {
        if (!ns.is_valid) {
            ns.* = Socket{};
            ns.family = s.family;
            ns.sock_type = s.sock_type;
            ns.protocol = .tcp;
            ns.proto_handle = new_handle;
            ns.is_valid = true;
            ns.is_bound = true;
            ns.is_connected = true;

            // Fill in client address if requested
            if (addr) |a| {
                a.family = AF_INET;
                a.port = htons(ns.remote_port);
                a.addr = htonl(ns.remote_addr);
            }

            socket_stats.created += 1;
            socket_stats.active += 1;
            socket_stats.tcp_sockets += 1;
            return @intCast(i);
        }
    }
    return -1;
}

// =============================================================================
// connect() — connect to a remote address
// =============================================================================
pub fn socketConnect(fd: i32, addr: *const SockAddrIn) i32 {
    const s = getSocket(fd) orelse return -1;

    const remote_addr = ntohl(addr.addr);
    const remote_port = ntohs(addr.port);

    switch (s.protocol) {
        .tcp => {
            if (!main.tcp.connect(s.proto_handle, remote_addr, remote_port)) return -1;
        },
        .udp => {
            if (!main.udp.connectSocket(s.proto_handle, remote_addr, remote_port)) return -1;
        },
        else => return -1,
    }

    s.remote_addr = remote_addr;
    s.remote_port = remote_port;
    s.is_connected = true;
    return 0;
}

// =============================================================================
// send() — send data on a connected socket
// =============================================================================
pub fn socketSend(fd: i32, data: []const u8, flags: u32) i32 {
    _ = flags;
    const s = getSocket(fd) orelse return -1;
    if (!s.is_connected) return -1;

    return switch (s.protocol) {
        .tcp => main.tcp.send(s.proto_handle, data),
        .udp => main.udp.send(s.proto_handle, data),
        else => -1,
    };
}

// =============================================================================
// recv() — receive data from a connected socket
// =============================================================================
pub fn socketRecv(fd: i32, buf: []u8, flags: u32) i32 {
    _ = flags;
    const s = getSocket(fd) orelse return -1;

    return switch (s.protocol) {
        .tcp => main.tcp.recv(s.proto_handle, buf),
        .udp => main.udp.recv(s.proto_handle, buf),
        else => -1,
    };
}

// =============================================================================
// sendto() — send datagram to a specific address (UDP)
// =============================================================================
pub fn socketSendto(fd: i32, data: []const u8, addr: *const SockAddrIn) i32 {
    const s = getSocket(fd) orelse return -1;
    if (s.protocol != .udp) return -1;

    return main.udp.sendto(s.proto_handle, data, ntohl(addr.addr), ntohs(addr.port));
}

// =============================================================================
// recvfrom() — receive datagram with source address (UDP)
// =============================================================================
pub fn socketRecvfrom(fd: i32, buf: []u8, addr: *SockAddrIn) i32 {
    const s = getSocket(fd) orelse return -1;
    if (s.protocol != .udp) return -1;

    var src_addr: u32 = 0;
    var src_port: u16 = 0;
    const result = main.udp.recvfrom(s.proto_handle, buf, &src_addr, &src_port);
    if (result >= 0) {
        addr.family = AF_INET;
        addr.addr = htonl(src_addr);
        addr.port = htons(src_port);
    }
    return result;
}

// =============================================================================
// close() — close a socket
// =============================================================================
pub fn socketClose(fd: i32) i32 {
    const s = getSocket(fd) orelse return -1;

    switch (s.protocol) {
        .tcp => main.tcp.close(s.proto_handle),
        .udp => main.udp.closeSocket(s.proto_handle),
        else => {},
    }

    s.is_valid = false;
    socket_stats.active -|= 1;
    socket_stats.closed += 1;
    return 0;
}

// =============================================================================
// setsockopt() — set socket option
// =============================================================================
pub fn socketSetopt(fd: i32, level: u16, optname: u16, optval: u32) i32 {
    const s = getSocket(fd) orelse return -1;

    if (level == SOL_SOCKET) {
        switch (optname) {
            SO_REUSEADDR => {
                s.reuse_addr = optval != 0;
                return 0;
            },
            SO_BROADCAST => {
                s.broadcast_enabled = optval != 0;
                if (s.protocol == .udp) {
                    _ = main.udp.setBroadcast(s.proto_handle, s.broadcast_enabled);
                }
                return 0;
            },
            SO_KEEPALIVE => {
                s.keepalive = optval != 0;
                return 0;
            },
            else => return -1,
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            TCP_NODELAY => {
                s.nodelay = optval != 0;
                return 0;
            },
            else => return -1,
        }
    }
    return -1;
}

// =============================================================================
// shutdown() — partially close a socket
// =============================================================================
pub fn socketShutdown(fd: i32, how: u8) i32 {
    const s = getSocket(fd) orelse return -1;
    _ = how;

    if (s.protocol == .tcp) {
        main.tcp.close(s.proto_handle);
    }
    return 0;
}

// =============================================================================
// Internal helpers
// =============================================================================
fn getSocket(fd: i32) ?*Socket {
    if (fd < 0 or fd >= MAX_SOCKETS) return null;
    const s = &socket_table[@intCast(fd)];
    if (!s.is_valid) return null;
    return s;
}

pub fn getStats() SocketStats {
    return socket_stats;
}

// =============================================================================
// Byte order conversion (network = big endian)
// =============================================================================
pub fn htons(val: u16) u16 {
    return @as(u16, @truncate(val >> 8)) | (@as(u16, @truncate(val & 0xFF)) << 8);
}

pub fn ntohs(val: u16) u16 {
    return htons(val);
}

pub fn htonl(val: u32) u32 {
    return (@as(u32, @truncate(val >> 24))) |
        (@as(u32, @truncate((val >> 8) & 0xFF)) << 8) |
        (@as(u32, @truncate((val >> 16) & 0xFF)) << 16) | // swapped
        (@as(u32, @truncate(val & 0xFF)) << 24);
}

pub fn ntohl(val: u32) u32 {
    return htonl(val);
}
