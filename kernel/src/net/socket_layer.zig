// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Socket Layer: Berkeley Sockets, Socket Buffers, Protocol Registration
// Linux 6.x+ compatible with Zxyphor zero-copy and capability-based extensions

const std = @import("std");

// ============================================================================
// Address Families
// ============================================================================

pub const AF_UNSPEC: u16 = 0;
pub const AF_LOCAL: u16 = 1;
pub const AF_UNIX: u16 = AF_LOCAL;
pub const AF_INET: u16 = 2;
pub const AF_AX25: u16 = 3;
pub const AF_IPX: u16 = 4;
pub const AF_APPLETALK: u16 = 5;
pub const AF_NETROM: u16 = 6;
pub const AF_BRIDGE: u16 = 7;
pub const AF_ATMPVC: u16 = 8;
pub const AF_X25: u16 = 9;
pub const AF_INET6: u16 = 10;
pub const AF_ROSE: u16 = 11;
pub const AF_DECnet: u16 = 12;
pub const AF_NETBEUI: u16 = 13;
pub const AF_SECURITY: u16 = 14;
pub const AF_KEY: u16 = 15;
pub const AF_NETLINK: u16 = 16;
pub const AF_PACKET: u16 = 17;
pub const AF_ASH: u16 = 18;
pub const AF_ECONET: u16 = 19;
pub const AF_ATMSVC: u16 = 20;
pub const AF_RDS: u16 = 21;
pub const AF_SNA: u16 = 22;
pub const AF_IRDA: u16 = 23;
pub const AF_PPPOX: u16 = 24;
pub const AF_WANPIPE: u16 = 25;
pub const AF_LLC: u16 = 26;
pub const AF_IB: u16 = 27;
pub const AF_MPLS: u16 = 28;
pub const AF_CAN: u16 = 29;
pub const AF_TIPC: u16 = 30;
pub const AF_BLUETOOTH: u16 = 31;
pub const AF_IUCV: u16 = 32;
pub const AF_RXRPC: u16 = 33;
pub const AF_ISDN: u16 = 34;
pub const AF_PHONET: u16 = 35;
pub const AF_IEEE802154: u16 = 36;
pub const AF_CAIF: u16 = 37;
pub const AF_ALG: u16 = 38;
pub const AF_NFC: u16 = 39;
pub const AF_VSOCK: u16 = 40;
pub const AF_KCM: u16 = 41;
pub const AF_QIPCRTR: u16 = 42;
pub const AF_SMC: u16 = 43;
pub const AF_XDP: u16 = 44;
pub const AF_MCTP: u16 = 45;
pub const AF_MAX: u16 = 46;

// ============================================================================
// Socket Types
// ============================================================================

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_RDM: u32 = 4;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_DCCP: u32 = 6;
pub const SOCK_PACKET: u32 = 10;

pub const SOCK_NONBLOCK: u32 = 0o4000;
pub const SOCK_CLOEXEC: u32 = 0o2000000;

// ============================================================================
// Socket Options
// ============================================================================

pub const SOL_SOCKET: i32 = 1;
pub const SOL_IP: i32 = 0;
pub const SOL_TCP: i32 = 6;
pub const SOL_UDP: i32 = 17;
pub const SOL_IPV6: i32 = 41;
pub const SOL_ICMPV6: i32 = 58;
pub const SOL_RAW: i32 = 255;
pub const SOL_PACKET: i32 = 263;
pub const SOL_NETLINK: i32 = 270;
pub const SOL_TLS: i32 = 282;
pub const SOL_XDP: i32 = 283;

pub const SO_DEBUG: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_DONTROUTE: i32 = 5;
pub const SO_BROADCAST: i32 = 6;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_OOBINLINE: i32 = 10;
pub const SO_NO_CHECK: i32 = 11;
pub const SO_PRIORITY: i32 = 12;
pub const SO_LINGER: i32 = 13;
pub const SO_BSDCOMPAT: i32 = 14;
pub const SO_REUSEPORT: i32 = 15;
pub const SO_PASSCRED: i32 = 16;
pub const SO_PEERCRED: i32 = 17;
pub const SO_RCVLOWAT: i32 = 18;
pub const SO_SNDLOWAT: i32 = 19;
pub const SO_RCVTIMEO_OLD: i32 = 20;
pub const SO_SNDTIMEO_OLD: i32 = 21;
pub const SO_ACCEPTCONN: i32 = 30;
pub const SO_PEERSEC: i32 = 31;
pub const SO_SNDBUFFORCE: i32 = 32;
pub const SO_RCVBUFFORCE: i32 = 33;
pub const SO_PROTOCOL: i32 = 38;
pub const SO_DOMAIN: i32 = 39;
pub const SO_RCVTIMEO_NEW: i32 = 66;
pub const SO_SNDTIMEO_NEW: i32 = 67;
pub const SO_DETACH_REUSEPORT_BPF: i32 = 68;
pub const SO_PREFER_BUSY_POLL: i32 = 69;
pub const SO_BUSY_POLL_BUDGET: i32 = 70;
pub const SO_NETNS_COOKIE: i32 = 71;
pub const SO_BUF_LOCK: i32 = 72;
pub const SO_RESERVE_MEM: i32 = 73;
pub const SO_TXREHASH: i32 = 74;
pub const SO_RCVMARK: i32 = 75;

// TCP Socket Options
pub const TCP_NODELAY: i32 = 1;
pub const TCP_MAXSEG: i32 = 2;
pub const TCP_CORK: i32 = 3;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
pub const TCP_SYNCNT: i32 = 7;
pub const TCP_LINGER2: i32 = 8;
pub const TCP_DEFER_ACCEPT: i32 = 9;
pub const TCP_WINDOW_CLAMP: i32 = 10;
pub const TCP_INFO: i32 = 11;
pub const TCP_QUICKACK: i32 = 12;
pub const TCP_CONGESTION: i32 = 13;
pub const TCP_MD5SIG: i32 = 14;
pub const TCP_THIN_LINEAR_TIMEOUTS: i32 = 16;
pub const TCP_THIN_DUPACK: i32 = 17;
pub const TCP_USER_TIMEOUT: i32 = 18;
pub const TCP_REPAIR: i32 = 19;
pub const TCP_REPAIR_QUEUE: i32 = 20;
pub const TCP_QUEUE_SEQ: i32 = 21;
pub const TCP_REPAIR_OPTIONS: i32 = 22;
pub const TCP_FASTOPEN: i32 = 23;
pub const TCP_TIMESTAMP: i32 = 24;
pub const TCP_NOTSENT_LOWAT: i32 = 25;
pub const TCP_CC_INFO: i32 = 26;
pub const TCP_SAVE_SYN: i32 = 27;
pub const TCP_SAVED_SYN: i32 = 28;
pub const TCP_REPAIR_WINDOW: i32 = 29;
pub const TCP_FASTOPEN_CONNECT: i32 = 30;
pub const TCP_ULP: i32 = 31;
pub const TCP_MD5SIG_EXT: i32 = 32;
pub const TCP_FASTOPEN_KEY: i32 = 33;
pub const TCP_FASTOPEN_NO_COOKIE: i32 = 34;
pub const TCP_ZEROCOPY_RECEIVE: i32 = 35;
pub const TCP_INQ: i32 = 36;
pub const TCP_TX_DELAY: i32 = 37;
pub const TCP_AO_ADD_KEY: i32 = 38;
pub const TCP_AO_DEL_KEY: i32 = 39;
pub const TCP_AO_INFO: i32 = 40;
pub const TCP_AO_GET_KEYS: i32 = 41;
pub const TCP_AO_REPAIR: i32 = 42;

// ============================================================================
// Socket Address Structures
// ============================================================================

pub const SockAddr = extern struct {
    sa_family: u16,
    sa_data: [14]u8,
};

pub const SockAddrIn = extern struct {
    sin_family: u16,
    sin_port: u16,    // Network byte order
    sin_addr: u32,    // Network byte order
    sin_zero: [8]u8,
};

pub const SockAddrIn6 = extern struct {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    sin6_scope_id: u32,
};

pub const SockAddrUn = extern struct {
    sun_family: u16,
    sun_path: [108]u8,
};

pub const SockAddrNl = extern struct {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
};

pub const SockAddrLl = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

pub const SockAddrStorage = extern struct {
    ss_family: u16,
    __ss_padding: [126]u8,
};

// ============================================================================
// Socket Buffer (sk_buff)
// ============================================================================

pub const SkbSharedInfo = struct {
    nr_frags: u8,
    tx_flags: u8,
    gso_size: u16,
    gso_segs: u16,
    gso_type: u32,
    frag_list: ?*SkBuff,
    hwtstamps: SkbHwTimestamps,
    tskey: u32,
    dataref: u32,
    frags: [17]SkbFrag,
};

pub const SkbFrag = struct {
    page: u64,         // Page frame number
    offset: u32,
    size: u32,
};

pub const SkbHwTimestamps = struct {
    hwtstamp: u64,     // Nanoseconds
};

pub const SkBuff = struct {
    // Packet data pointers
    head: [*]u8,
    data: [*]u8,
    tail: u32,
    end: u32,
    len: u32,
    data_len: u32,     // Paged data length
    // Control block
    cb: [48]u8,
    // Socket association
    sk: ?*Sock,
    // Network device
    dev: ?*anyopaque,    // NetDevice
    // Protocol headers
    mac_header: u16,
    network_header: u16,
    transport_header: u16,
    // Queue mapping
    queue_mapping: u16,
    // Cloned
    cloned: bool,
    nohdr: bool,
    fclone: u2,
    pkt_type: u3,
    ip_summed: u2,
    // Priority
    priority: u32,
    // Protocol
    protocol: u16,
    // VLAN
    vlan_proto: u16,
    vlan_tci: u16,
    // Hash
    hash: u32,
    sw_hash: bool,
    l4_hash: bool,
    // Flags
    inner_protocol_type: u1,
    remcsum_offload: bool,
    offload_fwd_mark: bool,
    offload_l3_fwd_mark: bool,
    redirected: bool,
    from_ingress: bool,
    nf_skip_egress: bool,
    decrypted: bool,
    slow_gro: bool,
    csum_not_inet: bool,
    // TC
    tc_index: u16,
    tc_at_ingress: bool,
    tc_skip_classify: bool,
    // Timestamp
    tstamp: u64,
    // Mark
    mark: u32,
    // Shared info
    shinfo: ?*SkbSharedInfo,
    // Destructor
    destructor: ?*const fn (*SkBuff) void,
    // Security
    secmark: u32,
    // Conntrack
    _nfct: u64,

    pub fn headroom(self: *const SkBuff) u32 {
        return @intCast(@intFromPtr(self.data) - @intFromPtr(self.head));
    }

    pub fn tailroom(self: *const SkBuff) u32 {
        return self.end - self.tail;
    }

    pub fn is_nonlinear(self: *const SkBuff) bool {
        return self.data_len > 0;
    }

    pub fn headlen(self: *const SkBuff) u32 {
        return self.len - self.data_len;
    }

    pub fn put(self: *SkBuff, bytes: u32) [*]u8 {
        const old_tail = self.tail;
        self.tail += bytes;
        self.len += bytes;
        return self.head + old_tail;
    }

    pub fn push(self: *SkBuff, bytes: u32) [*]u8 {
        self.data -= bytes;
        self.len += bytes;
        return self.data;
    }

    pub fn pull(self: *SkBuff, bytes: u32) [*]u8 {
        self.data += bytes;
        self.len -= bytes;
        return self.data;
    }

    pub fn reserve(self: *SkBuff, bytes: u32) void {
        self.data += bytes;
        self.tail += bytes;
    }

    pub fn trim(self: *SkBuff, new_len: u32) void {
        if (new_len < self.len) {
            self.len = new_len;
            self.tail = @intCast(@intFromPtr(self.data) - @intFromPtr(self.head) + new_len);
        }
    }

    pub fn reset_network_header(self: *SkBuff) void {
        self.network_header = @intCast(@intFromPtr(self.data) - @intFromPtr(self.head));
    }

    pub fn reset_transport_header(self: *SkBuff) void {
        self.transport_header = @intCast(@intFromPtr(self.data) - @intFromPtr(self.head));
    }

    pub fn reset_mac_header(self: *SkBuff) void {
        self.mac_header = @intCast(@intFromPtr(self.data) - @intFromPtr(self.head));
    }
};

// ============================================================================
// Socket Structure
// ============================================================================

pub const SockState = enum(u8) {
    free = 0,
    unconnected = 1,
    connecting = 2,
    connected = 3,
    disconnecting = 4,
};

pub const SockFlags = packed struct(u32) {
    dead: bool = false,
    done: bool = false,
    urginline: bool = false,
    keepopen: bool = false,
    linger: bool = false,
    destroy: bool = false,
    broadcast: bool = false,
    no_check: bool = false,
    // TCP flags
    no_delay: bool = false,
    cork: bool = false,
    defer_accept: bool = false,
    // Generic
    zerocopy: bool = false,
    timestamp: bool = false,
    wifi_status: bool = false,
    timestamping_any: bool = false,
    select_err_queue: bool = false,
    rcvtstamp: bool = false,
    _reserved: u15 = 0,
};

pub const Sock = struct {
    // Common
    sk_family: u16,
    sk_type: u16,
    sk_protocol: u16,
    sk_state: u8,
    sk_reuse: u8,
    sk_reuseport: bool,
    sk_bound_dev_if: i32,
    // Socket layer
    sk_socket: ?*Socket,
    // Network namespace
    sk_net: ?*anyopaque,
    // Receive buffer
    sk_receive_queue: SkBuffHead,
    sk_rmem_alloc: u32,
    sk_rcvbuf: u32,
    // Send buffer
    sk_write_queue: SkBuffHead,
    sk_wmem_alloc: u32,
    sk_wmem_queued: u32,
    sk_sndbuf: u32,
    // Backlog
    sk_backlog: SkBuffHead,
    sk_max_ack_backlog: u32,
    sk_ack_backlog: u32,
    // Priority and mark
    sk_priority: u32,
    sk_mark: u32,
    // Binding
    sk_rcv_saddr: u32,
    sk_saddr: u32,
    sk_daddr: u32,
    sk_dport: u16,
    sk_sport: u16,
    // Routing
    sk_dst_cache: ?*anyopaque,
    // Timestamps
    sk_rcvtimeo: i64,
    sk_sndtimeo: i64,
    // User ID
    sk_uid: u32,
    // Lock
    sk_lock: u64,
    // Callbacks
    sk_data_ready: ?*const fn (*Sock) void,
    sk_write_space: ?*const fn (*Sock) void,
    sk_error_report: ?*const fn (*Sock) void,
    sk_state_change: ?*const fn (*Sock) void,
    sk_destruct: ?*const fn (*Sock) void,
    // Flags
    sk_flags: SockFlags,
    sk_shutdown: u8,
    // Error
    sk_err: i32,
    sk_err_soft: i32,
    // Protocol private
    sk_prot: ?*const Proto,
    sk_prot_creator: ?*const Proto,
    // Timer
    sk_timer_expires: u64,
    // Drops
    sk_drops: u64,
    // Memory accounting
    sk_forward_alloc: i64,
    sk_reserved_mem: u32,
    // Security
    sk_security: ?*anyopaque,
    // Cgroup
    sk_cgrp_data: u64,
    // Linger
    sk_lingertime: u64,
    sk_max_pacing_rate: u64,
    // BPF
    sk_filter: ?*anyopaque,
    // Private data
    sk_user_data: ?*anyopaque,
};

pub const SkBuffHead = struct {
    next: ?*SkBuff,
    prev: ?*SkBuff,
    qlen: u32,
};

pub const Socket = struct {
    state: SockState,
    sock_type: u16,
    flags: u64,
    file: ?*anyopaque,  // struct file
    sk: ?*Sock,
    ops: ?*const ProtoOps,
    wq: u64,
};

// ============================================================================
// Protocol Operations (BSD socket → transport)
// ============================================================================

pub const ProtoOps = struct {
    family: u16,
    owner: ?*anyopaque,
    release: ?*const fn (*Socket) i32,
    bind: ?*const fn (*Socket, *SockAddr, i32) i32,
    connect: ?*const fn (*Socket, *SockAddr, i32, i32) i32,
    socketpair: ?*const fn (*Socket, *Socket) i32,
    accept: ?*const fn (*Socket, *Socket, i32, bool) i32,
    getname: ?*const fn (*Socket, *SockAddr, i32) i32,
    poll: ?*const fn (?*anyopaque, *Socket, ?*anyopaque) u32,
    ioctl: ?*const fn (*Socket, u32, u64) i32,
    gettstamp: ?*const fn (*Socket, ?*anyopaque, bool, bool) i32,
    listen: ?*const fn (*Socket, i32) i32,
    shutdown: ?*const fn (*Socket, i32) i32,
    setsockopt: ?*const fn (*Socket, i32, i32, ?*anyopaque, u32) i32,
    getsockopt: ?*const fn (*Socket, i32, i32, ?*anyopaque, ?*u32) i32,
    sendmsg: ?*const fn (*Socket, *MsgHdr, u64) i32,
    recvmsg: ?*const fn (*Socket, *MsgHdr, u64, i32) i32,
    mmap: ?*const fn (?*anyopaque, *Socket, ?*anyopaque) i32,
    splice_read: ?*const fn (*Socket, *i64, ?*anyopaque, u64, u32) i64,
    sendmsg_locked: ?*const fn (*Sock, *MsgHdr, u64) i32,
    sendpage_locked: ?*const fn (*Sock, ?*anyopaque, i32, u64, i32) i32,
};

// ============================================================================
// Transport Protocol (e.g., TCP, UDP)
// ============================================================================

pub const Proto = struct {
    name: [32]u8,
    owner: ?*anyopaque,
    close: ?*const fn (*Sock, i64) void,
    pre_connect: ?*const fn (*Sock, *SockAddr, i32) i32,
    connect: ?*const fn (*Sock, *SockAddr, i32) i32,
    disconnect: ?*const fn (*Sock, i32) i32,
    accept: ?*const fn (*Sock, i32, *i32, bool) ?*Sock,
    ioctl: ?*const fn (*Sock, i32, u64) i32,
    init: ?*const fn (*Sock) i32,
    destroy: ?*const fn (*Sock) void,
    shutdown: ?*const fn (*Sock, i32) void,
    setsockopt: ?*const fn (*Sock, i32, i32, ?*anyopaque, u32) i32,
    getsockopt: ?*const fn (*Sock, i32, i32, ?*anyopaque, ?*u32) i32,
    keepalive: ?*const fn (*Sock, i32) void,
    sendmsg: ?*const fn (*Sock, *MsgHdr, u64) i32,
    recvmsg: ?*const fn (*Sock, *MsgHdr, u64, i32) i32,
    bind: ?*const fn (*Sock, *SockAddr, i32) i32,
    bind_add: ?*const fn (*Sock, *SockAddr, i32) i32,
    backlog_rcv: ?*const fn (*Sock, *SkBuff) i32,
    release_cb: ?*const fn (*Sock) void,
    hash: ?*const fn (*Sock) i32,
    unhash: ?*const fn (*Sock) void,
    get_port: ?*const fn (*Sock, u16) i32,
    // Slab allocator
    obj_size: u32,
    slab_flags: u32,
    // Per-CPU
    orphan_count: u64,
    // Name
    memory_allocated: u64,
    per_cpu_fw_alloc: u64,
    sockets_allocated: u64,
    // Pressure
    memory_pressure: bool,
    sysctl_mem: [3]i64,
    sysctl_wmem: [3]u32,
    sysctl_rmem: [3]u32,
    max_header: u32,
    // Diag
    diag_destroy: ?*const fn (*Sock, i32) i32,
};

// ============================================================================
// Message Header
// ============================================================================

pub const MsgHdr = struct {
    msg_name: ?*SockAddr,
    msg_namelen: u32,
    msg_iov: ?*Iovec,
    msg_iovlen: u64,
    msg_control: ?*anyopaque,
    msg_controllen: u64,
    msg_flags: u32,
};

pub const Iovec = struct {
    iov_base: [*]u8,
    iov_len: u64,
};

// Message flags
pub const MSG_OOB: u32 = 1;
pub const MSG_PEEK: u32 = 2;
pub const MSG_DONTROUTE: u32 = 4;
pub const MSG_TRYHARD: u32 = 4;
pub const MSG_CTRUNC: u32 = 8;
pub const MSG_PROBE: u32 = 0x10;
pub const MSG_TRUNC: u32 = 0x20;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_EOR: u32 = 0x80;
pub const MSG_WAITALL: u32 = 0x100;
pub const MSG_FIN: u32 = 0x200;
pub const MSG_SYN: u32 = 0x400;
pub const MSG_CONFIRM: u32 = 0x800;
pub const MSG_RST: u32 = 0x1000;
pub const MSG_ERRQUEUE: u32 = 0x2000;
pub const MSG_NOSIGNAL: u32 = 0x4000;
pub const MSG_MORE: u32 = 0x8000;
pub const MSG_WAITFORONE: u32 = 0x10000;
pub const MSG_SENDPAGE_NOPOLICY: u32 = 0x10000;
pub const MSG_BATCH: u32 = 0x40000;
pub const MSG_EOF: u32 = MSG_FIN;
pub const MSG_NO_SHARED_FRAGS: u32 = 0x80000;
pub const MSG_SENDPAGE_DECRYPTED: u32 = 0x100000;
pub const MSG_ZEROCOPY: u32 = 0x4000000;
pub const MSG_FASTOPEN: u32 = 0x20000000;
pub const MSG_CMSG_CLOEXEC: u32 = 0x40000000;

// ============================================================================
// Control Messages (cmsg)
// ============================================================================

pub const CmsgHdr = extern struct {
    cmsg_len: u64,
    cmsg_level: i32,
    cmsg_type: i32,
};

// IP control messages
pub const IP_TOS: i32 = 1;
pub const IP_TTL: i32 = 2;
pub const IP_HDRINCL: i32 = 3;
pub const IP_OPTIONS: i32 = 4;
pub const IP_ROUTER_ALERT: i32 = 5;
pub const IP_RECVOPTS: i32 = 6;
pub const IP_RETOPTS: i32 = 7;
pub const IP_PKTINFO: i32 = 8;
pub const IP_PKTOPTIONS: i32 = 9;
pub const IP_MTU_DISCOVER: i32 = 10;
pub const IP_RECVERR: i32 = 11;
pub const IP_RECVTTL: i32 = 12;
pub const IP_RECVTOS: i32 = 13;
pub const IP_MTU: i32 = 14;
pub const IP_FREEBIND: i32 = 15;
pub const IP_ADD_MEMBERSHIP: i32 = 35;
pub const IP_DROP_MEMBERSHIP: i32 = 36;
pub const IP_MULTICAST_IF: i32 = 32;
pub const IP_MULTICAST_TTL: i32 = 33;
pub const IP_MULTICAST_LOOP: i32 = 34;
pub const IP_TRANSPARENT: i32 = 19;
pub const IP_BIND_ADDRESS_NO_PORT: i32 = 24;
pub const IP_RECVORIGDSTADDR: i32 = 20;

// ============================================================================
// Netlink
// ============================================================================

pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_UNUSED: i32 = 1;
pub const NETLINK_USERSOCK: i32 = 2;
pub const NETLINK_FIREWALL: i32 = 3;
pub const NETLINK_SOCK_DIAG: i32 = 4;
pub const NETLINK_NFLOG: i32 = 5;
pub const NETLINK_XFRM: i32 = 6;
pub const NETLINK_SELINUX: i32 = 7;
pub const NETLINK_ISCSI: i32 = 8;
pub const NETLINK_AUDIT: i32 = 9;
pub const NETLINK_FIB_LOOKUP: i32 = 10;
pub const NETLINK_CONNECTOR: i32 = 11;
pub const NETLINK_NETFILTER: i32 = 12;
pub const NETLINK_IP6_FW: i32 = 13;
pub const NETLINK_DNRTMSG: i32 = 14;
pub const NETLINK_KOBJECT_UEVENT: i32 = 15;
pub const NETLINK_GENERIC: i32 = 16;
pub const NETLINK_SCSITRANSPORT: i32 = 18;
pub const NETLINK_ECRYPTFS: i32 = 19;
pub const NETLINK_RDMA: i32 = 20;
pub const NETLINK_CRYPTO: i32 = 21;
pub const NETLINK_SMC: i32 = 22;

pub const NlMsgHdr = extern struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
};

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

// Rtnetlink
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_NEWTCLASS: u16 = 40;
pub const RTM_DELTCLASS: u16 = 41;
pub const RTM_GETTCLASS: u16 = 42;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_NEWNSID: u16 = 88;
pub const RTM_DELNSID: u16 = 89;
pub const RTM_GETNSID: u16 = 90;
pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_DELNEXTHOP: u16 = 105;
pub const RTM_GETNEXTHOP: u16 = 106;
pub const RTM_NEWVLAN: u16 = 112;
pub const RTM_DELVLAN: u16 = 113;
pub const RTM_GETVLAN: u16 = 114;
pub const RTM_NEWNEXTHOPBUCKET: u16 = 116;
pub const RTM_DELNEXTHOPBUCKET: u16 = 117;
pub const RTM_GETNEXTHOPBUCKET: u16 = 118;
pub const RTM_NEWTUNNEL: u16 = 120;
pub const RTM_DELTUNNEL: u16 = 121;
pub const RTM_GETTUNNEL: u16 = 122;

// ============================================================================
// Network Protocol Registration
// ============================================================================

pub const MAX_INET_PROTOS: usize = 256;

pub const NetProtocol = struct {
    handler: ?*const fn (*SkBuff) i32,
    err_handler: ?*const fn (*SkBuff, u32) i32,
    no_policy: bool,
    icmp_strict_tag_validation: bool,
};

pub const InetProtosw = struct {
    list_next: ?*InetProtosw,
    sock_type: u16,
    protocol: u16,
    prot: ?*const Proto,
    ops: ?*const ProtoOps,
    flags: u8,
};

pub const INET_PROTOSW_REUSE: u8 = 0x01;
pub const INET_PROTOSW_PERMANENT: u8 = 0x02;
pub const INET_PROTOSW_ICSK: u8 = 0x04;

// ============================================================================
// Network Namespace
// ============================================================================

pub const NetNs = struct {
    count: u32,
    // Network devices
    dev_index_head: [256]?*anyopaque,
    dev_name_head: [256]?*anyopaque,
    // IPv4
    ipv4_fib_table: ?*anyopaque,
    ipv4_route_cache: ?*anyopaque,
    // IPv6
    ipv6_fib_table: ?*anyopaque,
    // Netfilter
    nf_hooks: [7][5]?*anyopaque, // 7 families × 5 hooks
    nf_conntrack: ?*anyopaque,
    // XDP
    xdp_features: u32,
    // Sysctl
    sysctls: NetNsSysctls,
};

pub const NetNsSysctls = struct {
    ip_forward: bool,
    ip_default_ttl: u8,
    tcp_timestamps: bool,
    tcp_window_scaling: bool,
    tcp_sack: bool,
    tcp_ecn: u8,
    tcp_congestion: [16]u8,
    somaxconn: u32,
    tcp_max_syn_backlog: u32,
    tcp_fin_timeout: u32,
    tcp_keepalive_time: u32,
    tcp_keepalive_intvl: u32,
    tcp_keepalive_probes: u32,
    tcp_synack_retries: u32,
    tcp_syn_retries: u32,
    tcp_rmem: [3]u32,
    tcp_wmem: [3]u32,
    udp_rmem_min: u32,
    udp_wmem_min: u32,
    ip_local_port_range: [2]u16,
};

// ============================================================================
// TCP Info (for getsockopt TCP_INFO)
// ============================================================================

pub const TcpInfo = extern struct {
    tcpi_state: u8,
    tcpi_ca_state: u8,
    tcpi_retransmits: u8,
    tcpi_probes: u8,
    tcpi_backoff: u8,
    tcpi_options: u8,
    tcpi_snd_wscale: u4,
    tcpi_rcv_wscale: u4,
    tcpi_delivery_rate_app_limited: u1,
    tcpi_fastopen_client_fail: u2,
    tcpi_rto: u32,
    tcpi_ato: u32,
    tcpi_snd_mss: u32,
    tcpi_rcv_mss: u32,
    tcpi_unacked: u32,
    tcpi_sacked: u32,
    tcpi_lost: u32,
    tcpi_retrans: u32,
    tcpi_fackets: u32,
    // Times
    tcpi_last_data_sent: u32,
    tcpi_last_ack_sent: u32,
    tcpi_last_data_recv: u32,
    tcpi_last_ack_recv: u32,
    // Metrics
    tcpi_pmtu: u32,
    tcpi_rcv_ssthresh: u32,
    tcpi_rtt: u32,
    tcpi_rttvar: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_advmss: u32,
    tcpi_reordering: u32,
    tcpi_rcv_rtt: u32,
    tcpi_rcv_space: u32,
    tcpi_total_retrans: u32,
    tcpi_pacing_rate: u64,
    tcpi_max_pacing_rate: u64,
    tcpi_bytes_acked: u64,
    tcpi_bytes_received: u64,
    tcpi_segs_out: u32,
    tcpi_segs_in: u32,
    tcpi_notsent_bytes: u32,
    tcpi_min_rtt: u32,
    tcpi_data_segs_in: u32,
    tcpi_data_segs_out: u32,
    tcpi_delivery_rate: u64,
    tcpi_busy_time: u64,
    tcpi_rwnd_limited: u64,
    tcpi_sndbuf_limited: u64,
    tcpi_delivered: u32,
    tcpi_delivered_ce: u32,
    tcpi_bytes_sent: u64,
    tcpi_bytes_retrans: u64,
    tcpi_dsack_dups: u32,
    tcpi_reord_seen: u32,
    tcpi_rcv_ooopack: u32,
    tcpi_snd_wnd: u32,
    tcpi_rcv_wnd: u32,
    tcpi_rehash: u32,
    tcpi_total_rto: u16,
    tcpi_total_rto_recoveries: u16,
    tcpi_total_rto_time: u32,
};

// ============================================================================
// Generic Netlink
// ============================================================================

pub const GenlMsgHdr = extern struct {
    cmd: u8,
    version: u8,
    reserved: u16,
};

pub const GenlFamily = struct {
    id: u16,
    name: [16]u8,
    version: u8,
    maxattr: u16,
    policy: ?*anyopaque,
    ops: [32]GenlOps,
    nr_ops: u32,
    mcgrps: [8]GenlMulticastGroup,
    nr_mcgrps: u32,
    pre_doit: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque) i32,
    post_doit: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque) void,
};

pub const GenlOps = struct {
    cmd: u8,
    flags: u8,
    policy: ?*anyopaque,
    doit: ?*const fn (*SkBuff, ?*anyopaque) i32,
    dumpit: ?*const fn (*SkBuff, ?*anyopaque) i32,
    done: ?*const fn (?*anyopaque) i32,
};

pub const GenlMulticastGroup = struct {
    name: [16]u8,
};
