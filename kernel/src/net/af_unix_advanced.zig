// Zxyphor Kernel - AF_UNIX Advanced: Abstract, Pathname, Socketpair,
// SCM_RIGHTS, SCM_CREDENTIALS, OOB, Garbage Collection,
// Unix datagram, stream, seqpacket, io_uring passthrough
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// AF_UNIX Socket Types
// ============================================================================

pub const UnixSockType = enum(u8) {
    stream = 1,
    dgram = 2,
    seqpacket = 5,
};

pub const UnixAddrType = enum(u8) {
    unnamed = 0,
    pathname = 1,
    abstract_addr = 2,
};

pub const UnixAddr = struct {
    addr_type: UnixAddrType,
    sun_family: u16,       // AF_UNIX = 1
    sun_path: [108]u8,
    path_len: u32,
    hash: u32,
    refcnt: u32,
};

// ============================================================================
// Unix Socket Structure
// ============================================================================

pub const UnixSock = struct {
    // Generic socket state
    state: UnixSockState,
    sock_type: UnixSockType,
    flags: UnixSockFlags,
    // Address
    addr: ?*UnixAddr,
    // Peer
    peer: ?*UnixSock,
    // Listener backlog
    listener: ?*UnixSock,
    max_backlog: u32,
    pending_count: u32,
    // Receive queue
    recv_queue_len: u32,
    recv_queue_bytes: u64,
    recv_queue_max: u64,
    // Send buffer
    send_buf_size: u64,
    send_buf_used: u64,
    // Credentials
    peer_cred: UnixCredentials,
    // Garbage collection
    gc_candidate: bool,
    gc_tree: u64,
    inflight: u32,
    // OOB
    oob_skb: u64,
    // Timeouts
    send_timeout: i64,
    recv_timeout: i64,
    // Stats
    stats: UnixSockStats,
    // Inode (for pathname sockets)
    inode: u64,
    dentry: u64,
    // Lock
    lock: u64,
    // Wait queue
    wq: u64,
};

pub const UnixSockState = enum(u8) {
    unconnected = 0,
    connecting = 1,
    connected = 2,
    disconnecting = 3,
    listening = 4,
};

pub const UnixSockFlags = packed struct(u32) {
    passcred: bool = false,
    abstract_addr: bool = false,
    peek_off: bool = false,
    oob_ahead: bool = false,
    autobind: bool = false,
    nonblock: bool = false,
    cloexec: bool = false,
    nosigpipe: bool = false,
    // SO_PEERSEC
    peersec: bool = false,
    // BPF hooks
    bpf_sk_lookup: bool = false,
    _pad: u22 = 0,
};

pub const UnixSockStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    msgs_sent: u64,
    msgs_received: u64,
    fds_sent: u64,
    fds_received: u64,
    errors: u64,
    dgram_drops: u64,
    oob_sent: u64,
    oob_received: u64,
    connect_attempts: u64,
    accept_count: u64,
    pair_created: u64,
};

// ============================================================================
// SCM (Socket Control Messages)
// ============================================================================

pub const ScmType = enum(u32) {
    rights = 0x01,         // SCM_RIGHTS - fd passing
    credentials = 0x02,    // SCM_CREDENTIALS - pid/uid/gid
    security = 0x03,       // SCM_SECURITY - SELinux label
    pidfd = 0x04,          // SCM_PIDFD
};

pub const UnixCredentials = struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

pub const ScmCookie = struct {
    pid: i32,
    uid: u32,
    gid: u32,
    // File descriptor passing
    fds: [253]i32,     // SCM_MAX_FD = 253
    fd_count: u32,
    // Security label
    secid: u32,
    sec_label: [256]u8,
    sec_label_len: u32,
};

// ============================================================================
// SCM_RIGHTS - File Descriptor Passing
// ============================================================================

pub const SCM_MAX_FD: u32 = 253;

pub const UnixFdInfo = struct {
    fp: u64,           // struct file *
    count: u32,
};

pub const ScmFpList = struct {
    user: u64,
    fds: [SCM_MAX_FD]u64,    // struct file *
    count: u32,
    max: u32,
    inflight: bool,
    dead: bool,
};

// ============================================================================
// Garbage Collection (for circular fd references)
// ============================================================================

pub const UnixGcState = enum(u8) {
    idle = 0,
    running = 1,
    candidate_found = 2,
};

pub const UnixGc = struct {
    state: UnixGcState,
    cycle_count: u64,
    inflight_count: u64,
    // GC candidate list
    gc_candidates: u32,
    gc_inflight_fds_total: u64,
    // Statistics
    gc_runs: u64,
    gc_freed: u64,
    gc_cycle_detected: u64,
    gc_duration_ns: u64,
    gc_max_duration_ns: u64,
};

pub const UnixInflight = struct {
    sock: ?*UnixSock,
    inflight: u32,
};

// ============================================================================
// Unix Dgram
// ============================================================================

pub const UnixDgramControl = struct {
    src: ?*UnixSock,
    max_dgram_qlen: u32,       // sysctl_max_dgram_qlen
    // Queue
    queue_len: u32,
    queue_bytes: u64,
    // Drop policy
    drop_on_full: bool,
};

// ============================================================================
// Unix Stream
// ============================================================================

pub const UnixStreamControl = struct {
    // Splice support
    splice_pipe: u64,
    // Peek offset
    peek_off: i64,
    // OOB
    oob_head: u64,
    oob_count: u32,
    // Memory pressure
    memory_pressure: bool,
    // Scatter/gather
    sg_enabled: bool,
};

// ============================================================================
// Unix Seqpacket
// ============================================================================

pub const UnixSeqpacketControl = struct {
    max_msg_size: u64,
    msg_boundary_preserved: bool,
};

// ============================================================================
// Abstract Namespace
// ============================================================================

pub const UnixAbstractName = struct {
    name: [107]u8,     // max abstract name (108 - NUL)
    name_len: u32,
    hash: u32,
    addr: ?*UnixAddr,
};

// ============================================================================
// Autobind
// ============================================================================

pub const UnixAutobind = struct {
    next_num: u32,
    prefix: [5]u8,     // "\x00" + 5 hex chars
};

// ============================================================================
// Unix Diag (sock_diag for AF_UNIX)
// ============================================================================

pub const UnixDiagReq = struct {
    family: u8,
    protocol: u8,
    states: u32,
    ino: u32,
    show: UnixDiagShow,
    cookie: [2]u32,
};

pub const UnixDiagShow = packed struct(u32) {
    name: bool = false,
    vfs: bool = false,
    peer: bool = false,
    icons: bool = false,
    rqlen: bool = false,
    meminfo: bool = false,
    shutdown: bool = false,
    uid: bool = false,
    _pad: u24 = 0,
};

pub const UnixDiagMsg = struct {
    family: u8,
    sock_type: u8,
    state: u8,
    ino: u32,
    cookie: [2]u32,
};

// ============================================================================
// Unix Socket Options
// ============================================================================

pub const UnixSockOpt = enum(u32) {
    so_debug = 1,
    so_reuseaddr = 2,
    so_type = 3,
    so_error = 4,
    so_dontroute = 5,
    so_broadcast = 6,
    so_sndbuf = 7,
    so_rcvbuf = 8,
    so_keepalive = 9,
    so_oobinline = 10,
    so_linger = 13,
    so_rcvlowat = 18,
    so_sndlowat = 19,
    so_rcvtimeo_old = 20,
    so_sndtimeo_old = 21,
    so_passcred = 16,
    so_peercred = 17,
    so_peername = 28,
    so_acceptconn = 30,
    so_peersec = 31,
    so_passsec = 34,
    so_mark = 36,
    so_domain = 39,
    so_protocol = 38,
    so_peek_off = 42,
    so_busy_poll = 46,
    so_incoming_cpu = 49,
    so_attach_bpf = 50,
    so_detach_bpf = 27,
    so_cookie = 57,
    so_incoming_napi_id = 56,
    so_meminfo = 55,
    so_txrehash = 74,
    so_rcvtimeo_new = 66,
    so_sndtimeo_new = 67,
    so_prefer_busy_poll = 69,
    so_busy_poll_budget = 70,
};

// ============================================================================
// Netlink UNIX_DIAG (for ss/iproute2)
// ============================================================================

pub const UnixDiagInfo = struct {
    state: UnixSockState,
    ino: u32,
    peer_ino: u32,
    send_queue_len: u32,
    recv_queue_len: u32,
    send_queue_bytes: u64,
    recv_queue_bytes: u64,
    // VFS info
    dev: u32,
    vfs_ino: u64,
    // Memory info
    rmem_alloc: u32,
    wmem_alloc: u32,
    fwd_alloc: u32,
    wmem_queued: u32,
    // Path
    path: [108]u8,
    path_len: u32,
    // Shutdown state
    shutdown_rd: bool,
    shutdown_wr: bool,
};

// ============================================================================
// BPF Socket Lookup for AF_UNIX
// ============================================================================

pub const UnixBpfContext = struct {
    src_addr: ?*UnixAddr,
    dst_addr: ?*UnixAddr,
    sock_type: UnixSockType,
    protocol: u32,
    // Return value: selected socket
    selected_sk: u64,
};

// ============================================================================
// Unix Socket Memory Accounting
// ============================================================================

pub const UnixMemAccount = struct {
    alloc: u64,
    fwd_alloc: u64,
    wmem_alloc: u64,
    rmem_alloc: u64,
    // Pressure thresholds
    rcvbuf: u64,
    sndbuf: u64,
    // Sysctl defaults
    max_dgram_qlen: u32,
    // Global counters
    total_unix_memory: u64,
    unix_inflight: u64,
};

// ============================================================================
// Splice / io_uring integration
// ============================================================================

pub const UnixSpliceCtx = struct {
    pipe: u64,
    flags: u32,
    bytes_spliced: u64,
};

pub const UnixIoUringCtx = struct {
    // io_uring socket operations
    accept_multishot: bool,
    recv_multishot: bool,
    send_zc: bool,
    recvmsg_multishot: bool,
    connect_async: bool,
    // Stats
    io_uring_ops: u64,
};

// ============================================================================
// Unix Socket Manager
// ============================================================================

pub const UnixSubsystemManager = struct {
    total_sockets: u64,
    active_sockets: u32,
    stream_sockets: u32,
    dgram_sockets: u32,
    seqpacket_sockets: u32,
    pathname_sockets: u32,
    abstract_sockets: u32,
    unnamed_sockets: u32,
    socketpairs: u32,
    total_bytes_tx: u64,
    total_bytes_rx: u64,
    total_fds_passed: u64,
    gc_runs: u64,
    gc_freed: u64,
    total_oob: u64,
    max_dgram_qlen: u32,
    initialized: bool,

    pub fn init() UnixSubsystemManager {
        return UnixSubsystemManager{
            .total_sockets = 0,
            .active_sockets = 0,
            .stream_sockets = 0,
            .dgram_sockets = 0,
            .seqpacket_sockets = 0,
            .pathname_sockets = 0,
            .abstract_sockets = 0,
            .unnamed_sockets = 0,
            .socketpairs = 0,
            .total_bytes_tx = 0,
            .total_bytes_rx = 0,
            .total_fds_passed = 0,
            .gc_runs = 0,
            .gc_freed = 0,
            .total_oob = 0,
            .max_dgram_qlen = 10,
            .initialized = true,
        };
    }
};
