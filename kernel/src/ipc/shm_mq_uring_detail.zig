// Zxyphor Kernel - Shared Memory Detail (POSIX/SysV),
// POSIX Message Queue Advanced, AF_UNIX Advanced,
// pidfd Detail, signalfd/timerfd Extensions,
// eventpoll Internals, io_uring SQE/CQE Detail,
// io_uring opcodes, Registered Buffers/Files
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// POSIX Shared Memory (shm_open)
// ============================================================================

pub const PosixShmFlags = packed struct(u32) {
    rdonly: bool = false,
    rdwr: bool = false,
    creat: bool = false,
    excl: bool = false,
    trunc: bool = false,
    noreserve: bool = false,
    hugetlb: bool = false,
    // Hugetlb size encoding (ln2 in bits 26-31)
    _reserved: u25 = 0,
};

pub const PosixShmDesc = struct {
    name: [256]u8,
    name_len: u16,
    size: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    seals: u32,              // F_SEAL_* flags
    nr_mappings: u32,
    // Backing
    is_hugetlb: bool,
    hugepage_size: u64,
    nr_pages: u64,
    nr_pages_populated: u64,
};

// ============================================================================
// SysV Shared Memory
// ============================================================================

pub const SysvShmFlags = packed struct(u32) {
    ipc_creat: bool = false,
    ipc_excl: bool = false,
    shm_hugetlb: bool = false,
    shm_noreserve: bool = false,
    shm_rdonly: bool = false,
    shm_rnd: bool = false,
    shm_remap: bool = false,
    shm_exec: bool = false,
    _reserved: u24 = 0,
};

pub const SysvShmidDs = struct {
    shm_perm: IpcPerm,
    shm_segsz: u64,
    shm_atime: i64,
    shm_dtime: i64,
    shm_ctime: i64,
    shm_cpid: u32,
    shm_lpid: u32,
    shm_nattch: u32,
};

pub const IpcPerm = struct {
    key: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    seq: u16,
};

pub const ShmInfo = struct {
    shmmax: u64,           // Max segment size
    shmmin: u64,           // Min segment size
    shmmni: u32,           // Max number of segments
    shmseg: u32,           // Max segments per process
    shmall: u64,           // Max total shared memory pages
};

// ============================================================================
// POSIX Message Queue Advanced
// ============================================================================

pub const MqAttr = struct {
    mq_flags: i64,          // Message queue flags (O_NONBLOCK)
    mq_maxmsg: i64,         // Max number of messages
    mq_msgsize: i64,        // Max message size (bytes)
    mq_curmsgs: i64,        // Current messages in queue
};

pub const MqPriority = u32;  // 0 = lowest, 31 = highest (Linux max)

pub const MqNotifyMode = enum(u8) {
    none = 0,
    signal = 1,
    thread = 2,
};

pub const MqLimits = struct {
    msg_max: u32,            // /proc/sys/fs/mqueue/msg_max
    msgsize_max: u32,        // /proc/sys/fs/mqueue/msgsize_max
    queues_max: u32,         // /proc/sys/fs/mqueue/queues_max
    msg_default: u32,
    msgsize_default: u32,
};

pub const MqStats = struct {
    queues_created: u64,
    queues_destroyed: u64,
    messages_sent: u64,
    messages_received: u64,
    messages_timed_out: u64,
    notifications_sent: u64,
    overflows: u64,
};

// ============================================================================
// AF_UNIX Socket Advanced
// ============================================================================

pub const UnixSocketType = enum(u8) {
    stream = 1,
    dgram = 2,
    seqpacket = 5,
};

pub const UnixSocketState = enum(u8) {
    unconnected = 0,
    connecting = 1,
    connected = 2,
    disconnecting = 3,
};

pub const UnixSocketFlags = packed struct(u32) {
    passcred: bool = false,     // SO_PASSCRED
    passfile: bool = false,     // SCM_RIGHTS
    passsec: bool = false,      // SO_PASSSEC
    abstract: bool = false,     // Abstract namespace
    autobind: bool = false,
    dgram_connect: bool = false,
    _reserved: u26 = 0,
};

pub const UnixScmRights = struct {
    nr_fds: u32,
    fds: [253]i32,              // SCM_RIGHTS max ~253 fds
};

pub const UnixScmCredentials = struct {
    pid: u32,
    uid: u32,
    gid: u32,
};

pub const UnixSocketInfo = struct {
    socket_type: UnixSocketType,
    state: UnixSocketState,
    flags: UnixSocketFlags,
    path: [108]u8,              // Unix socket path
    path_len: u8,
    ino: u64,
    peer_ino: u64,
    sk_sndbuf: u32,
    sk_rcvbuf: u32,
    sk_wmem_alloc: u32,
    sk_rmem_alloc: u32,
    send_queue_len: u32,
    recv_queue_len: u32,
    drops: u64,
};

// ============================================================================
// pidfd Detail
// ============================================================================

pub const PidfdFlags = packed struct(u32) {
    nonblock: bool = false,
    thread: bool = false,      // PIDFD_THREAD
    _reserved: u30 = 0,
};

pub const PidfdInfo = struct {
    pid: u32,
    tgid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    ns_pid: u32,                // PID in namespace
    start_time: u64,            // Process start time
    flags: PidfdFlags,
};

pub const PidfdOps = enum(u8) {
    open = 0,                   // pidfd_open
    send_signal = 1,            // pidfd_send_signal
    getfd = 2,                  // pidfd_getfd
    wait = 3,                   // waitid with P_PIDFD
};

// ============================================================================
// signalfd / timerfd
// ============================================================================

pub const SignalfdFlags = packed struct(u32) {
    nonblock: bool = false,
    cloexec: bool = false,
    _reserved: u30 = 0,
};

pub const SignalfdInfo = struct {
    ssi_signo: u32,
    ssi_errno: i32,
    ssi_code: i32,
    ssi_pid: u32,
    ssi_uid: u32,
    ssi_fd: i32,
    ssi_tid: u32,
    ssi_band: u32,
    ssi_overrun: u32,
    ssi_trapno: u32,
    ssi_status: i32,
    ssi_int: i32,
    ssi_ptr: u64,
    ssi_utime: u64,
    ssi_stime: u64,
    ssi_addr: u64,
    ssi_addr_lsb: u16,
    _pad: [46]u8,
};

pub const TimerfdClockId = enum(u32) {
    realtime = 0,
    monotonic = 1,
    boottime = 7,
    realtime_alarm = 8,
    boottime_alarm = 9,
};

pub const TimerfdFlags = packed struct(u32) {
    nonblock: bool = false,
    cloexec: bool = false,
    timer_abstime: bool = false,
    timer_cancel_on_set: bool = false,
    _reserved: u28 = 0,
};

pub const TimerfdSpec = struct {
    it_interval_sec: i64,
    it_interval_nsec: i64,
    it_value_sec: i64,
    it_value_nsec: i64,
};

// ============================================================================
// eventpoll (epoll) Internals
// ============================================================================

pub const EpollEvent = struct {
    events: EpollEventFlags,
    data: u64,                  // User data
};

pub const EpollEventFlags = packed struct(u32) {
    pollin: bool = false,       // EPOLLIN
    pollpri: bool = false,      // EPOLLPRI
    pollout: bool = false,      // EPOLLOUT
    pollerr: bool = false,      // EPOLLERR
    pollhup: bool = false,      // EPOLLHUP
    pollnval: bool = false,     // EPOLLNVAL
    pollrdnorm: bool = false,
    pollrdband: bool = false,
    pollwrnorm: bool = false,
    pollwrband: bool = false,
    pollmsg: bool = false,
    pollrdhup: bool = false,    // EPOLLRDHUP
    exclusive: bool = false,    // EPOLLEXCLUSIVE
    wakeup_source: bool = false, // EPOLLWAKEUP
    oneshot: bool = false,      // EPOLLONESHOT
    edge_triggered: bool = false, // EPOLLET
    _reserved: u16 = 0,
};

pub const EpollOp = enum(u32) {
    add = 1,     // EPOLL_CTL_ADD
    del = 2,     // EPOLL_CTL_DEL
    mod = 3,     // EPOLL_CTL_MOD
};

pub const EpollInternalState = struct {
    nr_fds_registered: u32,
    nr_ready: u32,
    ovflist_active: bool,     // Overflow list for concurrent events
    nesting_depth: u8,        // Epoll-in-epoll depth
};

pub const EpollStats = struct {
    epoll_creates: u64,
    epoll_ctl_add: u64,
    epoll_ctl_del: u64,
    epoll_ctl_mod: u64,
    epoll_wait_calls: u64,
    events_delivered: u64,
    wakeups_total: u64,
    wakeups_spurious: u64,
};

// ============================================================================
// io_uring SQE (Submission Queue Entry) Detail - 64 bytes
// ============================================================================

pub const IoUringSqe = extern struct {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_or_addr2: u64,      // Union: off / addr2
    addr_or_splice_off: u64, // Union: addr / splice_off_in
    len: u32,
    op_flags: u32,            // Union: rw_flags / fsync_flags / etc.
    user_data: u64,
    buf_index_or_group: u16,  // Union: buf_index / buf_group
    personality: u16,
    splice_fd_in_or_file: i32,
    addr3: u64,
    _pad2: [1]u64,
};

// ============================================================================
// io_uring CQE (Completion Queue Entry) Detail - 16/32 bytes
// ============================================================================

pub const IoUringCqe = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

pub const IoUringCqeExtended = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
    big_cqe: [2]u64,         // Extended CQE data
};

pub const CqeFlags = packed struct(u32) {
    buffer: bool = false,       // IORING_CQE_F_BUFFER
    more: bool = false,         // IORING_CQE_F_MORE
    sock_nonempty: bool = false, // IORING_CQE_F_SOCK_NONEMPTY
    notif: bool = false,        // IORING_CQE_F_NOTIF
    _reserved: u28 = 0,
};

// ============================================================================
// io_uring Opcodes
// ============================================================================

pub const IoUringOp = enum(u8) {
    nop = 0,
    readv = 1,
    writev = 2,
    fsync = 3,
    read_fixed = 4,
    write_fixed = 5,
    poll_add = 6,
    poll_remove = 7,
    sync_file_range = 8,
    sendmsg = 9,
    recvmsg = 10,
    timeout = 11,
    timeout_remove = 12,
    accept = 13,
    async_cancel = 14,
    link_timeout = 15,
    connect = 16,
    fallocate = 17,
    openat = 18,
    close = 19,
    files_update = 20,
    statx = 21,
    read = 22,
    write = 23,
    fadvise = 24,
    madvise = 25,
    send = 26,
    recv = 27,
    openat2 = 28,
    epoll_ctl = 29,
    splice = 30,
    provide_buffers = 31,
    remove_buffers = 32,
    tee = 33,
    shutdown = 34,
    renameat = 35,
    unlinkat = 36,
    mkdirat = 37,
    symlinkat = 38,
    linkat = 39,
    msg_ring = 40,
    fsetxattr = 41,
    setxattr = 42,
    fgetxattr = 43,
    getxattr = 44,
    socket = 45,
    uring_cmd = 46,
    send_zc = 47,        // Zero-copy send
    sendmsg_zc = 48,
    read_multishot = 49,
    waitid = 50,
    futex_wait = 51,
    futex_wake = 52,
    futex_waitv = 53,
    fixed_fd_install = 54,
    ftruncate = 55,
    bind = 56,
    listen = 57,
    // Zxyphor
    zxy_io_batch = 200,     // Batched I/O
    zxy_nvme_passthrough = 201,
};

// ============================================================================
// io_uring SQE Flags
// ============================================================================

pub const IoUringSqeFlags = packed struct(u8) {
    fixed_file: bool = false,     // IOSQE_FIXED_FILE
    io_drain: bool = false,       // IOSQE_IO_DRAIN
    io_link: bool = false,        // IOSQE_IO_LINK
    io_hardlink: bool = false,    // IOSQE_IO_HARDLINK
    async_flag: bool = false,     // IOSQE_ASYNC
    buffer_select: bool = false,  // IOSQE_BUFFER_SELECT
    cqe_skip: bool = false,       // IOSQE_CQE_SKIP_SUCCESS
    _reserved: u1 = 0,
};

// ============================================================================
// io_uring Setup Params
// ============================================================================

pub const IoUringSetupFlags = packed struct(u32) {
    iopoll: bool = false,          // IORING_SETUP_IOPOLL
    sqpoll: bool = false,          // IORING_SETUP_SQPOLL
    sq_aff: bool = false,          // IORING_SETUP_SQ_AFF
    cqsize: bool = false,          // IORING_SETUP_CQSIZE
    clamp: bool = false,           // IORING_SETUP_CLAMP
    attach_wq: bool = false,       // IORING_SETUP_ATTACH_WQ
    r_disabled: bool = false,      // IORING_SETUP_R_DISABLED
    submit_all: bool = false,      // IORING_SETUP_SUBMIT_ALL
    coop_taskrun: bool = false,    // IORING_SETUP_COOP_TASKRUN
    taskrun_flag: bool = false,    // IORING_SETUP_TASKRUN_FLAG
    sqe128: bool = false,          // IORING_SETUP_SQE128
    cqe32: bool = false,           // IORING_SETUP_CQE32
    single_issuer: bool = false,   // IORING_SETUP_SINGLE_ISSUER
    defer_taskrun: bool = false,   // IORING_SETUP_DEFER_TASKRUN
    no_mmap: bool = false,         // IORING_SETUP_NO_MMAP
    registered_fd_only: bool = false, // IORING_SETUP_REGISTERED_FD_ONLY
    no_sqarray: bool = false,      // IORING_SETUP_NO_SQARRAY
    _reserved: u15 = 0,
};

pub const IoUringParams = struct {
    sq_entries: u32,
    cq_entries: u32,
    flags: IoUringSetupFlags,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    sq_off: IoUringSqRingOffsets,
    cq_off: IoUringCqRingOffsets,
};

pub const IoUringSqRingOffsets = struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    _reserved: [3]u32,
};

pub const IoUringCqRingOffsets = struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    _reserved: [3]u32,
};

// ============================================================================
// IPC Subsystem Manager (Zxyphor)
// ============================================================================

pub const IpcSubsystemManager = struct {
    // SysV IPC
    shm_info: ShmInfo,
    mq_limits: MqLimits,
    mq_stats: MqStats,
    // epoll
    epoll_stats: EpollStats,
    // io_uring
    io_uring_instances: u32,
    io_uring_sqs_total: u32,
    io_uring_cqs_total: u32,
    io_uring_submissions: u64,
    io_uring_completions: u64,
    // Unix sockets
    unix_sockets_active: u32,
    // pidfd
    pidfds_open: u32,
    // signalfd/timerfd
    signalfds_open: u32,
    timerfds_open: u32,
    // Status
    initialized: bool,

    pub fn init() IpcSubsystemManager {
        return .{
            .shm_info = .{
                .shmmax = 18446744073709551615,
                .shmmin = 1,
                .shmmni = 4096,
                .shmseg = 4096,
                .shmall = 18446744073709551615,
            },
            .mq_limits = .{
                .msg_max = 10,
                .msgsize_max = 8192,
                .queues_max = 256,
                .msg_default = 10,
                .msgsize_default = 8192,
            },
            .mq_stats = std.mem.zeroes(MqStats),
            .epoll_stats = std.mem.zeroes(EpollStats),
            .io_uring_instances = 0,
            .io_uring_sqs_total = 0,
            .io_uring_cqs_total = 0,
            .io_uring_submissions = 0,
            .io_uring_completions = 0,
            .unix_sockets_active = 0,
            .pidfds_open = 0,
            .signalfds_open = 0,
            .timerfds_open = 0,
            .initialized = true,
        };
    }
};
