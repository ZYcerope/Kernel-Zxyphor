// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Pipe/FIFO Implementation, eventfd,
// signalfd, timerfd, userfaultfd, pidfd,
// Anonymous Inode Framework, Epoll Internals
// More advanced than Linux 2026 IPC primitives

const std = @import("std");

// ============================================================================
// Pipe/FIFO
// ============================================================================

/// Pipe buffer page descriptor
pub const PipeBufPage = struct {
    page_addr: u64 = 0,
    offset: u32 = 0,
    len: u32 = 0,
    flags: PipeBufFlags = .{},
    ops: PipeBufOpsType = .default,
};

/// Pipe buffer flags
pub const PipeBufFlags = packed struct(u32) {
    can_merge: bool = false,
    whole_page: bool = false,
    gift: bool = false,           // page is a gift (splice)
    packet: bool = false,         // O_DIRECT write boundary
    _padding: u28 = 0,
};

/// Pipe buffer operations type
pub const PipeBufOpsType = enum(u8) {
    default = 0,
    anon = 1,
    packet = 2,
    vmsplice = 3,
    splice = 4,
};

/// Pipe flags (from pipe2 flags)
pub const PipeFlags = packed struct(u32) {
    nonblock: bool = false,       // O_NONBLOCK
    cloexec: bool = false,        // O_CLOEXEC
    direct: bool = false,         // O_DIRECT (packet mode)
    notification: bool = false,   // pipe-as-notification
    _padding: u28 = 0,
};

/// Pipe descriptor
pub const PipeDescriptor = struct {
    nr_bufs: u32 = 16,            // default pipe size in pages
    max_bufs: u32 = 1048576,      // max pipe size (/proc/sys/fs/pipe-max-size)
    curbuf: u32 = 0,
    head: u32 = 0,
    tail: u32 = 0,
    readers: u32 = 0,
    writers: u32 = 0,
    files: u32 = 0,
    r_counter: u32 = 0,
    w_counter: u32 = 0,
    flags: PipeFlags = .{},
    fasync_readers: u64 = 0,
    fasync_writers: u64 = 0,
    user_id: u32 = 0,
    watch_queue: bool = false,
};

/// Pipe resize info
pub const PipeResizeInfo = struct {
    old_size: u32 = 0,
    new_size: u32 = 0,
    min_size: u32 = 4096,             // PAGE_SIZE
    max_size: u32 = 1048576,
    pipe_user_pages_hard: u64 = 0,    // 0 = unlimited
    pipe_user_pages_soft: u64 = 16384,
};

// ============================================================================
// eventfd
// ============================================================================

/// eventfd flags
pub const EventfdFlags = packed struct(u32) {
    cloexec: bool = false,        // EFD_CLOEXEC
    nonblock: bool = false,       // EFD_NONBLOCK
    semaphore: bool = false,      // EFD_SEMAPHORE
    _padding: u29 = 0,
};

/// eventfd descriptor
pub const EventfdDesc = struct {
    count: u64 = 0,
    flags: EventfdFlags = .{},
    id: u64 = 0,
    wqh: u64 = 0,         // wait queue head
};

// ============================================================================
// signalfd
// ============================================================================

/// signalfd flags
pub const SignalfdFlags = packed struct(u32) {
    cloexec: bool = false,        // SFD_CLOEXEC
    nonblock: bool = false,       // SFD_NONBLOCK
    _padding: u30 = 0,
};

/// signalfd_siginfo structure
pub const SignalfdSiginfo = extern struct {
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
    __pad2: u16,
    ssi_syscall: i32,
    ssi_call_addr: u64,
    ssi_arch: u32,
    __pad: [28]u8,
};

// ============================================================================
// timerfd
// ============================================================================

/// timerfd clock type
pub const TimerfdClock = enum(i32) {
    realtime = 0,
    monotonic = 1,
    boottime = 7,
    realtime_alarm = 8,
    boottime_alarm = 9,
};

/// timerfd flags
pub const TimerfdFlags = packed struct(u32) {
    cloexec: bool = false,        // TFD_CLOEXEC
    nonblock: bool = false,       // TFD_NONBLOCK
    timer_abstime: bool = false,  // TFD_TIMER_ABSTIME
    timer_cancel_on_set: bool = false, // TFD_TIMER_CANCEL_ON_SET
    _padding: u28 = 0,
};

/// timerfd descriptor
pub const TimerfdDesc = struct {
    clock: TimerfdClock = .monotonic,
    flags: TimerfdFlags = .{},
    it_value_sec: i64 = 0,
    it_value_nsec: i64 = 0,
    it_interval_sec: i64 = 0,
    it_interval_nsec: i64 = 0,
    ticks: u64 = 0,
    settime_flags: u32 = 0,
    expired: bool = false,
    cancelled: bool = false,
};

// ============================================================================
// userfaultfd
// ============================================================================

/// userfaultfd flags
pub const UserfaultfdFlags = packed struct(u32) {
    cloexec: bool = false,        // O_CLOEXEC
    nonblock: bool = false,       // O_NONBLOCK
    user_mode_only: bool = false, // UFFD_USER_MODE_ONLY
    _padding: u29 = 0,
};

/// userfaultfd features
pub const UffdFeatures = packed struct(u64) {
    pagefault_flag_wp: bool = false,
    event_fork: bool = false,
    event_remap: bool = false,
    event_remove: bool = false,
    missing_hugetlbfs: bool = false,
    missing_shmem: bool = false,
    event_unmap: bool = false,
    sigbus: bool = false,
    thread_id: bool = false,
    minor_hugetlbfs: bool = false,
    minor_shmem: bool = false,
    exact_address: bool = false,
    wp_hugetlbfs_shmem: bool = false,
    wp_unpopulated: bool = false,
    poison: bool = false,
    wp_async: bool = false,
    move_page: bool = false,
    // Zxyphor
    zxy_batch_fault: bool = false,
    zxy_prefetch: bool = false,
    _padding: u45 = 0,
};

/// userfaultfd ioctl commands
pub const UffdIoctl = enum(u32) {
    api = 0xAA00,
    register = 0xAA01,
    unregister = 0xAA02,
    wake = 0xAA03,
    copy = 0xAA04,
    zeropage = 0xAA05,
    writeprotect = 0xAA06,
    continue_ioctl = 0xAA07,
    poison = 0xAA08,
    move_ioctl = 0xAA09,
};

/// userfaultfd register mode
pub const UffdRegisterMode = packed struct(u64) {
    missing: bool = false,
    wp: bool = false,
    minor: bool = false,
    _padding: u61 = 0,
};

/// userfaultfd msg type
pub const UffdEventType = enum(u8) {
    pagefault = 0x12,
    fork = 0x13,
    remap = 0x14,
    remove = 0x15,
    unmap = 0x16,
};

/// userfaultfd pagefault flags
pub const UffdPagefaultFlags = packed struct(u64) {
    write: bool = false,
    wp: bool = false,
    minor: bool = false,
    _padding: u61 = 0,
};

// ============================================================================
// pidfd
// ============================================================================

/// pidfd flags
pub const PidfdFlags = packed struct(u32) {
    nonblock: bool = false,       // PIDFD_NONBLOCK
    thread: bool = false,         // PIDFD_THREAD (clone3 PIDFD)
    _padding: u30 = 0,
};

/// pidfd info (from pidfd_getfd, pidfd_send_signal, etc.)
pub const PidfdInfo = struct {
    pid: i32 = 0,
    tgid: i32 = 0,
    ppid: i32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    ns_pid: i32 = 0,
    ns_tgid: i32 = 0,
    flags: PidfdFlags = .{},
    exit_status: i32 = 0,
    exited: bool = false,
};

/// waitid extensions for pidfd
pub const WaitidOptions = packed struct(u32) {
    exited: bool = false,         // WEXITED
    stopped: bool = false,        // WSTOPPED
    continued: bool = false,      // WCONTINUED
    nohang: bool = false,         // WNOHANG
    nowait: bool = false,         // WNOWAIT
    clone: bool = false,          // __WCLONE
    wall: bool = false,           // __WALL
    _padding: u25 = 0,
};

// ============================================================================
// Epoll Internals
// ============================================================================

/// Epoll event flags (extended)
pub const EpollEventFlags = packed struct(u32) {
    in_event: bool = false,       // EPOLLIN
    pri: bool = false,            // EPOLLPRI
    out: bool = false,            // EPOLLOUT
    rdnorm: bool = false,         // EPOLLRDNORM
    rdband: bool = false,         // EPOLLRDBAND
    wrnorm: bool = false,         // EPOLLWRNORM
    wrband: bool = false,         // EPOLLWRBAND
    msg: bool = false,            // EPOLLMSG
    err: bool = false,            // EPOLLERR
    hup: bool = false,            // EPOLLHUP
    rdhup: bool = false,          // EPOLLRDHUP
    exclusive: bool = false,      // EPOLLEXCLUSIVE
    wakeup: bool = false,         // EPOLLWAKEUP
    oneshot: bool = false,        // EPOLLONESHOT
    et: bool = false,             // EPOLLET (edge-triggered)
    _padding: u17 = 0,
};

/// Epoll ctl operation
pub const EpollCtlOp = enum(i32) {
    add = 1,
    del = 2,
    mod_op = 3,
};

/// Epoll internal item descriptor
pub const EpollItemDesc = struct {
    fd: i32 = 0,
    events: EpollEventFlags = .{},
    user_data: u64 = 0,
    revents: EpollEventFlags = .{},
    nwait: i32 = 0,
    next_ep_links: u32 = 0,
};

/// Epoll instance stats
pub const EpollInstanceStats = struct {
    nr_fds: u32 = 0,
    nr_ready: u32 = 0,
    nr_ovflist: u32 = 0,
    nr_wakeups: u64 = 0,
    nr_pwait: u64 = 0,
    user_id: u32 = 0,
    ep_id: u64 = 0,
};

// ============================================================================
// Anonymous Inode
// ============================================================================

/// Anonymous inode type
pub const AnonInodeType = enum(u8) {
    generic = 0,
    eventfd_type = 1,
    signalfd_type = 2,
    timerfd_type = 3,
    userfaultfd_type = 4,
    pidfd_type = 5,
    epoll_type = 6,
    io_uring_type = 7,
    fanotify_type = 8,
    inotify_type = 9,
    perf_event_type = 10,
    bpf_prog_type = 11,
    bpf_map_type = 12,
    seccomp_type = 13,
    dma_buf_type = 14,
    sync_file_type = 15,
    // Zxyphor
    zxy_channel_type = 100,
};

/// Anonymous inode descriptor
pub const AnonInodeDesc = struct {
    inode_type: AnonInodeType = .generic,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    refcount: u32 = 0,
    file_mode: u32 = 0,
    cloexec: bool = false,
};

// ============================================================================
// Splice / vmsplice / tee
// ============================================================================

/// Splice flags
pub const SpliceFlags = packed struct(u32) {
    move_pages: bool = false,     // SPLICE_F_MOVE
    nonblock: bool = false,       // SPLICE_F_NONBLOCK
    more: bool = false,           // SPLICE_F_MORE
    gift: bool = false,           // SPLICE_F_GIFT
    _padding: u28 = 0,
};

/// Splice descriptor
pub const SpliceDesc = struct {
    fd_in: i32 = 0,
    off_in: ?u64 = null,
    fd_out: i32 = 0,
    off_out: ?u64 = null,
    len: u64 = 0,
    flags: SpliceFlags = .{},
    bytes_spliced: u64 = 0,
};

// ============================================================================
// IPC Fd Subsystem Manager
// ============================================================================

pub const IpcFdSubsystem = struct {
    nr_pipes: u64 = 0,
    nr_fifos: u64 = 0,
    nr_eventfds: u64 = 0,
    nr_signalfds: u64 = 0,
    nr_timerfds: u64 = 0,
    nr_userfaultfds: u64 = 0,
    nr_pidfds: u64 = 0,
    nr_epolls: u64 = 0,
    nr_anon_inodes: u64 = 0,
    nr_splice_ops: u64 = 0,
    pipe_max_size: u32 = 1048576,
    pipe_user_limit: u64 = 16384,
    epoll_max_user_watches: u64 = 0,
    initialized: bool = false,

    pub fn init() IpcFdSubsystem {
        return IpcFdSubsystem{
            .initialized = true,
        };
    }
};
