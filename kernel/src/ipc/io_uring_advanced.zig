// Zxyphor Kernel - io_uring Advanced: SQE/CQE detail, registered buffers,
// fixed files, kernel-side completion, submission queues, linked SQEs,
// cancelation, timeout, poll, io_uring_cmd, multishot, provided buffers,
// registered ring, direct descriptors, io_uring_buf_ring, IOPOLL
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// io_uring Opcodes (Linux 6.x complete)
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
    send_zc = 47,
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
    last = 58,
};

// ============================================================================
// SQE (Submission Queue Entry) - 64 bytes
// ============================================================================

pub const IoUringSqe = extern struct {
    opcode: u8,
    flags: IoUringSqeFlags,
    ioprio: u16,
    fd: i32,
    off_addr2: extern union {
        off: u64,
        addr2: u64,
        cmd_op: u32,
        __pad1: u32,
    },
    addr_splice_off: extern union {
        addr: u64,
        splice_off_in: u64,
        level: u32,
        optname: u32,
    },
    len: u32,
    op_flags: extern union {
        rw_flags: u32,
        fsync_flags: u32,
        poll_events: u16,
        poll32_events: u32,
        sync_range_flags: u32,
        msg_flags: u32,
        timeout_flags: u32,
        accept_flags: u32,
        cancel_flags: u32,
        open_flags: u32,
        statx_flags: u32,
        fadvise_advice: u32,
        splice_flags: u32,
        rename_flags: u32,
        unlink_flags: u32,
        hardlink_flags: u32,
        xattr_flags: u32,
        msg_ring_flags: u32,
        uring_cmd_flags: u32,
        waitid_flags: u32,
        futex_flags: u32,
        install_fd_flags: u32,
    },
    user_data: u64,
    buf_index_group: extern union {
        buf_index: u16,
        buf_group: u16,
    },
    personality: u16,
    splice_fd_file: extern union {
        splice_fd_in: i32,
        file_index: u32,
        optlen: u32,
        addr_len: extern struct {
            addr_len: u16,
            __pad3: [1]u16,
        },
    },
    addr3_cmd: extern union {
        addr3: u64,
        cmd: [0]u8,
    },
    __pad2: u64,
};

pub const IoUringSqeFlags = packed struct(u8) {
    fixed_file: bool = false,
    io_drain: bool = false,
    io_link: bool = false,
    io_hardlink: bool = false,
    async_mode: bool = false,
    buffer_select: bool = false,
    cqe_skip_success: bool = false,
    _pad: u1 = 0,
};

// ============================================================================
// CQE (Completion Queue Entry) - 16 or 32 bytes
// ============================================================================

pub const IoUringCqe = extern struct {
    user_data: u64,
    res: i32,
    flags: IoUringCqeFlags,
};

pub const IoUringCqe32 = extern struct {
    user_data: u64,
    res: i32,
    flags: IoUringCqeFlags,
    big_cqe: [2]u64,
};

pub const IoUringCqeFlags = packed struct(u32) {
    buffer: bool = false,       // F_BUFFER - buffer index in upper 16 bits
    more: bool = false,         // F_MORE - more CQEs to come
    sock_nonempty: bool = false, // F_SOCK_NONEMPTY
    notif: bool = false,        // F_NOTIF - notification CQE
    _pad: u12 = 0,
    buffer_id: u16 = 0,        // upper 16 bits for buffer selection
};

// ============================================================================
// io_uring Setup/Params
// ============================================================================

pub const IoUringSetupFlags = packed struct(u32) {
    iopoll: bool = false,
    sqpoll: bool = false,
    sq_aff: bool = false,
    cqsize: bool = false,
    clamp: bool = false,
    attach_wq: bool = false,
    r_disabled: bool = false,
    submit_all: bool = false,
    coop_taskrun: bool = false,
    taskrun_flag: bool = false,
    sqe128: bool = false,
    cqe32: bool = false,
    single_issuer: bool = false,
    defer_taskrun: bool = false,
    no_mmap: bool = false,
    registered_fd_only: bool = false,
    no_sqarray: bool = false,
    _pad: u15 = 0,
};

pub const IoUringParams = extern struct {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: IoUringFeatures,
    wq_fd: u32,
    resv: [3]u32,
    sq_off: IoUringSqRingOffsets,
    cq_off: IoUringCqRingOffsets,
};

pub const IoUringFeatures = packed struct(u32) {
    single_mmap: bool = false,
    nodrop: bool = false,
    submit_stable: bool = false,
    rw_cur_pos: bool = false,
    cur_personality: bool = false,
    fast_poll: bool = false,
    poll_32bits: bool = false,
    sqpoll_nonfixed: bool = false,
    ext_arg: bool = false,
    native_workers: bool = false,
    rsrc_tags: bool = false,
    cqe_skip: bool = false,
    linked_file: bool = false,
    reg_reg_ring: bool = false,
    recvsend_bundle: bool = false,
    min_timeout: bool = false,
    _pad: u16 = 0,
};

pub const IoUringSqRingOffsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
};

pub const IoUringCqRingOffsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
};

// ============================================================================
// io_uring Register Operations
// ============================================================================

pub const IoUringRegisterOp = enum(u32) {
    register_buffers = 0,
    unregister_buffers = 1,
    register_files = 2,
    unregister_files = 3,
    register_eventfd = 4,
    unregister_eventfd = 5,
    register_files_update = 6,
    register_eventfd_async = 7,
    register_probe = 8,
    register_personality = 9,
    unregister_personality = 10,
    register_restrictions = 11,
    register_enable_rings = 12,
    register_files2 = 13,
    register_files_update2 = 14,
    register_buffers2 = 15,
    register_buffers_update = 16,
    register_iowq_aff = 17,
    unregister_iowq_aff = 18,
    register_iowq_max_workers = 19,
    register_ring_fds = 20,
    unregister_ring_fds = 21,
    register_pbuf_ring = 22,
    unregister_pbuf_ring = 23,
    register_sync_cancel = 24,
    register_file_alloc_range = 25,
    register_pbuf_status = 26,
    register_napi = 27,
    unregister_napi = 28,
    register_clock = 29,
    register_clone_buffers = 30,
    last = 31,
};

// ============================================================================
// io_uring Provided Buffer Ring
// ============================================================================

pub const IoUringBufRing = extern struct {
    resv1: u64,
    resv2: u32,
    resv3: u16,
    tail: u16,
    // bufs follow
};

pub const IoUringBuf = extern struct {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
};

pub const IoUringBufReg = extern struct {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [3]u64,
};

pub const IoUringBufStatus = extern struct {
    buf_group: u32,
    head: u32,
    resv: [8]u32,
};

// ============================================================================
// io_uring Restrictions
// ============================================================================

pub const IoUringRestriction = extern struct {
    opcode: IoUringRestrictionOp,
    register_op: union { register_op: u8, sqe_op: u8, sqe_flags: u8 },
    resv: u8,
    resv2: [3]u32,
};

pub const IoUringRestrictionOp = enum(u16) {
    register_op = 0,
    sqe_op = 1,
    sqe_flags_allowed = 2,
    sqe_flags_required = 3,
    last = 4,
};

// ============================================================================
// Kernel-Side io_uring Context
// ============================================================================

pub const IoRingCtx = struct {
    // Ring sizes
    sq_entries: u32,
    cq_entries: u32,
    sq_mask: u32,
    cq_mask: u32,
    // Flags
    flags: IoUringSetupFlags,
    features: IoUringFeatures,
    // SQ state
    sq_sqes: u64,       // pointer to SQE array
    sq_array: u64,      // pointer to SQ array
    sq_head: u32,
    sq_tail: u32,
    sq_dropped: u32,
    sq_flags: IoSqFlags,
    // CQ state
    cq_cqes: u64,       // pointer to CQE array
    cq_head: u32,
    cq_tail: u32,
    cq_overflow: u32,
    cq_flags: u32,
    // Task/thread
    submitter_task: u64,
    sq_thread: u64,
    sq_cpu: i32,
    sq_thread_idle: u32,
    // Registered resources
    registered_files_count: u32,
    registered_buffers_count: u32,
    registered_eventfd: i32,
    // Work queues
    io_wq: u64,
    hash_table: u64,
    // Cancelation
    cancel_table_size: u32,
    cancel_seq: u64,
    // Accounting
    cq_extra: u32,
    // Statistics
    stats: IoUringStats,
};

pub const IoSqFlags = packed struct(u32) {
    need_wakeup: bool = false,
    cq_overflow: bool = false,
    taskrun: bool = false,
    _pad: u29 = 0,
};

pub const IoUringStats = struct {
    submissions: u64,
    completions: u64,
    sq_polls: u64,
    cq_overflows: u64,
    cancel_ok: u64,
    cancel_fail: u64,
    linked_requests: u64,
    timeouts: u64,
    // Per-op counters
    op_counts: [58]u64,    // one per IoUringOp
    // Latency
    avg_submit_latency_ns: u64,
    avg_complete_latency_ns: u64,
    max_submit_latency_ns: u64,
    max_complete_latency_ns: u64,
    // Worker stats
    io_workers_active: u32,
    io_workers_max: u32,
    bound_workers_active: u32,
    bound_workers_max: u32,
};

// ============================================================================
// io_uring Request (kernel internal)
// ============================================================================

pub const IoKiocb = struct {
    // Common fields
    ctx: ?*IoRingCtx,
    opcode: IoUringOp,
    flags: IoKiocbFlags,
    user_data: u64,
    personality: u16,
    // File
    file: u64,         // struct file *
    file_index: u32,
    // Result
    result: i32,
    cqe_flags: u32,
    // Buffer
    buf: u64,
    buf_index: u16,
    // Link chain
    link: ?*IoKiocb,
    // Timeout
    timeout_rem: u64,
    // Async data
    async_data: u64,
    // Work
    work: IoUringWork,
    // CQE extra for CQE32
    extra1: u64,
    extra2: u64,
};

pub const IoKiocbFlags = packed struct(u32) {
    fixed_file: bool = false,
    drain: bool = false,
    link: bool = false,
    hardlink: bool = false,
    async_mode: bool = false,
    buffer_select: bool = false,
    skip_cqe: bool = false,
    polled: bool = false,
    in_hash: bool = false,
    needs_cleanup: bool = false,
    poll_first: bool = false,
    double_poll: bool = false,
    buffer_ring: bool = false,
    cqe32_init: bool = false,
    multishot: bool = false,
    _pad: u17 = 0,
};

pub const IoUringWork = struct {
    list: u64,          // list_head
    flags: u32,
    cancel_seq: u64,
    identity: u64,
};

// ============================================================================
// io_uring Timeout
// ============================================================================

pub const IoUringTimeoutData = struct {
    timer: u64,         // hrtimer
    ts: Timespec64,
    mode: IoUringTimeoutMode,
    flags: u32,
    seq_offset: u32,
    target_seq: u32,
};

pub const Timespec64 = extern struct {
    tv_sec: i64,
    tv_nsec: i64,
};

pub const IoUringTimeoutMode = enum(u8) {
    relative = 0,
    absolute = 1,
    boottime = 2,
    realtime = 3,
    clock_monotonic = 4,
};

// ============================================================================
// io_uring NAPI
// ============================================================================

pub const IoUringNapi = struct {
    busy_poll_to: u32,
    prefer_busy_poll: bool,
    track_napi: bool,
    napi_id: u32,
};

// ============================================================================
// io_uring msg_ring
// ============================================================================

pub const IoUringMsgData = struct {
    src_fd: i32,
    dst_fd: i32,
    src_file: u64,
    flags: IoUringMsgFlags,
};

pub const IoUringMsgFlags = packed struct(u32) {
    cqe_data: bool = false,
    cqe_flags: bool = false,
    _pad: u30 = 0,
};

// ============================================================================
// io_uring Zero-Copy Send
// ============================================================================

pub const IoUringSendZc = struct {
    addr: u64,
    addr_len: u32,
    buf_index: u16,
    zc_flags: u16,
    notif_seq: u32,
};

// ============================================================================
// io_uring Manager
// ============================================================================

pub const IoUringSubsystemManager = struct {
    active_rings: u32,
    total_rings_created: u64,
    total_submissions: u64,
    total_completions: u64,
    total_cq_overflows: u64,
    sqpoll_threads: u32,
    io_workers: u32,
    registered_files: u64,
    registered_buffers: u64,
    provided_buf_rings: u32,
    total_cancel_ops: u64,
    total_timeouts: u64,
    // Per-opcode totals
    op_totals: [58]u64,
    initialized: bool,

    pub fn init() IoUringSubsystemManager {
        return IoUringSubsystemManager{
            .active_rings = 0,
            .total_rings_created = 0,
            .total_submissions = 0,
            .total_completions = 0,
            .total_cq_overflows = 0,
            .sqpoll_threads = 0,
            .io_workers = 0,
            .registered_files = 0,
            .registered_buffers = 0,
            .provided_buf_rings = 0,
            .total_cancel_ops = 0,
            .total_timeouts = 0,
            .op_totals = [_]u64{0} ** 58,
            .initialized = true,
        };
    }
};
