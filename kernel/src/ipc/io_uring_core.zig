// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - io_uring Core Engine, SQE/CQE Definitions,
// io_uring Opcodes, Submission Queue, Completion Queue,
// io_uring Linked Operations, Fixed Files/Buffers,
// io_uring Provided Buffers, io_uring Multishot
// More advanced than Linux 2026 io_uring subsystem

const std = @import("std");

// ============================================================================
// io_uring Setup Parameters
// ============================================================================

/// io_uring setup flags
pub const IoUringSetupFlags = packed struct(u32) {
    iopoll: bool = false,           // SQ_POLL - kernel polls for completions
    sqpoll: bool = false,           // SQPOLL - kernel polls SQ
    sq_aff: bool = false,           // SQPOLL CPU affinity
    cqsize: bool = false,           // custom CQ size
    clamp: bool = false,            // clamp SQ/CQ ring sizes
    attach_wq: bool = false,        // attach to existing workqueue
    r_disabled: bool = false,       // ring starts disabled
    submit_all: bool = false,       // submit all SQEs on submit
    coop_taskrun: bool = false,     // cooperative task running
    taskrun_flag: bool = false,     // use IORING_SQ_TASKRUN
    sqe128: bool = false,           // 128-byte SQEs
    cqe32: bool = false,            // 32-byte CQEs
    single_issuer: bool = false,    // only one task submits
    defer_taskrun: bool = false,    // defer taskrun to cq wait
    no_mmap: bool = false,          // no mmap, use registered buffers
    registered_fd_only: bool = false,
    no_sqarray: bool = false,       // no SQ array
    // Zxyphor extensions
    zxy_priority_queue: bool = false,
    zxy_numa_aware: bool = false,
    _padding: u13 = 0,
};

/// io_uring parameters
pub const IoUringParams = extern struct {
    sq_entries: u32,
    cq_entries: u32,
    flags: IoUringSetupFlags,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: IoUringFeatures,
    wq_fd: u32,
    resv: [3]u32,
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
};

/// io_uring features (returned by kernel)
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
    // Zxyphor
    zxy_batch_submit: bool = false,
    zxy_kernel_bufpool: bool = false,
    _padding: u15 = 0,
};

/// SQ ring offsets
pub const IoSqringOffsets = extern struct {
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

/// CQ ring offsets
pub const IoCqringOffsets = extern struct {
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
// SQE - Submission Queue Entry
// ============================================================================

/// io_uring SQE (Submission Queue Entry)
pub const IoUringSqe = extern struct {
    opcode: IoUringOp,
    flags: SqeFlags,
    ioprio: u16,
    fd: i32,
    off_addr2: extern union {
        off: u64,
        addr2: u64,
        cmd_op: u32,
        __pad1: [1]u64,
    },
    addr_splice: extern union {
        addr: u64,
        splice_off_in: u64,
        level: u32,
        __pad1: [1]u64,
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
        nop_flags: u32,
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

/// io_uring operations (opcodes)
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
    recv_bundle = 58,
    // Zxyphor extensions
    zxy_batch_io = 200,
    zxy_kernel_call = 201,
    _,
};

/// SQE flags
pub const SqeFlags = packed struct(u8) {
    fixed_file: bool = false,     // use fixed fileset
    io_drain: bool = false,       // issue after inflight completions
    io_link: bool = false,        // link with next SQE
    io_hardlink: bool = false,    // hard link with next
    io_async: bool = false,       // always go async
    buffer_select: bool = false,  // select buffer from group
    cqe_skip_success: bool = false, // don't post CQE on success
    _padding: u1 = 0,
};

// ============================================================================
// CQE - Completion Queue Entry
// ============================================================================

/// io_uring CQE (Completion Queue Entry)
pub const IoUringCqe = extern struct {
    user_data: u64,
    res: i32,
    flags: CqeFlags,
};

/// Extended CQE (32-byte mode)
pub const IoUringCqe32 = extern struct {
    user_data: u64,
    res: i32,
    flags: CqeFlags,
    big_cqe: [2]u64,
};

/// CQE flags
pub const CqeFlags = packed struct(u32) {
    buffer: bool = false,       // buffer ID is set
    more: bool = false,         // more CQEs for this request
    sock_nonempty: bool = false, // socket has more data
    notif: bool = false,        // notification CQE
    _padding: u12 = 0,
    buf_id: u16 = 0,           // buffer ID
};

// ============================================================================
// io_uring Register Operations
// ============================================================================

/// io_uring_register opcodes
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
    // Zxyphor extensions
    zxy_register_kernel_bufs = 200,
    _,
};

/// io_uring restriction entry
pub const IoUringRestriction = extern struct {
    opcode: IoUringRestrictionOp,
    register_op_or_sqe_op: u8,
    sqe_flags: SqeFlags,
    resv: u8,
    resv2: [3]u32,
};

pub const IoUringRestrictionOp = enum(u16) {
    register_op = 0,
    sqe_op = 1,
    sqe_flags_allowed = 2,
    sqe_flags_required = 3,
    _,
};

// ============================================================================
// Provided Buffer Ring
// ============================================================================

/// Buffer ring entry
pub const IoUringBufRing = extern struct {
    resv1: u64,
    resv2: u32,
    resv3: u16,
    tail: u16,
    // followed by IoUringBuf entries
};

/// Individual buffer entry in ring
pub const IoUringBuf = extern struct {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
};

/// Provided buffer ring registration
pub const IoUringBufReg = extern struct {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [3]u64,
};

/// Buffer status for IORING_REGISTER_PBUF_STATUS
pub const IoUringBufStatus = extern struct {
    buf_group: u32,
    head: u32,
    resv: [8]u32,
};

// ============================================================================
// io_uring NAPI
// ============================================================================

/// NAPI configuration for io_uring
pub const IoUringNapi = extern struct {
    busy_poll_to: u32,
    prefer_busy_poll: u8,
    pad: [3]u8,
    resv: u64,
};

// ============================================================================
// io_uring Sync Cancel
// ============================================================================

/// Sync cancel request
pub const IoUringSyncCancelReg = extern struct {
    addr: u64,
    fd: i32,
    flags: u32,
    timeout_sec: i64,
    timeout_nsec: i64,
    opcode: u8,
    pad: [7]u8,
    pad2: [3]u64,
};

// ============================================================================
// io_uring Clock
// ============================================================================

pub const IoUringClockRegister = extern struct {
    clockid: u32,
    pad: [3]u32,
};

// ============================================================================
// io_uring Internal Statistics
// ============================================================================

/// io_uring context statistics
pub const IoUringCtxStats = struct {
    sq_entries: u32 = 0,
    cq_entries: u32 = 0,
    sq_sq_dropped: u64 = 0,
    cq_cq_overflow: u64 = 0,
    submit_count: u64 = 0,
    complete_count: u64 = 0,
    sqpoll_wakeups: u64 = 0,
    poll_reqs: u64 = 0,
    cancel_reqs: u64 = 0,
    timeout_reqs: u64 = 0,
    link_reqs: u64 = 0,
    async_reqs: u64 = 0,
    fixed_file_reqs: u64 = 0,
    buf_select_reqs: u64 = 0,
    zc_send_reqs: u64 = 0,
    multishot_reqs: u64 = 0,
    // Per-opcode counters
    opcode_counts: [256]u64 = [_]u64{0} ** 256,
};

// ============================================================================
// io_uring Subsystem Manager
// ============================================================================

pub const IoUringSubsystem = struct {
    nr_rings: u64 = 0,
    nr_sqpoll_rings: u64 = 0,
    nr_registered_files: u64 = 0,
    nr_registered_buffers: u64 = 0,
    nr_provided_buf_rings: u64 = 0,
    nr_fixed_workers: u32 = 0,
    nr_unbound_workers: u32 = 0,
    total_submits: u64 = 0,
    total_completions: u64 = 0,
    total_cancels: u64 = 0,
    max_entries_supported: u32 = 32768,
    zxy_priority_enabled: bool = false,
    zxy_numa_enabled: bool = false,
    initialized: bool = false,

    pub fn init() IoUringSubsystem {
        return IoUringSubsystem{
            .initialized = true,
        };
    }
};
