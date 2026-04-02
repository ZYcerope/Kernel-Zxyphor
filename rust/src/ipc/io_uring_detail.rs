// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust io_uring Advanced
// Complete: io_uring submission/completion queues, SQE opcodes, CQE handling,
// buffer groups, registered files, fixed buffers, linked SQEs, multishot

use core::fmt;

// ============================================================================
// io_uring Constants
// ============================================================================

pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
pub const IORING_SETUP_SQE128: u32 = 1 << 10;
pub const IORING_SETUP_CQE32: u32 = 1 << 11;
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
pub const IORING_SETUP_NO_MMAP: u32 = 1 << 14;
pub const IORING_SETUP_REGISTERED_FD_ONLY: u32 = 1 << 15;
pub const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;

// ============================================================================
// SQE (Submission Queue Entry)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IoringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendmsgZc = 48,
    ReadMultishot = 49,
    Waitid = 50,
    Futex_Wait = 51,
    Futex_Wake = 52,
    Futex_Waitv = 53,
    FixedFdInstall = 54,
    Ftruncate = 55,
    Bind = 56,
    Listen = 57,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off_addr2: u64,       // union: off, addr2
    pub addr_splice_off: u64, // union: addr, splice_off_in
    pub len: u32,
    pub op_flags: u32,        // union: rw_flags, fsync_flags, etc.
    pub user_data: u64,
    pub buf_index: u16,       // union: buf_index, buf_group
    pub personality: u16,
    pub splice_fd_in: i32,    // union: splice_fd_in, file_index, optlen
    pub addr3_pad: [u64; 2],  // addr3 + padding
}

pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

// ============================================================================
// CQE (Completion Queue Entry)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
    // Extended CQE (when IORING_SETUP_CQE32)
    pub big_cqe: [u64; 2],
}

pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;
pub const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
pub const IORING_CQE_F_NOTIF: u32 = 1 << 3;

// ============================================================================
// io_uring_params
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}

pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;
pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
pub const IORING_FEAT_NATIVE_WORKERS: u32 = 1 << 9;
pub const IORING_FEAT_RSRC_TAGS: u32 = 1 << 10;
pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;
pub const IORING_FEAT_LINKED_FILE: u32 = 1 << 12;
pub const IORING_FEAT_REG_REG_RING: u32 = 1 << 13;
pub const IORING_FEAT_RECVSEND_BUNDLE: u32 = 1 << 14;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

// ============================================================================
// io_uring Register Operations
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IoringRegisterOp {
    RegisterBuffers = 0,
    UnregisterBuffers = 1,
    RegisterFiles = 2,
    UnregisterFiles = 3,
    RegisterEventfd = 4,
    UnregisterEventfd = 5,
    RegisterFilesUpdate = 6,
    RegisterEventfdAsync = 7,
    RegisterProbe = 8,
    RegisterPersonality = 9,
    UnregisterPersonality = 10,
    RegisterRestrictions = 11,
    RegisterEnableRings = 12,
    RegisterFiles2 = 13,
    RegisterFilesUpdate2 = 14,
    RegisterBuffers2 = 15,
    RegisterBuffersUpdate = 16,
    RegisterIowqAff = 17,
    UnregisterIowqAff = 18,
    RegisterIowqMaxWorkers = 19,
    RegisterRingFds = 20,
    UnregisterRingFds = 21,
    RegisterPbufRing = 22,
    UnregisterPbufRing = 23,
    RegisterSyncCancel = 24,
    RegisterFileAllocRange = 25,
    RegisterPbufStatus = 26,
    RegisterNapi = 27,
    UnregisterNapi = 28,
    RegisterClock = 29,
    RegisterCloneBuffers = 30,
}

// ============================================================================
// Buffer Ring (registered)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringBufReg {
    pub ring_addr: u64,
    pub ring_entries: u32,
    pub bgid: u16,
    pub flags: u16,
    pub resv: [u64; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringBuf {
    pub addr: u64,
    pub len: u32,
    pub bid: u16,
    pub resv: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringBufRing {
    pub resv1: u64,
    pub resv2: u32,
    pub resv3: u16,
    pub tail: u16,
    // Followed by IoUringBuf[]
}

// ============================================================================
// Resource Tags
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringRsrcRegister {
    pub nr: u32,
    pub flags: u32,
    pub resv2: u64,
    pub data: u64,
    pub tags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringRsrcUpdate2 {
    pub offset: u32,
    pub resv: u32,
    pub data: u64,
    pub tags: u64,
    pub nr: u32,
    pub resv2: u32,
}

// ============================================================================
// Probe
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringProbeOp {
    pub op: u8,
    pub resv: u8,
    pub flags: u16,
    pub resv2: u32,
}

pub const IO_URING_OP_SUPPORTED: u16 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringProbe {
    pub last_op: u8,
    pub ops_len: u8,
    pub resv: u16,
    pub resv2: [u32; 3],
    pub ops: [IoUringProbeOp; 64],
}

// ============================================================================
// Restrictions
// ============================================================================

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IoringRestrictionOp {
    RegisterOp = 0,
    SqeOp = 1,
    SqeFlagsAllowed = 2,
    SqeFlagsRequired = 3,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringRestriction {
    pub opcode: u16,
    pub register_or_sqe_op_or_sqe_flags: u32,
    pub resv: u8,
    pub resv2: [u32; 3],
}

// ============================================================================
// Sync Cancel
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringSyncCancelReg {
    pub addr: u64,
    pub fd: i32,
    pub flags: u32,
    pub timeout: Timespec64,
    pub opcode: u8,
    pub pad: [u8; 7],
    pub pad2: [u64; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec64 {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// ============================================================================
// File Alloc Range
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringFileIndexRange {
    pub off: u32,
    pub len: u32,
    pub resv: u64,
}

// ============================================================================
// NAPI
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringNapi {
    pub busy_poll_to: u32,
    pub prefer_busy_poll: u8,
    pub pad: [u8; 3],
    pub resv: u64,
}

// ============================================================================
// Kernel-side io_uring context
// ============================================================================

pub struct IoRingCtx {
    pub flags: u32,
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub sq_mask: u32,
    pub cq_mask: u32,
    pub sq_sqe_count: u64,
    pub cq_cqe_count: u64,
    pub sq_dropped: u64,
    pub cq_overflow: u64,
    pub cached_sq_head: u32,
    pub cached_cq_tail: u32,
    pub sqo_sq_thread_cpu: i32,
    pub sqo_sq_thread_idle: u32,
    pub user_bufs_nr: u32,
    pub user_files_nr: u32,
    pub nr_user_bufs: u32,
    pub nr_user_files: u32,
    pub submit_state: IoSubmitState,
    pub cancel_table: IoCancelTable,
    pub restrictions_registered: bool,
    pub registered_rings: u32,
    pub work_done: u64,
}

pub struct IoSubmitState {
    pub file_refs: u32,
    pub free_list: u64,
    pub compl_nr: u32,
    pub compl_reqs: [u64; 32],
    pub submit_nr: u32,
    pub plug_started: bool,
    pub need_plug: bool,
    pub flush_cqes: bool,
    pub cq_flush: bool,
}

pub struct IoCancelTable {
    pub hash_bits: u32,
    pub entries: u64,
}

// ============================================================================
// io_uring stats
// ============================================================================

pub struct IoUringStats {
    pub total_ctx_created: u64,
    pub total_sqes_submitted: u64,
    pub total_cqes_posted: u64,
    pub total_cqe_overflows: u64,
    pub total_sq_polls: u64,
    pub total_timeouts: u64,
    pub total_cancels: u64,
    pub total_linked_sqes: u64,
    pub total_multishot_completions: u64,
    pub total_buf_ring_entries: u64,
    pub total_registered_files: u64,
    pub total_registered_buffers: u64,
}

impl IoUringStats {
    pub const fn new() Self {
        Self {
            total_ctx_created: 0,
            total_sqes_submitted: 0,
            total_cqes_posted: 0,
            total_cqe_overflows: 0,
            total_sq_polls: 0,
            total_timeouts: 0,
            total_cancels: 0,
            total_linked_sqes: 0,
            total_multishot_completions: 0,
            total_buf_ring_entries: 0,
            total_registered_files: 0,
            total_registered_buffers: 0,
        }
    }
}
