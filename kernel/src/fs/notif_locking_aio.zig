// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Filesystem Notifications (fanotify/inotify),
// io_uring FS Operations, File Locking (POSIX/flock/OFD),
// Direct I/O, AIO, FS Freezing, Quotas
// More advanced than Linux 2026 filesystem features

const std = @import("std");

// ============================================================================
// inotify
// ============================================================================

/// inotify event mask flags
pub const InotifyMask = packed struct {
    access: bool = false,         // IN_ACCESS
    modify: bool = false,         // IN_MODIFY
    attrib: bool = false,         // IN_ATTRIB
    close_write: bool = false,    // IN_CLOSE_WRITE
    close_nowrite: bool = false,  // IN_CLOSE_NOWRITE
    open: bool = false,           // IN_OPEN
    moved_from: bool = false,     // IN_MOVED_FROM
    moved_to: bool = false,       // IN_MOVED_TO
    create: bool = false,         // IN_CREATE
    delete: bool = false,         // IN_DELETE
    delete_self: bool = false,    // IN_DELETE_SELF
    move_self: bool = false,      // IN_MOVE_SELF
    _reserved: u1 = 0,
    unmount: bool = false,        // IN_UNMOUNT
    q_overflow: bool = false,     // IN_Q_OVERFLOW
    ignored: bool = false,        // IN_IGNORED
    // Flags for add_watch
    onlydir: bool = false,        // IN_ONLYDIR
    dont_follow: bool = false,    // IN_DONT_FOLLOW
    excl_unlink: bool = false,    // IN_EXCL_UNLINK
    _reserved2: u1 = 0,
    mask_create: bool = false,    // IN_MASK_CREATE
    mask_add: bool = false,       // IN_MASK_ADD
    _reserved3: u2 = 0,
    isdir: bool = false,          // IN_ISDIR
    oneshot: bool = false,        // IN_ONESHOT
    _padding: u6 = 0,
};

/// inotify event structure
pub const InotifyEvent = struct {
    wd: i32,             // Watch descriptor
    mask: u32,           // Event mask
    cookie: u32,         // Cookie for rename tracking
    len: u32,            // Name length (including null)
    // Followed by name[len]
};

/// inotify instance info
pub const InotifyInstance = struct {
    fd: i32,
    nr_watches: u32,
    max_watches: u32,
    queue_size: u32,
    max_queued_events: u32,
    // Zxyphor
    zxy_recursive: bool,
    zxy_batch_mode: bool,
};

// ============================================================================
// fanotify
// ============================================================================

/// fanotify event mask
pub const FanotifyMask = packed struct {
    access: bool = false,           // FAN_ACCESS
    modify: bool = false,           // FAN_MODIFY
    attrib: bool = false,           // FAN_ATTRIB
    close_write: bool = false,      // FAN_CLOSE_WRITE
    close_nowrite: bool = false,    // FAN_CLOSE_NOWRITE
    open: bool = false,             // FAN_OPEN
    moved_from: bool = false,       // FAN_MOVED_FROM
    moved_to: bool = false,         // FAN_MOVED_TO
    create: bool = false,           // FAN_CREATE
    delete: bool = false,           // FAN_DELETE
    delete_self: bool = false,      // FAN_DELETE_SELF
    move_self: bool = false,        // FAN_MOVE_SELF
    open_exec: bool = false,        // FAN_OPEN_EXEC
    // Event info flags
    ondir: bool = false,            // FAN_ONDIR
    event_on_child: bool = false,   // FAN_EVENT_ON_CHILD
    // Permission events
    open_perm: bool = false,        // FAN_OPEN_PERM
    access_perm: bool = false,      // FAN_ACCESS_PERM
    open_exec_perm: bool = false,   // FAN_OPEN_EXEC_PERM
    // Rename
    rename: bool = false,           // FAN_RENAME
    // FS error
    fs_error: bool = false,         // FAN_FS_ERROR
    // Pre-content
    pre_access: bool = false,       // FAN_PRE_ACCESS
    _padding: u11 = 0,
};

/// fanotify init flags
pub const FanotifyInitFlags = packed struct {
    cloexec: bool = false,
    nonblock: bool = false,
    class_notif: bool = false,
    class_content: bool = false,
    class_pre_content: bool = false,
    unlimited_queue: bool = false,
    unlimited_marks: bool = false,
    report_tid: bool = false,
    report_fid: bool = false,
    report_dir_fid: bool = false,
    report_name: bool = false,
    report_target_fid: bool = false,
    report_pidfd: bool = false,
    _padding: u3 = 0,
};

/// fanotify mark flags
pub const FanotifyMarkFlags = packed struct {
    add: bool = false,
    remove: bool = false,
    dont_follow: bool = false,
    onlydir: bool = false,
    mount: bool = false,          // FAN_MARK_MOUNT
    filesystem: bool = false,     // FAN_MARK_FILESYSTEM
    ignored_mask: bool = false,
    ignored_surv_modify: bool = false,
    flush: bool = false,
    evictable: bool = false,
    ignore: bool = false,
    _padding: u5 = 0,
};

/// fanotify response
pub const FanotifyResponse = struct {
    fd: i32,
    response: FanotifyResponseVal,
};

pub const FanotifyResponseVal = enum(u32) {
    allow = 0x01,
    deny = 0x02,
};

/// fanotify event metadata
pub const FanotifyEventMetadata = struct {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
};

pub const FANOTIFY_METADATA_VERSION: u8 = 3;

/// fanotify event info FID
pub const FanotifyEventInfoFid = struct {
    hdr_type: u8,         // FAN_EVENT_INFO_TYPE_FID
    hdr_pad: u8,
    hdr_len: u16,
    fsid: [2]u32,         // __kernel_fsid_t
    // Followed by file_handle
};

// ============================================================================
// File Locking
// ============================================================================

/// Lock type
pub const FlockType = enum(i16) {
    rdlck = 0,           // F_RDLCK - Read lock
    wrlck = 1,           // F_WRLCK - Write lock
    unlck = 2,           // F_UNLCK - Unlock
};

/// flock structure (BSD-style whole-file locking)
pub const Flock = struct {
    l_type: FlockType,
    l_whence: i16,        // SEEK_SET, SEEK_CUR, SEEK_END
    l_start: i64,
    l_len: i64,           // 0 = entire file
    l_pid: i32,
};

/// Lock operation (flock syscall)
pub const LockOp = packed struct {
    sh: bool = false,     // LOCK_SH
    ex: bool = false,     // LOCK_EX
    nb: bool = false,     // LOCK_NB
    un: bool = false,     // LOCK_UN
    _padding: u4 = 0,
};

/// OFD lock (Open File Description lock)
pub const OfdLockCmd = enum(i32) {
    getlk = 36,          // F_OFD_GETLK
    setlk = 37,          // F_OFD_SETLK
    setlkw = 38,         // F_OFD_SETLKW
};

/// Lock info
pub const FileLockInfo = struct {
    lock_type: FlockType,
    whence: i16,
    start: i64,
    end: i64,             // 0 = EOF
    owner_pid: i32,
    owner_fd: i32,        // For OFD locks
    is_posix: bool,
    is_flock: bool,
    is_ofd: bool,
    // Lease
    is_lease: bool,
    lease_type: FlockType,
    // Zxyphor
    zxy_distributed: bool,
};

/// Lease type
pub const LeaseType = enum(i32) {
    f_rdlck = 0,
    f_wrlck = 1,
    f_unlck = 2,
};

// ============================================================================
// Direct I/O
// ============================================================================

/// Direct I/O flags
pub const DirectIoFlags = packed struct {
    sync: bool = false,        // O_SYNC
    dsync: bool = false,       // O_DSYNC
    direct: bool = false,      // O_DIRECT
    // Alignment requirements
    alignment_shift: u4 = 0,   // Block size shift (e.g., 9=512, 12=4096)
    _padding: u1 = 0,
};

/// I/O priority
pub const IoPriority = struct {
    class: IoPrioClass,
    data: u13,            // Priority level within class
};

/// I/O priority class
pub const IoPrioClass = enum(u3) {
    none = 0,
    rt = 1,              // Real-time
    be = 2,              // Best-effort
    idle = 3,            // Idle
};

// ============================================================================
// AIO (Asynchronous I/O)
// ============================================================================

/// AIO opcode
pub const AioOpcode = enum(u16) {
    pread = 0,
    pwrite = 1,
    fsync = 2,
    fdsync = 3,
    noop = 6,
    preadv = 7,
    pwritev = 8,
};

/// AIO iocb (I/O Control Block)
pub const AioIocb = struct {
    aio_data: u64,        // User data passed back in completion
    aio_key: u32,         // __PADDED
    aio_rw_flags: i32,    // RWF_*
    aio_lio_opcode: AioOpcode,
    aio_reqprio: i16,
    aio_fildes: u32,
    aio_buf: u64,
    aio_nbytes: u64,
    aio_offset: i64,
    _reserved2: u64,
    aio_flags: u32,
    aio_resfd: u32,       // eventfd for notification
};

/// AIO completion event
pub const AioEvent = struct {
    data: u64,            // From iocb.aio_data
    obj: u64,             // iocb pointer
    res: i64,             // Result (bytes or error)
    res2: i64,            // Secondary result
};

/// AIO context info
pub const AioContext = struct {
    max_reqs: u32,
    nr_pending: u32,
    nr_running: u32,
    nr_completed: u32,
    // Ring buffer
    ring_pages: u32,
    head: u32,
    tail: u32,
};

// ============================================================================
// io_uring FS Operations
// ============================================================================

/// io_uring opcodes (FS-related)
pub const IoUringFsOp = enum(u8) {
    nop = 0,
    readv = 1,
    writev = 2,
    fsync = 3,
    read_fixed = 4,
    write_fixed = 5,
    openat = 18,
    close = 19,
    statx = 21,
    read = 22,
    write = 23,
    fadvise = 24,
    madvise = 25,
    openat2 = 28,
    fallocate = 30,
    unlinkat = 36,
    renameat = 37,
    mkdirat = 38,
    symlinkat = 39,
    linkat = 40,
    fsetxattr = 42,
    setxattr = 43,
    fgetxattr = 44,
    getxattr = 45,
    splice = 46,
    tee = 47,
    ftruncate = 48,
    // Zxyphor
    zxy_zero_copy_read = 200,
    zxy_batched_stat = 201,
};

/// io_uring SQE flags (FS-relevant)
pub const IoUringSqeFlags = packed struct {
    fixed_file: bool = false,       // IOSQE_FIXED_FILE
    io_drain: bool = false,         // IOSQE_IO_DRAIN
    io_link: bool = false,          // IOSQE_IO_LINK
    io_hardlink: bool = false,      // IOSQE_IO_HARDLINK
    async_flag: bool = false,       // IOSQE_ASYNC
    buffer_select: bool = false,    // IOSQE_BUFFER_SELECT
    cqe_skip_success: bool = false, // IOSQE_CQE_SKIP_SUCCESS
    _padding: u1 = 0,
};

/// Read/Write flags
pub const RwfFlags = packed struct {
    hipri: bool = false,       // RWF_HIPRI (high priority)
    dsync: bool = false,       // RWF_DSYNC
    sync: bool = false,        // RWF_SYNC
    nowait: bool = false,      // RWF_NOWAIT
    append: bool = false,      // RWF_APPEND
    noappend: bool = false,    // RWF_NOAPPEND
    _padding: u2 = 0,
};

// ============================================================================
// Filesystem Quotas
// ============================================================================

/// Quota type
pub const QuotaType = enum(u8) {
    usrquota = 0,
    grpquota = 1,
    prjquota = 2,
};

/// Quota format
pub const QuotaFormat = enum(u32) {
    vfsold = 1,
    vfsv0 = 2,
    vfsv1 = 4,
    // Zxyphor
    zxy_v1 = 100,
};

/// Disk quota (dqblk)
pub const DiskQuota = struct {
    dqb_bhardlimit: u64,  // Hard block limit
    dqb_bsoftlimit: u64,  // Soft block limit
    dqb_curspace: u64,     // Current disk space used
    dqb_ihardlimit: u64,   // Hard inode limit
    dqb_isoftlimit: u64,   // Soft inode limit
    dqb_curinodes: u64,    // Current inode count
    dqb_btime: i64,        // Block time limit
    dqb_itime: i64,        // Inode time limit
    dqb_valid: u32,        // QIF_* flags
};

/// Quota info (dqinfo)
pub const QuotaInfo = struct {
    dqi_bgrace: u64,      // Block grace period
    dqi_igrace: u64,      // Inode grace period
    dqi_flags: u32,       // DQF_*
    dqi_valid: u32,       // IIF_*
};

// ============================================================================
// FS Freeze
// ============================================================================

/// Freeze state
pub const FsFreezeState = enum(u8) {
    unfrozen = 0,
    write_lock = 1,
    pagefault_lock = 2,
    frozen = 3,
};

/// Freeze info
pub const FsFreezeInfo = struct {
    state: FsFreezeState,
    freeze_count: u32,
    nr_frozen_sb: u32,
    // Zxyphor
    zxy_auto_thaw_timeout_ms: u64,
};

// ============================================================================
// fallocate
// ============================================================================

/// fallocate mode flags
pub const FallocateMode = packed struct {
    keep_size: bool = false,       // FALLOC_FL_KEEP_SIZE
    punch_hole: bool = false,      // FALLOC_FL_PUNCH_HOLE
    no_hide_stale: bool = false,   // FALLOC_FL_NO_HIDE_STALE
    collapse_range: bool = false,  // FALLOC_FL_COLLAPSE_RANGE
    zero_range: bool = false,      // FALLOC_FL_ZERO_RANGE
    insert_range: bool = false,    // FALLOC_FL_INSERT_RANGE
    unshare_range: bool = false,   // FALLOC_FL_UNSHARE_RANGE
    _padding: u1 = 0,
};

// ============================================================================
// fadvise
// ============================================================================

/// fadvise advice
pub const FadviseAdvice = enum(i32) {
    normal = 0,           // POSIX_FADV_NORMAL
    random = 1,           // POSIX_FADV_RANDOM
    sequential = 2,       // POSIX_FADV_SEQUENTIAL
    willneed = 3,         // POSIX_FADV_WILLNEED
    dontneed = 4,         // POSIX_FADV_DONTNEED
    noreuse = 5,          // POSIX_FADV_NOREUSE
};

// ============================================================================
// statx
// ============================================================================

/// statx mask flags
pub const StatxMask = packed struct {
    type_field: bool = false,    // STATX_TYPE
    mode: bool = false,          // STATX_MODE
    nlink: bool = false,         // STATX_NLINK
    uid: bool = false,           // STATX_UID
    gid: bool = false,           // STATX_GID
    atime: bool = false,         // STATX_ATIME
    mtime: bool = false,         // STATX_MTIME
    ctime: bool = false,         // STATX_CTIME
    ino: bool = false,           // STATX_INO
    size: bool = false,          // STATX_SIZE
    blocks: bool = false,        // STATX_BLOCKS
    btime: bool = false,         // STATX_BTIME
    mnt_id: bool = false,        // STATX_MNT_ID
    dioalign: bool = false,      // STATX_DIOALIGN
    mnt_id_unique: bool = false, // STATX_MNT_ID_UNIQUE
    subvol: bool = false,        // STATX_SUBVOL
    _padding: u16 = 0,
};

/// statx attributes
pub const StatxAttr = packed struct {
    compressed: bool = false,
    immutable: bool = false,
    append: bool = false,
    nodump: bool = false,
    encrypted: bool = false,
    automount: bool = false,
    mount_root: bool = false,
    verity: bool = false,
    dax: bool = false,
    // Zxyphor
    zxy_dedup: bool = false,
    zxy_cow: bool = false,
    _padding: u21 = 0,
};

/// statx structure
pub const Statx = struct {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    _spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    // Timestamps
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    // Device
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    // Mount ID
    stx_mnt_id: u64,
    // Direct I/O alignment
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    // Subvol
    stx_subvol: u64,
    _spare3: [11]u64,
};

pub const StatxTimestamp = struct {
    tv_sec: i64,
    tv_nsec: u32,
    _reserved: i32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const FsNotifSubsystem = struct {
    // inotify
    nr_inotify_instances: u64,
    nr_inotify_watches: u64,
    max_watches_per_instance: u32,
    // fanotify
    nr_fanotify_groups: u64,
    nr_fanotify_marks: u64,
    nr_perm_events_pending: u64,
    // Locking
    nr_posix_locks: u64,
    nr_flock_locks: u64,
    nr_ofd_locks: u64,
    nr_leases: u64,
    nr_lock_deadlocks: u64,
    // AIO
    nr_aio_contexts: u64,
    total_aio_ops: u64,
    // io_uring FS
    nr_io_uring_fs_ops: u64,
    // Quotas
    nr_quota_enabled_fs: u32,
    // Zxyphor
    zxy_recursive_inotify: bool,
    zxy_batched_notif: bool,
    initialized: bool,

    pub fn init() FsNotifSubsystem {
        return FsNotifSubsystem{
            .nr_inotify_instances = 0,
            .nr_inotify_watches = 0,
            .max_watches_per_instance = 65536,
            .nr_fanotify_groups = 0,
            .nr_fanotify_marks = 0,
            .nr_perm_events_pending = 0,
            .nr_posix_locks = 0,
            .nr_flock_locks = 0,
            .nr_ofd_locks = 0,
            .nr_leases = 0,
            .nr_lock_deadlocks = 0,
            .nr_aio_contexts = 0,
            .total_aio_ops = 0,
            .nr_io_uring_fs_ops = 0,
            .nr_quota_enabled_fs = 0,
            .zxy_recursive_inotify = true,
            .zxy_batched_notif = true,
            .initialized = false,
        };
    }
};
