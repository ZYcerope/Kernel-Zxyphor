// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - File Descriptor Table, OverlayFS, and FUSE Advanced
// File descriptor management, dup/dup2/dup3, close_range, fd passing,
// OverlayFS (union mount), FUSE protocol, CUSE, virtiofs
// More advanced than Linux 2026 VFS/FUSE subsystem

const std = @import("std");

// ============================================================================
// File Descriptor Flags
// ============================================================================

pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_EXCL: u32 = 0x0080;
pub const O_NOCTTY: u32 = 0x0100;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;
pub const O_NONBLOCK: u32 = 0x0800;
pub const O_DSYNC: u32 = 0x1000;
pub const O_DIRECT: u32 = 0x4000;
pub const O_LARGEFILE: u32 = 0x8000;
pub const O_DIRECTORY: u32 = 0x10000;
pub const O_NOFOLLOW: u32 = 0x20000;
pub const O_NOATIME: u32 = 0x40000;
pub const O_CLOEXEC: u32 = 0x80000;
pub const O_SYNC: u32 = 0x101000;
pub const O_PATH: u32 = 0x200000;
pub const O_TMPFILE: u32 = 0x410000;

pub const FD_CLOEXEC: u32 = 1;

// fcntl commands
pub const F_DUPFD: u32 = 0;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const F_GETLK: u32 = 5;
pub const F_SETLK: u32 = 6;
pub const F_SETLKW: u32 = 7;
pub const F_SETOWN: u32 = 8;
pub const F_GETOWN: u32 = 9;
pub const F_SETSIG: u32 = 10;
pub const F_GETSIG: u32 = 11;
pub const F_SETOWN_EX: u32 = 15;
pub const F_GETOWN_EX: u32 = 16;
pub const F_OFD_GETLK: u32 = 36;
pub const F_OFD_SETLK: u32 = 37;
pub const F_OFD_SETLKW: u32 = 38;
pub const F_DUPFD_CLOEXEC: u32 = 1030;
pub const F_ADD_SEALS: u32 = 1033;
pub const F_GET_SEALS: u32 = 1034;

// File seals (memfd)
pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub const F_SEAL_EXEC: u32 = 0x0020;

// ============================================================================
// File Descriptor Entry
// ============================================================================

pub const FdFlags = packed struct(u32) {
    cloexec: bool = false,
    _reserved: u31 = 0,
};

pub const FileEntry = struct {
    // File pointer (struct file *)
    file: u64,
    // Flags
    fd_flags: FdFlags,
    // Open flags at time of open
    open_flags: u32,
    // Position
    pos: i64,
    // Reference to underlying objects
    inode_nr: u64,
    dentry: u64,
    // Path
    path: [256]u8,
    path_len: u16,
    // File type
    file_type: FileType,
    // Stats
    read_count: u64,
    write_count: u64,
    read_bytes: u64,
    write_bytes: u64,
};

pub const FileType = enum(u8) {
    regular = 0,
    directory = 1,
    symlink = 2,
    block_device = 3,
    char_device = 4,
    fifo = 5,
    socket = 6,
    unknown = 7,
};

// ============================================================================
// File Descriptor Table
// ============================================================================

pub const FdTable = struct {
    // Current table
    max_fds: u32,
    // Open bitmap
    open_fds_bitmap: [16]u64,    // Supports up to 1024 fds
    close_on_exec_bitmap: [16]u64,
    full_fds_bits: [16]u64,
    // Next free fd
    next_fd: u32,
    // Stats
    nr_open_fds: u32,
    nr_max_open_fds: u32,       // High water mark
    // Limits
    rlimit_nofile: u64,

    pub fn is_open(self: *const FdTable, fd: u32) bool {
        if (fd >= self.max_fds) return false;
        const word = fd / 64;
        const bit: u6 = @intCast(fd % 64);
        return (self.open_fds_bitmap[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn is_cloexec(self: *const FdTable, fd: u32) bool {
        if (fd >= self.max_fds) return false;
        const word = fd / 64;
        const bit: u6 = @intCast(fd % 64);
        return (self.close_on_exec_bitmap[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn count_open(self: *const FdTable) u32 {
        return self.nr_open_fds;
    }
};

// ============================================================================
// close_range (Linux 5.9+)
// ============================================================================

pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

pub const CloseRangeParams = struct {
    first: u32,
    last: u32,
    flags: u32,
};

// ============================================================================
// File Locking
// ============================================================================

pub const LockType = enum(u16) {
    f_rdlck = 0,
    f_wrlck = 1,
    f_unlck = 2,
};

pub const FileLock = struct {
    lock_type: LockType,
    whence: u16,
    start: i64,
    len: i64,           // 0 = to EOF
    pid: i32,
    // OFD lock
    is_ofd: bool,

    pub fn end_pos(self: *const FileLock) i64 {
        if (self.len == 0) return @as(i64, 0x7FFFFFFFFFFFFFFF);
        return self.start + self.len;
    }

    pub fn conflicts_with(self: *const FileLock, other: *const FileLock) bool {
        // Unlocks don't conflict
        if (self.lock_type == .f_unlck or other.lock_type == .f_unlck) return false;
        // Read-read doesn't conflict
        if (self.lock_type == .f_rdlck and other.lock_type == .f_rdlck) return false;
        // Check overlap
        return self.start < other.end_pos() and other.start < self.end_pos();
    }
};

// ============================================================================
// File Lease
// ============================================================================

pub const LeaseType = enum(u8) {
    f_rdlck = 0,
    f_wrlck = 1,
    f_unlck = 2,
};

pub const FileLease = struct {
    lease_type: LeaseType,
    pid: i32,
    active: bool,
    breaking: bool,
    break_time_ns: u64,
};

// ============================================================================
// OverlayFS
// ============================================================================

pub const OvlLayerType = enum(u8) {
    lower = 0,
    upper = 1,
    work = 2,
    merged = 3,
};

pub const OvlFlags = packed struct(u32) {
    redirect_dir: bool = false,
    redirect_ftype: bool = false,
    index: bool = false,
    uuid: bool = false,          // Real/lower layer UUID check
    nfs_export: bool = false,
    xino: bool = false,          // Extended inode numbering
    metacopy: bool = false,      // Metadata-only copy-up
    volatile_mode: bool = false,
    userxattr: bool = false,
    // Zxyphor
    zxy_dedup: bool = false,
    zxy_compress: bool = false,
    _reserved: u21 = 0,
};

pub const OvlWhiteoutType = enum(u8) {
    none = 0,
    whiteout = 1,        // Character device 0/0
    opaque = 2,          // Directory marked opaque
    redirect = 3,        // Redirect to different path
};

pub const OvlLayer = struct {
    path: [256]u8,
    path_len: u16,
    layer_type: OvlLayerType,
    idx: u16,
    // Filesystem info
    fstype: [16]u8,
    // Features
    has_xattr: bool,
    has_d_type: bool,
    has_fileid: bool,
};

pub const OvlEntry = struct {
    // Dentry pointers
    upper: u64,          // Upper layer dentry
    lower: [8]u64,       // Lower layer dentries
    nr_lower: u8,
    // Type
    whiteout: OvlWhiteoutType,
    // Redirect
    redirect: [256]u8,
    redirect_len: u16,
    // Copy-up
    needs_copyup: bool,
    metacopy: bool,
    // inode
    real_inode: u64,
};

pub const OvlSuperblock = struct {
    // Layers
    upper: OvlLayer,
    lower: [8]OvlLayer,
    nr_lower: u8,
    work: OvlLayer,
    // Flags
    flags: OvlFlags,
    // Stats
    nr_whiteouts: u64,
    nr_copyups: u64,
    nr_metacopyups: u64,
    nr_redirects: u64,
    // Space
    upper_free_bytes: u64,
    // Performance
    copyup_bytes: u64,
    copyup_time_ns: u64,
};

// ============================================================================
// FUSE Protocol
// ============================================================================

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 39;

pub const FuseOpcode = enum(u32) {
    lookup = 1,
    forget = 2,
    getattr = 3,
    setattr = 4,
    readlink = 5,
    symlink = 6,
    mknod = 8,
    mkdir = 9,
    unlink = 10,
    rmdir = 11,
    rename = 12,
    link = 13,
    open = 14,
    read = 15,
    write = 16,
    statfs = 17,
    release = 18,
    fsync = 20,
    setxattr = 21,
    getxattr = 22,
    listxattr = 23,
    removexattr = 24,
    flush = 25,
    init = 26,
    opendir = 27,
    readdir = 28,
    releasedir = 29,
    fsyncdir = 30,
    getlk = 31,
    setlk = 32,
    setlkw = 33,
    access = 34,
    create = 35,
    interrupt = 36,
    bmap = 37,
    destroy = 38,
    ioctl = 39,
    poll = 40,
    notify_reply = 41,
    batch_forget = 42,
    fallocate = 43,
    readdirplus = 44,
    rename2 = 45,
    lseek = 46,
    copy_file_range = 47,
    setupmapping = 48,
    removemapping = 49,
    syncfs = 50,
    tmpfile = 51,
    statx = 52,
    // CUSE
    cuse_init = 4096,
};

pub const FuseInitFlags = packed struct(u64) {
    async_read: bool = false,
    posix_locks: bool = false,
    file_ops: bool = false,
    atomic_o_trunc: bool = false,
    export_support: bool = false,
    big_writes: bool = false,
    dont_mask: bool = false,
    splice_write: bool = false,
    splice_move: bool = false,
    splice_read: bool = false,
    flock_locks: bool = false,
    has_ioctl_dir: bool = false,
    auto_inval_data: bool = false,
    do_readdirplus: bool = false,
    readdirplus_auto: bool = false,
    async_dio: bool = false,
    writeback_cache: bool = false,
    no_open_support: bool = false,
    parallel_dirops: bool = false,
    handle_killpriv: bool = false,
    posix_acl: bool = false,
    abort_err: bool = false,
    max_pages: bool = false,
    cache_symlinks: bool = false,
    no_opendir_support: bool = false,
    explicit_inval_data: bool = false,
    map_alignment: bool = false,
    submounts: bool = false,
    handle_killpriv_v2: bool = false,
    setxattr_ext: bool = false,
    init_ext: bool = false,
    init_reserved: bool = false,
    // Extended flags (second u32)
    security_ctx: bool = false,
    has_inode_dax: bool = false,
    create_supp_group: bool = false,
    has_expire_only: bool = false,
    direct_io_allow_mmap: bool = false,
    passthrough: bool = false,
    no_export_support: bool = false,
    has_resend: bool = false,
    // Zxyphor
    zxy_zero_copy: bool = false,
    _reserved: u23 = 0,
};

pub const FuseInHeader = struct {
    len: u32,
    opcode: FuseOpcode,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    total_extlen: u16,
    padding: u16,
};

pub const FuseOutHeader = struct {
    len: u32,
    error: i32,
    unique: u64,
};

// ============================================================================
// virtiofs (virtio-fs)
// ============================================================================

pub const VirtioFsConfig = struct {
    tag: [36]u8,
    num_request_queues: u32,
    notify_buf_size: u32,
};

pub const VirtioFsDevice = struct {
    tag: [36]u8,
    nr_queues: u32,
    // DAX mapping
    dax_enabled: bool,
    dax_window_size: u64,
    dax_window_base: u64,
    // Stats
    requests_processed: u64,
    bytes_read: u64,
    bytes_written: u64,
    cache_hits: u64,
    cache_misses: u64,
    avg_latency_ns: u64,
};

// ============================================================================
// FD/VFS Subsystem
// ============================================================================

pub const FdVfsSubsystem = struct {
    // FD stats
    nr_open_files: u64,
    nr_max_open_files: u64,
    max_fds_per_process: u32,
    // File locks
    nr_posix_locks: u64,
    nr_flock_locks: u64,
    nr_ofd_locks: u64,
    nr_leases: u64,
    // OverlayFS
    nr_overlay_mounts: u32,
    total_copyup_bytes: u64,
    // FUSE
    nr_fuse_connections: u32,
    nr_fuse_pending: u64,
    total_fuse_requests: u64,
    // virtiofs
    nr_virtiofs_devices: u32,
    // Stats
    total_open_calls: u64,
    total_close_calls: u64,
    total_read_calls: u64,
    total_write_calls: u64,
    total_dup_calls: u64,
    total_fcntl_calls: u64,
    // Zxyphor
    zxy_fd_recycling: bool,
    zxy_smart_caching: bool,
    initialized: bool,
};
