// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - FUSE Advanced / Userspace FS Detail
// FUSE protocol opcodes, init flags, request/response, FUSE_NOTIFY,
// passthrough, DAX window, virtiofs, writeback cache, open flags

const std = @import("std");

// ============================================================================
// FUSE Protocol Version
// ============================================================================

pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 40;

// ============================================================================
// FUSE Opcodes
// ============================================================================

pub const FuseOpcode = enum(u32) {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Setxattr = 21,
    Getxattr = 22,
    Listxattr = 23,
    Removexattr = 24,
    Flush = 25,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Fsyncdir = 30,
    Getlk = 31,
    Setlk = 32,
    Setlkw = 33,
    Access = 34,
    Create = 35,
    Interrupt = 36,
    Bmap = 37,
    Destroy = 38,
    Ioctl = 39,
    Poll = 40,
    NotifyReply = 41,
    BatchForget = 42,
    Fallocate = 43,
    Readdirplus = 44,
    Rename2 = 45,
    Lseek = 46,
    CopyFileRange = 47,
    SetupMapping = 48,    // DAX
    RemoveMapping = 49,   // DAX
    Syncfs = 50,
    TmpFile = 51,
    Statx = 52,
};

// ============================================================================
// FUSE Init Flags
// ============================================================================

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
    abort_error: bool = false,
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
    security_ctx: bool = false,
    has_inode_dax: bool = false,
    create_supp_group: bool = false,
    has_expire_only: bool = false,
    direct_io_allow_mmap: bool = false,
    passthrough: bool = false,
    no_export_support: bool = false,
    has_resend: bool = false,
    _pad: u24 = 0,
};

// ============================================================================
// FUSE In/Out Headers
// ============================================================================

pub const FuseInHeader = extern struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    total_extlen: u16,
    padding: u16,
};

pub const FuseOutHeader = extern struct {
    len: u32,
    error: i32,
    unique: u64,
};

// ============================================================================
// FUSE Request/Response Types
// ============================================================================

pub const FuseInitIn = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    flags2: u32,
    _unused: [11]u32,
};

pub const FuseInitOut = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    max_stack_depth: u32,
    _unused: [6]u32,
};

pub const FuseAttr = extern struct {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    flags: u32,
};

pub const FuseEntryOut = extern struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
};

pub const FuseAttrOut = extern struct {
    attr_valid: u64,
    attr_valid_nsec: u32,
    dummy: u32,
    attr: FuseAttr,
};

pub const FuseOpenIn = extern struct {
    flags: u32,
    open_flags: u32,
};

pub const FuseOpenOut = extern struct {
    fh: u64,
    open_flags: u32,
    passthrough_fh: i32,
};

pub const FuseOpenFlags = packed struct(u32) {
    direct_io: bool = false,
    keep_cache: bool = false,
    nonseekable: bool = false,
    cache_dir: bool = false,
    stream: bool = false,
    noflush: bool = false,
    parallel_direct_writes: bool = false,
    passthrough: bool = false,
    _pad: u24 = 0,
};

pub const FuseReadIn = extern struct {
    fh: u64,
    offset: u64,
    size: u32,
    read_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
};

pub const FuseWriteIn = extern struct {
    fh: u64,
    offset: u64,
    size: u32,
    write_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
};

pub const FuseWriteOut = extern struct {
    size: u32,
    padding: u32,
};

pub const FuseMkdirIn = extern struct {
    mode: u32,
    umask: u32,
};

pub const FuseCreateIn = extern struct {
    flags: u32,
    mode: u32,
    umask: u32,
    open_flags: u32,
};

pub const FuseRename2In = extern struct {
    newdir: u64,
    flags: u32,
    padding: u32,
};

pub const FuseIoctlIn = extern struct {
    fh: u64,
    flags: u32,
    cmd: u32,
    arg: u64,
    in_size: u32,
    out_size: u32,
};

pub const FuseIoctlOut = extern struct {
    result: i32,
    flags: u32,
    in_iovs: u32,
    out_iovs: u32,
};

// ============================================================================
// FUSE Notifications (daemon to kernel)
// ============================================================================

pub const FuseNotifyCode = enum(u32) {
    Poll = 1,
    InvalInode = 2,
    InvalEntry = 3,
    Store = 4,
    Retrieve = 5,
    Delete = 6,
    Resend = 7,
};

pub const FuseNotifyInvalInodeOut = extern struct {
    ino: u64,
    off: i64,
    len: i64,
};

pub const FuseNotifyInvalEntryOut = extern struct {
    parent: u64,
    namelen: u32,
    flags: u32,
};

pub const FuseNotifyDeleteOut = extern struct {
    parent: u64,
    child: u64,
    namelen: u32,
    padding: u32,
};

pub const FuseNotifyStoreOut = extern struct {
    nodeid: u64,
    offset: u64,
    size: u32,
    padding: u32,
};

// ============================================================================
// virtiofs
// ============================================================================

pub const VirtioFsConfig = struct {
    tag: [36]u8,              // filesystem mount tag
    num_request_queues: u32,
    // DAX window
    dax_window_size: u64,
    dax_enabled: bool,
};

pub const VirtioFsShmRegion = struct {
    fd: i32,
    len: u64,
    offset: u64,
    flags: u32,
};

// ============================================================================
// FUSE Connection Info
// ============================================================================

pub const FuseConn = struct {
    // Protocol
    proto_major: u32,
    proto_minor: u32,
    // Capabilities
    init_flags: FuseInitFlags,
    // Limits
    max_read: u32,
    max_write: u32,
    max_readahead: u32,
    max_pages: u16,
    max_background: u16,
    congestion_threshold: u16,
    // State
    connected: bool,
    blocked: bool,
    aborted: bool,
    // Writeback cache
    writeback_cache: bool,
    // DAX
    dax_mode: FuseDaxMode,
    // Passthrough
    passthrough_enabled: bool,
    // Stats
    num_waiting: u32,
    num_background: u32,
    num_interrupted: u32,
    stats: FuseConnStats,
};

pub const FuseDaxMode = enum(u8) {
    Never = 0,
    Always = 1,
    Inode = 2,       // per-inode DAX
};

pub const FuseConnStats = struct {
    total_requests: u64,
    total_replies: u64,
    total_interrupts: u64,
    total_forgets: u64,
    total_notifications: u64,
    total_bytes_read: u64,
    total_bytes_written: u64,
    avg_latency_ns: u64,
    max_latency_ns: u64,
    timeouts: u64,
};

// ============================================================================
// FUSE Subsystem Manager
// ============================================================================

pub const FuseSubsystemManager = struct {
    total_connections: u32,
    active_connections: u32,
    total_requests_processed: u64,
    total_bytes_transferred: u64,
    virtiofs_mounts: u32,
    initialized: bool,

    pub fn init() FuseSubsystemManager {
        return .{
            .total_connections = 0,
            .active_connections = 0,
            .total_requests_processed = 0,
            .total_bytes_transferred = 0,
            .virtiofs_mounts = 0,
            .initialized = true,
        };
    }
};
