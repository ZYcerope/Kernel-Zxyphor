// Zxyphor Kernel - OverlayFS Internals & FUSE Detail
// OverlayFS: layer management, whiteout handling, redirect directories
// Copy-up mechanism, metacopy, volatile overlays
// FUSE: protocol messages, opcodes, session management
// FUSE passthrough, splice support, writeback cache
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// OverlayFS Core
// ============================================================================

pub const OvlLayerType = enum(u8) {
    upper = 0,
    lower = 1,
    work = 2,
};

pub const OvlEntryType = enum(u8) {
    file = 0,
    directory = 1,
    symlink = 2,
    whiteout = 3,
    opaque_dir = 4,
};

pub const OvlFlags = packed struct(u32) {
    impure: bool = false,
    opaque: bool = false,
    metacopy: bool = false,
    nlink_upper_valid: bool = false,
    has_xattr: bool = false,
    const_ino: bool = false,
    redirect: bool = false,
    upperdata: bool = false,
    index: bool = false,
    verified: bool = false,
    _pad: u22 = 0,
};

pub const OvlSuperblockFlags = packed struct(u32) {
    redirect_dir: bool = false,
    redirect_always_follow: bool = false,
    nfs_export: bool = false,
    xino_auto: bool = false,
    index: bool = false,
    metacopy: bool = false,
    volatile: bool = false,
    userxattr: bool = false,
    override_creds: bool = false,
    _pad: u23 = 0,
};

// ============================================================================
// OverlayFS Layer Stack
// ============================================================================

pub const OvlLayer = struct {
    mnt: u64,           // vfsmount pointer
    trap: u64,          // inode trap
    name: [256]u8,
    idx: u16,
    fsid: u32,
};

pub const OvlSuperblock = struct {
    upper_layer: ?OvlLayer,
    lower_layers: [16]OvlLayer,
    lower_layer_count: u8,
    workdir: [256]u8,
    config: OvlConfig,
    // index directory
    indexdir: u64, // dentry pointer
    // whiteout inode
    whiteout: u64,
    // stats
    total_lookups: u64,
    total_copyups: u64,
    total_whiteouts: u64,
    flags: OvlSuperblockFlags,
};

pub const OvlConfig = struct {
    upperdir: [256]u8,
    lowerdir: [1024]u8,
    workdir: [256]u8,
    redirect_mode: OvlRedirectMode,
    metacopy: bool,
    nfs_export: bool,
    xino: OvlXinoMode,
    index: OvlIndexMode,
    uuid: OvlUuidMode,
    volatile_mode: bool,
    userxattr: bool,
    override_creds: bool,
};

pub const OvlRedirectMode = enum(u8) {
    off = 0,
    follow = 1,
    nofollow = 2,
    on = 3,
};

pub const OvlXinoMode = enum(u8) {
    off = 0,
    on = 1,
    auto = 2,
};

pub const OvlIndexMode = enum(u8) {
    off = 0,
    on = 1,
    all = 2,
};

pub const OvlUuidMode = enum(u8) {
    null_uuid = 0,
    on = 1,
    off = 2,
};

// ============================================================================
// OverlayFS Copy-up
// ============================================================================

pub const CopyUpFlags = packed struct(u8) {
    hardlink: bool = false,
    metadata_only: bool = false,
    may_whiteout: bool = false,
    tmpfile: bool = false,
    _pad: u4 = 0,
};

pub const CopyUpContext = struct {
    parent: u64,        // dentry
    dentry: u64,
    stat_mode: u32,
    stat_size: u64,
    link: [256]u8,      // symlink target
    workdir: u64,
    destdir: u64,
    flags: CopyUpFlags,
    // Data copy progress
    bytes_copied: u64,
    total_bytes: u64,
};

pub const WhiteoutType = enum(u8) {
    char_device = 0,      // character device 0/0
    xattr = 1,           // trusted.overlay.whiteout
    opaque = 2,          // trusted.overlay.opaque = "y"
};

pub const OvlXattr = struct {
    pub const REDIRECT: []const u8 = "trusted.overlay.redirect";
    pub const ORIGIN: []const u8 = "trusted.overlay.origin";
    pub const IMPURE: []const u8 = "trusted.overlay.impure";
    pub const NLINK: []const u8 = "trusted.overlay.nlink";
    pub const UPPER: []const u8 = "trusted.overlay.upper";
    pub const METACOPY: []const u8 = "trusted.overlay.metacopy";
    pub const PROTATTR: []const u8 = "trusted.overlay.protattr";
    pub const OPAQUE: []const u8 = "trusted.overlay.opaque";
};

// ============================================================================
// OverlayFS Inode Operations
// ============================================================================

pub const OvlInodeOps = struct {
    lookup: ?*const fn (u64, u64, u32) ?*anyopaque = null,
    create: ?*const fn (u64, u64, u16, bool) i32 = null,
    mkdir: ?*const fn (u64, u64, u16) i32 = null,
    rmdir: ?*const fn (u64, u64) i32 = null,
    unlink: ?*const fn (u64, u64) i32 = null,
    symlink: ?*const fn (u64, u64, [*:0]const u8) i32 = null,
    link: ?*const fn (u64, u64, u64) i32 = null,
    rename: ?*const fn (u64, u64, u64, u64, u32) i32 = null,
    setattr: ?*const fn (u64, u64) i32 = null,
    getattr: ?*const fn (u64, u64, u32, u32) i32 = null,
    permission: ?*const fn (u64, u64, i32) i32 = null,
    listxattr: ?*const fn (u64, [*]u8, u64) i64 = null,
    get_inode_acl: ?*const fn (u64, i32, bool) ?*anyopaque = null,
    fiemap: ?*const fn (u64, u64) i32 = null,
    fileattr_get: ?*const fn (u64, u64) i32 = null,
    fileattr_set: ?*const fn (u64, u64, u64) i32 = null,
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
    _,
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
// FUSE Message Headers
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
    @"error": i32,
    unique: u64,
};

// ============================================================================
// FUSE Init/Destroy
// ============================================================================

pub const FuseInitIn = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    flags2: u32,
    unused: [11]u32,
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
    unused: [6]u32,
};

// ============================================================================
// FUSE Attributes / Entry
// ============================================================================

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

// ============================================================================
// FUSE Read/Write
// ============================================================================

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

// ============================================================================
// FUSE Open/Create
// ============================================================================

pub const FuseOpenIn = extern struct {
    flags: u32,
    open_flags: u32,
};

pub const FuseOpenOut = extern struct {
    fh: u64,
    open_flags: u32,
    passthrough_fh: u32,
};

pub const FuseCreateIn = extern struct {
    flags: u32,
    mode: u32,
    umask: u32,
    open_flags: u32,
};

pub const FuseReleaseIn = extern struct {
    fh: u64,
    flags: u32,
    release_flags: u32,
    lock_owner: u64,
};

// ============================================================================
// FUSE Directory
// ============================================================================

pub const FuseDirent = extern struct {
    ino: u64,
    off: u64,
    namelen: u32,
    @"type": u32,
    // name follows (variable length)
};

pub const FuseDirentplus = extern struct {
    entry_out: FuseEntryOut,
    dirent: FuseDirent,
};

// ============================================================================
// FUSE Notifications
// ============================================================================

pub const FuseNotifyCode = enum(u32) {
    poll = 1,
    inval_inode = 2,
    inval_entry = 3,
    store = 4,
    retrieve = 5,
    delete = 6,
    resend = 7,
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

// ============================================================================
// FUSE Connection / Session
// ============================================================================

pub const FuseConnInfo = struct {
    proto_major: u32,
    proto_minor: u32,
    max_write: u32,
    max_read: u32,
    max_readahead: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_pages: u16,
    time_gran: u32,
    want: FuseInitFlags,
    capable: FuseInitFlags,
};

pub const FuseSession = struct {
    conn: FuseConnInfo,
    mountpoint: [256]u8,
    fd: i32,
    got_init: bool,
    got_destroy: bool,
    debug: bool,
    running: bool,
    // Pending requests
    pending_count: u32,
    processing_count: u32,
    // Stats
    num_waiting: u32,
    max_background: u16,
    blocked: bool,
    // Passthrough
    passthrough_enabled: bool,
    // Writeback cache
    writeback_cache: bool,
    no_open_support: bool,
    no_opendir_support: bool,
};

// ============================================================================
// FUSE Passthrough
// ============================================================================

pub const FusePassthroughOut = extern struct {
    fd: u32,
    padding: u32,
};

// ============================================================================
// OverlayFS/FUSE Subsystem Manager
// ============================================================================

pub const OvlFuseSubsystemManager = struct {
    // OverlayFS stats
    ovl_mount_count: u32,
    ovl_total_copyups: u64,
    ovl_total_lookups: u64,
    ovl_total_whiteouts: u64,
    ovl_total_redirects: u64,
    // FUSE stats
    fuse_connection_count: u32,
    fuse_total_requests: u64,
    fuse_total_interrupts: u64,
    fuse_writeback_cache_enabled: bool,
    fuse_passthrough_enabled: bool,
    // State
    initialized: bool,

    pub fn init() OvlFuseSubsystemManager {
        return OvlFuseSubsystemManager{
            .ovl_mount_count = 0,
            .ovl_total_copyups = 0,
            .ovl_total_lookups = 0,
            .ovl_total_whiteouts = 0,
            .ovl_total_redirects = 0,
            .fuse_connection_count = 0,
            .fuse_total_requests = 0,
            .fuse_total_interrupts = 0,
            .fuse_writeback_cache_enabled = false,
            .fuse_passthrough_enabled = false,
            .initialized = true,
        };
    }
};
