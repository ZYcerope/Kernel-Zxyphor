// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Writeback, DAX, Filesystem
// Encryption (fscrypt), Filesystem Verity (fsverity),
// OverlayFS Internals, Quota System, Extended Attributes,
// File Locking (flock/POSIX/OFD), Inode Watcher (inotify/fanotify)
// More advanced than Linux 2026 filesystem infrastructure

const std = @import("std");

// ============================================================================
// Writeback
// ============================================================================

/// Writeback reason
pub const WbReason = enum(u8) {
    background = 0,
    vmscan = 1,
    sync = 2,
    periodic = 3,
    laptop_timer = 4,
    free_more_mem = 5,
    fs_free_space = 6,
    forker_thread = 7,
    // Zxyphor
    zxy_predictive = 100,
    zxy_priority = 101,
};

/// Writeback work item
pub const WbWork = struct {
    nr_pages: u64 = 0,
    sb: u64 = 0,                   // superblock pointer
    sync_mode: WbSyncMode = .none,
    tagged_writepages: bool = false,
    for_kupdate: bool = false,
    range_cyclic: bool = false,
    for_background: bool = false,
    for_sync: bool = false,
    auto_free: bool = false,
    reason: WbReason = .background,
    start: u64 = 0,
    end: u64 = 0xFFFFFFFFFFFFFFFF,
};

pub const WbSyncMode = enum(u8) {
    none = 0,
    all = 1,
};

/// Writeback control (per-BDI)
pub const WbCtrl = struct {
    dirty_thresh: u64 = 0,
    bg_thresh: u64 = 0,
    dirty_ratelimit: u64 = 0,
    balanced_dirty_ratelimit: u64 = 0,
    write_bandwidth: u64 = 0,
    avg_write_bandwidth: u64 = 0,
    dirty_exceeded: bool = false,
    // Statistics
    stat_dirtied: u64 = 0,
    stat_written: u64 = 0,
    stat_reclaimable: u64 = 0,
    stat_writeback: u64 = 0,
};

/// Backing device info flags
pub const BdiFlags = packed struct(u32) {
    writeback: bool = false,
    has_dirty_io: bool = false,
    registered: bool = false,
    async_congested: bool = false,
    sync_congested: bool = false,
    read_congested: bool = false,
    // Zxyphor
    zxy_prioritized: bool = false,
    _padding: u25 = 0,
};

// ============================================================================
// DAX (Direct Access)
// ============================================================================

/// DAX operation mode
pub const DaxMode = enum(u8) {
    disabled = 0,
    always = 1,         // -o dax=always
    never = 2,          // -o dax=never
    inode = 3,          // -o dax=inode (per-file)
};

/// DAX flags (per-inode)
pub const DaxInodeFlags = packed struct(u32) {
    dax_enabled: bool = false,
    dax_pinned: bool = false,
    dax_cow: bool = false,
    verity: bool = false,
    // Zxyphor
    zxy_persistent: bool = false,
    _padding: u27 = 0,
};

/// DAX device descriptor
pub const DaxDevDesc = struct {
    id: u32 = 0,
    alive: bool = false,
    size: u64 = 0,
    pgoff: u64 = 0,
    nr_range: u32 = 0,
    mode: DaxMode = .disabled,
    // Zxyphor
    zxy_numa_node: i32 = -1,
};

/// DAX fault result
pub const DaxFaultResult = packed struct(u32) {
    major: bool = false,
    minor: bool = false,
    nopage: bool = false,
    error: bool = false,
    oom: bool = false,
    retry: bool = false,
    done: bool = false,
    huge_pmd: bool = false,
    huge_pud: bool = false,
    _padding: u23 = 0,
};

// ============================================================================
// fscrypt (Filesystem-level Encryption)
// ============================================================================

/// fscrypt encryption mode
pub const FscryptMode = enum(u8) {
    aes_256_xts = 1,
    aes_256_cts = 4,
    aes_128_cbc = 5,
    aes_128_cts = 6,
    adiantum = 9,
    aes_256_hctr2 = 10,
    // Zxyphor
    zxy_chacha20 = 100,
    zxy_aes_512_xts = 101,
};

/// fscrypt policy version
pub const FscryptPolicyVersion = enum(u8) {
    v1 = 0,
    v2 = 2,
};

/// fscrypt policy v2
pub const FscryptPolicyV2 = struct {
    version: FscryptPolicyVersion = .v2,
    contents_encryption_mode: FscryptMode = .aes_256_xts,
    filenames_encryption_mode: FscryptMode = .aes_256_cts,
    flags: FscryptPolicyFlags = .{},
    log2_data_unit_size: u8 = 0,
    master_key_identifier: [16]u8 = [_]u8{0} ** 16,
};

pub const FscryptPolicyFlags = packed struct(u8) {
    padding_4: bool = false,
    padding_8: bool = false,
    padding_16: bool = false,
    padding_32: bool = false,
    direct_key: bool = false,
    iv_ino_lblk_64: bool = false,
    iv_ino_lblk_32: bool = false,
    _reserved: bool = false,
};

/// fscrypt key specifier type
pub const FscryptKeySpecType = enum(u32) {
    descriptor = 1,
    identifier = 2,
};

/// fscrypt provisioning key
pub const FscryptProvisioningKey = struct {
    type_field: u32 = 0,
    _reserved: u32 = 0,
    raw: [64]u8 = [_]u8{0} ** 64,
    raw_len: u32 = 0,
};

// ============================================================================
// fsverity (Filesystem Verity)
// ============================================================================

/// fsverity hash algorithm
pub const FsverityHashAlgo = enum(u32) {
    sha256 = 1,
    sha512 = 2,
    // Zxyphor
    zxy_blake3 = 100,
};

/// fsverity enable args
pub const FsverityEnableArgs = struct {
    version: u32 = 1,
    hash_algorithm: FsverityHashAlgo = .sha256,
    block_size: u32 = 4096,
    salt_size: u32 = 0,
    salt: [32]u8 = [_]u8{0} ** 32,
    sig_size: u32 = 0,
    _reserved: [11]u32 = [_]u32{0} ** 11,
};

/// fsverity descriptor
pub const FsverityDescriptor = struct {
    version: u8 = 1,
    hash_algorithm: FsverityHashAlgo = .sha256,
    log_blocksize: u8 = 12,     // log2(4096)
    data_size: u64 = 0,
    root_hash: [64]u8 = [_]u8{0} ** 64,
    root_hash_len: u8 = 0,
    salt: [32]u8 = [_]u8{0} ** 32,
    salt_len: u8 = 0,
    authenticated: bool = false,
};

// ============================================================================
// Quota System
// ============================================================================

/// Quota type
pub const QuotaType = enum(u8) {
    user = 0,
    group = 1,
    project = 2,
};

/// Quota format
pub const QuotaFormat = enum(u32) {
    vfsold = 1,
    vfsv0 = 2,
    vfsv1 = 4,
    // Zxyphor
    zxy_v1 = 100,
};

/// Quota flags
pub const QuotaFlags = packed struct(u32) {
    enabled: bool = false,
    enforcing: bool = false,
    grace_period: bool = false,
    root_squash: bool = false,
    // Zxyphor
    zxy_adaptive: bool = false,
    _padding: u27 = 0,
};

/// Disk quota (dquot)
pub const DiskQuota = struct {
    id: u32 = 0,
    qtype: QuotaType = .user,
    bh_limit: u64 = 0,         // hard limit (blocks)
    bs_limit: u64 = 0,         // soft limit (blocks)
    ih_limit: u64 = 0,         // hard limit (inodes)
    is_limit: u64 = 0,         // soft limit (inodes)
    cur_blocks: u64 = 0,
    cur_inodes: u64 = 0,
    b_time: i64 = 0,           // block grace period expiry
    i_time: i64 = 0,           // inode grace period expiry
    flags: QuotaFlags = .{},
};

/// Quota info (per-superblock)
pub const QuotaInfo = struct {
    format: QuotaFormat = .vfsv1,
    flags: [3]QuotaFlags = .{ .{}, .{}, .{} }, // user, group, project
    bgrace: u64 = 604800,     // 7 days default
    igrace: u64 = 604800,
    nr_dquots: u64 = 0,
};

// ============================================================================
// Extended Attributes (xattr)
// ============================================================================

/// xattr namespace
pub const XattrNs = enum(u8) {
    user = 1,
    posix_acl_access = 2,
    posix_acl_default = 3,
    trusted = 4,
    security = 6,
    system = 7,
    // Zxyphor
    zxy = 100,
};

/// xattr flags
pub const XattrFlags = packed struct(u32) {
    create: bool = false,       // XATTR_CREATE
    replace: bool = false,      // XATTR_REPLACE
    _padding: u30 = 0,
};

/// xattr entry descriptor
pub const XattrEntry = struct {
    ns: XattrNs = .user,
    name: [256]u8 = [_]u8{0} ** 256,
    name_len: u16 = 0,
    value_size: u32 = 0,
    inline_value: bool = false,
    block_nr: u64 = 0,
};

// ============================================================================
// File Locking
// ============================================================================

/// Lock type
pub const FlockType = enum(u16) {
    rdlck = 0,    // F_RDLCK
    wrlck = 1,    // F_WRLCK
    unlck = 2,    // F_UNLCK
};

/// Lock style
pub const LockStyle = enum(u8) {
    flock = 0,           // BSD flock()
    posix = 1,           // POSIX fcntl() lock
    ofd = 2,             // Open File Description lock
    lease = 3,           // file lease
    // Zxyphor
    zxy_range = 100,
};

/// File lock descriptor
pub const FileLockDesc = struct {
    style: LockStyle = .posix,
    lock_type: FlockType = .rdlck,
    start: u64 = 0,
    end: u64 = 0xFFFFFFFFFFFFFFFF,
    pid: i32 = 0,
    fd: i32 = -1,
    inode: u64 = 0,
    flags: FileLockFlags = .{},
};

pub const FileLockFlags = packed struct(u32) {
    posix: bool = false,
    flock: bool = false,
    deleg: bool = false,
    access: bool = false,
    exists: bool = false,
    lease_time: bool = false,
    ofd: bool = false,
    // Zxyphor
    zxy_priority: bool = false,
    _padding: u24 = 0,
};

/// Lease type
pub const LeaseType = enum(u8) {
    read = 0,
    write = 1,
    none = 2,           // break
};

// ============================================================================
// inotify
// ============================================================================

/// inotify event mask
pub const InotifyMask = packed struct(u32) {
    access: bool = false,          // IN_ACCESS
    modify: bool = false,          // IN_MODIFY
    attrib: bool = false,          // IN_ATTRIB
    close_write: bool = false,     // IN_CLOSE_WRITE
    close_nowrite: bool = false,   // IN_CLOSE_NOWRITE
    open: bool = false,            // IN_OPEN
    moved_from: bool = false,      // IN_MOVED_FROM
    moved_to: bool = false,        // IN_MOVED_TO
    create: bool = false,          // IN_CREATE
    delete: bool = false,          // IN_DELETE
    delete_self: bool = false,     // IN_DELETE_SELF
    move_self: bool = false,       // IN_MOVE_SELF
    _reserved: u1 = 0,
    unmount: bool = false,         // IN_UNMOUNT
    q_overflow: bool = false,      // IN_Q_OVERFLOW
    ignored: bool = false,         // IN_IGNORED
    _reserved2: u8 = 0,
    onlydir: bool = false,         // IN_ONLYDIR
    dont_follow: bool = false,     // IN_DONT_FOLLOW
    excl_unlink: bool = false,     // IN_EXCL_UNLINK
    _reserved3: u1 = 0,
    mask_create: bool = false,     // IN_MASK_CREATE
    mask_add: bool = false,        // IN_MASK_ADD
    isdir: bool = false,           // IN_ISDIR
    oneshot: bool = false,         // IN_ONESHOT
};

/// inotify event (userspace)
pub const InotifyEvent = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
    // name follows (variable length)
};

// ============================================================================
// fanotify
// ============================================================================

/// fanotify event mask
pub const FanotifyMask = packed struct(u64) {
    access: bool = false,          // FAN_ACCESS
    modify: bool = false,          // FAN_MODIFY
    attrib: bool = false,          // FAN_ATTRIB
    close_write: bool = false,     // FAN_CLOSE_WRITE
    close_nowrite: bool = false,   // FAN_CLOSE_NOWRITE
    open: bool = false,            // FAN_OPEN
    moved_from: bool = false,      // FAN_MOVED_FROM
    moved_to: bool = false,        // FAN_MOVED_TO
    create: bool = false,          // FAN_CREATE
    delete: bool = false,          // FAN_DELETE
    delete_self: bool = false,     // FAN_DELETE_SELF
    move_self: bool = false,       // FAN_MOVE_SELF
    open_exec: bool = false,       // FAN_OPEN_EXEC
    _reserved: u14 = 0,
    q_overflow: bool = false,      // FAN_Q_OVERFLOW
    fs_error: bool = false,        // FAN_FS_ERROR
    open_perm: bool = false,       // FAN_OPEN_PERM
    access_perm: bool = false,     // FAN_ACCESS_PERM
    open_exec_perm: bool = false,  // FAN_OPEN_EXEC_PERM
    rename: bool = false,          // FAN_RENAME
    _reserved2: u27 = 0,
    ondir: bool = false,           // FAN_ONDIR
    event_on_child: bool = false,  // FAN_EVENT_ON_CHILD
};

/// fanotify init flags
pub const FanotifyInitFlags = packed struct(u32) {
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
    _padding: u19 = 0,
};

/// fanotify response
pub const FanotifyResponse = extern struct {
    fd: i32,
    response: u32,
};

pub const FAN_ALLOW: u32 = 0x01;
pub const FAN_DENY: u32 = 0x02;
pub const FAN_AUDIT: u32 = 0x10;

// ============================================================================
// OverlayFS Internals
// ============================================================================

/// OverlayFS layer type
pub const OvlLayerType = enum(u8) {
    upper = 0,
    lower = 1,
    workdir = 2,
};

/// OverlayFS inode flags
pub const OvlInodeFlags = packed struct(u32) {
    upper: bool = false,
    lower: bool = false,
    impure: bool = false,
    whiteout: bool = false,
    opaque: bool = false,
    index: bool = false,
    nlink: bool = false,
    metacopy: bool = false,
    redirect: bool = false,
    // Zxyphor
    zxy_dedup: bool = false,
    _padding: u22 = 0,
};

/// OverlayFS config
pub const OvlConfig = struct {
    upperdir: [256]u8 = [_]u8{0} ** 256,
    upper_len: u16 = 0,
    workdir: [256]u8 = [_]u8{0} ** 256,
    work_len: u16 = 0,
    nr_lower: u32 = 0,
    redirect_dir: bool = false,
    redirect_always: bool = false,
    index: bool = false,
    uuid: bool = true,
    nfs_export: bool = false,
    metacopy: bool = false,
    volatile_opt: bool = false,
    userxattr: bool = false,
};

// ============================================================================
// FS Infrastructure Subsystem Manager
// ============================================================================

pub const FsInfraSubsystem = struct {
    nr_writeback_threads: u32 = 0,
    dirty_thresh_pct: u32 = 20,
    dirty_bg_pct: u32 = 10,
    writeback_centisecs: u32 = 500,
    dirty_expire_centisecs: u32 = 3000,
    dax_enabled: bool = false,
    fscrypt_enabled: bool = false,
    fsverity_enabled: bool = false,
    max_inotify_watches: u32 = 65536,
    max_inotify_instances: u32 = 128,
    max_fanotify_marks: u32 = 65536,
    quota_enabled: bool = false,
    overlayfs_mounted: bool = false,
    initialized: bool = false,

    pub fn init() FsInfraSubsystem {
        return FsInfraSubsystem{
            .initialized = true,
        };
    }
};
