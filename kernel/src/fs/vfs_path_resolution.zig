// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - VFS Path Resolution, Dentry Cache, Inode Cache Complete
// Nameidata, path walk state, dentry operations, inode operations,
// dcache hash, inode hash, super_operations, file_lock, fasync

const std = @import("std");

// ============================================================================
// Path Resolution State (nameidata)
// ============================================================================

pub const LookupFlags = packed struct(u32) {
    follow: bool = false,       // LOOKUP_FOLLOW
    directory: bool = false,    // LOOKUP_DIRECTORY
    automount: bool = false,    // LOOKUP_AUTOMOUNT
    parent: bool = false,       // LOOKUP_PARENT
    reval: bool = false,        // LOOKUP_REVAL
    rcu: bool = false,          // LOOKUP_RCU
    open: bool = false,         // LOOKUP_OPEN
    create: bool = false,       // LOOKUP_CREATE
    excl: bool = false,         // LOOKUP_EXCL
    rename_target: bool = false, // LOOKUP_RENAME_TARGET
    jumped: bool = false,       // LOOKUP_JUMPED
    root: bool = false,         // LOOKUP_ROOT
    empty: bool = false,        // LOOKUP_EMPTY
    down: bool = false,         // LOOKUP_DOWN
    mountpoint: bool = false,   // LOOKUP_MOUNTPOINT
    no_symlinks: bool = false,  // LOOKUP_NO_SYMLINKS
    no_magiclinks: bool = false, // LOOKUP_NO_MAGICLINKS
    no_xdev: bool = false,      // LOOKUP_NO_XDEV
    beneath: bool = false,      // LOOKUP_BENEATH
    in_root: bool = false,      // LOOKUP_IN_ROOT
    cached: bool = false,       // LOOKUP_CACHED
    _reserved: u11 = 0,
};

pub const PathWalkType = enum(u8) {
    Normal = 0,
    Parent = 1,
    Root = 2,
    Empty = 3,
};

pub const Nameidata = struct {
    path: Path,
    root: Path,
    inode: ?*Inode,
    flags: LookupFlags,
    state: u32,             // LOOKUP_RCU / LOOKUP_PARENT state
    seq: u32,               // sequence number for RCU
    m_seq: u32,             // mount sequence
    r_seq: u32,             // rename sequence
    last_type: PathComponentType,
    depth: u32,
    total_link_count: u32,
    dir_mode: u16,
    dir_uid: u32,
    dir_vfsgid: u32,
    saved_names: [8][256]u8, // nested symlink stack
};

pub const PathComponentType = enum(u8) {
    Normal = 0,
    Root = 1,
    Dot = 2,
    DotDot = 3,
};

pub const Path = struct {
    mnt: ?*VfsMount,
    dentry: ?*Dentry,
};

// ============================================================================
// Dentry (Directory Entry Cache)
// ============================================================================

pub const DentryFlags = packed struct(u32) {
    mounted: bool = false,       // DCACHE_MOUNTED
    need_automount: bool = false, // DCACHE_NEED_AUTOMOUNT
    manage_transit: bool = false, // DCACHE_MANAGE_TRANSIT
    disconnected: bool = false,  // DCACHE_DISCONNECTED
    referenced: bool = false,    // DCACHE_REFERENCED
    rcuaccess: bool = false,     // DCACHE_RCUACCESS
    op_hash: bool = false,       // DCACHE_OP_HASH
    op_compare: bool = false,    // DCACHE_OP_COMPARE
    op_revalidate: bool = false, // DCACHE_OP_REVALIDATE
    op_delete: bool = false,     // DCACHE_OP_DELETE
    op_prune: bool = false,      // DCACHE_OP_PRUNE
    op_real: bool = false,       // DCACHE_OP_REAL
    par_lookup: bool = false,    // DCACHE_PAR_LOOKUP
    lru_list: bool = false,      // DCACHE_LRU_LIST
    shrink_list: bool = false,   // DCACHE_SHRINK_LIST
    fallthru: bool = false,      // DCACHE_FALLTHRU
    nokey_name: bool = false,    // DCACHE_NOKEY_NAME
    encrypted_name: bool = false, // DCACHE_ENCRYPTED_NAME
    cant_mount: bool = false,    // DCACHE_CANT_MOUNT
    genocide: bool = false,      // DCACHE_GENOCIDE
    _reserved: u12 = 0,
};

pub const Dentry = struct {
    d_flags: DentryFlags,
    d_seq: u32,              // seqcount for RCU lookups
    d_hash: HashListNode,    // dcache hash table entry
    d_parent: ?*Dentry,
    d_name: QStr,
    d_inode: ?*Inode,
    d_iname: [40]u8,         // small name inline
    d_lockref: LockRef,
    d_op: ?*const DentryOperations,
    d_sb: ?*SuperBlock,
    d_time: u64,
    d_fsdata: ?*anyopaque,
    d_child: ListHead,
    d_subdirs: ListHead,
    d_u: DentryUnion,
    d_lru: ListHead,
};

pub const DentryUnion = union {
    d_alias: HashListNode,
    d_in_lookup_hash: HashListNode,
    d_rcu: RcuHead,
};

pub const QStr = struct {
    hash: u32,
    len: u32,
    name: [*]const u8,
};

pub const DentryOperations = struct {
    d_revalidate: ?*const fn (dentry: *Dentry, flags: u32) callconv(.C) i32,
    d_weak_revalidate: ?*const fn (dentry: *Dentry, flags: u32) callconv(.C) i32,
    d_hash: ?*const fn (dentry: *const Dentry, name: *QStr) callconv(.C) i32,
    d_compare: ?*const fn (dentry: *const Dentry, wh_len: u32, wh_name: [*]const u8, name: *const QStr) callconv(.C) i32,
    d_delete: ?*const fn (dentry: *const Dentry) callconv(.C) i32,
    d_init: ?*const fn (dentry: *Dentry) callconv(.C) i32,
    d_release: ?*const fn (dentry: *Dentry) callconv(.C) void,
    d_prune: ?*const fn (dentry: *Dentry) callconv(.C) void,
    d_iput: ?*const fn (dentry: *Dentry, inode: *Inode) callconv(.C) void,
    d_dname: ?*const fn (dentry: *Dentry, buf: [*]u8, buflen: i32) callconv(.C) [*]u8,
    d_automount: ?*const fn (path: *Path) callconv(.C) ?*VfsMount,
    d_manage: ?*const fn (path: *Path, mounting: bool) callconv(.C) i32,
    d_real: ?*const fn (dentry: *Dentry, inode: ?*const Inode) callconv(.C) ?*Dentry,
};

// ============================================================================
// Inode
// ============================================================================

pub const InodeFlags = packed struct(u32) {
    dirty_sync: bool = false,     // I_DIRTY_SYNC
    dirty_datasync: bool = false, // I_DIRTY_DATASYNC
    dirty_pages: bool = false,    // I_DIRTY_PAGES
    new: bool = false,            // I_NEW
    will_free: bool = false,      // I_WILL_FREE
    freeing: bool = false,        // I_FREEING
    clear: bool = false,          // I_CLEAR
    sync: bool = false,           // I_SYNC
    creating: bool = false,       // I_CREATING
    linkable: bool = false,       // I_LINKABLE
    wb_switch: bool = false,      // I_WB_SWITCH
    opq_dentry: bool = false,     // I_OPQ_DENTRY
    dirty_time: bool = false,     // I_DIRTY_TIME
    dontcache: bool = false,      // I_DONTCACHE
    _reserved: u18 = 0,
};

pub const FileMode = packed struct(u16) {
    other_exec: bool = false,
    other_write: bool = false,
    other_read: bool = false,
    group_exec: bool = false,
    group_write: bool = false,
    group_read: bool = false,
    owner_exec: bool = false,
    owner_write: bool = false,
    owner_read: bool = false,
    sticky: bool = false,
    setgid: bool = false,
    setuid: bool = false,
    file_type: u4 = 0,
};

pub const FileType = enum(u4) {
    Unknown = 0,
    Fifo = 1,
    CharDev = 2,
    Dir = 4,
    BlkDev = 6,
    Regular = 8,
    Symlink = 10,
    Socket = 12,
};

pub const Inode = struct {
    i_mode: u16,
    i_opflags: u16,
    i_uid: u32,
    i_gid: u32,
    i_flags: InodeFlags,
    i_op: ?*const InodeOperations,
    i_sb: ?*SuperBlock,
    i_mapping: ?*AddressSpace,
    i_security: ?*anyopaque,
    i_ino: u64,
    i_nlink: u32,
    i_rdev: u32,
    i_size: i64,
    i_atime: Timespec64,
    i_mtime: Timespec64,
    i_ctime: Timespec64,
    i_lock: SpinLock,
    i_bytes: u16,
    i_blkbits: u8,
    i_write_hint: u8,
    i_blocks: u64,
    i_state: u64,
    i_rwsem: RwSemaphore,
    i_hash: HashListNode,
    i_io_list: ListHead,
    i_lru: ListHead,
    i_sb_list: ListHead,
    i_wb_list: ListHead,
    i_dentry: HashListBl,
    i_count: i32,
    i_writecount: i32,
    i_readcount: i32,
    i_fop: ?*const FileOperations,
    i_flctx: ?*FileLockContext,
    i_data: AddressSpace,
    i_devices: ListHead,
    i_pipe: ?*anyopaque,
    i_cdev: ?*anyopaque,
    i_generation: u32,
    i_fsnotify_mask: u32,
    i_private: ?*anyopaque,
};

pub const InodeOperations = struct {
    lookup: ?*const fn (dir: *Inode, dentry: *Dentry, flags: u32) callconv(.C) ?*Dentry,
    get_link: ?*const fn (dentry: *Dentry, inode: *Inode) callconv(.C) ?[*:0]const u8,
    permission: ?*const fn (user_ns: ?*anyopaque, inode: *Inode, mask: i32) callconv(.C) i32,
    get_inode_acl: ?*const fn (inode: *Inode, acl_type: i32, rcu: bool) callconv(.C) ?*anyopaque,
    readlink: ?*const fn (dentry: *Dentry, buf: [*]u8, buflen: i32) callconv(.C) i32,
    create: ?*const fn (user_ns: ?*anyopaque, dir: *Inode, dentry: *Dentry, mode: u16, excl: bool) callconv(.C) i32,
    link: ?*const fn (old_dentry: *Dentry, dir: *Inode, new_dentry: *Dentry) callconv(.C) i32,
    unlink: ?*const fn (dir: *Inode, dentry: *Dentry) callconv(.C) i32,
    symlink: ?*const fn (user_ns: ?*anyopaque, dir: *Inode, dentry: *Dentry, symname: [*:0]const u8) callconv(.C) i32,
    mkdir: ?*const fn (user_ns: ?*anyopaque, dir: *Inode, dentry: *Dentry, mode: u16) callconv(.C) i32,
    rmdir: ?*const fn (dir: *Inode, dentry: *Dentry) callconv(.C) i32,
    mknod: ?*const fn (user_ns: ?*anyopaque, dir: *Inode, dentry: *Dentry, mode: u16, dev: u32) callconv(.C) i32,
    rename: ?*const fn (user_ns: ?*anyopaque, old_dir: *Inode, old_dentry: *Dentry, new_dir: *Inode, new_dentry: *Dentry, flags: u32) callconv(.C) i32,
    setattr: ?*const fn (user_ns: ?*anyopaque, dentry: *Dentry, attr: *InodeAttr) callconv(.C) i32,
    getattr: ?*const fn (user_ns: ?*anyopaque, path: *Path, stat: *Kstat, request_mask: u32, flags: u32) callconv(.C) i32,
    listxattr: ?*const fn (dentry: *Dentry, buf: [*]u8, size: usize) callconv(.C) isize,
    fiemap: ?*const fn (inode: *Inode, fieinfo: ?*anyopaque, start: u64, len: u64) callconv(.C) i32,
    update_time: ?*const fn (inode: *Inode, time: *Timespec64, flags: i32) callconv(.C) i32,
    atomic_open: ?*const fn (dir: *Inode, dentry: *Dentry, file: ?*anyopaque, open_flag: u32, create_mode: u16) callconv(.C) i32,
    tmpfile: ?*const fn (user_ns: ?*anyopaque, dir: *Inode, file: ?*anyopaque, mode: u16) callconv(.C) i32,
    fileattr_set: ?*const fn (user_ns: ?*anyopaque, dentry: *Dentry, fa: ?*anyopaque) callconv(.C) i32,
    fileattr_get: ?*const fn (dentry: *Dentry, fa: ?*anyopaque) callconv(.C) i32,
    get_offset_ctx: ?*const fn (inode: *Inode) callconv(.C) ?*anyopaque,
};

pub const InodeAttr = struct {
    ia_valid: u32,
    ia_mode: u16,
    ia_uid: u32,
    ia_gid: u32,
    ia_size: i64,
    ia_atime: Timespec64,
    ia_mtime: Timespec64,
    ia_ctime: Timespec64,
    ia_file: ?*anyopaque,
};

// ============================================================================
// File Operations
// ============================================================================

pub const FileOperations = struct {
    owner: ?*anyopaque,
    llseek: ?*const fn (file: ?*anyopaque, offset: i64, whence: i32) callconv(.C) i64,
    read: ?*const fn (file: ?*anyopaque, buf: [*]u8, count: usize, pos: *i64) callconv(.C) isize,
    write: ?*const fn (file: ?*anyopaque, buf: [*]const u8, count: usize, pos: *i64) callconv(.C) isize,
    read_iter: ?*const fn (kio: ?*anyopaque, iter: ?*anyopaque) callconv(.C) isize,
    write_iter: ?*const fn (kio: ?*anyopaque, iter: ?*anyopaque) callconv(.C) isize,
    iopoll: ?*const fn (kio: ?*anyopaque, bio: ?*anyopaque, flags: u32) callconv(.C) i32,
    iterate_shared: ?*const fn (file: ?*anyopaque, ctx: ?*anyopaque) callconv(.C) i32,
    poll: ?*const fn (file: ?*anyopaque, table: ?*anyopaque) callconv(.C) u32,
    unlocked_ioctl: ?*const fn (file: ?*anyopaque, cmd: u32, arg: u64) callconv(.C) i64,
    compat_ioctl: ?*const fn (file: ?*anyopaque, cmd: u32, arg: u64) callconv(.C) i64,
    mmap: ?*const fn (file: ?*anyopaque, vma: ?*anyopaque) callconv(.C) i32,
    open: ?*const fn (inode: *Inode, file: ?*anyopaque) callconv(.C) i32,
    flush: ?*const fn (file: ?*anyopaque, id: ?*anyopaque) callconv(.C) i32,
    release: ?*const fn (inode: *Inode, file: ?*anyopaque) callconv(.C) i32,
    fsync: ?*const fn (file: ?*anyopaque, start: i64, end: i64, datasync: i32) callconv(.C) i32,
    fasync: ?*const fn (fd: i32, file: ?*anyopaque, on: i32) callconv(.C) i32,
    lock: ?*const fn (file: ?*anyopaque, cmd: i32, fl: ?*anyopaque) callconv(.C) i32,
    get_unmapped_area: ?*const fn (file: ?*anyopaque, addr: u64, len: u64, pgoff: u64, flags: u64) callconv(.C) u64,
    check_flags: ?*const fn (flags: i32) callconv(.C) i32,
    flock: ?*const fn (file: ?*anyopaque, cmd: i32, fl: ?*anyopaque) callconv(.C) i32,
    splice_write: ?*const fn (pipe: ?*anyopaque, file: ?*anyopaque, ppos: *i64, len: usize, flags: u32) callconv(.C) isize,
    splice_read: ?*const fn (file: ?*anyopaque, ppos: *i64, pipe: ?*anyopaque, len: usize, flags: u32) callconv(.C) isize,
    setlease: ?*const fn (file: ?*anyopaque, arg: i64, lease: ?*anyopaque, priv: ?*anyopaque) callconv(.C) i32,
    fallocate: ?*const fn (file: ?*anyopaque, mode: i32, offset: i64, len: i64) callconv(.C) i64,
    copy_file_range: ?*const fn (src: ?*anyopaque, off_in: *i64, dst: ?*anyopaque, off_out: *i64, len: usize, flags: u32) callconv(.C) isize,
    remap_file_range: ?*const fn (src: ?*anyopaque, pos_in: i64, dst: ?*anyopaque, pos_out: i64, len: u64, flags: u32) callconv(.C) i64,
    fadvise: ?*const fn (file: ?*anyopaque, offset: i64, len: i64, advice: i32) callconv(.C) i32,
    uring_cmd: ?*const fn (issue_flags: u32, cmd: ?*anyopaque) callconv(.C) i32,
    uring_cmd_iopoll: ?*const fn (cmd: ?*anyopaque) callconv(.C) i32,
};

// ============================================================================
// Super Block Operations
// ============================================================================

pub const SuperBlockFlags = packed struct(u64) {
    rdonly: bool = false,
    nosuid: bool = false,
    nodev: bool = false,
    noexec: bool = false,
    synchronous: bool = false,
    mandlock: bool = false,
    dirsync: bool = false,
    noatime: bool = false,
    nodiratime: bool = false,
    relatime: bool = false,
    kernmount: bool = false,
    i_version: bool = false,
    lazytime: bool = false,
    submount: bool = false,
    noremotelock: bool = false,
    nosec: bool = false,
    born: bool = false,
    active: bool = false,
    nouser: bool = false,
    posixacl: bool = false,
    _reserved: u44 = 0,
};

pub const SuperBlock = struct {
    s_dev: u32,
    s_blocksize: u64,
    s_blocksize_bits: u8,
    s_dirt: bool,
    s_maxbytes: u64,
    s_type: ?*anyopaque,       // file_system_type
    s_op: ?*const SuperOperations,
    s_dquot: DquotInfo,
    s_flags: SuperBlockFlags,
    s_magic: u64,
    s_root: ?*Dentry,
    s_umount: RwSemaphore,
    s_count: i32,
    s_active: i32,
    s_security: ?*anyopaque,
    s_xattr: ?*anyopaque,
    s_id: [32]u8,
    s_uuid: [16]u8,
    s_fs_info: ?*anyopaque,
    s_time_gran: u32,
    s_time_min: i64,
    s_time_max: i64,
    s_shrink: Shrinker,
    s_inodes: ListHead,
    s_inode_lru: ListLruOne,
    s_dentry_lru: ListLruOne,
};

pub const SuperOperations = struct {
    alloc_inode: ?*const fn (sb: *SuperBlock) callconv(.C) ?*Inode,
    destroy_inode: ?*const fn (inode: *Inode) callconv(.C) void,
    free_inode: ?*const fn (inode: *Inode) callconv(.C) void,
    dirty_inode: ?*const fn (inode: *Inode, flags: i32) callconv(.C) void,
    write_inode: ?*const fn (inode: *Inode, wbc: ?*anyopaque) callconv(.C) i32,
    drop_inode: ?*const fn (inode: *Inode) callconv(.C) i32,
    evict_inode: ?*const fn (inode: *Inode) callconv(.C) void,
    put_super: ?*const fn (sb: *SuperBlock) callconv(.C) void,
    sync_fs: ?*const fn (sb: *SuperBlock, wait: i32) callconv(.C) i32,
    freeze_super: ?*const fn (sb: *SuperBlock) callconv(.C) i32,
    freeze_fs: ?*const fn (sb: *SuperBlock) callconv(.C) i32,
    thaw_super: ?*const fn (sb: *SuperBlock) callconv(.C) i32,
    unfreeze_fs: ?*const fn (sb: *SuperBlock) callconv(.C) i32,
    statfs: ?*const fn (dentry: *Dentry, buf: *Kstatfs) callconv(.C) i32,
    remount_fs: ?*const fn (sb: *SuperBlock, flags: *i32, data: ?[*:0]u8) callconv(.C) i32,
    umount_begin: ?*const fn (sb: *SuperBlock) callconv(.C) void,
    show_options: ?*const fn (m: ?*anyopaque, root: *Dentry) callconv(.C) i32,
    show_devname: ?*const fn (m: ?*anyopaque, root: *Dentry) callconv(.C) i32,
    show_path: ?*const fn (m: ?*anyopaque, root: *Dentry) callconv(.C) i32,
    show_stats: ?*const fn (m: ?*anyopaque, root: *Dentry) callconv(.C) i32,
    quota_read: ?*const fn (sb: *SuperBlock, qtype: i32, data: [*]u8, len: usize, off: i64) callconv(.C) isize,
    quota_write: ?*const fn (sb: *SuperBlock, qtype: i32, data: [*]const u8, len: usize, off: i64) callconv(.C) isize,
    get_dquots: ?*const fn (inode: *Inode) callconv(.C) ?*anyopaque,
    nr_cached_objects: ?*const fn (sb: *SuperBlock, sc: ?*anyopaque) callconv(.C) i64,
    free_cached_objects: ?*const fn (sb: *SuperBlock, sc: ?*anyopaque) callconv(.C) i64,
};

// ============================================================================
// File Locking
// ============================================================================

pub const FileLockType = enum(u8) {
    ReadLock = 0,   // F_RDLCK
    WriteLock = 1,  // F_WRLCK
    Unlock = 2,     // F_UNLCK
};

pub const FileLock = struct {
    fl_blocker: ?*FileLock,
    fl_list: ListHead,
    fl_link: HashListNode,
    fl_blocked_requests: ListHead,
    fl_blocked_member: ListHead,
    fl_owner: ?*anyopaque,
    fl_flags: u32,
    fl_type: FileLockType,
    fl_pid: i32,
    fl_start: i64,
    fl_end: i64,
    fl_fasync: ?*FasyncStruct,
    fl_break_time: u64,
    fl_downgrade_time: u64,
    fl_ops: ?*const FileLockOps,
    fl_lmops: ?*const LockManagerOps,
    fl_nspid: ?*anyopaque,
    fl_file: ?*anyopaque,
};

pub const FileLockOps = struct {
    fl_copy_lock: ?*const fn (new: *FileLock, fl: *FileLock) callconv(.C) void,
    fl_release_private: ?*const fn (fl: *FileLock) callconv(.C) void,
};

pub const LockManagerOps = struct {
    lm_mod_owner: ?*anyopaque,
    lm_notify: ?*const fn (fl: *FileLock) callconv(.C) i32,
    lm_grant: ?*const fn (fl: *FileLock, new: *FileLock) callconv(.C) i32,
    lm_break: ?*const fn (fl: *FileLock) callconv(.C) bool,
    lm_change: ?*const fn (fl: *FileLock, arg: i32, list: *ListHead) callconv(.C) i32,
    lm_setup: ?*const fn (fl: *FileLock, pfl: ?*?*anyopaque) callconv(.C) void,
    lm_put_owner: ?*const fn (owner: ?*anyopaque) callconv(.C) void,
    lm_breaker_owns_lease: ?*const fn (fl: *FileLock) callconv(.C) bool,
    lm_lock_expirable: ?*const fn (fl: *FileLock) callconv(.C) bool,
    lm_expire_lock: ?*const fn () callconv(.C) void,
};

pub const FileLockContext = struct {
    flc_lock: SpinLock,
    flc_flock: ListHead,
    flc_posix: ListHead,
    flc_lease: ListHead,
    flc_flock_cnt: i32,
    flc_posix_cnt: i32,
    flc_lease_cnt: i32,
};

// ============================================================================
// Fasync (Async Notification)
// ============================================================================

pub const FasyncStruct = struct {
    fa_list: ?*FasyncStruct,
    magic: u32,
    fa_fd: i32,
    fa_file: ?*anyopaque,
    fa_lock: RwLock,
    fa_rcu: RcuHead,
};

// ============================================================================
// Kstatfs / Kstat
// ============================================================================

pub const Kstatfs = struct {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [4]u64,
};

pub const Kstat = struct {
    result_mask: u32,
    mode: u16,
    nlink: u32,
    blksize: u32,
    attributes: u64,
    attributes_mask: u64,
    ino: u64,
    dev: u32,
    rdev: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: Timespec64,
    mtime: Timespec64,
    ctime: Timespec64,
    btime: Timespec64,
    blocks: u64,
    mnt_id: u64,
    dio_mem_align: u32,
    dio_offset_align: u32,
    change_cookie: u64,
    subvol: u64,
};

// ============================================================================
// Address Space
// ============================================================================

pub const AddressSpaceOperations = struct {
    writepage: ?*const fn (page: ?*anyopaque, wbc: ?*anyopaque) callconv(.C) i32,
    read_folio: ?*const fn (file: ?*anyopaque, folio: ?*anyopaque) callconv(.C) i32,
    writepages: ?*const fn (mapping: *AddressSpace, wbc: ?*anyopaque) callconv(.C) i32,
    dirty_folio: ?*const fn (mapping: *AddressSpace, folio: ?*anyopaque) callconv(.C) bool,
    readahead: ?*const fn (rac: ?*anyopaque) callconv(.C) void,
    write_begin: ?*const fn (file: ?*anyopaque, mapping: *AddressSpace, pos: i64, len: u32, pagep: ?*?*anyopaque) callconv(.C) i32,
    write_end: ?*const fn (file: ?*anyopaque, mapping: *AddressSpace, pos: i64, len: u32, copied: u32, page: ?*anyopaque) callconv(.C) i32,
    bmap: ?*const fn (mapping: *AddressSpace, block: u64) callconv(.C) u64,
    invalidate_folio: ?*const fn (folio: ?*anyopaque, offset: usize, length: usize) callconv(.C) void,
    release_folio: ?*const fn (folio: ?*anyopaque, gfp: u32) callconv(.C) bool,
    free_folio: ?*const fn (folio: ?*anyopaque) callconv(.C) void,
    direct_IO: ?*const fn (iocb: ?*anyopaque, iter: ?*anyopaque) callconv(.C) isize,
    migrate_folio: ?*const fn (mapping: *AddressSpace, dst: ?*anyopaque, src: ?*anyopaque, mode: i32) callconv(.C) i32,
    launder_folio: ?*const fn (folio: ?*anyopaque) callconv(.C) i32,
    is_partially_uptodate: ?*const fn (folio: ?*anyopaque, from: usize, count: usize) callconv(.C) bool,
    error_remove_folio: ?*const fn (mapping: *AddressSpace, folio: ?*anyopaque) callconv(.C) i32,
    swap_activate: ?*const fn (sis: ?*anyopaque, file: ?*anyopaque, span: ?*anyopaque) callconv(.C) i32,
    swap_deactivate: ?*const fn (file: ?*anyopaque) callconv(.C) void,
    swap_rw: ?*const fn (iocb: ?*anyopaque, iter: ?*anyopaque) callconv(.C) i32,
};

pub const AddressSpace = struct {
    host: ?*Inode,
    i_pages: XArray,
    invalidate_lock: RwSemaphore,
    gfp_mask: u32,
    i_mmap_writable: i32,
    i_mmap: RbRoot,
    i_mmap_rwsem: RwSemaphore,
    nrpages: u64,
    writeback_index: u64,
    a_ops: ?*const AddressSpaceOperations,
    flags: u64,
    wb_err: u32,
    private_lock: SpinLock,
    private_list: ListHead,
    private_data: ?*anyopaque,
};

// ============================================================================
// Stub types (referenced throughout)
// ============================================================================

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,
};

pub const HashListNode = struct {
    next: ?*HashListNode,
    pprev: ?*?*HashListNode,
};

pub const HashListBl = struct {
    first: ?*HashListNode,
};

pub const RcuHead = struct {
    next: ?*RcuHead,
    func: ?*const fn (head: *RcuHead) callconv(.C) void,
};

pub const SpinLock = struct { raw: u32 = 0 };
pub const RwLock = struct { raw: u32 = 0 };
pub const RwSemaphore = struct { count: i64 = 0, owner: u64 = 0 };
pub const LockRef = struct { lock: SpinLock = .{}, count: i32 = 0 };
pub const Shrinker = struct { count: u64 = 0, batch: u64 = 0 };
pub const ListLruOne = struct { list: ListHead = .{ .next = null, .prev = null }, nr_items: u64 = 0 };
pub const DquotInfo = struct { dummy: u64 = 0 };
pub const VfsMount = struct { dummy: u64 = 0 };
pub const Timespec64 = extern struct { tv_sec: i64, tv_nsec: i64 };
pub const XArray = struct { xa_lock: SpinLock = .{}, xa_flags: u32 = 0, xa_head: ?*anyopaque = null };
pub const RbRoot = struct { rb_node: ?*anyopaque = null };

// ============================================================================
// VFS Manager
// ============================================================================

pub const VfsPathManager = struct {
    dcache_entries: u64,
    inode_cache_entries: u64,
    dentry_unused: u64,
    inode_unused: u64,
    total_lookups: u64,
    cache_hits: u64,
    cache_misses: u64,
    path_walks_rcu: u64,
    path_walks_ref: u64,
    negative_dentries: u64,
    total_file_locks: u64,
    initialized: bool,

    pub fn init() VfsPathManager {
        return .{
            .dcache_entries = 0,
            .inode_cache_entries = 0,
            .dentry_unused = 0,
            .inode_unused = 0,
            .total_lookups = 0,
            .cache_hits = 0,
            .cache_misses = 0,
            .path_walks_rcu = 0,
            .path_walks_ref = 0,
            .negative_dentries = 0,
            .total_file_locks = 0,
            .initialized = true,
        };
    }
};
