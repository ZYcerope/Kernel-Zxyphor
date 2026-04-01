// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - VFS Layer: Virtual Filesystem Switch, Inode Operations, Dentry Cache
// Linux 6.x compatible with Zxyphor capability-based extensions

const std = @import("std");

// ============================================================================
// Superblock
// ============================================================================

pub const SUPER_MAGIC_EXT4: u64 = 0xEF53;
pub const SUPER_MAGIC_XFS: u64 = 0x58465342;
pub const SUPER_MAGIC_BTRFS: u64 = 0x9123683E;
pub const SUPER_MAGIC_TMPFS: u64 = 0x01021994;
pub const SUPER_MAGIC_PROC: u64 = 0x9FA0;
pub const SUPER_MAGIC_SYSFS: u64 = 0x62656572;
pub const SUPER_MAGIC_DEVTMPFS: u64 = 0x01021994;
pub const SUPER_MAGIC_ZXYFS: u64 = 0x5A585946;
pub const SUPER_MAGIC_NFS: u64 = 0x6969;
pub const SUPER_MAGIC_CIFS: u64 = 0xFF534D42;
pub const SUPER_MAGIC_FUSE: u64 = 0x65735546;
pub const SUPER_MAGIC_OVERLAY: u64 = 0x794C7630;
pub const SUPER_MAGIC_SQUASHFS: u64 = 0x73717368;
pub const SUPER_MAGIC_EROFS: u64 = 0xE0F5E1E2;
pub const SUPER_MAGIC_F2FS: u64 = 0xF2F52010;

pub const SB_RDONLY: u64 = 1;
pub const SB_NOSUID: u64 = 2;
pub const SB_NODEV: u64 = 4;
pub const SB_NOEXEC: u64 = 8;
pub const SB_SYNCHRONOUS: u64 = 16;
pub const SB_MANDLOCK: u64 = 64;
pub const SB_DIRSYNC: u64 = 128;
pub const SB_NOATIME: u64 = 1024;
pub const SB_NODIRATIME: u64 = 2048;
pub const SB_SILENT: u64 = 0x8000;
pub const SB_POSIXACL: u64 = 1 << 16;
pub const SB_INLINECRYPT: u64 = 1 << 17;
pub const SB_LAZYTIME: u64 = 1 << 25;

pub const SuperBlock = struct {
    s_dev: u64,
    s_blocksize: u32,
    s_blocksize_bits: u8,
    s_maxbytes: u64,
    s_type: ?*FileSystemType,
    s_op: ?*const SuperOperations,
    s_dq_op: ?*const DquotOperations,
    s_xattr: ?*const XattrHandler,
    s_export_op: ?*const ExportOperations,
    s_magic: u64,
    s_root: ?*Dentry,
    s_flags: u64,
    s_iflags: u32,
    s_id: [32]u8,
    s_uuid: [16]u8,
    s_fs_info: ?*anyopaque,
    s_time_gran: u32,
    s_time_min: i64,
    s_time_max: i64,
    // Counts
    s_count: u32,
    s_active: u32,
    s_nr_inodes: u64,
    s_nr_dentry_unused: u64,
    // Writeback
    s_writeback: WritebackState,
    // Quota
    s_dquot: SuperBlockDquot,
    // Freeze
    s_frozen: FreezeState,
    s_freeze_count: u32,
    // Security
    s_security: ?*anyopaque,
    // Zxyphor extensions
    s_zxy_features: ZxyFsFeatures,

    pub fn is_readonly(self: *const SuperBlock) bool {
        return (self.s_flags & SB_RDONLY) != 0;
    }

    pub fn remount_readonly(self: *SuperBlock) void {
        self.s_flags |= SB_RDONLY;
    }

    pub fn needs_sync(self: *const SuperBlock) bool {
        return (self.s_flags & SB_SYNCHRONOUS) != 0;
    }
};

pub const WritebackState = struct {
    nr_dirty: u64,
    nr_writeback: u64,
    nr_to_write: u64,
    last_written: u64,
};

pub const FreezeState = enum(u8) {
    unfrozen = 0,
    write = 1,
    pagefault = 2,
    fs = 3,
    complete = 4,
};

pub const ZxyFsFeatures = packed struct(u64) {
    capability_based: bool = false,
    encryption: bool = false,
    compression: bool = false,
    deduplication: bool = false,
    snapshots: bool = false,
    cow: bool = false,
    checksumming: bool = false,
    inline_data: bool = false,
    zero_copy: bool = false,
    persistent_cache: bool = false,
    ai_prefetch: bool = false,
    _reserved: u53 = 0,
};

// ============================================================================
// Super Operations
// ============================================================================

pub const SuperOperations = struct {
    alloc_inode: ?*const fn (*SuperBlock) ?*Inode,
    destroy_inode: ?*const fn (*Inode) void,
    free_inode: ?*const fn (*Inode) void,
    dirty_inode: ?*const fn (*Inode, i32) void,
    write_inode: ?*const fn (*Inode, *WritebackControl) i32,
    drop_inode: ?*const fn (*Inode) i32,
    evict_inode: ?*const fn (*Inode) void,
    put_super: ?*const fn (*SuperBlock) void,
    sync_fs: ?*const fn (*SuperBlock, bool) i32,
    freeze_super: ?*const fn (*SuperBlock) i32,
    freeze_fs: ?*const fn (*SuperBlock) i32,
    thaw_super: ?*const fn (*SuperBlock) i32,
    unfreeze_fs: ?*const fn (*SuperBlock) i32,
    statfs: ?*const fn (*Dentry, *Kstatfs) i32,
    remount_fs: ?*const fn (*SuperBlock, *i32, [*]u8) i32,
    umount_begin: ?*const fn (*SuperBlock) void,
    show_options: ?*const fn (*anyopaque, *Dentry) i32,
    show_devname: ?*const fn (*anyopaque, *Dentry) i32,
    show_path: ?*const fn (*anyopaque, *Dentry) i32,
    show_stats: ?*const fn (*anyopaque, *Dentry) i32,
    nr_cached_objects: ?*const fn (*SuperBlock, *anyopaque) u64,
    free_cached_objects: ?*const fn (*SuperBlock, *anyopaque, u64) u64,
};

pub const WritebackControl = struct {
    nr_to_write: u64,
    pages_skipped: u64,
    range_start: u64,
    range_end: u64,
    sync_mode: WritebackSyncMode,
    for_kupdate: bool,
    for_background: bool,
    tagged_writepages: bool,
    for_reclaim: bool,
    range_cyclic: bool,
    for_sync: bool,
    unpinned_fscache_wb: bool,
};

pub const WritebackSyncMode = enum(u8) {
    none = 0,
    all = 1,
    hold = 2,
};

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

// ============================================================================
// Inode
// ============================================================================

pub const InodeMode = packed struct(u16) {
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

pub const S_IFMT: u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFIFO: u16 = 0o010000;

pub const InodeFlags = packed struct(u32) {
    sync: bool = false,
    immutable: bool = false,
    append: bool = false,
    nodump: bool = false,
    noatime: bool = false,
    dirty: bool = false,
    compressed: bool = false,
    encrypt: bool = false,
    casefold: bool = false,
    verity: bool = false,
    dax: bool = false,
    inline_data: bool = false,
    // Zxyphor
    zxy_dedup: bool = false,
    zxy_snapshot: bool = false,
    zxy_sealed: bool = false,
    _reserved: u17 = 0,
};

pub const Inode = struct {
    i_mode: u16,
    i_opflags: u16,
    i_uid: u32,
    i_gid: u32,
    i_flags: InodeFlags,
    // ACL
    i_acl: ?*anyopaque,
    i_default_acl: ?*anyopaque,
    // Operations
    i_op: ?*const InodeOperations,
    i_sb: ?*SuperBlock,
    i_fop: ?*const FileOperations,
    // Address space for page cache
    i_mapping: ?*AddressSpace,
    // Security
    i_security: ?*anyopaque,
    // Inode number
    i_ino: u64,
    // Counts
    i_nlink: u32,
    i_count: u32,
    // Device
    i_rdev: u64,
    // Size
    i_size: i64,
    // Timestamps
    i_atime: Timespec,
    i_mtime: Timespec,
    i_ctime: Timespec,
    // Blocks
    i_blkbits: u32,
    i_blocks: u64,
    i_bytes: u16,
    // State
    i_state: u32,
    i_writecount: i32,
    // Private data
    i_private: ?*anyopaque,
    // Generation
    i_generation: u32,
    i_version: u64,

    pub fn is_reg(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFREG;
    }

    pub fn is_dir(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFDIR;
    }

    pub fn is_lnk(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFLNK;
    }

    pub fn is_chr(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFCHR;
    }

    pub fn is_blk(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFBLK;
    }

    pub fn is_fifo(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFIFO;
    }

    pub fn is_sock(self: *const Inode) bool {
        return (self.i_mode & S_IFMT) == S_IFSOCK;
    }
};

pub const Timespec = struct {
    tv_sec: i64,
    tv_nsec: i64,
};

pub const AddressSpace = struct {
    host: ?*Inode,
    nrpages: u64,
    nrexceptional: u64,
    a_ops: ?*const AddressSpaceOperations,
    flags: u64,
    wb_err: i32,
    i_mmap: ?*anyopaque, // rb_root for VMAs
    i_mmap_writable: u64,
    private_data: ?*anyopaque,
};

pub const AddressSpaceOperations = struct {
    writepage: ?*const fn (?*anyopaque, *WritebackControl) i32,
    read_folio: ?*const fn (?*anyopaque, ?*anyopaque) i32,
    writepages: ?*const fn (*AddressSpace, *WritebackControl) i32,
    dirty_folio: ?*const fn (*AddressSpace, ?*anyopaque) bool,
    readahead: ?*const fn (?*anyopaque) void,
    write_begin: ?*const fn (?*anyopaque, *AddressSpace, u64, u32, ?*?*anyopaque) i32,
    write_end: ?*const fn (?*anyopaque, *AddressSpace, u64, u32, u32, ?*anyopaque) i32,
    bmap: ?*const fn (*AddressSpace, u64) u64,
    invalidate_folio: ?*const fn (?*anyopaque, u64, u64) void,
    release_folio: ?*const fn (?*anyopaque, u32) bool,
    free_folio: ?*const fn (?*anyopaque) void,
    direct_IO: ?*const fn (?*anyopaque, ?*anyopaque) i64,
    migrate_folio: ?*const fn (*AddressSpace, ?*anyopaque, ?*anyopaque, u32) i32,
    launder_folio: ?*const fn (?*anyopaque) i32,
    is_partially_uptodate: ?*const fn (?*anyopaque, u64, u64) bool,
    error_remove_page: ?*const fn (*AddressSpace, ?*anyopaque) i32,
    swap_activate: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque) i32,
    swap_deactivate: ?*const fn (?*anyopaque) void,
    swap_rw: ?*const fn (?*anyopaque, ?*anyopaque) i32,
};

// ============================================================================
// Inode Operations
// ============================================================================

pub const InodeOperations = struct {
    lookup: ?*const fn (*Inode, *Dentry, u32) ?*Dentry,
    get_link: ?*const fn (*Dentry, *Inode, ?*anyopaque) ?[*]const u8,
    permission: ?*const fn (?*anyopaque, *Inode, i32) i32,
    get_inode_acl: ?*const fn (*Inode, i32, bool) ?*anyopaque,
    readlink: ?*const fn (*Dentry, [*]u8, i32) i32,
    create: ?*const fn (?*anyopaque, *Inode, *Dentry, u16, bool) i32,
    link: ?*const fn (*Dentry, *Inode, *Dentry) i32,
    unlink: ?*const fn (*Inode, *Dentry) i32,
    symlink: ?*const fn (?*anyopaque, *Inode, *Dentry, [*]const u8) i32,
    mkdir: ?*const fn (?*anyopaque, *Inode, *Dentry, u16) i32,
    rmdir: ?*const fn (*Inode, *Dentry) i32,
    mknod: ?*const fn (?*anyopaque, *Inode, *Dentry, u16, u32) i32,
    rename: ?*const fn (?*anyopaque, *Inode, *Dentry, *Inode, *Dentry, u32) i32,
    setattr: ?*const fn (?*anyopaque, *Dentry, *Iattr) i32,
    getattr: ?*const fn (?*anyopaque, *const Path, *Kstat, u32, u32) i32,
    listxattr: ?*const fn (*Dentry, [*]u8, u64) i64,
    fiemap: ?*const fn (*Inode, ?*anyopaque) i32,
    update_time: ?*const fn (*Inode, i32) i32,
    atomic_open: ?*const fn (*Inode, *Dentry, ?*anyopaque, u32, u16) i32,
    tmpfile: ?*const fn (?*anyopaque, *Inode, ?*anyopaque, u16) i32,
    fileattr_set: ?*const fn (?*anyopaque, *Dentry, ?*anyopaque) i32,
    fileattr_get: ?*const fn (*Dentry, ?*anyopaque) i32,
};

pub const Iattr = struct {
    ia_valid: u32,
    ia_mode: u16,
    ia_uid: u32,
    ia_gid: u32,
    ia_size: i64,
    ia_atime: Timespec,
    ia_mtime: Timespec,
    ia_ctime: Timespec,
    ia_file: ?*anyopaque,
};

pub const ATTR_MODE: u32 = 1 << 0;
pub const ATTR_UID: u32 = 1 << 1;
pub const ATTR_GID: u32 = 1 << 2;
pub const ATTR_SIZE: u32 = 1 << 3;
pub const ATTR_ATIME: u32 = 1 << 4;
pub const ATTR_MTIME: u32 = 1 << 5;
pub const ATTR_CTIME: u32 = 1 << 6;
pub const ATTR_OPEN: u32 = 1 << 15;

pub const Kstat = struct {
    result_mask: u32,
    mode: u16,
    nlink: u32,
    blksize: u32,
    attributes: u64,
    attributes_mask: u64,
    ino: u64,
    dev: u64,
    rdev: u64,
    uid: u32,
    gid: u32,
    size: i64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    btime: Timespec,
    blocks: u64,
    mnt_id: u64,
    dio_mem_align: u32,
    dio_offset_align: u32,
    change_cookie: u64,
    subvol: u64,
};

// ============================================================================
// Dentry (Directory Entry Cache)
// ============================================================================

pub const DNAME_INLINE_LEN: usize = 40;

pub const DentryFlags = packed struct(u32) {
    mounted: bool = false,
    disconnected: bool = false,
    autodir: bool = false,
    genocide: bool = false,
    shrink_list: bool = false,
    op_hash: bool = false,
    op_compare: bool = false,
    op_revalidate: bool = false,
    op_delete: bool = false,
    op_prune: bool = false,
    op_real: bool = false,
    is_negative: bool = false,
    // Zxyphor
    zxy_cached: bool = false,
    zxy_encrypted: bool = false,
    _reserved: u18 = 0,
};

pub const Dentry = struct {
    d_flags: DentryFlags,
    d_seq: u32,           // Seqlock for parallel lookups
    d_hash_next: ?*Dentry,
    d_parent: ?*Dentry,
    d_name: QStr,
    d_inode: ?*Inode,
    d_iname: [DNAME_INLINE_LEN]u8, // Small name
    d_lockref: u64,       // Lock + refcount
    d_op: ?*const DentryOperations,
    d_sb: ?*SuperBlock,
    d_time: u64,          // Revalidate timeout
    d_fsdata: ?*anyopaque,
    // Children/siblings LRU
    d_child_first: ?*Dentry,
    d_subdirs_count: u32,

    pub fn is_root(self: *const Dentry) bool {
        return self.d_parent == null or @intFromPtr(self.d_parent) == @intFromPtr(self);
    }

    pub fn is_negative(self: *const Dentry) bool {
        return self.d_inode == null;
    }

    pub fn name_slice(self: *const Dentry) []const u8 {
        return self.d_name.name[0..self.d_name.len];
    }
};

pub const QStr = struct {
    hash: u32,
    len: u32,
    name: [*]const u8,
};

pub const DentryOperations = struct {
    d_revalidate: ?*const fn (*Dentry, u32) i32,
    d_weak_revalidate: ?*const fn (*Dentry, u32) i32,
    d_hash: ?*const fn (*const Dentry, *QStr) i32,
    d_compare: ?*const fn (*const Dentry, u32, [*]const u8, *const QStr) i32,
    d_delete: ?*const fn (*const Dentry) i32,
    d_init: ?*const fn (*Dentry) i32,
    d_release: ?*const fn (*Dentry) void,
    d_prune: ?*const fn (*Dentry) void,
    d_iput: ?*const fn (*Dentry, *Inode) void,
    d_dname: ?*const fn (*Dentry, [*]u8, i32) [*]const u8,
    d_automount: ?*const fn (*Path) ?*anyopaque,
    d_manage: ?*const fn (*const Path, bool) i32,
    d_real: ?*const fn (*Dentry, *const Inode) ?*Dentry,
};

// ============================================================================
// Path Lookup
// ============================================================================

pub const Path = struct {
    mnt: ?*VfsMount,
    dentry: ?*Dentry,
};

pub const Nameidata = struct {
    path: Path,
    last: QStr,
    root: Path,
    inode: ?*Inode,
    flags: u32,
    state: u32,
    seq: u32,
    next_seq: u32,
    last_type: NameType,
    depth: u32,
    total_link_count: u32,
    // Saved paths for ".."
    saved: [8]NameidataSaved,
    // RCU lookup
    m_seq: u32,
    r_seq: u32,
    filename: ?*Filename,
};

pub const NameType = enum(u8) {
    normal = 0,
    root = 1,
    dot = 2,
    dotdot = 3,
};

pub const NameidataSaved = struct {
    link: Path,
    seq: u32,
};

pub const Filename = struct {
    name: [*]const u8,
    uptr: ?[*]const u8,
    refcnt: u32,
    aname: ?*anyopaque,
    iname: [256]u8,
};

// Lookup flags
pub const LOOKUP_FOLLOW: u32 = 0x0001;
pub const LOOKUP_DIRECTORY: u32 = 0x0002;
pub const LOOKUP_AUTOMOUNT: u32 = 0x0004;
pub const LOOKUP_EMPTY: u32 = 0x4000;
pub const LOOKUP_REVAL: u32 = 0x0020;
pub const LOOKUP_RCU: u32 = 0x0040;
pub const LOOKUP_OPEN: u32 = 0x0100;
pub const LOOKUP_CREATE: u32 = 0x0200;
pub const LOOKUP_EXCL: u32 = 0x0400;
pub const LOOKUP_RENAME_TARGET: u32 = 0x0800;
pub const LOOKUP_PARENT: u32 = 0x0010;
pub const LOOKUP_NO_XDEV: u32 = 0x1000;
pub const LOOKUP_BENEATH: u32 = 0x2000;
pub const LOOKUP_IN_ROOT: u32 = 0x8000;
pub const LOOKUP_CACHED: u32 = 0x10000;

// ============================================================================
// File Operations
// ============================================================================

pub const FileOperations = struct {
    owner: ?*anyopaque,
    llseek: ?*const fn (?*anyopaque, i64, i32) i64,
    read: ?*const fn (?*anyopaque, [*]u8, u64, *i64) i64,
    write: ?*const fn (?*anyopaque, [*]const u8, u64, *i64) i64,
    read_iter: ?*const fn (?*anyopaque, ?*anyopaque) i64,
    write_iter: ?*const fn (?*anyopaque, ?*anyopaque) i64,
    iopoll: ?*const fn (?*anyopaque, ?*anyopaque, u32) i32,
    iterate_shared: ?*const fn (?*anyopaque, ?*anyopaque) i32,
    poll: ?*const fn (?*anyopaque, ?*anyopaque) u32,
    unlocked_ioctl: ?*const fn (?*anyopaque, u32, u64) i64,
    compat_ioctl: ?*const fn (?*anyopaque, u32, u64) i64,
    mmap: ?*const fn (?*anyopaque, ?*anyopaque) i32,
    open: ?*const fn (*Inode, ?*anyopaque) i32,
    flush: ?*const fn (?*anyopaque, ?*anyopaque) i32,
    release: ?*const fn (*Inode, ?*anyopaque) i32,
    fsync: ?*const fn (?*anyopaque, i64, i64, i32) i32,
    fasync: ?*const fn (i32, ?*anyopaque, i32) i32,
    lock: ?*const fn (?*anyopaque, i32, ?*anyopaque) i32,
    get_unmapped_area: ?*const fn (?*anyopaque, u64, u64, u64, u64) u64,
    check_flags: ?*const fn (i32) i32,
    flock: ?*const fn (?*anyopaque, i32, ?*anyopaque) i32,
    splice_write: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, *u64, u64, u32) i64,
    splice_read: ?*const fn (?*anyopaque, *i64, ?*anyopaque, u64, u32) i64,
    splice_eof: ?*const fn (?*anyopaque) void,
    setlease: ?*const fn (?*anyopaque, i32, ?*?*anyopaque, ?*?*anyopaque) i32,
    fallocate: ?*const fn (?*anyopaque, i32, i64, i64) i64,
    show_fdinfo: ?*const fn (?*anyopaque, ?*anyopaque) void,
    copy_file_range: ?*const fn (?*anyopaque, i64, ?*anyopaque, i64, u64, u32) i64,
    remap_file_range: ?*const fn (?*anyopaque, u64, ?*anyopaque, u64, u64, u32) i64,
    fadvise: ?*const fn (?*anyopaque, i64, i64, i32) i32,
    uring_cmd: ?*const fn (?*anyopaque, u32) i32,
    uring_cmd_iopoll: ?*const fn (?*anyopaque, ?*anyopaque, u32) i32,
};

// ============================================================================
// File
// ============================================================================

pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DSYNC: u32 = 0o10000;
pub const O_SYNC: u32 = 0o4010000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_TMPFILE: u32 = 0o20200000;
pub const O_PATH: u32 = 0o10000000;
pub const O_LARGEFILE: u32 = 0o100000;

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;
pub const SEEK_DATA: i32 = 3;
pub const SEEK_HOLE: i32 = 4;

pub const File = struct {
    f_path: Path,
    f_inode: ?*Inode,
    f_op: ?*const FileOperations,
    f_lock: u32,
    f_count: u64,
    f_flags: u32,
    f_mode: u32,
    f_pos: i64,
    f_pos_lock: u64,
    f_owner: FownStruct,
    f_cred: ?*anyopaque,
    f_ra: FileRaState,
    f_version: u64,
    f_security: ?*anyopaque,
    private_data: ?*anyopaque,
    f_mapping: ?*AddressSpace,
    f_wb_err: i32,
    f_sb_err: i32,
};

pub const FownStruct = struct {
    pid: ?*anyopaque,
    pid_type: u32,
    uid: u32,
    euid: u32,
    signum: i32,
};

pub const FileRaState = struct {
    start: u64,
    size: u32,
    async_size: u32,
    ra_pages: u32,
    mmap_miss: u32,
    prev_pos: i64,
};

// ============================================================================
// VFS Mount
// ============================================================================

pub const MNT_NOSUID: u32 = 0x01;
pub const MNT_NODEV: u32 = 0x02;
pub const MNT_NOEXEC: u32 = 0x04;
pub const MNT_NOATIME: u32 = 0x08;
pub const MNT_NODIRATIME: u32 = 0x10;
pub const MNT_RELATIME: u32 = 0x20;
pub const MNT_READONLY: u32 = 0x40;
pub const MNT_SHRINKABLE: u32 = 0x100;
pub const MNT_WRITE_HOLD: u32 = 0x200;
pub const MNT_SHARED: u32 = 0x1000;
pub const MNT_UNBINDABLE: u32 = 0x2000;

pub const VfsMount = struct {
    mnt_root: ?*Dentry,
    mnt_sb: ?*SuperBlock,
    mnt_flags: u32,
    // Private mount internals
    mnt_id: u32,
    mnt_group_id: u32,
    mnt_count: u32,
    mnt_expiry_mark: bool,
    mnt_parent: ?*VfsMount,
    mnt_mountpoint: ?*Dentry,
    mnt_devname: [256]u8,
    // Mount namespace
    mnt_ns: ?*MountNamespace,
};

pub const MountNamespace = struct {
    count: u32,
    nr_mounts: u32,
    root: ?*VfsMount,
    mounts: [1024]?*VfsMount,
    pending_mounts: u32,
    seq: u64,
    poll: u64,
    event: u64,
    user_ns: ?*anyopaque,
};

// ============================================================================
// File System Type Registration
// ============================================================================

pub const FileSystemType = struct {
    name: [32]u8,
    fs_flags: u32,
    // Mount function pointer
    init_fs_context: ?*const fn (?*anyopaque) i32,
    parameters: ?*anyopaque,
    mount: ?*const fn (*FileSystemType, i32, [*]const u8, ?*anyopaque) ?*Dentry,
    kill_sb: ?*const fn (*SuperBlock) void,
    // Module owner
    owner: ?*anyopaque,
    next: ?*FileSystemType,
    // Superblock list
    fs_supers: [64]?*SuperBlock,
    nr_supers: u32,
};

pub const FS_REQUIRES_DEV: u32 = 1;
pub const FS_BINARY_MOUNTDATA: u32 = 2;
pub const FS_HAS_SUBTYPE: u32 = 4;
pub const FS_USERNS_MOUNT: u32 = 8;
pub const FS_DISALLOW_NOTIFY_PERM: u32 = 16;
pub const FS_ALLOW_IDMAP: u32 = 32;
pub const FS_RENAME_DOES_D_MOVE: u32 = 32768;

// ============================================================================
// Filesystem Context (for new mount API)
// ============================================================================

pub const FsContextPurpose = enum(u8) {
    mount = 0,
    submount = 1,
    remount = 2,
    reconfigure = 3,
};

pub const FsContext = struct {
    ops: ?*const FsContextOperations,
    uapi_mutex: u64,
    fs_type: ?*FileSystemType,
    root: ?*Dentry,
    user_ns: ?*anyopaque,
    net_ns: ?*anyopaque,
    cred: ?*anyopaque,
    log: FsContextLog,
    source: [256]u8,
    security: ?*anyopaque,
    s_fs_info: ?*anyopaque,
    sb_flags: u32,
    sb_flags_mask: u32,
    s_iflags: u32,
    purpose: FsContextPurpose,
    need_free: bool,
    global: bool,
    oldapi: bool,
    exclusive: bool,
};

pub const FsContextOperations = struct {
    free: ?*const fn (*FsContext) void,
    dup: ?*const fn (*FsContext, *FsContext) i32,
    parse_param: ?*const fn (*FsContext, ?*anyopaque) i32,
    parse_monolithic: ?*const fn (*FsContext, ?*anyopaque) i32,
    get_tree: ?*const fn (*FsContext) i32,
    reconfigure: ?*const fn (*FsContext) i32,
};

pub const FsContextLog = struct {
    buffer: [4096]u8,
    len: u32,
    head: u32,
};

// ============================================================================
// Dentry Hashing and Cache
// ============================================================================

pub const DHASH_BITS: u32 = 16;
pub const DHASH_SIZE: u32 = 1 << DHASH_BITS;

pub const DentryHashTable = struct {
    buckets: [DHASH_SIZE]?*Dentry,
    nr_entries: u64,
    nr_unused: u64,
    age_limit: u32,      // Seconds before reclaim

    pub fn hash_name(parent: u64, name: []const u8) u32 {
        var h: u32 = @truncate(parent);
        for (name) |c| {
            h = h *% 31 +% c;
        }
        return h & (DHASH_SIZE - 1);
    }

    pub fn lookup(self: *const DentryHashTable, parent: *const Dentry, name: *const QStr) ?*Dentry {
        const bucket = hash_name(@intFromPtr(parent), name.name[0..name.len]);
        var entry = self.buckets[bucket];
        while (entry) |e| {
            if (e.d_parent == parent and e.d_name.len == name.len and e.d_name.hash == name.hash) {
                return e;
            }
            entry = e.d_hash_next;
        }
        return null;
    }
};

// ============================================================================
// Inode Cache
// ============================================================================

pub const IHASH_BITS: u32 = 16;
pub const IHASH_SIZE: u32 = 1 << IHASH_BITS;

pub const InodeHashTable = struct {
    buckets: [IHASH_SIZE]?*InodeHashEntry,
    nr_inodes: u64,
    nr_unused: u64,
    nr_free: u64,
};

pub const InodeHashEntry = struct {
    inode: ?*Inode,
    next: ?*InodeHashEntry,
    sb: ?*SuperBlock,
    ino: u64,
};

// ============================================================================
// Extended Operations
// ============================================================================

pub const XattrHandler = struct {
    name: [32]u8,
    prefix: [32]u8,
    flags: i32,
    list: ?*const fn (*Dentry) bool,
    get: ?*const fn (*const XattrHandler, *Dentry, *Inode, [*]const u8, ?*anyopaque, u64) i32,
    set: ?*const fn (*const XattrHandler, ?*anyopaque, *Dentry, *Inode, [*]const u8, ?*const anyopaque, u64, i32) i32,
};

pub const ExportOperations = struct {
    encode_fh: ?*const fn (*Inode, [*]u32, *i32, ?*Inode) i32,
    fh_to_dentry: ?*const fn (*SuperBlock, ?*anyopaque) ?*Dentry,
    fh_to_parent: ?*const fn (*SuperBlock, ?*anyopaque) ?*Dentry,
    get_name: ?*const fn (*Dentry, [*]u8, *Dentry) i32,
    get_parent: ?*const fn (*Dentry) ?*Dentry,
    commit_metadata: ?*const fn (*Inode) i32,
    flags: u32,
};

pub const SuperBlockDquot = struct {
    flags: u32,
    dq_op: ?*const DquotOperations,
    dq_fmt: ?*anyopaque,
};

pub const DquotOperations = struct {
    write_dquot: ?*const fn (?*anyopaque) i32,
    alloc_dquot: ?*const fn (?*anyopaque, i32) ?*anyopaque,
    destroy_dquot: ?*const fn (?*anyopaque) void,
    acquire_dquot: ?*const fn (?*anyopaque) i32,
    release_dquot: ?*const fn (?*anyopaque) i32,
    mark_dirty: ?*const fn (?*anyopaque) i32,
    write_info: ?*const fn (*SuperBlock, i32) i32,
    get_reserved_space: ?*const fn (*Inode) ?*anyopaque,
    get_projid: ?*const fn (*Inode, *u32) i32,
    get_inode_usage: ?*const fn (*Inode, *i64) i32,
    get_next_id: ?*const fn (*SuperBlock, *u32) i32,
};

// ============================================================================
// Poll / Select / Epoll definitions
// ============================================================================

pub const POLLIN: u32 = 0x0001;
pub const POLLPRI: u32 = 0x0002;
pub const POLLOUT: u32 = 0x0004;
pub const POLLERR: u32 = 0x0008;
pub const POLLHUP: u32 = 0x0010;
pub const POLLNVAL: u32 = 0x0020;
pub const POLLRDNORM: u32 = 0x0040;
pub const POLLRDBAND: u32 = 0x0080;
pub const POLLWRNORM: u32 = 0x0100;
pub const POLLWRBAND: u32 = 0x0200;
pub const POLLMSG: u32 = 0x0400;
pub const POLLREMOVE: u32 = 0x1000;
pub const POLLRDHUP: u32 = 0x2000;
pub const POLLFREE: u32 = 0x4000;

// ============================================================================
// Dirent
// ============================================================================

pub const DirContext = struct {
    actor: ?*const fn (*DirContext, [*]const u8, u32, u64, u64, u32) bool,
    pos: i64,
    count: u32,
    error: i32,
};

// Linux getdents64 format
pub const Dirent64 = extern struct {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // d_name follows (variable length)
};

pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;
pub const DT_WHT: u8 = 14;

// ============================================================================
// Notification / Watch
// ============================================================================

pub const FsnotifyGroup = struct {
    marks: [1024]?*FsnotifyMark,
    nr_marks: u32,
    notification_queue: [4096]FsnotifyEvent,
    queue_head: u32,
    queue_tail: u32,
    overflow: bool,
    max_events: u32,
    num_marks: u32,
    ops: ?*const FsnotifyOps,
};

pub const FsnotifyMark = struct {
    mask: u32,
    inode: ?*Inode,
    mnt: ?*VfsMount,
    sb: ?*SuperBlock,
    group: ?*FsnotifyGroup,
    flags: u32,
};

pub const FsnotifyEvent = struct {
    mask: u32,
    inode: ?*Inode,
    dir: ?*Inode,
    name: [256]u8,
    name_len: u16,
    cookie: u32,
};

pub const FsnotifyOps = struct {
    handle_event: ?*const fn (*FsnotifyGroup, u32, *const anyopaque, i32, ?*Inode, *const QStr, u32) i32,
    handle_inode_event: ?*const fn (*FsnotifyMark, u32, *Inode, ?*Inode, *const QStr, u32) i32,
    free_group_priv: ?*const fn (*FsnotifyGroup) void,
    freeing_mark: ?*const fn (*FsnotifyMark, *FsnotifyGroup) void,
    free_event: ?*const fn (*FsnotifyGroup, *FsnotifyEvent) void,
    free_mark: ?*const fn (*FsnotifyMark) void,
};

// ============================================================================
// Overlayfs
// ============================================================================

pub const OverlayEntry = struct {
    is_upper: bool,
    impure: bool,
    opaque: bool,
    copy_up: bool,
    whiteout: bool,
    metacopy: bool,
    upper: ?*Dentry,
    lower_stack: [8]OverlayPath,
    numlower: u32,
    redirect: ?[*]const u8,
};

pub const OverlayPath = struct {
    dentry: ?*Dentry,
    layer: ?*OverlayLayer,
};

pub const OverlayLayer = struct {
    mnt: ?*VfsMount,
    idx: u32,
    fsid: u32,
};

pub const OverlayFsInfo = struct {
    upper_mnt: ?*VfsMount,
    lower_layers: [8]OverlayLayer,
    nr_lower: u32,
    workdir: ?*Dentry,
    workbasedir: ?*Dentry,
    config: OverlayConfig,
};

pub const OverlayConfig = struct {
    lowerdir: [1024]u8,
    upperdir: [256]u8,
    workdir: [256]u8,
    redirect_mode: OverlayRedirectMode,
    nfs_export: bool,
    index: bool,
    metacopy: bool,
    userxattr: bool,
    ovl_volatile: bool,
};

pub const OverlayRedirectMode = enum(u8) {
    off = 0,
    follow = 1,
    nofollow = 2,
    on = 3,
};

// ============================================================================
// FUSE Interface
// ============================================================================

pub const FuseOpcode = enum(u32) {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,
    FUSE_SETUPMAPPING = 48,
    FUSE_REMOVEMAPPING = 49,
    FUSE_SYNCFS = 50,
    FUSE_TMPFILE = 51,
};

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

pub const FuseEntryOut = extern struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
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
