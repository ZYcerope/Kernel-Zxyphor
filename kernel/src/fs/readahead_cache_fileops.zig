// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Readahead, Page Cache Policies & File Handles
// Complete: readahead algorithms, page cache management, file locking,
// file handle operations, dentry cache, inode lifecycle, writeback control

const std = @import("std");

// ============================================================================
// Readahead Algorithm
// ============================================================================

pub const ReadaheadState = enum(u8) {
    Initial = 0,
    Sequential = 1,
    Interleaved = 2,
    RandomAccess = 3,
    Thrashing = 4,
};

pub const ReadaheadControl = struct {
    file: ?*anyopaque,
    mapping: ?*AddressSpace,
    start: u64,           // First page index
    nr_pages: u32,        // Number of pages to read
    async_size: u32,      // Start of async readahead
    ra_pages: u32,        // Max readahead window
    mmap_miss: u32,       // Mmap sequential miss count
    prev_pos: i64,        // Previous read position
    flags: ReadaheadFlags,
};

pub const ReadaheadFlags = packed struct(u32) {
    async_readahead: bool,
    mmap_readahead: bool,
    drop_behind: bool,
    no_readahead: bool,
    initial: bool,
    interleaved: bool,
    _reserved: u26,
};

pub const ReadaheadConfig = struct {
    initial_window: u32,
    max_window: u32,
    min_window: u32,
    ramp_factor: u32,       // Window growth factor
    lookahead_ratio: u32,   // Async trigger ratio (percentage)
    thrash_factor: u32,     // Thrashing detection threshold
    interleave_max: u32,    // Max interleaved streams
    mmap_miss_threshold: u32,
};

pub const FileReadahead = struct {
    state: ReadaheadState,
    start: u64,
    size: u32,
    async_size: u32,
    prev_pos: i64,
    prev_start: u64,
    prev_size: u32,
    pattern: ReadaheadPattern,
    hits: u32,
    misses: u32,
    lookahead_hit: u32,
    config: ReadaheadConfig,
};

pub const ReadaheadPattern = enum(u8) {
    Unknown = 0,
    Sequential = 1,
    RandomSingle = 2,
    InterleaveA = 3,
    InterleaveB = 4,
    Stride = 5,
    Backward = 6,
};

// ============================================================================
// Page Cache
// ============================================================================

pub const AddressSpace = struct {
    host: ?*Inode,
    nr_pages: u64,
    nr_exceptional: u64,
    flags: AddressSpaceFlags,
    a_ops: AddressSpaceOps,
    backing_dev_info: ?*anyopaque,
    private_data: ?*anyopaque,
    wb_err: u32,
    writeback_index: u64,
    i_pages: u64,       // XArray root
};

pub const AddressSpaceFlags = packed struct(u32) {
    nrpages: bool,
    moved: bool,
    has_errors: bool,
    large_folio_support: bool,
    release_always: bool,
    stable_writes: bool,
    _reserved: u26,
};

pub const AddressSpaceOps = struct {
    writepage: ?*const fn (page: *Page, wbc: *WritebackControl) callconv(.C) i32,
    read_folio: ?*const fn (file: ?*anyopaque, folio: *Folio) callconv(.C) i32,
    writepages: ?*const fn (mapping: *AddressSpace, wbc: *WritebackControl) callconv(.C) i32,
    dirty_folio: ?*const fn (mapping: *AddressSpace, folio: *Folio) callconv(.C) bool,
    readahead: ?*const fn (rac: *ReadaheadControl) callconv(.C) void,
    write_begin: ?*const fn (file: ?*anyopaque, mapping: *AddressSpace, pos: i64, len: u32, pagep: **Page) callconv(.C) i32,
    write_end: ?*const fn (file: ?*anyopaque, mapping: *AddressSpace, pos: i64, len: u32, copied: u32, page: *Page) callconv(.C) i32,
    bmap: ?*const fn (mapping: *AddressSpace, block: u64) callconv(.C) u64,
    invalidate_folio: ?*const fn (folio: *Folio, offset: u64, length: u64) callconv(.C) void,
    release_folio: ?*const fn (folio: *Folio, gfp: u32) callconv(.C) bool,
    free_folio: ?*const fn (folio: *Folio) callconv(.C) void,
    direct_IO: ?*const fn (iocb: *Kiocb, iter: *IovIter) callconv(.C) isize,
    migrate_folio: ?*const fn (mapping: *AddressSpace, dst: *Folio, src: *Folio, mode: u32) callconv(.C) i32,
    launder_folio: ?*const fn (folio: *Folio) callconv(.C) i32,
    is_partially_uptodate: ?*const fn (folio: *Folio, from: usize, count: usize) callconv(.C) bool,
    error_remove_folio: ?*const fn (mapping: *AddressSpace, folio: *Folio) callconv(.C) void,
    swap_activate: ?*const fn (sis: *anyopaque, file: *anyopaque, span: *u64) callconv(.C) i32,
    swap_deactivate: ?*const fn (file: *anyopaque) callconv(.C) void,
    swap_rw: ?*const fn (iocb: *Kiocb, iter: *IovIter) callconv(.C) i32,
};

pub const Page = struct {
    flags: PageFlags,
    mapping: ?*AddressSpace,
    index: u64,
    private: u64,
    refcount: i32,
    mapcount: i32,
    lru_prev: ?*Page,
    lru_next: ?*Page,
};

pub const PageFlags = packed struct(u64) {
    locked: bool,
    referenced: bool,
    uptodate: bool,
    dirty: bool,
    lru: bool,
    active: bool,
    workingset: bool,
    waiters: bool,
    error: bool,
    slab: bool,
    owner_priv: bool,
    arch1: bool,
    reserved: bool,
    private: bool,
    private2: bool,
    writeback: bool,
    compound_head: bool,
    compound_tail: bool,
    mappedtodisk: bool,
    reclaim: bool,
    swapbacked: bool,
    unevictable: bool,
    mlocked: bool,
    uncached: bool,
    hwpoison: bool,
    young: bool,
    idle: bool,
    _reserved: u37,
};

pub const Folio = struct {
    flags: PageFlags,
    mapping: ?*AddressSpace,
    index: u64,
    private: u64,
    refcount: i32,
    mapcount: i32,
    order: u8,           // log2(number of pages)
    nr_pages_mapped: u32,
    pincount: i32,
};

// ============================================================================
// Writeback Control
// ============================================================================

pub const WritebackControl = struct {
    nr_to_write: i64,
    pages_skipped: i64,
    range_start: i64,
    range_end: i64,
    range_cyclic: bool,
    for_kupdate: bool,
    for_background: bool,
    tagged_writepages: bool,
    for_reclaim: bool,
    for_sync: bool,
    no_cgroup_owner: bool,
    punt_to_cgroup: bool,
    sync_mode: WritebackSyncMode,
    wb: ?*anyopaque,
    inode: ?*Inode,
    wb_id: i32,
    wb_lcand_id: i32,
    wb_tcand_id: i32,
    wb_bytes: usize,
    wb_lcand_bytes: usize,
    wb_tcand_bytes: usize,
};

pub const WritebackSyncMode = enum(u8) {
    None = 0,
    All = 1,
};

// ============================================================================
// Inode
// ============================================================================

pub const Inode = struct {
    i_mode: u16,
    i_opflags: u16,
    i_uid: u32,
    i_gid: u32,
    i_flags: InodeFlags,
    i_ino: u64,
    i_nlink: u32,
    i_size: i64,
    i_atime: Timespec,
    i_mtime: Timespec,
    i_ctime: Timespec,
    i_blocks: u64,
    i_bytes: u16,
    i_blkbits: u8,
    i_state: InodeState,
    i_rwsem: u64,
    i_op: ?*InodeOps,
    i_fop: ?*FileOps,
    i_sb: ?*SuperBlock,
    i_mapping: ?*AddressSpace,
    i_security: ?*anyopaque,
    i_private: ?*anyopaque,
    i_generation: u32,
    i_version: u64,
    i_count: i32,
    i_writecount: i32,
    i_readcount: i32,
    i_flctx: ?*FileLockContext,
    i_data: AddressSpace,
    i_devices: u64,
    i_pipe: ?*anyopaque,
    i_cdev: ?*anyopaque,
    i_link: [256]u8,
    i_dir_seq: u32,
    i_rdev: u32,
};

pub const InodeFlags = packed struct(u32) {
    sync: bool,
    immutable: bool,
    append: bool,
    nodump: bool,
    noatime: bool,
    dirsync: bool,
    topdir: bool,
    huge_file: bool,
    notail: bool,
    journal_data: bool,
    encrypt: bool,
    casefold: bool,
    verity: bool,
    dax: bool,
    _reserved: u18,
};

pub const InodeState = packed struct(u32) {
    new: bool,
    dirty_sync: bool,
    dirty_datasync: bool,
    dirty_pages: bool,
    will_free: bool,
    freeing: bool,
    clear: bool,
    hash: bool,
    sync: bool,
    referenced: bool,
    dontcache: bool,
    io_dontcache: bool,
    pinning_fscache: bool,
    wb_switch: bool,
    _reserved: u18,
};

pub const InodeOps = struct {
    lookup: ?*const fn (dir: *Inode, dentry: *Dentry, flags: u32) callconv(.C) ?*Dentry,
    get_link: ?*const fn (dentry: *Dentry, inode: *Inode, delayed: ?*anyopaque) callconv(.C) ?[*:0]const u8,
    permission: ?*const fn (user_ns: *anyopaque, inode: *Inode, mask: i32) callconv(.C) i32,
    get_inode_acl: ?*const fn (inode: *Inode, acl_type: i32, cached: bool) callconv(.C) ?*anyopaque,
    readlink: ?*const fn (dentry: *Dentry, buf: [*]u8, buflen: i32) callconv(.C) i32,
    create: ?*const fn (user_ns: *anyopaque, dir: *Inode, dentry: *Dentry, mode: u16, excl: bool) callconv(.C) i32,
    link: ?*const fn (old_dentry: *Dentry, dir: *Inode, new_dentry: *Dentry) callconv(.C) i32,
    unlink: ?*const fn (dir: *Inode, dentry: *Dentry) callconv(.C) i32,
    symlink: ?*const fn (user_ns: *anyopaque, dir: *Inode, dentry: *Dentry, symname: [*:0]const u8) callconv(.C) i32,
    mkdir: ?*const fn (user_ns: *anyopaque, dir: *Inode, dentry: *Dentry, mode: u16) callconv(.C) i32,
    rmdir: ?*const fn (dir: *Inode, dentry: *Dentry) callconv(.C) i32,
    mknod: ?*const fn (user_ns: *anyopaque, dir: *Inode, dentry: *Dentry, mode: u16, dev: u32) callconv(.C) i32,
    rename: ?*const fn (user_ns: *anyopaque, old_dir: *Inode, old_dentry: *Dentry, new_dir: *Inode, new_dentry: *Dentry, flags: u32) callconv(.C) i32,
    setattr: ?*const fn (user_ns: *anyopaque, dentry: *Dentry, attr: *InodeAttr) callconv(.C) i32,
    getattr: ?*const fn (user_ns: *anyopaque, path: *anyopaque, stat: *anyopaque, request_mask: u32, query_flags: u32) callconv(.C) i32,
    listxattr: ?*const fn (dentry: *Dentry, list: [*]u8, size: usize) callconv(.C) isize,
    fiemap: ?*const fn (inode: *Inode, fieinfo: *anyopaque, start: u64, len: u64) callconv(.C) i32,
    update_time: ?*const fn (inode: *Inode, time: *Timespec, flags: i32) callconv(.C) i32,
    atomic_open: ?*const fn (dir: *Inode, dentry: *Dentry, file: *anyopaque, open_flag: u32, create_mode: u16) callconv(.C) i32,
    tmpfile: ?*const fn (user_ns: *anyopaque, dir: *Inode, file: *anyopaque, mode: u16) callconv(.C) i32,
    fileattr_set: ?*const fn (user_ns: *anyopaque, dentry: *Dentry, fa: *anyopaque) callconv(.C) i32,
    fileattr_get: ?*const fn (dentry: *Dentry, fa: *anyopaque) callconv(.C) i32,
    get_offset_ctx: ?*const fn (inode: *Inode) callconv(.C) ?*anyopaque,
};

pub const InodeAttr = struct {
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

// ============================================================================
// Dentry Cache
// ============================================================================

pub const Dentry = struct {
    d_flags: DentryFlags,
    d_parent: ?*Dentry,
    d_name: QStr,
    d_inode: ?*Inode,
    d_iname: [40]u8,
    d_op: ?*DentryOps,
    d_sb: ?*SuperBlock,
    d_time: u64,
    d_fsdata: ?*anyopaque,
    d_lockref: i64,        // Combined lock and refcount
    d_lru_prev: ?*Dentry,
    d_lru_next: ?*Dentry,
    d_child_prev: ?*Dentry,
    d_child_next: ?*Dentry,
    d_subdirs: ?*Dentry,
};

pub const QStr = struct {
    hash: u32,
    len: u32,
    name: [256]u8,
};

pub const DentryFlags = packed struct(u32) {
    mounted: bool,
    autodir: bool,
    fallthrough: bool,
    disconnected: bool,
    referenced: bool,
    lru_maintain: bool,
    shrink: bool,
    op_hash: bool,
    op_compare: bool,
    op_revalidate: bool,
    op_delete: bool,
    op_prune: bool,
    is_negative: bool,
    noretain: bool,
    _reserved: u18,
};

pub const DentryOps = struct {
    d_revalidate: ?*const fn (dentry: *Dentry, flags: u32) callconv(.C) i32,
    d_weak_revalidate: ?*const fn (dentry: *Dentry, flags: u32) callconv(.C) i32,
    d_hash: ?*const fn (dentry: *const Dentry, name: *QStr) callconv(.C) i32,
    d_compare: ?*const fn (dentry: *const Dentry, wh_len: u32, wh_name: [*]const u8, name: *const QStr) callconv(.C) i32,
    d_delete: ?*const fn (dentry: *const Dentry) callconv(.C) i32,
    d_iput: ?*const fn (dentry: *Dentry, inode: *Inode) callconv(.C) void,
    d_dname: ?*const fn (dentry: *Dentry, buf: [*]u8, buflen: i32) callconv(.C) [*]u8,
    d_automount: ?*const fn (path: *anyopaque) callconv(.C) ?*anyopaque,
    d_manage: ?*const fn (path: *const anyopaque, rcu_walk: bool) callconv(.C) i32,
    d_real: ?*const fn (dentry: *Dentry, inode: *const Inode) callconv(.C) ?*Dentry,
    d_prune: ?*const fn (dentry: *Dentry) callconv(.C) void,
    d_init: ?*const fn (dentry: *Dentry) callconv(.C) i32,
    d_release: ?*const fn (dentry: *Dentry) callconv(.C) void,
};

// ============================================================================
// File Operations & Handle
// ============================================================================

pub const FileOps = struct {
    owner: ?*anyopaque,
    llseek: ?*const fn (file: *File, offset: i64, whence: i32) callconv(.C) i64,
    read: ?*const fn (file: *File, buf: [*]u8, count: usize, pos: *i64) callconv(.C) isize,
    write: ?*const fn (file: *File, buf: [*]const u8, count: usize, pos: *i64) callconv(.C) isize,
    read_iter: ?*const fn (iocb: *Kiocb, to: *IovIter) callconv(.C) isize,
    write_iter: ?*const fn (iocb: *Kiocb, from: *IovIter) callconv(.C) isize,
    iopoll: ?*const fn (iocb: *Kiocb, bio: ?*anyopaque, flags: u32) callconv(.C) i32,
    iterate_shared: ?*const fn (file: *File, ctx: *DirContext) callconv(.C) i32,
    poll: ?*const fn (file: *File, wait: *anyopaque) callconv(.C) u32,
    unlocked_ioctl: ?*const fn (file: *File, cmd: u32, arg: u64) callconv(.C) i64,
    compat_ioctl: ?*const fn (file: *File, cmd: u32, arg: u64) callconv(.C) i64,
    mmap: ?*const fn (file: *File, vma: *anyopaque) callconv(.C) i32,
    open: ?*const fn (inode: *Inode, file: *File) callconv(.C) i32,
    flush: ?*const fn (file: *File, id: ?*anyopaque) callconv(.C) i32,
    release: ?*const fn (inode: *Inode, file: *File) callconv(.C) i32,
    fsync: ?*const fn (file: *File, start: i64, end: i64, datasync: i32) callconv(.C) i32,
    fasync: ?*const fn (fd: i32, file: *File, on: i32) callconv(.C) i32,
    lock: ?*const fn (file: *File, cmd: i32, fl: *FileLock) callconv(.C) i32,
    get_unmapped_area: ?*const fn (file: *File, addr: u64, len: u64, pgoff: u64, flags: u64) callconv(.C) u64,
    check_flags: ?*const fn (flags: i32) callconv(.C) i32,
    flock: ?*const fn (file: *File, cmd: i32, fl: *FileLock) callconv(.C) i32,
    splice_write: ?*const fn (pipe: *anyopaque, out: *File, ppos: *i64, len: usize, flags: u32) callconv(.C) isize,
    splice_read: ?*const fn (in_file: *File, ppos: *i64, pipe: *anyopaque, len: usize, flags: u32) callconv(.C) isize,
    splice_eof: ?*const fn (file: *File) callconv(.C) void,
    setlease: ?*const fn (file: *File, arg: i64, lease: *?*anyopaque, priv: ?*?*anyopaque) callconv(.C) i32,
    fallocate: ?*const fn (file: *File, mode: i32, offset: i64, len: i64) callconv(.C) i64,
    show_fdinfo: ?*const fn (m: *anyopaque, file: *File) callconv(.C) void,
    copy_file_range: ?*const fn (src: *File, off_in: *i64, dst: *File, off_out: *i64, len: usize, flags: u32) callconv(.C) isize,
    remap_file_range: ?*const fn (src: *File, loff_in: u64, dst: *File, loff_out: u64, count: u64, remap_flags: u32) callconv(.C) i64,
    fadvise: ?*const fn (file: *File, offset: i64, len: i64, advice: i32) callconv(.C) i32,
    uring_cmd: ?*const fn (ioucmd: *anyopaque, issue_flags: u32) callconv(.C) i32,
    uring_cmd_iopoll: ?*const fn (ioucmd: *anyopaque, bio: ?*anyopaque, flags: u32) callconv(.C) i32,
};

pub const File = struct {
    f_path: FilePath,
    f_inode: ?*Inode,
    f_op: ?*FileOps,
    f_flags: u32,
    f_mode: u32,
    f_pos: i64,
    f_owner: FileOwner,
    f_cred: ?*anyopaque,
    f_ra: FileReadahead,
    f_version: u64,
    f_security: ?*anyopaque,
    private_data: ?*anyopaque,
    f_mapping: ?*AddressSpace,
    f_wb_err: u32,
    f_sb_err: u32,
};

pub const FilePath = struct {
    mnt: ?*anyopaque,
    dentry: ?*Dentry,
};

pub const FileOwner = struct {
    pid: i32,
    pid_type: i32,
    uid: u32,
    euid: u32,
    signum: i32,
};

pub const Kiocb = struct {
    ki_filp: ?*File,
    ki_pos: i64,
    ki_complete: ?*const fn (iocb: *Kiocb, res: i64) callconv(.C) void,
    ki_flags: KiocbFlags,
    ki_ioprio: u16,
    private_data: ?*anyopaque,
};

pub const KiocbFlags = packed struct(u32) {
    sync: bool,
    append: bool,
    dsync: bool,
    iopoll: bool,
    nowait: bool,
    buffered: bool,
    noio: bool,
    _reserved: u25,
};

pub const IovIter = struct {
    iter_type: IovIterType,
    copy_mc: bool,
    nofault: bool,
    data_source: bool,
    user_backed: bool,
    count: usize,
    iov_offset: usize,
    nr_segs: u64,
};

pub const IovIterType = enum(u8) {
    Iovec = 0,
    Kvec = 1,
    Bvec = 2,
    Xarray = 3,
    Pipe = 4,
    Ubuf = 5,
};

pub const DirContext = struct {
    actor: ?*const fn (ctx: *DirContext, name: [*]const u8, namelen: i32, offset: i64, ino: u64, d_type: u8) callconv(.C) bool,
    pos: i64,
};

// ============================================================================
// File Locking
// ============================================================================

pub const FileLock = struct {
    fl_blocker: ?*FileLock,
    fl_next: ?*FileLock,
    fl_link_cpu: i32,
    fl_owner: ?*anyopaque,
    fl_flags: FileFlLockFlags,
    fl_type: u8,           // F_RDLCK, F_WRLCK, F_UNLCK
    fl_pid: i32,
    fl_start: i64,
    fl_end: i64,
    fl_ops: ?*FileLockOps,
    fl_lmops: ?*LockManagerOps,
    fl_nspid: ?*anyopaque,
    fl_fasync: ?*anyopaque,
    fl_break_time: u64,
    fl_downgrade_time: u64,
    fl_file: ?*File,
};

pub const FileFlLockFlags = packed struct(u32) {
    posix: bool,
    flock: bool,
    deleg: bool,          // Delegation
    access: bool,
    exists: bool,
    lease: bool,
    close: bool,
    sleep: bool,
    downgrade_pending: bool,
    unlock_pending: bool,
    ofdlck: bool,
    layout: bool,
    reclaim: bool,
    _reserved: u19,
};

pub const FileLockOps = struct {
    fl_copy_lock: ?*const fn (new: *FileLock, fl: *FileLock) callconv(.C) void,
    fl_release_private: ?*const fn (fl: *FileLock) callconv(.C) void,
};

pub const LockManagerOps = struct {
    lm_mod_owner: ?*anyopaque,
    lm_notify: ?*const fn (fl: *FileLock) callconv(.C) void,
    lm_grant: ?*const fn (fl: *FileLock, owner: ?*anyopaque) callconv(.C) i32,
    lm_break: ?*const fn (fl: *FileLock) callconv(.C) bool,
    lm_change: ?*const fn (fl: *FileLock, arg: i32, list: ?*anyopaque) callconv(.C) i32,
    lm_setup: ?*const fn (fl: *FileLock, flags: ?*?*anyopaque) callconv(.C) void,
    lm_breaker_owns_lease: ?*const fn (fl: *FileLock) callconv(.C) bool,
    lm_lock_expirable: ?*const fn (fl: *FileLock) callconv(.C) bool,
    lm_expire_lock: ?*const fn () callconv(.C) void,
};

pub const FileLockContext = struct {
    flc_flock: ?*FileLock,
    flc_posix: ?*FileLock,
    flc_lease: ?*FileLock,
    flc_flock_cnt: i32,
    flc_posix_cnt: i32,
    flc_lease_cnt: i32,
};

// ============================================================================
// Super Block
// ============================================================================

pub const SuperBlock = struct {
    s_type: ?*anyopaque,
    s_op: ?*SuperOps,
    s_flags: u64,
    s_magic: u64,
    s_root: ?*Dentry,
    s_bdev: ?*anyopaque,
    s_maxbytes: i64,
    s_blocksize: u64,
    s_blocksize_bits: u8,
    s_time_gran: u32,
    s_time_min: i64,
    s_time_max: i64,
    s_id: [32]u8,
    s_uuid: [16]u8,
    s_fs_info: ?*anyopaque,
    s_count: i32,
    s_active: i32,
    s_security: ?*anyopaque,
    s_xattr: ?*anyopaque,
    s_d_op: ?*DentryOps,
    s_export_op: ?*anyopaque,
    s_iflags: u32,
    s_encoding: ?*anyopaque,
    s_encoding_flags: u16,
    s_stack_depth: i32,
};

pub const SuperOps = struct {
    alloc_inode: ?*const fn (sb: *SuperBlock) callconv(.C) ?*Inode,
    destroy_inode: ?*const fn (inode: *Inode) callconv(.C) void,
    free_inode: ?*const fn (inode: *Inode) callconv(.C) void,
    dirty_inode: ?*const fn (inode: *Inode, flags: i32) callconv(.C) void,
    write_inode: ?*const fn (inode: *Inode, wbc: *WritebackControl) callconv(.C) i32,
    drop_inode: ?*const fn (inode: *Inode) callconv(.C) i32,
    evict_inode: ?*const fn (inode: *Inode) callconv(.C) void,
    put_super: ?*const fn (sb: *SuperBlock) callconv(.C) void,
    sync_fs: ?*const fn (sb: *SuperBlock, wait: i32) callconv(.C) i32,
    freeze_super: ?*const fn (sb: *SuperBlock, who: i32) callconv(.C) i32,
    freeze_fs: ?*const fn (sb: *SuperBlock) callconv(.C) i32,
    thaw_super: ?*const fn (sb: *SuperBlock, who: i32) callconv(.C) i32,
    unfreeze_fs: ?*const fn (sb: *SuperBlock) callconv(.C) i32,
    statfs: ?*const fn (dentry: *Dentry, buf: *Kstatfs) callconv(.C) i32,
    remount_fs: ?*const fn (sb: *SuperBlock, flags: *i32, data: *u8) callconv(.C) i32,
    umount_begin: ?*const fn (sb: *SuperBlock) callconv(.C) void,
    show_options: ?*const fn (m: *anyopaque, root: *Dentry) callconv(.C) i32,
    show_devname: ?*const fn (m: *anyopaque, root: *Dentry) callconv(.C) i32,
    show_path: ?*const fn (m: *anyopaque, root: *Dentry) callconv(.C) i32,
    show_stats: ?*const fn (m: *anyopaque, root: *Dentry) callconv(.C) i32,
    nr_cached_objects: ?*const fn (sb: *SuperBlock, sc: *anyopaque) callconv(.C) i64,
    free_cached_objects: ?*const fn (sb: *SuperBlock, sc: *anyopaque) callconv(.C) i64,
    shutdown: ?*const fn (sb: *SuperBlock) callconv(.C) void,
};

pub const Kstatfs = struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

pub const Timespec = struct {
    tv_sec: i64,
    tv_nsec: i64,
};

// ============================================================================
// Manager
// ============================================================================

pub const ReadaheadCacheManager = struct {
    total_readahead_pages: u64,
    total_cache_hits: u64,
    total_cache_misses: u64,
    total_writeback_pages: u64,
    total_inodes_allocated: u64,
    total_dentries_allocated: u64,
    total_file_locks: u32,
    initialized: bool,

    pub fn init() ReadaheadCacheManager {
        return .{
            .total_readahead_pages = 0,
            .total_cache_hits = 0,
            .total_cache_misses = 0,
            .total_writeback_pages = 0,
            .total_inodes_allocated = 0,
            .total_dentries_allocated = 0,
            .total_file_locks = 0,
            .initialized = true,
        };
    }
};
