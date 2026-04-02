// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - File Locking, Quota, Direct I/O Subsystem
// Complete POSIX/flock/OFD locks, disk quota, direct I/O,
// readahead, lease/delegation, file sealing

const std = @import("std");

// ============================================================================
// File Lock Types
// ============================================================================

pub const FileLockCmd = enum(u32) {
    GetLk = 5,          // F_GETLK
    SetLk = 6,          // F_SETLK
    SetLkW = 7,         // F_SETLKW
    GetLk64 = 12,       // F_GETLK64
    SetLk64 = 13,       // F_SETLK64
    SetLkW64 = 14,      // F_SETLKW64
    OfdGetLk = 36,      // F_OFD_GETLK
    OfdSetLk = 37,      // F_OFD_SETLK
    OfdSetLkW = 38,     // F_OFD_SETLKW
};

pub const FileLockType = enum(u16) {
    ReadLock = 0,        // F_RDLCK
    WriteLock = 1,       // F_WRLCK
    Unlock = 2,          // F_UNLCK
};

pub const FlockOperation = packed struct(u32) {
    shared: bool = false,    // LOCK_SH
    exclusive: bool = false, // LOCK_EX
    nonblock: bool = false,  // LOCK_NB
    unlock: bool = false,    // LOCK_UN
    _reserved: u28 = 0,
};

pub const FlockStruct = struct {
    l_type: FileLockType,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
};

pub const FileLock = struct {
    fl_blocker: ?*FileLock,
    fl_next: ?*FileLock,
    fl_link: u64,           // hlist_node
    fl_blocked: u64,        // list_head - waiters
    fl_owner: u64,          // fl_owner_t
    fl_flags: FileLockFlags,
    fl_type: FileLockType,
    fl_pid: i32,
    fl_link_cpu: i32,
    fl_wait: u64,           // wait_queue_head_t
    fl_file: u64,           // struct file *
    fl_start: i64,
    fl_end: i64,
    fl_fasync: u64,
    fl_break_time: u64,
    fl_downgrade_time: u64,
    fl_ops: ?*const FileLockOps,
    fl_lmops: ?*const LockManagerOps,
    fl_nspid: u64,          // struct pid *
};

pub const FileLockFlags = packed struct(u32) {
    posix: bool = false,
    flock: bool = false,
    deleg: bool = false,
    access: bool = false,
    exists: bool = false,
    lease: bool = false,
    close: bool = false,
    sleep: bool = false,
    downgrade_pending: bool = false,
    unlock_pending: bool = false,
    ofdlocks: bool = false,
    layout: bool = false,
    _reserved: u20 = 0,
};

pub const FileLockOps = struct {
    fl_copy_lock: ?*const fn (*FileLock, *const FileLock) void,
    fl_release_private: ?*const fn (*FileLock) void,
};

pub const LockManagerOps = struct {
    lm_compare_owner: ?*const fn (*const FileLock, *const FileLock) bool,
    lm_owner_key: ?*const fn (*const FileLock) u64,
    lm_notify: ?*const fn (*FileLock) void,
    lm_grant: ?*const fn (*FileLock, i32) void,
    lm_break: ?*const fn (*FileLock) bool,
    lm_change: ?*const fn (*FileLock, i32, u64) i32,
    lm_setup: ?*const fn (*FileLock, *const fn (u64) void) void,
    lm_breaker_owns_lease: ?*const fn (*const FileLock) bool,
    lm_lock_expirable: ?*const fn (*const FileLock) bool,
    lm_expire_lock: ?*const fn () void,
};

// ============================================================================
// Lease / Delegation
// ============================================================================

pub const LeaseType = enum(u8) {
    Read = 0,      // F_RDLCK
    Write = 1,     // F_WRLCK
    Unlock = 2,    // F_UNLCK
};

pub const LeaseFlags = packed struct(u32) {
    layout: bool = false,
    deleg: bool = false,
    _reserved: u30 = 0,
};

pub const LeaseState = enum(u8) {
    None = 0,
    Read = 1,
    Write = 2,
    Breaking = 3,
};

pub const NfsOpenDelegation = struct {
    delegation_type: LeaseType,
    stateid: [16]u8,      // NFS stateid
    recall: bool,
    space_limit: u64,
    ace: [64]u8,
};

// ============================================================================
// File Sealing (memfd)
// ============================================================================

pub const FileSeal = packed struct(u32) {
    seal: bool = false,            // F_SEAL_SEAL
    shrink: bool = false,          // F_SEAL_SHRINK
    grow: bool = false,            // F_SEAL_GROW
    write: bool = false,           // F_SEAL_WRITE
    future_write: bool = false,    // F_SEAL_FUTURE_WRITE
    exec: bool = false,            // F_SEAL_EXEC
    _reserved: u26 = 0,
};

// ============================================================================
// Disk Quota System
// ============================================================================

pub const QuotaType = enum(u8) {
    UserQuota = 0,       // USRQUOTA
    GroupQuota = 1,      // GRPQUOTA
    ProjectQuota = 2,    // PRJQUOTA
};

pub const MAX_QUOTA_TYPES = 3;

pub const QuotaFormat = enum(u32) {
    Vfs_Old = 1,
    Vfs_V0 = 2,
    Vfs_V1 = 3,
    Ocfs2 = 4,
};

pub const QuotaFlags = packed struct(u32) {
    usage_enabled: bool = false,
    limits_enabled: bool = false,
    nocharge: bool = false,
    negative: bool = false,
    sync: bool = false,
    _reserved: u27 = 0,
};

pub const DqBlk = struct {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace: u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes: u64,
    dqb_btime: u64,           // Block grace period (seconds)
    dqb_itime: u64,           // Inode grace period (seconds)
    dqb_valid: DqBlkValid,
};

pub const DqBlkValid = packed struct(u32) {
    bhardlimit: bool = false,  // QIF_BLIMITS
    bsoftlimit: bool = false,
    space: bool = false,       // QIF_SPACE
    ihardlimit: bool = false,  // QIF_ILIMITS
    isoftlimit: bool = false,
    inodes: bool = false,      // QIF_INODES
    btime: bool = false,       // QIF_BTIME
    itime: bool = false,       // QIF_ITIME
    _reserved: u24 = 0,
};

pub const DqInfo = struct {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags: u32,
    dqi_valid: DqInfoValid,
};

pub const DqInfoValid = packed struct(u32) {
    bgrace: bool = false,     // IIF_BGRACE
    igrace: bool = false,     // IIF_IGRACE
    flags: bool = false,      // IIF_FLAGS
    _reserved: u29 = 0,
};

pub const QuotaInfo = struct {
    types: [MAX_QUOTA_TYPES]MemDqInfo,
    flags: u32,
    only_twostate: bool,
};

pub const MemDqInfo = struct {
    dqi_format: ?*const QuotaFormatOps,
    dqi_fmt_id: u32,
    dqi_dirty_list: u64,      // list_head
    dqi_flags: u32,
    dqi_bgrace: u32,
    dqi_igrace: u32,
    dqi_max_spc_limit: u64,
    dqi_max_ino_limit: u64,
    dqi_priv: u64,
};

pub const QuotaFormatOps = struct {
    check_quota_file: ?*const fn (u64, i32) i32,
    read_file_info: ?*const fn (u64, i32) i32,
    write_file_info: ?*const fn (u64, i32) i32,
    free_file_info: ?*const fn (u64, i32) i32,
    read_dqblk: ?*const fn (u64) i32,
    commit_dqblk: ?*const fn (u64) i32,
    release_dqblk: ?*const fn (u64) i32,
    get_next_id: ?*const fn (u64, *u32) i32,
};

pub const QuotaOps = struct {
    quota_on: ?*const fn (u64, i32, i32, u64) i32,
    quota_off: ?*const fn (u64, i32) i32,
    quota_enable: ?*const fn (u64, u32) i32,
    quota_disable: ?*const fn (u64, u32) i32,
    quota_sync: ?*const fn (u64, i32) i32,
    set_info: ?*const fn (u64, i32, *DqInfo) i32,
    get_dqblk: ?*const fn (u64, u64, *DqBlk) i32,
    get_nextdqblk: ?*const fn (u64, u64, *DqBlk) i32,
    set_dqblk: ?*const fn (u64, u64, *DqBlk) i32,
    get_state: ?*const fn (u64, u64) i32,
    rm_xquota: ?*const fn (u64, u32) i32,
};

// ============================================================================
// Direct I/O
// ============================================================================

pub const DioFlags = packed struct(u32) {
    locking: bool = false,       // DIO_LOCKING
    skip_holes: bool = false,
    no_dma: bool = false,
    async_extend: bool = false,
    unwritten: bool = false,
    _reserved: u27 = 0,
};

pub const DioIodone = enum(u8) {
    None = 0,
    BlockWritten = 1,
    EndIo = 2,
};

pub const DioState = struct {
    flags: DioFlags,
    rw: u8,
    inode: u64,
    start_zero_done: u8,
    pages_in_io: u64,
    size: i64,
    block_in_file: i64,
    blocks_available: u32,
    cur_page_offset: u32,
    cur_page_len: u32,
    cur_page_block: u64,
    final_block_in_request: i64,
    result: i32,
    logical_offset_in_bio: u64,
    bio_bytes: u64,
    page_errors: u32,
    is_async: bool,
    io_error: i32,
    total_pages: u64,
};

pub const IoMap = struct {
    addr: u64,
    length: u64,
    flags: IoMapFlags,
    bdev: u64,
    dax_dev: u64,
    offset: u64,
};

pub const IoMapFlags = packed struct(u32) {
    new: bool = false,
    dirty: bool = false,
    shared: bool = false,
    merged: bool = false,
    buffer_new: bool = false,
    buffer_head: bool = false,
    unwritten: bool = false,
    _reserved: u25 = 0,
};

pub const IoMapOps = struct {
    iomap_begin: ?*const fn (u64, i64, i64, u32, *IoMap, *IoMap) i32,
    iomap_end: ?*const fn (u64, i64, i64, i64, u32, *IoMap) i32,
};

// ============================================================================
// Readahead
// ============================================================================

pub const ReadaheadControl = struct {
    file: u64,           // struct file *
    mapping: u64,        // struct address_space *
    _index: u64,         // starting page index
    _nr_pages: u32,      // total pages in readahead window
    _batch_count: u32,
    _workingset: bool,
    _nr_pages_orig: u32, // original nr_pages before extension
};

pub const FileRa_State = struct {
    start: u64,          // Current readahead start
    size: u32,           // Current readahead size
    async_size: u32,     // Async readahead size
    ra_pages: u32,       // Maximum readahead pages
    mmap_miss: u32,      // Cache miss count for mmap
    prev_pos: i64,       // Previous file position
};

pub const ReadaheadConfig = struct {
    default_backing_dev_ra_pages: u32,
    dirty_ratio: u32,             // Percentage
    dirty_background_ratio: u32,  // Percentage
    dirty_writeback_centisecs: u32,
    dirty_expire_centisecs: u32,
    vfs_cache_pressure: u32,
    page_cluster: u32,
    min_free_kbytes: u32,
    watermark_scale_factor: u32,
};

// ============================================================================
// Writeback Control
// ============================================================================

pub const WritebBackSync = enum(u8) {
    None = 0,
    All = 1,
};

pub const WbcFlags = packed struct(u32) {
    tagged_writepages: bool = false,
    sync_all: bool = false,
    for_kupdate: bool = false,
    for_background: bool = false,
    for_reclaim: bool = false,
    range_cyclic: bool = false,
    no_cgroup_owner: bool = false,
    _reserved: u25 = 0,
};

pub const WritebackControl = struct {
    nr_to_write: i64,
    pages_skipped: i64,
    range_start: i64,
    range_end: i64,
    sync_mode: WritebBackSync,
    flags: WbcFlags,
    wb: u64,              // struct bdi_writeback *
    inode: u64,           // struct inode *
    wb_id: u64,
    wb_lcand_id: u64,
    wb_tcand_id: u64,
    wb_bytes: u64,
    wb_lcand_bytes: u64,
    wb_tcand_bytes: u64,
};

// ============================================================================
// Writeback Stats
// ============================================================================

pub const WritebackStats = struct {
    nr_dirty: u64,
    nr_writeback: u64,
    nr_dirtied: u64,
    nr_written: u64,
    dirty_thresh: u64,
    dirty_bg_thresh: u64,
    wb_dirty: u64,
    wb_thresh: u64,
    wb_bg_thresh: u64,
};

// ============================================================================
// Lock/Quota/DIO Manager
// ============================================================================

pub const FileLockQuotaManager = struct {
    total_posix_locks: u64,
    total_flock_locks: u64,
    total_ofd_locks: u64,
    total_leases: u64,
    total_delegations: u64,
    total_lock_waits: u64,
    total_deadlock_detections: u64,
    total_quota_checks: u64,
    total_quota_over_softlimit: u64,
    total_quota_over_hardlimit: u64,
    total_direct_io_reads: u64,
    total_direct_io_writes: u64,
    total_direct_io_bytes: u64,
    total_readahead_pages: u64,
    total_readahead_hits: u64,
    total_writeback_pages: u64,
    ra_config: ReadaheadConfig,
    wb_stats: WritebackStats,
    initialized: bool,

    pub fn init() FileLockQuotaManager {
        return .{
            .total_posix_locks = 0,
            .total_flock_locks = 0,
            .total_ofd_locks = 0,
            .total_leases = 0,
            .total_delegations = 0,
            .total_lock_waits = 0,
            .total_deadlock_detections = 0,
            .total_quota_checks = 0,
            .total_quota_over_softlimit = 0,
            .total_quota_over_hardlimit = 0,
            .total_direct_io_reads = 0,
            .total_direct_io_writes = 0,
            .total_direct_io_bytes = 0,
            .total_readahead_pages = 0,
            .total_readahead_hits = 0,
            .total_writeback_pages = 0,
            .ra_config = .{
                .default_backing_dev_ra_pages = 128,
                .dirty_ratio = 20,
                .dirty_background_ratio = 10,
                .dirty_writeback_centisecs = 500,
                .dirty_expire_centisecs = 3000,
                .vfs_cache_pressure = 100,
                .page_cluster = 3,
                .min_free_kbytes = 67584,
                .watermark_scale_factor = 10,
            },
            .wb_stats = std.mem.zeroes(WritebackStats),
            .initialized = true,
        };
    }
};
