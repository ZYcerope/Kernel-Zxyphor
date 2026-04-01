// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced Page Cache: Writeback, Readahead, Folio, Memory-Mapped I/O

const std = @import("std");

// ============================================================================
// Page Cache Core
// ============================================================================

pub const PAGE_SHIFT: u6 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = ~(PAGE_SIZE - 1);
pub const PAGES_PER_HUGE: usize = 512; // 2MB huge page

// Page flags for page cache
pub const PageCacheFlags = packed struct(u32) {
    locked: bool = false,
    referenced: bool = false,
    uptodate: bool = false,
    dirty: bool = false,
    writeback: bool = false,
    reclaim: bool = false,
    active: bool = false,
    slab: bool = false,
    private: bool = false,
    private2: bool = false,
    mappedtodisk: bool = false,
    swapbacked: bool = false,
    unevictable: bool = false,
    mlocked: bool = false,
    workingset: bool = false,
    error: bool = false,
    owner_priv1: bool = false,
    large_rmappable: bool = false,
    readahead: bool = false,
    young: bool = false,
    idle: bool = false,
    // Zxyphor extensions
    compressed: bool = false,
    encrypted: bool = false,
    dedup: bool = false,
    _reserved: u8 = 0,
};

// ============================================================================
// Folio (Compound page abstraction - Linux 5.16+)
// ============================================================================

pub const FolioOrder = enum(u8) {
    order_0 = 0,     // 4KB
    order_1 = 1,     // 8KB
    order_2 = 2,     // 16KB
    order_3 = 3,     // 32KB
    order_4 = 4,     // 64KB
    order_9 = 9,     // 2MB (huge page)
    order_18 = 18,   // 1GB (gigantic page)
};

pub const Folio = struct {
    // Core fields
    flags: PageCacheFlags,
    mapping: ?*AddressSpace,
    index: u64,             // Page cache index (in PAGE_SIZE units)
    private_data: u64,
    // Reference counting
    refcount: u32,
    mapcount: u32,
    // LRU
    lru_prev: ?*Folio,
    lru_next: ?*Folio,
    // Compound page info
    order: u8,
    // Memory cgroup
    memcg_data: u64,
    // Physical frame number
    pfn: u64,

    pub fn nr_pages(self: *const Folio) u32 {
        return @as(u32, 1) << self.order;
    }

    pub fn size(self: *const Folio) usize {
        return @as(usize, self.nr_pages()) * PAGE_SIZE;
    }

    pub fn is_large(self: *const Folio) bool {
        return self.order > 0;
    }

    pub fn is_huge(self: *const Folio) bool {
        return self.order >= 9;
    }

    pub fn get(self: *Folio) void {
        self.refcount += 1;
    }

    pub fn put(self: *Folio) bool {
        self.refcount -= 1;
        return self.refcount == 0;
    }

    pub fn set_dirty(self: *Folio) void {
        self.flags.dirty = true;
    }

    pub fn clear_dirty(self: *Folio) void {
        self.flags.dirty = false;
    }

    pub fn set_writeback(self: *Folio) void {
        self.flags.writeback = true;
    }

    pub fn end_writeback(self: *Folio) void {
        self.flags.writeback = false;
    }

    pub fn lock(self: *Folio) void {
        self.flags.locked = true;
    }

    pub fn unlock(self: *Folio) void {
        self.flags.locked = false;
    }

    pub fn mark_uptodate(self: *Folio) void {
        self.flags.uptodate = true;
    }

    pub fn mark_error(self: *Folio) void {
        self.flags.error = true;
    }

    pub fn test_set_writeback(self: *Folio) bool {
        const was = self.flags.writeback;
        self.flags.writeback = true;
        return was;
    }
};

// ============================================================================
// Address Space (inode page cache)
// ============================================================================

pub const AddressSpaceOps = struct {
    writepage: ?*const fn (*Folio) i32,
    readahead: ?*const fn (*ReadaheadControl) void,
    write_begin: ?*const fn (*AddressSpace, u64, u32) i32,
    write_end: ?*const fn (*AddressSpace, u64, u32) i32,
    dirty_folio: ?*const fn (*AddressSpace, *Folio) bool,
    release_folio: ?*const fn (*Folio, u32) bool,
    free_folio: ?*const fn (*Folio) void,
    direct_io: ?*const fn (u32, u64, u64) i64,
    migrate_folio: ?*const fn (*AddressSpace, *Folio, *Folio, u32) i32,
    launder_folio: ?*const fn (*Folio) i32,
    is_partially_uptodate: ?*const fn (*Folio, usize, usize) bool,
    error_remove_folio: ?*const fn (*AddressSpace, *Folio) void,
    swap_activate: ?*const fn (*anyopaque, *anyopaque, *u64) i32,
    swap_deactivate: ?*const fn (*anyopaque) void,
    swap_rw: ?*const fn (*anyopaque, *anyopaque) i32,
};

pub const XA_CHUNK_SHIFT: u5 = 6;
pub const XA_CHUNK_SIZE: usize = 1 << XA_CHUNK_SHIFT;

pub const XArrayNode = struct {
    shift: u8,
    offset: u8,
    count: u8,
    nr_values: u8,
    parent: ?*XArrayNode,
    slots: [XA_CHUNK_SIZE]?*anyopaque,
};

pub const AddressSpace = struct {
    // XArray-based page cache (replaces radix tree since Linux 4.20)
    xa_root: ?*XArrayNode,
    nr_pages: u64,
    // Writeback tracking
    nr_dirty: u64,
    nr_writeback: u64,
    nr_unstable_nfs: u64,
    // Operations
    ops: *const AddressSpaceOps,
    // Flags
    flags: u32,
    // GFP mask for allocations
    gfp_mask: u32,
    // Private data (filesystem-specific)
    private_data: ?*anyopaque,
    // Write error tracking
    wb_err: u32,
    // Inode back-reference
    host: ?*anyopaque, // *Inode

    pub fn init(ops: *const AddressSpaceOps) AddressSpace {
        return AddressSpace{
            .xa_root = null,
            .nr_pages = 0,
            .nr_dirty = 0,
            .nr_writeback = 0,
            .nr_unstable_nfs = 0,
            .ops = ops,
            .flags = 0,
            .gfp_mask = 0,
            .private_data = null,
            .wb_err = 0,
            .host = null,
        };
    }

    pub fn has_dirty_pages(self: *const AddressSpace) bool {
        return self.nr_dirty > 0;
    }

    pub fn has_writeback(self: *const AddressSpace) bool {
        return self.nr_writeback > 0;
    }

    pub fn add_folio(self: *AddressSpace, folio: *Folio) bool {
        folio.mapping = self;
        self.nr_pages += folio.nr_pages();
        return true;
    }

    pub fn remove_folio(self: *AddressSpace, folio: *Folio) void {
        if (folio.flags.dirty) {
            self.nr_dirty -= folio.nr_pages();
        }
        self.nr_pages -|= folio.nr_pages();
        folio.mapping = null;
    }

    pub fn mark_folio_dirty(self: *AddressSpace, folio: *Folio) void {
        if (!folio.flags.dirty) {
            folio.set_dirty();
            self.nr_dirty += folio.nr_pages();
        }
    }
};

// ============================================================================
// Readahead Control
// ============================================================================

pub const ReadaheadControl = struct {
    mapping: *AddressSpace,
    // Current readahead window
    start: u64,           // Start index
    nr_pages: u32,        // Total pages to read
    // Async trigger
    async_size: u32,      // Pages that triggered the readahead
    // Batch control
    batch_count: u32,

    pub fn next_folio(self: *ReadaheadControl, order: u8) ?*Folio {
        _ = self;
        _ = order;
        return null; // Placeholder - would allocate and return next folio
    }
};

// Readahead State (per file)
pub const ReadaheadState = struct {
    start: u64,
    size: u32,
    async_size: u32,
    ra_pages: u32,       // Max readahead window
    mmap_miss: u32,
    prev_pos: i64,

    pub fn init() ReadaheadState {
        return ReadaheadState{
            .start = 0,
            .size = 0,
            .async_size = 0,
            .ra_pages = 128,  // Default: 512KB
            .mmap_miss = 0,
            .prev_pos = -1,
        };
    }

    pub fn reset(self: *ReadaheadState) void {
        self.start = 0;
        self.size = 0;
        self.async_size = 0;
    }

    // Determine if we should trigger readahead
    pub fn should_readahead(self: *const ReadaheadState, offset: u64) bool {
        // Async readahead trigger
        if (self.async_size > 0) {
            const ra_end = self.start + self.size;
            const async_start = ra_end - self.async_size;
            return offset >= async_start and offset < ra_end;
        }
        return false;
    }

    // Calculate initial readahead size
    pub fn initial_size(self: *const ReadaheadState) u32 {
        var size = self.ra_pages;
        // Start with a reasonable size
        if (size > 32) size = 32;
        // Round up to power of 2
        var s: u32 = 1;
        while (s < size) s <<= 1;
        return s;
    }

    // Calculate next readahead size (grows exponentially)
    pub fn next_size(self: *const ReadaheadState) u32 {
        var size = self.size * 2;
        if (size > self.ra_pages) size = self.ra_pages;
        return size;
    }

    pub fn update(self: *ReadaheadState, new_start: u64, new_size: u32, new_async: u32) void {
        self.start = new_start;
        self.size = new_size;
        self.async_size = new_async;
    }
};

// ============================================================================
// Writeback Control
// ============================================================================

pub const WritebackReason = enum(u8) {
    background = 0,
    vmscan = 1,
    sync = 2,
    periodic = 3,
    laptop_timer = 4,
    free_more_mem = 5,
    fs_free_space = 6,
    fork = 7,
};

pub const WritebackControl = struct {
    nr_to_write: i64,
    pages_skipped: i64,
    // Range
    range_start: u64,
    range_end: u64,
    // Sync mode
    sync_mode: WritebackSyncMode,
    // Flags
    tagged_writepages: bool,
    for_kupdate: bool,
    for_background: bool,
    for_reclaim: bool,
    range_cyclic: bool,
    // Reason
    reason: WritebackReason,
    // Stats
    nr_written: i64,

    pub fn init(reason: WritebackReason) WritebackControl {
        return WritebackControl{
            .nr_to_write = 1024,
            .pages_skipped = 0,
            .range_start = 0,
            .range_end = std.math.maxInt(u64),
            .sync_mode = .none,
            .tagged_writepages = false,
            .for_kupdate = false,
            .for_background = false,
            .for_reclaim = false,
            .range_cyclic = false,
            .reason = reason,
            .nr_written = 0,
        };
    }
};

pub const WritebackSyncMode = enum(u8) {
    none = 0,
    all = 1,
};

// ============================================================================
// BDI (Backing Device Info) Writeback
// ============================================================================

pub const BdiWriteback = struct {
    // Bandwidth estimation
    avg_write_bandwidth: u64,   // Bytes/second
    dirty_ratelimit: u64,       // Pages/second
    balanced_dirty_ratelimit: u64,
    write_bandwidth: u64,
    written_stamp: u64,
    bw_time_stamp: u64,
    // Dirty page tracking
    dirtied_stamp: u64,
    written: u64,
    // State
    state: u32,
    last_old_flush: u64,
    // Per-BDI counters
    stat: [8]u64,
    // Completions
    completions: u64,
    // Work list (flusher thread work queue)
    work_count: u32,
};

pub const BdiStat = enum(u8) {
    writeback = 0,
    reclaimable = 1,
    dirtied = 2,
    written = 3,
    clean = 4,
};

// Global dirty throttle parameters (sysctl tunables)
pub const DirtyThrottleConfig = struct {
    dirty_background_ratio: u32,       // % of total memory
    dirty_background_bytes: u64,
    dirty_ratio: u32,                  // % of total memory
    dirty_bytes: u64,
    dirty_writeback_interval: u32,     // centiseconds
    dirty_expire_interval: u32,        // centiseconds
    // Calculated thresholds
    dirty_thresh: u64,
    dirty_background_thresh: u64,

    pub fn default() DirtyThrottleConfig {
        return .{
            .dirty_background_ratio = 10,
            .dirty_background_bytes = 0,
            .dirty_ratio = 20,
            .dirty_bytes = 0,
            .dirty_writeback_interval = 500,
            .dirty_expire_interval = 3000,
            .dirty_thresh = 0,
            .dirty_background_thresh = 0,
        };
    }

    pub fn background_thresh(self: *const DirtyThrottleConfig, total_pages: u64) u64 {
        if (self.dirty_background_bytes > 0) {
            return self.dirty_background_bytes / PAGE_SIZE;
        }
        return (total_pages * self.dirty_background_ratio) / 100;
    }

    pub fn hard_thresh(self: *const DirtyThrottleConfig, total_pages: u64) u64 {
        if (self.dirty_bytes > 0) {
            return self.dirty_bytes / PAGE_SIZE;
        }
        return (total_pages * self.dirty_ratio) / 100;
    }
};

// ============================================================================
// Buffer Head (for block device buffering)
// ============================================================================

pub const BufferHeadState = packed struct(u32) {
    uptodate: bool = false,
    dirty: bool = false,
    locked: bool = false,
    req: bool = false,
    mapped: bool = false,
    new: bool = false,
    async_read: bool = false,
    async_write: bool = false,
    delay: bool = false,
    boundary: bool = false,
    write_eio: bool = false,
    unwritten: bool = false,
    quiet: bool = false,
    meta: bool = false,
    prio: bool = false,
    defer_completion: bool = false,
    _reserved: u16 = 0,
};

pub const BufferHead = struct {
    state: BufferHeadState,
    blocknr: u64,
    size: u32,
    data: ?[*]u8,
    bdev: ?*anyopaque,  // BlockDevice
    b_count: u32,
    folio: ?*Folio,
    b_next: ?*BufferHead,
    b_prev: ?*BufferHead,

    pub fn is_mapped(self: *const BufferHead) bool {
        return self.state.mapped;
    }

    pub fn is_dirty(self: *const BufferHead) bool {
        return self.state.dirty;
    }

    pub fn mark_dirty(self: *BufferHead) void {
        self.state.dirty = true;
    }
};

// ============================================================================
// Direct I/O
// ============================================================================

pub const DioFlags = packed struct(u32) {
    multi_bio: bool = false,
    last_bio: bool = false,
    is_async: bool = false,
    locking: bool = false,
    no_mmap_sema: bool = false,
    _reserved: u27 = 0,
};

pub const DirectIoInfo = struct {
    op: u32,
    inode: ?*anyopaque,
    offset: u64,
    len: u64,
    flags: DioFlags,
    // Stats
    bytes_done: u64,

    pub fn is_write(self: *const DirectIoInfo) bool {
        return (self.op & 1) != 0;
    }
};

// ============================================================================
// Memory-Mapped File I/O
// ============================================================================

pub const VmFaultResult = enum(u32) {
    nopage = 0,
    minor = 1,
    major = 2,
    bus_error = 3,
    sigbus = 4,
    oom = 5,
    retry = 6,
    done = 7,
    // Zxyphor
    deferred = 8,
};

pub const VmFault = struct {
    vma: ?*anyopaque,    // VMA pointer
    pgoff: u64,          // Page offset in file
    address: u64,        // Faulting virtual address
    flags: VmFaultFlags,
    pte: ?*u64,          // Page table entry
    pmd: ?*u64,          // Page middle directory entry
    pud: ?*u64,          // Page upper directory entry
    folio: ?*Folio,      // Resulting folio
    cow_page: ?*Folio,   // CoW page
    prealloc_pte: ?*u64,

    pub fn is_write(self: *const VmFault) bool {
        return self.flags.write;
    }

    pub fn is_mkwrite(self: *const VmFault) bool {
        return self.flags.mkwrite;
    }
};

pub const VmFaultFlags = packed struct(u32) {
    write: bool = false,
    mkwrite: bool = false,
    allow_retry: bool = false,
    retry_nowait: bool = false,
    killable: bool = false,
    tried: bool = false,
    user: bool = false,
    remote: bool = false,
    lockless: bool = false,
    prefault: bool = false,
    // Zxyphor
    speculative: bool = false,
    _reserved: u21 = 0,
};

pub const VmOperations = struct {
    open: ?*const fn (?*anyopaque) void,
    close: ?*const fn (?*anyopaque) void,
    may_split: ?*const fn (?*anyopaque, u64) i32,
    mremap: ?*const fn (?*anyopaque) i32,
    mprotect: ?*const fn (?*anyopaque, u64, u64, u64) i32,
    fault: ?*const fn (*VmFault) VmFaultResult,
    huge_fault: ?*const fn (*VmFault, u32) VmFaultResult,
    map_pages: ?*const fn (*VmFault, u64, u64) VmFaultResult,
    page_mkwrite: ?*const fn (*VmFault) VmFaultResult,
    pfn_mkwrite: ?*const fn (*VmFault) VmFaultResult,
    access: ?*const fn (?*anyopaque, u64, ?*anyopaque, i32, i32) i32,
    name: ?*const fn (?*anyopaque) ?[*:0]const u8,
    find_special_page: ?*const fn (?*anyopaque, u64) ?*Folio,
};

// ============================================================================
// Page Writeback Statistics
// ============================================================================

pub const WritebackStats = struct {
    nr_dirty: u64,
    nr_writeback: u64,
    nr_dirtied: u64,
    nr_written: u64,
    nr_unstable: u64,
    nr_vmscan_write: u64,
    nr_vmscan_immediate: u64,
    nr_dirty_threshold: u64,
    nr_dirty_background_threshold: u64,
    // Per-BDI stats
    bdi_dirty: u64,
    bdi_writeback: u64,
    bdi_reclaimable: u64,
    // Bandwidth
    avg_write_bandwidth: u64,  // KB/s
    dirty_ratelimit: u64,      // pages/s
    // Throttling
    nr_throttled: u64,
    throttle_time_us: u64,
};

// ============================================================================
// File Read/Write Path
// ============================================================================

pub const FileRaState = struct {
    ra: ReadaheadState,
    file_pos: i64,
    mmap_miss: u32,

    pub fn init() FileRaState {
        return .{
            .ra = ReadaheadState.init(),
            .file_pos = 0,
            .mmap_miss = 0,
        };
    }
};

pub const KiovecIter = struct {
    // I/O vector for scatter-gather
    type_op: u32,      // ITER_KVEC, ITER_BVEC, ITER_PIPE, ITER_XARRAY, ITER_UBUF
    data_source: bool,  // true for write data
    count: usize,       // Remaining bytes
    // Current position
    iov_offset: usize,
    nr_segs: u32,
    // Union of segment types
    segments: union {
        kvec: KvecArray,
        bvec: BvecArray,
        ubuf: UbufInfo,
    },
};

pub const Kvec = struct {
    base: [*]u8,
    len: usize,
};

pub const KvecArray = struct {
    iov: [16]Kvec,
    count: u32,
};

pub const Bvec = struct {
    page_pfn: u64,
    len: u32,
    offset: u32,
};

pub const BvecArray = struct {
    bvec: [256]Bvec,
    count: u32,
};

pub const UbufInfo = struct {
    buf: u64,  // User buffer address
    len: usize,
};

// ============================================================================
// Truncate/Hole Punch
// ============================================================================

pub const TruncateMode = enum(u8) {
    truncate = 0,
    hole_punch = 1,
    zero_range = 2,
    collapse_range = 3,
    insert_range = 4,
};

pub const FallocateInfo = struct {
    mode: u32,
    offset: u64,
    len: u64,

    pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
    pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
    pub const FALLOC_FL_NO_HIDE_STALE: u32 = 0x04;
    pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
    pub const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
    pub const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
    pub const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;

    pub fn is_punch_hole(self: *const FallocateInfo) bool {
        return (self.mode & FALLOC_FL_PUNCH_HOLE) != 0;
    }

    pub fn is_collapse(self: *const FallocateInfo) bool {
        return (self.mode & FALLOC_FL_COLLAPSE_RANGE) != 0;
    }
};

// ============================================================================
// DAX (Direct Access)
// ============================================================================

pub const DaxDevice = struct {
    alive: bool,
    ops: *const DaxOps,
    private_data: ?*anyopaque,

    pub fn is_alive(self: *const DaxDevice) bool {
        return self.alive;
    }
};

pub const DaxOps = struct {
    direct_access: ?*const fn (*DaxDevice, u64, u64, *u64, *?*anyopaque) i64,
    zero_page_range: ?*const fn (*DaxDevice, u64, usize) i32,
    recovery_write: ?*const fn (*DaxDevice, u64, ?*anyopaque, usize, *anyopaque) usize,
};

// ============================================================================
// Filesystem Notification (fsnotify)
// ============================================================================

pub const FsnotifyEventType = enum(u32) {
    access = 0x00000001,
    modify = 0x00000002,
    attrib = 0x00000004,
    close_write = 0x00000008,
    close_nowrite = 0x00000010,
    open = 0x00000020,
    moved_from = 0x00000040,
    moved_to = 0x00000080,
    create = 0x00000100,
    delete = 0x00000200,
    delete_self = 0x00000400,
    move_self = 0x00000800,
    open_perm = 0x00010000,
    access_perm = 0x00020000,
    open_exec = 0x00001000,
    open_exec_perm = 0x00040000,
    // Flags
    // moved = moved_from | moved_to,
    // close = close_write | close_nowrite,
};

pub const FsnotifyMark = struct {
    mask: u32,
    ignored_mask: u32,
    flags: u32,
    group: ?*anyopaque,
    inode: ?*anyopaque,

    pub const FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY: u32 = 0x01;
    pub const FSNOTIFY_MARK_FLAG_ALIVE: u32 = 0x02;
    pub const FSNOTIFY_MARK_FLAG_ATTACHED: u32 = 0x04;
};

pub const InotifyEvent = struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    name_len: u32,
    name: [256]u8,
};

pub const FanotifyEvent = struct {
    event_type: u32,
    pid: u32,
    fd: i32,
    metadata_len: u32,
    response: u32,
};

// ============================================================================
// File Lock (flock/POSIX locks)
// ============================================================================

pub const LockType = enum(u8) {
    read = 0,   // F_RDLCK
    write = 1,  // F_WRLCK
    unlock = 2, // F_UNLCK
};

pub const FileLock = struct {
    lock_type: LockType,
    whence: u8,
    start: u64,
    len: u64,
    pid: u32,
    // Blocker tracking
    blocker: ?*FileLock,
    next: ?*FileLock,
    // Open File Lock (OFD)
    is_ofd: bool,

    pub fn conflicts_with(self: *const FileLock, other: *const FileLock) bool {
        // Check range overlap
        if (self.start + self.len <= other.start) return false;
        if (other.start + other.len <= self.start) return false;
        // Read + read don't conflict
        if (self.lock_type == .read and other.lock_type == .read) return false;
        return true;
    }

    pub fn covers(self: *const FileLock, offset: u64, length: u64) bool {
        if (self.len == 0) return offset >= self.start; // 0 = until EOF
        return offset >= self.start and offset + length <= self.start + self.len;
    }
};

// ============================================================================
// Extended Attributes (xattr)
// ============================================================================

pub const XattrNamespace = enum(u8) {
    user = 1,
    posix_acl_access = 2,
    posix_acl_default = 3,
    trusted = 4,
    security = 6,
    system = 7,
};

pub const XattrEntry = struct {
    namespace: XattrNamespace,
    name: [256]u8,
    name_len: u16,
    value: [65536]u8,
    value_len: u32,
};

pub const XattrHandler = struct {
    name: [32]u8,
    prefix: [32]u8,
    flags: u32,
    list: ?*const fn (?*anyopaque) bool,
    get: ?*const fn (?*anyopaque, [*:0]const u8, ?*anyopaque, usize) i32,
    set: ?*const fn (?*anyopaque, [*:0]const u8, ?*const anyopaque, usize, i32) i32,
};

// ============================================================================
// Quota
// ============================================================================

pub const QuotaType = enum(u8) {
    user = 0,
    group = 1,
    project = 2,
};

pub const DiskQuota = struct {
    quota_type: QuotaType,
    id: u32,
    // Block limits (in 1KB units)
    bhardlimit: u64,
    bsoftlimit: u64,
    curspace: u64,
    // Inode limits
    ihardlimit: u64,
    isoftlimit: u64,
    curinodes: u64,
    // Grace periods
    btime: u64,        // Block grace timer
    itime: u64,        // Inode grace timer
    btimelimit: u64,
    itimelimit: u64,
    // Flags
    flags: u32,

    pub fn blocks_over_softlimit(self: *const DiskQuota) bool {
        return self.bsoftlimit > 0 and self.curspace > self.bsoftlimit;
    }

    pub fn blocks_over_hardlimit(self: *const DiskQuota) bool {
        return self.bhardlimit > 0 and self.curspace >= self.bhardlimit;
    }

    pub fn inodes_over_softlimit(self: *const DiskQuota) bool {
        return self.isoftlimit > 0 and self.curinodes > self.isoftlimit;
    }

    pub fn inodes_over_hardlimit(self: *const DiskQuota) bool {
        return self.ihardlimit > 0 and self.curinodes >= self.ihardlimit;
    }
};
