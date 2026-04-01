// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - tmpfs/shmem, hugetlbfs, ramfs extended,
// block allocation strategies, extent trees, journaling concepts
// More advanced than Linux 2026 filesystem internals

const std = @import("std");

// ============================================================================
// tmpfs / shmem (Shared Memory Filesystem)
// ============================================================================

pub const ShmemFlags = packed struct(u64) {
    huge: u2 = 0,               // SHMEM_HUGE_* (0=never, 1=always, 2=within_size, 3=advise)
    huge_deny: bool = false,
    huge_force: bool = false,
    noswap: bool = false,
    // Mount options
    user_xattr: bool = false,
    posix_acl: bool = false,
    inode32: bool = false,
    inode64: bool = false,
    noatime: bool = false,
    strictatime: bool = false,
    // Zxyphor
    zxy_compressed: bool = false,
    zxy_encrypted: bool = false,
    zxy_dedup: bool = false,
    _reserved: u50 = 0,
};

pub const ShmemHugePolicy = enum(u8) {
    never = 0,
    always = 1,
    within_size = 2,
    advise = 3,
    deny = 4,
    force = 5,
};

pub const ShmemSuperblock = struct {
    // Mount parameters
    uid: u32,
    gid: u32,
    mode: u16,
    // Size limits
    max_blocks: u64,            // In pages
    free_blocks: u64,
    max_inodes: u64,
    free_inodes: u64,
    // Huge page policy
    huge_policy: ShmemHugePolicy,
    // Flags
    flags: ShmemFlags,
    // NUMA policy
    mpol_mode: u8,              // Default memory policy
    mpol_nodemask: [4]u64,
    // Stats
    nr_pages_allocated: u64,
    nr_pages_swapped: u64,
    nr_huge_pages: u64,
    nr_huge_pages_swapped: u64,
    nr_fallocated: u64,
    // Quota
    usrquota_enabled: bool,
    grpquota_enabled: bool,
};

pub const ShmemInode = struct {
    // Base
    ino: u64,
    mode: u16,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    blocks: u64,
    // Timestamps
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
    // Shmem-specific
    alloced: u64,               // Pages allocated
    swapped: u64,               // Pages swapped
    fallocend: u64,             // fallocate end
    // Flags
    flags: u32,
    // Security
    security_label_offset: u32,
    security_label_len: u16,
    // xattr
    nr_xattrs: u16,
    // Seal (for memfd)
    seals: ShmemSeals,
};

pub const ShmemSeals = packed struct(u32) {
    seal: bool = false,
    shrink: bool = false,
    grow: bool = false,
    write: bool = false,
    future_write: bool = false,
    exec: bool = false,
    // Zxyphor
    zxy_immutable: bool = false,
    _reserved: u25 = 0,
};

// memfd_create flags
pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_HUGETLB: u32 = 0x0004;
pub const MFD_NOEXEC_SEAL: u32 = 0x0008;
pub const MFD_EXEC: u32 = 0x0010;

// ============================================================================
// hugetlbfs
// ============================================================================

pub const HugePageSize = enum(u8) {
    size_2mb = 0,
    size_1gb = 1,
    size_16kb = 2,      // ARM
    size_64kb = 3,      // ARM
    size_512mb = 4,     // PowerPC
    size_16gb = 5,      // PowerPC
};

pub const HugetlbSuperblock = struct {
    // Page size
    page_size: u64,     // In bytes
    page_shift: u8,
    // Limits
    max_inodes: i64,    // -1 = unlimited
    free_inodes: i64,
    // Pool
    nr_hugepages: u64,
    free_hugepages: u64,
    reserved_hugepages: u64,
    surplus_hugepages: u64,
    max_surplus_hugepages: u64,
    // Per-NUMA stats
    nr_nodes: u8,
    per_node_free: [64]u64,
    per_node_surplus: [64]u64,
    // Stats
    nr_faults: u64,
    nr_allocations: u64,
    nr_failures: u64,
    nr_reservation_fails: u64,
};

// ============================================================================
// Block Allocation (ext4-like)
// ============================================================================

pub const BlockAllocFlags = packed struct(u32) {
    // Strategy hints
    hint: bool = false,          // Use provided hint block
    exact: bool = false,         // Exact block requested
    goal: bool = false,          // Use goal block
    best_fit: bool = false,      // Best fit search
    contig: bool = false,        // Contiguous allocation
    // Multi-block
    prealloc: bool = false,
    delalloc: bool = false,
    stream: bool = false,        // Streaming allocation
    metadata: bool = false,      // For metadata
    // Alignment
    aligned: bool = false,
    stripe_aligned: bool = false,
    // Zxyphor
    zxy_fast: bool = false,
    zxy_secure_erase: bool = false,
    _reserved: u19 = 0,
};

pub const BlockAllocRequest = struct {
    // Goal
    goal_block: u64,
    // Length
    len: u32,
    // Group hint
    group: u32,
    // Flags
    flags: BlockAllocFlags,
    // Alignment
    alignment: u32,
    // Stripe size (RAID alignment)
    stripe_size: u32,
    // Logical block
    logical_block: u64,
    // Inode context
    inode_nr: u64,
    // Result
    result_block: u64,
    result_len: u32,
};

// Multi-block allocator (mballoc) buddy bitmap
pub const BuddyGroup = struct {
    group_nr: u32,
    // Block bitmap
    bitmap_addr: u64,
    // Buddy bitmap (for coalescing)
    buddy_addr: u64,
    // Free blocks
    free_blocks: u32,
    // Fragment info
    fragments: u32,
    // Largest free extent
    largest_free_order: u8,
    // Counters per order (0..13 for ext4 = groups up to block_size * 8)
    counters: [14]u16,
    // Flags
    need_init: bool,
    bb_corrupt: bool,
    // Stats
    alloc_count: u64,
    free_count: u64,
};

// ============================================================================
// Extent Trees (ext4/XFS-like)
// ============================================================================

pub const ExtentHeader = packed struct {
    magic: u16,          // 0xF30A for ext4
    entries: u16,
    max_entries: u16,
    depth: u16,
    generation: u32,
};

pub const ExtentLeaf = packed struct {
    // Logical block
    block: u32,
    // Length (15 bits length + 1 bit unwritten)
    len: u16,
    // Physical block (48-bit)
    start_hi: u16,
    start_lo: u32,

    pub fn physical_block(self: ExtentLeaf) u64 {
        return (@as(u64, self.start_hi) << 32) | @as(u64, self.start_lo);
    }

    pub fn length(self: ExtentLeaf) u16 {
        return self.len & 0x7FFF;
    }

    pub fn is_unwritten(self: ExtentLeaf) bool {
        return (self.len & 0x8000) != 0;
    }
};

pub const ExtentIndex = packed struct {
    block: u32,          // Logical block covered
    leaf_lo: u32,        // Physical block of child node
    leaf_hi: u16,
    _unused: u16,

    pub fn physical_block(self: ExtentIndex) u64 {
        return (@as(u64, self.leaf_hi) << 32) | @as(u64, self.leaf_lo);
    }
};

// XFS-like B+Tree extent format
pub const BmbtRecord = packed struct {
    // 128-bit record: startoff(54) + startblock(52) + blockcount(21) + flag(1)
    l0: u64,
    l1: u64,

    pub fn file_offset(self: BmbtRecord) u64 {
        return (self.l0 & 0x7FFFFFFFFFFFFFF) >> 9;
    }

    pub fn start_block(self: BmbtRecord) u64 {
        return ((self.l0 & 0x1FF) << 43) | (self.l1 >> 21);
    }

    pub fn block_count(self: BmbtRecord) u32 {
        return @truncate(self.l1 & 0x1FFFFF);
    }

    pub fn is_unwritten(self: BmbtRecord) bool {
        return (self.l0 >> 63) != 0;
    }
};

// ============================================================================
// Journaling (JBD2 concepts)
// ============================================================================

pub const JournalState = enum(u8) {
    unmounted = 0,
    running = 1,
    locked = 2,
    flush = 3,
    recovery = 4,
    abort = 5,
};

pub const JournalBlockType = enum(u32) {
    descriptor = 1,       // Descriptor block
    commit = 2,           // Commit block
    superblock_v1 = 3,    // Superblock v1
    superblock_v2 = 4,    // Superblock v2
    revoke = 5,           // Revocation records
};

pub const JournalSuperblock = struct {
    // Header
    magic: u32,                  // 0xC03B3998
    blocktype: u32,
    sequence: u32,
    // Journal params
    blocksize: u32,
    maxlen: u32,                // Total blocks in journal
    first: u32,                 // First usable block
    // Transaction info
    sequence_first: u32,        // First expected commit ID
    start: u32,                 // Block of first transaction
    errno: i32,
    // Features
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    // UUID
    uuid: [16]u8,
    // Users
    nr_users: u32,
    dynsuper: u32,
    // Limits
    max_trans_buffers: u32,
    // Checksum
    checksum_type: u8,
    checksum: u32,
};

pub const JournalFeatureIncompat = packed struct(u32) {
    revoke: bool = false,        // Revocation records
    @"64bit": bool = false,      // 64-bit support
    async_commit: bool = false,
    csum_v2: bool = false,       // Metadata checksumming v2
    csum_v3: bool = false,       // Metadata checksumming v3
    fast_commit: bool = false,
    _reserved: u26 = 0,
};

pub const JournalTransaction = struct {
    // Transaction ID
    tid: u32,
    // State
    state: JTransState,
    // Buffers
    nr_buffers: u32,
    nr_metadata: u32,
    nr_revoke: u32,
    nr_reserved: u32,
    // Log space
    log_start: u32,
    log_end: u32,
    // Credits
    total_credits: i32,
    outstanding_credits: i32,
    // Timestamps
    start_time_ns: u64,
    commit_time_ns: u64,
    // Stats
    nr_handle_count: u32,
    max_wait_ns: u64,
    commit_wait_ns: u64,
    locked_wait_ns: u64,
    flushing_wait_ns: u64,
};

pub const JTransState = enum(u8) {
    running = 0,
    locked = 1,
    flush = 2,
    commit = 3,
    commit_dflush = 4,
    commit_jflush = 5,
    commit_callback = 6,
    finished = 7,
};

// ============================================================================
// Quota System
// ============================================================================

pub const QuotaType = enum(u8) {
    user = 0,
    group = 1,
    project = 2,
};

pub const QuotaFormat = enum(u8) {
    vfsold = 1,          // Original quota format
    vfsv0 = 2,           // VFS quota v0
    vfsv1 = 3,           // VFS quota v1
    // Filesystem-specific
    ocfs2 = 10,
};

pub const QuotaFlags = packed struct(u32) {
    enabled: bool = false,
    enforced: bool = false,
    // Grace period
    user_grace_exceeded: bool = false,
    group_grace_exceeded: bool = false,
    // Limits
    hardlimit: bool = false,
    softlimit: bool = false,
    // Zxyphor
    zxy_realtime: bool = false,
    _reserved: u25 = 0,
};

pub const DquotInfo = struct {
    // Identification
    dqi_type: QuotaType,
    dqi_id: u32,
    // Limits (in blocks and inodes)
    dqi_bhardlimit: u64,
    dqi_bsoftlimit: u64,
    dqi_ihardlimit: u64,
    dqi_isoftlimit: u64,
    // Current usage
    dqi_curspace: u64,       // Current space usage (bytes)
    dqi_curinodes: u64,      // Current inode usage
    // Grace periods
    dqi_btime: i64,          // Block grace deadline (epoch seconds)
    dqi_itime: i64,          // Inode grace deadline
    dqi_bgrace: u64,         // Block grace period (seconds)
    dqi_igrace: u64,         // Inode grace period (seconds)
    // Flags
    dqi_flags: QuotaFlags,
    // Valid fields
    dqi_valid: u32,          // Bitmap of valid fields

    pub fn is_over_block_softlimit(self: *const DquotInfo) bool {
        if (self.dqi_bsoftlimit == 0) return false;
        return self.dqi_curspace > self.dqi_bsoftlimit;
    }

    pub fn is_over_block_hardlimit(self: *const DquotInfo) bool {
        if (self.dqi_bhardlimit == 0) return false;
        return self.dqi_curspace > self.dqi_bhardlimit;
    }

    pub fn is_over_inode_softlimit(self: *const DquotInfo) bool {
        if (self.dqi_isoftlimit == 0) return false;
        return self.dqi_curinodes > self.dqi_isoftlimit;
    }

    pub fn block_usage_pct(self: *const DquotInfo) u8 {
        if (self.dqi_bhardlimit == 0) return 0;
        return @truncate((self.dqi_curspace * 100) / self.dqi_bhardlimit);
    }
};

// ============================================================================
// ACL (POSIX Access Control Lists)
// ============================================================================

pub const AclTag = enum(u16) {
    user_obj = 0x01,     // Owner
    user = 0x02,         // Named user
    group_obj = 0x04,    // Owning group
    group = 0x08,        // Named group
    mask = 0x10,         // Mask
    other = 0x20,        // Other
};

pub const AclPerm = packed struct(u16) {
    execute: bool = false,
    write: bool = false,
    read: bool = false,
    _reserved: u13 = 0,
};

pub const AclEntry = struct {
    tag: AclTag,
    perm: AclPerm,
    id: u32,             // UID or GID (for named user/group)
};

pub const Acl = struct {
    version: u32,       // Always 2
    nr_entries: u16,
    entries: [32]AclEntry,   // Max entries

    pub fn has_mask(self: *const Acl) bool {
        for (self.entries[0..self.nr_entries]) |entry| {
            if (entry.tag == .mask) return true;
        }
        return false;
    }
};

// ============================================================================
// xattr (Extended Attributes)
// ============================================================================

pub const XattrNamespace = enum(u8) {
    user = 1,
    posix_acl_access = 2,
    posix_acl_default = 3,
    trusted = 4,
    security = 6,
    system = 7,
    // Zxyphor
    zxyphor = 10,
};

pub const XattrEntry = struct {
    namespace: XattrNamespace,
    name_offset: u32,
    name_len: u16,
    value_offset: u32,
    value_len: u32,
};

pub const XATTR_NAME_MAX: u32 = 255;
pub const XATTR_SIZE_MAX: u32 = 65536;
pub const XATTR_LIST_MAX: u32 = 65536;

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const FsInternalsSubsystem = struct {
    // tmpfs
    nr_shmem_mounts: u32,
    total_shmem_pages: u64,
    total_shmem_swapped: u64,
    shmem_huge_policy: ShmemHugePolicy,
    // hugetlbfs
    nr_hugetlb_mounts: u32,
    hugepage_sizes: [6]u64,      // Available sizes
    nr_hugepage_sizes: u8,
    // Block allocation
    default_alloc_flags: BlockAllocFlags,
    // Journaling
    journal_enabled: bool,
    journal_state: JournalState,
    journal_transactions: u64,
    journal_avg_commit_ms: u32,
    // Quota
    quota_enabled: [3]bool,      // user, group, project
    quota_format: QuotaFormat,
    total_quota_checks: u64,
    total_quota_denials: u64,
    // ACL
    posix_acl_enabled: bool,
    total_acl_checks: u64,
    // xattr
    total_xattr_gets: u64,
    total_xattr_sets: u64,
    // Stats
    total_extent_lookups: u64,
    total_block_allocations: u64,
    total_block_frees: u64,
    // Zxyphor
    zxy_inline_encryption: bool,
    initialized: bool,
};
