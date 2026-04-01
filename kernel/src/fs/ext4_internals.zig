// Zxyphor Kernel - Ext4 Filesystem Internals (Zig),
// Superblock, Inode, Group Descriptors, Extents,
// Journal (JBD2), Directory Indexing (htree),
// Inline Data, Project Quotas, Verity, Casefold,
// Fast Commit, Orphan File, Large Directories
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Ext4 Superblock
// ============================================================================

pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

pub const Ext4Superblock = extern struct {
    s_inodes_count: u32,           // Total inodes
    s_blocks_count_lo: u32,        // Total blocks (low 32)
    s_r_blocks_count_lo: u32,      // Reserved blocks
    s_free_blocks_count_lo: u32,   // Free blocks
    s_free_inodes_count: u32,      // Free inodes
    s_first_data_block: u32,       // First data block
    s_log_block_size: u32,         // Block size = 2^(10 + s_log_block_size)
    s_log_cluster_size: u32,       // Cluster size
    s_blocks_per_group: u32,
    s_clusters_per_group: u32,
    s_inodes_per_group: u32,
    s_mtime: u32,                  // Last mount time
    s_wtime: u32,                  // Last write time
    s_mnt_count: u16,              // Mount count
    s_max_mnt_count: u16,          // Max mount count before fsck
    s_magic: u16,                  // 0xEF53
    s_state: u16,                  // FS state
    s_errors: u16,                 // Error behavior
    s_minor_rev_level: u16,
    s_lastcheck: u32,              // Last fsck time
    s_checkinterval: u32,
    s_creator_os: u32,
    s_rev_level: u32,              // Revision level
    s_def_resuid: u16,
    s_def_resgid: u16,
    // Dynamic revision fields
    s_first_ino: u32,              // First non-reserved inode
    s_inode_size: u16,             // Inode structure size
    s_block_group_nr: u16,
    s_feature_compat: u32,
    s_feature_incompat: u32,
    s_feature_ro_compat: u32,
    s_uuid: [16]u8,
    s_volume_name: [16]u8,
    s_last_mounted: [64]u8,
    s_algorithm_usage_bitmap: u32,
    // Performance hints
    s_prealloc_blocks: u8,
    s_prealloc_dir_blocks: u8,
    s_reserved_gdt_blocks: u16,
    // Journal fields
    s_journal_uuid: [16]u8,
    s_journal_inum: u32,
    s_journal_dev: u32,
    s_last_orphan: u32,
    s_hash_seed: [4]u32,
    s_def_hash_version: u8,
    s_jnl_backup_type: u8,
    s_desc_size: u16,              // Group desc size
    s_default_mount_opts: u32,
    s_first_meta_bg: u32,
    s_mkfs_time: u32,
    s_jnl_blocks: [17]u32,
    // 64-bit fields
    s_blocks_count_hi: u32,
    s_r_blocks_count_hi: u32,
    s_free_blocks_count_hi: u32,
    s_min_extra_isize: u16,
    s_want_extra_isize: u16,
    s_flags: u32,
    s_raid_stride: u16,
    s_mmp_update_interval: u16,
    s_mmp_block: u64,
    s_raid_stripe_width: u32,
    s_log_groups_per_flex: u8,
    s_checksum_type: u8,
    s_encryption_level: u8,
    s_reserved_pad: u8,
    s_kbytes_written: u64,
    s_snapshot_inum: u32,
    s_snapshot_id: u32,
    s_snapshot_r_blocks_count: u64,
    s_snapshot_list: u32,
    s_error_count: u32,
    s_first_error_time: u32,
    s_first_error_ino: u32,
    s_first_error_block: u64,
    s_first_error_func: [32]u8,
    s_first_error_line: u32,
    s_last_error_time: u32,
    s_last_error_ino: u32,
    s_last_error_line: u32,
    s_last_error_block: u64,
    s_last_error_func: [32]u8,
    s_mount_opts: [64]u8,
    s_usr_quota_inum: u32,
    s_grp_quota_inum: u32,
    s_overhead_clusters: u32,
    s_backup_bgs: [2]u32,
    s_encrypt_algos: [4]u8,
    s_encrypt_pw_salt: [16]u8,
    s_lpf_ino: u32,
    s_prj_quota_inum: u32,
    s_checksum_seed: u32,
    s_wtime_hi: u8,
    s_mtime_hi: u8,
    s_mkfs_time_hi: u8,
    s_lastcheck_hi: u8,
    s_first_error_time_hi: u8,
    s_last_error_time_hi: u8,
    s_first_error_errcode: u8,
    s_last_error_errcode: u8,
    s_encoding: u16,
    s_encoding_flags: u16,
    s_orphan_file_inum: u32,
    s_reserved: [94]u32,
    s_checksum: u32,
};

// ============================================================================
// Feature Flags
// ============================================================================

pub const Ext4FeatureCompat = packed struct(u32) {
    dir_prealloc: bool = false,
    imagic_inodes: bool = false,
    has_journal: bool = false,
    ext_attr: bool = false,
    resize_inode: bool = false,
    dir_index: bool = false,
    lazy_bg: bool = false,
    exclude_inode: bool = false,
    exclude_bitmap: bool = false,
    sparse_super2: bool = false,
    fast_commit: bool = false,
    stable_inodes: bool = false,
    orphan_file: bool = false,
    _reserved: u19 = 0,
};

pub const Ext4FeatureIncompat = packed struct(u32) {
    compression: bool = false,
    filetype: bool = false,
    recover: bool = false,
    journal_dev: bool = false,
    meta_bg: bool = false,
    _reserved1: bool = false,
    extents: bool = false,
    @"64bit": bool = false,
    mmp: bool = false,
    flex_bg: bool = false,
    ea_inode: bool = false,
    _reserved2: bool = false,
    dirdata: bool = false,
    csum_seed: bool = false,
    largedir: bool = false,
    inline_data: bool = false,
    encrypt: bool = false,
    casefold: bool = false,
    _reserved3: u14 = 0,
};

pub const Ext4FeatureRoCompat = packed struct(u32) {
    sparse_super: bool = false,
    large_file: bool = false,
    btree_dir: bool = false,
    huge_file: bool = false,
    gdt_csum: bool = false,
    dir_nlink: bool = false,
    extra_isize: bool = false,
    has_snapshot: bool = false,
    quota: bool = false,
    bigalloc: bool = false,
    metadata_csum: bool = false,
    replica: bool = false,
    readonly: bool = false,
    project: bool = false,
    shared_blocks: bool = false,
    verity: bool = false,
    orphan_present: bool = false,
    _reserved: u15 = 0,
};

// ============================================================================
// Ext4 Inode
// ============================================================================

pub const Ext4Inode = extern struct {
    i_mode: u16,
    i_uid: u16,
    i_size_lo: u32,
    i_atime: u32,
    i_ctime: u32,
    i_mtime: u32,
    i_dtime: u32,
    i_gid: u16,
    i_links_count: u16,
    i_blocks_lo: u32,       // 512-byte blocks
    i_flags: u32,
    i_osd1: u32,
    i_block: [60]u8,        // 15×4 bytes: extent tree or block map
    i_generation: u32,
    i_file_acl_lo: u32,
    i_size_high: u32,        // Was i_dir_acl
    i_obso_faddr: u32,
    i_osd2: [12]u8,
    i_extra_isize: u16,
    i_checksum_hi: u16,
    i_ctime_extra: u32,
    i_mtime_extra: u32,
    i_atime_extra: u32,
    i_crtime: u32,           // Creation time
    i_crtime_extra: u32,
    i_version_hi: u32,
    i_projid: u32,
};

pub const Ext4InodeFlags = packed struct(u32) {
    secrm: bool = false,           // Secure deletion
    unrm: bool = false,            // Undelete
    compr: bool = false,           // Compressed
    sync: bool = false,            // Synchronous updates
    immutable: bool = false,       // Immutable
    append: bool = false,          // Append only
    nodump: bool = false,          // No dump
    noatime: bool = false,         // No access time
    dirty: bool = false,
    comprblk: bool = false,
    nocompr: bool = false,
    encrypt: bool = false,         // Encrypted
    index: bool = false,           // Hash-indexed directory
    imagic: bool = false,
    journal_data: bool = false,
    notail: bool = false,
    dirsync: bool = false,
    topdir: bool = false,
    huge_file: bool = false,
    extents: bool = false,         // Uses extents
    verity: bool = false,          // verity protected
    ea_inode: bool = false,        // EA in inode body
    _reserved1: bool = false,
    dax: bool = false,             // DAX
    inline_data: bool = false,     // Inline data
    projinherit: bool = false,     // Project inheritance
    casefold: bool = false,        // Casefolded directory
    _reserved2: u5 = 0,
};

// ============================================================================
// Ext4 Extent Tree
// ============================================================================

pub const Ext4ExtentHeader = extern struct {
    eh_magic: u16,          // 0xF30A
    eh_entries: u16,        // Number of valid entries
    eh_max: u16,            // Maximum entries
    eh_depth: u16,          // 0 = leaf, >0 = internal
    eh_generation: u32,
};

pub const Ext4Extent = extern struct {
    ee_block: u32,          // First logical block
    ee_len: u16,            // Number of blocks (high bit = uninitialized)
    ee_start_hi: u16,       // Physical block number (high 16)
    ee_start_lo: u32,       // Physical block number (low 32)
};

pub const Ext4ExtentIdx = extern struct {
    ei_block: u32,          // Index covers blocks from ei_block
    ei_leaf_lo: u32,        // Physical block of next-level node (low 32)
    ei_leaf_hi: u16,        // Physical block (high 16)
    ei_unused: u16,
};

pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

// ============================================================================
// Ext4 Directory Entry
// ============================================================================

pub const Ext4DirEntry2 = extern struct {
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
    name: [255]u8,          // Flexible array (actual size = name_len)
};

pub const Ext4FileType = enum(u8) {
    unknown = 0,
    regular = 1,
    directory = 2,
    chrdev = 3,
    blkdev = 4,
    fifo = 5,
    sock = 6,
    symlink = 7,
};

// ============================================================================
// Ext4 Directory Hash Tree (htree)
// ============================================================================

pub const Ext4DxRoot = extern struct {
    dot: Ext4DirEntry2,
    dotdot: Ext4DirEntry2,
    info: Ext4DxRootInfo,
};

pub const Ext4DxRootInfo = extern struct {
    reserved_zero: u32,
    hash_version: u8,
    info_length: u8,
    indirect_levels: u8,
    unused_flags: u8,
};

pub const Ext4DxEntry = extern struct {
    hash: u32,
    block: u32,
};

pub const Ext4DxCountlimit = extern struct {
    limit: u16,
    count: u16,
};

pub const Ext4HashVersion = enum(u8) {
    legacy = 0,
    half_md4 = 1,
    tea = 2,
    legacy_unsigned = 3,
    half_md4_unsigned = 4,
    tea_unsigned = 5,
    siphash = 6,
};

// ============================================================================
// Ext4 Group Descriptor (64-byte)
// ============================================================================

pub const Ext4GroupDesc = extern struct {
    bg_block_bitmap_lo: u32,
    bg_inode_bitmap_lo: u32,
    bg_inode_table_lo: u32,
    bg_free_blocks_count_lo: u16,
    bg_free_inodes_count_lo: u16,
    bg_used_dirs_count_lo: u16,
    bg_flags: u16,
    bg_exclude_bitmap_lo: u32,
    bg_block_bitmap_csum_lo: u16,
    bg_inode_bitmap_csum_lo: u16,
    bg_itable_unused_lo: u16,
    bg_checksum: u16,
    // 64-bit extension
    bg_block_bitmap_hi: u32,
    bg_inode_bitmap_hi: u32,
    bg_inode_table_hi: u32,
    bg_free_blocks_count_hi: u16,
    bg_free_inodes_count_hi: u16,
    bg_used_dirs_count_hi: u16,
    bg_itable_unused_hi: u16,
    bg_exclude_bitmap_hi: u32,
    bg_block_bitmap_csum_hi: u16,
    bg_inode_bitmap_csum_hi: u16,
    bg_reserved: u32,
};

pub const Ext4GroupDescFlags = packed struct(u16) {
    inode_uninit: bool = false,
    block_uninit: bool = false,
    inode_zeroed: bool = false,
    _reserved: u13 = 0,
};

// ============================================================================
// JBD2 Journal
// ============================================================================

pub const JBD2_MAGIC: u32 = 0xC03B3998;

pub const Jbd2BlockType = enum(u32) {
    descriptor = 1,
    commit = 2,
    superblock_v1 = 3,
    superblock_v2 = 4,
    revoke = 5,
};

pub const Jbd2Superblock = extern struct {
    s_header_magic: u32,
    s_header_blocktype: u32,
    s_header_sequence: u32,
    s_blocksize: u32,
    s_maxlen: u32,           // Total blocks in journal
    s_first: u32,            // First block of log
    s_sequence: u32,         // First expected commit ID
    s_start: u32,            // Block number of start of log
    s_no: u32,
    s_feature_compat: u32,
    s_feature_incompat: u32,
    s_feature_ro_compat: u32,
    s_uuid: [16]u8,
    s_nr_users: u32,
    s_dynsuper: u32,
    s_max_transaction: u32,
    s_max_trans_data: u32,
    s_checksum_type: u8,
    s_padding2: [3]u8,
    s_num_fc_blks: u32,      // Fast commit blocks
    s_head: u32,             // Head of journal
    s_padding: [40]u32,
    s_checksum: u32,
    s_users: [16][16]u8,     // 16 × 16-byte UUIDs
};

pub const Jbd2IncompatFeatures = packed struct(u32) {
    revoke: bool = false,
    @"64bit": bool = false,
    async_commit: bool = false,
    csum_v2: bool = false,
    csum_v3: bool = false,
    fast_commit: bool = false,
    _reserved: u26 = 0,
};

pub const Jbd2TransactionState = enum(u8) {
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
// Ext4 Mount Options
// ============================================================================

pub const Ext4MountOpts = struct {
    journal_data: bool,
    journal_ordered: bool,
    journal_writeback: bool,
    nobarrier: bool,
    discard: bool,
    dax_mode: Ext4DaxMode,
    data_err: Ext4DataErr,
    delalloc: bool,
    max_batch_time_us: u32,
    min_batch_time_us: u32,
    commit_interval_s: u32,
    stripe: u32,
    errors_behavior: Ext4ErrorBehavior,
    quota_enabled: bool,
    prjquota: bool,
    usrquota: bool,
    grpquota: bool,
    norecovery: bool,
    debug: bool,
};

pub const Ext4DaxMode = enum(u8) {
    disabled = 0,
    always = 1,
    never = 2,
    inode = 3,        // Per-inode DAX via ioctl
};

pub const Ext4DataErr = enum(u8) {
    ignore = 0,
    abort = 1,
};

pub const Ext4ErrorBehavior = enum(u8) {
    @"continue" = 1,
    remount_ro = 2,
    panic = 3,
};

// ============================================================================
// Ext4 Multi-Block Allocator (mballoc)
// ============================================================================

pub const Ext4AllocationRequest = struct {
    inode: u32,
    logical_block: u64,
    goal: u64,             // Preferred physical block
    len: u32,              // Requested length
    flags: Ext4AllocFlags,
};

pub const Ext4AllocFlags = packed struct(u16) {
    delalloc: bool = false,
    metadata: bool = false,
    force_group: bool = false,
    exact: bool = false,
    stream: bool = false,     // Streaming allocation
    no_normalize: bool = false,
    _reserved: u10 = 0,
};

pub const Ext4Prealloc = struct {
    pa_lstart: u64,         // Logical start
    pa_pstart: u64,         // Physical start
    pa_len: u32,            // Preallocated length
    pa_free: u32,           // Free blocks remaining
    pa_type: PreallocType,
};

pub const PreallocType = enum(u8) {
    inode = 0,
    group = 1,
};

pub const MballocStats = struct {
    allocated: u64,
    freed: u64,
    buddy_splits: u64,
    buddy_merges: u64,
    prealloc_hits: u64,
    prealloc_misses: u64,
    groups_scanned: u64,
    goal_hits: u64,
    goal_misses: u64,
    cr0_hits: u64,       // Best fit
    cr1_hits: u64,       // Next to goal
    cr2_hits: u64,       // Any group
    cr3_hits: u64,       // Fragmented
    extents_scanned: u64,
};

// ============================================================================
// Ext4 Fast Commit
// ============================================================================

pub const Ext4FastCommitTag = enum(u16) {
    add_range = 0x0001,
    del_range = 0x0002,
    creat = 0x0003,
    link = 0x0004,
    unlink = 0x0005,
    inode = 0x0006,
    tail = 0x0007,     // End of fast commit section
    head = 0x0008,
};

pub const Ext4FcStats = struct {
    fc_num_commits: u64,
    fc_ineligible_commits: u64,
    fc_numblks: u64,
    fc_jbd_commits: u64,
    fc_full_commits: u64,
    fc_avg_commit_time_us: u64,
};

// ============================================================================
// Ext4 Filesystem Manager (Zxyphor)
// ============================================================================

pub const Ext4FsManager = struct {
    nr_mounted: u32,
    nr_inodes_total: u64,
    nr_inodes_free: u64,
    nr_blocks_total: u64,
    nr_blocks_free: u64,
    nr_groups: u32,
    block_size: u32,
    inode_size: u16,
    features_compat: Ext4FeatureCompat,
    features_incompat: Ext4FeatureIncompat,
    features_ro_compat: Ext4FeatureRoCompat,
    journal_active: bool,
    fast_commit_active: bool,
    mballoc_stats: MballocStats,
    fc_stats: Ext4FcStats,
    initialized: bool,

    pub fn init() Ext4FsManager {
        return .{
            .nr_mounted = 0,
            .nr_inodes_total = 0,
            .nr_inodes_free = 0,
            .nr_blocks_total = 0,
            .nr_blocks_free = 0,
            .nr_groups = 0,
            .block_size = 4096,
            .inode_size = 256,
            .features_compat = .{},
            .features_incompat = .{},
            .features_ro_compat = .{},
            .journal_active = false,
            .fast_commit_active = false,
            .mballoc_stats = std.mem.zeroes(MballocStats),
            .fc_stats = std.mem.zeroes(Ext4FcStats),
            .initialized = true,
        };
    }
};
