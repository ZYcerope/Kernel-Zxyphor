// Zxyphor Kernel - F2FS (Flash-Friendly File System) Internals
// On-disk layout, superblock, checkpoint, NAT/SIT,
// segment info table, node address table,
// multi-head logging, zone-aware allocation,
// compress/GC/discard, atomic writes, casefold
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

pub const F2FS_MAGIC: u32 = 0xF2F52010;
pub const F2FS_SUPER_OFFSET: usize = 1024;
pub const F2FS_LOG_SECTOR_SIZE: u32 = 9;  // 512 bytes
pub const F2FS_BLKSIZE: u32 = 4096;

// ============================================================================
// F2FS Superblock (on-disk)
// ============================================================================

pub const F2fsSuperblock = extern struct {
    magic: u32,
    major_ver: u16,
    minor_ver: u16,
    log_sectorsize: u32,
    log_sectors_per_block: u32,
    log_blocksize: u32,
    log_blocks_per_seg: u32,
    segs_per_sec: u32,
    secs_per_zone: u32,
    checksum_offset: u32,
    block_count: u64,
    section_count: u32,
    segment_count: u32,
    segment_count_ckpt: u32,
    segment_count_sit: u32,
    segment_count_nat: u32,
    segment_count_ssa: u32,
    segment_count_main: u32,
    segment0_blkaddr: u32,
    cp_blkaddr: u32,
    sit_blkaddr: u32,
    nat_blkaddr: u32,
    ssa_blkaddr: u32,
    main_blkaddr: u32,
    root_ino: u32,
    node_ino: u32,
    meta_ino: u32,
    uuid: [16]u8,
    volume_name: [512]u8,      // UTF-16
    extension_count: u32,
    extension_list: [64][8]u8, // 64 extensions, 8 bytes each
    cp_payload: u32,
    version: [256]u8,
    init_version: [256]u8,
    feature: F2fsFeatureFlags,
    encryption_level: u8,
    encrypt_pw_salt: [16]u8,
    devs: [8]F2fsDeviceEntry,
    qf_ino: [3]u32,           // quota file inodes
    hot_ext_count: u8,
    s_encoding: u16,
    s_encoding_flags: u16,
    s_stop_reason: [32]u8,
    s_errors: [16]u8,
    _reserved: [258]u8,
    crc: u32,
};

pub const F2fsDeviceEntry = extern struct {
    path: [64]u8,
    total_segments: u32,
};

pub const F2fsFeatureFlags = packed struct(u32) {
    encrypt: bool = false,
    blkzoned: bool = false,
    atomic_write: bool = false,
    extra_attr: bool = false,
    prjquota: bool = false,
    inode_chksum: bool = false,
    flexible_inline_xattr: bool = false,
    quota_ino: bool = false,
    inode_crtime: bool = false,
    lost_found: bool = false,
    verity: bool = false,
    sb_chksum: bool = false,
    casefold: bool = false,
    compression: bool = false,
    ro: bool = false,
    _reserved: u17 = 0,
};

// ============================================================================
// F2FS Checkpoint (on-disk)
// ============================================================================

pub const F2fsCheckpoint = extern struct {
    checkpoint_ver: u64,
    user_block_count: u64,
    valid_block_count: u64,
    rsvd_segment_count: u32,
    overprov_segment_count: u32,
    free_segment_count: u32,
    cur_node_segno: [8]u32,
    cur_node_blkoff: [8]u16,
    cur_data_segno: [8]u32,
    cur_data_blkoff: [8]u16,
    ckpt_flags: F2fsCkptFlags,
    cp_pack_total_block_count: u32,
    cp_pack_start_sum: u32,
    valid_node_count: u32,
    valid_inode_count: u32,
    next_free_nid: u32,
    sit_ver_bitmap_bytesize: u32,
    nat_ver_bitmap_bytesize: u32,
    checksum_offset: u32,
    elapsed_time: u64,
    alloc_type: [16]u8,
    sit_nat_version_bitmap: [3900]u8, // variable
    checksum: u32,
};

pub const F2fsCkptFlags = packed struct(u32) {
    is_large_nat_bitmap: bool = false,
    cp_disabled: bool = false,
    cp_quota_need_repair: bool = false,
    cp_quota_need_fsck: bool = false,
    nat_bits: bool = false,
    cp_trimmed: bool = false,
    cp_nocrc_recovery: bool = false,
    cp_large_sec: bool = false,
    cp_compact_sum: bool = false,
    cp_orphan_present: bool = false,
    cp_umount: bool = false,
    cp_fsck_flag: bool = false,
    cp_error_flag: bool = false,
    _reserved: u19 = 0,
};

// ============================================================================
// F2FS NAT (Node Address Table)
// ============================================================================

pub const F2fsNatEntry = extern struct {
    ino: u32,
    block_addr: u32,
    version: u8,
};

pub const F2fsNatBlock = extern struct {
    entries: [455]F2fsNatEntry, // entries per NAT block
};

pub const F2fsNatJournal = extern struct {
    entries: [64]F2fsNatJournalEntry,
    count: u16,
};

pub const F2fsNatJournalEntry = extern struct {
    nid: u32,
    entry: F2fsNatEntry,
};

// ============================================================================
// F2FS SIT (Segment Information Table)
// ============================================================================

pub const F2fsSitEntry = extern struct {
    vblocks: u16,
    valid_map: [64]u8,     // 512 bits (4096/8 = 512 blocks per segment)
    mtime: u64,
};

pub const F2fsSitBlock = extern struct {
    entries: [55]F2fsSitEntry,
};

pub const F2fsSitJournal = extern struct {
    entries: [64]F2fsSitJournalEntry,
    count: u16,
};

pub const F2fsSitJournalEntry = extern struct {
    segno: u32,
    entry: F2fsSitEntry,
};

// ============================================================================
// F2FS Segment Types
// ============================================================================

pub const F2fsSegType = enum(u8) {
    hot_data = 0,
    warm_data = 1,
    cold_data = 2,
    hot_node = 3,
    warm_node = 4,
    cold_node = 5,
    no_check_type = 6,
};

pub const F2fsAllocMode = enum(u8) {
    normal = 0,
    ssr = 1,       // Slack Space Recycling
    lfs = 2,       // Log-structured File System
};

// ============================================================================
// F2FS Inode (on-disk)
// ============================================================================

pub const F2fsInode = extern struct {
    i_mode: u16,
    i_advise: u8,
    i_inline: u8,
    i_uid: u32,
    i_gid: u32,
    i_links: u32,
    i_size: u64,
    i_blocks: u64,
    i_atime: u64,
    i_ctime: u64,
    i_mtime: u64,
    i_atime_nsec: u32,
    i_ctime_nsec: u32,
    i_mtime_nsec: u32,
    i_generation: u32,
    i_current_depth: u32,
    i_xattr_nid: u32,
    i_flags: F2fsInodeFlags,
    i_pino: u32,
    i_namelen: u32,
    i_name: [255]u8,
    i_dir_level: u8,
    // Extra attributes area (if EXTRA_ATTR)
    i_extra_isize: u16,
    i_inline_xattr_size: u16,
    i_projid: u32,
    i_inode_checksum: u32,
    i_crtime: u64,
    i_crtime_nsec: u32,
    i_compr_blocks: u64,
    _reserved: u8,
    i_compress_algorithm: u8,
    i_log_cluster_size: u8,
    i_compress_flag: u16,
    i_extra_end: [12]u8,
    // Block addresses
    i_addr: [929]u32,        // inline data or block addresses
    i_nid: [5]u32,           // direct/indirect node IDs
};

pub const F2fsInodeFlags = packed struct(u32) {
    sync: bool = false,
    immutable: bool = false,
    append: bool = false,
    nodump: bool = false,
    noatime: bool = false,
    index_fl: bool = false,
    dirsync: bool = false,
    projinherit: bool = false,
    casefold: bool = false,
    encrypt: bool = false,
    verity: bool = false,
    _reserved: u21 = 0,
};

pub const F2fsInlineFlags = packed struct(u8) {
    has_inline_xattr: bool = false,
    has_inline_data: bool = false,
    has_inline_dentry: bool = false,
    has_data_summary: bool = false,
    has_inline_dots: bool = false,
    has_extra_attr: bool = false,
    has_pin_file: bool = false,
    has_compress_file: bool = false,
};

// ============================================================================
// F2FS Node Structure
// ============================================================================

pub const F2fsNode = extern struct {
    // union: inode / direct_node / indirect_node
    footer: F2fsNodeFooter,
};

pub const F2fsNodeFooter = extern struct {
    nid: u32,
    ino: u32,
    flag: u32,
    cp_ver: u64,
    next_blkaddr: u32,
};

pub const F2fsDirectNode = extern struct {
    addr: [1018]u32,        // block addresses
    footer: F2fsNodeFooter,
};

pub const F2fsIndirectNode = extern struct {
    nid: [1018]u32,         // node IDs
    footer: F2fsNodeFooter,
};

// ============================================================================
// F2FS SSA (Segment Summary Area)
// ============================================================================

pub const F2fsSummaryBlock = extern struct {
    entries: [512]F2fsSummary,
    footer: F2fsSummaryFooter,
    // Journal area
    nat_journal: F2fsNatJournal,
    sit_journal: F2fsSitJournal,
};

pub const F2fsSummary = extern struct {
    nid: u32,
    version: u8,
    ofs_in_node: u16,
};

pub const F2fsSummaryFooter = extern struct {
    check_sum: u32,
    entry_type: u8,
};

// ============================================================================
// F2FS Compression
// ============================================================================

pub const F2fsCompressAlgo = enum(u8) {
    lzo = 0,
    lz4 = 1,
    zstd = 2,
    lzorle = 3,
};

pub const F2fsCompressFlags = packed struct(u16) {
    chksum: bool = false,
    _reserved: u15 = 0,
};

pub const F2fsCompressCtx = struct {
    algo: F2fsCompressAlgo,
    log_cluster_size: u8,
    flags: F2fsCompressFlags,
    cluster_idx: u32,
    nr_rpages: u32,
    nr_cpages: u32,
    compressed_size: u64,
    original_size: u64,
};

// ============================================================================
// F2FS GC (Garbage Collection)
// ============================================================================

pub const F2fsGcType = enum(u8) {
    bg_gc = 0,       // background GC
    fg_gc = 1,       // foreground GC
};

pub const F2fsGcPolicy = enum(u8) {
    greedy = 0,
    cost_benefit = 1,
    age_threshold = 2,
};

pub const F2fsGcStats = struct {
    gc_count: u64,
    bg_gc_count: u64,
    fg_gc_count: u64,
    data_segments_freed: u64,
    node_segments_freed: u64,
    blocks_moved: u64,
    gc_time_ms: u64,
};

// ============================================================================
// F2FS Discard
// ============================================================================

pub const F2fsDiscardPolicy = struct {
    type_: F2fsDiscardType,
    min_interval: u32,    // ms
    mid_interval: u32,    // ms
    max_interval: u32,    // ms
    max_requests: u32,
    io_aware: bool,
    sync_: bool,
    ordered: bool,
    granularity: u32,
    timeout: i64,
};

pub const F2fsDiscardType = enum(u8) {
    dpolicy_bg = 0,
    dpolicy_force = 1,
    dpolicy_fstrim = 2,
    dpolicy_umount = 3,
};

// ============================================================================
// F2FS Zone-Aware Allocation (zoned block devices)
// ============================================================================

pub const F2fsZoneInfo = struct {
    total_zones: u32,
    zone_size_blocks: u32,
    zone_size_sectors: u64,
    conventional_zones: u32,
    sequential_zones: u32,
    open_zones: u32,
    active_zones: u32,
    max_open_zones: u32,
};

// ============================================================================
// F2FS Mount Options
// ============================================================================

pub const F2fsMountOpts = packed struct(u64) {
    bg_gc_enable: bool = true,
    discard: bool = true,
    noheap: bool = false,
    nouser_xattr: bool = false,
    noacl: bool = false,
    inline_xattr: bool = false,
    inline_data: bool = false,
    inline_dentry: bool = false,
    flush_merge: bool = true,
    nobarrier: bool = false,
    fastboot: bool = false,
    extent_cache: bool = true,
    noinline_data: bool = false,
    data_flush: bool = false,
    mode_lfs: bool = false,
    mode_adaptive: bool = true,
    io_bits: bool = false,
    usrquota: bool = false,
    grpquota: bool = false,
    prjquota: bool = false,
    atgc: bool = false,         // Age Threshold GC
    gc_merge: bool = false,
    compress_cache: bool = false,
    _reserved: u41 = 0,
};

// ============================================================================
// F2FS Filesystem Manager
// ============================================================================

pub const F2fsFsManager = struct {
    superblock: ?*F2fsSuperblock,
    checkpoint: ?*F2fsCheckpoint,
    features: F2fsFeatureFlags,
    mount_opts: F2fsMountOpts,
    zone_info: ?F2fsZoneInfo,
    gc_stats: F2fsGcStats,
    segment_count: u32,
    free_segments: u32,
    dirty_segments: u32,
    total_valid_blocks: u64,
    total_node_count: u32,
    total_inode_count: u32,
    compress_algo: F2fsCompressAlgo,
    initialized: bool,

    pub fn init() F2fsFsManager {
        return std.mem.zeroes(F2fsFsManager);
    }
};
