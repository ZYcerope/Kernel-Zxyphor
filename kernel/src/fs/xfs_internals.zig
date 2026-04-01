// Zxyphor Kernel - XFS Internals
// On-disk format, AG headers, inode format,
// B+tree structures, journal/log, allocation groups,
// extent format, directory format, ACL, quota,
// reflink, reverse mapping, DAX, realtime subvolume
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

pub const XFS_MAGIC: u32 = 0x58465342; // "XFSB"

// ============================================================================
// XFS Superblock (on-disk, sector 0 of AG 0)
// ============================================================================

pub const XfsSuperblock = extern struct {
    sb_magicnum: u32,
    sb_blocksize: u32,
    sb_dblocks: u64,       // total data blocks
    sb_rblocks: u64,       // realtime blocks
    sb_rextents: u64,      // realtime extents
    sb_uuid: [16]u8,
    sb_logstart: u64,      // log start block (internal log)
    sb_rootino: u64,       // root inode number
    sb_rbmino: u64,        // realtime bitmap inode
    sb_rsumino: u64,       // realtime summary inode
    sb_rextsize: u32,      // realtime extent size (blocks)
    sb_agblocks: u32,      // blocks per AG
    sb_agcount: u32,       // number of AGs
    sb_rbmblocks: u32,     // bitmap blocks for RT
    sb_logblocks: u32,     // log blocks
    sb_versionnum: u16,    // version flags
    sb_sectsize: u16,      // sector size (bytes)
    sb_inodesize: u16,     // inode size (bytes)
    sb_inopblock: u16,     // inodes per block
    sb_fname: [12]u8,      // filesystem name
    sb_blocklog: u8,
    sb_sectlog: u8,
    sb_inodelog: u8,
    sb_inopblog: u8,
    sb_agblklog: u8,
    sb_rextslog: u8,
    sb_inprogress: u8,
    sb_imax_pct: u8,       // max inode percentage
    sb_icount: u64,        // allocated inodes
    sb_ifree: u64,         // free inodes
    sb_fdblocks: u64,      // free data blocks
    sb_frextents: u64,     // free realtime extents
    sb_uquotino: u64,      // user quota inode
    sb_gquotino: u64,      // group quota inode
    sb_qflags: u16,        // quota flags
    sb_flags: u8,
    sb_shared_vn: u8,
    sb_inoalignmt: u32,
    sb_unit: u32,
    sb_width: u32,
    sb_dirblklog: u8,
    sb_logsectlog: u8,
    sb_logsectsize: u16,
    sb_logsunit: u32,
    sb_features2: u32,
    sb_bad_features2: u32,
    // V5 superblock fields
    sb_features_compat: u32,
    sb_features_ro_compat: u32,
    sb_features_incompat: u32,
    sb_features_log_incompat: u32,
    sb_crc: u32,
    sb_spino_align: u32,
    sb_pquotino: u64,      // project quota inode
    sb_lsn: u64,           // last write sequence
    sb_meta_uuid: [16]u8,  // metadata UUID
};

// ============================================================================
// XFS On-disk Feature Flags
// ============================================================================

pub const XfsIncompatFlags = packed struct(u32) {
    ftype: bool = false,        // directory ftype
    spinodes: bool = false,     // sparse inodes
    meta_uuid: bool = false,    // metadata UUID
    bigtime: bool = false,      // large timestamps
    needsrepair: bool = false,  // needs repair flag
    nrext64: bool = false,      // large extent counts
    exchange_range: bool = false,
    parent: bool = false,       // parent pointers
    _reserved: u24 = 0,
};

pub const XfsRoCompatFlags = packed struct(u32) {
    finobt: bool = false,       // free inode B+tree
    rmapbt: bool = false,       // reverse mapping B+tree
    reflink: bool = false,      // reflink/CoW
    inobtcnt: bool = false,     // inobt block counts
    _reserved: u28 = 0,
};

// ============================================================================
// Allocation Group Header (AGF)
// ============================================================================

pub const XfsAgf = extern struct {
    agf_magicnum: u32,          // 0x58414746 "XAGF"
    agf_versionnum: u32,
    agf_seqno: u32,             // AG number
    agf_length: u32,            // AG size in blocks
    agf_roots: [3]u32,          // B+tree roots (BNO, CNT, RMAP)
    agf_levels: [3]u32,         // B+tree levels
    agf_flfirst: u32,           // freelist first
    agf_fllast: u32,            // freelist last
    agf_flcount: u32,           // freelist count
    agf_freeblks: u32,          // free blocks
    agf_longest: u32,           // longest free extent
    agf_btreeblks: u32,         // blocks in B+trees
    agf_uuid: [16]u8,
    agf_rmap_blocks: u32,       // rmap B+tree blocks
    agf_refcount_blocks: u32,   // refcount B+tree blocks
    agf_refcount_root: u32,     // refcount B+tree root
    agf_refcount_level: u32,    // refcount B+tree level
    _spare: u64,
    agf_lsn: u64,
    agf_crc: u32,
    _pad: u32,
};

// ============================================================================
// Allocation Group Inode Header (AGI)
// ============================================================================

pub const XfsAgi = extern struct {
    agi_magicnum: u32,          // 0x58414749 "XAGI"
    agi_versionnum: u32,
    agi_seqno: u32,
    agi_length: u32,
    agi_count: u32,             // allocated inodes
    agi_root: u32,              // inobt root
    agi_level: u32,             // inobt levels
    agi_freecount: u32,         // free inodes
    agi_newino: u32,            // last allocated inode
    agi_dirino: u32,            // deprecated
    agi_unlinked: [64]u32,      // unlinked inode hash
    agi_uuid: [16]u8,
    agi_crc: u32,
    _pad: u32,
    agi_lsn: u64,
    agi_free_root: u32,         // finobt root
    agi_free_level: u32,        // finobt levels
    agi_iblocks: u32,           // inobt block count
    agi_fblocks: u32,           // finobt block count
};

// ============================================================================
// XFS Inode On-Disk Format
// ============================================================================

pub const XFS_DINODE_MAGIC: u16 = 0x494E; // "IN"

pub const XfsDinode = extern struct {
    di_magic: u16,
    di_mode: u16,
    di_version: u8,
    di_format: u8,
    di_onlink: u16,
    di_uid: u32,
    di_gid: u32,
    di_nlink: u32,
    di_projid_lo: u16,
    di_projid_hi: u16,
    _pad: [6]u8,
    di_flushiter: u16,
    di_atime: XfsTimestamp,
    di_mtime: XfsTimestamp,
    di_ctime: XfsTimestamp,
    di_size: u64,
    di_nblocks: u64,
    di_extsize: u32,
    di_nextents: u32,
    di_anextents: u16,
    di_forkoff: u8,
    di_aformat: u8,
    di_dmevmask: u32,
    di_dmstate: u16,
    di_flags: u16,
    di_gen: u32,
    // V3 inode fields
    di_next_unlinked: u32,
    di_crc: u32,
    di_changecount: u64,
    di_lsn: u64,
    di_flags2: u64,
    di_cowextsize: u32,
    _pad2: [12]u8,
    di_crtime: XfsTimestamp,
    di_ino: u64,
    di_uuid: [16]u8,
};

pub const XfsTimestamp = extern struct {
    t_sec: i32,
    t_nsec: i32,
};

pub const XfsInodeFormat = enum(u8) {
    dev = 0,
    local = 1,       // inline data
    extents = 2,     // extent list
    btree = 3,       // B+tree of extents
    uuid = 4,        // reserved
    rmap = 5,        // reserved for rmap
};

pub const XfsInodeFlags = packed struct(u16) {
    realtime: bool = false,
    prealloc: bool = false,
    newrtbm: bool = false,
    immutable: bool = false,
    append: bool = false,
    sync_: bool = false,
    noatime: bool = false,
    nodump: bool = false,
    rtinherit: bool = false,
    projinherit: bool = false,
    nosymlinks: bool = false,
    extsize: bool = false,
    extszinherit: bool = false,
    nodefrag: bool = false,
    filestream: bool = false,
    _reserved: bool = false,
};

pub const XfsInodeFlags2 = packed struct(u64) {
    dax: bool = false,
    reflink: bool = false,
    cowextsize: bool = false,
    bigtime: bool = false,
    nrext64: bool = false,
    _reserved: u59 = 0,
};

// ============================================================================
// XFS Extent (B+tree record, on-disk)
// ============================================================================

pub const XfsBmbtRec = extern struct {
    l0: u64,  // startoff (54 bits) | flag (1 bit) | startblock (52 bits split)
    l1: u64,  // blockcount (21 bits) | startblock low (43 bits)

    pub fn startoff(self: *const XfsBmbtRec) u64 {
        return self.l0 >> 9;
    }

    pub fn startblock(self: *const XfsBmbtRec) u64 {
        return ((self.l0 & 0x1FF) << 43) | (self.l1 >> 21);
    }

    pub fn blockcount(self: *const XfsBmbtRec) u21 {
        return @truncate(self.l1 & 0x1FFFFF);
    }

    pub fn isUnwritten(self: *const XfsBmbtRec) bool {
        return (self.l0 & (1 << 63)) != 0;
    }
};

// ============================================================================
// XFS B+tree Node (short / long form)
// ============================================================================

pub const XfsBtreeBlockShort = extern struct {
    bb_magic: u32,
    bb_level: u16,
    bb_numrecs: u16,
    bb_leftsib: u32,
    bb_rightsib: u32,
    bb_blkno: u64,
    bb_lsn: u64,
    bb_uuid: [16]u8,
    bb_owner: u32,
    bb_crc: u32,
};

pub const XfsBtreeBlockLong = extern struct {
    bb_magic: u32,
    bb_level: u16,
    bb_numrecs: u16,
    bb_leftsib: u64,
    bb_rightsib: u64,
    bb_blkno: u64,
    bb_lsn: u64,
    bb_uuid: [16]u8,
    bb_owner: u64,
    bb_crc: u32,
    _pad: u32,
};

// ============================================================================
// XFS Directory Format
// ============================================================================

pub const XfsDirFormat = enum(u8) {
    sf = 0,       // short form (inline in inode)
    block = 1,    // single block directory
    leaf = 2,     // leaf form
    node = 3,     // full B+tree
    btree = 4,    // equivalent to node
};

pub const XfsDirSfEntry = extern struct {
    namelen: u8,
    offset: [2]u8,
    // name[namelen] follows
    // optional ftype byte
    // inumber (4 or 8 bytes) follows
};

pub const XfsDir2DataEntry = extern struct {
    inumber: u64,
    namelen: u8,
    // name[namelen] follows
    // optional ftype
    // tag (last 2 bytes)
};

pub const XfsDirFtype = enum(u8) {
    unknown = 0,
    reg_file = 1,
    dir = 2,
    chrdev = 3,
    blkdev = 4,
    fifo = 5,
    socket = 6,
    symlink = 7,
    whiteout = 8,
};

// ============================================================================
// XFS Journal/Log (XFS Log)
// ============================================================================

pub const XFS_LOG_MAGIC: u32 = 0xFEEDbabe;

pub const XLogRecHeader = extern struct {
    h_magicno: u32,
    h_cycle: u32,
    h_version: u32,
    h_len: u32,
    h_lsn: u64,
    h_tail_lsn: u64,
    h_crc: u32,
    h_prev_block: u32,
    h_num_logops: u32,
    h_cycle_data: [256]u32, // CRC cycle data
    h_fmt: u32,
    h_fs_uuid: [16]u8,
    h_size: u32,
};

pub const XLogOpType = enum(u16) {
    buffer_data = 0x0001,
    inode_data = 0x0002,
    dquot_data = 0x0004,
    efi_data = 0x0008,
    efd_data = 0x0010,
    iunlink_data = 0x0020,
    buf_cancel = 0x0040,
    inode_create = 0x0080,
    rui_data = 0x0100,
    rud_data = 0x0200,
    cui_data = 0x0400,
    cud_data = 0x0800,
    bui_data = 0x1000,
    bud_data = 0x2000,
    attri_data = 0x4000,
    attrd_data = 0x8000,
};

// ============================================================================
// XFS Reverse Mapping B+tree (rmapbt)
// ============================================================================

pub const XfsRmapRec = extern struct {
    rm_startblock: u32,
    rm_blockcount: u32,
    rm_owner: u64,         // inode or special owner
    rm_offset: u64,        // file offset (high bits are flags)
};

pub const XfsRmapOwner = enum(i64) {
    free = -1,
    unknown = -2,
    fs = -3,
    log = -4,
    ag = -5,
    inobt = -6,
    inodes = -7,
    refc = -8,
    cow = -9,
};

// ============================================================================
// XFS Reference Count B+tree (refcountbt)
// ============================================================================

pub const XfsRefcountRec = extern struct {
    rc_startblock: u32,
    rc_blockcount: u32,
    rc_refcount: u32,
};

// ============================================================================
// XFS Quota
// ============================================================================

pub const XfsDqblk = extern struct {
    d_magic: u16,
    d_version: u8,
    d_type: u8,
    d_id: u32,
    d_blk_hardlimit: u64,
    d_blk_softlimit: u64,
    d_ino_hardlimit: u64,
    d_ino_softlimit: u64,
    d_bcount: u64,
    d_icount: u64,
    d_itimer: u32,
    d_btimer: u32,
    d_iwarns: u16,
    d_bwarns: u16,
    _pad0: u32,
    d_rtb_hardlimit: u64,
    d_rtb_softlimit: u64,
    d_rtbcount: u64,
    d_rtbtimer: u32,
    d_rtbwarns: u16,
    _pad1: u16,
    d_lsn: u64,
};

// ============================================================================
// XFS Allocation Strategies
// ============================================================================

pub const XfsAllocType = enum(u8) {
    any_ag = 0,
    start_ag = 1,
    this_ag = 2,
    first_ag = 3,
    start_bno = 4,
    near_bno = 5,
    this_bno = 6,
    exact_bno = 7,
};

// ============================================================================
// XFS Mount Options
// ============================================================================

pub const XfsMountOpts = packed struct(u64) {
    wsync: bool = false,
    noalign: bool = false,
    allocsize: bool = false,
    largeio: bool = false,
    attr2: bool = false,
    filestreams: bool = false,
    grpid: bool = false,
    discard: bool = false,
    lazytime: bool = false,
    dax_always: bool = false,
    dax_never: bool = false,
    norecovery: bool = false,
    nouuid: bool = false,
    ikeep: bool = false,
    swalloc: bool = false,
    _reserved: u49 = 0,
};

// ============================================================================
// XFS Online Repair / Scrub
// ============================================================================

pub const XfsScrubType = enum(u32) {
    probe = 0,
    superblock = 1,
    agf = 2,
    agfl = 3,
    agi = 4,
    bnobt = 5,
    cntbt = 6,
    inobt = 7,
    finobt = 8,
    rmapbt = 9,
    refcountbt = 10,
    inode = 11,
    bmapbtd = 12,
    bmapbta = 13,
    directory = 14,
    xattr = 15,
    symlink = 16,
    parent = 17,
    quotacheck = 18,
    nlinks = 19,
    fscounters = 20,
};

pub const XfsScrubFlags = packed struct(u32) {
    repair: bool = false,
    oflag_corrupt: bool = false,
    oflag_preen: bool = false,
    oflag_xfail: bool = false,
    oflag_xcorrupt: bool = false,
    oflag_incomplete: bool = false,
    oflag_warning: bool = false,
    force_rebuild: bool = false,
    _reserved: u24 = 0,
};

// ============================================================================
// XFS Manager
// ============================================================================

pub const XfsFsManager = struct {
    superblock: ?*XfsSuperblock,
    ag_count: u32,
    block_size: u32,
    inode_size: u16,
    has_reflink: bool,
    has_rmapbt: bool,
    has_finobt: bool,
    has_bigtime: bool,
    log_start: u64,
    log_blocks: u32,
    mount_opts: XfsMountOpts,
    initialized: bool,

    pub fn init() XfsFsManager {
        return std.mem.zeroes(XfsFsManager);
    }
};
