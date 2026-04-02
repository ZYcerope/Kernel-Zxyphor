// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust ext4 & Btrfs Structures
// Complete: ext4 superblock, group descriptor, inode, extent tree, journal,
// Btrfs superblock, chunk/device tree, B-tree, snapshot, RAID, scrub

use core::fmt;

// ============================================================================
// ext4 Superblock
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4SuperBlock {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,               // 0xEF53
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // ext4-specific
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    // Journal
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    pub s_jnl_blocks: [u32; 17],
    // 64-bit support
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_count_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
    pub s_raid_stride: u16,
    pub s_mmp_update_interval: u16,
    pub s_mmp_block: u64,
    pub s_raid_stripe_width: u32,
    pub s_log_groups_per_flex: u8,
    pub s_checksum_type: u8,
    pub s_encryption_level: u8,
    pub s_reserved_pad: u8,
    pub s_kbytes_written: u64,
    pub s_snapshot_inum: u32,
    pub s_snapshot_id: u32,
    pub s_snapshot_r_blocks_count: u64,
    pub s_snapshot_list: u32,
    pub s_error_count: u32,
    pub s_first_error_time: u32,
    pub s_first_error_ino: u32,
    pub s_first_error_block: u64,
    pub s_first_error_func: [u8; 32],
    pub s_first_error_line: u32,
    pub s_last_error_time: u32,
    pub s_last_error_ino: u32,
    pub s_last_error_line: u32,
    pub s_last_error_block: u64,
    pub s_last_error_func: [u8; 32],
    pub s_mount_opts: [u8; 64],
    pub s_usr_quota_inum: u32,
    pub s_grp_quota_inum: u32,
    pub s_overhead_blocks: u32,
    pub s_backup_bgs: [u32; 2],
    pub s_encrypt_algos: [u8; 4],
    pub s_encrypt_pw_salt: [u8; 16],
    pub s_lpf_ino: u32,
    pub s_prj_quota_inum: u32,
    pub s_checksum_seed: u32,
    pub s_encoding: u16,
    pub s_encoding_flags: u16,
    pub s_orphan_file_inum: u32,
    pub s_reserved: [u32; 94],
    pub s_checksum: u32,
}

// ============================================================================
// ext4 Group Descriptor
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4GroupDesc {
    pub bg_block_bitmap_lo: u32,
    pub bg_inode_bitmap_lo: u32,
    pub bg_inode_table_lo: u32,
    pub bg_free_blocks_count_lo: u16,
    pub bg_free_inodes_count_lo: u16,
    pub bg_used_dirs_count_lo: u16,
    pub bg_flags: u16,
    pub bg_exclude_bitmap_lo: u32,
    pub bg_block_bitmap_csum_lo: u16,
    pub bg_inode_bitmap_csum_lo: u16,
    pub bg_itable_unused_lo: u16,
    pub bg_checksum: u16,
    // 64-bit fields
    pub bg_block_bitmap_hi: u32,
    pub bg_inode_bitmap_hi: u32,
    pub bg_inode_table_hi: u32,
    pub bg_free_blocks_count_hi: u16,
    pub bg_free_inodes_count_hi: u16,
    pub bg_used_dirs_count_hi: u16,
    pub bg_itable_unused_hi: u16,
    pub bg_exclude_bitmap_hi: u32,
    pub bg_block_bitmap_csum_hi: u16,
    pub bg_inode_bitmap_csum_hi: u16,
    pub bg_reserved: u32,
}

// ============================================================================
// ext4 Inode
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub osd1: u32,
    pub i_block: [u32; 15],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub i_obso_faddr: u32,
    pub osd2: [u8; 12],
    pub i_extra_isize: u16,
    pub i_checksum_hi: u16,
    pub i_ctime_extra: u32,
    pub i_mtime_extra: u32,
    pub i_atime_extra: u32,
    pub i_crtime: u32,
    pub i_crtime_extra: u32,
    pub i_version_hi: u32,
    pub i_projid: u32,
}

pub const EXT4_INODE_FLAGS_SECRM: u32 = 0x00000001;
pub const EXT4_INODE_FLAGS_UNRM: u32 = 0x00000002;
pub const EXT4_INODE_FLAGS_COMPR: u32 = 0x00000004;
pub const EXT4_INODE_FLAGS_SYNC: u32 = 0x00000008;
pub const EXT4_INODE_FLAGS_IMMUTABLE: u32 = 0x00000010;
pub const EXT4_INODE_FLAGS_APPEND: u32 = 0x00000020;
pub const EXT4_INODE_FLAGS_NODUMP: u32 = 0x00000040;
pub const EXT4_INODE_FLAGS_NOATIME: u32 = 0x00000080;
pub const EXT4_INODE_FLAGS_INDEX: u32 = 0x00001000;
pub const EXT4_INODE_FLAGS_JOURNAL_DATA: u32 = 0x00004000;
pub const EXT4_INODE_FLAGS_DIRSYNC: u32 = 0x00010000;
pub const EXT4_INODE_FLAGS_TOPDIR: u32 = 0x00020000;
pub const EXT4_INODE_FLAGS_HUGE_FILE: u32 = 0x00040000;
pub const EXT4_INODE_FLAGS_EXTENTS: u32 = 0x00080000;
pub const EXT4_INODE_FLAGS_VERITY: u32 = 0x00100000;
pub const EXT4_INODE_FLAGS_EA_INODE: u32 = 0x00200000;
pub const EXT4_INODE_FLAGS_INLINE_DATA: u32 = 0x10000000;
pub const EXT4_INODE_FLAGS_PROJINHERIT: u32 = 0x20000000;
pub const EXT4_INODE_FLAGS_CASEFOLD: u32 = 0x40000000;

// ============================================================================
// ext4 Extent Tree
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentHeader {
    pub eh_magic: u16,     // 0xF30A
    pub eh_entries: u16,
    pub eh_max: u16,
    pub eh_depth: u16,
    pub eh_generation: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32,
    pub ei_leaf_lo: u32,
    pub ei_leaf_hi: u16,
    pub ei_unused: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Extent {
    pub ee_block: u32,
    pub ee_len: u16,
    pub ee_start_hi: u16,
    pub ee_start_lo: u32,
}

// ============================================================================
// ext4 Journal (JBD2)
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Jbd2BlockType {
    DescriptorBlock = 1,
    CommitBlock = 2,
    SuperblockV1 = 3,
    SuperblockV2 = 4,
    RevokeBlock = 5,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct JournalHeaderS {
    pub h_magic: u32,       // 0xC03B3998
    pub h_blocktype: u32,
    pub h_sequence: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct JournalSuperblockS {
    pub s_header: JournalHeaderS,
    pub s_blocksize: u32,
    pub s_maxlen: u32,
    pub s_first: u32,
    pub s_sequence: u32,
    pub s_start: u32,
    pub s_errno: i32,
    // V2 fields
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_nr_users: u32,
    pub s_dynsuper: u32,
    pub s_max_transaction: u32,
    pub s_max_trans_data: u32,
    pub s_checksum_type: u8,
    pub s_padding2: [u8; 3],
    pub s_num_fc_blks: u32,
    pub s_head: u32,
    pub s_padding: [u32; 40],
    pub s_checksum: u32,
    pub s_users: [[u8; 16]; 48],
}

// ============================================================================
// Btrfs Superblock
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsSuperBlock {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,          // _BHRfS_M (0x4D5F53665248425F)
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub log_root_transid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub __unused_leafsize: u32,
    pub stripesize: u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub dev_item: BtrfsDevItem,
    pub label: [u8; 256],
    pub cache_generation: u64,
    pub uuid_tree_generation: u64,
    pub metadata_uuid: [u8; 16],
    pub nr_global_roots: u64,
    pub reserved: [u64; 27],
    pub sys_chunk_array: [u8; 2048],
    pub super_roots: [BtrfsRootBackup; 4],
    pub padding: [u8; 565],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsDevItem {
    pub devid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub dev_type: u64,
    pub generation: u64,
    pub start_offset: u64,
    pub dev_group: u32,
    pub seek_speed: u8,
    pub bandwidth: u8,
    pub uuid: [u8; 16],
    pub fsid: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsRootBackup {
    pub tree_root: u64,
    pub tree_root_gen: u64,
    pub chunk_root: u64,
    pub chunk_root_gen: u64,
    pub extent_root: u64,
    pub extent_root_gen: u64,
    pub fs_root: u64,
    pub fs_root_gen: u64,
    pub dev_root: u64,
    pub dev_root_gen: u64,
    pub csum_root: u64,
    pub csum_root_gen: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
    pub unused_64: [u64; 4],
    pub tree_root_level: u8,
    pub chunk_root_level: u8,
    pub extent_root_level: u8,
    pub fs_root_level: u8,
    pub dev_root_level: u8,
    pub csum_root_level: u8,
    pub unused_8: [u8; 10],
}

// ============================================================================
// Btrfs Key & Item
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub key_type: u8,
    pub offset: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BtrfsKeyType {
    InodeItem = 1,
    InodeRef = 12,
    InodeExtref = 13,
    XattrItem = 24,
    OrphanItem = 48,
    DirLogItem = 60,
    DirLogIndex = 72,
    DirItem = 84,
    DirIndex = 96,
    ExtentData = 108,
    ExtentCsum = 128,
    RootItem = 132,
    RootBackref = 144,
    RootRef = 156,
    ExtentItem = 168,
    MetadataItem = 169,
    TreeBlockRef = 176,
    ExtentDataRef = 178,
    SharedBlockRef = 182,
    SharedDataRef = 184,
    BlockGroupItem = 192,
    FreeSpaceInfo = 198,
    FreeSpaceExtent = 199,
    FreeSpaceBitmap = 200,
    DevExtent = 204,
    DevItem = 216,
    ChunkItem = 228,
    QgroupStatus = 240,
    QgroupInfo = 242,
    QgroupLimit = 244,
    QgroupRelation = 246,
    Uuid = 251,
    UuidRecv = 252,
    StringItem = 253,
    PersistentItem = 249,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsHeader {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: [u8; 16],
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsItem {
    pub key: BtrfsKey,
    pub offset: u32,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsKeyPtr {
    pub key: BtrfsKey,
    pub blockptr: u64,
    pub generation: u64,
}

// ============================================================================
// Btrfs Chunk & RAID
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsChunk {
    pub length: u64,
    pub owner: u64,
    pub stripe_len: u64,
    pub chunk_type: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    // Followed by BtrfsStripe[num_stripes]
}

pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1 << 0;
pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 1 << 2;
pub const BTRFS_BLOCK_GROUP_RAID0: u64 = 1 << 3;
pub const BTRFS_BLOCK_GROUP_RAID1: u64 = 1 << 4;
pub const BTRFS_BLOCK_GROUP_DUP: u64 = 1 << 5;
pub const BTRFS_BLOCK_GROUP_RAID10: u64 = 1 << 6;
pub const BTRFS_BLOCK_GROUP_RAID5: u64 = 1 << 7;
pub const BTRFS_BLOCK_GROUP_RAID6: u64 = 1 << 8;
pub const BTRFS_BLOCK_GROUP_RAID1C3: u64 = 1 << 9;
pub const BTRFS_BLOCK_GROUP_RAID1C4: u64 = 1 << 10;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: [u8; 16],
}

// ============================================================================
// Btrfs Subvolume / Snapshot
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsRootItem {
    pub inode: BtrfsInodeItem,
    pub generation: u64,
    pub root_dirid: u64,
    pub bytenr: u64,
    pub byte_limit: u64,
    pub bytes_used: u64,
    pub last_snapshot: u64,
    pub flags: u64,
    pub refs: u32,
    pub drop_progress: BtrfsKey,
    pub drop_level: u8,
    pub level: u8,
    pub generation_v2: u64,
    pub uuid: [u8; 16],
    pub parent_uuid: [u8; 16],
    pub received_uuid: [u8; 16],
    pub ctransid: u64,
    pub otransid: u64,
    pub stransid: u64,
    pub rtransid: u64,
    pub ctime: BtrfsTimespec,
    pub otime: BtrfsTimespec,
    pub stime: BtrfsTimespec,
    pub rtime: BtrfsTimespec,
    pub global_tree_id: u64,
    pub reserved: [u64; 7],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsInodeItem {
    pub generation: u64,
    pub transid: u64,
    pub size: u64,
    pub nbytes: u64,
    pub block_group: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub flags: u64,
    pub sequence: u64,
    pub reserved: [u64; 4],
    pub atime: BtrfsTimespec,
    pub ctime: BtrfsTimespec,
    pub mtime: BtrfsTimespec,
    pub otime: BtrfsTimespec,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsTimespec {
    pub sec: u64,
    pub nsec: u32,
}

// ============================================================================
// Btrfs Scrub
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BtrfsScrubError {
    None = 0,
    Read = 1,
    Super = 2,
    NoSuperFlags = 3,
    Verify = 4,
    Csum = 5,
    Generation = 6,
    Parity = 7,
}

pub struct BtrfsScrubProgress {
    pub data_extents_scrubbed: u64,
    pub tree_extents_scrubbed: u64,
    pub data_bytes_scrubbed: u64,
    pub tree_bytes_scrubbed: u64,
    pub read_errors: u64,
    pub csum_errors: u64,
    pub verify_errors: u64,
    pub no_csum: u64,
    pub csum_discards: u64,
    pub super_errors: u64,
    pub malloc_errors: u64,
    pub uncorrectable_errors: u64,
    pub corrected_errors: u64,
    pub last_physical: u64,
    pub unverified_errors: u64,
}

// ============================================================================
// Statistics
// ============================================================================

pub struct Ext4BtrfsStats {
    pub ext4_mounts: u64,
    pub ext4_total_inodes: u64,
    pub ext4_total_blocks: u64,
    pub ext4_journal_commits: u64,
    pub btrfs_mounts: u64,
    pub btrfs_total_subvolumes: u64,
    pub btrfs_total_snapshots: u64,
    pub btrfs_scrub_runs: u64,
    pub btrfs_balance_runs: u64,
}

impl Ext4BtrfsStats {
    pub const fn new() Self {
        Self {
            ext4_mounts: 0,
            ext4_total_inodes: 0,
            ext4_total_blocks: 0,
            ext4_journal_commits: 0,
            btrfs_mounts: 0,
            btrfs_total_subvolumes: 0,
            btrfs_total_snapshots: 0,
            btrfs_scrub_runs: 0,
            btrfs_balance_runs: 0,
        }
    }
}
