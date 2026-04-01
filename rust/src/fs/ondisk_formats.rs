// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced Filesystem: ext4-compatible, XFS-compatible, Btrfs-compatible
// Production-quality filesystem implementations with journaling, extent trees, CoW

#![no_std]
#![allow(dead_code)]

// ============================================================================
// ext4 On-Disk Structures
// ============================================================================

pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;
pub const EXT4_BLOCK_SIZE_MIN: u32 = 1024;
pub const EXT4_BLOCK_SIZE_MAX: u32 = 65536;
pub const EXT4_NDIR_BLOCKS: usize = 12;
pub const EXT4_IND_BLOCK: usize = 12;
pub const EXT4_DIND_BLOCK: usize = 13;
pub const EXT4_TIND_BLOCK: usize = 14;
pub const EXT4_N_BLOCKS: usize = 15;

// ext4 Superblock
#[repr(C)]
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
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // Extended fields (rev 1+)
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
    // Performance hints
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    // Journaling
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
    pub s_overhead_clusters: u32,
    pub s_backup_bgs: [u32; 2],
    pub s_encrypt_algos: [u8; 4],
    pub s_encrypt_pw_salt: [u8; 16],
    pub s_lpf_ino: u32,
    pub s_prj_quota_inum: u32,
    pub s_checksum_seed: u32,
    pub s_wtime_hi: u8,
    pub s_mtime_hi: u8,
    pub s_mkfs_time_hi: u8,
    pub s_lastcheck_hi: u8,
    pub s_first_error_time_hi: u8,
    pub s_last_error_time_hi: u8,
    pub s_first_error_errcode: u8,
    pub s_last_error_errcode: u8,
    pub s_encoding: u16,
    pub s_encoding_flags: u16,
    pub s_orphan_file_inum: u32,
    pub s_reserved: [u32; 94],
    pub s_checksum: u32,
}

impl Ext4SuperBlock {
    pub fn block_size(&self) -> u64 {
        1024u64 << self.s_log_block_size
    }

    pub fn blocks_count(&self) -> u64 {
        ((self.s_blocks_count_hi as u64) << 32) | (self.s_blocks_count_lo as u64)
    }

    pub fn free_blocks_count(&self) -> u64 {
        ((self.s_free_blocks_count_hi as u64) << 32) | (self.s_free_blocks_count_lo as u64)
    }

    pub fn is_valid(&self) -> bool {
        self.s_magic == EXT4_SUPER_MAGIC
    }

    pub fn has_feature_compat(&self, feature: u32) -> bool {
        (self.s_feature_compat & feature) != 0
    }

    pub fn has_feature_incompat(&self, feature: u32) -> bool {
        (self.s_feature_incompat & feature) != 0
    }

    pub fn has_feature_ro_compat(&self, feature: u32) -> bool {
        (self.s_feature_ro_compat & feature) != 0
    }

    pub fn group_count(&self) -> u32 {
        let blocks = self.blocks_count();
        let blocks_per_group = self.s_blocks_per_group as u64;
        if blocks_per_group == 0 { return 0; }
        ((blocks - self.s_first_data_block as u64 + blocks_per_group - 1)
            / blocks_per_group) as u32
    }
}

// ext4 Compatible Features
pub const EXT4_FEATURE_COMPAT_DIR_PREALLOC: u32 = 0x0001;
pub const EXT4_FEATURE_COMPAT_IMAGIC_INODES: u32 = 0x0002;
pub const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;
pub const EXT4_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;
pub const EXT4_FEATURE_COMPAT_RESIZE_INODE: u32 = 0x0010;
pub const EXT4_FEATURE_COMPAT_DIR_INDEX: u32 = 0x0020;
pub const EXT4_FEATURE_COMPAT_SPARSE_SUPER2: u32 = 0x0200;
pub const EXT4_FEATURE_COMPAT_FAST_COMMIT: u32 = 0x0400;
pub const EXT4_FEATURE_COMPAT_STABLE_INODES: u32 = 0x0800;
pub const EXT4_FEATURE_COMPAT_ORPHAN_FILE: u32 = 0x1000;

// ext4 Incompatible Features
pub const EXT4_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001;
pub const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
pub const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
pub const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;
pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub const EXT4_FEATURE_INCOMPAT_EA_INODE: u32 = 0x0400;
pub const EXT4_FEATURE_INCOMPAT_DIRDATA: u32 = 0x1000;
pub const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;
pub const EXT4_FEATURE_INCOMPAT_LARGEDIR: u32 = 0x4000;
pub const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
pub const EXT4_FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;
pub const EXT4_FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;

// Read-Only Compatible Features
pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const EXT4_FEATURE_RO_COMPAT_BTREE_DIR: u32 = 0x0004;
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const EXT4_FEATURE_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub const EXT4_FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x0020;
pub const EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
pub const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
pub const EXT4_FEATURE_RO_COMPAT_BIGALLOC: u32 = 0x0200;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub const EXT4_FEATURE_RO_COMPAT_READONLY: u32 = 0x1000;
pub const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = 0x2000;
pub const EXT4_FEATURE_RO_COMPAT_VERITY: u32 = 0x8000;
pub const EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT: u32 = 0x10000;

// ext4 Inode
#[repr(C)]
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
    pub i_osd1: u32,
    pub i_block: [u32; EXT4_N_BLOCKS],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub i_obso_faddr: u32,
    pub i_osd2: [u8; 12],
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

impl Ext4Inode {
    pub fn size(&self) -> u64 {
        ((self.i_size_high as u64) << 32) | (self.i_size_lo as u64)
    }

    pub fn is_dir(&self) -> bool {
        (self.i_mode & 0xF000) == 0x4000
    }

    pub fn is_regular(&self) -> bool {
        (self.i_mode & 0xF000) == 0x8000
    }

    pub fn is_symlink(&self) -> bool {
        (self.i_mode & 0xF000) == 0xA000
    }

    pub fn has_extents(&self) -> bool {
        (self.i_flags & EXT4_EXTENTS_FL) != 0
    }

    pub fn has_inline_data(&self) -> bool {
        (self.i_flags & EXT4_INLINE_DATA_FL) != 0
    }
}

// Inode Flags
pub const EXT4_SECRM_FL: u32 = 0x00000001;
pub const EXT4_UNRM_FL: u32 = 0x00000002;
pub const EXT4_COMPR_FL: u32 = 0x00000004;
pub const EXT4_SYNC_FL: u32 = 0x00000008;
pub const EXT4_IMMUTABLE_FL: u32 = 0x00000010;
pub const EXT4_APPEND_FL: u32 = 0x00000020;
pub const EXT4_NODUMP_FL: u32 = 0x00000040;
pub const EXT4_NOATIME_FL: u32 = 0x00000080;
pub const EXT4_DIRTY_FL: u32 = 0x00000100;
pub const EXT4_COMPRBLK_FL: u32 = 0x00000200;
pub const EXT4_NOCOMPR_FL: u32 = 0x00000400;
pub const EXT4_ENCRYPT_FL: u32 = 0x00000800;
pub const EXT4_INDEX_FL: u32 = 0x00001000;
pub const EXT4_IMAGIC_FL: u32 = 0x00002000;
pub const EXT4_JOURNAL_DATA_FL: u32 = 0x00004000;
pub const EXT4_NOTAIL_FL: u32 = 0x00008000;
pub const EXT4_DIRSYNC_FL: u32 = 0x00010000;
pub const EXT4_TOPDIR_FL: u32 = 0x00020000;
pub const EXT4_HUGE_FILE_FL: u32 = 0x00040000;
pub const EXT4_EXTENTS_FL: u32 = 0x00080000;
pub const EXT4_VERITY_FL: u32 = 0x00100000;
pub const EXT4_EA_INODE_FL: u32 = 0x00200000;
pub const EXT4_DAX_FL: u32 = 0x02000000;
pub const EXT4_INLINE_DATA_FL: u32 = 0x10000000;
pub const EXT4_PROJINHERIT_FL: u32 = 0x20000000;
pub const EXT4_CASEFOLD_FL: u32 = 0x40000000;

// ext4 Extent Header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentHeader {
    pub eh_magic: u16,      // 0xF30A
    pub eh_entries: u16,
    pub eh_max: u16,
    pub eh_depth: u16,
    pub eh_generation: u32,
}

pub const EXT4_EXT_MAGIC: u16 = 0xF30A;

// ext4 Extent
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ext4Extent {
    pub ee_block: u32,      // First logical block
    pub ee_len: u16,        // Number of blocks
    pub ee_start_hi: u16,   // Upper 16 bits of physical block
    pub ee_start_lo: u32,   // Lower 32 bits of physical block
}

impl Ext4Extent {
    pub fn start_block(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | (self.ee_start_lo as u64)
    }

    pub fn is_unwritten(&self) -> bool {
        self.ee_len > 32768 // MSB is the unwritten flag
    }

    pub fn len(&self) -> u32 {
        (self.ee_len & 0x7FFF) as u32
    }
}

// ext4 Extent Index (internal node)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32,
    pub ei_leaf_lo: u32,
    pub ei_leaf_hi: u16,
    pub ei_unused: u16,
}

impl Ext4ExtentIdx {
    pub fn leaf_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | (self.ei_leaf_lo as u64)
    }
}

// ext4 Group Descriptor
#[repr(C)]
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
    // 64-bit extension
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

impl Ext4GroupDesc {
    pub fn block_bitmap(&self) -> u64 {
        ((self.bg_block_bitmap_hi as u64) << 32) | (self.bg_block_bitmap_lo as u64)
    }

    pub fn inode_bitmap(&self) -> u64 {
        ((self.bg_inode_bitmap_hi as u64) << 32) | (self.bg_inode_bitmap_lo as u64)
    }

    pub fn inode_table(&self) -> u64 {
        ((self.bg_inode_table_hi as u64) << 32) | (self.bg_inode_table_lo as u64)
    }

    pub fn free_blocks_count(&self) -> u32 {
        ((self.bg_free_blocks_count_hi as u32) << 16) | (self.bg_free_blocks_count_lo as u32)
    }

    pub fn free_inodes_count(&self) -> u32 {
        ((self.bg_free_inodes_count_hi as u32) << 16) | (self.bg_free_inodes_count_lo as u32)
    }
}

// ext4 Directory Entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ext4DirEntry2 {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name: [u8; 255],
}

pub const EXT4_FT_UNKNOWN: u8 = 0;
pub const EXT4_FT_REG_FILE: u8 = 1;
pub const EXT4_FT_DIR: u8 = 2;
pub const EXT4_FT_CHRDEV: u8 = 3;
pub const EXT4_FT_BLKDEV: u8 = 4;
pub const EXT4_FT_FIFO: u8 = 5;
pub const EXT4_FT_SOCK: u8 = 6;
pub const EXT4_FT_SYMLINK: u8 = 7;

// ============================================================================
// JBD2 Journal
// ============================================================================

pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B3998;

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum JournalBlockType {
    DescriptorBlock = 1,
    CommitBlock = 2,
    SuperblockV1 = 3,
    SuperblockV2 = 4,
    RevokeBlock = 5,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalHeader {
    pub h_magic: u32,
    pub h_blocktype: u32,
    pub h_sequence: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalSuperblock {
    pub s_header: JournalHeader,
    pub s_blocksize: u32,
    pub s_maxlen: u32,
    pub s_first: u32,
    pub s_sequence: u32,
    pub s_start: u32,
    pub s_errno: u32,
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

// Journal Transaction States
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Running = 0,
    Locked = 1,
    Flush = 2,
    Commit = 3,
    CommitDflush = 4,
    CommitJflush = 5,
    CommitCallback = 6,
    Finished = 7,
}

pub struct JournalTransaction {
    pub tid: u32,
    pub state: TransactionState,
    pub t_log_start: u64,
    pub t_nr_buffers: u32,
    pub t_outstanding_credits: i32,
    pub t_max_wait: u64,
    pub t_start: u64,
    pub t_requested: u64,
    pub t_expires: u64,
}

// ============================================================================
// XFS On-Disk Structures
// ============================================================================

pub const XFS_SB_MAGIC: u32 = 0x58465342; // "XFSB"

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XfsSuperBlock {
    pub sb_magicnum: u32,
    pub sb_blocksize: u32,
    pub sb_dblocks: u64,
    pub sb_rblocks: u64,
    pub sb_rextents: u64,
    pub sb_uuid: [u8; 16],
    pub sb_logstart: u64,
    pub sb_rootino: u64,
    pub sb_rbmino: u64,
    pub sb_rsumino: u64,
    pub sb_rextsize: u32,
    pub sb_agblocks: u32,
    pub sb_agcount: u32,
    pub sb_rbmblocks: u32,
    pub sb_logblocks: u32,
    pub sb_versionnum: u16,
    pub sb_sectsize: u16,
    pub sb_inodesize: u16,
    pub sb_inopblock: u16,
    pub sb_fname: [u8; 12],
    pub sb_blocklog: u8,
    pub sb_sectlog: u8,
    pub sb_inodelog: u8,
    pub sb_inopblog: u8,
    pub sb_agblklog: u8,
    pub sb_rextslog: u8,
    pub sb_inprogress: u8,
    pub sb_imax_pct: u8,
    pub sb_icount: u64,
    pub sb_ifree: u64,
    pub sb_fdblocks: u64,
    pub sb_frextents: u64,
    pub sb_uquotino: u64,
    pub sb_gquotino: u64,
    pub sb_qflags: u16,
    pub sb_flags: u8,
    pub sb_shared_vn: u8,
    pub sb_inoalignmt: u32,
    pub sb_unit: u32,
    pub sb_width: u32,
    pub sb_dirblklog: u8,
    pub sb_logsectlog: u8,
    pub sb_logsectsize: u16,
    pub sb_logsunit: u32,
    pub sb_features2: u32,
    pub sb_bad_features2: u32,
    // V5 features
    pub sb_features_compat: u32,
    pub sb_features_ro_compat: u32,
    pub sb_features_incompat: u32,
    pub sb_features_log_incompat: u32,
    pub sb_crc: u32,
    pub sb_spino_align: u32,
    pub sb_pquotino: u64,
    pub sb_lsn: u64,
    pub sb_meta_uuid: [u8; 16],
}

impl XfsSuperBlock {
    pub fn is_valid(&self) -> bool {
        self.sb_magicnum == XFS_SB_MAGIC
    }

    pub fn total_blocks(&self) -> u64 {
        self.sb_dblocks
    }

    pub fn free_blocks(&self) -> u64 {
        self.sb_fdblocks
    }
}

// XFS B+Tree structures
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XfsBtreeBlockShort {
    pub bb_magic: u32,
    pub bb_level: u16,
    pub bb_numrecs: u16,
    pub bb_leftsib: u32,
    pub bb_rightsib: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XfsBtreeBlockLong {
    pub bb_magic: u32,
    pub bb_level: u16,
    pub bb_numrecs: u16,
    pub bb_leftsib: u64,
    pub bb_rightsib: u64,
    pub bb_blkno: u64,
    pub bb_lsn: u64,
    pub bb_uuid: [u8; 16],
    pub bb_owner: u64,
    pub bb_crc: u32,
    pub bb_pad: u32,
}

// XFS AG (Allocation Group) Header
pub const XFS_AGF_MAGIC: u32 = 0x58414746; // "XAGF"
pub const XFS_AGI_MAGIC: u32 = 0x58414749; // "XAGI"

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XfsAgf {
    pub agf_magicnum: u32,
    pub agf_versionnum: u32,
    pub agf_seqno: u32,
    pub agf_length: u32,
    pub agf_roots: [u32; 2],      // Bno and Cnt B+tree roots
    pub agf_levels: [u32; 2],
    pub agf_flfirst: u32,
    pub agf_fllast: u32,
    pub agf_flcount: u32,
    pub agf_freeblks: u32,
    pub agf_longest: u32,
    pub agf_btreeblks: u32,
    pub agf_uuid: [u8; 16],
    pub agf_rmap_blocks: u32,
    pub agf_refcount_blocks: u32,
    pub agf_refcount_root: u32,
    pub agf_refcount_level: u32,
    pub agf_spare64: [u64; 15],
    pub agf_lsn: u64,
    pub agf_crc: u32,
    pub agf_spare2: u32,
}

// ============================================================================
// Btrfs On-Disk Structures
// ============================================================================

pub const BTRFS_MAGIC: u64 = 0x4D5F53665248425F; // "_BHRfS_M"
pub const BTRFS_SUPER_INFO_OFFSET: u64 = 0x10000; // 64KB

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BtrfsSuperBlock {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,
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
    pub leafsize: u32,
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

impl BtrfsSuperBlock {
    pub fn is_valid(&self) -> bool {
        self.magic == BTRFS_MAGIC
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BtrfsDevItem {
    pub devid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub type_field: u64,
    pub generation: u64,
    pub start_offset: u64,
    pub dev_group: u32,
    pub seek_speed: u8,
    pub bandwidth: u8,
    pub uuid: [u8; 16],
    pub fsid: [u8; 16],
}

#[repr(C)]
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

// Btrfs Key
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub type_field: u8,
    pub offset: u64,
}

// Btrfs Item Types
pub const BTRFS_INODE_ITEM_KEY: u8 = 1;
pub const BTRFS_INODE_REF_KEY: u8 = 12;
pub const BTRFS_INODE_EXTREF_KEY: u8 = 13;
pub const BTRFS_XATTR_ITEM_KEY: u8 = 24;
pub const BTRFS_DIR_LOG_ITEM_KEY: u8 = 60;
pub const BTRFS_DIR_LOG_INDEX_KEY: u8 = 72;
pub const BTRFS_DIR_ITEM_KEY: u8 = 84;
pub const BTRFS_DIR_INDEX_KEY: u8 = 96;
pub const BTRFS_EXTENT_DATA_KEY: u8 = 108;
pub const BTRFS_EXTENT_CSUM_KEY: u8 = 128;
pub const BTRFS_ROOT_ITEM_KEY: u8 = 132;
pub const BTRFS_ROOT_BACKREF_KEY: u8 = 144;
pub const BTRFS_ROOT_REF_KEY: u8 = 156;
pub const BTRFS_EXTENT_ITEM_KEY: u8 = 168;
pub const BTRFS_METADATA_ITEM_KEY: u8 = 169;
pub const BTRFS_TREE_BLOCK_REF_KEY: u8 = 176;
pub const BTRFS_EXTENT_DATA_REF_KEY: u8 = 178;
pub const BTRFS_SHARED_BLOCK_REF_KEY: u8 = 182;
pub const BTRFS_SHARED_DATA_REF_KEY: u8 = 184;
pub const BTRFS_BLOCK_GROUP_ITEM_KEY: u8 = 192;
pub const BTRFS_FREE_SPACE_INFO_KEY: u8 = 198;
pub const BTRFS_FREE_SPACE_EXTENT_KEY: u8 = 199;
pub const BTRFS_FREE_SPACE_BITMAP_KEY: u8 = 200;
pub const BTRFS_DEV_EXTENT_KEY: u8 = 204;
pub const BTRFS_DEV_ITEM_KEY: u8 = 216;
pub const BTRFS_CHUNK_ITEM_KEY: u8 = 228;
pub const BTRFS_QGROUP_STATUS_KEY: u8 = 240;
pub const BTRFS_QGROUP_INFO_KEY: u8 = 242;
pub const BTRFS_QGROUP_LIMIT_KEY: u8 = 244;
pub const BTRFS_QGROUP_RELATION_KEY: u8 = 246;

// Btrfs Chunk Types (RAID profiles)
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

// Btrfs Node Header
#[repr(C)]
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

// Btrfs Leaf Item
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BtrfsItem {
    pub key: BtrfsKey,
    pub offset: u32,
    pub size: u32,
}

// Btrfs Inode Item
#[repr(C)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BtrfsTimespec {
    pub sec: u64,
    pub nsec: u32,
}

// Btrfs Extent Data
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BtrfsFileExtentType {
    Inline = 0,
    Regular = 1,
    Prealloc = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BtrfsFileExtentItem {
    pub generation: u64,
    pub ram_bytes: u64,
    pub compression: u8,
    pub encryption: u8,
    pub other_encoding: u16,
    pub type_field: u8,
    // Only for regular/prealloc:
    pub disk_bytenr: u64,
    pub disk_num_bytes: u64,
    pub offset: u64,
    pub num_bytes: u64,
}

// ============================================================================
// F2FS (Flash-Friendly File System) Structures
// ============================================================================

pub const F2FS_SUPER_MAGIC: u32 = 0xF2F52010;
pub const F2FS_SUPER_OFFSET: u64 = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct F2fsSuperBlock {
    pub magic: u32,
    pub major_ver: u16,
    pub minor_ver: u16,
    pub log_sectorsize: u32,
    pub log_sectors_per_block: u32,
    pub log_blocksize: u32,
    pub log_blocks_per_seg: u32,
    pub segs_per_sec: u32,
    pub secs_per_zone: u32,
    pub checksum_offset: u32,
    pub block_count: u64,
    pub section_count: u32,
    pub segment_count: u32,
    pub segment_count_ckpt: u32,
    pub segment_count_sit: u32,
    pub segment_count_nat: u32,
    pub segment_count_ssa: u32,
    pub segment_count_main: u32,
    pub segment0_blkaddr: u32,
    pub cp_blkaddr: u32,
    pub sit_blkaddr: u32,
    pub nat_blkaddr: u32,
    pub ssa_blkaddr: u32,
    pub main_blkaddr: u32,
    pub root_ino: u32,
    pub node_ino: u32,
    pub meta_ino: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 512],
    pub extension_count: u32,
    pub extension_list: [[u8; 8]; 64],
    pub cp_payload: u32,
    pub version: [u8; 256],
    pub init_version: [u8; 256],
    pub feature: u32,
    pub encryption_level: u8,
    pub encrypt_pw_salt: [u8; 16],
    pub devices: [F2fsDeviceInfo; 8],
    pub qf_ino: [u32; 3],
    pub hot_ext_count: u8,
    pub s_encoding: u16,
    pub s_encoding_flags: u16,
    pub s_stop_reason: [u8; 32],
    pub s_errors: [u8; 16],
    pub reserved: [u8; 258],
    pub crc: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct F2fsDeviceInfo {
    pub path: [u8; 64],
    pub total_segments: u32,
}

impl F2fsSuperBlock {
    pub fn is_valid(&self) -> bool {
        self.magic == F2FS_SUPER_MAGIC
    }

    pub fn block_size(&self) -> u64 {
        1u64 << self.log_blocksize
    }
}
