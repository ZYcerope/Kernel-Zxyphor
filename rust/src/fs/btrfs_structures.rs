// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - Btrfs On-Disk Structures, Extent Tree,
// Chunk Tree, Snapshot/Subvolume, Send/Receive, RAID, Scrub
// More advanced than Linux 2026 Btrfs filesystem

/// Btrfs magic number
pub const BTRFS_MAGIC: u64 = 0x4D5F53665248425F; // "_BHRfS_M"

/// Btrfs disk key
#[derive(Debug, Clone, Copy)]
pub struct BtrfsDiskKey {
    pub objectid: u64,
    pub type_: u8,
    pub offset: u64,
}

/// Btrfs item types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsItemType {
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
    ExtentRefV0 = 180, // deprecated
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
    TemporaryItem = 248,
    PersistentItem = 249,
    DevReplace = 250,
    UuidSubvol = 251,
    UuidReceivedSubvol = 252,
    StringItem = 253,
}

/// Btrfs superblock
#[derive(Debug, Clone)]
pub struct BtrfsSuperblock {
    pub csum: [32; u8],
    pub fsid: [16; u8],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,
    pub generation: u64,
    pub root: u64,           // Root tree root
    pub chunk_root: u64,
    pub log_root: u64,
    pub log_root_transid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub leafsize: u32,       // = nodesize
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
    // Device item
    pub dev_item: BtrfsDevItem,
    pub label: [256; u8],
    pub cache_generation: u64,
    pub uuid_tree_generation: u64,
    // Metadata UUID
    pub metadata_uuid: [16; u8],
    // Block group tree
    pub block_group_root: u64,
    pub block_group_root_generation: u64,
    pub block_group_root_level: u8,
    // Nr global roots
    pub nr_global_roots: u64,
}

/// Btrfs checksum type
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsCsumType {
    Crc32c = 0,
    Xxhash = 1,
    Sha256 = 2,
    Blake2b = 3,
}

/// Btrfs incompatible flags
pub const BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF: u64 = 1 << 0;
pub const BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL: u64 = 1 << 1;
pub const BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS: u64 = 1 << 2;
pub const BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO: u64 = 1 << 3;
pub const BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD: u64 = 1 << 4;
pub const BTRFS_FEATURE_INCOMPAT_BIG_METADATA: u64 = 1 << 5;
pub const BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF: u64 = 1 << 6;
pub const BTRFS_FEATURE_INCOMPAT_RAID56: u64 = 1 << 7;
pub const BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA: u64 = 1 << 8;
pub const BTRFS_FEATURE_INCOMPAT_NO_HOLES: u64 = 1 << 9;
pub const BTRFS_FEATURE_INCOMPAT_METADATA_UUID: u64 = 1 << 10;
pub const BTRFS_FEATURE_INCOMPAT_RAID1C3: u64 = 1 << 11;
pub const BTRFS_FEATURE_INCOMPAT_RAID1C4: u64 = 1 << 12;
pub const BTRFS_FEATURE_INCOMPAT_ZONED: u64 = 1 << 13;
pub const BTRFS_FEATURE_INCOMPAT_EXTENT_TREE_V2: u64 = 1 << 14;
pub const BTRFS_FEATURE_INCOMPAT_RAID_STRIPE_TREE: u64 = 1 << 15;
pub const BTRFS_FEATURE_INCOMPAT_SIMPLE_QUOTA: u64 = 1 << 16;
pub const BTRFS_FEATURE_INCOMPAT_BLOCK_GROUP_TREE: u64 = 1 << 17;

/// Btrfs read-only compat flags
pub const BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE: u64 = 1 << 0;
pub const BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID: u64 = 1 << 1;
pub const BTRFS_FEATURE_COMPAT_RO_VERITY: u64 = 1 << 2;
pub const BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE: u64 = 1 << 3;

/// Btrfs device item
#[derive(Debug, Clone)]
pub struct BtrfsDevItem {
    pub devid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub type_: u64,
    pub generation: u64,
    pub start_offset: u64,
    pub dev_group: u32,
    pub seek_speed: u8,
    pub bandwidth: u8,
    pub uuid: [16; u8],
    pub fsid: [16; u8],
}

/// Btrfs chunk item (in chunk tree)
#[derive(Debug, Clone)]
pub struct BtrfsChunk {
    pub length: u64,
    pub owner: u64,       // objectid of block group
    pub stripe_len: u64,
    pub type_: u64,       // RAID type flags
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    // Followed by BtrfsStripe[num_stripes]
}

/// RAID profile flags
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

/// Btrfs stripe
#[derive(Debug, Clone)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: [16; u8],
}

/// Btrfs inode item
#[derive(Debug, Clone)]
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
    // Times
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub otime_sec: i64,    // creation time
    pub otime_nsec: u32,
}

/// Btrfs inode flags
pub const BTRFS_INODE_NODATASUM: u64 = 1 << 0;
pub const BTRFS_INODE_NODATACOW: u64 = 1 << 1;
pub const BTRFS_INODE_READONLY: u64 = 1 << 2;
pub const BTRFS_INODE_NOCOMPRESS: u64 = 1 << 3;
pub const BTRFS_INODE_PREALLOC: u64 = 1 << 4;
pub const BTRFS_INODE_SYNC: u64 = 1 << 5;
pub const BTRFS_INODE_IMMUTABLE: u64 = 1 << 6;
pub const BTRFS_INODE_APPEND: u64 = 1 << 7;
pub const BTRFS_INODE_NODUMP: u64 = 1 << 8;
pub const BTRFS_INODE_NOATIME: u64 = 1 << 9;
pub const BTRFS_INODE_DIRSYNC: u64 = 1 << 10;
pub const BTRFS_INODE_COMPRESS: u64 = 1 << 11;

/// Btrfs extent data item
#[derive(Debug, Clone)]
pub struct BtrfsFileExtentItem {
    pub generation: u64,
    pub ram_bytes: u64,
    pub compression: u8,
    pub encryption: u8,
    pub other_encoding: u16,
    pub type_: BtrfsExtentType,
    // For regular extents
    pub disk_bytenr: u64,
    pub disk_num_bytes: u64,
    pub offset: u64,
    pub num_bytes: u64,
}

/// Btrfs extent type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsExtentType {
    Inline = 0,
    Regular = 1,
    Prealloc = 2,
    Encoded = 3,
}

/// Btrfs compression type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsCompression {
    None = 0,
    Zlib = 1,
    Lzo = 2,
    Zstd = 3,
}

/// Btrfs root item (subvolume/snapshot)
#[derive(Debug, Clone)]
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
    pub drop_progress: BtrfsDiskKey,
    pub drop_level: u8,
    pub level: u8,
    pub generation_v2: u64,
    pub uuid: [16; u8],
    pub parent_uuid: [16; u8],
    pub received_uuid: [16; u8],
    pub ctransid: u64,
    pub otransid: u64,
    pub stransid: u64,
    pub rtransid: u64,
    pub ctime: BtrfsTimespec,
    pub otime: BtrfsTimespec,
    pub stime: BtrfsTimespec,
    pub rtime: BtrfsTimespec,
    pub global_tree_id: u64,
}

/// Btrfs timespec
#[derive(Debug, Clone, Copy)]
pub struct BtrfsTimespec {
    pub sec: i64,
    pub nsec: u32,
}

/// Well-known tree objectids
pub const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
pub const BTRFS_EXTENT_TREE_OBJECTID: u64 = 2;
pub const BTRFS_CHUNK_TREE_OBJECTID: u64 = 3;
pub const BTRFS_DEV_TREE_OBJECTID: u64 = 4;
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;
pub const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const BTRFS_CSUM_TREE_OBJECTID: u64 = 7;
pub const BTRFS_QUOTA_TREE_OBJECTID: u64 = 8;
pub const BTRFS_UUID_TREE_OBJECTID: u64 = 9;
pub const BTRFS_FREE_SPACE_TREE_OBJECTID: u64 = 10;
pub const BTRFS_BLOCK_GROUP_TREE_OBJECTID: u64 = 11;
pub const BTRFS_RAID_STRIPE_TREE_OBJECTID: u64 = 12;
pub const BTRFS_DATA_RELOC_TREE_OBJECTID: u64 = !0u64 - 8;
pub const BTRFS_TREE_LOG_OBJECTID: u64 = !0u64 - 6;
pub const BTRFS_TREE_RELOC_OBJECTID: u64 = !0u64 - 7;
pub const BTRFS_ORPHAN_OBJECTID: u64 = !0u64 - 4;

/// Send/Receive stream version
pub const BTRFS_SEND_STREAM_MAGIC: &[u8; 13] = b"btrfs-stream\0";
pub const BTRFS_SEND_STREAM_VERSION: u32 = 3;

/// Send command types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsSendCmd {
    Unspec = 0,
    Subvol = 1,
    Snapshot = 2,
    Mkfile = 3,
    Mkdir = 4,
    Mknod = 5,
    Mkfifo = 6,
    Mksock = 7,
    Symlink = 8,
    Rename = 9,
    Link = 10,
    Unlink = 11,
    Rmdir = 12,
    SetXattr = 13,
    RemoveXattr = 14,
    Write = 15,
    Clone = 16,
    Truncate = 17,
    Chmod = 18,
    Chown = 19,
    Utimes = 20,
    End = 21,
    UpdateExtent = 22,
    // v2+
    EncodedWrite = 23,
    // v3+
    Fallocate = 24,
    Fileattr = 25,
    EnableVerity = 26,
}

/// Qgroup info
#[derive(Debug, Clone)]
pub struct BtrfsQgroupInfo {
    pub generation: u64,
    pub rfer: u64,        // Referenced extent size
    pub rfer_cmpr: u64,   // Compressed referenced size
    pub excl: u64,        // Exclusive extent size
    pub excl_cmpr: u64,   // Compressed exclusive size
}

/// Qgroup limit
#[derive(Debug, Clone)]
pub struct BtrfsQgroupLimit {
    pub flags: u64,
    pub max_rfer: u64,
    pub max_excl: u64,
    pub rsv_rfer: u64,
    pub rsv_excl: u64,
}

/// Scrub progress
#[derive(Debug, Clone)]
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

/// Balance args
#[derive(Debug, Clone)]
pub struct BtrfsBalanceArgs {
    pub profiles: u64,
    pub usage: u64,
    pub devid: u64,
    pub pstart: u64,
    pub pend: u64,
    pub vstart: u64,
    pub vend: u64,
    pub target: u64,
    pub flags: u64,
    pub limit: u64,
    pub stripes_min: u32,
    pub stripes_max: u32,
}

/// Btrfs filesystem summary
#[derive(Debug, Clone)]
pub struct BtrfsFsInfo {
    pub fsid: [16; u8],
    pub metadata_uuid: [16; u8],
    pub generation: u64,
    pub nodesize: u32,
    pub sectorsize: u32,
    pub nr_devices: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    // Features
    pub csum_type: BtrfsCsumType,
    pub incompat_flags: u64,
    pub compat_ro_flags: u64,
    // Subvolumes
    pub nr_subvolumes: u64,
    pub nr_snapshots: u64,
    // Quota
    pub quota_enabled: bool,
    pub nr_qgroups: u64,
    // Stats
    pub total_writes: u64,
    pub total_reads: u64,
    pub total_flushes: u64,
    pub total_scrubs: u64,
    pub total_balances: u64,
    pub total_send_ops: u64,
    pub total_receive_ops: u64,
    // Zxyphor
    pub zxy_dedup_savings_bytes: u64,
    pub zxy_compression_ratio: f32,
}

/// Btrfs filesystem subsystem
#[derive(Debug, Clone)]
pub struct BtrfsSubsystem {
    pub nr_filesystems: u32,
    pub total_capacity: u64,
    pub total_used: u64,
    pub total_devices: u32,
    pub total_subvolumes: u64,
    pub total_snapshots: u64,
    pub total_scrub_errors: u64,
    pub total_balance_ops: u64,
    pub initialized: bool,
}
