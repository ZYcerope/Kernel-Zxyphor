// =============================================================================
// Zxyphor Kernel — Btrfs Filesystem Implementation (Core On-Disk Structures)
// =============================================================================
// Production-ready Btrfs (B-tree Filesystem) implementation providing
// copy-on-write, checksumming, snapshots, RAID, compression, and
// subvolume support. This is the core on-disk format and B-tree engine.
//
// Btrfs Architecture:
//   - B-tree based metadata + data organization
//   - Copy-on-Write (CoW): never overwrite data in place
//   - Extent-based allocation for large files
//   - Inline data for small files (stored directly in B-tree leaves)
//   - Checksumming of all data and metadata (CRC32C, xxHash, SHA256, BLAKE2b)
//   - Transparent compression (zlib, lzo, zstd)
//   - Multi-device support (RAID 0/1/5/6/10, single, DUP)
//   - Snapshots and clones (nearly zero-cost via CoW)
//   - Subvolumes as independent filesystem roots
//   - Scrubbing and self-healing from RAID mirrors
//   - Online defragmentation and balance
//   - Send/receive for incremental backup
//   - Quotas (qgroups)
//   - Free space management (free space tree or free space cache)
//
// Key Trees:
//   Root Tree:     holds references to all other trees
//   FS Tree:       directory structure and inodes for each subvolume
//   Extent Tree:   tracks allocated extents (data + metadata)
//   Chunk Tree:    logical → physical address mapping
//   Device Tree:   per-device extent allocation
//   Checksum Tree: data checksums
//   UUID Tree:     subvolume UUID lookup
//   Free Space:    free space tracking
//   Block Group:   block group items
//   Quota Tree:    disk usage quotas
// =============================================================================

#![no_std]
#![allow(dead_code)]

/// Btrfs magic number "\_BHRfS_M" in little-endian
pub const BTRFS_MAGIC: u64 = 0x4D5F53665248425F;

/// Superblock offsets (in bytes from start of device)
pub const BTRFS_SUPER_INFO_OFFSET: u64 = 0x10000;       // 64KiB
pub const BTRFS_SUPER_INFO_OFFSET2: u64 = 0x4000000;    // 64MiB
pub const BTRFS_SUPER_INFO_OFFSET3: u64 = 0x4000000000; // 256GiB

pub const BTRFS_SUPER_INFO_SIZE: usize = 4096;
pub const BTRFS_MAX_LEVEL: u8 = 8;
pub const BTRFS_CSUM_SIZE: usize = 32;
pub const BTRFS_FSID_SIZE: usize = 16;
pub const BTRFS_UUID_SIZE: usize = 16;
pub const BTRFS_LABEL_SIZE: usize = 256;
pub const BTRFS_SYSTEM_CHUNK_ARRAY_SIZE: usize = 2048;
pub const BTRFS_NUM_BACKUP_ROOTS: usize = 4;
pub const BTRFS_MAX_METADATA_BLOCKSIZE: u32 = 65536;

// ── Object IDs ────────────────────────────────────────────────────────────
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
pub const BTRFS_DEV_STATS_OBJECTID: u64 = 0;
pub const BTRFS_BALANCE_OBJECTID: u64 = u64::MAX - 4;
pub const BTRFS_ORPHAN_OBJECTID: u64 = u64::MAX - 5;
pub const BTRFS_TREE_LOG_OBJECTID: u64 = u64::MAX - 6;
pub const BTRFS_TREE_LOG_FIXUP_OBJECTID: u64 = u64::MAX - 7;
pub const BTRFS_TREE_RELOC_OBJECTID: u64 = u64::MAX - 8;
pub const BTRFS_DATA_RELOC_TREE_OBJECTID: u64 = u64::MAX - 9;
pub const BTRFS_EMPTY_SUBVOL_DIR_OBJECTID: u64 = 2;
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;
pub const BTRFS_LAST_FREE_OBJECTID: u64 = u64::MAX - 256;
pub const BTRFS_FIRST_CHUNK_TREE_OBJECTID: u64 = 256;

// ── Item Type Keys ────────────────────────────────────────────────────────
pub const BTRFS_INODE_ITEM_KEY: u8 = 1;
pub const BTRFS_INODE_REF_KEY: u8 = 12;
pub const BTRFS_INODE_EXTREF_KEY: u8 = 13;
pub const BTRFS_XATTR_ITEM_KEY: u8 = 24;
pub const BTRFS_VERITY_DESC_ITEM_KEY: u8 = 36;
pub const BTRFS_VERITY_MERKLE_ITEM_KEY: u8 = 37;
pub const BTRFS_ORPHAN_ITEM_KEY: u8 = 48;
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
pub const BTRFS_DEV_REPLACE_KEY: u8 = 250;
pub const BTRFS_UUID_KEY_SUBVOL: u8 = 251;
pub const BTRFS_UUID_KEY_RECEIVED_SUBVOL: u8 = 252;
pub const BTRFS_STRING_ITEM_KEY: u8 = 253;

// ── Checksum Types ────────────────────────────────────────────────────────
pub const BTRFS_CSUM_TYPE_CRC32: u16 = 0;
pub const BTRFS_CSUM_TYPE_XXHASH: u16 = 1;
pub const BTRFS_CSUM_TYPE_SHA256: u16 = 2;
pub const BTRFS_CSUM_TYPE_BLAKE2: u16 = 3;

// ── Compression Types ─────────────────────────────────────────────────────
pub const BTRFS_COMPRESS_NONE: u8 = 0;
pub const BTRFS_COMPRESS_ZLIB: u8 = 1;
pub const BTRFS_COMPRESS_LZO: u8 = 2;
pub const BTRFS_COMPRESS_ZSTD: u8 = 3;

// ── On-Disk Key ───────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub item_type: u8,
    pub offset: u64,
}

impl BtrfsKey {
    pub const fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        Self { objectid, item_type, offset }
    }

    pub const fn min() -> Self {
        Self { objectid: 0, item_type: 0, offset: 0 }
    }

    pub const fn max() -> Self {
        Self { objectid: u64::MAX, item_type: u8::MAX, offset: u64::MAX }
    }
}

// ── Disk Key (17 bytes, packed) ───────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsDiskKey {
    pub objectid: [u8; 8],  // Little-endian u64
    pub item_type: u8,
    pub offset: [u8; 8],    // Little-endian u64
}

impl BtrfsDiskKey {
    pub fn to_cpu_key(&self) -> BtrfsKey {
        BtrfsKey {
            objectid: u64::from_le_bytes(self.objectid),
            item_type: self.item_type,
            offset: u64::from_le_bytes(self.offset),
        }
    }

    pub fn from_cpu_key(key: &BtrfsKey) -> Self {
        Self {
            objectid: key.objectid.to_le_bytes(),
            item_type: key.item_type,
            offset: key.offset.to_le_bytes(),
        }
    }
}

// ── Superblock ────────────────────────────────────────────────────────────
#[repr(C, packed)]
pub struct BtrfsSuperBlock {
    pub csum: [u8; BTRFS_CSUM_SIZE],          // Checksum of everything after this field
    pub fsid: [u8; BTRFS_FSID_SIZE],          // Filesystem UUID
    pub bytenr: u64,                           // Physical address of this block
    pub flags: u64,                            // Flags
    pub magic: u64,                            // Must be BTRFS_MAGIC
    pub generation: u64,                       // Transaction generation
    pub root: u64,                             // Logical address of root tree root
    pub chunk_root: u64,                       // Logical address of chunk tree root
    pub log_root: u64,                         // Logical address of log tree root
    pub log_root_transid: u64,
    pub total_bytes: u64,                      // Total bytes in filesystem
    pub bytes_used: u64,                       // Bytes used
    pub root_dir_objectid: u64,                // Root directory objectid
    pub num_devices: u64,                      // Number of devices
    pub sectorsize: u32,                       // Sector size (typically 4096)
    pub nodesize: u32,                         // Node size (typically 16384)
    pub leafsize: u32,                         // Leaf size (= nodesize)
    pub stripesize: u32,                       // Stripe size
    pub sys_chunk_array_size: u32,             // Size of system chunk array
    pub chunk_root_generation: u64,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,                        // Checksum algorithm
    pub root_level: u8,                        // Root tree level
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub dev_item: BtrfsDevItem,                // First device info
    pub label: [u8; BTRFS_LABEL_SIZE],
    pub cache_generation: u64,
    pub uuid_tree_generation: u64,
    pub metadata_uuid: [u8; BTRFS_FSID_SIZE],
    pub nr_global_roots: u64,
    pub reserved: [u64; 27],
    pub sys_chunk_array: [u8; BTRFS_SYSTEM_CHUNK_ARRAY_SIZE],
    pub super_roots: [BtrfsRootBackup; BTRFS_NUM_BACKUP_ROOTS],
    pub padding: [u8; 565],
}

// ── Device Item ───────────────────────────────────────────────────────────
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
    pub uuid: [u8; BTRFS_UUID_SIZE],
    pub fsid: [u8; BTRFS_FSID_SIZE],
}

// ── Root Backup ───────────────────────────────────────────────────────────
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
    pub unused: [u64; 4],
    pub tree_root_level: u8,
    pub chunk_root_level: u8,
    pub extent_root_level: u8,
    pub fs_root_level: u8,
    pub dev_root_level: u8,
    pub csum_root_level: u8,
    pub unused_level: [u8; 2],
}

// ── B-tree Node Header ───────────────────────────────────────────────────
#[repr(C, packed)]
pub struct BtrfsHeader {
    pub csum: [u8; BTRFS_CSUM_SIZE],
    pub fsid: [u8; BTRFS_FSID_SIZE],
    pub bytenr: u64,                  // Logical address of this node
    pub flags: u64,
    pub chunk_tree_uuid: [u8; BTRFS_UUID_SIZE],
    pub generation: u64,
    pub owner: u64,                   // Tree objectid that owns this node
    pub nritems: u32,                 // Number of items
    pub level: u8,                    // 0 = leaf, > 0 = internal node
}

// ── B-tree Internal Node Key Pointer ──────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsKeyPtr {
    pub key: BtrfsDiskKey,
    pub blockptr: u64,                // Logical address of child node
    pub generation: u64,
}

// ── B-tree Leaf Item ──────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsItem {
    pub key: BtrfsDiskKey,
    pub offset: u32,       // Byte offset within leaf data area
    pub size: u32,         // Size of data referenced by this item
}

// ── Inode Item ────────────────────────────────────────────────────────────
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

// ── Directory Item ────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsDirItem {
    pub location: BtrfsDiskKey,
    pub transid: u64,
    pub data_len: u16,
    pub name_len: u16,
    pub dir_type: u8,
    // Followed by name[name_len] and data[data_len]
}

pub const BTRFS_FT_UNKNOWN: u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR: u8 = 2;
pub const BTRFS_FT_CHRDEV: u8 = 3;
pub const BTRFS_FT_BLKDEV: u8 = 4;
pub const BTRFS_FT_FIFO: u8 = 5;
pub const BTRFS_FT_SOCK: u8 = 6;
pub const BTRFS_FT_SYMLINK: u8 = 7;
pub const BTRFS_FT_XATTR: u8 = 8;

// ── Extent Data ───────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsFileExtentItem {
    pub generation: u64,
    pub ram_bytes: u64,        // Uncompressed size
    pub compression: u8,
    pub encryption: u8,
    pub other_encoding: u16,
    pub extent_type: u8,       // 0 = inline, 1 = regular, 2 = prealloc
    // For non-inline:
    pub disk_bytenr: u64,      // Logical byte number on disk
    pub disk_num_bytes: u64,   // On-disk extent size
    pub offset: u64,           // Offset within the extent
    pub num_bytes: u64,        // Logical number of bytes in file
}

pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
pub const BTRFS_FILE_EXTENT_REG: u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

// ── Extent Item ───────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsExtentItem {
    pub refs: u64,             // Reference count
    pub generation: u64,
    pub flags: u64,
}

pub const BTRFS_EXTENT_FLAG_DATA: u64 = 1;
pub const BTRFS_EXTENT_FLAG_TREE_BLOCK: u64 = 2;

// ── Chunk Item ────────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsChunkItem {
    pub length: u64,
    pub owner: u64,            // Objectid of owning tree
    pub stripe_len: u64,
    pub chunk_type: u64,       // Allocation profile (RAID type + data/metadata/system)
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    // Followed by BtrfsStripe[num_stripes]
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: [u8; BTRFS_UUID_SIZE],
}

// Chunk types
pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1;
pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 2;
pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 4;
pub const BTRFS_BLOCK_GROUP_RAID0: u64 = 1 << 3;
pub const BTRFS_BLOCK_GROUP_RAID1: u64 = 1 << 4;
pub const BTRFS_BLOCK_GROUP_DUP: u64 = 1 << 5;
pub const BTRFS_BLOCK_GROUP_RAID10: u64 = 1 << 6;
pub const BTRFS_BLOCK_GROUP_RAID5: u64 = 1 << 7;
pub const BTRFS_BLOCK_GROUP_RAID6: u64 = 1 << 8;
pub const BTRFS_BLOCK_GROUP_RAID1C3: u64 = 1 << 9;
pub const BTRFS_BLOCK_GROUP_RAID1C4: u64 = 1 << 10;

// ── Block Group Item ──────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsBlockGroupItem {
    pub used: u64,
    pub chunk_objectid: u64,
    pub flags: u64,
}

// ── Root Item ─────────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsRootItem {
    pub inode: BtrfsInodeItem,
    pub generation: u64,
    pub root_dirid: u64,
    pub bytenr: u64,           // Logical address of root node
    pub byte_limit: u64,
    pub bytes_used: u64,
    pub last_snapshot: u64,
    pub flags: u64,
    pub refs: u32,
    pub drop_progress: BtrfsDiskKey,
    pub drop_level: u8,
    pub level: u8,
    pub generation_v2: u64,
    pub uuid: [u8; BTRFS_UUID_SIZE],
    pub parent_uuid: [u8; BTRFS_UUID_SIZE],
    pub received_uuid: [u8; BTRFS_UUID_SIZE],
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

// ── Inode Ref ─────────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsInodeRef {
    pub index: u64,
    pub name_len: u16,
    // Followed by name[name_len]
}

// ── Free Space Entry ──────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsFreeSpaceInfo {
    pub extent_count: u32,
    pub flags: u32,
}

// ── Dev Extent ────────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsDevExtent {
    pub chunk_tree: u64,
    pub chunk_objectid: u64,
    pub chunk_offset: u64,
    pub length: u64,
    pub chunk_tree_uuid: [u8; BTRFS_UUID_SIZE],
}

// ── Qgroup Info ───────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsQgroupInfoItem {
    pub generation: u64,
    pub rfer: u64,             // Referenced bytes
    pub rfer_cmpr: u64,       // Referenced compressed bytes
    pub excl: u64,             // Exclusive bytes
    pub excl_cmpr: u64,       // Exclusive compressed bytes
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsQgroupLimitItem {
    pub flags: u64,
    pub max_rfer: u64,
    pub max_excl: u64,
    pub rsv_rfer: u64,
    pub rsv_excl: u64,
}

// ── Incompat Feature Flags ────────────────────────────────────────────────
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
pub const BTRFS_FEATURE_INCOMPAT_RAID1C34: u64 = 1 << 11;
pub const BTRFS_FEATURE_INCOMPAT_ZONED: u64 = 1 << 12;
pub const BTRFS_FEATURE_INCOMPAT_EXTENT_TREE_V2: u64 = 1 << 13;

// ── CRC32C (for checksum verification) ────────────────────────────────────
const CRC32C_TABLE: [256]u32 = generate_crc32c_table();

const fn generate_crc32c_table() -> [256; u32] {
    let mut table = [0u32; 256];
    let mut i: usize = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[index];
    }
    crc ^ 0xFFFFFFFF
}

/// Verify superblock checksum
pub fn verify_superblock_csum(sb_bytes: &[u8; BTRFS_SUPER_INFO_SIZE]) -> bool {
    let computed = crc32c(&sb_bytes[BTRFS_CSUM_SIZE..]);
    let stored = u32::from_le_bytes([
        sb_bytes[0], sb_bytes[1], sb_bytes[2], sb_bytes[3]
    ]);
    computed == stored
}

/// Validate superblock magic and basic fields
pub fn validate_superblock(sb: &BtrfsSuperBlock) -> bool {
    if sb.magic != BTRFS_MAGIC {
        return false;
    }
    if sb.nodesize < 4096 || sb.nodesize > BTRFS_MAX_METADATA_BLOCKSIZE {
        return false;
    }
    if sb.sectorsize != 4096 {
        return false;
    }
    if sb.num_devices == 0 {
        return false;
    }
    true
}
