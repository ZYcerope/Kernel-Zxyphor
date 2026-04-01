// Zxyphor Kernel - Rust F2FS Structures, XFS Structures,
// Filesystem Encryption (fscrypt), Filesystem Verification (fsverity)
// More advanced than Linux 2026 on-disk formats

/// F2FS on-disk superblock structure
#[repr(C, packed)]
pub struct F2fsSuperBlock {
    pub magic: u32,                    // 0xF2F52010
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
    pub uuid: [16; u8],
    pub volume_name: [512; u8],
    pub extension_count: u32,
    pub extension_list: [[8; u8]; 64],
    pub cp_payload: u32,
    pub version: [256; u8],
    pub init_version: [256; u8],
    pub feature: u32,
    pub encryption_level: u8,
    pub encrypt_pw_salt: [16; u8],
    pub devs: [48; F2fsDeviceEntry],
    pub qf_ino: [3; u32],
    pub hot_ext_count: u8,
    pub s_encoding: u16,
    pub s_encoding_flags: u16,
    pub s_stop_reason: [32; u8],
    pub s_errors: [16; u8],
    pub compress_algorithm: u8,
    pub compress_log_size: u8,
    pub compress_level: u16,
    pub zxy_predictive_gc: u8,     // Zxyphor extension
}

pub const F2FS_MAGIC: u32 = 0xF2F52010;

#[repr(C, packed)]
pub struct F2fsDeviceEntry {
    pub path: [64; u8],
    pub total_segments: u32,
}

/// F2FS inode flags
pub struct F2fsInodeFlags;
impl F2fsInodeFlags {
    pub const COMPR_FL: u32 = 0x00000004;
    pub const SYNC_FL: u32 = 0x00000008;
    pub const IMMUTABLE_FL: u32 = 0x00000010;
    pub const APPEND_FL: u32 = 0x00000020;
    pub const NODUMP_FL: u32 = 0x00000040;
    pub const NOATIME_FL: u32 = 0x00000080;
    pub const INDEX_FL: u32 = 0x00001000;
    pub const DIRSYNC_FL: u32 = 0x00010000;
    pub const PROJINHERIT_FL: u32 = 0x20000000;
    pub const CASEFOLD_FL: u32 = 0x40000000;
    pub const VERITY_FL: u32 = 0x00100000;
    pub const ENCRYPT_FL: u32 = 0x00000800;
    pub const INLINE_DATA_FL: u32 = 0x10000000;
    pub const INLINE_DENTRY_FL: u32 = 0x08000000;
    pub const PIN_FL: u32 = 0x00000100;
}

/// F2FS segment type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F2fsSegType {
    HotData = 0,
    WarmData = 1,
    ColdData = 2,
    HotNode = 3,
    WarmNode = 4,
    ColdNode = 5,
}

/// F2FS checkpoint flags
pub struct F2fsCpFlags;
impl F2fsCpFlags {
    pub const UMOUNT: u32 = 0x00000001;
    pub const COMPACT_SUM: u32 = 0x00000004;
    pub const ORPHAN_PRESENT: u32 = 0x00000008;
    pub const FASTBOOT: u32 = 0x00000020;
    pub const FSCK: u32 = 0x00000040;
    pub const ERROR: u32 = 0x00000080;
    pub const QUOTA_NEED_REPAIR: u32 = 0x00001000;
    pub const LARGE_NAT_BITMAP: u32 = 0x00000400;
    pub const NOCRC_RECOVERY: u32 = 0x00000200;
    pub const TRIMMED: u32 = 0x00000100;
    pub const RESIZEFS: u32 = 0x00004000;
    pub const DISABLED: u32 = 0x00002000;
}

/// F2FS garbage collection mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F2fsGcMode {
    Background = 0,
    Foreground = 1,
    /// Zxyphor: ML-assisted GC
    ZxyPredictive = 10,
}

/// F2FS compress algorithm
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F2fsCompressAlgo {
    Lzo = 0,
    Lz4 = 1,
    Zstd = 2,
    Lzorle = 3,
}

// ============================================================================
// XFS On-Disk Structures
// ============================================================================

/// XFS superblock
#[repr(C, packed)]
pub struct XfsSuperBlock {
    pub sb_magicnum: u32,              // 0x58465342 = "XFSB"
    pub sb_blocksize: u32,
    pub sb_dblocks: u64,               // Total data blocks
    pub sb_rblocks: u64,               // Realtime blocks
    pub sb_rextents: u64,              // Realtime extents
    pub sb_uuid: [16; u8],
    pub sb_logstart: u64,
    pub sb_rootino: u64,
    pub sb_rbmino: u64,               // Realtime bitmap inode
    pub sb_rsumino: u64,              // Realtime summary inode
    pub sb_rextsize: u32,
    pub sb_agblocks: u32,             // AG size in blocks
    pub sb_agcount: u32,              // Number of AGs
    pub sb_rbmblocks: u32,
    pub sb_logblocks: u32,
    pub sb_versionnum: u16,
    pub sb_sectsize: u16,
    pub sb_inodesize: u16,
    pub sb_inopblock: u16,
    pub sb_fname: [12; u8],
    pub sb_blocklog: u8,
    pub sb_sectlog: u8,
    pub sb_inodelog: u8,
    pub sb_inopblog: u8,
    pub sb_agblklog: u8,
    pub sb_rextslog: u8,
    pub sb_inprogress: u8,
    pub sb_imax_pct: u8,
    pub sb_icount: u64,               // Allocated inodes
    pub sb_ifree: u64,                // Free inodes
    pub sb_fdblocks: u64,             // Free data blocks
    pub sb_frextents: u64,            // Free realtime extents
    pub sb_uquotino: u64,             // User quota inode
    pub sb_gquotino: u64,             // Group quota inode
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
    // V5 superblock fields
    pub sb_features_compat: u32,
    pub sb_features_ro_compat: u32,
    pub sb_features_incompat: u32,
    pub sb_features_log_incompat: u32,
    pub sb_crc: u32,
    pub sb_spino_align: u32,
    pub sb_pquotino: u64,             // Project quota inode
    pub sb_lsn: u64,
    pub sb_meta_uuid: [16; u8],
    pub sb_metadirino: u64,
    pub sb_rgcount: u32,
    pub sb_rgextents: u32,
    pub sb_rgblklog: u8,
}

pub const XFS_SB_MAGIC: u32 = 0x58465342;

/// XFS incompat features
pub struct XfsIncompatFeatures;
impl XfsIncompatFeatures {
    pub const FTYPE: u32 = 1 << 0;
    pub const SPINODES: u32 = 1 << 1;
    pub const META_UUID: u32 = 1 << 2;
    pub const BIGTIME: u32 = 1 << 3;
    pub const NEEDSREPAIR: u32 = 1 << 4;
    pub const NREXT64: u32 = 1 << 5;
    pub const EXCHRANGE: u32 = 1 << 6;
    pub const PARENT: u32 = 1 << 7;
    pub const METADIR: u32 = 1 << 8;
}

/// XFS ro-compat features
pub struct XfsRoCompatFeatures;
impl XfsRoCompatFeatures {
    pub const FINOBT: u32 = 1 << 0;
    pub const RMAPBT: u32 = 1 << 1;
    pub const REFLINK: u32 = 1 << 2;
    pub const INOBTCNT: u32 = 1 << 3;
}

/// XFS allocation group header (AGF)
#[repr(C, packed)]
pub struct XfsAgf {
    pub agf_magicnum: u32,             // 0x58414746 = "XAGF"
    pub agf_versionnum: u32,
    pub agf_seqno: u32,
    pub agf_length: u32,
    pub agf_roots: [3; u32],          // BNO, CNT, RMAP btree roots
    pub agf_levels: [3; u32],
    pub agf_flfirst: u32,
    pub agf_fllast: u32,
    pub agf_flcount: u32,
    pub agf_freeblks: u32,
    pub agf_longest: u32,
    pub agf_btreeblks: u32,
    pub agf_uuid: [16; u8],
    pub agf_rmap_blocks: u32,
    pub agf_refcount_blocks: u32,
    pub agf_refcount_root: u32,
    pub agf_refcount_level: u32,
    pub agf_spare64: [14; u64],
    pub agf_lsn: u64,
    pub agf_crc: u32,
}

/// XFS B+tree block (long format, on-disk)
#[repr(C, packed)]
pub struct XfsBtreeBlockLong {
    pub bb_magic: u32,
    pub bb_level: u16,
    pub bb_numrecs: u16,
    pub bb_leftsib: u64,
    pub bb_rightsib: u64,
    pub bb_blkno: u64,
    pub bb_lsn: u64,
    pub bb_uuid: [16; u8],
    pub bb_owner: u64,
    pub bb_crc: u32,
    pub bb_pad: u32,
}

// ============================================================================
// fscrypt (Filesystem Encryption)
// ============================================================================

/// fscrypt policy version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptPolicyVersion {
    V1 = 1,
    V2 = 2,
}

/// fscrypt encryption mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptMode {
    Aes256Xts = 1,
    Aes256Cts = 4,
    Aes128Cbc = 5,
    Aes128Cts = 6,
    AdestsSpeck128Xts = 7,      // Deprecated
    AdestsSpeck256Xts = 8,      // Deprecated
    Aes256Hctr2 = 9,
    Sm4Xts = 10,
    Sm4Cts = 11,
    /// Zxyphor: XChaCha20 for contents
    ZxyXchacha20 = 50,
}

/// fscrypt flags
pub struct FscryptPolicyFlags;
impl FscryptPolicyFlags {
    pub const PAD_4: u8 = 0x00;
    pub const PAD_8: u8 = 0x01;
    pub const PAD_16: u8 = 0x02;
    pub const PAD_32: u8 = 0x03;
    pub const PAD_MASK: u8 = 0x03;
    pub const DIRECT_KEY: u8 = 0x04;
    pub const IV_INO_LBLK_64: u8 = 0x08;
    pub const IV_INO_LBLK_32: u8 = 0x10;
}

/// fscrypt key specifier type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptKeySpecType {
    Descriptor = 1,
    Identifier = 2,
}

/// fscrypt v2 policy
#[repr(C)]
pub struct FscryptPolicyV2 {
    pub version: u8,           // Must be 2
    pub contents_encryption_mode: FscryptMode,
    pub filenames_encryption_mode: FscryptMode,
    pub flags: u8,
    pub log2_data_unit_size: u8,
    pub reserved: [3; u8],
    pub master_key_identifier: [16; u8],
}

/// fscrypt provisioning key
#[repr(C)]
pub struct FscryptProvisioningKey {
    pub type_field: u32,
    pub reserved: u32,
    pub raw_size: u32,
    // raw key data follows
}

/// fscrypt key status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FscryptKeyStatus {
    Absent = 1,
    Present = 2,
    IncompletlyRemoved = 3,
}

// ============================================================================
// fsverity (Filesystem Verification / dm-verity)
// ============================================================================

/// fsverity hash algorithm
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsverityHashAlgorithm {
    Sha256 = 1,
    Sha512 = 2,
}

/// fsverity enable arg
#[repr(C)]
pub struct FsverityEnableArg {
    pub version: u32,          // Must be 1
    pub hash_algorithm: FsverityHashAlgorithm,
    pub block_size: u32,
    pub salt_size: u32,
    pub salt_ptr: u64,
    pub sig_size: u32,
    pub reserved1: u32,
    pub sig_ptr: u64,
    pub reserved2: [11; u64],
}

/// fsverity descriptor
#[repr(C)]
pub struct FsverityDescriptor {
    pub version: u8,           // 1
    pub hash_algorithm: u8,
    pub log_blocksize: u8,
    pub salt_size: u8,
    pub reserved_0x04: u32,
    pub data_size: u64,
    pub root_hash: [64; u8],
    pub salt: [32; u8],
    pub reserved: [144; u8],
}

/// fsverity digest
#[repr(C)]
pub struct FsverityDigest {
    pub digest_algorithm: u16,
    pub digest_size: u16,
    pub digest: [64; u8],
}

/// fsverity measurement ioctl
#[repr(C)]
pub struct FsverityMeasureDigest {
    pub digest_algorithm: u16,
    pub digest_size: u16,
    pub digest: [64; u8],
}

// ============================================================================
// dm-verity (Device Mapper Verification)
// ============================================================================

/// dm-verity version
pub const DM_VERITY_VERSION: u32 = 1;

/// dm-verity config
#[repr(C)]
pub struct DmVerityConfig {
    pub version: u32,
    pub data_dev_block_bits: u32,
    pub hash_dev_block_bits: u32,
    pub data_blocks: u64,
    pub hash_start: u64,
    pub algorithm: DmVerityAlgorithm,
    pub digest_size: u32,
    pub salt_size: u32,
    pub salt: [256; u8],
    pub root_digest: [64; u8],
    pub root_digest_size: u32,
    // FEC
    pub fec_enabled: bool,
    pub fec_dev_blocks: u64,
    pub fec_start: u64,
    pub fec_roots: u32,
    // Flags
    pub check_at_most_once: bool,
    pub ignore_zero_blocks: bool,
    pub ignore_corruption: bool,
    pub restart_on_corruption: bool,
    pub panic_on_corruption: bool,
}

/// dm-verity algorithm
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmVerityAlgorithm {
    Sha256 = 0,
    Sha512 = 1,
    Sha1 = 2,
    Crc32c = 3,
    /// Zxyphor: BLAKE3 for faster verification
    ZxyBlake3 = 50,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

pub struct FsStructuresSubsystem {
    // F2FS
    pub nr_f2fs_mounts: u32,
    pub total_f2fs_gc_runs: u64,
    pub total_f2fs_discard_cmds: u64,
    // XFS
    pub nr_xfs_mounts: u32,
    pub total_xfs_log_writes: u64,
    pub total_xfs_ag_scans: u64,
    // fscrypt
    pub nr_encrypted_inodes: u64,
    pub total_encrypt_ops: u64,
    pub total_decrypt_ops: u64,
    pub nr_master_keys: u32,
    // fsverity
    pub nr_verity_files: u64,
    pub total_verify_ops: u64,
    pub total_verify_failures: u64,
    // dm-verity
    pub nr_dm_verity_targets: u32,
    pub total_dm_verify_ops: u64,
    pub total_dm_verify_errors: u64,
    // Zxyphor
    pub zxy_predictive_gc: bool,
    pub zxy_hw_crypto_offload: bool,
    pub initialized: bool,
}

impl FsStructuresSubsystem {
    pub fn new() -> Self {
        Self {
            nr_f2fs_mounts: 0,
            total_f2fs_gc_runs: 0,
            total_f2fs_discard_cmds: 0,
            nr_xfs_mounts: 0,
            total_xfs_log_writes: 0,
            total_xfs_ag_scans: 0,
            nr_encrypted_inodes: 0,
            total_encrypt_ops: 0,
            total_decrypt_ops: 0,
            nr_master_keys: 0,
            nr_verity_files: 0,
            total_verify_ops: 0,
            total_verify_failures: 0,
            nr_dm_verity_targets: 0,
            total_dm_verify_ops: 0,
            total_dm_verify_errors: 0,
            zxy_predictive_gc: true,
            zxy_hw_crypto_offload: true,
            initialized: false,
        }
    }
}
