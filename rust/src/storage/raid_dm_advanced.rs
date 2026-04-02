// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Rust RAID/MD & Device Mapper Advanced
// Software RAID levels, MD personality, reshape, bitmap,
// Device Mapper targets, linear/striped/mirror/snapshot/cache/thin

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

// ============================================================================
// RAID Levels
// ============================================================================

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RaidLevel {
    Linear = -1,
    Raid0 = 0,
    Raid1 = 1,
    Raid4 = 4,
    Raid5 = 5,
    Raid6 = 6,
    Raid10 = 10,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Raid5Algorithm {
    LeftAsymmetric = 0,
    RightAsymmetric = 1,
    LeftSymmetric = 2,
    RightSymmetric = 3,
    PreambleN = 4,
    LeftAsymmetric6 = 16,
    RightAsymmetric6 = 17,
    LeftSymmetric6 = 18,
    RightSymmetric6 = 19,
    PreambleN6 = 20,
}

// ============================================================================
// MD Superblock
// ============================================================================

#[repr(C)]
pub struct MdSuperblock1 {
    pub magic: u32,            // 0xa92b4efc
    pub major_version: u32,
    pub feature_map: u32,
    pub pad0: u32,
    pub set_uuid: [u8; 16],
    pub set_name: [u8; 32],
    pub ctime: u64,
    pub level: i32,
    pub layout: u32,
    pub size: u64,
    pub chunksize: u32,
    pub raid_disks: u32,
    pub bitmap_offset: u32,
    pub new_level: i32,
    pub reshape_position: u64,
    pub delta_disks: i32,
    pub new_layout: u32,
    pub new_chunk: u32,
    pub new_offset: u32,
    pub data_offset: u64,
    pub data_size: u64,
    pub super_offset: u64,
    pub recovery_offset: u64,
    pub dev_number: u32,
    pub cnt_corrected_read: u32,
    pub device_uuid: [u8; 16],
    pub devflags: u8,
    pub bblog_shift: u8,
    pub bblog_size: u16,
    pub bblog_offset: u32,
    pub utime: u64,
    pub events: u64,
    pub resync_offset: u64,
    pub sb_csum: u32,
    pub max_dev: u32,
    pub dev_roles: [u16; 256],
}

pub const MD_SUPERBLOCK_MAGIC: u32 = 0xa92b4efc;

// ============================================================================
// MD Device (mddev)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MdState {
    Clean = 0,
    Active = 1,
    ReadOnly = 2,
    Inactive = 3,
    Suspended = 4,
    Broken = 5,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MdArrayState {
    Clear = 0,
    Inactive = 1,
    Suspended = 2,
    ReadOnly = 3,
    ReadAuto = 4,
    Active = 5,
    ActiveIdle = 6,
    WritePending = 7,
    BrokenWritePending = 8,
}

#[repr(C)]
pub struct MdDev {
    pub unit: u32,
    pub md_minor: u32,
    pub level: RaidLevel,
    pub state: MdState,
    pub array_state: MdArrayState,
    pub dev_sectors: u64,
    pub array_sectors: u64,
    pub external_size: bool,
    pub chunk_sectors: u32,
    pub new_chunk_sectors: u32,
    pub layout: u32,
    pub new_layout: u32,
    pub raid_disks: u32,
    pub max_disks: u32,
    pub delta_disks: i32,
    pub degraded: u32,
    pub recovery_disabled: u32,
    pub in_sync: u32,
    pub bitmap_info: MdBitmapInfo,
    pub reshape_position: u64,
    pub reshape_backwards: bool,
    pub recovery_cp: u64,
    pub resync_min: u64,
    pub resync_max: u64,
    pub resync_mismatches: AtomicU64,
    pub suspend_lo: u64,
    pub suspend_hi: u64,
    pub sync_speed_min: u32,
    pub sync_speed_max: u32,
    pub safemode_delay: u32,
    pub last_sync_action: [u8; 20],
    pub uuid: [u8; 16],
    pub events: u64,
    pub flags: MdDevFlags,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MdDevFlags {
    bits: u32,
}

impl MdDevFlags {
    pub const MD_UPDATE_SB_FLAGS: u32 = 1 << 0;
    pub const MD_ARRAY_FIRST_USE: u32 = 1 << 1;
    pub const MD_CLOSING: u32 = 1 << 2;
    pub const MD_JOURNAL_CLEAN: u32 = 1 << 3;
    pub const MD_HAS_JOURNAL: u32 = 1 << 4;
    pub const MD_CLUSTER_RESYNC_LOCKED: u32 = 1 << 5;
    pub const MD_FAILFAST_SUPPORTED: u32 = 1 << 6;
    pub const MD_HAS_PPL: u32 = 1 << 7;
    pub const MD_BROKEN: u32 = 1 << 8;
}

#[repr(C)]
pub struct MdBitmapInfo {
    pub default_offset: u64,
    pub default_space: u64,
    pub chunksize: u64,
    pub daemon_sleep: u64,
    pub max_write_behind: u32,
    pub nodes: u32,
    pub external: bool,
}

// ============================================================================
// MD Personality
// ============================================================================

#[repr(C)]
pub struct MdPersonality {
    pub name: [u8; 16],
    pub level: RaidLevel,
    pub owner: u64,
    pub make_request: u64,
    pub run: u64,
    pub free: u64,
    pub status: u64,
    pub error_handler: u64,
    pub hot_add_disk: u64,
    pub hot_remove_disk: u64,
    pub spare_active: u64,
    pub sync_request: u64,
    pub resize: u64,
    pub size: u64,
    pub check_reshape: u64,
    pub start_reshape: u64,
    pub finish_reshape: u64,
    pub quiesce: u64,
    pub takeover: u64,
    pub change_consistency_policy: u64,
}

// ============================================================================
// Device Mapper Core
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmTargetType {
    Linear = 0,
    Striped = 1,
    Mirror = 2,
    Snapshot = 3,
    SnapshotOrigin = 4,
    SnapshotMerge = 5,
    Zero = 6,
    Error = 7,
    Crypt = 8,
    Delay = 9,
    Flakey = 10,
    Log_Writes = 11,
    Dust = 12,
    Thin = 13,
    ThinPool = 14,
    Cache = 15,
    Era = 16,
    Clone = 17,
    Writecache = 18,
    Verity = 19,
    Integrity = 20,
    Raid = 21,
    MultipathBio = 22,
    Switch = 23,
    Unstriped = 24,
    Bow = 25,
}

#[repr(C)]
pub struct DmTarget {
    pub target_type: DmTargetType,
    pub begin: u64,         // Start sector
    pub len: u64,           // Length in sectors
    pub max_io_len: u32,
    pub num_flush_bios: u32,
    pub num_discard_bios: u32,
    pub num_secure_erase_bios: u32,
    pub num_write_zeroes_bios: u32,
    pub per_io_data_size: u32,
    pub private: u64,
    pub error: [u8; 256],
    pub always_writeable: bool,
    pub is_immutable: bool,
    pub accounts_remapped_io: bool,
    pub discards_supported: bool,
}

#[repr(C)]
pub struct DmTable {
    pub num_targets: u32,
    pub targets: [DmTarget; 256],
    pub mode: u32,           // FMODE_READ | FMODE_WRITE
    pub immutable_target_type: DmTargetType,
    pub integrity_supported: bool,
    pub singleton: bool,
    pub flush_supported: bool,
    pub discards_supported: bool,
}

// ============================================================================
// DM Crypt
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmCryptCipher {
    AesXtsPlain64 = 0,
    AesCbcEssiv = 1,
    AesCbcPlain = 2,
    AesCbcPlain64 = 3,
    Sm4XtsPlain64 = 4,
    AesAdiantum = 5,
    ChaCha20 = 6,
    Twofish128CbcPlain64 = 7,
    Serpent256XtsPlain64 = 8,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmCryptIvMode {
    Plain = 0,
    Plain64 = 1,
    Plain64be = 2,
    Essiv = 3,
    Benbi = 4,
    Null = 5,
    Lmk = 6,
    TcwPlain = 7,
    Eboiv = 8,
    Elephant = 9,
}

#[repr(C)]
pub struct DmCryptConfig {
    pub cipher: DmCryptCipher,
    pub iv_mode: DmCryptIvMode,
    pub key_size: u32,
    pub key: [u8; 64],
    pub key_string: [u8; 128],
    pub key_parts: u32,
    pub key_extra_size: u32,
    pub iv_offset: u64,
    pub sector_size: u16,
    pub sector_shift: u8,
    pub allow_discards: bool,
    pub same_cpu_crypt: bool,
    pub submit_from_crypt_cpus: bool,
    pub no_read_workqueue: bool,
    pub no_write_workqueue: bool,
    pub integrity: bool,
    pub integrity_tag_size: u32,
    pub integrity_iv_size: u32,
}

// ============================================================================
// DM Thin Provisioning
// ============================================================================

#[repr(C)]
pub struct DmThinPoolConfig {
    pub data_dev: [u8; 64],
    pub metadata_dev: [u8; 64],
    pub block_size: u32,         // In 512-byte sectors
    pub low_water_blocks: u64,
    pub error_if_no_space: bool,
    pub skip_block_zeroing: bool,
    pub ignore_discard: bool,
    pub no_discard_passdown: bool,
}

#[repr(C)]
pub struct DmThinPoolStatus {
    pub transaction_id: u64,
    pub used_metadata_blocks: u64,
    pub total_metadata_blocks: u64,
    pub used_data_blocks: u64,
    pub total_data_blocks: u64,
    pub held_metadata_root: u64,
    pub mode: DmThinPoolMode,
    pub discard_passdown: bool,
    pub error_if_no_space: bool,
    pub needs_check: bool,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmThinPoolMode {
    Write = 0,
    ReadOnly = 1,
    OutOfDataSpace = 2,
    Failed = 3,
}

#[repr(C)]
pub struct DmThinDev {
    pub dev_id: u32,
    pub mapped_blocks: u64,
    pub highest_mapped: u64,
    pub creation_time: u32,
    pub snap_time: u32,
    pub is_snapshot: bool,
    pub origin_id: u32,
}

// ============================================================================
// DM Cache (bcache-style)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmCachePolicy {
    Smq = 0,     // Stochastic Multiqueue
    Mq = 1,      // Multiqueue (deprecated)
    Cleaner = 2,
}

#[repr(C)]
pub struct DmCacheConfig {
    pub metadata_dev: [u8; 64],
    pub cache_dev: [u8; 64],
    pub origin_dev: [u8; 64],
    pub block_size: u32,
    pub policy: DmCachePolicy,
    pub migration_threshold: u32,
    pub sequential_threshold: u32,
    pub random_threshold: u32,
    pub background_writeout: bool,
    pub writeback: bool,
    pub passthrough: bool,
}

#[repr(C)]
pub struct DmCacheStatus {
    pub metadata_block_size: u32,
    pub metadata_used: u64,
    pub metadata_total: u64,
    pub cache_block_size: u32,
    pub cache_used: u64,
    pub cache_total: u64,
    pub read_hits: AtomicU64,
    pub read_misses: AtomicU64,
    pub write_hits: AtomicU64,
    pub write_misses: AtomicU64,
    pub demotions: AtomicU64,
    pub promotions: AtomicU64,
    pub dirty: u64,
    pub mode: DmThinPoolMode,
    pub needs_check: bool,
}

// ============================================================================
// DM Integrity
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmIntegrityMode {
    Bitmap = 0,    // Bitmap mode (for SSDs)
    Journal = 1,   // Journal mode
    DirectIO = 2,
}

#[repr(C)]
pub struct DmIntegrityConfig {
    pub mode: DmIntegrityMode,
    pub tag_size: u32,
    pub internal_hash: [u8; 32],
    pub journal_sectors: u32,
    pub interleave_sectors: u32,
    pub buffer_sectors: u32,
    pub journal_watermark: u32,
    pub commit_time: u32,
    pub sectors_per_bit: u32,
    pub bitmap_flush_interval: u32,
    pub fix_padding: bool,
    pub fix_hmac: bool,
    pub legacy_recalculate: bool,
    pub allow_discards: bool,
}

// ============================================================================
// Manager
// ============================================================================

pub struct RaidDmManager {
    pub total_arrays: AtomicU32,
    pub total_dm_targets: AtomicU32,
    pub total_thin_pools: AtomicU32,
    pub total_cache_targets: AtomicU32,
    pub total_crypt_targets: AtomicU32,
    pub total_integrity_targets: AtomicU32,
    pub total_io_submitted: AtomicU64,
    pub total_io_completed: AtomicU64,
    pub total_resync_sectors: AtomicU64,
    pub total_reshape_sectors: AtomicU64,
    pub total_write_hits: AtomicU64,
    pub total_write_misses: AtomicU64,
    pub initialized: bool,
}

impl RaidDmManager {
    pub const fn new() Self {
        Self {
            total_arrays: AtomicU32::new(0),
            total_dm_targets: AtomicU32::new(0),
            total_thin_pools: AtomicU32::new(0),
            total_cache_targets: AtomicU32::new(0),
            total_crypt_targets: AtomicU32::new(0),
            total_integrity_targets: AtomicU32::new(0),
            total_io_submitted: AtomicU64::new(0),
            total_io_completed: AtomicU64::new(0),
            total_resync_sectors: AtomicU64::new(0),
            total_reshape_sectors: AtomicU64::new(0),
            total_write_hits: AtomicU64::new(0),
            total_write_misses: AtomicU64::new(0),
            initialized: true,
        }
    }
}
