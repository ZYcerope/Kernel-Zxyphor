// Zxyphor Kernel - Device Mapper (dm-crypt, dm-thin, dm-cache, dm-era),
// MD RAID (mdadm), bcache, Target Drivers, Storage Multipathing
// More advanced than Linux 2026 device-mapper

use core::fmt;

/// Device-Mapper target types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Log = 11,
    Raid = 12,
    Thin = 13,
    ThinPool = 14,
    Cache = 15,
    Writecache = 16,
    Era = 17,
    Integrity = 18,
    Verity = 19,
    VDO = 20,
    Dust = 21,
    Ebs = 22,
    Clone = 23,
    // Zxyphor extensions
    ZxyDedup = 100,
    ZxyCompress = 101,
    ZxyTiered = 102,
}

/// DM ioctl commands
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DmIoctlCmd {
    Version = 0,
    RemoveAll = 1,
    ListDevices = 2,
    DevCreate = 3,
    DevRemove = 4,
    DevRename = 5,
    DevSuspend = 6,
    DevStatus = 7,
    DevWait = 8,
    TableLoad = 9,
    TableClear = 10,
    TableDeps = 11,
    TableStatus = 12,
    ListVersions = 13,
    TargetMsg = 14,
    DevSetGeometry = 15,
    DevArm = 16,
    GetTargetVersion = 17,
}

/// DM flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct DmFlags(pub u32);

impl DmFlags {
    pub const READONLY: Self = Self(1 << 0);
    pub const SUSPEND: Self = Self(1 << 1);
    pub const PERSISTENT_DEV: Self = Self(1 << 3);
    pub const STATUS_TABLE: Self = Self(1 << 4);
    pub const ACTIVE_PRESENT: Self = Self(1 << 5);
    pub const INACTIVE_PRESENT: Self = Self(1 << 6);
    pub const BUFFER_FULL: Self = Self(1 << 8);
    pub const SKIP_BDGET: Self = Self(1 << 9);
    pub const SKIP_LOCKFS: Self = Self(1 << 10);
    pub const NOFLUSH: Self = Self(1 << 11);
    pub const QUERY_INACTIVE: Self = Self(1 << 12);
    pub const DEFERRED_REMOVE: Self = Self(1 << 14);
    pub const INTERNAL_SUSPEND: Self = Self(1 << 18);
    pub const IMA_MEASUREMENT: Self = Self(1 << 19);
}

// ============================================================================
// dm-crypt
// ============================================================================

/// dm-crypt cipher mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCryptCipherMode {
    Ecb = 0,
    Cbc = 1,
    Essiv = 2,
    Xts = 3,
    Lmk = 4,
    Tcw = 5,
    Plain = 6,
    Plain64 = 7,
    Plain64be = 8,
    Elephant = 9,  // Adiantum
    // Zxyphor
    ZxyHctr2 = 20,
}

/// dm-crypt IV generation mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCryptIvMode {
    Plain = 0,
    Plain64 = 1,
    Plain64be = 2,
    Essiv = 3,
    Benbi = 4,
    Null = 5,
    Lmk = 6,
    Tcw = 7,
    Random = 8,
    Elephant = 9,
}

/// dm-crypt optional flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct DmCryptFlags(pub u32);

impl DmCryptFlags {
    pub const ALLOW_DISCARDS: Self = Self(1 << 0);
    pub const SAME_CPU_CRYPT: Self = Self(1 << 1);
    pub const SUBMIT_FROM_CRYPT: Self = Self(1 << 2);
    pub const NO_READ_WORKQUEUE: Self = Self(1 << 3);
    pub const NO_WRITE_WORKQUEUE: Self = Self(1 << 4);
    pub const IV_LARGE_SECTORS: Self = Self(1 << 5);
    pub const HIGH_PRIORITY: Self = Self(1 << 6);
}

/// dm-crypt configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmCryptConfig {
    pub cipher_name: [u8; 64],
    pub cipher_name_len: u8,
    pub cipher_mode: DmCryptCipherMode,
    pub iv_mode: DmCryptIvMode,
    pub key_size: u32,       // Bytes
    pub key_hash: [u8; 32],  // Key fingerprint (not the key itself)
    pub sector_size: u32,    // 512 or 4096
    pub offset: u64,         // Start offset in sectors
    pub flags: DmCryptFlags,
    // Integrity tag
    pub integrity_tag_size: u32,
    pub integrity_alg: [u8; 32],
    pub integrity_alg_len: u8,
    // Journal
    pub journal_mode: DmCryptJournalMode,
    // Stats
    pub total_sectors_encrypted: u64,
    pub total_sectors_decrypted: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCryptJournalMode {
    None = 0,
    Dm = 1,
    Bitmap = 2,
}

// ============================================================================
// dm-thin (Thin Provisioning)
// ============================================================================

/// Thin pool configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmThinPoolConfig {
    pub metadata_dev_size: u64,    // Sectors
    pub data_dev_size: u64,        // Sectors
    pub data_block_size: u32,      // Sectors (64KB-1GB)
    pub low_water_mark: u64,       // Blocks
    // Features
    pub skip_block_zeroing: bool,
    pub ignore_discard: bool,
    pub no_discard_passdown: bool,
    pub read_only: bool,
    pub error_if_no_space: bool,
    // Zxyphor
    pub zxy_auto_extend: bool,
    pub zxy_dedup: bool,
}

/// Thin pool status
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmThinPoolStatus {
    pub transaction_id: u64,
    pub used_metadata_blocks: u64,
    pub total_metadata_blocks: u64,
    pub used_data_blocks: u64,
    pub total_data_blocks: u64,
    pub held_metadata_root: u64,
    // Flags
    pub out_of_data_space: bool,
    pub needs_check: bool,
    pub read_only: bool,
    // Discard
    pub discard_passdown: bool,
    // Zxyphor
    pub zxy_dedup_ratio: u32,
}

/// Thin device snapshot relationship
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmThinDeviceInfo {
    pub thin_id: u32,
    pub mapped_blocks: u64,
    pub highest_mapped_block: u64,
    // Snapshot origin (0 if none)
    pub origin_thin_id: u32,
    pub snap_time: u64,
}

// ============================================================================
// dm-cache
// ============================================================================

/// Cache policy type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCachePolicy {
    Smq = 0,          // Stochastic Multi-Queue (default)
    Mq = 1,           // Multi-Queue (deprecated)
    Cleaner = 2,      // For safe removal
    // Zxyphor
    ZxyAdaptive = 10,
    ZxyMlCache = 11,
}

/// Cache mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCacheMode {
    Writeback = 0,
    Writethrough = 1,
    Passthrough = 2,
}

/// dm-cache configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmCacheConfig {
    pub metadata_dev_size: u64,
    pub cache_dev_size: u64,
    pub origin_dev_size: u64,
    pub block_size: u32,           // Sectors
    pub policy: DmCachePolicy,
    pub mode: DmCacheMode,
    // Features
    pub discard_passdown: bool,
    pub metadata_version: u32,     // 1 or 2
    // Zxyphor
    pub zxy_tiered_cache: bool,
}

/// dm-cache status
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmCacheStatus {
    pub used_metadata_blocks: u64,
    pub total_metadata_blocks: u64,
    pub nr_blocks: u64,            // Cache size in blocks
    pub nr_used: u64,              // Cache blocks in use
    pub nr_dirty: u64,             // Dirty cache blocks
    // Hit/miss
    pub read_hits: u64,
    pub read_misses: u64,
    pub write_hits: u64,
    pub write_misses: u64,
    // Demotions/promotions
    pub demotions: u64,
    pub promotions: u64,
    // Migration
    pub nr_migrations: u64,
    // Discard
    pub nr_discards: u64,
    // Policy
    pub policy_name: [u8; 32],
    pub policy_name_len: u8,
}

// ============================================================================
// dm-era
// ============================================================================

/// dm-era status
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmEraStatus {
    pub metadata_block_size: u32,
    pub nr_blocks: u64,
    pub current_era: u32,
    pub used_metadata_blocks: u64,
    pub total_metadata_blocks: u64,
}

// ============================================================================
// MD RAID
// ============================================================================

/// RAID level
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidLevel {
    Linear = 0,
    Raid0 = 1,
    Raid1 = 2,
    Raid4 = 4,
    Raid5 = 5,
    Raid6 = 6,
    Raid10 = 10,
    // Zxyphor
    ZxyRaid7 = 70,     // Triple parity
    ZxyAdaptive = 100,
}

/// RAID state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RaidState {
    Clear = 0,
    Inactive = 1,
    Suspended = 2,
    Readonly = 3,
    ReadAuto = 4,
    Clean = 5,
    Active = 6,
    WritePending = 7,
    ActiveIdle = 8,
    Broken = 9,
}

/// RAID disk state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RaidDiskState {
    Active = 0,
    Faulty = 1,
    Spare = 2,
    WriteMostly = 3,
    Blocked = 4,
    Replacement = 5,
    Removed = 6,
    // Zxyphor
    ZxyDegraded = 10,
    ZxyRebuilding = 11,
}

/// MD RAID superblock (v1.2)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MdSuperblock {
    pub magic: u32,                // MD_SB_MAGIC = 0xa92b4efc
    pub major_version: u32,        // 1
    pub feature_map: u32,
    pub pad0: u32,
    pub set_uuid: [u8; 16],
    pub set_name: [u8; 32],
    pub ctime: u64,
    pub level: i32,
    pub layout: u32,
    pub size: u64,                 // Used device size in 512-byte sectors
    pub chunksize: u32,            // In 512-byte sectors
    pub raid_disks: u32,
    pub bitmap_offset: u32,
    // Reshape
    pub new_level: i32,
    pub reshape_position: u64,
    pub delta_disks: i32,
    pub new_layout: u32,
    pub new_chunk: u32,
    pub new_offset: u32,
    // This device
    pub data_offset: u64,
    pub data_size: u64,
    pub super_offset: u64,
    pub recovery_offset: u64,
    pub dev_number: u32,
    pub cnt_corrected_read: u32,
    pub device_uuid: [u8; 16],
    pub devflags: u8,
    // Bad block log
    pub bblog_shift: u8,
    pub bblog_size: u16,
    pub bblog_offset: u32,
}

pub const MD_SB_MAGIC: u32 = 0xa92b4efc;

/// RAID array configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RaidArrayConfig {
    pub level: RaidLevel,
    pub nr_disks: u32,
    pub nr_active: u32,
    pub nr_spare: u32,
    pub nr_failed: u32,
    pub chunk_size_kb: u32,
    pub layout: u32,
    pub state: RaidState,
    // Bitmap
    pub bitmap_enabled: bool,
    pub bitmap_file: bool,     // External bitmap
    // Write intent
    pub write_behind: u32,
    pub write_mostly_count: u32,
    // Journal
    pub journal_dev: bool,
    // Reshape
    pub reshape_active: bool,
    pub reshape_position: u64,
    // Consistency policy
    pub consistency_policy: RaidConsistency,
    // Zxyphor
    pub zxy_scrub_interval_hours: u32,
    pub zxy_auto_rebuild: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RaidConsistency {
    Unknown = 0,
    None = 1,
    Resync = 2,
    Bitmap = 3,
    Journal = 4,
    Ppl = 5,      // Partial Parity Log
}

/// RAID stats
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RaidStats {
    pub total_sync_speed_kb: u64,
    pub sync_completed: u64,
    pub sync_total: u64,
    pub mismatch_count: u64,
    pub read_errors: u64,
    pub write_errors: u64,
    // Rebuild
    pub rebuild_progress: u64,   // Percentage * 100
    pub rebuild_speed_kb: u64,
    // Scrub
    pub last_scrub_time: u64,
    pub scrub_errors: u64,
}

// ============================================================================
// bcache
// ============================================================================

/// bcache cache mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BcacheCacheMode {
    Writethrough = 0,
    Writeback = 1,
    Writearound = 2,
    None = 3,
}

/// bcache state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BcacheState {
    NoBdevBound = 0,
    BdevBound = 1,
    CacheReady = 2,
    Running = 3,
}

/// bcache configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BcacheConfig {
    pub cache_mode: BcacheCacheMode,
    pub state: BcacheState,
    pub sequential_cutoff: u32,   // Bytes
    pub readahead: u32,           // Sectors
    pub writeback_running: bool,
    pub writeback_percent: u8,
    pub writeback_delay: u32,     // Seconds
    // Stats
    pub bypassed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bypass_hits: u64,
    pub cache_bypass_misses: u64,
    pub cache_readaheads: u64,
    pub cache_miss_collisions: u64,
    // Bucket
    pub bucket_size_kb: u32,
    pub nr_buckets: u64,
    pub nr_free_buckets: u64,
    // Priority
    pub average_key_age: u32,
    pub btree_cache_size: u64,
}

// ============================================================================
// dm-multipath
// ============================================================================

/// Path selector
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmMpathSelector {
    RoundRobin = 0,
    QueueLength = 1,
    ServiceTime = 2,
    Historical = 3,
    IoAffinity = 4,
    // Zxyphor
    ZxyAdaptive = 10,
    ZxyLatencyAware = 11,
}

/// Path state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmMpathPathState {
    Active = 0,
    Failed = 1,
    Shaky = 2,
    Ghost = 3,
}

/// Multipath config
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DmMpathConfig {
    pub nr_priority_groups: u32,
    pub nr_paths: u32,
    pub queue_mode: DmMpathQueueMode,
    pub hw_handler: [u8; 32],
    pub hw_handler_len: u8,
    pub selector: DmMpathSelector,
    // Features
    pub no_partitions: bool,
    pub retain_attached_hw_handler: bool,
    // Stats
    pub total_io: u64,
    pub total_failovers: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmMpathQueueMode {
    Bio = 0,
    Rq = 1,
    Mq = 2,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct DeviceMapperSubsystem {
    // DM
    pub nr_dm_devices: u64,
    pub nr_dm_targets: u64,
    // dm-crypt
    pub nr_crypt_devices: u32,
    pub total_encrypted_sectors: u64,
    // dm-thin
    pub nr_thin_pools: u32,
    pub nr_thin_devices: u32,
    pub total_provisioned_bytes: u64,
    // dm-cache
    pub nr_cache_devices: u32,
    pub total_cache_hits: u64,
    pub total_cache_misses: u64,
    // MD RAID
    pub nr_raid_arrays: u32,
    pub nr_degraded_arrays: u32,
    pub total_rebuild_ops: u64,
    // bcache
    pub nr_bcache_devices: u32,
    // Multipath
    pub nr_multipath_devices: u32,
    pub total_failovers: u64,
    // Zxyphor
    pub zxy_dedup_enabled: bool,
    pub zxy_compression_enabled: bool,
    pub initialized: bool,
}

impl DeviceMapperSubsystem {
    pub const fn new() -> Self {
        Self {
            nr_dm_devices: 0,
            nr_dm_targets: 0,
            nr_crypt_devices: 0,
            total_encrypted_sectors: 0,
            nr_thin_pools: 0,
            nr_thin_devices: 0,
            total_provisioned_bytes: 0,
            nr_cache_devices: 0,
            total_cache_hits: 0,
            total_cache_misses: 0,
            nr_raid_arrays: 0,
            nr_degraded_arrays: 0,
            total_rebuild_ops: 0,
            nr_bcache_devices: 0,
            nr_multipath_devices: 0,
            total_failovers: 0,
            zxy_dedup_enabled: true,
            zxy_compression_enabled: true,
            initialized: false,
        }
    }
}
