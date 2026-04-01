// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Block Device Layer, BIO, Disk Partitions,
// Filesystem Freeze/Thaw, Disk Quota Zig-side, Block I/O Priority
// More advanced than Linux 2026 block device interface

const std = @import("std");

// ============================================================================
// Block Device
// ============================================================================

/// Block device flags
pub const BlockDevFlags = packed struct {
    read_only: bool = false,
    removable: bool = false,
    rotational: bool = false,       // HDD vs SSD
    write_same: bool = false,
    write_zeroes: bool = false,
    discard: bool = false,
    secure_erase: bool = false,
    no_partition_scan: bool = false,
    hidden: bool = false,
    nowait: bool = false,
    raid_partition: bool = false,
    zoned: bool = false,
    // Zxyphor
    zxy_compressed: bool = false,
    zxy_encrypted: bool = false,
    zxy_dedup: bool = false,
    _padding: u1 = 0,
};

/// Block device type
pub const BlockDevType = enum(u8) {
    disk = 0,
    partition = 1,
    loop_dev = 2,
    ram = 3,
    nbd = 4,    // Network block device
    dm = 5,     // Device mapper
    md = 6,     // Software RAID
    nvme = 7,
    virtio = 8,
    // Zxyphor
    zxy_unified = 50,
};

/// Block device descriptor
pub const BlockDevice = struct {
    // Identity
    name: [32]u8,
    disk_name: [32]u8,
    dev_major: u32,
    dev_minor: u32,
    dev_type: BlockDevType,
    // Geometry
    nr_sectors: u64,        // 512-byte sectors
    sector_size: u32,       // Logical sector size
    physical_block_size: u32,
    io_min: u32,            // Minimum I/O size
    io_opt: u32,            // Optimal I/O size
    alignment_offset: u32,
    max_sectors: u32,       // Max sectors per request
    max_hw_sectors: u32,
    max_segments: u16,
    max_segment_size: u32,
    max_discard_sectors: u32,
    max_write_zeroes_sectors: u32,
    discard_granularity: u32,
    discard_alignment: u32,
    // Zoned
    zone_model: ZoneModel,
    nr_zones: u32,
    zone_size_sectors: u64,
    max_open_zones: u32,
    max_active_zones: u32,
    // Queue limits
    max_hw_discard_sectors: u32,
    max_secure_erase_sectors: u32,
    dma_alignment: u32,
    // Flags
    flags: BlockDevFlags,
    // Partitions
    nr_partitions: u32,
    start_sect: u64,         // Partition start
    nr_sects: u64,           // Partition size
    // Queue
    nr_hw_queues: u16,
    queue_depth: u32,
    // I/O scheduler
    scheduler: IoScheduler,
    // Stats
    read_ios: u64,
    read_merges: u64,
    read_sectors: u64,
    read_ticks_ms: u64,
    write_ios: u64,
    write_merges: u64,
    write_sectors: u64,
    write_ticks_ms: u64,
    discard_ios: u64,
    discard_merges: u64,
    discard_sectors: u64,
    discard_ticks_ms: u64,
    flush_ios: u64,
    flush_ticks_ms: u64,
    in_flight: u32,
    io_ticks_ms: u64,
    time_in_queue_ms: u64,
};

/// Zone model
pub const ZoneModel = enum(u8) {
    none = 0,           // Conventional
    host_aware = 1,     // Host-aware SMR
    host_managed = 2,   // Host-managed SMR
};

/// I/O Scheduler type
pub const IoScheduler = enum(u8) {
    none = 0,
    mq_deadline = 1,
    bfq = 2,
    kyber = 3,
    // Zxyphor
    zxy_adaptive = 10,
    zxy_latency = 11,
};

// ============================================================================
// BIO (Block I/O)
// ============================================================================

/// BIO operation flags
pub const BioOpFlags = packed struct {
    // Operation type (bits 0-7)
    op: u8 = 0,
    // Flags
    failfast_dev: bool = false,
    failfast_transport: bool = false,
    failfast_driver: bool = false,
    sync: bool = false,
    meta: bool = false,
    prio: bool = false,
    nomerge: bool = false,
    idle: bool = false,
    integrity: bool = false,
    fua: bool = false,
    preflush: bool = false,
    rahead: bool = false,
    background: bool = false,
    nowait: bool = false,
    polled: bool = false,
    alloc_cache: bool = false,
    // Zxyphor
    zxy_priority: bool = false,
    zxy_compressed: bool = false,
    _padding: u6 = 0,
};

/// BIO operation type
pub const BioOp = enum(u8) {
    read = 0,
    write = 1,
    flush = 2,
    discard = 3,
    secure_erase = 4,
    write_zeroes = 5,
    zone_open = 6,
    zone_close = 7,
    zone_finish = 8,
    zone_append = 9,
    zone_reset = 10,
    zone_reset_all = 11,
    drv_in = 12,
    drv_out = 13,
};

/// BIO status
pub const BioStatus = enum(u8) {
    ok = 0,
    io_err = 1,
    timeout = 2,
    nospc = 3,
    transport = 4,
    target = 5,
    nexus = 6,
    medium = 7,
    protection = 8,
    resource = 9,
    again = 10,
    zone_resource = 11,
    zone_open_resource = 12,
    zone_active_resource = 13,
    offline = 14,
    // Zxyphor
    zxy_compressed_err = 50,
};

/// Request I/O priority (ioprio)
pub const IoprioClass = enum(u3) {
    none = 0,
    rt = 1,       // Real-time
    best_effort = 2,
    idle = 3,
};

/// I/O priority value
pub const Ioprio = struct {
    class: IoprioClass,
    level: u4, // 0-7 for RT and BE
    hint: IoprioHint,
};

/// I/O priority hint
pub const IoprioHint = enum(u4) {
    none = 0,
    dur_short = 1,
    dur_medium = 2,
    dur_long = 3,
};

// ============================================================================
// Disk Partitions
// ============================================================================

/// Partition table type
pub const PartTableType = enum(u8) {
    none = 0,
    mbr = 1,      // MBR (legacy)
    gpt = 2,      // GPT (UEFI)
    mac = 3,      // Apple Partition Map
    bsd = 4,      // BSD disklabel
    sun = 5,      // Sun/Solaris
    sgi = 6,      // SGI/IRIX
};

/// MBR partition entry
pub const MbrPartEntry = struct {
    boot_indicator: u8,
    start_chs: [3]u8,
    os_type: u8,
    end_chs: [3]u8,
    start_lba: u32,
    size_lba: u32,
};

/// MBR OS type codes
pub const MBR_TYPE_EMPTY: u8 = 0x00;
pub const MBR_TYPE_FAT12: u8 = 0x01;
pub const MBR_TYPE_FAT16_SMALL: u8 = 0x04;
pub const MBR_TYPE_EXTENDED: u8 = 0x05;
pub const MBR_TYPE_FAT16_LARGE: u8 = 0x06;
pub const MBR_TYPE_NTFS: u8 = 0x07;
pub const MBR_TYPE_FAT32: u8 = 0x0B;
pub const MBR_TYPE_FAT32_LBA: u8 = 0x0C;
pub const MBR_TYPE_FAT16_LBA: u8 = 0x0E;
pub const MBR_TYPE_EXTENDED_LBA: u8 = 0x0F;
pub const MBR_TYPE_LINUX_SWAP: u8 = 0x82;
pub const MBR_TYPE_LINUX: u8 = 0x83;
pub const MBR_TYPE_LINUX_EXTENDED: u8 = 0x85;
pub const MBR_TYPE_LINUX_LVM: u8 = 0x8E;
pub const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;
pub const MBR_TYPE_EFI_SYSTEM: u8 = 0xEF;
pub const MBR_TYPE_LINUX_RAID: u8 = 0xFD;

/// GPT header
pub const GptHeader = struct {
    signature: u64,         // "EFI PART"
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32,
    my_lba: u64,
    alternate_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [16]u8,
    partition_entry_lba: u64,
    num_partition_entries: u32,
    sizeof_partition_entry: u32,
    partition_entry_array_crc32: u32,
};

pub const GPT_SIGNATURE: u64 = 0x5452415020494645; // "EFI PART"

/// GPT partition entry
pub const GptPartEntry = struct {
    type_guid: [16]u8,
    unique_guid: [16]u8,
    starting_lba: u64,
    ending_lba: u64,
    attributes: u64,
    name: [72]u8,      // UTF-16LE, 36 chars
};

/// Well-known GPT type GUIDs (first 4 bytes)
pub const GPT_TYPE_EFI_SYSTEM: [4]u8 = .{ 0x28, 0x73, 0x2A, 0xC1 };
pub const GPT_TYPE_LINUX_FS: [4]u8 = .{ 0xAF, 0x3D, 0xC6, 0x0F };
pub const GPT_TYPE_LINUX_SWAP: [4]u8 = .{ 0x57, 0x2F, 0x85, 0x06 };
pub const GPT_TYPE_LINUX_LVM: [4]u8 = .{ 0x79, 0xD3, 0xD6, 0xE6 };
pub const GPT_TYPE_LINUX_RAID: [4]u8 = .{ 0xDB, 0xEA, 0x26, 0xA5 };
pub const GPT_TYPE_LINUX_HOME: [4]u8 = .{ 0x3F, 0xAC, 0x68, 0x93 };
pub const GPT_TYPE_LINUX_ROOT: [4]u8 = .{ 0x35, 0x54, 0x0F, 0x69 };

// ============================================================================
// Filesystem Freeze/Thaw
// ============================================================================

/// Filesystem freeze state
pub const FsFreezeState = enum(u8) {
    unfrozen = 0,
    write_freeze = 1,  // sb_start_write blocked
    page_fault_freeze = 2,
    fs_freeze = 3,     // fs_reclaim blocked
    complete = 4,      // Fully frozen
};

/// Filesystem freeze info
pub const FsFreezeInfo = struct {
    state: FsFreezeState,
    freeze_count: u32,     // Can be frozen multiple times
    // Timing
    freeze_time_ns: u64,
    total_freeze_duration_ns: u64,
    total_freeze_count: u64,
    // Waiters
    nr_pending_writes: u32,
    nr_pending_faults: u32,
};

// ============================================================================
// Disk Quota
// ============================================================================

/// Quota type
pub const QuotaType = enum(u8) {
    user = 0,
    group = 1,
    project = 2,
};

/// Quota format
pub const QuotaFormat = enum(u8) {
    vfsold = 1,   // Original VFS quota format
    vfsv0 = 2,    // VFS v0 quota format
    vfsv1 = 3,    // VFS v1 quota format (variable length)
    ocfs2 = 4,    // OCFS2 quota format
};

/// Quota flags
pub const QuotaFlags = packed struct {
    usrquota: bool = false,
    grpquota: bool = false,
    prjquota: bool = false,
    // Enforcement
    usrquota_enforced: bool = false,
    grpquota_enforced: bool = false,
    prjquota_enforced: bool = false,
    _padding: u2 = 0,
};

/// Disk quota entry
pub const DiskQuota = struct {
    id: u32,                     // UID/GID/Project ID
    quota_type: QuotaType,
    // Block limits
    dqb_bhardlimit: u64,        // Hard block limit (bytes)
    dqb_bsoftlimit: u64,        // Soft block limit
    dqb_curspace: u64,           // Current space usage
    dqb_btime: i64,              // Time limit for excess soft block usage
    // Inode limits
    dqb_ihardlimit: u64,        // Hard inode limit
    dqb_isoftlimit: u64,        // Soft inode limit
    dqb_curinodes: u64,          // Current inode count
    dqb_itime: i64,              // Time limit for excess soft inode usage
    // Grace periods
    dqb_btime_grace: i64,       // Block grace period (seconds)
    dqb_itime_grace: i64,       // Inode grace period
    // Warnings
    dqb_bwarns: u32,
    dqb_iwarns: u32,
    // Flags
    dqb_valid: u32,              // Valid fields mask
};

/// Quota info per filesystem
pub const QuotaInfo = struct {
    flags: QuotaFlags,
    format: QuotaFormat,
    // Timing
    bgrace: i64,     // Block grace period default
    igrace: i64,     // Inode grace period default
    // Counts
    nr_dquotes: u64,  // Active dquot entries
    syncs: u64,
    // Stats
    total_lookups: u64,
    total_drops: u64,
    total_reads: u64,
    total_writes: u64,
    total_cache_hits: u64,
};

// ============================================================================
// Block I/O Accounting
// ============================================================================

/// Per-cgroup blkio stats
pub const BlkioCgroupStats = struct {
    // Service bytes
    read_bytes: u64,
    write_bytes: u64,
    // Service IOs
    read_ios: u64,
    write_ios: u64,
    // Merged
    read_merges: u64,
    write_merges: u64,
    // Wait time (us)
    read_wait_us: u64,
    write_wait_us: u64,
    // Service time (us)
    read_service_us: u64,
    write_service_us: u64,
    // Queued
    avg_queue_size: u32,
    // Throttle
    throttle_read_bytes: u64,
    throttle_write_bytes: u64,
    throttle_read_ios: u64,
    throttle_write_ios: u64,
    // IO cost
    io_cost_usage: u64,
    io_cost_weight: u32,
    io_cost_qos_rpct: u8,
    io_cost_qos_rlat: u32,
    io_cost_qos_wpct: u8,
    io_cost_qos_wlat: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Block device subsystem
pub const BlockDevSubsystem = struct {
    // Devices
    nr_block_devices: u32,
    nr_disks: u32,
    nr_partitions: u32,
    nr_loop_devices: u32,
    // Bio
    total_bio_alloc: u64,
    total_bio_free: u64,
    total_bio_split: u64,
    // I/O stats
    total_read_ios: u64,
    total_write_ios: u64,
    total_read_bytes: u64,
    total_write_bytes: u64,
    total_discard_ios: u64,
    total_flush_ios: u64,
    // Scheduler
    total_merges: u64,
    total_dispatches: u64,
    // Quota
    nr_quota_enabled_fs: u32,
    total_quota_checks: u64,
    total_quota_denials: u64,
    // Freeze
    nr_frozen_fs: u32,
    // Zxyphor
    zxy_io_prediction: bool,
    zxy_adaptive_scheduler: bool,
    initialized: bool,

    pub fn init() BlockDevSubsystem {
        return BlockDevSubsystem{
            .nr_block_devices = 0,
            .nr_disks = 0,
            .nr_partitions = 0,
            .nr_loop_devices = 0,
            .total_bio_alloc = 0,
            .total_bio_free = 0,
            .total_bio_split = 0,
            .total_read_ios = 0,
            .total_write_ios = 0,
            .total_read_bytes = 0,
            .total_write_bytes = 0,
            .total_discard_ios = 0,
            .total_flush_ios = 0,
            .total_merges = 0,
            .total_dispatches = 0,
            .nr_quota_enabled_fs = 0,
            .total_quota_checks = 0,
            .total_quota_denials = 0,
            .nr_frozen_fs = 0,
            .zxy_io_prediction = true,
            .zxy_adaptive_scheduler = true,
            .initialized = false,
        };
    }
};
