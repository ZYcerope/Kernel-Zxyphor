// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Block Layer (Rust)  
// Block I/O scheduler, multi-queue, bio, request management, device-mapper targets

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// Block Device
// ============================================================================

pub const SECTOR_SIZE: u64 = 512;
pub const SECTOR_SHIFT: u32 = 9;
pub const PAGE_SECTORS: u64 = 4096 / SECTOR_SIZE;

pub struct BlockDevice {
    pub major: u32,
    pub minor: u32,
    pub name: [u8; 32],
    pub name_len: u8,
    // Geometry
    pub capacity_sectors: u64,   // Device size in sectors
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub io_min: u32,             // Minimum I/O size
    pub io_opt: u32,             // Optimal I/O size
    pub alignment_offset: u32,
    pub max_sectors: u32,        // Max sectors per request
    pub max_hw_sectors: u32,     // Hardware max
    pub max_segments: u16,       // Max scatter-gather segments
    pub max_segment_size: u32,
    pub max_discard_sectors: u32,
    pub max_write_zeroes_sectors: u32,
    pub discard_granularity: u32,
    pub discard_alignment: u32,
    // Features
    pub rotational: bool,
    pub removable: bool,
    pub read_only: bool,
    pub fua_supported: bool,    // Force Unit Access
    pub discard_supported: bool,
    pub write_zeroes_supported: bool,
    pub secure_erase_supported: bool,
    pub zoned: ZonedModel,
    // Queue limits
    pub nr_hw_queues: u16,
    pub queue_depth: u16,
    pub nr_requests: u32,
    // Stats
    pub stats: DiskStats,
    // I/O scheduler
    pub iosched: IoSchedType,
    // Partition info
    pub partno: u32,
    pub nr_partitions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZonedModel {
    None,
    HostAware,
    HostManaged,
    DeviceManaged,
}

pub struct DiskStats {
    pub read_ios: AtomicU64,
    pub read_merges: AtomicU64,
    pub read_sectors: AtomicU64,
    pub read_ticks: AtomicU64,     // ms
    pub write_ios: AtomicU64,
    pub write_merges: AtomicU64,
    pub write_sectors: AtomicU64,
    pub write_ticks: AtomicU64,
    pub discard_ios: AtomicU64,
    pub discard_merges: AtomicU64,
    pub discard_sectors: AtomicU64,
    pub discard_ticks: AtomicU64,
    pub flush_ios: AtomicU64,
    pub flush_ticks: AtomicU64,
    pub in_flight: AtomicU32,
    pub io_ticks: AtomicU64,       // Wall clock time doing I/O
    pub time_in_queue: AtomicU64,  // Weighted I/O time
}

// ============================================================================
// BIO (Block I/O)
// ============================================================================

pub const BIO_MAX_VECS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum BioOp {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    SecureErase = 4,
    WriteZeroes = 5,
    ZoneOpen = 6,
    ZoneClose = 7,
    ZoneFinish = 8,
    ZoneAppend = 9,
    ZoneReset = 10,
    ZoneResetAll = 11,
    DrvIn = 12,      // Driver-specific in
    DrvOut = 13,     // Driver-specific out
}

pub struct Bio {
    pub bi_opf: u32,          // Operation + flags
    pub bi_status: BioStatus,
    pub bi_iter: BioIter,
    pub bi_vcnt: u16,
    pub bi_max_vecs: u16,
    pub bi_io_vec: [BioVec; BIO_MAX_VECS],
    pub bi_disk_major: u32,
    pub bi_disk_minor: u32,
    pub bi_partno: u32,
    pub bi_flags: u32,
    pub bi_ioprio: u16,
    pub bi_write_hint: u8,
    pub bi_end_io_id: u64,     // Completion callback
    pub bi_private: u64,
    pub bi_cg_id: u64,         // Cgroup
    pub bi_blkg_id: u64,       // Block cgroup
    pub bi_issue_time: u64,
    pub bi_iocost_cost: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BioStatus {
    Ok = 0,
    IoErr = -5,
    Again = -11,
    NoSpc = -28,
    DmBioErr = -256,
}

pub struct BioIter {
    pub bi_sector: u64,       // Current sector
    pub bi_size: u32,         // Remaining bytes
    pub bi_idx: u16,          // Current bio_vec index
    pub bi_bvec_done: u32,    // Bytes completed in current vec
}

pub struct BioVec {
    pub bv_page: u64,         // Page frame number
    pub bv_len: u32,          // Bytes in this vec
    pub bv_offset: u32,       // Offset within page
}

// BIO flags
pub const BIO_NO_PAGE_REF: u32 = 0;
pub const BIO_CLONED: u32 = 1;
pub const BIO_BOUNCED: u32 = 2;
pub const BIO_WORKINGSET: u32 = 3;
pub const BIO_QUIET: u32 = 4;
pub const BIO_CHAIN: u32 = 5;
pub const BIO_REFFED: u32 = 6;
pub const BIO_BPS_THROTTLED: u32 = 7;
pub const BIO_TRACE_COMPLETION: u32 = 8;
pub const BIO_CGROUP_ACCT: u32 = 9;
pub const BIO_QOS_THROTTLED: u32 = 10;
pub const BIO_QOS_MERGED: u32 = 11;
pub const BIO_REMAPPED: u32 = 12;
pub const BIO_ZONE_WRITE_LOCKED: u32 = 13;

// REQ flags (combined with BioOp)
pub const REQ_FAILFAST_DEV: u32 = 1 << 8;
pub const REQ_FAILFAST_TRANSPORT: u32 = 1 << 9;
pub const REQ_FAILFAST_DRIVER: u32 = 1 << 10;
pub const REQ_SYNC: u32 = 1 << 11;
pub const REQ_META: u32 = 1 << 12;
pub const REQ_PRIO: u32 = 1 << 13;
pub const REQ_NOMERGE: u32 = 1 << 14;
pub const REQ_IDLE: u32 = 1 << 15;
pub const REQ_INTEGRITY: u32 = 1 << 16;
pub const REQ_FUA: u32 = 1 << 17;
pub const REQ_PREFLUSH: u32 = 1 << 18;
pub const REQ_RAHEAD: u32 = 1 << 19;
pub const REQ_BACKGROUND: u32 = 1 << 20;
pub const REQ_NOWAIT: u32 = 1 << 21;
pub const REQ_POLLED: u32 = 1 << 22;
pub const REQ_ALLOC_CACHE: u32 = 1 << 23;
pub const REQ_SWAP: u32 = 1 << 24;
pub const REQ_DRV: u32 = 1 << 25;
pub const REQ_FS_PRIVATE: u32 = 1 << 26;
pub const REQ_NOUNMAP: u32 = 1 << 27;

// ============================================================================
// Request
// ============================================================================

pub struct Request {
    pub cmd_flags: u32,
    pub rq_flags: u32,
    pub state: RequestState,
    pub tag: i32,
    pub internal_tag: i32,
    pub errors: i32,
    // Sector range
    pub sector: u64,
    pub nr_sectors: u32,
    pub nr_phys_segments: u16,
    pub nr_integrity_segments: u16,
    // Timing
    pub start_time_ns: u64,
    pub io_start_time_ns: u64,
    pub deadline: u64,
    // Stats
    pub stats_sectors: u32,
    // DMA
    pub dma_addr: u64,
    pub dma_len: u32,
    // Priority
    pub ioprio: u16,
    pub write_hint: u8,
    // Bio chain
    pub bio_count: u32,
    pub bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequestState {
    Idle,
    InFlight,
    Complete,
    End,
}

// ============================================================================
// Multi-Queue Block Layer (blk-mq)
// ============================================================================

pub struct BlkMqTag {
    pub nr_tags: u32,
    pub nr_reserved_tags: u32,
    pub active_queues: AtomicU32,
    pub bitmap: [u64; 128],      // Tag bitmap
    pub bitmap_size: u32,
}

impl BlkMqTag {
    pub fn get_tag(&mut self) -> Option<i32> {
        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros();
                if word_idx as u32 * 64 + bit < self.nr_tags {
                    *word |= 1u64 << bit;
                    return Some((word_idx as u32 * 64 + bit) as i32);
                }
            }
        }
        None
    }

    pub fn put_tag(&mut self, tag: i32) {
        if tag < 0 { return; }
        let tag = tag as u32;
        let word_idx = (tag / 64) as usize;
        let bit = tag % 64;
        if word_idx < self.bitmap.len() {
            self.bitmap[word_idx] &= !(1u64 << bit);
        }
    }
}

pub struct BlkMqHwCtx {
    pub queue_num: u32,
    pub nr_ctx: u32,
    pub cpu_list: [u32; 32],     // CPUs mapped to this queue
    pub nr_cpus: u32,
    pub tags: BlkMqTag,
    pub sched_tags: BlkMqTag,
    pub dispatched: [AtomicU64; 8],  // Dispatch histogram
    pub queued: AtomicU64,
    pub run: AtomicU64,
    pub dispatched_total: AtomicU64,
    pub numa_node: i32,
    pub flags: u32,
}

pub struct BlkMqCtx {
    pub cpu: u32,
    pub index_hw: [u32; 4],    // Hardware queue indices
    pub nr_hw: u32,
    pub dispatched: AtomicU64,
    pub merged: AtomicU64,
    pub completed: AtomicU64,
}

// ============================================================================
// I/O Schedulers
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoSchedType {
    None,           // No scheduler (direct dispatch)
    Mq_Deadline,    // mq-deadline
    Bfq,            // Budget Fair Queueing
    Kyber,          // Kyber
    ZxyAdaptive,    // Zxyphor adaptive
}

// mq-deadline scheduler
pub struct MqDeadlineSched {
    pub read_expire: u64,     // Read deadline (default 500ms)
    pub write_expire: u64,    // Write deadline (default 5000ms)
    pub writes_starved: u32,  // After this many reads, force a write
    pub front_merges: bool,
    pub fifo_batch: u32,      // Requests per batch
    // Sorted lists (by sector)
    pub sort_read_count: u32,
    pub sort_write_count: u32,
    // FIFO lists (by deadline)
    pub fifo_read_count: u32,
    pub fifo_write_count: u32,
    pub batching: u32,
    pub starved: u32,
    // Stats
    pub read_dispatched: AtomicU64,
    pub write_dispatched: AtomicU64,
    pub read_merged: AtomicU64,
    pub write_merged: AtomicU64,
}

// BFQ scheduler
pub struct BfqSched {
    pub peak_rate: u64,       // Estimated peak rate (sectors/us)
    pub peak_rate_samples: u32,
    pub bfq_back_max: u32,    // Max backward seeking (KB)
    pub bfq_back_penalty: u32,
    pub bfq_quantum: u32,     // Max requests dispatched per round
    pub bfq_timeout: u64,     // Process budget timeout (ms)
    pub bfq_wr_coeff: u32,    // Weight-raising coefficient
    pub bfq_wr_max_time: u64, // Max weight-raising time (ms)
    pub bfq_wr_rt_max_time: u64,
    pub bfq_wr_min_idle_time: u64,
    pub bfq_wr_min_inter_arr_async: u64,
    pub bfq_slice_idle: u64,  // Idle time before expiring queue (us)
    pub bfq_strict_guarantees: bool,
    pub low_latency: bool,
    // Stats
    pub queued: AtomicU32,
    pub dispatched: AtomicU64,
    pub budget_timeout: AtomicU64,
    pub weight_raised: AtomicU32,
}

// Kyber scheduler
pub struct KyberSched {
    pub read_lat_target: u64,   // Read latency target (us)
    pub write_lat_target: u64,  // Write latency target (us)
    pub read_tokens: AtomicU32, // Available read tokens
    pub write_tokens: AtomicU32,
    pub discard_tokens: AtomicU32,
    pub other_tokens: AtomicU32,
    pub read_depth: u32,
    pub write_depth: u32,
    pub discard_depth: u32,
    pub other_depth: u32,
    // Latency histograms
    pub read_lat_hist: [AtomicU64; 32],
    pub write_lat_hist: [AtomicU64; 32],
}

// ============================================================================
// Device Mapper
// ============================================================================

pub struct DmDevice {
    pub name: [u8; 128],
    pub name_len: u8,
    pub uuid: [u8; 129],
    pub uuid_len: u8,
    pub major: u32,
    pub minor: u32,
    pub flags: u32,
    pub open_count: AtomicU32,
    pub event_nr: AtomicU32,
    pub target_count: u32,
    pub targets: [DmTarget; 16],
    pub suspended: AtomicBool,
}

pub struct DmTarget {
    pub target_type: DmTargetType,
    pub begin: u64,       // Start sector
    pub len: u64,         // Length in sectors
    pub status: [u8; 256],
    pub status_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmTargetType {
    Linear,
    Striped,
    Mirror,
    Snapshot,
    SnapshotOrigin,
    SnapshotMerge,
    Zero,
    Error,
    Crypt,
    Delay,
    Flakey,
    Dust,
    Thin,
    ThinPool,
    Cache,
    Writecache,
    Era,
    Clone,
    Integrity,
    VerityV1,
    VerityV2,
    Raid,
    Log,
    Switch,
    Unstriped,
    Zoned,
    Ebs,
    VdoPools,
}

// dm-crypt
pub struct DmCrypt {
    pub cipher_name: [u8; 64],
    pub cipher_name_len: u8,
    pub iv_mode: IvMode,
    pub key_size: u32,
    pub key_parts: u32,
    pub key_mac_size: u32,
    pub sector_size: u32,
    pub sector_shift: u32,
    pub iv_offset: u64,
    pub per_bio_data_size: u32,
    pub integrity_tag_size: u32,
    pub integrity_iv_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IvMode {
    Plain,
    Plain64,
    Plain64be,
    Essiv,
    Benbi,
    Null,
    Lmk,
    Tcw,
    Random,
    Eboiv,
    Elephant,
}

// dm-verity
pub struct DmVerity {
    pub version: u32,
    pub data_dev_major: u32,
    pub data_dev_minor: u32,
    pub hash_dev_major: u32,
    pub hash_dev_minor: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub hash_start_block: u64,
    pub algorithm: [u8; 32],
    pub algorithm_len: u8,
    pub digest_size: u32,
    pub root_digest: [u8; 64],
    pub root_digest_len: u8,
    pub salt: [u8; 256],
    pub salt_len: u16,
    pub validated_blocks: AtomicU64,
    pub corrupted_blocks: AtomicU64,
}

// dm-thin
pub struct DmThinPool {
    pub data_dev_major: u32,
    pub data_dev_minor: u32,
    pub metadata_dev_major: u32,
    pub metadata_dev_minor: u32,
    pub data_block_size: u32,  // Sectors
    pub low_water_mark: u64,   // Blocks
    pub nr_data_blocks: u64,
    pub nr_free_blocks: AtomicU64,
    pub nr_thins: u32,
    pub discard_enabled: bool,
    pub discard_passdown: bool,
    pub error_if_no_space: bool,
}

// ============================================================================
// I/O Priority  
// ============================================================================

pub const IOPRIO_CLASS_NONE: u32 = 0;
pub const IOPRIO_CLASS_RT: u32 = 1;    // Realtime
pub const IOPRIO_CLASS_BE: u32 = 2;    // Best-effort
pub const IOPRIO_CLASS_IDLE: u32 = 3;

pub const IOPRIO_NR_LEVELS: u32 = 8;

pub fn ioprio_value(class: u32, level: u32) -> u16 {
    ((class & 0x7) << 13 | (level & 0x7)) as u16
}

pub fn ioprio_class(ioprio: u16) -> u32 {
    ((ioprio >> 13) & 0x7) as u32
}

pub fn ioprio_level(ioprio: u16) -> u32 {
    (ioprio & 0x7) as u32
}

// ============================================================================
// Block cgroup (blkcg)
// ============================================================================

pub struct BlkCgroup {
    pub id: u64,
    pub parent_id: u64,
    // IO throttle (blk-throttle)
    pub bps_limit_read: u64,     // Bytes per second for reads
    pub bps_limit_write: u64,
    pub iops_limit_read: u64,    // IOPS limit for reads
    pub iops_limit_write: u64,
    // IO latency (blk-iolatency)
    pub lat_target_us: u64,
    pub lat_window_us: u64,
    // IO cost (blk-iocost)
    pub iocost_weight: u32,       // 1-10000
    pub iocost_qos_enable: bool,
    pub iocost_qos_rpct: u32,     // Read latency percentile
    pub iocost_qos_rlat_us: u64,  // Target read latency
    pub iocost_qos_wpct: u32,
    pub iocost_qos_wlat_us: u64,
    pub iocost_qos_min: u32,
    pub iocost_qos_max: u32,
    // Stats
    pub bytes_read: AtomicU64,
    pub bytes_write: AtomicU64,
    pub ios_read: AtomicU64,
    pub ios_write: AtomicU64,
    pub bytes_discard: AtomicU64,
    pub ios_discard: AtomicU64,
}

// ============================================================================
// Zoned Block Devices
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZoneType2 {
    Conventional,
    SeqWriteRequired,
    SeqWritePreferred,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZoneCondition {
    NotWP,
    Empty,
    ImplicitOpen,
    ExplicitOpen,
    Closed,
    ReadOnly,
    Full,
    Offline,
}

pub struct BlkZone {
    pub start: u64,          // Zone start sector
    pub len: u64,            // Zone length in sectors
    pub wp: u64,             // Write pointer position
    pub zone_type: ZoneType2,
    pub cond: ZoneCondition,
    pub non_seq: bool,
    pub reset: bool,
    pub capacity: u64,       // Zone capacity (may differ from len)
}

pub struct ZonedDevice {
    pub nr_zones: u32,
    pub zone_size_sectors: u64,
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub nr_open: AtomicU32,
    pub nr_active: AtomicU32,
    pub nr_seq_zones: u32,
    pub nr_conv_zones: u32,
}

// ============================================================================
// NVMe Zoned Namespaces (ZNS)
// ============================================================================

pub struct NvmeZnsCmdSet {
    pub zsze: u64,           // Zone Size
    pub zoc: u16,            // Zone Operation Characteristics
    pub ozcs: u16,           // Optional Zoned Command Support
    pub mar: u32,            // Max Active Resources
    pub mor: u32,            // Max Open Resources
    pub rrl: u32,            // Reset Recommended Limit
    pub frl: u32,            // Finish Recommended Limit
    pub rrl1: u32,           // Reset Recommended Limit 1
    pub rrl2: u32,
    pub rrl3: u32,
    pub frl1: u32,
    pub frl2: u32,
    pub frl3: u32,
    pub numzrwa: u32,        // Number of ZRWA Resources
    pub zrwafg: u16,         // ZRWA Flush Granularity
    pub zrwasz: u16,         // ZRWA Size
}

// ============================================================================
// Partition Table
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PartitionScheme {
    Mbr,
    Gpt,
    None,
}

// MBR partition entry (16 bytes)
#[repr(C, packed)]
pub struct MbrEntry {
    pub status: u8,
    pub first_chs: [u8; 3],
    pub part_type: u8,
    pub last_chs: [u8; 3],
    pub first_lba: u32,
    pub sectors: u32,
}

// GPT Header
#[repr(C, packed)]
pub struct GptHeader {
    pub signature: [u8; 8],       // "EFI PART"
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub nr_partition_entries: u32,
    pub partition_entry_size: u32,
    pub partition_entry_crc32: u32,
}

// GPT Partition Entry (128 bytes)
#[repr(C, packed)]
pub struct GptEntry {
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub name: [u16; 36],    // UTF-16LE name
}

// Well-known GPT partition type GUIDs
pub const GPT_UNUSED: [u8; 16] = [0; 16];
pub const GPT_EFI_SYSTEM: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
pub const GPT_LINUX_FS: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];
pub const GPT_LINUX_SWAP: [u8; 16] = [
    0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43,
    0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F,
];
pub const GPT_LINUX_LVM: [u8; 16] = [
    0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44,
    0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28,
];
