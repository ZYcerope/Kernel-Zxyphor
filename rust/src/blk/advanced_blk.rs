// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Rust Block I/O Advanced Subsystem
// Multi-queue block layer, I/O schedulers (mq-deadline/BFQ/Kyber),
// Device Mapper targets, bcache, block integrity, zoned storage, NVMe-oF
// More advanced than Linux 2026 block layer

use core::fmt;

// ============================================================================
// Block Device Core
// ============================================================================

pub const SECTOR_SIZE: u64 = 512;
pub const SECTOR_SHIFT: u32 = 9;
pub const PAGE_SIZE: u64 = 4096;
pub const BLK_MAX_SEGMENTS: u32 = 128;
pub const BLK_MAX_SEGMENT_SIZE: u32 = 65536;
pub const BLK_BOUNCE_NONE: u64 = u64::MAX;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlkReqOp {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    SecureErase = 4,
    WriteZeroes = 5,
    WriteSame = 6,
    ZoneReset = 7,
    ZoneResetAll = 8,
    ZoneOpen = 9,
    ZoneClose = 10,
    ZoneFinish = 11,
    ZoneAppend = 12,
    DrvIn = 13,
    DrvOut = 14,
    Last = 15,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum BlkReqFlag {
    Failfast = 1 << 8,
    FailfastTransport = 1 << 9,
    FailfastDriver = 1 << 10,
    Sync = 1 << 11,
    Meta = 1 << 12,
    Prio = 1 << 13,
    Nomerge = 1 << 14,
    Idle = 1 << 15,
    Integrity = 1 << 16,
    Fua = 1 << 17,
    Preflush = 1 << 18,
    Rahead = 1 << 19,
    Background = 1 << 20,
    Nowait = 1 << 21,
    Polled = 1 << 22,
    AllowCache = 1 << 23,
    Swap = 1 << 24,
    DrvPriv = 1 << 25,
    Nounmap = 1 << 26,
    Cgroup = 1 << 27,
}

#[derive(Debug, Clone)]
pub struct BlockDeviceParams {
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub io_min: u32,
    pub io_opt: u32,
    pub max_hw_sectors: u32,
    pub max_sectors: u32,
    pub max_segments: u32,
    pub max_segment_size: u32,
    pub max_discard_sectors: u32,
    pub max_write_zeroes_sectors: u32,
    pub discard_granularity: u32,
    pub discard_alignment: u32,
    pub alignment_offset: u32,
    pub dma_alignment: u32,
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub chunk_sectors: u32,
    pub virt_boundary_mask: u64,
    // Feature flags
    pub rotational: bool,
    pub discard: bool,
    pub secure_erase: bool,
    pub write_zeroes: bool,
    pub write_same: bool,
    pub nowait: bool,
    pub io_stat: bool,
    pub zoned: bool,
    pub stable_writes: bool,
    pub add_random: bool,
    pub nonrot: bool,
    pub fua: bool,
    pub dax: bool,
    pub integrity: bool,
}

// ============================================================================
// BIO (Block I/O)
// ============================================================================

#[derive(Debug, Clone)]
pub struct BioVec {
    pub page: u64,      // Physical page
    pub len: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BioStatus {
    Ok = 0,
    IoErr = -5,   // EIO
    NoDev = -19,  // ENODEV
    Dma = -100,
    Timeout = -110,
    Transport = -111,
    Target = -112,
    Nexus = -113,
    Medium = -114,
    FailBarrier = -115,
    Again = -11,
    Unknown = -1,
}

pub struct Bio {
    pub bi_opf: u32,        // Op + flags
    pub bi_status: BioStatus,
    pub bi_disk: u32,        // Disk index
    pub bi_partno: u8,
    pub bi_flags: u32,
    // Sector range
    pub bi_iter: BioIter,
    // BIO vector
    pub bi_io_vec: [BLK_MAX_SEGMENTS as usize]BioVec,
    pub bi_vcnt: u16,
    pub bi_max_vecs: u16,
    // Integrity
    pub bi_integrity: Option<BioIntegrity>,
    // Completion
    pub bi_remaining: i32,
    pub bi_end_io: u64,     // Callback pointer
    pub bi_private: u64,
    // Pool
    pub bi_pool: u64,
    // Cgroup
    pub bi_blkg: u64,
    pub bi_issue_time: u64,
    // Write hint
    pub bi_write_hint: u8,
    // Counters
    pub bi_cnt: i32,
}

#[derive(Debug, Clone)]
pub struct BioIter {
    pub bi_sector: u64,
    pub bi_size: u32,
    pub bi_idx: u16,
    pub bi_bvec_done: u32,
}

impl BioIter {
    pub fn advance(&mut self, bytes: u32) {
        self.bi_size -= bytes;
        self.bi_bvec_done += bytes;
        self.bi_sector += bytes as u64 / SECTOR_SIZE;
    }

    pub fn end_sector(&self) -> u64 {
        self.bi_sector + self.bi_size as u64 / SECTOR_SIZE
    }
}

// ============================================================================
// Block Multi-Queue (blk-mq)
// ============================================================================

pub const BLK_MQ_MAX_HW_QUEUES: u32 = 256;
pub const BLK_MQ_MAX_TAGS: u32 = 65536;

#[derive(Debug, Clone)]
pub struct BlkMqTagSet {
    pub ops: BlkMqOps,
    pub nr_hw_queues: u32,
    pub queue_depth: u32,
    pub reserved_tags: u32,
    pub cmd_size: u32,
    pub numa_node: i32,
    pub timeout: u32,       // Jiffies
    pub flags: u32,
    pub driver_data: u64,
    pub nr_maps: u32,
    pub tags: [Option<BlkMqTags>; BLK_MQ_MAX_HW_QUEUES as usize],
}

pub struct BlkMqTags {
    pub nr_tags: u32,
    pub nr_reserved_tags: u32,
    pub active_queues: u32,
    pub bitmap: [u64; BLK_MQ_MAX_TAGS as usize / 64],
    pub breserved: [u64; 1024 / 64],
}

#[derive(Debug, Clone)]
pub struct BlkMqOps {
    pub queue_rq: u64,       // fn(hctx, bd) -> blk_status
    pub commit_rqs: u64,     // fn(hctx) void
    pub queue_rqs: u64,      // fn(rq_list)
    pub get_budget: u64,     // fn(q) -> bool
    pub put_budget: u64,     // fn(q, budget)
    pub set_rq_budget_token: u64,
    pub get_rq_budget_token: u64,
    pub timeout: u64,        // fn(rq) -> timeout_action
    pub poll: u64,           // fn(hctx, iob)
    pub complete: u64,       // fn(rq)
    pub init_hctx: u64,
    pub exit_hctx: u64,
    pub init_request: u64,
    pub exit_request: u64,
    pub map_queues: u64,
    pub show_rq: u64,
}

pub struct BlkMqHwCtx {
    pub queue_num: u32,
    pub nr_ctx: u32,
    pub state: u64,
    pub flags: u32,
    pub sched_tags: Option<BlkMqTags>,
    pub tags: Option<BlkMqTags>,
    pub dispatched: [u64; 8],  // Stats per bucket
    pub queued: u64,
    pub run: u64,
    pub numa_node: i32,
    pub cpumask: [u64; 4],    // 256 CPUs
}

// ============================================================================
// I/O Schedulers
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IoSchedulerType {
    None = 0,
    MqDeadline = 1,
    Bfq = 2,
    Kyber = 3,
    // Zxyphor
    ZxyAdaptive = 200,
}

// mq-deadline
pub struct MqDeadlineData {
    // Sorted queues
    pub read_fifo_expires: u32,    // ms
    pub write_fifo_expires: u32,   // ms
    pub writes_starved: u32,       // Reads per write batch
    pub front_merges: bool,
    pub fifo_batch: u32,
    // Stats
    pub batching: u32,
    pub starved: u32,
    pub read_dispatched: u64,
    pub write_dispatched: u64,
}

// BFQ (Budget Fair Queueing)
pub struct BfqData {
    // Parameters
    pub quantum: u32,
    pub max_budget: u32,
    pub budget_timeout: u32,     // ms
    pub default_ioprio: u8,
    pub default_ioprio_class: u8,
    pub low_latency: bool,
    pub strict_guarantees: bool,
    pub slice_idle: u32,         // us
    pub idling_max_wait: u32,    // us
    // Weight-based scheduling
    pub wr_coeff: u32,           // Weight raising coefficient
    pub wr_max_time: u32,        // Max weight raise time
    pub wr_min_idle_for_wr: u32, // Min idle time for weight raising
    pub wr_min_inter_arr: u32,   // Min inter-arrival time
    // Stats
    pub queued: u64,
    pub dispatched: u64,
    pub rq_in_driver: [2]u32,   // [sync][async]
    pub rq_in_driver_total: u32,
    // Service trees
    pub peak_rate: u64,          // Sectors/us
    pub peak_rate_samples: u32,
    pub sequential_streams: u32,
}

// Kyber
pub struct KyberData {
    pub read_lat_target: u32,     // us
    pub write_lat_target: u32,    // us
    pub discard_lat_target: u32,  // us
    pub other_lat_target: u32,    // us
    // Domain depths
    pub read_depth: u32,
    pub write_depth: u32,
    pub discard_depth: u32,
    pub other_depth: u32,
    // Token counts
    pub read_tokens: u32,
    pub write_tokens: u32,
    // Stats
    pub total_lat_avg: [4]u64,   // Per domain
    pub read_percentiles: [8]u64,
}

// ============================================================================
// Device Mapper
// ============================================================================

pub const DM_MAX_TARGETS: u32 = 1048576;

#[repr(u8)]
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
    Dust = 11,
    Thin = 12,
    ThinPool = 13,
    Cache = 14,
    Era = 15,
    Log = 16,
    Integrity = 17,
    Verity = 18,
    WritecachE = 19,
    Raid = 20,
    MultiPath = 21,
    Switch = 22,
    Clone = 23,
    Vdo = 24,
    // Zxyphor
    ZxyCow = 200,
    ZxyDedup = 201,
    ZxyCompress = 202,
}

pub struct DmTarget {
    pub target_type: DmTargetType,
    pub begin: u64,     // Start sector
    pub len: u64,       // Length in sectors
    pub target_data: DmTargetData,
}

pub enum DmTargetData {
    Linear(DmLinear),
    Striped(DmStriped),
    Crypt(DmCrypt),
    Thin(DmThin),
    ThinPool(DmThinPool),
    Verity(DmVerity),
    Integrity(DmIntegrity),
    Cache(DmCache),
    Raid(DmRaid),
    MultiPath(DmMultiPath),
    Vdo(DmVdo),
}

pub struct DmLinear {
    pub dev_path: [u8; 256],
    pub dev_path_len: u16,
    pub start: u64,
}

pub struct DmStriped {
    pub stripes: u32,
    pub chunk_size: u32,
    pub devs: [(u32, u64); 64],  // (dev_idx, start_offset)
    pub nr_devs: u32,
}

pub struct DmCrypt {
    pub cipher: [u8; 128],
    pub cipher_len: u8,
    pub key: [u8; 64],
    pub key_size: u8,
    pub iv_offset: u64,
    pub sector_size: u32,
    pub sector_shift: u8,
    // Encryption mode
    pub mode: DmCryptMode,
    pub integrity: bool,
    pub integrity_tag_size: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCryptMode {
    CbcEssiv = 0,
    XtsPlain64 = 1,
    Hctr2 = 2,
    Adiantum = 3,
    BitlockerAesXts = 4,
}

pub struct DmThinPool {
    pub metadata_dev: u32,
    pub data_dev: u32,
    pub data_block_size: u32,
    pub low_water_mark: u64,
    pub error_if_no_space: bool,
    // Stats
    pub nr_free_blocks: u64,
    pub nr_data_blocks: u64,
    pub nr_metadata_blocks: u64,
    pub held_metadata_root: u64,
}

pub struct DmThin {
    pub pool_dev: u32,
    pub thin_id: u32,
    pub origin_dev: Option<u32>,
    pub external_origin_dev: Option<u32>,
}

pub struct DmVerity {
    pub data_dev: u32,
    pub hash_dev: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub hash_start: u64,
    pub algorithm: [u8; 32],
    pub algorithm_len: u8,
    pub root_digest: [u8; 64],
    pub root_digest_len: u8,
    pub salt: [u8; 256],
    pub salt_len: u16,
    pub version: u32,
    pub fec_dev: Option<u32>,
    pub fec_start: u64,
    pub fec_blocks: u64,
    pub fec_roots: u32,
    pub check_at_most_once: bool,
    pub panic_on_corruption: bool,
    pub restart_on_corruption: bool,
}

pub struct DmIntegrity {
    pub dev: u32,
    pub tag_size: u32,
    pub sectors_per_tag: u32,
    pub internal_hash: [u8; 32],
    pub internal_hash_len: u8,
    pub journal_sectors: u64,
    pub interleave_sectors: u32,
    pub buffer_sectors: u32,
    pub journal_watermark: u32,
    pub commit_time: u32,
    pub recalculate: bool,
    pub fix_padding: bool,
    pub bitmap_mode: bool,
}

pub struct DmCache {
    pub origin_dev: u32,
    pub cache_dev: u32,
    pub metadata_dev: u32,
    pub cache_block_size: u32,
    pub policy: DmCachePolicy,
    pub migration_threshold: u32,
    pub metadata_version: u32,
    // Stats
    pub read_hits: u64,
    pub read_misses: u64,
    pub write_hits: u64,
    pub write_misses: u64,
    pub demotions: u64,
    pub promotions: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmCachePolicy {
    Smq = 0,
    Mq = 1,
    Cleaner = 2,
}

pub struct DmRaid {
    pub level: DmRaidLevel,
    pub nr_disks: u32,
    pub region_size: u32,
    pub stripe_cache_size: u32,
    pub rebuild_slots: [bool; 64],
    // Journal
    pub journal_dev: Option<u32>,
    pub journal_mode: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmRaidLevel {
    Raid0 = 0,
    Raid1 = 1,
    Raid4 = 4,
    Raid5La = 5,
    Raid5Ra = 50,
    Raid5Ls = 51,
    Raid5Rs = 52,
    Raid6ZrLa = 6,
    Raid6ZrRa = 60,
    Raid6NcLa = 61,
    Raid6NcRa = 62,
    Raid10 = 10,
}

pub struct DmMultiPath {
    pub nr_priority_groups: u32,
    pub current_pg: u32,
    pub queue_if_no_path: bool,
    pub retain_attached_hw_handler: bool,
    pub pg_init_retries: u32,
    pub pg_init_delay: u32,
    pub paths: [DmMpathPath; 64],
    pub nr_paths: u32,
    pub path_selector: DmPathSelector,
}

pub struct DmMpathPath {
    pub dev: u32,
    pub pg_num: u32,
    pub is_active: bool,
    pub fail_count: u64,
    pub repeat_count: u32,
    pub relative_throughput: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmPathSelector {
    RoundRobin = 0,
    QueueLength = 1,
    ServiceTime = 2,
    Sto = 3,        // Historical service time
    IoAffinity = 4,
}

pub struct DmVdo {
    pub storage_dev: u32,
    pub virtual_size: u64,
    pub block_map_era: u32,
    pub logical_block_size: u32,
    pub compression: bool,
    pub deduplication: bool,
    // Stats
    pub data_blocks_used: u64,
    pub overhead_blocks: u64,
    pub logical_blocks_used: u64,
    pub savings_percent: u32,
}

// ============================================================================
// NVMe-oF (NVMe over Fabrics)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NvmeofTransportType {
    Rdma = 1,
    FcFibreChannel = 2,
    Tcp = 3,
    Loop = 254,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NvmeofAddrFamily {
    Pci = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Ib = 3,
    Fc = 4,
    Loop = 254,
}

pub struct NvmeofCtrl {
    pub transport: NvmeofTransportType,
    pub traddr: [u8; 256],
    pub traddr_len: u16,
    pub trsvcid: [u8; 32],
    pub trsvcid_len: u8,
    pub host_traddr: [u8; 256],
    pub host_traddr_len: u16,
    pub subsys_nqn: [u8; 256],     // NVMe qualified name
    pub subsys_nqn_len: u16,
    pub host_nqn: [u8; 256],
    pub host_nqn_len: u16,
    pub hostnqn_configured: bool,
    // Queues
    pub nr_io_queues: u32,
    pub nr_write_queues: u32,
    pub nr_poll_queues: u32,
    pub queue_count: u32,
    pub sqsize: u32,
    // Options
    pub kato: u32,           // Keep alive timeout (ms)
    pub reconnect_delay: u32,
    pub ctrl_loss_tmo: i32,
    pub nr_reconnects: u32,
    pub fast_io_fail_tmo: i32,
    // Discovery
    pub discovery_ctrl: bool,
    pub persistent: bool,
    // Auth
    pub dhchap_secret: [u8; 128],
    pub dhchap_ctrl_secret: [u8; 128],
    // State
    pub state: NvmeofCtrlState,
    // Stats
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_cmds: u64,
    pub write_cmds: u64,
    pub errors: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NvmeofCtrlState {
    New = 0,
    Live = 1,
    Resetting = 2,
    Connecting = 3,
    Deleting = 4,
    DeletedNodetach = 5,
    Dead = 6,
}

// ============================================================================
// Block Integrity (DIF/DIX)
// ============================================================================

pub struct BioIntegrity {
    pub bip_vec: [BioVec; 64],
    pub bip_vcnt: u16,
    pub bip_iter: BioIter,
    pub bip_flags: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BlkIntegrityProfile {
    None = 0,
    T10DifType1Crc = 1,
    T10DifType1Ip = 2,
    T10DifType3Crc = 3,
    T10DifType3Ip = 4,
}

pub struct BlkIntegrity {
    pub profile: BlkIntegrityProfile,
    pub flags: u32,
    pub tuple_size: u32,
    pub interval_exp: u32,
    pub tag_size: u32,
}

// ============================================================================
// Zoned Block Device
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlkZoneType {
    Conventional = 1,
    SeqWriteRequired = 2,
    SeqWritePreferred = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlkZoneCondition {
    NotWp = 0,
    Empty = 1,
    ImplicitOpen = 2,
    ExplicitOpen = 3,
    Closed = 4,
    ReadOnly = 13,
    Full = 14,
    Offline = 15,
}

#[derive(Debug, Clone)]
pub struct BlkZone {
    pub start: u64,
    pub len: u64,
    pub wp: u64,
    pub zone_type: BlkZoneType,
    pub cond: BlkZoneCondition,
    pub non_seq: bool,
    pub reset: bool,
    pub capacity: u64,
}

pub struct ZonedDevice {
    pub nr_zones: u32,
    pub zone_size: u64,        // Sectors
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub zones: [BlkZone; 16384],
    pub open_zones: u32,
    pub active_zones: u32,
    // Append
    pub max_zone_append_size: u32,
    // Stats
    pub zone_resets: u64,
    pub zone_appends: u64,
}

// ============================================================================
// bcache
// ============================================================================

pub struct BcacheDevice {
    pub uuid: [u8; 16],
    pub backing_dev: u32,
    pub cache_dev: u32,
    // Cache state
    pub cache_mode: BcacheCacheMode,
    pub sequential_cutoff: u64,
    pub writeback_percent: u32,
    pub writeback_running: bool,
    pub writeback_rate: u64,
    // Stats
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_ratio: u32,  // permille
    pub cache_bypass_hits: u64,
    pub cache_bypass_misses: u64,
    pub cache_readaheads: u64,
    // State
    pub dirty_data: u64,
    pub cache_available: u64,
    pub cache_used: u64,
    pub bucket_size: u32,
    pub nr_buckets: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BcacheCacheMode {
    Writethrough = 0,
    Writeback = 1,
    Writearound = 2,
    None = 3,
}

// ============================================================================
// Block Layer Manager
// ============================================================================

pub struct BlockLayerManager {
    // Registered devices
    pub nr_block_devices: u32,
    pub nr_dm_devices: u32,
    pub nr_nvmeof_ctrls: u32,
    pub nr_bcache_devices: u32,
    // Global I/O scheduler
    pub default_scheduler: IoSchedulerType,
    // Stats
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_discards: u64,
    pub total_flushes: u64,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    // Memory
    pub bio_pool_size: u64,
    pub bounce_pool_size: u64,
    pub initialized: bool,
}
