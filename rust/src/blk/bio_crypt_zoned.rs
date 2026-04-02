// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - BIO Cryptography, Zoned Block Devices, and I/O Accounting
// Complete: blk-crypto (inline encryption), zoned storage (ZNS/ZBC/ZAC),
// I/O accounting, blk-mq tag management, request merging, I/O priorities

// ============================================================================
// Block Layer Inline Encryption (blk-crypto)
// ============================================================================

/// Crypto algorithm identifiers for inline encryption
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkCryptoMode {
    /// No encryption
    Unset = 0,
    /// AES-256-XTS (most common for storage)
    Aes256Xts = 1,
    /// AES-128-CBC-ESSIV
    Aes128CbcEssiv = 2,
    /// Adiantum (for low-power ARM devices)
    Adiantum = 3,
    /// SM4-XTS (Chinese standard)
    Sm4Xts = 4,
}

/// Key sizes for each crypto mode
pub const BLK_CRYPTO_KEY_SIZE_AES_256_XTS: usize = 64;
pub const BLK_CRYPTO_KEY_SIZE_AES_128_CBC_ESSIV: usize = 16;
pub const BLK_CRYPTO_KEY_SIZE_ADIANTUM: usize = 32;
pub const BLK_CRYPTO_KEY_SIZE_SM4_XTS: usize = 32;

/// Maximum key size supported
pub const BLK_CRYPTO_MAX_KEY_SIZE: usize = 64;

/// Maximum Data Unit Size (DUS) exponent
pub const BLK_CRYPTO_MAX_DUN_BYTES: usize = 8;

/// Inline encryption key
#[repr(C)]
pub struct BlkCryptoKey {
    pub crypto_cfg: BlkCryptoCfg,
    pub data_unit_size: u32,
    pub data_unit_size_bits: u32,
    pub size: u32,
    pub raw: [u8; BLK_CRYPTO_MAX_KEY_SIZE],
}

/// Crypto configuration for a key
#[repr(C)]
pub struct BlkCryptoCfg {
    pub crypto_mode: BlkCryptoMode,
    pub data_unit_size: u32,
    pub dun_bytes: u32,
}

/// Bio crypto context - attached to BIOs for inline encryption
#[repr(C)]
pub struct BioCryptCtx {
    pub bc_key: *const BlkCryptoKey,
    pub bc_dun: [u64; BLK_CRYPTO_MAX_DUN_BYTES / 8],
}

/// Keyslot manager for hardware that supports limited key slots
#[repr(C)]
pub struct BlkCryptoProfile {
    pub ll_ops: BlkCryptoLlOps,
    pub max_dun_bytes_supported: u32,
    pub modes_supported: [BlkCryptoModeSupport; 5],
    pub num_slots: u32,
    pub slot_hashtable_size: u32,
    pub log_slot_ht_size: u32,
    pub slots: *mut BlkCryptoKeyslot,
    pub idle_slots: SlotList,
    pub idle_slots_wait_queue: WaitQueue,
    pub dev: *mut u8,
}

/// Crypto low-level operations
#[repr(C)]
pub struct BlkCryptoLlOps {
    pub keyslot_program: Option<
        unsafe extern "C" fn(
            profile: *mut BlkCryptoProfile,
            key: *const BlkCryptoKey,
            slot: u32,
        ) -> i32,
    >,
    pub keyslot_evict: Option<
        unsafe extern "C" fn(
            profile: *mut BlkCryptoProfile,
            key: *const BlkCryptoKey,
            slot: u32,
        ) -> i32,
    >,
    pub derive_sw_secret: Option<
        unsafe extern "C" fn(
            profile: *mut BlkCryptoProfile,
            wrapped_key: *const u8,
            wrapped_key_size: u32,
            sw_secret: *mut u8,
        ) -> i32,
    >,
}

/// Support info for a crypto mode
#[repr(C)]
pub struct BlkCryptoModeSupport {
    pub max_dun_bytes: u32,
}

#[repr(C)]
pub struct BlkCryptoKeyslot {
    pub slot_idx: u32,
    pub key: *const BlkCryptoKey,
    pub idle_slot_node: SlotListNode,
    pub hash_node: SlotListNode,
    pub slotp: *mut BlkCryptoProfile,
}

pub struct SlotList {
    head: *mut SlotListNode,
}

pub struct SlotListNode {
    next: *mut SlotListNode,
    prev: *mut SlotListNode,
}

pub struct WaitQueue {
    lock: u64,
    head: *mut u8,
}

/// Crypto fallback (software implementation when HW doesn't support)
pub struct BlkCryptoFallback {
    pub tfms: [*mut u8; 5],   // One per crypto mode
    pub bounce_page_pool: *mut u8,
    pub work_mem: *mut u8,
}

// ============================================================================
// Zoned Block Device Support
// ============================================================================

/// Zone types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkZoneType {
    /// Conventional (random read/write)
    Conventional = 1,
    /// Sequential Write Required
    SeqWriteRequired = 2,
    /// Sequential Write Preferred
    SeqWritePreferred = 3,
}

/// Zone states/conditions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkZoneCondition {
    NotWp = 0,
    Empty = 1,
    ImplicitOpen = 2,
    ExplicitOpen = 3,
    Closed = 4,
    ReadOnly = 0xD,
    Full = 0xE,
    Offline = 0xF,
}

/// Zone descriptor
#[repr(C)]
pub struct BlkZone {
    pub start: u64,
    pub len: u64,
    pub wp: u64,
    pub zone_type: BlkZoneType,
    pub cond: BlkZoneCondition,
    pub non_seq: u8,
    pub reset: u8,
    pub resv: [u8; 4],
    pub capacity: u64,
    pub resv2: [u8; 24],
}

/// Zone report header
#[repr(C)]
pub struct BlkZoneReport {
    pub nr_zones: u64,
    pub flags: u64,
    pub zones: [BlkZone; 0],   // Flexible array
}

/// Zone management operations
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkZoneOp {
    Reset = 0,
    Open = 1,
    Close = 2,
    Finish = 3,
    ResetAll = 4,
}

/// Zoned device model
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkZonedModel {
    None = 0,
    HostAware = 1,
    HostManaged = 2,
}

/// Zone write granularity info
pub struct ZonedDeviceInfo {
    pub nr_zones: u32,
    pub zone_sectors: u64,
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub max_zone_append_sectors: u32,
    pub zone_write_granularity: u32,
    pub model: BlkZonedModel,
    pub conv_zones_bitmap: *mut u64,
    pub seq_zones_bitmap: *mut u64,
    pub seq_zones_wlock: *mut u64,
}

/// Zone append result
#[repr(C)]
pub struct ZoneAppendResult {
    pub sector: u64,
    pub status: i32,
}

/// Zone write plug (prevents out-of-order writes within zones)
pub struct BlkZoneWritePlug {
    pub node: u64,
    pub flags: ZoneWpFlags,
    pub zone_no: u32,
    pub wp_offset: u32,
    pub bio_list: *mut u8,
    pub bio_list_lock: u64,
    pub refcount: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum ZoneWpFlags {
    None = 0,
    Plugged = 1,
    Error = 2,
    NeedReset = 4,
}

// ============================================================================
// BIO (Block I/O) Internals
// ============================================================================

/// BIO operation flags
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum BioOpFlags {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
    SecureErase = 5,
    ZoneReset = 6,
    ZoneResetAll = 7,
    ZoneOpen = 8,
    ZoneClose = 9,
    ZoneFinish = 10,
    ZoneAppend = 11,
    WriteZeroes = 12,
}

/// BIO flags
pub struct BioFlags(u16);

impl BioFlags {
    pub const SPLIT: u16 = 1 << 0;
    pub const MAPPED_INTEGRITY: u16 = 1 << 1;
    pub const THROTTLED: u16 = 1 << 2;
    pub const TRACE_COMPLETION: u16 = 1 << 3;
    pub const CGROUP_ACCT: u16 = 1 << 4;
    pub const TRACKED: u16 = 1 << 5;
    pub const REMAPPED: u16 = 1 << 6;
    pub const ZONE_WRITE_LOCKED: u16 = 1 << 7;
    pub const PERCPU_CACHE: u16 = 1 << 8;
}

/// BIO vec (single segment of a BIO)
#[repr(C)]
pub struct BioVec {
    pub bv_page: *mut u8,
    pub bv_len: u32,
    pub bv_offset: u32,
}

/// BIO vec iterator
#[repr(C)]
pub struct BvecIter {
    pub bi_sector: u64,
    pub bi_size: u32,
    pub bi_idx: u32,
    pub bi_bvec_done: u32,
}

/// Complete BIO structure
#[repr(C)]
pub struct Bio {
    pub bi_next: *mut Bio,
    pub bi_bdev: *mut u8,
    pub bi_opf: u32,
    pub bi_flags: u16,
    pub bi_ioprio: u16,
    pub bi_status: i8,
    pub bi_max_vecs: u16,
    pub bi_cnt: i32,
    pub bi_io_vec: *mut BioVec,
    pub bi_iter: BvecIter,
    pub bi_private: *mut u8,
    pub bi_end_io: Option<unsafe extern "C" fn(bio: *mut Bio)>,
    pub bi_crypt_context: *mut BioCryptCtx,
    pub bi_integrity: *mut BioIntegrity,
    pub bi_vcnt: u16,
    pub bi_cookie: u32,
    pub bi_inline_vecs: [BioVec; 0],
}

/// BIO integrity payload (DIF/DIX)
#[repr(C)]
pub struct BioIntegrity {
    pub bip_vec: *mut BioVec,
    pub bip_iter: BvecIter,
    pub bip_vcnt: u16,
    pub bip_max_vcnt: u16,
    pub bip_flags: u16,
}

// ============================================================================
// I/O Accounting
// ============================================================================

/// Per-partition I/O statistics
#[repr(C)]
pub struct DiskStats {
    pub nsecs: [u64; 4],      // time in ns (read, write, discard, flush)
    pub sectors: [u64; 4],    // sectors (read, write, discard, flush)
    pub ios: [u64; 4],        // completed I/Os
    pub merges: [u64; 4],     // merged I/Os
    pub io_ticks: u64,        // time doing I/Os (ms)
    pub in_flight: [u32; 2],  // in-flight (read, write)
}

/// I/O latency histogram buckets
pub const IO_LATENCY_BUCKETS: usize = 31;

#[repr(C)]
pub struct IoLatencyBucket {
    pub lat_us_threshold: u64,
    pub count: u64,
}

#[repr(C)]
pub struct IoLatencyStats {
    pub buckets: [IoLatencyBucket; IO_LATENCY_BUCKETS],
    pub total: u64,
    pub avg_us: u64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

/// I/O priority classes
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoPrioClass {
    None = 0,
    RealTime = 1,
    BestEffort = 2,
    Idle = 3,
}

/// I/O priority
#[repr(C)]
pub struct IoPrio {
    pub class: IoPrioClass,
    pub level: u16,   // 0-7
}

impl IoPrio {
    pub const MAX_LEVEL: u16 = 7;
    pub const NR_LEVELS: u16 = 8;

    pub fn new(class: IoPrioClass, level: u16) -> Self {
        Self {
            class,
            level: if level > Self::MAX_LEVEL { Self::MAX_LEVEL } else { level },
        }
    }

    pub fn to_raw(&self) -> u16 {
        ((self.class as u16) << 13) | self.level
    }
}

// ============================================================================
// blk-mq Tag Management
// ============================================================================

/// Tag set flags
pub struct BlkMqTagSetFlags(u32);

impl BlkMqTagSetFlags {
    pub const SHOULD_MERGE: u32 = 1 << 0;
    pub const TAG_SHARED: u32 = 1 << 1;
    pub const STACKING: u32 = 1 << 2;
    pub const TAG_HCTX_SHARED: u32 = 1 << 3;
    pub const BLOCKING: u32 = 1 << 5;
    pub const DRIVER_TAGS: u32 = 1 << 6;
    pub const NO_SCHED_TAGS: u32 = 1 << 7;
}

/// Hardware dispatch queue tag info
#[repr(C)]
pub struct BlkMqTags {
    pub nr_tags: u32,
    pub nr_reserved_tags: u32,
    pub active_queues: u32,
    pub bitmap_tags: SbitMap,
    pub breserved_tags: SbitMap,
    pub rqs: *mut *mut u8,     // Array of request pointers
    pub static_rqs: *mut *mut u8,
    pub page_list: *mut u8,
}

/// Scalable bitmap for tag allocation
#[repr(C)]
pub struct SbitMap {
    pub depth: u32,
    pub shift: u32,
    pub map_nr: u32,
    pub round_robin: bool,
    pub map: *mut SbitMapWord,
    pub alloc_hint: *mut u32,   // Per-CPU
}

#[repr(C)]
pub struct SbitMapWord {
    pub word: u64,
    pub depth: u32,
}

/// Hardware context (one per hardware queue)
#[repr(C)]
pub struct BlkMqHwCtx {
    pub queue_num: u32,
    pub nr_ctx: u16,
    pub flags: u32,
    pub dispatch_busy: u64,
    pub state: BlkMqHwCtxState,
    pub tags: *mut BlkMqTags,
    pub sched_tags: *mut BlkMqTags,
    pub dispatch: RequestList,
    pub cpumask: *mut u64,
    pub next_cpu: i32,
    pub next_cpu_batch: i32,
    pub queued: u64,
    pub run: u64,
    pub dispatched: [u64; 8],
    pub numa_node: i32,
    pub queue: *mut u8,
    pub ctxs: *mut *mut u8,
    pub nr_active: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum BlkMqHwCtxState {
    Stopped = 0,
    TagActive = 1,
    SchedRestart = 2,
    Inactive = 3,
}

pub struct RequestList {
    head: *mut u8,
    count: u32,
}

// ============================================================================
// Request Merging
// ============================================================================

/// Merge result types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElvMerge {
    None = 0,
    Front = 1,
    Back = 2,
    Discard = 3,
}

/// Request merge info
pub struct BlkMergeInfo {
    pub max_sectors: u32,
    pub max_segments: u16,
    pub max_segment_size: u32,
    pub max_discard_sectors: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_zone_append_sectors: u32,
    pub chunk_sectors: u32,
    pub virt_boundary_mask: u64,
    pub discard_granularity: u32,
    pub discard_alignment: u32,
    pub discard_misaligned: bool,
}

/// Plug (batching mechanism)
#[repr(C)]
pub struct BlkPlug {
    pub mq_list: *mut u8,
    pub cached_rq: *mut u8,
    pub nr_ios: u16,
    pub rq_count: u16,
    pub multiple_queues: bool,
    pub has_elevator: bool,
    pub nowait: bool,
}

// ============================================================================
// I/O cgroup (blkcg)
// ============================================================================

/// Block cgroup policy types
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum BlkcgPolicyType {
    Throttle = 0,     // blk-throttle (BPS/IOPS limits)
    IoWeight = 1,     // BFQ weight / io.weight
    IoCost = 2,       // io.cost model
    IoLatency = 3,    // io.latency
}

/// Block cgroup
#[repr(C)]
pub struct Blkcg {
    pub css: *mut u8,           // cgroup_subsys_state
    pub id: u64,
    pub blkg_list: *mut u8,     // List of blkcg_gqs
    pub blkg_tree: *mut u8,
    pub cpd: [*mut u8; 4],     // Per-policy data (one per policy type)
    pub online_pin: u32,
    pub cgwb_list: *mut u8,
    pub cgwb_refcnt: u32,
}

/// blk-throttle config
#[repr(C)]
pub struct ThrottleConfig {
    pub bps_limit: [u64; 2],       // Read/Write bytes per second limit
    pub iops_limit: [u32; 2],      // Read/Write IOPS limit
    pub bytes_disp: [u64; 2],      // bytes dispatched
    pub io_disp: [u32; 2],         // IOs dispatched
    pub last_low_overflow_time: [u64; 2],
    pub latency_target: u64,
    pub idletime_threshold: u64,
    pub slice_start: [u64; 2],
    pub slice_end: [u64; 2],
}

/// io.cost model
#[repr(C)]
pub struct IosCostModel {
    pub rbps: u64,        // Read BPS
    pub rseqiops: u64,    // Read sequential IOPS
    pub rrandiops: u64,   // Read random IOPS
    pub wbps: u64,        // Write BPS
    pub wseqiops: u64,    // Write sequential IOPS
    pub wrandiops: u64,   // Write random IOPS
}

/// io.cost QoS parameters
#[repr(C)]
pub struct IosCostQos {
    pub enable: bool,
    pub ctrl: IosCostCtrl,
    pub rpct: u32,         // Read latency percentile
    pub rlat: u64,         // Read latency target
    pub wpct: u32,         // Write latency percentile
    pub wlat: u64,         // Write latency target
    pub min: u32,          // Min scaling percentage
    pub max: u32,          // Max scaling percentage
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IosCostCtrl {
    Auto = 0,
    User = 1,
}

// ============================================================================
// I/O Scheduler Interface
// ============================================================================

/// Elevator types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevatorType {
    None = 0,
    Mq_Deadline = 1,
    Bfq = 2,
    Kyber = 3,
}

/// Elevator operations
#[repr(C)]
pub struct ElevatorMqOps {
    pub init_sched: Option<unsafe extern "C" fn(q: *mut u8, e: *mut u8) -> i32>,
    pub exit_sched: Option<unsafe extern "C" fn(e: *mut u8)>,
    pub init_hctx: Option<unsafe extern "C" fn(hctx: *mut BlkMqHwCtx, idx: u32) -> i32>,
    pub exit_hctx: Option<unsafe extern "C" fn(hctx: *mut BlkMqHwCtx, idx: u32)>,
    pub depth_updated: Option<unsafe extern "C" fn(hctx: *mut BlkMqHwCtx)>,
    pub limit_depth: Option<unsafe extern "C" fn(opf: u32, data: *mut u8)>,
    pub bio_merge: Option<unsafe extern "C" fn(q: *mut u8, bio: *mut Bio, nr_segs: u32) -> bool>,
    pub request_merge: Option<unsafe extern "C" fn(q: *mut u8, rq: *mut u8, bio: *mut Bio) -> ElvMerge>,
    pub request_merged: Option<unsafe extern "C" fn(q: *mut u8, rq: *mut u8, merge_type: ElvMerge)>,
    pub requests_merged: Option<unsafe extern "C" fn(q: *mut u8, rq: *mut u8, next: *mut u8)>,
    pub insert_requests: Option<unsafe extern "C" fn(hctx: *mut BlkMqHwCtx, list: *mut u8, flags: u32)>,
    pub dispatch_request: Option<unsafe extern "C" fn(hctx: *mut BlkMqHwCtx) -> *mut u8>,
    pub has_work: Option<unsafe extern "C" fn(hctx: *mut BlkMqHwCtx) -> bool>,
    pub completed_request: Option<unsafe extern "C" fn(rq: *mut u8, now: u64)>,
    pub requeue_request: Option<unsafe extern "C" fn(rq: *mut u8)>,
    pub former_request: Option<unsafe extern "C" fn(q: *mut u8, rq: *mut u8) -> *mut u8>,
    pub next_request: Option<unsafe extern "C" fn(q: *mut u8, rq: *mut u8) -> *mut u8>,
    pub prepare_request: Option<unsafe extern "C" fn(rq: *mut u8)>,
    pub finish_request: Option<unsafe extern "C" fn(rq: *mut u8)>,
}

/// mq-deadline scheduler data
#[repr(C)]
pub struct DeadlineData {
    pub fifo_list: [[*mut u8; 2]; 2],  // [read/write][fifo_time sorted]
    pub sort_list: [*mut u8; 2],        // [read/write] sorted by sector
    pub fifo_expire: [i64; 2],          // Read/Write expire (jiffies)
    pub writes_starved: i32,
    pub front_merges: i32,
    pub fifo_batch: u32,
    pub batching: i32,
    pub last_dir: i32,
    pub starved: i32,
    pub dispatch: [*mut u8; 2],
    pub async_depth: u32,
    pub prio_aging_expire: u64,
}

/// BFQ scheduler data
#[repr(C)]
pub struct BfqData {
    pub queue: *mut u8,
    pub root_group: *mut BfqGroup,
    pub in_service_queue: *mut BfqQueue,
    pub active_numerous_groups: u32,
    pub num_groups_with_pending_reqs: u32,
    pub tot_rq_in_driver: u32,
    pub hw_tag: i32,
    pub rq_in_driver: [u32; 8],
    pub peak_rate: u64,
    pub peak_rate_samples: u32,
    pub bfq_max_budget: u32,
    pub budgets_assigned: u64,
    pub idle_slice_timer: u64,
    pub dispatch_wait_timer: u64,
    pub wr_busy_queues: i32,
    pub busy_queues: [i32; 4],
    pub strict_guarantees: bool,
    pub low_latency: bool,
    pub bfq_slice_idle: u64,
}

#[repr(C)]
pub struct BfqQueue {
    pub sort_list: *mut u8,
    pub next_rq: *mut u8,
    pub queued: [i32; 2],
    pub allocated: i32,
    pub meta_pending: i32,
    pub dispatched: i32,
    pub service_from_wr: u64,
    pub wr_coeff: u32,
    pub wr_start_at_switch_to_srt: u64,
    pub wr_cur_max_time: u64,
    pub last_wr_start_finish: u64,
    pub entity: *mut u8,
    pub bfqd: *mut BfqData,
    pub bfqg: *mut BfqGroup,
    pub pid: i32,
    pub ioprio: u16,
    pub ioprio_class: u16,
    pub new_ioprio: u16,
    pub new_ioprio_class: u16,
}

pub struct BfqGroup {
    pub entity: *mut u8,
    pub sched_data: *mut u8,
    pub bfqd: *mut BfqData,
    pub active_entities: u32,
    pub rq_pos_tree: *mut u8,
}

/// Kyber scheduler data
#[repr(C)]
pub struct KyberQueueData {
    pub domain_tokens: [u32; 4],    // Read, Write, Discard, Other
    pub async_depth: u32,
    pub latency_targets: [u64; 4],
    pub latency_buckets: [KyberLatencyBuckets; 4],
    pub cpu_latency: [*mut u8; 4],
    pub timer: u64,
}

pub struct KyberLatencyBuckets {
    pub buckets: [u32; 4],         // 4 latency buckets
    pub total: u64,
}

// ============================================================================
// Statistics
// ============================================================================

pub struct BioCryptZonedStats {
    pub inline_encrypt_ops: u64,
    pub inline_decrypt_ops: u64,
    pub keyslot_programs: u64,
    pub keyslot_evictions: u64,
    pub fallback_encryptions: u64,
    pub fallback_decryptions: u64,
    pub zone_resets: u64,
    pub zone_opens: u64,
    pub zone_closes: u64,
    pub zone_finishes: u64,
    pub zone_appends: u64,
    pub zone_append_retries: u64,
    pub bio_splits: u64,
    pub bio_merges_front: u64,
    pub bio_merges_back: u64,
    pub io_accounting_reads: u64,
    pub io_accounting_writes: u64,
    pub io_accounting_discards: u64,
    pub blkcg_throttle_events: u64,
    pub iocost_adjustments: u64,
    pub initialized: bool,
}

impl BioCryptZonedStats {
    pub fn new() -> Self {
        Self {
            inline_encrypt_ops: 0,
            inline_decrypt_ops: 0,
            keyslot_programs: 0,
            keyslot_evictions: 0,
            fallback_encryptions: 0,
            fallback_decryptions: 0,
            zone_resets: 0,
            zone_opens: 0,
            zone_closes: 0,
            zone_finishes: 0,
            zone_appends: 0,
            zone_append_retries: 0,
            bio_splits: 0,
            bio_merges_front: 0,
            bio_merges_back: 0,
            io_accounting_reads: 0,
            io_accounting_writes: 0,
            io_accounting_discards: 0,
            blkcg_throttle_events: 0,
            iocost_adjustments: 0,
            initialized: true,
        }
    }
}
