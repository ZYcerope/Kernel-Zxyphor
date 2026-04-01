// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust Block I/O Scheduler Detail
//! mq-deadline, BFQ, kyber internals from Rust perspective,
//! request merging, dispatch, blk-stat, blkcg throttle,
//! I/O latency controller, I/O cost model (iocost)

#![allow(dead_code)]

// ============================================================================
// I/O Priority
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoprioClass {
    None = 0,
    Rt = 1,      // realtime
    Be = 2,      // best effort
    Idle = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ioprio {
    pub class: IoprioClass,
    pub level: u8,       // 0-7
    pub hint: u8,        // hint for scheduler
}

impl Ioprio {
    pub const MAX_LEVEL: u8 = 7;
    pub const NR_LEVELS: u8 = 8;

    pub fn encode(class: IoprioClass, level: u8) -> u16 {
        let c = class as u16;
        let l = (level & 0x7) as u16;
        (c << 13) | l
    }
}

// ============================================================================
// Block Cgroup (blkcg)
// ============================================================================

#[repr(C)]
pub struct BlkcgGq {
    pub blkcg: u64,         // blkcg *
    pub q: u64,             // request_queue *
    pub refcnt: u64,
    // Per-policy data
    pub pd: [u64; 6],       // blkcg_policy_data * (max 6 policies)
    // Stats
    pub stat_bytes: BlkcgStat,
    pub stat_ios: BlkcgStat,
    // Throttle
    pub has_rules: [bool; 2], // read, write
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct BlkcgStat {
    pub bytes: [u64; 4],    // read, write, discard, flush
    pub ios: [u64; 4],
}

// ============================================================================
// I/O Throttle (blk-throttle)
// ============================================================================

#[repr(C)]
pub struct ThrotlGrp {
    // BPS limits
    pub bps_limit: [u64; 2],    // read, write (bytes/sec, u64::MAX = unlimited)
    // IOPS limits
    pub iops_limit: [u32; 2],   // read, write
    // Current
    pub bytes_disp: [u64; 2],
    pub io_disp: [u64; 2],
    // Slice
    pub slice_start: u64,
    pub slice_end: u64,
    // Wait
    pub nr_queued: [u32; 2],
    pub wait_time: u64,
    // Low/high limits
    pub bps_low: [u64; 2],
    pub iops_low: [u32; 2],
    pub idletime_threshold: u64,
    pub latency_target: u64,
    // Flags
    pub flags: ThrotlGrpFlags,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct ThrotlGrpFlags {
    bits: u32,
}

impl ThrotlGrpFlags {
    pub const HAS_IOPS: u32 = 1 << 0;
    pub const HAS_BPS: u32 = 1 << 1;
    pub const IS_TG_IDLE: u32 = 1 << 2;
}

// ============================================================================
// I/O Latency Controller (blk-iolatency)
// ============================================================================

#[repr(C)]
pub struct IolatencyGrp {
    pub target_lat: u64,      // target latency in nanoseconds
    pub min_lat_nsec: u64,
    pub max_lat_nsec: u64,
    // Stats
    pub total_lat_avg: u64,
    pub rq_wait: RqWait,
    pub scale_cookie: u64,
    // Depth
    pub rq_depth: RqDepth,
    // Counters
    pub done_bio_cnt: u64,
    pub outstanding_bio_cnt: u64,
    pub scale_lat: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct RqWait {
    pub wait: u64,            // wait_queue_head
    pub inflight: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct RqDepth {
    pub max_depth: u32,
    pub default_depth: u32,
    pub queue_depth: u32,
    pub scale_step: i32,
    pub scaled: bool,
}

// ============================================================================
// I/O Cost Model (iocost)
// ============================================================================

#[repr(C)]
pub struct IocGrp {
    pub ioc: u64,             // ioc *
    // Weights
    pub weight: u32,
    pub active: bool,
    // vtime
    pub vtime: u64,
    pub done_vtime: u64,
    pub abs_vdebt: u64,
    pub delay: u64,
    // Usage
    pub usage_delta_us: u64,
    pub usage_us: u64,
    pub wait_us: u64,
    pub indebt_us: u64,
    pub indelay_us: u64,
    // Hierarchy
    pub level: u32,
    pub child_active_count: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct IocParams {
    // QoS parameters
    pub qos_rpct: [u32; 2],  // read/write latency percentile (0-100)
    pub qos_rlat: [u64; 2],  // read/write latency target (us)
    pub qos_wpct: [u32; 2],
    pub qos_wlat: [u64; 2],
    pub qos_min: u32,
    pub qos_max: u32,
    // Cost model
    pub lcoefs: [IocCoef; 2],  // read/write
    // Autotune
    pub autop: IocAutop,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct IocCoef {
    pub rbps: u64,     // random bytes per second
    pub rseqiops: u64, // random sequential IOPS
    pub rlat: u64,     // random latency
    pub wbps: u64,
    pub wseqiops: u64,
    pub wlat: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocAutop {
    Hdd = 0,
    SsdQd1 = 1,
    SsdDfl = 2,
    SsdFast = 3,
    Custom = 4,
}

impl Default for IocAutop {
    fn default() -> Self {
        IocAutop::SsdDfl
    }
}

// ============================================================================
// BFQ (Budget Fair Queueing) - Rust View
// ============================================================================

#[repr(C)]
pub struct BfqEntity {
    pub weight: u32,
    pub new_weight: u32,
    pub orig_weight: u32,
    pub ioprio: u16,
    pub ioprio_class: IoprioClass,
    pub new_ioprio: u16,
    pub new_ioprio_class: IoprioClass,
    // Service tree
    pub start: u64,
    pub finish: u64,
    pub budget: u64,
    pub service: u64,
    // Weight raising
    pub wr_coeff: u32,
    pub wr_start_at_switch_to_srt: u64,
    pub wr_cur_max_time: u64,
    pub last_wr_start_finish: u64,
    pub soft_rt_next_start: u64,
    // State
    pub on_st_or_in_serv: bool,
    pub in_groups_with_pending_reqs: bool,
}

#[repr(C)]
pub struct BfqEntityStats {
    pub sectors: u64,
    pub service_bytes: u64,
    pub service_ios: u64,
    pub wait_time: u64,
    pub idle_time: u64,
    pub dequeue: u64,
    pub avg_queue_size_sum: u64,
    pub avg_queue_size_samples: u64,
}

// ============================================================================
// mq-deadline - Rust View
// ============================================================================

#[repr(C)]
pub struct MqDeadlineConfig {
    pub read_expire: u32,     // milliseconds (default: 500)
    pub write_expire: u32,    // milliseconds (default: 5000)
    pub writes_starved: u32,  // default: 2
    pub front_merges: bool,   // default: true
    pub fifo_batch: u32,      // default: 16
    pub prio_aging_expire: u32, // jiffies
}

impl Default for MqDeadlineConfig {
    fn default() -> Self {
        Self {
            read_expire: 500,
            write_expire: 5000,
            writes_starved: 2,
            front_merges: true,
            fifo_batch: 16,
            prio_aging_expire: 10000,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MqDeadlineStats {
    pub batching: u32,
    pub starved: u32,
    pub dispatched: [u64; 2],   // read, write
    pub merged: [u64; 2],
    pub completed: [u64; 2],
    pub insert_count: u64,
}

// ============================================================================
// Kyber - Rust View
// ============================================================================

#[repr(C)]
pub struct KyberConfig {
    pub read_lat_nsec: u64,   // default: 2ms
    pub write_lat_nsec: u64,  // default: 10ms
    pub discard_lat_nsec: u64,
    pub other_lat_nsec: u64,
}

impl Default for KyberConfig {
    fn default() -> Self {
        Self {
            read_lat_nsec: 2_000_000,
            write_lat_nsec: 10_000_000,
            discard_lat_nsec: 5_000_000,
            other_lat_nsec: 5_000_000,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct KyberDomainStats {
    pub token_limit: u32,
    pub nr_tokens: u32,
    pub total_tokens_used: u64,
    pub nr_dispatched: u64,
    pub lat_buckets: [u64; 8],
}

// ============================================================================
// WBT (Write-Back Throttle)
// ============================================================================

#[repr(C)]
pub struct WbtState {
    pub wb_normal: u32,       // normal background write depth
    pub wb_background: u32,   // background write depth
    pub wb_max: u32,
    pub scale_step: i32,
    pub unknown_cnt: u32,
    pub min_lat_nsec: u64,
    pub cur_win_nsec: u64,
    pub enabled: bool,
    // Stats
    pub total_throttled: u64,
    pub total_completion: u64,
    pub inflight: [u32; 2], // read, write
}

// ============================================================================
// Request Merge
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeType {
    None = 0,
    Front = 1,
    Back = 2,
    Discard = 3,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MergeStats {
    pub front_merges: u64,
    pub back_merges: u64,
    pub discard_merges: u64,
    pub bio_attempts: u64,
    pub total_merged: u64,
    pub failed_merges: u64,
}

// ============================================================================
// blk-stat (I/O Statistics)
// ============================================================================

#[repr(C)]
#[derive(Debug, Default)]
pub struct BlkStatCallback {
    pub bucket_fn: u64,
    pub timer_fn: u64,
    pub stat: [BlkStatBucket; 4], // per bucket (read/write/discard/flush)
    pub timer_interval_ns: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct BlkStatBucket {
    pub nr_samples: u64,
    pub mean: u64,
    pub min: u64,
    pub max: u64,
    pub batch_nr: u32,
}

// ============================================================================
// Latency Histograms
// ============================================================================

pub const BLK_LAT_BUCKETS: usize = 20;

#[repr(C)]
#[derive(Debug)]
pub struct BlkLatHistogram {
    pub boundaries_ns: [u64; BLK_LAT_BUCKETS],
    pub read_buckets: [u64; BLK_LAT_BUCKETS],
    pub write_buckets: [u64; BLK_LAT_BUCKETS],
    pub discard_buckets: [u64; BLK_LAT_BUCKETS],
    pub flush_buckets: [u64; BLK_LAT_BUCKETS],
}

impl Default for BlkLatHistogram {
    fn default() -> Self {
        let mut boundaries = [0u64; BLK_LAT_BUCKETS];
        // Log-scale boundaries: 1us, 2us, 4us, ..., ~500ms
        for i in 0..BLK_LAT_BUCKETS {
            boundaries[i] = 1000 << i;
        }
        Self {
            boundaries_ns: boundaries,
            read_buckets: [0; BLK_LAT_BUCKETS],
            write_buckets: [0; BLK_LAT_BUCKETS],
            discard_buckets: [0; BLK_LAT_BUCKETS],
            flush_buckets: [0; BLK_LAT_BUCKETS],
        }
    }
}

// ============================================================================
// I/O Scheduler Manager
// ============================================================================

#[derive(Debug)]
pub struct IoSchedManager {
    pub active_scheduler: SchedulerType,
    pub total_queues: u32,
    pub total_ios_dispatched: u64,
    pub total_ios_merged: u64,
    pub total_ios_completed: u64,
    pub total_bytes_dispatched: u64,
    // Throttle stats
    pub throttle_ios: u64,
    pub throttle_bytes: u64,
    // Latency
    pub avg_read_lat_ns: u64,
    pub avg_write_lat_ns: u64,
    pub p99_read_lat_ns: u64,
    pub p99_write_lat_ns: u64,
    // iocost
    pub iocost_active: bool,
    pub iocost_vtime: u64,
    // WBT
    pub wbt_enabled: bool,
    pub wbt_throttled: u64,
    // Histogram
    pub histogram: BlkLatHistogram,
    pub initialized: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerType {
    None = 0,
    MqDeadline = 1,
    Bfq = 2,
    Kyber = 3,
}

impl IoSchedManager {
    pub fn new() -> Self {
        Self {
            active_scheduler: SchedulerType::MqDeadline,
            total_queues: 0,
            total_ios_dispatched: 0,
            total_ios_merged: 0,
            total_ios_completed: 0,
            total_bytes_dispatched: 0,
            throttle_ios: 0,
            throttle_bytes: 0,
            avg_read_lat_ns: 0,
            avg_write_lat_ns: 0,
            p99_read_lat_ns: 0,
            p99_write_lat_ns: 0,
            iocost_active: false,
            iocost_vtime: 0,
            wbt_enabled: true,
            wbt_throttled: 0,
            histogram: BlkLatHistogram::default(),
            initialized: true,
        }
    }
}
