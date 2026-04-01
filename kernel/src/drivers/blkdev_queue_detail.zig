// Zxyphor Kernel - Block Device Queue Detail
// Request queue, I/O scheduler (mq-deadline, BFQ, kyber, none)
// blk-mq: hardware queues, software queues, tag sets
// bio, bvec, request lifecycle, plug/unplug, merge, stat
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Bio (Block I/O) - Core
// ============================================================================

pub const BioOpf = packed struct(u32) {
    op: u8,         // REQ_OP_*
    flags: u24,     // REQ_*
};

pub const BioOp = enum(u8) {
    read = 0,
    write = 1,
    flush = 2,
    discard = 3,
    secure_erase = 5,
    write_zeroes = 9,
    zone_open = 10,
    zone_close = 11,
    zone_finish = 12,
    zone_append = 13,
    zone_reset = 15,
    zone_reset_all = 17,
    drv_in = 34,
    drv_out = 35,
    last = 36,
};

pub const ReqFlags = packed struct(u24) {
    failfast_dev: bool = false,
    failfast_transport: bool = false,
    failfast_driver: bool = false,
    sync: bool = false,
    meta: bool = false,
    prio: bool = false,
    nomerge: bool = false,
    idle: bool = false,
    integrity: bool = false,
    fua: bool = false,          // Force Unit Access
    preflush: bool = false,
    rahead: bool = false,
    background: bool = false,
    nowait: bool = false,
    polled: bool = false,
    alloc_cache: bool = false,
    swap: bool = false,
    drv: bool = false,
    nounmap: bool = false,
    _pad: u5 = 0,
};

pub const Bio = struct {
    bi_next: ?*Bio,
    bi_bdev: u64,       // block_device *
    bi_opf: u32,
    bi_flags: BioFlags,
    bi_status: BlkStatus,
    bi_ioprio: u16,
    bi_write_hint: u8,
    // Iterator
    bi_iter: BvecIter,
    // Completion
    bi_end_io: u64,     // callback
    bi_private: u64,
    // Inline vecs
    bi_io_vec: u64,     // struct bio_vec *
    bi_max_vecs: u16,
    bi_cnt: u32,        // reference count
    // cgroup
    bi_blkg: u64,
    bi_iocost_cost: u64,
    // Crypt
    bi_crypt_context: u64,
    // Integrity
    bi_integrity: u64,
    // Pool
    bi_pool: u64,
};

pub const BioFlags = packed struct(u16) {
    seg_valid: bool = false,
    cloned: bool = false,
    bounced: bool = false,
    workingset: bool = false,
    quiet: bool = false,
    chain: bool = false,
    reffed: bool = false,
    bps_throttled: bool = false,
    trace_completion: bool = false,
    cgroup_acct: bool = false,
    tracked: bool = false,
    remapped: bool = false,
    zone_write_plugging: bool = false,
    _pad: u3 = 0,
};

pub const BvecIter = extern struct {
    bi_sector: u64,
    bi_size: u32,
    bi_idx: u32,
    bi_bvec_done: u32,
};

pub const BioVec = extern struct {
    bv_page: u64,
    bv_len: u32,
    bv_offset: u32,
};

pub const BlkStatus = enum(u8) {
    ok = 0,
    notsupp = 1,
    timeout = 2,
    nospc = 3,
    transport = 4,
    target = 5,
    nexus = 6,
    medium = 7,
    protection = 8,
    resource = 9,
    ioerr = 10,
    dma = 11,
    invalid = 12,
    write_same = 13,
    zone_resource = 14,
    zone_open_resource = 15,
    offline = 16,
    duration_limit = 17,
    again = 18,
};

// ============================================================================
// Request (blk-mq request)
// ============================================================================

pub const Request = struct {
    // Queue
    q: u64,                 // request_queue *
    mq_ctx: u64,            // blk_mq_ctx *
    mq_hctx: u64,           // blk_mq_hw_ctx *
    // Command type
    cmd_type: u32,
    cmd_flags: u32,
    // Tag
    tag: u32,
    internal_tag: u32,
    // Sector
    __sector: u64,
    __data_len: u32,
    // Bio chain
    bio: ?*Bio,
    biotail: ?*Bio,
    // Timing
    start_time_ns: u64,
    io_start_time_ns: u64,
    // Deadline
    deadline: u64,
    // Stats
    stats_sectors: u32,
    nr_phys_segments: u16,
    // Error
    errors: u32,
    // Ref count
    ref: u32,
    // Flags
    rq_flags: RqFlags,
    // Priority
    ioprio: u16,
    // Completion
    end_io: u64,
    end_io_data: u64,
};

pub const RqFlags = packed struct(u32) {
    sorted: bool = false,
    started: bool = false,
    flush_seq: bool = false,
    mixed_merge: bool = false,
    mq_inflight: bool = false,
    dontprep: bool = false,
    sched_tags: bool = false,
    use_sched: bool = false,
    failed: bool = false,
    quiet: bool = false,
    io_stat: bool = false,
    pm: bool = false,
    hashed: bool = false,
    stats: bool = false,
    special_payload: bool = false,
    zone_write_plugging: bool = false,
    timed_out: bool = false,
    resv: bool = false,
    _pad: u14 = 0,
};

// ============================================================================
// Request Queue
// ============================================================================

pub const RequestQueue = struct {
    // Queue limits
    limits: QueueLimits,
    // Elevator (scheduler)
    elevator: u64,          // elevator_queue *
    elevator_type: ElevatorType,
    // blk-mq
    tag_set: u64,           // blk_mq_tag_set *
    nr_hw_queues: u32,
    queue_depth: u32,
    // Software queues (per-CPU)
    nr_sw_queues: u32,
    // Flags
    queue_flags: QueueFlags,
    // Backing device
    backing_dev_info: u64,
    // Stats
    stats: BlkQueueStats,
    // Plugging
    plug_count: u64,
    // Merge
    merge_bvec: u64,
    // Throttle
    td: u64,               // throtl_data *
    // WBT (writeback throttle)
    rq_wb: u64,
    // Freeze
    mq_freeze_depth: u32,
    // Quiesce
    quiesce_depth: u32,
    // Integrity
    integrity: BlkIntegrityProfile,
    // Zoned
    nr_zones: u32,
    conv_zones_bitmap: u64,
    seq_zones_wlock: u64,
    zone_write_plugs: u64,
};

pub const QueueLimits = struct {
    max_hw_sectors: u32,
    max_dev_sectors: u32,
    chunk_sectors: u32,
    max_sectors: u32,
    max_user_sectors: u32,
    max_segment_size: u32,
    max_segments: u16,
    max_integrity_segments: u16,
    max_discard_sectors: u32,
    max_hw_discard_sectors: u32,
    max_secure_erase_sectors: u32,
    max_write_zeroes_sectors: u32,
    max_zone_append_sectors: u32,
    discard_granularity: u32,
    discard_alignment: u32,
    logical_block_size: u32,
    physical_block_size: u32,
    io_min: u32,
    io_opt: u32,
    max_open_zones: u32,
    max_active_zones: u32,
    misaligned: bool,
    discard_misaligned: bool,
    no_cluster: bool,
    zoned: BlkZonedModel,
    dma_alignment: u32,
    // Features
    features: QueueFeatures,
};

pub const QueueFeatures = packed struct(u32) {
    rotational: bool = false,
    add_random: bool = false,
    synchronous: bool = false,
    nowait: bool = false,
    io_stat: bool = false,
    poll: bool = false,
    zone_resetall: bool = false,
    secure_erase: bool = false,
    discard: bool = false,
    write_zeroes: bool = false,
    raid56_rmw: bool = false,
    stable_writes: bool = false,
    _pad: u20 = 0,
};

pub const BlkZonedModel = enum(u8) {
    none = 0,
    host_aware = 1,
    host_managed = 2,
};

pub const QueueFlags = packed struct(u64) {
    stopped: bool = false,
    dying: bool = false,
    nomerges: bool = false,
    same_comp: bool = false,
    fail_io: bool = false,
    nonrot: bool = false,
    io_stat: bool = false,
    noxmerges: bool = false,
    add_random: bool = false,
    same_force: bool = false,
    init_done: bool = false,
    stable_writes: bool = false,
    poll: bool = false,
    wb_report: bool = false,
    registered: bool = false,
    nowait: bool = false,
    sq_sched: bool = false,
    _pad: u47 = 0,
};

// ============================================================================
// I/O Schedulers
// ============================================================================

pub const ElevatorType = enum(u8) {
    none = 0,
    mq_deadline = 1,
    bfq = 2,
    kyber = 3,
};

// -- mq-deadline --

pub const MqDeadlineData = struct {
    // Sorted by deadline
    fifo_time: [2]u64,     // read, write expiry (jiffies)
    // Batching
    batching: u32,
    front_merges: bool,
    // Dispatch
    writes_starved: u32,
    fifo_batch: u32,
    read_expire: u32,     // ms
    write_expire: u32,    // ms
    // Stats
    dispatch: [2]u64,     // read, write
    merged: [2]u64,
    starved: u64,
    prio_aging_expire: u32,
};

// -- BFQ --

pub const BfqData = struct {
    // Queue weight
    default_weight: u32,
    // Parameters
    low_latency: bool,
    back_seek_max: u32,
    back_seek_penalty: u32,
    slice_idle: u32,       // us
    strict_guarantees: bool,
    // Groups
    num_groups_with_pending_reqs: u32,
    // Stats
    queued: u32,
    dispatched: u32,
    rq_in_driver: u32,
    peak_rate: u64,
    // Scheduling
    in_service_queue: u64,
    active_entities: u32,
    idle_entities: u32,
    tot_budget_assigned: u64,
    budget_timeout: u32,
};

pub const BfqQueue = struct {
    weight: u32,
    ioprio: u16,
    ioprio_class: u8,
    wr_coeff: u32,         // weight-raising coefficient
    last_wr_start_finish: u64,
    wr_cur_max_time: u64,
    // Budget
    entity_budget: u32,
    max_budget: u32,
    // Stats
    dispatched: u64,
    queued: u64,
    seek_mean: u64,
};

// -- Kyber --

pub const KyberData = struct {
    // Domain tokens
    domain_tokens: [3]u32,  // read, write, discard
    // Latency targets
    read_lat_nsec: u64,
    write_lat_nsec: u64,
    // Statistics
    latency_buckets: [3][10]u64,
    cur_domain: [3]u32,
};

// ============================================================================
// blk-mq Hardware Context
// ============================================================================

pub const BlkMqHwCtx = struct {
    queue_num: u32,
    nr_ctx: u32,
    sched_tags: u64,
    tags: u64,
    flags: BlkMqHwFlags,
    // CPU mapping
    cpumask: [4]u64,    // 256 CPUs
    // Dispatch
    dispatch_busy: u64,
    dispatch_count: u64,
    // State
    state: BlkMqHctxState,
    // Stats
    dispatched: [11]u64, // by request count bucket
    queued: u64,
    run: u64,
    poll_considered: u64,
    poll_invoked: u64,
    poll_success: u64,
};

pub const BlkMqHwFlags = packed struct(u16) {
    should_merge: bool = false,
    tag_queue_shared: bool = false,
    stacking: bool = false,
    tag_hctx_shared: bool = false,
    blocking: bool = false,
    _pad: u11 = 0,
};

pub const BlkMqHctxState = enum(u8) {
    running = 0,
    stopped = 1,
    tag_active = 2,
    sched_restart = 3,
};

// ============================================================================
// blk-mq Tag Set
// ============================================================================

pub const BlkMqTagSet = struct {
    nr_hw_queues: u32,
    queue_depth: u32,
    reserved_tags: u32,
    cmd_size: u32,
    numa_node: i32,
    timeout: u32,
    flags: BlkMqTagSetFlags,
    driver_data: u64,
    nr_maps: u32,
};

pub const BlkMqTagSetFlags = packed struct(u32) {
    blocking: bool = false,
    no_sched: bool = false,
    tag_queue_shared: bool = false,
    stacking: bool = false,
    tag_hctx_shared: bool = false,
    _pad: u27 = 0,
};

// ============================================================================
// Block Device Integrity
// ============================================================================

pub const BlkIntegrityProfile = struct {
    generate_fn: u64,
    verify_fn: u64,
    name: [32]u8,
    interval_exp: u8,
    tag_size: u8,
    tuple_size: u8,
    flags: BlkIntegrityFlags,
};

pub const BlkIntegrityFlags = packed struct(u8) {
    generate: bool = false,
    verify: bool = false,
    device_capable: bool = false,
    ip_checksum: bool = false,
    _pad: u4 = 0,
};

// ============================================================================
// Block Stats
// ============================================================================

pub const BlkQueueStats = struct {
    // I/O counts
    read_ios: u64,
    read_merges: u64,
    read_sectors: u64,
    read_ticks: u64,
    write_ios: u64,
    write_merges: u64,
    write_sectors: u64,
    write_ticks: u64,
    discard_ios: u64,
    discard_merges: u64,
    discard_sectors: u64,
    discard_ticks: u64,
    flush_ios: u64,
    flush_ticks: u64,
    // In-flight
    in_flight: [2]u32,    // read, write
    // Queue time
    io_ticks: u64,
    time_in_queue: u64,
    // Latency histograms (ns)
    read_lat_histogram: [20]u64,
    write_lat_histogram: [20]u64,
};

// ============================================================================
// Plug/Unplug
// ============================================================================

pub const BlkPlug = struct {
    mq_list: u64,      // list of requests
    cached_rq: u64,
    nr_ios: u16,
    rq_count: u32,
    multiple_queues: bool,
    has_elevator: bool,
    nowait: bool,
};

// ============================================================================
// Block Queue Manager
// ============================================================================

pub const BlkQueueManager = struct {
    total_queues: u32,
    active_queues: u32,
    // By scheduler
    none_queues: u32,
    deadline_queues: u32,
    bfq_queues: u32,
    kyber_queues: u32,
    // I/O stats
    total_read_ios: u64,
    total_write_ios: u64,
    total_discard_ios: u64,
    total_flush_ios: u64,
    total_sectors_read: u64,
    total_sectors_written: u64,
    // Merge stats
    total_merges: u64,
    // Plug stats
    total_plugs: u64,
    total_unplugs: u64,
    initialized: bool,

    pub fn init() BlkQueueManager {
        return BlkQueueManager{
            .total_queues = 0,
            .active_queues = 0,
            .none_queues = 0,
            .deadline_queues = 0,
            .bfq_queues = 0,
            .kyber_queues = 0,
            .total_read_ios = 0,
            .total_write_ios = 0,
            .total_discard_ios = 0,
            .total_flush_ios = 0,
            .total_sectors_read = 0,
            .total_sectors_written = 0,
            .total_merges = 0,
            .total_plugs = 0,
            .total_unplugs = 0,
            .initialized = true,
        };
    }
};
