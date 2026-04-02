// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Radix Tree, Percpu Allocator & RCU Detail
// Complete: radix tree operations, percpu memory management, RCU callbacks,
// SRCU, RCU tree, preempt notifiers, workqueue detail

const std = @import("std");

// ============================================================================
// Radix Tree
// ============================================================================

pub const RADIX_TREE_MAP_SHIFT: u32 = 6;
pub const RADIX_TREE_MAP_SIZE: u32 = 1 << RADIX_TREE_MAP_SHIFT;
pub const RADIX_TREE_MAP_MASK: u64 = RADIX_TREE_MAP_SIZE - 1;
pub const RADIX_TREE_MAX_TAGS: u32 = 3;

pub const RadixTreeTag = enum(u8) {
    Dirty = 0,
    Writeback = 1,
    ToFree = 2,
};

pub const RadixTreeNode = struct {
    shift: u8,
    offset: u8,
    count: u8,
    exceptional: u8,
    parent: ?*RadixTreeNode,
    root: ?*RadixTreeRoot,
    slots: [RADIX_TREE_MAP_SIZE]?*anyopaque,
    tags: [RADIX_TREE_MAX_TAGS][1]u64,        // Bitmap per tag
    pending_count: u32,
};

pub const RadixTreeRoot = struct {
    height: u32,
    gfp_mask: u32,
    rnode: ?*RadixTreeNode,
    idr_rt: bool,
    xa_lock: u64,
    xa_flags: u32,
};

pub const RadixTreeIter = struct {
    index: u64,
    next_index: u64,
    tags: u64,
    node: ?*RadixTreeNode,
    flags: RadixTreeIterFlags,
};

pub const RadixTreeIterFlags = packed struct(u32) {
    tagged: bool,
    contig: bool,
    _reserved: u30,
};

pub const RadixTreeOps = struct {
    init: ?*const fn (root: *RadixTreeRoot, gfp_mask: u32) callconv(.C) void,
    lookup: ?*const fn (root: *const RadixTreeRoot, index: u64) callconv(.C) ?*anyopaque,
    lookup_slot: ?*const fn (root: *const RadixTreeRoot, index: u64) callconv(.C) ?*?*anyopaque,
    insert: ?*const fn (root: *RadixTreeRoot, index: u64, item: *anyopaque) callconv(.C) i32,
    delete: ?*const fn (root: *RadixTreeRoot, index: u64) callconv(.C) ?*anyopaque,
    replace_slot: ?*const fn (root: *RadixTreeRoot, slot: *?*anyopaque, item: *anyopaque) callconv(.C) ?*anyopaque,
    tag_set: ?*const fn (root: *RadixTreeRoot, index: u64, tag: RadixTreeTag) callconv(.C) ?*anyopaque,
    tag_clear: ?*const fn (root: *RadixTreeRoot, index: u64, tag: RadixTreeTag) callconv(.C) ?*anyopaque,
    tag_get: ?*const fn (root: *const RadixTreeRoot, index: u64, tag: RadixTreeTag) callconv(.C) bool,
    tagged_count: ?*const fn (root: *const RadixTreeRoot, tag: RadixTreeTag) callconv(.C) u64,
    gang_lookup: ?*const fn (root: *const RadixTreeRoot, results: [*]*anyopaque, first_index: u64, max_items: u32) callconv(.C) u32,
    gang_lookup_tag: ?*const fn (root: *const RadixTreeRoot, results: [*]*anyopaque, first_index: u64, max_items: u32, tag: RadixTreeTag) callconv(.C) u32,
    preload: ?*const fn (gfp_mask: u32) callconv(.C) i32,
    preload_end: ?*const fn () callconv(.C) void,
};

// ============================================================================
// Percpu Allocator
// ============================================================================

pub const PcpuChunkType = enum(u8) {
    First = 0,
    Reserved = 1,
    Dynamic = 2,
};

pub const PcpuChunk = struct {
    chunk_type: PcpuChunkType,
    base_addr: u64,
    start_offset: u32,
    end_offset: u32,
    nr_pages: u32,
    nr_populated: u32,
    nr_empty_pop_pages: u32,
    free_bytes: u32,
    contig_bits: u32,
    contig_bits_start: u32,
    first_bit: u32,
    populated: [64]u64,    // Bitmap: populated pages
    bound_map: [64]u64,    // Bitmap: allocation bounds
    alloc_map: [64]u64,    // Bitmap: allocated areas
    map_used: u32,
    map_alloc: u32,
    immutable: bool,
    obj_cgroups: ?*anyopaque,
    has_page: [64]u64,
};

pub const PcpuAllocInfo = struct {
    static_size: u32,
    reserved_size: u32,
    dyn_size: u32,
    unit_size: u32,
    atom_size: u32,
    alloc_size: u32,
    nr_groups: u32,
    groups: [8]PcpuGroupInfo,
};

pub const PcpuGroupInfo = struct {
    nr_units: u32,
    base_offset: u64,
    cpu_map: [256]u32,
};

pub const PercpuConfig = struct {
    unit_size: u32,
    first_chunk_size: u32,
    reserved_size: u32,
    dyn_size: u32,
    atom_size: u32,
    page_size: u32,
    min_alloc_size: u32,
    nr_slots: u32,
    nr_chunks: u32,
    nr_max_chunks: u32,
};

pub const PcpuStats = struct {
    nr_alloc: u64,
    nr_dealloc: u64,
    nr_cur_alloc: u64,
    nr_max_alloc: u64,
    min_alloc_size: u32,
    max_alloc_size: u32,
    total_alloc_bytes: u64,
    total_dealloc_bytes: u64,
};

// ============================================================================
// RCU (Read-Copy-Update)
// ============================================================================

pub const RcuFlavorType = enum(u8) {
    Rcu = 0,
    Rcu_Bh = 1,
    Rcu_Sched = 2,
    Srcu = 3,
    Tasks = 4,
    Tasks_Rude = 5,
    Tasks_Trace = 6,
};

pub const RcuState = struct {
    gp_seq: u64,
    gp_start: u64,
    gp_flags: RcuGpFlags,
    gp_kthread: ?*anyopaque,
    gp_activity: u64,
    gp_req_activity: u64,
    gp_wake_time: u64,
    gp_wake_seq: u64,
    completed: u64,
    expedited_sequence: u64,
    expedited_need_qs: u64,
    expedited_workdone0: u64,
    expedited_workdone1: u64,
    expedited_workdone2: u64,
    expedited_workdone3: u64,
    name: [16]u8,
    abbr: [4]u8,
    nr_nodes: u32,
    level_count: [4]u32,
    levelspread: [4]u32,
    ncpus: u32,
    qovld: i64,
    jiffies_force_qs: u64,
    jiffies_kick_kthreads: u64,
};

pub const RcuGpFlags = packed struct(u32) {
    init: bool,
    fqs: bool,
    cleanup: bool,
    flag_exp: bool,
    _reserved: u28,
};

pub const RcuNode = struct {
    gp_seq: u64,
    gp_seq_needed: u64,
    completedqs: u64,
    qsmask: u64,          // Bitmask of CPUs needing quiescent states
    qsmaskinit: u64,
    expmask: u64,
    expmaskinit: u64,
    boost_kthread: ?*anyopaque,
    boost_time: u64,
    boost_tasks: u64,
    exp_tasks: u64,
    parent: ?*RcuNode,
    level: u8,
    grplo: u16,
    grphi: u16,
    grpnum: u8,
    wait_blkd_tasks: bool,
};

pub const RcuData = struct {
    gp_seq: u64,
    gp_seq_needed: u64,
    cpu_no_qs: RcuCpuNoQs,
    core_needs_qs: bool,
    beenonline: bool,
    gpwrap: bool,
    cpu: u32,
    mynode: ?*RcuNode,
    grpmask: u64,
    nxtcb: [4]?*RcuHead,
    nxttail: [4]?*?*RcuHead,
    qlen: i64,
    qlen_lazy: i64,
    n_cbs_invoked: u64,
    n_force_qs_snap: u64,
    blimit: i64,
    dynticks_nesting: i64,
    dynticks_nmi_nesting: i64,
    dynticks: u64,
};

pub const RcuCpuNoQs = packed struct(u32) {
    core_needs_qs: bool,
    exp_need_qs: bool,
    _reserved: u30,
};

pub const RcuHead = struct {
    next: ?*RcuHead,
    func: ?*const fn (head: *RcuHead) callconv(.C) void,
};

pub const RcuCallbackStats = struct {
    nr_cbs_invoked: u64,
    nr_cbs_orphaned: u64,
    nr_cbs_adopted: u64,
    nr_gps_started: u64,
    nr_gps_completed: u64,
    nr_fqs_started: u64,
    nr_fqs_completed: u64,
    nr_expedited_started: u64,
    nr_expedited_completed: u64,
    total_gp_wait_ns: u64,
    max_gp_wait_ns: u64,
};

// ============================================================================
// SRCU (Sleepable RCU)
// ============================================================================

pub const SrcuStruct = struct {
    sda: ?*SrcuData,
    srcu_idx: u32,
    srcu_gp_seq: u64,
    srcu_gp_seq_needed: u64,
    srcu_gp_seq_needed_exp: u64,
    srcu_gp_start: u64,
    srcu_last_gp_end: u64,
    srcu_size_state: u32,
    srcu_sup: ?*SrcuUsage,
    work: u64,
};

pub const SrcuData = struct {
    srcu_lock_count: [2]u64,
    srcu_unlock_count: [2]u64,
    srcu_nmi_safety: u32,
    srcu_gp_seq_needed_exp: u64,
    mynode: ?*anyopaque,
    cpu: u32,
};

pub const SrcuUsage = struct {
    srcu_lock_nesting: [2]u64,
    srcu_idx: u32,
    srcu_sup_size: u32,
};

// ============================================================================
// Workqueue Detail
// ============================================================================

pub const WorkqueueFlags = packed struct(u32) {
    unbound: bool,
    freezable: bool,
    mem_reclaim: bool,
    highpri: bool,
    cpu_intensive: bool,
    sysfs: bool,
    power_efficient: bool,
    _reserved: u25,
};

pub const WorkqueueStruct = struct {
    name: [24]u8,
    flags: WorkqueueFlags,
    saved_max_active: i32,
    max_active: i32,
    nr_drainers: i32,
    nr_active: i32,
    rescuer: ?*anyopaque,
    unbound_attrs: ?*WorkqueueAttrs,
    id: i32,
    nice: i32,
    cpu_pwq: [256]?*PoolWorkqueue,
};

pub const WorkqueueAttrs = struct {
    nice: i32,
    cpumask: [256]bool,
    no_numa: bool,
    ordered: bool,
    affn_scope: WorkqueueAffinityScope,
    affn_strict: bool,
};

pub const WorkqueueAffinityScope = enum(u8) {
    Cpu = 0,
    Smt = 1,
    Cache = 2,
    Numa = 3,
    System = 4,
};

pub const PoolWorkqueue = struct {
    pool: ?*WorkerPool,
    wq: ?*WorkqueueStruct,
    work_color: i32,
    flush_color: i32,
    max_active: i32,
    nr_in_flight: [16]i32,
    nr_active: i32,
    refcnt: i32,
    nr_demoted: i32,
};

pub const WorkerPool = struct {
    id: i32,
    cpu: i32,
    node: i32,
    flags: u32,
    nr_workers: u32,
    nr_idle: u32,
    nr_running: i32,
    watchdog_ts: u64,
    manager_arb: u64,
    idle_list: u64,
    busy_hash: [64]u64,
    attrs: ?*WorkqueueAttrs,
};

pub const WorkStruct = struct {
    data: u64,
    entry_next: ?*WorkStruct,
    entry_prev: ?*WorkStruct,
    func: ?*const fn (work: *WorkStruct) callconv(.C) void,
};

pub const DelayedWorkStruct = struct {
    work: WorkStruct,
    timer_expires: u64,
    wq: ?*WorkqueueStruct,
    cpu: i32,
};

// ============================================================================
// Preempt Notifiers
// ============================================================================

pub const PreemptNotifier = struct {
    ops: ?*PreemptOps,
    link_next: ?*PreemptNotifier,
    link_prev: ?*PreemptNotifier,
};

pub const PreemptOps = struct {
    sched_in: ?*const fn (notifier: *PreemptNotifier, cpu: i32) callconv(.C) void,
    sched_out: ?*const fn (notifier: *PreemptNotifier, next: *anyopaque) callconv(.C) void,
};

// ============================================================================
// Manager
// ============================================================================

pub const RadixPercpuRcuManager = struct {
    total_radix_entries: u64,
    total_percpu_allocs: u64,
    total_rcu_gps: u64,
    total_rcu_callbacks: u64,
    total_srcu_gps: u64,
    total_workqueue_jobs: u64,
    initialized: bool,

    pub fn init() RadixPercpuRcuManager {
        return .{
            .total_radix_entries = 0,
            .total_percpu_allocs = 0,
            .total_rcu_gps = 0,
            .total_rcu_callbacks = 0,
            .total_srcu_gps = 0,
            .total_workqueue_jobs = 0,
            .initialized = true,
        };
    }
};
