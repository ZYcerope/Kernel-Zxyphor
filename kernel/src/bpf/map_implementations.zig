// Zxyphor Kernel - BPF Map Implementations Detail
// Hash maps, Array maps, LRU maps, LPM trie, Queue/Stack,
// Ringbuf, Bloom filter, cgroup storage, struct_ops,
// Map-in-Map, per-CPU variants, local storage
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// BPF Map Types (Complete)
// ============================================================================

pub const BpfMapType = enum(u32) {
    unspec = 0,
    hash = 1,
    array = 2,
    prog_array = 3,
    perf_event_array = 4,
    percpu_hash = 5,
    percpu_array = 6,
    stack_trace = 7,
    cgroup_array = 8,
    lru_hash = 9,
    lru_percpu_hash = 10,
    lpm_trie = 11,
    array_of_maps = 12,
    hash_of_maps = 13,
    devmap = 14,
    sockmap = 15,
    cpumap = 16,
    xskmap = 17,
    sockhash = 18,
    cgroup_storage_deprecated = 19,
    reuseport_sockarray = 20,
    percpu_cgroup_storage = 21,
    queue = 22,
    stack = 23,
    sk_storage = 24,
    devmap_hash = 25,
    struct_ops = 26,
    ringbuf = 27,
    inode_storage = 28,
    task_storage = 29,
    bloom_filter = 30,
    user_ringbuf = 31,
    cgrp_storage = 32,
    arena = 33,
};

// ============================================================================
// BPF Map Flags
// ============================================================================

pub const BpfMapCreateFlags = packed struct(u32) {
    no_prealloc: bool = false,
    no_common_lru: bool = false,
    numa_node: bool = false,
    rdonly: bool = false,
    wronly: bool = false,
    stack_build_id: bool = false,
    zero_seed: bool = false,
    rdonly_prog: bool = false,
    wronly_prog: bool = false,
    clone: bool = false,
    mmapable: bool = false,
    preserve_elems: bool = false,
    inner_map: bool = false,
    link: bool = false,
    path_fd: bool = false,
    vtype_btf_obj_fd: bool = false,
    token_fd: bool = false,
    segv_on_fault: bool = false,
    _pad: u14 = 0,
};

pub const BpfMapUpdateFlags = enum(u64) {
    any = 0,
    noexist = 1,
    exist = 2,
    f_lock = 4,
};

// ============================================================================
// BPF Map Core Structure
// ============================================================================

pub const BpfMap = struct {
    ops: ?*const BpfMapOps,
    map_type: BpfMapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    id: u32,
    name: [16]u8,
    // BTF info
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    btf: u64,              // struct btf *
    // Memory
    numa_node: i32,
    pages: u32,
    // Ownership
    owner_prog_type: u32,
    owner_jited: bool,
    // Refcount
    refcnt: u32,
    usercnt: u32,
    // Security
    frozen: bool,
    // Inner map (for map-in-map)
    inner_map_meta: ?*BpfMap,
    // Memory charge
    memory: BpfMapMemory,
    // Writecnt
    writecnt: i32,
    // Timer
    timer_off: u32,
    // Spin lock offset
    spin_lock_off: i32,
    // kptr offset
    kptr_off: [16]i32,
    kptr_cnt: u32,
};

pub const BpfMapMemory = struct {
    user: u64,
    pages: u64,
};

pub const BpfMapOps = struct {
    map_alloc_check: ?*const fn (*BpfMapAttr) i32,
    map_alloc: ?*const fn (*BpfMapAttr) ?*BpfMap,
    map_release: ?*const fn (*BpfMap, u64) void,
    map_free: ?*const fn (*BpfMap) void,
    map_get_next_key: ?*const fn (*BpfMap, ?*anyopaque, *anyopaque) i32,
    map_release_uref: ?*const fn (*BpfMap) void,
    map_lookup_elem_sys_only: ?*const fn (*BpfMap, *anyopaque) ?*anyopaque,
    map_lookup_batch: ?*const fn (*BpfMap, *BpfMapBatchAttr, u64) i32,
    map_lookup_and_delete_batch: ?*const fn (*BpfMap, *BpfMapBatchAttr, u64) i32,
    map_update_batch: ?*const fn (*BpfMap, u64, *BpfMapBatchAttr, u64) i32,
    map_delete_batch: ?*const fn (*BpfMap, *BpfMapBatchAttr, u64) i32,
    // BPF prog helpers
    map_lookup_elem: ?*const fn (*BpfMap, *anyopaque) ?*anyopaque,
    map_update_elem: ?*const fn (*BpfMap, *anyopaque, *anyopaque, u64) i64,
    map_delete_elem: ?*const fn (*BpfMap, *anyopaque) i64,
    map_push_elem: ?*const fn (*BpfMap, *anyopaque, u64) i64,
    map_pop_elem: ?*const fn (*BpfMap, *anyopaque) i64,
    map_peek_elem: ?*const fn (*BpfMap, *anyopaque) i64,
    map_lookup_percpu_elem: ?*const fn (*BpfMap, *anyopaque, u32) ?*anyopaque,
    // Iterator
    map_fd_get_ptr: ?*const fn (*BpfMap, u64, i32, u64) ?*anyopaque,
    map_fd_put_ptr: ?*const fn (*BpfMap, ?*anyopaque, bool) void,
    map_gen_lookup: ?*const fn (*BpfMap, *u64) u32,
    map_fd_sys_lookup_elem: ?*const fn (*anyopaque, *anyopaque) i32,
    map_seq_show_elem: ?*const fn (*BpfMap, *anyopaque, u64) void,
    map_check_btf: ?*const fn (*BpfMap, u64, u32, u32) i32,
    // Map freeze
    map_poke_track: ?*const fn (*BpfMap, u64) i32,
    map_poke_untrack: ?*const fn (*BpfMap, u64) void,
    map_poke_run: ?*const fn (*BpfMap, u32, u64, u64) void,
    // Direct value access
    map_direct_value_addr: ?*const fn (*BpfMap, *u64, u32) i32,
    map_direct_value_meta: ?*const fn (*BpfMap, u64, *u32) i32,
    // Mmap
    map_mmap: ?*const fn (*BpfMap, u64) i32,
    // Set frozen
    map_poll: ?*const fn (*BpfMap, u64) u32,
    // Local storage
    map_local_storage_charge: ?*const fn (u64, *anyopaque, u32) i32,
    map_local_storage_uncharge: ?*const fn (u64, *anyopaque, u32) void,
    // Mem usage
    map_mem_usage: ?*const fn (*BpfMap) u64,
};

pub const BpfMapAttr = struct {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [16]u8,
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
    value_type_btf_obj_fd: u32,
    map_token_fd: i32,
};

pub const BpfMapBatchAttr = struct {
    in_batch: u64,   // ptr start key
    out_batch: u64,  // ptr next key
    keys: u64,
    values: u64,
    count: u32,
    flags: u64,
};

// ============================================================================
// Hash Map Implementation Details
// ============================================================================

pub const BpfHtab = struct {
    map: BpfMap,
    buckets: u64,           // struct bucket *
    n_buckets: u32,
    elem_size: u32,
    hashrnd: u32,
    count: u64,             // percpu counter
    // LRU
    lru: ?*BpfLruList,
    // Prealloc
    elems: u64,
    extra_elems: u64,
    freelist: u64,
    // Lock
    lock_size: u32,
};

pub const HtabElem = struct {
    hash: u32,
    key: [256]u8,       // variable length
    // flags
    state: HtabElemState,
};

pub const HtabElemState = packed struct(u8) {
    deleted: bool = false,
    free: bool = false,
    lru: bool = false,
    _pad: u5 = 0,
};

// ============================================================================
// LRU Map Details
// ============================================================================

pub const BpfLruList = struct {
    lists: [3]BpfLruNode,  // active, inactive, free
    counts: [3]u32,
    next_inactive_rotation: u64,
    lock: u64,
};

pub const BpfLruNode = struct {
    next: ?*BpfLruNode,
    prev: ?*BpfLruNode,
    ref_count: u8,
    list_type: BpfLruListType,
};

pub const BpfLruListType = enum(u8) {
    active = 0,
    inactive = 1,
    free = 2,
};

pub const BpfCommonLru = struct {
    lru: BpfLruList,
    local_list: u64,    // percpu
};

// ============================================================================
// LPM Trie
// ============================================================================

pub const LpmTrieNode = struct {
    flags: u32,
    prefixlen: u32,
    child: [2]?*LpmTrieNode,
    value: u64,
    data: [256]u8,     // flexible
};

pub const LpmTrieKey = struct {
    prefixlen: u32,
    data: [256]u8,     // flexible
};

pub const LpmTrie = struct {
    map: BpfMap,
    root: ?*LpmTrieNode,
    n_entries: u64,
    data_size: u32,
    max_prefixlen: u32,
    lock: u64,         // raw_spinlock
};

// ============================================================================
// Ringbuf
// ============================================================================

pub const BpfRingbuf = struct {
    map: BpfMap,
    data: u64,         // data pages
    mask: u64,
    consumer_pos: u64,
    producer_pos: u64,
    pending_pos: u64,
    pages: u32,
    // Wait queue for readers
    waitq: u64,
    // Event fd
    irq_work: u64,
};

pub const BpfRingbufHdr = extern struct {
    len: u32,          // lower 28 bits = len, bit 29 = discard, bit 30 = busy, bit 31 = reserved
    pg_off: u32,
};

pub const RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const RINGBUF_HDR_SZ: u32 = 8;

// ============================================================================
// Bloom Filter
// ============================================================================

pub const BpfBloomFilter = struct {
    map: BpfMap,
    bitset_mask: u32,
    hash_seed: u32,
    nr_hash_funcs: u32,
    bitset: u64,       // u64 array
    aligned_u32_count: u32,
};

// ============================================================================
// Queue and Stack
// ============================================================================

pub const BpfQueue = struct {
    map: BpfMap,
    elements: u64,
    head: u32,
    tail: u32,
    count: u32,
    lock: u64,
};

pub const BpfStack = struct {
    map: BpfMap,
    elements: u64,
    top: i32,
    lock: u64,
};

// ============================================================================
// Array Map
// ============================================================================

pub const BpfArray = struct {
    map: BpfMap,
    elem_size: u32,
    index_mask: u32,
    value: u64,
    // Per-CPU
    pptrs: u64,        // for percpu_array
    // Owner
    owner_map_type: u32,
    owner_jited: bool,
};

// ============================================================================
// Prog Array (tail calls)
// ============================================================================

pub const BpfProgArray = struct {
    map: BpfMap,
    ptrs: u64,
    poke_tab: u64,     // for JIT tail call patching
    aux: u64,
};

// ============================================================================
// Stack Trace Map
// ============================================================================

pub const BpfStackMap = struct {
    map: BpfMap,
    elems: u64,
    n_buckets: u32,
    // Build ID mode
    build_id: bool,
};

pub const BpfStackBuildId = extern struct {
    status: i32,
    build_id: [20]u8,
    ip: u64,
};

pub const BPF_MAX_STACK_DEPTH: u32 = 127;

// ============================================================================
// DevMap / CpuMap / XskMap
// ============================================================================

pub const DevMapVal = extern struct {
    ifindex: u32,
    bpf_prog_fd: i32,
};

pub const CpuMapVal = extern struct {
    qsize: u32,
    bpf_prog_fd: i32,
};

pub const XskMapEntry = struct {
    xs: u64,  // xdp_sock *
    node: u64,
};

// ============================================================================
// SockMap / SockHash
// ============================================================================

pub const BpfSockMap = struct {
    map: BpfMap,
    stab: u64,         // sock_map_stab *
};

pub const BpfSockHash = struct {
    map: BpfMap,
    htab: u64,
    buckets: u64,
    elem_size: u32,
};

pub const SockMapLink = struct {
    attach_type: BpfAttachType,
    map: ?*BpfMap,
    prog: u64,
};

pub const BpfAttachType = enum(u32) {
    cgroup_inet_ingress = 0,
    cgroup_inet_egress = 1,
    cgroup_inet_sock_create = 2,
    cgroup_sock_ops = 3,
    sk_skb_stream_parser = 25,
    sk_skb_stream_verdict = 26,
    sk_msg_verdict = 27,
    sk_skb_verdict = 39,
    sk_reuseport_select = 43,
    sk_reuseport_select_or_migrate = 44,
    _,
};

// ============================================================================
// Local Storage (task, socket, inode, cgroup)
// ============================================================================

pub const BpfLocalStorageMap = struct {
    map: BpfMap,
    cache_idx: u32,
    bucket_log: u32,
    buckets: u64,
};

pub const BpfLocalStorageData = struct {
    smap: ?*BpfLocalStorageMap,
    data: u64,
    // Linked list node
    snode: u64,
    map_node: u64,
};

pub const BpfLocalStorage = struct {
    cache: [16]?*BpfLocalStorageData,
    list: u64,             // list_head
    owner: u64,
    lock: u64,
};

pub const BpfLocalStorageCache = struct {
    idx_lock: u64,
    idx_usage_counts: [16]u32,
};

// ============================================================================
// Struct Ops Map
// ============================================================================

pub const BpfStructOpsMap = struct {
    map: BpfMap,
    st_ops: ?*BpfStructOps,
    kvalue: u64,
    links: u64,
    image: u64,
    uvalue: u64,
};

pub const BpfStructOps = struct {
    verifier_ops: u64,
    init: ?*const fn (u64) i32,
    init_member: ?*const fn (u64, u32) i32,
    reg: ?*const fn (u64, u64) i32,
    unreg: ?*const fn (u64) void,
    check_member: ?*const fn (u64, u64) i32,
    name: [16]u8,
    cfi_stubs: u64,
    owner: u64,
};

// ============================================================================
// BPF Arena (6.9+)
// ============================================================================

pub const BpfArena = struct {
    map: BpfMap,
    user_vm_start: u64,
    user_vm_end: u64,
    kern_vm_start: u64,
    kern_vm_end: u64,
    // Page tracking
    page_cnt: u64,
    max_pages: u64,
    lock: u64,
};

// ============================================================================
// Perf Event Array
// ============================================================================

pub const BpfPerfEventArray = struct {
    map: BpfMap,
    pages: u64,
    // Per-CPU perf event buffer
    tailroom: u32,
};

pub const PerfEventOutputCtx = struct {
    regs: u64,
    data: u64,
    size: u64,
};

// ============================================================================
// Cgroup Storage
// ============================================================================

pub const BpfCgroupStorageKey = extern struct {
    cgroup_inode_id: u64,
    attach_type: u32,
    _pad: u32,
};

pub const BpfCgroupStorage = struct {
    map: ?*BpfMap,
    key: BpfCgroupStorageKey,
    buf: u64,
    node: u64,
};

// ============================================================================
// User Ringbuf
// ============================================================================

pub const BpfUserRingbuf = struct {
    map: BpfMap,
    consumer_pos: u64,
    producer_pos: u64,
    data: u64,
    mask: u64,
    pages: u32,
    epoll_waitq: u64,
};

// ============================================================================
// BPF Map Implementation Manager
// ============================================================================

pub const BpfMapImplManager = struct {
    total_maps: u64,
    maps_by_type: [34]u64,  // count per BpfMapType
    total_entries: u64,
    total_memory_pages: u64,
    hash_maps: u32,
    array_maps: u32,
    lru_maps: u32,
    ringbuf_maps: u32,
    lpm_trie_maps: u32,
    struct_ops_maps: u32,
    local_storage_maps: u32,
    arena_maps: u32,
    bloom_filter_maps: u32,
    // Memory
    total_allocated_bytes: u64,
    total_freed_bytes: u64,
    initialized: bool,

    pub fn init() BpfMapImplManager {
        return BpfMapImplManager{
            .total_maps = 0,
            .maps_by_type = [_]u64{0} ** 34,
            .total_entries = 0,
            .total_memory_pages = 0,
            .hash_maps = 0,
            .array_maps = 0,
            .lru_maps = 0,
            .ringbuf_maps = 0,
            .lpm_trie_maps = 0,
            .struct_ops_maps = 0,
            .local_storage_maps = 0,
            .arena_maps = 0,
            .bloom_filter_maps = 0,
            .total_allocated_bytes = 0,
            .total_freed_bytes = 0,
            .initialized = true,
        };
    }
};
