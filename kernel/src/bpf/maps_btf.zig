// SPDX-License-Identifier: MIT
// Zxyphor Kernel - BPF Maps, BPF Helpers, BTF (BPF Type Format),
// BPF Ringbuffer, BPF Bloom Filter, BPF Local Storage
// More advanced than Linux 2026 BPF subsystem

const std = @import("std");

// ============================================================================
// BPF Map Types
// ============================================================================

/// BPF map type
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
    cgroup_storage = 19,
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
    // Zxyphor
    zxy_adaptive_hash = 200,
    zxy_persistent = 201,
    zxy_tiered = 202,
};

/// BPF map flags
pub const BpfMapFlags = packed struct {
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
    segcnt_elems: bool = false,
    // Zxyphor
    zxy_compressed: bool = false,
    zxy_encrypted: bool = false,
    _padding: u12 = 0,
};

/// BPF map info
pub const BpfMapInfo = struct {
    map_type: BpfMapType,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: BpfMapFlags,
    name: [16]u8,
    ifindex: u32,              // For offloaded maps
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    map_extra: u64,
};

// ============================================================================
// BPF Helpers
// ============================================================================

/// BPF helper function IDs
pub const BpfFunc = enum(u32) {
    unspec = 0,
    map_lookup_elem = 1,
    map_update_elem = 2,
    map_delete_elem = 3,
    probe_read = 4,
    ktime_get_ns = 5,
    trace_printk = 6,
    get_prandom_u32 = 7,
    get_smp_processor_id = 8,
    skb_store_bytes = 9,
    l3_csum_replace = 10,
    l4_csum_replace = 11,
    tail_call = 12,
    clone_redirect = 13,
    get_current_pid_tgid = 14,
    get_current_uid_gid = 15,
    get_current_comm = 16,
    get_cgroup_classid = 17,
    skb_vlan_push = 18,
    skb_vlan_pop = 19,
    skb_get_tunnel_key = 20,
    skb_set_tunnel_key = 21,
    perf_event_read = 22,
    redirect = 23,
    get_route_realm = 24,
    perf_event_output = 25,
    skb_load_bytes = 26,
    get_stackid = 27,
    csum_diff = 28,
    skb_get_tunnel_opt = 29,
    skb_set_tunnel_opt = 30,
    skb_change_proto = 31,
    skb_change_type = 32,
    skb_under_cgroup = 33,
    get_hash_recalc = 34,
    get_current_task = 35,
    probe_write_user = 36,
    current_task_under_cgroup = 37,
    skb_change_tail = 38,
    skb_pull_data = 39,
    csum_update = 40,
    set_hash_invalid = 41,
    get_numa_node_id = 42,
    skb_change_head = 43,
    xdp_adjust_head = 44,
    probe_read_str = 45,
    get_socket_cookie = 46,
    get_socket_uid = 47,
    set_hash = 48,
    setsockopt = 49,
    skb_adjust_room = 50,
    redirect_map = 51,
    sk_redirect_map = 52,
    sock_map_update = 53,
    xdp_adjust_meta = 54,
    perf_event_read_value = 55,
    perf_prog_read_value = 56,
    getsockopt = 57,
    override_return = 58,
    sock_ops_cb_flags_set = 59,
    msg_redirect_map = 60,
    msg_apply_bytes = 61,
    msg_cork_bytes = 62,
    msg_pull_data = 63,
    bind = 64,
    xdp_adjust_tail = 65,
    skb_get_xfrm_state = 66,
    get_stack = 67,
    skb_load_bytes_relative = 68,
    fib_lookup = 69,
    sock_hash_update = 70,
    msg_redirect_hash = 71,
    sk_redirect_hash = 72,
    lwt_push_encap = 73,
    lwt_seg6_store_bytes = 74,
    lwt_seg6_adjust_srh = 75,
    lwt_seg6_action = 76,
    rc_repeat = 77,
    rc_keydown = 78,
    skb_cgroup_id = 79,
    get_current_cgroup_id = 80,
    get_local_storage = 81,
    sk_select_reuseport = 82,
    skb_ancestor_cgroup_id = 83,
    sk_lookup_tcp = 84,
    sk_lookup_udp = 85,
    sk_release = 86,
    map_push_elem = 87,
    map_pop_elem = 88,
    map_peek_elem = 89,
    msg_push_data = 90,
    msg_pop_data = 91,
    rc_pointer_rel = 92,
    spin_lock = 93,
    spin_unlock = 94,
    sk_fullsock = 95,
    tcp_sock = 96,
    skb_ecn_set_ce = 97,
    get_listener_sock = 98,
    skc_lookup_tcp = 99,
    tcp_check_syncookie = 100,
    sysctl_get_name = 101,
    sysctl_get_current_value = 102,
    sysctl_get_new_value = 103,
    sysctl_set_new_value = 104,
    strtol = 105,
    strtoul = 106,
    sk_storage_get = 107,
    sk_storage_delete = 108,
    send_signal = 109,
    tcp_gen_syncookie = 110,
    skb_output = 111,
    probe_read_user = 112,
    probe_read_kernel = 113,
    probe_read_user_str = 114,
    probe_read_kernel_str = 115,
    tcp_send_ack = 116,
    send_signal_thread = 117,
    jiffies64 = 118,
    read_branch_records = 119,
    get_ns_current_pid_tgid = 120,
    xdp_output = 121,
    get_netns_cookie = 122,
    get_current_ancestor_cgroup_id = 123,
    sk_assign = 124,
    ktime_get_boot_ns = 125,
    seq_printf = 126,
    seq_write = 127,
    sk_cgroup_id = 128,
    sk_ancestor_cgroup_id = 129,
    ringbuf_output = 130,
    ringbuf_reserve = 131,
    ringbuf_submit = 132,
    ringbuf_discard = 133,
    ringbuf_query = 134,
    csum_level = 135,
    skc_to_tcp6_sock = 136,
    skc_to_tcp_sock = 137,
    skc_to_tcp_timewait_sock = 138,
    skc_to_tcp_request_sock = 139,
    skc_to_udp6_sock = 140,
    get_task_stack = 141,
    load_hdr_opt = 142,
    store_hdr_opt = 143,
    reserve_hdr_opt = 144,
    inode_storage_get = 145,
    inode_storage_delete = 146,
    d_path = 147,
    copy_from_user = 148,
    snprintf_btf = 149,
    seq_printf_btf = 150,
    skb_cgroup_classid = 151,
    redirect_neigh = 152,
    per_cpu_ptr = 153,
    this_cpu_ptr = 154,
    redirect_peer = 155,
    task_storage_get = 156,
    task_storage_delete = 157,
    get_current_task_btf = 158,
    bprm_opts_set = 159,
    ktime_get_coarse_ns = 160,
    ima_inode_hash = 161,
    sock_from_file = 162,
    check_mtu = 163,
    for_each_map_elem = 164,
    snprintf = 165,
    sys_bpf = 166,
    btf_find_by_name_kind = 167,
    sys_close = 168,
    timer_init = 169,
    timer_set_callback = 170,
    timer_start = 171,
    timer_cancel = 172,
    get_func_ip = 173,
    get_attach_cookie = 174,
    task_pt_regs = 175,
    get_branch_snapshot = 176,
    trace_vprintk = 177,
    skc_to_unix_sock = 178,
    kallsyms_lookup_name = 179,
    find_vma = 180,
    loop = 181,
    strncmp = 182,
    get_func_arg = 183,
    get_func_ret = 184,
    get_func_arg_cnt = 185,
    get_retval = 186,
    set_retval = 187,
    xdp_get_buff_len = 188,
    xdp_load_bytes = 189,
    xdp_store_bytes = 190,
    copy_from_user_task = 191,
    skb_set_tstamp = 192,
    ima_file_hash = 193,
    kptr_xchg = 194,
    map_lookup_percpu_elem = 195,
    skc_to_mptcp_sock = 196,
    dynptr_from_mem = 197,
    ringbuf_reserve_dynptr = 198,
    ringbuf_submit_dynptr = 199,
    ringbuf_discard_dynptr = 200,
    dynptr_read = 201,
    dynptr_write = 202,
    dynptr_data = 203,
    tcp_raw_gen_syncookie_ipv4 = 204,
    tcp_raw_gen_syncookie_ipv6 = 205,
    tcp_raw_check_syncookie_ipv4 = 206,
    tcp_raw_check_syncookie_ipv6 = 207,
    ktime_get_tai_ns = 208,
    user_ringbuf_drain = 209,
    cgrp_storage_get = 210,
    cgrp_storage_delete = 211,
};

// ============================================================================
// BTF (BPF Type Format)
// ============================================================================

/// BTF magic number
pub const BTF_MAGIC: u16 = 0xEB9F;

/// BTF header
pub const BtfHeader = struct {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,
    // Offsets and lengths into the type/string sections
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
};

/// BTF kind
pub const BtfKind = enum(u5) {
    unknown = 0,
    int = 1,
    ptr = 2,
    array = 3,
    @"struct" = 4,
    @"union" = 5,
    @"enum" = 6,
    fwd = 7,
    typedef = 8,
    @"volatile" = 9,
    @"const" = 10,
    restrict = 11,
    func = 12,
    func_proto = 13,
    @"var" = 14,
    datasec = 15,
    float = 16,
    decl_tag = 17,
    type_tag = 18,
    @"enum64" = 19,
};

/// BTF type header (common fields)
pub const BtfType = struct {
    name_off: u32,
    info: u32,       // Contains vlen:16, kind:5, kind_flag:1, unused:10
    size_or_type: u32, // size for INT/STRUCT/UNION/ENUM/DATASEC/FLOAT
                       // type_id for PTR/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/VAR/DECL_TAG/TYPE_TAG
};

/// BTF INT encoding
pub const BtfIntInfo = packed struct {
    bits: u8,
    offset: u8,
    encoding: u4,
    _reserved: u12,
};

/// BTF INT encoding flags
pub const BTF_INT_SIGNED: u4 = 1;
pub const BTF_INT_CHAR: u4 = 2;
pub const BTF_INT_BOOL: u4 = 4;

/// BTF ARRAY type
pub const BtfArray = struct {
    elem_type: u32,
    index_type: u32,
    nelems: u32,
};

/// BTF STRUCT/UNION member
pub const BtfMember = struct {
    name_off: u32,
    type_id: u32,
    offset: u32,      // Bit offset (or bitfield info with kind_flag)
};

/// BTF ENUM value
pub const BtfEnum = struct {
    name_off: u32,
    val: i32,
};

/// BTF ENUM64 value
pub const BtfEnum64 = struct {
    name_off: u32,
    val_lo32: u32,
    val_hi32: u32,
};

/// BTF FUNC_PROTO parameter
pub const BtfParam = struct {
    name_off: u32,
    type_id: u32,
};

/// BTF VAR info
pub const BtfVar = struct {
    linkage: u32,      // 0=static, 1=global
};

/// BTF DATASEC variable
pub const BtfVarSecinfo = struct {
    type_id: u32,
    offset: u32,
    size: u32,
};

/// BTF DECL_TAG attribute
pub const BtfDeclTag = struct {
    component_idx: i32,  // -1 for no component
};

// ============================================================================
// BPF Ring Buffer
// ============================================================================

/// BPF ringbuf header
pub const BpfRingbufHeader = struct {
    len: u32,           // Data length | BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT
};

/// Ring buffer flags
pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const BPF_RINGBUF_HDR_SZ: u32 = 8;

/// Ring buffer info
pub const BpfRingbufInfo = struct {
    size: u64,           // Must be power of 2
    consumer_pos: u64,   // Consumer position
    producer_pos: u64,   // Producer position
    // Stats
    total_records: u64,
    total_bytes: u64,
    total_drops: u64,
    total_discards: u64,
};

// ============================================================================
// BPF Bloom Filter
// ============================================================================

/// Bloom filter config
pub const BpfBloomFilterConfig = struct {
    nr_hash_funcs: u32,  // Number of hash functions (k)
    value_size: u32,
    max_entries: u32,     // ~= m/ln(2) where m is bits
    // Derived
    nr_bits: u64,
    false_positive_rate: f64,
};

// ============================================================================
// BPF Local Storage
// ============================================================================

/// BPF local storage type
pub const BpfLocalStorageType = enum(u8) {
    sk_storage = 0,
    inode_storage = 1,
    task_storage = 2,
    cgrp_storage = 3,
};

/// BPF local storage cache
pub const BpfLocalStorageCache = struct {
    storage_type: BpfLocalStorageType,
    nr_entries: u32,
    cache_hits: u64,
    cache_misses: u64,
};

// ============================================================================
// BPF Subsystem Manager
// ============================================================================

pub const BpfMapsSubsystem = struct {
    // Maps
    nr_maps: u32,
    nr_hash_maps: u32,
    nr_array_maps: u32,
    nr_ringbuf_maps: u32,
    nr_lru_maps: u32,
    nr_percpu_maps: u32,
    nr_sockmap_maps: u32,
    nr_bloom_filters: u32,
    nr_arena_maps: u32,
    // BTF
    nr_btf_objects: u32,
    total_btf_size: u64,
    // Storage
    nr_sk_storage: u32,
    nr_inode_storage: u32,
    nr_task_storage: u32,
    nr_cgrp_storage: u32,
    // Stats
    total_map_lookups: u64,
    total_map_updates: u64,
    total_map_deletes: u64,
    total_ringbuf_submits: u64,
    total_ringbuf_discards: u64,
    // Memory
    total_map_memory_bytes: u64,
    // Zxyphor
    zxy_adaptive_maps: bool,
    zxy_persistent_maps: bool,
    initialized: bool,

    pub fn init() BpfMapsSubsystem {
        return BpfMapsSubsystem{
            .nr_maps = 0,
            .nr_hash_maps = 0,
            .nr_array_maps = 0,
            .nr_ringbuf_maps = 0,
            .nr_lru_maps = 0,
            .nr_percpu_maps = 0,
            .nr_sockmap_maps = 0,
            .nr_bloom_filters = 0,
            .nr_arena_maps = 0,
            .nr_btf_objects = 0,
            .total_btf_size = 0,
            .nr_sk_storage = 0,
            .nr_inode_storage = 0,
            .nr_task_storage = 0,
            .nr_cgrp_storage = 0,
            .total_map_lookups = 0,
            .total_map_updates = 0,
            .total_map_deletes = 0,
            .total_ringbuf_submits = 0,
            .total_ringbuf_discards = 0,
            .total_map_memory_bytes = 0,
            .zxy_adaptive_maps = true,
            .zxy_persistent_maps = true,
            .initialized = false,
        };
    }
};
