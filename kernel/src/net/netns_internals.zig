// Zxyphor Kernel - Network Namespace Internals
// Network namespaces: creation, proc entries, sysctl, device migration
// Loopback per-ns, routing tables per-ns, iptables per-ns
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Network Namespace Core
// ============================================================================

pub const NetNsFlags = packed struct(u32) {
    user_ns: bool = false,
    loopback: bool = false,
    proc_net: bool = false,
    sysctl: bool = false,
    ipv4_ready: bool = false,
    ipv6_ready: bool = false,
    nf_ready: bool = false,
    xfrm_ready: bool = false,
    can_change: bool = false,
    _pad: u23 = 0,
};

pub const NetNs = struct {
    // Identity
    ns_id: u32,
    inum: u64,         // inode number for nsfs
    user_ns: u64,      // owning user namespace
    // Reference counting
    count: u64,        // active references
    passive: u64,      // passive references
    // Core networking
    loopback_dev: u64, // lo device
    rules_mod: u64,    // fib rules
    // IPv4
    ipv4: NetNsIpv4,
    // IPv6
    ipv6: NetNsIpv6,
    // Netfilter
    nf: NetNsNf,
    // XFRM / IPsec
    xfrm: NetNsXfrm,
    // proc/sys/net
    proc_net: u64,
    proc_net_stat: u64,
    // Sysctl
    sysctl_hdr: u64,
    // Network devices
    dev_base_head: u64,
    dev_name_head: u64,
    dev_index_head: u64,
    dev_count: u32,
    // Packet types
    ptype_all: u64,
    ptype_specific: u64,
    // Flags
    flags: NetNsFlags,
    // Genetlink
    genl_sock: u64,
    // Diag
    diag_nlsk: u64,
    // Statistics
    stats: NetNsStats,
    // Network namespace IDs
    nsid_lock: u64,
    peer_ns_count: u32,
};

// ============================================================================
// Per-NS IPv4 Configuration
// ============================================================================

pub const NetNsIpv4 = struct {
    // Forwarding
    ip_forward: bool,
    ip_forward_use_pmtu: bool,
    ip_forward_update_priority: bool,
    // FIB
    fib_table_hash: u64,
    fib_table_count: u32,
    fib_default: u64,
    // Route cache / FIB trie
    fib_trie: u64,
    fib_trie_stats: FibTrieStats,
    // Sysctl tuning
    sysctl_ip_default_ttl: u8,
    sysctl_ip_no_pmtu_disc: bool,
    sysctl_ip_fwd_use_pmtu: bool,
    sysctl_ip_nonlocal_bind: bool,
    sysctl_ip_dynaddr: bool,
    sysctl_ip_early_demux: bool,
    sysctl_raw_l3mdev_accept: bool,
    sysctl_tcp_l3mdev_accept: bool,
    sysctl_udp_l3mdev_accept: bool,
    // Fragment
    fqdir: u64,
    frags_max: u32,
    frags_timeout: u32,
    frags_secret_interval: u32,
    // TCP
    tcp_death_row: u64,
    tcp_sk: u64,
    sysctl_tcp_mem: [3]u64,
    sysctl_tcp_rmem: [3]u32,
    sysctl_tcp_wmem: [3]u32,
    sysctl_tcp_timestamps: bool,
    sysctl_tcp_window_scaling: bool,
    sysctl_tcp_sack: bool,
    sysctl_tcp_dsack: bool,
    sysctl_tcp_ecn: u8,
    sysctl_tcp_ecn_fallback: bool,
    sysctl_tcp_fin_timeout: u32,
    sysctl_tcp_keepalive_time: u32,
    sysctl_tcp_keepalive_probes: u32,
    sysctl_tcp_keepalive_intvl: u32,
    sysctl_tcp_synack_retries: u8,
    sysctl_tcp_syn_retries: u8,
    sysctl_tcp_max_syn_backlog: u32,
    sysctl_tcp_max_tw_buckets: u32,
    sysctl_tcp_tw_reuse: u8,
    sysctl_tcp_abort_on_overflow: bool,
    sysctl_tcp_fastopen: u32,
    sysctl_tcp_mtu_probing: u8,
    sysctl_tcp_base_mss: u32,
    sysctl_tcp_min_snd_mss: u32,
    sysctl_tcp_probe_threshold: u32,
    sysctl_tcp_probe_interval: u32,
    // UDP
    sysctl_udp_mem: [3]u64,
    sysctl_udp_rmem: [3]u32,
    sysctl_udp_wmem: [3]u32,
    // ICMP
    sysctl_icmp_echo_ignore_all: bool,
    sysctl_icmp_echo_ignore_broadcasts: bool,
    sysctl_icmp_ignore_bogus_error_responses: bool,
    sysctl_icmp_ratelimit: u32,
    sysctl_icmp_ratemask: u32,
    // IGMP
    igmp_max_memberships: u32,
    igmp_max_msf: u32,
    igmp_qrv: u32,
    // ARP
    sysctl_arp_max_retries: u8,
    // Conntrack
    ct_net: u64,
    // Ping
    ping_group_range: [2]u32,
};

pub const FibTrieStats = struct {
    gets: u64,
    backtrack: u64,
    semantic_match_passed: u64,
    semantic_match_miss: u64,
    null_node_hit: u64,
    trie_nodes: u64,
    trie_leaves: u64,
    prefixes: u64,
};

// ============================================================================
// Per-NS IPv6 Configuration
// ============================================================================

pub const NetNsIpv6 = struct {
    // Sysctl
    sysctl_ipv6_devconf_all: u64,
    sysctl_ipv6_devconf_dflt: u64,
    // Forwarding
    ip6_fwd_enabled: bool,
    // FIB6
    fib6_table_hash: u64,
    fib6_main_tbl: u64,
    fib6_local_tbl: u64,
    fib6_rules_ops: u64,
    fib6_node_count: u64,
    fib6_rt_count: u64,
    // Fragmentation
    ip6_fqdir: u64,
    ip6_frags_max: u32,
    ip6_frags_timeout: u32,
    // Sysctl
    sysctl_mld_max_msf: u32,
    sysctl_mld_qrv: u32,
    sysctl_flowlabel_consistency: bool,
    sysctl_auto_flowlabels: u8,
    sysctl_flowlabel_state_ranges: bool,
    sysctl_segment_routing_hmac_policy: u8,
    sysctl_fib_multipath_hash_policy: u8,
    sysctl_seg6_flowlabel: u8,
    sysctl_ioam6_id: u32,
    sysctl_ioam6_id_wide: u64,
    sysctl_calipso: u8,
    // Anycast
    anycast_src_echo_reply: bool,
    // Route info
    ip6_rt_gc_expire: u64,
    ip6_rt_gc_min_interval: u64,
    ip6_rt_gc_timeout: u64,
    ip6_rt_gc_interval: u64,
    ip6_rt_gc_elasticity: u32,
    ip6_rt_mtu_expires: u32,
    ip6_rt_min_advmss: u32,
    ip6_rt_gc_thresh: u32,
};

// ============================================================================
// Per-NS Netfilter
// ============================================================================

pub const NetNsNf = struct {
    // Connection tracking
    ct_count: u64,
    ct_max: u64,
    ct_gen_id: u32,
    ct_htable_size: u32,
    ct_expect_count: u32,
    ct_expect_max: u32,
    // Tables (iptables/nftables)
    nf_tables_count: u32,
    nft_chain_count: u32,
    nft_rule_count: u32,
    nft_set_count: u32,
    // Hooks
    hooks_ipv4: [5]u64,   // NF_INET_* hooks
    hooks_ipv6: [5]u64,
    hooks_arp: [3]u64,
    hooks_bridge: [5]u64,
    // Log
    nf_log_default: [12]u8,
    // NAT
    nat_htable: u64,
    nat_bysource: u64,
    nat_used: u64,
    // Queue
    nf_queue_handler: u64,
    // Stats
    nf_stats: NfStats,
};

pub const NfStats = struct {
    packets_seen: u64,
    packets_accepted: u64,
    packets_dropped: u64,
    packets_stolen: u64,
    packets_queued: u64,
    ct_new: u64,
    ct_established: u64,
    ct_invalid: u64,
    ct_expect_new: u64,
    nat_translations: u64,
};

// ============================================================================
// Per-NS XFRM (IPsec)
// ============================================================================

pub const NetNsXfrm = struct {
    state_hash_generation: u32,
    state_num: u32,
    state_bydst: u64,
    state_bysrc: u64,
    state_byspi: u64,
    state_hmask: u32,
    policy_count: [6]u32,  // per direction (in/out/fwd) * (v4/v6)
    policy_default: [3]u8, // per direction
    sysctl_aevent_etime: u32,
    sysctl_aevent_rseqth: u32,
    sysctl_larval_drop: bool,
    sysctl_acq_expires: u32,
};

// ============================================================================
// Device Migration Between Namespaces
// ============================================================================

pub const NetDevMigration = struct {
    dev_ifindex: u32,
    dev_name: [16]u8,
    src_ns: u64,       // source netns
    dst_ns: u64,       // destination netns
    // State during migration
    state: MigrationState,
    // Address preservation
    preserve_addrs: bool,
    // Error handling
    error_code: i32,
};

pub const MigrationState = enum(u8) {
    idle = 0,
    preparing = 1,
    detaching = 2,
    attaching = 3,
    complete = 4,
    error = 5,
};

// ============================================================================
// Proc/Net Entries Per Namespace
// ============================================================================

pub const ProcNetEntries = struct {
    // /proc/net/ standard entries per ns
    tcp: bool,
    tcp6: bool,
    udp: bool,
    udp6: bool,
    raw: bool,
    raw6: bool,
    unix: bool,
    netstat: bool,
    snmp: bool,
    snmp6: bool,
    sockstat: bool,
    sockstat6: bool,
    dev: bool,
    wireless: bool,
    arp: bool,
    route: bool,
    ipv6_route: bool,
    if_inet6: bool,
    igmp: bool,
    igmp6: bool,
    mcfilter: bool,
    mcfilter6: bool,
    anycast6: bool,
    protocols: bool,
    ptype: bool,
    softnet_stat: bool,
    fib_trie: bool,
    fib_triestat: bool,
    rt_cache: bool,
    nf_conntrack: bool,
    nf_conntrack_expect: bool,
    ip_tables_names: bool,
    ip6_tables_names: bool,
    xfrm_stat: bool,
    // Custom entries
    custom_count: u32,
};

// ============================================================================
// Per-NS Sysctl
// ============================================================================

pub const NetNsSysctl = struct {
    // Core
    core_somaxconn: u32,
    core_netdev_budget: u32,
    core_netdev_budget_usecs: u32,
    core_rmem_default: u32,
    core_rmem_max: u32,
    core_wmem_default: u32,
    core_wmem_max: u32,
    core_optmem_max: u32,
    core_txqueuelen: u32,
    core_dev_weight: u32,
    core_bpf_jit_enable: u8,
    core_bpf_jit_harden: u8,
    core_bpf_jit_kallsyms: bool,
    core_bpf_jit_limit: u64,
    // GRO
    gro_normal_batch: u32,
    // Busy Poll
    busy_read: u32,
    busy_poll: u32,
    // Netdev tstamp
    tstamp_allow_data: bool,
};

// ============================================================================
// NSID (Network Namespace ID) Management
// ============================================================================

pub const NsidEntry = struct {
    net: u64,       // net *
    peer_net: u64,  // net *
    nsid: i32,      // assigned ID (-1 = not assigned)
};

pub const NsidManager = struct {
    next_nsid: u32,
    allocated: u32,
    max_nsid: u32,
    generation: u64,
};

// ============================================================================
// Network Namespace Stats
// ============================================================================

pub const NetNsStats = struct {
    devices: u64,
    ipv4_routes: u64,
    ipv6_routes: u64,
    conntrack_entries: u64,
    nft_rules: u64,
    xfrm_states: u64,
    xfrm_policies: u64,
    unix_sockets: u64,
    tcp_sockets: u64,
    udp_sockets: u64,
    raw_sockets: u64,
    // Memory
    memory_used: u64,
    sk_alloc: u64,
    sk_free: u64,
    // Packets
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_drops: u64,
    tx_drops: u64,
    // Time
    created_ns: u64,
    lifetime_ns: u64,
};

// ============================================================================
// Network Namespace Manager
// ============================================================================

pub const NetNsManager = struct {
    active_ns: u32,
    total_ns_created: u64,
    total_ns_destroyed: u64,
    total_devices_migrated: u64,
    max_ns: u32,
    default_ns: u64,
    // ID tracking
    nsid_manager: NsidManager,
    // Memory
    total_memory: u64,
    // Limits
    max_devices_per_ns: u32,
    max_routes_per_ns: u32,
    max_ct_per_ns: u32,
    initialized: bool,

    pub fn init() NetNsManager {
        return NetNsManager{
            .active_ns = 1,     // init_net
            .total_ns_created = 1,
            .total_ns_destroyed = 0,
            .total_devices_migrated = 0,
            .max_ns = 4096,
            .default_ns = 0,
            .nsid_manager = NsidManager{
                .next_nsid = 0,
                .allocated = 0,
                .max_nsid = 0x7FFFFFFF,
                .generation = 0,
            },
            .total_memory = 0,
            .max_devices_per_ns = 1024,
            .max_routes_per_ns = 1048576,
            .max_ct_per_ns = 262144,
            .initialized = true,
        };
    }
};
