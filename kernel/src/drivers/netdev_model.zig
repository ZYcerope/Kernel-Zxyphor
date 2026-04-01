// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Network driver model, ethtool, NAPI polling,
// netdev features, traffic control qdiscs, XPS/RPS, devlink,
// hardware offload, switchdev, MACsec offload
// More advanced than Linux 2026 netdev subsystem

const std = @import("std");

// ============================================================================
// Network Device Flags
// ============================================================================

pub const IFF_UP: u32 = 1 << 0;
pub const IFF_BROADCAST: u32 = 1 << 1;
pub const IFF_DEBUG: u32 = 1 << 2;
pub const IFF_LOOPBACK: u32 = 1 << 3;
pub const IFF_POINTOPOINT: u32 = 1 << 4;
pub const IFF_NOTRAILERS: u32 = 1 << 5;
pub const IFF_RUNNING: u32 = 1 << 6;
pub const IFF_NOARP: u32 = 1 << 7;
pub const IFF_PROMISC: u32 = 1 << 8;
pub const IFF_ALLMULTI: u32 = 1 << 9;
pub const IFF_MASTER: u32 = 1 << 10;
pub const IFF_SLAVE: u32 = 1 << 11;
pub const IFF_MULTICAST: u32 = 1 << 12;
pub const IFF_PORTSEL: u32 = 1 << 13;
pub const IFF_AUTOMEDIA: u32 = 1 << 14;
pub const IFF_DYNAMIC: u32 = 1 << 15;
pub const IFF_LOWER_UP: u32 = 1 << 16;
pub const IFF_DORMANT: u32 = 1 << 17;
pub const IFF_ECHO: u32 = 1 << 18;

// Private flags
pub const IFF_802_1Q_VLAN: u32 = 1 << 0;
pub const IFF_EBRIDGE: u32 = 1 << 1;
pub const IFF_BONDING: u32 = 1 << 2;
pub const IFF_ISATAP: u32 = 1 << 3;
pub const IFF_WAN_HDLC: u32 = 1 << 4;
pub const IFF_XMIT_DST_RELEASE: u32 = 1 << 5;
pub const IFF_DONT_BRIDGE: u32 = 1 << 6;
pub const IFF_DISABLE_NETPOLL: u32 = 1 << 7;
pub const IFF_MACVLAN_PORT: u32 = 1 << 8;
pub const IFF_BRIDGE_PORT: u32 = 1 << 9;
pub const IFF_OVS_DATAPATH: u32 = 1 << 10;
pub const IFF_TX_SKB_SHARING: u32 = 1 << 11;
pub const IFF_UNICAST_FLT: u32 = 1 << 12;
pub const IFF_TEAM_PORT: u32 = 1 << 13;
pub const IFF_SUPP_NOFCS: u32 = 1 << 14;
pub const IFF_LIVE_ADDR_CHANGE: u32 = 1 << 15;
pub const IFF_MACVLAN: u32 = 1 << 16;
pub const IFF_XMIT_DST_RELEASE_PERM: u32 = 1 << 17;
pub const IFF_L3MDEV_MASTER: u32 = 1 << 18;
pub const IFF_NO_QUEUE: u32 = 1 << 19;
pub const IFF_OPENVSWITCH: u32 = 1 << 20;
pub const IFF_L3MDEV_SLAVE: u32 = 1 << 21;
pub const IFF_TEAM: u32 = 1 << 22;
pub const IFF_RXFH_CONFIGURED: u32 = 1 << 23;
pub const IFF_PHONY_HEADROOM: u32 = 1 << 24;
pub const IFF_MACSEC: u32 = 1 << 25;
pub const IFF_NO_RX_HANDLER: u32 = 1 << 26;
pub const IFF_FAILOVER: u32 = 1 << 27;
pub const IFF_FAILOVER_SLAVE: u32 = 1 << 28;
pub const IFF_L3MDEV_RX_HANDLER: u32 = 1 << 29;
pub const IFF_NO_ADDRCONF: u32 = 1 << 30;

// ============================================================================
// Network Device Features (NETIF_F_*)
// ============================================================================

pub const NetDevFeatures = packed struct(u64) {
    sg: bool = false,                    // Scatter/Gather
    ip_csum: bool = false,              // IP TX checksum offload
    no_csum: bool = false,              // No TX checksum needed
    hw_csum: bool = false,             // HW TX checksum (all protocols)
    ipv6_csum: bool = false,
    highdma: bool = false,             // Can DMA to high memory
    fraglist: bool = false,
    hw_vlan_ctag_tx: bool = false,     // VLAN C-tag TX offload
    hw_vlan_ctag_rx: bool = false,     // VLAN C-tag RX offload
    hw_vlan_ctag_filter: bool = false,
    vlan_challenged: bool = false,
    gso: bool = false,                 // Generic Segmentation Offload
    lltx: bool = false,               // Lockless TX
    netns_local: bool = false,
    gro: bool = false,                 // Generic Receive Offload
    gro_hw: bool = false,             // Hardware GRO
    lro: bool = false,                 // Large Receive Offload
    tso: bool = false,                 // TCP Segmentation Offload
    tso6: bool = false,               // TCPv6 Segmentation Offload
    tso_ecn: bool = false,
    tso_mangleid: bool = false,
    gso_sctp: bool = false,
    gso_udp_tunnel: bool = false,
    gso_gre: bool = false,
    gso_partial: bool = false,
    gso_tunnel_remcsum: bool = false,
    gso_esp: bool = false,
    gso_udp: bool = false,
    gso_udp_l4: bool = false,
    gso_fraglist: bool = false,
    fcoe_crc: bool = false,
    sctp_crc: bool = false,
    rxhash: bool = false,             // RX hash (for RSS)
    rxcsum: bool = false,             // RX checksum offload
    unicast_filter: bool = false,
    ntuple: bool = false,             // N-tuple filters
    rx_gro_list: bool = false,
    rx_udp_gro_forwarding: bool = false,
    hw_tls_tx: bool = false,          // HW TLS TX offload
    hw_tls_rx: bool = false,          // HW TLS RX offload
    rx_gro_hw: bool = false,
    hw_tc: bool = false,              // HW Traffic Control
    esp_offload: bool = false,
    loopback: bool = false,
    hw_macsec: bool = false,          // HW MACsec offload
    // Zxyphor
    zxy_zero_copy_tx: bool = false,
    zxy_zero_copy_rx: bool = false,
    zxy_hw_crypto: bool = false,
    _reserved: u17 = 0,
};

// ============================================================================
// Link Speed / Duplex
// ============================================================================

pub const LinkSpeed = enum(u32) {
    speed_10 = 10,
    speed_100 = 100,
    speed_1000 = 1000,        // 1 Gbps
    speed_2500 = 2500,        // 2.5 Gbps
    speed_5000 = 5000,        // 5 Gbps
    speed_10000 = 10000,      // 10 Gbps
    speed_14000 = 14000,      // 14 Gbps (FDR)
    speed_20000 = 20000,      // 20 Gbps
    speed_25000 = 25000,      // 25 Gbps
    speed_40000 = 40000,      // 40 Gbps
    speed_50000 = 50000,      // 50 Gbps
    speed_56000 = 56000,      // 56 Gbps (FDR)
    speed_100000 = 100000,    // 100 Gbps
    speed_200000 = 200000,    // 200 Gbps
    speed_400000 = 400000,    // 400 Gbps
    speed_800000 = 800000,    // 800 Gbps
    speed_unknown = 0xFFFFFFFF,
    _,
};

pub const LinkDuplex = enum(u8) {
    half = 0,
    full = 1,
    unknown = 0xFF,
};

// ============================================================================
// Ethtool Link Modes
// ============================================================================

pub const EthtoolLinkMode = packed struct(u128) {
    // 10 Mbps
    base_10_t_half: bool = false,
    base_10_t_full: bool = false,
    // 100 Mbps
    base_100_t_half: bool = false,
    base_100_t_full: bool = false,
    // 1 Gbps
    base_1000_t_half: bool = false,
    base_1000_t_full: bool = false,
    base_1000_kx_full: bool = false,
    // 2.5 Gbps
    base_2500_t_full: bool = false,
    // 5 Gbps
    base_5000_t_full: bool = false,
    // 10 Gbps
    base_10000_t_full: bool = false,
    base_10000_kr_full: bool = false,
    base_10000_kx4_full: bool = false,
    base_10000_sr_full: bool = false,
    base_10000_lr_full: bool = false,
    base_10000_er_full: bool = false,
    base_10000_cr_full: bool = false,
    // 25 Gbps
    base_25000_cr_full: bool = false,
    base_25000_kr_full: bool = false,
    base_25000_sr_full: bool = false,
    // 40 Gbps
    base_40000_cr4_full: bool = false,
    base_40000_kr4_full: bool = false,
    base_40000_sr4_full: bool = false,
    base_40000_lr4_full: bool = false,
    // 50 Gbps
    base_50000_cr2_full: bool = false,
    base_50000_kr2_full: bool = false,
    base_50000_sr2_full: bool = false,
    base_50000_kr_full: bool = false,
    base_50000_sr_full: bool = false,
    base_50000_cr_full: bool = false,
    // 100 Gbps
    base_100000_cr4_full: bool = false,
    base_100000_kr4_full: bool = false,
    base_100000_sr4_full: bool = false,
    base_100000_cr2_full: bool = false,
    base_100000_kr2_full: bool = false,
    base_100000_sr2_full: bool = false,
    base_100000_lr4_full: bool = false,
    base_100000_cr_full: bool = false,
    base_100000_kr_full: bool = false,
    base_100000_sr_full: bool = false,
    // 200 Gbps
    base_200000_cr4_full: bool = false,
    base_200000_kr4_full: bool = false,
    base_200000_sr4_full: bool = false,
    base_200000_cr2_full: bool = false,
    base_200000_kr2_full: bool = false,
    base_200000_sr2_full: bool = false,
    // 400 Gbps
    base_400000_cr8_full: bool = false,
    base_400000_kr8_full: bool = false,
    base_400000_sr8_full: bool = false,
    base_400000_cr4_full: bool = false,
    base_400000_kr4_full: bool = false,
    base_400000_sr4_full: bool = false,
    base_400000_dr4_full: bool = false,
    base_400000_fr4_full: bool = false,
    // 800 Gbps
    base_800000_cr8_full: bool = false,
    base_800000_kr8_full: bool = false,
    base_800000_sr8_full: bool = false,
    base_800000_dr8_full: bool = false,
    // FEC modes (encoded in link modes)
    fec_none: bool = false,
    fec_rs: bool = false,
    fec_baser: bool = false,
    fec_llrs: bool = false,
    // Autoneg
    autoneg: bool = false,
    // Pause
    pause: bool = false,
    asym_pause: bool = false,
    _reserved: u66 = 0,
};

// ============================================================================
// Ethtool operations  
// ============================================================================

pub const EthtoolCmd = enum(u32) {
    get_settings = 0x00000001,
    set_settings = 0x00000002,
    get_drvinfo = 0x00000003,
    get_regs = 0x00000004,
    get_wol = 0x00000005,
    set_wol = 0x00000006,
    get_msglevel = 0x00000007,
    set_msglevel = 0x00000008,
    get_link = 0x0000000a,
    get_eeprom = 0x0000000b,
    set_eeprom = 0x0000000c,
    get_coalesce = 0x0000000e,
    set_coalesce = 0x0000000f,
    get_ringparam = 0x00000010,
    set_ringparam = 0x00000011,
    get_pauseparam = 0x00000012,
    set_pauseparam = 0x00000013,
    get_rx_csum = 0x00000014,
    get_tx_csum = 0x00000016,
    get_strings = 0x0000001b,
    get_stats = 0x0000001d,
    get_perm_addr = 0x00000020,
    get_sset_count = 0x00000025,
    get_rxnfc = 0x00000029,
    set_rxnfc = 0x0000002a,
    get_channels = 0x0000003c,
    set_channels = 0x0000003d,
    get_ts_info = 0x00000041,
    get_module_info = 0x00000042,
    get_module_eeprom = 0x00000043,
    get_eee = 0x00000044,
    set_eee = 0x00000045,
    get_fecparam = 0x00000050,
    set_fecparam = 0x00000051,
    _,
};

pub const EthtoolCoalesce = struct {
    rx_coalesce_usecs: u32,
    rx_max_coalesced_frames: u32,
    rx_coalesce_usecs_irq: u32,
    rx_max_coalesced_frames_irq: u32,
    tx_coalesce_usecs: u32,
    tx_max_coalesced_frames: u32,
    tx_coalesce_usecs_irq: u32,
    tx_max_coalesced_frames_irq: u32,
    stats_block_coalesce_usecs: u32,
    use_adaptive_rx_coalesce: bool,
    use_adaptive_tx_coalesce: bool,
    pkt_rate_low: u32,
    rx_coalesce_usecs_low: u32,
    tx_coalesce_usecs_low: u32,
    pkt_rate_high: u32,
    rx_coalesce_usecs_high: u32,
    tx_coalesce_usecs_high: u32,
    rate_sample_interval: u32,
    // Per-queue DIM (Dynamic Interrupt Moderation)
    cqe_mode_rx: bool,
    cqe_mode_tx: bool,
    tx_aggr_max_bytes: u32,
    tx_aggr_max_frames: u32,
    tx_aggr_time_usecs: u32,
};

pub const EthtoolRingparam = struct {
    rx_max_pending: u32,
    rx_mini_max_pending: u32,
    rx_jumbo_max_pending: u32,
    tx_max_pending: u32,
    rx_pending: u32,
    rx_mini_pending: u32,
    rx_jumbo_pending: u32,
    tx_pending: u32,
    // Header/data split
    rx_buf_len: u32,
    tcp_data_split: u8,        // 0=auto, 1=off, 2=on
    // CQE size
    cqe_size: u32,
    tx_push: bool,
    rx_push: bool,
    tx_push_buf_len: u32,
    tx_push_buf_len_max: u32,
};

pub const EthtoolChannels = struct {
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
};

// ============================================================================
// NAPI (New API) Polling
// ============================================================================

pub const NapiState = enum(u8) {
    idle = 0,
    sched = 1,           // Scheduled
    disable = 2,          // Disabled
    npsvc = 3,            // Netpoll service
    listed = 4,
    no_busy_poll = 5,
    in_busy_poll = 6,
    prefer_busy_poll = 7,
    threaded = 8,
};

pub const NapiStruct = struct {
    id: u32,
    // State
    state: NapiState,
    // Budget
    weight: i32,           // Default 64
    // Stats
    poll_count: u64,
    rx_count: u64,
    complete_count: u64,
    // Busy poll
    busy_poll_us: u32,
    busy_poll_budget: u32,
    // CPU affinity
    cpu: u16,
    // IRQ
    irq: u32,
    // GRO
    gro_count: u64,
    gro_hash_count: u32,
};

// ============================================================================
// Traffic Control (tc)
// ============================================================================

pub const TcQdiscType = enum(u8) {
    // Classless
    pfifo_fast = 0,        // Default
    fq = 1,                // Fair Queuing
    fq_codel = 2,          // Fair Queuing + CoDel
    sfq = 3,               // Stochastic Fair Queuing
    tbf = 4,               // Token Bucket Filter
    noqueue = 5,
    pfifo = 6,
    bfifo = 7,
    red = 8,               // Random Early Detection
    sfb = 9,
    cake = 10,             // Common Applications Kept Enhanced
    // Classful
    htb = 20,              // Hierarchy Token Bucket
    hfsc = 21,             // Hierarchical Fair Service Curve
    cbq = 22,              // Class Based Queuing
    drr = 23,              // Deficit Round Robin
    qfq = 24,              // Quick Fair Queuing
    prio = 25,             // Priority
    mqprio = 26,           // Multi-Queue Priority
    // Special
    ingress = 30,
    clsact = 31,           // Classifier/Action (BPF)
    mq = 32,               // Multi-queue
    // TSN (Time-Sensitive Networking)
    taprio = 40,           // Time-Aware Priority Shaper (IEEE 802.1Qbv)
    etf = 41,              // Earliest TxTime First
    // Zxyphor
    zxy_adaptive = 50,
};

// ============================================================================
// Network Statistics (RTNL)
// ============================================================================

pub const RtnlLinkStats64 = struct {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    multicast: u64,
    collisions: u64,
    // Detailed rx errors
    rx_length_errors: u64,
    rx_over_errors: u64,
    rx_crc_errors: u64,
    rx_frame_errors: u64,
    rx_fifo_errors: u64,
    rx_missed_errors: u64,
    // Detailed tx errors
    tx_aborted_errors: u64,
    tx_carrier_errors: u64,
    tx_fifo_errors: u64,
    tx_heartbeat_errors: u64,
    tx_window_errors: u64,
    // Compression
    rx_compressed: u64,
    tx_compressed: u64,
    // Other
    rx_nohandler: u64,
    rx_otherhost_dropped: u64,
};

// ============================================================================
// Net Device
// ============================================================================

pub const NetDevType = enum(u16) {
    ether = 1,             // Ethernet
    loopback = 772,
    sit = 776,             // SIT tunnel
    ipgre = 778,
    ipip = 768,
    tunnel6 = 769,
    vlan = 1,
    bridge = 1,
    bond = 1,
    team = 1,
    vxlan = 1,
    geneve = 1,
    wireguard = 65534,
    _,
};

pub const NetDevice = struct {
    // Identity
    name: [16]u8,
    ifindex: u32,
    dev_type: NetDevType,
    // MAC
    dev_addr: [6]u8,
    broadcast: [6]u8,
    addr_len: u8,
    // MTU
    mtu: u32,
    min_mtu: u32,
    max_mtu: u32,
    hard_header_len: u16,
    // Flags
    flags: u32,
    priv_flags: u32,
    features: NetDevFeatures,
    hw_features: NetDevFeatures,
    wanted_features: NetDevFeatures,
    vlan_features: NetDevFeatures,
    hw_enc_features: NetDevFeatures,
    mpls_features: NetDevFeatures,
    gso_max_size: u32,
    gso_max_segs: u16,
    gso_ipv4_max_size: u32,
    gro_max_size: u32,
    gro_ipv4_max_size: u32,
    tso_max_size: u32,
    tso_max_segs: u16,
    // Link
    speed: u32,
    duplex: LinkDuplex,
    link_up: bool,
    carrier: bool,
    // Queue
    num_tx_queues: u16,
    real_num_tx_queues: u16,
    num_rx_queues: u16,
    real_num_rx_queues: u16,
    tx_queue_len: u32,
    // NAPI
    nr_napi: u16,
    napi_budget: i32,
    // Watchdog
    watchdog_timeo_ms: u32,
    // Network namespace
    net_ns_id: i32,
    // Device state
    operstate: u8,        // IF_OPER_*
    link_mode: u8,
    // Group
    group: u32,
    // Master
    master_ifindex: u32,
    // NUMA node
    numa_node: i32,
    // Statistics
    stats: RtnlLinkStats64,
    // Per-CPU stats
    pcpu_refcnt: u32,
    // XPS/RPS
    xps_maps_valid: bool,
    rps_maps_valid: bool,
    // Timestamping
    hw_timestamping: bool,
    // TC
    qdisc_type: TcQdiscType,
    // Promiscuity
    promiscuity: u32,
    allmulti: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const NetdevSubsystem = struct {
    // Devices
    nr_netdevs: u32,
    nr_up: u32,
    nr_running: u32,
    // Types
    nr_ethernet: u32,
    nr_virtual: u32,
    nr_tunnel: u32,
    nr_bonding: u32,
    nr_bridge: u32,
    // Stats (aggregate)
    total_rx_packets: u64,
    total_tx_packets: u64,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_rx_errors: u64,
    total_tx_errors: u64,
    // NAPI
    total_napi_polls: u64,
    // ethtool
    total_ethtool_ops: u64,
    // TC
    nr_qdiscs: u32,
    nr_tc_filters: u32,
    // Offload
    nr_hw_offload_devs: u32,
    // Zxyphor
    zxy_zero_copy_enabled: bool,
    initialized: bool,
};
