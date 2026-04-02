// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Netdev Internals / net_device Detail
// net_device complete structure, netdev_ops, ethtool_ops, NAPI, XPS, RPS,
// flow steering, tc qdisc hooks, netdev features, netdev notifier

const std = @import("std");

// ============================================================================
// Interface Flags (IFF_*)
// ============================================================================

pub const NetDevFlags = packed struct(u32) {
    up: bool = false,            // IFF_UP
    broadcast: bool = false,     // IFF_BROADCAST
    debug: bool = false,         // IFF_DEBUG
    loopback: bool = false,      // IFF_LOOPBACK
    pointopoint: bool = false,   // IFF_POINTOPOINT
    notrailers: bool = false,    // IFF_NOTRAILERS
    running: bool = false,       // IFF_RUNNING
    noarp: bool = false,         // IFF_NOARP
    promisc: bool = false,       // IFF_PROMISC
    allmulti: bool = false,      // IFF_ALLMULTI
    master: bool = false,        // IFF_MASTER
    slave: bool = false,         // IFF_SLAVE
    multicast: bool = false,     // IFF_MULTICAST
    portsel: bool = false,       // IFF_PORTSEL
    automedia: bool = false,     // IFF_AUTOMEDIA
    dynamic: bool = false,       // IFF_DYNAMIC
    lower_up: bool = false,      // IFF_LOWER_UP
    dormant: bool = false,       // IFF_DORMANT
    echo: bool = false,          // IFF_ECHO
    _pad: u13 = 0,
};

pub const NetDevPrivFlags = packed struct(u64) {
    vlan_challenged: bool = false,
    xmit_dst_release: bool = false,
    dont_bridge: bool = false,
    has_macvlan_port: bool = false,
    is_macvlan: bool = false,
    is_bridge_port: bool = false,
    is_ovs_port: bool = false,
    is_ovs_master: bool = false,
    has_team_port: bool = false,
    is_team: bool = false,
    is_bonding: bool = false,
    is_bonding_slave: bool = false,
    has_netprio: bool = false,
    has_switchdev: bool = false,
    is_l3_master: bool = false,
    is_l3_slave: bool = false,
    has_nft_flowtable: bool = false,
    has_xdp_offload: bool = false,
    _pad: u46 = 0,
};

// ============================================================================
// Netdev Features (NETIF_F_*)
// ============================================================================

pub const NetdevFeatures = packed struct(u64) {
    sg: bool = false,               // NETIF_F_SG
    ip_csum: bool = false,          // NETIF_F_IP_CSUM
    no_csum: bool = false,          // NETIF_F_NO_CSUM
    hw_csum: bool = false,          // NETIF_F_HW_CSUM
    ipv6_csum: bool = false,        // NETIF_F_IPV6_CSUM
    highdma: bool = false,          // NETIF_F_HIGHDMA
    fraglist: bool = false,         // NETIF_F_FRAGLIST
    hw_vlan_ctag_tx: bool = false,  // NETIF_F_HW_VLAN_CTAG_TX
    hw_vlan_ctag_rx: bool = false,  // NETIF_F_HW_VLAN_CTAG_RX
    hw_vlan_ctag_filter: bool = false,
    vlan_challenged: bool = false,
    gso: bool = false,              // NETIF_F_GSO
    lltx: bool = false,            // NETIF_F_LLTX
    netns_local: bool = false,
    gro: bool = false,              // NETIF_F_GRO
    gro_hw: bool = false,           // NETIF_F_GRO_HW
    lro: bool = false,              // NETIF_F_LRO
    tso: bool = false,              // NETIF_F_TSO
    ufo: bool = false,              // NETIF_F_UFO
    tso6: bool = false,             // NETIF_F_TSO6
    tso_ecn: bool = false,          // NETIF_F_TSO_ECN
    tso_mangleid: bool = false,
    gso_sctp: bool = false,
    gso_gre: bool = false,
    gso_gre_csum: bool = false,
    gso_ipxip4: bool = false,
    gso_ipxip6: bool = false,
    gso_udp_tunnel: bool = false,
    gso_udp_tunnel_csum: bool = false,
    gso_partial: bool = false,
    gso_tunnel_remcsum: bool = false,
    gso_esp: bool = false,
    gso_udp: bool = false,
    gso_udp_l4: bool = false,
    gso_fraglist: bool = false,
    fcoe_crc: bool = false,
    sctp_crc: bool = false,
    rxhash: bool = false,           // NETIF_F_RXHASH
    rxcsum: bool = false,           // NETIF_F_RXCSUM
    ntuple: bool = false,
    rxall: bool = false,
    hw_l2fw_doffload: bool = false,
    hw_tc: bool = false,            // NETIF_F_HW_TC
    hw_esp: bool = false,
    hw_esp_tx_csum: bool = false,
    rx_udp_tunnel_port: bool = false,
    hw_tls_tx: bool = false,        // NETIF_F_HW_TLS_TX
    hw_tls_rx: bool = false,
    gro_fraglist: bool = false,
    hw_macsec: bool = false,
    xdp: bool = false,             // XDP offload
    _pad: u14 = 0,
};

// ============================================================================
// NAPI
// ============================================================================

pub const NAPI_POLL_WEIGHT: u32 = 64;

pub const NapiStruct = struct {
    poll: u64,               // fn(*NapiStruct, budget: i32) -> i32
    poll_list: u64,          // list_head (per-CPU softnet_data)
    state: NapiState,
    weight: i32,
    defer_hard_irqs_count: i32,
    gro_bitmask: u64,
    gro_hash: [8]u64,       // GRO hash buckets
    skb: u64,                // GRO receive list
    rx_count: u64,
    rx_list: u64,            // list_head
    dev: u64,                // net_device *
    dev_list: u64,           // list_head (per-device)
    napi_id: u32,
    timer: u64,              // hrtimer for busy poll
    budget: u32,
    list_owner: i32,         // CPU owning this NAPI
};

pub const NapiState = packed struct(u32) {
    sched: bool = false,       // NAPI_STATE_SCHED
    disable: bool = false,     // NAPI_STATE_DISABLE
    npsvc: bool = false,       // NAPI_STATE_NPSVC
    listed: bool = false,      // NAPI_STATE_LISTED
    no_busy_poll: bool = false,
    in_busy_poll: bool = false,
    prefer_busy_poll: bool = false,
    threaded: bool = false,    // NAPI threaded mode
    sched_threaded: bool = false,
    _pad: u23 = 0,
};

// ============================================================================
// Net Device (net_device)
// ============================================================================

pub const MAX_ADDR_LEN: u32 = 32;
pub const IFNAMSIZ: u32 = 16;

pub const NetDevice = struct {
    // Identity
    name: [IFNAMSIZ]u8,
    ifindex: i32,
    dev_id: u16,
    dev_port: u16,
    group: u32,

    // Statistics
    stats: NetDeviceStats,
    core_stats: u64,         // pcpu_sw_netstats *

    // Hardware
    mem_start: u64,
    mem_end: u64,
    base_addr: u64,
    irq: i32,

    // State
    state: NetDevFlags,
    priv_flags: NetDevPrivFlags,
    operstate: u8,           // RFC2863 operstate
    link_mode: u8,
    carrier: bool,

    // MTU
    mtu: u32,
    min_mtu: u32,
    max_mtu: u32,
    hard_header_len: u16,
    needed_headroom: u16,
    needed_tailroom: u16,

    // Link layer
    type_field: u16,         // ARPHRD_*
    addr_len: u8,
    dev_addr: [MAX_ADDR_LEN]u8,
    broadcast: [MAX_ADDR_LEN]u8,
    perm_addr: [MAX_ADDR_LEN]u8,

    // Features
    features: NetdevFeatures,
    hw_features: NetdevFeatures,
    wanted_features: NetdevFeatures,
    vlan_features: NetdevFeatures,
    hw_enc_features: NetdevFeatures,
    mpls_features: NetdevFeatures,
    gso_max_size: u32,
    gso_max_segs: u16,
    gso_partial_features: NetdevFeatures,
    tso_max_size: u32,
    tso_max_segs: u16,

    // Transmit
    tx_queue_len: u32,
    num_tx_queues: u32,
    real_num_tx_queues: u32,
    qdisc: u64,             // Qdisc *
    watchdog_timeo: u32,

    // Receive
    num_rx_queues: u32,
    real_num_rx_queues: u32,
    rx_handler: u64,
    rx_handler_data: u64,

    // Operations
    netdev_ops: u64,         // net_device_ops *
    ethtool_ops: u64,        // ethtool_ops *
    dcbnl_ops: u64,          // dcbnl_rtnl_ops *
    xfrmdev_ops: u64,        // xfrmdev_ops *
    tlsdev_ops: u64,         // tlsdev_ops *
    l3mdev_ops: u64,         // l3mdev_ops *

    // Network namespace
    nd_net: u64,             // possible_net_t

    // NAPI
    napi_list: u64,          // list_head

    // XDP
    xdp_state: [3]u64,      // generic/native/offload

    // RPS/RFS/XPS
    ingress_queue: u64,
    _rx: u64,                // netdev_rx_queue *
    _tx: u64,                // netdev_queue *

    // PHY
    phydev: u64,             // phy_device *
    sfp_bus: u64,            // sfp_bus *

    // Promiscuity and allmulti (can nest)
    promiscuity: u32,
    allmulti: u32,
    uc_count: u32,           // unicast address count
    mc_count: u32,           // multicast address count

    // Neighbor
    neigh_priv_len: u16,

    // PCIe/DMA
    dev_parent: u64,         // struct device *
    dma_mask: u64,
    coherent_dma_mask: u64,

    // Misc
    flags_changed: bool,
    priv_destructor: u64,
    needs_free_netdev: bool,
};

// ============================================================================
// Net Device Statistics
// ============================================================================

pub const NetDeviceStats = struct {
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
    // Detailed
    rx_length_errors: u64,
    rx_over_errors: u64,
    rx_crc_errors: u64,
    rx_frame_errors: u64,
    rx_fifo_errors: u64,
    rx_missed_errors: u64,
    tx_aborted_errors: u64,
    tx_carrier_errors: u64,
    tx_fifo_errors: u64,
    tx_heartbeat_errors: u64,
    tx_window_errors: u64,
    rx_compressed: u64,
    tx_compressed: u64,
    rx_nohandler: u64,
};

// ============================================================================
// net_device_ops
// ============================================================================

pub const NetDeviceOps = struct {
    ndo_init: u64,
    ndo_uninit: u64,
    ndo_open: u64,
    ndo_stop: u64,
    ndo_start_xmit: u64,
    ndo_select_queue: u64,
    ndo_get_stats64: u64,
    ndo_set_rx_mode: u64,
    ndo_set_mac_address: u64,
    ndo_validate_addr: u64,
    ndo_do_ioctl: u64,
    ndo_eth_ioctl: u64,
    ndo_siocdevprivate: u64,
    ndo_change_mtu: u64,
    ndo_tx_timeout: u64,
    ndo_vlan_rx_add_vid: u64,
    ndo_vlan_rx_kill_vid: u64,
    ndo_poll_controller: u64,
    ndo_set_features: u64,
    ndo_fix_features: u64,
    ndo_setup_tc: u64,
    ndo_bpf: u64,
    ndo_xdp_xmit: u64,
    ndo_xsk_wakeup: u64,
    ndo_get_devlink_port: u64,
};

// ============================================================================
// RPS / XPS / Flow Steering
// ============================================================================

pub const RpsConfig = struct {
    rps_cpus: [16]u64,          // CPU bitmask per queue
    rps_flow_cnt: u32,          // flow table size per queue
    rps_sock_flow_entries: u32, // global socket flow table size
};

pub const XpsConfig = struct {
    xps_cpus: [16]u64,          // CPU bitmask per TX queue
    xps_rxqs: [16]u64,          // RX queue mapping per TX queue
};

// ============================================================================
// Ethtool Operations
// ============================================================================

pub const EthtoolLinkMode = enum(u8) {
    Speed10 = 0,
    Speed100 = 1,
    Speed1000 = 2,
    Speed2500 = 3,
    Speed5000 = 4,
    Speed10000 = 5,
    Speed25000 = 6,
    Speed40000 = 7,
    Speed50000 = 8,
    Speed100000 = 9,
    Speed200000 = 10,
    Speed400000 = 11,
    Speed800000 = 12,
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
    pkt_rate_high: u32,
    rate_sample_interval: u32,
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
};

// ============================================================================
// Netdev Notifier
// ============================================================================

pub const NetdevEvent = enum(u32) {
    Up = 0x0001,
    Down = 0x0002,
    Reboot = 0x0003,
    Change = 0x0004,
    Register = 0x0005,
    Unregister = 0x0006,
    ChangeMtu = 0x0007,
    ChangeAddr = 0x0008,
    GoingDown = 0x0009,
    ChangeName = 0x000a,
    FeatChange = 0x000b,
    BondingSlave = 0x000c,
    PreChangeMtu = 0x000d,
    PreChangeAddr = 0x000e,
    PreTypeChange = 0x000f,
    PostTypeChange = 0x0010,
    JoinBridge = 0x0011,
    ExitBridge = 0x0012,
    Offload_Xstats = 0x0013,
    PreOpen = 0x0014,
    XdpFeat = 0x0015,
};

// ============================================================================
// Net Device Manager
// ============================================================================

pub const NetdevManager = struct {
    total_devices: u32,
    total_up: u32,
    total_packets_rx: u64,
    total_packets_tx: u64,
    total_bytes_rx: u64,
    total_bytes_tx: u64,
    total_errors: u64,
    total_drops: u64,
    napi_polls: u64,
    xdp_redirects: u64,
    initialized: bool,

    pub fn init() NetdevManager {
        return .{
            .total_devices = 0,
            .total_up = 0,
            .total_packets_rx = 0,
            .total_packets_tx = 0,
            .total_bytes_rx = 0,
            .total_bytes_tx = 0,
            .total_errors = 0,
            .total_drops = 0,
            .napi_polls = 0,
            .xdp_redirects = 0,
            .initialized = true,
        };
    }
};
