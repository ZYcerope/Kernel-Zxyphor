// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Network Bridge, Bonding, and Teaming
// IEEE 802.1D/Q bridge, link aggregation (bond), team driver,
// VXLAN, GRE/GRETAP, GENEVE, WireGuard, MACsec 802.1AE
// More advanced than Linux 2026 network subsystem

const std = @import("std");

// ============================================================================
// Bridge (IEEE 802.1D/Q)
// ============================================================================

pub const BridgeState = enum(u8) {
    disabled = 0,
    listening = 1,
    learning = 2,
    forwarding = 3,
    blocking = 4,
};

pub const BridgePortFlags = packed struct(u32) {
    hairpin_mode: bool = false,
    bpdu_guard: bool = false,
    root_block: bool = false,
    fastleave: bool = false,
    learning: bool = false,
    flood: bool = false,
    proxyarp: bool = false,
    proxyarp_wifi: bool = false,
    isolated: bool = false,
    multicast_to_unicast: bool = false,
    mcast_flood: bool = false,
    mcast_to_ucast: bool = false,
    vlan_tunnel: bool = false,
    backup_port: bool = false,
    neigh_suppress: bool = false,
    locked: bool = false,
    mab: bool = false,           // MAC Authentication Bypass
    // Zxyphor
    zxy_mirror: bool = false,
    _reserved: u14 = 0,
};

pub const BridgePort = struct {
    port_no: u16,
    port_id: u16,
    state: BridgeState,
    flags: BridgePortFlags,
    // STP
    priority: u8,
    path_cost: u32,
    designated_root: u64,
    designated_bridge: u64,
    designated_port: u16,
    designated_cost: u32,
    // Timers
    message_age_timer: u64,
    forward_delay_timer: u64,
    hold_timer: u64,
    // VLAN
    pvid: u16,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    // FDB entries learned
    fdb_count: u32,
    // STP transitions
    topology_change_count: u64,
    // Multicast
    multicast_router: u8,        // 0=disabled, 1=temp, 2=permanent
    mcast_groups: u32,
};

pub const BridgeFdbEntry = struct {
    addr: [6]u8,
    vlan_id: u16,
    port_no: u16,
    // Flags
    is_local: bool,
    is_static: bool,
    is_sticky: bool,
    is_routed: bool,
    added_by_user: bool,
    added_by_external_learn: bool,
    offloaded: bool,
    // Aging
    updated: u64,                // jiffies
    used: u64,
};

pub const BridgeVlanInfo = struct {
    vid: u16,
    flags: u16,                  // BRIDGE_VLAN_INFO_*
    pvid: bool,
    untagged: bool,
    range_begin: bool,
    range_end: bool,
    brentry: bool,
    only_opts: bool,
};

pub const StpMode = enum(u8) {
    no_stp = 0,
    stp = 1,
    rstp = 2,
    mstp = 3,
};

pub const Bridge = struct {
    // Identity
    bridge_id: u64,
    name: [16]u8,
    // STP
    stp_enabled: StpMode,
    designated_root: u64,
    root_port: u16,
    root_path_cost: u32,
    bridge_max_age: u32,
    bridge_hello_time: u32,
    bridge_forward_delay: u32,
    max_age: u32,
    hello_time: u32,
    forward_delay: u32,
    ageing_time: u32,
    // Topology
    topology_change: bool,
    topology_change_detected: bool,
    topology_change_count: u64,
    topology_change_timer: u64,
    // Ports
    nr_ports: u16,
    // VLAN filtering
    vlan_filtering: bool,
    vlan_protocol: u16,          // ETH_P_8021Q or ETH_P_8021AD
    default_pvid: u16,
    vlan_stats_enabled: bool,
    vlan_stats_per_port: bool,
    // Multicast
    multicast_snooping: bool,
    multicast_querier: bool,
    multicast_igmp_version: u8,
    multicast_mld_version: u8,
    multicast_router: u8,
    multicast_last_member_count: u32,
    multicast_startup_query_count: u32,
    // NF
    nf_call_iptables: bool,
    nf_call_ip6tables: bool,
    nf_call_arptables: bool,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    fdb_n_learned: u32,
    fdb_max_learned: u32,
};

// ============================================================================
// Bonding (Link Aggregation - IEEE 802.3ad / 802.1AX)
// ============================================================================

pub const BondMode = enum(u8) {
    balance_rr = 0,              // Round-robin
    active_backup = 1,
    balance_xor = 2,
    broadcast = 3,
    lacp_802_3ad = 4,            // IEEE 802.3ad / 802.1AX
    balance_tlb = 5,             // Adaptive transmit load balancing
    balance_alb = 6,             // Adaptive load balancing
    // Zxyphor
    zxy_adaptive = 10,
};

pub const BondXmitHashPolicy = enum(u8) {
    layer2 = 0,
    layer3_4 = 1,
    layer2_3 = 2,
    encap2_3 = 3,
    encap3_4 = 4,
    vlan_srcmac = 5,
};

pub const BondSlaveState = enum(u8) {
    active = 0,
    backup = 1,
};

pub const BondLacpRate = enum(u8) {
    slow = 0,                    // Every 30 seconds
    fast = 1,                    // Every 1 second
};

pub const BondAdSelect = enum(u8) {
    stable = 0,
    bandwidth = 1,
    count = 2,
};

pub const BondPrimaryReselect = enum(u8) {
    always = 0,
    better = 1,
    failure = 2,
};

pub const BondFailOverMac = enum(u8) {
    none = 0,
    active = 1,
    follow = 2,
};

pub const BondArpValidate = enum(u8) {
    none = 0,
    active = 1,
    backup = 2,
    all_val = 3,
    filter = 4,
    filter_active = 5,
    filter_backup = 6,
};

pub const BondSlave = struct {
    name: [16]u8,
    mac: [6]u8,
    state: BondSlaveState,
    mii_status: u8,              // 0=down, 1=up
    link_failure_count: u32,
    perm_hwaddr: [6]u8,
    queue_id: u16,
    // LACP info
    ad_partner_key: u16,
    ad_aggregator_id: u16,
    ad_actor_oper_port_state: u8,
    ad_partner_oper_port_state: u8,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    // Speed/duplex
    speed: u32,
    duplex: u8,
};

pub const Bond = struct {
    name: [16]u8,
    mac: [6]u8,
    mode: BondMode,
    // Slaves
    nr_slaves: u8,
    active_slave: u8,            // Index
    primary_slave: u8,
    // Monitoring
    miimon: u32,                 // MII mon interval (ms)
    updelay: u32,                // ms
    downdelay: u32,              // ms
    peer_notif_delay: u32,
    arp_interval: u32,           // ms
    arp_ip_target: [16]u32,      // ARP targets
    nr_arp_targets: u8,
    arp_validate: BondArpValidate,
    arp_all_targets: u8,
    // LACP
    lacp_rate: BondLacpRate,
    lacp_active: bool,
    ad_select: BondAdSelect,
    ad_aggregator: u16,
    ad_num_ports: u16,
    ad_actor_key: u16,
    ad_partner_key: u16,
    ad_partner_mac: [6]u8,
    // Xmit
    xmit_hash_policy: BondXmitHashPolicy,
    // TLB/ALB
    tlb_dynamic_lb: bool,
    lp_interval: u32,
    // Failover
    primary_reselect: BondPrimaryReselect,
    fail_over_mac: BondFailOverMac,
    num_grat_arp: u8,
    num_unsol_na: u8,
    // Misc
    min_links: u32,
    all_slaves_active: bool,
    resend_igmp: u32,
    packets_per_slave: u32,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    failover_count: u64,
};

// ============================================================================
// VXLAN (Virtual Extensible LAN - RFC 7348)
// ============================================================================

pub const VxlanFlags = packed struct(u32) {
    collect_metadata: bool = false,
    proxy: bool = false,
    rsc: bool = false,           // Route short circuit
    l2miss: bool = false,
    l3miss: bool = false,
    gbp: bool = false,           // Group-based policy
    gpe: bool = false,           // Generic protocol extension
    remcsum_tx: bool = false,
    remcsum_rx: bool = false,
    remcsum_nopartial: bool = false,
    localbypass: bool = false,
    ttl_inherit: bool = false,
    df_set: bool = false,
    df_unset: bool = false,
    // Zxyphor
    zxy_encrypted: bool = false,
    _reserved: u17 = 0,
};

pub const VxlanDevice = struct {
    name: [16]u8,
    vni: u32,                    // VXLAN Network Identifier (24-bit)
    // Local
    local_ip: u32,
    local_ip6: [16]u8,
    local_port: u16,
    // Remote
    remote_ip: u32,
    remote_ip6: [16]u8,
    remote_port: u16,            // Default 4789
    // Interface
    link_ifindex: u32,
    // TTL/TOS
    ttl: u8,
    tos: u8,
    // Learning
    learning: bool,
    ageing: u32,                 // FDB aging time (secs)
    max_fdb_count: u32,
    // Flags
    flags: VxlanFlags,
    // Ranges
    port_min: u16,
    port_max: u16,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_drops: u64,
    tx_drops: u64,
    tx_errors: u64,
};

// ============================================================================
// GRE (Generic Routing Encapsulation - RFC 2784/2890)
// ============================================================================

pub const GreFlags = packed struct(u16) {
    checksum: bool = false,
    routing: bool = false,
    key: bool = false,
    sequence: bool = false,
    strict_source_route: bool = false,
    recursion_control: u3 = 0,
    ack: bool = false,
    // ERSPAN
    erspan: bool = false,
    _reserved: u6 = 0,
};

pub const GreTunnel = struct {
    name: [16]u8,
    // Endpoints
    local_ip: u32,
    remote_ip: u32,
    local_ip6: [16]u8,
    remote_ip6: [16]u8,
    is_ipv6: bool,
    // GRE options
    flags: GreFlags,
    key: u32,
    // TTL/TOS
    ttl: u8,
    tos: u8,
    // PMTU
    pmtudisc: bool,
    // ERSPAN
    erspan_ver: u8,              // 1 or 2
    erspan_idx: u32,
    erspan_dir: u8,
    erspan_hwid: u8,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_frame_errors: u64,
    tx_carrier_errors: u64,
};

// ============================================================================
// GENEVE (Generic Network Virtualization Encapsulation - RFC 8926)
// ============================================================================

pub const GeneveDevice = struct {
    name: [16]u8,
    vni: u32,                    // 24-bit
    // Remote
    remote_ip: u32,
    remote_ip6: [16]u8,
    is_ipv6: bool,
    // Port
    dst_port: u16,               // Default 6081
    // Options
    collect_metadata: bool,
    ttl: u8,
    tos: u8,
    ttl_inherit: bool,
    df: u8,
    // UDP
    udp_csum: bool,
    udp6_rx_zero_csum: bool,
    // Inner protocol
    inner_proto_inherit: bool,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
};

// ============================================================================
// WireGuard
// ============================================================================

pub const WgPeer = struct {
    public_key: [32]u8,
    preshared_key: [32]u8,
    has_preshared_key: bool,
    // Endpoint
    endpoint_ip: u32,
    endpoint_ip6: [16]u8,
    endpoint_port: u16,
    endpoint_is_ipv6: bool,
    // Allowed IPs
    allowed_ips: [32]WgAllowedIp,
    nr_allowed_ips: u8,
    // Keepalive
    persistent_keepalive_interval: u16,  // seconds, 0=disabled
    // Handshake
    last_handshake_ns: u64,
    // Stats
    rx_bytes: u64,
    tx_bytes: u64,
    last_rx_ns: u64,
    last_tx_ns: u64,
};

pub const WgAllowedIp = struct {
    addr: u32,
    addr6: [16]u8,
    is_ipv6: bool,
    cidr: u8,
};

pub const WgDevice = struct {
    name: [16]u8,
    private_key: [32]u8,
    public_key: [32]u8,
    listen_port: u16,
    fwmark: u32,
    // Peers
    nr_peers: u32,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
};

// ============================================================================
// MACsec (IEEE 802.1AE)
// ============================================================================

pub const MacsecCipherSuite = enum(u64) {
    gcm_aes_128 = 0x0080C20001000001,
    gcm_aes_256 = 0x0080C20001000002,
    gcm_aes_xpn_128 = 0x0080C20001000003,
    gcm_aes_xpn_256 = 0x0080C20001000004,
};

pub const MacsecValidation = enum(u8) {
    disabled = 0,
    check = 1,
    strict = 2,
};

pub const MacsecOffload = enum(u8) {
    off = 0,
    phy = 1,
    mac = 2,
};

pub const MacsecTxSa = struct {
    an: u8,                      // Association Number (0-3)
    active: bool,
    next_pn: u64,
    // Key
    key_id: [16]u8,
    // Stats
    encrypted_packets: u64,
    encrypted_octets: u64,
    protected_packets: u64,
    protected_octets: u64,
};

pub const MacsecRxSa = struct {
    an: u8,
    active: bool,
    next_pn: u64,
    lowest_pn: u64,
    // Key
    key_id: [16]u8,
    // Stats
    valid_packets: u64,
    valid_bytes: u64,
    invalid_packets: u64,
    not_valid_packets: u64,
    not_using_sa_packets: u64,
    unused_sa_packets: u64,
};

pub const MacsecSecy = struct {
    // SCI
    sci: u64,
    // Cipher
    cipher_suite: MacsecCipherSuite,
    icv_len: u8,
    // Encoding
    encoding_sa: u8,             // 0-3
    // Validation
    validate_frames: MacsecValidation,
    // Capabilities
    replay_protect: bool,
    replay_window: u32,
    protect_frames: bool,
    include_sci: bool,
    es: bool,
    scb: bool,
    // Offload
    offload: MacsecOffload,
    // TX
    tx_sa: [4]MacsecTxSa,
    // Stats
    out_pkts_untagged: u64,
    out_pkts_too_long: u64,
    in_pkts_untagged: u64,
    in_pkts_no_tag: u64,
    in_pkts_bad_tag: u64,
    in_pkts_unknown_sci: u64,
    in_pkts_no_sci: u64,
    in_pkts_overrun: u64,
};

// ============================================================================
// IP-in-IP and SIT Tunnels
// ============================================================================

pub const IpIpTunnel = struct {
    name: [16]u8,
    local_ip: u32,
    remote_ip: u32,
    ttl: u8,
    tos: u8,
    pmtudisc: bool,
    // IPsec
    encap_type: u8,              // 0=none, 1=FOU, 2=GUE
    encap_sport: u16,
    encap_dport: u16,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
};

pub const SitTunnel = struct {
    name: [16]u8,
    local_ip: u32,
    remote_ip: u32,
    ttl: u8,
    tos: u8,
    isatap: bool,                // RFC 5214
    // 6RD (RFC 5969)
    ip6rd_prefix: [16]u8,
    ip6rd_prefixlen: u8,
    ip6rd_relay_prefix: u32,
    ip6rd_relay_prefixlen: u8,
    // Stats
    rx_packets: u64,
    tx_packets: u64,
};

// ============================================================================
// Network Tunnel Subsystem
// ============================================================================

pub const TunnelType = enum(u8) {
    vxlan = 0,
    gre = 1,
    gretap = 2,
    ip6gre = 3,
    ip6gretap = 4,
    geneve = 5,
    wireguard = 6,
    macsec = 7,
    ipip = 8,
    sit = 9,
    ip6tnl = 10,
    erspan = 11,
    vti = 12,
    vti6 = 13,
    bareudp = 14,
    // Zxyphor
    zxy_quic_tunnel = 20,
    zxy_encrypted_tunnel = 21,
};

pub const NetworkOverlaySubsystem = struct {
    // Bridges
    nr_bridges: u32,
    nr_bridge_ports: u32,
    nr_fdb_entries: u64,
    // Bonds
    nr_bonds: u32,
    nr_bond_slaves: u32,
    // Tunnels
    nr_vxlan: u32,
    nr_gre: u32,
    nr_geneve: u32,
    nr_wireguard: u32,
    nr_macsec: u32,
    nr_ipip: u32,
    nr_sit: u32,
    // Stats
    total_tunnel_rx_packets: u64,
    total_tunnel_tx_packets: u64,
    total_tunnel_rx_bytes: u64,
    total_tunnel_tx_bytes: u64,
    total_encap_overhead_bytes: u64,
    // Errors
    total_tunnel_errors: u64,
    total_encap_errors: u64,
    total_decap_errors: u64,
    // STP
    stp_topology_changes: u64,
    // LACP
    lacp_partner_changes: u64,
    // Zxyphor
    zxy_auto_tunnel: bool,
    zxy_tunnel_compression: bool,
    initialized: bool,
};
