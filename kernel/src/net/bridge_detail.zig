// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Bridge Subsystem Detail
// Complete IEEE 802.1D/Q bridge, STP/RSTP/MSTP, VLAN filtering,
// MDB, FDB, bridge ports, multicast, netfilter bridge

const std = @import("std");

// ============================================================================
// Bridge Port State (STP)
// ============================================================================

pub const BrPortState = enum(u8) {
    Disabled = 0,
    Listening = 1,
    Learning = 2,
    Forwarding = 3,
    Blocking = 4,
};

pub const StpState = enum(u8) {
    Disabled = 0,
    Topology = 1,
    Root = 2,
    Designated = 3,
    Alternate = 4,
    Backup = 5,
};

// ============================================================================
// STP Protocol
// ============================================================================

pub const BridgeId = packed struct(u64) {
    priority: u16,
    mac_addr: [6]u8,
};

pub const StpBpdu = packed struct {
    protocol_id: u16,
    version: u8,
    bpdu_type: u8,
    flags: StpBpduFlags,
    root_id: BridgeId,
    root_path_cost: u32,
    bridge_id: BridgeId,
    port_id: u16,
    message_age: u16,
    max_age: u16,
    hello_time: u16,
    forward_delay: u16,
};

pub const StpBpduFlags = packed struct(u8) {
    topology_change: bool,
    proposal: bool,
    port_role: u2,
    learning: bool,
    forwarding: bool,
    agreement: bool,
    topology_change_ack: bool,
};

pub const StpPortRole = enum(u2) {
    Unknown = 0,
    Root = 1,
    Designated = 2,
    Alternate = 3,
};

// ============================================================================
// Bridge Config
// ============================================================================

pub const BridgeConfig = struct {
    bridge_id: BridgeId,
    designated_root: BridgeId,
    root_path_cost: u32,
    max_age: u32,              // jiffies (default 20s)
    hello_time: u32,           // jiffies (default 2s)
    forward_delay: u32,        // jiffies (default 15s)
    bridge_max_age: u32,
    bridge_hello_time: u32,
    bridge_forward_delay: u32,
    ageing_time: u32,          // FDB ageing (default 300s)
    stp_enabled: StpVersion,
    topology_change: bool,
    topology_change_detected: bool,
    root_port: u16,
    group_fwd_mask: u16,
    group_addr: [6]u8,         // Default: 01:80:C2:00:00:00
    priority: u16,             // Default: 32768
    vlan_filtering: bool,
    vlan_protocol: u16,        // ETH_P_8021Q or ETH_P_8021AD
    default_pvid: u16,         // Default PVID (usually 1)
    mcast_router: u8,
    mcast_snooping: bool,
    mcast_querier: bool,
    mcast_query_use_ifaddr: bool,
    nf_call_iptables: bool,
    nf_call_ip6tables: bool,
    nf_call_arptables: bool,
};

pub const StpVersion = enum(u8) {
    None = 0,
    Stp = 1,
    Rstp = 2,
    Mstp = 3,
};

// ============================================================================
// Bridge Port
// ============================================================================

pub const BrPortFlags = packed struct(u32) {
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
    neigh_suppress: bool = false,
    vlan_tunnel: bool = false,
    backup_port: bool = false,
    mcast_flood: bool = false,
    bcast_flood: bool = false,
    locked: bool = false,
    _reserved: u16 = 0,
};

pub const BridgePort = struct {
    dev: u64,               // struct net_device *
    br: u64,                // struct net_bridge *
    port_no: u16,
    state: BrPortState,
    flags: BrPortFlags,
    path_cost: u32,
    priority: u8,
    designated_root: BridgeId,
    designated_cost: u32,
    designated_bridge: BridgeId,
    designated_port: u16,
    topology_change_ack: bool,
    config_pending: bool,
    role: StpPortRole,
    // Port timers
    message_age_timer: u64,
    forward_delay_timer: u64,
    hold_timer: u64,
    // Stats
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    // VLAN
    vlgrp: u64,             // struct net_bridge_vlan_group *
    // Multicast
    multicast_router: u8,
    mcast_n_groups: u32,
};

// ============================================================================
// Forwarding Database (FDB)
// ============================================================================

pub const FdbEntryFlags = packed struct(u16) {
    is_local: bool = false,
    is_static: bool = false,
    added_by_user: bool = false,
    added_by_external_learn: bool = false,
    offloaded: bool = false,
    locked: bool = false,
    sticky: bool = false,
    _reserved: u9 = 0,
};

pub const FdbEntry = struct {
    hlist: u64,             // hlist_node
    mac_addr: [6]u8,
    flags: FdbEntryFlags,
    dst: u64,               // struct net_bridge_port *
    vlan_id: u16,
    updated: u64,           // jiffies
    used: u64,              // jiffies
    key: u32,               // hash key
};

pub const FDB_HASH_SIZE = 256;

// ============================================================================
// VLAN Filtering
// ============================================================================

pub const BrVlanFlags = packed struct(u16) {
    master: bool = false,
    pvid: bool = false,
    untagged: bool = false,
    range_begin: bool = false,
    range_end: bool = false,
    brentry: bool = false,
    tunnel: bool = false,
    _reserved: u9 = 0,
};

pub const BridgeVlan = struct {
    vid: u16,
    flags: BrVlanFlags,
    state: BrPortState,
    stats: BrVlanStats,
    tinfo: BrVlanTunnelInfo,
};

pub const BrVlanStats = struct {
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
};

pub const BrVlanTunnelInfo = struct {
    tunnel_id: u32,
    tunnel_dst: u64,
};

pub const VLAN_VID_MASK = 0x0FFF;
pub const VLAN_MAX_VID = 4094;

pub const VlanHdr = packed struct {
    h_vlan_TCI: u16,     // Priority (3) + CFI (1) + VID (12)
    h_vlan_encap_proto: u16,
};

// ============================================================================
// Multicast Database (MDB)
// ============================================================================

pub const MdbEntryType = enum(u8) {
    Temporary = 0,
    Permanent = 1,
};

pub const MdbEntry = struct {
    addr: MdbAddr,
    port: u64,             // struct net_bridge_port *
    entry_type: MdbEntryType,
    state: u8,
    flags: MdbFlags,
    vid: u16,
    timer: u64,
    src_count: u32,
};

pub const MdbAddr = struct {
    proto: u16,            // ETH_P_IP or ETH_P_IPV6
    u: union {
        ip4: u32,
        ip6: [16]u8,
        mac: [6]u8,
    },
};

pub const MdbFlags = packed struct(u8) {
    star_exclude: bool = false,
    fast_leave: bool = false,
    added_by_star: bool = false,
    _reserved: u5 = 0,
};

// ============================================================================
// IGMP Snooping
// ============================================================================

pub const IgmpType = enum(u8) {
    MembershipQuery = 0x11,
    V1MembershipReport = 0x12,
    V2MembershipReport = 0x16,
    V2LeaveGroup = 0x17,
    V3MembershipReport = 0x22,
};

pub const MldType = enum(u8) {
    ListenerQuery = 130,
    V1ListenerReport = 131,
    V1ListenerDone = 132,
    V2ListenerReport = 143,
};

pub const McastSnoopingConfig = struct {
    mcast_snooping: bool,
    mcast_querier: bool,
    mcast_hash_max: u32,
    mcast_last_member_cnt: u32,
    mcast_startup_query_cnt: u32,
    mcast_last_member_interval: u64,
    mcast_membership_interval: u64,
    mcast_querier_interval: u64,
    mcast_query_interval: u64,
    mcast_query_response_interval: u64,
    mcast_startup_query_interval: u64,
    mcast_igmp_version: u8,         // 2 or 3
    mcast_mld_version: u8,          // 1 or 2
};

// ============================================================================
// Bridge Netfilter (br_netfilter)
// ============================================================================

pub const BrNfHook = enum(u8) {
    PreRouting = 0,
    LocalIn = 1,
    Forward = 2,
    LocalOut = 3,
    PostRouting = 4,
};

pub const BrNfConfig = struct {
    call_iptables: bool,
    call_ip6tables: bool,
    call_arptables: bool,
    filter_vlan_tagged: bool,
    filter_pppoe_tagged: bool,
    pass_vlan_input_dev: bool,
};

// ============================================================================
// MSTP (Multiple Spanning Tree Protocol)
// ============================================================================

pub const MstpRegion = struct {
    region_name: [32]u8,
    revision: u16,
    config_digest: [16]u8,
};

pub const MAX_MSTI = 64;  // Maximum MSTI instances

pub const MstiInfo = struct {
    msti_id: u16,
    bridge_id: BridgeId,
    root_id: BridgeId,
    root_path_cost: u32,
    designated_root: BridgeId,
    vlans: [512]u8,  // 4096-bit VLAN bitmap
};

// ============================================================================
// Bridge Manager
// ============================================================================

pub const BridgeManager = struct {
    total_bridges: u32,
    total_ports: u32,
    total_fdb_entries: u64,
    total_mdb_entries: u64,
    total_vlans: u32,
    total_stp_topology_changes: u64,
    total_stp_root_changes: u64,
    total_igmp_queries: u64,
    total_igmp_reports: u64,
    total_mld_queries: u64,
    total_mld_reports: u64,
    total_br_nf_calls: u64,
    total_fdb_learned: u64,
    total_fdb_aged_out: u64,
    total_forwarded: u64,
    total_flooded: u64,
    total_filtered: u64,
    initialized: bool,

    pub fn init() BridgeManager {
        return .{
            .total_bridges = 0,
            .total_ports = 0,
            .total_fdb_entries = 0,
            .total_mdb_entries = 0,
            .total_vlans = 0,
            .total_stp_topology_changes = 0,
            .total_stp_root_changes = 0,
            .total_igmp_queries = 0,
            .total_igmp_reports = 0,
            .total_mld_queries = 0,
            .total_mld_reports = 0,
            .total_br_nf_calls = 0,
            .total_fdb_learned = 0,
            .total_fdb_aged_out = 0,
            .total_forwarded = 0,
            .total_flooded = 0,
            .total_filtered = 0,
            .initialized = true,
        };
    }
};
