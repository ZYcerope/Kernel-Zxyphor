// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Ethtool Complete Interface Detail
// Complete: ethtool ioctl/netlink commands, link settings, coalescing,
// ring parameters, pause frames, EEE, FEC, RSS, self-test, dump,
// timestamping, cable test, module EEPROM, PHY tunable, statistics

const std = @import("std");

// ============================================================================
// Ethtool Commands
// ============================================================================

pub const EthtoolCmd = enum(u32) {
    ETHTOOL_GSET = 0x00000001,
    ETHTOOL_SSET = 0x00000002,
    ETHTOOL_GDRVINFO = 0x00000003,
    ETHTOOL_GREGS = 0x00000004,
    ETHTOOL_GWOL = 0x00000005,
    ETHTOOL_SWOL = 0x00000006,
    ETHTOOL_GMSGLVL = 0x00000007,
    ETHTOOL_SMSGLVL = 0x00000008,
    ETHTOOL_NWAY_RST = 0x00000009,
    ETHTOOL_GLINK = 0x0000000a,
    ETHTOOL_GEEPROM = 0x0000000b,
    ETHTOOL_SEEPROM = 0x0000000c,
    ETHTOOL_GCOALESCE = 0x0000000e,
    ETHTOOL_SCOALESCE = 0x0000000f,
    ETHTOOL_GRINGPARAM = 0x00000010,
    ETHTOOL_SRINGPARAM = 0x00000011,
    ETHTOOL_GPAUSEPARAM = 0x00000012,
    ETHTOOL_SPAUSEPARAM = 0x00000013,
    ETHTOOL_GRXCSUM = 0x00000014,
    ETHTOOL_SRXCSUM = 0x00000015,
    ETHTOOL_GTXCSUM = 0x00000016,
    ETHTOOL_STXCSUM = 0x00000017,
    ETHTOOL_GSG = 0x00000018,
    ETHTOOL_SSG = 0x00000019,
    ETHTOOL_TEST = 0x0000001a,
    ETHTOOL_GSTRINGS = 0x0000001b,
    ETHTOOL_PHYS_ID = 0x0000001c,
    ETHTOOL_GSTATS = 0x0000001d,
    ETHTOOL_GTSO = 0x0000001e,
    ETHTOOL_STSO = 0x0000001f,
    ETHTOOL_GPERMADDR = 0x00000020,
    ETHTOOL_GUFO = 0x00000021,
    ETHTOOL_SUFO = 0x00000022,
    ETHTOOL_GGSO = 0x00000023,
    ETHTOOL_SGSO = 0x00000024,
    ETHTOOL_GFLAGS = 0x00000025,
    ETHTOOL_SFLAGS = 0x00000026,
    ETHTOOL_GPFLAGS = 0x00000027,
    ETHTOOL_SPFLAGS = 0x00000028,
    ETHTOOL_GRXFH = 0x00000029,
    ETHTOOL_SRXFH = 0x0000002a,
    ETHTOOL_GGRO = 0x0000002b,
    ETHTOOL_SGRO = 0x0000002c,
    ETHTOOL_GRXRINGS = 0x0000002d,
    ETHTOOL_GRXCLSRLCNT = 0x0000002e,
    ETHTOOL_GRXCLSRULE = 0x0000002f,
    ETHTOOL_GRXCLSRLALL = 0x00000030,
    ETHTOOL_SRXCLSRLDEL = 0x00000031,
    ETHTOOL_SRXCLSRLINS = 0x00000032,
    ETHTOOL_FLASHDEV = 0x00000033,
    ETHTOOL_RESET = 0x00000034,
    ETHTOOL_SRXNTUPLE = 0x00000035,
    ETHTOOL_GRXNTUPLE = 0x00000036,
    ETHTOOL_GSSET_INFO = 0x00000037,
    ETHTOOL_GRXFHINDIR = 0x00000038,
    ETHTOOL_SRXFHINDIR = 0x00000039,
    ETHTOOL_GFEATURES = 0x0000003a,
    ETHTOOL_SFEATURES = 0x0000003b,
    ETHTOOL_GCHANNELS = 0x0000003c,
    ETHTOOL_SCHANNELS = 0x0000003d,
    ETHTOOL_SET_DUMP = 0x0000003e,
    ETHTOOL_GET_DUMP_FLAG = 0x0000003f,
    ETHTOOL_GET_DUMP_DATA = 0x00000040,
    ETHTOOL_GET_TS_INFO = 0x00000041,
    ETHTOOL_GMODULEINFO = 0x00000042,
    ETHTOOL_GMODULEEEPROM = 0x00000043,
    ETHTOOL_GEEE = 0x00000044,
    ETHTOOL_SEEE = 0x00000045,
    ETHTOOL_GRSSH = 0x00000046,
    ETHTOOL_SRSSH = 0x00000047,
    ETHTOOL_GTUNABLE = 0x00000048,
    ETHTOOL_STUNABLE = 0x00000049,
    ETHTOOL_GPHYSTATS = 0x0000004a,
    ETHTOOL_PERQUEUE = 0x0000004b,
    ETHTOOL_GLINKSETTINGS = 0x0000004c,
    ETHTOOL_SLINKSETTINGS = 0x0000004d,
    ETHTOOL_PHY_GTUNABLE = 0x0000004e,
    ETHTOOL_PHY_STUNABLE = 0x0000004f,
    ETHTOOL_GFECPARAM = 0x00000050,
    ETHTOOL_SFECPARAM = 0x00000051,
};

// ============================================================================
// Link Settings
// ============================================================================

pub const EthtoolLinkModeMask = packed struct(u128) {
    @"10baseT_Half": bool,
    @"10baseT_Full": bool,
    @"100baseT_Half": bool,
    @"100baseT_Full": bool,
    @"1000baseT_Half": bool,
    @"1000baseT_Full": bool,
    Autoneg: bool,
    TP: bool,
    AUI: bool,
    MII: bool,
    FIBRE: bool,
    BNC: bool,
    @"10000baseT_Full": bool,
    Pause: bool,
    Asym_Pause: bool,
    @"2500baseX_Full": bool,
    Backplane: bool,
    @"1000baseKX_Full": bool,
    @"10000baseKX4_Full": bool,
    @"10000baseKR_Full": bool,
    @"10000baseR_FEC": bool,
    @"20000baseMLD2_Full": bool,
    @"20000baseKR2_Full": bool,
    @"40000baseKR4_Full": bool,
    @"40000baseCR4_Full": bool,
    @"40000baseSR4_Full": bool,
    @"40000baseLR4_Full": bool,
    @"56000baseKR4_Full": bool,
    @"56000baseCR4_Full": bool,
    @"56000baseSR4_Full": bool,
    @"56000baseLR4_Full": bool,
    @"25000baseCR_Full": bool,
    @"25000baseKR_Full": bool,
    @"25000baseSR_Full": bool,
    @"50000baseCR2_Full": bool,
    @"50000baseKR2_Full": bool,
    @"100000baseKR4_Full": bool,
    @"100000baseSR4_Full": bool,
    @"100000baseCR4_Full": bool,
    @"100000baseLR4_ER4_Full": bool,
    @"50000baseSR2_Full": bool,
    @"1000baseX_Full": bool,
    @"10000baseCR_Full": bool,
    @"10000baseSR_Full": bool,
    @"10000baseLR_Full": bool,
    @"10000baseLRM_Full": bool,
    @"10000baseER_Full": bool,
    @"2500baseT_Full": bool,
    @"5000baseT_Full": bool,
    FEC_NONE: bool,
    FEC_RS: bool,
    FEC_BASER: bool,
    @"50000baseKR_Full": bool,
    @"50000baseSR_Full": bool,
    @"50000baseCR_Full": bool,
    @"50000baseLR_ER_FR_Full": bool,
    @"50000baseDR_Full": bool,
    @"100000baseKR2_Full": bool,
    @"100000baseSR2_Full": bool,
    @"100000baseCR2_Full": bool,
    @"100000baseLR2_ER2_FR2_Full": bool,
    @"100000baseDR2_Full": bool,
    @"200000baseKR4_Full": bool,
    @"200000baseSR4_Full": bool,
    @"200000baseLR4_ER4_FR4_Full": bool,
    @"200000baseDR4_Full": bool,
    @"200000baseCR4_Full": bool,
    @"100baseT1_Full": bool,
    @"1000baseT1_Full": bool,
    @"400000baseKR8_Full": bool,
    @"400000baseSR8_Full": bool,
    @"400000baseLR8_ER8_FR8_Full": bool,
    @"400000baseDR8_Full": bool,
    @"400000baseCR8_Full": bool,
    FEC_LLRS: bool,
    @"100000baseKR_Full": bool,
    @"100000baseSR_Full": bool,
    @"100000baseLR_ER_FR_Full": bool,
    @"100000baseCR_Full": bool,
    @"100000baseDR_Full": bool,
    @"200000baseKR2_Full": bool,
    @"200000baseSR2_Full": bool,
    @"200000baseLR2_ER2_FR2_Full": bool,
    @"200000baseDR2_Full": bool,
    @"200000baseCR2_Full": bool,
    @"400000baseKR4_Full": bool,
    @"400000baseSR4_Full": bool,
    @"400000baseLR4_ER4_FR4_Full": bool,
    @"400000baseDR4_Full": bool,
    @"400000baseCR4_Full": bool,
    @"800000baseCR8_Full": bool,
    @"800000baseKR8_Full": bool,
    @"800000baseDR8_Full": bool,
    @"800000baseDR8_2_Full": bool,
    @"800000baseSR8_Full": bool,
    @"800000baseVR8_Full": bool,
    _reserved: u33,
};

pub const EthtoolLinkSettings = struct {
    cmd: u32,
    speed: u32,                         // Mbps or SPEED_UNKNOWN
    duplex: EthtoolDuplex,
    port: EthtoolPort,
    phy_address: u8,
    autoneg: bool,
    mdio_support: u8,
    eth_tp_mdix: u8,
    eth_tp_mdix_ctrl: u8,
    link_mode_masks_nwords: i8,
    transceiver: u8,
    master_slave_cfg: u8,
    master_slave_state: u8,
    rate_matching: u8,
    link_mode_data: [3]EthtoolLinkModeMask,  // supported, advertising, lp_advertising
};

pub const EthtoolDuplex = enum(u8) {
    Half = 0,
    Full = 1,
    Unknown = 255,
};

pub const EthtoolPort = enum(u8) {
    TP = 0,
    AUI = 1,
    MII = 2,
    FIBRE = 3,
    BNC = 4,
    DA = 5,
    NONE = 0xEF,
    OTHER = 0xFF,
};

// ============================================================================
// Coalescing
// ============================================================================

pub const EthtoolCoalesce = struct {
    cmd: u32,
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
    rx_max_coalesced_frames_low: u32,
    tx_coalesce_usecs_low: u32,
    tx_max_coalesced_frames_low: u32,
    pkt_rate_high: u32,
    rx_coalesce_usecs_high: u32,
    rx_max_coalesced_frames_high: u32,
    tx_coalesce_usecs_high: u32,
    tx_max_coalesced_frames_high: u32,
    rate_sample_interval: u32,
    cqe_mode_rx: bool,
    cqe_mode_tx: bool,
    tx_aggr_max_bytes: u32,
    tx_aggr_max_frames: u32,
    tx_aggr_time_usecs: u32,
};

// ============================================================================
// Ring Parameters
// ============================================================================

pub const EthtoolRingparam = struct {
    cmd: u32,
    rx_max_pending: u32,
    rx_mini_max_pending: u32,
    rx_jumbo_max_pending: u32,
    tx_max_pending: u32,
    rx_pending: u32,
    rx_mini_pending: u32,
    rx_jumbo_pending: u32,
    tx_pending: u32,
    rx_buf_len: u32,
    cqe_size: u32,
    tx_push: bool,
    rx_push: bool,
    tx_push_buf_len: u32,
    tx_push_buf_len_max: u32,
};

// ============================================================================
// Pause Parameters
// ============================================================================

pub const EthtoolPauseparam = struct {
    cmd: u32,
    autoneg: bool,
    rx_pause: bool,
    tx_pause: bool,
};

pub const EthtoolPauseStats = struct {
    tx_pause_frames: u64,
    rx_pause_frames: u64,
};

// ============================================================================
// EEE (Energy Efficient Ethernet)
// ============================================================================

pub const EthtoolEee = struct {
    cmd: u32,
    supported: u32,         // Link modes supporting EEE
    advertised: u32,
    lp_advertised: u32,
    eee_active: bool,
    eee_enabled: bool,
    tx_lpi_enabled: bool,
    tx_lpi_timer: u32,      // Time in microseconds
};

// ============================================================================
// FEC (Forward Error Correction)
// ============================================================================

pub const EthtoolFecParam = struct {
    cmd: u32,
    active_fec: EthtoolFecMode,
    fec: EthtoolFecMode,
    reserved: u32,
};

pub const EthtoolFecMode = packed struct(u32) {
    none: bool,
    auto_neg: bool,
    off: bool,
    rs: bool,
    baser: bool,
    llrs: bool,
    _reserved: u26,
};

// ============================================================================
// Channels
// ============================================================================

pub const EthtoolChannels = struct {
    cmd: u32,
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
// RSS (Receive Side Scaling)
// ============================================================================

pub const EthtoolRxfh = struct {
    cmd: u32,
    rss_context: u32,
    indir_size: u32,
    key_size: u32,
    hfunc: u8,
    input_xfrm: u8,
    rsvd8: [2]u8,
    rsvd32: u32,
    indir: [128]u32,        // Indirection table
    key: [52]u8,            // Hash key
};

pub const EthtoolRxfhIndir = struct {
    cmd: u32,
    size: u32,
    ring_index: [128]u32,
};

pub const EthtoolHashFunc = packed struct(u8) {
    toeplitz: bool,
    xor: bool,
    crc32: bool,
    _reserved: u5,
};

// ============================================================================
// Driver Info
// ============================================================================

pub const EthtoolDrvinfo = struct {
    cmd: u32,
    driver: [32]u8,
    version: [32]u8,
    fw_version: [32]u8,
    bus_info: [32]u8,
    erom_version: [32]u8,
    reserved2: [12]u8,
    n_priv_flags: u32,
    n_stats: u32,
    testinfo_len: u32,
    eedump_len: u32,
    regdump_len: u32,
};

// ============================================================================
// Self Test
// ============================================================================

pub const EthtoolTest = struct {
    cmd: u32,
    flags: EthtoolTestFlags,
    reserved: u32,
    len: u32,
    data: [64]u64,          // Test results
};

pub const EthtoolTestFlags = packed struct(u32) {
    offline: bool,
    online: bool,
    external_lb: bool,
    _reserved: u29,
};

// ============================================================================
// Timestamping
// ============================================================================

pub const EthtoolTsInfo = struct {
    cmd: u32,
    so_timestamping: SoTimestamping,
    phc_index: i32,
    tx_types: u32,
    tx_reserved: [3]u32,
    rx_filters: u32,
    rx_reserved: [3]u32,
};

pub const SoTimestamping = packed struct(u32) {
    tx_hardware: bool,
    tx_software: bool,
    rx_hardware: bool,
    rx_software: bool,
    software: bool,
    sys_hardware: bool,
    raw_hardware: bool,
    opt_id: bool,
    tx_sched: bool,
    tx_ack: bool,
    opt_cmsg: bool,
    opt_tsonly: bool,
    opt_stats: bool,
    opt_pktinfo: bool,
    opt_tx_swhw: bool,
    bind_phc: bool,
    opt_id_tcp: bool,
    _reserved: u15,
};

pub const HwTstampConfig = struct {
    flags: u32,
    tx_type: HwTsTxType,
    rx_filter: HwTsRxFilter,
};

pub const HwTsTxType = enum(u32) {
    HWTSTAMP_TX_OFF = 0,
    HWTSTAMP_TX_ON = 1,
    HWTSTAMP_TX_ONESTEP_SYNC = 2,
    HWTSTAMP_TX_ONESTEP_P2P = 3,
};

pub const HwTsRxFilter = enum(u32) {
    HWTSTAMP_FILTER_NONE = 0,
    HWTSTAMP_FILTER_ALL = 1,
    HWTSTAMP_FILTER_SOME = 2,
    HWTSTAMP_FILTER_PTP_V1_L4_EVENT = 3,
    HWTSTAMP_FILTER_PTP_V1_L4_SYNC = 4,
    HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ = 5,
    HWTSTAMP_FILTER_PTP_V2_L4_EVENT = 6,
    HWTSTAMP_FILTER_PTP_V2_L4_SYNC = 7,
    HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ = 8,
    HWTSTAMP_FILTER_PTP_V2_L2_EVENT = 9,
    HWTSTAMP_FILTER_PTP_V2_L2_SYNC = 10,
    HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ = 11,
    HWTSTAMP_FILTER_PTP_V2_EVENT = 12,
    HWTSTAMP_FILTER_PTP_V2_SYNC = 13,
    HWTSTAMP_FILTER_PTP_V2_DELAY_REQ = 14,
    HWTSTAMP_FILTER_NTP_ALL = 15,
};

// ============================================================================
// Cable Test
// ============================================================================

pub const EthtoolCableTest = struct {
    header_flags: u32,
    header_dev_index: u32,
    header_dev_name: [16]u8,
};

pub const EthtoolCableTestResult = enum(u8) {
    ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC = 0,
    ETHTOOL_A_CABLE_RESULT_CODE_OK = 1,
    ETHTOOL_A_CABLE_RESULT_CODE_OPEN = 2,
    ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT = 3,
    ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT = 4,
};

pub const EthtoolCableTestTdr = struct {
    header_flags: u32,
    header_dev_index: u32,
    first: u32,     // First TDR distance
    last: u32,      // Last TDR distance
    step: u32,      // TDR step
    pair: u8,       // Cable pair
};

// ============================================================================
// Module EEPROM
// ============================================================================

pub const EthtoolModuleInfo = struct {
    cmd: u32,
    module_type: EthtoolModuleType,
    eeprom_len: u32,
    reserved: [8]u32,
};

pub const EthtoolModuleType = enum(u32) {
    ETH_MODULE_SFF_8079 = 0x1,
    ETH_MODULE_SFF_8472 = 0x2,
    ETH_MODULE_SFF_8436 = 0x3,
    ETH_MODULE_SFF_8636 = 0x4,
    ETH_MODULE_SFF_8024 = 0x5,
    ETH_MODULE_CMIS = 0x6,
};

pub const EthtoolEeprom = struct {
    cmd: u32,
    magic: u32,
    offset: u32,
    len: u32,
    data: [256]u8,
};

// ============================================================================
// Ethtool Operations (netdev)
// ============================================================================

pub const EthtoolOps = struct {
    cap_link_lanes_supported: bool,
    cap_rss_ctx_supported: bool,
    cap_rss_sym_xor_supported: bool,
    supported_coalesce_params: u32,
    supported_ring_params: u32,
    get_drvinfo: ?*const fn (dev: *anyopaque, info: *EthtoolDrvinfo) callconv(.C) void,
    get_regs_len: ?*const fn (dev: *anyopaque) callconv(.C) i32,
    get_regs: ?*const fn (dev: *anyopaque, regs: *anyopaque, data: [*]u8) callconv(.C) void,
    get_wol: ?*const fn (dev: *anyopaque, wol: *anyopaque) callconv(.C) void,
    set_wol: ?*const fn (dev: *anyopaque, wol: *anyopaque) callconv(.C) i32,
    get_msglevel: ?*const fn (dev: *anyopaque) callconv(.C) u32,
    set_msglevel: ?*const fn (dev: *anyopaque, level: u32) callconv(.C) void,
    nway_reset: ?*const fn (dev: *anyopaque) callconv(.C) i32,
    get_link: ?*const fn (dev: *anyopaque) callconv(.C) u32,
    get_eeprom_len: ?*const fn (dev: *anyopaque) callconv(.C) i32,
    get_eeprom: ?*const fn (dev: *anyopaque, ee: *EthtoolEeprom, data: [*]u8) callconv(.C) i32,
    set_eeprom: ?*const fn (dev: *anyopaque, ee: *EthtoolEeprom, data: [*]const u8) callconv(.C) i32,
    get_coalesce: ?*const fn (dev: *anyopaque, coal: *EthtoolCoalesce, extack: ?*anyopaque) callconv(.C) i32,
    set_coalesce: ?*const fn (dev: *anyopaque, coal: *EthtoolCoalesce, extack: ?*anyopaque) callconv(.C) i32,
    get_ringparam: ?*const fn (dev: *anyopaque, ring: *EthtoolRingparam, extack: ?*anyopaque) callconv(.C) void,
    set_ringparam: ?*const fn (dev: *anyopaque, ring: *EthtoolRingparam, extack: ?*anyopaque) callconv(.C) i32,
    get_pauseparam: ?*const fn (dev: *anyopaque, pause: *EthtoolPauseparam) callconv(.C) void,
    set_pauseparam: ?*const fn (dev: *anyopaque, pause: *EthtoolPauseparam) callconv(.C) i32,
    self_test: ?*const fn (dev: *anyopaque, test_info: *EthtoolTest, data: [*]u64) callconv(.C) void,
    get_strings: ?*const fn (dev: *anyopaque, stringset: u32, data: [*]u8) callconv(.C) void,
    set_phys_id: ?*const fn (dev: *anyopaque, state: u32) callconv(.C) i32,
    get_ethtool_stats: ?*const fn (dev: *anyopaque, stats: *anyopaque, data: [*]u64) callconv(.C) void,
    get_sset_count: ?*const fn (dev: *anyopaque, sset: i32) callconv(.C) i32,
    get_priv_flags: ?*const fn (dev: *anyopaque) callconv(.C) u32,
    set_priv_flags: ?*const fn (dev: *anyopaque, flags: u32) callconv(.C) i32,
    get_rxnfc: ?*const fn (dev: *anyopaque, info: *anyopaque, rule_locs: ?[*]u32) callconv(.C) i32,
    set_rxnfc: ?*const fn (dev: *anyopaque, info: *anyopaque) callconv(.C) i32,
    flash_device: ?*const fn (dev: *anyopaque, flash: *anyopaque) callconv(.C) i32,
    reset: ?*const fn (dev: *anyopaque, flags: *u32) callconv(.C) i32,
    get_rxfh_key_size: ?*const fn (dev: *anyopaque) callconv(.C) u32,
    get_rxfh_indir_size: ?*const fn (dev: *anyopaque) callconv(.C) u32,
    get_rxfh: ?*const fn (dev: *anyopaque, rxfh: *EthtoolRxfh) callconv(.C) i32,
    set_rxfh: ?*const fn (dev: *anyopaque, rxfh: *const EthtoolRxfh, extack: ?*anyopaque) callconv(.C) i32,
    get_channels: ?*const fn (dev: *anyopaque, ch: *EthtoolChannels) callconv(.C) void,
    set_channels: ?*const fn (dev: *anyopaque, ch: *EthtoolChannels) callconv(.C) i32,
    get_dump_flag: ?*const fn (dev: *anyopaque, dump: *anyopaque) callconv(.C) i32,
    get_dump_data: ?*const fn (dev: *anyopaque, dump: *anyopaque, data: [*]u8) callconv(.C) i32,
    set_dump: ?*const fn (dev: *anyopaque, dump: *anyopaque) callconv(.C) i32,
    get_ts_info: ?*const fn (dev: *anyopaque, info: *EthtoolTsInfo) callconv(.C) i32,
    get_module_info: ?*const fn (dev: *anyopaque, modinfo: *EthtoolModuleInfo) callconv(.C) i32,
    get_module_eeprom: ?*const fn (dev: *anyopaque, ee: *EthtoolEeprom, data: [*]u8) callconv(.C) i32,
    get_eee: ?*const fn (dev: *anyopaque, eee: *EthtoolEee) callconv(.C) i32,
    set_eee: ?*const fn (dev: *anyopaque, eee: *EthtoolEee) callconv(.C) i32,
    get_link_ksettings: ?*const fn (dev: *anyopaque, cmd: *EthtoolLinkSettings) callconv(.C) i32,
    set_link_ksettings: ?*const fn (dev: *anyopaque, cmd: *const EthtoolLinkSettings) callconv(.C) i32,
    get_fecparam: ?*const fn (dev: *anyopaque, fec: *EthtoolFecParam) callconv(.C) i32,
    set_fecparam: ?*const fn (dev: *anyopaque, fec: *EthtoolFecParam) callconv(.C) i32,
    get_pause_stats: ?*const fn (dev: *anyopaque, stats: *EthtoolPauseStats) callconv(.C) void,
};

// ============================================================================
// Ethtool Netlink
// ============================================================================

pub const EthtoolNlCmd = enum(u8) {
    ETHTOOL_MSG_STRSET_GET = 1,
    ETHTOOL_MSG_LINKINFO_GET = 2,
    ETHTOOL_MSG_LINKINFO_SET = 3,
    ETHTOOL_MSG_LINKMODES_GET = 4,
    ETHTOOL_MSG_LINKMODES_SET = 5,
    ETHTOOL_MSG_LINKSTATE_GET = 6,
    ETHTOOL_MSG_DEBUG_GET = 7,
    ETHTOOL_MSG_DEBUG_SET = 8,
    ETHTOOL_MSG_WOL_GET = 9,
    ETHTOOL_MSG_WOL_SET = 10,
    ETHTOOL_MSG_FEATURES_GET = 11,
    ETHTOOL_MSG_FEATURES_SET = 12,
    ETHTOOL_MSG_PRIVFLAGS_GET = 13,
    ETHTOOL_MSG_PRIVFLAGS_SET = 14,
    ETHTOOL_MSG_RINGS_GET = 15,
    ETHTOOL_MSG_RINGS_SET = 16,
    ETHTOOL_MSG_CHANNELS_GET = 17,
    ETHTOOL_MSG_CHANNELS_SET = 18,
    ETHTOOL_MSG_COALESCE_GET = 19,
    ETHTOOL_MSG_COALESCE_SET = 20,
    ETHTOOL_MSG_PAUSE_GET = 21,
    ETHTOOL_MSG_PAUSE_SET = 22,
    ETHTOOL_MSG_EEE_GET = 23,
    ETHTOOL_MSG_EEE_SET = 24,
    ETHTOOL_MSG_TSINFO_GET = 25,
    ETHTOOL_MSG_CABLE_TEST_ACT = 26,
    ETHTOOL_MSG_CABLE_TEST_TDR_ACT = 27,
    ETHTOOL_MSG_TUNNEL_INFO_GET = 28,
    ETHTOOL_MSG_FEC_GET = 29,
    ETHTOOL_MSG_FEC_SET = 30,
    ETHTOOL_MSG_MODULE_EEPROM_GET = 31,
    ETHTOOL_MSG_STATS_GET = 32,
    ETHTOOL_MSG_PHC_VCLOCKS_GET = 33,
    ETHTOOL_MSG_MODULE_GET = 34,
    ETHTOOL_MSG_MODULE_SET = 35,
    ETHTOOL_MSG_PSE_GET = 36,
    ETHTOOL_MSG_PSE_SET = 37,
    ETHTOOL_MSG_RSS_GET = 38,
    ETHTOOL_MSG_PLCA_GET_CFG = 39,
    ETHTOOL_MSG_PLCA_SET_CFG = 40,
    ETHTOOL_MSG_PLCA_GET_STATUS = 41,
    ETHTOOL_MSG_MM_GET = 42,
    ETHTOOL_MSG_MM_SET = 43,
};

// ============================================================================
// PHY Tunable
// ============================================================================

pub const EthtoolPhyTunable = enum(u32) {
    ETHTOOL_PHY_DOWNSHIFT = 1,
    ETHTOOL_PHY_ENERGY_DETECT_POWER_DOWN = 2,
    ETHTOOL_PHY_FAST_LINK_DOWN = 3,
    ETHTOOL_PHY_EDPD = 4,
};

// ============================================================================
// WoL (Wake-on-LAN)
// ============================================================================

pub const EthtoolWolInfo = struct {
    cmd: u32,
    supported: WolModes,
    wolopts: WolModes,
    sopass: [6]u8,      // SecureOn password
};

pub const WolModes = packed struct(u32) {
    phy: bool,          // WAKE_PHY
    ucast: bool,        // WAKE_UCAST
    mcast: bool,        // WAKE_MCAST
    bcast: bool,        // WAKE_BCAST
    arp: bool,          // WAKE_ARP
    magic: bool,        // WAKE_MAGIC
    magicsecure: bool,  // WAKE_MAGICSECURE
    filter: bool,       // WAKE_FILTER
    _reserved: u24,
};

// ============================================================================
// Manager
// ============================================================================

pub const EthtoolManager = struct {
    total_get_ops: u64,
    total_set_ops: u64,
    total_self_tests: u64,
    total_cable_tests: u64,
    total_flash_ops: u64,
    total_reset_ops: u64,
    initialized: bool,

    pub fn init() EthtoolManager {
        return .{
            .total_get_ops = 0,
            .total_set_ops = 0,
            .total_self_tests = 0,
            .total_cable_tests = 0,
            .total_flash_ops = 0,
            .total_reset_ops = 0,
            .initialized = true,
        };
    }
};
