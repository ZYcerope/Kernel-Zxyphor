// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - WiFi/802.11 Internals Complete
// cfg80211, mac80211, nl80211 commands, management frames,
// BSS, Station, Key, Scan, Association, WPA/WPA3

const std = @import("std");

// ============================================================================
// IEEE 802.11 Frame Types
// ============================================================================

pub const Ieee80211FrameType = enum(u4) {
    Management = 0,
    Control = 1,
    Data = 2,
    Extension = 3,
};

pub const Ieee80211MgmtSubtype = enum(u4) {
    AssocReq = 0,
    AssocResp = 1,
    ReassocReq = 2,
    ReassocResp = 3,
    ProbeReq = 4,
    ProbeResp = 5,
    TimingAdv = 6,
    Reserved7 = 7,
    Beacon = 8,
    Atim = 9,
    Disassoc = 10,
    Auth = 11,
    Deauth = 12,
    Action = 13,
    ActionNoAck = 14,
    Reserved15 = 15,
};

pub const Ieee80211CtrlSubtype = enum(u4) {
    Reserved0 = 0,
    Reserved1 = 1,
    Trigger = 2,
    Tack = 3,
    BeamformingReportPoll = 4,
    NdpAnnouncement = 5,
    ControlFrameExtension = 6,
    ControlWrapper = 7,
    BlockAckReq = 8,
    BlockAck = 9,
    PsPoll = 10,
    Rts = 11,
    Cts = 12,
    Ack = 13,
    CfEnd = 14,
    CfEndAck = 15,
};

pub const Ieee80211FrameControl = packed struct(u16) {
    protocol_version: u2 = 0,
    frame_type: u2,
    subtype: u4,
    to_ds: bool = false,
    from_ds: bool = false,
    more_fragments: bool = false,
    retry: bool = false,
    power_management: bool = false,
    more_data: bool = false,
    protected_frame: bool = false,
    htc_order: bool = false,
};

pub const Ieee80211MgmtHeader = extern struct {
    frame_control: u16,
    duration_id: u16,
    da: [6]u8,
    sa: [6]u8,
    bssid: [6]u8,
    seq_ctrl: u16,
};

// ============================================================================
// WiFi Bands and Channels
// ============================================================================

pub const Nl80211Band = enum(u8) {
    Band2GHz = 0,
    Band5GHz = 1,
    Band60GHz = 2,
    Band6GHz = 3,
    BandS1GHz = 4,
    BandLC = 5,
    NUM_BANDS = 6,
};

pub const Ieee80211Channel = struct {
    center_freq: u32,
    freq_offset: u16,
    hw_value: u16,
    flags: ChannelFlags,
    max_antenna_gain: i32,
    max_power: i32,
    max_reg_power: i32,
    beacon_found: bool,
    dfs_state: DfsState,
    dfs_state_entered: u64,
    dfs_cac_ms: u32,
};

pub const ChannelFlags = packed struct(u32) {
    disabled: bool = false,
    no_ir: bool = false,
    radar: bool = false,
    no_ht40plus: bool = false,
    no_ht40minus: bool = false,
    no_ofdm: bool = false,
    no_80mhz: bool = false,
    no_160mhz: bool = false,
    indoor_only: bool = false,
    ir_concurrent: bool = false,
    no_20mhz: bool = false,
    no_10mhz: bool = false,
    no_he: bool = false,
    no_320mhz: bool = false,
    no_eht: bool = false,
    dfs_concurrent: bool = false,
    no_6ghz_vlp_client: bool = false,
    no_6ghz_afc_client: bool = false,
    _reserved: u14 = 0,
};

pub const DfsState = enum(u8) {
    Usable = 0,
    Unavailable = 1,
    Available = 2,
};

pub const ChannelWidth = enum(u8) {
    Width20NoHT = 0,
    Width20 = 1,
    Width40 = 2,
    Width80 = 3,
    Width80P80 = 4,
    Width160 = 5,
    Width5 = 6,
    Width10 = 7,
    Width1 = 8,
    Width2 = 9,
    Width4 = 10,
    Width8 = 11,
    Width16 = 12,
    Width320 = 13,
};

pub const Chandef = struct {
    chan: ?*Ieee80211Channel,
    width: ChannelWidth,
    center_freq1: u32,
    center_freq2: u32,
    freq1_offset: u16,
    edmg_bw_config: u8,
    edmg_channels: u8,
};

// ============================================================================
// IEEE 802.11 HT/VHT/HE/EHT Capabilities
// ============================================================================

pub const HtCapInfo = packed struct(u16) {
    ldpc_coding_cap: bool = false,
    channel_width_set: bool = false,
    sm_power_save: u2 = 0,
    greenfield: bool = false,
    short_gi_20mhz: bool = false,
    short_gi_40mhz: bool = false,
    tx_stbc: bool = false,
    rx_stbc: u2 = 0,
    delayed_ba: bool = false,
    max_amsdu_length: bool = false,
    dsss_cck_40: bool = false,
    _reserved: bool = false,
    forty_mhz_intolerant: bool = false,
    l_sig_txop_protection: bool = false,
};

pub const VhtCapInfo = packed struct(u32) {
    max_mpdu_length: u2 = 0,
    supported_channel_width: u2 = 0,
    rx_ldpc: bool = false,
    short_gi_80: bool = false,
    short_gi_160: bool = false,
    tx_stbc: bool = false,
    rx_stbc: u3 = 0,
    su_beamformer: bool = false,
    su_beamformee: bool = false,
    beamformee_sts: u3 = 0,
    sounding_dimensions: u3 = 0,
    mu_beamformer: bool = false,
    mu_beamformee: bool = false,
    vht_txop_ps: bool = false,
    htc_vht: bool = false,
    max_a_mpdu_exp: u3 = 0,
    vht_link_adapt: u2 = 0,
    rx_ant_pattern: bool = false,
    tx_ant_pattern: bool = false,
    ext_nss_bw: u2 = 0,
};

pub const HeCapElement = struct {
    mac_cap_info: [6]u8,
    phy_cap_info: [11]u8,
    optional: [48]u8,    // MCS/NSS + PPE thresholds
    optional_len: u8,
};

pub const EhtCapElement = struct {
    mac_cap_info: [2]u8,
    phy_cap_info: [9]u8,
    mcs_nss: [36]u8,
    mcs_nss_len: u8,
    ppe_thresholds: [32]u8,
    ppe_len: u8,
};

// ============================================================================
// cfg80211 BSS
// ============================================================================

pub const Cfg80211Bss = struct {
    channel: ?*Ieee80211Channel,
    chandef: Chandef,
    bssid: [6]u8,
    beacon_interval: u16,
    capability: u16,
    signal: i32,
    signal_type: SignalType,
    tsf: u64,
    last_seen_ms: u64,
    ies: ?*Cfg80211BssIes,
    beacon_ies: ?*Cfg80211BssIes,
    proberesp_ies: ?*Cfg80211BssIes,
    hidden_beacon_bss: ?*Cfg80211Bss,
    transmitted_bss: ?*Cfg80211Bss,
    refcount: i32,
};

pub const SignalType = enum(u8) {
    None = 0,
    Mbm = 1,
    Unspec = 2,
};

pub const Cfg80211BssIes = struct {
    data: [*]const u8,
    len: u32,
    tsf: u64,
    from_beacon: bool,
};

// ============================================================================
// cfg80211 Station Info
// ============================================================================

pub const StationInfoFlags = packed struct(u64) {
    inactive_time: bool = false,
    rx_bytes: bool = false,
    tx_bytes: bool = false,
    llid: bool = false,
    plid: bool = false,
    plink_state: bool = false,
    signal: bool = false,
    tx_bitrate: bool = false,
    rx_packets: bool = false,
    tx_packets: bool = false,
    tx_retries: bool = false,
    tx_failed: bool = false,
    rx_dropped_misc: bool = false,
    signal_avg: bool = false,
    rx_bitrate: bool = false,
    bss_param: bool = false,
    connected_time: bool = false,
    assoc_req_ies: bool = false,
    sta_flags: bool = false,
    beacon_loss_count: bool = false,
    t_offset: bool = false,
    local_pm: bool = false,
    peer_pm: bool = false,
    nonpeer_pm: bool = false,
    rx_bytes64: bool = false,
    tx_bytes64: bool = false,
    chain_signal: bool = false,
    chain_signal_avg: bool = false,
    expected_throughput: bool = false,
    rx_drop_misc: bool = false,
    beacon_rx: bool = false,
    beacon_signal_avg: bool = false,
    tid_stats: bool = false,
    rx_duration: bool = false,
    pad: bool = false,
    ack_signal: bool = false,
    ack_signal_avg: bool = false,
    rx_mpdus: bool = false,
    fcs_err_count: bool = false,
    airtime_weight: bool = false,
    airtime_link_metric: bool = false,
    assoc_at_boottime: bool = false,
    connected_to_gate: bool = false,
    connected_to_as: bool = false,
    _reserved: u20 = 0,
};

pub const StationInfo = struct {
    filled: StationInfoFlags,
    connected_time: u32,
    inactive_time: u32,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u32,
    tx_packets: u32,
    tx_retries: u32,
    tx_failed: u32,
    rx_dropped_misc: u32,
    signal: i8,
    signal_avg: i8,
    chain_signal: [4]i8,
    chain_signal_avg: [4]i8,
    chains: u8,
    txrate: RateInfo,
    rxrate: RateInfo,
    beacon_loss_count: u32,
    beacon_rx: u64,
    beacon_signal_avg: i8,
    rx_duration: u64,
    ack_signal: i8,
    ack_signal_avg: i8,
    expected_throughput: u32,
    fcs_err_count: u32,
    airtime_weight: u16,
};

pub const RateInfo = struct {
    flags: RateInfoFlags,
    mcs: u8,
    legacy: u16,         // in 100kbps
    nss: u8,
    bw: ChannelWidth,
    he_gi: u8,
    he_dcm: u8,
    he_ru_alloc: u16,
    n_bonded_ch: u8,
    eht_gi: u8,
    eht_ru_alloc: u16,
};

pub const RateInfoFlags = packed struct(u32) {
    mcs: bool = false,
    vht_mcs: bool = false,
    short_gi: bool = false,
    bw_60: bool = false,
    he_mcs: bool = false,
    eht_mcs: bool = false,
    edmg: bool = false,
    s1g_mcs: bool = false,
    _reserved: u24 = 0,
};

// ============================================================================
// Key Management
// ============================================================================

pub const KeyCipher = enum(u32) {
    WEP40 = 0x000FAC01,
    TKIP = 0x000FAC02,
    CCMP = 0x000FAC04,
    WEP104 = 0x000FAC05,
    CMAC = 0x000FAC06,
    GCMP = 0x000FAC08,
    GCMP256 = 0x000FAC09,
    CCMP256 = 0x000FAC0A,
    GMAC128 = 0x000FAC0B,
    GMAC256 = 0x000FAC0C,
    SMS4 = 0x00147201,
};

pub const KeyType = enum(u8) {
    Group = 0,
    Pairwise = 1,
    PeerKey = 2,
};

pub const KeyParams = struct {
    key: [32]u8,
    key_len: u8,
    cipher: u32,
    seq: [16]u8,
    seq_len: u8,
    pn: [6]u8,
    mode: u8,
};

pub const AkmSuite = enum(u32) {
    IEEE_8021X = 0x000FAC01,
    PSK = 0x000FAC02,
    FT_IEEE_8021X = 0x000FAC03,
    FT_PSK = 0x000FAC04,
    IEEE_8021X_SHA256 = 0x000FAC05,
    PSK_SHA256 = 0x000FAC06,
    TDLS = 0x000FAC07,
    SAE = 0x000FAC08,
    FT_SAE = 0x000FAC09,
    AP_PEER_KEY = 0x000FAC0A,
    IEEE_8021X_SUITE_B = 0x000FAC0B,
    IEEE_8021X_SUITE_B_192 = 0x000FAC0C,
    FT_IEEE_8021X_SHA384 = 0x000FAC0D,
    FILS_SHA256 = 0x000FAC0E,
    FILS_SHA384 = 0x000FAC0F,
    FT_FILS_SHA256 = 0x000FAC10,
    FT_FILS_SHA384 = 0x000FAC11,
    OWE = 0x000FAC12,
    PASN = 0x000FACFF,
};

// ============================================================================
// Scan Request
// ============================================================================

pub const ScanRequest = struct {
    wiphy: ?*anyopaque,
    ssids: [16]SsidEntry,
    n_ssids: u32,
    channels: [256]?*Ieee80211Channel,
    n_channels: u32,
    ie: [256]u8,
    ie_len: u32,
    flags: ScanFlags,
    rates: [6]u32,
    duration: u16,
    duration_mandatory: bool,
    no_cck: bool,
    scan_6ghz_params: [64]Scan6GhzParams,
    n_6ghz_params: u32,
};

pub const SsidEntry = struct {
    ssid: [32]u8,
    ssid_len: u8,
};

pub const ScanFlags = packed struct(u32) {
    low_priority: bool = false,
    flush: bool = false,
    ap: bool = false,
    random_addr: bool = false,
    fils_max_channel_time: bool = false,
    accept_bcast_probe_resp: bool = false,
    ocr_on_first_chan: bool = false,
    min_preq_content: bool = false,
    freq_kbz: bool = false,
    colocated_6ghz: bool = false,
    _reserved: u22 = 0,
};

pub const Scan6GhzParams = struct {
    short_ssid: u32,
    bssid: [6]u8,
    channel_idx: u8,
    unsolicited_probe: bool,
    short_ssid_valid: bool,
    psc_no_listen: bool,
};

// ============================================================================
// Connection/Association Parameters
// ============================================================================

pub const ConnectParams = struct {
    channel: ?*Ieee80211Channel,
    channel_hint: ?*Ieee80211Channel,
    bssid: ?[6]u8,
    bssid_hint: ?[6]u8,
    ssid: [32]u8,
    ssid_len: u8,
    auth_type: AuthType,
    ie: [512]u8,
    ie_len: u32,
    privacy: bool,
    mfp: MfpState,
    crypto: CryptoSettings,
    key_idx: u8,
    key_len: u8,
    key: [32]u8,
    flags: u32,
    ht_capa: [26]u8,
    ht_capa_mask: [26]u8,
    vht_capa: [12]u8,
    vht_capa_mask: [12]u8,
    fils_erp_username: [253]u8,
    fils_erp_realm: [253]u8,
    fils_erp_next_seq_num: u16,
    fils_erp_rrk: [64]u8,
    fils_erp_rrk_len: u8,
};

pub const AuthType = enum(u8) {
    OpenSystem = 0,
    SharedKey = 1,
    Ft = 2,
    NetworkEap = 3,
    Sae = 4,
    FilsSk = 5,
    FilsSkPfs = 6,
    FilsPk = 7,
    Automatic = 8,
};

pub const MfpState = enum(u8) {
    No = 0,
    Required = 1,
    Optional = 2,
};

pub const CryptoSettings = struct {
    wpa_versions: u32,
    cipher_group: u32,
    n_ciphers_pairwise: u32,
    ciphers_pairwise: [5]u32,
    n_akm_suites: u32,
    akm_suites: [8]u32,
    control_port: bool,
    control_port_ethertype: u16,
    control_port_no_encrypt: bool,
    control_port_over_nl80211: bool,
    control_port_no_preauth: bool,
    psk: ?[32]u8,
    sae_pwd: ?[128]u8,
};

// ============================================================================
// nl80211 Commands
// ============================================================================

pub const Nl80211Command = enum(u8) {
    Unspec = 0,
    GetWiphy = 1,
    SetWiphy = 2,
    NewWiphy = 3,
    DelWiphy = 4,
    GetInterface = 5,
    SetInterface = 6,
    NewInterface = 7,
    DelInterface = 8,
    GetKey = 9,
    SetKey = 10,
    NewKey = 11,
    DelKey = 12,
    GetBeacon = 13,
    SetBeacon = 14,
    StartAp = 15,
    StopAp = 16,
    GetStation = 17,
    SetStation = 18,
    NewStation = 19,
    DelStation = 20,
    GetMpath = 21,
    SetMpath = 22,
    NewMpath = 23,
    DelMpath = 24,
    SetBss = 25,
    SetReg = 26,
    ReqSetReg = 27,
    GetMeshConfig = 28,
    SetMeshConfig = 29,
    SetMgmtExtraIe = 30,
    GetReg = 31,
    GetScan = 32,
    TriggerScan = 33,
    NewScanResults = 34,
    ScanAborted = 35,
    RegChange = 36,
    Authenticate = 37,
    Associate = 38,
    Deauthenticate = 39,
    Disassociate = 40,
    MichaelMicFailure = 41,
    RegBeaconHint = 42,
    JoinIbss = 43,
    LeaveIbss = 44,
    Testmode = 45,
    Connect = 46,
    Roam = 47,
    Disconnect = 48,
    SetWiphyNetns = 49,
    GetSurvey = 50,
    NewSurveyResults = 51,
    SetPmksa = 52,
    DelPmksa = 53,
    FlushPmksa = 54,
    RemainOnChannel = 55,
    CancelRemainOnChannel = 56,
    SetTxBitrateMask = 57,
    RegisterFrame = 58,
    Frame = 59,
    FrameTxStatus = 60,
    SetPowerSave = 61,
    GetPowerSave = 62,
    SetCqm = 63,
    NotifyCqm = 64,
    SetChannel = 65,
};

pub const Nl80211Iftype = enum(u8) {
    Unspecified = 0,
    Adhoc = 1,
    Station = 2,
    Ap = 3,
    ApVlan = 4,
    Wds = 5,
    Monitor = 6,
    MeshPoint = 7,
    P2pClient = 8,
    P2pGo = 9,
    P2pDevice = 10,
    Ocb = 11,
    Nan = 12,
};

// ============================================================================
// WiFi Manager
// ============================================================================

pub const WifiManager = struct {
    total_wiphys: u32,
    total_interfaces: u32,
    total_stations: u32,
    total_bss: u32,
    scan_in_progress: bool,
    current_band: Nl80211Band,
    current_channel: u32,
    current_width: ChannelWidth,
    supported_bands: [6]bool,
    total_scan_results: u64,
    total_associations: u64,
    total_deauths: u64,
    total_disassocs: u64,
    wpa3_supported: bool,
    he_supported: bool,
    eht_supported: bool,
    mlo_supported: bool,
    initialized: bool,

    pub fn init() WifiManager {
        return .{
            .total_wiphys = 0,
            .total_interfaces = 0,
            .total_stations = 0,
            .total_bss = 0,
            .scan_in_progress = false,
            .current_band = .Band2GHz,
            .current_channel = 0,
            .current_width = .Width20,
            .supported_bands = [_]bool{false} ** 6,
            .total_scan_results = 0,
            .total_associations = 0,
            .total_deauths = 0,
            .total_disassocs = 0,
            .wpa3_supported = true,
            .he_supported = true,
            .eht_supported = true,
            .mlo_supported = true,
            .initialized = true,
        };
    }
};
