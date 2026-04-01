// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Wireless/Wi-Fi 7 Stack
// IEEE 802.11be (Wi-Fi 7), MLO, nl80211/cfg80211, WPA3, SAE,
// 802.11ax (Wi-Fi 6E), regulatory domains, mesh, TDLS, DFS
// More advanced than Linux 2026 wireless stack

const std = @import("std");

// ============================================================================
// IEEE 802.11 Frame Types
// ============================================================================

pub const Ieee80211FrameType = enum(u8) {
    management = 0,
    control = 1,
    data = 2,
    extension = 3,
};

pub const Ieee80211MgmtSubtype = enum(u4) {
    assoc_request = 0,
    assoc_response = 1,
    reassoc_request = 2,
    reassoc_response = 3,
    probe_request = 4,
    probe_response = 5,
    timing_advertisement = 6,
    beacon = 8,
    atim = 9,
    disassoc = 10,
    auth = 11,
    deauth = 12,
    action = 13,
    action_no_ack = 14,
};

pub const Ieee80211Header = extern struct {
    frame_control: u16,
    duration_id: u16,
    addr1: [6]u8,
    addr2: [6]u8,
    addr3: [6]u8,
    seq_ctrl: u16,

    pub fn protocol_version(self: *const Ieee80211Header) u2 {
        return @truncate(self.frame_control & 0x03);
    }

    pub fn frame_type(self: *const Ieee80211Header) u2 {
        return @truncate((self.frame_control >> 2) & 0x03);
    }

    pub fn subtype(self: *const Ieee80211Header) u4 {
        return @truncate((self.frame_control >> 4) & 0x0F);
    }

    pub fn to_ds(self: *const Ieee80211Header) bool {
        return (self.frame_control & 0x0100) != 0;
    }

    pub fn from_ds(self: *const Ieee80211Header) bool {
        return (self.frame_control & 0x0200) != 0;
    }

    pub fn is_protected(self: *const Ieee80211Header) bool {
        return (self.frame_control & 0x4000) != 0;
    }

    pub fn sequence_number(self: *const Ieee80211Header) u12 {
        return @truncate(self.seq_ctrl >> 4);
    }

    pub fn fragment_number(self: *const Ieee80211Header) u4 {
        return @truncate(self.seq_ctrl & 0x0F);
    }
};

// ============================================================================
// Wi-Fi Generations
// ============================================================================

pub const WifiGeneration = enum(u8) {
    wifi_1 = 1,      // 802.11b
    wifi_2 = 2,      // 802.11a
    wifi_3 = 3,      // 802.11g
    wifi_4 = 4,      // 802.11n (HT)
    wifi_5 = 5,      // 802.11ac (VHT)
    wifi_6 = 6,      // 802.11ax (HE)
    wifi_6e = 7,     // 802.11ax 6GHz
    wifi_7 = 8,      // 802.11be (EHT)
    zxy_wifi_8 = 9,  // Zxyphor next-gen
};

pub const WifiBand = enum(u8) {
    band_2ghz = 0,
    band_5ghz = 1,
    band_6ghz = 2,
    band_60ghz = 3,  // WiGig
};

// ============================================================================
// Channel Definition
// ============================================================================

pub const Ieee80211Channel = struct {
    center_freq: u32,   // MHz
    band: WifiBand,
    hw_value: u16,
    flags: u32,
    max_antenna_gain: i32,
    max_power: i32,     // dBm
    max_reg_power: i32,
    dfs_state: DfsState,
    dfs_state_entered: u64,
    dfs_cac_ms: u32,
    indoor_only: bool,
};

pub const ChannelWidth = enum(u8) {
    width_20_noht = 0,
    width_20 = 1,
    width_40 = 2,
    width_80 = 3,
    width_80p80 = 4,
    width_160 = 5,
    width_320 = 6,      // Wi-Fi 7
    width_5 = 7,
    width_10 = 8,
};

pub const ChanDef = struct {
    chan: ?*Ieee80211Channel,
    width: ChannelWidth,
    center_freq1: u32,
    center_freq2: u32,   // For 80+80
    freq1_offset: u32,
    edmg_bw_config: u8,
    edmg_channels: u8,
    punctured_bitmap: u16,  // Wi-Fi 7 preamble puncturing
};

pub const DfsState = enum(u8) {
    usable = 0,
    unavailable = 1,
    available = 2,
};

// ============================================================================
// Regulatory Domain
// ============================================================================

pub const RegulatoryDomain = enum(u16) {
    world = 0x00,
    fcc = 0x10,      // US
    etsi = 0x30,     // EU
    mkk = 0x40,      // Japan
    cn = 0x50,       // China
    kr = 0x60,       // Korea
    in = 0x70,       // India
};

pub const RegRule = struct {
    freq_range_start: u32,
    freq_range_end: u32,
    max_bandwidth: u32,
    max_antenna_gain: i32,
    max_eirp: i32,
    flags: u32,
    dfs_cac_ms: u32,
};

pub const RegulatoryRequest = struct {
    initiator: RegInitiator,
    wiphy_idx: i32,
    alpha2: [2]u8,
    dfs_region: DfsRegion,
    intersect: bool,
    country_ie_env: u8,
};

pub const RegInitiator = enum(u8) {
    core = 0,
    user = 1,
    driver = 2,
    country_ie = 3,
};

pub const DfsRegion = enum(u8) {
    unset = 0,
    fcc = 1,
    etsi = 2,
    jp = 3,
};

// ============================================================================
// Wi-Fi 7 (802.11be) - EHT (Extremely High Throughput)
// ============================================================================

pub const EhtCapabilities = struct {
    // EHT MAC Capabilities
    epcs_priority_access: bool,
    om_control: bool,
    triggered_txop_sharing: bool,
    restricted_twt: bool,
    scs_traffic_description: bool,
    max_mpdu_length: u2,     // 0=3895, 1=7991, 2=11454
    max_a_mpdu_exp: u8,

    // EHT PHY Capabilities
    supports_320mhz_in_6ghz: bool,
    supports_242_tone_ru_in_bw_wider_than_20: bool,
    ndp_4x_eht_ltf_3_2us_gi: bool,
    partial_bandwidth_dl_mu_mimo: bool,
    su_beamformer: bool,
    su_beamformee: bool,
    beamformee_ss_80mhz: u8,
    beamformee_ss_160mhz: u8,
    beamformee_ss_320mhz: u8,
    sounding_dim_80mhz: u8,
    sounding_dim_160mhz: u8,
    sounding_dim_320mhz: u8,
    max_nc: u8,
    non_ofdma_ul_mu_mimo_80mhz: bool,
    non_ofdma_ul_mu_mimo_160mhz: bool,
    non_ofdma_ul_mu_mimo_320mhz: bool,
    mu_beamformer_80mhz: bool,
    mu_beamformer_160mhz: bool,
    mu_beamformer_320mhz: bool,
    eht_ppe_thresholds_present: bool,
    // MCS/NSS support
    mcs_map_20: [4]u8,
    mcs_map_80: [4]u8,
    mcs_map_160: [4]u8,
    mcs_map_320: [4]u8,
    // 4096-QAM support
    supports_4k_qam: bool,
};

pub const EhtMcsNssMap = struct {
    rx_max_nss: [14]u8,  // Per MCS 0-13
    tx_max_nss: [14]u8,
};

// ============================================================================
// Multi-Link Operation (MLO) - Wi-Fi 7
// ============================================================================

pub const MLO_MAX_LINKS: u32 = 15;

pub const MloLink = struct {
    link_id: u8,
    addr: [6]u8,
    channel: ChanDef,
    active: bool,
    disabled: bool,
    // Link stats
    rssi: i32,
    noise: i32,
    tx_rate: u64,    // bps
    rx_rate: u64,
    // EMLSR/EMLMR
    emlsr_enabled: bool,
    emlmr_enabled: bool,
    emlsr_transition_delay_us: u32,
    emlsr_padding_delay_us: u32,
    // TID-to-link mapping
    tid_bitmap: u16,
};

pub const MloConfig = struct {
    mld_addr: [6]u8,
    links: [MLO_MAX_LINKS]MloLink,
    nr_links: u8,
    // EMLSR (Enhanced Multi-Link Single Radio)
    emlsr_support: bool,
    emlsr_transition_timeout_us: u32,
    // EMLMR (Enhanced Multi-Link Multi Radio)
    emlmr_support: bool,
    // T2LM (TID-to-Link Mapping)
    t2lm_negotiation_support: u8,  // 0=none, 1=same, 2=different
    // NSTR (Non-Simultaneous Transmit and Receive)
    nstr_indication: bool,
    // STR (Simultaneous Transmit and Receive)
    str_bitmap: u16,
};

// ============================================================================
// Security - WPA3 / SAE / OWE
// ============================================================================

pub const WifiSecurity = enum(u8) {
    open = 0,
    wep = 1,       // Deprecated
    wpa = 2,       // Deprecated
    wpa2_personal = 3,
    wpa2_enterprise = 4,
    wpa3_personal = 5,   // SAE
    wpa3_enterprise = 6,
    wpa3_enterprise_192 = 7,
    owe = 8,             // Opportunistic Wireless Encryption
    enhanced_open = 9,
    wpa3_personal_transition = 10,
    // Zxyphor
    zxy_quantum_safe = 11,
};

pub const AkmSuite = enum(u32) {
    ieee8021x = 0x000FAC01,
    psk = 0x000FAC02,
    ft_ieee8021x = 0x000FAC03,
    ft_psk = 0x000FAC04,
    ieee8021x_sha256 = 0x000FAC05,
    psk_sha256 = 0x000FAC06,
    tdls = 0x000FAC07,
    sae = 0x000FAC08,
    ft_sae = 0x000FAC09,
    ap_peerkey = 0x000FAC0A,
    ieee8021x_suite_b = 0x000FAC0B,
    ieee8021x_suite_b_192 = 0x000FAC0C,
    ft_ieee8021x_sha384 = 0x000FAC0D,
    fils_sha256 = 0x000FAC0E,
    fils_sha384 = 0x000FAC0F,
    ft_fils_sha256 = 0x000FAC10,
    ft_fils_sha384 = 0x000FAC11,
    owe = 0x000FAC12,
    ft_psk_sha384 = 0x000FAC13,
    psk_sha384 = 0x000FAC14,
    pasn = 0x000FAC15,
    sae_ext_key = 0x000FAC18,
    ft_sae_ext_key = 0x000FAC19,
};

pub const CipherSuite = enum(u32) {
    use_group = 0x000FAC00,
    wep40 = 0x000FAC01,
    tkip = 0x000FAC02,
    ccmp = 0x000FAC04,
    wep104 = 0x000FAC05,
    bip_cmac_128 = 0x000FAC06,
    no_group_addressed = 0x000FAC07,
    gcmp_128 = 0x000FAC08,
    gcmp_256 = 0x000FAC09,
    ccmp_256 = 0x000FAC0A,
    bip_gmac_128 = 0x000FAC0B,
    bip_gmac_256 = 0x000FAC0C,
    bip_cmac_256 = 0x000FAC0D,
};

pub const SaeGroup = enum(u16) {
    ecc_p256 = 19,
    ecc_p384 = 20,
    ecc_p521 = 21,
    ffc_3072 = 15,
    ffc_4096 = 16,
    ecc_brainpool_p256 = 28,
    ecc_brainpool_p384 = 29,
    ecc_brainpool_p512 = 30,
};

pub const SaeState = struct {
    group: SaeGroup,
    state: enum(u8) { nothing, committed, confirmed, accepted },
    send_confirm: u16,
    peer_commit_scalar: [64]u8,
    peer_commit_element: [128]u8,
    own_commit_scalar: [64]u8,
    own_commit_element: [128]u8,
    pmk: [48]u8,
    pmkid: [16]u8,
    kck: [32]u8,
    // H2E (Hash-to-Element)
    h2e: bool,
    // PK (Public Key)
    pk_enabled: bool,
    // Anti-clogging token
    token: [256]u8,
    token_len: u16,
};

// ============================================================================
// cfg80211 / nl80211 Interface Types
// ============================================================================

pub const Nl80211Iftype = enum(u8) {
    unspecified = 0,
    adhoc = 1,
    station = 2,
    ap = 3,
    ap_vlan = 4,
    wds = 5,
    monitor = 6,
    mesh_point = 7,
    p2p_client = 8,
    p2p_go = 9,
    p2p_device = 10,
    ocb = 11,
    nan = 12,
};

pub const StationInfo = struct {
    connected_time: u32,  // seconds
    inactive_time: u32,   // ms
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    tx_retries: u64,
    tx_failed: u64,
    rx_dropped_misc: u64,
    signal: i8,           // dBm
    signal_avg: i8,
    tx_bitrate: u64,      // 100 kbps
    rx_bitrate: u64,
    // MFP
    mfp: bool,
    // Capabilities
    ht_cap: bool,
    vht_cap: bool,
    he_cap: bool,
    eht_cap: bool,
    // Auth
    authorized: bool,
    authenticated: bool,
    associated: bool,
    // Power management
    ps_enabled: bool,
    // WiFi 7
    mlo_link_id: u8,
    assoc_link_bitmask: u16,
};

pub const BssInfo = struct {
    bssid: [6]u8,
    ssid: [32]u8,
    ssid_len: u8,
    channel: ChanDef,
    signal: i32,      // mBm
    beacon_interval: u16,
    capability: u16,
    tsf: u64,
    // Security
    privacy: bool,
    wpa: bool,
    rsn: bool,
    akm_suites: [8]AkmSuite,
    nr_akm_suites: u8,
    pairwise_cipher: CipherSuite,
    group_cipher: CipherSuite,
    // 802.11k/v/r
    rrm_enabled: bool,
    bss_transition: bool,
    ft_enabled: bool,
    // Wi-Fi 7
    eht_capable: bool,
    mlo_capable: bool,
};

// ============================================================================
// Power Management
// ============================================================================

pub const WifiPowerMode = enum(u8) {
    active = 0,
    ps_poll = 1,      // Legacy PS
    uapsd = 2,        // Unscheduled APSD
    twt = 3,          // Target Wake Time (Wi-Fi 6)
    restricted_twt = 4,// Wi-Fi 7
    // Zxyphor
    zxy_adaptive = 5,  // ML-based adaptive
};

pub const TwtSetup = struct {
    flow_id: u8,
    flow_type: enum(u1) { announced = 0, unannounced = 1 },
    trigger: bool,
    implicit: bool,
    protection: bool,
    wake_interval_mantissa: u16,
    wake_interval_exponent: u8,
    min_wake_duration: u16,
    channel: u8,
    // Broadcast TWT
    broadcast: bool,
    bcast_id: u8,
    // Restricted TWT (Wi-Fi 7)
    restricted: bool,
};

// ============================================================================
// Rate Control
// ============================================================================

pub const RateInfo = struct {
    flags: u32,
    mcs: u8,
    legacy: u16,
    nss: u8,
    bw: ChannelWidth,
    he_gi: u8,     // 0=0.8us, 1=1.6us, 2=3.2us
    he_dcm: u8,
    he_ru_alloc: u16,
    eht_gi: u8,
    eht_ru_alloc: u16,
};

pub const RateControlAlgorithm = enum(u8) {
    minstrel = 0,        // Minstrel
    minstrel_ht = 1,     // Minstrel HT
    iwl_mvm_rs = 2,      // Intel driver
    ath_rate = 3,         // Atheros
    // Zxyphor
    zxy_ml_rate = 4,     // ML-based rate adaptation
};

pub const MinstrelHtStats = struct {
    // Per-group stats
    supported: u16,
    max_tp_rate: [4]u16,
    max_prob_rate: u16,
    // Per-rate stats
    attempts: u64,
    success: u64,
    last_attempts: u32,
    last_success: u32,
    cur_prob: u32,       // scaled by 2^18
    cur_tp: u32,         // Throughput, scaled by 2^18
    // EWMA
    prob_ewma: u32,
    // Retry chain
    retry_count: u8,
    retry_count_rtscts: u8,
    sample_skipped: u8,
};

// ============================================================================
// Mesh Networking (802.11s)
// ============================================================================

pub const MeshConfig = struct {
    mesh_id: [32]u8,
    mesh_id_len: u8,
    path_sel_protocol: u8,    // HWMP
    path_sel_metric: u8,      // Airtime Link Metric
    congestion_control: u8,
    sync_method: u8,
    auth_protocol: u8,
    // Peering
    mesh_max_peer_links: u16,
    mesh_max_retries: u8,
    mesh_ttl: u8,
    mesh_element_ttl: u8,
    mesh_auto_open_plinks: bool,
    // HWMP
    hwmp_max_preq_retries: u8,
    hwmp_path_timeout: u32,
    hwmp_preq_min_interval: u16,
    hwmp_peering_min_interval: u16,
    hwmp_net_diameter_traversal_time: u16,
    hwmp_rootmode: u8,
    hwmp_rann_interval: u16,
    hwmp_confirmation_interval: u16,
    // Gate
    mesh_gate_announcements: bool,
    // Power mode
    mesh_power_mode: WifiPowerMode,
    // Connected to AS
    mesh_connected_to_as: bool,
    mesh_connected_to_gate: bool,
    // Forwarding
    mesh_forwarding: bool,
    // SAE
    mesh_auth_id: u8,
    // Zxyphor
    zxy_mesh_optimization: bool,
};

pub const MeshPath = struct {
    dst: [6]u8,
    next_hop: [6]u8,
    metric: u32,
    sn: u32,        // Destination Sequence Number
    hop_count: u8,
    exp_time: u64,
    flags: u32,
    is_root: bool,
    is_gate: bool,
    gate_timeout: u64,
};

// ============================================================================
// TDLS (Tunneled Direct Link Setup) - 802.11z
// ============================================================================

pub const TdlsState = enum(u8) {
    disabled = 0,
    peer_setup_req = 1,
    peer_setup_resp = 2,
    peer_setup_confirm = 3,
    established = 4,
    teardown = 5,
};

pub const TdlsPeer = struct {
    addr: [6]u8,
    state: TdlsState,
    capability: u16,
    supported_rates: [32]u8,
    nr_supported_rates: u8,
    ht_cap: bool,
    vht_cap: bool,
    he_cap: bool,
    eht_cap: bool,
    // Channel switch
    chan_switch_enabled: bool,
    oper_chan: ChanDef,
    // Link
    rssi: i32,
    last_activity: u64,
};

// ============================================================================
// Roaming / 802.11r (FT) / 802.11k (RRM) / 802.11v (BSS TM)
// ============================================================================

pub const RoamingConfig = struct {
    // 802.11r (Fast BSS Transition)
    ft_enabled: bool,
    ft_over_ds: bool,     // Over Distribution System
    ft_over_air: bool,    // Over Air
    ft_psk: bool,
    ft_sae: bool,
    mobility_domain: u16,
    r0kh_id: [48]u8,
    r0kh_id_len: u8,
    r1kh_id: [6]u8,

    // 802.11k (Radio Resource Measurement)
    rrm_enabled: bool,
    rrm_beacon_report: bool,
    rrm_neighbor_report: bool,
    rrm_link_measurement: bool,
    rrm_channel_load: bool,
    rrm_noise_histogram: bool,

    // 802.11v (BSS Transition Management)
    btm_enabled: bool,
    btm_disassociation_imminent: bool,
    btm_ess_disassociation_imminent: bool,
    btm_url: [256]u8,
    btm_url_len: u16,

    // Thresholds
    rssi_threshold: i32,
    hysteresis: u32,
    scan_interval_ms: u32,
    // Zxyphor
    zxy_predictive_roaming: bool,
    zxy_ai_bss_selection: bool,
};

// ============================================================================
// Driver Interface
// ============================================================================

pub const WiphyBands = struct {
    band_2ghz: ?*WifiBandInfo,
    band_5ghz: ?*WifiBandInfo,
    band_6ghz: ?*WifiBandInfo,
    band_60ghz: ?*WifiBandInfo,
};

pub const WifiBandInfo = struct {
    channels: [256]Ieee80211Channel,
    nr_channels: u32,
    bitrates: [64]WifiBitrate,
    nr_bitrates: u32,
    // HT capabilities
    ht_supported: bool,
    ht_cap: u16,
    // VHT
    vht_supported: bool,
    vht_cap: u32,
    // HE (Wi-Fi 6)
    he_supported: bool,
    he_cap_elem: [8]u8,
    // EHT (Wi-Fi 7)
    eht_supported: bool,
    eht_cap: EhtCapabilities,
};

pub const WifiBitrate = struct {
    bitrate: u16,   // 100kbps units
    flags: u16,
    hw_value: u16,
    hw_value_short: u16,
};

pub const WirelessSubsystem = struct {
    // Registered interfaces
    nr_interfaces: u32,
    // Regulatory
    current_regulatory: RegulatoryDomain,
    alpha2: [2]u8,
    dfs_region: DfsRegion,
    // Rate control
    rate_algo: RateControlAlgorithm,
    // Stats
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    total_tx_packets: u64,
    total_rx_packets: u64,
    total_connections: u64,
    total_disconnections: u64,
    total_roams: u64,
    scan_count: u64,
    // Wi-Fi 7 specific
    mlo_enabled: bool,
    eht_enabled: bool,
    // Mesh
    mesh_interfaces: u32,
    // TDLS
    tdls_peers: u32,
    // Power
    default_power_mode: WifiPowerMode,
    // Zxyphor
    zxy_wifi8_preview: bool,
    initialized: bool,
};
