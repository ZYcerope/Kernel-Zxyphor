// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Bluetooth/BLE Protocol Stack
// Classic Bluetooth (BR/EDR), Bluetooth Low Energy (BLE 5.4+),
// HCI transport, L2CAP, RFCOMM, SDP, GATT/ATT, LE Audio, Mesh
// More advanced than Linux 2026 Bluetooth stack

const std = @import("std");

// ============================================================================
// HCI (Host Controller Interface)
// ============================================================================

pub const HciDevType = enum(u8) {
    bredr = 0x00,       // BR/EDR (Classic Bluetooth)
    amp = 0x01,         // AMP (Alternate MAC/PHY)
    le = 0x02,          // LE only
    dual = 0x03,        // Dual-mode BR/EDR + LE
};

pub const HciDevFlags = packed struct(u64) {
    up: bool = false,
    init: bool = false,
    running: bool = false,
    raw: bool = false,
    auth: bool = false,
    encrypt: bool = false,
    inquiry: bool = false,
    scan_le: bool = false,
    connectable: bool = false,
    discoverable: bool = false,
    bondable: bool = false,
    privacy: bool = false,
    advertising: bool = false,
    secure_connections: bool = false,
    wide_band_speech: bool = false,
    debug_keys: bool = false,
    fast_connectable: bool = false,
    bredr_enabled: bool = false,
    le_enabled: bool = false,
    // BT 5.0+
    extended_advertising: bool = false,
    periodic_advertising: bool = false,
    coded_phy: bool = false,
    // BT 5.1
    aoa_aod: bool = false,     // Angle of Arrival/Departure
    // BT 5.2
    iso_channels: bool = false,
    le_power_control: bool = false,
    // BT 5.3
    channel_classification: bool = false,
    connection_subrating: bool = false,
    // BT 5.4
    periodic_adv_transport: bool = false,
    // Zxyphor
    zxy_quantum_pairing: bool = false,
    zxy_ultra_low_latency: bool = false,
    _reserved: u34 = 0,
};

pub const HciCommandOpcode = enum(u16) {
    // Link Control
    inquiry = 0x0401,
    inquiry_cancel = 0x0402,
    create_connection = 0x0405,
    disconnect = 0x0406,
    accept_connection = 0x0409,
    reject_connection = 0x040a,
    link_key_reply = 0x040b,
    pin_code_reply = 0x040d,
    auth_requested = 0x0411,
    set_conn_encrypt = 0x0413,
    remote_name_req = 0x0419,
    read_remote_features = 0x041b,
    read_remote_ext_features = 0x041c,
    read_remote_version = 0x041d,
    // Link Policy
    sniff_mode = 0x0803,
    exit_sniff_mode = 0x0804,
    role_discovery = 0x0809,
    switch_role = 0x080b,
    read_link_policy = 0x080c,
    write_link_policy = 0x080d,
    // Controller & Baseband
    set_event_mask = 0x0c01,
    reset = 0x0c03,
    set_event_filter = 0x0c05,
    write_local_name = 0x0c13,
    read_local_name = 0x0c14,
    write_conn_accept_timeout = 0x0c16,
    write_page_timeout = 0x0c18,
    write_scan_enable = 0x0c1a,
    write_page_scan_activity = 0x0c1c,
    write_inquiry_scan_activity = 0x0c1e,
    write_auth_enable = 0x0c20,
    write_class_of_device = 0x0c24,
    read_tx_power = 0x0c2d,
    write_ssp_mode = 0x0c56,
    write_le_host_supported = 0x0c6d,
    write_secure_connections = 0x0c7a,
    // Informational
    read_local_version = 0x1001,
    read_local_commands = 0x1002,
    read_local_features = 0x1003,
    read_local_ext_features = 0x1004,
    read_buffer_size = 0x1005,
    read_bd_addr = 0x1009,
    // Status
    read_rssi = 0x1405,
    // LE Controller
    le_set_event_mask = 0x2001,
    le_read_buffer_size = 0x2002,
    le_set_adv_params = 0x2006,
    le_set_adv_data = 0x2008,
    le_set_scan_resp_data = 0x2009,
    le_set_adv_enable = 0x200a,
    le_set_scan_params = 0x200b,
    le_set_scan_enable = 0x200c,
    le_create_connection = 0x200d,
    le_read_whilelist_size = 0x200f,
    le_clear_whitelist = 0x2010,
    le_add_whitelist = 0x2011,
    le_conn_update = 0x2013,
    le_rand = 0x2018,
    le_start_encryption = 0x2019,
    le_read_supported_states = 0x201c,
    // LE 5.0
    le_set_ext_adv_params = 0x2036,
    le_set_ext_adv_data = 0x2037,
    le_set_ext_scan_resp = 0x2038,
    le_set_ext_adv_enable = 0x2039,
    le_ext_create_conn = 0x2043,
    le_set_periodic_adv_params = 0x203e,
    // LE 5.2 (ISO)
    le_set_cig_params = 0x2062,
    le_create_cis = 0x2064,
    le_setup_iso_data_path = 0x206e,
    // LE 5.3
    le_set_default_subrate = 0x207d,
    le_subrate_request = 0x207e,
    _,
};

pub const HciEventCode = enum(u8) {
    inquiry_complete = 0x01,
    inquiry_result = 0x02,
    conn_complete = 0x03,
    conn_request = 0x04,
    disconn_complete = 0x05,
    auth_complete = 0x06,
    remote_name = 0x07,
    encrypt_change = 0x08,
    change_link_key = 0x09,
    remote_features = 0x0b,
    remote_version = 0x0c,
    cmd_complete = 0x0e,
    cmd_status = 0x0f,
    hardware_error = 0x10,
    role_change = 0x12,
    num_comp_pkts = 0x13,
    mode_change = 0x14,
    pin_code_req = 0x16,
    link_key_req = 0x17,
    link_key_notify = 0x18,
    clock_offset = 0x1c,
    pkt_type_change = 0x1d,
    inquiry_result_rssi = 0x22,
    remote_ext_features = 0x23,
    sync_conn_complete = 0x2c,
    ext_inquiry_result = 0x2f,
    encrypt_key_refresh = 0x30,
    io_capa_request = 0x31,
    io_capa_reply = 0x32,
    user_confirm_req = 0x33,
    user_passkey_req = 0x34,
    simple_pair_complete = 0x36,
    le_meta_event = 0x3e,
    num_comp_blocks = 0x48,
    _,
};

pub const BdAddr = struct {
    b: [6]u8,

    pub fn is_zero(self: *const BdAddr) bool {
        for (self.b) |byte| {
            if (byte != 0) return false;
        }
        return true;
    }

    pub fn addr_type(self: *const BdAddr) BdAddrType {
        if (self.b[5] & 0xC0 == 0xC0) return .random_static;
        if (self.b[5] & 0xC0 == 0x40) return .random_resolvable;
        if (self.b[5] & 0xC0 == 0x00) return .random_non_resolvable;
        return .public;
    }
};

pub const BdAddrType = enum(u8) {
    public = 0,
    random_static = 1,
    random_resolvable = 2,
    random_non_resolvable = 3,
};

pub const HciDevice = struct {
    id: u32,
    name: [248]u8,
    dev_type: HciDevType,
    bus_type: HciBusType,
    // Address
    bdaddr: BdAddr,
    // Features
    features: [8][8]u8,       // 8 pages of features
    le_features: [8]u8,
    commands: [64]u8,
    // Flags
    dev_flags: HciDevFlags,
    // Parameters
    acl_mtu: u16,
    acl_max_pkt: u16,
    sco_mtu: u16,
    sco_max_pkt: u16,
    le_mtu: u16,
    le_max_pkt: u16,
    iso_mtu: u16,
    iso_max_pkt: u16,
    // Version
    hci_ver: u8,
    hci_rev: u16,
    lmp_ver: u8,
    lmp_subver: u16,
    manufacturer: u16,
    // State
    conn_count: u16,
    // Class of Device
    dev_class: [3]u8,
    // Power
    tx_power_class: u8,
    le_tx_power_min: i8,
    le_tx_power_max: i8,
    // Advertising
    adv_instance_cnt: u8,
    // Resolving list
    le_resolv_list_size: u8,
    // Filter accept list
    le_accept_list_size: u8,
    // Stats
    stat_acl_tx: u64,
    stat_acl_rx: u64,
    stat_sco_tx: u64,
    stat_sco_rx: u64,
    stat_le_tx: u64,
    stat_le_rx: u64,
    stat_iso_tx: u64,
    stat_iso_rx: u64,
    stat_err_tx: u64,
    stat_err_rx: u64,
    stat_cmd_tx: u64,
    stat_evt_rx: u64,
};

pub const HciBusType = enum(u8) {
    virtual = 0,
    usb = 1,
    pccard = 2,
    uart = 3,
    rs232 = 4,
    pci = 5,
    sdio = 6,
    spi = 7,
    i2c = 8,
    smd = 9,
    virtio = 10,
    ipc = 11,
};

// ============================================================================
// L2CAP (Logical Link Control and Adaptation Protocol)
// ============================================================================

pub const L2capCid = enum(u16) {
    signaling = 0x0001,
    connectionless = 0x0002,
    amp_manager = 0x0003,
    att = 0x0004,
    le_signaling = 0x0005,
    smp = 0x0006,
    smp_bredr = 0x0007,
    _,
};

pub const L2capMode = enum(u8) {
    basic = 0,
    retransmission = 1,
    flow_control = 2,
    ertm = 3,             // Enhanced Retransmission Mode
    streaming = 4,
    le_flowctl = 5,        // LE Flow Control (CoC)
    ecred = 6,             // Enhanced Credit Based
};

pub const L2capChannel = struct {
    // Identifiers
    scid: u16,             // Source CID
    dcid: u16,             // Destination CID
    psm: u16,              // Protocol/Service Multiplexer
    // Mode
    mode: L2capMode,
    // MTU
    imtu: u16,             // Incoming MTU
    omtu: u16,             // Outgoing MTU
    // Flow control
    tx_credits: u16,
    rx_credits: u16,
    mps: u16,              // Maximum PDU Size
    // State
    state: L2capState,
    // Flush timeout
    flush_to: u32,
    // Security
    sec_level: BtSecurityLevel,
    // Stats
    tx_bytes: u64,
    rx_bytes: u64,
    tx_count: u64,
    rx_count: u64,
};

pub const L2capState = enum(u8) {
    closed = 0,
    listen = 1,
    connect_req = 2,
    connect_rsp = 3,
    config = 4,
    connected = 5,
    disconn = 6,
    move_ch = 7,
};

pub const BtSecurityLevel = enum(u8) {
    sdp = 0,
    low = 1,
    medium = 2,
    high = 3,
    fips = 4,
};

// ============================================================================
// RFCOMM (Serial Port Emulation)
// ============================================================================

pub const RfcommChannel = struct {
    dlci: u8,
    channel: u8,
    initiator: bool,
    mtu: u16,
    rx_credits: u16,
    tx_credits: u16,
    modem_status: u8,
    state: RfcommState,
    priority: u8,
    // Stats
    tx_bytes: u64,
    rx_bytes: u64,
};

pub const RfcommState = enum(u8) {
    closed = 0,
    open = 1,
    listen = 2,
    connect = 3,
    connected = 4,
    disconn = 5,
};

// ============================================================================
// SDP (Service Discovery Protocol)
// ============================================================================

pub const SdpUuid = struct {
    type_: SdpUuidType,
    value: SdpUuidValue,
};

pub const SdpUuidType = enum(u8) {
    uuid16 = 2,
    uuid32 = 4,
    uuid128 = 16,
};

pub const SdpUuidValue = union {
    uuid16: u16,
    uuid32: u32,
    uuid128: [16]u8,
};

// Well-known UUIDs (16-bit)
pub const BT_UUID_SDP: u16 = 0x0001;
pub const BT_UUID_RFCOMM: u16 = 0x0003;
pub const BT_UUID_OBEX: u16 = 0x0008;
pub const BT_UUID_HTTP: u16 = 0x000C;
pub const BT_UUID_L2CAP: u16 = 0x0100;
pub const BT_UUID_BNEP: u16 = 0x000F;
pub const BT_UUID_AVCTP: u16 = 0x0017;
pub const BT_UUID_AVDTP: u16 = 0x0019;
pub const BT_UUID_HDP: u16 = 0x001E;
// Service UUIDs
pub const BT_UUID_SPP: u16 = 0x1101;
pub const BT_UUID_DIALUP: u16 = 0x1103;
pub const BT_UUID_OBEX_PUSH: u16 = 0x1105;
pub const BT_UUID_OBEX_FTP: u16 = 0x1106;
pub const BT_UUID_HSP: u16 = 0x1108;
pub const BT_UUID_A2DP_SOURCE: u16 = 0x110A;
pub const BT_UUID_A2DP_SINK: u16 = 0x110B;
pub const BT_UUID_AVRCP_TARGET: u16 = 0x110C;
pub const BT_UUID_AVRCP: u16 = 0x110E;
pub const BT_UUID_HDP_PROFILE: u16 = 0x1400;
pub const BT_UUID_PNP_INFO: u16 = 0x1200;
pub const BT_UUID_HID: u16 = 0x1124;
pub const BT_UUID_HFP: u16 = 0x111E;
pub const BT_UUID_HFP_AG: u16 = 0x111F;
pub const BT_UUID_PBAP: u16 = 0x1130;
pub const BT_UUID_MAP: u16 = 0x1134;

// ============================================================================
// ATT (Attribute Protocol = GATT foundation)
// ============================================================================

pub const AttOpcode = enum(u8) {
    error_rsp = 0x01,
    mtu_req = 0x02,
    mtu_rsp = 0x03,
    find_info_req = 0x04,
    find_info_rsp = 0x05,
    find_by_type_req = 0x06,
    find_by_type_rsp = 0x07,
    read_type_req = 0x08,
    read_type_rsp = 0x09,
    read_req = 0x0a,
    read_rsp = 0x0b,
    read_blob_req = 0x0c,
    read_blob_rsp = 0x0d,
    read_multi_req = 0x0e,
    read_multi_rsp = 0x0f,
    read_group_req = 0x10,
    read_group_rsp = 0x11,
    write_req = 0x12,
    write_rsp = 0x13,
    write_cmd = 0x52,
    prepare_write_req = 0x16,
    prepare_write_rsp = 0x17,
    exec_write_req = 0x18,
    exec_write_rsp = 0x19,
    handle_notify = 0x1b,
    handle_indicate = 0x1d,
    handle_confirm = 0x1e,
    // BTE 5.2+
    read_multi_var_req = 0x20,
    read_multi_var_rsp = 0x21,
    multi_handle_notify = 0x23,
    _,
};

pub const AttError = enum(u8) {
    invalid_handle = 0x01,
    read_not_perm = 0x02,
    write_not_perm = 0x03,
    invalid_pdu = 0x04,
    authentication = 0x05,
    req_not_supp = 0x06,
    invalid_offset = 0x07,
    authorization = 0x08,
    prep_queue_full = 0x09,
    attr_not_found = 0x0a,
    attr_not_long = 0x0b,
    insuff_encr_key_size = 0x0c,
    invalid_attr_len = 0x0d,
    unlikely = 0x0e,
    insuff_encryption = 0x0f,
    unsupported_group = 0x10,
    insuff_resources = 0x11,
    _,
};

// ============================================================================
// GATT (Generic Attribute Profile)
// ============================================================================

pub const GattCharProps = packed struct(u8) {
    broadcast: bool = false,
    read: bool = false,
    write_no_rsp: bool = false,
    write: bool = false,
    notify: bool = false,
    indicate: bool = false,
    auth_signed_write: bool = false,
    extended_props: bool = false,
};

pub const GattService = struct {
    uuid: [16]u8,
    start_handle: u16,
    end_handle: u16,
    is_primary: bool,
    nr_characteristics: u16,
};

pub const GattCharacteristic = struct {
    uuid: [16]u8,
    handle: u16,
    value_handle: u16,
    properties: GattCharProps,
    nr_descriptors: u8,
};

pub const GattDescriptor = struct {
    uuid: [16]u8,
    handle: u16,
};

// Standard GATT Service UUIDs (16-bit)
pub const GATT_UUID_GAP: u16 = 0x1800;
pub const GATT_UUID_GATT: u16 = 0x1801;
pub const GATT_UUID_IMMEDIATE_ALERT: u16 = 0x1802;
pub const GATT_UUID_LINK_LOSS: u16 = 0x1803;
pub const GATT_UUID_TX_POWER: u16 = 0x1804;
pub const GATT_UUID_HEART_RATE: u16 = 0x180D;
pub const GATT_UUID_BATTERY: u16 = 0x180F;
pub const GATT_UUID_BLOOD_PRESSURE: u16 = 0x1810;
pub const GATT_UUID_HID_SERVICE: u16 = 0x1812;
pub const GATT_UUID_GLUCOSE: u16 = 0x1808;
pub const GATT_UUID_HEALTH_THERMO: u16 = 0x1809;
pub const GATT_UUID_DEVICE_INFO: u16 = 0x180A;
pub const GATT_UUID_SCAN_PARAMS: u16 = 0x1813;
pub const GATT_UUID_CSC: u16 = 0x1816;
pub const GATT_UUID_RSC: u16 = 0x1814;
pub const GATT_UUID_MESH_PROV: u16 = 0x1827;
pub const GATT_UUID_MESH_PROXY: u16 = 0x1828;

// ============================================================================
// SMP (Security Manager Protocol)
// ============================================================================

pub const SmpPairingMethod = enum(u8) {
    just_works = 0,
    passkey_entry = 1,
    oob = 2,               // Out of Band
    numeric_comparison = 3,
};

pub const SmpIoCap = enum(u8) {
    display_only = 0x00,
    display_yesno = 0x01,
    keyboard_only = 0x02,
    no_io = 0x03,
    keyboard_display = 0x04,
};

pub const SmpAuthReq = packed struct(u8) {
    bonding: bool = false,
    mitm: bool = false,
    sc: bool = false,       // Secure Connections
    keypress: bool = false,
    ct2: bool = false,      // Cross-Transport
    _reserved: u3 = 0,
};

pub const SmpKeyDist = packed struct(u8) {
    enc_key: bool = false,
    id_key: bool = false,
    sign: bool = false,
    link_key: bool = false,
    _reserved: u4 = 0,
};

pub const SmpLtk = struct {
    val: [16]u8,
    rand: u64,
    ediv: u16,
    authenticated: bool,
    sc: bool,
    enc_size: u8,
};

pub const SmpIrk = struct {
    val: [16]u8,
    bdaddr: BdAddr,
    addr_type: u8,
};

pub const SmpCsrk = struct {
    val: [16]u8,
    type_: u8,
};

// ============================================================================
// LE Audio (BT 5.2+)
// ============================================================================

pub const LeAudioCodecId = enum(u8) {
    lc3 = 0x06,           // Low Complexity Communication Codec
    // Vendor specific
    aptx_adaptive = 0xFF,
};

pub const LeAudioLocation = packed struct(u32) {
    front_left: bool = false,
    front_right: bool = false,
    front_center: bool = false,
    low_frequency_effects: bool = false,
    back_left: bool = false,
    back_right: bool = false,
    front_left_center: bool = false,
    front_right_center: bool = false,
    back_center: bool = false,
    side_left: bool = false,
    side_right: bool = false,
    top_front_left: bool = false,
    top_front_right: bool = false,
    top_front_center: bool = false,
    top_center: bool = false,
    top_back_left: bool = false,
    top_back_right: bool = false,
    top_side_left: bool = false,
    top_side_right: bool = false,
    top_back_center: bool = false,
    bottom_front_center: bool = false,
    bottom_front_left: bool = false,
    bottom_front_right: bool = false,
    front_left_wide: bool = false,
    front_right_wide: bool = false,
    left_surround: bool = false,
    right_surround: bool = false,
    _reserved: u5 = 0,
};

pub const LeAudioContext = packed struct(u16) {
    unspecified: bool = false,
    conversational: bool = false,
    media: bool = false,
    game: bool = false,
    instructional: bool = false,
    voice_assistant: bool = false,
    live: bool = false,
    sound_effects: bool = false,
    notifications: bool = false,
    ringtone: bool = false,
    alerts: bool = false,
    emergency_alarm: bool = false,
    _reserved: u4 = 0,
};

// CIG (Connected Isochronous Group)
pub const CigParams = struct {
    cig_id: u8,
    sdu_interval_m_to_s_us: u32,
    sdu_interval_s_to_m_us: u32,
    sca: u8,                     // Sleep Clock Accuracy
    packing: u8,                 // 0=sequential, 1=interleaved
    framing: u8,                 // 0=unframed, 1=framed
    latency_m_to_s_ms: u16,
    latency_s_to_m_ms: u16,
    num_cis: u8,
};

// CIS (Connected Isochronous Stream)
pub const CisParams = struct {
    cis_id: u8,
    max_sdu_m_to_s: u16,
    max_sdu_s_to_m: u16,
    phy_m_to_s: u8,
    phy_s_to_m: u8,
    rtn_m_to_s: u8,
    rtn_s_to_m: u8,
};

// BIG (Broadcast Isochronous Group)
pub const BigParams = struct {
    big_handle: u8,
    adv_handle: u8,
    num_bis: u8,
    sdu_interval_us: u32,
    max_sdu: u16,
    max_transport_latency_ms: u16,
    rtn: u8,
    phy: u8,
    packing: u8,
    framing: u8,
    encryption: bool,
    broadcast_code: [16]u8,
};

// ============================================================================
// Bluetooth Mesh
// ============================================================================

pub const MeshNetKeyIdx = u12;
pub const MeshAppKeyIdx = u12;

pub const MeshFeatures = packed struct(u16) {
    relay: bool = false,
    proxy: bool = false,
    friend: bool = false,
    low_power: bool = false,
    // Zxyphor
    zxy_quantum_mesh: bool = false,
    _reserved: u11 = 0,
};

pub const MeshNode = struct {
    unicast_addr: u16,
    nr_elements: u8,
    net_key_idx: MeshNetKeyIdx,
    features: MeshFeatures,
    // Security
    ttl: u8,
    seq_number: u32,
    iv_index: u32,
    // Keys
    nr_net_keys: u8,
    nr_app_keys: u8,
    // State
    provisioned: bool,
    relay_enabled: bool,
    proxy_enabled: bool,
    friend_enabled: bool,
    // Stats
    tx_count: u64,
    rx_count: u64,
    relay_count: u64,
};

pub const MeshProvisioningState = enum(u8) {
    unprovisioned = 0,
    invite = 1,
    capabilities = 2,
    start = 3,
    public_key = 4,
    input_complete = 5,
    confirmation = 6,
    random = 7,
    data = 8,
    complete = 9,
    failed = 10,
};

// ============================================================================
// Connection Management
// ============================================================================

pub const BtConnection = struct {
    // Remote device
    dst: BdAddr,
    dst_type: BdAddrType,
    // Connection
    handle: u16,
    conn_type: BtConnType,
    state: BtConnState,
    role: BtRole,
    // Parameters
    interval: u16,          // in 1.25ms units
    latency: u16,
    supervision_timeout: u16,
    // PHY
    tx_phy: BtPhy,
    rx_phy: BtPhy,
    // Security
    sec_level: BtSecurityLevel,
    auth_type: u8,
    encrypt: bool,
    // Keys
    ltk: ?SmpLtk,
    // RSSI
    rssi: i8,
    tx_power: i8,
    // Stats
    tx_bytes: u64,
    rx_bytes: u64,
    tx_count: u64,
    rx_count: u64,
    // Timestamps
    created_ns: u64,
    last_activity_ns: u64,
};

pub const BtConnType = enum(u8) {
    acl = 0,
    sco = 1,
    esco = 2,
    le = 3,
    iso = 4,
};

pub const BtConnState = enum(u8) {
    disconnected = 0,
    connecting = 1,
    connected = 2,
    config = 3,
    disconnecting = 4,
};

pub const BtRole = enum(u8) {
    central = 0,
    peripheral = 1,
};

pub const BtPhy = enum(u8) {
    le_1m = 1,
    le_2m = 2,
    le_coded = 3,
};

// ============================================================================
// Bluetooth Profiles
// ============================================================================

pub const BtProfileType = enum(u8) {
    a2dp = 0,
    avrcp = 1,
    hfp = 2,
    hsp = 3,
    hid = 4,
    pan = 5,
    pbap = 6,
    map = 7,
    opp = 8,
    ftp = 9,
    sap = 10,
    // LE
    hogp = 20,          // HID over GATT
    csip = 21,          // Coordinated Set
    vcp = 22,           // Volume Control
    micp = 23,          // Microphone Control
    bap = 24,           // Basic Audio
    cap = 25,           // Common Audio
    tmap = 26,          // Telephony and Media
    hap = 27,           // Hearing Access
    // Zxyphor
    zxy_stream = 50,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const BluetoothSubsystem = struct {
    // Devices
    nr_hci_devices: u32,
    // Features
    bredr_support: bool,
    le_support: bool,
    le_audio_support: bool,
    mesh_support: bool,
    // Connections
    nr_acl_connections: u32,
    nr_le_connections: u32,
    nr_sco_connections: u32,
    nr_iso_connections: u32,
    // Services
    nr_sdp_records: u32,
    nr_gatt_services: u32,
    // Mesh
    mesh_provisioned: bool,
    mesh_nodes: u16,
    // Stats
    total_tx_bytes: u64,
    total_rx_bytes: u64,
    total_connections: u64,
    total_disconnections: u64,
    total_pairing_attempts: u64,
    total_pairing_successes: u64,
    total_pairing_failures: u64,
    total_encryption_errors: u64,
    // Security
    nr_bonded_devices: u32,
    sc_enabled: bool,         // Secure Connections
    // Power
    current_power_mode: u8,
    // Zxyphor
    zxy_ultra_low_latency: bool,
    initialized: bool,
};
