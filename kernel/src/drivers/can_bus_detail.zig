// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - CAN Bus Subsystem
// Complete: CAN 2.0A/B frames, CAN FD, CAN XL, ISO-TP, J1939,
// CAN controller hardware abstraction, bitrate/timing, error handling,
// network device integration, raw/broadcast manager sockets

const std = @import("std");

// ============================================================================
// CAN Frame Formats
// ============================================================================

pub const CanFrameType = enum(u8) {
    Standard = 0,    // CAN 2.0A (11-bit ID)
    Extended = 1,    // CAN 2.0B (29-bit ID)
    Fd = 2,          // CAN FD
    FdBrs = 3,       // CAN FD with bit rate switch
    Xl = 4,          // CAN XL
    Remote = 5,      // Remote transmission request
    Error = 6,       // Error frame
};

pub const CanId = packed struct(u32) {
    id: u29,          // 11 or 29 bit identifier
    err: bool,        // Error frame flag
    rtr: bool,        // Remote transmission request
    eff: bool,        // Extended frame format
};

pub const CanFrame = struct {
    can_id: CanId,
    len: u8,          // Data length 0..8
    flags: u8,
    __res0: u8,
    __res1: u8,
    data: [8]u8,
};

pub const CanFdFrame = struct {
    can_id: CanId,
    len: u8,          // Data length 0..64
    flags: CanFdFlags,
    __res0: u8,
    __res1: u8,
    data: [64]u8,
};

pub const CanFdFlags = packed struct(u8) {
    brs: bool,        // Bit rate switch
    esi: bool,        // Error state indicator
    _reserved: u6,
};

pub const CanXlFrame = struct {
    prio: u32,         // Priority/acceptance filter
    flags: CanXlFlags,
    sdt: u8,           // SDU (Service Data Unit) type
    len: u16,          // Data length 0..2048
    af: u32,           // Acceptance field
    data: [2048]u8,    // Max CAN XL payload
};

pub const CanXlFlags = packed struct(u8) {
    xlf: bool,         // CAN XL format
    sec: bool,         // Simple Extended Content
    _reserved: u6,
};

// ============================================================================
// CAN Bitrate / Timing
// ============================================================================

pub const CanBitrateConst = struct {
    pub const CAN_10KBPS: u32 = 10000;
    pub const CAN_20KBPS: u32 = 20000;
    pub const CAN_50KBPS: u32 = 50000;
    pub const CAN_100KBPS: u32 = 100000;
    pub const CAN_125KBPS: u32 = 125000;
    pub const CAN_250KBPS: u32 = 250000;
    pub const CAN_500KBPS: u32 = 500000;
    pub const CAN_800KBPS: u32 = 800000;
    pub const CAN_1MBPS: u32 = 1000000;
    // FD data bitrates
    pub const CANFD_2MBPS: u32 = 2000000;
    pub const CANFD_4MBPS: u32 = 4000000;
    pub const CANFD_5MBPS: u32 = 5000000;
    pub const CANFD_8MBPS: u32 = 8000000;
    pub const CANFD_10MBPS: u32 = 10000000;
    pub const CANFD_12MBPS: u32 = 12000000;
    // XL bitrates
    pub const CANXL_10MBPS: u32 = 10000000;
    pub const CANXL_20MBPS: u32 = 20000000;
};

pub const CanBitTiming = struct {
    bitrate: u32,       // Bit rate in bits/second
    sample_point: u32,  // Sample point in one-tenth of percent
    tq: u32,            // Time quanta (TQ) in nanoseconds
    prop_seg: u32,      // Propagation segment in TQs
    phase_seg1: u32,    // Phase buffer segment 1 in TQs
    phase_seg2: u32,    // Phase buffer segment 2 in TQs
    sjw: u32,           // Synchronization jump width in TQs
    brp: u32,           // Bit rate prescaler
};

pub const CanBitTimingConst = struct {
    name: [32]u8,
    tseg1_min: u32,
    tseg1_max: u32,
    tseg2_min: u32,
    tseg2_max: u32,
    sjw_max: u32,
    brp_min: u32,
    brp_max: u32,
    brp_inc: u32,
};

pub const CanDataBitTiming = struct {
    bitrate: u32,
    sample_point: u32,
    tq: u32,
    prop_seg: u32,
    phase_seg1: u32,
    phase_seg2: u32,
    sjw: u32,
    brp: u32,
};

pub const CanDataBitTimingConst = struct {
    name: [32]u8,
    tseg1_min: u32,
    tseg1_max: u32,
    tseg2_min: u32,
    tseg2_max: u32,
    sjw_max: u32,
    brp_min: u32,
    brp_max: u32,
    brp_inc: u32,
};

// ============================================================================
// CAN Controller
// ============================================================================

pub const CanCtrlMode = packed struct(u32) {
    loopback: bool,
    listen_only: bool,
    triple_sampling: bool,
    one_shot: bool,
    berr_reporting: bool,
    fd: bool,
    presume_ack: bool,
    fd_non_iso: bool,
    cc_len8_dlc: bool,
    tdc_auto: bool,
    tdc_manual: bool,
    _reserved: u21,
};

pub const CanState = enum(u8) {
    ErrorActive = 0,
    ErrorWarning = 1,
    ErrorPassive = 2,
    BusOff = 3,
    Stopped = 4,
    Sleeping = 5,
    MaxState = 6,
};

pub const CanDeviceStats = struct {
    bus_error: u32,
    error_warning: u32,
    error_passive: u32,
    bus_off: u32,
    arbitration_lost: u32,
    restarts: u32,
};

pub const CanErrorCounters = struct {
    txerr: u16,
    rxerr: u16,
};

pub const CanClock = struct {
    freq: u32,    // CAN system clock frequency in Hz
};

pub const CanControllerOps = struct {
    set_mode: ?*const fn (dev: *CanDevice, mode: CanCtrlMode) callconv(.C) i32,
    set_bittiming: ?*const fn (dev: *CanDevice) callconv(.C) i32,
    set_data_bittiming: ?*const fn (dev: *CanDevice) callconv(.C) i32,
    get_berr_counter: ?*const fn (dev: *CanDevice, bec: *CanErrorCounters) callconv(.C) i32,
    do_set_mode: ?*const fn (dev: *CanDevice, mode: CanState) callconv(.C) i32,
    do_get_state: ?*const fn (dev: *CanDevice, state: *CanState) callconv(.C) i32,
    do_restart: ?*const fn (dev: *CanDevice) callconv(.C) i32,
};

pub const CanDevice = struct {
    ctrlmode: CanCtrlMode,
    ctrlmode_supported: CanCtrlMode,
    ctrlmode_static: CanCtrlMode,
    restart_ms: u32,
    can_stats: CanDeviceStats,
    bittiming: CanBitTiming,
    bittiming_const: ?*const CanBitTimingConst,
    data_bittiming: CanDataBitTiming,
    data_bittiming_const: ?*const CanDataBitTimingConst,
    bitrate_max: u32,
    clock: CanClock,
    state: CanState,
    restart_work: u64,
    berr_counter: CanErrorCounters,
    ops: ?*const CanControllerOps,
    netdev: ?*anyopaque,
    tx_head: u32,
    tx_tail: u32,
    echo_skb_max: u32,
    echo_skb: [32]?*anyopaque,
    tdc: CanTdc,
    tdc_const: ?*const CanTdcConst,
    termination: u16,
    termination_const: ?*const [8]u16,
    termination_gpio: ?*anyopaque,
    termination_gpio_ohms: [2]u16,
};

pub const CanTdc = struct {
    tdcv: u32,  // Transmitter Delay Compensation Value
    tdco: u32,  // Transmitter Delay Compensation Offset
    tdcf: u32,  // Transmitter Delay Compensation Filter Window Length
};

pub const CanTdcConst = struct {
    tdcv_min: u32,
    tdcv_max: u32,
    tdco_min: u32,
    tdco_max: u32,
    tdcf_min: u32,
    tdcf_max: u32,
};

// ============================================================================
// CAN Error Handling
// ============================================================================

pub const CanErrorType = packed struct(u32) {
    tx_timeout: bool,
    lost_arbitration: bool,
    controller: bool,
    protocol_violation: bool,
    transceiver: bool,
    no_ack: bool,
    bus_off: bool,
    bus_error: bool,
    restarted: bool,
    _reserved: u23,
};

pub const CanProtocolError = enum(u8) {
    Unspecified = 0,
    BitError = 1,
    FormError = 2,
    StuffError = 3,
    Bit1Error = 4,
    Bit0Error = 5,
    CrcError = 6,
    AckError = 7,
};

pub const CanProtocolLocation = enum(u8) {
    Unspecified = 0,
    Sof = 0x03,
    Id28to21 = 0x02,
    Id20to18 = 0x06,
    Srtr = 0x04,
    Ide = 0x05,
    Id17to13 = 0x07,
    Id12to05 = 0x0F,
    Id04to00 = 0x0E,
    Rtr = 0x0C,
    Reserved1 = 0x0D,
    Reserved0 = 0x09,
    Dlc = 0x0B,
    Data = 0x0A,
    Crc = 0x08,
    CrcDelimiter = 0x18,
    Ack = 0x19,
    AckDelimiter = 0x1B,
    Eof = 0x1A,
    Intermission = 0x12,
};

pub const CanTransceiverError = enum(u8) {
    Unspecified = 0,
    CanhNoWire = 0x04,
    CanhShortToBat = 0x05,
    CanhShortToVcc = 0x06,
    CanhShortToGnd = 0x07,
    CanlNoWire = 0x40,
    CanlShortToBat = 0x50,
    CanlShortToVcc = 0x60,
    CanlShortToGnd = 0x70,
    CanlShortToCanh = 0x80,
};

// ============================================================================
// ISO-TP (ISO 15765-2)
// ============================================================================

pub const IsoTpFrameType = enum(u8) {
    SingleFrame = 0,
    FirstFrame = 1,
    ConsecutiveFrame = 2,
    FlowControl = 3,
};

pub const IsoTpFlowStatus = enum(u8) {
    ContinueToSend = 0,
    Wait = 1,
    Overflow = 2,
};

pub const IsoTpOpts = struct {
    flags: IsoTpFlags,
    frame_txtime: u32,    // Frame transmission time (N_As/N_Ar) in ns
    ext_address: u8,      // Extended addressing byte
    txpad_content: u8,    // Padding byte for TX
    rxpad_content: u8,    // Padding byte for RX
    rx_ext_address: u8,   // RX extended addressing byte
};

pub const IsoTpFlags = packed struct(u32) {
    listen_mode: bool,
    ext_addr: bool,
    tx_padding: bool,
    rx_padding: bool,
    chk_pad_len: bool,
    chk_pad_data: bool,
    half_duplex: bool,
    force_txstmin: bool,
    force_rxstmin: bool,
    rx_ext_addr: bool,
    wait_tx_done: bool,
    sf_broadcast: bool,
    cf_broadcast: bool,
    _reserved: u19,
};

pub const IsoTpFcOpts = struct {
    bs: u8,       // Block size
    stmin: u8,    // Separation time minimum
    wftmax: u8,   // Maximum wait frame transmissions
};

pub const IsoTpLlOpts = struct {
    mtu: u32,     // Generated frames CAN MTU
    tx_dl: u8,    // Generated frames data length
    tx_flags: u8, // Generated frames can_fd flags
};

pub const IsoTpState = enum(u8) {
    Idle = 0,
    WaitFirstFc = 1,
    WaitFc = 2,
    WaitData = 3,
    Sending = 4,
};

pub const IsoTpSocket = struct {
    sk: ?*anyopaque,
    bound: bool,
    ifindex: i32,
    txid: CanId,
    rxid: CanId,
    opt: IsoTpOpts,
    fc_opt: IsoTpFcOpts,
    ll_opt: IsoTpLlOpts,
    state: IsoTpState,
    tx_sn: u8,         // TX sequence number
    rx_sn: u8,         // RX sequence number
    tx_bs: u8,         // TX block size counter
    rx_bs: u8,         // RX block size counter
    tx_buf: [4095]u8,  // TX buffer
    rx_buf: [4095]u8,  // RX buffer
    tx_len: u32,
    rx_len: u32,
    tx_idx: u32,
    rx_idx: u32,
    tx_gap: u32,
    lastrxcf_tstamp: u64,
    tx_timer: u64,
    rx_timer: u64,
};

// ============================================================================
// J1939 (SAE J1939)
// ============================================================================

pub const J1939PgnParts = packed struct(u32) {
    pdu_specific: u8,
    pdu_format: u8,
    data_page: bool,
    extended_data_page: bool,
    _reserved: u14,
};

pub const J1939Priority = u3;  // 0-7

pub const J1939Name = packed struct(u64) {
    identity_number: u21,
    manufacturer_code: u11,
    ecu_instance: u3,
    function_instance: u5,
    function: u8,
    _reserved: u1,
    vehicle_system: u7,
    vehicle_system_instance: u4,
    industry_group: u3,
    arbitrary_address_capable: u1,
};

pub const J1939Filter = struct {
    name: J1939Name,
    name_mask: u64,
    pgn: u32,
    pgn_mask: u32,
    addr: u8,
    addr_mask: u8,
};

pub const J1939Socket = struct {
    sk: ?*anyopaque,
    ifindex: i32,
    addr: J1939SockAddr,
    state: J1939State,
    filters: [16]J1939Filter,
    filter_count: u32,
    priv_data: ?*anyopaque,
};

pub const J1939SockAddr = struct {
    name: J1939Name,
    pgn: u32,
    addr: u8,
};

pub const J1939State = enum(u8) {
    Idle = 0,
    AddressClaiming = 1,
    AddressClaimed = 2,
    Active = 3,
};

pub const J1939TransportProtocol = enum(u8) {
    TP_CM = 0xEC,     // Transport Protocol - Connection Management
    TP_DT = 0xEB,     // Transport Protocol - Data Transfer
    ETP_CM = 0xC8,    // Extended Transport Protocol - Connection Management
    ETP_DT = 0xC7,    // Extended Transport Protocol - Data Transfer
};

pub const J1939TpCmd = enum(u8) {
    RTS = 16,          // Request to Send
    CTS = 17,          // Clear to Send
    EOM_ACK = 19,      // End of Message Acknowledgment
    BAM = 32,          // Broadcast Announce Message
    ABORT = 255,       // Connection Abort
};

pub const J1939SessionState = enum(u8) {
    Idle = 0,
    WaitingCts = 1,
    Active = 2,
    WaitingEomAck = 3,
    Done = 4,
    Aborted = 5,
};

pub const J1939Session = struct {
    state: J1939SessionState,
    skcb: J1939SockCb,
    total_message_size: u32,
    total_queued_size: u32,
    pkt_total: u32,
    pkt_done: u32,
    pkt_block: u32,
    last_cmd: J1939TpCmd,
    last_txcmd: J1939TpCmd,
    tx_retry: u32,
    err: i32,
    tskey: u32,
};

pub const J1939SockCb = struct {
    priority: J1939Priority,
    src_name: J1939Name,
    dst_name: J1939Name,
    src_addr: u8,
    dst_addr: u8,
    pgn: u32,
    msg_flags: u32,
};

// ============================================================================
// CAN Raw Socket
// ============================================================================

pub const CanRawOpt = enum(u8) {
    Filter = 1,
    ErrFilter = 2,
    Loopback = 3,
    RecvOwnMsgs = 4,
    FdFrames = 5,
    JoinFilters = 6,
    XlFrames = 7,
};

pub const CanRawFilter = struct {
    can_id: CanId,
    can_mask: CanId,
};

pub const CanRawSocket = struct {
    sk: ?*anyopaque,
    ifindex: i32,
    bound: bool,
    filter: [64]CanRawFilter,
    filter_count: u32,
    err_mask: CanErrorType,
    loopback: bool,
    recv_own_msgs: bool,
    fd_frames: bool,
    xl_frames: bool,
    join_filters: bool,
};

// ============================================================================
// CAN BCM (Broadcast Manager)
// ============================================================================

pub const BcmOpcode = enum(u32) {
    TX_SETUP = 1,
    TX_DELETE = 2,
    TX_READ = 3,
    TX_SEND = 4,
    RX_SETUP = 5,
    RX_DELETE = 6,
    RX_READ = 7,
    TX_STATUS = 8,
    TX_EXPIRED = 9,
    RX_STATUS = 10,
    RX_TIMEOUT = 11,
    RX_CHANGED = 12,
};

pub const BcmFlags = packed struct(u32) {
    settimer: bool,
    starttimer: bool,
    tx_countevt: bool,
    tx_announce: bool,
    tx_cp_can_id: bool,
    rx_filter_id: bool,
    rx_check_dlc: bool,
    rx_no_autotimer: bool,
    rx_announce_resume: bool,
    tx_reset_multi_idx: bool,
    rx_rtc_filter: bool,
    _reserved: u21,
};

pub const BcmMsgHead = struct {
    opcode: BcmOpcode,
    flags: BcmFlags,
    count: u32,
    ival1: BcmTimeval,
    ival2: BcmTimeval,
    can_id: CanId,
    nframes: u32,
};

pub const BcmTimeval = struct {
    tv_sec: i64,
    tv_usec: i64,
};

pub const BcmOp = struct {
    msg_head: BcmMsgHead,
    j_ival1: u64,
    j_ival2: u64,
    j_lastmsg: u64,
    frames_abs: u32,
    count: u32,
    nframes: u32,
    currframe: u32,
    last_frames: [256]CanFrame,
    ifindex: i32,
    rx_changed: bool,
    timer: u64,
    thrtimer: u64,
    kt_ival1: u64,
    kt_ival2: u64,
    kt_lastmsg: u64,
};

// ============================================================================
// CAN GW (Gateway/Routing)
// ============================================================================

pub const CanGwType = enum(u8) {
    Unspec = 0,
    ModAnd = 1,
    ModOr = 2,
    ModXor = 3,
    ModSet = 4,
};

pub const CanGwOp = enum(u8) {
    None = 0,
    And = 1,
    Or = 2,
    Xor = 3,
    Set = 4,
};

pub const CanGwModAttr = packed struct(u32) {
    mod_id: bool,
    mod_dlc: bool,
    mod_data: bool,
    and: bool,
    or_flag: bool,
    xor: bool,
    set: bool,
    _reserved: u25,
};

pub const CanGwJob = struct {
    src_dev: ?*anyopaque,
    dst_dev: ?*anyopaque,
    handled_frames: u64,
    dropped_frames: u64,
    deleted_frames: u64,
    mod: CanGwModification,
    flags: u32,
    gwtype: CanGwType,
    limit_hops: u8,
    src_ifindex: i32,
    dst_ifindex: i32,
};

pub const CanGwModification = struct {
    modtype: CanGwOp,
    and_mask: CanFrame,
    or_mask: CanFrame,
    xor_mask: CanFrame,
    set_mask: CanFrame,
    csumfunc: CanGwCsumFunc,
    uid: u32,
};

pub const CanGwCsumFunc = enum(u8) {
    None = 0,
    Xor = 1,
    Crc8 = 2,
};

// ============================================================================
// Hardware Controllers
// ============================================================================

pub const CanHwControllerType = enum(u8) {
    Mcp251x = 0,      // Microchip MCP2515/MCP251xFD
    Sja1000 = 1,      // NXP SJA1000
    Flexcan = 2,       // NXP FlexCAN
    Mcan = 3,          // Bosch M_CAN
    C_can = 4,         // Bosch C_CAN
    Rcar = 5,          // Renesas R-Car CAN
    TiHecc = 6,        // TI HECC
    Bxcan = 7,         // STM32 bxCAN
    Fdcan = 8,         // STM32 FDCAN
    At91 = 9,          // Atmel AT91 CAN
    Ifi = 10,          // IFI CANFD
    Peak = 11,         // PEAK-System PCAN
    Kvaser = 12,       // Kvaser CAN
    Ixxat = 13,        // IXXAT CAN
    Gs_usb = 14,       // Geschwister Schneider USB/CAN
    Etas = 15,         // ETAS ES58X
    Softing = 16,      // Softing CAN
};

pub const CanHwFeatures = packed struct(u32) {
    can_classic: bool,
    can_fd: bool,
    can_fd_brs: bool,
    can_xl: bool,
    tx_timestamp: bool,
    rx_timestamp: bool,
    hw_filter: bool,
    hw_fifo: bool,
    auto_retransmit: bool,
    wakeup: bool,
    listen_only: bool,
    loopback: bool,
    triple_sample: bool,
    one_shot: bool,
    error_reporting: bool,
    tdc: bool,
    _reserved: u16,
};

pub const CanHwTimestamp = struct {
    sw_timestamp: u64,
    hw_timestamp: u64,
    adapter_timestamp: u64,
    timestamp_ns: u64,
};

pub const CanHwFilter = struct {
    id: u32,
    mask: u32,
    type_flag: CanFrameType,
    fifo: u8,
    enabled: bool,
};

pub const CanHwController = struct {
    controller_type: CanHwControllerType,
    features: CanHwFeatures,
    max_bitrate: u32,
    max_data_bitrate: u32,
    tx_fifo_depth: u8,
    rx_fifo_depth: u8,
    hw_filters: [32]CanHwFilter,
    hw_filter_count: u8,
    irq: i32,
    base_addr: u64,
    clock_freq: u32,
    fw_version: u32,
    hw_version: u32,
    timestamp_support: bool,
    ops: ?*const CanControllerOps,
    priv_data: ?*anyopaque,
};

// ============================================================================
// CAN Netlink Interface
// ============================================================================

pub const CanNlAttrType = enum(u16) {
    IFLA_CAN_UNSPEC = 0,
    IFLA_CAN_BITTIMING = 1,
    IFLA_CAN_BITTIMING_CONST = 2,
    IFLA_CAN_CLOCK = 3,
    IFLA_CAN_STATE = 4,
    IFLA_CAN_CTRLMODE = 5,
    IFLA_CAN_RESTART_MS = 6,
    IFLA_CAN_RESTART = 7,
    IFLA_CAN_BERR_COUNTER = 8,
    IFLA_CAN_DATA_BITTIMING = 9,
    IFLA_CAN_DATA_BITTIMING_CONST = 10,
    IFLA_CAN_TERMINATION = 11,
    IFLA_CAN_TERMINATION_CONST = 12,
    IFLA_CAN_BITRATE_CONST = 13,
    IFLA_CAN_DATA_BITRATE_CONST = 14,
    IFLA_CAN_BITRATE_MAX = 15,
    IFLA_CAN_TDC = 16,
    IFLA_CAN_CTRLMODE_EXT = 17,
};

// ============================================================================
// CAN Statistics
// ============================================================================

pub const CanIfaceStats = struct {
    rx_frames: u64,
    tx_frames: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_overflows: u64,
    tx_timeouts: u64,
    arbitration_lost: u64,
    bus_errors: u64,
    bus_off_count: u64,
    error_passive_count: u64,
    error_warning_count: u64,
    restarts: u64,
    rx_filtered: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    echo_dropped: u64,
};

// ============================================================================
// Manager
// ============================================================================

pub const CanBusManager = struct {
    controllers: [16]?*CanHwController,
    controller_count: u32,
    total_rx_frames: u64,
    total_tx_frames: u64,
    total_bus_errors: u64,
    total_bus_offs: u64,
    initialized: bool,

    pub fn init() CanBusManager {
        return .{
            .controllers = [_]?*CanHwController{null} ** 16,
            .controller_count = 0,
            .total_rx_frames = 0,
            .total_tx_frames = 0,
            .total_bus_errors = 0,
            .total_bus_offs = 0,
            .initialized = true,
        };
    }
};
