// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - DRM Connector, Panel & Display Modes
// Complete DRM connector types, display modes, EDID parsing,
// panel detection, HDMI/DP/eDP/DSI, color spaces, HDR metadata

const std = @import("std");

// ============================================================================
// DRM Connector Types
// ============================================================================

pub const DrmConnectorType = enum(u32) {
    Unknown = 0,
    VGA = 1,
    DVII = 2,
    DVID = 3,
    DVIA = 4,
    Composite = 5,
    SVIDEO = 6,
    LVDS = 7,
    Component = 8,
    NinePinDIN = 9,
    DisplayPort = 10,
    HDMIA = 11,
    HDMIB = 12,
    TV = 13,
    eDP = 14,
    Virtual = 15,
    DSI = 16,
    DPI = 17,
    Writeback = 18,
    SPI = 19,
    USB = 20,
};

pub const DrmConnectorStatus = enum(u8) {
    Connected = 1,
    Disconnected = 2,
    Unknown = 3,
};

pub const DrmConnectorPolled = packed struct(u8) {
    hpd: bool,              // Hot Plug Detect
    connect: bool,          // Polling for connect
    disconnect: bool,       // Polling for disconnect
    _reserved: u5,
};

// ============================================================================
// Display Modes
// ============================================================================

pub const DrmDisplayMode = struct {
    name: [32]u8,
    clock: u32,            // Pixel clock in kHz
    hdisplay: u16,
    hsync_start: u16,
    hsync_end: u16,
    htotal: u16,
    hskew: u16,
    vdisplay: u16,
    vsync_start: u16,
    vsync_end: u16,
    vtotal: u16,
    vscan: u16,
    vrefresh: u32,         // Vertical refresh rate
    flags: DrmModeFlags,
    mode_type: DrmModeType,
    width_mm: u32,
    height_mm: u32,
    picture_aspect_ratio: DrmAspectRatio,
};

pub const DrmModeFlags = packed struct(u32) {
    phsync: bool,          // Positive horizontal sync
    nhsync: bool,          // Negative horizontal sync
    pvsync: bool,          // Positive vertical sync
    nvsync: bool,          // Negative vertical sync
    interlace: bool,
    dblscan: bool,
    csync: bool,
    pcsync: bool,
    ncsync: bool,
    hskew: bool,
    bcast: bool,           // Deprecated
    pixmux: bool,
    dblclk: bool,
    clkdiv2: bool,
    _reserved: u18,
};

pub const DrmModeType = packed struct(u32) {
    preferred: bool,
    userdef: bool,
    driver: bool,
    _reserved: u29,
};

pub const DrmAspectRatio = enum(u8) {
    None = 0,
    _4_3 = 1,
    _16_9 = 2,
    _64_27 = 3,
    _256_135 = 4,
};

// ============================================================================
// EDID (Extended Display Identification Data)
// ============================================================================

pub const EdidHeader = struct {
    header: [8]u8,          // Should be 00 FF FF FF FF FF FF 00
    manufacturer_id: u16,
    product_code: u16,
    serial_number: u32,
    week_of_manufacture: u8,
    year_of_manufacture: u8,
    edid_version: u8,
    edid_revision: u8,
};

pub const EdidDisplayParams = struct {
    video_input: EdidVideoInput,
    max_h_size_cm: u8,
    max_v_size_cm: u8,
    gamma: u8,             // (gamma * 100) - 100
    features: EdidFeatures,
};

pub const EdidVideoInput = packed struct(u8) {
    signal_level: u2,
    video_setup: bool,
    separate_sync: bool,
    composite_sync: bool,
    sync_on_green: bool,
    vsync_serration: bool,
    digital: bool,
};

pub const EdidFeatures = packed struct(u8) {
    standby: bool,
    suspend: bool,
    active_off: bool,
    display_type: u2,
    standard_srgb: bool,
    preferred_timing: bool,
    default_gtf: bool,
};

pub const EdidChromaticity = struct {
    red_x: u16,
    red_y: u16,
    green_x: u16,
    green_y: u16,
    blue_x: u16,
    blue_y: u16,
    white_x: u16,
    white_y: u16,
};

pub const EdidStandardTiming = packed struct(u16) {
    h_active: u8,          // (h_active / 8) - 31
    aspect_ratio: u2,
    refresh: u6,           // refresh - 60
};

pub const EdidDetailedTiming = struct {
    pixel_clock: u16,      // In 10 kHz units
    h_active_low: u8,
    h_blanking_low: u8,
    h_active_blanking_high: u8,
    v_active_low: u8,
    v_blanking_low: u8,
    v_active_blanking_high: u8,
    h_sync_offset_low: u8,
    h_sync_width_low: u8,
    v_sync_offset_width_low: u8,
    sync_offset_width_high: u8,
    h_image_size_low: u8,
    v_image_size_low: u8,
    image_size_high: u8,
    h_border: u8,
    v_border: u8,
    signal_type: u8,
};

pub const EdidBlock = struct {
    header: EdidHeader,
    display: EdidDisplayParams,
    chroma: EdidChromaticity,
    established_timings: [3]u8,
    standard_timings: [8]EdidStandardTiming,
    detailed_timings: [4]EdidDetailedTiming,
    extension_count: u8,
    checksum: u8,
};

// ============================================================================
// HDMI
// ============================================================================

pub const HdmiInfoframeType = enum(u8) {
    VendorSpecific = 0x81,
    Avi = 0x82,
    Spd = 0x83,
    Audio = 0x84,
    DrmInfoframe = 0x87,
};

pub const HdmiAviInfoframe = struct {
    frame_type: HdmiInfoframeType,
    version: u8,
    length: u8,
    colorspace: HdmiColorspace,
    active_aspect: u8,
    top_bar: u16,
    bottom_bar: u16,
    left_bar: u16,
    right_bar: u16,
    scan_mode: u8,
    picture_aspect: DrmAspectRatio,
    colorimetry: HdmiColorimetry,
    extended_colorimetry: HdmiExtColorimetry,
    quantization_range: HdmiQuantRange,
    nups: u8,
    video_code: u8,
    ycc_quantization_range: u8,
    content_type: u8,
    pixel_repeat: u8,
    itc: bool,
};

pub const HdmiColorspace = enum(u8) {
    Rgb = 0,
    Ycbcr422 = 1,
    Ycbcr444 = 2,
    Ycbcr420 = 3,
};

pub const HdmiColorimetry = enum(u8) {
    None = 0,
    Itu601 = 1,
    Itu709 = 2,
    Extended = 3,
};

pub const HdmiExtColorimetry = enum(u8) {
    XvYcc601 = 0,
    XvYcc709 = 1,
    SYcc601 = 2,
    OpYcc601 = 3,
    OpRgb = 4,
    Bt2020CYcc = 5,
    Bt2020Ycc = 6,
    Bt2020Rgb = 7,
};

pub const HdmiQuantRange = enum(u8) {
    Default = 0,
    LimitedRange = 1,
    FullRange = 2,
};

// ============================================================================
// HDR Metadata
// ============================================================================

pub const HdrMetadataType = enum(u8) {
    None = 0,
    Static1 = 1,       // CTA-861-G Static Type 1
    Dynamic = 2,
};

pub const HdrStaticMetadata = struct {
    eotf: HdrEotf,
    metadata_type: HdrMetadataType,
    display_primaries: [3]HdrColorPrimary, // RGB
    white_point: HdrColorPrimary,
    max_display_mastering_luminance: u16,   // cd/m²
    min_display_mastering_luminance: u16,   // 0.0001 cd/m²
    max_cll: u16,              // Max Content Light Level
    max_fall: u16,             // Max Frame Average Light Level
};

pub const HdrEotf = enum(u8) {
    Sdr = 0,
    HdrLuminance = 1,     // Traditional HDR
    Smpte2084 = 2,        // PQ (Perceptual Quantizer)
    Hlg = 3,              // Hybrid Log-Gamma
};

pub const HdrColorPrimary = struct {
    x: u16,               // In 0.00002 units
    y: u16,
};

// ============================================================================
// DisplayPort
// ============================================================================

pub const DpLinkRate = enum(u32) {
    RBR = 162000,          // 1.62 GHz (RBR)
    HBR = 270000,          // 2.7 GHz (HBR)
    HBR2 = 540000,         // 5.4 GHz (HBR2)
    HBR3 = 810000,         // 8.1 GHz (HBR3)
    UHBR10 = 1000000,      // 10 Gbps (UHBR10)
    UHBR13_5 = 1350000,    // 13.5 Gbps
    UHBR20 = 2000000,      // 20 Gbps (UHBR20)
};

pub const DpLaneCount = enum(u8) {
    Lane1 = 1,
    Lane2 = 2,
    Lane4 = 4,
};

pub const DpTrainingStatus = enum(u8) {
    NotStarted = 0,
    ClockRecovery = 1,
    ChannelEqualization = 2,
    Complete = 3,
    Failed = 4,
};

pub const DpAuxCommand = enum(u8) {
    NativeWrite = 0x8,
    NativeRead = 0x9,
    I2cWrite = 0x0,
    I2cRead = 0x1,
    I2cWriteStatusRequest = 0x2,
    MotI2cWrite = 0x4,
    MotI2cRead = 0x5,
    MotI2cWriteStatusRequest = 0x6,
};

pub const DpDpcdRegister = enum(u32) {
    RevMajor = 0x00000,
    MaxLinkRate = 0x00001,
    MaxLaneCount = 0x00002,
    MaxDownspread = 0x00003,
    NorpDpPwrVoltage = 0x00004,
    DownstreamPortPresent = 0x00005,
    MainLinkChannelCoding = 0x00006,
    DownstreamPortCount = 0x00007,
    ReceiverAudioCaps = 0x00009,
    ReceivePort0Status = 0x00200,
    LinkStatus = 0x00202,
    SinkCount = 0x00200,
    DeviceServiceIrqVector = 0x00201,
    TrainingPatternSet = 0x00102,
    LinkBwSet = 0x00100,
    LaneCountSet = 0x00101,
};

pub const DpMstBranch = struct {
    device_type: u8,
    peer_device_type: u8,
    num_ports: u8,
    rad: [8]u8,
    rad_len: u8,
    lct: u8,
    guid: [16]u8,
    ports: [16]DpMstPort,
};

pub const DpMstPort = struct {
    port_num: u8,
    input_port: bool,
    peer_device_type: u8,
    mcs: bool,
    ddps: bool,
    legacy_device_plug_status: bool,
    dpcd_revision: u8,
    available_pbn: u16,
    full_pbn: u16,
    num_sdp_streams: u8,
};

// ============================================================================
// DSI (Display Serial Interface)
// ============================================================================

pub const DsiMode = enum(u8) {
    Command = 0,
    Video = 1,
};

pub const DsiVideoMode = enum(u8) {
    NonBurstSyncPulse = 0,
    NonBurstSyncEvent = 1,
    Burst = 2,
};

pub const DsiPixelFormat = enum(u8) {
    Rgb888 = 0,
    Rgb666 = 1,
    Rgb666Packed = 2,
    Rgb565 = 3,
};

pub const DsiFlags = packed struct(u32) {
    mode_video: bool,
    video_burst: bool,
    video_sync_pulse: bool,
    mode_eot_packet: bool,
    clock_non_continuous: bool,
    mode_lpm: bool,
    no_eot_packet: bool,
    _reserved: u25,
};

// ============================================================================
// Color Management
// ============================================================================

pub const DrmColorEncoding = enum(u8) {
    Bt601 = 0,
    Bt709 = 1,
    Bt2020 = 2,
};

pub const DrmColorRange = enum(u8) {
    Limited = 0,
    Full = 1,
};

pub const DrmColorGammaLut = struct {
    red: u16,
    green: u16,
    blue: u16,
    _reserved: u16,
};

pub const DrmColorCtmEntry = struct {
    value: i64,            // Sign-magnitude format (1.31.32)
};

pub const DrmColorCtm = struct {
    matrix: [9]DrmColorCtmEntry, // 3x3 conversion matrix
};

// ============================================================================
// Manager
// ============================================================================

pub const DrmConnectorManager = struct {
    total_connectors: u32,
    total_modes: u32,
    total_edid_parsed: u32,
    total_hotplug_events: u64,
    total_dp_link_trains: u64,
    total_hdmi_infoframes: u64,
    total_mst_topology_changes: u32,
    hdr_supported: bool,
    initialized: bool,

    pub fn init() DrmConnectorManager {
        return .{
            .total_connectors = 0,
            .total_modes = 0,
            .total_edid_parsed = 0,
            .total_hotplug_events = 0,
            .total_dp_link_trains = 0,
            .total_hdmi_infoframes = 0,
            .total_mst_topology_changes = 0,
            .hdr_supported = false,
            .initialized = true,
        };
    }
};
