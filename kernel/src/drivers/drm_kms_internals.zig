// Zxyphor Kernel - DRM/KMS Internals
// Full display pipeline: CRTC, encoder, connector, plane, framebuffer
// Mode setting, atomic commit, display state machine
// Pixel formats, modifiers, color management
// Output properties, EDID parsing structures
// Panel/bridge abstraction, backlight control
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Pixel Formats (fourcc codes)
// ============================================================================

pub const PixelFormat = enum(u32) {
    // Packed RGB
    rgb332 = fourcc('R', 'G', 'B', '8'),
    rgb565 = fourcc('R', 'G', '1', '6'),
    bgr565 = fourcc('B', 'G', '1', '6'),
    xrgb8888 = fourcc('X', 'R', '2', '4'),
    xbgr8888 = fourcc('X', 'B', '2', '4'),
    argb8888 = fourcc('A', 'R', '2', '4'),
    abgr8888 = fourcc('A', 'B', '2', '4'),
    xrgb2101010 = fourcc('X', 'R', '3', '0'),
    argb2101010 = fourcc('A', 'R', '3', '0'),
    xbgr2101010 = fourcc('X', 'B', '3', '0'),
    abgr2101010 = fourcc('A', 'B', '3', '0'),
    xrgb16161616f = fourcc('X', 'R', '4', 'H'),
    argb16161616f = fourcc('A', 'R', '4', 'H'),
    // Packed YUV
    yuyv = fourcc('Y', 'U', 'Y', 'V'),
    yvyu = fourcc('Y', 'V', 'Y', 'U'),
    uyvy = fourcc('U', 'Y', 'V', 'Y'),
    vyuy = fourcc('V', 'Y', 'U', 'Y'),
    // Planar YUV
    nv12 = fourcc('N', 'V', '1', '2'),
    nv21 = fourcc('N', 'V', '2', '1'),
    nv16 = fourcc('N', 'V', '1', '6'),
    nv61 = fourcc('N', 'V', '6', '1'),
    yuv420 = fourcc('Y', 'U', '1', '2'),
    yuv422 = fourcc('Y', 'U', '1', '6'),
    yuv444 = fourcc('Y', 'U', '2', '4'),
    // Compressed
    c8 = fourcc('C', '8', ' ', ' '),
    r8 = fourcc('R', '8', ' ', ' '),
    r16 = fourcc('R', '1', '6', ' '),
    rg88 = fourcc('R', 'G', '8', '8'),
    rg1616 = fourcc('R', 'G', '3', '2'),
    _,
};

fn fourcc(a: u8, b: u8, c: u8, d: u8) u32 {
    return @as(u32, a) | (@as(u32, b) << 8) | (@as(u32, c) << 16) | (@as(u32, d) << 24);
}

// ============================================================================
// Format Modifiers (vendor-neutral and vendor-specific)
// ============================================================================

pub const FormatModifier = enum(u64) {
    linear = 0,
    // Intel modifiers
    i915_x_tiled = (1 << 56) | 1,
    i915_y_tiled = (1 << 56) | 2,
    i915_yf_tiled = (1 << 56) | 3,
    i915_y_tiled_ccs = (1 << 56) | 4,
    i915_yf_tiled_ccs = (1 << 56) | 5,
    i915_y_tiled_gen12_rc_ccs = (1 << 56) | 6,
    i915_y_tiled_gen12_mc_ccs = (1 << 56) | 7,
    i915_4_tiled = (1 << 56) | 9,
    i915_4_tiled_dg2_rc_ccs = (1 << 56) | 10,
    i915_4_tiled_dg2_mc_ccs = (1 << 56) | 11,
    i915_4_tiled_dg2_rc_ccs_cc = (1 << 56) | 12,
    // AMD modifiers
    amd_gfx9_64kb_s = (2 << 56) | 1,
    amd_gfx9_64kb_d = (2 << 56) | 2,
    amd_gfx9_64kb_s_x = (2 << 56) | 3,
    amd_gfx9_64kb_d_x = (2 << 56) | 4,
    amd_gfx10_64kb_r_x = (2 << 56) | 5,
    amd_gfx10_64kb_s_x = (2 << 56) | 6,
    amd_gfx11_256kb_r_x = (2 << 56) | 7,
    // ARM modifiers
    arm_afbc_16x16 = (8 << 56) | 1,
    arm_afbc_32x8 = (8 << 56) | 2,
    _,
};

// ============================================================================
// Display Mode
// ============================================================================

pub const DisplayMode = struct {
    clock: u32,        // pixel clock in kHz
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
    vrefresh: u32,     // in Hz
    flags: ModeFlags,
    mode_type: u32,
    name: [32]u8,
    width_mm: u16,
    height_mm: u16,

    pub fn hfreq_khz(self: *const @This()) u32 {
        if (self.htotal == 0) return 0;
        return self.clock / @as(u32, self.htotal);
    }
};

pub const ModeFlags = packed struct(u32) {
    phsync: bool = false,
    nhsync: bool = false,
    pvsync: bool = false,
    nvsync: bool = false,
    interlace: bool = false,
    dblscan: bool = false,
    csync: bool = false,
    pcsync: bool = false,
    ncsync: bool = false,
    hskew: bool = false,
    dblclk: bool = false,
    clkdiv2: bool = false,
    _pad: u20 = 0,
};

// ============================================================================
// CRTC (Cathode Ray Tube Controller / Display Pipeline)
// ============================================================================

pub const CrtcState = struct {
    enable: bool,
    active: bool,
    mode: DisplayMode,
    adjusted_mode: DisplayMode,
    gamma_lut: ?*GammaLut,
    degamma_lut: ?*GammaLut,
    ctm: ?*ColorTransformMatrix,
    vrr_enabled: bool,
    self_refresh_active: bool,
    scaling_filter: ScalingFilter,
    event: ?*PageFlipEvent,
    commit: ?*AtomicCommit,
    connector_mask: u32,
    encoder_mask: u32,
    zpos_changed: bool,
    color_mgmt_changed: bool,
    no_vblank: bool,
};

pub const Crtc = struct {
    index: u32,
    crtc_id: u32,
    name: [32]u8,
    enabled: bool,
    mode: DisplayMode,
    cursor_x: i32,
    cursor_y: i32,
    state: ?*CrtcState,
    primary_plane: ?*Plane,
    cursor_plane: ?*Plane,
    gamma_size: u32,
    funcs: CrtcFuncs,
};

pub const CrtcFuncs = struct {
    reset: ?*const fn (*Crtc) void = null,
    set_config: ?*const fn (*Crtc, *const DisplayMode) i32 = null,
    page_flip: ?*const fn (*Crtc, *const Framebuffer) i32 = null,
    destroy: ?*const fn (*Crtc) void = null,
    atomic_check: ?*const fn (*Crtc, *CrtcState) i32 = null,
    atomic_begin: ?*const fn (*Crtc, *CrtcState) void = null,
    atomic_flush: ?*const fn (*Crtc, *CrtcState) void = null,
    atomic_enable: ?*const fn (*Crtc, *CrtcState) void = null,
    atomic_disable: ?*const fn (*Crtc, *CrtcState) void = null,
    get_vblank_counter: ?*const fn (*Crtc) u64 = null,
    enable_vblank: ?*const fn (*Crtc) i32 = null,
    disable_vblank: ?*const fn (*Crtc) void = null,
};

// ============================================================================
// Plane (overlay, primary, cursor)
// ============================================================================

pub const PlaneType = enum(u8) {
    overlay = 0,
    primary = 1,
    cursor = 2,
};

pub const PlaneState = struct {
    crtc: ?*Crtc,
    fb: ?*Framebuffer,
    crtc_x: i32,
    crtc_y: i32,
    crtc_w: u32,
    crtc_h: u32,
    src_x: u32, // 16.16 fixed point
    src_y: u32,
    src_w: u32,
    src_h: u32,
    alpha: u16,
    pixel_blend_mode: PixelBlendMode,
    rotation: RotationFlags,
    zpos: u32,
    normalized_zpos: u32,
    color_encoding: ColorEncoding,
    color_range: ColorRange,
    scaling_filter: ScalingFilter,
    visible: bool,
    commit: ?*AtomicCommit,
};

pub const PixelBlendMode = enum(u8) {
    none = 0,
    premulti = 1,
    coverage = 2,
};

pub const RotationFlags = packed struct(u8) {
    rotate_0: bool = true,
    rotate_90: bool = false,
    rotate_180: bool = false,
    rotate_270: bool = false,
    reflect_x: bool = false,
    reflect_y: bool = false,
    _pad: u2 = 0,
};

pub const ColorEncoding = enum(u8) {
    bt601 = 0,
    bt709 = 1,
    bt2020 = 2,
};

pub const ColorRange = enum(u8) {
    limited = 0,
    full = 1,
};

pub const ScalingFilter = enum(u8) {
    default = 0,
    nearest_neighbor = 1,
};

pub const Plane = struct {
    index: u32,
    plane_id: u32,
    plane_type: PlaneType,
    possible_crtcs: u32,
    format_count: u32,
    formats: [64]PixelFormat,
    modifier_count: u32,
    modifiers: [32]FormatModifier,
    state: ?*PlaneState,
    funcs: PlaneFuncs,
    name: [32]u8,
};

pub const PlaneFuncs = struct {
    update_plane: ?*const fn (*Plane, *Crtc, *Framebuffer) i32 = null,
    disable_plane: ?*const fn (*Plane) i32 = null,
    destroy: ?*const fn (*Plane) void = null,
    atomic_check: ?*const fn (*Plane, *PlaneState) i32 = null,
    atomic_update: ?*const fn (*Plane, *PlaneState) void = null,
    atomic_disable: ?*const fn (*Plane, *PlaneState) void = null,
};

// ============================================================================
// Encoder
// ============================================================================

pub const EncoderType = enum(u8) {
    none = 0,
    dac = 1,
    tmds = 2,
    lvds = 3,
    tvdac = 4,
    virtual_enc = 5,
    dsi = 6,
    dpmst = 7,
    dpi = 8,
};

pub const Encoder = struct {
    encoder_id: u32,
    encoder_type: EncoderType,
    possible_crtcs: u32,
    possible_clones: u32,
    crtc: ?*Crtc,
    name: [32]u8,
    funcs: EncoderFuncs,
};

pub const EncoderFuncs = struct {
    reset: ?*const fn (*Encoder) void = null,
    destroy: ?*const fn (*Encoder) void = null,
    mode_fixup: ?*const fn (*Encoder, *const DisplayMode, *DisplayMode) bool = null,
    mode_set: ?*const fn (*Encoder, *const DisplayMode, *const DisplayMode) void = null,
    enable: ?*const fn (*Encoder) void = null,
    disable: ?*const fn (*Encoder) void = null,
    atomic_check: ?*const fn (*Encoder, *CrtcState) i32 = null,
};

// ============================================================================
// Connector
// ============================================================================

pub const ConnectorType = enum(u8) {
    unknown = 0,
    vga = 1,
    dvii = 2,
    dvid = 3,
    dvia = 4,
    composite = 5,
    svideo = 6,
    lvds = 7,
    component = 8,
    mini_din9 = 9,
    displayport = 10,
    hdmia = 11,
    hdmib = 12,
    tv = 13,
    edp = 14,
    virtual_conn = 15,
    dsi = 16,
    dpi = 17,
    writeback = 18,
    spi = 19,
    usb = 20,
};

pub const ConnectorStatus = enum(u8) {
    connected = 1,
    disconnected = 2,
    unknown = 3,
};

pub const ContentProtection = enum(u8) {
    undesired = 0,
    desired = 1,
    enabled = 2,
};

pub const HdcpVersion = enum(u8) {
    none = 0,
    hdcp14 = 1,
    hdcp22 = 2,
};

pub const LinkStatus = enum(u8) {
    good = 0,
    bad = 1,
};

pub const DpmsState = enum(u8) {
    on = 0,
    standby = 1,
    suspend = 2,
    off = 3,
};

pub const ConnectorState = struct {
    crtc: ?*Crtc,
    encoder: ?*Encoder,
    best_encoder: ?*Encoder,
    link_status: LinkStatus,
    content_protection: ContentProtection,
    hdcp_content_type: u8,
    scaling_mode: u8,
    colorspace: u32,
    max_bpc: u32,
    max_requested_bpc: u32,
    hdr_output_metadata: ?*HdrMetadata,
    vrr_capable: bool,
    underscan: u8,
    underscan_hborder: u32,
    underscan_vborder: u32,
    commit: ?*AtomicCommit,
};

pub const Connector = struct {
    connector_id: u32,
    connector_type: ConnectorType,
    connector_type_id: u32,
    status: ConnectorStatus,
    encoder: ?*Encoder,
    possible_encoders: u32,
    modes_count: u32,
    modes: [64]DisplayMode,
    dpms: DpmsState,
    state: ?*ConnectorState,
    funcs: ConnectorFuncs,
    name: [32]u8,
    edid_blob: ?[*]u8,
    edid_len: u32,
    // Physical dimensions
    width_mm: u32,
    height_mm: u32,
    // Subconnector info
    subconnector: u8,
};

pub const ConnectorFuncs = struct {
    detect: ?*const fn (*Connector, bool) ConnectorStatus = null,
    fill_modes: ?*const fn (*Connector, u32, u32) i32 = null,
    destroy: ?*const fn (*Connector) void = null,
    force: ?*const fn (*Connector) void = null,
    reset: ?*const fn (*Connector) void = null,
    atomic_check: ?*const fn (*Connector, *ConnectorState) i32 = null,
    get_modes: ?*const fn (*Connector) i32 = null,
    mode_valid: ?*const fn (*Connector, *const DisplayMode) ModeStatus = null,
    best_encoder: ?*const fn (*Connector) ?*Encoder = null,
};

pub const ModeStatus = enum(u8) {
    ok = 0,
    hsync = 1,
    vsync = 2,
    h_illegal = 3,
    v_illegal = 4,
    bad_width = 5,
    nomode = 6,
    no_interlace = 7,
    no_dblescan = 8,
    clock_high = 9,
    clock_low = 10,
    clock_range = 11,
    bad_hvalue = 12,
    bad_vvalue = 13,
    bad_vscan = 14,
    no_reduced = 15,
    virtual_x = 16,
    virtual_y = 17,
    mem = 18,
    bandwidth = 19,
    panel = 20,
    connector = 21,
    encoder_cloning = 22,
};

// ============================================================================
// Framebuffer
// ============================================================================

pub const Framebuffer = struct {
    fb_id: u32,
    width: u32,
    height: u32,
    format: PixelFormat,
    modifier: FormatModifier,
    pitches: [4]u32,
    offsets: [4]u32,
    num_planes: u8,
    obj: [4]?*GemObject,
    funcs: FramebufferFuncs,
};

pub const FramebufferFuncs = struct {
    destroy: ?*const fn (*Framebuffer) void = null,
    create_handle: ?*const fn (*Framebuffer, u32) i32 = null,
    dirty: ?*const fn (*Framebuffer, ?*const DirtyClip, u32) i32 = null,
};

pub const DirtyClip = struct {
    x1: u32,
    y1: u32,
    x2: u32,
    y2: u32,
};

// ============================================================================
// GEM (Graphics Execution Manager)
// ============================================================================

pub const GemObject = struct {
    size: u64,
    name: u32,
    handle_count: u32,
    funcs: GemObjectFuncs,
    vma_node: u64,
    dma_buf: ?*DmaBuf,
    import_attach: ?*DmaBufAttachment,
};

pub const GemObjectFuncs = struct {
    free: ?*const fn (*GemObject) void = null,
    open: ?*const fn (*GemObject) i32 = null,
    close: ?*const fn (*GemObject) void = null,
    export: ?*const fn (*GemObject) ?*DmaBuf = null,
    pin: ?*const fn (*GemObject) i32 = null,
    unpin: ?*const fn (*GemObject) void = null,
    vmap: ?*const fn (*GemObject) ?*anyopaque = null,
    vunmap: ?*const fn (*GemObject, *anyopaque) void = null,
    mmap: ?*const fn (*GemObject) i32 = null,
};

pub const DmaBuf = struct {
    size: u64,
    file: u64,
    ops: ?*DmaBufOps,
    exp_name: [32]u8,
};

pub const DmaBufOps = struct {
    attach: ?*const fn (*DmaBuf) i32 = null,
    detach: ?*const fn (*DmaBuf) void = null,
    map_dma_buf: ?*const fn (*DmaBuf) ?*anyopaque = null,
    unmap_dma_buf: ?*const fn (*DmaBuf, *anyopaque) void = null,
    release: ?*const fn (*DmaBuf) void = null,
    mmap: ?*const fn (*DmaBuf) i32 = null,
    vmap: ?*const fn (*DmaBuf) ?*anyopaque = null,
    vunmap: ?*const fn (*DmaBuf, *anyopaque) void = null,
};

pub const DmaBufAttachment = struct {
    dmabuf: ?*DmaBuf,
    peer2peer: bool,
};

// ============================================================================
// Atomic Commit
// ============================================================================

pub const AtomicCommit = struct {
    flags: AtomicFlags,
    crtc_count: u32,
    plane_count: u32,
    connector_count: u32,
    fence_count: u32,
    user_data: u64,
};

pub const AtomicFlags = packed struct(u32) {
    page_flip_event: bool = false,
    test_only: bool = false,
    nonblock: bool = false,
    allow_modeset: bool = false,
    _pad: u28 = 0,
};

// ============================================================================
// Color Management
// ============================================================================

pub const GammaLut = struct {
    size: u32,
    entries: [1024]GammaEntry,
};

pub const GammaEntry = struct {
    red: u16,
    green: u16,
    blue: u16,
    _reserved: u16 = 0,
};

pub const ColorTransformMatrix = struct {
    // 3x3 matrix in S31.32 fixed-point format
    matrix: [9]i64,
};

// ============================================================================
// HDR Metadata
// ============================================================================

pub const HdrMetadata = struct {
    metadata_type: HdrMetadataType,
    display_primaries: [3]Chromaticity,
    white_point: Chromaticity,
    max_display_mastering_luminance: u32,
    min_display_mastering_luminance: u32,
    max_cll: u16,
    max_fall: u16,
    eotf: EotfType,
};

pub const HdrMetadataType = enum(u8) {
    type1 = 0,
    type2 = 1,
};

pub const Chromaticity = struct {
    x: u16, // CIE 1931 x * 50000
    y: u16, // CIE 1931 y * 50000
};

pub const EotfType = enum(u8) {
    traditional_sdr = 0,
    traditional_hdr = 1,
    smpte_st2084 = 2,
    hlg = 3,
};

// ============================================================================
// Page Flip Event
// ============================================================================

pub const PageFlipEvent = struct {
    tv_sec: u64,
    tv_usec: u64,
    sequence: u32,
    crtc_id: u32,
    user_data: u64,
};

// ============================================================================
// EDID Structures
// ============================================================================

pub const EdidHeader = extern struct {
    header: [8]u8,           // 00 FF FF FF FF FF FF 00
    manufacturer: [2]u8,     // compressed ASCII
    product_code: u16,
    serial_number: u32,
    week: u8,
    year: u8,               // year - 1990
    version: u8,
    revision: u8,
    video_input: u8,
    width_cm: u8,
    height_cm: u8,
    gamma: u8,              // (gamma * 100) - 100
    features: u8,
    red_green_lo: u8,
    blue_white_lo: u8,
    red_x_hi: u8,
    red_y_hi: u8,
    green_x_hi: u8,
    green_y_hi: u8,
    blue_x_hi: u8,
    blue_y_hi: u8,
    white_x_hi: u8,
    white_y_hi: u8,
    established_timings: [3]u8,
    standard_timings: [8]u16,
    detailed_timings: [4][18]u8,
    extension_count: u8,
    checksum: u8,
};

pub const EdidDetailedTiming = struct {
    pixel_clock: u16, // * 10 kHz
    h_active: u16,
    h_blanking: u16,
    v_active: u16,
    v_blanking: u16,
    h_sync_offset: u16,
    h_sync_width: u16,
    v_sync_offset: u8,
    v_sync_width: u8,
    h_image_size: u16,
    v_image_size: u16,
    h_border: u8,
    v_border: u8,
    flags: u8,
};

// ============================================================================
// DisplayPort AUX
// ============================================================================

pub const DpAuxMessage = struct {
    address: u32,
    reply: u8,
    size: u32,
    buffer: [16]u8,
    request: DpAuxCmd,
};

pub const DpAuxCmd = enum(u8) {
    native_write = 0x08,
    native_read = 0x09,
    i2c_write = 0x00,
    i2c_read = 0x01,
    i2c_write_status = 0x02,
    i2c_mot_write = 0x04,
    i2c_mot_read = 0x05,
};

pub const DpLinkRate = enum(u32) {
    rbr = 162000,    // 1.62 Gbps
    hbr = 270000,    // 2.7 Gbps
    hbr2 = 540000,   // 5.4 Gbps
    hbr3 = 810000,   // 8.1 Gbps
    uhbr10 = 1000000, // 10 Gbps
    uhbr13p5 = 1350000,
    uhbr20 = 2000000, // 20 Gbps
};

pub const DpTrainingPattern = enum(u8) {
    disable = 0,
    pattern1 = 1,
    pattern2 = 2,
    pattern3 = 3,
    pattern4 = 4,
};

// ============================================================================
// Panel / Bridge
// ============================================================================

pub const PanelOrientation = enum(u8) {
    normal = 0,
    bottom_up = 1,
    left_up = 2,
    right_up = 3,
};

pub const Panel = struct {
    connector: ?*Connector,
    backlight: ?*BacklightDevice,
    orientation: PanelOrientation,
    prepared: bool,
    enabled: bool,
    funcs: PanelFuncs,
};

pub const PanelFuncs = struct {
    prepare: ?*const fn (*Panel) i32 = null,
    enable: ?*const fn (*Panel) i32 = null,
    disable: ?*const fn (*Panel) i32 = null,
    unprepare: ?*const fn (*Panel) i32 = null,
    get_modes: ?*const fn (*Panel, *Connector) i32 = null,
    get_timings: ?*const fn (*Panel, u32, *DisplayMode) i32 = null,
};

pub const BridgeType = enum(u8) {
    unknown = 0,
    dsi_to_edp = 1,
    lvds_to_edp = 2,
    dp_to_hdmi = 3,
    hdmi_to_dp = 4,
    analog = 5,
};

pub const Bridge = struct {
    bridge_type: BridgeType,
    encoder: ?*Encoder,
    next: ?*Bridge,
    funcs: BridgeFuncs,
};

pub const BridgeFuncs = struct {
    attach: ?*const fn (*Bridge) i32 = null,
    detach: ?*const fn (*Bridge) void = null,
    mode_fixup: ?*const fn (*Bridge, *const DisplayMode, *DisplayMode) bool = null,
    mode_set: ?*const fn (*Bridge, *const DisplayMode, *const DisplayMode) void = null,
    pre_enable: ?*const fn (*Bridge) void = null,
    enable: ?*const fn (*Bridge) void = null,
    disable: ?*const fn (*Bridge) void = null,
    post_disable: ?*const fn (*Bridge) void = null,
    atomic_check: ?*const fn (*Bridge, *CrtcState) i32 = null,
    detect: ?*const fn (*Bridge) ConnectorStatus = null,
    get_modes: ?*const fn (*Bridge, *Connector) i32 = null,
    get_edid: ?*const fn (*Bridge) ?*EdidHeader = null,
    hpd_enable: ?*const fn (*Bridge) void = null,
    hpd_disable: ?*const fn (*Bridge) void = null,
};

// ============================================================================
// Backlight
// ============================================================================

pub const BacklightType = enum(u8) {
    raw = 0,
    platform = 1,
    firmware = 2,
};

pub const BacklightDevice = struct {
    bl_type: BacklightType,
    max_brightness: u32,
    brightness: u32,
    power: u8,
    scale: BacklightScale,
    ops: BacklightOps,
};

pub const BacklightScale = enum(u8) {
    unknown = 0,
    linear = 1,
    non_linear = 2,
};

pub const BacklightOps = struct {
    update_status: ?*const fn (*BacklightDevice) i32 = null,
    get_brightness: ?*const fn (*BacklightDevice) u32 = null,
};

// ============================================================================
// GPU Scheduler
// ============================================================================

pub const SchedPriority = enum(u8) {
    min = 0,
    normal = 1,
    high = 2,
    kernel = 3,
};

pub const SchedEntity = struct {
    priority: SchedPriority,
    guilty: bool,
    job_count: u64,
    hang_count: u32,
};

pub const SchedJob = struct {
    entity: ?*SchedEntity,
    id: u64,
    timeout: u64,
    credits: u32,
    s_fence: ?*SchedFence,
};

pub const SchedFence = struct {
    scheduled: u64,    // fence for scheduling
    finished: u64,     // fence for completion
    parent: ?*u64,
};

// ============================================================================
// DRM Device
// ============================================================================

pub const DrmDevice = struct {
    dev_name: [64]u8,
    driver: DrmDriver,
    unique: [128]u8,
    // Modesetting state
    num_crtcs: u32,
    num_encoders: u32,
    num_connectors: u32,
    num_planes: u32,
    num_fbs: u32,
    // Feature flags
    pci_vendor: u16,
    pci_device: u16,
    agp_enabled: bool,
    irq_enabled: bool,
    vblank_disable_immediate: bool,
    mode_config: ModeConfig,
};

pub const DrmDriver = struct {
    name: [32]u8,
    desc: [128]u8,
    date: [16]u8,
    major: u32,
    minor: u32,
    patchlevel: u32,
    driver_features: DriverFeatures,
};

pub const DriverFeatures = packed struct(u32) {
    gem: bool = false,
    modeset: bool = false,
    render: bool = false,
    atomic: bool = false,
    syncobj: bool = false,
    syncobj_timeline: bool = false,
    compute_accel: bool = false,
    _pad: u25 = 0,
};

pub const ModeConfig = struct {
    min_width: u32,
    max_width: u32,
    min_height: u32,
    max_height: u32,
    preferred_depth: u32,
    prefer_shadow: bool,
    prefer_shadow_fbdev: bool,
    async_page_flip: bool,
    quirk_addfb_prefer_xbgr_30bpp: bool,
    allow_fb_modifiers: bool,
    normalize_zpos: bool,
    cursor_width: u32,
    cursor_height: u32,
    num_property: u32,
};

// ============================================================================
// DRM/KMS Subsystem Manager
// ============================================================================

pub const DrmSubsystemManager = struct {
    device_count: u32,
    total_connectors: u32,
    total_crtcs: u32,
    total_planes: u32,
    total_encoders: u32,
    total_fbs_allocated: u64,
    total_gem_objects: u64,
    total_mode_sets: u64,
    total_page_flips: u64,
    total_atomic_commits: u64,
    total_vblank_events: u64,
    initialized: bool,

    pub fn init() DrmSubsystemManager {
        return DrmSubsystemManager{
            .device_count = 0,
            .total_connectors = 0,
            .total_crtcs = 0,
            .total_planes = 0,
            .total_encoders = 0,
            .total_fbs_allocated = 0,
            .total_gem_objects = 0,
            .total_mode_sets = 0,
            .total_page_flips = 0,
            .total_atomic_commits = 0,
            .total_vblank_events = 0,
            .initialized = true,
        };
    }
};
