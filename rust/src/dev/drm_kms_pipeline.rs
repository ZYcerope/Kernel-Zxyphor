// SPDX-License-Identifier: Apache-2.0
// Zxyphor Kernel Rust - DRM/KMS Display Pipeline Complete
// CRTC, Encoder, Connector, Plane, Framebuffer, Mode,
// Atomic commit, Property, GEM, Fence, VBlank

/// DRM Object Types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrmObjectType {
    Crtc = 0xcccccccc,
    Connector = 0xc0c0c0c0,
    Encoder = 0xe0e0e0e0,
    Mode = 0xdededede,
    Property = 0xb0b0b0b0,
    Fb = 0xfbfbfbfb,
    Blob = 0xbbbbbbbb,
    Plane = 0xeeeeeeee,
}

/// DRM Mode Info (display mode)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DrmModeInfo {
    pub clock: u32,              // kHz
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub hskew: u16,
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub vscan: u16,
    pub vrefresh: u32,
    pub flags: DrmModeFlags,
    pub mode_type: DrmModeType,
    pub name: [32; u8],
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct DrmModeFlags: u32 {
        const PHSYNC = 1 << 0;
        const NHSYNC = 1 << 1;
        const PVSYNC = 1 << 2;
        const NVSYNC = 1 << 3;
        const INTERLACE = 1 << 4;
        const DBLSCAN = 1 << 5;
        const CSYNC = 1 << 6;
        const PCSYNC = 1 << 7;
        const NCSYNC = 1 << 8;
        const HSKEW = 1 << 9;
        const DBLCLK = 1 << 12;
        const CLKDIV2 = 1 << 13;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct DrmModeType: u32 {
        const PREFERRED = 1 << 3;
        const USERDEF = 1 << 5;
        const DRIVER = 1 << 6;
    }
}

/// DRM Pixel Formats (fourcc)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrmFourcc {
    C8 = 0x20203843,
    RGB332 = 0x38424752,
    BGR233 = 0x38524742,
    XRGB4444 = 0x32315258,
    XBGR4444 = 0x32314258,
    RGBX4444 = 0x32315852,
    BGRX4444 = 0x32315842,
    ARGB4444 = 0x32315241,
    ABGR4444 = 0x32314241,
    RGBA4444 = 0x32314152,
    BGRA4444 = 0x32314142,
    XRGB1555 = 0x35315258,
    RGB565 = 0x36314752,
    BGR565 = 0x36314742,
    RGB888 = 0x34324752,
    BGR888 = 0x34324742,
    XRGB8888 = 0x34325258,
    XBGR8888 = 0x34324258,
    RGBX8888 = 0x34325852,
    BGRX8888 = 0x34325842,
    ARGB8888 = 0x34325241,
    ABGR8888 = 0x34324241,
    RGBA8888 = 0x34324152,
    BGRA8888 = 0x34324142,
    XRGB2101010 = 0x30335258,
    XBGR2101010 = 0x30334258,
    ARGB2101010 = 0x30335241,
    ABGR2101010 = 0x30334241,
    NV12 = 0x3231564E,
    NV21 = 0x3132564E,
    NV16 = 0x3631564E,
    NV61 = 0x3136564E,
    YUV420 = 0x32315559,
    YVU420 = 0x32315659,
    YUV422 = 0x36315559,
    YUV444 = 0x34325559,
    XRGB16161616F = 0x48345258,
    XBGR16161616F = 0x48344258,
    ARGB16161616F = 0x48345241,
    ABGR16161616F = 0x48344241,
}

/// DRM Connector Types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrmConnectorType {
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
    EDP = 14,
    Virtual = 15,
    DSI = 16,
    DPI = 17,
    Writeback = 18,
    SPI = 19,
    USB = 20,
}

/// DRM Connector Status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrmConnectorStatus {
    Connected = 1,
    Disconnected = 2,
    Unknown = 3,
}

/// DRM Encoder Types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrmEncoderType {
    None = 0,
    DAC = 1,
    TMDS = 2,
    LVDS = 3,
    TVDAC = 4,
    Virtual = 5,
    DSI = 6,
    DPMST = 7,
    DPI = 8,
}

/// DRM Plane Types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrmPlaneType {
    Overlay = 0,
    Primary = 1,
    Cursor = 2,
}

/// DRM CRTC State (for atomic modeset)
#[derive(Debug, Clone)]
pub struct DrmCrtcState {
    pub enable: bool,
    pub active: bool,
    pub planes_changed: bool,
    pub mode_changed: bool,
    pub active_changed: bool,
    pub connectors_changed: bool,
    pub zpos_changed: bool,
    pub color_mgmt_changed: bool,
    pub no_vblank: bool,
    pub self_refresh_active: bool,
    pub mode: DrmModeInfo,
    pub adjusted_mode: DrmModeInfo,
    pub gamma_lut: Option<Vec<DrmColorLut>>,
    pub degamma_lut: Option<Vec<DrmColorLut>>,
    pub ctm: Option<DrmColorCtm>,
    pub target_vblank: u32,
    pub async_flip: bool,
    pub vrr_enabled: bool,
}

/// DRM Plane State
#[derive(Debug, Clone)]
pub struct DrmPlaneState {
    pub crtc_id: u32,
    pub fb_id: u32,
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    pub src_x: u32,     // 16.16 fixed
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    pub alpha: u16,     // 0-0xFFFF
    pub pixel_blend_mode: DrmBlendMode,
    pub rotation: DrmRotation,
    pub zpos: u32,
    pub normalized_zpos: u32,
    pub color_encoding: DrmColorEncoding,
    pub color_range: DrmColorRange,
    pub fb_damage_clips: Vec<DrmRect>,
    pub visible: bool,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmBlendMode {
    None = 0,
    PreMultiplied = 1,
    Coverage = 2,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct DrmRotation: u32 {
        const ROTATE_0 = 1 << 0;
        const ROTATE_90 = 1 << 1;
        const ROTATE_180 = 1 << 2;
        const ROTATE_270 = 1 << 3;
        const REFLECT_X = 1 << 4;
        const REFLECT_Y = 1 << 5;
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmColorEncoding {
    BT601 = 0,
    BT709 = 1,
    BT2020 = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmColorRange {
    Limited = 0,
    Full = 1,
}

/// DRM Rect
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DrmRect {
    pub x1: i32,
    pub y1: i32,
    pub x2: i32,
    pub y2: i32,
}

/// Color LUT and CTM
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DrmColorLut {
    pub red: u16,
    pub green: u16,
    pub blue: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DrmColorCtm {
    pub matrix: [9; i64], // S31.32 sign-magnitude
}

/// Framebuffer
#[derive(Debug, Clone)]
pub struct DrmFramebuffer {
    pub fb_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: DrmFourcc,
    pub modifier: u64,
    pub pitches: [4; u32],
    pub offsets: [4; u32],
    pub handles: [4; u32],
    pub flags: DrmFbFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct DrmFbFlags: u32 {
        const INTERLACED = 1 << 0;
        const MODIFIERS = 1 << 1;
    }
}

/// GEM (Graphics Execution Manager) Object
#[derive(Debug)]
pub struct GemObject {
    pub handle: u32,
    pub size: u64,
    pub name: u32,
    pub map_offset: u64,
    pub import_attach: Option<u64>,
    pub dma_buf: Option<u64>,
    pub funcs: GemObjectFuncs,
    pub resv: DmaResv,
}

/// GEM Object Functions
#[derive(Debug, Clone)]
pub struct GemObjectFuncs {
    pub free: bool,
    pub open: bool,
    pub close: bool,
    pub print_info: bool,
    pub export: bool,
    pub pin: bool,
    pub unpin: bool,
    pub get_sg_table: bool,
    pub vmap: bool,
    pub vunmap: bool,
    pub mmap: bool,
    pub vm_ops: bool,
    pub evict: bool,
    pub purge: bool,
    pub status: bool,
    pub rss: bool,
}

/// DMA Fence
#[derive(Debug)]
pub struct DmaFence {
    pub context: u64,
    pub seqno: u64,
    pub flags: DmaFenceFlags,
    pub timestamp: i64,
    pub error: i32,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct DmaFenceFlags: u32 {
        const SIGNALED = 1 << 0;
        const TIMESTAMP = 1 << 1;
        const ENABLE_SIGNAL = 1 << 2;
        const USER = 1 << 3;
    }
}

/// DMA Reservation
#[derive(Debug)]
pub struct DmaResv {
    pub fence_excl: Option<Box<DmaFence>>,
    pub num_shared: u32,
    pub max_shared: u32,
}

/// Atomic Commit Flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct AtomicCommitFlags: u32 {
        const PAGE_FLIP_EVENT = 1 << 0;
        const TEST_ONLY = 1 << 8;
        const NONBLOCK = 1 << 9;
        const ALLOW_MODESET = 1 << 10;
    }
}

/// Atomic State
#[derive(Debug)]
pub struct DrmAtomicState {
    pub crtc_states: Vec<(u32, DrmCrtcState)>,
    pub plane_states: Vec<(u32, DrmPlaneState)>,
    pub connector_states: Vec<(u32, DrmConnectorState)>,
    pub commit_flags: AtomicCommitFlags,
    pub allow_modeset: bool,
    pub legacy_cursor_update: bool,
    pub async_update: bool,
}

/// DRM Connector State
#[derive(Debug, Clone)]
pub struct DrmConnectorState {
    pub crtc_id: u32,
    pub best_encoder_id: u32,
    pub link_status: DrmLinkStatus,
    pub dpms: DrmDpms,
    pub content_type: DrmContentType,
    pub content_protection: DrmContentProtection,
    pub hdcp_content_type: DrmHdcpContentType,
    pub scaling_mode: DrmScalingMode,
    pub underscan: DrmUnderscan,
    pub max_bpc: u32,
    pub hdr_output_metadata: Option<HdrOutputMetadata>,
    pub colorspace: DrmColorspace,
    pub vrr_capable: bool,
    pub writeback_fb_id: u32,
    pub writeback_out_fence_ptr: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmLinkStatus { Good = 0, Bad = 1 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmDpms { On = 0, Standby = 1, Suspend = 2, Off = 3 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmContentType { NoData = 0, Graphics = 1, Photo = 2, Cinema = 3, Game = 4 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmContentProtection { Undesired = 0, Desired = 1, Enabled = 2 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmHdcpContentType { Type0 = 0, Type1 = 1 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmScalingMode { None = 0, Full = 1, Center = 2, Aspect = 3 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmUnderscan { Off = 0, On = 1, Auto = 2 }

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmColorspace {
    Default = 0,
    RGBWideGamutFixed = 1,
    RGBWideGamutFloat = 2,
    OpenBT601 = 3,
    OpenBT709 = 4,
    DciP3RGBData = 5,
    DciP3RGBTheater = 6,
    BT2020RGBData = 7,
    BT2020YCC = 8,
}

/// HDR Output Metadata
#[derive(Debug, Clone)]
pub struct HdrOutputMetadata {
    pub metadata_type: u32,
    pub eotf: HdrEotf,
    pub metadata_descriptor: u8,
    pub display_primaries: [(u16, u16); 3],
    pub white_point: (u16, u16),
    pub max_display_mastering_luminance: u16,
    pub min_display_mastering_luminance: u16,
    pub max_cll: u16,
    pub max_fall: u16,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum HdrEotf {
    Traditional = 0,
    TraditionalHdr = 1,
    SmpteSt2084 = 2,
    Hlg = 3,
}

/// VBlank Management
#[derive(Debug)]
pub struct VblankState {
    pub count: u64,
    pub time_ns: i64,
    pub enabled: bool,
    pub inmodeset: i32,
    pub refcount: u32,
    pub last: u32,
    pub max_vblank_count: u32,
    pub framedur_ns: i64,
    pub linedur_ns: i64,
}

/// DRM IOCTL Commands
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmIoctl {
    Version = 0x00,
    GetUnique = 0x01,
    GetMagic = 0x02,
    IrqBusid = 0x03,
    GetMap = 0x04,
    GetClient = 0x05,
    GetStats = 0x06,
    SetVersion = 0x07,
    ModesetCtl = 0x08,
    GemClose = 0x09,
    GemFlink = 0x0A,
    GemOpen = 0x0B,
    GetCap = 0x0C,
    SetClientCap = 0x0D,
    ModeGetResources = 0xA0,
    ModeGetCrtc = 0xA1,
    ModeSetCrtc = 0xA2,
    ModeCursor = 0xA3,
    ModeGetGamma = 0xA4,
    ModeSetGamma = 0xA5,
    ModeGetEncoder = 0xA6,
    ModeGetConnector = 0xA7,
    ModeGetProperty = 0xAA,
    ModeSetProperty = 0xAB,
    ModeGetPropBlob = 0xAC,
    ModeGetFB = 0xAD,
    ModeAddFB = 0xAE,
    ModeRmFB = 0xAF,
    ModePageFlip = 0xB0,
    ModeGetPlaneResources = 0xB5,
    ModeGetPlane = 0xB6,
    ModeSetPlane = 0xB7,
    ModeAddFB2 = 0xB8,
    ModeObjGetProperties = 0xB9,
    ModeObjSetProperty = 0xBA,
    ModeCursor2 = 0xBB,
    ModeAtomic = 0xBC,
    ModeCreatePropBlob = 0xBD,
    ModeDestroyPropBlob = 0xBE,
    SyncobjCreate = 0xBF,
    SyncobjDestroy = 0xC0,
    SyncobjHandleToFD = 0xC1,
    SyncobjFDToHandle = 0xC2,
    SyncobjWait = 0xC3,
    SyncobjReset = 0xC4,
    SyncobjSignal = 0xC5,
    ModeCreateLease = 0xC6,
    ModeListLessees = 0xC7,
    ModeGetLease = 0xC8,
    ModeRevokeLease = 0xC9,
    SyncobjTimeline = 0xCA,
    SyncobjQuery = 0xCB,
    SyncobjTransfer = 0xCC,
}

/// DRM Display Pipeline Manager
#[derive(Debug)]
pub struct DrmDisplayManager {
    pub num_crtcs: u32,
    pub num_connectors: u32,
    pub num_encoders: u32,
    pub num_planes: u32,
    pub num_framebuffers: u32,
    pub num_gem_objects: u32,
    pub atomic_modeset_enabled: bool,
    pub universal_planes: bool,
    pub vrr_supported: bool,
    pub hdr_supported: bool,
    pub writeback_supported: bool,
    pub preferred_depth: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub cursor_width: u32,
    pub cursor_height: u32,
    pub vblank_events: u64,
    pub page_flips: u64,
    pub atomic_commits: u64,
    pub total_mode_changes: u64,
    pub initialized: bool,
}

impl DrmDisplayManager {
    pub fn new() -> Self {
        Self {
            num_crtcs: 0,
            num_connectors: 0,
            num_encoders: 0,
            num_planes: 0,
            num_framebuffers: 0,
            num_gem_objects: 0,
            atomic_modeset_enabled: true,
            universal_planes: true,
            vrr_supported: true,
            hdr_supported: true,
            writeback_supported: false,
            preferred_depth: 24,
            max_width: 16384,
            max_height: 16384,
            cursor_width: 64,
            cursor_height: 64,
            vblank_events: 0,
            page_flips: 0,
            atomic_commits: 0,
            total_mode_changes: 0,
            initialized: true,
        }
    }
}
