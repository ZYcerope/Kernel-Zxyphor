// Zxyphor Kernel - Media V4L2 Framework, Camera Sensor,
// DRM KMS Modesetting Advanced, Display Pipeline,
// Video Codec Engine, Media Controller
// More advanced than Linux 2026 media/display subsystem

use core::fmt;

// ============================================================================
// V4L2 - Video4Linux2 Framework
// ============================================================================

/// V4L2 device type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2DevType {
    VideoCapture = 1,
    VideoOutput = 2,
    VideoOverlay = 3,
    VbiCapture = 4,
    VbiOutput = 5,
    SlicedVbiCapture = 6,
    SlicedVbiOutput = 7,
    VideoOutputOverlay = 8,
    VideoCaptureMplane = 9,
    VideoOutputMplane = 10,
    SdrCapture = 11,
    SdrOutput = 12,
    MetaCapture = 13,
    MetaOutput = 14,
    // Zxyphor extensions
    ZxyNeuralCapture = 100,
    ZxyDepthCapture = 101,
}

/// V4L2 pixel format FourCC
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2PixFmt {
    Rgb24 = 0x33424752,
    Bgr24 = 0x33524742,
    Rgb32 = 0x34424752,
    Argb32 = 0x42475241,
    Xrgb32 = 0x42475258,
    Yuyv = 0x56595559,
    Uyvy = 0x59565955,
    Nv12 = 0x3231564E,
    Nv21 = 0x3132564E,
    Yuv420 = 0x32315559,
    Yuv422p = 0x50323234,
    Mjpeg = 0x47504A4D,
    Jpeg = 0x4745504A,
    H264 = 0x34363248,
    Hevc = 0x43564548,
    Vp8 = 0x30385056,
    Vp9 = 0x30395056,
    Av1 = 0x31305641,
    Srggb8 = 0x42474752,
    Srggb10 = 0x47523031,
    Srggb12 = 0x47523231,
    // Zxyphor
    ZxyHdr10 = 0x5A484431,
    ZxyRaw16 = 0x5A523136,
}

/// V4L2 buffer type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2BufType {
    VideoCapture = 1,
    VideoOutput = 2,
    VideoOverlay = 3,
    VbiCapture = 4,
    VbiOutput = 5,
    VideoCaptureMplane = 9,
    VideoOutputMplane = 10,
    SdrCapture = 11,
    SdrOutput = 12,
    MetaCapture = 13,
    MetaOutput = 14,
}

/// V4L2 memory model
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2Memory {
    Mmap = 1,
    Userptr = 2,
    Overlay = 3,
    Dmabuf = 4,
}

/// V4L2 field order
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2Field {
    Any = 0,
    None = 1,
    Top = 2,
    Bottom = 3,
    Interlaced = 4,
    SeqTb = 5,
    SeqBt = 6,
    Alternate = 7,
    InterlacedTb = 8,
    InterlacedBt = 9,
}

/// V4L2 colorspace
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2Colorspace {
    Default = 0,
    Smpte170m = 1,
    Smpte240m = 2,
    Rec709 = 3,
    Bt878 = 4,
    Srgb = 8,
    Oprgb = 9,
    Bt2020 = 10,
    Raw = 11,
    DciP3 = 12,
}

/// V4L2 quantization
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2Quantization {
    Default = 0,
    FullRange = 1,
    LimitedRange = 2,
}

/// V4L2 format description
#[repr(C)]
#[derive(Debug, Clone)]
pub struct V4l2PixFormat {
    pub width: u32,
    pub height: u32,
    pub pixelformat: V4l2PixFmt,
    pub field: V4l2Field,
    pub bytesperline: u32,
    pub sizeimage: u32,
    pub colorspace: V4l2Colorspace,
    pub quantization: V4l2Quantization,
    pub xfer_func: u32,
    pub ycbcr_enc: u32,
    pub flags: u32,
}

/// V4L2 capability flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct V4l2CapFlags(pub u32);

impl V4l2CapFlags {
    pub const VIDEO_CAPTURE: Self = Self(0x00000001);
    pub const VIDEO_OUTPUT: Self = Self(0x00000002);
    pub const VIDEO_OVERLAY: Self = Self(0x00000004);
    pub const VIDEO_CAPTURE_MPLANE: Self = Self(0x00001000);
    pub const VIDEO_OUTPUT_MPLANE: Self = Self(0x00002000);
    pub const VIDEO_M2M: Self = Self(0x00004000);
    pub const VIDEO_M2M_MPLANE: Self = Self(0x00008000);
    pub const STREAMING: Self = Self(0x04000000);
    pub const EXT_PIX_FORMAT: Self = Self(0x00200000);
    pub const READWRITE: Self = Self(0x01000000);
    pub const IO_MC: Self = Self(0x20000000);
    pub const DEVICE_CAPS: Self = Self(0x80000000);
}

/// V4L2 control type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum V4l2CtrlType {
    Integer = 1,
    Boolean = 2,
    Menu = 3,
    Button = 4,
    Integer64 = 5,
    CtrlClass = 6,
    String = 7,
    Bitmask = 8,
    IntegerMenu = 9,
    CompoundTypes = 0x0100,
    U8 = 0x0100,
    U16 = 0x0101,
    U32 = 0x0102,
    Area = 0x0106,
    Hdr10CllInfo = 0x0110,
    Hdr10MasteringDisplay = 0x0111,
    H264Sps = 0x0200,
    H264Pps = 0x0201,
    H264ScalingMatrix = 0x0202,
    H264SliceParams = 0x0203,
    H264DecodeParams = 0x0204,
    H264PredWeights = 0x0205,
    FwhtParams = 0x0220,
    Vp8Frame = 0x0240,
    Mpeg2Quantisation = 0x0250,
    Mpeg2Sequence = 0x0251,
    Mpeg2Picture = 0x0252,
    HevcSps = 0x0260,
    HevcPps = 0x0261,
    HevcSliceParams = 0x0262,
    HevcScalingMatrix = 0x0263,
    HevcDecodeParams = 0x0264,
    Vp9CompressedHdr = 0x0280,
    Vp9Frame = 0x0281,
    Av1Sequence = 0x0290,
    Av1TileGroupEntry = 0x0291,
    Av1Frame = 0x0292,
    Av1FilmGrain = 0x0293,
}

// ============================================================================
// Camera Sensor Framework
// ============================================================================

/// Camera sensor type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CamSensorType {
    Bayer = 0,
    YuvOut = 1,
    Mono = 2,
    Rgbir = 3,
    Tof = 4,
    // Zxyphor
    ZxyMultispectral = 100,
}

/// Camera sensor mode
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CamSensorMode {
    pub width: u32,
    pub height: u32,
    pub pixel_format: V4l2PixFmt,
    pub h_blanking: u32,
    pub v_blanking: u32,
    pub pixel_clock_hz: u64,
    pub link_freq_hz: u64,
    pub fps_num: u32,
    pub fps_den: u32,
    pub crop_left: u32,
    pub crop_top: u32,
    pub crop_width: u32,
    pub crop_height: u32,
    pub binning_h: u8,
    pub binning_v: u8,
    pub bit_depth: u8,
}

/// ISP (Image Signal Processor) pipeline stage
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IspStage {
    BlackLevelCorrection = 0,
    LinearizationLut = 1,
    LensShadingCorrection = 2,
    BadPixelCorrection = 3,
    Demosaic = 4,
    ColorCorrectionMatrix = 5,
    GammaCorrection = 6,
    WhiteBalance = 7,
    NoiseReduction = 8,
    Sharpening = 9,
    ToneMapping = 10,
    ChromaticAbCorrection = 11,
    DistortionCorrection = 12,
    Hdr = 13,
    // Zxyphor extensions
    ZxyAiDenoise = 100,
    ZxyAiHdr = 101,
    ZxyNightMode = 102,
}

/// Camera flash mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CamFlashMode {
    Off = 0,
    TorchMode = 1,
    FlashMode = 2,
    Red = 3,
    Ir = 4,
}

// ============================================================================
// DRM KMS - Advanced Modesetting
// ============================================================================

/// DRM connector type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmConnectorType {
    Unknown = 0,
    Vga = 1,
    DviI = 2,
    DviD = 3,
    DviA = 4,
    Composite = 5,
    Svideo = 6,
    Lvds = 7,
    Component = 8,
    NinePinDin = 9,
    DisplayPort = 10,
    HdmiA = 11,
    HdmiB = 12,
    Tv = 13,
    Edp = 14,
    Virtual = 15,
    Dsi = 16,
    Dpi = 17,
    Writeback = 18,
    Spi = 19,
    Usb = 20,
}

/// DRM encoder type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmEncoderType {
    None = 0,
    Dac = 1,
    Tmds = 2,
    Lvds = 3,
    Tvdac = 4,
    Virtual = 5,
    Dsi = 6,
    Dpmst = 7,
    Dpi = 8,
}

/// DRM mode info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DrmModeInfo {
    pub clock_khz: u32,
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
    pub name: [u8; 32],
    pub name_len: u8,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct DrmModeFlags(pub u32);

impl DrmModeFlags {
    pub const PHSYNC: Self = Self(1 << 0);
    pub const NHSYNC: Self = Self(1 << 1);
    pub const PVSYNC: Self = Self(1 << 2);
    pub const NVSYNC: Self = Self(1 << 3);
    pub const INTERLACE: Self = Self(1 << 4);
    pub const DBLSCAN: Self = Self(1 << 5);
    pub const CSYNC: Self = Self(1 << 6);
    pub const PCSYNC: Self = Self(1 << 7);
    pub const NCSYNC: Self = Self(1 << 8);
    pub const HSKEW: Self = Self(1 << 9);
    pub const DBLCLK: Self = Self(1 << 12);
    pub const CLKDIV2: Self = Self(1 << 13);
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct DrmModeType(pub u32);

impl DrmModeType {
    pub const PREFERRED: Self = Self(1 << 3);
    pub const USERDEF: Self = Self(1 << 5);
    pub const DRIVER: Self = Self(1 << 6);
}

/// DRM plane type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmPlaneType {
    Overlay = 0,
    Primary = 1,
    Cursor = 2,
}

/// DRM blend mode
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmBlendMode {
    None = 0,
    PreMultiplied = 1,
    Coverage = 2,
}

/// DRM color encoding
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmColorEncoding {
    Bt601 = 0,
    Bt709 = 1,
    Bt2020 = 2,
}

/// DRM color range
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DrmColorRange {
    Limited = 0,
    Full = 1,
}

/// DRM HDR output metadata
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DrmHdrMetadata {
    pub metadata_type: DrmHdrMetadataType,
    pub display_primaries_x: [u16; 3],
    pub display_primaries_y: [u16; 3],
    pub white_point_x: u16,
    pub white_point_y: u16,
    pub max_display_mastering_luminance: u32,
    pub min_display_mastering_luminance: u32,
    pub max_cll: u16,
    pub max_fall: u16,
    pub eotf: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DrmHdrMetadataType {
    None = 0,
    Hdr10 = 1,
    Hdr10Plus = 2,
    DolbyVision = 3,
    HlgInfo = 4,
}

/// DRM EDID info parsed
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DrmEdidInfo {
    pub manufacturer: [u8; 4],
    pub product_code: u16,
    pub serial: u32,
    pub year: u16,
    pub week: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub width_cm: u32,
    pub height_cm: u32,
    pub gamma: u8,
    pub dpms_standby: bool,
    pub dpms_suspend: bool,
    pub dpms_off: bool,
    pub digital: bool,
    pub color_depth: u8,
    pub interface_type: u8,
    pub preferred_timing_mode: DrmModeInfo,
    pub num_detailed_timings: u8,
    pub num_standard_timings: u8,
    pub cea_sad_count: u8,
    pub hdr_supported: bool,
    pub hdr_metadata: DrmHdrMetadata,
}

// ============================================================================
// Video Codec Engine
// ============================================================================

/// Video codec type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum VideoCodec {
    H264 = 0,
    H265Hevc = 1,
    Vp8 = 2,
    Vp9 = 3,
    Av1 = 4,
    Mpeg2 = 5,
    Mpeg4 = 6,
    Vc1 = 7,
    Jpeg = 8,
    // Zxyphor
    ZxyLossless = 100,
}

/// Video codec profile
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum VideoProfile {
    H264Baseline = 0,
    H264Main = 1,
    H264High = 2,
    H264High10 = 3,
    H264High422 = 4,
    H264High444 = 5,
    HevcMain = 10,
    HevcMain10 = 11,
    HevcMain12 = 12,
    HevcMainStill = 13,
    Vp9Profile0 = 20,
    Vp9Profile2 = 21,
    Av1Main = 30,
    Av1High = 31,
    Av1Professional = 32,
}

/// Video codec capabilities
#[repr(C)]
#[derive(Debug, Clone)]
pub struct VideoCodecCaps {
    pub codec: VideoCodec,
    pub decode: bool,
    pub encode: bool,
    pub max_width: u32,
    pub max_height: u32,
    pub min_width: u32,
    pub min_height: u32,
    pub max_fps: u32,
    pub max_bitrate_kbps: u64,
    pub profiles_supported: u32,
    pub levels_supported: u32,
    pub hw_accelerated: bool,
    pub secure_decode: bool,
    pub hdr_capable: bool,
    pub slice_mode: bool,
    pub roi_encode: bool,
}

/// Media controller entity type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MediaEntityType {
    Unknown = 0,
    VideoCapture = 1,
    VideoOutput = 2,
    VideoDecoder = 3,
    VideoEncoder = 4,
    Isp = 5,
    Csi2 = 6,
    Flash = 7,
    Lens = 8,
    VbiCapture = 9,
    Atu = 10,
    Tuner = 11,
    Subdev = 12,
    // Zxyphor
    ZxyAiProcessor = 100,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct MediaDisplaySubsystem {
    pub nr_v4l2_devices: u32,
    pub nr_cam_sensors: u32,
    pub nr_isp_devices: u32,
    pub nr_drm_devices: u32,
    pub nr_connectors: u32,
    pub nr_encoders: u32,
    pub nr_crtcs: u32,
    pub nr_planes: u32,
    pub nr_video_codecs: u32,
    pub nr_media_entities: u32,
    pub hdr_support: bool,
    pub zxy_ai_isp: bool,
    pub initialized: bool,
}

impl MediaDisplaySubsystem {
    pub const fn new() -> Self {
        Self {
            nr_v4l2_devices: 0,
            nr_cam_sensors: 0,
            nr_isp_devices: 0,
            nr_drm_devices: 0,
            nr_connectors: 0,
            nr_encoders: 0,
            nr_crtcs: 0,
            nr_planes: 0,
            nr_video_codecs: 0,
            nr_media_entities: 0,
            hdr_support: false,
            zxy_ai_isp: false,
            initialized: false,
        }
    }
}
