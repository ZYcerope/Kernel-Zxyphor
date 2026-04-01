// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust: DRM/KMS Display, GPU compute, Display connectors
// Framebuffer, CRTC, encoder, connector, plane, atomic modesetting,
// GEM buffer objects, DMA-BUF, GPU scheduler, render nodes
// More advanced than Linux 2026 DRM subsystem

/// DRM Driver capabilities
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmCap {
    DumbBuffer = 0x1,
    VblankHighCrtc = 0x2,
    DumbPreferredDepth = 0x3,
    DumbPreferShadow = 0x4,
    Prime = 0x5,
    TimestampMonotonic = 0x6,
    AsyncPageFlip = 0x7,
    CursorWidth = 0x8,
    CursorHeight = 0x9,
    AddFb2Modifiers = 0x10,
    PageFlipTarget = 0x11,
    CrtcInVblankEvent = 0x12,
    SyncObj = 0x13,
    SyncObjTimeline = 0x14,
    AtomicAsyncPageFlip = 0x15,
}

/// DRM Client capabilities
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmClientCap {
    Stereo3d = 1,
    UniversalPlanes = 2,
    Atomic = 3,
    AspectRatio = 4,
    WritebackConnectors = 5,
    CursorPlaneHotspot = 6,
}

/// Connector type (physical display connector)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorType {
    Unknown = 0,
    Vga = 1,
    DviI = 2,
    DviD = 3,
    DviA = 4,
    Composite = 5,
    SVideo = 6,
    Lvds = 7,
    Component = 8,
    Pin9DIN = 9,
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

/// Connector status
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorStatus {
    Connected = 1,
    Disconnected = 2,
    Unknown = 3,
}

/// DRM connector
#[derive(Debug, Clone)]
pub struct DrmConnector {
    pub id: u32,
    pub connector_type: ConnectorType,
    pub connector_type_id: u32,
    pub status: ConnectorStatus,
    // Physical dimensions
    pub mm_width: u32,
    pub mm_height: u32,
    // Subpixel layout
    pub subpixel: SubPixel,
    // DPMS state
    pub dpms: DpmsState,
    // EDID
    pub has_edid: bool,
    pub edid_block_count: u8,
    // Content Protection (HDCP)
    pub hdcp_status: HdcpStatus,
    pub hdcp_version: HdcpVersion,
    // Link status
    pub link_status: LinkStatus,
    // VRR
    pub vrr_capable: bool,
    // HDR
    pub hdr_output_metadata: bool,
    pub max_bpc: u8,
    // CRC
    pub crc_source: [u8; 32],
    // Panel
    pub panel_orientation: PanelOrientation,
    // Current mode
    pub current_mode_id: u32,
    // Encoder
    pub encoder_id: u32,
}

/// Sub-pixel layout
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubPixel {
    Unknown = 0,
    HorizontalRgb = 1,
    HorizontalBgr = 2,
    VerticalRgb = 3,
    VerticalBgr = 4,
    None = 5,
}

/// DPMS (Display Power Management Signaling)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpmsState {
    On = 0,
    Standby = 1,
    Suspend = 2,
    Off = 3,
}

/// HDCP status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdcpStatus {
    Undesired = 0,
    Desired = 1,
    Enabled = 2,
}

/// HDCP version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdcpVersion {
    None = 0,
    V1_4 = 1,
    V2_2 = 2,
    V2_3 = 3,
}

/// Link status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Good = 0,
    Bad = 1,
}

/// Panel orientation
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelOrientation {
    Normal = 0,
    UpsideDown = 1,
    LeftSide = 2,
    RightSide = 3,
}

// ============================================================================
// CRTC (Cathode Ray Tube Controller = display pipeline)
// ============================================================================

/// CRTC state
#[derive(Debug, Clone)]
pub struct DrmCrtc {
    pub id: u32,
    pub active: bool,
    // Current mode
    pub mode: DrmDisplayMode,
    pub mode_valid: bool,
    // Gamma
    pub gamma_size: u32,
    pub degamma_lut_size: u32,
    pub gamma_lut_size: u32,
    // VRR
    pub vrr_enabled: bool,
    // Scaling filter
    pub scaling_filter: ScalingFilter,
    // Background color
    pub background_color: u64,
    // Vblank
    pub vblank_count: u64,
    // CTM (Color Transformation Matrix)
    pub has_ctm: bool,
    // Out fence
    pub out_fence_ptr: u64,
    // Planes
    pub primary_plane_id: u32,
    pub cursor_plane_id: u32,
    // Active planes count
    pub nr_active_planes: u8,
}

/// Display mode
#[derive(Debug, Clone, Copy)]
pub struct DrmDisplayMode {
    pub clock: u32,            // Pixel clock in kHz
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
    pub vrefresh: u32,         // Vertical refresh rate (Hz * 1000)
    pub flags: u32,            // DRM_MODE_FLAG_*
    pub mode_type: u32,        // DRM_MODE_TYPE_*
    pub name: [u8; 32],
}

impl DrmDisplayMode {
    pub fn refresh_hz(&self) -> f64 {
        if self.htotal == 0 || self.vtotal == 0 {
            return 0.0;
        }
        (self.clock as f64 * 1000.0) / (self.htotal as f64 * self.vtotal as f64)
    }

    pub fn is_interlaced(&self) -> bool {
        self.flags & 0x10 != 0  // DRM_MODE_FLAG_INTERLACE
    }
}

/// Scaling filter
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalingFilter {
    Default = 0,
    NearestNeighbor = 1,
}

// ============================================================================
// Planes
// ============================================================================

/// Plane type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneType {
    Overlay = 0,
    Primary = 1,
    Cursor = 2,
}

/// DRM Plane
#[derive(Debug, Clone)]
pub struct DrmPlane {
    pub id: u32,
    pub plane_type: PlaneType,
    pub possible_crtcs: u32,
    // Source rectangle (16.16 fixed point)
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    // Destination rectangle
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    // Framebuffer
    pub fb_id: u32,
    pub crtc_id: u32,
    // Rotation
    pub rotation: PlaneRotation,
    // Blend mode
    pub blend_mode: BlendMode,
    pub alpha: u16,        // 0-65535
    // Color encoding/range
    pub color_encoding: ColorEncoding,
    pub color_range: ColorRange,
    // zpos
    pub zpos: u32,
    pub normalized_zpos: u32,
    // Pixel format count
    pub nr_formats: u32,
    // IN_FENCE
    pub in_fence_fd: i32,
    // Damage
    pub fb_damage_clips_count: u32,
    // Scaling filter
    pub scaling_filter: ScalingFilter,
    // Hotspot (cursor)
    pub hotspot_x: i32,
    pub hotspot_y: i32,
}

/// Plane rotation
#[derive(Debug, Clone, Copy)]
pub struct PlaneRotation {
    pub rotate_0: bool,
    pub rotate_90: bool,
    pub rotate_180: bool,
    pub rotate_270: bool,
    pub reflect_x: bool,
    pub reflect_y: bool,
}

/// Blend mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlendMode {
    None = 0,        // No blending
    PreMultiplied = 1,
    Coverage = 2,
}

/// Color encoding
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorEncoding {
    Bt601 = 0,
    Bt709 = 1,
    Bt2020 = 2,
}

/// Color range
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorRange {
    LimitedRange = 0,
    FullRange = 1,
}

// ============================================================================
// Framebuffer
// ============================================================================

/// Pixel format (DRM FourCC)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    C8 = 0x20203843,
    Rgb332 = 0x38424752,
    Bgr233 = 0x38524742,
    Xrgb4444 = 0x32315258,
    Xbgr4444 = 0x32314258,
    Rgbx4444 = 0x32315852,
    Bgrx4444 = 0x32315842,
    Argb4444 = 0x32315241,
    Abgr4444 = 0x32314241,
    Rgba4444 = 0x32314152,
    Bgra4444 = 0x32314142,
    Xrgb1555 = 0x35315258,
    Xbgr1555 = 0x35314258,
    Argb1555 = 0x35315241,
    Abgr1555 = 0x35314241,
    Rgb565 = 0x36314752,
    Bgr565 = 0x36314742,
    Rgb888 = 0x34324752,
    Bgr888 = 0x34324742,
    Xrgb8888 = 0x34325258,
    Xbgr8888 = 0x34324258,
    Rgbx8888 = 0x34325852,
    Bgrx8888 = 0x34325842,
    Argb8888 = 0x34325241,
    Abgr8888 = 0x34324241,
    Rgba8888 = 0x34324152,
    Bgra8888 = 0x34324142,
    Xrgb2101010 = 0x30335258,
    Xbgr2101010 = 0x30334258,
    Argb2101010 = 0x30335241,
    Abgr2101010 = 0x30334241,
    // HDR
    Xrgb16161616f = 0x48345258,
    Xbgr16161616f = 0x48344258,
    Argb16161616f = 0x48345241,
    Abgr16161616f = 0x48344241,
    // YUV
    Nv12 = 0x3231564E,
    Nv21 = 0x3132564E,
    Yuyv = 0x56595559,
    Yvyu = 0x55595659,
    Uyvy = 0x59565955,
    P010 = 0x30313050,
}

/// Framebuffer
#[derive(Debug, Clone)]
pub struct DrmFramebuffer {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub modifier: u64,
    // Per-plane info (up to 4 planes for multi-planar formats)
    pub pitches: [u32; 4],
    pub offsets: [u32; 4],
    pub handles: [u32; 4],
    pub nr_planes: u8,
    // Flags
    pub interlaced: bool,
    pub addfb2_flags: u32,
}

// ============================================================================
// GEM (Graphics Execution Manager) Buffer Objects
// ============================================================================

/// GEM memory domain
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemDomain {
    Cpu = 0x1,
    Gtt = 0x2,          // GPU aperture
    Vram = 0x4,          // GPU VRAM
    WC = 0x8,            // Write-Combining
}

/// GEM Buffer Object
#[derive(Debug, Clone)]
pub struct GemObject {
    pub handle: u32,
    pub size: u64,
    // Memory domain
    pub read_domain: u32,
    pub write_domain: u32,
    // Tiling
    pub tiling_mode: TilingMode,
    pub stride: u32,
    pub swizzle_mode: u8,
    // Cache
    pub cache_level: CacheLevel,
    // Pinned
    pub pin_count: u32,
    // DMA-BUF
    pub dma_buf_fd: i32,
    pub imported: bool,
    pub exported: bool,
    // mmap
    pub mmap_offset: u64,
    // Stats
    pub resident: bool,
    pub purgeable: bool,
}

/// Tiling mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TilingMode {
    None = 0,
    X = 1,
    Y = 2,
    Yf = 3,
    Ys = 4,
    // Tile4 (Intel Gen12.5+)
    Tile4 = 5,
    Tile64 = 6,
}

/// Cache level
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLevel {
    Uncached = 0,
    WriteCombining = 1,
    Llc = 2,
    L3Only = 3,
}

// ============================================================================
// DMA-BUF
// ============================================================================

/// DMA-BUF sharing
#[derive(Debug, Clone)]
pub struct DmaBufInfo {
    pub fd: i32,
    pub size: u64,
    pub name: [u8; 32],
    pub exporter: [u8; 32],
    // Attachments
    pub nr_attachments: u32,
    // Map count
    pub map_count: u32,
    // Flags
    pub writable: bool,
}

// ============================================================================
// GPU Scheduler
// ============================================================================

/// Scheduler priority
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPriority {
    Min = 0,
    Normal = 1,
    High = 2,
    Kernel = 3,
}

/// GPU Scheduler entity
#[derive(Debug, Clone)]
pub struct SchedEntity {
    pub priority: SchedPriority,
    pub guilty: bool,
    pub jobs_submitted: u64,
    pub jobs_completed: u64,
    pub last_scheduled_ns: u64,
}

/// GPU Job type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuJobType {
    Render = 0,
    Compute = 1,
    Copy = 2,
    Video = 3,
}

/// GPU Engine type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuEngine {
    Render = 0,
    Copy = 1,
    Video = 2,
    VideEnhance = 3,
    Compute = 4,
    // Zxyphor
    ZxyAi = 10,
}

// ============================================================================
// EDID (Extended Display Identification Data)
// ============================================================================

/// EDID block
#[derive(Debug, Clone)]
pub struct EdidInfo {
    pub version: u8,
    pub revision: u8,
    // Manufacturer
    pub mfg_id: [u8; 3],
    pub product_code: u16,
    pub serial_number: u32,
    pub mfg_week: u8,
    pub mfg_year: u16,    // Actual year
    // Display
    pub digital: bool,
    pub bits_per_color: u8,
    pub color_format: EdidColorFormat,
    pub h_size_cm: u8,
    pub v_size_cm: u8,
    pub gamma: u8,         // (gamma * 100) - 100
    // Features
    pub dpms_standby: bool,
    pub dpms_suspend: bool,
    pub dpms_off: bool,
    pub srgb_default: bool,
    pub preferred_timing: bool,
    pub continuous_frequency: bool,
    // CEA-861 Extensions
    pub nr_cea_blocks: u8,
    pub supports_audio: bool,
    pub supports_ycbcr444: bool,
    pub supports_ycbcr422: bool,
    // HDR
    pub hdr_static_metadata: bool,
    pub hdr_eotf_sdr: bool,
    pub hdr_eotf_hdr: bool,
    pub hdr_eotf_st2084: bool,
    pub hdr_eotf_hlg: bool,
    pub max_luminance: u16,
    pub min_luminance: u16,
    pub max_fall: u16,
    // VRR (Adaptive Sync)
    pub adaptive_sync: bool,
    pub vrr_min: u16,
    pub vrr_max: u16,
    // DSC (Display Stream Compression)
    pub dsc_supported: bool,
    pub dsc_max_slices: u8,
}

/// EDID Color format
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdidColorFormat {
    Rgb = 0,
    RgbYcbcr444 = 1,
    RgbYcbcr422 = 2,
    RgbYcbcr444422 = 3,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// DRM/KMS subsystem
#[derive(Debug, Clone)]
pub struct DrmSubsystem {
    // Devices
    pub nr_devices: u32,
    pub nr_render_nodes: u32,
    // Connectors
    pub nr_connectors: u32,
    pub nr_connected: u32,
    // CRTCs
    pub nr_crtcs: u32,
    pub nr_active_crtcs: u32,
    // Planes
    pub nr_planes: u32,
    pub nr_overlay_planes: u32,
    // Framebuffers
    pub nr_framebuffers: u32,
    pub total_fb_memory: u64,
    // GEM
    pub nr_gem_objects: u32,
    pub total_gem_memory: u64,
    // DMA-BUF
    pub nr_dma_bufs: u32,
    pub total_dma_buf_memory: u64,
    // GPU
    pub nr_gpu_engines: u32,
    pub total_gpu_jobs: u64,
    pub total_gpu_time_ns: u64,
    // Stats
    pub total_vblank_count: u64,
    pub total_page_flips: u64,
    pub total_atomic_commits: u64,
    pub total_mode_sets: u64,
    // Zxyphor
    pub zxy_ai_upscaling: bool,
    pub initialized: bool,
}
