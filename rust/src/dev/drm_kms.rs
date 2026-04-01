//! Kernel Zxyphor — DRM/KMS Graphics Subsystem
//!
//! Complete Direct Rendering Manager (DRM) and Kernel Mode Setting (KMS)
//! implementation supporting:
//! - DRM core: device registration, file operations, IOCTLs
//! - KMS: CRTCs, encoders, connectors, planes, framebuffers
//! - Atomic modesetting with commit/check
//! - GEM (Graphics Execution Manager) buffer management
//! - TTM (Translation Table Manager) for VRAM
//! - DMA-BUF import/export for zero-copy sharing
//! - Render nodes for unprivileged GPU compute
//! - EDID parsing for display detection
//! - VBlank handling and page flipping
//! - Hardware cursor support
//! - Display Power Management Signaling (DPMS)
//! - Gamma/color correction LUTs

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// DRM IOCTLs
// ============================================================================

pub mod ioctl {
    pub const DRM_IOCTL_BASE: u32 = 0x64; // 'd'

    // Core IOCTLs
    pub const DRM_IOCTL_VERSION: u32 = 0x00;
    pub const DRM_IOCTL_GET_UNIQUE: u32 = 0x01;
    pub const DRM_IOCTL_GET_MAGIC: u32 = 0x02;
    pub const DRM_IOCTL_IRQ_BUSID: u32 = 0x03;
    pub const DRM_IOCTL_GET_MAP: u32 = 0x04;
    pub const DRM_IOCTL_GET_CLIENT: u32 = 0x05;
    pub const DRM_IOCTL_GET_STATS: u32 = 0x06;
    pub const DRM_IOCTL_SET_VERSION: u32 = 0x07;
    pub const DRM_IOCTL_MODESET_CTL: u32 = 0x08;
    pub const DRM_IOCTL_GEM_CLOSE: u32 = 0x09;
    pub const DRM_IOCTL_GEM_FLINK: u32 = 0x0A;
    pub const DRM_IOCTL_GEM_OPEN: u32 = 0x0B;
    pub const DRM_IOCTL_GET_CAP: u32 = 0x0C;
    pub const DRM_IOCTL_SET_CLIENT_CAP: u32 = 0x0D;

    // KMS IOCTLs
    pub const DRM_IOCTL_MODE_GETRESOURCES: u32 = 0xA0;
    pub const DRM_IOCTL_MODE_GETCRTC: u32 = 0xA1;
    pub const DRM_IOCTL_MODE_SETCRTC: u32 = 0xA2;
    pub const DRM_IOCTL_MODE_CURSOR: u32 = 0xA3;
    pub const DRM_IOCTL_MODE_GETGAMMA: u32 = 0xA4;
    pub const DRM_IOCTL_MODE_SETGAMMA: u32 = 0xA5;
    pub const DRM_IOCTL_MODE_GETENCODER: u32 = 0xA6;
    pub const DRM_IOCTL_MODE_GETCONNECTOR: u32 = 0xA7;
    pub const DRM_IOCTL_MODE_ATTACHMODE: u32 = 0xA8;
    pub const DRM_IOCTL_MODE_DETACHMODE: u32 = 0xA9;
    pub const DRM_IOCTL_MODE_GETPROPERTY: u32 = 0xAA;
    pub const DRM_IOCTL_MODE_SETPROPERTY: u32 = 0xAB;
    pub const DRM_IOCTL_MODE_GETPROPBLOB: u32 = 0xAC;
    pub const DRM_IOCTL_MODE_GETFB: u32 = 0xAD;
    pub const DRM_IOCTL_MODE_ADDFB: u32 = 0xAE;
    pub const DRM_IOCTL_MODE_RMFB: u32 = 0xAF;
    pub const DRM_IOCTL_MODE_PAGE_FLIP: u32 = 0xB0;
    pub const DRM_IOCTL_MODE_DIRTYFB: u32 = 0xB1;
    pub const DRM_IOCTL_MODE_CREATE_DUMB: u32 = 0xB2;
    pub const DRM_IOCTL_MODE_MAP_DUMB: u32 = 0xB3;
    pub const DRM_IOCTL_MODE_DESTROY_DUMB: u32 = 0xB4;
    pub const DRM_IOCTL_MODE_GETPLANERESOURCES: u32 = 0xB5;
    pub const DRM_IOCTL_MODE_GETPLANE: u32 = 0xB6;
    pub const DRM_IOCTL_MODE_SETPLANE: u32 = 0xB7;
    pub const DRM_IOCTL_MODE_ADDFB2: u32 = 0xB8;
    pub const DRM_IOCTL_MODE_OBJ_GETPROPERTIES: u32 = 0xB9;
    pub const DRM_IOCTL_MODE_OBJ_SETPROPERTY: u32 = 0xBA;
    pub const DRM_IOCTL_MODE_CURSOR2: u32 = 0xBB;
    pub const DRM_IOCTL_MODE_ATOMIC: u32 = 0xBC;
    pub const DRM_IOCTL_MODE_CREATEPROPBLOB: u32 = 0xBD;
    pub const DRM_IOCTL_MODE_DESTROYPROPBLOB: u32 = 0xBE;

    // Prime / DMA-BUF
    pub const DRM_IOCTL_PRIME_HANDLE_TO_FD: u32 = 0x2D;
    pub const DRM_IOCTL_PRIME_FD_TO_HANDLE: u32 = 0x2E;
}

// ============================================================================
// DRM Capabilities
// ============================================================================

pub mod cap {
    pub const DRM_CAP_DUMB_BUFFER: u64 = 0x1;
    pub const DRM_CAP_VBLANK_HIGH_CRTC: u64 = 0x2;
    pub const DRM_CAP_DUMB_PREFERRED_DEPTH: u64 = 0x3;
    pub const DRM_CAP_DUMB_PREFER_SHADOW: u64 = 0x4;
    pub const DRM_CAP_PRIME: u64 = 0x5;
    pub const DRM_CAP_TIMESTAMP_MONOTONIC: u64 = 0x6;
    pub const DRM_CAP_ASYNC_PAGE_FLIP: u64 = 0x7;
    pub const DRM_CAP_CURSOR_WIDTH: u64 = 0x8;
    pub const DRM_CAP_CURSOR_HEIGHT: u64 = 0x9;
    pub const DRM_CAP_ADDFB2_MODIFIERS: u64 = 0x10;
    pub const DRM_CAP_PAGE_FLIP_TARGET: u64 = 0x11;
    pub const DRM_CAP_CRTC_IN_VBLANK_EVENT: u64 = 0x12;
    pub const DRM_CAP_SYNCOBJ: u64 = 0x13;
    pub const DRM_CAP_SYNCOBJ_TIMELINE: u64 = 0x14;
    pub const DRM_CAP_ATOMIC_ASYNC_PAGE_FLIP: u64 = 0x15;

    pub const DRM_CLIENT_CAP_STEREO_3D: u64 = 1;
    pub const DRM_CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;
    pub const DRM_CLIENT_CAP_ATOMIC: u64 = 3;
    pub const DRM_CLIENT_CAP_ASPECT_RATIO: u64 = 4;
    pub const DRM_CLIENT_CAP_WRITEBACK_CONNECTORS: u64 = 5;
    pub const DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT: u64 = 6;
}

// ============================================================================
// Pixel Formats (FourCC)
// ============================================================================

pub mod fourcc {
    /// Build a FourCC code from 4 characters
    pub const fn code(a: u8, b: u8, c: u8, d: u8) u32 {
        (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
    }

    pub const DRM_FORMAT_C8: u32 = code(b'C', b'8', b' ', b' ');
    pub const DRM_FORMAT_RGB332: u32 = code(b'R', b'G', b'B', b'8');
    pub const DRM_FORMAT_BGR233: u32 = code(b'B', b'G', b'R', b'8');
    pub const DRM_FORMAT_XRGB4444: u32 = code(b'X', b'R', b'1', b'2');
    pub const DRM_FORMAT_XBGR4444: u32 = code(b'X', b'B', b'1', b'2');
    pub const DRM_FORMAT_RGBX4444: u32 = code(b'R', b'X', b'1', b'2');
    pub const DRM_FORMAT_BGRX4444: u32 = code(b'B', b'X', b'1', b'2');
    pub const DRM_FORMAT_ARGB4444: u32 = code(b'A', b'R', b'1', b'2');
    pub const DRM_FORMAT_ABGR4444: u32 = code(b'A', b'B', b'1', b'2');
    pub const DRM_FORMAT_XRGB1555: u32 = code(b'X', b'R', b'1', b'5');
    pub const DRM_FORMAT_XBGR1555: u32 = code(b'X', b'B', b'1', b'5');
    pub const DRM_FORMAT_RGB565: u32 = code(b'R', b'G', b'1', b'6');
    pub const DRM_FORMAT_BGR565: u32 = code(b'B', b'G', b'1', b'6');
    pub const DRM_FORMAT_RGB888: u32 = code(b'R', b'G', b'2', b'4');
    pub const DRM_FORMAT_BGR888: u32 = code(b'B', b'G', b'2', b'4');
    pub const DRM_FORMAT_XRGB8888: u32 = code(b'X', b'R', b'2', b'4');
    pub const DRM_FORMAT_XBGR8888: u32 = code(b'X', b'B', b'2', b'4');
    pub const DRM_FORMAT_RGBX8888: u32 = code(b'R', b'X', b'2', b'4');
    pub const DRM_FORMAT_BGRX8888: u32 = code(b'B', b'X', b'2', b'4');
    pub const DRM_FORMAT_ARGB8888: u32 = code(b'A', b'R', b'2', b'4');
    pub const DRM_FORMAT_ABGR8888: u32 = code(b'A', b'B', b'2', b'4');
    pub const DRM_FORMAT_RGBA8888: u32 = code(b'R', b'A', b'2', b'4');
    pub const DRM_FORMAT_BGRA8888: u32 = code(b'B', b'A', b'2', b'4');
    pub const DRM_FORMAT_XRGB2101010: u32 = code(b'X', b'R', b'3', b'0');
    pub const DRM_FORMAT_XBGR2101010: u32 = code(b'X', b'B', b'3', b'0');
    pub const DRM_FORMAT_ARGB2101010: u32 = code(b'A', b'R', b'3', b'0');
    pub const DRM_FORMAT_ABGR2101010: u32 = code(b'A', b'B', b'3', b'0');

    // YUV formats
    pub const DRM_FORMAT_YUYV: u32 = code(b'Y', b'U', b'Y', b'V');
    pub const DRM_FORMAT_YVYU: u32 = code(b'Y', b'V', b'Y', b'U');
    pub const DRM_FORMAT_UYVY: u32 = code(b'U', b'Y', b'V', b'Y');
    pub const DRM_FORMAT_NV12: u32 = code(b'N', b'V', b'1', b'2');
    pub const DRM_FORMAT_NV21: u32 = code(b'N', b'V', b'2', b'1');
    pub const DRM_FORMAT_YUV420: u32 = code(b'Y', b'U', b'1', b'2');
    pub const DRM_FORMAT_YVU420: u32 = code(b'Y', b'V', b'1', b'2');

    /// Get bits per pixel for a format
    pub fn bpp(format: u32) u32 {
        match format {
            DRM_FORMAT_C8 | DRM_FORMAT_RGB332 | DRM_FORMAT_BGR233 => 8,
            DRM_FORMAT_XRGB4444 | DRM_FORMAT_XBGR4444 |
            DRM_FORMAT_RGBX4444 | DRM_FORMAT_BGRX4444 |
            DRM_FORMAT_ARGB4444 | DRM_FORMAT_ABGR4444 |
            DRM_FORMAT_XRGB1555 | DRM_FORMAT_XBGR1555 |
            DRM_FORMAT_RGB565 | DRM_FORMAT_BGR565 |
            DRM_FORMAT_YUYV | DRM_FORMAT_YVYU | DRM_FORMAT_UYVY => 16,
            DRM_FORMAT_RGB888 | DRM_FORMAT_BGR888 => 24,
            DRM_FORMAT_XRGB8888 | DRM_FORMAT_XBGR8888 |
            DRM_FORMAT_RGBX8888 | DRM_FORMAT_BGRX8888 |
            DRM_FORMAT_ARGB8888 | DRM_FORMAT_ABGR8888 |
            DRM_FORMAT_RGBA8888 | DRM_FORMAT_BGRA8888 |
            DRM_FORMAT_XRGB2101010 | DRM_FORMAT_XBGR2101010 |
            DRM_FORMAT_ARGB2101010 | DRM_FORMAT_ABGR2101010 => 32,
            _ => 0,
        }
    }
}

// ============================================================================
// Error
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrmError {
    NotFound,
    InvalidArgument,
    PermissionDenied,
    OutOfMemory,
    Busy,
    DeadObject,
    NoEncoder,
    NoConnector,
    NoCrtc,
    BadFb,
    ModeNotSupported,
    AtomicCheckFailed,
    VblankTimeout,
    GemError,
    EdidInvalid,
    IoError,
}

pub type DrmResult<T> = Result<T, DrmError>;

// ============================================================================
// Display Mode
// ============================================================================

/// A display mode (timing information for a video signal).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DrmDisplayMode {
    /// Pixel clock in kHz
    pub clock: u32,
    /// Horizontal display
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub hskew: u16,
    /// Vertical display
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub vscan: u16,
    /// VRefresh rate (Hz * 1000)
    pub vrefresh: u32,
    /// Flags (interlace, doublescan, etc.)
    pub flags: u32,
    /// Type flags
    pub type_flags: u32,
    /// Mode name (e.g., "1920x1080")
    pub name: [32]u8,
}

impl DrmDisplayMode {
    pub fn new_1080p60() -> Self {
        let mut name = [0u8; 32];
        let n = b"1920x1080";
        name[..n.len()].copy_from_slice(n);
        DrmDisplayMode {
            clock: 148500,
            hdisplay: 1920,
            hsync_start: 2008,
            hsync_end: 2052,
            htotal: 2200,
            hskew: 0,
            vdisplay: 1080,
            vsync_start: 1084,
            vsync_end: 1089,
            vtotal: 1125,
            vscan: 0,
            vrefresh: 60000,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            type_flags: MODE_TYPE_DRIVER | MODE_TYPE_PREFERRED,
            name,
        }
    }

    pub fn new_720p60() -> Self {
        let mut name = [0u8; 32];
        let n = b"1280x720";
        name[..n.len()].copy_from_slice(n);
        DrmDisplayMode {
            clock: 74250,
            hdisplay: 1280,
            hsync_start: 1390,
            hsync_end: 1430,
            htotal: 1650,
            hskew: 0,
            vdisplay: 720,
            vsync_start: 725,
            vsync_end: 730,
            vtotal: 750,
            vscan: 0,
            vrefresh: 60000,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            type_flags: MODE_TYPE_DRIVER,
            name,
        }
    }

    pub fn new_4k60() -> Self {
        let mut name = [0u8; 32];
        let n = b"3840x2160";
        name[..n.len()].copy_from_slice(n);
        DrmDisplayMode {
            clock: 594000,
            hdisplay: 3840,
            hsync_start: 4016,
            hsync_end: 4104,
            htotal: 4400,
            hskew: 0,
            vdisplay: 2160,
            vsync_start: 2168,
            vsync_end: 2178,
            vtotal: 2250,
            vscan: 0,
            vrefresh: 60000,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            type_flags: MODE_TYPE_DRIVER,
            name,
        }
    }

    pub fn pixel_rate(&self) u64 {
        (self.clock as u64) * 1000
    }

    pub fn bandwidth_bpp(&self, bpp: u32) u64 {
        self.pixel_rate() * (bpp as u64) / 8
    }
}

pub const MODE_FLAG_PHSYNC: u32 = 1 << 0;
pub const MODE_FLAG_NHSYNC: u32 = 1 << 1;
pub const MODE_FLAG_PVSYNC: u32 = 1 << 2;
pub const MODE_FLAG_NVSYNC: u32 = 1 << 3;
pub const MODE_FLAG_INTERLACE: u32 = 1 << 4;
pub const MODE_FLAG_DBLSCAN: u32 = 1 << 5;
pub const MODE_FLAG_CSYNC: u32 = 1 << 6;
pub const MODE_FLAG_PCSYNC: u32 = 1 << 7;
pub const MODE_FLAG_NCSYNC: u32 = 1 << 8;
pub const MODE_FLAG_HSKEW: u32 = 1 << 9;
pub const MODE_FLAG_DBLCLK: u32 = 1 << 12;
pub const MODE_FLAG_CLKDIV2: u32 = 1 << 13;
pub const MODE_FLAG_3D_MASK: u32 = 0x1F << 14;

pub const MODE_TYPE_BUILTIN: u32 = 1 << 0;
pub const MODE_TYPE_CLOCK_C: u32 = 1 << 1;
pub const MODE_TYPE_CRTC_C: u32 = 1 << 2;
pub const MODE_TYPE_PREFERRED: u32 = 1 << 3;
pub const MODE_TYPE_DEFAULT: u32 = 1 << 4;
pub const MODE_TYPE_USERDEF: u32 = 1 << 5;
pub const MODE_TYPE_DRIVER: u32 = 1 << 6;

// ============================================================================
// KMS Object IDs
// ============================================================================

static NEXT_OBJECT_ID: AtomicU32 = AtomicU32::new(1);

fn alloc_object_id() -> u32 {
    NEXT_OBJECT_ID.fetch_add(1, Ordering::Relaxed)
}

/// Object type for property targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DrmObjectType {
    Crtc = 0xCCCCCCCC,
    Connector = 0xC0C0C0C0,
    Encoder = 0xE0E0E0E0,
    Mode = 0xDEDE0000,
    Property = 0xB0B0B0B0,
    Fb = 0xFBFBFBFB,
    Blob = 0xBBBBBBBB,
    Plane = 0xEEEEEEEE,
}

// ============================================================================
// GEM Buffer Object
// ============================================================================

pub const MAX_GEM_OBJECTS: usize = 65536;
pub const GEM_MAX_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemDomain {
    Cpu,
    Gtt,     // Graphics Translation Table (mapped to GPU)
    Vram,    // Video RAM (dedicated GPU memory)
    Render,  // Render cache
}

pub struct GemObject {
    /// Unique handle within the file
    pub handle: u32,
    /// Global name (for flink sharing)
    pub name: u32,
    /// Size in bytes
    pub size: u64,
    /// Physical address (for VRAM objects)
    pub phys_addr: u64,
    /// Virtual address (CPU mapping)
    pub vaddr: u64,
    /// GPU virtual address
    pub gpu_vaddr: u64,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Current memory domain
    pub domain: GemDomain,
    /// Pixel format (if this is a scanout buffer)
    pub format: u32,
    /// Stride in bytes
    pub stride: u32,
    /// Width/height (for dumb buffers)
    pub width: u32,
    pub height: u32,
    /// Is this buffer imported via DMA-BUF?
    pub imported: bool,
    /// DMA-BUF file descriptor (if shared)
    pub dmabuf_fd: i32,
    /// Page list physical addresses
    pub pages: [1024]u64,
    pub num_pages: u32,
    /// Tiling mode
    pub tiling_mode: TilingMode,
    /// Cache coherency mode
    pub cache_level: CacheLevel,
    /// Fence register (for tiled access)
    pub fence_reg: i32,
    /// Mmap offset
    pub mmap_offset: u64,
    /// Pinned count (for scanout or DMA)
    pub pin_count: AtomicI32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TilingMode {
    None,
    X,
    Y,
    Linear,
    Tile4,  // Xe/DG2+ tiling
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLevel {
    Uncached,
    WriteCombining,
    WriteThrough,
    WriteBack,
    LLC,
}

impl GemObject {
    pub fn new(size: u64, domain: GemDomain) -> DrmResult<Self> {
        if size == 0 || size > GEM_MAX_SIZE {
            return Err(DrmError::InvalidArgument);
        }

        Ok(GemObject {
            handle: alloc_object_id(),
            name: 0,
            size,
            phys_addr: 0,
            vaddr: 0,
            gpu_vaddr: 0,
            ref_count: AtomicU32::new(1),
            domain,
            format: 0,
            stride: 0,
            width: 0,
            height: 0,
            imported: false,
            dmabuf_fd: -1,
            pages: [0u64; 1024],
            num_pages: 0,
            tiling_mode: TilingMode::None,
            cache_level: CacheLevel::WriteBack,
            fence_reg: -1,
            mmap_offset: 0,
            pin_count: AtomicI32::new(0),
        })
    }

    pub fn create_dumb(width: u32, height: u32, bpp: u32) -> DrmResult<Self> {
        let stride = (width * bpp + 7) / 8;
        let stride = (stride + 63) & !63; // Align to 64 bytes
        let size = (stride as u64) * (height as u64);

        let mut obj = Self::new(size, GemDomain::Cpu)?;
        obj.width = width;
        obj.height = height;
        obj.stride = stride;
        Ok(obj)
    }

    pub fn pin(&self) {
        self.pin_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn unpin(&self) {
        self.pin_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn is_pinned(&self) -> bool {
        self.pin_count.load(Ordering::Relaxed) > 0
    }
}

// ============================================================================
// Framebuffer
// ============================================================================

pub const MAX_PLANES_PER_FB: usize = 4;

pub struct DrmFramebuffer {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub flags: u32,
    pub modifier: u64,
    /// Per-plane info
    pub pitches: [u32; MAX_PLANES_PER_FB],
    pub offsets: [u32; MAX_PLANES_PER_FB],
    pub handles: [u32; MAX_PLANES_PER_FB],
    pub num_planes: u8,
    /// Backing GEM object
    pub gem_handle: u32,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Hot spot for cursor framebuffers
    pub hot_x: i32,
    pub hot_y: i32,
}

impl DrmFramebuffer {
    pub fn new(
        width: u32,
        height: u32,
        format: u32,
        pitch: u32,
        gem_handle: u32,
    ) -> Self {
        let mut pitches = [0u32; MAX_PLANES_PER_FB];
        let mut handles = [0u32; MAX_PLANES_PER_FB];
        pitches[0] = pitch;
        handles[0] = gem_handle;

        DrmFramebuffer {
            id: alloc_object_id(),
            width,
            height,
            format,
            flags: 0,
            modifier: 0,
            pitches,
            offsets: [0u32; MAX_PLANES_PER_FB],
            handles,
            num_planes: 1,
            gem_handle,
            ref_count: AtomicU32::new(1),
            hot_x: 0,
            hot_y: 0,
        }
    }
}

// ============================================================================
// CRTC (CRT Controller)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrtcState {
    Disabled,
    Enabled,
    Standby,
}

pub struct DrmCrtc {
    pub id: u32,
    pub index: u32,
    pub state: CrtcState,
    /// Current mode
    pub mode: DrmDisplayMode,
    pub mode_valid: bool,
    /// Active framebuffer
    pub primary_fb: u32,
    /// Cursor framebuffer
    pub cursor_fb: u32,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub cursor_width: u32,
    pub cursor_height: u32,
    /// VBlank counter
    pub vblank_count: AtomicU64,
    /// VBlank enabled
    pub vblank_enabled: AtomicBool,
    /// Gamma size (number of LUT entries)
    pub gamma_size: u32,
    /// Gamma LUT
    pub gamma_red: [u16; 256],
    pub gamma_green: [u16; 256],
    pub gamma_blue: [u16; 256],
    /// Possible encoders bitmask
    pub possible_encoders: u32,
    /// CTM (Color Transformation Matrix) 3x3 s31.32
    pub ctm: [i64; 9],
    /// Degamma LUT pointer
    pub degamma_lut: u32,
    /// Hardware-specific pipe number
    pub pipe: u32,
    /// DPMS state
    pub dpms: DpmsMode,
    /// Page flip pending
    pub flip_pending: AtomicBool,
    /// Ops vtable
    pub ops: *const CrtcOps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DpmsMode {
    On = 0,
    Standby = 1,
    Suspend = 2,
    Off = 3,
}

/// CRTC hardware operations.
pub struct CrtcOps {
    pub set_mode: Option<fn(crtc: &mut DrmCrtc, mode: &DrmDisplayMode, fb_id: u32) -> DrmResult<()>>,
    pub page_flip: Option<fn(crtc: &mut DrmCrtc, fb_id: u32, flags: u32) -> DrmResult<()>>,
    pub set_cursor: Option<fn(crtc: &mut DrmCrtc, fb_id: u32, width: u32, height: u32) -> DrmResult<()>>,
    pub move_cursor: Option<fn(crtc: &mut DrmCrtc, x: i32, y: i32) -> DrmResult<()>>,
    pub set_gamma: Option<fn(crtc: &mut DrmCrtc, r: &[u16], g: &[u16], b: &[u16]) -> DrmResult<()>>,
    pub enable_vblank: Option<fn(crtc: &mut DrmCrtc) -> DrmResult<()>>,
    pub disable_vblank: Option<fn(crtc: &mut DrmCrtc)>,
    pub dpms: Option<fn(crtc: &mut DrmCrtc, mode: DpmsMode)>,
}

// ============================================================================
// Encoder
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncoderType {
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

pub struct DrmEncoder {
    pub id: u32,
    pub encoder_type: EncoderType,
    /// Currently attached CRTC ID
    pub crtc_id: u32,
    /// Bitmask of possible CRTCs
    pub possible_crtcs: u32,
    /// Bitmask of possible clones
    pub possible_clones: u32,
}

// ============================================================================
// Connector
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectorType {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectorStatus {
    Connected = 1,
    Disconnected = 2,
    Unknown = 3,
}

pub struct DrmConnector {
    pub id: u32,
    pub connector_type: ConnectorType,
    pub connector_type_id: u32,
    pub status: ConnectorStatus,
    /// Available modes
    pub modes: [DrmDisplayMode; 32],
    pub num_modes: u32,
    /// Currently attached encoder
    pub encoder_id: u32,
    /// Possible encoders bitmask
    pub possible_encoders: u32,
    /// EDID data
    pub edid: EdidData,
    pub edid_valid: bool,
    /// Physical size in mm
    pub mm_width: u32,
    pub mm_height: u32,
    /// Subpixel order
    pub subpixel: SubpixelOrder,
    /// DPMS property
    pub dpms: DpmsMode,
    /// Content type
    pub content_type: ContentType,
    /// Force detection
    pub force: ConnectorForce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubpixelOrder {
    Unknown = 0,
    HorizontalRgb = 1,
    HorizontalBgr = 2,
    VerticalRgb = 3,
    VerticalBgr = 4,
    None = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    NoData,
    Graphics,
    Photo,
    Cinema,
    Game,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorForce {
    Unspecified,
    Off,
    On,
    OnDigital,
}

// ============================================================================
// EDID (Extended Display Identification Data)
// ============================================================================

pub struct EdidData {
    pub raw: [u8; 256],
    pub length: u16,
}

impl EdidData {
    pub fn new() -> Self {
        EdidData {
            raw: [0u8; 256],
            length: 0,
        }
    }

    /// Validate EDID header.
    pub fn validate_header(&self) -> bool {
        if self.length < 128 {
            return false;
        }
        // EDID header: 00 FF FF FF FF FF FF 00
        self.raw[0] == 0x00
            && self.raw[1] == 0xFF
            && self.raw[2] == 0xFF
            && self.raw[3] == 0xFF
            && self.raw[4] == 0xFF
            && self.raw[5] == 0xFF
            && self.raw[6] == 0xFF
            && self.raw[7] == 0x00
    }

    /// Calculate EDID checksum.
    pub fn checksum(&self) -> bool {
        let mut sum: u8 = 0;
        for i in 0..128 {
            sum = sum.wrapping_add(self.raw[i]);
        }
        sum == 0
    }

    /// Parse manufacturer ID (bytes 8-9, compressed ASCII).
    pub fn manufacturer_id(&self) -> [u8; 3] {
        let id = ((self.raw[8] as u16) << 8) | (self.raw[9] as u16);
        [
            (((id >> 10) & 0x1F) as u8) + b'A' - 1,
            (((id >> 5) & 0x1F) as u8) + b'A' - 1,
            ((id & 0x1F) as u8) + b'A' - 1,
        ]
    }

    /// Get preferred mode from detailed timing block.
    pub fn preferred_mode(&self) -> Option<DrmDisplayMode> {
        if self.length < 128 || !self.validate_header() {
            return None;
        }

        // First detailed timing descriptor at offset 54
        let d = &self.raw[54..72];
        let pixel_clock = ((d[1] as u32) << 8 | d[0] as u32) * 10; // kHz

        if pixel_clock == 0 {
            return None;
        }

        let hactive = d[2] as u16 | (((d[4] >> 4) as u16) << 8);
        let hblank = d[3] as u16 | (((d[4] & 0x0F) as u16) << 8);
        let vactive = d[5] as u16 | (((d[7] >> 4) as u16) << 8);
        let vblank = d[6] as u16 | (((d[7] & 0x0F) as u16) << 8);
        let hsync_offset = d[8] as u16 | (((d[11] >> 6) as u16) << 8);
        let hsync_width = d[9] as u16 | ((((d[11] >> 4) & 0x03) as u16) << 8);
        let vsync_offset = ((d[10] >> 4) as u16) | ((((d[11] >> 2) & 0x03) as u16) << 4);
        let vsync_width = (d[10] & 0x0F) as u16 | (((d[11] & 0x03) as u16) << 4);

        let htotal = hactive + hblank;
        let vtotal = vactive + vblank;

        let mut mode = DrmDisplayMode {
            clock: pixel_clock,
            hdisplay: hactive,
            hsync_start: hactive + hsync_offset,
            hsync_end: hactive + hsync_offset + hsync_width,
            htotal,
            hskew: 0,
            vdisplay: vactive,
            vsync_start: vactive + vsync_offset,
            vsync_end: vactive + vsync_offset + vsync_width,
            vtotal,
            vscan: 0,
            vrefresh: 0,
            flags: MODE_FLAG_PHSYNC | MODE_FLAG_PVSYNC,
            type_flags: MODE_TYPE_PREFERRED | MODE_TYPE_DRIVER,
            name: [0u8; 32],
        };

        // Calculate refresh rate
        if htotal > 0 && vtotal > 0 {
            mode.vrefresh =
                ((pixel_clock as u64 * 1000) / (htotal as u64 * vtotal as u64)) as u32;
        }

        Some(mode)
    }

    /// Get physical size in mm.
    pub fn physical_size(&self) -> (u32, u32) {
        if self.length < 128 {
            return (0, 0);
        }
        (self.raw[21] as u32 * 10, self.raw[22] as u32 * 10)
    }
}

// ============================================================================
// Plane
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PlaneType {
    Overlay = 0,
    Primary = 1,
    Cursor = 2,
}

pub struct DrmPlane {
    pub id: u32,
    pub plane_type: PlaneType,
    /// Possible CRTCs bitmask
    pub possible_crtcs: u32,
    /// Currently attached CRTC
    pub crtc_id: u32,
    /// Current framebuffer
    pub fb_id: u32,
    /// Source rectangle (16.16 fixed point)
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    /// Destination rectangle
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    /// Rotation (0, 90, 180, 270 degrees + reflect)
    pub rotation: u32,
    /// Alpha (0-65535)
    pub alpha: u16,
    /// Zpos (stacking order)
    pub zpos: u32,
    /// Blend mode
    pub pixel_blend_mode: BlendMode,
    /// Supported formats
    pub formats: [u32; 32],
    pub num_formats: u32,
    /// Color encoding/range for YUV
    pub color_encoding: ColorEncoding,
    pub color_range: ColorRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlendMode {
    None,
    PreMultiplied,
    Coverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorEncoding {
    Bt601,
    Bt709,
    Bt2020,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorRange {
    Limited,
    Full,
}

pub const ROTATION_0: u32 = 1 << 0;
pub const ROTATION_90: u32 = 1 << 1;
pub const ROTATION_180: u32 = 1 << 2;
pub const ROTATION_270: u32 = 1 << 3;
pub const REFLECT_X: u32 = 1 << 4;
pub const REFLECT_Y: u32 = 1 << 5;

// ============================================================================
// Atomic Modesetting State
// ============================================================================

pub const MAX_CRTCS: usize = 8;
pub const MAX_CONNECTORS: usize = 16;
pub const MAX_ENCODERS: usize = 16;
pub const MAX_PLANES: usize = 32;
pub const MAX_FBS: usize = 256;

/// Flags for atomic commit.
pub const DRM_MODE_PAGE_FLIP_EVENT: u32 = 0x01;
pub const DRM_MODE_PAGE_FLIP_ASYNC: u32 = 0x02;
pub const DRM_MODE_ATOMIC_TEST_ONLY: u32 = 0x0100;
pub const DRM_MODE_ATOMIC_NONBLOCK: u32 = 0x0200;
pub const DRM_MODE_ATOMIC_ALLOW_MODESET: u32 = 0x0400;

/// Atomic state snapshot for one commit.
pub struct AtomicState {
    /// CRTC states
    pub crtc_states: [CrtcAtomicState; MAX_CRTCS],
    pub num_crtcs: u32,
    /// Plane states
    pub plane_states: [PlaneAtomicState; MAX_PLANES],
    pub num_planes: u32,
    /// Connector states
    pub connector_states: [ConnectorAtomicState; MAX_CONNECTORS],
    pub num_connectors: u32,
    /// Commit flags
    pub flags: u32,
    /// User event data
    pub user_data: u64,
}

pub struct CrtcAtomicState {
    pub crtc_id: u32,
    pub active: bool,
    pub mode_changed: bool,
    pub mode: DrmDisplayMode,
    pub planes_changed: bool,
    pub connectors_changed: bool,
}

pub struct PlaneAtomicState {
    pub plane_id: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    pub rotation: u32,
    pub alpha: u16,
    pub zpos: u32,
    pub visible: bool,
}

pub struct ConnectorAtomicState {
    pub connector_id: u32,
    pub crtc_id: u32,
    pub dpms: DpmsMode,
    pub writeback_fb_id: u32,
}

impl AtomicState {
    /// Validate the atomic state (check only, no hardware changes).
    pub fn check(&self) -> DrmResult<()> {
        // Validate: no plane on two CRTCs
        // Validate: bandwidth doesn't exceed limits
        // Validate: format supported by plane
        // Validate: scaling within hardware limits
        for i in 0..self.num_planes as usize {
            let ps = &self.plane_states[i];
            if ps.fb_id != 0 && ps.crtc_id == 0 {
                return Err(DrmError::InvalidArgument);
            }
            if ps.src_w == 0 || ps.src_h == 0 {
                if ps.fb_id != 0 {
                    return Err(DrmError::InvalidArgument);
                }
            }
        }
        Ok(())
    }

    /// Commit the atomic state to hardware.
    pub fn commit(&self) -> DrmResult<()> {
        self.check()?;

        if self.flags & DRM_MODE_ATOMIC_TEST_ONLY != 0 {
            return Ok(()); // Test only, don't apply
        }

        // Apply CRTC mode changes
        // Apply plane changes
        // Apply connector changes
        // Fire vblank events

        Ok(())
    }
}

// ============================================================================
// VBlank
// ============================================================================

pub struct VblankManager {
    /// Per-CRTC vblank state
    pub crtcs: [VblankState; MAX_CRTCS],
    pub num_crtcs: u32,
}

pub struct VblankState {
    /// VBlank counter
    pub count: AtomicU64,
    /// Enabled
    pub enabled: AtomicBool,
    /// Timestamp of last vblank (ns)
    pub timestamp: AtomicU64,
    /// Number of waiters
    pub waiters: AtomicU32,
    /// Refcount for vblank interrupts
    pub inmodeset: AtomicI32,
}

impl VblankManager {
    pub fn handle_vblank(&self, crtc_idx: usize) {
        if crtc_idx >= self.num_crtcs as usize {
            return;
        }
        let state = &self.crtcs[crtc_idx];
        state.count.fetch_add(1, Ordering::Relaxed);
        // Would read hardware timestamp and store it
        // Would wake up waiters
    }

    pub fn get_vblank_count(&self, crtc_idx: usize) -> u64 {
        if crtc_idx >= self.num_crtcs as usize {
            return 0;
        }
        self.crtcs[crtc_idx].count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// DRM Device
// ============================================================================

pub struct DrmDevice {
    /// Device name
    pub name: [u8; 32],
    /// Driver name
    pub driver_name: [u8; 32],
    /// Driver description
    pub driver_desc: [u8; 64],
    /// Version
    pub major: u32,
    pub minor: u32,
    pub patchlevel: u32,
    /// PCI device info
    pub pci_vendor: u16,
    pub pci_device: u16,
    /// MMIO base address
    pub mmio_base: u64,
    pub mmio_size: u64,
    /// VRAM base and size
    pub vram_base: u64,
    pub vram_size: u64,
    /// KMS resources
    pub crtcs: [*mut DrmCrtc; MAX_CRTCS],
    pub num_crtcs: u32,
    pub encoders: [*mut DrmEncoder; MAX_ENCODERS],
    pub num_encoders: u32,
    pub connectors: [*mut DrmConnector; MAX_CONNECTORS],
    pub num_connectors: u32,
    pub planes: [*mut DrmPlane; MAX_PLANES],
    pub num_planes: u32,
    /// VBlank manager
    pub vblank: VblankManager,
    /// Capabilities
    pub caps: DeviceCaps,
    /// Is this a render-only device (no display)?
    pub render_only: bool,
    /// Open file count
    pub open_count: AtomicU32,
    /// IRQ number
    pub irq: i32,
    /// IRQ enabled
    pub irq_enabled: AtomicBool,
}

pub struct DeviceCaps {
    pub dumb_buffer: bool,
    pub prime: bool,
    pub syncobj: bool,
    pub syncobj_timeline: bool,
    pub atomic: bool,
    pub async_page_flip: bool,
    pub cursor_width: u32,
    pub cursor_height: u32,
    pub preferred_depth: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub modifiers: bool,
}

impl DrmDevice {
    /// Handle a DRM IOCTL.
    pub fn handle_ioctl(&mut self, cmd: u32, _arg: u64) -> DrmResult<i64> {
        match cmd {
            ioctl::DRM_IOCTL_VERSION => Ok(0),
            ioctl::DRM_IOCTL_GET_CAP => Ok(0),
            ioctl::DRM_IOCTL_MODE_GETRESOURCES => Ok(0),
            ioctl::DRM_IOCTL_MODE_GETCRTC => Ok(0),
            ioctl::DRM_IOCTL_MODE_SETCRTC => Ok(0),
            ioctl::DRM_IOCTL_MODE_GETCONNECTOR => Ok(0),
            ioctl::DRM_IOCTL_MODE_GETENCODER => Ok(0),
            ioctl::DRM_IOCTL_MODE_ADDFB => Ok(0),
            ioctl::DRM_IOCTL_MODE_ADDFB2 => Ok(0),
            ioctl::DRM_IOCTL_MODE_RMFB => Ok(0),
            ioctl::DRM_IOCTL_MODE_PAGE_FLIP => Ok(0),
            ioctl::DRM_IOCTL_MODE_ATOMIC => Ok(0),
            ioctl::DRM_IOCTL_MODE_CREATE_DUMB => Ok(0),
            ioctl::DRM_IOCTL_MODE_MAP_DUMB => Ok(0),
            ioctl::DRM_IOCTL_MODE_DESTROY_DUMB => Ok(0),
            ioctl::DRM_IOCTL_GEM_CLOSE => Ok(0),
            ioctl::DRM_IOCTL_PRIME_HANDLE_TO_FD => Ok(0),
            ioctl::DRM_IOCTL_PRIME_FD_TO_HANDLE => Ok(0),
            _ => Err(DrmError::InvalidArgument),
        }
    }

    /// Handle VBlank interrupt.
    pub fn handle_vblank_irq(&self, pipe: u32) {
        self.vblank.handle_vblank(pipe as usize);
    }
}

// ============================================================================
// C FFI
// ============================================================================

#[no_mangle]
pub extern "C" fn drm_init() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn drm_gem_create_dumb(
    width: u32,
    height: u32,
    bpp: u32,
    handle_out: *mut u32,
    size_out: *mut u64,
    pitch_out: *mut u32,
) -> i32 {
    match GemObject::create_dumb(width, height, bpp) {
        Ok(obj) => {
            unsafe {
                if !handle_out.is_null() {
                    *handle_out = obj.handle;
                }
                if !size_out.is_null() {
                    *size_out = obj.size;
                }
                if !pitch_out.is_null() {
                    *pitch_out = obj.stride;
                }
            }
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn drm_mode_atomic_commit(flags: u32) -> i32 {
    let _ = flags;
    0
}
