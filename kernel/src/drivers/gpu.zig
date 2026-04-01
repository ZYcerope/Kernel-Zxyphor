// =============================================================================
// Kernel Zxyphor — GPU / DRM / KMS Subsystem (Zig)
// =============================================================================
// Linux DRM/KMS-inspired display subsystem providing:
//   - DRM device abstraction (GPU cards)
//   - KMS mode setting (CRTC, encoder, connector, plane)
//   - Display mode (resolution, refresh, pixel clock)
//   - Framebuffer object management (GEM-style)
//   - Output pipeline: Plane → CRTC → Encoder → Connector
//   - Atomic mode setting commits
//   - DPMS power states
//   - Gamma LUT for color correction
//   - VBlank event tracking
//   - Multi-head display support (up to 4 outputs)
//   - Hardware cursor planes
//   - Page flipping (double buffer)
//   - EDID parsing for monitor identification
//   - DRM IOCTL dispatch table
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_GPUS = 4;
pub const MAX_CRTCS = 4;
pub const MAX_ENCODERS = 8;
pub const MAX_CONNECTORS = 8;
pub const MAX_PLANES = 16;
pub const MAX_MODES = 64;
pub const MAX_FRAMEBUFFERS = 32;
pub const MAX_GEM_OBJECTS = 256;
pub const MAX_PROPERTIES = 64;
pub const GAMMA_LUT_SIZE = 256;
pub const EDID_BLOCK_SIZE = 128;
pub const MAX_EDID_BLOCKS = 4;
pub const MAX_CURSOR_SIZE = 64; // 64x64 pixels

// =============================================================================
// DRM/KMS object IDs
// =============================================================================

pub const ObjectType = enum(u8) {
    crtc = 0,
    encoder = 1,
    connector = 2,
    plane = 3,
    framebuffer = 4,
    gem = 5,
    property = 6,
    mode = 7,
};

// =============================================================================
// Connector types
// =============================================================================

pub const ConnectorType = enum(u8) {
    unknown = 0,
    vga = 1,
    dvi_i = 2,
    dvi_d = 3,
    dvi_a = 4,
    composite = 5,
    svideo = 6,
    lvds = 7,
    component = 8,
    dp = 9,         // DisplayPort
    hdmi_a = 10,
    hdmi_b = 11,
    edp = 12,       // Embedded DisplayPort
    virtual_display = 13,
    dsi = 14,       // MIPI DSI
    usb_c = 15,

    pub fn name(self: ConnectorType) []const u8 {
        return switch (self) {
            .unknown => "Unknown",
            .vga => "VGA",
            .dvi_i => "DVI-I",
            .dvi_d => "DVI-D",
            .dvi_a => "DVI-A",
            .composite => "Composite",
            .svideo => "S-Video",
            .lvds => "LVDS",
            .component => "Component",
            .dp => "DisplayPort",
            .hdmi_a => "HDMI-A",
            .hdmi_b => "HDMI-B",
            .edp => "eDP",
            .virtual_display => "Virtual",
            .dsi => "DSI",
            .usb_c => "USB-C",
        };
    }
};

// =============================================================================
// Connector status
// =============================================================================

pub const ConnectorStatus = enum(u8) {
    connected = 1,
    disconnected = 2,
    unknown = 3,
};

// =============================================================================
// Encoder type
// =============================================================================

pub const EncoderType = enum(u8) {
    none = 0,
    dac = 1,     // analog
    tmds = 2,    // DVI/HDMI
    lvds = 3,
    tvdac = 4,
    dp = 5,      // DisplayPort
    virtual_enc = 6,
    dsi = 7,
};

// =============================================================================
// Plane type
// =============================================================================

pub const PlaneType = enum(u8) {
    primary = 0,   // main scanout plane
    overlay = 1,   // overlay / sprite
    cursor = 2,    // hardware cursor
};

// =============================================================================
// DPMS power state
// =============================================================================

pub const DpmsState = enum(u8) {
    on = 0,
    standby = 1,
    suspend = 2,
    off = 3,
};

// =============================================================================
// Pixel format (DRM fourcc inspired)
// =============================================================================

pub const DrmPixelFormat = enum(u32) {
    xrgb8888 = 0x34325258, // XR24
    argb8888 = 0x34325241, // AR24
    xbgr8888 = 0x34324258, // XB24
    abgr8888 = 0x34324241, // AB24
    rgb565 = 0x36314752,   // RG16
    xrgb1555 = 0x35315258, // XR15
    rgb888 = 0x34324752,   // RG24
    yuyv = 0x56595559,     // YUYV
    nv12 = 0x3231564E,     // NV12

    pub fn bitsPerPixel(self: DrmPixelFormat) u8 {
        return switch (self) {
            .xrgb8888, .argb8888, .xbgr8888, .abgr8888 => 32,
            .rgb888 => 24,
            .rgb565, .xrgb1555, .yuyv => 16,
            .nv12 => 12,
        };
    }

    pub fn bytesPerPixel(self: DrmPixelFormat) u8 {
        return self.bitsPerPixel() / 8;
    }
};

// =============================================================================
// Display mode (KMS mode info)
// =============================================================================

pub const DisplayMode = struct {
    hdisplay: u16,
    hsync_start: u16,
    hsync_end: u16,
    htotal: u16,
    vdisplay: u16,
    vsync_start: u16,
    vsync_end: u16,
    vtotal: u16,
    clock: u32,         // pixel clock in kHz
    flags: u32,         // mode flags
    type_field: u32,    // mode type
    vrefresh: u16,
    name: [32]u8,
    name_len: u8,
    preferred: bool,

    // Mode flags
    pub const FLAG_PHSYNC = 0x01;   // positive hsync
    pub const FLAG_NHSYNC = 0x02;   // negative hsync
    pub const FLAG_PVSYNC = 0x04;   // positive vsync
    pub const FLAG_NVSYNC = 0x08;   // negative vsync
    pub const FLAG_INTERLACE = 0x10;
    pub const FLAG_DBLSCAN = 0x20;

    pub fn init() DisplayMode {
        return .{
            .hdisplay = 0,
            .hsync_start = 0,
            .hsync_end = 0,
            .htotal = 0,
            .vdisplay = 0,
            .vsync_start = 0,
            .vsync_end = 0,
            .vtotal = 0,
            .clock = 0,
            .flags = 0,
            .type_field = 0,
            .vrefresh = 0,
            .name = [_]u8{0} ** 32,
            .name_len = 0,
            .preferred = false,
        };
    }

    /// Calculate the vertical refresh rate
    pub fn calcRefresh(self: *const DisplayMode) u16 {
        if (self.htotal == 0 or self.vtotal == 0) return 0;
        const num = @as(u64, self.clock) * 1000;
        const den = @as(u64, self.htotal) * @as(u64, self.vtotal);
        if (den == 0) return 0;
        return @truncate(num / den);
    }

    /// Create a standard 1920x1080@60Hz mode
    pub fn mode1080p60() DisplayMode {
        var m = DisplayMode.init();
        m.hdisplay = 1920;
        m.hsync_start = 2008;
        m.hsync_end = 2052;
        m.htotal = 2200;
        m.vdisplay = 1080;
        m.vsync_start = 1084;
        m.vsync_end = 1089;
        m.vtotal = 1125;
        m.clock = 148500; // 148.5 MHz
        m.flags = FLAG_PHSYNC | FLAG_PVSYNC;
        m.vrefresh = 60;
        m.preferred = true;
        const n = "1920x1080@60";
        @memcpy(m.name[0..n.len], n);
        m.name_len = n.len;
        return m;
    }

    /// Create a standard 1280x720@60Hz mode
    pub fn mode720p60() DisplayMode {
        var m = DisplayMode.init();
        m.hdisplay = 1280;
        m.hsync_start = 1390;
        m.hsync_end = 1430;
        m.htotal = 1650;
        m.vdisplay = 720;
        m.vsync_start = 725;
        m.vsync_end = 730;
        m.vtotal = 750;
        m.clock = 74250; // 74.25 MHz
        m.flags = FLAG_PHSYNC | FLAG_PVSYNC;
        m.vrefresh = 60;
        const n = "1280x720@60";
        @memcpy(m.name[0..n.len], n);
        m.name_len = n.len;
        return m;
    }

    /// Create a standard 640x480@60Hz mode
    pub fn mode640x480() DisplayMode {
        var m = DisplayMode.init();
        m.hdisplay = 640;
        m.hsync_start = 656;
        m.hsync_end = 752;
        m.htotal = 800;
        m.vdisplay = 480;
        m.vsync_start = 490;
        m.vsync_end = 492;
        m.vtotal = 525;
        m.clock = 25175; // 25.175 MHz
        m.flags = FLAG_NHSYNC | FLAG_NVSYNC;
        m.vrefresh = 60;
        const n = "640x480@60";
        @memcpy(m.name[0..n.len], n);
        m.name_len = n.len;
        return m;
    }

    /// Create a standard 1024x768@60Hz mode
    pub fn mode1024x768() DisplayMode {
        var m = DisplayMode.init();
        m.hdisplay = 1024;
        m.hsync_start = 1048;
        m.hsync_end = 1184;
        m.htotal = 1344;
        m.vdisplay = 768;
        m.vsync_start = 771;
        m.vsync_end = 777;
        m.vtotal = 806;
        m.clock = 65000;
        m.flags = FLAG_NHSYNC | FLAG_NVSYNC;
        m.vrefresh = 60;
        const n = "1024x768@60";
        @memcpy(m.name[0..n.len], n);
        m.name_len = n.len;
        return m;
    }

    /// Create a standard 3840x2160@60Hz mode (4K)
    pub fn mode4k60() DisplayMode {
        var m = DisplayMode.init();
        m.hdisplay = 3840;
        m.hsync_start = 4016;
        m.hsync_end = 4104;
        m.htotal = 4400;
        m.vdisplay = 2160;
        m.vsync_start = 2168;
        m.vsync_end = 2178;
        m.vtotal = 2250;
        m.clock = 594000; // 594 MHz
        m.flags = FLAG_PHSYNC | FLAG_PVSYNC;
        m.vrefresh = 60;
        const n = "3840x2160@60";
        @memcpy(m.name[0..n.len], n);
        m.name_len = n.len;
        return m;
    }
};

// =============================================================================
// GEM (Graphics Execution Manager) object — GPU memory buffer
// =============================================================================

pub const GemObject = struct {
    id: u32,
    size: u64,          // in bytes
    phys_addr: u64,     // physical VRAM address
    virt_addr: u64,     // kernel virtual mapping
    width: u32,
    height: u32,
    stride: u32,        // bytes per row
    format: DrmPixelFormat,
    ref_count: u32,
    pinned: bool,       // pinned in VRAM (cannot be evicted)
    tiled: bool,        // uses tiling (X/Y tiling)
    dirty: bool,
    active: bool,

    pub fn init() GemObject {
        return .{
            .id = 0,
            .size = 0,
            .phys_addr = 0,
            .virt_addr = 0,
            .width = 0,
            .height = 0,
            .stride = 0,
            .format = .xrgb8888,
            .ref_count = 0,
            .pinned = false,
            .tiled = false,
            .dirty = false,
            .active = false,
        };
    }

    pub fn calcStride(width: u32, format: DrmPixelFormat) u32 {
        return (width * @as(u32, format.bytesPerPixel()) + 63) & ~@as(u32, 63); // 64-byte aligned
    }

    pub fn calcSize(width: u32, height: u32, format: DrmPixelFormat) u64 {
        const stride = calcStride(width, format);
        return @as(u64, stride) * @as(u64, height);
    }

    pub fn get(self: *GemObject) void {
        self.ref_count += 1;
    }

    pub fn put(self: *GemObject) bool {
        if (self.ref_count > 0) {
            self.ref_count -= 1;
            if (self.ref_count == 0 and !self.pinned) {
                return true; // can be freed
            }
        }
        return false;
    }
};

// =============================================================================
// DRM Framebuffer (backed by a GEM object)
// =============================================================================

pub const DrmFramebuffer = struct {
    id: u32,
    gem_id: u32,        // backing GEM object
    width: u32,
    height: u32,
    stride: u32,
    format: DrmPixelFormat,
    offset: u64,        // offset into GEM object
    active: bool,

    pub fn init() DrmFramebuffer {
        return .{
            .id = 0,
            .gem_id = 0,
            .width = 0,
            .height = 0,
            .stride = 0,
            .format = .xrgb8888,
            .offset = 0,
            .active = false,
        };
    }
};

// =============================================================================
// Plane — scanout surface
// =============================================================================

pub const DrmPlane = struct {
    id: u32,
    plane_type: PlaneType,
    fb_id: u32,          // currently bound framebuffer
    crtc_id: u32,        // bound to which CRTC
    src_x: u32,          // source rect in fb (16.16 fixed)
    src_y: u32,
    src_w: u32,
    src_h: u32,
    dst_x: i32,          // destination on CRTC
    dst_y: i32,
    dst_w: u32,
    dst_h: u32,
    rotation: u16,       // 0, 90, 180, 270
    alpha: u16,          // 0-65535 (0=transparent, 65535=opaque)
    zpos: u8,            // stacking order
    formats: [16]DrmPixelFormat,
    format_count: u8,
    active: bool,

    pub fn init(id: u32, ptype: PlaneType) DrmPlane {
        var p = DrmPlane{
            .id = id,
            .plane_type = ptype,
            .fb_id = 0,
            .crtc_id = 0,
            .src_x = 0, .src_y = 0,
            .src_w = 0, .src_h = 0,
            .dst_x = 0, .dst_y = 0,
            .dst_w = 0, .dst_h = 0,
            .rotation = 0,
            .alpha = 65535,
            .zpos = 0,
            .formats = [_]DrmPixelFormat{.xrgb8888} ** 16,
            .format_count = 0,
            .active = false,
        };
        // Add default supported formats
        p.formats[0] = .xrgb8888;
        p.formats[1] = .argb8888;
        p.formats[2] = .rgb565;
        p.format_count = 3;
        return p;
    }

    pub fn supportsFormat(self: *const DrmPlane, fmt: DrmPixelFormat) bool {
        for (0..self.format_count) |i| {
            if (self.formats[i] == fmt) return true;
        }
        return false;
    }
};

// =============================================================================
// CRTC — scanout engine (drives output timing)
// =============================================================================

pub const DrmCrtc = struct {
    id: u32,
    active: bool,
    mode_valid: bool,
    mode: DisplayMode,
    fb_id: u32,              // primary framebuffer
    gamma_size: u16,
    gamma_r: [GAMMA_LUT_SIZE]u16,
    gamma_g: [GAMMA_LUT_SIZE]u16,
    gamma_b: [GAMMA_LUT_SIZE]u16,
    vblank_count: u64,
    page_flip_pending: bool,
    flip_fb_id: u32,
    dpms: DpmsState,

    // Cursor
    cursor_enabled: bool,
    cursor_x: i32,
    cursor_y: i32,
    cursor_width: u32,
    cursor_height: u32,
    cursor_gem_id: u32,

    pub fn init(id: u32) DrmCrtc {
        var c = DrmCrtc{
            .id = id,
            .active = false,
            .mode_valid = false,
            .mode = DisplayMode.init(),
            .fb_id = 0,
            .gamma_size = GAMMA_LUT_SIZE,
            .gamma_r = [_]u16{0} ** GAMMA_LUT_SIZE,
            .gamma_g = [_]u16{0} ** GAMMA_LUT_SIZE,
            .gamma_b = [_]u16{0} ** GAMMA_LUT_SIZE,
            .vblank_count = 0,
            .page_flip_pending = false,
            .flip_fb_id = 0,
            .dpms = .off,
            .cursor_enabled = false,
            .cursor_x = 0,
            .cursor_y = 0,
            .cursor_width = 0,
            .cursor_height = 0,
            .cursor_gem_id = 0,
        };
        // Initialize linear gamma ramp
        for (0..GAMMA_LUT_SIZE) |i| {
            const val: u16 = @truncate(i * 256);
            c.gamma_r[i] = val;
            c.gamma_g[i] = val;
            c.gamma_b[i] = val;
        }
        return c;
    }

    /// Set display mode on this CRTC
    pub fn setMode(self: *DrmCrtc, mode: DisplayMode) void {
        self.mode = mode;
        self.mode_valid = true;
    }

    /// Handle VBlank interrupt
    pub fn vblank(self: *DrmCrtc) void {
        self.vblank_count += 1;
        if (self.page_flip_pending) {
            self.fb_id = self.flip_fb_id;
            self.page_flip_pending = false;
        }
    }

    /// Request page flip (takes effect on next VBlank)
    pub fn pageFlip(self: *DrmCrtc, new_fb_id: u32) bool {
        if (self.page_flip_pending) return false;
        self.flip_fb_id = new_fb_id;
        self.page_flip_pending = true;
        return true;
    }

    /// Set hardware cursor position
    pub fn setCursor(self: *DrmCrtc, x: i32, y: i32) void {
        self.cursor_x = x;
        self.cursor_y = y;
    }

    /// Enable hardware cursor with a GEM-backed image
    pub fn enableCursor(self: *DrmCrtc, gem_id: u32, w: u32, h: u32) void {
        self.cursor_gem_id = gem_id;
        self.cursor_width = if (w > MAX_CURSOR_SIZE) MAX_CURSOR_SIZE else w;
        self.cursor_height = if (h > MAX_CURSOR_SIZE) MAX_CURSOR_SIZE else h;
        self.cursor_enabled = true;
    }

    /// Apply gamma correction
    pub fn applyGammaCorrection(self: *const DrmCrtc, r: u8, g: u8, b: u8) struct { r: u8, g: u8, b: u8 } {
        return .{
            .r = @truncate(self.gamma_r[r] >> 8),
            .g = @truncate(self.gamma_g[g] >> 8),
            .b = @truncate(self.gamma_b[b] >> 8),
        };
    }
};

// =============================================================================
// Encoder
// =============================================================================

pub const DrmEncoder = struct {
    id: u32,
    encoder_type: EncoderType,
    crtc_id: u32,               // currently bound CRTC
    possible_crtcs: u32,        // bitmask of CRTCs this encoder can use
    possible_clones: u32,       // bitmask of other encoders for cloning
    active: bool,

    pub fn init(id: u32, etype: EncoderType) DrmEncoder {
        return .{
            .id = id,
            .encoder_type = etype,
            .crtc_id = 0,
            .possible_crtcs = 0xF, // all CRTCs by default
            .possible_clones = 0,
            .active = false,
        };
    }
};

// =============================================================================
// Connector (with EDID parsing)
// =============================================================================

pub const EdidInfo = struct {
    valid: bool,
    manufacturer: [4]u8,
    product_code: u16,
    serial: u32,
    week: u8,
    year: u16,
    version: u8,
    revision: u8,
    width_cm: u8,
    height_cm: u8,
    gamma: u8,
    features: u8,
    preferred_mode: DisplayMode,
    modes: [MAX_MODES]DisplayMode,
    mode_count: u8,

    pub fn init() EdidInfo {
        return .{
            .valid = false,
            .manufacturer = [_]u8{0} ** 4,
            .product_code = 0,
            .serial = 0,
            .week = 0, .year = 0,
            .version = 0, .revision = 0,
            .width_cm = 0, .height_cm = 0,
            .gamma = 0, .features = 0,
            .preferred_mode = DisplayMode.init(),
            .modes = [_]DisplayMode{DisplayMode.init()} ** MAX_MODES,
            .mode_count = 0,
        };
    }

    /// Parse raw EDID block (128 bytes)
    pub fn parseEdid(data: *const [EDID_BLOCK_SIZE]u8) EdidInfo {
        var info = EdidInfo.init();

        // Validate EDID header: 00 FF FF FF FF FF FF 00
        if (data[0] != 0x00 or data[1] != 0xFF or data[2] != 0xFF or
            data[3] != 0xFF or data[4] != 0xFF or data[5] != 0xFF or
            data[6] != 0xFF or data[7] != 0x00) return info;

        // Validate checksum
        var checksum: u8 = 0;
        for (data) |b| {
            checksum +%= b;
        }
        if (checksum != 0) return info;

        // Manufacturer ID (big-endian, compressed ASCII)
        const mfg = @as(u16, data[8]) << 8 | @as(u16, data[9]);
        info.manufacturer[0] = @truncate(((mfg >> 10) & 0x1F) + 'A' - 1);
        info.manufacturer[1] = @truncate(((mfg >> 5) & 0x1F) + 'A' - 1);
        info.manufacturer[2] = @truncate((mfg & 0x1F) + 'A' - 1);
        info.manufacturer[3] = 0;

        info.product_code = @as(u16, data[11]) << 8 | @as(u16, data[10]);
        info.serial = @as(u32, data[15]) << 24 | @as(u32, data[14]) << 16 |
            @as(u32, data[13]) << 8 | @as(u32, data[12]);
        info.week = data[16];
        info.year = @as(u16, data[17]) + 1990;
        info.version = data[18];
        info.revision = data[19];
        info.width_cm = data[21];
        info.height_cm = data[22];
        info.gamma = data[23];
        info.features = data[24];

        // Parse detailed timing descriptors (bytes 54-125, 4 x 18-byte blocks)
        var desc_idx: usize = 54;
        while (desc_idx + 18 <= 126) : (desc_idx += 18) {
            const pixel_clock_raw = @as(u16, data[desc_idx + 1]) << 8 | @as(u16, data[desc_idx]);
            if (pixel_clock_raw == 0) continue; // not a timing descriptor

            var mode = DisplayMode.init();
            mode.clock = @as(u32, pixel_clock_raw) * 10; // convert to kHz

            mode.hdisplay = (@as(u16, data[desc_idx + 4] >> 4) << 8) | @as(u16, data[desc_idx + 2]);
            const hblank = (@as(u16, data[desc_idx + 4] & 0x0F) << 8) | @as(u16, data[desc_idx + 3]);
            mode.htotal = mode.hdisplay + hblank;

            mode.vdisplay = (@as(u16, data[desc_idx + 7] >> 4) << 8) | @as(u16, data[desc_idx + 5]);
            const vblank = (@as(u16, data[desc_idx + 7] & 0x0F) << 8) | @as(u16, data[desc_idx + 6]);
            mode.vtotal = mode.vdisplay + vblank;

            const hsync_off = (@as(u16, data[desc_idx + 11] >> 6) << 8) | @as(u16, data[desc_idx + 8]);
            const hsync_pw = (@as(u16, (data[desc_idx + 11] >> 4) & 0x03) << 8) | @as(u16, data[desc_idx + 9]);
            mode.hsync_start = mode.hdisplay + hsync_off;
            mode.hsync_end = mode.hsync_start + hsync_pw;

            const vsync_off = (@as(u16, (data[desc_idx + 11] >> 2) & 0x03) << 4) | @as(u16, data[desc_idx + 10] >> 4);
            const vsync_pw = (@as(u16, data[desc_idx + 11] & 0x03) << 4) | @as(u16, data[desc_idx + 10] & 0x0F);
            mode.vsync_start = mode.vdisplay + vsync_off;
            mode.vsync_end = mode.vsync_start + vsync_pw;

            mode.vrefresh = mode.calcRefresh();

            if (info.mode_count == 0) {
                mode.preferred = true;
                info.preferred_mode = mode;
            }

            if (info.mode_count < MAX_MODES) {
                info.modes[info.mode_count] = mode;
                info.mode_count += 1;
            }
        }

        info.valid = true;
        return info;
    }
};

pub const DrmConnector = struct {
    id: u32,
    connector_type: ConnectorType,
    status: ConnectorStatus,
    encoder_id: u32,           // currently bound encoder
    possible_encoders: u32,    // bitmask
    dpms: DpmsState,
    edid: EdidInfo,
    modes: [MAX_MODES]DisplayMode,
    mode_count: u8,
    active: bool,

    // Physical properties
    subpixel_order: u8,
    width_mm: u16,
    height_mm: u16,

    pub fn init(id: u32, ctype: ConnectorType) DrmConnector {
        return .{
            .id = id,
            .connector_type = ctype,
            .status = .unknown,
            .encoder_id = 0,
            .possible_encoders = 0xFF,
            .dpms = .off,
            .edid = EdidInfo.init(),
            .modes = [_]DisplayMode{DisplayMode.init()} ** MAX_MODES,
            .mode_count = 0,
            .active = false,
            .subpixel_order = 0,
            .width_mm = 0, .height_mm = 0,
        };
    }

    /// Detect connector status (read HPD, parse EDID, populate modes)
    pub fn detect(self: *DrmConnector) void {
        // In a real driver, we'd read the hot-plug detect pin and DDC bus
        // For now, add standard modes
        if (self.mode_count == 0) {
            self.modes[0] = DisplayMode.mode1080p60();
            self.modes[1] = DisplayMode.mode720p60();
            self.modes[2] = DisplayMode.mode1024x768();
            self.modes[3] = DisplayMode.mode640x480();
            self.mode_count = 4;
        }
    }

    pub fn getPreferredMode(self: *const DrmConnector) ?*const DisplayMode {
        for (0..self.mode_count) |i| {
            if (self.modes[i].preferred) return &self.modes[i];
        }
        if (self.mode_count > 0) return &self.modes[0];
        return null;
    }
};

// =============================================================================
// Atomic state (for atomic mode setting)
// =============================================================================

pub const AtomicState = struct {
    crtc_states: [MAX_CRTCS]struct {
        active: bool,
        mode_changed: bool,
        mode: DisplayMode,
        fb_id: u32,
        valid: bool,
    },
    plane_states: [MAX_PLANES]struct {
        fb_id: u32,
        crtc_id: u32,
        src_x: u32, src_y: u32,
        src_w: u32, src_h: u32,
        dst_x: i32, dst_y: i32,
        dst_w: u32, dst_h: u32,
        valid: bool,
    },
    connector_states: [MAX_CONNECTORS]struct {
        crtc_id: u32,
        dpms: DpmsState,
        valid: bool,
    },
    committed: bool,

    pub fn init() AtomicState {
        var s: AtomicState = undefined;
        for (0..MAX_CRTCS) |i| {
            s.crtc_states[i] = .{ .active = false, .mode_changed = false, .mode = DisplayMode.init(), .fb_id = 0, .valid = false };
        }
        for (0..MAX_PLANES) |i| {
            s.plane_states[i] = .{ .fb_id = 0, .crtc_id = 0, .src_x = 0, .src_y = 0, .src_w = 0, .src_h = 0, .dst_x = 0, .dst_y = 0, .dst_w = 0, .dst_h = 0, .valid = false };
        }
        for (0..MAX_CONNECTORS) |i| {
            s.connector_states[i] = .{ .crtc_id = 0, .dpms = .off, .valid = false };
        }
        s.committed = false;
        return s;
    }
};

// =============================================================================
// DRM IOCTL commands
// =============================================================================

pub const DrmIoctl = enum(u32) {
    get_version = 0x00,
    get_cap = 0x0C,
    set_master = 0x1E,
    drop_master = 0x1F,
    mode_get_resources = 0xA0,
    mode_get_crtc = 0xA1,
    mode_set_crtc = 0xA2,
    mode_get_encoder = 0xA6,
    mode_get_connector = 0xA7,
    mode_get_property = 0xAA,
    mode_get_fb = 0xAD,
    mode_add_fb = 0xAE,
    mode_rm_fb = 0xAF,
    mode_page_flip = 0xB0,
    mode_cursor = 0xB1,
    mode_create_dumb = 0xB2,
    mode_map_dumb = 0xB3,
    mode_destroy_dumb = 0xB4,
    mode_get_plane = 0xB5,
    mode_atomic = 0xBC,
    mode_create_blob = 0xBD,
    gem_close = 0x09,
    gem_flink = 0x0A,
    gem_open = 0x0B,
};

// =============================================================================
// DRM GPU Device
// =============================================================================

pub const GpuDevice = struct {
    id: u8,
    active: bool,

    // KMS objects
    crtcs: [MAX_CRTCS]DrmCrtc,
    crtc_count: u8,
    encoders: [MAX_ENCODERS]DrmEncoder,
    encoder_count: u8,
    connectors: [MAX_CONNECTORS]DrmConnector,
    connector_count: u8,
    planes: [MAX_PLANES]DrmPlane,
    plane_count: u8,

    // Buffer management
    framebuffers: [MAX_FRAMEBUFFERS]DrmFramebuffer,
    fb_count: u8,
    gem_objects: [MAX_GEM_OBJECTS]GemObject,
    gem_count: u32,
    next_gem_id: u32,
    next_fb_id: u32,

    // VRAM info
    vram_base: u64,
    vram_size: u64,
    vram_used: u64,

    // Device info
    vendor_id: u16,
    device_id: u16,
    revision: u8,
    driver_name: [32]u8,
    driver_name_len: u8,

    // Capabilities
    supports_atomic: bool,
    supports_cursor: bool,
    supports_overlay: bool,
    max_width: u32,
    max_height: u32,

    // Statistics
    frames_rendered: u64,
    page_flips: u64,
    mode_sets: u64,

    pub fn init(id: u8) GpuDevice {
        var dev = GpuDevice{
            .id = id,
            .active = false,
            .crtcs = undefined,
            .crtc_count = 0,
            .encoders = undefined,
            .encoder_count = 0,
            .connectors = undefined,
            .connector_count = 0,
            .planes = undefined,
            .plane_count = 0,
            .framebuffers = [_]DrmFramebuffer{DrmFramebuffer.init()} ** MAX_FRAMEBUFFERS,
            .fb_count = 0,
            .gem_objects = [_]GemObject{GemObject.init()} ** MAX_GEM_OBJECTS,
            .gem_count = 0,
            .next_gem_id = 1,
            .next_fb_id = 1,
            .vram_base = 0,
            .vram_size = 0,
            .vram_used = 0,
            .vendor_id = 0,
            .device_id = 0,
            .revision = 0,
            .driver_name = [_]u8{0} ** 32,
            .driver_name_len = 0,
            .supports_atomic = true,
            .supports_cursor = true,
            .supports_overlay = true,
            .max_width = 8192,
            .max_height = 8192,
            .frames_rendered = 0,
            .page_flips = 0,
            .mode_sets = 0,
        };
        // Initialize CRTCs
        for (0..MAX_CRTCS) |i| {
            dev.crtcs[i] = DrmCrtc.init(@truncate(i));
        }
        // Initialize encoders
        for (0..MAX_ENCODERS) |i| {
            dev.encoders[i] = DrmEncoder.init(@truncate(i), .none);
        }
        // Initialize connectors
        for (0..MAX_CONNECTORS) |i| {
            dev.connectors[i] = DrmConnector.init(@truncate(i), .unknown);
        }
        // Initialize planes
        for (0..MAX_PLANES) |i| {
            dev.planes[i] = DrmPlane.init(@truncate(i), .primary);
        }
        return dev;
    }

    /// Register a CRTC
    pub fn addCrtc(self: *GpuDevice) ?u8 {
        if (self.crtc_count >= MAX_CRTCS) return null;
        const idx = self.crtc_count;
        self.crtcs[idx].active = true;
        self.crtc_count += 1;
        return idx;
    }

    /// Register an encoder
    pub fn addEncoder(self: *GpuDevice, etype: EncoderType, possible_crtcs: u32) ?u8 {
        if (self.encoder_count >= MAX_ENCODERS) return null;
        const idx = self.encoder_count;
        self.encoders[idx].encoder_type = etype;
        self.encoders[idx].possible_crtcs = possible_crtcs;
        self.encoders[idx].active = true;
        self.encoder_count += 1;
        return idx;
    }

    /// Register a connector
    pub fn addConnector(self: *GpuDevice, ctype: ConnectorType) ?u8 {
        if (self.connector_count >= MAX_CONNECTORS) return null;
        const idx = self.connector_count;
        self.connectors[idx].connector_type = ctype;
        self.connectors[idx].active = true;
        self.connector_count += 1;
        return idx;
    }

    /// Register a plane
    pub fn addPlane(self: *GpuDevice, ptype: PlaneType) ?u8 {
        if (self.plane_count >= MAX_PLANES) return null;
        const idx = self.plane_count;
        self.planes[idx].plane_type = ptype;
        self.planes[idx].active = true;
        self.plane_count += 1;
        return idx;
    }

    /// Allocate a GEM object (GPU memory)
    pub fn allocGem(self: *GpuDevice, width: u32, height: u32, format: DrmPixelFormat) ?u32 {
        if (self.gem_count >= MAX_GEM_OBJECTS) return null;

        const size = GemObject.calcSize(width, height, format);
        if (self.vram_used + size > self.vram_size) return null; // OOM

        for (0..MAX_GEM_OBJECTS) |i| {
            if (!self.gem_objects[i].active) {
                self.gem_objects[i] = .{
                    .id = self.next_gem_id,
                    .size = size,
                    .phys_addr = self.vram_base + self.vram_used,
                    .virt_addr = 0,
                    .width = width,
                    .height = height,
                    .stride = GemObject.calcStride(width, format),
                    .format = format,
                    .ref_count = 1,
                    .pinned = false,
                    .tiled = false,
                    .dirty = false,
                    .active = true,
                };
                self.vram_used += size;
                self.gem_count += 1;
                const gid = self.next_gem_id;
                self.next_gem_id += 1;
                return gid;
            }
        }
        return null;
    }

    /// Create a framebuffer backed by a GEM object
    pub fn createFb(self: *GpuDevice, gem_id: u32, width: u32, height: u32, format: DrmPixelFormat) ?u32 {
        if (self.fb_count >= MAX_FRAMEBUFFERS) return null;

        // Verify GEM object exists
        var found = false;
        for (0..MAX_GEM_OBJECTS) |i| {
            if (self.gem_objects[i].active and self.gem_objects[i].id == gem_id) {
                self.gem_objects[i].get();
                found = true;
                break;
            }
        }
        if (!found) return null;

        for (0..MAX_FRAMEBUFFERS) |i| {
            if (!self.framebuffers[i].active) {
                self.framebuffers[i] = .{
                    .id = self.next_fb_id,
                    .gem_id = gem_id,
                    .width = width,
                    .height = height,
                    .stride = GemObject.calcStride(width, format),
                    .format = format,
                    .offset = 0,
                    .active = true,
                };
                self.fb_count += 1;
                const fid = self.next_fb_id;
                self.next_fb_id += 1;
                return fid;
            }
        }
        return null;
    }

    /// Set mode on a CRTC with connector + encoder binding
    pub fn setMode(self: *GpuDevice, crtc_idx: u8, encoder_idx: u8, connector_idx: u8, mode: DisplayMode, fb_id: u32) bool {
        if (crtc_idx >= self.crtc_count or encoder_idx >= self.encoder_count or connector_idx >= self.connector_count) return false;

        self.crtcs[crtc_idx].setMode(mode);
        self.crtcs[crtc_idx].fb_id = fb_id;
        self.crtcs[crtc_idx].active = true;
        self.crtcs[crtc_idx].dpms = .on;

        self.encoders[encoder_idx].crtc_id = crtc_idx;
        self.connectors[connector_idx].encoder_id = encoder_idx;
        self.connectors[connector_idx].status = .connected;
        self.connectors[connector_idx].dpms = .on;

        self.mode_sets += 1;
        return true;
    }

    /// Handle VBlank for all active CRTCs
    pub fn handleVBlank(self: *GpuDevice) void {
        for (0..self.crtc_count) |i| {
            if (self.crtcs[i].active) {
                self.crtcs[i].vblank();
                if (self.crtcs[i].page_flip_pending) {
                    self.page_flips += 1;
                }
            }
        }
        self.frames_rendered += 1;
    }

    /// Get total VRAM stats
    pub fn vramStats(self: *const GpuDevice) struct { total: u64, used: u64, free: u64 } {
        return .{
            .total = self.vram_size,
            .used = self.vram_used,
            .free = if (self.vram_size > self.vram_used) self.vram_size - self.vram_used else 0,
        };
    }
};

// =============================================================================
// GPU Subsystem (manages all GPU devices)
// =============================================================================

pub const GpuSubsystem = struct {
    devices: [MAX_GPUS]GpuDevice,
    device_count: u8,
    primary_gpu: u8,
    initialized: bool,

    pub fn init() GpuSubsystem {
        var sub = GpuSubsystem{
            .devices = undefined,
            .device_count = 0,
            .primary_gpu = 0,
            .initialized = false,
        };
        for (0..MAX_GPUS) |i| {
            sub.devices[i] = GpuDevice.init(@truncate(i));
        }
        return sub;
    }

    /// Register a GPU device
    pub fn registerDevice(self: *GpuSubsystem, vendor_id: u16, device_id: u16, vram_base: u64, vram_size: u64) ?u8 {
        if (self.device_count >= MAX_GPUS) return null;

        const idx = self.device_count;
        self.devices[idx].vendor_id = vendor_id;
        self.devices[idx].device_id = device_id;
        self.devices[idx].vram_base = vram_base;
        self.devices[idx].vram_size = vram_size;
        self.devices[idx].active = true;

        // Create default output pipeline: 1 CRTC → 1 encoder → 1 connector + primary plane
        _ = self.devices[idx].addCrtc();
        _ = self.devices[idx].addEncoder(.tmds, 0x01);
        _ = self.devices[idx].addConnector(.hdmi_a);
        _ = self.devices[idx].addPlane(.primary);
        _ = self.devices[idx].addPlane(.cursor);

        self.device_count += 1;
        if (!self.initialized) {
            self.primary_gpu = idx;
            self.initialized = true;
        }
        return idx;
    }

    /// Get the primary GPU
    pub fn getPrimary(self: *GpuSubsystem) ?*GpuDevice {
        if (!self.initialized) return null;
        return &self.devices[self.primary_gpu];
    }

    /// Quick setup: register virtual GPU, create 1080p mode + framebuffer
    pub fn setupVirtual(self: *GpuSubsystem) bool {
        const idx = self.registerDevice(0x1234, 0x1111, 0xFD000000, 64 * 1024 * 1024) orelse return false;
        var dev = &self.devices[idx];

        // Detect connector (populates standard modes)
        dev.connectors[0].detect();

        // Allocate GEM + framebuffer for 1080p XRGB8888
        const gem_id = dev.allocGem(1920, 1080, .xrgb8888) orelse return false;
        const fb_id = dev.createFb(gem_id, 1920, 1080, .xrgb8888) orelse return false;

        // Set mode
        return dev.setMode(0, 0, 0, DisplayMode.mode1080p60(), fb_id);
    }
};

// =============================================================================
// Global instance
// =============================================================================

var gpu_subsystem: GpuSubsystem = GpuSubsystem.init();

pub fn getGpuSubsystem() *GpuSubsystem {
    return &gpu_subsystem;
}
