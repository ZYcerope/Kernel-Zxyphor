// SPDX-License-Identifier: MIT
// Zxyphor Kernel — DRM/Display Core Subsystem (Zig)
//
// Direct Rendering Manager and KMS (Kernel Mode Setting):
// - DRM device registration with GPU capabilities
// - CRTC (display controller), encoder, connector, plane objects
// - Modeset pipeline: connector → encoder → CRTC → plane → framebuffer
// - Display mode (resolution, refresh, timing) management
// - Framebuffer object management with pixel formats
// - Atomic modesetting with test-only and commit paths
// - VBlank event tracking and signaling
// - DPMS power states
// - Gamma/color correction LUT
// - Cursor plane with position tracking
// - Hot-plug detection for connectors
// - GEM (Graphics Execution Manager) buffer objects

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_DRM_DEVICES: usize = 4;
const MAX_CRTCS: usize = 4;
const MAX_ENCODERS: usize = 8;
const MAX_CONNECTORS: usize = 8;
const MAX_PLANES: usize = 16;
const MAX_FBS: usize = 32;
const MAX_GEM_OBJECTS: usize = 64;
const MAX_MODES: usize = 16;
const GAMMA_LUT_SIZE: usize = 256;
const DRM_NAME_LEN: usize = 32;

// ─────────────────── Pixel Formats ──────────────────────────────────

pub const PixelFormat = enum(u32) {
    argb8888 = 0x34325241,
    xrgb8888 = 0x34325258,
    rgb888 = 0x34324752,
    rgb565 = 0x36314752,
    argb1555 = 0x35315241,
    xrgb1555 = 0x35315258,
    argb4444 = 0x34344241,
    abgr8888 = 0x34324241,
    rgba8888 = 0x34324152,
    bgra8888 = 0x34324142,
    nv12 = 0x3231564e,  // YUV 4:2:0
    yuyv = 0x56595559,  // YUV 4:2:2

    pub fn bpp(self: PixelFormat) u8 {
        return switch (self) {
            .argb8888, .xrgb8888, .abgr8888, .rgba8888, .bgra8888 => 32,
            .rgb888 => 24,
            .rgb565, .argb1555, .xrgb1555, .argb4444 => 16,
            .nv12 => 12,
            .yuyv => 16,
        };
    }
};

// ─────────────────── Display Mode ───────────────────────────────────

pub const DisplayMode = struct {
    hdisplay: u16,
    vdisplay: u16,
    hsync_start: u16,
    hsync_end: u16,
    htotal: u16,
    vsync_start: u16,
    vsync_end: u16,
    vtotal: u16,
    clock_khz: u32,     // Pixel clock in KHz
    vrefresh: u16,       // Hz
    flags: ModeFlags,
    type_: ModeType,

    pub const ModeFlags = packed struct {
        phsync: bool = false,   // Positive H sync
        nhsync: bool = false,   // Negative H sync
        pvsync: bool = false,
        nvsync: bool = false,
        interlace: bool = false,
        dblscan: bool = false,
        csync: bool = false,
        _pad: u1 = 0,
    };

    pub const ModeType = enum(u8) {
        preferred = 0,
        driver = 1,
        userdef = 2,
    };

    pub fn init() DisplayMode {
        return .{
            .hdisplay = 0,
            .vdisplay = 0,
            .hsync_start = 0,
            .hsync_end = 0,
            .htotal = 0,
            .vsync_start = 0,
            .vsync_end = 0,
            .vtotal = 0,
            .clock_khz = 0,
            .vrefresh = 0,
            .flags = .{},
            .type_ = .preferred,
        };
    }

    pub fn vga_640x480() DisplayMode {
        return .{
            .hdisplay = 640,
            .vdisplay = 480,
            .hsync_start = 656,
            .hsync_end = 752,
            .htotal = 800,
            .vsync_start = 490,
            .vsync_end = 492,
            .vtotal = 525,
            .clock_khz = 25175,
            .vrefresh = 60,
            .flags = .{ .nhsync = true, .nvsync = true },
            .type_ = .driver,
        };
    }

    pub fn hd_1920x1080() DisplayMode {
        return .{
            .hdisplay = 1920,
            .vdisplay = 1080,
            .hsync_start = 2008,
            .hsync_end = 2052,
            .htotal = 2200,
            .vsync_start = 1084,
            .vsync_end = 1089,
            .vtotal = 1125,
            .clock_khz = 148500,
            .vrefresh = 60,
            .flags = .{ .phsync = true, .pvsync = true },
            .type_ = .preferred,
        };
    }

    pub fn uhd_3840x2160() DisplayMode {
        return .{
            .hdisplay = 3840,
            .vdisplay = 2160,
            .hsync_start = 4016,
            .hsync_end = 4104,
            .htotal = 4400,
            .vsync_start = 2168,
            .vsync_end = 2178,
            .vtotal = 2250,
            .clock_khz = 594000,
            .vrefresh = 60,
            .flags = .{ .phsync = true, .pvsync = true },
            .type_ = .driver,
        };
    }
};

// ─────────────────── DPMS ───────────────────────────────────────────

pub const DpmsState = enum(u8) {
    on = 0,
    standby = 1,
    suspend = 2,
    off = 3,
};

// ─────────────────── Connector ──────────────────────────────────────

pub const ConnectorType = enum(u8) {
    vga = 0,
    dvi_i = 1,
    dvi_d = 2,
    dvi_a = 3,
    hdmi_a = 4,
    hdmi_b = 5,
    display_port = 6,
    edp = 7,
    lvds = 8,
    virtual_ = 9,
    dsi = 10,
    usb_c = 11,
};

pub const ConnectorStatus = enum(u8) {
    connected = 0,
    disconnected = 1,
    unknown = 2,
};

pub const Connector = struct {
    id: u32,
    conn_type: ConnectorType,
    status: ConnectorStatus,
    dpms: DpmsState,
    encoder_id: i16,     // Attached encoder, -1 = none
    modes: [MAX_MODES]DisplayMode,
    mode_count: u8,
    current_mode: u8,    // Index into modes
    edid_valid: bool,
    // EDID parsed info
    physical_width_mm: u16,
    physical_height_mm: u16,
    manufacturer: [4]u8,
    serial: u32,
    // Hotplug
    hotplug_count: u32,
    last_hotplug_tick: u64,
    active: bool,

    pub fn init() Connector {
        var c: Connector = undefined;
        c.id = 0;
        c.conn_type = .hdmi_a;
        c.status = .unknown;
        c.dpms = .on;
        c.encoder_id = -1;
        for (0..MAX_MODES) |i| c.modes[i] = DisplayMode.init();
        c.mode_count = 0;
        c.current_mode = 0;
        c.edid_valid = false;
        c.physical_width_mm = 0;
        c.physical_height_mm = 0;
        c.manufacturer = [_]u8{0} ** 4;
        c.serial = 0;
        c.hotplug_count = 0;
        c.last_hotplug_tick = 0;
        c.active = false;
        return c;
    }

    pub fn add_mode(self: *Connector, mode: DisplayMode) bool {
        if (self.mode_count >= MAX_MODES) return false;
        self.modes[self.mode_count] = mode;
        self.mode_count += 1;
        return true;
    }
};

// ─────────────────── Encoder ────────────────────────────────────────

pub const EncoderType = enum(u8) {
    none = 0,
    dac = 1,     // VGA analog
    tmds = 2,    // DVI/HDMI digital
    lvds = 3,
    tvdac = 4,
    dp = 5,      // DisplayPort
    dsi = 6,     // MIPI DSI
    virtual_ = 7,
};

pub const Encoder = struct {
    id: u32,
    enc_type: EncoderType,
    crtc_id: i16,            // Attached CRTC, -1 = none
    possible_crtcs: u8,       // Bitmask of compatible CRTCs
    possible_clones: u8,      // Bitmask of compatible encoders
    active: bool,

    pub fn init() Encoder {
        return .{
            .id = 0,
            .enc_type = .none,
            .crtc_id = -1,
            .possible_crtcs = 0,
            .possible_clones = 0,
            .active = false,
        };
    }
};

// ─────────────────── CRTC ───────────────────────────────────────────

pub const Crtc = struct {
    id: u32,
    mode: DisplayMode,
    mode_valid: bool,

    // Framebuffer
    fb_id: i16,          // Primary FB, -1 = none
    x: u16,             // Viewport offset
    y: u16,

    // Gamma LUT
    gamma_r: [GAMMA_LUT_SIZE]u16,
    gamma_g: [GAMMA_LUT_SIZE]u16,
    gamma_b: [GAMMA_LUT_SIZE]u16,
    gamma_size: u16,

    // VBlank
    vblank_count: u64,
    vblank_time: u64,

    // Cursor
    cursor_x: i32,
    cursor_y: i32,
    cursor_fb_id: i16,
    cursor_visible: bool,

    enabled: bool,
    active: bool,

    pub fn init() Crtc {
        var crtc: Crtc = undefined;
        crtc.id = 0;
        crtc.mode = DisplayMode.init();
        crtc.mode_valid = false;
        crtc.fb_id = -1;
        crtc.x = 0;
        crtc.y = 0;
        for (0..GAMMA_LUT_SIZE) |i| {
            const v: u16 = @intCast(i * 257); // Linear identity
            crtc.gamma_r[i] = v;
            crtc.gamma_g[i] = v;
            crtc.gamma_b[i] = v;
        }
        crtc.gamma_size = GAMMA_LUT_SIZE;
        crtc.vblank_count = 0;
        crtc.vblank_time = 0;
        crtc.cursor_x = 0;
        crtc.cursor_y = 0;
        crtc.cursor_fb_id = -1;
        crtc.cursor_visible = false;
        crtc.enabled = false;
        crtc.active = false;
        return crtc;
    }

    pub fn set_gamma(self: *Crtc, idx: u16, r: u16, g: u16, b: u16) void {
        if (idx >= GAMMA_LUT_SIZE) return;
        self.gamma_r[idx] = r;
        self.gamma_g[idx] = g;
        self.gamma_b[idx] = b;
    }
};

// ─────────────────── Plane ──────────────────────────────────────────

pub const PlaneType = enum(u8) {
    primary = 0,
    cursor = 1,
    overlay = 2,
};

pub const Plane = struct {
    id: u32,
    plane_type: PlaneType,
    crtc_id: i16,
    fb_id: i16,
    // Source rectangle (16.16 fixed point)
    src_x: u32,
    src_y: u32,
    src_w: u32,
    src_h: u32,
    // Destination rectangle
    dst_x: i32,
    dst_y: i32,
    dst_w: u32,
    dst_h: u32,
    // Rotation
    rotation: u8,  // 0, 90, 180, 270
    // Alpha
    alpha: u16,    // 0-65535
    // Z-order
    zpos: u8,
    possible_crtcs: u8,
    active: bool,

    pub fn init() Plane {
        return .{
            .id = 0,
            .plane_type = .primary,
            .crtc_id = -1,
            .fb_id = -1,
            .src_x = 0,
            .src_y = 0,
            .src_w = 0,
            .src_h = 0,
            .dst_x = 0,
            .dst_y = 0,
            .dst_w = 0,
            .dst_h = 0,
            .rotation = 0,
            .alpha = 0xFFFF,
            .zpos = 0,
            .possible_crtcs = 0,
            .active = false,
        };
    }
};

// ─────────────────── Framebuffer ────────────────────────────────────

pub const Framebuffer = struct {
    id: u32,
    width: u32,
    height: u32,
    pitch: u32,      // Bytes per row
    format: PixelFormat,
    gem_handle: i16,  // GEM buffer object
    offset: u64,     // Offset in VRAM/GTT
    size: u64,
    flags: FbFlags,
    ref_count: u16,
    active: bool,

    pub const FbFlags = packed struct {
        interlaced: bool = false,
        modifiers: bool = false,  // Has format modifier
        _pad: u6 = 0,
    };

    pub fn init() Framebuffer {
        return .{
            .id = 0,
            .width = 0,
            .height = 0,
            .pitch = 0,
            .format = .xrgb8888,
            .gem_handle = -1,
            .offset = 0,
            .size = 0,
            .flags = .{},
            .ref_count = 0,
            .active = false,
        };
    }

    pub fn calc_size(width: u32, height: u32, format: PixelFormat) u64 {
        const bpp: u64 = @intCast(format.bpp());
        const pitch = (width * bpp + 7) / 8;
        // Align pitch to 64 bytes for GPU requirements
        const aligned_pitch = (pitch + 63) & ~@as(u64, 63);
        return aligned_pitch * @as(u64, height);
    }
};

// ─────────────────── GEM Buffer Object ──────────────────────────────

pub const GemObject = struct {
    handle: u32,
    size: u64,
    phys_addr: u64,
    // Mapping
    mapped: bool,
    map_count: u16,
    // Pinned (prevent migration)
    pinned: bool,
    pin_count: u16,
    // Domain
    domain: GemDomain,
    // Name for sharing
    flink_name: u32,
    active: bool,

    pub const GemDomain = enum(u8) {
        cpu = 0,
        gtt = 1,
        vram = 2,
    };

    pub fn init() GemObject {
        return .{
            .handle = 0,
            .size = 0,
            .phys_addr = 0,
            .mapped = false,
            .map_count = 0,
            .pinned = false,
            .pin_count = 0,
            .domain = .cpu,
            .flink_name = 0,
            .active = false,
        };
    }
};

// ─────────────────── Atomic State ───────────────────────────────────

pub const AtomicState = struct {
    // Per-CRTC changes
    crtc_active: [MAX_CRTCS]bool,
    crtc_mode_changed: [MAX_CRTCS]bool,
    crtc_fb: [MAX_CRTCS]i16,
    // Per-connector changes
    conn_crtc: [MAX_CONNECTORS]i16,
    // Per-plane changes
    plane_fb: [MAX_PLANES]i16,
    plane_crtc: [MAX_PLANES]i16,
    // Flags
    allow_modeset: bool,
    test_only: bool,
    page_flip_async: bool,

    pub fn init() AtomicState {
        var s: AtomicState = undefined;
        for (0..MAX_CRTCS) |i| {
            s.crtc_active[i] = false;
            s.crtc_mode_changed[i] = false;
            s.crtc_fb[i] = -1;
        }
        for (0..MAX_CONNECTORS) |i| s.conn_crtc[i] = -1;
        for (0..MAX_PLANES) |i| {
            s.plane_fb[i] = -1;
            s.plane_crtc[i] = -1;
        }
        s.allow_modeset = false;
        s.test_only = false;
        s.page_flip_async = false;
        return s;
    }
};

// ─────────────────── DRM Device ─────────────────────────────────────

pub const DrmDevice = struct {
    name: [DRM_NAME_LEN]u8,
    name_len: u8,
    crtcs: [MAX_CRTCS]Crtc,
    crtc_count: u8,
    encoders: [MAX_ENCODERS]Encoder,
    encoder_count: u8,
    connectors: [MAX_CONNECTORS]Connector,
    connector_count: u8,
    planes: [MAX_PLANES]Plane,
    plane_count: u8,
    fbs: [MAX_FBS]Framebuffer,
    fb_count: u8,
    gem_objects: [MAX_GEM_OBJECTS]GemObject,
    gem_count: u16,
    next_obj_id: u32,

    // VRAM
    vram_size: u64,
    vram_used: u64,
    gtt_size: u64,
    gtt_used: u64,

    // Stats
    total_flips: u64,
    total_modesets: u64,
    total_vblanks: u64,

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var dev: Self = undefined;
        dev.name = [_]u8{0} ** DRM_NAME_LEN;
        dev.name_len = 0;
        for (0..MAX_CRTCS) |i| dev.crtcs[i] = Crtc.init();
        dev.crtc_count = 0;
        for (0..MAX_ENCODERS) |i| dev.encoders[i] = Encoder.init();
        dev.encoder_count = 0;
        for (0..MAX_CONNECTORS) |i| dev.connectors[i] = Connector.init();
        dev.connector_count = 0;
        for (0..MAX_PLANES) |i| dev.planes[i] = Plane.init();
        dev.plane_count = 0;
        for (0..MAX_FBS) |i| dev.fbs[i] = Framebuffer.init();
        dev.fb_count = 0;
        for (0..MAX_GEM_OBJECTS) |i| dev.gem_objects[i] = GemObject.init();
        dev.gem_count = 0;
        dev.next_obj_id = 1;
        dev.vram_size = 0;
        dev.vram_used = 0;
        dev.gtt_size = 0;
        dev.gtt_used = 0;
        dev.total_flips = 0;
        dev.total_modesets = 0;
        dev.total_vblanks = 0;
        dev.active = false;
        return dev;
    }

    // ─── Object Creation ────────────────────────────────────────────

    pub fn add_crtc(self: *Self) ?u8 {
        if (self.crtc_count >= MAX_CRTCS) return null;
        const idx = self.crtc_count;
        self.crtcs[idx] = Crtc.init();
        self.crtcs[idx].id = self.next_obj_id;
        self.next_obj_id += 1;
        self.crtcs[idx].active = true;
        self.crtc_count += 1;
        return idx;
    }

    pub fn add_encoder(self: *Self, enc_type: EncoderType, possible_crtcs: u8) ?u8 {
        if (self.encoder_count >= MAX_ENCODERS) return null;
        const idx = self.encoder_count;
        self.encoders[idx] = Encoder.init();
        self.encoders[idx].id = self.next_obj_id;
        self.next_obj_id += 1;
        self.encoders[idx].enc_type = enc_type;
        self.encoders[idx].possible_crtcs = possible_crtcs;
        self.encoders[idx].active = true;
        self.encoder_count += 1;
        return idx;
    }

    pub fn add_connector(self: *Self, conn_type: ConnectorType) ?u8 {
        if (self.connector_count >= MAX_CONNECTORS) return null;
        const idx = self.connector_count;
        self.connectors[idx] = Connector.init();
        self.connectors[idx].id = self.next_obj_id;
        self.next_obj_id += 1;
        self.connectors[idx].conn_type = conn_type;
        self.connectors[idx].active = true;
        self.connector_count += 1;
        return idx;
    }

    pub fn add_plane(self: *Self, plane_type: PlaneType, possible_crtcs: u8) ?u8 {
        if (self.plane_count >= MAX_PLANES) return null;
        const idx = self.plane_count;
        self.planes[idx] = Plane.init();
        self.planes[idx].id = self.next_obj_id;
        self.next_obj_id += 1;
        self.planes[idx].plane_type = plane_type;
        self.planes[idx].possible_crtcs = possible_crtcs;
        self.planes[idx].active = true;
        self.plane_count += 1;
        return idx;
    }

    // ─── Framebuffer ────────────────────────────────────────────────

    pub fn create_fb(self: *Self, width: u32, height: u32, format: PixelFormat) ?u8 {
        if (self.fb_count >= MAX_FBS) return null;
        for (0..MAX_FBS) |i| {
            if (!self.fbs[i].active) {
                self.fbs[i] = Framebuffer.init();
                self.fbs[i].id = self.next_obj_id;
                self.next_obj_id += 1;
                self.fbs[i].width = width;
                self.fbs[i].height = height;
                self.fbs[i].format = format;
                const bpp: u32 = @intCast(format.bpp());
                self.fbs[i].pitch = ((width * bpp + 7) / 8 + 63) & ~@as(u32, 63);
                self.fbs[i].size = Framebuffer.calc_size(width, height, format);
                self.fbs[i].ref_count = 1;
                self.fbs[i].active = true;
                self.fb_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn destroy_fb(self: *Self, fb_idx: u8) bool {
        if (fb_idx >= MAX_FBS or !self.fbs[fb_idx].active) return false;
        self.fbs[fb_idx].ref_count -|= 1;
        if (self.fbs[fb_idx].ref_count == 0) {
            self.fbs[fb_idx].active = false;
            self.fb_count -= 1;
        }
        return true;
    }

    // ─── GEM ────────────────────────────────────────────────────────

    pub fn gem_create(self: *Self, size: u64) ?u16 {
        if (self.gem_count >= MAX_GEM_OBJECTS) return null;
        // Check VRAM
        if (self.vram_used + size > self.vram_size and self.vram_size > 0) return null;
        for (0..MAX_GEM_OBJECTS) |i| {
            if (!self.gem_objects[i].active) {
                self.gem_objects[i] = GemObject.init();
                self.gem_objects[i].handle = self.next_obj_id;
                self.next_obj_id += 1;
                self.gem_objects[i].size = size;
                self.gem_objects[i].domain = .vram;
                self.gem_objects[i].active = true;
                self.gem_count += 1;
                self.vram_used += size;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn gem_close(self: *Self, gem_idx: u16) bool {
        if (gem_idx >= MAX_GEM_OBJECTS or !self.gem_objects[gem_idx].active) return false;
        if (self.gem_objects[gem_idx].pinned) return false;
        self.vram_used -|= self.gem_objects[gem_idx].size;
        self.gem_objects[gem_idx].active = false;
        self.gem_count -= 1;
        return true;
    }

    // ─── Modeset ────────────────────────────────────────────────────

    pub fn set_mode(self: *Self, crtc_idx: u8, conn_idx: u8, mode: DisplayMode, fb_idx: u8) bool {
        if (crtc_idx >= self.crtc_count or conn_idx >= self.connector_count) return false;
        if (fb_idx >= MAX_FBS or !self.fbs[fb_idx].active) return false;

        self.crtcs[crtc_idx].mode = mode;
        self.crtcs[crtc_idx].mode_valid = true;
        self.crtcs[crtc_idx].fb_id = @intCast(fb_idx);
        self.crtcs[crtc_idx].enabled = true;
        self.connectors[conn_idx].current_mode = 0;
        self.total_modesets += 1;
        return true;
    }

    pub fn page_flip(self: *Self, crtc_idx: u8, fb_idx: u8) bool {
        if (crtc_idx >= self.crtc_count or !self.crtcs[crtc_idx].enabled) return false;
        if (fb_idx >= MAX_FBS or !self.fbs[fb_idx].active) return false;
        self.crtcs[crtc_idx].fb_id = @intCast(fb_idx);
        self.total_flips += 1;
        return true;
    }

    // ─── VBlank ─────────────────────────────────────────────────────

    pub fn signal_vblank(self: *Self, crtc_idx: u8, tick: u64) void {
        if (crtc_idx >= self.crtc_count) return;
        self.crtcs[crtc_idx].vblank_count += 1;
        self.crtcs[crtc_idx].vblank_time = tick;
        self.total_vblanks += 1;
    }

    // ─── Cursor ─────────────────────────────────────────────────────

    pub fn set_cursor(self: *Self, crtc_idx: u8, fb_idx: i16, x: i32, y: i32) bool {
        if (crtc_idx >= self.crtc_count) return false;
        self.crtcs[crtc_idx].cursor_fb_id = fb_idx;
        self.crtcs[crtc_idx].cursor_x = x;
        self.crtcs[crtc_idx].cursor_y = y;
        self.crtcs[crtc_idx].cursor_visible = fb_idx >= 0;
        return true;
    }

    pub fn move_cursor(self: *Self, crtc_idx: u8, x: i32, y: i32) void {
        if (crtc_idx >= self.crtc_count) return;
        self.crtcs[crtc_idx].cursor_x = x;
        self.crtcs[crtc_idx].cursor_y = y;
    }

    // ─── DPMS ───────────────────────────────────────────────────────

    pub fn set_dpms(self: *Self, conn_idx: u8, state: DpmsState) bool {
        if (conn_idx >= self.connector_count) return false;
        self.connectors[conn_idx].dpms = state;
        return true;
    }

    // ─── Hotplug ────────────────────────────────────────────────────

    pub fn hotplug(self: *Self, conn_idx: u8, connected: bool, tick: u64) void {
        if (conn_idx >= self.connector_count) return;
        self.connectors[conn_idx].status = if (connected) .connected else .disconnected;
        self.connectors[conn_idx].hotplug_count += 1;
        self.connectors[conn_idx].last_hotplug_tick = tick;
        if (!connected) {
            self.connectors[conn_idx].encoder_id = -1;
        }
    }
};

// ─────────────────── DRM Manager ────────────────────────────────────

pub const DrmManager = struct {
    devices: [MAX_DRM_DEVICES]DrmDevice,
    dev_count: u8,
    tick: u64,
    total_registered: u64,
    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var mgr: Self = undefined;
        for (0..MAX_DRM_DEVICES) |i| mgr.devices[i] = DrmDevice.init();
        mgr.dev_count = 0;
        mgr.tick = 0;
        mgr.total_registered = 0;
        mgr.initialized = true;
        return mgr;
    }

    pub fn register_device(self: *Self, name: []const u8, vram_mb: u32) ?u8 {
        for (0..MAX_DRM_DEVICES) |i| {
            if (!self.devices[i].active) {
                self.devices[i] = DrmDevice.init();
                const len = @min(name.len, DRM_NAME_LEN - 1);
                @memcpy(self.devices[i].name[0..len], name[0..len]);
                self.devices[i].name_len = @intCast(len);
                self.devices[i].vram_size = @as(u64, vram_mb) * 1024 * 1024;
                self.devices[i].gtt_size = @as(u64, vram_mb) * 2 * 1024 * 1024;
                self.devices[i].active = true;
                self.dev_count += 1;
                self.total_registered += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn process_vblanks(self: *Self) void {
        self.tick += 1;
        for (0..MAX_DRM_DEVICES) |i| {
            if (self.devices[i].active) {
                for (0..self.devices[i].crtc_count) |c| {
                    if (self.devices[i].crtcs[c].enabled and self.devices[i].crtcs[c].mode_valid) {
                        // Signal vblank at refresh rate intervals
                        const refresh: u64 = @intCast(self.devices[i].crtcs[c].mode.vrefresh);
                        if (refresh > 0 and self.tick % (1000 / refresh) == 0) {
                            self.devices[i].signal_vblank(@intCast(c), self.tick);
                        }
                    }
                }
            }
        }
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_drm: DrmManager = undefined;
var g_drm_init: bool = false;

fn dm() *DrmManager {
    return &g_drm;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_drm_init() void {
    g_drm = DrmManager.init();
    g_drm_init = true;
}

export fn zxy_drm_register(name_ptr: [*]const u8, name_len: usize, vram_mb: u32) i8 {
    if (!g_drm_init) return -1;
    if (dm().register_device(name_ptr[0..name_len], vram_mb)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_drm_add_crtc(dev: u8) i8 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES or !dm().devices[dev].active) return -1;
    if (dm().devices[dev].add_crtc()) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_drm_add_connector(dev: u8, conn_type: u8) i8 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES or !dm().devices[dev].active) return -1;
    if (dm().devices[dev].add_connector(@enumFromInt(conn_type))) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_drm_create_fb(dev: u8, width: u32, height: u32, format: u32) i8 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES or !dm().devices[dev].active) return -1;
    if (dm().devices[dev].create_fb(width, height, @enumFromInt(format))) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_drm_page_flip(dev: u8, crtc: u8, fb: u8) bool {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES) return false;
    return dm().devices[dev].page_flip(crtc, fb);
}

export fn zxy_drm_tick() void {
    if (g_drm_init) dm().process_vblanks();
}

export fn zxy_drm_dev_count() u8 {
    if (!g_drm_init) return 0;
    return dm().dev_count;
}

export fn zxy_drm_total_vblanks(dev: u8) u64 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES) return 0;
    return dm().devices[dev].total_vblanks;
}

export fn zxy_drm_total_flips(dev: u8) u64 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES) return 0;
    return dm().devices[dev].total_flips;
}

export fn zxy_drm_gem_create(dev: u8, size: u64) i16 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES or !dm().devices[dev].active) return -1;
    if (dm().devices[dev].gem_create(size)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_drm_gem_close(dev: u8, gem: u16) bool {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES) return false;
    return dm().devices[dev].gem_close(gem);
}

export fn zxy_drm_vram_used(dev: u8) u64 {
    if (!g_drm_init or dev >= MAX_DRM_DEVICES) return 0;
    return dm().devices[dev].vram_used;
}
