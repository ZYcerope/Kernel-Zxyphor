// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced GPU Driver Framework
// DRM/KMS, GPU command submission, memory management, display pipeline
const std = @import("std");

// ============================================================================
// Display / KMS (Kernel Mode Setting)
// ============================================================================

pub const MaxConnectors: usize = 8;
pub const MaxCrtcs: usize = 4;
pub const MaxPlanes: usize = 16;
pub const MaxEncoders: usize = 8;
pub const MaxModes: usize = 64;
pub const MaxFramebuffers: usize = 32;
pub const MaxProperties: usize = 128;

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
    din_9pin = 9,
    dp = 10,
    hdmi_a = 11,
    hdmi_b = 12,
    tv = 13,
    edp = 14,
    virtual_display = 15,
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

pub const DpmsMode = enum(u8) {
    on = 0,
    standby = 1,
    suspend = 2,
    off = 3,
};

pub const DisplayMode = struct {
    clock_khz: u32 = 0,
    hdisplay: u16 = 0,
    hsync_start: u16 = 0,
    hsync_end: u16 = 0,
    htotal: u16 = 0,
    hskew: u16 = 0,
    vdisplay: u16 = 0,
    vsync_start: u16 = 0,
    vsync_end: u16 = 0,
    vtotal: u16 = 0,
    vscan: u16 = 0,
    vrefresh: u32 = 0,
    flags: u32 = 0,
    mode_type: u32 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,

    pub const MODE_FLAG_PHSYNC: u32 = 1 << 0;
    pub const MODE_FLAG_NHSYNC: u32 = 1 << 1;
    pub const MODE_FLAG_PVSYNC: u32 = 1 << 2;
    pub const MODE_FLAG_NVSYNC: u32 = 1 << 3;
    pub const MODE_FLAG_INTERLACE: u32 = 1 << 4;
    pub const MODE_FLAG_DBLSCAN: u32 = 1 << 5;
    pub const MODE_FLAG_CSYNC: u32 = 1 << 6;
    pub const MODE_TYPE_PREFERRED: u32 = 1 << 3;
    pub const MODE_TYPE_DRIVER: u32 = 1 << 6;

    pub fn pixelRate(self: *const DisplayMode) u64 {
        return @as(u64, self.clock_khz) * 1000;
    }

    pub fn bandwidth(self: *const DisplayMode, bpp: u8) u64 {
        return self.pixelRate() * @as(u64, bpp) / 8;
    }
};

pub const Connector = struct {
    id: u32,
    connector_type: ConnectorType = .unknown,
    status: ConnectorStatus = .unknown,
    dpms: DpmsMode = .on,
    encoder_id: u32 = 0,
    modes: [MaxModes]DisplayMode = [_]DisplayMode{DisplayMode{}} ** MaxModes,
    mode_count: u8 = 0,
    // Physical
    mm_width: u32 = 0,
    mm_height: u32 = 0,
    subpixel: SubpixelOrder = .unknown,
    // EDID
    edid: [256]u8 = [_]u8{0} ** 256,
    edid_len: u16 = 0,
    // HPD
    hpd_enabled: bool = false,
    // Properties
    properties: [32]Property = [_]Property{Property{}} ** 32,
    prop_count: u8 = 0,
};

pub const SubpixelOrder = enum(u8) {
    unknown = 0,
    horizontal_rgb = 1,
    horizontal_bgr = 2,
    vertical_rgb = 3,
    vertical_bgr = 4,
    none = 5,
};

pub const Encoder = struct {
    id: u32,
    encoder_type: EncoderType = .none,
    crtc_id: u32 = 0,
    possible_crtcs: u32 = 0,
    possible_clones: u32 = 0,
};

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

pub const Crtc = struct {
    id: u32,
    active: bool = false,
    mode: DisplayMode = DisplayMode{},
    mode_valid: bool = false,
    // Position
    x: i32 = 0,
    y: i32 = 0,
    // Primary framebuffer
    fb_id: u32 = 0,
    // Gamma
    gamma_size: u32 = 256,
    gamma_lut: [256]GammaEntry = [_]GammaEntry{GammaEntry{}} ** 256,
    // VBlank
    vblank_count: u64 = 0,
    vblank_ns: u64 = 0,
    // State
    enabled: bool = false,
    self_refresh: bool = false,
};

pub const GammaEntry = struct {
    red: u16 = 0,
    green: u16 = 0,
    blue: u16 = 0,
};

pub const PlaneType = enum(u8) {
    overlay = 0,
    primary = 1,
    cursor = 2,
};

pub const Plane = struct {
    id: u32,
    plane_type: PlaneType = .overlay,
    possible_crtcs: u32 = 0,
    crtc_id: u32 = 0,
    fb_id: u32 = 0,
    // Source rectangle (16.16 fixed point)
    src_x: u32 = 0,
    src_y: u32 = 0,
    src_w: u32 = 0,
    src_h: u32 = 0,
    // Destination rectangle
    crtc_x: i32 = 0,
    crtc_y: i32 = 0,
    crtc_w: u32 = 0,
    crtc_h: u32 = 0,
    // Rotation
    rotation: u8 = 0,
    // Alpha
    alpha: u16 = 0xFFFF,
    // Pixel blend mode
    blend_mode: BlendMode = .premulti,
    // Formats
    formats: [32]PixelFormat = [_]PixelFormat{.argb8888} ** 32,
    format_count: u8 = 0,
    // Properties
    zpos: i32 = 0,
};

pub const BlendMode = enum(u8) {
    none = 0,
    premulti = 1,
    coverage = 2,
};

pub const PixelFormat = enum(u32) {
    c8 = 0x20203843,
    rgb332 = 0x38424752,
    bgr233 = 0x38524742,
    xrgb4444 = 0x32315258,
    xbgr4444 = 0x32314258,
    argb4444 = 0x32315241,
    abgr4444 = 0x32314241,
    xrgb1555 = 0x35315258,
    xbgr1555 = 0x35314258,
    argb1555 = 0x35315241,
    abgr1555 = 0x35314241,
    rgb565 = 0x36314752,
    bgr565 = 0x36314742,
    rgb888 = 0x34324752,
    bgr888 = 0x34324742,
    xrgb8888 = 0x34325258,
    xbgr8888 = 0x34324258,
    argb8888 = 0x34325241,
    abgr8888 = 0x34324241,
    xrgb2101010 = 0x30335258,
    xbgr2101010 = 0x30334258,
    argb2101010 = 0x30335241,
    abgr2101010 = 0x30334241,
    // YUV
    yuyv = 0x56595559,
    yvyu = 0x55595659,
    uyvy = 0x59565955,
    vyuy = 0x59555956,
    nv12 = 0x3231564E,
    nv21 = 0x3132564E,
    nv16 = 0x3631564E,
    // HDR
    xrgb16161616f = 0x48345258,
    argb16161616f = 0x48345241,
};

pub const Property = struct {
    id: u32 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    prop_type: PropertyType = .range,
    value: u64 = 0,
    range_min: u64 = 0,
    range_max: u64 = 0,
    flags: u32 = 0,
};

pub const PropertyType = enum(u8) {
    range = 0,
    enum_type = 1,
    blob = 2,
    bitmask = 3,
    object = 4,
    signed_range = 5,
};

// ============================================================================
// Framebuffer
// ============================================================================

pub const Framebuffer = struct {
    id: u32,
    width: u32 = 0,
    height: u32 = 0,
    format: PixelFormat = .argb8888,
    flags: u32 = 0,
    // Per-plane
    pitches: [4]u32 = [_]u32{0} ** 4,
    offsets: [4]u32 = [_]u32{0} ** 4,
    handles: [4]u32 = [_]u32{0} ** 4, // GEM handles
    modifier: u64 = 0,
    // Backing memory
    gem_obj: u32 = 0,
    vaddr: usize = 0,
    size: usize = 0,
    // Status
    ref_count: u32 = 1,
    pinned: bool = false,

    pub const FB_FLAG_INTERLACED: u32 = 1 << 0;
    pub const FB_FLAG_MODIFIERS: u32 = 1 << 1;

    pub fn bytesPerPixel(self: *const Framebuffer) u8 {
        return switch (self.format) {
            .c8, .rgb332, .bgr233 => 1,
            .xrgb4444, .xbgr4444, .argb4444, .abgr4444, .xrgb1555, .xbgr1555, .argb1555, .abgr1555, .rgb565, .bgr565 => 2,
            .rgb888, .bgr888 => 3,
            .xrgb8888, .xbgr8888, .argb8888, .abgr8888, .xrgb2101010, .xbgr2101010, .argb2101010, .abgr2101010, .yuyv, .yvyu, .uyvy, .vyuy => 4,
            .nv12, .nv21, .nv16 => 2, // Approximate
            .xrgb16161616f, .argb16161616f => 8,
        };
    }

    pub fn totalSize(self: *const Framebuffer) usize {
        return @as(usize, self.pitches[0]) * @as(usize, self.height);
    }
};

// ============================================================================
// GPU Memory Management (GEM/TTM-like)
// ============================================================================

pub const GemObject = struct {
    handle: u32,
    size: usize,
    vaddr: usize = 0,
    paddr: usize = 0,
    domain: MemDomain = .cpu,
    tiling: TilingMode = .none,
    ref_count: u32 = 1,
    name: u32 = 0, // flink name
    flags: u32 = 0,
    // GPU virtual address
    gpu_vaddr: u64 = 0,
    gpu_mapped: bool = false,
    // Caching
    cache_level: CacheLevel = .cached,
    // Fence
    read_fence: u64 = 0,
    write_fence: u64 = 0,
    // DMA-buf
    dmabuf_fd: i32 = -1,
};

pub const MemDomain = enum(u8) {
    cpu = 0,
    gtt = 1,    // Graphics Translation Table
    vram = 2,
    system = 3,
};

pub const TilingMode = enum(u8) {
    none = 0,
    x_tiled = 1,
    y_tiled = 2,
    y_tiled_ccs = 3,
    tile4 = 4,     // Intel DG2+
    tile64 = 5,
};

pub const CacheLevel = enum(u8) {
    uncached = 0,
    write_combining = 1,
    cached = 2,
    display = 3,
};

pub const GpuMemManager = struct {
    objects: [1024]GemObject = undefined,
    obj_count: u32 = 0,
    next_handle: u32 = 1,
    // VRAM
    vram_size: u64 = 0,
    vram_used: u64 = 0,
    vram_base: u64 = 0,
    // GTT
    gtt_size: u64 = 0,
    gtt_used: u64 = 0,
    gtt_base: u64 = 0,
    // Stats
    total_allocs: u64 = 0,
    total_frees: u64 = 0,
    peak_vram: u64 = 0,
    
    pub fn init(vram_size: u64, gtt_size: u64) GpuMemManager {
        return GpuMemManager{
            .vram_size = vram_size,
            .gtt_size = gtt_size,
        };
    }

    pub fn createObject(self: *GpuMemManager, size: usize, flags: u32) ?u32 {
        if (self.obj_count >= 1024) return null;
        
        const handle = self.next_handle;
        self.next_handle += 1;
        const idx = self.obj_count;
        self.obj_count += 1;
        
        self.objects[idx] = GemObject{
            .handle = handle,
            .size = size,
            .flags = flags,
        };
        
        self.total_allocs += 1;
        return handle;
    }

    pub fn destroyObject(self: *GpuMemManager, handle: u32) bool {
        var i: u32 = 0;
        while (i < self.obj_count) : (i += 1) {
            if (self.objects[i].handle == handle) {
                if (self.objects[i].domain == .vram) {
                    self.vram_used -= self.objects[i].size;
                }
                // Shift
                var j = i;
                while (j + 1 < self.obj_count) : (j += 1) {
                    self.objects[j] = self.objects[j + 1];
                }
                self.obj_count -= 1;
                self.total_frees += 1;
                return true;
            }
        }
        return false;
    }

    pub fn pinToVram(self: *GpuMemManager, handle: u32) bool {
        var i: u32 = 0;
        while (i < self.obj_count) : (i += 1) {
            if (self.objects[i].handle == handle) {
                if (self.vram_used + self.objects[i].size > self.vram_size) {
                    return false; // OOM
                }
                self.objects[i].domain = .vram;
                self.objects[i].paddr = self.vram_base + self.vram_used;
                self.vram_used += self.objects[i].size;
                if (self.vram_used > self.peak_vram) {
                    self.peak_vram = self.vram_used;
                }
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// GPU Command Submission
// ============================================================================

pub const GpuRingType = enum(u8) {
    render = 0,
    blitter = 1,
    video = 2,
    video_enhance = 3,
    compute = 4,
};

pub const GpuCommand = struct {
    opcode: u32 = 0,
    length: u16 = 0,
    flags: u16 = 0,
    data: [60]u32 = [_]u32{0} ** 60,

    pub fn batchBufferStart(addr: u64, flags: u32) GpuCommand {
        var cmd = GpuCommand{};
        cmd.opcode = 0x18800001; // MI_BATCH_BUFFER_START
        cmd.length = 3;
        cmd.data[0] = @intCast(addr & 0xFFFFFFFF);
        cmd.data[1] = @intCast(addr >> 32);
        cmd.data[2] = flags;
        return cmd;
    }

    pub fn pipeControl(flags: u32, addr: u64, imm: u64) GpuCommand {
        var cmd = GpuCommand{};
        cmd.opcode = 0x7A000004; // PIPE_CONTROL
        cmd.length = 6;
        cmd.data[0] = flags;
        cmd.data[1] = @intCast(addr & 0xFFFFFFFF);
        cmd.data[2] = @intCast(addr >> 32);
        cmd.data[3] = @intCast(imm & 0xFFFFFFFF);
        cmd.data[4] = @intCast(imm >> 32);
        return cmd;
    }

    pub fn noop() GpuCommand {
        return GpuCommand{ .opcode = 0x00000000, .length = 1 };
    }
};

pub const GpuRing = struct {
    ring_type: GpuRingType = .render,
    base_addr: u64 = 0,
    size: u32 = 0,
    head: u32 = 0,
    tail: u32 = 0,
    // Fence tracking
    last_submitted_fence: u64 = 0,
    last_completed_fence: u64 = 0,
    // Commands waiting
    pending_commands: [256]GpuCommand = undefined,
    pending_count: u32 = 0,
    // Active
    active: bool = false,
    idle: bool = true,
    // Stats
    total_submitted: u64 = 0,
    total_completed: u64 = 0,
    gpu_busy_ns: u64 = 0,
    
    pub fn submit(self: *GpuRing, cmd: *const GpuCommand) bool {
        if (self.pending_count >= 256 or !self.active) return false;
        self.pending_commands[self.pending_count] = cmd.*;
        self.pending_count += 1;
        self.total_submitted += 1;
        self.idle = false;
        return true;
    }
    
    pub fn flush(self: *GpuRing) u64 {
        self.last_submitted_fence += 1;
        self.pending_count = 0;
        return self.last_submitted_fence;
    }
    
    pub fn isFenceComplete(self: *const GpuRing, fence: u64) bool {
        return self.last_completed_fence >= fence;
    }
};

// ============================================================================ 
// DRM Device
// ============================================================================

pub const DrmDevice = struct {
    // Resources
    connectors: [MaxConnectors]Connector = undefined,
    connector_count: u8 = 0,
    crtcs: [MaxCrtcs]Crtc = undefined,
    crtc_count: u8 = 0,
    planes: [MaxPlanes]Plane = undefined,
    plane_count: u8 = 0,
    encoders: [MaxEncoders]Encoder = undefined,
    encoder_count: u8 = 0,
    framebuffers: [MaxFramebuffers]Framebuffer = undefined,
    fb_count: u8 = 0,
    // GPU
    mem: GpuMemManager = GpuMemManager.init(0, 0),
    rings: [5]GpuRing = [_]GpuRing{GpuRing{}} ** 5,
    ring_count: u8 = 0,
    // Info
    driver_name: [32]u8 = [_]u8{0} ** 32,
    driver_name_len: u8 = 0,
    driver_version: [3]u32 = [_]u32{0} ** 3,
    pci_vendor: u16 = 0,
    pci_device: u16 = 0,
    // Caps
    dumb_buffer: bool = true,
    vblank_high_crtc: bool = true,
    prime: bool = true,
    async_page_flip: bool = false,
    atomic_modeset: bool = true,
    // Next IDs
    next_id: u32 = 1,

    pub fn allocId(self: *DrmDevice) u32 {
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    pub fn addConnector(self: *DrmDevice, ctype: ConnectorType) ?u32 {
        if (self.connector_count >= MaxConnectors) return null;
        const id = self.allocId();
        const idx = self.connector_count;
        self.connector_count += 1;
        self.connectors[idx] = Connector{ .id = id, .connector_type = ctype };
        return id;
    }

    pub fn addCrtc(self: *DrmDevice) ?u32 {
        if (self.crtc_count >= MaxCrtcs) return null;
        const id = self.allocId();
        const idx = self.crtc_count;
        self.crtc_count += 1;
        self.crtcs[idx] = Crtc{ .id = id };
        return id;
    }

    pub fn addPlane(self: *DrmDevice, ptype: PlaneType, possible_crtcs: u32) ?u32 {
        if (self.plane_count >= MaxPlanes) return null;
        const id = self.allocId();
        const idx = self.plane_count;
        self.plane_count += 1;
        self.planes[idx] = Plane{
            .id = id,
            .plane_type = ptype,
            .possible_crtcs = possible_crtcs,
        };
        return id;
    }

    pub fn createFramebuffer(self: *DrmDevice, width: u32, height: u32, format: PixelFormat) ?u32 {
        if (self.fb_count >= MaxFramebuffers) return null;
        const id = self.allocId();
        const idx = self.fb_count;
        self.fb_count += 1;
        var fb = &self.framebuffers[idx];
        fb.* = Framebuffer{ .id = id };
        fb.width = width;
        fb.height = height;
        fb.format = format;
        fb.pitches[0] = width * @as(u32, fb.bytesPerPixel());
        fb.size = @as(usize, fb.pitches[0]) * @as(usize, height);
        return id;
    }

    /// Atomic modeset commit
    pub fn atomicCommit(self: *DrmDevice, crtc_idx: u8, connector_idx: u8, mode: *const DisplayMode, fb_id: u32) bool {
        if (crtc_idx >= self.crtc_count or connector_idx >= self.connector_count) return false;
        
        var crtc = &self.crtcs[crtc_idx];
        var connector = &self.connectors[connector_idx];
        
        if (connector.status != .connected) return false;
        
        crtc.mode = mode.*;
        crtc.mode_valid = true;
        crtc.active = true;
        crtc.enabled = true;
        crtc.fb_id = fb_id;
        
        // Set encoder
        if (self.encoder_count > 0) {
            connector.encoder_id = self.encoders[0].id;
            self.encoders[0].crtc_id = crtc.id;
        }
        
        connector.dpms = .on;
        return true;
    }
};
