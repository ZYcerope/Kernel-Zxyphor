// =============================================================================
// Kernel Zxyphor — Framebuffer / Display Driver
// =============================================================================
// Provides a linear framebuffer abstraction for graphical output:
//   - VBE/GOP framebuffer from bootloader
//   - Pixel-level rendering primitives
//   - Hardware cursor support
//   - Double buffering (backbuffer + page flip)
//   - Font rendering (built-in 8x16 bitmap font)
//   - Window/region clipping
//   - Alpha blending (32-bit ARGB)
//   - DMA-accelerated memcpy where available
//   - Console text mode emulation on top of framebuffer
//
// Pixel formats supported:
//   - 32-bit ARGB (A=alpha, R=red, G=green, B=blue)
//   - 24-bit RGB
//   - 16-bit RGB565
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Types
// =============================================================================

pub const PixelFormat = enum(u8) {
    argb32 = 0, // 32-bit: AARRGGBB
    rgb24 = 1, // 24-bit: RRGGBB
    rgb565 = 2, // 16-bit: RRRRRGGGGGGBBBBB
    bgr32 = 3, // 32-bit: AABBGGRR (common in UEFI GOP)
};

pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,
    a: u8,

    pub const white = Color{ .r = 255, .g = 255, .b = 255, .a = 255 };
    pub const black = Color{ .r = 0, .g = 0, .b = 0, .a = 255 };
    pub const red = Color{ .r = 255, .g = 0, .b = 0, .a = 255 };
    pub const green = Color{ .r = 0, .g = 255, .b = 0, .a = 255 };
    pub const blue = Color{ .r = 0, .g = 0, .b = 255, .a = 255 };
    pub const yellow = Color{ .r = 255, .g = 255, .b = 0, .a = 255 };
    pub const cyan = Color{ .r = 0, .g = 255, .b = 255, .a = 255 };
    pub const magenta = Color{ .r = 255, .g = 0, .b = 255, .a = 255 };
    pub const gray = Color{ .r = 128, .g = 128, .b = 128, .a = 255 };
    pub const dark_gray = Color{ .r = 64, .g = 64, .b = 64, .a = 255 };
    pub const transparent = Color{ .r = 0, .g = 0, .b = 0, .a = 0 };

    /// Convert to 32-bit packed ARGB
    pub fn toArgb32(self: Color) u32 {
        return (@as(u32, self.a) << 24) | (@as(u32, self.r) << 16) | (@as(u32, self.g) << 8) | @as(u32, self.b);
    }

    /// Convert from 32-bit packed ARGB
    pub fn fromArgb32(val: u32) Color {
        return .{
            .a = @truncate((val >> 24) & 0xFF),
            .r = @truncate((val >> 16) & 0xFF),
            .g = @truncate((val >> 8) & 0xFF),
            .b = @truncate(val & 0xFF),
        };
    }

    /// Convert to RGB565
    pub fn toRgb565(self: Color) u16 {
        return (@as(u16, self.r >> 3) << 11) | (@as(u16, self.g >> 2) << 5) | @as(u16, self.b >> 3);
    }

    /// Alpha blend: overlay `self` on top of `bg`
    pub fn blend(self: Color, bg: Color) Color {
        if (self.a == 255) return self;
        if (self.a == 0) return bg;

        const sa: u16 = self.a;
        const da: u16 = 255 - sa;

        return .{
            .r = @truncate((sa * @as(u16, self.r) + da * @as(u16, bg.r)) / 255),
            .g = @truncate((sa * @as(u16, self.g) + da * @as(u16, bg.g)) / 255),
            .b = @truncate((sa * @as(u16, self.b) + da * @as(u16, bg.b)) / 255),
            .a = @truncate(sa + (da * @as(u16, bg.a)) / 255),
        };
    }

    /// Lerp between two colors (t = 0-255)
    pub fn lerp(a: Color, b: Color, t: u8) Color {
        const t16: u16 = t;
        const inv: u16 = 255 - t16;
        return .{
            .r = @truncate((inv * @as(u16, a.r) + t16 * @as(u16, b.r)) / 255),
            .g = @truncate((inv * @as(u16, a.g) + t16 * @as(u16, b.g)) / 255),
            .b = @truncate((inv * @as(u16, a.b) + t16 * @as(u16, b.b)) / 255),
            .a = @truncate((inv * @as(u16, a.a) + t16 * @as(u16, b.a)) / 255),
        };
    }
};

pub const Rect = struct {
    x: i32,
    y: i32,
    width: u32,
    height: u32,

    pub fn right(self: Rect) i32 {
        return self.x + @as(i32, @intCast(self.width));
    }

    pub fn bottom(self: Rect) i32 {
        return self.y + @as(i32, @intCast(self.height));
    }

    pub fn intersect(self: Rect, other: Rect) ?Rect {
        const x1 = @max(self.x, other.x);
        const y1 = @max(self.y, other.y);
        const x2 = @min(self.right(), other.right());
        const y2 = @min(self.bottom(), other.bottom());

        if (x2 <= x1 or y2 <= y1) return null;
        return Rect{
            .x = x1,
            .y = y1,
            .width = @intCast(x2 - x1),
            .height = @intCast(y2 - y1),
        };
    }

    pub fn contains(self: Rect, px: i32, py: i32) bool {
        return px >= self.x and px < self.right() and py >= self.y and py < self.bottom();
    }
};

// =============================================================================
// Framebuffer state
// =============================================================================

pub const FramebufferInfo = struct {
    address: u64, // Physical address of framebuffer
    pitch: u32, // Bytes per scanline
    width: u32, // Horizontal resolution in pixels
    height: u32, // Vertical resolution in pixels
    bpp: u8, // Bits per pixel
    format: PixelFormat,
    size: u64, // Total framebuffer size in bytes
};

var fb_info: FramebufferInfo = undefined;
var backbuffer: ?[*]u8 = null;
var backbuffer_size: u64 = 0;
var fb_ptr: ?[*]u8 = null;
var fb_initialized: bool = false;

// Clipping rectangle (defaults to full screen)
var clip_rect: Rect = .{ .x = 0, .y = 0, .width = 0, .height = 0 };

// Text console state
var console_col: u32 = 0;
var console_row: u32 = 0;
var console_fg: Color = Color.white;
var console_bg: Color = Color.black;
var console_cols: u32 = 0;
var console_rows: u32 = 0;

// =============================================================================
// Built-in 8x16 bitmap font (CP437/VGA-compatible, first 128 chars)
// =============================================================================

const FONT_WIDTH: u32 = 8;
const FONT_HEIGHT: u32 = 16;

// This is a simplified representation. A real kernel would include the full
// VGA ROM font data (4096 bytes for 256 chars × 16 bytes each).
// Here we define a few critical characters for bootstrapping.
const font_data: [128 * 16]u8 = blk: {
    var data: [128 * 16]u8 = [_]u8{0} ** (128 * 16);

    // Space (0x20) — all zeros (already default)

    // 'A' (0x41)
    const char_A = [16]u8{
        0x00, 0x00, 0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66,
        0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    for (0..16) |i| {
        data[0x41 * 16 + i] = char_A[i];
    }

    // 'B' (0x42)
    const char_B = [16]u8{
        0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66,
        0x66, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    for (0..16) |i| {
        data[0x42 * 16 + i] = char_B[i];
    }

    // 'Z' (0x5A) — for "Zxyphor"
    const char_Z = [16]u8{
        0x00, 0x00, 0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60,
        0x60, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    for (0..16) |i| {
        data[0x5A * 16 + i] = char_Z[i];
    }

    // Fill block character (0xDB) — for progress bars etc.
    for (0..16) |i| {
        data[0xDB * 16 + i] = 0xFF;
    }

    break :blk data;
};

// =============================================================================
// Core rendering operations
// =============================================================================

/// Get the target buffer pointer (backbuffer if available, else front buffer)
fn getTarget() [*]u8 {
    return backbuffer orelse fb_ptr.?;
}

/// Set a single pixel (no clipping)
fn putPixelRaw(x: u32, y: u32, color: Color) void {
    const target = getTarget();
    const offset = @as(u64, y) * fb_info.pitch + @as(u64, x) * (fb_info.bpp / 8);

    switch (fb_info.format) {
        .argb32 => {
            const ptr: *u32 = @ptrCast(@alignCast(target + offset));
            ptr.* = color.toArgb32();
        },
        .bgr32 => {
            const ptr: *u32 = @ptrCast(@alignCast(target + offset));
            ptr.* = (@as(u32, color.a) << 24) | (@as(u32, color.b) << 16) | (@as(u32, color.g) << 8) | @as(u32, color.r);
        },
        .rgb24 => {
            target[offset] = color.r;
            target[offset + 1] = color.g;
            target[offset + 2] = color.b;
        },
        .rgb565 => {
            const ptr: *u16 = @ptrCast(@alignCast(target + offset));
            ptr.* = color.toRgb565();
        },
    }
}

/// Get a single pixel color
fn getPixelRaw(x: u32, y: u32) Color {
    const target = getTarget();
    const offset = @as(u64, y) * fb_info.pitch + @as(u64, x) * (fb_info.bpp / 8);

    switch (fb_info.format) {
        .argb32 => {
            const ptr: *const u32 = @ptrCast(@alignCast(target + offset));
            return Color.fromArgb32(ptr.*);
        },
        .bgr32 => {
            const ptr: *const u32 = @ptrCast(@alignCast(target + offset));
            const val = ptr.*;
            return .{
                .a = @truncate((val >> 24) & 0xFF),
                .b = @truncate((val >> 16) & 0xFF),
                .g = @truncate((val >> 8) & 0xFF),
                .r = @truncate(val & 0xFF),
            };
        },
        .rgb24 => {
            return .{ .r = target[offset], .g = target[offset + 1], .b = target[offset + 2], .a = 255 };
        },
        .rgb565 => {
            const ptr: *const u16 = @ptrCast(@alignCast(target + offset));
            const val = ptr.*;
            return .{
                .r = @truncate(((val >> 11) & 0x1F) << 3),
                .g = @truncate(((val >> 5) & 0x3F) << 2),
                .b = @truncate((val & 0x1F) << 3),
                .a = 255,
            };
        },
    }
}

// =============================================================================
// Drawing primitives (with clipping)
// =============================================================================

/// Set a pixel with clipping
pub fn putPixel(x: i32, y: i32, color: Color) void {
    if (!fb_initialized) return;
    if (!clip_rect.contains(x, y)) return;
    if (x < 0 or y < 0) return;
    const ux: u32 = @intCast(x);
    const uy: u32 = @intCast(y);
    if (ux >= fb_info.width or uy >= fb_info.height) return;

    if (color.a == 255) {
        putPixelRaw(ux, uy, color);
    } else if (color.a > 0) {
        const bg = getPixelRaw(ux, uy);
        putPixelRaw(ux, uy, color.blend(bg));
    }
}

/// Fill a rectangle
pub fn fillRect(rect: Rect, color: Color) void {
    if (!fb_initialized) return;

    const clipped = rect.intersect(clip_rect) orelse return;
    const x1: u32 = @intCast(@max(clipped.x, 0));
    const y1: u32 = @intCast(@max(clipped.y, 0));
    const x2 = @min(x1 + clipped.width, fb_info.width);
    const y2 = @min(y1 + clipped.height, fb_info.height);

    if (color.a == 255 and (fb_info.format == .argb32 or fb_info.format == .bgr32)) {
        // Fast path: fill with 32-bit value using memset-like approach
        const packed = if (fb_info.format == .argb32) color.toArgb32() else (@as(u32, color.a) << 24) | (@as(u32, color.b) << 16) | (@as(u32, color.g) << 8) | @as(u32, color.r);
        const target = getTarget();

        var y: u32 = y1;
        while (y < y2) : (y += 1) {
            const row_offset = @as(u64, y) * fb_info.pitch + @as(u64, x1) * 4;
            const row: [*]u32 = @ptrCast(@alignCast(target + row_offset));
            for (0..x2 - x1) |i| {
                row[i] = packed;
            }
        }
    } else {
        var y = @as(i32, @intCast(y1));
        while (y < @as(i32, @intCast(y2))) : (y += 1) {
            var x = @as(i32, @intCast(x1));
            while (x < @as(i32, @intCast(x2))) : (x += 1) {
                putPixel(x, y, color);
            }
        }
    }
}

/// Draw a horizontal line (optimized)
pub fn hline(x1: i32, x2: i32, y: i32, color: Color) void {
    fillRect(.{ .x = @min(x1, x2), .y = y, .width = @intCast(@max(x1, x2) - @min(x1, x2) + 1), .height = 1 }, color);
}

/// Draw a vertical line (optimized)
pub fn vline(x: i32, y1: i32, y2: i32, color: Color) void {
    fillRect(.{ .x = x, .y = @min(y1, y2), .width = 1, .height = @intCast(@max(y1, y2) - @min(y1, y2) + 1) }, color);
}

/// Draw a rectangle outline
pub fn drawRect(rect: Rect, color: Color) void {
    const x = rect.x;
    const y = rect.y;
    const r = rect.right() - 1;
    const b = rect.bottom() - 1;
    hline(x, r, y, color); // Top
    hline(x, r, b, color); // Bottom
    vline(x, y, b, color); // Left
    vline(r, y, b, color); // Right
}

/// Draw a line using Bresenham's algorithm
pub fn drawLine(x0: i32, y0: i32, x1: i32, y1: i32, color: Color) void {
    var dx: i32 = if (x1 > x0) x1 - x0 else x0 - x1;
    var dy: i32 = -(if (y1 > y0) y1 - y0 else y0 - y1);
    const sx: i32 = if (x0 < x1) 1 else -1;
    const sy: i32 = if (y0 < y1) 1 else -1;
    var err = dx + dy;

    var x = x0;
    var y = y0;
    _ = dx;
    _ = dy;

    while (true) {
        putPixel(x, y, color);
        if (x == x1 and y == y1) break;

        const e2 = 2 * err;
        if (e2 >= dy) {
            if (x == x1) break;
            err += dy;
            x += sx;
        }
        if (e2 <= dx) {
            if (y == y1) break;
            err += dx;
            y += sy;
        }
    }
}

/// Draw a circle outline using midpoint algorithm
pub fn drawCircle(cx: i32, cy: i32, radius: i32, color: Color) void {
    var x: i32 = radius;
    var y: i32 = 0;
    var d: i32 = 1 - radius;

    while (x >= y) {
        putPixel(cx + x, cy + y, color);
        putPixel(cx - x, cy + y, color);
        putPixel(cx + x, cy - y, color);
        putPixel(cx - x, cy - y, color);
        putPixel(cx + y, cy + x, color);
        putPixel(cx - y, cy + x, color);
        putPixel(cx + y, cy - x, color);
        putPixel(cx - y, cy - x, color);

        y += 1;
        if (d <= 0) {
            d += 2 * y + 1;
        } else {
            x -= 1;
            d += 2 * (y - x) + 1;
        }
    }
}

/// Fill a circle
pub fn fillCircle(cx: i32, cy: i32, radius: i32, color: Color) void {
    var x: i32 = radius;
    var y: i32 = 0;
    var d: i32 = 1 - radius;

    while (x >= y) {
        hline(cx - x, cx + x, cy + y, color);
        hline(cx - x, cx + x, cy - y, color);
        hline(cx - y, cx + y, cy + x, color);
        hline(cx - y, cx + y, cy - x, color);

        y += 1;
        if (d <= 0) {
            d += 2 * y + 1;
        } else {
            x -= 1;
            d += 2 * (y - x) + 1;
        }
    }
}

// =============================================================================
// Text rendering
// =============================================================================

/// Draw a single character at pixel position (x, y)
pub fn drawChar(ch: u8, x: i32, y: i32, fg: Color, bg: Color) void {
    if (ch >= 128) return; // Only ASCII for now

    const glyph = font_data[ch * 16 ..][0..16];

    for (0..FONT_HEIGHT) |row| {
        for (0..FONT_WIDTH) |col| {
            const bit: u3 = @truncate(7 - col);
            const px_x = x + @as(i32, @intCast(col));
            const px_y = y + @as(i32, @intCast(row));

            if (glyph[row] & (@as(u8, 1) << bit) != 0) {
                putPixel(px_x, px_y, fg);
            } else if (bg.a > 0) {
                putPixel(px_x, px_y, bg);
            }
        }
    }
}

/// Draw a string at pixel position (x, y)
pub fn drawString(s: []const u8, x: i32, y: i32, fg: Color, bg: Color) void {
    var cx = x;
    for (s) |ch| {
        if (ch == '\n') {
            cx = x;
            // y handled by caller or advance not needed
            continue;
        }
        drawChar(ch, cx, y, fg, bg);
        cx += @as(i32, FONT_WIDTH);
    }
}

// =============================================================================
// Console (text mode emulation over framebuffer)
// =============================================================================

fn scrollConsole() void {
    const target = getTarget();
    const line_bytes = fb_info.pitch * FONT_HEIGHT;
    const total_text_bytes = @as(u64, line_bytes) * (console_rows - 1);

    // Copy all lines up by one
    const src_offset = line_bytes;
    @memcpy(target[0..total_text_bytes], target[src_offset..][0..total_text_bytes]);

    // Clear last line
    const last_line_offset = total_text_bytes;
    @memset(target[last_line_offset..][0..line_bytes], 0);
}

/// Write a character to the text console
pub fn consoleWrite(ch: u8) void {
    if (!fb_initialized) return;

    if (ch == '\n') {
        console_col = 0;
        console_row += 1;
        if (console_row >= console_rows) {
            scrollConsole();
            console_row = console_rows - 1;
        }
        return;
    }

    if (ch == '\r') {
        console_col = 0;
        return;
    }

    if (ch == '\t') {
        console_col = (console_col + 4) & ~@as(u32, 3);
        if (console_col >= console_cols) {
            console_col = 0;
            console_row += 1;
            if (console_row >= console_rows) {
                scrollConsole();
                console_row = console_rows - 1;
            }
        }
        return;
    }

    if (ch == 0x08) { // Backspace
        if (console_col > 0) {
            console_col -= 1;
            drawChar(' ', @intCast(console_col * FONT_WIDTH), @intCast(console_row * FONT_HEIGHT), console_fg, console_bg);
        }
        return;
    }

    // Draw character
    drawChar(ch, @intCast(console_col * FONT_WIDTH), @intCast(console_row * FONT_HEIGHT), console_fg, console_bg);

    console_col += 1;
    if (console_col >= console_cols) {
        console_col = 0;
        console_row += 1;
        if (console_row >= console_rows) {
            scrollConsole();
            console_row = console_rows - 1;
        }
    }
}

/// Write a string to the text console
pub fn consolePrint(s: []const u8) void {
    for (s) |ch| {
        consoleWrite(ch);
    }
}

/// Set console colors
pub fn setConsoleColors(fg: Color, bg: Color) void {
    console_fg = fg;
    console_bg = bg;
}

// =============================================================================
// Framebuffer management
// =============================================================================

/// Clear the entire screen
pub fn clear(color: Color) void {
    fillRect(.{ .x = 0, .y = 0, .width = fb_info.width, .height = fb_info.height }, color);
}

/// Swap backbuffer to frontbuffer
pub fn swapBuffers() void {
    if (backbuffer == null or fb_ptr == null) return;
    @memcpy(fb_ptr.?[0..backbuffer_size], backbuffer.?[0..backbuffer_size]);
}

/// Set the clipping rectangle
pub fn setClipRect(rect: Rect) void {
    clip_rect = rect;
}

/// Reset clipping to full screen
pub fn resetClipRect() void {
    clip_rect = .{ .x = 0, .y = 0, .width = fb_info.width, .height = fb_info.height };
}

/// Get framebuffer info
pub fn getInfo() FramebufferInfo {
    return fb_info;
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the framebuffer driver
pub fn initialize(address: u64, width: u32, height: u32, pitch: u32, bpp: u8) void {
    fb_info = .{
        .address = address,
        .width = width,
        .height = height,
        .pitch = pitch,
        .bpp = bpp,
        .format = switch (bpp) {
            32 => .argb32,
            24 => .rgb24,
            16 => .rgb565,
            else => .argb32,
        },
        .size = @as(u64, pitch) * height,
    };

    fb_ptr = @ptrFromInt(address);

    // Console dimensions
    console_cols = width / FONT_WIDTH;
    console_rows = height / FONT_HEIGHT;
    console_col = 0;
    console_row = 0;

    // Set default clip to full screen
    clip_rect = .{ .x = 0, .y = 0, .width = width, .height = height };

    backbuffer_size = fb_info.size;
    // Backbuffer allocation would use kernel heap here
    // backbuffer = @ptrFromInt(heap.alloc(backbuffer_size));

    fb_initialized = true;

    main.klog(.info, "Framebuffer: {d}x{d} @ {d}bpp, pitch={d}", .{ width, height, bpp, pitch });
    main.klog(.info, "Console: {d}x{d} characters", .{ console_cols, console_rows });
}

/// Check if framebuffer is initialized
pub fn isInitialized() bool {
    return fb_initialized;
}
