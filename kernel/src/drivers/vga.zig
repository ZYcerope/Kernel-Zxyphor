// =============================================================================
// Kernel Zxyphor - VGA Text Mode Driver
// =============================================================================
// Provides output to the standard 80x25 VGA text mode framebuffer.
// The VGA text buffer is memory-mapped at physical address 0xB8000.
// Each character cell is 2 bytes: [ASCII char][attribute byte].
//
// Attribute byte format:
//   Bits 0-3: Foreground color
//   Bits 4-6: Background color
//   Bit 7:    Blink (or bright background, depending on VGA mode)
//
// This driver supports:
//   - Colored text output with 16 foreground and 8 background colors
//   - Cursor positioning (via VGA CRTC registers)
//   - Scrolling
//   - Basic ANSI-like escape sequences (optional)
//   - Tab expansion
//   - Screen clearing
//   - Backspace
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// VGA constants
// =============================================================================
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;
const VGA_BUFFER_ADDR: usize = 0xB8000;
const VGA_BUFFER_SIZE: usize = VGA_WIDTH * VGA_HEIGHT;
const TAB_WIDTH: usize = 8;

// VGA CRT Controller registers (via port I/O)
const VGA_CRTC_ADDR: u16 = 0x3D4;
const VGA_CRTC_DATA: u16 = 0x3D5;
const VGA_CURSOR_HIGH: u8 = 0x0E;
const VGA_CURSOR_LOW: u8 = 0x0F;
const VGA_CURSOR_START: u8 = 0x0A;
const VGA_CURSOR_END: u8 = 0x0B;

// =============================================================================
// Color definitions (standard VGA palette)
// =============================================================================
pub const Color = enum(u4) {
    black = 0,
    blue = 1,
    green = 2,
    cyan = 3,
    red = 4,
    magenta = 5,
    brown = 6,
    light_gray = 7,
    dark_gray = 8,
    light_blue = 9,
    light_green = 10,
    light_cyan = 11,
    light_red = 12,
    light_magenta = 13,
    yellow = 14,
    white = 15,
};

// =============================================================================
// State
// =============================================================================
var column: usize = 0;
var row: usize = 0;
var color_attr: u8 = makeColor(.light_gray, .black);
var buffer: [*]volatile u16 = undefined;
var vga_initialized: bool = false;

// Scroll-back buffer (stores last N lines)
const SCROLLBACK_LINES: usize = 200;
var scrollback: [SCROLLBACK_LINES][VGA_WIDTH]u16 = undefined;
var scrollback_pos: usize = 0;
var scrollback_count: usize = 0;

// =============================================================================
// Initialize VGA
// =============================================================================
pub fn initialize() void {
    buffer = @ptrFromInt(VGA_BUFFER_ADDR);

    // Clear scrollback buffer
    for (&scrollback) |*line| {
        @memset(line, makeEntry(' ', color_attr));
    }

    // Clear screen
    clear();

    // Enable cursor (scanline 14-15 for underline cursor)
    enableCursor(14, 15);

    vga_initialized = true;
}

// =============================================================================
// Color management
// =============================================================================
pub fn makeColor(fg: Color, bg: Color) u8 {
    return @as(u8, @intFromEnum(fg)) | (@as(u8, @intFromEnum(bg)) << 4);
}

fn makeEntry(char: u8, attr: u8) u16 {
    return @as(u16, char) | (@as(u16, attr) << 8);
}

pub fn setColor(fg: Color, bg: Color) void {
    color_attr = makeColor(fg, bg);
}

pub fn setColorAttr(attr: u8) void {
    color_attr = attr;
}

pub fn getColor() u8 {
    return color_attr;
}

// =============================================================================
// Cursor management
// =============================================================================
fn enableCursor(start: u8, end: u8) void {
    main.cpu.outb(VGA_CRTC_ADDR, VGA_CURSOR_START);
    main.cpu.outb(VGA_CRTC_DATA, (main.cpu.inb(VGA_CRTC_DATA) & 0xC0) | start);
    main.cpu.outb(VGA_CRTC_ADDR, VGA_CURSOR_END);
    main.cpu.outb(VGA_CRTC_DATA, (main.cpu.inb(VGA_CRTC_DATA) & 0xE0) | end);
}

pub fn disableCursor() void {
    main.cpu.outb(VGA_CRTC_ADDR, VGA_CURSOR_START);
    main.cpu.outb(VGA_CRTC_DATA, 0x20); // Bit 5 disables cursor
}

fn updateCursor() void {
    const pos: u16 = @intCast(row * VGA_WIDTH + column);
    main.cpu.outb(VGA_CRTC_ADDR, VGA_CURSOR_LOW);
    main.cpu.outb(VGA_CRTC_DATA, @truncate(pos));
    main.cpu.outb(VGA_CRTC_ADDR, VGA_CURSOR_HIGH);
    main.cpu.outb(VGA_CRTC_DATA, @truncate(pos >> 8));
}

pub fn setCursorPos(r: usize, c: usize) void {
    row = @min(r, VGA_HEIGHT - 1);
    column = @min(c, VGA_WIDTH - 1);
    updateCursor();
}

pub fn getCursorPos() struct { row: usize, col: usize } {
    return .{ .row = row, .col = column };
}

// =============================================================================
// Screen operations
// =============================================================================
pub fn clear() void {
    const blank = makeEntry(' ', color_attr);
    var i: usize = 0;
    while (i < VGA_BUFFER_SIZE) : (i += 1) {
        buffer[i] = blank;
    }
    row = 0;
    column = 0;
    updateCursor();
}

pub fn clearLine(r: usize) void {
    if (r >= VGA_HEIGHT) return;
    const blank = makeEntry(' ', color_attr);
    const start = r * VGA_WIDTH;
    var i: usize = 0;
    while (i < VGA_WIDTH) : (i += 1) {
        buffer[start + i] = blank;
    }
}

fn scroll() void {
    // Save the top line to scrollback
    var saved: [VGA_WIDTH]u16 = undefined;
    var k: usize = 0;
    while (k < VGA_WIDTH) : (k += 1) {
        saved[k] = buffer[k];
    }
    scrollback[scrollback_pos] = saved;
    scrollback_pos = (scrollback_pos + 1) % SCROLLBACK_LINES;
    if (scrollback_count < SCROLLBACK_LINES) scrollback_count += 1;

    // Move all rows up by one
    var i: usize = 0;
    while (i < (VGA_HEIGHT - 1) * VGA_WIDTH) : (i += 1) {
        buffer[i] = buffer[i + VGA_WIDTH];
    }

    // Clear the bottom row
    const blank = makeEntry(' ', color_attr);
    i = (VGA_HEIGHT - 1) * VGA_WIDTH;
    while (i < VGA_BUFFER_SIZE) : (i += 1) {
        buffer[i] = blank;
    }
}

// =============================================================================
// Character output
// =============================================================================
pub fn writeChar(ch: u8) void {
    switch (ch) {
        '\n' => newline(),
        '\r' => {
            column = 0;
        },
        '\t' => {
            // Expand to next tab stop
            const next_tab = ((column / TAB_WIDTH) + 1) * TAB_WIDTH;
            while (column < next_tab and column < VGA_WIDTH) {
                putChar(' ');
            }
        },
        0x08 => backspace(), // Backspace
        else => putChar(ch),
    }
    updateCursor();
}

fn putChar(ch: u8) void {
    buffer[row * VGA_WIDTH + column] = makeEntry(ch, color_attr);
    column += 1;
    if (column >= VGA_WIDTH) {
        column = 0;
        row += 1;
        if (row >= VGA_HEIGHT) {
            scroll();
            row = VGA_HEIGHT - 1;
        }
    }
}

fn newline() void {
    column = 0;
    row += 1;
    if (row >= VGA_HEIGHT) {
        scroll();
        row = VGA_HEIGHT - 1;
    }
}

pub fn backspace() void {
    if (column > 0) {
        column -= 1;
        buffer[row * VGA_WIDTH + column] = makeEntry(' ', color_attr);
    } else if (row > 0) {
        row -= 1;
        column = VGA_WIDTH - 1;
        buffer[row * VGA_WIDTH + column] = makeEntry(' ', color_attr);
    }
}

// =============================================================================
// String output
// =============================================================================
pub fn writeString(str: []const u8) void {
    for (str) |ch| {
        writeChar(ch);
    }
}

/// Write a string at a specific position with a specific color
pub fn writeAt(r: usize, c: usize, str: []const u8, attr: u8) void {
    if (r >= VGA_HEIGHT) return;
    var col = c;
    for (str) |ch| {
        if (col >= VGA_WIDTH) break;
        buffer[r * VGA_WIDTH + col] = makeEntry(ch, attr);
        col += 1;
    }
}

// =============================================================================
// Writer interface (for formatted printing via klog)
// =============================================================================
pub const writer = Writer{};

pub const Writer = struct {
    pub fn writeAll(self: Writer, bytes: []const u8) error{}!void {
        _ = self;
        writeString(bytes);
    }

    pub fn writeBytesNTimes(self: Writer, bytes: []const u8, n: usize) error{}!void {
        _ = self;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            writeString(bytes);
        }
    }
};

// =============================================================================
// Status bar (bottom line of screen)
// =============================================================================
pub fn drawStatusBar(text: []const u8) void {
    const status_row = VGA_HEIGHT - 1;
    const attr = makeColor(.black, .light_gray);

    // Clear the status line
    var i: usize = 0;
    while (i < VGA_WIDTH) : (i += 1) {
        buffer[status_row * VGA_WIDTH + i] = makeEntry(' ', attr);
    }

    // Write text
    const len = @min(text.len, VGA_WIDTH);
    i = 0;
    while (i < len) : (i += 1) {
        buffer[status_row * VGA_WIDTH + i] = makeEntry(text[i], attr);
    }
}

// =============================================================================
// Colored text helpers
// =============================================================================
pub fn writeColored(str: []const u8, fg: Color, bg: Color) void {
    const old_color = color_attr;
    color_attr = makeColor(fg, bg);
    writeString(str);
    color_attr = old_color;
}

pub fn writeOk(str: []const u8) void {
    writeColored(str, .light_green, .black);
}

pub fn writeError(str: []const u8) void {
    writeColored(str, .light_red, .black);
}

pub fn writeWarning(str: []const u8) void {
    writeColored(str, .yellow, .black);
}

pub fn writeInfo(str: []const u8) void {
    writeColored(str, .light_cyan, .black);
}
