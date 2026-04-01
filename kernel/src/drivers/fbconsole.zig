// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Framebuffer Console
//
// Text-mode console rendered on a linear framebuffer:
// - PSF font rendering (8x16 bitmap font)
// - ANSI escape sequence parser (colors, cursor positioning)
// - Scrollback buffer
// - Text cursor (blinking support)
// - Console I/O (write characters, scroll, clear)
// - Color palette (16 standard + 256 extended)
// - Tab stops, line wrapping
// - VT100/xterm-compatible escape sequences

const std = @import("std");

// ─────────────────── Color Definitions ──────────────────────────────
pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,

    pub fn toArgb32(self: Color) u32 {
        return 0xFF000000 | (@as(u32, self.r) << 16) | (@as(u32, self.g) << 8) | self.b;
    }

    pub fn toBgr32(self: Color) u32 {
        return 0xFF000000 | (@as(u32, self.b) << 16) | (@as(u32, self.g) << 8) | self.r;
    }
};

/// Standard 16-color ANSI palette
pub const ansi_palette = [16]Color{
    .{ .r = 0, .g = 0, .b = 0 },       // 0: Black
    .{ .r = 170, .g = 0, .b = 0 },     // 1: Red
    .{ .r = 0, .g = 170, .b = 0 },     // 2: Green
    .{ .r = 170, .g = 85, .b = 0 },    // 3: Yellow/Brown
    .{ .r = 0, .g = 0, .b = 170 },     // 4: Blue
    .{ .r = 170, .g = 0, .b = 170 },   // 5: Magenta
    .{ .r = 0, .g = 170, .b = 170 },   // 6: Cyan
    .{ .r = 170, .g = 170, .b = 170 }, // 7: White
    .{ .r = 85, .g = 85, .b = 85 },    // 8: Bright Black (Gray)
    .{ .r = 255, .g = 85, .b = 85 },   // 9: Bright Red
    .{ .r = 85, .g = 255, .b = 85 },   // 10: Bright Green
    .{ .r = 255, .g = 255, .b = 85 },  // 11: Bright Yellow
    .{ .r = 85, .g = 85, .b = 255 },   // 12: Bright Blue
    .{ .r = 255, .g = 85, .b = 255 },  // 13: Bright Magenta
    .{ .r = 85, .g = 255, .b = 255 },  // 14: Bright Cyan
    .{ .r = 255, .g = 255, .b = 255 }, // 15: Bright White
};

/// Generate 256-color palette (16 standard + 216 color cube + 24 grayscale)
pub fn color256(idx: u8) Color {
    if (idx < 16) return ansi_palette[idx];

    if (idx < 232) {
        // 6x6x6 color cube
        const ci = idx - 16;
        const b_val: u8 = @as(u8, ci % 6) * 51;
        const g_val: u8 = @as(u8, (ci / 6) % 6) * 51;
        const r_val: u8 = @as(u8, ci / 36) * 51;
        return .{ .r = r_val, .g = g_val, .b = b_val };
    }

    // Grayscale ramp (232-255)
    const gray: u8 = @as(u8, idx - 232) * 10 + 8;
    return .{ .r = gray, .g = gray, .b = gray };
}

// ─────────────────── PSF1 Font ──────────────────────────────────────
pub const FONT_WIDTH = 8;
pub const FONT_HEIGHT = 16;
pub const FONT_GLYPHS = 256;

/// Embedded 8x16 bitmap font (basic ASCII subset)
/// Each glyph is 16 bytes (one byte per row, 8 pixels wide)
pub const default_font: [FONT_GLYPHS * FONT_HEIGHT]u8 = buildDefaultFont();

fn buildDefaultFont() [FONT_GLYPHS * FONT_HEIGHT]u8 {
    var font = [_]u8{0} ** (FONT_GLYPHS * FONT_HEIGHT);

    // Space (32): all zeros, already done

    // '!' (33)
    setGlyph(&font, 33, &[_]u8{
        0b00011000, 0b00011000, 0b00011000, 0b00011000,
        0b00011000, 0b00011000, 0b00011000, 0b00011000,
        0b00011000, 0b00000000, 0b00000000, 0b00011000,
        0b00011000, 0b00000000, 0b00000000, 0b00000000,
    });

    // 'A' (65)
    setGlyph(&font, 65, &[_]u8{
        0b00000000, 0b00011000, 0b00111100, 0b01100110,
        0b01100110, 0b01100110, 0b01111110, 0b01100110,
        0b01100110, 0b01100110, 0b01100110, 0b01100110,
        0b00000000, 0b00000000, 0b00000000, 0b00000000,
    });

    // 'B' (66)
    setGlyph(&font, 66, &[_]u8{
        0b00000000, 0b01111100, 0b01100110, 0b01100110,
        0b01100110, 0b01111100, 0b01100110, 0b01100110,
        0b01100110, 0b01100110, 0b01111100, 0b00000000,
        0b00000000, 0b00000000, 0b00000000, 0b00000000,
    });

    // 'C' (67)
    setGlyph(&font, 67, &[_]u8{
        0b00000000, 0b00111100, 0b01100110, 0b01100000,
        0b01100000, 0b01100000, 0b01100000, 0b01100000,
        0b01100000, 0b01100110, 0b00111100, 0b00000000,
        0b00000000, 0b00000000, 0b00000000, 0b00000000,
    });

    // '0' (48)
    setGlyph(&font, 48, &[_]u8{
        0b00000000, 0b00111100, 0b01100110, 0b01100110,
        0b01101110, 0b01110110, 0b01100110, 0b01100110,
        0b01100110, 0b01100110, 0b00111100, 0b00000000,
        0b00000000, 0b00000000, 0b00000000, 0b00000000,
    });

    // Box drawing character (for borders) at 0xDA
    setGlyph(&font, 0xDA, &[_]u8{
        0b00000000, 0b00000000, 0b00000000, 0b00000000,
        0b00000000, 0b00000000, 0b00000000, 0b00011111,
        0b00011000, 0b00011000, 0b00011000, 0b00011000,
        0b00011000, 0b00011000, 0b00011000, 0b00011000,
    });

    return font;
}

fn setGlyph(font: *[FONT_GLYPHS * FONT_HEIGHT]u8, index: usize, data: *const [FONT_HEIGHT]u8) void {
    const offset = index * FONT_HEIGHT;
    @memcpy(font[offset .. offset + FONT_HEIGHT], data);
}

// ─────────────────── Character Cell ─────────────────────────────────
pub const CharCell = struct {
    ch: u8 = ' ',
    fg: u8 = 7, // white
    bg: u8 = 0, // black
    attrs: CellAttrs = .{},
};

pub const CellAttrs = packed struct {
    bold: bool = false,
    underline: bool = false,
    inverse: bool = false,
    blink: bool = false,
    _reserved: u4 = 0,
};

// ─────────────────── ANSI Parser ────────────────────────────────────
pub const AnsiState = enum(u8) {
    normal = 0,
    escape = 1,   // saw ESC
    csi = 2,      // saw ESC[
    osc = 3,      // saw ESC]
};

pub const MAX_CSI_PARAMS = 8;

pub const AnsiParser = struct {
    state: AnsiState = .normal,
    params: [MAX_CSI_PARAMS]u16 = [_]u16{0} ** MAX_CSI_PARAMS,
    param_count: u8 = 0,
    current_param: u16 = 0,
    have_param: bool = false,
    intermediate: u8 = 0,

    pub fn reset(self: *AnsiParser) void {
        self.state = .normal;
        self.param_count = 0;
        self.current_param = 0;
        self.have_param = false;
        self.intermediate = 0;
    }

    pub fn feed(self: *AnsiParser, ch: u8) ?AnsiAction {
        switch (self.state) {
            .normal => {
                if (ch == 0x1B) {
                    self.state = .escape;
                    return null;
                }
                return AnsiAction{ .print = ch };
            },
            .escape => {
                switch (ch) {
                    '[' => {
                        self.state = .csi;
                        self.param_count = 0;
                        self.current_param = 0;
                        self.have_param = false;
                        return null;
                    },
                    ']' => {
                        self.state = .osc;
                        return null;
                    },
                    'c' => {
                        self.reset();
                        return .reset_terminal;
                    },
                    'D' => {
                        self.state = .normal;
                        return .index_down;
                    },
                    'M' => {
                        self.state = .normal;
                        return .reverse_index;
                    },
                    '7' => {
                        self.state = .normal;
                        return .save_cursor;
                    },
                    '8' => {
                        self.state = .normal;
                        return .restore_cursor;
                    },
                    else => {
                        self.state = .normal;
                        return null;
                    },
                }
            },
            .csi => {
                if (ch >= '0' and ch <= '9') {
                    self.current_param = self.current_param * 10 + (ch - '0');
                    self.have_param = true;
                    return null;
                }
                if (ch == ';') {
                    if (self.param_count < MAX_CSI_PARAMS) {
                        self.params[self.param_count] = if (self.have_param) self.current_param else 0;
                        self.param_count += 1;
                    }
                    self.current_param = 0;
                    self.have_param = false;
                    return null;
                }
                if (ch == '?' or ch == '>' or ch == '!') {
                    self.intermediate = ch;
                    return null;
                }
                // Final character
                if (self.have_param and self.param_count < MAX_CSI_PARAMS) {
                    self.params[self.param_count] = self.current_param;
                    self.param_count += 1;
                }
                self.state = .normal;
                return self.executeCsi(ch);
            },
            .osc => {
                // OSC terminated by BEL (0x07) or ST (ESC \)
                if (ch == 0x07) {
                    self.state = .normal;
                }
                return null;
            },
        }
    }

    fn executeCsi(self: *AnsiParser, ch: u8) ?AnsiAction {
        const p0 = if (self.param_count > 0) self.params[0] else 0;
        const p1 = if (self.param_count > 1) self.params[1] else 0;

        return switch (ch) {
            'A' => AnsiAction{ .cursor_up = @intCast(if (p0 == 0) 1 else p0) },
            'B' => AnsiAction{ .cursor_down = @intCast(if (p0 == 0) 1 else p0) },
            'C' => AnsiAction{ .cursor_right = @intCast(if (p0 == 0) 1 else p0) },
            'D' => AnsiAction{ .cursor_left = @intCast(if (p0 == 0) 1 else p0) },
            'H', 'f' => AnsiAction{ .cursor_position = .{ .row = if (p0 > 0) p0 - 1 else 0, .col = if (p1 > 0) p1 - 1 else 0 } },
            'J' => AnsiAction{ .erase_display = @intCast(p0) },
            'K' => AnsiAction{ .erase_line = @intCast(p0) },
            'L' => AnsiAction{ .insert_lines = @intCast(if (p0 == 0) 1 else p0) },
            'M' => AnsiAction{ .delete_lines = @intCast(if (p0 == 0) 1 else p0) },
            'S' => AnsiAction{ .scroll_up = @intCast(if (p0 == 0) 1 else p0) },
            'T' => AnsiAction{ .scroll_down = @intCast(if (p0 == 0) 1 else p0) },
            'm' => AnsiAction{ .sgr = .{ .params = self.params, .count = self.param_count } },
            's' => .save_cursor,
            'u' => .restore_cursor,
            'n' => if (p0 == 6) .report_cursor else null,
            else => null,
        };
    }
};

pub const AnsiAction = union(enum) {
    print: u8,
    cursor_up: u16,
    cursor_down: u16,
    cursor_left: u16,
    cursor_right: u16,
    cursor_position: struct { row: u16, col: u16 },
    erase_display: u8,
    erase_line: u8,
    insert_lines: u16,
    delete_lines: u16,
    scroll_up: u16,
    scroll_down: u16,
    sgr: struct { params: [MAX_CSI_PARAMS]u16, count: u8 },
    save_cursor,
    restore_cursor,
    reset_terminal,
    index_down,
    reverse_index,
    report_cursor,
};

// ─────────────────── Framebuffer Console ────────────────────────────
pub const MAX_COLS = 200;
pub const MAX_ROWS = 75;
pub const SCROLLBACK_LINES = 500;
pub const TAB_WIDTH = 8;

pub const Console = struct {
    /// Framebuffer info
    fb_addr: [*]u32,
    fb_pitch: u32,  // bytes per line
    fb_width: u32,
    fb_height: u32,

    /// Console dimensions (in characters)
    cols: u16 = 80,
    rows: u16 = 25,

    /// Cursor position
    cursor_x: u16 = 0,
    cursor_y: u16 = 0,
    cursor_visible: bool = true,
    cursor_blink_state: bool = true,

    /// Saved cursor
    saved_x: u16 = 0,
    saved_y: u16 = 0,

    /// Current attributes
    fg_color: u8 = 7,
    bg_color: u8 = 0,
    attrs: CellAttrs = .{},

    /// Screen buffer
    screen: [MAX_ROWS * MAX_COLS]CharCell = [_]CharCell{.{}} ** (MAX_ROWS * MAX_COLS),

    /// Scrollback buffer
    scrollback: [SCROLLBACK_LINES * MAX_COLS]CharCell = [_]CharCell{.{}} ** (SCROLLBACK_LINES * MAX_COLS),
    scrollback_pos: u32 = 0,
    scrollback_count: u32 = 0,
    scroll_offset: u32 = 0, // viewing offset

    /// ANSI parser
    parser: AnsiParser = .{},

    /// Tab stops
    tab_stops: [MAX_COLS]bool = init_tab_stops(),

    /// Stats
    total_chars_written: u64 = 0,

    pub fn init(self: *Console, fb: [*]u32, pitch: u32, width: u32, height: u32) void {
        self.fb_addr = fb;
        self.fb_pitch = pitch;
        self.fb_width = width;
        self.fb_height = height;
        self.cols = @intCast(width / FONT_WIDTH);
        self.rows = @intCast(height / FONT_HEIGHT);
        if (self.cols > MAX_COLS) self.cols = MAX_COLS;
        if (self.rows > MAX_ROWS) self.rows = MAX_ROWS;
        self.clear();
    }

    pub fn clear(self: *Console) void {
        for (&self.screen) |*cell| {
            cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
        self.redrawAll();
    }

    /// Write a string to the console
    pub fn write(self: *Console, data: []const u8) void {
        for (data) |ch| {
            self.writeByte(ch);
        }
    }

    pub fn writeByte(self: *Console, ch: u8) void {
        if (self.parser.feed(ch)) |action| {
            self.executeAction(action);
        }
        self.total_chars_written += 1;
    }

    fn executeAction(self: *Console, action: AnsiAction) void {
        switch (action) {
            .print => |ch| self.putChar(ch),
            .cursor_up => |n| self.moveCursor(0, -@as(i16, @intCast(n))),
            .cursor_down => |n| self.moveCursor(0, @intCast(n)),
            .cursor_left => |n| self.moveCursor(-@as(i16, @intCast(n)), 0),
            .cursor_right => |n| self.moveCursor(@intCast(n), 0),
            .cursor_position => |pos| self.setCursor(pos.col, pos.row),
            .erase_display => |mode| self.eraseDisplay(mode),
            .erase_line => |mode| self.eraseLine(mode),
            .scroll_up => |n| {
                var i: u16 = 0;
                while (i < n) : (i += 1) self.scrollUp();
            },
            .scroll_down => |n| {
                var i: u16 = 0;
                while (i < n) : (i += 1) self.scrollDown();
            },
            .insert_lines => |n| self.insertLines(n),
            .delete_lines => |n| self.deleteLines(n),
            .sgr => |sgr| self.applySgr(sgr.params[0..sgr.count]),
            .save_cursor => {
                self.saved_x = self.cursor_x;
                self.saved_y = self.cursor_y;
            },
            .restore_cursor => {
                self.cursor_x = self.saved_x;
                self.cursor_y = self.saved_y;
            },
            .reset_terminal => self.clear(),
            .index_down => {
                if (self.cursor_y + 1 >= self.rows) {
                    self.scrollUp();
                } else {
                    self.cursor_y += 1;
                }
            },
            .reverse_index => {
                if (self.cursor_y == 0) {
                    self.scrollDown();
                } else {
                    self.cursor_y -= 1;
                }
            },
            .report_cursor => {},
        }
    }

    fn putChar(self: *Console, ch: u8) void {
        switch (ch) {
            '\n' => {
                self.cursor_x = 0;
                if (self.cursor_y + 1 >= self.rows) {
                    self.scrollUp();
                } else {
                    self.cursor_y += 1;
                }
            },
            '\r' => {
                self.cursor_x = 0;
            },
            '\t' => {
                // Advance to next tab stop
                var x = self.cursor_x + 1;
                while (x < self.cols and !self.tab_stops[x]) : (x += 1) {}
                self.cursor_x = if (x >= self.cols) self.cols - 1 else x;
            },
            0x08 => { // Backspace
                if (self.cursor_x > 0) self.cursor_x -= 1;
            },
            0x07 => { // Bell
                // Could trigger audio beep
            },
            else => {
                if (ch >= 0x20) {
                    const idx = @as(usize, self.cursor_y) * MAX_COLS + self.cursor_x;
                    self.screen[idx] = CharCell{
                        .ch = ch,
                        .fg = self.fg_color,
                        .bg = self.bg_color,
                        .attrs = self.attrs,
                    };
                    self.renderChar(self.cursor_x, self.cursor_y, &self.screen[idx]);
                    self.cursor_x += 1;
                    if (self.cursor_x >= self.cols) {
                        self.cursor_x = 0;
                        if (self.cursor_y + 1 >= self.rows) {
                            self.scrollUp();
                        } else {
                            self.cursor_y += 1;
                        }
                    }
                }
            },
        }
    }

    fn scrollUp(self: *Console) void {
        // Save top line to scrollback
        const sb_offset = (self.scrollback_pos % SCROLLBACK_LINES) * MAX_COLS;
        @memcpy(
            self.scrollback[sb_offset .. sb_offset + self.cols],
            self.screen[0..self.cols],
        );
        self.scrollback_pos += 1;
        if (self.scrollback_count < SCROLLBACK_LINES) {
            self.scrollback_count += 1;
        }

        // Shift all lines up
        var y: u16 = 0;
        while (y + 1 < self.rows) : (y += 1) {
            const dst_off = @as(usize, y) * MAX_COLS;
            const src_off = @as(usize, y + 1) * MAX_COLS;
            @memcpy(
                self.screen[dst_off .. dst_off + self.cols],
                self.screen[src_off .. src_off + self.cols],
            );
        }

        // Clear bottom line
        const last_off = @as(usize, self.rows - 1) * MAX_COLS;
        for (self.screen[last_off .. last_off + self.cols]) |*cell| {
            cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
        }

        self.redrawAll();
    }

    fn scrollDown(self: *Console) void {
        var y: u16 = self.rows - 1;
        while (y > 0) : (y -= 1) {
            const dst_off = @as(usize, y) * MAX_COLS;
            const src_off = @as(usize, y - 1) * MAX_COLS;
            @memcpy(
                self.screen[dst_off .. dst_off + self.cols],
                self.screen[src_off .. src_off + self.cols],
            );
        }
        // Clear top line
        for (self.screen[0..self.cols]) |*cell| {
            cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
        }
        self.redrawAll();
    }

    fn insertLines(self: *Console, count: u16) void {
        var i: u16 = 0;
        while (i < count) : (i += 1) {
            var y: u16 = self.rows - 1;
            while (y > self.cursor_y) : (y -= 1) {
                const dst = @as(usize, y) * MAX_COLS;
                const src = @as(usize, y - 1) * MAX_COLS;
                @memcpy(self.screen[dst .. dst + self.cols], self.screen[src .. src + self.cols]);
            }
            const cur = @as(usize, self.cursor_y) * MAX_COLS;
            for (self.screen[cur .. cur + self.cols]) |*cell| {
                cell.* = CharCell{};
            }
        }
        self.redrawAll();
    }

    fn deleteLines(self: *Console, count: u16) void {
        var i: u16 = 0;
        while (i < count) : (i += 1) {
            var y: u16 = self.cursor_y;
            while (y + 1 < self.rows) : (y += 1) {
                const dst = @as(usize, y) * MAX_COLS;
                const src = @as(usize, y + 1) * MAX_COLS;
                @memcpy(self.screen[dst .. dst + self.cols], self.screen[src .. src + self.cols]);
            }
            const last = @as(usize, self.rows - 1) * MAX_COLS;
            for (self.screen[last .. last + self.cols]) |*cell| {
                cell.* = CharCell{};
            }
        }
        self.redrawAll();
    }

    fn moveCursor(self: *Console, dx: i16, dy: i16) void {
        var new_x = @as(i32, self.cursor_x) + dx;
        var new_y = @as(i32, self.cursor_y) + dy;
        if (new_x < 0) new_x = 0;
        if (new_y < 0) new_y = 0;
        if (new_x >= self.cols) new_x = self.cols - 1;
        if (new_y >= self.rows) new_y = self.rows - 1;
        self.cursor_x = @intCast(new_x);
        self.cursor_y = @intCast(new_y);
    }

    fn setCursor(self: *Console, x: u16, y: u16) void {
        self.cursor_x = if (x >= self.cols) self.cols - 1 else x;
        self.cursor_y = if (y >= self.rows) self.rows - 1 else y;
    }

    fn eraseDisplay(self: *Console, mode: u8) void {
        switch (mode) {
            0 => {
                // Erase from cursor to end
                const start = @as(usize, self.cursor_y) * MAX_COLS + self.cursor_x;
                const end = @as(usize, self.rows) * MAX_COLS;
                for (self.screen[start..end]) |*cell| {
                    cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
                }
            },
            1 => {
                // Erase from start to cursor
                const end = @as(usize, self.cursor_y) * MAX_COLS + self.cursor_x + 1;
                for (self.screen[0..end]) |*cell| {
                    cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
                }
            },
            2, 3 => {
                // Erase entire display
                for (&self.screen) |*cell| {
                    cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
                }
                if (mode == 3) {
                    self.scrollback_count = 0;
                    self.scrollback_pos = 0;
                }
            },
            else => {},
        }
        self.redrawAll();
    }

    fn eraseLine(self: *Console, mode: u8) void {
        const row_start = @as(usize, self.cursor_y) * MAX_COLS;
        switch (mode) {
            0 => { // cursor to end
                for (self.screen[row_start + self.cursor_x .. row_start + self.cols]) |*cell| {
                    cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
                }
            },
            1 => { // start to cursor
                for (self.screen[row_start .. row_start + self.cursor_x + 1]) |*cell| {
                    cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
                }
            },
            2 => { // entire line
                for (self.screen[row_start .. row_start + self.cols]) |*cell| {
                    cell.* = CharCell{ .fg = self.fg_color, .bg = self.bg_color };
                }
            },
            else => {},
        }
        // Redraw this line
        var x: u16 = 0;
        while (x < self.cols) : (x += 1) {
            self.renderChar(x, self.cursor_y, &self.screen[row_start + x]);
        }
    }

    fn applySgr(self: *Console, params: []const u16) void {
        if (params.len == 0) {
            self.fg_color = 7;
            self.bg_color = 0;
            self.attrs = .{};
            return;
        }

        var i: usize = 0;
        while (i < params.len) : (i += 1) {
            const p = params[i];
            switch (p) {
                0 => { // Reset
                    self.fg_color = 7;
                    self.bg_color = 0;
                    self.attrs = .{};
                },
                1 => self.attrs.bold = true,
                4 => self.attrs.underline = true,
                5 => self.attrs.blink = true,
                7 => self.attrs.inverse = true,
                22 => self.attrs.bold = false,
                24 => self.attrs.underline = false,
                25 => self.attrs.blink = false,
                27 => self.attrs.inverse = false,
                30...37 => self.fg_color = @intCast(p - 30),
                38 => {
                    // 256-color mode: ESC[38;5;Nm
                    if (i + 2 < params.len and params[i + 1] == 5) {
                        self.fg_color = @intCast(params[i + 2]);
                        i += 2;
                    }
                },
                39 => self.fg_color = 7, // default fg
                40...47 => self.bg_color = @intCast(p - 40),
                48 => {
                    if (i + 2 < params.len and params[i + 1] == 5) {
                        self.bg_color = @intCast(params[i + 2]);
                        i += 2;
                    }
                },
                49 => self.bg_color = 0, // default bg
                90...97 => self.fg_color = @intCast(p - 90 + 8),
                100...107 => self.bg_color = @intCast(p - 100 + 8),
                else => {},
            }
        }
    }

    /// Render a single character cell to the framebuffer
    fn renderChar(self: *Console, cx: u16, cy: u16, cell: *const CharCell) void {
        var fg_idx = cell.fg;
        var bg_idx = cell.bg;
        if (cell.attrs.inverse) {
            const tmp = fg_idx;
            fg_idx = bg_idx;
            bg_idx = tmp;
        }
        if (cell.attrs.bold and fg_idx < 8) {
            fg_idx += 8;
        }

        const fg = color256(fg_idx).toArgb32();
        const bg = color256(bg_idx).toArgb32();

        const glyph_offset = @as(usize, cell.ch) * FONT_HEIGHT;
        const px = @as(usize, cx) * FONT_WIDTH;
        const py = @as(usize, cy) * FONT_HEIGHT;
        const pitch_pixels = self.fb_pitch / 4;

        var row: usize = 0;
        while (row < FONT_HEIGHT) : (row += 1) {
            const glyph_row = default_font[glyph_offset + row];
            const fb_y = (py + row) * pitch_pixels + px;

            var col: u3 = 0;
            while (col < FONT_WIDTH) : (col += 1) {
                const bit = (glyph_row >> (7 - col)) & 1;
                self.fb_addr[fb_y + col] = if (bit != 0) fg else bg;
            }

            // Underline: draw on second-to-last row
            if (cell.attrs.underline and row == FONT_HEIGHT - 2) {
                var ux: u3 = 0;
                while (ux < FONT_WIDTH) : (ux += 1) {
                    self.fb_addr[fb_y + ux] = fg;
                }
            }
        }
    }

    fn redrawAll(self: *Console) void {
        var y: u16 = 0;
        while (y < self.rows) : (y += 1) {
            var x: u16 = 0;
            while (x < self.cols) : (x += 1) {
                const idx = @as(usize, y) * MAX_COLS + x;
                self.renderChar(x, y, &self.screen[idx]);
            }
        }
    }

    /// Render cursor block
    pub fn drawCursor(self: *Console) void {
        if (!self.cursor_visible or !self.cursor_blink_state) return;

        const px = @as(usize, self.cursor_x) * FONT_WIDTH;
        const py = @as(usize, self.cursor_y) * FONT_HEIGHT;
        const pitch_pixels = self.fb_pitch / 4;
        const fg = color256(self.fg_color).toArgb32();

        // Draw underline cursor
        var col: usize = 0;
        while (col < FONT_WIDTH) : (col += 1) {
            const y1 = (py + FONT_HEIGHT - 2) * pitch_pixels + px + col;
            const y2 = (py + FONT_HEIGHT - 1) * pitch_pixels + px + col;
            self.fb_addr[y1] = fg;
            self.fb_addr[y2] = fg;
        }
    }

    pub fn toggleCursorBlink(self: *Console) void {
        self.cursor_blink_state = !self.cursor_blink_state;
        // Redraw cursor position
        const idx = @as(usize, self.cursor_y) * MAX_COLS + self.cursor_x;
        self.renderChar(self.cursor_x, self.cursor_y, &self.screen[idx]);
        if (self.cursor_blink_state) {
            self.drawCursor();
        }
    }
};

fn init_tab_stops() [MAX_COLS]bool {
    var tabs = [_]bool{false} ** MAX_COLS;
    var i: usize = 0;
    while (i < MAX_COLS) : (i += TAB_WIDTH) {
        tabs[i] = true;
    }
    return tabs;
}

// ─────────────────── Global Instance ────────────────────────────────
var console_instance: Console = .{
    .fb_addr = undefined,
    .fb_pitch = 0,
    .fb_width = 0,
    .fb_height = 0,
};

pub fn getConsole() *Console {
    return &console_instance;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_fbcon_init(fb: [*]u32, pitch: u32, width: u32, height: u32) void {
    console_instance.init(fb, pitch, width, height);
}

export fn zxy_fbcon_write(data: [*]const u8, len: u32) void {
    if (len > 0) {
        console_instance.write(data[0..len]);
    }
}

export fn zxy_fbcon_clear() void {
    console_instance.clear();
}

export fn zxy_fbcon_set_cursor(x: u16, y: u16) void {
    console_instance.setCursor(x, y);
}

export fn zxy_fbcon_cursor_blink() void {
    console_instance.toggleCursorBlink();
}

export fn zxy_fbcon_cols() u16 {
    return console_instance.cols;
}

export fn zxy_fbcon_rows() u16 {
    return console_instance.rows;
}
