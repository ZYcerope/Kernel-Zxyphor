// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Console & TTY Subsystem (Zig)
//
// Full virtual terminal and TTY layer:
// - TTY line discipline (N_TTY canonical/raw mode)
// - Terminal attributes (termios)
// - Input/output ring buffers with FIFO semantics
// - Console driver abstraction (VGA text, framebuffer, serial)
// - Virtual terminals (VT switching)
// - ANSI/VT100 escape sequence parsing
// - Control character handling (^C, ^D, ^Z, ^S, ^Q)
// - Echo, erase, kill, word-erase
// - Window size (TIOCGWINSZ)
// - Foreground process group (job control)
// - Pseudo-terminal (pty) master/slave pairs

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_TTYS: usize = 16;
const MAX_VTS: usize = 8;
const MAX_PTY_PAIRS: usize = 64;
const INPUT_BUF_SIZE: usize = 4096;
const OUTPUT_BUF_SIZE: usize = 8192;
const MAX_CANON: usize = 255; // Max canonical line length
const LINE_BUF_SIZE: usize = 512;

// ─────────────────── Special Characters ─────────────────────────────

const CTRL_C: u8 = 0x03; // ETX  — SIGINT
const CTRL_D: u8 = 0x04; // EOT  — EOF
const CTRL_H: u8 = 0x08; // BS   — Backspace
const CTRL_Q: u8 = 0x11; // DC1  — XON (resume output)
const CTRL_S: u8 = 0x13; // DC3  — XOFF (pause output)
const CTRL_U: u8 = 0x15; // NAK  — Kill line
const CTRL_W: u8 = 0x17; // ETB  — Word erase
const CTRL_Z: u8 = 0x1A; // SUB  — SIGTSTP
const DEL: u8 = 0x7F; // DEL  — Delete (backspace on most terminals)
const ESC: u8 = 0x1B; // ESC  — Start escape sequence
const LF: u8 = 0x0A; // LF   — Newline
const CR: u8 = 0x0D; // CR   — Carriage return
const TAB: u8 = 0x09; // HT   — Tab

// ─────────────────── TTY Mode Flags ─────────────────────────────────

pub const InputFlags = packed struct {
    icrnl: bool = true, // Map CR to NL on input
    inlcr: bool = false, // Map NL to CR
    igncr: bool = false, // Ignore CR
    istrip: bool = false, // Strip eighth bit
    ixon: bool = true, // Enable XON/XOFF flow control
    ixoff: bool = false,
    iuclc: bool = false, // Map uppercase to lowercase
    _pad: u1 = 0,
};

pub const OutputFlags = packed struct {
    opost: bool = true, // Post-process output
    onlcr: bool = true, // Map NL to CR-NL
    ocrnl: bool = false,
    onocr: bool = false, // No CR output in column 0
    onlret: bool = false,
    ofill: bool = false,
    _pad: u2 = 0,
};

pub const LocalFlags = packed struct {
    echo: bool = true, // Echo input characters
    echoe: bool = true, // Echo erase as BS-SP-BS
    echok: bool = true, // Echo kill line
    echonl: bool = false, // Echo NL even if echo off
    icanon: bool = true, // Canonical (line-buffered) mode
    isig: bool = true, // Enable signals (^C, ^Z)
    iexten: bool = true, // Extended processing
    _pad: u1 = 0,
};

pub const ControlFlags = packed struct {
    csize: u2 = 3, // 0=CS5, 1=CS6, 2=CS7, 3=CS8
    cstopb: bool = false, // 2 stop bits
    cread: bool = true, // Enable receiver
    parenb: bool = false, // Enable parity
    parodd: bool = false, // Odd parity
    hupcl: bool = true, // Hang up on last close
    clocal: bool = false, // Ignore modem control
};

// ─────────────────── Termios ────────────────────────────────────────

pub const Termios = struct {
    iflag: InputFlags = .{},
    oflag: OutputFlags = .{},
    lflag: LocalFlags = .{},
    cflag: ControlFlags = .{},

    // Special characters
    cc_eof: u8 = CTRL_D,
    cc_eol: u8 = 0,
    cc_erase: u8 = DEL,
    cc_intr: u8 = CTRL_C,
    cc_kill: u8 = CTRL_U,
    cc_quit: u8 = 0x1C, // ^\
    cc_susp: u8 = CTRL_Z,
    cc_start: u8 = CTRL_Q,
    cc_stop: u8 = CTRL_S,
    cc_werase: u8 = CTRL_W,
    cc_min: u8 = 1, // MIN for non-canonical
    cc_time: u8 = 0, // TIME for non-canonical (tenths of second)

    // Baud rate
    baud: u32 = 115200,
};

// ─────────────────── Window Size ────────────────────────────────────

pub const WinSize = struct {
    rows: u16 = 25,
    cols: u16 = 80,
    xpixel: u16 = 0,
    ypixel: u16 = 0,
};

// ─────────────────── Ring Buffer ────────────────────────────────────

pub fn RingBuffer(comptime SIZE: usize) type {
    return struct {
        buf: [SIZE]u8 = [_]u8{0} ** SIZE,
        head: usize = 0,
        tail: usize = 0,
        count: usize = 0,

        const Self = @This();

        pub fn push(self: *Self, byte: u8) bool {
            if (self.count >= SIZE) return false;
            self.buf[self.head] = byte;
            self.head = (self.head + 1) % SIZE;
            self.count += 1;
            return true;
        }

        pub fn pop(self: *Self) ?u8 {
            if (self.count == 0) return null;
            const byte = self.buf[self.tail];
            self.tail = (self.tail + 1) % SIZE;
            self.count -= 1;
            return byte;
        }

        pub fn peek(self: *const Self) ?u8 {
            if (self.count == 0) return null;
            return self.buf[self.tail];
        }

        pub fn available(self: *const Self) usize {
            return self.count;
        }

        pub fn free_space(self: *const Self) usize {
            return SIZE - self.count;
        }

        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
            self.count = 0;
        }

        /// Read up to `dst.len` bytes
        pub fn read(self: *Self, dst: []u8) usize {
            var n: usize = 0;
            while (n < dst.len) {
                if (self.pop()) |byte| {
                    dst[n] = byte;
                    n += 1;
                } else break;
            }
            return n;
        }

        /// Write bytes into buffer
        pub fn write(self: *Self, src: []const u8) usize {
            var n: usize = 0;
            while (n < src.len) {
                if (!self.push(src[n])) break;
                n += 1;
            }
            return n;
        }

        /// Remove last pushed byte (for backspace in canonical mode)
        pub fn unpush(self: *Self) bool {
            if (self.count == 0) return false;
            if (self.head == 0) {
                self.head = SIZE - 1;
            } else {
                self.head -= 1;
            }
            self.count -= 1;
            return true;
        }
    };
}

// ─────────────────── TTY State ──────────────────────────────────────

pub const TtyState = enum(u8) {
    closed = 0,
    open = 1,
    stopped = 2, // XOFF
    hung_up = 3,
};

// ─────────────────── Console Backend ────────────────────────────────

pub const ConsoleType = enum(u8) {
    vga_text = 0,
    framebuffer = 1,
    serial = 2,
    null_console = 3,
};

pub const ConsoleOps = struct {
    write_fn: ?*const fn (data: [*]const u8, len: usize) void = null,
    clear_fn: ?*const fn () void = null,
    set_cursor_fn: ?*const fn (row: u16, col: u16) void = null,
    scroll_fn: ?*const fn (lines: u16) void = null,
    set_color_fn: ?*const fn (fg: u8, bg: u8) void = null,
};

// ─────────────────── Escape Sequence Parser ─────────────────────────

pub const EscState = enum(u8) {
    normal = 0,
    escape = 1, // Got ESC
    bracket = 2, // Got ESC[
    param = 3, // Reading parameter digits
    question = 4, // Got ESC[?
};

pub const EscParser = struct {
    state: EscState = .normal,
    params: [8]u16 = [_]u16{0} ** 8,
    param_count: u8 = 0,
    current_param: u16 = 0,

    const Self = @This();

    pub fn reset(self: *Self) void {
        self.state = .normal;
        self.param_count = 0;
        self.current_param = 0;
    }

    /// Feed a byte. Returns true if escape sequence is complete and ready to dispatch
    pub fn feed(self: *Self, c: u8) ?u8 {
        switch (self.state) {
            .normal => {
                if (c == ESC) {
                    self.state = .escape;
                    self.param_count = 0;
                    self.current_param = 0;
                    return null;
                }
                return c;
            },
            .escape => {
                if (c == '[') {
                    self.state = .bracket;
                    return null;
                }
                // Not CSI — treat as unknown and reset
                self.reset();
                return null;
            },
            .bracket => {
                if (c == '?') {
                    self.state = .question;
                    return null;
                }
                self.state = .param;
                return self.handle_param_byte(c);
            },
            .param, .question => {
                return self.handle_param_byte(c);
            },
        }
    }

    fn handle_param_byte(self: *Self, c: u8) ?u8 {
        if (c >= '0' and c <= '9') {
            self.current_param = self.current_param * 10 + (c - '0');
            return null;
        }
        if (c == ';') {
            if (self.param_count < 8) {
                self.params[self.param_count] = self.current_param;
                self.param_count += 1;
            }
            self.current_param = 0;
            return null;
        }
        // Final byte — dispatch command
        if (self.param_count < 8) {
            self.params[self.param_count] = self.current_param;
            self.param_count += 1;
        }
        self.reset();
        // Return the command character (e.g. 'H', 'J', 'm', etc.)
        return null; // Escape fully consumed
    }

    pub fn get_param(self: *const Self, idx: u8, default: u16) u16 {
        if (idx >= self.param_count) return default;
        const v = self.params[idx];
        return if (v == 0) default else v;
    }
};

// ─────────────────── TTY Device ─────────────────────────────────────

pub const Tty = struct {
    // Identity
    index: u8,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,

    // State
    state: TtyState = .closed,
    termios: Termios = .{},
    winsize: WinSize = .{},

    // Buffers
    input_buf: RingBuffer(INPUT_BUF_SIZE) = .{},
    output_buf: RingBuffer(OUTPUT_BUF_SIZE) = .{},

    // Canonical mode line buffer
    line_buf: [LINE_BUF_SIZE]u8 = [_]u8{0} ** LINE_BUF_SIZE,
    line_len: usize = 0,

    // ANSI escape parser
    esc: EscParser = .{},

    // Console backend
    console_type: ConsoleType = .vga_text,
    console_ops: ConsoleOps = .{},

    // Cursor
    cursor_row: u16 = 0,
    cursor_col: u16 = 0,

    // Process group (for signals)
    fg_pgrp: u32 = 0,
    session_id: u32 = 0,

    // Flow control
    stopped: bool = false,

    // Stats
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    signal_count: u64 = 0,

    // PTY linkage (-1 means not a pty)
    pty_peer: i8 = -1,

    const Self = @This();

    pub fn init(idx: u8) Self {
        var t: Self = .{ .index = idx };
        // Set name "tty0", "tty1", etc.
        t.name[0] = 't';
        t.name[1] = 't';
        t.name[2] = 'y';
        t.name[3] = '0' + idx;
        t.name_len = 4;
        return t;
    }

    pub fn open(self: *Self) bool {
        if (self.state != .closed) return false;
        self.state = .open;
        self.input_buf.clear();
        self.output_buf.clear();
        self.line_len = 0;
        self.cursor_row = 0;
        self.cursor_col = 0;
        return true;
    }

    pub fn close(self: *Self) void {
        self.state = .closed;
    }

    /// Receive a character from input (keyboard, serial)
    pub fn receive_char(self: *Self, c: u8) void {
        if (self.state != .open) return;

        // Signal generation (if isig is set)
        if (self.termios.lflag.isig) {
            if (c == self.termios.cc_intr) {
                self.signal_count += 1;
                return; // Would send SIGINT to fg_pgrp
            }
            if (c == self.termios.cc_susp) {
                self.signal_count += 1;
                return; // Would send SIGTSTP
            }
            if (c == self.termios.cc_quit) {
                self.signal_count += 1;
                return; // Would send SIGQUIT
            }
        }

        // Input preprocessing
        var ch = c;
        if (self.termios.iflag.istrip) {
            ch &= 0x7F;
        }
        if (self.termios.iflag.icrnl and ch == CR) {
            ch = LF;
        } else if (self.termios.iflag.inlcr and ch == LF) {
            ch = CR;
        } else if (self.termios.iflag.igncr and ch == CR) {
            return;
        }

        // Flow control
        if (self.termios.iflag.ixon) {
            if (ch == self.termios.cc_stop) {
                self.stopped = true;
                return;
            }
            if (ch == self.termios.cc_start) {
                self.stopped = false;
                return;
            }
        }

        // Canonical mode
        if (self.termios.lflag.icanon) {
            self.canonical_input(ch);
        } else {
            // Raw mode — push directly to input buffer
            _ = self.input_buf.push(ch);
            if (self.termios.lflag.echo) {
                self.echo_char(ch);
            }
        }
    }

    fn canonical_input(self: *Self, c: u8) void {
        // EOF
        if (c == self.termios.cc_eof) {
            // Flush line buffer as-is (empty line = EOF)
            self.flush_line_buf();
            return;
        }

        // Erase (backspace)
        if (c == self.termios.cc_erase or c == CTRL_H) {
            if (self.line_len > 0) {
                self.line_len -= 1;
                if (self.termios.lflag.echoe) {
                    self.echo_erase();
                }
            }
            return;
        }

        // Word erase
        if (c == self.termios.cc_werase) {
            // Erase trailing spaces, then word
            while (self.line_len > 0 and self.line_buf[self.line_len - 1] == ' ') {
                self.line_len -= 1;
                if (self.termios.lflag.echoe) self.echo_erase();
            }
            while (self.line_len > 0 and self.line_buf[self.line_len - 1] != ' ') {
                self.line_len -= 1;
                if (self.termios.lflag.echoe) self.echo_erase();
            }
            return;
        }

        // Kill line
        if (c == self.termios.cc_kill) {
            while (self.line_len > 0) {
                self.line_len -= 1;
                if (self.termios.lflag.echoe) self.echo_erase();
            }
            return;
        }

        // Newline — flush line
        if (c == LF or c == CR) {
            if (self.line_len < LINE_BUF_SIZE) {
                self.line_buf[self.line_len] = LF;
                self.line_len += 1;
            }
            self.flush_line_buf();
            if (self.termios.lflag.echo or self.termios.lflag.echonl) {
                self.echo_char(LF);
            }
            return;
        }

        // Regular character
        if (self.line_len < LINE_BUF_SIZE - 1) {
            self.line_buf[self.line_len] = c;
            self.line_len += 1;
            if (self.termios.lflag.echo) {
                self.echo_char(c);
            }
        }
    }

    fn flush_line_buf(self: *Self) void {
        if (self.line_len == 0) return;
        _ = self.input_buf.write(self.line_buf[0..self.line_len]);
        self.line_len = 0;
    }

    fn echo_char(self: *Self, c: u8) void {
        if (c < 0x20 and c != LF and c != CR and c != TAB) {
            // Echo control character as ^X
            _ = self.output_buf.push('^');
            _ = self.output_buf.push(c + 0x40);
        } else {
            _ = self.output_buf.push(c);
        }
        self.flush_output();
    }

    fn echo_erase(self: *Self) void {
        // BS, space, BS
        _ = self.output_buf.push(CTRL_H);
        _ = self.output_buf.push(' ');
        _ = self.output_buf.push(CTRL_H);
        self.flush_output();
    }

    /// Write data to terminal output
    pub fn write_output(self: *Self, data: []const u8) usize {
        if (self.state != .open or self.stopped) return 0;
        var written: usize = 0;

        for (data) |c| {
            // Output post-processing
            if (self.termios.oflag.opost) {
                if (self.termios.oflag.onlcr and c == LF) {
                    _ = self.output_buf.push(CR);
                    _ = self.output_buf.push(LF);
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    written += 1;
                    continue;
                }
            }
            _ = self.output_buf.push(c);
            self.cursor_col += 1;
            if (self.cursor_col >= self.winsize.cols) {
                self.cursor_col = 0;
                self.cursor_row += 1;
            }
            written += 1;
        }
        self.bytes_written += written;
        self.flush_output();
        return written;
    }

    /// Read data from input buffer (userspace read)
    pub fn read_input(self: *Self, dst: []u8) usize {
        const n = self.input_buf.read(dst);
        self.bytes_read += n;
        return n;
    }

    fn flush_output(self: *Self) void {
        if (self.console_ops.write_fn) |write_fn| {
            var tmp: [256]u8 = undefined;
            while (self.output_buf.available() > 0) {
                const n = self.output_buf.read(&tmp);
                if (n == 0) break;
                write_fn(@ptrCast(&tmp), n);
            }
        }
    }

    pub fn set_winsize(self: *Self, rows: u16, cols: u16) void {
        self.winsize.rows = rows;
        self.winsize.cols = cols;
    }
};

// ─────────────────── PTY Pair ───────────────────────────────────────

pub const PtyPair = struct {
    master_idx: u8,
    slave_idx: u8,
    active: bool,
};

// ─────────────────── Virtual Terminal ────────────────────────────────

pub const VirtualTerminal = struct {
    tty_idx: u8,
    active: bool,
    screen_buf: [80 * 25]u16, // Attribute + char (VGA-style)
    cursor_pos: u16,

    pub fn init(idx: u8) VirtualTerminal {
        return .{
            .tty_idx = idx,
            .active = false,
            .screen_buf = [_]u16{0x0720} ** (80 * 25), // space with grey-on-black
            .cursor_pos = 0,
        };
    }

    pub fn clear(self: *VirtualTerminal) void {
        for (&self.screen_buf) |*cell| {
            cell.* = 0x0720;
        }
        self.cursor_pos = 0;
    }

    pub fn put_char(self: *VirtualTerminal, c: u8, attr: u8) void {
        if (self.cursor_pos >= 80 * 25) {
            self.scroll_up();
        }
        self.screen_buf[self.cursor_pos] = (@as(u16, attr) << 8) | @as(u16, c);
        self.cursor_pos += 1;
    }

    fn scroll_up(self: *VirtualTerminal) void {
        // Move rows 1-24 to 0-23
        var i: usize = 0;
        while (i < 80 * 24) : (i += 1) {
            self.screen_buf[i] = self.screen_buf[i + 80];
        }
        // Clear last row
        while (i < 80 * 25) : (i += 1) {
            self.screen_buf[i] = 0x0720;
        }
        self.cursor_pos = 80 * 24;
    }
};

// ─────────────────── TTY Manager ────────────────────────────────────

pub const TtyManager = struct {
    ttys: [MAX_TTYS]Tty,
    vts: [MAX_VTS]VirtualTerminal,
    pty_pairs: [MAX_PTY_PAIRS]PtyPair,

    active_vt: u8,
    tty_count: u8,
    pty_count: u8,

    total_reads: u64,
    total_writes: u64,

    const Self = @This();

    pub fn init() Self {
        var mgr: Self = undefined;
        for (0..MAX_TTYS) |i| {
            mgr.ttys[i] = Tty.init(@intCast(i));
        }
        for (0..MAX_VTS) |i| {
            mgr.vts[i] = VirtualTerminal.init(@intCast(i));
        }
        for (0..MAX_PTY_PAIRS) |i| {
            mgr.pty_pairs[i] = .{ .master_idx = 0, .slave_idx = 0, .active = false };
        }
        mgr.active_vt = 0;
        mgr.vts[0].active = true;
        mgr.tty_count = MAX_TTYS;
        mgr.pty_count = 0;
        mgr.total_reads = 0;
        mgr.total_writes = 0;
        return mgr;
    }

    pub fn open_tty(self: *Self, idx: u8) bool {
        if (idx >= MAX_TTYS) return false;
        return self.ttys[idx].open();
    }

    pub fn close_tty(self: *Self, idx: u8) void {
        if (idx >= MAX_TTYS) return;
        self.ttys[idx].close();
    }

    pub fn write_tty(self: *Self, idx: u8, data: []const u8) usize {
        if (idx >= MAX_TTYS) return 0;
        const n = self.ttys[idx].write_output(data);
        self.total_writes += n;
        return n;
    }

    pub fn read_tty(self: *Self, idx: u8, buf: []u8) usize {
        if (idx >= MAX_TTYS) return 0;
        const n = self.ttys[idx].read_input(buf);
        self.total_reads += n;
        return n;
    }

    pub fn input_char(self: *Self, idx: u8, c: u8) void {
        if (idx >= MAX_TTYS) return;
        self.ttys[idx].receive_char(c);
    }

    /// Switch active virtual terminal
    pub fn switch_vt(self: *Self, vt: u8) bool {
        if (vt >= MAX_VTS) return false;
        self.vts[self.active_vt].active = false;
        self.active_vt = vt;
        self.vts[vt].active = true;
        return true;
    }

    /// Allocate a PTY pair
    pub fn alloc_pty(self: *Self) ?u8 {
        for (0..MAX_PTY_PAIRS) |i| {
            if (!self.pty_pairs[i].active) {
                // Master at ttys[MAX_VTS + i*2], Slave at ttys[MAX_VTS + i*2 + 1]
                const master_idx: u8 = @intCast(MAX_VTS + i * 2);
                const slave_idx: u8 = @intCast(MAX_VTS + i * 2 + 1);
                if (master_idx >= MAX_TTYS or slave_idx >= MAX_TTYS) return null;

                self.pty_pairs[i] = .{
                    .master_idx = master_idx,
                    .slave_idx = slave_idx,
                    .active = true,
                };

                self.ttys[master_idx].pty_peer = @intCast(slave_idx);
                self.ttys[slave_idx].pty_peer = @intCast(master_idx);
                _ = self.ttys[master_idx].open();
                _ = self.ttys[slave_idx].open();

                self.pty_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn free_pty(self: *Self, pair_idx: u8) void {
        if (pair_idx >= MAX_PTY_PAIRS) return;
        if (!self.pty_pairs[pair_idx].active) return;

        const m = self.pty_pairs[pair_idx].master_idx;
        const s = self.pty_pairs[pair_idx].slave_idx;
        self.ttys[m].close();
        self.ttys[s].close();
        self.ttys[m].pty_peer = -1;
        self.ttys[s].pty_peer = -1;
        self.pty_pairs[pair_idx].active = false;
        self.pty_count -= 1;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var g_tty_mgr: TtyManager = undefined;
var g_tty_initialized: bool = false;

fn tty_mgr() *TtyManager {
    return &g_tty_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_tty_init() void {
    g_tty_mgr = TtyManager.init();
    g_tty_initialized = true;
}

export fn zxy_tty_open(idx: u8) bool {
    if (!g_tty_initialized) return false;
    return tty_mgr().open_tty(idx);
}

export fn zxy_tty_close(idx: u8) void {
    if (g_tty_initialized) tty_mgr().close_tty(idx);
}

export fn zxy_tty_write(idx: u8, data: [*]const u8, len: usize) usize {
    if (!g_tty_initialized) return 0;
    return tty_mgr().write_tty(idx, data[0..len]);
}

export fn zxy_tty_read(idx: u8, buf: [*]u8, len: usize) usize {
    if (!g_tty_initialized) return 0;
    return tty_mgr().read_tty(idx, buf[0..len]);
}

export fn zxy_tty_input_char(idx: u8, c: u8) void {
    if (g_tty_initialized) tty_mgr().input_char(idx, c);
}

export fn zxy_tty_switch_vt(vt: u8) bool {
    if (!g_tty_initialized) return false;
    return tty_mgr().switch_vt(vt);
}

export fn zxy_tty_active_vt() u8 {
    if (!g_tty_initialized) return 0;
    return tty_mgr().active_vt;
}

export fn zxy_tty_alloc_pty() i8 {
    if (!g_tty_initialized) return -1;
    if (tty_mgr().alloc_pty()) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_tty_free_pty(pair: u8) void {
    if (g_tty_initialized) tty_mgr().free_pty(pair);
}

export fn zxy_tty_total_reads() u64 {
    if (!g_tty_initialized) return 0;
    return tty_mgr().total_reads;
}

export fn zxy_tty_total_writes() u64 {
    if (!g_tty_initialized) return 0;
    return tty_mgr().total_writes;
}

export fn zxy_tty_pty_count() u8 {
    if (!g_tty_initialized) return 0;
    return tty_mgr().pty_count;
}
