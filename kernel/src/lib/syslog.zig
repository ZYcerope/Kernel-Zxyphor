// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Kernel Logging / printk Subsystem (Zig)
//
// Linux-compatible kernel logging implementation:
// - Log levels: EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG
// - Ring buffer for kernel messages (dmesg)
// - Console output dispatch (serial, VGA, framebuffer)
// - Structured log entries with timestamp and facility
// - Rate limiting to prevent log flooding
// - Printk with format-like interface
// - Log facility codes (kern, user, daemon, auth, etc.)
// - syslog(2) interface for /dev/kmsg

const std = @import("std");

// ─────────── Log Levels (Linux-compatible) ──────────────────────────

pub const LOG_EMERG: u8 = 0;    // System is unusable
pub const LOG_ALERT: u8 = 1;    // Action must be taken immediately
pub const LOG_CRIT: u8 = 2;     // Critical conditions
pub const LOG_ERR: u8 = 3;      // Error conditions
pub const LOG_WARNING: u8 = 4;  // Warning conditions
pub const LOG_NOTICE: u8 = 5;   // Normal but significant
pub const LOG_INFO: u8 = 6;     // Informational
pub const LOG_DEBUG: u8 = 7;    // Debug-level messages

pub const LOG_DEFAULT: u8 = LOG_WARNING;

// ─────────── Facilities ─────────────────────────────────────────────

pub const FAC_KERN: u8 = 0;
pub const FAC_USER: u8 = 1;
pub const FAC_MAIL: u8 = 2;
pub const FAC_DAEMON: u8 = 3;
pub const FAC_AUTH: u8 = 4;
pub const FAC_SYSLOG: u8 = 5;
pub const FAC_LPR: u8 = 6;
pub const FAC_NEWS: u8 = 7;
pub const FAC_UUCP: u8 = 8;
pub const FAC_CRON: u8 = 9;
pub const FAC_LOCAL0: u8 = 16;
pub const FAC_LOCAL7: u8 = 23;

// ─────────── Console Flags ──────────────────────────────────────────

pub const ConsoleFlags = packed struct(u8) {
    serial: bool = false,
    vga: bool = false,
    framebuffer: bool = false,
    netconsole: bool = false,
    _pad: u4 = 0,
};

// ─────────── Log Entry ──────────────────────────────────────────────

const MSG_MAX_LEN: u16 = 256;

pub const LogEntry = struct {
    /// Message text (null-terminated)
    text: [MSG_MAX_LEN]u8,
    text_len: u16,

    /// Metadata
    level: u8,
    facility: u8,
    timestamp_ns: u64,   // Nanoseconds since boot
    seq: u64,            // Sequence number (monotonic)

    /// Source identification
    cpu: u8,
    pid: u32,

    /// Used flag
    valid: bool,
};

const EMPTY_ENTRY: LogEntry = .{
    .text = [_]u8{0} ** MSG_MAX_LEN,
    .text_len = 0,
    .level = LOG_INFO,
    .facility = FAC_KERN,
    .timestamp_ns = 0,
    .seq = 0,
    .cpu = 0,
    .pid = 0,
    .valid = false,
};

// ─────────── Ring Buffer ────────────────────────────────────────────

const LOG_BUFFER_SIZE: u32 = 4096; // Number of log entries

const LogRingBuffer = struct {
    entries: [LOG_BUFFER_SIZE]LogEntry,
    head: u32,       // Next write position
    tail: u32,       // Oldest valid entry
    count: u32,
    total_written: u64,
    total_dropped: u64,

    fn init() LogRingBuffer {
        return .{
            .entries = [_]LogEntry{EMPTY_ENTRY} ** LOG_BUFFER_SIZE,
            .head = 0,
            .tail = 0,
            .count = 0,
            .total_written = 0,
            .total_dropped = 0,
        };
    }

    fn write(self: *LogRingBuffer, entry: LogEntry) void {
        self.entries[self.head] = entry;
        self.entries[self.head].valid = true;
        self.head = (self.head + 1) % LOG_BUFFER_SIZE;
        if (self.count >= LOG_BUFFER_SIZE) {
            // Overwrite oldest
            self.tail = (self.tail + 1) % LOG_BUFFER_SIZE;
            self.total_dropped += 1;
        } else {
            self.count += 1;
        }
        self.total_written += 1;
    }

    fn read_at(self: *const LogRingBuffer, idx: u32) ?*const LogEntry {
        if (idx >= self.count) return null;
        const pos = (self.tail + idx) % LOG_BUFFER_SIZE;
        if (self.entries[pos].valid) {
            return &self.entries[pos];
        }
        return null;
    }

    fn read_by_seq(self: *const LogRingBuffer, seq: u64) ?*const LogEntry {
        // Binary-ish search: entries are sequential
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const pos = (self.tail + i) % LOG_BUFFER_SIZE;
            if (self.entries[pos].valid and self.entries[pos].seq == seq) {
                return &self.entries[pos];
            }
        }
        return null;
    }

    fn clear(self: *LogRingBuffer) void {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
};

// ─────────── Rate Limiter ───────────────────────────────────────────

const RateLimiter = struct {
    interval_ms: u64,       // Window size
    burst: u32,             // Max messages per window
    tokens: u32,            // Current tokens
    last_refill: u64,
    suppressed: u64,

    fn init(interval_ms: u64, burst: u32) RateLimiter {
        return .{
            .interval_ms = interval_ms,
            .burst = burst,
            .tokens = burst,
            .last_refill = 0,
            .suppressed = 0,
        };
    }

    fn allow(self: *RateLimiter, now_ms: u64) bool {
        // Refill tokens
        if (now_ms >= self.last_refill + self.interval_ms) {
            self.tokens = self.burst;
            self.last_refill = now_ms;
            if (self.suppressed > 0) {
                // Caller should log "N messages suppressed"
                self.suppressed = 0;
            }
        }
        if (self.tokens > 0) {
            self.tokens -= 1;
            return true;
        }
        self.suppressed += 1;
        return false;
    }
};

// ─────────── Console Backend ────────────────────────────────────────

pub const ConsoleType = enum(u8) {
    serial = 0,
    vga = 1,
    framebuffer = 2,
    netconsole = 3,
};

const MAX_CONSOLES: u8 = 8;

const ConsoleBackend = struct {
    ctype: ConsoleType,
    name: [16]u8,
    min_level: u8,        // Only show messages >= this level
    enabled: bool,
    write_count: u64,
    active: bool,
};

const EMPTY_CONSOLE: ConsoleBackend = .{
    .ctype = .serial,
    .name = [_]u8{0} ** 16,
    .min_level = LOG_WARNING,
    .enabled = false,
    .write_count = 0,
    .active = false,
};

// ─────────── Level Names ────────────────────────────────────────────

const LEVEL_NAMES: [8][]const u8 = .{
    "EMERG",
    "ALERT",
    "CRIT",
    "ERR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG",
};

const LEVEL_COLORS: [8][]const u8 = .{
    "\x1b[31;1m",  // EMERG: bright red
    "\x1b[31m",    // ALERT: red
    "\x1b[35;1m",  // CRIT: bright magenta
    "\x1b[31m",    // ERR: red
    "\x1b[33m",    // WARNING: yellow
    "\x1b[36m",    // NOTICE: cyan
    "\x1b[37m",    // INFO: white
    "\x1b[90m",    // DEBUG: gray
};

const COLOR_RESET: []const u8 = "\x1b[0m";

// ─────────── Syslog State ───────────────────────────────────────────

const SyslogState = struct {
    initialized: bool = false,
    ring: LogRingBuffer = LogRingBuffer.init(),
    consoles: [MAX_CONSOLES]ConsoleBackend = [_]ConsoleBackend{EMPTY_CONSOLE} ** MAX_CONSOLES,
    console_count: u8 = 0,

    // Log filtering
    console_loglevel: u8 = LOG_WARNING,     // Messages <= this level go to console
    default_message_level: u8 = LOG_WARNING,

    // Sequence counter
    next_seq: u64 = 1,

    // Time tracking
    boot_ns: u64 = 0,
    tick_ns: u64 = 0,

    // Rate limiters per facility
    rate_limiters: [24]RateLimiter = [_]RateLimiter{RateLimiter.init(5000, 10)} ** 24,

    // Global rate limiter
    global_rate: RateLimiter = RateLimiter.init(1000, 200),

    // Stats
    total_messages: u64 = 0,
    total_suppressed: u64 = 0,
    total_console_writes: u64 = 0,

    // Early boot buffer (before console init)
    early_buffer: [64][MSG_MAX_LEN]u8 = [_][MSG_MAX_LEN]u8{[_]u8{0} ** MSG_MAX_LEN} ** 64,
    early_count: u8 = 0,
    early_flushed: bool = false,
};

var g_syslog: SyslogState = .{};

// ─────────── External output hooks (link-time) ─────────────────────

extern fn zxy_serial_write(ptr: [*]const u8, len: u32) void;
extern fn zxy_vga_write(ptr: [*]const u8, len: u32) void;
extern fn zxy_fb_write(ptr: [*]const u8, len: u32) void;

// ─────────── Formatting Helpers ─────────────────────────────────────

fn copy_str(dst: []u8, src: []const u8) u16 {
    const len = @min(src.len, dst.len);
    @memcpy(dst[0..len], src[0..len]);
    return @intCast(len);
}

fn format_u64(buf: []u8, value: u64) u16 {
    if (value == 0) {
        if (buf.len > 0) buf[0] = '0';
        return 1;
    }
    var tmp: [20]u8 = undefined;
    var pos: u8 = 0;
    var v = value;
    while (v > 0) {
        tmp[pos] = @intCast((v % 10) + '0');
        v /= 10;
        pos += 1;
    }
    const len = @min(pos, @as(u8, @intCast(buf.len)));
    var i: u8 = 0;
    while (i < len) : (i += 1) {
        buf[i] = tmp[pos - 1 - i];
    }
    return len;
}

fn format_timestamp(buf: []u8, ns: u64) u16 {
    // Format as [SSSSS.UUUUUU] — seconds.microseconds
    const us = ns / 1000;
    const secs = us / 1_000_000;
    const frac = us % 1_000_000;

    var pos: u16 = 0;
    buf[pos] = '[';
    pos += 1;

    pos += format_u64(buf[pos..], secs);
    buf[pos] = '.';
    pos += 1;

    // Zero-pad microseconds to 6 digits
    var frac_buf: [6]u8 = [_]u8{'0'} ** 6;
    _ = format_u64(&frac_buf, frac);
    // Right-justify
    var tmp_val = frac;
    var digits: u8 = 0;
    if (frac == 0) {
        digits = 1;
    } else {
        var tv = tmp_val;
        while (tv > 0) {
            tv /= 10;
            digits += 1;
        }
    }
    // Fill leading zeros
    var fill: [6]u8 = [_]u8{'0'} ** 6;
    const start_pos = 6 - digits;
    var k: u8 = 0;
    while (k < digits) : (k += 1) {
        fill[start_pos + k] = frac_buf[k];
    }
    @memcpy(buf[pos..][0..6], &fill);
    pos += 6;

    buf[pos] = ']';
    pos += 1;

    return pos;
}

// ─────────── Core Logging ───────────────────────────────────────────

pub fn klog(level: u8, facility: u8, msg: []const u8) void {
    klog_ext(level, facility, msg, 0, 0);
}

pub fn klog_ext(level: u8, facility: u8, msg: []const u8, cpu: u8, pid: u32) void {
    const now_ms = g_syslog.tick_ns / 1_000_000;

    // Global rate limiting
    if (!g_syslog.global_rate.allow(now_ms)) {
        g_syslog.total_suppressed += 1;
        return;
    }

    // Per-facility rate limiting
    if (facility < 24) {
        if (!g_syslog.rate_limiters[facility].allow(now_ms)) {
            g_syslog.total_suppressed += 1;
            return;
        }
    }

    // Build log entry
    var entry: LogEntry = EMPTY_ENTRY;
    const text_len = @min(msg.len, MSG_MAX_LEN - 1);
    @memcpy(entry.text[0..text_len], msg[0..text_len]);
    entry.text_len = @intCast(text_len);
    entry.level = level;
    entry.facility = facility;
    entry.timestamp_ns = g_syslog.tick_ns;
    entry.seq = g_syslog.next_seq;
    entry.cpu = cpu;
    entry.pid = pid;
    entry.valid = true;

    g_syslog.next_seq += 1;
    g_syslog.total_messages += 1;

    // Write to ring buffer
    g_syslog.ring.write(entry);

    // Output to consoles
    if (level <= g_syslog.console_loglevel) {
        output_to_consoles(&entry);
    }
}

fn output_to_consoles(entry: *const LogEntry) void {
    // Format: [TIMESTAMP] LEVEL: message\n
    var line_buf: [512]u8 = undefined;
    var pos: u16 = 0;

    // Timestamp
    pos += format_timestamp(line_buf[pos..], entry.timestamp_ns);
    line_buf[pos] = ' ';
    pos += 1;

    // Level name
    if (entry.level < 8) {
        pos += copy_str(line_buf[pos..], LEVEL_NAMES[entry.level]);
    }
    line_buf[pos] = ':';
    pos += 1;
    line_buf[pos] = ' ';
    pos += 1;

    // Message text
    const msg_len = @min(entry.text_len, @as(u16, 512) - pos - 1);
    @memcpy(line_buf[pos..][0..msg_len], entry.text[0..msg_len]);
    pos += msg_len;

    line_buf[pos] = '\n';
    pos += 1;

    // Dispatch to active consoles
    var i: u8 = 0;
    while (i < g_syslog.console_count) : (i += 1) {
        const con = &g_syslog.consoles[i];
        if (!con.active or !con.enabled) continue;
        if (entry.level > con.min_level) continue;

        write_to_console(con.ctype, line_buf[0..pos]);
        g_syslog.total_console_writes += 1;
    }
}

fn write_to_console(ctype: ConsoleType, data: []const u8) void {
    switch (ctype) {
        .serial => zxy_serial_write(data.ptr, @intCast(data.len)),
        .vga => zxy_vga_write(data.ptr, @intCast(data.len)),
        .framebuffer => zxy_fb_write(data.ptr, @intCast(data.len)),
        .netconsole => {}, // TODO: UDP netconsole
    }
}

// ─────────── Public API ─────────────────────────────────────────────

pub fn init() void {
    g_syslog.initialized = true;
    g_syslog.ring = LogRingBuffer.init();
    g_syslog.next_seq = 1;
    g_syslog.console_loglevel = LOG_INFO;

    klog(LOG_INFO, FAC_KERN, "syslog: kernel logging initialized");
}

pub fn register_console(ctype: ConsoleType, name: []const u8, min_level: u8) bool {
    if (g_syslog.console_count >= MAX_CONSOLES) return false;
    const idx = g_syslog.console_count;
    g_syslog.consoles[idx].ctype = ctype;
    const nlen = @min(name.len, 15);
    @memcpy(g_syslog.consoles[idx].name[0..nlen], name[0..nlen]);
    g_syslog.consoles[idx].min_level = min_level;
    g_syslog.consoles[idx].enabled = true;
    g_syslog.consoles[idx].active = true;
    g_syslog.console_count += 1;

    // Flush early buffer
    if (!g_syslog.early_flushed and g_syslog.early_count > 0) {
        flush_early_buffer();
    }

    return true;
}

fn flush_early_buffer() void {
    var i: u8 = 0;
    while (i < g_syslog.early_count) : (i += 1) {
        const msg = &g_syslog.early_buffer[i];
        // Find null terminator
        var len: u16 = 0;
        while (len < MSG_MAX_LEN and msg[len] != 0) len += 1;
        if (len > 0) {
            klog(LOG_INFO, FAC_KERN, msg[0..len]);
        }
    }
    g_syslog.early_flushed = true;
}

pub fn set_console_loglevel(level: u8) void {
    if (level < 8) {
        g_syslog.console_loglevel = level;
    }
}

pub fn get_console_loglevel() u8 {
    return g_syslog.console_loglevel;
}

/// Read log entries for /dev/kmsg or dmesg
pub fn read_log(start_seq: u64, buf: []u8) u32 {
    var pos: u32 = 0;
    var found = false;

    var i: u32 = 0;
    while (i < g_syslog.ring.count) : (i += 1) {
        if (g_syslog.ring.read_at(i)) |entry| {
            if (entry.seq < start_seq) continue;
            found = true;

            // Format: priority,seq,timestamp;message\n
            const prio = (@as(u32, entry.facility) << 3) | entry.level;
            var line_buf: [384]u8 = undefined;
            var lpos: u16 = 0;

            lpos += format_u64(line_buf[lpos..], prio);
            line_buf[lpos] = ',';
            lpos += 1;
            lpos += format_u64(line_buf[lpos..], entry.seq);
            line_buf[lpos] = ',';
            lpos += 1;
            lpos += format_u64(line_buf[lpos..], entry.timestamp_ns / 1000); // microseconds
            line_buf[lpos] = ';';
            lpos += 1;

            const msg_len = @min(entry.text_len, @as(u16, 384) - lpos - 1);
            @memcpy(line_buf[lpos..][0..msg_len], entry.text[0..msg_len]);
            lpos += msg_len;
            line_buf[lpos] = '\n';
            lpos += 1;

            const copy_len = @min(@as(u32, lpos), @as(u32, @intCast(buf.len)) - pos);
            if (copy_len == 0) break;
            @memcpy(buf[pos..][0..copy_len], line_buf[0..copy_len]);
            pos += copy_len;
        }
    }
    _ = found;
    return pos;
}

/// Clear the log ring buffer
pub fn clear_log() void {
    g_syslog.ring.clear();
    klog(LOG_NOTICE, FAC_KERN, "syslog: log buffer cleared");
}

/// Advance kernel time (called from timer tick)
pub fn tick(delta_ns: u64) void {
    g_syslog.tick_ns += delta_ns;
}

// ─────────── Convenience macros as functions ────────────────────────

pub fn pr_emerg(msg: []const u8) void { klog(LOG_EMERG, FAC_KERN, msg); }
pub fn pr_alert(msg: []const u8) void { klog(LOG_ALERT, FAC_KERN, msg); }
pub fn pr_crit(msg: []const u8) void { klog(LOG_CRIT, FAC_KERN, msg); }
pub fn pr_err(msg: []const u8) void { klog(LOG_ERR, FAC_KERN, msg); }
pub fn pr_warn(msg: []const u8) void { klog(LOG_WARNING, FAC_KERN, msg); }
pub fn pr_notice(msg: []const u8) void { klog(LOG_NOTICE, FAC_KERN, msg); }
pub fn pr_info(msg: []const u8) void { klog(LOG_INFO, FAC_KERN, msg); }
pub fn pr_debug(msg: []const u8) void { klog(LOG_DEBUG, FAC_KERN, msg); }

// ─────────── Panic Handler ──────────────────────────────────────────

pub fn panic_log(msg: []const u8) void {
    // Bypass rate limiting for panics
    var entry: LogEntry = EMPTY_ENTRY;
    const text_len = @min(msg.len, MSG_MAX_LEN - 1);
    @memcpy(entry.text[0..text_len], msg[0..text_len]);
    entry.text_len = @intCast(text_len);
    entry.level = LOG_EMERG;
    entry.facility = FAC_KERN;
    entry.timestamp_ns = g_syslog.tick_ns;
    entry.seq = g_syslog.next_seq;
    entry.valid = true;
    g_syslog.next_seq += 1;

    g_syslog.ring.write(entry);

    // Force output to ALL consoles regardless of log level
    var i: u8 = 0;
    while (i < g_syslog.console_count) : (i += 1) {
        if (g_syslog.consoles[i].active) {
            var line_buf: [384]u8 = undefined;
            var pos: u16 = 0;
            const prefix = "KERNEL PANIC: ";
            @memcpy(line_buf[0..prefix.len], prefix);
            pos = prefix.len;
            @memcpy(line_buf[pos..][0..text_len], msg[0..text_len]);
            pos += @intCast(text_len);
            line_buf[pos] = '\n';
            pos += 1;
            write_to_console(g_syslog.consoles[i].ctype, line_buf[0..pos]);
        }
    }
}

// ─────────── syslog(2) Interface ────────────────────────────────────

pub const SYSLOG_ACTION_CLOSE: u32 = 0;
pub const SYSLOG_ACTION_OPEN: u32 = 1;
pub const SYSLOG_ACTION_READ: u32 = 2;
pub const SYSLOG_ACTION_READ_ALL: u32 = 3;
pub const SYSLOG_ACTION_READ_CLEAR: u32 = 4;
pub const SYSLOG_ACTION_CLEAR: u32 = 5;
pub const SYSLOG_ACTION_CONSOLE_OFF: u32 = 6;
pub const SYSLOG_ACTION_CONSOLE_ON: u32 = 7;
pub const SYSLOG_ACTION_CONSOLE_LEVEL: u32 = 8;
pub const SYSLOG_ACTION_SIZE_UNREAD: u32 = 9;
pub const SYSLOG_ACTION_SIZE_BUFFER: u32 = 10;

pub fn do_syslog(action: u32, buf: ?[]u8, _len: u32) i32 {
    switch (action) {
        SYSLOG_ACTION_CLOSE => return 0,
        SYSLOG_ACTION_OPEN => return 0,
        SYSLOG_ACTION_READ_ALL => {
            if (buf) |b| {
                return @intCast(read_log(0, b));
            }
            return -1;
        },
        SYSLOG_ACTION_CLEAR => {
            clear_log();
            return 0;
        },
        SYSLOG_ACTION_READ_CLEAR => {
            if (buf) |b| {
                const n = read_log(0, b);
                clear_log();
                return @intCast(n);
            }
            return -1;
        },
        SYSLOG_ACTION_CONSOLE_OFF => {
            g_syslog.console_loglevel = 0;
            return 0;
        },
        SYSLOG_ACTION_CONSOLE_ON => {
            g_syslog.console_loglevel = LOG_INFO;
            return 0;
        },
        SYSLOG_ACTION_CONSOLE_LEVEL => {
            set_console_loglevel(@intCast(_len));
            return 0;
        },
        SYSLOG_ACTION_SIZE_UNREAD => return @intCast(g_syslog.ring.count),
        SYSLOG_ACTION_SIZE_BUFFER => return @intCast(LOG_BUFFER_SIZE),
        else => return -1,
    }
}

// ─────────── FFI Exports ────────────────────────────────────────────

export fn zxy_syslog_init() void {
    init();
}

export fn zxy_syslog_register_console(ctype: u8, min_level: u8) bool {
    const ct: ConsoleType = @enumFromInt(ctype);
    return register_console(ct, "console", min_level);
}

export fn zxy_syslog_log(level: u8, facility: u8, msg_ptr: [*]const u8, msg_len: u32) void {
    klog(level, facility, msg_ptr[0..msg_len]);
}

export fn zxy_syslog_set_level(level: u8) void {
    set_console_loglevel(level);
}

export fn zxy_syslog_get_level() u8 {
    return get_console_loglevel();
}

export fn zxy_syslog_read(seq: u64, buf_ptr: [*]u8, buf_len: u32) u32 {
    return read_log(seq, buf_ptr[0..buf_len]);
}

export fn zxy_syslog_clear() void {
    clear_log();
}

export fn zxy_syslog_tick(delta_ns: u64) void {
    tick(delta_ns);
}

export fn zxy_syslog_total_messages() u64 {
    return g_syslog.total_messages;
}

export fn zxy_syslog_total_suppressed() u64 {
    return g_syslog.total_suppressed;
}

export fn zxy_syslog_total_dropped() u64 {
    return g_syslog.ring.total_dropped;
}

export fn zxy_syslog_buffer_count() u32 {
    return g_syslog.ring.count;
}

export fn zxy_syslog_next_seq() u64 {
    return g_syslog.next_seq;
}

export fn zxy_syslog_panic(msg_ptr: [*]const u8, msg_len: u32) void {
    panic_log(msg_ptr[0..msg_len]);
}

export fn zxy_syslog_action(action: u32, buf_ptr: ?[*]u8, buf_len: u32) i32 {
    if (buf_ptr) |ptr| {
        return do_syslog(action, ptr[0..buf_len], buf_len);
    }
    return do_syslog(action, null, buf_len);
}
