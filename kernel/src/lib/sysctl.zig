// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Sysctl Interface
//
// Implements a hierarchical key-value parameter system similar to Linux's
// /proc/sys interface. Kernel subsystems register tunables that can be
// read and modified at runtime. This enables dynamic configuration of
// scheduler parameters, memory management thresholds, network stack
// settings, security policies, and more — all without rebooting.

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");
const string = @import("../lib/string.zig");

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────
pub const SYSCTL_NAME_MAX: usize = 64;
pub const SYSCTL_PATH_MAX: usize = 256;
pub const SYSCTL_VALUE_MAX: usize = 512;
pub const SYSCTL_MAX_ENTRIES: usize = 1024;
pub const SYSCTL_MAX_CHILDREN: usize = 64;
pub const SYSCTL_MAX_TABLES: usize = 32;

// ─────────────────────────────────────────────────────────────────────
// Sysctl Value Types
// ─────────────────────────────────────────────────────────────────────
pub const SysctlType = enum(u8) {
    integer,
    unsigned_integer,
    long_integer,
    unsigned_long,
    string_type,
    boolean,
    bitmask,
    percentage,
    bytes_size, // human-readable size (e.g., "4096" or "4K")
    mode, // file permission mode (e.g., 0o755)
};

// ─────────────────────────────────────────────────────────────────────
// Sysctl Flags
// ─────────────────────────────────────────────────────────────────────
pub const SysctlFlags = packed struct {
    readable: bool = true,
    writable: bool = true,
    root_only_write: bool = false,
    root_only_read: bool = false,
    needs_reboot: bool = false,
    deprecated: bool = false,
    experimental: bool = false,
    _reserved: u1 = 0,
};

// ─────────────────────────────────────────────────────────────────────
// SysctlValue — tagged union for holding different value types
// ─────────────────────────────────────────────────────────────────────
pub const SysctlValue = union(SysctlType) {
    integer: i64,
    unsigned_integer: u64,
    long_integer: i64,
    unsigned_long: u64,
    string_type: StringValue,
    boolean: bool,
    bitmask: u64,
    percentage: u8,
    bytes_size: u64,
    mode: u16,

    pub const StringValue = struct {
        data: [SYSCTL_VALUE_MAX]u8,
        len: u16,

        pub fn init(src: []const u8) StringValue {
            var sv = StringValue{
                .data = [_]u8{0} ** SYSCTL_VALUE_MAX,
                .len = 0,
            };
            const copy_len = @min(src.len, SYSCTL_VALUE_MAX);
            @memcpy(sv.data[0..copy_len], src[0..copy_len]);
            sv.len = @intCast(copy_len);
            return sv;
        }

        pub fn get(self: *const StringValue) []const u8 {
            return self.data[0..self.len];
        }
    };

    /// Format the value to a human-readable string representation
    pub fn format(self: *const SysctlValue, buf: []u8) usize {
        return switch (self.*) {
            .integer => |v| formatI64(v, buf),
            .unsigned_integer, .unsigned_long, .bytes_size, .bitmask => |v| formatU64(v, buf),
            .long_integer => |v| formatI64(v, buf),
            .string_type => |v| blk: {
                const len = @min(v.len, buf.len);
                @memcpy(buf[0..len], v.data[0..len]);
                break :blk len;
            },
            .boolean => |v| blk: {
                if (v) {
                    if (buf.len >= 1) {
                        buf[0] = '1';
                        break :blk 1;
                    }
                } else {
                    if (buf.len >= 1) {
                        buf[0] = '0';
                        break :blk 1;
                    }
                }
                break :blk 0;
            },
            .percentage => |v| formatU64(@intCast(v), buf),
            .mode => |v| formatOctal(v, buf),
        };
    }
};

fn formatU64(val: u64, buf: []u8) usize {
    if (buf.len == 0) return 0;
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    var tmp: [20]u8 = undefined;
    var v = val;
    var pos: usize = 20;
    while (v > 0) {
        pos -= 1;
        tmp[pos] = @intCast((v % 10) + '0');
        v /= 10;
    }
    const len = @min(20 - pos, buf.len);
    @memcpy(buf[0..len], tmp[pos .. pos + len]);
    return len;
}

fn formatI64(val: i64, buf: []u8) usize {
    if (buf.len == 0) return 0;
    if (val < 0) {
        buf[0] = '-';
        const abs_val: u64 = @intCast(-val);
        return 1 + formatU64(abs_val, buf[1..]);
    }
    return formatU64(@intCast(val), buf);
}

fn formatOctal(val: u16, buf: []u8) usize {
    if (buf.len < 2) return 0;
    buf[0] = '0';
    var tmp: [6]u8 = undefined;
    var v = val;
    var pos: usize = 6;
    if (v == 0) {
        buf[1] = '0';
        return 2;
    }
    while (v > 0) {
        pos -= 1;
        tmp[pos] = @intCast((v % 8) + '0');
        v /= 8;
    }
    const digits = 6 - pos;
    const len = @min(digits, buf.len - 1);
    @memcpy(buf[1 .. 1 + len], tmp[pos .. pos + len]);
    return 1 + len;
}

// ─────────────────────────────────────────────────────────────────────
// SysctlEntry — a single tunable parameter
// ─────────────────────────────────────────────────────────────────────
pub const SysctlEntry = struct {
    /// Name of this parameter (leaf name, not full path)
    name: [SYSCTL_NAME_MAX]u8,
    name_len: u8,

    /// Full path (e.g., "kernel.sched.min_granularity_ns")
    path: [SYSCTL_PATH_MAX]u8,
    path_len: u16,

    /// Current value
    value: SysctlValue,

    /// Default value (for reset)
    default_value: SysctlValue,

    /// Minimum allowed value (for numeric types)
    min_value: ?i64,

    /// Maximum allowed value (for numeric types)
    max_value: ?i64,

    /// Flags controlling access and behavior
    flags: SysctlFlags,

    /// Description string (for /proc/sys or debug output)
    description: [128]u8,
    desc_len: u8,

    /// Custom validation callback
    validate: ?*const fn (new_value: *const SysctlValue) bool,

    /// Notification callback — called after value changes
    on_change: ?*const fn (entry: *SysctlEntry, old_value: *const SysctlValue) void,

    /// Number of times this entry has been read
    read_count: u64,

    /// Number of times this entry has been written
    write_count: u64,

    /// Lock
    lock: spinlock.SpinLock,

    /// Is this entry active?
    active: bool,

    const Self = @This();

    pub fn init(
        name: []const u8,
        path: []const u8,
        initial_value: SysctlValue,
        flags: SysctlFlags,
    ) Self {
        var entry = Self{
            .name = [_]u8{0} ** SYSCTL_NAME_MAX,
            .name_len = 0,
            .path = [_]u8{0} ** SYSCTL_PATH_MAX,
            .path_len = 0,
            .value = initial_value,
            .default_value = initial_value,
            .min_value = null,
            .max_value = null,
            .flags = flags,
            .description = [_]u8{0} ** 128,
            .desc_len = 0,
            .validate = null,
            .on_change = null,
            .read_count = 0,
            .write_count = 0,
            .lock = spinlock.SpinLock{},
            .active = true,
        };

        const nlen = @min(name.len, SYSCTL_NAME_MAX);
        @memcpy(entry.name[0..nlen], name[0..nlen]);
        entry.name_len = @intCast(nlen);

        const plen = @min(path.len, SYSCTL_PATH_MAX);
        @memcpy(entry.path[0..plen], path[0..plen]);
        entry.path_len = @intCast(plen);

        return entry;
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getPath(self: *const Self) []const u8 {
        return self.path[0..self.path_len];
    }

    pub fn getDescription(self: *const Self) []const u8 {
        return self.description[0..self.desc_len];
    }

    pub fn setDescription(self: *Self, desc: []const u8) void {
        const len = @min(desc.len, 128);
        @memcpy(self.description[0..len], desc[0..len]);
        self.desc_len = @intCast(len);
    }

    pub fn setRange(self: *Self, min: i64, max: i64) void {
        self.min_value = min;
        self.max_value = max;
    }

    /// Read the current value, copying it to the output buffer.
    /// Returns the number of bytes written, or -1 on error.
    pub fn read(self: *Self, buf: []u8) isize {
        self.lock.acquire();
        defer self.lock.release();

        if (!self.active) return -1;
        if (!self.flags.readable) return -1;

        self.read_count += 1;
        const len = self.value.format(buf);
        return @intCast(len);
    }

    /// Write a new value from a string representation.
    /// Returns 0 on success, negative on error.
    pub fn write(self: *Self, input: []const u8) i32 {
        self.lock.acquire();
        defer self.lock.release();

        if (!self.active) return -1;
        if (!self.flags.writable) return -1;

        // Parse the input based on the value type
        const new_value = self.parseInput(input) orelse return -2;

        // Validate range constraints for numeric types
        if (!self.checkRange(&new_value)) return -3;

        // Run custom validation
        if (self.validate) |validate_fn| {
            if (!validate_fn(&new_value)) return -4;
        }

        // Store old value for notification
        const old_value = self.value;

        // Apply the new value
        self.value = new_value;
        self.write_count += 1;

        // Notify listeners
        if (self.on_change) |on_change_fn| {
            on_change_fn(self, &old_value);
        }

        return 0;
    }

    /// Reset to default value
    pub fn resetToDefault(self: *Self) void {
        self.lock.acquire();
        defer self.lock.release();

        const old = self.value;
        self.value = self.default_value;
        self.write_count += 1;

        if (self.on_change) |notify| {
            notify(self, &old);
        }
    }

    fn parseInput(self: *const Self, input: []const u8) ?SysctlValue {
        if (input.len == 0) return null;

        return switch (self.value) {
            .integer => {
                const val = parseInt64(input) orelse return null;
                return SysctlValue{ .integer = val };
            },
            .unsigned_integer, .unsigned_long => {
                const val = parseUint64(input) orelse return null;
                return SysctlValue{ .unsigned_integer = val };
            },
            .long_integer => {
                const val = parseInt64(input) orelse return null;
                return SysctlValue{ .long_integer = val };
            },
            .string_type => {
                return SysctlValue{ .string_type = SysctlValue.StringValue.init(input) };
            },
            .boolean => {
                if (input.len == 1) {
                    if (input[0] == '1' or input[0] == 'y' or input[0] == 'Y') {
                        return SysctlValue{ .boolean = true };
                    }
                    if (input[0] == '0' or input[0] == 'n' or input[0] == 'N') {
                        return SysctlValue{ .boolean = false };
                    }
                }
                if (std.mem.eql(u8, input, "true") or std.mem.eql(u8, input, "yes")) {
                    return SysctlValue{ .boolean = true };
                }
                if (std.mem.eql(u8, input, "false") or std.mem.eql(u8, input, "no")) {
                    return SysctlValue{ .boolean = false };
                }
                return null;
            },
            .percentage => {
                const val = parseUint64(input) orelse return null;
                if (val > 100) return null;
                return SysctlValue{ .percentage = @intCast(val) };
            },
            .bitmask => {
                const val = parseUint64(input) orelse return null;
                return SysctlValue{ .bitmask = val };
            },
            .bytes_size => {
                const val = parseBytesSize(input) orelse return null;
                return SysctlValue{ .bytes_size = val };
            },
            .mode => {
                const val = parseOctal(input) orelse return null;
                return SysctlValue{ .mode = @intCast(val) };
            },
        };
    }

    fn checkRange(self: *const Self, new_val: *const SysctlValue) bool {
        const numeric_val: ?i64 = switch (new_val.*) {
            .integer, .long_integer => |v| v,
            .unsigned_integer, .unsigned_long => |v| if (v <= @as(u64, @intCast(std.math.maxInt(i64)))) @as(i64, @intCast(v)) else null,
            .percentage => |v| @as(i64, @intCast(v)),
            .bytes_size => |v| if (v <= @as(u64, @intCast(std.math.maxInt(i64)))) @as(i64, @intCast(v)) else null,
            else => null,
        };

        if (numeric_val) |val| {
            if (self.min_value) |min| {
                if (val < min) return false;
            }
            if (self.max_value) |max| {
                if (val > max) return false;
            }
        }

        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Parse helpers
// ─────────────────────────────────────────────────────────────────────
fn parseInt64(input: []const u8) ?i64 {
    if (input.len == 0) return null;

    var negative = false;
    var start: usize = 0;

    if (input[0] == '-') {
        negative = true;
        start = 1;
    } else if (input[0] == '+') {
        start = 1;
    }

    var result: i64 = 0;
    for (input[start..]) |c| {
        if (c < '0' or c > '9') {
            if (c == '\n' or c == ' ') break; // Ignore trailing whitespace
            return null;
        }
        result = result * 10 + @as(i64, @intCast(c - '0'));
    }

    return if (negative) -result else result;
}

fn parseUint64(input: []const u8) ?u64 {
    if (input.len == 0) return null;

    // Handle hex prefix
    if (input.len > 2 and input[0] == '0' and (input[1] == 'x' or input[1] == 'X')) {
        return parseHex(input[2..]);
    }

    var result: u64 = 0;
    for (input) |c| {
        if (c < '0' or c > '9') {
            if (c == '\n' or c == ' ') break;
            return null;
        }
        result = result * 10 + @as(u64, @intCast(c - '0'));
    }

    return result;
}

fn parseHex(input: []const u8) ?u64 {
    var result: u64 = 0;
    for (input) |c| {
        const digit: u64 = if (c >= '0' and c <= '9')
            c - '0'
        else if (c >= 'a' and c <= 'f')
            c - 'a' + 10
        else if (c >= 'A' and c <= 'F')
            c - 'A' + 10
        else if (c == '\n' or c == ' ')
            break
        else
            return null;
        result = result * 16 + digit;
    }
    return result;
}

fn parseBytesSize(input: []const u8) ?u64 {
    if (input.len == 0) return null;

    var num_end: usize = 0;
    for (input) |c| {
        if (c >= '0' and c <= '9') {
            num_end += 1;
        } else break;
    }

    const base = parseUint64(input[0..num_end]) orelse return null;
    const suffix = input[num_end..];

    if (suffix.len == 0) return base;

    const first = suffix[0];
    const multiplier: u64 = switch (first) {
        'K', 'k' => 1024,
        'M', 'm' => 1024 * 1024,
        'G', 'g' => 1024 * 1024 * 1024,
        'T', 't' => 1024 * 1024 * 1024 * 1024,
        else => return null,
    };

    return base * multiplier;
}

fn parseOctal(input: []const u8) ?u64 {
    var start: usize = 0;
    // Skip optional leading '0'
    if (input.len > 0 and input[0] == '0') {
        start = 1;
    }
    if (start >= input.len) return 0;

    var result: u64 = 0;
    for (input[start..]) |c| {
        if (c < '0' or c > '7') {
            if (c == '\n' or c == ' ') break;
            return null;
        }
        result = result * 8 + @as(u64, @intCast(c - '0'));
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────
// SysctlDirectory — hierarchical namespace node
// ─────────────────────────────────────────────────────────────────────
pub const SysctlDirectory = struct {
    name: [SYSCTL_NAME_MAX]u8,
    name_len: u8,
    children: [SYSCTL_MAX_CHILDREN]?*SysctlDirectory,
    child_count: u8,
    entries: [SYSCTL_MAX_CHILDREN]?*SysctlEntry,
    entry_count: u8,
    parent: ?*SysctlDirectory,

    const Self = @This();

    pub fn init(name: []const u8) Self {
        var dir = Self{
            .name = [_]u8{0} ** SYSCTL_NAME_MAX,
            .name_len = 0,
            .children = [_]?*SysctlDirectory{null} ** SYSCTL_MAX_CHILDREN,
            .child_count = 0,
            .entries = [_]?*SysctlEntry{null} ** SYSCTL_MAX_CHILDREN,
            .entry_count = 0,
            .parent = null,
        };
        const len = @min(name.len, SYSCTL_NAME_MAX);
        @memcpy(dir.name[0..len], name[0..len]);
        dir.name_len = @intCast(len);
        return dir;
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Find or create a child directory
    pub fn getOrCreateChild(self: *Self, name: []const u8) ?*SysctlDirectory {
        // Search existing children
        for (self.children[0..self.child_count]) |child_opt| {
            if (child_opt) |child| {
                if (std.mem.eql(u8, child.getName(), name)) {
                    return child;
                }
            }
        }

        // Create new child
        if (self.child_count >= SYSCTL_MAX_CHILDREN) return null;

        // We'd allocate from slab allocator in production; for now use
        // static storage from the global pool
        const new_dir = allocDirectory() orelse return null;
        new_dir.* = SysctlDirectory.init(name);
        new_dir.parent = self;

        self.children[self.child_count] = new_dir;
        self.child_count += 1;

        return new_dir;
    }

    /// Add an entry to this directory
    pub fn addEntry(self: *Self, entry: *SysctlEntry) bool {
        if (self.entry_count >= SYSCTL_MAX_CHILDREN) return false;

        // Check for duplicates
        for (self.entries[0..self.entry_count]) |e_opt| {
            if (e_opt) |e| {
                if (std.mem.eql(u8, e.getName(), entry.getName())) {
                    return false; // Already exists
                }
            }
        }

        self.entries[self.entry_count] = entry;
        self.entry_count += 1;
        return true;
    }

    /// Find an entry by name
    pub fn findEntry(self: *Self, name: []const u8) ?*SysctlEntry {
        for (self.entries[0..self.entry_count]) |e_opt| {
            if (e_opt) |e| {
                if (std.mem.eql(u8, e.getName(), name)) {
                    return e;
                }
            }
        }
        return null;
    }

    /// Find a child directory by name
    pub fn findChild(self: *Self, name: []const u8) ?*SysctlDirectory {
        for (self.children[0..self.child_count]) |child_opt| {
            if (child_opt) |child| {
                if (std.mem.eql(u8, child.getName(), name)) {
                    return child;
                }
            }
        }
        return null;
    }
};

// ─────────────────────────────────────────────────────────────────────
// SysctlTable — a group of related sysctl entries from a subsystem
// ─────────────────────────────────────────────────────────────────────
pub const SysctlTable = struct {
    name: [SYSCTL_NAME_MAX]u8,
    name_len: u8,
    entries: [128]?*SysctlEntry,
    entry_count: u16,
    base_path: [SYSCTL_PATH_MAX]u8,
    base_path_len: u16,

    const Self = @This();

    pub fn init(name: []const u8, base_path: []const u8) Self {
        var table = Self{
            .name = [_]u8{0} ** SYSCTL_NAME_MAX,
            .name_len = 0,
            .entries = [_]?*SysctlEntry{null} ** 128,
            .entry_count = 0,
            .base_path = [_]u8{0} ** SYSCTL_PATH_MAX,
            .base_path_len = 0,
        };

        const nlen = @min(name.len, SYSCTL_NAME_MAX);
        @memcpy(table.name[0..nlen], name[0..nlen]);
        table.name_len = @intCast(nlen);

        const plen = @min(base_path.len, SYSCTL_PATH_MAX);
        @memcpy(table.base_path[0..plen], base_path[0..plen]);
        table.base_path_len = @intCast(plen);

        return table;
    }

    pub fn addEntry(self: *Self, entry: *SysctlEntry) bool {
        if (self.entry_count >= 128) return false;
        self.entries[self.entry_count] = entry;
        self.entry_count += 1;
        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Global State & Static Pools
// ─────────────────────────────────────────────────────────────────────
var root_directory: SysctlDirectory = SysctlDirectory.init("sysctl");

var entry_pool: [SYSCTL_MAX_ENTRIES]SysctlEntry = undefined;
var entry_pool_used: u16 = 0;

var dir_pool: [256]SysctlDirectory = undefined;
var dir_pool_used: u16 = 0;

var tables: [SYSCTL_MAX_TABLES]?*SysctlTable = [_]?*SysctlTable{null} ** SYSCTL_MAX_TABLES;
var table_count: u8 = 0;

var global_lock: spinlock.SpinLock = spinlock.SpinLock{};

fn allocEntry() ?*SysctlEntry {
    if (entry_pool_used >= SYSCTL_MAX_ENTRIES) return null;
    const idx = entry_pool_used;
    entry_pool_used += 1;
    return &entry_pool[idx];
}

fn allocDirectory() ?*SysctlDirectory {
    if (dir_pool_used >= 256) return null;
    const idx = dir_pool_used;
    dir_pool_used += 1;
    return &dir_pool[idx];
}

// ─────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────

/// Initialize the sysctl subsystem and register the default kernel parameters.
pub fn init() void {
    global_lock.acquire();
    defer global_lock.release();

    entry_pool_used = 0;
    dir_pool_used = 0;
    table_count = 0;
    root_directory = SysctlDirectory.init("sysctl");

    // Register default kernel parameters
    registerDefaults();
}

/// Register a new sysctl entry at the given path.
/// Path format: "kernel.sched.min_granularity_ns" (dot-separated).
pub fn register(
    path: []const u8,
    initial_value: SysctlValue,
    flags: SysctlFlags,
    description: ?[]const u8,
) ?*SysctlEntry {
    global_lock.acquire();
    defer global_lock.release();

    // Allocate an entry from the pool
    const entry = allocEntry() orelse return null;

    // Parse the path to get the leaf name
    var last_dot: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '.') last_dot = i;
    }

    const leaf_name = if (last_dot > 0) path[last_dot + 1 ..] else path;

    entry.* = SysctlEntry.init(leaf_name, path, initial_value, flags);

    if (description) |desc| {
        entry.setDescription(desc);
    }

    // Navigate/create the directory hierarchy
    var dir = &root_directory;
    var remaining = path;

    while (remaining.len > 0) {
        // Find the next dot separator
        var end: usize = 0;
        while (end < remaining.len and remaining[end] != '.') {
            end += 1;
        }

        const component = remaining[0..end];

        if (end >= remaining.len) {
            // This is the leaf — add the entry
            _ = dir.addEntry(entry);
            break;
        }

        // This is a directory component — get or create
        dir = dir.getOrCreateChild(component) orelse return null;

        remaining = remaining[end + 1 ..];
    }

    return entry;
}

/// Register a sysctl table (a group of entries from a subsystem)
pub fn registerTable(table: *SysctlTable) bool {
    global_lock.acquire();
    defer global_lock.release();

    if (table_count >= SYSCTL_MAX_TABLES) return false;
    tables[table_count] = table;
    table_count += 1;
    return true;
}

/// Read a sysctl value by path. Returns bytes written to buf, or -1 on error.
pub fn readByPath(path: []const u8, buf: []u8) isize {
    const entry = lookupEntry(path) orelse return -1;
    return entry.read(buf);
}

/// Write a sysctl value by path. Returns 0 on success.
pub fn writeByPath(path: []const u8, input: []const u8) i32 {
    const entry = lookupEntry(path) orelse return -1;
    return entry.write(input);
}

/// Look up a sysctl entry by its dot-separated path
pub fn lookupEntry(path: []const u8) ?*SysctlEntry {
    global_lock.acquire();
    defer global_lock.release();

    var dir = &root_directory;
    var remaining = path;

    while (remaining.len > 0) {
        var end: usize = 0;
        while (end < remaining.len and remaining[end] != '.') {
            end += 1;
        }

        const component = remaining[0..end];

        if (end >= remaining.len) {
            // This should be the leaf entry
            return dir.findEntry(component);
        }

        // Look for child directory
        dir = dir.findChild(component) orelse return null;
        remaining = remaining[end + 1 ..];
    }

    return null;
}

/// Reset all entries in a subtree to their default values
pub fn resetDefaults(path_prefix: []const u8) u32 {
    global_lock.acquire();
    defer global_lock.release();

    var count: u32 = 0;

    for (entry_pool[0..entry_pool_used]) |*entry| {
        if (!entry.active) continue;

        const entry_path = entry.getPath();
        if (entry_path.len >= path_prefix.len) {
            if (std.mem.eql(u8, entry_path[0..path_prefix.len], path_prefix)) {
                entry.resetToDefault();
                count += 1;
            }
        }
    }

    return count;
}

/// Enumerate all entries, calling the callback for each
pub fn enumerate(callback: *const fn (*SysctlEntry) void) void {
    global_lock.acquire();
    defer global_lock.release();

    for (entry_pool[0..entry_pool_used]) |*entry| {
        if (entry.active) {
            callback(entry);
        }
    }
}

/// Get statistics about the sysctl subsystem
pub fn getStats() SysctlStats {
    return SysctlStats{
        .total_entries = entry_pool_used,
        .total_directories = dir_pool_used,
        .total_tables = table_count,
        .max_entries = SYSCTL_MAX_ENTRIES,
    };
}

pub const SysctlStats = struct {
    total_entries: u16,
    total_directories: u16,
    total_tables: u8,
    max_entries: usize,
};

// ─────────────────────────────────────────────────────────────────────
// Default kernel parameters
// ─────────────────────────────────────────────────────────────────────
fn registerDefaults() void {
    // Scheduler parameters
    _ = register(
        "kernel.sched.min_granularity_ns",
        SysctlValue{ .unsigned_long = 4000000 },
        SysctlFlags{},
        "Minimum preemption granularity for CFS scheduler (ns)",
    );
    _ = register(
        "kernel.sched.latency_ns",
        SysctlValue{ .unsigned_long = 24000000 },
        SysctlFlags{},
        "Targeted preemption latency for CFS scheduler (ns)",
    );
    _ = register(
        "kernel.sched.nr_migrate",
        SysctlValue{ .unsigned_integer = 32 },
        SysctlFlags{},
        "Maximum number of tasks to migrate in one batch",
    );
    _ = register(
        "kernel.sched.child_runs_first",
        SysctlValue{ .boolean = false },
        SysctlFlags{},
        "Whether forked child should run before parent",
    );

    // Memory management parameters
    _ = register(
        "vm.dirty_ratio",
        SysctlValue{ .percentage = 40 },
        SysctlFlags{},
        "Maximum dirty page ratio before forced writeback (%)",
    );
    _ = register(
        "vm.dirty_background_ratio",
        SysctlValue{ .percentage = 10 },
        SysctlFlags{},
        "Dirty page ratio to trigger background writeback (%)",
    );
    _ = register(
        "vm.swappiness",
        SysctlValue{ .percentage = 60 },
        SysctlFlags{},
        "Tendency to reclaim mapped pages vs page cache (0-100)",
    );
    _ = register(
        "vm.overcommit_memory",
        SysctlValue{ .unsigned_integer = 0 },
        SysctlFlags{},
        "Memory overcommit policy: 0=heuristic, 1=always, 2=never",
    );
    _ = register(
        "vm.min_free_kbytes",
        SysctlValue{ .unsigned_integer = 67584 },
        SysctlFlags{},
        "Minimum free memory reserved for critical allocations (KiB)",
    );
    _ = register(
        "vm.vfs_cache_pressure",
        SysctlValue{ .unsigned_integer = 100 },
        SysctlFlags{},
        "Tendency to reclaim VFS caches (default 100)",
    );
    _ = register(
        "vm.page_cache_readahead_max",
        SysctlValue{ .unsigned_integer = 256 },
        SysctlFlags{},
        "Maximum readahead window in pages",
    );

    // Network parameters
    _ = register(
        "net.ipv4.tcp_syncookies",
        SysctlValue{ .boolean = true },
        SysctlFlags{},
        "Enable SYN cookies for SYN flood protection",
    );
    _ = register(
        "net.ipv4.tcp_max_syn_backlog",
        SysctlValue{ .unsigned_integer = 4096 },
        SysctlFlags{},
        "Maximum SYN queue length",
    );
    _ = register(
        "net.ipv4.tcp_keepalive_time",
        SysctlValue{ .unsigned_integer = 7200 },
        SysctlFlags{},
        "TCP keepalive interval in seconds",
    );
    _ = register(
        "net.ipv4.tcp_fin_timeout",
        SysctlValue{ .unsigned_integer = 60 },
        SysctlFlags{},
        "Timeout for FIN-WAIT-2 state in seconds",
    );
    _ = register(
        "net.ipv4.ip_forward",
        SysctlValue{ .boolean = false },
        SysctlFlags{},
        "Enable IP forwarding between interfaces",
    );
    _ = register(
        "net.ipv4.tcp_window_scaling",
        SysctlValue{ .boolean = true },
        SysctlFlags{},
        "Enable RFC 1323 window scaling",
    );
    _ = register(
        "net.core.rmem_max",
        SysctlValue{ .bytes_size = 16 * 1024 * 1024 },
        SysctlFlags{},
        "Maximum receive socket buffer size",
    );
    _ = register(
        "net.core.wmem_max",
        SysctlValue{ .bytes_size = 16 * 1024 * 1024 },
        SysctlFlags{},
        "Maximum send socket buffer size",
    );

    // Kernel parameters
    _ = register(
        "kernel.hostname",
        SysctlValue{ .string_type = SysctlValue.StringValue.init("zxyphor") },
        SysctlFlags{},
        "System hostname",
    );
    _ = register(
        "kernel.ostype",
        SysctlValue{ .string_type = SysctlValue.StringValue.init("Zxyphor") },
        SysctlFlags{ .writable = false },
        "Operating system name",
    );
    _ = register(
        "kernel.osrelease",
        SysctlValue{ .string_type = SysctlValue.StringValue.init("1.0.0") },
        SysctlFlags{ .writable = false },
        "Kernel version string",
    );
    _ = register(
        "kernel.panic",
        SysctlValue{ .integer = 0 },
        SysctlFlags{},
        "Seconds to wait before reboot after panic (0=disabled)",
    );
    _ = register(
        "kernel.printk_ratelimit",
        SysctlValue{ .unsigned_integer = 5 },
        SysctlFlags{},
        "Minimum seconds between printk messages",
    );
    _ = register(
        "kernel.modules_disabled",
        SysctlValue{ .boolean = false },
        SysctlFlags{ .root_only_write = true },
        "Disable loading of kernel modules (one-way toggle)",
    );

    // Security parameters
    _ = register(
        "kernel.dmesg_restrict",
        SysctlValue{ .boolean = false },
        SysctlFlags{ .root_only_write = true },
        "Restrict dmesg access to root only",
    );
    _ = register(
        "kernel.kptr_restrict",
        SysctlValue{ .unsigned_integer = 0 },
        SysctlFlags{ .root_only_write = true },
        "Restrict kernel pointer exposure (0=off, 1=restricted, 2=hidden)",
    );
    _ = register(
        "kernel.randomize_va_space",
        SysctlValue{ .unsigned_integer = 2 },
        SysctlFlags{ .root_only_write = true },
        "ASLR mode: 0=off, 1=stack/mmap, 2=full (heap too)",
    );

    // File system parameters
    _ = register(
        "fs.file_max",
        SysctlValue{ .unsigned_long = 1048576 },
        SysctlFlags{},
        "Maximum number of open file descriptors system-wide",
    );
    _ = register(
        "fs.inode_max",
        SysctlValue{ .unsigned_long = 524288 },
        SysctlFlags{},
        "Maximum number of cached inodes",
    );
    _ = register(
        "fs.dentry_max",
        SysctlValue{ .unsigned_long = 262144 },
        SysctlFlags{},
        "Maximum number of cached directory entries",
    );
}

// ─────────────────────────────────────────────────────────────────────
// C FFI — exported symbols for the Rust side
// ─────────────────────────────────────────────────────────────────────
export fn zxy_sysctl_init() void {
    init();
}

export fn zxy_sysctl_read(path_ptr: [*]const u8, path_len: usize, buf_ptr: [*]u8, buf_len: usize) i32 {
    const path = path_ptr[0..path_len];
    const buf = buf_ptr[0..buf_len];
    const result = readByPath(path, buf);
    return @intCast(result);
}

export fn zxy_sysctl_write(path_ptr: [*]const u8, path_len: usize, val_ptr: [*]const u8, val_len: usize) i32 {
    const path = path_ptr[0..path_len];
    const input = val_ptr[0..val_len];
    return writeByPath(path, input);
}
