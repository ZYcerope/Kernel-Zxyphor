// =============================================================================
// Kernel Zxyphor - String Utilities
// =============================================================================
// Kernel string manipulation library. Provides C-like string functions
// (strlen, memcpy, memset, strcmp, etc.) and Zig-native string utilities.
// These functions operate on raw byte slices rather than null-terminated
// strings where possible, since the kernel doesn't use std.
// =============================================================================

// =============================================================================
// Comparison
// =============================================================================

/// Compare two byte slices for equality
pub fn equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

/// Compare two byte slices lexicographically
/// Returns: <0 if a < b, 0 if a == b, >0 if a > b
pub fn compare(a: []const u8, b: []const u8) i32 {
    const min_len = @min(a.len, b.len);
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        if (a[i] != b[i]) {
            return @as(i32, a[i]) - @as(i32, b[i]);
        }
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// Case-insensitive equality check
pub fn equalIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (toLower(x) != toLower(y)) return false;
    }
    return true;
}

/// Check if a slice starts with a prefix
pub fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (prefix.len > haystack.len) return false;
    return equal(haystack[0..prefix.len], prefix);
}

/// Check if a slice ends with a suffix
pub fn endsWith(haystack: []const u8, suffix: []const u8) bool {
    if (suffix.len > haystack.len) return false;
    return equal(haystack[haystack.len - suffix.len ..], suffix);
}

// =============================================================================
// Search
// =============================================================================

/// Find first occurrence of a byte in a slice
pub fn indexOf(haystack: []const u8, needle: u8) ?usize {
    for (haystack, 0..) |c, i| {
        if (c == needle) return i;
    }
    return null;
}

/// Find last occurrence of a byte in a slice
pub fn lastIndexOf(haystack: []const u8, needle: u8) ?usize {
    var i = haystack.len;
    while (i > 0) {
        i -= 1;
        if (haystack[i] == needle) return i;
    }
    return null;
}

/// Find first occurrence of a substring
pub fn findSubstring(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (equal(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

/// Count occurrences of a byte
pub fn count(haystack: []const u8, needle: u8) usize {
    var c: usize = 0;
    for (haystack) |ch| {
        if (ch == needle) c += 1;
    }
    return c;
}

/// Check if a byte slice contains a specific byte
pub fn contains(haystack: []const u8, needle: u8) bool {
    return indexOf(haystack, needle) != null;
}

// =============================================================================
// Manipulation (in-place where possible)
// =============================================================================

/// Copy bytes from src to dst (non-overlapping)
pub fn copy(dst: []u8, src: []const u8) usize {
    const len = @min(dst.len, src.len);
    @memcpy(dst[0..len], src[0..len]);
    return len;
}

/// Fill a buffer with a specific byte
pub fn fill(dst: []u8, val: u8) void {
    @memset(dst, val);
}

/// Zero out a buffer
pub fn zero(dst: []u8) void {
    @memset(dst, 0);
}

/// Reverse a byte slice in place
pub fn reverse(buf: []u8) void {
    if (buf.len <= 1) return;
    var lo: usize = 0;
    var hi: usize = buf.len - 1;
    while (lo < hi) {
        const tmp = buf[lo];
        buf[lo] = buf[hi];
        buf[hi] = tmp;
        lo += 1;
        hi -= 1;
    }
}

/// Convert to lowercase in place
pub fn toLowerSlice(buf: []u8) void {
    for (buf) |*c| {
        c.* = toLower(c.*);
    }
}

/// Convert to uppercase in place
pub fn toUpperSlice(buf: []u8) void {
    for (buf) |*c| {
        c.* = toUpper(c.*);
    }
}

/// Trim leading and trailing whitespace (returns sub-slice)
pub fn trim(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and isWhitespace(s[start])) : (start += 1) {}
    if (start == s.len) return s[0..0];

    var end: usize = s.len;
    while (end > start and isWhitespace(s[end - 1])) : (end -= 1) {}

    return s[start..end];
}

/// Trim leading whitespace
pub fn trimLeft(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and isWhitespace(s[start])) : (start += 1) {}
    return s[start..];
}

/// Trim trailing whitespace
pub fn trimRight(s: []const u8) []const u8 {
    var end: usize = s.len;
    while (end > 0 and isWhitespace(s[end - 1])) : (end -= 1) {}
    return s[0..end];
}

// =============================================================================
// Splitting
// =============================================================================

/// Split by a delimiter, returning a bounded iterator
pub const SplitIterator = struct {
    buffer: []const u8,
    delimiter: u8,
    pos: usize = 0,

    pub fn next(self: *SplitIterator) ?[]const u8 {
        if (self.pos > self.buffer.len) return null;

        const start = self.pos;
        while (self.pos < self.buffer.len) : (self.pos += 1) {
            if (self.buffer[self.pos] == self.delimiter) {
                const result = self.buffer[start..self.pos];
                self.pos += 1;
                return result;
            }
        }

        // Last segment (or only segment)
        self.pos = self.buffer.len + 1;
        if (start <= self.buffer.len) {
            return self.buffer[start..self.buffer.len];
        }
        return null;
    }

    pub fn rest(self: *const SplitIterator) []const u8 {
        if (self.pos >= self.buffer.len) return "";
        return self.buffer[self.pos..];
    }
};

pub fn split(buffer: []const u8, delimiter: u8) SplitIterator {
    return SplitIterator{
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Split a path by '/' separator
pub fn splitPath(path: []const u8) SplitIterator {
    return split(path, '/');
}

// =============================================================================
// Integer to String Conversion
// =============================================================================

/// Convert an unsigned integer to a decimal string
pub fn formatUint(value: u64, buf: []u8) []const u8 {
    if (buf.len == 0) return buf[0..0];

    if (value == 0) {
        buf[0] = '0';
        return buf[0..1];
    }

    var val = value;
    var len: usize = 0;

    while (val > 0 and len < buf.len) {
        buf[len] = @truncate((val % 10) + '0');
        val /= 10;
        len += 1;
    }

    // Reverse the digits
    reverse(buf[0..len]);
    return buf[0..len];
}

/// Convert a signed integer to a decimal string
pub fn formatInt(value: i64, buf: []u8) []const u8 {
    if (buf.len == 0) return buf[0..0];

    if (value < 0) {
        buf[0] = '-';
        const uval: u64 = @intCast(-value);
        const rest = formatUint(uval, buf[1..]);
        return buf[0 .. 1 + rest.len];
    }

    return formatUint(@intCast(value), buf);
}

/// Convert an unsigned integer to hex string
pub fn formatHex(value: u64, buf: []u8) []const u8 {
    const hex_chars = "0123456789abcdef";
    if (buf.len == 0) return buf[0..0];

    if (value == 0) {
        buf[0] = '0';
        return buf[0..1];
    }

    var val = value;
    var len: usize = 0;

    while (val > 0 and len < buf.len) {
        buf[len] = hex_chars[@truncate(val & 0xF)];
        val >>= 4;
        len += 1;
    }

    reverse(buf[0..len]);
    return buf[0..len];
}

// =============================================================================
// String to Integer Conversion
// =============================================================================

/// Parse a decimal unsigned integer from a string
pub fn parseUint(s: []const u8) ?u64 {
    if (s.len == 0) return null;

    var result: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        const digit: u64 = c - '0';
        // Overflow check
        if (result > (0xFFFFFFFFFFFFFFFF - digit) / 10) return null;
        result = result * 10 + digit;
    }
    return result;
}

/// Parse a hexadecimal unsigned integer from a string
pub fn parseHex(s: []const u8) ?u64 {
    if (s.len == 0) return null;

    var result: u64 = 0;
    for (s) |c| {
        const digit: u64 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return null,
        };
        if (result > 0x0FFFFFFFFFFFFFFF) return null;
        result = (result << 4) | digit;
    }
    return result;
}

// =============================================================================
// C-compatibility functions (for null-terminated strings)
// =============================================================================

/// Length of a null-terminated C string
pub fn cstrLen(s: [*]const u8) usize {
    var len: usize = 0;
    while (s[len] != 0) : (len += 1) {}
    return len;
}

/// Convert null-terminated C string to a Zig slice
pub fn fromCStr(s: [*]const u8) []const u8 {
    return s[0..cstrLen(s)];
}

/// Copy a Zig slice into a buffer with null-terminator
pub fn toCStr(dst: []u8, src: []const u8) void {
    const len = @min(src.len, dst.len -| 1);
    @memcpy(dst[0..len], src[0..len]);
    if (len < dst.len) dst[len] = 0;
}

// =============================================================================
// Character classification
// =============================================================================
pub fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

pub fn isHexDigit(c: u8) bool {
    return isDigit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

pub fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

pub fn isAlphanumeric(c: u8) bool {
    return isAlpha(c) or isDigit(c);
}

pub fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

pub fn isPrintable(c: u8) bool {
    return c >= 0x20 and c <= 0x7E;
}

pub fn isUpper(c: u8) bool {
    return c >= 'A' and c <= 'Z';
}

pub fn isLower(c: u8) bool {
    return c >= 'a' and c <= 'z';
}

pub fn toLower(c: u8) u8 {
    if (isUpper(c)) return c + 32;
    return c;
}

pub fn toUpper(c: u8) u8 {
    if (isLower(c)) return c - 32;
    return c;
}

// =============================================================================
// Path utilities
// =============================================================================

/// Extract the filename from a path (after last '/')
pub fn basename(path: []const u8) []const u8 {
    if (lastIndexOf(path, '/')) |pos| {
        return path[pos + 1 ..];
    }
    return path;
}

/// Extract the directory from a path (before last '/')
pub fn dirname(path: []const u8) []const u8 {
    if (lastIndexOf(path, '/')) |pos| {
        if (pos == 0) return "/";
        return path[0..pos];
    }
    return ".";
}

/// Extract file extension (after last '.')
pub fn extension(path: []const u8) []const u8 {
    const name = basename(path);
    if (lastIndexOf(name, '.')) |pos| {
        if (pos == 0) return "";
        return name[pos..];
    }
    return "";
}

/// Check if path is absolute (starts with '/')
pub fn isAbsolute(path: []const u8) bool {
    return path.len > 0 and path[0] == '/';
}
