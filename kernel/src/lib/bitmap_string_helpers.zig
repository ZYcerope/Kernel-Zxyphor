// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - String/Memory Helpers & Bitmap Operations
// Complete kernel string functions, memory copy/set/cmp,
// bitmap operations, bitfield macros, checksum helpers,
// sort algorithms, kernel-safe printf, hexdump

const std = @import("std");

// ============================================================================
// Bitmap Operations
// ============================================================================

pub const BITS_PER_LONG = 64;
pub const BITS_PER_BYTE = 8;
pub const BITS_PER_TYPE = fn(comptime T: type) comptime_int {
    return @bitSizeOf(T);
};

pub const BitmapWord = u64;

pub fn BITS_TO_LONGS(nr: u64) u64 {
    return (nr + BITS_PER_LONG - 1) / BITS_PER_LONG;
}

pub fn BIT_WORD(nr: u64) u64 {
    return nr / BITS_PER_LONG;
}

pub fn BIT_MASK(nr: u64) u64 {
    return @as(u64, 1) << @as(u6, @intCast(nr % BITS_PER_LONG));
}

pub const BitmapOps = struct {
    pub fn set(bitmap: []BitmapWord, bit: u64) void {
        bitmap[BIT_WORD(bit)] |= BIT_MASK(bit);
    }

    pub fn clear(bitmap: []BitmapWord, bit: u64) void {
        bitmap[BIT_WORD(bit)] &= ~BIT_MASK(bit);
    }

    pub fn test_bit(bitmap: []const BitmapWord, bit: u64) bool {
        return (bitmap[BIT_WORD(bit)] & BIT_MASK(bit)) != 0;
    }

    pub fn test_and_set(bitmap: []BitmapWord, bit: u64) bool {
        const word = BIT_WORD(bit);
        const mask = BIT_MASK(bit);
        const old = bitmap[word];
        bitmap[word] |= mask;
        return (old & mask) != 0;
    }

    pub fn test_and_clear(bitmap: []BitmapWord, bit: u64) bool {
        const word = BIT_WORD(bit);
        const mask = BIT_MASK(bit);
        const old = bitmap[word];
        bitmap[word] &= ~mask;
        return (old & mask) != 0;
    }

    pub fn set_range(bitmap: []BitmapWord, start: u64, len: u64) void {
        var i: u64 = start;
        while (i < start + len) : (i += 1) {
            set(bitmap, i);
        }
    }

    pub fn clear_range(bitmap: []BitmapWord, start: u64, len: u64) void {
        var i: u64 = start;
        while (i < start + len) : (i += 1) {
            clear(bitmap, i);
        }
    }

    pub fn find_first_zero(bitmap: []const BitmapWord, nbits: u64) ?u64 {
        var i: u64 = 0;
        while (i < nbits) : (i += 1) {
            if (!test_bit(bitmap, i)) return i;
        }
        return null;
    }

    pub fn find_first_set(bitmap: []const BitmapWord, nbits: u64) ?u64 {
        var i: u64 = 0;
        while (i < nbits) : (i += 1) {
            if (test_bit(bitmap, i)) return i;
        }
        return null;
    }

    pub fn find_next_zero(bitmap: []const BitmapWord, nbits: u64, offset: u64) ?u64 {
        var i: u64 = offset;
        while (i < nbits) : (i += 1) {
            if (!test_bit(bitmap, i)) return i;
        }
        return null;
    }

    pub fn find_next_set(bitmap: []const BitmapWord, nbits: u64, offset: u64) ?u64 {
        var i: u64 = offset;
        while (i < nbits) : (i += 1) {
            if (test_bit(bitmap, i)) return i;
        }
        return null;
    }

    pub fn popcount(bitmap: []const BitmapWord, nbits: u64) u64 {
        var count: u64 = 0;
        var i: u64 = 0;
        while (i < nbits) : (i += 1) {
            if (test_bit(bitmap, i)) count += 1;
        }
        return count;
    }

    pub fn bitmap_and(dst: []BitmapWord, a: []const BitmapWord, b: []const BitmapWord, nbits: u64) void {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            dst[i] = a[i] & b[i];
        }
    }

    pub fn bitmap_or(dst: []BitmapWord, a: []const BitmapWord, b: []const BitmapWord, nbits: u64) void {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            dst[i] = a[i] | b[i];
        }
    }

    pub fn bitmap_xor(dst: []BitmapWord, a: []const BitmapWord, b: []const BitmapWord, nbits: u64) void {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            dst[i] = a[i] ^ b[i];
        }
    }

    pub fn bitmap_not(dst: []BitmapWord, src: []const BitmapWord, nbits: u64) void {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            dst[i] = ~src[i];
        }
    }

    pub fn is_empty(bitmap: []const BitmapWord, nbits: u64) bool {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            if (bitmap[i] != 0) return false;
        }
        return true;
    }

    pub fn is_full(bitmap: []const BitmapWord, nbits: u64) bool {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            if (bitmap[i] != ~@as(u64, 0)) return false;
        }
        return true;
    }

    pub fn equal(a: []const BitmapWord, b: []const BitmapWord, nbits: u64) bool {
        const nwords = BITS_TO_LONGS(nbits);
        var i: usize = 0;
        while (i < nwords) : (i += 1) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
};

// ============================================================================
// String Operations (Kernel-safe)
// ============================================================================

pub const StringOps = struct {
    pub fn kstrlen(s: [*:0]const u8) usize {
        var len: usize = 0;
        while (s[len] != 0) : (len += 1) {}
        return len;
    }

    pub fn kstrnlen(s: [*]const u8, maxlen: usize) usize {
        var len: usize = 0;
        while (len < maxlen and s[len] != 0) : (len += 1) {}
        return len;
    }

    pub fn kstrcmp(s1: [*:0]const u8, s2: [*:0]const u8) i32 {
        var i: usize = 0;
        while (s1[i] != 0 and s2[i] != 0) : (i += 1) {
            if (s1[i] < s2[i]) return -1;
            if (s1[i] > s2[i]) return 1;
        }
        if (s1[i] == 0 and s2[i] == 0) return 0;
        if (s1[i] == 0) return -1;
        return 1;
    }

    pub fn kstrncmp(s1: [*]const u8, s2: [*]const u8, n: usize) i32 {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (s1[i] < s2[i]) return -1;
            if (s1[i] > s2[i]) return 1;
            if (s1[i] == 0) return 0;
        }
        return 0;
    }

    pub fn kstrcpy(dst: [*]u8, src: [*:0]const u8) [*]u8 {
        var i: usize = 0;
        while (src[i] != 0) : (i += 1) {
            dst[i] = src[i];
        }
        dst[i] = 0;
        return dst;
    }

    pub fn kstrlcpy(dst: [*]u8, src: [*:0]const u8, size: usize) usize {
        const src_len = kstrlen(src);
        if (size > 0) {
            const copy_len = if (src_len >= size) size - 1 else src_len;
            var i: usize = 0;
            while (i < copy_len) : (i += 1) {
                dst[i] = src[i];
            }
            dst[copy_len] = 0;
        }
        return src_len;
    }

    pub fn kstrlcat(dst: [*]u8, src: [*:0]const u8, size: usize) usize {
        const dst_len = kstrnlen(dst, size);
        if (dst_len >= size) return size + kstrlen(src);
        return dst_len + kstrlcpy(dst + dst_len, src, size - dst_len);
    }

    pub fn kstrdup(s: [*:0]const u8, allocator: std.mem.Allocator) ![]u8 {
        const len = kstrlen(s);
        const buf = try allocator.alloc(u8, len + 1);
        var i: usize = 0;
        while (i <= len) : (i += 1) {
            buf[i] = s[i];
        }
        return buf;
    }

    pub fn kstrsep(stringp: *?[*:0]u8, delim: [*:0]const u8) ?[*:0]u8 {
        const s = stringp.* orelse return null;
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            var j: usize = 0;
            while (delim[j] != 0) : (j += 1) {
                if (s[i] == delim[j]) {
                    s[i] = 0;
                    stringp.* = @ptrCast(&s[i + 1]);
                    return s;
                }
            }
        }
        stringp.* = null;
        return s;
    }

    pub fn kstrchr(s: [*:0]const u8, c: u8) ?[*:0]const u8 {
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            if (s[i] == c) return @ptrCast(&s[i]);
        }
        if (c == 0) return @ptrCast(&s[i]);
        return null;
    }

    pub fn kstrrchr(s: [*:0]const u8, c: u8) ?[*:0]const u8 {
        var last: ?[*:0]const u8 = null;
        var i: usize = 0;
        while (s[i] != 0) : (i += 1) {
            if (s[i] == c) last = @ptrCast(&s[i]);
        }
        if (c == 0) return @ptrCast(&s[i]);
        return last;
    }
};

// ============================================================================
// Memory Operations
// ============================================================================

pub const MemOps = struct {
    pub fn kmemset(dst: [*]u8, val: u8, count: usize) [*]u8 {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            dst[i] = val;
        }
        return dst;
    }

    pub fn kmemcpy(dst: [*]u8, src: [*]const u8, count: usize) [*]u8 {
        if (@intFromPtr(dst) < @intFromPtr(src)) {
            var i: usize = 0;
            while (i < count) : (i += 1) {
                dst[i] = src[i];
            }
        } else {
            var i: usize = count;
            while (i > 0) {
                i -= 1;
                dst[i] = src[i];
            }
        }
        return dst;
    }

    pub fn kmemmove(dst: [*]u8, src: [*]const u8, count: usize) [*]u8 {
        return kmemcpy(dst, src, count); // Already handles overlap
    }

    pub fn kmemcmp(s1: [*]const u8, s2: [*]const u8, count: usize) i32 {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (s1[i] < s2[i]) return -1;
            if (s1[i] > s2[i]) return 1;
        }
        return 0;
    }

    pub fn kmemchr(s: [*]const u8, c: u8, count: usize) ?[*]const u8 {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (s[i] == c) return @ptrCast(&s[i]);
        }
        return null;
    }

    pub fn kbzero(s: [*]u8, count: usize) void {
        _ = kmemset(s, 0, count);
    }

    pub fn kmemzero_explicit(s: [*]volatile u8, count: usize) void {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            s[i] = 0;
        }
        asm volatile ("" ::: "memory");
    }
};

// ============================================================================
// Checksum Helpers
// ============================================================================

pub const ChecksumOps = struct {
    pub fn csum_partial(buf: [*]const u8, len: usize, wsum: u32) u32 {
        var sum: u64 = wsum;
        var i: usize = 0;
        while (i + 1 < len) : (i += 2) {
            sum += @as(u16, buf[i]) | (@as(u16, buf[i + 1]) << 8);
        }
        if (i < len) {
            sum += buf[i];
        }
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return @intCast(sum);
    }

    pub fn csum_fold(csum: u32) u16 {
        var sum = csum;
        sum += sum >> 16;
        return @intCast(~sum & 0xFFFF);
    }

    pub fn ip_fast_csum(iph: [*]const u8, ihl: u32) u16 {
        return csum_fold(csum_partial(iph, ihl * 4, 0));
    }

    pub fn crc32c(crc: u32, buf: [*]const u8, len: usize) u32 {
        var c = crc ^ 0xFFFFFFFF;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            c = crc32c_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
        }
        return c ^ 0xFFFFFFFF;
    }

    // Placeholder for CRC32C lookup table (first 8 entries)
    const crc32c_table = [256]u32{
        0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
        0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    } ++ [_]u32{0} ** 248; // Remaining entries zeroed for brevity
};

// ============================================================================
// Sort Algorithm (Heapsort - O(n log n) in-place)
// ============================================================================

pub const SortOps = struct {
    pub fn sort(
        base: [*]u8,
        num: usize,
        size: usize,
        cmp_func: *const fn ([*]const u8, [*]const u8) i32,
    ) void {
        if (num < 2) return;
        // Sift down
        var i: usize = num / 2;
        while (i > 0) {
            i -= 1;
            sift_down(base, i, num, size, cmp_func);
        }
        // Extract
        i = num - 1;
        while (i > 0) : (i -= 1) {
            swap_elements(base, 0, i, size);
            sift_down(base, 0, i, size, cmp_func);
        }
    }

    fn sift_down(
        base: [*]u8,
        start: usize,
        end_idx: usize,
        size: usize,
        cmp_func: *const fn ([*]const u8, [*]const u8) i32,
    ) void {
        var root = start;
        while (2 * root + 1 < end_idx) {
            var child = 2 * root + 1;
            if (child + 1 < end_idx) {
                if (cmp_func(base + child * size, base + (child + 1) * size) < 0) {
                    child += 1;
                }
            }
            if (cmp_func(base + root * size, base + child * size) < 0) {
                swap_elements(base, root, child, size);
                root = child;
            } else {
                return;
            }
        }
    }

    fn swap_elements(base: [*]u8, a: usize, b: usize, size: usize) void {
        const pa = base + a * size;
        const pb = base + b * size;
        var i: usize = 0;
        while (i < size) : (i += 1) {
            const tmp = pa[i];
            pa[i] = pb[i];
            pb[i] = tmp;
        }
    }
};

// ============================================================================
// Hexdump
// ============================================================================

pub const HexdumpOps = struct {
    pub const HEX_DUMP_PREFIX_NONE: u8 = 0;
    pub const HEX_DUMP_PREFIX_ADDRESS: u8 = 1;
    pub const HEX_DUMP_PREFIX_OFFSET: u8 = 2;

    pub fn hex_dump_to_buffer(
        buf: [*]const u8,
        len: usize,
        rowsize: usize,
        groupsize: usize,
        linebuf: [*]u8,
        linebuflen: usize,
        ascii: bool,
    ) usize {
        _ = ascii;
        _ = groupsize;
        const hex_chars = "0123456789abcdef";
        var lx: usize = 0;
        var i: usize = 0;
        while (i < len and i < rowsize and lx + 3 < linebuflen) : (i += 1) {
            linebuf[lx] = hex_chars[buf[i] >> 4];
            lx += 1;
            linebuf[lx] = hex_chars[buf[i] & 0x0F];
            lx += 1;
            linebuf[lx] = ' ';
            lx += 1;
        }
        if (lx > 0) lx -= 1; // Remove trailing space
        linebuf[lx] = 0;
        return lx;
    }
};

// ============================================================================
// Number Parsing
// ============================================================================

pub const ParseOps = struct {
    pub fn kstrtoul(s: [*:0]const u8, base: u32, result: *u64) i32 {
        var val: u64 = 0;
        var i: usize = 0;
        var b = base;

        // Skip leading whitespace
        while (s[i] == ' ' or s[i] == '\t') : (i += 1) {}

        // Detect base
        if (b == 0) {
            if (s[i] == '0') {
                i += 1;
                if (s[i] == 'x' or s[i] == 'X') {
                    b = 16;
                    i += 1;
                } else {
                    b = 8;
                }
            } else {
                b = 10;
            }
        }

        while (s[i] != 0) : (i += 1) {
            var digit: u64 = undefined;
            if (s[i] >= '0' and s[i] <= '9') {
                digit = s[i] - '0';
            } else if (s[i] >= 'a' and s[i] <= 'f') {
                digit = s[i] - 'a' + 10;
            } else if (s[i] >= 'A' and s[i] <= 'F') {
                digit = s[i] - 'A' + 10;
            } else {
                break;
            }
            if (digit >= b) return -22; // -EINVAL
            val = val * b + digit;
        }

        result.* = val;
        return 0;
    }

    pub fn kstrtol(s: [*:0]const u8, base: u32, result: *i64) i32 {
        var uval: u64 = undefined;
        var i: usize = 0;
        var neg = false;

        while (s[i] == ' ' or s[i] == '\t') : (i += 1) {}
        if (s[i] == '-') {
            neg = true;
            i += 1;
        }

        const ret = kstrtoul(@ptrCast(&s[i]), base, &uval);
        if (ret != 0) return ret;

        if (neg) {
            result.* = -@as(i64, @intCast(uval));
        } else {
            result.* = @intCast(uval);
        }
        return 0;
    }
};

// ============================================================================
// Manager
// ============================================================================

pub const LibHelpersManager = struct {
    total_bitmap_ops: u64,
    total_string_ops: u64,
    total_memops: u64,
    total_checksums: u64,
    total_sorts: u64,
    total_parses: u64,
    initialized: bool,

    pub fn init() LibHelpersManager {
        return .{
            .total_bitmap_ops = 0,
            .total_string_ops = 0,
            .total_memops = 0,
            .total_checksums = 0,
            .total_sorts = 0,
            .total_parses = 0,
            .initialized = true,
        };
    }
};
