// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Radix Tree / XArray / Maple Tree Detail
// Complete internal structures, iteration, tagging, advanced operations

const std = @import("std");

// ============================================================================
// XArray (eXtensible Array) - Modern replacement for radix tree
// ============================================================================

pub const XA_CHUNK_SHIFT: u32 = 6;   // 64 slots per node
pub const XA_CHUNK_SIZE: u32 = 1 << XA_CHUNK_SHIFT;
pub const XA_CHUNK_MASK: u32 = XA_CHUNK_SIZE - 1;
pub const XA_MAX_MARKS: u32 = 3;

pub const XaMarkType = enum(u2) {
    Mark0 = 0,   // XA_MARK_0 (typically page dirty)
    Mark1 = 1,   // XA_MARK_1 (typically page accessed/towrite)
    Mark2 = 2,   // XA_MARK_2 (typically page writeback)
};

pub const XA_FLAGS_LOCK_IRQ: u32 = 1 << 0;
pub const XA_FLAGS_LOCK_BH: u32 = 1 << 1;
pub const XA_FLAGS_TRACK_FREE: u32 = 1 << 2;
pub const XA_FLAGS_ZERO_BUSY: u32 = 1 << 3;
pub const XA_FLAGS_ALLOC: u32 = XA_FLAGS_TRACK_FREE | XA_FLAGS_ZERO_BUSY;
pub const XA_FLAGS_ALLOC1: u32 = XA_FLAGS_TRACK_FREE;
pub const XA_FLAGS_ACCOUNT: u32 = 1 << 4;

pub const XArray = struct {
    xa_lock: u64,           // spinlock
    xa_flags: u32,
    xa_head: ?*XaNode,      // root pointer (or value entry)

    // XArray state
    pub fn isEmpty(self: *const XArray) bool {
        return self.xa_head == null;
    }
};

pub const XaNode = struct {
    shift: u8,              // bits remaining in each slot
    offset: u8,             // slot offset in parent
    count: u8,              // total slots used
    nr_values: u8,          // number of value entries
    parent: ?*XaNode,
    array: *XArray,         // owning xarray
    marks: [XA_MAX_MARKS][1]u64, // mark bitmasks (64 bits each)
    slots: [XA_CHUNK_SIZE]u64,   // child pointers or values

    pub fn isLeaf(self: *const XaNode) bool {
        return self.shift == 0;
    }

    pub fn getSlot(self: *const XaNode, index: u32) u64 {
        const slot_idx = (index >> @intCast(self.shift)) & XA_CHUNK_MASK;
        return self.slots[slot_idx];
    }

    pub fn hasMark(self: *const XaNode, slot: u32, mark: XaMarkType) bool {
        const idx = @intFromEnum(mark);
        return (self.marks[idx][0] & (@as(u64, 1) << @truncate(slot))) != 0;
    }

    pub fn setMark(self: *XaNode, slot: u32, mark: XaMarkType) void {
        const idx = @intFromEnum(mark);
        self.marks[idx][0] |= @as(u64, 1) << @truncate(slot);
    }

    pub fn clearMark(self: *XaNode, slot: u32, mark: XaMarkType) void {
        const idx = @intFromEnum(mark);
        self.marks[idx][0] &= ~(@as(u64, 1) << @truncate(slot));
    }
};

// XArray iteration state
pub const XaState = struct {
    xa: *XArray,
    xa_node: ?*XaNode,
    xa_index: u64,
    xa_shift: u32,
    xa_sibs: u32,
    xa_offset: u32,
    xa_pad: u32,
    xa_alloc: ?*XaNode,

    pub fn init(xa: *XArray, index: u64) XaState {
        return .{
            .xa = xa,
            .xa_node = null,
            .xa_index = index,
            .xa_shift = 0,
            .xa_sibs = 0,
            .xa_offset = 0,
            .xa_pad = 0,
            .xa_alloc = null,
        };
    }
};

// Value entry encoding
pub const XA_VALUE_SHIFT: u64 = 1;
pub const XA_ZERO_ENTRY: u64 = 0x100;
pub const XA_RETRY_ENTRY: u64 = 0x200;

pub fn xa_is_value(entry: u64) bool {
    return (entry & 1) != 0;
}

pub fn xa_to_value(entry: u64) u64 {
    return entry >> XA_VALUE_SHIFT;
}

pub fn xa_mk_value(v: u64) u64 {
    return (v << XA_VALUE_SHIFT) | 1;
}

// ============================================================================
// Radix Tree (legacy, wraps XArray)
// ============================================================================

pub const RADIX_TREE_MAP_SHIFT: u32 = XA_CHUNK_SHIFT;
pub const RADIX_TREE_MAP_SIZE: u32 = XA_CHUNK_SIZE;
pub const RADIX_TREE_MAP_MASK: u32 = XA_CHUNK_MASK;
pub const RADIX_TREE_MAX_TAGS: u32 = XA_MAX_MARKS;

pub const RadixTreeTag = enum(u32) {
    Dirty = 0,      // PAGECACHE_TAG_DIRTY
    Writeback = 1,  // PAGECACHE_TAG_WRITEBACK
    ToWrite = 2,    // PAGECACHE_TAG_TOWRITE
};

pub const RadixTreeRoot = struct {
    xa: XArray,      // underlying xarray (since 4.20+)
    rnode: ?*RadixTreeNode,

    pub fn init() RadixTreeRoot {
        return .{
            .xa = .{ .xa_lock = 0, .xa_flags = 0, .xa_head = null },
            .rnode = null,
        };
    }
};

pub const RadixTreeNode = struct {
    shift: u8,
    offset: u8,
    count: u8,
    exceptional: u8,
    parent: ?*RadixTreeNode,
    root: *RadixTreeRoot,
    tags: [RADIX_TREE_MAX_TAGS][1]u64,
    slots: [RADIX_TREE_MAP_SIZE]u64,
};

pub const RadixTreeIter = struct {
    index: u64,
    next_index: u64,
    tags: u64,
    node: ?*RadixTreeNode,
};

// ============================================================================
// Maple Tree
// ============================================================================

pub const MAPLE_NODE_SLOTS: u32 = 31;  // max slots per node
pub const MAPLE_RANGE64_SLOTS: u32 = 16;
pub const MAPLE_ARANGE64_SLOTS: u32 = 10;

pub const MapleType = enum(u8) {
    Dense = 0,       // maple_dense - leaf with sequential entries
    Leaf64 = 1,      // maple_leaf_64 - leaf with range pivots
    Range64 = 2,     // maple_range_64 - internal node
    Arange64 = 3,    // maple_arange_64 - internal node with allocation
};

pub const MapleEnode = u64;  // encoded node pointer with type in low bits

pub const MapleTree = struct {
    lock: u64,         // spinlock or rw_lock
    flags: MapleTreeFlags,
    root: MapleEnode,  // encoded root pointer

    pub fn isEmpty(self: *const MapleTree) bool {
        return self.root == 0;
    }
};

pub const MapleTreeFlags = packed struct(u32) {
    height: u8 = 0,
    use_rcu: bool = false,
    alloc_mode: bool = false,  // for allocating IDs
    _pad: u22 = 0,
};

pub const MapleNode = struct {
    parent: u64,       // encoded parent (or root pointer)
    node_type: MapleType,

    // Union of node types
    data: MapleNodeData,
};

pub const MapleNodeData = union {
    dense: MapleDense,
    leaf64: MapleLeaf64,
    range64: MapleRange64,
    arange64: MapleArange64,
};

pub const MapleDense = struct {
    slots: [MAPLE_NODE_SLOTS]u64,
};

pub const MapleLeaf64 = struct {
    pivots: [MAPLE_RANGE64_SLOTS - 1]u64,
    slots: [MAPLE_RANGE64_SLOTS]u64,
    gap: u64,
    pad: u64,
};

pub const MapleRange64 = struct {
    pivots: [MAPLE_RANGE64_SLOTS - 1]u64,
    slots: [MAPLE_RANGE64_SLOTS]u64,
    gap: u64,
    pad: u64,
};

pub const MapleArange64 = struct {
    pivots: [MAPLE_ARANGE64_SLOTS - 1]u64,
    slots: [MAPLE_ARANGE64_SLOTS]u64,
    gap: [MAPLE_ARANGE64_SLOTS]u64,
    meta: MapleMetadata,
};

pub const MapleMetadata = struct {
    end: u8,
    gap: u8,
};

// Maple tree state for iteration
pub const MaState = struct {
    tree: *MapleTree,
    index: u64,
    last: u64,
    node: MapleEnode,
    min: u64,
    max: u64,
    alloc: ?*MapleNode,
    depth: u8,
    offset: u8,
    mas_flags: MaStateFlags,
};

pub const MaStateFlags = packed struct(u8) {
    active: bool = false,
    start: bool = false,
    pause: bool = false,
    rewind: bool = false,
    _pad: u4 = 0,
};

// ============================================================================
// IDR (ID Radix tree) - wraps XArray
// ============================================================================

pub const Idr = struct {
    idr_rt: XArray,         // underlying xarray with XA_FLAGS_ALLOC
    idr_base: u32,
    idr_next: u32,

    pub fn init(base: u32) Idr {
        return .{
            .idr_rt = .{
                .xa_lock = 0,
                .xa_flags = XA_FLAGS_ALLOC,
                .xa_head = null,
            },
            .idr_base = base,
            .idr_next = 0,
        };
    }
};

pub const IDA = struct {
    xa: XArray,

    pub fn init() IDA {
        return .{
            .xa = .{
                .xa_lock = 0,
                .xa_flags = XA_FLAGS_ALLOC,
                .xa_head = null,
            },
        };
    }
};

// ============================================================================
// String and Bitmap Helpers
// ============================================================================

pub const BitmapOps = struct {
    pub fn setBit(bitmap: []u64, bit: u32) void {
        const word = bit / 64;
        const offset: u6 = @truncate(bit % 64);
        if (word < bitmap.len) {
            bitmap[word] |= @as(u64, 1) << offset;
        }
    }

    pub fn clearBit(bitmap: []u64, bit: u32) void {
        const word = bit / 64;
        const offset: u6 = @truncate(bit % 64);
        if (word < bitmap.len) {
            bitmap[word] &= ~(@as(u64, 1) << offset);
        }
    }

    pub fn testBit(bitmap: []const u64, bit: u32) bool {
        const word = bit / 64;
        const offset: u6 = @truncate(bit % 64);
        if (word >= bitmap.len) return false;
        return (bitmap[word] & (@as(u64, 1) << offset)) != 0;
    }

    pub fn findFirstZero(bitmap: []const u64, nbits: u32) ?u32 {
        var bit: u32 = 0;
        for (bitmap) |word| {
            if (word != ~@as(u64, 0)) {
                const offset: u32 = @ctz(~word);
                const result = bit + offset;
                if (result < nbits) return result;
                return null;
            }
            bit += 64;
            if (bit >= nbits) return null;
        }
        return null;
    }

    pub fn findFirstSet(bitmap: []const u64, nbits: u32) ?u32 {
        var bit: u32 = 0;
        for (bitmap) |word| {
            if (word != 0) {
                const offset: u32 = @ctz(word);
                const result = bit + offset;
                if (result < nbits) return result;
                return null;
            }
            bit += 64;
            if (bit >= nbits) return null;
        }
        return null;
    }

    pub fn popcount(bitmap: []const u64, nbits: u32) u32 {
        var count: u32 = 0;
        var remaining = nbits;
        for (bitmap) |word| {
            if (remaining == 0) break;
            if (remaining >= 64) {
                count += @popCount(word);
                remaining -= 64;
            } else {
                const mask = (@as(u64, 1) << @truncate(remaining)) - 1;
                count += @popCount(word & mask);
                remaining = 0;
            }
        }
        return count;
    }

    pub fn andBitmaps(dst: []u64, a: []const u64, b: []const u64) void {
        const len = @min(dst.len, @min(a.len, b.len));
        for (0..len) |i| {
            dst[i] = a[i] & b[i];
        }
    }

    pub fn orBitmaps(dst: []u64, a: []const u64, b: []const u64) void {
        const len = @min(dst.len, @min(a.len, b.len));
        for (0..len) |i| {
            dst[i] = a[i] | b[i];
        }
    }
};

// ============================================================================
// String helpers
// ============================================================================

pub const StringOps = struct {
    pub fn kstrdup(src: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const dst = try allocator.alloc(u8, src.len + 1);
        @memcpy(dst[0..src.len], src);
        dst[src.len] = 0;
        return dst;
    }

    pub fn strnlen(s: [*]const u8, max: usize) usize {
        var i: usize = 0;
        while (i < max and s[i] != 0) : (i += 1) {}
        return i;
    }

    pub fn strcmp(a: [*:0]const u8, b: [*:0]const u8) i32 {
        var i: usize = 0;
        while (a[i] != 0 and b[i] != 0) : (i += 1) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        if (a[i] == 0 and b[i] == 0) return 0;
        if (a[i] == 0) return -1;
        return 1;
    }

    pub fn strtoul(s: []const u8, base: u8) !u64 {
        var result: u64 = 0;
        var actual_base: u8 = base;
        var start: usize = 0;

        // Skip whitespace
        while (start < s.len and (s[start] == ' ' or s[start] == '\t')) : (start += 1) {}
        if (start >= s.len) return error.InvalidInput;

        // Auto-detect base
        if (actual_base == 0) {
            if (s.len > start + 1 and s[start] == '0') {
                if (s.len > start + 2 and (s[start + 1] == 'x' or s[start + 1] == 'X')) {
                    actual_base = 16;
                    start += 2;
                } else if (s[start + 1] == 'b' or s[start + 1] == 'B') {
                    actual_base = 2;
                    start += 2;
                } else {
                    actual_base = 8;
                    start += 1;
                }
            } else {
                actual_base = 10;
            }
        }

        for (s[start..]) |c| {
            const digit: u64 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => break,
            };
            if (digit >= actual_base) break;
            result = result *% actual_base +% digit;
        }
        return result;
    }

    // Hex dump helper
    pub fn hexDump(buf: []u8, data: []const u8, row_size: u32) usize {
        var pos: usize = 0;
        var offset: usize = 0;
        const rs = @as(usize, row_size);

        while (offset < data.len) {
            // Address
            if (pos + 10 > buf.len) break;
            const addr_bytes = std.fmt.bufPrint(buf[pos..], "{x:0>8}: ", .{offset}) catch break;
            pos += addr_bytes.len;

            // Hex bytes
            var i: usize = 0;
            while (i < rs and offset + i < data.len) : (i += 1) {
                if (pos + 3 > buf.len) break;
                const hex = std.fmt.bufPrint(buf[pos..], "{x:0>2} ", .{data[offset + i]}) catch break;
                pos += hex.len;
            }

            // Padding for short rows
            while (i < rs) : (i += 1) {
                if (pos + 3 > buf.len) break;
                buf[pos] = ' ';
                buf[pos + 1] = ' ';
                buf[pos + 2] = ' ';
                pos += 3;
            }

            // ASCII
            if (pos + 1 > buf.len) break;
            buf[pos] = '|';
            pos += 1;
            i = 0;
            while (i < rs and offset + i < data.len) : (i += 1) {
                if (pos + 1 > buf.len) break;
                const c = data[offset + i];
                buf[pos] = if (c >= 0x20 and c < 0x7f) c else '.';
                pos += 1;
            }
            if (pos + 2 > buf.len) break;
            buf[pos] = '|';
            buf[pos + 1] = '\n';
            pos += 2;

            offset += rs;
        }
        return pos;
    }
};

// ============================================================================
// Sort helpers (heapsort for kernel, not quicksort to avoid worst-case stack)
// ============================================================================

pub fn kernelSort(
    comptime T: type,
    items: []T,
    comptime cmpFn: fn (a: *const T, b: *const T) i32,
) void {
    const n = items.len;
    if (n <= 1) return;

    // Build max-heap
    var i: usize = n / 2;
    while (i > 0) {
        i -= 1;
        siftDown(T, items, i, n, cmpFn);
    }

    // Extract elements
    var end: usize = n - 1;
    while (end > 0) {
        const tmp = items[0];
        items[0] = items[end];
        items[end] = tmp;
        siftDown(T, items, 0, end, cmpFn);
        end -= 1;
    }
}

fn siftDown(
    comptime T: type,
    items: []T,
    start: usize,
    end: usize,
    comptime cmpFn: fn (a: *const T, b: *const T) i32,
) void {
    var root = start;
    while (true) {
        var largest = root;
        const left = 2 * root + 1;
        const right = 2 * root + 2;

        if (left < end and cmpFn(&items[left], &items[largest]) > 0) {
            largest = left;
        }
        if (right < end and cmpFn(&items[right], &items[largest]) > 0) {
            largest = right;
        }
        if (largest == root) break;

        const tmp = items[root];
        items[root] = items[largest];
        items[largest] = tmp;
        root = largest;
    }
}

// ============================================================================
// CRC32 (for filesystem & network checksums)
// ============================================================================

pub const Crc32 = struct {
    const TABLE_SIZE = 256;
    const POLY_CRC32: u32 = 0xEDB88320;
    const POLY_CRC32C: u32 = 0x82F63B78;

    table: [TABLE_SIZE]u32,

    pub fn initCrc32() Crc32 {
        var t: [TABLE_SIZE]u32 = undefined;
        for (0..TABLE_SIZE) |i| {
            var crc: u32 = @intCast(i);
            for (0..8) |_| {
                if (crc & 1 != 0) {
                    crc = (crc >> 1) ^ POLY_CRC32;
                } else {
                    crc >>= 1;
                }
            }
            t[i] = crc;
        }
        return .{ .table = t };
    }

    pub fn initCrc32c() Crc32 {
        var t: [TABLE_SIZE]u32 = undefined;
        for (0..TABLE_SIZE) |i| {
            var crc: u32 = @intCast(i);
            for (0..8) |_| {
                if (crc & 1 != 0) {
                    crc = (crc >> 1) ^ POLY_CRC32C;
                } else {
                    crc >>= 1;
                }
            }
            t[i] = crc;
        }
        return .{ .table = t };
    }

    pub fn compute(self: *const Crc32, data: []const u8) u32 {
        var crc: u32 = 0xFFFFFFFF;
        for (data) |byte| {
            const idx: u8 = @truncate((crc ^ byte) & 0xFF);
            crc = (crc >> 8) ^ self.table[idx];
        }
        return crc ^ 0xFFFFFFFF;
    }

    pub fn update(self: *const Crc32, crc_in: u32, data: []const u8) u32 {
        var crc = crc_in ^ 0xFFFFFFFF;
        for (data) |byte| {
            const idx: u8 = @truncate((crc ^ byte) & 0xFF);
            crc = (crc >> 8) ^ self.table[idx];
        }
        return crc ^ 0xFFFFFFFF;
    }
};

// ============================================================================
// DataStructureManager
// ============================================================================

pub const DataStructureManager = struct {
    xa_nodes_allocated: u64,
    xa_entries_stored: u64,
    maple_nodes_allocated: u64,
    maple_entries_stored: u64,
    idr_ids_allocated: u64,
    bitmap_ops_performed: u64,
    sort_operations: u64,
    crc_computations: u64,
    initialized: bool,

    pub fn init() DataStructureManager {
        return .{
            .xa_nodes_allocated = 0,
            .xa_entries_stored = 0,
            .maple_nodes_allocated = 0,
            .maple_entries_stored = 0,
            .idr_ids_allocated = 0,
            .bitmap_ops_performed = 0,
            .sort_operations = 0,
            .crc_computations = 0,
            .initialized = true,
        };
    }
};
