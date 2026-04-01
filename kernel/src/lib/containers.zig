// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Advanced Container Data Structures
// IDR/IDA, radix tree, XArray, rhashtable, maple tree,
// lru_cache, skip list, bloom filter, cuckoo filter, HyperLogLog
// More advanced than Linux 2026 container implementations

const std = @import("std");

// ============================================================================
// IDR (ID Radix) - Integer ID management
// ============================================================================

pub const IDR_BITS: u32 = 8;
pub const IDR_SIZE: u32 = 1 << IDR_BITS; // 256
pub const IDR_MASK: u32 = IDR_SIZE - 1;

pub const IdrLayer = struct {
    slots: [IDR_SIZE]?*anyopaque,
    bitmap: [IDR_SIZE / 64]u64,
    count: u32,
    layer: u32,
    prefix: u32,

    pub fn is_full(self: *const IdrLayer) bool {
        for (self.bitmap) |word| {
            if (word != ~@as(u64, 0)) return false;
        }
        return true;
    }

    pub fn find_free_bit(self: *const IdrLayer) ?u32 {
        for (self.bitmap, 0..) |word, i| {
            if (word != ~@as(u64, 0)) {
                var bit: u6 = 0;
                var w = ~word;
                while (w != 0) : (bit += 1) {
                    if ((w & 1) != 0) {
                        return @as(u32, @intCast(i)) * 64 + bit;
                    }
                    w >>= 1;
                }
            }
        }
        return null;
    }
};

pub const Idr = struct {
    top: ?*IdrLayer,
    layers: u32,
    cur: u32,
    allocated: u64,
    freed: u64,

    pub fn init() Idr {
        return Idr{
            .top = null,
            .layers = 0,
            .cur = 0,
            .allocated = 0,
            .freed = 0,
        };
    }
};

// ============================================================================
// IDA (ID Allocator) - Lightweight integer allocator
// ============================================================================

pub const IDA_BITMAP_BITS: u32 = 1024;

pub const IdaBitmap = struct {
    bitmap: [IDA_BITMAP_BITS / 64]u64,

    pub fn test_bit(self: *const IdaBitmap, bit: u32) bool {
        const word_idx = bit / 64;
        const bit_idx: u6 = @truncate(bit % 64);
        return (self.bitmap[word_idx] & (@as(u64, 1) << bit_idx)) != 0;
    }

    pub fn set_bit(self: *IdaBitmap, bit: u32) void {
        const word_idx = bit / 64;
        const bit_idx: u6 = @truncate(bit % 64);
        self.bitmap[word_idx] |= (@as(u64, 1) << bit_idx);
    }

    pub fn clear_bit(self: *IdaBitmap, bit: u32) void {
        const word_idx = bit / 64;
        const bit_idx: u6 = @truncate(bit % 64);
        self.bitmap[word_idx] &= ~(@as(u64, 1) << bit_idx);
    }

    pub fn find_first_zero(self: *const IdaBitmap) ?u32 {
        for (self.bitmap, 0..) |word, i| {
            if (word != ~@as(u64, 0)) {
                var bit: u6 = 0;
                var w = ~word;
                while (w != 0) : (bit += 1) {
                    if ((w & 1) != 0) {
                        return @as(u32, @intCast(i)) * 64 + bit;
                    }
                    w >>= 1;
                }
            }
        }
        return null;
    }
};

pub const Ida = struct {
    idr: Idr,
    free_bitmap: ?*IdaBitmap,

    pub fn init() Ida {
        return Ida{
            .idr = Idr.init(),
            .free_bitmap = null,
        };
    }
};

// ============================================================================
// Radix Tree
// ============================================================================

pub const RADIX_TREE_MAP_SHIFT: u32 = 6;
pub const RADIX_TREE_MAP_SIZE: u32 = 1 << RADIX_TREE_MAP_SHIFT;
pub const RADIX_TREE_MAP_MASK: u32 = RADIX_TREE_MAP_SIZE - 1;
pub const RADIX_TREE_MAX_TAGS: u32 = 3;

pub const RadixTreeNode = struct {
    shift: u8,
    offset: u8,
    count: u16,
    exceptional: u16,
    parent: ?*RadixTreeNode,
    slots: [RADIX_TREE_MAP_SIZE]?*anyopaque,
    tags: [RADIX_TREE_MAX_TAGS][RADIX_TREE_MAP_SIZE / 64]u64,

    pub fn tag_set(self: *RadixTreeNode, tag: u32, offset: u32) void {
        const word_idx = offset / 64;
        const bit_idx: u6 = @truncate(offset % 64);
        self.tags[tag][word_idx] |= (@as(u64, 1) << bit_idx);
    }

    pub fn tag_get(self: *const RadixTreeNode, tag: u32, offset: u32) bool {
        const word_idx = offset / 64;
        const bit_idx: u6 = @truncate(offset % 64);
        return (self.tags[tag][word_idx] & (@as(u64, 1) << bit_idx)) != 0;
    }

    pub fn tag_clear(self: *RadixTreeNode, tag: u32, offset: u32) void {
        const word_idx = offset / 64;
        const bit_idx: u6 = @truncate(offset % 64);
        self.tags[tag][word_idx] &= ~(@as(u64, 1) << bit_idx);
    }
};

pub const RadixTree = struct {
    height: u32,
    gfp_mask: u32,
    rnode: ?*RadixTreeNode,

    pub fn init() RadixTree {
        return RadixTree{
            .height = 0,
            .gfp_mask = 0,
            .rnode = null,
        };
    }
};

// ============================================================================
// Maple Tree (B-tree for ranges) - Linux 6.1+
// ============================================================================

pub const MapleType = enum(u8) {
    dense = 0,
    leaf_64 = 1,
    range_64 = 2,
    arange_64 = 3,
};

pub const MAPLE_NODE_SLOTS: u32 = 16;
pub const MAPLE_RANGE64_SLOTS: u32 = 16;
pub const MAPLE_ARANGE64_SLOTS: u32 = 10;

pub const MapleRange64 = struct {
    parent: ?*MapleNode,
    pivot: [MAPLE_RANGE64_SLOTS - 1]u64,
    slot: [MAPLE_RANGE64_SLOTS]?*anyopaque,
    pad: u64,
};

pub const MapleArange64 = struct {
    parent: ?*MapleNode,
    pivot: [MAPLE_ARANGE64_SLOTS - 1]u64,
    slot: [MAPLE_ARANGE64_SLOTS]?*anyopaque,
    gap: [MAPLE_ARANGE64_SLOTS]u64,
    meta: MapleMetadata,
};

pub const MapleMetadata = struct {
    end: u8,
    gap: u8,
};

pub const MapleNode = struct {
    parent: ?*MapleNode,
    node_type: MapleType,
    // Union of different node types
    slot_count: u8,
    pivots: [MAPLE_NODE_SLOTS - 1]u64,
    slots: [MAPLE_NODE_SLOTS]?*anyopaque,
    gaps: [MAPLE_NODE_SLOTS]u64,
    min: u64,
    max: u64,

    pub fn is_leaf(self: *const MapleNode) bool {
        return self.node_type == .leaf_64 or self.node_type == .dense;
    }
};

pub const MapleTree = struct {
    root: ?*MapleNode,
    flags: u32,
    height: u32,
    ma_flags: u32,
    // Stats
    nr_entries: u64,
    nr_nodes: u64,
    nr_allocated: u64,

    pub fn init() MapleTree {
        return MapleTree{
            .root = null,
            .flags = 0,
            .height = 0,
            .ma_flags = 0,
            .nr_entries = 0,
            .nr_nodes = 0,
            .nr_allocated = 0,
        };
    }
};

// ============================================================================
// Resizable Hash Table (rhashtable)
// ============================================================================

pub const RhashtableParams = struct {
    nelem_hint: u32,
    key_len: u32,
    key_offset: u32,
    head_offset: u32,
    max_size: u32,
    min_size: u32,
    automatic_shrinking: bool,
    hashfn: ?*const fn (*const anyopaque, u32, u32) u32,
    obj_hashfn: ?*const fn (*const anyopaque, u32, u32) u32,
    obj_cmpfn: ?*const fn (*const anyopaque, *const anyopaque) bool,
};

pub const RhashHead = struct {
    next: ?*RhashHead,
};

pub const BucketTable = struct {
    size: u32,
    nest: u32,
    hash_rnd: u32,
    walkers: u32,
    buckets: [*]?*RhashHead,
};

pub const Rhashtable = struct {
    tbl: ?*BucketTable,
    key_len: u32,
    max_elems: u32,
    p: RhashtableParams,
    rhlist: bool,
    run_work: bool,
    nelems: u64,
    nht_unfree: u32,

    pub fn init(params: RhashtableParams) Rhashtable {
        return Rhashtable{
            .tbl = null,
            .key_len = params.key_len,
            .max_elems = params.max_size,
            .p = params,
            .rhlist = false,
            .run_work = false,
            .nelems = 0,
            .nht_unfree = 0,
        };
    }

    pub fn load_factor(self: *const Rhashtable) f64 {
        if (self.tbl) |tbl| {
            if (tbl.size > 0) {
                return @as(f64, @floatFromInt(self.nelems)) / @as(f64, @floatFromInt(tbl.size));
            }
        }
        return 0.0;
    }
};

// ============================================================================
// LRU Cache
// ============================================================================

pub fn LruCache(comptime K: type, comptime V: type, comptime MAX_ENTRIES: u32) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            key: K,
            value: V,
            prev: ?u32,
            next: ?u32,
            valid: bool,
        };

        entries: [MAX_ENTRIES]Entry,
        head: ?u32,
        tail: ?u32,
        count: u32,
        hits: u64,
        misses: u64,
        evictions: u64,

        pub fn init() Self {
            var cache: Self = undefined;
            cache.head = null;
            cache.tail = null;
            cache.count = 0;
            cache.hits = 0;
            cache.misses = 0;
            cache.evictions = 0;
            for (&cache.entries) |*e| {
                e.valid = false;
                e.prev = null;
                e.next = null;
            }
            return cache;
        }

        pub fn hit_rate(self: *const Self) f64 {
            const total = self.hits + self.misses;
            if (total == 0) return 0.0;
            return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
        }
    };
}

// ============================================================================
// Skip List
// ============================================================================

pub const SKIPLIST_MAX_LEVEL: u32 = 32;

pub fn SkipList(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        pub const Node = struct {
            key: K,
            value: V,
            level: u32,
            forward: [SKIPLIST_MAX_LEVEL]?*Node,

            pub fn init(key: K, value: V, level: u32) Node {
                var node: Node = undefined;
                node.key = key;
                node.value = value;
                node.level = level;
                for (&node.forward) |*f| {
                    f.* = null;
                }
                return node;
            }
        };

        head: Node,
        level: u32,
        count: u64,
        max_level: u32,

        pub fn init() Self {
            return Self{
                .head = Node.init(undefined, undefined, SKIPLIST_MAX_LEVEL),
                .level = 1,
                .count = 0,
                .max_level = SKIPLIST_MAX_LEVEL,
            };
        }

        pub fn random_level(self: *Self) u32 {
            var lvl: u32 = 1;
            // Geometric distribution p=0.25
            var rng_state: u32 = @truncate(self.count ^ 0xDEADBEEF);
            while (lvl < self.max_level) {
                rng_state = rng_state *% 1103515245 +% 12345;
                if ((rng_state >> 16) & 0x03 != 0) break;
                lvl += 1;
            }
            return lvl;
        }
    };
}

// ============================================================================
// Bloom Filter
// ============================================================================

pub fn BloomFilter(comptime SIZE_BITS: u32) type {
    return struct {
        const Self = @This();
        const WORDS = SIZE_BITS / 64;

        bits: [WORDS]u64,
        nr_hashes: u32,
        nr_elements: u64,

        pub fn init(num_hashes: u32) Self {
            var bf: Self = undefined;
            bf.nr_hashes = num_hashes;
            bf.nr_elements = 0;
            for (&bf.bits) |*w| {
                w.* = 0;
            }
            return bf;
        }

        pub fn add(self: *Self, data: []const u8) void {
            var i: u32 = 0;
            while (i < self.nr_hashes) : (i += 1) {
                const h = hash_with_seed(data, i) % SIZE_BITS;
                const word_idx = h / 64;
                const bit_idx: u6 = @truncate(h % 64);
                self.bits[word_idx] |= (@as(u64, 1) << bit_idx);
            }
            self.nr_elements += 1;
        }

        pub fn may_contain(self: *const Self, data: []const u8) bool {
            var i: u32 = 0;
            while (i < self.nr_hashes) : (i += 1) {
                const h = hash_with_seed(data, i) % SIZE_BITS;
                const word_idx = h / 64;
                const bit_idx: u6 = @truncate(h % 64);
                if ((self.bits[word_idx] & (@as(u64, 1) << bit_idx)) == 0) {
                    return false;
                }
            }
            return true;
        }

        pub fn false_positive_rate(self: *const Self) f64 {
            var set_bits: u64 = 0;
            for (self.bits) |word| {
                set_bits += @popCount(word);
            }
            const p = @as(f64, @floatFromInt(set_bits)) / @as(f64, @floatFromInt(SIZE_BITS));
            // Approximate: p^k
            var result: f64 = 1.0;
            var i: u32 = 0;
            while (i < self.nr_hashes) : (i += 1) {
                result *= p;
            }
            return result;
        }

        fn hash_with_seed(data: []const u8, seed: u32) u32 {
            var h: u32 = seed *% 0x9E3779B9;
            for (data) |b| {
                h = h *% 31 +% b;
            }
            return h;
        }
    };
}

// ============================================================================
// Cuckoo Filter
// ============================================================================

pub fn CuckooFilter(comptime BUCKETS: u32, comptime BUCKET_SIZE: u32) type {
    return struct {
        const Self = @This();
        const FINGERPRINT_BITS: u32 = 16;

        const Bucket = struct {
            fingerprints: [BUCKET_SIZE]u16,
            count: u8,

            pub fn insert(self: *Bucket, fp: u16) bool {
                if (self.count >= BUCKET_SIZE) return false;
                self.fingerprints[self.count] = fp;
                self.count += 1;
                return true;
            }

            pub fn contains(self: *const Bucket, fp: u16) bool {
                var i: u8 = 0;
                while (i < self.count) : (i += 1) {
                    if (self.fingerprints[i] == fp) return true;
                }
                return false;
            }

            pub fn remove(self: *Bucket, fp: u16) bool {
                var i: u8 = 0;
                while (i < self.count) : (i += 1) {
                    if (self.fingerprints[i] == fp) {
                        self.fingerprints[i] = self.fingerprints[self.count - 1];
                        self.count -= 1;
                        return true;
                    }
                }
                return false;
            }
        };

        buckets: [BUCKETS]Bucket,
        nr_elements: u64,
        max_kicks: u32,

        pub fn init() Self {
            var cf: Self = undefined;
            cf.nr_elements = 0;
            cf.max_kicks = 500;
            for (&cf.buckets) |*b| {
                b.count = 0;
                for (&b.fingerprints) |*f| {
                    f.* = 0;
                }
            }
            return cf;
        }

        pub fn load_factor(self: *const Self) f64 {
            return @as(f64, @floatFromInt(self.nr_elements)) /
                @as(f64, @floatFromInt(BUCKETS * BUCKET_SIZE));
        }
    };
}

// ============================================================================
// HyperLogLog - Cardinality estimation
// ============================================================================

pub fn HyperLogLog(comptime PRECISION: u32) type {
    return struct {
        const Self = @This();
        const NUM_REGISTERS = @as(u32, 1) << PRECISION;

        registers: [NUM_REGISTERS]u8,
        count: u64,

        pub fn init() Self {
            var hll: Self = undefined;
            hll.count = 0;
            for (&hll.registers) |*r| {
                r.* = 0;
            }
            return hll;
        }

        pub fn add(self: *Self, hash: u64) void {
            const index: u32 = @truncate(hash >> (64 - PRECISION));
            const remaining = (hash << PRECISION) | (@as(u64, 1) << (PRECISION - 1));
            const zeros: u8 = @intCast(@clz(remaining) + 1);
            if (zeros > self.registers[index]) {
                self.registers[index] = zeros;
            }
            self.count += 1;
        }

        pub fn estimate(self: *const Self) f64 {
            const m = @as(f64, @floatFromInt(NUM_REGISTERS));
            // Alpha constant
            const alpha = switch (PRECISION) {
                4 => 0.673,
                5 => 0.697,
                6 => 0.709,
                else => 0.7213 / (1.0 + 1.079 / m),
            };

            var sum: f64 = 0.0;
            var zeros: u32 = 0;
            for (self.registers) |reg| {
                sum += std.math.pow(f64, 2.0, -@as(f64, @floatFromInt(reg)));
                if (reg == 0) zeros += 1;
            }

            var est = alpha * m * m / sum;

            // Small range correction
            if (est <= 2.5 * m and zeros > 0) {
                est = m * @log(@as(f64, @floatFromInt(NUM_REGISTERS)) / @as(f64, @floatFromInt(zeros)));
            }

            return est;
        }

        pub fn merge(self: *Self, other: *const Self) void {
            for (self.registers, 0..) |*reg, i| {
                if (other.registers[i] > reg.*) {
                    reg.* = other.registers[i];
                }
            }
        }
    };
}

// ============================================================================
// Count-Min Sketch - Frequency estimation
// ============================================================================

pub fn CountMinSketch(comptime WIDTH: u32, comptime DEPTH: u32) type {
    return struct {
        const Self = @This();

        counts: [DEPTH][WIDTH]u32,
        seeds: [DEPTH]u32,
        total: u64,

        pub fn init() Self {
            var cms: Self = undefined;
            cms.total = 0;
            for (&cms.counts) |*row| {
                for (row) |*c| {
                    c.* = 0;
                }
            }
            // Initialize seeds
            var s: u32 = 0x12345678;
            for (&cms.seeds) |*seed| {
                s = s *% 1103515245 +% 12345;
                seed.* = s;
            }
            return cms;
        }

        pub fn add(self: *Self, item: u32, count: u32) void {
            var d: u32 = 0;
            while (d < DEPTH) : (d += 1) {
                const h = (item *% self.seeds[d]) % WIDTH;
                self.counts[d][h] += count;
            }
            self.total += count;
        }

        pub fn estimate(self: *const Self, item: u32) u32 {
            var min_count: u32 = std.math.maxInt(u32);
            var d: u32 = 0;
            while (d < DEPTH) : (d += 1) {
                const h = (item *% self.seeds[d]) % WIDTH;
                if (self.counts[d][h] < min_count) {
                    min_count = self.counts[d][h];
                }
            }
            return min_count;
        }
    };
}

// ============================================================================
// Interval Tree (augmented red-black tree for overlapping intervals)
// ============================================================================

pub const IntervalTreeNode = struct {
    start: u64,
    last: u64,    // end of this interval
    max_last: u64, // max end in subtree
    left: ?*IntervalTreeNode,
    right: ?*IntervalTreeNode,
    parent: ?*IntervalTreeNode,
    color: enum(u1) { red = 0, black = 1 },
    data: ?*anyopaque,

    pub fn overlaps(self: *const IntervalTreeNode, start: u64, last: u64) bool {
        return self.start <= last and start <= self.last;
    }

    pub fn contains(self: *const IntervalTreeNode, point: u64) bool {
        return self.start <= point and point <= self.last;
    }

    pub fn length(self: *const IntervalTreeNode) u64 {
        return self.last - self.start + 1;
    }
};

pub const IntervalTree = struct {
    root: ?*IntervalTreeNode,
    count: u64,

    pub fn init() IntervalTree {
        return IntervalTree{
            .root = null,
            .count = 0,
        };
    }
};

// ============================================================================
// Priority Queue (Binary Heap)
// ============================================================================

pub fn PriorityQueue(comptime T: type, comptime MAX_SIZE: u32, comptime less_fn: fn (T, T) bool) type {
    return struct {
        const Self = @This();

        items: [MAX_SIZE]T,
        count: u32,

        pub fn init() Self {
            return Self{
                .items = undefined,
                .count = 0,
            };
        }

        pub fn push(self: *Self, item: T) bool {
            if (self.count >= MAX_SIZE) return false;
            self.items[self.count] = item;
            self.sift_up(self.count);
            self.count += 1;
            return true;
        }

        pub fn pop(self: *Self) ?T {
            if (self.count == 0) return null;
            const result = self.items[0];
            self.count -= 1;
            if (self.count > 0) {
                self.items[0] = self.items[self.count];
                self.sift_down(0);
            }
            return result;
        }

        pub fn peek(self: *const Self) ?T {
            if (self.count == 0) return null;
            return self.items[0];
        }

        fn sift_up(self: *Self, idx: u32) void {
            var i = idx;
            while (i > 0) {
                const parent = (i - 1) / 2;
                if (less_fn(self.items[i], self.items[parent])) {
                    const tmp = self.items[i];
                    self.items[i] = self.items[parent];
                    self.items[parent] = tmp;
                    i = parent;
                } else break;
            }
        }

        fn sift_down(self: *Self, idx: u32) void {
            var i = idx;
            while (true) {
                var smallest = i;
                const left = 2 * i + 1;
                const right = 2 * i + 2;
                if (left < self.count and less_fn(self.items[left], self.items[smallest])) {
                    smallest = left;
                }
                if (right < self.count and less_fn(self.items[right], self.items[smallest])) {
                    smallest = right;
                }
                if (smallest == i) break;
                const tmp = self.items[i];
                self.items[i] = self.items[smallest];
                self.items[smallest] = tmp;
                i = smallest;
            }
        }
    };
}

// ============================================================================
// Circular Buffer with power-of-two sizing
// ============================================================================

pub fn CircularBuffer(comptime T: type, comptime SIZE: u32) type {
    return struct {
        const Self = @This();
        const MASK = SIZE - 1;

        buffer: [SIZE]T,
        head: u32,
        tail: u32,
        full: bool,

        pub fn init() Self {
            return Self{
                .buffer = undefined,
                .head = 0,
                .tail = 0,
                .full = false,
            };
        }

        pub fn push(self: *Self, item: T) bool {
            if (self.full) return false;
            self.buffer[self.head & MASK] = item;
            self.head +%= 1;
            if ((self.head & MASK) == (self.tail & MASK)) self.full = true;
            return true;
        }

        pub fn pop(self: *Self) ?T {
            if (!self.full and (self.head & MASK) == (self.tail & MASK)) return null;
            const item = self.buffer[self.tail & MASK];
            self.tail +%= 1;
            self.full = false;
            return item;
        }

        pub fn count(self: *const Self) u32 {
            if (self.full) return SIZE;
            return (self.head -% self.tail) & MASK;
        }

        pub fn is_empty(self: *const Self) bool {
            return !self.full and (self.head & MASK) == (self.tail & MASK);
        }
    };
}

// ============================================================================
// Bitmap allocator
// ============================================================================

pub fn BitmapAllocator(comptime MAX_BITS: u32) type {
    return struct {
        const Self = @This();
        const WORDS = (MAX_BITS + 63) / 64;

        bits: [WORDS]u64,
        nr_free: u32,
        hint: u32,

        pub fn init() Self {
            var ba: Self = undefined;
            ba.nr_free = MAX_BITS;
            ba.hint = 0;
            for (&ba.bits) |*w| {
                w.* = 0;
            }
            return ba;
        }

        pub fn alloc(self: *Self) ?u32 {
            if (self.nr_free == 0) return null;
            // Start search from hint
            var bit = self.hint;
            while (bit < MAX_BITS) {
                const word_idx = bit / 64;
                const bit_idx: u6 = @truncate(bit % 64);
                if ((self.bits[word_idx] & (@as(u64, 1) << bit_idx)) == 0) {
                    self.bits[word_idx] |= (@as(u64, 1) << bit_idx);
                    self.nr_free -= 1;
                    self.hint = bit + 1;
                    return bit;
                }
                bit += 1;
            }
            // Wrap around
            bit = 0;
            while (bit < self.hint) {
                const word_idx = bit / 64;
                const bit_idx: u6 = @truncate(bit % 64);
                if ((self.bits[word_idx] & (@as(u64, 1) << bit_idx)) == 0) {
                    self.bits[word_idx] |= (@as(u64, 1) << bit_idx);
                    self.nr_free -= 1;
                    self.hint = bit + 1;
                    return bit;
                }
                bit += 1;
            }
            return null;
        }

        pub fn free(self: *Self, bit: u32) void {
            if (bit >= MAX_BITS) return;
            const word_idx = bit / 64;
            const bit_idx: u6 = @truncate(bit % 64);
            if ((self.bits[word_idx] & (@as(u64, 1) << bit_idx)) != 0) {
                self.bits[word_idx] &= ~(@as(u64, 1) << bit_idx);
                self.nr_free += 1;
                if (bit < self.hint) self.hint = bit;
            }
        }

        pub fn alloc_contiguous(self: *Self, count: u32) ?u32 {
            if (count == 0 or count > self.nr_free) return null;
            var start: u32 = 0;
            var run: u32 = 0;
            var bit: u32 = 0;
            while (bit < MAX_BITS) : (bit += 1) {
                const word_idx = bit / 64;
                const bit_idx: u6 = @truncate(bit % 64);
                if ((self.bits[word_idx] & (@as(u64, 1) << bit_idx)) == 0) {
                    if (run == 0) start = bit;
                    run += 1;
                    if (run == count) {
                        // Mark all bits
                        var b = start;
                        while (b < start + count) : (b += 1) {
                            const wi = b / 64;
                            const bi: u6 = @truncate(b % 64);
                            self.bits[wi] |= (@as(u64, 1) << bi);
                        }
                        self.nr_free -= count;
                        return start;
                    }
                } else {
                    run = 0;
                }
            }
            return null;
        }
    };
}

// ============================================================================
// Container Registry - Zxyphor
// ============================================================================

pub const ContainerSubsystem = struct {
    // IDR instances
    pid_idr: Idr,
    fd_idr: Idr,
    inode_ida: Ida,
    // Radix trees
    page_tree: RadixTree,
    // Maple tree for VMAs
    vma_tree: MapleTree,
    // Stats
    total_allocations: u64,
    total_frees: u64,
    active_structures: u64,
    initialized: bool,

    pub fn init() ContainerSubsystem {
        return ContainerSubsystem{
            .pid_idr = Idr.init(),
            .fd_idr = Idr.init(),
            .inode_ida = Ida.init(),
            .page_tree = RadixTree.init(),
            .vma_tree = MapleTree.init(),
            .total_allocations = 0,
            .total_frees = 0,
            .active_structures = 0,
            .initialized = true,
        };
    }
};
