// =============================================================================
// Kernel Zxyphor - Bitmap Data Structure
// =============================================================================
// Fixed-size and variable-size bitmap implementation used by the PMM (physical
// memory manager) for frame allocation tracking, and by other subsystems for
// efficient set membership operations.
//
// Operations: set, clear, test, find first set/clear, count, bulk ops.
// All operations are O(1) for single-bit or O(n/64) for scanning.
// =============================================================================

// =============================================================================
// Fixed-size Bitmap (inline array, comptime-known size)
// =============================================================================
pub fn StaticBitmap(comptime N: usize) type {
    const WORDS = (N + 63) / 64;

    return struct {
        const Self = @This();
        pub const BIT_COUNT = N;
        pub const WORD_COUNT = WORDS;

        data: [WORDS]u64 = [_]u64{0} ** WORDS,

        /// Create with all bits clear
        pub fn initClear() Self {
            return Self{};
        }

        /// Create with all bits set
        pub fn initSet() Self {
            var bm = Self{};
            @memset(&bm.data, 0xFFFFFFFFFFFFFFFF);
            // Clear excess bits in last word
            const excess = N % 64;
            if (excess != 0) {
                bm.data[WORDS - 1] = (@as(u64, 1) << @truncate(excess)) - 1;
            }
            return bm;
        }

        /// Set a bit
        pub fn set(self: *Self, index: usize) void {
            if (index >= N) return;
            self.data[index / 64] |= @as(u64, 1) << @truncate(index % 64);
        }

        /// Clear a bit
        pub fn clear(self: *Self, index: usize) void {
            if (index >= N) return;
            self.data[index / 64] &= ~(@as(u64, 1) << @truncate(index % 64));
        }

        /// Test a bit
        pub fn test_bit(self: *const Self, index: usize) bool {
            if (index >= N) return false;
            return (self.data[index / 64] & (@as(u64, 1) << @truncate(index % 64))) != 0;
        }

        /// Toggle a bit
        pub fn toggle(self: *Self, index: usize) void {
            if (index >= N) return;
            self.data[index / 64] ^= @as(u64, 1) << @truncate(index % 64);
        }

        /// Set a range of bits [start, start + count)
        pub fn setRange(self: *Self, start: usize, count_val: usize) void {
            var i: usize = 0;
            while (i < count_val) : (i += 1) {
                self.set(start + i);
            }
        }

        /// Clear a range of bits [start, start + count)
        pub fn clearRange(self: *Self, start: usize, count_val: usize) void {
            var i: usize = 0;
            while (i < count_val) : (i += 1) {
                self.clear(start + i);
            }
        }

        /// Find first clear bit (returns null if all set)
        pub fn findFirstClear(self: *const Self) ?usize {
            for (self.data, 0..) |word, wi| {
                if (word != 0xFFFFFFFFFFFFFFFF) {
                    const bit_pos = @ctz(~word);
                    const index = wi * 64 + bit_pos;
                    if (index < N) return index;
                }
            }
            return null;
        }

        /// Find first set bit (returns null if all clear)
        pub fn findFirstSet(self: *const Self) ?usize {
            for (self.data, 0..) |word, wi| {
                if (word != 0) {
                    const bit_pos = @ctz(word);
                    const index = wi * 64 + bit_pos;
                    if (index < N) return index;
                }
            }
            return null;
        }

        /// Find first clear bit starting from a given index
        pub fn findFirstClearFrom(self: *const Self, from: usize) ?usize {
            if (from >= N) return null;

            var wi = from / 64;
            var bi: u6 = @truncate(from % 64);

            // Check first (partial) word
            var word = self.data[wi] | ((@as(u64, 1) << bi) - 1); // Mask out bits before 'from'
            if (word != 0xFFFFFFFFFFFFFFFF) {
                const bit_pos = @ctz(~word);
                const index = wi * 64 + bit_pos;
                if (index < N) return index;
            }

            // Check remaining words
            wi += 1;
            while (wi < WORDS) : (wi += 1) {
                if (self.data[wi] != 0xFFFFFFFFFFFFFFFF) {
                    const bit_pos = @ctz(~self.data[wi]);
                    const index = wi * 64 + bit_pos;
                    if (index < N) return index;
                }
            }

            return null;
        }

        /// Find N consecutive clear bits
        pub fn findConsecutiveClear(self: *const Self, count_val: usize) ?usize {
            if (count_val == 0) return 0;
            if (count_val > N) return null;

            var start: usize = 0;
            var run: usize = 0;

            var i: usize = 0;
            while (i < N) : (i += 1) {
                if (!self.test_bit(i)) {
                    if (run == 0) start = i;
                    run += 1;
                    if (run >= count_val) return start;
                } else {
                    run = 0;
                }
            }

            return null;
        }

        /// Count the number of set bits
        pub fn popCount(self: *const Self) usize {
            var total: usize = 0;
            for (self.data) |word| {
                total += @popCount(word);
            }
            return total;
        }

        /// Count the number of clear bits
        pub fn clearCount(self: *const Self) usize {
            return N - self.popCount();
        }

        /// Check if all bits are set
        pub fn allSet(self: *const Self) bool {
            return self.popCount() == N;
        }

        /// Check if all bits are clear
        pub fn allClear(self: *const Self) bool {
            for (self.data) |word| {
                if (word != 0) return false;
            }
            return true;
        }

        /// Bitwise OR with another bitmap
        pub fn bitwiseOr(self: *Self, other: *const Self) void {
            for (&self.data, other.data) |*a, b| {
                a.* |= b;
            }
        }

        /// Bitwise AND with another bitmap
        pub fn bitwiseAnd(self: *Self, other: *const Self) void {
            for (&self.data, other.data) |*a, b| {
                a.* &= b;
            }
        }

        /// Bitwise XOR with another bitmap
        pub fn bitwiseXor(self: *Self, other: *const Self) void {
            for (&self.data, other.data) |*a, b| {
                a.* ^= b;
            }
        }

        /// Bitwise NOT (complement)
        pub fn bitwiseNot(self: *Self) void {
            for (&self.data) |*word| {
                word.* = ~word.*;
            }
            // Clear excess bits
            const excess = N % 64;
            if (excess != 0) {
                self.data[WORDS - 1] &= (@as(u64, 1) << @truncate(excess)) - 1;
            }
        }

        /// Clear all bits
        pub fn clearAll(self: *Self) void {
            @memset(&self.data, 0);
        }

        /// Set all bits
        pub fn setAll(self: *Self) void {
            @memset(&self.data, 0xFFFFFFFFFFFFFFFF);
            const excess = N % 64;
            if (excess != 0) {
                self.data[WORDS - 1] = (@as(u64, 1) << @truncate(excess)) - 1;
            }
        }
    };
}

// =============================================================================
// Dynamic Bitmap (runtime-sized, uses a slice)
// =============================================================================
pub const DynamicBitmap = struct {
    data: []u64,
    bit_count: usize,

    pub fn initFromSlice(slice: []u64, bits: usize) DynamicBitmap {
        @memset(slice, 0);
        return DynamicBitmap{
            .data = slice,
            .bit_count = bits,
        };
    }

    pub fn set(self: *DynamicBitmap, index: usize) void {
        if (index >= self.bit_count) return;
        self.data[index / 64] |= @as(u64, 1) << @truncate(index % 64);
    }

    pub fn clear(self: *DynamicBitmap, index: usize) void {
        if (index >= self.bit_count) return;
        self.data[index / 64] &= ~(@as(u64, 1) << @truncate(index % 64));
    }

    pub fn test_bit(self: *const DynamicBitmap, index: usize) bool {
        if (index >= self.bit_count) return false;
        return (self.data[index / 64] & (@as(u64, 1) << @truncate(index % 64))) != 0;
    }

    pub fn findFirstClear(self: *const DynamicBitmap) ?usize {
        const words = (self.bit_count + 63) / 64;
        for (self.data[0..words], 0..) |word, wi| {
            if (word != 0xFFFFFFFFFFFFFFFF) {
                const bit_pos = @ctz(~word);
                const index = wi * 64 + bit_pos;
                if (index < self.bit_count) return index;
            }
        }
        return null;
    }

    pub fn popCount(self: *const DynamicBitmap) usize {
        var total: usize = 0;
        const words = (self.bit_count + 63) / 64;
        for (self.data[0..words]) |word| {
            total += @popCount(word);
        }
        return total;
    }
};
