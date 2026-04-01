// =============================================================================
// Kernel Zxyphor - Ring Buffer
// =============================================================================
// Generic ring buffer (circular buffer) implementation used for:
//   - Keyboard input buffering
//   - Serial port FIFOs
//   - Pipe I/O buffers
//   - Network packet queues
//   - Log buffering
//
// This is a power-of-2 sized ring buffer that uses masking instead of
// modulo operations for maximum performance. Supports both single-item
// and bulk (slice) operations.
// =============================================================================

// =============================================================================
// Static Ring Buffer (comptime-known capacity, must be power of 2)
// =============================================================================
pub fn RingBuffer(comptime T: type, comptime CAPACITY: usize) type {
    // Verify power of 2
    if (CAPACITY == 0 or (CAPACITY & (CAPACITY - 1)) != 0) {
        @compileError("RingBuffer capacity must be a power of 2");
    }

    const MASK = CAPACITY - 1;

    return struct {
        const Self = @This();
        pub const capacity = CAPACITY;

        data: [CAPACITY]T = [_]T{undefined} ** CAPACITY,
        head: usize = 0, // Next read position
        tail: usize = 0, // Next write position

        pub fn init() Self {
            return Self{};
        }

        /// Number of items currently in the buffer
        pub fn count(self: *const Self) usize {
            return self.tail -% self.head;
        }

        /// Available space for writing
        pub fn space(self: *const Self) usize {
            return CAPACITY - self.count();
        }

        /// Check if buffer is empty
        pub fn isEmpty(self: *const Self) bool {
            return self.head == self.tail;
        }

        /// Check if buffer is full
        pub fn isFull(self: *const Self) bool {
            return self.count() == CAPACITY;
        }

        /// Write one item (returns false if full)
        pub fn write(self: *Self, item: T) bool {
            if (self.isFull()) return false;
            self.data[self.tail & MASK] = item;
            self.tail +%= 1;
            return true;
        }

        /// Read one item (returns null if empty)
        pub fn read(self: *Self) ?T {
            if (self.isEmpty()) return null;
            const item = self.data[self.head & MASK];
            self.head +%= 1;
            return item;
        }

        /// Peek at the next item without consuming it
        pub fn peek(self: *const Self) ?T {
            if (self.isEmpty()) return null;
            return self.data[self.head & MASK];
        }

        /// Peek at item at offset from head (0 = next read)
        pub fn peekAt(self: *const Self, offset: usize) ?T {
            if (offset >= self.count()) return null;
            return self.data[(self.head +% offset) & MASK];
        }

        /// Write multiple items, returns number actually written
        pub fn writeSlice(self: *Self, items: []const T) usize {
            var written: usize = 0;
            for (items) |item| {
                if (!self.write(item)) break;
                written += 1;
            }
            return written;
        }

        /// Read multiple items into a buffer, returns number actually read
        pub fn readSlice(self: *Self, buf: []T) usize {
            var count_val: usize = 0;
            while (count_val < buf.len) {
                buf[count_val] = self.read() orelse break;
                count_val += 1;
            }
            return count_val;
        }

        /// Discard N items from the read end
        pub fn discard(self: *Self, n: usize) usize {
            const to_discard = @min(n, self.count());
            self.head +%= to_discard;
            return to_discard;
        }

        /// Clear the buffer (discard everything)
        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
        }

        /// Force-write an item even if full (overwrites oldest)
        pub fn forceWrite(self: *Self, item: T) void {
            if (self.isFull()) {
                self.head +%= 1; // Drop oldest
            }
            self.data[self.tail & MASK] = item;
            self.tail +%= 1;
        }
    };
}

// =============================================================================
// Byte Ring Buffer (optimized for u8, with efficient bulk operations)
// =============================================================================
pub fn ByteRingBuffer(comptime CAPACITY: usize) type {
    if (CAPACITY == 0 or (CAPACITY & (CAPACITY - 1)) != 0) {
        @compileError("ByteRingBuffer capacity must be a power of 2");
    }

    const MASK = CAPACITY - 1;

    return struct {
        const Self = @This();
        pub const capacity = CAPACITY;

        data: [CAPACITY]u8 = [_]u8{0} ** CAPACITY,
        head: usize = 0,
        tail: usize = 0,

        pub fn init() Self {
            return Self{};
        }

        pub fn count(self: *const Self) usize {
            return self.tail -% self.head;
        }

        pub fn space(self: *const Self) usize {
            return CAPACITY - self.count();
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head == self.tail;
        }

        pub fn isFull(self: *const Self) bool {
            return self.count() == CAPACITY;
        }

        /// Write bytes from a slice, returns number of bytes written
        pub fn writeBytes(self: *Self, src: []const u8) usize {
            const avail = self.space();
            const to_write = @min(src.len, avail);
            if (to_write == 0) return 0;

            const pos = self.tail & MASK;
            const first_chunk = @min(to_write, CAPACITY - pos);

            @memcpy(self.data[pos .. pos + first_chunk], src[0..first_chunk]);
            if (first_chunk < to_write) {
                const second_chunk = to_write - first_chunk;
                @memcpy(self.data[0..second_chunk], src[first_chunk .. first_chunk + second_chunk]);
            }

            self.tail +%= to_write;
            return to_write;
        }

        /// Read bytes into a buffer, returns number of bytes read
        pub fn readBytes(self: *Self, dst: []u8) usize {
            const avail = self.count();
            const to_read = @min(dst.len, avail);
            if (to_read == 0) return 0;

            const pos = self.head & MASK;
            const first_chunk = @min(to_read, CAPACITY - pos);

            @memcpy(dst[0..first_chunk], self.data[pos .. pos + first_chunk]);
            if (first_chunk < to_read) {
                const second_chunk = to_read - first_chunk;
                @memcpy(dst[first_chunk .. first_chunk + second_chunk], self.data[0..second_chunk]);
            }

            self.head +%= to_read;
            return to_read;
        }

        /// Write a single byte
        pub fn writeByte(self: *Self, b: u8) bool {
            if (self.isFull()) return false;
            self.data[self.tail & MASK] = b;
            self.tail +%= 1;
            return true;
        }

        /// Read a single byte
        pub fn readByte(self: *Self) ?u8 {
            if (self.isEmpty()) return null;
            const b = self.data[self.head & MASK];
            self.head +%= 1;
            return b;
        }

        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
        }
    };
}

// =============================================================================
// Common presets
// =============================================================================
pub const KeyboardBuffer = RingBuffer(u8, 256);
pub const SerialBuffer = RingBuffer(u8, 4096);
pub const LogBuffer = ByteRingBuffer(65536);
pub const PipeBuffer = ByteRingBuffer(65536);
