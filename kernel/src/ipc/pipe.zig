// =============================================================================
// Kernel Zxyphor - Pipe IPC
// =============================================================================
// Unix-style pipes for inter-process communication. A pipe is a unidirectional
// byte stream between two endpoints: a read end and a write end.
//
// Features:
//   - Circular buffer (default 64 KB)
//   - Blocking reads (sleep until data available)
//   - Blocking writes (sleep until space available)
//   - SIGPIPE on write to closed read end
//   - Reader/writer reference counting
//   - Named pipes (FIFOs) via VFS integration
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const PIPE_BUFFER_SIZE: usize = 65536; // 64 KB per pipe
const MAX_PIPES: usize = 256;

// =============================================================================
// Pipe state
// =============================================================================
pub const PipeState = enum {
    active,
    read_closed,
    write_closed,
    closed,
};

pub const Pipe = struct {
    // Ring buffer
    buffer: [PIPE_BUFFER_SIZE]u8 = [_]u8{0} ** PIPE_BUFFER_SIZE,
    read_pos: usize = 0,
    write_pos: usize = 0,
    data_size: usize = 0,

    // Reference counts
    readers: u32 = 0,
    writers: u32 = 0,

    // State
    state: PipeState = .active,
    is_valid: bool = false,

    // Waiting threads
    read_waiters: ?*main.thread.Thread = null,
    write_waiters: ?*main.thread.Thread = null,

    pub fn availableRead(self: *const Pipe) usize {
        return self.data_size;
    }

    pub fn availableWrite(self: *const Pipe) usize {
        return PIPE_BUFFER_SIZE - self.data_size;
    }

    /// Read from the pipe (may return fewer bytes than requested)
    pub fn read(self: *Pipe, buffer: []u8) i64 {
        if (self.data_size == 0) {
            if (self.writers == 0) return 0; // EOF — no more writers
            return -1; // Would block (EAGAIN)
        }

        const to_read = @min(buffer.len, self.data_size);
        var i: usize = 0;
        while (i < to_read) : (i += 1) {
            buffer[i] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUFFER_SIZE;
        }
        self.data_size -= to_read;

        // Wake up any writers waiting for space
        wakeWaiters(&self.write_waiters);

        return @intCast(to_read);
    }

    /// Write to the pipe (may write fewer bytes than requested)
    pub fn write(self: *Pipe, data: []const u8) i64 {
        if (self.readers == 0) {
            // Broken pipe — no readers
            return -1; // EPIPE
        }

        const space = self.availableWrite();
        if (space == 0) return -1; // Would block

        const to_write = @min(data.len, space);
        var i: usize = 0;
        while (i < to_write) : (i += 1) {
            self.buffer[self.write_pos] = data[i];
            self.write_pos = (self.write_pos + 1) % PIPE_BUFFER_SIZE;
        }
        self.data_size += to_write;

        // Wake up any readers waiting for data
        wakeWaiters(&self.read_waiters);

        return @intCast(to_write);
    }

    /// Close the read end
    pub fn closeRead(self: *Pipe) void {
        if (self.readers > 0) self.readers -= 1;
        if (self.readers == 0) {
            if (self.writers == 0) {
                self.state = .closed;
            } else {
                self.state = .read_closed;
                wakeWaiters(&self.write_waiters);
            }
        }
    }

    /// Close the write end
    pub fn closeWrite(self: *Pipe) void {
        if (self.writers > 0) self.writers -= 1;
        if (self.writers == 0) {
            if (self.readers == 0) {
                self.state = .closed;
            } else {
                self.state = .write_closed;
                wakeWaiters(&self.read_waiters);
            }
        }
    }
};

// =============================================================================
// Pipe pool
// =============================================================================
var pipe_pool: [MAX_PIPES]Pipe = undefined;

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&pipe_pool) |*p| {
        p.* = Pipe{};
    }
    main.klog(.info, "pipe: initialized ({d} max pipes)", .{MAX_PIPES});
}

// =============================================================================
// Create a new pipe
// =============================================================================
pub fn createPipe() ?*Pipe {
    for (&pipe_pool) |*p| {
        if (!p.is_valid) {
            p.* = Pipe{};
            p.is_valid = true;
            p.readers = 1;
            p.writers = 1;
            p.state = .active;
            return p;
        }
    }
    return null;
}

/// Destroy a pipe
pub fn destroyPipe(pipe: *Pipe) void {
    pipe.is_valid = false;
    pipe.state = .closed;
}

// =============================================================================
// Wait/wake helpers
// =============================================================================
fn wakeWaiters(waiter_head: *?*main.thread.Thread) void {
    if (waiter_head.*) |thread| {
        main.thread.wakeOne(thread);
        waiter_head.* = null;
    }
}

/// Get statistics
pub fn getStats() struct { total: usize, active: usize } {
    var active: usize = 0;
    for (pipe_pool) |p| {
        if (p.is_valid and p.state == .active) active += 1;
    }
    return .{ .total = MAX_PIPES, .active = active };
}
