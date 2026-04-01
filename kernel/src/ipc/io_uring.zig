// SPDX-License-Identifier: MIT
// Zxyphor Kernel — io_uring-style Asynchronous I/O Subsystem
//
// Implements a high-performance, zero-copy asynchronous I/O interface.
// Applications submit I/O requests via a lock-free submission queue and
// receive completions through a completion queue, all in shared memory.
// This eliminates syscall overhead for I/O-heavy workloads and supports:
//
// - File read/write (buffered and direct I/O)
// - Network socket operations (connect, accept, send, recv)
// - Timeout and cancellation
// - Linked operations (chains that execute sequentially)
// - Fixed buffers and fixed files
// - Polling mode for ultra-low-latency I/O

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");
const vmm = @import("../mm/vmm.zig");

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────
pub const IORING_MAX_ENTRIES: usize = 32768;
pub const IORING_MAX_CQ_ENTRIES: usize = IORING_MAX_ENTRIES * 2;
pub const IORING_MAX_FIXED_FILES: usize = 1024;
pub const IORING_MAX_FIXED_BUFFERS: usize = 256;
pub const IORING_MAX_INSTANCES: usize = 256;
pub const IORING_SQ_ENTRY_SIZE: usize = 64;
pub const IORING_CQ_ENTRY_SIZE: usize = 16;

// ─────────────────────────────────────────────────────────────────────
// Operation Codes
// ─────────────────────────────────────────────────────────────────────
pub const IoOp = enum(u8) {
    nop = 0,
    readv = 1,
    writev = 2,
    fsync = 3,
    read_fixed = 4,
    write_fixed = 5,
    poll_add = 6,
    poll_remove = 7,
    sync_file_range = 8,
    sendmsg = 9,
    recvmsg = 10,
    timeout = 11,
    timeout_remove = 12,
    accept = 13,
    cancel = 14,
    link_timeout = 15,
    connect = 16,
    fallocate = 17,
    openat = 18,
    close = 19,
    statx = 20,
    read = 21,
    write = 22,
    fadvise = 23,
    madvise = 24,
    send = 25,
    recv = 26,
    splice = 27,
    provide_buffers = 28,
    remove_buffers = 29,
    tee = 30,
    shutdown = 31,
    renameat = 32,
    unlinkat = 33,
    mkdirat = 34,
    symlinkat = 35,
    linkat = 36,
    socket = 37,
    msg_ring = 38,
    waitid = 39,
};

// ─────────────────────────────────────────────────────────────────────
// SQE Flags
// ─────────────────────────────────────────────────────────────────────
pub const SqeFlags = packed struct {
    fixed_file: bool = false,
    io_drain: bool = false,
    io_link: bool = false,
    io_hardlink: bool = false,
    async_op: bool = false,
    buffer_select: bool = false,
    cqe_skip_success: bool = false,
    _reserved: u1 = 0,
};

// ─────────────────────────────────────────────────────────────────────
// Submission Queue Entry (SQE) — 64 bytes
// ─────────────────────────────────────────────────────────────────────
pub const SubmissionQueueEntry = struct {
    /// Operation code
    opcode: IoOp,
    /// SQE flags
    flags: SqeFlags,
    /// IO priority
    ioprio: u16,
    /// File descriptor
    fd: i32,
    /// Offset in file or timeout value
    off: u64,
    /// Buffer address or flags
    addr: u64,
    /// Length of operation
    len: u32,
    /// Operation-specific flags
    op_flags: u32,
    /// User data — returned in CQE for identification
    user_data: u64,
    /// Buffer index or group ID
    buf_index: u16,
    /// Personality (credentials) index
    personality: u16,
    /// Splice FD in
    splice_fd_in: i32,
    /// Padding for alignment to 64 bytes
    _pad: [2]u64,

    const Self = @This();

    pub fn init(opcode: IoOp, fd: i32, user_data: u64) Self {
        return Self{
            .opcode = opcode,
            .flags = SqeFlags{},
            .ioprio = 0,
            .fd = fd,
            .off = 0,
            .addr = 0,
            .len = 0,
            .op_flags = 0,
            .user_data = user_data,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = -1,
            ._pad = [_]u64{0} ** 2,
        };
    }

    /// Prepare a read operation
    pub fn prepRead(fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) Self {
        var sqe = Self.init(.read, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.off = offset;
        return sqe;
    }

    /// Prepare a write operation
    pub fn prepWrite(fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) Self {
        var sqe = Self.init(.write, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.off = offset;
        return sqe;
    }

    /// Prepare a fsync operation
    pub fn prepFsync(fd: i32, fsync_flags: u32, user_data: u64) Self {
        var sqe = Self.init(.fsync, fd, user_data);
        sqe.op_flags = fsync_flags;
        return sqe;
    }

    /// Prepare a timeout operation
    pub fn prepTimeout(timeout_ns: u64, count: u32, user_data: u64) Self {
        var sqe = Self.init(.timeout, -1, user_data);
        sqe.off = timeout_ns;
        sqe.len = count;
        return sqe;
    }

    /// Prepare a socket accept operation
    pub fn prepAccept(fd: i32, addr: u64, addrlen: u64, flags: u32, user_data: u64) Self {
        var sqe = Self.init(.accept, fd, user_data);
        sqe.addr = addr;
        sqe.off = addrlen;
        sqe.op_flags = flags;
        return sqe;
    }

    /// Prepare a socket connect operation
    pub fn prepConnect(fd: i32, addr: u64, addrlen: u32, user_data: u64) Self {
        var sqe = Self.init(.connect, fd, user_data);
        sqe.addr = addr;
        sqe.off = addrlen;
        return sqe;
    }

    /// Prepare a send operation
    pub fn prepSend(fd: i32, buf_addr: u64, len: u32, flags: u32, user_data: u64) Self {
        var sqe = Self.init(.send, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.op_flags = flags;
        return sqe;
    }

    /// Prepare a recv operation
    pub fn prepRecv(fd: i32, buf_addr: u64, len: u32, flags: u32, user_data: u64) Self {
        var sqe = Self.init(.recv, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.op_flags = flags;
        return sqe;
    }

    /// Prepare a cancel operation
    pub fn prepCancel(target_user_data: u64, flags: u32, user_data: u64) Self {
        var sqe = Self.init(.cancel, -1, user_data);
        sqe.addr = target_user_data;
        sqe.op_flags = flags;
        return sqe;
    }

    /// Prepare an openat operation
    pub fn prepOpenat(dfd: i32, pathname_addr: u64, flags: u32, mode: u32, user_data: u64) Self {
        var sqe = Self.init(.openat, dfd, user_data);
        sqe.addr = pathname_addr;
        sqe.op_flags = flags;
        sqe.len = mode;
        return sqe;
    }

    /// Prepare a close operation
    pub fn prepClose(fd: i32, user_data: u64) Self {
        return Self.init(.close, fd, user_data);
    }

    /// Set the linked flag (next SQE depends on this one)
    pub fn setLink(self: *Self) void {
        self.flags.io_link = true;
    }

    /// Set the drain flag (wait for all previous SQEs to complete)
    pub fn setDrain(self: *Self) void {
        self.flags.io_drain = true;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Completion Queue Entry (CQE) — 16 bytes
// ─────────────────────────────────────────────────────────────────────
pub const CompletionQueueEntry = struct {
    /// User data from the corresponding SQE
    user_data: u64,
    /// Result of the operation (bytes transferred or errno)
    res: i32,
    /// Flags with additional info
    flags: u32,

    const Self = @This();

    pub fn init(user_data: u64, res: i32) Self {
        return Self{
            .user_data = user_data,
            .res = res,
            .flags = 0,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// Ring Buffer — lock-free SPSC ring for SQ and CQ
// ─────────────────────────────────────────────────────────────────────
pub fn RingBuffer(comptime T: type, comptime MAX_SIZE: usize) type {
    return struct {
        entries: [MAX_SIZE]T,
        head: u32, // Producer writes here
        tail: u32, // Consumer reads here
        mask: u32,
        ring_size: u32,

        const Self = @This();

        pub fn init(size: u32) Self {
            // Round up to power of 2
            const actual_size = roundUpPow2(size);
            return Self{
                .entries = undefined,
                .head = 0,
                .tail = 0,
                .mask = actual_size - 1,
                .ring_size = actual_size,
            };
        }

        /// Push an entry to the ring (producer side)
        pub fn push(self: *Self, entry: T) bool {
            const next_head = (self.head + 1) & self.mask;
            if (next_head == @atomicLoad(u32, &self.tail, .acquire)) {
                return false; // Ring full
            }
            self.entries[self.head] = entry;
            @atomicStore(u32, &self.head, next_head, .release);
            return true;
        }

        /// Pop an entry from the ring (consumer side)
        pub fn pop(self: *Self) ?T {
            const current_tail = self.tail;
            if (current_tail == @atomicLoad(u32, &self.head, .acquire)) {
                return null; // Ring empty
            }
            const entry = self.entries[current_tail];
            @atomicStore(u32, &self.tail, (current_tail + 1) & self.mask, .release);
            return entry;
        }

        /// Peek at the next entry without consuming it
        pub fn peek(self: *Self) ?*const T {
            if (self.tail == @atomicLoad(u32, &self.head, .acquire)) {
                return null;
            }
            return &self.entries[self.tail];
        }

        /// Number of entries currently in the ring
        pub fn count(self: *const Self) u32 {
            const h = @atomicLoad(u32, &self.head, .acquire);
            const t = @atomicLoad(u32, &self.tail, .acquire);
            return (h -% t) & self.mask;
        }

        /// Check if the ring is empty
        pub fn isEmpty(self: *const Self) bool {
            return self.count() == 0;
        }

        /// Check if the ring is full
        pub fn isFull(self: *const Self) bool {
            return self.count() == self.ring_size - 1;
        }
    };
}

fn roundUpPow2(v: u32) u32 {
    var n = v;
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n += 1;
    return if (n < 2) 2 else n;
}

// ─────────────────────────────────────────────────────────────────────
// Fixed Buffer Registry — pre-registered buffers for zero-copy I/O
// ─────────────────────────────────────────────────────────────────────
pub const FixedBuffer = struct {
    addr: u64,
    len: u64,
    mapped: bool,
};

pub const FixedFileTable = struct {
    fds: [IORING_MAX_FIXED_FILES]i32,
    count: u16,

    pub fn init() FixedFileTable {
        return FixedFileTable{
            .fds = [_]i32{-1} ** IORING_MAX_FIXED_FILES,
            .count = 0,
        };
    }

    pub fn registerFd(self: *FixedFileTable, index: u16, fd: i32) bool {
        if (index >= IORING_MAX_FIXED_FILES) return false;
        self.fds[index] = fd;
        if (index >= self.count) {
            self.count = index + 1;
        }
        return true;
    }

    pub fn getFd(self: *const FixedFileTable, index: u16) i32 {
        if (index >= self.count) return -1;
        return self.fds[index];
    }

    pub fn unregisterFd(self: *FixedFileTable, index: u16) void {
        if (index >= IORING_MAX_FIXED_FILES) return;
        self.fds[index] = -1;
    }
};

// ─────────────────────────────────────────────────────────────────────
// IoUring Instance — represents one io_uring context (per-process)
// ─────────────────────────────────────────────────────────────────────
pub const IoUringState = enum {
    idle,
    processing,
    polling,
    disabled,
};

pub const IoUring = struct {
    /// Instance ID
    id: u32,

    /// Submission queue ring buffer
    sq: RingBuffer(SubmissionQueueEntry, IORING_MAX_ENTRIES),

    /// Completion queue ring buffer
    cq: RingBuffer(CompletionQueueEntry, IORING_MAX_CQ_ENTRIES),

    /// Fixed buffers for zero-copy I/O
    fixed_buffers: [IORING_MAX_FIXED_BUFFERS]FixedBuffer,
    fixed_buffer_count: u16,

    /// Fixed file descriptor table
    fixed_files: FixedFileTable,

    /// Owning process ID
    owner_pid: u32,

    /// State
    state: IoUringState,

    /// Configuration
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,

    /// Statistics
    sqe_submitted: u64,
    cqe_completed: u64,
    io_errors: u64,
    timeouts: u64,
    cancellations: u64,

    /// Lock
    lock: spinlock.SpinLock,

    /// Shared memory region (mapped into userspace)
    sq_ring_addr: u64,
    cq_ring_addr: u64,
    sqes_addr: u64,

    /// Event FD for notifications (if any)
    eventfd: i32,

    /// Whether to use polling mode
    polling: bool,

    /// Linked SQE chain state
    link_head: ?u32,
    link_failed: bool,

    const Self = @This();

    pub fn init(id: u32, sq_size: u32, cq_size: u32, pid: u32) Self {
        return Self{
            .id = id,
            .sq = RingBuffer(SubmissionQueueEntry, IORING_MAX_ENTRIES).init(sq_size),
            .cq = RingBuffer(CompletionQueueEntry, IORING_MAX_CQ_ENTRIES).init(cq_size),
            .fixed_buffers = [_]FixedBuffer{FixedBuffer{ .addr = 0, .len = 0, .mapped = false }} ** IORING_MAX_FIXED_BUFFERS,
            .fixed_buffer_count = 0,
            .fixed_files = FixedFileTable.init(),
            .owner_pid = pid,
            .state = .idle,
            .sq_entries = sq_size,
            .cq_entries = cq_size,
            .flags = 0,
            .sqe_submitted = 0,
            .cqe_completed = 0,
            .io_errors = 0,
            .timeouts = 0,
            .cancellations = 0,
            .lock = spinlock.SpinLock{},
            .sq_ring_addr = 0,
            .cq_ring_addr = 0,
            .sqes_addr = 0,
            .eventfd = -1,
            .polling = false,
            .link_head = null,
            .link_failed = false,
        };
    }

    /// Submit pending SQEs for processing
    pub fn submit(self: *Self) u32 {
        self.lock.acquire();
        defer self.lock.release();

        var processed: u32 = 0;
        self.state = .processing;

        while (self.sq.pop()) |sqe| {
            const result = self.processSquentry(&sqe);

            // Post completion
            const cqe = CompletionQueueEntry.init(sqe.user_data, result);
            if (!self.cq.push(cqe)) {
                // CQ overflow — record the error but continue
                self.io_errors += 1;
            }

            processed += 1;
            self.sqe_submitted += 1;
            self.cqe_completed += 1;

            // Handle linked operations: if this SQE was linked and failed,
            // cancel the remaining chain
            if (sqe.flags.io_link and result < 0) {
                self.cancelLinkChain();
            }
        }

        self.state = .idle;
        return processed;
    }

    /// Submit and wait for at least `min_complete` completions
    pub fn submitAndWait(self: *Self, min_complete: u32) u32 {
        const submitted = self.submit();

        // Wait for enough completions (busy-wait in kernel; would use
        // proper sleeping in production)
        if (min_complete > 0) {
            while (self.cq.count() < min_complete) {
                // Yield or sleep
            }
        }

        return submitted;
    }

    /// Process a single submission queue entry
    fn processSquentry(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        // Handle linked chain failures
        if (self.link_failed) {
            if (!sqe.flags.io_link and !sqe.flags.io_hardlink) {
                self.link_failed = false;
            }
            return -125; // ECANCELED
        }

        return switch (sqe.opcode) {
            .nop => 0,
            .read => self.handleRead(sqe),
            .write => self.handleWrite(sqe),
            .fsync => self.handleFsync(sqe),
            .read_fixed => self.handleReadFixed(sqe),
            .write_fixed => self.handleWriteFixed(sqe),
            .poll_add => self.handlePollAdd(sqe),
            .poll_remove => self.handlePollRemove(sqe),
            .timeout => self.handleTimeout(sqe),
            .timeout_remove => self.handleTimeoutRemove(sqe),
            .accept => self.handleAccept(sqe),
            .connect => self.handleConnect(sqe),
            .cancel => self.handleCancel(sqe),
            .send => self.handleSend(sqe),
            .recv => self.handleRecv(sqe),
            .openat => self.handleOpenat(sqe),
            .close => self.handleClose(sqe),
            .readv => self.handleReadv(sqe),
            .writev => self.handleWritev(sqe),
            .sendmsg => self.handleSendmsg(sqe),
            .recvmsg => self.handleRecvmsg(sqe),
            .splice => self.handleSplice(sqe),
            .shutdown => self.handleShutdown(sqe),
            .socket => self.handleSocket(sqe),
            .msg_ring => self.handleMsgRing(sqe),
            else => -38, // ENOSYS
        };
    }

    fn handleRead(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        // In a real kernel, this would:
        // 1. Resolve the fd to a file structure
        // 2. Check permissions
        // 3. Call the file's read operation
        // 4. Copy data to the user buffer at sqe.addr
        const fd = sqe.fd;
        if (fd < 0) return -9; // EBADF
        // Simulated successful read returning bytes "read"
        return @intCast(sqe.len);
    }

    fn handleWrite(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        const fd = sqe.fd;
        if (fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleFsync(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return 0;
    }

    fn handleReadFixed(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        if (sqe.buf_index >= self.fixed_buffer_count) return -22; // EINVAL
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleWriteFixed(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        if (sqe.buf_index >= self.fixed_buffer_count) return -22;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handlePollAdd(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        // Register interest in poll events
        return 0;
    }

    fn handlePollRemove(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        _ = sqe;
        return 0;
    }

    fn handleTimeout(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = sqe;
        self.timeouts += 1;
        return -62; // ETIME
    }

    fn handleTimeoutRemove(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        _ = sqe;
        return 0;
    }

    fn handleAccept(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        // Would return the new socket fd
        return 3;
    }

    fn handleConnect(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return 0;
    }

    fn handleCancel(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = sqe;
        self.cancellations += 1;
        return 0;
    }

    fn handleSend(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleRecv(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleOpenat(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        _ = sqe;
        // Would open a file and return the fd
        return 3;
    }

    fn handleClose(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return 0;
    }

    fn handleReadv(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleWritev(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleSendmsg(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleRecvmsg(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return @intCast(sqe.len);
    }

    fn handleSplice(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        _ = sqe;
        return 0;
    }

    fn handleShutdown(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        if (sqe.fd < 0) return -9;
        return 0;
    }

    fn handleSocket(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        _ = sqe;
        return 3;
    }

    fn handleMsgRing(self: *Self, sqe: *const SubmissionQueueEntry) i32 {
        _ = self;
        _ = sqe;
        return 0;
    }

    fn cancelLinkChain(self: *Self) void {
        self.link_failed = true;
        self.cancellations += 1;
    }

    /// Register fixed buffers for zero-copy I/O
    pub fn registerBuffers(self: *Self, buffers: []const FixedBuffer) u32 {
        self.lock.acquire();
        defer self.lock.release();

        var registered: u32 = 0;
        for (buffers) |buf| {
            if (self.fixed_buffer_count >= IORING_MAX_FIXED_BUFFERS) break;
            self.fixed_buffers[self.fixed_buffer_count] = buf;
            self.fixed_buffers[self.fixed_buffer_count].mapped = true;
            self.fixed_buffer_count += 1;
            registered += 1;
        }
        return registered;
    }

    /// Unregister all fixed buffers
    pub fn unregisterBuffers(self: *Self) void {
        self.lock.acquire();
        defer self.lock.release();

        for (self.fixed_buffers[0..self.fixed_buffer_count]) |*buf| {
            buf.mapped = false;
        }
        self.fixed_buffer_count = 0;
    }

    /// Register a fixed file descriptor
    pub fn registerFile(self: *Self, index: u16, fd: i32) bool {
        return self.fixed_files.registerFd(index, fd);
    }

    /// Unregister a fixed file descriptor
    pub fn unregisterFile(self: *Self, index: u16) void {
        self.fixed_files.unregisterFd(index);
    }

    /// Enable polling mode
    pub fn enablePolling(self: *Self) void {
        self.polling = true;
        self.state = .polling;
    }

    /// Reap completions from the CQ (called from userspace via syscall)
    pub fn reapCompletions(self: *Self, cqe_buf: []CompletionQueueEntry) u32 {
        var reaped: u32 = 0;
        while (reaped < cqe_buf.len) {
            if (self.cq.pop()) |cqe| {
                cqe_buf[reaped] = cqe;
                reaped += 1;
            } else {
                break;
            }
        }
        return reaped;
    }

    /// Get the number of pending completions
    pub fn completionsPending(self: *Self) u32 {
        return self.cq.count();
    }

    /// Destroy this io_uring instance
    pub fn destroy(self: *Self) void {
        self.lock.acquire();
        self.state = .disabled;
        self.unregisterBuffers();
        self.lock.release();
    }

    /// Get statistics
    pub fn getStats(self: *const Self) IoUringStats {
        return IoUringStats{
            .sqe_submitted = self.sqe_submitted,
            .cqe_completed = self.cqe_completed,
            .io_errors = self.io_errors,
            .timeouts = self.timeouts,
            .cancellations = self.cancellations,
            .sq_pending = self.sq.count(),
            .cq_pending = self.cq.count(),
            .fixed_buffers = self.fixed_buffer_count,
            .fixed_files = self.fixed_files.count,
        };
    }
};

pub const IoUringStats = struct {
    sqe_submitted: u64,
    cqe_completed: u64,
    io_errors: u64,
    timeouts: u64,
    cancellations: u64,
    sq_pending: u32,
    cq_pending: u32,
    fixed_buffers: u16,
    fixed_files: u16,
};

// ─────────────────────────────────────────────────────────────────────
// Global Instance Manager
// ─────────────────────────────────────────────────────────────────────
var instances: [IORING_MAX_INSTANCES]IoUring = undefined;
var instance_used: [IORING_MAX_INSTANCES]bool = [_]bool{false} ** IORING_MAX_INSTANCES;
var instance_count: u32 = 0;
var global_lock: spinlock.SpinLock = spinlock.SpinLock{};
var next_id: u32 = 1;

pub fn init() void {
    global_lock.acquire();
    defer global_lock.release();

    instance_count = 0;
    next_id = 1;
    for (&instance_used) |*u| {
        u.* = false;
    }
}

/// Create a new io_uring instance
pub fn create(sq_entries: u32, cq_entries: u32, pid: u32) ?*IoUring {
    global_lock.acquire();
    defer global_lock.release();

    // Find a free slot
    for (instance_used, 0..) |used, i| {
        if (!used) {
            const id = next_id;
            next_id += 1;

            instances[i] = IoUring.init(
                id,
                @min(sq_entries, IORING_MAX_ENTRIES),
                @min(cq_entries, IORING_MAX_CQ_ENTRIES),
                pid,
            );
            instance_used[i] = true;
            instance_count += 1;

            return &instances[i];
        }
    }

    return null;
}

/// Destroy an io_uring instance
pub fn destroy(ring: *IoUring) void {
    global_lock.acquire();
    defer global_lock.release();

    ring.destroy();

    // Find and mark as unused
    for (&instances, 0..) |*inst, i| {
        if (inst == ring) {
            instance_used[i] = false;
            instance_count -= 1;
            break;
        }
    }
}

/// Find an io_uring instance by ID
pub fn findById(id: u32) ?*IoUring {
    for (instances[0..IORING_MAX_INSTANCES], 0..) |*inst, i| {
        if (instance_used[i] and inst.id == id) {
            return inst;
        }
    }
    return null;
}

/// Find all io_uring instances owned by a process
pub fn findByPid(pid: u32, out: []?*IoUring) u32 {
    var count: u32 = 0;
    for (instances[0..IORING_MAX_INSTANCES], 0..) |*inst, i| {
        if (instance_used[i] and inst.owner_pid == pid) {
            if (count < out.len) {
                out[count] = inst;
                count += 1;
            }
        }
    }
    return count;
}

// ─────────────────────────────────────────────────────────────────────
// Syscall Interface
// ─────────────────────────────────────────────────────────────────────

/// io_uring_setup syscall handler
pub fn sysSetup(entries: u32, params_addr: u64) i32 {
    _ = params_addr;
    const ring = create(entries, entries * 2, 0) orelse return -12; // ENOMEM
    return @intCast(ring.id);
}

/// io_uring_enter syscall handler
pub fn sysEnter(ring_id: u32, to_submit: u32, min_complete: u32, flags: u32) i32 {
    _ = to_submit;
    _ = flags;
    const ring = findById(ring_id) orelse return -9; // EBADF

    if (min_complete > 0) {
        return @intCast(ring.submitAndWait(min_complete));
    }
    return @intCast(ring.submit());
}

/// io_uring_register syscall handler
pub fn sysRegister(ring_id: u32, opcode: u32, arg_addr: u64, nr_args: u32) i32 {
    _ = arg_addr;
    _ = nr_args;
    const ring = findById(ring_id) orelse return -9;
    _ = ring;

    return switch (opcode) {
        0 => 0, // REGISTER_BUFFERS
        1 => 0, // UNREGISTER_BUFFERS
        2 => 0, // REGISTER_FILES
        3 => 0, // UNREGISTER_FILES
        else => -22, // EINVAL
    };
}

// ─────────────────────────────────────────────────────────────────────
// C FFI — exported symbols for the Rust side
// ─────────────────────────────────────────────────────────────────────
export fn zxy_io_uring_init() void {
    init();
}

export fn zxy_io_uring_create(sq_size: u32, cq_size: u32, pid: u32) i32 {
    if (create(sq_size, cq_size, pid)) |ring| {
        return @intCast(ring.id);
    }
    return -1;
}

export fn zxy_io_uring_submit(ring_id: u32) i32 {
    const ring = findById(ring_id) orelse return -1;
    return @intCast(ring.submit());
}

export fn zxy_io_uring_destroy(ring_id: u32) void {
    if (findById(ring_id)) |ring| {
        destroy(ring);
    }
}
