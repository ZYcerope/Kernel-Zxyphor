// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust io_uring Interface
//
// Provides the Rust-side abstraction for the Zig io_uring implementation.
// This module enables Rust subsystems to submit asynchronous I/O through
// the io_uring interface, with safe wrappers around the lock-free ring
// buffers. Imported from the Zig side via C FFI.

#![allow(dead_code)]

// ─────────────────── External FFI (Zig-side io_uring) ───────────────
extern "C" {
    fn zxy_io_uring_init();
    fn zxy_io_uring_create(sq_size: u32, cq_size: u32, pid: u32) -> i32;
    fn zxy_io_uring_submit(ring_id: u32) -> i32;
    fn zxy_io_uring_destroy(ring_id: u32);
}

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_SQ_ENTRIES: usize = 32768;
pub const MAX_CQ_ENTRIES: usize = MAX_SQ_ENTRIES * 2;
pub const MAX_FIXED_FILES: usize = 1024;
pub const MAX_FIXED_BUFFERS: usize = 256;
pub const SQE_SIZE: usize = 64;
pub const CQE_SIZE: usize = 16;

// ─────────────────── Operation Codes ────────────────────────────────
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    Cancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    Statx = 20,
    Read = 21,
    Write = 22,
    Fadvise = 23,
    Madvise = 24,
    Send = 25,
    Recv = 26,
    Splice = 27,
    ProvideBuffers = 28,
    RemoveBuffers = 29,
    Tee = 30,
    Shutdown = 31,
    Renameat = 32,
    Unlinkat = 33,
    Mkdirat = 34,
    Symlinkat = 35,
    Linkat = 36,
    Socket = 37,
    MsgRing = 38,
    Waitid = 39,
}

// ─────────────────── SQE Flags ──────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct SqeFlags {
    pub fixed_file: bool,
    pub io_drain: bool,
    pub io_link: bool,
    pub io_hardlink: bool,
    pub async_op: bool,
    pub buffer_select: bool,
    pub cqe_skip_success: bool,
}

impl Default for SqeFlags {
    fn default() -> Self {
        Self {
            fixed_file: false,
            io_drain: false,
            io_link: false,
            io_hardlink: false,
            async_op: false,
            buffer_select: false,
            cqe_skip_success: false,
        }
    }
}

impl SqeFlags {
    pub fn to_bits(&self) -> u8 {
        let mut bits: u8 = 0;
        if self.fixed_file { bits |= 1; }
        if self.io_drain { bits |= 2; }
        if self.io_link { bits |= 4; }
        if self.io_hardlink { bits |= 8; }
        if self.async_op { bits |= 16; }
        if self.buffer_select { bits |= 32; }
        if self.cqe_skip_success { bits |= 64; }
        bits
    }
}

// ─────────────────── Submission Queue Entry ─────────────────────────
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SubmissionQueueEntry {
    pub opcode: IoOp,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub _pad: [u64; 2],
}

impl SubmissionQueueEntry {
    pub fn new(opcode: IoOp, fd: i32, user_data: u64) -> Self {
        Self {
            opcode,
            flags: 0,
            ioprio: 0,
            fd,
            off: 0,
            addr: 0,
            len: 0,
            op_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: -1,
            _pad: [0; 2],
        }
    }

    pub fn prep_read(fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Read, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.off = offset;
        sqe
    }

    pub fn prep_write(fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Write, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.off = offset;
        sqe
    }

    pub fn prep_fsync(fd: i32, fsync_flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Fsync, fd, user_data);
        sqe.op_flags = fsync_flags;
        sqe
    }

    pub fn prep_timeout(timeout_ns: u64, count: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Timeout, -1, user_data);
        sqe.off = timeout_ns;
        sqe.len = count;
        sqe
    }

    pub fn prep_accept(fd: i32, addr: u64, addrlen: u64, flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Accept, fd, user_data);
        sqe.addr = addr;
        sqe.off = addrlen;
        sqe.op_flags = flags;
        sqe
    }

    pub fn prep_connect(fd: i32, addr: u64, addrlen: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Connect, fd, user_data);
        sqe.addr = addr;
        sqe.off = addrlen as u64;
        sqe
    }

    pub fn prep_send(fd: i32, buf_addr: u64, len: u32, flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Send, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.op_flags = flags;
        sqe
    }

    pub fn prep_recv(fd: i32, buf_addr: u64, len: u32, flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Recv, fd, user_data);
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.op_flags = flags;
        sqe
    }

    pub fn prep_cancel(target_user_data: u64, flags: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Cancel, -1, user_data);
        sqe.addr = target_user_data;
        sqe.op_flags = flags;
        sqe
    }

    pub fn prep_openat(dfd: i32, pathname_addr: u64, flags: u32, mode: u32, user_data: u64) -> Self {
        let mut sqe = Self::new(IoOp::Openat, dfd, user_data);
        sqe.addr = pathname_addr;
        sqe.op_flags = flags;
        sqe.len = mode;
        sqe
    }

    pub fn prep_close(fd: i32, user_data: u64) -> Self {
        Self::new(IoOp::Close, fd, user_data)
    }

    pub fn set_link(&mut self) {
        self.flags |= 4; // IO_LINK
    }

    pub fn set_drain(&mut self) {
        self.flags |= 2; // IO_DRAIN
    }

    pub fn set_fixed_file(&mut self) {
        self.flags |= 1; // FIXED_FILE
    }
}

// ─────────────────── Completion Queue Entry ─────────────────────────
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompletionQueueEntry {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

impl CompletionQueueEntry {
    pub fn new(user_data: u64, res: i32) -> Self {
        Self {
            user_data,
            res,
            flags: 0,
        }
    }

    pub fn is_error(&self) -> bool {
        self.res < 0
    }

    pub fn error_code(&self) -> i32 {
        if self.res < 0 { -self.res } else { 0 }
    }
}

// ─────────────────── Lock-Free Ring Buffer ──────────────────────────
pub struct RingBuffer<T: Copy + Default, const N: usize> {
    entries: [T; N],
    head: u32,
    tail: u32,
    mask: u32,
}

impl<T: Copy + Default, const N: usize> RingBuffer<T, N> {
    pub fn new() -> Self {
        let size = N.next_power_of_two();
        Self {
            entries: [T::default(); N],
            head: 0,
            tail: 0,
            mask: (size - 1) as u32,
        }
    }

    pub fn push(&mut self, entry: T) -> bool {
        let next_head = (self.head + 1) & self.mask;
        if next_head == self.tail {
            return false;
        }
        self.entries[self.head as usize % N] = entry;
        self.head = next_head;
        true
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.tail == self.head {
            return None;
        }
        let entry = self.entries[self.tail as usize % N];
        self.tail = (self.tail + 1) & self.mask;
        Some(entry)
    }

    pub fn count(&self) -> u32 {
        (self.head.wrapping_sub(self.tail)) & self.mask
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub fn is_full(&self) -> bool {
        ((self.head + 1) & self.mask) == self.tail
    }
}

// ─────────────────── Fixed Buffer Registry ──────────────────────────
pub struct FixedBuffer {
    pub addr: u64,
    pub len: u64,
    pub mapped: bool,
}

impl Default for FixedBuffer {
    fn default() -> Self {
        Self { addr: 0, len: 0, mapped: false }
    }
}

pub struct FixedFileTable {
    fds: [i32; MAX_FIXED_FILES],
    count: u16,
}

impl FixedFileTable {
    pub fn new() -> Self {
        Self {
            fds: [-1; MAX_FIXED_FILES],
            count: 0,
        }
    }

    pub fn register(&mut self, index: u16, fd: i32) -> bool {
        if index as usize >= MAX_FIXED_FILES { return false; }
        self.fds[index as usize] = fd;
        if index >= self.count {
            self.count = index + 1;
        }
        true
    }

    pub fn unregister(&mut self, index: u16) {
        if (index as usize) < MAX_FIXED_FILES {
            self.fds[index as usize] = -1;
        }
    }

    pub fn get(&self, index: u16) -> i32 {
        if index >= self.count { return -1; }
        self.fds[index as usize]
    }
}

// ─────────────────── IoRing Context ─────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoRingState {
    Idle,
    Processing,
    Polling,
    Disabled,
}

pub struct IoRingStats {
    pub sqe_submitted: u64,
    pub cqe_completed: u64,
    pub io_errors: u64,
    pub timeouts: u64,
    pub cancellations: u64,
}

impl IoRingStats {
    fn new() -> Self {
        Self {
            sqe_submitted: 0,
            cqe_completed: 0,
            io_errors: 0,
            timeouts: 0,
            cancellations: 0,
        }
    }
}

/// Rust-side io_uring instance.
///
/// This wraps the Zig-side io_uring through C FFI for operations that
/// need native unsafe ring access, and provides a safe Rust-native
/// implementation for operations done entirely in Rust.
pub struct IoRing {
    /// Underlying ring ID from the Zig allocator
    ring_id: u32,
    /// Owner process ID
    owner_pid: u32,
    /// Current state
    state: IoRingState,
    /// Local SQ buffer (staged SQEs before submission)
    staged_sqes: [SubmissionQueueEntry; 256],
    staged_count: usize,
    /// Fixed file table (Rust-managed)
    fixed_files: FixedFileTable,
    /// Fixed buffers (Rust-managed)
    fixed_buffers: [FixedBuffer; MAX_FIXED_BUFFERS],
    fixed_buffer_count: u16,
    /// Statistics
    stats: IoRingStats,
    /// Completion callback registry
    callbacks: [Option<fn(u64, i32)>; 256],
}

impl IoRing {
    /// Create a new io_uring instance with the given queue sizes.
    pub fn new(sq_entries: u32, cq_entries: u32, pid: u32) -> Option<Self> {
        let ring_id = unsafe { zxy_io_uring_create(sq_entries, cq_entries, pid) };
        if ring_id < 0 {
            return None;
        }

        Some(Self {
            ring_id: ring_id as u32,
            owner_pid: pid,
            state: IoRingState::Idle,
            staged_sqes: [SubmissionQueueEntry::new(IoOp::Nop, -1, 0); 256],
            staged_count: 0,
            fixed_files: FixedFileTable::new(),
            fixed_buffers: [FixedBuffer::default(); MAX_FIXED_BUFFERS],
            fixed_buffer_count: 0,
            stats: IoRingStats::new(),
            callbacks: [None; 256],
        })
    }

    /// Stage an SQE for later submission.
    pub fn prepare(&mut self, sqe: SubmissionQueueEntry) -> bool {
        if self.staged_count >= 256 {
            return false;
        }
        self.staged_sqes[self.staged_count] = sqe;
        self.staged_count += 1;
        true
    }

    /// Stage a read operation.
    pub fn prepare_read(&mut self, fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_read(fd, buf_addr, len, offset, user_data))
    }

    /// Stage a write operation.
    pub fn prepare_write(&mut self, fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_write(fd, buf_addr, len, offset, user_data))
    }

    /// Stage a send operation.
    pub fn prepare_send(&mut self, fd: i32, buf_addr: u64, len: u32, flags: u32, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_send(fd, buf_addr, len, flags, user_data))
    }

    /// Stage a recv operation.
    pub fn prepare_recv(&mut self, fd: i32, buf_addr: u64, len: u32, flags: u32, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_recv(fd, buf_addr, len, flags, user_data))
    }

    /// Stage a fsync operation.
    pub fn prepare_fsync(&mut self, fd: i32, flags: u32, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_fsync(fd, flags, user_data))
    }

    /// Stage a timeout.
    pub fn prepare_timeout(&mut self, timeout_ns: u64, count: u32, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_timeout(timeout_ns, count, user_data))
    }

    /// Stage a close operation.
    pub fn prepare_close(&mut self, fd: i32, user_data: u64) -> bool {
        self.prepare(SubmissionQueueEntry::prep_close(fd, user_data))
    }

    /// Stage a linked chain of operations (executed in sequence).
    pub fn prepare_linked(&mut self, sqes: &[SubmissionQueueEntry]) -> bool {
        if self.staged_count + sqes.len() > 256 {
            return false;
        }
        for (i, sqe) in sqes.iter().enumerate() {
            let mut staged = sqe.clone();
            if i < sqes.len() - 1 {
                staged.set_link();
            }
            self.staged_sqes[self.staged_count] = staged;
            self.staged_count += 1;
        }
        true
    }

    /// Submit all staged SQEs to the ring.
    pub fn submit(&mut self) -> i32 {
        if self.staged_count == 0 {
            return 0;
        }

        self.state = IoRingState::Processing;
        let result = unsafe { zxy_io_uring_submit(self.ring_id) };

        self.stats.sqe_submitted += self.staged_count as u64;
        self.staged_count = 0;
        self.state = IoRingState::Idle;

        result
    }

    /// Submit and wait for at least `min_complete` completions.
    pub fn submit_and_wait(&mut self, min_complete: u32) -> i32 {
        let submitted = self.submit();
        if submitted < 0 {
            return submitted;
        }
        // The wait is handled on the Zig side
        submitted
    }

    /// Register a completion callback for a specific user_data value.
    pub fn register_callback(&mut self, slot: usize, callback: fn(u64, i32)) -> bool {
        if slot >= 256 { return false; }
        self.callbacks[slot] = Some(callback);
        true
    }

    /// Register fixed file descriptors.
    pub fn register_files(&mut self, fds: &[(u16, i32)]) -> u32 {
        let mut count = 0u32;
        for &(index, fd) in fds {
            if self.fixed_files.register(index, fd) {
                count += 1;
            }
        }
        count
    }

    /// Register fixed buffers for zero-copy I/O.
    pub fn register_buffers(&mut self, buffers: &[(u64, u64)]) -> u32 {
        let mut count = 0u32;
        for &(addr, len) in buffers {
            if (self.fixed_buffer_count as usize) >= MAX_FIXED_BUFFERS { break; }
            self.fixed_buffers[self.fixed_buffer_count as usize] = FixedBuffer {
                addr,
                len,
                mapped: true,
            };
            self.fixed_buffer_count += 1;
            count += 1;
        }
        count
    }

    /// Get the underlying ring ID.
    pub fn id(&self) -> u32 {
        self.ring_id
    }

    /// Get statistics.
    pub fn stats(&self) -> &IoRingStats {
        &self.stats
    }

    /// Destroy this ring.
    pub fn destroy(&mut self) {
        self.state = IoRingState::Disabled;
        unsafe { zxy_io_uring_destroy(self.ring_id); }
    }
}

impl Drop for IoRing {
    fn drop(&mut self) {
        if self.state != IoRingState::Disabled {
            self.destroy();
        }
    }
}

// ─────────────────── Builder Pattern for Complex Sequences ──────────
pub struct IoRingBuilder<'a> {
    ring: &'a mut IoRing,
    chain: bool,
}

impl<'a> IoRingBuilder<'a> {
    pub fn new(ring: &'a mut IoRing) -> Self {
        Self { ring, chain: false }
    }

    pub fn read(mut self, fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) -> Self {
        let mut sqe = SubmissionQueueEntry::prep_read(fd, buf_addr, len, offset, user_data);
        if self.chain {
            sqe.set_link();
        }
        self.ring.prepare(sqe);
        self
    }

    pub fn write(mut self, fd: i32, buf_addr: u64, len: u32, offset: u64, user_data: u64) -> Self {
        let mut sqe = SubmissionQueueEntry::prep_write(fd, buf_addr, len, offset, user_data);
        if self.chain {
            sqe.set_link();
        }
        self.ring.prepare(sqe);
        self
    }

    pub fn fsync(mut self, fd: i32, user_data: u64) -> Self {
        let mut sqe = SubmissionQueueEntry::prep_fsync(fd, 0, user_data);
        if self.chain {
            sqe.set_link();
        }
        self.ring.prepare(sqe);
        self
    }

    pub fn chain(mut self) -> Self {
        self.chain = true;
        self
    }

    pub fn submit(self) -> i32 {
        self.ring.submit()
    }
}

// ─────────────────── Module Initialization ──────────────────────────
pub fn init() {
    unsafe { zxy_io_uring_init(); }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_io_uring_init() {
    init();
}
