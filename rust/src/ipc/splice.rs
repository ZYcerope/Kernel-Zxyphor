// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Splice / Sendfile / TEE (Rust)
//
// Zero-copy data transfer between file descriptors:
// - splice(): Move data between fd and pipe without user-space copy
// - sendfile(): Copy between two fds using kernel-space pipe
// - tee(): Duplicate data in a pipe without consuming it
// - vmsplice(): Splice user pages into pipe
// - Pipe buffer management with reference-counted pages
// - Scatter/gather I/O through pipe ring buffer
// - SPLICE_F_MOVE, SPLICE_F_NONBLOCK, SPLICE_F_MORE, SPLICE_F_GIFT
// - Multi-segment transfer with partial completion tracking
// - FFI exports for Zig/Rust interop

#![no_std]
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

pub const MAX_PIPES: usize = 64;
pub const PIPE_BUF_PAGES: usize = 16;
pub const PAGE_SIZE: usize = 4096;
pub const MAX_SPLICE_OPS: usize = 128;

// splice flags
pub const SPLICE_F_MOVE: u32 = 1;
pub const SPLICE_F_NONBLOCK: u32 = 2;
pub const SPLICE_F_MORE: u32 = 4;
pub const SPLICE_F_GIFT: u32 = 8;

// ============================================================================
// Pipe Buffer Page
// ============================================================================

#[derive(Clone, Copy)]
pub struct PipeBuffer {
    /// Physical page frame number (or address)
    page_pfn: u64,
    /// Offset within the page
    offset: u16,
    /// Length of valid data
    len: u16,
    /// Reference count (shared between tee/splice)
    refcount: u16,
    /// Flags
    flags: u16,
    /// Whether this buffer slot is in use
    in_use: bool,
    /// Whether page can be moved (SPLICE_F_MOVE)
    can_move: bool,
    /// Whether page was gifted from user (SPLICE_F_GIFT)
    gifted: bool,
}

impl PipeBuffer {
    pub const fn new() -> Self {
        Self {
            page_pfn: 0,
            offset: 0,
            len: 0,
            refcount: 0,
            flags: 0,
            in_use: false,
            can_move: false,
            gifted: false,
        }
    }

    pub fn available_space(&self) -> u16 {
        if !self.in_use {
            return PAGE_SIZE as u16;
        }
        PAGE_SIZE as u16 - self.offset - self.len
    }

    pub fn acquire(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    pub fn release(&mut self) -> bool {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
        if self.refcount == 0 {
            self.in_use = false;
            self.page_pfn = 0;
            self.offset = 0;
            self.len = 0;
            self.can_move = false;
            self.gifted = false;
            return true; // Page freed
        }
        false
    }
}

// ============================================================================
// Splice Pipe (ring buffer of page references)
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PipeState {
    Free = 0,
    Open = 1,
    ReadClosed = 2,
    WriteClosed = 3,
    Closed = 4,
}

pub struct SplicePipe {
    state: PipeState,
    buffers: [PipeBuffer; PIPE_BUF_PAGES],
    /// Ring head (next buffer to read from)
    head: u8,
    /// Ring tail (next buffer to write to)
    tail: u8,
    /// Number of buffers with data
    nrbufs: u8,
    /// Owner (fd pair)
    read_fd: i32,
    write_fd: i32,
    /// Max number of buffers (configurable up to PIPE_BUF_PAGES)
    max_bufs: u8,
    /// Stats
    bytes_spliced_in: u64,
    bytes_spliced_out: u64,
    bytes_teed: u64,
}

impl SplicePipe {
    pub const fn new() -> Self {
        Self {
            state: PipeState::Free,
            buffers: [const { PipeBuffer::new() }; PIPE_BUF_PAGES],
            head: 0,
            tail: 0,
            nrbufs: 0,
            read_fd: -1,
            write_fd: -1,
            max_bufs: PIPE_BUF_PAGES as u8,
            bytes_spliced_in: 0,
            bytes_spliced_out: 0,
            bytes_teed: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nrbufs == 0
    }

    pub fn is_full(&self) -> bool {
        self.nrbufs >= self.max_bufs
    }

    pub fn data_available(&self) -> u32 {
        let mut total: u32 = 0;
        for i in 0..self.nrbufs as usize {
            let idx = ((self.head as usize) + i) % PIPE_BUF_PAGES;
            if self.buffers[idx].in_use {
                total += self.buffers[idx].len as u32;
            }
        }
        total
    }

    /// Push a page buffer into the pipe (write end)
    pub fn push_buf(&mut self, pfn: u64, offset: u16, len: u16, can_move: bool) -> bool {
        if self.is_full() {
            return false;
        }

        let idx = self.tail as usize;
        self.buffers[idx].page_pfn = pfn;
        self.buffers[idx].offset = offset;
        self.buffers[idx].len = len;
        self.buffers[idx].refcount = 1;
        self.buffers[idx].in_use = true;
        self.buffers[idx].can_move = can_move;
        self.buffers[idx].gifted = false;

        self.tail = ((self.tail as usize + 1) % PIPE_BUF_PAGES) as u8;
        self.nrbufs += 1;
        self.bytes_spliced_in += len as u64;
        true
    }

    /// Pop a page buffer from the pipe (read end)
    pub fn pop_buf(&mut self) -> Option<PipeBuffer> {
        if self.is_empty() {
            return None;
        }

        let idx = self.head as usize;
        let buf = self.buffers[idx];
        self.buffers[idx] = PipeBuffer::new();
        self.head = ((self.head as usize + 1) % PIPE_BUF_PAGES) as u8;
        self.nrbufs -= 1;
        self.bytes_spliced_out += buf.len as u64;
        Some(buf)
    }

    /// Peek at the head buffer without consuming
    pub fn peek_buf(&self) -> Option<&PipeBuffer> {
        if self.is_empty() {
            return None;
        }
        let idx = self.head as usize;
        Some(&self.buffers[idx])
    }

    /// TEE: duplicate N bytes from head without consuming
    /// Returns a new set of buffer references
    pub fn tee_buf(&mut self, max_bytes: u32) -> u32 {
        let mut copied: u32 = 0;
        for i in 0..self.nrbufs as usize {
            let idx = ((self.head as usize) + i) % PIPE_BUF_PAGES;
            if !self.buffers[idx].in_use {
                continue;
            }

            let avail = self.buffers[idx].len as u32;
            let to_copy = if (max_bytes - copied) < avail {
                max_bytes - copied
            } else {
                avail
            };

            // Increment refcount (shared page)
            self.buffers[idx].acquire();
            copied += to_copy;
            self.bytes_teed += to_copy as u64;

            if copied >= max_bytes {
                break;
            }
        }
        copied
    }

    /// Consume exactly N bytes from head, possibly partial buffer
    pub fn consume(&mut self, mut bytes: u32) -> u32 {
        let mut consumed: u32 = 0;

        while bytes > 0 && !self.is_empty() {
            let idx = self.head as usize;
            let avail = self.buffers[idx].len as u32;

            if bytes >= avail {
                // Consume entire buffer
                let buf_len = avail;
                self.buffers[idx].release();
                self.head = ((self.head as usize + 1) % PIPE_BUF_PAGES) as u8;
                self.nrbufs -= 1;
                consumed += buf_len;
                bytes -= buf_len;
                self.bytes_spliced_out += buf_len as u64;
            } else {
                // Partial consume — advance offset
                self.buffers[idx].offset += bytes as u16;
                self.buffers[idx].len -= bytes as u16;
                consumed += bytes;
                self.bytes_spliced_out += bytes as u64;
                bytes = 0;
            }
        }

        consumed
    }
}

// ============================================================================
// Splice Operation
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SpliceDirection {
    FdToPipe = 0,   // splice: fd → pipe
    PipeToFd = 1,   // splice: pipe → fd
    PipeToPipe = 2, // tee: pipe → pipe (no consume)
    UserToPipe = 3, // vmsplice: user pages → pipe
}

#[derive(Clone, Copy)]
pub struct SpliceOp {
    direction: SpliceDirection,
    src_fd: i32,
    dst_fd: i32,
    pipe_idx: u16,
    dst_pipe_idx: u16, // For tee
    offset_in: u64,
    offset_out: u64,
    len: u32,
    flags: u32,
    completed: u32,
    active: bool,
}

impl SpliceOp {
    pub const fn new() -> Self {
        Self {
            direction: SpliceDirection::FdToPipe,
            src_fd: -1,
            dst_fd: -1,
            pipe_idx: 0xFFFF,
            dst_pipe_idx: 0xFFFF,
            offset_in: 0,
            offset_out: 0,
            len: 0,
            flags: 0,
            completed: 0,
            active: false,
        }
    }
}

// ============================================================================
// Sendfile State
// ============================================================================

#[derive(Clone, Copy)]
pub struct SendfileState {
    in_fd: i32,
    out_fd: i32,
    offset: u64,
    count: u64,
    transferred: u64,
    active: bool,
}

impl SendfileState {
    pub const fn new() -> Self {
        Self {
            in_fd: -1,
            out_fd: -1,
            offset: 0,
            count: 0,
            transferred: 0,
            active: false,
        }
    }
}

// ============================================================================
// Splice Manager
// ============================================================================

pub struct SpliceManager {
    pipes: [SplicePipe; MAX_PIPES],
    pipe_count: u32,

    ops: [SpliceOp; MAX_SPLICE_OPS],
    sendfiles: [SendfileState; 32],

    // Page pool for splice (simulated PFNs)
    next_pfn: u64,

    // Stats
    total_splices: u64,
    total_tees: u64,
    total_vmsplices: u64,
    total_sendfiles: u64,
    total_bytes_spliced: u64,
    total_bytes_teed: u64,
    total_bytes_sendfile: u64,
    total_pages_moved: u64,
    total_pages_copied: u64,
}

impl SpliceManager {
    pub const fn new() -> Self {
        Self {
            pipes: [const { SplicePipe::new() }; MAX_PIPES],
            pipe_count: 0,
            ops: [const { SpliceOp::new() }; MAX_SPLICE_OPS],
            sendfiles: [const { SendfileState::new() }; 32],
            next_pfn: 0x100000,
            total_splices: 0,
            total_tees: 0,
            total_vmsplices: 0,
            total_sendfiles: 0,
            total_bytes_spliced: 0,
            total_bytes_teed: 0,
            total_bytes_sendfile: 0,
            total_pages_moved: 0,
            total_pages_copied: 0,
        }
    }

    fn alloc_pfn(&mut self) -> u64 {
        let pfn = self.next_pfn;
        self.next_pfn += 1;
        pfn
    }

    /// Create a new pipe
    pub fn create_pipe(&mut self) -> Option<u16> {
        for (i, pipe) in self.pipes.iter_mut().enumerate() {
            if pipe.state == PipeState::Free {
                *pipe = SplicePipe::new();
                pipe.state = PipeState::Open;
                pipe.read_fd = (i * 2) as i32;
                pipe.write_fd = (i * 2 + 1) as i32;
                self.pipe_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    /// Close a pipe
    pub fn close_pipe(&mut self, idx: u16) {
        if idx as usize >= MAX_PIPES { return; }
        // Release all buffers
        while let Some(_buf) = self.pipes[idx as usize].pop_buf() {
            // Page freed via release
        }
        self.pipes[idx as usize] = SplicePipe::new();
        if self.pipe_count > 0 { self.pipe_count -= 1; }
    }

    /// splice(): fd → pipe (read from file, push pages into pipe)
    pub fn splice_fd_to_pipe(
        &mut self,
        fd: i32,
        pipe_idx: u16,
        offset: u64,
        len: u32,
        flags: u32,
    ) -> i32 {
        if pipe_idx as usize >= MAX_PIPES { return -9; }
        if self.pipes[pipe_idx as usize].state != PipeState::Open { return -9; }

        let can_move = (flags & SPLICE_F_MOVE) != 0;
        let mut remaining = len;
        let mut total: u32 = 0;
        let mut off = offset;

        while remaining > 0 {
            let chunk = if remaining > PAGE_SIZE as u32 { PAGE_SIZE as u32 } else { remaining };
            let pfn = self.alloc_pfn();

            if !self.pipes[pipe_idx as usize].push_buf(pfn, 0, chunk as u16, can_move) {
                if (flags & SPLICE_F_NONBLOCK) != 0 {
                    break; // Pipe full, non-blocking
                }
                break;
            }

            if can_move {
                self.total_pages_moved += 1;
            } else {
                self.total_pages_copied += 1;
            }

            remaining -= chunk;
            total += chunk;
            off += chunk as u64;
        }

        self.total_splices += 1;
        self.total_bytes_spliced += total as u64;
        total as i32
    }

    /// splice(): pipe → fd (pop pages from pipe, write to file)
    pub fn splice_pipe_to_fd(
        &mut self,
        pipe_idx: u16,
        fd: i32,
        offset: u64,
        len: u32,
        flags: u32,
    ) -> i32 {
        if pipe_idx as usize >= MAX_PIPES { return -9; }
        if self.pipes[pipe_idx as usize].state != PipeState::Open { return -9; }
        let _ = fd;
        let _ = offset;

        let consumed = self.pipes[pipe_idx as usize].consume(len);

        if (flags & SPLICE_F_MOVE) != 0 {
            self.total_pages_moved += (consumed as u64 + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
        }

        self.total_splices += 1;
        self.total_bytes_spliced += consumed as u64;
        consumed as i32
    }

    /// tee(): duplicate pipe data without consuming
    pub fn tee(
        &mut self,
        src_pipe: u16,
        dst_pipe: u16,
        len: u32,
        _flags: u32,
    ) -> i32 {
        if src_pipe as usize >= MAX_PIPES || dst_pipe as usize >= MAX_PIPES { return -9; }
        if self.pipes[src_pipe as usize].state != PipeState::Open { return -9; }
        if self.pipes[dst_pipe as usize].state != PipeState::Open { return -9; }
        if src_pipe == dst_pipe { return -22; } // EINVAL

        // Duplicate buffers from src to dst by sharing pages
        let teed = self.pipes[src_pipe as usize].tee_buf(len);

        // Push references into dst pipe
        let src_head = self.pipes[src_pipe as usize].head;
        let src_nrbufs = self.pipes[src_pipe as usize].nrbufs;
        let mut pushed: u32 = 0;

        for i in 0..src_nrbufs as usize {
            if pushed >= teed { break; }
            let idx = ((src_head as usize) + i) % PIPE_BUF_PAGES;
            let buf = self.pipes[src_pipe as usize].buffers[idx];
            if !buf.in_use { continue; }

            if !self.pipes[dst_pipe as usize].push_buf(
                buf.page_pfn,
                buf.offset,
                buf.len,
                false,
            ) {
                break;
            }
            // Mark shared (already incremented refcount in tee_buf)
            pushed += buf.len as u32;
        }

        self.total_tees += 1;
        self.total_bytes_teed += pushed as u64;
        pushed as i32
    }

    /// vmsplice(): splice user pages into pipe
    pub fn vmsplice(
        &mut self,
        pipe_idx: u16,
        user_pages: &[(u64, u32)], // (addr, len) pairs
        flags: u32,
    ) -> i32 {
        if pipe_idx as usize >= MAX_PIPES { return -9; }
        if self.pipes[pipe_idx as usize].state != PipeState::Open { return -9; }

        let gifted = (flags & SPLICE_F_GIFT) != 0;
        let mut total: u32 = 0;

        for &(addr, len) in user_pages {
            let pfn = if gifted {
                // User gifted the page — we take ownership
                addr >> 12  // Convert addr to PFN
            } else {
                // Copy page
                let pfn = self.alloc_pfn();
                self.total_pages_copied += 1;
                pfn
            };

            let actual_len = if len > PAGE_SIZE as u32 { PAGE_SIZE as u32 } else { len };
            if !self.pipes[pipe_idx as usize].push_buf(pfn, 0, actual_len as u16, gifted) {
                break;
            }

            if gifted {
                let idx = if self.pipes[pipe_idx as usize].tail == 0 {
                    PIPE_BUF_PAGES - 1
                } else {
                    (self.pipes[pipe_idx as usize].tail - 1) as usize
                };
                self.pipes[pipe_idx as usize].buffers[idx].gifted = true;
            }

            total += actual_len;
        }

        self.total_vmsplices += 1;
        self.total_bytes_spliced += total as u64;
        total as i32
    }

    /// sendfile(): in_fd → out_fd using internal pipe
    pub fn sendfile(
        &mut self,
        in_fd: i32,
        out_fd: i32,
        offset: u64,
        count: u64,
    ) -> i64 {
        // Allocate internal pipe
        let pipe_idx = match self.create_pipe() {
            Some(p) => p,
            None => return -23, // ENFILE
        };

        let mut transferred: u64 = 0;
        let mut off = offset;
        let mut remaining = count;

        while remaining > 0 {
            let chunk = if remaining > (PAGE_SIZE * PIPE_BUF_PAGES) as u64 {
                (PAGE_SIZE * PIPE_BUF_PAGES) as u32
            } else {
                remaining as u32
            };

            // Splice in
            let spliced_in = self.splice_fd_to_pipe(in_fd, pipe_idx, off, chunk, SPLICE_F_MOVE);
            if spliced_in <= 0 { break; }

            // Splice out
            let spliced_out = self.splice_pipe_to_fd(pipe_idx, out_fd, 0, spliced_in as u32, SPLICE_F_MOVE);
            if spliced_out <= 0 { break; }

            transferred += spliced_out as u64;
            off += spliced_out as u64;
            remaining -= spliced_out as u64;
        }

        // Free internal pipe
        self.close_pipe(pipe_idx);

        self.total_sendfiles += 1;
        self.total_bytes_sendfile += transferred;
        transferred as i64
    }

    /// Get pipe info
    pub fn pipe_data_available(&self, idx: u16) -> u32 {
        if idx as usize >= MAX_PIPES { return 0; }
        self.pipes[idx as usize].data_available()
    }

    pub fn pipe_is_empty(&self, idx: u16) -> bool {
        if idx as usize >= MAX_PIPES { return true; }
        self.pipes[idx as usize].is_empty()
    }

    pub fn pipe_is_full(&self, idx: u16) -> bool {
        if idx as usize >= MAX_PIPES { return false; }
        self.pipes[idx as usize].is_full()
    }

    /// Set pipe max buffers (F_SETPIPE_SZ equivalent)
    pub fn set_pipe_size(&mut self, idx: u16, pages: u8) -> bool {
        if idx as usize >= MAX_PIPES { return false; }
        if pages == 0 || pages as usize > PIPE_BUF_PAGES { return false; }
        self.pipes[idx as usize].max_bufs = pages;
        true
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static mut SPLICE: SpliceManager = SpliceManager::new();

fn mgr() -> &'static mut SpliceManager {
    unsafe { &mut SPLICE }
}

// ============================================================================
// FFI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_splice_init() {
    let m = mgr();
    *m = SpliceManager::new();
}

#[no_mangle]
pub extern "C" fn rust_splice_create_pipe() -> i32 {
    match mgr().create_pipe() {
        Some(idx) => idx as i32,
        None => -23,
    }
}

#[no_mangle]
pub extern "C" fn rust_splice_close_pipe(idx: u16) {
    mgr().close_pipe(idx);
}

#[no_mangle]
pub extern "C" fn rust_splice_fd_to_pipe(fd: i32, pipe_idx: u16, offset: u64, len: u32, flags: u32) -> i32 {
    mgr().splice_fd_to_pipe(fd, pipe_idx, offset, len, flags)
}

#[no_mangle]
pub extern "C" fn rust_splice_pipe_to_fd(pipe_idx: u16, fd: i32, offset: u64, len: u32, flags: u32) -> i32 {
    mgr().splice_pipe_to_fd(pipe_idx, fd, offset, len, flags)
}

#[no_mangle]
pub extern "C" fn rust_tee(src_pipe: u16, dst_pipe: u16, len: u32, flags: u32) -> i32 {
    mgr().tee(src_pipe, dst_pipe, len, flags)
}

#[no_mangle]
pub extern "C" fn rust_sendfile(in_fd: i32, out_fd: i32, offset: u64, count: u64) -> i64 {
    mgr().sendfile(in_fd, out_fd, offset, count)
}

#[no_mangle]
pub extern "C" fn rust_splice_pipe_data(idx: u16) -> u32 {
    mgr().pipe_data_available(idx)
}

#[no_mangle]
pub extern "C" fn rust_splice_pipe_count() -> u32 {
    mgr().pipe_count
}

#[no_mangle]
pub extern "C" fn rust_splice_total_splices() -> u64 {
    mgr().total_splices
}

#[no_mangle]
pub extern "C" fn rust_splice_total_tees() -> u64 {
    mgr().total_tees
}

#[no_mangle]
pub extern "C" fn rust_splice_total_sendfiles() -> u64 {
    mgr().total_sendfiles
}

#[no_mangle]
pub extern "C" fn rust_splice_total_bytes() -> u64 {
    mgr().total_bytes_spliced
}

#[no_mangle]
pub extern "C" fn rust_splice_pages_moved() -> u64 {
    mgr().total_pages_moved
}

#[no_mangle]
pub extern "C" fn rust_splice_pages_copied() -> u64 {
    mgr().total_pages_copied
}

#[no_mangle]
pub extern "C" fn rust_splice_set_pipe_size(idx: u16, pages: u8) -> i32 {
    if mgr().set_pipe_size(idx, pages) { 0 } else { -22 }
}
