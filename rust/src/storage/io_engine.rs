// SPDX-License-Identifier: MIT
// Zxyphor Kernel - io_uring-like Async I/O Engine (Rust)
// Submission/Completion ring architecture, multi-shot, fixed buffers

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Ring Buffer Infrastructure
// ============================================================================

/// Submission Queue Entry (SQE)
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct IoSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,      // offset or addr2
    pub addr: u64,     // buffer address or splice_off_in
    pub len: u32,      // buffer length or number of bytes
    pub op_flags: u32, // Operation-specific flags
    pub user_data: u64, // User data (passed through to CQE)
    // Union area for operation-specific data
    pub buf_index: u16,
    pub buf_group: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub _pad: [u64; 1],
}

/// Submission flags
pub mod sqe_flags {
    pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
    pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
    pub const IOSQE_IO_LINK: u8 = 1 << 2;
    pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
    pub const IOSQE_ASYNC: u8 = 1 << 4;
    pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
    pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;
}

/// Completion Queue Entry (CQE)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct IoCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// CQE flags
pub mod cqe_flags {
    pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
    pub const IORING_CQE_F_MORE: u32 = 1 << 1;
    pub const IORING_CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
    pub const IORING_CQE_F_NOTIF: u32 = 1 << 3;
}

/// I/O operation opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
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
    SendMsg = 9,
    RecvMsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    OpenAt = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    OpenAt2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    FSetXattr = 41,
    SetXattr = 42,
    FGetXattr = 43,
    GetXattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendMsgZc = 48,
    // Zxyphor extensions
    ZxyNvmePassthru = 200,
    ZxyDmaTransfer = 201,
    ZxyGpuSubmit = 202,
    ZxyNetBatch = 203,
    ZxyMemcpy = 204,
    ZxyAioBarrier = 205,
}

// ============================================================================
// Ring Buffer Management
// ============================================================================

/// Shared ring header (memory-mapped to userspace)
#[repr(C)]
pub struct IoRingHeader {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: AtomicU32,
    pub dropped: AtomicU32,
    pub array: u32, // offset to SQE index array
    pub resv1: u32,
    pub user_addr: u64,
}

/// Ring parameters
#[repr(C)]
pub struct IoRingParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqRingOffsets,
    pub cq_off: IoCqRingOffsets,
}

#[repr(C)]
pub struct IoSqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[repr(C)]
pub struct IoCqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// Setup flags
pub mod setup_flags {
    pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
    pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
    pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
    pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
    pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
    pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
    pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
    pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
    pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
    pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
    pub const IORING_SETUP_SQE128: u32 = 1 << 10;
    pub const IORING_SETUP_CQE32: u32 = 1 << 11;
    pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
    pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
    pub const IORING_SETUP_NO_MMAP: u32 = 1 << 14;
    pub const IORING_SETUP_REGISTERED_FD_ONLY: u32 = 1 << 15;
    pub const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;
}

/// Feature flags
pub mod features {
    pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
    pub const IORING_FEAT_NODROP: u32 = 1 << 1;
    pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
    pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
    pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
    pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
    pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;
    pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
    pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
    pub const IORING_FEAT_NATIVE_WORKERS: u32 = 1 << 9;
    pub const IORING_FEAT_RSRC_TAGS: u32 = 1 << 10;
    pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;
    pub const IORING_FEAT_LINKED_FILE: u32 = 1 << 12;
    pub const IORING_FEAT_REG_REG_RING: u32 = 1 << 13;
}

// ============================================================================
// I/O Ring Context
// ============================================================================

/// Buffer group for automatic buffer selection
pub struct BufGroup {
    pub group_id: u16,
    pub buf_ring_addr: u64,
    pub buf_size: u32,
    pub buf_count: u16,
    pub head: AtomicU32,
    pub mask: u32,
}

impl BufGroup {
    pub fn pick_buffer(&self) -> Option<(u16, u64)> {
        let head = self.head.load(Ordering::Acquire);
        if head >= self.buf_count as u32 {
            return None;
        }
        // CAS to claim buffer
        if self.head.compare_exchange(head, head + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            let addr = self.buf_ring_addr + (head as u64 * self.buf_size as u64);
            Some((head as u16, addr))
        } else {
            None
        }
    }

    pub fn return_buffer(&self, _buf_id: u16) {
        self.head.fetch_sub(1, Ordering::Release);
    }
}

/// Fixed file table for registered file descriptors
pub struct FixedFileTable {
    pub files: [i32; 4096],
    pub count: u32,
    pub bitmap: [u64; 64], // 4096 bits
}

impl FixedFileTable {
    pub fn new() -> Self {
        FixedFileTable {
            files: [-1; 4096],
            count: 0,
            bitmap: [0; 64],
        }
    }

    pub fn register(&mut self, fd: i32) -> Option<u32> {
        for i in 0..4096 {
            let word = i / 64;
            let bit = i % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                self.bitmap[word] |= 1u64 << bit;
                self.files[i] = fd;
                self.count += 1;
                return Some(i as u32);
            }
        }
        None
    }

    pub fn unregister(&mut self, idx: u32) {
        if idx < 4096 {
            let word = idx as usize / 64;
            let bit = idx as usize % 64;
            self.bitmap[word] &= !(1u64 << bit);
            self.files[idx as usize] = -1;
            self.count -= 1;
        }
    }

    pub fn get(&self, idx: u32) -> Option<i32> {
        if idx < 4096 {
            let word = idx as usize / 64;
            let bit = idx as usize % 64;
            if self.bitmap[word] & (1u64 << bit) != 0 {
                return Some(self.files[idx as usize]);
            }
        }
        None
    }
}

/// Fixed buffer table for registered buffers
pub struct FixedBufTable {
    pub addrs: [u64; 1024],
    pub lens: [u32; 1024],
    pub count: u32,
}

impl FixedBufTable {
    pub fn new() -> Self {
        FixedBufTable {
            addrs: [0; 1024],
            lens: [0; 1024],
            count: 0,
        }
    }

    pub fn register(&mut self, addr: u64, len: u32) -> Option<u32> {
        if self.count < 1024 {
            let idx = self.count;
            self.addrs[idx as usize] = addr;
            self.lens[idx as usize] = len;
            self.count += 1;
            Some(idx)
        } else {
            None
        }
    }

    pub fn get(&self, idx: u32) -> Option<(u64, u32)> {
        if idx < self.count {
            Some((self.addrs[idx as usize], self.lens[idx as usize]))
        } else {
            None
        }
    }
}

/// I/O Ring instance
pub struct IoRing {
    /// Ring Identity
    pub ring_id: u32,
    pub owner_pid: u32,
    
    /// Submission Ring
    pub sq_entries: u32,
    pub sq_mask: u32,
    pub sq_head: AtomicU32,
    pub sq_tail: AtomicU32,
    pub sq_flags: AtomicU32,
    pub sq_dropped: AtomicU32,
    pub sqe_base: u64,      // Base address of SQE array
    
    /// Completion Ring
    pub cq_entries: u32,
    pub cq_mask: u32,
    pub cq_head: AtomicU32,
    pub cq_tail: AtomicU32,
    pub cq_overflow: AtomicU32,
    pub cq_flags: AtomicU32,
    pub cqe_base: u64,      // Base address of CQE array
    
    /// Configuration
    pub setup_flags: u32,
    pub feature_flags: u32,
    
    /// SQ Polling thread
    pub sqpoll_enabled: bool,
    pub sqpoll_cpu: u32,
    pub sqpoll_idle: u32,
    pub sqpoll_running: AtomicBool,
    
    /// Registered resources
    pub fixed_files: FixedFileTable,
    pub fixed_bufs: FixedBufTable,
    
    /// Statistics
    pub stats: IoRingStats,
    
    /// Cancellation support
    pub cancel_seq: AtomicU64,
    
    /// Timeouts
    pub timeout_count: AtomicU32,
}

pub struct IoRingStats {
    pub sqes_submitted: AtomicU64,
    pub cqes_completed: AtomicU64,
    pub sqes_dropped: AtomicU64,
    pub cq_overflows: AtomicU64,
    pub submit_calls: AtomicU64,
    pub enter_calls: AtomicU64,
    pub cancel_ops: AtomicU64,
    pub poll_timeouts: AtomicU64,
    pub io_read_bytes: AtomicU64,
    pub io_write_bytes: AtomicU64,
    pub net_rx_bytes: AtomicU64,
    pub net_tx_bytes: AtomicU64,
    pub avg_latency_ns: AtomicU64,
    pub max_latency_ns: AtomicU64,
}

impl IoRingStats {
    pub const fn new() -> Self {
        IoRingStats {
            sqes_submitted: AtomicU64::new(0),
            cqes_completed: AtomicU64::new(0),
            sqes_dropped: AtomicU64::new(0),
            cq_overflows: AtomicU64::new(0),
            submit_calls: AtomicU64::new(0),
            enter_calls: AtomicU64::new(0),
            cancel_ops: AtomicU64::new(0),
            poll_timeouts: AtomicU64::new(0),
            io_read_bytes: AtomicU64::new(0),
            io_write_bytes: AtomicU64::new(0),
            net_rx_bytes: AtomicU64::new(0),
            net_tx_bytes: AtomicU64::new(0),
            avg_latency_ns: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
        }
    }
}

impl IoRing {
    /// Create new I/O ring
    pub fn new(ring_id: u32, sq_entries: u32, cq_entries: u32, flags: u32) -> Self {
        let sq_entries = sq_entries.next_power_of_two();
        let cq_entries = cq_entries.next_power_of_two();
        
        IoRing {
            ring_id,
            owner_pid: 0,
            sq_entries,
            sq_mask: sq_entries - 1,
            sq_head: AtomicU32::new(0),
            sq_tail: AtomicU32::new(0),
            sq_flags: AtomicU32::new(0),
            sq_dropped: AtomicU32::new(0),
            sqe_base: 0,
            cq_entries,
            cq_mask: cq_entries - 1,
            cq_head: AtomicU32::new(0),
            cq_tail: AtomicU32::new(0),
            cq_overflow: AtomicU32::new(0),
            cq_flags: AtomicU32::new(0),
            cqe_base: 0,
            setup_flags: flags,
            feature_flags: features::IORING_FEAT_SINGLE_MMAP 
                | features::IORING_FEAT_NODROP
                | features::IORING_FEAT_SUBMIT_STABLE
                | features::IORING_FEAT_FAST_POLL
                | features::IORING_FEAT_NATIVE_WORKERS
                | features::IORING_FEAT_CQE_SKIP,
            sqpoll_enabled: flags & setup_flags::IORING_SETUP_SQPOLL != 0,
            sqpoll_cpu: 0,
            sqpoll_idle: 1000,
            sqpoll_running: AtomicBool::new(false),
            fixed_files: FixedFileTable::new(),
            fixed_bufs: FixedBufTable::new(),
            stats: IoRingStats::new(),
            cancel_seq: AtomicU64::new(0),
            timeout_count: AtomicU32::new(0),
        }
    }

    /// Submit pending SQEs for processing
    pub fn submit(&self, to_submit: u32, min_complete: u32, flags: u32) -> Result<u32, IoError> {
        let _ = flags;
        self.stats.submit_calls.fetch_add(1, Ordering::Relaxed);
        
        let head = self.sq_head.load(Ordering::Acquire);
        let tail = self.sq_tail.load(Ordering::Acquire);
        let pending = tail.wrapping_sub(head);
        
        let submit_count = core::cmp::min(to_submit, pending);
        
        for _ in 0..submit_count {
            self.stats.sqes_submitted.fetch_add(1, Ordering::Relaxed);
        }
        
        // Process completions
        if min_complete > 0 {
            self.wait_completions(min_complete)?;
        }
        
        Ok(submit_count)
    }

    fn wait_completions(&self, min: u32) -> Result<(), IoError> {
        let cq_head = self.cq_head.load(Ordering::Acquire);
        let cq_tail = self.cq_tail.load(Ordering::Acquire);
        let available = cq_tail.wrapping_sub(cq_head);
        
        if available >= min {
            return Ok(());
        }
        
        // Would block here in real implementation
        Ok(())
    }

    /// Post a completion
    pub fn post_cqe(&self, user_data: u64, res: i32, flags: u32) -> Result<(), IoError> {
        let tail = self.cq_tail.load(Ordering::Acquire);
        let head = self.cq_head.load(Ordering::Acquire);
        
        if tail.wrapping_sub(head) >= self.cq_entries {
            self.cq_overflow.fetch_add(1, Ordering::Relaxed);
            self.stats.cq_overflows.fetch_add(1, Ordering::Relaxed);
            return Err(IoError::CqOverflow);
        }
        
        let _ = IoCqe { user_data, res, flags };
        
        self.cq_tail.store(tail.wrapping_add(1), Ordering::Release);
        self.stats.cqes_completed.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }

    /// Cancel an operation by user_data
    pub fn cancel(&self, user_data: u64, flags: u32) -> Result<(), IoError> {
        let _ = user_data;
        let _ = flags;
        self.cancel_seq.fetch_add(1, Ordering::Relaxed);
        self.stats.cancel_ops.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get SQ space available
    pub fn sq_space(&self) -> u32 {
        let head = self.sq_head.load(Ordering::Acquire);
        let tail = self.sq_tail.load(Ordering::Acquire);
        self.sq_entries - tail.wrapping_sub(head)
    }
    
    /// Get CQ entries ready
    pub fn cq_ready(&self) -> u32 {
        let head = self.cq_head.load(Ordering::Acquire);
        let tail = self.cq_tail.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    /// Enter the ring (syscall entry point)
    pub fn enter(&self, to_submit: u32, min_complete: u32, flags: u32) -> Result<u32, IoError> {
        self.stats.enter_calls.fetch_add(1, Ordering::Relaxed);
        
        if self.sqpoll_enabled {
            // Wake SQ poll thread if needed
            if flags & IORING_ENTER_SQ_WAKEUP != 0 {
                self.sqpoll_running.store(true, Ordering::Release);
            }
            
            if to_submit > 0 {
                // SQ poll thread will handle submission
                return Ok(0);
            }
        }
        
        self.submit(to_submit, min_complete, flags)
    }
}

pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;
pub const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;

#[derive(Debug)]
pub enum IoError {
    InvalidArg,
    NoMem,
    CqOverflow,
    Busy,
    Canceled,
    Fault,
    NotSupported,
    PermissionDenied,
}

// ============================================================================
// Block I/O Layer
// ============================================================================

/// Block device operations
pub struct BlockDevOps {
    pub read: Option<fn(dev: &BlockDev, lba: u64, count: u32, buf: u64) -> i32>,
    pub write: Option<fn(dev: &BlockDev, lba: u64, count: u32, buf: u64) -> i32>,
    pub flush: Option<fn(dev: &BlockDev) -> i32>,
    pub discard: Option<fn(dev: &BlockDev, lba: u64, count: u32) -> i32>,
    pub get_status: Option<fn(dev: &BlockDev) -> u32>,
    pub ioctl: Option<fn(dev: &BlockDev, cmd: u32, arg: u64) -> i32>,
}

/// Block device
pub struct BlockDev {
    pub name: [u8; 32],
    pub major: u16,
    pub minor: u16,
    pub block_size: u32,
    pub total_blocks: u64,
    pub capacity_bytes: u64,
    pub read_only: bool,
    pub removable: bool,
    pub queue_depth: u32,
    pub max_segments: u32,
    pub max_segment_size: u32,
    pub max_sectors: u32,
    pub dma_alignment: u32,
    pub optimal_io_size: u32,
    pub discard_granularity: u32,
    pub discard_max_bytes: u64,
    pub write_cache: bool,
    pub fua: bool,         // Force Unit Access
    pub rotational: bool,  // HDD vs SSD
    pub ops: BlockDevOps,
    pub stats: BlkStats,
}

pub struct BlkStats {
    pub read_ios: AtomicU64,
    pub write_ios: AtomicU64,
    pub read_sectors: AtomicU64,
    pub write_sectors: AtomicU64,
    pub read_ticks: AtomicU64,
    pub write_ticks: AtomicU64,
    pub in_flight: AtomicU32,
    pub io_ticks: AtomicU64,
    pub time_in_queue: AtomicU64,
    pub discard_ios: AtomicU64,
    pub discard_sectors: AtomicU64,
    pub flush_ios: AtomicU64,
}

impl BlkStats {
    pub const fn new() -> Self {
        BlkStats {
            read_ios: AtomicU64::new(0),
            write_ios: AtomicU64::new(0),
            read_sectors: AtomicU64::new(0),
            write_sectors: AtomicU64::new(0),
            read_ticks: AtomicU64::new(0),
            write_ticks: AtomicU64::new(0),
            in_flight: AtomicU32::new(0),
            io_ticks: AtomicU64::new(0),
            time_in_queue: AtomicU64::new(0),
            discard_ios: AtomicU64::new(0),
            discard_sectors: AtomicU64::new(0),
            flush_ios: AtomicU64::new(0),
        }
    }
}

/// RAID implementation
#[derive(Debug, Clone, Copy)]
pub enum RaidLevel {
    Raid0,  // Striping only
    Raid1,  // Mirroring
    Raid5,  // Striping with distributed parity
    Raid6,  // Striping with double parity
    Raid10, // Mirroring + Striping
    ZxyAdaptive, // Zxyphor adaptive RAID
}

pub struct RaidArray {
    pub level: RaidLevel,
    pub disks: [Option<u32>; 32], // block device indices
    pub disk_count: u8,
    pub spare_count: u8,
    pub chunk_size: u32,
    pub stripe_width: u32,
    pub total_sectors: u64,
    pub degraded: bool,
    pub rebuilding: bool,
    pub rebuild_progress: u64,
    pub sync_speed: u32,
}

impl RaidArray {
    pub fn usable_capacity(&self) -> u64 {
        match self.level {
            RaidLevel::Raid0 => self.total_sectors,
            RaidLevel::Raid1 => self.total_sectors / self.disk_count as u64,
            RaidLevel::Raid5 => self.total_sectors * (self.disk_count as u64 - 1) / self.disk_count as u64,
            RaidLevel::Raid6 => self.total_sectors * (self.disk_count as u64 - 2) / self.disk_count as u64,
            RaidLevel::Raid10 => self.total_sectors / 2,
            RaidLevel::ZxyAdaptive => self.total_sectors * 3 / 4, // 75% usable
        }
    }

    pub fn stripe_for_sector(&self, sector: u64) -> (u8, u64) {
        let stripe = sector / self.chunk_size as u64;
        let offset = sector % self.chunk_size as u64;
        let disk = (stripe % self.disk_count as u64) as u8;
        let disk_sector = (stripe / self.disk_count as u64) * self.chunk_size as u64 + offset;
        (disk, disk_sector)
    }

    pub fn parity_disk_for_stripe(&self, stripe: u64) -> u8 {
        match self.level {
            RaidLevel::Raid5 => ((self.disk_count as u64 - 1) - (stripe % self.disk_count as u64)) as u8,
            RaidLevel::Raid6 => ((self.disk_count as u64 - 1) - (stripe % self.disk_count as u64)) as u8,
            _ => 0,
        }
    }
}

/// Device-mapper target types
#[derive(Debug, Clone, Copy)]
pub enum DmTargetType {
    Linear,
    Striped,
    Mirror,
    Snapshot,
    SnapshotOrigin,
    Zero,
    Error,
    Crypt,
    Delay,
    Flakey,
    Thin,
    ThinPool,
    Cache,
    Era,
    Integrity,
    // Zxyphor
    ZxyDedup,
    ZxyCompress,
    ZxyTiered,
}

pub struct DmTarget {
    pub target_type: DmTargetType,
    pub start_sector: u64,
    pub length: u64,
    pub args: [u64; 8],
}

/// Device-mapper device
pub struct DmDevice {
    pub name: [u8; 32],
    pub uuid: [u8; 64],
    pub targets: [Option<DmTarget>; 16],
    pub target_count: u8,
    pub suspended: bool,
    pub read_only: bool,
}
