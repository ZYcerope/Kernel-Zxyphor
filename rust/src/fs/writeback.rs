// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Writeback Engine & Dirty Page Management (Rust)
//
// Manages flushing dirty pages from the page cache to backing store:
// - Per-backing-device writeback work queues
// - Dirty page ratio tracking with throttling
// - Background writeback (bdflush/pdflush equivalent)
// - Periodic writeback timer
// - Writeback control: nr_to_write, sync mode, bandwidth
// - Congestion tracking for I/O backpressure
// - Write-behind optimization for sequential writes
// - Per-inode dirty tracking
// - Writeback stats and tunables

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

/// Maximum backing devices
const MAX_BDI: usize = 16;
/// Maximum dirty inodes per BDI
const MAX_DIRTY_INODES: usize = 256;
/// Maximum writeback work items
const MAX_WB_WORK: usize = 64;
/// Default dirty ratio threshold (percent of total RAM)
const DEFAULT_DIRTY_RATIO: u32 = 20;
/// Background dirty ratio (start writeback at this %)
const DEFAULT_DIRTY_BG_RATIO: u32 = 10;
/// Default writeback interval (centiseconds)
const DEFAULT_WB_INTERVAL_CS: u32 = 500; // 5 seconds

// ─────────────────── Writeback Modes ────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum WbSyncMode {
    /// Best effort: skip locked/busy pages
    None = 0,
    /// Write all dirty pages, don't skip anything
    All = 1,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum WbReason {
    Background = 0,
    SyncAll = 1,
    Periodic = 2,
    LaptopTimer = 3,
    FreeMoreMem = 4,
    FsFreeFd = 5,
    Shutdown = 6,
    Fork = 7,
}

impl WbReason {
    pub fn name(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::SyncAll => "sync",
            Self::Periodic => "periodic",
            Self::LaptopTimer => "laptop_timer",
            Self::FreeMoreMem => "free_more_mem",
            Self::FsFreeFd => "fs_free_fd",
            Self::Shutdown => "shutdown",
            Self::Fork => "fork",
        }
    }
}

// ─────────────────── Writeback Control ──────────────────────────────

#[repr(C)]
pub struct WbControl {
    pub nr_to_write: u64,
    pub pages_skipped: u64,
    pub pages_written: u64,
    pub sync_mode: WbSyncMode,
    pub range_start: u64,
    pub range_end: u64,
    /// For rate-limited writeback
    pub bandwidth_bps: u64,   // bytes per second limit (0 = unlimited)
}

impl WbControl {
    pub fn new(nr_pages: u64, mode: WbSyncMode) -> Self {
        Self {
            nr_to_write: nr_pages,
            pages_skipped: 0,
            pages_written: 0,
            sync_mode: mode,
            range_start: 0,
            range_end: u64::MAX,
            bandwidth_bps: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.pages_written >= self.nr_to_write
    }

    pub fn remaining(&self) -> u64 {
        self.nr_to_write.saturating_sub(self.pages_written)
    }
}

// ─────────────────── Dirty Inode Entry ──────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirtyInode {
    pub inode_nr: u64,
    pub dirty_pages: u32,
    pub writeback_pages: u32,     // currently being written
    pub first_dirtied_time: u64,  // when first page was dirtied
    pub last_dirtied_time: u64,
    pub state: u8,                // 0=clean, 1=dirty, 2=writeback, 3=both
    pub active: bool,
}

impl DirtyInode {
    pub const EMPTY: Self = Self {
        inode_nr: 0,
        dirty_pages: 0,
        writeback_pages: 0,
        first_dirtied_time: 0,
        last_dirtied_time: 0,
        state: 0,
        active: false,
    };

    pub fn dirty(&mut self, pages: u32, time: u64) {
        self.dirty_pages += pages;
        if self.state == 0 {
            self.first_dirtied_time = time;
        }
        self.last_dirtied_time = time;
        self.state = if self.writeback_pages > 0 { 3 } else { 1 };
    }

    pub fn start_writeback(&mut self, pages: u32) -> u32 {
        let actual = pages.min(self.dirty_pages);
        self.dirty_pages -= actual;
        self.writeback_pages += actual;
        self.state = if self.dirty_pages > 0 { 3 } else { 2 };
        actual
    }

    pub fn complete_writeback(&mut self, pages: u32) {
        let actual = pages.min(self.writeback_pages);
        self.writeback_pages -= actual;
        if self.dirty_pages == 0 && self.writeback_pages == 0 {
            self.state = 0;
        } else if self.dirty_pages > 0 {
            self.state = if self.writeback_pages > 0 { 3 } else { 1 };
        }
    }

    pub fn total_pages(&self) -> u32 {
        self.dirty_pages + self.writeback_pages
    }
}

// ─────────────────── Writeback Work Item ────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WbWorkItem {
    pub reason: WbReason,
    pub nr_pages: u64,
    pub sync_mode: WbSyncMode,
    pub inode_nr: u64,     // 0 = all inodes
    pub enqueued_time: u64,
    pub active: bool,
}

impl WbWorkItem {
    pub const EMPTY: Self = Self {
        reason: WbReason::Background,
        nr_pages: 0,
        sync_mode: WbSyncMode::None,
        inode_nr: 0,
        enqueued_time: 0,
        active: false,
    };
}

// ─────────────────── Backing Device Info ────────────────────────────

#[repr(C)]
pub struct BdiWriteback {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: u8,
    /// Dirty inode tracking
    pub inodes: [DirtyInode; MAX_DIRTY_INODES],
    pub inode_count: u32,
    /// Work queue
    pub work_queue: [WbWorkItem; MAX_WB_WORK],
    pub work_head: u32,
    pub work_tail: u32,
    pub work_count: AtomicU32,
    /// Bandwidth estimation (pages/sec)
    pub avg_write_bandwidth: AtomicU64,
    pub write_bandwidth: AtomicU64,
    /// Dirty page limits for this BDI
    pub dirty_limit: AtomicU64,
    pub thresh: AtomicU64,
    /// Stats
    pub pages_written_total: AtomicU64,
    pub pages_dirtied_total: AtomicU64,
    pub writeback_errors: AtomicU32,
    /// Congestion
    pub congested: AtomicBool,
    pub active: AtomicBool,
}

impl BdiWriteback {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            name: [0u8; 32],
            name_len: 0,
            inodes: [DirtyInode::EMPTY; MAX_DIRTY_INODES],
            inode_count: 0,
            work_queue: [WbWorkItem::EMPTY; MAX_WB_WORK],
            work_head: 0,
            work_tail: 0,
            work_count: AtomicU32::new(0),
            avg_write_bandwidth: AtomicU64::new(1024), // 4MB/s default
            write_bandwidth: AtomicU64::new(0),
            dirty_limit: AtomicU64::new(0),
            thresh: AtomicU64::new(0),
            pages_written_total: AtomicU64::new(0),
            pages_dirtied_total: AtomicU64::new(0),
            writeback_errors: AtomicU32::new(0),
            congested: AtomicBool::new(false),
            active: AtomicBool::new(true),
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    /// Mark an inode dirty
    pub fn mark_inode_dirty(&mut self, inode_nr: u64, pages: u32, time: u64) {
        // Find existing
        for i in 0..self.inode_count as usize {
            if self.inodes[i].active && self.inodes[i].inode_nr == inode_nr {
                self.inodes[i].dirty(pages, time);
                self.pages_dirtied_total.fetch_add(pages as u64, Ordering::Relaxed);
                return;
            }
        }
        // New dirty inode
        if (self.inode_count as usize) < MAX_DIRTY_INODES {
            let idx = self.inode_count as usize;
            self.inodes[idx] = DirtyInode {
                inode_nr,
                dirty_pages: pages,
                writeback_pages: 0,
                first_dirtied_time: time,
                last_dirtied_time: time,
                state: 1,
                active: true,
            };
            self.inode_count += 1;
            self.pages_dirtied_total.fetch_add(pages as u64, Ordering::Relaxed);
        }
    }

    /// Enqueue writeback work
    pub fn enqueue_work(&mut self, item: WbWorkItem) -> bool {
        let count = self.work_count.load(Ordering::Relaxed) as usize;
        if count >= MAX_WB_WORK { return false; }
        let idx = self.work_tail as usize % MAX_WB_WORK;
        self.work_queue[idx] = item;
        self.work_tail += 1;
        self.work_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Dequeue next work item
    pub fn dequeue_work(&mut self) -> Option<WbWorkItem> {
        if self.work_count.load(Ordering::Relaxed) == 0 { return None; }
        let idx = self.work_head as usize % MAX_WB_WORK;
        let item = self.work_queue[idx];
        self.work_head += 1;
        self.work_count.fetch_sub(1, Ordering::Relaxed);
        Some(item)
    }

    /// Process writeback: write dirty pages to backing store
    pub fn do_writeback(&mut self, control: &mut WbControl) -> u64 {
        let mut written = 0u64;

        // Sort inodes by dirtied time (oldest first — FIFO)
        // Simple linear scan for oldest dirty inode
        while !control.is_complete() {
            let oldest = self.find_oldest_dirty();
            let idx = match oldest {
                Some(i) => i,
                None => break,
            };

            let batch = control.remaining().min(self.inodes[idx].dirty_pages as u64);
            if batch == 0 { break; }

            let actual = self.inodes[idx].start_writeback(batch as u32);
            if actual == 0 { break; }

            // Simulate write completion
            self.inodes[idx].complete_writeback(actual);
            control.pages_written += actual as u64;
            written += actual as u64;
            self.pages_written_total.fetch_add(actual as u64, Ordering::Relaxed);

            // Clean up fully clean inodes
            if self.inodes[idx].total_pages() == 0 {
                self.inodes[idx].active = false;
            }
        }

        written
    }

    fn find_oldest_dirty(&self) -> Option<usize> {
        let mut oldest_time = u64::MAX;
        let mut oldest_idx: Option<usize> = None;
        for i in 0..self.inode_count as usize {
            if self.inodes[i].active && self.inodes[i].dirty_pages > 0 {
                if self.inodes[i].first_dirtied_time < oldest_time {
                    oldest_time = self.inodes[i].first_dirtied_time;
                    oldest_idx = Some(i);
                }
            }
        }
        oldest_idx
    }

    /// Total dirty pages across all inodes
    pub fn nr_dirty(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.inode_count as usize {
            if self.inodes[i].active {
                total += self.inodes[i].dirty_pages as u64;
            }
        }
        total
    }

    /// Total pages in writeback
    pub fn nr_writeback(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.inode_count as usize {
            if self.inodes[i].active {
                total += self.inodes[i].writeback_pages as u64;
            }
        }
        total
    }

    /// Update bandwidth estimate
    pub fn update_bandwidth(&self, pages_written: u64, elapsed_ms: u64) {
        if elapsed_ms == 0 { return; }
        let bw = (pages_written * 1000) / elapsed_ms; // pages/sec
        let prev = self.avg_write_bandwidth.load(Ordering::Relaxed);
        // Exponential moving average
        let new_avg = (prev * 7 + bw) / 8;
        self.avg_write_bandwidth.store(new_avg.max(1), Ordering::Relaxed);
        self.write_bandwidth.store(bw, Ordering::Relaxed);
    }
}

// ─────────────────── Dirty Throttle State ───────────────────────────

#[repr(C)]
pub struct DirtyThrottleState {
    /// Global thresholds
    pub dirty_ratio_pct: AtomicU32,
    pub dirty_bg_ratio_pct: AtomicU32,
    /// Absolute limits (in pages, 0 = use ratio)
    pub dirty_bytes: AtomicU64,
    pub dirty_bg_bytes: AtomicU64,
    /// Current state
    pub nr_dirty_global: AtomicU64,
    pub nr_writeback_global: AtomicU64,
    pub total_ram_pages: AtomicU64,
    /// Throttle state per-task
    pub throttle_generation: AtomicU64,
    /// Writeback interval
    pub wb_interval_cs: AtomicU32,
    /// Balance dirty pages timing
    pub dirty_expire_cs: AtomicU32, // centiseconds
    /// Stats
    pub nr_dirtied: AtomicU64,
    pub nr_written: AtomicU64,
}

impl DirtyThrottleState {
    pub fn new(total_ram: u64) -> Self {
        Self {
            dirty_ratio_pct: AtomicU32::new(DEFAULT_DIRTY_RATIO),
            dirty_bg_ratio_pct: AtomicU32::new(DEFAULT_DIRTY_BG_RATIO),
            dirty_bytes: AtomicU64::new(0),
            dirty_bg_bytes: AtomicU64::new(0),
            nr_dirty_global: AtomicU64::new(0),
            nr_writeback_global: AtomicU64::new(0),
            total_ram_pages: AtomicU64::new(total_ram),
            throttle_generation: AtomicU64::new(0),
            wb_interval_cs: AtomicU32::new(DEFAULT_WB_INTERVAL_CS),
            dirty_expire_cs: AtomicU32::new(3000), // 30 seconds
            nr_dirtied: AtomicU64::new(0),
            nr_written: AtomicU64::new(0),
        }
    }

    /// Get dirty threshold in pages
    pub fn dirty_thresh(&self) -> u64 {
        let bytes = self.dirty_bytes.load(Ordering::Relaxed);
        if bytes > 0 {
            return bytes / 4096; // PAGE_SIZE
        }
        let total = self.total_ram_pages.load(Ordering::Relaxed);
        let ratio = self.dirty_ratio_pct.load(Ordering::Relaxed) as u64;
        (total * ratio) / 100
    }

    /// Get background dirty threshold
    pub fn bg_thresh(&self) -> u64 {
        let bytes = self.dirty_bg_bytes.load(Ordering::Relaxed);
        if bytes > 0 {
            return bytes / 4096;
        }
        let total = self.total_ram_pages.load(Ordering::Relaxed);
        let ratio = self.dirty_bg_ratio_pct.load(Ordering::Relaxed) as u64;
        (total * ratio) / 100
    }

    /// Check if we should start background writeback
    pub fn over_bg_thresh(&self) -> bool {
        self.nr_dirty_global.load(Ordering::Relaxed) > self.bg_thresh()
    }

    /// Check if we need to throttle dirtying
    pub fn over_dirty_thresh(&self) -> bool {
        let dirty = self.nr_dirty_global.load(Ordering::Relaxed);
        let wb = self.nr_writeback_global.load(Ordering::Relaxed);
        dirty + wb > self.dirty_thresh()
    }

    /// Balance dirty pages: slow down writers when approaching limits
    pub fn balance_dirty_pages(&self, pages_dirtied: u64) -> u64 {
        self.nr_dirtied.fetch_add(pages_dirtied, Ordering::Relaxed);
        self.nr_dirty_global.fetch_add(pages_dirtied, Ordering::Relaxed);

        if !self.over_dirty_thresh() {
            return 0; // No throttling needed
        }

        // Calculate pause time based on how far over threshold
        let thresh = self.dirty_thresh();
        let dirty = self.nr_dirty_global.load(Ordering::Relaxed);
        if dirty <= thresh || thresh == 0 {
            return 0;
        }

        // Proportional pause: more over = longer pause
        let excess_ratio = ((dirty - thresh) * 100) / thresh;
        let pause_ms = excess_ratio.min(200); // Max 200ms pause

        self.throttle_generation.fetch_add(1, Ordering::Relaxed);
        pause_ms
    }

    /// Record pages written back
    pub fn pages_written(&self, count: u64) {
        self.nr_written.fetch_add(count, Ordering::Relaxed);
        let prev = self.nr_dirty_global.load(Ordering::Relaxed);
        if prev >= count {
            self.nr_dirty_global.fetch_sub(count, Ordering::Relaxed);
        } else {
            self.nr_dirty_global.store(0, Ordering::Relaxed);
        }
    }

    pub fn dirty_ratio_pct(&self) -> u32 {
        let dirty = self.nr_dirty_global.load(Ordering::Relaxed);
        let total = self.total_ram_pages.load(Ordering::Relaxed);
        if total == 0 { return 0; }
        ((dirty * 100) / total) as u32
    }
}

// ─────────────────── Writeback Manager ──────────────────────────────

pub struct WritebackManager {
    pub bdis: [Option<BdiWriteback>; MAX_BDI],
    pub bdi_count: u32,
    pub throttle: DirtyThrottleState,
    /// Periodic timer
    pub last_periodic_time: AtomicU64,
    /// Global writeback counter
    pub total_wb_invocations: AtomicU64,
    pub initialized: AtomicBool,
}

impl WritebackManager {
    pub fn new(total_ram_pages: u64) -> Self {
        Self {
            bdis: [None, None, None, None, None, None, None, None,
                   None, None, None, None, None, None, None, None],
            bdi_count: 0,
            throttle: DirtyThrottleState::new(total_ram_pages),
            last_periodic_time: AtomicU64::new(0),
            total_wb_invocations: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self) {
        self.initialized.store(true, Ordering::Release);
    }

    /// Register a backing device
    pub fn register_bdi(&mut self, name: &[u8]) -> Option<u32> {
        if self.bdi_count as usize >= MAX_BDI { return None; }
        let id = self.bdi_count;
        let mut bdi = BdiWriteback::new(id);
        bdi.set_name(name);
        self.bdis[id as usize] = Some(bdi);
        self.bdi_count += 1;
        Some(id)
    }

    /// Mark pages dirty for an inode on a BDI
    pub fn mark_dirty(&mut self, bdi_id: u32, inode_nr: u64, pages: u32, time: u64) -> u64 {
        if let Some(ref mut bdi) = self.bdis[bdi_id as usize] {
            bdi.mark_inode_dirty(inode_nr, pages, time);
        }
        // Check throttling
        self.throttle.balance_dirty_pages(pages as u64)
    }

    /// Trigger background writeback if needed
    pub fn wakeup_flusher(&mut self, time: u64) {
        if !self.throttle.over_bg_thresh() { return; }

        for i in 0..self.bdi_count as usize {
            if let Some(ref mut bdi) = self.bdis[i] {
                if !bdi.active.load(Ordering::Relaxed) { continue; }
                let dirty = bdi.nr_dirty();
                if dirty > 0 {
                    let work = WbWorkItem {
                        reason: WbReason::Background,
                        nr_pages: dirty.min(1024), // batch size
                        sync_mode: WbSyncMode::None,
                        inode_nr: 0,
                        enqueued_time: time,
                        active: true,
                    };
                    bdi.enqueue_work(work);
                }
            }
        }
    }

    /// Process writeback work for a BDI
    pub fn process_bdi_work(&mut self, bdi_id: u32) -> u64 {
        let total_ram = self.throttle.total_ram_pages.load(Ordering::Relaxed);
        let _ = total_ram;

        if let Some(ref mut bdi) = self.bdis[bdi_id as usize] {
            let mut total_written = 0u64;

            while let Some(work) = bdi.dequeue_work() {
                let mut ctrl = WbControl::new(work.nr_pages, work.sync_mode);
                let written = bdi.do_writeback(&mut ctrl);
                total_written += written;
                self.throttle.pages_written(written);
            }

            self.total_wb_invocations.fetch_add(1, Ordering::Relaxed);
            total_written
        } else {
            0
        }
    }

    /// Periodic timer callback (every wb_interval centiseconds)
    pub fn periodic_writeback(&mut self, current_time: u64) {
        let interval_cs = self.throttle.wb_interval_cs.load(Ordering::Relaxed) as u64;
        let interval_us = interval_cs * 10000; // centiseconds to microseconds
        let last = self.last_periodic_time.load(Ordering::Relaxed);

        if current_time - last < interval_us { return; }
        self.last_periodic_time.store(current_time, Ordering::Relaxed);

        // Flush expired dirty pages
        let expire_cs = self.throttle.dirty_expire_cs.load(Ordering::Relaxed) as u64;
        let expire_us = expire_cs * 10000;

        for i in 0..self.bdi_count as usize {
            if let Some(ref mut bdi) = self.bdis[i] {
                if !bdi.active.load(Ordering::Relaxed) { continue; }

                // Find old dirty inodes
                let mut old_dirty = 0u64;
                for j in 0..bdi.inode_count as usize {
                    if bdi.inodes[j].active && bdi.inodes[j].dirty_pages > 0 {
                        if current_time - bdi.inodes[j].first_dirtied_time > expire_us {
                            old_dirty += bdi.inodes[j].dirty_pages as u64;
                        }
                    }
                }

                if old_dirty > 0 {
                    let work = WbWorkItem {
                        reason: WbReason::Periodic,
                        nr_pages: old_dirty,
                        sync_mode: WbSyncMode::None,
                        inode_nr: 0,
                        enqueued_time: current_time,
                        active: true,
                    };
                    bdi.enqueue_work(work);
                }
            }
        }
    }

    /// Sync all: write all dirty pages (called from sync() syscall)
    pub fn sync_all(&mut self, time: u64) -> u64 {
        let mut total = 0u64;
        for i in 0..self.bdi_count as usize {
            if let Some(ref mut bdi) = self.bdis[i] {
                let dirty = bdi.nr_dirty();
                if dirty > 0 {
                    let work = WbWorkItem {
                        reason: WbReason::SyncAll,
                        nr_pages: dirty,
                        sync_mode: WbSyncMode::All,
                        inode_nr: 0,
                        enqueued_time: time,
                        active: true,
                    };
                    bdi.enqueue_work(work);
                }
            }
        }
        // Process all
        for i in 0..self.bdi_count as usize {
            total += self.process_bdi_work(i as u32);
        }
        total
    }

    pub fn total_dirty_pages(&self) -> u64 {
        self.throttle.nr_dirty_global.load(Ordering::Relaxed)
    }

    pub fn total_written_pages(&self) -> u64 {
        self.throttle.nr_written.load(Ordering::Relaxed)
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut WB_MGR: Option<WritebackManager> = None;

fn wb_mgr() -> &'static mut WritebackManager {
    unsafe {
        if WB_MGR.is_none() {
            let mut mgr = WritebackManager::new(786432); // ~3GB
            mgr.init();
            WB_MGR = Some(mgr);
        }
        WB_MGR.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_writeback_init() {
    let _ = wb_mgr();
}

#[no_mangle]
pub extern "C" fn rust_writeback_register_bdi(name_ptr: *const u8, name_len: u32) -> i32 {
    if name_ptr.is_null() || name_len == 0 || name_len > 31 {
        return -1;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match wb_mgr().register_bdi(name) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_writeback_mark_dirty(bdi_id: u32, inode: u64, pages: u32, time: u64) -> u64 {
    wb_mgr().mark_dirty(bdi_id, inode, pages, time)
}

#[no_mangle]
pub extern "C" fn rust_writeback_sync_all(time: u64) -> u64 {
    wb_mgr().sync_all(time)
}

#[no_mangle]
pub extern "C" fn rust_writeback_periodic(current_time: u64) {
    wb_mgr().periodic_writeback(current_time);
}

#[no_mangle]
pub extern "C" fn rust_writeback_process_bdi(bdi_id: u32) -> u64 {
    wb_mgr().process_bdi_work(bdi_id)
}

#[no_mangle]
pub extern "C" fn rust_writeback_total_dirty() -> u64 {
    wb_mgr().total_dirty_pages()
}

#[no_mangle]
pub extern "C" fn rust_writeback_total_written() -> u64 {
    wb_mgr().total_written_pages()
}

#[no_mangle]
pub extern "C" fn rust_writeback_dirty_ratio() -> u32 {
    wb_mgr().throttle.dirty_ratio_pct()
}

#[no_mangle]
pub extern "C" fn rust_writeback_bdi_count() -> u32 {
    wb_mgr().bdi_count
}

#[no_mangle]
pub extern "C" fn rust_writeback_set_ratio(ratio: u32) {
    wb_mgr().throttle.dirty_ratio_pct.store(ratio.clamp(1, 90), Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn rust_writeback_set_bg_ratio(ratio: u32) {
    wb_mgr().throttle.dirty_bg_ratio_pct.store(ratio.clamp(1, 90), Ordering::Relaxed);
}
