// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Block Layer Page Cache (Rust)
//
// Buffer/page cache for block devices:
// - LRU page cache with dirty tracking
// - Write-back vs write-through policies
// - Read-ahead (sequential detection + prefetch)
// - Buffer head abstraction (sub-page block mapping)
// - Cache pressure reclamation (shrink callback)
// - Per-device I/O statistics
// - Writeback work queue integration
// - Barrier/flush support for data integrity
// - Sync/fsync semantics

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────

const PAGE_SIZE: usize = 4096;
const MAX_PAGES: usize = 2048;
const MAX_DEVICES: usize = 16;
const READAHEAD_WINDOW: u64 = 32; // Pages
const DIRTY_EXPIRE_JIFFIES: u64 = 3000; // ~30 seconds at 100 HZ

// ─────────────────── Page State ─────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PageState {
    Free = 0,
    Clean = 1,
    Dirty = 2,
    Writeback = 3,
    Locked = 4,
    Error = 5,
}

// ─────────────────── Cache Policy ───────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CachePolicy {
    WriteBack = 0,
    WriteThrough = 1,
    None = 2,       // Bypass cache (O_DIRECT)
}

// ─────────────────── Cached Page ────────────────────────────────────

#[derive(Clone, Copy)]
pub struct CachedPage {
    /// Block device this page belongs to
    pub dev_id: u16,
    /// Block offset (in PAGE_SIZE units)
    pub block_nr: u64,
    /// Page data
    pub data: [u8; PAGE_SIZE],
    /// State
    pub state: PageState,
    /// LRU timestamp (jiffies when last accessed)
    pub lru_time: u64,
    /// When this page became dirty
    pub dirty_time: u64,
    /// Access count (for frequency-based eviction)
    pub access_count: u32,
    /// Flags
    pub referenced: bool,
    pub uptodate: bool,
    pub active: bool,
}

impl CachedPage {
    pub const fn new() -> Self {
        Self {
            dev_id: 0,
            block_nr: 0,
            data: [0u8; PAGE_SIZE],
            state: PageState::Free,
            lru_time: 0,
            dirty_time: 0,
            access_count: 0,
            referenced: false,
            uptodate: false,
            active: false,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.state == PageState::Dirty && now.wrapping_sub(self.dirty_time) > DIRTY_EXPIRE_JIFFIES
    }
}

// ─────────────────── Buffer Head ────────────────────────────────────

/// Sub-page buffer for filesystems that use block sizes < PAGE_SIZE
#[derive(Clone, Copy)]
pub struct BufferHead {
    pub page_idx: u16,
    pub offset: u16,      // Offset within page
    pub size: u16,        // Block size (512, 1024, 2048, 4096)
    pub block_nr: u64,    // Absolute block number
    pub dirty: bool,
    pub uptodate: bool,
    pub active: bool,
}

impl BufferHead {
    pub const fn new() -> Self {
        Self {
            page_idx: 0,
            offset: 0,
            size: 512,
            block_nr: 0,
            dirty: false,
            uptodate: false,
            active: false,
        }
    }
}

const MAX_BUFFER_HEADS: usize = 4096;

// ─────────────────── Read-Ahead State ───────────────────────────────

#[derive(Clone, Copy)]
pub struct ReadAheadState {
    /// Start of current read-ahead window
    pub start: u64,
    /// Size of window (pages)
    pub size: u64,
    /// Maximum window size
    pub max_size: u64,
    /// Previous access block (for sequential detection)
    pub prev_block: u64,
    /// Sequential count
    pub sequential: u32,
    /// Async read-ahead trigger point
    pub async_size: u64,
    pub active: bool,
}

impl ReadAheadState {
    pub const fn new() -> Self {
        Self {
            start: 0,
            size: 4,
            max_size: READAHEAD_WINDOW,
            prev_block: u64::MAX,
            sequential: 0,
            async_size: 0,
            active: false,
        }
    }

    pub fn record_access(&mut self, block_nr: u64) {
        if self.prev_block != u64::MAX {
            if block_nr == self.prev_block + 1 {
                self.sequential += 1;
                // Grow window on sequential access
                if self.sequential > 4 && self.size < self.max_size {
                    self.size = (self.size * 2).min(self.max_size);
                }
            } else {
                // Random access — shrink
                self.sequential = 0;
                self.size = (self.size / 2).max(4);
            }
        }
        self.prev_block = block_nr;
    }

    /// Should we trigger read-ahead for this block?
    pub fn should_readahead(&self, block_nr: u64) -> bool {
        self.sequential > 2 && block_nr >= self.start + self.size - self.async_size
    }
}

// ─────────────────── Device Cache Stats ─────────────────────────────

#[derive(Clone, Copy)]
pub struct DeviceCacheStats {
    pub dev_id: u16,
    pub read_hits: u64,
    pub read_misses: u64,
    pub write_hits: u64,
    pub write_misses: u64,
    pub writebacks: u64,
    pub evictions: u64,
    pub readahead_pages: u64,
    pub policy: CachePolicy,
    pub readahead: ReadAheadState,
    pub active: bool,
}

impl DeviceCacheStats {
    pub const fn new() -> Self {
        Self {
            dev_id: 0,
            read_hits: 0,
            read_misses: 0,
            write_hits: 0,
            write_misses: 0,
            writebacks: 0,
            evictions: 0,
            readahead_pages: 0,
            policy: CachePolicy::WriteBack,
            readahead: ReadAheadState::new(),
            active: false,
        }
    }

    pub fn hit_ratio(&self) -> u32 {
        let total = self.read_hits + self.read_misses;
        if total == 0 {
            return 0;
        }
        ((self.read_hits * 100) / total) as u32
    }
}

// ─────────────────── Page Cache Manager ─────────────────────────────

pub struct PageCache {
    pages: [CachedPage; MAX_PAGES],
    page_count: u16,
    dirty_count: u16,

    buffer_heads: [BufferHead; MAX_BUFFER_HEADS],
    bh_count: u16,

    devices: [DeviceCacheStats; MAX_DEVICES],
    device_count: u8,

    /// Global clock for LRU
    clock: u64,

    /// Cache pressure (0-100, external hint from MM reclaimer)
    pressure: u8,

    // Global stats
    total_hits: AtomicU64,
    total_misses: AtomicU64,
    total_writebacks: AtomicU64,
    total_evictions: AtomicU64,
}

impl PageCache {
    pub const fn new() -> Self {
        Self {
            pages: [CachedPage::new(); MAX_PAGES],
            page_count: 0,
            dirty_count: 0,
            buffer_heads: [BufferHead::new(); MAX_BUFFER_HEADS],
            bh_count: 0,
            devices: [DeviceCacheStats::new(); MAX_DEVICES],
            device_count: 0,
            clock: 0,
            pressure: 0,
            total_hits: AtomicU64::new(0),
            total_misses: AtomicU64::new(0),
            total_writebacks: AtomicU64::new(0),
            total_evictions: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self) {
        // Nothing special — defaults are correct
    }

    /// Register a block device for caching
    pub fn register_device(&mut self, dev_id: u16, policy: CachePolicy) -> Option<u8> {
        if self.device_count as usize >= MAX_DEVICES {
            return None;
        }
        let idx = self.device_count;
        self.devices[idx as usize] = DeviceCacheStats::new();
        self.devices[idx as usize].dev_id = dev_id;
        self.devices[idx as usize].policy = policy;
        self.devices[idx as usize].active = true;
        self.device_count += 1;
        Some(idx)
    }

    fn find_device(&self, dev_id: u16) -> Option<u8> {
        for i in 0..self.device_count as usize {
            if self.devices[i].active && self.devices[i].dev_id == dev_id {
                return Some(i as u8);
            }
        }
        None
    }

    // ─── Page Lookup ────────────────────────────────────────────────

    fn find_page(&self, dev_id: u16, block_nr: u64) -> Option<u16> {
        for i in 0..MAX_PAGES {
            if self.pages[i].active && self.pages[i].dev_id == dev_id && self.pages[i].block_nr == block_nr
            {
                return Some(i as u16);
            }
        }
        None
    }

    fn alloc_page(&mut self) -> Option<u16> {
        // Find free page
        for i in 0..MAX_PAGES {
            if !self.pages[i].active {
                return Some(i as u16);
            }
        }
        // Evict LRU clean page
        self.evict_lru_clean()
    }

    fn evict_lru_clean(&mut self) -> Option<u16> {
        let mut oldest_time = u64::MAX;
        let mut oldest_idx: Option<u16> = None;

        // First pass: evict unreferenced clean pages
        for i in 0..MAX_PAGES {
            if self.pages[i].active
                && self.pages[i].state == PageState::Clean
                && !self.pages[i].referenced
            {
                if self.pages[i].lru_time < oldest_time {
                    oldest_time = self.pages[i].lru_time;
                    oldest_idx = Some(i as u16);
                }
            }
        }

        // Second pass: clear referenced bit (clock algorithm)
        if oldest_idx.is_none() {
            for i in 0..MAX_PAGES {
                if self.pages[i].active && self.pages[i].state == PageState::Clean {
                    if self.pages[i].referenced {
                        self.pages[i].referenced = false;
                    } else if self.pages[i].lru_time < oldest_time {
                        oldest_time = self.pages[i].lru_time;
                        oldest_idx = Some(i as u16);
                    }
                }
            }
        }

        if let Some(idx) = oldest_idx {
            let dev_id = self.pages[idx as usize].dev_id;
            self.pages[idx as usize].active = false;
            self.page_count -= 1;
            self.total_evictions.fetch_add(1, Ordering::Relaxed);
            if let Some(didx) = self.find_device(dev_id) {
                self.devices[didx as usize].evictions += 1;
            }
        }

        oldest_idx
    }

    // ─── Read ───────────────────────────────────────────────────────

    /// Read a page from cache. Returns page index if hit, None on miss.
    pub fn read_page(&mut self, dev_id: u16, block_nr: u64) -> Option<u16> {
        self.clock += 1;

        // Update read-ahead
        if let Some(didx) = self.find_device(dev_id) {
            self.devices[didx as usize].readahead.record_access(block_nr);
        }

        if let Some(idx) = self.find_page(dev_id, block_nr) {
            // Cache hit
            self.pages[idx as usize].lru_time = self.clock;
            self.pages[idx as usize].access_count += 1;
            self.pages[idx as usize].referenced = true;
            self.total_hits.fetch_add(1, Ordering::Relaxed);
            if let Some(didx) = self.find_device(dev_id) {
                self.devices[didx as usize].read_hits += 1;
            }
            return Some(idx);
        }

        // Cache miss
        self.total_misses.fetch_add(1, Ordering::Relaxed);
        if let Some(didx) = self.find_device(dev_id) {
            self.devices[didx as usize].read_misses += 1;
        }
        None
    }

    /// Insert a page into cache after reading from disk
    pub fn insert_page(&mut self, dev_id: u16, block_nr: u64, data: &[u8; PAGE_SIZE]) -> Option<u16> {
        let idx = self.alloc_page()?;
        let pg = &mut self.pages[idx as usize];
        pg.dev_id = dev_id;
        pg.block_nr = block_nr;
        pg.data.copy_from_slice(data);
        pg.state = PageState::Clean;
        pg.lru_time = self.clock;
        pg.dirty_time = 0;
        pg.access_count = 1;
        pg.referenced = true;
        pg.uptodate = true;
        pg.active = true;
        self.page_count += 1;
        Some(idx)
    }

    /// Get page data (after read_page returned an index)
    pub fn get_page_data(&self, idx: u16) -> Option<&[u8; PAGE_SIZE]> {
        let i = idx as usize;
        if i >= MAX_PAGES || !self.pages[i].active {
            return None;
        }
        Some(&self.pages[i].data)
    }

    // ─── Write ──────────────────────────────────────────────────────

    /// Write to a page in cache
    pub fn write_page(
        &mut self,
        dev_id: u16,
        block_nr: u64,
        data: &[u8; PAGE_SIZE],
    ) -> Option<u16> {
        self.clock += 1;

        let policy = if let Some(didx) = self.find_device(dev_id) {
            self.devices[didx as usize].policy
        } else {
            CachePolicy::WriteBack
        };

        // Check if page exists
        let idx = if let Some(existing) = self.find_page(dev_id, block_nr) {
            existing
        } else {
            // Allocate new page
            let new_idx = self.alloc_page()?;
            self.pages[new_idx as usize].dev_id = dev_id;
            self.pages[new_idx as usize].block_nr = block_nr;
            self.pages[new_idx as usize].active = true;
            self.page_count += 1;
            new_idx
        };

        let pg = &mut self.pages[idx as usize];
        pg.data.copy_from_slice(data);
        pg.lru_time = self.clock;
        pg.access_count += 1;
        pg.referenced = true;
        pg.uptodate = true;

        match policy {
            CachePolicy::WriteBack => {
                if pg.state != PageState::Dirty {
                    self.dirty_count += 1;
                }
                pg.state = PageState::Dirty;
                pg.dirty_time = self.clock;
            }
            CachePolicy::WriteThrough => {
                // Data must be written to disk immediately (handled by caller)
                pg.state = PageState::Clean;
                if let Some(didx) = self.find_device(dev_id) {
                    self.devices[didx as usize].writebacks += 1;
                }
                self.total_writebacks.fetch_add(1, Ordering::Relaxed);
            }
            CachePolicy::None => {
                // Not cached — mark for immediate eviction
                pg.state = PageState::Clean;
                pg.referenced = false;
            }
        }

        if let Some(didx) = self.find_device(dev_id) {
            if self.find_page(dev_id, block_nr).is_some() {
                self.devices[didx as usize].write_hits += 1;
            } else {
                self.devices[didx as usize].write_misses += 1;
            }
        }

        Some(idx)
    }

    // ─── Writeback ──────────────────────────────────────────────────

    /// Get dirty pages that need writeback (returns indices)
    pub fn get_dirty_pages(&self, dev_id: u16, out: &mut [u16; 64]) -> u8 {
        let mut count = 0u8;
        for i in 0..MAX_PAGES {
            if self.pages[i].active
                && self.pages[i].dev_id == dev_id
                && self.pages[i].state == PageState::Dirty
            {
                if (count as usize) < 64 {
                    out[count as usize] = i as u16;
                    count += 1;
                }
            }
        }
        count
    }

    /// Get expired dirty pages (need urgent writeback)
    pub fn get_expired_dirty(&self, out: &mut [u16; 64]) -> u8 {
        let mut count = 0u8;
        for i in 0..MAX_PAGES {
            if self.pages[i].active && self.pages[i].is_expired(self.clock) {
                if (count as usize) < 64 {
                    out[count as usize] = i as u16;
                    count += 1;
                }
            }
        }
        count
    }

    /// Mark page as being written back
    pub fn start_writeback(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_PAGES || !self.pages[i].active || self.pages[i].state != PageState::Dirty {
            return false;
        }
        self.pages[i].state = PageState::Writeback;
        true
    }

    /// Complete writeback — mark page clean
    pub fn complete_writeback(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_PAGES || !self.pages[i].active || self.pages[i].state != PageState::Writeback {
            return false;
        }
        self.pages[i].state = PageState::Clean;
        if self.dirty_count > 0 {
            self.dirty_count -= 1;
        }
        let dev_id = self.pages[i].dev_id;
        if let Some(didx) = self.find_device(dev_id) {
            self.devices[didx as usize].writebacks += 1;
        }
        self.total_writebacks.fetch_add(1, Ordering::Relaxed);
        true
    }

    // ─── Sync ───────────────────────────────────────────────────────

    /// Sync all dirty pages for a device (returns count)
    pub fn sync_device(&mut self, dev_id: u16) -> u16 {
        let mut count: u16 = 0;
        for i in 0..MAX_PAGES {
            if self.pages[i].active
                && self.pages[i].dev_id == dev_id
                && self.pages[i].state == PageState::Dirty
            {
                self.pages[i].state = PageState::Clean;
                if self.dirty_count > 0 {
                    self.dirty_count -= 1;
                }
                count += 1;
            }
        }
        if let Some(didx) = self.find_device(dev_id) {
            self.devices[didx as usize].writebacks += count as u64;
        }
        self.total_writebacks
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    /// Sync all dirty pages (all devices)
    pub fn sync_all(&mut self) -> u16 {
        let mut count: u16 = 0;
        for i in 0..MAX_PAGES {
            if self.pages[i].active && self.pages[i].state == PageState::Dirty {
                self.pages[i].state = PageState::Clean;
                count += 1;
            }
        }
        self.dirty_count = 0;
        self.total_writebacks
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    // ─── Invalidation ───────────────────────────────────────────────

    /// Invalidate all cached pages for a device
    pub fn invalidate_device(&mut self, dev_id: u16) -> u16 {
        let mut count: u16 = 0;
        for i in 0..MAX_PAGES {
            if self.pages[i].active && self.pages[i].dev_id == dev_id {
                if self.pages[i].state == PageState::Dirty {
                    if self.dirty_count > 0 {
                        self.dirty_count -= 1;
                    }
                }
                self.pages[i].active = false;
                self.page_count -= 1;
                count += 1;
            }
        }
        count
    }

    /// Invalidate a specific page
    pub fn invalidate_page(&mut self, dev_id: u16, block_nr: u64) -> bool {
        if let Some(idx) = self.find_page(dev_id, block_nr) {
            let i = idx as usize;
            if self.pages[i].state == PageState::Dirty && self.dirty_count > 0 {
                self.dirty_count -= 1;
            }
            self.pages[i].active = false;
            self.page_count -= 1;
            true
        } else {
            false
        }
    }

    // ─── Shrink (reclaim under memory pressure) ─────────────────────

    /// Shrink cache by evicting nr_to_scan clean pages. Returns evicted count.
    pub fn shrink(&mut self, nr_to_scan: u16) -> u16 {
        let mut evicted: u16 = 0;
        let mut i: usize = 0;

        while evicted < nr_to_scan && i < MAX_PAGES {
            if self.pages[i].active && self.pages[i].state == PageState::Clean {
                if !self.pages[i].referenced {
                    self.pages[i].active = false;
                    self.page_count -= 1;
                    evicted += 1;
                    self.total_evictions.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.pages[i].referenced = false;
                }
            }
            i += 1;
        }

        evicted
    }

    pub fn set_pressure(&mut self, pressure: u8) {
        self.pressure = pressure.min(100);
    }

    // ─── Buffer Heads ───────────────────────────────────────────────

    pub fn alloc_buffer_head(&mut self, page_idx: u16, offset: u16, size: u16, block_nr: u64) -> Option<u16> {
        for i in 0..MAX_BUFFER_HEADS {
            if !self.buffer_heads[i].active {
                self.buffer_heads[i] = BufferHead {
                    page_idx,
                    offset,
                    size,
                    block_nr,
                    dirty: false,
                    uptodate: false,
                    active: true,
                };
                self.bh_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn free_buffer_head(&mut self, idx: u16) {
        let i = idx as usize;
        if i < MAX_BUFFER_HEADS && self.buffer_heads[i].active {
            self.buffer_heads[i].active = false;
            self.bh_count -= 1;
        }
    }

    // ─── Tick (periodic maintenance) ────────────────────────────────

    pub fn tick(&mut self) {
        self.clock += 1;

        // Auto-shrink under high pressure
        if self.pressure > 80 && self.page_count > 0 {
            let nr = (self.page_count / 10).max(1);
            self.shrink(nr);
        }
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut PAGE_CACHE: PageCache = PageCache::new();

fn cache() -> &'static mut PageCache {
    unsafe { &mut PAGE_CACHE }
}

fn cache_ref() -> &'static PageCache {
    unsafe { &PAGE_CACHE }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_pagecache_init() {
    cache().init();
}

#[no_mangle]
pub extern "C" fn rust_pagecache_register_device(dev_id: u16, policy: u8) -> i8 {
    let p = match policy {
        0 => CachePolicy::WriteBack,
        1 => CachePolicy::WriteThrough,
        2 => CachePolicy::None,
        _ => CachePolicy::WriteBack,
    };
    match cache().register_device(dev_id, p) {
        Some(idx) => idx as i8,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_pagecache_page_count() -> u16 {
    cache_ref().page_count
}

#[no_mangle]
pub extern "C" fn rust_pagecache_dirty_count() -> u16 {
    cache_ref().dirty_count
}

#[no_mangle]
pub extern "C" fn rust_pagecache_total_hits() -> u64 {
    cache_ref().total_hits.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_pagecache_total_misses() -> u64 {
    cache_ref().total_misses.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_pagecache_total_writebacks() -> u64 {
    cache_ref().total_writebacks.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_pagecache_total_evictions() -> u64 {
    cache_ref().total_evictions.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_pagecache_sync_all() -> u16 {
    cache().sync_all()
}

#[no_mangle]
pub extern "C" fn rust_pagecache_shrink(nr: u16) -> u16 {
    cache().shrink(nr)
}

#[no_mangle]
pub extern "C" fn rust_pagecache_set_pressure(pressure: u8) {
    cache().set_pressure(pressure);
}

#[no_mangle]
pub extern "C" fn rust_pagecache_tick() {
    cache().tick();
}
