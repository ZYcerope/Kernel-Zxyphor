// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Swap Manager (Rust)
//
// Virtual memory swap subsystem:
// - Swap area management (disk partitions / swap files)
// - Swap slot allocator with cluster grouping
// - Swap cache for deduplication
// - Page-out / page-in (swap I/O) request tracking
// - Swap map with reference counting
// - Zswap (compressed swap cache) with LRU eviction
// - Swap priority management (multiple swap areas)
// - Swap readahead for sequential access
// - Swap throttling under memory pressure

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

/// Maximum concurrent swap areas
const MAX_SWAP_AREAS: usize = 8;
/// Swap slot cluster size (pages grouped for sequential I/O)
const CLUSTER_SIZE: usize = 64;
/// Maximum slots per swap area (256 MB in 4K pages)
const MAX_SLOTS: usize = 65536;
/// Swap cache hash table size
const SWAP_CACHE_HASH_SIZE: usize = 1024;
/// Zswap pool size in compressed pages
const ZSWAP_POOL_SIZE: usize = 4096;
/// Readahead window size (pages)
const READAHEAD_WINDOW: usize = 8;

// ─────────────────── Swap Slot Identifier ───────────────────────────

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct SwapEntry {
    /// Swap area index in bits [29..31], offset in bits [0..28]
    pub val: u32,
}

impl SwapEntry {
    pub const NONE: SwapEntry = SwapEntry { val: 0 };

    pub fn new(area: u8, offset: u32) -> Self {
        Self {
            val: ((area as u32 & 0x7) << 29) | (offset & 0x1FFFFFFF),
        }
    }

    pub fn area(self) -> u8 {
        ((self.val >> 29) & 0x7) as u8
    }

    pub fn offset(self) -> u32 {
        self.val & 0x1FFFFFFF
    }

    pub fn is_none(self) -> bool {
        self.val == 0
    }
}

// ─────────────────── Swap Slot Map ──────────────────────────────────
// Tracks reference counts per slot. 0 = free, >0 = in use.

pub struct SwapMap {
    /// Reference counts (0 = free, 255 = max)
    pub counts: [u8; MAX_SLOTS],
    /// Total number of configured slots
    pub nr_slots: u32,
    /// Number of free slots
    pub nr_free: AtomicU32,
    /// Cluster-based free tracking
    pub cluster_free: [u16; MAX_SLOTS / CLUSTER_SIZE],
    /// Next search hint for allocation
    pub search_hint: u32,
}

impl SwapMap {
    pub fn new(nr_slots: u32) -> Self {
        let capped = (nr_slots as usize).min(MAX_SLOTS);
        let nr_clusters = (capped + CLUSTER_SIZE - 1) / CLUSTER_SIZE;
        let mut map = Self {
            counts: [0u8; MAX_SLOTS],
            nr_slots: capped as u32,
            nr_free: AtomicU32::new(capped as u32),
            cluster_free: [0u16; MAX_SLOTS / CLUSTER_SIZE],
            search_hint: 0,
        };
        // Initialize cluster free counts
        for i in 0..nr_clusters {
            let cluster_slots = if (i + 1) * CLUSTER_SIZE <= capped {
                CLUSTER_SIZE as u16
            } else {
                (capped - i * CLUSTER_SIZE) as u16
            };
            map.cluster_free[i] = cluster_slots;
        }
        map
    }

    /// Allocate a single swap slot
    pub fn alloc(&mut self) -> Option<u32> {
        if self.nr_free.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let nr_clusters = ((self.nr_slots as usize) + CLUSTER_SIZE - 1) / CLUSTER_SIZE;
        let start_cluster = (self.search_hint as usize) / CLUSTER_SIZE;

        // Search from hint cluster forward, wrapping
        for attempt in 0..nr_clusters {
            let ci = (start_cluster + attempt) % nr_clusters;
            if self.cluster_free[ci] == 0 {
                continue;
            }
            // Search within cluster
            let base = ci * CLUSTER_SIZE;
            let end = ((ci + 1) * CLUSTER_SIZE).min(self.nr_slots as usize);
            for slot in base..end {
                if self.counts[slot] == 0 {
                    self.counts[slot] = 1;
                    self.cluster_free[ci] -= 1;
                    self.nr_free.fetch_sub(1, Ordering::Relaxed);
                    self.search_hint = (slot as u32) + 1;
                    return Some(slot as u32);
                }
            }
        }
        None
    }

    /// Allocate a contiguous cluster of slots (for readahead)
    pub fn alloc_cluster(&mut self) -> Option<u32> {
        let nr_clusters = ((self.nr_slots as usize) + CLUSTER_SIZE - 1) / CLUSTER_SIZE;
        for ci in 0..nr_clusters {
            if self.cluster_free[ci] == CLUSTER_SIZE as u16 {
                let base = ci * CLUSTER_SIZE;
                for slot in base..base + CLUSTER_SIZE {
                    self.counts[slot] = 1;
                }
                self.cluster_free[ci] = 0;
                self.nr_free.fetch_sub(CLUSTER_SIZE as u32, Ordering::Relaxed);
                return Some(base as u32);
            }
        }
        None
    }

    /// Increment reference count (for fork COW sharing)
    pub fn get_ref(&mut self, offset: u32) -> bool {
        let idx = offset as usize;
        if idx >= self.nr_slots as usize { return false; }
        if self.counts[idx] >= 254 { return false; } // Overflow guard
        self.counts[idx] += 1;
        true
    }

    /// Decrement reference count, free if zero
    pub fn put_ref(&mut self, offset: u32) -> bool {
        let idx = offset as usize;
        if idx >= self.nr_slots as usize { return false; }
        if self.counts[idx] == 0 { return false; }
        self.counts[idx] -= 1;
        if self.counts[idx] == 0 {
            let ci = idx / CLUSTER_SIZE;
            self.cluster_free[ci] += 1;
            self.nr_free.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    pub fn ref_count(&self, offset: u32) -> u8 {
        let idx = offset as usize;
        if idx >= self.nr_slots as usize { return 0; }
        self.counts[idx]
    }

    pub fn usage_percent(&self) -> u32 {
        if self.nr_slots == 0 { return 0; }
        let used = self.nr_slots - self.nr_free.load(Ordering::Relaxed);
        (used * 100) / self.nr_slots
    }
}

// ─────────────────── Swap Cache ─────────────────────────────────────
// Maps (swap_entry, page_frame) to avoid redundant I/O

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SwapCacheEntry {
    pub swap: SwapEntry,
    pub page_frame: u64,  // physical page frame number
    pub dirty: bool,
    pub valid: bool,
}

impl SwapCacheEntry {
    pub const EMPTY: Self = Self {
        swap: SwapEntry::NONE,
        page_frame: 0,
        dirty: false,
        valid: false,
    };
}

pub struct SwapCache {
    pub entries: [SwapCacheEntry; SWAP_CACHE_HASH_SIZE],
    pub hit_count: AtomicU64,
    pub miss_count: AtomicU64,
    pub evict_count: AtomicU64,
}

impl SwapCache {
    pub fn new() -> Self {
        Self {
            entries: [SwapCacheEntry::EMPTY; SWAP_CACHE_HASH_SIZE],
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            evict_count: AtomicU64::new(0),
        }
    }

    fn hash(entry: SwapEntry) -> usize {
        // FNV-1a inspired hash for swap entries
        let mut h = 2166136261u32;
        h ^= entry.val;
        h = h.wrapping_mul(16777619);
        h ^= entry.val >> 16;
        h = h.wrapping_mul(16777619);
        (h as usize) % SWAP_CACHE_HASH_SIZE
    }

    pub fn lookup(&self, swap: SwapEntry) -> Option<u64> {
        let idx = Self::hash(swap);
        // Linear probing
        for probe in 0..16 {
            let i = (idx + probe) % SWAP_CACHE_HASH_SIZE;
            if !self.entries[i].valid {
                self.miss_count.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if self.entries[i].swap.val == swap.val {
                self.hit_count.fetch_add(1, Ordering::Relaxed);
                return Some(self.entries[i].page_frame);
            }
        }
        self.miss_count.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&mut self, swap: SwapEntry, page_frame: u64) -> bool {
        let idx = Self::hash(swap);
        for probe in 0..16 {
            let i = (idx + probe) % SWAP_CACHE_HASH_SIZE;
            if !self.entries[i].valid {
                self.entries[i] = SwapCacheEntry {
                    swap,
                    page_frame,
                    dirty: false,
                    valid: true,
                };
                return true;
            }
            if self.entries[i].swap.val == swap.val {
                self.entries[i].page_frame = page_frame;
                return true;
            }
        }
        // Evict oldest in probe chain
        self.entries[idx] = SwapCacheEntry {
            swap,
            page_frame,
            dirty: false,
            valid: true,
        };
        self.evict_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn remove(&mut self, swap: SwapEntry) -> bool {
        let idx = Self::hash(swap);
        for probe in 0..16 {
            let i = (idx + probe) % SWAP_CACHE_HASH_SIZE;
            if !self.entries[i].valid { return false; }
            if self.entries[i].swap.val == swap.val {
                self.entries[i].valid = false;
                return true;
            }
        }
        false
    }

    pub fn hit_rate(&self) -> u32 {
        let hits = self.hit_count.load(Ordering::Relaxed);
        let misses = self.miss_count.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 { return 0; }
        ((hits * 100) / total) as u32
    }
}

// ─────────────────── Zswap (Compressed Swap Cache) ──────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZswapEntry {
    pub swap: SwapEntry,
    pub compressed_size: u32,
    /// Compressed data stored inline (max 2KB per entry for ~50% ratio)
    pub data: [u8; 2048],
    pub lru_time: u64,
    pub valid: bool,
}

impl ZswapEntry {
    pub const EMPTY: Self = Self {
        swap: SwapEntry::NONE,
        compressed_size: 0,
        data: [0u8; 2048],
        lru_time: 0,
        valid: false,
    };
}

pub struct ZswapPool {
    pub entries: [ZswapEntry; ZSWAP_POOL_SIZE],
    pub count: u32,
    pub max_entries: u32,
    pub stored_pages: AtomicU64,
    pub rejected_pages: AtomicU64,
    pub written_back: AtomicU64,
    pub time_counter: AtomicU64,
    /// Accept ratio threshold: reject if compression < this %
    pub accept_threshold_pct: u32,
}

impl ZswapPool {
    pub fn new() -> Self {
        Self {
            entries: [ZswapEntry::EMPTY; ZSWAP_POOL_SIZE],
            count: 0,
            max_entries: ZSWAP_POOL_SIZE as u32,
            stored_pages: AtomicU64::new(0),
            rejected_pages: AtomicU64::new(0),
            written_back: AtomicU64::new(0),
            time_counter: AtomicU64::new(0),
            accept_threshold_pct: 50, // reject if compressed > 50% of original
        }
    }

    /// Simple RLE-based compression for swap pages
    fn compress(input: &[u8], output: &mut [u8]) -> Option<u32> {
        if input.is_empty() { return None; }
        let mut out_pos = 0usize;
        let mut in_pos = 0usize;

        while in_pos < input.len() {
            let byte = input[in_pos];
            let mut run_len = 1u8;

            while in_pos + run_len as usize < input.len()
                && input[in_pos + run_len as usize] == byte
                && run_len < 255
            {
                run_len += 1;
            }

            if run_len >= 3 || byte == 0xFF {
                // Encode as: 0xFF <byte> <length>
                if out_pos + 3 > output.len() { return None; }
                output[out_pos] = 0xFF;
                output[out_pos + 1] = byte;
                output[out_pos + 2] = run_len;
                out_pos += 3;
            } else {
                for _ in 0..run_len {
                    if out_pos >= output.len() { return None; }
                    output[out_pos] = byte;
                    out_pos += 1;
                }
            }
            in_pos += run_len as usize;
        }
        Some(out_pos as u32)
    }

    /// Decompress RLE data
    fn decompress(input: &[u8], comp_size: u32, output: &mut [u8]) -> bool {
        let mut in_pos = 0usize;
        let mut out_pos = 0usize;
        let in_end = comp_size as usize;

        while in_pos < in_end {
            if input[in_pos] == 0xFF {
                if in_pos + 2 >= in_end { return false; }
                let byte = input[in_pos + 1];
                let count = input[in_pos + 2] as usize;
                if out_pos + count > output.len() { return false; }
                for i in 0..count {
                    output[out_pos + i] = byte;
                }
                out_pos += count;
                in_pos += 3;
            } else {
                if out_pos >= output.len() { return false; }
                output[out_pos] = input[in_pos];
                out_pos += 1;
                in_pos += 1;
            }
        }
        // Zero-fill remainder
        while out_pos < output.len() {
            output[out_pos] = 0;
            out_pos += 1;
        }
        true
    }

    /// Store a page in compressed form
    pub fn store(&mut self, swap: SwapEntry, page_data: &[u8]) -> bool {
        let mut compressed = [0u8; 2048];
        let comp_size = match Self::compress(page_data, &mut compressed) {
            Some(s) => s,
            None => {
                self.rejected_pages.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };

        // Check compression ratio
        let threshold = (page_data.len() as u32 * self.accept_threshold_pct) / 100;
        if comp_size > threshold {
            self.rejected_pages.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let time = self.time_counter.fetch_add(1, Ordering::Relaxed);

        // Find free slot or evict LRU
        let slot = if (self.count as usize) < ZSWAP_POOL_SIZE {
            let s = self.count as usize;
            self.count += 1;
            s
        } else {
            self.evict_lru()
        };

        self.entries[slot] = ZswapEntry {
            swap,
            compressed_size: comp_size,
            data: compressed,
            lru_time: time,
            valid: true,
        };
        self.stored_pages.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn evict_lru(&mut self) -> usize {
        let mut oldest_time = u64::MAX;
        let mut oldest_idx = 0usize;
        for i in 0..self.count as usize {
            if self.entries[i].valid && self.entries[i].lru_time < oldest_time {
                oldest_time = self.entries[i].lru_time;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx].valid = false;
        self.written_back.fetch_add(1, Ordering::Relaxed);
        oldest_idx
    }

    /// Load a page from compressed cache
    pub fn load(&mut self, swap: SwapEntry, output: &mut [u8]) -> bool {
        for i in 0..self.count as usize {
            if self.entries[i].valid && self.entries[i].swap.val == swap.val {
                let ok = Self::decompress(
                    &self.entries[i].data,
                    self.entries[i].compressed_size,
                    output,
                );
                if ok {
                    let time = self.time_counter.fetch_add(1, Ordering::Relaxed);
                    self.entries[i].lru_time = time;
                }
                return ok;
            }
        }
        false
    }

    /// Invalidate an entry
    pub fn invalidate(&mut self, swap: SwapEntry) {
        for i in 0..self.count as usize {
            if self.entries[i].valid && self.entries[i].swap.val == swap.val {
                self.entries[i].valid = false;
                return;
            }
        }
    }

    pub fn active_entries(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.count as usize {
            if self.entries[i].valid { count += 1; }
        }
        count
    }
}

// ─────────────────── Swap Area ──────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SwapAreaType {
    Partition = 0,
    File = 1,
}

#[repr(C)]
pub struct SwapArea {
    pub area_type: SwapAreaType,
    pub priority: i16,     // higher = preferred, -1 = auto
    pub nr_pages: u32,     // total swap slots
    pub map: SwapMap,
    pub flags: u32,        // SWP_USED | SWP_WRITEOK etc.
    pub active: bool,
    /// Swap I/O stats
    pub pages_in: AtomicU64,
    pub pages_out: AtomicU64,
    pub io_errors: AtomicU32,
}

// Swap flags
pub const SWP_USED: u32 = 1 << 0;
pub const SWP_WRITEOK: u32 = 1 << 1;
pub const SWP_DISCARDABLE: u32 = 1 << 2;
pub const SWP_DISCARDING: u32 = 1 << 3;
pub const SWP_SOLIDSTATE: u32 = 1 << 4;

impl SwapArea {
    pub fn new(area_type: SwapAreaType, nr_pages: u32, priority: i16) -> Self {
        Self {
            area_type,
            priority,
            nr_pages,
            map: SwapMap::new(nr_pages),
            flags: SWP_USED | SWP_WRITEOK,
            active: true,
            pages_in: AtomicU64::new(0),
            pages_out: AtomicU64::new(0),
            io_errors: AtomicU32::new(0),
        }
    }

    pub fn is_ssd(&self) -> bool {
        (self.flags & SWP_SOLIDSTATE) != 0
    }

    pub fn alloc_slot(&mut self) -> Option<u32> {
        if (self.flags & SWP_WRITEOK) == 0 { return None; }
        self.map.alloc()
    }

    pub fn free_slot(&mut self, offset: u32) {
        self.map.put_ref(offset);
    }

    pub fn record_page_out(&self) {
        self.pages_out.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_page_in(&self) {
        self.pages_in.fetch_add(1, Ordering::Relaxed);
    }
}

// ─────────────────── Swap Readahead ─────────────────────────────────

pub struct SwapReadahead {
    /// Last accessed swap entries for pattern detection
    pub history: [SwapEntry; 16],
    pub history_pos: usize,
    /// Current readahead window
    pub window_size: usize,
    /// Sequential detection
    pub sequential_count: u32,
}

impl SwapReadahead {
    pub fn new() -> Self {
        Self {
            history: [SwapEntry::NONE; 16],
            history_pos: 0,
            window_size: 1,
            sequential_count: 0,
        }
    }

    /// Record swap-in and detect access pattern
    pub fn record(&mut self, entry: SwapEntry) {
        let prev_pos = if self.history_pos > 0 { self.history_pos - 1 } else { 15 };
        let prev = self.history[prev_pos];

        if !prev.is_none()
            && prev.area() == entry.area()
            && entry.offset() == prev.offset() + 1
        {
            self.sequential_count += 1;
            // Grow readahead window on sequential access
            if self.sequential_count > 2 && self.window_size < READAHEAD_WINDOW {
                self.window_size += 1;
            }
        } else {
            self.sequential_count = 0;
            // Shrink window on random access
            if self.window_size > 1 {
                self.window_size -= 1;
            }
        }

        self.history[self.history_pos] = entry;
        self.history_pos = (self.history_pos + 1) % 16;
    }

    /// Get list of entries to readahead
    pub fn get_readahead(&self, entry: SwapEntry) -> ([SwapEntry; READAHEAD_WINDOW], usize) {
        let mut ahead = [SwapEntry::NONE; READAHEAD_WINDOW];
        let count = self.window_size.min(READAHEAD_WINDOW);
        for i in 0..count {
            ahead[i] = SwapEntry::new(entry.area(), entry.offset() + i as u32 + 1);
        }
        (ahead, count)
    }
}

// ─────────────────── Swap Manager ───────────────────────────────────

pub struct SwapManager {
    pub areas: [Option<SwapArea>; MAX_SWAP_AREAS],
    pub num_areas: u32,
    pub cache: SwapCache,
    pub zswap: ZswapPool,
    pub readahead: SwapReadahead,
    /// Throttle: max outstanding page-out I/Os
    pub max_pending_io: u32,
    pub pending_io: AtomicU32,
    /// Total stats
    pub total_swap_pages: AtomicU64,
    pub total_used_pages: AtomicU64,
    pub initialized: AtomicBool,
}

impl SwapManager {
    pub fn new() -> Self {
        Self {
            areas: [None, None, None, None, None, None, None, None],
            num_areas: 0,
            cache: SwapCache::new(),
            zswap: ZswapPool::new(),
            readahead: SwapReadahead::new(),
            max_pending_io: 64,
            pending_io: AtomicU32::new(0),
            total_swap_pages: AtomicU64::new(0),
            total_used_pages: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self) {
        self.initialized.store(true, Ordering::Release);
    }

    /// Add a swap area
    pub fn swapon(
        &mut self,
        area_type: SwapAreaType,
        nr_pages: u32,
        priority: i16,
    ) -> Option<u8> {
        if self.num_areas as usize >= MAX_SWAP_AREAS { return None; }

        let idx = self.num_areas as usize;
        let actual_priority = if priority < 0 {
            // Auto-assign decreasing priority
            (MAX_SWAP_AREAS as i16) - idx as i16
        } else {
            priority
        };

        self.areas[idx] = Some(SwapArea::new(area_type, nr_pages, actual_priority));
        self.num_areas += 1;
        self.total_swap_pages.fetch_add(nr_pages as u64, Ordering::Relaxed);
        Some(idx as u8)
    }

    /// Disable a swap area
    pub fn swapoff(&mut self, area_idx: u8) -> bool {
        let idx = area_idx as usize;
        if idx >= self.num_areas as usize { return false; }
        if let Some(ref mut area) = self.areas[idx] {
            // Check if any slots still in use
            let free = area.map.nr_free.load(Ordering::Relaxed);
            if free < area.nr_pages {
                return false; // Cannot disable while pages in use
            }
            area.active = false;
            area.flags &= !SWP_WRITEOK;
            self.total_swap_pages.fetch_sub(area.nr_pages as u64, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Allocate a swap slot from the highest-priority area
    pub fn alloc_page(&mut self) -> Option<SwapEntry> {
        // Sort by priority (highest first) — simple selection
        let mut best_area: Option<usize> = None;
        let mut best_priority: i16 = i16::MIN;

        for i in 0..self.num_areas as usize {
            if let Some(ref area) = self.areas[i] {
                if area.active
                    && (area.flags & SWP_WRITEOK) != 0
                    && area.map.nr_free.load(Ordering::Relaxed) > 0
                    && area.priority > best_priority
                {
                    best_area = Some(i);
                    best_priority = area.priority;
                }
            }
        }

        let area_idx = best_area?;
        if let Some(ref mut area) = self.areas[area_idx] {
            let offset = area.alloc_slot()?;
            self.total_used_pages.fetch_add(1, Ordering::Relaxed);
            Some(SwapEntry::new(area_idx as u8, offset))
        } else {
            None
        }
    }

    /// Free a swap slot
    pub fn free_page(&mut self, entry: SwapEntry) {
        let area_idx = entry.area() as usize;
        if area_idx >= self.num_areas as usize { return; }
        if let Some(ref mut area) = self.areas[area_idx] {
            area.free_slot(entry.offset());
            self.total_used_pages.fetch_sub(1, Ordering::Relaxed);
        }
        self.cache.remove(entry);
        self.zswap.invalidate(entry);
    }

    /// Page-out: write page to swap (tries zswap first)
    pub fn page_out(&mut self, page_data: &[u8]) -> Option<SwapEntry> {
        // Throttle check
        let pending = self.pending_io.load(Ordering::Relaxed);
        if pending >= self.max_pending_io {
            return None;
        }

        let entry = self.alloc_page()?;

        // Try zswap first
        if self.zswap.store(entry, page_data) {
            return Some(entry);
        }

        // Fall back to disk I/O
        let area_idx = entry.area() as usize;
        if let Some(ref area) = self.areas[area_idx] {
            area.record_page_out();
        }
        self.pending_io.fetch_add(1, Ordering::Relaxed);
        Some(entry)
    }

    /// Page-in: read page from swap (checks zswap/cache first)
    pub fn page_in(&mut self, entry: SwapEntry, output: &mut [u8]) -> bool {
        // Check swap cache
        if let Some(_pfn) = self.cache.lookup(entry) {
            return true; // Page still in memory
        }

        // Check zswap
        if self.zswap.load(entry, output) {
            self.readahead.record(entry);
            return true;
        }

        // Need disk I/O
        let area_idx = entry.area() as usize;
        if area_idx >= self.num_areas as usize { return false; }
        if let Some(ref area) = self.areas[area_idx] {
            if !area.active { return false; }
            area.record_page_in();
        }

        self.readahead.record(entry);
        self.pending_io.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// I/O completion callback
    pub fn io_complete(&self) {
        let prev = self.pending_io.load(Ordering::Relaxed);
        if prev > 0 {
            self.pending_io.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn total_pages(&self) -> u64 {
        self.total_swap_pages.load(Ordering::Relaxed)
    }

    pub fn used_pages(&self) -> u64 {
        self.total_used_pages.load(Ordering::Relaxed)
    }

    pub fn free_pages(&self) -> u64 {
        self.total_pages() - self.used_pages()
    }

    pub fn usage_percent(&self) -> u32 {
        let total = self.total_pages();
        if total == 0 { return 0; }
        ((self.used_pages() * 100) / total) as u32
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut SWAP_MGR: Option<SwapManager> = None;

fn swap_mgr() -> &'static mut SwapManager {
    unsafe {
        if SWAP_MGR.is_none() {
            let mut mgr = SwapManager::new();
            mgr.init();
            SWAP_MGR = Some(mgr);
        }
        SWAP_MGR.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_swap_init() {
    let _ = swap_mgr();
}

#[no_mangle]
pub extern "C" fn rust_swap_swapon(area_type: u8, nr_pages: u32, priority: i16) -> i32 {
    let at = if area_type == 0 { SwapAreaType::Partition } else { SwapAreaType::File };
    match swap_mgr().swapon(at, nr_pages, priority) {
        Some(idx) => idx as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_swap_swapoff(area_idx: u8) -> i32 {
    if swap_mgr().swapoff(area_idx) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_swap_total_pages() -> u64 {
    swap_mgr().total_pages()
}

#[no_mangle]
pub extern "C" fn rust_swap_used_pages() -> u64 {
    swap_mgr().used_pages()
}

#[no_mangle]
pub extern "C" fn rust_swap_usage_pct() -> u32 {
    swap_mgr().usage_percent()
}

#[no_mangle]
pub extern "C" fn rust_swap_area_count() -> u32 {
    swap_mgr().num_areas
}

#[no_mangle]
pub extern "C" fn rust_swap_cache_hit_rate() -> u32 {
    swap_mgr().cache.hit_rate()
}

#[no_mangle]
pub extern "C" fn rust_swap_zswap_entries() -> u32 {
    swap_mgr().zswap.active_entries()
}

#[no_mangle]
pub extern "C" fn rust_swap_pending_io() -> u32 {
    swap_mgr().pending_io.load(Ordering::Relaxed)
}
