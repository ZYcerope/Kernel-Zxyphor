// =============================================================================
// Kernel Zxyphor — Page Reclaim & Swap Subsystem
// =============================================================================
// Linux-style page reclaim with LRU lists, swap management, page writeback,
// kswapd-style background reclaim, and OOM killer integration.
// =============================================================================

// ============================================================================
// Constants
// ============================================================================

pub const MAX_SWAP_AREAS: usize = 8;
pub const MAX_SWAP_EXTENT: usize = 64;
pub const SWAP_CLUSTER_MAX: u32 = 32;
pub const SWAP_MAP_FREE: u8 = 0;
pub const SWAP_MAP_USED: u8 = 1;
pub const SWAP_MAP_SHARED: u8 = 2;

pub const LRU_INACTIVE_ANON: u8 = 0;
pub const LRU_ACTIVE_ANON: u8 = 1;
pub const LRU_INACTIVE_FILE: u8 = 2;
pub const LRU_ACTIVE_FILE: u8 = 3;
pub const LRU_UNEVICTABLE: u8 = 4;
pub const NR_LRU_LISTS: usize = 5;

const BATCH_SIZE: u32 = 32;

// ============================================================================
// Swap entry
// ============================================================================

pub const SwapEntry = struct {
    raw: u64,

    pub fn empty() SwapEntry {
        return .{ .raw = 0 };
    }

    pub fn encode(area_id: u8, offset: u32) SwapEntry {
        return .{ .raw = (@as(u64, area_id) << 48) | @as(u64, offset) };
    }

    pub fn areaId(self: SwapEntry) u8 {
        return @intCast(self.raw >> 48);
    }

    pub fn offset(self: SwapEntry) u32 {
        return @truncate(self.raw);
    }

    pub fn isValid(self: SwapEntry) bool {
        return self.raw != 0;
    }
};

// ============================================================================
// Swap extent (maps swap offsets to disk blocks)
// ============================================================================

pub const SwapExtent = struct {
    start_page: u32,
    nr_pages: u32,
    start_block: u64,

    pub fn isEmpty(self: *const SwapExtent) bool {
        return self.nr_pages == 0;
    }

    pub fn contains(self: *const SwapExtent, page: u32) bool {
        return page >= self.start_page and page < self.start_page + self.nr_pages;
    }

    pub fn toBlock(self: *const SwapExtent, page: u32) u64 {
        return self.start_block + @as(u64, page - self.start_page);
    }
};

// ============================================================================
// Swap area
// ============================================================================

pub const SwapArea = struct {
    device_id: u32,
    flags: u32,
    priority: i16,
    active: bool,
    total_pages: u32,
    used_pages: u32,
    highest_bit: u32,
    lowest_bit: u32,
    cluster_next: u32,

    // Extent map
    extents: [MAX_SWAP_EXTENT]SwapExtent,
    extent_count: u32,

    // Swap map (per-page usage count)
    swap_map: [8192]u8, // One byte per swap slot

    pub fn init() SwapArea {
        var area: SwapArea = undefined;
        area.device_id = 0;
        area.flags = 0;
        area.priority = 0;
        area.active = false;
        area.total_pages = 0;
        area.used_pages = 0;
        area.highest_bit = 0;
        area.lowest_bit = 0;
        area.cluster_next = 0;
        area.extent_count = 0;
        for (0..MAX_SWAP_EXTENT) |i| {
            area.extents[i] = .{ .start_page = 0, .nr_pages = 0, .start_block = 0 };
        }
        for (0..8192) |i| {
            area.swap_map[i] = SWAP_MAP_FREE;
        }
        return area;
    }

    /// Allocate a swap slot
    pub fn allocSlot(self: *SwapArea) ?u32 {
        if (self.used_pages >= self.total_pages) return null;

        // Cluster-based allocation for sequential I/O
        var offset = self.cluster_next;
        var scanned: u32 = 0;
        while (scanned < self.total_pages) : (scanned += 1) {
            if (offset >= self.total_pages) offset = 0;
            if (self.swap_map[offset] == SWAP_MAP_FREE) {
                self.swap_map[offset] = SWAP_MAP_USED;
                self.used_pages += 1;
                self.cluster_next = offset + 1;
                return offset;
            }
            offset += 1;
        }
        return null;
    }

    /// Free a swap slot
    pub fn freeSlot(self: *SwapArea, slot: u32) void {
        if (slot >= self.total_pages) return;
        if (self.swap_map[slot] != SWAP_MAP_FREE) {
            self.swap_map[slot] = SWAP_MAP_FREE;
            self.used_pages -= 1;
            if (slot < self.lowest_bit) self.lowest_bit = slot;
        }
    }

    /// Increment reference count (shared swap)
    pub fn dupSlot(self: *SwapArea, slot: u32) bool {
        if (slot >= self.total_pages) return false;
        if (self.swap_map[slot] == SWAP_MAP_FREE) return false;
        if (self.swap_map[slot] < 255) {
            self.swap_map[slot] += 1;
            return true;
        }
        return false; // Max refs reached
    }
};

// ============================================================================
// LRU list for page reclaim
// ============================================================================

pub const LruList = struct {
    head: u32,  // PFN/page index
    tail: u32,
    count: u64,
    scan_count: u64,

    pub fn init() LruList {
        return .{
            .head = 0xFFFFFFFF,
            .tail = 0xFFFFFFFF,
            .count = 0,
            .scan_count = 0,
        };
    }

    pub fn isEmpty(self: *const LruList) bool {
        return self.count == 0;
    }
};

// ============================================================================
// Page reclaim statistics
// ============================================================================

pub const ReclaimStat = struct {
    scanned_anon: u64,
    scanned_file: u64,
    reclaimed_anon: u64,
    reclaimed_file: u64,
    activated: u64,
    deactivated: u64,
    writeback: u64,
    congestion_wait: u64,
    oom_kill: u64,

    pub fn init() ReclaimStat {
        return .{
            .scanned_anon = 0,
            .scanned_file = 0,
            .reclaimed_anon = 0,
            .reclaimed_file = 0,
            .activated = 0,
            .deactivated = 0,
            .writeback = 0,
            .congestion_wait = 0,
            .oom_kill = 0,
        };
    }
};

// ============================================================================
// Scan control (controls reclaim behavior per invocation)
// ============================================================================

pub const ScanControl = struct {
    nr_to_reclaim: u64,
    nr_reclaimed: u64,
    nr_scanned: u64,
    priority: u8,           // Scanning priority (0 = most aggressive)
    may_writepage: bool,    // Can write dirty pages
    may_swap: bool,         // Can swap anonymous pages
    may_unmap: bool,        // Can unmap pages from processes
    compaction_ready: bool, // Enough free pages for compaction
    target_lruvec: ?u8,     // Specific LRU to target, or null for all

    pub fn default() ScanControl {
        return .{
            .nr_to_reclaim = BATCH_SIZE,
            .nr_reclaimed = 0,
            .nr_scanned = 0,
            .priority = 12,  // Start with light scanning
            .may_writepage = true,
            .may_swap = true,
            .may_unmap = true,
            .compaction_ready = false,
            .target_lruvec = null,
        };
    }
};

// ============================================================================
// OOM score for process selection
// ============================================================================

pub const OomScore = struct {
    pid: u32,
    score: i32,
    adj: i16,           // OOM score adjustment (-1000 to 1000)
    rss_pages: u64,     // Resident set size
    swap_pages: u64,    // Swap usage
    oom_protected: bool, // Not killable

    pub fn calculate(rss: u64, swap: u64, total_ram: u64, adj: i16) i32 {
        if (adj == -1000) return 0; // Protected
        // Linux-like: normalize RSS to 0-1000 range, then apply adjustment
        const rss_score: i64 = @intCast((rss * 1000) / @max(total_ram, 1));
        var score: i64 = rss_score + @as(i64, adj);
        if (score < 0) score = 0;
        if (score > 1000) score = 1000;
        return @intCast(score);
    }
};

// ============================================================================
// Page cache entry (for file-backed page tracking)
// ============================================================================

pub const PageCacheEntry = struct {
    pfn: u32,           // Page frame number
    inode: u64,         // File inode
    file_offset: u64,   // Offset within file (in pages)
    dirty: bool,
    referenced: bool,
    uptodate: bool,
    locked: bool,
    writeback: bool,

    pub fn init() PageCacheEntry {
        return .{
            .pfn = 0,
            .inode = 0,
            .file_offset = 0,
            .dirty = false,
            .referenced = false,
            .uptodate = false,
            .locked = false,
            .writeback = false,
        };
    }
};

pub const MAX_PAGE_CACHE: usize = 4096;

// ============================================================================
// Page reclaim engine
// ============================================================================

pub const PageReclaimEngine = struct {
    // Per-LRU lists
    lru: [NR_LRU_LISTS]LruList,
    stats: ReclaimStat,

    // Swap areas
    swap_areas: [MAX_SWAP_AREAS]SwapArea,
    swap_count: u32,
    total_swap_pages: u64,
    free_swap_pages: u64,

    // Page cache (simplified radix tree substitute)
    page_cache: [MAX_PAGE_CACHE]PageCacheEntry,
    cache_count: u32,

    // OOM state
    oom_in_progress: bool,
    last_oom_pid: u32,

    // Configuration
    swappiness: u32,       // 0-200 (default 60)
    min_free_kbytes: u64,
    vfs_cache_pressure: u32,  // 0-1000 (default 100)

    pub fn init() PageReclaimEngine {
        var engine: PageReclaimEngine = undefined;
        for (0..NR_LRU_LISTS) |i| {
            engine.lru[i] = LruList.init();
        }
        engine.stats = ReclaimStat.init();
        for (0..MAX_SWAP_AREAS) |i| {
            engine.swap_areas[i] = SwapArea.init();
        }
        engine.swap_count = 0;
        engine.total_swap_pages = 0;
        engine.free_swap_pages = 0;
        for (0..MAX_PAGE_CACHE) |i| {
            engine.page_cache[i] = PageCacheEntry.init();
        }
        engine.cache_count = 0;
        engine.oom_in_progress = false;
        engine.last_oom_pid = 0;
        engine.swappiness = 60;
        engine.min_free_kbytes = 16384;
        engine.vfs_cache_pressure = 100;
        return engine;
    }

    /// Register a swap area
    pub fn addSwapArea(self: *PageReclaimEngine, device_id: u32, total_pages: u32, priority: i16) bool {
        if (self.swap_count >= MAX_SWAP_AREAS) return false;
        const idx = self.swap_count;
        self.swap_areas[idx].device_id = device_id;
        self.swap_areas[idx].total_pages = @min(total_pages, 8192);
        self.swap_areas[idx].priority = priority;
        self.swap_areas[idx].active = true;
        self.total_swap_pages += total_pages;
        self.free_swap_pages += total_pages;
        self.swap_count += 1;
        return true;
    }

    /// Allocate a swap entry (pick highest priority area with free slots)
    pub fn allocSwapEntry(self: *PageReclaimEngine) SwapEntry {
        var best_area: ?u8 = null;
        var best_priority: i16 = -32768;

        for (0..self.swap_count) |i| {
            const area = &self.swap_areas[i];
            if (area.active and area.used_pages < area.total_pages) {
                if (area.priority > best_priority) {
                    best_priority = area.priority;
                    best_area = @intCast(i);
                }
            }
        }

        if (best_area) |area_id| {
            if (self.swap_areas[area_id].allocSlot()) |slot| {
                self.free_swap_pages -= 1;
                return SwapEntry.encode(area_id, slot);
            }
        }
        return SwapEntry.empty();
    }

    /// Free a swap entry
    pub fn freeSwapEntry(self: *PageReclaimEngine, entry: SwapEntry) void {
        if (!entry.isValid()) return;
        const area_id = entry.areaId();
        if (area_id >= self.swap_count) return;
        self.swap_areas[area_id].freeSlot(entry.offset());
        self.free_swap_pages += 1;
    }

    /// Add a page to the page cache
    pub fn addToPageCache(self: *PageReclaimEngine, pfn: u32, inode: u64, file_offset: u64) bool {
        if (self.cache_count >= MAX_PAGE_CACHE) return false;
        self.page_cache[self.cache_count] = .{
            .pfn = pfn,
            .inode = inode,
            .file_offset = file_offset,
            .dirty = false,
            .referenced = false,
            .uptodate = true,
            .locked = false,
            .writeback = false,
        };
        self.cache_count += 1;
        return true;
    }

    /// Lookup page in cache
    pub fn findInPageCache(self: *const PageReclaimEngine, inode: u64, offset: u64) ?u32 {
        for (0..self.cache_count) |i| {
            const entry = &self.page_cache[i];
            if (entry.inode == inode and entry.file_offset == offset) {
                return entry.pfn;
            }
        }
        return null;
    }

    /// Perform page reclaim
    pub fn reclaimPages(self: *PageReclaimEngine, sc: *ScanControl) void {
        // Calculate anon/file scan ratio based on swappiness
        const anon_priority = self.swappiness;
        const file_priority = 200 - self.swappiness;

        // Scan inactive file list first (cheaper)
        if (file_priority > 0) {
            const to_scan = @max(sc.nr_to_reclaim / 2, 1);
            self.shrinkInactiveList(LRU_INACTIVE_FILE, to_scan, sc);
        }

        // Scan inactive anon if swap is available
        if (anon_priority > 0 and sc.may_swap and self.free_swap_pages > 0) {
            const to_scan = @max(sc.nr_to_reclaim / 2, 1);
            self.shrinkInactiveList(LRU_INACTIVE_ANON, to_scan, sc);
        }

        // If not enough reclaimed, shrink active lists
        if (sc.nr_reclaimed < sc.nr_to_reclaim) {
            self.shrinkActiveList(LRU_ACTIVE_FILE);
            self.shrinkActiveList(LRU_ACTIVE_ANON);
        }
    }

    /// Shrink the inactive list of given type
    fn shrinkInactiveList(self: *PageReclaimEngine, lru_type: u8, nr_to_scan: u64, sc: *ScanControl) void {
        var scanned: u64 = 0;
        while (scanned < nr_to_scan and !self.lru[lru_type].isEmpty()) : (scanned += 1) {
            self.lru[lru_type].scan_count += 1;
            sc.nr_scanned += 1;

            // In a real implementation:
            // 1. Remove from tail of inactive list
            // 2. Check referenced bit → move to active if set
            // 3. If file-backed and clean → free immediately
            // 4. If dirty → queue for writeback (if may_writepage)
            // 5. If anon → swap out (if may_swap)
            // Simplified: just count
            self.lru[lru_type].count -|= 1;
            sc.nr_reclaimed += 1;

            if (lru_type == LRU_INACTIVE_ANON) {
                self.stats.reclaimed_anon += 1;
                self.stats.scanned_anon += 1;
            } else {
                self.stats.reclaimed_file += 1;
                self.stats.scanned_file += 1;
            }
        }
    }

    /// Shrink active list (move pages to inactive)
    fn shrinkActiveList(self: *PageReclaimEngine, lru_type: u8) void {
        if (self.lru[lru_type].isEmpty()) return;
        // Move some pages from active to inactive
        const to_move = @min(self.lru[lru_type].count, BATCH_SIZE);
        self.lru[lru_type].count -|= to_move;
        const inactive_type = lru_type - 1; // ACTIVE_FILE→INACTIVE_FILE etc.
        self.lru[inactive_type].count += to_move;
        self.stats.deactivated += to_move;
    }

    /// Background reclaim (kswapd equivalent)
    pub fn backgroundReclaim(self: *PageReclaimEngine, free_pages: u64, target_free: u64) void {
        if (free_pages >= target_free) return;

        var sc = ScanControl.default();
        sc.nr_to_reclaim = target_free - free_pages;
        sc.priority = 12;

        // Reduce priority (increase aggressiveness) if needed
        while (sc.priority > 0 and sc.nr_reclaimed < sc.nr_to_reclaim) : (sc.priority -= 1) {
            self.reclaimPages(&sc);
        }
    }

    /// Direct reclaim (when allocation fails)
    pub fn directReclaim(self: *PageReclaimEngine, order: u8) u64 {
        var sc = ScanControl.default();
        sc.nr_to_reclaim = @as(u64, 1) << @intCast(order);
        sc.priority = 4; // More aggressive than background

        self.reclaimPages(&sc);
        return sc.nr_reclaimed;
    }

    /// Select OOM victim
    pub fn selectOomVictim(self: *PageReclaimEngine, pids: []const u32, rss: []const u64, adjs: []const i16, total_ram: u64) ?u32 {
        var worst_score: i32 = 0;
        var victim: ?u32 = null;

        for (0..pids.len) |i| {
            const score = OomScore.calculate(rss[i], 0, total_ram, adjs[i]);
            if (score > worst_score) {
                worst_score = score;
                victim = pids[i];
            }
        }

        if (victim) |v| {
            self.oom_in_progress = true;
            self.last_oom_pid = v;
            self.stats.oom_kill += 1;
        }
        return victim;
    }

    /// Get swap usage info
    pub fn getSwapInfo(self: *const PageReclaimEngine) SwapInfo {
        return .{
            .total = self.total_swap_pages,
            .free = self.free_swap_pages,
            .used = self.total_swap_pages - self.free_swap_pages,
            .areas = self.swap_count,
        };
    }
};

pub const SwapInfo = struct {
    total: u64,
    free: u64,
    used: u64,
    areas: u32,
};

var reclaim_engine: PageReclaimEngine = PageReclaimEngine.init();

pub fn getReclaimEngine() *PageReclaimEngine {
    return &reclaim_engine;
}
