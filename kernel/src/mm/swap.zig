// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Memory Swap Subsystem (Zig)
//
// Full swap management for virtual memory paging:
// - Swap area management (multiple swap devices/files)
// - Swap slot allocation (bitmap-based, cluster grouping)
// - Page swap-out (LRU eviction → swap write)
// - Page swap-in (fault handler → swap read → page frame)
// - Swap cache (avoid redundant I/O for recently swapped pages)
// - Swap statistics and pressure tracking
// - Priority-based swap device selection
// - Swap entry encoding (type : 5 bits, offset : 59 bits)
// - Swappiness control (tunable eviction aggressiveness)
// - Read-ahead during swap-in (batch sequential slots)
// - Swap extent tracking (contiguous allocation optimization)
// - Reference counting for shared swap entries

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_SWAP_AREAS: usize = 8;
const MAX_SWAP_SLOTS: usize = 65536; // Per area (256 MB at 4K pages)
const BITMAP_WORDS: usize = MAX_SWAP_SLOTS / 64;
const SWAP_CLUSTER_SIZE: usize = 64; // Pages per cluster
const SWAP_CACHE_SIZE: usize = 2048;
const PAGE_SIZE: usize = 4096;
const READAHEAD_MAX: usize = 8;
const MAX_EXTENTS: usize = 128;
const SWAP_TYPE_BITS: u6 = 5;
const SWAP_OFFSET_SHIFT: u6 = 5;
const SWAP_TYPE_MASK: u64 = (1 << SWAP_TYPE_BITS) - 1;

// ─────────────────── Swap Entry ─────────────────────────────────────

/// Encoded swap entry: [63:5] = offset, [4:0] = type
pub const SwapEntry = struct {
    value: u64,

    pub fn make(swap_type: u8, offset: u64) SwapEntry {
        return .{ .value = (offset << SWAP_OFFSET_SHIFT) | @as(u64, swap_type & @as(u8, @intCast(SWAP_TYPE_MASK))) };
    }

    pub fn swap_type(self: SwapEntry) u8 {
        return @intCast(self.value & SWAP_TYPE_MASK);
    }

    pub fn offset(self: SwapEntry) u64 {
        return self.value >> SWAP_OFFSET_SHIFT;
    }

    pub fn is_valid(self: SwapEntry) bool {
        return self.value != 0;
    }

    pub fn none() SwapEntry {
        return .{ .value = 0 };
    }
};

// ─────────────────── Swap Area ──────────────────────────────────────

pub const SwapFlags = packed struct {
    writethrough: bool = false,
    discard: bool = false,  // TRIM support
    solid_state: bool = false,
    prefer: bool = false,
    _pad: u4 = 0,
};

pub const SwapAreaState = enum(u8) {
    inactive = 0,
    active = 1,
    degraded = 2,
    full = 3,
};

pub const SwapExtent = struct {
    start_slot: u32,
    nr_slots: u32,
    start_block: u64, // Physical block device offset
};

pub const SwapArea = struct {
    /// Allocation bitmap: 1 = used, 0 = free
    bitmap: [BITMAP_WORDS]u64,
    /// Reference counts per slot (for shared mappings via fork/COW)
    refcounts: [MAX_SWAP_SLOTS]u8,
    /// Total slots available
    total_slots: u32,
    /// Free slots remaining
    free_slots: u32,
    /// Lowest free slot hint (for O(1) allocation amortization)
    lowest_free: u32,
    /// Device/file identifier
    dev_id: u32,
    /// Priority (higher = used first)
    priority: i16,
    /// State
    state: SwapAreaState,
    /// Flags
    flags: SwapFlags,
    /// Current cluster for contiguous allocation
    cluster_next: u32,
    cluster_nr: u32,
    /// Extents (physical layout)
    extents: [MAX_EXTENTS]SwapExtent,
    extent_count: u16,
    /// Stats
    pages_in: u64,
    pages_out: u64,
    discard_count: u64,
    /// Active flag
    active: bool,

    const Self = @This();

    pub fn init(dev_id: u32, total: u32, priority: i16) Self {
        var area: Self = undefined;
        area.bitmap = [_]u64{0} ** BITMAP_WORDS;
        area.refcounts = [_]u8{0} ** MAX_SWAP_SLOTS;
        area.total_slots = total;
        area.free_slots = total;
        area.lowest_free = 0;
        area.dev_id = dev_id;
        area.priority = priority;
        area.state = .active;
        area.flags = .{};
        area.cluster_next = 0;
        area.cluster_nr = SWAP_CLUSTER_SIZE;
        area.extent_count = 0;
        area.pages_in = 0;
        area.pages_out = 0;
        area.discard_count = 0;
        area.active = true;
        // Mark slot 0 as used (reserved for "no swap" sentinel)
        area.bitmap[0] |= 1;
        area.free_slots -= 1;
        area.lowest_free = 1;
        return area;
    }

    /// Allocate a swap slot. Returns slot index or null.
    pub fn alloc_slot(self: *Self) ?u32 {
        if (self.free_slots == 0) {
            self.state = .full;
            return null;
        }

        // Try cluster-first allocation for locality
        if (self.cluster_nr < SWAP_CLUSTER_SIZE) {
            const slot = self.cluster_next + @as(u32, @intCast(self.cluster_nr));
            if (slot < self.total_slots and !self.is_slot_used(slot)) {
                self.mark_used(slot);
                self.cluster_nr += 1;
                return slot;
            }
        }

        // Scan from lowest_free hint
        var slot = self.lowest_free;
        while (slot < self.total_slots) : (slot += 1) {
            if (!self.is_slot_used(slot)) {
                self.mark_used(slot);
                // Start new cluster
                self.cluster_next = slot;
                self.cluster_nr = 1;
                // Update lowest_free
                self.update_lowest_free(slot + 1);
                return slot;
            }
        }

        self.state = .full;
        return null;
    }

    /// Free a swap slot
    pub fn free_slot(self: *Self, slot: u32) void {
        if (slot >= self.total_slots) return;
        if (!self.is_slot_used(slot)) return;

        // Decrement refcount
        if (self.refcounts[slot] > 1) {
            self.refcounts[slot] -= 1;
            return;
        }

        self.mark_free(slot);
        self.refcounts[slot] = 0;
        if (slot < self.lowest_free) {
            self.lowest_free = slot;
        }
        if (self.state == .full) {
            self.state = .active;
        }
    }

    /// Increment reference count for shared swap entry
    pub fn dup_slot(self: *Self, slot: u32) void {
        if (slot >= self.total_slots) return;
        if (self.refcounts[slot] < 255) {
            self.refcounts[slot] += 1;
        }
    }

    fn is_slot_used(self: *const Self, slot: u32) bool {
        const word = slot / 64;
        const bit: u6 = @intCast(slot % 64);
        return (self.bitmap[word] & (@as(u64, 1) << bit)) != 0;
    }

    fn mark_used(self: *Self, slot: u32) void {
        const word = slot / 64;
        const bit: u6 = @intCast(slot % 64);
        self.bitmap[word] |= (@as(u64, 1) << bit);
        self.free_slots -= 1;
        self.refcounts[slot] = 1;
    }

    fn mark_free(self: *Self, slot: u32) void {
        const word = slot / 64;
        const bit: u6 = @intCast(slot % 64);
        self.bitmap[word] &= ~(@as(u64, 1) << bit);
        self.free_slots += 1;
    }

    fn update_lowest_free(self: *Self, from: u32) void {
        var i = from;
        while (i < self.total_slots) : (i += 1) {
            if (!self.is_slot_used(i)) {
                self.lowest_free = i;
                return;
            }
        }
        self.lowest_free = self.total_slots;
    }

    pub fn usage_percent(self: *const Self) u8 {
        if (self.total_slots == 0) return 0;
        return @intCast(((@as(u64, self.total_slots - self.free_slots)) * 100) / @as(u64, self.total_slots));
    }

    pub fn add_extent(self: *Self, start_slot: u32, nr_slots: u32, start_block: u64) bool {
        if (self.extent_count >= MAX_EXTENTS) return false;
        self.extents[self.extent_count] = .{
            .start_slot = start_slot,
            .nr_slots = nr_slots,
            .start_block = start_block,
        };
        self.extent_count += 1;
        return true;
    }
};

// ─────────────────── Swap Cache ─────────────────────────────────────

pub const SwapCacheEntry = struct {
    entry: SwapEntry,
    page_frame: u64, // Physical frame address
    dirty: bool,
    referenced: bool,
    locked: bool,
    timestamp: u64,
    active: bool,
};

pub const SwapCache = struct {
    entries: [SWAP_CACHE_SIZE]SwapCacheEntry,
    count: u16,
    hits: u64,
    misses: u64,

    pub fn init() SwapCache {
        var sc: SwapCache = undefined;
        for (0..SWAP_CACHE_SIZE) |i| {
            sc.entries[i] = .{
                .entry = SwapEntry.none(),
                .page_frame = 0,
                .dirty = false,
                .referenced = false,
                .locked = false,
                .timestamp = 0,
                .active = false,
            };
        }
        sc.count = 0;
        sc.hits = 0;
        sc.misses = 0;
        return sc;
    }

    /// Find page in swap cache
    pub fn find(self: *SwapCache, entry: SwapEntry) ?u64 {
        for (0..SWAP_CACHE_SIZE) |i| {
            if (self.entries[i].active and self.entries[i].entry.value == entry.value) {
                self.entries[i].referenced = true;
                self.hits += 1;
                return self.entries[i].page_frame;
            }
        }
        self.misses += 1;
        return null;
    }

    /// Insert page into swap cache
    pub fn insert(self: *SwapCache, entry: SwapEntry, page_frame: u64, timestamp: u64) bool {
        // Check duplicate
        for (0..SWAP_CACHE_SIZE) |i| {
            if (self.entries[i].active and self.entries[i].entry.value == entry.value) {
                self.entries[i].page_frame = page_frame;
                self.entries[i].timestamp = timestamp;
                self.entries[i].referenced = true;
                return true;
            }
        }

        // Find free slot
        for (0..SWAP_CACHE_SIZE) |i| {
            if (!self.entries[i].active) {
                self.entries[i] = .{
                    .entry = entry,
                    .page_frame = page_frame,
                    .dirty = false,
                    .referenced = true,
                    .locked = false,
                    .timestamp = timestamp,
                    .active = true,
                };
                self.count += 1;
                return true;
            }
        }

        // Evict unreferenced entry (clock algorithm)
        for (0..SWAP_CACHE_SIZE) |i| {
            if (self.entries[i].active and !self.entries[i].referenced and !self.entries[i].locked) {
                self.entries[i] = .{
                    .entry = entry,
                    .page_frame = page_frame,
                    .dirty = false,
                    .referenced = true,
                    .locked = false,
                    .timestamp = timestamp,
                    .active = true,
                };
                return true;
            }
        }

        // Second pass: clear referenced bits
        for (0..SWAP_CACHE_SIZE) |i| {
            if (self.entries[i].active and !self.entries[i].locked) {
                self.entries[i].referenced = false;
            }
        }
        // Try again
        for (0..SWAP_CACHE_SIZE) |i| {
            if (self.entries[i].active and !self.entries[i].referenced and !self.entries[i].locked) {
                self.entries[i] = .{
                    .entry = entry,
                    .page_frame = page_frame,
                    .dirty = false,
                    .referenced = true,
                    .locked = false,
                    .timestamp = timestamp,
                    .active = true,
                };
                return true;
            }
        }

        return false;
    }

    /// Remove from cache
    pub fn remove(self: *SwapCache, entry: SwapEntry) bool {
        for (0..SWAP_CACHE_SIZE) |i| {
            if (self.entries[i].active and self.entries[i].entry.value == entry.value) {
                self.entries[i].active = false;
                self.count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn hit_ratio(self: *const SwapCache) u8 {
        const total = self.hits + self.misses;
        if (total == 0) return 0;
        return @intCast((self.hits * 100) / total);
    }
};

// ─────────────────── Swap Manager ───────────────────────────────────

pub const SwapManager = struct {
    areas: [MAX_SWAP_AREAS]SwapArea,
    area_count: u8,

    cache: SwapCache,

    /// Swappiness (0-200, default 60). Higher = more aggressive swap
    swappiness: u16,
    /// High watermark: start swapping above this memory pressure (%)
    high_wmark: u8,
    /// Low watermark: stop swapping below this
    low_wmark: u8,

    /// Readahead window
    readahead_pages: u8,

    /// Monotonic tick for cache timestamps
    tick: u64,

    // Stats
    total_swap_out: u64,
    total_swap_in: u64,
    total_cache_hits: u64,
    total_alloc_fails: u64,
    total_reclaimed: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        return .{
            .areas = undefined,
            .area_count = 0,
            .cache = SwapCache.init(),
            .swappiness = 60,
            .high_wmark = 90,
            .low_wmark = 70,
            .readahead_pages = 4,
            .tick = 0,
            .total_swap_out = 0,
            .total_swap_in = 0,
            .total_cache_hits = 0,
            .total_alloc_fails = 0,
            .total_reclaimed = 0,
            .initialized = true,
        };
    }

    // ─── Area Management ────────────────────────────────────────────

    pub fn add_area(self: *Self, dev_id: u32, total_pages: u32, priority: i16) ?u8 {
        if (self.area_count >= MAX_SWAP_AREAS) return null;
        const capped = @min(total_pages, MAX_SWAP_SLOTS);
        const idx = self.area_count;
        self.areas[idx] = SwapArea.init(dev_id, @intCast(capped), priority);
        self.area_count += 1;
        return idx;
    }

    pub fn remove_area(self: *Self, idx: u8) bool {
        if (idx >= self.area_count) return false;
        if (!self.areas[idx].active) return false;
        // Refuse if slots still in use
        if (self.areas[idx].free_slots < self.areas[idx].total_slots - 1) return false;
        self.areas[idx].active = false;
        return true;
    }

    /// Select best area (highest priority with free slots)
    fn select_area(self: *Self) ?u8 {
        var best: ?u8 = null;
        var best_prio: i16 = -32768;

        for (0..self.area_count) |i| {
            if (!self.areas[i].active or self.areas[i].state == .full) continue;
            if (self.areas[i].priority > best_prio) {
                best_prio = self.areas[i].priority;
                best = @intCast(i);
            }
        }
        return best;
    }

    // ─── Swap Out (Page → Swap) ─────────────────────────────────────

    /// Swap out a page. Returns swap entry or null on failure.
    pub fn swap_out(self: *Self, page_frame: u64) ?SwapEntry {
        const area_idx = self.select_area() orelse {
            self.total_alloc_fails += 1;
            return null;
        };

        const slot = self.areas[area_idx].alloc_slot() orelse {
            self.total_alloc_fails += 1;
            return null;
        };

        const entry = SwapEntry.make(area_idx, @as(u64, slot));

        // Add to swap cache
        self.tick += 1;
        _ = self.cache.insert(entry, page_frame, self.tick);

        self.areas[area_idx].pages_out += 1;
        self.total_swap_out += 1;

        return entry;
    }

    // ─── Swap In (Swap → Page) ──────────────────────────────────────

    /// Swap in a page. Returns page frame address or null.
    pub fn swap_in(self: *Self, entry: SwapEntry) ?u64 {
        if (!entry.is_valid()) return null;

        // Check swap cache first
        if (self.cache.find(entry)) |pf| {
            self.total_cache_hits += 1;
            // Trigger readahead
            self.readahead(entry);
            return pf;
        }

        const area_idx = entry.swap_type();
        if (area_idx >= self.area_count) return null;
        if (!self.areas[area_idx].active) return null;

        // In a real kernel, this would issue I/O to read the page.
        // Here we return a sentinel "read from disk" address.
        const slot_offset = entry.offset();
        const pf = slot_offset * PAGE_SIZE; // Placeholder

        // Insert into cache for future reads
        self.tick += 1;
        _ = self.cache.insert(entry, pf, self.tick);

        self.areas[area_idx].pages_in += 1;
        self.total_swap_in += 1;

        // Trigger readahead
        self.readahead(entry);

        return pf;
    }

    /// Free a swap entry (page no longer needed in swap)
    pub fn swap_free(self: *Self, entry: SwapEntry) void {
        if (!entry.is_valid()) return;
        const area_idx = entry.swap_type();
        if (area_idx >= self.area_count) return;
        const slot: u32 = @intCast(entry.offset());
        self.areas[area_idx].free_slot(slot);
        _ = self.cache.remove(entry);
        self.total_reclaimed += 1;
    }

    /// Duplicate swap entry (for fork/COW)
    pub fn swap_dup(self: *Self, entry: SwapEntry) void {
        if (!entry.is_valid()) return;
        const area_idx = entry.swap_type();
        if (area_idx >= self.area_count) return;
        const slot: u32 = @intCast(entry.offset());
        self.areas[area_idx].dup_slot(slot);
    }

    // ─── Readahead ──────────────────────────────────────────────────

    fn readahead(self: *Self, entry: SwapEntry) void {
        const area_idx = entry.swap_type();
        if (area_idx >= self.area_count) return;
        const base_offset = entry.offset();

        var i: u8 = 1;
        while (i <= self.readahead_pages) : (i += 1) {
            const ra_offset = base_offset + @as(u64, i);
            if (ra_offset >= @as(u64, self.areas[area_idx].total_slots)) break;
            const ra_entry = SwapEntry.make(area_idx, ra_offset);
            // Only readahead if slot is actually used (contains data)
            const slot: u32 = @intCast(ra_offset);
            if (self.areas[area_idx].is_slot_used(slot)) {
                if (self.cache.find(ra_entry) == null) {
                    // Would issue async I/O here; for now insert placeholder
                    self.tick += 1;
                    _ = self.cache.insert(ra_entry, ra_offset * PAGE_SIZE, self.tick);
                }
            }
        }
    }

    // ─── Statistics ─────────────────────────────────────────────────

    pub fn total_capacity(self: *const Self) u64 {
        var total: u64 = 0;
        for (0..self.area_count) |i| {
            if (self.areas[i].active) {
                total += @as(u64, self.areas[i].total_slots);
            }
        }
        return total;
    }

    pub fn total_free(self: *const Self) u64 {
        var free: u64 = 0;
        for (0..self.area_count) |i| {
            if (self.areas[i].active) {
                free += @as(u64, self.areas[i].free_slots);
            }
        }
        return free;
    }

    pub fn total_used(self: *const Self) u64 {
        return self.total_capacity() - self.total_free();
    }

    pub fn pressure(self: *const Self) u8 {
        const cap = self.total_capacity();
        if (cap == 0) return 0;
        return @intCast((self.total_used() * 100) / cap);
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_swap: SwapManager = undefined;
var g_swap_initialized: bool = false;

fn swap() *SwapManager {
    return &g_swap;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_swap_init() void {
    g_swap = SwapManager.init();
    g_swap_initialized = true;
}

export fn zxy_swap_add_area(dev_id: u32, total_pages: u32, priority: i16) i8 {
    if (!g_swap_initialized) return -1;
    if (swap().add_area(dev_id, total_pages, priority)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_swap_out(page_frame: u64) u64 {
    if (!g_swap_initialized) return 0;
    if (swap().swap_out(page_frame)) |entry| return entry.value;
    return 0;
}

export fn zxy_swap_in(entry_val: u64) u64 {
    if (!g_swap_initialized) return 0;
    const entry = SwapEntry{ .value = entry_val };
    if (swap().swap_in(entry)) |pf| return pf;
    return 0;
}

export fn zxy_swap_free(entry_val: u64) void {
    if (!g_swap_initialized) return;
    swap().swap_free(.{ .value = entry_val });
}

export fn zxy_swap_dup(entry_val: u64) void {
    if (!g_swap_initialized) return;
    swap().swap_dup(.{ .value = entry_val });
}

export fn zxy_swap_total_out() u64 {
    if (!g_swap_initialized) return 0;
    return swap().total_swap_out;
}

export fn zxy_swap_total_in() u64 {
    if (!g_swap_initialized) return 0;
    return swap().total_swap_in;
}

export fn zxy_swap_capacity() u64 {
    if (!g_swap_initialized) return 0;
    return swap().total_capacity();
}

export fn zxy_swap_used() u64 {
    if (!g_swap_initialized) return 0;
    return swap().total_used();
}

export fn zxy_swap_free_slots() u64 {
    if (!g_swap_initialized) return 0;
    return swap().total_free();
}

export fn zxy_swap_pressure() u8 {
    if (!g_swap_initialized) return 0;
    return swap().pressure();
}

export fn zxy_swap_cache_hits() u64 {
    if (!g_swap_initialized) return 0;
    return swap().total_cache_hits;
}

export fn zxy_swap_cache_count() u16 {
    if (!g_swap_initialized) return 0;
    return swap().cache.count;
}

export fn zxy_swap_area_count() u8 {
    if (!g_swap_initialized) return 0;
    return swap().area_count;
}

export fn zxy_swap_set_swappiness(val: u16) void {
    if (!g_swap_initialized) return;
    swap().swappiness = @min(val, 200);
}

export fn zxy_swap_get_swappiness() u16 {
    if (!g_swap_initialized) return 60;
    return swap().swappiness;
}
