// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Memory Management: CMA, Huge Pages, OOM, Memory Hotplug
// Full physical memory management with advanced features

const std = @import("std");

// ============================================================================
// Page Flags
// ============================================================================

pub const PG_locked: u32 = 0;
pub const PG_referenced: u32 = 1;
pub const PG_uptodate: u32 = 2;
pub const PG_dirty: u32 = 3;
pub const PG_lru: u32 = 4;
pub const PG_active: u32 = 5;
pub const PG_workingset: u32 = 6;
pub const PG_waiters: u32 = 7;
pub const PG_error: u32 = 8;
pub const PG_slab: u32 = 9;
pub const PG_owner_priv_1: u32 = 10;
pub const PG_arch_1: u32 = 11;
pub const PG_reserved: u32 = 12;
pub const PG_private: u32 = 13;
pub const PG_private_2: u32 = 14;
pub const PG_writeback: u32 = 15;
pub const PG_head: u32 = 16;
pub const PG_mappedtodisk: u32 = 17;
pub const PG_reclaim: u32 = 18;
pub const PG_swapbacked: u32 = 19;
pub const PG_unevictable: u32 = 20;
pub const PG_mlocked: u32 = 21;
pub const PG_hwpoison: u32 = 22;
pub const PG_young: u32 = 23;
pub const PG_idle: u32 = 24;
pub const PG_arch_2: u32 = 25;
pub const PG_arch_3: u32 = 26;

pub const PageFlags = u32;

pub fn test_page_flag(flags: PageFlags, bit: u32) bool {
    return (flags & (@as(u32, 1) << @as(u5, @truncate(bit)))) != 0;
}

pub fn set_page_flag(flags: *PageFlags, bit: u32) void {
    flags.* |= @as(u32, 1) << @as(u5, @truncate(bit));
}

pub fn clear_page_flag(flags: *PageFlags, bit: u32) void {
    flags.* &= ~(@as(u32, 1) << @as(u5, @truncate(bit)));
}

// ============================================================================
// GFP Flags (Get Free Pages allocation flags)
// ============================================================================

pub const GFP_ATOMIC: u32 = 0x00000001;     // Cannot sleep
pub const GFP_KERNEL: u32 = 0x00000002;     // Normal kernel allocation
pub const GFP_NOWAIT: u32 = 0x00000004;
pub const GFP_NOIO: u32 = 0x00000008;
pub const GFP_NOFS: u32 = 0x00000010;
pub const GFP_USER: u32 = 0x00000020;       // User-space allocation
pub const GFP_DMA: u32 = 0x00000040;        // DMA zone
pub const GFP_DMA32: u32 = 0x00000080;      // DMA32 zone
pub const GFP_HIGHUSER: u32 = 0x00000100;
pub const GFP_HIGHUSER_MOVABLE: u32 = 0x00000200;
pub const GFP_TRANSHUGE: u32 = 0x00000400;
pub const GFP_ZERO: u32 = 0x00000800;       // Zero pages
pub const GFP_COMP: u32 = 0x00001000;       // Compound page
pub const GFP_RETRY_MAYFAIL: u32 = 0x00002000;
pub const GFP_NOFAIL: u32 = 0x00004000;     // Must succeed
pub const GFP_NORETRY: u32 = 0x00008000;
pub const GFP_NOWARN: u32 = 0x00010000;
pub const GFP_THISNODE: u32 = 0x00020000;
pub const GFP_MOVABLE: u32 = 0x00040000;
pub const GFP_HARDWALL: u32 = 0x00080000;
pub const GFP_ACCOUNT: u32 = 0x00100000;
pub const GFP_RECLAIM: u32 = 0x00200000;
pub const GFP_DIRECT_RECLAIM: u32 = 0x00400000;
pub const GFP_KSWAPD_RECLAIM: u32 = 0x00800000;

// ============================================================================
// Zone Types
// ============================================================================

pub const ZoneType = enum(u8) {
    ZONE_DMA = 0,       // < 16MB (ISA DMA)
    ZONE_DMA32 = 1,     // < 4GB
    ZONE_NORMAL = 2,    // Normal mappable memory
    ZONE_HIGHMEM = 3,   // Only on 32-bit
    ZONE_MOVABLE = 4,   // Memory hotplug/CMA
    ZONE_DEVICE = 5,    // Device memory (PMEM, GPU)
};

pub const MAX_ZONES: usize = 6;
pub const MAX_ORDER: usize = 11; // Max buddy order (0-10, max = 2^10 * 4KB = 4MB)
pub const MAX_NR_ZONES: usize = 6;
pub const MAX_NUMNODES: usize = 64;

// ============================================================================
// Free Area (Buddy allocator free list per order)
// ============================================================================

pub const MigrateType = enum(u8) {
    UNMOVABLE = 0,
    MOVABLE = 1,
    RECLAIMABLE = 2,
    PCPTYPES = 3,  // Number of types on pcp lists
    HIGHATOMIC = 3,
    CMA = 4,
    ISOLATE = 5,
    NR_TYPES = 6,
};

pub const FreeArea = struct {
    free_list: [6]PageList, // One per migrate type
    nr_free: u64,
};

pub const PageList = struct {
    head: ?*PageFrame,
    tail: ?*PageFrame,
    count: u64,

    pub fn add(self: *PageList, page: *PageFrame) void {
        page.next = self.head;
        page.prev = null;
        if (self.head) |h| h.prev = page;
        if (self.tail == null) self.tail = page;
        self.head = page;
        self.count += 1;
    }

    pub fn remove(self: *PageList, page: *PageFrame) void {
        if (page.prev) |p| p.next = page.next else self.head = page.next;
        if (page.next) |n| n.prev = page.prev else self.tail = page.prev;
        page.prev = null;
        page.next = null;
        self.count -= 1;
    }

    pub fn pop(self: *PageList) ?*PageFrame {
        const page = self.head orelse return null;
        self.remove(page);
        return page;
    }
};

// ============================================================================
// Page Frame Structure
// ============================================================================

pub const PageFrame = struct {
    flags: PageFlags,
    // Linked list pointers (for free lists, LRU lists)
    next: ?*PageFrame,
    prev: ?*PageFrame,
    // Physical frame number
    pfn: u64,
    // Reference count
    ref_count: i32,
    map_count: i32, // Number of page table mappings
    // Slab info (when used by slab allocator)
    slab_cache: ?*anyopaque,
    // Page cache (when used by file cache)
    mapping: ?*anyopaque,
    index: u64,
    // Compound page
    compound_head: ?*PageFrame,
    compound_order: u8,
    compound_mapcount: i32,
    // Private data
    private: u64,
    // Memory cgroup
    memcg_data: u64,
    // NUMA node
    node_id: u8,
    zone_id: u8,
    // Migrate type
    migrate_type: MigrateType,

    pub fn order_pages(self: *PageFrame) u64 {
        return @as(u64, 1) << @as(u6, self.compound_order);
    }

    pub fn is_compound(self: *const PageFrame) bool {
        return test_page_flag(self.flags, PG_head);
    }

    pub fn is_free(self: *const PageFrame) bool {
        return self.ref_count == 0;
    }

    pub fn get(self: *PageFrame) void {
        self.ref_count += 1;
    }

    pub fn put(self: *PageFrame) bool {
        self.ref_count -= 1;
        return self.ref_count == 0;
    }
};

// ============================================================================
// Zone Structure
// ============================================================================

pub const Zone = struct {
    name: [16]u8,
    zone_type: ZoneType,
    // Watermarks
    watermark_min: u64,
    watermark_low: u64,
    watermark_high: u64,
    watermark_boost: u64,
    // Free pages
    free_area: [MAX_ORDER]FreeArea,
    managed_pages: u64,
    spanned_pages: u64,
    present_pages: u64,
    // PCP (Per-CPU Pages)
    per_cpu_pages: [256]PerCpuPages, // Up to 256 CPUs
    // Statistics
    vm_stat: [32]i64,
    // Zone lock
    lock: u32,
    // Zone start PFN
    zone_start_pfn: u64,
    // Compaction
    compact_cached_free_pfn: u64,
    compact_cached_migrate_pfn: u64,
    compact_order_failed: u8,
    compact_considered: u64,
    compact_defer_shift: u8,
    // NUMA node
    node_id: u8,
    // CMA
    cma_alloc: u64,

    pub fn free_pages(self: *const Zone) u64 {
        var total: u64 = 0;
        for (0..MAX_ORDER) |order| {
            total += self.free_area[order].nr_free << @as(u6, @truncate(order));
        }
        return total;
    }

    pub fn is_low_on_memory(self: *const Zone) bool {
        return self.free_pages() < self.watermark_low;
    }

    pub fn alloc_pages(self: *Zone, order: u8, migrate_type: MigrateType) ?*PageFrame {
        // Try to find a free block at the requested order
        var current_order: u8 = order;
        while (current_order < MAX_ORDER) : (current_order += 1) {
            const area = &self.free_area[current_order];
            const page = area.free_list[@intFromEnum(migrate_type)].pop();
            if (page) |p| {
                area.nr_free -= 1;
                // Split if we got a larger block
                if (current_order > order) {
                    self.split_page(p, order, current_order, migrate_type);
                }
                set_page_flag(&p.flags, PG_reserved); // Mark allocated
                p.ref_count = 1;
                return p;
            }
        }
        return null;
    }

    fn split_page(self: *Zone, page: *PageFrame, target_order: u8, current_order: u8, migrate_type: MigrateType) void {
        var order = current_order;
        while (order > target_order) {
            order -= 1;
            // The buddy goes to the free list
            const buddy_pfn = page.pfn + (@as(u64, 1) << @as(u6, order));
            _ = buddy_pfn;
            // In real impl: get buddy page frame and add to free list
            self.free_area[order].nr_free += 1;
            _ = migrate_type;
        }
    }

    pub fn free_pages_order(self: *Zone, page: *PageFrame, order: u8) void {
        clear_page_flag(&page.flags, PG_reserved);
        page.ref_count = 0;

        // Try to coalesce with buddy
        var current_page = page;
        var current_order = order;
        while (current_order < MAX_ORDER - 1) {
            const buddy_pfn = current_page.pfn ^ (@as(u64, 1) << @as(u6, current_order));
            _ = buddy_pfn;
            // In real impl: find buddy, check if free, remove from free list, coalesce
            break; // Simplified
        }

        // Add to free list
        self.free_area[current_order].free_list[@intFromEnum(current_page.migrate_type)].add(current_page);
        self.free_area[current_order].nr_free += 1;
    }
};

pub const PerCpuPages = struct {
    count: u32,
    high: u32,
    batch: u32,
    lists: [3]PageList, // UNMOVABLE, MOVABLE, RECLAIMABLE

    pub fn alloc(self: *PerCpuPages, migrate_type: MigrateType) ?*PageFrame {
        if (self.count == 0) return null;
        const mt = @min(@intFromEnum(migrate_type), 2);
        const page = self.lists[mt].pop();
        if (page != null) self.count -= 1;
        return page;
    }

    pub fn free(self: *PerCpuPages, page: *PageFrame) void {
        const mt = @min(@intFromEnum(page.migrate_type), 2);
        self.lists[mt].add(page);
        self.count += 1;
    }
};

// ============================================================================
// NUMA Node
// ============================================================================

pub const LruList = enum(u8) {
    LRU_INACTIVE_ANON = 0,
    LRU_ACTIVE_ANON = 1,
    LRU_INACTIVE_FILE = 2,
    LRU_ACTIVE_FILE = 3,
    LRU_UNEVICTABLE = 4,
    NR_LRU_LISTS = 5,
};

pub const NumaNode = struct {
    node_id: u8,
    zones: [MAX_ZONES]Zone,
    nr_zones: u8,
    // LRU lists for page reclaim
    lru_lists: [5]PageList, // One per LRU type
    lru_lock: u32,
    // Stats
    total_pages: u64,
    free_pages_total: u64,
    // NUMA distance to other nodes
    distance: [MAX_NUMNODES]u8,
    // Memory policy
    mem_policy_default: MemPolicy,
    // Page reclaim
    kswapd_order: u8,
    kswapd_highest_zoneidx: u8,
    kswapd_failures: u32,
    // Proactive reclaim
    reclaim_target: u64,
    reclaim_progress: u64,

    pub fn total_free_pages(self: *const NumaNode) u64 {
        var total: u64 = 0;
        for (0..self.nr_zones) |i| {
            total += self.zones[i].free_pages();
        }
        return total;
    }
};

pub const MemPolicy = enum(u8) {
    DEFAULT = 0,
    PREFERRED = 1,
    BIND = 2,
    INTERLEAVE = 3,
    LOCAL = 4,
    PREFERRED_MANY = 5,
    WEIGHTED_INTERLEAVE = 6,
};

// ============================================================================
// CMA (Contiguous Memory Allocator)
// ============================================================================

pub const CMA_MAX_AREAS: usize = 32;
pub const CMA_MAX_NAME: usize = 64;

pub const CmaArea = struct {
    name: [CMA_MAX_NAME]u8,
    name_len: u8,
    base_pfn: u64,
    count: u64,      // Number of pages
    // Bitmap: 1 = allocated, 0 = free
    bitmap: [8192]u64, // Supports up to 512K pages (2GB)
    order_per_bit: u8,
    // Statistics
    alloc_count: u64,
    alloc_fail_count: u64,
    release_count: u64,
    // Lock
    lock: u32,

    pub fn alloc_pages(self: *CmaArea, count: u64, alignment: u64) ?u64 {
        const aligned_count = (count + (alignment - 1)) & ~(alignment - 1);
        const bitmap_count = aligned_count >> @as(u6, self.order_per_bit);

        // Find contiguous free region in bitmap
        var start: u64 = 0;
        var found: u64 = 0;

        var i: u64 = 0;
        while (i < self.count >> @as(u6, self.order_per_bit)) : (i += 1) {
            const word_idx = i / 64;
            const bit_idx: u6 = @truncate(i % 64);
            if (word_idx >= self.bitmap.len) break;

            if ((self.bitmap[word_idx] & (@as(u64, 1) << bit_idx)) == 0) {
                if (found == 0) start = i;
                found += 1;
                if (found >= bitmap_count) {
                    // Mark allocated
                    self.mark_bitmap(start, bitmap_count, true);
                    self.alloc_count += 1;
                    return self.base_pfn + (start << @as(u6, self.order_per_bit));
                }
            } else {
                found = 0;
            }
        }

        self.alloc_fail_count += 1;
        return null;
    }

    pub fn release_pages(self: *CmaArea, pfn: u64, count: u64) void {
        const start = (pfn - self.base_pfn) >> @as(u6, self.order_per_bit);
        const bitmap_count = count >> @as(u6, self.order_per_bit);
        self.mark_bitmap(start, bitmap_count, false);
        self.release_count += 1;
    }

    fn mark_bitmap(self: *CmaArea, start: u64, count: u64, set: bool) void {
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const idx = start + i;
            const word_idx = idx / 64;
            const bit_idx: u6 = @truncate(idx % 64);
            if (word_idx >= self.bitmap.len) break;

            if (set) {
                self.bitmap[word_idx] |= @as(u64, 1) << bit_idx;
            } else {
                self.bitmap[word_idx] &= ~(@as(u64, 1) << bit_idx);
            }
        }
    }
};

// ============================================================================
// Huge Pages (HugeTLB)
// ============================================================================

pub const HugePageSize = enum(u8) {
    SIZE_2MB = 0,    // x86 PMD
    SIZE_1GB = 1,    // x86 PUD
    SIZE_16KB = 2,   // ARM 16KB
    SIZE_64KB = 3,   // ARM 64KB
    SIZE_32MB = 4,   // ARM CONT-PMD
    SIZE_512MB = 5,  // ARM CONT-PUD
    SIZE_16GB = 6,   // PPC
};

pub fn huge_page_size_bytes(size: HugePageSize) u64 {
    return switch (size) {
        .SIZE_2MB => 2 * 1024 * 1024,
        .SIZE_1GB => 1024 * 1024 * 1024,
        .SIZE_16KB => 16 * 1024,
        .SIZE_64KB => 64 * 1024,
        .SIZE_32MB => 32 * 1024 * 1024,
        .SIZE_512MB => 512 * 1024 * 1024,
        .SIZE_16GB => 16 * @as(u64, 1024) * 1024 * 1024,
    };
}

pub const HugePagePool = struct {
    size: HugePageSize,
    nr_huge_pages: u64,        // Total huge pages
    free_huge_pages: u64,      // Currently free
    resv_huge_pages: u64,      // Reserved (committed but not allocated)
    surplus_huge_pages: u64,   // Overcommit surplus
    max_huge_pages: u64,
    // Per-NUMA pools
    per_node_free: [MAX_NUMNODES]u64,
    per_node_surplus: [MAX_NUMNODES]u64,
    // Free list
    free_list: PageList,
    // Lock
    lock: u32,

    pub fn alloc_page(self: *HugePagePool, node: ?u8) ?*PageFrame {
        if (self.free_huge_pages == 0) {
            // Try surplus
            if (self.surplus_huge_pages >= self.max_huge_pages) return null;
            // In real impl: allocate from buddy
            return null;
        }
        const page = self.free_list.pop() orelse return null;
        self.free_huge_pages -= 1;
        if (node) |n| {
            if (n < MAX_NUMNODES) {
                self.per_node_free[n] -|= 1;
            }
        }
        return page;
    }

    pub fn free_page(self: *HugePagePool, page: *PageFrame, node: u8) void {
        self.free_list.add(page);
        self.free_huge_pages += 1;
        if (node < MAX_NUMNODES) {
            self.per_node_free[node] += 1;
        }
    }
};

// ============================================================================
// OOM Killer
// ============================================================================

pub const OomPriority = enum(u8) {
    DEFAULT = 0,         // Normal
    OOM_SCORE_ADJ_MIN = 1, // -1000 (never kill)
    OOM_SCORE_ADJ_MAX = 2, // +1000 (kill first)
};

pub const OomVictimInfo = struct {
    pid: u32,
    tgid: u32,
    uid: u32,
    score: i32,           // Computed OOM score (0-2000)
    oom_score_adj: i16,   // User-set adjustment (-1000 to +1000)
    total_vm: u64,        // Total virtual memory (pages)
    rss: u64,             // Resident Set Size (pages)
    swap: u64,            // Swap usage (pages)
    pgtables: u64,        // Page table pages
    comm: [16]u8,         // Process name
};

pub const OomControl = struct {
    enabled: bool,
    panic_on_oom: bool,
    // Memory cgroup OOM
    memcg_oom: bool,
    memcg_oom_group_kill: bool,
    // Recent kills
    last_victim_pid: u32,
    last_kill_time: u64,
    kill_count: u64,
    // Thresholds
    oom_min_free_kbytes: u64,

    pub fn compute_oom_score(info: *OomVictimInfo) i32 {
        // OOM scoring algorithm:
        // Base score proportional to RSS + swap + page tables
        if (info.oom_score_adj == -1000) return 0; // Never kill

        const total_memory = info.rss + info.swap + info.pgtables;
        var score: i64 = @intCast(total_memory);

        // Normalize to 0-1000 range (in real impl, relative to total system RAM)
        score = @min(score, 1000);

        // Apply user adjustment
        score += info.oom_score_adj;
        score = @max(0, @min(score, 2000));

        info.score = @intCast(score);
        return @intCast(score);
    }

    pub fn select_victim(self: *OomControl, processes: []OomVictimInfo) ?*OomVictimInfo {
        _ = self;
        var best: ?*OomVictimInfo = null;
        var best_score: i32 = -1;

        for (processes) |*proc| {
            const score = compute_oom_score(proc);
            if (score > best_score) {
                best_score = score;
                best = proc;
            }
        }

        return best;
    }
};

// ============================================================================
// Memory Hotplug
// ============================================================================

pub const MEMORY_BLOCK_SIZE: u64 = 128 * 1024 * 1024; // 128MB per block (Linux default)

pub const MemoryBlockState = enum(u8) {
    OFFLINE = 0,
    GOING_OFFLINE = 1,
    ONLINE = 2,
    GOING_ONLINE = 3,
};

pub const MemoryBlock = struct {
    id: u32,
    state: MemoryBlockState,
    start_section_nr: u32,
    phys_device: u32,
    nid: u8,                // NUMA node
    zone_type: ZoneType,
    removable: bool,
    // Statistics
    online_type: OnlineType,
    nr_vmemmap_pages: u64,

    pub fn online(self: *MemoryBlock, online_type: OnlineType) bool {
        if (self.state != .OFFLINE) return false;
        self.state = .GOING_ONLINE;
        self.online_type = online_type;
        // In real impl: add pages to zones, init struct pages
        self.state = .ONLINE;
        return true;
    }

    pub fn offline(self: *MemoryBlock) bool {
        if (self.state != .ONLINE) return false;
        self.state = .GOING_OFFLINE;
        // In real impl: isolate pages, migrate data, remove from zones
        self.state = .OFFLINE;
        return true;
    }
};

pub const OnlineType = enum(u8) {
    ONLINE_MOVABLE = 0,
    ONLINE_KERNEL = 1,
    ONLINE_KEEP = 2,
};

pub const MemoryHotplugState = struct {
    blocks: [4096]?MemoryBlock, // Support up to 512GB memory (4096 * 128MB)
    block_count: u32,
    auto_online: bool,
    auto_online_type: OnlineType,

    pub fn add_memory(self: *MemoryHotplugState, start_addr: u64, size: u64, nid: u8) bool {
        const nr_blocks: u32 = @intCast(size / MEMORY_BLOCK_SIZE);
        var added: u32 = 0;
        var i: u32 = 0;
        while (i < nr_blocks) : (i += 1) {
            if (self.block_count >= 4096) break;
            self.blocks[self.block_count] = MemoryBlock{
                .id = self.block_count,
                .state = .OFFLINE,
                .start_section_nr = @intCast((start_addr + @as(u64, i) * MEMORY_BLOCK_SIZE) / MEMORY_BLOCK_SIZE),
                .phys_device = 0,
                .nid = nid,
                .zone_type = .ZONE_NORMAL,
                .removable = true,
                .online_type = .ONLINE_KERNEL,
                .nr_vmemmap_pages = 0,
            };
            if (self.auto_online) {
                if (self.blocks[self.block_count]) |*block| {
                    _ = block.online(self.auto_online_type);
                }
            }
            self.block_count += 1;
            added += 1;
        }
        return added > 0;
    }
};

// ============================================================================
// Page Compaction
// ============================================================================

pub const CompactResult = enum(u8) {
    NOT_SUITABLE_ZONE = 0,
    SKIPPED = 1,
    DEFERRED = 2,
    NO_SUITABLE_PAGE = 3,
    CONTINUE = 4,
    PARTIAL_SKIPPED = 5,
    COMPLETE = 6,
    SUCCESS = 7,
};

pub const CompactionMode = enum(u8) {
    ASYNC = 0,
    SYNC_LIGHT = 1,
    SYNC_FULL = 2,
};

pub const CompactionStats = struct {
    nr_migrated: u64,
    nr_failed: u64,
    nr_scanned: u64,
    nr_free_scanned: u64,
    compact_stalls: u64,
    compact_success: u64,
    compact_fail: u64,
};

pub const CompactionControl = struct {
    zone: *Zone,
    order: u8,
    mode: CompactionMode,
    migrate_pfn: u64,
    free_pfn: u64,
    nr_migratepages: u64,
    nr_freepages: u64,
    whole_zone: bool,
    contended: bool,
    finish_pageblock: bool,
    stats: CompactionStats,

    pub fn run(self: *CompactionControl) CompactResult {
        // Phase 1: Scan for movable pages from the beginning of the zone
        const migrate_result = self.scan_movable_pages();
        if (migrate_result == .NO_SUITABLE_PAGE) return .NO_SUITABLE_PAGE;

        // Phase 2: Scan for free pages from the end of the zone
        const free_result = self.scan_free_pages();
        if (free_result == .NO_SUITABLE_PAGE) return .NO_SUITABLE_PAGE;

        // Phase 3: Migrate pages
        if (self.nr_migratepages > 0 and self.nr_freepages > 0) {
            // In real impl: call migrate_pages()
            self.stats.nr_migrated += self.nr_migratepages;
            self.stats.compact_success += 1;
            return .SUCCESS;
        }

        return .CONTINUE;
    }

    fn scan_movable_pages(self: *CompactionControl) CompactResult {
        // Scan forward from migrate_pfn
        var pfn = self.migrate_pfn;
        const end = self.zone.zone_start_pfn + self.zone.spanned_pages;
        while (pfn < end) : (pfn += 1) {
            // Check if page is movable
            self.stats.nr_scanned += 1;
            // Simplified: count movable pages
            self.nr_migratepages += 1;
            if (self.nr_migratepages >= 32) break; // Batch size
        }
        self.migrate_pfn = pfn;
        return if (self.nr_migratepages > 0) .CONTINUE else .NO_SUITABLE_PAGE;
    }

    fn scan_free_pages(self: *CompactionControl) CompactResult {
        // Scan backward from free_pfn
        var pfn = self.free_pfn;
        const start = self.zone.zone_start_pfn;
        while (pfn > start) {
            pfn -= 1;
            self.stats.nr_free_scanned += 1;
            self.nr_freepages += 1;
            if (self.nr_freepages >= 32) break;
        }
        self.free_pfn = pfn;
        return if (self.nr_freepages > 0) .CONTINUE else .NO_SUITABLE_PAGE;
    }
};

// ============================================================================
// KSM (Kernel Same-page Merging)
// ============================================================================

pub const KsmConfig = struct {
    enabled: bool,
    pages_to_scan: u32,        // Pages to scan per sleep cycle
    sleep_ms: u32,             // Sleep between scans
    merge_across_nodes: bool,
    use_zero_pages: bool,
    max_page_sharing: u32,     // Max sharing per KSM page
    // Statistics
    pages_shared: u64,
    pages_sharing: u64,
    pages_unshared: u64,
    pages_volatile: u64,
    full_scans: u64,
    stable_node_chains: u64,
    stable_node_dups: u64,
};

// ============================================================================
// DAMON (Data Access MONitor) - Linux 5.15+
// ============================================================================

pub const DamonConfig = struct {
    sample_interval_us: u64,    // Sampling interval
    aggr_interval_us: u64,     // Aggregation interval
    update_interval_us: u64,   // Regions update interval
    min_nr_regions: u32,
    max_nr_regions: u32,
};

pub const DamonRegion = struct {
    start: u64,
    end: u64,
    nr_accesses: u32,  // Access frequency during last aggregation
    age: u64,          // Aggregation intervals since creation
};

pub const DamonTarget = struct {
    pid: u32,
    regions: [1024]?DamonRegion,
    region_count: u32,
};

pub const DamonSchemeAction = enum(u8) {
    WILLNEED = 0,    // madvise MADV_WILLNEED
    COLD = 1,        // madvise MADV_COLD
    PAGEOUT = 2,     // madvise MADV_PAGEOUT
    HUGEPAGE = 3,    // madvise MADV_HUGEPAGE
    NOHUGEPAGE = 4,  // madvise MADV_NOHUGEPAGE
    LRU_PRIO = 5,    // Prioritize in LRU
    LRU_DEPRIO = 6,  // Deprioritize in LRU
    STAT = 7,        // Just collect statistics
    MIGRATE_HOT = 8, // Migrate to fast NUMA node (Zxyphor)
    MIGRATE_COLD = 9, // Migrate to slow NUMA node (Zxyphor)
};

pub const DamonScheme = struct {
    // Access pattern to match
    min_sz_region: u64,
    max_sz_region: u64,
    min_nr_accesses: u32,
    max_nr_accesses: u32,
    min_age_region: u64,
    max_age_region: u64,
    // Action
    action: DamonSchemeAction,
    // Quotas
    quota_ms: u64,
    quota_bytes: u64,
    // Stats
    stat_nr_tried: u64,
    stat_sz_tried: u64,
    stat_nr_applied: u64,
    stat_sz_applied: u64,
    stat_qt_exceeds: u64,
};

// ============================================================================
// Memory Policy (NUMA policies)
// ============================================================================

pub const MPOL_F_STATIC_NODES: u32 = 1 << 15;
pub const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
pub const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;

pub const NumaBalancingConfig = struct {
    enabled: bool,
    scan_delay_ms: u32,
    scan_period_min_ms: u32,
    scan_period_max_ms: u32,
    scan_size_mb: u32,
    // Statistics
    pages_migrated: u64,
    hint_faults: u64,
    hint_faults_local: u64,
};

// ============================================================================
// vmstat Counters
// ============================================================================

pub const VmStatItem = enum(u8) {
    NR_FREE_PAGES = 0,
    NR_ZONE_INACTIVE_ANON = 1,
    NR_ZONE_ACTIVE_ANON = 2,
    NR_ZONE_INACTIVE_FILE = 3,
    NR_ZONE_ACTIVE_FILE = 4,
    NR_ZONE_UNEVICTABLE = 5,
    NR_ZONE_WRITE_PENDING = 6,
    NR_MLOCK = 7,
    NR_BOUNCE = 8,
    NR_ZSPAGES = 9,
    NR_FREE_CMA = 10,
    NR_ANON_MAPPED = 11,
    NR_FILE_MAPPED = 12,
    NR_FILE_PAGES = 13,
    NR_FILE_DIRTY = 14,
    NR_WRITEBACK = 15,
    NR_WRITEBACK_TEMP = 16,
    NR_SHMEM = 17,
    NR_SHMEM_HUGEPAGES = 18,
    NR_SHMEM_PMDMAPPED = 19,
    NR_ANON_THPS = 20,
    NR_VMSCAN_WRITE = 21,
    NR_VMSCAN_IMMEDIATE = 22,
    NR_DIRTIED = 23,
    NR_WRITTEN = 24,
    NR_THROTTLED_WRITTEN = 25,
    NR_KERNEL_MISC_RECLAIMABLE = 26,
    NR_FOLL_PIN_ACQUIRED = 27,
    NR_FOLL_PIN_RELEASED = 28,
    NR_KERNEL_STACK = 29,
    NR_PAGETABLE = 30,
    NR_SECONDARY_PAGETABLE = 31,
    NR_SWAPCACHE = 32,
    PGPGIN = 33,
    PGPGOUT = 34,
    PSWPIN = 35,
    PSWPOUT = 36,
    PGALLOC_DMA = 37,
    PGALLOC_DMA32 = 38,
    PGALLOC_NORMAL = 39,
    PGALLOC_MOVABLE = 40,
    PGFREE = 41,
    PGACTIVATE = 42,
    PGDEACTIVATE = 43,
    PGLAZYFREE = 44,
    PGLAZYFREED = 45,
    PGFAULT = 46,
    PGMAJFAULT = 47,
    PGSTEAL_ANON = 48,
    PGSTEAL_FILE = 49,
    PGSCAN_ANON = 50,
    PGSCAN_FILE = 51,
    COMPACT_MIGRATE_SCANNED = 52,
    COMPACT_FREE_SCANNED = 53,
    COMPACT_ISOLATED = 54,
    COMPACT_STALL = 55,
    COMPACT_FAIL = 56,
    COMPACT_SUCCESS = 57,
    HTLB_BUDDY_ALLOC_SUCCESS = 58,
    HTLB_BUDDY_ALLOC_FAIL = 59,
    CMA_ALLOC_SUCCESS = 60,
    CMA_ALLOC_FAIL = 61,
    UNEVICTABLE_PGCULLED = 62,
    UNEVICTABLE_PGSCANNED = 63,
    NR_STAT_ITEMS = 64,
};
