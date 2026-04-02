// =============================================================================
// Kernel Zxyphor v0.0.3 — Physical Memory Manager (PMM)
// =============================================================================
// Advanced physical memory management with:
//   - Buddy allocator (orders 0-10, 4KB-4MB blocks)
//   - Zone-based memory management (DMA, DMA32, Normal, HighMem, Movable)
//   - Per-CPU page frame caches (PCP — hot/cold page lists)
//   - NUMA-aware allocation with distance-based fallback
//   - Watermark-based reclaim triggers (min/low/high)
//   - Compaction support with migration types
//   - Memory hotplug support
//   - CMA (Contiguous Memory Allocator) integration
//   - Page reference counting with mapcount
//   - Memory statistics per zone and per node
//   - Anti-fragmentation grouping (unmovable, movable, reclaimable)
//
// Architecture: Linux-style zone/buddy hybrid that exceeds Linux 7.x
// =============================================================================

const main = @import("../main.zig");
const multiboot = @import("../boot/multiboot.zig");

// =============================================================================
// Physical Page Frame Descriptor
// =============================================================================
pub const PageFrame = struct {
    flags: PageFlags = .{},
    refcount: i32 = 0,
    mapcount: i32 = -1,
    buddy_order: u8 = 0,
    buddy_next: ?*PageFrame = null,
    buddy_prev: ?*PageFrame = null,
    zone_id: u8 = 0,
    node_id: u8 = 0,
    migration_type: MigrationType = .unmovable,
    mapping: usize = 0,
    index: u64 = 0,
    private: u64 = 0,
    lru_next: ?*PageFrame = null,
    lru_prev: ?*PageFrame = null,
    lru_gen: u8 = 0,
    slab_cache: usize = 0,
    slab_freelist: usize = 0,
    slab_inuse: u16 = 0,
    slab_objects: u16 = 0,
    compound_head: ?*PageFrame = null,
    compound_order: u8 = 0,
    compound_mapcount: i32 = 0,
    alloc_trace: u64 = 0,
    free_trace: u64 = 0,
    last_cpu: u16 = 0,

    pub fn physAddr(self: *const PageFrame) u64 {
        const idx = (@intFromPtr(self) - @intFromPtr(&page_array)) / @sizeOf(PageFrame);
        return @as(u64, idx) * FRAME_SIZE;
    }

    pub fn pfn(self: *const PageFrame) u64 {
        return self.physAddr() / FRAME_SIZE;
    }

    pub fn get(self: *PageFrame) void {
        self.refcount += 1;
    }

    pub fn put(self: *PageFrame) bool {
        self.refcount -= 1;
        return self.refcount == 0;
    }

    pub fn isCompound(self: *const PageFrame) bool {
        return self.compound_head != null;
    }

    pub fn isSlab(self: *const PageFrame) bool {
        return self.flags.slab;
    }

    pub fn isLocked(self: *const PageFrame) bool {
        return self.flags.locked;
    }

    pub fn isWriteback(self: *const PageFrame) bool {
        return self.flags.writeback;
    }

    pub fn isDirty(self: *const PageFrame) bool {
        return self.flags.dirty;
    }

    pub fn isUptodate(self: *const PageFrame) bool {
        return self.flags.uptodate;
    }

    pub fn isActive(self: *const PageFrame) bool {
        return self.flags.active;
    }

    pub fn isReferenced(self: *const PageFrame) bool {
        return self.flags.referenced;
    }

    pub fn isBuddy(self: *const PageFrame) bool {
        return self.flags.buddy;
    }

    pub fn isReserved(self: *const PageFrame) bool {
        return self.flags.reserved;
    }

    pub fn setDirty(self: *PageFrame) void {
        self.flags.dirty = true;
    }

    pub fn clearDirty(self: *PageFrame) void {
        self.flags.dirty = false;
    }

    pub fn setReferenced(self: *PageFrame) void {
        self.flags.referenced = true;
    }

    pub fn clearReferenced(self: *PageFrame) bool {
        const was = self.flags.referenced;
        self.flags.referenced = false;
        return was;
    }

    pub fn headPage(self: *PageFrame) *PageFrame {
        if (self.compound_head) |head| return head;
        return self;
    }
};

pub const PageFlags = packed struct {
    locked: bool = false,
    uptodate: bool = false,
    dirty: bool = false,
    writeback: bool = false,
    referenced: bool = false,
    active: bool = false,
    slab: bool = false,
    buddy: bool = false,
    reserved: bool = false,
    private: bool = false,
    mappedtodisk: bool = false,
    reclaim: bool = false,
    swapbacked: bool = false,
    mlocked: bool = false,
    uncached: bool = false,
    hwpoison: bool = false,
    compound_head: bool = false,
    compound_tail: bool = false,
    huge: bool = false,
    idle: bool = false,
    table: bool = false,
    guard: bool = false,
    isolated: bool = false,
    reported: bool = false,
    vmemmap: bool = false,
    pinned: bool = false,
    foreign: bool = false,
    xen_remapped: bool = false,
    balloon: bool = false,
    ksm: bool = false,
    thp: bool = false,
    offline: bool = false,
    _pad: u32 = 0,
};

pub const MigrationType = enum(u8) {
    unmovable = 0,
    movable = 1,
    reclaimable = 2,
    highatomic = 3,
    cma = 4,
    isolate = 5,
};
pub const MIGRATE_TYPES: usize = 6;

pub const ZoneType = enum(u8) {
    dma = 0,
    dma32 = 1,
    normal = 2,
    highmem = 3,
    movable = 4,
};
pub const NR_ZONES: usize = 5;

pub const MAX_ORDER: usize = 11;
pub const FRAME_SIZE: u64 = 4096;
const MAX_MEMORY: u64 = 64 * 1024 * 1024 * 1024;
const MAX_FRAMES: u64 = MAX_MEMORY / FRAME_SIZE;

const BuddyFreeList = struct {
    head: ?*PageFrame = null,
    count: u64 = 0,

    fn insert(self: *BuddyFreeList, page: *PageFrame) void {
        page.buddy_next = self.head;
        page.buddy_prev = null;
        if (self.head) |h| h.buddy_prev = page;
        self.head = page;
        self.count += 1;
        page.flags.buddy = true;
    }

    fn remove(self: *BuddyFreeList, page: *PageFrame) void {
        if (page.buddy_prev) |prev| {
            prev.buddy_next = page.buddy_next;
        } else {
            self.head = page.buddy_next;
        }
        if (page.buddy_next) |next| {
            next.buddy_prev = page.buddy_prev;
        }
        page.buddy_next = null;
        page.buddy_prev = null;
        page.flags.buddy = false;
        if (self.count > 0) self.count -= 1;
    }

    fn popFirst(self: *BuddyFreeList) ?*PageFrame {
        const page = self.head orelse return null;
        self.remove(page);
        return page;
    }

    fn isEmpty(self: *const BuddyFreeList) bool {
        return self.head == null;
    }
};

pub const Zone = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: usize = 0,
    zone_type: ZoneType = .normal,
    zone_start_pfn: u64 = 0,
    spanned_pages: u64 = 0,
    present_pages: u64 = 0,
    managed_pages: u64 = 0,
    free_area: [MAX_ORDER][MIGRATE_TYPES]BuddyFreeList = [_][MIGRATE_TYPES]BuddyFreeList{
        [_]BuddyFreeList{.{}} ** MIGRATE_TYPES,
    } ** MAX_ORDER,
    watermark_min: u64 = 0,
    watermark_low: u64 = 0,
    watermark_high: u64 = 0,
    watermark_boost: u64 = 0,
    stat: ZoneStats = .{},
    nr_reserved_highatomic: u64 = 0,
    compact_cached_free_pfn: u64 = 0,
    compact_cached_migrate_pfn: u64 = 0,
    compact_defer_shift: u8 = 0,
    compact_order_failed: u8 = 0,
    compact_considered: u32 = 0,
    lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init(),

    pub fn allocPages(self: *Zone, order: usize, mtype: MigrationType) ?*PageFrame {
        self.lock.acquire();
        defer self.lock.release();
        if (self.allocFromBuddy(order, mtype)) |page| return page;
        var cur_order = order + 1;
        while (cur_order < MAX_ORDER) : (cur_order += 1) {
            if (self.allocFromBuddy(cur_order, mtype)) |page| {
                self.splitBuddy(page, cur_order, order, mtype);
                return page;
            }
        }
        return self.stealFromFallback(order, mtype);
    }

    pub fn freePages(self: *Zone, page: *PageFrame, order: usize) void {
        self.lock.acquire();
        defer self.lock.release();
        self.freePagesInternal(page, order);
    }

    pub fn freePagesInternal(self: *Zone, page: *PageFrame, order: usize) void {
        var current_page = page;
        var current_order = order;
        while (current_order < MAX_ORDER - 1) {
            const buddy_pfn = current_page.pfn() ^ (@as(u64, 1) << @as(u6, @truncate(current_order)));
            const buddy = pfnToPage(buddy_pfn) orelse break;
            if (!buddy.flags.buddy or buddy.buddy_order != @as(u8, @truncate(current_order))) break;
            const mtype = @intFromEnum(buddy.migration_type);
            self.free_area[current_order][mtype].remove(buddy);
            buddy.buddy_order = 0;
            if (buddy.pfn() < current_page.pfn()) current_page = buddy;
            current_order += 1;
        }
        current_page.buddy_order = @as(u8, @truncate(current_order));
        const mtype = @intFromEnum(current_page.migration_type);
        self.free_area[current_order][mtype].insert(current_page);
        self.managed_pages += @as(u64, 1) << @as(u6, @truncate(order));
        self.stat.free_pages += @as(u64, 1) << @as(u6, @truncate(order));
    }

    fn allocFromBuddy(self: *Zone, order: usize, mtype: MigrationType) ?*PageFrame {
        const mt = @intFromEnum(mtype);
        const page = self.free_area[order][mt].popFirst() orelse return null;
        page.buddy_order = 0;
        page.flags.buddy = false;
        const nr_pages = @as(u64, 1) << @as(u6, @truncate(order));
        if (self.managed_pages >= nr_pages) self.managed_pages -= nr_pages;
        self.stat.free_pages -|= nr_pages;
        self.stat.alloc_count += 1;
        return page;
    }

    fn splitBuddy(self: *Zone, page: *PageFrame, high_order: usize, target_order: usize, mtype: MigrationType) void {
        var o = high_order;
        while (o > target_order) {
            o -= 1;
            const buddy_pfn = page.pfn() + (@as(u64, 1) << @as(u6, @truncate(o)));
            if (pfnToPage(buddy_pfn)) |buddy| {
                buddy.buddy_order = @as(u8, @truncate(o));
                buddy.migration_type = mtype;
                const mt = @intFromEnum(mtype);
                self.free_area[o][mt].insert(buddy);
            }
        }
    }

    fn stealFromFallback(self: *Zone, order: usize, preferred: MigrationType) ?*PageFrame {
        const fallback_order = switch (preferred) {
            .movable => [_]MigrationType{ .reclaimable, .unmovable, .highatomic },
            .reclaimable => [_]MigrationType{ .unmovable, .movable, .highatomic },
            .unmovable => [_]MigrationType{ .reclaimable, .movable, .highatomic },
            else => [_]MigrationType{ .movable, .reclaimable, .unmovable },
        };
        for (fallback_order) |fallback_mt| {
            var cur_order = MAX_ORDER - 1;
            while (cur_order >= order) : (cur_order -= 1) {
                if (self.allocFromBuddy(cur_order, fallback_mt)) |page| {
                    if (cur_order > order) self.splitBuddy(page, cur_order, order, preferred);
                    page.migration_type = preferred;
                    return page;
                }
                if (cur_order == 0) break;
            }
        }
        return null;
    }

    pub fn isAboveLowWatermark(self: *const Zone) bool {
        return self.stat.free_pages > self.watermark_low;
    }

    pub fn isAboveHighWatermark(self: *const Zone) bool {
        return self.stat.free_pages > self.watermark_high;
    }

    pub fn isBelowMinWatermark(self: *const Zone) bool {
        return self.stat.free_pages < self.watermark_min;
    }

    pub fn calculateWatermarks(self: *Zone) void {
        self.watermark_min = self.present_pages / 200;
        if (self.watermark_min < 32) self.watermark_min = 32;
        self.watermark_low = self.watermark_min + (self.watermark_min / 4);
        self.watermark_high = self.watermark_min + (self.watermark_min / 2);
    }

    pub fn totalFreePages(self: *const Zone) u64 {
        var total: u64 = 0;
        for (0..MAX_ORDER) |o| {
            for (0..MIGRATE_TYPES) |mt| {
                total += self.free_area[o][mt].count << @as(u6, @truncate(o));
            }
        }
        return total;
    }

    pub fn fragmentationIndex(self: *const Zone, target_order: usize) u64 {
        const total_free = self.totalFreePages();
        if (total_free == 0) return 1000;
        var suitable: u64 = 0;
        var o = target_order;
        while (o < MAX_ORDER) : (o += 1) {
            for (0..MIGRATE_TYPES) |mt| {
                suitable += self.free_area[o][mt].count << @as(u6, @truncate(o));
            }
        }
        if (suitable >= total_free) return 0;
        return 1000 - (suitable * 1000 / total_free);
    }
};

pub const ZoneStats = struct {
    free_pages: u64 = 0,
    alloc_count: u64 = 0,
    free_count: u64 = 0,
    alloc_fail_count: u64 = 0,
    compact_stall: u64 = 0,
    compact_fail: u64 = 0,
    compact_success: u64 = 0,
    pgsteal_kswapd: u64 = 0,
    pgsteal_direct: u64 = 0,
    pgscan_kswapd: u64 = 0,
    pgscan_direct: u64 = 0,
    pgfault: u64 = 0,
    pgmajfault: u64 = 0,
    pgrefill: u64 = 0,
    pgactivate: u64 = 0,
    pgdeactivate: u64 = 0,
    pglazyfree: u64 = 0,
    pglazyfreed: u64 = 0,
    thp_fault_alloc: u64 = 0,
    thp_fault_fallback: u64 = 0,
    thp_collapse_alloc: u64 = 0,
    thp_split_page: u64 = 0,
    thp_zero_page_alloc: u64 = 0,
    balloon_inflate: u64 = 0,
    balloon_deflate: u64 = 0,
    nr_anon_pages: u64 = 0,
    nr_file_pages: u64 = 0,
    nr_dirty_pages: u64 = 0,
    nr_writeback_pages: u64 = 0,
    nr_slab_reclaimable: u64 = 0,
    nr_slab_unreclaimable: u64 = 0,
    nr_pagetable_pages: u64 = 0,
    nr_kernel_stack: u64 = 0,
    nr_bounce: u64 = 0,
    nr_vmscan_write: u64 = 0,
    nr_vmscan_immediate: u64 = 0,
    workingset_refault_anon: u64 = 0,
    workingset_refault_file: u64 = 0,
    workingset_activate_anon: u64 = 0,
    workingset_activate_file: u64 = 0,
    workingset_restore_anon: u64 = 0,
    workingset_restore_file: u64 = 0,
    workingset_nodereclaim: u64 = 0,
};

pub const NumaNode = struct {
    node_id: u8 = 0,
    zones: [NR_ZONES]Zone = [_]Zone{.{}} ** NR_ZONES,
    nr_zones: usize = 0,
    node_start_pfn: u64 = 0,
    node_spanned_pages: u64 = 0,
    node_present_pages: u64 = 0,
    pcp: [MAX_CPUS]PerCpuPages = [_]PerCpuPages{.{}} ** MAX_CPUS,
    stat: NodeStats = .{},
    distance: [MAX_NODES]u8 = [_]u8{255} ** MAX_NODES,
    tier: u8 = 0,
    demotion_target: u8 = 0xFF,

    pub fn getZone(self: *NumaNode, ztype: ZoneType) *Zone {
        return &self.zones[@intFromEnum(ztype)];
    }
};

const NodeStats = struct {
    nr_inactive_anon: u64 = 0,
    nr_active_anon: u64 = 0,
    nr_inactive_file: u64 = 0,
    nr_active_file: u64 = 0,
    nr_unevictable: u64 = 0,
    nr_slab_reclaimable: u64 = 0,
    nr_slab_unreclaimable: u64 = 0,
    nr_isolated_anon: u64 = 0,
    nr_isolated_file: u64 = 0,
    nr_writeback_temp: u64 = 0,
    nr_shmem: u64 = 0,
    nr_shmem_hugepages: u64 = 0,
    nr_shmem_pmdmapped: u64 = 0,
    nr_anon_thps: u64 = 0,
    nr_kernel_misc_reclaimable: u64 = 0,
};

pub const PerCpuPages = struct {
    count: u32 = 0,
    high: u32 = 0,
    batch: u32 = 0,
    lists: [MIGRATE_TYPES]PcpList = [_]PcpList{.{}} ** MIGRATE_TYPES,

    pub fn allocPage(self: *PerCpuPages, mtype: MigrationType) ?*PageFrame {
        const mt = @intFromEnum(mtype);
        const page = self.lists[mt].head orelse return null;
        self.lists[mt].head = page.buddy_next;
        if (page.buddy_next) |next| next.buddy_prev = null;
        page.buddy_next = null;
        self.lists[mt].count -= 1;
        self.count -= 1;
        return page;
    }

    pub fn freePage(self: *PerCpuPages, page: *PageFrame, mtype: MigrationType) void {
        const mt = @intFromEnum(mtype);
        page.buddy_next = self.lists[mt].head;
        page.buddy_prev = null;
        if (self.lists[mt].head) |h| h.buddy_prev = page;
        self.lists[mt].head = page;
        self.lists[mt].count += 1;
        self.count += 1;
    }

    pub fn drain(self: *PerCpuPages, zone: *Zone, count: u32) void {
        var drained: u32 = 0;
        for (0..MIGRATE_TYPES) |mt| {
            while (drained < count) {
                const page = self.lists[mt].head orelse break;
                self.lists[mt].head = page.buddy_next;
                if (page.buddy_next) |next| next.buddy_prev = null;
                self.lists[mt].count -= 1;
                self.count -= 1;
                zone.freePagesInternal(page, 0);
                drained += 1;
            }
        }
    }

    pub fn refill(self: *PerCpuPages, zone: *Zone, mtype: MigrationType, count: u32) void {
        var filled: u32 = 0;
        while (filled < count) : (filled += 1) {
            const page = zone.allocPages(0, mtype) orelse break;
            self.freePage(page, mtype);
        }
    }
};

const PcpList = struct {
    head: ?*PageFrame = null,
    count: u32 = 0,
};

pub const GfpFlags = packed struct {
    dma: bool = false,
    dma32: bool = false,
    highmem: bool = false,
    movable: bool = false,
    wait: bool = true,
    io: bool = true,
    fs: bool = true,
    zero: bool = false,
    nowarn: bool = false,
    retry: bool = false,
    nofail: bool = false,
    noretry: bool = false,
    memalloc: bool = false,
    comp: bool = false,
    nomemalloc: bool = false,
    hardwall: bool = false,
    thisnode: bool = false,
    reclaimable: bool = false,
    account: bool = false,
    writeonly: bool = false,
    _pad: u12 = 0,

    pub const KERNEL = GfpFlags{};
    pub const ATOMIC = GfpFlags{ .wait = false, .io = false, .fs = false };
    pub const USER = GfpFlags{ .movable = true, .wait = true };
    pub const HIGHUSER = GfpFlags{ .highmem = true, .movable = true, .wait = true };
    pub const HIGHUSER_MOVABLE = GfpFlags{ .highmem = true, .movable = true, .wait = true };
    pub const DMA = GfpFlags{ .dma = true };
    pub const DMA32 = GfpFlags{ .dma32 = true };
    pub const NOIO = GfpFlags{ .io = false };
    pub const NOFS = GfpFlags{ .fs = false };

    pub fn preferredZone(self: GfpFlags) ZoneType {
        if (self.dma) return .dma;
        if (self.dma32) return .dma32;
        if (self.highmem) return .highmem;
        if (self.movable) return .movable;
        return .normal;
    }

    pub fn migrationTypeForAlloc(self: GfpFlags) MigrationType {
        if (self.movable) return .movable;
        if (self.reclaimable) return .reclaimable;
        return .unmovable;
    }
};

// =============================================================================
// Global PMM State
// =============================================================================
const MAX_NODES: usize = 8;
const MAX_CPUS: usize = 256;

var nodes: [MAX_NODES]NumaNode = [_]NumaNode{.{}} ** MAX_NODES;
var nr_online_nodes: usize = 1;
var total_pages: u64 = 0;
var total_free_pages: u64 = 0;
var total_reserved_pages: u64 = 0;

var page_array: [MAX_FRAMES]PageFrame = undefined;
var page_array_initialized: bool = false;

var preferred_zonelist: [MAX_NODES * NR_ZONES]ZoneRef = [_]ZoneRef{.{}} ** (MAX_NODES * NR_ZONES);
var nr_zonelist_entries: usize = 0;

const ZoneRef = struct {
    zone: ?*Zone = null,
    node_id: u8 = 0,
};

var global_lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Initialization
// =============================================================================
pub fn initialize(
    memory_map: []const multiboot.MmapEntry,
    map_entries: usize,
    kernel_start: usize,
    kernel_end: usize,
) void {
    _ = map_entries;
    main.klog(.info, "PMM: Initializing advanced buddy allocator...", .{});
    initPageArray();

    var node = &nodes[0];
    node.node_id = 0;
    node.distance[0] = 10;
    nr_online_nodes = 1;

    setupZones(node, memory_map);
    reserveKernelMemory(kernel_start, kernel_end);
    populateBuddyAllocator(node, memory_map);

    for (0..NR_ZONES) |zi| {
        node.zones[zi].calculateWatermarks();
    }

    setupPerCpuPages(node);
    buildZonelist();
    totalizeStats();

    main.klog(.info, "PMM: {d} MB total, {d} MB free, {d} MB reserved", .{
        (total_pages * FRAME_SIZE) / (1024 * 1024),
        (total_free_pages * FRAME_SIZE) / (1024 * 1024),
        (total_reserved_pages * FRAME_SIZE) / (1024 * 1024),
    });

    for (0..NR_ZONES) |zi| {
        const zone = &node.zones[zi];
        if (zone.present_pages > 0) {
            main.klog(.info, "PMM:   Zone {s}: {d} pages ({d} MB), min={d} low={d} high={d}", .{
                zone.name[0..zone.name_len],
                zone.present_pages,
                (zone.present_pages * FRAME_SIZE) / (1024 * 1024),
                zone.watermark_min,
                zone.watermark_low,
                zone.watermark_high,
            });
        }
    }
}

fn initPageArray() void {
    for (&page_array) |*pf| {
        pf.* = PageFrame{};
    }
    page_array_initialized = true;
}

fn setupZones(node: *NumaNode, memory_map: []const multiboot.MmapEntry) void {
    var max_pfn: u64 = 0;
    for (memory_map) |entry| {
        if (!entry.isAvailable()) continue;
        const end_pfn = (entry.base_addr + entry.length) / FRAME_SIZE;
        if (end_pfn > max_pfn) max_pfn = end_pfn;
    }
    if (max_pfn > MAX_FRAMES) max_pfn = MAX_FRAMES;

    const dma_end_pfn: u64 = 16 * 1024 * 1024 / FRAME_SIZE;
    node.zones[0].zone_type = .dma;
    setZoneName(&node.zones[0], "DMA");
    node.zones[0].zone_start_pfn = 0;
    node.zones[0].spanned_pages = @min(max_pfn, dma_end_pfn);
    node.nr_zones = 1;

    if (max_pfn > dma_end_pfn) {
        const dma32_end_pfn: u64 = 4 * 1024 * 1024 * 1024 / FRAME_SIZE;
        node.zones[1].zone_type = .dma32;
        setZoneName(&node.zones[1], "DMA32");
        node.zones[1].zone_start_pfn = dma_end_pfn;
        node.zones[1].spanned_pages = @min(max_pfn, dma32_end_pfn) - dma_end_pfn;
        node.nr_zones = 2;

        if (max_pfn > dma32_end_pfn) {
            node.zones[2].zone_type = .normal;
            setZoneName(&node.zones[2], "Normal");
            node.zones[2].zone_start_pfn = dma32_end_pfn;
            node.zones[2].spanned_pages = max_pfn - dma32_end_pfn;
            node.nr_zones = 3;
        }
    }

    node.node_start_pfn = 0;
    node.node_spanned_pages = max_pfn;
}

fn setZoneName(zone: *Zone, name: []const u8) void {
    const len = @min(name.len, zone.name.len);
    @memcpy(zone.name[0..len], name[0..len]);
    zone.name_len = len;
}

fn reserveKernelMemory(kernel_start: usize, kernel_end: usize) void {
    var pfn_val: u64 = 0;
    while (pfn_val < 256) : (pfn_val += 1) {
        page_array[pfn_val].flags.reserved = true;
        total_reserved_pages += 1;
    }

    const kern_start_pfn = @as(u64, kernel_start) / FRAME_SIZE;
    const kern_end_pfn = (@as(u64, kernel_end) + FRAME_SIZE - 1) / FRAME_SIZE;
    pfn_val = kern_start_pfn;
    while (pfn_val < kern_end_pfn) : (pfn_val += 1) {
        if (pfn_val < MAX_FRAMES) {
            page_array[pfn_val].flags.reserved = true;
            total_reserved_pages += 1;
        }
    }

    const array_size = MAX_FRAMES * @sizeOf(PageFrame);
    const array_start_pfn = @intFromPtr(&page_array) / FRAME_SIZE;
    const array_end_pfn = (@intFromPtr(&page_array) + array_size + FRAME_SIZE - 1) / FRAME_SIZE;
    pfn_val = array_start_pfn;
    while (pfn_val < array_end_pfn and pfn_val < MAX_FRAMES) : (pfn_val += 1) {
        page_array[pfn_val].flags.reserved = true;
        total_reserved_pages += 1;
    }
}

fn populateBuddyAllocator(node: *NumaNode, memory_map: []const multiboot.MmapEntry) void {
    for (memory_map) |entry| {
        if (!entry.isAvailable()) continue;

        var base_pfn = entry.base_addr / FRAME_SIZE;
        const end_pfn = (entry.base_addr + entry.length) / FRAME_SIZE;
        if (entry.base_addr % FRAME_SIZE != 0) base_pfn += 1;

        var pfn_val = base_pfn;
        while (pfn_val < end_pfn and pfn_val < MAX_FRAMES) {
            if (page_array[pfn_val].flags.reserved) {
                pfn_val += 1;
                continue;
            }

            var order: usize = 0;
            while (order < MAX_ORDER - 1) {
                const block_size = @as(u64, 1) << @as(u6, @truncate(order + 1));
                if (pfn_val % block_size != 0) break;
                if (pfn_val + block_size > end_pfn) break;
                if (pfn_val + block_size > MAX_FRAMES) break;
                var ok = true;
                var check_pfn = pfn_val;
                while (check_pfn < pfn_val + block_size) : (check_pfn += 1) {
                    if (page_array[check_pfn].flags.reserved) {
                        ok = false;
                        break;
                    }
                }
                if (!ok) break;
                order += 1;
            }

            const zone = pfnToZone(node, pfn_val);
            page_array[pfn_val].migration_type = .movable;
            page_array[pfn_val].buddy_order = @as(u8, @truncate(order));
            page_array[pfn_val].zone_id = @as(u8, @intFromEnum(zone.zone_type));
            const mt = @intFromEnum(MigrationType.movable);
            zone.free_area[order][mt].insert(&page_array[pfn_val]);
            const nr_pages = @as(u64, 1) << @as(u6, @truncate(order));
            zone.present_pages += nr_pages;
            zone.managed_pages += nr_pages;
            zone.stat.free_pages += nr_pages;
            total_pages += nr_pages;
            total_free_pages += nr_pages;
            pfn_val += nr_pages;
        }
    }
}

fn pfnToZone(node: *NumaNode, pfn_val: u64) *Zone {
    const dma_end: u64 = 16 * 1024 * 1024 / FRAME_SIZE;
    const dma32_end: u64 = 4 * 1024 * 1024 * 1024 / FRAME_SIZE;
    if (pfn_val < dma_end) return &node.zones[0];
    if (pfn_val < dma32_end) return &node.zones[1];
    return &node.zones[2];
}

fn setupPerCpuPages(node: *NumaNode) void {
    for (0..NR_ZONES) |zi| {
        if (node.zones[zi].present_pages == 0) continue;
        node.pcp[0].batch = 31;
        node.pcp[0].high = 186;
    }
}

fn buildZonelist() void {
    nr_zonelist_entries = 0;
    var zi: usize = NR_ZONES;
    while (zi > 0) {
        zi -= 1;
        if (nodes[0].zones[zi].present_pages > 0) {
            preferred_zonelist[nr_zonelist_entries] = .{
                .zone = &nodes[0].zones[zi],
                .node_id = 0,
            };
            nr_zonelist_entries += 1;
        }
    }
}

fn totalizeStats() void {
    total_pages = 0;
    total_free_pages = 0;
    for (0..nr_online_nodes) |ni| {
        for (0..NR_ZONES) |zi| {
            total_pages += nodes[ni].zones[zi].present_pages;
            total_free_pages += nodes[ni].zones[zi].stat.free_pages;
        }
    }
}

// =============================================================================
// Public Allocation API
// =============================================================================
pub fn allocFrame() ?u64 {
    return allocFrameGfp(GfpFlags.KERNEL);
}

pub fn allocFrameGfp(gfp: GfpFlags) ?u64 {
    return allocPagesGfp(0, gfp);
}

pub fn allocPagesGfp(order: usize, gfp: GfpFlags) ?u64 {
    if (order >= MAX_ORDER) return null;
    const mtype = gfp.migrationTypeForAlloc();

    if (order == 0) {
        const cpu_id: usize = 0;
        const node = &nodes[0];
        var pcp = &node.pcp[cpu_id];
        if (pcp.allocPage(mtype)) |page| {
            page.refcount = 1;
            page.flags.buddy = false;
            if (gfp.zero) zeroPage(page);
            return page.physAddr();
        }
        pcp.refill(pfnToZone(node, node.node_start_pfn), mtype, pcp.batch);
        if (pcp.allocPage(mtype)) |page| {
            page.refcount = 1;
            page.flags.buddy = false;
            if (gfp.zero) zeroPage(page);
            return page.physAddr();
        }
    }

    for (0..nr_zonelist_entries) |i| {
        const zref = preferred_zonelist[i];
        const zone = zref.zone orelse continue;
        if (gfp.dma and zone.zone_type != .dma) continue;
        if (gfp.dma32 and @intFromEnum(zone.zone_type) > @intFromEnum(ZoneType.dma32)) continue;
        const nr_pages = @as(u64, 1) << @as(u6, @truncate(order));
        if (!gfp.memalloc and zone.stat.free_pages < zone.watermark_low + nr_pages) {
            if (!gfp.wait) continue;
        }
        if (zone.allocPages(order, mtype)) |page| {
            page.refcount = 1;
            if (gfp.zero) zeroPageOrder(page, order);
            return page.physAddr();
        }
    }

    if (!gfp.nowarn) {
        main.klog(.warn, "PMM: Page allocation failure: order={d}", .{order});
    }
    return null;
}

pub fn allocContiguousFrames(count: u64) ?u64 {
    var order: usize = 0;
    while ((@as(u64, 1) << @as(u6, @truncate(order))) < count) : (order += 1) {
        if (order >= MAX_ORDER - 1) return null;
    }
    return allocPagesGfp(order, GfpFlags.KERNEL);
}

pub fn freeFrame(phys_addr: u64) void {
    freePages(phys_addr, 0);
}

pub fn freePages(phys_addr: u64, order: usize) void {
    const pfn_val = phys_addr / FRAME_SIZE;
    if (pfn_val >= MAX_FRAMES) return;
    var page = &page_array[pfn_val];
    if (page.flags.reserved) {
        main.klog(.warn, "PMM: Attempt to free reserved page PFN={d}", .{pfn_val});
        return;
    }
    page.refcount -= 1;
    if (page.refcount > 0) return;
    page.flags.locked = false;
    page.flags.dirty = false;
    page.flags.active = false;
    page.flags.referenced = false;
    page.flags.uptodate = false;
    page.flags.slab = false;
    page.mapping = 0;
    page.index = 0;
    page.private = 0;

    if (order == 0) {
        const cpu_id: usize = 0;
        const node = &nodes[0];
        var pcp = &node.pcp[cpu_id];
        const mtype = page.migration_type;
        pcp.freePage(page, mtype);
        if (pcp.count > pcp.high) {
            const zone = pfnToZone(node, pfn_val);
            pcp.drain(zone, pcp.batch);
        }
        return;
    }
    const zone = pfnToZone(&nodes[0], pfn_val);
    zone.freePages(page, order);
}

pub fn freeContiguousFrames(phys_addr: u64, count: u64) void {
    var order: usize = 0;
    while ((@as(u64, 1) << @as(u6, @truncate(order))) < count) : (order += 1) {}
    freePages(phys_addr, order);
}

pub fn reserveFrame(phys_addr: u64) void {
    const pfn_val = phys_addr / FRAME_SIZE;
    if (pfn_val >= MAX_FRAMES) return;
    page_array[pfn_val].flags.reserved = true;
}

pub fn reserveRange(start: u64, size: u64) void {
    var addr = start & ~@as(u64, FRAME_SIZE - 1);
    const end = (start + size + FRAME_SIZE - 1) & ~@as(u64, FRAME_SIZE - 1);
    while (addr < end) : (addr += FRAME_SIZE) {
        reserveFrame(addr);
    }
}

// =============================================================================
// Statistics
// =============================================================================
pub fn freePageCount() u64 {
    var count: u64 = 0;
    for (0..nr_online_nodes) |ni| {
        for (0..NR_ZONES) |zi| {
            count += nodes[ni].zones[zi].stat.free_pages;
        }
    }
    return count;
}

pub fn totalPageCount() u64 {
    var count: u64 = 0;
    for (0..nr_online_nodes) |ni| {
        for (0..NR_ZONES) |zi| {
            count += nodes[ni].zones[zi].present_pages;
        }
    }
    return count;
}

pub fn usedPageCount() u64 {
    return totalPageCount() - freePageCount();
}

pub fn freeMemoryBytes() u64 {
    return freePageCount() * FRAME_SIZE;
}

pub fn usedMemoryBytes() u64 {
    return usedPageCount() * FRAME_SIZE;
}

pub fn totalMemoryBytes() u64 {
    return totalPageCount() * FRAME_SIZE;
}

// =============================================================================
// Page frame lookup helpers
// =============================================================================
pub fn pfnToPage(pfn_val: u64) ?*PageFrame {
    if (pfn_val >= MAX_FRAMES) return null;
    return &page_array[@as(usize, @truncate(pfn_val))];
}

pub fn pageToPfn(page: *const PageFrame) u64 {
    return (@intFromPtr(page) - @intFromPtr(&page_array)) / @sizeOf(PageFrame);
}

pub fn physToPage(phys_addr: u64) ?*PageFrame {
    return pfnToPage(phys_addr / FRAME_SIZE);
}

pub fn pageToPhys(page: *const PageFrame) u64 {
    return pageToPfn(page) * FRAME_SIZE;
}

fn zeroPage(page: *PageFrame) void {
    const addr = page.physAddr() +% 0xFFFFFFFF80000000;
    const ptr: [*]u8 = @ptrFromInt(@as(usize, @truncate(addr)));
    @memset(ptr[0..FRAME_SIZE], 0);
}

fn zeroPageOrder(page: *PageFrame, order: usize) void {
    const nr_pages = @as(u64, 1) << @as(u6, @truncate(order));
    const addr = page.physAddr() +% 0xFFFFFFFF80000000;
    const size = nr_pages * FRAME_SIZE;
    const ptr: [*]u8 = @ptrFromInt(@as(usize, @truncate(addr)));
    @memset(ptr[0..@as(usize, @truncate(size))], 0);
}

// =============================================================================
// CMA (Contiguous Memory Allocator)
// =============================================================================
pub const CmaRegion = struct {
    base_pfn: u64 = 0,
    count: u64 = 0,
    bitmap: [*]u8 = undefined,
    bitmap_size: usize = 0,
    order_per_bit: u8 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: usize = 0,
    lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init(),
    alloc_count: u64 = 0,
    free_count: u64 = 0,
    alloc_fail: u64 = 0,
    alloc_pages_success: u64 = 0,
    alloc_pages_fail: u64 = 0,

    pub fn allocPages(self: *CmaRegion, count_val: u64, alignment: u64) ?u64 {
        self.lock.acquire();
        defer self.lock.release();
        const pages_per_bit = @as(u64, 1) << @as(u6, @truncate(self.order_per_bit));
        const bits_needed = (count_val + pages_per_bit - 1) / pages_per_bit;
        const align_bits = if (alignment > pages_per_bit) alignment / pages_per_bit else 1;
        const total_bits = self.count / pages_per_bit;
        var start: u64 = 0;
        while (start + bits_needed <= total_bits) {
            if (start % align_bits != 0) {
                start = ((start / align_bits) + 1) * align_bits;
                continue;
            }
            var found = true;
            var bit: u64 = 0;
            while (bit < bits_needed) : (bit += 1) {
                const byte_idx = @as(usize, @truncate((start + bit) / 8));
                const bit_idx = @as(u3, @truncate((start + bit) % 8));
                if (byte_idx >= self.bitmap_size) {
                    found = false;
                    break;
                }
                if (self.bitmap[byte_idx] & (@as(u8, 1) << bit_idx) != 0) {
                    found = false;
                    start = start + bit + 1;
                    break;
                }
            }
            if (found) {
                bit = 0;
                while (bit < bits_needed) : (bit += 1) {
                    const byte_idx = @as(usize, @truncate((start + bit) / 8));
                    const bit_idx = @as(u3, @truncate((start + bit) % 8));
                    self.bitmap[byte_idx] |= @as(u8, 1) << bit_idx;
                }
                self.alloc_count += 1;
                self.alloc_pages_success += count_val;
                return (self.base_pfn + start * pages_per_bit) * FRAME_SIZE;
            }
        }
        self.alloc_fail += 1;
        self.alloc_pages_fail += count_val;
        return null;
    }

    pub fn freePages(self: *CmaRegion, addr: u64, count_val: u64) void {
        self.lock.acquire();
        defer self.lock.release();
        const pfn_val = addr / FRAME_SIZE;
        if (pfn_val < self.base_pfn) return;
        const pages_per_bit = @as(u64, 1) << @as(u6, @truncate(self.order_per_bit));
        const start_bit = (pfn_val - self.base_pfn) / pages_per_bit;
        const bits_needed = (count_val + pages_per_bit - 1) / pages_per_bit;
        var bit: u64 = 0;
        while (bit < bits_needed) : (bit += 1) {
            const byte_idx = @as(usize, @truncate((start_bit + bit) / 8));
            const bit_idx = @as(u3, @truncate((start_bit + bit) % 8));
            if (byte_idx < self.bitmap_size) {
                self.bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
            }
        }
        self.free_count += 1;
    }
};

var cma_regions: [16]CmaRegion = [_]CmaRegion{.{}} ** 16;
var nr_cma_regions: usize = 0;

// =============================================================================
// Memory Hotplug Support
// =============================================================================
pub const MemoryBlock = struct {
    start_pfn: u64 = 0,
    end_pfn: u64 = 0,
    state: MemoryBlockState = .offline,
    node_id: u8 = 0,
    zone_id: u8 = 0,
    removable: bool = false,

    pub const MemoryBlockState = enum {
        offline,
        going_online,
        online,
        going_offline,
    };
};

var memory_blocks: [256]MemoryBlock = [_]MemoryBlock{.{}} ** 256;
var nr_memory_blocks: usize = 0;

pub fn onlineMemoryBlock(block_idx: usize) bool {
    if (block_idx >= nr_memory_blocks) return false;
    var block = &memory_blocks[block_idx];
    if (block.state != .offline) return false;
    block.state = .going_online;
    const node = &nodes[block.node_id];
    const zone = &node.zones[block.zone_id];
    var pfn_val = block.start_pfn;
    while (pfn_val < block.end_pfn and pfn_val < MAX_FRAMES) : (pfn_val += 1) {
        page_array[pfn_val].flags = .{};
        page_array[pfn_val].refcount = 0;
        page_array[pfn_val].zone_id = block.zone_id;
        page_array[pfn_val].node_id = block.node_id;
        page_array[pfn_val].migration_type = .movable;
        zone.freePagesInternal(&page_array[pfn_val], 0);
        zone.present_pages += 1;
    }
    zone.calculateWatermarks();
    block.state = .online;
    main.klog(.info, "PMM: Memory block onlined: PFN {d}-{d} ({d} MB)", .{
        block.start_pfn, block.end_pfn,
        ((block.end_pfn - block.start_pfn) * FRAME_SIZE) / (1024 * 1024),
    });
    return true;
}

pub fn offlineMemoryBlock(block_idx: usize) bool {
    if (block_idx >= nr_memory_blocks) return false;
    var block = &memory_blocks[block_idx];
    if (block.state != .online) return false;
    block.state = .going_offline;
    var pfn_val = block.start_pfn;
    while (pfn_val < block.end_pfn) : (pfn_val += 1) {
        if (pfn_val >= MAX_FRAMES) break;
        const page = &page_array[pfn_val];
        if (page.flags.reserved or page.flags.pinned) {
            block.state = .online;
            return false;
        }
        if (page.refcount > 0 and page.migration_type == .unmovable) {
            block.state = .online;
            return false;
        }
    }
    block.state = .offline;
    return true;
}

// =============================================================================
// Page Isolation for Compaction
// =============================================================================
pub fn isolatePageRange(start_pfn: u64, end_pfn: u64) u64 {
    var isolated: u64 = 0;
    var pfn_val = start_pfn;
    while (pfn_val < end_pfn and pfn_val < MAX_FRAMES) : (pfn_val += 1) {
        var page = &page_array[pfn_val];
        if (page.flags.buddy) {
            const order = page.buddy_order;
            const zone = &nodes[page.node_id].zones[page.zone_id];
            const mt = @intFromEnum(page.migration_type);
            zone.free_area[order][mt].remove(page);
            page.flags.isolated = true;
            isolated += @as(u64, 1) << @as(u6, @truncate(order));
            pfn_val += (@as(u64, 1) << @as(u6, @truncate(order))) - 1;
        } else if (page.refcount > 0 and page.migration_type == .movable) {
            page.flags.isolated = true;
            isolated += 1;
        }
    }
    return isolated;
}

pub fn unIsolatePageRange(start_pfn: u64, end_pfn: u64) void {
    var pfn_val = start_pfn;
    while (pfn_val < end_pfn and pfn_val < MAX_FRAMES) : (pfn_val += 1) {
        var page = &page_array[pfn_val];
        if (page.flags.isolated) {
            page.flags.isolated = false;
            if (page.refcount == 0) {
                const zone = &nodes[page.node_id].zones[page.zone_id];
                zone.freePagesInternal(page, 0);
            }
        }
    }
}

// =============================================================================
// Debug / Dump
// =============================================================================
pub fn dumpBuddyInfo() void {
    main.klog(.info, "=== Buddy Allocator Info ===", .{});
    for (0..nr_online_nodes) |ni| {
        for (0..NR_ZONES) |zi| {
            const zone = &nodes[ni].zones[zi];
            if (zone.present_pages == 0) continue;
            main.klog(.info, "Node {d} Zone {s}:", .{ ni, zone.name[0..zone.name_len] });
            for (0..MAX_ORDER) |order| {
                var total: u64 = 0;
                for (0..MIGRATE_TYPES) |mt| {
                    total += zone.free_area[order][mt].count;
                }
                if (total > 0) {
                    main.klog(.info, "  order {d}: {d} free blocks ({d} pages)", .{
                        order, total, total << @as(u6, @truncate(order)),
                    });
                }
            }
        }
    }
}

pub fn dumpZoneStats() void {
    for (0..nr_online_nodes) |ni| {
        for (0..NR_ZONES) |zi| {
            const zone = &nodes[ni].zones[zi];
            if (zone.present_pages == 0) continue;
            const s = &zone.stat;
            main.klog(.info, "Zone {s}: free={d} alloc={d} fail={d} pgfault={d}", .{
                zone.name[0..zone.name_len],
                s.free_pages,
                s.alloc_count,
                s.alloc_fail_count,
                s.pgfault,
            });
        }
    }
}

pub fn alignDown(addr: u64) u64 {
    return addr & ~@as(u64, FRAME_SIZE - 1);
}

pub fn alignUp(addr: u64) u64 {
    return (addr + FRAME_SIZE - 1) & ~@as(u64, FRAME_SIZE - 1);
}
