// =============================================================================
// Kernel Zxyphor — NUMA Topology & Memory Zones
// =============================================================================
// Advanced memory management: NUMA node tracking, memory zones (DMA, DMA32,
// Normal, HighMem), per-zone page free lists, zone-aware allocation, NUMA
// distance table, memory hotplug stubs, page reclaim watermarks, compaction.
// =============================================================================

// ============================================================================
// Constants
// ============================================================================

pub const MAX_NUMA_NODES: usize = 8;
pub const MAX_ZONES: usize = 4;
pub const MAX_ZONE_ORDER: usize = 11;  // Buddy orders 0..10
pub const MAX_NODE_CPUS: usize = 64;
pub const MAX_MEMORY_REGIONS: usize = 32;

pub const ZONE_DMA: u8 = 0;       // 0 – 16 MB
pub const ZONE_DMA32: u8 = 1;     // 16 MB – 4 GB
pub const ZONE_NORMAL: u8 = 2;    // 4 GB – end of memory
pub const ZONE_HIGHMEM: u8 = 3;   // For PAE/32-bit (unused in x86_64)

pub const ZONE_DMA_LIMIT: u64 = 16 * 1024 * 1024;
pub const ZONE_DMA32_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

// Page flags
pub const PAGE_BUDDY: u32 = 1 << 0;
pub const PAGE_SLAB: u32 = 1 << 1;
pub const PAGE_LOCKED: u32 = 1 << 2;
pub const PAGE_DIRTY: u32 = 1 << 3;
pub const PAGE_ACTIVE: u32 = 1 << 4;
pub const PAGE_REFERENCED: u32 = 1 << 5;
pub const PAGE_RESERVED: u32 = 1 << 6;
pub const PAGE_WRITEBACK: u32 = 1 << 7;
pub const PAGE_RECLAIM: u32 = 1 << 8;
pub const PAGE_COMPOUND: u32 = 1 << 9;
pub const PAGE_HEAD: u32 = 1 << 10;
pub const PAGE_TAIL: u32 = 1 << 11;
pub const PAGE_SWAPBACKED: u32 = 1 << 12;
pub const PAGE_MLOCKED: u32 = 1 << 13;

// ============================================================================
// Physical page frame descriptor
// ============================================================================

pub const PageFrame = struct {
    flags: u32,
    order: u8,         // Buddy order (0 = single page)
    zone_id: u8,       // Which zone this page belongs to
    node_id: u8,       // Which NUMA node
    refcount: u16,     // Reference count
    mapcount: u16,     // Number of page table mappings
    lru_next: u32,     // Index into page array for LRU list
    lru_prev: u32,
    private: u64,      // Slab/buddy metadata

    pub fn init() PageFrame {
        return .{
            .flags = 0,
            .order = 0,
            .zone_id = 0,
            .node_id = 0,
            .refcount = 0,
            .mapcount = 0,
            .lru_next = 0xFFFFFFFF,
            .lru_prev = 0xFFFFFFFF,
            .private = 0,
        };
    }

    pub fn hasFlag(self: *const PageFrame, flag: u32) bool {
        return (self.flags & flag) != 0;
    }

    pub fn setFlag(self: *PageFrame, flag: u32) void {
        self.flags |= flag;
    }

    pub fn clearFlag(self: *PageFrame, flag: u32) void {
        self.flags &= ~flag;
    }

    pub fn get(self: *PageFrame) void {
        self.refcount += 1;
    }

    pub fn put(self: *PageFrame) bool {
        if (self.refcount == 0) return false;
        self.refcount -= 1;
        return self.refcount == 0;
    }
};

// ============================================================================
// Free area for buddy allocator
// ============================================================================

pub const FreeArea = struct {
    free_list_head: u32,  // Head of page index list
    count: u32,           // Number of free blocks at this order

    pub fn init() FreeArea {
        return .{
            .free_list_head = 0xFFFFFFFF,
            .count = 0,
        };
    }
};

// ============================================================================
// Zone watermarks
// ============================================================================

pub const ZoneWatermarks = struct {
    min: u64,       // Minimum free pages (OOM below this)
    low: u64,       // kswapd wakes up
    high: u64,      // kswapd sleeps
    boost: u64,     // Temporary boost for compaction
    managed: u64,   // Total managed pages

    pub fn init() ZoneWatermarks {
        return .{ .min = 0, .low = 0, .high = 0, .boost = 0, .managed = 0 };
    }

    pub fn calculate(total_pages: u64) ZoneWatermarks {
        // Linux-like watermark calculation
        const min_pages = @max(total_pages / 256, 32);
        return .{
            .min = min_pages,
            .low = min_pages + (min_pages / 2),
            .high = min_pages * 3,
            .boost = 0,
            .managed = total_pages,
        };
    }

    pub fn isEmergency(self: *const ZoneWatermarks, free: u64) bool {
        return free < self.min;
    }

    pub fn needsReclaim(self: *const ZoneWatermarks, free: u64) bool {
        return free < self.low + self.boost;
    }

    pub fn reclaimComplete(self: *const ZoneWatermarks, free: u64) bool {
        return free >= self.high + self.boost;
    }
};

// ============================================================================
// Memory zone
// ============================================================================

pub const MemoryZone = struct {
    id: u8,
    name: [8]u8,
    start_pfn: u64,        // Starting page frame number
    end_pfn: u64,
    present_pages: u64,    // Physically present
    managed_pages: u64,    // Available for allocation
    spanned_pages: u64,    // Total span (may include holes)
    free_pages: u64,       // Current free count

    // Buddy allocator free lists per order
    free_areas: [MAX_ZONE_ORDER]FreeArea,
    watermarks: ZoneWatermarks,

    // LRU lists for page reclaim
    active_list_head: u32,
    active_count: u64,
    inactive_list_head: u32,
    inactive_count: u64,

    // Statistics
    alloc_count: u64,
    free_count: u64,
    reclaim_count: u64,
    compact_count: u64,

    pub fn init(id: u8) MemoryZone {
        var zone: MemoryZone = undefined;
        zone.id = id;
        zone.name = switch (id) {
            ZONE_DMA => "DMA\x00\x00\x00\x00\x00".*,
            ZONE_DMA32 => "DMA32\x00\x00\x00".*,
            ZONE_NORMAL => "Normal\x00\x00".*,
            ZONE_HIGHMEM => "HighMem\x00".*,
            else => "Unknown\x00".*,
        };
        zone.start_pfn = 0;
        zone.end_pfn = 0;
        zone.present_pages = 0;
        zone.managed_pages = 0;
        zone.spanned_pages = 0;
        zone.free_pages = 0;
        for (0..MAX_ZONE_ORDER) |i| {
            zone.free_areas[i] = FreeArea.init();
        }
        zone.watermarks = ZoneWatermarks.init();
        zone.active_list_head = 0xFFFFFFFF;
        zone.active_count = 0;
        zone.inactive_list_head = 0xFFFFFFFF;
        zone.inactive_count = 0;
        zone.alloc_count = 0;
        zone.free_count = 0;
        zone.reclaim_count = 0;
        zone.compact_count = 0;
        return zone;
    }

    /// Setup zone boundaries
    pub fn configure(self: *MemoryZone, start: u64, end: u64) void {
        self.start_pfn = start;
        self.end_pfn = end;
        self.spanned_pages = end - start;
        self.present_pages = self.spanned_pages;
        self.managed_pages = self.present_pages;
        self.free_pages = self.managed_pages;
        self.watermarks = ZoneWatermarks.calculate(self.managed_pages);
    }

    /// Check if zone can satisfy allocation of given order
    pub fn canAllocate(self: *const MemoryZone, order: u8) bool {
        const needed = @as(u64, 1) << @intCast(order);
        return self.free_pages >= needed;
    }

    /// Check if allocation would violate watermarks
    pub fn watermarkOk(self: *const MemoryZone, order: u8) bool {
        const needed = @as(u64, 1) << @intCast(order);
        return (self.free_pages -| needed) >= self.watermarks.min;
    }
};

// ============================================================================
// NUMA node
// ============================================================================

pub const NumaNode = struct {
    id: u8,
    active: bool,
    zones: [MAX_ZONES]MemoryZone,
    zone_count: u8,

    // CPU affinity
    cpus: [MAX_NODE_CPUS]u32,
    cpu_count: u32,

    // Memory regions
    mem_start: u64,
    mem_end: u64,
    total_pages: u64,

    // Distance to other nodes (self = 10, remote = 20+)
    distance: [MAX_NUMA_NODES]u8,

    // Allocation statistics
    local_allocs: u64,
    remote_allocs: u64,

    pub fn init(id: u8) NumaNode {
        var node: NumaNode = undefined;
        node.id = id;
        node.active = false;
        node.zone_count = 0;
        node.cpu_count = 0;
        node.mem_start = 0;
        node.mem_end = 0;
        node.total_pages = 0;
        node.local_allocs = 0;
        node.remote_allocs = 0;
        for (0..MAX_ZONES) |i| {
            node.zones[i] = MemoryZone.init(@intCast(i));
        }
        for (0..MAX_NODE_CPUS) |i| {
            node.cpus[i] = 0;
        }
        for (0..MAX_NUMA_NODES) |i| {
            if (i == id) {
                node.distance[i] = 10; // Local
            } else {
                node.distance[i] = 20; // Default remote
            }
        }
        return node;
    }

    /// Add a CPU to this NUMA node
    pub fn addCpu(self: *NumaNode, cpu_id: u32) bool {
        if (self.cpu_count >= MAX_NODE_CPUS) return false;
        self.cpus[self.cpu_count] = cpu_id;
        self.cpu_count += 1;
        return true;
    }

    /// Configure memory range for this node
    pub fn configureMemory(self: *NumaNode, start: u64, end: u64) void {
        self.mem_start = start;
        self.mem_end = end;
        self.total_pages = (end - start) / 4096;
        self.active = true;

        // Setup zones within this node's memory range
        const start_pfn = start / 4096;
        const end_pfn = end / 4096;

        // Zone DMA: 0 – 16 MB
        const dma_end_pfn = @min(end_pfn, ZONE_DMA_LIMIT / 4096);
        if (start_pfn < dma_end_pfn) {
            self.zones[ZONE_DMA].configure(start_pfn, dma_end_pfn);
            self.zone_count = 1;
        }

        // Zone DMA32: 16 MB – 4 GB
        const dma32_start = @max(start_pfn, ZONE_DMA_LIMIT / 4096);
        const dma32_end = @min(end_pfn, ZONE_DMA32_LIMIT / 4096);
        if (dma32_start < dma32_end) {
            self.zones[ZONE_DMA32].configure(dma32_start, dma32_end);
            self.zone_count = 2;
        }

        // Zone Normal: 4 GB+
        const normal_start = @max(start_pfn, ZONE_DMA32_LIMIT / 4096);
        if (normal_start < end_pfn) {
            self.zones[ZONE_NORMAL].configure(normal_start, end_pfn);
            self.zone_count = 3;
        }
    }

    /// Find best zone for allocation
    pub fn findZone(self: *const NumaNode, gfp_flags: u32) ?*const MemoryZone {
        // Determine highest allowed zone from GFP flags
        const max_zone: u8 = if (gfp_flags & GFP_DMA != 0) ZONE_DMA
            else if (gfp_flags & GFP_DMA32 != 0) ZONE_DMA32
            else ZONE_NORMAL;

        // Fallback list: try from requested zone downward
        var zone_id: u8 = max_zone;
        while (true) {
            if (self.zones[zone_id].managed_pages > 0) {
                return &self.zones[zone_id];
            }
            if (zone_id == 0) break;
            zone_id -= 1;
        }
        return null;
    }
};

// ============================================================================
// GFP flags (Get Free Pages)
// ============================================================================

pub const GFP_DMA: u32 = 1 << 0;
pub const GFP_DMA32: u32 = 1 << 1;
pub const GFP_HIGHMEM: u32 = 1 << 2;
pub const GFP_KERNEL: u32 = 1 << 3;   // Can sleep, can reclaim
pub const GFP_ATOMIC: u32 = 1 << 4;   // Cannot sleep
pub const GFP_NOWAIT: u32 = 1 << 5;   // Don't wait
pub const GFP_NORETRY: u32 = 1 << 6;
pub const GFP_NOFAIL: u32 = 1 << 7;   // Must succeed
pub const GFP_ZERO: u32 = 1 << 8;     // Zero the page
pub const GFP_COMP: u32 = 1 << 9;     // Compound page
pub const GFP_THISNODE: u32 = 1 << 10; // This NUMA node only
pub const GFP_MOVABLE: u32 = 1 << 11;  // Movable allocation (for compaction)
pub const GFP_RECLAIM: u32 = 1 << 12;  // Can trigger reclaim

// ============================================================================
// NUMA topology manager
// ============================================================================

pub const NumaTopology = struct {
    nodes: [MAX_NUMA_NODES]NumaNode,
    node_count: u8,
    initialized: bool,

    // Page frame array (indexed by PFN)
    page_frames: [*]PageFrame,
    total_pages: u64,

    // Zonelist for fallback (node ordering per CPU)
    fallback_order: [MAX_NUMA_NODES]u8,

    pub fn init() NumaTopology {
        var topo: NumaTopology = undefined;
        topo.node_count = 0;
        topo.initialized = false;
        topo.page_frames = undefined;
        topo.total_pages = 0;
        for (0..MAX_NUMA_NODES) |i| {
            topo.nodes[i] = NumaNode.init(@intCast(i));
            topo.fallback_order[i] = @intCast(i);
        }
        return topo;
    }

    /// Register a NUMA node
    pub fn addNode(self: *NumaTopology, start: u64, end: u64) ?u8 {
        if (self.node_count >= MAX_NUMA_NODES) return null;
        const id = self.node_count;
        self.nodes[id].configureMemory(start, end);
        self.node_count += 1;
        return id;
    }

    /// Set NUMA distance between two nodes
    pub fn setDistance(self: *NumaTopology, from: u8, to: u8, dist: u8) void {
        if (from >= MAX_NUMA_NODES or to >= MAX_NUMA_NODES) return;
        self.nodes[from].distance[to] = dist;
    }

    /// Build fallback order for a given node (sorted by distance)
    pub fn buildFallbackOrder(self: *NumaTopology, local_node: u8) void {
        // Simple insertion sort by distance
        var order: [MAX_NUMA_NODES]u8 = undefined;
        for (0..MAX_NUMA_NODES) |i| {
            order[i] = @intCast(i);
        }

        var i: usize = 1;
        while (i < self.node_count) : (i += 1) {
            var j = i;
            while (j > 0 and self.nodes[local_node].distance[order[j]] <
                self.nodes[local_node].distance[order[j - 1]]) : (j -= 1) {
                const tmp = order[j];
                order[j] = order[j - 1];
                order[j - 1] = tmp;
            }
        }
        self.fallback_order = order;
    }

    /// Try to allocate pages from a specific node
    pub fn allocFromNode(self: *NumaTopology, node_id: u8, order: u8, gfp: u32) u64 {
        if (node_id >= self.node_count) return 0;
        const node = &self.nodes[node_id];

        // Try the requested zone type first
        const max_zone: u8 = if (gfp & GFP_DMA != 0) ZONE_DMA
            else if (gfp & GFP_DMA32 != 0) ZONE_DMA32
            else ZONE_NORMAL;

        var zone_idx: u8 = max_zone;
        while (true) {
            var zone = &node.zones[zone_idx];
            if (zone.managed_pages > 0 and zone.canAllocate(order)) {
                if (zone.watermarkOk(order) or (gfp & GFP_ATOMIC != 0)) {
                    const pages = @as(u64, 1) << @intCast(order);
                    zone.free_pages -|= pages;
                    zone.alloc_count += 1;
                    node.local_allocs += 1;
                    // Return a placeholder PFN (actual buddy allocator would return real PFN)
                    return zone.start_pfn;
                }
            }
            if (zone_idx == 0) break;
            zone_idx -= 1;
        }
        return 0;
    }

    /// Allocate pages with NUMA-aware fallback
    pub fn allocPages(self: *NumaTopology, preferred_node: u8, order: u8, gfp: u32) u64 {
        // Try preferred node first
        const result = self.allocFromNode(preferred_node, order, gfp);
        if (result != 0) return result;

        // If THISNODE flag, don't fallback
        if (gfp & GFP_THISNODE != 0) return 0;

        // Try fallback nodes in distance order
        for (0..self.node_count) |i| {
            const node_id = self.fallback_order[i];
            if (node_id == preferred_node) continue;
            const fb_result = self.allocFromNode(node_id, order, gfp);
            if (fb_result != 0) {
                self.nodes[node_id].remote_allocs += 1;
                return fb_result;
            }
        }

        // If GFP_RECLAIM, try reclaim and retry
        if (gfp & GFP_RECLAIM != 0) {
            self.reclaimPages(preferred_node);
            return self.allocFromNode(preferred_node, order, gfp & ~GFP_RECLAIM);
        }

        return 0; // OOM
    }

    /// Trigger page reclaim on a node
    fn reclaimPages(self: *NumaTopology, node_id: u8) void {
        if (node_id >= self.node_count) return;
        const node = &self.nodes[node_id];
        // Walk inactive LRU and free pages
        for (0..MAX_ZONES) |z| {
            var zone = &node.zones[z];
            if (zone.inactive_count > 0) {
                // In a real implementation, walk the inactive list and:
                // 1. Check page reference bits
                // 2. Write back dirty pages
                // 3. Free unreferenced pages
                zone.reclaim_count += 1;
            }
        }
    }

    /// Get memory info for a node
    pub fn getNodeInfo(self: *const NumaTopology, node_id: u8) NodeMemInfo {
        if (node_id >= self.node_count) return NodeMemInfo.empty();
        const node = &self.nodes[node_id];
        var info = NodeMemInfo.empty();
        info.node_id = node_id;
        info.total_pages = node.total_pages;
        for (0..MAX_ZONES) |z| {
            info.free_pages += node.zones[z].free_pages;
            info.managed_pages += node.zones[z].managed_pages;
        }
        info.local_allocs = node.local_allocs;
        info.remote_allocs = node.remote_allocs;
        return info;
    }
};

pub const NodeMemInfo = struct {
    node_id: u8,
    total_pages: u64,
    free_pages: u64,
    managed_pages: u64,
    local_allocs: u64,
    remote_allocs: u64,

    pub fn empty() NodeMemInfo {
        return .{
            .node_id = 0,
            .total_pages = 0,
            .free_pages = 0,
            .managed_pages = 0,
            .local_allocs = 0,
            .remote_allocs = 0,
        };
    }
};

var numa_topology: NumaTopology = NumaTopology.init();

pub fn getNumaTopology() *NumaTopology {
    return &numa_topology;
}
