// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced SLAB Allocator
// SLUB-like design with per-CPU caches, NUMA-awareness, object tracking
const std = @import("std");

// ============================================================================
// SLAB Cache Configuration
// ============================================================================

pub const SLAB_HWCACHE_ALIGN: u32 = 1 << 0;
pub const SLAB_CACHE_DMA: u32 = 1 << 1;
pub const SLAB_CACHE_DMA32: u32 = 1 << 2;
pub const SLAB_PANIC: u32 = 1 << 3;
pub const SLAB_POISON: u32 = 1 << 4;
pub const SLAB_RED_ZONE: u32 = 1 << 5;
pub const SLAB_STORE_USER: u32 = 1 << 6;
pub const SLAB_RECLAIM_ACCOUNT: u32 = 1 << 7;
pub const SLAB_MEM_SPREAD: u32 = 1 << 8;
pub const SLAB_TYPESAFE_BY_RCU: u32 = 1 << 9;
pub const SLAB_DEBUG_FREE: u32 = 1 << 10;
pub const SLAB_NOLEAKTRACE: u32 = 1 << 11;
pub const SLAB_FAILSLAB: u32 = 1 << 12;
pub const SLAB_ACCOUNT: u32 = 1 << 13;
pub const SLAB_NO_USER_FLAGS: u32 = 1 << 14;

pub const MAX_CPUS: usize = 256;
pub const MAX_NUMA_NODES: usize = 8;
pub const SLAB_FREELIST_END: usize = 0xDEAD_BEEF_DEAD_BEEF;
pub const SLAB_REDZONE_PATTERN: u32 = 0xBB;
pub const SLAB_POISON_FREE: u8 = 0x6B;
pub const SLAB_POISON_ALLOC: u8 = 0xA5;

// ============================================================================
// Per-Object Metadata
// ============================================================================

pub const SlabObjTrack = struct {
    addr: usize = 0,           // Caller address
    cpu_id: u16 = 0,
    pid: u32 = 0,
    timestamp_ns: u64 = 0,
    stack: [8]usize = [_]usize{0} ** 8,
    stack_depth: u8 = 0,
};

pub const SlabRedzone = struct {
    pub const LEFT_PATTERN: u64 = 0xDEAD_C0DE_DEAD_C0DE;
    pub const RIGHT_PATTERN: u64 = 0xBAAD_F00D_BAAD_F00D;

    left: u64 = LEFT_PATTERN,
    right: u64 = RIGHT_PATTERN,

    pub fn check(self: *const SlabRedzone) bool {
        return self.left == LEFT_PATTERN and self.right == RIGHT_PATTERN;
    }
};

// ============================================================================
// Page-level SLAB (multiple objects per page)
// ============================================================================

pub const SlabPage = struct {
    /// Freelist: linked list of free objects via embedded pointers
    freelist: usize = 0,
    /// Number of allocated objects
    inuse: u16 = 0,
    /// Total objects in this slab
    objects: u16 = 0,
    /// slab_cache backpointer
    cache_idx: u16 = 0,
    /// Frozen flag (per-CPU)
    frozen: bool = false,
    /// NUMA node
    node: u8 = 0,
    /// Base virtual address of page
    base_addr: usize = 0,
    /// Page order (2^order pages)
    order: u8 = 0,
    /// Next/prev for partial list
    next: ?*SlabPage = null,
    prev: ?*SlabPage = null,
    /// Debug
    flags: u32 = 0,
    /// Per-slab free count
    free_count: u16 = 0,

    pub fn isFull(self: *const SlabPage) bool {
        return self.inuse >= self.objects;
    }

    pub fn isEmpty(self: *const SlabPage) bool {
        return self.inuse == 0;
    }

    /// Initialize freelist for a new slab page
    pub fn initFreelist(self: *SlabPage, obj_size: usize, obj_count: u16) void {
        self.objects = obj_count;
        self.inuse = 0;
        self.free_count = obj_count;
        
        if (obj_count == 0) return;
        
        // Build freelist through embedded pointers
        self.freelist = self.base_addr;
        var i: u16 = 0;
        while (i < obj_count - 1) : (i += 1) {
            const current = self.base_addr + @as(usize, i) * obj_size;
            const next = self.base_addr + @as(usize, i + 1) * obj_size;
            const ptr: *usize = @ptrFromInt(current);
            ptr.* = next;
        }
        // Last object points to end sentinel
        const last = self.base_addr + @as(usize, obj_count - 1) * obj_size;
        const last_ptr: *usize = @ptrFromInt(last);
        last_ptr.* = SLAB_FREELIST_END;
    }

    /// Allocate one object from this slab
    pub fn allocObject(self: *SlabPage) ?usize {
        if (self.freelist == 0 or self.freelist == SLAB_FREELIST_END) return null;
        
        const obj = self.freelist;
        const next_ptr: *const usize = @ptrFromInt(obj);
        self.freelist = next_ptr.*;
        self.inuse += 1;
        self.free_count -= 1;
        return obj;
    }

    /// Free an object back to this slab
    pub fn freeObject(self: *SlabPage, addr: usize) void {
        const ptr: *usize = @ptrFromInt(addr);
        ptr.* = self.freelist;
        self.freelist = addr;
        if (self.inuse > 0) self.inuse -= 1;
        self.free_count += 1;
    }
};

// ============================================================================
// Per-CPU Cache (fast path)
// ============================================================================

pub const PerCpuSlabCache = struct {
    /// Currently active slab (frozen)
    active_slab: ?*SlabPage = null,
    /// Recently freed objects cache (magazine)
    magazine: [64]usize = [_]usize{0} ** 64,
    magazine_count: u8 = 0,
    magazine_max: u8 = 64,
    /// Statistics
    alloc_fastpath: u64 = 0,
    alloc_slowpath: u64 = 0,
    free_fastpath: u64 = 0,
    free_slowpath: u64 = 0,
    free_frozen: u64 = 0,
    /// Tid for lockless operations  
    tid: u64 = 0,

    /// Fast-path allocation from magazine
    pub fn allocFast(self: *PerCpuSlabCache) ?usize {
        if (self.magazine_count > 0) {
            self.magazine_count -= 1;
            const obj = self.magazine[self.magazine_count];
            self.alloc_fastpath += 1;
            return obj;
        }
        // Try active slab
        if (self.active_slab) |slab| {
            if (slab.allocObject()) |obj| {
                self.alloc_fastpath += 1;
                return obj;
            }
        }
        return null; // Slow path needed
    }

    /// Fast-path free to magazine
    pub fn freeFast(self: *PerCpuSlabCache, addr: usize) bool {
        if (self.magazine_count < self.magazine_max) {
            self.magazine[self.magazine_count] = addr;
            self.magazine_count += 1;
            self.free_fastpath += 1;
            return true;
        }
        return false; // Magazine full, slow path
    }
};

// ============================================================================
// NUMA-aware Per-Node Data
// ============================================================================

pub const PerNodeSlabData = struct {
    /// Partial slab list (has free objects)
    partial_head: ?*SlabPage = null,
    partial_count: u32 = 0,
    partial_max: u32 = 32,
    /// Full slab list
    full_head: ?*SlabPage = null,
    full_count: u32 = 0,
    /// Total
    nr_slabs: u32 = 0,
    nr_objs: u64 = 0,
    /// NUMA node affinity
    node_id: u8 = 0,

    pub fn addPartial(self: *PerNodeSlabData, slab: *SlabPage) void {
        slab.next = self.partial_head;
        slab.prev = null;
        if (self.partial_head) |h| {
            h.prev = slab;
        }
        self.partial_head = slab;
        self.partial_count += 1;
    }

    pub fn removePartial(self: *PerNodeSlabData, slab: *SlabPage) void {
        if (slab.prev) |p| {
            p.next = slab.next;
        } else {
            self.partial_head = slab.next;
        }
        if (slab.next) |n| {
            n.prev = slab.prev;
        }
        slab.next = null;
        slab.prev = null;
        if (self.partial_count > 0) self.partial_count -= 1;
    }

    /// Get a partial slab for allocation
    pub fn getPartialSlab(self: *PerNodeSlabData) ?*SlabPage {
        var slab = self.partial_head;
        while (slab) |s| {
            if (!s.isFull()) {
                return s;
            }
            slab = s.next;
        }
        return null;
    }
};

// ============================================================================
// SLAB Cache (kmem_cache equivalent)
// ============================================================================

pub const SlabCache = struct {
    /// Cache name
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    /// Object layout
    object_size: u32 = 0,       // Requested size
    size: u32 = 0,              // Actual size (with alignment, redzone, etc.)
    align: u32 = 8,             // Alignment requirement
    offset: u32 = 0,            // Freelist pointer offset
    /// Page allocation
    order: u8 = 0,              // Page order (2^order pages per slab)
    objects_per_slab: u16 = 0,  // Objects per slab page
    /// Flags
    flags: u32 = 0,
    /// Constructor/destructor
    ctor: ?*const fn (usize) void = null,
    /// Per-CPU caches
    cpu_caches: [MAX_CPUS]PerCpuSlabCache = [_]PerCpuSlabCache{PerCpuSlabCache{}} ** MAX_CPUS,
    /// Per-NUMA-node data
    node_data: [MAX_NUMA_NODES]PerNodeSlabData = [_]PerNodeSlabData{PerNodeSlabData{}} ** MAX_NUMA_NODES,
    /// Slab page pool
    slab_pool: [256]SlabPage = undefined,
    slab_pool_used: u32 = 0,
    /// Statistics
    total_allocs: u64 = 0,
    total_frees: u64 = 0,
    active_objects: u64 = 0,
    total_slabs: u32 = 0,
    /// Refcount for destruction
    refcount: u32 = 1,

    pub fn create(name: []const u8, obj_size: u32, align_val: u32, flags: u32) SlabCache {
        var cache = SlabCache{};
        
        const nlen = @min(name.len, 32);
        @memcpy(cache.name[0..nlen], name[0..nlen]);
        cache.name_len = @intCast(nlen);
        cache.object_size = obj_size;
        cache.flags = flags;
        
        // Calculate actual size with metadata
        var actual_size = obj_size;
        
        // Add redzone space if requested
        if (flags & SLAB_RED_ZONE != 0) {
            actual_size += 16; // 8 bytes before + 8 bytes after
        }
        
        // Align
        const alignment = if (flags & SLAB_HWCACHE_ALIGN != 0)
            @max(align_val, 64) // Cache line alignment
        else
            @max(align_val, 8);
        
        actual_size = (actual_size + alignment - 1) & ~(alignment - 1);
        cache.size = actual_size;
        cache.align = alignment;
        
        // Calculate order and objects per slab
        // Target: at least 8 objects per slab, try smallest order
        var order: u8 = 0;
        while (order < 10) : (order += 1) {
            const slab_size = @as(usize, 4096) << @as(u6, @intCast(order));
            const objs = slab_size / actual_size;
            if (objs >= 8 or order >= 3) {
                cache.order = order;
                cache.objects_per_slab = @intCast(@min(objs, 65535));
                break;
            }
        }
        
        return cache;
    }

    /// Allocate an object from this cache
    pub fn alloc(self: *SlabCache, cpu_id: u16) ?usize {
        // Fast path: per-CPU cache
        const obj = self.cpu_caches[cpu_id].allocFast();
        if (obj) |addr| {
            self.total_allocs += 1;
            self.active_objects += 1;
            
            // Poison check if enabled
            if (self.flags & SLAB_POISON != 0) {
                self.poisonAlloc(addr);
            }
            // Call constructor
            if (self.ctor) |ctor| {
                ctor(addr);
            }
            return addr;
        }

        // Slow path: get from node partial list
        return self.allocSlowpath(cpu_id);
    }

    fn allocSlowpath(self: *SlabCache, cpu_id: u16) ?usize {
        // Try NUMA node 0 for now
        var node = &self.node_data[0];
        
        if (node.getPartialSlab()) |slab| {
            const obj = slab.allocObject() orelse return null;
            self.cpu_caches[cpu_id].alloc_slowpath += 1;
            self.total_allocs += 1;
            self.active_objects += 1;
            return obj;
        }

        // Need to allocate a new slab
        return self.allocNewSlab(cpu_id, 0);
    }

    fn allocNewSlab(self: *SlabCache, cpu_id: u16, node_id: u8) ?usize {
        if (self.slab_pool_used >= self.slab_pool.len) return null;
        
        const idx = self.slab_pool_used;
        self.slab_pool_used += 1;
        var slab = &self.slab_pool[idx];
        
        // In a real kernel, we'd call page allocator here
        // For now, use a fixed address space simulation
        slab.base_addr = 0x1000_0000 + @as(usize, idx) * (@as(usize, 4096) << @as(u6, @intCast(self.order)));
        slab.order = self.order;
        slab.cache_idx = 0;
        slab.node = node_id;
        slab.initFreelist(self.size, self.objects_per_slab);
        
        // Add to node data
        self.node_data[node_id].addPartial(slab);
        self.node_data[node_id].nr_slabs += 1;
        self.total_slabs += 1;
        
        // Freeze for this CPU
        slab.frozen = true;
        self.cpu_caches[cpu_id].active_slab = slab;
        
        const obj = slab.allocObject() orelse return null;
        self.total_allocs += 1;
        self.active_objects += 1;
        return obj;
    }

    /// Free an object back to this cache
    pub fn free(self: *SlabCache, addr: usize, cpu_id: u16) void {
        // Validate
        if (self.flags & SLAB_RED_ZONE != 0) {
            // Check redzone integrity
            // (Would check the redzone patterns around the object)
        }
        
        if (self.flags & SLAB_POISON != 0) {
            self.poisonFree(addr);
        }

        // Fast path: per-CPU magazine
        if (self.cpu_caches[cpu_id].freeFast(addr)) {
            self.total_frees += 1;
            if (self.active_objects > 0) self.active_objects -= 1;
            return;
        }

        // Slow path: return to slab
        self.freeSlowpath(addr, cpu_id);
    }

    fn freeSlowpath(self: *SlabCache, addr: usize, cpu_id: u16) void {
        _ = cpu_id;
        // Find which slab this object belongs to
        var i: u32 = 0;
        while (i < self.slab_pool_used) : (i += 1) {
            const slab = &self.slab_pool[i];
            const slab_end = slab.base_addr + @as(usize, self.objects_per_slab) * self.size;
            if (addr >= slab.base_addr and addr < slab_end) {
                slab.freeObject(addr);
                self.total_frees += 1;
                if (self.active_objects > 0) self.active_objects -= 1;
                
                // Check if slab is now empty (can be freed)
                if (slab.isEmpty() and !slab.frozen) {
                    // Could return pages to page allocator
                }
                return;
            }
        }
    }

    fn poisonAlloc(self: *const SlabCache, addr: usize) void {
        const ptr: [*]u8 = @ptrFromInt(addr);
        @memset(ptr[0..self.object_size], SLAB_POISON_ALLOC);
    }

    fn poisonFree(self: *const SlabCache, addr: usize) void {
        const ptr: [*]u8 = @ptrFromInt(addr);
        @memset(ptr[0..self.object_size], SLAB_POISON_FREE);
    }

    /// Shrink cache by reclaiming empty slabs
    pub fn shrink(self: *SlabCache) u32 {
        var freed: u32 = 0;
        var node_idx: usize = 0;
        while (node_idx < MAX_NUMA_NODES) : (node_idx += 1) {
            var node = &self.node_data[node_idx];
            var slab = node.partial_head;
            while (slab) |s| {
                const next_slab = s.next;
                if (s.isEmpty() and !s.frozen) {
                    node.removePartial(s);
                    node.nr_slabs -= 1;
                    if (self.total_slabs > 0) self.total_slabs -= 1;
                    freed += 1;
                }
                slab = next_slab;
            }
        }
        return freed;
    }

    /// Get utilization statistics
    pub fn utilization(self: *const SlabCache) SlabStats {
        var total_objs: u64 = 0;
        var i: u32 = 0;
        while (i < self.slab_pool_used) : (i += 1) {
            total_objs += self.slab_pool[i].objects;
        }
        return SlabStats{
            .active_objects = self.active_objects,
            .total_objects = total_objs,
            .total_slabs = self.total_slabs,
            .object_size = self.object_size,
            .slab_size = self.size,
            .pages_per_slab = @as(u32, 1) << @as(u5, @intCast(self.order)),
            .total_allocs = self.total_allocs,
            .total_frees = self.total_frees,
        };
    }
};

pub const SlabStats = struct {
    active_objects: u64,
    total_objects: u64,
    total_slabs: u32,
    object_size: u32,
    slab_size: u32,
    pages_per_slab: u32,
    total_allocs: u64,
    total_frees: u64,

    pub fn utilizationPct(self: *const SlabStats) u32 {
        if (self.total_objects == 0) return 0;
        return @intCast((self.active_objects * 100) / self.total_objects);
    }

    pub fn wastedBytes(self: *const SlabStats) u64 {
        const overhead_per_obj = self.slab_size - self.object_size;
        return self.total_objects * @as(u64, overhead_per_obj);
    }
};

// ============================================================================
// Global Slab Allocator (kmalloc equivalent)
// ============================================================================

pub const KMALLOC_MIN_SIZE: u32 = 8;
pub const KMALLOC_MAX_SIZE: u32 = 8192;
pub const KMALLOC_NUM_CACHES: usize = 13;

pub const KmallocCacheSizes = [KMALLOC_NUM_CACHES]u32{
    8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
};

pub const GlobalSlabAllocator = struct {
    caches: [KMALLOC_NUM_CACHES]SlabCache = undefined,
    initialized: bool = false,
    // DMA caches
    dma_caches: [KMALLOC_NUM_CACHES]SlabCache = undefined,
    dma_initialized: bool = false,

    pub fn init(self: *GlobalSlabAllocator) void {
        for (&self.caches, 0..) |*cache, i| {
            var name_buf: [32]u8 = [_]u8{0} ** 32;
            const prefix = "kmalloc-";
            @memcpy(name_buf[0..prefix.len], prefix);
            cache.* = SlabCache.create(&name_buf, KmallocCacheSizes[i], 8, SLAB_HWCACHE_ALIGN);
        }
        self.initialized = true;
    }

    pub fn selectCache(size: u32) ?usize {
        for (KmallocCacheSizes, 0..) |cache_size, i| {
            if (size <= cache_size) return i;
        }
        return null;
    }

    pub fn kmalloc(self: *GlobalSlabAllocator, size: u32, cpu_id: u16) ?usize {
        if (!self.initialized) return null;
        const idx = selectCache(size) orelse return null;
        return self.caches[idx].alloc(cpu_id);
    }

    pub fn kfree(self: *GlobalSlabAllocator, addr: usize, size: u32, cpu_id: u16) void {
        if (!self.initialized) return;
        const idx = selectCache(size) orelse return;
        self.caches[idx].free(addr, cpu_id);
    }

    pub fn kmallocStats(self: *const GlobalSlabAllocator) [KMALLOC_NUM_CACHES]SlabStats {
        var stats: [KMALLOC_NUM_CACHES]SlabStats = undefined;
        for (&self.caches, 0..) |*cache, i| {
            stats[i] = cache.utilization();
        }
        return stats;
    }
};
