// =============================================================================
// Kernel Zxyphor - Slab Allocator
// =============================================================================
// Slab allocation is optimized for frequently allocated kernel objects of
// fixed sizes. Instead of using the general-purpose heap for every small
// allocation, the slab allocator pre-allocates pools ("caches") for common
// sizes, dramatically reducing fragmentation and improving performance.
//
// Each cache manages objects of a single size. A slab is a page (or group
// of pages) divided into equal-sized slots. Caches maintain three lists:
//   - Full slabs (all slots allocated)
//   - Partial slabs (some slots free — preferred for allocation)
//   - Empty slabs (all slots free — can be returned to PMM)
//
// This is modeled after the Solaris/Linux SLAB allocator concept.
// =============================================================================

const main = @import("../main.zig");
const paging = @import("../arch/x86_64/paging.zig");

// =============================================================================
// Slab structure — one page worth of objects
// =============================================================================
const Slab = struct {
    cache: *SlabCache, // Back-pointer to the owning cache
    free_list: ?*FreeSlot, // Head of the internal free list
    free_count: u32, // Number of free objects in this slab
    total_count: u32, // Total capacity of this slab
    next: ?*Slab, // Next slab in the cache's list
    prev: ?*Slab, // Previous slab in the cache's list
    base_addr: usize, // Start of the data area
};

const FreeSlot = struct {
    next: ?*FreeSlot,
};

// =============================================================================
// Slab Cache — manages all slabs for a particular object size
// =============================================================================
pub const SlabCache = struct {
    name: [32]u8, // Human-readable name
    name_len: usize,
    object_size: usize, // Size of each object
    objects_per_slab: u32, // How many objects fit in one slab
    slab_pages: u32, // Pages per slab

    partial_list: ?*Slab, // Slabs with free objects
    full_list: ?*Slab, // Slabs with no free objects
    empty_list: ?*Slab, // Completely free slabs

    // Statistics
    total_allocated: u64,
    total_freed: u64,
    active_objects: u64,
    total_slabs: u32,
    empty_slabs: u32,

    lock: main.spinlock.SpinLock,

    /// Allocate an object from this cache
    pub fn allocObject(self: *SlabCache) ?[*]u8 {
        self.lock.acquire();
        defer self.lock.release();

        // Try to allocate from a partial slab first
        if (self.partial_list) |slab| {
            return self.allocFromSlab(slab);
        }

        // Try to reuse an empty slab
        if (self.empty_list) |slab| {
            // Move from empty to partial list
            removeFromList(&self.empty_list, slab);
            self.empty_slabs -= 1;
            addToList(&self.partial_list, slab);
            return self.allocFromSlab(slab);
        }

        // Need to create a new slab
        const new_slab = self.createSlab() orelse return null;
        addToList(&self.partial_list, new_slab);
        return self.allocFromSlab(new_slab);
    }

    /// Free an object back to this cache
    pub fn freeObject(self: *SlabCache, ptr: [*]u8) void {
        self.lock.acquire();
        defer self.lock.release();

        // Find which slab this object belongs to
        const slab = self.findSlab(ptr) orelse {
            main.klog(.err, "Slab: free of unknown pointer 0x{x} in cache '{s}'", .{
                @intFromPtr(ptr),
                self.name[0..self.name_len],
            });
            return;
        };

        // Add the object back to the slab's free list
        const slot = @as(*FreeSlot, @ptrCast(@alignCast(ptr)));
        slot.next = slab.free_list;
        slab.free_list = slot;
        slab.free_count += 1;

        self.active_objects -= 1;
        self.total_freed += 1;

        // Move the slab to the appropriate list
        if (slab.free_count == slab.total_count) {
            // Became empty — move to empty list (or free if we have too many)
            if (slab.free_count < slab.total_count) {
                // was in partial, now empty
                removeFromList(&self.partial_list, slab);
            } else {
                removeFromList(&self.full_list, slab);
            }

            if (self.empty_slabs >= 2) {
                // Free excess empty slabs back to the system
                self.destroySlab(slab);
            } else {
                addToList(&self.empty_list, slab);
                self.empty_slabs += 1;
            }
        } else if (slab.free_count == 1) {
            // Was full, now has a free slot — move to partial
            removeFromList(&self.full_list, slab);
            addToList(&self.partial_list, slab);
        }
        // Otherwise it was already in the partial list
    }

    /// Allocate an object from a specific slab
    fn allocFromSlab(self: *SlabCache, slab: *Slab) ?[*]u8 {
        const slot = slab.free_list orelse return null;
        slab.free_list = slot.next;
        slab.free_count -= 1;

        self.active_objects += 1;
        self.total_allocated += 1;

        // If slab is now full, move to full list
        if (slab.free_count == 0) {
            removeFromList(&self.partial_list, slab);
            addToList(&self.full_list, slab);
        }

        return @as([*]u8, @ptrCast(slot));
    }

    /// Create a new slab
    fn createSlab(self: *SlabCache) ?*Slab {
        // Allocate pages for the slab
        const pages = main.vmm.allocKernelPages(@as(u64, self.slab_pages)) orelse return null;
        const base = @as(usize, @truncate(pages));

        // Place the Slab header at the beginning of the allocated pages
        const slab = @as(*Slab, @ptrFromInt(base));
        slab.* = Slab{
            .cache = self,
            .free_list = null,
            .free_count = self.objects_per_slab,
            .total_count = self.objects_per_slab,
            .next = null,
            .prev = null,
            .base_addr = base + @sizeOf(Slab),
        };

        // Initialize the free list within the slab
        const data_start = alignUpAddr(base + @sizeOf(Slab), self.object_size);
        var i: u32 = 0;
        var prev_slot: ?*FreeSlot = null;

        while (i < self.objects_per_slab) : (i += 1) {
            const slot_addr = data_start + @as(usize, i) * self.object_size;
            const slot = @as(*FreeSlot, @ptrFromInt(slot_addr));
            slot.next = prev_slot;
            prev_slot = slot;
        }

        slab.free_list = prev_slot;
        self.total_slabs += 1;

        return slab;
    }

    /// Destroy a slab and return its memory
    fn destroySlab(self: *SlabCache, slab: *Slab) void {
        const base_page = @intFromPtr(slab) & ~@as(usize, @truncate(paging.PAGE_SIZE - 1));
        main.vmm.freeKernelPages(@as(u64, base_page), @as(u64, self.slab_pages));
        self.total_slabs -= 1;
    }

    /// Find which slab a pointer belongs to
    fn findSlab(self: *SlabCache, ptr: [*]u8) ?*Slab {
        const addr = @intFromPtr(ptr);

        // Check partial slabs
        var slab = self.partial_list;
        while (slab) |s| {
            if (addr >= s.base_addr and addr < s.base_addr + @as(usize, s.total_count) * self.object_size) {
                return s;
            }
            slab = s.next;
        }

        // Check full slabs
        slab = self.full_list;
        while (slab) |s| {
            if (addr >= s.base_addr and addr < s.base_addr + @as(usize, s.total_count) * self.object_size) {
                return s;
            }
            slab = s.next;
        }

        return null;
    }
};

// =============================================================================
// Global slab caches for common object sizes
// =============================================================================
const NUM_SIZE_CACHES = 8;
const size_classes = [NUM_SIZE_CACHES]usize{ 32, 64, 128, 256, 512, 1024, 2048, 4096 };

var size_caches: [NUM_SIZE_CACHES]SlabCache = undefined;

// Named caches for specific kernel objects
const MAX_NAMED_CACHES = 32;
var named_caches: [MAX_NAMED_CACHES]?*SlabCache = [_]?*SlabCache{null} ** MAX_NAMED_CACHES;
var named_cache_count: usize = 0;

// =============================================================================
// Initialize the slab allocator
// =============================================================================
pub fn initialize() void {
    for (0..NUM_SIZE_CACHES) |i| {
        const obj_size = size_classes[i];
        const page_size = @as(usize, @truncate(paging.PAGE_SIZE));
        const objects = @as(u32, @truncate((page_size - @sizeOf(Slab)) / obj_size));

        size_caches[i] = SlabCache{
            .name = [_]u8{0} ** 32,
            .name_len = 0,
            .object_size = obj_size,
            .objects_per_slab = objects,
            .slab_pages = 1,
            .partial_list = null,
            .full_list = null,
            .empty_list = null,
            .total_allocated = 0,
            .total_freed = 0,
            .active_objects = 0,
            .total_slabs = 0,
            .empty_slabs = 0,
            .lock = main.spinlock.SpinLock.init(),
        };

        // Set cache name
        const name_str = "size-";
        @memcpy(size_caches[i].name[0..name_str.len], name_str);
        size_caches[i].name_len = name_str.len;
    }

    main.klog(.info, "Slab: Initialized {d} size-class caches", .{NUM_SIZE_CACHES});
}

/// Allocate memory of the given size using the appropriate slab cache
pub fn alloc(size: usize) ?[*]u8 {
    // Find the smallest size class that fits
    for (&size_caches) |*cache| {
        if (cache.object_size >= size) {
            return cache.allocObject();
        }
    }

    // Too large for slab caches — fall back to heap
    return main.heap.alloc(size);
}

/// Free memory allocated via slab_alloc
pub fn free(ptr: [*]u8, size: usize) void {
    for (&size_caches) |*cache| {
        if (cache.object_size >= size) {
            cache.freeObject(ptr);
            return;
        }
    }

    // Was allocated from heap
    main.heap.free(ptr);
}

// =============================================================================
// List management helpers
// =============================================================================
fn addToList(list: *?*Slab, slab: *Slab) void {
    slab.next = list.*;
    slab.prev = null;
    if (list.*) |head| {
        head.prev = slab;
    }
    list.* = slab;
}

fn removeFromList(list: *?*Slab, slab: *Slab) void {
    if (slab.prev) |prev| {
        prev.next = slab.next;
    } else {
        list.* = slab.next;
    }
    if (slab.next) |next| {
        next.prev = slab.prev;
    }
    slab.prev = null;
    slab.next = null;
}

fn alignUpAddr(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}
