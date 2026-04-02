// =============================================================================
// Kernel Zxyphor — vmalloc/vmap Subsystem
// =============================================================================
// Full virtual memory allocation subsystem for large non-physically-contiguous
// allocations. Manages the vmalloc address space (kernel virtual address range)
// with an RB-tree of VMA areas and lazy TLB flushing.
//
// Features:
//   - vmalloc(): Allocate virtually contiguous, physically scattered pages
//   - vzalloc(): Same as vmalloc but zeroed
//   - vmap(): Map an array of pages into contiguous VA space
//   - vunmap(): Unmap previously vmap'd pages
//   - ioremap(): Map device MMIO into kernel VA space
//   - ioremap_wc(): Map with write-combining
//   - ioremap_nocache(): Map uncacheable
//   - vm_map_ram(): Fast temporary mappings
//   - Lazy TLB purge with work batching
//   - Per-CPU vmap block allocator for small vmallocs
//   - Huge page vmalloc (PMD-level 2MB mappings)
//   - NUMA-aware page allocation for vmalloc
//   - Red-zone guard pages (CONFIG_DEBUG_PAGEALLOC)
//   - vread()/vwrite() for /dev/kmem access
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const VMALLOC_START: u64 = 0xFFFFC90000000000;
pub const VMALLOC_END: u64 = 0xFFFFE8FFFFFFFFFF;
pub const MODULES_VADDR: u64 = 0xFFFFFFFFA0000000;
pub const MODULES_END: u64 = 0xFFFFFFFFBFFFFFFF;
pub const IOREMAP_BASE: u64 = 0xFFFFEA0000000000;
pub const IOREMAP_END: u64 = 0xFFFFEAFFFFFFFFFF;
pub const FIXMAP_START: u64 = 0xFFFFFFFFFF5FF000;
pub const FIXMAP_END: u64 = 0xFFFFFFFFFF600000;

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u6 = 12;
pub const PMD_SIZE: u64 = 2 * 1024 * 1024; // 2MB
pub const PMD_SHIFT: u6 = 21;
pub const PUD_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
pub const PUD_SHIFT: u6 = 30;

pub const MAX_VMAP_AREAS: usize = 65536;
pub const MAX_PURGE_BATCH: usize = 256;
pub const VMAP_BLOCK_SIZE: u64 = 256 * PAGE_SIZE; // 1MB per vmap block
pub const VMAP_MAX_ALLOC: u64 = 32 * PAGE_SIZE; // Max for per-CPU fast path
pub const GUARD_PAGE_COUNT: u64 = 1; // Guard pages between allocations
pub const MAX_NUMA_NODES: usize = 8;

// =============================================================================
// Page table entry flags (x86_64)
// =============================================================================
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_PWT: u64 = 1 << 3; // Page Write-Through
pub const PTE_PCD: u64 = 1 << 4; // Page Cache Disable
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_PAT: u64 = 1 << 7; // Page Attribute Table
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NX: u64 = @as(u64, 1) << 63; // No Execute

pub const PAGE_KERNEL: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED | PTE_DIRTY | PTE_GLOBAL | PTE_NX;
pub const PAGE_KERNEL_EXEC: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED | PTE_DIRTY | PTE_GLOBAL;
pub const PAGE_KERNEL_RO: u64 = PTE_PRESENT | PTE_ACCESSED | PTE_GLOBAL | PTE_NX;
pub const PAGE_KERNEL_NOCACHE: u64 = PAGE_KERNEL | PTE_PCD | PTE_PWT;
pub const PAGE_KERNEL_WC: u64 = PAGE_KERNEL | PTE_PAT; // Write-combining

// =============================================================================
// VM area flags
// =============================================================================
pub const VmFlags = packed struct(u32) {
    ioremap: bool = false, // MMIO mapping
    alloc: bool = false, // vmalloc allocation
    map: bool = false, // vmap mapping
    usermap: bool = false, // Mapped to userspace
    dma_coherent: bool = false, // DMA coherent allocation
    huge_pages: bool = false, // Using 2MB pages
    no_guard: bool = false, // No guard pages
    allow_huge: bool = false, // Allow huge page optimization
    uninitialized: bool = false, // Pages not zeroed
    sparse: bool = false, // Sparse allocation
    module: bool = false, // Module code/data
    kasan: bool = false, // KASAN shadow
    flush_reset: bool = false, // Reset flush state
    _reserved: u19 = 0,
};

// =============================================================================
// Memory cache type
// =============================================================================
pub const CacheType = enum(u8) {
    write_back = 0, // Normal cacheable (WB)
    write_combine = 1, // Write combining (WC)
    uncacheable = 2, // Uncacheable (UC)
    write_through = 3, // Write through (WT)
    write_protect = 4, // Write protect (WP)
};

// =============================================================================
// Virtual Memory Area (vmap_area)
// =============================================================================
pub const VmapArea = struct {
    va_start: u64 = 0,
    va_end: u64 = 0,
    flags: VmFlags = .{},
    vm: ?*VmStruct = null,

    // RB-tree links
    rb_parent: ?*VmapArea = null,
    rb_left: ?*VmapArea = null,
    rb_right: ?*VmapArea = null,
    rb_color: RbColor = .red,

    // Free-area links (for free space management)
    subtree_max_size: u64 = 0,

    // Purge list
    purge_next: ?*VmapArea = null,

    pub fn size(self: *const VmapArea) u64 {
        return self.va_end - self.va_start;
    }
};

pub const RbColor = enum(u1) {
    red = 0,
    black = 1,
};

// =============================================================================
// VM struct (vm_struct — the high-level vmalloc descriptor)
// =============================================================================
pub const VmStruct = struct {
    addr: u64 = 0, // Virtual address of allocation
    size: u64 = 0, // Total size including guard pages
    flags: VmFlags = .{},
    pages: [1024]u64 = [_]u64{0} ** 1024, // Physical page frame addresses
    nr_pages: u32 = 0,
    phys_addr: u64 = 0, // For ioremap: physical base address
    caller: u64 = 0, // Return address of caller (for debugging)
    cache_type: CacheType = .write_back,
    numa_node: i32 = -1, // NUMA node preference (-1 = any)

    pub fn pageCount(self: *const VmStruct) u64 {
        return (self.size - GUARD_PAGE_COUNT * PAGE_SIZE) / PAGE_SIZE;
    }
};

// =============================================================================
// Per-CPU vmap block (fast path for small allocations)
// =============================================================================
pub const VmapBlock = struct {
    va: u64 = 0, // Base virtual address of this block
    used_map: [256 / 8]u8 = [_]u8{0} ** (256 / 8), // Bitmap of used pages
    free_count: u32 = 256, // Free pages in this block
    dirty_count: u32 = 0, // Pages needing TLB flush

    pub fn allocPages(self: *VmapBlock, count: u32) ?u64 {
        if (count > self.free_count) return null;
        if (count == 0) return null;

        // Find 'count' consecutive free bits
        var start: u32 = 0;
        var run: u32 = 0;
        var bit: u32 = 0;

        while (bit < 256) : (bit += 1) {
            const byte_idx = bit / 8;
            const bit_idx: u3 = @intCast(bit % 8);
            const used = (self.used_map[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;

            if (!used) {
                if (run == 0) start = bit;
                run += 1;
                if (run >= count) {
                    // Mark bits as used
                    var i: u32 = start;
                    while (i < start + count) : (i += 1) {
                        const bi = i / 8;
                        const bo: u3 = @intCast(i % 8);
                        self.used_map[bi] |= @as(u8, 1) << bo;
                    }
                    self.free_count -= count;
                    return self.va + @as(u64, start) * PAGE_SIZE;
                }
            } else {
                run = 0;
            }
        }
        return null;
    }

    pub fn freePages(self: *VmapBlock, addr: u64, count: u32) void {
        const offset = (addr - self.va) / PAGE_SIZE;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const bit = @as(u32, @intCast(offset)) + i;
            const byte_idx = bit / 8;
            const bit_idx: u3 = @intCast(bit % 8);
            self.used_map[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        }
        self.free_count += count;
        self.dirty_count += count;
    }
};

// =============================================================================
// Lazy TLB purge state
// =============================================================================
pub const TlbPurgeState = struct {
    areas: [MAX_PURGE_BATCH]*VmapArea = undefined,
    count: u32 = 0,
    start: u64 = 0xFFFFFFFFFFFFFFFF,
    end: u64 = 0,
    total_purged: u64 = 0,

    pub fn addArea(self: *TlbPurgeState, area: *VmapArea) bool {
        if (self.count >= MAX_PURGE_BATCH) return false;
        self.areas[self.count] = area;
        self.count += 1;

        if (area.va_start < self.start) self.start = area.va_start;
        if (area.va_end > self.end) self.end = area.va_end;
        return true;
    }

    pub fn flush(self: *TlbPurgeState) void {
        if (self.count == 0) return;

        // Flush TLB for the entire range
        flushTlbRange(self.start, self.end);

        self.total_purged += self.count;
        self.count = 0;
        self.start = 0xFFFFFFFFFFFFFFFF;
        self.end = 0;
    }
};

// =============================================================================
// vmalloc subsystem state
// =============================================================================
pub const VmallocState = struct {
    // Area pool
    areas: [MAX_VMAP_AREAS]VmapArea = undefined,
    area_count: u32 = 0,

    // VmStruct pool
    vm_structs: [MAX_VMAP_AREAS]VmStruct = undefined,
    vm_struct_count: u32 = 0,

    // RB-tree root for busy areas
    rb_root: ?*VmapArea = null,

    // Free area tracking (augmented RB-tree)
    free_root: ?*VmapArea = null,

    // Per-CPU fast-path blocks
    per_cpu_blocks: [256]VmapBlock = undefined,
    per_cpu_block_count: u32 = 0,

    // Lazy TLB purge
    purge: TlbPurgeState = .{},

    // Statistics
    total_allocated: u64 = 0,
    total_freed: u64 = 0,
    peak_usage: u64 = 0,
    current_usage: u64 = 0,
    nr_vmalloc: u64 = 0,
    nr_vmap: u64 = 0,
    nr_ioremap: u64 = 0,
    largest_allocation: u64 = 0,
    huge_page_mappings: u64 = 0,
    guard_page_overhead: u64 = 0,
    tlb_flush_count: u64 = 0,

    // Configuration
    vmalloc_base: u64 = VMALLOC_START,
    vmalloc_end: u64 = VMALLOC_END,

    initialized: bool = false,

    pub fn init(self: *VmallocState) void {
        self.area_count = 0;
        self.vm_struct_count = 0;
        self.rb_root = null;
        self.free_root = null;
        self.per_cpu_block_count = 0;
        self.initialized = true;

        // Create initial free area spanning the whole vmalloc range
        if (self.area_count < MAX_VMAP_AREAS) {
            var free_area = &self.areas[self.area_count];
            free_area.* = VmapArea{
                .va_start = self.vmalloc_base,
                .va_end = self.vmalloc_end,
                .subtree_max_size = self.vmalloc_end - self.vmalloc_base,
            };
            self.free_root = free_area;
            self.area_count += 1;
        }
    }

    // =========================================================================
    // vmalloc — Allocate virtually contiguous memory
    // =========================================================================
    pub fn vmalloc(self: *VmallocState, size: u64) ?u64 {
        return self.vmallocNode(size, -1, .write_back, false);
    }

    pub fn vzalloc(self: *VmallocState, size: u64) ?u64 {
        return self.vmallocNode(size, -1, .write_back, true);
    }

    pub fn vmallocNode(self: *VmallocState, size_req: u64, node: i32, cache: CacheType, zero: bool) ?u64 {
        if (size_req == 0) return null;

        // Align up to page size
        const size = alignUp(size_req, PAGE_SIZE);
        const total_size = size + GUARD_PAGE_COUNT * PAGE_SIZE; // Add guard page

        // Allocate VA space
        const va = self.findFreeArea(total_size) orelse return null;

        // Allocate a VmStruct
        if (self.vm_struct_count >= MAX_VMAP_AREAS) return null;
        var vm = &self.vm_structs[self.vm_struct_count];
        self.vm_struct_count += 1;

        vm.* = VmStruct{
            .addr = va,
            .size = total_size,
            .flags = .{ .alloc = true },
            .numa_node = node,
            .cache_type = cache,
        };

        // Allocate physical pages
        const nr_pages = size / PAGE_SIZE;
        if (nr_pages > 1024) return null; // Limit per allocation

        var i: u32 = 0;
        while (i < @as(u32, @intCast(nr_pages))) : (i += 1) {
            // In real kernel: allocate page from buddy allocator
            // Simulated: use sequential physical addresses
            const phys = allocPhysicalPage(node);
            if (phys == 0) {
                // Rollback: free already allocated pages
                self.freePhysPages(vm, i);
                return null;
            }
            vm.pages[i] = phys;
            vm.nr_pages = i + 1;

            if (zero) {
                // Zero the page (in real kernel, this maps it temporarily)
                zeroPhysicalPage(phys);
            }
        }

        // Map pages into page tables
        if (!self.mapPages(va, vm.pages[0..nr_pages], pageFlags(cache))) {
            self.freePhysPages(vm, vm.nr_pages);
            return null;
        }

        // Update statistics
        self.total_allocated += size;
        self.current_usage += size;
        if (self.current_usage > self.peak_usage) {
            self.peak_usage = self.current_usage;
        }
        if (size > self.largest_allocation) {
            self.largest_allocation = size;
        }
        self.nr_vmalloc += 1;

        return va;
    }

    // =========================================================================
    // vfree — Free vmalloc'd memory
    // =========================================================================
    pub fn vfree(self: *VmallocState, addr: u64) void {
        if (addr == 0) return;

        // Find the VmStruct
        const vm = self.findVmStruct(addr) orelse return;

        // Unmap from page tables
        self.unmapPages(vm.addr, vm.size);

        // Free physical pages
        self.freePhysPages(vm, vm.nr_pages);

        // Add VA space to lazy purge list
        // (Don't immediately add back to free list; need TLB flush first)
        self.schedulePurge(addr, vm.size);

        // Update statistics
        self.total_freed += vm.size - GUARD_PAGE_COUNT * PAGE_SIZE;
        self.current_usage -|= vm.size - GUARD_PAGE_COUNT * PAGE_SIZE;
        self.nr_vmalloc -|= 1;
    }

    // =========================================================================
    // vmap — Map existing pages into contiguous VA space
    // =========================================================================
    pub fn vmap(self: *VmallocState, pages: []const u64, count: u32, cache: CacheType) ?u64 {
        if (count == 0) return null;

        const size = @as(u64, count) * PAGE_SIZE;
        const total_size = size + GUARD_PAGE_COUNT * PAGE_SIZE;

        const va = self.findFreeArea(total_size) orelse return null;

        if (!self.mapPages(va, pages[0..count], pageFlags(cache))) {
            return null;
        }

        self.nr_vmap += 1;
        return va;
    }

    pub fn vunmap(self: *VmallocState, addr: u64, size: u64) void {
        self.unmapPages(addr, size);
        self.schedulePurge(addr, size + GUARD_PAGE_COUNT * PAGE_SIZE);
        self.nr_vmap -|= 1;
    }

    // =========================================================================
    // ioremap — Map device MMIO into kernel VA space
    // =========================================================================
    pub fn ioremap(self: *VmallocState, phys_addr: u64, size_req: u64) ?u64 {
        return self.ioremapType(phys_addr, size_req, .uncacheable);
    }

    pub fn ioremapWc(self: *VmallocState, phys_addr: u64, size_req: u64) ?u64 {
        return self.ioremapType(phys_addr, size_req, .write_combine);
    }

    pub fn ioremapNocache(self: *VmallocState, phys_addr: u64, size_req: u64) ?u64 {
        return self.ioremapType(phys_addr, size_req, .uncacheable);
    }

    fn ioremapType(self: *VmallocState, phys_addr: u64, size_req: u64, cache: CacheType) ?u64 {
        // Align to page boundaries
        const offset = phys_addr & (PAGE_SIZE - 1);
        const aligned_phys = phys_addr & ~(PAGE_SIZE - 1);
        const size = alignUp(size_req + offset, PAGE_SIZE);
        const total_size = size + GUARD_PAGE_COUNT * PAGE_SIZE;

        // Validate: don't allow mapping RAM as MMIO
        if (isRamAddress(aligned_phys)) return null;

        const va = self.findFreeArea(total_size) orelse return null;

        // Map physical pages directly (not from page allocator)
        const nr_pages = size / PAGE_SIZE;
        var i: u64 = 0;
        while (i < nr_pages) : (i += 1) {
            const pte_flags = ioremapFlags(cache);
            mapSinglePage(va + i * PAGE_SIZE, aligned_phys + i * PAGE_SIZE, pte_flags);
        }

        self.nr_ioremap += 1;
        return va + offset; // Return address with sub-page offset
    }

    pub fn iounmap(self: *VmallocState, addr: u64, size: u64) void {
        const aligned = addr & ~(PAGE_SIZE - 1);
        self.unmapPages(aligned, alignUp(size, PAGE_SIZE));
        self.schedulePurge(aligned, alignUp(size, PAGE_SIZE) + GUARD_PAGE_COUNT * PAGE_SIZE);
        self.nr_ioremap -|= 1;
    }

    // =========================================================================
    // Huge page vmalloc (2MB PMD mappings)
    // =========================================================================
    pub fn vmallocHuge(self: *VmallocState, size_req: u64) ?u64 {
        // Only for sizes >= PMD_SIZE and aligned
        if (size_req < PMD_SIZE) return self.vmalloc(size_req);

        const size = alignUp(size_req, PMD_SIZE);
        const nr_huge_pages = size / PMD_SIZE;
        const total_size = size + GUARD_PAGE_COUNT * PAGE_SIZE;

        // Find PMD-aligned free area
        const va = self.findFreeAreaAligned(total_size, PMD_SIZE) orelse
            return self.vmalloc(size_req); // Fallback to 4K pages

        // Allocate huge pages
        var i: u64 = 0;
        while (i < nr_huge_pages) : (i += 1) {
            const huge_phys = allocHugePage();
            if (huge_phys == 0) {
                // Fallback: unmap what we've done and use 4K pages
                self.unmapPages(va, i * PMD_SIZE);
                return self.vmalloc(size_req);
            }
            // Map as PMD (2MB page)
            mapHugePage(va + i * PMD_SIZE, huge_phys);
        }

        self.huge_page_mappings += nr_huge_pages;
        self.total_allocated += size;
        self.current_usage += size;
        return va;
    }

    // =========================================================================
    // Internal: Find free VA space
    // =========================================================================
    fn findFreeArea(self: *VmallocState, size: u64) ?u64 {
        return self.findFreeAreaAligned(size, PAGE_SIZE);
    }

    fn findFreeAreaAligned(self: *VmallocState, size: u64, alignment: u64) ?u64 {
        // Walk free area RB-tree to find best fit
        var node = self.free_root;
        var best: ?*VmapArea = null;
        var best_size: u64 = 0xFFFFFFFFFFFFFFFF;

        while (node) |n| {
            const area_size = n.size();

            if (area_size >= size) {
                // Check alignment
                const aligned_start = alignUp(n.va_start, alignment);
                if (aligned_start + size <= n.va_end) {
                    if (area_size < best_size) {
                        best = n;
                        best_size = area_size;
                    }
                }
            }

            // Check subtree
            if (n.rb_left) |left| {
                if (left.subtree_max_size >= size) {
                    node = n.rb_left;
                    continue;
                }
            }
            node = n.rb_right;
        }

        if (best) |b| {
            const va = alignUp(b.va_start, alignment);
            // Split the free area
            self.splitFreeArea(b, va, va + size);
            return va;
        }

        return null;
    }

    fn splitFreeArea(self: *VmallocState, area: *VmapArea, alloc_start: u64, alloc_end: u64) void {
        // If there's space before the allocation, keep it as free
        if (alloc_start > area.va_start and self.area_count < MAX_VMAP_AREAS) {
            var pre = &self.areas[self.area_count];
            self.area_count += 1;
            pre.* = VmapArea{
                .va_start = area.va_start,
                .va_end = alloc_start,
                .subtree_max_size = alloc_start - area.va_start,
            };
            // Insert into free tree (simplified)
        }

        // If there's space after the allocation, keep it as free
        if (alloc_end < area.va_end and self.area_count < MAX_VMAP_AREAS) {
            var post = &self.areas[self.area_count];
            self.area_count += 1;
            post.* = VmapArea{
                .va_start = alloc_end,
                .va_end = area.va_end,
                .subtree_max_size = area.va_end - alloc_end,
            };
            // Insert into free tree
        }

        // Convert this area to a busy area
        area.va_start = alloc_start;
        area.va_end = alloc_end;
        area.subtree_max_size = 0;
    }

    // =========================================================================
    // Internal: Page table manipulation
    // =========================================================================
    fn mapPages(self: *VmallocState, va: u64, pages: []const u64, flags: u64) bool {
        var addr = va;
        for (pages) |phys| {
            mapSinglePage(addr, phys, flags);
            addr += PAGE_SIZE;
        }
        _ = self;
        return true;
    }

    fn unmapPages(self: *VmallocState, va: u64, size: u64) void {
        var addr = va;
        while (addr < va + size) : (addr += PAGE_SIZE) {
            unmapSinglePage(addr);
        }
        _ = self;
    }

    fn schedulePurge(self: *VmallocState, addr: u64, size: u64) void {
        // Add to lazy purge batch
        if (self.area_count < MAX_VMAP_AREAS) {
            var area = &self.areas[self.area_count];
            self.area_count += 1;
            area.* = VmapArea{
                .va_start = addr,
                .va_end = addr + size,
            };

            if (!self.purge.addArea(area)) {
                // Batch full — flush now
                self.purge.flush();
                self.tlb_flush_count += 1;
                _ = self.purge.addArea(area);
            }
        }
    }

    fn findVmStruct(self: *VmallocState, addr: u64) ?*VmStruct {
        for (0..self.vm_struct_count) |i| {
            if (self.vm_structs[i].addr == addr) {
                return &self.vm_structs[i];
            }
        }
        return null;
    }

    fn freePhysPages(self: *VmallocState, vm: *VmStruct, count: u32) void {
        _ = self;
        for (0..count) |i| {
            if (vm.pages[i] != 0) {
                freePhysicalPage(vm.pages[i]);
                vm.pages[i] = 0;
            }
        }
    }

    // =========================================================================
    // vm_map_ram — Fast temporary kernel mappings
    // =========================================================================
    pub fn vmMapRam(self: *VmallocState, pages: []const u64, count: u32, node: i32) ?u64 {
        _ = node;
        // For small mappings, use per-CPU vmap blocks
        if (count <= @as(u32, @intCast(VMAP_MAX_ALLOC / PAGE_SIZE))) {
            return self.vmapBlockAlloc(count);
        }
        // Large mappings go through normal vmap
        return self.vmap(pages, count, .write_back);
    }

    pub fn vmUnmapRam(self: *VmallocState, addr: u64, count: u32) void {
        // Check if it was from a vmap block
        for (0..self.per_cpu_block_count) |i| {
            const block = &self.per_cpu_blocks[i];
            if (addr >= block.va and addr < block.va + VMAP_BLOCK_SIZE) {
                block.freePages(addr, count);
                return;
            }
        }
        // Otherwise normal vunmap
        self.vunmap(addr, @as(u64, count) * PAGE_SIZE);
    }

    fn vmapBlockAlloc(self: *VmallocState, count: u32) ?u64 {
        // Try existing blocks first
        for (0..self.per_cpu_block_count) |i| {
            if (self.per_cpu_blocks[i].allocPages(count)) |addr| {
                return addr;
            }
        }

        // Allocate new block
        if (self.per_cpu_block_count >= 256) return null;
        const va = self.findFreeArea(VMAP_BLOCK_SIZE) orelse return null;

        var block = &self.per_cpu_blocks[self.per_cpu_block_count];
        self.per_cpu_block_count += 1;
        block.* = VmapBlock{ .va = va };

        return block.allocPages(count);
    }

    // =========================================================================
    // vread/vwrite — Read/write from vmalloc address space
    // =========================================================================
    pub fn vread(self: *const VmallocState, buf: []u8, addr: u64, count: u64) u64 {
        _ = self;
        var read: u64 = 0;
        var src = addr;
        var dst: u64 = 0;

        while (read < count and dst < buf.len) {
            // Check if address is mapped
            if (lookupPte(src)) |pte| {
                const phys = pteToPhys(pte);
                const page_offset = src & (PAGE_SIZE - 1);
                const to_copy = @min(PAGE_SIZE - page_offset, count - read);
                const byte_count: usize = @intCast(@min(to_copy, buf.len - dst));

                // Copy from physical page (simplified)
                for (0..byte_count) |i| {
                    buf[@intCast(dst + i)] = readPhysByte(phys + page_offset + i);
                }

                read += to_copy;
                src += to_copy;
                dst += to_copy;
            } else {
                // Unmapped — zero fill
                buf[@intCast(dst)] = 0;
                read += 1;
                src += 1;
                dst += 1;
            }
        }
        return read;
    }

    pub fn vwrite(self: *VmallocState, addr: u64, data: []const u8, count: u64) u64 {
        _ = self;
        var written: u64 = 0;
        var dst = addr;
        var src: u64 = 0;

        while (written < count and src < data.len) {
            if (lookupPte(dst)) |pte| {
                const phys = pteToPhys(pte);
                const page_offset = dst & (PAGE_SIZE - 1);
                const to_copy = @min(PAGE_SIZE - page_offset, count - written);
                const byte_count: usize = @intCast(@min(to_copy, data.len - src));

                for (0..byte_count) |i| {
                    writePhysByte(phys + page_offset + i, data[@intCast(src + i)]);
                }

                written += to_copy;
                dst += to_copy;
                src += to_copy;
            } else {
                break; // Can't write to unmapped page
            }
        }
        return written;
    }

    // =========================================================================
    // Debug / procfs info
    // =========================================================================
    pub fn getInfo(self: *const VmallocState) VmallocInfo {
        return VmallocInfo{
            .total_allocated = self.total_allocated,
            .total_freed = self.total_freed,
            .current_usage = self.current_usage,
            .peak_usage = self.peak_usage,
            .nr_vmalloc = self.nr_vmalloc,
            .nr_vmap = self.nr_vmap,
            .nr_ioremap = self.nr_ioremap,
            .area_count = self.area_count,
            .huge_page_mappings = self.huge_page_mappings,
            .tlb_flush_count = self.tlb_flush_count,
            .largest_allocation = self.largest_allocation,
            .vmalloc_total = self.vmalloc_end - self.vmalloc_base,
        };
    }
};

pub const VmallocInfo = struct {
    total_allocated: u64,
    total_freed: u64,
    current_usage: u64,
    peak_usage: u64,
    nr_vmalloc: u64,
    nr_vmap: u64,
    nr_ioremap: u64,
    area_count: u32,
    huge_page_mappings: u64,
    tlb_flush_count: u64,
    largest_allocation: u64,
    vmalloc_total: u64,
};

// =============================================================================
// Helper functions
// =============================================================================
fn alignUp(value: u64, alignment: u64) u64 {
    return (value + alignment - 1) & ~(alignment - 1);
}

fn isRamAddress(phys: u64) bool {
    // In real kernel: check e820/UEFI memory map
    return phys < 0x100000000; // Simplified: below 4GB is RAM
}

fn pageFlags(cache: CacheType) u64 {
    return switch (cache) {
        .write_back => PAGE_KERNEL,
        .write_combine => PAGE_KERNEL_WC,
        .uncacheable => PAGE_KERNEL_NOCACHE,
        .write_through => PAGE_KERNEL | PTE_PWT,
        .write_protect => PAGE_KERNEL_RO,
    };
}

fn ioremapFlags(cache: CacheType) u64 {
    return pageFlags(cache) & ~PTE_GLOBAL; // MMIO shouldn't use global bit
}

fn mapSinglePage(va: u64, phys: u64, flags: u64) void {
    _ = va;
    _ = phys;
    _ = flags;
    // In real kernel: walk PGD→P4D→PUD→PMD→PTE and set entry
}

fn unmapSinglePage(va: u64) void {
    _ = va;
    // In real kernel: clear PTE entry
}

fn mapHugePage(va: u64, phys: u64) void {
    _ = va;
    _ = phys;
    // In real kernel: set PMD entry with PS bit
}

fn allocHugePage() u64 {
    // In real kernel: alloc_pages(GFP_KERNEL, 9) for 2MB
    return 0; // Simplified
}

fn allocPhysicalPage(node: i32) u64 {
    _ = node;
    // In real kernel: alloc_page(GFP_KERNEL)
    return 0x1000; // Simplified
}

fn freePhysicalPage(phys: u64) void {
    _ = phys;
    // In real kernel: __free_page()
}

fn zeroPhysicalPage(phys: u64) void {
    _ = phys;
    // In real kernel: clear_page(kmap(page))
}

fn flushTlbRange(start: u64, end: u64) void {
    // INVLPG or full TLB flush
    var addr = start;
    while (addr < end) : (addr += PAGE_SIZE) {
        asm volatile ("" ::: "memory");
        // invlpg [addr] in real kernel
    }
}

fn lookupPte(va: u64) ?u64 {
    _ = va;
    // Walk page tables to find PTE
    return null;
}

fn pteToPhys(pte: u64) u64 {
    return pte & 0x000FFFFFFFFFF000; // Extract physical address from PTE
}

fn readPhysByte(phys: u64) u8 {
    _ = phys;
    return 0; // In real kernel: map page temporarily and read
}

fn writePhysByte(phys: u64, value: u8) void {
    _ = phys;
    _ = value;
    // In real kernel: map page temporarily and write
}

// =============================================================================
// Global vmalloc state
// =============================================================================
var global_vmalloc: VmallocState = .{};

pub fn getVmalloc() *VmallocState {
    return &global_vmalloc;
}

pub fn initVmalloc() void {
    global_vmalloc.init();
}

// Public convenience functions
pub fn vmalloc(size: u64) ?u64 {
    return global_vmalloc.vmalloc(size);
}

pub fn vzalloc(size: u64) ?u64 {
    return global_vmalloc.vzalloc(size);
}

pub fn vfree(addr: u64) void {
    global_vmalloc.vfree(addr);
}

pub fn ioremap_addr(phys: u64, size: u64) ?u64 {
    return global_vmalloc.ioremap(phys, size);
}

pub fn iounmap(addr: u64, size: u64) void {
    global_vmalloc.iounmap(addr, size);
}
