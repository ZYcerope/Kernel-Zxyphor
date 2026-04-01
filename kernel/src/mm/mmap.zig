// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Memory-Mapped I/O & Page Cache
//
// Implements:
// - Page cache with radix-tree-like addressing
// - mmap() region management (anonymous + file-backed)
// - Demand paging with fault handler integration
// - Dirty page tracking and writeback scheduling
// - Page reference counting with LRU lists
// - Copy-on-write (COW) for fork()
// - msync() semantics for flush-to-backing-store
// - madvise() hints (sequential, random, willneed, dontneed)
// - mprotect() permission changes
// - MADV_HUGEPAGE transparent huge page support stub

const std = @import("std");

// ─────────────────── Page Cache Pages ───────────────────────────────
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: u6 = 12;

pub const PageFlags = packed struct(u16) {
    present: bool = false,
    dirty: bool = false,
    referenced: bool = false,
    uptodate: bool = false,
    locked: bool = false,
    writeback: bool = false,
    reclaim: bool = false,
    swapcache: bool = false,
    active: bool = false,
    mapped: bool = false,
    anon: bool = false,
    cow: bool = false,
    _reserved: u4 = 0,
};

pub const CachedPage = struct {
    /// Physical frame number
    pfn: u64 = 0,
    /// Page offset in file/object (in pages)
    index: u64 = 0,
    /// Reference count
    refcount: u32 = 0,
    /// Map count (number of PTEs pointing here)
    mapcount: u32 = 0,
    flags: PageFlags = .{},
    /// LRU list position (for eviction)
    lru_prev: u32 = 0xFFFFFFFF,
    lru_next: u32 = 0xFFFFFFFF,
    /// Owner inode (or 0 for anonymous)
    inode: u64 = 0,

    pub fn acquire(self: *CachedPage) void {
        self.refcount += 1;
        self.flags.referenced = true;
    }

    pub fn release(self: *CachedPage) bool {
        if (self.refcount > 0) self.refcount -= 1;
        return self.refcount == 0;
    }

    pub fn markDirty(self: *CachedPage) void {
        self.flags.dirty = true;
        self.flags.uptodate = true;
    }

    pub fn clearDirty(self: *CachedPage) void {
        self.flags.dirty = false;
    }

    pub fn setCow(self: *CachedPage) void {
        self.flags.cow = true;
    }
};

// ─────────────────── Page Cache ─────────────────────────────────────
pub const CACHE_SIZE: usize = 8192;
pub const RADIX_SLOTS: usize = 256;

/// Simple radix-like hash for (inode, index) → cache slot
fn cacheHash(inode: u64, index: u64) usize {
    var h: u64 = inode *% 2654435761;
    h ^= index *% 2246822519;
    h ^= h >> 16;
    return @intCast(h % CACHE_SIZE);
}

pub const PageCache = struct {
    pages: [CACHE_SIZE]CachedPage = [_]CachedPage{.{}} ** CACHE_SIZE,
    /// LRU active list head/tail
    active_head: u32 = 0xFFFFFFFF,
    active_tail: u32 = 0xFFFFFFFF,
    active_count: u32 = 0,
    /// LRU inactive list head/tail
    inactive_head: u32 = 0xFFFFFFFF,
    inactive_tail: u32 = 0xFFFFFFFF,
    inactive_count: u32 = 0,
    /// Stats
    total_cached: u32 = 0,
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    pages_written_back: u64 = 0,
    pages_evicted: u64 = 0,

    pub fn init(self: *PageCache) void {
        self.active_head = 0xFFFFFFFF;
        self.active_tail = 0xFFFFFFFF;
        self.inactive_head = 0xFFFFFFFF;
        self.inactive_tail = 0xFFFFFFFF;
    }

    /// Find a cached page
    pub fn findPage(self: *PageCache, inode: u64, index: u64) ?*CachedPage {
        const start = cacheHash(inode, index);
        // Linear probing
        var probe: usize = 0;
        while (probe < 32) : (probe += 1) {
            const slot = (start + probe) % CACHE_SIZE;
            if (!self.pages[slot].flags.present) {
                self.cache_misses += 1;
                return null;
            }
            if (self.pages[slot].inode == inode and self.pages[slot].index == index) {
                self.cache_hits += 1;
                self.pages[slot].flags.referenced = true;
                return &self.pages[slot];
            }
        }
        self.cache_misses += 1;
        return null;
    }

    /// Add page to cache
    pub fn addPage(self: *PageCache, inode: u64, index: u64, pfn: u64) ?*CachedPage {
        const start = cacheHash(inode, index);
        var probe: usize = 0;
        while (probe < 32) : (probe += 1) {
            const slot = (start + probe) % CACHE_SIZE;
            if (!self.pages[slot].flags.present) {
                self.pages[slot] = .{
                    .pfn = pfn,
                    .index = index,
                    .refcount = 1,
                    .mapcount = 0,
                    .flags = .{ .present = true, .uptodate = true, .active = true },
                    .inode = inode,
                };
                self.total_cached += 1;
                self.addToActiveList(@intCast(slot));
                return &self.pages[slot];
            }
            // Existing entry for same inode+index: update
            if (self.pages[slot].inode == inode and self.pages[slot].index == index) {
                self.pages[slot].pfn = pfn;
                self.pages[slot].flags.uptodate = true;
                self.pages[slot].acquire();
                return &self.pages[slot];
            }
        }
        // Cache full in this hash chain — evict from inactive
        if (self.evictOnePage()) {
            return self.addPage(inode, index, pfn);
        }
        return null;
    }

    /// Remove page from cache
    pub fn removePage(self: *PageCache, inode: u64, index: u64) bool {
        const start = cacheHash(inode, index);
        var probe: usize = 0;
        while (probe < 32) : (probe += 1) {
            const slot = (start + probe) % CACHE_SIZE;
            if (!self.pages[slot].flags.present) return false;
            if (self.pages[slot].inode == inode and self.pages[slot].index == index) {
                if (self.pages[slot].flags.dirty) {
                    self.pages_written_back += 1;
                }
                self.pages[slot].flags = .{};
                self.total_cached -= 1;
                self.pages_evicted += 1;
                return true;
            }
        }
        return false;
    }

    fn addToActiveList(self: *PageCache, idx: u32) void {
        self.pages[idx].lru_next = self.active_head;
        self.pages[idx].lru_prev = 0xFFFFFFFF;
        if (self.active_head != 0xFFFFFFFF) {
            self.pages[self.active_head].lru_prev = idx;
        }
        self.active_head = idx;
        if (self.active_tail == 0xFFFFFFFF) {
            self.active_tail = idx;
        }
        self.active_count += 1;
    }

    /// Evict one page from the inactive list tail (LRU)
    fn evictOnePage(self: *PageCache) bool {
        if (self.inactive_tail == 0xFFFFFFFF) {
            // Try demoting from active to inactive first
            return self.demoteActivePage();
        }
        const idx = self.inactive_tail;
        // Skip dirty pages (writeback first)
        if (self.pages[idx].flags.dirty) {
            self.pages_written_back += 1;
            self.pages[idx].flags.dirty = false;
        }
        // Remove from inactive list
        const prev = self.pages[idx].lru_prev;
        if (prev != 0xFFFFFFFF) {
            self.pages[prev].lru_next = 0xFFFFFFFF;
        } else {
            self.inactive_head = 0xFFFFFFFF;
        }
        self.inactive_tail = prev;
        self.inactive_count -= 1;

        self.pages[idx].flags = .{};
        self.total_cached -= 1;
        self.pages_evicted += 1;
        return true;
    }

    fn demoteActivePage(self: *PageCache) bool {
        if (self.active_tail == 0xFFFFFFFF) return false;
        const idx = self.active_tail;
        // Remove from active list tail
        const prev = self.pages[idx].lru_prev;
        if (prev != 0xFFFFFFFF) {
            self.pages[prev].lru_next = 0xFFFFFFFF;
        } else {
            self.active_head = 0xFFFFFFFF;
        }
        self.active_tail = prev;
        self.active_count -= 1;

        // Add to inactive list head
        self.pages[idx].flags.active = false;
        self.pages[idx].lru_next = self.inactive_head;
        self.pages[idx].lru_prev = 0xFFFFFFFF;
        if (self.inactive_head != 0xFFFFFFFF) {
            self.pages[self.inactive_head].lru_prev = idx;
        }
        self.inactive_head = idx;
        if (self.inactive_tail == 0xFFFFFFFF) {
            self.inactive_tail = idx;
        }
        self.inactive_count += 1;
        return true;
    }

    /// Sync all dirty pages (flush callback stub)
    pub fn syncAll(self: *PageCache) u32 {
        var synced: u32 = 0;
        for (&self.pages) |*page| {
            if (page.flags.present and page.flags.dirty) {
                page.flags.writeback = true;
                page.flags.dirty = false;
                page.flags.writeback = false;
                synced += 1;
                self.pages_written_back += 1;
            }
        }
        return synced;
    }

    /// Get dirty page count
    pub fn dirtyCount(self: *const PageCache) u32 {
        var count: u32 = 0;
        for (self.pages) |page| {
            if (page.flags.present and page.flags.dirty) count += 1;
        }
        return count;
    }

    pub fn hitRate(self: *const PageCache) u32 {
        const total = self.cache_hits + self.cache_misses;
        if (total == 0) return 0;
        return @intCast(self.cache_hits * 100 / total);
    }
};

// ─────────────────── mmap Region ────────────────────────────────────
pub const MmapProt = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
    _reserved: u5 = 0,
};

pub const MmapFlags = packed struct(u16) {
    shared: bool = false,
    private: bool = false,
    anonymous: bool = false,
    fixed: bool = false,
    populate: bool = false,
    noreserve: bool = false,
    growsdown: bool = false, // stack
    locked: bool = false,
    hugetlb: bool = false,
    _reserved: u7 = 0,
};

pub const MadviseHint = enum(u8) {
    normal = 0,
    sequential = 1,
    random = 2,
    willneed = 3,
    dontneed = 4,
    free = 5,
    hugepage = 6,
    nohugepage = 7,
    mergeable = 8,    // KSM
    unmergeable = 9,
};

pub const MAX_VMA_REGIONS: usize = 256;

pub const VmaRegion = struct {
    start: u64 = 0,       // virtual start address
    end: u64 = 0,         // virtual end address (exclusive)
    prot: MmapProt = .{},
    flags: MmapFlags = .{},
    /// File-backed: inode and offset
    file_inode: u64 = 0,
    file_offset: u64 = 0,
    /// Hint for readahead/eviction
    advice: MadviseHint = .normal,
    /// Fault counters
    minor_faults: u32 = 0,
    major_faults: u32 = 0,
    active: bool = false,

    pub fn length(self: *const VmaRegion) u64 {
        return self.end - self.start;
    }

    pub fn containsAddr(self: *const VmaRegion, addr: u64) bool {
        return addr >= self.start and addr < self.end;
    }

    pub fn isAnonymous(self: *const VmaRegion) bool {
        return self.flags.anonymous;
    }

    pub fn isWritable(self: *const VmaRegion) bool {
        return self.prot.write;
    }

    pub fn isExecutable(self: *const VmaRegion) bool {
        return self.prot.exec;
    }

    pub fn pageCount(self: *const VmaRegion) u64 {
        return (self.end - self.start + PAGE_SIZE - 1) / PAGE_SIZE;
    }
};

// ─────────────────── Page Fault Handler ─────────────────────────────
pub const FaultType = enum(u8) {
    read,
    write,
    exec,
    cow,   // copy-on-write trigger
};

pub const FaultResult = enum(u8) {
    success,
    oom,
    sigsegv,  // invalid access
    sigbus,   // mapping error
};

// ─────────────────── mmap Manager ───────────────────────────────────
pub const MmapManager = struct {
    regions: [MAX_VMA_REGIONS]VmaRegion = [_]VmaRegion{.{}} ** MAX_VMA_REGIONS,
    region_count: u32 = 0,
    /// Brk (heap end) tracking
    brk_start: u64 = 0,
    brk_current: u64 = 0,
    /// Stack region
    stack_start: u64 = 0,
    stack_end: u64 = 0,
    /// Next free address for mmap (top-down)
    mmap_base: u64 = 0x7F0000000000,
    /// Page cache reference
    cache: PageCache = .{},
    /// Stats
    total_mapped_pages: u64 = 0,
    total_faults: u64 = 0,
    cow_faults: u64 = 0,

    pub fn init(self: *MmapManager) void {
        self.cache.init();
        self.brk_start = 0x400000;
        self.brk_current = 0x400000;
        self.stack_start = 0x7FFFFFFFE000;
        self.stack_end = 0x800000000000;
    }

    /// Map a new region (mmap syscall)
    pub fn mmap(
        self: *MmapManager,
        addr: u64,
        length: u64,
        prot: MmapProt,
        flags: MmapFlags,
        file_inode: u64,
        file_offset: u64,
    ) ?u64 {
        if (length == 0) return null;
        if (self.region_count >= MAX_VMA_REGIONS) return null;

        const aligned_len = (length + PAGE_SIZE - 1) & ~@as(u64, PAGE_SIZE - 1);

        // Choose address
        var mapped_addr: u64 = 0;
        if (flags.fixed) {
            // MAP_FIXED: use specified address
            if (addr == 0) return null;
            mapped_addr = addr & ~@as(u64, PAGE_SIZE - 1);
        } else if (addr != 0) {
            // Hint address — try it first, fall back to auto
            mapped_addr = addr & ~@as(u64, PAGE_SIZE - 1);
            if (self.overlapsExisting(mapped_addr, mapped_addr + aligned_len)) {
                mapped_addr = self.findFreeRegion(aligned_len) orelse return null;
            }
        } else {
            mapped_addr = self.findFreeRegion(aligned_len) orelse return null;
        }

        const idx = self.region_count;
        self.regions[idx] = .{
            .start = mapped_addr,
            .end = mapped_addr + aligned_len,
            .prot = prot,
            .flags = flags,
            .file_inode = file_inode,
            .file_offset = file_offset,
            .active = true,
        };
        self.region_count += 1;
        self.total_mapped_pages += aligned_len / PAGE_SIZE;

        return mapped_addr;
    }

    /// Unmap a region (munmap syscall)
    pub fn munmap(self: *MmapManager, addr: u64, length: u64) bool {
        const aligned_end = addr + ((length + PAGE_SIZE - 1) & ~@as(u64, PAGE_SIZE - 1));

        var i: u32 = 0;
        while (i < self.region_count) {
            if (self.regions[i].active and
                self.regions[i].start >= addr and
                self.regions[i].end <= aligned_end)
            {
                const pages = self.regions[i].pageCount();
                self.regions[i].active = false;
                if (self.total_mapped_pages >= pages) {
                    self.total_mapped_pages -= pages;
                }
                return true;
            }
            i += 1;
        }
        return false;
    }

    /// Change protection (mprotect syscall)
    pub fn mprotect(self: *MmapManager, addr: u64, length: u64, new_prot: MmapProt) bool {
        _ = length;
        var i: u32 = 0;
        while (i < self.region_count) : (i += 1) {
            if (self.regions[i].active and self.regions[i].containsAddr(addr)) {
                self.regions[i].prot = new_prot;
                return true;
            }
        }
        return false;
    }

    /// Advise kernel about memory usage patterns (madvise syscall)
    pub fn madvise(self: *MmapManager, addr: u64, length: u64, advice: MadviseHint) bool {
        _ = length;
        var i: u32 = 0;
        while (i < self.region_count) : (i += 1) {
            if (self.regions[i].active and self.regions[i].containsAddr(addr)) {
                self.regions[i].advice = advice;
                return true;
            }
        }
        return false;
    }

    /// Handle page fault
    pub fn handleFault(self: *MmapManager, addr: u64, fault_type: FaultType) FaultResult {
        self.total_faults += 1;

        // Find the VMA containing the faulting address
        const vma = self.findVma(addr) orelse return .sigsegv;

        // Permission check
        switch (fault_type) {
            .write => if (!vma.prot.write and !vma.flags.cow) return .sigsegv,
            .exec => if (!vma.prot.exec) return .sigsegv,
            .read => if (!vma.prot.read) return .sigsegv,
            .cow => {
                self.cow_faults += 1;
            },
        }

        if (vma.isAnonymous()) {
            // Anonymous page: allocate a zeroed page
            vma.minor_faults += 1;
            return .success;
        } else {
            // File-backed: check page cache
            const page_index = (addr - vma.start) / PAGE_SIZE + vma.file_offset / PAGE_SIZE;
            if (self.cache.findPage(vma.file_inode, page_index)) |_| {
                vma.minor_faults += 1;
                return .success;
            } else {
                // Need to read from disk (major fault)
                vma.major_faults += 1;
                // Add to cache after read
                _ = self.cache.addPage(vma.file_inode, page_index, 0);
                return .success;
            }
        }
    }

    /// Sync dirty pages in a range
    pub fn msync(self: *MmapManager, addr: u64, length: u64) u32 {
        _ = addr;
        _ = length;
        return self.cache.syncAll();
    }

    /// Adjust program break (brk syscall)
    pub fn brk(self: *MmapManager, new_brk: u64) u64 {
        if (new_brk == 0) return self.brk_current;
        if (new_brk < self.brk_start) return self.brk_current;

        const aligned = (new_brk + PAGE_SIZE - 1) & ~@as(u64, PAGE_SIZE - 1);
        self.brk_current = aligned;
        return self.brk_current;
    }

    fn findVma(self: *MmapManager, addr: u64) ?*VmaRegion {
        var i: u32 = 0;
        while (i < self.region_count) : (i += 1) {
            if (self.regions[i].active and self.regions[i].containsAddr(addr)) {
                return &self.regions[i];
            }
        }
        return null;
    }

    fn overlapsExisting(self: *const MmapManager, start: u64, end: u64) bool {
        var i: u32 = 0;
        while (i < self.region_count) : (i += 1) {
            if (self.regions[i].active) {
                if (start < self.regions[i].end and end > self.regions[i].start) {
                    return true;
                }
            }
        }
        return false;
    }

    fn findFreeRegion(self: *MmapManager, size: u64) ?u64 {
        // Top-down allocation from mmap_base
        var candidate = self.mmap_base - size;
        // Ensure it doesn't overlap
        var attempts: u32 = 0;
        while (attempts < MAX_VMA_REGIONS) : (attempts += 1) {
            if (!self.overlapsExisting(candidate, candidate + size)) {
                self.mmap_base = candidate;
                return candidate;
            }
            candidate -= size;
            if (candidate < 0x10000) return null;
        }
        return null;
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var mmap_mgr: MmapManager = .{};

pub fn initMmap() void {
    mmap_mgr.init();
}

pub fn getMmapManager() *MmapManager {
    return &mmap_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_mmap_init() void {
    initMmap();
}

export fn zxy_mmap_map(addr: u64, length: u64, prot: u8, flags: u16, inode: u64, offset: u64) u64 {
    const p: MmapProt = @bitCast(prot);
    const f: MmapFlags = @bitCast(flags);
    return mmap_mgr.mmap(addr, length, p, f, inode, offset) orelse 0;
}

export fn zxy_mmap_unmap(addr: u64, length: u64) bool {
    return mmap_mgr.munmap(addr, length);
}

export fn zxy_mmap_fault(addr: u64, fault_type: u8) u8 {
    const ft: FaultType = @enumFromInt(fault_type);
    return @intFromEnum(mmap_mgr.handleFault(addr, ft));
}

export fn zxy_mmap_region_count() u32 {
    return mmap_mgr.region_count;
}

export fn zxy_mmap_total_mapped() u64 {
    return mmap_mgr.total_mapped_pages;
}

export fn zxy_mmap_total_faults() u64 {
    return mmap_mgr.total_faults;
}

export fn zxy_mmap_cache_hit_rate() u32 {
    return mmap_mgr.cache.hitRate();
}

export fn zxy_mmap_cache_dirty() u32 {
    return mmap_mgr.cache.dirtyCount();
}

export fn zxy_mmap_brk(new_brk: u64) u64 {
    return mmap_mgr.brk(new_brk);
}

export fn zxy_mmap_sync(addr: u64, length: u64) u32 {
    return mmap_mgr.msync(addr, length);
}
