// =============================================================================
// Kernel Zxyphor - Page Frame Management
// =============================================================================
// Higher-level page management that sits between the VMM and PMM. Provides
// reference counting for shared pages (copy-on-write), page aging for
// potential future swap support, and page flags tracking.
// =============================================================================

const main = @import("../main.zig");
const paging = @import("../arch/x86_64/paging.zig");

// =============================================================================
// Page descriptor — metadata tracked per physical page frame
// =============================================================================
pub const PageDescriptor = struct {
    ref_count: u32, // Number of references to this page
    flags: PageFlags,
    order: u8, // Buddy allocator order (for future use)
    age: u8, // Page age (for LRU approximation)
    mapping: ?*anyopaque, // Back-pointer to VMA or address space
};

pub const PageFlags = packed struct {
    present: bool = false,
    locked: bool = false, // Page is pinned in memory (can't be swapped)
    dirty: bool = false, // Page has been modified
    referenced: bool = false, // Page was recently accessed
    slab: bool = false, // Page is used by slab allocator
    reserved: bool = false, // Page is reserved by hardware
    compound: bool = false, // Part of a compound (huge) page
    private: bool = false, // Page is privately mapped (not shared)
};

// =============================================================================
// Page descriptor array — one entry per physical frame
// =============================================================================
const MAX_PAGES: usize = 4 * 1024 * 1024; // 4M pages = 16GB max
var page_descriptors: [MAX_PAGES]PageDescriptor = [_]PageDescriptor{
    PageDescriptor{
        .ref_count = 0,
        .flags = PageFlags{},
        .order = 0,
        .age = 0,
        .mapping = null,
    },
} ** MAX_PAGES;

// =============================================================================
// Get the page descriptor for a physical address
// =============================================================================
pub fn getDescriptor(phys_addr: u64) ?*PageDescriptor {
    const idx = @as(usize, @truncate(phys_addr / paging.PAGE_SIZE));
    if (idx >= MAX_PAGES) return null;
    return &page_descriptors[idx];
}

// =============================================================================
// Reference counting
// =============================================================================

/// Increment the reference count for a physical page
pub fn getPage(phys_addr: u64) void {
    if (getDescriptor(phys_addr)) |desc| {
        desc.ref_count += 1;
    }
}

/// Decrement the reference count. Returns true if the page should be freed.
pub fn putPage(phys_addr: u64) bool {
    if (getDescriptor(phys_addr)) |desc| {
        if (desc.ref_count > 0) {
            desc.ref_count -= 1;
            if (desc.ref_count == 0) {
                desc.flags = PageFlags{};
                desc.mapping = null;
                return true;
            }
        }
    }
    return false;
}

/// Get the current reference count for a page
pub fn refCount(phys_addr: u64) u32 {
    if (getDescriptor(phys_addr)) |desc| {
        return desc.ref_count;
    }
    return 0;
}

// =============================================================================
// Page flags management
// =============================================================================

pub fn setLocked(phys_addr: u64, locked: bool) void {
    if (getDescriptor(phys_addr)) |desc| {
        desc.flags.locked = locked;
    }
}

pub fn isLocked(phys_addr: u64) bool {
    if (getDescriptor(phys_addr)) |desc| {
        return desc.flags.locked;
    }
    return false;
}

pub fn setDirty(phys_addr: u64, dirty: bool) void {
    if (getDescriptor(phys_addr)) |desc| {
        desc.flags.dirty = dirty;
    }
}

pub fn isDirty(phys_addr: u64) bool {
    if (getDescriptor(phys_addr)) |desc| {
        return desc.flags.dirty;
    }
    return false;
}

pub fn setReferenced(phys_addr: u64, referenced: bool) void {
    if (getDescriptor(phys_addr)) |desc| {
        desc.flags.referenced = referenced;
    }
}

pub fn isReferenced(phys_addr: u64) bool {
    if (getDescriptor(phys_addr)) |desc| {
        return desc.flags.referenced;
    }
    return false;
}

// =============================================================================
// Page aging (for LRU approximation — future swap support)
// =============================================================================

/// Age all pages (called periodically by the kernel)
pub fn ageAllPages() void {
    for (&page_descriptors) |*desc| {
        if (desc.ref_count > 0 and !desc.flags.locked) {
            if (desc.flags.referenced) {
                // Recently accessed — reset age
                desc.age = 0;
                desc.flags.referenced = false;
            } else {
                // Not accessed — increase age
                if (desc.age < 255) {
                    desc.age += 1;
                }
            }
        }
    }
}

/// Find the oldest (least recently used) non-locked page
pub fn findOldestPage() ?u64 {
    var oldest_age: u8 = 0;
    var oldest_idx: ?usize = null;

    for (page_descriptors, 0..) |desc, i| {
        if (desc.ref_count > 0 and !desc.flags.locked and desc.age > oldest_age) {
            oldest_age = desc.age;
            oldest_idx = i;
        }
    }

    if (oldest_idx) |idx| {
        return @as(u64, idx) * paging.PAGE_SIZE;
    }
    return null;
}

// =============================================================================
// Copy-on-Write support
// =============================================================================

/// Mark a page for copy-on-write (set read-only, keep shared)
pub fn markCow(pml4_phys: u64, virt_addr: u64) void {
    if (paging.walkPageTable(pml4_phys, virt_addr)) |pte| {
        // Remove writable flag but keep the page present
        const new_flags = (pte.flags() & ~paging.PAGE_WRITABLE) | paging.PAGE_PRESENT;
        pte.setFlags(new_flags);
        main.arch.invlpg(virt_addr);
    }
}

/// Handle a COW fault: copy the page and make the copy writable
pub fn handleCowFault(pml4_phys: u64, virt_addr: u64) bool {
    const pte = paging.walkPageTable(pml4_phys, virt_addr) orelse return false;
    const old_phys = pte.physAddr();

    if (refCount(old_phys) <= 1) {
        // Only one reference — just make it writable again
        pte.setFlags(pte.flags() | paging.PAGE_WRITABLE);
        main.arch.invlpg(virt_addr);
        return true;
    }

    // Multiple references — need to copy
    const new_phys = main.pmm.allocFrame() orelse return false;

    // Copy the page contents
    const src = @as([*]const u8, @ptrFromInt(@as(usize, @truncate(paging.physToVirt(old_phys)))));
    const dst = @as([*]u8, @ptrFromInt(@as(usize, @truncate(paging.physToVirt(new_phys)))));
    @memcpy(dst[0..4096], src[0..4096]);

    // Update the PTE to point to the new copy
    pte.* = paging.PageTableEntry.create(new_phys, (pte.flags() | paging.PAGE_WRITABLE));
    main.arch.invlpg(virt_addr);

    // Decrease reference count on the old page
    _ = putPage(old_phys);

    // Initialize the new page's descriptor
    getPage(new_phys);

    return true;
}
