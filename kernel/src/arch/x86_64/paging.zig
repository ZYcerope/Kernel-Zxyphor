// =============================================================================
// Kernel Zxyphor - x86_64 Paging (4-Level Page Tables)
// =============================================================================
// Implements 4-level page tables for x86_64 long mode:
//   PML4 (Page Map Level 4) → PDPT → PD → PT → Physical Page
//
// Virtual address breakdown (48-bit canonical):
//   Bits 47-39: PML4 index (9 bits = 512 entries)
//   Bits 38-30: PDPT index (9 bits = 512 entries)
//   Bits 29-21: PD index   (9 bits = 512 entries)
//   Bits 20-12: PT index   (9 bits = 512 entries)
//   Bits 11-0:  Page offset (12 bits = 4096 bytes)
//
// Page sizes supported:
//   4KB  — standard pages (PT entry)
//   2MB  — large pages (PD entry with PS bit)
//   1GB  — huge pages (PDPT entry with PS bit, if CPU supports it)
// =============================================================================

const main = @import("../../main.zig");

// =============================================================================
// Page table entry flags (common to all levels)
// =============================================================================
pub const PAGE_PRESENT: u64 = 1 << 0; // Page is mapped
pub const PAGE_WRITABLE: u64 = 1 << 1; // Page is writable
pub const PAGE_USER: u64 = 1 << 2; // Accessible from ring 3
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3; // Write-through caching
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4; // Disable caching
pub const PAGE_ACCESSED: u64 = 1 << 5; // CPU sets this on access
pub const PAGE_DIRTY: u64 = 1 << 6; // CPU sets this on write (PT only)
pub const PAGE_HUGE: u64 = 1 << 7; // 2MB (PD) or 1GB (PDPT) page
pub const PAGE_GLOBAL: u64 = 1 << 8; // Don't flush from TLB on CR3 change
pub const PAGE_NO_EXECUTE: u64 = @as(u64, 1) << 63; // No-execute (NX) bit

// Convenience flag combinations
pub const PAGE_KERNEL_RO: u64 = PAGE_PRESENT | PAGE_NO_EXECUTE;
pub const PAGE_KERNEL_RW: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE;
pub const PAGE_KERNEL_RX: u64 = PAGE_PRESENT;
pub const PAGE_KERNEL_RWX: u64 = PAGE_PRESENT | PAGE_WRITABLE;
pub const PAGE_USER_RO: u64 = PAGE_PRESENT | PAGE_USER | PAGE_NO_EXECUTE;
pub const PAGE_USER_RW: u64 = PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE | PAGE_NO_EXECUTE;
pub const PAGE_USER_RX: u64 = PAGE_PRESENT | PAGE_USER;
pub const PAGE_USER_RWX: u64 = PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
pub const PAGE_MMIO: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;

// Mask to extract the physical address from a page table entry
pub const PHYS_ADDR_MASK: u64 = 0x000FFFFFFFFFF000;

pub const PAGE_SIZE: u64 = 4096;
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024; // 2MB
pub const HUGE_PAGE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
pub const ENTRIES_PER_TABLE: usize = 512;

// Higher-half kernel base address
pub const KERNEL_VMA: u64 = 0xFFFFFFFF80000000;

// =============================================================================
// Page Table Entry
// =============================================================================
pub const PageTableEntry = packed struct {
    value: u64,

    pub fn empty() PageTableEntry {
        return .{ .value = 0 };
    }

    pub fn isPresent(self: PageTableEntry) bool {
        return (self.value & PAGE_PRESENT) != 0;
    }

    pub fn isWritable(self: PageTableEntry) bool {
        return (self.value & PAGE_WRITABLE) != 0;
    }

    pub fn isUser(self: PageTableEntry) bool {
        return (self.value & PAGE_USER) != 0;
    }

    pub fn isHuge(self: PageTableEntry) bool {
        return (self.value & PAGE_HUGE) != 0;
    }

    pub fn isAccessed(self: PageTableEntry) bool {
        return (self.value & PAGE_ACCESSED) != 0;
    }

    pub fn isDirty(self: PageTableEntry) bool {
        return (self.value & PAGE_DIRTY) != 0;
    }

    pub fn isNoExecute(self: PageTableEntry) bool {
        return (self.value & PAGE_NO_EXECUTE) != 0;
    }

    /// Extract the physical address from this entry
    pub fn physAddr(self: PageTableEntry) u64 {
        return self.value & PHYS_ADDR_MASK;
    }

    /// Get the flags portion of this entry
    pub fn flags(self: PageTableEntry) u64 {
        return self.value & ~PHYS_ADDR_MASK;
    }

    /// Create an entry with the given physical address and flags
    pub fn create(phys: u64, entry_flags: u64) PageTableEntry {
        return .{ .value = (phys & PHYS_ADDR_MASK) | entry_flags };
    }

    /// Set flags on this entry
    pub fn setFlags(self: *PageTableEntry, entry_flags: u64) void {
        self.value = (self.value & PHYS_ADDR_MASK) | entry_flags;
    }

    /// Clear this entry (unmap)
    pub fn clear(self: *PageTableEntry) void {
        self.value = 0;
    }

    /// Clear the accessed bit
    pub fn clearAccessed(self: *PageTableEntry) void {
        self.value &= ~PAGE_ACCESSED;
    }

    /// Clear the dirty bit
    pub fn clearDirty(self: *PageTableEntry) void {
        self.value &= ~PAGE_DIRTY;
    }
};

// =============================================================================
// Page Table (512 entries = 4KB = one page)
// =============================================================================
pub const PageTable = struct {
    entries: [ENTRIES_PER_TABLE]PageTableEntry,

    pub fn zero(self: *PageTable) void {
        for (&self.entries) |*entry| {
            entry.* = PageTableEntry.empty();
        }
    }
};

// =============================================================================
// Virtual address decomposition
// =============================================================================
pub fn pml4Index(virt: u64) u9 {
    return @truncate((virt >> 39) & 0x1FF);
}

pub fn pdptIndex(virt: u64) u9 {
    return @truncate((virt >> 30) & 0x1FF);
}

pub fn pdIndex(virt: u64) u9 {
    return @truncate((virt >> 21) & 0x1FF);
}

pub fn ptIndex(virt: u64) u9 {
    return @truncate((virt >> 12) & 0x1FF);
}

pub fn pageOffset(virt: u64) u12 {
    return @truncate(virt & 0xFFF);
}

/// Align an address down to the nearest page boundary
pub fn alignDown(addr: u64) u64 {
    return addr & ~@as(u64, PAGE_SIZE - 1);
}

/// Align an address up to the nearest page boundary
pub fn alignUp(addr: u64) u64 {
    return (addr + PAGE_SIZE - 1) & ~@as(u64, PAGE_SIZE - 1);
}

/// Convert a physical address to a virtual address (higher-half mapping)
pub fn physToVirt(phys: u64) u64 {
    return phys + KERNEL_VMA;
}

/// Convert a virtual address to a physical address (higher-half mapping)
pub fn virtToPhys(virt: u64) u64 {
    return virt - KERNEL_VMA;
}

// =============================================================================
// Page table walking and manipulation
// =============================================================================

/// Walk the page tables to find the PTE for a given virtual address.
/// Returns null if the mapping doesn't exist at any level.
pub fn walkPageTable(pml4_phys: u64, virt: u64) ?*PageTableEntry {
    const pml4 = @as(*PageTable, @ptrFromInt(physToVirt(pml4_phys)));
    const pml4_entry = &pml4.entries[pml4Index(virt)];
    if (!pml4_entry.isPresent()) return null;

    const pdpt = @as(*PageTable, @ptrFromInt(physToVirt(pml4_entry.physAddr())));
    const pdpt_entry = &pdpt.entries[pdptIndex(virt)];
    if (!pdpt_entry.isPresent()) return null;
    if (pdpt_entry.isHuge()) return pdpt_entry; // 1GB page

    const pd = @as(*PageTable, @ptrFromInt(physToVirt(pdpt_entry.physAddr())));
    const pd_entry = &pd.entries[pdIndex(virt)];
    if (!pd_entry.isPresent()) return null;
    if (pd_entry.isHuge()) return pd_entry; // 2MB page

    const pt = @as(*PageTable, @ptrFromInt(physToVirt(pd_entry.physAddr())));
    return &pt.entries[ptIndex(virt)];
}

/// Map a single 4KB page. Allocates intermediate page tables as needed.
pub fn mapPage(pml4_phys: u64, virt: u64, phys: u64, entry_flags: u64) !void {
    const pml4 = @as(*PageTable, @ptrFromInt(physToVirt(pml4_phys)));

    // Ensure PML4 entry exists
    var pml4_entry = &pml4.entries[pml4Index(virt)];
    if (!pml4_entry.isPresent()) {
        const new_table = try allocPageTable();
        pml4_entry.* = PageTableEntry.create(new_table, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }

    // Ensure PDPT entry exists
    const pdpt = @as(*PageTable, @ptrFromInt(physToVirt(pml4_entry.physAddr())));
    var pdpt_entry = &pdpt.entries[pdptIndex(virt)];
    if (!pdpt_entry.isPresent()) {
        const new_table = try allocPageTable();
        pdpt_entry.* = PageTableEntry.create(new_table, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }

    // Ensure PD entry exists
    const pd = @as(*PageTable, @ptrFromInt(physToVirt(pdpt_entry.physAddr())));
    var pd_entry = &pd.entries[pdIndex(virt)];
    if (!pd_entry.isPresent()) {
        const new_table = try allocPageTable();
        pd_entry.* = PageTableEntry.create(new_table, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }

    // Set the PT entry
    const pt = @as(*PageTable, @ptrFromInt(physToVirt(pd_entry.physAddr())));
    var pt_entry = &pt.entries[ptIndex(virt)];
    pt_entry.* = PageTableEntry.create(phys, entry_flags);

    // Invalidate the TLB entry for this virtual address
    main.arch.invlpg(virt);
}

/// Unmap a single 4KB page. Returns the physical address that was mapped.
pub fn unmapPage(pml4_phys: u64, virt: u64) ?u64 {
    const pte = walkPageTable(pml4_phys, virt) orelse return null;
    const phys = pte.physAddr();
    pte.clear();
    main.arch.invlpg(virt);
    return phys;
}

/// Map a contiguous range of physical memory to virtual memory
pub fn mapRange(pml4_phys: u64, virt_start: u64, phys_start: u64, size: u64, entry_flags: u64) !void {
    var offset: u64 = 0;
    while (offset < size) : (offset += PAGE_SIZE) {
        try mapPage(pml4_phys, virt_start + offset, phys_start + offset, entry_flags);
    }
}

/// Unmap a contiguous range of virtual memory
pub fn unmapRange(pml4_phys: u64, virt_start: u64, size: u64) void {
    var offset: u64 = 0;
    while (offset < size) : (offset += PAGE_SIZE) {
        _ = unmapPage(pml4_phys, virt_start + offset);
    }
}

/// Map a 2MB large page
pub fn mapLargePage(pml4_phys: u64, virt: u64, phys: u64, entry_flags: u64) !void {
    const pml4 = @as(*PageTable, @ptrFromInt(physToVirt(pml4_phys)));

    var pml4_entry = &pml4.entries[pml4Index(virt)];
    if (!pml4_entry.isPresent()) {
        const new_table = try allocPageTable();
        pml4_entry.* = PageTableEntry.create(new_table, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }

    const pdpt = @as(*PageTable, @ptrFromInt(physToVirt(pml4_entry.physAddr())));
    var pdpt_entry = &pdpt.entries[pdptIndex(virt)];
    if (!pdpt_entry.isPresent()) {
        const new_table = try allocPageTable();
        pdpt_entry.* = PageTableEntry.create(new_table, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    }

    const pd = @as(*PageTable, @ptrFromInt(physToVirt(pdpt_entry.physAddr())));
    var pd_entry = &pd.entries[pdIndex(virt)];
    pd_entry.* = PageTableEntry.create(phys, entry_flags | PAGE_HUGE);

    main.arch.invlpg(virt);
}

// =============================================================================
// Page table allocation helper
// =============================================================================
fn allocPageTable() !u64 {
    const phys = main.pmm.allocFrame() orelse return error.OutOfMemory;

    // Zero the new page table
    const virt = @as(*PageTable, @ptrFromInt(physToVirt(phys)));
    virt.zero();

    return phys;
}

/// Free a page table and all its sub-tables recursively (for process cleanup)
pub fn freePageTableRecursive(pml4_phys: u64, user_only: bool) void {
    const pml4 = @as(*PageTable, @ptrFromInt(physToVirt(pml4_phys)));

    // Only free user-space entries (indices 0-255) if user_only is set
    const start_idx: usize = 0;
    const end_idx: usize = if (user_only) 256 else 512;

    for (start_idx..end_idx) |i| {
        const pml4_entry = pml4.entries[i];
        if (!pml4_entry.isPresent()) continue;
        if (pml4_entry.isHuge()) continue; // shouldn't happen at PML4 level

        const pdpt = @as(*PageTable, @ptrFromInt(physToVirt(pml4_entry.physAddr())));
        for (0..512) |j| {
            const pdpt_entry = pdpt.entries[j];
            if (!pdpt_entry.isPresent()) continue;
            if (pdpt_entry.isHuge()) continue; // 1GB page — don't recurse

            const pd = @as(*PageTable, @ptrFromInt(physToVirt(pdpt_entry.physAddr())));
            for (0..512) |k| {
                const pd_entry = pd.entries[k];
                if (!pd_entry.isPresent()) continue;
                if (pd_entry.isHuge()) continue; // 2MB page — don't recurse

                // Free the PT
                main.pmm.freeFrame(pd_entry.physAddr());
            }
            // Free the PD
            main.pmm.freeFrame(pdpt_entry.physAddr());
        }
        // Free the PDPT
        main.pmm.freeFrame(pml4_entry.physAddr());
    }

    if (!user_only) {
        main.pmm.freeFrame(pml4_phys);
    }
}
