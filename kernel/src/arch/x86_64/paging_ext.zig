// =============================================================================
// Kernel Zxyphor — Advanced x86_64 Paging & TLB Management
// =============================================================================
// Extends the base paging system with advanced features:
// - PCID (Process Context Identifiers) for TLB tagging
// - 5-level paging (LA57) support for 57-bit virtual addresses
// - Large page (2MB/1GB) management
// - Page table walker for debugging
// - Copy-on-Write (COW) page fault handling
// - Demand paging infrastructure
// - KPTI (Kernel Page Table Isolation) support
// =============================================================================

const std = @import("std");

// =============================================================================
// Page Table Entry Flags — Complete x86_64 flag definitions
// =============================================================================
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7; // PS bit — 2MB in PD, 1GB in PDPT
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_PAT: u64 = 1 << 7; // PAT bit for 4KB pages (bit 7 of PTE)
pub const PTE_PAT_LARGE: u64 = 1 << 12; // PAT bit for large pages
pub const PTE_NO_EXECUTE: u64 = 1 << 63;

// Software-defined bits (available for OS use: bits 9-11, 52-62)
pub const PTE_COW: u64 = 1 << 9; // Copy-on-Write marker
pub const PTE_DEMAND: u64 = 1 << 10; // Demand-paged (not yet allocated)
pub const PTE_SWAPPED: u64 = 1 << 11; // Page is swapped out
pub const PTE_PINNED: u64 = 1 << 52; // Pinned in memory (no swap)
pub const PTE_SHARED: u64 = 1 << 53; // Shared memory page
pub const PTE_FILE_BACKED: u64 = 1 << 54; // File-backed mapping
pub const PTE_ANONYMOUS: u64 = 1 << 55; // Anonymous mapping

pub const PTE_ADDR_MASK: u64 = 0x000FFFFFFFFFF000; // Bits 12-51

// =============================================================================
// Page Sizes and Constants
// =============================================================================
pub const PAGE_SIZE_4K: u64 = 4096;
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;
pub const ENTRIES_PER_TABLE: usize = 512;
pub const TABLE_SIZE: usize = 4096;

// Virtual address space layout (4-level paging, 48-bit)
pub const USER_SPACE_START: u64 = 0x0000_0000_0000_0000;
pub const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
pub const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_SPACE_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// Kernel sub-regions within the higher half
pub const KERNEL_DIRECT_MAP_BASE: u64 = 0xFFFF_8880_0000_0000; // Direct map of all physical memory
pub const KERNEL_DIRECT_MAP_SIZE: u64 = 64 * 1024 * 1024 * 1024; // 64GB direct map
pub const KERNEL_VMALLOC_BASE: u64 = 0xFFFF_C900_0000_0000; // vmalloc area
pub const KERNEL_VMALLOC_SIZE: u64 = 32 * 1024 * 1024 * 1024; // 32GB vmalloc space
pub const KERNEL_MODULES_BASE: u64 = 0xFFFF_FFFF_0000_0000; // Kernel modules
pub const KERNEL_MODULES_SIZE: u64 = 1024 * 1024 * 1024; // 1GB for modules
pub const KERNEL_IMAGE_BASE: u64 = 0xFFFF_FFFF_8000_0000; // Kernel image (higher half)
pub const KERNEL_FIXMAP_BASE: u64 = 0xFFFF_FFFF_FF00_0000; // Fix-mapped addresses
pub const KERNEL_PERCPU_BASE: u64 = 0xFFFF_FE00_0000_0000; // Per-CPU data area

// Max PCID value (12-bit)
pub const MAX_PCID: u16 = 4095;

// =============================================================================
// Page Table Entry Abstraction
// =============================================================================
pub const PageTableEntry = packed struct {
    value: u64,

    pub const empty = PageTableEntry{ .value = 0 };

    pub fn isPresent(self: PageTableEntry) bool {
        return (self.value & PTE_PRESENT) != 0;
    }

    pub fn isWritable(self: PageTableEntry) bool {
        return (self.value & PTE_WRITABLE) != 0;
    }

    pub fn isUserAccessible(self: PageTableEntry) bool {
        return (self.value & PTE_USER) != 0;
    }

    pub fn isHuge(self: PageTableEntry) bool {
        return (self.value & PTE_HUGE) != 0;
    }

    pub fn isGlobal(self: PageTableEntry) bool {
        return (self.value & PTE_GLOBAL) != 0;
    }

    pub fn isAccessed(self: PageTableEntry) bool {
        return (self.value & PTE_ACCESSED) != 0;
    }

    pub fn isDirty(self: PageTableEntry) bool {
        return (self.value & PTE_DIRTY) != 0;
    }

    pub fn isNoExecute(self: PageTableEntry) bool {
        return (self.value & PTE_NO_EXECUTE) != 0;
    }

    pub fn isCow(self: PageTableEntry) bool {
        return (self.value & PTE_COW) != 0;
    }

    pub fn isDemand(self: PageTableEntry) bool {
        return (self.value & PTE_DEMAND) != 0;
    }

    pub fn isSwapped(self: PageTableEntry) bool {
        return (self.value & PTE_SWAPPED) != 0;
    }

    pub fn getAddress(self: PageTableEntry) u64 {
        return self.value & PTE_ADDR_MASK;
    }

    pub fn getFlags(self: PageTableEntry) u64 {
        return self.value & ~PTE_ADDR_MASK;
    }

    pub fn setAddress(self: *PageTableEntry, addr: u64) void {
        self.value = (self.value & ~PTE_ADDR_MASK) | (addr & PTE_ADDR_MASK);
    }

    pub fn setFlags(self: *PageTableEntry, flags: u64) void {
        self.value = (self.value & PTE_ADDR_MASK) | flags;
    }

    pub fn clearAccessed(self: *PageTableEntry) void {
        self.value &= ~PTE_ACCESSED;
    }

    pub fn clearDirty(self: *PageTableEntry) void {
        self.value &= ~PTE_DIRTY;
    }

    /// Create a new page table entry mapping a physical address with flags.
    pub fn create(phys_addr: u64, flags: u64) PageTableEntry {
        return .{ .value = (phys_addr & PTE_ADDR_MASK) | flags };
    }

    /// Mark this entry for Copy-on-Write: remove write permission, set COW bit.
    pub fn markCow(self: *PageTableEntry) void {
        self.value = (self.value & ~PTE_WRITABLE) | PTE_COW;
    }

    /// Resolve COW: clear COW bit and optionally restore write permission.
    pub fn resolveCow(self: *PageTableEntry, new_phys: u64) void {
        self.value = (new_phys & PTE_ADDR_MASK) |
            (self.value & ~PTE_ADDR_MASK & ~PTE_COW) | PTE_WRITABLE;
    }
};

// =============================================================================
// Page Table Structure (4-level / 5-level compatible)
// =============================================================================
pub const PageTable = struct {
    entries: [ENTRIES_PER_TABLE]PageTableEntry,

    pub fn zero(self: *PageTable) void {
        for (&self.entries) |*entry| {
            entry.* = PageTableEntry.empty;
        }
    }

    pub fn getEntry(self: *const PageTable, index: usize) PageTableEntry {
        return self.entries[index];
    }

    pub fn setEntry(self: *PageTable, index: usize, entry: PageTableEntry) void {
        self.entries[index] = entry;
    }
};

// =============================================================================
// Virtual Address Decomposition
// =============================================================================
pub const VirtualAddress = struct {
    raw: u64,

    pub fn pml4Index(self: VirtualAddress) usize {
        return @intCast((self.raw >> 39) & 0x1FF);
    }

    pub fn pdptIndex(self: VirtualAddress) usize {
        return @intCast((self.raw >> 30) & 0x1FF);
    }

    pub fn pdIndex(self: VirtualAddress) usize {
        return @intCast((self.raw >> 21) & 0x1FF);
    }

    pub fn ptIndex(self: VirtualAddress) usize {
        return @intCast((self.raw >> 12) & 0x1FF);
    }

    pub fn pageOffset(self: VirtualAddress) u12 {
        return @truncate(self.raw & 0xFFF);
    }

    pub fn hugePage2mOffset(self: VirtualAddress) u21 {
        return @truncate(self.raw & 0x1FFFFF);
    }

    pub fn hugePage1gOffset(self: VirtualAddress) u30 {
        return @truncate(self.raw & 0x3FFFFFFF);
    }

    // 5-level paging (LA57) support
    pub fn pml5Index(self: VirtualAddress) usize {
        return @intCast((self.raw >> 48) & 0x1FF);
    }

    pub fn isCanonical(self: VirtualAddress) bool {
        const bit47 = (self.raw >> 47) & 1;
        const top_bits = self.raw >> 48;
        return if (bit47 == 1) top_bits == 0xFFFF else top_bits == 0;
    }

    pub fn isUserSpace(self: VirtualAddress) bool {
        return self.raw <= USER_SPACE_END;
    }

    pub fn isKernelSpace(self: VirtualAddress) bool {
        return self.raw >= KERNEL_SPACE_START;
    }

    pub fn fromRaw(addr: u64) VirtualAddress {
        return .{ .raw = addr };
    }

    pub fn alignDown(self: VirtualAddress, alignment: u64) VirtualAddress {
        return .{ .raw = self.raw & ~(alignment - 1) };
    }

    pub fn alignUp(self: VirtualAddress, alignment: u64) VirtualAddress {
        return .{ .raw = (self.raw + alignment - 1) & ~(alignment - 1) };
    }
};

// =============================================================================
// PCID (Process Context Identifiers) Management
// =============================================================================

/// PCID allocator — manages 12-bit PCIDs for TLB tagging.
/// With PCIDs, TLB entries are tagged per-process, avoiding full TLB flushes
/// on context switches. This is critical for performance.
pub const PcidAllocator = struct {
    bitmap: [MAX_PCID / 64 + 1]u64,
    next_hint: u16,
    generation: u64,

    pub fn init() PcidAllocator {
        var alloc = PcidAllocator{
            .bitmap = [_]u64{0} ** (MAX_PCID / 64 + 1),
            .next_hint = 1, // PCID 0 is reserved for kernel
            .generation = 0,
        };
        // Reserve PCID 0 for the kernel
        alloc.bitmap[0] |= 1;
        return alloc;
    }

    pub fn allocate(self: *PcidAllocator) ?u16 {
        var pcid = self.next_hint;
        var checked: u16 = 0;
        while (checked < MAX_PCID) : (checked += 1) {
            const word = pcid / 64;
            const bit: u6 = @intCast(pcid % 64);
            if (self.bitmap[word] & (@as(u64, 1) << bit) == 0) {
                self.bitmap[word] |= (@as(u64, 1) << bit);
                self.next_hint = if (pcid + 1 >= MAX_PCID) 1 else pcid + 1;
                return pcid;
            }
            pcid = if (pcid + 1 >= MAX_PCID) 1 else pcid + 1;
        }
        // All PCIDs exhausted — bump generation and reclaim
        self.generation += 1;
        @memset(&self.bitmap, 0);
        self.bitmap[0] |= 1; // Re-reserve kernel PCID
        self.next_hint = 1;
        return self.allocate();
    }

    pub fn free(self: *PcidAllocator, pcid: u16) void {
        if (pcid == 0 or pcid >= MAX_PCID) return;
        const word = pcid / 64;
        const bit: u6 = @intCast(pcid % 64);
        self.bitmap[word] &= ~(@as(u64, 1) << bit);
    }
};

// =============================================================================
// TLB Management
// =============================================================================

/// Invalidate a single page in the TLB (INVLPG instruction).
pub inline fn invalidatePage(virt_addr: u64) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt_addr),
        : "memory"
    );
}

/// Flush the entire TLB by reloading CR3.
pub inline fn flushTlb() void {
    const cr3 = readCr3();
    writeCr3(cr3);
}

/// Flush TLB entries for a specific PCID without flushing others.
/// Uses INVPCID instruction (type 1: single address).
pub inline fn invpcidSingle(pcid: u16, addr: u64) void {
    const descriptor = [2]u64{ @as(u64, pcid), addr };
    asm volatile ("invpcid (%[desc]), %[type]"
        :
        : [desc] "r" (&descriptor),
          [type] "r" (@as(u64, 0)),
        : "memory"
    );
}

/// Flush all TLB entries for a specific PCID.
/// Uses INVPCID instruction (type 1: single context).
pub inline fn invpcidContext(pcid: u16) void {
    const descriptor = [2]u64{ @as(u64, pcid), 0 };
    asm volatile ("invpcid (%[desc]), %[type]"
        :
        : [desc] "r" (&descriptor),
          [type] "r" (@as(u64, 1)),
        : "memory"
    );
}

/// Flush all TLB entries including globals.
/// Uses INVPCID instruction (type 2: all contexts).
pub inline fn invpcidAll() void {
    const descriptor = [2]u64{ 0, 0 };
    asm volatile ("invpcid (%[desc]), %[type]"
        :
        : [desc] "r" (&descriptor),
          [type] "r" (@as(u64, 2)),
        : "memory"
    );
}

/// Flush all TLB entries except global pages.
/// Uses INVPCID instruction (type 3: all contexts, retaining globals).
pub inline fn invpcidAllRetainGlobal() void {
    const descriptor = [2]u64{ 0, 0 };
    asm volatile ("invpcid (%[desc]), %[type]"
        :
        : [desc] "r" (&descriptor),
          [type] "r" (@as(u64, 3)),
        : "memory"
    );
}

/// Flush a range of virtual addresses from TLB.
pub fn flushTlbRange(start: u64, end: u64) void {
    var addr = start & ~(PAGE_SIZE_4K - 1);
    while (addr < end) : (addr += PAGE_SIZE_4K) {
        invalidatePage(addr);
    }
}

// =============================================================================
// CR Register Access
// =============================================================================

pub inline fn readCr0() u64 {
    return asm volatile ("mov %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr0(val: u64) void {
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (val),
    );
}

pub inline fn readCr2() u64 {
    return asm volatile ("mov %%cr2, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn readCr3() u64 {
    return asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr3(val: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (val),
        : "memory"
    );
}

/// Write CR3 with PCID — does NOT flush PCID entries if bit 63 is set.
pub inline fn writeCr3Pcid(phys_addr: u64, pcid: u16, no_flush: bool) void {
    var cr3 = (phys_addr & PTE_ADDR_MASK) | @as(u64, pcid);
    if (no_flush) cr3 |= (1 << 63);
    writeCr3(cr3);
}

pub inline fn readCr4() u64 {
    return asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr4(val: u64) void {
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (val),
    );
}

// CR4 feature bits
pub const CR4_VME: u64 = 1 << 0; // Virtual-8086 Mode Extensions
pub const CR4_PVI: u64 = 1 << 1; // Protected-Mode Virtual Interrupts
pub const CR4_TSD: u64 = 1 << 2; // Time Stamp Disable
pub const CR4_DE: u64 = 1 << 3; // Debugging Extensions
pub const CR4_PSE: u64 = 1 << 4; // Page Size Extensions
pub const CR4_PAE: u64 = 1 << 5; // Physical Address Extension
pub const CR4_MCE: u64 = 1 << 6; // Machine Check Enable
pub const CR4_PGE: u64 = 1 << 7; // Page Global Enable
pub const CR4_PCE: u64 = 1 << 8; // Performance Counter Enable
pub const CR4_OSFXSR: u64 = 1 << 9; // OS FXSAVE/FXRSTOR Support
pub const CR4_OSXMMEXCPT: u64 = 1 << 10; // OS Unmasked SIMD Exceptions
pub const CR4_UMIP: u64 = 1 << 11; // User-Mode Instruction Prevention
pub const CR4_LA57: u64 = 1 << 12; // 5-Level Paging
pub const CR4_VMXE: u64 = 1 << 13; // VMX Enable
pub const CR4_SMXE: u64 = 1 << 14; // SMX Enable
pub const CR4_FSGSBASE: u64 = 1 << 16; // FSGSBASE Instructions
pub const CR4_PCIDE: u64 = 1 << 17; // PCID Enable
pub const CR4_OSXSAVE: u64 = 1 << 18; // XSAVE/XRSTOR Support
pub const CR4_SMEP: u64 = 1 << 20; // Supervisor Mode Execution Prevention
pub const CR4_SMAP: u64 = 1 << 21; // Supervisor Mode Access Prevention
pub const CR4_PKE: u64 = 1 << 22; // Protection Key Enable
pub const CR4_CET: u64 = 1 << 23; // Control-Flow Enforcement Technology
pub const CR4_PKS: u64 = 1 << 24; // Protection Keys for Supervisor

// =============================================================================
// KPTI (Kernel Page Table Isolation) Support
// =============================================================================

/// KPTI state tracking structure.
/// When KPTI is active, we maintain two page table sets:
/// - Kernel PML4: maps everything (kernel + user)
/// - User PML4: maps only user pages + minimal kernel trampoline
pub const KptiState = struct {
    kernel_pml4_phys: u64,
    user_pml4_phys: u64,
    enabled: bool,
    trampoline_mapped: bool,

    pub fn init() KptiState {
        return .{
            .kernel_pml4_phys = 0,
            .user_pml4_phys = 0,
            .enabled = false,
            .trampoline_mapped = false,
        };
    }

    /// Determine if KPTI should be enabled based on CPU vulnerability status.
    /// KPTI mitigates Meltdown (CVE-2017-5754) and related speculative execution attacks.
    pub fn shouldEnable() bool {
        // Check CPUID for vulnerability status
        // Leaf 7, subleaf 0, EDX bit 29 = IA32_ARCH_CAPABILITIES supported
        var eax: u32 = undefined;
        var ebx: u32 = undefined;
        var ecx: u32 = undefined;
        var edx: u32 = undefined;
        cpuid(7, 0, &eax, &ebx, &ecx, &edx);

        if (edx & (1 << 29) != 0) {
            // Read IA32_ARCH_CAPABILITIES MSR
            const arch_cap = @import("msr.zig").read(0x10A);
            // Bit 0 = RDCL_NO (not vulnerable to Meltdown)
            if (arch_cap & 1 != 0) return false;
        }

        // Assume vulnerable if we can't confirm otherwise
        return true;
    }
};

/// CPUID instruction wrapper.
pub fn cpuid(leaf: u32, subleaf: u32, eax: *u32, ebx: *u32, ecx: *u32, edx: *u32) void {
    asm volatile ("cpuid"
        : "={eax}" (eax.*),
          "={ebx}" (ebx.*),
          "={ecx}" (ecx.*),
          "={edx}" (edx.*),
        : "{eax}" (leaf),
          "{ecx}" (subleaf),
    );
}

// =============================================================================
// Advanced Page Walk — Translate virtual to physical address
// =============================================================================

pub const WalkResult = struct {
    physical_address: u64,
    page_size: PageSize,
    flags: u64,
    level: u8, // At which level the mapping was found
};

pub const PageSize = enum {
    page_4k,
    page_2m,
    page_1g,
};

pub const WalkError = error{
    NotPresent,
    InvalidAddress,
    ReservedBitSet,
};

/// Walk the page tables starting from a given PML4 physical address.
/// Translates a virtual address to its physical address and retrieves mapping info.
pub fn walkPageTable(pml4_phys: u64, virt: u64) WalkError!WalkResult {
    const va = VirtualAddress.fromRaw(virt);

    if (!va.isCanonical()) return error.InvalidAddress;

    // Level 4 (PML4)
    const pml4 = physToVirt(PageTable, pml4_phys);
    const pml4e = pml4.entries[va.pml4Index()];
    if (!pml4e.isPresent()) return error.NotPresent;

    // Level 3 (PDPT)
    const pdpt = physToVirt(PageTable, pml4e.getAddress());
    const pdpte = pdpt.entries[va.pdptIndex()];
    if (!pdpte.isPresent()) return error.NotPresent;

    // Check for 1GB page
    if (pdpte.isHuge()) {
        return .{
            .physical_address = pdpte.getAddress() | @as(u64, va.hugePage1gOffset()),
            .page_size = .page_1g,
            .flags = pdpte.getFlags(),
            .level = 3,
        };
    }

    // Level 2 (PD)
    const pd = physToVirt(PageTable, pdpte.getAddress());
    const pde = pd.entries[va.pdIndex()];
    if (!pde.isPresent()) return error.NotPresent;

    // Check for 2MB page
    if (pde.isHuge()) {
        return .{
            .physical_address = pde.getAddress() | @as(u64, va.hugePage2mOffset()),
            .page_size = .page_2m,
            .flags = pde.getFlags(),
            .level = 2,
        };
    }

    // Level 1 (PT)
    const pt = physToVirt(PageTable, pde.getAddress());
    const pte = pt.entries[va.ptIndex()];
    if (!pte.isPresent()) return error.NotPresent;

    return .{
        .physical_address = pte.getAddress() | @as(u64, va.pageOffset()),
        .page_size = .page_4k,
        .flags = pte.getFlags(),
        .level = 1,
    };
}

/// Convert a physical address to a virtual address in the direct map region.
fn physToVirt(comptime T: type, phys: u64) *T {
    return @ptrFromInt(phys + KERNEL_DIRECT_MAP_BASE);
}

// =============================================================================
// Page Table Manipulation — Map/Unmap/Protect operations
// =============================================================================

pub const MapError = error{
    OutOfMemory,
    AlreadyMapped,
    InvalidAlignment,
    InvalidAddress,
};

/// Page frame allocator function type (provided by PMM).
pub const FrameAllocFn = *const fn () ?u64;
pub const FrameFreeFn = *const fn (u64) void;

/// Map a single 4KB page in the given address space.
pub fn mapPage(
    pml4_phys: u64,
    virt: u64,
    phys: u64,
    flags: u64,
    alloc_frame: FrameAllocFn,
) MapError!void {
    const va = VirtualAddress.fromRaw(virt);
    if (!va.isCanonical()) return error.InvalidAddress;

    // Walk/create page table levels
    const pml4 = physToVirt(PageTable, pml4_phys);

    // PML4 -> PDPT
    var pml4e = &pml4.entries[va.pml4Index()];
    if (!pml4e.isPresent()) {
        const frame = alloc_frame() orelse return error.OutOfMemory;
        const new_table = physToVirt(PageTable, frame);
        new_table.zero();
        pml4e.* = PageTableEntry.create(frame, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    const pdpt = physToVirt(PageTable, pml4e.getAddress());
    var pdpte = &pdpt.entries[va.pdptIndex()];
    if (!pdpte.isPresent()) {
        const frame = alloc_frame() orelse return error.OutOfMemory;
        const new_table = physToVirt(PageTable, frame);
        new_table.zero();
        pdpte.* = PageTableEntry.create(frame, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    if (pdpte.isHuge()) return error.AlreadyMapped;

    const pd = physToVirt(PageTable, pdpte.getAddress());
    var pde = &pd.entries[va.pdIndex()];
    if (!pde.isPresent()) {
        const frame = alloc_frame() orelse return error.OutOfMemory;
        const new_table = physToVirt(PageTable, frame);
        new_table.zero();
        pde.* = PageTableEntry.create(frame, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    if (pde.isHuge()) return error.AlreadyMapped;

    const pt = physToVirt(PageTable, pde.getAddress());
    var pte = &pt.entries[va.ptIndex()];
    if (pte.isPresent()) return error.AlreadyMapped;

    pte.* = PageTableEntry.create(phys, flags | PTE_PRESENT);
}

/// Unmap a single 4KB page and return its physical address.
pub fn unmapPage(
    pml4_phys: u64,
    virt: u64,
) ?u64 {
    const va = VirtualAddress.fromRaw(virt);
    if (!va.isCanonical()) return null;

    const pml4 = physToVirt(PageTable, pml4_phys);
    const pml4e = pml4.entries[va.pml4Index()];
    if (!pml4e.isPresent()) return null;

    const pdpt = physToVirt(PageTable, pml4e.getAddress());
    const pdpte = pdpt.entries[va.pdptIndex()];
    if (!pdpte.isPresent() or pdpte.isHuge()) return null;

    const pd = physToVirt(PageTable, pdpte.getAddress());
    const pde = pd.entries[va.pdIndex()];
    if (!pde.isPresent() or pde.isHuge()) return null;

    const pt = physToVirt(PageTable, pde.getAddress());
    var pte = &pt.entries[va.ptIndex()];
    if (!pte.isPresent()) return null;

    const phys = pte.getAddress();
    pte.* = PageTableEntry.empty;
    invalidatePage(virt);
    return phys;
}

/// Map a 2MB huge page.
pub fn mapHugePage2M(
    pml4_phys: u64,
    virt: u64,
    phys: u64,
    flags: u64,
    alloc_frame: FrameAllocFn,
) MapError!void {
    if (virt & (PAGE_SIZE_2M - 1) != 0) return error.InvalidAlignment;
    if (phys & (PAGE_SIZE_2M - 1) != 0) return error.InvalidAlignment;

    const va = VirtualAddress.fromRaw(virt);
    const pml4 = physToVirt(PageTable, pml4_phys);

    var pml4e = &pml4.entries[va.pml4Index()];
    if (!pml4e.isPresent()) {
        const frame = alloc_frame() orelse return error.OutOfMemory;
        physToVirt(PageTable, frame).zero();
        pml4e.* = PageTableEntry.create(frame, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    const pdpt = physToVirt(PageTable, pml4e.getAddress());
    var pdpte = &pdpt.entries[va.pdptIndex()];
    if (!pdpte.isPresent()) {
        const frame = alloc_frame() orelse return error.OutOfMemory;
        physToVirt(PageTable, frame).zero();
        pdpte.* = PageTableEntry.create(frame, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    const pd = physToVirt(PageTable, pdpte.getAddress());
    var pde = &pd.entries[va.pdIndex()];
    if (pde.isPresent()) return error.AlreadyMapped;

    pde.* = PageTableEntry.create(phys, flags | PTE_PRESENT | PTE_HUGE);
}

/// Map a 1GB huge page.
pub fn mapHugePage1G(
    pml4_phys: u64,
    virt: u64,
    phys: u64,
    flags: u64,
    alloc_frame: FrameAllocFn,
) MapError!void {
    if (virt & (PAGE_SIZE_1G - 1) != 0) return error.InvalidAlignment;
    if (phys & (PAGE_SIZE_1G - 1) != 0) return error.InvalidAlignment;

    const va = VirtualAddress.fromRaw(virt);
    const pml4 = physToVirt(PageTable, pml4_phys);

    var pml4e = &pml4.entries[va.pml4Index()];
    if (!pml4e.isPresent()) {
        const frame = alloc_frame() orelse return error.OutOfMemory;
        physToVirt(PageTable, frame).zero();
        pml4e.* = PageTableEntry.create(frame, PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    const pdpt = physToVirt(PageTable, pml4e.getAddress());
    var pdpte = &pdpt.entries[va.pdptIndex()];
    if (pdpte.isPresent()) return error.AlreadyMapped;

    pdpte.* = PageTableEntry.create(phys, flags | PTE_PRESENT | PTE_HUGE);
}

/// Change the protection flags on an existing 4KB mapping.
pub fn protectPage(pml4_phys: u64, virt: u64, new_flags: u64) bool {
    const va = VirtualAddress.fromRaw(virt);
    const pml4 = physToVirt(PageTable, pml4_phys);

    const pml4e = pml4.entries[va.pml4Index()];
    if (!pml4e.isPresent()) return false;

    const pdpt = physToVirt(PageTable, pml4e.getAddress());
    const pdpte = pdpt.entries[va.pdptIndex()];
    if (!pdpte.isPresent() or pdpte.isHuge()) return false;

    const pd = physToVirt(PageTable, pdpte.getAddress());
    const pde = pd.entries[va.pdIndex()];
    if (!pde.isPresent() or pde.isHuge()) return false;

    const pt = physToVirt(PageTable, pde.getAddress());
    var pte = &pt.entries[va.ptIndex()];
    if (!pte.isPresent()) return false;

    const addr = pte.getAddress();
    pte.* = PageTableEntry.create(addr, new_flags | PTE_PRESENT);
    invalidatePage(virt);
    return true;
}

/// Map a range of virtual addresses to contiguous physical addresses.
pub fn mapRange(
    pml4_phys: u64,
    virt_start: u64,
    phys_start: u64,
    size: u64,
    flags: u64,
    alloc_frame: FrameAllocFn,
) MapError!void {
    var offset: u64 = 0;
    while (offset < size) : (offset += PAGE_SIZE_4K) {
        try mapPage(pml4_phys, virt_start + offset, phys_start + offset, flags, alloc_frame);
    }
}

/// Map a range using the largest possible page sizes for efficiency.
pub fn mapRangeOptimal(
    pml4_phys: u64,
    virt_start: u64,
    phys_start: u64,
    size: u64,
    flags: u64,
    alloc_frame: FrameAllocFn,
) MapError!void {
    var offset: u64 = 0;
    while (offset < size) {
        const remaining = size - offset;
        const virt = virt_start + offset;
        const phys = phys_start + offset;

        // Try 1GB pages first
        if (remaining >= PAGE_SIZE_1G and
            virt & (PAGE_SIZE_1G - 1) == 0 and
            phys & (PAGE_SIZE_1G - 1) == 0)
        {
            mapHugePage1G(pml4_phys, virt, phys, flags, alloc_frame) catch {
                // Fall through to smaller page sizes
                offset += PAGE_SIZE_4K;
                continue;
            };
            offset += PAGE_SIZE_1G;
            continue;
        }

        // Try 2MB pages
        if (remaining >= PAGE_SIZE_2M and
            virt & (PAGE_SIZE_2M - 1) == 0 and
            phys & (PAGE_SIZE_2M - 1) == 0)
        {
            mapHugePage2M(pml4_phys, virt, phys, flags, alloc_frame) catch {
                offset += PAGE_SIZE_4K;
                continue;
            };
            offset += PAGE_SIZE_2M;
            continue;
        }

        // Fall back to 4KB pages
        try mapPage(pml4_phys, virt, phys, flags, alloc_frame);
        offset += PAGE_SIZE_4K;
    }
}

// =============================================================================
// Copy-on-Write (COW) Support
// =============================================================================

/// Mark all user-space pages in an address space as COW.
/// Used during fork() to share pages between parent and child.
pub fn markAddressSpaceCow(pml4_phys: u64) void {
    const pml4 = physToVirt(PageTable, pml4_phys);

    // Only process user-space entries (indices 0-255 for lower half)
    for (pml4.entries[0..256]) |*pml4e| {
        if (!pml4e.isPresent()) continue;

        const pdpt = physToVirt(PageTable, pml4e.getAddress());
        for (&pdpt.entries) |*pdpte| {
            if (!pdpte.isPresent()) continue;
            if (pdpte.isHuge()) {
                // Mark 1GB huge pages as COW
                pdpte.markCow();
                continue;
            }

            const pd = physToVirt(PageTable, pdpte.getAddress());
            for (&pd.entries) |*pde| {
                if (!pde.isPresent()) continue;
                if (pde.isHuge()) {
                    // Mark 2MB huge pages as COW
                    pde.markCow();
                    continue;
                }

                const pt = physToVirt(PageTable, pde.getAddress());
                for (&pt.entries) |*pte| {
                    if (!pte.isPresent()) continue;
                    if (pte.isWritable()) {
                        pte.markCow();
                    }
                }
            }
        }
    }
}

/// Clone page tables for fork() — creates a new PML4 sharing all entries.
/// User pages are marked COW; kernel mappings are shared directly.
pub fn clonePageTable(
    src_pml4_phys: u64,
    alloc_frame: FrameAllocFn,
) ?u64 {
    const new_pml4_frame = alloc_frame() orelse return null;
    const new_pml4 = physToVirt(PageTable, new_pml4_frame);
    const src_pml4 = physToVirt(PageTable, src_pml4_phys);

    // Copy kernel-space entries directly (indices 256-511)
    for (256..512) |i| {
        new_pml4.entries[i] = src_pml4.entries[i];
    }

    // Deep-copy user-space entries (indices 0-255) with COW
    for (0..256) |i| {
        if (!src_pml4.entries[i].isPresent()) {
            new_pml4.entries[i] = PageTableEntry.empty;
            continue;
        }
        // For COW: share the same PDPT page, mark source and dest as COW
        new_pml4.entries[i] = src_pml4.entries[i];
    }

    // Mark all user-writable pages in both address spaces as COW
    markAddressSpaceCow(src_pml4_phys);
    markAddressSpaceCow(new_pml4_frame);

    return new_pml4_frame;
}

// =============================================================================
// Page Fault Handler Support
// =============================================================================

pub const PageFaultType = enum {
    not_present, // Page not in page table
    protection_violation, // Permission violation
    cow_fault, // Write to COW page
    demand_page, // First access to demand-paged region
    swap_in, // Page swapped out, needs loading
    guard_page, // Stack guard page hit
    kernel_fault, // Fault in kernel mode
};

/// Analyze a page fault and determine its type.
pub fn classifyPageFault(error_code: u64, fault_addr: u64, pml4_phys: u64) PageFaultType {
    const was_write = (error_code & 2) != 0;
    const was_user = (error_code & 4) != 0;
    const was_present = (error_code & 1) != 0;
    _ = was_user;

    if (!was_present) {
        // Page not present — check if it's a demand page or swap
        const va = VirtualAddress.fromRaw(fault_addr);
        const pml4 = physToVirt(PageTable, pml4_phys);
        const pml4e = pml4.entries[va.pml4Index()];
        if (!pml4e.isPresent()) return .not_present;

        const pdpt = physToVirt(PageTable, pml4e.getAddress());
        const pdpte = pdpt.entries[va.pdptIndex()];
        if (!pdpte.isPresent()) return .not_present;

        if (!pdpte.isHuge()) {
            const pd = physToVirt(PageTable, pdpte.getAddress());
            const pde = pd.entries[va.pdIndex()];
            if (!pde.isPresent()) return .not_present;

            if (!pde.isHuge()) {
                const pt = physToVirt(PageTable, pde.getAddress());
                const pte = pt.entries[va.ptIndex()];

                if (pte.isSwapped()) return .swap_in;
                if (pte.isDemand()) return .demand_page;
            }
        }

        return .not_present;
    }

    // Page present but fault occurred
    if (was_write) {
        // Check if this is a COW page
        const va = VirtualAddress.fromRaw(fault_addr);
        const pml4 = physToVirt(PageTable, pml4_phys);
        const pml4e = pml4.entries[va.pml4Index()];
        if (pml4e.isPresent()) {
            const pdpt = physToVirt(PageTable, pml4e.getAddress());
            const pdpte = pdpt.entries[va.pdptIndex()];
            if (pdpte.isPresent() and !pdpte.isHuge()) {
                const pd = physToVirt(PageTable, pdpte.getAddress());
                const pde = pd.entries[va.pdIndex()];
                if (pde.isPresent() and !pde.isHuge()) {
                    const pt = physToVirt(PageTable, pde.getAddress());
                    const pte = pt.entries[va.ptIndex()];
                    if (pte.isCow()) return .cow_fault;
                }
            }
        }
    }

    return .protection_violation;
}

// =============================================================================
// SMEP/SMAP Support (Supervisor Mode Execution/Access Prevention)
// =============================================================================

/// Enable SMEP — prevents kernel from executing user-space code.
pub fn enableSmep() void {
    writeCr4(readCr4() | CR4_SMEP);
}

/// Enable SMAP — prevents kernel from accessing user-space memory
/// unless explicitly allowed via STAC/CLAC instructions.
pub fn enableSmap() void {
    writeCr4(readCr4() | CR4_SMAP);
}

/// Temporarily allow supervisor access to user pages (STAC instruction).
pub inline fn stac() void {
    asm volatile ("stac" ::: "memory", "cc");
}

/// Clear access to user pages from supervisor mode (CLAC instruction).
pub inline fn clac() void {
    asm volatile ("clac" ::: "memory", "cc");
}

/// Enable PCID support.
pub fn enablePcid() void {
    writeCr4(readCr4() | CR4_PCIDE);
}

/// Enable global pages.
pub fn enableGlobalPages() void {
    writeCr4(readCr4() | CR4_PGE);
}

/// Enable UMIP (User-Mode Instruction Prevention).
pub fn enableUmip() void {
    writeCr4(readCr4() | CR4_UMIP);
}

/// Enable NX bit support via EFER.
pub fn enableNxBit() void {
    @import("msr.zig").enableEferBits(@import("msr.zig").EFER_NXE);
}

/// Enable 5-level paging (LA57).
pub fn enableLa57() void {
    writeCr4(readCr4() | CR4_LA57);
}

/// Check if 5-level paging is supported.
pub fn isLa57Supported() bool {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    return (ecx & (1 << 16)) != 0;
}

// =============================================================================
// Write-Protect CR0 bit management (for safe kernel page table modification)
// =============================================================================

/// Temporarily disable write protection so we can modify read-only kernel pages.
pub fn disableWriteProtect() void {
    writeCr0(readCr0() & ~@as(u64, 1 << 16));
}

/// Re-enable write protection.
pub fn enableWriteProtect() void {
    writeCr0(readCr0() | (1 << 16));
}
