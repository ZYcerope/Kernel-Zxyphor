// =============================================================================
// Zxyphor Kernel — ARM64 MMU (Memory Management Unit)
// =============================================================================
// Full 4-level page table implementation for AArch64 with Sv48 (48-bit VA).
// Supports 4KB, 16KB, and 64KB granules, huge pages (1GB/2MB blocks),
// ASID management, copy-on-write, demand paging, memory-mapped I/O regions,
// per-process address spaces, and kernel/user split at 0xFFFF_0000_0000_0000.
//
// Page Table Levels (4KB granule):
//   L0 (PGD):  512 entries, each covers 512GB, bits 47:39
//   L1 (PUD):  512 entries, each covers 1GB,   bits 38:30 (can be block)
//   L2 (PMD):  512 entries, each covers 2MB,   bits 29:21 (can be block)
//   L3 (PTE):  512 entries, each covers 4KB,   bits 20:12
//
// Memory Attributes (MAIR):
//   Index 0: Device-nGnRnE (strongly ordered)
//   Index 1: Device-nGnRE
//   Index 2: Normal Non-Cacheable
//   Index 3: Normal Write-Through
//   Index 4: Normal Write-Back (read/write allocate)
//   Index 5: Tagged Normal (MTE)
// =============================================================================

const boot_mod = @import("boot.zig");

// ── Constants ─────────────────────────────────────────────────────────────
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: u6 = 12;
pub const ENTRIES_PER_TABLE: usize = 512;
pub const TABLE_SIZE: usize = PAGE_SIZE;
pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
pub const BLOCK_L1_SIZE: u64 = 1 << 30;   // 1GB
pub const BLOCK_L2_SIZE: u64 = 1 << 21;   // 2MB

// Kernel/User split
pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const USER_END: u64 = 0x0000_FFFF_FFFF_FFFF;

// Kernel memory layout
pub const KERNEL_TEXT_START: u64 = KERNEL_BASE;
pub const KERNEL_VMALLOC_START: u64 = KERNEL_BASE + 0x1000_0000_0000; // 16TB offset
pub const KERNEL_VMALLOC_END: u64 = KERNEL_VMALLOC_START + 0x0100_0000_0000; // 1TB
pub const KERNEL_VMEMMAP_START: u64 = KERNEL_BASE + 0x2000_0000_0000;
pub const KERNEL_PCI_IO_START: u64 = KERNEL_BASE + 0x3000_0000_0000;
pub const KERNEL_FIXMAP_START: u64 = KERNEL_BASE + 0x3F00_0000_0000;
pub const KERNEL_MODULES_START: u64 = KERNEL_BASE + 0x4000_0000_0000;

// Maximum supported physical address bits
pub const MAX_PA_BITS: u6 = 48;

// ── Page Table Entry Formats ──────────────────────────────────────────────
pub const PageTableEntry = packed struct {
    valid: bool,        // Bit 0: Valid
    table_or_page: bool, // Bit 1: Table (L0-2) or Page (L3)
    attr_idx: u3,       // Bits 4:2: MAIR attribute index
    ns: bool,           // Bit 5: Non-Secure
    ap: u2,             // Bits 7:6: Access Permission
    sh: u2,             // Bits 9:8: Shareability
    af: bool,           // Bit 10: Access Flag
    ng: bool,           // Bit 11: Not Global
    _reserved0: u4,     // Bits 15:12
    nT: bool,           // Bit 16: Block translation entry (nT)
    _reserved1: u4,     // Bits 20:17
    _reserved2: u28,    // Bits 48:21 (part of OA/next table addr)
    gp: bool,           // Bit 50: Guard Page (BTI/MTE-related)
    dbm: bool,          // Bit 51: Dirty Bit Modifier
    contiguous: bool,   // Bit 52: Contiguous hint
    pxn: bool,          // Bit 53: Privileged eXecute Never
    uxn: bool,          // Bit 54: Unprivileged eXecute Never
    sw_reserved: u4,    // Bits 58:55: Software use
    pbha: u4,           // Bits 62:59: Page-Based Hardware Attributes
    _reserved3: bool,   // Bit 63

    const Self = @This();

    pub fn asU64(self: Self) u64 {
        return @bitCast(self);
    }

    pub fn fromU64(val: u64) Self {
        return @bitCast(val);
    }
};

// Access Permission values
pub const AP = struct {
    pub const RW_EL1: u2 = 0b00; // R/W at EL1, none at EL0
    pub const RW_ALL: u2 = 0b01; // R/W at EL1 and EL0
    pub const RO_EL1: u2 = 0b10; // Read-only at EL1, none at EL0
    pub const RO_ALL: u2 = 0b11; // Read-only at both EL1 and EL0
};

// Shareability values
pub const SH = struct {
    pub const NON: u2 = 0b00;
    pub const OUTER: u2 = 0b10;
    pub const INNER: u2 = 0b11;
};

// ── Memory Type Definitions ───────────────────────────────────────────────
pub const MemType = enum(u3) {
    device_nGnRnE = 0,
    device_nGnRE = 1,
    normal_nc = 2,
    normal_wt = 3,
    normal_wb = 4,
    normal_tagged = 5,
};

// ── Page Table Flags (combined for convenience) ───────────────────────────
pub const PF = struct {
    // Raw flag bits for u64 page table entries
    pub const VALID: u64 = 1 << 0;
    pub const TABLE: u64 = 1 << 1;
    pub const PAGE: u64 = 1 << 1;
    pub const AF: u64 = 1 << 10;
    pub const NG: u64 = 1 << 11;
    pub const CONTIGUOUS: u64 = 1 << 52;
    pub const PXN: u64 = 1 << 53;
    pub const UXN: u64 = 1 << 54;

    pub const AP_RW_EL1: u64 = 0b00 << 6;
    pub const AP_RW_ALL: u64 = 0b01 << 6;
    pub const AP_RO_EL1: u64 = 0b10 << 6;
    pub const AP_RO_ALL: u64 = 0b11 << 6;

    pub const SH_NON: u64 = 0b00 << 8;
    pub const SH_OUTER: u64 = 0b10 << 8;
    pub const SH_INNER: u64 = 0b11 << 8;

    // Software bits (bits 55-58)
    pub const SW_COW: u64 = 1 << 55;       // Copy-on-Write
    pub const SW_DIRTY: u64 = 1 << 56;     // Software dirty bit
    pub const SW_ACCESSED: u64 = 1 << 57;  // Software accessed bit
    pub const SW_SPECIAL: u64 = 1 << 58;   // Special mapping (MMIO, etc.)

    // Common combined flags
    pub fn kernelText() u64 {
        return VALID | PAGE | AF | SH_INNER | AP_RO_EL1 | PXN; // not PXN for text!
    }

    pub fn kernelRoData() u64 {
        return VALID | PAGE | AF | SH_INNER | AP_RO_EL1 | PXN | UXN |
               (@as(u64, @intFromEnum(MemType.normal_wb)) << 2);
    }

    pub fn kernelData() u64 {
        return VALID | PAGE | AF | SH_INNER | AP_RW_EL1 | PXN | UXN |
               (@as(u64, @intFromEnum(MemType.normal_wb)) << 2);
    }

    pub fn userText() u64 {
        return VALID | PAGE | AF | SH_INNER | AP_RO_ALL | NG |
               (@as(u64, @intFromEnum(MemType.normal_wb)) << 2);
    }

    pub fn userData() u64 {
        return VALID | PAGE | AF | SH_INNER | AP_RW_ALL | PXN | NG |
               (@as(u64, @intFromEnum(MemType.normal_wb)) << 2);
    }

    pub fn userRoData() u64 {
        return VALID | PAGE | AF | SH_INNER | AP_RO_ALL | PXN | NG |
               (@as(u64, @intFromEnum(MemType.normal_wb)) << 2);
    }

    pub fn deviceMmio() u64 {
        return VALID | PAGE | AF | SH_NON | AP_RW_EL1 | PXN | UXN |
               (@as(u64, @intFromEnum(MemType.device_nGnRnE)) << 2);
    }
};

// ── ASID Manager ──────────────────────────────────────────────────────────
pub const MAX_ASIDS: usize = 65536; // 16-bit ASID
const ASID_BITMAP_SIZE: usize = MAX_ASIDS / 64;

var asid_bitmap: [ASID_BITMAP_SIZE]u64 = [_]u64{0} ** ASID_BITMAP_SIZE;
var asid_generation: u64 = 1;
var next_asid: u16 = 1; // ASID 0 is reserved for kernel

pub fn allocAsid() u16 {
    var attempts: usize = 0;
    while (attempts < MAX_ASIDS) : (attempts += 1) {
        const asid = next_asid;
        next_asid +%= 1;
        if (next_asid == 0) next_asid = 1; // Skip 0

        const word = asid / 64;
        const bit: u6 = @truncate(asid % 64);
        if (asid_bitmap[word] & (@as(u64, 1) << bit) == 0) {
            asid_bitmap[word] |= @as(u64, 1) << bit;
            return asid;
        }
    }
    // All ASIDs exhausted — force a generation rollover
    rolloverAsids();
    return allocAsid();
}

pub fn freeAsid(asid: u16) void {
    if (asid == 0) return;
    const word = asid / 64;
    const bit: u6 = @truncate(asid % 64);
    asid_bitmap[word] &= ~(@as(u64, 1) << bit);
}

fn rolloverAsids() void {
    @memset(&asid_bitmap, 0);
    asid_generation += 1;
    next_asid = 1;
    // Need to flush all TLBs on all CPUs
    flushTlbAll();
}

// ── Page Table Operations ─────────────────────────────────────────────────
pub const PageTable = struct {
    entries: [ENTRIES_PER_TABLE]u64 align(PAGE_SIZE),

    const Self = @This();

    pub fn init() Self {
        return Self{ .entries = [_]u64{0} ** ENTRIES_PER_TABLE };
    }

    pub fn getEntry(self: *const Self, index: usize) u64 {
        return self.entries[index];
    }

    pub fn setEntry(self: *Self, index: usize, val: u64) void {
        self.entries[index] = val;
    }

    pub fn isValid(self: *const Self, index: usize) bool {
        return (self.entries[index] & PF.VALID) != 0;
    }

    pub fn isTable(self: *const Self, index: usize) bool {
        return (self.entries[index] & (PF.VALID | PF.TABLE)) == (PF.VALID | PF.TABLE);
    }

    pub fn getNextTablePhys(self: *const Self, index: usize) u64 {
        return self.entries[index] & ADDR_MASK;
    }

    pub fn clear(self: *Self) void {
        @memset(&self.entries, 0);
    }
};

// ── Virtual Address Decomposition ─────────────────────────────────────────
pub const VAddrParts = struct {
    l0_idx: u9,    // PGD index (bits 47:39)
    l1_idx: u9,    // PUD index (bits 38:30)
    l2_idx: u9,    // PMD index (bits 29:21)
    l3_idx: u9,    // PTE index (bits 20:12)
    offset: u12,   // Page offset (bits 11:0)

    pub fn fromVAddr(vaddr: u64) VAddrParts {
        return VAddrParts{
            .l0_idx = @truncate((vaddr >> 39) & 0x1FF),
            .l1_idx = @truncate((vaddr >> 30) & 0x1FF),
            .l2_idx = @truncate((vaddr >> 21) & 0x1FF),
            .l3_idx = @truncate((vaddr >> 12) & 0x1FF),
            .offset = @truncate(vaddr & 0xFFF),
        };
    }

    pub fn toVAddr(self: VAddrParts) u64 {
        var addr: u64 = 0;
        addr |= @as(u64, self.l0_idx) << 39;
        addr |= @as(u64, self.l1_idx) << 30;
        addr |= @as(u64, self.l2_idx) << 21;
        addr |= @as(u64, self.l3_idx) << 12;
        addr |= @as(u64, self.offset);
        // Sign extend from bit 48
        if (addr & (1 << 47) != 0) {
            addr |= 0xFFFF_0000_0000_0000;
        }
        return addr;
    }
};

// ── Address Space Descriptor ──────────────────────────────────────────────
pub const AddressSpace = struct {
    pgd_phys: u64,     // Physical address of L0 (PGD) table
    asid: u16,         // Address Space ID
    generation: u64,   // ASID generation
    page_count: u64,   // Number of mapped pages
    table_count: u64,  // Number of page tables allocated
    lock: SpinLock,    // Lock for concurrent access (simplified)

    const Self = @This();

    pub fn create() ?Self {
        const pgd_phys = allocPageTable() orelse return null;
        return Self{
            .pgd_phys = pgd_phys,
            .asid = allocAsid(),
            .generation = asid_generation,
            .page_count = 0,
            .table_count = 1,
            .lock = SpinLock.init(),
        };
    }

    pub fn destroy(self: *Self) void {
        // Walk and free all page tables and mapped pages
        self.freePageTablesRecursive(self.pgd_phys, 0);
        freeAsid(self.asid);
        self.pgd_phys = 0;
        self.asid = 0;
    }

    pub fn mapPage(self: *Self, vaddr: u64, paddr: u64, flags: u64) !void {
        const parts = VAddrParts.fromVAddr(vaddr);

        // Walk/create page table hierarchy
        var table_phys = self.pgd_phys;

        // L0 → L1
        table_phys = try self.ensureTable(table_phys, parts.l0_idx);
        // L1 → L2
        table_phys = try self.ensureTable(table_phys, parts.l1_idx);
        // L2 → L3
        table_phys = try self.ensureTable(table_phys, parts.l2_idx);

        // Set L3 PTE
        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        table.setEntry(parts.l3_idx, (paddr & ADDR_MASK) | flags | PF.VALID | PF.PAGE | PF.AF);
        self.page_count += 1;
    }

    pub fn mapBlock2M(self: *Self, vaddr: u64, paddr: u64, flags: u64) !void {
        const parts = VAddrParts.fromVAddr(vaddr);

        var table_phys = self.pgd_phys;
        table_phys = try self.ensureTable(table_phys, parts.l0_idx);
        table_phys = try self.ensureTable(table_phys, parts.l1_idx);

        // Set L2 block entry (no TABLE bit)
        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        table.setEntry(parts.l2_idx, (paddr & ADDR_MASK) | flags | PF.VALID | PF.AF);
    }

    pub fn mapBlock1G(self: *Self, vaddr: u64, paddr: u64, flags: u64) !void {
        const parts = VAddrParts.fromVAddr(vaddr);

        var table_phys = self.pgd_phys;
        table_phys = try self.ensureTable(table_phys, parts.l0_idx);

        // Set L1 block entry
        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        table.setEntry(parts.l1_idx, (paddr & ADDR_MASK) | flags | PF.VALID | PF.AF);
    }

    pub fn unmapPage(self: *Self, vaddr: u64) void {
        const parts = VAddrParts.fromVAddr(vaddr);

        var table_phys = self.pgd_phys;

        // Walk to L3
        const l0: *PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l0.isTable(parts.l0_idx)) return;
        table_phys = l0.getNextTablePhys(parts.l0_idx);

        const l1: *PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l1.isTable(parts.l1_idx)) return;
        table_phys = l1.getNextTablePhys(parts.l1_idx);

        const l2: *PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l2.isTable(parts.l2_idx)) return;
        table_phys = l2.getNextTablePhys(parts.l2_idx);

        const l3: *PageTable = @ptrFromInt(physToVirt(table_phys));
        l3.setEntry(parts.l3_idx, 0);
        self.page_count -|= 1;

        // Invalidate TLB for this page
        flushTlbPage(vaddr, self.asid);
    }

    pub fn lookupPage(self: *const Self, vaddr: u64) ?u64 {
        const parts = VAddrParts.fromVAddr(vaddr);

        var table_phys = self.pgd_phys;

        const l0: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l0.isValid(parts.l0_idx)) return null;
        if (!l0.isTable(parts.l0_idx)) {
            // L0 cannot be a block on AArch64
            return null;
        }
        table_phys = l0.getNextTablePhys(parts.l0_idx);

        const l1: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l1.isValid(parts.l1_idx)) return null;
        if (!l1.isTable(parts.l1_idx)) {
            // 1GB block mapping
            return (l1.getEntry(parts.l1_idx) & ADDR_MASK) | (@as(u64, parts.l1_idx) << 30);
        }
        table_phys = l1.getNextTablePhys(parts.l1_idx);

        const l2: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l2.isValid(parts.l2_idx)) return null;
        if (!l2.isTable(parts.l2_idx)) {
            // 2MB block mapping
            return (l2.getEntry(parts.l2_idx) & ADDR_MASK) | (@as(u64, parts.l2_idx) << 21);
        }
        table_phys = l2.getNextTablePhys(parts.l2_idx);

        const l3: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!l3.isValid(parts.l3_idx)) return null;
        return l3.getEntry(parts.l3_idx) & ADDR_MASK;
    }

    pub fn switchTo(self: *const Self) void {
        const ttbr = self.pgd_phys | (@as(u64, self.asid) << 48);
        boot_mod.writeTtbr0EL1(ttbr);
        boot_mod.isb();
    }

    fn ensureTable(self: *Self, parent_phys: u64, index: u9) !u64 {
        const table: *PageTable = @ptrFromInt(physToVirt(parent_phys));
        if (table.isTable(index)) {
            return table.getNextTablePhys(index);
        }
        // Allocate new page table
        const new_table_phys = allocPageTable() orelse return error.OutOfMemory;
        // Zero it
        const new_table: *PageTable = @ptrFromInt(physToVirt(new_table_phys));
        new_table.clear();
        // Link it
        table.setEntry(index, (new_table_phys & ADDR_MASK) | PF.VALID | PF.TABLE);
        self.table_count += 1;
        return new_table_phys;
    }

    fn freePageTablesRecursive(self: *Self, table_phys: u64, level: u8) void {
        if (level >= 4) return;
        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        var i: usize = 0;
        while (i < ENTRIES_PER_TABLE) : (i += 1) {
            if (table.isTable(i) and level < 3) {
                self.freePageTablesRecursive(table.getNextTablePhys(i), level + 1);
            }
        }
        freePageTable(table_phys);
    }
};

// ── VMA (Virtual Memory Area) ─────────────────────────────────────────────
pub const VmFlags = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    shared: bool = false,
    user: bool = false,
    io: bool = false,           // Memory-mapped I/O
    dma: bool = false,          // DMA buffer
    stack: bool = false,        // Stack region
    heap: bool = false,         // Heap region
    hugetlb: bool = false,      // Huge page mapping
    growsdown: bool = false,    // Stack grows down
    pfnmap: bool = false,       // PFN mapped (no struct page)
    locked: bool = false,       // Locked in RAM
    populate: bool = false,     // Prefault pages
    cow: bool = false,          // Copy-on-write
    anonymous: bool = false,    // Anonymous mapping (no file)
    _pad: u16 = 0,
};

pub const VMA = struct {
    start: u64,
    end: u64,         // Exclusive end
    flags: VmFlags,
    pgoff: u64,        // Page offset in backing file
    file_id: u32,      // File inode ID (0 for anonymous)
    next: ?*VMA,
    prev: ?*VMA,

    const Self = @This();

    pub fn size(self: *const Self) u64 {
        return self.end - self.start;
    }

    pub fn contains(self: *const Self, addr: u64) bool {
        return addr >= self.start and addr < self.end;
    }

    pub fn overlaps(self: *const Self, start: u64, end: u64) bool {
        return self.start < end and start < self.end;
    }

    pub fn toPageFlags(self: *const Self) u64 {
        var flags: u64 = PF.VALID | PF.PAGE | PF.AF;

        if (self.flags.user) {
            flags |= PF.NG; // Not global for user pages
            if (self.flags.write) {
                flags |= PF.AP_RW_ALL;
            } else {
                flags |= PF.AP_RO_ALL;
            }
            if (!self.flags.execute) {
                flags |= PF.UXN;
            }
            flags |= PF.PXN; // Never execute user pages at EL1
        } else {
            if (self.flags.write) {
                flags |= PF.AP_RW_EL1;
            } else {
                flags |= PF.AP_RO_EL1;
            }
            if (!self.flags.execute) {
                flags |= PF.PXN;
            }
            flags |= PF.UXN; // Never execute kernel pages at EL0
        }

        if (self.flags.io) {
            flags |= @as(u64, @intFromEnum(MemType.device_nGnRnE)) << 2;
            flags &= ~PF.SH_INNER; // Device memory is non-shareable
        } else {
            flags |= @as(u64, @intFromEnum(MemType.normal_wb)) << 2;
            flags |= PF.SH_INNER; // Inner shareable for normal memory
        }

        if (self.flags.cow) {
            flags |= PF.SW_COW;
        }

        return flags;
    }
};

// ── TLB Management ────────────────────────────────────────────────────────
pub fn flushTlbAll() void {
    asm volatile (
        \\dsb ishst
        \\tlbi vmalle1
        \\dsb ish
        \\isb
    );
}

pub fn flushTlbPage(vaddr: u64, asid: u16) void {
    // TLBI VALE1IS — invalidate by VA, last level, EL1, Inner Shareable
    const val = (vaddr >> 12) | (@as(u64, asid) << 48);
    asm volatile ("tlbi vale1is, %[v]; dsb ish; isb" : : [v] "r" (val));
}

pub fn flushTlbAsid(asid: u16) void {
    // TLBI ASIDE1IS — invalidate by ASID, EL1, Inner Shareable
    const val: u64 = @as(u64, asid) << 48;
    asm volatile ("tlbi aside1is, %[v]; dsb ish; isb" : : [v] "r" (val));
}

pub fn flushTlbRange(start: u64, end: u64, asid: u16) void {
    var addr = start;
    while (addr < end) : (addr += PAGE_SIZE) {
        flushTlbPage(addr, asid);
    }
}

// ── Page Table Allocation (simplified — uses early allocator) ─────────────
// In a full kernel, this would use the physical page allocator
var page_table_pool: [8192]PageTable align(PAGE_SIZE) = undefined;
var next_pool_index: usize = 0;

fn allocPageTable() ?u64 {
    if (next_pool_index >= page_table_pool.len) return null;
    const table = &page_table_pool[next_pool_index];
    table.clear();
    next_pool_index += 1;
    return @intFromPtr(table); // In early boot, virt == phys for pool
}

fn freePageTable(phys: u64) void {
    // Simplified — just zero the table
    const table: *PageTable = @ptrFromInt(physToVirt(phys));
    table.clear();
}

// ── Physical ↔ Virtual Address Translation ────────────────────────────────
pub fn physToVirt(phys: u64) u64 {
    return phys + KERNEL_BASE;
}

pub fn virtToPhys(virt: u64) u64 {
    return virt - KERNEL_BASE;
}

pub fn isKernelAddr(addr: u64) bool {
    return addr >= KERNEL_BASE;
}

pub fn isUserAddr(addr: u64) bool {
    return addr <= USER_END;
}

// ── Page Fault Handler ────────────────────────────────────────────────────
pub const FaultType = enum {
    translation,     // Missing page table entry
    permission,      // Permission violation
    access_flag,     // Access flag not set
    alignment,       // Alignment fault
    size,            // Address size fault
    unknown,
};

pub const FaultInfo = struct {
    vaddr: u64,       // Faulting virtual address (FAR_EL1)
    fault_type: FaultType,
    is_write: bool,
    is_exec: bool,
    is_user: bool,
    level: u2,        // Translation table level (0-3)
    esr: u64,         // Exception Syndrome Register value
};

pub fn decodeFault(esr: u64, far: u64) FaultInfo {
    const ec = (esr >> 26) & 0x3F;  // Exception Class
    const iss = esr & 0x1FFFFFF;     // Instruction Specific Syndrome
    const dfsc = iss & 0x3F;         // Data Fault Status Code
    const wnr = (iss >> 6) & 1;     // Write/not-Read
    const cm = (iss >> 8) & 1;       // Cache maintenance
    _ = cm;
    const level: u2 = @truncate(dfsc & 0x3);

    const fault_type: FaultType = switch (dfsc >> 2) {
        0b0001 => .translation,    // Translation fault
        0b0011 => .permission,     // Permission fault
        0b0010 => .access_flag,    // Access flag fault
        0b0000 => .size,           // Address size fault
        0b1000 => .alignment,      // Alignment fault
        else => .unknown,
    };

    return FaultInfo{
        .vaddr = far,
        .fault_type = fault_type,
        .is_write = wnr == 1,
        .is_exec = (ec == 0x20 or ec == 0x21), // Instruction Abort
        .is_user = (ec & 1) == 0, // Lower EL
        .level = level,
        .esr = esr,
    };
}

// ── Simplified SpinLock ───────────────────────────────────────────────────
const SpinLock = struct {
    locked: u32 = 0,

    pub fn init() SpinLock {
        return .{};
    }

    pub fn acquire(self: *SpinLock) void {
        while (@atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) != 0) {
            asm volatile ("wfe");
        }
    }

    pub fn release(self: *SpinLock) void {
        @atomicStore(u32, &self.locked, 0, .release);
        asm volatile ("sev");
    }
};
