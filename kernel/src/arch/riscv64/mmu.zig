// =============================================================================
// Zxyphor Kernel — RISC-V 64-bit MMU (Sv48 Page Tables)
// =============================================================================
// Full Sv48 (4-level, 48-bit VA) page table implementation for RISC-V.
// Also supports Sv39 (3-level, 39-bit VA) and future Sv57 (5-level).
//
// Sv48 Page Table Layout (4KB pages):
//   L0 (Root):  512 entries, each covers 256TB, bits 47:39
//   L1:         512 entries, each covers 512GB, bits 38:30 (can be gigapage)
//   L2:         512 entries, each covers 1GB,   bits 29:21 (can be megapage)
//   L3 (Leaf):  512 entries, each covers 4KB,   bits 20:12
//
// RISC-V PTE Format (64 bits):
//   Bits 0:     V (Valid)
//   Bits 1:     R (Read)
//   Bits 2:     W (Write)
//   Bits 3:     X (Execute)
//   Bits 4:     U (User)
//   Bits 5:     G (Global)
//   Bits 6:     A (Accessed)
//   Bits 7:     D (Dirty)
//   Bits 9:8:   RSW (Reserved for Software)
//   Bits 53:10: PPN (Physical Page Number)
//   Bits 60:54: Reserved
//   Bits 62:61: PBMT (Page-Based Memory Types, Svpbmt)
//   Bit 63:     N (NAPOT, Svnapot)
//
// A PTE is a leaf when R|W|X != 0.
// A PTE is a pointer to next table when V=1 and R=W=X=0.
// =============================================================================

const boot = @import("boot.zig");

// ── Page Table Entry Fields ───────────────────────────────────────────────
pub const PTE = struct {
    pub const V: u64 = 1 << 0;  // Valid
    pub const R: u64 = 1 << 1;  // Read
    pub const W: u64 = 1 << 2;  // Write
    pub const X: u64 = 1 << 3;  // Execute
    pub const U: u64 = 1 << 4;  // User-accessible
    pub const G: u64 = 1 << 5;  // Global mapping
    pub const A: u64 = 1 << 6;  // Accessed
    pub const D: u64 = 1 << 7;  // Dirty

    // Software bits (RSW)
    pub const RSW_COW: u64 = 1 << 8;     // Copy-on-Write
    pub const RSW_SPECIAL: u64 = 1 << 9;  // Special mapping (MMIO)

    // Svpbmt (Page-Based Memory Types)
    pub const PBMT_PMA: u64 = 0 << 61;    // PMA (default)
    pub const PBMT_NC: u64 = 1 << 61;     // Non-Cacheable
    pub const PBMT_IO: u64 = 2 << 61;     // I/O (strongly ordered)
    pub const PBMT_MASK: u64 = 3 << 61;

    // Svnapot (NAPOT contiguity hint)
    pub const N: u64 = 1 << 63;

    // PPN extraction
    pub const PPN_MASK: u64 = 0x003F_FFFF_FFFF_FC00; // Bits 53:10
    pub const PPN_SHIFT: u6 = 10;

    pub fn isValid(pte: u64) bool {
        return (pte & V) != 0;
    }

    pub fn isLeaf(pte: u64) bool {
        return isValid(pte) and ((pte & (R | W | X)) != 0);
    }

    pub fn isTable(pte: u64) bool {
        return isValid(pte) and ((pte & (R | W | X)) == 0);
    }

    pub fn getPhysAddr(pte: u64) u64 {
        return ((pte & PPN_MASK) >> PPN_SHIFT) << 12;
    }

    pub fn makeTable(phys: u64) u64 {
        return V | ((phys >> 12) << PPN_SHIFT);
    }

    pub fn makeLeaf(phys: u64, flags: u64) u64 {
        return V | flags | ((phys >> 12) << PPN_SHIFT);
    }

    // Common leaf PTE combinations
    pub fn kernelText(phys: u64) u64 {
        return makeLeaf(phys, R | X | A | G);
    }

    pub fn kernelRoData(phys: u64) u64 {
        return makeLeaf(phys, R | A | G);
    }

    pub fn kernelData(phys: u64) u64 {
        return makeLeaf(phys, R | W | A | D | G);
    }

    pub fn kernelMmio(phys: u64) u64 {
        return makeLeaf(phys, R | W | A | D | G | PBMT_IO);
    }

    pub fn userText(phys: u64) u64 {
        return makeLeaf(phys, R | X | U | A);
    }

    pub fn userRoData(phys: u64) u64 {
        return makeLeaf(phys, R | U | A);
    }

    pub fn userData(phys: u64) u64 {
        return makeLeaf(phys, R | W | U | A | D);
    }

    pub fn userDataCow(phys: u64) u64 {
        return makeLeaf(phys, R | U | A | RSW_COW);
    }
};

// ── Constants ─────────────────────────────────────────────────────────────
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: u6 = 12;
pub const ENTRIES_PER_TABLE: usize = 512;
pub const VPN_BITS: u6 = 9;

pub const MEGAPAGE_SIZE: u64 = 1 << 21;   // 2MB
pub const GIGAPAGE_SIZE: u64 = 1 << 30;   // 1GB
pub const TERAPAGE_SIZE: u64 = 1 << 39;   // 512GB

pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const USER_END: u64 = 0x0000_7FFF_FFFF_FFFF;
pub const MAX_ASID: u16 = 65535;

// ── Virtual Address Decomposition ─────────────────────────────────────────
pub const VAddr = struct {
    l0: u9,    // VPN[3] — bits 47:39
    l1: u9,    // VPN[2] — bits 38:30
    l2: u9,    // VPN[1] — bits 29:21
    l3: u9,    // VPN[0] — bits 20:12
    offset: u12,

    pub fn from(va: u64) VAddr {
        return .{
            .l0 = @truncate((va >> 39) & 0x1FF),
            .l1 = @truncate((va >> 30) & 0x1FF),
            .l2 = @truncate((va >> 21) & 0x1FF),
            .l3 = @truncate((va >> 12) & 0x1FF),
            .offset = @truncate(va & 0xFFF),
        };
    }
};

// ── Page Table ────────────────────────────────────────────────────────────
pub const PageTable = struct {
    entries: [ENTRIES_PER_TABLE]u64 align(PAGE_SIZE),

    const Self = @This();

    pub fn init() Self {
        return .{ .entries = [_]u64{0} ** ENTRIES_PER_TABLE };
    }

    pub fn clear(self: *Self) void {
        @memset(&self.entries, 0);
    }
};

// ── ASID Manager ──────────────────────────────────────────────────────────
const ASID_BITMAP_SIZE: usize = (MAX_ASID + 1) / 64;
var asid_bitmap: [ASID_BITMAP_SIZE]u64 = [_]u64{0} ** ASID_BITMAP_SIZE;
var next_asid: u16 = 1;

pub fn allocAsid() u16 {
    var attempts: usize = 0;
    while (attempts < MAX_ASID) : (attempts += 1) {
        const asid = next_asid;
        next_asid +%= 1;
        if (next_asid == 0) next_asid = 1;

        const word = asid / 64;
        const bit: u6 = @truncate(asid % 64);
        if (asid_bitmap[word] & (@as(u64, 1) << bit) == 0) {
            asid_bitmap[word] |= @as(u64, 1) << bit;
            return asid;
        }
    }
    // Exhausted — flush all
    @memset(&asid_bitmap, 0);
    next_asid = 1;
    boot.sfenceVma();
    return allocAsid();
}

pub fn freeAsid(asid: u16) void {
    if (asid == 0) return;
    const word = asid / 64;
    const bit: u6 = @truncate(asid % 64);
    asid_bitmap[word] &= ~(@as(u64, 1) << bit);
}

// ── Address Space ─────────────────────────────────────────────────────────
pub const AddressSpace = struct {
    root_phys: u64,     // Physical address of root page table
    asid: u16,
    page_count: u64,
    table_count: u64,

    const Self = @This();

    pub fn create() ?Self {
        const root = allocPageTable() orelse return null;
        return Self{
            .root_phys = root,
            .asid = allocAsid(),
            .page_count = 0,
            .table_count = 1,
        };
    }

    pub fn mapPage(self: *Self, vaddr: u64, paddr: u64, flags: u64) !void {
        const parts = VAddr.from(vaddr);
        var table_phys = self.root_phys;

        // Walk L0 → L1 → L2 → L3
        table_phys = try self.ensureTable(table_phys, parts.l0);
        table_phys = try self.ensureTable(table_phys, parts.l1);
        table_phys = try self.ensureTable(table_phys, parts.l2);

        // Set L3 leaf PTE
        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        table.entries[parts.l3] = PTE.makeLeaf(paddr, flags);
        self.page_count += 1;
    }

    pub fn mapMegapage(self: *Self, vaddr: u64, paddr: u64, flags: u64) !void {
        const parts = VAddr.from(vaddr);
        var table_phys = self.root_phys;

        table_phys = try self.ensureTable(table_phys, parts.l0);
        table_phys = try self.ensureTable(table_phys, parts.l1);

        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        table.entries[parts.l2] = PTE.makeLeaf(paddr, flags);
    }

    pub fn mapGigapage(self: *Self, vaddr: u64, paddr: u64, flags: u64) !void {
        const parts = VAddr.from(vaddr);
        var table_phys = self.root_phys;

        table_phys = try self.ensureTable(table_phys, parts.l0);

        const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
        table.entries[parts.l1] = PTE.makeLeaf(paddr, flags);
    }

    pub fn unmapPage(self: *Self, vaddr: u64) void {
        const parts = VAddr.from(vaddr);
        var table_phys = self.root_phys;

        // Walk to L3
        const l0: *PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isTable(l0.entries[parts.l0])) return;
        table_phys = PTE.getPhysAddr(l0.entries[parts.l0]);

        const l1: *PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isTable(l1.entries[parts.l1])) return;
        table_phys = PTE.getPhysAddr(l1.entries[parts.l1]);

        const l2: *PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isTable(l2.entries[parts.l2])) return;
        table_phys = PTE.getPhysAddr(l2.entries[parts.l2]);

        const l3: *PageTable = @ptrFromInt(physToVirt(table_phys));
        l3.entries[parts.l3] = 0;
        self.page_count -|= 1;

        boot.sfenceVmaAddrAsid(vaddr, @as(u64, self.asid));
    }

    pub fn translate(self: *const Self, vaddr: u64) ?u64 {
        const parts = VAddr.from(vaddr);
        var table_phys = self.root_phys;

        const l0: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isValid(l0.entries[parts.l0])) return null;
        if (PTE.isLeaf(l0.entries[parts.l0])) return PTE.getPhysAddr(l0.entries[parts.l0]); // 512GB terapage
        table_phys = PTE.getPhysAddr(l0.entries[parts.l0]);

        const l1: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isValid(l1.entries[parts.l1])) return null;
        if (PTE.isLeaf(l1.entries[parts.l1])) return PTE.getPhysAddr(l1.entries[parts.l1]) + (@as(u64, parts.l2) << 21) + (@as(u64, parts.l3) << 12) + parts.offset;
        table_phys = PTE.getPhysAddr(l1.entries[parts.l1]);

        const l2: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isValid(l2.entries[parts.l2])) return null;
        if (PTE.isLeaf(l2.entries[parts.l2])) return PTE.getPhysAddr(l2.entries[parts.l2]) + (@as(u64, parts.l3) << 12) + parts.offset;
        table_phys = PTE.getPhysAddr(l2.entries[parts.l2]);

        const l3: *const PageTable = @ptrFromInt(physToVirt(table_phys));
        if (!PTE.isLeaf(l3.entries[parts.l3])) return null;
        return PTE.getPhysAddr(l3.entries[parts.l3]) + parts.offset;
    }

    pub fn switchTo(self: *const Self) void {
        const satp = boot.SATP.build(boot.SATP.MODE_SV48, self.asid, self.root_phys);
        boot.csrWrite(boot.CSR.SATP, satp);
        boot.sfenceVma();
    }

    fn ensureTable(self: *Self, parent_phys: u64, index: u9) !u64 {
        const table: *PageTable = @ptrFromInt(physToVirt(parent_phys));
        if (PTE.isTable(table.entries[index])) {
            return PTE.getPhysAddr(table.entries[index]);
        }
        const new_phys = allocPageTable() orelse return error.OutOfMemory;
        const new_table: *PageTable = @ptrFromInt(physToVirt(new_phys));
        new_table.clear();
        table.entries[index] = PTE.makeTable(new_phys);
        self.table_count += 1;
        return new_phys;
    }

    pub fn destroy(self: *Self) void {
        freePageTablesRecursive(self.root_phys, 0);
        freeAsid(self.asid);
    }
};

fn freePageTablesRecursive(table_phys: u64, level: u8) void {
    if (level >= 4) return;
    const table: *PageTable = @ptrFromInt(physToVirt(table_phys));
    var i: usize = 0;
    while (i < ENTRIES_PER_TABLE) : (i += 1) {
        if (PTE.isTable(table.entries[i]) and level < 3) {
            freePageTablesRecursive(PTE.getPhysAddr(table.entries[i]), level + 1);
        }
    }
    freePageTable(table_phys);
}

// ── Page Fault Handling ───────────────────────────────────────────────────
pub const FaultType = enum {
    instruction_page_fault,   // scause = 12
    load_page_fault,          // scause = 13
    store_page_fault,         // scause = 15
    instruction_access_fault, // scause = 1
    load_access_fault,        // scause = 5
    store_access_fault,       // scause = 7
};

pub const FaultInfo = struct {
    vaddr: u64,       // stval
    fault_type: FaultType,
    is_user: bool,
    scause: u64,
};

pub fn decodeFault(scause: u64, stval: u64, sstatus: u64) FaultInfo {
    const cause = scause & 0x7FFFFFFFFFFFFFFF; // Remove interrupt bit
    return .{
        .vaddr = stval,
        .fault_type = switch (cause) {
            12 => .instruction_page_fault,
            13 => .load_page_fault,
            15 => .store_page_fault,
            1 => .instruction_access_fault,
            5 => .load_access_fault,
            7 => .store_access_fault,
            else => .load_page_fault,
        },
        .is_user = (sstatus & boot.SSTATUS.SPP) == 0,
        .scause = scause,
    };
}

// ── TLB Management ────────────────────────────────────────────────────────
pub fn flushTlbAll() void {
    boot.sfenceVma();
}

pub fn flushTlbPage(vaddr: u64) void {
    boot.sfenceVmaAddr(vaddr);
}

pub fn flushTlbAsid(asid: u16) void {
    boot.sfenceVmaAsid(@as(u64, asid));
}

pub fn flushTlbPageAsid(vaddr: u64, asid: u16) void {
    boot.sfenceVmaAddrAsid(vaddr, @as(u64, asid));
}

// ── Address Helpers ───────────────────────────────────────────────────────
pub fn physToVirt(phys: u64) u64 {
    return phys + KERNEL_BASE;
}

pub fn virtToPhys(virt: u64) u64 {
    return virt - KERNEL_BASE;
}

// ── Page Table Pool ──────────────────────────────────────────────────────
var pt_pool: [4096]PageTable align(PAGE_SIZE) = undefined;
var pt_next: usize = 0;

fn allocPageTable() ?u64 {
    if (pt_next >= pt_pool.len) return null;
    const table = &pt_pool[pt_next];
    table.clear();
    pt_next += 1;
    return @intFromPtr(table);
}

fn freePageTable(phys: u64) void {
    const table: *PageTable = @ptrFromInt(physToVirt(phys));
    table.clear();
}
