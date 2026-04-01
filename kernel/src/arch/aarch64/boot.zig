// =============================================================================
// Zxyphor Kernel — ARM64 (AArch64) Boot Subsystem
// =============================================================================
// Handles the complete ARM64 boot sequence from EL2/EL3 entry through to
// kernel_main handoff. Implements device tree parsing, initial page table
// construction, and exception level transitions per ARMv8-A Architecture
// Reference Manual.
//
// Boot flow:
//   1. Entry at _start (EL2 or EL1 depending on firmware)
//   2. Disable interrupts, set up initial stack
//   3. If EL2: configure HCR_EL2, drop to EL1
//   4. Zero BSS section
//   5. Parse device tree blob (DTB) for memory layout
//   6. Build initial identity + higher-half page tables
//   7. Enable MMU with MAIR/TCR/SCTLR configuration
//   8. Jump to higher-half kernel_main
// =============================================================================

const std = @import("std");

// ── Exception Level Constants ──────────────────────────────────────────────
pub const ExceptionLevel = enum(u2) {
    el0 = 0,
    el1 = 1,
    el2 = 2,
    el3 = 3,
};

// ── SCTLR_EL1 Bit Definitions (System Control Register) ───────────────────
pub const SCTLR = struct {
    pub const M: u64 = 1 << 0;        // MMU enable
    pub const A: u64 = 1 << 1;        // Alignment check enable
    pub const C: u64 = 1 << 2;        // Data cache enable
    pub const SA: u64 = 1 << 3;       // Stack alignment check
    pub const SA0: u64 = 1 << 4;      // Stack alignment check EL0
    pub const CP15BEN: u64 = 1 << 5;  // CP15 barrier enable
    pub const nAA: u64 = 1 << 6;      // Non-aligned access
    pub const ITD: u64 = 1 << 7;      // IT Disable
    pub const SED: u64 = 1 << 8;      // SETEND Disable
    pub const UMA: u64 = 1 << 9;      // User Mask Access
    pub const EnRCTX: u64 = 1 << 10;  // Enable EL0 RCTX
    pub const EOS: u64 = 1 << 11;     // Exception exit is context sync
    pub const I: u64 = 1 << 12;       // Instruction cache enable
    pub const EnDB: u64 = 1 << 13;    // Pointer auth (data B key)
    pub const DZE: u64 = 1 << 14;     // DC ZVA access from EL0
    pub const UCT: u64 = 1 << 15;     // EL0 access to CTR_EL0
    pub const nTWI: u64 = 1 << 16;    // Not trap WFI
    pub const nTWE: u64 = 1 << 18;    // Not trap WFE
    pub const WXN: u64 = 1 << 19;     // Write permission implies XN
    pub const TSCXT: u64 = 1 << 20;   // Trap EL0 SCXT access
    pub const IESB: u64 = 1 << 21;    // Implicit error sync barrier
    pub const EIS: u64 = 1 << 22;     // Exception entry is context sync
    pub const SPAN: u64 = 1 << 23;    // Set Privileged Access Never
    pub const E0E: u64 = 1 << 24;     // Endianness of EL0
    pub const EE: u64 = 1 << 25;      // Endianness of EL1
    pub const UCI: u64 = 1 << 26;     // EL0 cache maintenance
    pub const EnDA: u64 = 1 << 27;    // Pointer auth (data A key)
    pub const nTLSMD: u64 = 1 << 28;  // No Trap LDR/STR Multiple to Device
    pub const LSMAOE: u64 = 1 << 29;  // Load/Store Multiple Atomicity/Ordering
    pub const EnIB: u64 = 1 << 30;    // Pointer auth (instruction B key)
    pub const EnIA: u64 = 1 << 31;    // Pointer auth (instruction A key)
};

// ── HCR_EL2 Bit Definitions (Hypervisor Configuration Register) ───────────
pub const HCR_EL2 = struct {
    pub const VM: u64 = 1 << 0;       // Virtualization enable
    pub const SWIO: u64 = 1 << 1;     // Set/Way invalidation override
    pub const PTW: u64 = 1 << 2;      // Protected Table Walk
    pub const FMO: u64 = 1 << 3;      // Physical FIQ routing
    pub const IMO: u64 = 1 << 4;      // Physical IRQ routing
    pub const AMO: u64 = 1 << 5;      // Physical SError routing
    pub const VF: u64 = 1 << 6;       // Virtual FIQ injection
    pub const VI: u64 = 1 << 7;       // Virtual IRQ injection
    pub const VSE: u64 = 1 << 8;      // Virtual SError injection
    pub const FB: u64 = 1 << 9;       // Force broadcast
    pub const BSU_INNER: u64 = 1 << 10; // Barrier shareability upgrade
    pub const BSU_OUTER: u64 = 2 << 10;
    pub const BSU_FULL: u64 = 3 << 10;
    pub const DC: u64 = 1 << 12;      // Default cacheability
    pub const TWI: u64 = 1 << 13;     // Trap WFI
    pub const TWE: u64 = 1 << 14;     // Trap WFE
    pub const TID0: u64 = 1 << 15;    // Trap ID group 0
    pub const TID1: u64 = 1 << 16;    // Trap ID group 1
    pub const TID2: u64 = 1 << 17;    // Trap ID group 2
    pub const TID3: u64 = 1 << 18;    // Trap ID group 3
    pub const TSC: u64 = 1 << 19;     // Trap SMC instruction
    pub const TIDCP: u64 = 1 << 20;   // Trap implementation defined
    pub const TACR: u64 = 1 << 21;    // Trap auxiliary control registers
    pub const TSW: u64 = 1 << 22;     // Trap data/unified cache
    pub const TPCP: u64 = 1 << 23;    // Trap data/unified cache by PoC
    pub const TPU: u64 = 1 << 24;     // Trap cache maintenance PoU
    pub const TTLB: u64 = 1 << 25;    // Trap TLB maintenance
    pub const TVM: u64 = 1 << 26;     // Trap virtual memory controls
    pub const TGE: u64 = 1 << 27;     // Trap general exceptions
    pub const TDZ: u64 = 1 << 28;     // Trap DC ZVA instructions
    pub const HCD: u64 = 1 << 29;     // HVC instruction disable
    pub const TRVM: u64 = 1 << 30;    // Trap reads of virtual memory
    pub const RW: u64 = 1 << 31;      // Lower EL is AArch64
    pub const CD: u64 = 1 << 32;      // Stage 2 cacheability disable
    pub const ID: u64 = 1 << 33;      // Stage 2 instruction access
    pub const E2H: u64 = 1 << 34;     // EL2 Host mode
    pub const TLOR: u64 = 1 << 35;    // Trap LOR registers
    pub const TERR: u64 = 1 << 36;    // Trap Error record accesses
    pub const TEA: u64 = 1 << 37;     // Route synchronous external abort
    pub const MIOCNCE: u64 = 1 << 38; // Mismatched Inner/Outer Cacheable Non-Coherency
    pub const APK: u64 = 1 << 40;     // Trap key values (Pointer Auth)
    pub const API: u64 = 1 << 41;     // Trap instructions (Pointer Auth)
    pub const NV: u64 = 1 << 42;      // Nested Virtualization
    pub const NV1: u64 = 1 << 43;     // Nested Virtualization (1)
    pub const AT: u64 = 1 << 44;      // Address translation
    pub const NV2: u64 = 1 << 45;     // Nested Virtualization (2)
};

// ── TCR_EL1 Bit Definitions (Translation Control Register) ────────────────
pub const TCR = struct {
    pub const T0SZ_SHIFT: u6 = 0;
    pub const EPD0: u64 = 1 << 7;       // Translation table walk disable for TTBR0
    pub const IRGN0_WB_WA: u64 = 1 << 8;  // Inner cacheability
    pub const ORGN0_WB_WA: u64 = 1 << 10; // Outer cacheability
    pub const SH0_INNER: u64 = 3 << 12;   // Inner shareable
    pub const TG0_4K: u64 = 0 << 14;      // 4KB granule for TTBR0
    pub const TG0_64K: u64 = 1 << 14;     // 64KB granule
    pub const TG0_16K: u64 = 2 << 14;     // 16KB granule
    pub const T1SZ_SHIFT: u6 = 16;
    pub const A1: u64 = 1 << 22;        // ASID select
    pub const EPD1: u64 = 1 << 23;      // Translation table walk disable for TTBR1
    pub const IRGN1_WB_WA: u64 = 1 << 24;
    pub const ORGN1_WB_WA: u64 = 1 << 26;
    pub const SH1_INNER: u64 = 3 << 28;
    pub const TG1_4K: u64 = 2 << 30;    // 4KB granule for TTBR1
    pub const TG1_16K: u64 = 1 << 30;
    pub const TG1_64K: u64 = 3 << 30;
    pub const IPS_32: u64 = 0 << 32;    // 32-bit PA (4GB)
    pub const IPS_36: u64 = 1 << 32;    // 36-bit PA (64GB)
    pub const IPS_40: u64 = 2 << 32;    // 40-bit PA (1TB)
    pub const IPS_42: u64 = 3 << 32;    // 42-bit PA (4TB)
    pub const IPS_44: u64 = 4 << 32;    // 44-bit PA (16TB)
    pub const IPS_48: u64 = 5 << 32;    // 48-bit PA (256TB)
    pub const IPS_52: u64 = 6 << 32;    // 52-bit PA (4PB)
    pub const AS_16: u64 = 1 << 36;     // 16-bit ASID
    pub const TBI0: u64 = 1 << 37;      // Top byte ignored (TTBR0)
    pub const TBI1: u64 = 1 << 38;      // Top byte ignored (TTBR1)
    pub const HA: u64 = 1 << 39;        // Hardware Access flag update
    pub const HD: u64 = 1 << 40;        // Hardware Dirty flag update
    pub const HPD0: u64 = 1 << 41;      // Hierarchical permission disables
    pub const HPD1: u64 = 1 << 42;
    pub const HWU059: u64 = 1 << 43;    // Hardware use fields
    pub const HWU060: u64 = 1 << 44;
    pub const HWU061: u64 = 1 << 45;
    pub const HWU062: u64 = 1 << 46;
    pub const HWU159: u64 = 1 << 47;
    pub const HWU160: u64 = 1 << 48;
    pub const HWU161: u64 = 1 << 49;
    pub const HWU162: u64 = 1 << 50;
    pub const TBID0: u64 = 1 << 51;
    pub const TBID1: u64 = 1 << 52;
    pub const NFD0: u64 = 1 << 53;
    pub const NFD1: u64 = 1 << 54;
    pub const E0PD0: u64 = 1 << 55;    // EL0 privileged disable
    pub const E0PD1: u64 = 1 << 56;
    pub const TCMA0: u64 = 1 << 57;    // Tag check MTE override
    pub const TCMA1: u64 = 1 << 58;
    pub const DS: u64 = 1 << 59;       // 52-bit descriptor support
};

// ── MAIR_EL1 Attribute Definitions (Memory Attribute Indirection Register) ─
pub const MAIR = struct {
    // Attribute index definitions for page table entries
    pub const DEVICE_nGnRnE: u8 = 0x00;  // Device-nGnRnE (strongly ordered)
    pub const DEVICE_nGnRE: u8 = 0x04;   // Device-nGnRE
    pub const DEVICE_GRE: u8 = 0x0C;     // Device-GRE
    pub const NORMAL_NC: u8 = 0x44;      // Normal Non-Cacheable
    pub const NORMAL_WT: u8 = 0xBB;      // Normal Write-Through
    pub const NORMAL_WB: u8 = 0xFF;      // Normal Write-Back (RW Allocate)
    pub const NORMAL_TAGGED: u8 = 0xF0;  // Tagged Normal (MTE)

    // Standard attribute indices used in page table entries
    pub const ATTR_IDX_DEVICE_nGnRnE: u64 = 0;
    pub const ATTR_IDX_DEVICE_nGnRE: u64 = 1;
    pub const ATTR_IDX_NORMAL_NC: u64 = 2;
    pub const ATTR_IDX_NORMAL_WT: u64 = 3;
    pub const ATTR_IDX_NORMAL_WB: u64 = 4;
    pub const ATTR_IDX_NORMAL_TAGGED: u64 = 5;

    pub fn build() u64 {
        return @as(u64, DEVICE_nGnRnE) << (8 * 0) |
               @as(u64, DEVICE_nGnRE) << (8 * 1) |
               @as(u64, NORMAL_NC) << (8 * 2) |
               @as(u64, NORMAL_WT) << (8 * 3) |
               @as(u64, NORMAL_WB) << (8 * 4) |
               @as(u64, NORMAL_TAGGED) << (8 * 5);
    }
};

// ── Page Table Entry Flags (AArch64 VMSAv8-64) ───────────────────────────
pub const PTE = struct {
    pub const VALID: u64 = 1 << 0;
    pub const TABLE: u64 = 1 << 1;      // Table descriptor (level 0-2)
    pub const PAGE: u64 = 1 << 1;       // Page descriptor (level 3)
    pub const ATTR_IDX_SHIFT: u6 = 2;   // AttrIndx[2:0]
    pub const NS: u64 = 1 << 5;         // Non-Secure
    pub const AP_RW_EL1: u64 = 0 << 6;  // R/W at EL1, none at EL0
    pub const AP_RW_ALL: u64 = 1 << 6;  // R/W at EL1 and EL0
    pub const AP_RO_EL1: u64 = 2 << 6;  // R/O at EL1, none at EL0
    pub const AP_RO_ALL: u64 = 3 << 6;  // R/O at both EL1 and EL0
    pub const SH_NON: u64 = 0 << 8;     // Non-shareable
    pub const SH_OUTER: u64 = 2 << 8;   // Outer shareable
    pub const SH_INNER: u64 = 3 << 8;   // Inner shareable
    pub const AF: u64 = 1 << 10;        // Access Flag
    pub const nG: u64 = 1 << 11;        // Not Global
    pub const DBM: u64 = 1 << 51;       // Dirty Bit Modifier
    pub const CONTIGUOUS: u64 = 1 << 52; // Contiguous hint
    pub const PXN: u64 = 1 << 53;       // Privileged eXecute Never
    pub const UXN: u64 = 1 << 54;       // Unprivileged eXecute Never (XN)

    pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    pub fn table_entry(addr: u64) u64 {
        return (addr & ADDR_MASK) | TABLE | VALID;
    }

    pub fn block_entry(addr: u64, attr_idx: u64, flags: u64) u64 {
        return (addr & ADDR_MASK) | (attr_idx << ATTR_IDX_SHIFT) | flags | AF | VALID;
    }

    pub fn page_entry(addr: u64, attr_idx: u64, flags: u64) u64 {
        return (addr & ADDR_MASK) | (attr_idx << ATTR_IDX_SHIFT) | flags | AF | PAGE | VALID;
    }
};

// ── Kernel Address Space Layout ───────────────────────────────────────────
pub const KERNEL_VMA: u64 = 0xFFFF_8000_0000_0000;      // Kernel virtual base (upper half)
pub const KERNEL_PHYS_BASE: u64 = 0x4000_0000;            // Default RAM start (1GB)
pub const KERNEL_STACK_SIZE: usize = 64 * 1024;           // 64KB kernel stack
pub const KERNEL_HEAP_START: u64 = KERNEL_VMA + 0x1000_0000;
pub const KERNEL_HEAP_SIZE: usize = 256 * 1024 * 1024;    // 256MB initial heap
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: u6 = 12;
pub const ENTRIES_PER_TABLE: usize = 512;

// ── Device Tree Blob (DTB) Parser ─────────────────────────────────────────
pub const FDT_MAGIC: u32 = 0xD00DFEED;
pub const FDT_BEGIN_NODE: u32 = 0x00000001;
pub const FDT_END_NODE: u32 = 0x00000002;
pub const FDT_PROP: u32 = 0x00000003;
pub const FDT_NOP: u32 = 0x00000004;
pub const FDT_END: u32 = 0x00000009;

pub const FdtHeader = extern struct {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,

    pub fn validate(self: *const FdtHeader) bool {
        return byteSwap32(self.magic) == FDT_MAGIC;
    }

    pub fn getTotalSize(self: *const FdtHeader) u32 {
        return byteSwap32(self.totalsize);
    }

    pub fn getStructOffset(self: *const FdtHeader) u32 {
        return byteSwap32(self.off_dt_struct);
    }

    pub fn getStringsOffset(self: *const FdtHeader) u32 {
        return byteSwap32(self.off_dt_strings);
    }

    pub fn getVersion(self: *const FdtHeader) u32 {
        return byteSwap32(self.version);
    }

    pub fn getBootCpuId(self: *const FdtHeader) u32 {
        return byteSwap32(self.boot_cpuid_phys);
    }
};

pub const FdtReserveEntry = extern struct {
    address: u64,
    size: u64,
};

pub const FdtProperty = extern struct {
    len: u32,
    nameoff: u32,
};

// Memory region descriptor from DTB parsing
pub const MemoryRegion = struct {
    base: u64,
    size: u64,
    flags: MemoryFlags,

    pub const MemoryFlags = packed struct {
        usable: bool = false,
        reserved: bool = false,
        mmio: bool = false,
        firmware: bool = false,
        acpi_reclaim: bool = false,
        acpi_nvs: bool = false,
        dma_zone: bool = false,
        highmem: bool = false,
        _pad: u24 = 0,
    };
};

pub const MAX_MEMORY_REGIONS: usize = 256;
pub const MAX_RESERVED_REGIONS: usize = 64;

pub const BootInfo = struct {
    dtb_addr: u64,
    dtb_size: u32,
    memory_regions: [MAX_MEMORY_REGIONS]MemoryRegion,
    memory_region_count: usize,
    reserved_regions: [MAX_RESERVED_REGIONS]MemoryRegion,
    reserved_region_count: usize,
    total_memory: u64,
    usable_memory: u64,
    initrd_start: u64,
    initrd_size: u64,
    cmdline: [512]u8,
    cmdline_len: usize,
    boot_cpu_id: u32,
    nr_cpus: u32,
    cpu_ids: [256]u32,
    uart_base: u64,
    uart_type: UartType,
    gic_dist_base: u64,
    gic_redist_base: u64,
    gic_version: u32,
    timer_freq: u32,
    pci_ecam_base: u64,
    pci_ecam_size: u64,
    pci_ranges: [8]PciRange,
    pci_range_count: usize,

    pub const UartType = enum(u8) {
        unknown = 0,
        pl011 = 1,
        ns16550 = 2,
        samsung = 3,
        cdns = 4,
    };

    pub const PciRange = struct {
        bus_start: u64,
        cpu_start: u64,
        size: u64,
        space_type: enum(u8) { config = 0, io = 1, mem32 = 2, mem64 = 3 },
    };

    pub fn init() BootInfo {
        var info: BootInfo = undefined;
        @memset(@as([*]u8, @ptrCast(&info))[0..@sizeOf(BootInfo)], 0);
        return info;
    }
};

var boot_info: BootInfo = BootInfo.init();

// ── DTB Parser Implementation ─────────────────────────────────────────────
pub const DtbParser = struct {
    base: [*]const u8,
    header: *const FdtHeader,
    struct_base: [*]const u8,
    strings_base: [*]const u8,
    info: *BootInfo,

    const Self = @This();

    pub fn init(dtb_addr: u64, info: *BootInfo) ?Self {
        const base: [*]const u8 = @ptrFromInt(dtb_addr);
        const header: *const FdtHeader = @ptrCast(@alignCast(base));

        if (!header.validate()) {
            return null;
        }

        info.dtb_addr = dtb_addr;
        info.dtb_size = header.getTotalSize();

        return Self{
            .base = base,
            .header = header,
            .struct_base = base + header.getStructOffset(),
            .strings_base = base + header.getStringsOffset(),
            .info = info,
        };
    }

    pub fn parse(self: *Self) void {
        self.parseReservedMemory();
        self.parseStructure();
        self.info.boot_cpu_id = self.header.getBootCpuId();
    }

    fn parseReservedMemory(self: *Self) void {
        const rsvmap_off = byteSwap32(self.header.off_mem_rsvmap);
        var ptr = self.base + rsvmap_off;
        var count: usize = 0;

        while (count < MAX_RESERVED_REGIONS) {
            const entry: *const FdtReserveEntry = @ptrCast(@alignCast(ptr));
            const address = byteSwap64(entry.address);
            const size = byteSwap64(entry.size);

            if (address == 0 and size == 0) break;

            self.info.reserved_regions[count] = MemoryRegion{
                .base = address,
                .size = size,
                .flags = .{ .reserved = true },
            };
            count += 1;
            ptr += @sizeOf(FdtReserveEntry);
        }
        self.info.reserved_region_count = count;
    }

    fn parseStructure(self: *Self) void {
        var offset: usize = 0;
        var depth: i32 = 0;
        var in_memory: bool = false;
        var in_chosen: bool = false;
        var in_cpus: bool = false;
        var in_cpu: bool = false;
        var in_gic: bool = false;
        var in_uart: bool = false;
        var in_pci: bool = false;

        while (offset < self.header.getTotalSize()) {
            const token = self.readU32(offset);
            offset += 4;

            switch (token) {
                FDT_BEGIN_NODE => {
                    const name = self.readString(offset);
                    offset += alignUp(name.len + 1, 4);
                    depth += 1;

                    if (depth == 1) {
                        in_memory = startsWith(name, "memory");
                        in_chosen = streq(name, "chosen");
                        in_cpus = streq(name, "cpus");
                        in_gic = startsWith(name, "interrupt-controller") or startsWith(name, "gic");
                        in_uart = startsWith(name, "serial") or startsWith(name, "uart") or startsWith(name, "pl011");
                        in_pci = startsWith(name, "pci") or startsWith(name, "pcie");
                    }
                    if (depth == 2 and in_cpus) {
                        in_cpu = startsWith(name, "cpu@");
                    }
                },
                FDT_END_NODE => {
                    depth -= 1;
                    if (depth <= 0) {
                        in_memory = false;
                        in_chosen = false;
                        in_cpus = false;
                        in_gic = false;
                        in_uart = false;
                        in_pci = false;
                    }
                    if (depth <= 1) {
                        in_cpu = false;
                    }
                },
                FDT_PROP => {
                    const prop: *const FdtProperty = @ptrCast(@alignCast(self.struct_base + offset));
                    const prop_len = byteSwap32(prop.len);
                    const name_off = byteSwap32(prop.nameoff);
                    offset += 8;
                    const prop_name = self.readStringFromStrings(name_off);
                    const prop_data = self.struct_base + offset;

                    if (in_memory and streq(prop_name, "reg")) {
                        self.parseMemoryReg(prop_data, prop_len);
                    }
                    if (in_chosen) {
                        self.parseChosenProp(prop_name, prop_data, prop_len);
                    }
                    if (in_cpu and streq(prop_name, "reg")) {
                        if (self.info.nr_cpus < 256) {
                            const cpu_id = readBE32(prop_data);
                            self.info.cpu_ids[self.info.nr_cpus] = cpu_id;
                            self.info.nr_cpus += 1;
                        }
                    }
                    if (in_gic and streq(prop_name, "reg")) {
                        self.parseGicReg(prop_data, prop_len);
                    }
                    if (in_uart and streq(prop_name, "reg")) {
                        if (self.info.uart_base == 0) {
                            self.info.uart_base = readBE64(prop_data);
                        }
                    }
                    if (in_uart and streq(prop_name, "compatible")) {
                        self.parseUartCompat(prop_data, prop_len);
                    }
                    if (in_pci and streq(prop_name, "reg")) {
                        self.info.pci_ecam_base = readBE64(prop_data);
                        if (prop_len >= 16) {
                            self.info.pci_ecam_size = readBE64(prop_data + 8);
                        }
                    }

                    offset += alignUp(prop_len, 4);
                },
                FDT_NOP => {},
                FDT_END => break,
                else => break,
            }
        }

        // Calculate totals
        var total: u64 = 0;
        var usable: u64 = 0;
        for (self.info.memory_regions[0..self.info.memory_region_count]) |region| {
            total += region.size;
            if (region.flags.usable) usable += region.size;
        }
        self.info.total_memory = total;
        self.info.usable_memory = usable;
    }

    fn parseMemoryReg(self: *Self, data: [*]const u8, len: u32) void {
        var off: usize = 0;
        while (off + 16 <= len and self.info.memory_region_count < MAX_MEMORY_REGIONS) {
            const base = readBE64(data + off);
            const size = readBE64(data + off + 8);
            if (size > 0) {
                self.info.memory_regions[self.info.memory_region_count] = MemoryRegion{
                    .base = base,
                    .size = size,
                    .flags = .{ .usable = true },
                };
                self.info.memory_region_count += 1;
            }
            off += 16;
        }
    }

    fn parseChosenProp(self: *Self, name: []const u8, data: [*]const u8, len: u32) void {
        if (streq(name, "bootargs") and len > 0) {
            const copy_len = @min(len - 1, self.info.cmdline.len);
            @memcpy(self.info.cmdline[0..copy_len], data[0..copy_len]);
            self.info.cmdline_len = copy_len;
        }
        if (streq(name, "linux,initrd-start") and len >= 4) {
            self.info.initrd_start = if (len >= 8) readBE64(data) else readBE32(data);
        }
        if (streq(name, "linux,initrd-end") and len >= 4) {
            const end = if (len >= 8) readBE64(data) else readBE32(data);
            self.info.initrd_size = end - self.info.initrd_start;
        }
    }

    fn parseGicReg(self: *Self, data: [*]const u8, len: u32) void {
        if (len >= 16) {
            self.info.gic_dist_base = readBE64(data);
        }
        if (len >= 32) {
            self.info.gic_redist_base = readBE64(data + 16);
        }
        self.info.gic_version = if (len >= 48) 3 else 2;
    }

    fn parseUartCompat(self: *Self, data: [*]const u8, len: u32) void {
        const compat = data[0..@min(len, 64)];
        if (containsStr(compat, "pl011")) {
            self.info.uart_type = .pl011;
        } else if (containsStr(compat, "ns16550") or containsStr(compat, "8250")) {
            self.info.uart_type = .ns16550;
        } else if (containsStr(compat, "samsung")) {
            self.info.uart_type = .samsung;
        }
    }

    fn readU32(self: *Self, offset: usize) u32 {
        const ptr: *const u32 = @ptrCast(@alignCast(self.struct_base + offset));
        return byteSwap32(ptr.*);
    }

    fn readString(self: *Self, offset: usize) []const u8 {
        const ptr = self.struct_base + offset;
        var len: usize = 0;
        while (ptr[len] != 0 and len < 256) : (len += 1) {}
        return ptr[0..len];
    }

    fn readStringFromStrings(self: *Self, offset: u32) []const u8 {
        const ptr = self.strings_base + offset;
        var len: usize = 0;
        while (ptr[len] != 0 and len < 256) : (len += 1) {}
        return ptr[0..len];
    }
};

// ── Initial Page Tables ───────────────────────────────────────────────────
// ARM64 uses 4-level page tables (4KB granule):
//   Level 0 (PGD): Bits 47..39 — 512GB per entry
//   Level 1 (PUD): Bits 38..30 — 1GB per entry (block mappings)
//   Level 2 (PMD): Bits 29..21 — 2MB per entry (block mappings)
//   Level 3 (PTE): Bits 20..12 — 4KB per entry

pub const InitialPageTables = struct {
    // We need at minimum:
    //   1 × Level 0 table (for both identity + higher-half map)
    //   2 × Level 1 tables (1 for identity, 1 for higher-half)
    //   Additional Level 2 tables as needed
    const MAX_TABLES: usize = 32;

    tables: [MAX_TABLES][ENTRIES_PER_TABLE]u64 align(PAGE_SIZE),
    next_table: usize,

    const Self = @This();

    pub fn init() Self {
        var self = Self{
            .tables = undefined,
            .next_table = 0,
        };
        for (&self.tables) |*table| {
            @memset(table, 0);
        }
        return self;
    }

    pub fn allocTable(self: *Self) ?*[ENTRIES_PER_TABLE]u64 {
        if (self.next_table >= MAX_TABLES) return null;
        const table = &self.tables[self.next_table];
        self.next_table += 1;
        return table;
    }

    pub fn tablePhysAddr(self: *Self, table: *[ENTRIES_PER_TABLE]u64) u64 {
        const base = @intFromPtr(&self.tables[0]);
        const addr = @intFromPtr(table);
        return addr - base + @as(u64, @intFromPtr(&self.tables[0]));
    }

    // Map a 1GB block (Level 1 block descriptor)
    pub fn mapBlock1G(table: *[ENTRIES_PER_TABLE]u64, vaddr: u64, paddr: u64, attr_idx: u64, flags: u64) void {
        const index = (vaddr >> 30) & 0x1FF;
        table[index] = PTE.block_entry(paddr, attr_idx, flags);
    }

    // Map a 2MB block (Level 2 block descriptor)
    pub fn mapBlock2M(table: *[ENTRIES_PER_TABLE]u64, vaddr: u64, paddr: u64, attr_idx: u64, flags: u64) void {
        const index = (vaddr >> 21) & 0x1FF;
        table[index] = PTE.block_entry(paddr, attr_idx, flags);
    }

    // Build identity + higher-half mappings for boot
    pub fn buildBootTables(self: *Self, total_ram: u64) !void {
        // Allocate L0 table (PGD)
        const pgd = self.allocTable() orelse return error.OutOfTables;

        // Allocate L1 tables (PUD)
        const pud_identity = self.allocTable() orelse return error.OutOfTables;
        const pud_kernel = self.allocTable() orelse return error.OutOfTables;

        // Link L0 -> L1
        pgd[0] = PTE.table_entry(@intFromPtr(pud_identity)); // Identity map at VA 0x0
        const kernel_pgd_idx = (KERNEL_VMA >> 39) & 0x1FF;
        pgd[kernel_pgd_idx] = PTE.table_entry(@intFromPtr(pud_kernel)); // Higher-half

        // Map first N GB as 1GB blocks for identity mapping
        const gb_count = @min((total_ram + 0x3FFF_FFFF) >> 30, ENTRIES_PER_TABLE);
        var i: usize = 0;
        while (i < gb_count) : (i += 1) {
            const addr: u64 = @as(u64, @intCast(i)) << 30;
            // Normal memory with Write-Back caching
            mapBlock1G(pud_identity, addr, addr, MAIR.ATTR_IDX_NORMAL_WB, PTE.SH_INNER | PTE.AP_RW_EL1);
            // Same mapping in kernel space
            mapBlock1G(pud_kernel, KERNEL_VMA + addr, addr, MAIR.ATTR_IDX_NORMAL_WB, PTE.SH_INNER | PTE.AP_RW_EL1);
        }

        // Map device regions (MMIO) — typically 0x0000_0000 to 0x3FFF_FFFF on many SoCs
        mapBlock1G(pud_identity, 0, 0, MAIR.ATTR_IDX_DEVICE_nGnRnE, PTE.SH_NON | PTE.AP_RW_EL1 | PTE.PXN | PTE.UXN);
    }
};

var initial_tables: InitialPageTables = InitialPageTables.init();

// ── System Register Access (inline assembly wrappers) ─────────────────────
pub inline fn readCurrentEL() u64 {
    return asm ("mrs %[result], CurrentEL"
        : [result] "=r" (-> u64),
    );
}

pub inline fn readMpidr() u64 {
    return asm ("mrs %[result], MPIDR_EL1"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeSctlrEL1(val: u64) void {
    asm volatile ("msr SCTLR_EL1, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn readSctlrEL1() u64 {
    return asm ("mrs %[result], SCTLR_EL1"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeTcrEL1(val: u64) void {
    asm volatile ("msr TCR_EL1, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeMairEL1(val: u64) void {
    asm volatile ("msr MAIR_EL1, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeTtbr0EL1(val: u64) void {
    asm volatile ("msr TTBR0_EL1, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeTtbr1EL1(val: u64) void {
    asm volatile ("msr TTBR1_EL1, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeHcrEL2(val: u64) void {
    asm volatile ("msr HCR_EL2, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeSpsr(val: u64) void {
    asm volatile ("msr SPSR_EL2, %[val]"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeElrEL2(val: u64) void {
    asm volatile ("msr ELR_EL2, %[val]"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeSpEL1(val: u64) void {
    asm volatile ("msr SP_EL1, %[val]"
        :
        : [val] "r" (val),
    );
}

pub inline fn writeVbarEL1(val: u64) void {
    asm volatile ("msr VBAR_EL1, %[val]; isb"
        :
        : [val] "r" (val),
    );
}

pub inline fn tlbiVmalle1() void {
    asm volatile ("dsb ishst; tlbi vmalle1; dsb ish; isb");
}

pub inline fn isb() void {
    asm volatile ("isb");
}

pub inline fn dsb() void {
    asm volatile ("dsb sy");
}

pub inline fn dmb() void {
    asm volatile ("dmb sy");
}

pub inline fn wfi() void {
    asm volatile ("wfi");
}

pub inline fn wfe() void {
    asm volatile ("wfe");
}

pub inline fn sev() void {
    asm volatile ("sev");
}

pub inline fn disableInterrupts() void {
    asm volatile ("msr DAIFSet, #0xf");
}

pub inline fn enableInterrupts() void {
    asm volatile ("msr DAIFClr, #0xf");
}

// ── EL2 → EL1 Transition ─────────────────────────────────────────────────
pub fn dropToEL1(entry_point: u64, stack_top: u64) void {
    // Configure HCR_EL2: set RW bit so EL1 is AArch64
    writeHcrEL2(HCR_EL2.RW);

    // Set up SPSR for EL1h (use SP_EL1)
    // SPSR_EL2: DAIF masked, EL1h mode (0b00101 = 0x5)
    const spsr_el1h: u64 = 0x3C5; // DAIF=0xF, M=0x5 (EL1h)
    writeSpsr(spsr_el1h);

    // Set EL1 entry point and stack
    writeElrEL2(entry_point);
    writeSpEL1(stack_top);

    // ERET to EL1
    asm volatile ("eret");
}

// ── BSS Zeroing ───────────────────────────────────────────────────────────
extern var __bss_start: u8;
extern var __bss_end: u8;

pub fn zeroBss() void {
    const bss_start = @intFromPtr(&__bss_start);
    const bss_end = @intFromPtr(&__bss_end);
    const bss_size = bss_end - bss_start;
    const bss_ptr: [*]u8 = @ptrFromInt(bss_start);
    @memset(bss_ptr[0..bss_size], 0);
}

// ── MMU Enable Sequence ───────────────────────────────────────────────────
pub fn enableMMU(pgd_phys: u64) void {
    // Invalidate all TLBs
    tlbiVmalle1();

    // Set MAIR_EL1 — memory attribute indirection register
    writeMairEL1(MAIR.build());

    // Set TCR_EL1 — translation control register
    // 48-bit VA, 48-bit PA, 4KB granule, inner-shareable WB-WA
    const tcr_val: u64 = @as(u64, 16) << TCR.T0SZ_SHIFT |    // T0SZ = 16 → 48-bit VA for TTBR0
                          @as(u64, 16) << TCR.T1SZ_SHIFT |    // T1SZ = 16 → 48-bit VA for TTBR1
                          TCR.TG0_4K |
                          TCR.TG1_4K |
                          TCR.IRGN0_WB_WA |
                          TCR.ORGN0_WB_WA |
                          TCR.SH0_INNER |
                          TCR.IRGN1_WB_WA |
                          TCR.ORGN1_WB_WA |
                          TCR.SH1_INNER |
                          TCR.IPS_48 |
                          TCR.AS_16 |
                          TCR.HA |
                          TCR.HD;
    writeTcrEL1(tcr_val);

    // Set TTBR0 and TTBR1
    writeTtbr0EL1(pgd_phys);   // User-space page tables (identity for now)
    writeTtbr1EL1(pgd_phys);   // Kernel-space page tables

    // Barrier
    isb();

    // Read SCTLR_EL1... enable MMU, caches
    var sctlr = readSctlrEL1();
    sctlr |= SCTLR.M;     // MMU enable
    sctlr |= SCTLR.C;     // Data cache enable
    sctlr |= SCTLR.I;     // Instruction cache enable
    sctlr |= SCTLR.SA;    // Stack alignment check
    sctlr |= SCTLR.SA0;   // Stack alignment check EL0
    sctlr |= SCTLR.WXN;   // Write implies XN
    sctlr |= SCTLR.SPAN;  // Set PAN on exception entry
    writeSctlrEL1(sctlr);

    // Barrier after MMU enable
    isb();
    dsb();
}

// ── Early Console (UART) ──────────────────────────────────────────────────
pub const EarlyConsole = struct {
    base: u64,
    uart_type: BootInfo.UartType,

    const Self = @This();

    pub fn init(base: u64, uart_type: BootInfo.UartType) Self {
        return Self{ .base = base, .uart_type = uart_type };
    }

    pub fn putc(self: *const Self, c: u8) void {
        switch (self.uart_type) {
            .pl011 => self.pl011PutC(c),
            .ns16550 => self.ns16550PutC(c),
            else => {}, // Unknown UART — drop output
        }
    }

    pub fn puts(self: *const Self, s: []const u8) void {
        for (s) |c| {
            if (c == '\n') self.putc('\r');
            self.putc(c);
        }
    }

    fn pl011PutC(self: *const Self, c: u8) void {
        const FR_TXFF: u32 = 1 << 5; // Transmit FIFO full
        const base = self.base;
        // Wait until TX FIFO is not full
        while (mmioRead32(base + 0x18) & FR_TXFF != 0) {}
        // Write character to data register
        mmioWrite32(base + 0x00, @as(u32, c));
    }

    fn ns16550PutC(self: *const Self, c: u8) void {
        const LSR_THRE: u32 = 1 << 5; // Transmitter holding register empty
        const base = self.base;
        // Wait for THRE
        while (mmioRead32(base + 0x14) & LSR_THRE == 0) {}
        // Write character
        mmioWrite32(base + 0x00, @as(u32, c));
    }
};

var early_console: EarlyConsole = EarlyConsole.init(0, .unknown);

pub fn earlyPrintk(comptime fmt: []const u8, args: anytype) void {
    _ = args;
    early_console.puts(fmt);
}

// ── Boot Entry Point ──────────────────────────────────────────────────────
extern fn kernel_main() noreturn;

export fn _start() callconv(.Naked) noreturn {
    // Disable interrupts immediately
    asm volatile ("msr DAIFSet, #0xf");

    // Read current exception level
    // CurrentEL[3:2] contains the EL number
    asm volatile (
        \\mrs x0, CurrentEL
        \\lsr x0, x0, #2
        \\and x0, x0, #3
        \\cmp x0, #2
        \\b.eq .Lat_el2
        \\cmp x0, #1
        \\b.eq .Lat_el1
        \\b .Lhalt
        \\.Lat_el2:
        \\bl _setup_el2
        \\.Lat_el1:
        \\bl _setup_el1
        \\.Lhalt:
        \\wfi
        \\b .Lhalt
    );
    unreachable;
}

export fn _setup_el2() void {
    // Configure and drop to EL1
    disableInterrupts();

    // Allow EL1 to access timers
    const cnthctl: u64 = asm ("mrs %[r], CNTHCTL_EL2" : [r] "=r" (-> u64));
    _ = cnthctl;
    asm volatile ("msr CNTHCTL_EL2, %[v]" : : [v] "r" (@as(u64, 0x3))); // EL1PCTEN | EL1PCEN
    asm volatile ("msr CNTVOFF_EL2, xzr"); // Clear virtual counter offset

    // Disable coprocessor traps
    asm volatile ("msr CPTR_EL2, xzr");

    // Disable hypervisor traps
    asm volatile ("msr HSTR_EL2, xzr");

    // Enable FP/SIMD at EL1
    asm volatile ("mov x0, #(3 << 20); msr CPACR_EL1, x0");

    dropToEL1(@intFromPtr(&_el1_entry), 0); // stack set later
}

extern fn _el1_entry() void;

export fn _setup_el1() void {
    zeroBss();

    // Set up initial stack pointer (use a known safe location)
    extern var __stack_top: u8;
    const stack_top = @intFromPtr(&__stack_top);
    asm volatile ("mov sp, %[sp]" : : [sp] "r" (stack_top));

    // Parse DTB (x0 from firmware contains DTB address on ARM64)
    const dtb_addr: u64 = asm ("mov %[r], x0" : [r] "=r" (-> u64));
    if (dtb_addr != 0) {
        if (DtbParser.init(dtb_addr, &boot_info)) |*parser| {
            var p = parser.*;
            p.parse();
        }
    }

    // Set up early console if UART was found
    if (boot_info.uart_base != 0) {
        early_console = EarlyConsole.init(boot_info.uart_base, boot_info.uart_type);
        early_console.puts("Zxyphor Kernel v2.0 Nexus — ARM64 Boot\r\n");
    }

    // Build initial page tables
    const total_ram = if (boot_info.total_memory > 0) boot_info.total_memory else 0x1_0000_0000; // default 4GB
    initial_tables.buildBootTables(total_ram) catch {
        early_console.puts("PANIC: Failed to build boot page tables!\r\n");
        while (true) wfi();
    };

    // Enable MMU
    const pgd_phys: u64 = @intFromPtr(&initial_tables.tables[0]);
    enableMMU(pgd_phys);
    early_console.puts("MMU enabled. Jumping to kernel_main...\r\n");

    // Jump to kernel main
    kernel_main();
}

// ── Utility Functions ─────────────────────────────────────────────────────
fn byteSwap32(v: u32) u32 {
    return ((v & 0xFF) << 24) |
           ((v & 0xFF00) << 8) |
           ((v & 0xFF0000) >> 8) |
           ((v & 0xFF000000) >> 24);
}

fn byteSwap64(v: u64) u64 {
    return @as(u64, byteSwap32(@truncate(v))) << 32 |
           @as(u64, byteSwap32(@truncate(v >> 32)));
}

fn readBE32(ptr: [*]const u8) u32 {
    return @as(u32, ptr[0]) << 24 |
           @as(u32, ptr[1]) << 16 |
           @as(u32, ptr[2]) << 8 |
           @as(u32, ptr[3]);
}

fn readBE64(ptr: [*]const u8) u64 {
    return @as(u64, readBE32(ptr)) << 32 | @as(u64, readBE32(ptr + 4));
}

fn alignUp(val: usize, alignment: usize) usize {
    return (val + alignment - 1) & ~(alignment - 1);
}

fn streq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn startsWith(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    return streq(haystack[0..needle.len], needle);
}

fn containsStr(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (streq(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

fn mmioRead32(addr: u64) u32 {
    const ptr: *volatile u32 = @ptrFromInt(addr);
    return ptr.*;
}

fn mmioWrite32(addr: u64, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(addr);
    ptr.* = val;
}

// ── Boot Info Accessor ────────────────────────────────────────────────────
pub fn getBootInfo() *const BootInfo {
    return &boot_info;
}

pub fn getBootInfoMut() *BootInfo {
    return &boot_info;
}
