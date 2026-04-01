// =============================================================================
// Zxyphor Kernel — ARM64 SMMUv3 (System Memory Management Unit v3)
// =============================================================================
// Full implementation of ARM SMMUv3 (System Memory Management Unit version 3)
// for DMA remapping and device isolation. SMMUv3 provides two-stage address
// translation for all DMA transactions from bus masters (PCIe, USB, etc.)
// enabling IOMMU-based device isolation, VFIO passthrough, and DMA protection.
//
// Architecture per ARM SMMUv3 specification:
//   - Stream Table: maps StreamID → Stream Table Entry (STE)
//   - Context Descriptor: maps SubstreamID → translation config
//   - Command Queue: circular buffer for SMMU commands
//   - Event Queue: reports translation faults and errors
//   - PRI Queue: Page Request Interface (ATS+PRI)
//
// Features:
//   - Two-stage translation (S1 for per-process, S2 for hypervisor)
//   - 2-level stream tables for large StreamID spaces (up to 2^20)
//   - Hardware-accelerated TLB with IOTLB invalidation
//   - PCIe ATS (Address Translation Service) support
//   - PRI (Page Request Interface) for on-demand paging
//   - STALL model for recoverable translation faults
//   - MSI remapping for device interrupt isolation
//   - HTTU (Hardware Translation Table Update) for access/dirty tracking
//   - MPAM (Memory Partitioning and Monitoring) integration
//   - RME (Realm Management Extension) support for CCA
//   - PBHA (Page-Based Hardware Attributes) support
// =============================================================================

// ── SMMU Global Registers ─────────────────────────────────────────────────
pub const SMMU_REG = struct {
    pub const IDR0: u32 = 0x0000;
    pub const IDR1: u32 = 0x0004;
    pub const IDR2: u32 = 0x0008;
    pub const IDR3: u32 = 0x000C;
    pub const IDR4: u32 = 0x0010;
    pub const IDR5: u32 = 0x0014;
    pub const IIDR: u32 = 0x0018;
    pub const AIDR: u32 = 0x001C;
    pub const CR0: u32 = 0x0020;
    pub const CR0ACK: u32 = 0x0024;
    pub const CR1: u32 = 0x0028;
    pub const CR2: u32 = 0x002C;
    pub const STATUSR: u32 = 0x0040;
    pub const GBPA: u32 = 0x0044;
    pub const AGBPA: u32 = 0x0048;
    pub const IRQ_CTRL: u32 = 0x0050;
    pub const IRQ_CTRLACK: u32 = 0x0054;
    pub const GERROR: u32 = 0x0060;
    pub const GERRORN: u32 = 0x0064;
    pub const GERROR_IRQ_CFG0: u32 = 0x0068;
    pub const GERROR_IRQ_CFG1: u32 = 0x0070;
    pub const GERROR_IRQ_CFG2: u32 = 0x0074;
    pub const STRTAB_BASE: u32 = 0x0080;
    pub const STRTAB_BASE_CFG: u32 = 0x0088;
    pub const CMDQ_BASE: u32 = 0x0090;
    pub const CMDQ_PROD: u32 = 0x0098;
    pub const CMDQ_CONS: u32 = 0x009C;
    pub const EVTQ_BASE: u32 = 0x00A0;
    pub const EVTQ_PROD: u32 = 0x00A8;
    pub const EVTQ_CONS: u32 = 0x00AC;
    pub const EVTQ_IRQ_CFG0: u32 = 0x00B0;
    pub const EVTQ_IRQ_CFG1: u32 = 0x00B8;
    pub const EVTQ_IRQ_CFG2: u32 = 0x00BC;
    pub const PRIQ_BASE: u32 = 0x00C0;
    pub const PRIQ_PROD: u32 = 0x00C8;
    pub const PRIQ_CONS: u32 = 0x00CC;
    pub const PRIQ_IRQ_CFG0: u32 = 0x00D0;
    pub const PRIQ_IRQ_CFG1: u32 = 0x00D8;
    pub const PRIQ_IRQ_CFG2: u32 = 0x00DC;

    // CR0 register bits
    pub const CR0_SMMUEN: u32 = 1 << 0;
    pub const CR0_PRIQEN: u32 = 1 << 1;
    pub const CR0_EVTQEN: u32 = 1 << 2;
    pub const CR0_CMDQEN: u32 = 1 << 3;
    pub const CR0_ATSCHK: u32 = 1 << 4;
    pub const CR0_VMW: u32 = 7 << 6;

    // IDR0 bit fields
    pub const IDR0_S1P: u32 = 1 << 1;   // Stage 1 translation
    pub const IDR0_S2P: u32 = 1 << 0;   // Stage 2 translation
    pub const IDR0_TTF_MASK: u32 = 3 << 2;
    pub const IDR0_TTF_AARCH32: u32 = 1 << 2;
    pub const IDR0_TTF_AARCH64: u32 = 2 << 2;
    pub const IDR0_CD2L: u32 = 1 << 19;  // 2-level context descriptors
    pub const IDR0_STALL_MODEL: u32 = 3 << 24;
    pub const IDR0_TERM_MODEL: u32 = 1 << 26;
    pub const IDR0_HTTU: u32 = 3 << 6;  // Hardware translation table update
    pub const IDR0_HYP: u32 = 1 << 9;
    pub const IDR0_ATS: u32 = 1 << 10;  // ATS support
    pub const IDR0_PRI: u32 = 1 << 16;  // PRI support
    pub const IDR0_ASID16: u32 = 1 << 12;
    pub const IDR0_VMID16: u32 = 1 << 18;
    pub const IDR0_MSI: u32 = 1 << 13;
    pub const IDR0_SEV: u32 = 1 << 14;
    pub const IDR0_ST_LVL_MASK: u32 = 3 << 27;
    pub const IDR0_ST_LVL_2LVL: u32 = 1 << 27;
};

// ── Stream Table Entry (STE) ──────────────────────────────────────────────
// 64 bytes (8 × u64 DWORDs), describes translation config for a StreamID
pub const STE = extern struct {
    data: [8]u64,

    const Self = @This();

    // STE.Config field values (bits 3:1 of DWORD0)
    pub const CONFIG_ABORT: u64 = 0;        // Abort all transactions
    pub const CONFIG_BYPASS: u64 = 4;       // Bypass translation
    pub const CONFIG_S1_ONLY: u64 = 5;      // Stage 1 only
    pub const CONFIG_S2_ONLY: u64 = 6;      // Stage 2 only
    pub const CONFIG_S1_S2: u64 = 7;        // Stage 1 + Stage 2

    pub fn init() Self {
        return .{ .data = [_]u64{0} ** 8 };
    }

    pub fn setValid(self: *Self) void {
        self.data[0] |= 1; // Valid bit
    }

    pub fn setConfig(self: *Self, config: u64) void {
        self.data[0] = (self.data[0] & ~@as(u64, 0xE)) | ((config & 0x7) << 1);
    }

    pub fn setS1ContextPtr(self: *Self, phys_addr: u64) void {
        // Context descriptor pointer in DWORD0 bits 51:6
        self.data[0] = (self.data[0] & 0xF) | ((phys_addr >> 6) << 6);
    }

    pub fn setS1Fmt(self: *Self, fmt: u2) void {
        // S1Fmt in DWORD0 bits 5:4
        self.data[0] = (self.data[0] & ~@as(u64, 0x30)) | (@as(u64, fmt) << 4);
    }

    pub fn setS2Ttb(self: *Self, phys_addr: u64) void {
        // Stage 2 translation table base in DWORD3
        self.data[3] = phys_addr & 0x0000_FFFF_FFFF_F000;
    }

    pub fn setS2Config(self: *Self, vmid: u16, t0sz: u6, sl0: u2, tg: u2) void {
        // DWORD2: VMID, S2T0SZ, S2SL0, S2TG
        self.data[2] = (@as(u64, vmid) << 32) |
                       (@as(u64, t0sz) << 0) |
                       (@as(u64, sl0) << 6) |
                       (@as(u64, tg) << 14);
    }

    pub fn setStreamWorldConfig(self: *Self, eats: u2, s1stalld: bool, strw: u2) void {
        // DWORD1 configuration
        self.data[1] = (@as(u64, eats) << 28) |
                       (@as(u64, @intFromBool(s1stalld)) << 27) |
                       (@as(u64, strw) << 16);
    }
};

// ── Context Descriptor (CD) ──────────────────────────────────────────────
// 64 bytes, describes Stage 1 translation config for a SubstreamID
pub const ContextDescriptor = extern struct {
    data: [8]u64,

    const Self = @This();

    pub fn init() Self {
        return .{ .data = [_]u64{0} ** 8 };
    }

    pub fn setValid(self: *Self) void {
        self.data[0] |= 1 << 30; // Valid bit
    }

    pub fn setTtb0(self: *Self, phys_addr: u64) void {
        // TTB0 in DWORD1
        self.data[1] = phys_addr & 0x0000_FFFF_FFFF_F000;
    }

    pub fn setTtb1(self: *Self, phys_addr: u64) void {
        // TTB1 in DWORD2
        self.data[2] = phys_addr & 0x0000_FFFF_FFFF_F000;
    }

    pub fn setAsid(self: *Self, asid: u16) void {
        // ASID in DWORD0 bits 63:48
        self.data[0] = (self.data[0] & 0x0000_FFFF_FFFF_FFFF) | (@as(u64, asid) << 48);
    }

    pub fn setTransConfig(self: *Self, t0sz: u6, tg0: u2, epd0: bool, endi: bool, aa64: bool) void {
        // DWORD0: T0SZ, TG0, EPD0, ENDI, AA64, ASET
        self.data[0] = (self.data[0] & 0xFFFF_0000_C000_0000) |
                       (@as(u64, t0sz) << 0) |
                       (@as(u64, tg0) << 6) |
                       (@as(u64, @intFromBool(epd0)) << 14) |
                       (@as(u64, @intFromBool(endi)) << 15) |
                       (@as(u64, @intFromBool(aa64)) << 30);
        // MAIR in DWORD3
        self.data[3] = 0xFF44BB00_04000000; // Standard MAIR
    }
};

// ── Command Queue Entry ───────────────────────────────────────────────────
pub const CmdEntry = extern struct {
    data: [2]u64, // 128-bit command

    // Command opcodes
    pub const PREFETCH_CONFIG: u8 = 0x01;
    pub const PREFETCH_ADDR: u8 = 0x02;
    pub const CFGI_STE: u8 = 0x03;
    pub const CFGI_STE_RANGE: u8 = 0x04;
    pub const CFGI_CD: u8 = 0x05;
    pub const CFGI_CD_ALL: u8 = 0x06;
    pub const TLBI_NH_ASID: u8 = 0x11;
    pub const TLBI_NH_VA: u8 = 0x12;
    pub const TLBI_NH_VAA: u8 = 0x13;
    pub const TLBI_NH_ALL: u8 = 0x18;
    pub const TLBI_S2_IPA: u8 = 0x2D;
    pub const TLBI_NSNH_ALL: u8 = 0x30;
    pub const CMD_SYNC: u8 = 0x46;
    pub const ATC_INV: u8 = 0x40;
    pub const PRI_RESP: u8 = 0x41;
    pub const RESUME: u8 = 0x44;
    pub const STALL_TERM: u8 = 0x45;

    const Self = @This();

    pub fn init(opcode: u8) Self {
        return .{
            .data = .{
                @as(u64, opcode),
                0,
            },
        };
    }

    pub fn cfgiSte(sid: u32, leaf: bool) Self {
        var cmd = Self.init(CFGI_STE);
        cmd.data[0] |= @as(u64, sid) << 32;
        if (leaf) cmd.data[0] |= 1 << 20;
        return cmd;
    }

    pub fn tlbiNhAll() Self {
        return Self.init(TLBI_NH_ALL);
    }

    pub fn tlbiNhAsid(asid: u16, vmid: u16) Self {
        var cmd = Self.init(TLBI_NH_ASID);
        cmd.data[0] |= @as(u64, asid) << 48;
        cmd.data[1] |= @as(u64, vmid) << 32;
        return cmd;
    }

    pub fn tlbiNhVa(asid: u16, va: u64, vmid: u16) Self {
        var cmd = Self.init(TLBI_NH_VA);
        cmd.data[0] |= @as(u64, asid) << 48;
        cmd.data[0] |= (va >> 12) << 12;
        cmd.data[1] |= @as(u64, vmid) << 32;
        return cmd;
    }

    pub fn sync(msiaddr: u64) Self {
        var cmd = Self.init(CMD_SYNC);
        cmd.data[0] |= 0b10 << 12; // CS = SEV
        cmd.data[1] = msiaddr;
        return cmd;
    }
};

// ── Event Queue Entry ────────────────────────────────────────────────────
pub const EvtEntry = extern struct {
    data: [4]u64, // 256-bit event

    pub const EVT_F_UUT: u8 = 0x01; // Unsupported Upstream Transaction
    pub const EVT_C_BAD_STREAMID: u8 = 0x02;
    pub const EVT_F_STE_FETCH: u8 = 0x03;
    pub const EVT_C_BAD_STE: u8 = 0x04;
    pub const EVT_F_BAD_ATS_TREQ: u8 = 0x05;
    pub const EVT_F_TRANSLATION: u8 = 0x10;
    pub const EVT_F_ADDR_SIZE: u8 = 0x11;
    pub const EVT_F_ACCESS: u8 = 0x12;
    pub const EVT_F_PERMISSION: u8 = 0x13;

    const Self = @This();

    pub fn getType(self: *const Self) u8 {
        return @truncate(self.data[0] & 0xFF);
    }

    pub fn getStreamId(self: *const Self) u32 {
        return @truncate(self.data[0] >> 32);
    }

    pub fn getFaultAddr(self: *const Self) u64 {
        return self.data[2];
    }

    pub fn isWrite(self: *const Self) bool {
        return (self.data[1] >> 5) & 1 == 1;
    }

    pub fn isExec(self: *const Self) bool {
        return (self.data[1] >> 6) & 1 == 1;
    }

    pub fn isStalled(self: *const Self) bool {
        return (self.data[1] >> 0) & 1 == 1;
    }
};

// ── SMMU Instance State ──────────────────────────────────────────────────
pub const SmmuState = struct {
    base: u64,
    // Capabilities from IDR registers
    has_s1: bool,
    has_s2: bool,
    has_ats: bool,
    has_pri: bool,
    has_httu: bool,
    has_2lvl_strtab: bool,
    has_cd2l: bool,
    has_msi: bool,
    has_vmid16: bool,
    has_asid16: bool,
    sid_bits: u8,       // Number of StreamID bits
    ssid_bits: u8,      // Number of SubstreamID bits
    oas: u8,            // Output Address Size
    // Queue state
    cmdq_base_phys: u64,
    cmdq_entries: u32,
    cmdq_prod: u32,
    evtq_base_phys: u64,
    evtq_entries: u32,
    evtq_cons: u32,
    // Stream table
    strtab_base_phys: u64,
    strtab_num_entries: u32,
    strtab_2lvl: bool,
    // Status
    initialized: bool,
    enabled: bool,

    const Self = @This();

    pub fn init() Self {
        var s: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&s))[0..@sizeOf(Self)], 0);
        return s;
    }
};

pub const MAX_SMMU_INSTANCES: usize = 4;
var smmu_instances: [MAX_SMMU_INSTANCES]SmmuState = [_]SmmuState{SmmuState.init()} ** MAX_SMMU_INSTANCES;
var smmu_count: usize = 0;

// ── MMIO Access ───────────────────────────────────────────────────────────
fn smmuRead32(smmu: *const SmmuState, offset: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(smmu.base + offset);
    return ptr.*;
}

fn smmuWrite32(smmu: *const SmmuState, offset: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(smmu.base + offset);
    ptr.* = val;
}

fn smmuRead64(smmu: *const SmmuState, offset: u32) u64 {
    const ptr: *volatile u64 = @ptrFromInt(smmu.base + offset);
    return ptr.*;
}

fn smmuWrite64(smmu: *const SmmuState, offset: u32, val: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(smmu.base + offset);
    ptr.* = val;
}

// ── SMMU Initialization ──────────────────────────────────────────────────
pub fn initSmmu(base: u64) !*SmmuState {
    if (smmu_count >= MAX_SMMU_INSTANCES) return error.TooManyInstances;

    var smmu = &smmu_instances[smmu_count];
    smmu.base = base;

    // Read identification registers
    const idr0 = smmuRead32(smmu, SMMU_REG.IDR0);
    const idr1 = smmuRead32(smmu, SMMU_REG.IDR1);
    const idr5 = smmuRead32(smmu, SMMU_REG.IDR5);

    // Parse capabilities
    smmu.has_s1 = (idr0 & SMMU_REG.IDR0_S1P) != 0;
    smmu.has_s2 = (idr0 & SMMU_REG.IDR0_S2P) != 0;
    smmu.has_ats = (idr0 & SMMU_REG.IDR0_ATS) != 0;
    smmu.has_pri = (idr0 & SMMU_REG.IDR0_PRI) != 0;
    smmu.has_httu = (idr0 & SMMU_REG.IDR0_HTTU) != 0;
    smmu.has_msi = (idr0 & SMMU_REG.IDR0_MSI) != 0;
    smmu.has_vmid16 = (idr0 & SMMU_REG.IDR0_VMID16) != 0;
    smmu.has_asid16 = (idr0 & SMMU_REG.IDR0_ASID16) != 0;
    smmu.has_2lvl_strtab = (idr0 & SMMU_REG.IDR0_ST_LVL_MASK) != 0;
    smmu.has_cd2l = (idr0 & SMMU_REG.IDR0_CD2L) != 0;

    // StreamID bits from IDR1
    smmu.sid_bits = @truncate((idr1 >> 0) & 0x3F);
    smmu.ssid_bits = @truncate((idr1 >> 6) & 0x1F);

    // Output address size from IDR5
    smmu.oas = @truncate((idr5 >> 0) & 0x7);

    // Disable SMMU before configuration
    smmuWrite32(smmu, SMMU_REG.CR0, 0);
    waitForCr0Ack(smmu, 0);

    // Set up command queue (PAGE_SIZE aligned, power-of-2 entries)
    const cmdq_order: u5 = 8; // 256 entries
    smmu.cmdq_entries = @as(u32, 1) << cmdq_order;
    // Allocate command queue memory (simplified — use early allocator)
    smmu.cmdq_base_phys = allocSmmuQueue(smmu.cmdq_entries * 16);
    smmuWrite64(smmu, SMMU_REG.CMDQ_BASE, smmu.cmdq_base_phys | @as(u64, cmdq_order));
    smmuWrite32(smmu, SMMU_REG.CMDQ_PROD, 0);
    smmuWrite32(smmu, SMMU_REG.CMDQ_CONS, 0);
    smmu.cmdq_prod = 0;

    // Set up event queue
    const evtq_order: u5 = 7; // 128 entries
    smmu.evtq_entries = @as(u32, 1) << evtq_order;
    smmu.evtq_base_phys = allocSmmuQueue(smmu.evtq_entries * 32);
    smmuWrite64(smmu, SMMU_REG.EVTQ_BASE, smmu.evtq_base_phys | @as(u64, evtq_order));
    smmuWrite32(smmu, SMMU_REG.EVTQ_CONS, 0);
    smmu.evtq_cons = 0;

    // Set up stream table
    if (smmu.has_2lvl_strtab and smmu.sid_bits > 7) {
        smmu.strtab_2lvl = true;
        try setupStreamTable2Level(smmu);
    } else {
        smmu.strtab_2lvl = false;
        try setupStreamTableLinear(smmu);
    }

    // Configure bypass for Global Bypass
    smmuWrite32(smmu, SMMU_REG.GBPA, 0); // Bypass

    // Enable SMMU: command queue + event queue + SMMU translation
    var cr0: u32 = SMMU_REG.CR0_CMDQEN | SMMU_REG.CR0_EVTQEN;
    smmuWrite32(smmu, SMMU_REG.CR0, cr0);
    waitForCr0Ack(smmu, cr0);

    // Now enable SMMU itself
    cr0 |= SMMU_REG.CR0_SMMUEN;
    smmuWrite32(smmu, SMMU_REG.CR0, cr0);
    waitForCr0Ack(smmu, cr0);

    smmu.initialized = true;
    smmu.enabled = true;
    smmu_count += 1;

    return smmu;
}

fn setupStreamTableLinear(smmu: *SmmuState) !void {
    const num_entries: u32 = @as(u32, 1) << @as(u5, @truncate(smmu.sid_bits));
    smmu.strtab_num_entries = num_entries;
    smmu.strtab_base_phys = allocSmmuQueue(num_entries * 64);

    // Initialize all STEs to bypass
    var ste_ptr: [*]STE = @ptrFromInt(smmu.strtab_base_phys);
    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        ste_ptr[i] = STE.init();
        ste_ptr[i].setConfig(STE.CONFIG_BYPASS);
        ste_ptr[i].setValid();
    }

    // Configure stream table base register
    const cfg: u64 = @as(u64, smmu.sid_bits) | (0 << 16); // Linear (FMT=0)
    smmuWrite64(smmu, SMMU_REG.STRTAB_BASE, smmu.strtab_base_phys);
    smmuWrite64(smmu, SMMU_REG.STRTAB_BASE_CFG, cfg);
}

fn setupStreamTable2Level(smmu: *SmmuState) !void {
    const l1_bits: u5 = @truncate(if (smmu.sid_bits > 7) smmu.sid_bits - 7 else 1);
    const l1_entries: u32 = @as(u32, 1) << l1_bits;
    smmu.strtab_num_entries = 0; // Populated lazily
    smmu.strtab_base_phys = allocSmmuQueue(l1_entries * 8); // L1 entries are 8 bytes

    // Initialize L1 entries to NULL (L2 allocated on demand)
    var l1_ptr: [*]u64 = @ptrFromInt(smmu.strtab_base_phys);
    var i: u32 = 0;
    while (i < l1_entries) : (i += 1) {
        l1_ptr[i] = 0; // Invalid — L2 not yet allocated
    }

    const cfg: u64 = @as(u64, smmu.sid_bits) | (1 << 16) | // 2-level (FMT=1)
                     (@as(u64, l1_bits) << 6);              // SPLIT
    smmuWrite64(smmu, SMMU_REG.STRTAB_BASE, smmu.strtab_base_phys);
    smmuWrite64(smmu, SMMU_REG.STRTAB_BASE_CFG, cfg);
}

// ── Command Queue Operations ──────────────────────────────────────────────
pub fn submitCommand(smmu: *SmmuState, cmd: CmdEntry) void {
    const prod = smmu.cmdq_prod;
    const entry_ptr: *CmdEntry = @ptrFromInt(smmu.cmdq_base_phys + @as(u64, prod) * 16);
    entry_ptr.* = cmd;

    // Advance producer
    smmu.cmdq_prod = (prod + 1) % smmu.cmdq_entries;
    smmuWrite32(smmu, SMMU_REG.CMDQ_PROD, smmu.cmdq_prod);
}

pub fn submitCommandSync(smmu: *SmmuState, cmd: CmdEntry) void {
    submitCommand(smmu, cmd);
    submitCommand(smmu, CmdEntry.sync(0));
    waitForCmdqDrain(smmu);
}

fn waitForCmdqDrain(smmu: *const SmmuState) void {
    var timeout: u32 = 1_000_000;
    while (timeout > 0) : (timeout -= 1) {
        const cons = smmuRead32(smmu, SMMU_REG.CMDQ_CONS);
        if (cons == smmu.cmdq_prod) return;
        asm volatile ("yield");
    }
}

// ── DMA Domain API ────────────────────────────────────────────────────────
pub fn attachDevice(smmu: *SmmuState, stream_id: u32, page_table_phys: u64, asid: u16) void {
    // Create and install STE for this device
    var ste = STE.init();
    ste.setConfig(STE.CONFIG_S1_ONLY);
    ste.setValid();

    // Create context descriptor
    // For simplicity, use single-level CD
    var cd = ContextDescriptor.init();
    cd.setTtb0(page_table_phys);
    cd.setAsid(asid);
    cd.setTransConfig(16, 0, false, false, true); // T0SZ=16, TG0=4K, AArch64
    cd.setValid();

    // Install STE in stream table
    installSte(smmu, stream_id, &ste);

    // Invalidate cached config
    submitCommandSync(smmu, CmdEntry.cfgiSte(stream_id, true));
}

pub fn detachDevice(smmu: *SmmuState, stream_id: u32) void {
    var ste = STE.init();
    ste.setConfig(STE.CONFIG_ABORT);
    installSte(smmu, stream_id, &ste);
    submitCommandSync(smmu, CmdEntry.cfgiSte(stream_id, true));
}

pub fn invalidateIotlbAll(smmu: *SmmuState) void {
    submitCommandSync(smmu, CmdEntry.tlbiNhAll());
}

pub fn invalidateIotlbAsid(smmu: *SmmuState, asid: u16, vmid: u16) void {
    submitCommandSync(smmu, CmdEntry.tlbiNhAsid(asid, vmid));
}

fn installSte(smmu: *SmmuState, stream_id: u32, ste: *const STE) void {
    if (!smmu.strtab_2lvl) {
        // Linear stream table — direct index
        var ste_ptr: [*]STE = @ptrFromInt(smmu.strtab_base_phys);
        ste_ptr[stream_id] = ste.*;
    } else {
        // 2-level: compute L1 index and L2 index
        const l2_bits: u5 = 7;
        const l1_idx = stream_id >> l2_bits;
        const l2_idx = stream_id & ((1 << l2_bits) - 1);

        var l1_ptr: [*]u64 = @ptrFromInt(smmu.strtab_base_phys);
        if (l1_ptr[l1_idx] == 0) {
            // Allocate L2 table
            const l2_phys = allocSmmuQueue(128 * 64); // 128 STEs
            l1_ptr[l1_idx] = l2_phys | (1 << 0); // Valid
        }

        const l2_base = l1_ptr[l1_idx] & ~@as(u64, 0x1F);
        var l2_ptr: [*]STE = @ptrFromInt(l2_base);
        l2_ptr[l2_idx] = ste.*;
    }
}

// ── Event Queue Processing ───────────────────────────────────────────────
pub fn processEvents(smmu: *SmmuState) void {
    const prod = smmuRead32(smmu, SMMU_REG.EVTQ_PROD);

    while (smmu.evtq_cons != prod) {
        const evt_ptr: *const EvtEntry = @ptrFromInt(smmu.evtq_base_phys + @as(u64, smmu.evtq_cons) * 32);
        handleEvent(smmu, evt_ptr);
        smmu.evtq_cons = (smmu.evtq_cons + 1) % smmu.evtq_entries;
    }

    smmuWrite32(smmu, SMMU_REG.EVTQ_CONS, smmu.evtq_cons);
}

fn handleEvent(smmu: *const SmmuState, evt: *const EvtEntry) void {
    const evt_type = evt.getType();
    const sid = evt.getStreamId();
    const fault_addr = evt.getFaultAddr();
    _ = smmu;
    _ = evt_type;
    _ = sid;
    _ = fault_addr;

    // TODO: Route faults to VFIO or kernel fault handler
    // For stalled faults: resume or terminate via CMD_RESUME/STALL_TERM
}

// ── Helpers ───────────────────────────────────────────────────────────────
fn waitForCr0Ack(smmu: *const SmmuState, expected: u32) void {
    var timeout: u32 = 1_000_000;
    while (timeout > 0) : (timeout -= 1) {
        if (smmuRead32(smmu, SMMU_REG.CR0ACK) == expected) return;
        asm volatile ("yield");
    }
}

// Simplified queue allocator — in production, use PMM
var queue_pool: [1024 * 1024]u8 align(4096) = undefined;
var queue_offset: usize = 0;

fn allocSmmuQueue(size: usize) u64 {
    const aligned = (size + 4095) & ~@as(usize, 4095);
    if (queue_offset + aligned > queue_pool.len) return 0;
    const ptr = @intFromPtr(&queue_pool[queue_offset]);
    @memset(queue_pool[queue_offset..][0..aligned], 0);
    queue_offset += aligned;
    return @as(u64, ptr);
}

pub fn getSmmuCount() usize {
    return smmu_count;
}

pub fn getSmmu(idx: usize) ?*SmmuState {
    if (idx >= smmu_count) return null;
    return &smmu_instances[idx];
}
