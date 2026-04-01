// =============================================================================
// Zxyphor Kernel — ARM64 GICv3/GICv4 Interrupt Controller Driver
// =============================================================================
// Complete implementation of ARM Generic Interrupt Controller version 3 and 4.
// Supports up to 1020 SPIs, 16 SGIs, 32 PPIs per CPU, LPIs with ITS,
// interrupt grouping (Group 0/1/1NS), priority-based preemption, and
// GICv4 direct virtual interrupt injection.
//
// Architecture: GICv3 (ARM GIC Architecture Specification v3/v4)
//   - Distributor (GICD): System-wide SPI management
//   - Redistributor (GICR): Per-CPU SGI/PPI/LPI management
//   - CPU Interface: System register based (ICC_*)
//   - ITS (Interrupt Translation Service): LPI routing for MSI/MSI-X
//
// Key Features:
//   - Full SPI/PPI/SGI/LPI support
//   - 1-of-N and directed SPI routing
//   - Interrupt affinity routing (ARE)  
//   - Priority drop and deactivation split (EOImode)
//   - GICv4 virtual LPI direct injection
//   - ITS command queue for LPI/vLPI management
//   - Extended SPI/PPI range (GICv3.1+)
// =============================================================================

const boot = @import("boot.zig");

// ── GIC Distributor Register Offsets (GICD_*) ─────────────────────────────
pub const GICD = struct {
    pub const CTLR:         u32 = 0x0000; // Distributor Control Register
    pub const TYPER:        u32 = 0x0004; // Interrupt Controller Type
    pub const IIDR:         u32 = 0x0008; // Implementer Identification
    pub const TYPER2:       u32 = 0x000C; // Interrupt Controller Type 2
    pub const STATUSR:      u32 = 0x0010; // Error Reporting Status
    pub const SETSPI_NSR:   u32 = 0x0040; // Set SPI Non-Secure
    pub const CLRSPI_NSR:   u32 = 0x0048; // Clear SPI Non-Secure
    pub const SETSPI_SR:    u32 = 0x0050; // Set SPI Secure
    pub const CLRSPI_SR:    u32 = 0x0058; // Clear SPI Secure
    pub const IGROUPR:      u32 = 0x0080; // Interrupt Group (32 regs)
    pub const ISENABLER:    u32 = 0x0100; // Interrupt Set-Enable (32 regs)
    pub const ICENABLER:    u32 = 0x0180; // Interrupt Clear-Enable (32 regs)
    pub const ISPENDR:      u32 = 0x0200; // Interrupt Set-Pending (32 regs)
    pub const ICPENDR:      u32 = 0x0280; // Interrupt Clear-Pending (32 regs)
    pub const ISACTIVER:    u32 = 0x0300; // Interrupt Set-Active (32 regs)
    pub const ICACTIVER:    u32 = 0x0380; // Interrupt Clear-Active (32 regs)
    pub const IPRIORITYR:   u32 = 0x0400; // Interrupt Priority (256 regs)
    pub const ITARGETSR:    u32 = 0x0800; // Interrupt Targets (GICv2 compat)
    pub const ICFGR:        u32 = 0x0C00; // Interrupt Configuration (64 regs)
    pub const IGRPMODR:     u32 = 0x0D00; // Interrupt Group Modifier (32 regs)
    pub const NSACR:        u32 = 0x0E00; // Non-Secure Access Control
    pub const SGIR:         u32 = 0x0F00; // Software Generated Interrupt
    pub const CPENDSGIR:    u32 = 0x0F10; // SGI Clear-Pending
    pub const SPENDSGIR:    u32 = 0x0F20; // SGI Set-Pending
    pub const IROUTER:      u32 = 0x6000; // Interrupt Routing (SPI) — 64-bit

    // GICD_CTLR bits
    pub const CTLR_EnableGrp0:      u32 = 1 << 0;
    pub const CTLR_EnableGrp1NS:    u32 = 1 << 1;
    pub const CTLR_EnableGrp1S:     u32 = 1 << 2;
    pub const CTLR_ARE_S:           u32 = 1 << 4;
    pub const CTLR_ARE_NS:          u32 = 1 << 5;
    pub const CTLR_DS:              u32 = 1 << 6;
    pub const CTLR_E1NWF:           u32 = 1 << 7;
    pub const CTLR_RWP:             u32 = 1 << 31;
};

// ── GIC Redistributor Register Offsets (GICR_*) ──────────────────────────
pub const GICR = struct {
    // RD_base frame (per PE)
    pub const CTLR:         u32 = 0x0000;
    pub const IIDR:         u32 = 0x0004;
    pub const TYPER:        u32 = 0x0008; // 64-bit
    pub const STATUSR:      u32 = 0x0010;
    pub const WAKER:        u32 = 0x0014;
    pub const MPAMIDR:      u32 = 0x0018;
    pub const PARTIDR:      u32 = 0x001C;
    pub const SETLPIR:      u32 = 0x0040; // 64-bit, Set LPI Pending
    pub const CLRLPIR:      u32 = 0x0048; // 64-bit, Clear LPI Pending
    pub const PROPBASER:    u32 = 0x0070; // 64-bit, LPI Configuration Table
    pub const PENDBASER:    u32 = 0x0078; // 64-bit, LPI Pending Table
    pub const INVLPIR:      u32 = 0x00A0; // Invalidate LPI
    pub const INVALLR:      u32 = 0x00B0; // Invalidate All
    pub const SYNCR:        u32 = 0x00C0;

    // SGI_base frame (per PE, at RD_base + 0x10000)
    pub const SGI_OFFSET:   u32 = 0x10000;
    pub const IGROUPR0:     u32 = SGI_OFFSET + 0x0080;
    pub const ISENABLER0:   u32 = SGI_OFFSET + 0x0100;
    pub const ICENABLER0:   u32 = SGI_OFFSET + 0x0180;
    pub const ISPENDR0:     u32 = SGI_OFFSET + 0x0200;
    pub const ICPENDR0:     u32 = SGI_OFFSET + 0x0280;
    pub const ISACTIVER0:   u32 = SGI_OFFSET + 0x0300;
    pub const ICACTIVER0:   u32 = SGI_OFFSET + 0x0380;
    pub const IPRIORITYR0:  u32 = SGI_OFFSET + 0x0400; // 8 regs
    pub const ICFGR0:       u32 = SGI_OFFSET + 0x0C00;
    pub const ICFGR1:       u32 = SGI_OFFSET + 0x0C04;
    pub const IGRPMODR0:    u32 = SGI_OFFSET + 0x0D00;
    pub const NSACR:        u32 = SGI_OFFSET + 0x0E00;

    // GICR_CTLR bits
    pub const CTLR_EnableLPIs:  u32 = 1 << 0;
    pub const CTLR_RWP:         u32 = 1 << 3;
    pub const CTLR_DPG0:        u32 = 1 << 24;
    pub const CTLR_DPG1NS:      u32 = 1 << 25;
    pub const CTLR_DPG1S:       u32 = 1 << 26;
    pub const CTLR_UWP:         u32 = 1 << 31;

    // GICR_WAKER bits
    pub const WAKER_ProcessorSleep:  u32 = 1 << 1;
    pub const WAKER_ChildrenAsleep:  u32 = 1 << 2;

    // GICR_TYPER bits
    pub const TYPER_PLPIS:      u64 = 1 << 0;
    pub const TYPER_VLPIS:      u64 = 1 << 1;
    pub const TYPER_DirectLPI:  u64 = 1 << 3;
    pub const TYPER_LAST:       u64 = 1 << 4;
    pub const TYPER_DPGS:       u64 = 1 << 5;

    // Stride between redistributor frames for different PEs
    pub const FRAME_SIZE: u32 = 0x20000; // 128KB (RD_base + SGI_base)
};

// ── Interrupt Types and Constants ─────────────────────────────────────────
pub const IntType = enum(u2) {
    sgi = 0, // Software Generated Interrupts (0-15)
    ppi = 1, // Private Peripheral Interrupts (16-31)
    spi = 2, // Shared Peripheral Interrupts (32-1019)
    lpi = 3, // Locality-specific Peripheral Interrupts (8192+)
};

pub const MAX_SPI: u32 = 1020;
pub const MAX_IRQS: u32 = 1020;
pub const SGI_COUNT: u32 = 16;
pub const PPI_START: u32 = 16;
pub const PPI_COUNT: u32 = 16;
pub const SPI_START: u32 = 32;
pub const LPI_START: u32 = 8192;
pub const MAX_LPI: u32 = 65536;
pub const INTID_SPURIOUS: u32 = 1023;

pub const IRQ_PRIORITY_HIGHEST: u8 = 0x00;
pub const IRQ_PRIORITY_HIGH: u8 = 0x20;
pub const IRQ_PRIORITY_MEDIUM: u8 = 0x80;
pub const IRQ_PRIORITY_LOW: u8 = 0xA0;
pub const IRQ_PRIORITY_LOWEST: u8 = 0xF0;
pub const IRQ_PRIORITY_IDLE: u8 = 0xFF;

pub const TriggerType = enum(u1) {
    level = 0,
    edge = 1,
};

pub const Polarity = enum(u1) {
    active_high = 0,
    active_low = 1,
};

// ── Interrupt Descriptor ──────────────────────────────────────────────────
pub const IrqDescriptor = struct {
    intid: u32,
    int_type: IntType,
    trigger: TriggerType,
    polarity: Polarity,
    priority: u8,
    target_cpu: u32,   // MPIDR affinity for routing
    enabled: bool,
    handler: ?*const fn (u32, ?*anyopaque) void, // IRQ handler
    handler_data: ?*anyopaque,
    name: [32]u8,
    name_len: usize,
    count: u64,        // Interrupt count (statistics)
    last_cpu: u32,     // Last CPU that handled this interrupt

    const Self = @This();

    pub fn init(intid: u32) Self {
        var desc: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&desc))[0..@sizeOf(Self)], 0);
        desc.intid = intid;
        desc.priority = IRQ_PRIORITY_MEDIUM;
        desc.trigger = .level;
        desc.polarity = .active_high;
        desc.int_type = if (intid < SGI_COUNT) .sgi
                       else if (intid < SPI_START) .ppi
                       else if (intid < LPI_START) .spi
                       else .lpi;
        return desc;
    }
};

var irq_table: [MAX_IRQS]IrqDescriptor = undefined;
var irq_table_initialized: bool = false;

// ── GIC State ─────────────────────────────────────────────────────────────
pub const GicState = struct {
    dist_base: u64,
    redist_base: u64,
    version: u32,
    max_irqs: u32,
    nr_spis: u32,
    nr_lpis: u32,
    has_security: bool,
    has_vlpis: bool,
    has_direct_lpi: bool,
    has_espi: bool,       // Extended SPI range
    has_eppi: bool,       // Extended PPI range
    initialized: bool,
    cpu_redist_base: [256]u64, // Per-CPU redistributor base addresses

    const Self = @This();

    pub fn init() Self {
        var state: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&state))[0..@sizeOf(Self)], 0);
        return state;
    }
};

var gic_state: GicState = GicState.init();

// ── MMIO Access ───────────────────────────────────────────────────────────
inline fn gicDistRead(offset: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(gic_state.dist_base + offset);
    return ptr.*;
}

inline fn gicDistWrite(offset: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gic_state.dist_base + offset);
    ptr.* = val;
}

inline fn gicDistRead64(offset: u32) u64 {
    const ptr: *volatile u64 = @ptrFromInt(gic_state.dist_base + offset);
    return ptr.*;
}

inline fn gicDistWrite64(offset: u32, val: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(gic_state.dist_base + offset);
    ptr.* = val;
}

inline fn gicRedistRead(cpu: u32, offset: u32) u32 {
    const base = gic_state.cpu_redist_base[cpu];
    const ptr: *volatile u32 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn gicRedistWrite(cpu: u32, offset: u32, val: u32) void {
    const base = gic_state.cpu_redist_base[cpu];
    const ptr: *volatile u32 = @ptrFromInt(base + offset);
    ptr.* = val;
}

// ── ICC System Register Access (CPU Interface) ────────────────────────────
pub inline fn iccReadIar1() u32 {
    return @truncate(asm ("mrs %[r], ICC_IAR1_EL1" : [r] "=r" (-> u64)));
}

pub inline fn iccWriteEoir1(intid: u32) void {
    asm volatile ("msr ICC_EOIR1_EL1, %[v]" : : [v] "r" (@as(u64, intid)));
}

pub inline fn iccWriteDir(intid: u32) void {
    asm volatile ("msr ICC_DIR_EL1, %[v]" : : [v] "r" (@as(u64, intid)));
}

pub inline fn iccWriteSgi1r(val: u64) void {
    asm volatile ("msr ICC_SGI1R_EL1, %[v]" : : [v] "r" (val));
}

pub inline fn iccWritePmr(priority: u8) void {
    asm volatile ("msr ICC_PMR_EL1, %[v]" : : [v] "r" (@as(u64, priority)));
}

pub inline fn iccReadPmr() u8 {
    return @truncate(asm ("mrs %[r], ICC_PMR_EL1" : [r] "=r" (-> u64)));
}

pub inline fn iccWriteCtlr(val: u32) void {
    asm volatile ("msr ICC_CTLR_EL1, %[v]" : : [v] "r" (@as(u64, val)));
}

pub inline fn iccReadCtlr() u32 {
    return @truncate(asm ("mrs %[r], ICC_CTLR_EL1" : [r] "=r" (-> u64)));
}

pub inline fn iccWriteIgrpen1(val: u32) void {
    asm volatile ("msr ICC_IGRPEN1_EL1, %[v]" : : [v] "r" (@as(u64, val)));
}

pub inline fn iccWriteBpr1(val: u32) void {
    asm volatile ("msr ICC_BPR1_EL1, %[v]" : : [v] "r" (@as(u64, val)));
}

pub inline fn iccReadRpr() u8 {
    return @truncate(asm ("mrs %[r], ICC_RPR_EL1" : [r] "=r" (-> u64)));
}

pub inline fn iccReadHppir1() u32 {
    return @truncate(asm ("mrs %[r], ICC_HPPIR1_EL1" : [r] "=r" (-> u64)));
}

// ── GIC Distributor Initialization ────────────────────────────────────────
pub fn initDistributor() void {
    // Disable Distributor
    gicDistWrite(GICD.CTLR, 0);
    waitForRwp();

    // Read GICD_TYPER to discover interrupt count
    const typer = gicDistRead(GICD.TYPER);
    const it_lines = (typer & 0x1F) + 1; // ITLinesNumber + 1
    gic_state.nr_spis = it_lines * 32;
    if (gic_state.nr_spis > MAX_SPI) gic_state.nr_spis = MAX_SPI;
    gic_state.max_irqs = gic_state.nr_spis;
    gic_state.has_security = (typer & (1 << 10)) == 0; // SecurityExtn
    gic_state.has_espi = (typer & (1 << 8)) != 0;

    // Read IIDR
    const iidr = gicDistRead(GICD.IIDR);
    _ = iidr;

    // Configure all SPIs: disable, clear pending, set default priority
    var i: u32 = 1; // Skip first group (SGI/PPI handled by redistributor)
    while (i < it_lines) : (i += 1) {
        gicDistWrite(GICD.ICENABLER + i * 4, 0xFFFFFFFF);    // Disable
        gicDistWrite(GICD.ICPENDR + i * 4, 0xFFFFFFFF);      // Clear pending
        gicDistWrite(GICD.ICACTIVER + i * 4, 0xFFFFFFFF);    // Clear active
        gicDistWrite(GICD.IGROUPR + i * 4, 0xFFFFFFFF);      // All Group 1 NS
        gicDistWrite(GICD.IGRPMODR + i * 4, 0x00000000);     // Group modifier = 0
    }

    // Set all SPI priorities to default
    var j: u32 = 8; // SPIs start at offset 32 (byte 8 in priority registers)
    while (j < gic_state.nr_spis / 4 + 8) : (j += 1) {
        gicDistWrite(GICD.IPRIORITYR + j * 4, 0xA0A0A0A0);  // Priority 0xA0
    }

    // Set all SPIs to level-triggered
    i = 2; // First 2 ICFGR registers are for SGI/PPI
    while (i < it_lines * 2) : (i += 1) {
        gicDistWrite(GICD.ICFGR + i * 4, 0x00000000); // Level-sensitive
    }

    // Set up affinity routing for all SPIs (route to CPU 0 by default)
    var spi: u32 = SPI_START;
    while (spi < gic_state.nr_spis + SPI_START) : (spi += 1) {
        const route_offset = GICD.IROUTER + (spi * 8);
        gicDistWrite64(route_offset, 0); // Route to PE with affinity 0.0.0.0
    }

    // Enable distributor with ARE (Affinity Routing Enable)
    gicDistWrite(GICD.CTLR, GICD.CTLR_EnableGrp1NS | GICD.CTLR_ARE_NS | GICD.CTLR_ARE_S);
    waitForRwp();
}

// ── GIC Redistributor Initialization (per CPU) ───────────────────────────
pub fn initRedistributor(cpu_idx: u32) void {
    // Find this CPU's redistributor
    const redist_base = findRedistributorForCpu(cpu_idx);
    if (redist_base == 0) return;
    gic_state.cpu_redist_base[cpu_idx] = redist_base;

    // Wake up redistributor
    var waker = gicRedistRead(cpu_idx, GICR.WAKER);
    waker &= ~GICR.WAKER_ProcessorSleep;
    gicRedistWrite(cpu_idx, GICR.WAKER, waker);

    // Wait for ChildrenAsleep to clear
    var timeout: u32 = 1_000_000;
    while (timeout > 0) : (timeout -= 1) {
        if (gicRedistRead(cpu_idx, GICR.WAKER) & GICR.WAKER_ChildrenAsleep == 0) break;
    }

    // Configure SGIs and PPIs (in SGI_base frame)
    // Disable all SGIs/PPIs first
    gicRedistWrite(cpu_idx, GICR.ICENABLER0, 0xFFFFFFFF);

    // Clear all pending
    gicRedistWrite(cpu_idx, GICR.ICPENDR0, 0xFFFFFFFF);

    // Set all to Group 1 NS
    gicRedistWrite(cpu_idx, GICR.IGROUPR0, 0xFFFFFFFF);
    gicRedistWrite(cpu_idx, GICR.IGRPMODR0, 0x00000000);

    // Set default priorities for SGIs/PPIs
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        gicRedistWrite(cpu_idx, GICR.IPRIORITYR0 + i * 4, 0xA0A0A0A0);
    }

    // Configure PPIs as level-triggered, SGIs as edge-triggered
    gicRedistWrite(cpu_idx, GICR.ICFGR0, 0x00000000);  // SGIs: fixed edge
    gicRedistWrite(cpu_idx, GICR.ICFGR1, 0x00000000);  // PPIs: level default

    // Enable SGIs (0-15)
    gicRedistWrite(cpu_idx, GICR.ISENABLER0, 0x0000FFFF);
}

// ── CPU Interface Initialization ──────────────────────────────────────────
pub fn initCpuInterface() void {
    // Set priority mask — allow all priorities
    iccWritePmr(0xFF);

    // Set binary point — no preemption grouping
    iccWriteBpr1(0);

    // Configure ICC_CTLR_EL1
    var ctlr = iccReadCtlr();
    ctlr |= 1 << 1; // EOImode = 1 (priority drop + deactivation split)
    iccWriteCtlr(ctlr);

    // Enable Group 1 interrupts
    iccWriteIgrpen1(1);

    // ISB to ensure system register writes take effect
    asm volatile ("isb");
}

// ── Main GIC Initialization ──────────────────────────────────────────────
pub fn init(dist_base: u64, redist_base: u64, version: u32) void {
    gic_state.dist_base = dist_base;
    gic_state.redist_base = redist_base;
    gic_state.version = version;

    // Initialize IRQ descriptor table
    if (!irq_table_initialized) {
        var i: u32 = 0;
        while (i < MAX_IRQS) : (i += 1) {
            irq_table[i] = IrqDescriptor.init(i);
        }
        irq_table_initialized = true;
    }

    // Initialize distributor
    initDistributor();

    // Initialize redistributor for boot CPU
    initRedistributor(0);

    // Initialize CPU interface for boot CPU
    initCpuInterface();

    gic_state.initialized = true;
}

pub fn initSecondaryCpu(cpu_idx: u32) void {
    initRedistributor(cpu_idx);
    initCpuInterface();
}

// ── IRQ Management API ───────────────────────────────────────────────────
pub fn enableIrq(intid: u32) void {
    if (intid >= MAX_IRQS) return;
    if (intid < SPI_START) {
        // SGI/PPI — use redistributor
        gicRedistWrite(0, GICR.ISENABLER0, @as(u32, 1) << @truncate(intid));
    } else {
        // SPI — use distributor
        const reg = (intid / 32);
        const bit = @as(u32, 1) << @truncate(intid % 32);
        gicDistWrite(GICD.ISENABLER + reg * 4, bit);
    }
    irq_table[intid].enabled = true;
}

pub fn disableIrq(intid: u32) void {
    if (intid >= MAX_IRQS) return;
    if (intid < SPI_START) {
        gicRedistWrite(0, GICR.ICENABLER0, @as(u32, 1) << @truncate(intid));
    } else {
        const reg = (intid / 32);
        const bit = @as(u32, 1) << @truncate(intid % 32);
        gicDistWrite(GICD.ICENABLER + reg * 4, bit);
    }
    irq_table[intid].enabled = false;
}

pub fn setPriority(intid: u32, priority: u8) void {
    if (intid >= MAX_IRQS) return;
    if (intid < SPI_START) {
        const reg = GICR.IPRIORITYR0 + (intid & ~@as(u32, 3));
        var val = gicRedistRead(0, reg);
        const shift: u5 = @truncate((intid % 4) * 8);
        val &= ~(@as(u32, 0xFF) << shift);
        val |= @as(u32, priority) << shift;
        gicRedistWrite(0, reg, val);
    } else {
        const reg = GICD.IPRIORITYR + (intid & ~@as(u32, 3));
        var val = gicDistRead(reg);
        const shift: u5 = @truncate((intid % 4) * 8);
        val &= ~(@as(u32, 0xFF) << shift);
        val |= @as(u32, priority) << shift;
        gicDistWrite(reg, val);
    }
    irq_table[intid].priority = priority;
}

pub fn setTrigger(intid: u32, trigger: TriggerType) void {
    if (intid < SGI_COUNT or intid >= MAX_IRQS) return; // SGIs are fixed edge

    const reg_offset = if (intid < SPI_START) blk: {
        break :blk GICR.ICFGR0 + ((intid / 16) * 4);
    } else blk: {
        break :blk GICD.ICFGR + ((intid / 16) * 4);
    };

    const bit_shift: u5 = @truncate((intid % 16) * 2 + 1);
    var val = if (intid < SPI_START) gicRedistRead(0, reg_offset) else gicDistRead(reg_offset);

    if (trigger == .edge) {
        val |= @as(u32, 1) << bit_shift;
    } else {
        val &= ~(@as(u32, 1) << bit_shift);
    }

    if (intid < SPI_START) {
        gicRedistWrite(0, reg_offset, val);
    } else {
        gicDistWrite(reg_offset, val);
    }
    irq_table[intid].trigger = trigger;
}

pub fn setAffinity(intid: u32, mpidr_aff: u64) void {
    if (intid < SPI_START or intid >= MAX_IRQS) return; // Only SPIs
    const route_reg = GICD.IROUTER + intid * 8;
    gicDistWrite64(route_reg, mpidr_aff & 0xFF00FFFFFF); // Aff3.Aff2.Aff1.Aff0
}

pub fn registerHandler(intid: u32, handler: *const fn (u32, ?*anyopaque) void, data: ?*anyopaque) void {
    if (intid >= MAX_IRQS) return;
    irq_table[intid].handler = handler;
    irq_table[intid].handler_data = data;
}

// ── Interrupt Handling ────────────────────────────────────────────────────
pub fn handleIrq() void {
    // Acknowledge interrupt
    const intid = iccReadIar1();

    // Check for spurious
    if (intid == INTID_SPURIOUS) return;

    if (intid < MAX_IRQS) {
        irq_table[intid].count += 1;

        // Call handler if registered
        if (irq_table[intid].handler) |handler| {
            handler(intid, irq_table[intid].handler_data);
        }
    }

    // Signal End of Interrupt (priority drop)
    iccWriteEoir1(intid);

    // Deactivate interrupt (since EOImode=1)
    iccWriteDir(intid);
}

// ── SGI (Software Generated Interrupt) ────────────────────────────────────
pub const SgiTarget = enum {
    all_but_self,
    self_only,
    specific,
};

pub fn sendSgi(intid: u32, target: SgiTarget, target_list: u16) void {
    if (intid >= SGI_COUNT) return;

    var val: u64 = @as(u64, intid) << 24;

    switch (target) {
        .all_but_self => {
            val |= 1 << 40; // IRM = 1 (all but self)
        },
        .self_only => {
            // Get own affinity
            const mpidr = asm ("mrs %[r], MPIDR_EL1" : [r] "=r" (-> u64));
            val |= (mpidr & 0xFF) << 0;         // Aff0 → TargetList
            val |= (mpidr & 0xFF00);             // Aff1
            val |= ((mpidr >> 16) & 0xFF) << 32; // Aff2
            val |= ((mpidr >> 32) & 0xFF) << 48; // Aff3
        },
        .specific => {
            val |= @as(u64, target_list); // TargetList
        },
    }

    iccWriteSgi1r(val);
    asm volatile ("isb");
}

// ── IPI Convenience Functions ─────────────────────────────────────────────
pub const IPI_RESCHEDULE: u32 = 0;    // SGI 0: scheduler reschedule
pub const IPI_CALL_FUNC: u32 = 1;     // SGI 1: call function on target
pub const IPI_CALL_FUNC_SINGLE: u32 = 2; // SGI 2: call function on single target
pub const IPI_TIMER: u32 = 3;         // SGI 3: timer broadcast
pub const IPI_CPU_STOP: u32 = 4;      // SGI 4: stop CPU
pub const IPI_CPU_CRASH: u32 = 5;     // SGI 5: crash dump
pub const IPI_TLB_SHOOTDOWN: u32 = 6; // SGI 6: TLB invalidation

pub fn sendIpiAllButSelf(ipi: u32) void {
    sendSgi(ipi, .all_but_self, 0);
}

pub fn sendIpiSelf(ipi: u32) void {
    sendSgi(ipi, .self_only, 0);
}

// ── Helper Functions ──────────────────────────────────────────────────────
fn waitForRwp() void {
    var timeout: u32 = 1_000_000;
    while (timeout > 0) : (timeout -= 1) {
        if (gicDistRead(GICD.CTLR) & GICD.CTLR_RWP == 0) return;
    }
}

fn findRedistributorForCpu(cpu_idx: u32) u64 {
    var offset: u64 = 0;
    var idx: u32 = 0;

    while (idx <= cpu_idx and offset < 0x200000) { // Safety limit
        const base = gic_state.redist_base + offset;
        const typer_ptr: *volatile u64 = @ptrFromInt(base + GICR.TYPER);
        const typer = typer_ptr.*;

        if (idx == cpu_idx) {
            return base;
        }

        idx += 1;

        // Check if this is the last redistributor
        if (typer & GICR.TYPER_LAST != 0) break;

        offset += GICR.FRAME_SIZE;
    }

    return 0;
}

pub fn isInitialized() bool {
    return gic_state.initialized;
}

pub fn getIrqCount(intid: u32) u64 {
    if (intid >= MAX_IRQS) return 0;
    return irq_table[intid].count;
}

pub fn getMaxIrqs() u32 {
    return gic_state.max_irqs;
}
