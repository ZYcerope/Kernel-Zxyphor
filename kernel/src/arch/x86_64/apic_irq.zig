// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Advanced APIC/IO-APIC/x2APIC and Interrupt Management
// Local APIC, IO-APIC, x2APIC, MSI/MSI-X, IPI, NMI, Timer,
// IRQ affinity, interrupt remapping, posted interrupts
// More advanced than Linux 2026 interrupt architecture

const std = @import("std");

// ============================================================================
// Local APIC Registers
// ============================================================================

pub const APIC_BASE_MSR: u32 = 0x1B;
pub const APIC_BASE_ADDR: u64 = 0xFEE00000;
pub const X2APIC_MSR_BASE: u32 = 0x800;

pub const ApicReg = enum(u32) {
    id = 0x020,
    version = 0x030,
    tpr = 0x080,       // Task Priority Register
    apr = 0x090,       // Arbitration Priority Register
    ppr = 0x0A0,       // Processor Priority Register
    eoi = 0x0B0,       // End Of Interrupt
    rrd = 0x0C0,       // Remote Read Register
    ldr = 0x0D0,       // Logical Destination Register
    dfr = 0x0E0,       // Destination Format Register
    svr = 0x0F0,       // Spurious Interrupt Vector Register
    isr_0 = 0x100,     // In-Service Register (8 regs)
    isr_1 = 0x110,
    isr_2 = 0x120,
    isr_3 = 0x130,
    isr_4 = 0x140,
    isr_5 = 0x150,
    isr_6 = 0x160,
    isr_7 = 0x170,
    tmr_0 = 0x180,     // Trigger Mode Register (8 regs)
    tmr_1 = 0x190,
    tmr_2 = 0x1A0,
    tmr_3 = 0x1B0,
    tmr_4 = 0x1C0,
    tmr_5 = 0x1D0,
    tmr_6 = 0x1E0,
    tmr_7 = 0x1F0,
    irr_0 = 0x200,     // Interrupt Request Register (8 regs)
    irr_1 = 0x210,
    irr_2 = 0x220,
    irr_3 = 0x230,
    irr_4 = 0x240,
    irr_5 = 0x250,
    irr_6 = 0x260,
    irr_7 = 0x270,
    esr = 0x280,        // Error Status Register
    lvt_cmci = 0x2F0,   // LVT Corrected Machine Check Interrupt
    icr_lo = 0x300,      // Interrupt Command Register (low)
    icr_hi = 0x310,      // Interrupt Command Register (high)
    lvt_timer = 0x320,
    lvt_thermal = 0x330,
    lvt_perf = 0x340,
    lvt_lint0 = 0x350,
    lvt_lint1 = 0x360,
    lvt_error = 0x370,
    timer_icr = 0x380,   // Timer Initial Count
    timer_ccr = 0x390,   // Timer Current Count
    timer_dcr = 0x3E0,   // Timer Divide Configuration
    self_ipi = 0x3F0,    // x2APIC Self IPI
};

// ============================================================================
// APIC Delivery Modes
// ============================================================================

pub const ApicDeliveryMode = enum(u3) {
    fixed = 0,
    lowest_priority = 1,
    smi = 2,
    nmi = 4,
    init = 5,
    startup = 6,
    ext_int = 7,
};

pub const ApicDestMode = enum(u1) {
    physical = 0,
    logical = 1,
};

pub const ApicTriggerMode = enum(u1) {
    edge = 0,
    level = 1,
};

pub const ApicTimerMode = enum(u2) {
    one_shot = 0,
    periodic = 1,
    tsc_deadline = 2,
};

// ============================================================================
// LVT Entry
// ============================================================================

pub const LvtEntry = packed struct {
    vector: u8,
    delivery_mode: u3,
    _reserved1: u1 = 0,
    delivery_status: u1,
    pin_polarity: u1,
    remote_irr: u1,
    trigger_mode: u1,
    mask: u1,
    timer_mode: u2,
    _reserved2: u13 = 0,

    pub fn is_pending(self: LvtEntry) bool {
        return self.delivery_status == 1;
    }

    pub fn is_masked(self: LvtEntry) bool {
        return self.mask == 1;
    }
};

// ============================================================================
// ICR (Interrupt Command Register)
// ============================================================================

pub const IcrEntry = packed struct {
    vector: u8,
    delivery_mode: u3,
    dest_mode: u1,
    delivery_status: u1,
    _reserved1: u1 = 0,
    level: u1,
    trigger_mode: u1,
    _reserved2: u2 = 0,
    dest_shorthand: u2,
    _reserved3: u12 = 0,
    destination: u32,
};

pub const IcrDestShorthand = enum(u2) {
    no_shorthand = 0,
    self_only = 1,
    all_including_self = 2,
    all_excluding_self = 3,
};

// ============================================================================
// IO-APIC
// ============================================================================

pub const IOAPIC_MAX_PINS: u32 = 256;
pub const IOAPIC_REG_SELECT: u32 = 0x00;
pub const IOAPIC_REG_WINDOW: u32 = 0x10;

pub const IoApicReg = enum(u32) {
    id = 0x00,
    version = 0x01,
    arb = 0x02,
    redtbl_base = 0x10,  // Each entry is 2 regs (low+high)
};

pub const IoApicRedirEntry = packed struct {
    vector: u8,
    delivery_mode: u3,
    dest_mode: u1,
    delivery_status: u1,
    polarity: u1,
    remote_irr: u1,
    trigger_mode: u1,
    mask: u1,
    _reserved: u15 = 0,
    extended_dest_id: u8,
    destination: u8,

    pub fn is_level_triggered(self: IoApicRedirEntry) bool {
        return self.trigger_mode == 1;
    }

    pub fn is_active_low(self: IoApicRedirEntry) bool {
        return self.polarity == 1;
    }
};

pub const IoApic = struct {
    id: u8,
    version: u8,
    base_addr: u64,
    gsi_base: u32,
    nr_pins: u32,
    // Redirection table
    redir_table: [IOAPIC_MAX_PINS]IoApicRedirEntry,
    // IRQ to pin mapping
    irq_pin_map: [IOAPIC_MAX_PINS]u32,
    pin_irq_map: [IOAPIC_MAX_PINS]u32,
    // Stats
    interrupts_delivered: [IOAPIC_MAX_PINS]u64,

    pub fn read_reg(self: *const IoApic, reg: u32) u32 {
        _ = self;
        _ = reg;
        // MMIO read: write reg to IOREGSEL, read from IOWIN
        return 0;
    }

    pub fn write_reg(self: *IoApic, reg: u32, value: u32) void {
        _ = self;
        _ = reg;
        _ = value;
        // MMIO write: write reg to IOREGSEL, write value to IOWIN
    }

    pub fn max_gsi(self: *const IoApic) u32 {
        return self.gsi_base + self.nr_pins - 1;
    }
};

// ============================================================================
// x2APIC Mode
// ============================================================================

pub const X2ApicState = struct {
    enabled: bool,
    id: u32,
    cluster_id: u16,
    logical_id: u16,
    version: u32,
    max_lvt_entry: u8,
    eoi_broadcast_suppression: bool,

    pub fn read_msr(self: *const X2ApicState, reg: ApicReg) u64 {
        _ = self;
        const msr = X2APIC_MSR_BASE + @intFromEnum(reg) / 0x10;
        _ = msr;
        return 0; // rdmsr
    }

    pub fn write_msr(self: *X2ApicState, reg: ApicReg, value: u64) void {
        _ = self;
        const msr = X2APIC_MSR_BASE + @intFromEnum(reg) / 0x10;
        _ = msr;
        _ = value;
        // wrmsr
    }
};

// ============================================================================
// MSI/MSI-X
// ============================================================================

pub const MsiAddress = packed struct {
    _reserved1: u2 = 0,
    dest_mode: u1,
    redirect_hint: u1,
    _reserved2: u8 = 0,
    destination_id: u8,
    base_address: u12 = 0xFEE,  // 0xFEE00000 >> 20
};

pub const MsiData = packed struct {
    vector: u8,
    delivery_mode: u3,
    _reserved1: u3 = 0,
    level: u1,
    trigger_mode: u1,
    _reserved2: u16 = 0,
};

pub const MsiEntry = struct {
    address_lo: u32,
    address_hi: u32,
    data: u32,
    // MSI-X table entry
    vector_control: u32,  // bit 0 = mask
    // Tracking
    irq: u32,
    cpu_affinity: u64,
    managed: bool,
};

pub const MsiXCapability = struct {
    msg_control: u16,
    table_offset: u32,
    table_bir: u8,
    pba_offset: u32,
    pba_bir: u8,
    nr_entries: u32,
    // Entries
    entries: [2048]MsiEntry,
    nr_allocated: u32,
    // State
    enabled: bool,
    masked: bool,
};

// ============================================================================
// IRQ Descriptor / IRQ Domain
// ============================================================================

pub const IrqType = enum(u8) {
    none = 0,
    edge = 1,
    level = 2,
    fasteoi = 3,
    simple = 4,
    percpu = 5,
    percpu_devid = 6,
    msi = 7,
};

pub const IrqAction = struct {
    handler: ?*const fn (u32, ?*anyopaque) u32,
    thread_fn: ?*const fn (u32, ?*anyopaque) u32,
    irq: u32,
    flags: u32,
    name: [64]u8,
    dev_id: ?*anyopaque,
    percpu_dev_id: ?*anyopaque,
    next: ?*IrqAction,
    // Thread
    thread_pid: i32,
    thread_flags: u32,
    // Stats
    count: u64,
};

// IRQ Action Flags
pub const IRQF_SHARED: u32 = 0x00000080;
pub const IRQF_PROBE_SHARED: u32 = 0x00000100;
pub const IRQF_TIMER: u32 = 0x00000200;
pub const IRQF_PERCPU: u32 = 0x00000400;
pub const IRQF_NOBALANCING: u32 = 0x00000800;
pub const IRQF_IRQPOLL: u32 = 0x00001000;
pub const IRQF_ONESHOT: u32 = 0x00002000;
pub const IRQF_NO_SUSPEND: u32 = 0x00004000;
pub const IRQF_FORCE_RESUME: u32 = 0x00008000;
pub const IRQF_NO_THREAD: u32 = 0x00010000;
pub const IRQF_EARLY_RESUME: u32 = 0x00020000;
pub const IRQF_COND_SUSPEND: u32 = 0x00040000;
pub const IRQF_NO_AUTOEN: u32 = 0x00080000;

pub const IrqDesc = struct {
    irq: u32,
    irq_type: IrqType,
    action: ?*IrqAction,
    depth: u32,        // Disable depth
    wake_depth: u32,
    irq_count: u64,
    irqs_unhandled: u64,
    last_unhandled: u64,
    // Affinity
    affinity_hint: u64,  // CPU bitmask
    effective_affinity: u64,
    pending_mask: u64,
    // State
    status_use_accessors: u32,
    core_internal_state__do_not_mess_with_it: u32,
    name: [32]u8,
    // Per-CPU counts
    kstat_irqs: [256]u64,  // per-CPU
};

pub const IrqDomainType = enum(u8) {
    linear = 0,
    tree = 1,
    nomap = 2,
    legacy = 3,
    msi = 4,
    msi_direct = 5,
};

pub const IrqDomain = struct {
    name: [64]u8,
    domain_type: IrqDomainType,
    parent: ?*IrqDomain,
    hwirq_max: u32,
    revmap_size: u32,
    // Mappings
    linear_revmap: [1024]u32,
    nr_irqs: u32,
    // Flags
    flags: u32,
};

// ============================================================================
// IPI (Inter-Processor Interrupt)
// ============================================================================

pub const IpiType = enum(u8) {
    reschedule = 0,
    call_function = 1,
    call_function_single = 2,
    tlb_shootdown = 3,
    reboot = 4,
    stop = 5,
    nmi_ipi = 6,
    irq_work = 7,
    timer = 8,
    // Zxyphor
    zxy_sync = 9,
    zxy_debug = 10,
};

pub const IPI_VECTORS_START: u8 = 0xE0;

pub const IpiStats = struct {
    sent: [16]u64,       // per IPI type
    received: [16]u64,
    total_sent: u64,
    total_received: u64,
    nr_cpus: u32,
};

// ============================================================================
// NMI (Non-Maskable Interrupt)
// ============================================================================

pub const NmiType = enum(u8) {
    unknown = 0,
    local = 1,
    io_check = 2,
    watchdog = 3,
    external = 4,
    serr = 5,
    back_to_back = 6,
    latency = 7,
};

pub const NmiStats = struct {
    count: [8]u64,       // per type
    unknown_count: u64,
    swallow_count: u64,
    total: u64,
};

// ============================================================================
// Interrupt Remapping (IR)
// ============================================================================

pub const IntRemapType = enum(u8) {
    none = 0,
    intel_ir = 1,     // Intel VT-d Interrupt Remapping
    amd_ir = 2,       // AMD IOMMU Interrupt Remapping
};

pub const IntrRemapEntry = struct {
    // Intel IRTE (Interrupt Remapping Table Entry)
    present: bool,
    fpd: bool,         // Fault Processing Disable
    dest_mode: ApicDestMode,
    redir_hint: bool,
    trigger_mode: ApicTriggerMode,
    delivery_mode: ApicDeliveryMode,
    avail: u4,
    vector: u8,
    destination_id: u32,
    sid: u16,          // Source ID
    sq: u2,            // Source ID qualifier
    svt: u2,           // Source Validation Type
    // Posted Interrupts
    posted: bool,
    urgent: bool,
    posted_desc_addr: u64,
};

pub const IntrRemapTable = struct {
    entries: [65536]IntrRemapEntry,
    nr_entries: u32,
    enabled: bool,
    ir_type: IntRemapType,
    // Extended interrupt mode (x2APIC)
    eim: bool,
};

// ============================================================================
// Posted Interrupts (Intel VT-d)
// ============================================================================

pub const PostedInterruptDesc = struct {
    pir: [4]u64,           // Posted Interrupt Requests (256 bits)
    outstanding: bool,
    suppress: bool,
    notification_vector: u8,
    notification_dest: u32,

    pub fn is_set(self: *const PostedInterruptDesc, vector: u8) bool {
        const word = vector / 64;
        const bit: u6 = @truncate(vector % 64);
        return (self.pir[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn set_vector(self: *PostedInterruptDesc, vector: u8) void {
        const word = vector / 64;
        const bit: u6 = @truncate(vector % 64);
        self.pir[word] |= (@as(u64, 1) << bit);
    }

    pub fn clear_vector(self: *PostedInterruptDesc, vector: u8) void {
        const word = vector / 64;
        const bit: u6 = @truncate(vector % 64);
        self.pir[word] &= ~(@as(u64, 1) << bit);
    }

    pub fn any_pending(self: *const PostedInterruptDesc) bool {
        for (self.pir) |word| {
            if (word != 0) return true;
        }
        return false;
    }
};

// ============================================================================
// TSC (Time Stamp Counter)
// ============================================================================

pub const TscState = struct {
    frequency_khz: u64,
    frequency_hz: u64,
    reliable: bool,
    // Calibration
    calibrated: bool,
    calibration_method: enum(u8) {
        none = 0,
        pmtimer = 1,
        hpet = 2,
        pit = 3,
        cpuid = 4,
        msr = 5,
    },
    // TSC deadline
    tsc_deadline_supported: bool,
    // Invariant TSC
    invariant_tsc: bool,
    // Nonstop TSC
    nonstop_tsc: bool,
    // TSC adjust
    tsc_adjust_msr: u64,
    // Conversion factors
    mult: u32,
    shift: u32,

    pub fn tsc_to_ns(self: *const TscState, tsc: u64) u64 {
        return (tsc *% @as(u64, self.mult)) >> @as(u6, @truncate(self.shift));
    }

    pub fn ns_to_tsc(self: *const TscState, ns: u64) u64 {
        if (self.mult == 0) return 0;
        return (ns << @as(u6, @truncate(self.shift))) / @as(u64, self.mult);
    }
};

// ============================================================================
// Full APIC Subsystem
// ============================================================================

pub const ApicMode = enum(u8) {
    disabled = 0,
    xapic = 1,
    x2apic = 2,
};

pub const ApicSubsystem = struct {
    // Mode
    mode: ApicMode,
    // Local APIC
    local_apic_id: u32,
    local_apic_version: u32,
    local_apic_base: u64,
    local_apic_enabled: bool,
    bsp: bool,  // Bootstrap Processor
    // x2APIC
    x2apic: X2ApicState,
    // IO-APICs
    ioapics: [8]IoApic,
    nr_ioapics: u32,
    // MSI-X
    msix_supported: bool,
    nr_msi_entries: u32,
    // IRQ descriptors
    irq_descs: [4096]IrqDesc,
    nr_irqs: u32,
    // IRQ domains
    irq_domains: [32]IrqDomain,
    nr_domains: u32,
    // IPI
    ipi_stats: IpiStats,
    // NMI
    nmi_stats: NmiStats,
    // Interrupt Remapping
    intr_remap: IntrRemapTable,
    // Posted Interrupts
    posted_intr_descs: [256]PostedInterruptDesc,
    nr_posted_descs: u32,
    // TSC
    tsc: TscState,
    // Timer
    timer_calibrated: bool,
    ticks_per_ms: u32,
    // Global stats
    total_interrupts: u64,
    spurious_interrupts: u64,
    err_interrupts: u64,
    // Zxyphor
    zxy_fast_eoi: bool,
    zxy_coalesced_irq: bool,
    initialized: bool,

    pub fn is_x2apic(self: *const ApicSubsystem) bool {
        return self.mode == .x2apic;
    }

    pub fn total_gsi(self: *const ApicSubsystem) u32 {
        var max_gsi: u32 = 0;
        for (self.ioapics[0..self.nr_ioapics]) |*ioapic| {
            const gsi = ioapic.max_gsi();
            if (gsi > max_gsi) max_gsi = gsi;
        }
        return max_gsi + 1;
    }
};
