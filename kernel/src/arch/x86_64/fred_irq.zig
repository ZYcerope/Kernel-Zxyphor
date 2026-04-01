// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - FRED (Flexible Return and Event Delivery),
// Interrupt Descriptor Table Advanced, MSI/MSI-X IRQ,
// IRQ Domain Framework, IRQ Chip Framework,
// x86 Exception Handlers, NMI Handling
// More advanced than Linux 2026 interrupt subsystem

const std = @import("std");

// ============================================================================
// FRED - Flexible Return and Event Delivery (Intel)
// ============================================================================

/// FRED event type (in stack frame)
pub const FredEventType = enum(u8) {
    external_interrupt = 0,
    nmi = 1,
    double_fault = 2,
    software_interrupt = 3,
    privileged_sw_exception = 4,
    sw_exception = 5,
    hw_exception = 6,
    other_event = 7,
};

/// FRED entry point level
pub const FredLevel = enum(u2) {
    level0 = 0,    // ring-0 events
    level1 = 1,    // ring-1/2 (rarely used)
    level2 = 2,    // ring-2
    level3 = 3,    // ring-3 (user) events
};

/// FRED configuration (RSP values for each level)
pub const FredConfig = struct {
    stklvls: [4]u64 = [_]u64{0} ** 4,   // RSP for each FRED level
    entrypoint_kernel: u64 = 0,           // IA32_FRED_CONFIG MSR
    entrypoint_user: u64 = 0,
    enabled: bool = false,
    // Event-level assignments
    nmi_level: FredLevel = .level0,
    db_level: FredLevel = .level0,
    mc_level: FredLevel = .level0,
    bp_level: FredLevel = .level3,
    of_level: FredLevel = .level3,
};

/// FRED stack frame (pushed by CPU on FRED event)
pub const FredStackFrame = extern struct {
    // Standard frame
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
    // FRED additional fields
    fred_ss_event_type: u64,   // SS + event type + event vector
    fred_cs_aux: u64,          // CS auxiliary info
    // Error code (if applicable)
    error_code: u64,
};

/// FRED MSRs
pub const FredMsr = enum(u32) {
    ia32_fred_rsp0 = 0x1CC,
    ia32_fred_rsp1 = 0x1CD,
    ia32_fred_rsp2 = 0x1CE,
    ia32_fred_rsp3 = 0x1CF,
    ia32_fred_stklvls = 0x1D0,
    ia32_fred_ssp0 = 0x1D1,
    ia32_fred_ssp1 = 0x1D2,
    ia32_fred_ssp2 = 0x1D3,
    ia32_fred_ssp3 = 0x1D4,
    ia32_fred_config = 0x1D5,
};

// ============================================================================
// x86 Exception Vectors
// ============================================================================

/// x86 exception vector number
pub const X86Exception = enum(u8) {
    divide_error = 0,             // #DE
    debug = 1,                    // #DB
    nmi = 2,                      // NMI
    breakpoint = 3,               // #BP
    overflow = 4,                 // #OF
    bound_range = 5,              // #BR
    invalid_opcode = 6,           // #UD
    device_not_available = 7,     // #NM
    double_fault = 8,             // #DF
    coprocessor_overrun = 9,      // (legacy)
    invalid_tss = 10,             // #TS
    segment_not_present = 11,     // #NP
    stack_fault = 12,             // #SS
    general_protection = 13,      // #GP
    page_fault = 14,              // #PF
    _reserved_15 = 15,
    x87_fp_error = 16,            // #MF
    alignment_check = 17,         // #AC
    machine_check = 18,           // #MC
    simd_fp_exception = 19,       // #XM / #XF
    virtualization_exception = 20, // #VE
    control_protection = 21,      // #CP (CET)
    _reserved_22 = 22,
    _reserved_23 = 23,
    _reserved_24 = 24,
    _reserved_25 = 25,
    _reserved_26 = 26,
    _reserved_27 = 27,
    hypervisor_injection = 28,    // #HV (AMD SEV-ES)
    vmm_communication = 29,       // #VC (AMD SEV-ES)
    security_exception = 30,      // #SX (AMD)
    _reserved_31 = 31,
};

/// Page fault error code bits
pub const PageFaultError = packed struct(u64) {
    present: bool = false,            // P: page was present
    write: bool = false,              // W/R: write access
    user: bool = false,               // U/S: user mode
    reserved_write: bool = false,     // RSVD: reserved bit set
    instruction_fetch: bool = false,  // I/D: instruction fetch
    protection_key: bool = false,     // PK: protection key violation
    shadow_stack: bool = false,       // SS: shadow stack
    hlat: bool = false,               // HLAT
    _reserved: u7 = 0,
    sgx: bool = false,                // SGX: SGX violation
    _padding: u48 = 0,
};

/// #GP error code (for segment-related)
pub const GpErrorCode = packed struct(u32) {
    ext: bool = false,        // external event
    idt: bool = false,        // IDT reference
    ti: bool = false,         // GDT/LDT (0=GDT, 1=LDT)
    selector_index: u13 = 0,  // segment selector index
    _padding: u16 = 0,
};

// ============================================================================
// IDT Advanced
// ============================================================================

/// IDT gate type
pub const IdtGateType = enum(u4) {
    interrupt_gate_32 = 0xE,
    trap_gate_32 = 0xF,
    interrupt_gate_64 = 0xE,
    trap_gate_64 = 0xF,
};

/// IDT entry (64-bit mode)
pub const IdtEntry64 = extern struct {
    offset_low: u16,
    segment_selector: u16,
    ist: u3,
    _reserved0: u5,
    gate_type: u4,
    _zero: u1,
    dpl: u2,
    present: u1,
    offset_mid: u16,
    offset_high: u32,
    _reserved1: u32,
};

/// IST (Interrupt Stack Table) assignments
pub const IstAssignment = struct {
    double_fault: u3 = 1,
    nmi: u3 = 2,
    debug: u3 = 3,
    machine_check: u3 = 4,
    // Available: 5, 6, 7
};

// ============================================================================
// MSI / MSI-X
// ============================================================================

/// MSI message descriptor
pub const MsiMessage = struct {
    address_lo: u32 = 0,
    address_hi: u32 = 0,
    data: u32 = 0,
};

/// MSI address format (x86)
pub const MsiAddress = packed struct(u32) {
    _reserved_low: u2 = 0,
    destination_mode: bool = false,   // 0=physical, 1=logical
    redirection_hint: bool = false,
    _reserved_mid: u8 = 0,
    destination_id: u8 = 0,
    base_address: u12 = 0xFEE,       // fixed MSI base
};

/// MSI data format (x86)
pub const MsiData = packed struct(u32) {
    vector: u8 = 0,
    delivery_mode: u3 = 0,
    _reserved: u3 = 0,
    level: bool = false,
    trigger_mode: bool = false,       // 0=edge, 1=level
    _padding: u16 = 0,
};

/// MSI-X table entry
pub const MsixTableEntry = extern struct {
    msg_addr: u32,
    msg_upper_addr: u32,
    msg_data: u32,
    vector_control: u32,    // bit 0 = masked
};

/// MSI capability descriptor
pub const MsiCapDesc = struct {
    nr_vectors: u32 = 0,
    nr_vectors_allocated: u32 = 0,
    is_msix: bool = false,
    multi_msg_capable: u8 = 0,
    multi_msg_enable: u8 = 0,
    per_vector_masking: bool = false,
    affinity_managed: bool = false,
};

// ============================================================================
// IRQ Domain Framework
// ============================================================================

/// IRQ domain type
pub const IrqDomainType = enum(u8) {
    linear = 0,
    tree = 1,
    nomap = 2,
    legacy = 3,
    msi = 4,
    // Zxyphor
    zxy_hierarchical = 100,
};

/// IRQ domain descriptor
pub const IrqDomainDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    domain_type: IrqDomainType = .linear,
    nr_irqs: u32 = 0,
    hwirq_max: u32 = 0,
    parent_domain: u64 = 0,           // parent IRQ domain for hierarchy
    fwnode: u64 = 0,                   // firmware node
    bus_token: IrqDomainBusToken = .any,
    flags: IrqDomainFlags = .{},
};

pub const IrqDomainBusToken = enum(u8) {
    any = 0,
    wired = 1,
    pci_msi = 2,
    platform_msi = 3,
    nexus = 4,
    ipi = 5,
    fsl_mc_msi = 6,
    ti_sci_inta_msi = 7,
    dmar = 8,
    hpet = 9,
    // Zxyphor
    zxy_native = 100,
};

pub const IrqDomainFlags = packed struct(u32) {
    hierarchy: bool = false,
    name_allocated: bool = false,
    is_fwnode: bool = false,
    no_map: bool = false,
    msi: bool = false,
    msi_parent: bool = false,
    msi_device: bool = false,
    noncore: bool = false,
    destroy_gc: bool = false,
    _padding: u23 = 0,
};

// ============================================================================
// IRQ Chip Framework
// ============================================================================

/// IRQ chip type
pub const IrqChipType = enum(u8) {
    dummy = 0,
    apic = 1,
    ioapic = 2,
    msi = 3,
    dmar = 4,
    hpet = 5,
    gpio = 6,
    pci = 7,
    platform = 8,
    // Zxyphor
    zxy_advanced = 100,
};

/// IRQ chip flags
pub const IrqChipFlags = packed struct(u32) {
    set_type_masked: bool = false,
    mask_on_suspend: bool = false,
    immutable: bool = false,
    skip_set_wake: bool = false,
    affinity_pre_startup: bool = false,
    init_mask_cache: bool = false,
    // Zxyphor
    zxy_priority_aware: bool = false,
    _padding: u25 = 0,
};

/// IRQ chip descriptor
pub const IrqChipDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    chip_type: IrqChipType = .dummy,
    flags: IrqChipFlags = .{},
    irq_base: u32 = 0,
    nr_irqs: u32 = 0,
    parent_chip: u64 = 0,
};

/// IRQ descriptor flags
pub const IrqDescFlags = packed struct(u32) {
    per_cpu: bool = false,
    is_chained: bool = false,
    is_percpu_devid: bool = false,
    noautoen: bool = false,
    no_balancing: bool = false,
    no_set_affinity: bool = false,
    nested_thread: bool = false,
    no_thread: bool = false,
    no_debug: bool = false,
    managed: bool = false,
    is_polled: bool = false,
    disable_unlazy: bool = false,
    hidden: bool = false,
    no_suspend: bool = false,
    cond_suspend: bool = false,
    _padding: u17 = 0,
};

// ============================================================================
// NMI Handling
// ============================================================================

/// NMI reason
pub const NmiReason = enum(u8) {
    unknown = 0,
    memory_parity = 1,
    io_check = 2,
    watchdog = 3,
    external = 4,
    local = 5,
    // Zxyphor
    zxy_kernel_debug = 100,
};

/// NMI handler type
pub const NmiHandlerType = enum(u8) {
    normal = 0,
    latency = 1,
    unknown = 2,
    default = 3,
};

/// NMI statistics
pub const NmiStats = struct {
    count: u64 = 0,
    external: u64 = 0,
    watchdog: u64 = 0,
    parity: u64 = 0,
    io_check: u64 = 0,
    unknown: u64 = 0,
    swallow: u64 = 0,
};

// ============================================================================
// IRQ Subsystem Manager
// ============================================================================

pub const IrqSubsystem = struct {
    nr_irqs: u32 = 0,
    nr_irq_domains: u32 = 0,
    nr_irq_chips: u32 = 0,
    nr_msi_irqs: u32 = 0,
    nr_msix_irqs: u32 = 0,
    fred_enabled: bool = false,
    max_vector: u32 = 256,
    nr_nmi: u64 = 0,
    nr_spurious: u64 = 0,
    nr_softirq: u64 = 0,
    irq_balance_enabled: bool = true,
    threaded_irq_count: u32 = 0,
    initialized: bool = false,

    pub fn init() IrqSubsystem {
        return IrqSubsystem{
            .nr_irqs = 256,
            .initialized = true,
        };
    }
};
