// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - APIC Detail, IOAPIC, x2APIC, MSI/MSI-X
// Complete: Local APIC registers, x2APIC, IOAPIC redirection table,
// interrupt remapping, MSI/MSI-X, IPI delivery, NMI handling

const std = @import("std");

// ============================================================================
// Local APIC Registers
// ============================================================================

pub const LocalApicRegister = enum(u32) {
    ID = 0x020,
    Version = 0x030,
    TaskPriority = 0x080,
    ArbitrationPriority = 0x090,
    ProcessorPriority = 0x0A0,
    EOI = 0x0B0,
    RemoteRead = 0x0C0,
    LogicalDestination = 0x0D0,
    DestinationFormat = 0x0E0,
    SpuriousInterruptVector = 0x0F0,
    ISR0 = 0x100,
    ISR1 = 0x110,
    ISR2 = 0x120,
    ISR3 = 0x130,
    ISR4 = 0x140,
    ISR5 = 0x150,
    ISR6 = 0x160,
    ISR7 = 0x170,
    TMR0 = 0x180,
    TMR1 = 0x190,
    TMR2 = 0x1A0,
    TMR3 = 0x1B0,
    TMR4 = 0x1C0,
    TMR5 = 0x1D0,
    TMR6 = 0x1E0,
    TMR7 = 0x1F0,
    IRR0 = 0x200,
    IRR1 = 0x210,
    IRR2 = 0x220,
    IRR3 = 0x230,
    IRR4 = 0x240,
    IRR5 = 0x250,
    IRR6 = 0x260,
    IRR7 = 0x270,
    ErrorStatus = 0x280,
    LVT_CMCI = 0x2F0,
    ICR_Low = 0x300,
    ICR_High = 0x310,
    LVT_Timer = 0x320,
    LVT_Thermal = 0x330,
    LVT_PerfMon = 0x340,
    LVT_LINT0 = 0x350,
    LVT_LINT1 = 0x360,
    LVT_Error = 0x370,
    TimerInitialCount = 0x380,
    TimerCurrentCount = 0x390,
    TimerDivideConfig = 0x3E0,
};

pub const ApicVersion = packed struct(u32) {
    version: u8,
    _reserved1: u8,
    max_lvt_entry: u8,
    eoi_broadcast_suppression: bool,
    _reserved2: u7,
};

pub const ApicSpuriousVector = packed struct(u32) {
    vector: u8,
    apic_enabled: bool,
    focus_processor_checking: bool,
    eoi_broadcast_suppression: bool,
    _reserved: u21,
};

pub const ApicLvtEntry = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _reserved1: u1,
    delivery_status: u1,
    pin_polarity: u1,
    remote_irr: u1,
    trigger_mode: u1,
    mask: u1,
    timer_mode: u2,
    _reserved2: u13,
};

pub const ApicTimerMode = enum(u2) {
    OneShot = 0,
    Periodic = 1,
    TSCDeadline = 2,
};

pub const ApicDeliveryMode = enum(u3) {
    Fixed = 0,
    SMI = 2,
    NMI = 4,
    INIT = 5,
    ExtINT = 7,
};

pub const ApicTimerDivide = enum(u32) {
    By1 = 0b1011,
    By2 = 0b0000,
    By4 = 0b0001,
    By8 = 0b0010,
    By16 = 0b0011,
    By32 = 0b1000,
    By64 = 0b1001,
    By128 = 0b1010,
};

// ============================================================================
// ICR (Interrupt Command Register)
// ============================================================================

pub const IcrLow = packed struct(u32) {
    vector: u8,
    delivery_mode: u3, // Fixed/Lowest/SMI/NMI/INIT/StartUp
    dest_mode: u1, // 0=Physical, 1=Logical
    delivery_status: u1,
    _reserved1: u1,
    level: u1, // 0=De-assert, 1=Assert
    trigger_mode: u1, // 0=Edge, 1=Level
    _reserved2: u2,
    dest_shorthand: u2, // 0=None, 1=Self, 2=All-incl-self, 3=All-excl-self
    _reserved3: u12,
};

pub const IcrDeliveryMode = enum(u3) {
    Fixed = 0,
    LowestPriority = 1,
    SMI = 2,
    NMI = 4,
    INIT = 5,
    StartUp = 6,
};

pub const IcrDestShorthand = enum(u2) {
    NoShorthand = 0,
    Self = 1,
    AllIncludingSelf = 2,
    AllExcludingSelf = 3,
};

// ============================================================================
// APIC Error Status
// ============================================================================

pub const ApicErrorStatus = packed struct(u32) {
    send_checksum_error: bool,
    receive_checksum_error: bool,
    send_accept_error: bool,
    receive_accept_error: bool,
    redirectable_ipi: bool,
    send_illegal_vector: bool,
    received_illegal_vector: bool,
    illegal_register_address: bool,
    _reserved: u24,
};

// ============================================================================
// x2APIC (MSR-based)
// ============================================================================

pub const X2apicMsr = enum(u32) {
    Id = 0x802,
    Version = 0x803,
    Tpr = 0x808,
    Ppr = 0x80A,
    Eoi = 0x80B,
    Ldr = 0x80D,
    Svr = 0x80F,
    Isr0 = 0x810,
    Isr1 = 0x811,
    Isr2 = 0x812,
    Isr3 = 0x813,
    Isr4 = 0x814,
    Isr5 = 0x815,
    Isr6 = 0x816,
    Isr7 = 0x817,
    Tmr0 = 0x818,
    Tmr1 = 0x819,
    Tmr2 = 0x81A,
    Tmr3 = 0x81B,
    Tmr4 = 0x81C,
    Tmr5 = 0x81D,
    Tmr6 = 0x81E,
    Tmr7 = 0x81F,
    Irr0 = 0x820,
    Irr1 = 0x821,
    Irr2 = 0x822,
    Irr3 = 0x823,
    Irr4 = 0x824,
    Irr5 = 0x825,
    Irr6 = 0x826,
    Irr7 = 0x827,
    Esr = 0x828,
    LvtCmci = 0x82F,
    Icr = 0x830,
    LvtTimer = 0x832,
    LvtThermal = 0x833,
    LvtPerfmon = 0x834,
    LvtLint0 = 0x835,
    LvtLint1 = 0x836,
    LvtError = 0x837,
    Ticr = 0x838,
    Tccr = 0x839,
    Tdcr = 0x83E,
    SelfIpi = 0x83F,
};

pub const X2apicIcr = packed struct(u64) {
    vector: u8,
    delivery_mode: u3,
    dest_mode: u1,
    _reserved1: u2,
    level: u1,
    trigger_mode: u1,
    _reserved2: u2,
    dest_shorthand: u2,
    _reserved3: u12,
    destination: u32,
};

// ============================================================================
// IOAPIC
// ============================================================================

pub const IoapicRegister = enum(u32) {
    Id = 0x00,
    Version = 0x01,
    ArbitrationId = 0x02,
    // Redirection table entries at 0x10 + 2*n
};

pub const IoapicVersion = packed struct(u32) {
    version: u8,
    _reserved1: u8,
    max_redirection_entry: u8,
    _reserved2: u8,
};

pub const IoapicRedEntry = packed struct(u64) {
    vector: u8,
    delivery_mode: u3,
    dest_mode: u1, // 0=Physical, 1=Logical
    delivery_status: u1,
    pin_polarity: u1, // 0=Active-high, 1=Active-low
    remote_irr: u1,
    trigger_mode: u1, // 0=Edge, 1=Level
    mask: u1,
    _reserved: u39,
    destination: u8,
};

pub const IoapicInfo = struct {
    id: u8,
    version: u8,
    address: u64,
    gsi_base: u32,
    nr_registers: u32,
    entries: [24]IoapicRedEntry,
};

// ============================================================================
// Interrupt Remapping (VT-d / AMD-Vi)
// ============================================================================

pub const IrteFormat = enum(u8) {
    IntelRemapped = 0,
    IntelPosted = 1,
    AmdRemapped = 2,
    AmdVapic = 3,
};

pub const IntelIrte = packed struct(u128) {
    present: bool,
    fpd: bool, // Fault Processing Disable
    dest_mode: u1,
    redir_hint: u1,
    trigger_mode: u1,
    delivery_mode: u3,
    _reserved1: u4,
    avail: u4,
    _reserved2: u8,
    vector: u8,
    _reserved3: u8,
    destination: u32,
    source_id: u16,
    source_id_qualifier: u2,
    source_validation_type: u2,
    _reserved4: u12,
    posted_interrupt_descriptor: u46, // Physical address >> 6
    _reserved5: u2,
};

pub const AmdIrte = packed struct(u128) {
    remapped_format: bool,
    dm_status: u1,
    int_type: u3,
    rqeoi: u1,
    dm: u1,
    guest_mode: u1,
    destination: u8,
    vector: u8,
    _reserved1: u40,
    valid: bool,
    _reserved2: u63,
};

pub const IntrRemapConfig = struct {
    enabled: bool,
    format: IrteFormat,
    table_base: u64,
    table_size: u32,
    nr_entries: u32,
    x2apic_mode: bool,
    posted_interrupts: bool,
    extended_dest_id: bool,
};

// ============================================================================
// MSI / MSI-X
// ============================================================================

pub const MsiAddress = packed struct(u32) {
    _reserved1: u2,
    dest_mode_logical: bool, // DM bit
    redirection_hint: bool, // RH bit
    _reserved2: u8,
    destination_id: u8,
    fixed_prefix: u12, // Must be 0xFEE
};

pub const MsiData = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _reserved1: u3,
    level: u1,
    trigger_mode: u1, // 0=Edge, 1=Level
    _reserved2: u16,
};

pub const MsiMsg = struct {
    address_lo: u32,
    address_hi: u32,
    data: u32,
};

pub const MsixEntry = struct {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_control: u32, // Bit 0 = mask
};

pub const MsiDesc = struct {
    irq: u32,
    nvec_used: u32,
    msi_index: u16,
    msg: MsiMsg,
    masked: bool,
    is_msix: bool,
    multi_cap: u8,
    is_64bit: bool,
    entry_nr: i32,
    default_irq: u32,
    mask_pos: u32,
    mask_base: u64,
};

pub const PciMsiCap = packed struct(u32) {
    cap_id: u8, // 0x05
    next_ptr: u8,
    msi_enable: bool,
    multiple_message_capable: u3,
    multiple_message_enable: u3,
    addr64_capable: bool,
    per_vector_masking: bool,
    extended_message_data_capable: bool,
    extended_message_data_enable: bool,
    _reserved: u5,
};

pub const PciMsixCap = packed struct(u32) {
    cap_id: u8, // 0x11
    next_ptr: u8,
    msix_enable: bool,
    function_mask: bool,
    _reserved: u3,
    table_size: u11,
};

// ============================================================================
// IPI (Inter-Processor Interrupt)
// ============================================================================

pub const IpiVector = enum(u8) {
    Reschedule = 0xFB,
    CallFunction = 0xFC,
    CallFunctionSingle = 0xFD,
    TlbFlush = 0xFE,
    Reboot = 0xF1,
    ThermalApic = 0xFA,
    ThresholdApic = 0xF9,
    DeferredError = 0xF8,
    Irq_Work = 0xF7,
    X86_Platform_Ipi = 0xF6,
};

pub const IpiMessage = struct {
    type_field: IpiType,
    vector: u8,
    dest_apic_id: u32,
    shorthand: IcrDestShorthand,
    delivery_mode: IcrDeliveryMode,
};

pub const IpiType = enum(u8) {
    Reschedule = 0,
    CallFunction = 1,
    CallFunctionSingle = 2,
    TlbFlush = 3,
    Reboot = 4,
    StopCPU = 5,
    IrqWork = 6,
    NMI = 7,
};

// ============================================================================
// NMI Handling
// ============================================================================

pub const NmiReason = enum(u8) {
    Unknown = 0,
    MemoryParity = 1,
    IOCheck = 2,
    Watchdog = 3,
    Software = 4,
    External = 5,
    BacktracePrint = 6,
    CrashDump = 7,
};

pub const NmiHandler = struct {
    handler: ?*const fn (typ: u32, regs: *anyopaque) callconv(.C) u32,
    name: [32]u8,
    handler_type: NmiHandlerType,
    flags: u32,
};

pub const NmiHandlerType = enum(u8) {
    Unknown = 0,
    External = 1,
    Watchdog = 2,
    Software = 3,
    Internal = 4,
    Max = 5,
};

// ============================================================================
// Manager
// ============================================================================

pub const ApicDetailManager = struct {
    local_apic_base: u64,
    local_apic_id: u32,
    x2apic_enabled: bool,
    nr_ioapics: u8,
    ioapics: [8]IoapicInfo,
    nr_msi_descs: u32,
    total_ipis_sent: u64,
    total_nmis: u64,
    total_eois: u64,
    interrupt_remapping_enabled: bool,
    ir_config: IntrRemapConfig,
    initialized: bool,

    pub fn init() ApicDetailManager {
        return .{
            .local_apic_base = 0xFEE00000,
            .local_apic_id = 0,
            .x2apic_enabled = false,
            .nr_ioapics = 0,
            .ioapics = undefined,
            .nr_msi_descs = 0,
            .total_ipis_sent = 0,
            .total_nmis = 0,
            .total_eois = 0,
            .interrupt_remapping_enabled = false,
            .ir_config = std.mem.zeroes(IntrRemapConfig),
            .initialized = true,
        };
    }
};
