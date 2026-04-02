// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - x86_64 Interrupt Subsystem Complete
// IDT gate descriptors, exception frames, IRQ chip abstraction,
// APIC timer, IPI, NMI, MCE, interrupt remapping, IRQ domain, MSI

const std = @import("std");

// ============================================================================
// IDT Gate Types
// ============================================================================

pub const GateType = enum(u4) {
    Interrupt64 = 0xE,
    Trap64 = 0xF,
    Task32 = 0x5,
};

pub const IdtGateDescriptor = packed struct(u128) {
    offset_low: u16,
    selector: u16,
    ist: u3,
    _zero1: u5 = 0,
    gate_type: u4,
    _zero2: u1 = 0,
    dpl: u2,
    present: u1,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32 = 0,
};

pub const IDTR = packed struct(u80) {
    limit: u16,
    base: u64,
};

// ============================================================================
// Exception Vectors
// ============================================================================

pub const ExceptionVector = enum(u8) {
    DivideError = 0,
    Debug = 1,
    Nmi = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRange = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTss = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtection = 13,
    PageFault = 14,
    Reserved15 = 15,
    X87FloatingPoint = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SimdFloatingPoint = 19,
    VirtualizationException = 20,
    ControlProtection = 21,
    Reserved22 = 22,
    Reserved23 = 23,
    Reserved24 = 24,
    Reserved25 = 25,
    Reserved26 = 26,
    Reserved27 = 27,
    HypervisorInjection = 28,
    VmmCommunication = 29,
    SecurityException = 30,
    Reserved31 = 31,
};

// ============================================================================
// Interrupt/Exception Stack Frame
// ============================================================================

pub const InterruptFrame = extern struct {
    // Saved by handler
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    // Pushed by CPU (or handler for error code)
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// Page fault error code bits
pub const PageFaultErrorCode = packed struct(u64) {
    present: bool = false,
    write: bool = false,
    user: bool = false,
    reserved_write: bool = false,
    instruction_fetch: bool = false,
    protection_key: bool = false,
    shadow_stack: bool = false,
    _reserved1: u8 = 0,
    sgx: bool = false,
    _reserved2: u48 = 0,
};

// ============================================================================
// IRQ Chip Abstraction
// ============================================================================

pub const IrqChipFlags = packed struct(u32) {
    set_type_on_activate: bool = false,
    skip_set_wake: bool = false,
    affinity_pre_startup: bool = false,
    immutable: bool = false,
    pipeline_safe: bool = false,
    _reserved: u27 = 0,
};

pub const IrqChipType = enum(u8) {
    None = 0,
    Pic8259 = 1,
    IoApic = 2,
    LapicTimer = 3,
    MsiX = 4,
    GicV3 = 5,
    GicV4 = 6,
    Dmar = 7,
    HyperV = 8,
};

pub const IrqChip = struct {
    name: [32]u8,
    chip_type: IrqChipType,
    flags: IrqChipFlags,

    // Function pointers (callbacks)
    irq_startup: ?*const fn (data: *IrqData) callconv(.C) u32,
    irq_shutdown: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_enable: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_disable: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_ack: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_mask: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_unmask: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_eoi: ?*const fn (data: *IrqData) callconv(.C) void,
    irq_set_affinity: ?*const fn (data: *IrqData, dest: *const CpuMask, force: bool) callconv(.C) i32,
    irq_retrigger: ?*const fn (data: *IrqData) callconv(.C) i32,
    irq_set_type: ?*const fn (data: *IrqData, flow_type: u32) callconv(.C) i32,
    irq_set_wake: ?*const fn (data: *IrqData, on: bool) callconv(.C) i32,
    irq_compose_msi_msg: ?*const fn (data: *IrqData, msg: *MsiMsg) callconv(.C) void,
};

pub const CpuMask = struct {
    bits: [4]u64, // 256 CPUs
};

pub const IrqData = struct {
    irq: u32,
    hwirq: u64,
    chip: ?*IrqChip,
    domain: ?*IrqDomain,
    parent_data: ?*IrqData,
    affinity: CpuMask,
    effective_affinity: CpuMask,
    common_flags: u32,
    state_use_accessors: u32,
};

// ============================================================================
// IRQ Domain
// ============================================================================

pub const IrqDomainOps = struct {
    match: ?*const fn (domain: *IrqDomain) callconv(.C) i32,
    map: ?*const fn (domain: *IrqDomain, virq: u32, hwirq: u64) callconv(.C) i32,
    unmap: ?*const fn (domain: *IrqDomain, virq: u32) callconv(.C) void,
    translate: ?*const fn (domain: *IrqDomain) callconv(.C) i32,
    alloc: ?*const fn (domain: *IrqDomain, virq: u32, nr_irqs: u32) callconv(.C) i32,
    free: ?*const fn (domain: *IrqDomain, virq: u32, nr_irqs: u32) callconv(.C) void,
    activate: ?*const fn (domain: *IrqDomain, irq_data: *IrqData) callconv(.C) i32,
    deactivate: ?*const fn (domain: *IrqDomain, irq_data: *IrqData) callconv(.C) void,
};

pub const IrqDomainFlags = packed struct(u32) {
    hierarchy: bool = false,
    msi: bool = false,
    msi_remap: bool = false,
    no_map: bool = false,
    msi_parent: bool = false,
    msi_device_domain: bool = false,
    noncore: bool = false,
    _reserved: u25 = 0,
};

pub const IrqDomain = struct {
    name: [64]u8,
    ops: IrqDomainOps,
    parent: ?*IrqDomain,
    flags: IrqDomainFlags,
    hwirq_max: u64,
    revmap_size: u32,
    host_data: ?*anyopaque,
};

// ============================================================================
// MSI (Message Signaled Interrupts)
// ============================================================================

pub const MsiMsg = extern struct {
    address_lo: u32,
    address_hi: u32,
    data: u32,
};

pub const MsiDesc = struct {
    irq: u32,
    nvec_used: u32,
    msi_index: u32,
    pci_devid: u32,
    msg: MsiMsg,
    masked: bool,
    is_msix: bool,
    multi_cap: u8,
    affinity: ?*CpuMask,
    sysfs_attrs: ?*anyopaque,
};

pub const MsiDomainInfo = struct {
    flags: u32,
    ops: MsiDomainOps,
    chip: ?*IrqChip,
    chip_data: ?*anyopaque,
    handler: ?*const fn (irq: u32, desc: ?*anyopaque) callconv(.C) void,
    handler_data: ?*anyopaque,
    handler_name: ?[*:0]const u8,
};

pub const MsiDomainOps = struct {
    get_hwirq: ?*const fn (info: *MsiDomainInfo, desc: *MsiDesc) callconv(.C) u64,
    msi_init: ?*const fn (domain: *IrqDomain, info: *MsiDomainInfo, virq: u32, hwirq: u64, desc: *MsiDesc) callconv(.C) i32,
    msi_free: ?*const fn (domain: *IrqDomain, info: *MsiDomainInfo, virq: u32) callconv(.C) void,
    msi_prepare: ?*const fn (domain: *IrqDomain, dev: ?*anyopaque, nvec: i32) callconv(.C) i32,
    set_desc: ?*const fn (msi_data: ?*anyopaque, desc: *MsiDesc) callconv(.C) void,
};

// ============================================================================
// IPI (Inter-Processor Interrupts)
// ============================================================================

pub const IpiType = enum(u8) {
    Reschedule = 0,
    CallFunction = 1,
    CallFunctionSingle = 2,
    TlbShootdown = 3,
    ThermalApic = 4,
    ThresholdApic = 5,
    DeferredError = 6,
    IRQWork = 7,
    Reboot = 8,
    NmiAll = 9,
};

pub const IPI_VECTOR_BASE: u8 = 0xF0;
pub const RESCHEDULE_VECTOR: u8 = 0xFD;
pub const CALL_FUNCTION_VECTOR: u8 = 0xFB;
pub const CALL_FUNCTION_SINGLE_VECTOR: u8 = 0xFA;
pub const TLB_FLUSH_VECTOR: u8 = 0xF9;
pub const THERMAL_APIC_VECTOR: u8 = 0xF8;
pub const THRESHOLD_APIC_VECTOR: u8 = 0xF7;
pub const REBOOT_VECTOR: u8 = 0xF6;
pub const ERROR_APIC_VECTOR: u8 = 0xFE;
pub const SPURIOUS_APIC_VECTOR: u8 = 0xFF;
pub const LOCAL_TIMER_VECTOR: u8 = 0xEC;
pub const POSTED_INTR_VECTOR: u8 = 0xF2;
pub const POSTED_INTR_WAKEUP_VECTOR: u8 = 0xF1;
pub const POSTED_INTR_NESTED_VECTOR: u8 = 0xF0;

// ============================================================================
// APIC Timer
// ============================================================================

pub const ApicTimerMode = enum(u8) {
    OneShot = 0,
    Periodic = 1,
    TscDeadline = 2,
};

pub const ApicTimerState = struct {
    mode: ApicTimerMode,
    initial_count: u32,
    current_count: u32,
    divide_config: u8,
    tsc_deadline: u64,
    calibrated_freq_hz: u64,
    ticks_per_us: u32,
    next_deadline_ns: u64,
};

// ============================================================================
// NMI (Non-Maskable Interrupt)
// ============================================================================

pub const NmiReason = enum(u8) {
    Unknown = 0,
    MemoryParity = 1,
    IoCheck = 2,
    Watchdog = 3,
    BackToBack = 4,
    External = 5,
    Kgdb = 6,
    Software = 7,
};

pub const NmiStats = struct {
    total_nmi_count: u64,
    unknown_nmi_count: u64,
    watchdog_nmi_count: u64,
    io_check_nmi_count: u64,
    external_nmi_count: u64,
    per_cpu_nmi_count: [256]u64,
};

// ============================================================================
// MCE (Machine Check Exception)
// ============================================================================

pub const MceBankStatus = packed struct(u64) {
    mca_error_code: u16,
    model_specific_error: u16,
    other_info: u5,
    corrected_error_count: u12,
    threshold_based_status: u2,
    ar: bool,
    s: bool,
    pcc: bool,
    addrv: bool,
    miscv: bool,
    en: bool,
    uc: bool,
    overflow: bool,
    val: bool,
};

pub const MceRecord = struct {
    status: u64,
    misc: u64,
    addr: u64,
    mcgstatus: u64,
    ip: u64,
    tsc: u64,
    time: u64,
    cpuvendor: u8,
    inject_flags: u8,
    severity: MceSeverity,
    pad: u8,
    cpuid: u32,
    cs: u8,
    bank: u8,
    cpu: u16,
    finished: bool,
    kflags: u32,
};

pub const MceSeverity = enum(u8) {
    NoConcern = 0,
    Keep = 1,
    SomePages = 2,
    AR = 3,
    UC = 4,
    Panic = 5,
};

pub const MCE_MAX_BANKS: u32 = 64;

pub const MceBank = struct {
    ctl: u64,
    status: u64,
    addr: u64,
    misc: u64,
    synd: u64,
    ipid: u64,
    init: bool,
    threshold_set: bool,
};

// ============================================================================
// Interrupt Remapping (IR)
// ============================================================================

pub const IrRemapType = enum(u8) {
    IntelVtd = 0,
    AmdIommu = 1,
    HyperV = 2,
};

pub const IntelIrte = extern struct {
    low: u64,
    high: u64,
};

pub const IntelIrteFields = packed struct(u128) {
    present: bool,
    fpd: bool,
    destination_mode: bool,
    redirection_hint: bool,
    trigger_mode: bool,
    delivery_mode: u3,
    avail: u4,
    _reserved1: u3,
    im: bool,
    vector: u8,
    _reserved2: u8,
    destination_id: u32,
    source_id: u16,
    source_id_qualifier: u2,
    source_validation_type: u2,
    _reserved3: u12,
    _reserved4: u32,
};

pub const AmdIrte = extern struct {
    data: [4]u32,
};

// ============================================================================
// Per-CPU Interrupt State
// ============================================================================

pub const PerCpuIrqState = struct {
    cpu_id: u32,
    irq_count: u64,
    nmi_count: u64,
    softirq_pending: u32,
    preempt_count: u32,
    apic_timer: ApicTimerState,
    in_interrupt: bool,
    in_nmi: bool,
    in_mce: bool,
    irq_stack_ptr: u64,
    hardirq_stack_ptr: u64,
    softirq_stack_ptr: u64,
    irq_stack_size: u64,
};

// ============================================================================
// Softirq
// ============================================================================

pub const SoftirqAction = enum(u32) {
    HI = 0,
    TIMER = 1,
    NET_TX = 2,
    NET_RX = 3,
    BLOCK = 4,
    IRQ_POLL = 5,
    TASKLET = 6,
    SCHED = 7,
    HRTIMER = 8,
    RCU = 9,
    NR_SOFTIRQS = 10,
};

pub const TaskletHead = struct {
    head: ?*TaskletStruct,
    tail: ?*?*TaskletStruct,
};

pub const TaskletStruct = struct {
    next: ?*TaskletStruct,
    state: u64,
    count: i32,
    use_callback: bool,
    func: ?*const fn (data: u64) callconv(.C) void,
    data: u64,
};

// ============================================================================
// Workqueue IRQ
// ============================================================================

pub const IrqWorkFlags = packed struct(u32) {
    pending: bool = false,
    busy: bool = false,
    lazy: bool = false,
    hard: bool = false,
    _reserved: u28 = 0,
};

pub const IrqWork = struct {
    node: ListHead,
    func: ?*const fn (work: *IrqWork) callconv(.C) void,
    irqflags: u64,
    flags: IrqWorkFlags,
};

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,
};

// ============================================================================
// Vector Allocation
// ============================================================================

pub const FIRST_EXTERNAL_VECTOR: u8 = 0x20;
pub const FIRST_SYSTEM_VECTOR: u8 = 0xEC;
pub const NR_VECTORS: u16 = 256;
pub const NR_EXTERNAL_VECTORS: u16 = NR_VECTORS - @as(u16, FIRST_EXTERNAL_VECTOR);
pub const IRQ_MATRIX_BITS: u16 = NR_VECTORS;

pub const VectorIrqState = enum(u8) {
    Free = 0,
    Used = 1,
    Managed = 2,
    Reserved = 3,
    SystemReserved = 4,
};

pub const IrqMatrix = struct {
    matrix_bits: u16,
    alloc_start: u16,
    alloc_end: u16,
    alloc_size: u16,
    global_available: u32,
    global_reserved: u32,
    total_allocated: u32,
    online_maps: u32,
};

// ============================================================================
// Interrupt Subsystem Manager
// ============================================================================

pub const InterruptSubsystemManager = struct {
    idt_loaded: bool,
    apic_timer_configured: bool,
    ioapic_count: u8,
    msi_enabled: bool,
    ir_type: IrqRemapType,
    ir_enabled: bool,
    mce_banks: u8,
    nmi_watchdog_enabled: bool,
    total_irq_domains: u32,
    total_allocated_vectors: u32,
    total_msi_irqs: u32,
    softirq_counts: [10]u64,
    per_cpu_states: [256]PerCpuIrqState,
    initialized: bool,

    const IrqRemapType = IrRemapType;

    pub fn init() InterruptSubsystemManager {
        return .{
            .idt_loaded = false,
            .apic_timer_configured = false,
            .ioapic_count = 0,
            .msi_enabled = false,
            .ir_type = .IntelVtd,
            .ir_enabled = false,
            .mce_banks = 0,
            .nmi_watchdog_enabled = false,
            .total_irq_domains = 0,
            .total_allocated_vectors = 0,
            .total_msi_irqs = 0,
            .softirq_counts = [_]u64{0} ** 10,
            .per_cpu_states = undefined,
            .initialized = true,
        };
    }
};
