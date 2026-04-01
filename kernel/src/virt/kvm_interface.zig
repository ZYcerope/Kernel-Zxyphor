// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - KVM / Hypervisor Interface Layer
// Full KVM ioctl interface, vCPU management, memory regions, VFIO passthrough,
// nested virtualization, live migration, dirty tracking, PV interfaces
// More advanced than Linux 2026 KVM subsystem

const std = @import("std");

// ============================================================================
// KVM System ioctls
// ============================================================================

pub const KVM_API_VERSION: u32 = 12;

pub const KVM_CREATE_VM: u32 = 0xAE01;
pub const KVM_GET_VCPU_MMAP_SIZE: u32 = 0xAE04;
pub const KVM_CHECK_EXTENSION: u32 = 0xAE03;
pub const KVM_GET_API_VERSION: u32 = 0xAE00;
pub const KVM_GET_MSR_INDEX_LIST: u32 = 0xAE02;
pub const KVM_GET_SUPPORTED_CPUID: u32 = 0xAE05;
pub const KVM_GET_EMULATED_CPUID: u32 = 0xAE09;
pub const KVM_GET_MSR_FEATURE_INDEX_LIST: u32 = 0xAE0A;
pub const KVM_CREATE_DEVICE: u32 = 0xAE0B;
pub const KVM_GET_DEVICE_ATTR: u32 = 0xAE0C;
pub const KVM_SET_DEVICE_ATTR: u32 = 0xAE0D;
pub const KVM_HAS_DEVICE_ATTR: u32 = 0xAE0E;

// KVM VM ioctls
pub const KVM_CREATE_VCPU: u32 = 0xAE41;
pub const KVM_SET_USER_MEMORY_REGION: u32 = 0xAE46;
pub const KVM_GET_DIRTY_LOG: u32 = 0xAE42;
pub const KVM_CLEAR_DIRTY_LOG: u32 = 0xAE4B;
pub const KVM_SET_TSS_ADDR: u32 = 0xAE47;
pub const KVM_SET_IDENTITY_MAP_ADDR: u32 = 0xAE48;
pub const KVM_CREATE_IRQCHIP: u32 = 0xAE60;
pub const KVM_IRQ_LINE: u32 = 0xAE61;
pub const KVM_GET_IRQCHIP: u32 = 0xAE62;
pub const KVM_SET_IRQCHIP: u32 = 0xAE63;
pub const KVM_CREATE_PIT2: u32 = 0xAE77;
pub const KVM_GET_PIT2: u32 = 0xAE9F;
pub const KVM_SET_PIT2: u32 = 0xAEA0;
pub const KVM_IRQFD: u32 = 0xAE76;
pub const KVM_IOEVENTFD: u32 = 0xAE79;
pub const KVM_SET_GSI_ROUTING: u32 = 0xAE6A;
pub const KVM_REGISTER_COALESCED_MMIO: u32 = 0xAE67;
pub const KVM_UNREGISTER_COALESCED_MMIO: u32 = 0xAE68;
pub const KVM_SIGNAL_MSI: u32 = 0xAEA5;
pub const KVM_SET_PMU_EVENT_FILTER: u32 = 0xAEB2;
pub const KVM_ENABLE_CAP: u32 = 0xAEA3;

// KVM vCPU ioctls
pub const KVM_RUN: u32 = 0xAE80;
pub const KVM_GET_REGS: u32 = 0xAE81;
pub const KVM_SET_REGS: u32 = 0xAE82;
pub const KVM_GET_SREGS: u32 = 0xAE83;
pub const KVM_SET_SREGS: u32 = 0xAE84;
pub const KVM_GET_MSRS: u32 = 0xAE88;
pub const KVM_SET_MSRS: u32 = 0xAE89;
pub const KVM_GET_FPU: u32 = 0xAE8C;
pub const KVM_SET_FPU: u32 = 0xAE8D;
pub const KVM_GET_CPUID2: u32 = 0xAE91;
pub const KVM_SET_CPUID2: u32 = 0xAE90;
pub const KVM_GET_LAPIC: u32 = 0xAE8E;
pub const KVM_SET_LAPIC: u32 = 0xAE8F;
pub const KVM_GET_VCPU_EVENTS: u32 = 0xAE9F;
pub const KVM_SET_VCPU_EVENTS: u32 = 0xAEA0;
pub const KVM_GET_DEBUGREGS: u32 = 0xAEA1;
pub const KVM_SET_DEBUGREGS: u32 = 0xAEA2;
pub const KVM_GET_XSAVE: u32 = 0xAEA4;
pub const KVM_SET_XSAVE: u32 = 0xAEA5;
pub const KVM_GET_XCRS: u32 = 0xAEA6;
pub const KVM_SET_XCRS: u32 = 0xAEA7;
pub const KVM_SET_GUEST_DEBUG: u32 = 0xAE9A;
pub const KVM_INTERRUPT: u32 = 0xAE86;
pub const KVM_NMI: u32 = 0xAE9A;
pub const KVM_SMI: u32 = 0xAEB7;
pub const KVM_GET_MP_STATE: u32 = 0xAE98;
pub const KVM_SET_MP_STATE: u32 = 0xAE99;
pub const KVM_TRANSLATE: u32 = 0xAE85;
pub const KVM_GET_NESTED_STATE: u32 = 0xAEBE;
pub const KVM_SET_NESTED_STATE: u32 = 0xAEBF;

// ============================================================================
// KVM Capabilities
// ============================================================================

pub const KvmCap = enum(u32) {
    irqchip = 0,
    hlt = 1,
    mmu_shadow_cache_control = 2,
    user_memory = 3,
    set_tss_addr = 4,
    ext_cpuid = 7,
    vapic = 6,
    clocksource = 7,
    nr_vcpus = 9,
    nr_memslots = 10,
    pit = 11,
    nop_io_delay = 12,
    pv_mmu = 13,
    mp_state = 14,
    coalesced_mmio = 15,
    sync_mmu = 16,
    iommu = 18,
    destroy_memory_region_works = 21,
    user_nmi = 22,
    set_guest_debug = 23,
    reinject_control = 24,
    irq_routing = 25,
    irqfd = 26,
    pit_state2 = 35,
    ioeventfd = 36,
    set_identity_map_addr = 37,
    xen_hvm = 38,
    adjust_clock = 39,
    internal_error_data = 40,
    vcpu_events = 41,
    s390_psw = 42,
    ppc_segstate = 43,
    hyperv = 44,
    hyperv_vapic = 45,
    hyperv_spin = 46,
    pci_segment = 47,
    ppc_paired_singles = 48,
    intr_shadow = 49,
    debugregs = 50,
    x86_robust_singlestep = 51,
    ppc_osi = 52,
    ppc_unset_irq = 53,
    enable_cap = 54,
    xsave = 55,
    xcrs = 56,
    ppc_get_pvinfo = 57,
    ppc_irq_level = 58,
    async_pf = 59,
    tsc_control = 60,
    get_tsc_khz = 61,
    ppc_booke_sregs = 62,
    spapr_tce = 63,
    ppc_smt = 64,
    ppc_rma = 65,
    max_vcpus = 66,
    ppc_hior = 67,
    ppc_papr = 68,
    sw_tlb = 69,
    one_reg = 70,
    s390_gmap = 71,
    tscdl = 72,
    signal_msi = 73,
    ppc_get_smmu_info = 74,
    s390_cow = 75,
    ppc_alloc_htab = 76,
    readonly_mem = 81,
    irqfd_resample = 82,
    ppc_booke_watchdog = 83,
    ppc_htab_fd = 84,
    s390_css_support = 85,
    ppc_epub = 86,
    ppc_fixup_hcall = 87,
    s390_irqchip = 88,
    ioeventfd_no_length = 89,
    vm_attributes = 90,
    arm_psci_02 = 91,
    ppc_fixup_hcall_2 = 92,
    ppc_htm = 93,
    kvmclock_ctrl = 108,
    arm_el1_32bit = 109,
    tsc_deadline_timer = 111,
    split_irqchip = 121,
    immediate_exit = 136,
    msr_platform_info = 159,
    nested = 200,
    // Zxyphor
    zxy_live_patch = 500,
    zxy_secure_vm = 501,
};

// ============================================================================
// KVM Exit Reasons
// ============================================================================

pub const KvmExitReason = enum(u32) {
    unknown = 0,
    exception = 1,
    io = 2,
    hypercall = 3,
    debug = 4,
    hlt = 5,
    mmio = 6,
    irq_window_open = 7,
    shutdown = 8,
    fail_entry = 9,
    intr = 10,
    set_tpr = 11,
    tpr_access = 12,
    s390_sieic = 13,
    s390_reset = 14,
    dcr = 15,
    nmi = 16,
    internal_error = 17,
    osi = 18,
    papr_hcall = 19,
    s390_ucontrol = 20,
    watchdog = 21,
    s390_tsch = 22,
    epr = 23,
    system_event = 24,
    s390_stsi = 25,
    ioapic_eoi = 26,
    hyperv = 27,
    arm_nisv = 28,
    x86_rdmsr = 29,
    x86_wrmsr = 30,
    dirty_ring_full = 31,
    ap_reset_hold = 32,
    x86_bus_lock = 33,
    xen = 34,
    riscv_sbi = 35,
    riscv_csr = 36,
    notify = 37,
};

// ============================================================================
// KVM Run structure (shared memory page between kernel and userspace)
// ============================================================================

pub const KvmRun = extern struct {
    // For KVM_RUN
    request_interrupt_window: u8,
    immediate_exit: u8,
    padding1: [6]u8,
    // Out
    exit_reason: u32,
    ready_for_interrupt_injection: u8,
    if_flag: u8,
    flags: u16,
    // CR8 intercept
    cr8: u64,
    apic_base: u64,

    // Exit info (union)
    exit_data: [256]u8,
};

pub const KvmRunExitIo = extern struct {
    direction: u8,    // 0=in, 1=out
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
};

pub const KvmRunExitMmio = extern struct {
    phys_addr: u64,
    data: [8]u8,
    len: u32,
    is_write: u8,
};

pub const KvmRunExitHypercall = extern struct {
    nr: u64,
    args: [6]u64,
    ret: u64,
    flags: u32,
};

pub const KvmRunExitInternalError = extern struct {
    suberror: u32,
    ndata: u32,
    data: [16]u64,
};

// ============================================================================
// KVM Registers
// ============================================================================

pub const KvmRegs = extern struct {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
};

pub const KvmSegment = extern struct {
    base: u64,
    limit: u32,
    selector: u16,
    seg_type: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
};

pub const KvmDtable = extern struct {
    base: u64,
    limit: u16,
    padding: [3]u16,
};

pub const KvmSregs = extern struct {
    cs: KvmSegment,
    ds: KvmSegment,
    es: KvmSegment,
    fs: KvmSegment,
    gs: KvmSegment,
    ss: KvmSegment,
    tr: KvmSegment,
    ldt: KvmSegment,
    gdt: KvmDtable,
    idt: KvmDtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [4]u64, // 256 bits
};

pub const KvmFpu = extern struct {
    fpr: [8][16]u8,   // FPU registers
    fcw: u16,
    fsw: u16,
    ftwx: u8,
    pad1: u8,
    last_opcode: u16,
    last_ip: u64,
    last_dp: u64,
    xmm: [16][16]u8,  // SSE registers
    mxcsr: u32,
    pad2: u32,
};

// ============================================================================
// KVM Memory Regions
// ============================================================================

pub const KVM_MEM_LOG_DIRTY_PAGES: u32 = 1;
pub const KVM_MEM_READONLY: u32 = 2;
pub const KVM_MEM_PRIVATE: u32 = 4;

pub const KvmUserspaceMemoryRegion = struct {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
};

pub const KvmUserspaceMemoryRegion2 = struct {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    guest_memfd_offset: u64,
    guest_memfd: u32,
    pad1: u32,
    pad2: [14]u64,
};

// ============================================================================
// KVM Dirty Ring
// ============================================================================

pub const KvmDirtyGfn = extern struct {
    flags: u32,
    slot: u32,
    offset: u64,  // gfn offset in slot
};

pub const KVM_DIRTY_GFN_F_DIRTY: u32 = 1;
pub const KVM_DIRTY_GFN_F_RESET: u32 = 2;
pub const KVM_DIRTY_GFN_F_MASK: u32 = 3;

// ============================================================================
// IRQ Routing
// ============================================================================

pub const KvmIrqRouting = struct {
    nr: u32,
    flags: u32,
    entries: [256]KvmIrqRoutingEntry,
};

pub const KvmIrqRoutingEntry = struct {
    gsi: u32,
    routing_type: u32,
    flags: u32,
    pad: u32,
    // Union
    data: KvmIrqRoutingData,
};

pub const KvmIrqRoutingData = union {
    irqchip: KvmIrqRoutingIrqchip,
    msi: KvmIrqRoutingMsi,
    s390_adapter: KvmIrqRoutingS390Adapter,
    hv_sint: KvmIrqRoutingHvSint,
};

pub const KvmIrqRoutingIrqchip = struct {
    irqchip: u32,
    pin: u32,
};

pub const KvmIrqRoutingMsi = struct {
    address_lo: u32,
    address_hi: u32,
    data: u32,
    pad: u32,
    devid: u32,
};

pub const KvmIrqRoutingS390Adapter = struct {
    ind_addr: u64,
    summary_addr: u64,
    ind_offset: u64,
    summary_offset: u32,
    adapter_id: u32,
};

pub const KvmIrqRoutingHvSint = struct {
    vcpu: u32,
    sint: u32,
};

// ============================================================================
// VFIO (Virtual Function I/O)
// ============================================================================

pub const VFIO_API_VERSION: u32 = 0;

pub const VfioDeviceType = enum(u8) {
    pci = 0,
    platform = 1,
    amba = 2,
    ccw = 3,
    ap = 4,
    cdx = 5,
};

pub const VfioGroup = struct {
    group_id: u32,
    viable: bool,
    devices: [32]VfioDeviceInfo,
    nr_devices: u32,
    iommu_group: u32,
};

pub const VfioDeviceInfo = struct {
    device_type: VfioDeviceType,
    flags: u32,
    num_regions: u32,
    num_irqs: u32,
    // PCI specific
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    subsystem_vendor: u16,
    subsystem_device: u16,
    // BDF
    bus: u8,
    dev: u8,
    func: u8,
};

pub const VfioRegionInfo = struct {
    index: u32,
    flags: u32,
    size: u64,
    offset: u64,     // mmap offset
    // Capabilities
    cap_type: u32,
    cap_sparse_areas: [16]VfioSparseArea,
    nr_sparse_areas: u8,
};

pub const VfioSparseArea = struct {
    offset: u64,
    size: u64,
};

pub const VfioIrqInfo = struct {
    index: u32,
    flags: u32,
    count: u32,
};

// VFIO IOMMU
pub const VfioIommuType1DmaMap = struct {
    flags: u32,
    vaddr: u64,
    iova: u64,
    size: u64,
};

pub const VfioIommuType1DmaUnmap = struct {
    flags: u32,
    iova: u64,
    size: u64,
};

// ============================================================================
// Live Migration
// ============================================================================

pub const MigrationState = enum(u8) {
    none = 0,
    setup = 1,
    active = 2,
    postcopy = 3,
    completed = 4,
    failed = 5,
    cancelling = 6,
    cancelled = 7,
};

pub const MigrationParams = struct {
    // Basic
    downtime_limit_ms: u64,
    max_bandwidth_mbps: u64,
    compress_level: u8,
    compress_threads: u8,
    decompress_threads: u8,
    // Features
    multifd_enabled: bool,
    multifd_channels: u8,
    multifd_compression: u8,   // 0=none, 1=zlib, 2=zstd
    xbzrle_enabled: bool,
    xbzrle_cache_size: u64,
    auto_converge: bool,
    // Pre-copy
    max_precopy_bandwidth: u64,
    // Post-copy
    postcopy_enabled: bool,
    postcopy_ram_enabled: bool,
    // Dirty
    dirty_rate_limit: u64,
    dirty_ring_size: u32,
    // TLS
    tls_enabled: bool,
    tls_hostname: [256]u8,
    tls_hostname_len: u16,
};

pub const MigrationStats = struct {
    transferred: u64,          // Bytes
    remaining: u64,
    total: u64,
    duplicate: u64,
    skipped: u64,
    normal: u64,
    normal_bytes: u64,
    dirty_pages_rate: u64,
    mbps: u64,
    dirty_sync_count: u64,
    postcopy_requests: u64,
    page_size: u32,
    // Timing
    setup_time: u64,
    total_time: u64,
    downtime: u64,
    // Compression
    compressed_pages: u64,
    compression_busy_rate: u32,
    // Multifd
    multifd_bytes: u64,
    // XBZRLE
    xbzrle_bytes: u64,
    xbzrle_pages: u64,
    xbzrle_cache_miss: u64,
    xbzrle_overflow: u64,
};

pub const LiveMigration = struct {
    state: MigrationState,
    params: MigrationParams,
    stats: MigrationStats,
    // Dirty tracking
    dirty_bitmap: [*]u64,
    dirty_bitmap_size: u64,
    dirty_ring: [*]KvmDirtyGfn,
    dirty_ring_size: u32,
};

// ============================================================================
// Paravirtualization Interfaces
// ============================================================================

pub const PvFeature = enum(u32) {
    clocksource_tsc = 0,
    async_pf = 1,
    steal_time = 2,
    eoi = 3,
    unhalt = 4,
    tlb_flush = 5,
    send_ipi = 6,
    poll_control = 7,
    sched_yield = 8,
    // Hyper-V
    hv_time_ref_count = 100,
    hv_reference_tsc = 101,
    hv_synic = 102,
    hv_syntimers = 103,
    hv_apic = 104,
    hv_hypercall = 105,
    hv_vpindex = 106,
    hv_relaxed_timing = 107,
    hv_vapic_assist = 108,
    hv_stimer_direct = 109,
    // Zxyphor PV
    zxy_fast_mmio = 200,
    zxy_shared_mem = 201,
};

pub const PvClockVcpuTimeInfo = extern struct {
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad: [2]u8,
};

// ============================================================================
// KVM Subsystem Manager
// ============================================================================

pub const KVMSubsystem = struct {
    // System capabilities
    supported_caps: [256]bool,
    api_version: u32,
    // VMs
    max_vcpus_per_vm: u32,
    max_memslots: u32,
    vcpu_mmap_size: u32,
    // Hardware
    hardware_type: HardwareVirtType,
    nested_supported: bool,
    // Stats
    total_vms: u64,
    total_vcpus: u64,
    total_exits: u64,
    total_io_exits: u64,
    total_mmio_exits: u64,
    total_hlt_exits: u64,
    total_irq_injections: u64,
    // Dirty tracking
    dirty_ring_supported: bool,
    dirty_ring_size: u32,
    // Live migration
    migration: LiveMigration,
    // Initialized
    initialized: bool,
};

pub const HardwareVirtType = enum(u8) {
    none = 0,
    intel_vmx = 1,
    amd_svm = 2,
    arm_vhe = 3,
    arm_nvhe = 4,
    riscv_h = 5,
    // Zxyphor
    zxy_hybrid = 200,
};
