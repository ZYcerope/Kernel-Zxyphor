// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - IOMMU/SMMU: Intel VT-d, AMD-Vi, ARM SMMU v3, DMA API
// IOMMU specification 3.4+ with Zxyphor security extensions

const std = @import("std");

// ============================================================================
// IOMMU Domain Types
// ============================================================================

pub const IommuDomainType = enum(u8) {
    blocked = 0,        // Block all DMA
    identity = 1,       // 1:1 mapping (passthrough)
    unmanaged = 2,      // Manually managed
    dma = 3,            // DMA API managed
    dma_fq = 4,         // DMA with flush queue
    svA = 5,            // Shared Virtual Addressing
    platform = 6,       // Platform specific
    // Zxyphor
    zxy_isolated = 200, // Per-device isolation
    zxy_nested = 201,   // Nested translation (VM)
};

pub const IommuCap = packed struct(u64) {
    cache_coherency: bool = false,
    intr_remap: bool = false,
    noexec: bool = false,
    pre_boot_protection: bool = false,
    enforce_cache_coherency: bool = false,
    deferred_flush: bool = false,
    dirty_tracking: bool = false,
    // Zxyphor
    zxy_device_tagging: bool = false,
    zxy_nested: bool = false,
    _reserved: u55 = 0,
};

pub const IommuProt = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    cache: bool = false,
    noexec: bool = false,
    mmio: bool = false,
    _reserved: u27 = 0,
};

// ============================================================================
// IOMMU Domain
// ============================================================================

pub const IommuDomain = struct {
    domain_type: IommuDomainType,
    ops: ?*const IommuDomainOps,
    // Page table
    pgd: u64,              // Physical address of page table root
    pgd_level: u8,         // Page table levels (3/4/5)
    // Address width
    iova_bits: u8,         // Max IOVA bits (48/57)
    pa_bits: u8,           // Max physical address bits
    // Geometry
    geometry: IommuDomainGeometry,
    // IOMMU instance
    iommu: ?*IommuDevice,
    // Devices
    attached_devices: [64]?*IommuDeviceHandle,
    nr_devices: u32,
    // Flags
    dirty_ops: ?*const IommuDirtyOps,
    // ID
    id: u32,

    pub fn map_page(self: *IommuDomain, iova: u64, paddr: u64, size: u64, prot: IommuProt) i32 {
        if (self.ops) |ops| {
            if (ops.map_pages) |map_fn| {
                return map_fn(self, iova, paddr, size, 1, prot, null);
            }
        }
        return -95; // EOPNOTSUPP
    }

    pub fn unmap_page(self: *IommuDomain, iova: u64, size: u64) u64 {
        if (self.ops) |ops| {
            if (ops.unmap_pages) |unmap_fn| {
                return unmap_fn(self, iova, size, 1, null);
            }
        }
        return 0;
    }

    pub fn iova_to_phys(self: *IommuDomain, iova: u64) u64 {
        if (self.ops) |ops| {
            if (ops.iova_to_phys_fn) |fn_ptr| {
                return fn_ptr(self, iova);
            }
        }
        return 0;
    }
};

pub const IommuDomainGeometry = struct {
    aperture_start: u64,
    aperture_end: u64,
    force_aperture: bool,
};

pub const IommuDomainOps = struct {
    attach_dev: ?*const fn (*IommuDomain, ?*anyopaque) i32,
    set_dev_pasid: ?*const fn (*IommuDomain, ?*anyopaque, u32) i32,
    map_pages: ?*const fn (*IommuDomain, u64, u64, u64, u64, IommuProt, ?*u64) i32,
    unmap_pages: ?*const fn (*IommuDomain, u64, u64, u64, ?*anyopaque) u64,
    flush_iotlb_all: ?*const fn (*IommuDomain) void,
    iotlb_sync_map: ?*const fn (*IommuDomain, u64, u64) void,
    iotlb_sync: ?*const fn (*IommuDomain, ?*anyopaque) void,
    iova_to_phys_fn: ?*const fn (*IommuDomain, u64) u64,
    enforce_cache_coherency: ?*const fn (*IommuDomain) bool,
    enable_nesting: ?*const fn (*IommuDomain) i32,
    set_pgtable_quirks: ?*const fn (*IommuDomain, u64) i32,
    free: ?*const fn (*IommuDomain) void,
};

pub const IommuDirtyOps = struct {
    set_dirty_tracking: ?*const fn (*IommuDomain, bool) i32,
    read_and_clear_dirty: ?*const fn (*IommuDomain, u64, u64, u64, ?*anyopaque) i32,
};

// ============================================================================
// IOMMU Device
// ============================================================================

pub const IommuDevice = struct {
    ops: ?*const IommuOps,
    dev: ?*anyopaque,
    // Hardware info
    hw_type: IommuHwType,
    segment: u16,        // PCI segment
    // Capabilities
    cap: IommuCap,
    // Domains
    default_domain: ?*IommuDomain,
    // IOTLB
    iotlb_ops: ?*const IotlbOps,
    // Interrupt remapping
    ir_enabled: bool,
    // Stats
    map_count: u64,
    unmap_count: u64,
    fault_count: u64,
};

pub const IommuHwType = enum(u8) {
    intel_vtd = 0,
    amd_vi = 1,
    arm_smmu_v2 = 2,
    arm_smmu_v3 = 3,
    riscv_iommu = 4,
    virtio_iommu = 5,
    // Zxyphor software IOMMU
    zxy_swiotlb = 200,
};

pub const IommuOps = struct {
    capable: ?*const fn (*IommuDevice, IommuCap) bool,
    hw_info: ?*const fn (?*anyopaque) ?*anyopaque,
    domain_alloc: ?*const fn (IommuDomainType) ?*IommuDomain,
    domain_alloc_paging: ?*const fn (?*anyopaque) ?*IommuDomain,
    probe_device: ?*const fn (?*anyopaque) ?*anyopaque,
    release_device: ?*const fn (?*anyopaque) void,
    probe_finalize: ?*const fn (?*anyopaque) void,
    device_group: ?*const fn (?*anyopaque) ?*IommuGroup,
    get_resv_regions: ?*const fn (?*anyopaque, ?*anyopaque) void,
    of_xlate: ?*const fn (?*anyopaque, ?*anyopaque) i32,
    is_attach_deferred: ?*const fn (?*anyopaque) bool,
    dev_enable_feat: ?*const fn (?*anyopaque, u32) i32,
    dev_disable_feat: ?*const fn (?*anyopaque, u32) i32,
    page_response: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque) i32,
    def_domain_type: ?*const fn (?*anyopaque) IommuDomainType,
    remove_dev_pasid: ?*const fn (?*anyopaque, u32) void,
    pgsize_bitmap: u64,
    owner: ?*anyopaque,
    identity_domain: ?*IommuDomain,
    blocked_domain: ?*IommuDomain,
    default_domain: ?*IommuDomain,
};

pub const IotlbOps = struct {
    tlb_flush_all: ?*const fn (*IommuDevice) void,
    tlb_flush_walk: ?*const fn (*IommuDevice, u64, u64, u64) void,
    tlb_add_page: ?*const fn (*IommuDevice, u64, u64) void,
};

// ============================================================================
// IOMMU Group
// ============================================================================

pub const IommuGroup = struct {
    id: u32,
    name: [32]u8,
    devices: [32]?*anyopaque,
    nr_devices: u32,
    domain: ?*IommuDomain,
    default_domain: ?*IommuDomain,
    // Notifications
    notifier_count: u32,
    // Type  
    group_type: IommuGroupType,
};

pub const IommuGroupType = enum(u8) {
    dma = 0,
    identity = 1,
    pci_bridge = 2,
    isolated = 3,
};

pub const IommuDeviceHandle = struct {
    dev: ?*anyopaque,
    group: ?*IommuGroup,
    domain: ?*IommuDomain,
    pasid: u32,
    enabled: bool,
};

// ============================================================================
// Intel VT-d (DMA Remapping)
// ============================================================================

pub const VtdCapRegister = packed struct(u64) {
    nd: u3 = 0,          // Number of domains
    afl: bool = false,    // Advanced fault logging
    rwbf: bool = false,   // Required write-buffer flushing
    plmr: bool = false,   // Protected low memory region
    phmr: bool = false,   // Protected high memory region
    cm: bool = false,     // Caching mode
    sagaw: u5 = 0,       // Supported adjusted guest addr widths
    _reserved_13: u3 = 0,
    mgaw: u6 = 0,        // Max guest address width
    zlr: bool = false,    // Zero length read
    _reserved_23: u1 = 0,
    fro: u10 = 0,        // Fault recording register offset
    sllps: u4 = 0,       // Second level large page support
    _reserved_38: u1 = 0,
    psi: bool = false,    // Page selective invalidation
    nfr: u8 = 0,         // Number of fault recording regs
    mamv: u6 = 0,        // Max address mask value
    dwd: bool = false,    // DMA write draining
    drd: bool = false,    // DMA read draining
    fl1gp: bool = false,  // First level 1G page
    _reserved_57: u2 = 0,
    pi: bool = false,     // Posted interrupt
    fl5lp: bool = false,  // First level 5-level paging
    esirtps: bool = false,
    esrtps: bool = false,
};

pub const VtdEcapRegister = packed struct(u64) {
    c: bool = false,      // Page walk coherency
    qi: bool = false,     // Queued invalidation
    dt: bool = false,     // Device-TLB
    ir: bool = false,     // Interrupt remapping
    eim: bool = false,    // Extended interrupt mode
    _reserved_5: u1 = 0,
    pt: bool = false,     // Pass through
    sc: bool = false,     // Snoop control
    iro: u10 = 0,        // IOTLB register offset
    _reserved_18: u2 = 0,
    mhmv: u4 = 0,        // Max handle mask value
    ecs: bool = false,    // Extended context support
    mts: bool = false,    // Memory type support
    nest: bool = false,   // Nested translation
    dis: bool = false,    // Deferred invalidation
    prs: bool = false,    // Page request support
    ers: bool = false,    // Execute request support
    srs: bool = false,    // Supervisor request support
    _reserved_31: u1 = 0,
    nwfs: bool = false,   // No write flag support
    eafs: bool = false,   // Extended accessed flag
    pss: u5 = 0,         // PASID size supported
    pasid: bool = false,  // Process address space ID
    dit: bool = false,    // Device-TLB invalidation throttle
    pds: bool = false,    // Page drain support
    smts: bool = false,   // Scalable mode translation
    vcs: bool = false,    // Virtual command support
    slads: bool = false,  // Second level accessed/dirty
    slts: bool = false,   // Second level translation
    flts: bool = false,   // First level translation
    smpwcs: bool = false, // SM prog write comb support
    rps: bool = false,    // RID-PASID support
    adms: bool = false,   // Abort DMA mode
    rprivs: bool = false, // RID_PRIV support
    _reserved_52: u12 = 0,
};

pub const VtdRootEntry = extern struct {
    lo: u64,
    hi: u64,
};

pub const VtdContextEntry = extern struct {
    lo: u64,
    hi: u64,
};

pub const VtdScalableRootEntry = extern struct {
    lo: u64,
    hi: u64,
};

pub const VtdScalableContextEntry = extern struct {
    val: [4]u64,
};

pub const VtdPasidEntry = extern struct {
    val: [8]u64,
};

// VT-d IOTLB invalidation descriptor
pub const VtdInvDesc = extern struct {
    lo: u64,
    hi: u64,
};

pub const VtdInvDescType = enum(u4) {
    context_cache = 1,
    iotlb = 2,
    device_tlb = 3,
    iec = 4,          // Interrupt entry cache
    wait = 5,
    pasid_cache = 6,
};

// ============================================================================
// AMD-Vi (AMD I/O Virtualization)
// ============================================================================

pub const AmdViDeviceTableEntry = extern struct {
    data: [4]u64,
};

pub const AmdViIrteEntry = extern struct {
    data: [2]u64,
};

pub const AmdViCommandType = enum(u4) {
    completion_wait = 1,
    invalidate_devtab = 2,
    invalidate_iommu_pages = 3,
    invalidate_iotlb_pages = 4,
    invalidate_interrupt_table = 5,
    prefetch_iommu_pages = 6,
    complete_ppr = 7,
    invalidate_iommu_all = 8,
};

pub const AmdViCommand = extern struct {
    data: [2]u64,
};

pub const AmdViEventType = enum(u8) {
    illegal_dev_tab_entry = 1,
    io_page_fault = 2,
    dev_tab_hw_error = 3,
    page_tab_hw_error = 4,
    illegal_command_error = 5,
    command_hw_error = 6,
    iotlb_inv_timeout = 7,
    invalid_dev_request = 8,
    invalid_ppr_request = 9,
    event_counter_zero = 10,
};

pub const AmdViMmioRegisters = struct {
    // Base register offsets
    pub const DEV_TAB_BASE: u32 = 0x0000;
    pub const CMD_BUF_BASE: u32 = 0x0008;
    pub const EVT_LOG_BASE: u32 = 0x0010;
    pub const CONTROL: u32 = 0x0018;
    pub const EXCLUSION_BASE: u32 = 0x0020;
    pub const EXCLUSION_LIMIT: u32 = 0x0028;
    pub const EXT_FEATURE: u32 = 0x0030;
    pub const PPR_LOG_BASE: u32 = 0x0038;
    pub const HW_EVT_HI: u32 = 0x0040;
    pub const HW_EVT_LO: u32 = 0x0048;
    pub const HW_EVT_STATUS: u32 = 0x0050;
    pub const SMI_FILTER_0: u32 = 0x0060;
    pub const GA_LOG_BASE: u32 = 0x00E0;
    pub const GA_LOG_TAIL: u32 = 0x00E8;
    pub const PPR_LOG_AUTO: u32 = 0x00F0;
    pub const PPR_LOG_OVERFLOW_EARLY: u32 = 0x00F8;
    pub const PPR_LOG_B_BASE: u32 = 0x00F0;
    pub const EVT_LOG_B_BASE: u32 = 0x00F8;
    pub const CMD_BUF_HEAD: u32 = 0x2000;
    pub const CMD_BUF_TAIL: u32 = 0x2008;
    pub const EVT_LOG_HEAD: u32 = 0x2010;
    pub const EVT_LOG_TAIL: u32 = 0x2018;
    pub const STATUS: u32 = 0x2020;
    pub const PPR_LOG_HEAD: u32 = 0x2030;
    pub const PPR_LOG_TAIL: u32 = 0x2038;
    pub const GA_LOG_HEAD: u32 = 0x2040;
    pub const GA_LOG_TAIL_REG: u32 = 0x2048;
};

// ============================================================================
// ARM SMMU v3
// ============================================================================

pub const SmmuV3StreamTableEntry = extern struct {
    data: [8]u64,
};

pub const SmmuV3ContextDescriptor = extern struct {
    data: [8]u64,
};

pub const SmmuV3CmdType = enum(u8) {
    prefetch_config = 0x01,
    prefetch_addr = 0x02,
    cfgi_ste = 0x03,
    cfgi_ste_range = 0x04,
    cfgi_cd = 0x05,
    cfgi_cd_all = 0x06,
    tlbi_nh_asid = 0x11,
    tlbi_nh_va = 0x12,
    tlbi_el2_all = 0x20,
    tlbi_el2_asid = 0x21,
    tlbi_el2_va = 0x22,
    tlbi_nsnh_all = 0x30,
    tlbi_s2_iPA = 0x2A,
    tlbi_s12_vmall = 0x28,
    cmd_sync = 0x46,
    ats_pri = 0x50,
    ats_inv = 0x51,
    resume = 0x52,
    stall_term = 0x53,
};

pub const SmmuV3Command = extern struct {
    data: [2]u64,
};

pub const SmmuV3Event = extern struct {
    data: [4]u64,
};

pub const SmmuV3EventType = enum(u8) {
    f_uut = 0x01,
    c_bad_streamid = 0x02,
    f_ste_fetch = 0x03,
    c_bad_ste = 0x04,
    f_bad_aste = 0x05,
    f_stream_disabled = 0x06,
    f_trans_forbidden = 0x07,
    c_bad_substreamid = 0x08,
    f_cd_fetch = 0x09,
    c_bad_cd = 0x0A,
    f_walk_eabt = 0x0B,
    f_translation = 0x10,
    f_addr_size = 0x11,
    f_access = 0x12,
    f_permission = 0x13,
    f_tlb_conflict = 0x20,
    f_cfg_conflict = 0x21,
    e_page_request = 0x24,
    f_vms_fetch = 0x25,
};

pub const SmmuV3Registers = struct {
    pub const IDR0: u32 = 0x000;
    pub const IDR1: u32 = 0x004;
    pub const IDR2: u32 = 0x008;
    pub const IDR3: u32 = 0x00C;
    pub const IDR4: u32 = 0x010;
    pub const IDR5: u32 = 0x014;
    pub const IIDR: u32 = 0x018;
    pub const AIDR: u32 = 0x01C;
    pub const CR0: u32 = 0x020;
    pub const CR0ACK: u32 = 0x024;
    pub const CR1: u32 = 0x028;
    pub const CR2: u32 = 0x02C;
    pub const STATUSR: u32 = 0x040;
    pub const GBPA: u32 = 0x044;
    pub const AGBPA: u32 = 0x048;
    pub const IRQ_CTRL: u32 = 0x050;
    pub const IRQ_CTRLACK: u32 = 0x054;
    pub const GERROR: u32 = 0x060;
    pub const GERRORN: u32 = 0x064;
    pub const GERROR_IRQ_CFG0: u32 = 0x068;
    pub const STRTAB_BASE: u32 = 0x080;
    pub const STRTAB_BASE_CFG: u32 = 0x088;
    pub const CMDQ_BASE: u32 = 0x090;
    pub const CMDQ_PROD: u32 = 0x098;
    pub const CMDQ_CONS: u32 = 0x09C;
    pub const EVTQ_BASE: u32 = 0x0A0;
    pub const EVTQ_PROD: u32 = 0x0A8;
    pub const EVTQ_CONS: u32 = 0x0AC;
    pub const PRIQ_BASE: u32 = 0x0C0;
    pub const PRIQ_PROD: u32 = 0x0C8;
    pub const PRIQ_CONS: u32 = 0x0CC;
};

// ============================================================================
// DMA API
// ============================================================================

pub const DmaDirection = enum(u8) {
    bidirectional = 0,
    to_device = 1,
    from_device = 2,
    none = 3,
};

pub const DmaAttr = packed struct(u64) {
    weak_ordering: bool = false,
    write_combine: bool = false,
    no_kernel_mapping: bool = false,
    skip_cpu_sync: bool = false,
    force_contiguous: bool = false,
    alloc_single_pages: bool = false,
    no_warn: bool = false,
    privileged: bool = false,
    _reserved: u56 = 0,
};

pub const DmaOps = struct {
    alloc: ?*const fn (?*anyopaque, u64, *u64, u32, DmaAttr) ?*anyopaque,
    free: ?*const fn (?*anyopaque, u64, ?*anyopaque, u64, DmaAttr) void,
    alloc_pages: ?*const fn (?*anyopaque, u64, *u64, DmaDirection, u32) ?*anyopaque,
    free_pages: ?*const fn (?*anyopaque, u64, ?*anyopaque, u64, DmaDirection) void,
    alloc_noncontiguous: ?*const fn (?*anyopaque, u64, DmaDirection, u32, DmaAttr) ?*anyopaque,
    free_noncontiguous: ?*const fn (?*anyopaque, u64, ?*anyopaque, DmaDirection) void,
    mmap: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, u64, u64, DmaAttr) i32,
    get_sgtable: ?*const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, u64, u64, DmaAttr) i32,
    map_page: ?*const fn (?*anyopaque, ?*anyopaque, u64, u64, DmaDirection, DmaAttr) u64,
    unmap_page: ?*const fn (?*anyopaque, u64, u64, DmaDirection, DmaAttr) void,
    map_sg: ?*const fn (?*anyopaque, ?*anyopaque, i32, DmaDirection, DmaAttr) i32,
    unmap_sg: ?*const fn (?*anyopaque, ?*anyopaque, i32, DmaDirection, DmaAttr) void,
    map_resource: ?*const fn (?*anyopaque, u64, u64, DmaDirection, DmaAttr) u64,
    unmap_resource: ?*const fn (?*anyopaque, u64, u64, DmaDirection, DmaAttr) void,
    sync_single_for_cpu: ?*const fn (?*anyopaque, u64, u64, DmaDirection) void,
    sync_single_for_device: ?*const fn (?*anyopaque, u64, u64, DmaDirection) void,
    sync_sg_for_cpu: ?*const fn (?*anyopaque, ?*anyopaque, i32, DmaDirection) void,
    sync_sg_for_device: ?*const fn (?*anyopaque, ?*anyopaque, i32, DmaDirection) void,
    cache_sync: ?*const fn (?*anyopaque, u64, u64, DmaDirection) void,
    dma_supported: ?*const fn (?*anyopaque, u64) i32,
    get_required_mask: ?*const fn (?*anyopaque) u64,
    max_mapping_size: ?*const fn (?*anyopaque) u64,
    opt_mapping_size: ?*const fn () u64,
};

// ============================================================================
// SWIOTLB (Software I/O TLB bounce buffer)
// ============================================================================

pub const SWIOTLB_MAX_SIZE: u64 = 256 * 1024 * 1024; // 256MB
pub const SWIOTLB_SLOT_SIZE: u64 = 2048;
pub const SWIOTLB_MAX_SLOTS: u64 = SWIOTLB_MAX_SIZE / SWIOTLB_SLOT_SIZE;

pub const SwiotlbSlot = struct {
    orig_addr: u64,
    alloc_size: u32,
    list: u16,        // Link to next free
    pad_slots: u16,
};

pub const SwiotlbPool = struct {
    start: u64,         // Physical start
    end: u64,           // Physical end
    mapping_size: u64,
    nslabs: u64,
    used: u64,
    slots: [65536]SwiotlbSlot, // Up to 128MB with 2KB slots
    area_nslabs: u64,
    nareas: u32,
    late_alloc: bool,
    force_bounce: bool,
    debugfs: bool,
    // Stats
    total_used: u64,
    max_used: u64,
    bounced: u64,
};

// ============================================================================
// IOVA Allocator
// ============================================================================

pub const IOVA_SHIFT: u32 = 12;  // 4KB granularity

pub const Iova = struct {
    pfn_lo: u64,
    pfn_hi: u64,
};

pub const IovaDomain = struct {
    // RB-tree of free IOVAs
    anchor: u64,        // RB root
    cached_node: ?*anyopaque,
    cached32_node: ?*anyopaque,
    granule: u64,
    start_pfn: u64,
    dma_32bit_pfn: u64,
    max_32bit_mapping_size: u64,
    // Magazine allocator for fast path
    rcaches: [6]IovaRcache,  // 4K, 8K, 16K, 32K, 64K, 128K
    // Flush queue
    fq: ?*IovaFlushQueue,
    fq_flush_start_cnt: u64,
    fq_flush_finish_cnt: u64,
    fq_domain: ?*IommuDomain,
    // Stats
    alloc_count: u64,
    free_count: u64,
};

pub const IovaRcache = struct {
    depot: [128]?*IovaMagazine,
    depot_size: u32,
    loaded: ?*IovaMagazine,
    prev: ?*IovaMagazine,
};

pub const IovaMagazine = struct {
    size: u32,
    pfns: [128]u64,
};

pub const IovaFlushQueue = struct {
    entries: [256]IovaFqEntry,
    head: u32,
    tail: u32,
};

pub const IovaFqEntry = struct {
    counter: u64,
    iova_pfn: u64,
    pages: u64,
    data: ?*anyopaque,
};

// ============================================================================
// IOMMU Fault Handling
// ============================================================================

pub const IommuFaultType = enum(u8) {
    dma_unrecov = 1,       // Unrecoverable DMA fault
    page_req = 2,          // Page request (ATS/PRI)
    dma_unrecov_iopf = 3,  // Unrecoverable with IOPF
};

pub const IommuFaultReason = enum(u8) {
    unknown = 0,
    pasid_invalid = 1,
    pasid_fetch = 2,
    bad_pasid_entry = 3,
    walk_eabt = 4,
    pte_fetch = 5,
    permission = 6,
    access = 7,
    addr_size = 8,
    oob_addr = 9,
};

pub const IommuFault = struct {
    fault_type: IommuFaultType,
    reason: IommuFaultReason,
    addr: u64,
    pasid: u32,
    grpid: u32,
    perm: u32,
    fetch_addr: u64,
    // Device
    source_id: u16,      // PCI BDF
    // Page request specific
    prg_index: u32,
    last_req: bool,
};

pub const IommuFaultHandler = struct {
    handler: ?*const fn (?*IommuFault, ?*anyopaque) i32,
    data: ?*anyopaque,
};

// ============================================================================
// PASID (Process Address Space ID)
// ============================================================================

pub const PASID_MAX: u32 = 0xFFFFF; // 20-bit
pub const PASID_INVALID: u32 = 0xFFFFFFFF;

pub const PasidState = struct {
    table: [1024]PasidEntry, // Simplified from multi-level
    max_pasid: u32,
    allocated: u32,
};

pub const PasidEntry = struct {
    pasid: u32,
    domain: ?*IommuDomain,
    pgd: u64,
    task: ?*anyopaque,
    flags: u32,
    enabled: bool,
};

// ============================================================================
// Scatter-Gather List for DMA
// ============================================================================

pub const ScatterlistEntry = struct {
    page: u64,        // Page frame number
    offset: u32,
    length: u32,
    dma_address: u64,
    dma_length: u32,
};

pub const SgTable = struct {
    sgl: [128]ScatterlistEntry,
    nents: u32,        // Number of mapped entries
    orig_nents: u32,   // Original number of entries
};

// ============================================================================
// IOMMU Subsystem Manager
// ============================================================================

pub const MAX_IOMMU_DEVICES: usize = 16;
pub const MAX_IOMMU_DOMAINS: usize = 4096;
pub const MAX_IOMMU_GROUPS: usize = 1024;

pub const IommuSubsystem = struct {
    devices: [MAX_IOMMU_DEVICES]?*IommuDevice,
    nr_devices: u32,
    domains: [MAX_IOMMU_DOMAINS]?*IommuDomain,
    nr_domains: u32,
    groups: [MAX_IOMMU_GROUPS]?*IommuGroup,
    nr_groups: u32,
    // Default DMA ops
    default_dma_ops: ?*const DmaOps,
    // SWIOTLB
    swiotlb: ?*SwiotlbPool,
    swiotlb_force: SwiotlbForce,
    // Global state
    initialized: bool,
    // Stats
    total_maps: u64,
    total_unmaps: u64,
    total_faults: u64,

    pub fn find_device(self: *const IommuSubsystem, segment: u16, bdf: u16) ?*IommuDevice {
        for (self.devices[0..self.nr_devices]) |maybe_dev| {
            if (maybe_dev) |dev| {
                if (dev.segment == segment) return dev;
            }
        }
        return null;
    }

    pub fn alloc_domain(self: *IommuSubsystem, domain_type: IommuDomainType) ?*IommuDomain {
        if (self.nr_domains >= MAX_IOMMU_DOMAINS) return null;
        // Find free slot
        for (&self.domains) |*slot| {
            if (slot.* == null) {
                // Would allocate domain here
                self.nr_domains += 1;
                return null; // Placeholder
            }
        }
        return null;
    }
};

pub const SwiotlbForce = enum(u8) {
    no_force = 0,
    force = 1,
    no_swiotlb = 2,
};
