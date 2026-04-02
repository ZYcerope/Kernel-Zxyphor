// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Virtualization: VMCS Shadow, Posted Interrupts, IOMMU Virt
// Complete Intel VMCS fields, shadow VMCS, posted interrupt descriptor,
// EPT violations, IOMMU / VT-d virtualization, PASID, scalable mode

const std = @import("std");

// ============================================================================
// VMCS Field Encoding
// ============================================================================

pub const VmcsFieldWidth = enum(u2) {
    Bit16 = 0,
    Bit64 = 1,
    Bit32 = 2,
    Natural = 3,
};

pub const VmcsFieldType = enum(u2) {
    Control = 0,
    ReadOnly = 1,
    Guest = 2,
    Host = 3,
};

pub const VmcsField = packed struct(u32) {
    access_type: u1,      // 0=full, 1=high
    index: u9,
    field_type: VmcsFieldType,
    _reserved: u1,
    width: VmcsFieldWidth,
    _pad: u17,
};

// ============================================================================
// VMCS 16-bit Fields
// ============================================================================

pub const VMCS_VIRTUAL_PROCESSOR_ID: u32 = 0x00000000;
pub const VMCS_POSTED_INT_NOTIFICATION_VEC: u32 = 0x00000002;
pub const VMCS_EPTP_INDEX: u32 = 0x00000004;
pub const VMCS_HLAT_PREFIX_SIZE: u32 = 0x00000006;
pub const VMCS_LAST_PID_POINTER_INDEX: u32 = 0x00000008;
pub const VMCS_GUEST_ES: u32 = 0x00000800;
pub const VMCS_GUEST_CS: u32 = 0x00000802;
pub const VMCS_GUEST_SS: u32 = 0x00000804;
pub const VMCS_GUEST_DS: u32 = 0x00000806;
pub const VMCS_GUEST_FS: u32 = 0x00000808;
pub const VMCS_GUEST_GS: u32 = 0x0000080A;
pub const VMCS_GUEST_LDTR: u32 = 0x0000080C;
pub const VMCS_GUEST_TR: u32 = 0x0000080E;
pub const VMCS_GUEST_INTR_STATUS: u32 = 0x00000810;
pub const VMCS_GUEST_PML_INDEX: u32 = 0x00000812;
pub const VMCS_HOST_ES: u32 = 0x00000C00;
pub const VMCS_HOST_CS: u32 = 0x00000C02;
pub const VMCS_HOST_SS: u32 = 0x00000C04;
pub const VMCS_HOST_DS: u32 = 0x00000C06;
pub const VMCS_HOST_FS: u32 = 0x00000C08;
pub const VMCS_HOST_GS: u32 = 0x00000C0A;
pub const VMCS_HOST_TR: u32 = 0x00000C0C;

// ============================================================================
// VMCS 64-bit Fields
// ============================================================================

pub const VMCS_IO_BITMAP_A: u32 = 0x00002000;
pub const VMCS_IO_BITMAP_B: u32 = 0x00002002;
pub const VMCS_MSR_BITMAP: u32 = 0x00002004;
pub const VMCS_VM_EXIT_MSR_STORE_ADDR: u32 = 0x00002006;
pub const VMCS_VM_EXIT_MSR_LOAD_ADDR: u32 = 0x00002008;
pub const VMCS_VM_ENTRY_MSR_LOAD_ADDR: u32 = 0x0000200A;
pub const VMCS_EXECUTIVE_VMCS_PTR: u32 = 0x0000200C;
pub const VMCS_PML_ADDRESS: u32 = 0x0000200E;
pub const VMCS_TSC_OFFSET: u32 = 0x00002010;
pub const VMCS_VIRTUAL_APIC_PAGE_ADDR: u32 = 0x00002012;
pub const VMCS_APIC_ACCESS_ADDR: u32 = 0x00002014;
pub const VMCS_PI_NOTIFICATION_ADDR: u32 = 0x00002016;
pub const VMCS_VM_FUNCTION_CONTROL: u32 = 0x00002018;
pub const VMCS_EPTP: u32 = 0x0000201A;
pub const VMCS_EOI_EXIT_BITMAP_0: u32 = 0x0000201C;
pub const VMCS_EOI_EXIT_BITMAP_1: u32 = 0x0000201E;
pub const VMCS_EOI_EXIT_BITMAP_2: u32 = 0x00002020;
pub const VMCS_EOI_EXIT_BITMAP_3: u32 = 0x00002022;
pub const VMCS_EPTP_LIST_ADDR: u32 = 0x00002024;
pub const VMCS_VMREAD_BITMAP: u32 = 0x00002026;
pub const VMCS_VMWRITE_BITMAP: u32 = 0x00002028;
pub const VMCS_VIRT_EXCEPTION_INFO_ADDR: u32 = 0x0000202A;
pub const VMCS_XSS_EXIT_BITMAP: u32 = 0x0000202C;
pub const VMCS_ENCLS_EXITING_BITMAP: u32 = 0x0000202E;
pub const VMCS_SUB_PAGE_PERM_TABLE_PTR: u32 = 0x00002030;
pub const VMCS_TSC_MULTIPLIER: u32 = 0x00002032;
pub const VMCS_TERTIARY_PROC_BASED: u32 = 0x00002034;
pub const VMCS_ENCLV_EXITING_BITMAP: u32 = 0x00002036;
pub const VMCS_LOW_PASID_DIR: u32 = 0x00002038;
pub const VMCS_HIGH_PASID_DIR: u32 = 0x0000203A;
pub const VMCS_SHARED_EPTP: u32 = 0x0000203C;
pub const VMCS_PCONFIG_EXITING: u32 = 0x0000203E;
pub const VMCS_HLAT_PTR: u32 = 0x00002040;
pub const VMCS_PID_TABLE_ADDR: u32 = 0x00002042;
pub const VMCS_SECONDARY_EXIT_CTLS: u32 = 0x00002044;

// Guest 64-bit fields
pub const VMCS_GUEST_VMCS_LINK_PTR: u32 = 0x00002800;
pub const VMCS_GUEST_IA32_DEBUGCTL: u32 = 0x00002802;
pub const VMCS_GUEST_IA32_PAT: u32 = 0x00002804;
pub const VMCS_GUEST_IA32_EFER: u32 = 0x00002806;
pub const VMCS_GUEST_IA32_PERF_GLOBAL_CTRL: u32 = 0x00002808;
pub const VMCS_GUEST_PDPTE0: u32 = 0x0000280A;
pub const VMCS_GUEST_PDPTE1: u32 = 0x0000280C;
pub const VMCS_GUEST_PDPTE2: u32 = 0x0000280E;
pub const VMCS_GUEST_PDPTE3: u32 = 0x00002810;
pub const VMCS_GUEST_IA32_BNDCFGS: u32 = 0x00002812;
pub const VMCS_GUEST_IA32_RTIT_CTL: u32 = 0x00002814;
pub const VMCS_GUEST_IA32_LBR_CTL: u32 = 0x00002816;
pub const VMCS_GUEST_IA32_PKRS: u32 = 0x00002818;

// ============================================================================
// VMCS 32-bit Fields
// ============================================================================

pub const VMCS_PIN_BASED_EXEC_CTRL: u32 = 0x00004000;
pub const VMCS_PROC_BASED_EXEC_CTRL: u32 = 0x00004002;
pub const VMCS_EXCEPTION_BITMAP: u32 = 0x00004004;
pub const VMCS_PAGE_FAULT_ERROR_MASK: u32 = 0x00004006;
pub const VMCS_PAGE_FAULT_ERROR_MATCH: u32 = 0x00004008;
pub const VMCS_CR3_TARGET_COUNT: u32 = 0x0000400A;
pub const VMCS_PRIMARY_EXIT_CTRL: u32 = 0x0000400C;
pub const VMCS_VM_EXIT_MSR_STORE_COUNT: u32 = 0x0000400E;
pub const VMCS_VM_EXIT_MSR_LOAD_COUNT: u32 = 0x00004010;
pub const VMCS_VM_ENTRY_CTRL: u32 = 0x00004012;
pub const VMCS_VM_ENTRY_MSR_LOAD_COUNT: u32 = 0x00004014;
pub const VMCS_VM_ENTRY_INT_INFO: u32 = 0x00004016;
pub const VMCS_VM_ENTRY_EXCEPTION_ERR: u32 = 0x00004018;
pub const VMCS_VM_ENTRY_INSTR_LEN: u32 = 0x0000401A;
pub const VMCS_TPR_THRESHOLD: u32 = 0x0000401C;
pub const VMCS_SECONDARY_PROC_BASED: u32 = 0x0000401E;
pub const VMCS_PLE_GAP: u32 = 0x00004020;
pub const VMCS_PLE_WINDOW: u32 = 0x00004022;
pub const VMCS_NOTIFY_WINDOW: u32 = 0x00004024;

// ============================================================================
// Pin-Based VM-Execution Controls
// ============================================================================

pub const PinBasedCtrl = packed struct(u32) {
    ext_int_exit: bool = false,         // Bit 0
    _reserved1: u2 = 0,
    nmi_exiting: bool = false,          // Bit 3
    _reserved2: u1 = 0,
    virtual_nmis: bool = false,         // Bit 5
    preemption_timer: bool = false,     // Bit 6
    posted_interrupts: bool = false,    // Bit 7
    _reserved3: u24 = 0,
};

// ============================================================================
// Primary Proc-Based Controls
// ============================================================================

pub const ProcBasedCtrl = packed struct(u32) {
    _reserved0: u2 = 0,
    int_window_exit: bool = false,      // Bit 2
    use_tsc_offsetting: bool = false,   // Bit 3
    _reserved1: u3 = 0,
    hlt_exit: bool = false,             // Bit 7
    _reserved2: u1 = 0,
    invlpg_exit: bool = false,          // Bit 9
    mwait_exit: bool = false,           // Bit 10
    rdpmc_exit: bool = false,           // Bit 11
    rdtsc_exit: bool = false,           // Bit 12
    _reserved3: u2 = 0,
    cr3_load_exit: bool = false,        // Bit 15
    cr3_store_exit: bool = false,       // Bit 16
    activate_tertiary: bool = false,    // Bit 17
    _reserved4: u1 = 0,
    cr8_load_exit: bool = false,        // Bit 19
    cr8_store_exit: bool = false,       // Bit 20
    tpr_shadow: bool = false,           // Bit 21
    nmi_window_exit: bool = false,      // Bit 22
    mov_dr_exit: bool = false,          // Bit 23
    uncond_io_exit: bool = false,       // Bit 24
    use_io_bitmaps: bool = false,       // Bit 25
    _reserved5: u1 = 0,
    monitor_trap: bool = false,         // Bit 27
    use_msr_bitmaps: bool = false,      // Bit 28
    monitor_exit: bool = false,         // Bit 29
    pause_exit: bool = false,           // Bit 30
    secondary_ctls: bool = false,       // Bit 31
};

// ============================================================================
// Posted Interrupt Descriptor
// ============================================================================

pub const PostedInterruptDesc = struct {
    pir: [4]u64,         // Posted Interrupt Requests (256 bits)
    control: PidControl,
    _reserved: [6]u32,
};

pub const PidControl = packed struct(u64) {
    outstanding_notification: bool,
    suppress_notification: bool,
    _reserved: u14,
    notification_vector: u8,
    _reserved2: u8,
    notification_destination: u32,
};

// ============================================================================
// Shadow VMCS
// ============================================================================

pub const ShadowVmcsConfig = struct {
    enabled: bool,
    vmread_bitmap_addr: u64,
    vmwrite_bitmap_addr: u64,
    shadow_vmcs_addr: u64,
    is_current: bool,
};

// ============================================================================
// EPT (Extended Page Tables) Violation
// ============================================================================

pub const EptViolation = packed struct(u64) {
    read: bool,
    write: bool,
    execute: bool,
    readable: bool,
    writable: bool,
    executable: bool,
    user_executable: bool,
    valid_guest_linear: bool,
    caused_by_translation: bool,
    user_mode_linear: bool,
    is_read_write_page: bool,
    is_execute_disable: bool,
    nmi_unblocking: bool,
    shadow_stack: bool,
    supervisor_shadow_stack: bool,
    _reserved: u49,
};

pub const EptpConfig = packed struct(u64) {
    memory_type: u3,     // 0=UC, 6=WB
    page_walk_length: u3, // 3 = 4-level
    enable_dirty_flag: bool,
    _reserved: u5,
    pml4_pfn: u52,
};

pub const EptEntry = packed struct(u64) {
    read: bool,
    write: bool,
    execute: bool,
    memory_type: u3,
    ignore_pat: bool,
    is_large_page: bool,
    accessed: bool,
    dirty: bool,
    user_execute: bool,
    _reserved: u1,
    pfn: u40,
    _reserved2: u8,
    suppress_ve: bool,
    _reserved3: u2,
    verify_guest_paging: bool,
    paging_write: bool,
    _reserved4: u1,
    supervisor_shadow_stack: bool,
    _reserved5: u1,
};

// ============================================================================
// VT-d / IOMMU Virtualization
// ============================================================================

pub const VtdCapReg = packed struct(u64) {
    nd: u3,              // Number of Domains
    afl: bool,           // Advanced fault logging
    rwbf: bool,          // Required write-buffer flushing
    plmr: bool,          // Protected low-memory region
    phmr: bool,          // Protected high-memory region
    cm: bool,            // Caching mode
    _reserved: u1,
    sagaw: u5,           // Supported adjusted guest address widths
    _reserved2: u3,
    mgaw: u6,            // Maximum guest address width
    zlr: bool,           // Zero length read
    _reserved3: u1,
    fro: u10,            // Fault recording register offset
    sllps: u4,           // Second level large page support
    _reserved4: u1,
    psi: bool,           // Page selective invalidation
    nfr: u8,             // Number of fault recording registers
    mamv: u6,            // Maximum address mask value
    dwd: bool,           // DMA write draining
    drd: bool,           // DMA read draining
    fl1gp: bool,         // First level 1-GByte page
    _reserved5: u2,
    pi: bool,            // Posted interrupts
    fl5lp: bool,         // First level 5-level paging
    _reserved6: u1,
    esirtps: bool,
    esrtps: bool,
};

pub const VtdEcapReg = packed struct(u64) {
    c: bool,             // Page-walk coherency
    qi: bool,            // Queued invalidation
    dt: bool,            // Device TLB
    ir: bool,            // Interrupt remapping
    eim: bool,           // Extended interrupt mode
    _reserved: u1,
    pt: bool,            // Pass through
    sc: bool,            // Snoop control
    iro: u10,            // IOTLB register offset
    _reserved2: u2,
    mhmv: u4,            // Maximum handle mask value
    ecs: bool,           // Extended context support
    mts: bool,           // Memory type support
    nest: bool,          // Nested translation
    _reserved3: u1,
    prs: bool,           // Page request support
    ers: bool,           // Execute request support
    srs: bool,           // Supervisor request support
    _reserved4: u1,
    nwfs: bool,          // No write flag support
    eafs: bool,          // Extended accessed flag
    pss: u5,             // PASID size supported
    pasid: bool,         // Process address space ID
    dit: bool,           // Device-TLB invalidation throttle
    pds: bool,           // Page-drain support
    smts: bool,          // Scalable mode translation
    vcs: bool,           // Virtual command support
    slads: bool,         // Second-level accessed dirty
    slts: bool,          // Second-level translation
    flts: bool,          // First-level translation
    smpwcs: bool,        // SM page-walk coherency
    rps: bool,           // RID-PASID support
    _reserved5: u7,
    adms: bool,          // Abort DMA mode
    rprivs: bool,        // RID_PRIV support
};

// ============================================================================
// PASID (Process Address Space ID)
// ============================================================================

pub const PASID_MAX = 0xFFFFF;  // 20-bit PASID

pub const PasidTableEntry = packed struct(u64) {
    present: bool,
    _reserved: u2,
    page_level_write_through: bool,
    page_level_cache_disable: bool,
    _reserved2: u7,
    first_level_pml5: u52,
};

pub const PasidDirEntry = packed struct(u64) {
    present: bool,
    _reserved: u11,
    pasid_table_ptr: u52,
};

pub const ScalableModeContextEntry = struct {
    lo: packed struct(u64) {
        present: bool,
        fault_processing_disable: bool,
        translation_type: u3,
        _reserved: u7,
        pasid_dir_ptr: u52,
    },
    hi: packed struct(u64) {
        _reserved: u3,
        aw: u3,        // Address width
        _reserved2: u4,
        did: u16,       // Domain ID
        _reserved3: u38,
    },
};

// ============================================================================
// Virt Manager
// ============================================================================

pub const VmcsIommuManager = struct {
    shadow_vmcs_enabled: bool,
    posted_interrupts_enabled: bool,
    ept_violation_count: u64,
    ept_misconfiguration_count: u64,
    vmcs_read_count: u64,
    vmcs_write_count: u64,
    vtd_enabled: bool,
    vtd_scalable_mode: bool,
    vtd_pasid_enabled: bool,
    vtd_posted_interrupts: bool,
    total_iommu_faults: u64,
    total_iotlb_flushes: u64,
    total_ctx_cache_flushes: u64,
    total_pasid_allocated: u64,
    initialized: bool,

    pub fn init() VmcsIommuManager {
        return .{
            .shadow_vmcs_enabled = false,
            .posted_interrupts_enabled = false,
            .ept_violation_count = 0,
            .ept_misconfiguration_count = 0,
            .vmcs_read_count = 0,
            .vmcs_write_count = 0,
            .vtd_enabled = false,
            .vtd_scalable_mode = false,
            .vtd_pasid_enabled = false,
            .vtd_posted_interrupts = false,
            .total_iommu_faults = 0,
            .total_iotlb_flushes = 0,
            .total_ctx_cache_flushes = 0,
            .total_pasid_allocated = 0,
            .initialized = true,
        };
    }
};
