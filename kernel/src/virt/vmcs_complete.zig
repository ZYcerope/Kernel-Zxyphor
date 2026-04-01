// Zxyphor Kernel - VMCS Layout Complete (Intel VMX),
// VMCS Field Encoding, VM-Entry/VM-Exit Controls,
// Secondary Processor-Based Controls,
// Tertiary Processor-Based Controls,
// VM-Execution Pin/Proc Controls,
// VMCS Shadowing, Nested VMX, VMFUNC
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// VMCS Field Encoding
// ============================================================================

pub const VmcsFieldWidth = enum(u2) {
    word16 = 0,
    word64 = 1,
    word32 = 2,
    natural = 3,   // 64-bit in 64-bit mode
};

pub const VmcsFieldType = enum(u2) {
    control = 0,
    read_only = 1,
    guest = 2,
    host = 3,
};

pub const VmcsFieldEncoding = packed struct(u32) {
    access_type: u1,      // 0 = full, 1 = high
    index: u9,
    field_type: u2,
    _reserved1: u1,
    field_width: u2,
    _reserved2: u17,
};

// ============================================================================
// VMCS 16-bit Control Fields
// ============================================================================

pub const VMCS16 = struct {
    // Control fields
    pub const VPID: u32 = 0x00000000;
    pub const POSTED_INT_NOTIFY_VEC: u32 = 0x00000002;
    pub const EPTP_INDEX: u32 = 0x00000004;
    pub const HLAT_PREFIX_SIZE: u32 = 0x00000006;
    // Guest-state fields
    pub const GUEST_ES_SEL: u32 = 0x00000800;
    pub const GUEST_CS_SEL: u32 = 0x00000802;
    pub const GUEST_SS_SEL: u32 = 0x00000804;
    pub const GUEST_DS_SEL: u32 = 0x00000806;
    pub const GUEST_FS_SEL: u32 = 0x00000808;
    pub const GUEST_GS_SEL: u32 = 0x0000080A;
    pub const GUEST_LDTR_SEL: u32 = 0x0000080C;
    pub const GUEST_TR_SEL: u32 = 0x0000080E;
    pub const GUEST_INT_STATUS: u32 = 0x00000810;
    pub const GUEST_PML_INDEX: u32 = 0x00000812;
    // Host-state fields
    pub const HOST_ES_SEL: u32 = 0x00000C00;
    pub const HOST_CS_SEL: u32 = 0x00000C02;
    pub const HOST_SS_SEL: u32 = 0x00000C04;
    pub const HOST_DS_SEL: u32 = 0x00000C06;
    pub const HOST_FS_SEL: u32 = 0x00000C08;
    pub const HOST_GS_SEL: u32 = 0x00000C0A;
    pub const HOST_TR_SEL: u32 = 0x00000C0C;
};

// ============================================================================
// VMCS 64-bit Control Fields
// ============================================================================

pub const VMCS64 = struct {
    // Control fields
    pub const IO_BITMAP_A: u32 = 0x00002000;
    pub const IO_BITMAP_B: u32 = 0x00002002;
    pub const MSR_BITMAP: u32 = 0x00002004;
    pub const VM_EXIT_MSR_STORE_ADDR: u32 = 0x00002006;
    pub const VM_EXIT_MSR_LOAD_ADDR: u32 = 0x00002008;
    pub const VM_ENTRY_MSR_LOAD_ADDR: u32 = 0x0000200A;
    pub const EXECUTIVE_VMCS: u32 = 0x0000200C;
    pub const PML_ADDRESS: u32 = 0x0000200E;
    pub const TSC_OFFSET: u32 = 0x00002010;
    pub const VIRTUAL_APIC_PAGE: u32 = 0x00002012;
    pub const APIC_ACCESS_ADDR: u32 = 0x00002014;
    pub const POSTED_INT_DESC: u32 = 0x00002016;
    pub const VM_FUNCTION_CONTROL: u32 = 0x00002018;
    pub const EPT_POINTER: u32 = 0x0000201A;
    pub const EOI_EXIT_BITMAP0: u32 = 0x0000201C;
    pub const EOI_EXIT_BITMAP1: u32 = 0x0000201E;
    pub const EOI_EXIT_BITMAP2: u32 = 0x00002020;
    pub const EOI_EXIT_BITMAP3: u32 = 0x00002022;
    pub const EPTP_LIST: u32 = 0x00002024;
    pub const VMREAD_BITMAP: u32 = 0x00002026;
    pub const VMWRITE_BITMAP: u32 = 0x00002028;
    pub const VIRT_EXCEPTION_INFO: u32 = 0x0000202A;
    pub const XSS_EXIT_BITMAP: u32 = 0x0000202C;
    pub const ENCLS_EXIT_BITMAP: u32 = 0x0000202E;
    pub const SPP_TABLE: u32 = 0x00002030;
    pub const TSC_MULTIPLIER: u32 = 0x00002032;
    pub const TERTIARY_PROC_EXEC: u32 = 0x00002034;
    pub const ENCLV_EXIT_BITMAP: u32 = 0x00002036;
    pub const LOW_PASID_DIR: u32 = 0x00002038;
    pub const HIGH_PASID_DIR: u32 = 0x0000203A;
    pub const SHARED_EPT_POINTER: u32 = 0x0000203C;
    pub const PCONFIG_EXITING: u32 = 0x0000203E;
    pub const HLAT_POINTER: u32 = 0x00002040;
    pub const SECONDARY_EXIT: u32 = 0x00002044;
    // Read-only
    pub const GUEST_PHYS_ADDR: u32 = 0x00002400;
    // Guest-state
    pub const VMCS_LINK_POINTER: u32 = 0x00002800;
    pub const GUEST_IA32_DEBUGCTL: u32 = 0x00002802;
    pub const GUEST_PAT: u32 = 0x00002804;
    pub const GUEST_EFER: u32 = 0x00002806;
    pub const GUEST_PERF_GLOBAL: u32 = 0x00002808;
    pub const GUEST_PDPTE0: u32 = 0x0000280A;
    pub const GUEST_PDPTE1: u32 = 0x0000280C;
    pub const GUEST_PDPTE2: u32 = 0x0000280E;
    pub const GUEST_PDPTE3: u32 = 0x00002810;
    pub const GUEST_BNDCFGS: u32 = 0x00002812;
    pub const GUEST_RTIT_CTL: u32 = 0x00002814;
    pub const GUEST_LBR_CTL: u32 = 0x00002816;
    pub const GUEST_PKRS: u32 = 0x00002818;
    // Host-state
    pub const HOST_PAT: u32 = 0x00002C00;
    pub const HOST_EFER: u32 = 0x00002C02;
    pub const HOST_PERF_GLOBAL: u32 = 0x00002C04;
    pub const HOST_PKRS: u32 = 0x00002C06;
};

// ============================================================================
// VMCS 32-bit Control Fields
// ============================================================================

pub const VMCS32 = struct {
    // Control fields
    pub const PIN_BASED_EXEC: u32 = 0x00004000;
    pub const PROC_BASED_EXEC: u32 = 0x00004002;
    pub const EXCEPTION_BITMAP: u32 = 0x00004004;
    pub const PAGE_FAULT_ERROR_MASK: u32 = 0x00004006;
    pub const PAGE_FAULT_ERROR_MATCH: u32 = 0x00004008;
    pub const CR3_TARGET_COUNT: u32 = 0x0000400A;
    pub const VM_EXIT_CONTROLS: u32 = 0x0000400C;
    pub const VM_EXIT_MSR_STORE_COUNT: u32 = 0x0000400E;
    pub const VM_EXIT_MSR_LOAD_COUNT: u32 = 0x00004010;
    pub const VM_ENTRY_CONTROLS: u32 = 0x00004012;
    pub const VM_ENTRY_MSR_LOAD_COUNT: u32 = 0x00004014;
    pub const VM_ENTRY_INT_INFO: u32 = 0x00004016;
    pub const VM_ENTRY_EXCEPTION_ERRCODE: u32 = 0x00004018;
    pub const VM_ENTRY_INSTR_LEN: u32 = 0x0000401A;
    pub const TPR_THRESHOLD: u32 = 0x0000401C;
    pub const SECONDARY_PROC_EXEC: u32 = 0x0000401E;
    pub const PLE_GAP: u32 = 0x00004020;
    pub const PLE_WINDOW: u32 = 0x00004022;
    pub const NOTIFY_WINDOW: u32 = 0x00004024;
    // Read-only
    pub const VM_INSTR_ERROR: u32 = 0x00004400;
    pub const VM_EXIT_REASON: u32 = 0x00004402;
    pub const VM_EXIT_INT_INFO: u32 = 0x00004404;
    pub const VM_EXIT_INT_ERRCODE: u32 = 0x00004406;
    pub const IDT_VECTORING_INFO: u32 = 0x00004408;
    pub const IDT_VECTORING_ERRCODE: u32 = 0x0000440A;
    pub const VM_EXIT_INSTR_LEN: u32 = 0x0000440C;
    pub const VM_EXIT_INSTR_INFO: u32 = 0x0000440E;
    // Guest-state
    pub const GUEST_ES_LIMIT: u32 = 0x00004800;
    pub const GUEST_CS_LIMIT: u32 = 0x00004802;
    pub const GUEST_SS_LIMIT: u32 = 0x00004804;
    pub const GUEST_DS_LIMIT: u32 = 0x00004806;
    pub const GUEST_FS_LIMIT: u32 = 0x00004808;
    pub const GUEST_GS_LIMIT: u32 = 0x0000480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x0000480C;
    pub const GUEST_TR_LIMIT: u32 = 0x0000480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x00004810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x00004812;
    pub const GUEST_ES_AR: u32 = 0x00004814;
    pub const GUEST_CS_AR: u32 = 0x00004816;
    pub const GUEST_SS_AR: u32 = 0x00004818;
    pub const GUEST_DS_AR: u32 = 0x0000481A;
    pub const GUEST_FS_AR: u32 = 0x0000481C;
    pub const GUEST_GS_AR: u32 = 0x0000481E;
    pub const GUEST_LDTR_AR: u32 = 0x00004820;
    pub const GUEST_TR_AR: u32 = 0x00004822;
    pub const GUEST_INT_STATE: u32 = 0x00004824;
    pub const GUEST_ACTIVITY_STATE: u32 = 0x00004826;
    pub const GUEST_SMBASE: u32 = 0x00004828;
    pub const GUEST_SYSENTER_CS: u32 = 0x0000482A;
    pub const GUEST_PREEMPT_TIMER: u32 = 0x0000482E;
    // Host-state
    pub const HOST_SYSENTER_CS: u32 = 0x00004C00;
};

// ============================================================================
// VMCS Natural-Width Fields
// ============================================================================

pub const VMCS_NAT = struct {
    // Control
    pub const CR0_GUEST_HOST_MASK: u32 = 0x00006000;
    pub const CR4_GUEST_HOST_MASK: u32 = 0x00006002;
    pub const CR0_READ_SHADOW: u32 = 0x00006004;
    pub const CR4_READ_SHADOW: u32 = 0x00006006;
    pub const CR3_TARGET_0: u32 = 0x00006008;
    pub const CR3_TARGET_1: u32 = 0x0000600A;
    pub const CR3_TARGET_2: u32 = 0x0000600C;
    pub const CR3_TARGET_3: u32 = 0x0000600E;
    // Read-only
    pub const EXIT_QUALIFICATION: u32 = 0x00006400;
    pub const IO_RCX: u32 = 0x00006402;
    pub const IO_RSI: u32 = 0x00006404;
    pub const IO_RDI: u32 = 0x00006406;
    pub const IO_RIP: u32 = 0x00006408;
    pub const GUEST_LINEAR_ADDR: u32 = 0x0000640A;
    // Guest-state
    pub const GUEST_CR0: u32 = 0x00006800;
    pub const GUEST_CR3: u32 = 0x00006802;
    pub const GUEST_CR4: u32 = 0x00006804;
    pub const GUEST_ES_BASE: u32 = 0x00006806;
    pub const GUEST_CS_BASE: u32 = 0x00006808;
    pub const GUEST_SS_BASE: u32 = 0x0000680A;
    pub const GUEST_DS_BASE: u32 = 0x0000680C;
    pub const GUEST_FS_BASE: u32 = 0x0000680E;
    pub const GUEST_GS_BASE: u32 = 0x00006810;
    pub const GUEST_LDTR_BASE: u32 = 0x00006812;
    pub const GUEST_TR_BASE: u32 = 0x00006814;
    pub const GUEST_GDTR_BASE: u32 = 0x00006816;
    pub const GUEST_IDTR_BASE: u32 = 0x00006818;
    pub const GUEST_DR7: u32 = 0x0000681A;
    pub const GUEST_RSP: u32 = 0x0000681C;
    pub const GUEST_RIP: u32 = 0x0000681E;
    pub const GUEST_RFLAGS: u32 = 0x00006820;
    pub const GUEST_PENDING_DBG: u32 = 0x00006822;
    pub const GUEST_SYSENTER_ESP: u32 = 0x00006824;
    pub const GUEST_SYSENTER_EIP: u32 = 0x00006826;
    pub const GUEST_S_CET: u32 = 0x00006828;
    pub const GUEST_SSP: u32 = 0x0000682A;
    pub const GUEST_ISST: u32 = 0x0000682C;
    // Host-state
    pub const HOST_CR0: u32 = 0x00006C00;
    pub const HOST_CR3: u32 = 0x00006C02;
    pub const HOST_CR4: u32 = 0x00006C04;
    pub const HOST_FS_BASE: u32 = 0x00006C06;
    pub const HOST_GS_BASE: u32 = 0x00006C08;
    pub const HOST_TR_BASE: u32 = 0x00006C0A;
    pub const HOST_GDTR_BASE: u32 = 0x00006C0C;
    pub const HOST_IDTR_BASE: u32 = 0x00006C0E;
    pub const HOST_SYSENTER_ESP: u32 = 0x00006C10;
    pub const HOST_SYSENTER_EIP: u32 = 0x00006C12;
    pub const HOST_RSP: u32 = 0x00006C14;
    pub const HOST_RIP: u32 = 0x00006C16;
    pub const HOST_S_CET: u32 = 0x00006C18;
    pub const HOST_SSP: u32 = 0x00006C1A;
    pub const HOST_ISST: u32 = 0x00006C1C;
};

// ============================================================================
// Pin-Based VM-Execution Controls
// ============================================================================

pub const PinExecControls = packed struct(u32) {
    external_int_exit: bool = true,
    _reserved1: u2 = 0,
    nmi_exiting: bool = true,
    _reserved2: bool = false,
    virtual_nmis: bool = true,
    preemption_timer: bool = false,
    posted_interrupts: bool = false,
    _reserved3: u24 = 0,
};

// ============================================================================
// Primary Processor-Based VM-Execution Controls
// ============================================================================

pub const PrimaryProcExecControls = packed struct(u32) {
    _reserved1: u2 = 0,
    int_window_exit: bool = false,
    use_tsc_offsetting: bool = true,
    _reserved2: u3 = 0,
    hlt_exiting: bool = false,
    _reserved3: bool = false,
    invlpg_exiting: bool = false,
    mwait_exiting: bool = false,
    rdpmc_exiting: bool = false,
    rdtsc_exiting: bool = false,
    _reserved4: u2 = 0,
    cr3_load_exiting: bool = false,
    cr3_store_exiting: bool = false,
    activate_tertiary: bool = false,
    _reserved5: bool = false,
    cr8_load_exiting: bool = false,
    cr8_store_exiting: bool = false,
    use_tpr_shadow: bool = false,
    nmi_window_exit: bool = false,
    mov_dr_exiting: bool = false,
    unconditional_io_exit: bool = false,
    use_io_bitmaps: bool = false,
    _reserved6: bool = false,
    monitor_trap: bool = false,
    use_msr_bitmaps: bool = true,
    monitor_exiting: bool = false,
    pause_exiting: bool = false,
    activate_secondary: bool = true,
};

// ============================================================================
// Secondary Processor-Based VM-Execution Controls
// ============================================================================

pub const SecondaryProcExecControls = packed struct(u32) {
    virt_apic_access: bool = false,
    enable_ept: bool = true,
    desc_table_exit: bool = false,
    enable_rdtscp: bool = true,
    virt_x2apic: bool = false,
    enable_vpid: bool = true,
    wbinvd_exiting: bool = false,
    unrestricted_guest: bool = true,
    apic_reg_virt: bool = false,
    virt_int_delivery: bool = false,
    pause_loop_exit: bool = false,
    rdrand_exiting: bool = false,
    enable_invpcid: bool = true,
    enable_vmfunc: bool = false,
    vmcs_shadowing: bool = false,
    enable_encls_exit: bool = false,
    rdseed_exiting: bool = false,
    enable_pml: bool = false,
    ept_ve: bool = false,
    conceal_from_pt: bool = false,
    enable_xsaves: bool = true,
    _reserved1: bool = false,
    mode_based_ept: bool = false,
    sub_page_write: bool = false,
    pt_use_guest_pa: bool = false,
    tsc_scaling: bool = false,
    enable_user_wait: bool = false,
    enable_pconfig: bool = false,
    enable_enclv_exit: bool = false,
    _reserved2: u3 = 0,
};

// ============================================================================
// VM-Exit Controls
// ============================================================================

pub const VmExitControls = packed struct(u32) {
    _reserved1: u2 = 0,
    save_debug_ctls: bool = true,
    _reserved2: u6 = 0,
    host_addr_space_size: bool = true,   // 64-bit host
    _reserved3: u2 = 0,
    load_perf_global: bool = false,
    _reserved4: u2 = 0,
    ack_int_on_exit: bool = true,
    _reserved5: u2 = 0,
    save_pat: bool = true,
    load_pat: bool = true,
    save_efer: bool = true,
    load_efer: bool = true,
    save_preempt_timer: bool = false,
    clear_bndcfgs: bool = false,
    conceal_from_pt: bool = false,
    clear_rtit_ctl: bool = false,
    clear_lbr_ctl: bool = false,
    _reserved6: bool = false,
    load_cet: bool = false,
    load_pkrs: bool = false,
    save_perf_global: bool = false,
    activate_secondary: bool = false,
};

// ============================================================================
// VM-Entry Controls
// ============================================================================

pub const VmEntryControls = packed struct(u32) {
    _reserved1: u2 = 0,
    load_debug_ctls: bool = true,
    _reserved2: u6 = 0,
    ia32e_mode_guest: bool = true,
    entry_to_smm: bool = false,
    deactivate_dual_monitor: bool = false,
    _reserved3: bool = false,
    load_perf_global: bool = false,
    load_pat: bool = true,
    load_efer: bool = true,
    load_bndcfgs: bool = false,
    conceal_from_pt: bool = false,
    load_rtit_ctl: bool = false,
    _reserved4: bool = false,
    load_cet: bool = false,
    load_lbr_ctl: bool = false,
    load_pkrs: bool = false,
    _reserved5: u9 = 0,
};

// ============================================================================
// VM-Exit Reasons
// ============================================================================

pub const VmExitReason = enum(u16) {
    exception_or_nmi = 0,
    external_interrupt = 1,
    triple_fault = 2,
    init_signal = 3,
    sipi = 4,
    smi = 5,
    other_smi = 6,
    interrupt_window = 7,
    nmi_window = 8,
    task_switch = 9,
    cpuid = 10,
    getsec = 11,
    hlt = 12,
    invd = 13,
    invlpg = 14,
    rdpmc = 15,
    rdtsc = 16,
    rsm = 17,
    vmcall = 18,
    vmclear = 19,
    vmlaunch = 20,
    vmptrld = 21,
    vmptrst = 22,
    vmread = 23,
    vmresume = 24,
    vmwrite = 25,
    vmxoff = 26,
    vmxon = 27,
    cr_access = 28,
    dr_access = 29,
    io_instruction = 30,
    rdmsr = 31,
    wrmsr = 32,
    entry_fail_guest = 33,
    entry_fail_msr = 34,
    mwait = 36,
    monitor_trap = 37,
    monitor = 39,
    pause = 40,
    entry_fail_mce = 41,
    tpr_below_threshold = 43,
    apic_access = 44,
    virtualized_eoi = 45,
    gdtr_idtr_access = 46,
    ldtr_tr_access = 47,
    ept_violation = 48,
    ept_misconfiguration = 49,
    invept = 50,
    rdtscp = 51,
    preemption_timer = 52,
    invvpid = 53,
    wbinvd_or_wbnoinvd = 54,
    xsetbv = 55,
    apic_write = 56,
    rdrand = 57,
    invpcid = 58,
    vmfunc = 59,
    encls = 60,
    rdseed = 61,
    pml_full = 62,
    xsaves = 63,
    xrstors = 64,
    spp_related = 66,
    umwait = 67,
    tpause = 68,
    loadiwkey = 69,
    enclv = 70,
    bus_lock = 74,
    notify = 75,
};

// ============================================================================
// VMCS Manager (Zxyphor)
// ============================================================================

pub const VmcsManager = struct {
    vmcs_revision_id: u32,
    vmcs_region_size: u32,
    pin_controls: PinExecControls,
    primary_proc_controls: PrimaryProcExecControls,
    secondary_proc_controls: SecondaryProcExecControls,
    exit_controls: VmExitControls,
    entry_controls: VmEntryControls,
    // Feature availability
    ept_supported: bool,
    vpid_supported: bool,
    unrestricted_guest: bool,
    vmcs_shadowing: bool,
    vmfunc_supported: bool,
    posted_interrupts: bool,
    pml_supported: bool,
    tsc_scaling: bool,
    mode_based_ept: bool,
    // Statistics
    vmentry_count: u64,
    vmexit_count: u64,
    exit_reasons: [76]u64,    // Count per exit reason
    initialized: bool,

    pub fn init(revision_id: u32) VmcsManager {
        var mgr = std.mem.zeroes(VmcsManager);
        mgr.vmcs_revision_id = revision_id;
        mgr.vmcs_region_size = 4096;
        mgr.pin_controls = .{};
        mgr.primary_proc_controls = .{};
        mgr.secondary_proc_controls = .{};
        mgr.exit_controls = .{};
        mgr.entry_controls = .{};
        mgr.initialized = true;
        return mgr;
    }
};
