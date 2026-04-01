// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - AMD SVM (Secure Virtual Machine) and KVM Extensions
// AMD-V SVM, VMCB, nested page tables (NPT), virtual interrupts,
// SEV (Secure Encrypted Virtualization), guest management, VM migration
// More advanced than Linux 2026 KVM/SVM subsystem

const std = @import("std");

// ============================================================================
// SVM MSRs
// ============================================================================

pub const MSR_VM_CR: u32 = 0xC0010114;
pub const MSR_VM_HSAVE_PA: u32 = 0xC0010117;
pub const MSR_SVM_KEY: u32 = 0xC0010118;
pub const MSR_SVM_FEATURES: u32 = 0xC000011F;

// VM_CR bits
pub const VM_CR_DPD: u64 = 1 << 0;
pub const VM_CR_R_INIT: u64 = 1 << 1;
pub const VM_CR_DIS_A20M: u64 = 1 << 2;
pub const VM_CR_LOCK: u64 = 1 << 3;
pub const VM_CR_SVMDIS: u64 = 1 << 4;

// ============================================================================
// CPUID Features for SVM
// ============================================================================

pub const SvmFeatures = packed struct(u32) {
    np: bool = false,              // Nested paging
    lbr_virt: bool = false,        // LBR virtualization
    svm_lock: bool = false,
    nrip_save: bool = false,       // Next RIP save
    tsc_rate_msr: bool = false,    // TSC rate control
    vmcb_clean: bool = false,      // VMCB clean bits
    flush_by_asid: bool = false,
    decode_assists: bool = false,
    pause_filter: bool = false,
    pause_filter_threshold: bool = false,
    avic: bool = false,            // Advanced Virtual Interrupt Controller
    vmsave_virtualize: bool = false,
    vgif: bool = false,            // Virtual GIF
    gmet: bool = false,            // Guest Mode Execute Trap
    x2avic: bool = false,
    sss_check: bool = false,       // Supervisor Shadow Stack check
    v_spec_ctrl: bool = false,     // Virtual SPEC_CTRL
    rogpt: bool = false,           // Read-Only Guest Page Table
    host_mce_override: bool = false,
    tlbictl: bool = false,         // TLBI control
    vnmi: bool = false,            // Virtual NMI
    ibs_virt: bool = false,        // IBS virtualization
    ext_lvt_offset_fault_chg: bool = false,
    svm_ctl_vmsave: bool = false,
    // Zxyphor
    zxy_fast_vmcb: bool = false,
    _reserved: u7 = 0,
};

// ============================================================================
// VMCB (Virtual Machine Control Block)
// ============================================================================

// VMCB Control Area (offset 0x000 - 0x3FF)
pub const VmcbControlArea = struct {
    // Intercepts
    intercept_cr_read: u32,        // CR0-15 read intercepts
    intercept_cr_write: u32,       // CR0-15 write intercepts
    intercept_dr_read: u32,        // DR0-15 read intercepts
    intercept_dr_write: u32,       // DR0-15 write intercepts
    intercept_exceptions: u32,     // Exception intercepts
    // Misc intercepts
    intercept_misc1: VmcbIntercept1,
    intercept_misc2: VmcbIntercept2,
    intercept_misc3: VmcbIntercept3,
    // Reserved: 0x018 - 0x03B
    // Pause filter
    pause_filter_threshold: u16,
    pause_filter_count: u16,
    // IOPM/MSRPM
    iopm_base_pa: u64,           // I/O Permission Map physical address
    msrpm_base_pa: u64,          // MSR Permission Map physical address
    // TSC
    tsc_offset: i64,             // TSC offset
    // Guest ASID
    guest_asid: u32,
    // TLB control
    tlb_control: TlbControl,
    // Virtual interrupts
    v_tpr: u8,                   // Virtual Task Priority Register
    v_irq: bool,                 // Virtual IRQ pending
    v_vgif: bool,                // Virtual GIF value
    v_intr_prio: u4,            // Virtual interrupt priority
    v_ign_tpr: bool,            // Ignore TPR
    v_intr_masking: bool,       // Virtualize EFLAGS.IF
    v_gif_enable: bool,         // Virtual GIF enable
    avic_enable: bool,          // AVIC enable
    v_intr_vector: u8,          // Virtual interrupt vector
    x2avic_enable: bool,
    // Interrupt shadow
    interrupt_shadow: bool,
    // EXITCODE
    exit_code: SvmExitCode,
    exit_info_1: u64,
    exit_info_2: u64,
    exit_int_info: u64,         // Intercepted exception/interrupt info
    // NP
    np_enable: bool,             // Nested paging enable
    sev_enable: bool,            // SEV
    sev_es_enable: bool,         // SEV-ES
    sev_snp_enable: bool,        // SEV-SNP
    gmet_enable: bool,           // Guest Mode Execute Trap
    sss_check_enable: bool,
    vte_enable: bool,            // Virtual Transparent Encryption
    rogpt_enable: bool,
    // Virtual VMLOAD/VMSAVE
    virtual_vmload_vmsave: bool,
    // Event injection
    event_inject: VmcbEventInject,
    // Nested page table
    n_cr3: u64,                  // Nested CR3
    // LBR
    lbr_virtualization_enable: bool,
    // VMCB clean bits
    vmcb_clean: VmcbCleanBits,
    // Next RIP
    nrip: u64,                  // Next sequential instruction pointer
    // Fetch info
    guest_instruction_bytes: [15]u8,
    nr_guest_instruction_bytes: u4,
    // AVIC
    avic_apic_backing_page_ptr: u64,
    avic_logical_table_ptr: u64,
    avic_physical_table_ptr: u64,
    vmsa_ptr: u64,               // SEV-ES VMSA pointer
    // VMGEXIT
    vmgexit_rax: u64,
    vmgexit_cpl: u8,
};

pub const VmcbIntercept1 = packed struct(u32) {
    intr: bool = false,
    nmi: bool = false,
    smi: bool = false,
    init: bool = false,
    vintr: bool = false,
    cr0_sel_write: bool = false,
    idtr_read: bool = false,
    gdtr_read: bool = false,
    ldtr_read: bool = false,
    tr_read: bool = false,
    idtr_write: bool = false,
    gdtr_write: bool = false,
    ldtr_write: bool = false,
    tr_write: bool = false,
    rdtsc: bool = false,
    rdpmc: bool = false,
    pushf: bool = false,
    popf: bool = false,
    cpuid: bool = false,
    rsm: bool = false,
    iret: bool = false,
    int_n: bool = false,
    invd: bool = false,
    pause: bool = false,
    hlt: bool = false,
    invlpg: bool = false,
    invlpga: bool = false,
    ioio: bool = false,
    msr: bool = false,
    task_switch: bool = false,
    ferr_freeze: bool = false,
    shutdown: bool = false,
};

pub const VmcbIntercept2 = packed struct(u32) {
    vmrun: bool = false,
    vmmcall: bool = false,
    vmload: bool = false,
    vmsave: bool = false,
    stgi: bool = false,
    clgi: bool = false,
    skinit: bool = false,
    rdtscp: bool = false,
    icebp: bool = false,
    wbinvd: bool = false,
    monitor: bool = false,
    mwait_uncond: bool = false,
    mwait_armed: bool = false,
    xsetbv: bool = false,
    rdpru: bool = false,
    efer_write_trap: bool = false,
    cr_write_after_trap: u16 = 0,
};

pub const VmcbIntercept3 = packed struct(u32) {
    invlpgb: bool = false,
    invlpgb_illegal: bool = false,
    invpcid: bool = false,
    mcommit: bool = false,
    tlbsync: bool = false,
    _reserved: u27 = 0,
};

pub const VmcbCleanBits = packed struct(u32) {
    intercepts: bool = false,     // Intercept vectors
    iopm: bool = false,           // IOPM_BASE, MSRPM_BASE
    asid: bool = false,           // ASID
    tpr: bool = false,            // V_TPR, V_IRQ, etc.
    np: bool = false,             // Nested paging
    crx: bool = false,            // CR0, CR3, CR4, EFER
    drx: bool = false,            // DR6, DR7
    dt: bool = false,             // GDT, IDT
    seg: bool = false,            // CS, DS, SS, ES, CPL
    cr2: bool = false,            // CR2
    lbr: bool = false,            // DBGCTL, BR_FROM, BR_TO, LAST*
    avic: bool = false,           // AVIC pointers
    cet: bool = false,            // CET state
    _reserved: u19 = 0,
};

pub const TlbControl = enum(u8) {
    do_nothing = 0,
    flush_all = 1,
    flush_guest = 3,
    flush_guest_nonglobal = 7,
};

// ============================================================================
// SVM Exit Codes
// ============================================================================

pub const SvmExitCode = enum(u64) {
    // CR access
    read_cr0 = 0x000,
    read_cr2 = 0x002,
    read_cr3 = 0x003,
    read_cr4 = 0x004,
    read_cr8 = 0x008,
    write_cr0 = 0x010,
    write_cr2 = 0x012,
    write_cr3 = 0x013,
    write_cr4 = 0x014,
    write_cr8 = 0x018,
    // DR access
    read_dr0 = 0x020,
    read_dr7 = 0x027,
    write_dr0 = 0x030,
    write_dr7 = 0x037,
    // Exception intercepts
    excp_de = 0x040,
    excp_db = 0x041,
    excp_bp = 0x043,
    excp_of = 0x044,
    excp_ud = 0x046,
    excp_nm = 0x047,
    excp_df = 0x048,
    excp_ts = 0x04A,
    excp_np = 0x04B,
    excp_ss = 0x04C,
    excp_gp = 0x04D,
    excp_pf = 0x04E,
    excp_mf = 0x050,
    excp_ac = 0x051,
    excp_mc = 0x052,
    excp_xf = 0x053,
    // Intercepts
    intr = 0x060,
    nmi = 0x061,
    smi = 0x062,
    init = 0x063,
    vintr = 0x064,
    cr0_sel_write = 0x065,
    idtr_read = 0x066,
    gdtr_read = 0x067,
    ldtr_read = 0x068,
    tr_read = 0x069,
    idtr_write = 0x06A,
    gdtr_write = 0x06B,
    ldtr_write = 0x06C,
    tr_write = 0x06D,
    rdtsc = 0x06E,
    rdpmc = 0x06F,
    pushf = 0x070,
    popf = 0x071,
    cpuid = 0x072,
    rsm = 0x073,
    iret = 0x074,
    swint = 0x075,
    invd = 0x076,
    pause = 0x077,
    hlt = 0x078,
    invlpg = 0x079,
    invlpga = 0x07A,
    ioio = 0x07B,
    msr = 0x07C,
    task_switch = 0x07D,
    ferr_freeze = 0x07E,
    shutdown = 0x07F,
    vmrun = 0x080,
    vmmcall = 0x081,
    vmload = 0x082,
    vmsave = 0x083,
    stgi = 0x084,
    clgi = 0x085,
    skinit = 0x086,
    rdtscp = 0x087,
    icebp = 0x088,
    wbinvd = 0x089,
    monitor = 0x08A,
    mwait = 0x08B,
    mwait_armed = 0x08C,
    xsetbv = 0x08D,
    rdpru = 0x08E,
    efer_write_trap = 0x08F,
    invlpgb = 0x0A0,
    invpcid = 0x0A2,
    mcommit = 0x0A3,
    tlbsync = 0x0A4,
    // NPF
    npf = 0x400,                 // Nested Page Fault
    // AVIC
    avic_incomplete_ipi = 0x401,
    avic_noaccel = 0x402,
    // VMGEXIT
    vmgexit = 0x403,
    // SEV-SNP
    busy = 0x404,
    // Invalid
    invalid = 0xFFFFFFFFFFFFFFFF,
};

// ============================================================================
// VMCB Event Injection
// ============================================================================

pub const VmcbEventType = enum(u3) {
    intr = 0,
    nmi = 2,
    exception = 3,
    software_int = 4,
};

pub const VmcbEventInject = packed struct(u64) {
    vector: u8 = 0,
    event_type: u3 = 0,
    ev: bool = false,            // Error code valid
    _reserved1: u19 = 0,
    v: bool = false,             // Valid
    error_code: u32 = 0,
};

// ============================================================================
// VMCB Save Area (Guest State)
// ============================================================================

pub const VmcbSaveArea = struct {
    // Segment registers
    es: VmcbSegment,
    cs: VmcbSegment,
    ss: VmcbSegment,
    ds: VmcbSegment,
    fs: VmcbSegment,
    gs: VmcbSegment,
    gdtr: VmcbSegment,
    ldtr: VmcbSegment,
    idtr: VmcbSegment,
    tr: VmcbSegment,
    // Control registers
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    // Debug registers
    dr6: u64,
    dr7: u64,
    // EFLAGS
    rflags: u64,
    // RIP
    rip: u64,
    // RSP
    rsp: u64,
    // S_CET, SSP, ISST_ADDR (CET)
    s_cet: u64,
    ssp: u64,
    isst_addr: u64,
    // RAX
    rax: u64,
    // STAR, LSTAR, CSTAR, SFMASK (SYSCALL/SYSRET)
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    // Kernel GS base
    kernel_gs_base: u64,
    // SYSENTER
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    // CR2
    cr2_actual: u64,
    // PAT
    g_pat: u64,
    // Debug control
    dbgctl: u64,
    br_from: u64,
    br_to: u64,
    last_excp_from: u64,
    last_excp_to: u64,
    // Speculation control
    spec_ctrl: u64,
    // SEV
    guest_tsc_aux: u64,
};

pub const VmcbSegment = struct {
    selector: u16,
    attrib: u16,
    limit: u32,
    base: u64,
};

// ============================================================================
// Nested Page Tables (NPT)
// ============================================================================

pub const NptEntry = packed struct(u64) {
    present: bool = false,
    writable: bool = false,
    user: bool = false,
    pwt: bool = false,
    pcd: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    large_page: bool = false,
    global: bool = false,
    _avl1: u3 = 0,
    pfn: u40 = 0,
    _avl2: u7 = 0,
    _pke: u4 = 0,
    nx: bool = false,

    pub fn address(self: NptEntry) u64 {
        return @as(u64, self.pfn) << 12;
    }

    pub fn set_address(self: *NptEntry, addr: u64) void {
        self.pfn = @truncate(addr >> 12);
    }
};

pub const NptPageTableLevel = enum(u3) {
    pml4 = 4,   // 512 GB
    pdpt = 3,   // 1 GB
    pd = 2,     // 2 MB
    pt = 1,     // 4 KB
};

pub const NptStats = struct {
    nr_pages_allocated: u64,
    nr_large_pages: u64,
    npf_count: u64,
    npf_total_ns: u64,
    page_splits: u64,
    page_merges: u64,
};

// ============================================================================
// SEV (Secure Encrypted Virtualization)
// ============================================================================

pub const SevGeneration = enum(u8) {
    none = 0,
    sev = 1,
    sev_es = 2,        // Encrypted State
    sev_snp = 3,       // Secure Nested Paging
    sev_snp_v2 = 4,    // Future
};

pub const SevAsid = struct {
    asid: u32,
    generation: SevGeneration,
    handle: u32,
    // Key
    policy: u32,
    // Migration
    can_migrate: bool,
};

pub const SevSnpPageType = enum(u8) {
    normal = 0,
    vmsa = 1,
    zero = 2,
    unmeasured = 3,
    secrets = 4,
    cpuid = 5,
};

pub const SevSnpPolicy = packed struct(u64) {
    abi_minor: u8 = 0,
    abi_major: u8 = 0,
    smt: bool = false,           // Allow SMT
    _reserved1: u1 = 0,
    migrate_ma: bool = false,    // Migration allowed
    debug: bool = false,         // Debug allowed
    single_socket: bool = false,
    _reserved2: u43 = 0,
};

pub const SevSnpGuestInfo = struct {
    policy: SevSnpPolicy,
    family_id: [16]u8,
    image_id: [16]u8,
    vmpl: u8,
    signature_algo: u32,
    platform_version: u64,
    // Attestation
    report_data: [64]u8,
    measurement: [48]u8,
    host_data: [32]u8,
    id_key_digest: [48]u8,
    author_key_digest: [48]u8,
};

// ============================================================================
// AVIC (Advanced Virtual Interrupt Controller)
// ============================================================================

pub const AvicPhysicalApicEntry = packed struct(u64) {
    host_physical_apicid: u8 = 0,
    _reserved1: u4 = 0,
    backing_page_pfn: u40 = 0,
    _reserved2: u10 = 0,
    is_running: bool = false,
    valid: bool = false,
};

pub const AvicLogicalApicEntry = packed struct(u32) {
    guest_physical_id: u8 = 0,
    _reserved: u23 = 0,
    valid: bool = false,
};

// ============================================================================
// SVM vCPU State
// ============================================================================

pub const SvmVcpuState = struct {
    // VMCB
    vmcb_pa: u64,                // Physical address of VMCB
    vmcb_gpa: u64,               // For nested SVM
    // Host save area
    host_save_pa: u64,
    // ASID
    asid: u32,
    asid_generation: u64,
    // Features
    features: SvmFeatures,
    // NPT
    npt_cr3: u64,
    npt_enabled: bool,
    npt_stats: NptStats,
    // SEV
    sev_gen: SevGeneration,
    sev_asid: u32,
    sev_handle: u32,
    // AVIC
    avic_enabled: bool,
    // vGIF
    vgif_enabled: bool,
    // Pause filter
    pause_filter_enabled: bool,
    pause_count: u64,
    // Stats
    vmrun_count: u64,
    vmexit_count: u64,
    total_guest_ns: u64,
    total_host_ns: u64,
    // Last exit
    last_exit_code: SvmExitCode,
    last_exit_info1: u64,
    last_exit_info2: u64,
    last_exit_ns: u64,
    // Nested SVM
    nested_enabled: bool,
    nested_vmcb_pa: u64,
    nested_vmcb_gpa: u64,
    nested_npt_cr3: u64,
    nested_int_ctl: u64,
    nested_depth: u8,
};

// ============================================================================
// SVM Subsystem
// ============================================================================

pub const SvmSubsystem = struct {
    // Capabilities
    svm_supported: bool,
    features: SvmFeatures,
    sev_supported: bool,
    sev_es_supported: bool,
    sev_snp_supported: bool,
    max_asid: u32,
    nr_asids_available: u32,
    // Active VMs
    nr_vcpus: u32,
    nr_vms: u32,
    // SEV
    sev_asid_count: u32,
    sev_es_asid_count: u32,
    // Performance
    total_vmruns: u64,
    total_vmexits: u64,
    total_npfs: u64,
    total_guest_ns: u64,
    // Exit stats
    exit_cr_access: u64,
    exit_msr_access: u64,
    exit_io: u64,
    exit_cpuid: u64,
    exit_hlt: u64,
    exit_npf: u64,
    exit_vmmcall: u64,
    exit_shutdown: u64,
    exit_avic_incomplete: u64,
    exit_avic_noaccel: u64,
    exit_vmgexit: u64,
    // Zxyphor
    zxy_fast_context_switch: bool,
    zxy_predictive_exit: bool,
    initialized: bool,
};
