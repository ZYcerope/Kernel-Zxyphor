// SPDX-License-Identifier: MIT
// Zxyphor Kernel - SGX (Software Guard Extensions), TDX (Trust Domain Extensions),
// Intel CET (Control-flow Enforcement Technology), SME/SEV (AMD),
// TSX (Transactional Synchronization Extensions), Microcode Update
// More advanced than Linux 2026 x86_64 security features

const std = @import("std");

// ============================================================================
// Intel SGX (Software Guard Extensions)
// ============================================================================

/// SGX enclave memory types
pub const SgxPageType = enum(u8) {
    secs = 0x00, // SGX Enclave Control Structure
    tcs = 0x01, // Thread Control Structure
    reg = 0x02, // Regular page
    va = 0x03, // Version Array
    trim = 0x04, // Trimmed
    restrict = 0x05, // Restricted (SGX2)
};

/// SGX page flags
pub const SgxPageFlags = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    pending: bool = false,
    modified: bool = false,
    pr: bool = false, // Permission restriction
    _padding: u2 = 0,
};

/// SGX SECS (enclave control structure)
pub const SgxSecs = struct {
    size: u64,
    base_addr: u64,
    ssa_frame_size: u32,
    misc_select: u32,
    _reserved1: [24]u8,
    attributes: SgxAttributes,
    mr_enclave: [32]u8, // Measurement
    _reserved2: [32]u8,
    mr_signer: [32]u8, // Signer measurement
    _reserved3: [96]u8,
    isv_prod_id: u16,
    isv_svn: u16,
    _reserved4: [3836]u8,
};

/// SGX attributes
pub const SgxAttributes = packed struct {
    initted: bool = false,
    debug: bool = false,
    mode64bit: bool = false,
    _reserved1: bool = false,
    provision_key: bool = false,
    einit_token_key: bool = false,
    cet: bool = false,
    kss: bool = false,
    _reserved2: u56 = 0,
    xfrm: u64 = 0x03, // XSAVE features
};

/// SGX TCS (Thread Control Structure)
pub const SgxTcs = struct {
    _reserved1: u64,
    flags: u64,
    ossa: u64, // Offset of SSA
    cssa: u32, // Current SSA slot
    nssa: u32, // Number of SSA slots
    oentry: u64, // Entry offset
    _reserved2: u64,
    ofs_base: u64,
    ogs_base: u64,
    ofs_limit: u32,
    ogs_limit: u32,
    _reserved3: [4024]u8,
};

/// SGX enclave info
pub const SgxEnclaveInfo = struct {
    base: u64,
    size: u64,
    flags: u64,
    secs_phys: u64,
    // Pages
    nr_pages: u64,
    nr_epc_pages: u64,
    // State
    initialized: bool,
    debug: bool,
    // EPC section
    epc_section_idx: u32,
    // Backing pages (swap support)
    nr_backing: u64,
    // SGX2 features
    sgx2_enabled: bool,
};

/// EPC (Enclave Page Cache) section
pub const SgxEpcSection = struct {
    phys_addr: u64,
    size: u64,
    nr_pages: u64,
    nr_free: u64,
    nr_used: u64,
    // NUMA node
    nid: u32,
};

/// SGX ioctl commands
pub const SgxIoctl = enum(u32) {
    enclave_create = 0,
    enclave_add_pages = 1,
    enclave_init = 2,
    enclave_provision = 3,
    enclave_restrict_permissions = 4,
    enclave_modify_types = 5,
    enclave_remove_pages = 6,
};

/// SGX key request
pub const SgxKeyRequest = struct {
    key_name: SgxKeyName,
    key_policy: u16,
    isv_svn: u16,
    _reserved1: u16,
    cpu_svn: [16]u8,
    attribute_mask: SgxAttributes,
    key_id: [32]u8,
    misc_mask: u32,
    config_svn: u16,
    _reserved2: [434]u8,
};

/// SGX key names
pub const SgxKeyName = enum(u16) {
    launch_key = 0,
    provision_key = 1,
    provision_seal_key = 2,
    report_key = 3,
    seal_key = 4,
};

// ============================================================================
// Intel TDX (Trust Domain Extensions)
// ============================================================================

/// TDX module status
pub const TdxModuleStatus = enum(u8) {
    not_loaded = 0,
    initialized = 1,
    configured = 2,
    ready = 3,
    shutdown = 4,
};

/// TDX guest attributes
pub const TdxAttributes = packed struct {
    debug: bool = false,
    // Bits 1-24 reserved
    _reserved1: u24 = 0,
    sept_ve_disable: bool = false,
    // Bits 26-27 reserved
    _reserved2: u2 = 0,
    pks: bool = false,
    kl: bool = false, // Key Locker
    tpa: bool = false, // TDX partial-write
    perfmon: bool = false,
    _reserved3: u32 = 0,
};

/// TDX TD (Trust Domain) info
pub const TdxTdInfo = struct {
    attributes: TdxAttributes,
    xfam: u64, // Extended Features Available Mask
    mr_td: [48]u8, // TD Measurement
    mr_config_id: [48]u8,
    mr_owner: [48]u8,
    mr_owner_config: [48]u8,
    // RTMR (Runtime Measurement Registers)
    rtmr: [4][48]u8,
    // Servtd hash
    servtd_hash: [4][48]u8,
};

/// TDX TDCALL leaf functions
pub const TdcallLeaf = enum(u64) {
    vp_vmcall = 0,
    vp_info = 1,
    mr_rtmr_extend = 2,
    vp_veinfo_get = 3,
    mr_report = 4,
    vp_cpuidve_set = 5,
    mem_page_accept = 6,
    mem_page_attr_rd = 23,
    mem_page_attr_wr = 24,
    vm_rd = 7,
    vm_wr = 8,
};

/// TDX SEAMCALL leaf functions (host-side)
pub const SeamcallLeaf = enum(u64) {
    tdhmnginit = 0,
    tdhvpcreate = 1,
    tdhmngaddcx = 2,
    tdhmempageadd = 3,
    tdhmemseptagg = 4,
    tdhmrfinalize = 5,
    tdhvpinit = 6,
    tdhvpenter = 7,
    tdhvprdwr = 8,
    tdhmngkeycfg = 9,
    tdhmngcreate = 10,
    tdhmempageaug = 11,
    tdhphymemcachewb = 12,
    tdhsysconfigure = 13,
    tdhsysinit = 14,
    tdhsysrdall = 15,
    tdhsyskeyconfig = 16,
    tdhsysinitlp = 17,
    tdhmemtrackglobally = 18,
    tdhmemseptremove = 19,
    tdhmempageremove = 20,
    tdhservetdbind = 21,
};

// ============================================================================
// Intel CET (Control-flow Enforcement Technology)
// ============================================================================

/// CET features
pub const CetFeatures = packed struct {
    shstk_en: bool = false, // Shadow stack enable
    wr_shstk_en: bool = false, // Writes to shadow stack pages
    endbr_en: bool = false, // ENDBRANCH enforcement (IBT)
    leg_iw_en: bool = false, // Legacy interworking enable
    no_track_en: bool = false, // NOTRACK prefix support
    suppress: bool = false, // Suppress #CP for far transfers
    _reserved: u2 = 0,
    tracker: CetTrackerState, // TRACKER state (for IBT)
    _padding: u6 = 0,
};

/// CET tracker state
pub const CetTrackerState = enum(u2) {
    idle = 0,
    wait_endbr = 1,
};

/// Shadow stack token
pub const ShadowStackToken = struct {
    linear_addr: u64, // Linear address stored on shadow stack
    flags: ShadowStackTokenFlags,
};

pub const ShadowStackTokenFlags = packed struct {
    busy: bool = false,
    mode: u1 = 0, // 0=supervisor, 1=user
    _reserved: u62 = 0,
};

/// CET user state (per-thread)
pub const CetUserState = struct {
    shstk_enabled: bool,
    ibt_enabled: bool,
    shstk_base: u64,
    shstk_size: u64,
    ssp: u64, // Shadow Stack Pointer
    // For signal delivery
    shstk_token: u64,
};

// ============================================================================
// AMD SME/SEV (Secure Memory Encryption / Secure Encrypted Virtualization)
// ============================================================================

/// SME features
pub const SmeFeatures = packed struct {
    sme: bool = false,
    sev: bool = false,
    page_flush_msr: bool = false,
    sev_es: bool = false,
    sev_snp: bool = false,
    vmpl: bool = false,
    rmpquery: bool = false,
    vm_perm_levels: bool = false,
    sss_check: bool = false,
    v_tsc_aux: bool = false,
    debug_swap: bool = false,
    _padding: u5 = 0,
};

/// SEV type
pub const SevType = enum(u8) {
    none = 0,
    sev = 1,
    sev_es = 2, // Encrypted State
    sev_snp = 3, // Secure Nested Paging
};

/// SEV-SNP page state
pub const SnpPageState = enum(u8) {
    private = 1,
    shared = 2,
    firmware = 3,
    reclaim = 4,
    psmash = 5,
    unsmash = 6,
};

/// RMP (Reverse Map Table) entry
pub const RmpEntry = struct {
    gpa: u64, // Guest Physical Address
    asid: u32, // Address Space ID
    vmpl: u8, // VM Permission Level (0-3)
    page_size: u8, // 0=4KB, 1=2MB
    validated: bool,
    assigned: bool,
    immutable: bool,
};

/// SEV-SNP GHCB (Guest-Hypervisor Communication Block) protocol
pub const GhcbMsrProtocol = enum(u12) {
    info_req = 0x001,
    info_resp = 0x002,
    cpuid_req = 0x004,
    cpuid_resp = 0x005,
    pref_ghcb_gpa_req = 0x010,
    pref_ghcb_gpa_resp = 0x011,
    reg_ghcb_gpa_req = 0x012,
    reg_ghcb_gpa_resp = 0x013,
    psc_req = 0x014,
    psc_resp = 0x015,
    snp_run_vmpl_req = 0x016,
    snp_run_vmpl_resp = 0x017,
    hv_features_req = 0x080,
    hv_features_resp = 0x081,
    termination_req = 0x100,
};

/// SEV-SNP attestation report
pub const SnpAttestationReport = struct {
    version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: [16]u8,
    image_id: [16]u8,
    vmpl: u32,
    signature_algo: u32,
    platform_version: u64,
    platform_info: u64,
    flags: u32,
    _reserved1: u32,
    report_data: [64]u8,
    measurement: [48]u8,
    host_data: [32]u8,
    id_key_digest: [48]u8,
    author_key_digest: [48]u8,
    report_id: [32]u8,
    report_id_ma: [32]u8,
    reported_tcb: u64,
    _reserved2: [24]u8,
    chip_id: [64]u8,
    committed_tcb: u64,
    current_build: u8,
    current_minor: u8,
    current_major: u8,
    _reserved3: u8,
    committed_build: u8,
    committed_minor: u8,
    committed_major: u8,
    _reserved4: u8,
    launch_tcb: u64,
    _reserved5: [168]u8,
    signature: [512]u8,
};

// ============================================================================
// Microcode Update
// ============================================================================

/// Microcode header (Intel)
pub const IntelMicrocodeHeader = struct {
    header_version: u32,
    update_revision: u32,
    date: u32, // BCD format MMDDYYYY
    processor_signature: u32, // CPUID
    checksum: u32,
    loader_revision: u32,
    processor_flags: u32,
    data_size: u32,
    total_size: u32,
    _reserved: [12]u8,
};

/// AMD microcode header
pub const AmdMicrocodeHeader = struct {
    data_code: u32,
    patch_id: u32,
    mc_patch_data_id: u16,
    mc_patch_data_len: u8,
    init_flag: u8,
    mc_patch_data_checksum: u32,
    nb_dev_id: u32,
    sb_dev_id: u32,
    processor_rev_id: u16,
    nb_rev_id: u8,
    sb_rev_id: u8,
    bios_api_rev: u8,
    _reserved: [3]u8,
    match_reg: [8]u32,
};

/// Microcode update result
pub const MicrocodeResult = enum(u8) {
    success = 0,
    not_found = 1,
    revision_not_newer = 2,
    signature_mismatch = 3,
    checksum_error = 4,
    load_error = 5,
    // Early load
    early_load_success = 10,
    early_load_fail = 11,
};

/// CPU microcode info
pub const CpuMicrocodeInfo = struct {
    cpu: u32,
    // Intel: CPUID signature, AMD: Family/Model/Stepping
    sig: u32,
    pf: u32,
    rev: u32,
    // Dates
    date: u32,
    // Loaded from
    source: MicrocodeSource,
};

/// Microcode source
pub const MicrocodeSource = enum(u8) {
    none = 0,
    early_initrd = 1, // Early load from initrd
    late_firmware = 2, // Late load from firmware
    late_manual = 3, // Manual late load
    builtin = 4, // Built into kernel
};

// ============================================================================
// TSX (Transactional Synchronization Extensions)
// ============================================================================

/// TSX state
pub const TsxState = enum(u8) {
    disabled = 0,
    enabled = 1,
    force_abort = 2, // RTM always aborts
};

/// RTM abort status bits
pub const RtmAbortStatus = packed struct {
    explicit: bool = false, // XABORT instruction
    retry: bool = false, // May succeed on retry
    conflict: bool = false, // Data conflict
    overflow: bool = false, // Internal buffer overflow
    breakpoint: bool = false, // Debug breakpoint hit
    nested: bool = false, // In nested transaction
    _reserved: u2 = 0,
    xabort_arg: u8 = 0, // XABORT argument
    _padding: u16 = 0,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const X64SecuritySubsystem = struct {
    // SGX
    sgx_enabled: bool,
    sgx_version: u8, // 1 or 2
    nr_epc_sections: u32,
    total_epc_bytes: u64,
    nr_enclaves: u64,
    nr_epc_pages_used: u64,
    // TDX
    tdx_enabled: bool,
    tdx_module_status: TdxModuleStatus,
    nr_tds: u32,
    // CET
    cet_shstk_enabled: bool,
    cet_ibt_enabled: bool,
    // SME/SEV
    sme_enabled: bool,
    sev_type: SevType,
    nr_sev_guests: u32,
    // Microcode
    microcode_revision: u32,
    microcode_date: u32,
    microcode_source: MicrocodeSource,
    // TSX
    tsx_state: TsxState,
    tsx_abort_count: u64,
    // Zxyphor
    zxy_hw_isolation: bool,
    initialized: bool,

    pub fn init() X64SecuritySubsystem {
        return X64SecuritySubsystem{
            .sgx_enabled = false,
            .sgx_version = 0,
            .nr_epc_sections = 0,
            .total_epc_bytes = 0,
            .nr_enclaves = 0,
            .nr_epc_pages_used = 0,
            .tdx_enabled = false,
            .tdx_module_status = .not_loaded,
            .nr_tds = 0,
            .cet_shstk_enabled = false,
            .cet_ibt_enabled = false,
            .sme_enabled = false,
            .sev_type = .none,
            .nr_sev_guests = 0,
            .microcode_revision = 0,
            .microcode_date = 0,
            .microcode_source = .none,
            .tsx_state = .disabled,
            .tsx_abort_count = 0,
            .zxy_hw_isolation = true,
            .initialized = false,
        };
    }
};
