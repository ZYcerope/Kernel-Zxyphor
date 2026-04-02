// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - AMD SEV/SNP & Intel TDX Guest Support
// Confidential computing: SEV, SEV-ES, SEV-SNP, TDX guest,
// Attestation, GHCB protocol, VMPL, page validation, remote attestation

const std = @import("std");

// ============================================================================
// SEV Generation
// ============================================================================

pub const SevGeneration = enum(u8) {
    None = 0,
    Sev = 1,        // Basic encryption
    SevEs = 2,      // Encrypted state
    SevSnp = 3,     // Secure nested paging
};

pub const SevStatus = packed struct(u64) {
    sev_enabled: bool,
    sev_es_enabled: bool,
    sev_snp_enabled: bool,
    vtom: bool,
    reflect_vc: bool,
    restricted_injection: bool,
    alternate_injection: bool,
    debug_swap: bool,
    prevent_host_ibs: bool,
    snp_bti: bool,
    vmpl_sss: bool,
    secure_tsc: bool,
    vmgexit_parameter: bool,
    _reserved1: u1,
    ibs_virt: bool,
    _reserved2: u1,
    vmsa_reg_prot: bool,
    smt_protection: bool,
    _reserved3: u46,
};

// ============================================================================
// GHCB (Guest-Hypervisor Communication Block)
// ============================================================================

pub const GHCB_PROTOCOL_MIN = 1;
pub const GHCB_PROTOCOL_MAX = 2;
pub const GHCB_DEFAULT_USAGE = 0;

pub const GhcbExitCode = enum(u64) {
    Read_DR0 = 0x000,
    Read_DR7 = 0x007,
    Write_DR0 = 0x010,
    Write_DR7 = 0x017,
    Excp_DE = 0x040,
    Excp_DB = 0x041,
    Excp_BP = 0x043,
    Excp_UD = 0x046,
    Excp_GP = 0x04d,
    Excp_PF = 0x04e,
    Excp_MC = 0x052,
    Intr = 0x060,
    Nmi = 0x061,
    Smi = 0x062,
    Init = 0x063,
    Vintr = 0x064,
    Cr0_Read = 0x065,
    Cr4_Read = 0x068,
    Cr8_Read = 0x069,
    Cr0_Write = 0x075,
    Cr4_Write = 0x078,
    Cr8_Write = 0x079,
    Invlpg = 0x06b,
    Invlpga = 0x06c,
    IoRead = 0x07b,
    IoWrite = 0x07c,
    Msr = 0x07c,
    TaskSwitch = 0x07e,
    FerRound = 0x07f,
    Shutdown = 0x07f,
    Vmgexit = 0x081,
    Rdtsc = 0x06e,
    Rdpmc = 0x06f,
    Cpuid = 0x072,
    Rsm = 0x073,
    Iret = 0x074,
    Swint = 0x075,
    Rdtscp = 0x087,
    Wbinvd = 0x089,
    MonitorTrap = 0x090,
    Busy = 0x0a0,
    SevSnpGuestReq = 0x080000011,
    SevSnpExtGuestReq = 0x080000012,
    SevSnpApCreate = 0x080000013,
    SevSnpRunVmpl = 0x080000018,
    UnsupportedEvent = 0x8000FFFF,
};

pub const GhcbSaveArea = struct {
    reserved_0: [203]u8,
    cpl: u8,
    reserved_1: [116]u8,
    rax: u64,
    reserved_2: [264]u8,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved_3: [8]u8,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    reserved_4: [16]u8,
    sw_exit_code: u64,
    sw_exit_info_1: u64,
    sw_exit_info_2: u64,
    sw_scratch: u64,
    reserved_5: [56]u8,
    xcr0: u64,
    valid_bitmap: [16]u8,
    x87_state_gpa: u64,
    reserved_6: [1016]u8,
};

pub const Ghcb = struct {
    save: GhcbSaveArea,
    shared_buffer: [2032]u8,
    reserved: [10]u8,
    protocol_version: u16,
    ghcb_usage: u32,
};

// ============================================================================
// SNP Guest Request
// ============================================================================

pub const SnpGuestMsgType = enum(u8) {
    Invalid = 0,
    CpuidReq = 1,
    CpuidRsp = 2,
    KeyReq = 3,
    KeyRsp = 4,
    ReportReq = 5,
    ReportRsp = 6,
    ExportReq = 7,
    ExportRsp = 8,
    ImportReq = 9,
    ImportRsp = 10,
    AbsorbReq = 11,
    AbsorbRsp = 12,
    VmpckReq = 13,
    VmpckRsp = 14,
    TscInfoReq = 17,
    TscInfoRsp = 18,
};

pub const SnpGuestMsgHdr = struct {
    authtag: [32]u8,
    msg_seqno: u64,
    _reserved1: [8]u8,
    algo: u8,             // AEAD algorithm
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: SnpGuestMsgType,
    msg_version: u8,
    msg_sz: u16,
    _reserved2: [4]u8,
    msg_vmpck: u8,        // VMPCK index (0-3)
    _reserved3: [35]u8,
};

pub const SnpAttestationReport = struct {
    version: u32,
    guest_svn: u32,
    policy: SnpGuestPolicy,
    family_id: [16]u8,
    image_id: [16]u8,
    vmpl: u32,
    signature_algo: u32,
    platform_version: u64,
    platform_info: u64,
    author_key_en: u32,
    _reserved1: u32,
    report_data: [64]u8,   // User-provided 512-bit nonce
    measurement: [48]u8,   // 384-bit launch measurement
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
    signature: [512]u8,    // ECDSA P-384 signature
};

pub const SnpGuestPolicy = packed struct(u64) {
    abi_minor: u8,
    abi_major: u8,
    smt_allowed: bool,
    _reserved1: u1,
    migrate_ma: bool,
    debug_allowed: bool,
    single_socket: bool,
    cxl_allowed: bool,
    mem_aes_256_xts: bool,
    rapl_dis: bool,
    cipher_aes_256_gcm: bool,
    _reserved2: u47,
};

pub const SnpPageState = enum(u8) {
    Private = 1,
    Shared = 2,
    Firmware = 3,
};

pub const VMPL_MAX = 4;
pub const VmplLevel = enum(u2) {
    Vmpl0 = 0,   // Most privileged (firmware)
    Vmpl1 = 1,
    Vmpl2 = 2,
    Vmpl3 = 3,   // Guest OS typically
};

pub const VmplPermissions = packed struct(u8) {
    read: bool,
    write: bool,
    execute_user: bool,
    execute_supervisor: bool,
    _reserved: u4,
};

// ============================================================================
// Intel TDX (Trust Domain Extensions)
// ============================================================================

pub const TdxModuleVersion = struct {
    major: u16,
    minor: u16,
    build: u16,
    patch: u16,
};

pub const TdCallLeaf = enum(u64) {
    TdgVpVmcall = 0,
    TdgVpInfo = 1,
    TdgMrRtmrExtend = 2,
    TdgVpVeinfoGet = 3,
    TdgMrReport = 4,
    TdgVpCpuidveSet = 5,
    TdgMemPageAccept = 6,
    TdgVmRd = 7,
    TdgVmWr = 8,
    TdgMrVerifyreport = 22,
    TdgMemPageAttrRd = 23,
    TdgMemPageAttrWr = 24,
    TdgServTd = 26,
};

pub const TdVmcallFunction = enum(u32) {
    MapGpa = 0x10001,
    GetQuote = 0x10002,
    ReportFatalError = 0x10003,
    SetupEventNotifyInterrupt = 0x10004,
};

pub const TdxReportStruct = struct {
    report_type: [4]u8,
    _reserved1: [12]u8,
    cpusvn: [16]u8,
    tee_tcb_info_hash: [48]u8,
    tee_info_hash: [48]u8,
    report_data: [64]u8,    // User data (nonce)
    _reserved2: [32]u8,
    mac: [32]u8,            // HMAC signature
};

pub const TdxTdInfoStruct = struct {
    attributes: TdxAttributes,
    xfam: u64,
    mrtd: [48]u8,           // Measurement of initial TD contents
    mrconfigid: [48]u8,
    mrowner: [48]u8,
    mrownerconfig: [48]u8,
    rtmr0: [48]u8,          // Runtime measurement register 0
    rtmr1: [48]u8,
    rtmr2: [48]u8,
    rtmr3: [48]u8,
    servtd_hash: [48]u8,
    _reserved: [64]u8,
};

pub const TdxAttributes = packed struct(u64) {
    debug: bool,
    _reserved1: u3,
    sept_ve_disable: bool,
    _reserved2: u23,
    pks: bool,
    kl: bool,
    tpa: bool,
    perfmon: bool,
    _reserved3: u32,
};

pub const TdxPageLevel = enum(u8) {
    Page4K = 0,
    Page2M = 1,
    Page1G = 2,
};

pub const TdxPageAttr = packed struct(u64) {
    read: bool,
    write: bool,
    execute_user: bool,
    execute_supervisor: bool,
    _reserved1: u11,
    suppress_ve: bool,
    _reserved2: u48,
};

pub const TdxEpochType = enum(u8) {
    None = 0,
    Current = 1,
    Previous = 2,
};

// ============================================================================
// Confidential Computing Abstraction
// ============================================================================

pub const CcVendor = enum(u8) {
    None = 0,
    AmdSev = 1,
    IntelTdx = 2,
    HyperV = 3,
};

pub const CcAttr = enum(u8) {
    MemEncrypt = 0,
    HostMemEncrypt = 1,
    GuestMemEncrypt = 2,
    GuestStateEncrypt = 3,
    GuestSnp = 4,
    GuestUnrollStringIo = 5,
    GuestSecureTsc = 6,
    GuestTdx = 7,
};

pub const CcBlob = struct {
    magic: u32,             // 0x45444D41 "AMDE" for AMD
    version: u16,
    _reserved: u16,
    secrets_phys: u64,
    secrets_len: u32,
    _reserved1: u32,
    cpuid_phys: u64,
    cpuid_len: u32,
    _reserved2: u32,
};

// ============================================================================
// Remote Attestation Protocol
// ============================================================================

pub const AttestationChallengeType = enum(u8) {
    None = 0,
    SnpReport = 1,
    TdxQuote = 2,
    SevCertChain = 3,
};

pub const AttestationChallenge = struct {
    challenge_type: AttestationChallengeType,
    nonce: [64]u8,
    algo: u8,
    extra_data_len: u32,
};

pub const AttestationEvidence = struct {
    vendor: CcVendor,
    report: [4096]u8,
    report_len: u32,
    certs: [8192]u8,
    certs_len: u32,
    nonce: [64]u8,
};

// ============================================================================
// Manager
// ============================================================================

pub const ConfidentialComputingManager = struct {
    cc_vendor: CcVendor,
    sev_generation: SevGeneration,
    sev_status: SevStatus,
    ghcb_base: u64,
    vmpl_level: VmplLevel,
    snp_page_state_changes: u64,
    tdx_module_version: TdxModuleVersion,
    tdx_attributes: TdxAttributes,
    total_attestation_requests: u64,
    total_page_validations: u64,
    total_guest_requests: u64,
    total_vmgexit_calls: u64,
    total_tdcall_calls: u64,
    initialized: bool,

    pub fn init() ConfidentialComputingManager {
        return .{
            .cc_vendor = .None,
            .sev_generation = .None,
            .sev_status = @bitCast(@as(u64, 0)),
            .ghcb_base = 0,
            .vmpl_level = .Vmpl0,
            .snp_page_state_changes = 0,
            .tdx_module_version = .{ .major = 0, .minor = 0, .build = 0, .patch = 0 },
            .tdx_attributes = @bitCast(@as(u64, 0)),
            .total_attestation_requests = 0,
            .total_page_validations = 0,
            .total_guest_requests = 0,
            .total_vmgexit_calls = 0,
            .total_tdcall_calls = 0,
            .initialized = true,
        };
    }
};
