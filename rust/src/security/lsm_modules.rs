// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - SMACK, TOMOYO, SafeSetID, LoadPin, Yama,
// Integrity Measurement Architecture (IMA) Advanced, LSM Stacking
// More advanced than Linux 2026 security modules

/// SMACK (Simplified Mandatory Access Control Kernel) label
#[derive(Debug, Clone)]
pub struct SmackLabel {
    pub label: [256; u8],
    pub len: u16,
}

/// SMACK well-known labels
pub const SMACK_STAR: &str = "*";        // Anything
pub const SMACK_FLOOR: &str = "_";       // Minimum floor
pub const SMACK_HAT: &str = "^";         // Internet
pub const SMACK_WEB: &str = "@";         // Web
pub const SMACK_INVALID: &str = "-";

/// SMACK access type (bit flags)
pub const SMACK_READ: u32 = 0x01;
pub const SMACK_WRITE: u32 = 0x02;
pub const SMACK_EXEC: u32 = 0x04;
pub const SMACK_APPEND: u32 = 0x08;
pub const SMACK_TRANSMUTE: u32 = 0x10;
pub const SMACK_LOCK: u32 = 0x20;
pub const SMACK_BRINGUP: u32 = 0x40;

/// SMACK rule
#[derive(Debug, Clone)]
pub struct SmackRule {
    pub subject: [256; u8],
    pub object: [256; u8],
    pub access: u32,
    // Audit
    pub audit: bool,
    // Timestamp
    pub created_ns: u64,
}

/// SMACK configuration
#[derive(Debug, Clone)]
pub struct SmackConfig {
    pub enabled: bool,
    pub enforcing: bool,
    // Default label
    pub default_label: [256; u8],
    // Ambient label
    pub ambient_label: [256; u8],
    // Network
    pub netlabel_enabled: bool,
    pub cipso_enabled: bool,
    pub cipso_doi: u32,
    // Mapped
    pub mapped_enabled: bool,
    // Stats
    pub total_rules: u64,
    pub total_checks: u64,
    pub total_grants: u64,
    pub total_denials: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    // Zxyphor
    pub zxy_ml_policy: bool,
}

// ============================================================================
// TOMOYO Linux
// ============================================================================

/// TOMOYO policy type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TomoyoPolicyType {
    DomainPolicy = 0,
    ExceptionPolicy = 1,
    Profile = 2,
    Manager = 3,
    Stat = 4,
}

/// TOMOYO profile mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TomoyoMode {
    Disabled = 0,
    Learning = 1,
    Permissive = 2,
    Enforcing = 3,
}

/// TOMOYO domain
#[derive(Debug, Clone)]
pub struct TomoyoDomain {
    pub name: [512; u8],
    pub mode: TomoyoMode,
    pub profile: u8,
    // Flags
    pub initializer: bool,
    pub keeper: bool,
    pub transition_failed: bool,
    // Stats
    pub nr_acl: u32,
    pub created_ns: u64,
}

/// TOMOYO ACL type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TomoyoAclType {
    FilePathname = 0,
    FileMkdir = 1,
    FileMkfifo = 2,
    FileMksock = 3,
    FileLink = 4,
    FileRename = 5,
    FileUnlink = 6,
    FileRmdir = 7,
    FileChmod = 8,
    FileChown = 9,
    FileChgrp = 10,
    FileMount = 11,
    FileUmount = 12,
    FilePivotRoot = 13,
    NetInet = 14,
    NetUnix = 15,
    IpcSignal = 16,
    EnvironVariable = 17,
    TaskManualDomainTransition = 18,
    TaskAutoDomainTransition = 19,
    // Zxyphor
    ZxyDeviceAccess = 50,
    ZxyNetFilter = 51,
}

/// TOMOYO configuration
#[derive(Debug, Clone)]
pub struct TomoyoConfig {
    pub enabled: bool,
    pub default_mode: TomoyoMode,
    // Policy
    pub nr_domains: u64,
    pub nr_acl_entries: u64,
    pub nr_exception_entries: u64,
    // Learning
    pub learning_counter: u64,
    // Stats
    pub total_checks: u64,
    pub total_grants: u64,
    pub total_denials: u64,
    pub total_learning_entries: u64,
    // Memory
    pub policy_memory_bytes: u64,
    pub policy_memory_quota: u64,
}

// ============================================================================
// Yama LSM
// ============================================================================

/// Yama ptrace scope
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamaPtraceScope {
    Classic = 0,        // Classic ptrace permissions
    RestrictedChild = 1, // Only descendants
    AdminOnly = 2,       // Only CAP_SYS_PTRACE
    NoAttach = 3,        // No ptrace at all
}

/// Yama configuration
#[derive(Debug, Clone)]
pub struct YamaConfig {
    pub enabled: bool,
    pub ptrace_scope: YamaPtraceScope,
    // Stats
    pub ptrace_denials: u64,
    pub symlink_denials: u64,
    pub hardlink_denials: u64,
}

// ============================================================================
// SafeSetID
// ============================================================================

/// SafeSetID policy type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeSetIdPolicyType {
    Uid = 0,
    Gid = 1,
}

/// SafeSetID rule
#[derive(Debug, Clone)]
pub struct SafeSetIdRule {
    pub policy_type: SafeSetIdPolicyType,
    pub from_id: u32,
    pub to_id: u32,
}

/// SafeSetID configuration
#[derive(Debug, Clone)]
pub struct SafeSetIdConfig {
    pub enabled: bool,
    pub nr_uid_rules: u32,
    pub nr_gid_rules: u32,
    pub total_checks: u64,
    pub total_denials: u64,
}

// ============================================================================
// LoadPin
// ============================================================================

/// LoadPin configuration
#[derive(Debug, Clone)]
pub struct LoadPinConfig {
    pub enabled: bool,
    pub enforce: bool,
    // Pinned device
    pub pinned_root_dev: u64,    // dev_t
    // Trusted verity
    pub dm_verity_only: bool,
    pub dm_verity_roothash: [64; u8],
    // Stats
    pub total_loads: u64,
    pub total_denials: u64,
    pub total_kernel_modules: u64,
    pub total_firmware: u64,
    pub total_kexec_images: u64,
    pub total_policy_loads: u64,
}

// ============================================================================
// Lockdown LSM
// ============================================================================

/// Lockdown level
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownLevel {
    None = 0,
    Integrity = 1,
    Confidentiality = 2,
    // Zxyphor
    ZxyMaximum = 10,
}

/// Lockdown reason
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownReason {
    None = 0,
    ModuleSig = 1,
    DevMem = 2,
    EfiTestMode = 3,
    KExec = 4,
    Hibernation = 5,
    PciAccess = 6,
    IoPort = 7,
    MsrAccess = 8,
    AcpiTables = 9,
    PerfEventAccess = 10,
    TraceFsAccess = 11,
    BpfRead = 12,
    BpfWriteUser = 13,
    Integrity = 14,
    Confidentiality = 15,
    // Zxyphor
    ZxySecureMemory = 50,
    ZxyDebugInterface = 51,
}

/// Lockdown configuration
#[derive(Debug, Clone)]
pub struct LockdownConfig {
    pub enabled: bool,
    pub level: LockdownLevel,
    pub total_denials: u64,
    pub denial_reasons: [64; u64],
}

// ============================================================================
// IMA Advanced
// ============================================================================

/// IMA hash algorithm
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaHashAlgo {
    Md5 = 0,
    Sha1 = 1,
    Ripemd160 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha224 = 6,
    Sm3_256 = 7,
    Streebog256 = 8,
    Streebog512 = 9,
    // Zxyphor
    ZxyBlake3 = 20,
    ZxySha3_256 = 21,
    ZxySha3_512 = 22,
}

/// IMA action
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaAction {
    Dont_measure = 0,
    Measure = 1,
    Audit = 2,
    Hash = 3,
    Dont_hash = 4,
    Appraise = 5,
    Dont_appraise = 6,
}

/// IMA hook
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaHook {
    FileCheck = 0,
    MmapCheck = 1,
    BprmCheck = 2,
    CretdsCheck = 3,
    PostSetAttr = 4,
    ModuleCheck = 5,
    FirmwareCheck = 6,
    KexecKernelCheck = 7,
    KexecInitRamfsCheck = 8,
    PolicyCheck = 9,
    SetXattrCheck = 10,
    RemoveXattrCheck = 11,
    KeyCheck = 12,
    CriticalDataCheck = 13,
    // Zxyphor
    ZxyDeviceAttestCheck = 50,
    ZxyRuntimeCheck = 51,
}

/// IMA template descriptor
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaTemplate {
    Ima = 0,          // "d|n"
    ImaNg = 1,        // "d-ng|n-ng"
    ImaSig = 2,       // "d-ng|n-ng|sig"
    ImaBuf = 3,       // "d-ng|n-ng|buf"
    ImaMoTSig = 4,    // "d-ng|n-ng|sig|d-modsig|modsig"
    EvmSig = 5,       // "d-ng|n-ng|evmsig|xattrnames|xattrlengths|xattrvalues"
    // Zxyphor
    ZxyFull = 20,     // Full attestation template
}

/// IMA policy rule
#[derive(Debug, Clone)]
pub struct ImaPolicyRule {
    pub action: ImaAction,
    pub hook: ImaHook,
    // Conditions
    pub uid: i32,          // -1 = any
    pub fowner: i32,       // -1 = any
    pub fsmagic: u64,      // 0 = any
    pub fsuuid: [16; u8],  // zero = any
    pub lsm_label: [256; u8],
    // Flags
    pub permit_directio: bool,
    pub appraise_type: ImaAppraiseType,
    pub template: ImaTemplate,
    pub hash_algo: ImaHashAlgo,
    // PCR
    pub pcr: u8,
}

/// IMA appraise type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaAppraiseType {
    None = 0,
    Imasig = 1,
    Imasig_or_Modsig = 2,
    Meta_immutable = 3,
}

/// IMA measurement entry
#[derive(Debug, Clone)]
pub struct ImaMeasurement {
    pub pcr: u8,
    pub template_hash: [64; u8],
    pub template_hash_len: u8,
    pub template: ImaTemplate,
    pub filename: [256; u8],
    pub timestamp_ns: u64,
    // File hash
    pub file_hash: [64; u8],
    pub file_hash_len: u8,
    pub hash_algo: ImaHashAlgo,
}

/// IMA statistics
#[derive(Debug, Clone)]
pub struct ImaStats {
    pub total_measurements: u64,
    pub total_violations: u64,
    pub total_appraisals: u64,
    pub total_appraisal_failures: u64,
    pub total_hash_failures: u64,
    pub total_sig_verifications: u64,
    pub total_sig_failures: u64,
    // Runtime
    pub runtime_measurements: u64,
    pub runtime_violations: u64,
    // Audit
    pub audit_entries: u64,
    // Policy
    pub nr_policy_rules: u32,
}

// ============================================================================
// EVM (Extended Verification Module) Advanced
// ============================================================================

/// EVM mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmMode {
    Disabled = 0,
    FixMode = 1,        // Fix mode (learning)
    EnforceMode = 2,    // Enforce HMAC
    SignedMode = 3,      // Enforce signatures
}

/// EVM protected xattrs
pub const EVM_XATTR_SELINUX: &str = "security.selinux";
pub const EVM_XATTR_SMACK: &str = "security.SMACK64";
pub const EVM_XATTR_APPARMOR: &str = "security.apparmor";
pub const EVM_XATTR_IMA: &str = "security.ima";
pub const EVM_XATTR_CAPS: &str = "security.capability";

/// EVM configuration
#[derive(Debug, Clone)]
pub struct EvmConfig {
    pub enabled: bool,
    pub mode: EvmMode,
    // Key
    pub hmac_key_loaded: bool,
    pub key_id: u32,
    // Protected attrs
    pub nr_protected_xattrs: u32,
    // Stats
    pub total_verifications: u64,
    pub total_hmac_pass: u64,
    pub total_hmac_fail: u64,
    pub total_sig_pass: u64,
    pub total_sig_fail: u64,
    pub total_unknown: u64,
}

// ============================================================================
// LSM Stacking
// ============================================================================

/// LSM order/stacking
#[derive(Debug, Clone)]
pub struct LsmStackConfig {
    pub nr_enabled: u8,
    pub order: [16; LsmId],
    // Major LSMs
    pub selinux_enabled: bool,
    pub apparmor_enabled: bool,
    pub smack_enabled: bool,
    pub tomoyo_enabled: bool,
    // Minor LSMs
    pub yama_enabled: bool,
    pub loadpin_enabled: bool,
    pub safesetid_enabled: bool,
    pub lockdown_enabled: bool,
    pub bpf_enabled: bool,
    pub landlock_enabled: bool,
    // IMA/EVM
    pub ima_enabled: bool,
    pub evm_enabled: bool,
    // Zxyphor
    pub zxy_lsm_enabled: bool,
}

/// LSM ID
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmId {
    Capability = 0,
    Selinux = 1,
    Smack = 2,
    Tomoyo = 3,
    Apparmor = 4,
    Yama = 5,
    Loadpin = 6,
    Safesetid = 7,
    Lockdown = 8,
    Bpf = 9,
    Landlock = 10,
    Ima = 11,
    Evm = 12,
    // Zxyphor
    ZxyGuard = 50,
}

/// LSM blob sizes
#[derive(Debug, Clone)]
pub struct LsmBlobSizes {
    pub lbs_cred: u32,
    pub lbs_file: u32,
    pub lbs_inode: u32,
    pub lbs_superblock: u32,
    pub lbs_ipc: u32,
    pub lbs_msg_msg: u32,
    pub lbs_task: u32,
    pub lbs_xattr_count: u32,
    pub lbs_tun_dev: u32,
    pub lbs_bdev: u32,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Security modules subsystem
#[derive(Debug, Clone)]
pub struct SecurityModulesSubsystem {
    // SMACK
    pub smack: SmackConfig,
    // TOMOYO
    pub tomoyo: TomoyoConfig,
    // Yama
    pub yama: YamaConfig,
    // SafeSetID
    pub safesetid: SafeSetIdConfig,
    // LoadPin
    pub loadpin: LoadPinConfig,
    // Lockdown
    pub lockdown: LockdownConfig,
    // IMA
    pub ima_stats: ImaStats,
    pub ima_hash_algo: ImaHashAlgo,
    pub ima_template: ImaTemplate,
    // EVM
    pub evm: EvmConfig,
    // LSM stack
    pub lsm_stack: LsmStackConfig,
    // Overall stats
    pub total_lsm_hooks_called: u64,
    pub total_lsm_denials: u64,
    // Zxyphor
    pub zxy_unified_policy: bool,
    pub initialized: bool,
}
