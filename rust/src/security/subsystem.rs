// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Rust Security Subsystem: LSM Framework, Audit, Keyring, IMA/EVM,
// Capabilities, Namespaces Security, Secure Boot, TPM Interface
// More advanced than Linux 2026 security subsystem

use core::fmt;

// ============================================================================
// Linux Security Modules (LSM) Framework
// ============================================================================

pub const LSM_MAX_HOOKS: usize = 256;
pub const LSM_MAX_MODULES: usize = 16;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LsmId {
    Selinux = 1,
    Smack = 2,
    Tomoyo = 3,
    AppArmor = 4,
    Yama = 5,
    LoadPin = 6,
    SafeSetId = 7,
    Lockdown = 8,
    Bpf = 9,
    Landlock = 10,
    Integrity = 11,  // IMA/EVM
    // Zxyphor extensions
    ZxyCap = 200,    // Capability-based security
    ZxyML = 201,     // ML-based anomaly detection
    ZxySandbox = 202,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LsmHookId {
    // Task hooks
    TaskAlloc = 0,
    TaskFree = 1,
    TaskSetuid = 2,
    TaskSetgid = 3,
    TaskSetpgid = 4,
    TaskKill = 5,
    TaskPrctl = 6,
    TaskToInode = 7,
    TaskGetSecid = 8,
    TaskSetnice = 9,
    TaskSetioprio = 10,
    TaskGetioprio = 11,
    TaskPrlimit = 12,
    TaskSetrlimit = 13,
    TaskSetscheduler = 14,
    TaskGetscheduler = 15,
    TaskMovememory = 16,
    // File hooks
    FilePermission = 50,
    FileAlloc = 51,
    FileFree = 52,
    FileIoctl = 53,
    FileMmap = 54,
    FileMprotect = 55,
    FileLock = 56,
    FileFcntl = 57,
    FileSetFowner = 58,
    FileSendSignoToFd = 59,
    FileReceive = 60,
    FileOpen = 61,
    FileTruncate = 62,
    // Inode hooks
    InodeAlloc = 100,
    InodeFree = 101,
    InodeInit = 102,
    InodeCreate = 103,
    InodeLink = 104,
    InodeUnlink = 105,
    InodeSymlink = 106,
    InodeMkdir = 107,
    InodeRmdir = 108,
    InodeMknod = 109,
    InodeRename = 110,
    InodeSetattr = 111,
    InodeGetattr = 112,
    InodeSetxattr = 113,
    InodeGetxattr = 114,
    InodeListxattr = 115,
    InodeRemovexattr = 116,
    InodePermission = 117,
    // Socket hooks
    SocketCreate = 150,
    SocketPost = 151,
    SocketBind = 152,
    SocketConnect = 153,
    SocketListen = 154,
    SocketAccept = 155,
    SocketSendmsg = 156,
    SocketRecvmsg = 157,
    SocketGetsockname = 158,
    SocketGetpeername = 159,
    SocketSetsockopt = 160,
    SocketGetsockopt = 161,
    SocketShutdown = 162,
    // Misc
    PtraceMayAccess = 200,
    PtraceTraceme = 201,
    CapableNoAudit = 202,
    Quotactl = 203,
    Syslog = 204,
    Settime = 205,
    SbAlloc = 206,
    SbFree = 207,
    SbMount = 208,
    SbUmount = 209,
    SbRemount = 210,
    SbPivotroot = 211,
    SbStatfs = 212,
    MoveMount = 213,
    // BPF hooks
    BpfProg = 220,
    BpfMap = 221,
    // Key hooks
    KeyAlloc = 230,
    KeyFree = 231,
    KeyPermission = 232,
}

#[derive(Clone)]
pub struct LsmHook {
    pub hook_id: LsmHookId,
    pub lsm_id: LsmId,
    pub priority: i32,
    pub enabled: bool,
}

pub struct LsmModule {
    pub id: LsmId,
    pub name: [u8; 32],
    pub name_len: u8,
    pub hooks: [Option<LsmHook>; LSM_MAX_HOOKS],
    pub nr_hooks: u32,
    pub enabled: bool,
    pub exclusive: bool,     // Major LSM (SELinux, AppArmor, Smack)
    pub blob_sizes: LsmBlobSizes,
    pub order: u32,          // Init order
}

#[derive(Debug, Clone, Copy)]
pub struct LsmBlobSizes {
    pub lbs_cred: u32,
    pub lbs_file: u32,
    pub lbs_inode: u32,
    pub lbs_superblock: u32,
    pub lbs_ipc: u32,
    pub lbs_msg_msg: u32,
    pub lbs_task: u32,
    pub lbs_xattr_count: u32,
}

pub struct LsmFramework {
    pub modules: [Option<LsmModule>; LSM_MAX_MODULES],
    pub nr_modules: u32,
    pub exclusive_module: Option<LsmId>,
    pub enabled: bool,
    pub blob_sizes: LsmBlobSizes,
    // Default module order
    pub order: [LsmId; LSM_MAX_MODULES],
    pub order_len: u32,
}

impl LsmFramework {
    pub fn call_hook(&self, hook_id: LsmHookId) -> i32 {
        let mut result: i32 = 0;
        for module in self.modules.iter().flatten() {
            if !module.enabled {
                continue;
            }
            for hook in module.hooks.iter().flatten() {
                if hook.hook_id as u32 == hook_id as u32 && hook.enabled {
                    // Would call the actual hook function here
                    // On deny (non-zero), short-circuit
                    if result != 0 {
                        return result;
                    }
                }
            }
        }
        result
    }
}

// ============================================================================
// POSIX Capabilities
// ============================================================================

pub const CAP_CHOWN: u8 = 0;
pub const CAP_DAC_OVERRIDE: u8 = 1;
pub const CAP_DAC_READ_SEARCH: u8 = 2;
pub const CAP_FOWNER: u8 = 3;
pub const CAP_FSETID: u8 = 4;
pub const CAP_KILL: u8 = 5;
pub const CAP_SETGID: u8 = 6;
pub const CAP_SETUID: u8 = 7;
pub const CAP_SETPCAP: u8 = 8;
pub const CAP_LINUX_IMMUTABLE: u8 = 9;
pub const CAP_NET_BIND_SERVICE: u8 = 10;
pub const CAP_NET_BROADCAST: u8 = 11;
pub const CAP_NET_ADMIN: u8 = 12;
pub const CAP_NET_RAW: u8 = 13;
pub const CAP_IPC_LOCK: u8 = 14;
pub const CAP_IPC_OWNER: u8 = 15;
pub const CAP_SYS_MODULE: u8 = 16;
pub const CAP_SYS_RAWIO: u8 = 17;
pub const CAP_SYS_CHROOT: u8 = 18;
pub const CAP_SYS_PTRACE: u8 = 19;
pub const CAP_SYS_PACCT: u8 = 20;
pub const CAP_SYS_ADMIN: u8 = 21;
pub const CAP_SYS_BOOT: u8 = 22;
pub const CAP_SYS_NICE: u8 = 23;
pub const CAP_SYS_RESOURCE: u8 = 24;
pub const CAP_SYS_TIME: u8 = 25;
pub const CAP_SYS_TTY_CONFIG: u8 = 26;
pub const CAP_MKNOD: u8 = 27;
pub const CAP_LEASE: u8 = 28;
pub const CAP_AUDIT_WRITE: u8 = 29;
pub const CAP_AUDIT_CONTROL: u8 = 30;
pub const CAP_SETFCAP: u8 = 31;
pub const CAP_MAC_OVERRIDE: u8 = 32;
pub const CAP_MAC_ADMIN: u8 = 33;
pub const CAP_SYSLOG: u8 = 34;
pub const CAP_WAKE_ALARM: u8 = 35;
pub const CAP_BLOCK_SUSPEND: u8 = 36;
pub const CAP_AUDIT_READ: u8 = 37;
pub const CAP_PERFMON: u8 = 38;
pub const CAP_BPF: u8 = 39;
pub const CAP_CHECKPOINT_RESTORE: u8 = 40;
pub const CAP_LAST_CAP: u8 = 40;

#[derive(Debug, Clone, Copy)]
pub struct KernelCapStruct {
    pub cap: [u32; 2], // 64 bits total
}

impl KernelCapStruct {
    pub fn new() -> Self {
        Self { cap: [0, 0] }
    }

    pub fn full() -> Self {
        let mask = (1u64 << (CAP_LAST_CAP as u64 + 1)) - 1;
        Self {
            cap: [mask as u32, (mask >> 32) as u32],
        }
    }

    pub fn has_cap(&self, cap: u8) -> bool {
        if cap > 63 {
            return false;
        }
        let word = (cap / 32) as usize;
        let bit = cap % 32;
        (self.cap[word] & (1 << bit)) != 0
    }

    pub fn raise_cap(&mut self, cap: u8) {
        if cap > 63 {
            return;
        }
        let word = (cap / 32) as usize;
        let bit = cap % 32;
        self.cap[word] |= 1 << bit;
    }

    pub fn drop_cap(&mut self, cap: u8) {
        if cap > 63 {
            return;
        }
        let word = (cap / 32) as usize;
        let bit = cap % 32;
        self.cap[word] &= !(1 << bit);
    }

    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            cap: [self.cap[0] & other.cap[0], self.cap[1] & other.cap[1]],
        }
    }

    pub fn union_with(&self, other: &Self) -> Self {
        Self {
            cap: [self.cap[0] | other.cap[0], self.cap[1] | other.cap[1]],
        }
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        (self.cap[0] & !other.cap[0]) == 0 && (self.cap[1] & !other.cap[1]) == 0
    }

    pub fn is_empty(&self) -> bool {
        self.cap[0] == 0 && self.cap[1] == 0
    }
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub securebits: u32,
    pub cap_inheritable: KernelCapStruct,
    pub cap_permitted: KernelCapStruct,
    pub cap_effective: KernelCapStruct,
    pub cap_bset: KernelCapStruct,     // Bounding set
    pub cap_ambient: KernelCapStruct,
    pub user_ns: u32,
    pub security: u64,  // LSM blob offset
    pub groups: [u32; 32],
    pub nr_groups: u8,
}

impl Credentials {
    pub fn is_root(&self) -> bool {
        self.euid == 0
    }

    pub fn capable(&self, cap: u8) -> bool {
        self.cap_effective.has_cap(cap)
    }

    pub fn in_group(&self, gid: u32) -> bool {
        if self.gid == gid || self.egid == gid {
            return true;
        }
        for g in &self.groups[..self.nr_groups as usize] {
            if *g == gid {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Audit Subsystem
// ============================================================================

pub const AUDIT_MAX_FIELDS: usize = 64;
pub const AUDIT_BUFFER_SIZE: usize = 8192;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuditMessageType {
    // Kernel messages 1000-1099
    Syscall = 1300,
    FilePath = 1302,
    Ipc = 1303,
    Socketcall = 1304,
    Config = 1305,
    Sockaddr = 1306,
    Cwd = 1307,
    Execve = 1309,
    IpcSetPerm = 1311,
    MqSendrecv = 1312,
    MqNotify = 1313,
    MqGetsetattr = 1314,
    KernelOther = 1315,
    FdPair = 1317,
    ObjPid = 1318,
    Tty = 1319,
    Eoe = 1320,         // End of event
    Bprm = 1323,
    CapSet = 1324,
    Mmap = 1326,
    NetfilterPkt = 1327,
    NetfilterCfg = 1328,
    Seccomp = 1326,
    Proctitle = 1327,
    FeatureChange = 1328,
    ReplaceFilter = 1329,
    KernIntegrity = 1400,
    // User messages
    UserAuth = 1100,
    UserAcct = 1101,
    UserMgmt = 1102,
    CredAcq = 1103,
    CredDisp = 1104,
    UserStart = 1105,
    UserEnd = 1106,
    UserLogin = 1112,
    UserLogout = 1113,
    // Anomaly messages
    AnomalyPromiscuous = 1700,
    AnomalyAbend = 1701,
    AnomalyLink = 1702,
    // Integrity
    IntegrityData = 1800,
    IntegrityMetadata = 1801,
    IntegrityStatus = 1802,
    IntegrityHash = 1803,
    IntegrityPcr = 1804,
    IntegrityRule = 1805,
    IntegrityEvm = 1806,
    IntegritySig = 1807,
    // Zxyphor
    ZxyCapabilityViolation = 2000,
    ZxyAnomalyDetected = 2001,
    ZxySandboxViolation = 2002,
}

#[derive(Debug, Clone)]
pub struct AuditBuffer {
    pub data: [u8; AUDIT_BUFFER_SIZE],
    pub len: usize,
    pub msg_type: AuditMessageType,
    pub serial: u64,
    pub timestamp_sec: u64,
    pub timestamp_nsec: u32,
    pub loginuid: u32,
    pub sessionid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub exe: [u8; 256],
    pub result: i32,      // Success/failure
    pub arch: u32,        // AUDIT_ARCH_*
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuditFieldOp {
    Eq = 0,
    Ne = 1,
    Lt = 2,
    Le = 3,
    Gt = 4,
    Ge = 5,
    BitMask = 6,
    BitTest = 7,
}

#[derive(Debug, Clone)]
pub struct AuditFilterRule {
    pub field: u32,
    pub op: AuditFieldOp,
    pub val: u64,
    pub str_val: [u8; 256],
    pub str_len: u16,
    pub flags: u32,
    pub listnr: u32,
    pub action: u32,     // AUDIT_NEVER / AUDIT_ALWAYS
}

pub struct AuditSubsystem {
    pub enabled: bool,
    pub backlog_limit: u32,
    pub backlog_wait_time: u32,
    pub rate_limit: u32,
    pub failure_action: u32,  // 0=silent, 1=printk, 2=panic
    pub rules: [Option<AuditFilterRule>; 1024],
    pub nr_rules: u32,
    // Stats
    pub lost: u64,
    pub backlog: u32,
    pub serial: u64,
    pub loginuid_immutable: bool,
}

// ============================================================================
// Keyring Subsystem
// ============================================================================

pub const KEY_MAX_DESC_SIZE: usize = 4096;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    User = 0,
    Logon = 1,
    BigKey = 2,
    Keyring = 3,
    Asymmetric = 4,
    Cifs = 5,
    Dns = 6,
    Encrypted = 7,
    Trusted = 8,
    RequestKey = 9,
    Rxrpc = 10,
    // Zxyphor
    ZxyCapability = 200,
    ZxyAttestation = 201,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyPerm {
    PossessView = 0x01000000,
    PossessRead = 0x02000000,
    PossessWrite = 0x04000000,
    PossessSearch = 0x08000000,
    PossessLink = 0x10000000,
    PossessSetattr = 0x20000000,
    UserView = 0x00010000,
    UserRead = 0x00020000,
    UserWrite = 0x00040000,
    UserSearch = 0x00080000,
    UserLink = 0x00100000,
    UserSetattr = 0x00200000,
    GroupView = 0x00000100,
    GroupRead = 0x00000200,
    GroupWrite = 0x00000400,
    GroupSearch = 0x00000800,
    GroupLink = 0x00001000,
    GroupSetattr = 0x00002000,
    OtherView = 0x00000001,
    OtherRead = 0x00000002,
    OtherWrite = 0x00000004,
    OtherSearch = 0x00000008,
    OtherLink = 0x00000010,
    OtherSetattr = 0x00000020,
}

#[derive(Debug, Clone)]
pub struct Key {
    pub serial: u32,
    pub key_type: KeyType,
    pub description: [u8; 256],
    pub desc_len: u16,
    pub uid: u32,
    pub gid: u32,
    pub perm: u32,
    pub flags: u32,
    pub expiry: u64,         // 0 = no expiry
    pub data: [u8; 4096],
    pub data_len: u32,
    pub usage: u32,          // Reference count
    pub state: KeyState,
    pub security_label: [u8; 256],
    pub security_len: u16,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyState {
    Fresh = 0,
    Instantiated = 1,
    Negative = 2,
    Expired = 3,
    Revoked = 4,
    Dead = 5,
}

pub struct Keyring {
    pub key: Key,
    pub children: [u32; 256],  // Key serials
    pub nr_children: u32,
    pub max_children: u32,
    pub restrict_link: Option<KeyRestrictLink>,
}

#[derive(Debug, Clone)]
pub struct KeyRestrictLink {
    pub check_type: u32,
    pub key_type_id: u32,
    pub restriction_key: u32, // Serial of key to check against
}

// ============================================================================
// IMA (Integrity Measurement Architecture)
// ============================================================================

pub const IMA_HASH_ALGO_SHA256: u8 = 4;
pub const IMA_HASH_ALGO_SHA384: u8 = 5;
pub const IMA_HASH_ALGO_SHA512: u8 = 6;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImaAction {
    DontMeasure = 0,
    Measure = 1,
    DontAppraise = 2,
    Appraise = 3,
    Audit = 4,
    Hash = 5,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImaHook {
    FileCheck = 1,
    MmapCheck = 2,
    BprmCheck = 3,
    CkedsCheck = 4,
    PostSetattr = 5,
    ModuleCheck = 6,
    FirmwareCheck = 7,
    KexecKernelCheck = 8,
    KexecInitramfsCheck = 9,
    PolicyCheck = 10,
    KexecCmdline = 11,
    KeyCheck = 12,
    CriticalData = 13,
}

#[derive(Debug, Clone)]
pub struct ImaRule {
    pub action: ImaAction,
    pub hook: ImaHook,
    pub mask: u32,
    pub uid: i32,        // -1 = any
    pub fowner: i32,     // -1 = any
    pub fsuuid: [u8; 16],
    pub lsm_label: [u8; 256],
    pub label_len: u16,
    pub flags: u32,
    pub hash_algo: u8,
}

#[derive(Debug, Clone)]
pub struct ImaMeasurement {
    pub pcr: u8,
    pub digest: [u8; 64],
    pub digest_len: u8,
    pub hash_algo: u8,
    pub template: [u8; 32],
    pub filename: [u8; 256],
    pub filename_len: u16,
}

pub struct ImaSubsystem {
    pub enabled: bool,
    pub hash_algo: u8,
    pub policy: [Option<ImaRule>; 256],
    pub nr_rules: u32,
    pub measurements: [Option<ImaMeasurement>; 4096],
    pub nr_measurements: u32,
    pub violations: u64,
    // PCR extend
    pub pcr: u8,
    pub pcr_digest: [u8; 64],
    // Appraise
    pub appraise_mode: u8,   // 0=off, 1=enforce, 2=log, 3=fix
    pub appraise_modsig: bool,
}

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvmStatus {
    Unknown = 0,
    Valid = 1,
    ValidSig = 2,
    Invalid = 3,
    NoXattr = 4,
    NoKey = 5,
    KeyFailure = 6,
}

pub struct EvmSubsystem {
    pub enabled: bool,
    pub immutable: bool,
    pub hmac_key: [u8; 32],
    pub hmac_key_loaded: bool,
    pub hash_algo: u8,
    pub protected_xattrs: [[u8; 64]; 32],
    pub nr_xattrs: u8,
}

// ============================================================================
// Secure Boot / UEFI Security
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecureBootState {
    Disabled = 0,
    Enabled = 1,
    SetupMode = 2,
    DeployedMode = 3,
    AuditMode = 4,
}

#[derive(Debug, Clone)]
pub struct SecureBootDb {
    pub state: SecureBootState,
    // Signature databases
    pub db: [SignatureEntry; 64],       // Allowed
    pub nr_db: u32,
    pub dbx: [SignatureEntry; 256],     // Forbidden
    pub nr_dbx: u32,
    pub dbt: [SignatureEntry; 32],      // Timestamping
    pub nr_dbt: u32,
    pub mok: [SignatureEntry; 32],      // Machine Owner Keys
    pub nr_mok: u32,
    pub mokx: [SignatureEntry; 32],     // MOK blacklist
    pub nr_mokx: u32,
    // Platform Key
    pub pk: Option<SignatureEntry>,
    // Key Exchange Keys
    pub kek: [SignatureEntry; 8],
    pub nr_kek: u32,
}

#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub sig_type: SignatureType,
    pub owner: [u8; 16],      // GUID
    pub data: [u8; 4096],
    pub data_len: u32,
    pub timestamp: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureType {
    Sha256 = 0,
    Rsa2048 = 1,
    Rsa2048Sha256 = 2,
    Sha1 = 3,
    Sha384 = 4,
    Sha512 = 5,
    X509 = 6,
    Pkcs7 = 7,
}

// ============================================================================
// TPM Interface
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TpmVersion {
    Tpm12 = 1,
    Tpm20 = 2,
}

pub const TPM_PCR_COUNT: usize = 24;

#[derive(Debug, Clone)]
pub struct TpmDevice {
    pub version: TpmVersion,
    pub manufacturer: u32,
    pub firmware_version: u64,
    // PCRs
    pub pcrs: [TpmPcr; TPM_PCR_COUNT],
    // Capabilities
    pub algorithms: [TpmAlgorithm; 16],
    pub nr_algorithms: u8,
    // State
    pub initialized: bool,
    pub owned: bool,
    pub enabled: bool,
    pub active: bool,
    // Locality
    pub active_locality: u8,
    // Stats
    pub total_commands: u64,
    pub total_duration_us: u64,
}

#[derive(Debug, Clone)]
pub struct TpmPcr {
    pub index: u8,
    pub digest: [u8; 64],
    pub digest_size: u8,
    pub hash_algo: TpmAlgorithm,
    pub extend_count: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TpmAlgorithm {
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Sm3_256 = 0x0012,
    Sha3_256 = 0x0027,
    Sha3_384 = 0x0028,
    Sha3_512 = 0x0029,
}

// TPM2 commands
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Tpm2Command {
    Startup = 0x0144,
    Shutdown = 0x0145,
    SelfTest = 0x0143,
    PcrExtend = 0x0182,
    PcrRead = 0x017E,
    PcrReset = 0x013D,
    NvRead = 0x014E,
    NvWrite = 0x0137,
    NvDefineSpace = 0x012A,
    NvUndefineSpace = 0x0122,
    GetCapability = 0x017A,
    GetRandom = 0x017B,
    HashSequenceStart = 0x0186,
    SequenceUpdate = 0x015C,
    SequenceComplete = 0x013E,
    Sign = 0x015D,
    VerifySignature = 0x0177,
    CreatePrimary = 0x0131,
    Create = 0x0153,
    Load = 0x0157,
    Quote = 0x0158,
    Unseal = 0x015E,
    FlushContext = 0x0165,
    DictionaryAttackLockReset = 0x0139,
    PolicyPCR = 0x017F,
    PolicyPassword = 0x018C,
    PolicyGetDigest = 0x0189,
    PolicyCommandCode = 0x016C,
    CreateLoaded = 0x0191,
}

impl TpmDevice {
    pub fn pcr_extend(&mut self, pcr_index: u8, digest: &[u8]) -> Result<(), i32> {
        if pcr_index as usize >= TPM_PCR_COUNT {
            return Err(-22); // EINVAL
        }
        let pcr = &mut self.pcrs[pcr_index as usize];
        // Extend: new_digest = HASH(old_digest || new_data)
        // Simplified - real impl needs actual hash
        for (i, byte) in digest.iter().enumerate() {
            if i < pcr.digest_size as usize {
                pcr.digest[i] ^= byte;
            }
        }
        pcr.extend_count += 1;
        Ok(())
    }

    pub fn pcr_read(&self, pcr_index: u8) -> Option<&[u8]> {
        if pcr_index as usize >= TPM_PCR_COUNT {
            return None;
        }
        let pcr = &self.pcrs[pcr_index as usize];
        Some(&pcr.digest[..pcr.digest_size as usize])
    }
}

// ============================================================================
// Lockdown
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockdownLevel {
    None = 0,
    Integrity = 1,     // Prevent unsigned code
    Confidentiality = 2, // Also prevent reading secrets
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockdownReason {
    None = 0,
    ModuleSignature = 1,
    DevMem = 2,
    EfiTestMode = 3,
    KexecLoad = 4,
    HibernationWrite = 5,
    Iopl = 6,
    Ioperm = 7,
    SetArchDmaAllowed = 8,
    Debugfs = 9,
    XmonWr = 10,
    BpfWriteUser = 11,
    KprobeOverride = 12,
    PciBarlAcks = 13,
    ModuleParameters = 14,
    MmioAccess = 15,
    TcgmemRw = 16,
    KernelRead = 17,
}

pub struct LockdownSubsystem {
    pub level: LockdownLevel,
    pub reasons_blocked: [bool; 32],
}

// ============================================================================
// Landlock (Unprivileged Access Control)
// ============================================================================

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LandlockAccessFs {
    Execute = 1 << 0,
    WriteFile = 1 << 1,
    ReadFile = 1 << 2,
    ReadDir = 1 << 3,
    RemoveDir = 1 << 4,
    RemoveFile = 1 << 5,
    MakeChar = 1 << 6,
    MakeDir = 1 << 7,
    MakeReg = 1 << 8,
    MakeSock = 1 << 9,
    MakeFifo = 1 << 10,
    MakeBlock = 1 << 11,
    MakeSym = 1 << 12,
    Refer = 1 << 13,
    Truncate = 1 << 14,
    IoctlDev = 1 << 15,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LandlockAccessNet {
    BindTcp = 1 << 0,
    ConnectTcp = 1 << 1,
}

#[derive(Debug, Clone)]
pub struct LandlockRuleset {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub fs_rules: [Option<LandlockFsRule>; 256],
    pub nr_fs_rules: u32,
    pub net_rules: [Option<LandlockNetRule>; 64],
    pub nr_net_rules: u32,
    pub enforcing: bool,
}

#[derive(Debug, Clone)]
pub struct LandlockFsRule {
    pub path: [u8; 256],
    pub path_len: u16,
    pub allowed_access: u64,
}

#[derive(Debug, Clone)]
pub struct LandlockNetRule {
    pub port: u16,
    pub allowed_access: u64,
}

// ============================================================================
// SECCOMP-BPF
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeccompMode {
    Disabled = 0,
    Strict = 1,
    Filter = 2,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeccompRetAction {
    KillProcess = 0x80000000,
    KillThread = 0x00000000,
    Trap = 0x00030000,
    Errno = 0x00050000,
    UserNotif = 0x7FC00000,
    Trace = 0x7FF00000,
    Log = 0x7FFC0000,
    Allow = 0x7FFF0000,
}

pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 2;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 4;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 8;
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 16;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 32;

#[derive(Debug, Clone)]
pub struct SeccompFilter {
    pub mode: SeccompMode,
    pub flags: u32,
    pub prog_len: u16,
    pub prog: [BpfInsn; 4096],
    pub log: bool,
    pub nr_matches: u64,
    pub nr_denials: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// ============================================================================
// Security Subsystem Manager
// ============================================================================

pub struct SecuritySubsystem {
    pub lsm: LsmFramework,
    pub audit: AuditSubsystem,
    pub ima: ImaSubsystem,
    pub evm: EvmSubsystem,
    pub secure_boot: SecureBootDb,
    pub tpm: Option<TpmDevice>,
    pub lockdown: LockdownSubsystem,
    pub initialized: bool,
}

impl SecuritySubsystem {
    pub fn is_secure_boot(&self) -> bool {
        self.secure_boot.state == SecureBootState::Enabled
            || self.secure_boot.state == SecureBootState::DeployedMode
    }

    pub fn lockdown_check(&self, reason: LockdownReason) -> bool {
        match self.lockdown.level {
            LockdownLevel::None => true,
            LockdownLevel::Integrity => {
                !matches!(
                    reason,
                    LockdownReason::ModuleSignature
                        | LockdownReason::KexecLoad
                        | LockdownReason::KprobeOverride
                        | LockdownReason::BpfWriteUser
                )
            }
            LockdownLevel::Confidentiality => false,
        }
    }
}
