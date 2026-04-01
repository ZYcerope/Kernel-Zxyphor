// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Mandatory Access Control (SELinux-like) + Sandboxing
// Bell-LaPadula, BLP/Biba, Type Enforcement, RBAC, MLS

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Type Enforcement (TE)
// ============================================================================

/// Security Context (SELinux-compatible)
pub struct SecurityContext {
    pub user: SecurityId,
    pub role: SecurityId,
    pub type_: SecurityId,
    pub level: MlsRange,
    pub raw: [u8; 256],
    pub raw_len: u16,
}

pub type SecurityId = u32;

pub const SECINITSID_KERNEL: SecurityId = 1;
pub const SECINITSID_SECURITY: SecurityId = 2;
pub const SECINITSID_UNLABELED: SecurityId = 3;
pub const SECINITSID_FILE: SecurityId = 4;
pub const SECINITSID_ANY_SOCKET: SecurityId = 5;
pub const SECINITSID_PORT: SecurityId = 6;
pub const SECINITSID_NETIF: SecurityId = 7;
pub const SECINITSID_NETMSG: SecurityId = 8;
pub const SECINITSID_NODE: SecurityId = 9;

/// MLS (Multi-Level Security) Range
#[derive(Clone, Copy)]
pub struct MlsRange {
    pub low: MlsLevel,
    pub high: MlsLevel,
}

impl MlsRange {
    pub fn is_valid(&self) -> bool {
        self.low.sensitivity <= self.high.sensitivity
    }

    pub fn dominates(&self, other: &MlsRange) -> bool {
        self.low.sensitivity <= other.low.sensitivity 
            && self.high.sensitivity >= other.high.sensitivity
    }
}

/// MLS Level (Sensitivity + Categories)
#[derive(Clone, Copy)]
pub struct MlsLevel {
    pub sensitivity: u16, // s0-s15
    pub categories: [u64; 4], // 256 category bits
}

impl MlsLevel {
    pub fn new(sensitivity: u16) -> Self {
        MlsLevel {
            sensitivity,
            categories: [0; 4],
        }
    }

    pub fn set_category(&mut self, cat: u16) {
        if cat < 256 {
            self.categories[cat as usize / 64] |= 1u64 << (cat % 64);
        }
    }

    pub fn has_category(&self, cat: u16) -> bool {
        if cat >= 256 { return false; }
        self.categories[cat as usize / 64] & (1u64 << (cat % 64)) != 0
    }

    pub fn dominates(&self, other: &MlsLevel) -> bool {
        if self.sensitivity < other.sensitivity {
            return false;
        }
        // All categories in other must be in self
        for i in 0..4 {
            if other.categories[i] & !self.categories[i] != 0 {
                return false;
            }
        }
        true
    }
}

/// Object class for access vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjClass {
    File = 0,
    Dir = 1,
    Socket = 2,
    Process = 3,
    Ipc = 4,
    Msg = 5,
    Sem = 6,
    Shm = 7,
    Capability = 8,
    Capability2 = 9,
    Tcp = 10,
    Udp = 11,
    RawIp = 12,
    Node = 13,
    Netif = 14,
    Key = 15,
    Bpf = 16,
    PerfEvent = 17,
    Lockdown = 18,
    // Zxyphor extensions
    ZxyDevice = 100,
    ZxyGpu = 101,
    ZxySecureEnclave = 102,
    ZxyVirtDomain = 103,
}

/// Permission bits for files
pub mod file_perms {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const APPEND: u32 = 1 << 3;
    pub const GETATTR: u32 = 1 << 4;
    pub const SETATTR: u32 = 1 << 5;
    pub const LOCK: u32 = 1 << 6;
    pub const IOCTL: u32 = 1 << 7;
    pub const LINK: u32 = 1 << 8;
    pub const UNLINK: u32 = 1 << 9;
    pub const RENAME: u32 = 1 << 10;
    pub const CREATE: u32 = 1 << 11;
    pub const RELABELFROM: u32 = 1 << 12;
    pub const RELABELTO: u32 = 1 << 13;
    pub const MOUNTON: u32 = 1 << 14;
    pub const QUOTAON: u32 = 1 << 15;
    pub const OPEN: u32 = 1 << 16;
    pub const AUDIT_ACCESS: u32 = 1 << 17;
    pub const EXECMOD: u32 = 1 << 18;
    pub const MAP: u32 = 1 << 19;
    pub const ENTRYPOINT: u32 = 1 << 20;
    pub const WATCH: u32 = 1 << 21;
    pub const WATCH_WITH_PERM: u32 = 1 << 22;
    pub const WATCH_READS: u32 = 1 << 23;
}

/// Permission bits for processes
pub mod proc_perms {
    pub const FORK: u32 = 1 << 0;
    pub const TRANSITION: u32 = 1 << 1;
    pub const SIGCHLD: u32 = 1 << 2;
    pub const SIGKILL: u32 = 1 << 3;
    pub const SIGSTOP: u32 = 1 << 4;
    pub const SIGNAL: u32 = 1 << 5;
    pub const PTRACE: u32 = 1 << 6;
    pub const GETSCHED: u32 = 1 << 7;
    pub const SETSCHED: u32 = 1 << 8;
    pub const GETSESSION: u32 = 1 << 9;
    pub const GETPGID: u32 = 1 << 10;
    pub const SETPGID: u32 = 1 << 11;
    pub const GETCAP: u32 = 1 << 12;
    pub const SETCAP: u32 = 1 << 13;
    pub const SHARE: u32 = 1 << 14;
    pub const GETATTR: u32 = 1 << 15;
    pub const SETEXEC: u32 = 1 << 16;
    pub const SETFSCREATE: u32 = 1 << 17;
    pub const NOATSECURE: u32 = 1 << 18;
    pub const SIGINH: u32 = 1 << 19;
    pub const SETRLIMIT: u32 = 1 << 20;
    pub const RLIMITINH: u32 = 1 << 21;
    pub const DYNTRANSITION: u32 = 1 << 22;
    pub const SETCURRENT: u32 = 1 << 23;
    pub const EXECMEM: u32 = 1 << 24;
    pub const EXECSTACK: u32 = 1 << 25;
    pub const EXECHEAP: u32 = 1 << 26;
    pub const SETKEYCREATE: u32 = 1 << 27;
    pub const SETSOCKCREATE: u32 = 1 << 28;
    pub const GETRLIMIT: u32 = 1 << 29;
}

/// Type Enforcement Rule
pub struct TeRule {
    pub source_type: SecurityId,
    pub target_type: SecurityId,
    pub obj_class: ObjClass,
    pub permissions: u32,
    pub rule_type: TeRuleType,
}

#[derive(Debug, Clone, Copy)]
pub enum TeRuleType {
    Allow,
    AuditAllow,
    DontAudit,
    Neverallow,
    TypeTransition,
    TypeChange,
    TypeMember,
}

/// Access Vector Cache (AVC)
pub struct Avc {
    pub entries: [AvcEntry; 4096],
    pub hash_mask: u32,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub sequence: AtomicU32,
}

pub struct AvcEntry {
    pub valid: bool,
    pub source_sid: SecurityId,
    pub target_sid: SecurityId,
    pub obj_class: u16,
    pub allowed: u32,
    pub auditallow: u32,
    pub auditdeny: u32,
    pub sequence: u32,
}

impl Avc {
    pub fn lookup(&self, src: SecurityId, tgt: SecurityId, class: ObjClass) -> Option<u32> {
        let hash = self.hash(src, tgt, class as u16);
        let entry = &self.entries[hash as usize];
        
        if entry.valid && entry.source_sid == src && entry.target_sid == tgt 
            && entry.obj_class == class as u16 {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.allowed)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn insert(&mut self, src: SecurityId, tgt: SecurityId, class: ObjClass, 
                  allowed: u32, auditallow: u32, auditdeny: u32) {
        let hash = self.hash(src, tgt, class as u16);
        let entry = &mut self.entries[hash as usize];
        
        if entry.valid {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        
        entry.valid = true;
        entry.source_sid = src;
        entry.target_sid = tgt;
        entry.obj_class = class as u16;
        entry.allowed = allowed;
        entry.auditallow = auditallow;
        entry.auditdeny = auditdeny;
        entry.sequence = self.sequence.load(Ordering::Relaxed);
    }

    pub fn flush(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn hash(&self, src: SecurityId, tgt: SecurityId, class: u16) -> u32 {
        let h = src.wrapping_mul(2654435761) ^ tgt.wrapping_mul(2246822519) ^ (class as u32).wrapping_mul(3266489917);
        h & self.hash_mask
    }
}

// ============================================================================
// Role-Based Access Control (RBAC)
// ============================================================================

/// Security Role
pub struct SecurityRole {
    pub role_id: SecurityId,
    pub name: [u8; 64],
    pub types: [u64; 16], // 1024 type bits
    pub dominates: [u64; 4], // 256 role bits 
}

impl SecurityRole {
    pub fn has_type(&self, type_id: SecurityId) -> bool {
        let id = type_id as usize;
        if id >= 1024 { return false; }
        self.types[id / 64] & (1u64 << (id % 64)) != 0
    }

    pub fn add_type(&mut self, type_id: SecurityId) {
        let id = type_id as usize;
        if id < 1024 {
            self.types[id / 64] |= 1u64 << (id % 64);
        }
    }

    pub fn dominates_role(&self, role_id: SecurityId) -> bool {
        let id = role_id as usize;
        if id >= 256 { return false; }
        self.dominates[id / 64] & (1u64 << (id % 64)) != 0
    }
}

/// Security User
pub struct SecurityUser {
    pub user_id: SecurityId,
    pub name: [u8; 64],
    pub roles: [u64; 4], // 256 role bits
    pub mls_range: MlsRange,
    pub mls_level: MlsLevel,
}

impl SecurityUser {
    pub fn has_role(&self, role_id: SecurityId) -> bool {
        let id = role_id as usize;
        if id >= 256 { return false; }
        self.roles[id / 64] & (1u64 << (id % 64)) != 0
    }
}

// ============================================================================
// Security Policy
// ============================================================================

/// Policy version
pub const POLICYDB_VERSION: u32 = 33;
pub const POLICYDB_CAP_IOCTL_ALL: u32 = 9;

/// Security policy database
pub struct PolicyDb {
    pub version: u32,
    pub handle: u32,
    
    // Type enforcement rules
    pub te_rules: [Option<TeRule>; 8192],
    pub te_rule_count: u32,
    
    // Conditional rules
    pub cond_rules: [Option<ConditionalRule>; 1024],
    pub cond_rule_count: u32,
    
    // Boolean settings
    pub booleans: [PolicyBoolean; 256],
    pub bool_count: u32,
    
    // Role allow rules
    pub role_allow: [(SecurityId, SecurityId); 512],
    pub role_allow_count: u32,
    
    // Role transitions
    pub role_trans: [RoleTransition; 256],
    pub role_trans_count: u32,
    
    // Type attributes
    pub type_attrs: [TypeAttribute; 1024],
    pub type_attr_count: u32,
    
    // File contexts
    pub file_contexts: [FileContext; 2048],
    pub file_context_count: u32,
    
    // Policy capabilities
    pub policycap: u32,
    
    // Statistics
    pub allow_count: u32,
    pub deny_count: u32,
    pub audit_count: u32,
}

pub struct ConditionalRule {
    pub boolean_id: u32,
    pub expression: CondExpr,
    pub true_rules: [u16; 16], // indices into te_rules
    pub true_count: u8,
    pub false_rules: [u16; 16],
    pub false_count: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum CondExpr {
    Bool(u32),
    Not(u32),
    And(u32, u32),
    Or(u32, u32),
    Xor(u32, u32),
    Eq(u32, u32),
    Neq(u32, u32),
}

pub struct PolicyBoolean {
    pub name: [u8; 64],
    pub state: AtomicBool,
    pub default_state: bool,
}

pub struct RoleTransition {
    pub source_role: SecurityId,
    pub target_type: SecurityId,
    pub obj_class: u16,
    pub new_role: SecurityId,
}

pub struct TypeAttribute {
    pub type_id: SecurityId,
    pub name: [u8; 64],
    pub attributes: [u64; 16], // 1024 attribute bits
    pub is_attribute: bool,
    pub is_alias: bool,
    pub primary: SecurityId,
}

pub struct FileContext {
    pub path_regex: [u8; 256],
    pub path_len: u16,
    pub file_type: FileContextType,
    pub context: SecurityId,
}

#[derive(Debug, Clone, Copy)]
pub enum FileContextType {
    All,
    RegularFile,
    Directory,
    CharDevice,
    BlockDevice,
    Socket,
    SymLink,
    Pipe,
}

// ============================================================================
// Sandbox Framework (Landlock-like)
// ============================================================================

/// Sandbox ruleset
pub struct Sandbox {
    pub id: u32,
    pub owner_pid: u32,
    pub rules: [SandboxRule; 256],
    pub rule_count: u32,
    pub fs_access_mask: u32,
    pub net_access_mask: u32,
    pub active: bool,
    pub nested_level: u8,
    pub parent_id: Option<u32>,
    pub stats: SandboxStats,
}

/// Sandbox rule
pub struct SandboxRule {
    pub rule_type: SandboxRuleType,
    pub access: u32,
    pub object: SandboxObject,
}

#[derive(Debug, Clone, Copy)]
pub enum SandboxRuleType {
    PathBeneath,
    PathExact,
    NetPort,
    NetAddr,
    // Zxyphor
    DeviceAccess,
    SyscallFilter,
    ResourceLimit,
}

pub enum SandboxObject {
    Path { inode: u64, dev: u64 },
    NetPort { proto: u8, port: u16 },
    NetAddr { addr: [u8; 16], mask: u8 },
    Device { major: u16, minor: u16 },
    Syscall { nr: u32 },
}

/// Filesystem access rights for sandboxing
pub mod sandbox_fs {
    pub const EXECUTE: u32 = 1 << 0;
    pub const WRITE_FILE: u32 = 1 << 1;
    pub const READ_FILE: u32 = 1 << 2;
    pub const READ_DIR: u32 = 1 << 3;
    pub const REMOVE_DIR: u32 = 1 << 4;
    pub const REMOVE_FILE: u32 = 1 << 5;
    pub const MAKE_CHAR: u32 = 1 << 6;
    pub const MAKE_DIR: u32 = 1 << 7;
    pub const MAKE_REG: u32 = 1 << 8;
    pub const MAKE_SOCK: u32 = 1 << 9;
    pub const MAKE_FIFO: u32 = 1 << 10;
    pub const MAKE_BLOCK: u32 = 1 << 11;
    pub const MAKE_SYM: u32 = 1 << 12;
    pub const REFER: u32 = 1 << 13;
    pub const TRUNCATE: u32 = 1 << 14;
    pub const IOCTL_DEV: u32 = 1 << 15;
}

/// Network access rights
pub mod sandbox_net {
    pub const BIND_TCP: u32 = 1 << 0;
    pub const CONNECT_TCP: u32 = 1 << 1;
    pub const BIND_UDP: u32 = 1 << 2;
    pub const CONNECT_UDP: u32 = 1 << 3;
    pub const LISTEN: u32 = 1 << 4;
    pub const ACCEPT: u32 = 1 << 5;
}

pub struct SandboxStats {
    pub operations_checked: AtomicU64,
    pub operations_denied: AtomicU64,
    pub operations_allowed: AtomicU64,
}

impl SandboxStats {
    pub const fn new() -> Self {
        SandboxStats {
            operations_checked: AtomicU64::new(0),
            operations_denied: AtomicU64::new(0),
            operations_allowed: AtomicU64::new(0),
        }
    }
}

impl Sandbox {
    pub fn check_fs_access(&self, inode: u64, dev: u64, access: u32) -> bool {
        self.stats.operations_checked.fetch_add(1, Ordering::Relaxed);
        
        // If access type is not in the mask, it's allowed
        if access & self.fs_access_mask == 0 {
            self.stats.operations_allowed.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        
        // Check rules
        for i in 0..self.rule_count as usize {
            if let SandboxObject::Path { inode: rule_inode, dev: rule_dev } = self.rules[i].object {
                if rule_inode == inode && rule_dev == dev {
                    if self.rules[i].access & access == access {
                        self.stats.operations_allowed.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                }
            }
        }
        
        self.stats.operations_denied.fetch_add(1, Ordering::Relaxed);
        false
    }

    pub fn check_net_access(&self, proto: u8, port: u16, access: u32) -> bool {
        self.stats.operations_checked.fetch_add(1, Ordering::Relaxed);
        
        if access & self.net_access_mask == 0 {
            self.stats.operations_allowed.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        
        for i in 0..self.rule_count as usize {
            if let SandboxObject::NetPort { proto: rule_proto, port: rule_port } = self.rules[i].object {
                if rule_proto == proto && rule_port == port {
                    if self.rules[i].access & access == access {
                        self.stats.operations_allowed.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                }
            }
        }
        
        self.stats.operations_denied.fetch_add(1, Ordering::Relaxed);
        false
    }
}

// ============================================================================
// Secure Boot Chain
// ============================================================================

/// Secure boot state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecureBootState {
    NotEnabled,
    SetupMode,
    UserMode,
    AuditMode,
    DeployedMode,
}

/// Key database
pub struct KeyDatabase {
    pub platform_keys: [SecureBootKey; 8], // PK
    pub pk_count: u8,
    pub kek_keys: [SecureBootKey; 32], // KEK
    pub kek_count: u8,
    pub db_keys: [SecureBootKey; 256], // db (allowed)
    pub db_count: u16,
    pub dbx_hashes: [SecureBootHash; 1024], // dbx (revoked)
    pub dbx_count: u16,
    pub mok_keys: [SecureBootKey; 64], // MOK (Machine Owner Keys)
    pub mok_count: u8,
}

pub struct SecureBootKey {
    pub key_type: KeyType,
    pub data: [u8; 4096],
    pub data_len: u16,
    pub owner: [u8; 16], // GUID
    pub attributes: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    Ecdsa256,
    Ecdsa384,
    Ed25519,
    X509Certificate,
}

pub struct SecureBootHash {
    pub algorithm: HashAlgorithm,
    pub hash: [u8; 64],
    pub hash_len: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Blake3,
}

/// Integrity Measurement Architecture (IMA)
pub struct ImaPolicy {
    pub rules: [ImaRule; 512],
    pub rule_count: u32,
    pub pcr_extend: bool,
    pub appraise: bool,
    pub audit: bool,
    pub hash_algo: HashAlgorithm,
}

pub struct ImaRule {
    pub action: ImaAction,
    pub mask: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub fowner: Option<u32>,
    pub fgroup: Option<u32>,
    pub obj_type: Option<[u8; 64]>,
    pub func: ImaFunc,
    pub pcr: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum ImaAction {
    Dont,
    Measure,
    Appraise,
    Audit,
    Hash,
}

#[derive(Debug, Clone, Copy)]
pub enum ImaFunc {
    FileCheck,
    MmapCheck,
    BprmCheck,
    CrtdCheck,
    PostSetattr,
    ModuleCheck,
    FirmwareCheck,
    PolicyCheck,
    KexecKernelCheck,
    KexecInitramfsCheck,
    KexecCmdline,
    KeyCheck,
}

/// Measurement list
pub struct MeasurementList {
    pub entries: [MeasurementEntry; 4096],
    pub count: u32,
    pub pcr_values: [PcrValue; 24], // PCR 0-23
}

pub struct MeasurementEntry {
    pub pcr: u8,
    pub hash: [u8; 64],
    pub hash_len: u8,
    pub template: MeasurementTemplate,
    pub filename: [u8; 256],
    pub filename_len: u16,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum MeasurementTemplate {
    Ima,        // hash of file contents
    ImaNg,      // hash algo + hash
    ImaSig,     // hash + signature
    ImaBuf,     // buffer measurement
    ImaMoesig,  // hash + portable signature
}

pub struct PcrValue {
    pub value: [u8; 64],
    pub algo: HashAlgorithm,
    pub extend_count: u32,
}

// ============================================================================
// Audit Framework
// ============================================================================

/// Audit message types
#[derive(Debug, Clone, Copy)]
pub enum AuditType {
    // User-space messages
    UserAuth = 1100,
    UserAcct = 1101,
    UserMgmt = 1103,
    Cred = 1104,
    UserLogin = 1112,
    UserLogout = 1113,
    // Kernel messages
    AvcDenied = 1400,
    AvcGranted = 1401,
    SelinuxErr = 1401,
    AnomalyPromiscuous = 1700,
    AnomalyAbend = 1701,
    Integrity = 1800,
    // Zxyphor
    ZxySandboxDenied = 2400,
    ZxySecureEnclave = 2401,
    ZxyIntegrityViolation = 2402,
}

/// Audit record
pub struct AuditRecord {
    pub msg_type: AuditType,
    pub serial: u64,
    pub timestamp: u64,
    pub result: AuditResult,
    pub subject: SecurityId,
    pub object: SecurityId,
    pub obj_class: ObjClass,
    pub requested: u32,
    pub denied: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tty: [u8; 16],
    pub comm: [u8; 16],
    pub exe: [u8; 256],
    pub path: [u8; 256],
    pub scontext: [u8; 128],
    pub tcontext: [u8; 128],
}

#[derive(Debug, Clone, Copy)]
pub enum AuditResult {
    Granted,
    Denied,
    Error,
}

/// Audit subsystem state
pub struct AuditState {
    pub enabled: AtomicBool,
    pub backlog_limit: AtomicU32,
    pub backlog: AtomicU32,
    pub lost: AtomicU64,
    pub serial: AtomicU64,
    pub rate_limit: AtomicU32,
    pub failure_mode: AuditFailure,
}

#[derive(Debug, Clone, Copy)]
pub enum AuditFailure {
    Silent = 0,
    Printk = 1,
    Panic = 2,
}

impl AuditState {
    pub const fn new() -> Self {
        AuditState {
            enabled: AtomicBool::new(true),
            backlog_limit: AtomicU32::new(8192),
            backlog: AtomicU32::new(0),
            lost: AtomicU64::new(0),
            serial: AtomicU64::new(0),
            rate_limit: AtomicU32::new(0),
            failure_mode: AuditFailure::Printk,
        }
    }

    pub fn next_serial(&self) -> u64 {
        self.serial.fetch_add(1, Ordering::Relaxed)
    }

    pub fn log(&self, record: &AuditRecord) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }
        
        let backlog = self.backlog.load(Ordering::Relaxed);
        let limit = self.backlog_limit.load(Ordering::Relaxed);
        
        if backlog >= limit {
            self.lost.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        self.backlog.fetch_add(1, Ordering::Relaxed);
        true
    }
}

static AUDIT_STATE: AuditState = AuditState::new();

pub fn get_audit_state() -> &'static AuditState {
    &AUDIT_STATE
}
