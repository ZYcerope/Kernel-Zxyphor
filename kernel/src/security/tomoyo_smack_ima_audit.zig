// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - TOMOYO, Smack, IMA/EVM Detail, Audit Log Format
// TOMOYO policy, Smack labels, IMA measurement/appraisal,
// EVM digital signatures, audit record format

const std = @import("std");

// ============================================================================
// TOMOYO Security Module
// ============================================================================

pub const TomoyoProfileMode = enum(u8) {
    Disabled = 0,
    Learning = 1,
    Permissive = 2,
    Enforcing = 3,
};

pub const TomoyoMacType = enum(u8) {
    FileExecute = 0,
    FileOpen = 1,
    FileCreate = 2,
    FileUnlink = 3,
    FileGetattr = 4,
    FileMkdir = 5,
    FileRmdir = 6,
    FileMkfifo = 7,
    FileMksock = 8,
    FileTruncate = 9,
    FileSymlink = 10,
    FileRewrite = 11,
    FileChroot = 12,
    FileMount = 13,
    FileUmount = 14,
    FilePivotRoot = 15,
    NetInetStreamBind = 16,
    NetInetStreamListen = 17,
    NetInetStreamConnect = 18,
    NetInetDgramBind = 19,
    NetInetDgramSend = 20,
    NetInetRawBind = 21,
    NetInetRawSend = 22,
    NetUnixStreamBind = 23,
    NetUnixStreamListen = 24,
    NetUnixStreamConnect = 25,
    NetUnixDgramBind = 26,
    NetUnixDgramSend = 27,
    NetUnixSeqpacketBind = 28,
    NetUnixSeqpacketListen = 29,
    NetUnixSeqpacketConnect = 30,
    EnvironVarEntry = 31,
    CapabilityUseRootPriv = 32,
    InodeOwner = 33,
    TaskManual = 34,
    MaxMac = 35,
};

pub const TomoyoDomainInfo = struct {
    name: [512]u8,
    name_len: u32,
    profile: u8,
    mode: TomoyoProfileMode,
    flags: TomoyoDomainFlags,
    acl_count: u32,
    transition_count: u32,
    is_deleted: bool,
};

pub const TomoyoDomainFlags = packed struct(u32) {
    quota_warned: bool = false,
    transition_failed: bool = false,
    ignore_global: bool = false,
    _reserved: u29 = 0,
};

pub const TomoyoPolicy = struct {
    version: u32,
    total_domains: u32,
    total_acls: u32,
    total_exception_rules: u32,
    learning_entries: u32,
    enforcing_violations: u64,
    permissive_violations: u64,
    profile_count: u8,
    profiles: [4]TomoyoProfileMode,
};

// ============================================================================
// Smack (Simplified Mandatory Access Control Kernel)
// ============================================================================

pub const SmackLabelMaxLen: u32 = 255;

pub const SmackLabel = struct {
    label: [256]u8,
    label_len: u8,
};

pub const SmackAccessType = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    append: bool = false,
    transmute: bool = false,
    lock: bool = false,
    bring_up: bool = false,
    _reserved: u25 = 0,
};

pub const SmackRule = struct {
    subject: SmackLabel,
    object: SmackLabel,
    access: SmackAccessType,
};

pub const SmackKnownLabel = enum(u8) {
    Huh = 0,       // "_"
    Hat = 1,        // "^"
    Star = 2,       // "*"
    Floor = 3,      // "@"
    Web = 4,        // "!"
    Invalid = 5,    // "\0"
};

pub const SmackCifsMount = struct {
    domain: SmackLabel,
    has_transmute: bool,
};

pub const SmackNetlabel = struct {
    addr: u32,      // IPv4
    addr6: [16]u8,  // IPv6
    mask_bits: u8,
    label: SmackLabel,
};

pub const SmackConfig = struct {
    enabled: bool,
    default_label: SmackLabel,
    floor_label: SmackLabel,
    onlycap_label: SmackLabel,
    unconfined_label: SmackLabel,
    total_rules: u32,
    total_labels: u32,
    total_netlabels: u32,
    cipso_enabled: bool,
    enforce: bool,
};

// ============================================================================
// IMA (Integrity Measurement Architecture)
// ============================================================================

pub const ImaAction = enum(u8) {
    Dont = 0,
    Measure = 1,
    Appraise = 2,
    Hash = 3,
    MeasureAndAppraise = 4,
    Audit = 5,
};

pub const ImaFunc = enum(u8) {
    None = 0,
    FileCheck = 1,
    MmapCheck = 2,
    BprmCheck = 3,
    CtimeCheck = 4,
    PostSetattr = 5,
    ModuleCheck = 6,
    FirmwareCheck = 7,
    KexecKernelCheck = 8,
    KexecInitramfsCheck = 9,
    PolicyCheck = 10,
    Setxattr = 11,
    KeyCheck = 12,
    CriticalData = 13,
};

pub const ImaHashAlgo = enum(u8) {
    Sha1 = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
    Sm3 = 4,
    Sha3_256 = 5,
    Sha3_384 = 6,
    Sha3_512 = 7,
};

pub const ImaPolicyEntry = struct {
    action: ImaAction,
    func: ImaFunc,
    mask: u32,
    uid: i32,      // -1 for any
    fowner: i32,
    fsuuid: [16]u8,
    pcr: u8,
    hash_algo: ImaHashAlgo,
    flags: ImaPolicyFlags,
    label: [256]u8,
    label_len: u32,
};

pub const ImaPolicyFlags = packed struct(u32) {
    uid_set: bool = false,
    fowner_set: bool = false,
    fsuuid_set: bool = false,
    label_set: bool = false,
    modsig_allowed: bool = false,
    check_blacklist: bool = false,
    permit_directio: bool = false,
    _reserved: u25 = 0,
};

pub const ImaMeasurement = struct {
    pcr: u8,
    digest: [64]u8,   // max SHA-512
    digest_len: u8,
    algo: ImaHashAlgo,
    filename: [256]u8,
    filename_len: u32,
    template_name: [32]u8,
    entry_num: u64,
};

pub const ImaTemplate = enum(u8) {
    ImaNG = 0,      // d-ng|n-ng
    ImaSIG = 1,     // d-ng|n-ng|sig
    ImaBUF = 2,     // d-ng|n-ng|buf
    ImaModSig = 3,  // d-ng|n-ng|sig|d-modsig
};

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

pub const EvmMode = enum(u8) {
    Disabled = 0,
    FixMode = 1,
    PortableMode = 2,
    EnforceMode = 3,
};

pub const EvmImaXattrType = enum(u8) {
    ImaXattrDigest = 0x01,
    ImaXattrDigestNG = 0x02,
    EvmXattrHmac = 0x03,
    EvmXattrPortableSig = 0x04,
    ImaModSig = 0x05,
    EvmImaXattrDigsig = 0x06,
};

pub const EvmProtectedXattrs = [_][]const u8{
    "security.selinux",
    "security.SMACK64",
    "security.SMACK64EXEC",
    "security.SMACK64TRANSMUTE",
    "security.SMACK64MMAP",
    "security.apparmor",
    "security.ima",
    "security.capability",
};

pub const EvmDigest = struct {
    algo: ImaHashAlgo,
    digest: [64]u8,
    digest_len: u8,
    xattr_type: EvmImaXattrType,
};

pub const EvmConfig = struct {
    mode: EvmMode,
    hash_algo: ImaHashAlgo,
    hmac_key_loaded: bool,
    rsa_key_loaded: bool,
    total_hmac_verifications: u64,
    total_sig_verifications: u64,
    total_failures: u64,
    portable_sigs: bool,
};

// ============================================================================
// Audit Log Format
// ============================================================================

pub const AuditMsgType = enum(u16) {
    // 1000-1099: kernel general
    Syscall = 1300,
    Path = 1302,
    Ipc = 1303,
    Socketcall = 1304,
    Config = 1305,
    Sockaddr = 1306,
    Cwd = 1307,
    ExecveArg = 1309,
    IpcSetPerm = 1311,
    MqSendRecv = 1313,
    MqNotify = 1314,
    MqGetSetAttr = 1315,
    ProcTitle = 1327,
    FeatureChange = 1328,
    ReplaceAll = 1329,
    KernModule = 1330,
    FanotifyResp = 1331,
    TimeAdjntx = 1333,
    TimeInjOff = 1334,
    Bpf = 1334,
    Event = 1335,
    // 1400-1499: SELinux
    AvcDecision = 1400,
    SelinuxErr = 1401,
    AvcPath = 1402,
    // 1500-1599: AppArmor
    ApparmorAudit = 1501,
    ApparmorAllowed = 1502,
    ApparmorDenied = 1503,
    ApparmorHint = 1504,
    ApparmorStatus = 1505,
    ApparmorError = 1506,
    // 1600-1699: crypto
    CryptoParamChangeUser = 1606,
    // 1700-1799: IMA/Integrity
    IntegrityData = 1800,
    IntegrityMetadata = 1801,
    IntegrityStatus = 1802,
    IntegrityHash = 1803,
    IntegrityPcrValue = 1804,
    IntegrityRule = 1805,
    IntegrityEvmXattr = 1806,
    IntegrityPolicy = 1807,
    // 2100+: anomaly
    Anomaly = 2100,
    AnomalyLink = 2101,
    AnomalyPromiscuous = 2102,
    // 2200+: response
    ResponseAnom = 2200,
    // Kernel events
    AuditFirst = 1000,
    AuditLast = 2999,
};

pub const AuditRecord = struct {
    msg_type: AuditMsgType,
    serial: u64,
    timestamp_sec: u64,
    timestamp_nsec: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    auid: u32,       // audit/login UID
    gid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,
    ses: u32,         // session ID
    tty: [16]u8,
    comm: [16]u8,
    exe: [256]u8,
    subj: [256]u8,    // SELinux context
    key: [256]u8,     // audit filter key
    success: bool,
    exit_code: i32,
};

pub const AuditSyscallRecord = struct {
    base: AuditRecord,
    syscall: u32,
    arch: u32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    items: u32,       // number of path records
};

pub const AuditPathRecord = struct {
    item: u32,
    name: [256]u8,
    name_len: u32,
    inode: u64,
    dev: u32,
    mode: u32,
    ouid: u32,
    ogid: u32,
    rdev: u32,
    nametype: AuditNameType,
    obj: [256]u8,     // SELinux object context
};

pub const AuditNameType = enum(u8) {
    Normal = 0,
    Parent = 1,
    Child = 2,
    Unknown = 3,
};

pub const AuditFilterType = enum(u8) {
    User = 0,
    Task = 1,
    Entry = 2,
    Watch = 3,
    Exit = 4,
    Exclude = 5,
    FsType = 6,
};

pub const AuditConfig = struct {
    enabled: bool,
    failure_action: AuditFailAction,
    rate_limit: u32,
    backlog_limit: u32,
    backlog: u32,
    lost: u64,
    loginuid_immutable: bool,
    pid: u32,
    total_events: u64,
    total_lost: u64,
};

pub const AuditFailAction = enum(u8) {
    Silent = 0,
    Printk = 1,
    Panic = 2,
};

// ============================================================================
// Security Module Manager
// ============================================================================

pub const SecurityModulesManager = struct {
    tomoyo: TomoyoPolicy,
    smack: SmackConfig,
    ima_measurements: u64,
    ima_violations: u64,
    ima_policy_entries: u32,
    evm_config: EvmConfig,
    audit_config: AuditConfig,
    initialized: bool,

    pub fn init() SecurityModulesManager {
        return .{
            .tomoyo = .{
                .version = 2,
                .total_domains = 0,
                .total_acls = 0,
                .total_exception_rules = 0,
                .learning_entries = 0,
                .enforcing_violations = 0,
                .permissive_violations = 0,
                .profile_count = 4,
                .profiles = [_]TomoyoProfileMode{.Disabled} ** 4,
            },
            .smack = .{
                .enabled = false,
                .default_label = undefined,
                .floor_label = undefined,
                .onlycap_label = undefined,
                .unconfined_label = undefined,
                .total_rules = 0,
                .total_labels = 0,
                .total_netlabels = 0,
                .cipso_enabled = false,
                .enforce = true,
            },
            .ima_measurements = 0,
            .ima_violations = 0,
            .ima_policy_entries = 0,
            .evm_config = .{
                .mode = .Disabled,
                .hash_algo = .Sha256,
                .hmac_key_loaded = false,
                .rsa_key_loaded = false,
                .total_hmac_verifications = 0,
                .total_sig_verifications = 0,
                .total_failures = 0,
                .portable_sigs = false,
            },
            .audit_config = .{
                .enabled = false,
                .failure_action = .Printk,
                .rate_limit = 0,
                .backlog_limit = 8192,
                .backlog = 0,
                .lost = 0,
                .loginuid_immutable = false,
                .pid = 0,
                .total_events = 0,
                .total_lost = 0,
            },
            .initialized = true,
        };
    }
};
