// Zxyphor Kernel - AppArmor Policy Engine Detail & IMA/EVM
// AppArmor: profiles, policy tree, rule matching, path mediation
// Capability mediation, network mediation, mount mediation
// IMA: measurement list, appraisal, policy rules, event types
// EVM: extended verification, HMAC/signature, portable signatures
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// AppArmor Profile Types
// ============================================================================

pub const ProfileMode = enum(u8) {
    unconfined = 0,
    enforce = 1,
    complain = 2,
    kill = 3,
    unconfined_hat = 4,
};

pub const ProfileFlags = packed struct(u32) {
    hat: bool = false,
    null_profile: bool = false,
    unconfined: bool = false,
    no_list_ref: bool = false,
    user_defined: bool = false,
    debug1: bool = false,
    debug2: bool = false,
    immutable: bool = false,
    mediate_deleted: bool = false,
    stacked: bool = false,
    ns_root: bool = false,
    delegation: bool = false,
    _pad: u20 = 0,
};

pub const AaProfile = struct {
    name: [256]u8,
    name_len: u32,
    ns: ?*AaNamespace,
    parent: ?*AaProfile,
    mode: ProfileMode,
    flags: ProfileFlags,
    // Reference counting
    count: u32,
    // Policy components
    file_rules: AaFileRules,
    cap_rules: AaCapRules,
    net_rules: AaNetRules,
    mount_rules: AaMountRules,
    dbus_rules: AaDbusRules,
    signal_rules: AaSignalRules,
    ptrace_rules: AaPtraceRules,
    rlimit_rules: AaRlimitRules,
    // Attachment
    attach: AaAttachInfo,
    // DFA for path matching
    dfa: ?*AaDfa,
    // Audit
    audit: AaAuditPolicy,
    // Stats
    complain_count: u64,
    deny_count: u64,
    allow_count: u64,
};

// ============================================================================
// AppArmor Namespace
// ============================================================================

pub const AaNamespace = struct {
    name: [128]u8,
    parent: ?*AaNamespace,
    level: u32,
    profile_count: u32,
    sub_ns_count: u32,
    unconfined: ?*AaProfile,
    revision: u64,
};

// ============================================================================
// AppArmor File Rules
// ============================================================================

pub const FilePermissions = packed struct(u32) {
    exec: bool = false,
    write: bool = false,
    read: bool = false,
    append: bool = false,
    link: bool = false,
    lock: bool = false,
    exec_mmap: bool = false,
    create: bool = false,
    delete: bool = false,
    rename_src: bool = false,
    rename_dest: bool = false,
    chmod: bool = false,
    chown: bool = false,
    setattr: bool = false,
    getattr: bool = false,
    chgrp: bool = false,
    // exec transitions
    exec_inherit: bool = false,
    exec_profile: bool = false,
    exec_child: bool = false,
    exec_unconfined: bool = false,
    exec_unsafe: bool = false,
    exec_stack: bool = false,
    _pad: u10 = 0,
};

pub const AaFileRules = struct {
    dfa: ?*AaDfa,
    rule_count: u32,
    default_allow: FilePermissions,
    default_deny: FilePermissions,
};

// ============================================================================
// AppArmor Capability Rules
// ============================================================================

pub const AaCapRules = struct {
    allow: [2]u32,    // capability bits (64 capabilities)
    audit: [2]u32,
    deny: [2]u32,
    quiet: [2]u32,
};

pub const LinuxCapability = enum(u8) {
    chown = 0,
    dac_override = 1,
    dac_read_search = 2,
    fowner = 3,
    fsetid = 4,
    kill = 5,
    setgid = 6,
    setuid = 7,
    setpcap = 8,
    linux_immutable = 9,
    net_bind_service = 10,
    net_broadcast = 11,
    net_admin = 12,
    net_raw = 13,
    ipc_lock = 14,
    ipc_owner = 15,
    sys_module = 16,
    sys_rawio = 17,
    sys_chroot = 18,
    sys_ptrace = 19,
    sys_pacct = 20,
    sys_admin = 21,
    sys_boot = 22,
    sys_nice = 23,
    sys_resource = 24,
    sys_time = 25,
    sys_tty_config = 26,
    mknod = 27,
    lease = 28,
    audit_write = 29,
    audit_control = 30,
    setfcap = 31,
    mac_override = 32,
    mac_admin = 33,
    syslog = 34,
    wake_alarm = 35,
    block_suspend = 36,
    audit_read = 37,
    perfmon = 38,
    bpf = 39,
    checkpoint_restore = 40,
};

// ============================================================================
// AppArmor Network Rules
// ============================================================================

pub const AaNetRules = struct {
    allow: [46]u32,    // per address family access mask
    audit: [46]u32,
    deny: [46]u32,
    quiet: [46]u32,
};

pub const AaNetPerm = packed struct(u32) {
    create: bool = false,
    bind_port: bool = false,
    connect: bool = false,
    listen: bool = false,
    accept: bool = false,
    send: bool = false,
    receive: bool = false,
    getsockopt: bool = false,
    setsockopt: bool = false,
    getattr: bool = false,
    setattr: bool = false,
    shutdown: bool = false,
    _pad: u20 = 0,
};

// ============================================================================
// AppArmor Mount Rules
// ============================================================================

pub const AaMountRules = struct {
    rule_count: u32,
    default_allow: MountPerms,
    default_deny: MountPerms,
};

pub const MountPerms = packed struct(u16) {
    mount: bool = false,
    remount: bool = false,
    umount: bool = false,
    pivot_root: bool = false,
    bind: bool = false,
    move: bool = false,
    rbind: bool = false,
    make_shared: bool = false,
    make_slave: bool = false,
    make_private: bool = false,
    make_unbindable: bool = false,
    make_runbindable: bool = false,
    _pad: u4 = 0,
};

// ============================================================================
// AppArmor D-Bus Rules
// ============================================================================

pub const AaDbusRules = struct {
    rule_count: u32,
};

pub const DbusPerms = packed struct(u8) {
    send: bool = false,
    receive: bool = false,
    bind: bool = false,
    eavesdrop: bool = false,
    _pad: u4 = 0,
};

// ============================================================================
// AppArmor Signal Rules
// ============================================================================

pub const AaSignalRules = struct {
    rule_count: u32,
    allow_mask: u64,
    deny_mask: u64,
};

// ============================================================================
// AppArmor Ptrace Rules
// ============================================================================

pub const AaPtraceRules = struct {
    allow: PtracePerms,
    deny: PtracePerms,
};

pub const PtracePerms = packed struct(u8) {
    trace: bool = false,
    read: bool = false,
    traceby: bool = false,
    readby: bool = false,
    _pad: u4 = 0,
};

// ============================================================================
// AppArmor Rlimit Rules
// ============================================================================

pub const AaRlimitRules = struct {
    mask: u32,  // which rlimits to restrict
    limits: [16]u64,
};

// ============================================================================
// AppArmor Attachment
// ============================================================================

pub const AaAttachInfo = struct {
    xmatch: ?*AaDfa,
    xmatch_len: u32,
    xattrs_count: u32,
};

// ============================================================================
// AppArmor DFA (Deterministic Finite Automaton)
// ============================================================================

pub const AaDfaFlags = packed struct(u16) {
    null_trans: bool = false,
    case_insensitive: bool = false,
    _pad: u14 = 0,
};

pub const AaDfa = struct {
    flags: AaDfaFlags,
    start: [4]u32,
    table_count: u32,
    tables: ?[*]AaDfaTable,
};

pub const AaDfaTable = struct {
    td_id: u16,
    td_flags: u16,
    td_lolen: u32,
    td_data: ?[*]u8,
};

// ============================================================================
// AppArmor Audit Policy
// ============================================================================

pub const AaAuditPolicy = struct {
    allow: u32,  // audit allowed accesses
    deny: u32,   // quiet denied accesses
};

// ============================================================================
// IMA (Integrity Measurement Architecture)
// ============================================================================

pub const ImaAction = enum(u8) {
    dont_measure = 0,
    measure = 1,
    dont_appraise = 2,
    appraise = 3,
    audit = 4,
    hash = 5,
    dont_hash = 6,
};

pub const ImaHook = enum(u8) {
    file_check = 0,
    mmap_check = 1,
    bprm_check = 2,
    creds_check = 3,
    post_setattr = 4,
    module_check = 5,
    firmware_check = 6,
    kexec_kernel_check = 7,
    kexec_initramfs_check = 8,
    policy_check = 9,
    kexec_cmdline = 10,
    key_check = 11,
    critical_data = 12,
    setxattr_check = 13,
};

pub const ImaHashAlgo = enum(u8) {
    md5 = 0,
    sha1 = 1,
    ripemd160 = 2,
    sha256 = 3,
    sha384 = 4,
    sha512 = 5,
    sha224 = 6,
    sm3_256 = 7,
    streebog_256 = 8,
    streebog_512 = 9,
};

pub const ImaPolicyFlags = packed struct(u32) {
    action: bool = false,
    func: bool = false,
    mask: bool = false,
    fsmagic: bool = false,
    fsuuid: bool = false,
    uid: bool = false,
    euid: bool = false,
    gid: bool = false,
    egid: bool = false,
    fowner: bool = false,
    fgroup: bool = false,
    lsm: bool = false,
    label: bool = false,
    digest: bool = false,
    modsig_allowed: bool = false,
    pcr: u4 = 0,
    _pad: u13 = 0,
};

pub const ImaPolicyRule = struct {
    action: ImaAction,
    hook: ImaHook,
    flags: ImaPolicyFlags,
    mask: u32,
    uid_val: u32,
    gid_val: u32,
    fowner_val: u32,
    fsmagic: u64,
    fsuuid: [16]u8,
    hash_algo: ImaHashAlgo,
    pcr: u8,
    lsm_label: [128]u8,
    lsm_label_len: u32,
    keyrings: [128]u8,
    keyrings_len: u32,
};

// ============================================================================
// IMA Measurement List
// ============================================================================

pub const ImaMeasurement = struct {
    pcr: u8,
    digest: [64]u8,  // max hash digest size
    digest_len: u8,
    hash_algo: ImaHashAlgo,
    template_name: [32]u8,
    template_data_len: u32,
    // File info
    filename: [256]u8,
    filename_len: u32,
    event_name: [128]u8,
    // Security
    sig: ?[*]u8,
    sig_len: u32,
};

pub const ImaTemplate = struct {
    name: [32]u8,
    num_fields: u8,
    field_names: [8][16]u8,
};

pub const ImaTemplateField = enum(u8) {
    d = 0,        // digest (SHA1/SHA256)
    n = 1,        // filename hint
    d_ng = 2,     // digest with algo
    n_ng = 3,     // full pathname
    sig = 4,      // file signature
    buf = 5,      // buffer data
    d_modsig = 6, // module appended signature digest
    modsig = 7,   // module appended signature
    evmsig = 8,   // EVM signature
    iuid = 9,     // inode UID
    igid = 10,    // inode GID
    imode = 11,   // inode mode
};

// ============================================================================
// IMA Appraisal
// ============================================================================

pub const ImaAppraisalStatus = enum(u8) {
    unknown = 0,
    pass = 1,
    pass_immutable = 2,
    fail = 3,
    no_data = 4,
    error = 5,
};

pub const ImaDigest = struct {
    algo: ImaHashAlgo,
    length: u8,
    digest_type: ImaDigestType,
    digest: [64]u8,
};

pub const ImaDigestType = enum(u8) {
    verity = 0,
    ima = 1,
    none = 0xFF,
};

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

pub const EvmConfig = struct {
    evm_initialized: bool,
    evm_hmac: bool,
    evm_signature: bool,
    evm_portable: bool,
};

pub const EvmImaXattrType = enum(u8) {
    evm_xattr_hmac = 1,
    evm_xattr_portable_digsig = 5,
    evm_ino_hash_algo = 6,
    ima_xattr_digest = 0x01,
    ima_xattr_digest_ng = 0x04,
    ima_xattr_digsig = 0x03,
    ima_xattr_modsig = 0x05,
};

pub const EvmHmacData = struct {
    hmac_algo: ImaHashAlgo,
    i_ino: u64,
    i_generation: u32,
    i_uid: u32,
    i_gid: u32,
    i_mode: u16,
    s_uuid: [16]u8,
    fsuuid: [16]u8,
};

pub const EvmDigsig = struct {
    version: u8,    // 2
    hash_algo: ImaHashAlgo,
    keyid: u32,
    sig_size: u16,
    sig: [512]u8,
};

pub const EvmXattrsToProtect = struct {
    pub const XATTRS: []const []const u8 = &.{
        "security.selinux",
        "security.apparmor",
        "security.ima",
        "security.SMACK64",
        "security.capability",
    };
};

// ============================================================================
// AppArmor/IMA/EVM Statistics
// ============================================================================

pub const ApparmorStats = struct {
    profile_count: u64,
    namespace_count: u32,
    enforced_count: u32,
    complain_count: u32,
    kill_count: u32,
    unconfined_count: u32,
    total_allow: u64,
    total_deny: u64,
    total_audit: u64,
    dfa_match_count: u64,
    cache_hits: u64,
    cache_misses: u64,
};

pub const ImaStats = struct {
    total_measurements: u64,
    total_violations: u64,
    total_appraisals: u64,
    appraisal_pass: u64,
    appraisal_fail: u64,
    runtime_measurements_count: u64,
    violations_count: u64,
    hash_time_total_ns: u64,
};

pub const EvmStats = struct {
    hmac_verifications: u64,
    sig_verifications: u64,
    hmac_pass: u64,
    hmac_fail: u64,
    sig_pass: u64,
    sig_fail: u64,
};

// ============================================================================
// Security Integrity Subsystem Manager
// ============================================================================

pub const IntegritySubsystemManager = struct {
    apparmor_stats: ApparmorStats,
    ima_stats: ImaStats,
    evm_stats: EvmStats,
    evm_config: EvmConfig,
    ima_policy_rules: u32,
    ima_template_count: u32,
    initialized: bool,

    pub fn init() IntegritySubsystemManager {
        return IntegritySubsystemManager{
            .apparmor_stats = std.mem.zeroes(ApparmorStats),
            .ima_stats = std.mem.zeroes(ImaStats),
            .evm_stats = std.mem.zeroes(EvmStats),
            .evm_config = EvmConfig{
                .evm_initialized = false,
                .evm_hmac = true,
                .evm_signature = true,
                .evm_portable = false,
            },
            .ima_policy_rules = 0,
            .ima_template_count = 0,
            .initialized = true,
        };
    }
};
