// Zxyphor Kernel - Landlock LSM, IPE (Integrity Policy Enforcement),
// Security Keys/Keyrings Extended, Audit Subsystem Detail,
// SELinux Policy Engine, IMA/EVM Extended Operations,
// seccomp BPF Program Types, Linux Security Namespace,
// Trusted/Encrypted Keys Framework
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Landlock LSM
// ============================================================================

pub const LandlockABI = enum(u32) {
    v1 = 1,    // Linux 5.13
    v2 = 2,    // Linux 5.19 - REFER
    v3 = 3,    // Linux 6.2 - TRUNCATE
    v4 = 4,    // Linux 6.7 - TCP/IOCTL
    v5 = 5,    // Linux 6.10 - SCOPE
};

pub const LandlockFsAccess = packed struct(u64) {
    execute: bool = false,
    write_file: bool = false,
    read_file: bool = false,
    read_dir: bool = false,
    remove_dir: bool = false,
    remove_file: bool = false,
    make_char: bool = false,
    make_dir: bool = false,
    make_reg: bool = false,
    make_sock: bool = false,
    make_fifo: bool = false,
    make_block: bool = false,
    make_sym: bool = false,
    refer: bool = false,          // ABI v2
    truncate: bool = false,       // ABI v3
    ioctl_dev: bool = false,      // ABI v4
    _reserved: u48 = 0,
};

pub const LandlockNetAccess = packed struct(u64) {
    bind_tcp: bool = false,
    connect_tcp: bool = false,
    _reserved: u62 = 0,
};

pub const LandlockScopeFlags = packed struct(u64) {
    abstract_unix_socket: bool = false,
    signal: bool = false,
    _reserved: u62 = 0,
};

pub const LandlockRuleType = enum(u32) {
    path_beneath = 1,
    net_port = 2,
};

pub const LandlockPathBeneathAttr = struct {
    allowed_access: LandlockFsAccess,
    parent_fd: i32,
};

pub const LandlockNetPortAttr = struct {
    allowed_access: LandlockNetAccess,
    port: u64,
};

pub const LandlockRulesetAttr = struct {
    handled_access_fs: LandlockFsAccess,
    handled_access_net: LandlockNetAccess,
    scoped: LandlockScopeFlags,
};

pub const LandlockDomain = struct {
    nr_rules: u32,
    fs_handled: u64,
    net_handled: u64,
    scoped: u64,
    hierarchy_depth: u8,
    parent_domain: ?*LandlockDomain,
};

pub const LandlockStats = struct {
    rulesets_created: u64,
    rules_added: u64,
    enforcements: u64,
    denials_fs: u64,
    denials_net: u64,
    denials_scope: u64,
};

// ============================================================================
// IPE (Integrity Policy Enforcement)
// ============================================================================

pub const IpePolicy = struct {
    name: [256]u8,
    name_len: u16,
    version: u32,
    default_action: IpeAction,
    rules: [128]IpeRule,
    nr_rules: u16,
    active: bool,
};

pub const IpeAction = enum(u8) {
    allow = 0,
    deny = 1,
};

pub const IpeOperation = enum(u8) {
    execute = 0,
    firmware = 1,
    kmodule = 2,
    kexec_image = 3,
    kexec_initramfs = 4,
    policy = 5,
    x509_certificate = 6,
};

pub const IpePropertyType = enum(u8) {
    dm_verity_roothash = 0,
    dm_verity_signature = 1,
    fsverity_digest = 2,
    fsverity_signature = 3,
    boot_verified = 4,
};

pub const IpeRule = struct {
    operation: IpeOperation,
    action: IpeAction,
    property: IpePropertyType,
    property_value: [64]u8,
    property_value_len: u8,
};

// ============================================================================
// Security Keys / Keyrings Extended
// ============================================================================

pub const KeyctlCommand = enum(u32) {
    get_keyring_id = 0,
    join_session_keyring = 1,
    update = 2,
    revoke = 3,
    chown = 4,
    setperm = 5,
    describe = 6,
    clear = 7,
    link = 8,
    unlink = 9,
    search = 10,
    read = 11,
    instantiate = 12,
    negate = 13,
    set_reqkey_keyring = 14,
    set_timeout = 15,
    assume_authority = 16,
    get_security = 17,
    session_to_parent = 18,
    reject = 19,
    instantiate_iov = 20,
    invalidate = 21,
    get_persistent = 22,
    dh_compute = 23,
    pkey_query = 24,
    pkey_encrypt = 25,
    pkey_decrypt = 26,
    pkey_sign = 27,
    pkey_verify = 28,
    restrict_keyring = 29,
    move = 30,
    capabilities = 31,
    watch_key = 32,
};

pub const TrustedKeyOps = enum(u8) {
    create = 0,
    load = 1,
    update = 2,
    seal = 3,
    unseal = 4,
};

pub const TrustedKeySource = enum(u8) {
    tpm = 0,
    tee = 1,           // ARM TrustZone TEE
    caam = 2,          // NXP CAAM
    dcp = 3,           // NXP DCP
};

pub const EncryptedKeyFormat = enum(u8) {
    default = 0,
    ecrypt = 1,
    enc32 = 2,
};

pub const KeyringRestrictionType = enum(u8) {
    builtin_trusted = 0,
    builtin_and_secondary = 1,
    key_or_keyring = 2,
    key_or_keyring_chain = 3,
};

pub const BigKeyConfig = struct {
    threshold: u32,        // Bytes above which we encrypt to tmpfs
    tmpfs_path: [256]u8,
    encrypt_algo: [32]u8,
};

// ============================================================================
// Audit Subsystem Detail
// ============================================================================

pub const AuditMessageType = enum(u16) {
    // User-generated (1000-1099)
    user = 1000,
    user_auth = 1100,
    user_acct = 1101,
    user_mgmt = 1102,
    user_err = 1109,
    cred_acq = 1103,
    cred_disp = 1104,
    user_start = 1105,
    user_end = 1106,
    user_avc = 1107,
    user_chauth = 1108,
    // Kernel (1300-1399)
    syscall = 1300,
    path = 1302,
    ipc = 1303,
    socketcall = 1304,
    config_change = 1305,
    sockaddr = 1306,
    cwd = 1307,
    execve = 1309,
    ipc_set_perm = 1311,
    mq_open = 1312,
    mq_send = 1313,
    mq_recv = 1314,
    mq_notify = 1315,
    fd_pair = 1317,
    obj_pid = 1318,
    tty = 1319,
    eoe = 1320,               // End of Event
    bprm_fcaps = 1321,
    cap_fail = 1322,
    netfilter_cfg = 1325,
    seccomp = 1326,
    proctitle = 1327,
    feature_change = 1328,
    replace = 1329,
    kern_module = 1330,
    fanotify = 1331,
    time_adj = 1333,
    time_injoffset = 1334,
    bpf = 1334,
    event_listener = 1335,
    uringop = 1336,
    openat2 = 1337,
    dm_ctrl = 1338,
    dm_event = 1339,
    // SELinux (1400-1499)
    avc = 1400,
    selinux_err = 1401,
    avc_path = 1402,
    // AppArmor (1500-1599)
    aa_audit = 1500,
    aa_allowed = 1501,
    aa_denied = 1502,
    aa_status = 1503,
    aa_error = 1504,
    // Anomaly (1700-1799)
    anom_promiscuous = 1700,
    anom_exec = 1706,
    anom_link = 1702,
    // Integrity (1800-1899)
    integrity_data = 1800,
    integrity_metadata = 1801,
    integrity_status = 1802,
    integrity_hash = 1803,
    integrity_pcr = 1804,
    integrity_rule = 1805,
    integrity_evm = 1806,
    integrity_policy_rule = 1807,
};

pub const AuditFilter = enum(u8) {
    user = 0,
    task = 1,
    entry = 2,           // Deprecated (use exit)
    watch = 3,
    exit = 4,
    exclude = 5,
    filesystem = 6,
    io_uring = 7,
};

pub const AuditField = enum(u16) {
    pid = 0,
    uid = 1,
    euid = 2,
    suid = 3,
    fsuid = 4,
    gid = 5,
    egid = 6,
    sgid = 7,
    fsgid = 8,
    loginuid = 9,
    pers = 10,
    arch = 11,
    msgtype = 12,
    ppid = 18,
    perm = 13,          // Access permission
    dir = 107,
    filetype = 108,
    obj_uid = 109,
    obj_gid = 110,
    field_compare = 111,
    exe = 112,
    sessionid = 25,
    subj_user = 13,
    subj_role = 14,
    subj_type = 15,
    subj_sen = 16,
    subj_clr = 17,
    obj_user = 18,
    obj_role = 19,
    obj_type = 20,
    obj_lev_low = 21,
    obj_lev_high = 22,
};

pub const AuditBacklog = struct {
    current: u32,
    limit: u32,
    lost: u64,
    wait_time_ms: u32,
    backlog_wait_time: u32,
};

pub const AuditStats = struct {
    enabled: bool,
    failure_mode: AuditFailure,
    pid: u32,                  // Audit daemon PID
    rate_limit: u32,
    backlog: AuditBacklog,
    rules_loaded: u32,
    events_total: u64,
    events_user: u64,
    events_kernel: u64,
    events_lost: u64,
};

pub const AuditFailure = enum(u8) {
    silent = 0,
    printk = 1,
    panic = 2,
};

// ============================================================================
// Seccomp BPF Detail
// ============================================================================

pub const SeccompFilterMode = enum(u8) {
    disabled = 0,
    strict = 1,         // Only read/write/exit/sigreturn
    filter = 2,         // BPF filter
};

pub const SeccompFilterFlags = packed struct(u32) {
    tsync: bool = false,           // Thread sync
    log: bool = false,             // Log all filtered syscalls
    spec_allow: bool = false,      // Disable speculation mitigation
    new_listener: bool = false,    // Return notification FD
    tsync_esrch: bool = false,     // Fail if can't sync
    wait_killable_recv: bool = false,
    _reserved: u26 = 0,
};

pub const SeccompRetAction = enum(u32) {
    kill_process = 0x80000000,
    kill_thread = 0x00000000,
    trap = 0x00030000,
    errno_val = 0x00050000,
    user_notif = 0x7FC00000,
    trace = 0x7FF00000,
    log = 0x7FFC0000,
    allow = 0x7FFF0000,
};

pub const SeccompNotifyReq = struct {
    id: u64,
    pid: u32,
    flags: u32,
    syscall_nr: i32,
    arch: u32,
    instruction_ptr: u64,
    args: [6]u64,
};

pub const SeccompNotifyResp = struct {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,     // SECCOMP_USER_NOTIF_FLAG_CONTINUE
};

pub const SeccompStats = struct {
    filters_installed: u64,
    notifications_sent: u64,
    notifications_received: u64,
    kills_process: u64,
    kills_thread: u64,
    traps: u64,
    errnos: u64,
    traces: u64,
    logs: u64,
    allows: u64,
};

// ============================================================================
// CPUID Feature Detection (for security mitigation)
// ============================================================================

pub const CpuMitigationType = enum(u8) {
    spectre_v1 = 0,          // Bounds check bypass
    spectre_v2 = 1,          // Branch target injection
    meltdown = 2,            // Rogue cache load
    l1tf = 3,                // L1 Terminal Fault
    mds = 4,                 // Microarchitectural Data Sampling
    tsx_async_abort = 5,     // TSX Async Abort
    srbds = 6,               // Special Register Buffer
    mmio_stale = 7,          // MMIO stale data
    retbleed = 8,            // Return address injection
    spec_rstack_overflow = 9, // SRSO
    gds = 10,                // Gather Data Sampling
    bhi = 11,                // Branch History Injection
    rfds = 12,               // Register File Data Sampling
};

pub const MitigationStatus = enum(u8) {
    not_affected = 0,
    vulnerable = 1,
    mitigated = 2,
    mitigated_nosmt = 3,     // Requires SMT off
    unknown = 255,
};

pub const SecurityMitigations = struct {
    spectre_v1: MitigationStatus,
    spectre_v2: MitigationStatus,
    meltdown: MitigationStatus,
    l1tf: MitigationStatus,
    mds: MitigationStatus,
    tsx_async: MitigationStatus,
    srbds: MitigationStatus,
    mmio: MitigationStatus,
    retbleed: MitigationStatus,
    srso: MitigationStatus,
    gds: MitigationStatus,
    bhi: MitigationStatus,
    rfds: MitigationStatus,
    // Mitigation methods active
    ibrs: bool,
    ibpb: bool,
    stibp: bool,
    ssbd: bool,            // Spec Store Bypass Disable
    retpoline: bool,
    rrsba: bool,
    bhi_dis_s: bool,
    kpti_active: bool,
    l1d_flush: bool,
    taa_clear: bool,
    mds_clear: bool,
};

// ============================================================================
// Security Advanced Manager (Zxyphor)
// ============================================================================

pub const SecurityAdvancedManager = struct {
    landlock: LandlockStats,
    audit: AuditStats,
    seccomp: SeccompStats,
    mitigations: SecurityMitigations,
    ipe_active: bool,
    landlock_enabled: bool,
    seccomp_enabled: bool,
    audit_enabled: bool,
    nr_keyrings: u32,
    nr_trusted_keys: u32,
    nr_encrypted_keys: u32,
    initialized: bool,

    pub fn init() SecurityAdvancedManager {
        return .{
            .landlock = std.mem.zeroes(LandlockStats),
            .audit = std.mem.zeroes(AuditStats),
            .seccomp = std.mem.zeroes(SeccompStats),
            .mitigations = std.mem.zeroes(SecurityMitigations),
            .ipe_active = false,
            .landlock_enabled = true,
            .seccomp_enabled = true,
            .audit_enabled = true,
            .nr_keyrings = 0,
            .nr_trusted_keys = 0,
            .nr_encrypted_keys = 0,
            .initialized = true,
        };
    }
};
