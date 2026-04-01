// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Security: AppArmor, Audit, Integrity, LSM stacking
// AppArmor profiles/labels, audit rules/logs, IMA/EVM measurements,
// LSM stacking framework, Landlock, SECCOMP deep integration
// More advanced than Linux 2026 security subsystem

const std = @import("std");

// ============================================================================
// AppArmor
// ============================================================================

pub const AaProfileMode = enum(u8) {
    enforce = 0,
    complain = 1,
    kill = 2,
    unconfined = 3,
    // Zxyphor
    zxy_adaptive = 10,
};

pub const AaPermissions = packed struct(u32) {
    exec = false,
    write = false,
    read = false,
    append = false,
    link = false,
    lock = false,
    exec_mmap = false,
    create = false,
    delete = false,
    chown = false,
    chmod = false,
    chgrp = false,
    setattr = false,
    getattr = false,
    // Network
    net_create = false,
    net_bind = false,
    net_listen = false,
    net_accept = false,
    net_connect = false,
    net_send = false,
    net_receive = false,
    net_shutdown = false,
    net_getattr = false,
    net_setattr = false,
    // IPC / ptrace / signal
    ptrace_trace = false,
    ptrace_read = false,
    signal_send = false,
    signal_receive = false,
    // Zxyphor
    zxy_encrypt = false,
    zxy_audit = false,
    _reserved: u2 = 0,
};

pub const AaRuleType = enum(u8) {
    file = 0,
    network = 1,
    capability = 2,
    mount = 3,
    pivot_root = 4,
    ptrace = 5,
    signal = 6,
    dbus = 7,
    unix_socket = 8,
    rlimit = 9,
    change_profile = 10,
    // Zxyphor
    zxy_ipc = 20,
    zxy_crypto = 21,
};

pub const AaFileRule = struct {
    // Path glob pattern (offset into rule string table)
    path_pattern_offset: u32,
    path_pattern_len: u16,
    // Permissions
    perms: AaPermissions,
    // Owner only
    owner: bool,
    // Audit
    audit: bool,
    deny: bool,
    // Exec transition
    exec_mode: AaExecMode,
    exec_target_offset: u32,   // Target profile for ix/px/cx
    exec_target_len: u16,
};

pub const AaExecMode = enum(u8) {
    inherit = 0,           // ix
    profile = 1,           // px
    child = 2,             // cx
    unconfined = 3,        // ux
    named = 4,             // Px, Cx (named transition)
    safe_inherit = 5,      // pix, cix
};

pub const AaCapRule = struct {
    // POSIX capabilities bitmask
    caps: [2]u64,          // CAP_* bits (64 caps × 2 = 128)
    deny: bool,
    audit: bool,
};

pub const AaNetRule = struct {
    family: u16,           // AF_*
    sock_type: u16,        // SOCK_*
    protocol: u16,
    perms: AaPermissions,
    deny: bool,
    audit: bool,
};

pub const AaProfile = struct {
    // Identity
    name_offset: u32,
    name_len: u16,
    // Namespace
    ns_offset: u32,
    ns_len: u16,
    // Mode
    mode: AaProfileMode,
    // Flags
    flags: AaProfileFlags,
    // HAT (hierarchical)
    parent_offset: u32,
    nr_children: u16,
    // Rules counts
    nr_file_rules: u32,
    nr_net_rules: u16,
    nr_cap_rules: u16,
    nr_mount_rules: u16,
    nr_signal_rules: u16,
    nr_ptrace_rules: u16,
    nr_dbus_rules: u16,
    nr_unix_rules: u16,
    // Stats
    total_allow: u64,
    total_deny: u64,
    total_audit: u64,
    total_complain: u64,
    // Timestamps
    load_time_ns: u64,
    last_used_ns: u64,
};

pub const AaProfileFlags = packed struct(u32) {
    hat: bool = false,              // HAT (subprofile)
    debug: bool = false,
    path_mediation: bool = false,
    path_attach: bool = false,
    interruptible: bool = false,
    uniq_name: bool = false,
    delegation: bool = false,
    disconnected: bool = false,
    // Zxyphor
    zxy_dynamic: bool = false,
    _reserved: u23 = 0,
};

// ============================================================================
// Audit Framework
// ============================================================================

pub const AuditMessageType = enum(u16) {
    // Kernel audit
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
    mq_sendrecv = 1313,
    mq_notify = 1314,
    mq_getsetattr = 1315,
    kernel_other = 1316,
    fd_pair = 1317,
    obj_pid = 1318,
    tty = 1319,
    eoe = 1320,            // End of event
    bprm_fcaps = 1321,
    capset = 1322,
    mmap = 1323,
    netfilter_pkt = 1324,
    netfilter_cfg = 1325,
    seccomp = 1326,
    proctitle = 1327,
    feature_change = 1328,
    replace = 1329,
    kern_module = 1330,
    fanotify = 1331,
    time_injoffset = 1332,
    time_adjntpval = 1333,
    bpf = 1334,
    event_listener = 1335,
    uringop = 1336,
    openat2 = 1337,
    dm_ctrl = 1338,
    dm_event = 1339,
    // User space messages
    user_auth = 1100,
    user_acct = 1101,
    user_mgmt = 1102,
    cred_acq = 1103,
    cred_disp = 1104,
    user_start = 1105,
    user_end = 1106,
    user_avc = 1107,
    user_chauthtok = 1108,
    user_role_change = 1109,
    user_labeled_export = 1110,
    user_unlabeled_export = 1111,
    user_device = 1112,
    user_selinux_err = 1113,
    user_cmd = 1114,
    // AVC (Access Vector Cache = SELinux)
    avc = 1400,
    selinux_err = 1401,
    avc_path = 1402,
    mac_policy_load = 1403,
    mac_status = 1404,
    mac_config_change = 1405,
    // AppArmor
    apparmor_audit = 1500,
    apparmor_allowed = 1501,
    apparmor_denied = 1502,
    apparmor_hint = 1503,
    apparmor_status = 1504,
    apparmor_error = 1505,
    // Anomaly detection
    anomaly = 1700,
    anomaly_kernel = 1701,
    anomaly_link = 1702,
    anomaly_resp = 1703,
    // Integrity (IMA/EVM)
    integrity_data = 1800,
    integrity_metadata = 1801,
    integrity_status = 1802,
    integrity_hash = 1803,
    integrity_pcr = 1804,
    integrity_rule = 1805,
    integrity_evm_xattr = 1806,
    integrity_policy_rule = 1807,
    // Zxyphor
    zxy_crypto_op = 2000,
    zxy_policy_change = 2001,
    _,
};

pub const AuditField = enum(u32) {
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
    subj_user = 13,
    subj_role = 14,
    subj_type = 15,
    subj_sen = 16,
    subj_clr = 17,
    ppid = 18,
    obj_user = 19,
    obj_role = 20,
    obj_type = 21,
    obj_lev_low = 22,
    obj_lev_high = 23,
    devmajor = 100,
    devminor = 101,
    inode = 102,
    exit_code = 103,
    success = 104,
    a0 = 200,
    a1 = 201,
    a2 = 202,
    a3 = 203,
    dir = 107,
    filetype = 108,
    perm = 106,
    exe = 112,
    sessionid = 25,
    _,
};

pub const AuditOp = enum(u8) {
    equal = 0,
    not_equal = 1,
    less_than = 2,
    greater_than = 3,
    less_equal = 4,
    greater_equal = 5,
    bitmask = 6,
    bittest = 7,
};

pub const AuditRule = struct {
    // Filter
    list: AuditFilterList,
    action: AuditAction,
    // Fields (up to 64 field conditions)
    nr_fields: u8,
    fields: [64]AuditRuleField,
    // Flags
    flags: u32,
    // Stats
    matches: u64,
};

pub const AuditRuleField = struct {
    field: AuditField,
    op: AuditOp,
    val: u64,
    // String value (for path, etc.)
    str_offset: u32,
    str_len: u16,
};

pub const AuditFilterList = enum(u8) {
    user = 0,
    task = 1,
    entry = 2,       // Deprecated
    watch = 3,       // Deprecated
    exit = 4,
    type_filter = 5,
    fs = 6,
    io_uring = 7,
    // Zxyphor
    zxy_security = 10,
};

pub const AuditAction = enum(u8) {
    never = 0,
    possible = 1,
    always = 2,
};

pub const AuditRecord = struct {
    // Header
    msg_type: AuditMessageType,
    serial: u64,
    timestamp_sec: u64,
    timestamp_nsec: u32,
    // Source
    pid: u32,
    uid: u32,
    auid: u32,        // Audit UID (loginuid)
    ses: u32,          // Session ID
    // Syscall info
    syscall_nr: i32,
    arch: u32,
    success: bool,
    exit_code: i64,
    args: [4]u64,
    // Subject context (SELinux/AppArmor)
    subj_offset: u32,
    subj_len: u16,
    // Message
    msg_offset: u32,
    msg_len: u16,
    // CPU
    cpu: u16,
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

pub const ImaFunc = enum(u8) {
    file_check = 1,
    mmap_check = 2,
    bprm_check = 3,
    creds_check = 4,
    post_setattr = 5,
    module_check = 6,
    firmware_check = 7,
    kexec_kernel_check = 8,
    kexec_initramfs_check = 9,
    policy_check = 10,
    kexec_cmdline = 11,
    key_check = 12,
    critical_data = 13,
    setxattr_check = 14,
};

pub const ImaHashAlgo = enum(u8) {
    md5 = 0,     // Legacy, not recommended
    sha1 = 1,
    rmd160 = 2,
    sha256 = 3,
    sha384 = 4,
    sha512 = 5,
    sha224 = 6,
    sm3_256 = 7,
    streebog_256 = 8,
    streebog_512 = 9,
    // Zxyphor
    zxy_blake3 = 20,
};

pub const ImaRule = struct {
    action: ImaAction,
    func: ImaFunc,
    mask: u32,
    // Conditions
    uid: i32,
    fowner: i32,
    // PCR (for TPM)
    pcr: u8,
    // Hash algorithm
    hash_algo: ImaHashAlgo,
    // Flags
    flags: ImaRuleFlags,
    // Stats
    matches: u64,
};

pub const ImaRuleFlags = packed struct(u32) {
    uid: bool = false,
    fowner: bool = false,
    fsuuid: bool = false,
    fgroup: bool = false,
    lsm_subj_user: bool = false,
    lsm_subj_role: bool = false,
    lsm_subj_type: bool = false,
    lsm_obj_user: bool = false,
    lsm_obj_role: bool = false,
    lsm_obj_type: bool = false,
    fsname: bool = false,
    keyrings: bool = false,
    label: bool = false,
    pcr: bool = false,
    // Zxyphor
    zxy_cgroup: bool = false,
    _reserved: u17 = 0,
};

pub const ImaMeasurement = struct {
    // PCR
    pcr: u8,
    // Template
    template_name_offset: u32,
    template_name_len: u16,
    // Digest
    hash_algo: ImaHashAlgo,
    digest: [64]u8,        // Max SHA-512
    digest_len: u8,
    // File
    filename_offset: u32,
    filename_len: u16,
    // Security context
    lsm_label_offset: u32,
    lsm_label_len: u16,
    // Timestamp
    timestamp_ns: u64,
};

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

pub const EvmMode = enum(u8) {
    disabled = 0,
    fix = 1,           // Fix mode (create/update signatures)
    enforce = 2,
    log_only = 3,
};

pub const EvmProtectedXattrs = packed struct(u32) {
    security_selinux: bool = false,
    security_smack: bool = false,
    security_apparmor: bool = false,
    security_ima: bool = false,
    security_capability: bool = false,
    // Zxyphor
    security_zxyphor: bool = false,
    _reserved: u26 = 0,
};

pub const EvmSignatureType = enum(u8) {
    hmac = 0,
    rsa = 1,
    ecc = 2,
    // Zxyphor
    zxy_dilithium = 10,
};

// ============================================================================
// Landlock (unprivileged sandboxing)
// ============================================================================

pub const LandlockRuleType = enum(u32) {
    path_beneath = 1,
    net_port = 2,
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
    refer: bool = false,
    truncate: bool = false,
    ioctl_dev: bool = false,
    // Zxyphor
    zxy_encrypt: bool = false,
    _reserved: u47 = 0,
};

pub const LandlockNetAccess = packed struct(u64) {
    bind_tcp: bool = false,
    connect_tcp: bool = false,
    // Zxyphor
    zxy_send_udp: bool = false,
    zxy_recv_udp: bool = false,
    _reserved: u60 = 0,
};

pub const LandlockRuleset = struct {
    // Handled access
    handled_fs_access: LandlockFsAccess,
    handled_net_access: LandlockNetAccess,
    // Rules
    nr_fs_rules: u32,
    nr_net_rules: u32,
    // Hierarchy
    nr_layers: u8,
    // Stats
    total_checks: u64,
    total_denied: u64,
};

// ============================================================================
// LSM Stacking
// ============================================================================

pub const LsmId = enum(u32) {
    selinux = 1,
    smack = 2,
    tomoyo = 3,
    apparmor = 4,
    lockdown = 5,
    yama = 6,
    loadpin = 7,
    safesetid = 8,
    bpf = 9,
    landlock = 10,
    ima = 11,
    evm = 12,
    // Zxyphor
    zxyphor = 100,
    _,
};

pub const LsmOrder = enum(u8) {
    first = 0,
    last = 255,
};

pub const LsmHookId = enum(u16) {
    // Task hooks
    task_alloc = 0,
    task_free = 1,
    task_setpgid = 2,
    task_getpgid = 3,
    task_getsid = 4,
    task_setnice = 5,
    task_setioprio = 6,
    task_getioprio = 7,
    task_prlimit = 8,
    task_setrlimit = 9,
    task_movememory = 10,
    task_kill = 11,
    task_prctl = 12,
    // BPRm hooks
    bprm_creds_for_exec = 20,
    bprm_creds_from_file = 21,
    bprm_check = 22,
    bprm_committing_creds = 23,
    bprm_committed_creds = 24,
    // File hooks
    file_permission = 30,
    file_alloc = 31,
    file_free = 32,
    file_ioctl = 33,
    file_mmap = 34,
    file_mprotect = 35,
    file_lock = 36,
    file_fcntl = 37,
    file_open = 38,
    file_truncate = 39,
    // Inode hooks
    inode_alloc = 50,
    inode_free = 51,
    inode_init = 52,
    inode_create = 53,
    inode_link = 54,
    inode_unlink = 55,
    inode_symlink = 56,
    inode_mkdir = 57,
    inode_rmdir = 58,
    inode_mknod = 59,
    inode_rename = 60,
    inode_readlink = 61,
    inode_follow_link = 62,
    inode_permission = 63,
    inode_setattr = 64,
    inode_getattr = 65,
    inode_setxattr = 66,
    inode_getxattr = 67,
    inode_listxattr = 68,
    inode_removexattr = 69,
    // Socket hooks
    socket_create = 80,
    socket_bind = 81,
    socket_connect = 82,
    socket_listen = 83,
    socket_accept = 84,
    socket_sendmsg = 85,
    socket_recvmsg = 86,
    socket_getsockname = 87,
    socket_getpeername = 88,
    socket_setsockopt = 89,
    socket_getsockopt = 90,
    socket_shutdown = 91,
    // Superblock hooks
    sb_alloc = 100,
    sb_free = 101,
    sb_mount = 102,
    sb_umount = 103,
    sb_pivotroot = 104,
    sb_statfs = 105,
    // Network hooks
    sk_alloc = 120,
    sk_free = 121,
    sk_clone = 122,
    unix_stream_connect = 123,
    unix_may_send = 124,
    // Key hooks
    key_alloc = 140,
    key_free = 141,
    key_permission = 142,
    // Zxyphor
    zxy_ipc_check = 200,
    zxy_crypto_check = 201,
    _,
};

pub const LsmStackEntry = struct {
    id: LsmId,
    // Enabled state
    enabled: bool,
    // Blob sizes (per-object security data)
    blob_sizes: LsmBlobSizes,
    // Stats
    total_hooks_called: u64,
    total_denials: u64,
};

pub const LsmBlobSizes = struct {
    lbs_cred: u32,
    lbs_file: u32,
    lbs_inode: u32,
    lbs_superblock: u32,
    lbs_ipc: u32,
    lbs_msg_msg: u32,
    lbs_task: u32,
    lbs_xattr_count: u32,
    lbs_tun_dev: u32,
    lbs_bdev: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const SecuritySubsystem = struct {
    // AppArmor
    apparmor_enabled: bool,
    aa_nr_profiles: u32,
    aa_nr_namespaces: u32,
    aa_total_allow: u64,
    aa_total_deny: u64,
    // Audit
    audit_enabled: bool,
    audit_backlog_limit: u32,
    audit_nr_rules: u32,
    audit_total_records: u64,
    audit_lost: u64,
    // IMA
    ima_enabled: bool,
    ima_nr_rules: u32,
    ima_nr_measurements: u64,
    ima_hash_algo: ImaHashAlgo,
    // EVM
    evm_mode: EvmMode,
    evm_nr_verifications: u64,
    evm_nr_failures: u64,
    // Landlock
    landlock_enabled: bool,
    landlock_nr_rulesets: u32,
    landlock_total_denials: u64,
    // LSM Stack
    nr_lsms: u8,
    lsm_stack: [16]LsmStackEntry,
    // Zxyphor
    zxy_adaptive_security: bool,
    initialized: bool,
};
