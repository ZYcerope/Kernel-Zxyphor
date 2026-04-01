// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Security Audit, BPF LSM, TPM Interface,
// Integrity Measurement, Security Namespaces, Landlock
// More advanced than Linux 2026 security infrastructure

const std = @import("std");

// ============================================================================
// Audit Subsystem
// ============================================================================

/// Audit message type
pub const AuditMsgType = enum(u16) {
    // Kernel messages
    syscall = 1300,
    path = 1302,
    ipc = 1303,
    socketcall = 1304,
    config_change = 1305,
    sockaddr = 1306,
    cwd = 1307,
    execve = 1309,
    ipc_set_perm = 1311,
    mq_sendrecv = 1312,
    mq_notify = 1313,
    mq_getsetattr = 1314,
    kernel_other = 1316,
    fd_pair = 1317,
    obj_pid = 1318,
    tty = 1319,
    eoe = 1320,          // End of Event
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
    // User messages
    user_auth = 1100,
    user_acct = 1101,
    user_mgmt = 1102,
    cred_acq = 1103,
    cred_disp = 1104,
    user_start = 1105,
    user_end = 1106,
    user_avc = 1107,
    user_chauthtok = 1108,
    user_err = 1109,
    user_login = 1112,
    // Anomaly
    anom_promiscuous = 1700,
    anom_abend = 1701,
    anom_link = 1702,
    // Integrity
    integrity_data = 1800,
    integrity_metadata = 1801,
    integrity_status = 1802,
    integrity_hash = 1803,
    integrity_pcr = 1804,
    integrity_rule = 1805,
    integrity_evm_xattr = 1806,
    integrity_policy_rule = 1807,
    // Zxyphor
    zxy_security_event = 2000,
    zxy_anomaly_detect = 2001,
};

/// Audit filter type
pub const AuditFilterType = enum(u8) {
    user = 0,
    task = 1,
    entry = 2,      // Deprecated
    watch = 3,
    exit = 4,
    exclude = 5,
    fs = 6,         // Filesystem
};

/// Audit field
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
    ppid = 18,
    perm = 13,         // Permission filter
    filetype = 14,
    obj_uid = 15,
    obj_gid = 16,
    devmajor = 100,
    devminor = 101,
    inode = 102,
    exit_code = 103,
    success = 104,
    a0 = 200,
    a1 = 201,
    a2 = 202,
    a3 = 203,
    sessionid = 25,
    subj_user = 13,
    subj_role = 14,
    subj_type = 15,
    subj_sen = 16,
    subj_clr = 17,
    exe = 112,
};

/// Audit rule
pub const AuditRule = struct {
    flags: u32,
    action: AuditAction,
    field_count: u32,
    // Filter
    filter_type: AuditFilterType,
    // Syscall mask
    syscall_mask: [8]u64,    // Bitmap, 512 syscalls
    // Fields (max 64)
    fields: [64]AuditField,
    values: [64]u64,
    ops: [64]AuditOp,
    field_count_actual: u32,
};

/// Audit action
pub const AuditAction = enum(u32) {
    never = 0,
    possible = 1,       // Deprecated
    always = 2,
};

/// Audit operator
pub const AuditOp = enum(u32) {
    unset = 0,
    amp_and = 1,       // Bitwise AND
    eq = 2,
    gt = 3,
    lt = 4,
    ge = 5,
    le = 6,
    ne = 7,
    bitmask = 8,
    bittest = 9,
};

/// Audit buffer for log messages
pub const AuditBuffer = struct {
    audit_type: AuditMsgType,
    serial: u64,         // Unique serial number
    timestamp_sec: u64,
    timestamp_usec: u32,
    pid: u32,
    uid: u32,
    auid: u32,           // Login UID
    sessionid: u32,
    // Buffer
    data_len: u32,
    data: [4096]u8,
};

// ============================================================================
// BPF LSM
// ============================================================================

/// BPF LSM hook type (subset)
pub const BpfLsmHook = enum(u32) {
    binder_set_context_mgr = 0,
    binder_transaction = 1,
    binder_transfer_binder = 2,
    binder_transfer_file = 3,
    ptrace_access_check = 4,
    ptrace_traceme = 5,
    capget = 6,
    capset = 7,
    capable = 8,
    quotactl = 9,
    quota_on = 10,
    syslog = 11,
    settime = 12,
    vm_enough_memory = 13,
    bprm_creds_for_exec = 14,
    bprm_creds_from_file = 15,
    bprm_check_security = 16,
    bprm_committing_creds = 17,
    bprm_committed_creds = 18,
    // Filesystem
    sb_alloc_security = 19,
    sb_delete = 20,
    sb_free_security = 21,
    sb_free_mnt_opts = 22,
    sb_eat_lsm_opts = 23,
    sb_mnt_opts_compat = 24,
    sb_remount = 25,
    sb_kern_mount = 26,
    sb_show_options = 27,
    sb_statfs = 28,
    sb_mount = 29,
    sb_umount = 30,
    sb_pivotroot = 31,
    sb_set_mnt_opts = 32,
    sb_clone_mnt_opts = 33,
    // Inode
    inode_alloc_security = 34,
    inode_free_security = 35,
    inode_init_security = 36,
    inode_init_security_anon = 37,
    inode_create = 38,
    inode_link = 39,
    inode_unlink = 40,
    inode_symlink = 41,
    inode_mkdir = 42,
    inode_rmdir = 43,
    inode_mknod = 44,
    inode_rename = 45,
    inode_readlink = 46,
    inode_follow_link = 47,
    inode_permission = 48,
    inode_setattr = 49,
    inode_getattr = 50,
    inode_setxattr = 51,
    inode_post_setxattr = 52,
    inode_getxattr = 53,
    inode_listxattr = 54,
    inode_removexattr = 55,
    inode_set_acl = 56,
    inode_get_acl = 57,
    inode_remove_acl = 58,
    // File
    file_permission = 59,
    file_alloc_security = 60,
    file_free_security = 61,
    file_ioctl = 62,
    file_mprotect = 63,
    file_lock = 64,
    file_fcntl = 65,
    file_set_fowner = 66,
    file_send_sigiotask = 67,
    file_receive = 68,
    file_open = 69,
    file_truncate = 70,
    // Task
    task_alloc = 71,
    task_free = 72,
    cred_alloc_blank = 73,
    cred_free = 74,
    cred_prepare = 75,
    cred_transfer = 76,
    kernel_act_as = 77,
    kernel_create_files_as = 78,
    kernel_module_request = 79,
    kernel_load_data = 80,
    kernel_post_load_data = 81,
    kernel_read_file = 82,
    kernel_post_read_file = 83,
    task_fix_setuid = 84,
    task_fix_setgid = 85,
    task_fix_setgroups = 86,
    task_setpgid = 87,
    task_getpgid = 88,
    task_getsid = 89,
    task_setnice = 90,
    task_setioprio = 91,
    task_getioprio = 92,
    task_prlimit = 93,
    task_setrlimit = 94,
    task_setscheduler = 95,
    task_getscheduler = 96,
    task_movememory = 97,
    task_kill = 98,
    task_prctl = 99,
    // Socket  
    socket_create = 100,
    socket_post_create = 101,
    socket_socketpair = 102,
    socket_bind = 103,
    socket_connect = 104,
    socket_listen = 105,
    socket_accept = 106,
    socket_sendmsg = 107,
    socket_recvmsg = 108,
    socket_getsockname = 109,
    socket_getpeername = 110,
    socket_getsockopt = 111,
    socket_setsockopt = 112,
    socket_shutdown = 113,
    // BPF
    bpf = 114,
    bpf_map = 115,
    bpf_prog = 116,
    bpf_map_alloc_security = 117,
    bpf_map_free_security = 118,
    bpf_prog_alloc_security = 119,
    bpf_prog_free_security = 120,
    bpf_token_alloc_security = 121,
    bpf_token_free_security = 122,
    bpf_token_cmd = 123,
    bpf_token_capable = 124,
    // Zxyphor
    zxy_resource_access = 200,
    zxy_network_policy = 201,
};

/// BPF LSM program info
pub const BpfLsmProgInfo = struct {
    hook: BpfLsmHook,
    prog_id: u32,
    attach_type: u32,
    // Stats
    run_count: u64,
    run_time_ns: u64,
    deny_count: u64,
};

// ============================================================================
// TPM (Trusted Platform Module)
// ============================================================================

/// TPM version
pub const TpmVersion = enum(u8) {
    tpm12 = 0,
    tpm20 = 1,
};

/// TPM command codes (subset for TPM 2.0)
pub const TpmCc = enum(u32) {
    nv_read = 0x0000014E,
    nv_write = 0x00000137,
    nv_define_space = 0x0000012A,
    nv_undefine_space = 0x00000122,
    pcr_read = 0x0000017E,
    pcr_extend = 0x00000182,
    pcr_reset = 0x0000013D,
    get_random = 0x0000017B,
    create_primary = 0x00000131,
    create = 0x00000153,
    load = 0x00000157,
    sign = 0x0000015D,
    verify_signature = 0x00000177,
    unseal = 0x0000015E,
    seal = 0x00000153,
    flush_context = 0x00000165,
    get_capability = 0x0000017A,
    startup = 0x00000144,
    shutdown = 0x00000145,
    self_test = 0x00000143,
    dictionary_attack_lock_reset = 0x00000139,
    clear = 0x00000126,
    hierachy_change_auth = 0x00000129,
    policy_pcr = 0x0000017F,
    policy_password = 0x0000018C,
};

/// TPM algorithm
pub const TpmAlg = enum(u16) {
    sha1 = 0x0004,
    sha256 = 0x000B,
    sha384 = 0x000C,
    sha512 = 0x000D,
    sha3_256 = 0x0027,
    sha3_384 = 0x0028,
    sha3_512 = 0x0029,
    sm3_256 = 0x0012,
    rsa = 0x0001,
    ecc = 0x0023,
    aes = 0x0006,
    null_alg = 0x0010,
};

/// PCR bank info
pub const PcrBankInfo = struct {
    algorithm: TpmAlg,
    digest_size: u16,
    nr_pcrs: u8,          // Usually 24
    pcr_values: [24][64]u8, // PCR digest values (max SHA-512)
};

/// TPM NV index attributes
pub const TpmNvAttributes = packed struct {
    ppwrite: bool = false,
    ownerwrite: bool = false,
    authwrite: bool = false,
    policywrite: bool = false,
    counter: bool = false,
    bits: bool = false,
    extend: bool = false,
    policy_delete: bool = false,
    writelocked: bool = false,
    writeall: bool = false,
    writedefine: bool = false,
    write_stclear: bool = false,
    globallock: bool = false,
    ppread: bool = false,
    ownerread: bool = false,
    authread: bool = false,
    policyread: bool = false,
    no_da: bool = false,
    orderly: bool = false,
    clear_stclear: bool = false,
    readlocked: bool = false,
    written: bool = false,
    platformcreate: bool = false,
    read_stclear: bool = false,
    _padding: u8 = 0,
};

// ============================================================================
// Landlock
// ============================================================================

/// Landlock rule type
pub const LandlockRuleType = enum(u32) {
    path_beneath = 1,
    net_port = 2,
};

/// Landlock access flags - filesystem
pub const LandlockAccessFs = packed struct {
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
    _padding: u16 = 0,
};

/// Landlock access flags - network
pub const LandlockAccessNet = packed struct {
    bind_tcp: bool = false,
    connect_tcp: bool = false,
    _padding: u6 = 0,
};

/// Landlock ruleset attr
pub const LandlockRulesetAttr = struct {
    handled_access_fs: LandlockAccessFs,
    handled_access_net: LandlockAccessNet,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const SecurityInfraSubsystem = struct {
    // Audit
    audit_enabled: bool,
    audit_backlog_limit: u32,
    audit_backlog: u32,
    total_audit_events: u64,
    total_audit_lost: u64,
    nr_audit_rules: u32,
    // BPF LSM
    nr_bpf_lsm_progs: u32,
    total_bpf_lsm_calls: u64,
    total_bpf_lsm_denials: u64,
    // TPM
    tpm_present: bool,
    tpm_version: TpmVersion,
    tpm_manufacturer: u32,
    nr_pcr_banks: u8,
    // Landlock
    nr_landlock_rulesets: u32,
    total_landlock_denials: u64,
    // Zxyphor
    zxy_anomaly_detection: bool,
    zxy_realtime_audit: bool,
    initialized: bool,

    pub fn init() SecurityInfraSubsystem {
        return SecurityInfraSubsystem{
            .audit_enabled = false,
            .audit_backlog_limit = 64,
            .audit_backlog = 0,
            .total_audit_events = 0,
            .total_audit_lost = 0,
            .nr_audit_rules = 0,
            .nr_bpf_lsm_progs = 0,
            .total_bpf_lsm_calls = 0,
            .total_bpf_lsm_denials = 0,
            .tpm_present = false,
            .tpm_version = .tpm20,
            .tpm_manufacturer = 0,
            .nr_pcr_banks = 0,
            .nr_landlock_rulesets = 0,
            .total_landlock_denials = 0,
            .zxy_anomaly_detection = true,
            .zxy_realtime_audit = true,
            .initialized = false,
        };
    }
};
