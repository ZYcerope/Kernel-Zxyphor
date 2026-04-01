// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Smack, TOMOYO, Yama LSM,
// SafeSetID, LoadPin, Lockdown,
// LSM Stacking Framework, LSM Hooks Comprehensive,
// Integrity Measurement Architecture (IMA) Extended,
// Security Namespace
// More advanced than Linux 2026 security modules

const std = @import("std");

// ============================================================================
// LSM Stacking Framework
// ============================================================================

/// LSM module ID
pub const LsmId = enum(u32) {
    selinux = 1,
    smack = 2,
    tomoyo = 3,
    apparmor = 4,
    yama = 5,
    loadpin = 6,
    safesetid = 7,
    lockdown = 8,
    bpf = 9,
    landlock = 10,
    ipe = 11,
    // Zxyphor
    zxy_guardian = 100,
    zxy_sandbox = 101,
};

/// LSM order (boot parameter lsm=)
pub const LsmOrder = struct {
    ids: [16]LsmId = [_]LsmId{.selinux} ** 16,
    count: u8 = 0,
    exclusive_chosen: bool = false,
    exclusive_id: LsmId = .selinux,
};

/// LSM blob sizes (per-task, per-cred, per-inode, etc.)
pub const LsmBlobSizes = struct {
    lbs_cred: u32 = 0,
    lbs_file: u32 = 0,
    lbs_inode: u32 = 0,
    lbs_ipc: u32 = 0,
    lbs_msg_msg: u32 = 0,
    lbs_task: u32 = 0,
    lbs_superblock: u32 = 0,
    lbs_xattr_count: u32 = 0,
    lbs_bdev: u32 = 0,
};

/// LSM hook category
pub const LsmHookCategory = enum(u8) {
    task = 0,
    cred = 1,
    file = 2,
    inode = 3,
    superblock = 4,
    socket = 5,
    network = 6,
    ipc = 7,
    key = 8,
    audit = 9,
    bpf = 10,
    perf = 11,
    uring = 12,
    xfrm = 13,
    // Zxyphor
    zxy_container = 100,
    zxy_device = 101,
};

/// Comprehensive LSM hook types
pub const LsmHookType = enum(u16) {
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
    task_setscheduler = 10,
    task_getscheduler = 11,
    task_movememory = 12,
    task_kill = 13,
    task_prctl = 14,
    task_to_inode = 15,
    task_fix_setuid = 16,
    task_fix_setgid = 17,
    task_fix_setgroups = 18,

    // Credential hooks
    cred_alloc_blank = 50,
    cred_free = 51,
    cred_prepare = 52,
    cred_transfer = 53,
    cred_getsecid = 54,

    // File hooks
    file_permission = 100,
    file_alloc_security = 101,
    file_free_security = 102,
    file_ioctl = 103,
    file_ioctl_compat = 104,
    file_mprotect = 105,
    file_lock = 106,
    file_fcntl = 107,
    file_set_fowner = 108,
    file_send_sigiotask = 109,
    file_receive = 110,
    file_open = 111,
    file_truncate = 112,

    // Inode hooks
    inode_alloc_security = 150,
    inode_free_security = 151,
    inode_init_security = 152,
    inode_init_security_anon = 153,
    inode_create = 154,
    inode_link = 155,
    inode_unlink = 156,
    inode_symlink = 157,
    inode_mkdir = 158,
    inode_rmdir = 159,
    inode_mknod = 160,
    inode_rename = 161,
    inode_readlink = 162,
    inode_follow_link = 163,
    inode_permission = 164,
    inode_setattr = 165,
    inode_getattr = 166,
    inode_setxattr = 167,
    inode_getxattr = 168,
    inode_listxattr = 169,
    inode_removexattr = 170,
    inode_getsecurity = 171,
    inode_setsecurity = 172,
    inode_listsecurity = 173,
    inode_need_killpriv = 174,
    inode_killpriv = 175,
    inode_getsecid = 176,
    inode_copy_up = 177,
    inode_copy_up_xattr = 178,

    // Socket hooks
    socket_create = 200,
    socket_post_create = 201,
    socket_socketpair = 202,
    socket_bind = 203,
    socket_connect = 204,
    socket_listen = 205,
    socket_accept = 206,
    socket_sendmsg = 207,
    socket_recvmsg = 208,
    socket_getsockname = 209,
    socket_getpeername = 210,
    socket_getsockopt = 211,
    socket_setsockopt = 212,
    socket_shutdown = 213,
    socket_sock_rcv_skb = 214,
    socket_getpeersec_stream = 215,
    socket_getpeersec_dgram = 216,
    sk_alloc_security = 217,
    sk_free_security = 218,
    sk_clone_security = 219,
    sk_getsecid = 220,

    // Superblock
    sb_alloc_security = 250,
    sb_free_security = 251,
    sb_free_mnt_opts = 252,
    sb_eat_lsm_opts = 253,
    sb_mnt_opts_compat = 254,
    sb_remount = 255,
    sb_kern_mount = 256,
    sb_show_options = 257,
    sb_statfs = 258,
    sb_mount = 259,
    sb_umount = 260,
    sb_pivotroot = 261,
    sb_set_mnt_opts = 262,
    sb_clone_mnt_opts = 263,

    // BPF hooks
    bpf = 300,
    bpf_map = 301,
    bpf_prog = 302,
    bpf_map_alloc_security = 303,
    bpf_map_free_security = 304,
    bpf_prog_alloc_security = 305,
    bpf_prog_free_security = 306,
    bpf_token_alloc = 307,
    bpf_token_free = 308,
    bpf_token_cmd = 309,
    bpf_token_capable = 310,

    // io_uring hooks
    uring_override_creds = 350,
    uring_sqpoll = 351,
    uring_cmd = 352,
};

// ============================================================================
// Smack (Simplified Mandatory Access Control Kernel)
// ============================================================================

/// Smack label (max 255 chars)
pub const SmackLabel = struct {
    label: [256]u8 = [_]u8{0} ** 256,
    label_len: u8 = 0,
    known: bool = false,
};

/// Smack access type
pub const SmackAccess = packed struct(u32) {
    read: bool = false,       // r
    write: bool = false,      // w
    execute: bool = false,    // x
    append: bool = false,     // a
    transmute: bool = false,  // t
    lock: bool = false,       // l
    bring_up: bool = false,   // b
    _padding: u25 = 0,
};

/// Smack rule
pub const SmackRule = struct {
    subject: SmackLabel = .{},
    object: SmackLabel = .{},
    access: SmackAccess = .{},
};

/// Smack cipso (CIPSO/CALIPSO mapping)
pub const SmackCipso = struct {
    label: SmackLabel = .{},
    level: u8 = 0,
    cat_set: [32]u8 = [_]u8{0} ** 32,  // 256 categories bitmap
};

/// Smack onlycap
pub const SmackOnlycap = struct {
    labels: [16]SmackLabel = [_]SmackLabel{.{}} ** 16,
    count: u8 = 0,
};

// ============================================================================
// TOMOYO
// ============================================================================

/// TOMOYO profile number
pub const TomoyoProfile = enum(u8) {
    disabled = 0,
    learning = 1,
    permissive = 2,
    enforcing = 3,
};

/// TOMOYO domain transition type
pub const TomoyoDomainType = enum(u8) {
    normal = 0,
    initializer = 1,
    no_initialize = 2,
    keep = 3,
    no_keep = 4,
    transition = 5,
};

/// TOMOYO ACL type
pub const TomoyoAclType = enum(u8) {
    file_execute = 0,
    file_open = 1,
    file_create = 2,
    file_unlink = 3,
    file_getattr = 4,
    file_mkdir = 5,
    file_rmdir = 6,
    file_mkfifo = 7,
    file_mksock = 8,
    file_truncate = 9,
    file_symlink = 10,
    file_mkblock = 11,
    file_mkchar = 12,
    file_link = 13,
    file_rename = 14,
    file_chmod = 15,
    file_chown = 16,
    file_chgrp = 17,
    file_ioctl = 18,
    file_chroot = 19,
    file_mount = 20,
    file_umount = 21,
    file_pivot_root = 22,
    env_var = 23,
    inet_stream_listen = 24,
    inet_stream_connect = 25,
    inet_dgram_bind = 26,
    inet_dgram_send = 27,
    inet_raw_bind = 28,
    inet_raw_send = 29,
    unix_stream_bind = 30,
    unix_stream_listen = 31,
    unix_stream_connect = 32,
    unix_dgram_bind = 33,
    unix_dgram_send = 34,
    unix_seqpacket_bind = 35,
    unix_seqpacket_listen = 36,
    unix_seqpacket_connect = 37,
    manual_domain_transition = 38,
    auto_domain_transition = 39,
    task_setuid = 40,
    task_setgid = 41,
    task_use_capabilities = 42,
};

/// TOMOYO domain descriptor
pub const TomoyoDomain = struct {
    name: [512]u8 = [_]u8{0} ** 512,
    name_len: u16 = 0,
    profile: TomoyoProfile = .disabled,
    flags: TomoyoDomainFlags = .{},
    nr_acl: u32 = 0,
    transition_failed: u64 = 0,
};

pub const TomoyoDomainFlags = packed struct(u32) {
    quota_warned: bool = false,
    ignore_global_allow_read: bool = false,
    ignore_global_allow_env: bool = false,
    transition_failed: bool = false,
    _padding: u28 = 0,
};

// ============================================================================
// Yama LSM
// ============================================================================

/// Yama ptrace scope
pub const YamaPtraceScope = enum(u32) {
    classic = 0,           // classic ptrace permissions
    restricted = 1,        // restricted to descendants
    admin_only = 2,        // admin-only attach
    no_attach = 3,         // completely disabled
};

/// Yama relation type
pub const YamaRelation = enum(u8) {
    descendant = 0,
    declared = 1,
};

// ============================================================================
// SafeSetID
// ============================================================================

/// SafeSetID policy type
pub const SafeSetIdPolicyType = enum(u8) {
    uid = 0,
    gid = 1,
};

/// SafeSetID rule
pub const SafeSetIdRule = struct {
    policy_type: SafeSetIdPolicyType = .uid,
    src: u32 = 0,
    dst: u32 = 0,
};

// ============================================================================
// LoadPin
// ============================================================================

/// LoadPin config
pub const LoadPinConfig = struct {
    enabled: bool = false,
    enforce: bool = false,
    pinned_root: u64 = 0,     // device where loading is allowed
    // Extended trusted verity roots
    nr_trusted_verity_roots: u32 = 0,
};

// ============================================================================
// Lockdown
// ============================================================================

/// Lockdown level
pub const LockdownLevel = enum(u8) {
    none = 0,
    integrity = 1,     // protect kernel integrity
    confidentiality = 2, // protect kernel confidentiality
};

/// Lockdown reason
pub const LockdownReason = enum(u8) {
    none = 0,
    unsigned_module = 1,
    hibernation = 2,
    pci_access = 3,
    ioport = 4,
    msr = 5,
    acpi_tables = 6,
    pcmcia_cis = 7,
    tiocsserial = 8,
    module_params = 9,
    mmiotrace = 10,
    debugfs = 11,
    xmon_wr = 12,
    bpf_read = 13,
    efivar_ssdt = 14,
    device_tree = 15,
    kexec = 16,
    ima_appraise = 17,
    kprobes = 18,
    bpf_write_user = 19,
    ioctl_compat = 20,
    // Zxyphor
    zxy_raw_io = 100,
};

// ============================================================================
// IMA Extended (Integrity Measurement Architecture)
// ============================================================================

/// IMA policy action
pub const ImaPolicyAction = packed struct(u32) {
    measure: bool = false,
    dont_measure: bool = false,
    appraise: bool = false,
    dont_appraise: bool = false,
    audit: bool = false,
    dont_audit: bool = false,
    hash: bool = false,
    dont_hash: bool = false,
    // Zxyphor
    zxy_attest: bool = false,
    _padding: u23 = 0,
};

/// IMA template descriptor
pub const ImaTemplateDesc = enum(u8) {
    ima = 0,           // d|n (legacy)
    ima_ng = 1,        // d-ng|n-ng
    ima_sig = 2,       // d-ng|n-ng|sig
    ima_buf = 3,       // d-ng|n-ng|buf
    ima_modsig = 4,    // d-ng|n-ng|sig|d-modsig|modsig
    evm_hmac = 5,
    // Zxyphor
    zxy_full = 100,
};

/// IMA hash algorithm
pub const ImaHashAlgo = enum(u8) {
    md5 = 0,
    sha1 = 1,
    rmd160 = 2,
    sha256 = 3,
    sha384 = 4,
    sha512 = 5,
    wp512 = 6,
    sm3 = 7,
    // Zxyphor
    zxy_blake3 = 100,
};

/// IMA policy rule condition
pub const ImaPolicyCond = enum(u8) {
    uid = 0,
    euid = 1,
    gid = 2,
    egid = 3,
    fowner = 4,
    fgroup = 5,
    fsuuid = 6,
    fsuuid_all = 7,
    lsm_subj_user = 8,
    lsm_subj_role = 9,
    lsm_subj_type = 10,
    lsm_obj_user = 11,
    lsm_obj_role = 12,
    lsm_obj_type = 13,
    func = 14,
    mask = 15,
    fsname = 16,
    keyrings = 17,
    label = 18,
};

/// IMA function (what triggered the measurement)
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

/// EVM (Extended Verification Module) mode
pub const EvmMode = enum(u8) {
    off = 0,
    setup = 1,
    init = 2,
    initialized = 3,
};

/// EVM hash type
pub const EvmHashType = enum(u8) {
    hmac = 0,
    digital_signature = 1,
    portable_signature = 2,
};

// ============================================================================
// Security Namespace (Zxyphor)
// ============================================================================

pub const SecurityNamespace = struct {
    id: u32 = 0,
    parent_id: u32 = 0,
    lsm_id: LsmId = .selinux,
    policy_version: u32 = 0,
    confined: bool = false,
    nr_subjects: u64 = 0,
    nr_objects: u64 = 0,
    nr_rules: u64 = 0,
    deny_count: u64 = 0,
    allow_count: u64 = 0,
};

// ============================================================================
// Security Modules Subsystem Manager
// ============================================================================

pub const SecurityModulesSubsystem = struct {
    lsm_order: LsmOrder = .{},
    lockdown_level: LockdownLevel = .none,
    yama_ptrace_scope: YamaPtraceScope = .classic,
    ima_enabled: bool = false,
    ima_template: ImaTemplateDesc = .ima_ng,
    ima_hash: ImaHashAlgo = .sha256,
    evm_mode: EvmMode = .off,
    loadpin: LoadPinConfig = .{},
    nr_smack_rules: u64 = 0,
    nr_tomoyo_domains: u64 = 0,
    nr_security_ns: u32 = 0,
    initialized: bool = false,

    pub fn init() SecurityModulesSubsystem {
        return SecurityModulesSubsystem{
            .initialized = true,
        };
    }
};
