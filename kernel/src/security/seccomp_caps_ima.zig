// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Seccomp BPF, Capability Sets, Security Contexts,
// Linux Security Keys, IMA/EVM, SafeSetID, LoadPin
// More advanced than Linux 2026 security subsystem

const std = @import("std");

// ============================================================================
// Seccomp BPF
// ============================================================================

/// Seccomp mode
pub const SeccompMode = enum(u32) {
    disabled = 0,
    strict = 1,      // Only read/write/exit/sigreturn
    filter = 2,      // BPF filter mode
};

/// Seccomp action
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

/// Seccomp data (passed to BPF filter)
pub const SeccompData = struct {
    nr: i32,              // System call number
    arch: u32,            // AUDIT_ARCH_*
    instruction_pointer: u64,
    args: [6]u64,
};

/// Seccomp filter flags
pub const SeccompFilterFlags = packed struct {
    tsync: bool = false,             // Thread sync
    log: bool = false,               // Log actions
    spec_allow: bool = false,        // Disable speculative store bypass mitigation
    new_listener: bool = false,      // Get notif FD
    tsync_esrch: bool = false,       // ESRCH for TSYNC failure
    wait_killable_recv: bool = false, // Killable usernotif recvmsg
    _padding: u10 = 0,
};

/// Seccomp notif (user notification)
pub const SeccompNotif = struct {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
};

/// Seccomp notif response
pub const SeccompNotifResp = struct {
    id: u64,
    val: i64,
    err: i32,
    flags: u32,         // SECCOMP_USER_NOTIF_FLAG_CONTINUE
};

/// Seccomp notif add FD (inject FD into target)
pub const SeccompNotifAddFd = struct {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
};

/// Per-filter stats
pub const SeccompFilterStats = struct {
    nr_progs: u32,
    total_insns: u32,
    max_insns: u32,
    nr_allow: u64,
    nr_kill: u64,
    nr_log: u64,
    nr_trace: u64,
    nr_errno: u64,
    nr_notif: u64,
    // Zxyphor
    zxy_cache_hits: u64,
    zxy_cache_misses: u64,
};

// ============================================================================
// Capabilities
// ============================================================================

/// Capability values (Linux-compatible)
pub const Cap = enum(u8) {
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
    // Zxyphor
    zxy_hypervisor = 50,
    zxy_hardware = 51,
    zxy_crypto = 52,
    zxy_namespace = 53,
};

pub const CAP_LAST_CAP: u8 = 53; // Zxyphor

/// Capability set (bitmask, 64-bit for extended caps)
pub const CapSet = struct {
    effective: u64,
    permitted: u64,
    inheritable: u64,
};

/// Thread capability state
pub const ThreadCapState = struct {
    cap_effective: u64,
    cap_permitted: u64,
    cap_inheritable: u64,
    cap_bounding: u64,
    cap_ambient: u64,
    // Secure bits
    securebits: SecureBits,
    // No new privs
    no_new_privs: bool,
};

/// Secure bits
pub const SecureBits = packed struct {
    noroot: bool = false,
    noroot_locked: bool = false,
    no_setuid_fixup: bool = false,
    no_setuid_fixup_locked: bool = false,
    keep_caps: bool = false,
    keep_caps_locked: bool = false,
    no_cap_ambient_raise: bool = false,
    no_cap_ambient_raise_locked: bool = false,
    _padding: u8 = 0,
};

/// VFS capability header (stored in xattr)
pub const VfsCapData = struct {
    magic_etc: u32,       // VFS_CAP_REVISION_* | VFS_CAP_FLAGS_*
    rootid: u32,          // Namespace root UID
    permitted: u64,
    inheritable: u64,
};

pub const VFS_CAP_REVISION_1: u32 = 0x01000000;
pub const VFS_CAP_REVISION_2: u32 = 0x02000000;
pub const VFS_CAP_REVISION_3: u32 = 0x03000000; // Namespace aware
pub const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x000001;

// ============================================================================
// Security Contexts (SELinux/Smack/AppArmor)
// ============================================================================

/// Security label type
pub const SecurityLabelType = enum(u8) {
    none = 0,
    selinux = 1,
    smack = 2,
    apparmor = 3,
    tomoyo = 4,
    // Zxyphor
    zxy_unified = 10,
};

/// SELinux security context
pub const SelinuxContext = struct {
    user: [64]u8,
    user_len: u8,
    role: [64]u8,
    role_len: u8,
    stype: [64]u8, // "type" is reserved
    type_len: u8,
    level: [128]u8,
    level_len: u8,
    // SID (Security Identifier)
    sid: u32,
};

/// SELinux access vector
pub const SelinuxAv = struct {
    source_sid: u32,
    target_sid: u32,
    tclass: u16,         // Object class
    requested: u32,      // Permission bits
    audited: u32,
    denied: u32,
};

/// SELinux object class
pub const SelinuxObjClass = enum(u16) {
    process = 1,
    file = 2,
    dir = 3,
    fd = 4,
    lnk_file = 5,
    chr_file = 6,
    blk_file = 7,
    sock_file = 8,
    fifo_file = 9,
    socket = 10,
    tcp_socket = 11,
    udp_socket = 12,
    rawip_socket = 13,
    node = 14,
    netif = 15,
    netlink_socket = 16,
    packet_socket = 17,
    key_socket = 18,
    unix_stream_socket = 19,
    unix_dgram_socket = 20,
    sem = 21,
    msg = 22,
    msgq = 23,
    shm = 24,
    ipc = 25,
    filesystem = 26,
    key = 27,
    capability = 28,
    capability2 = 29,
    bpf = 30,
    perf_event = 31,
    lockdown = 32,
    io_uring = 33,
    // Zxyphor
    zxy_hypervisor = 50,
    zxy_device = 51,
};

// ============================================================================
// Linux Security Keys (Kernel Keyring)
// ============================================================================

/// Key type
pub const KeyType = enum(u8) {
    user = 0,
    logon = 1,
    keyring = 2,
    big_key = 3,
    trusted = 4,
    encrypted = 5,
    asymmetric = 6,
    dns_resolver = 7,
    rxrpc = 8,
    rxrpc_s = 9,
    id_resolver = 10,
    id_legacy = 11,
    // Zxyphor
    zxy_hardware = 20,
    zxy_tpm_sealed = 21,
};

/// Key permissions
pub const KeyPermissions = packed struct {
    // Possessor permissions
    poss_view: bool = false,
    poss_read: bool = false,
    poss_write: bool = false,
    poss_search: bool = false,
    poss_link: bool = false,
    poss_setattr: bool = false,
    _poss_reserved: u2 = 0,
    // User (owner) permissions
    usr_view: bool = false,
    usr_read: bool = false,
    usr_write: bool = false,
    usr_search: bool = false,
    usr_link: bool = false,
    usr_setattr: bool = false,
    _usr_reserved: u2 = 0,
    // Group permissions
    grp_view: bool = false,
    grp_read: bool = false,
    grp_write: bool = false,
    grp_search: bool = false,
    grp_link: bool = false,
    grp_setattr: bool = false,
    _grp_reserved: u2 = 0,
    // Other permissions
    oth_view: bool = false,
    oth_read: bool = false,
    oth_write: bool = false,
    oth_search: bool = false,
    oth_link: bool = false,
    oth_setattr: bool = false,
    _oth_reserved: u2 = 0,
};

/// Key flags
pub const KeyFlags = packed struct {
    dead: bool = false,
    revoked: bool = false,
    negative: bool = false,
    built_in: bool = false,
    uid_keyring: bool = false,
    root_can_clear: bool = false,
    invalidated: bool = false,
    trusted_only: bool = false,
    root_can_inval: bool = false,
    keep: bool = false,
    _padding: u6 = 0,
};

/// Key descriptor
pub const KeyDescriptor = struct {
    serial: i32,           // Key serial number
    key_type: KeyType,
    description: [256]u8,
    desc_len: u16,
    uid: u32,
    gid: u32,
    perm: KeyPermissions,
    flags: KeyFlags,
    // Expiry
    expiry: i64,           // 0 = no expiry
    // Payload
    payload_size: u32,
    // Quota
    quotalen: u16,
    // Zxyphor
    zxy_hw_bound: bool,
    zxy_attestation: [64]u8,
};

/// Special keyring IDs
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;

// ============================================================================
// IMA (Integrity Measurement Architecture)
// ============================================================================

/// IMA hash algorithm
pub const ImaHashAlgo = enum(u8) {
    md5 = 0,
    sha1 = 1,
    ripemd160 = 2,
    sha256 = 3,
    sha384 = 4,
    sha512 = 5,
    sha224 = 6,
    sha3_256 = 7,
    sha3_384 = 8,
    sha3_512 = 9,
    sm3 = 10,
    // Zxyphor
    zxy_blake3 = 20,
    zxy_shake256 = 21,
};

/// IMA action
pub const ImaAction = enum(u8) {
    dont_measure = 0,
    measure = 1,
    dont_appraise = 2,
    appraise = 3,
    audit = 4,
    hash = 5,
    dont_hash = 6,
};

/// IMA hooks
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
    // Zxyphor
    zxy_driver_check = 20,
    zxy_bpf_check = 21,
};

/// IMA policy rule
pub const ImaPolicyRule = struct {
    action: ImaAction,
    hooks: u32,          // Bitmask of ImaHook
    uid_op: u8,          // 0=eq, 1=ne, 2=lt, 3=gt
    uid: u32,
    fowner_op: u8,
    fowner: u32,
    lsm_label: [256]u8,
    lsm_label_len: u16,
    func_mask: u32,
    flags: u32,
    hash_algo: ImaHashAlgo,
    pcr: u8,             // TPM PCR to extend
    // Template
    template_name: [32]u8,
    template_name_len: u8,
};

/// IMA measurement entry
pub const ImaMeasurement = struct {
    pcr: u8,
    template_hash: [64]u8,
    template_hash_len: u8,
    template_name: [32]u8,
    // File digest
    file_hash_algo: ImaHashAlgo,
    file_hash: [64]u8,
    file_hash_len: u8,
    // File name
    filename: [256]u8,
    filename_len: u16,
    // Signature
    sig_present: bool,
    sig_type: u8,         // IMA_DIGSIG_*, EVM_IMA_XATTR_*
};

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

/// EVM type
pub const EvmType = enum(u8) {
    hmac = 0,
    xattr = 1,
    hmac_xattr = 2, // Both
};

/// EVM protected xattrs
pub const EvmXattrType = enum(u8) {
    security_selinux = 0,
    security_smack = 1,
    security_apparmor = 2,
    security_ima = 3,
    security_capability = 4,
    // Zxyphor
    zxy_security_context = 10,
};

/// EVM inode flags
pub const EvmInodeFlags = packed struct {
    immutable: bool = false,
    init_hmac: bool = false,
    init_xattr: bool = false,
    _padding: u5 = 0,
};

// ============================================================================
// SafeSetID / LoadPin
// ============================================================================

/// SafeSetID policy type
pub const SafeSetIdPolicy = enum(u8) {
    allow_setuid = 0,
    allow_setgid = 1,
};

/// SafeSetID rule
pub const SafeSetIdRule = struct {
    policy_type: SafeSetIdPolicy,
    from_id: u32,
    to_id: u32,
};

/// LoadPin state
pub const LoadPinState = struct {
    enabled: bool,
    // Root device
    root_dev: u64,       // Device number
    // Allowed
    allow_sysfs: bool,
    allow_debugfs: bool,
    // Zxyphor
    zxy_signed_only: bool,
};

// ============================================================================
// Lockdown
// ============================================================================

/// Lockdown level
pub const LockdownLevel = enum(u8) {
    none = 0,
    integrity = 1,
    confidentiality = 2,
    // Zxyphor
    zxy_paranoid = 10,
};

/// Lockdown reason
pub const LockdownReason = enum(u8) {
    none = 0,
    unsigned_module = 1,
    dev_mem = 2,
    ext_set_module_params = 3,
    kexec = 4,
    hibernation = 5,
    pci_access = 6,
    ioport = 7,
    msr = 8,
    acpi_tables = 9,
    pcmcia_cis = 10,
    tiocsserial = 11,
    module_parameters = 12,
    mmiotrace = 13,
    debugfs = 14,
    xmon_rw = 15,
    bpf_read_kernel = 16,
    perf_cpu = 17,
    tracefs = 18,
    xmon_wr = 19,
    xfrm_alg = 20,
    integrity_max = 21,
    kcore = 22,
    kprobes = 23,
    bpf_write_user = 24,
    confidentiality_max = 25,
    // Zxyphor
    zxy_hw_debug = 30,
    zxy_hypervisor = 31,
};

// ============================================================================
// Security Subsystem Manager
// ============================================================================

pub const SecurityContextSubsystem = struct {
    // Seccomp
    seccomp_mode: SeccompMode,
    nr_seccomp_filters: u64,
    nr_seccomp_notifs: u64,
    total_seccomp_checks: u64,
    // Capabilities
    cap_last_cap: u8,
    nr_cap_checks: u64,
    nr_cap_denials: u64,
    // Keyring
    nr_keys: u64,
    nr_keyrings: u64,
    key_quota_bytes: u64,
    // IMA
    ima_enabled: bool,
    ima_hash_algo: ImaHashAlgo,
    nr_ima_measurements: u64,
    // EVM
    evm_enabled: bool,
    evm_type: EvmType,
    // Lockdown
    lockdown_level: LockdownLevel,
    // Zxyphor
    zxy_hw_security: bool,
    zxy_unified_labels: bool,
    initialized: bool,

    pub fn init() SecurityContextSubsystem {
        return SecurityContextSubsystem{
            .seccomp_mode = .disabled,
            .nr_seccomp_filters = 0,
            .nr_seccomp_notifs = 0,
            .total_seccomp_checks = 0,
            .cap_last_cap = CAP_LAST_CAP,
            .nr_cap_checks = 0,
            .nr_cap_denials = 0,
            .nr_keys = 0,
            .nr_keyrings = 0,
            .key_quota_bytes = 0,
            .ima_enabled = true,
            .ima_hash_algo = .sha256,
            .nr_ima_measurements = 0,
            .evm_enabled = true,
            .evm_type = .hmac_xattr,
            .lockdown_level = .integrity,
            .zxy_hw_security = true,
            .zxy_unified_labels = true,
            .initialized = false,
        };
    }
};
