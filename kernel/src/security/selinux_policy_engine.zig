// Zxyphor Kernel - SELinux Policy Engine Detail,
// Type Enforcement (TE) Rules, Role-Based Access Control,
// MLS/MCS, Security Contexts, AVC Cache,
// Policy DB Format, Conditional Booleans,
// Security Server Interface
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// SELinux Policy Version
// ============================================================================

pub const SELINUX_POLICY_VERSION: u32 = 33;
pub const SELINUX_MAGIC: u32 = 0xF97CFF8C;

pub const PolicyVersion = enum(u32) {
    base = 15,
    mlsfields = 19,
    avtab_hash = 20,
    rangetrans = 21,
    polcap = 22,
    permissive = 23,
    boundary = 24,
    filename_trans = 25,
    roletrans = 26,
    new_object_defaults = 27,
    default_type = 28,
    constraint_names = 29,
    xperms_ioctl = 30,
    infiniband = 31,
    glblub = 32,
    comp_ftrans = 33,
};

// ============================================================================
// Security Class IDs (common kernel classes)
// ============================================================================

pub const SecurityClass = enum(u16) {
    unspecified = 0,
    security = 1,
    process = 2,
    system = 3,
    capability = 4,
    filesystem = 5,
    file = 6,
    dir = 7,
    fd = 8,
    lnk_file = 9,
    chr_file = 10,
    blk_file = 11,
    sock_file = 12,
    fifo_file = 13,
    socket = 14,
    tcp_socket = 15,
    udp_socket = 16,
    rawip_socket = 17,
    node = 18,
    netif = 19,
    netlink_socket = 20,
    packet_socket = 21,
    key_socket = 22,
    unix_stream = 23,
    unix_dgram = 24,
    sem = 25,
    msg = 26,
    msgq = 27,
    shm = 28,
    ipc = 29,
    netlink_route = 30,
    netlink_firewall = 31,
    netlink_tcpdiag = 32,
    netlink_nflog = 33,
    netlink_xfrm = 34,
    netlink_selinux = 35,
    netlink_audit = 36,
    netlink_ip6fw = 37,
    netlink_dnrt = 38,
    association = 39,
    netlink_kobject_uevent = 40,
    appletalk_socket = 41,
    packet = 42,
    key = 43,
    dccp_socket = 44,
    memprotect = 45,
    peer = 46,
    kernel_service = 47,
    tun_socket = 48,
    binder = 49,
    cap_userns = 50,
    cap2_userns = 51,
    sctp_socket = 52,
    icmp_socket = 53,
    ax25_socket = 54,
    netrom_socket = 55,
    rose_socket = 56,
    bpf = 57,
    xdp_socket = 58,
    perf_event = 59,
    lockdown = 60,
    io_uring = 61,
};

// ============================================================================
// File Permission Bits (SELinux)
// ============================================================================

pub const FilePerms = packed struct(u32) {
    ioctl: bool = false,
    read: bool = false,
    write: bool = false,
    create: bool = false,
    getattr: bool = false,
    setattr: bool = false,
    lock: bool = false,
    relabelfrom: bool = false,
    relabelto: bool = false,
    append: bool = false,
    map: bool = false,
    unlink: bool = false,
    link: bool = false,
    rename: bool = false,
    execute: bool = false,
    quotaon: bool = false,
    mounton: bool = false,
    audit_access: bool = false,
    open: bool = false,
    execmod: bool = false,
    watch: bool = false,
    watch_mount: bool = false,
    watch_sb: bool = false,
    watch_with_perm: bool = false,
    watch_reads: bool = false,
    _reserved: u7 = 0,
};

pub const ProcessPerms = packed struct(u32) {
    fork: bool = false,
    transition: bool = false,
    sigchld: bool = false,
    sigkill: bool = false,
    sigstop: bool = false,
    signull: bool = false,
    signal: bool = false,
    ptrace: bool = false,
    getsched: bool = false,
    setsched: bool = false,
    getsession: bool = false,
    getpgid: bool = false,
    setpgid: bool = false,
    getcap: bool = false,
    setcap: bool = false,
    share: bool = false,
    getattr: bool = false,
    setexec: bool = false,
    setfscreate: bool = false,
    noatsecure: bool = false,
    siginh: bool = false,
    setrlimit: bool = false,
    rlimitinh: bool = false,
    dyntransition: bool = false,
    setcurrent: bool = false,
    execmem: bool = false,
    execstack: bool = false,
    execheap: bool = false,
    setkeycreate: bool = false,
    setsockcreate: bool = false,
    getrlimit: bool = false,
    _reserved: bool = false,
};

// ============================================================================
// Access Vector Table (avtab)
// ============================================================================

pub const AvtabKey = struct {
    source_type: u16,
    target_type: u16,
    target_class: u16,
    specified: AvtabSpecified,
};

pub const AvtabSpecified = enum(u16) {
    allowed = 0x0001,
    auditallow = 0x0002,
    auditdeny = 0x0004,
    neverallow = 0x0080,
    transition = 0x0010,
    member = 0x0020,
    change = 0x0040,
    xperms_allowed = 0x0100,
    xperms_auditallow = 0x0200,
    xperms_dontaudit = 0x0400,
    xperms_neverallow = 0x0800,
};

pub const AvtabDatum = struct {
    data: u32,                    // permission bitmask or type ID
    xperms: ?*AvtabXperms,
};

pub const AvtabXperms = struct {
    specified: u8,
    driver: u8,
    perms: [8]u32,               // 256-bit permission bitmap
};

// ============================================================================
// Access Vector Cache (AVC)
// ============================================================================

pub const AVC_CACHE_SLOTS: usize = 512;
pub const AVC_CACHE_THRESHOLD: usize = 512;

pub const AvcEntry = struct {
    key: AvcEntryKey,
    allowed: u32,
    auditallow: u32,
    auditdeny: u32,
    tsid: u32,
    sequence: u32,
};

pub const AvcEntryKey = struct {
    ssid: u32,                    // source SID
    tsid: u32,                    // target SID
    tclass: u16,                  // target class
};

pub const AvcDecision = enum(u8) {
    allowed = 0,
    denied = 1,
    auditallow = 2,
    dontaudit = 3,
};

pub const AvcAuditData = struct {
    audit_type: AvcAuditType,
    selinux_audit_rule: ?*anyopaque,
    // Union-style fields
    fs_inode: ?u64,
    fs_path: ?[256]u8,
    net_port: ?u16,
    net_addr: ?[16]u8,
    net_netif: ?[16]u8,
    pid: ?u32,
    cap: ?u32,
    ipc_id: ?u32,
};

pub const AvcAuditType = enum(u8) {
    none = 0,
    ipc = 1,
    cap = 2,
    fs = 3,
    net = 4,
    ioctl = 5,
};

pub const AvcStats = struct {
    lookups: u64,
    hits: u64,
    misses: u64,
    allocations: u64,
    reclaims: u64,
    frees: u64,
};

// ============================================================================
// Security Context
// ============================================================================

pub const SecurityContext = struct {
    user: u32,
    role: u32,
    type_: u32,           // type (TE)
    range: MlsRange,
    str_repr: [256]u8,    // "user:role:type:level" string
    str_len: u16,
};

pub const MlsRange = struct {
    low: MlsLevel,
    high: MlsLevel,
};

pub const MlsLevel = struct {
    sensitivity: u32,
    category: MlsCatSet,
};

pub const MlsCatSet = struct {
    bits: [8]u64,         // 512-bit category bitmap
};

// ============================================================================
// Type Enforcement Policy
// ============================================================================

pub const TypeDatum = struct {
    type_id: u32,
    primary: bool,
    attribute: bool,
    permissive: bool,
    bounds: u32,          // bounded type
    name: [64]u8,
};

pub const TypeAttr = struct {
    attr_id: u32,
    types: TypeBitmap,     // types in this attribute
    name: [64]u8,
};

pub const TypeBitmap = struct {
    bits: [128]u64,        // support up to 8192 types
};

pub const RoleDatum = struct {
    role_id: u32,
    dominates: RoleBitmap,
    types: TypeBitmap,     // allowed types for this role
    bounds: u32,
    name: [32]u8,
};

pub const RoleBitmap = struct {
    bits: [4]u64,          // up to 256 roles
};

pub const UserDatum = struct {
    user_id: u32,
    roles: RoleBitmap,     // allowed roles
    default_level: MlsLevel,
    range: MlsRange,
    name: [32]u8,
};

// ============================================================================
// Conditional Booleans
// ============================================================================

pub const CondBool = struct {
    bool_id: u32,
    state: bool,
    name: [64]u8,
};

pub const CondNode = struct {
    expr: [32]CondExprNode,
    expr_len: u8,
    true_list: ?*CondAvRule,
    false_list: ?*CondAvRule,
    cur_state: bool,
};

pub const CondExprType = enum(u8) {
    bool_val = 1,
    not = 2,
    or_ = 3,
    and_ = 4,
    xor_ = 5,
    eq = 6,
    neq = 7,
};

pub const CondExprNode = struct {
    expr_type: CondExprType,
    bool_id: u32,
};

pub const CondAvRule = struct {
    key: AvtabKey,
    datum: AvtabDatum,
    next: ?*CondAvRule,
};

// ============================================================================
// Role Transitions & Type Transitions
// ============================================================================

pub const RoleTransRule = struct {
    role: u32,
    type_: u32,
    tclass: u16,
    new_role: u32,
};

pub const TypeTransRule = struct {
    source_type: u16,
    target_type: u16,
    tclass: u16,
    default_type: u16,
    filename: ?[256]u8,    // filename transition (optional)
};

pub const RangeTransRule = struct {
    source_type: u16,
    target_type: u16,
    tclass: u16,
    target_range: MlsRange,
};

// ============================================================================
// Constraints
// ============================================================================

pub const ConstraintExprType = enum(u8) {
    not = 1,
    and_ = 2,
    or_ = 3,
    attr = 4,
    names = 5,
};

pub const ConstraintAttr = enum(u8) {
    user = 1,
    role = 2,
    type_ = 3,
    mls_level_low = 4,
    mls_level_high = 5,
    mls_level_low_high = 6,
};

pub const ConstraintOp = enum(u8) {
    eq = 1,
    neq = 2,
    dom = 3,
    domby = 4,
    incomp = 5,
};

pub const Constraint = struct {
    permissions: u32,
    expr: [16]ConstraintExprNode,
    expr_len: u8,
    names: ?*TypeBitmap,
};

pub const ConstraintExprNode = struct {
    expr_type: ConstraintExprType,
    attr: ConstraintAttr,
    op: ConstraintOp,
};

// ============================================================================
// Object Context Defaults
// ============================================================================

pub const ObjectDefault = enum(u8) {
    unspecified = 0,
    source = 1,
    target = 2,
    // For range:
    source_low = 3,
    source_high = 4,
    source_low_high = 5,
    target_low = 6,
    target_high = 7,
    target_low_high = 8,
    glblub = 9,
};

pub const ClassDefaults = struct {
    default_user: ObjectDefault,
    default_role: ObjectDefault,
    default_type: ObjectDefault,
    default_range: ObjectDefault,
};

// ============================================================================
// Policy Capabilities
// ============================================================================

pub const PolicyCap = enum(u8) {
    network_peer_controls = 0,
    open_perms = 1,
    extended_socket_class = 2,
    always_check_network = 3,
    cgroup_seclabel = 4,
    nnp_nosuid_transition = 5,
    genfs_seclabel_symlinks = 6,
    ioctl_skip_cloexec = 7,
};

pub const PolicyCapBitmap = packed struct(u32) {
    network_peer_controls: bool = false,
    open_perms: bool = false,
    extended_socket_class: bool = false,
    always_check_network: bool = false,
    cgroup_seclabel: bool = false,
    nnp_nosuid_transition: bool = false,
    genfs_seclabel_symlinks: bool = false,
    ioctl_skip_cloexec: bool = false,
    _reserved: u24 = 0,
};

// ============================================================================
// SID (Security Identifier) Table
// ============================================================================

pub const SID_UNLABELED: u32 = 1;
pub const SID_KERNEL: u32 = 2;
pub const SID_SECURITY: u32 = 3;
pub const SID_PORT: u32 = 4;
pub const SID_NETIF: u32 = 5;
pub const SID_NODE: u32 = 6;
pub const SID_ANY_SOCKET: u32 = 7;

pub const SidEntry = struct {
    sid: u32,
    context: SecurityContext,
    refcount: u32,
};

// ============================================================================
// Genfs (Generic Filesystem) Labeling
// ============================================================================

pub const GenfsEntry = struct {
    fstype: [32]u8,
    path: [256]u8,
    sclass: SecurityClass,
    sid: u32,
};

// ============================================================================
// SELinux Security Server
// ============================================================================

pub const SelinuxState = enum(u8) {
    disabled = 0,
    initializing = 1,
    permissive = 2,
    enforcing = 3,
};

pub const SelinuxSecurityServer = struct {
    state: SelinuxState,
    policy_version: u32,
    policy_loaded: bool,
    // SID table
    sid_count: u32,
    next_sid: u32,
    // Policy DB
    type_count: u32,
    role_count: u32,
    user_count: u32,
    bool_count: u32,
    class_count: u16,
    // AVC
    avc: AvcStats,
    // Policy capabilities
    polcap: PolicyCapBitmap,
    // Sequence
    latest_granting: u32,
    initialized: bool,

    pub fn init() SelinuxSecurityServer {
        return std.mem.zeroes(SelinuxSecurityServer);
    }
};
