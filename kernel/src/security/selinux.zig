// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Security: SELinux-compatible MAC, Audit, Keyring, IMA
// Full LSM framework with type enforcement, integrity measurement, key management

const std = @import("std");

// ============================================================================
// SELinux Security Context
// ============================================================================

pub const MAX_SECURITY_CONTEXT_LEN: usize = 4096;
pub const MAX_CATEGORY_BITS: usize = 1024;
pub const MAX_SENSITIVITY_LEVELS: usize = 256;
pub const MAX_TYPES: usize = 8192;
pub const MAX_ROLES: usize = 1024;
pub const MAX_USERS: usize = 1024;

pub const SecurityId = u32;
pub const SECSID_NULL: SecurityId = 0;
pub const SECSID_KERNEL: SecurityId = 1;
pub const SECSID_UNLABELED: SecurityId = 2;

pub const SecurityClass = enum(u16) {
    PROCESS = 1,
    FILE = 2,
    DIR = 3,
    FD = 4,
    LNK_FILE = 5,
    CHR_FILE = 6,
    BLK_FILE = 7,
    SOCK_FILE = 8,
    FIFO_FILE = 9,
    SOCKET = 10,
    TCP_SOCKET = 11,
    UDP_SOCKET = 12,
    RAWIP_SOCKET = 13,
    NODE = 14,
    NETIF = 15,
    NETLINK_SOCKET = 16,
    PACKET_SOCKET = 17,
    KEY_SOCKET = 18,
    UNIX_STREAM_SOCKET = 19,
    UNIX_DGRAM_SOCKET = 20,
    SEM = 21,
    MSG = 22,
    MSGQ = 23,
    SHM = 24,
    IPC = 25,
    CAPABILITY = 26,
    CAPABILITY2 = 27,
    SECURITY = 28,
    SYSTEM = 29,
    KEY = 30,
    MEMPROTECT = 31,
    BPF = 32,
    PERF_EVENT = 33,
    LOCKDOWN = 34,
    IO_URING = 35,
    // Zxyphor extensions
    ZXY_HYPERVISOR = 128,
    ZXY_CONTAINER = 129,
    ZXY_SANDBOX = 130,
    ZXY_ENCLAVE = 131,
    _,
};

// File permission bits (SELinux av_permissions)
pub const FILE_READ: u32 = 1 << 0;
pub const FILE_WRITE: u32 = 1 << 1;
pub const FILE_APPEND: u32 = 1 << 2;
pub const FILE_EXECUTE: u32 = 1 << 3;
pub const FILE_GETATTR: u32 = 1 << 4;
pub const FILE_SETATTR: u32 = 1 << 5;
pub const FILE_LOCK: u32 = 1 << 6;
pub const FILE_IOCTL: u32 = 1 << 7;
pub const FILE_CREATE: u32 = 1 << 8;
pub const FILE_RENAME: u32 = 1 << 9;
pub const FILE_LINK: u32 = 1 << 10;
pub const FILE_UNLINK: u32 = 1 << 11;
pub const FILE_OPEN: u32 = 1 << 12;
pub const FILE_MOUNTON: u32 = 1 << 13;
pub const FILE_QUOTAON: u32 = 1 << 14;
pub const FILE_WATCH: u32 = 1 << 15;
pub const FILE_WATCH_MOUNT: u32 = 1 << 16;
pub const FILE_WATCH_SB: u32 = 1 << 17;
pub const FILE_WATCH_WITH_PERM: u32 = 1 << 18;
pub const FILE_WATCH_READS: u32 = 1 << 19;
pub const FILE_MAP: u32 = 1 << 20;
pub const FILE_EXECMOD: u32 = 1 << 21;
pub const FILE_AUDIT_ACCESS: u32 = 1 << 22;

// Process permission bits
pub const PROCESS_FORK: u32 = 1 << 0;
pub const PROCESS_TRANSITION: u32 = 1 << 1;
pub const PROCESS_SIGCHLD: u32 = 1 << 2;
pub const PROCESS_SIGKILL: u32 = 1 << 3;
pub const PROCESS_SIGSTOP: u32 = 1 << 4;
pub const PROCESS_SIGNAL: u32 = 1 << 5;
pub const PROCESS_PTRACE: u32 = 1 << 6;
pub const PROCESS_GETSCHED: u32 = 1 << 7;
pub const PROCESS_SETSCHED: u32 = 1 << 8;
pub const PROCESS_GETSESSION: u32 = 1 << 9;
pub const PROCESS_GETPGID: u32 = 1 << 10;
pub const PROCESS_SETPGID: u32 = 1 << 11;
pub const PROCESS_GETCAP: u32 = 1 << 12;
pub const PROCESS_SETCAP: u32 = 1 << 13;
pub const PROCESS_SHARE: u32 = 1 << 14;
pub const PROCESS_GETATTR: u32 = 1 << 15;
pub const PROCESS_SETEXEC: u32 = 1 << 16;
pub const PROCESS_SETFSCREATE: u32 = 1 << 17;
pub const PROCESS_NOATSECURE: u32 = 1 << 18;
pub const PROCESS_SIGINH: u32 = 1 << 19;
pub const PROCESS_SETRLIMIT: u32 = 1 << 20;
pub const PROCESS_RLIMITINH: u32 = 1 << 21;
pub const PROCESS_DYNTRANSITION: u32 = 1 << 22;
pub const PROCESS_SETCURRENT: u32 = 1 << 23;
pub const PROCESS_EXECMEM: u32 = 1 << 24;
pub const PROCESS_EXECSTACK: u32 = 1 << 25;
pub const PROCESS_EXECHEAP: u32 = 1 << 26;
pub const PROCESS_SETKEYCREATE: u32 = 1 << 27;
pub const PROCESS_SETSOCKCREATE: u32 = 1 << 28;
pub const PROCESS_GETRLIMIT: u32 = 1 << 29;

// ============================================================================
// Security Context Structure
// ============================================================================

pub const SecurityContext = struct {
    user: u16,
    role: u16,
    type_: u16,
    // MLS/MCS (Multi-Level Security / Multi-Category Security)
    low_sensitivity: u16,
    high_sensitivity: u16,
    low_categories: [MAX_CATEGORY_BITS / 64]u64,
    high_categories: [MAX_CATEGORY_BITS / 64]u64,

    pub fn dominates(self: *const SecurityContext, other: *const SecurityContext) bool {
        // MLS dominance check: self >= other
        if (self.low_sensitivity < other.low_sensitivity) return false;
        if (self.high_sensitivity < other.high_sensitivity) return false;
        // Category check: self's categories ⊇ other's categories
        for (0..self.low_categories.len) |i| {
            if ((other.low_categories[i] & ~self.low_categories[i]) != 0) return false;
        }
        return true;
    }

    pub fn equals(self: *const SecurityContext, other: *const SecurityContext) bool {
        return self.user == other.user and
            self.role == other.role and
            self.type_ == other.type_ and
            self.low_sensitivity == other.low_sensitivity and
            self.high_sensitivity == other.high_sensitivity;
    }
};

// ============================================================================
// Type Enforcement Policy
// ============================================================================

pub const PolicyVersion = enum(u32) {
    BASE = 15,
    MLS = 19,
    AVTAB_HASH = 20,
    RANGETRANS = 21,
    POLCAP = 22,
    PERMISSIVE = 23,
    BOUNDARY = 24,
    FILENAME_TRANS = 25,
    ROLETRANS = 26,
    NEW_OBJECT_DEFAULTS = 27,
    DEFAULT_TYPE = 28,
    CONSTRAINT_NAMES = 29,
    XEN_DEVICETREE = 30,
    INFINIBAND = 31,
    GLBLUB = 32,
    COMP_FTRANS = 33,
    CURRENT = 33,
};

pub const AccessVectorRule = struct {
    source_type: u16,
    target_type: u16,
    target_class: SecurityClass,
    permissions: u32,
    specified: RuleType,
};

pub const RuleType = enum(u8) {
    ALLOWED = 0,
    AUDITALLOW = 1,
    AUDITDENY = 2,
    DONTAUDIT = 3,
    NEVERALLOW = 4,
    ALLOWXPERM = 5,
    AUDITALLOWXPERM = 6,
    DONTAUDITXPERM = 7,
    NEVERALLOWXPERM = 8,
    TYPE_TRANSITION = 9,
    TYPE_CHANGE = 10,
    TYPE_MEMBER = 11,
};

pub const TypeTransitionRule = struct {
    source_type: u16,
    target_type: u16,
    target_class: SecurityClass,
    default_type: u16,
    // Filename transition (optional)
    filename: ?[256]u8,
    filename_len: u16,
};

pub const RoleAllowRule = struct {
    role: u16,
    new_role: u16,
};

pub const RoleTransitionRule = struct {
    role: u16,
    type_: u16,
    tclass: SecurityClass,
    new_role: u16,
};

pub const ConstraintExpr = struct {
    expr_type: ExprType,
    attr: ConstraintAttr,
    op: ConstraintOp,
    names_count: u32,
    names: [64]u32, // Type/role/user IDs
    next: ?*ConstraintExpr,
};

pub const ExprType = enum(u8) {
    NOT = 0,
    AND = 1,
    OR = 2,
    ATTR = 3,
    NAMES = 4,
};

pub const ConstraintAttr = enum(u8) {
    USER = 1,
    ROLE = 2,
    TYPE = 3,
    USER_R2 = 4,
    ROLE_R2 = 5,
    TYPE_R2 = 6,
    L1_L2 = 7,
    L1_H2 = 8,
    H1_L2 = 9,
    H1_H2 = 10,
    L1_H1 = 11,
    L2_H2 = 12,
};

pub const ConstraintOp = enum(u8) {
    EQ = 1,
    NEQ = 2,
    DOM = 3,
    DOMBY = 4,
    INCOMP = 5,
};

// ============================================================================
// Policy Database
// ============================================================================

pub const MAX_AV_RULES: usize = 65536;
pub const MAX_TT_RULES: usize = 16384;
pub const MAX_ROLE_ALLOW_RULES: usize = 4096;
pub const MAX_BOOL_COUNT: usize = 512;

pub const PolicyBool = struct {
    name: [64]u8,
    name_len: u8,
    state: bool,
    default_state: bool,
};

pub const PolicyDb = struct {
    version: PolicyVersion,
    // Access Vector Rules (hash table)
    av_rules: [MAX_AV_RULES]?AccessVectorRule,
    av_rule_count: u32,
    // Type Transition Rules
    tt_rules: [MAX_TT_RULES]?TypeTransitionRule,
    tt_rule_count: u32,
    // Role allows
    role_allows: [MAX_ROLE_ALLOW_RULES]?RoleAllowRule,
    role_allow_count: u32,
    // Role transitions
    role_transitions: [MAX_ROLE_ALLOW_RULES]?RoleTransitionRule,
    role_trans_count: u32,
    // Booleans
    booleans: [MAX_BOOL_COUNT]?PolicyBool,
    bool_count: u32,
    // Type attributes
    type_attr_map: [MAX_TYPES / 64]u64,
    // Permissive types bitmap
    permissive_map: [MAX_TYPES / 64]u64,
    // Policy capabilities
    policycap: u32,

    const POLICYCAP_NETWORK_PEER_CONTROL: u32 = 1 << 0;
    const POLICYCAP_OPEN_PERMS: u32 = 1 << 1;
    const POLICYCAP_EXTENDED_SOCKET_CLASS: u32 = 1 << 2;
    const POLICYCAP_ALWAYS_CHECK_NETWORK: u32 = 1 << 3;
    const POLICYCAP_CGE: u32 = 1 << 4;
    const POLICYCAP_IOCTL_SKIP_CLOEXEC: u32 = 1 << 5;

    pub fn check_access(self: *PolicyDb, source_sid: SecurityId, target_sid: SecurityId, tclass: SecurityClass, requested: u32) AccessDecision {
        _ = source_sid;
        _ = target_sid;
        // Look up AV rules
        var allowed: u32 = 0;
        var audit_allow: u32 = 0;
        var audit_deny: u32 = 0xFFFFFFFF;

        for (self.av_rules[0..self.av_rule_count]) |maybe_rule| {
            const rule = maybe_rule orelse continue;
            if (rule.target_class != tclass) continue;

            switch (rule.specified) {
                .ALLOWED => allowed |= rule.permissions,
                .AUDITALLOW => audit_allow |= rule.permissions,
                .AUDITDENY => audit_deny &= ~rule.permissions,
                .DONTAUDIT => audit_deny &= ~rule.permissions,
                else => {},
            }
        }

        return .{
            .allowed = (requested & allowed) == requested,
            .audit = (requested & ~allowed & audit_deny) != 0 or (requested & allowed & audit_allow) != 0,
            .permitted = allowed,
            .audited = (requested & ~allowed & audit_deny) | (requested & allowed & audit_allow),
        };
    }

    pub fn is_permissive(self: *PolicyDb, type_id: u16) bool {
        const idx = type_id / 64;
        const bit: u6 = @truncate(type_id % 64);
        if (idx >= self.permissive_map.len) return false;
        return (self.permissive_map[idx] & (@as(u64, 1) << bit)) != 0;
    }
};

pub const AccessDecision = struct {
    allowed: bool,
    audit: bool,
    permitted: u32,
    audited: u32,
};

// ============================================================================
// Audit System
// ============================================================================

pub const AUDIT_MAX_FIELDS: usize = 64;
pub const AUDIT_BITMASK_SIZE: usize = 64;

pub const AuditMessageType = enum(u32) {
    // Generic
    GET = 1000,
    SET = 1001,
    LIST = 1002,
    ADD = 1003,
    DEL = 1004,
    USER = 1005,
    LOGIN = 1006,
    WATCH_INS = 1007,
    WATCH_REM = 1008,
    WATCH_LIST = 1009,
    SIGNAL_INFO = 1010,
    ADD_RULE = 1011,
    DEL_RULE = 1012,
    LIST_RULES = 1013,
    TRIM = 1014,
    MAKE_EQUIV = 1015,
    TTY_GET = 1016,
    TTY_SET = 1017,
    SET_FEATURE = 1018,
    GET_FEATURE = 1019,

    // Audit events
    SYSCALL = 1300,
    PATH = 1302,
    IPC = 1303,
    SOCKETCALL = 1304,
    CONFIG_CHANGE = 1305,
    SOCKADDR = 1306,
    CWD = 1307,
    EXECVE = 1309,
    IPC_SET_PERM = 1311,
    MQ_OPEN = 1312,
    MQ_SENDRECV = 1313,
    MQ_NOTIFY = 1314,
    MQ_GETSETATTR = 1315,
    KERNEL_OTHER = 1316,
    FD_PAIR = 1317,
    OBJ_PID = 1318,
    BPRM_FCAPS = 1321,
    CAPSET = 1322,
    MMAP = 1323,
    NETFILTER_PKT = 1324,
    NETFILTER_CFG = 1325,
    SECCOMP = 1326,
    PROCTITLE = 1327,
    FEATURE_CHANGE = 1328,
    REPLACE = 1329,
    KERN_MODULE = 1330,
    FANOTIFY = 1331,
    TIME_INJOFFSET = 1332,
    TIME_ADJNTPVAL = 1333,
    BPF = 1334,
    EVENT_LISTENER = 1335,
    URINGOP = 1336,
    OPENAT2 = 1337,
    DM_CTRL = 1338,
    DM_EVENT = 1339,

    // SELinux (AVC)
    AVC = 1400,
    SELINUX_ERR = 1401,
    AVC_PATH = 1402,

    // AppArmor
    APPARMOR_AUDIT = 1501,
    APPARMOR_ALLOWED = 1502,
    APPARMOR_DENIED = 1503,
    APPARMOR_HINT = 1504,
    APPARMOR_STATUS = 1505,
    APPARMOR_ERROR = 1506,

    // Integrity (IMA/EVM)
    INTEGRITY_DATA = 1800,
    INTEGRITY_METADATA = 1801,
    INTEGRITY_STATUS = 1802,
    INTEGRITY_HASH = 1803,
    INTEGRITY_PCR = 1804,
    INTEGRITY_RULE = 1805,
    INTEGRITY_EVM_XATTR = 1806,
    INTEGRITY_POLICY_RULE = 1807,

    // Anomaly events
    ANOM_PROMISCUOUS = 1700,
    ANOM_ABEND = 1701,
    ANOM_LINK = 1702,
    ANOM_CREAT = 1703,
    _,
};

pub const AuditField = enum(u32) {
    PID = 0,
    UID = 1,
    EUID = 2,
    SUID = 3,
    FSUID = 4,
    GID = 5,
    EGID = 6,
    SGID = 7,
    FSGID = 8,
    LOGINUID = 9,
    PERS = 10,
    ARCH = 11,
    MSGTYPE = 12,
    PPID = 18,
    LOGINUID_SET = 24,
    SESSIONID = 25,
    FSTYPE = 26,
    DEVMAJOR = 100,
    DEVMINOR = 101,
    INODE = 102,
    EXIT = 103,
    SUCCESS = 104,
    A0 = 200,
    A1 = 201,
    A2 = 202,
    A3 = 203,
    PERM = 106,
    FILETYPE = 107,
    OBJ_UID = 109,
    OBJ_GID = 110,
    FIELD_COMPARE = 111,
    EXE = 112,
    SUBJ_USER = 13,
    SUBJ_ROLE = 14,
    SUBJ_TYPE = 15,
    SUBJ_SEN = 16,
    SUBJ_CLR = 17,
    OBJ_USER = 19,
    OBJ_ROLE = 20,
    OBJ_TYPE = 21,
    OBJ_LEV_LOW = 22,
    OBJ_LEV_HIGH = 23,
    _,
};

pub const AuditOperator = enum(u32) {
    EQUAL = 0x40000000,
    NOT_EQUAL = 0x80000000,
    LESS_THAN = 0x10000000,
    LESS_THAN_OR_EQUAL = 0x50000000,
    GREATER_THAN = 0x20000000,
    GREATER_THAN_OR_EQUAL = 0x60000000,
    BIT_MASK = 0x08000000,
    BIT_TEST = 0x48000000,
};

pub const AuditRule = struct {
    flags: u32,
    action: AuditAction,
    field_count: u32,
    fields: [AUDIT_MAX_FIELDS]AuditFieldSpec,
    // Linked list of watches
    watch_path: ?[256]u8,
    watch_len: u16,
};

pub const AuditFieldSpec = struct {
    type_: AuditField,
    op: AuditOperator,
    val: u64,
    lsm_str: ?[256]u8,
};

pub const AuditAction = enum(u32) {
    NEVER = 0,
    POSSIBLE = 1,
    ALWAYS = 2,
};

pub const AuditRecord = struct {
    type_: AuditMessageType,
    serial: u64,
    timestamp_secs: u64,
    timestamp_nsecs: u32,
    pid: u32,
    uid: u32,
    auid: u32,     // Audit (login) UID
    ses: u32,      // Session ID
    // Message data
    message: [4096]u8,
    message_len: u32,
    // Context
    security_context: SecurityContext,
};

pub const AuditBuffer = struct {
    records: [8192]?AuditRecord,
    head: u32,
    tail: u32,
    serial_counter: u64,
    lost_count: u64,
    enabled: bool,
    backlog_limit: u32,
    rate_limit: u32,
    failure_action: AuditFailure,

    pub fn init() AuditBuffer {
        return .{
            .records = [_]?AuditRecord{null} ** 8192,
            .head = 0,
            .tail = 0,
            .serial_counter = 0,
            .lost_count = 0,
            .enabled = true,
            .backlog_limit = 8192,
            .rate_limit = 0,
            .failure_action = .PRINTK,
        };
    }

    pub fn log(self: *AuditBuffer, msg_type: AuditMessageType, message: []const u8) ?u64 {
        if (!self.enabled) return null;

        const next_head = (self.head + 1) % 8192;
        if (next_head == self.tail) {
            self.lost_count += 1;
            return null;
        }

        self.serial_counter += 1;
        var record = AuditRecord{
            .type_ = msg_type,
            .serial = self.serial_counter,
            .timestamp_secs = 0, // Would use ktime
            .timestamp_nsecs = 0,
            .pid = 0,
            .uid = 0,
            .auid = 0xFFFFFFFF,
            .ses = 0xFFFFFFFF,
            .message = undefined,
            .message_len = @intCast(@min(message.len, 4096)),
            .security_context = undefined,
        };
        @memcpy(record.message[0..record.message_len], message[0..record.message_len]);

        self.records[self.head] = record;
        self.head = next_head;

        return self.serial_counter;
    }
};

pub const AuditFailure = enum(u8) {
    SILENT = 0,
    PRINTK = 1,
    PANIC = 2,
};

// ============================================================================
// Keyring (Kernel Key Retention Service)
// ============================================================================

pub const KEY_TYPE_MAX_LEN: usize = 32;
pub const KEY_DESC_MAX_LEN: usize = 4096;
pub const KEY_MAX_PAYLOAD: usize = 1048576; // 1MB
pub const KEY_MAX_KEYS: usize = 65536;

pub const KeySerial = i32;

pub const KEY_SPEC_THREAD_KEYRING: KeySerial = -1;
pub const KEY_SPEC_PROCESS_KEYRING: KeySerial = -2;
pub const KEY_SPEC_SESSION_KEYRING: KeySerial = -3;
pub const KEY_SPEC_USER_KEYRING: KeySerial = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: KeySerial = -5;
pub const KEY_SPEC_GROUP_KEYRING: KeySerial = -6;
pub const KEY_SPEC_REQKEY_AUTH_KEY: KeySerial = -7;
pub const KEY_SPEC_REQUESTOR_KEYRING: KeySerial = -8;

pub const KeyPerm = u32;
pub const KEY_POS_VIEW: KeyPerm = 0x01000000;
pub const KEY_POS_READ: KeyPerm = 0x02000000;
pub const KEY_POS_WRITE: KeyPerm = 0x04000000;
pub const KEY_POS_SEARCH: KeyPerm = 0x08000000;
pub const KEY_POS_LINK: KeyPerm = 0x10000000;
pub const KEY_POS_SETATTR: KeyPerm = 0x20000000;
pub const KEY_POS_ALL: KeyPerm = 0x3F000000;

pub const KEY_USR_VIEW: KeyPerm = 0x00010000;
pub const KEY_USR_READ: KeyPerm = 0x00020000;
pub const KEY_USR_WRITE: KeyPerm = 0x00040000;
pub const KEY_USR_SEARCH: KeyPerm = 0x00080000;
pub const KEY_USR_LINK: KeyPerm = 0x00100000;
pub const KEY_USR_SETATTR: KeyPerm = 0x00200000;
pub const KEY_USR_ALL: KeyPerm = 0x003F0000;

pub const KEY_GRP_ALL: KeyPerm = 0x00003F00;
pub const KEY_OTH_ALL: KeyPerm = 0x0000003F;

pub const KeyType = enum(u8) {
    KEYRING = 0,
    USER = 1,
    LOGON = 2,
    BIG_KEY = 3,
    ENCRYPTED = 4,
    TRUSTED = 5,
    ASYMMETRIC = 6,
    PKCS7 = 7,
    DH = 8,
    // Zxyphor key types
    ZXY_ENCLAVE_KEY = 32,
    ZXY_SECURE_BOOT_KEY = 33,
    ZXY_VM_KEY = 34,
};

pub const KeyFlags = u32;
pub const KEY_FLAG_DEAD: KeyFlags = 1 << 0;
pub const KEY_FLAG_REVOKED: KeyFlags = 1 << 1;
pub const KEY_FLAG_IN_QUOTA: KeyFlags = 1 << 2;
pub const KEY_FLAG_USER_CONSTRUCT: KeyFlags = 1 << 3;
pub const KEY_FLAG_ROOT_CAN_CLEAR: KeyFlags = 1 << 4;
pub const KEY_FLAG_INVALIDATED: KeyFlags = 1 << 5;
pub const KEY_FLAG_BUILTIN: KeyFlags = 1 << 6;
pub const KEY_FLAG_ROOT_CAN_INVAL: KeyFlags = 1 << 7;
pub const KEY_FLAG_KEEP: KeyFlags = 1 << 8;
pub const KEY_FLAG_UID_KEYRING: KeyFlags = 1 << 9;

pub const Key = struct {
    serial: KeySerial,
    type_: KeyType,
    description: [256]u8,
    desc_len: u16,
    flags: KeyFlags,
    perm: KeyPerm,
    uid: u32,
    gid: u32,
    // Payload
    payload: ?[*]u8,
    payload_len: u32,
    // Quotas
    quotalen: u32,
    // Expiry
    expiry: u64, // 0 = no expiry
    // References
    ref_count: u32,
    // Security
    security_id: SecurityId,

    pub fn is_valid(self: *const Key) bool {
        return (self.flags & (KEY_FLAG_DEAD | KEY_FLAG_REVOKED | KEY_FLAG_INVALIDATED)) == 0;
    }

    pub fn has_expired(self: *const Key, now: u64) bool {
        return self.expiry != 0 and now >= self.expiry;
    }

    pub fn check_perm(self: *const Key, caller_uid: u32, caller_gid: u32, perm_mask: KeyPerm) bool {
        var applicable_perm: KeyPerm = 0;

        if (caller_uid == self.uid) {
            applicable_perm = (self.perm >> 16) & 0x3F;
        } else if (caller_gid == self.gid) {
            applicable_perm = (self.perm >> 8) & 0x3F;
        } else {
            applicable_perm = self.perm & 0x3F;
        }

        // Possessor permissions (always checked)
        applicable_perm |= (self.perm >> 24) & 0x3F;

        return (applicable_perm & perm_mask) == perm_mask;
    }
};

pub const Keyring = struct {
    key: Key,
    children: [256]?KeySerial,
    child_count: u16,
    max_children: u16,

    pub fn search(self: *Keyring, type_: KeyType, description: []const u8) ?KeySerial {
        for (self.children[0..self.child_count]) |maybe_serial| {
            const serial = maybe_serial orelse continue;
            _ = serial;
            _ = type_;
            _ = description;
            // In real impl, look up key by serial and match
        }
        return null;
    }

    pub fn link_key(self: *Keyring, serial: KeySerial) bool {
        if (self.child_count >= self.max_children) return false;
        self.children[self.child_count] = serial;
        self.child_count += 1;
        return true;
    }

    pub fn unlink_key(self: *Keyring, serial: KeySerial) bool {
        for (0..self.child_count) |i| {
            if (self.children[i] == serial) {
                // Shift remaining
                var j = i;
                while (j + 1 < self.child_count) : (j += 1) {
                    self.children[j] = self.children[j + 1];
                }
                self.child_count -= 1;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// IMA (Integrity Measurement Architecture)
// ============================================================================

pub const IMA_HASH_ALGO_SHA1: u8 = 0;
pub const IMA_HASH_ALGO_SHA256: u8 = 1;
pub const IMA_HASH_ALGO_SHA384: u8 = 2;
pub const IMA_HASH_ALGO_SHA512: u8 = 3;
pub const IMA_HASH_ALGO_SM3: u8 = 4;

pub const IMA_PCR: u32 = 10; // Default PCR for IMA measurements

pub const ImaAction = enum(u32) {
    DONT_MEASURE = 0,
    MEASURE = 1,
    DONT_APPRAISE = 2,
    APPRAISE = 4,
    AUDIT = 8,
    HASH = 16,
    DONT_HASH = 32,
};

pub const ImaPolicyFunc = enum(u32) {
    FILE_CHECK = 1,
    MMAP_CHECK = 2,
    BPRM_CHECK = 3,
    CREDS_CHECK = 4,
    POST_SETATTR = 5,
    MODULE_CHECK = 6,
    FIRMWARE_CHECK = 7,
    KEXEC_KERNEL_CHECK = 8,
    KEXEC_INITRAMFS_CHECK = 9,
    POLICY_CHECK = 10,
    KEXEC_CMDLINE = 11,
    KEY_CHECK = 12,
    CRITICAL_DATA = 13,
    SETXATTR_CHECK = 14,
};

pub const ImaPolicyRule = struct {
    action: ImaAction,
    flags: u32,
    mask: u32,
    func: ImaPolicyFunc,
    uid: u32,
    uid_op: u8,             // == or !=
    fowner: u32,
    fowner_op: u8,
    fsuuid: [16]u8,         // Filesystem UUID
    fsname: [64]u8,
    fsname_len: u8,
    lsm_rules: [4]?*anyopaque, // LSM rule references
    keyrings: [128]u8,
    keyrings_len: u8,
    label: [128]u8,
    label_len: u8,
    hash_algo: u8,

    pub const FLAG_UID: u32 = 1 << 0;
    pub const FLAG_MASK: u32 = 1 << 1;
    pub const FLAG_FSMAGIC: u32 = 1 << 2;
    pub const FLAG_FSUUID: u32 = 1 << 3;
    pub const FLAG_FOWNER: u32 = 1 << 4;
    pub const FLAG_FSNAME: u32 = 1 << 5;
    pub const FLAG_SUBJ_USER: u32 = 1 << 6;
    pub const FLAG_SUBJ_ROLE: u32 = 1 << 7;
    pub const FLAG_SUBJ_TYPE: u32 = 1 << 8;
    pub const FLAG_OBJ_USER: u32 = 1 << 9;
    pub const FLAG_OBJ_ROLE: u32 = 1 << 10;
    pub const FLAG_OBJ_TYPE: u32 = 1 << 11;
    pub const FLAG_KEYRINGS: u32 = 1 << 12;
    pub const FLAG_LABEL: u32 = 1 << 13;
};

pub const ImaDigest = struct {
    algo: u8,
    length: u16,
    digest: [64]u8, // Max SHA-512

    pub fn matches(self: *const ImaDigest, other: *const ImaDigest) bool {
        if (self.algo != other.algo or self.length != other.length) return false;
        for (0..self.length) |i| {
            if (self.digest[i] != other.digest[i]) return false;
        }
        return true;
    }
};

pub const ImaMeasurementEntry = struct {
    pcr: u32,
    digest: ImaDigest,
    template_desc: ImaTemplate,
    filename: [256]u8,
    filename_len: u16,
    // Security context of the file
    file_security_id: SecurityId,
};

pub const ImaTemplate = enum(u8) {
    IMA = 0,           // d|n (digest|filename)
    IMA_NG = 1,        // d-ng|n-ng (digest with algo prefix)
    IMA_SIG = 2,       // d-ng|n-ng|sig (with signature)
    IMA_BUF = 3,       // d-ng|n-ng|buf
    IMA_MODSIG = 4,    // d-ng|n-ng|sig|d-modsig|modsig
    EVM_IMA_XATTRS = 5,
};

pub const IMA_ML_MAX_ENTRIES: usize = 65536;

pub const ImaMeasurementList = struct {
    entries: [IMA_ML_MAX_ENTRIES]?ImaMeasurementEntry,
    count: u32,
    violation_count: u64,
    hash_algo: u8,
    policy_rules: [256]?ImaPolicyRule,
    policy_count: u32,
    appraise_mode: ImaAppraiseMode,

    pub fn init() ImaMeasurementList {
        return .{
            .entries = [_]?ImaMeasurementEntry{null} ** IMA_ML_MAX_ENTRIES,
            .count = 0,
            .violation_count = 0,
            .hash_algo = IMA_HASH_ALGO_SHA256,
            .policy_rules = [_]?ImaPolicyRule{null} ** 256,
            .policy_count = 0,
            .appraise_mode = .ENFORCE,
        };
    }

    pub fn add_measurement(self: *ImaMeasurementList, entry: ImaMeasurementEntry) bool {
        if (self.count >= IMA_ML_MAX_ENTRIES) return false;
        // Check for duplicates
        for (self.entries[0..self.count]) |maybe_existing| {
            const existing = maybe_existing orelse continue;
            if (existing.digest.matches(&entry.digest)) return true; // Already measured
        }
        self.entries[self.count] = entry;
        self.count += 1;
        return true;
    }
};

pub const ImaAppraiseMode = enum(u8) {
    OFF = 0,
    ENFORCE = 1,
    LOG = 2,
    FIX = 3,
};

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

pub const EvmStatus = enum(u8) {
    UNKNOWN = 0,
    PASS = 1,
    PASS_IMMUTABLE = 2,
    FAIL = 3,
    NO_XATTRS = 4,
    NO_KEY = 5,
};

pub const EvmConfig = struct {
    evm_initialized: bool,
    evm_key_loaded: bool,
    evm_hmac_enabled: bool,    // HMAC-based EVM
    evm_signature_enabled: bool, // Signature-based EVM
    evm_protect_xattrs: bool,
    // Protected xattrs
    protected_xattrs: [32][64]u8,
    protected_xattr_count: u8,
};

// ============================================================================
// AppArmor Profiles (Alternative MAC)
// ============================================================================

pub const AA_MAX_PROFILE_NAME: usize = 256;
pub const AA_MAX_PATH: usize = 4096;

pub const AppArmorMode = enum(u8) {
    UNCONFINED = 0,
    COMPLAIN = 1,
    ENFORCE = 2,
    KILL = 3,
    UNLOADED = 4,
};

pub const AppArmorPerms = packed struct {
    allow: u32 = 0,
    audit: u32 = 0,
    deny: u32 = 0,
    quiet: u32 = 0,
    kill: u32 = 0,
};

pub const AppArmorFileRule = struct {
    path: [AA_MAX_PATH]u8,
    path_len: u16,
    perms: AppArmorPerms,
    owner_only: bool,
};

pub const AppArmorNetRule = struct {
    family: u16,   // AF_*
    type_: u16,    // SOCK_*
    protocol: u16,
    perms: AppArmorPerms,
};

pub const AppArmorCapRule = struct {
    cap: u32,  // CAP_* number
    perms: AppArmorPerms,
};

pub const AppArmorProfile = struct {
    name: [AA_MAX_PROFILE_NAME]u8,
    name_len: u16,
    mode: AppArmorMode,
    // File rules
    file_rules: [1024]?AppArmorFileRule,
    file_rule_count: u32,
    // Network rules
    net_rules: [256]?AppArmorNetRule,
    net_rule_count: u32,
    // Capability rules
    cap_rules: [64]?AppArmorCapRule,
    cap_rule_count: u32,
    // Child profiles
    child_profiles: [64]?*AppArmorProfile,
    child_count: u16,
    // Attachment
    attach_pattern: [256]u8,
    attach_len: u16,
    // Flags
    flags: u32,
    pub const FLAG_HAT: u32 = 1 << 0;
    pub const FLAG_UNCONFINED: u32 = 1 << 1;
    pub const FLAG_NULL_PROFILE: u32 = 1 << 2;
    pub const FLAG_IX_ON_NAME_ERROR: u32 = 1 << 3;
    pub const FLAG_IMMUTABLE: u32 = 1 << 4;
    pub const FLAG_USER_DEFINED: u32 = 1 << 5;
    pub const FLAG_NO_LIST_REF: u32 = 1 << 6;
    pub const FLAG_MEDIATE_DELETED: u32 = 1 << 7;
    pub const FLAG_STALE: u32 = 1 << 8;
};

// ============================================================================
// Lockdown (Kernel Lockdown)
// ============================================================================

pub const LockdownReason = enum(u32) {
    NONE = 0,
    MODULE_SIGNATURE = 1,
    DEV_MEM = 2,
    EFI_TEST = 3,
    KEXEC = 4,
    HIBERNATION = 5,
    PCI_ACCESS = 6,
    IOPORT = 7,
    MSR = 8,
    ACPI_TABLES = 9,
    PCMCIA_CIS = 10,
    BPF_READ_KERNEL = 11,
    PERF = 12,
    TRACEFS = 13,
    XMON_RW = 14,
    XMON_WR = 15,
    INTEGRITY_MAX = 16,
    KCORE = 17,
    KPROBES = 18,
    BPF_WRITE = 19,
    DEBUGFS = 20,
    CONFIDENTIALITY_MAX = 21,
};

pub const LockdownMode = enum(u8) {
    NONE = 0,
    INTEGRITY = 1,     // Protect kernel integrity
    CONFIDENTIALITY = 2, // Protect kernel confidentiality
};
