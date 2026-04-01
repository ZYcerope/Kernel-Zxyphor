// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Security Module (LSM-like framework)
// Mandatory Access Control, Role-Based Security, Capability-driven architecture

const std = @import("std");

/// Security context identifier
pub const SecurityId = u64;
pub const SECURITY_ID_INVALID: SecurityId = 0;
pub const SECURITY_ID_KERNEL: SecurityId = 1;
pub const SECURITY_ID_ROOT: SecurityId = 2;

/// Security level classification
pub const SecurityLevel = enum(u8) {
    unclassified = 0,
    restricted = 1,
    confidential = 2,
    secret = 3,
    top_secret = 4,
    kernel = 255,

    pub fn dominates(self: SecurityLevel, other: SecurityLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(other);
    }
};

/// Integrity level (Biba model)
pub const IntegrityLevel = enum(u8) {
    untrusted = 0,
    low = 1,
    medium = 2,
    high = 3,
    system = 4,
    kernel = 255,

    pub fn dominates(self: IntegrityLevel, other: IntegrityLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(other);
    }
};

/// Security categories for compartmentalization
pub const CategorySet = struct {
    bits: [4]u64, // 256 categories

    pub fn init() CategorySet {
        return .{ .bits = [_]u64{0} ** 4 };
    }

    pub fn all() CategorySet {
        return .{ .bits = [_]u64{0xFFFFFFFFFFFFFFFF} ** 4 };
    }

    pub fn set(self: *CategorySet, cat: u8) void {
        const word = cat / 64;
        const bit = @as(u6, @truncate(cat % 64));
        self.bits[word] |= @as(u64, 1) << bit;
    }

    pub fn clear(self: *CategorySet, cat: u8) void {
        const word = cat / 64;
        const bit = @as(u6, @truncate(cat % 64));
        self.bits[word] &= ~(@as(u64, 1) << bit);
    }

    pub fn has(self: *const CategorySet, cat: u8) bool {
        const word = cat / 64;
        const bit = @as(u6, @truncate(cat % 64));
        return (self.bits[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn contains(self: *const CategorySet, other: *const CategorySet) bool {
        for (0..4) |i| {
            if ((other.bits[i] & ~self.bits[i]) != 0) return false;
        }
        return true;
    }

    pub fn intersect(self: *const CategorySet, other: *const CategorySet) CategorySet {
        var result: CategorySet = .{ .bits = undefined };
        for (0..4) |i| {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        return result;
    }

    pub fn unite(self: *const CategorySet, other: *const CategorySet) CategorySet {
        var result: CategorySet = .{ .bits = undefined };
        for (0..4) |i| {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        return result;
    }
};

/// Security label combining Bell-LaPadula + Biba
pub const SecurityLabel = struct {
    security_level: SecurityLevel,
    integrity_level: IntegrityLevel,
    categories: CategorySet,
    domain: u32,
    type_id: u32,

    pub fn kernel() SecurityLabel {
        return .{
            .security_level = .kernel,
            .integrity_level = .kernel,
            .categories = CategorySet.all(),
            .domain = 0,
            .type_id = 0,
        };
    }

    pub fn userDefault() SecurityLabel {
        return .{
            .security_level = .unclassified,
            .integrity_level = .medium,
            .categories = CategorySet.init(),
            .domain = 1,
            .type_id = 1,
        };
    }

    /// Bell-LaPadula: no read up
    pub fn canRead(subject: *const SecurityLabel, object: *const SecurityLabel) bool {
        return subject.security_level.dominates(object.security_level) and
            object.categories.contains(&subject.categories);
    }

    /// Bell-LaPadula: no write down
    pub fn canWrite(subject: *const SecurityLabel, object: *const SecurityLabel) bool {
        return object.security_level.dominates(subject.security_level) and
            subject.integrity_level.dominates(object.integrity_level);
    }

    /// Biba: no read down (integrity)
    pub fn canReadIntegrity(subject: *const SecurityLabel, object: *const SecurityLabel) bool {
        return object.integrity_level.dominates(subject.integrity_level);
    }

    pub fn canExecute(subject: *const SecurityLabel, object: *const SecurityLabel) bool {
        return subject.security_level.dominates(object.security_level) and
            object.integrity_level.dominates(subject.integrity_level);
    }
};

/// Capability bits (POSIX capabilities + Zxyphor extensions)
pub const Capability = enum(u6) {
    CAP_CHOWN = 0,
    CAP_DAC_OVERRIDE = 1,
    CAP_DAC_READ_SEARCH = 2,
    CAP_FOWNER = 3,
    CAP_FSETID = 4,
    CAP_KILL = 5,
    CAP_SETGID = 6,
    CAP_SETUID = 7,
    CAP_SETPCAP = 8,
    CAP_LINUX_IMMUTABLE = 9,
    CAP_NET_BIND_SERVICE = 10,
    CAP_NET_BROADCAST = 11,
    CAP_NET_ADMIN = 12,
    CAP_NET_RAW = 13,
    CAP_IPC_LOCK = 14,
    CAP_IPC_OWNER = 15,
    CAP_SYS_MODULE = 16,
    CAP_SYS_RAWIO = 17,
    CAP_SYS_CHROOT = 18,
    CAP_SYS_PTRACE = 19,
    CAP_SYS_PACCT = 20,
    CAP_SYS_ADMIN = 21,
    CAP_SYS_BOOT = 22,
    CAP_SYS_NICE = 23,
    CAP_SYS_RESOURCE = 24,
    CAP_SYS_TIME = 25,
    CAP_SYS_TTY_CONFIG = 26,
    CAP_MKNOD = 27,
    CAP_LEASE = 28,
    CAP_AUDIT_WRITE = 29,
    CAP_AUDIT_CONTROL = 30,
    CAP_SETFCAP = 31,
    CAP_MAC_OVERRIDE = 32,
    CAP_MAC_ADMIN = 33,
    CAP_SYSLOG = 34,
    CAP_WAKE_ALARM = 35,
    CAP_BLOCK_SUSPEND = 36,
    CAP_AUDIT_READ = 37,
    CAP_PERFMON = 38,
    CAP_BPF = 39,
    CAP_CHECKPOINT_RESTORE = 40,
    // Zxyphor extensions
    CAP_ZXY_SECURE_ENCLAVE = 41,
    CAP_ZXY_GPU_ACCESS = 42,
    CAP_ZXY_DMA_MAP = 43,
    CAP_ZXY_REAL_TIME = 44,
    CAP_ZXY_POWER_MANAGE = 45,
    CAP_ZXY_HYPERVISOR = 46,
    CAP_ZXY_DEBUG = 47,
};

/// Capability set (64 capabilities max)
pub const CapabilitySet = struct {
    effective: u64,
    permitted: u64,
    inheritable: u64,
    bounding: u64,
    ambient: u64,

    pub fn init() CapabilitySet {
        return .{
            .effective = 0,
            .permitted = 0,
            .inheritable = 0,
            .bounding = 0xFFFFFFFFFFFFFFFF,
            .ambient = 0,
        };
    }

    pub fn all() CapabilitySet {
        return .{
            .effective = 0xFFFFFFFFFFFFFFFF,
            .permitted = 0xFFFFFFFFFFFFFFFF,
            .inheritable = 0xFFFFFFFFFFFFFFFF,
            .bounding = 0xFFFFFFFFFFFFFFFF,
            .ambient = 0xFFFFFFFFFFFFFFFF,
        };
    }

    pub fn hasEffective(self: *const CapabilitySet, cap: Capability) bool {
        return (self.effective & (@as(u64, 1) << @intFromEnum(cap))) != 0;
    }

    pub fn hasPermitted(self: *const CapabilitySet, cap: Capability) bool {
        return (self.permitted & (@as(u64, 1) << @intFromEnum(cap))) != 0;
    }

    pub fn setEffective(self: *CapabilitySet, cap: Capability) void {
        const bit = @as(u64, 1) << @intFromEnum(cap);
        if (self.permitted & bit != 0) {
            self.effective |= bit;
        }
    }

    pub fn clearEffective(self: *CapabilitySet, cap: Capability) void {
        self.effective &= ~(@as(u64, 1) << @intFromEnum(cap));
    }

    pub fn raise(self: *CapabilitySet, cap: Capability) void {
        const bit = @as(u64, 1) << @intFromEnum(cap);
        self.permitted |= bit;
        self.effective |= bit;
    }

    pub fn drop(self: *CapabilitySet, cap: Capability) void {
        const bit = ~(@as(u64, 1) << @intFromEnum(cap));
        self.permitted &= bit;
        self.effective &= bit;
        self.inheritable &= bit;
        self.ambient &= bit;
    }

    pub fn dropBounding(self: *CapabilitySet, cap: Capability) void {
        self.bounding &= ~(@as(u64, 1) << @intFromEnum(cap));
    }

    /// Calculate caps after execve() (capability evolution)
    pub fn afterExec(self: *const CapabilitySet, file_caps: *const CapabilitySet) CapabilitySet {
        var new = CapabilitySet.init();

        // P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & cap_bset) | P'(ambient)
        new.permitted = (self.inheritable & file_caps.inheritable) |
            (file_caps.permitted & self.bounding) |
            self.ambient;

        // P'(effective) = F(effective) ? P'(permitted) : P'(ambient)
        if (file_caps.effective != 0) {
            new.effective = new.permitted;
        } else {
            new.effective = self.ambient;
        }

        // P'(inheritable) = P(inheritable)
        new.inheritable = self.inheritable;

        // P'(bounding) = P(bounding)
        new.bounding = self.bounding;

        // P'(ambient) = (file is privileged) ? 0 : P(ambient)
        if (file_caps.permitted != 0 or file_caps.inheritable != 0) {
            new.ambient = 0;
        } else {
            new.ambient = self.ambient;
        }

        return new;
    }
};

/// Security credential for a process/thread 
pub const Credential = struct {
    uid: u32,
    gid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    supplementary_groups: [32]u32,
    group_count: u8,
    capabilities: CapabilitySet,
    label: SecurityLabel,
    security_id: SecurityId,
    no_new_privs: bool,
    securebits: u32,
    keyrings: [4]u64,
    ref_count: u32,

    pub fn initRoot() Credential {
        return .{
            .uid = 0,
            .gid = 0,
            .euid = 0,
            .egid = 0,
            .suid = 0,
            .sgid = 0,
            .fsuid = 0,
            .fsgid = 0,
            .supplementary_groups = [_]u32{0} ** 32,
            .group_count = 0,
            .capabilities = CapabilitySet.all(),
            .label = SecurityLabel.kernel(),
            .security_id = SECURITY_ID_ROOT,
            .no_new_privs = false,
            .securebits = 0,
            .keyrings = [_]u64{0} ** 4,
            .ref_count = 1,
        };
    }

    pub fn initUser(uid: u32, gid: u32) Credential {
        return .{
            .uid = uid,
            .gid = gid,
            .euid = uid,
            .egid = gid,
            .suid = uid,
            .sgid = gid,
            .fsuid = uid,
            .fsgid = gid,
            .supplementary_groups = [_]u32{0} ** 32,
            .group_count = 0,
            .capabilities = CapabilitySet.init(),
            .label = SecurityLabel.userDefault(),
            .security_id = SECURITY_ID_INVALID,
            .no_new_privs = false,
            .securebits = 0,
            .keyrings = [_]u64{0} ** 4,
            .ref_count = 1,
        };
    }

    pub fn isRoot(self: *const Credential) bool {
        return self.euid == 0;
    }

    pub fn hasCapability(self: *const Credential, cap: Capability) bool {
        return self.capabilities.hasEffective(cap);
    }

    pub fn inGroup(self: *const Credential, gid: u32) bool {
        if (self.egid == gid) return true;
        for (0..self.group_count) |i| {
            if (self.supplementary_groups[i] == gid) return true;
        }
        return false;
    }
};

/// Access decision cache (AVC)
pub const AvcEntry = struct {
    source_sid: SecurityId,
    target_sid: SecurityId,
    target_class: u16,
    allowed: u32,
    denied: u32,
    audited: u32,
    used: bool,
    timestamp: u64,
};

const AVC_CACHE_SIZE = 512;
var avc_cache: [AVC_CACHE_SIZE]AvcEntry = undefined;
var avc_hits: u64 = 0;
var avc_misses: u64 = 0;

fn avcHash(source: SecurityId, target: SecurityId, class: u16) usize {
    var hash = source *% 0x9E3779B97F4A7C15;
    hash ^= target *% 0x517CC1B727220A95;
    hash ^= @as(u64, class) *% 0x6C62272E07BB0142;
    return @truncate(hash % AVC_CACHE_SIZE);
}

pub fn avcLookup(source: SecurityId, target: SecurityId, class: u16) ?*AvcEntry {
    const idx = avcHash(source, target, class);
    const entry = &avc_cache[idx];
    if (entry.used and entry.source_sid == source and
        entry.target_sid == target and entry.target_class == class)
    {
        avc_hits += 1;
        return entry;
    }
    avc_misses += 1;
    return null;
}

pub fn avcInsert(source: SecurityId, target: SecurityId, class: u16, allowed: u32, denied: u32) void {
    const idx = avcHash(source, target, class);
    avc_cache[idx] = .{
        .source_sid = source,
        .target_sid = target,
        .target_class = class,
        .allowed = allowed,
        .denied = denied,
        .audited = denied,
        .used = true,
        .timestamp = 0,
    };
}

pub fn avcFlush() void {
    for (&avc_cache) |*entry| {
        entry.used = false;
    }
}

/// Security hooks (LSM callbacks)
pub const SecurityHook = struct {
    // Task hooks
    task_alloc: ?*const fn (*Credential) i32 = null,
    task_free: ?*const fn (*Credential) void = null,
    task_kill: ?*const fn (*const Credential, *const Credential, i32) i32 = null,
    task_setnice: ?*const fn (*const Credential, i32) i32 = null,
    task_setscheduler: ?*const fn (*const Credential) i32 = null,

    // File hooks
    file_permission: ?*const fn (SecurityId, u32) i32 = null,
    file_open: ?*const fn (SecurityId, u32) i32 = null,
    file_ioctl: ?*const fn (SecurityId, u32) i32 = null,
    file_mmap: ?*const fn (SecurityId, u32) i32 = null,
    file_mprotect: ?*const fn (SecurityId, u32) i32 = null,

    // Inode hooks
    inode_create: ?*const fn (SecurityId, u16) i32 = null,
    inode_link: ?*const fn (SecurityId, SecurityId) i32 = null,
    inode_unlink: ?*const fn (SecurityId, SecurityId) i32 = null,
    inode_mkdir: ?*const fn (SecurityId, u16) i32 = null,
    inode_rmdir: ?*const fn (SecurityId, SecurityId) i32 = null,
    inode_rename: ?*const fn (SecurityId, SecurityId) i32 = null,
    inode_permission: ?*const fn (SecurityId, u32) i32 = null,
    inode_setattr: ?*const fn (SecurityId, u32) i32 = null,
    inode_getattr: ?*const fn (SecurityId) i32 = null,

    // Socket hooks
    socket_create: ?*const fn (*const Credential, i32, i32, i32) i32 = null,
    socket_bind: ?*const fn (*const Credential, u16) i32 = null,
    socket_connect: ?*const fn (*const Credential, u16) i32 = null,
    socket_listen: ?*const fn (*const Credential, i32) i32 = null,
    socket_accept: ?*const fn (*const Credential) i32 = null,
    socket_sendmsg: ?*const fn (*const Credential, u32) i32 = null,
    socket_recvmsg: ?*const fn (*const Credential, u32) i32 = null,

    // Network hooks
    net_send: ?*const fn (SecurityId, u32) i32 = null,
    net_recv: ?*const fn (SecurityId, u32) i32 = null,
    
    // IPC hooks  
    ipc_permission: ?*const fn (SecurityId, u32) i32 = null,
    msg_queue_msgrcv: ?*const fn (SecurityId) i32 = null,
    shm_shmat: ?*const fn (SecurityId, u32) i32 = null,

    // Kernel module hooks
    kernel_module_request: ?*const fn (*const Credential, []const u8) i32 = null,
    kernel_load_data: ?*const fn (u32) i32 = null,

    // BPF hooks
    bpf: ?*const fn (*const Credential, u32) i32 = null,
    bpf_map: ?*const fn (*const Credential, u32) i32 = null,
    bpf_prog: ?*const fn (*const Credential, u32) i32 = null,
};

/// Maximum number of stacked security modules
const MAX_LSM_MODULES: usize = 8;

var security_hooks: [MAX_LSM_MODULES]?SecurityHook = [_]?SecurityHook{null} ** MAX_LSM_MODULES;
var active_modules: u32 = 0;
var security_initialized: bool = false;

/// Security module registration
pub fn registerModule(hook: SecurityHook) !u32 {
    if (active_modules >= MAX_LSM_MODULES) return error.TooManyModules;
    const id = active_modules;
    security_hooks[id] = hook;
    active_modules += 1;
    return id;
}

/// File permission check
pub const FilePermission = struct {
    pub const READ: u32 = 0x04;
    pub const WRITE: u32 = 0x02;
    pub const EXEC: u32 = 0x01;
    pub const APPEND: u32 = 0x08;
    pub const CREATE: u32 = 0x10;
    pub const DELETE: u32 = 0x20;
    pub const SETATTR: u32 = 0x40;
    pub const GETATTR: u32 = 0x80;

    pub fn check(cred: *const Credential, file_uid: u32, file_gid: u32, file_mode: u16, requested: u32) bool {
        // Root bypass (unless no_new_privs)
        if (cred.isRoot() and !cred.no_new_privs) return true;

        // DAC check
        var mode_bits: u32 = 0;
        if (cred.euid == file_uid) {
            // Owner permissions (bits 8-6)
            mode_bits = (file_mode >> 6) & 0x7;
        } else if (cred.inGroup(file_gid)) {
            // Group permissions (bits 5-3)
            mode_bits = (file_mode >> 3) & 0x7;
        } else {
            // Other permissions (bits 2-0)
            mode_bits = file_mode & 0x7;
        }

        // Check DAC bits against requested access
        if (requested & READ != 0 and mode_bits & 0x4 == 0) return false;
        if (requested & WRITE != 0 and mode_bits & 0x2 == 0) return false;
        if (requested & EXEC != 0 and mode_bits & 0x1 == 0) return false;

        // Capability override for DAC
        if (requested & READ != 0 and !cred.hasCapability(.CAP_DAC_READ_SEARCH)) {
            if (mode_bits & 0x4 == 0) return false;
        }

        return true;
    }
};

/// SECCOMP-BPF filter support
pub const SeccompMode = enum(u8) {
    disabled = 0,
    strict = 1,
    filter = 2,
};

pub const SeccompFilter = struct {
    mode: SeccompMode,
    filter_count: u16,
    filters: [64]SeccompRule,
    log_denials: bool,
    kill_on_violation: bool,

    pub fn init() SeccompFilter {
        return .{
            .mode = .disabled,
            .filter_count = 0,
            .filters = undefined,
            .log_denials = true,
            .kill_on_violation = true,
        };
    }

    pub fn addRule(self: *SeccompFilter, rule: SeccompRule) !void {
        if (self.filter_count >= 64) return error.FilterFull;
        self.filters[self.filter_count] = rule;
        self.filter_count += 1;
    }

    pub fn checkSyscall(self: *const SeccompFilter, syscall_nr: u32, args: [6]u64) SeccompAction {
        if (self.mode == .disabled) return .allow;

        if (self.mode == .strict) {
            // Only allow read, write, exit, sigreturn
            return switch (syscall_nr) {
                0, 1, 60, 15 => .allow,
                else => .kill,
            };
        }

        // Filter mode - check rules
        for (0..self.filter_count) |i| {
            const action = self.filters[i].evaluate(syscall_nr, args);
            if (action != .allow) return action;
        }

        return .allow;
    }
};

pub const SeccompAction = enum(u8) {
    allow = 0,
    log = 1,
    trap = 2,
    errno_val = 3,
    trace = 4,
    kill = 5,
};

pub const SeccompRule = struct {
    syscall_nr: u32,
    action: SeccompAction,
    arg_checks: [6]ArgCheck,
    arg_count: u8,

    pub const ArgCheck = struct {
        arg_index: u8,
        op: enum(u8) { eq, ne, lt, le, gt, ge, masked_eq },
        value: u64,
        mask: u64,
    };

    pub fn evaluate(self: *const SeccompRule, syscall_nr: u32, args: [6]u64) SeccompAction {
        if (self.syscall_nr != syscall_nr) return .allow;

        for (0..self.arg_count) |i| {
            const check = &self.arg_checks[i];
            const arg_val = args[check.arg_index];
            const matches = switch (check.op) {
                .eq => arg_val == check.value,
                .ne => arg_val != check.value,
                .lt => arg_val < check.value,
                .le => arg_val <= check.value,
                .gt => arg_val > check.value,
                .ge => arg_val >= check.value,
                .masked_eq => (arg_val & check.mask) == check.value,
            };
            if (!matches) return .allow;
        }

        return self.action;
    }
};

/// Audit subsystem
pub const AuditEvent = struct {
    timestamp: u64,
    event_type: AuditType,
    subject_sid: SecurityId,
    object_sid: SecurityId,
    action: u32,
    result: i32,
    pid: u32,
    uid: u32,
    message: [256]u8,
    msg_len: u16,
};

pub const AuditType = enum(u16) {
    login = 1000,
    login_failed = 1001,
    user_auth = 1100,
    user_acct = 1101,
    cred_acquire = 1102,
    cred_release = 1103,
    user_start = 1105,
    user_end = 1106,
    syscall = 1300,
    file_access = 1301,
    ipc = 1302,
    socket = 1303,
    signal = 1304,
    capability = 1305,
    mac_policy_load = 1403,
    mac_status = 1404,
    mac_config = 1405,
    avc_decision = 1400,
    selinux = 1401,
    integrity = 1800,
    kernel = 2000,
    kernel_module = 2001,
    anomaly = 2100,
    response = 2200,
};

const AUDIT_BUFFER_SIZE: usize = 4096;
var audit_buffer: [AUDIT_BUFFER_SIZE]AuditEvent = undefined;
var audit_write_idx: usize = 0;
var audit_read_idx: usize = 0;
var audit_enabled: bool = false;
var audit_lost: u64 = 0;

pub fn auditLog(event: AuditEvent) void {
    if (!audit_enabled) return;

    const next = (audit_write_idx + 1) % AUDIT_BUFFER_SIZE;
    if (next == audit_read_idx) {
        audit_lost += 1;
        return;
    }

    audit_buffer[audit_write_idx] = event;
    audit_write_idx = next;
}

pub fn enableAudit() void {
    audit_enabled = true;
}

pub fn disableAudit() void {
    audit_enabled = false;
}

/// Namespace security
pub const NamespaceSecurity = struct {
    user_ns_id: u64,
    parent_ns_id: u64,
    uid_map: [5]IdMapping,
    gid_map: [5]IdMapping,
    map_count: u8,
    deny_setgroups: bool,

    pub const IdMapping = struct {
        inner_start: u32,
        outer_start: u32,
        count: u32,
    };

    pub fn init(ns_id: u64, parent: u64) NamespaceSecurity {
        return .{
            .user_ns_id = ns_id,
            .parent_ns_id = parent,
            .uid_map = undefined,
            .gid_map = undefined,
            .map_count = 0,
            .deny_setgroups = false,
        };
    }

    pub fn mapUid(self: *const NamespaceSecurity, uid: u32) ?u32 {
        for (0..self.map_count) |i| {
            const map = &self.uid_map[i];
            if (uid >= map.inner_start and uid < map.inner_start + map.count) {
                return map.outer_start + (uid - map.inner_start);
            }
        }
        return null;
    }

    pub fn mapGid(self: *const NamespaceSecurity, gid: u32) ?u32 {
        for (0..self.map_count) |i| {
            const map = &self.gid_map[i];
            if (gid >= map.inner_start and gid < map.inner_start + map.count) {
                return map.outer_start + (gid - map.inner_start);
            }
        }
        return null;
    }
};

/// Keyring and key management
pub const KeyType = enum(u8) {
    user = 0,
    logon = 1,
    big_key = 2,
    keyring = 3,
    asymmetric = 4,
    encrypted = 5,
    trusted = 6,
    dns_resolver = 7,
};

pub const Key = struct {
    serial: u32,
    key_type: KeyType,
    description: [128]u8,
    desc_len: u8,
    uid: u32,
    gid: u32,
    perm: u32,
    data: [512]u8,
    data_len: u16,
    flags: u32,
    expiry: u64,
    last_used: u64,
    ref_count: u32,
    revoked: bool,

    pub fn isExpired(self: *const Key, now: u64) bool {
        return self.expiry != 0 and now > self.expiry;
    }

    pub fn isRevoked(self: *const Key) bool {
        return self.revoked;
    }

    pub fn canAccess(self: *const Key, cred: *const Credential, perm: u32) bool {
        if (cred.isRoot()) return true;

        var applicable_perm: u32 = 0;
        if (cred.euid == self.uid) {
            applicable_perm = (self.perm >> 16) & 0x3F;
        } else if (cred.inGroup(self.gid)) {
            applicable_perm = (self.perm >> 8) & 0x3F;
        } else {
            applicable_perm = self.perm & 0x3F;
        }

        return (applicable_perm & perm) == perm;
    }
};

const MAX_KEYS: usize = 1024;
var keyring: [MAX_KEYS]?Key = [_]?Key{null} ** MAX_KEYS;
var next_key_serial: u32 = 1;

pub fn allocateKey(key_type: KeyType, desc: []const u8, cred: *const Credential) !u32 {
    for (0..MAX_KEYS) |i| {
        if (keyring[i] == null) {
            var key = Key{
                .serial = next_key_serial,
                .key_type = key_type,
                .description = [_]u8{0} ** 128,
                .desc_len = @truncate(desc.len),
                .uid = cred.euid,
                .gid = cred.egid,
                .perm = 0x3F3F3F00, // owner/group/other: all perms
                .data = [_]u8{0} ** 512,
                .data_len = 0,
                .flags = 0,
                .expiry = 0,
                .last_used = 0,
                .ref_count = 1,
                .revoked = false,
            };
            const len = @min(desc.len, 128);
            @memcpy(key.description[0..len], desc[0..len]);
            keyring[i] = key;
            next_key_serial += 1;
            return key.serial;
        }
    }
    return error.KeyringFull;
}

/// Landlock (sandboxing) support
pub const LandlockRuleset = struct {
    handled_access_fs: u32,
    handled_access_net: u32,
    rules: [64]LandlockRule,
    rule_count: u16,
    enforcing: bool,

    pub fn init() LandlockRuleset {
        return .{
            .handled_access_fs = 0,
            .handled_access_net = 0,
            .rules = undefined,
            .rule_count = 0,
            .enforcing = false,
        };
    }

    pub fn addRule(self: *LandlockRuleset, rule: LandlockRule) !void {
        if (self.rule_count >= 64) return error.RulesetFull;
        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
    }

    pub fn checkAccess(self: *const LandlockRuleset, access: u32, obj_type: LandlockObjectType) bool {
        if (!self.enforcing) return true;

        for (0..self.rule_count) |i| {
            const rule = &self.rules[i];
            if (rule.obj_type == obj_type and (rule.allowed_access & access) == access) {
                return true;
            }
        }

        // Check if this access type is handled by the ruleset
        const handled = switch (obj_type) {
            .path_beneath => self.handled_access_fs,
            .net_port => self.handled_access_net,
        };

        return (handled & access) == 0;
    }
};

pub const LandlockObjectType = enum(u8) {
    path_beneath = 1,
    net_port = 2,
};

pub const LandlockRule = struct {
    obj_type: LandlockObjectType,
    allowed_access: u32,
    path_inode: u64,
    port: u16,
};

/// Initialize security subsystem
pub fn init() void {
    // Initialize AVC cache
    for (&avc_cache) |*entry| {
        entry.used = false;
    }

    // Register built-in security module (DAC + capabilities)
    _ = registerModule(.{
        .file_permission = defaultFilePermission,
        .inode_permission = defaultInodePermission,
        .task_kill = defaultTaskKill,
    }) catch {};

    security_initialized = true;
}

fn defaultFilePermission(sid: SecurityId, mask: u32) i32 {
    _ = sid;
    _ = mask;
    return 0; // Allow by default
}

fn defaultInodePermission(sid: SecurityId, mask: u32) i32 {
    _ = sid;
    _ = mask;
    return 0;
}

fn defaultTaskKill(subject: *const Credential, target: *const Credential, sig: i32) i32 {
    _ = sig;
    // Root can kill anything
    if (subject.isRoot()) return 0;
    // Same user can kill own processes
    if (subject.euid == target.uid or subject.euid == target.suid) return 0;
    // Check CAP_KILL
    if (subject.hasCapability(.CAP_KILL)) return 0;
    return -1; // EPERM
}

pub fn isInitialized() bool {
    return security_initialized;
}
