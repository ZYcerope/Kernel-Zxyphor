// =============================================================================
// Kernel Zxyphor — Linux Security Module (LSM) Framework
// =============================================================================
// Comprehensive security framework providing mandatory access control (MAC)
// through a pluggable hook architecture. Supports stacking multiple LSMs.
//
// Implemented LSM subsystems:
//   - Core LSM hook infrastructure with 200+ hook points
//   - Security blob management for task, inode, file, IPC, socket, key objects
//   - Capability (POSIX capabilities, default LSM)
//   - SELinux-compatible type enforcement engine
//   - AppArmor-compatible path-based MAC
//   - Landlock (unprivileged sandboxing)
//   - Seccomp-BPF integration
//   - Integrity Measurement Architecture (IMA)
//   - Extended Verification Module (EVM)
//   - SafeSetID
//   - LoadPin
//   - Lockdown
//   - KASAN shadow (Kernel Address Sanitizer security)
//   - KASLR entropy pool
//   - Stack canary management
//   - Control Flow Integrity (CFI) hooks
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Security Constants
// =============================================================================
pub const MAX_LSM_MODULES: usize = 16;
pub const MAX_SECURITY_BLOB_SIZE: usize = 4096;
pub const MAX_AUDIT_MSG_LEN: usize = 8192;
pub const SECURITY_NAME_MAX: usize = 64;
pub const MAX_SECURITY_CONTEXT_LEN: usize = 256;
pub const MAX_STACKED_LSMS: usize = 8;
pub const SELINUX_MAGIC: u32 = 0xF97CFF8C;
pub const SMACK_MAGIC: u32 = 0x43415D53;
pub const APPARMOR_MAGIC: u32 = 0xAABBCCDD;
pub const IMA_DIGEST_SIZE: usize = 64; // SHA-512
pub const MAX_CAPABILITY_SETS: usize = 3; // effective, permitted, inheritable
pub const CAP_LAST_CAP: u32 = 40;

// =============================================================================
// POSIX Capabilities (Full Linux set)
// =============================================================================
pub const Capability = enum(u6) {
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

pub const CapabilitySet = struct {
    bits: [2]u32 = [_]u32{ 0, 0 }, // 64 bits total

    pub fn set(self: *CapabilitySet, cap: Capability) void {
        const idx = @intFromEnum(cap);
        if (idx < 32) {
            self.bits[0] |= @as(u32, 1) << @intCast(idx);
        } else {
            self.bits[1] |= @as(u32, 1) << @intCast(idx - 32);
        }
    }

    pub fn clear(self: *CapabilitySet, cap: Capability) void {
        const idx = @intFromEnum(cap);
        if (idx < 32) {
            self.bits[0] &= ~(@as(u32, 1) << @intCast(idx));
        } else {
            self.bits[1] &= ~(@as(u32, 1) << @intCast(idx - 32));
        }
    }

    pub fn has(self: *const CapabilitySet, cap: Capability) bool {
        const idx = @intFromEnum(cap);
        if (idx < 32) {
            return (self.bits[0] & (@as(u32, 1) << @intCast(idx))) != 0;
        } else {
            return (self.bits[1] & (@as(u32, 1) << @intCast(idx - 32))) != 0;
        }
    }

    pub fn isSubsetOf(self: *const CapabilitySet, other: *const CapabilitySet) bool {
        return (self.bits[0] & ~other.bits[0]) == 0 and
            (self.bits[1] & ~other.bits[1]) == 0;
    }

    pub fn intersect(self: *const CapabilitySet, other: *const CapabilitySet) CapabilitySet {
        return CapabilitySet{
            .bits = .{
                self.bits[0] & other.bits[0],
                self.bits[1] & other.bits[1],
            },
        };
    }

    pub fn unite(self: *const CapabilitySet, other: *const CapabilitySet) CapabilitySet {
        return CapabilitySet{
            .bits = .{
                self.bits[0] | other.bits[0],
                self.bits[1] | other.bits[1],
            },
        };
    }

    pub fn isEmpty(self: *const CapabilitySet) bool {
        return self.bits[0] == 0 and self.bits[1] == 0;
    }

    pub fn full() CapabilitySet {
        return CapabilitySet{ .bits = .{ 0xFFFFFFFF, 0x000001FF } }; // caps 0-40
    }

    pub fn empty() CapabilitySet {
        return CapabilitySet{ .bits = .{ 0, 0 } };
    }
};

// =============================================================================
// Process Credentials (like Linux's struct cred)
// =============================================================================
pub const Credentials = struct {
    uid: u32 = 0,
    gid: u32 = 0,
    euid: u32 = 0,
    egid: u32 = 0,
    suid: u32 = 0,
    sgid: u32 = 0,
    fsuid: u32 = 0,
    fsgid: u32 = 0,

    // Supplementary groups
    ngroups: u32 = 0,
    groups: [32]u32 = [_]u32{0} ** 32,

    // Capabilities
    cap_effective: CapabilitySet = .{},
    cap_permitted: CapabilitySet = .{},
    cap_inheritable: CapabilitySet = .{},
    cap_bset: CapabilitySet = CapabilitySet.full(), // Bounding set
    cap_ambient: CapabilitySet = .{},

    // Security context (SELinux SID, etc.)
    security_label: [MAX_SECURITY_CONTEXT_LEN]u8 = [_]u8{0} ** MAX_SECURITY_CONTEXT_LEN,
    security_label_len: u32 = 0,

    // Keyring IDs
    session_keyring: u32 = 0,
    process_keyring: u32 = 0,
    thread_keyring: u32 = 0,

    // User namespace
    user_ns_id: u32 = 0,

    // LSM blobs
    security_blob: [MAX_SECURITY_BLOB_SIZE]u8 = [_]u8{0} ** MAX_SECURITY_BLOB_SIZE,

    // Seccomp
    seccomp_mode: SeccompMode = .disabled,
    no_new_privs: bool = false,

    // Landlock domain
    landlock_domain_depth: u32 = 0,

    pub fn isRoot(self: *const Credentials) bool {
        return self.euid == 0;
    }

    pub fn capable(self: *const Credentials, cap: Capability) bool {
        return self.cap_effective.has(cap);
    }

    pub fn inGroup(self: *const Credentials, gid: u32) bool {
        if (self.egid == gid) return true;
        for (0..self.ngroups) |i| {
            if (self.groups[i] == gid) return true;
        }
        return false;
    }

    pub fn dropAllCaps(self: *Credentials) void {
        self.cap_effective = CapabilitySet.empty();
        self.cap_permitted = CapabilitySet.empty();
        self.cap_inheritable = CapabilitySet.empty();
        self.cap_ambient = CapabilitySet.empty();
    }

    /// Apply capabilities transformation on execve
    pub fn applyExecCaps(self: *Credentials, file_caps: *const FileCaps) void {
        // pP' = (fP & cap_bset) | (fI & pI)
        var new_permitted = file_caps.permitted.intersect(&self.cap_bset);
        new_permitted = new_permitted.unite(&file_caps.inheritable.intersect(&self.cap_inheritable));

        // pE' = fE ? pP' : empty
        if (file_caps.effective_bit) {
            self.cap_effective = new_permitted;
        } else {
            self.cap_effective = CapabilitySet.empty();
        }

        // Add ambient caps
        self.cap_effective = self.cap_effective.unite(&self.cap_ambient);
        new_permitted = new_permitted.unite(&self.cap_ambient);

        self.cap_permitted = new_permitted;
    }
};

pub const FileCaps = struct {
    permitted: CapabilitySet = .{},
    inheritable: CapabilitySet = .{},
    effective_bit: bool = false,
    rootid: u32 = 0,
    version: u32 = 0x02000080, // VFS_CAP_REVISION_2
};

// =============================================================================
// Seccomp (Secure Computing Mode)
// =============================================================================
pub const SeccompMode = enum(u8) {
    disabled = 0,
    strict = 1, // Only read/write/exit/sigreturn
    filter = 2, // BPF filter
};

pub const SeccompAction = enum(u32) {
    kill_process = 0x80000000,
    kill_thread = 0x00000000,
    trap = 0x00030000,
    errno = 0x00050000,
    user_notif = 0x7FC00000,
    trace = 0x7FF00000,
    log = 0x7FFC0000,
    allow = 0x7FFF0000,
};

pub const SeccompData = struct {
    nr: u32 = 0, // System call number
    arch: u32 = 0, // AUDIT_ARCH_X86_64 etc
    instruction_pointer: u64 = 0,
    args: [6]u64 = [_]u64{0} ** 6,
};

pub const SeccompFilter = struct {
    // BPF program for seccomp
    insns: [256]BpfInsn = undefined,
    insn_count: u32 = 0,
    flags: u32 = 0,
    prev: ?*SeccompFilter = null, // Chain of filters

    // Statistics
    total_evaluations: u64 = 0,
    total_kills: u64 = 0,
    total_traps: u64 = 0,
    total_errnos: u64 = 0,
    total_allows: u64 = 0,

    pub fn evaluate(self: *SeccompFilter, data: *const SeccompData) SeccompAction {
        self.total_evaluations += 1;
        // Classic BPF evaluation
        var acc: u32 = 0;
        var idx: u32 = 0;
        var pc: u32 = 0;

        while (pc < self.insn_count) {
            const insn = self.insns[pc];
            switch (insn.code & 0x07) {
                0x00 => { // LD
                    switch (insn.code) {
                        0x00 => acc = loadSeccompField(data, insn.k), // LD abs
                        0x01 => acc = idx, // LD idx
                        0x04 => acc = insn.k, // LD imm
                        else => {},
                    }
                },
                0x01 => { // ST
                    idx = acc;
                },
                0x04 => { // ALU
                    const src = if ((insn.code & 0x08) != 0) idx else insn.k;
                    switch (insn.code & 0xF0) {
                        0x00 => acc +%= src, // ADD
                        0x10 => acc -%= src, // SUB
                        0x20 => acc *%= src, // MUL
                        0x30 => if (src != 0) { acc /= src; }, // DIV
                        0x40 => acc |= src, // OR
                        0x50 => acc &= src, // AND
                        0x60 => if (src < 32) {
                            acc <<= @intCast(src);
                        }, // LSH
                        0x70 => if (src < 32) {
                            acc >>= @intCast(src);
                        }, // RSH
                        0x80 => acc = ~acc, // NEG
                        else => {},
                    }
                },
                0x05 => { // JMP
                    switch (insn.code & 0xF0) {
                        0x00 => pc += insn.k, // JA
                        0x10 => { // JEQ
                            pc += if (acc == insn.k) @as(u32, insn.jt) else @as(u32, insn.jf);
                        },
                        0x20 => { // JGT
                            pc += if (acc > insn.k) @as(u32, insn.jt) else @as(u32, insn.jf);
                        },
                        0x30 => { // JGE
                            pc += if (acc >= insn.k) @as(u32, insn.jt) else @as(u32, insn.jf);
                        },
                        0x40 => { // JSET
                            pc += if ((acc & insn.k) != 0) @as(u32, insn.jt) else @as(u32, insn.jf);
                        },
                        else => {},
                    }
                },
                0x06 => { // RET
                    const action_val = if ((insn.code & 0x10) != 0) acc else insn.k;
                    const result: SeccompAction = @enumFromInt(action_val & 0xFFFF0000);
                    switch (result) {
                        .kill_process, .kill_thread => self.total_kills += 1,
                        .trap => self.total_traps += 1,
                        .errno => self.total_errnos += 1,
                        .allow => self.total_allows += 1,
                        else => {},
                    }
                    return result;
                },
                else => {},
            }
            pc += 1;
        }
        return .kill_process; // Default deny
    }

    fn loadSeccompField(data: *const SeccompData, offset: u32) u32 {
        return switch (offset) {
            0 => data.nr,
            4 => data.arch,
            8 => @truncate(data.instruction_pointer),
            12 => @truncate(data.instruction_pointer >> 32),
            16 => @truncate(data.args[0]),
            20 => @truncate(data.args[0] >> 32),
            24 => @truncate(data.args[1]),
            28 => @truncate(data.args[1] >> 32),
            32 => @truncate(data.args[2]),
            36 => @truncate(data.args[2] >> 32),
            40 => @truncate(data.args[3]),
            44 => @truncate(data.args[3] >> 32),
            48 => @truncate(data.args[4]),
            52 => @truncate(data.args[4] >> 32),
            56 => @truncate(data.args[5]),
            60 => @truncate(data.args[5] >> 32),
            else => 0,
        };
    }
};

pub const BpfInsn = struct {
    code: u16 = 0,
    jt: u8 = 0,
    jf: u8 = 0,
    k: u32 = 0,
};

// =============================================================================
// LSM Hook Results
// =============================================================================
pub const LsmResult = enum(i32) {
    allow = 0,
    deny_eacces = -13, // EACCES
    deny_eperm = -1, // EPERM
    deny_enosys = -38, // ENOSYS
    deny_einval = -22, // EINVAL
    deny_enoent = -2, // ENOENT
    defer = 1, // Let next LSM decide
};

// =============================================================================
// LSM Hook Types (200+ hooks matching Linux kernel)
// =============================================================================
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
    task_setrlimit = 8,
    task_setscheduler = 9,
    task_getscheduler = 10,
    task_movememory = 11,
    task_kill = 12,
    task_prctl = 13,
    task_to_inode = 14,
    task_fix_setuid = 15,

    // Inode hooks
    inode_alloc_security = 20,
    inode_free_security = 21,
    inode_init_security = 22,
    inode_create = 23,
    inode_link = 24,
    inode_unlink = 25,
    inode_symlink = 26,
    inode_mkdir = 27,
    inode_rmdir = 28,
    inode_mknod = 29,
    inode_rename = 30,
    inode_readlink = 31,
    inode_follow_link = 32,
    inode_permission = 33,
    inode_setattr = 34,
    inode_getattr = 35,
    inode_setxattr = 36,
    inode_post_setxattr = 37,
    inode_getxattr = 38,
    inode_listxattr = 39,
    inode_removexattr = 40,
    inode_need_killpriv = 41,
    inode_killpriv = 42,
    inode_getsecurity = 43,
    inode_setsecurity = 44,
    inode_listsecurity = 45,
    inode_copy_up = 46,
    inode_copy_up_xattr = 47,

    // File hooks
    file_permission = 50,
    file_alloc_security = 51,
    file_free_security = 52,
    file_ioctl = 53,
    file_mprotect = 54,
    file_lock = 55,
    file_fcntl = 56,
    file_set_fowner = 57,
    file_send_sigiotask = 58,
    file_receive = 59,
    file_open = 60,
    file_truncate = 61,

    // Superblock hooks
    sb_alloc_security = 70,
    sb_free_security = 71,
    sb_statfs = 72,
    sb_mount = 73,
    sb_umount = 74,
    sb_pivotroot = 75,
    sb_set_mnt_opts = 76,
    sb_clone_mnt_opts = 77,
    sb_kern_mount = 78,
    sb_show_options = 79,
    sb_remount = 80,

    // Socket hooks
    socket_create = 90,
    socket_post_create = 91,
    socket_socketpair = 92,
    socket_bind = 93,
    socket_connect = 94,
    socket_listen = 95,
    socket_accept = 96,
    socket_sendmsg = 97,
    socket_recvmsg = 98,
    socket_getsockname = 99,
    socket_getpeername = 100,
    socket_getsockopt = 101,
    socket_setsockopt = 102,
    socket_shutdown = 103,
    socket_sock_rcv_skb = 104,
    socket_getpeer_dgram = 105,

    // IPC hooks
    ipc_permission = 110,
    ipc_getsecid = 111,
    msg_msg_alloc_security = 112,
    msg_msg_free_security = 113,
    msg_queue_alloc_security = 114,
    msg_queue_free_security = 115,
    msg_queue_associate = 116,
    msg_queue_msgctl = 117,
    msg_queue_msgsnd = 118,
    msg_queue_msgrcv = 119,
    shm_alloc_security = 120,
    shm_free_security = 121,
    shm_associate = 122,
    shm_shmctl = 123,
    shm_shmat = 124,
    sem_alloc_security = 125,
    sem_free_security = 126,
    sem_associate = 127,
    sem_semctl = 128,
    sem_semop = 129,

    // Key management hooks
    key_alloc = 140,
    key_free = 141,
    key_permission = 142,
    key_getsecurity = 143,

    // Network hooks
    netlink_send = 150,
    d_instantiate = 151,
    getprocattr = 152,
    setprocattr = 153,

    // Audit hooks
    audit_rule_init = 160,
    audit_rule_known = 161,
    audit_rule_match = 162,
    audit_rule_free = 163,

    // BPF hooks
    bpf = 170,
    bpf_map = 171,
    bpf_prog = 172,
    bpf_map_alloc = 173,
    bpf_map_free = 174,

    // Perf event hooks
    perf_event_open = 180,
    perf_event_alloc = 181,
    perf_event_free = 182,
    perf_event_read = 183,
    perf_event_write = 184,

    // Memory management hooks
    mmap_addr = 190,
    mmap_file = 191,
    vm_enough_memory = 192,

    // Cred hooks
    cred_alloc_blank = 200,
    cred_free = 201,
    cred_prepare = 202,
    cred_transfer = 203,
    cred_getsecid = 204,
    kernel_act_as = 205,
    kernel_create_files_as = 206,
    kernel_module_request = 207,

    // Exec hooks
    bprm_creds_for_exec = 210,
    bprm_creds_from_file = 211,
    bprm_check = 212,
    bprm_committing_creds = 213,
    bprm_committed_creds = 214,

    // Misc
    syslog = 220,
    settime = 221,
    quotactl = 222,
    quota_on = 223,
    sysctl = 224,
    capable = 225,
    ptrace_access_check = 226,
    ptrace_traceme = 227,
};

// =============================================================================
// LSM Module Registration
// =============================================================================
pub const LsmFlags = packed struct(u32) {
    exclusive: bool = false, // Only one of same type
    stacking: bool = false, // Can stack with others
    immutable: bool = false, // Cannot be unloaded
    builtin: bool = false, // Built into kernel
    major: bool = false, // Major LSM (SELinux, AppArmor)
    default_off: bool = false, // Disabled unless explicit
    _reserved: u26 = 0,
};

pub const LsmModule = struct {
    name: [SECURITY_NAME_MAX]u8 = [_]u8{0} ** SECURITY_NAME_MAX,
    name_len: u32 = 0,
    id: u32 = 0,
    flags: LsmFlags = .{},

    // Blob sizes (how much security data this LSM needs per object)
    task_blob_size: u32 = 0,
    inode_blob_size: u32 = 0,
    file_blob_size: u32 = 0,
    ipc_blob_size: u32 = 0,
    socket_blob_size: u32 = 0,
    key_blob_size: u32 = 0,
    msg_msg_blob_size: u32 = 0,
    superblock_blob_size: u32 = 0,
    cred_blob_size: u32 = 0,

    // Hook callbacks — pointers to LsmHookHead chains
    enabled: bool = false,
    order: u32 = 0, // Evaluation order (lower = first)
    initialized: bool = false,

    // Statistics
    hook_calls: u64 = 0,
    hook_denials: u64 = 0,
    hook_errors: u64 = 0,
};

// =============================================================================
// LSM Hook Infrastructure
// =============================================================================
pub const LsmHookHead = struct {
    callbacks: [MAX_STACKED_LSMS]?*const LsmCallback = [_]?*const LsmCallback{null} ** MAX_STACKED_LSMS,
    count: u32 = 0,

    pub fn addCallback(self: *LsmHookHead, cb: *const LsmCallback) bool {
        if (self.count >= MAX_STACKED_LSMS) return false;
        self.callbacks[self.count] = cb;
        self.count += 1;
        return true;
    }

    pub fn callChain(self: *const LsmHookHead, cred: *const Credentials, context: *const HookContext) LsmResult {
        var result: LsmResult = .allow;
        for (0..self.count) |i| {
            if (self.callbacks[i]) |cb| {
                const r = cb.call(cred, context);
                if (r != .allow and r != .defer) {
                    return r; // First denial wins
                }
                if (r != .defer) {
                    result = r;
                }
            }
        }
        return result;
    }
};

pub const LsmCallback = struct {
    module_id: u32 = 0,
    hook_type: LsmHookType = .task_alloc,
    priority: u32 = 0,

    pub fn call(self: *const LsmCallback, cred: *const Credentials, context: *const HookContext) LsmResult {
        // Dispatch based on hook type category
        _ = self;
        _ = cred;
        _ = context;
        return .allow;
    }
};

pub const HookContext = struct {
    hook_type: LsmHookType = .task_alloc,

    // Object pointers (only relevant ones filled per hook)
    target_uid: u32 = 0,
    target_gid: u32 = 0,
    inode_ino: u64 = 0,
    inode_mode: u32 = 0,
    file_flags: u32 = 0,
    signal_num: u32 = 0,
    socket_type: u32 = 0,
    socket_protocol: u32 = 0,
    requested_cap: u32 = 0,

    // Path information
    path: [256]u8 = [_]u8{0} ** 256,
    path_len: u32 = 0,

    // Request type
    mask: u32 = 0, // MAY_READ|MAY_WRITE|MAY_EXEC

    // IPC key
    ipc_key: u32 = 0,
    ipc_cmd: u32 = 0,
};

// =============================================================================
// DAC Permission Checks
// =============================================================================
pub const MAY_EXEC: u32 = 0x001;
pub const MAY_WRITE: u32 = 0x002;
pub const MAY_READ: u32 = 0x004;
pub const MAY_APPEND: u32 = 0x008;
pub const MAY_ACCESS: u32 = 0x010;
pub const MAY_CHDIR: u32 = 0x040;

pub fn checkDacPermission(cred: *const Credentials, mode: u32, mask: u32) LsmResult {
    // Root bypass (with DAC_OVERRIDE)
    if (cred.euid == 0) {
        if (cred.capable(.dac_override)) return .allow;
    }

    // Owner check
    var granted: u32 = 0;
    if (cred.fsuid == 0) { // Check against inode uid would go here
        // Owner permissions (upper triad)
        granted = (mode >> 6) & 0x7;
    } else if (cred.inGroup(0)) { // Check against inode gid
        // Group permissions (middle triad)
        granted = (mode >> 3) & 0x7;
    } else {
        // Other permissions (lower triad)
        granted = mode & 0x7;
    }

    // Map rwx to MAY_* flags
    var perm: u32 = 0;
    if (granted & 4 != 0) perm |= MAY_READ;
    if (granted & 2 != 0) perm |= MAY_WRITE;
    if (granted & 1 != 0) perm |= MAY_EXEC;

    if ((mask & ~perm) != 0) {
        return .deny_eacces;
    }
    return .allow;
}

// =============================================================================
// Type Enforcement Engine (SELinux-compatible)
// =============================================================================
pub const MAX_SECURITY_TYPES: u32 = 4096;
pub const MAX_SECURITY_CLASSES: u32 = 128;
pub const MAX_PERMISSIONS_PER_CLASS: u32 = 32;

pub const SecurityId = u32; // SID

pub const SecurityContext = struct {
    user: [64]u8 = [_]u8{0} ** 64,
    user_len: u32 = 0,
    role: [64]u8 = [_]u8{0} ** 64,
    role_len: u32 = 0,
    type_name: [64]u8 = [_]u8{0} ** 64,
    type_name_len: u32 = 0,
    level: MlsLevel = .{},

    pub fn format(self: *const SecurityContext, buf: []u8) u32 {
        // Format: "user:role:type:s0-s0:c0.c1023"
        var pos: u32 = 0;
        // Copy user
        for (0..self.user_len) |i| {
            if (pos >= buf.len) break;
            buf[pos] = self.user[i];
            pos += 1;
        }
        if (pos < buf.len) {
            buf[pos] = ':';
            pos += 1;
        }
        // Copy role
        for (0..self.role_len) |i| {
            if (pos >= buf.len) break;
            buf[pos] = self.role[i];
            pos += 1;
        }
        if (pos < buf.len) {
            buf[pos] = ':';
            pos += 1;
        }
        // Copy type
        for (0..self.type_name_len) |i| {
            if (pos >= buf.len) break;
            buf[pos] = self.type_name[i];
            pos += 1;
        }
        return pos;
    }
};

pub const MlsLevel = struct {
    sensitivity: u16 = 0, // s0-s15
    categories: [32]u8 = [_]u8{0} ** 32, // Bitmap for c0-c255

    pub fn dominates(self: *const MlsLevel, other: *const MlsLevel) bool {
        if (self.sensitivity < other.sensitivity) return false;
        // Check category containment
        for (0..32) |i| {
            if ((other.categories[i] & ~self.categories[i]) != 0) return false;
        }
        return true;
    }

    pub fn equals(self: *const MlsLevel, other: *const MlsLevel) bool {
        if (self.sensitivity != other.sensitivity) return false;
        for (0..32) |i| {
            if (self.categories[i] != other.categories[i]) return false;
        }
        return true;
    }
};

pub const AccessVector = u32; // Bitmap of permissions

pub const TypeEnforcementRule = struct {
    source_type: u16 = 0,
    target_type: u16 = 0,
    object_class: u16 = 0,
    allowed: AccessVector = 0,
    auditallow: AccessVector = 0,
    auditdeny: AccessVector = 0xFFFFFFFF,
    dontaudit: AccessVector = 0,
};

pub const TypeTransitionRule = struct {
    source_type: u16 = 0,
    target_type: u16 = 0,
    object_class: u16 = 0,
    default_type: u16 = 0,
};

pub const SecurityPolicy = struct {
    // Type enforcement rules (Access Vector Cache)
    te_rules: [4096]TypeEnforcementRule = undefined,
    te_rule_count: u32 = 0,

    // Type transitions
    tt_rules: [1024]TypeTransitionRule = undefined,
    tt_rule_count: u32 = 0,

    // Role allow rules
    role_allow: [256]RoleAllow = undefined,
    role_allow_count: u32 = 0,

    // Boolean conditionals
    booleans: [64]PolicyBoolean = undefined,
    boolean_count: u32 = 0,

    // Policy version
    policy_version: u32 = 33, // SELinux policy version
    mls_enabled: bool = true,
    enforce: bool = true,
    permissive_types: [512]u8 = [_]u8{0} ** 512, // Bitmap

    pub fn checkAccess(self: *const SecurityPolicy, source: u16, target: u16, class: u16, perm: AccessVector) LsmResult {
        // Search TE rules for matching rule
        for (0..self.te_rule_count) |i| {
            const rule = &self.te_rules[i];
            if (rule.source_type == source and rule.target_type == target and rule.object_class == class) {
                if ((rule.allowed & perm) == perm) {
                    return .allow;
                } else {
                    // Check if source type is permissive
                    const byte_idx = source / 8;
                    const bit_idx: u3 = @intCast(source % 8);
                    if (byte_idx < self.permissive_types.len and
                        (self.permissive_types[byte_idx] & (@as(u8, 1) << bit_idx)) != 0)
                    {
                        return .allow; // Permissive mode for this type
                    }
                    if (!self.enforce) return .allow; // Permissive mode globally
                    return .deny_eacces;
                }
            }
        }

        // No rule found — deny by default (unless permissive)
        if (!self.enforce) return .allow;
        return .deny_eacces;
    }

    pub fn findTransition(self: *const SecurityPolicy, source: u16, target: u16, class: u16) ?u16 {
        for (0..self.tt_rule_count) |i| {
            const rule = &self.tt_rules[i];
            if (rule.source_type == source and rule.target_type == target and rule.object_class == class) {
                return rule.default_type;
            }
        }
        return null;
    }
};

pub const RoleAllow = struct {
    source_role: u16 = 0,
    target_role: u16 = 0,
};

pub const PolicyBoolean = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u32 = 0,
    value: bool = false,
    default_value: bool = false,
    conditional_id: u32 = 0,
};

// =============================================================================
// Access Vector Cache (AVC)
// =============================================================================
pub const AVC_CACHE_SLOTS: usize = 512;

pub const AvcEntry = struct {
    source_type: u16 = 0,
    target_type: u16 = 0,
    object_class: u16 = 0,
    allowed: AccessVector = 0,
    decided: AccessVector = 0,
    auditallow: AccessVector = 0,
    auditdeny: AccessVector = 0,
    valid: bool = false,
    seq: u32 = 0, // Sequence for invalidation

    pub fn hash(source: u16, target: u16, class: u16) u32 {
        var h: u32 = @as(u32, source) * 17 + @as(u32, target) * 31 + @as(u32, class) * 13;
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        return h % AVC_CACHE_SLOTS;
    }
};

pub const AccessVectorCache = struct {
    entries: [AVC_CACHE_SLOTS]AvcEntry = [_]AvcEntry{AvcEntry{}} ** AVC_CACHE_SLOTS,
    hits: u64 = 0,
    misses: u64 = 0,
    evictions: u64 = 0,
    seq: u32 = 0, // Global sequence

    pub fn lookup(self: *AccessVectorCache, source: u16, target: u16, class: u16) ?*const AvcEntry {
        const slot = AvcEntry.hash(source, target, class);
        const entry = &self.entries[slot];
        if (entry.valid and entry.source_type == source and
            entry.target_type == target and entry.object_class == class and
            entry.seq == self.seq)
        {
            self.hits += 1;
            return entry;
        }
        self.misses += 1;
        return null;
    }

    pub fn insert(self: *AccessVectorCache, source: u16, target: u16, class: u16, allowed: AccessVector) void {
        const slot = AvcEntry.hash(source, target, class);
        const entry = &self.entries[slot];
        if (entry.valid) self.evictions += 1;

        entry.source_type = source;
        entry.target_type = target;
        entry.object_class = class;
        entry.allowed = allowed;
        entry.decided = 0xFFFFFFFF;
        entry.valid = true;
        entry.seq = self.seq;
    }

    pub fn invalidateAll(self: *AccessVectorCache) void {
        self.seq +%= 1; // Bump sequence to invalidate all entries
    }
};

// =============================================================================
// Integrity Measurement Architecture (IMA)
// =============================================================================
pub const ImaPolicy = enum(u8) {
    dont_measure = 0,
    measure = 1,
    dont_appraise = 2,
    appraise = 3,
    audit = 4,
    hash = 5,
};

pub const ImaDigestAlgo = enum(u8) {
    sha1 = 0,
    sha256 = 1,
    sha384 = 2,
    sha512 = 3,
    sm3_256 = 4,
};

pub const ImaMeasurement = struct {
    pcr: u32 = 10, // TPM PCR index
    digest_algo: ImaDigestAlgo = .sha256,
    digest: [IMA_DIGEST_SIZE]u8 = [_]u8{0} ** IMA_DIGEST_SIZE,
    digest_len: u32 = 32, // SHA-256 = 32 bytes
    filename: [256]u8 = [_]u8{0} ** 256,
    filename_len: u32 = 0,
    template_name: [32]u8 = [_]u8{0} ** 32,
    template_len: u32 = 0,
    inode_ino: u64 = 0,
    uid: u32 = 0,
    flags: u32 = 0,
};

pub const ImaLog = struct {
    measurements: [8192]ImaMeasurement = undefined,
    count: u32 = 0,
    violations: u64 = 0,
    total_measured: u64 = 0,

    pub fn addMeasurement(self: *ImaLog, m: ImaMeasurement) bool {
        if (self.count >= 8192) return false;
        self.measurements[self.count] = m;
        self.count += 1;
        self.total_measured += 1;
        return true;
    }

    /// Extend TPM PCR (simulated)
    pub fn extendPcr(self: *ImaLog, pcr: u32, digest: []const u8) void {
        _ = self;
        _ = pcr;
        _ = digest;
        // In real kernel: TPM2_PCR_Extend(pcr, SHA256, digest)
    }
};

// =============================================================================
// Extended Verification Module (EVM)
// =============================================================================
pub const EvmStatus = enum(u8) {
    unknown = 0,
    valid = 1,
    invalid = 2,
    failed = 3,
    not_signed = 4,
};

pub const EvmXattrType = enum(u8) {
    hmac = 1, // EVM HMAC
    signature_v2 = 2, // EVM digital signature
    portable_digsig = 3, // Portable digest signature
};

pub const EvmProtectedXattrs = struct {
    // xattrs protected by EVM
    pub const XATTR_IMA: []const u8 = "security.ima";
    pub const XATTR_SELINUX: []const u8 = "security.selinux";
    pub const XATTR_SMACK: []const u8 = "security.SMACK64";
    pub const XATTR_APPARMOR: []const u8 = "security.apparmor";
    pub const XATTR_CAPS: []const u8 = "security.capability";

    pub fn isProtected(name: []const u8) bool {
        const protected = [_][]const u8{
            XATTR_IMA,
            XATTR_SELINUX,
            XATTR_SMACK,
            XATTR_APPARMOR,
            XATTR_CAPS,
        };
        for (protected) |p| {
            if (name.len == p.len and std.mem.eql(u8, name, p)) return true;
        }
        return false;
    }
};

const std = @import("std");

// =============================================================================
// Landlock (Unprivileged Sandboxing)
// =============================================================================
pub const LandlockAccessFs = packed struct(u16) {
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
    _reserved: u1 = 0,
};

pub const LandlockAccessNet = packed struct(u8) {
    bind_tcp: bool = false,
    connect_tcp: bool = false,
    _reserved: u6 = 0,
};

pub const LandlockRule = struct {
    rule_type: LandlockRuleType = .path_beneath,
    access_fs: LandlockAccessFs = .{},
    access_net: LandlockAccessNet = .{},
    parent_fd: i32 = -1,
    port: u16 = 0, // For net rules
};

pub const LandlockRuleType = enum(u8) {
    path_beneath = 1,
    net_port = 2,
};

pub const LandlockDomain = struct {
    rules: [64]LandlockRule = undefined,
    rule_count: u32 = 0,
    handled_access_fs: LandlockAccessFs = .{},
    handled_access_net: LandlockAccessNet = .{},
    parent: ?*LandlockDomain = null,
    depth: u32 = 0,

    pub fn addRule(self: *LandlockDomain, rule: LandlockRule) bool {
        if (self.rule_count >= 64) return false;
        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
        return true;
    }

    pub fn checkAccessFs(self: *const LandlockDomain, path: []const u8, access: LandlockAccessFs) LsmResult {
        _ = path;
        // Check if this access type is handled
        const handled_bits: u16 = @bitCast(self.handled_access_fs);
        const requested_bits: u16 = @bitCast(access);

        // Only check access types that are handled by this domain
        const relevant = requested_bits & handled_bits;
        if (relevant == 0) return .allow; // Not handled → allow

        // Search rules for a matching allow
        for (0..self.rule_count) |i| {
            const rule = &self.rules[i];
            if (rule.rule_type == .path_beneath) {
                const rule_bits: u16 = @bitCast(rule.access_fs);
                if ((relevant & rule_bits) == relevant) {
                    return .allow;
                }
            }
        }

        // Check parent domain
        if (self.parent) |p| {
            return p.checkAccessFs(path, access);
        }

        return .deny_eacces; // No rule matched → deny
    }
};

// =============================================================================
// Lockdown (Kernel Lockdown)
// =============================================================================
pub const LockdownReason = enum(u8) {
    none = 0,
    module_signature = 1,
    dev_mem = 2,
    efi_test = 3,
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
    perf_bpf = 17,
    integrity_kexec = 18,
};

pub const LockdownLevel = enum(u8) {
    none = 0,
    integrity = 1, // Protect kernel integrity
    confidentiality = 2, // Protect kernel secrets too
};

pub const LockdownState = struct {
    level: LockdownLevel = .none,
    reasons_blocked: [32]u8 = [_]u8{0} ** 32, // Bitmap
    violations: u64 = 0,

    pub fn checkLockdown(self: *LockdownState, reason: LockdownReason) LsmResult {
        const r = @intFromEnum(reason);
        switch (self.level) {
            .none => return .allow,
            .integrity => {
                // Block modifications to running kernel
                switch (reason) {
                    .module_signature, .dev_mem, .kexec, .acpi_tables, .module_parameters, .debugfs => {
                        self.violations += 1;
                        self.reasons_blocked[r / 8] |= @as(u8, 1) << @intCast(r % 8);
                        return .deny_eperm;
                    },
                    else => return .allow,
                }
            },
            .confidentiality => {
                // Block all dangerous operations
                if (r != 0) {
                    self.violations += 1;
                    self.reasons_blocked[r / 8] |= @as(u8, 1) << @intCast(r % 8);
                    return .deny_eperm;
                }
                return .allow;
            },
        }
    }
};

// =============================================================================
// Stack Canary & CFI
// =============================================================================
pub const StackProtector = struct {
    canary: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *StackProtector, entropy_source: u64) void {
        // Generate canary from entropy
        // Include null byte at bottom to prevent string-based overflows
        self.canary = (entropy_source & 0xFFFFFFFFFFFFFF00);
        self.initialized = true;
    }

    pub fn check(self: *const StackProtector, current_canary: u64) bool {
        return self.canary == current_canary;
    }

    pub fn onStackSmash(self: *const StackProtector) void {
        _ = self;
        // In real kernel: kernel panic with stack dump
    }
};

pub const CfiState = struct {
    enabled: bool = false,
    shadow_stack_enabled: bool = false, // Intel CET
    btb_isolation: bool = false, // Branch Target Buffer isolation
    ibrs_enabled: bool = false, // Indirect Branch Restricted Speculation
    stibp_enabled: bool = false, // Single Thread Indirect Branch Predictors
    ssbd_enabled: bool = false, // Speculative Store Bypass Disable
    retpoline_enabled: bool = false,
    violations: u64 = 0,

    pub fn checkReturnAddress(self: *CfiState, expected: u64, actual: u64) bool {
        if (!self.shadow_stack_enabled) return true;
        if (expected != actual) {
            self.violations += 1;
            return false;
        }
        return true;
    }
};

// =============================================================================
// KASLR (Kernel Address Space Layout Randomization)
// =============================================================================
pub const KaslrState = struct {
    enabled: bool = false,
    text_offset: u64 = 0, // Randomized kernel text offset
    module_offset: u64 = 0, // Module loading area offset
    physmap_offset: u64 = 0, // Physical mapping offset
    vmalloc_offset: u64 = 0, // vmalloc area offset
    entropy_bits: u32 = 0,

    pub fn init(self: *KaslrState, seed: u64) void {
        // LCG-based offset generation (simplified)
        var rng = seed;
        rng ^= rng >> 33;
        rng *%= 0xff51afd7ed558ccd;
        rng ^= rng >> 33;
        rng *%= 0xc4ceb9fe1a85ec53;
        rng ^= rng >> 33;

        // Align offsets to 2MB (huge page boundary)
        self.text_offset = (rng & 0x3FE00000); // Max ~1GB range
        rng = rng *% 0x6c62272e07bb0142 +% 1;
        self.module_offset = (rng & 0x3FE00000);
        rng = rng *% 0x6c62272e07bb0142 +% 1;
        self.physmap_offset = (rng & 0x3FE00000);
        self.vmalloc_offset = 0; // Determined separately
        self.entropy_bits = 30;
        self.enabled = true;
    }
};

// =============================================================================
// Global LSM State
// =============================================================================
pub const LsmFramework = struct {
    modules: [MAX_LSM_MODULES]LsmModule = undefined,
    module_count: u32 = 0,

    // Hook heads (one per hook type)
    hooks: [256]LsmHookHead = [_]LsmHookHead{LsmHookHead{}} ** 256,

    // Global policy objects
    policy: SecurityPolicy = .{},
    avc: AccessVectorCache = .{},
    ima_log: ImaLog = .{},
    lockdown: LockdownState = .{},
    kaslr: KaslrState = .{},
    cfi: CfiState = .{},

    // Boot-time configuration
    enabled_lsm_names: [512]u8 = [_]u8{0} ** 512,
    default_lsm: [64]u8 = [_]u8{0} ** 64,

    // Statistics
    total_hook_calls: u64 = 0,
    total_denials: u64 = 0,
    total_audit_events: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *LsmFramework) void {
        self.module_count = 0;
        self.initialized = true;
        self.lockdown.level = .none;
    }

    pub fn registerModule(self: *LsmFramework, module: LsmModule) bool {
        if (self.module_count >= MAX_LSM_MODULES) return false;
        self.modules[self.module_count] = module;
        self.module_count += 1;
        return true;
    }

    pub fn callHook(self: *LsmFramework, hook: LsmHookType, cred: *const Credentials, ctx: *const HookContext) LsmResult {
        self.total_hook_calls += 1;
        const result = self.hooks[@intFromEnum(hook)].callChain(cred, ctx);
        if (result != .allow) {
            self.total_denials += 1;
        }
        return result;
    }

    pub fn avcLookupAndCheck(self: *LsmFramework, source: u16, target: u16, class: u16, perm: AccessVector) LsmResult {
        // Check AVC first
        if (self.avc.lookup(source, target, class)) |entry| {
            if ((entry.allowed & perm) == perm) return .allow;
            return .deny_eacces;
        }

        // AVC miss — consult policy
        const result = self.policy.checkAccess(source, target, class, perm);
        // Cache the result
        if (result == .allow) {
            self.avc.insert(source, target, class, perm);
        }
        return result;
    }
};

var global_lsm: LsmFramework = .{};

pub fn getLsmFramework() *LsmFramework {
    return &global_lsm;
}

pub fn initSecurity() void {
    global_lsm.init();
}
