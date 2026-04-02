// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - IPC Namespace, Cgroup Freezer, PID Namespace
// Complete IPC namespace isolation, cgroup freezer v2,
// PID namespace hierarchy, user namespace capabilities

const std = @import("std");

// ============================================================================
// IPC Namespace
// ============================================================================

pub const IpcNamespace = struct {
    ns: Namespace,
    ids: [3]IpcIds,       // sem, msg, shm
    sem_ctls: SemCtls,
    msg_ctlmax: u32,      // Max message size
    msg_ctlmnb: u32,      // Max bytes in queue
    msg_ctlmni: u32,      // Max queues
    shm_ctlmax: u64,      // Max shared memory segment size
    shm_ctlall: u64,      // Max total shared memory
    shm_ctlmni: u32,      // Max shared memory segments
    shm_rmid_forced: bool,
    mq_queues_count: u32,
    mq_queues_max: u32,
    mq_msg_max: u32,
    mq_msgsize_max: u32,
    mq_msg_default: u32,
    mq_msgsize_default: u32,
    user_ns: u64,          // struct user_namespace *
    ucounts: u64,
};

pub const SemCtls = struct {
    semmsl: u32,           // Max semaphores per array (default 32000)
    semmns: u32,           // Max system semaphores (default 1024000000)
    semopm: u32,           // Max ops per semop (default 500)
    semmni: u32,           // Max semaphore sets (default 32000)
};

pub const IpcIds = struct {
    in_use: u32,
    seq: u32,
    seq_max: u32,
    last_idx: i32,
    key_ht: u64,           // rhashtable
    ipcs_idr: u64,         // struct idr
    max_idx: i32,
    last_mni_idx: i32,
};

pub const IpcPerm = struct {
    key: i32,              // __key
    uid: u32,
    gid: u32,
    cuid: u32,             // Creator uid
    cgid: u32,             // Creator gid
    mode: u16,
    seq: u16,
    id: i32,
    security: u64,
};

// ============================================================================
// PID Namespace
// ============================================================================

pub const MAX_PID_NS_LEVEL = 32;

pub const PidNamespace = struct {
    ns: Namespace,
    idr: u64,              // struct idr
    rcu: u64,
    pid_allocated: u32,
    child_reaper: u64,     // struct task_struct *
    bacct: u64,            // BSD accounting
    proc_self: u64,        // struct dentry *
    proc_thread_self: u64,
    user_ns: u64,
    ucounts: u64,
    level: u32,
    parent: ?*PidNamespace,
    pid_cachep: u64,       // kmem_cache
    nr_hashed: u32,
    hide_pid: HidePidType,
    reboot: i32,           // LINUX_REBOOT_CMD_*
    memfd_noexec_scope: u32,
};

pub const HidePidType = enum(u8) {
    Off = 0,
    NoPtrace = 1,
    Invisible = 2,
    NotMySelf = 4,
};

pub const PidType = enum(u8) {
    Pid = 0,
    Tgid = 1,
    Pgid = 2,
    Sid = 3,
    MaxPidType = 4,
};

pub const Pid = struct {
    count: u32,
    level: u32,
    stashed: u64,
    tasks: [4]u64,         // hlist_head per PidType
    rcu: u64,
    numbers: [1]Upid,      // Variable length
};

pub const Upid = struct {
    nr: i32,
    ns: ?*PidNamespace,
};

// ============================================================================
// User Namespace
// ============================================================================

pub const UserNamespace = struct {
    ns: Namespace,
    uid_map: IdMap,
    gid_map: IdMap,
    projid_map: IdMap,
    parent: ?*UserNamespace,
    level: i32,
    owner: u32,            // kuid_t
    group: u32,            // kgid_t
    flags: UserNsFlags,
    keyring: u64,
    uid_keyring_register_lock: u64,
    persistent_keyring_register: u64,
    work: u64,
    ns_set: u64,
    ucounts_list: u64,
};

pub const UserNsFlags = packed struct(u32) {
    setgroups_allowed: bool = false,
    userns_created: bool = false,
    _reserved: u30 = 0,
};

pub const IdMap = struct {
    nr_extents: u32,
    extents: [5]IdMapExtent, // Keep up to 5 in-place, more on heap
    forward: u64,
    reverse: u64,
};

pub const IdMapExtent = struct {
    first: u32,
    lower_first: u32,
    count: u32,
};

// ============================================================================
// Mount Namespace
// ============================================================================

pub const MntNamespace = struct {
    ns: Namespace,
    root: u64,             // struct mount *
    mounts: u32,
    pending_mounts: u32,
    nr_mounts: u32,
    user_ns: u64,
    ucounts: u64,
    seq: u64,              // Sequence number
    poll: u64,
    event: u64,
    mnt_id_start: u32,    // Starting mount ID
};

// ============================================================================
// Network Namespace
// ============================================================================

pub const NetNamespace = struct {
    ns: Namespace,
    count: u32,
    passive: u32,
    rules_mod_lock: u64,
    loopback_dev: u64,     // struct net_device *
    core_net: u64,
    proc_net: u64,         // /proc/net dentry
    proc_net_stat: u64,
    net_generic: u64,
    ipv4: NetIpv4Config,   // Simplified - full would be massive
    user_ns: u64,
    ucounts: u64,
    net_cookie: u64,
};

pub const NetIpv4Config = struct {
    ip_forward: bool,
    ip_default_ttl: u8,
    tcp_ecn: u8,
    tcp_ecn_fallback: bool,
    ip_local_port_range_min: u16,
    ip_local_port_range_max: u16,
    sysctl_tcp_rmem: [3]u32,
    sysctl_tcp_wmem: [3]u32,
};

// ============================================================================
// UTS Namespace
// ============================================================================

pub const UtsNamespace = struct {
    ns: Namespace,
    name: Utsname,
    user_ns: u64,
    ucounts: u64,
};

pub const Utsname = struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
    domainname: [65]u8,
};

// ============================================================================
// Time Namespace
// ============================================================================

pub const TimeNamespace = struct {
    ns: Namespace,
    user_ns: u64,
    ucounts: u64,
    vvar_page: u64,
    offsets: TimensOffsets,
    frozen_offsets: bool,
};

pub const TimensOffsets = struct {
    monotonic: Timespec64,
    boottime: Timespec64,
};

pub const Timespec64 = struct {
    tv_sec: i64,
    tv_nsec: i64,
};

// ============================================================================
// Cgroup Namespace
// ============================================================================

pub const CgroupNamespace = struct {
    ns: Namespace,
    user_ns: u64,
    ucounts: u64,
    root_cset: u64,        // struct css_set *
};

// ============================================================================
// Common Namespace Type
// ============================================================================

pub const Namespace = struct {
    stashed: u64,
    ops: ?*const NsOps,
    inum: u32,
    net: u64,
};

pub const NsOps = struct {
    name: [16]u8,
    ns_type: NsType,
    get: ?*const fn (u64) u64,
    put: ?*const fn (u64) void,
    install: ?*const fn (u64, u64) i32,
    owner: ?*const fn (u64) u64,
    get_parent: ?*const fn (u64) u64,
};

pub const NsType = enum(u32) {
    Mnt = 0x00020000,     // CLONE_NEWNS
    Uts = 0x04000000,     // CLONE_NEWUTS
    Ipc = 0x08000000,     // CLONE_NEWIPC
    User = 0x10000000,    // CLONE_NEWUSER
    Pid = 0x20000000,     // CLONE_NEWPID
    Net = 0x40000000,     // CLONE_NEWNET
    Cgroup = 0x02000000,  // CLONE_NEWCGROUP
    Time = 0x00000080,    // CLONE_NEWTIME
};

// ============================================================================
// Cgroup Freezer (v2)
// ============================================================================

pub const CgroupFreezerState = enum(u8) {
    Thawed = 0,
    Freezing = 1,
    Frozen = 2,
};

pub const CgroupFreezer = struct {
    state: CgroupFreezerState,
    self_freezing: bool,
    parent_freezing: u32,
    nr_frozen: u32,
    nr_lazy: u32,
};

pub const CgroupFreezerConfig = struct {
    freeze_timeout_ms: u32,     // Timeout for freeze completion
    allow_partial_freeze: bool,  // Allow partial freeze
    freeze_signal: u32,         // Signal for force freeze (SIGSTOP)
};

// ============================================================================
// Namespace Manager
// ============================================================================

pub const NamespaceManager = struct {
    total_pid_ns: u32,
    total_user_ns: u32,
    total_net_ns: u32,
    total_mnt_ns: u32,
    total_ipc_ns: u32,
    total_uts_ns: u32,
    total_cgroup_ns: u32,
    total_time_ns: u32,
    max_pid_ns_level: u32,
    max_user_ns_level: u32,
    total_ns_clones: u64,
    total_ns_unshares: u64,
    total_setns_calls: u64,
    total_freeze_ops: u64,
    total_thaw_ops: u64,
    initialized: bool,

    pub fn init() NamespaceManager {
        return .{
            .total_pid_ns = 0,
            .total_user_ns = 0,
            .total_net_ns = 0,
            .total_mnt_ns = 0,
            .total_ipc_ns = 0,
            .total_uts_ns = 0,
            .total_cgroup_ns = 0,
            .total_time_ns = 0,
            .max_pid_ns_level = MAX_PID_NS_LEVEL,
            .max_user_ns_level = 32,
            .total_ns_clones = 0,
            .total_ns_unshares = 0,
            .total_setns_calls = 0,
            .total_freeze_ops = 0,
            .total_thaw_ops = 0,
            .initialized = true,
        };
    }
};
