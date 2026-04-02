// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - IPC Namespace, User Namespace, and PID Namespace Detail
// Complete: ns_operations, namespace types, clone flags, setns/unshare,
// user_namespace (uid/gid mapping), PID namespace, mount propagation

/// Namespace types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsType {
    Mount = 0x00020000,    // CLONE_NEWNS
    Cgroup = 0x02000000,   // CLONE_NEWCGROUP
    Uts = 0x04000000,      // CLONE_NEWUTS
    Ipc = 0x08000000,      // CLONE_NEWIPC
    User = 0x10000000,     // CLONE_NEWUSER
    Pid = 0x20000000,      // CLONE_NEWPID
    Net = 0x40000000,      // CLONE_NEWNET
    Time = 0x00000080,     // CLONE_NEWTIME
}

/// All namespace clone flags
pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_NEWTIME: u64 = 0x00000080;

/// Namespace operations
pub struct NsOperations {
    pub name: &'static str,
    pub ns_type: NsType,
    pub get: Option<unsafe extern "C" fn(task: *mut u8) -> *mut NsCommon>,
    pub put: Option<unsafe extern "C" fn(ns: *mut NsCommon)>,
    pub install: Option<unsafe extern "C" fn(nsproxy: *mut NsProxy, ns: *mut NsCommon) -> i32>,
    pub owner: Option<unsafe extern "C" fn(ns: *mut NsCommon) -> *mut UserNamespace>,
    pub get_parent: Option<unsafe extern "C" fn(ns: *mut NsCommon) -> *mut NsCommon>,
}

/// Common namespace header
#[repr(C)]
pub struct NsCommon {
    pub stashed: *mut u8,
    pub ops: *const NsOperations,
    pub inum: u32,
    pub count: u64,
}

/// Namespace proxy - per-task namespace set
#[repr(C)]
pub struct NsProxy {
    pub count: u64,
    pub uts_ns: *mut UtsNamespace,
    pub ipc_ns: *mut IpcNamespace,
    pub mnt_ns: *mut MntNamespace,
    pub pid_ns_for_children: *mut PidNamespace,
    pub net_ns: *mut NetNamespace,
    pub time_ns: *mut TimeNamespace,
    pub time_ns_for_children: *mut TimeNamespace,
    pub cgroup_ns: *mut CgroupNamespace,
}

// ============================================================================
// User Namespace
// ============================================================================

pub const MAX_UID_MAP_EXTENTS: usize = 340;
pub const MAX_GID_MAP_EXTENTS: usize = 340;

/// UID/GID mapping extent
#[repr(C)]
pub struct UidGidExtent {
    pub first: u32,
    pub lower_first: u32,
    pub count: u32,
}

/// UID/GID map
#[repr(C)]
pub struct UidGidMap {
    pub nr_extents: u32,
    pub forward: [UidGidExtent; 5],     // Small (most common case)
    pub reverse: [UidGidExtent; 5],
    pub forward_ptr: *mut UidGidExtent,  // Large (> 5 extents)
    pub reverse_ptr: *mut UidGidExtent,
}

/// User namespace
#[repr(C)]
pub struct UserNamespace {
    pub ns: NsCommon,
    pub uid_map: UidGidMap,
    pub gid_map: UidGidMap,
    pub projid_map: UidGidMap,
    pub parent: *mut UserNamespace,
    pub level: i32,
    pub owner: u32,     // kuid_t
    pub group: u32,     // kgid_t
    pub flags: UserNsFlags,
    pub keyring: *mut u8,
    pub persistent_keyring: *mut u8,
    pub ucounts: *mut UCounts,
    pub ucount_max: [u64; 16],  // Per-resource limits
    pub rlimit_max: [u64; 16],  // Per-resource rlimits
    pub binfmt_misc: *mut u8,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum UserNsFlags {
    None = 0,
    SetGroupsAllowed = 1,
    UnprivilegedUserns = 2,
}

/// Per-user resource counters
#[repr(C)]
pub struct UCounts {
    pub ns: *mut UserNamespace,
    pub uid: u32,
    pub count: u32,
    pub ucount: [i64; 16],
    pub rlimit: [i64; 16],
}

/// Ucount types
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum UcountType {
    UserNamespaces = 0,
    PidNamespaces = 1,
    UtsNamespaces = 2,
    IpcNamespaces = 3,
    NetNamespaces = 4,
    MntNamespaces = 5,
    CgroupNamespaces = 6,
    TimeNamespaces = 7,
    Inotify = 8,
    InotifyWatches = 9,
    Fanotify = 10,
    FanotifyMarks = 11,
    RlimitNproc = 12,
    RlimitMsgqueue = 13,
    RlimitSigpending = 14,
    RlimitMemlock = 15,
}

// ============================================================================
// PID Namespace
// ============================================================================

/// PID namespace
#[repr(C)]
pub struct PidNamespace {
    pub ns: NsCommon,
    pub idr: *mut u8,          // IDR for PID allocation
    pub rcu: *mut u8,
    pub pid_allocated: u32,
    pub child_reaper: *mut u8,  // init process for this namespace
    pub pid_cachep: *mut u8,
    pub level: u32,
    pub parent: *mut PidNamespace,
    pub bacct: *mut u8,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
    pub nr_hashed: i32,
    pub reboot: i32,
    pub memfd_noexec_scope: u32,
}

/// PID structure (multi-level for nested PID namespaces)
#[repr(C)]
pub struct Pid {
    pub count: u64,
    pub level: u32,
    pub stashed: *mut u8,
    pub rcu: *mut u8,
    pub numbers: [UPid; 1],  // Flexible: one per namespace level
}

/// Per-namespace PID number
#[repr(C)]
pub struct UPid {
    pub nr: i32,
    pub ns: *mut PidNamespace,
}

/// PID type (thread group, process group, session)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidType {
    Pid = 0,
    Tgid = 1,
    Pgid = 2,
    Sid = 3,
}

// ============================================================================
// IPC Namespace
// ============================================================================

/// IPC namespace
#[repr(C)]
pub struct IpcNamespace {
    pub ns: NsCommon,
    pub ids: [IpcIds; 3],       // sem, msg, shm
    pub sem_ctls: [i32; 4],     // SEMMSL, SEMMNS, SEMOPM, SEMMNI
    pub used_sems: i32,
    pub msg_ctlmax: i32,
    pub msg_ctlmnb: i32,
    pub msg_ctlmni: i32,
    pub msg_bytes: u64,
    pub msg_hdrs: u64,
    pub shm_ctlmax: u64,
    pub shm_ctlall: u64,
    pub shm_ctlmni: i32,
    pub shm_rmid_forced: i32,
    pub shm_tot: u64,
    pub mq_queues_count: u32,
    pub mq_queues_max: u32,
    pub mq_msg_max: u32,
    pub mq_msgsize_max: u32,
    pub mq_msg_default: u32,
    pub mq_msgsize_default: u32,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
    pub mnt: *mut u8,
}

/// IPC IDs (shared between sem, msg, shm)
#[repr(C)]
pub struct IpcIds {
    pub in_use: i32,
    pub seq: u16,
    pub next_id: i32,
    pub ipcs_idr: *mut u8,    // IDR radix tree
    pub max_idx: i32,
    pub last_idx: i32,
}

// ============================================================================
// UTS Namespace
// ============================================================================

/// UTS namespace (hostname, domainname)
#[repr(C)]
pub struct UtsNamespace {
    pub ns: NsCommon,
    pub name: NewUtsname,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
}

/// New uts name fields
#[repr(C)]
pub struct NewUtsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

// ============================================================================
// Mount Namespace
// ============================================================================

/// Mount namespace
#[repr(C)]
pub struct MntNamespace {
    pub ns: NsCommon,
    pub root: *mut Mount,
    pub list: *mut Mount,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
    pub seq: u64,
    pub poll: u64,
    pub event: u64,
    pub nr_mounts: u32,
    pub pending_mounts: u32,
    pub mounts: u32,
}

/// Mount structure
#[repr(C)]
pub struct Mount {
    pub mnt_hash: *mut u8,
    pub mnt_parent: *mut Mount,
    pub mnt_mountpoint: *mut u8,
    pub mnt: VfsMount,
    pub mnt_rcu: *mut u8,
    pub mnt_id: i32,
    pub mnt_group_id: i32,
    pub mnt_expiry_mark: i32,
    pub mnt_pins: *mut u8,
    pub mnt_slave_list: *mut u8,
    pub mnt_slave: *mut u8,
    pub mnt_master: *mut Mount,
    pub mnt_ns: *mut MntNamespace,
    pub mnt_umounting: i32,
}

/// VFS mount
#[repr(C)]
pub struct VfsMount {
    pub mnt_root: *mut u8,     // dentry
    pub mnt_sb: *mut u8,       // super_block
    pub mnt_flags: MntFlags,
    pub mnt_idmap: *mut u8,
}

/// Mount flags
pub struct MntFlags(u32);

impl MntFlags {
    pub const NOSUID: u32 = 0x01;
    pub const NODEV: u32 = 0x02;
    pub const NOEXEC: u32 = 0x04;
    pub const NOATIME: u32 = 0x08;
    pub const NODIRATIME: u32 = 0x10;
    pub const RELATIME: u32 = 0x20;
    pub const READONLY: u32 = 0x40;
    pub const NOSYMFOLLOW: u32 = 0x80;
    pub const SHRINKABLE: u32 = 0x100;
    pub const WRITE_HOLD: u32 = 0x200;
    pub const SHARED: u32 = 0x1000;
    pub const UNBINDABLE: u32 = 0x2000;
    pub const INTERNAL: u32 = 0x4000;
    pub const LOCK_ATIME: u32 = 0x8000;
    pub const LOCK_NOEXEC: u32 = 0x10000;
    pub const LOCK_NOSUID: u32 = 0x20000;
    pub const LOCK_NODEV: u32 = 0x40000;
    pub const LOCK_READONLY: u32 = 0x80000;
    pub const LOCKED: u32 = 0x800000;
    pub const DOOMED: u32 = 0x1000000;
    pub const SYNC_UMOUNT: u32 = 0x2000000;
    pub const MARKED: u32 = 0x4000000;
    pub const UMOUNT: u32 = 0x8000000;
}

/// Mount propagation types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountPropagation {
    Private = 0,
    Shared = 1,
    Slave = 2,
    Unbindable = 3,
}

// ============================================================================
// Network Namespace
// ============================================================================

/// Network namespace
#[repr(C)]
pub struct NetNamespace {
    pub ns: NsCommon,
    pub count: u64,
    pub passive: u32,
    pub rules_mod_lock: u64,
    pub list: *mut u8,
    pub exit_list: *mut u8,
    pub cleanup_list: *mut u8,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
    pub net_cookie: u64,
    pub ipv4: NetnsIpv4,
    pub ipv6: NetnsIpv6,
    pub loopback_dev: *mut u8,
    pub gen: *mut u8,
    pub proc_net: *mut u8,
    pub proc_net_stat: *mut u8,
    pub unx: NetnsUnix,
    pub nf: NetnsNf,
    pub ct: NetnsCt,
    pub nft: NetnsNft,
    pub mib: NetnsMib,
}

#[repr(C)]
pub struct NetnsIpv4 {
    pub sysctl_ip_default_ttl: u8,
    pub sysctl_tcp_ecn: u8,
    pub sysctl_tcp_timestamps: u8,
    pub sysctl_tcp_window_scaling: u8,
    pub sysctl_tcp_sack: u8,
    pub sysctl_tcp_fin_timeout: i32,
    pub sysctl_tcp_keepalive_time: i32,
    pub sysctl_tcp_keepalive_probes: i32,
    pub sysctl_tcp_keepalive_intvl: i32,
    pub sysctl_tcp_max_orphans: i32,
    pub sysctl_tcp_max_tw_buckets: i32,
    pub sysctl_tcp_rmem: [i32; 3],
    pub sysctl_tcp_wmem: [i32; 3],
    pub sysctl_ip_local_port_range: [i32; 2],
    pub sysctl_ip_forward: bool,
    pub sysctl_icmp_echo_ignore_all: bool,
    pub sysctl_icmp_echo_ignore_broadcasts: bool,
    pub fib_table_hash: *mut u8,
    pub fib_table_hash_size: u32,
    pub rules_ops: *mut u8,
    pub fib_has_custom_rules: bool,
}

#[repr(C)]
pub struct NetnsIpv6 {
    pub sysctl: Ipv6Sysctl,
    pub devconf_all: *mut u8,
    pub devconf_dflt: *mut u8,
    pub fib6_main_tbl: *mut u8,
    pub fib6_local_tbl: *mut u8,
    pub fib6_rules_ops: *mut u8,
    pub fib6_has_custom_rules: bool,
    pub ip6_dst_ops: *mut u8,
    pub rt6_stats: *mut u8,
    pub ip6_fib_timer: u64,
    pub ip6_prohibit_entry: *mut u8,
    pub ip6_blk_hole_entry: *mut u8,
}

#[repr(C)]
pub struct Ipv6Sysctl {
    pub ip6_rt_gc_interval: i32,
    pub ip6_rt_gc_timeout: i32,
    pub ip6_rt_gc_elasticity: i32,
    pub ip6_rt_mtu_expires: i32,
    pub ip6_rt_min_advmss: i32,
    pub multipath_hash_fields: u32,
    pub multipath_hash_policy: u8,
}

#[repr(C)]
pub struct NetnsUnix {
    pub sysctl_max_dgram_qlen: i32,
}

#[repr(C)]
pub struct NetnsNf {
    pub proc_netfilter: *mut u8,
    pub nf_loggers: [*mut u8; 12],
    pub hooks_ipv4: [*mut u8; 5],
    pub hooks_ipv6: [*mut u8; 5],
    pub hooks_arp: [*mut u8; 3],
    pub hooks_bridge: [*mut u8; 5],
}

#[repr(C)]
pub struct NetnsCt {
    pub count: u64,
    pub expect_count: u32,
    pub htable_size: u32,
    pub sysctl_events: bool,
    pub sysctl_acct: bool,
    pub auto_assign_helper: bool,
    pub sysctl_tstamp: bool,
    pub sysctl_checksum: bool,
    pub sysctl_log_invalid: u8,
}

#[repr(C)]
pub struct NetnsNft {
    pub tables: *mut u8,
    pub base_seq: u32,
    pub gc_seq: u32,
}

#[repr(C)]
pub struct NetnsMib {
    pub net_statistics: *mut u8,
    pub ip_statistics: *mut u8,
    pub tcp_statistics: *mut u8,
    pub udp_statistics: *mut u8,
    pub udplite_statistics: *mut u8,
    pub icmp_statistics: *mut u8,
    pub icmpmsg_statistics: *mut u8,
}

// ============================================================================
// Time Namespace
// ============================================================================

/// Time namespace
#[repr(C)]
pub struct TimeNamespace {
    pub ns: NsCommon,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
    pub offsets: TimeNsOffsets,
    pub frozen_offsets: bool,
}

#[repr(C)]
pub struct TimeNsOffsets {
    pub monotonic: TimespecOffset,
    pub boottime: TimespecOffset,
}

#[repr(C)]
pub struct TimespecOffset {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// ============================================================================
// Cgroup Namespace
// ============================================================================

/// Cgroup namespace
#[repr(C)]
pub struct CgroupNamespace {
    pub ns: NsCommon,
    pub user_ns: *mut UserNamespace,
    pub ucounts: *mut UCounts,
    pub root_cset: *mut u8,
}

// ============================================================================
// setns / unshare
// ============================================================================

/// setns() flags
pub const SETNS_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWTIME;

/// unshare() flags
pub const UNSHARE_FLAGS: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWTIME
    | 0x00000200    // CLONE_FILES
    | 0x00000100    // CLONE_FS
    | 0x00000800;   // CLONE_SYSVSEM

// ============================================================================
// Statistics
// ============================================================================

pub struct NamespaceStats {
    pub total_namespaces_created: u64,
    pub total_namespaces_destroyed: u64,
    pub total_setns_calls: u64,
    pub total_unshare_calls: u64,
    pub total_clone_ns: u64,
    pub total_uid_maps: u64,
    pub total_gid_maps: u64,
    pub nr_user_namespaces: u32,
    pub nr_pid_namespaces: u32,
    pub nr_net_namespaces: u32,
    pub nr_mnt_namespaces: u32,
    pub nr_ipc_namespaces: u32,
    pub nr_uts_namespaces: u32,
    pub nr_cgroup_namespaces: u32,
    pub nr_time_namespaces: u32,
    pub max_pid_ns_depth: u32,
    pub max_user_ns_depth: u32,
    pub initialized: bool,
}

impl NamespaceStats {
    pub fn new() -> Self {
        Self {
            total_namespaces_created: 0,
            total_namespaces_destroyed: 0,
            total_setns_calls: 0,
            total_unshare_calls: 0,
            total_clone_ns: 0,
            total_uid_maps: 0,
            total_gid_maps: 0,
            nr_user_namespaces: 1,    // init_user_ns
            nr_pid_namespaces: 1,     // init_pid_ns
            nr_net_namespaces: 1,     // init_net
            nr_mnt_namespaces: 1,
            nr_ipc_namespaces: 1,
            nr_uts_namespaces: 1,
            nr_cgroup_namespaces: 1,
            nr_time_namespaces: 1,
            max_pid_ns_depth: 32,
            max_user_ns_depth: 32,
            initialized: true,
        }
    }
}
