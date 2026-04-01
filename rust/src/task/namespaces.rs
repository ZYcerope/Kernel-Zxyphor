// Zxyphor Kernel - Rust Namespaces, PID NS, User NS, Mount NS,
// Network NS, UTS NS, IPC NS, Cgroup NS, Time NS
// More advanced than Linux 2026 namespace infrastructure

/// Namespace type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsType {
    /// Mount namespace
    Mnt = 0x00020000,
    /// Cgroup namespace
    Cgroup = 0x02000000,
    /// UTS namespace
    Uts = 0x04000000,
    /// IPC namespace
    Ipc = 0x08000000,
    /// User namespace
    User = 0x10000000,
    /// PID namespace
    Pid = 0x20000000,
    /// Network namespace
    Net = 0x40000000,
    /// Time namespace
    Time = 0x00000080,
}

/// Clone flags (for clone3 / unshare)
pub struct CloneFlags;
impl CloneFlags {
    pub const CLONE_VM: u64 = 0x00000100;
    pub const CLONE_FS: u64 = 0x00000200;
    pub const CLONE_FILES: u64 = 0x00000400;
    pub const CLONE_SIGHAND: u64 = 0x00000800;
    pub const CLONE_PIDFD: u64 = 0x00001000;
    pub const CLONE_PTRACE: u64 = 0x00002000;
    pub const CLONE_VFORK: u64 = 0x00004000;
    pub const CLONE_PARENT: u64 = 0x00008000;
    pub const CLONE_THREAD: u64 = 0x00010000;
    pub const CLONE_NEWNS: u64 = 0x00020000;
    pub const CLONE_SYSVSEM: u64 = 0x00040000;
    pub const CLONE_SETTLS: u64 = 0x00080000;
    pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
    pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
    pub const CLONE_DETACHED: u64 = 0x00400000;
    pub const CLONE_UNTRACED: u64 = 0x00800000;
    pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
    pub const CLONE_NEWCGROUP: u64 = 0x02000000;
    pub const CLONE_NEWUTS: u64 = 0x04000000;
    pub const CLONE_NEWIPC: u64 = 0x08000000;
    pub const CLONE_NEWUSER: u64 = 0x10000000;
    pub const CLONE_NEWPID: u64 = 0x20000000;
    pub const CLONE_NEWNET: u64 = 0x40000000;
    pub const CLONE_IO: u64 = 0x80000000;
    pub const CLONE_NEWTIME: u64 = 0x00000080;
    pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;
    pub const CLONE_INTO_CGROUP: u64 = 0x200000000;
}

/// clone3 args structure
#[repr(C)]
pub struct Clone3Args {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,           // Pointer to array of pid_t
    pub set_tid_size: u64,
    pub cgroup: u64,            // For CLONE_INTO_CGROUP
}

// ============================================================================
// PID Namespace
// ============================================================================

/// PID namespace descriptor
#[repr(C)]
pub struct PidNamespace {
    pub level: u32,              // Nesting level (0 = init)
    pub nr_pids: u64,           // Number of PIDs allocated
    pub nr_hashed: u64,         // PIDs in hash table
    pub pid_allocated: u64,     // Total PIDs ever allocated
    pub pid_max: u32,           // Max PID in this ns (default 32768)
    pub last_pid: u32,          // Last allocated PID
    pub hide_pid: HidePidMode,  // hidepid mount option
    pub reboot: RebootMode,     // What happens on ns exit
    /// User namespace
    pub user_ns_id: u64,
    /// Parent PID ns
    pub parent_id: u64,
    /// Proc mount options
    pub proc_pid_nlink: bool,
    pub proc_subset: ProcSubset,
}

/// hidepid modes for /proc
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidePidMode {
    Off = 0,
    NoPtrace = 1,      // Invisible to non-ptrace-ers
    Invisible = 2,      // Invisible to everyone
    NotOwned = 4,       // Subset of 2 + stat
}

/// /proc subset mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcSubset {
    All = 0,
    Pid = 1,            // Only /proc/[pid] entries
}

/// Reboot behavior after last process exits
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootMode {
    Normal = 0,
    SignalParent = 1,
}

// ============================================================================
// User Namespace
// ============================================================================

/// User namespace descriptor
#[repr(C)]
pub struct UserNamespace {
    pub level: u32,              // Nesting level
    pub owner_uid: u32,          // UID of creator in parent ns
    pub owner_gid: u32,          // GID of creator in parent ns
    pub nr_uid_mappings: u32,
    pub nr_gid_mappings: u32,
    pub nr_projid_mappings: u32,
    /// UID mappings
    pub uid_map: [IdMapping; 340],
    pub uid_map_count: u32,
    /// GID mappings
    pub gid_map: [IdMapping; 340],
    pub gid_map_count: u32,
    /// Project ID mappings
    pub projid_map: [IdMapping; 340],
    pub projid_map_count: u32,
    /// Flags
    pub flags: UserNsFlags,
    /// Stats
    pub nr_processes: u64,
    pub nr_threads: u64,
    pub nr_open_files: u64,
    /// Parent ns
    pub parent_id: u64,
}

/// ID mapping entry
#[repr(C)]
pub struct IdMapping {
    pub first: u32,              // First ID in this ns
    pub lower_first: u32,        // First ID in parent ns
    pub count: u32,              // Number of IDs mapped
}

/// User namespace flags
pub struct UserNsFlags;
impl UserNsFlags {
    pub const USERNS_SETGROUPS_ALLOWED: u32 = 1 << 0;
    pub const USERNS_INIT_FLAGS: u32 = Self::USERNS_SETGROUPS_ALLOWED;
}

// ============================================================================
// Mount Namespace
// ============================================================================

/// Mount namespace descriptor
#[repr(C)]
pub struct MountNamespace {
    pub nr_mounts: u64,
    pub max_mounts: u64,         // sysctl limit
    pub pending_mounts: u32,
    /// Propagation stats
    pub nr_shared: u32,
    pub nr_slave: u32,
    pub nr_private: u32,
    pub nr_unbindable: u32,
    /// User ns
    pub user_ns_id: u64,
    /// Mount tree root
    pub root_mnt_id: u64,
}

/// Mount propagation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountPropagation {
    Private = 0,
    Shared = 1 << 20,           // MS_SHARED
    Slave = 1 << 19,            // MS_SLAVE
    Unbindable = 1 << 17,       // MS_UNBINDABLE
}

/// Mount flags (MS_*)
pub struct MountFlags;
impl MountFlags {
    pub const MS_RDONLY: u64 = 1;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_SYNCHRONOUS: u64 = 16;
    pub const MS_REMOUNT: u64 = 32;
    pub const MS_MANDLOCK: u64 = 64;
    pub const MS_DIRSYNC: u64 = 128;
    pub const MS_NOSYMFOLLOW: u64 = 256;
    pub const MS_NOATIME: u64 = 1024;
    pub const MS_NODIRATIME: u64 = 2048;
    pub const MS_BIND: u64 = 4096;
    pub const MS_MOVE: u64 = 8192;
    pub const MS_REC: u64 = 16384;
    pub const MS_SILENT: u64 = 32768;
    pub const MS_POSIXACL: u64 = 1 << 16;
    pub const MS_UNBINDABLE: u64 = 1 << 17;
    pub const MS_PRIVATE: u64 = 1 << 18;
    pub const MS_SLAVE: u64 = 1 << 19;
    pub const MS_SHARED: u64 = 1 << 20;
    pub const MS_RELATIME: u64 = 1 << 21;
    pub const MS_KERNMOUNT: u64 = 1 << 22;
    pub const MS_I_VERSION: u64 = 1 << 23;
    pub const MS_STRICTATIME: u64 = 1 << 24;
    pub const MS_LAZYTIME: u64 = 1 << 25;
    pub const MS_NOSEC: u64 = 1 << 28;
    pub const MS_BORN: u64 = 1 << 29;
    pub const MS_ACTIVE: u64 = 1 << 30;
    pub const MS_NOUSER: u64 = 1 << 31;
}

/// mount_setattr flags (new mount API)
pub struct MountAttrFlags;
impl MountAttrFlags {
    pub const MOUNT_ATTR_RDONLY: u64 = 0x00000001;
    pub const MOUNT_ATTR_NOSUID: u64 = 0x00000002;
    pub const MOUNT_ATTR_NODEV: u64 = 0x00000004;
    pub const MOUNT_ATTR_NOEXEC: u64 = 0x00000008;
    pub const MOUNT_ATTR__ATIME: u64 = 0x00000070;
    pub const MOUNT_ATTR_RELATIME: u64 = 0x00000000;
    pub const MOUNT_ATTR_NOATIME: u64 = 0x00000010;
    pub const MOUNT_ATTR_STRICTATIME: u64 = 0x00000020;
    pub const MOUNT_ATTR_NODIRATIME: u64 = 0x00000080;
    pub const MOUNT_ATTR_IDMAP: u64 = 0x00100000;
    pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x00200000;
}

// ============================================================================
// Network Namespace
// ============================================================================

/// Network namespace descriptor
#[repr(C)]
pub struct NetNamespace {
    pub id: u64,
    pub ifindex_max: u32,
    /// Device counts
    pub nr_net_devices: u32,
    pub nr_loopback: u32,
    pub nr_veth: u32,
    pub nr_bridge: u32,
    pub nr_vlan: u32,
    /// Socket counts
    pub nr_sockets: u64,
    pub nr_tcp_sockets: u64,
    pub nr_udp_sockets: u64,
    pub nr_unix_sockets: u64,
    /// Routing
    pub nr_routes: u64,
    pub nr_fib_rules: u32,
    /// Netfilter
    pub nr_nf_hooks: u32,
    pub nr_conntrack_entries: u64,
    pub conntrack_max: u64,
    /// Network config
    pub ip_forward: bool,
    pub ipv6_forward: bool,
    /// User ns
    pub user_ns_id: u64,
    /// Sysctl overrides
    pub net_sysctl_overrides: u32,
}

// ============================================================================
// UTS Namespace
// ============================================================================

/// UTS namespace descriptor
#[repr(C)]
pub struct UtsNamespace {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
    pub user_ns_id: u64,
}

// ============================================================================
// IPC Namespace
// ============================================================================

/// IPC namespace descriptor
#[repr(C)]
pub struct IpcNamespace {
    /// SysV IPC limits
    pub shm_ctlmax: u64,     // SHMMAX
    pub shm_ctlall: u64,     // SHMALL
    pub shm_ctlmni: u32,     // SHMMNI
    pub shm_rmid_forced: bool,
    pub msg_ctlmax: u32,     // MSGMAX
    pub msg_ctlmnb: u32,     // MSGMNB
    pub msg_ctlmni: u32,     // MSGMNI
    pub sem_ctls_semmsl: u32,
    pub sem_ctls_semmns: u32,
    pub sem_ctls_semopm: u32,
    pub sem_ctls_semmni: u32,
    /// POSIX MQ limits
    pub mq_queues_max: u32,
    pub mq_msg_max: u32,
    pub mq_msgsize_max: u32,
    pub mq_msg_default: u32,
    pub mq_msgsize_default: u32,
    /// Current usage
    pub nr_shm_segments: u32,
    pub nr_msg_queues: u32,
    pub nr_sem_sets: u32,
    pub nr_mq_queues: u32,
    /// User ns
    pub user_ns_id: u64,
}

// ============================================================================
// Cgroup Namespace
// ============================================================================

/// Cgroup namespace descriptor  
#[repr(C)]
pub struct CgroupNamespace {
    /// Root cgroup (visible to this ns)
    pub root_cgrp_id: u64,
    /// User ns
    pub user_ns_id: u64,
    /// Stats
    pub nr_cgroups: u32,
    pub nr_css_sets: u32,
}

// ============================================================================
// Time Namespace
// ============================================================================

/// Time namespace descriptor
#[repr(C)]
pub struct TimeNamespace {
    /// Clock offsets
    pub monotonic_offset_sec: i64,
    pub monotonic_offset_nsec: i64,
    pub boottime_offset_sec: i64,
    pub boottime_offset_nsec: i64,
    /// User ns
    pub user_ns_id: u64,
    /// Frozen (for checkpoint/restore)
    pub frozen: bool,
}

// ============================================================================
// Namespace Operations
// ============================================================================

/// setns flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetnsType {
    Mnt = 0x00020000,
    Cgroup = 0x02000000,
    Uts = 0x04000000,
    Ipc = 0x08000000,
    User = 0x10000000,
    Pid = 0x20000000,
    Net = 0x40000000,
    Time = 0x00000080,
}

/// Namespace proc file info
#[repr(C)]
pub struct NsProcInfo {
    pub ns_type: NsType,
    pub inum: u64,           // Inode number of /proc/[pid]/ns/*
    pub dev: u64,            // Device number
    pub userns_inum: u64,    // Owner user namespace inode
}

// ============================================================================
// Subsystem Manager
// ============================================================================

pub struct NamespaceSubsystem {
    /// PID NS
    pub nr_pid_namespaces: u32,
    pub max_pid_ns_level: u32,
    /// User NS
    pub nr_user_namespaces: u32,
    pub max_user_ns_level: u32,
    /// Mount NS
    pub nr_mnt_namespaces: u32,
    pub total_mnt_operations: u64,
    /// Net NS
    pub nr_net_namespaces: u32,
    /// UTS NS
    pub nr_uts_namespaces: u32,
    /// IPC NS
    pub nr_ipc_namespaces: u32,
    /// Cgroup NS
    pub nr_cgroup_namespaces: u32,
    /// Time NS
    pub nr_time_namespaces: u32,
    /// Total
    pub total_ns_creates: u64,
    pub total_ns_destroys: u64,
    pub total_setns_calls: u64,
    pub total_unshare_calls: u64,
    /// Zxyphor
    pub zxy_fast_ns_switch: bool,
    pub zxy_ns_checkpointing: bool,
    pub initialized: bool,
}

impl NamespaceSubsystem {
    pub fn new() -> Self {
        Self {
            nr_pid_namespaces: 1,
            max_pid_ns_level: 32,
            nr_user_namespaces: 1,
            max_user_ns_level: 32,
            nr_mnt_namespaces: 1,
            total_mnt_operations: 0,
            nr_net_namespaces: 1,
            nr_uts_namespaces: 1,
            nr_ipc_namespaces: 1,
            nr_cgroup_namespaces: 1,
            nr_time_namespaces: 1,
            total_ns_creates: 0,
            total_ns_destroys: 0,
            total_setns_calls: 0,
            total_unshare_calls: 0,
            zxy_fast_ns_switch: true,
            zxy_ns_checkpointing: true,
            initialized: false,
        }
    }
}
