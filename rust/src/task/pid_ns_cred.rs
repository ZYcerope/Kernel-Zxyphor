// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust PID Namespace, Credentials & Capabilities
// Complete: PID namespaces, task credentials, Linux capabilities,
// user namespaces, security contexts, capability sets

use core::fmt;

// ============================================================================
// Capabilities
// ============================================================================

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_BROADCAST: u32 = 11;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;
pub const CAP_SYS_MODULE: u32 = 16;
pub const CAP_SYS_RAWIO: u32 = 17;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_PACCT: u32 = 20;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_LEASE: u32 = 28;
pub const CAP_AUDIT_WRITE: u32 = 29;
pub const CAP_AUDIT_CONTROL: u32 = 30;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_MAC_ADMIN: u32 = 33;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_WAKE_ALARM: u32 = 35;
pub const CAP_BLOCK_SUSPEND: u32 = 36;
pub const CAP_AUDIT_READ: u32 = 37;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;
pub const CAP_LAST_CAP: u32 = 40;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KernelCapStruct {
    pub cap: [u32; 2],    // 64-bit capability set
}

impl KernelCapStruct {
    pub const fn empty() -> Self {
        Self { cap: [0, 0] }
    }

    pub const fn full() -> Self {
        Self {
            cap: [0xFFFFFFFF, (1u32 << (CAP_LAST_CAP - 31)) - 1],
        }
    }

    pub fn has_cap(&self, cap: u32) -> bool {
        if cap > CAP_LAST_CAP {
            return false;
        }
        let idx = (cap / 32) as usize;
        let bit = cap % 32;
        (self.cap[idx] & (1 << bit)) != 0
    }

    pub fn raise_cap(&mut self, cap: u32) {
        if cap <= CAP_LAST_CAP {
            let idx = (cap / 32) as usize;
            let bit = cap % 32;
            self.cap[idx] |= 1 << bit;
        }
    }

    pub fn drop_cap(&mut self, cap: u32) {
        if cap <= CAP_LAST_CAP {
            let idx = (cap / 32) as usize;
            let bit = cap % 32;
            self.cap[idx] &= !(1 << bit);
        }
    }
}

// ============================================================================
// Credentials
// ============================================================================

#[repr(C)]
pub struct Cred {
    pub usage: i32,
    pub uid: u32,          // real UID
    pub gid: u32,          // real GID
    pub suid: u32,         // saved UID
    pub sgid: u32,         // saved GID
    pub euid: u32,         // effective UID
    pub egid: u32,         // effective GID
    pub fsuid: u32,        // FS UID
    pub fsgid: u32,        // FS GID
    pub securebits: u32,
    pub cap_inheritable: KernelCapStruct,
    pub cap_permitted: KernelCapStruct,
    pub cap_effective: KernelCapStruct,
    pub cap_bset: KernelCapStruct,
    pub cap_ambient: KernelCapStruct,
    pub jit_keyring: u8,
    pub session_keyring: u64,   // key handle
    pub process_keyring: u64,
    pub thread_keyring: u64,
    pub request_key_auth: u64,
    pub security: u64,          // LSM security pointer
    pub user_ns: u64,           // user_namespace pointer
    pub group_info: u64,        // group_info pointer
    pub non_rcu: u32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SecureBit {
    NoRoot = 0,
    NoRootLocked = 1,
    NoSetuidFixup = 2,
    NoSetuidFixupLocked = 3,
    KeepCaps = 4,
    KeepCapsLocked = 5,
    NoCapAmbientRaise = 6,
    NoCapAmbientRaiseLocked = 7,
}

pub const SECUREBITS_DEFAULT: u32 = 0x00000000;

// ============================================================================
// User Namespace
// ============================================================================

#[repr(C)]
pub struct UserNamespace {
    pub parent: u64,         // parent user_namespace
    pub level: u32,
    pub owner: u32,          // kuid of creator
    pub group: u32,          // kgid of creator
    pub ns: NsCommon,
    pub flags: UserNsFlags,
    pub uid_map: UidGidMap,
    pub gid_map: UidGidMap,
    pub projid_map: UidGidMap,
    pub keyring: u64,
    pub persistent_keyring: u64,
    pub ucounts: u64,
    pub ucount_max: [i64; 16],
    pub rlimit_max: [u64; 16],
    pub binfmt_misc: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserNsFlags {
    pub flags: u32,
}

pub const USERNS_SETGROUPS_ALLOWED: u32 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UidGidExtent {
    pub first: u32,
    pub lower_first: u32,
    pub count: u32,
}

#[repr(C)]
pub struct UidGidMap {
    pub nr_extents: u32,
    pub extents: [UidGidExtent; 340],  // UID_GID_MAP_MAX_EXTENTS
}

// ============================================================================
// PID Namespace
// ============================================================================

#[repr(C)]
pub struct PidNamespace {
    pub ns: NsCommon,
    pub pidmap: [PidMap; 1],
    pub rcu: u64,
    pub pid_allocated: u32,
    pub child_reaper: u64,    // task_struct pointer
    pub pid_cachep: u64,
    pub level: u32,
    pub parent: u64,          // parent pid_namespace
    pub bacct: u64,           // bsd accounting
    pub user_ns: u64,
    pub ucounts: u64,
    pub reboot: i32,
    pub memfd_noexec_scope: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PidMap {
    pub nr_free: u32,
    pub page: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NsCommon {
    pub stashed: u64,
    pub ops: u64,           // ns_operations pointer
    pub inum: u32,
    pub count: u64,         // refcount
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NsType {
    Mnt = 0x00020000,
    Cgroup = 0x02000000,
    Uts = 0x04000000,
    Ipc = 0x08000000,
    User = 0x10000000,
    Pid = 0x20000000,
    Net = 0x40000000,
    Time = 0x80000000,
}

// ============================================================================
// PID Structure
// ============================================================================

#[repr(C)]
pub struct Pid {
    pub count: i32,
    pub level: u32,
    pub stashed: u64,
    pub rcu: u64,
    pub numbers: [Upid; 4],  // MAX_PID_NS_LEVEL = 32, using 4 for common case
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Upid {
    pub nr: i32,
    pub ns: u64,            // pid_namespace pointer
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PidType {
    Pid = 0,
    Tgid = 1,
    Pgid = 2,
    Sid = 3,
    Max = 4,
}

// ============================================================================
// Group Info
// ============================================================================

#[repr(C)]
pub struct GroupInfo {
    pub usage: i32,
    pub ngroups: i32,
    pub small_block: [u32; 32],
    pub blocks: [u64; 16],     // pages with gid_t arrays
}

// ============================================================================
// Resource Limits
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RlimitResource {
    Cpu = 0,
    Fsize = 1,
    Data = 2,
    Stack = 3,
    Core = 4,
    Rss = 5,
    Nproc = 6,
    Nofile = 7,
    Memlock = 8,
    As = 9,
    Locks = 10,
    Sigpending = 11,
    Msgqueue = 12,
    Nice = 13,
    Rtprio = 14,
    Rttime = 15,
}

pub const RLIM_NLIMITS: u32 = 16;
pub const RLIM_INFINITY: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rlimit {
    pub rlim_cur: u64,    // soft limit
    pub rlim_max: u64,    // hard limit
}

pub struct TaskRlimits {
    pub limits: [Rlimit; RLIM_NLIMITS as usize],
}

impl TaskRlimits {
    pub const fn default_init() -> Self {
        Self {
            limits: [Rlimit {
                rlim_cur: RLIM_INFINITY,
                rlim_max: RLIM_INFINITY,
            }; RLIM_NLIMITS as usize],
        }
    }
}

// ============================================================================
// UCounts (User namespace resource limits)
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
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
    Counts = 16,
}

#[repr(C)]
pub struct Ucounts {
    pub ns: u64,            // user_namespace pointer
    pub uid: u32,
    pub count: i32,
    pub ucount: [i64; 16],
}

// ============================================================================
// Security Context
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LsmId {
    Unspecified = 0,
    Selinux = 1,
    Smack = 2,
    Tomoyo = 3,
    Apparmor = 4,
    Yama = 5,
    Loadpin = 6,
    Safesetid = 7,
    Lockdown = 8,
    Bpf = 9,
    Landlock = 10,
    Ima = 11,
    Evm = 12,
}

pub struct TaskSecurityContext {
    pub lsm_id: LsmId,
    pub label: [u8; 256],
    pub label_len: u32,
    pub sid: u32,           // Security ID
    pub exec_sid: u32,
    pub create_sid: u32,
    pub keycreate_sid: u32,
    pub sockcreate_sid: u32,
}

// ============================================================================
// Statistics
// ============================================================================

pub struct PidNsCredStats {
    pub total_pid_namespaces: u64,
    pub total_user_namespaces: u64,
    pub total_cred_clones: u64,
    pub total_cap_raises: u64,
    pub total_cap_drops: u64,
    pub total_setuid: u64,
    pub total_setgid: u64,
    pub total_ns_creates: u64,
    pub total_ns_destroys: u64,
}

impl PidNsCredStats {
    pub const fn new() -> Self {
        Self {
            total_pid_namespaces: 0,
            total_user_namespaces: 0,
            total_cred_clones: 0,
            total_cap_raises: 0,
            total_cap_drops: 0,
            total_setuid: 0,
            total_setgid: 0,
            total_ns_creates: 0,
            total_ns_destroys: 0,
        }
    }
}
