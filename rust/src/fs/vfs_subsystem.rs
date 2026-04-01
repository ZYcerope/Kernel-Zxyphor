// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Rust Filesystem Advanced Subsystem
// VFS operations, mount API, file locking, page cache interface,
// filesystem freeze/thaw, quota, ACL, xattr, io_uring fs ops
// More advanced than Linux 2026 VFS

use core::fmt;

// ============================================================================
// Filesystem Types Registry
// ============================================================================

pub const FS_MAX_TYPES: usize = 128;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FsMagic {
    Ext2 = 0xEF53,
    Ext4 = 0xEF53,       // Same as ext2
    Xfs = 0x58465342,
    Btrfs = 0x9123683E,
    F2fs = 0xF2F52010,
    Tmpfs = 0x01021994,
    Devtmpfs = 0x01021994,
    Procfs = 0x9FA0,
    Sysfs = 0x62656572,
    Debugfs = 0x64626720,
    Securityfs = 0x73636673,
    Tracefs = 0x74726163,
    Hugetlbfs = 0x958458F6,
    Cgroup2 = 0x63677270,
    Pstore = 0x6165676C,
    BpfFs = 0xCAFE4A11,
    Overlayfs = 0x794C7630,
    Fuse = 0x65735546,
    Nfs = 0x6969,
    Cifs = 0xFF534D42,
    Fat = 0x4D44,
    Exfat = 0x2011BAB0,
    Ntfs = 0x5346544E,
    Iso9660 = 0x9660,
    Udf = 0x15013346,
    Squashfs = 0x73717368,
    Erofs = 0xE0F5E1E2,
    Bcachefs = 0xCA451A4E,
    // Zxyphor
    ZxyFs = 0x5A585946,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum FsTypeFlag {
    RequiresDev = 1,
    Binary = 2,         // Binary mountdata
    HasSubtype = 4,
    Userns = 8,
    Disallow = 16,
    Rename = 32,
    AllowIdmap = 64,
}

#[derive(Debug, Clone)]
pub struct FileSystemType {
    pub name: [u8; 32],
    pub name_len: u8,
    pub fs_flags: u32,
    pub magic: u32,
    // Module owner
    pub owner: u32,
    // Superblock management
    pub init_fs_context: u64,   // fn pointer
    pub parameters: [FsParameter; 64],
    pub nr_parameters: u32,
    // Kill superblock
    pub kill_sb: u64,
    // Stats
    pub mount_count: u64,
}

#[derive(Debug, Clone)]
pub struct FsParameter {
    pub name: [u8; 32],
    pub name_len: u8,
    pub param_type: FsParamType,
    pub opt: u32,
    pub flags: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FsParamType {
    Flag = 0,
    Bool = 1,
    U32 = 2,
    U32Oct = 3,
    U32Hex = 4,
    S32 = 5,
    U64 = 6,
    Enum = 7,
    String = 8,
    Blob = 9,
    Blockdev = 10,
    Path = 11,
    Fd = 12,
}

// ============================================================================
// New Mount API (fsopen/fsmount/move_mount)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FsContextPhase {
    Free = 0,
    CreateParams = 1,
    CreateSuper = 2,
    Reconfigure = 3,
    Reconf = 4,
    Failed = 5,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FsContextPurpose {
    Mount = 0,
    Submount = 1,
    Remount = 2,
}

pub struct FsContext {
    pub phase: FsContextPhase,
    pub purpose: FsContextPurpose,
    pub fs_type: u32,    // Index into fs types
    pub source: [u8; 256],
    pub source_len: u16,
    // Parameters collected
    pub params: [MountParam; 128],
    pub nr_params: u32,
    // Superblock flags
    pub sb_flags: u32,
    pub sb_flags_mask: u32,
    // Security
    pub security_ctx: u64,
    // Credentials
    pub cred_uid: u32,
    pub cred_gid: u32,
    // Namespace
    pub user_ns: u64,
    pub net_ns: u64,
    pub mnt_ns: u64,
    // Log
    pub log_buf: [u8; 4096],
    pub log_len: u32,
}

pub struct MountParam {
    pub key: [u8; 64],
    pub key_len: u8,
    pub value: [u8; 256],
    pub value_len: u16,
    pub param_type: FsParamType,
}

// Mount flags
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
pub const MS_SUBMOUNT: u64 = 1 << 26;
pub const MS_NOREMOTELOCK: u64 = 1 << 27;
pub const MS_NOSEC: u64 = 1 << 28;
pub const MS_BORN: u64 = 1 << 29;
pub const MS_ACTIVE: u64 = 1 << 30;
pub const MS_NOUSER: u64 = 1 << 31;

// ============================================================================
// File Locking
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileLockType {
    None = 0,
    ReadLock = 1,    // F_RDLCK
    WriteLock = 2,   // F_WRLCK
    Unlock = 3,      // F_UNLCK
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FileLockKind {
    Posix = 0,       // fcntl F_SETLK/F_SETLKW
    Flock = 1,       // flock()
    Lease = 2,       // F_SETLEASE
    Ofd = 3,         // Open file description locks (F_OFD_*)
}

#[derive(Debug, Clone)]
pub struct FileLock {
    pub lock_type: FileLockType,
    pub kind: FileLockKind,
    pub start: u64,
    pub end: u64,      // 0 = EOF
    pub pid: u32,
    pub fd: i32,
    pub flags: u32,
    // Blocking
    pub blocking: bool,
    pub wait_queue: u64,
    // Deadlock detection
    pub owner: u64,
}

#[derive(Debug, Clone)]
pub struct FileLease {
    pub lease_type: FileLockType,
    pub breaker: u32,     // PID of lease breaker
    pub break_time: u64,
    pub downgrade: bool,
}

pub struct FileLockManager {
    pub posix_locks: [FileLock; 4096],
    pub nr_posix: u32,
    pub flock_locks: [FileLock; 1024],
    pub nr_flock: u32,
    pub leases: [FileLease; 512],
    pub nr_leases: u32,
    pub lease_break_time: u32,  // seconds
    pub locks_limit: u64,
    // Stats
    pub posix_lock_count: u64,
    pub flock_count: u64,
    pub lease_count: u64,
    pub deadlocks_detected: u64,
    pub lock_waits: u64,
}

// ============================================================================
// Disk Quota
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QuotaType {
    User = 0,
    Group = 1,
    Project = 2,
}

#[derive(Debug, Clone)]
pub struct DiskQuota {
    pub dqb_bhardlimit: u64,  // Absolute block hard limit
    pub dqb_bsoftlimit: u64,  // Preferred block limit
    pub dqb_curspace: u64,     // Current space used (bytes)
    pub dqb_ihardlimit: u64,  // Absolute inode hard limit
    pub dqb_isoftlimit: u64,  // Preferred inode limit
    pub dqb_curinodes: u64,   // Current inodes
    pub dqb_btime: u64,       // Time limit for excessive use (blocks)
    pub dqb_itime: u64,       // Time limit for excessive use (inodes)
    pub dqb_valid: u32,
}

pub struct QuotaInfo {
    pub quota_type: QuotaType,
    pub dqi_bgrace: u64,      // Default block grace period
    pub dqi_igrace: u64,      // Default inode grace period
    pub dqi_max_spc_limit: u64,
    pub dqi_max_ino_limit: u64,
    pub dqi_flags: u32,
    pub dqi_valid: u32,
}

pub struct QuotaManager {
    pub enabled: [bool; 3],    // Per quota type
    pub enforced: [bool; 3],
    pub quotas: [DiskQuota; 8192],
    pub nr_quotas: u32,
    // Per-type info
    pub info: [QuotaInfo; 3],
    // Stats
    pub syncs: u64,
    pub warnings_issued: u64,
    pub over_limit_count: u64,
}

// ============================================================================
// POSIX ACLs
// ============================================================================

pub const ACL_MAX_ENTRIES: usize = 32;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AclTag {
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

#[derive(Debug, Clone)]
pub struct AclEntry {
    pub tag: AclTag,
    pub perm: u16,     // rwx (4|2|1)
    pub id: u32,       // UID or GID (for USER/GROUP tags)
}

#[derive(Debug, Clone)]
pub struct PosixAcl {
    pub entries: [AclEntry; ACL_MAX_ENTRIES],
    pub count: u32,
    pub version: u32,
}

impl PosixAcl {
    pub fn check_permission(&self, uid: u32, gid: u32, want: u16) -> bool {
        // Check USER_OBJ first
        for entry in &self.entries[..self.count as usize] {
            match entry.tag {
                AclTag::UserObj => {
                    // Owner check is done by caller
                }
                AclTag::User => {
                    if entry.id == uid {
                        return (entry.perm & want) == want;
                    }
                }
                AclTag::GroupObj => {
                    // Group check
                }
                AclTag::Group => {
                    if entry.id == gid {
                        return (entry.perm & want) == want;
                    }
                }
                AclTag::Other => {
                    return (entry.perm & want) == want;
                }
                _ => {}
            }
        }
        false
    }
}

// ============================================================================
// Extended Attributes (xattr)
// ============================================================================

pub const XATTR_MAX_NAME_LEN: usize = 255;
pub const XATTR_MAX_VALUE_SIZE: usize = 65536;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XattrNamespace {
    User = 0,
    System = 1,
    Trusted = 2,
    Security = 3,
}

#[derive(Debug, Clone)]
pub struct Xattr {
    pub namespace: XattrNamespace,
    pub name: [u8; XATTR_MAX_NAME_LEN],
    pub name_len: u8,
    pub value: [u8; 4096],   // Inline value
    pub value_len: u32,
    pub flags: u32,
}

// Common xattr names
pub const XATTR_NAME_POSIX_ACL_ACCESS: &[u8] = b"system.posix_acl_access";
pub const XATTR_NAME_POSIX_ACL_DEFAULT: &[u8] = b"system.posix_acl_default";
pub const XATTR_NAME_SELINUX: &[u8] = b"security.selinux";
pub const XATTR_NAME_SMACK: &[u8] = b"security.SMACK64";
pub const XATTR_NAME_CAPS: &[u8] = b"security.capability";
pub const XATTR_NAME_IMA: &[u8] = b"security.ima";
pub const XATTR_NAME_EVM: &[u8] = b"security.evm";

// ============================================================================
// Filesystem Freeze/Thaw
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FsFreezeState {
    Unfrozen = 0,
    WriteFreeze = 1,
    PageFault = 2,
    Frozen = 3,
}

pub struct FsFreeze {
    pub state: FsFreezeState,
    pub freeze_count: u32,
    pub freeze_holders: u32,
    // Timing
    pub freeze_start: u64,
    pub total_frozen_time_ms: u64,
    // Stats
    pub freeze_count_total: u64,
    pub thaw_count_total: u64,
}

// ============================================================================
// Writeback Control
// ============================================================================

pub struct WritebackControl {
    pub nr_to_write: i64,
    pub pages_skipped: i64,
    // Range
    pub range_start: u64,
    pub range_end: u64,
    // Writeback reason
    pub reason: WritebackReason,
    // Flags
    pub for_kupdate: bool,
    pub for_background: bool,
    pub tagged_writepages: bool,
    pub for_reclaim: bool,
    pub range_cyclic: bool,
    pub for_sync: bool,
    pub unpinned_fscache_wb: bool,
    pub no_cgroup_owner: bool,
    pub punt_to_cgroup: bool,
    // Sync mode
    pub sync_mode: WritebackSyncMode,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum WritebackReason {
    Background = 0,
    Vmscan = 1,
    Sync = 2,
    Periodic = 3,
    LaptopTimer = 4,
    FreeMoreMem = 5,
    FsFreeMem = 6,
    Fork = 7,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum WritebackSyncMode {
    None = 0,
    Normal = 1,
    All = 2,
}

// ============================================================================
// io_uring filesystem operations
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IoUringFsOp {
    Open = 0,
    Close = 1,
    Read = 2,
    Write = 3,
    Fsync = 4,
    Ftruncate = 5,
    Fadvise = 6,
    Fallocate = 7,
    Openat = 8,
    Statx = 9,
    Unlink = 10,
    Rename = 11,
    Mkdir = 12,
    Symlink = 13,
    Link = 14,
    Splice = 15,
    Tee = 16,
    Getxattr = 17,
    Setxattr = 18,
    // Zxyphor extensions
    ZxyBatchRead = 200,
    ZxyAtomicWrite = 201,
}

// ============================================================================
// Filesystem Notification (fanotify/inotify)
// ============================================================================

pub const FAN_ACCESS: u64 = 0x00000001;
pub const FAN_MODIFY: u64 = 0x00000002;
pub const FAN_ATTRIB: u64 = 0x00000004;
pub const FAN_CLOSE_WRITE: u64 = 0x00000008;
pub const FAN_CLOSE_NOWRITE: u64 = 0x00000010;
pub const FAN_OPEN: u64 = 0x00000020;
pub const FAN_MOVED_FROM: u64 = 0x00000040;
pub const FAN_MOVED_TO: u64 = 0x00000080;
pub const FAN_CREATE: u64 = 0x00000100;
pub const FAN_DELETE: u64 = 0x00000200;
pub const FAN_DELETE_SELF: u64 = 0x00000400;
pub const FAN_MOVE_SELF: u64 = 0x00000800;
pub const FAN_OPEN_EXEC: u64 = 0x00001000;
pub const FAN_Q_OVERFLOW: u64 = 0x00004000;
pub const FAN_FS_ERROR: u64 = 0x00008000;
pub const FAN_OPEN_PERM: u64 = 0x00010000;
pub const FAN_ACCESS_PERM: u64 = 0x00020000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x08000000;
pub const FAN_RENAME: u64 = 0x10000000;
pub const FAN_ONDIR: u64 = 0x40000000;

#[derive(Debug, Clone)]
pub struct FanotifyEvent {
    pub mask: u64,
    pub fd: i32,
    pub pid: u32,
    // File identification
    pub fid: [u8; 128],
    pub fid_len: u8,
    pub name: [u8; 256],
    pub name_len: u16,
    // Timestamp
    pub timestamp: u64,
}

pub struct FanotifyGroup {
    pub flags: u32,
    pub event_f_flags: u32,
    pub max_events: u32,
    pub marks: [FanotifyMark; 4096],
    pub nr_marks: u32,
    pub events: [FanotifyEvent; 16384],
    pub event_head: u32,
    pub event_tail: u32,
    // Priority
    pub priority: u32,
    // Stats
    pub overflow_count: u64,
    pub permission_events: u64,
}

#[derive(Debug, Clone)]
pub struct FanotifyMark {
    pub mask: u64,
    pub ignored_mask: u64,
    pub flags: u32,
    pub inode: u64,
    pub mount_id: u32,
    pub filesystem: bool,
}

// ============================================================================
// Filesystem Subsystem Manager
// ============================================================================

pub struct VfsSubsystem {
    // Registered filesystem types
    pub fs_types: [Option<FileSystemType>; FS_MAX_TYPES],
    pub nr_fs_types: u32,
    // Mount table
    pub nr_mounts: u64,
    // File lock manager
    pub lock_mgr: FileLockManager,
    // Quota
    pub quota_mgr: QuotaManager,
    // Fanotify groups
    pub fanotify_groups: [Option<FanotifyGroup>; 32],
    pub nr_fanotify_groups: u32,
    // Global stats
    pub total_opens: u64,
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_lookups: u64,
    pub total_creates: u64,
    pub total_unlinks: u64,
    pub total_renames: u64,
    // Limits
    pub max_file_size: u64,
    pub file_max: u64,         // Max open files system-wide
    pub file_nr: u64,          // Current open files
    // Initialized
    pub initialized: bool,
}
