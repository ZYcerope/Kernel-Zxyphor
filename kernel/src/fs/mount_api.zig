// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Filesystem Mount API, mount_setattr,
// fsconfig/fsmount/fsopen/fspick, Bind Mounts,
// Mount Propagation (shared/slave/private/unbindable),
// Super Block Operations, Filesystem Registration
// More advanced than Linux 2026 mount subsystem

const std = @import("std");

// ============================================================================
// New Mount API (fsopen/fsconfig/fsmount)
// ============================================================================

/// fsopen flags
pub const FsOpenFlags = packed struct(u32) {
    cloexec: bool = false,
    _padding: u31 = 0,
};

/// fsconfig command
pub const FsConfigCmd = enum(u32) {
    set_flag = 0,           // FSCONFIG_SET_FLAG
    set_string = 1,         // FSCONFIG_SET_STRING
    set_binary = 2,         // FSCONFIG_SET_BINARY
    set_path = 3,           // FSCONFIG_SET_PATH
    set_path_empty = 4,     // FSCONFIG_SET_PATH_EMPTY
    set_fd = 5,             // FSCONFIG_SET_FD
    cmd_create = 6,         // FSCONFIG_CMD_CREATE
    cmd_reconfigure = 7,    // FSCONFIG_CMD_RECONFIGURE
    cmd_create_excl = 8,    // FSCONFIG_CMD_CREATE_EXCL
};

/// fsmount flags
pub const FsMountFlags = packed struct(u32) {
    cloexec: bool = false,
    _padding: u31 = 0,
};

/// fsmount attr flags
pub const FsMountAttrFlags = packed struct(u64) {
    rdonly: bool = false,         // MOUNT_ATTR_RDONLY
    nosuid: bool = false,         // MOUNT_ATTR_NOSUID
    nodev: bool = false,          // MOUNT_ATTR_NODEV
    noexec: bool = false,         // MOUNT_ATTR_NOEXEC
    noatime: bool = false,        // MOUNT_ATTR__ATIME (MOUNT_ATTR_NOATIME)
    relatime: bool = false,       // MOUNT_ATTR_RELATIME
    strictatime: bool = false,
    nodiratime: bool = false,     // MOUNT_ATTR_NODIRATIME
    idmap: bool = false,          // MOUNT_ATTR_IDMAP
    nosymfollow: bool = false,    // MOUNT_ATTR_NOSYMFOLLOW
    // Zxyphor
    zxy_encrypted: bool = false,
    zxy_verified: bool = false,
    _padding: u52 = 0,
};

/// fspick flags
pub const FsPickFlags = packed struct(u32) {
    cloexec: bool = false,
    symlink_nofollow: bool = false,
    no_automount: bool = false,
    empty_path: bool = false,
    _padding: u28 = 0,
};

// ============================================================================
// Mount Propagation
// ============================================================================

/// Mount propagation type
pub const MountPropagation = enum(u32) {
    none = 0,
    shared = 0x100000,       // MS_SHARED
    slave = 0x080000,        // MS_SLAVE
    private = 0x040000,      // MS_PRIVATE
    unbindable = 0x020000,   // MS_UNBINDABLE
};

/// Mount flags (classic MS_* flags)
pub const MountFlags = packed struct(u32) {
    rdonly: bool = false,        // MS_RDONLY
    nosuid: bool = false,        // MS_NOSUID
    nodev: bool = false,         // MS_NODEV
    noexec: bool = false,        // MS_NOEXEC
    synchronous: bool = false,   // MS_SYNCHRONOUS
    remount: bool = false,       // MS_REMOUNT
    mandlock: bool = false,      // MS_MANDLOCK
    dirsync: bool = false,       // MS_DIRSYNC
    nosymfollow: bool = false,   // MS_NOSYMFOLLOW
    noatime: bool = false,       // MS_NOATIME
    nodiratime: bool = false,    // MS_NODIRATIME
    bind: bool = false,          // MS_BIND
    move_mount: bool = false,    // MS_MOVE
    rec: bool = false,           // MS_REC
    silent: bool = false,        // MS_SILENT
    posixacl: bool = false,      // MS_POSIXACL
    unbindable: bool = false,    // MS_UNBINDABLE
    private: bool = false,       // MS_PRIVATE
    slave: bool = false,         // MS_SLAVE
    shared: bool = false,        // MS_SHARED
    relatime: bool = false,      // MS_RELATIME
    kernmount: bool = false,     // MS_KERNMOUNT
    i_version: bool = false,     // MS_I_VERSION
    strictatime: bool = false,   // MS_STRICTATIME
    lazytime: bool = false,      // MS_LAZYTIME
    _padding: u7 = 0,
};

/// move_mount flags
pub const MoveMountFlags = packed struct(u32) {
    f_symlinks: bool = false,      // MOVE_MOUNT_F_SYMLINKS
    f_automounts: bool = false,    // MOVE_MOUNT_F_AUTOMOUNTS
    f_empty_path: bool = false,    // MOVE_MOUNT_F_EMPTY_PATH
    t_symlinks: bool = false,      // MOVE_MOUNT_T_SYMLINKS
    t_automounts: bool = false,    // MOVE_MOUNT_T_AUTOMOUNTS
    t_empty_path: bool = false,    // MOVE_MOUNT_T_EMPTY_PATH
    set_group: bool = false,       // MOVE_MOUNT_SET_GROUP
    beneath: bool = false,         // MOVE_MOUNT_BENEATH
    _padding: u24 = 0,
};

/// open_tree flags
pub const OpenTreeFlags = packed struct(u32) {
    cloexec: bool = false,
    clone: bool = false,
    _padding: u30 = 0,
};

// ============================================================================
// mount_setattr
// ============================================================================

/// mount_setattr structure
pub const MountAttr = extern struct {
    attr_set: FsMountAttrFlags,
    attr_clr: FsMountAttrFlags,
    propagation: u64,
    userns_fd: u64,
};

/// Recursive mount flags
pub const AtRecursive: u32 = 0x8000;

// ============================================================================
// Superblock Operations
// ============================================================================

/// Superblock flags
pub const SuperBlockFlags = packed struct(u64) {
    rdonly: bool = false,
    nosuid: bool = false,
    nodev: bool = false,
    noexec: bool = false,
    synchronous: bool = false,
    mandlock: bool = false,
    dirsync: bool = false,
    noatime: bool = false,
    nodiratime: bool = false,
    posixacl: bool = false,
    lazytime: bool = false,
    i_version: bool = false,
    born: bool = false,          // SB_BORN
    active: bool = false,        // SB_ACTIVE
    nosec: bool = false,         // SB_NOSEC
    inlinecrypt: bool = false,   // SB_INLINECRYPT
    // Zxyphor
    zxy_verified: bool = false,
    zxy_encrypted: bool = false,
    _padding: u46 = 0,
};

/// Filesystem type flags
pub const FsTypeFlags = packed struct(u32) {
    requires_dev: bool = false,         // FS_REQUIRES_DEV
    binary_mountdata: bool = false,     // FS_BINARY_MOUNTDATA
    has_subtype: bool = false,          // FS_HAS_SUBTYPE
    userns_mount: bool = false,         // FS_USERNS_MOUNT
    disallow_notify_perm: bool = false, // FS_DISALLOW_NOTIFY_PERM
    allow_idmap: bool = false,          // FS_ALLOW_IDMAP
    rename_does_d_move: bool = false,
    _padding: u25 = 0,
};

/// Registered filesystem descriptor
pub const FilesystemDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    fs_flags: FsTypeFlags = .{},
    sb_flags_default: SuperBlockFlags = .{},
    magic_number: u64 = 0,
    max_file_size: u64 = 0,
    max_filename_len: u32 = 255,
    max_symlink_len: u32 = 4096,
    max_links: u32 = 0,
    block_size_min: u32 = 512,
    block_size_max: u32 = 65536,
    supports_xattr: bool = false,
    supports_acl: bool = false,
    supports_quota: bool = false,
    supports_casefold: bool = false,
    supports_verity: bool = false,
    supports_encryption: bool = false,
    supports_reflink: bool = false,
    supports_inline_data: bool = false,
    supports_compression: bool = false,
    is_network_fs: bool = false,
    is_pseudo_fs: bool = false,
    // Zxyphor
    zxy_snapshot_support: bool = false,
    zxy_dedup_support: bool = false,
};

/// Well-known filesystem magic numbers
pub const FS_MAGIC_EXT4: u64 = 0xEF53;
pub const FS_MAGIC_BTRFS: u64 = 0x9123683E;
pub const FS_MAGIC_XFS: u64 = 0x58465342;
pub const FS_MAGIC_F2FS: u64 = 0xF2F52010;
pub const FS_MAGIC_TMPFS: u64 = 0x01021994;
pub const FS_MAGIC_PROC: u64 = 0x9FA0;
pub const FS_MAGIC_SYSFS: u64 = 0x62656572;
pub const FS_MAGIC_DEVTMPFS: u64 = 0x01021994;
pub const FS_MAGIC_CGROUP2: u64 = 0x63677270;
pub const FS_MAGIC_NFS: u64 = 0x6969;
pub const FS_MAGIC_CIFS: u64 = 0xFF534D42;
pub const FS_MAGIC_FUSE: u64 = 0x65735546;
pub const FS_MAGIC_OVERLAYFS: u64 = 0x794C7630;
pub const FS_MAGIC_SQUASHFS: u64 = 0x73717368;
pub const FS_MAGIC_EROFS: u64 = 0xE0F5E1E2;
pub const FS_MAGIC_BCACHEFS: u64 = 0xCA451A4E;
pub const FS_MAGIC_ZXYFS: u64 = 0x5A585946; // Zxyphor

// ============================================================================
// Mount Namespace
// ============================================================================

/// Mount namespace descriptor
pub const MountNsDesc = struct {
    id: u64 = 0,
    nr_mounts: u32 = 0,
    nr_pending_mounts: u32 = 0,
    mount_max: u32 = 100000,
    seq: u64 = 0,
    event: u64 = 0,
    root_mount_id: u64 = 0,
    user_ns_id: u64 = 0,
};

/// Mount info (from /proc/self/mountinfo)
pub const MountInfo = struct {
    mount_id: u64 = 0,
    parent_id: u64 = 0,
    dev_major: u32 = 0,
    dev_minor: u32 = 0,
    root: [256]u8 = [_]u8{0} ** 256,
    root_len: u16 = 0,
    mountpoint: [256]u8 = [_]u8{0} ** 256,
    mountpoint_len: u16 = 0,
    mount_flags: MountFlags = .{},
    fs_type: [32]u8 = [_]u8{0} ** 32,
    fs_type_len: u8 = 0,
    mount_source: [256]u8 = [_]u8{0} ** 256,
    mount_source_len: u16 = 0,
    super_options: [256]u8 = [_]u8{0} ** 256,
    super_options_len: u16 = 0,
    propagation: MountPropagation = .private,
    master_id: u64 = 0,           // for slave mounts
    peer_group: u64 = 0,          // for shared mounts
};

// ============================================================================
// Automount
// ============================================================================

/// Automount type
pub const AutomountType = enum(u8) {
    none = 0,
    autofs = 1,
    nfs_referral = 2,
    afs_mountpoint = 3,
    cifs_dfs = 4,
};

/// Automount descriptor
pub const AutomountDesc = struct {
    fs_type: AutomountType = .none,
    path: [256]u8 = [_]u8{0} ** 256,
    path_len: u16 = 0,
    timeout_sec: u32 = 300,
    ghost: bool = false,
    direct: bool = false,
};

// ============================================================================
// Filesystem Context
// ============================================================================

/// fs_context purpose
pub const FsContextPurpose = enum(u8) {
    mount = 0,
    submount = 1,
    remount = 2,
    reconfigure = 3,
};

/// fs_context phase
pub const FsContextPhase = enum(u8) {
    free = 0,
    create_params = 1,
    creating = 2,
    active = 3,
    failed = 4,
};

/// fs_context parameter type
pub const FsParamType = enum(u8) {
    flag = 0,
    bool_type = 1,
    u32_type = 2,
    u32_oct = 3,
    u32_hex = 4,
    s32_type = 5,
    u64_type = 6,
    string = 7,
    blob = 8,
    blockdev = 9,
    path = 10,
    fd = 11,
    enum_type = 12,
};

/// fs_context descriptor
pub const FsContextDesc = struct {
    purpose: FsContextPurpose = .mount,
    phase: FsContextPhase = .free,
    fs_name: [32]u8 = [_]u8{0} ** 32,
    fs_name_len: u8 = 0,
    sb_flags: SuperBlockFlags = .{},
    sb_flags_mask: SuperBlockFlags = .{},
    nr_params: u32 = 0,
    need_free: bool = false,
    global: bool = false,
    oldapi: bool = false,
    exclusive: bool = false,
    // Zxyphor
    zxy_verified: bool = false,
};

// ============================================================================
// Mount Subsystem Manager
// ============================================================================

pub const MountSubsystem = struct {
    nr_mounts: u64 = 0,
    nr_mount_namespaces: u32 = 0,
    nr_filesystems: u32 = 0,
    nr_superblocks: u32 = 0,
    nr_bind_mounts: u64 = 0,
    nr_automounts: u32 = 0,
    mount_max: u32 = 100000,
    new_mount_api: bool = true,
    idmap_mounts: u32 = 0,
    initialized: bool = false,

    pub fn init() MountSubsystem {
        return MountSubsystem{
            .initialized = true,
        };
    }
};
