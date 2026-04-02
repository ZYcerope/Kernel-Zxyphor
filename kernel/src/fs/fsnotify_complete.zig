// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Fsnotify / Inotify / Fanotify Complete
// inotify events, fanotify marks, fsnotify group, fsnotify backend,
// inotify_event, fanotify_event, mark types, permission events

const std = @import("std");

// ============================================================================
// Inotify Events
// ============================================================================

pub const IN_ACCESS: u32 = 0x00000001;
pub const IN_MODIFY: u32 = 0x00000002;
pub const IN_ATTRIB: u32 = 0x00000004;
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
pub const IN_OPEN: u32 = 0x00000020;
pub const IN_MOVED_FROM: u32 = 0x00000040;
pub const IN_MOVED_TO: u32 = 0x00000080;
pub const IN_CREATE: u32 = 0x00000100;
pub const IN_DELETE: u32 = 0x00000200;
pub const IN_DELETE_SELF: u32 = 0x00000400;
pub const IN_MOVE_SELF: u32 = 0x00000800;
pub const IN_UNMOUNT: u32 = 0x00002000;
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
pub const IN_IGNORED: u32 = 0x00008000;
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
pub const IN_ONLYDIR: u32 = 0x01000000;
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
pub const IN_MASK_CREATE: u32 = 0x10000000;
pub const IN_MASK_ADD: u32 = 0x20000000;
pub const IN_ISDIR: u32 = 0x40000000;
pub const IN_ONESHOT: u32 = 0x80000000;
pub const IN_ALL_EVENTS: u32 = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF;

pub const InotifyEvent = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
    // followed by name[len]
};

pub const InotifyWdEntry = struct {
    wd: i32,
    mask: u32,
    inode_number: u64,
    device: u32,
    flags: u32,
    mark: ?*FsnotifyMark,
};

// ============================================================================
// Fanotify Events and Flags
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

// fanotify_init flags
pub const FAN_CLOEXEC: u32 = 0x00000001;
pub const FAN_NONBLOCK: u32 = 0x00000002;
pub const FAN_CLASS_NOTIF: u32 = 0x00000000;
pub const FAN_CLASS_CONTENT: u32 = 0x00000004;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x00000008;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x00000010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x00000020;
pub const FAN_ENABLE_AUDIT: u32 = 0x00000040;
pub const FAN_REPORT_TID: u32 = 0x00000100;
pub const FAN_REPORT_FID: u32 = 0x00000200;
pub const FAN_REPORT_DIR_FID: u32 = 0x00000400;
pub const FAN_REPORT_NAME: u32 = 0x00000800;
pub const FAN_REPORT_TARGET_FID: u32 = 0x00001000;
pub const FAN_REPORT_PIDFD: u32 = 0x00000080;

// fanotify_mark flags
pub const FAN_MARK_ADD: u32 = 0x00000001;
pub const FAN_MARK_REMOVE: u32 = 0x00000002;
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x00000004;
pub const FAN_MARK_ONLYDIR: u32 = 0x00000008;
pub const FAN_MARK_IGNORED_MASK: u32 = 0x00000020;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x00000040;
pub const FAN_MARK_FLUSH: u32 = 0x00000080;
pub const FAN_MARK_EVICTABLE: u32 = 0x00000200;
pub const FAN_MARK_IGNORE: u32 = 0x00000400;

pub const FAN_MARK_INODE: u32 = 0x00000000;
pub const FAN_MARK_MOUNT: u32 = 0x00000010;
pub const FAN_MARK_FILESYSTEM: u32 = 0x00000100;

pub const FanotifyEventMetadata = extern struct {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
};

pub const FanotifyEventInfoHeader = extern struct {
    info_type: u8,
    pad: u8,
    len: u16,
};

pub const FanotifyEventInfoFid = extern struct {
    hdr: FanotifyEventInfoHeader,
    fsid: [2]u32,
    // followed by file_handle
};

pub const FanotifyResponse = extern struct {
    fd: i32,
    response: u32,
};

pub const FAN_ALLOW: u32 = 0x01;
pub const FAN_DENY: u32 = 0x02;
pub const FAN_AUDIT: u32 = 0x10;
pub const FAN_INFO: u32 = 0x20;

// ============================================================================
// Fsnotify Core
// ============================================================================

pub const FsnotifyDataType = enum(u8) {
    None = 0,
    Path = 1,
    Inode = 2,
    FileRange = 3,
    Error = 4,
};

pub const FsnotifyGroupType = enum(u8) {
    Inotify = 0,
    Fanotify = 1,
    Audit = 2,
    Dnotify = 3,
};

pub const FsnotifyGroupFlags = packed struct(u32) {
    user_waits_for_perm: bool = false,
    large_queue: bool = false,
    shutdown: bool = false,
    overflow: bool = false,
    _reserved: u28 = 0,
};

pub const FsnotifyOps = struct {
    handle_event: ?*const fn (group: *FsnotifyGroup, mask: u32, data: ?*const anyopaque, data_type: FsnotifyDataType, dir: ?*anyopaque, file_name: ?[*:0]const u8, cookie: u32, iter_info: ?*anyopaque) callconv(.C) i32,
    handle_inode_event: ?*const fn (mark: *FsnotifyMark, mask: u32, inode: ?*anyopaque, dir: ?*anyopaque, name: ?[*:0]const u8, cookie: u32) callconv(.C) i32,
    free_group_priv: ?*const fn (group: *FsnotifyGroup) callconv(.C) void,
    freeing_mark: ?*const fn (mark: *FsnotifyMark, group: *FsnotifyGroup) callconv(.C) void,
    free_event: ?*const fn (group: *FsnotifyGroup, event: *FsnotifyEvent) callconv(.C) void,
    free_mark: ?*const fn (mark: *FsnotifyMark) callconv(.C) void,
};

pub const FsnotifyGroup = struct {
    refcnt: i32,
    flags: FsnotifyGroupFlags,
    group_type: FsnotifyGroupType,
    ops: ?*const FsnotifyOps,
    notification_lock: SpinLock,
    notification_list: ListHead,
    notification_waitq: WaitQueueHead,
    q_len: u32,
    max_events: u32,
    num_marks: u32,
    priority: u32,
    shutdown: bool,
    fanotify_data: FanotifyGroupData,
    inotify_data: InotifyGroupData,
    marks_list: ListHead,
    overflow_event: ?*FsnotifyEvent,
    user: ?*anyopaque,
};

pub const FanotifyGroupData = struct {
    f_flags: u32,
    flags: u32,
    max_marks: u32,
    audit: bool,
    report_fid: bool,
    report_dir_fid: bool,
    report_name: bool,
    report_target_fid: bool,
    report_pidfd: bool,
};

pub const InotifyGroupData = struct {
    idr_lock: SpinLock,
    last_wd: u32,
    max_watches: u32,
    ucounts: ?*anyopaque,
};

// ============================================================================
// Fsnotify Marks
// ============================================================================

pub const FsnotifyMarkType = enum(u8) {
    Inode = 0,
    Vfsmount = 1,
    Sb = 2,
    Connector = 3,
};

pub const FsnotifyMarkFlags = packed struct(u32) {
    alive: bool = false,
    attached: bool = false,
    inode_mark: bool = false,
    vfsmount_mark: bool = false,
    sb_mark: bool = false,
    object_pinned: bool = false,
    allow_dups: bool = false,
    _reserved: u25 = 0,
};

pub const FsnotifyMark = struct {
    mask: u32,
    flags: FsnotifyMarkFlags,
    refcnt: i32,
    group: ?*FsnotifyGroup,
    group_list: ListHead,
    obj_list: ListHead,
    connector: ?*FsnotifyMarkConnector,
    ignored_mask: u32,
};

pub const FsnotifyMarkConnector = struct {
    lock: SpinLock,
    conn_type: FsnotifyMarkType,
    obj: ?*anyopaque,
    list: HashListHead,
    flags: u32,
};

pub const FsnotifyEvent = struct {
    list: ListHead,
    mask: u32,
    objectid: u64,
};

// ============================================================================
// Dnotify (legacy)
// ============================================================================

pub const DN_ACCESS: u32 = 0x00000001;
pub const DN_MODIFY: u32 = 0x00000002;
pub const DN_CREATE: u32 = 0x00000004;
pub const DN_DELETE: u32 = 0x00000008;
pub const DN_RENAME: u32 = 0x00000010;
pub const DN_ATTRIB: u32 = 0x00000020;
pub const DN_MULTISHOT: u32 = 0x80000000;

pub const DnotifyStruct = struct {
    dn_mark: ?*FsnotifyMark,
    dn_mask: u32,
    dn_fd: i32,
    dn_filp: ?*anyopaque,
    dn_fown: FownStruct,
};

pub const FownStruct = struct {
    lock: RwLock,
    pid: ?*anyopaque,
    pid_type: i32,
    uid: u32,
    euid: u32,
    signum: i32,
};

// ============================================================================
// Fsnotify Backend for Specific Filesystems
// ============================================================================

pub const FsnotifyBackendType = enum(u8) {
    GenericVfs = 0,
    Ext4 = 1,
    Btrfs = 2,
    Xfs = 3,
    Nfs = 4,
    Overlayfs = 5,
    Fuse = 6,
};

pub const FsnotifyBackendConfig = struct {
    backend_type: FsnotifyBackendType,
    supports_fid: bool,
    supports_dir_fid: bool,
    supports_name: bool,
    supports_rename: bool,
    supports_pre_content: bool,
    supports_error_events: bool,
    max_marks: u32,
    max_queued_events: u32,
    default_queue_size: u32,
};

// ============================================================================
// Audit Watch (uses fsnotify)
// ============================================================================

pub const AuditWatch = struct {
    path: [256]u8,
    path_len: u32,
    dev: u32,
    ino: u64,
    filterkey: [256]u8,
    key_len: u32,
    mark: ?*FsnotifyMark,
    parent: ?*AuditParent,
    count: i32,
};

pub const AuditParent = struct {
    flags: u32,
    mark: ?*FsnotifyMark,
    watches: ListHead,
    count: i32,
};

// ============================================================================
// Helper types
// ============================================================================

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,
};

pub const HashListHead = struct {
    first: ?*HashListNode,
};

pub const HashListNode = struct {
    next: ?*HashListNode,
    pprev: ?*?*HashListNode,
};

pub const SpinLock = struct { raw: u32 = 0 };
pub const RwLock = struct { raw: u32 = 0 };
pub const WaitQueueHead = struct { lock: SpinLock = .{}, head: ListHead = .{ .next = null, .prev = null } };

// ============================================================================
// Fsnotify Manager
// ============================================================================

pub const FsnotifyManager = struct {
    total_groups: u32,
    total_marks: u32,
    inotify_instances: u32,
    fanotify_instances: u32,
    audit_watches: u32,
    total_events_queued: u64,
    total_events_dispatched: u64,
    permission_events: u64,
    overflow_events: u64,
    max_user_instances: u32,
    max_user_watches: u32,
    max_queued_events: u32,
    initialized: bool,

    pub fn init() FsnotifyManager {
        return .{
            .total_groups = 0,
            .total_marks = 0,
            .inotify_instances = 0,
            .fanotify_instances = 0,
            .audit_watches = 0,
            .total_events_queued = 0,
            .total_events_dispatched = 0,
            .permission_events = 0,
            .overflow_events = 0,
            .max_user_instances = 8192,
            .max_user_watches = 1048576,
            .max_queued_events = 16384,
            .initialized = true,
        };
    }
};
