// Zxyphor Kernel - Kobject Lifecycle, Sysfs Attribute Groups, debugobjects
// kobject reference counting, kset management, ktype operations
// Sysfs: attribute types, binary attributes, groups, symlinks
// Debugobjects: object tracking, state machine, fixup callbacks
// Seq_file: iterator interface for procfs/sysfs reading
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Kobject Core
// ============================================================================

pub const KobjectType = enum(u8) {
    device = 0,
    driver = 1,
    bus = 2,
    class = 3,
    firmware = 4,
    module = 5,
    power = 6,
    block = 7,
    virtual_dev = 8,
    platform = 9,
};

pub const KobjectState = packed struct(u8) {
    initialized: bool = false,
    in_sysfs: bool = false,
    add_uevent_sent: bool = false,
    remove_uevent_sent: bool = false,
    registered: bool = false,
    _pad: u3 = 0,
};

pub const Kobject = struct {
    name: [64]u8,
    name_len: u32,
    refcount: u32,
    parent: ?*Kobject,
    kset: ?*Kset,
    ktype: ?*KobjType,
    sd: ?*SysfsDirectory,
    state: KobjectState,
    state_add_uevent_sent: bool,
    state_remove_uevent_sent: bool,
    uevent_suppress: bool,

    pub fn get(self: *Kobject) *Kobject {
        self.refcount += 1;
        return self;
    }

    pub fn put(self: *Kobject) void {
        if (self.refcount > 0) {
            self.refcount -= 1;
            if (self.refcount == 0) {
                if (self.ktype) |kt| {
                    if (kt.release) |release_fn| {
                        release_fn(self);
                    }
                }
            }
        }
    }
};

pub const KobjType = struct {
    release: ?*const fn (*Kobject) void,
    sysfs_ops: ?*SysfsOps,
    default_groups: ?*const [*]const AttributeGroup,
    default_groups_count: u32,
    child_ns_type: ?*const fn (*Kobject) ?*KobjNsType,
};

pub const KobjNsType = struct {
    ns_type: enum(u8) {
        none = 0,
        net = 1,
        user = 2,
        pid = 3,
    },
    ops: struct {
        grab_current_ns: ?*const fn () ?*anyopaque,
        netlink_ns: ?*const fn (?*anyopaque) ?*anyopaque,
        initial_ns: ?*const fn () ?*anyopaque,
        drop_ns: ?*const fn (?*anyopaque) void,
    },
};

// ============================================================================
// Kset
// ============================================================================

pub const Kset = struct {
    kobject: Kobject,
    list_count: u32,
    uevent_ops: ?*KsetUeventOps,
};

pub const KsetUeventOps = struct {
    filter: ?*const fn (*Kobject) bool,
    name: ?*const fn (*Kobject) [*:0]const u8,
    uevent: ?*const fn (*Kobject, *UeventEnv) i32,
};

pub const UeventAction = enum(u8) {
    add = 0,
    remove = 1,
    change = 2,
    move_action = 3,
    online = 4,
    offline = 5,
    bind = 6,
    unbind = 7,
};

pub const UeventEnv = struct {
    envp: [64][*:0]u8,
    envp_idx: u32,
    buf: [2048]u8,
    buflen: u32,
    action: UeventAction,
    devpath: [256]u8,
    subsystem: [64]u8,
};

// ============================================================================
// Sysfs Core
// ============================================================================

pub const SysfsDirectory = struct {
    name: [64]u8,
    mode: u16,
    parent: ?*SysfsDirectory,
    children_count: u32,
    symlink_target: ?*SysfsDirectory,
    ns: ?*anyopaque,
    flags: SysfsDirFlags,
};

pub const SysfsDirFlags = packed struct(u8) {
    removed: bool = false,
    ns: bool = false,
    has_callouts: bool = false,
    _pad: u5 = 0,
};

pub const SysfsOps = struct {
    show: ?*const fn (*Kobject, *Attribute, []u8) i32,
    store: ?*const fn (*Kobject, *Attribute, []const u8) i32,
};

// ============================================================================
// Sysfs Attributes
// ============================================================================

pub const Attribute = struct {
    name: [64]u8,
    mode: u16,
    owner: ?*anyopaque,
};

pub const AttributeMode = struct {
    pub const S_IRUGO: u16 = 0o444;
    pub const S_IWUSR: u16 = 0o200;
    pub const S_IRUSR: u16 = 0o400;
    pub const S_IRWXU: u16 = 0o700;
    pub const S_IWGRP: u16 = 0o020;
    pub const S_IRGRP: u16 = 0o040;
    pub const S_IROTH: u16 = 0o004;
    pub const S_IWOTH: u16 = 0o002;
    pub const S_IXUSR: u16 = 0o100;
    pub const S_IXGRP: u16 = 0o010;
    pub const S_IXOTH: u16 = 0o001;
    pub const RO: u16 = S_IRUGO;
    pub const RW: u16 = S_IRUGO | S_IWUSR;
    pub const WO: u16 = S_IWUSR;
};

pub const DeviceAttribute = struct {
    attr: Attribute,
    show: ?*const fn (*anyopaque, *DeviceAttribute, []u8) i32,
    store: ?*const fn (*anyopaque, *DeviceAttribute, []const u8) i32,
};

pub const DriverAttribute = struct {
    attr: Attribute,
    show: ?*const fn (*anyopaque, []u8) i32,
    store: ?*const fn (*anyopaque, []const u8) i32,
};

pub const BusAttribute = struct {
    attr: Attribute,
    show: ?*const fn (*anyopaque, []u8) i32,
    store: ?*const fn (*anyopaque, []const u8) i32,
};

pub const ClassAttribute = struct {
    attr: Attribute,
    show: ?*const fn (*anyopaque, *ClassAttribute, []u8) i32,
    store: ?*const fn (*anyopaque, *ClassAttribute, []const u8) i32,
};

// ============================================================================
// Binary Attributes
// ============================================================================

pub const BinAttribute = struct {
    attr: Attribute,
    size: u64,
    mmap: ?*const fn (*anyopaque, *BinAttribute) i32,
    read: ?*const fn (*anyopaque, *BinAttribute, []u8, u64) i32,
    write: ?*const fn (*anyopaque, *BinAttribute, []const u8, u64) i32,
};

// ============================================================================
// Attribute Groups
// ============================================================================

pub const AttributeGroup = struct {
    name: ?[*:0]const u8,
    is_visible: ?*const fn (*Kobject, *Attribute, u32) u16,
    is_bin_visible: ?*const fn (*Kobject, *BinAttribute, u32) u16,
    attrs: ?[*]const *Attribute,
    bin_attrs: ?[*]const *BinAttribute,
    attrs_count: u32,
    bin_attrs_count: u32,
};

// ============================================================================
// debugobjects Infrastructure
// ============================================================================

pub const DebugObjState = enum(u8) {
    none = 0,
    init = 1,
    active = 2,
    deactivate = 3,
    destroy = 4,
};

pub const DebugObjFixupType = enum(u8) {
    init = 0,
    activate = 1,
    deactivate = 2,
    destroy = 3,
    free = 4,
    assert = 5,
};

pub const DebugObjDescr = struct {
    name: [32]u8,
    debug_hint: ?*const fn (*anyopaque) ?*anyopaque,
    is_static_object: ?*const fn (*anyopaque) bool,
    fixup_init: ?*const fn (*anyopaque, DebugObjState) bool,
    fixup_activate: ?*const fn (*anyopaque, DebugObjState) bool,
    fixup_destroy: ?*const fn (*anyopaque, DebugObjState) bool,
    fixup_free: ?*const fn (*anyopaque, DebugObjState) bool,
    fixup_assert_init: ?*const fn (*anyopaque, DebugObjState) bool,
};

pub const DebugObject = struct {
    object: ?*anyopaque,
    state: DebugObjState,
    astate: u8,
    descr: ?*const DebugObjDescr,
};

pub const DebugObjStats = struct {
    objects_active: u64,
    objects_max_active: u64,
    objects_freed: u64,
    objects_allocated: u64,
    objects_destroyed: u64,
    pool_free: u32,
    pool_min_free: u32,
    pool_used: u32,
    fixup_init: u64,
    fixup_activate: u64,
    fixup_destroy: u64,
    fixup_free: u64,
    warnings: u64,
};

pub const DebugObjBucket = struct {
    lock: u64,  // spinlock
    count: u32,
};

pub const DebugObjConfig = struct {
    enabled: bool,
    pool_size: u32,
    pool_min_level: u32,
    hash_bits: u8,
    buckets: [1024]DebugObjBucket,
    stats: DebugObjStats,
};

// ============================================================================
// seq_file Interface (procfs/sysfs reading)
// ============================================================================

pub const SeqFile = struct {
    buf: [*]u8,
    buf_size: u64,
    from: u64,
    count: u64,
    pad_until: u64,
    index: u64,
    read_pos: u64,
    version: u64,
    private_data: ?*anyopaque,
    op: ?*const SeqOperations,
    file: u64,  // file pointer
    overflow: bool,
};

pub const SeqOperations = struct {
    start: ?*const fn (*SeqFile, *u64) ?*anyopaque,
    stop: ?*const fn (*SeqFile, ?*anyopaque) void,
    next: ?*const fn (*SeqFile, ?*anyopaque, *u64) ?*anyopaque,
    show: ?*const fn (*SeqFile, ?*anyopaque) i32,
};

pub const SingleOpenFn = *const fn (*SeqFile, ?*anyopaque) i32;

// ============================================================================
// Proc Filesystem Helpers
// ============================================================================

pub const ProcDirEntry = struct {
    name: [256]u8,
    name_len: u32,
    mode: u16,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    parent: ?*ProcDirEntry,
    subdir: ?*ProcDirEntry,
    next: ?*ProcDirEntry,
    data: ?*anyopaque,
    proc_ops: ?*ProcOps,
    count: u32,
    pde_flags: ProcFlags,
};

pub const ProcOps = struct {
    proc_open: ?*const fn (u64, u64) i32,
    proc_read: ?*const fn (u64, [*]u8, u64, *u64) i64,
    proc_write: ?*const fn (u64, [*]const u8, u64, *u64) i64,
    proc_lseek: ?*const fn (u64, i64, u32) i64,
    proc_release: ?*const fn (u64, u64) i32,
    proc_poll: ?*const fn (u64, u64) u32,
    proc_ioctl: ?*const fn (u64, u32, u64) i64,
    proc_mmap: ?*const fn (u64, u64) i32,
    proc_get_unmapped_area: ?*const fn (u64, u64, u64, u64, u64) u64,
};

pub const ProcFlags = packed struct(u8) {
    pde_permanent: bool = false,
    pde_free: bool = false,
    pde_is_proc_inode: bool = false,
    _pad: u5 = 0,
};

// ============================================================================
// String Helpers
// ============================================================================

pub const StringHelpers = struct {
    // Kernel string utility function signatures
    pub const KSTRTOX_OVERFLOW: i32 = -34; // ERANGE

    pub fn simple_strtoul(buf: []const u8, base: u8) ?u64 {
        var result: u64 = 0;
        for (buf) |c| {
            const digit = charToDigit(c, base) orelse return null;
            result = result *% @as(u64, base) +% digit;
        }
        return result;
    }

    fn charToDigit(c: u8, base: u8) ?u64 {
        const d: u8 = if (c >= '0' and c <= '9')
            c - '0'
        else if (c >= 'a' and c <= 'f')
            c - 'a' + 10
        else if (c >= 'A' and c <= 'F')
            c - 'A' + 10
        else
            return null;
        if (d >= base) return null;
        return @as(u64, d);
    }
};

// ============================================================================
// Notifier Chain
// ============================================================================

pub const NotifierPriority = enum(i32) {
    min = -1000,
    low = -100,
    normal = 0,
    high = 100,
    max = 1000,
};

pub const NotifierBlock = struct {
    notifier_call: ?*const fn (*NotifierBlock, u64, ?*anyopaque) i32,
    next: ?*NotifierBlock,
    priority: i32,
};

pub const NotifierReturn = enum(i32) {
    done = 0,
    ok = 0,
    stop_mask = 0x8000,
    bad = 1,
};

pub const NotifierChainType = enum(u8) {
    atomic = 0,
    blocking = 1,
    raw = 2,
    srcu = 3,
};

// ============================================================================
// Kernel Parameters (module parameters)
// ============================================================================

pub const KernelParamType = enum(u8) {
    bool_type = 0,
    int_type = 1,
    uint_type = 2,
    long_type = 3,
    ulong_type = 4,
    charp_type = 5,
    string_type = 6,
    invbool_type = 7,
    byte_type = 8,
    short_type = 9,
    ushort_type = 10,
    hexint_type = 11,
};

pub const KernelParam = struct {
    name: [64]u8,
    mod_name: [64]u8,
    ops: ?*KernelParamOps,
    perm: u16,
    level: i8,
    param_type: KernelParamType,
    arg: ?*anyopaque,
};

pub const KernelParamOps = struct {
    flags: u32,
    set: ?*const fn ([]const u8, *const KernelParam) i32,
    get: ?*const fn ([]u8, *const KernelParam) i32,
    free: ?*const fn (?*anyopaque) void,
};

// ============================================================================
// Kernel Subsystem Manager
// ============================================================================

pub const KobjSubsystemManager = struct {
    total_kobjects: u64,
    total_ksets: u64,
    total_sysfs_entries: u64,
    total_bin_attrs: u64,
    total_attr_groups: u64,
    debug_objects: DebugObjConfig,
    notifier_chains: u32,
    kernel_params: u32,
    proc_entries: u32,
    initialized: bool,

    pub fn init() KobjSubsystemManager {
        return KobjSubsystemManager{
            .total_kobjects = 0,
            .total_ksets = 0,
            .total_sysfs_entries = 0,
            .total_bin_attrs = 0,
            .total_attr_groups = 0,
            .debug_objects = DebugObjConfig{
                .enabled = true,
                .pool_size = 1024,
                .pool_min_level = 256,
                .hash_bits = 10,
                .buckets = [_]DebugObjBucket{.{ .lock = 0, .count = 0 }} ** 1024,
                .stats = std.mem.zeroes(DebugObjStats),
            },
            .notifier_chains = 0,
            .kernel_params = 0,
            .proc_entries = 0,
            .initialized = true,
        };
    }
};
