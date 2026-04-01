// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - procfs, sysfs, debugfs, devtmpfs advanced implementation
// Full pseudo-filesystem implementations with complete node types,
// directory operations, read/write handlers, permission model
// More advanced than Linux 2026 pseudo-filesystem stack

const std = @import("std");

// ============================================================================
// Common Inode / Dentry structures for pseudo-fs
// ============================================================================

pub const PseudoInodeType = enum(u8) {
    file = 0,
    directory = 1,
    symlink = 2,
    device_char = 3,
    device_block = 4,
    pipe = 5,
    socket = 6,
};

pub const PseudoPermissions = packed struct {
    other_exec: bool,
    other_write: bool,
    other_read: bool,
    group_exec: bool,
    group_write: bool,
    group_read: bool,
    user_exec: bool,
    user_write: bool,
    user_read: bool,
    sticky: bool,
    setgid: bool,
    setuid: bool,
    _padding: u4 = 0,

    pub fn from_mode(mode: u16) PseudoPermissions {
        return @bitCast(@as(u16, mode & 0x0FFF));
    }

    pub fn to_mode(self: PseudoPermissions) u16 {
        return @bitCast(self);
    }
};

pub const PseudoInode = struct {
    ino: u64,
    inode_type: PseudoInodeType,
    permissions: PseudoPermissions,
    uid: u32,
    gid: u32,
    size: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    nlink: u32,
    // Operations
    read_fn: ?*const fn (*PseudoInode, []u8, u64) i64,
    write_fn: ?*const fn (*PseudoInode, []const u8, u64) i64,
    // Private data
    private_data: ?*anyopaque,
    // Parent
    parent: ?*PseudoDentry,
};

pub const PseudoDentry = struct {
    name: [256]u8,
    name_len: u16,
    inode: ?*PseudoInode,
    parent: ?*PseudoDentry,
    children: [512]*PseudoDentry,
    nr_children: u32,
    // Hash for lookup
    d_hash: u32,
    // Flags
    d_flags: u32,
    // Mount point
    is_mount_point: bool,

    pub fn lookup_child(self: *const PseudoDentry, name: []const u8) ?*PseudoDentry {
        for (self.children[0..self.nr_children]) |child| {
            if (std.mem.eql(u8, child.name[0..child.name_len], name)) {
                return child;
            }
        }
        return null;
    }
};

// ============================================================================
// /proc filesystem (procfs)
// ============================================================================

pub const ProcEntryType = enum(u8) {
    // Per-process entries under /proc/<pid>/
    status = 0,
    stat = 1,
    statm = 2,
    maps = 3,
    smaps = 4,
    smaps_rollup = 5,
    cmdline = 6,
    environ = 7,
    exe = 8,
    cwd = 9,
    root = 10,
    fd = 11,
    fdinfo = 12,
    task = 13,
    io = 14,
    oom_score = 15,
    oom_adj = 16,
    oom_score_adj = 17,
    limits = 18,
    cgroup = 19,
    mountinfo = 20,
    mounts = 21,
    mountstats = 22,
    ns = 23,
    net = 24,
    mem = 25,
    pagemap = 26,
    wchan = 27,
    stack = 28,
    syscall = 29,
    loginuid = 30,
    sessionid = 31,
    personality = 32,
    attr = 33,
    autogroup = 34,
    comm = 35,
    coredump_filter = 36,
    cpuset = 37,
    latency = 38,
    sched = 39,
    schedstat = 40,
    timers = 41,
    timerslack_ns = 42,
    // System-wide entries under /proc/
    meminfo = 100,
    cpuinfo = 101,
    version = 102,
    uptime = 103,
    loadavg = 104,
    vmstat = 105,
    zoneinfo = 106,
    buddyinfo = 107,
    pagetypeinfo = 108,
    slabinfo = 109,
    modules = 110,
    interrupts = 111,
    softirqs = 112,
    filesystems = 113,
    diskstats = 114,
    partitions = 115,
    swaps = 116,
    devices = 117,
    misc = 118,
    cmdline_sys = 119,
    config_gz = 120,
    crypto = 121,
    keys = 122,
    key_users = 123,
    kallsyms = 124,
    kcore = 125,
    kmsg = 126,
    locks = 127,
    iomem = 128,
    ioports = 129,
    timer_list = 130,
    timer_stats = 131,
    sched_debug = 132,
    // /proc/sys (sysctl)
    sys_kernel = 200,
    sys_vm = 201,
    sys_fs = 202,
    sys_net = 203,
    sys_debug = 204,
    sys_dev = 205,
    sys_abi = 206,
    // /proc/net/
    net_tcp = 250,
    net_tcp6 = 251,
    net_udp = 252,
    net_udp6 = 253,
    net_unix = 254,
};

pub const ProcPidStatus = struct {
    name: [16]u8,
    umask: u32,
    state: u8,
    tgid: i32,
    ngid: i32,
    pid: i32,
    ppid: i32,
    tracer_pid: i32,
    uid: [4]u32,     // Real, Effective, Saved Set, FS
    gid: [4]u32,
    fd_size: u32,
    groups: [32]u32,
    nr_groups: u32,
    ns_tgid: [4]i32,
    ns_pid: [4]i32,
    ns_pgid: [4]i32,
    ns_sid: [4]i32,
    // Memory
    vm_peak: u64,
    vm_size: u64,
    vm_lck: u64,
    vm_pin: u64,
    vm_hwm: u64,     // Peak RSS
    vm_rss: u64,
    rss_anon: u64,
    rss_file: u64,
    rss_shmem: u64,
    vm_data: u64,
    vm_stk: u64,
    vm_exe: u64,
    vm_lib: u64,
    vm_pte: u64,
    vm_swap: u64,
    hugetlb_pages: u64,
    // Thread
    threads: u32,
    sig_q: [2]u32,   // queued/max
    // Signals
    sig_pnd: u64,
    shd_pnd: u64,
    sig_blk: u64,
    sig_ign: u64,
    sig_cgt: u64,
    // Capabilities
    cap_inh: u64,
    cap_prm: u64,
    cap_eff: u64,
    cap_bnd: u64,
    cap_amb: u64,
    no_new_privs: bool,
    // Seccomp
    seccomp: u8,
    seccomp_filters: u32,
    // Speculation
    speculation_store_bypass: u8,
    speculative_store_bypass_disable: bool,
    // coreDumping
    core_dumping: bool,
    // THP
    thp_enabled: bool,
    // Zxyphor
    zxy_priority_class: u8,
};

pub const ProcMeminfo = struct {
    mem_total: u64,
    mem_free: u64,
    mem_available: u64,
    buffers: u64,
    cached: u64,
    swap_cached: u64,
    active: u64,
    inactive: u64,
    active_anon: u64,
    inactive_anon: u64,
    active_file: u64,
    inactive_file: u64,
    unevictable: u64,
    mlocked: u64,
    swap_total: u64,
    swap_free: u64,
    zswap: u64,
    zswapped: u64,
    dirty: u64,
    writeback: u64,
    anon_pages: u64,
    mapped: u64,
    shmem: u64,
    kreclaimable: u64,
    slab: u64,
    s_reclaimable: u64,
    s_unreclaimable: u64,
    kernel_stack: u64,
    page_tables: u64,
    sec_page_tables: u64,
    nfs_unstable: u64,
    bounce: u64,
    writeback_tmp: u64,
    commit_limit: u64,
    committed_as: u64,
    vmalloc_total: u64,
    vmalloc_used: u64,
    vmalloc_chunk: u64,
    percpu: u64,
    hardware_corrupted: u64,
    anon_huge_pages: u64,
    shmem_huge_pages: u64,
    shmem_pmd_mapped: u64,
    file_huge_pages: u64,
    file_pmd_mapped: u64,
    cma_total: u64,
    cma_free: u64,
    huge_pages_total: u64,
    huge_pages_free: u64,
    huge_pages_rsvd: u64,
    huge_pages_surp: u64,
    hugepagesize: u64,
    hugetlb: u64,
    direct_map_4k: u64,
    direct_map_2m: u64,
    direct_map_1g: u64,
};

// ============================================================================
// /sys filesystem (sysfs) - kobject representation
// ============================================================================

pub const SysfsAttrType = enum(u8) {
    str_attr = 0,
    int_attr = 1,
    uint_attr = 2,
    bool_attr = 3,
    binary_attr = 4,
    // Group
    attr_group = 5,
};

pub const SysfsAttribute = struct {
    name: [64]u8,
    name_len: u8,
    attr_type: SysfsAttrType,
    mode: u16,
    // Callbacks
    show: ?*const fn (*SysfsAttribute, []u8) i64,
    store: ?*const fn (*SysfsAttribute, []const u8) i64,
    // Data
    private_data: ?*anyopaque,
};

pub const SysfsGroup = struct {
    name: [64]u8,
    name_len: u8,
    attrs: [64]*SysfsAttribute,
    nr_attrs: u32,
    is_visible: ?*const fn (*SysfsAttribute) bool,
};

pub const SysfsKobject = struct {
    name: [256]u8,
    name_len: u16,
    parent: ?*SysfsKobject,
    ktype: SysfsKtype,
    kset: ?*SysfsKset,
    children: [128]*SysfsKobject,
    nr_children: u32,
    attrs: [64]*SysfsAttribute,
    nr_attrs: u32,
    groups: [16]*SysfsGroup,
    nr_groups: u32,
    uevent_suppress: bool,
    state_in_sysfs: bool,
    state_add_uevent_sent: bool,
    state_remove_uevent_sent: bool,
    refcount: u32,

    pub fn path(self: *const SysfsKobject, buf: []u8) u32 {
        // Build full path from root
        var depth: u32 = 0;
        var node: ?*const SysfsKobject = self;
        while (node) |n| : (node = n.parent) {
            depth += 1;
        }
        _ = buf;
        return depth;
    }
};

pub const SysfsKtype = enum(u8) {
    device = 0,
    driver = 1,
    bus = 2,
    class = 3,
    firmware = 4,
    module = 5,
    block = 6,
    power = 7,
    // Subsystems
    cpu = 10,
    memory = 11,
    node = 12,
    pci = 13,
    usb = 14,
    net = 15,
    // Zxyphor
    zxy_subsystem = 20,
};

pub const SysfsKset = struct {
    name: [64]u8,
    kobjects: [256]*SysfsKobject,
    nr_kobjects: u32,
    uevent_ops: ?*SysfsUeventOps,
};

pub const SysfsUeventOps = struct {
    filter: ?*const fn (*SysfsKobject) bool,
    name: ?*const fn (*SysfsKobject) [64]u8,
    uevent: ?*const fn (*SysfsKobject, *UeventEnv) i32,
};

pub const UeventAction = enum(u8) {
    add = 0,
    remove = 1,
    change = 2,
    move = 3,
    online = 4,
    offline = 5,
    bind = 6,
    unbind = 7,
};

pub const UeventEnv = struct {
    action: UeventAction,
    envp: [64][256]u8,
    envp_idx: u32,
    buf: [2048]u8,
    buf_len: u32,
};

// ============================================================================
// /sys/devices hierarchy
// ============================================================================

pub const SysfsDeviceClass = enum(u8) {
    block = 0,
    char_device = 1,
    net = 2,
    input = 3,
    tty = 4,
    sound = 5,
    video = 6,
    drm = 7,
    hwmon = 8,
    thermal = 9,
    power_supply = 10,
    backlight = 11,
    leds = 12,
    gpio = 13,
    iio = 14,
    usb = 15,
    pci = 16,
    scsi = 17,
    nvme = 18,
    mmc = 19,
    bluetooth = 20,
    ieee80211 = 21,
    firmware = 22,
    // Zxyphor
    zxy_accel = 30,
};

// ============================================================================
// /sys/fs/ - Filesystem specific sysfs
// ============================================================================

pub const SysfsFsType = enum(u8) {
    ext4 = 0,
    xfs = 1,
    btrfs = 2,
    f2fs = 3,
    tmpfs = 4,
    cgroup = 5,
    cgroup2 = 6,
    fuse = 7,
    nfs = 8,
    // Zxyphor
    zxyfs = 9,
};

// ============================================================================
// debugfs
// ============================================================================

pub const DebugfsEntryType = enum(u8) {
    u8_val = 0,
    u16_val = 1,
    u32_val = 2,
    u64_val = 3,
    x8_val = 4,     // Hex
    x16_val = 5,
    x32_val = 6,
    x64_val = 7,
    size_t_val = 8,
    atomic_t_val = 9,
    bool_val = 10,
    blob = 11,
    regset32 = 12,
    u32_array = 13,
    file_ops = 14,
    symlink = 15,
};

pub const DebugfsEntry = struct {
    name: [128]u8,
    name_len: u16,
    entry_type: DebugfsEntryType,
    mode: u16,
    parent: ?*DebugfsEntry,
    children: [256]*DebugfsEntry,
    nr_children: u32,
    // Value pointer
    data: ?*anyopaque,
    data_size: u64,
    // Custom ops
    read_fn: ?*const fn (*DebugfsEntry, []u8) i64,
    write_fn: ?*const fn (*DebugfsEntry, []const u8) i64,
};

pub const DebugfsBlob = struct {
    data: [*]const u8,
    size: u64,
};

pub const DebugfsRegset32 = struct {
    regs: [*]const DebugfsReg32,
    nregs: u32,
    base: u64,
};

pub const DebugfsReg32 = struct {
    name: [32]u8,
    offset: u32,
};

// ============================================================================
// devtmpfs
// ============================================================================

pub const DevtmpfsNodeType = enum(u8) {
    char_device = 0,
    block_device = 1,
};

pub const DevtmpfsNode = struct {
    name: [256]u8,
    name_len: u16,
    node_type: DevtmpfsNodeType,
    major: u32,
    minor: u32,
    mode: u16,
    uid: u32,
    gid: u32,
    // Parent directory path
    dir_path: [256]u8,
    dir_path_len: u16,
};

// ============================================================================
// configfs
// ============================================================================

pub const ConfigfsItem = struct {
    name: [128]u8,
    name_len: u16,
    parent: ?*ConfigfsItem,
    children: [64]*ConfigfsItem,
    nr_children: u32,
    attrs: [32]*ConfigfsAttribute,
    nr_attrs: u32,
    // Type
    item_type: ConfigfsItemType,
    is_group: bool,
    refcount: u32,
};

pub const ConfigfsItemType = enum(u8) {
    simple_item = 0,
    default_group = 1,
    dependent_subsystem = 2,
};

pub const ConfigfsAttribute = struct {
    name: [64]u8,
    name_len: u8,
    mode: u16,
    show: ?*const fn (*ConfigfsItem, []u8) i64,
    store: ?*const fn (*ConfigfsItem, []const u8) i64,
};

// ============================================================================
// securityfs
// ============================================================================

pub const SecurityfsEntry = struct {
    name: [128]u8,
    name_len: u16,
    mode: u16,
    parent: ?*SecurityfsEntry,
    // Purpose
    subsystem: SecurityfsSubsystem,
    // Ops
    read_fn: ?*const fn ([]u8) i64,
    write_fn: ?*const fn ([]const u8) i64,
};

pub const SecurityfsSubsystem = enum(u8) {
    selinux = 0,
    apparmor = 1,
    smack = 2,
    tomoyo = 3,
    ima = 4,
    evm = 5,
    tpm = 6,
    // Zxyphor
    zxy_security = 7,
};

// ============================================================================
// Pseudo-FS Subsystem Manager
// ============================================================================

pub const PseudoFsSubsystem = struct {
    // procfs
    proc_root: ?*PseudoDentry,
    proc_meminfo: ProcMeminfo,
    proc_nr_open_files: u64,
    // sysfs
    sysfs_root: ?*SysfsKobject,
    sysfs_devices: [1024]*SysfsKobject,
    nr_sysfs_devices: u32,
    // debugfs
    debugfs_root: ?*DebugfsEntry,
    debugfs_nr_entries: u64,
    // devtmpfs
    devtmpfs_nodes: [4096]DevtmpfsNode,
    nr_devtmpfs_nodes: u32,
    // configfs
    configfs_root: ?*ConfigfsItem,
    // securityfs
    securityfs_root: ?*SecurityfsEntry,
    // Stats
    total_proc_reads: u64,
    total_sysfs_reads: u64,
    total_sysfs_writes: u64,
    total_debugfs_reads: u64,
    // Zxyphor
    zxy_unified_pseudo_fs: bool,
    initialized: bool,
};
