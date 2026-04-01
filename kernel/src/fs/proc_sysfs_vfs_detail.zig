// Zxyphor Kernel - Proc/Sysfs VFS Detail
// procfs: /proc internals, PID entries, stat, status, maps, mountinfo
// sysfs: kobject glue, bus/class/driver hierarchy, attribute show/store
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// procfs Core
// ============================================================================

pub const ProcEntryType = enum(u8) {
    dir = 0,
    file = 1,
    symlink = 2,
};

pub const ProcDirEntry = struct {
    name: [256]u8,
    name_len: u32,
    mode: u16,
    nlink: u32,
    uid: u32,
    gid: u32,
    // Low-level
    ino: u64,
    size: u64,
    entry_type: ProcEntryType,
    // Ops
    proc_ops: ?*const ProcOps,
    // Hierarchy
    parent: ?*ProcDirEntry,
    subdir: ?*ProcDirEntry,
    next: ?*ProcDirEntry,
    // Refcount
    count: u32,
    // In use
    in_use: u32,
    // Data
    data: u64,
    // PDE users
    pde_unload_completion: u64,
    // Single open
    single_show: ?*const fn (u64, u64) i32,
};

pub const ProcOps = struct {
    proc_open: ?*const fn (u64, u64) i32,
    proc_read: ?*const fn (u64, [*]u8, u64, *u64) i64,
    proc_read_iter: ?*const fn (u64, u64) i64,
    proc_write: ?*const fn (u64, [*]const u8, u64, *u64) i64,
    proc_lseek: ?*const fn (u64, i64, u32) i64,
    proc_release: ?*const fn (u64, u64) i32,
    proc_poll: ?*const fn (u64, u64) u32,
    proc_ioctl: ?*const fn (u64, u32, u64) i64,
    proc_compat_ioctl: ?*const fn (u64, u32, u64) i64,
    proc_mmap: ?*const fn (u64, u64) i32,
    proc_get_unmapped_area: ?*const fn (u64, u64, u64, u64, u64) u64,
    proc_flags: u32,
};

// ============================================================================
// /proc/<pid>/ Per-Process Entries
// ============================================================================

pub const ProcPidEntry = struct {
    name: [32]u8,
    mode: u16,
    ops: ?*const ProcOps,
    inode_ops: u64,
    // Type
    entry_type: ProcPidEntryType,
};

pub const ProcPidEntryType = enum(u8) {
    status = 0,
    stat = 1,
    statm = 2,
    maps = 3,
    smaps = 4,
    smaps_rollup = 5,
    pagemap = 6,
    wchan = 7,
    stack = 8,
    cmdline = 9,
    environ = 10,
    auxv = 11,
    limits = 12,
    cgroup = 13,
    mountinfo = 14,
    mounts = 15,
    mountstats = 16,
    io = 17,
    fdinfo = 18,
    fd = 19,
    ns = 20,
    task = 21,
    net = 22,
    attr = 23,
    oom_adj = 24,
    oom_score = 25,
    oom_score_adj = 26,
    mem = 27,
    clear_refs = 28,
    comm = 29,
    exe = 30,
    root = 31,
    cwd = 32,
    loginuid = 33,
    sessionid = 34,
    syscall = 35,
    personality = 36,
    setgroups = 37,
    uid_map = 38,
    gid_map = 39,
    projid_map = 40,
    autogroup = 41,
    sched = 42,
    schedstat = 43,
    timers = 44,
    timerslack_ns = 45,
    patch_state = 46,
    arch_status = 47,
    coredump_filter = 48,
    cpu_resctrl_groups = 49,
    latency = 50,
};

// ============================================================================
// /proc/stat Data
// ============================================================================

pub const ProcStat = struct {
    // Per-CPU times (jiffies)
    per_cpu: [256]ProcCpuTime,
    nr_cpus: u32,
    // Total
    total: ProcCpuTime,
    // Other counts
    intr_total: u64,
    ctxt: u64,          // context switches
    btime: u64,         // boot time (seconds since epoch)
    processes: u64,     // forks since boot
    procs_running: u32,
    procs_blocked: u32,
    softirq_total: u64,
    softirq: [10]u64,  // per-softirq counts
};

pub const ProcCpuTime = struct {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    guest: u64,
    guest_nice: u64,
};

// ============================================================================
// /proc/<pid>/status Fields
// ============================================================================

pub const ProcPidStatus = struct {
    name: [16]u8,
    umask: u16,
    state: u8,
    tgid: i32,
    ngid: i32,
    pid: i32,
    ppid: i32,
    tracer_pid: i32,
    uid: [4]u32,        // Real, Effective, Saved, FS
    gid: [4]u32,
    fd_size: u32,
    groups: [32]u32,
    ngroups: u32,
    ns_tgid: [8]i32,    // up to 8 levels of PID namespaces
    ns_pid: [8]i32,
    ns_pgid: [8]i32,
    ns_sid: [8]i32,
    // Memory
    vm_peak: u64,
    vm_size: u64,
    vm_lck: u64,
    vm_pin: u64,
    vm_hwm: u64,        // high water mark RSS
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
    // Threads
    threads: u32,
    // Signals
    sig_q: [2]u64,       // queued/max
    sig_pnd: u64,
    shd_pnd: u64,
    sig_blk: u64,
    sig_ign: u64,
    sig_cgt: u64,        // caught
    // Capabilities
    cap_inh: u64,
    cap_prm: u64,
    cap_eff: u64,
    cap_bnd: u64,
    cap_amb: u64,
    // No new privs
    no_new_privs: bool,
    // Seccomp
    seccomp: u8,
    seccomp_filters: u32,
    // Speculation
    speculation_store_bypass: u8,
    spec_indirect_branch: u8,
    // Core scheduling
    core_sched_cookie: u64,
    // cgroup
    cpus_allowed: [4]u64,
    cpus_allowed_list: [256]u8,
    mems_allowed: [16]u64,
    mems_allowed_list: [256]u8,
    // Voluntary switches
    vol_ctx_switches: u64,
    nonvol_ctx_switches: u64,
};

// ============================================================================
// /proc/<pid>/maps Entry
// ============================================================================

pub const ProcMapsEntry = struct {
    vm_start: u64,
    vm_end: u64,
    flags: ProcMapsFlags,
    pgoff: u64,
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
    pathname: [256]u8,
    pathname_len: u32,
};

pub const ProcMapsFlags = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
    shared: bool = false,    // else private
    _pad: u4 = 0,
};

// ============================================================================
// /proc/<pid>/smaps Extended
// ============================================================================

pub const ProcSmapsEntry = struct {
    base: ProcMapsEntry,
    // Memory sizes (kB)
    size: u64,
    kernel_page_size: u64,
    mmu_page_size: u64,
    rss: u64,
    pss: u64,
    pss_dirty: u64,
    shared_clean: u64,
    shared_dirty: u64,
    private_clean: u64,
    private_dirty: u64,
    referenced: u64,
    anonymous: u64,
    lazy_free: u64,
    anon_huge_pages: u64,
    shmem_pmd_mapped: u64,
    file_pmd_mapped: u64,
    shared_hugetlb: u64,
    private_hugetlb: u64,
    swap: u64,
    swap_pss: u64,
    locked: u64,
    // VMA flags
    thp_eligible: bool,
    vm_flags: [64]u8,
};

// ============================================================================
// /proc/meminfo
// ============================================================================

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
    k_reclaimable: u64,
    slab: u64,
    s_reclaimable: u64,
    s_unreclaim: u64,
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
// sysfs Core
// ============================================================================

pub const SysfsDirEntryType = enum(u8) {
    dir = 0,
    file = 1,
    link = 2,
    bin = 3,
    group = 4,
};

pub const SysfsKernObj = struct {
    // sysfs directory
    name: [256]u8,
    parent: ?*SysfsKernObj,
    // Type
    ktype: ?*const SysfsKobjType,
    // sysfs_dirent
    sd: u64,
    // Refcount
    kref: u32,
    // kobject state
    state_initialized: bool,
    state_in_sysfs: bool,
    state_add_uevent_sent: bool,
    state_remove_uevent_sent: bool,
};

pub const SysfsKobjType = struct {
    release: ?*const fn (*SysfsKernObj) void,
    sysfs_ops: ?*const SysfsOps,
    default_groups: u64,
    namespace: ?*const fn (*SysfsKernObj) ?*const anyopaque,
    get_ownership: ?*const fn (*SysfsKernObj, *u32, *u32) void,
};

pub const SysfsOps = struct {
    show: ?*const fn (*SysfsKernObj, *SysfsAttribute, [*]u8) i64,
    store: ?*const fn (*SysfsKernObj, *SysfsAttribute, [*]const u8, u64) i64,
};

pub const SysfsAttribute = struct {
    name: [64]u8,
    mode: u16,
    // For binary attributes
    size: u64,
    read: ?*const fn (u64, *SysfsAttribute, [*]u8, u64, u64) i64,
    write: ?*const fn (u64, *SysfsAttribute, [*]const u8, u64, u64) i64,
    mmap: ?*const fn (u64, *SysfsAttribute, u64) i32,
};

// ============================================================================
// sysfs Bus/Class/Driver
// ============================================================================

pub const SysfsBusType = struct {
    name: [32]u8,
    dev_name: [32]u8,
    // Callbacks
    match_fn: ?*const fn (u64, u64) i32,
    uevent: ?*const fn (u64, u64) i32,
    probe: ?*const fn (u64) i32,
    remove: ?*const fn (u64) void,
    shutdown: ?*const fn (u64) void,
    // PM
    pm: u64,
    // Subsystem
    subsys_private: u64,
    // Groups
    bus_groups: u64,
    dev_groups: u64,
    drv_groups: u64,
    // Device count
    dev_count: u32,
    drv_count: u32,
};

pub const SysfsClass = struct {
    name: [32]u8,
    owner: u64,
    // Groups
    class_groups: u64,
    dev_groups: u64,
    // Callbacks
    dev_uevent: ?*const fn (u64, u64) i32,
    devnode: ?*const fn (u64, *u16) ?[*]u8,
    class_release: ?*const fn (*SysfsClass) void,
    dev_release: ?*const fn (u64) void,
    // PM
    pm: u64,
    // Subsys
    subsys: u64,
    // Namespace type
    ns_type: u64,
    namespace: ?*const fn (u64) ?*const anyopaque,
    get_ownership: ?*const fn (u64, *u32, *u32) void,
    // Device count
    dev_count: u32,
};

pub const SysfsDriver = struct {
    name: [32]u8,
    bus: ?*SysfsBusType,
    owner: u64,
    mod_name: [64]u8,
    // Callbacks
    probe: ?*const fn (u64) i32,
    remove: ?*const fn (u64) void,
    shutdown: ?*const fn (u64) void,
    suspend: ?*const fn (u64, u32) i32,
    resume: ?*const fn (u64) i32,
    // Groups
    groups: u64,
    // PM
    pm: u64,
    // bind count
    bind_count: u32,
    unbind_count: u32,
};

// ============================================================================
// Proc/Sysfs Stats
// ============================================================================

pub const ProcSysfsStats = struct {
    // procfs
    proc_entries: u32,
    proc_reads: u64,
    proc_writes: u64,
    proc_opens: u64,
    proc_pid_lookups: u64,
    // sysfs
    sysfs_dirs: u32,
    sysfs_files: u32,
    sysfs_links: u32,
    sysfs_reads: u64,
    sysfs_writes: u64,
    sysfs_uevent_sent: u64,
    // Bus/Class/Driver
    buses_registered: u32,
    classes_registered: u32,
    drivers_registered: u32,
};

// ============================================================================
// Proc/Sysfs Manager
// ============================================================================

pub const ProcSysfsManager = struct {
    proc_root: ?*ProcDirEntry,
    proc_net: ?*ProcDirEntry,
    proc_self: ?*ProcDirEntry,
    proc_thread_self: ?*ProcDirEntry,
    sysfs_root: ?*SysfsKernObj,
    stats: ProcSysfsStats,
    initialized: bool,

    pub fn init() ProcSysfsManager {
        return ProcSysfsManager{
            .proc_root = null,
            .proc_net = null,
            .proc_self = null,
            .proc_thread_self = null,
            .sysfs_root = null,
            .stats = ProcSysfsStats{
                .proc_entries = 0,
                .proc_reads = 0,
                .proc_writes = 0,
                .proc_opens = 0,
                .proc_pid_lookups = 0,
                .sysfs_dirs = 0,
                .sysfs_files = 0,
                .sysfs_links = 0,
                .sysfs_reads = 0,
                .sysfs_writes = 0,
                .sysfs_uevent_sent = 0,
                .buses_registered = 0,
                .classes_registered = 0,
                .drivers_registered = 0,
            },
            .initialized = true,
        };
    }
};
