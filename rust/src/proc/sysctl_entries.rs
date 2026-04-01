// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust Process / sysctl entries detail
//! /proc/<pid>/* entries, sysctl table, proc_ops Rust bindings,
//! /proc/sys/ hierarchy, auto-registration, seq_file integration

#![allow(dead_code)]

use core::sync::atomic::AtomicU64;

// ============================================================================
// Proc PID entries - Rust side
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcPidEntry {
    Status = 0,
    Stat = 1,
    Statm = 2,
    Cmdline = 3,
    Environ = 4,
    Maps = 5,
    Smaps = 6,
    SmapsRollup = 7,
    Pagemap = 8,
    Mem = 9,
    Mountinfo = 10,
    Mounts = 11,
    Mountstats = 12,
    Cgroup = 13,
    Oom_score = 14,
    Oom_score_adj = 15,
    Limits = 16,
    Io = 17,
    Comm = 18,
    Exe = 19,
    Cwd = 20,
    Root = 21,
    Fd = 22,
    Fdinfo = 23,
    Ns = 24,
    Net = 25,
    Auxv = 26,
    Stack = 27,
    Wchan = 28,
    Timers = 29,
    Numa_maps = 30,
    Syscall = 31,
    Loginuid = 32,
    Sessionid = 33,
    Attr = 34,
    Sched = 35,
    Schedstat = 36,
    Cpuset = 37,
    Personality = 38,
    Children = 39,
    Coredump_filter = 40,
    Clear_refs = 41,
    Task = 42,
    Autogroup = 43,
    Timerslack_ns = 44,
    Patch_state = 45,
    Arch_status = 46,
    Seccomp = 47,
    Projid_map = 48,
    Uid_map = 49,
    Gid_map = 50,
    Setgroups = 51,
    Ksm_merging_pages = 52,
    Ksm_stat = 53,
}

// ============================================================================
// /proc/stat
// ============================================================================

#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcStatGlobal {
    pub cpu_total: CpuTime,
    pub per_cpu: [CpuTime; 256],
    pub nr_cpus_online: u32,
    pub intr_count: u64,
    pub ctxt_switches: u64,
    pub btime: u64,          // boot time (seconds since epoch)
    pub processes: u64,      // forks since boot
    pub procs_running: u32,
    pub procs_blocked: u32,
    pub softirq: [u64; 10],  // per-softirq type
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CpuTime {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

// ============================================================================
// /proc/meminfo
// ============================================================================

#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcMeminfo {
    pub mem_total: u64,
    pub mem_free: u64,
    pub mem_available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_cached: u64,
    pub active: u64,
    pub inactive: u64,
    pub active_anon: u64,
    pub inactive_anon: u64,
    pub active_file: u64,
    pub inactive_file: u64,
    pub unevictable: u64,
    pub mlocked: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub zswap: u64,
    pub zswapped: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub anon_pages: u64,
    pub mapped: u64,
    pub shmem: u64,
    pub kreclaimable: u64,
    pub slab: u64,
    pub sreclaimable: u64,
    pub sunreclaim: u64,
    pub kernel_stack: u64,
    pub page_tables: u64,
    pub sec_page_tables: u64,
    pub nfs_unstable: u64,
    pub bounce: u64,
    pub writeback_tmp: u64,
    pub commit_limit: u64,
    pub committed_as: u64,
    pub vmalloc_total: u64,
    pub vmalloc_used: u64,
    pub vmalloc_chunk: u64,
    pub percpu: u64,
    pub hardware_corrupted: u64,
    pub anon_huge_pages: u64,
    pub shmem_huge_pages: u64,
    pub shmem_pmd_mapped: u64,
    pub file_huge_pages: u64,
    pub file_pmd_mapped: u64,
    pub cma_total: u64,
    pub cma_free: u64,
    pub hugepages_total: u64,
    pub hugepages_free: u64,
    pub hugepages_rsvd: u64,
    pub hugepages_surp: u64,
    pub hugepagesize: u64,
    pub hugetlb: u64,
    pub direct_map_4k: u64,
    pub direct_map_2m: u64,
    pub direct_map_1g: u64,
}

// ============================================================================
// /proc/vmstat
// ============================================================================

#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcVmstat {
    pub nr_free_pages: u64,
    pub nr_zone_inactive_anon: u64,
    pub nr_zone_active_anon: u64,
    pub nr_zone_inactive_file: u64,
    pub nr_zone_active_file: u64,
    pub nr_zone_unevictable: u64,
    pub nr_zone_write_pending: u64,
    pub nr_mlock: u64,
    pub nr_bounce: u64,
    pub nr_zspages: u64,
    pub nr_free_cma: u64,
    // Page faults
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub pgrefill: u64,
    pub pgsteal_kswapd: u64,
    pub pgsteal_direct: u64,
    pub pgsteal_khugepaged: u64,
    pub pgscan_kswapd: u64,
    pub pgscan_direct: u64,
    pub pgscan_khugepaged: u64,
    pub pginodesteal: u64,
    pub slabs_scanned: u64,
    pub kswapd_inodesteal: u64,
    pub kswapd_low_wmark_hit_quickly: u64,
    pub kswapd_high_wmark_hit_quickly: u64,
    // Page allocation
    pub pgalloc_dma: u64,
    pub pgalloc_dma32: u64,
    pub pgalloc_normal: u64,
    pub pgalloc_movable: u64,
    pub pgfree: u64,
    pub pgactivate: u64,
    pub pgdeactivate: u64,
    pub pglazyfree: u64,
    pub pglazyfreed: u64,
    // Compaction
    pub compact_stall: u64,
    pub compact_fail: u64,
    pub compact_success: u64,
    pub compact_daemon_wake: u64,
    pub compact_daemon_migrate_scanned: u64,
    pub compact_daemon_free_scanned: u64,
    // THP
    pub thp_fault_alloc: u64,
    pub thp_fault_fallback: u64,
    pub thp_fault_fallback_charge: u64,
    pub thp_collapse_alloc: u64,
    pub thp_collapse_alloc_failed: u64,
    pub thp_split_page: u64,
    pub thp_split_page_failed: u64,
    pub thp_deferred_split_page: u64,
    pub thp_split_pmd: u64,
    pub thp_scan_exceed_none_pte: u64,
    pub thp_scan_exceed_swap_pte: u64,
    pub thp_scan_exceed_shared_pte: u64,
    pub thp_zero_page_alloc: u64,
    pub thp_zero_page_alloc_failed: u64,
    pub thp_swpout: u64,
    pub thp_swpout_fallback: u64,
    // NUMA
    pub pgpromote_success: u64,
    pub pgpromote_candidate: u64,
    pub pgdemote_kswapd: u64,
    pub pgdemote_direct: u64,
    pub pgdemote_khugepaged: u64,
    pub numa_hint_faults: u64,
    pub numa_hint_faults_local: u64,
    pub numa_pages_migrated: u64,
}

// ============================================================================
// sysctl table
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysctlType {
    Int = 0,
    Uint = 1,
    Long = 2,
    Ulong = 3,
    String = 4,
    Bool = 5,
}

#[repr(C)]
pub struct CtlTable {
    pub procname: [64]u8,
    pub procname_len: u16,
    pub data: u64,             // pointer to actual data
    pub maxlen: u32,
    pub mode: u16,             // file permissions (0644 etc)
    pub ctl_type: SysctlType,
    pub proc_handler: u64,     // fn ptr
    pub extra1: u64,           // min value / extra context
    pub extra2: u64,           // max value / extra context
    pub child: u64,            // ctl_table * for sub-directory
}

/// Well-known sysctl paths
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SysctlKnownPaths {
    // kernel.*
    KernelHostname = 0,
    KernelDomainname = 1,
    KernelMaxThreads = 2,
    KernelPanicTimeout = 3,
    KernelSchedLatencyNs = 4,
    KernelSchedMinGranNs = 5,
    KernelSchedWakeupGranNs = 6,
    KernelSchedChildRunsFirst = 7,
    KernelMsgmax = 8,
    KernelMsgmni = 9,
    KernelMsgmnb = 10,
    KernelShmmax = 11,
    KernelShmall = 12,
    KernelShmmni = 13,
    KernelSemaphores = 14,
    KernelPid_max = 15,
    KernelPrintk = 16,
    KernelRandomize_va_space = 17,
    KernelSysrq = 18,
    KernelCore_pattern = 19,
    KernelModprobe = 20,
    // vm.*
    VmDirtyRatio = 30,
    VmDirtyBackgroundRatio = 31,
    VmDirtyExpireCentisecs = 32,
    VmDirtyWritebackCentisecs = 33,
    VmSwappiness = 34,
    VmOvercommitMemory = 35,
    VmOvercommitRatio = 36,
    VmVfsCachePressure = 37,
    VmMinFreeKbytes = 38,
    VmZoneReclaimMode = 39,
    VmCompactMemory = 40,
    VmNumaZoneReclaimMode = 41,
    VmDropCaches = 42,
    VmMaxMapCount = 43,
    VmExtfragThreshold = 44,
    VmNrHugepages = 45,
    VmHugepagesMadvise = 46,
    VmTHPEnabled = 47,
    VmTHPDefrag = 48,
    // net.core.*
    NetCoreRmemDefault = 60,
    NetCoreRmemMax = 61,
    NetCoreWmemDefault = 62,
    NetCoreWmemMax = 63,
    NetCoreSoMaxconn = 64,
    NetCoreNetdevBudget = 65,
    NetCoreNetdevMaxBacklog = 66,
    NetCoreOptmemMax = 67,
    NetCoreBpfJitEnable = 68,
    // net.ipv4.*
    NetIpv4TcpWmem = 80,
    NetIpv4TcpRmem = 81,
    NetIpv4TcpMaxSynBacklog = 82,
    NetIpv4TcpSyncookies = 83,
    NetIpv4TcpTimestamps = 84,
    NetIpv4TcpSack = 85,
    NetIpv4TcpWindowScaling = 86,
    NetIpv4TcpFastopen = 87,
    NetIpv4TcpKeepaliveTime = 88,
    NetIpv4TcpKeepaliveProbes = 89,
    NetIpv4TcpKeepaliveIntvl = 90,
    NetIpv4TcpFinTimeout = 91,
    NetIpv4TcpMaxOrphan = 92,
    NetIpv4TcpMaxTwBuckets = 93,
    NetIpv4TcpCongestionControl = 94,
    NetIpv4IpForward = 95,
    NetIpv4IcmpEchoIgnoreAll = 96,
    NetIpv4IcmpEchoIgnoreBroadcasts = 97,
    // net.ipv6.*
    NetIpv6ConfAllForwarding = 110,
    NetIpv6ConfAllAcceptRa = 111,
    // fs.*
    FsFileMax = 120,
    FsFileNr = 121,
    FsInodeNr = 122,
    FsInodeState = 123,
    FsDentryState = 124,
    FsAioMaxNr = 125,
    FsAioNr = 126,
    FsEpollMaxUserWatches = 127,
    FsInotifyMaxUserWatches = 128,
    FsInotifyMaxUserInstances = 129,
    FsPipeMaxSize = 130,
    FsProtectedHardlinks = 131,
    FsProtectedSymlinks = 132,
    FsProtectedFifos = 133,
    FsProtectedRegular = 134,
}

// ============================================================================
// seq_file integration
// ============================================================================

#[repr(C)]
pub struct SeqFile {
    pub buf: u64,            // char *
    pub size: usize,
    pub from: usize,
    pub count: usize,
    pub pad_until: u64,
    pub index: u64,
    pub read_pos: u64,
    pub private: u64,
    pub op: u64,             // seq_operations *
    pub file: u64,           // struct file *
    pub version: u64,
}

#[repr(C)]
pub struct SeqOperations {
    pub start: u64,          // fn(*SeqFile, *loff_t) -> *void
    pub stop: u64,           // fn(*SeqFile, *void)
    pub next: u64,           // fn(*SeqFile, *void, *loff_t) -> *void
    pub show: u64,           // fn(*SeqFile, *void) -> i32
}

// ============================================================================
// Proc ops
// ============================================================================

#[repr(C)]
pub struct ProcOps {
    pub proc_flags: u32,
    pub proc_open: u64,
    pub proc_read: u64,
    pub proc_read_iter: u64,
    pub proc_write: u64,
    pub proc_lseek: u64,
    pub proc_release: u64,
    pub proc_poll: u64,
    pub proc_ioctl: u64,
    pub proc_mmap: u64,
    pub proc_get_unmapped_area: u64,
}

// ============================================================================
// ProcSysctlManager
// ============================================================================

#[derive(Debug)]
pub struct ProcSysctlManager {
    pub registered_entries: u32,
    pub registered_sysctls: u32,
    pub sysctl_reads: AtomicU64,
    pub sysctl_writes: AtomicU64,
    pub proc_lookups: AtomicU64,
    pub proc_reads: AtomicU64,
    pub initialized: bool,
}

impl ProcSysctlManager {
    pub fn new() -> Self {
        Self {
            registered_entries: 0,
            registered_sysctls: 0,
            sysctl_reads: AtomicU64::new(0),
            sysctl_writes: AtomicU64::new(0),
            proc_lookups: AtomicU64::new(0),
            proc_reads: AtomicU64::new(0),
            initialized: true,
        }
    }
}
