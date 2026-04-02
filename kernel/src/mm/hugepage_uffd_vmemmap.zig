// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Huge Pages, Userfaultfd, ioremap, memfd, vmemmap
// THP, hugetlbfs, khugepaged, userfaultfd, ioremap/memtype, memfd

const std = @import("std");

// ============================================================================
// Transparent Huge Pages (THP)
// ============================================================================

pub const ThpConfig = struct {
    enabled: ThpPolicy,
    defrag: ThpDefragPolicy,
    use_zero_page: bool,
    max_ptes_none: u32,
    max_ptes_swap: u32,
    max_ptes_shared: u32,
    scan_sleep_ms: u32,
    alloc_sleep_ms: u32,
    pages_to_scan: u32,
    pages_collapsed: u64,
    full_scans: u64,
    pages_allocated: u64,
    khugepaged_succ: u64,
    khugepaged_fail: u64,

    pub fn default() ThpConfig {
        return .{
            .enabled = .MAdvise,
            .defrag = .MAdvise,
            .use_zero_page = true,
            .max_ptes_none = 511,
            .max_ptes_swap = 64,
            .max_ptes_shared = 256,
            .scan_sleep_ms = 10000,
            .alloc_sleep_ms = 60000,
            .pages_to_scan = 4096,
            .pages_collapsed = 0,
            .full_scans = 0,
            .pages_allocated = 0,
            .khugepaged_succ = 0,
            .khugepaged_fail = 0,
        };
    }
};

pub const ThpPolicy = enum(u8) {
    Always = 0,
    MAdvise = 1,
    Never = 2,
};

pub const ThpDefragPolicy = enum(u8) {
    Always = 0,
    Defer = 1,
    DeferMAdvise = 2,
    MAdvise = 3,
    Never = 4,
};

pub const ThpHugeSize = enum(u8) {
    PMD = 0,
    PUD = 1,
};

pub const ThpPerSizeConfig = struct {
    size_kb: u64,
    enabled: ThpPolicy,
    defrag: ThpDefragPolicy,
    allocation_order: u8,
    total_allocated: u64,
    total_split: u64,
    total_collapsed: u64,
};

// ============================================================================
// HugeTLB
// ============================================================================

pub const HugetlbPageSize = enum(u8) {
    Size2MB = 0,
    Size1GB = 1,
    Size16KB = 2,  // ARM
    Size32MB = 3,  // ARM
    Size512MB = 4, // ARM
    Size16GB = 5,  // PPC
};

pub const HugetlbPool = struct {
    page_size: u64,
    nr_hugepages: u64,
    free_hugepages: u64,
    surplus_hugepages: u64,
    resv_hugepages: u64,
    nr_overcommit: u64,
    max_huge_pages: u64,
    nr_hugepages_node: [64]u64,   // per-NUMA
    free_hugepages_node: [64]u64,
    surplus_node: [64]u64,
    total_nodes: u32,
};

pub const HugetlbCgroup = struct {
    limit_in_bytes: i64,
    usage_in_bytes: u64,
    max_usage_in_bytes: u64,
    failcnt: u64,
    rsvd_limit_in_bytes: i64,
    rsvd_usage_in_bytes: u64,
    rsvd_max_usage_in_bytes: u64,
    rsvd_failcnt: u64,
};

pub const HugetlbFsConfig = struct {
    min_hpages: u64,
    max_hpages: i64,
    mode: u16,
    uid: u32,
    gid: u32,
    page_size: u64,
};

// ============================================================================
// Userfaultfd
// ============================================================================

pub const UserfaultfdFeatures = packed struct(u64) {
    pagefault_flag_wp: bool = false,
    event_fork: bool = false,
    event_remap: bool = false,
    event_remove: bool = false,
    missing_hugetlbfs: bool = false,
    missing_shmem: bool = false,
    event_unmap: bool = false,
    sigbus: bool = false,
    thread_id: bool = false,
    minor_hugetlbfs: bool = false,
    minor_shmem: bool = false,
    exact_address: bool = false,
    wp_hugetlbfs_shmem: bool = false,
    wp_unpopulated: bool = false,
    poison: bool = false,
    wp_async: bool = false,
    move: bool = false,
    _reserved: u47 = 0,
};

pub const UffdioRegister = extern struct {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
};

pub const UffdioRange = extern struct {
    start: u64,
    len: u64,
};

pub const UffdRegisterMode = packed struct(u64) {
    missing: bool = false,
    wp: bool = false,
    minor: bool = false,
    _reserved: u61 = 0,
};

pub const UffdEvent = enum(u8) {
    Pagefault = 0x12,
    Fork = 0x13,
    Remap = 0x14,
    Remove = 0x15,
    Unmap = 0x16,
};

pub const UserfaultfdMsg = extern struct {
    event: u8,
    _reserved1: u8,
    _reserved2: u16,
    _reserved3: u32,
    // union based on event type
    arg_address: u64,
    arg_flags: u64,
    arg_ptid: u32,
    _pad: u32,
};

pub const UffdIoctl = struct {
    pub const UFFDIO_API: u64 = 0xC018AA3F;
    pub const UFFDIO_REGISTER: u64 = 0xC020AA00;
    pub const UFFDIO_UNREGISTER: u64 = 0x8010AA01;
    pub const UFFDIO_WAKE: u64 = 0x8010AA02;
    pub const UFFDIO_COPY: u64 = 0xC028AA03;
    pub const UFFDIO_ZEROPAGE: u64 = 0xC020AA04;
    pub const UFFDIO_WRITEPROTECT: u64 = 0xC018AA06;
    pub const UFFDIO_CONTINUE: u64 = 0xC018AA07;
    pub const UFFDIO_POISON: u64 = 0xC018AA08;
    pub const UFFDIO_MOVE: u64 = 0xC028AA09;
};

// ============================================================================
// ioremap / memtype
// ============================================================================

pub const IoremapType = enum(u8) {
    NoCache = 0,        // ioremap_nocache / ioremap
    WriteBack = 1,      // ioremap_cache
    WriteCombine = 2,   // ioremap_wc
    WriteThrough = 3,   // ioremap_wt
    Encrypted = 4,      // ioremap_encrypted
    Prot = 5,           // ioremap_prot
};

pub const MemTypeEntry = struct {
    start: u64,
    end: u64,
    mem_type: PatMemType,
};

pub const PatMemType = enum(u8) {
    WriteBack = 0,
    WriteCombining = 1,
    Uncached = 2,
    UncachableMinus = 3,
    WriteThrough = 4,
    WriteProtect = 5,
};

pub const IoMemResource = struct {
    name: [64]u8,
    start: u64,
    end: u64,
    flags: IoResourceFlags,
    parent: ?*IoMemResource,
    sibling: ?*IoMemResource,
    child: ?*IoMemResource,
};

pub const IoResourceFlags = packed struct(u64) {
    io: bool = false,
    mem: bool = false,
    irq: bool = false,
    dma: bool = false,
    prefetch: bool = false,
    readonly: bool = false,
    disabled: bool = false,
    unset: bool = false,
    auto: bool = false,
    busy: bool = false,
    exclusive: bool = false,
    rangelength: bool = false,
    shadowable: bool = false,
    cacheable: bool = false,
    window: bool = false,
    bus_has_vga: bool = false,
    rom_enable: bool = false,
    pci_ea_brs: bool = false,
    _reserved: u46 = 0,
};

// ============================================================================
// memfd
// ============================================================================

pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_HUGETLB: u32 = 0x0004;
pub const MFD_NOEXEC_SEAL: u32 = 0x0008;
pub const MFD_EXEC: u32 = 0x0010;

pub const MemfdSealFlags = packed struct(u32) {
    seal: bool = false,       // F_SEAL_SEAL
    shrink: bool = false,     // F_SEAL_SHRINK
    grow: bool = false,       // F_SEAL_GROW
    write: bool = false,      // F_SEAL_WRITE
    future_write: bool = false, // F_SEAL_FUTURE_WRITE
    exec: bool = false,       // F_SEAL_EXEC
    _reserved: u26 = 0,
};

pub const MemfdState = struct {
    name: [256]u8,
    name_len: u16,
    flags: u32,
    seals: MemfdSealFlags,
    size: u64,
    file_inode: u64,
    hugetlb_size: u64,
};

// ============================================================================
// vmemmap
// ============================================================================

pub const VmemmapConfig = struct {
    start: u64,
    end: u64,
    section_size: u64,
    pages_per_section: u64,
    total_sections: u64,
    present_sections: u64,
    online_sections: u64,
    vmemmap_base: u64,
    vmemmap_shift: u8,
    vmemmap_pgtable_levels: u8,
    sparse_vmemmap: bool,
    optimize_vmemmap_enabled: bool,
    nr_free_vmemmap: u64,
};

pub const MemSectionState = enum(u8) {
    NotPresent = 0,
    Present = 1,
    Online = 2,
    GoingOffline = 3,
};

pub const PageFlags = packed struct(u64) {
    locked: bool = false,
    error: bool = false,
    referenced: bool = false,
    uptodate: bool = false,
    dirty: bool = false,
    lru: bool = false,
    active: bool = false,
    workingset: bool = false,
    waiters: bool = false,
    slab: bool = false,
    owner_priv_1: bool = false,
    private: bool = false,
    private_2: bool = false,
    writeback: bool = false,
    head: bool = false,
    mappedtodisk: bool = false,
    reclaim: bool = false,
    swapbacked: bool = false,
    unevictable: bool = false,
    mlocked: bool = false,
    uncached: bool = false,
    hwpoison: bool = false,
    isolated: bool = false,
    reported: bool = false,
    skip_kasan_poison: bool = false,
    _reserved: u7 = 0,
    zone: u4 = 0,
    nid: u12 = 0,
    section: u16 = 0,
};

pub const FolioFlags = packed struct(u64) {
    large: bool = false,
    large_rmappable: bool = false,
    partially_mapped: bool = false,
    _inherited: u61 = 0,
};

pub const FolioCommon = struct {
    flags: PageFlags,
    mapping: u64,
    index: u64,
    private: u64,
    refcount: i32,
    mapcount: i32,
    order: u8,
    mlock_count: u32,
    pincount: i32,
    memcg: u64,
    lru: ListHead,
    deferred_list: ListHead,
};

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,
};

// ============================================================================
// Kernel Samepage Merging (KSM) extended
// ============================================================================

pub const KsmConfig = struct {
    run: KsmRunMode,
    sleep_ms: u32,
    max_page_sharing: u32,
    pages_to_scan: u32,
    use_zero_pages: bool,
    merge_across_nodes: bool,
    advisor_mode: KsmAdvisorMode,
    advisor_max_cpu: u8,
    advisor_min_pages_to_scan: u32,
    advisor_max_pages_to_scan: u32,
    advisor_target_scan_time: u32,
    // stats
    pages_shared: u64,
    pages_sharing: u64,
    pages_unshared: u64,
    pages_volatile: u64,
    full_scans: u64,
    stable_node_chains: u64,
    stable_node_dups: u64,
};

pub const KsmRunMode = enum(u8) {
    Stop = 0,
    Run = 1,
    Unmerge = 2,
};

pub const KsmAdvisorMode = enum(u8) {
    None = 0,
    ScanTime = 1,
};

// ============================================================================
// DAMON (Data Access MONitoring)
// ============================================================================

pub const DamonConfig = struct {
    sample_interval_us: u64,
    aggr_interval_us: u64,
    update_interval_us: u64,
    min_nr_regions: u32,
    max_nr_regions: u32,
    ops_type: DamonOpsType,
};

pub const DamonOpsType = enum(u8) {
    VAddr = 0,
    PAddr = 1,
    FVAddr = 2,
};

pub const DamonScheme = struct {
    pattern: DamonAccessPattern,
    action: DamonAction,
    quota: DamonQuota,
    watermarks: DamonWmarks,
};

pub const DamonAccessPattern = struct {
    min_sz_region: u64,
    max_sz_region: u64,
    min_nr_accesses: u32,
    max_nr_accesses: u32,
    min_age_region: u32,
    max_age_region: u32,
};

pub const DamonAction = enum(u8) {
    WillneedHint = 0,
    ColdHint = 1,
    PageOut = 2,
    HugePage = 3,
    NoHugePage = 4,
    LruPrio = 5,
    LruDeprio = 6,
    MigrateCold = 7,
    MigrateHot = 8,
    Stat = 9,
};

pub const DamonQuota = struct {
    ms: u64,
    sz: u64,
    reset_interval_ms: u64,
    weight_sz: u32,
    weight_nr_accesses: u32,
    weight_age: u32,
};

pub const DamonWmarks = struct {
    metric: DamonWmarkMetric,
    interval_us: u64,
    high: u64,
    mid: u64,
    low: u64,
};

pub const DamonWmarkMetric = enum(u8) {
    None = 0,
    FreeMemPct = 1,
};

// ============================================================================
// Memory Manager
// ============================================================================

pub const HugePageMemManager = struct {
    thp_config: ThpConfig,
    hugetlb_pools: [6]HugetlbPool,
    nr_hugetlb_pools: u8,
    vmemmap_config: VmemmapConfig,
    ksm_config: KsmConfig,
    damon_config: DamonConfig,
    total_uffd_instances: u32,
    total_memfd_instances: u32,
    total_ioremap_regions: u32,
    initialized: bool,

    pub fn init() HugePageMemManager {
        return .{
            .thp_config = ThpConfig.default(),
            .hugetlb_pools = undefined,
            .nr_hugetlb_pools = 0,
            .vmemmap_config = undefined,
            .ksm_config = undefined,
            .damon_config = undefined,
            .total_uffd_instances = 0,
            .total_memfd_instances = 0,
            .total_ioremap_regions = 0,
            .initialized = true,
        };
    }
};
