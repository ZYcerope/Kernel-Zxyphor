// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced Memory Mapping and Virtual Memory Areas
// mmap/munmap, VMA management, VMA merging, mremap, mprotect, mlock,
// userfaultfd, guard pages, madvise, page fault handling, ASLR
// More advanced than Linux 2026 mm subsystem

const std = @import("std");

// ============================================================================
// Memory Protection Flags
// ============================================================================

pub const PROT_NONE: u32 = 0x0;
pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;
pub const PROT_SEM: u32 = 0x8;
pub const PROT_GROWSDOWN: u32 = 0x01000000;
pub const PROT_GROWSUP: u32 = 0x02000000;

// ============================================================================
// mmap Flags
// ============================================================================

pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_SHARED_VALIDATE: u32 = 0x03;
pub const MAP_TYPE: u32 = 0x0f;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_GROWSDOWN: u32 = 0x100;
pub const MAP_DENYWRITE: u32 = 0x800;
pub const MAP_EXECUTABLE: u32 = 0x1000;
pub const MAP_LOCKED: u32 = 0x2000;
pub const MAP_NORESERVE: u32 = 0x4000;
pub const MAP_POPULATE: u32 = 0x8000;
pub const MAP_NONBLOCK: u32 = 0x10000;
pub const MAP_STACK: u32 = 0x20000;
pub const MAP_HUGETLB: u32 = 0x40000;
pub const MAP_SYNC: u32 = 0x80000;
pub const MAP_FIXED_NOREPLACE: u32 = 0x100000;
pub const MAP_UNINITIALIZED: u32 = 0x4000000;

// HugeTLB size encoding
pub const MAP_HUGE_SHIFT: u32 = 26;
pub const MAP_HUGE_MASK: u32 = 0x3f;
pub const MAP_HUGE_2MB: u32 = 21 << MAP_HUGE_SHIFT;
pub const MAP_HUGE_1GB: u32 = 30 << MAP_HUGE_SHIFT;

// ============================================================================
// madvise Flags
// ============================================================================

pub const MADV_NORMAL: u32 = 0;
pub const MADV_RANDOM: u32 = 1;
pub const MADV_SEQUENTIAL: u32 = 2;
pub const MADV_WILLNEED: u32 = 3;
pub const MADV_DONTNEED: u32 = 4;
pub const MADV_FREE: u32 = 8;
pub const MADV_REMOVE: u32 = 9;
pub const MADV_DONTFORK: u32 = 10;
pub const MADV_DOFORK: u32 = 11;
pub const MADV_MERGEABLE: u32 = 12;
pub const MADV_UNMERGEABLE: u32 = 13;
pub const MADV_HUGEPAGE: u32 = 14;
pub const MADV_NOHUGEPAGE: u32 = 15;
pub const MADV_DONTDUMP: u32 = 16;
pub const MADV_DODUMP: u32 = 17;
pub const MADV_WIPEONFORK: u32 = 18;
pub const MADV_KEEPONFORK: u32 = 19;
pub const MADV_COLD: u32 = 20;
pub const MADV_PAGEOUT: u32 = 21;
pub const MADV_POPULATE_READ: u32 = 22;
pub const MADV_POPULATE_WRITE: u32 = 23;
pub const MADV_DONTNEED_LOCKED: u32 = 24;
pub const MADV_COLLAPSE: u32 = 25;
// Zxyphor
pub const MADV_ZXY_PREFETCH: u32 = 100;
pub const MADV_ZXY_COMPRESS: u32 = 101;

// ============================================================================
// VMA Flags
// ============================================================================

pub const VmaFlags = packed struct(u64) {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
    shared: bool = false,
    mayread: bool = false,
    maywrite: bool = false,
    mayexec: bool = false,
    mayshare: bool = false,
    growsdown: bool = false,
    growsup: bool = false,
    pfnmap: bool = false,            // Page frame numbers
    locked: bool = false,
    io: bool = false,                // Memory mapped I/O
    seq_read: bool = false,
    rand_read: bool = false,
    dontcopy: bool = false,
    dontexpand: bool = false,
    lockonfault: bool = false,
    account: bool = false,
    noreserve: bool = false,
    hugetlb: bool = false,
    sync: bool = false,
    arch_1: bool = false,
    wipeonfork: bool = false,
    dontdump: bool = false,
    softdirty: bool = false,
    mixedmap: bool = false,
    hugepage: bool = false,
    nohugepage: bool = false,
    mergeable: bool = false,
    uffd_missing: bool = false,
    uffd_wp: bool = false,
    uffd_minor: bool = false,
    // Stack
    stack: bool = false,
    // Shadow stack
    shadow_stack: bool = false,
    // Zxyphor
    zxy_encrypted: bool = false,
    zxy_compressed: bool = false,
    zxy_pinned: bool = false,
    zxy_monitored: bool = false,
    _reserved: u25 = 0,

    pub fn is_anonymous(self: VmaFlags) bool {
        return !self.shared and !self.pfnmap;
    }

    pub fn is_cow(self: VmaFlags) bool {
        return !self.shared and self.write;
    }
};

// ============================================================================
// Virtual Memory Area
// ============================================================================

pub const VmaType = enum(u8) {
    anonymous = 0,
    file_backed = 1,
    shared_memory = 2,
    device_memory = 3,
    stack = 4,
    heap = 5,
    vdso = 6,
    vsyscall = 7,
    gate = 8,
    // Zxyphor
    zxy_secure = 10,
};

pub const Vma = struct {
    // Address range
    vm_start: u64,
    vm_end: u64,
    // Flags
    vm_flags: VmaFlags,
    // Page protection
    vm_page_prot: u64,
    // RB tree linkage
    rb_parent: ?*Vma,
    rb_left: ?*Vma,
    rb_right: ?*Vma,
    rb_color: u1,       // 0=red, 1=black
    // Linked list
    vm_next: ?*Vma,
    vm_prev: ?*Vma,
    // Owner
    vm_mm: u64,          // Pointer to mm_struct
    // File mapping
    vm_file: u64,        // Pointer to file
    vm_pgoff: u64,       // Page offset in file
    // Anon
    anon_vma: u64,       // Pointer to anon_vma
    anon_vma_chain: u64,
    // Type
    vma_type: VmaType,
    // Policy
    vm_policy: u64,      // NUMA policy
    // Userfaultfd
    vm_userfaultfd_ctx: u64,
    // Stats
    nr_pages_mapped: u64,
    nr_pages_resident: u64,
    nr_pages_swapped: u64,
    nr_pages_shared: u64,
    // Huge pages
    nr_thp_mapped: u64,
    // Access tracking
    access_count: u64,
    last_access_ns: u64,
    // KSM
    ksm_merging: bool,
    ksm_merged_pages: u64,
    // Locking
    locked: bool,
    lock_count: u32,

    pub fn size(self: *const Vma) u64 {
        return self.vm_end - self.vm_start;
    }

    pub fn nr_pages(self: *const Vma) u64 {
        return self.size() >> 12; // 4KB pages
    }

    pub fn contains(self: *const Vma, addr: u64) bool {
        return addr >= self.vm_start and addr < self.vm_end;
    }

    pub fn overlaps(self: *const Vma, start: u64, end: u64) bool {
        return self.vm_start < end and start < self.vm_end;
    }

    pub fn is_mergeable_with(self: *const Vma, other: *const Vma) bool {
        // Adjacent VMAs with same flags/protection can merge
        if (self.vm_end != other.vm_start) return false;
        if (@as(u64, @bitCast(self.vm_flags)) != @as(u64, @bitCast(other.vm_flags))) return false;
        if (self.vm_page_prot != other.vm_page_prot) return false;
        if (self.vm_file != other.vm_file) return false;
        if (self.vm_policy != other.vm_policy) return false;
        return true;
    }

    pub fn resident_pct(self: *const Vma) u32 {
        const total = self.nr_pages();
        if (total == 0) return 0;
        return @intCast((self.nr_pages_resident * 100) / total);
    }
};

// ============================================================================
// MM Struct (Process Address Space)
// ============================================================================

pub const MmStruct = struct {
    // VMA management
    mmap: ?*Vma,         // Linked list head
    mm_rb_root: u64,    // RB tree root
    mmap_cache: ?*Vma,   // Last find_vma result
    nr_vmas: u32,
    map_count: u32,
    // Locks
    mmap_lock_seq: u64,  // Read-write seqlock
    // Address space bounds
    mmap_base: u64,
    mmap_legacy_base: u64,
    task_size: u64,
    highest_vm_end: u64,
    // Page table
    pgd: u64,            // Page Global Directory
    // Users
    mm_users: u32,       // Address space users
    mm_count: u32,       // Reference count
    // Counters
    total_vm: u64,       // Total pages mapped
    locked_vm: u64,      // Pages locked
    pinned_vm: u64,      // Pages pinned
    data_vm: u64,        // Data + stack pages
    exec_vm: u64,        // Executable pages
    stack_vm: u64,       // Stack pages
    // Segments
    start_code: u64,
    end_code: u64,
    start_data: u64,
    end_data: u64,
    start_brk: u64,
    brk: u64,
    start_stack: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
    // RSS (Resident Set Size)
    rss_stat: [4]i64,    // file, anon, shmem, swap
    // HugeTLB
    hugetlb_usage: u64,
    // Context
    context: MmContext,
    // Flags
    def_flags: u32,
    // Core dump
    core_state: u64,
    // ASLR
    has_pinned: bool,
    // OOM
    oom_kill_disable: bool,
    // Uprobes
    uprobes_state: u64,
    // Stats
    nr_ptes: u64,
    nr_pmds: u64,
    nr_puds: u64,
    // NUMA
    numa_next_scan: u64,
    numa_scan_offset: u64,
    numa_scan_seq: u32,
    // Zxyphor
    zxy_aslr_entropy_bits: u8,
    zxy_memory_encrypted: bool,

    pub fn total_rss(self: *const MmStruct) i64 {
        var total: i64 = 0;
        for (self.rss_stat) |s| {
            total += s;
        }
        return total;
    }

    pub fn heap_size(self: *const MmStruct) u64 {
        return self.brk - self.start_brk;
    }

    pub fn code_size(self: *const MmStruct) u64 {
        return self.end_code - self.start_code;
    }

    pub fn data_size(self: *const MmStruct) u64 {
        return self.end_data - self.start_data;
    }
};

pub const MmContext = struct {
    ctx_id: u64,
    // TLB
    tlb_gen: u64,
    // PCID/ASID
    asid: u16,
    asid_gen: u64,
    // LDT
    ldt: u64,
    // PKU
    pkey_allocation_map: u16,
    execute_only_pkey: i16,
};

// ============================================================================
// Page Fault
// ============================================================================

pub const FaultFlags = packed struct(u32) {
    write: bool = false,
    mkwrite: bool = false,
    allow_retry: bool = false,
    retry: bool = false,
    user: bool = false,
    remote: bool = false,
    flag_trace: bool = false,
    interruptible: bool = false,
    unshare: bool = false,
    orig_pte_valid: bool = false,
    // Zxyphor
    zxy_prefault: bool = false,
    zxy_speculative: bool = false,
    _reserved: u20 = 0,
};

pub const FaultResult = enum(u32) {
    // VM_FAULT_* values
    oom = 0x000001,
    sigbus = 0x000002,
    major = 0x000004,
    write = 0x000008,
    hwpoison = 0x000010,
    hwpoison_large = 0x000020,
    sigsegv = 0x000040,
    nopage = 0x000100,
    locked = 0x000200,
    retry = 0x000400,
    fallback = 0x000800,
    done_cow = 0x001000,
    needdsync = 0x002000,
    completed = 0x004000,
    hindex_mask = 0x0f0000,
};

pub const PageFaultInfo = struct {
    // Faulting address
    address: u64,
    // Error code (x86)
    error_code: u64,
    // Flags
    flags: FaultFlags,
    // Result
    result: u32,        // Bitmask of FaultResult
    // VMA
    vma: ?*Vma,
    // PTE
    pte_val: u64,
    orig_pte: u64,
    // Page
    page: u64,          // Physical page
    // Cow
    cow_page: u64,
    // Stats
    is_major: bool,
    allocations: u32,
    io_operations: u32,
    latency_ns: u64,
};

// ============================================================================
// mlock
// ============================================================================

pub const MlockFlags = packed struct(u32) {
    lock: bool = false,         // MLOCK_ONFAULT
    onfault: bool = false,
    _reserved: u30 = 0,
};

pub const MLOCK_LIMIT_DEFAULT: u64 = 8 * 1024 * 1024; // 8MB

pub const MlockStats = struct {
    locked_bytes: u64,
    lock_limit_bytes: u64,
    nr_locked_vmas: u32,
    lock_failures: u64,
    // Per-process
    rlimit_memlock: u64,
};

// ============================================================================
// userfaultfd
// ============================================================================

pub const UffdFeatures = packed struct(u64) {
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
    // Zxyphor
    zxy_prefault: bool = false,
    _reserved: u46 = 0,
};

pub const UffdEventType = enum(u8) {
    pagefault = 0x12,
    fork = 0x13,
    remap = 0x14,
    remove = 0x15,
    unmap = 0x16,
};

pub const UffdIoctls = enum(u32) {
    register = 0xAA00,
    unregister = 0xAA01,
    wake = 0xAA02,
    copy = 0xAA03,
    zeropage = 0xAA04,
    writeprotect = 0xAA05,
    continue_op = 0xAA06,
    poison = 0xAA07,
    move_op = 0xAA08,
};

pub const UserfaultfdCtx = struct {
    // Features
    features: UffdFeatures,
    // Registration
    nr_registered_ranges: u32,
    // Stats
    fault_pending: u64,
    fault_resolved: u64,
    fault_wakeups: u64,
    copy_count: u64,
    zero_count: u64,
    wp_count: u64,
    move_count: u64,
    // Mode
    mode: u8,           // 0=missing, 1=wp, 2=minor
    // State
    active: bool,
};

// ============================================================================
// mremap
// ============================================================================

pub const MREMAP_MAYMOVE: u32 = 1;
pub const MREMAP_FIXED: u32 = 2;
pub const MREMAP_DONTUNMAP: u32 = 4;

pub const MremapParams = struct {
    old_addr: u64,
    old_len: u64,
    new_len: u64,
    flags: u32,
    new_addr: u64,      // Only if MREMAP_FIXED
};

// ============================================================================
// Process VM Operations (process_vm_readv/writev)
// ============================================================================

pub const RemoteIovec = struct {
    base: u64,
    len: u64,
};

pub const ProcessVmOp = struct {
    pid: i32,
    local_iov: [16]RemoteIovec,
    local_iovcnt: u32,
    remote_iov: [16]RemoteIovec,
    remote_iovcnt: u32,
    flags: u32,
    bytes_transferred: u64,
};

// ============================================================================
// ASLR (Address Space Layout Randomization)
// ============================================================================

pub const AslrConfig = struct {
    // Enable flags
    enabled: bool,
    full_randomize: bool,
    // Entropy bits
    mmap_rnd_bits: u8,           // 28-32 for 64-bit
    mmap_rnd_compat_bits: u8,    // 8-16 for 32-bit compat
    stack_rnd_bits: u8,
    // Regions
    pie_base: u64,
    heap_base: u64,
    mmap_base: u64,
    stack_base: u64,
    vdso_base: u64,
    // Zxyphor
    zxy_extra_entropy: bool,
    zxy_rerandomize_on_exec: bool,
};

// ============================================================================
// Memory Policy (NUMA)
// ============================================================================

pub const MpolMode = enum(u8) {
    default = 0,
    preferred = 1,
    bind = 2,
    interleave = 3,
    local = 4,
    preferred_many = 5,
    // Zxyphor
    zxy_adaptive = 10,
};

pub const MpolFlags = packed struct(u16) {
    static_nodes: bool = false,
    relative_nodes: bool = false,
    _reserved: u14 = 0,
};

pub const MempolicyInfo = struct {
    mode: MpolMode,
    flags: MpolFlags,
    // Node mask (64 nodes max)
    nodemask: u64,
    // Interleave
    il_node: u16,        // Current interleave node
    il_count: u64,       // Pages interleaved
    // Preferred
    preferred_node: u16,
    // Stats
    local_allocs: u64,
    remote_allocs: u64,
    interleave_allocs: u64,
    // Migration
    migration_count: u64,
    migration_failures: u64,
};

// ============================================================================
// mincore / mlock2 / msync
// ============================================================================

pub const MsyncFlags = packed struct(u32) {
    ms_async: bool = false,
    ms_invalidate: bool = false,
    ms_sync: bool = false,
    _reserved: u29 = 0,
};

pub const MincoreResult = struct {
    nr_pages: u64,
    nr_resident: u64,
    nr_dirty: u64,
    nr_referenced: u64,
    // Per-page vector
    vec: [*]u8,          // Each byte: bit 0 = resident
    vec_len: u64,
};

// ============================================================================
// Guard Pages
// ============================================================================

pub const GuardPageType = enum(u8) {
    stack_guard = 0,
    heap_guard = 1,
    canary = 2,
    red_zone = 3,
    // Zxyphor
    zxy_crypto_guard = 10,
};

pub const GuardPage = struct {
    address: u64,
    size: u64,           // Usually 4KB or 8KB
    guard_type: GuardPageType,
    // Detection
    hit_count: u64,
    last_hit_ns: u64,
    signaled: bool,
};

// ============================================================================
// Memory Mapping Statistics
// ============================================================================

pub const MmapStats = struct {
    // Global
    nr_mmap_calls: u64,
    nr_munmap_calls: u64,
    nr_mremap_calls: u64,
    nr_mprotect_calls: u64,
    nr_madvise_calls: u64,
    nr_mlock_calls: u64,
    nr_msync_calls: u64,
    nr_mincore_calls: u64,
    // Failures
    nr_mmap_failures: u64,
    nr_oom_kills: u64,
    // Page faults
    nr_minor_faults: u64,
    nr_major_faults: u64,
    nr_wp_faults: u64,
    nr_swap_faults: u64,
    // CoW
    nr_cow_faults: u64,
    nr_cow_pages: u64,
    // THP
    nr_thp_faults: u64,
    nr_thp_collapse: u64,
    nr_thp_split: u64,
    // KSM
    nr_ksm_merged: u64,
    nr_ksm_scanned: u64,
    // UFFD
    nr_uffd_faults: u64,
    nr_uffd_resolves: u64,
    // Guard pages
    nr_guard_violations: u64,
    // Zxyphor
    zxy_speculative_faults: u64,
    zxy_prefault_pages: u64,
};

pub const MmapSubsystem = struct {
    // Configuration
    vm_overcommit_memory: u8,   // 0=heuristic, 1=always, 2=never
    vm_overcommit_ratio: u32,   // Percentage
    vm_overcommit_kbytes: u64,
    // Limits
    vm_max_map_count: u32,      // Default 65530
    mmap_min_addr: u64,         // Default 65536
    mmap_rnd_bits: u8,
    // System state
    committed_as: i64,          // Committed address space (pages)
    committed_limit: i64,
    overcommit_count: u64,
    // Compaction
    compact_stall: u64,
    compact_fail: u64,
    compact_success: u64,
    // ASLR
    aslr_config: AslrConfig,
    // Stats
    stats: MmapStats,
    // Zxyphor
    zxy_speculative_pgfault: bool,
    zxy_cow_lazy: bool,
    initialized: bool,
};
