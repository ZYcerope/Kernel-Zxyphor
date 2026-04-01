// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Virtual Memory Manager
// 4/5-level paging, huge pages, CoW, demand paging, KASAN, memory compaction

const std = @import("std");

// ============================================================================
// Page Table Definitions (x86_64 4/5-level paging)
// ============================================================================

pub const PAGE_SHIFT = 12;
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;
pub const PAGE_MASK: u64 = ~(PAGE_SIZE - 1);
pub const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024; // 2MB
pub const GIANT_PAGE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB

// Page table entry flags
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7; // PS bit for 2MB/1GB pages
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NO_EXECUTE: u64 = @as(u64, 1) << 63;
pub const PTE_PROTECTION_KEY_MASK: u64 = 0xF << 59;

// Zxyphor custom flags (using available bits 9-11, 52-58)
pub const PTE_COW: u64 = 1 << 9; // Copy-on-Write
pub const PTE_SWAPPED: u64 = 1 << 10; // Swapped out
pub const PTE_SPECIAL: u64 = 1 << 11; // Special mapping (MMIO, etc.)
pub const PTE_SOFT_DIRTY: u64 = 1 << 52; // Soft dirty tracking
pub const PTE_UFFD_WP: u64 = 1 << 53; // Userfaultfd write-protect
pub const PTE_DEVMAP: u64 = 1 << 54; // Device-mapped page

pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

pub const PageTableEntry = u64;

/// Page table level (PML5/PML4/PDPT/PD/PT)
pub const PageLevel = enum(u3) {
    PT = 0, // Page Table (4KB pages)
    PD = 1, // Page Directory (2MB huge pages)
    PDPT = 2, // Page Directory Pointer Table (1GB giant pages)
    PML4 = 3, // PML4
    PML5 = 4, // PML5 (LA57)
};

/// Virtual address breakdown
pub const VirtAddr = packed struct(u64) {
    offset: u12,
    pt_index: u9,
    pd_index: u9,
    pdpt_index: u9,
    pml4_index: u9,
    pml5_index: u9,
    sign_extend: u7,
};

pub fn virt_to_indices(addr: u64) -> struct { pml4: u9, pdpt: u9, pd: u9, pt: u9, offset: u12 } {
    return .{
        .pml4 = @truncate((addr >> 39) & 0x1FF),
        .pdpt = @truncate((addr >> 30) & 0x1FF),
        .pd = @truncate((addr >> 21) & 0x1FF),
        .pt = @truncate((addr >> 12) & 0x1FF),
        .offset = @truncate(addr & 0xFFF),
    };
}

// ============================================================================
// Virtual Memory Area (VMA)
// ============================================================================

/// VMA protection flags
pub const VM_READ: u32 = 0x00000001;
pub const VM_WRITE: u32 = 0x00000002;
pub const VM_EXEC: u32 = 0x00000004;
pub const VM_SHARED: u32 = 0x00000008;
pub const VM_MAYREAD: u32 = 0x00000010;
pub const VM_MAYWRITE: u32 = 0x00000020;
pub const VM_MAYEXEC: u32 = 0x00000040;
pub const VM_MAYSHARE: u32 = 0x00000080;
pub const VM_GROWSDOWN: u32 = 0x00000100; // Stack
pub const VM_GROWSUP: u32 = 0x00000200;
pub const VM_PFNMAP: u32 = 0x00000400;
pub const VM_DENYWRITE: u32 = 0x00000800;
pub const VM_LOCKONFAULT: u32 = 0x00001000;
pub const VM_LOCKED: u32 = 0x00002000;
pub const VM_IO: u32 = 0x00004000;
pub const VM_SEQ_READ: u32 = 0x00008000;
pub const VM_RAND_READ: u32 = 0x00010000;
pub const VM_DONTCOPY: u32 = 0x00020000;
pub const VM_DONTEXPAND: u32 = 0x00040000;
pub const VM_ACCOUNT: u32 = 0x00100000;
pub const VM_NORESERVE: u32 = 0x00200000;
pub const VM_HUGETLB: u32 = 0x00400000;
pub const VM_MIXEDMAP: u32 = 0x10000000;
pub const VM_HUGEPAGE: u32 = 0x20000000;
pub const VM_NOHUGEPAGE: u32 = 0x40000000;
pub const VM_MERGEABLE: u32 = 0x80000000;

/// Virtual Memory Area descriptor
pub const Vma = struct {
    start: u64,
    end: u64,
    flags: u32,
    prot: u32,
    offset: u64, // File offset for file-backed mappings

    // File backing
    file_inode: u64,
    file_dev: u64,

    // VMA identity
    pgoff: u64,

    // Anonymous / shared
    anon_vma_id: u32,

    // NUMA
    numa_policy: NumaPolicy,
    preferred_node: u8,

    // Linked list pointers (indices into VMA array)
    next: u16,
    prev: u16,

    // Red-black tree for fast lookup
    rb_parent: u16,
    rb_left: u16,
    rb_right: u16,
    rb_color: u1,

    pub fn size(self: *const Vma) u64 {
        return self.end - self.start;
    }

    pub fn contains(self: *const Vma, addr: u64) bool {
        return addr >= self.start and addr < self.end;
    }

    pub fn isReadable(self: *const Vma) bool {
        return self.flags & VM_READ != 0;
    }

    pub fn isWritable(self: *const Vma) bool {
        return self.flags & VM_WRITE != 0;
    }

    pub fn isExecutable(self: *const Vma) bool {
        return self.flags & VM_EXEC != 0;
    }

    pub fn isShared(self: *const Vma) bool {
        return self.flags & VM_SHARED != 0;
    }

    pub fn isStack(self: *const Vma) bool {
        return self.flags & VM_GROWSDOWN != 0;
    }

    pub fn isHugePage(self: *const Vma) bool {
        return self.flags & (VM_HUGETLB | VM_HUGEPAGE) != 0;
    }

    pub fn pteFlags(self: *const Vma) u64 {
        var flags: u64 = PTE_PRESENT | PTE_USER;
        if (self.flags & VM_WRITE != 0) flags |= PTE_WRITABLE;
        if (self.flags & VM_EXEC == 0) flags |= PTE_NO_EXECUTE;
        return flags;
    }
};

pub const NumaPolicy = enum(u4) {
    default = 0,
    preferred = 1,
    bind = 2,
    interleave = 3,
    local = 4,
    preferred_many = 5,
    weighted_interleave = 6,
};

// ============================================================================
// Memory Map (mm_struct)
// ============================================================================

pub const MAX_VMAS = 65535;

/// Process memory map
pub const MmStruct = struct {
    // Page table root
    pgd: u64, // Physical address of PGD (PML4/PML5)
    is_la57: bool, // 5-level paging

    // VMA management
    vmas: [Vma; 4096],
    vma_count: u16,
    total_vm: u64, // Total mapped pages
    locked_vm: u64,
    pinned_vm: u64,
    data_vm: u64,
    exec_vm: u64,
    stack_vm: u64,

    // Memory limits
    brk: u64,
    start_brk: u64,
    mmap_base: u64,
    mmap_end: u64,
    start_code: u64,
    end_code: u64,
    start_data: u64,
    end_data: u64,
    start_stack: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,

    // RSS (Resident Set Size)
    rss_file: u64, // File-backed pages
    rss_anon: u64, // Anonymous pages
    rss_shmem: u64, // Shared memory pages

    // Statistics
    total_faults: u64,
    minor_faults: u64,
    major_faults: u64,
    cow_faults: u64,
    swap_ins: u64,
    swap_outs: u64,

    // OOM score
    oom_score_adj: i16,

    // ASID for TLB tagging
    asid: u16,

    // ref count
    ref_count: u32,

    pub fn findVma(self: *MmStruct, addr: u64) ?*Vma {
        // Linear search (would use RB-tree in production)
        for (&self.vmas, 0..) |*vma, i| {
            if (i >= self.vma_count) break;
            if (vma.contains(addr)) return vma;
        }
        return null;
    }

    pub fn totalRss(self: *const MmStruct) u64 {
        return self.rss_file + self.rss_anon + self.rss_shmem;
    }

    pub fn oomScore(self: *const MmStruct) i32 {
        const rss = self.totalRss();
        var score: i32 = @intCast(@min(rss / 1024, 1000));
        score += self.oom_score_adj;
        return @max(0, @min(1000, score));
    }
};

// ============================================================================
// Page Fault Handler
// ============================================================================

pub const FaultFlags = packed struct(u32) {
    write: bool,
    user: bool,
    instr_fetch: bool,
    reserved_bit: bool,
    protection_key: bool,
    shadow_stack: bool,
    _padding: u26 = 0,
};

pub const FaultResult = enum {
    handled,
    cow_break,
    demand_alloc,
    swap_in,
    file_map,
    huge_page_alloc,
    sigbus,
    sigsegv,
    oom_kill,
    retry,
};

pub const PageFaultInfo = struct {
    address: u64,
    flags: FaultFlags,
    vma: ?*const Vma,
    result: FaultResult,
    page_phys: u64,
    latency_ns: u64,
};

/// Handle a page fault
pub fn handlePageFault(mm: *MmStruct, addr: u64, flags: FaultFlags) FaultResult {
    mm.total_faults += 1;

    // Find VMA containing the faulting address
    const vma = mm.findVma(addr) orelse {
        // Check if stack growth needed
        if (addr + PAGE_SIZE >= mm.start_stack and flags.user) {
            // Stack growth - would expand stack VMA
            return .demand_alloc;
        }
        return .sigsegv;
    };

    // Check permissions
    if (flags.write and !vma.isWritable()) {
        // Write to read-only mapping
        // Check if COW
        if (vma.flags & VM_SHARED == 0) {
            // Private mapping - check for COW page
            return handleCowFault(mm, addr, vma);
        }
        return .sigsegv;
    }

    if (flags.instr_fetch and !vma.isExecutable()) {
        return .sigsegv;
    }

    // The page is not present - demand fault
    mm.minor_faults += 1;

    // Check if huge page
    if (vma.isHugePage() and isHugePageAligned(addr)) {
        return .huge_page_alloc;
    }

    // Check if file-backed
    if (vma.file_inode != 0) {
        return .file_map;
    }

    // Anonymous page - zero-fill
    return .demand_alloc;
}

fn handleCowFault(mm: *MmStruct, addr: u64, vma: *const Vma) FaultResult {
    _ = addr;
    _ = vma;
    mm.cow_faults += 1;
    return .cow_break;
}

fn isHugePageAligned(addr: u64) bool {
    return addr & (HUGE_PAGE_SIZE - 1) == 0;
}

// ============================================================================
// Transparent Huge Pages (THP)
// ============================================================================

pub const ThpConfig = struct {
    enabled: ThpMode,
    defrag: ThpDefrag,
    max_ptes_none: u32, // Max PTEs that can be none for collapse
    max_ptes_swap: u32,
    khugepaged_scan_sleep: u64, // ms
    khugepaged_alloc_sleep: u64,
    collapse_limit: u32,
    // Statistics
    thp_fault_alloc: u64,
    thp_fault_fallback: u64,
    thp_collapse_alloc: u64,
    thp_split: u64,
    thp_zero: u64,
};

pub const ThpMode = enum {
    always,
    madvise,
    never,
};

pub const ThpDefrag = enum {
    always,
    defer,
    defer_madvise,
    madvise,
    never,
};

/// Check if a VMA is eligible for THP
pub fn thpEligible(vma: *const Vma) bool {
    // Must be anonymous, not IO, not special
    if (vma.flags & (VM_IO | VM_PFNMAP | VM_NOHUGEPAGE) != 0) return false;
    if (vma.flags & VM_HUGEPAGE != 0) return true;
    // Size must be >= 2MB
    if (vma.size() < HUGE_PAGE_SIZE) return false;
    return true;
}

// ============================================================================
// Kernel Same-page Merging (KSM)
// ============================================================================

pub const KsmConfig = struct {
    enabled: bool,
    sleep_ms: u64,
    pages_to_scan: u32,
    pages_shared: u64,
    pages_sharing: u64,
    pages_unshared: u64,
    pages_volatile: u64,
    full_scans: u64,
    stable_nodes: u32,
    unstable_nodes: u32,
    merge_across_nodes: bool,
    max_page_sharing: u32,
};

/// KSM page hash for deduplication
pub const KsmPageHash = struct {
    hash: u32,
    page_pfn: u64,

    pub fn compute(data: [*]const u8, len: usize) u32 {
        var h: u32 = 0x811c9dc5;
        for (data[0..len]) |byte| {
            h ^= byte;
            h *%= 0x01000193;
        }
        return h;
    }
};

// ============================================================================
// Memory Compaction
// ============================================================================

pub const CompactResult = enum {
    not_suitable,
    skipped,
    deferred,
    no_suitable_page,
    success,
    partial_skipped,
    contended,
};

pub const CompactPriority = enum {
    async_compact, // Don't block
    sync_light, // Block for migration
    sync_full, // Block for everything
};

pub const MigrationMode = enum {
    async_migration,
    sync_light,
    sync,
};

pub const CompactState = struct {
    zone_start: u64,
    zone_end: u64,
    migrate_pfn: u64,
    free_pfn: u64,
    priority: CompactPriority,
    result: CompactResult,
    pages_migrated: u64,
    pages_freed: u64,
    contended: bool,
};

// ============================================================================
// KASAN (Kernel Address Sanitizer)
// ============================================================================

pub const KASAN_SHADOW_SCALE = 3; // 1 byte shadows 8 bytes
pub const KASAN_SHADOW_OFFSET: u64 = 0xdffffc0000000000;
pub const KASAN_TAG_KERNEL: u8 = 0xFF;
pub const KASAN_TAG_INVALID: u8 = 0xFE;
pub const KASAN_TAG_MAX: u8 = 0xFD;

/// KASAN shadow memory states
pub const KASAN_SHADOW_FREE: u8 = 0xFF;
pub const KASAN_SHADOW_GAP: u8 = 0xF9;
pub const KASAN_SHADOW_STACK_LEFT: u8 = 0xF1;
pub const KASAN_SHADOW_STACK_MID: u8 = 0xF2;
pub const KASAN_SHADOW_STACK_RIGHT: u8 = 0xF3;
pub const KASAN_SHADOW_GLOBAL_REDZONE: u8 = 0xF5;
pub const KASAN_SHADOW_SLAB_REDZONE: u8 = 0xFC;
pub const KASAN_SHADOW_FREED: u8 = 0xFB;
pub const KASAN_SHADOW_ALLOCA_LEFT: u8 = 0xCA;
pub const KASAN_SHADOW_ALLOCA_RIGHT: u8 = 0xCB;

pub fn kasanMemToShadow(addr: u64) u64 {
    return (addr >> KASAN_SHADOW_SCALE) + KASAN_SHADOW_OFFSET;
}

pub fn kasanShadowToMem(shadow: u64) u64 {
    return (shadow - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE;
}

/// Report KASAN violation
pub const KasanReport = struct {
    access_addr: u64,
    access_size: usize,
    is_write: bool,
    ip: u64, // instruction pointer
    shadow_val: u8,
    bug_type: KasanBugType,
};

pub const KasanBugType = enum {
    out_of_bounds,
    use_after_free,
    slab_out_of_bounds,
    global_out_of_bounds,
    stack_out_of_bounds,
    alloca_out_of_bounds,
    wild_access,
    null_deref,
};

// ============================================================================
// Memory Cgroups
// ============================================================================ 

pub const MemCgroup = struct {
    id: u64,
    parent_id: u64,
    limit: u64, // memory.max (bytes)
    soft_limit: u64, // memory.high
    swap_limit: u64, // memory.swap.max
    usage: u64, // Current usage
    max_usage: u64, // High water mark
    swap_usage: u64,
    kmem_usage: u64, // Kernel memory
    tcp_mem_usage: u64,
    failcnt: u64, // OOM counter
    oom_kill_count: u64,
    
    // Pressure
    some_avg10: u32,
    some_avg60: u32,
    some_avg300: u32,
    full_avg10: u32,
    full_avg60: u32,
    full_avg300: u32,

    // Configuration
    oom_kill_disable: bool,
    use_hierarchy: bool,
    swappiness: u8,

    pub fn isOverLimit(self: *const MemCgroup) bool {
        return self.usage > self.limit;
    }

    pub fn isOverSoftLimit(self: *const MemCgroup) bool {
        return self.usage > self.soft_limit;
    }

    pub fn availableMemory(self: *const MemCgroup) u64 {
        if (self.limit > self.usage) return self.limit - self.usage;
        return 0;
    }

    pub fn charge(self: *MemCgroup, pages: u64) bool {
        const bytes = pages * PAGE_SIZE;
        if (self.usage + bytes > self.limit) {
            self.failcnt += 1;
            return false;
        }
        self.usage += bytes;
        if (self.usage > self.max_usage) self.max_usage = self.usage;
        return true;
    }

    pub fn uncharge(self: *MemCgroup, pages: u64) void {
        const bytes = pages * PAGE_SIZE;
        self.usage -= @min(self.usage, bytes);
    }
};

// ============================================================================
// OOM Killer
// ============================================================================

pub const OomContext = struct {
    constraint: OomConstraint,
    gfp_mask: u32,
    order: u32,
    memcg: ?*MemCgroup,
    zone_idx: u8,
    nodemask: u64,
    chosen_pid: u32,
    chosen_score: i32,
    totalpages: u64,
};

pub const OomConstraint = enum {
    none,
    cpuset,
    memory_policy,
    memcg,
};

/// Select an OOM victim
pub fn oomBadness(total_vm: u64, rss: u64, oom_score_adj: i16, totalpages: u64) i32 {
    if (oom_score_adj == -1000) return 0; // OOM immune

    // Points = rss * 1000 / totalpages
    var points: i64 = @intCast((rss * 1000) / @max(totalpages, 1));
    
    // Adjust by oom_score_adj
    const adj: i64 = @as(i64, oom_score_adj) * @intCast(totalpages) / 1000;
    points += adj;
    
    return @intCast(@max(1, @min(1000, points)));
}

// ============================================================================
// Memory Pressure / PSI
// ============================================================================

pub const PsiGroup = struct {
    some_total: u64, // microseconds
    full_total: u64,
    some_avg: [3]u64, // 10s, 60s, 300s windows
    full_avg: [3]u64,
    some_stall: u64, // current stall start time, 0 if not stalled
    full_stall: u64,
    tasks_some: u32, // tasks experiencing some pressure
    tasks_full: u32,
    last_update: u64,

    pub fn update(self: *PsiGroup, now: u64) void {
        if (self.last_update == 0) {
            self.last_update = now;
            return;
        }
        
        const elapsed = now - self.last_update;
        self.last_update = now;
        
        if (self.tasks_some > 0) {
            self.some_total += elapsed;
        }
        if (self.tasks_full > 0) {
            self.full_total += elapsed;
        }
    }
};

pub const PsiState = struct {
    memory: PsiGroup,
    io: PsiGroup,
    cpu: PsiGroup,
    irq: PsiGroup,
};
