// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - GUP, mlock & mremap Internals
// get_user_pages() fast & slow paths, pin_user_pages, mlock/munlock,
// mremap internals, userfaultfd integration, VM_LOCKED pages

const std = @import("std");

// ============================================================================
// GUP Flags
// ============================================================================

pub const GupFlags = packed struct(u32) {
    write: bool,           // FOLL_WRITE - need write access
    touch: bool,           // FOLL_TOUCH - mark page accessed
    remote: bool,          // FOLL_REMOTE - different mm
    get: bool,             // FOLL_GET - get page reference
    force: bool,           // FOLL_FORCE - bypass prot check (careful)
    nowait: bool,          // FOLL_NOWAIT - non-blocking
    nofault: bool,         // FOLL_NOFAULT - no page fault
    hwpoison: bool,        // FOLL_HWPOISON - check hwpoison
    migration: bool,       // FOLL_MIGRATION - wait for migration
    tried: bool,           // FOLL_TRIED - already attempted
    longterm: bool,        // FOLL_LONGTERM - long-term pin
    split_pmd: bool,       // FOLL_SPLIT_PMD - split huge PMD
    pin: bool,             // FOLL_PIN - pin pages
    fast_only: bool,       // FOLL_FAST_ONLY - fast path only
    unlockable: bool,      // FOLL_UNLOCKABLE - mmap_lock rw
    madv_populate: bool,   // FOLL_MADV_POPULATE - madvise path
    interruptible: bool,   // FOLL_INTERRUPTIBLE
    _reserved: u15,
};

// ============================================================================
// GUP Result
// ============================================================================

pub const GupResult = struct {
    nr_pinned: i64,        // Number of pages pinned
    pages: [*]u64,         // Array of page pointers
    vmas: [*]?*VmAreaStruct,
    locked: ?*i32,
};

pub const GupFastResult = struct {
    nr_pinned: i64,
    flags: GupFlags,
    pt_walk_success: bool,
    pte_speculative: bool,
};

// ============================================================================
// Pin User Pages
// ============================================================================

pub const PinState = enum(u8) {
    Unpinned = 0,
    DevicePinned = 1,      // FOLL_PIN ref
    GupPinned = 2,         // FOLL_GET ref
    LongtermPinned = 3,    // FOLL_LONGTERM (for RDMA etc.)
};

pub const PagePinCount = struct {
    gup_pin_count: u32,    // GUP (map_count based)
    dma_pin_count: u32,    // DMA/RDMA pins
    is_longterm: bool,
    is_pinnable: bool,     // Not in movable zone etc.
};

pub const PIN_BIAS: u32 = 1024;    // GUP_PIN_COUNTING_BIAS

// ============================================================================
// Page Table Walk for GUP
// ============================================================================

pub const PteWalkState = struct {
    pgd: u64,
    p4d: u64,
    pud: u64,
    pmd: u64,
    pte: u64,
    level: PageLevel,
    huge: bool,
    devmap: bool,
    migration: bool,
    swap: bool,
};

pub const PageLevel = enum(u8) {
    Pgd = 0,
    P4d = 1,
    Pud = 2,
    Pmd = 3,
    Pte = 4,
};

pub const HugePmdInfo = struct {
    pmd_val: u64,
    is_trans_huge: bool,
    is_pmd_migration: bool,
    is_splitting: bool,
    compound_order: u8,
};

// ============================================================================
// mlock
// ============================================================================

pub const MlockFlags = packed struct(u32) {
    mlock_current: bool,   // MCL_CURRENT
    mlock_future: bool,    // MCL_FUTURE
    mlock_onfault: bool,   // MCL_ONFAULT
    _reserved: u29,
};

pub const MlockLimit = struct {
    rlimit_memlock: u64,   // Bytes (soft limit)
    rlimit_memlock_hard: u64,
    locked_vm: u64,        // Currently locked pages
    pinned_vm: u64,        // Currently pinned pages
    data_vm: u64,
    stack_vm: u64,
};

pub const MlockedPageState = enum(u8) {
    Unlocked = 0,
    Locked = 1,            // VM_LOCKED
    LockedOnFault = 2,     // VM_LOCKONFAULT
    Migrating = 3,         // Temporarily unlocked for migration
};

pub const VmLockBatch = struct {
    pages: [16]u64,        // Page pointers to lock/unlock
    count: u32,
    done_index: u32,
    error: i32,
};

pub const MlockVmaConfig = struct {
    vm_flags: VmFlags,
    vm_start: u64,
    vm_end: u64,
    new_flags: u32,
    nr_pages: u64,
    nr_locked: u64,
    nr_failed: u64,
};

// ============================================================================
// mremap
// ============================================================================

pub const MremapFlags = packed struct(u32) {
    maymove: bool,         // MREMAP_MAYMOVE
    fixed: bool,           // MREMAP_FIXED
    dontunmap: bool,       // MREMAP_DONTUNMAP
    _reserved: u29,
};

pub const MremapParams = struct {
    old_addr: u64,
    old_len: u64,
    new_len: u64,
    new_addr: u64,         // Only if MREMAP_FIXED
    flags: MremapFlags,
};

pub const MremapResult = struct {
    new_addr: u64,
    success: bool,
    moved: bool,
    expanded: bool,
    shrunk: bool,
    nr_ptes_moved: u64,
    nr_ptes_copied: u64,
};

pub const MremapOperation = enum(u8) {
    Expand = 0,
    Shrink = 1,
    Move = 2,
    ExpandInPlace = 3,
};

pub const VmaSplitResult = struct {
    left: ?*VmAreaStruct,
    right: ?*VmAreaStruct,
    split_addr: u64,
    success: bool,
};

// ============================================================================
// VMA (Virtual Memory Area) Definition
// ============================================================================

pub const VmFlags = packed struct(u64) {
    read: bool,           // VM_READ
    write: bool,          // VM_WRITE
    exec: bool,           // VM_EXEC
    shared: bool,         // VM_SHARED
    mayread: bool,
    maywrite: bool,
    mayexec: bool,
    mayshare: bool,
    growsdown: bool,      // VM_GROWSDOWN (stack)
    uffd_missing: bool,   // VM_UFFD_MISSING
    pfnmap: bool,         // VM_PFNMAP
    locked: bool,         // VM_LOCKED
    io: bool,             // VM_IO
    seq_read: bool,       // VM_SEQ_READ
    rand_read: bool,      // VM_RAND_READ
    dontcopy: bool,       // VM_DONTCOPY
    dontexpand: bool,     // VM_DONTEXPAND
    lockonfault: bool,    // VM_LOCKONFAULT
    account: bool,        // VM_ACCOUNT
    noreserve: bool,      // VM_NORESERVE
    hugetlb: bool,        // VM_HUGETLB
    sync: bool,           // VM_SYNC
    arch1: bool,          // VM_ARCH_1
    wipeonfork: bool,     // VM_WIPEONFORK
    dontdump: bool,       // VM_DONTDUMP
    softdirty: bool,      // VM_SOFTDIRTY
    mixedmap: bool,       // VM_MIXEDMAP
    hugepage: bool,       // VM_HUGEPAGE
    nohugepage: bool,     // VM_NOHUGEPAGE
    mergeable: bool,      // VM_MERGEABLE (KSM)
    uffd_wp: bool,        // VM_UFFD_WP
    _reserved: u33,
};

pub const VmAreaStruct = struct {
    vm_start: u64,
    vm_end: u64,
    vm_flags: VmFlags,
    vm_page_prot: u64,    // Page protection bits
    vm_pgoff: u64,         // Offset within file (in pages)
    vm_file: u64,          // File pointer
    vm_private_data: u64,
    anon_name: [32]u8,
    anon_vma: u64,         // Anon reverse mapping
    vm_ops: ?*VmOps,
    rb_subtree_gap: u64,
    vm_userfaultfd_ctx: UffdCtx,
    vm_policy: ?*MempolicyRef,
};

pub const VmOps = struct {
    open: ?*const fn (*VmAreaStruct) void,
    close: ?*const fn (*VmAreaStruct) void,
    may_split: ?*const fn (*VmAreaStruct, u64) i32,
    mremap: ?*const fn (*VmAreaStruct) i32,
    mprotect: ?*const fn (*VmAreaStruct, u32, u32) i32,
    fault: ?*const fn (*VmFault) i32,
    huge_fault: ?*const fn (*VmFault, u32) i32,
    map_pages: ?*const fn (*VmFault, u64, u64) i32,
    page_mkwrite: ?*const fn (*VmFault) i32,
    pfn_mkwrite: ?*const fn (*VmFault) i32,
    access: ?*const fn (*VmAreaStruct, u64, [*]u8, i32, i32) i32,
    name: ?*const fn (*VmAreaStruct) [*:0]const u8,
    find_special_page: ?*const fn (*VmAreaStruct, u64) ?u64,
};

pub const VmFault = struct {
    flags: VmFaultFlags,
    vma: ?*VmAreaStruct,
    address: u64,
    pgoff: u64,
    real_address: u64,
    pte: ?*u64,
    pmd: ?*u64,
    pud: ?*u64,
    page: u64,
    prealloc_pte: u64,
    cow_page: u64,
    huge_page: u64,
};

pub const VmFaultFlags = packed struct(u32) {
    write: bool,
    mkwrite: bool,
    allow_retry: bool,
    retry: bool,
    user: bool,
    done_cow: bool,
    remote: bool,
    lockonfault: bool,
    interruptible: bool,
    unshare: bool,
    orig_pte_valid: bool,
    vma_lock: bool,
    _reserved: u20,
};

pub const UffdCtx = struct {
    ctx: u64,              // Userfaultfd context pointer
};

pub const MempolicyRef = struct {
    policy_ptr: u64,
};

// ============================================================================
// Page Walk Callbacks
// ============================================================================

pub const PageWalkOps = struct {
    pgd_entry: ?*const fn (u64, u64, u64, *MmWalkState) i32,
    p4d_entry: ?*const fn (u64, u64, u64, *MmWalkState) i32,
    pud_entry: ?*const fn (u64, u64, u64, *MmWalkState) i32,
    pmd_entry: ?*const fn (u64, u64, u64, *MmWalkState) i32,
    pte_entry: ?*const fn (u64, u64, u64, *MmWalkState) i32,
    pte_hole: ?*const fn (u64, u64, i32, *MmWalkState) i32,
    hugetlb_entry: ?*const fn (u64, u64, u64, i32, *MmWalkState) i32,
    test_walk: ?*const fn (u64, u64, *MmWalkState) i32,
    pre_vma: ?*const fn (u64, u64, *MmWalkState) i32,
    post_vma: ?*const fn (*MmWalkState) void,
};

pub const MmWalkState = struct {
    ops: ?*const PageWalkOps,
    mm: u64,
    pgd: u64,
    vma: ?*VmAreaStruct,
    action: PageWalkAction,
    no_vma: bool,
    private_data: u64,
};

pub const PageWalkAction = enum(u8) {
    Continue = 0,
    Again = 1,
    Skip = 2,
};

// ============================================================================
// Manager
// ============================================================================

pub const GupMlockMremapManager = struct {
    total_gup_fast: u64,
    total_gup_slow: u64,
    total_pages_pinned: u64,
    total_pages_unpinned: u64,
    total_longterm_pins: u64,
    total_mlock_calls: u64,
    total_munlock_calls: u64,
    total_mremap_calls: u64,
    total_mremap_moves: u64,
    total_vma_splits: u64,
    total_vma_merges: u64,
    total_page_walks: u64,
    current_locked_pages: u64,
    current_pinned_pages: u64,
    initialized: bool,

    pub fn init() GupMlockMremapManager {
        return .{
            .total_gup_fast = 0,
            .total_gup_slow = 0,
            .total_pages_pinned = 0,
            .total_pages_unpinned = 0,
            .total_longterm_pins = 0,
            .total_mlock_calls = 0,
            .total_munlock_calls = 0,
            .total_mremap_calls = 0,
            .total_mremap_moves = 0,
            .total_vma_splits = 0,
            .total_vma_merges = 0,
            .total_page_walks = 0,
            .current_locked_pages = 0,
            .current_pinned_pages = 0,
            .initialized = true,
        };
    }
};
