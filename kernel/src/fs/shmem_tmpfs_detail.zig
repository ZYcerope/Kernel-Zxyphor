// Zxyphor Kernel - tmpfs/shmem Advanced Internals
// Shared memory: shmem_inode_info, fallocate, huge pages,
// swap accounting, xattr, POSIX ACL, encryption,
// transparent huge page for shmem, userfaultfd
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Shmem Filesystem Config
// ============================================================================

pub const ShmemMountOpts = struct {
    mode: u16,               // directory mode
    uid: u32,
    gid: u32,
    size: u64,               // max bytes
    nr_blocks: u64,          // max blocks
    nr_inodes: u64,          // max inodes
    // Huge page policy
    huge: ShmemHugePolicy,
    // Quota
    usrquota: bool,
    grpquota: bool,
    // inode64
    inode64: bool,
    // noswap
    noswap: bool,
};

pub const ShmemHugePolicy = enum(u8) {
    never = 0,
    always = 1,
    within_size = 2,
    advise = 3,
    deny = 4,
    force = 5,
};

// ============================================================================
// Shmem Superblock Info
// ============================================================================

pub const ShmemSbInfo = struct {
    max_blocks: u64,
    used_blocks: u64,
    free_inodes: u64,
    max_inodes: u64,
    // Huge page
    huge: ShmemHugePolicy,
    // Spinlock
    stat_lock: u64,
    // Swap
    swapped_pages: u64,
    // Options
    uid: u32,
    gid: u32,
    mode: u16,
    // Quota
    qlimits: ShmemQuotaLimits,
    // Inode numbering
    next_ino: u64,
    inode64: bool,
    noswap: bool,
    // Stats
    stats: ShmemSbStats,
};

pub const ShmemQuotaLimits = struct {
    usrquota_block_hardlimit: u64,
    usrquota_inode_hardlimit: u64,
    grpquota_block_hardlimit: u64,
    grpquota_inode_hardlimit: u64,
};

pub const ShmemSbStats = struct {
    total_pages: u64,
    resident_pages: u64,
    swapped_pages: u64,
    fallocated_pages: u64,
    thp_pages: u64,
    inodes_used: u64,
    inodes_free: u64,
};

// ============================================================================
// Shmem Inode Info
// ============================================================================

pub const ShmemInodeInfo = struct {
    // Flags
    flags: ShmemFlags,
    // Allocation
    alloced: u64,       // number of pages allocated
    swapped: u64,       // number of pages swapped
    // Fallocate
    fallocate_start: u64,
    fallocate_end: u64,
    // Huge page
    huge_policy: ShmemHugePolicy,
    // Page cache (xarray based swap cache)
    xarray_root: u64,
    // Seal
    seals: ShmemSeals,
    // Lock
    lock: u64,
    // Dir offset
    dir_offsets: u64,
    // Writeprotect
    writeprotect_start: u64,
    writeprotect_count: u64,
    // Encryption
    fscrypt_ctx: u64,
    // Userfaultfd
    uffd_ctx: ShmemUffdCtx,
    // xattr
    xattrs: u64,
    // POSIX ACL
    default_acl: u64,
    access_acl: u64,
    // Stats
    stats: ShmemInodeStats,
};

pub const ShmemFlags = packed struct(u32) {
    volatile_page: bool = false,
    sealed: bool = false,
    nommu: bool = false,
    fscrypted: bool = false,
    verity: bool = false,
    casefold: bool = false,
    _pad: u26 = 0,
};

pub const ShmemSeals = packed struct(u32) {
    seal: bool = false,        // F_SEAL_SEAL
    shrink: bool = false,      // F_SEAL_SHRINK
    grow: bool = false,        // F_SEAL_GROW
    write: bool = false,       // F_SEAL_WRITE
    future_write: bool = false, // F_SEAL_FUTURE_WRITE
    exec: bool = false,        // F_SEAL_EXEC
    _pad: u26 = 0,
};

pub const ShmemInodeStats = struct {
    reads: u64,
    writes: u64,
    faults: u64,
    huge_faults: u64,
    swap_ins: u64,
    swap_outs: u64,
    fallocate_ops: u64,
    hole_punches: u64,
};

// ============================================================================
// Userfaultfd Context for Shmem
// ============================================================================

pub const ShmemUffdCtx = struct {
    registered: bool,
    mode: UffdMode,
    events: UffdEvents,
    // Minor faults (for shmem)
    minor_enabled: bool,
    // Stats
    uffd_faults: u64,
    uffd_minor_faults: u64,
    uffd_copy_ops: u64,
    uffd_zeropage_ops: u64,
    uffd_continue_ops: u64,
};

pub const UffdMode = packed struct(u8) {
    missing: bool = false,
    wp: bool = false,
    minor: bool = false,
    _pad: u5 = 0,
};

pub const UffdEvents = packed struct(u16) {
    pagefault: bool = false,
    fork: bool = false,
    remap: bool = false,
    remove: bool = false,
    unmap: bool = false,
    _pad: u11 = 0,
};

// ============================================================================
// Shmem Operations
// ============================================================================

pub const ShmemFallocateMode = enum(u8) {
    allocate = 0,
    punch_hole = 1,
    collapse_range = 2,
    insert_range = 3,
    zero_range = 4,
};

pub const ShmemFallocateCtx = struct {
    mode: ShmemFallocateMode,
    offset: u64,
    length: u64,
    // State
    pages_allocated: u64,
    pages_freed: u64,
    error: i32,
};

// ============================================================================
// Shmem Swap
// ============================================================================

pub const ShmemSwapEntry = struct {
    type_idx: u8,        // swap device index
    offset: u64,         // offset in swap device
    flags: ShmemSwapFlags,
};

pub const ShmemSwapFlags = packed struct(u8) {
    exclusive: bool = false,
    dirty: bool = false,
    _pad: u6 = 0,
};

pub const ShmemSwapCache = struct {
    // Per-inode swap tracking
    total_swapped: u64,
    total_swap_in: u64,
    total_swap_out: u64,
    swap_readahead_hits: u64,
    swap_readahead_misses: u64,
};

// ============================================================================
// Shmem THP (Transparent Huge Pages)
// ============================================================================

pub const ShmemThpConfig = struct {
    enabled: ShmemHugePolicy,
    // Per-mount override
    mount_override: bool,
    mount_policy: ShmemHugePolicy,
    // Defrag
    defrag: u8,
    // Size thresholds
    min_alloc_order: u32,
    // Stats
    thp_alloc_success: u64,
    thp_alloc_failure: u64,
    thp_split: u64,
    thp_collapse: u64,
    thp_fallback: u64,
};

// ============================================================================
// tmpfs xattr
// ============================================================================

pub const ShmemXattrEntry = struct {
    name_index: ShmemXattrIndex,
    name: [256]u8,
    name_len: u32,
    value: [65536]u8,
    value_len: u32,
    next: ?*ShmemXattrEntry,
};

pub const ShmemXattrIndex = enum(u8) {
    user = 1,
    posix_acl_access = 2,
    posix_acl_default = 3,
    trusted = 4,
    security = 6,
};

// ============================================================================
// POSIX Shared Memory (dev/shm)
// ============================================================================

pub const PosixShmObj = struct {
    name: [256]u8,
    name_len: u32,
    size: u64,
    flags: u32,
    mode: u16,
    uid: u32,
    gid: u32,
    inode: u64,
    // Mapping
    mapped_count: u32,
    // Seal
    seals: ShmemSeals,
    // Stats
    created_ns: u64,
    last_access_ns: u64,
    last_modify_ns: u64,
};

// ============================================================================
// SysV Shared Memory (for completeness)
// ============================================================================

pub const SysvShmSegment = struct {
    key: i32,
    shmid: i32,
    size: u64,
    // Permissions
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    // Timestamps
    atime: u64,
    dtime: u64,
    ctime: u64,
    // Attach count
    nattach: u32,
    // Flags
    flags: SysvShmFlags,
    // Pages
    pages_resident: u64,
    pages_swapped: u64,
};

pub const SysvShmFlags = packed struct(u32) {
    locked: bool = false,
    hugetlb: bool = false,
    noreserve: bool = false,
    dest: bool = false,
    removed: bool = false,
    _pad: u27 = 0,
};

// ============================================================================
// memfd_create
// ============================================================================

pub const MemfdFlags = packed struct(u32) {
    cloexec: bool = false,
    allow_sealing: bool = false,
    hugetlb: bool = false,
    noexec_seal: bool = false,
    exec: bool = false,
    hugetlb_size: u6 = 0,  // huge page size encoding
    _pad: u21 = 0,
};

pub const MemfdObj = struct {
    name: [256]u8,
    name_len: u32,
    flags: MemfdFlags,
    size: u64,
    seals: ShmemSeals,
    // Hugetlb info
    hugetlb_size: u64,
    // Stats
    pages_resident: u64,
    pages_swapped: u64,
    maps_count: u32,
};

// ============================================================================
// mmap for tmpfs/shmem
// ============================================================================

pub const ShmemMmapCtx = struct {
    vm_flags: u64,
    vm_start: u64,
    vm_end: u64,
    vm_pgoff: u64,
    // Huge page alignment
    huge_aligned: bool,
    // Fault handler
    fault_handler: ShmemFaultType,
    // Stats
    mapped_pages: u64,
    faults_major: u64,
    faults_minor: u64,
};

pub const ShmemFaultType = enum(u8) {
    page_fault = 0,
    huge_fault = 1,
    uffd_fault = 2,
    swap_fault = 3,
};

// ============================================================================
// Shmem Writeback
// ============================================================================

pub const ShmemWriteback = struct {
    // Dirty tracking
    dirty_pages: u64,
    writeback_pages: u64,
    // Rate limiting
    ratelimit_pages: u64,
    // Balance dirty
    thresh: u64,
    bg_thresh: u64,
    dirty_exceeded: bool,
    // Stats
    writeback_count: u64,
    writeback_bytes: u64,
};

// ============================================================================
// Shmem Security
// ============================================================================

pub const ShmemSecurityCtx = struct {
    // SELinux
    sid: u32,
    // Smack
    smack_label: [256]u8,
    smack_label_len: u32,
    // IMA
    ima_hash: [64]u8,
    ima_hash_len: u32,
    ima_measured: bool,
    // Encryption (fscrypt)
    encrypted: bool,
    encrypt_policy_version: u8,
    encrypt_key_identifier: [16]u8,
};

// ============================================================================
// Shmem Subsystem Manager
// ============================================================================

pub const ShmemSubsystemManager = struct {
    total_shmem_pages: u64,
    total_shmem_pmdmapped: u64,
    total_shmem_swapped: u64,
    total_tmpfs_mounts: u32,
    total_memfd_pages: u64,
    total_shm_segments: u32,
    total_posix_shm: u32,
    // Huge page stats
    thp_shmem_alloc: u64,
    thp_shmem_fallback: u64,
    thp_shmem_split: u64,
    // Swap stats
    shmem_swap_in: u64,
    shmem_swap_out: u64,
    // Fallocate stats
    fallocate_ops: u64,
    punch_hole_ops: u64,
    // xattr stats
    xattr_set_ops: u64,
    xattr_get_ops: u64,
    initialized: bool,

    pub fn init() ShmemSubsystemManager {
        return ShmemSubsystemManager{
            .total_shmem_pages = 0,
            .total_shmem_pmdmapped = 0,
            .total_shmem_swapped = 0,
            .total_tmpfs_mounts = 0,
            .total_memfd_pages = 0,
            .total_shm_segments = 0,
            .total_posix_shm = 0,
            .thp_shmem_alloc = 0,
            .thp_shmem_fallback = 0,
            .thp_shmem_split = 0,
            .shmem_swap_in = 0,
            .shmem_swap_out = 0,
            .fallocate_ops = 0,
            .punch_hole_ops = 0,
            .xattr_set_ops = 0,
            .xattr_get_ops = 0,
            .initialized = true,
        };
    }
};
