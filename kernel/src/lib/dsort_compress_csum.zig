// Zxyphor Kernel - Linked List / RB-Tree Detail,
// Sorting Algorithms, Compression Library,
// Checksum Routines, Firmware Loading Framework,
// Printf/Printk Format Internals, String Matching,
// Static Key/Jump Label, Notifier Chains,
// percpu Operations, refcount_t, lockref, seqlock
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Linked List Variants
// ============================================================================

pub const ListHead = struct {
    next: ?*ListHead,
    prev: ?*ListHead,

    pub const INIT: ListHead = .{ .next = null, .prev = null };

    pub fn is_empty(self: *const ListHead) bool {
        return self.next == @as(?*const ListHead, self);
    }
};

pub const HlistHead = struct {
    first: ?*HlistNode,

    pub const INIT: HlistHead = .{ .first = null };
};

pub const HlistNode = struct {
    next: ?*HlistNode,
    pprev: ?*?*HlistNode,
};

pub const ListLru = struct {
    node_count: u32,
    per_node: [64]ListLruNode,    // Up to 64 NUMA nodes
};

pub const ListLruNode = struct {
    list: ListHead,
    nr_items: u64,
};

pub const LlistHead = struct {
    first: ?*LlistNode,           // Lock-less linked list head
};

pub const LlistNode = struct {
    next: ?*LlistNode,
};

// ============================================================================
// RB-Tree (Red-Black Tree)
// ============================================================================

pub const RbColor = enum(u1) {
    red = 0,
    black = 1,
};

pub const RbNode = struct {
    parent_color: usize,    // Parent pointer + color in LSB
    left: ?*RbNode,
    right: ?*RbNode,

    pub fn color(self: *const RbNode) RbColor {
        return if (self.parent_color & 1 == 0) .red else .black;
    }

    pub fn parent(self: *const RbNode) ?*RbNode {
        const ptr = self.parent_color & ~@as(usize, 3);
        if (ptr == 0) return null;
        return @ptrFromInt(ptr);
    }
};

pub const RbRoot = struct {
    node: ?*RbNode,

    pub const INIT: RbRoot = .{ .node = null };

    pub fn is_empty(self: *const RbRoot) bool {
        return self.node == null;
    }
};

pub const RbRootCached = struct {
    root: RbRoot,
    leftmost: ?*RbNode,       // Cached leftmost (minimum)
};

pub const RbAugmentCallbacks = struct {
    propagate: ?*const fn (*RbNode, ?*RbNode) void,
    copy: ?*const fn (?*RbNode, ?*RbNode) void,
    rotate: ?*const fn (?*RbNode, ?*RbNode) void,
};

// ============================================================================
// Maple Tree (Advanced radix tree, Linux 6.1+)
// ============================================================================

pub const MapleNodeType = enum(u8) {
    dense = 0,            // Dense node
    leaf_64 = 1,          // Leaf with 64-bit entries
    range_64 = 2,         // Range node with 64-bit
    arange_64 = 3,        // Allocation range
};

pub const MapleTree = struct {
    root: ?*MapleNode,
    flags: MapleTreeFlags,
    height: u8,
};

pub const MapleNode = struct {
    parent: usize,        // Parent + type bits
    node_type: MapleNodeType,
    slot_count: u8,
    // Actual data depends on node_type
};

pub const MapleTreeFlags = packed struct(u32) {
    alloc: bool = false,
    use_rcu: bool = false,
    height: u8 = 0,
    _reserved: u22 = 0,
};

// ============================================================================
// Sorting Algorithms
// ============================================================================

pub const SortAlgorithm = enum(u8) {
    insertion = 0,          // For small arrays
    heap = 1,               // Heapsort (guaranteed O(n log n))
    merge = 2,              // Mergesort (stable, needs O(n) extra)
    quick = 3,              // Quicksort (average O(n log n))
    radix = 4,              // Radix sort (for integers)
    timsort = 5,            // Hybrid stable sort
    // Kernel-specific
    list_sort = 6,          // Bottom-up merge sort for linked lists
    // Zxyphor
    zxy_adaptive = 100,     // Adapts to data patterns
};

pub const SortConfig = struct {
    algorithm: SortAlgorithm,
    element_size: u32,
    compare_fn: ?*const fn (*const anyopaque, *const anyopaque) i32,
    swap_fn: ?*const fn (*anyopaque, *anyopaque, u32) void,
    threshold_insertion: u32,    // Switch to insertion sort below this
};

pub const SortStats = struct {
    comparisons: u64,
    swaps: u64,
    recursive_depth: u32,
    cpu_cycles: u64,
};

// ============================================================================
// Compression Library
// ============================================================================

pub const CompressAlgo = enum(u8) {
    none = 0,
    lz4 = 1,
    lz4hc = 2,
    lzo = 3,
    lzo_rle = 4,
    zlib = 5,
    zstd = 6,
    deflate = 7,
    lzma = 8,
    bzip2 = 9,
    xz = 10,
    // Zxyphor
    zxy_fast = 100,
    zxy_balanced = 101,
    zxy_best = 102,
};

pub const CompressLevel = enum(u8) {
    fastest = 1,
    fast = 3,
    default = 6,
    better = 8,
    best = 9,
    ultra = 22,       // zstd max
};

pub const CompressContext = struct {
    algorithm: CompressAlgo,
    level: CompressLevel,
    window_bits: u8,          // For zlib/zstd
    workspace_size: u32,
    // Dictionary support
    dict_id: u32,
    dict_size: u32,
    // Streaming state
    is_streaming: bool,
    bytes_in: u64,
    bytes_out: u64,
};

pub const CompressStats = struct {
    total_compressed: u64,
    total_decompressed: u64,
    bytes_saved: u64,
    avg_ratio: u32,          // Fixed-point (× 100)
    compression_errors: u64,
    decompression_errors: u64,
};

// ============================================================================
// Checksum Routines
// ============================================================================

pub const CsumAlgorithm = enum(u8) {
    crc32 = 0,
    crc32c = 1,             // Castagnoli (iSCSI, btrfs)
    crc16 = 2,
    crc64_rocksoft = 3,     // NVMe
    crc_t10dif = 4,         // T10 DIF
    adler32 = 5,
    xxhash32 = 6,
    xxhash64 = 7,
    crc_itu_t = 8,
    crc_ccitt = 9,
    // IP networking
    ip_checksum = 20,       // One's complement
    tcp_checksum = 21,
    udp_checksum = 22,
    // Hardware accelerated
    hw_crc32c = 30,         // SSE4.2 CRC32C
};

pub const CsumConfig = struct {
    algorithm: CsumAlgorithm,
    seed: u64,
    hw_accelerated: bool,
    instruction_set: CsumHwAccel,
};

pub const CsumHwAccel = enum(u8) {
    none = 0,
    sse42 = 1,              // Intel SSE4.2 CRC32
    arm_crc = 2,            // ARM CRC32 extension
    pclmulqdq = 3,          // Carry-less multiply
    vpclmulqdq = 4,         // AVX-512 VPCLMULQDQ
};

pub const CsumStats = struct {
    computations: u64,
    bytes_processed: u64,
    hw_offloaded: u64,
    sw_fallback: u64,
};

// ============================================================================
// Firmware Loading Framework
// ============================================================================

pub const FirmwareLoadMode = enum(u8) {
    builtin = 0,            // Compiled into kernel
    filesystem = 1,         // /lib/firmware/
    userspace_helper = 2,   // udev helper
    direct_fs = 3,          // Direct filesystem read
    cache = 4,              // From firmware cache
    // Zxyphor
    zxy_secure_load = 100,  // Verified + encrypted firmware
};

pub const FirmwareFlags = packed struct(u32) {
    no_cache: bool = false,
    uevent: bool = false,
    no_uevent: bool = false,
    nowait: bool = false,
    optional: bool = false,
    compressed: bool = false,     // xz/zstd compressed
    partial: bool = false,        // partial read
    _reserved: u25 = 0,
};

pub const FirmwareDesc = struct {
    name: [256]u8,
    name_len: u16,
    size: u64,
    data_phys: u64,           // Physical address
    mode: FirmwareLoadMode,
    flags: FirmwareFlags,
    // Verification
    signature_verified: bool,
    hash_sha256: [32]u8,
    // Status
    loaded: bool,
    loading: bool,
    error_code: i32,
};

pub const FirmwareStats = struct {
    loads_total: u64,
    loads_builtin: u64,
    loads_filesystem: u64,
    loads_cache_hit: u64,
    loads_failed: u64,
    total_bytes_loaded: u64,
};

// ============================================================================
// Static Keys / Jump Labels
// ============================================================================

pub const StaticKeyType = enum(u1) {
    false_default = 0,
    true_default = 1,
};

pub const StaticKeyState = enum(u8) {
    disabled = 0,
    enabled = 1,
    pending_enable = 2,
    pending_disable = 3,
};

pub const StaticKeyEntry = struct {
    code_addr: u64,        // Address of NOP/JMP instruction
    target_addr: u64,      // Jump target address
    key_addr: u64,         // Static key variable address
    key_type: StaticKeyType,
    state: StaticKeyState,
};

pub const StaticKeyStats = struct {
    total_keys: u32,
    enabled_keys: u32,
    branch_updates: u64,
    text_patches: u64,
};

// ============================================================================
// Notifier Chains
// ============================================================================

pub const NotifierPriority = enum(i32) {
    lowest = -2147483648,
    low = -100,
    default = 0,
    high = 100,
    highest = 2147483647,
};

pub const NotifierAction = enum(u32) {
    done = 0,
    ok = 0,
    notify_bad = 2,
    stop = 4,
    stop_mask = 0x8000,
};

pub const NotifierChainType = enum(u8) {
    atomic = 0,
    blocking = 1,
    raw = 2,
    srcu = 3,
};

pub const NotifierBlock = struct {
    callback: ?*const fn (u64, ?*anyopaque) NotifierAction,
    next: ?*NotifierBlock,
    priority: i32,
};

// ============================================================================
// Per-CPU Operations
// ============================================================================

pub const PercpuAllocator = struct {
    base_addr: u64,
    unit_size: u64,        // Size of each per-CPU unit
    nr_units: u32,         // One per CPU
    nr_groups: u32,        // NUMA groups
    atom_size: u32,        // Allocation alignment
    reserved_size: u32,
    dyn_size: u32,         // Dynamic area size
    // Statistics
    total_allocated: u64,
    total_available: u64,
    nr_chunks: u32,
};

pub const PercpuChunkType = enum(u8) {
    reserved = 0,
    first = 1,
    normal = 2,
};

// ============================================================================
// Refcount (overflow-safe reference counting)
// ============================================================================

pub const RefcountSaturation = enum(u8) {
    none = 0,
    @"default" = 1,
    full_paranoid = 2,
};

pub const RefcountConfig = struct {
    saturation: RefcountSaturation,
    warn_on_saturate: bool,
    warn_on_zero_dec: bool,
};

pub const RefcountStats = struct {
    saturation_warnings: u64,
    zero_dec_warnings: u64,
    underflow_attempts: u64,
    overflow_attempts: u64,
};

// ============================================================================
// Seqlock / Seqcount
// ============================================================================

pub const SeqlockType = enum(u8) {
    raw = 0,              // seqcount_t
    spinlock = 1,         // seqcount_spinlock_t
    rwlock = 2,           // seqcount_rwlock_t
    mutex = 3,            // seqcount_mutex_t
    ww_mutex = 4,         // seqcount_ww_mutex_t
};

pub const SeqcountState = struct {
    sequence: u32,        // Even = stable, Odd = write in progress
};

// ============================================================================
// Lockref (spinlock + reference count)
// ============================================================================

pub const LockrefState = struct {
    lock: u32,            // Spinlock
    count: i32,           // Reference count
    // Combined into single 64-bit for cmpxchg optimization
};

// ============================================================================
// Kernel Utility Library Manager (Zxyphor)
// ============================================================================

pub const KernelUtilManager = struct {
    sort_stats: SortStats,
    compress_stats: CompressStats,
    csum_stats: CsumStats,
    firmware_stats: FirmwareStats,
    static_key_stats: StaticKeyStats,
    percpu: PercpuAllocator,
    refcount_stats: RefcountStats,
    initialized: bool,

    pub fn init() KernelUtilManager {
        return .{
            .sort_stats = std.mem.zeroes(SortStats),
            .compress_stats = std.mem.zeroes(CompressStats),
            .csum_stats = std.mem.zeroes(CsumStats),
            .firmware_stats = std.mem.zeroes(FirmwareStats),
            .static_key_stats = std.mem.zeroes(StaticKeyStats),
            .percpu = std.mem.zeroes(PercpuAllocator),
            .refcount_stats = std.mem.zeroes(RefcountStats),
            .initialized = true,
        };
    }
};
