// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Xarray, Maple Tree, Radix Tree Detail,
// String Formatting/Parsing, Bitmap Operations,
// IDR/IDA, Sorting Algorithms, Printf Engine
// More advanced than Linux 2026 kernel library

const std = @import("std");

// ============================================================================
// Xarray (eXtensible Array)
// ============================================================================

/// Xarray flags
pub const XarrayFlags = packed struct {
    lock_irq: bool = false,       // XA_FLAGS_LOCK_IRQ
    lock_bh: bool = false,        // XA_FLAGS_LOCK_BH
    track_free: bool = false,     // XA_FLAGS_TRACK_FREE
    zero_busy: bool = false,      // XA_FLAGS_ZERO_BUSY
    alloc: bool = false,          // XA_FLAGS_ALLOC
    alloc1: bool = false,         // XA_FLAGS_ALLOC1
    account: bool = false,        // XA_FLAGS_ACCOUNT
    _padding: u1 = 0,
};

/// Xarray marks (3 marks available)
pub const XarrayMark = enum(u2) {
    mark_0 = 0,          // XA_MARK_0
    mark_1 = 1,          // XA_MARK_1
    mark_2 = 2,          // XA_MARK_2
};

/// Xarray node entry tags
pub const XA_ENTRY_FREE: u64 = 0;
pub const XA_ENTRY_RETRY: u64 = 0x100;
pub const XA_ENTRY_ZERO: u64 = 0x200;

/// Xarray node (16 slots per node)
pub const XarrayNode = struct {
    shift: u8,            // Bits away from leaf
    offset: u8,           // Slot offset in parent
    count: u8,            // Total entries
    nr_values: u8,        // Number of value entries
    parent: ?*XarrayNode, // Parent node
    // Slots (16 per node)
    slots: [16]u64,       // Pointers or values
    // Tags/marks (3 marks, 16 bits each)
    marks: [3]u16,
    // Union type for different node types
    node_type: XaNodeType,
};

pub const XaNodeType = enum(u8) {
    internal = 0,
    leaf = 1,
};

/// Xarray descriptor
pub const Xarray = struct {
    head: u64,            // Root entry
    flags: XarrayFlags,
    // Statistics
    nr_entries: u64,
    nr_nodes: u64,
    max_index: u64,
};

/// Xarray state (for iteration)
pub const XarrayState = struct {
    node: ?*XarrayNode,
    index: u64,
    shift: u8,
    sibs: u8,
    offset: u8,
    marks: u8,
};

// ============================================================================
// Maple Tree
// ============================================================================

/// Maple tree flags
pub const MapleTreeFlags = packed struct {
    alloc_range: bool = false,    // MT_FLAGS_ALLOC_RANGE
    use_rcu: bool = false,        // MT_FLAGS_USE_RCU
    height_offset: u6 = 0,       // Tree height (bits 2-7)
    lock_type: MapleTreeLockType = .spin,
    _padding: u6 = 0,
};

pub const MapleTreeLockType = enum(u2) {
    spin = 0,
    lock = 1,
    none = 2,
};

/// Maple tree node types
pub const MapleNodeType = enum(u8) {
    dense = 0,           // Dense leaves
    leaf_64 = 1,         // Leaf node with 64-bit pivots
    range_64 = 2,        // Range node with 64-bit pivots
    arange_64 = 3,       // Allocation range node
};

/// Maple tree node (16 slots)
pub const MapleNode = struct {
    parent: u64,          // Parent pointer with type info
    node_type: MapleNodeType,
    // For range nodes
    pivots: [15]u64,      // Max 15 pivots (16 - 1)
    slots: [16]u64,       // Pointers
    // Gaps (for arange_64 nodes)
    gaps: [16]u64,
    // Metadata
    pad: u8,
    end: u8,              // Number of valid entries
};

/// Maple tree descriptor
pub const MapleTree = struct {
    root: u64,            // Root node or value
    flags: MapleTreeFlags,
    height: u8,
    // Statistics
    nr_entries: u64,
    nr_nodes: u64,
};

/// Maple tree state (iterator/walk)
pub const MapleTreeState = struct {
    tree: *MapleTree,
    index: u64,
    last: u64,            // Last index in range
    node: ?*MapleNode,
    min: u64,
    max: u64,
    alloc: ?*MapleNode,   // Pre-allocated nodes
    offset: u8,
    depth: u8,
    status: MtStatus,
};

pub const MtStatus = enum(u8) {
    active = 0,
    start = 1,
    none = 2,
    root = 3,
    pause = 4,
    overflow = 5,
    underflow = 6,
};

// ============================================================================
// IDR/IDA (Integer ID Allocator)
// ============================================================================

/// IDR descriptor
pub const Idr = struct {
    // Backed by xarray
    xa: Xarray,
    // Next ID hint
    idr_next: u32,
    // Range
    idr_base: u32,
};

/// IDA (ID Allocator - simpler, bitmap-based)
pub const Ida = struct {
    xa: Xarray,
};

/// IDR/IDA config
pub const IdrConfig = struct {
    base: u32,            // Minimum ID
    max: u32,             // Maximum ID (usually INT_MAX)
    cyclic: bool,         // Cyclic allocation
};

// ============================================================================
// Printf Engine
// ============================================================================

/// Printf format specifier
pub const PrintfSpec = struct {
    spec_type: PrintfType,
    flags: PrintfFlags,
    width: i32,
    precision: i32,
    qualifier: PrintfQualifier,
    base: u8,
};

/// Printf type
pub const PrintfType = enum(u8) {
    none = 0,
    percent = 1,
    char_type = 2,
    string = 3,
    ptr = 4,
    nrchars = 5,
    width = 6,
    precision = 7,
    // Integer types
    ulong = 10,
    long = 11,
    ulonglong = 12,
    longlong = 13,
    size = 14,
    ptrdiff = 15,
    ubyte = 16,
    byte = 17,
    ushort = 18,
    short = 19,
    uint = 20,
    int = 21,
};

/// Printf flags
pub const PrintfFlags = packed struct {
    zeropad: bool = false,
    sign: bool = false,
    plus: bool = false,
    space: bool = false,
    left: bool = false,
    small: bool = false,    // Lowercase hex
    special: bool = false,  // 0x prefix
    _padding: u1 = 0,
};

/// Printf qualifier
pub const PrintfQualifier = enum(u8) {
    none = 0,
    h = 1,               // short
    hh = 2,              // char
    l = 3,               // long
    ll = 4,              // long long
    L = 5,               // long double
    z = 6,               // size_t
    t = 7,               // ptrdiff_t
};

/// Pointer format extensions (%p*)
pub const PtrFormatType = enum(u8) {
    default = 0,         // %p - hashed pointer
    raw = 1,             // %px - raw pointer
    symbol = 2,          // %pS - symbol name
    symbol_raw = 3,      // %ps - symbol name (no offset)
    resource = 4,        // %pR - struct resource
    mac = 5,             // %pM - MAC address
    mac_reverse = 6,     // %pm - MAC in reverse
    ipv4 = 7,            // %pI4 - IPv4
    ipv6 = 8,            // %pI6 - IPv6
    ipv6_short = 9,      // %pI6c - IPv6 shortened
    uuid = 10,           // %pU - UUID
    dentry = 11,         // %pd - dentry name
    dentry_full = 12,    // %pD - file name
    va_format = 13,      // %pV - va_format
    netdev = 14,         // %pNF - netdev features
    fw_node = 15,        // %pfwP - firmware node
    bitmap = 16,         // %*pb - bitmap
    bitmap_list = 17,    // %*pbl - bitmap as list
    page = 18,           // %pg - struct page
    flags = 19,          // %pGp - page flags
    clock = 20,          // %pC - clock
    of_node = 21,        // %pOF - device tree node
    // Zxyphor
    zxy_error = 30,     // %pE - error code
    zxy_timespec = 31,  // %pT - timespec
};

// ============================================================================
// Bitmap Operations
// ============================================================================

/// Bitmap operations
pub const BitmapOps = struct {
    pub const BITS_PER_LONG: usize = 64;
    pub const BITS_PER_BYTE: usize = 8;

    // Bitmap sizes for common use cases
    pub const CPU_BITS: usize = 256;  // MAX_NR_CPUS
    pub const NUMA_BITS: usize = 64;  // MAX_NUMNODES
    pub const IRQ_BITS: usize = 1024; // NR_IRQS
};

/// Bitmap descriptor
pub const BitmapDesc = struct {
    bits: [*]u64,
    nbits: u32,
    // Stats
    weight: u32,          // Number of set bits (cached)
};

// ============================================================================
// Sorting Algorithms
// ============================================================================

/// Sort algorithm
pub const SortAlgo = enum(u8) {
    heapsort = 0,         // Default kernel sort
    introsort = 1,        // Quicksort + heapsort
    radixsort = 2,        // For integers
    mergesort = 3,        // Stable sort
    timsort = 4,          // Python-style
    // Zxyphor
    zxy_adaptive = 10,    // Auto-select based on data
};

/// Sort config
pub const SortConfig = struct {
    algo: SortAlgo,
    element_size: usize,
    nr_elements: usize,
    // Comparison function pointer
    cmp_fn: ?*const fn (a: *const anyopaque, b: *const anyopaque) callconv(.C) i32,
    // Swap function pointer
    swap_fn: ?*const fn (a: *anyopaque, b: *anyopaque, size: usize) callconv(.C) void,
};

// ============================================================================
// String Parsing
// ============================================================================

/// Parse result
pub const ParseResult = struct {
    value: i64,
    end_pos: usize,
    err: ParseError,
};

pub const ParseError = enum(u8) {
    success = 0,
    overflow = 1,
    underflow = 2,
    invalid = 3,
    empty = 4,
    trailing = 5,
};

/// String match type (for kernel command line)
pub const MatchType = enum(u8) {
    exact = 0,
    prefix = 1,
    substring = 2,
    token = 3,
    glob = 4,
};

/// Match token
pub const MatchToken = struct {
    token: i32,
    pattern: [64]u8,
    pattern_len: u8,
};

// ============================================================================
// Kernel Hashing
// ============================================================================

/// Hash algorithm for internal use
pub const KernelHashType = enum(u8) {
    jhash = 0,           // Jenkins hash
    xxhash32 = 1,
    xxhash64 = 2,
    siphash = 3,
    halfsiphash = 4,
    // Zxyphor
    zxy_fast_hash = 10,
};

/// Hash descriptor
pub const HashDesc = struct {
    hash_type: KernelHashType,
    seed: u64,
    // For hash tables
    bits: u8,            // log2(table_size)
    table_size: u32,
};

/// SipHash key
pub const SipHashKey = struct {
    key: [2]u64,
};

/// HalfSipHash key
pub const HalfSipHashKey = struct {
    key: [2]u32,
};

// ============================================================================
// Checksum
// ============================================================================

/// Checksum type
pub const ChecksumType = enum(u8) {
    crc32 = 0,
    crc32c = 1,
    crc16 = 2,
    crc_t10dif = 3,
    adler32 = 4,
    // Zxyphor
    zxy_xxh3 = 10,
};

/// CRC polynomial
pub const CrcPoly = enum(u32) {
    crc32 = 0xEDB88320,     // Standard CRC32
    crc32c = 0x82F63B78,    // Castagnoli
    crc16_ccitt = 0x8408,
    crc_t10dif = 0x8BB7,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const KernelLibSubsystem = struct {
    // Xarray
    nr_xarrays: u64,
    total_xa_entries: u64,
    total_xa_nodes: u64,
    // Maple tree
    nr_maple_trees: u64,
    total_mt_entries: u64,
    total_mt_nodes: u64,
    // IDR/IDA
    nr_idrs: u64,
    nr_idas: u64,
    total_ids_allocated: u64,
    // Bitmap
    nr_bitmaps: u64,
    // Printf
    total_printf_calls: u64,
    // Hashing
    total_hash_ops: u64,
    // CRC
    total_crc_ops: u64,
    // Zxyphor
    zxy_adaptive_ds: bool,
    initialized: bool,

    pub fn init() KernelLibSubsystem {
        return KernelLibSubsystem{
            .nr_xarrays = 0,
            .total_xa_entries = 0,
            .total_xa_nodes = 0,
            .nr_maple_trees = 0,
            .total_mt_entries = 0,
            .total_mt_nodes = 0,
            .nr_idrs = 0,
            .nr_idas = 0,
            .total_ids_allocated = 0,
            .nr_bitmaps = 0,
            .total_printf_calls = 0,
            .total_hash_ops = 0,
            .total_crc_ops = 0,
            .zxy_adaptive_ds = true,
            .initialized = false,
        };
    }
};
