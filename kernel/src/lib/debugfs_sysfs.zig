// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Debugfs, Sysfs Helpers,
// Kobject Internals, Radix Tree,
// String Helpers, Bitmap API,
// IDR/IDA, Generic Netlink,
// Kernel Module Framework, Symbol Export
// More advanced than Linux 2026 kernel library

const std = @import("std");

// ============================================================================
// Debugfs
// ============================================================================

/// Debugfs file mode
pub const DebugfsMode = packed struct(u16) {
    other_x: bool = false,
    other_w: bool = false,
    other_r: bool = false,
    group_x: bool = false,
    group_w: bool = false,
    group_r: bool = false,
    owner_x: bool = false,
    owner_w: bool = false,
    owner_r: bool = false,
    sticky: bool = false,
    setgid: bool = false,
    setuid: bool = false,
    _format: u4 = 0,
};

/// Debugfs entry type
pub const DebugfsEntryType = enum(u8) {
    file = 0,
    dir = 1,
    symlink = 2,
    blob = 3,
    bool_val = 4,
    u8_val = 5,
    u16_val = 6,
    u32_val = 7,
    u64_val = 8,
    x8_val = 9,        // hex
    x16_val = 10,
    x32_val = 11,
    x64_val = 12,
    size_t_val = 13,
    atomic_t_val = 14,
    regset32 = 15,
    devm = 16,
};

/// Debugfs entry descriptor
pub const DebugfsEntry = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    entry_type: DebugfsEntryType = .file,
    mode: DebugfsMode = .{},
    parent: u64 = 0,          // parent dentry
    data: u64 = 0,            // private data
    size: u64 = 0,
};

// ============================================================================
// Sysfs Helpers
// ============================================================================

/// Sysfs attribute type
pub const SysfsAttrType = enum(u8) {
    normal = 0,
    binary = 1,
    group = 2,
};

/// Sysfs attribute flags
pub const SysfsAttrFlags = packed struct(u16) {
    prealloc: bool = false,
    ignore_lockdep: bool = false,
    is_visible: bool = false,
    is_bin: bool = false,
    _padding: u12 = 0,
};

/// Sysfs attribute descriptor
pub const SysfsAttrDesc = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    mode: DebugfsMode = .{},
    attr_type: SysfsAttrType = .normal,
    flags: SysfsAttrFlags = .{},
    size: u64 = 0,
};

/// Sysfs group descriptor
pub const SysfsGroupDesc = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    nr_attrs: u32 = 0,
    nr_bin_attrs: u32 = 0,
    is_visible: bool = false,
};

// ============================================================================
// Kobject Internals
// ============================================================================

/// Kobject type
pub const KobjType = enum(u8) {
    device = 0,
    driver = 1,
    bus = 2,
    class = 3,
    firmware = 4,
    module = 5,
    block = 6,
    // Zxyphor
    zxy_subsystem = 100,
};

/// Kobject state
pub const KobjState = packed struct(u32) {
    initialized: bool = false,
    in_sysfs: bool = false,
    name_set: bool = false,
    delete_pending: bool = false,
    _padding: u28 = 0,
};

/// Kobject uevent action
pub const KobjUeventAction = enum(u8) {
    add = 0,
    remove = 1,
    change = 2,
    move = 3,
    online = 4,
    offline = 5,
    bind = 6,
    unbind = 7,
};

/// Kobject uevent environment
pub const KobjUeventEnv = struct {
    envp: [64][256]u8 = undefined,
    envp_count: u32 = 0,
    buf: [2048]u8 = [_]u8{0} ** 2048,
    buflen: u32 = 0,
};

/// Kset descriptor
pub const KsetDesc = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    parent: u64 = 0,
    nr_kobjects: u32 = 0,
    uevent_ops: bool = false,
};

// ============================================================================
// Radix Tree
// ============================================================================

/// Radix tree node (conceptual description)
pub const RadixTreeNode = struct {
    shift: u8 = 0,
    offset: u8 = 0,
    count: u8 = 0,
    exceptional: u8 = 0,
    parent: u64 = 0,
    tags: [3]u64 = [_]u64{0} ** 3,   // tag bitmaps
};

/// Radix tree tags
pub const RadixTreeTag = enum(u8) {
    dirty = 0,
    writeback = 1,
    towrite = 2,
};

/// XArray marks (supersedes radix tree tags)
pub const XArrayMark = enum(u8) {
    mark0 = 0,
    mark1 = 1,
    mark2 = 2,
};

/// XArray flags
pub const XArrayFlags = packed struct(u32) {
    lock_irq: bool = false,
    lock_bh: bool = false,
    // Zxyphor
    zxy_rcu: bool = false,
    _padding: u29 = 0,
};

// ============================================================================
// IDR / IDA
// ============================================================================

/// IDR (ID Radix tree) descriptor
pub const IdrDesc = struct {
    base: u32 = 0,            // minimum ID
    next: u32 = 0,            // next expected ID
    cur: u32 = 0,             // current allocated count
    max: u32 = 0x7FFFFFFF,    // maximum ID
};

/// IDA (ID Allocator) descriptor
pub const IdaDesc = struct {
    next: u32 = 0,
    allocated: u64 = 0,
};

// ============================================================================
// Bitmap API
// ============================================================================

/// Bitmap operations descriptor
pub const BitmapDesc = struct {
    nr_bits: u64 = 0,
    nr_longs: u64 = 0,
    weight: u64 = 0,          // nr of set bits
};

/// NUMA node bitmap (for CPU/memory topology)
pub const NumaNodeBitmap = struct {
    mask: [64]u64 = [_]u64{0} ** 64,    // supports 4096 nodes
    nr_nodes: u32 = 0,
};

/// CPU bitmap
pub const CpuBitmap = struct {
    mask: [64]u64 = [_]u64{0} ** 64,    // supports 4096 CPUs
    nr_cpus_present: u32 = 0,
    nr_cpus_online: u32 = 0,
    nr_cpus_possible: u32 = 0,
    nr_cpus_active: u32 = 0,
};

// ============================================================================
// String Helpers
// ============================================================================

/// String hash type
pub const StringHashType = enum(u8) {
    half_md4 = 0,
    tea = 1,
    siphash = 2,
    // Zxyphor
    zxy_fast = 100,
};

/// Kernel string format specifiers
pub const PrintfSpec = enum(u8) {
    // Standard
    decimal = 'd',
    unsigned = 'u',
    hex = 'x',
    oct = 'o',
    string = 's',
    char = 'c',
    pointer = 'p',
    percent = '%',
    // Extended %p formats
    ptr_symbol = 'S',        // %pS kernel symbol
    ptr_func = 'f',          // %pf function name
    ptr_resource = 'R',      // %pR resource
    ptr_mac = 'M',           // %pM MAC address
    ptr_ipv4 = 'I',          // %pI4 IPv4 address
    ptr_ipv6 = 'i',          // %pI6 IPv6 address
    ptr_uuid = 'U',          // %pU UUID
    ptr_dentry = 'D',        // %pd dentry name
    ptr_va_fmt = 'V',        // %pV va_format
    ptr_netdev = 'N',        // %pN netdev features
    ptr_flags = 'G',         // %pGp page flags
};

// ============================================================================
// Kernel Module Framework
// ============================================================================

/// Module state
pub const ModuleState = enum(u8) {
    live = 0,
    coming = 1,
    going = 2,
    unformed = 3,
};

/// Module flags
pub const ModuleFlags = packed struct(u32) {
    force_unload: bool = false,
    init_live: bool = false,
    sig_ok: bool = false,
    livepatch: bool = false,
    going_remove: bool = false,
    // Zxyphor
    zxy_verified: bool = false,
    _padding: u26 = 0,
};

/// Module taints
pub const ModuleTaint = packed struct(u32) {
    proprietary: bool = false,          // P
    forced_load: bool = false,          // F
    cpu_out_of_spec: bool = false,      // S
    forced_unload: bool = false,        // R
    machine_check: bool = false,        // M
    bad_page: bool = false,             // B
    user_request: bool = false,         // U
    die_oops: bool = false,             // D
    out_of_tree: bool = false,          // O
    firmware_workaround: bool = false,  // E
    staging: bool = false,              // C
    unsigned_module: bool = false,      // N
    soft_lockup: bool = false,          // L
    livepatch: bool = false,            // K
    test: bool = false,                 // T
    _padding: u17 = 0,
};

/// Module descriptor
pub const ModuleDesc = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    version: [64]u8 = [_]u8{0} ** 64,
    version_len: u8 = 0,
    srcversion: [25]u8 = [_]u8{0} ** 25,
    state: ModuleState = .unformed,
    flags: ModuleFlags = .{},
    taints: ModuleTaint = .{},
    // Memory layout
    init_layout_size: u64 = 0,
    core_layout_size: u64 = 0,
    init_layout_text: u64 = 0,
    core_layout_text: u64 = 0,
    init_layout_ro: u64 = 0,
    core_layout_ro: u64 = 0,
    // Symbols
    num_syms: u32 = 0,
    num_gpl_syms: u32 = 0,
    // Parameters
    num_params: u32 = 0,
    // Dependencies
    num_deps: u32 = 0,
    refcnt: u32 = 0,
};

/// Symbol export type
pub const SymbolExportType = enum(u8) {
    plain = 0,
    gpl = 1,
    gpl_future = 2,
    // Zxyphor
    zxy_stable = 100,
};

/// Kernel symbol
pub const KernelSymbol = struct {
    name: [128]u8 = [_]u8{0} ** 128,
    name_len: u8 = 0,
    address: u64 = 0,
    module: [64]u8 = [_]u8{0} ** 64,
    module_len: u8 = 0,
    export_type: SymbolExportType = .plain,
    crc: u32 = 0,
};

/// Module parameter type
pub const ModParamType = enum(u8) {
    bool_type = 0,
    byte_type = 1,
    short_type = 2,
    ushort_type = 3,
    int_type = 4,
    uint_type = 5,
    long_type = 6,
    ulong_type = 7,
    charp_type = 8,
    string_type = 9,
    invbool_type = 10,
    // Array types
    array_type = 20,
};

// ============================================================================
// Kernel Library Subsystem Manager
// ============================================================================

pub const KernelLibSubsystem = struct {
    debugfs_mounted: bool = false,
    nr_debugfs_entries: u64 = 0,
    sysfs_mounted: bool = false,
    nr_sysfs_entries: u64 = 0,
    nr_kobjects: u64 = 0,
    nr_ksets: u32 = 0,
    nr_modules_loaded: u32 = 0,
    nr_symbols_exported: u64 = 0,
    nr_idr_allocated: u64 = 0,
    string_hash_type: StringHashType = .siphash,
    initialized: bool = false,

    pub fn init() KernelLibSubsystem {
        return KernelLibSubsystem{
            .initialized = true,
        };
    }
};
