// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Module Loading, sysctl, kmod, kernel parameters,
// Module dependencies, module signing, livepatch
// More advanced than Linux 2026 module subsystem

const std = @import("std");

// ============================================================================
// Kernel Module
// ============================================================================

pub const ModuleState = enum(u8) {
    live = 0,
    coming = 1,
    going = 2,
    unformed = 3,
};

pub const ModuleTaint = packed struct {
    proprietary: bool = false,         // P
    staged: bool = false,              // C
    forced_load: bool = false,         // F
    forced_unload: bool = false,       // R
    unsigned: bool = false,            // E
    out_of_tree: bool = false,         // O
    test: bool = false,                // T
    livepatch: bool = false,           // K
    _padding: u8 = 0,
};

pub const ModuleFlags = packed struct {
    gpl_compatible: bool = false,
    async_probe: bool = false,
    init_done: bool = false,
    sig_ok: bool = false,
    built_in: bool = false,
    // Zxyphor
    zxy_verified: bool = false,
    zxy_sandboxed: bool = false,
    _padding: u1 = 0,
};

pub const Module = struct {
    name: [56]u8 = [_]u8{0} ** 56,
    state: ModuleState = .unformed,
    flags: ModuleFlags = .{},
    taint: ModuleTaint = .{},
    // Version
    version: [64]u8 = [_]u8{0} ** 64,
    srcversion: [25]u8 = [_]u8{0} ** 25,
    // License
    license: [32]u8 = [_]u8{0} ** 32,
    // Size
    core_size: u64 = 0,
    init_size: u64 = 0,
    core_text_size: u64 = 0,
    core_ro_size: u64 = 0,
    core_ro_after_init_size: u64 = 0,
    // Module layout
    core_layout_base: u64 = 0,
    init_layout_base: u64 = 0,
    // Sections
    num_symtab: u32 = 0,
    num_gpl_syms: u32 = 0,
    // Parameters
    num_params: u32 = 0,
    // Dependencies
    num_depends: u32 = 0,
    refcnt: u32 = 0,
    // Module init/exit
    has_init: bool = false,
    has_exit: bool = false,
    // Percpu
    percpu_size: u32 = 0,
    // Signature
    sig_algo: [8]u8 = [_]u8{0} ** 8,
    sig_hash: [8]u8 = [_]u8{0} ** 8,
    sig_id_type: u8 = 0,
    sig_signer_len: u32 = 0,
    sig_key_id_len: u32 = 0,
    sig_len: u32 = 0,
    // Modinfo
    author: [128]u8 = [_]u8{0} ** 128,
    description: [256]u8 = [_]u8{0} ** 256,
    // BTF
    has_btf: bool = false,
    btf_data_size: u32 = 0,
};

pub const ModParam = struct {
    name: [56]u8 = [_]u8{0} ** 56,
    ptype: ModParamType = .int,
    perm: u16 = 0o644,
    // Current value
    int_val: i64 = 0,
    str_val: [256]u8 = [_]u8{0} ** 256,
    bool_val: bool = false,
};

pub const ModParamType = enum(u8) {
    bool = 0,
    int = 1,
    uint = 2,
    long = 3,
    ulong = 4,
    charp = 5,     // char pointer (string)
    short = 6,
    ushort = 7,
    byte = 8,
    invbool = 9,
    hexint = 10,
};

// ============================================================================
// Module Symbol Export
// ============================================================================

pub const SymbolType = enum(u8) {
    export = 0,
    export_gpl = 1,
    export_gpl_future = 2,
    // Zxyphor
    export_zxy = 10,
};

pub const KernelSymbol = struct {
    name: [128]u8 = [_]u8{0} ** 128,
    addr: u64 = 0,
    namespace: [64]u8 = [_]u8{0} ** 64,
    sym_type: SymbolType = .export_gpl,
    module_name: [56]u8 = [_]u8{0} ** 56,
};

// ============================================================================
// Module Signing
// ============================================================================

pub const ModSigAlgo = enum(u8) {
    rsa = 0,
    ecdsa = 1,
    ecdsa_nist_p256 = 2,
    ecdsa_nist_p384 = 3,
    sm2 = 4,
    // Zxyphor
    zxy_ed25519 = 10,
};

pub const ModSigHash = enum(u8) {
    sha256 = 0,
    sha384 = 1,
    sha512 = 2,
    sm3 = 3,
    // Zxyphor
    zxy_blake3 = 10,
};

pub const ModSigConfig = struct {
    require_signed: bool = true,
    allow_unsigned: bool = false,
    force_signed: bool = false,
    // Algorithms
    sig_algo: ModSigAlgo = .rsa,
    sig_hash: ModSigHash = .sha512,
    // Key
    key_id: [20]u8 = [_]u8{0} ** 20,
    // Stats
    total_verified: u64 = 0,
    total_rejected: u64 = 0,
};

// ============================================================================
// Livepatch
// ============================================================================

pub const LivepatchState = enum(u8) {
    disabled = 0,
    enabled = 1,
    transition = 2,
};

pub const LivepatchFunc = struct {
    old_name: [128]u8 = [_]u8{0} ** 128,
    new_addr: u64 = 0,
    old_addr: u64 = 0,
    old_size: u64 = 0,
    // ftrace integration
    fops_addr: u64 = 0,
    // Status
    patched: bool = false,
    nop: bool = false,         // No-op patch (undo)
};

pub const LivepatchObject = struct {
    name: [56]u8 = [_]u8{0} ** 56,   // Module name or "vmlinux"
    nr_funcs: u32 = 0,
    patched: bool = false,
};

pub const Livepatch = struct {
    mod_name: [56]u8 = [_]u8{0} ** 56,
    state: LivepatchState = .disabled,
    // Objects
    nr_objects: u32 = 0,
    // Transition
    transition_started: bool = false,
    transition_complete: bool = false,
    forced: bool = false,
    // Stats
    total_apply: u64 = 0,
    total_revert: u64 = 0,
};

// ============================================================================
// sysctl
// ============================================================================

pub const SysctlType = enum(u8) {
    integer = 0,
    string = 1,
    ulong = 2,
    u8_val = 3,
    u16_val = 4,
    u32_val = 5,
    u64_val = 6,
    bool_val = 7,
};

pub const SysctlEntry = struct {
    procname: [64]u8 = [_]u8{0} ** 64,
    data_type: SysctlType = .integer,
    maxlen: u32 = 0,
    mode: u16 = 0o644,
    // Extra bounds
    extra1: i64 = 0,    // min value
    extra2: i64 = 0,    // max value
    // Current value
    int_value: i64 = 0,
    str_value: [256]u8 = [_]u8{0} ** 256,
};

/// Well-known sysctl paths
pub const SysctlPath = enum(u8) {
    kernel = 0,
    vm = 1,
    fs = 2,
    net = 3,
    net_core = 4,
    net_ipv4 = 5,
    net_ipv6 = 6,
    debug = 7,
    dev = 8,
    abi = 9,
    // Zxyphor
    zxy = 10,
};

/// Important kernel sysctls
pub const KernelSysctls = struct {
    // Kernel
    hostname: [64]u8 = [_]u8{0} ** 64,
    domainname: [64]u8 = [_]u8{0} ** 64,
    ostype: [64]u8 = [_]u8{0} ** 64,
    osrelease: [64]u8 = [_]u8{0} ** 64,
    version: [64]u8 = [_]u8{0} ** 64,
    shmmax: u64 = 0,
    shmall: u64 = 0,
    shmmni: u32 = 0,
    msgmax: u32 = 0,
    msgmni: u32 = 0,
    msgmnb: u32 = 0,
    sem: [4]u32 = [_]u32{0} ** 4,
    pid_max: i32 = 4194304,
    threads_max: i32 = 0,
    panic: i32 = 0,
    panic_on_oops: i32 = 0,
    panic_on_warn: i32 = 0,
    printk_ratelimit: i32 = 5,
    printk_ratelimit_burst: i32 = 10,
    ngroups_max: i32 = 65536,
    randomize_va_space: i32 = 2,
    modprobe: [256]u8 = [_]u8{0} ** 256,
    core_pattern: [256]u8 = [_]u8{0} ** 256,
    core_pipe_limit: i32 = 0,
    // VM
    overcommit_memory: i32 = 0,
    overcommit_ratio: i32 = 50,
    dirty_ratio: i32 = 20,
    dirty_background_ratio: i32 = 10,
    dirty_expire_centisecs: i32 = 3000,
    dirty_writeback_centisecs: i32 = 500,
    swappiness: i32 = 60,
    vfs_cache_pressure: i32 = 100,
    min_free_kbytes: i32 = 0,
    watermark_boost_factor: i32 = 15000,
    watermark_scale_factor: i32 = 10,
    compaction_proactiveness: i32 = 20,
    // Net
    tcp_keepalive_time: i32 = 7200,
    tcp_keepalive_probes: i32 = 9,
    tcp_keepalive_intvl: i32 = 75,
    tcp_syncookies: i32 = 1,
    tcp_max_syn_backlog: i32 = 1024,
    tcp_fin_timeout: i32 = 60,
    tcp_max_tw_buckets: i32 = 16384,
    ip_forward: i32 = 0,
    ip_default_ttl: i32 = 64,
    somaxconn: i32 = 4096,
    netdev_budget: i32 = 300,
    netdev_budget_usecs: i32 = 8000,
    rmem_default: i32 = 212992,
    rmem_max: i32 = 212992,
    wmem_default: i32 = 212992,
    wmem_max: i32 = 212992,
};

// ============================================================================
// kmod (Kernel Module Loader Daemon)
// ============================================================================

pub const KmodRequest = struct {
    module_name: [56]u8 = [_]u8{0} ** 56,
    wait: bool = true,
    // Result
    retval: i32 = 0,
    loaded: bool = false,
    // Timing
    request_time_ns: u64 = 0,
    complete_time_ns: u64 = 0,
};

pub const KmodConfig = struct {
    max_modprobes: u32 = 50,
    enabled: bool = true,
    // Allowlist/Denylist
    nr_allowed: u32 = 0,
    nr_denied: u32 = 0,
    // Stats
    total_requests: u64 = 0,
    total_loaded: u64 = 0,
    total_failed: u64 = 0,
    total_denied: u64 = 0,
};

// ============================================================================
// Kernel Command Line
// ============================================================================

pub const BootParamType = enum(u8) {
    boolean = 0,
    integer = 1,
    string = 2,
    ulong = 3,
    // Early params
    early = 10,
};

pub const BootParam = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    ptype: BootParamType = .string,
    str_val: [256]u8 = [_]u8{0} ** 256,
    int_val: i64 = 0,
    bool_val: bool = false,
    is_early: bool = false,
    was_set: bool = false,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const ModuleSubsystem = struct {
    // Loaded modules
    nr_modules: u32 = 0,
    nr_live: u32 = 0,
    nr_coming: u32 = 0,
    nr_going: u32 = 0,
    // Memory
    total_core_size: u64 = 0,
    total_init_size: u64 = 0,
    // Symbols
    nr_exported_symbols: u32 = 0,
    nr_gpl_symbols: u32 = 0,
    // Signing
    sig_config: ModSigConfig = .{},
    // Livepatch
    nr_livepatches: u32 = 0,
    nr_active_patches: u32 = 0,
    // sysctl
    nr_sysctl_tables: u32 = 0,
    nr_sysctl_entries: u64 = 0,
    // kmod
    kmod: KmodConfig = .{},
    // Boot params
    nr_boot_params: u32 = 0,
    // Zxyphor
    zxy_module_sandbox_enabled: bool = false,
    initialized: bool = false,
};
