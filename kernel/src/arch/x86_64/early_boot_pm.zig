// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Early Boot, Microcode Update, Power Management Arch,
// MSR control, CPUID parsing, CPU topology, x86 early setup
// More advanced than Linux 2026 x86_64 boot subsystem

const std = @import("std");

// ============================================================================
// Early Boot (startup_64 / early init)
// ============================================================================

pub const EarlyBootStage = enum(u8) {
    bios_handoff = 0,
    real_mode_setup = 1,
    protected_mode_enter = 2,
    long_mode_enter = 3,
    early_page_table = 4,
    early_console = 5,
    early_memory = 6,
    early_irq = 7,
    cpu_init = 8,
    boot_cpu_ready = 9,
    ap_startup = 10,
    kernel_start = 11,
    // Zxyphor
    zxy_security_init = 20,
    zxy_hw_validation = 21,
};

pub const BootParams = struct {
    // Screen info
    orig_x: u8 = 0,
    orig_y: u8 = 0,
    ext_mem_k: u16 = 0,
    orig_video_page: u16 = 0,
    orig_video_mode: u8 = 0,
    orig_video_cols: u8 = 0,
    orig_video_lines: u8 = 0,
    orig_video_ega_bx: u16 = 0,
    orig_video_points: u16 = 0,
    orig_video_is_vga: u16 = 0,
    // APM BIOS
    apm_bios_info_version: u16 = 0,
    apm_bios_info_cseg: u16 = 0,
    apm_bios_info_offset: u32 = 0,
    apm_bios_info_flags: u16 = 0,
    // Setup header
    setup_sects: u8 = 0,
    root_flags: u16 = 0,
    syssize: u32 = 0,
    ram_size: u16 = 0,
    vid_mode: u16 = 0,
    root_dev: u16 = 0,
    boot_flag: u16 = 0,
    header_magic: u32 = 0,
    version: u16 = 0,
    type_of_loader: u8 = 0,
    loadflags: u8 = 0,
    setup_move_size: u16 = 0,
    code32_start: u32 = 0,
    ramdisk_image: u32 = 0,
    ramdisk_size: u32 = 0,
    bootsect_kludge: u32 = 0,
    heap_end_ptr: u16 = 0,
    ext_loader_ver: u8 = 0,
    ext_loader_type: u8 = 0,
    cmd_line_ptr: u32 = 0,
    initrd_addr_max: u32 = 0,
    kernel_alignment: u32 = 0,
    relocatable: u8 = 0,
    min_alignment: u8 = 0,
    xloadflags: u16 = 0,
    cmdline_size: u32 = 0,
    hardware_subarch: u32 = 0,
    hardware_subarch_data: u64 = 0,
    payload_offset: u32 = 0,
    payload_length: u32 = 0,
    setup_data_ptr: u64 = 0,
    pref_address: u64 = 0,
    init_size: u32 = 0,
    handover_offset: u32 = 0,
    kernel_info_offset: u32 = 0,
};

// ============================================================================
// CPU Identification
// ============================================================================

pub const CpuidLeaf = struct {
    eax: u32 = 0,
    ebx: u32 = 0,
    ecx: u32 = 0,
    edx: u32 = 0,
};

pub const CpuVendor = enum(u8) {
    unknown = 0,
    intel = 1,
    amd = 2,
    hygon = 3,
    centaur = 4,
    zhaoxin = 5,
};

pub const CpuFamily = struct {
    vendor: CpuVendor = .unknown,
    family: u16 = 0,
    model: u16 = 0,
    stepping: u8 = 0,
    // Extended
    x86_model_id: [64]u8 = [_]u8{0} ** 64,
    // Cache info
    l1d_cache_size: u32 = 0,    // KB
    l1i_cache_size: u32 = 0,    // KB
    l2_cache_size: u32 = 0,     // KB
    l3_cache_size: u32 = 0,     // KB
    cache_line_size: u32 = 64,
    // Topology
    physical_cores: u32 = 0,
    logical_cores: u32 = 0,
    threads_per_core: u8 = 0,
    cores_per_die: u32 = 0,
    dies_per_package: u8 = 1,
    // Features
    max_cpuid_leaf: u32 = 0,
    max_cpuid_ext_leaf: u32 = 0,
    // Address widths
    phys_bits: u8 = 0,
    virt_bits: u8 = 0,
    // Microcode revision
    microcode_rev: u64 = 0,
};

// ============================================================================
// Microcode Update
// ============================================================================

pub const UcodeResult = enum(u8) {
    ok = 0,
    not_found = 1,
    error = 2,
    nfio = 3,
    updated = 4,
};

pub const IntelUcodeHeader = struct {
    header_version: u32 = 1,
    update_revision: u32 = 0,
    date: u32 = 0,               // BCD MMDDYYYY
    processor_signature: u32 = 0,
    checksum: u32 = 0,
    loader_revision: u32 = 1,
    processor_flags: u32 = 0,
    data_size: u32 = 0,
    total_size: u32 = 0,
};

pub const AmdUcodeHeader = struct {
    data_code: u32 = 0,
    patch_id: u32 = 0,
    mc_patch_data_id: u16 = 0,
    mc_patch_data_len: u16 = 0,
    init_flag: u32 = 0,
    mc_patch_data_checksum: u32 = 0,
    nb_dev_id: u32 = 0,
    sb_dev_id: u32 = 0,
    processor_rev_id: u16 = 0,
    nb_rev_id: u8 = 0,
    sb_rev_id: u8 = 0,
    bios_api_rev: u8 = 0,
};

pub const UcodeState = struct {
    vendor: CpuVendor = .unknown,
    current_revision: u64 = 0,
    new_revision: u64 = 0,
    result: UcodeResult = .not_found,
    date: u32 = 0,
    // Early loading
    early_loaded: bool = false,
    late_loaded: bool = false,
    // Stats
    total_updates: u64 = 0,
    total_failures: u64 = 0,
};

// ============================================================================
// MSR (Model Specific Registers)
// ============================================================================

pub const MsrIndex = enum(u32) {
    // General
    ia32_tsc = 0x10,
    ia32_platform_id = 0x17,
    ia32_apic_base = 0x1B,
    ia32_feature_control = 0x3A,
    ia32_tsc_adjust = 0x3B,
    ia32_spec_ctrl = 0x48,
    ia32_pred_cmd = 0x49,
    // Performance
    ia32_pmc0 = 0xC1,
    ia32_pmc1 = 0xC2,
    ia32_pmc2 = 0xC3,
    ia32_pmc3 = 0xC4,
    ia32_mperf = 0xE7,
    ia32_aperf = 0xE8,
    // MTRR
    ia32_mtrrcap = 0xFE,
    ia32_sysenter_cs = 0x174,
    ia32_sysenter_esp = 0x175,
    ia32_sysenter_eip = 0x176,
    ia32_mcg_cap = 0x179,
    ia32_mcg_status = 0x17A,
    ia32_mcg_ctl = 0x17B,
    // Perfmon
    ia32_perfevtsel0 = 0x186,
    ia32_perfevtsel1 = 0x187,
    ia32_perfevtsel2 = 0x188,
    ia32_perfevtsel3 = 0x189,
    ia32_perf_status = 0x198,
    ia32_perf_ctl = 0x199,
    ia32_clock_modulation = 0x19A,
    ia32_therm_interrupt = 0x19B,
    ia32_therm_status = 0x19C,
    // Misc
    ia32_misc_enable = 0x1A0,
    ia32_package_therm_status = 0x1B1,
    ia32_package_therm_interrupt = 0x1B2,
    ia32_debugctl = 0x1D9,
    ia32_pat = 0x277,
    ia32_perf_capabilities = 0x345,
    ia32_fixed_ctr0 = 0x309,
    ia32_fixed_ctr1 = 0x30A,
    ia32_fixed_ctr2 = 0x30B,
    ia32_perf_global_status = 0x38E,
    ia32_perf_global_ctrl = 0x38F,
    ia32_perf_global_ovf_ctrl = 0x390,
    // MTRR
    ia32_mtrr_def_type = 0x2FF,
    ia32_mtrr_physbase0 = 0x200,
    ia32_mtrr_physmask0 = 0x201,
    // AMD
    amd64_syscfg = 0xC0010010,
    amd64_hwcr = 0xC0010015,
    amd64_nb_cfg = 0xC001001F,
    // Speculation
    ia32_arch_capabilities = 0x10A,
    ia32_flush_cmd = 0x10B,
    ia32_tsx_ctrl = 0x122,
    // LSTAR/SYSCALL
    ia32_star = 0xC0000081,
    ia32_lstar = 0xC0000082,
    ia32_cstar = 0xC0000083,
    ia32_fmask = 0xC0000084,
    ia32_fs_base = 0xC0000100,
    ia32_gs_base = 0xC0000101,
    ia32_kernel_gs_base = 0xC0000102,
    ia32_tsc_aux = 0xC0000103,
    // XSS
    ia32_xss = 0x0DA0,
    // PKRS
    ia32_pkrs = 0x06E1,
    // Turbo
    ia32_energy_perf_bias = 0x1B0,
    ia32_turbo_ratio_limit = 0x1AD,
    // RAPL
    ia32_rapl_power_unit = 0x606,
    ia32_pkg_energy_status = 0x611,
    ia32_dram_energy_status = 0x619,
    ia32_pp0_energy_status = 0x639,
    ia32_pp1_energy_status = 0x641,
};

// ============================================================================
// CPU Power Management
// ============================================================================

pub const CState = enum(u8) {
    c0 = 0,    // Active
    c1 = 1,    // Halt
    c1e = 2,   // Enhanced Halt
    c3 = 3,    // Sleep
    c6 = 6,    // Deep power down
    c7 = 7,    // Package C7
    c8 = 8,    // Package C8
    c9 = 9,    // Package C9
    c10 = 10,  // Package C10
};

pub const PState = struct {
    frequency_mhz: u32 = 0,
    voltage_mv: u32 = 0,
    power_mw: u32 = 0,
    latency_us: u32 = 0,
    // P-state ratio
    fid: u8 = 0,     // Frequency ID
    did: u8 = 0,     // Divisor ID
    vid: u8 = 0,     // Voltage ID
};

pub const CpuFreqGovernor = enum(u8) {
    performance = 0,
    powersave = 1,
    userspace = 2,
    ondemand = 3,
    conservative = 4,
    schedutil = 5,
    // Zxyphor
    zxy_intelligent = 10,
};

pub const CpuFreqPolicy = struct {
    cpu: u32 = 0,
    min_freq_khz: u32 = 0,
    max_freq_khz: u32 = 0,
    cur_freq_khz: u32 = 0,
    governor: CpuFreqGovernor = .schedutil,
    // Driver info
    driver_name: [16]u8 = [_]u8{0} ** 16,
    // Intel HWP / AMD CPPC
    hwp_enabled: bool = false,
    hwp_min: u8 = 0,
    hwp_max: u8 = 0,
    hwp_desired: u8 = 0,
    hwp_epp: u8 = 0,        // Energy Performance Preference
    // Boost
    boost_enabled: bool = false,
    // Stats
    total_transitions: u64 = 0,
    time_in_state_ns: [16]u64 = [_]u64{0} ** 16,
};

pub const CpuIdleDriver = struct {
    name: [16]u8 = [_]u8{0} ** 16,
    nr_states: u8 = 0,
    // States
    state_names: [16][16]u8 = [_][16]u8{[_]u8{0} ** 16} ** 16,
    state_latencies_us: [16]u32 = [_]u32{0} ** 16,
    state_target_residencies_us: [16]u32 = [_]u32{0} ** 16,
    state_power_mw: [16]u32 = [_]u32{0} ** 16,
    // Stats
    state_usage: [16]u64 = [_]u64{0} ** 16,
    state_time_us: [16]u64 = [_]u64{0} ** 16,
    state_above: [16]u64 = [_]u64{0} ** 16,    // Wrong state (too shallow)
    state_below: [16]u64 = [_]u64{0} ** 16,    // Wrong state (too deep)
};

// ============================================================================
// RAPL (Running Average Power Limit)
// ============================================================================

pub const RaplDomain = enum(u8) {
    package = 0,
    cores = 1,     // PP0
    uncore = 2,    // PP1 (GPU)
    dram = 3,
    psys = 4,      // Platform
};

pub const RaplInfo = struct {
    domain: RaplDomain = .package,
    power_unit: u32 = 0,           // Watts = 1 / (1 << power_unit)
    energy_unit: u32 = 0,          // Joules = 1 / (1 << energy_unit)
    time_unit: u32 = 0,
    // Limits
    power_limit_1_mw: u64 = 0,    // Long-term
    time_window_1_us: u64 = 0,
    power_limit_2_mw: u64 = 0,    // Short-term
    time_window_2_us: u64 = 0,
    // Energy
    energy_counter: u64 = 0,
    max_energy_range: u64 = 0,
    // Thermal
    tdp_mw: u64 = 0,
    min_power_mw: u64 = 0,
    max_power_mw: u64 = 0,
    max_time_window_us: u64 = 0,
};

// ============================================================================
// CPU Topology
// ============================================================================

pub const CpuTopology = struct {
    nr_cpus: u32 = 0,
    nr_online: u32 = 0,
    nr_sockets: u32 = 0,
    nr_dies: u32 = 0,
    nr_clusters: u32 = 0,
    nr_cores: u32 = 0,
    // Per-CPU topology
    apic_ids: [256]u32 = [_]u32{0} ** 256,
    package_ids: [256]u32 = [_]u32{0} ** 256,
    die_ids: [256]u32 = [_]u32{0} ** 256,
    core_ids: [256]u32 = [_]u32{0} ** 256,
    thread_ids: [256]u8 = [_]u8{0} ** 256,
    // Siblings
    core_siblings: [256]u64 = [_]u64{0} ** 256,
    thread_siblings: [256]u64 = [_]u64{0} ** 256,
    die_siblings: [256]u64 = [_]u64{0} ** 256,
    // Hybrid architecture (Intel)
    is_hybrid: bool = false,
    nr_perf_cores: u32 = 0,
    nr_eff_cores: u32 = 0,
    perf_core_mask: u64 = 0,
    eff_core_mask: u64 = 0,
};

// ============================================================================
// Speculative Execution Mitigations
// ============================================================================

pub const MitigationStatus = enum(u8) {
    not_affected = 0,
    vulnerable = 1,
    mitigated = 2,
    unknown = 3,
};

pub const X86Mitigations = struct {
    // Spectre
    spectre_v1: MitigationStatus = .unknown,
    spectre_v2: MitigationStatus = .unknown,
    spectre_v2_user: MitigationStatus = .unknown,
    // Meltdown
    meltdown: MitigationStatus = .unknown,
    // L1TF
    l1tf: MitigationStatus = .unknown,
    // MDS
    mds: MitigationStatus = .unknown,
    // TAA
    tsx_async_abort: MitigationStatus = .unknown,
    // MMIO
    mmio_stale_data: MitigationStatus = .unknown,
    // Retbleed
    retbleed: MitigationStatus = .unknown,
    // SRSO
    srso: MitigationStatus = .unknown,
    // GDS
    gather_data_sampling: MitigationStatus = .unknown,
    // RFDS
    reg_file_data_sampling: MitigationStatus = .unknown,
    // BHI
    branch_history_injection: MitigationStatus = .unknown,
    // IBPB
    ibpb_enabled: bool = false,
    ibrs_enabled: bool = false,
    stibp_enabled: bool = false,
    ssbd_enabled: bool = false,
    // KPTI
    kpti_enabled: bool = false,
    // Retpoline
    retpoline_enabled: bool = false,
    // RSB filling
    rsb_filling: bool = false,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const X86BootSubsystem = struct {
    // Boot
    boot_stage: EarlyBootStage = .bios_handoff,
    // CPU
    cpu_info: CpuFamily = .{},
    topology: CpuTopology = .{},
    // Microcode
    ucode: UcodeState = .{},
    // Power
    nr_cpufreq_policies: u32 = 0,
    // RAPL
    nr_rapl_domains: u8 = 0,
    // Mitigations
    mitigations: X86Mitigations = .{},
    // Zxyphor
    zxy_secure_boot_verified: bool = false,
    initialized: bool = false,
};
