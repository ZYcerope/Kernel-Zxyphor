// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Clock Framework & DVFS Detail
// Complete Common Clock Framework (CCF), clock tree, PLL configs,
// DVFS, cpufreq governors, OPP (Operating Performance Points),
// clock gating, power domains

const std = @import("std");

// ============================================================================
// Clock Types
// ============================================================================

pub const ClkType = enum(u8) {
    Fixed = 0,
    Gate = 1,
    Divider = 2,
    Mux = 3,
    FixedFactor = 4,
    Composite = 5,
    Pll = 6,
    FractionalDivider = 7,
    GpioGate = 8,
    GpioMux = 9,
};

pub const ClkFlags = packed struct(u64) {
    set_rate_gate: bool,
    set_parent_gate: bool,
    set_rate_parent: bool,
    ignore_unused: bool,
    get_rate_nocache: bool,
    set_rate_no_reparent: bool,
    get_accuracy_nocache: bool,
    recalc_new_rates: bool,
    set_rate_ungate: bool,
    is_critical: bool,
    opp_table_valid: bool,
    set_rate_parent_in_order: bool,
    duty_cycle_parent: bool,
    _reserved: u51,
};

// ============================================================================
// Clock Hardware Definition
// ============================================================================

pub const ClkHw = struct {
    core: ?*ClkCore,
    clk: ?*Clk,
    init: ?*const ClkInitData,
};

pub const ClkInitData = struct {
    name: [64]u8,
    ops: ?*const ClkOps,
    parent_names: [8][64]u8,
    parent_data: [8]ClkParentData,
    num_parents: u8,
    flags: ClkFlags,
};

pub const ClkParentData = struct {
    hw: ?*ClkHw,
    fw_name: [64]u8,
    name: [64]u8,
    index: i32,
};

pub const ClkOps = struct {
    prepare: ?*const fn (*ClkHw) i32,
    unprepare: ?*const fn (*ClkHw) void,
    is_prepared: ?*const fn (*ClkHw) bool,
    enable: ?*const fn (*ClkHw) i32,
    disable: ?*const fn (*ClkHw) void,
    is_enabled: ?*const fn (*ClkHw) bool,
    recalc_rate: ?*const fn (*ClkHw, u64) u64,
    round_rate: ?*const fn (*ClkHw, u64, *u64) i64,
    determine_rate: ?*const fn (*ClkHw, *ClkRateRequest) i32,
    set_parent: ?*const fn (*ClkHw, u8) i32,
    get_parent: ?*const fn (*ClkHw) u8,
    set_rate: ?*const fn (*ClkHw, u64, u64) i32,
    set_rate_and_parent: ?*const fn (*ClkHw, u64, u64, u8) i32,
    recalc_accuracy: ?*const fn (*ClkHw, u64) u64,
    get_phase: ?*const fn (*ClkHw) i32,
    set_phase: ?*const fn (*ClkHw, i32) i32,
    get_duty_cycle: ?*const fn (*ClkHw, *ClkDuty) i32,
    set_duty_cycle: ?*const fn (*ClkHw, *ClkDuty) i32,
    init_hw: ?*const fn (*ClkHw) i32,
    terminate: ?*const fn (*ClkHw) void,
    debug_init: ?*const fn (*ClkHw) void,
};

pub const ClkRateRequest = struct {
    rate: u64,
    min_rate: u64,
    max_rate: u64,
    best_parent_rate: u64,
    best_parent_hw: ?*ClkHw,
};

pub const ClkDuty = struct {
    num: u32,
    den: u32,
};

// ============================================================================
// Clock Core Internal State
// ============================================================================

pub const ClkCore = struct {
    name: [64]u8,
    ops: ?*const ClkOps,
    hw: ?*ClkHw,
    parent: ?*ClkCore,
    parent_names: [8][64]u8,
    parents: [8]?*ClkCore,
    num_parents: u8,
    new_parent: ?*ClkCore,
    new_parent_index: u8,
    rate: u64,
    new_rate: u64,
    new_child: ?*ClkCore,
    flags: ClkFlags,
    enable_count: u32,
    prepare_count: u32,
    protect_count: u32,
    min_rate: u64,
    max_rate: u64,
    accuracy: u64,
    phase: i32,
    duty: ClkDuty,
    new_duty: ClkDuty,
    orphan: bool,
    notifier_count: u32,
};

pub const Clk = struct {
    core: ?*ClkCore,
    dev_id: [64]u8,
    con_id: [64]u8,
    min_rate: u64,
    max_rate: u64,
    exclusive_count: u32,
};

// ============================================================================
// PLL Configuration
// ============================================================================

pub const PllType = enum(u8) {
    Integer = 0,
    Fractional = 1,
    SpreadSpectrum = 2,
    SigmaDelta = 3,
};

pub const PllParams = struct {
    pll_type: PllType,
    ref_rate: u64,         // Reference clock rate
    vco_min: u64,
    vco_max: u64,
    pfd_min: u64,          // Phase-freq detector min
    pfd_max: u64,
    m_min: u16,            // Feedback divider range
    m_max: u16,
    n_min: u16,            // Pre-divider range
    n_max: u16,
    p_min: u8,             // Post-divider range
    p_max: u8,
    frac_bits: u8,         // Fractional bits
    lock_delay_us: u32,
    lock_timeout_us: u32,
    ss_rate: u32,          // Spread spectrum rate
    ss_amplitude: u16,     // Spread spectrum amplitude
};

pub const PllRateTable = struct {
    rate: u64,
    m: u16,
    n: u16,
    p: u8,
    k: u16,               // Integer or fractional
    s: u8,                 // Secondary divider
};

// ============================================================================
// Clock Gating
// ============================================================================

pub const ClkGateFlags = packed struct(u32) {
    set_to_disable: bool,
    hiword_mask: bool,
    big_endian: bool,
    _reserved: u29,
};

pub const ClkGate = struct {
    hw: ClkHw,
    reg: usize,            // MMIO register address
    bit_idx: u8,
    flags: ClkGateFlags,
    lock: usize,           // Spinlock
};

pub const ClkDivider = struct {
    hw: ClkHw,
    reg: usize,
    shift: u8,
    width: u8,
    flags: u32,
    table: [32]ClkDivTable,
    lock: usize,
};

pub const ClkDivTable = struct {
    val: u32,
    div: u32,
};

pub const ClkMux = struct {
    hw: ClkHw,
    reg: usize,
    table: [16]u32,
    mask: u32,
    shift: u8,
    flags: u32,
    lock: usize,
};

// ============================================================================
// CPUFreq Subsystem
// ============================================================================

pub const CpufreqGovernor = enum(u8) {
    Performance = 0,
    Powersave = 1,
    Userspace = 2,
    Ondemand = 3,
    Conservative = 4,
    Schedutil = 5,
};

pub const CpufreqDriverFlags = packed struct(u32) {
    need_update: bool,
    async_notification: bool,
    need_name_check: bool,
    need_initial_freq_check: bool,
    is_cooling_dev: bool,
    have_governor_per_policy: bool,
    _reserved: u26,
};

pub const CpufreqDriver = struct {
    name: [16]u8,
    flags: CpufreqDriverFlags,
    init: ?*const fn (*CpufreqPolicy) i32,
    verify: ?*const fn (*CpufreqPolicyData) i32,
    setpolicy: ?*const fn (*CpufreqPolicy) i32,
    target: ?*const fn (*CpufreqPolicy, u32, u32) i32,
    target_index: ?*const fn (*CpufreqPolicy, u32) i32,
    fast_switch: ?*const fn (*CpufreqPolicy, u32) u32,
    adjust_perf: ?*const fn (u32, u64, u64, u64) void,
    get: ?*const fn (u32) u32,
    update_limits: ?*const fn (u32) void,
    bios_limit: ?*const fn (u32, *u32) i32,
    online: ?*const fn (*CpufreqPolicy) i32,
    offline: ?*const fn (*CpufreqPolicy) i32,
    exit: ?*const fn (*CpufreqPolicy) i32,
    suspend: ?*const fn (*CpufreqPolicy) i32,
    resume: ?*const fn (*CpufreqPolicy) i32,
    ready: ?*const fn (*CpufreqPolicy) void,
    set_boost: ?*const fn (*CpufreqPolicy, i32) i32,
    register_em: ?*const fn (*CpufreqPolicy) void,
};

pub const CpufreqPolicy = struct {
    cpu: u32,              // Managed CPU
    cpus: u64,             // CPU mask (packed)
    related_cpus: u64,
    real_cpus: u64,
    shared_type: u32,
    cur: u32,              // Current frequency (kHz)
    min: u32,
    max: u32,
    cpuinfo_min: u32,      // Hardware limits
    cpuinfo_max: u32,
    cpuinfo_transition_latency: u32,
    last_governor: CpufreqGovernor,
    governor: CpufreqGovernor,
    governor_data: usize,
    stats: CpufreqStats,
    fast_switch_possible: bool,
    fast_switch_enabled: bool,
    strict_target: bool,
    efficiencies_available: bool,
    transition_ongoing: bool,
    boost_enabled: bool,
    freq_table: [64]CpufreqFreqEntry,
    freq_table_len: u32,
};

pub const CpufreqPolicyData = struct {
    min: u32,
    max: u32,
};

pub const CpufreqFreqEntry = struct {
    driver_data: u32,
    frequency: u32,        // kHz
    flags: u32,
};

pub const CpufreqStats = struct {
    total_trans: u64,
    last_time: u64,
    max_state: u32,
    state_num: u32,
    time_in_state: [64]u64,
    freq_table: [64]u32,
    trans_table: [64][64]u32,
};

// ============================================================================
// Operating Performance Points (OPP)
// ============================================================================

pub const DevOpp = struct {
    rate: u64,             // Frequency (Hz)
    u_volt: u32,           // Supply voltage (uV)
    u_volt_min: u32,
    u_volt_max: u32,
    u_amp: u32,            // Current draw (uA)
    clock_latency_ns: u64,
    level: u32,
    turbo: bool,
    suspend: bool,
    available: bool,
    dynamic: bool,
    supplies: [4]OppSupply,
    num_supplies: u8,
    required_opps: [4]?*DevOpp,
    num_required: u8,
    bandwidth: [4]OppBandwidth,
    num_bw: u8,
};

pub const OppSupply = struct {
    u_volt: u32,
    u_volt_min: u32,
    u_volt_max: u32,
    u_amp: u32,
};

pub const OppBandwidth = struct {
    avg: u32,              // Average bandwidth (kBps)
    peak: u32,             // Peak bandwidth (kBps)
};

pub const OppTable = struct {
    num_opps: u32,
    opps: [64]DevOpp,
    supported_hw: [8]u32,
    supported_hw_count: u8,
    prop_name: [64]u8,
    shared_opp: u32,
    parsed_static_opps: u32,
    clk_count: u8,
    regulator_count: u8,
    path_count: u8,
    genpd_virt_devs: [8]usize,
    is_genpd: bool,
    suspend_opp: ?*DevOpp,
};

// ============================================================================
// Power Domains (genpd)
// ============================================================================

pub const GenpdState = enum(u8) {
    On = 0,
    Off = 1,
};

pub const GenPowerDomain = struct {
    name: [64]u8,
    state: GenpdState,
    device_count: u32,
    sd_count: u32,           // Subdomain count
    performance_state: u32,
    suspended_count: u32,
    prepared_count: u32,
    max_off_time_ns: i64,
    power_on_latency_ns: u64,
    power_off_latency_ns: u64,
    flags: GenpdFlags,
    states: [8]GenpdPowerState,
    state_count: u32,
    free_states: bool,
    gov: ?*GenpdGovernor,
    accounting_time: u64,
    // Callbacks
    power_off: ?*const fn (*GenPowerDomain) i32,
    power_on: ?*const fn (*GenPowerDomain) i32,
    set_performance_state: ?*const fn (*GenPowerDomain, u32) i32,
    attach_dev: ?*const fn (*GenPowerDomain, usize) i32,
    detach_dev: ?*const fn (*GenPowerDomain, usize) void,
};

pub const GenpdFlags = packed struct(u32) {
    active_wakeup: bool,
    cpu_domain: bool,
    rpg_as_perf: bool,
    opp_table_fw: bool,
    dev_idle_states: bool,
    always_on: bool,
    min_residency: bool,
    _reserved: u25,
};

pub const GenpdPowerState = struct {
    name: [32]u8,
    power_off_latency_ns: u64,
    power_on_latency_ns: u64,
    residency_ns: u64,
    usage: u64,
    rejected: u64,
    idle_time_s: u64,
};

pub const GenpdGovernor = struct {
    name: [32]u8,
    power_down_ok: ?*const fn (*GenPowerDomain) bool,
    save_state: ?*const fn (*GenPowerDomain) bool,
};

// ============================================================================
// DVFS Thermal Coupling
// ============================================================================

pub const ThermalCoolingDevice = struct {
    name: [32]u8,
    dev_type: [32]u8,
    max_state: u32,
    cur_state: u32,
    ops: ThermalCoolingOps,
};

pub const ThermalCoolingOps = struct {
    get_max_state: ?*const fn (*ThermalCoolingDevice, *u32) i32,
    get_cur_state: ?*const fn (*ThermalCoolingDevice, *u32) i32,
    set_cur_state: ?*const fn (*ThermalCoolingDevice, u32) i32,
    get_requested_power: ?*const fn (*ThermalCoolingDevice, *u32) i32,
    state2power: ?*const fn (*ThermalCoolingDevice, u32, *u32) i32,
    power2state: ?*const fn (*ThermalCoolingDevice, u32, *u32) i32,
};

// ============================================================================
// Manager
// ============================================================================

pub const ClockDvfsManager = struct {
    total_clocks: u32,
    total_plls: u32,
    total_gates: u32,
    total_dividers: u32,
    total_muxes: u32,
    total_opps: u32,
    total_cpufreq_policies: u32,
    total_power_domains: u32,
    total_freq_transitions: u64,
    current_governor: CpufreqGovernor,
    boost_enabled: bool,
    initialized: bool,

    pub fn init() ClockDvfsManager {
        return .{
            .total_clocks = 0,
            .total_plls = 0,
            .total_gates = 0,
            .total_dividers = 0,
            .total_muxes = 0,
            .total_opps = 0,
            .total_cpufreq_policies = 0,
            .total_power_domains = 0,
            .total_freq_transitions = 0,
            .current_governor = .Schedutil,
            .boost_enabled = false,
            .initialized = true,
        };
    }
};
