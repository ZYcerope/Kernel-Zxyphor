// SPDX-License-Identifier: MIT
// Zxyphor Kernel - EDAC (Error Detection and Correction), devfreq,
// Device Frequency Scaling, Memory Controller, ECC, Chipkill
// More advanced than Linux 2026 RAS subsystem

const std = @import("std");

// ============================================================================
// EDAC - Error Detection And Correction
// ============================================================================

/// EDAC error type
pub const EdacErrorType = enum(u8) {
    correctable = 0, // CE
    uncorrectable = 1, // UE
    fatal = 2, // Fatal
    deferred = 3, // Deferred
    // Zxyphor
    predicted = 10, // Predictive failure (Zxyphor AI)
};

/// EDAC grain type - error granularity
pub const EdacGrain = enum(u8) {
    unknown = 0,
    cache_line = 1,
    page = 2,
    memory_controller = 3,
    channel = 4,
    dimm = 5,
    rank = 6,
    bank = 7,
    row = 8,
    // Zxyphor
    sub_row = 10,
};

/// Memory controller type
pub const McType = enum(u8) {
    empty = 0,
    reserved = 1,
    unknown = 2,
    sdr = 3,
    rdr = 4,
    ddr = 5,
    ddr2 = 6,
    ddr3 = 7,
    ddr4 = 8,
    ddr5 = 9,
    lpddr2 = 10,
    lpddr3 = 11,
    lpddr4 = 12,
    lpddr5 = 13,
    lpddr5x = 14,
    hbm = 15,
    hbm2 = 16,
    hbm2e = 17,
    hbm3 = 18,
    hbm3e = 19,
    gddr5 = 20,
    gddr5x = 21,
    gddr6 = 22,
    gddr6x = 23,
    gddr7 = 24,
    // Zxyphor
    zxy_mram = 30,
    zxy_reram = 31,
    zxy_pcm = 32,
};

/// DIMM location
pub const DimmLocation = struct {
    mc_idx: u8,
    channel: u8,
    dimm: u8,
    rank: u8,
    bank: u8,
    row: u32,
    col: u16,
    // Physical mapping
    socket: u8,
    imc: u8,
    channel_addr: u64,
};

/// DIMM info
pub const DimmInfo = struct {
    label: [64]u8,
    location: DimmLocation,
    mem_type: McType,
    edac_mode: EdacMode,
    // Size
    nr_pages: u64,
    grain: u32, // error granularity in bytes
    // ECC
    dtype: DeviceType,
    // Counts
    ce_count: u64,
    ue_count: u64,
    ce_noinfo_count: u64,
    ue_noinfo_count: u64,
    // Manufacturing
    mfg_id: u16,
    serial: u32,
    part_number: [20]u8,
    revision: u8,
    // Temperature
    current_temp_c: i16,
    max_temp_c: i16,
    temp_threshold_c: i16,
    // Zxyphor predictive
    predicted_failure_hours: u32,
    health_score: u8, // 0-100
};

/// EDAC mode
pub const EdacMode = enum(u8) {
    none = 0,
    ec = 1, // Error Check
    secded = 2, // SEC-DED
    s2ecd2ed = 3, // Double-bit ECC with double detection
    s4ecd4ed = 4, // Quad
    s8ecd8ed = 5,
    s16ecd16ed = 6,
    chipkill = 7,
    advanced_ecc = 8,
    // Zxyphor
    zxy_ml_ecc = 20, // ML-enhanced ECC
};

/// Device type (data width)
pub const DeviceType = enum(u8) {
    x1 = 0,
    x2 = 1,
    x4 = 2,
    x8 = 3,
    x16 = 4,
    x32 = 5,
    x64 = 6,
    unknown = 255,
};

/// Memory controller instance
pub const McInstance = struct {
    mc_idx: u32,
    mc_type: McType,
    edac_mode: EdacMode,
    // Layers
    nr_csrows: u32,
    nr_channels: u32,
    nr_dimms: u32,
    // Error counts
    ce_count: u64,
    ue_count: u64,
    ce_per_layer: [3]u64,
    ue_per_layer: [3]u64,
    // Features
    scrub_mode: ScrubType,
    scrub_cap: u32,
    // Addresses
    ctl_page_to_phys: ?u64,
    // Status
    op_state: OpState,
    // Zxyphor
    predictive_failure_enabled: bool,
    ml_model_version: u32,
    last_scrub_timestamp: u64,
    scrub_interval_ms: u32,
};

/// Scrub type
pub const ScrubType = enum(u8) {
    none = 0,
    sw_prog = 1,
    sw_src = 2,
    sw_prog_src = 3,
    hw_prog = 4,
    hw_src = 5,
    hw_prog_src = 6,
    hw_auto = 7,
    // Zxyphor
    zxy_adaptive = 20,
};

/// Operation state
pub const OpState = enum(u8) {
    unknown = 0,
    online = 1,
    offline = 2,
    offline_repair = 3,
};

/// EDAC error record
pub const EdacErrorRecord = struct {
    timestamp_ns: u64,
    error_type: EdacErrorType,
    mc_idx: u32,
    location: DimmLocation,
    // Syndrome
    syndrome: u64,
    // Physical address (if available)
    phys_addr: u64,
    page_frame_number: u64,
    offset_in_page: u32,
    // Error info
    error_count: u32,
    msg: [128]u8,
    // CPER (Common Platform Error Record)
    cper_section_type: u128,
    cper_severity: u8,
};

/// PCI device error (EDAC PCI)
pub const EdacPciError = struct {
    bus: u8,
    device: u5,
    function: u3,
    error_type: PciEdacErrorType,
    status: u32,
    timestamp_ns: u64,
};

/// PCI EDAC error type
pub const PciEdacErrorType = enum(u8) {
    parity = 0,
    system_error = 1,
    master_abort = 2,
    target_abort = 3,
    multiple_parity = 4,
    // PCIe
    correctable = 10,
    non_fatal = 11,
    fatal = 12,
};

// ============================================================================
// DevFreq - Device Frequency Scaling
// ============================================================================

/// DevFreq governor type
pub const DevfreqGovernor = enum(u8) {
    simple_ondemand = 0,
    performance = 1,
    powersave = 2,
    userspace = 3,
    passive = 4,
    // Zxyphor
    zxy_adaptive = 10, // ML-based
    zxy_latency_aware = 11,
    zxy_thermal_aware = 12,
};

/// DevFreq OPP (Operating Performance Point)
pub const DevfreqOpp = struct {
    freq_hz: u64,
    voltage_uv: u32,
    power_uw: u32, // estimated power
    is_turbo: bool,
    is_suspend: bool,
    // Latency
    transition_latency_ns: u32,
    // Thermal
    max_temp_c: i16,
};

/// DevFreq device profile
pub const DevfreqProfile = struct {
    // Frequency
    initial_freq: u64,
    polling_ms: u32,
    // OPP count
    nr_opp: u32,
    min_freq: u64,
    max_freq: u64,
    // Load
    busy_time: u64,
    total_time: u64,
    // Stats
    total_transitions: u64,
    time_in_state: [32]u64, // per OPP
    // Governor
    governor: DevfreqGovernor,
    // Thresholds
    upthreshold: u8,
    downdifferential: u8,
};

/// DevFreq event
pub const DevfreqEvent = struct {
    timestamp_ns: u64,
    load_count: u64,
    total_count: u64,
    // Performance counters
    gpu_busy: u64,
    gpu_total: u64,
    bus_busy: u64,
    bus_total: u64,
};

/// DevFreq cooling integration
pub const DevfreqCooling = struct {
    id: u32,
    max_state: u32,
    cur_state: u32,
    // Power model
    dynamic_power_mw: u32,
    static_power_mw: u32,
    // Frequency cap
    freq_cap_hz: u64,
};

// ============================================================================
// GPU Frequency Scaling
// ============================================================================

/// GPU frequency domain
pub const GpuFreqDomain = enum(u8) {
    core = 0,
    shader = 1,
    memory = 2,
    video = 3,
    display = 4,
    // Zxyphor
    tensor = 10,
    raytracing = 11,
};

/// GPU power state
pub const GpuPowerState = enum(u8) {
    d0_active = 0,
    d0i1_screen_off = 1,
    d0i2_render_standby = 2,
    d0i3_rc6 = 3,
    d1_light_sleep = 4,
    d2_deep_sleep = 5,
    d3_hot = 6,
    d3_cold = 7,
};

/// GPU frequency table
pub const GpuFreqTable = struct {
    domain: GpuFreqDomain,
    nr_levels: u32,
    min_freq_mhz: u32,
    max_freq_mhz: u32,
    base_freq_mhz: u32, // guaranteed frequency
    boost_freq_mhz: u32,
    // Current
    cur_freq_mhz: u32,
    req_freq_mhz: u32, // requested
    act_freq_mhz: u32, // actual (may differ from req)
    // Voltage
    cur_voltage_mv: u32,
    // Temperature
    temp_c: i16,
    throttle_reason: GpuThrottleReason,
    // Stats
    total_transitions: u64,
    time_active_us: u64,
    time_idle_us: u64,
};

/// GPU throttle reason
pub const GpuThrottleReason = packed struct {
    thermal: bool = false,
    power: bool = false,
    current: bool = false,
    voltage: bool = false,
    utilization: bool = false,
    vr_thermal: bool = false,
    prochot: bool = false,
    pl1_tdp: bool = false,
    pl2_turbo: bool = false,
    pl4_burst: bool = false,
    reliability: bool = false,
    // Zxyphor
    zxy_predictive: bool = false,
    _padding: u4 = 0,
};

// ============================================================================
// OPP (Operating Performance Points) Framework
// ============================================================================

/// OPP supply voltage
pub const OppSupply = struct {
    u_volt: u64,
    u_volt_min: u64,
    u_volt_max: u64,
    u_amp: u64,
    u_watt: u64,
};

/// OPP table entry
pub const OppEntry = struct {
    rate: u64, // Hz
    level: u32,
    supplies: [4]OppSupply, // up to 4 supplies
    nr_supplies: u8,
    // Bandwidth
    peak_bw: u64, // bytes/sec
    avg_bw: u64,
    // Properties
    turbo: bool,
    suspend: bool,
    // Performance
    performance_weight: u32,
    // Latency
    clock_latency_ns: u64,
    voltage_latency_ns: u64,
};

/// OPP table
pub const OppTable = struct {
    nr_opp: u32,
    // Status
    shared: bool,
    enabled: bool,
    // Supply names
    nr_supplies: u8,
    // Bandwidth
    has_bandwidth: bool,
    // Genpd performance state
    is_genpd: bool,
    // Current
    cur_opp_idx: u32,
    // Stats
    total_transitions: u64,
};

// ============================================================================
// Interconnect Framework
// ============================================================================

/// Interconnect node
pub const IccNode = struct {
    id: u32,
    name: [64]u8,
    // Bandwidth
    peak_bw: u64, // bytes/sec
    avg_bw: u64,
    // Aggregated
    agg_peak_bw: u64,
    agg_avg_bw: u64,
    // Links
    nr_links: u32,
    // Bus width
    buswidth: u16,
    // Provider
    provider_id: u32,
};

/// Interconnect path
pub const IccPath = struct {
    src_id: u32,
    dst_id: u32,
    // Requested
    peak_bw: u64,
    avg_bw: u64,
    // Tag
    tag: u32,
    // Status
    enabled: bool,
};

/// Interconnect provider
pub const IccProvider = struct {
    id: u32,
    name: [64]u8,
    nr_nodes: u32,
    // Features
    has_tag: bool,
    // Stats
    total_set_bw: u64,
    total_aggregate: u64,
};

// ============================================================================
// Power Domain (Generic PM Domain)
// ============================================================================

/// Power domain state
pub const GenpdState = enum(u8) {
    active = 0,
    retention = 1,
    power_off = 2,
    deep_power_off = 3,
};

/// Generic PM Domain
pub const GenericPmDomain = struct {
    name: [64]u8,
    // State
    state: GenpdState,
    // Performance
    performance_state: u32,
    nr_perf_states: u32,
    // Timing
    power_on_latency_ns: u64,
    power_off_latency_ns: u64,
    resume_latency_ns: u64,
    // Sub-domains
    nr_subdomains: u32,
    // Devices
    nr_devices: u32,
    // Flags
    always_on: bool,
    active_wakeup: bool,
    rpm_always_on: bool,
    // Governor
    gov_type: GenpdGovType,
    // Stats
    on_time_ns: u64,
    off_time_ns: u64,
    total_transitions: u64,
    // Zxyphor
    zxy_auto_power_gate: bool,
    zxy_predict_next_wake_ns: u64,
};

/// Genpd governor type
pub const GenpdGovType = enum(u8) {
    simple_qos = 0,
    always_on = 1,
    power_down_ok = 2,
    cpu_pm = 3,
    // Zxyphor
    zxy_smart = 10,
};

// ============================================================================
// APEI (ACPI Platform Error Interface)
// ============================================================================

/// APEI error source type
pub const ApeiErrorSource = enum(u8) {
    ghes = 0, // Generic Hardware Error Source
    ghes_v2 = 1,
    erst = 2, // Error Record Serialization Table
    bert = 3, // Boot Error Record Table
    einj = 4, // Error Injection
    hest = 5, // Hardware Error Source Table
    sdei = 6, // Software Delegated Exception Interface
};

/// GHES (Generic Hardware Error Source)
pub const GhesInstance = struct {
    source_id: u32,
    error_source: ApeiErrorSource,
    // Notification
    notify_type: GhesNotifyType,
    // Error block
    error_block_address: u64,
    error_block_length: u32,
    // Records
    max_raw_data_length: u32,
    // Flags
    enabled: bool,
    firmware_first: bool,
    global: bool,
    // Stats
    total_errors: u64,
    corrected_errors: u64,
    uncorrected_errors: u64,
    fatal_errors: u64,
};

/// GHES notification type
pub const GhesNotifyType = enum(u8) {
    polled = 0,
    external_interrupt = 1,
    local_interrupt = 2,
    sci = 3,
    nmi = 4,
    cmci = 5,
    mce = 6,
    gpio = 7,
    sea = 8, // Synchronous External Abort (ARM)
    sei = 9, // SError Interrupt (ARM)
    gsiv = 10,
    software_delegated = 11,
};

/// CPER (Common Platform Error Record) section type
pub const CperSectionType = enum(u8) {
    processor_generic = 0,
    processor_x86 = 1,
    processor_arm = 2,
    memory = 3,
    memory2 = 4,
    pcie = 5,
    firmware = 6,
    pci_bus = 7,
    pci_device = 8,
    generic_dmar = 9,
    directed_io_dmar = 10,
    // CXL
    cxl_protocol = 20,
    cxl_component = 21,
    // Zxyphor
    zxy_predictive = 50,
};

/// Error injection capability
pub const EinjCapability = packed struct {
    processor_correctable: bool = false,
    processor_uncorrectable: bool = false,
    processor_fatal: bool = false,
    memory_correctable: bool = false,
    memory_uncorrectable: bool = false,
    memory_fatal: bool = false,
    pcie_correctable: bool = false,
    pcie_uncorrectable: bool = false,
    pcie_fatal: bool = false,
    platform_correctable: bool = false,
    platform_uncorrectable: bool = false,
    platform_fatal: bool = false,
    _padding: u4 = 0,
};

// ============================================================================
// CXL Memory RAS
// ============================================================================

/// CXL device type
pub const CxlDeviceType = enum(u8) {
    type1 = 1, // CXL.io + CXL.cache
    type2 = 2, // CXL.io + CXL.cache + CXL.mem
    type3 = 3, // CXL.io + CXL.mem
    switch_port = 4,
    root_port = 5,
    // CXL 3.1
    type3_mhd = 10, // Multi-Headed Device
    // Zxyphor
    zxy_fabric = 50,
};

/// CXL memory region
pub const CxlMemRegion = struct {
    id: u32,
    cxl_type: CxlDeviceType,
    // Range
    base_hpa: u64, // Host Physical Address
    size: u64,
    // Interleave
    interleave_ways: u8,
    interleave_granularity: u32,
    // NUMA
    numa_node: i32,
    // QoS
    bandwidth_mbps: u32,
    latency_ns: u32,
    // Volatile / Persistent
    is_volatile: bool,
    is_persistent: bool,
    // Status
    online: bool,
    // Stats
    ce_count: u64,
    ue_count: u64,
    total_reads: u64,
    total_writes: u64,
    temperature_c: i16,
    // Health
    media_status: CxlMediaStatus,
    life_used_percent: u8,
    dirty_shutdown_count: u32,
};

/// CXL media status
pub const CxlMediaStatus = enum(u8) {
    normal = 0,
    not_ready = 1,
    write_persistency_lost = 2,
    all_data_lost = 3,
    write_persistency_loss_imminent = 4,
    write_persistency_loss_imminent_cold_storage = 5,
    data_loss_imminent = 6,
    // Zxyphor
    zxy_degraded_performance = 50,
};

// ============================================================================
// Device DVFS (Dynamic Voltage and Frequency Scaling) Engine
// ============================================================================

/// DVFS domain
pub const DvfsDomain = struct {
    id: u32,
    name: [64]u8,
    // Clock
    cur_freq_hz: u64,
    min_freq_hz: u64,
    max_freq_hz: u64,
    // Voltage
    cur_voltage_uv: u32,
    min_voltage_uv: u32,
    max_voltage_uv: u32,
    // Performance
    cur_perf_level: u32,
    max_perf_level: u32,
    // Utilization
    utilization_pct: u8,
    // Transition
    transition_latency_ns: u64,
    total_transitions: u64,
    // Target
    target_freq_hz: u64,
    // PLL
    pll_locked: bool,
    pll_lock_time_us: u32,
};

/// DVFS policy
pub const DvfsPolicy = struct {
    min_freq_hz: u64,
    max_freq_hz: u64,
    governor: DevfreqGovernor,
    // QoS
    latency_tolerance_ns: u64,
    // Constraints
    power_budget_mw: u32,
    thermal_limit_c: i16,
    // Boost
    boost_enabled: bool,
    boost_timeout_ms: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// EDAC and DevFreq subsystem
pub const EdacDevfreqSubsystem = struct {
    // EDAC
    nr_mc: u32,
    total_ce: u64,
    total_ue: u64,
    total_fatal: u64,
    total_deferred: u64,
    panic_on_ue: bool,
    log_ce: bool,
    log_ue: bool,
    poll_msec: u32,
    // PCI EDAC
    pci_parity_count: u64,
    pci_serr_count: u64,
    // APEI
    nr_ghes: u32,
    ghes_total_errors: u64,
    // Error injection
    einj_available: bool,
    einj_count: u64,
    // CXL RAS
    nr_cxl_regions: u32,
    cxl_total_ce: u64,
    cxl_total_ue: u64,
    // DevFreq
    nr_devfreq: u32,
    total_devfreq_transitions: u64,
    // Interconnect
    nr_icc_providers: u32,
    nr_icc_nodes: u32,
    // Power domains
    nr_genpd: u32,
    // DVFS
    nr_dvfs_domains: u32,
    // Zxyphor
    zxy_predictive_ras: bool,
    zxy_ml_error_prediction: bool,
    zxy_auto_page_offline: bool,
    initialized: bool,

    pub fn init() EdacDevfreqSubsystem {
        return EdacDevfreqSubsystem{
            .nr_mc = 0,
            .total_ce = 0,
            .total_ue = 0,
            .total_fatal = 0,
            .total_deferred = 0,
            .panic_on_ue = false,
            .log_ce = true,
            .log_ue = true,
            .poll_msec = 1000,
            .pci_parity_count = 0,
            .pci_serr_count = 0,
            .nr_ghes = 0,
            .ghes_total_errors = 0,
            .einj_available = false,
            .einj_count = 0,
            .nr_cxl_regions = 0,
            .cxl_total_ce = 0,
            .cxl_total_ue = 0,
            .nr_devfreq = 0,
            .total_devfreq_transitions = 0,
            .nr_icc_providers = 0,
            .nr_icc_nodes = 0,
            .nr_genpd = 0,
            .nr_dvfs_domains = 0,
            .zxy_predictive_ras = true,
            .zxy_ml_error_prediction = true,
            .zxy_auto_page_offline = true,
            .initialized = false,
        };
    }
};
