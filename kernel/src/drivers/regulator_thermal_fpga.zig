// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Regulator Framework, Thermal Zone Management,
// FPGA Manager/Bridge, RTC Subsystem, Reset Controller,
// Generic PHY Framework
// More advanced than Linux 2026 device subsystems

const std = @import("std");

// ============================================================================
// Regulator Framework
// ============================================================================

/// Regulator type
pub const RegulatorType = enum(u8) {
    voltage = 0,
    current = 1,
};

/// Regulator state
pub const RegulatorState = enum(u8) {
    disabled = 0,
    enabled = 1,
    suspended = 2,
    forced_disabled = 3,
};

/// Regulator operating mode
pub const RegulatorMode = enum(u8) {
    fast = 0,
    normal = 1,
    idle = 2,
    standby = 3,
};

/// Regulator event
pub const RegulatorEvent = enum(u32) {
    under_voltage = 0x01,
    over_current = 0x02,
    regulation_out = 0x04,
    fail = 0x08,
    over_temp = 0x10,
    force_disable = 0x20,
    voltage_change = 0x40,
    disable = 0x80,
    pre_voltage_change = 0x100,
    abort_voltage_change = 0x200,
    pre_disable = 0x400,
    abort_disable = 0x800,
    enable = 0x1000,
    over_voltage_warn = 0x2000,
    under_voltage_warn = 0x4000,
    over_current_warn = 0x8000,
    over_temp_warn = 0x10000,
    // Zxyphor
    zxy_efficiency_change = 0x100000,
};

/// Regulator constraints
pub const RegulatorConstraints = struct {
    name: [64]u8,
    name_len: u8,
    // Voltage
    min_uV: i32,
    max_uV: i32,
    uV_offset: i32,
    // Current
    min_uA: i32,
    max_uA: i32,
    // Operating mode
    valid_modes_mask: u32,
    valid_ops_mask: u32,
    // Initial state
    initial_state: RegulatorState,
    initial_mode: RegulatorMode,
    // Ramp delay
    ramp_delay: u32,           // uV/us
    settling_time: u32,        // us
    settling_time_up: u32,
    settling_time_down: u32,
    // Enable time
    enable_time: u32,          // us
    // Boot state
    boot_on: bool,
    always_on: bool,
    // Pull down
    pull_down: bool,
    // Over current protection
    over_current_protection: bool,
    over_voltage_detection: bool,
    under_voltage_detection: bool,
    over_temp_detection: bool,
    // Soft start
    soft_start: bool,
};

/// Regulator descriptor
pub const RegulatorDesc = struct {
    name: [64]u8,
    name_len: u8,
    id: u32,
    reg_type: RegulatorType,
    // Voltage table
    n_voltages: u32,
    min_uV: i32,
    uV_step: i32,
    linear_min_sel: u32,
    // Current limit
    n_current_limits: u32,
    // Registers
    vsel_reg: u32,
    vsel_mask: u32,
    csel_reg: u32,
    csel_mask: u32,
    enable_reg: u32,
    enable_mask: u32,
    enable_val: u32,
    disable_val: u32,
    enable_is_inverted: bool,
    // Ramp
    ramp_delay: u32,
    // Flags
    continuous_voltage_range: bool,
    // Ops
    ops_type: RegulatorOpsType,
};

/// Regulator ops type
pub const RegulatorOpsType = enum(u8) {
    voltage_only = 0,
    current_only = 1,
    voltage_and_current = 2,
    fixed = 3,
};

/// Regulator stats
pub const RegulatorStats = struct {
    enabled_count: u64,
    disabled_count: u64,
    total_on_time_ms: u64,
    // Voltage changes
    voltage_changes: u64,
    last_voltage_uV: i32,
    // Current
    last_current_uA: i32,
    // Efficiency
    efficiency_percent: u32,
    power_loss_mW: u32,
};

// ============================================================================
// Thermal Zone Management
// ============================================================================

/// Thermal zone type
pub const ThermalZoneType = enum(u8) {
    acpi = 0,           // ACPI thermal zone
    cpu = 1,            // CPU thermal sensor
    gpu = 2,            // GPU thermal sensor
    memory = 3,         // Memory controller
    board = 4,          // Board sensor
    // Zxyphor
    zxy_soc = 10,
};

/// Thermal trip type
pub const ThermalTripType = enum(u8) {
    active = 0,         // Active cooling (fan)
    passive = 1,        // Passive cooling (throttle)
    hot = 2,            // Hot trip point
    critical = 3,       // Critical shutdown
    // Zxyphor
    zxy_warning = 10,
};

/// Thermal trip point
pub const ThermalTrip = struct {
    trip_type: ThermalTripType,
    temperature: i32,    // millidegrees Celsius
    hysteresis: i32,     // millidegrees Celsius
    flags: u32,
};

/// Thermal governor
pub const ThermalGovernor = enum(u8) {
    step_wise = 0,
    fair_share = 1,
    bang_bang = 2,       // On/Off
    user_space = 3,
    power_allocator = 4, // IPA
    // Zxyphor
    zxy_adaptive = 10,
    zxy_ml_thermal = 11,
};

/// Thermal zone descriptor
pub const ThermalZone = struct {
    id: u32,
    zone_type: ThermalZoneType,
    name: [32]u8,
    name_len: u8,
    // Current state
    temperature: i32,         // millidegrees Celsius
    last_temperature: i32,
    emul_temperature: i32,    // Emulated (for testing)
    // Trip points
    nr_trips: u8,
    trips: [12]ThermalTrip,
    // Governor
    governor: ThermalGovernor,
    // Polling
    polling_delay: u32,       // ms
    passive_delay: u32,       // ms
    // Mode
    mode: ThermalMode,
    // Cooling devices bound
    nr_cooling_devices: u8,
    // Zxyphor
    zxy_trend: ThermalTrend,
    zxy_predicted_temp: i32,
};

/// Thermal mode
pub const ThermalMode = enum(u8) {
    disabled = 0,
    enabled = 1,
};

/// Thermal trend
pub const ThermalTrend = enum(u8) {
    stable = 0,
    raising = 1,
    dropping = 2,
};

/// Cooling device type
pub const CoolingDevType = enum(u8) {
    processor = 0,       // CPU freq throttling
    fan = 1,
    power_allocator = 2,
    // Zxyphor
    zxy_liquid = 10,
};

/// Cooling device descriptor
pub const CoolingDevice = struct {
    id: u32,
    dev_type: CoolingDevType,
    name: [32]u8,
    name_len: u8,
    // State
    cur_state: u64,
    max_state: u64,
    // Stats
    total_trans: u64,
    transition_table: [32]u64,  // Time in each state
};

// ============================================================================
// FPGA Manager
// ============================================================================

/// FPGA state
pub const FpgaState = enum(u8) {
    unknown = 0,
    power_off = 1,
    power_up = 2,
    reset = 3,
    firmware_req = 4,
    firmware_req_err = 5,
    write_init = 6,
    write_init_err = 7,
    write = 8,
    write_err = 9,
    write_complete = 10,
    write_complete_err = 11,
    operating = 12,
};

/// FPGA manager flags
pub const FpgaMgrFlags = packed struct {
    partial_reconfig: bool = false,
    external_config: bool = false,
    encrypted_bitstream: bool = false,
    compressed_bitstream: bool = false,
    // Zxyphor
    zxy_hot_reconfig: bool = false,
    _padding: u3 = 0,
};

/// FPGA manager descriptor
pub const FpgaManager = struct {
    name: [64]u8,
    name_len: u8,
    state: FpgaState,
    flags: FpgaMgrFlags,
    // Compatibility info
    compat_id: u64,
    // Status
    status: u64,
    // Bitstream info
    bitstream_size: u64,
    region_id: u32,
};

/// FPGA bridge descriptor
pub const FpgaBridge = struct {
    name: [64]u8,
    name_len: u8,
    enabled: bool,
    br_type: FpgaBridgeType,
};

pub const FpgaBridgeType = enum(u8) {
    none = 0,
    axi = 1,
    avalon = 2,
    // Zxyphor
    zxy_native = 10,
};

/// FPGA region
pub const FpgaRegion = struct {
    compat_id: u64,
    mgr_idx: u32,
    nr_bridges: u8,
    bridge_ids: [8]u32,
    // Partial reconfig info
    is_partial: bool,
};

// ============================================================================
// RTC Subsystem
// ============================================================================

/// RTC time
pub const RtcTime = struct {
    tm_sec: i32,         // 0-59
    tm_min: i32,         // 0-59
    tm_hour: i32,        // 0-23
    tm_mday: i32,        // 1-31
    tm_mon: i32,         // 0-11
    tm_year: i32,        // Years since 1900
    tm_wday: i32,        // 0-6 (Sunday=0)
    tm_yday: i32,        // 0-365
    tm_isdst: i32,       // DST flag
};

/// RTC alarm
pub const RtcWkalrm = struct {
    enabled: bool,
    pending: bool,
    time: RtcTime,
};

/// RTC features
pub const RtcFeatures = packed struct {
    alarm: bool = false,
    alarm_rng: bool = false,
    need_week_day: bool = false,
    alarm_wakeup: bool = false,
    update_interrupt: bool = false,
    correction: bool = false,
    backup_time: bool = false,
    set_start_time_s_only: bool = false,
    _padding: u8 = 0,
};

/// RTC device descriptor
pub const RtcDevice = struct {
    name: [32]u8,
    name_len: u8,
    id: u32,
    features: RtcFeatures,
    // Current time
    current_time: RtcTime,
    // Alarm
    alarm: RtcWkalrm,
    // Counter
    range_min: i64,
    range_max: i64,
    start_secs: i64,
    offset_secs: i64,
    // UIE (Update Interrupt Enable)
    uie_unsupported: bool,
    // Irqs
    irq_freq: u32,
    max_user_freq: u32,
};

// ============================================================================
// Reset Controller
// ============================================================================

/// Reset type
pub const ResetType = enum(u8) {
    exclusive = 0,
    shared = 1,
    acquired = 2,
};

/// Reset control descriptor
pub const ResetControl = struct {
    id: u32,
    reset_type: ResetType,
    // State
    deasserted: bool,
    triggered: bool,
    acquired: bool,
    // Shared reference count
    shared_count: u32,
};

/// Reset controller descriptor
pub const ResetController = struct {
    name: [32]u8,
    name_len: u8,
    nr_resets: u32,
    // Stats
    total_asserts: u64,
    total_deasserts: u64,
};

// ============================================================================
// Generic PHY Framework
// ============================================================================

/// PHY type
pub const PhyType = enum(u8) {
    none = 0,
    usb2 = 1,
    usb3 = 2,
    ufs = 3,
    pcie = 4,
    sata = 5,
    dp = 6,            // DisplayPort
    hdmi = 7,
    sgmii = 8,
    mipi_dphy = 9,
    mipi_cphy = 10,
    ethernet = 11,
    // Zxyphor
    zxy_custom = 100,
};

/// PHY mode
pub const PhyMode = enum(u8) {
    invalid = 0,
    usb_host = 1,
    usb_host_ls = 2,
    usb_host_fs = 3,
    usb_host_hs = 4,
    usb_host_ss = 5,
    usb_device = 6,
    usb_device_ls = 7,
    usb_device_fs = 8,
    usb_device_hs = 9,
    usb_device_ss = 10,
    usb_otg = 11,
    ufs_hs_a = 12,
    ufs_hs_b = 13,
    pcie_rc = 14,
    pcie_ep = 15,
    sata_host = 16,
    dp_alt = 17,
    ethernet_1000basex = 18,
    ethernet_sgmii = 19,
    ethernet_10gbase_r = 20,
    ethernet_25gbase_r = 21,
    mipi_dphy = 22,
    // Zxyphor
    zxy_high_speed = 100,
};

/// PHY state
pub const PhyState = enum(u8) {
    off = 0,
    on = 1,
    reset = 2,
    calibrating = 3,
    ready = 4,
};

/// PHY descriptor
pub const PhyDescriptor = struct {
    id: u32,
    phy_type: PhyType,
    mode: PhyMode,
    state: PhyState,
    // Configuration
    attrs: PhyAttrs,
    // Stats
    power_on_count: u64,
    calibration_count: u64,
};

/// PHY attributes
pub const PhyAttrs = struct {
    bus_width: u8,
    max_link_rate: u32,    // Mbps
    // Speed mode
    mode_supported: u32,   // Bitmask of PHY modes
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const DeviceFrameworkSubsystem = struct {
    // Regulators
    nr_regulators: u32,
    nr_regulator_consumers: u32,
    total_regulator_events: u64,
    // Thermal
    nr_thermal_zones: u32,
    nr_cooling_devices: u32,
    max_temperature: i32,
    // FPGA
    nr_fpga_managers: u32,
    nr_fpga_regions: u32,
    nr_fpga_bridges: u32,
    // RTC
    nr_rtc_devices: u32,
    // Reset
    nr_reset_controllers: u32,
    // PHY
    nr_phys: u32,
    // Zxyphor
    zxy_adaptive_power: bool,
    zxy_thermal_prediction: bool,
    initialized: bool,

    pub fn init() DeviceFrameworkSubsystem {
        return DeviceFrameworkSubsystem{
            .nr_regulators = 0,
            .nr_regulator_consumers = 0,
            .total_regulator_events = 0,
            .nr_thermal_zones = 0,
            .nr_cooling_devices = 0,
            .max_temperature = 0,
            .nr_fpga_managers = 0,
            .nr_fpga_regions = 0,
            .nr_fpga_bridges = 0,
            .nr_rtc_devices = 0,
            .nr_reset_controllers = 0,
            .nr_phys = 0,
            .zxy_adaptive_power = true,
            .zxy_thermal_prediction = true,
            .initialized = false,
        };
    }
};
