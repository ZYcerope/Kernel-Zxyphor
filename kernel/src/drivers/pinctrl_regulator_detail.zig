// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Pin Control, Regulator Framework & Power Domains
// Comprehensive: pinmux, pinconf, GPIO ranges, regulator constraints,
// voltage/current domains, DVFS coupling, power sequencing

const std = @import("std");

// ============================================================================
// Pin Control Subsystem
// ============================================================================

pub const PinFunction = struct {
    name: [64]u8,
    name_len: u8,
    groups: [16][64]u8,
    num_groups: u8,
};

pub const PinGroup = struct {
    name: [64]u8,
    name_len: u8,
    pins: [64]u32,
    num_pins: u8,
    data: ?*anyopaque,
};

pub const PinctrlPinDesc = struct {
    number: u32,
    name: [32]u8,
    drv_data: ?*anyopaque,
};

pub const PinctrlOps = struct {
    get_groups_count: ?*const fn (pctldev: *PinctrlDev) callconv(.C) i32,
    get_group_name: ?*const fn (pctldev: *PinctrlDev, selector: u32) callconv(.C) [*:0]const u8,
    get_group_pins: ?*const fn (pctldev: *PinctrlDev, selector: u32, pins: *[*]const u32, num_pins: *u32) callconv(.C) i32,
    dt_node_to_map: ?*const fn (pctldev: *PinctrlDev, np_node: u64, map: *[*]PinctrlMap, num_maps: *u32) callconv(.C) i32,
    dt_free_map: ?*const fn (pctldev: *PinctrlDev, map: [*]PinctrlMap, num_maps: u32) callconv(.C) void,
    pin_dbg_show: ?*const fn (pctldev: *PinctrlDev, seq: *anyopaque, offset: u32) callconv(.C) void,
};

pub const PinmuxOps = struct {
    request: ?*const fn (pctldev: *PinctrlDev, offset: u32) callconv(.C) i32,
    free: ?*const fn (pctldev: *PinctrlDev, offset: u32) callconv(.C) i32,
    get_functions_count: ?*const fn (pctldev: *PinctrlDev) callconv(.C) i32,
    get_function_name: ?*const fn (pctldev: *PinctrlDev, selector: u32) callconv(.C) [*:0]const u8,
    get_function_groups: ?*const fn (pctldev: *PinctrlDev, selector: u32, groups: *[*]const [*:0]const u8, num_groups: *u32) callconv(.C) i32,
    set_mux: ?*const fn (pctldev: *PinctrlDev, func_selector: u32, group_selector: u32) callconv(.C) i32,
    gpio_request_enable: ?*const fn (pctldev: *PinctrlDev, range: *PinctrlGpioRange, offset: u32) callconv(.C) i32,
    gpio_disable_free: ?*const fn (pctldev: *PinctrlDev, range: *PinctrlGpioRange, offset: u32) callconv(.C) void,
    gpio_set_direction: ?*const fn (pctldev: *PinctrlDev, range: *PinctrlGpioRange, offset: u32, input: bool) callconv(.C) i32,
    strict: bool,
};

pub const PinconfParam = enum(u32) {
    BiasDisable = 0,
    BiasPullUp = 1,
    BiasPullDown = 2,
    BiasBusHold = 3,
    BiasHighImpedance = 4,
    BiasPullPin = 5,
    DriveStrength = 6,
    DriveStrengthUa = 7,
    DriveOpenDrain = 8,
    DriveOpenSource = 9,
    DrivePushPull = 10,
    InputEnable = 11,
    InputDisable = 12,
    InputDebounce = 13,
    InputSchmittEnable = 14,
    InputSchmittDisable = 15,
    PowerSource = 16,
    SlewRate = 17,
    LowPowerMode = 18,
    OutputEnable = 19,
    Output = 20,
    OutputLow = 21,
    OutputHigh = 22,
    PersistState = 23,
    IoPadVoltage = 24,
};

pub const PinconfOps = struct {
    is_generic: bool,
    pin_config_get: ?*const fn (pctldev: *PinctrlDev, pin: u32, config: *u64) callconv(.C) i32,
    pin_config_set: ?*const fn (pctldev: *PinctrlDev, pin: u32, configs: [*]const u64, num_configs: u32) callconv(.C) i32,
    pin_config_group_get: ?*const fn (pctldev: *PinctrlDev, selector: u32, config: *u64) callconv(.C) i32,
    pin_config_group_set: ?*const fn (pctldev: *PinctrlDev, selector: u32, configs: [*]const u64, num_configs: u32) callconv(.C) i32,
    pin_config_dbg_show: ?*const fn (pctldev: *PinctrlDev, seq: *anyopaque, offset: u32) callconv(.C) void,
    pin_config_config_dbg_show: ?*const fn (pctldev: *PinctrlDev, seq: *anyopaque, config: u64) callconv(.C) void,
};

pub const PinctrlMapType = enum(u8) {
    Dummy = 0,
    MuxGroup = 1,
    ConfigsPin = 2,
    ConfigsGroup = 3,
};

pub const PinctrlMap = struct {
    dev_name: [64]u8,
    map_type: PinctrlMapType,
    ctrl_dev_name: [64]u8,
    function: [64]u8,
    group: [64]u8,
    configs: [16]u64,
    num_configs: u8,
};

pub const PinctrlGpioRange = struct {
    name: [32]u8,
    id: u32,
    base: u32,
    pin_base: u32,
    npins: u32,
    pins: [128]u32,
    gc: ?*anyopaque,   // gpio_chip
};

pub const PinctrlDev = struct {
    desc: PinctrlDesc,
    owner: ?*anyopaque,
    pin_descs: [512]PinctrlPinDesc,
    num_pins: u32,
    gpio_ranges: [8]PinctrlGpioRange,
    num_gpio_ranges: u8,
    dev: ?*anyopaque,
    hog_default: ?*PinctrlState,
    hog_sleep: ?*PinctrlState,
    p: ?*Pinctrl,
};

pub const PinctrlDesc = struct {
    name: [64]u8,
    pins: [512]PinctrlPinDesc,
    npins: u32,
    pctlops: PinctrlOps,
    pmxops: ?PinmuxOps,
    confops: ?PinconfOps,
    owner: ?*anyopaque,
    link_consumers: bool,
    custom_params: [16]PinconfParam,
    num_custom_params: u8,
};

pub const PinctrlState = struct {
    name: [32]u8,
    settings: [16]PinctrlSetting,
    num_settings: u8,
};

pub const PinctrlSetting = struct {
    map_type: PinctrlMapType,
    pctldev: ?*PinctrlDev,
    dev_name: [64]u8,
    data: PinctrlSettingData,
};

pub const PinctrlSettingData = union(enum) {
    mux: PinctrlSettingMux,
    configs: PinctrlSettingConfigs,
};

pub const PinctrlSettingMux = struct {
    group: u32,
    func: u32,
};

pub const PinctrlSettingConfigs = struct {
    group_or_pin: u32,
    configs: [16]u64,
    num_configs: u8,
};

pub const Pinctrl = struct {
    states: [8]PinctrlState,
    num_states: u8,
    state: ?*PinctrlState,
    dt_maps: [32]PinctrlMap,
    num_dt_maps: u8,
};

// ============================================================================
// Regulator Framework
// ============================================================================

pub const RegulatorType = enum(u8) {
    Voltage = 0,
    Current = 1,
};

pub const RegulatorStatus = enum(u8) {
    Off = 0,
    On = 1,
    Error = 2,
    FastChanging = 3,
    Bypass = 4,
    Undefined = 5,
};

pub const RegulatorMode = enum(u32) {
    Fast = 0x1,
    Normal = 0x2,
    Idle = 0x4,
    Standby = 0x8,
};

pub const RegulatorChanges = packed struct(u32) {
    voltage: bool,
    current_limit: bool,
    input_voltage: bool,
    status: bool,
    mode: bool,
    drms: bool,
    bypass: bool,
    under_voltage: bool,
    over_current: bool,
    over_current_warn: bool,
    over_voltage_warn: bool,
    under_voltage_warn: bool,
    over_temp: bool,
    over_temp_warn: bool,
    _reserved: u18,
};

pub const RegulatorOps = struct {
    list_voltage: ?*const fn (rdev: *RegulatorDev, selector: u32) callconv(.C) i32,
    set_voltage: ?*const fn (rdev: *RegulatorDev, min_uv: i32, max_uv: i32, selector: *u32) callconv(.C) i32,
    set_voltage_sel: ?*const fn (rdev: *RegulatorDev, selector: u32) callconv(.C) i32,
    map_voltage: ?*const fn (rdev: *RegulatorDev, min_uv: i32, max_uv: i32) callconv(.C) i32,
    get_voltage: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    get_voltage_sel: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_current_limit: ?*const fn (rdev: *RegulatorDev, min_ua: i32, max_ua: i32) callconv(.C) i32,
    get_current_limit: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_input_current_limit: ?*const fn (rdev: *RegulatorDev, limit: i32) callconv(.C) i32,
    set_over_current_protection: ?*const fn (rdev: *RegulatorDev, lim_ua: i32, severity: u32, enable: bool) callconv(.C) i32,
    set_over_voltage_protection: ?*const fn (rdev: *RegulatorDev, lim_uv: i32, severity: u32, enable: bool) callconv(.C) i32,
    set_under_voltage_protection: ?*const fn (rdev: *RegulatorDev, lim_uv: i32, severity: u32, enable: bool) callconv(.C) i32,
    set_thermal_protection: ?*const fn (rdev: *RegulatorDev, lim: i32, severity: u32, enable: bool) callconv(.C) i32,
    enable: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    disable: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    is_enabled: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_mode: ?*const fn (rdev: *RegulatorDev, mode: u32) callconv(.C) i32,
    get_mode: ?*const fn (rdev: *RegulatorDev) callconv(.C) u32,
    get_error_flags: ?*const fn (rdev: *RegulatorDev, flags: *u32) callconv(.C) i32,
    enable_time: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_ramp_delay: ?*const fn (rdev: *RegulatorDev, ramp_delay: i32) callconv(.C) i32,
    set_voltage_time: ?*const fn (rdev: *RegulatorDev, old_uv: i32, new_uv: i32) callconv(.C) i32,
    set_voltage_time_sel: ?*const fn (rdev: *RegulatorDev, old_sel: u32, new_sel: u32) callconv(.C) i32,
    set_soft_start: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_suspend_voltage: ?*const fn (rdev: *RegulatorDev, uv: i32) callconv(.C) i32,
    set_suspend_enable: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_suspend_disable: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_suspend_mode: ?*const fn (rdev: *RegulatorDev, mode: u32) callconv(.C) i32,
    resume: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_pull_down: ?*const fn (rdev: *RegulatorDev) callconv(.C) i32,
    set_bypass: ?*const fn (rdev: *RegulatorDev, enable: bool) callconv(.C) i32,
    get_bypass: ?*const fn (rdev: *RegulatorDev, enable: *bool) callconv(.C) i32,
};

pub const RegulatorDesc = struct {
    name: [64]u8,
    supply_name: [64]u8,
    of_match: [64]u8,
    regulators_node: [64]u8,
    id: i32,
    regulator_type: RegulatorType,
    owner: ?*anyopaque,
    continuous_voltage_range: bool,
    n_voltages: u32,
    n_current_limits: u32,
    ops: RegulatorOps,
    min_uv: i32,
    uv_step: i32,
    linear_min_sel: u32,
    fixed_uv: i32,
    ramp_delay: u32,
    min_dropout_uv: i32,
    vsel_reg: u32,
    vsel_mask: u32,
    csel_reg: u32,
    csel_mask: u32,
    apply_reg: u32,
    apply_bit: u32,
    enable_reg: u32,
    enable_mask: u32,
    enable_val: u32,
    disable_val: u32,
    enable_is_inverted: bool,
    bypass_reg: u32,
    bypass_mask: u32,
    bypass_val_on: u32,
    bypass_val_off: u32,
    active_discharge_on: u32,
    active_discharge_off: u32,
    active_discharge_mask: u32,
    active_discharge_reg: u32,
    soft_start_reg: u32,
    soft_start_mask: u32,
    soft_start_val_on: u32,
    pull_down_reg: u32,
    pull_down_mask: u32,
    pull_down_val_on: u32,
    ramp_reg: u32,
    ramp_mask: u32,
    ramp_delay_table: [16]u32,
    n_ramp_values: u32,
    enable_time: u32,
    off_on_delay: u32,
    poll_enabled_time: u32,
};

pub const RegulatorConstraints = struct {
    name: [64]u8,
    min_uv: i32,
    max_uv: i32,
    uv_offset: i32,
    min_ua: i32,
    max_ua: i32,
    ilim_ua: i32,
    system_load: i32,
    max_spread: i32,
    max_step_uv: i32,
    valid_modes_mask: u32,
    valid_ops_mask: u32,
    input_uv: i32,
    state_disk: RegulatorState,
    state_mem: RegulatorState,
    state_standby: RegulatorState,
    initial_state: u32,
    initial_mode: u32,
    ramp_delay: u32,
    settling_time: u32,
    settling_time_up: u32,
    settling_time_down: u32,
    enable_time: u32,
    active_discharge: u8,
    always_on: bool,
    boot_on: bool,
    apply_uv: bool,
    over_current_protection: bool,
    over_current_detection: bool,
    over_voltage_detection: bool,
    under_voltage_detection: bool,
    over_temp_detection: bool,
};

pub const RegulatorState = struct {
    uv: i32,
    mode: u32,
    enabled: bool,
    disabled: bool,
    changeable: bool,
};

pub const RegulatorConsumer = struct {
    dev_name: [64]u8,
    supply: [32]u8,
};

pub const RegulatorDev = struct {
    desc: ?*RegulatorDesc,
    regmap: ?*anyopaque,
    constraints: RegulatorConstraints,
    consumers: [16]RegulatorConsumer,
    num_consumers: u8,
    supply: ?*RegulatorDev,
    use_count: u32,
    open_count: u32,
    bypass_count: u32,
    deferred_disables: u32,
    coupling: RegulatorCoupling,
    enabled: bool,
    is_switch: bool,
};

pub const RegulatorCoupling = struct {
    coupled_regulators: [4]*RegulatorDev,
    n_coupled: u8,
    max_spread: i32,
    balance_voltage: ?*const fn (regulators: [*]*RegulatorDev, n_regulators: u32) callconv(.C) i32,
};

pub const RegulatorVoltageTable = struct {
    min_uv: i32,
    max_uv: i32,
};

// ============================================================================
// Power Domain Framework
// ============================================================================

pub const GenpowerDomainFlags = packed struct(u32) {
    active_wakeup: bool,
    cpu_domain: bool,
    hw_ctrl: bool,
    always_on: bool,
    rpm_always_on: bool,
    opp_table_fw: bool,
    dev_has_states: bool,
    min_residency: bool,
    _reserved: u24,
};

pub const GenpowerDomainState = struct {
    name: [32]u8,
    power_off_latency_ns: u64,
    power_on_latency_ns: u64,
    residency_ns: u64,
    usage_count: u64,
    rejected: u64,
    idle_time: u64,
};

pub const GenpowerDomainOps = struct {
    power_on: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    power_off: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    start: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    stop: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    attach_dev: ?*const fn (domain: *GenPowerDomain, dev: *anyopaque) callconv(.C) i32,
    detach_dev: ?*const fn (domain: *GenPowerDomain, dev: *anyopaque) callconv(.C) void,
    save_ctx: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    restore_ctx: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    suspend: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    resume: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    freeze: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
    thaw: ?*const fn (domain: *GenPowerDomain) callconv(.C) i32,
};

pub const GenPowerDomain = struct {
    name: [64]u8,
    ops: GenpowerDomainOps,
    states: [8]GenpowerDomainState,
    state_count: u32,
    state_idx: u32,
    performance_state: u32,
    flags: GenpowerDomainFlags,
    parent_domains: [4]*GenPowerDomain,
    num_parents: u8,
    child_domains: [8]*GenPowerDomain,
    num_children: u8,
    device_count: u32,
    sd_count: u32,
    suspended_count: u32,
    prepared_count: u32,
    cached_power_down_ok: bool,
    cached_power_down_state_idx: u32,
    provider: ?*anyopaque,
    opp_table: ?*anyopaque,
    cpus: [256]bool,
    synced_poweroff: bool,
    accounting_time: u64,
};

// ============================================================================
// Manager
// ============================================================================

pub const PinctrlRegulatorManager = struct {
    total_pinctrl_devs: u32,
    total_regulators: u32,
    total_power_domains: u32,
    total_pin_configs: u64,
    total_voltage_changes: u64,
    total_power_transitions: u64,
    initialized: bool,

    pub fn init() PinctrlRegulatorManager {
        return .{
            .total_pinctrl_devs = 0,
            .total_regulators = 0,
            .total_power_domains = 0,
            .total_pin_configs = 0,
            .total_voltage_changes = 0,
            .total_power_transitions = 0,
            .initialized = true,
        };
    }
};
