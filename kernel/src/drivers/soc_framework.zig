// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Clock/Regulator/Pinctrl Framework
// Comprehensive SoC infrastructure: CCF, regulator consumers/providers, pin muxing
// More advanced than Linux 2026 clock/regulator/pinctrl subsystems

const std = @import("std");

// ============================================================================
// Common Clock Framework (CCF)
// ============================================================================

pub const CLK_MAX_CLOCKS: u32 = 2048;
pub const CLK_MAX_PARENTS: u32 = 16;
pub const CLK_MAX_CONSUMERS: u32 = 32;
pub const CLK_NAME_MAX: u32 = 64;

// Clock flags
pub const CLK_SET_RATE_GATE: u32 = 1 << 0;
pub const CLK_SET_PARENT_GATE: u32 = 1 << 1;
pub const CLK_SET_RATE_PARENT: u32 = 1 << 2;
pub const CLK_IGNORE_UNUSED: u32 = 1 << 3;
pub const CLK_GET_RATE_NOCACHE: u32 = 1 << 4;
pub const CLK_SET_RATE_NO_REPARENT: u32 = 1 << 5;
pub const CLK_GET_ACCURACY_NOCACHE: u32 = 1 << 6;
pub const CLK_RECALC_NEW_RATES: u32 = 1 << 7;
pub const CLK_SET_RATE_UNGATE: u32 = 1 << 8;
pub const CLK_IS_CRITICAL: u32 = 1 << 9;
pub const CLK_OPS_PARENT_ENABLE: u32 = 1 << 10;
pub const CLK_DUTY_CYCLE_PARENT: u32 = 1 << 11;

pub const ClkType = enum(u8) {
    fixed = 0,
    gate = 1,
    divider = 2,
    mux = 3,
    pll = 4,
    fixed_factor = 5,
    fractional_divider = 6,
    composite = 7,
    gpio_gate = 8,
    // SoC-specific
    arm_pll = 20,
    ddr_pll = 21,
    video_pll = 22,
    audio_pll = 23,
    // Zxyphor
    zxy_adaptive = 200,
    zxy_spread_spectrum = 201,
};

pub const ClkDutyCycle = struct {
    num: u32,   // Numerator (on time)
    den: u32,   // Denominator (period)
};

pub const ClkRateRequest = struct {
    rate: u64,
    min_rate: u64,
    max_rate: u64,
    best_parent_rate: u64,
    best_parent_hw: ?*ClkHw,
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
    set_rate: ?*const fn (*ClkHw, u64, u64) i32,
    set_rate_and_parent: ?*const fn (*ClkHw, u64, u64, u8) i32,
    get_parent: ?*const fn (*ClkHw) u8,
    set_parent: ?*const fn (*ClkHw, u8) i32,
    recalc_accuracy: ?*const fn (*ClkHw, u64) u64,
    get_phase: ?*const fn (*ClkHw) i32,
    set_phase: ?*const fn (*ClkHw, i32) i32,
    get_duty_cycle: ?*const fn (*ClkHw, *ClkDutyCycle) i32,
    set_duty_cycle: ?*const fn (*ClkHw, *const ClkDutyCycle) i32,
    init: ?*const fn (*ClkHw) void,
    debug_init: ?*const fn (*ClkHw) void,
};

pub const ClkHw = struct {
    core: ?*ClkCore,
    clk: ?*Clk,
    init: ?*const ClkInitData,
};

pub const ClkInitData = struct {
    name: [CLK_NAME_MAX]u8,
    name_len: u8,
    ops: *const ClkOps,
    parent_names: [CLK_MAX_PARENTS][CLK_NAME_MAX]u8,
    parent_name_lens: [CLK_MAX_PARENTS]u8,
    num_parents: u8,
    flags: u32,
};

pub const ClkCore = struct {
    name: [CLK_NAME_MAX]u8,
    name_len: u8,
    ops: *const ClkOps,
    hw: *ClkHw,
    parent: ?*ClkCore,
    parent_names: [CLK_MAX_PARENTS][CLK_NAME_MAX]u8,
    parents: [CLK_MAX_PARENTS]?*ClkCore,
    num_parents: u8,
    new_parent: ?*ClkCore,
    new_parent_index: u8,
    rate: u64,
    req_rate: u64,
    new_rate: u64,
    accuracy: u64,
    phase: i32,
    duty: ClkDutyCycle,
    flags: u32,
    enable_count: u32,
    prepare_count: u32,
    protect_count: u32,
    notifier_count: u32,
    clk_type: ClkType,
    // Tree linkage
    children: [32]?*ClkCore,
    nr_children: u32,

    pub fn is_enabled(self: *const ClkCore) bool {
        return self.enable_count > 0;
    }

    pub fn is_prepared(self: *const ClkCore) bool {
        return self.prepare_count > 0;
    }
};

pub const Clk = struct {
    core: *ClkCore,
    dev_id: [64]u8,
    con_id: [64]u8,
    min_rate: u64,
    max_rate: u64,
    exclusive_count: u32,
};

// Clock-specific implementations
pub const ClkGate = struct {
    hw: ClkHw,
    reg: u64,    // MMIO address
    bit_idx: u8,
    flags: u8,
    // 0=set to enable, 1=clear to enable
    active_low: bool,
};

pub const ClkDivider = struct {
    hw: ClkHw,
    reg: u64,
    shift: u8,
    width: u8,
    flags: u8,
    table: ?[*]const ClkDivTable,
    table_len: u32,
};

pub const ClkDivTable = struct {
    val: u32,
    div: u32,
};

pub const ClkMux = struct {
    hw: ClkHw,
    reg: u64,
    shift: u8,
    mask: u32,
    flags: u8,
    table: ?[*]const u32,
};

pub const ClkPll = struct {
    hw: ClkHw,
    reg_base: u64,
    // PLL parameters
    input_freq: u64,
    prediv: u32,
    fbdiv: u32,
    postdiv1: u32,
    postdiv2: u32,
    frac: u32,
    frac_bits: u8,
    // Lock
    lock_reg: u64,
    lock_bit: u8,
    // Spread spectrum
    ssc_enabled: bool,
    ssc_range_ppm: u32,
    ssc_modfreq_hz: u32,
    // Type
    pll_type: PllType,

    pub fn compute_rate(self: *const ClkPll) u64 {
        if (self.prediv == 0) return 0;
        var rate = self.input_freq * @as(u64, self.fbdiv);
        rate /= @as(u64, self.prediv);
        if (self.postdiv1 > 0) rate /= @as(u64, self.postdiv1);
        if (self.postdiv2 > 0) rate /= @as(u64, self.postdiv2);
        // Fractional part
        if (self.frac > 0 and self.frac_bits > 0) {
            const frac_rate = (self.input_freq * @as(u64, self.frac)) >>
                @intCast(self.frac_bits);
            rate += frac_rate / @as(u64, self.prediv);
        }
        return rate;
    }
};

pub const PllType = enum(u8) {
    integer_n = 0,
    fractional_n = 1,
    sigma_delta = 2,
    phase_interpolator = 3,
};

pub const ClkFixedFactor = struct {
    hw: ClkHw,
    mult: u32,
    div: u32,
};

// ============================================================================
// Regulator Framework
// ============================================================================

pub const REG_MAX_REGULATORS: u32 = 512;
pub const REG_NAME_MAX: u32 = 64;

pub const RegulatorType = enum(u8) {
    voltage = 0,
    current = 1,
};

pub const RegulatorMode = enum(u32) {
    fast = 0x01,
    normal = 0x02,
    idle = 0x04,
    standby = 0x08,
};

pub const RegulatorStatus = enum(u8) {
    off = 0,
    on = 1,
    error = 2,
    fast = 3,
    normal = 4,
    idle = 5,
    standby = 6,
    bypass = 7,
    undefined = 8,
};

pub const RegulatorChangeReason = enum(u8) {
    system_init = 0,
    consumer_request = 1,
    voltage_scaling = 2,
    suspend = 3,
    resume = 4,
    thermal = 5,
    overcurrent = 6,
    regulation_out = 7,
};

pub const RegulatorOps = struct {
    list_voltage: ?*const fn (*RegulatorDev, u32) i32,
    set_voltage: ?*const fn (*RegulatorDev, i32, i32, *u32) i32,
    set_voltage_sel: ?*const fn (*RegulatorDev, u32) i32,
    map_voltage: ?*const fn (*RegulatorDev, i32, i32) i32,
    get_voltage: ?*const fn (*RegulatorDev) i32,
    get_voltage_sel: ?*const fn (*RegulatorDev) i32,
    set_current_limit: ?*const fn (*RegulatorDev, i32, i32) i32,
    get_current_limit: ?*const fn (*RegulatorDev) i32,
    set_active_discharge: ?*const fn (*RegulatorDev, bool) i32,
    enable: ?*const fn (*RegulatorDev) i32,
    disable: ?*const fn (*RegulatorDev) i32,
    is_enabled: ?*const fn (*RegulatorDev) bool,
    set_mode: ?*const fn (*RegulatorDev, u32) i32,
    get_mode: ?*const fn (*RegulatorDev) u32,
    get_error_flags: ?*const fn (*RegulatorDev, *u32) i32,
    enable_time: ?*const fn (*RegulatorDev) u32,
    set_ramp_delay: ?*const fn (*RegulatorDev, i32) i32,
    set_voltage_time_sel: ?*const fn (*RegulatorDev, u32, u32) i32,
    set_soft_start: ?*const fn (*RegulatorDev) i32,
    set_suspend_voltage: ?*const fn (*RegulatorDev, i32) i32,
    set_suspend_enable: ?*const fn (*RegulatorDev) i32,
    set_suspend_disable: ?*const fn (*RegulatorDev) i32,
    set_suspend_mode: ?*const fn (*RegulatorDev, u32) i32,
    set_pull_down: ?*const fn (*RegulatorDev) i32,
    set_over_current_protection: ?*const fn (*RegulatorDev, i32, i32, bool) i32,
    set_over_voltage_protection: ?*const fn (*RegulatorDev, i32, i32, bool) i32,
    set_under_voltage_protection: ?*const fn (*RegulatorDev, i32, i32, bool) i32,
    set_thermal_protection: ?*const fn (*RegulatorDev, i32, i32, bool) i32,
};

pub const RegulatorDesc = struct {
    name: [REG_NAME_MAX]u8,
    name_len: u8,
    supply_name: [REG_NAME_MAX]u8,
    reg_type: RegulatorType,
    id: u32,
    ops: *const RegulatorOps,
    // Voltage
    n_voltages: u32,
    min_uv: i32,
    max_uv: i32,
    uv_step: i32,
    linear_min_sel: u32,
    // Current
    csel_reg: u32,
    csel_mask: u32,
    // Enable
    enable_reg: u32,
    enable_mask: u32,
    enable_val: u32,
    disable_val: u32,
    enable_is_inverted: bool,
    // Voltage selector
    vsel_reg: u32,
    vsel_mask: u32,
    vsel_range_reg: u32,
    vsel_range_mask: u32,
    // Bypass
    bypass_reg: u32,
    bypass_mask: u32,
    bypass_val_on: u32,
    // Active discharge
    active_discharge_reg: u32,
    active_discharge_mask: u32,
    active_discharge_on: u32,
    active_discharge_off: u32,
    // Soft start
    soft_start_reg: u32,
    soft_start_mask: u32,
    soft_start_val_on: u32,
    // Ramp delay
    ramp_delay: u32,
    ramp_reg: u32,
    ramp_mask: u32,
    ramp_delay_table: [16]u32,
    n_ramp_values: u8,
    // Pull down
    pull_down_reg: u32,
    pull_down_mask: u32,
    pull_down_val_on: u32,
    // Linear ranges
    linear_ranges: [8]LinearRange,
    n_linear_ranges: u8,
    // OCP/OVP/UVP/OTP
    of_match: [64]u8,
    of_match_len: u8,
    owner: u32,
};

pub const LinearRange = struct {
    min: u32,
    min_sel: u32,
    max_sel: u32,
    step: u32,
};

pub const RegulatorDev = struct {
    desc: *const RegulatorDesc,
    // State
    enabled: bool,
    voltage_uv: i32,
    current_ua: i32,
    mode: RegulatorMode,
    status: RegulatorStatus,
    use_count: u32,
    open_count: u32,
    bypass: bool,
    // Constraints
    constraints: RegulatorConstraints,
    // Supply chain
    supply: ?*RegulatorDev,
    consumers: [REG_MAX_REGULATORS]?*Regulator,
    nr_consumers: u32,
    // Coupling
    coupled: [4]?*RegulatorDev,
    nr_coupled: u8,
    // Notifications
    under_voltage: bool,
    over_current: bool,
    regulation_out: bool,
    over_temp: bool,
};

pub const RegulatorConstraints = struct {
    min_uv: i32,
    max_uv: i32,
    uv_offset: i32,
    min_ua: i32,
    max_ua: i32,
    valid_modes_mask: u32,
    valid_ops_mask: u32,
    always_on: bool,
    boot_on: bool,
    apply_uv: bool,
    ramp_disable: bool,
    soft_start: bool,
    pull_down: bool,
    over_current_protection: bool,
    over_voltage_protection: bool,
    under_voltage_protection: bool,
    over_temp_protection: bool,
    // Suspend states
    suspend_state: [4]RegulatorSuspendState,
    initial_state: u8,
    initial_mode: u32,
    settling_time: u32,
    settling_time_up: u32,
    settling_time_down: u32,
    enable_time: u32,
};

pub const RegulatorSuspendState = struct {
    uv: i32,
    mode: u32,
    enabled: bool,
    disabled: bool,
    changeable: bool,
};

pub const Regulator = struct {
    dev: *RegulatorDev,
    min_uv: i32,
    max_uv: i32,
    exclusive: bool,
    enabled: bool,
    always_on: bool,
    bypass: bool,
    device_name: [64]u8,
    supply_name: [64]u8,
};

// ============================================================================
// Pin Control Framework
// ============================================================================

pub const PIN_MAX_PINS: u32 = 1024;
pub const PIN_MAX_GROUPS: u32 = 512;
pub const PIN_MAX_FUNCTIONS: u32 = 256;
pub const PIN_MAX_CONFIGS: u32 = 32;

pub const PinDirection = enum(u8) {
    input = 0,
    output = 1,
};

pub const PinBias = enum(u8) {
    disable = 0,
    pull_up = 1,
    pull_down = 2,
    bus_hold = 3,
    high_impedance = 4,
};

pub const PinDriveType = enum(u8) {
    push_pull = 0,
    open_drain = 1,
    open_source = 2,
};

pub const PinConfigParam = enum(u32) {
    bias_bus_hold = 0,
    bias_disable = 1,
    bias_high_impedance = 2,
    bias_pull_down = 3,
    bias_pull_pin_default = 4,
    bias_pull_up = 5,
    drive_open_drain = 6,
    drive_open_source = 7,
    drive_push_pull = 8,
    drive_strength = 9,
    drive_strength_ua = 10,
    input_debounce = 11,
    input_enable = 12,
    input_schmitt = 13,
    input_schmitt_enable = 14,
    low_power_mode = 15,
    output_enable = 16,
    output = 17,
    power_source = 18,
    sleep_hardware_state = 19,
    slew_rate = 20,
    skew_delay = 21,
    persist_state = 22,
};

pub const PinDesc = struct {
    number: u32,
    name: [32]u8,
    name_len: u8,
    drv_data: u64,
    // Dynamic config
    mux_owner: [64]u8,
    gpio_owner: [64]u8,
};

pub const PinGroup = struct {
    name: [64]u8,
    name_len: u8,
    pins: [64]u32,
    nr_pins: u32,
    data: u64,
};

pub const PinFunction = struct {
    name: [64]u8,
    name_len: u8,
    groups: [64]u32,    // Group indices
    nr_groups: u32,
};

pub const PinctlOps = struct {
    get_groups_count: ?*const fn (*PinctlDev) u32,
    get_group_name: ?*const fn (*PinctlDev, u32) [*]const u8,
    get_group_pins: ?*const fn (*PinctlDev, u32, *[*]const u32, *u32) i32,
    pin_dbg_show: ?*const fn (*PinctlDev, u32) void,
    dt_node_to_map: ?*const fn (*PinctlDev, u64) i32,
    dt_free_map: ?*const fn (*PinctlDev, u64) void,
};

pub const PinmuxOps = struct {
    request: ?*const fn (*PinctlDev, u32) i32,
    free: ?*const fn (*PinctlDev, u32) i32,
    get_functions_count: ?*const fn (*PinctlDev) u32,
    get_function_name: ?*const fn (*PinctlDev, u32) [*]const u8,
    get_function_groups: ?*const fn (*PinctlDev, u32, *[*]const [*]const u8, *u32) i32,
    set_mux: ?*const fn (*PinctlDev, u32, u32) i32,
    gpio_request_enable: ?*const fn (*PinctlDev, u64, u32) i32,
    gpio_disable_free: ?*const fn (*PinctlDev, u64, u32) i32,
    gpio_set_direction: ?*const fn (*PinctlDev, u64, u32, bool) i32,
    strict: bool,
};

pub const PinconfOps = struct {
    pin_config_get: ?*const fn (*PinctlDev, u32, *u64) i32,
    pin_config_set: ?*const fn (*PinctlDev, u32, [*]const u64, u32) i32,
    pin_config_group_get: ?*const fn (*PinctlDev, u32, *u64) i32,
    pin_config_group_set: ?*const fn (*PinctlDev, u32, [*]const u64, u32) i32,
    pin_config_dbg_show: ?*const fn (*PinctlDev, u32) void,
    pin_config_config_dbg_show: ?*const fn (*PinctlDev, u64) void,
    is_generic: bool,
};

pub const PinctlDesc = struct {
    name: [64]u8,
    name_len: u8,
    pins: [PIN_MAX_PINS]PinDesc,
    nr_pins: u32,
    pctlops: *const PinctlOps,
    pmxops: ?*const PinmuxOps,
    confops: ?*const PinconfOps,
    custom_params: [32]PinConfigParam,
    nr_custom_params: u32,
    owner: u32,
};

pub const PinctlDev = struct {
    desc: *const PinctlDesc,
    // Groups
    groups: [PIN_MAX_GROUPS]PinGroup,
    nr_groups: u32,
    // Functions
    functions: [PIN_MAX_FUNCTIONS]PinFunction,
    nr_functions: u32,
    // State
    states: [16]PinctlState,
    nr_states: u32,
    current_state: u32,
    // Mux settings
    mux_settings: [PIN_MAX_PINS]PinMuxSetting,
    // GPIO ranges
    gpio_ranges: [16]PinctlGpioRange,
    nr_gpio_ranges: u32,
};

pub const PinctlState = struct {
    name: [64]u8,
    name_len: u8,
    settings: [32]PinctlSetting,
    nr_settings: u32,
};

pub const PinctlSetting = struct {
    setting_type: PinctlSettingType,
    // Mux
    func_selector: u32,
    group_selector: u32,
    // Config
    configs: [PIN_MAX_CONFIGS]u64,
    nr_configs: u32,
};

pub const PinctlSettingType = enum(u8) {
    mux = 0,
    configs_pin = 1,
    configs_group = 2,
};

pub const PinMuxSetting = struct {
    function: u32,
    group: u32,
    gpio_owner: bool,
    mux_owner: bool,
};

pub const PinctlGpioRange = struct {
    name: [64]u8,
    id: u32,
    base: u32,     // GPIO base number
    pin_base: u32,
    npins: u32,
    gc: u64,       // GPIO chip reference
};

// ============================================================================
// GPIO Framework
// ============================================================================

pub const GPIO_MAX_CHIPS: u32 = 64;
pub const GPIO_MAX_PER_CHIP: u32 = 512;
pub const GPIOLINE_FLAG_KERNEL: u64 = 1 << 0;
pub const GPIOLINE_FLAG_IS_OUT: u64 = 1 << 1;
pub const GPIOLINE_FLAG_ACTIVE_LOW: u64 = 1 << 2;
pub const GPIOLINE_FLAG_OPEN_DRAIN: u64 = 1 << 3;
pub const GPIOLINE_FLAG_OPEN_SOURCE: u64 = 1 << 4;
pub const GPIOLINE_FLAG_BIAS_PULL_UP: u64 = 1 << 5;
pub const GPIOLINE_FLAG_BIAS_PULL_DOWN: u64 = 1 << 6;
pub const GPIOLINE_FLAG_BIAS_DISABLE: u64 = 1 << 7;

pub const GpioChipOps = struct {
    request: ?*const fn (*GpioChip, u32) i32,
    free: ?*const fn (*GpioChip, u32) void,
    get_direction: ?*const fn (*GpioChip, u32) i32,
    direction_input: ?*const fn (*GpioChip, u32) i32,
    direction_output: ?*const fn (*GpioChip, u32, i32) i32,
    get: ?*const fn (*GpioChip, u32) i32,
    get_multiple: ?*const fn (*GpioChip, [*]const u64, [*]u64) i32,
    set: ?*const fn (*GpioChip, u32, i32) void,
    set_multiple: ?*const fn (*GpioChip, [*]const u64, [*]const u64) void,
    set_config: ?*const fn (*GpioChip, u32, u64) i32,
    to_irq: ?*const fn (*GpioChip, u32) i32,
    init_valid_mask: ?*const fn (*GpioChip, [*]u64, u32) i32,
    add_pin_ranges: ?*const fn (*GpioChip) i32,
};

pub const GpioChip = struct {
    label: [64]u8,
    label_len: u8,
    ops: *const GpioChipOps,
    base: i32,
    ngpio: u32,
    // State
    requested: [GPIO_MAX_PER_CHIP / 64]u64,  // Bitmap
    direction: [GPIO_MAX_PER_CHIP / 64]u64,  // 0=in, 1=out
    value: [GPIO_MAX_PER_CHIP / 64]u64,      // Current values
    // IRQ
    irq_chip: ?*GpioIrqChip,
    irq_valid: [GPIO_MAX_PER_CHIP / 64]u64,
    // Names
    names: [GPIO_MAX_PER_CHIP][32]u8,
    // Pinctrl mapping
    pinctrl_dev: ?*PinctlDev,

    pub fn is_requested(self: *const GpioChip, offset: u32) bool {
        if (offset >= self.ngpio) return false;
        const word = offset / 64;
        const bit: u6 = @intCast(offset % 64);
        return (self.requested[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn get_value(self: *const GpioChip, offset: u32) ?bool {
        if (offset >= self.ngpio) return null;
        const word = offset / 64;
        const bit: u6 = @intCast(offset % 64);
        return (self.value[word] & (@as(u64, 1) << bit)) != 0;
    }

    pub fn count_requested(self: *const GpioChip) u32 {
        var count: u32 = 0;
        const words = (self.ngpio + 63) / 64;
        for (self.requested[0..words]) |word| {
            count += @popCount(word);
        }
        return count;
    }
};

pub const GpioIrqChip = struct {
    chip_name: [32]u8,
    irq_enable: ?*const fn (u32) void,
    irq_disable: ?*const fn (u32) void,
    irq_ack: ?*const fn (u32) void,
    irq_mask: ?*const fn (u32) void,
    irq_unmask: ?*const fn (u32) void,
    irq_set_type: ?*const fn (u32, u32) i32,
    irq_set_wake: ?*const fn (u32, bool) i32,
    // IRQ type flags
    handler: u32,        // IRQ_TYPE_*
    threaded: bool,
    parent_handler: ?*const fn () void,
    parent_domain: u64,
    // Per-line type
    irq_types: [GPIO_MAX_PER_CHIP]u8,
};

// ============================================================================
// IIO (Industrial I/O) Framework
// ============================================================================

pub const IIO_MAX_CHANNELS: u32 = 64;

pub const IioChannelType = enum(u8) {
    voltage = 0,
    current = 1,
    power = 2,
    accel = 3,
    angl_vel = 4,
    magn = 5,
    light = 6,
    intensity = 7,
    proximity = 8,
    temp = 9,
    incli = 10,
    rot = 11,
    angl = 12,
    timestamp = 13,
    capacitance = 14,
    altvoltage = 15,
    cct = 16,
    pressure = 17,
    humidityrelative = 18,
    activity = 19,
    steps = 20,
    energy = 21,
    distance = 22,
    velocity = 23,
    concentration = 24,
    resistance = 25,
    ph = 26,
    uvindex = 27,
    electricalconductivity = 28,
    count = 29,
    index = 30,
    gravity = 31,
    positionrelative = 32,
    phase = 33,
    massconcentration = 34,
};

pub const IioChanInfoEnum = enum(u8) {
    raw = 0,
    processed = 1,
    scale = 2,
    offset = 3,
    calibscale = 4,
    calibbias = 5,
    peak = 6,
    peak_scale = 7,
    quadrature_correction_raw = 8,
    average_raw = 9,
    low_pass_filter_3db_frequency = 10,
    high_pass_filter_3db_frequency = 11,
    samp_freq = 12,
    frequency = 13,
    phase = 14,
    hardwaregain = 15,
    hysteresis = 16,
    hysteresis_relative = 17,
    int_time = 18,
    enable = 19,
    calibheight = 20,
    calibweight = 21,
    debounce_count = 22,
    debounce_time = 23,
    oversampling_ratio = 24,
    thermocouple_type = 25,
    calibemissivity = 26,
};

pub const IioChanSpec = struct {
    chan_type: IioChannelType,
    channel: i32,
    channel2: i32,
    address: u64,
    scan_index: i32,
    scan_type: IioScanType,
    info_mask_separate: u64,
    info_mask_shared_by_type: u64,
    info_mask_shared_by_dir: u64,
    info_mask_shared_by_all: u64,
    modified: bool,
    indexed: bool,
    output: bool,
    differential: bool,
    extend_name: [32]u8,
    extend_name_len: u8,
};

pub const IioScanType = struct {
    sign: u8,     // 's' or 'u'
    realbits: u8,
    storagebits: u8,
    shift: u8,
    repeat: u8,
    endianness: u8, // 'l' or 'b'
};

pub const IioDevOps = struct {
    read_raw: ?*const fn (*IioDev, *IioChanSpec, *i32, *i32, i64) i32,
    read_raw_multi: ?*const fn (*IioDev, *IioChanSpec, i32, [*]i32, *i32, i64) i32,
    write_raw: ?*const fn (*IioDev, *IioChanSpec, i32, i32, i64) i32,
    read_avail: ?*const fn (*IioDev, *IioChanSpec, [*]*const i32, *i32, *i32, i64) i32,
    validate_trigger: ?*const fn (*IioDev, *IioTrigger) i32,
    update_scan_mode: ?*const fn (*IioDev, [*]const u64) i32,
    debugfs_reg_access: ?*const fn (*IioDev, u32, u32, *u32) i32,
    of_xlate: ?*const fn (*IioDev, u64) i32,
    hwfifo_set_watermark: ?*const fn (*IioDev, u32) i32,
    hwfifo_flush_to_buffer: ?*const fn (*IioDev) i32,
};

pub const IioDev = struct {
    name: [64]u8,
    name_len: u8,
    id: u32,
    modes: u32,
    channels: [IIO_MAX_CHANNELS]IioChanSpec,
    nr_channels: u32,
    ops: *const IioDevOps,
    // Buffer
    buffer_enabled: bool,
    scan_mask: [IIO_MAX_CHANNELS / 64]u64,
    scan_timestamp: bool,
    // Trigger
    trigger: ?*IioTrigger,
    // Current
    current_mode: u32,
};

pub const IioTrigger = struct {
    name: [64]u8,
    name_len: u8,
    id: u32,
    ops: ?*const IioTriggerOps,
    use_count: u32,
};

pub const IioTriggerOps = struct {
    set_trigger_state: ?*const fn (*IioTrigger, bool) i32,
    try_reenable: ?*const fn (*IioTrigger) i32,
    validate_device: ?*const fn (*IioTrigger, *IioDev) i32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const SoCFramework = struct {
    // Clocks
    clocks: [CLK_MAX_CLOCKS]?*ClkCore,
    nr_clocks: u32,

    // Regulators
    regulators: [REG_MAX_REGULATORS]?*RegulatorDev,
    nr_regulators: u32,

    // Pin controllers
    pinctrl_devs: [32]?*PinctlDev,
    nr_pinctrl: u32,

    // GPIO chips
    gpio_chips: [GPIO_MAX_CHIPS]?*GpioChip,
    nr_gpio_chips: u32,

    // IIO devices
    iio_devs: [32]?*IioDev,
    nr_iio: u32,

    initialized: bool,

    pub fn find_clock_by_name(self: *const SoCFramework, name: []const u8) ?*ClkCore {
        for (self.clocks[0..self.nr_clocks]) |maybe_clk| {
            if (maybe_clk) |clk| {
                if (std.mem.eql(u8, clk.name[0..clk.name_len], name)) {
                    return clk;
                }
            }
        }
        return null;
    }

    pub fn find_regulator_by_name(self: *const SoCFramework, name: []const u8) ?*RegulatorDev {
        for (self.regulators[0..self.nr_regulators]) |maybe_reg| {
            if (maybe_reg) |reg| {
                if (std.mem.eql(u8, reg.desc.name[0..reg.desc.name_len], name)) {
                    return reg;
                }
            }
        }
        return null;
    }
};
