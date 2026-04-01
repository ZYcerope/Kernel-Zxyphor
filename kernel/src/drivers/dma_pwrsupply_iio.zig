// SPDX-License-Identifier: MIT
// Zxyphor Kernel - DMA Controller, Power Supply, Pin Control,
// Industrial I/O (IIO), Clock Framework, Remoteproc/RPMsg
// More advanced than Linux 2026 device subsystem

const std = @import("std");

// ============================================================================
// DMA Controller Framework
// ============================================================================

/// DMA transfer direction
pub const DmaTransferDir = enum(u8) {
    mem_to_mem = 0,
    mem_to_dev = 1,
    dev_to_mem = 2,
    dev_to_dev = 3,
};

/// DMA transfer type
pub const DmaTransferType = enum(u8) {
    single = 0,          // Single transfer
    cyclic = 1,          // Cyclic (circular buffer)
    scatter_gather = 2,  // Scatter-gather
    interleaved = 3,     // Interleaved
    // Zxyphor
    zxy_adaptive = 10,
};

/// DMA channel status
pub const DmaChanStatus = enum(u8) {
    idle = 0,
    running = 1,
    paused = 2,
    completed = 3,
    error_state = 4,
    terminated = 5,
};

/// DMA slave config
pub const DmaSlaveConfig = struct {
    direction: DmaTransferDir,
    // Source
    src_addr: u64,
    src_addr_width: DmaAddrWidth,
    src_maxburst: u32,
    src_port_window_size: u32,
    // Destination
    dst_addr: u64,
    dst_addr_width: DmaAddrWidth,
    dst_maxburst: u32,
    dst_port_window_size: u32,
    // Flow control
    device_fc: bool,
    peripheral_config: u64,
};

/// DMA address width
pub const DmaAddrWidth = enum(u8) {
    undefined = 0,
    width_1 = 1,
    width_2 = 2,
    width_3 = 3,
    width_4 = 4,
    width_8 = 8,
    width_16 = 16,
    width_32 = 32,
    width_64 = 64,
};

/// DMA controller capabilities
pub const DmaCaps = packed struct {
    mem_to_mem: bool = false,
    mem_to_dev: bool = false,
    dev_to_mem: bool = false,
    dev_to_dev: bool = false,
    cyclic: bool = false,
    scatter_gather: bool = false,
    interleaved: bool = false,
    // Zxyphor
    zxy_hw_coherent: bool = false,
};

/// DMA controller descriptor
pub const DmaController = struct {
    name: [32]u8,
    nr_channels: u16,
    max_burst: u32,
    max_sg_burst: u32,
    caps: DmaCaps,
    // Stats
    total_transfers: u64,
    total_bytes: u64,
    total_errors: u64,
};

// ============================================================================
// Power Supply Framework
// ============================================================================

/// Power supply type
pub const PsupplyType = enum(u8) {
    battery = 0,
    ups = 1,
    mains = 2,
    usb = 3,
    usb_dcp = 4,
    usb_cdp = 5,
    usb_aca = 6,
    usb_type_c = 7,
    usb_pd = 8,
    usb_pd_drp = 9,
    apple_brick_id = 10,
    wireless = 11,
    // Zxyphor
    zxy_smart = 50,
};

/// Power supply status
pub const PsupplyStatus = enum(u8) {
    unknown = 0,
    charging = 1,
    discharging = 2,
    not_charging = 3,
    full = 4,
};

/// Power supply health
pub const PsupplyHealth = enum(u8) {
    unknown = 0,
    good = 1,
    overheat = 2,
    dead = 3,
    overvoltage = 4,
    unspec_failure = 5,
    cold = 6,
    watchdog_timer_expire = 7,
    safety_timer_expire = 8,
    overcurrent = 9,
    calibration_required = 10,
    warm = 11,
    cool = 12,
    hot = 13,
    no_battery = 14,
};

/// Power supply technology
pub const PsupplyTech = enum(u8) {
    unknown = 0,
    nicd = 1,
    nimh = 2,
    lion = 3,
    lipo = 4,
    life = 5,
    niznc = 6,
    lmno = 7,
};

/// Power supply property
pub const PsupplyProp = enum(u8) {
    status = 0,
    charge_type = 1,
    health = 2,
    present = 3,
    online = 4,
    authentic = 5,
    technology = 6,
    cycle_count = 7,
    voltage_max = 8,
    voltage_min = 9,
    voltage_max_design = 10,
    voltage_min_design = 11,
    voltage_now = 12,
    voltage_avg = 13,
    voltage_ocv = 14,
    voltage_boot = 15,
    current_max = 16,
    current_now = 17,
    current_avg = 18,
    current_boot = 19,
    power_now = 20,
    power_avg = 21,
    charge_full_design = 22,
    charge_empty_design = 23,
    charge_full = 24,
    charge_empty = 25,
    charge_now = 26,
    charge_avg = 27,
    charge_counter = 28,
    constant_charge_current = 29,
    constant_charge_current_max = 30,
    constant_charge_voltage = 31,
    constant_charge_voltage_max = 32,
    charge_control_limit = 33,
    charge_control_limit_max = 34,
    charge_control_start_threshold = 35,
    charge_control_end_threshold = 36,
    charge_behaviour = 37,
    input_current_limit = 38,
    input_voltage_limit = 39,
    input_power_limit = 40,
    energy_full_design = 41,
    energy_empty_design = 42,
    energy_full = 43,
    energy_empty = 44,
    energy_now = 45,
    energy_avg = 46,
    capacity = 47,
    capacity_alert_min = 48,
    capacity_alert_max = 49,
    capacity_error_margin = 50,
    capacity_level = 51,
    temp = 52,
    temp_max = 53,
    temp_min = 54,
    temp_alert_min = 55,
    temp_alert_max = 56,
    temp_ambient = 57,
    temp_ambient_alert_min = 58,
    temp_ambient_alert_max = 59,
    time_to_empty_now = 60,
    time_to_empty_avg = 61,
    time_to_full_now = 62,
    time_to_full_avg = 63,
    supply_type = 64,
    usb_type = 65,
    scope = 66,
    precharge_current = 67,
    charge_term_current = 68,
    model_name = 69,
    manufacturer = 70,
    serial_number = 71,
};

// ============================================================================
// Pin Control (pinctrl)
// ============================================================================

/// Pin config type
pub const PinConfigType = enum(u8) {
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
    mode_low_power = 15,
    mode_pwm = 16,
    output = 17,
    output_enable = 18,
    output_impedance_ohms = 19,
    power_source = 20,
    persist_state = 21,
    sleep_hardware_state = 22,
    slew_rate = 23,
    skew_delay = 24,
};

/// Pin mux function
pub const PinMuxFunc = struct {
    name: [32]u8,
    groups: [16][32]u8,
    nr_groups: u8,
};

// ============================================================================
// IIO (Industrial I/O)
// ============================================================================

/// IIO channel type
pub const IioChannelType = enum(u8) {
    voltage = 0,
    current = 1,
    power = 2,
    accel = 3,
    angl_vel = 4,        // Gyroscope
    magn = 5,            // Magnetometer
    light = 6,
    intensity = 7,
    proximity = 8,
    temp = 9,
    incli = 10,          // Inclinometer
    rot = 11,            // Rotation
    angl = 12,           // Angle
    timestamp = 13,
    capacitance = 14,
    altvoltage = 15,
    cct = 16,            // Correlated Color Temperature
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
    index_type = 30,
    gravity = 31,
    positionrelative = 32,
    phase = 33,
    massconcentration = 34,
    // Zxyphor
    zxy_composite = 50,
};

/// IIO modifier
pub const IioModifier = enum(u8) {
    none = 0,
    x = 1,
    y = 2,
    z = 3,
    x_and_y = 4,
    x_and_z = 5,
    y_and_z = 6,
    x_and_y_and_z = 7,
    sqrt_x2_y2_z2 = 8,
    light_both = 9,
    light_ir = 10,
    light_clear = 11,
    light_red = 12,
    light_green = 13,
    light_blue = 14,
    light_uv = 15,
    light_dua = 16,
    quaternion = 17,
    temp_ambient = 18,
    temp_object = 19,
    north_magn = 20,
    north_true = 21,
    north_magn_tilt_comp = 22,
    north_true_tilt_comp = 23,
    running = 24,
    jogging = 25,
    walking = 26,
    still = 27,
    root_sum_squared_x_y = 28,
    root_sum_squared_x_y_z = 29,
    i = 30,
    q = 31,
    co2 = 32,
    voc = 33,
    pm1 = 34,
    pm2p5 = 35,
    pm4 = 36,
    pm10 = 37,
    o2 = 38,
    ethanol = 39,
    h2 = 40,
};

/// IIO event type
pub const IioEventType = enum(u8) {
    thresh = 0,
    mag = 1,
    roc = 2,           // Rate of change
    thresh_adaptive = 3,
    mag_adaptive = 4,
    change = 5,
    mag_referenced = 6,
    gesture = 7,
};

/// IIO trigger
pub const IioTrigger = struct {
    name: [64]u8,
    trigger_type: IioTriggerType,
    frequency_hz: u32,
};

/// IIO trigger type
pub const IioTriggerType = enum(u8) {
    hrtimer = 0,
    sysfs = 1,
    interrupt = 2,
    // Zxyphor
    zxy_adaptive = 10,
};

// ============================================================================
// Clock Framework (Common Clock Framework)
// ============================================================================

/// Clock flags
pub const ClkFlags = packed struct {
    set_rate_gate: bool = false,
    set_parent_gate: bool = false,
    set_rate_parent: bool = false,
    ignore_unused: bool = false,
    is_basic: bool = false,
    get_rate_nocache: bool = false,
    set_rate_no_reparent: bool = false,
    get_accuracy_nocache: bool = false,
    recalc_new_rates: bool = false,
    set_rate_ungate: bool = false,
    is_critical: bool = false,
    ops_parent_enable: bool = false,
    duty_cycle_parent: bool = false,
    _padding: u3 = 0,
};

/// Clock type
pub const ClkType = enum(u8) {
    fixed_rate = 0,
    gate = 1,
    divider = 2,
    mux = 3,
    fixed_factor = 4,
    composite = 5,
    fractional_divider = 6,
    gpio = 7,
    pll = 8,
    // Zxyphor
    zxy_adaptive = 50,
};

/// Clock descriptor
pub const ClkDescriptor = struct {
    name: [64]u8,
    clk_type: ClkType,
    flags: ClkFlags,
    rate_hz: u64,
    parent_rate_hz: u64,
    num_parents: u8,
    enable_count: u32,
    prepare_count: u32,
    // Divider
    div_value: u32,
    div_max: u32,
    // Mux
    mux_index: u8,
    nr_mux_parents: u8,
};

// ============================================================================
// Remoteproc / RPMsg
// ============================================================================

/// Remote processor state
pub const RprocState = enum(u8) {
    offline = 0,
    suspended = 1,
    running = 2,
    crashed = 3,
    deleted = 4,
    attached = 5,      // Already running when probed
    detached = 6,
};

/// Remoteproc crash type
pub const RprocCrashType = enum(u8) {
    none = 0,
    mmu_fault = 1,
    hw_error = 2,
    exception = 3,
    watchdog = 4,
    fatal_error = 5,
};

/// Remoteproc resource type
pub const RprocResourceType = enum(u32) {
    carveout = 0,        // Contiguous memory
    devmem = 1,          // Device memory mapping
    trace = 2,           // Trace buffer
    vdev = 3,            // Virtio device
    last = 4,
    fw_rsc_addr_any: u32 = 0xFFFFFFFF,
};

/// RPMsg endpoint
pub const RpmsgEndpoint = struct {
    name: [32]u8,
    src_addr: u32,
    dst_addr: u32,
    // Stats
    tx_msgs: u64,
    rx_msgs: u64,
    tx_bytes: u64,
    rx_bytes: u64,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const DeviceSubsystem = struct {
    // DMA
    nr_dma_controllers: u32,
    nr_dma_channels: u32,
    total_dma_transfers: u64,
    total_dma_bytes: u64,
    // Power supply
    nr_power_supplies: u32,
    nr_batteries: u32,
    // Pin control
    nr_pinctrl: u32,
    nr_pin_groups: u32,
    // IIO
    nr_iio_devices: u32,
    nr_iio_channels: u32,
    nr_iio_triggers: u32,
    // Clocks
    nr_clocks: u32,
    nr_clock_parents: u32,
    // Remoteproc
    nr_remoteprocs: u32,
    nr_rpmsg_endpoints: u32,
    // Zxyphor
    zxy_hw_discovery_complete: bool,
    initialized: bool,

    pub fn init() DeviceSubsystem {
        return DeviceSubsystem{
            .nr_dma_controllers = 0,
            .nr_dma_channels = 0,
            .total_dma_transfers = 0,
            .total_dma_bytes = 0,
            .nr_power_supplies = 0,
            .nr_batteries = 0,
            .nr_pinctrl = 0,
            .nr_pin_groups = 0,
            .nr_iio_devices = 0,
            .nr_iio_channels = 0,
            .nr_iio_triggers = 0,
            .nr_clocks = 0,
            .nr_clock_parents = 0,
            .nr_remoteprocs = 0,
            .nr_rpmsg_endpoints = 0,
            .zxy_hw_discovery_complete = false,
            .initialized = false,
        };
    }
};
