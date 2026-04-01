// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Hardware Monitoring and Sensor Subsystem
// hwmon framework, thermal sensors, voltage/current/power monitoring,
// fan control, PMBus, ACPI thermal, cooling devices, IIO integration
// More advanced than Linux 2026 hwmon subsystem

const std = @import("std");

// ============================================================================
// Sensor Types
// ============================================================================

pub const SensorType = enum(u8) {
    temperature = 0,
    voltage = 1,
    current = 2,
    power = 3,
    energy = 4,
    humidity = 5,
    fan_speed = 6,
    pwm = 7,
    intrusion = 8,
    // IIO types
    acceleration = 10,
    angular_velocity = 11,
    magnetic_field = 12,
    pressure = 13,
    light = 14,
    proximity = 15,
    // Zxyphor
    zxy_efficiency = 30,
    zxy_thermal_flux = 31,
};

pub const SensorAttribute = enum(u8) {
    input = 0,        // Current value
    min = 1,
    max = 2,
    crit = 3,         // Critical threshold
    crit_hyst = 4,    // Critical hysteresis
    lcrit = 5,        // Lower critical
    emergency = 6,
    average = 7,
    lowest = 8,
    highest = 9,
    label = 10,
    enable = 11,
    alarm = 12,
    fault = 13,
    offset = 14,
    rated_min = 15,
    rated_max = 16,
    // Fan specific
    target = 20,
    div = 21,
    pulses = 22,
    // PWM specific
    pwm_mode = 30,
    pwm_enable = 31,
    pwm_freq = 32,
    auto_point = 33,
};

// ============================================================================
// Temperature Sensor
// ============================================================================

pub const TempSensorType = enum(u8) {
    disabled = 0,
    cpu_diode = 1,
    transistor = 2,
    thermal_diode = 3,
    thermistor = 4,
    amd_amdsi = 5,
    intel_peci = 6,
    // Digital sensors
    i2c_lm75 = 10,
    i2c_lm90 = 11,
    i2c_tmp102 = 12,
    i2c_adt7410 = 13,
    i2c_max31790 = 14,
    spi_max31855 = 15,
    spi_max6675 = 16,
    // SoC internal
    soc_tsensor = 20,
    pch_thermal = 21,
    acpi_thermal_zone = 22,
};

pub const TempReading = struct {
    value_millic: i32,       // millidegrees Celsius
    min_millic: i32,
    max_millic: i32,
    crit_millic: i32,
    crit_hyst_millic: i32,
    emergency_millic: i32,
    lcrit_millic: i32,
    // Historical
    lowest_millic: i32,
    highest_millic: i32,
    average_millic: i32,
    // Status
    alarm: bool,
    crit_alarm: bool,
    emergency_alarm: bool,
    fault: bool,
    // Calibration
    offset_millic: i32,
    // Timestamp
    timestamp_ns: u64,

    pub fn to_celsius(self: *const TempReading) f32 {
        return @as(f32, @floatFromInt(self.value_millic)) / 1000.0;
    }

    pub fn is_critical(self: *const TempReading) bool {
        return self.value_millic >= self.crit_millic;
    }

    pub fn is_emergency(self: *const TempReading) bool {
        return self.value_millic >= self.emergency_millic;
    }
};

// ============================================================================
// Voltage Sensor
// ============================================================================

pub const VoltageReading = struct {
    value_mv: i32,           // millivolts
    min_mv: i32,
    max_mv: i32,
    lcrit_mv: i32,
    crit_mv: i32,
    average_mv: i32,
    lowest_mv: i32,
    highest_mv: i32,
    // Status
    alarm: bool,
    min_alarm: bool,
    max_alarm: bool,
    lcrit_alarm: bool,
    crit_alarm: bool,
    // Nominal
    rated_min_mv: i32,
    rated_max_mv: i32,
    label: [32]u8,
    timestamp_ns: u64,

    pub fn to_volts(self: *const VoltageReading) f32 {
        return @as(f32, @floatFromInt(self.value_mv)) / 1000.0;
    }

    pub fn in_range(self: *const VoltageReading) bool {
        return self.value_mv >= self.min_mv and self.value_mv <= self.max_mv;
    }
};

// ============================================================================
// Current Sensor
// ============================================================================

pub const CurrentReading = struct {
    value_ma: i32,           // milliamps
    min_ma: i32,
    max_ma: i32,
    lcrit_ma: i32,
    crit_ma: i32,
    average_ma: i32,
    lowest_ma: i32,
    highest_ma: i32,
    // Status
    alarm: bool,
    min_alarm: bool,
    max_alarm: bool,
    lcrit_alarm: bool,
    crit_alarm: bool,
    label: [32]u8,
    timestamp_ns: u64,

    pub fn to_amps(self: *const CurrentReading) f32 {
        return @as(f32, @floatFromInt(self.value_ma)) / 1000.0;
    }
};

// ============================================================================
// Power Sensor
// ============================================================================

pub const PowerReading = struct {
    value_uw: i64,           // microwatts
    average_uw: i64,
    min_uw: i64,
    max_uw: i64,
    crit_uw: i64,
    cap_uw: i64,             // Power cap
    // Energy
    energy_uj: u64,          // microjoules
    // Average window
    average_interval_ms: u32,
    average_min_ms: u32,
    average_max_ms: u32,
    // Accuracy
    accuracy_ppm: u32,       // parts per million
    // Status
    alarm: bool,
    cap_alarm: bool,
    crit_alarm: bool,
    label: [32]u8,
    timestamp_ns: u64,

    pub fn to_watts(self: *const PowerReading) f64 {
        return @as(f64, @floatFromInt(self.value_uw)) / 1000000.0;
    }

    pub fn to_joules(self: *const PowerReading) f64 {
        return @as(f64, @floatFromInt(self.energy_uj)) / 1000000.0;
    }
};

// ============================================================================
// Fan Sensor
// ============================================================================

pub const FanReading = struct {
    value_rpm: u32,
    min_rpm: u32,
    max_rpm: u32,
    target_rpm: u32,
    // Divider
    div: u32,
    pulses: u32,
    // Status
    alarm: bool,
    min_alarm: bool,
    max_alarm: bool,
    fault: bool,
    stall: bool,
    label: [32]u8,
    timestamp_ns: u64,

    pub fn is_spinning(self: *const FanReading) bool {
        return self.value_rpm > 0 and !self.fault;
    }

    pub fn pct_of_max(self: *const FanReading) u32 {
        if (self.max_rpm == 0) return 0;
        return (self.value_rpm * 100) / self.max_rpm;
    }
};

// ============================================================================
// PWM (Fan Control)
// ============================================================================

pub const PwmMode = enum(u8) {
    dc = 0,           // DC voltage control
    pwm = 1,          // PWM signal
    auto_mode = 2,    // Automatic
};

pub const PwmEnableMode = enum(u8) {
    off = 0,          // Fan full speed
    manual = 1,       // Manual PWM control
    automatic = 2,    // Automatic thermal control
    fan_curve = 3,    // Custom fan curve
    smart = 4,        // Smart control
};

pub const PwmAutoPoint = struct {
    temp_millic: i32,
    pwm: u8,          // 0-255
};

pub const PwmControl = struct {
    value: u8,         // 0-255
    mode: PwmMode,
    enable: PwmEnableMode,
    freq_hz: u32,
    min_value: u8,
    max_value: u8,
    // Fan curve
    auto_points: [12]PwmAutoPoint,
    nr_auto_points: u8,
    // Hysteresis
    temp_tolerance_millic: i32,
    // Ramp
    ramp_rate: u8,
    // Status
    label: [32]u8,

    pub fn duty_cycle_pct(self: *const PwmControl) u32 {
        return (@as(u32, self.value) * 100) / 255;
    }
};

// ============================================================================
// Thermal Zone (ACPI Thermal)
// ============================================================================

pub const ThermalTripType = enum(u8) {
    active = 0,
    passive = 1,
    hot = 2,
    critical = 3,
    // Zxyphor
    zxy_predictive = 10,
};

pub const ThermalTripPoint = struct {
    trip_type: ThermalTripType,
    temperature_millic: i32,
    hysteresis_millic: i32,
    // Active cooling
    cooling_device_id: u32,
    cooling_level: u32,
};

pub const ThermalGovernor = enum(u8) {
    step_wise = 0,
    fair_share = 1,
    bang_bang = 2,
    user_space = 3,
    power_allocator = 4,
    // Zxyphor
    zxy_ml_thermal = 10,
};

pub const ThermalZone = struct {
    id: u32,
    zone_type: [64]u8,
    // Current temperature
    temp_millic: i32,
    last_temp_millic: i32,
    // Polling
    polling_delay_ms: u32,
    passive_delay_ms: u32,
    // Trip points
    trips: [16]ThermalTripPoint,
    nr_trips: u8,
    // Governor
    governor: ThermalGovernor,
    // Policy
    mode_enabled: bool,
    // Emulation
    emul_temp_millic: i32,
    // Cooling
    cooling_devices: [8]u32,
    nr_cooling_devices: u8,
    // Stats
    passive_count: u64,
    active_count: u64,
    hot_count: u64,
    critical_count: u64,
    // Timestamp
    last_update_ns: u64,

    pub fn is_overheating(self: *const ThermalZone) bool {
        for (self.trips[0..self.nr_trips]) |trip| {
            if (trip.trip_type == .hot or trip.trip_type == .critical) {
                if (self.temp_millic >= trip.temperature_millic) return true;
            }
        }
        return false;
    }

    pub fn headroom_millic(self: *const ThermalZone) i32 {
        var min_crit: i32 = 200000; // 200°C
        for (self.trips[0..self.nr_trips]) |trip| {
            if (trip.trip_type == .critical) {
                if (trip.temperature_millic < min_crit) {
                    min_crit = trip.temperature_millic;
                }
            }
        }
        return min_crit - self.temp_millic;
    }
};

// ============================================================================
// Cooling Device
// ============================================================================

pub const CoolingDeviceType = enum(u8) {
    fan = 0,
    processor = 1,     // CPU frequency throttling
    lcd_brightness = 2,
    cpufreq = 3,
    devfreq = 4,
    // Zxyphor
    zxy_liquid_cooling = 10,
    zxy_peltier = 11,
};

pub const CoolingDevice = struct {
    id: u32,
    device_type: CoolingDeviceType,
    name: [64]u8,
    // Cooling state
    cur_state: u32,
    max_state: u32,
    min_state: u32,
    // Stats
    total_trans_count: u64,
    time_in_state: [32]u64,  // Time in each state (ns)
    // Power
    power_uw: u64,
    max_power_uw: u64,
    min_power_uw: u64,

    pub fn cooling_pct(self: *const CoolingDevice) u32 {
        if (self.max_state == 0) return 0;
        return (self.cur_state * 100) / self.max_state;
    }
};

// ============================================================================
// PMBus (Power Management Bus)
// ============================================================================

pub const PmbusCommand = enum(u8) {
    page = 0x00,
    operation = 0x01,
    on_off_config = 0x02,
    clear_faults = 0x03,
    phase = 0x04,
    write_protect = 0x10,
    capability = 0x19,
    vout_mode = 0x20,
    vout_command = 0x21,
    vout_max = 0x24,
    vout_margin_high = 0x25,
    vout_margin_low = 0x26,
    vout_ov_fault_limit = 0x40,
    vout_ov_warn_limit = 0x42,
    vout_uv_warn_limit = 0x43,
    vout_uv_fault_limit = 0x44,
    iout_oc_fault_limit = 0x46,
    iout_oc_warn_limit = 0x4A,
    ot_fault_limit = 0x4F,
    ot_warn_limit = 0x51,
    status_byte = 0x78,
    status_word = 0x79,
    status_vout = 0x7A,
    status_iout = 0x7B,
    status_input = 0x7C,
    status_temperature = 0x7D,
    status_cml = 0x7E,
    status_fans_1_2 = 0x81,
    read_vin = 0x88,
    read_iin = 0x89,
    read_vout = 0x8B,
    read_iout = 0x8C,
    read_temperature_1 = 0x8D,
    read_temperature_2 = 0x8E,
    read_fan_speed_1 = 0x90,
    read_pout = 0x96,
    read_pin = 0x97,
    pmbus_revision = 0x98,
    mfr_id = 0x99,
    mfr_model = 0x9A,
    mfr_revision = 0x9B,
};

pub const PmbusDevice = struct {
    i2c_addr: u8,
    i2c_bus: u8,
    name: [64]u8,
    // Capabilities
    max_pages: u8,
    has_vout: bool,
    has_iout: bool,
    has_pin: bool,
    has_pout: bool,
    has_fan: bool,
    has_temp: bool,
    // VReg settings
    vout_mode: u8,
    vout_exponent: i8,
    // Status
    status_word: u16,
    // Readings
    vin_mv: i32,
    vout_mv: i32,
    iin_ma: i32,
    iout_ma: i32,
    pin_uw: i64,
    pout_uw: i64,
    temp1_millic: i32,
    temp2_millic: i32,
    fan1_rpm: u32,
    // Efficiency
    efficiency_pct: u8,
};

// ============================================================================
// Intel RAPL (Running Average Power Limit)
// ============================================================================

pub const RaplDomain = enum(u8) {
    package = 0,
    cores = 1,
    uncore = 2,
    dram = 3,
    gt = 4,           // GPU
    psys = 5,         // Platform
    // Zxyphor
    zxy_accelerator = 10,
};

pub const RaplConstraint = struct {
    power_limit_uw: u64,
    time_window_us: u64,
    max_power_uw: u64,
    min_power_uw: u64,
    max_time_window_us: u64,
    min_time_window_us: u64,
    enabled: bool,
    clamping: bool,
    lock: bool,
};

pub const RaplDomainInfo = struct {
    domain: RaplDomain,
    name: [32]u8,
    // Energy counter
    energy_uj: u64,
    max_energy_uj: u64,
    energy_unit_uj: f64,
    // Power limits
    constraints: [2]RaplConstraint,
    nr_constraints: u8,
    // Info
    thermal_spec_power_uw: u64,
    max_power_uw: u64,
    min_power_uw: u64,
    // Stats
    throttle_count: u64,
    throttle_time_us: u64,
};

// ============================================================================
// ACPI Battery
// ============================================================================

pub const BatteryTechnology = enum(u8) {
    nonrechargeable = 0,
    rechargeable = 1,
};

pub const BatteryChemistry = enum(u8) {
    unknown = 0,
    nicd = 1,
    nimh = 2,
    lion = 3,
    lipo = 4,
    lifepo4 = 5,
    lead_acid = 6,
    // Zxyphor
    zxy_solid_state = 10,
};

pub const BatteryStatus = enum(u8) {
    unknown = 0,
    charging = 1,
    discharging = 2,
    not_charging = 3,
    full = 4,
};

pub const BatteryInfo = struct {
    // Identity
    manufacturer: [64]u8,
    model: [64]u8,
    serial: [32]u8,
    technology: BatteryTechnology,
    chemistry: BatteryChemistry,
    // Status
    status: BatteryStatus,
    present: bool,
    // Capacity
    design_capacity_uah: u32,
    last_full_capacity_uah: u32,
    remaining_capacity_uah: u32,
    capacity_pct: u8,
    capacity_level: u8,
    // Voltage
    design_voltage_uv: u32,
    voltage_now_uv: u32,
    voltage_min_uv: u32,
    voltage_max_uv: u32,
    // Current
    current_now_ua: i32,
    current_avg_ua: i32,
    // Power
    power_now_uw: i32,
    power_avg_uw: i32,
    // Energy
    energy_now_uwh: u32,
    energy_full_uwh: u32,
    energy_full_design_uwh: u32,
    // Temperature
    temp_millic: i32,
    temp_alert_min: i32,
    temp_alert_max: i32,
    // Cycles
    cycle_count: u32,
    // Time
    time_to_empty_min: u32,
    time_to_full_min: u32,
    // Health
    health_pct: u8,
    // Thresholds
    charge_start_threshold: u8,
    charge_stop_threshold: u8,
    // Timestamp
    last_update_ns: u64,

    pub fn is_low(self: *const BatteryInfo) bool {
        return self.capacity_pct <= 10;
    }

    pub fn is_critical(self: *const BatteryInfo) bool {
        return self.capacity_pct <= 5;
    }

    pub fn degradation_pct(self: *const BatteryInfo) u8 {
        if (self.design_capacity_uah == 0) return 0;
        const ratio = (self.last_full_capacity_uah * 100) / self.design_capacity_uah;
        if (ratio >= 100) return 0;
        return @intCast(100 - ratio);
    }
};

// ============================================================================
// IIO (Industrial I/O) Subsystem
// ============================================================================

pub const IioChanType = enum(u8) {
    voltage = 0,
    current = 1,
    power = 2,
    accel = 3,
    angl_vel = 4,      // Angular velocity (gyroscope)
    magn = 5,           // Magnetic field
    light = 6,
    intensity = 7,
    proximity = 8,
    temp = 9,
    incli = 10,         // Inclination
    rot = 11,           // Rotation
    angl = 12,          // Angle
    timestamp = 13,
    capacitance = 14,
    altvoltage = 15,
    steps = 16,
    distance = 17,
    velocity = 18,
    concentration = 19,
    resistance = 20,
    ph = 21,
    uvindex = 22,
    gravity = 23,
    positionrelative = 24,
    phase = 25,
    massconcentration = 26,
    // Zxyphor
    zxy_radiation = 40,
    zxy_vibration = 41,
};

pub const IioModifier = enum(u8) {
    none = 0,
    x = 1,
    y = 2,
    z = 3,
    x_and_y = 4,
    x_and_z = 5,
    y_and_z = 6,
    root_sum_squared_x_y = 7,
    root_sum_squared_x_y_z = 8,
    light_uv = 20,
    light_ir = 21,
    light_clear = 22,
    light_red = 23,
    light_green = 24,
    light_blue = 25,
};

pub const IioEventType = enum(u8) {
    thresh = 0,
    mag = 1,
    roc = 2,            // Rate of change
    thresh_adaptive = 3,
    mag_adaptive = 4,
    change = 5,
    gesture = 6,
};

pub const IioEventDirection = enum(u8) {
    either = 0,
    rising = 1,
    falling = 2,
    none = 3,
    singletap = 4,
    doubletap = 5,
};

pub const IioChannel = struct {
    chan_type: IioChanType,
    modifier: IioModifier,
    channel_num: u16,
    indexed: bool,
    differential: bool,
    // Scan
    scan_index: u16,
    scan_type_bits: u8,
    scan_type_storagebits: u8,
    scan_type_shift: u8,
    scan_type_endian: u8,   // 0=LE, 1=BE
    scan_type_signed: bool,
    // Scale/offset
    scale: i64,         // Fixed point
    scale_type: u8,     // 0=int, 1=fractional_log2
    offset: i64,
    // Info
    label: [32]u8,
    // Events
    event_count: u32,
};

pub const IioDevice = struct {
    id: u32,
    name: [64]u8,
    label: [32]u8,
    // Channels
    channels: [32]IioChannel,
    nr_channels: u8,
    // Trigger
    current_trigger: [64]u8,
    // Buffer
    buffer_enabled: bool,
    buffer_length: u32,
    buffer_watermark: u32,
    // Sampling
    sampling_frequency_hz: u32,
    sampling_frequency_available: [8]u32,
    // Power
    power_state: u8,
    // Stats
    samples_read: u64,
    buffer_overruns: u64,
};

// ============================================================================
// Hwmon Device
// ============================================================================

pub const HwmonChipType = enum(u16) {
    generic = 0,
    // Common sensor chips
    lm75 = 1,
    lm78 = 2,
    lm85 = 3,
    lm87 = 4,
    lm90 = 5,
    lm92 = 6,
    lm95234 = 7,
    w83627hf = 10,
    w83795 = 11,
    it8728f = 20,
    it8790e = 21,
    nct6775 = 30,
    nct6776 = 31,
    nct6779 = 32,
    nct6791 = 33,
    nct6795 = 34,
    nct6796 = 35,
    nct6798 = 36,
    // AMD
    k10temp = 40,
    k8temp = 41,
    zenpower = 42,
    amdgpu = 43,
    // Intel
    coretemp = 50,
    pch_thermal = 51,
    // ASICs
    ina219 = 60,
    ina226 = 61,
    ina3221 = 62,
    adt7475 = 70,
    max6697 = 71,
    tmp102 = 72,
    tmp401 = 73,
    // VRM
    ir35221 = 80,
    ir38064 = 81,
    isl68137 = 82,
    mp2975 = 83,
    tps53679 = 84,
    xdpe12284 = 85,
    // GPU
    nvidia_gpu = 90,
    amd_gpu = 91,
    // Zxyphor
    zxy_sensor = 100,
};

pub const HwmonDevice = struct {
    id: u32,
    name: [64]u8,
    chip_type: HwmonChipType,
    // Bus info
    bus_type: u8,       // 0=PCI, 1=I2C, 2=ISA, 3=SPI, 4=platform
    bus_id: u16,
    bus_addr: u16,
    // Temperatures
    temp: [16]TempReading,
    nr_temp: u8,
    temp_types: [16]TempSensorType,
    // Voltages
    voltage_in: [16]VoltageReading,
    nr_voltage_in: u8,
    // Currents
    current: [8]CurrentReading,
    nr_current: u8,
    // Power
    power: [8]PowerReading,
    nr_power: u8,
    // Fans
    fan: [8]FanReading,
    nr_fan: u8,
    // PWM
    pwm: [8]PwmControl,
    nr_pwm: u8,
    // Intrusion
    intrusion_alarm: [2]bool,
    nr_intrusion: u8,
    // Beep enable
    beep_enable: bool,
    // Update interval
    update_interval_ms: u32,
    // Stats
    read_count: u64,
    error_count: u64,
    last_update_ns: u64,

    pub fn max_temp_millic(self: *const HwmonDevice) i32 {
        var max: i32 = -273000; // Absolute zero
        for (self.temp[0..self.nr_temp]) |t| {
            if (t.value_millic > max) max = t.value_millic;
        }
        return max;
    }

    pub fn total_power_uw(self: *const HwmonDevice) i64 {
        var total: i64 = 0;
        for (self.power[0..self.nr_power]) |p| {
            total += p.value_uw;
        }
        return total;
    }

    pub fn all_fans_ok(self: *const HwmonDevice) bool {
        for (self.fan[0..self.nr_fan]) |f| {
            if (f.fault or f.stall) return false;
        }
        return true;
    }
};

// ============================================================================
// System Monitoring Aggregator
// ============================================================================

pub const SystemThermalState = enum(u8) {
    normal = 0,
    warm = 1,
    throttling = 2,
    critical = 3,
    emergency = 4,
    shutdown_imminent = 5,
};

pub const HwmonSubsystem = struct {
    // Devices
    nr_hwmon_devices: u32,
    nr_thermal_zones: u32,
    nr_cooling_devices: u32,
    nr_rapl_domains: u32,
    nr_iio_devices: u32,
    nr_pmbus_devices: u32,
    // Battery
    nr_batteries: u32,
    ac_online: bool,
    // System state
    system_thermal_state: SystemThermalState,
    system_max_temp_millic: i32,
    system_avg_temp_millic: i32,
    system_total_power_uw: i64,
    // RAPL
    package_power_uw: i64,
    cpu_power_uw: i64,
    dram_power_uw: i64,
    gpu_power_uw: i64,
    // Alerts
    nr_temp_alerts: u32,
    nr_voltage_alerts: u32,
    nr_fan_alerts: u32,
    nr_power_alerts: u32,
    // Stats
    total_reads: u64,
    total_errors: u64,
    thermal_throttle_count: u64,
    thermal_throttle_total_us: u64,
    // Zxyphor
    zxy_predictive_cooling: bool,
    zxy_efficiency_score: u8,
    initialized: bool,
};
