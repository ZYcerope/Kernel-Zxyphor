// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Power Supply / Battery / Charger Detail
// Power supply class, battery info, fuel gauge, charger manager,
// ACPI battery, UPower, sysfs attributes, supply chain

const std = @import("std");

// ============================================================================
// Power Supply Types
// ============================================================================

pub const PowerSupplyType = enum(u8) {
    Battery = 0,
    Ups = 1,
    Mains = 2,
    Usb = 3,
    UsbDcp = 4,       // Dedicated Charging Port
    UsbCdp = 5,       // Charging Downstream Port
    UsbAca = 6,       // Accessory Charger Adapter
    UsbTypecSource = 7,
    UsbPd = 8,        // USB Power Delivery
    UsbPdDrp = 9,     // Dual Role Port
    Apple1A = 10,
    Apple2_1A = 11,
    Apple0_5A = 12,
    Wireless = 13,
};

pub const PowerSupplyStatus = enum(u8) {
    Unknown = 0,
    Charging = 1,
    Discharging = 2,
    NotCharging = 3,
    Full = 4,
};

pub const PowerSupplyChargeBehavior = enum(u8) {
    Auto = 0,
    InhibitCharge = 1,
    ForceDischarge = 2,
};

pub const PowerSupplyHealth = enum(u8) {
    Unknown = 0,
    Good = 1,
    Overheat = 2,
    Dead = 3,
    OverVoltage = 4,
    UnspecifiedFailure = 5,
    Cold = 6,
    WatchdogTimerExpire = 7,
    SafetyTimerExpire = 8,
    OverCurrent = 9,
    CalibrationRequired = 10,
    Warm = 11,
    Cool = 12,
    Hot = 13,
    NoInput = 14,
};

pub const PowerSupplyTechnology = enum(u8) {
    Unknown = 0,
    NiMH = 1,
    LiIon = 2,
    LiPoly = 3,
    LiFe = 4,
    NiCd = 5,
    LiMnO2 = 6,
};

pub const PowerSupplyCapacity = enum(u8) {
    Full = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Critical = 4,
};

pub const PowerSupplyScope = enum(u8) {
    Unknown = 0,
    System = 1,
    Device = 2,
};

// ============================================================================
// Power Supply Properties
// ============================================================================

pub const PowerSupplyProperty = enum(u16) {
    Status = 0,
    ChargeBehavior = 1,
    ChargeType = 2,
    Health = 3,
    Present = 4,
    Online = 5,
    Authentic = 6,
    Technology = 7,
    CycleCount = 8,
    VoltageMax = 9,
    VoltageMin = 10,
    VoltageMaxDesign = 11,
    VoltageMinDesign = 12,
    VoltageNow = 13,
    VoltageAvg = 14,
    VoltageOcv = 15,
    VoltageBootMin = 16,
    CurrentMax = 17,
    CurrentNow = 18,
    CurrentAvg = 19,
    CurrentBootMin = 20,
    PowerNow = 21,
    PowerAvg = 22,
    ChargeFullDesign = 23,
    ChargeFull = 24,
    ChargeNow = 25,
    ChargeAvg = 26,
    ChargeCounter = 27,
    ConstChargeCurrentMax = 28,
    ConstChargeVoltageMax = 29,
    EnergyFullDesign = 30,
    EnergyFull = 31,
    EnergyNow = 32,
    EnergyAvg = 33,
    Capacity = 34,
    CapacityAlert_min = 35,
    CapacityAlert_max = 36,
    CapacityErrorMargin = 37,
    CapacityLevel = 38,
    Temp = 39,
    TempMax = 40,
    TempMin = 41,
    TempAlert_min = 42,
    TempAlert_max = 43,
    TempAmbient = 44,
    TempAmbientAlert_min = 45,
    TempAmbientAlert_max = 46,
    TimeToEmptyNow = 47,
    TimeToEmptyAvg = 48,
    TimeToFullNow = 49,
    TimeToFullAvg = 50,
    Type = 51,
    UsbType = 52,
    Scope = 53,
    PrechargeVoltageMax = 54,
    ChargeTerm_currentMax = 55,
    CalibrateNow = 56,
    ManufactureYear = 57,
    ManufactureMonth = 58,
    ManufactureDay = 59,
    ModelName = 60,
    Manufacturer = 61,
    SerialNumber = 62,
};

// ============================================================================
// Power Supply Core
// ============================================================================

pub const PowerSupplyDesc = struct {
    name: [64]u8,
    supply_type: PowerSupplyType,
    properties: [64]PowerSupplyProperty,
    num_properties: u32,
    // Callbacks
    get_property: u64,
    set_property: u64,
    property_is_writeable: u64,
    external_power_changed: u64,
    set_charged: u64,
    // USB type
    usb_types: [16]PowerSupplyType,
    num_usb_types: u32,
};

pub const PowerSupplyConfig = struct {
    drv_data: u64,
    attr_grp: u64,
    fwnode: u64,
    supplied_to: [16][64]u8,     // names of supplicants
    num_supplicants: u32,
};

pub const PowerSupplyDevice = struct {
    desc: PowerSupplyDesc,
    config: PowerSupplyConfig,
    // State cache
    status_cache: PowerSupplyStatus,
    health_cache: PowerSupplyHealth,
    technology_cache: PowerSupplyTechnology,
    // Cached values (µV, µA, µAh, µWh, °C*10)
    voltage_now_uv: i32,
    voltage_avg_uv: i32,
    voltage_max_uv: i32,
    voltage_min_uv: i32,
    current_now_ua: i32,
    current_avg_ua: i32,
    current_max_ua: i32,
    power_now_uw: i32,
    power_avg_uw: i32,
    charge_full_design_uah: i32,
    charge_full_uah: i32,
    charge_now_uah: i32,
    energy_full_design_uwh: i32,
    energy_full_uwh: i32,
    energy_now_uwh: i32,
    capacity_pct: u8,
    capacity_level: PowerSupplyCapacity,
    temp_tenths_c: i16,
    temp_max_tenths_c: i16,
    temp_min_tenths_c: i16,
    cycle_count: u32,
    time_to_empty_sec: u32,
    time_to_full_sec: u32,
    present: bool,
    online: bool,
    // Device info
    model_name: [32]u8,
    manufacturer: [32]u8,
    serial_number: [32]u8,
    // sysfs
    registered: bool,
};

// ============================================================================
// Battery Management (Fuel Gauge)
// ============================================================================

pub const FuelGaugeAlgorithm = enum(u8) {
    CoulombCounting = 0,
    VoltageBasedOcv = 1,
    Impedance = 2,
    ModelBased = 3,
    Hybrid = 4,
};

pub const BatteryProfile = struct {
    // Design values
    design_capacity_mah: u32,
    design_voltage_mv: u32,
    min_voltage_mv: u32,
    max_voltage_mv: u32,
    // Charge parameters
    fast_charge_current_ma: u32,
    fast_charge_voltage_mv: u32,
    trickle_charge_current_ma: u32,
    precharge_current_ma: u32,
    precharge_voltage_mv: u32,
    termination_current_ma: u32,
    // Temperature limits (°C)
    temp_charge_min: i8,
    temp_charge_max: i8,
    temp_discharge_min: i8,
    temp_discharge_max: i8,
    // OCV table (SOC vs OCV)
    ocv_table: [101]u16,     // mV for 0-100% SOC
    // Cycle info
    design_cycle_count: u32,
    // Impedance
    internal_resistance_mohm: u16,
    // Chemistry
    technology: PowerSupplyTechnology,
};

// ============================================================================
// Charger Manager
// ============================================================================

pub const ChargerState = enum(u8) {
    Disconnected = 0,
    Connected = 1,
    PreCharge = 2,
    FastChargeCC = 3,  // Constant Current
    FastChargeCV = 4,  // Constant Voltage
    TopOff = 5,
    Done = 6,
    Fault = 7,
    TimerExpired = 8,
};

pub const ChargerType = enum(u8) {
    Unknown = 0,
    SdpUsb = 1,         // Standard Downstream Port (500mA)
    DcpCharger = 2,     // Dedicated Charging Port
    CdpCharger = 3,     // Charging Downstream Port
    TypeC_1_5A = 4,
    TypeC_3_0A = 5,
    PdCharger = 6,
    WirelessQi = 7,
    WirelessPma = 8,
    DcBarrel = 9,
};

pub const ChargerManager = struct {
    state: ChargerState,
    charger_type: ChargerType,
    // Input
    input_voltage_mv: u32,
    input_current_limit_ma: u32,
    // Regulation
    charge_voltage_mv: u32,
    charge_current_ma: u32,
    // Timers
    charge_timer_sec: u32,
    safety_timer_sec: u32,
    // Thermal
    temp_throttle_active: bool,
    thermal_zone: [32]u8,
    // Stats
    total_charge_cycles: u32,
    total_energy_delivered_mwh: u64,
};

// ============================================================================
// ACPI Battery (/proc/acpi/battery or /sys/class/power_supply/)
// ============================================================================

pub const AcpiBatteryInfo = struct {
    // _BIF / _BIX
    power_unit: AcpiBatUnit,
    design_capacity: u32,      // mAh or mWh
    last_full_capacity: u32,
    battery_technology: u8,    // 0=primary, 1=secondary
    design_voltage: u32,       // mV
    design_capacity_warning: u32,
    design_capacity_low: u32,
    cycle_count: u32,
    measurement_accuracy: u32, // percentage * 1000
    max_sampling_time: u32,    // ms
    min_sampling_time: u32,
    max_averaging_interval: u32,
    min_averaging_interval: u32,
    model_number: [32]u8,
    serial_number: [32]u8,
    battery_type: [32]u8,
    oem_info: [32]u8,
    // _BST
    state: AcpiBatState,
    present_rate: u32,         // mA or mW
    remaining_capacity: u32,   // mAh or mWh
    present_voltage: u32,      // mV
};

pub const AcpiBatUnit = enum(u8) {
    Milliwatt = 0,
    Milliamp = 1,
};

pub const AcpiBatState = packed struct(u32) {
    discharging: bool = false,
    charging: bool = false,
    critical: bool = false,
    _pad: u29 = 0,
};

// ============================================================================
// Sysfs Power Supply Attributes
// ============================================================================

pub const PsySysfsAttr = enum(u8) {
    type_attr,
    status_attr,
    health_attr,
    present_attr,
    online_attr,
    authentic_attr,
    technology_attr,
    cycle_count_attr,
    voltage_max_attr,
    voltage_min_attr,
    voltage_max_design_attr,
    voltage_min_design_attr,
    voltage_now_attr,
    voltage_avg_attr,
    voltage_ocv_attr,
    current_max_attr,
    current_now_attr,
    current_avg_attr,
    power_now_attr,
    power_avg_attr,
    charge_full_design_attr,
    charge_full_attr,
    charge_now_attr,
    charge_avg_attr,
    charge_counter_attr,
    energy_full_design_attr,
    energy_full_attr,
    energy_now_attr,
    energy_avg_attr,
    capacity_attr,
    capacity_level_attr,
    temp_attr,
    temp_max_attr,
    temp_min_attr,
    time_to_empty_now_attr,
    time_to_empty_avg_attr,
    time_to_full_now_attr,
    time_to_full_avg_attr,
    model_name_attr,
    manufacturer_attr,
    serial_number_attr,
    usb_type_attr,
    charge_behaviour_attr,
    scope_attr,
};

// ============================================================================
// Power Supply Chain (supply graph)
// ============================================================================

pub const SupplyChainNode = struct {
    supply_name: [64]u8,
    supplicant_names: [8][64]u8,
    num_supplicants: u32,
    // Parent supply
    parent: ?*SupplyChainNode,
    // Supply type
    supply_type: PowerSupplyType,
    online: bool,
};

// ============================================================================
// Power Supply Subsystem Manager
// ============================================================================

pub const PowerSupplyManager = struct {
    total_supplies: u32,
    total_batteries: u32,
    total_chargers: u32,
    total_uevent_notifications: u64,
    total_property_reads: u64,
    total_property_writes: u64,
    initialized: bool,

    pub fn init() PowerSupplyManager {
        return .{
            .total_supplies = 0,
            .total_batteries = 0,
            .total_chargers = 0,
            .total_uevent_notifications = 0,
            .total_property_reads = 0,
            .total_property_writes = 0,
            .initialized = true,
        };
    }
};
