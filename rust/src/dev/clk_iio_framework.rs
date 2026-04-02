// SPDX-License-Identifier: Apache-2.0
// Zxyphor Kernel Rust - Clock Framework and IIO/ADC Complete
// Common Clock Framework, clock tree, PLL, dividers, mux,
// IIO subsystem, ADC channels, DAC, accelerometer, gyroscope

/// Clock types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClkType {
    Fixed = 0,
    Gate = 1,
    Divider = 2,
    Mux = 3,
    FixedFactor = 4,
    Pll = 5,
    Fractional = 6,
    Composite = 7,
    Gpio = 8,
    PwmClk = 9,
}

/// Clock flags
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct ClkFlags: u64 {
        const SET_RATE_GATE = 1 << 0;
        const SET_PARENT_GATE = 1 << 1;
        const SET_RATE_PARENT = 1 << 2;
        const IGNORE_UNUSED = 1 << 3;
        const GET_RATE_NOCACHE = 1 << 6;
        const SET_RATE_NO_REPARENT = 1 << 7;
        const GET_ACCURACY_NOCACHE = 1 << 8;
        const RECALC_NEW_RATES = 1 << 9;
        const SET_RATE_UNGATE = 1 << 10;
        const IS_CRITICAL = 1 << 11;
        const OPS_PARENT_ENABLE = 1 << 12;
        const DUTY_CYCLE_PARENT = 1 << 13;
    }
}

/// Clock hardware description
#[derive(Debug, Clone)]
pub struct ClkHw {
    pub name: [u8; 64],
    pub clk_type: ClkType,
    pub flags: ClkFlags,
    pub num_parents: u32,
    pub parent_names: Vec<[u8; 64]>,
    pub init_rate: u64,
}

/// PLL parameters
#[derive(Debug, Clone)]
pub struct PllParams {
    pub ref_freq: u64,
    pub vco_min: u64,
    pub vco_max: u64,
    pub m: u32,     // pre-divider
    pub n: u32,     // multiplier
    pub p: u32,     // post-divider
    pub frac: u32,  // fractional part
    pub k: u32,     // spread spectrum
    pub lock_timeout_us: u32,
    pub pll_type: PllType,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PllType {
    Integer = 0,
    Fractional = 1,
    SpreadSpectrum = 2,
    AllDigital = 3,
    DeltaSigma = 4,
}

/// Divider clock
#[derive(Debug, Clone)]
pub struct ClkDivider {
    pub shift: u8,
    pub width: u8,
    pub reg_offset: u32,
    pub flags: DividerFlags,
    pub table: Vec<ClkDivTable>,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct DividerFlags: u32 {
        const ONE_BASED = 1 << 0;
        const POWER_OF_TWO = 1 << 1;
        const ALLOW_ZERO = 1 << 2;
        const HIWORD_MASK = 1 << 3;
        const ROUND_CLOSEST = 1 << 4;
        const READ_ONLY = 1 << 5;
        const MAX_AT_CLK_MAX = 1 << 6;
        const BIG_ENDIAN = 1 << 7;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClkDivTable {
    pub val: u32,
    pub div: u32,
}

/// Mux clock
#[derive(Debug, Clone)]
pub struct ClkMux {
    pub shift: u8,
    pub mask: u32,
    pub reg_offset: u32,
    pub flags: MuxFlags,
    pub table: Vec<u32>,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct MuxFlags: u32 {
        const INDEX_ONE = 1 << 0;
        const INDEX_BIT = 1 << 1;
        const HIWORD_MASK = 1 << 2;
        const READ_ONLY = 1 << 3;
        const ROUND_CLOSEST = 1 << 4;
        const BIG_ENDIAN = 1 << 5;
    }
}

/// Gate clock
#[derive(Debug, Clone)]
pub struct ClkGate {
    pub bit_idx: u8,
    pub reg_offset: u32,
    pub flags: GateFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct GateFlags: u32 {
        const SET_TO_DISABLE = 1 << 0;
        const HIWORD_MASK = 1 << 1;
        const BIG_ENDIAN = 1 << 2;
    }
}

/// Clock tree node
#[derive(Debug, Clone)]
pub struct ClkTreeNode {
    pub name: [u8; 64],
    pub clk_type: ClkType,
    pub rate: u64,
    pub accuracy: u64,
    pub enable_count: u32,
    pub prepare_count: u32,
    pub protect_count: u32,
    pub phase: i32,
    pub duty_num: u32,
    pub duty_den: u32,
    pub parent_idx: Option<u32>,
    pub children_count: u32,
    pub flags: ClkFlags,
    pub orphan: bool,
}

/// Clock summary stats
#[derive(Debug)]
pub struct ClkSummary {
    pub total_clocks: u32,
    pub enabled_clocks: u32,
    pub orphan_clocks: u32,
    pub critical_clocks: u32,
}

// ============================================================================
// IIO (Industrial I/O) Subsystem
// ============================================================================

/// IIO Channel Types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IioChanType {
    Voltage = 0,
    Current = 1,
    Power = 2,
    Accel = 3,
    AnglVel = 4,
    Magn = 5,
    Light = 6,
    Intensity = 7,
    Proximity = 8,
    Temp = 9,
    Incli = 10,
    Rot = 11,
    Angl = 12,
    Timestamp = 13,
    Capacitance = 14,
    AltVoltage = 15,
    Cct = 16,
    Pressure = 17,
    Humidityrelative = 18,
    Activity = 19,
    Steps = 20,
    Energy = 21,
    Distance = 22,
    Velocity = 23,
    Concentration = 24,
    Resistance = 25,
    Ph = 26,
    UvIndex = 27,
    Electrically = 28,
    Count = 29,
    Index = 30,
    Gravity = 31,
    Positionrelative = 32,
    Phase = 33,
    MassConcentration = 34,
    Delta = 35,
}

/// IIO Channel Info
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IioChanInfo {
    Raw = 0,
    Processed = 1,
    Scale = 2,
    Offset = 3,
    Calibscale = 4,
    Calibbias = 5,
    PeakScale = 6,
    Peak = 7,
    Average = 8,
    SampFreq = 9,
    Frequency = 10,
    Phase = 11,
    Hardwaregain = 12,
    Hysteresis = 13,
    OverSamplingRatio = 14,
    Thermocouple = 15,
    CalibWeight = 16,
    CalibHeight = 17,
    Debounce = 18,
    Debounce2 = 19,
    IntegrationTime = 20,
    Enable = 21,
    ZerothorderCoeff = 22,
    ToughEnable = 23,
}

/// IIO Channel Modifier
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IioChanModifier {
    None = 0,
    X = 1,
    Y = 2,
    Z = 3,
    XAndY = 4,
    XAndZ = 5,
    YAndZ = 6,
    XAndYAndZ = 7,
    Sqrt = 8,
    RootSumSquared = 9,
    Light = 10,
    Infrared = 11,
    UltraViolet = 12,
    UltraVioletA = 13,
    UltraVioletB = 14,
    ColorTemp = 15,
    Pm1 = 16,
    Pm2p5 = 17,
    Pm4 = 18,
    Pm10 = 19,
    Ethanol = 20,
    Co2 = 21,
    Voc = 22,
    Pitch = 23,
    Yaw = 24,
    Roll = 25,
}

/// IIO Channel Spec
#[derive(Debug, Clone)]
pub struct IioChanSpec {
    pub chan_type: IioChanType,
    pub channel: i32,
    pub channel2: i32,
    pub address: u64,
    pub scan_index: i32,
    pub scan_type: IioScanType,
    pub info_mask_separate: u64,
    pub info_mask_shared_by_type: u64,
    pub info_mask_shared_by_dir: u64,
    pub info_mask_shared_by_all: u64,
    pub modified: bool,
    pub indexed: bool,
    pub output: bool,
    pub differential: bool,
    pub extend_name: Option<[u8; 32]>,
}

/// IIO Scan Type
#[derive(Debug, Clone)]
pub struct IioScanType {
    pub sign: char,        // 's' or 'u'
    pub realbits: u8,
    pub storagebits: u8,
    pub shift: u8,
    pub repeat: u8,
    pub endianness: IioEndian,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioEndian {
    Little = 0,
    Big = 1,
    Cpu = 2,
}

/// IIO Device Info
#[derive(Debug, Clone)]
pub struct IioDeviceInfo {
    pub name: [u8; 64],
    pub label: [u8; 64],
    pub num_channels: u32,
    pub modes: IioDeviceModes,
    pub current_mode: IioDeviceMode,
    pub available_scan_masks: Vec<u64>,
    pub active_scan_mask: u64,
    pub masklength: u32,
    pub buffer_enabled: bool,
    pub buffer_length: u32,
    pub watermark: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioDeviceMode {
    Direct = 0,
    Buffer = 1,
    EventDriven = 2,
    HwBuffer = 3,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct IioDeviceModes: u32 {
        const DIRECT = 1 << 0;
        const BUFFER_TRIGGERED = 1 << 1;
        const BUFFER_SOFTWARE = 1 << 2;
        const BUFFER_HARDWARE = 1 << 3;
        const EVENT_DRIVEN = 1 << 4;
    }
}

/// IIO Trigger
#[derive(Debug, Clone)]
pub struct IioTrigger {
    pub name: [u8; 64],
    pub trigger_type: IioTriggerType,
    pub attached_devices: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioTriggerType {
    Sysfs = 0,
    Hrtimer = 1,
    Interrupt = 2,
    Loop = 3,
    StackedIrq = 4,
}

/// IIO Event Type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IioEventType {
    Threshold = 0,
    MagAdaptive = 1,
    Roc = 2,
    ThreshAdaptive = 3,
    Change = 4,
    MagReferenced = 5,
    Gesture = 6,
}

/// IIO Event Direction
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IioEventDirection {
    Either = 0,
    Rising = 1,
    Falling = 2,
    None = 3,
    Singletap = 4,
    Doubletap = 5,
}

/// IIO Buffer Modes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioBufferMode {
    PolledDirect = 0,
    Triggered = 1,
    DmaHw = 2,
}

/// ADC specific
#[derive(Debug, Clone)]
pub struct AdcChannelConfig {
    pub channel_num: u32,
    pub reference_voltage_mv: u32,
    pub resolution_bits: u8,
    pub sample_rate_sps: u32,
    pub averaging_samples: u32,
    pub input_range: AdcInputRange,
    pub gain: u32,
    pub conversion_time_us: u32,
    pub single_ended: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AdcInputRange {
    Unipolar = 0,
    Bipolar = 1,
    Differential = 2,
}

/// DAC specific
#[derive(Debug, Clone)]
pub struct DacChannelConfig {
    pub channel_num: u32,
    pub resolution_bits: u8,
    pub reference_voltage_mv: u32,
    pub output_range: DacOutputRange,
    pub glitch_filter: bool,
    pub powerdown_mode: DacPowerdownMode,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DacOutputRange {
    Unipolar = 0,
    Bipolar = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DacPowerdownMode {
    None = 0,
    OneKToGnd = 1,
    HundredKToGnd = 2,
    ThreeState = 3,
}

/// IMU (Inertial Measurement Unit) config
#[derive(Debug, Clone)]
pub struct ImuConfig {
    pub accel_range_g: u32,
    pub accel_odr_hz: u32,
    pub gyro_range_dps: u32,
    pub gyro_odr_hz: u32,
    pub mag_range_gauss: u32,
    pub mag_odr_hz: u32,
    pub fifo_watermark: u32,
    pub fifo_mode: FifoMode,
    pub fusion_enabled: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FifoMode {
    Bypass = 0,
    Fifo = 1,
    Stream = 2,
    StreamToFifo = 3,
    BypassToStream = 4,
    BypassToFifo = 5,
}

/// Clock & IIO Manager
#[derive(Debug)]
pub struct ClkIioManager {
    pub total_clocks: u32,
    pub total_iio_devices: u32,
    pub total_adc_channels: u32,
    pub total_dac_channels: u32,
    pub total_imu_devices: u32,
    pub total_triggers: u32,
    pub clock_tree_depth: u32,
    pub clock_summary: ClkSummary,
    pub initialized: bool,
}

impl ClkIioManager {
    pub fn new() -> Self {
        Self {
            total_clocks: 0,
            total_iio_devices: 0,
            total_adc_channels: 0,
            total_dac_channels: 0,
            total_imu_devices: 0,
            total_triggers: 0,
            clock_tree_depth: 0,
            clock_summary: ClkSummary {
                total_clocks: 0,
                enabled_clocks: 0,
                orphan_clocks: 0,
                critical_clocks: 0,
            },
            initialized: true,
        }
    }
}
