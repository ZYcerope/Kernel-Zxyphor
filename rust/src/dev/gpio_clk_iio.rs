// Zxyphor Kernel - GPIO Subsystem Framework, Pinctrl,
// Clock Framework (CCF), Reset Controller Advanced,
// IIO (Industrial I/O) Subsystem, PWM Framework
// More advanced than Linux 2026 device frameworks

use core::fmt;

// ============================================================================
// GPIO Subsystem Framework
// ============================================================================

/// GPIO direction
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioDir {
    Input = 0,
    Output = 1,
}

/// GPIO active level
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum GpioActiveLevel {
    High = 0,
    Low = 1,
}

/// GPIO line flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct GpioLineFlags(pub u64);

impl GpioLineFlags {
    pub const USED: Self = Self(1 << 0);
    pub const ACTIVE_LOW: Self = Self(1 << 1);
    pub const INPUT: Self = Self(1 << 2);
    pub const OUTPUT: Self = Self(1 << 3);
    pub const EDGE_RISING: Self = Self(1 << 4);
    pub const EDGE_FALLING: Self = Self(1 << 5);
    pub const OPEN_DRAIN: Self = Self(1 << 6);
    pub const OPEN_SOURCE: Self = Self(1 << 7);
    pub const BIAS_PULL_UP: Self = Self(1 << 8);
    pub const BIAS_PULL_DOWN: Self = Self(1 << 9);
    pub const BIAS_DISABLED: Self = Self(1 << 10);
    pub const EVENT_CLOCK_REALTIME: Self = Self(1 << 11);
    pub const EVENT_CLOCK_HTE: Self = Self(1 << 12);
    // Zxyphor extensions
    pub const ZXY_DEBOUNCE_HW: Self = Self(1 << 32);
    pub const ZXY_INTERRUPT_SAFE: Self = Self(1 << 33);
}

/// GPIO chip descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct GpioChipDesc {
    pub label: [u8; 32],
    pub label_len: u8,
    pub base: i32,
    pub ngpio: u16,
    pub can_sleep: bool,
    pub irq_chip_present: bool,
    pub irq_nested: bool,
    pub direction_input_supported: bool,
    pub direction_output_supported: bool,
    pub get_supported: bool,
    pub set_supported: bool,
    pub set_config_supported: bool,
    pub parent_irq_chip: u32,
    pub parent_handler: u64,
    pub owner_module: u32,
}

/// GPIO event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GpioLineEvent {
    pub timestamp_ns: u64,
    pub id: GpioEventId,
    pub offset: u32,
    pub seqno: u32,
    pub line_seqno: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum GpioEventId {
    RisingEdge = 1,
    FallingEdge = 2,
}

/// GPIO lookup table entry
#[repr(C)]
#[derive(Debug, Clone)]
pub struct GpioLookup {
    pub provider: [u8; 32],
    pub provider_len: u8,
    pub chip_hwnum: u16,
    pub con_id: [u8; 32],
    pub con_id_len: u8,
    pub idx: u32,
    pub flags: GpioLookupFlags,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct GpioLookupFlags(pub u32);

impl GpioLookupFlags {
    pub const ACTIVE_LOW: Self = Self(1 << 0);
    pub const OPEN_DRAIN: Self = Self(1 << 1);
    pub const OPEN_SOURCE: Self = Self(1 << 2);
    pub const TRANSITORY: Self = Self(1 << 3);
    pub const PULL_UP: Self = Self(1 << 4);
    pub const PULL_DOWN: Self = Self(1 << 5);
    pub const PULL_DISABLE: Self = Self(1 << 6);
}

// ============================================================================
// Pin Control Subsystem
// ============================================================================

/// Pin function type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PinFuncType {
    Gpio = 0,
    Function = 1,
    Special = 2,
}

/// Pin configuration parameter
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PinConfigParam {
    BiasDefault = 0,
    BiasDisable = 1,
    BiasBusHold = 2,
    BiasPullDown = 3,
    BiasPullPin = 4,
    BiasPullUp = 5,
    DriveOpenDrain = 6,
    DriveOpenSource = 7,
    DrivePushPull = 8,
    DriveStrength = 9,
    DriveStrengthUa = 10,
    InputDebounce = 11,
    InputEnable = 12,
    InputSchmittEnable = 13,
    LowPowerMode = 14,
    OutputEnable = 15,
    Output = 16,
    PowerSource = 17,
    SlewRate = 18,
    // Zxyphor extensions
    ZxySpeedClass = 100,
    ZxyVoltageLevel = 101,
}

/// Pin group descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PinGroupDesc {
    pub name: [u8; 32],
    pub name_len: u8,
    pub nr_pins: u32,
    pub pin_ids: [u32; 64],
}

/// Pinctrl map type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PinctrlMapType {
    DummyState = 0,
    MuxGroup = 1,
    ConfigsPin = 2,
    ConfigsGroup = 3,
}

/// Pinmux function descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PinmuxFuncDesc {
    pub name: [u8; 32],
    pub name_len: u8,
    pub nr_groups: u32,
    pub group_names: [[u8; 32]; 16],
}

/// Pinctrl state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PinctrlState {
    Default = 0,
    Idle = 1,
    Sleep = 2,
    Init = 3,
}

// ============================================================================
// Common Clock Framework (CCF)
// ============================================================================

/// Clock type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ClkType {
    Fixed = 0,
    Gate = 1,
    Divider = 2,
    Mux = 3,
    FixedFactor = 4,
    Composite = 5,
    Pll = 6,
    Fractional = 7,
    Gpio = 8,
    // Zxyphor extensions
    ZxyAdaptive = 100,
    ZxySpreading = 101,
}

/// Clock flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ClkFlags(pub u64);

impl ClkFlags {
    pub const SET_RATE_GATE: Self = Self(1 << 0);
    pub const SET_PARENT_GATE: Self = Self(1 << 1);
    pub const SET_RATE_PARENT: Self = Self(1 << 2);
    pub const IGNORE_UNUSED: Self = Self(1 << 3);
    pub const GET_RATE_NOCACHE: Self = Self(1 << 4);
    pub const SET_RATE_NO_REPARENT: Self = Self(1 << 5);
    pub const GET_ACCURACY_NOCACHE: Self = Self(1 << 6);
    pub const RECALC_NEW_RATES: Self = Self(1 << 7);
    pub const SET_RATE_UNGATE: Self = Self(1 << 8);
    pub const IS_CRITICAL: Self = Self(1 << 11);
    pub const OPS_PARENT_ENABLE: Self = Self(1 << 12);
    pub const DUTY_CYCLE_PARENT: Self = Self(1 << 13);
}

/// Clock hardware descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ClkHwDesc {
    pub name: [u8; 32],
    pub name_len: u8,
    pub clk_type: ClkType,
    pub flags: ClkFlags,
    pub num_parents: u8,
    pub parent_names: [[u8; 32]; 8],
    pub init_rate: u64,
    pub accuracy: u64,
    pub phase: i16,
    pub duty_cycle_num: u32,
    pub duty_cycle_den: u32,
}

/// PLL parameters
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PllParams {
    pub vco_min: u64,
    pub vco_max: u64,
    pub input_min: u64,
    pub input_max: u64,
    pub output_min: u64,
    pub output_max: u64,
    pub m_min: u32,
    pub m_max: u32,
    pub n_min: u32,
    pub n_max: u32,
    pub p_min: u32,
    pub p_max: u32,
    pub frac_bits: u8,
    pub lock_delay_us: u32,
}

/// Clock rate request
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ClkRateRequest {
    pub rate: u64,
    pub min_rate: u64,
    pub max_rate: u64,
    pub best_parent_rate: u64,
    pub best_parent_hw_idx: u8,
}

/// Clock notifier events
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum ClkNotifierEvent {
    PreRateChange = 1,
    PostRateChange = 2,
    AbortRateChange = 3,
}

// ============================================================================
// IIO - Industrial I/O Subsystem
// ============================================================================

/// IIO channel type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
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
    Altvoltage = 15,
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
    ElectricallyConductive = 28,
    Count = 29,
    Index = 30,
    Gravity = 31,
    Positionrelative = 32,
    Phase = 33,
    MassConcentration = 34,
    // Zxyphor
    ZxySensorFusion = 100,
    ZxyVibration = 101,
}

/// IIO channel info mask
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct IioChanInfoMask(pub u32);

impl IioChanInfoMask {
    pub const RAW: Self = Self(1 << 0);
    pub const PROCESSED: Self = Self(1 << 1);
    pub const SCALE: Self = Self(1 << 2);
    pub const OFFSET: Self = Self(1 << 3);
    pub const CALIBSCALE: Self = Self(1 << 4);
    pub const CALIBBIAS: Self = Self(1 << 5);
    pub const PEAK: Self = Self(1 << 6);
    pub const PEAK_SCALE: Self = Self(1 << 7);
    pub const AVERAGE_RAW: Self = Self(1 << 8);
    pub const SAMP_FREQ: Self = Self(1 << 9);
    pub const FREQUENCY: Self = Self(1 << 10);
    pub const HARDWAREGAIN: Self = Self(1 << 11);
    pub const OVERSAMPLING_RATIO: Self = Self(1 << 12);
    pub const INT_TIME: Self = Self(1 << 13);
    pub const HYSTERESIS: Self = Self(1 << 14);
}

/// IIO trigger type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioTriggerType {
    DataReady = 0,
    Timer = 1,
    Irq = 2,
    Sysfs = 3,
    Hrtimer = 4,
    Interrupt = 5,
    // Zxyphor
    ZxyEvent = 100,
}

/// IIO buffer mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioBufMode {
    KfifoFlat = 0,
    KfifoHw = 1,
    Dmaengine = 2,
    // Zxyphor
    ZxyZeroCopy = 100,
}

/// IIO event type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IioEventType {
    ThreshRising = 0,
    ThreshFalling = 1,
    ThreshEither = 2,
    Roc = 3,
    ThreshAdaptive = 4,
    MagAdaptive = 5,
    Change = 6,
}

/// IIO device descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IioDeviceDesc {
    pub name: [u8; 32],
    pub name_len: u8,
    pub label: [u8; 32],
    pub label_len: u8,
    pub num_channels: u32,
    pub current_mode: IioBufMode,
    pub trigger_type: IioTriggerType,
    pub buffered: bool,
    pub triggered: bool,
    pub polled: bool,
    pub direct_mode: bool,
    pub setup_ops_present: bool,
    pub parent_dev: u32,
}

/// IIO channel spec
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IioChannelSpec {
    pub channel_type: IioChanType,
    pub channel: i32,
    pub channel2: i32,
    pub address: u64,
    pub scan_index: i32,
    pub scan_type_sign: u8,
    pub scan_type_realbits: u8,
    pub scan_type_storagebits: u8,
    pub scan_type_shift: u8,
    pub scan_type_repeat: u32,
    pub scan_type_endian: IioEndian,
    pub info_mask_separate: IioChanInfoMask,
    pub info_mask_shared_by_type: IioChanInfoMask,
    pub info_mask_shared_by_dir: IioChanInfoMask,
    pub info_mask_shared_by_all: IioChanInfoMask,
    pub modified: bool,
    pub indexed: bool,
    pub output: bool,
    pub differential: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IioEndian {
    Native = 0,
    Little = 1,
    Big = 2,
}

// ============================================================================
// PWM Framework
// ============================================================================

/// PWM polarity
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PwmPolarity {
    Normal = 0,
    Inversed = 1,
}

/// PWM state
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PwmState {
    pub period_ns: u64,
    pub duty_cycle_ns: u64,
    pub polarity: PwmPolarity,
    pub enabled: bool,
    pub usage_power: bool,
}

/// PWM chip descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PwmChipDesc {
    pub base: i32,
    pub npwm: u32,
    pub atomic: bool,
    pub uses_pwmchip_alloc: bool,
    pub parent_dev: u32,
}

/// PWM capture result
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PwmCapture {
    pub period_ns: u32,
    pub duty_cycle_ns: u32,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct GpioClkSubsystem {
    pub nr_gpio_chips: u32,
    pub nr_gpio_lines: u32,
    pub nr_gpio_irq: u32,
    pub nr_pinctrl_dev: u32,
    pub nr_pin_groups: u32,
    pub nr_pin_functions: u32,
    pub nr_clk_providers: u32,
    pub nr_clk_hw: u32,
    pub nr_iio_devices: u32,
    pub nr_iio_triggers: u32,
    pub nr_pwm_chips: u32,
    pub nr_pwm_channels: u32,
    pub initialized: bool,
}

impl GpioClkSubsystem {
    pub const fn new() -> Self {
        Self {
            nr_gpio_chips: 0,
            nr_gpio_lines: 0,
            nr_gpio_irq: 0,
            nr_pinctrl_dev: 0,
            nr_pin_groups: 0,
            nr_pin_functions: 0,
            nr_clk_providers: 0,
            nr_clk_hw: 0,
            nr_iio_devices: 0,
            nr_iio_triggers: 0,
            nr_pwm_chips: 0,
            nr_pwm_channels: 0,
            initialized: false,
        }
    }
}
