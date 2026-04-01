// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Framebuffer Console (fbcon),
// GPIO Controller (Zig side), Crypto HW Accelerator,
// Clock Subsystem Provider, Watchdog Timer Core,
// Thermal Zone Framework, Voltage Regulator Core
// More advanced than Linux 2026 device drivers

const std = @import("std");

// ============================================================================
// Framebuffer Console (fbcon)
// ============================================================================

/// fbcon cursor type
pub const FbconCursorType = enum(u8) {
    off = 0,
    underline = 1,
    lower_third = 2,
    lower_half = 3,
    two_thirds = 4,
    block = 5,
};

/// fbcon scroll mode
pub const FbconScrollMode = enum(u8) {
    redraw = 0,
    move = 1,
    pan_move = 2,
    wrap_move = 3,
};

/// fbcon descriptor
pub const FbconDesc = struct {
    fb_index: u32 = 0,
    cursor: FbconCursorType = .underline,
    scroll_mode: FbconScrollMode = .move,
    font_width: u8 = 8,
    font_height: u8 = 16,
    rows: u32 = 0,
    cols: u32 = 0,
    cursor_x: u32 = 0,
    cursor_y: u32 = 0,
    fg_color: u32 = 0xC0C0C0,    // default gray
    bg_color: u32 = 0x000000,
    // Attributes
    bold: bool = false,
    underline: bool = false,
    blink: bool = false,
    reverse: bool = false,
    // Buffer
    visible: bool = true,
    blanked: bool = false,
    softback_size: u64 = 0,
};

/// Framebuffer color depth
pub const FbColorDepth = enum(u8) {
    mono = 1,
    bpp4 = 4,
    bpp8 = 8,
    bpp15 = 15,
    bpp16 = 16,
    bpp24 = 24,
    bpp32 = 32,
};

/// Framebuffer pixel format
pub const FbPixelFormat = enum(u8) {
    packed = 0,
    planar = 1,
    interleaved = 2,
    fourcc = 3,
};

/// Framebuffer var screen info
pub const FbVarScreenInfo = struct {
    xres: u32 = 0,
    yres: u32 = 0,
    xres_virtual: u32 = 0,
    yres_virtual: u32 = 0,
    xoffset: u32 = 0,
    yoffset: u32 = 0,
    bits_per_pixel: u32 = 0,
    grayscale: u32 = 0,
    red_offset: u32 = 0,
    red_length: u32 = 0,
    green_offset: u32 = 0,
    green_length: u32 = 0,
    blue_offset: u32 = 0,
    blue_length: u32 = 0,
    transp_offset: u32 = 0,
    transp_length: u32 = 0,
    nonstd: u32 = 0,
    activate: u32 = 0,
    pixclock: u32 = 0,
    left_margin: u32 = 0,
    right_margin: u32 = 0,
    upper_margin: u32 = 0,
    lower_margin: u32 = 0,
    hsync_len: u32 = 0,
    vsync_len: u32 = 0,
    sync: u32 = 0,
    vmode: u32 = 0,
    rotate: u32 = 0,
    colorspace: u32 = 0,
};

// ============================================================================
// GPIO Controller (Zig side)
// ============================================================================

/// GPIO direction
pub const GpioDir = enum(u8) {
    input = 0,
    output = 1,
};

/// GPIO active level
pub const GpioActiveLevel = enum(u8) {
    high = 0,
    low = 1,
};

/// GPIO line flags
pub const GpioLineFlags = packed struct(u64) {
    used: bool = false,
    active_low: bool = false,
    input: bool = false,
    output: bool = false,
    edge_rising: bool = false,
    edge_falling: bool = false,
    open_drain: bool = false,
    open_source: bool = false,
    bias_pull_up: bool = false,
    bias_pull_down: bool = false,
    bias_disabled: bool = false,
    event_clock_realtime: bool = false,
    event_clock_hte: bool = false,
    // Zxyphor
    zxy_debounce: bool = false,
    zxy_interrupt: bool = false,
    _padding: u49 = 0,
};

/// GPIO chip descriptor
pub const GpioChipDesc = struct {
    label: [32]u8 = [_]u8{0} ** 32,
    label_len: u8 = 0,
    base: i32 = -1,
    ngpio: u16 = 0,
    names: bool = false,
    can_sleep: bool = false,
    irq_chip: bool = false,
    parent: u64 = 0,
};

/// GPIO line info
pub const GpioLineInfo = struct {
    offset: u32 = 0,
    flags: GpioLineFlags = .{},
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    consumer: [32]u8 = [_]u8{0} ** 32,
    consumer_len: u8 = 0,
};

// ============================================================================
// Crypto HW Accelerator
// ============================================================================

/// Crypto accelerator type
pub const CryptoHwType = enum(u8) {
    aes_ni = 0,         // Intel AES-NI
    sha_ni = 1,         // Intel SHA-NI
    avx2 = 2,           // AVX2 crypto
    avx512 = 3,         // AVX-512 crypto
    qat = 4,            // Intel QuickAssist
    ccp = 5,            // AMD CCP
    caam = 6,           // NXP CAAM
    ce = 7,             // ARM Crypto Extensions
    // Zxyphor
    zxy_accel = 100,
};

/// Crypto HW capabilities
pub const CryptoHwCaps = packed struct(u64) {
    aes_ecb: bool = false,
    aes_cbc: bool = false,
    aes_ctr: bool = false,
    aes_gcm: bool = false,
    aes_xts: bool = false,
    aes_ccm: bool = false,
    sha1: bool = false,
    sha256: bool = false,
    sha384: bool = false,
    sha512: bool = false,
    sha3: bool = false,
    chacha20: bool = false,
    poly1305: bool = false,
    rsa: bool = false,
    ecdsa: bool = false,
    ecdh: bool = false,
    dh: bool = false,
    hmac: bool = false,
    cmac: bool = false,
    rng: bool = false,
    compress_deflate: bool = false,
    compress_lzo: bool = false,
    compress_lz4: bool = false,
    compress_zstd: bool = false,
    // Zxyphor
    zxy_post_quantum: bool = false,
    _padding: u39 = 0,
};

/// Crypto HW descriptor
pub const CryptoHwDesc = struct {
    hw_type: CryptoHwType = .aes_ni,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    caps: CryptoHwCaps = .{},
    max_engines: u8 = 0,
    active_engines: u8 = 0,
    queue_depth: u32 = 0,
    // Stats
    ops_completed: u64 = 0,
    ops_failed: u64 = 0,
    bytes_processed: u64 = 0,
};

// ============================================================================
// Clock Subsystem Provider
// ============================================================================

/// Clock type
pub const ClockType = enum(u8) {
    fixed_rate = 0,
    gate = 1,
    divider = 2,
    mux = 3,
    fixed_factor = 4,
    fractional_divider = 5,
    composite = 6,
    pll = 7,
    gpio = 8,
    // Zxyphor
    zxy_adaptive = 100,
};

/// Clock flags
pub const ClockFlags = packed struct(u64) {
    set_rate_gate: bool = false,
    set_parent_gate: bool = false,
    set_rate_parent: bool = false,
    ignore_unused: bool = false,
    get_rate_nocache: bool = false,
    set_rate_no_reparent: bool = false,
    get_accuracy_nocache: bool = false,
    recalc_new_rate: bool = false,
    set_rate_ungate: bool = false,
    is_critical: bool = false,
    ops_parent_enable: bool = false,
    duty_cycle_parent: bool = false,
    // Zxyphor
    zxy_auto_gate: bool = false,
    _padding: u51 = 0,
};

/// Clock descriptor
pub const ClockDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    clock_type: ClockType = .fixed_rate,
    flags: ClockFlags = .{},
    rate_hz: u64 = 0,
    accuracy: u32 = 0,
    phase: i32 = 0,
    duty_num: u32 = 0,
    duty_den: u32 = 0,
    enable_count: u32 = 0,
    prepare_count: u32 = 0,
    notifier_count: u32 = 0,
    nr_parents: u8 = 0,
    nr_children: u32 = 0,
};

// ============================================================================
// Watchdog Timer Core
// ============================================================================

/// Watchdog status
pub const WatchdogStatus = packed struct(u32) {
    active: bool = false,
    dev_open: bool = false,
    allow_release: bool = false,
    hrt_running: bool = false,
    no_way_out: bool = false,
    unregistered: bool = false,
    has_pretimeout_governor: bool = false,
    // Zxyphor
    zxy_smart_reboot: bool = false,
    _padding: u24 = 0,
};

/// Watchdog info (WDIOF_* flags)
pub const WatchdogInfoFlags = packed struct(u32) {
    overheat: bool = false,
    fan_fault: bool = false,
    extern1: bool = false,
    extern2: bool = false,
    powerunder: bool = false,
    cardreset: bool = false,
    powerover: bool = false,
    settimeout: bool = false,
    magicclose: bool = false,
    pretimeout: bool = false,
    alarmonly: bool = false,
    keepaliveping: bool = false,
    _padding: u20 = 0,
};

/// Watchdog descriptor
pub const WatchdogDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    id: u32 = 0,
    status: WatchdogStatus = .{},
    info_flags: WatchdogInfoFlags = .{},
    timeout: u32 = 60,         // seconds
    pretimeout: u32 = 0,
    min_timeout: u32 = 1,
    max_timeout: u32 = 65535,
    min_hw_heartbeat_ms: u32 = 0,
    max_hw_heartbeat_ms: u32 = 0,
    bootstatus: u32 = 0,
    last_keepalive: u64 = 0,   // jiffies
    last_hw_keepalive: u64 = 0,
};

// ============================================================================
// Thermal Zone Framework
// ============================================================================

/// Thermal zone type
pub const ThermalZoneType = enum(u8) {
    cpu = 0,
    gpu = 1,
    memory = 2,
    board = 3,
    nvme = 4,
    pch = 5,
    battery = 6,
    skin = 7,
    // Zxyphor
    zxy_ai_managed = 100,
};

/// Thermal trip type
pub const ThermalTripType = enum(u8) {
    active = 0,
    passive = 1,
    hot = 2,
    critical = 3,
};

/// Thermal trip point
pub const ThermalTripPoint = struct {
    trip_type: ThermalTripType = .passive,
    temperature: i32 = 0,      // millidegree Celsius
    hysteresis: i32 = 0,
};

/// Thermal governor type
pub const ThermalGovernor = enum(u8) {
    step_wise = 0,
    fair_share = 1,
    bang_bang = 2,
    user_space = 3,
    power_allocator = 4,
    // Zxyphor
    zxy_adaptive = 100,
};

/// Thermal cooling device type
pub const ThermalCoolType = enum(u8) {
    processor = 0,
    fan = 1,
    devfreq = 2,
    cpufreq = 3,
    lcd = 4,
    // Zxyphor
    zxy_smart = 100,
};

/// Thermal zone descriptor
pub const ThermalZoneDesc = struct {
    zone_type: ThermalZoneType = .cpu,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    governor: ThermalGovernor = .step_wise,
    temperature: i32 = 0,
    last_temperature: i32 = 0,
    nr_trips: u8 = 0,
    trips: [12]ThermalTripPoint = [_]ThermalTripPoint{.{}} ** 12,
    nr_cooling_devices: u8 = 0,
    passive_delay_ms: u32 = 0,
    polling_delay_ms: u32 = 0,
    mode: ThermalZoneMode = .enabled,
};

pub const ThermalZoneMode = enum(u8) {
    disabled = 0,
    enabled = 1,
};

// ============================================================================
// Voltage Regulator Core
// ============================================================================

/// Regulator type
pub const RegulatorType = enum(u8) {
    voltage = 0,
    current = 1,
};

/// Regulator status
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

/// Regulator constraints
pub const RegulatorConstraints = struct {
    min_uv: i32 = 0,
    max_uv: i32 = 0,
    uv_offset: i32 = 0,
    min_ua: i32 = 0,
    max_ua: i32 = 0,
    valid_modes_mask: u32 = 0,
    valid_ops_mask: u32 = 0,
    always_on: bool = false,
    boot_on: bool = false,
    apply_uv: bool = false,
    over_current_protection: bool = false,
    ramp_delay: u32 = 0,       // uV/us
    settling_time: u32 = 0,    // us
    settling_time_up: u32 = 0,
    settling_time_down: u32 = 0,
};

/// Regulator descriptor
pub const RegulatorDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    reg_type: RegulatorType = .voltage,
    status: RegulatorStatus = .off,
    constraints: RegulatorConstraints = .{},
    volt_table_count: u32 = 0,
    continuous_voltage_range: bool = false,
    n_voltages: u32 = 0,
    enable_time: u32 = 0,       // us
    off_on_delay: u32 = 0,      // us
    use_count: u32 = 0,
    open_count: u32 = 0,
    bypass_count: u32 = 0,
};

// ============================================================================
// Driver Subsystem Manager
// ============================================================================

pub const DriverExtSubsystem = struct {
    nr_fbcon: u32 = 0,
    nr_gpio_chips: u32 = 0,
    nr_gpio_lines: u32 = 0,
    nr_crypto_hw: u32 = 0,
    nr_clocks: u32 = 0,
    nr_watchdogs: u32 = 0,
    nr_thermal_zones: u32 = 0,
    nr_regulators: u32 = 0,
    initialized: bool = false,

    pub fn init() DriverExtSubsystem {
        return DriverExtSubsystem{
            .initialized = true,
        };
    }
};
