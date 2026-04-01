// SPDX-License-Identifier: MIT
// Zxyphor Kernel - LED Subsystem, Regmap, MTD Flash, DeviceTree Overlay, PWM
// Comprehensive hardware abstraction framework beyond Linux 2026

const std = @import("std");

// ============================================================================
// LED Subsystem
// ============================================================================

pub const LedColor = enum(u8) {
    white = 0,
    red = 1,
    green = 2,
    blue = 3,
    amber = 4,
    violet = 5,
    yellow = 6,
    orange = 7,
    pink = 8,
    purple = 9,
    cyan = 10,
    lime = 11,
    ir = 12,
    multi_color = 13,
};

pub const LedFunction = enum(u8) {
    activity = 0,
    alarm = 1,
    backlight = 2,
    bluetooth_power = 3,
    boot = 4,
    capslock = 5,
    charging = 6,
    cpu = 7,
    debug = 8,
    disk_activity = 9,
    disk_err = 10,
    disk_read = 11,
    disk_write = 12,
    fault = 13,
    flash = 14,
    heartbeat = 15,
    indicator = 16,
    kbd_backlight = 17,
    lan = 18,
    mail = 19,
    micmute = 20,
    mmc = 21,
    mtd = 22,
    mute_audio = 23,
    numlock = 24,
    panic = 25,
    player_1 = 26,
    player_2 = 27,
    player_3 = 28,
    player_4 = 29,
    player_5 = 30,
    power = 31,
    programming = 32,
    rx = 33,
    scrolllock = 34,
    sd = 35,
    standby = 36,
    status = 37,
    torch = 38,
    tx = 39,
    usb = 40,
    wan = 41,
    wlan = 42,
};

pub const LedTriggerType = enum(u8) {
    none = 0,
    default_on = 1,
    heartbeat = 2,
    timer = 3,
    oneshot = 4,
    disk_activity = 5,
    mtd = 6,
    nand = 7,
    mmc = 8,
    cpu = 9,
    gpio = 10,
    netdev = 11,
    transient = 12,
    camera_flash = 13,
    camera_torch = 14,
    panic = 15,
    pattern = 16,
    audio_mute = 17,
    audio_micmute = 18,
    // Zxyphor
    zxy_system_load = 50,
    zxy_temp_indicator = 51,
};

pub const LedDevice = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    color: LedColor = .white,
    function: LedFunction = .status,
    // Brightness
    brightness: u32 = 0,
    max_brightness: u32 = 255,
    // Trigger
    trigger: LedTriggerType = .none,
    // Blink
    blink_delay_on: u32 = 0,
    blink_delay_off: u32 = 0,
    // Multi-color
    nr_subled: u8 = 0,
    subled_info: [8]SubLedInfo = [_]SubLedInfo{.{}} ** 8,
    // Pattern
    pattern_repeat: i32 = -1,
    nr_pattern_entries: u16 = 0,
    // Flags
    has_hw_blink: bool = false,
    has_flash: bool = false,
    has_flash_config: bool = false,
    // Stats
    total_brightness_sets: u64 = 0,
    total_blink_configs: u64 = 0,
};

pub const SubLedInfo = struct {
    color: LedColor = .white,
    brightness: u32 = 0,
    intensity: u32 = 0,
    channel: u8 = 0,
};

// ============================================================================
// Regmap (Register Map Abstraction)
// ============================================================================

pub const RegmapBusType = enum(u8) {
    mmio = 0,
    i2c = 1,
    spi = 2,
    spmi = 3,
    slimbus = 4,
    ac97 = 5,
    sdw = 6,
    sccb = 7,
    // Zxyphor
    zxy_fast_bus = 20,
};

pub const RegmapEndian = enum(u8) {
    native = 0,
    big = 1,
    little = 2,
};

pub const RegmapCacheType = enum(u8) {
    none = 0,
    rbtree = 1,
    flat = 2,
    maple = 3,
};

pub const RegmapConfig = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    reg_bits: u8 = 8,
    reg_stride: u8 = 1,
    val_bits: u8 = 8,
    // Endianness
    reg_format_endian: RegmapEndian = .native,
    val_format_endian: RegmapEndian = .native,
    // Bus
    bus_type: RegmapBusType = .mmio,
    // Cache
    cache_type: RegmapCacheType = .none,
    // Max register
    max_register: u32 = 0,
    // Volatile / precious
    nr_volatile_ranges: u16 = 0,
    nr_precious_ranges: u16 = 0,
    nr_read_only_ranges: u16 = 0,
    nr_write_only_ranges: u16 = 0,
    // Paging
    has_paging: bool = false,
    page_reg: u32 = 0,
    page_mask: u32 = 0,
    // IRQ
    has_irq_chip: bool = false,
    nr_irqs: u16 = 0,
    // Stats
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    total_cache_hits: u64 = 0,
    total_cache_misses: u64 = 0,
    total_cache_syncs: u64 = 0,
    cache_dirty: bool = false,
    cache_bypassed: bool = false,
};

pub const RegmapRange = struct {
    range_min: u32 = 0,
    range_max: u32 = 0,
};

pub const RegmapIrqType = struct {
    type_reg_offset: u32 = 0,
    type_rising_val: u32 = 0,
    type_falling_val: u32 = 0,
    type_level_low_val: u32 = 0,
    type_level_high_val: u32 = 0,
    types_supported: u32 = 0,
};

// ============================================================================
// MTD (Memory Technology Devices) / Flash
// ============================================================================

pub const MtdType = enum(u8) {
    absent = 0,
    ram = 1,
    rom = 2,
    norflash = 3,
    nandflash = 4,
    dataflash = 5,
    ubivolume = 6,
    mlcnandflash = 7,
};

pub const MtdFlags = packed struct {
    writeable: bool = false,
    bit_writeable: bool = false,
    no_erase: bool = false,
    powerup_lock: bool = false,
    spi_nor: bool = false,
    _padding: u3 = 0,
};

pub const MtdDevice = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    index: u32 = 0,
    mtd_type: MtdType = .norflash,
    flags: MtdFlags = .{},
    // Size
    size: u64 = 0,
    erasesize: u32 = 0,
    writesize: u32 = 0,         // Minimum write size
    writebufsize: u32 = 0,      // Write buffer size
    oobsize: u16 = 0,           // Out-of-band data size
    oobavail: u16 = 0,
    // ECC
    ecc_strength: u8 = 0,
    ecc_step_size: u16 = 0,
    bitflip_threshold: u32 = 0,
    // Subpage
    subpage_sft: u8 = 0,
    // Stats
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    total_erases: u64 = 0,
    total_read_errors: u64 = 0,
    total_write_errors: u64 = 0,
    total_erase_errors: u64 = 0,
    total_ecc_corrections: u64 = 0,
    total_ecc_failures: u64 = 0,
    // Bad blocks
    nr_bad_blocks: u32 = 0,
    nr_reserved_blocks: u32 = 0,
};

pub const NandChipInfo = struct {
    manufacturer: [32]u8 = [_]u8{0} ** 32,
    model: [32]u8 = [_]u8{0} ** 32,
    id: [8]u8 = [_]u8{0} ** 8,
    id_len: u8 = 0,
    // Geometry
    chipsize: u64 = 0,
    pages_per_block: u32 = 0,
    page_size: u32 = 0,
    oob_size: u16 = 0,
    planes: u8 = 1,
    luns: u8 = 1,
    // Technology
    bits_per_cell: u8 = 1,      // SLC=1, MLC=2, TLC=3, QLC=4
    interface: NandInterface = .sdr,
    // Timing
    tBERS_max: u32 = 0,         // Block erase time (us)
    tPROG_max: u32 = 0,         // Page program time (us)
    tR_max: u32 = 0,            // Page read time (us)
};

pub const NandInterface = enum(u8) {
    sdr = 0,
    nvddr = 1,
    nvddr2 = 2,
    onfi = 3,
};

// ============================================================================
// UBI (Unsorted Block Images)
// ============================================================================

pub const UbiVolumeType = enum(u8) {
    dynamic = 0,
    static_ = 1,
};

pub const UbiVolume = struct {
    vol_id: u32 = 0,
    name: [128]u8 = [_]u8{0} ** 128,
    vol_type: UbiVolumeType = .dynamic,
    reserved_pebs: u32 = 0,
    used_ebs: u32 = 0,
    data_pad: u32 = 0,
    usable_leb_size: u32 = 0,
    alignment: u32 = 1,
    corrupted: bool = false,
    upd_marker: bool = false,
};

pub const UbiDeviceInfo = struct {
    ubi_num: u32 = 0,
    mtd_num: u32 = 0,
    // Physical
    peb_size: u32 = 0,
    peb_count: u32 = 0,
    // Logical
    leb_size: u32 = 0,
    min_io_size: u32 = 0,
    // Overhead
    bad_peb_count: u32 = 0,
    max_ec: u64 = 0,
    mean_ec: u64 = 0,
    // Volumes
    nr_volumes: u32 = 0,
    max_vol_count: u32 = 128,
    avail_pebs: u32 = 0,
    // Wear leveling
    wl_threshold: u32 = 4096,
    total_wl_moves: u64 = 0,
};

// ============================================================================
// DeviceTree Overlay
// ============================================================================

pub const DtPropertyType = enum(u8) {
    unknown = 0,
    string = 1,
    stringlist = 2,
    u32_val = 3,
    u64_val = 4,
    phandle = 5,
    phandle_args = 6,
    boolean = 7,
    byte_array = 8,
    // Complex
    reg = 10,           // <addr len> pairs
    ranges = 11,        // <child parent len>
    interrupts = 12,
    clocks = 13,
    gpio = 14,
    dma = 15,
};

pub const DtNode = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    full_name: [256]u8 = [_]u8{0} ** 256,
    phandle: u32 = 0,
    nr_properties: u32 = 0,
    nr_children: u32 = 0,
    // Status
    status: DtNodeStatus = .okay,
    // Compatible
    compatible: [256]u8 = [_]u8{0} ** 256,
    nr_compatible: u8 = 0,
};

pub const DtNodeStatus = enum(u8) {
    okay = 0,
    disabled = 1,
    reserved = 2,
    fail = 3,
    fail_sss = 4,
};

pub const DtOverlay = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    // Target
    target_phandle: u32 = 0,
    target_path: [256]u8 = [_]u8{0} ** 256,
    // Fragment
    nr_fragments: u32 = 0,
    // Status
    applied: bool = false,
    // Stats
    nr_nodes_added: u32 = 0,
    nr_nodes_modified: u32 = 0,
    nr_properties_set: u32 = 0,
    nr_properties_removed: u32 = 0,
};

pub const DtOverlaySubsystem = struct {
    nr_overlays_applied: u32 = 0,
    nr_overlays_failed: u32 = 0,
    total_nodes: u64 = 0,
    total_properties: u64 = 0,
};

// ============================================================================
// PWM (Pulse Width Modulation)
// ============================================================================

pub const PwmPolarity = enum(u8) {
    normal = 0,
    inversed = 1,
};

pub const PwmState = struct {
    period: u64 = 0,            // Period in nanoseconds
    duty_cycle: u64 = 0,        // Duty cycle in nanoseconds
    polarity: PwmPolarity = .normal,
    enabled: bool = false,
    usage_power: bool = false,   // Power mode
};

pub const PwmDevice = struct {
    hwpwm: u32 = 0,
    label: [32]u8 = [_]u8{0} ** 32,
    state: PwmState = .{},
    // Chip info
    chip_id: u32 = 0,
    nr_pwms: u32 = 0,
    // Stats
    total_enable: u64 = 0,
    total_disable: u64 = 0,
    total_config: u64 = 0,
};

// ============================================================================
// Watchdog (extended)
// ============================================================================

pub const WatchdogInfoFlags2 = packed struct {
    overheat: bool = false,
    fan_fault: bool = false,
    extern_1: bool = false,
    extern_2: bool = false,
    powerunder: bool = false,
    cardreset: bool = false,
    powerover: bool = false,
    settimeout: bool = false,
    magicclose: bool = false,
    pretimeout: bool = false,
    alarmonly: bool = false,
    keepaliveping: bool = false,
    _padding: u4 = 0,
};

pub const WatchdogTimerInfo = struct {
    identity: [32]u8 = [_]u8{0} ** 32,
    firmware_version: u32 = 0,
    options: WatchdogInfoFlags2 = .{},
    timeout: u32 = 0,          // seconds
    min_timeout: u32 = 0,
    max_timeout: u32 = 0,
    pretimeout: u32 = 0,
    bootstatus: u32 = 0,
    // Stats
    total_keepalives: u64 = 0,
    total_timeouts: u64 = 0,
    last_keepalive_ns: u64 = 0,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const HwAbstractionSubsystem = struct {
    // LED
    nr_leds: u32 = 0,
    nr_led_triggers: u32 = 0,
    total_brightness_changes: u64 = 0,
    // Regmap
    nr_regmap_instances: u32 = 0,
    total_regmap_reads: u64 = 0,
    total_regmap_writes: u64 = 0,
    total_cache_syncs: u64 = 0,
    // MTD
    nr_mtd_devices: u32 = 0,
    total_mtd_reads: u64 = 0,
    total_mtd_writes: u64 = 0,
    total_mtd_erases: u64 = 0,
    // UBI
    nr_ubi_devices: u32 = 0,
    nr_ubi_volumes: u32 = 0,
    // DeviceTree
    dt_overlay: DtOverlaySubsystem = .{},
    // PWM
    nr_pwm_chips: u32 = 0,
    nr_pwm_channels: u32 = 0,
    // Watchdog
    nr_watchdogs: u32 = 0,
    // Zxyphor
    zxy_hot_overlay_enabled: bool = false,
    initialized: bool = false,
};
