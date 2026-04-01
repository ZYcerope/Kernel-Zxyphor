// Zxyphor Kernel - I2C/SPI Controller Detail, RTC Framework
// I2C: adapter, algorithm, client, SMBus protocol
// SPI: controller, device, transfer, message
// RTC: class, alarm, timer, wakealarm
// Regmap: register map abstraction, cache
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// I2C Core
// ============================================================================

pub const I2C_M_RD: u16 = 0x0001;
pub const I2C_M_TEN: u16 = 0x0010;
pub const I2C_M_DMA_SAFE: u16 = 0x0200;
pub const I2C_M_RECV_LEN: u16 = 0x0400;
pub const I2C_M_NO_RD_ACK: u16 = 0x0800;
pub const I2C_M_IGNORE_NAK: u16 = 0x1000;
pub const I2C_M_REV_DIR_ADDR: u16 = 0x2000;
pub const I2C_M_NOSTART: u16 = 0x4000;
pub const I2C_M_STOP: u16 = 0x8000;

pub const I2cMsg = struct {
    addr: u16,
    flags: u16,
    len: u16,
    buf: [*]u8,
};

pub const I2cAdapter = struct {
    name: [64]u8,
    nr: u32,
    algo: ?*const I2cAlgorithm,
    owner: u64,        // module owner
    class: u32,
    retries: u32,
    timeout: u32,      // in jiffies
    quirks: I2cAdapterQuirks,
    bus_lock: u64,     // mutex
    // Transfer stats
    xfer_count: u64,
    byte_count: u64,
    nack_count: u64,
    timeout_count: u64,
};

pub const I2cAlgorithm = struct {
    master_xfer: ?*const fn (*I2cAdapter, [*]I2cMsg, u32) i32,
    master_xfer_atomic: ?*const fn (*I2cAdapter, [*]I2cMsg, u32) i32,
    smbus_xfer: ?*const fn (*I2cAdapter, u16, u16, u8, u8, u32, *SmbusData) i32,
    smbus_xfer_atomic: ?*const fn (*I2cAdapter, u16, u16, u8, u8, u32, *SmbusData) i32,
    functionality: ?*const fn (*I2cAdapter) u32,
    reg_slave: ?*const fn (*I2cClient) i32,
    unreg_slave: ?*const fn (*I2cClient) i32,
};

pub const I2cAdapterQuirks = struct {
    flags: I2cQuirkFlags,
    max_num_msgs: u32,
    max_write_len: u32,
    max_read_len: u32,
    max_comb_1st_msg_len: u32,
    max_comb_2nd_msg_len: u32,
};

pub const I2cQuirkFlags = packed struct(u32) {
    no_clr_addr: bool = false,
    no_rep_start: bool = false,
    clr_default_addr: bool = false,
    no_zero_len: bool = false,
    no_zero_len_read: bool = false,
    no_zero_len_write: bool = false,
    _pad: u26 = 0,
};

pub const I2cClient = struct {
    addr: u16,
    name: [20]u8,
    adapter: ?*I2cAdapter,
    flags: u16,
    irq: i32,
    detected: bool,
    slave_cb: ?*const fn (*I2cClient, u8, *u8) i32,
    init_irq: i32,
};

// ============================================================================
// SMBus Protocol
// ============================================================================

pub const SmbusSize = enum(u32) {
    quick = 0,
    byte = 1,
    byte_data = 2,
    word_data = 3,
    proc_call = 4,
    block_data = 5,
    i2c_block_broken = 6,
    block_proc_call = 7,
    i2c_block_data = 8,
};

pub const SmbusData = extern union {
    byte: u8,
    word: u16,
    block: [34]u8,  // block[0] = length
};

pub const I2cFunctionality = struct {
    pub const I2C: u32 = 0x00000001;
    pub const TEN_BIT_ADDR: u32 = 0x00000002;
    pub const PROTOCOL_MANGLING: u32 = 0x00000004;
    pub const SMBUS_PEC: u32 = 0x00000008;
    pub const NOSTART: u32 = 0x00000010;
    pub const SLAVE: u32 = 0x00000020;
    pub const SMBUS_BLOCK_PROC_CALL: u32 = 0x00008000;
    pub const SMBUS_QUICK: u32 = 0x00010000;
    pub const SMBUS_READ_BYTE: u32 = 0x00020000;
    pub const SMBUS_WRITE_BYTE: u32 = 0x00040000;
    pub const SMBUS_READ_BYTE_DATA: u32 = 0x00080000;
    pub const SMBUS_WRITE_BYTE_DATA: u32 = 0x00100000;
    pub const SMBUS_READ_WORD_DATA: u32 = 0x00200000;
    pub const SMBUS_WRITE_WORD_DATA: u32 = 0x00400000;
    pub const SMBUS_PROC_CALL: u32 = 0x00800000;
    pub const SMBUS_READ_BLOCK_DATA: u32 = 0x01000000;
    pub const SMBUS_WRITE_BLOCK_DATA: u32 = 0x02000000;
    pub const SMBUS_READ_I2C_BLOCK: u32 = 0x04000000;
    pub const SMBUS_WRITE_I2C_BLOCK: u32 = 0x08000000;
    pub const SMBUS_HOST_NOTIFY: u32 = 0x10000000;
};

// ============================================================================
// SPI Core
// ============================================================================

pub const SpiMode = packed struct(u32) {
    cpha: bool = false,       // clock phase
    cpol: bool = false,       // clock polarity
    cs_high: bool = false,
    lsb_first: bool = false,
    three_wire: bool = false,
    loop_mode: bool = false,
    no_cs: bool = false,
    ready: bool = false,
    tx_dual: bool = false,
    tx_quad: bool = false,
    tx_octal: bool = false,
    rx_dual: bool = false,
    rx_quad: bool = false,
    rx_octal: bool = false,
    cs_word: bool = false,
    tx_1x_only: bool = false,
    rx_3wire: bool = false,
    _pad: u15 = 0,
};

pub const SpiController = struct {
    bus_num: u16,
    num_chipselect: u16,
    mode_bits: u32,
    bits_per_word_mask: u32,
    min_speed_hz: u32,
    max_speed_hz: u32,
    flags: SpiControllerFlags,
    // DMA
    dma_tx: u64,
    dma_rx: u64,
    dma_alignment: u32,
    // Auto CS
    auto_runtime_pm: bool,
    cur_msg: ?*SpiMessage,
    cur_msg_incomplete: bool,
    cur_msg_need_completion: bool,
    // Statistics
    xfer_count: u64,
    byte_count: u64,
    error_count: u64,
    timedout_count: u64,
    // Callbacks
    setup: ?*const fn (*SpiDevice) i32,
    cleanup: ?*const fn (*SpiDevice) void,
    transfer: ?*const fn (*SpiDevice, *SpiMessage) i32,
    transfer_one: ?*const fn (*SpiController, *SpiDevice, *SpiTransfer) i32,
    set_cs_timing: ?*const fn (*SpiDevice) i32,
    can_dma: ?*const fn (*SpiController, *SpiDevice, *SpiTransfer) bool,
};

pub const SpiControllerFlags = packed struct(u16) {
    half_duplex: bool = false,
    no_rx: bool = false,
    no_tx: bool = false,
    must_rx: bool = false,
    must_tx: bool = false,
    gpio_cs: bool = false,
    master: bool = false,
    slave: bool = false,
    idle_free: bool = false,
    multi_cs: bool = false,
    _pad: u6 = 0,
};

pub const SpiDevice = struct {
    controller: ?*SpiController,
    max_speed_hz: u32,
    chip_select: u8,
    bits_per_word: u8,
    rt: bool,
    mode: SpiMode,
    irq: i32,
    modalias: [32]u8,
    cs_gpiod: u64,     // GPIO descriptor
    cs_setup: u32,      // nanoseconds
    cs_hold: u32,
    cs_inactive: u32,
    word_delay: SpiDelay,
};

pub const SpiDelay = struct {
    value: u16,
    unit: SpiDelayUnit,
};

pub const SpiDelayUnit = enum(u8) {
    usecs = 0,
    nsecs = 1,
    sck = 2,
};

pub const SpiTransfer = struct {
    tx_buf: ?[*]const u8,
    rx_buf: ?[*]u8,
    len: u32,
    tx_nbits: u8,
    rx_nbits: u8,
    bits_per_word: u8,
    dummy_data: bool,
    cs_off: bool,
    cs_change: bool,
    cs_change_delay: SpiDelay,
    delay: SpiDelay,
    speed_hz: u32,
    word_delay: SpiDelay,
    effective_speed_hz: u32,
    // SG mapping
    tx_sg_mapped: bool,
    rx_sg_mapped: bool,
};

pub const SpiMessage = struct {
    transfers_count: u32,
    spi: ?*SpiDevice,
    status: i32,
    actual_length: u32,
    complete: ?*const fn (*SpiMessage) void,
    frame_length: u32,
    is_dma_mapped: bool,
    prepared: bool,
};

// ============================================================================
// RTC (Real-Time Clock) Framework
// ============================================================================

pub const RtcTime = struct {
    tm_sec: u8,
    tm_min: u8,
    tm_hour: u8,
    tm_mday: u8,
    tm_mon: u8,     // 0-11
    tm_year: u16,   // years since 1900
    tm_wday: u8,
    tm_yday: u16,
    tm_isdst: i8,
};

pub const RtcWkAlarm = struct {
    enabled: bool,
    pending: bool,
    time: RtcTime,
};

pub const RtcDevice = struct {
    name: [32]u8,
    id: u32,
    ops: ?*const RtcClassOps,
    owner: u64,
    max_user_freq: u32,
    irq_freq: u32,
    pie_enabled: bool,
    aie_timer_enabled: bool,
    uie_rtctimer_enabled: bool,
    // Features
    features: RtcFeatures,
    // Range
    range_min: u64,   // seconds since epoch
    range_max: u64,
    // Alarms
    alarm_offset: i64,
    start_secs: u64,
    offset_secs: i64,
    // Stats
    irq_count: u64,
    alarm_irq_count: u64,
    update_irq_count: u64,
    periodic_irq_count: u64,
};

pub const RtcFeatures = packed struct(u16) {
    alarm: bool = false,
    alarm_res_minute: bool = false,
    need_week_day: bool = false,
    alarm_res_2s: bool = false,
    update_interrupt: bool = false,
    correction: bool = false,
    backup_switch_time: bool = false,
    alarm_wakeup_only: bool = false,
    _pad: u8 = 0,
};

pub const RtcClassOps = struct {
    ioctl: ?*const fn (*RtcDevice, u32, u64) i32,
    read_time: ?*const fn (*RtcDevice, *RtcTime) i32,
    set_time: ?*const fn (*RtcDevice, *const RtcTime) i32,
    read_alarm: ?*const fn (*RtcDevice, *RtcWkAlarm) i32,
    set_alarm: ?*const fn (*RtcDevice, *const RtcWkAlarm) i32,
    proc: ?*const fn (*RtcDevice) i32,
    alarm_irq_enable: ?*const fn (*RtcDevice, bool) i32,
    read_offset: ?*const fn (*RtcDevice, *i64) i32,
    set_offset: ?*const fn (*RtcDevice, i64) i32,
    param_get: ?*const fn (*RtcDevice, *RtcParam) i32,
    param_set: ?*const fn (*RtcDevice, *RtcParam) i32,
};

pub const RtcParam = struct {
    param: RtcParamType,
    uvalue: u64,
    svalue: i64,
    index: u32,
};

pub const RtcParamType = enum(u32) {
    features = 0,
    correction = 1,
    backup_switch_time = 2,
};

// ============================================================================
// Regmap (Register Map Abstraction)
// ============================================================================

pub const RegmapBusType = enum(u8) {
    i2c = 0,
    spi = 1,
    mmio = 2,
    spmi = 3,
    w1 = 4,
    slimbus = 5,
    sdw = 6,
    sccb = 7,
    custom = 0xFF,
};

pub const RegmapConfig = struct {
    name: [32]u8,
    reg_bits: u8,
    reg_stride: u8,
    pad_bits: u8,
    val_bits: u8,
    // Formatting
    reg_base: u32,
    reg_shift: u8,
    write_flag_mask: u32,
    read_flag_mask: u32,
    // Defaults
    reg_defaults_count: u32,
    // Cache
    cache_type: RegmapCacheType,
    // Ranges
    num_reg_defaults: u32,
    max_register: u32,
    // Access
    writeable_reg: ?*const fn (u64, u32) bool,
    readable_reg: ?*const fn (u64, u32) bool,
    volatile_reg: ?*const fn (u64, u32) bool,
    precious_reg: ?*const fn (u64, u32) bool,
    writeable_noinc_reg: ?*const fn (u64, u32) bool,
    readable_noinc_reg: ?*const fn (u64, u32) bool,
    // Misc
    disable_locking: bool,
    can_sleep: bool,
    fast_io: bool,
    io_port: bool,
    use_single_read: bool,
    use_single_write: bool,
    can_multi_write: bool,
    use_relaxed_mmio: bool,
};

pub const RegmapCacheType = enum(u8) {
    none = 0,
    rbtree = 1,
    flat = 2,
    maple = 3,
};

pub const RegmapAccess = struct {
    range_min: u32,
    range_max: u32,
    readable: bool,
    writeable: bool,
    volatile_access: bool,
    precious: bool,
};

pub const RegmapRange = struct {
    range_min: u32,
    range_max: u32,
    page_sel_reg: u32,
    page_sel_mask: u32,
    page_sel_shift: u32,
    window_start: u32,
    window_len: u32,
};

pub const RegmapBusOps = struct {
    write: ?*const fn (u64, *const anyopaque, u64) i32,
    gather_write: ?*const fn (u64, *const anyopaque, u64, *const anyopaque, u64) i32,
    async_write: ?*const fn (u64, *const anyopaque, u64, *const anyopaque, u64) i32,
    read: ?*const fn (u64, *const anyopaque, u64, *anyopaque, u64) i32,
    async_read: ?*const fn (u64, *const anyopaque, u64, *anyopaque, u64) i32,
    free_context: ?*const fn (u64) void,
    async_alloc: ?*const fn () ?*anyopaque,
    reg_write: ?*const fn (u64, u32, u32) i32,
    reg_read: ?*const fn (u64, u32, *u32) i32,
    reg_noinc_write: ?*const fn (u64, u32, *const anyopaque, u64) i32,
    reg_noinc_read: ?*const fn (u64, u32, *anyopaque, u64) i32,
};

pub const RegmapStats = struct {
    reads: u64,
    writes: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_bypasses: u64,
    cache_syncs: u64,
    cache_drops: u64,
};

// ============================================================================
// I2C/SPI/RTC Subsystem Manager
// ============================================================================

pub const BusSubsystemDetailManager = struct {
    // I2C
    i2c_adapters: u32,
    i2c_clients: u32,
    i2c_total_xfers: u64,
    i2c_total_bytes: u64,
    i2c_nack_errors: u64,
    i2c_timeout_errors: u64,
    // SPI
    spi_controllers: u32,
    spi_devices: u32,
    spi_total_xfers: u64,
    spi_total_bytes: u64,
    spi_errors: u64,
    // RTC
    rtc_devices: u32,
    rtc_alarms_set: u64,
    rtc_alarms_triggered: u64,
    // Regmap
    regmap_instances: u32,
    regmap_reads: u64,
    regmap_writes: u64,
    regmap_cache_hits: u64,
    // State
    initialized: bool,

    pub fn init() BusSubsystemDetailManager {
        return BusSubsystemDetailManager{
            .i2c_adapters = 0,
            .i2c_clients = 0,
            .i2c_total_xfers = 0,
            .i2c_total_bytes = 0,
            .i2c_nack_errors = 0,
            .i2c_timeout_errors = 0,
            .spi_controllers = 0,
            .spi_devices = 0,
            .spi_total_xfers = 0,
            .spi_total_bytes = 0,
            .spi_errors = 0,
            .rtc_devices = 0,
            .rtc_alarms_set = 0,
            .rtc_alarms_triggered = 0,
            .regmap_instances = 0,
            .regmap_reads = 0,
            .regmap_writes = 0,
            .regmap_cache_hits = 0,
            .initialized = true,
        };
    }
};
