// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - FPGA Manager, Region, Bridge & IIO Framework
// Complete: FPGA management subsystem, bitstream loading, partial reconfiguration,
// IIO (Industrial I/O) devices, ADC/DAC channels, triggers, buffers

const std = @import("std");

// ============================================================================
// FPGA Manager
// ============================================================================

pub const FpgaManagerState = enum(u8) {
    Unknown = 0,
    PowerUp = 1,
    Reset = 2,
    FirmwareRequest = 3,
    FirmwareRequestErr = 4,
    WriteInit = 5,
    WriteInitErr = 6,
    Write = 7,
    WriteErr = 8,
    WriteComplete = 9,
    WriteCompleteErr = 10,
    Operating = 11,
};

pub const FpgaManagerFlags = packed struct(u32) {
    full_reconfig: bool,
    partial_reconfig: bool,
    external_config: bool,
    encrypted_bitstream: bool,
    bitstream_compress: bool,
    read_back: bool,
    sleep: bool,
    auth_bitstream: bool,
    _reserved: u24,
};

pub const FpgaManagerOps = struct {
    initial_header_size: usize,
    state: ?*const fn (mgr: *FpgaMgr) callconv(.C) FpgaManagerState,
    status: ?*const fn (mgr: *FpgaMgr, status: *u64) callconv(.C) i32,
    write_init: ?*const fn (mgr: *FpgaMgr, info: *FpgaImage, buf: [*]const u8, count: usize) callconv(.C) i32,
    write: ?*const fn (mgr: *FpgaMgr, buf: [*]const u8, count: usize) callconv(.C) i32,
    write_sg: ?*const fn (mgr: *FpgaMgr, sgt: *anyopaque) callconv(.C) i32,
    write_complete: ?*const fn (mgr: *FpgaMgr, info: *FpgaImage) callconv(.C) i32,
    fpga_remove: ?*const fn (mgr: *FpgaMgr) callconv(.C) void,
    groups: ?*const fn (mgr: *FpgaMgr) callconv(.C) ?*anyopaque,
    read_init: ?*const fn (mgr: *FpgaMgr, info: *FpgaImage, buf_size: *usize) callconv(.C) i32,
    read: ?*const fn (mgr: *FpgaMgr, buf: [*]u8, count: usize) callconv(.C) i32,
};

pub const FpgaMgr = struct {
    name: [64]u8,
    dev: ?*anyopaque,
    ops: FpgaManagerOps,
    state: FpgaManagerState,
    flags: FpgaManagerFlags,
    compat_id: u64,
    priv_data: ?*anyopaque,
};

pub const FpgaImage = struct {
    flags: FpgaManagerFlags,
    firmware_name: [128]u8,
    buf: ?[*]const u8,
    count: usize,
    region_id: u32,
    dev: ?*anyopaque,
    overlay: ?*anyopaque,
    config_data: ?*anyopaque,
    config_size: usize,
};

// ============================================================================
// FPGA Region
// ============================================================================

pub const FpgaRegion = struct {
    dev: ?*anyopaque,
    mgr: ?*FpgaMgr,
    bridge_list: [8]*FpgaBridge,
    num_bridges: u8,
    info: ?*FpgaImage,
    compat_id: u64,
    priv_data: ?*anyopaque,
    get_bridges: ?*const fn (region: *FpgaRegion) callconv(.C) i32,
};

// ============================================================================
// FPGA Bridge
// ============================================================================

pub const FpgaBridgeState = enum(u8) {
    Disabled = 0,
    Enabled = 1,
};

pub const FpgaBridgeOps = struct {
    enable_show: ?*const fn (bridge: *FpgaBridge) callconv(.C) FpgaBridgeState,
    enable_set: ?*const fn (bridge: *FpgaBridge, enable: bool) callconv(.C) i32,
    fpga_bridge_remove: ?*const fn (bridge: *FpgaBridge) callconv(.C) void,
};

pub const FpgaBridge = struct {
    name: [64]u8,
    dev: ?*anyopaque,
    ops: FpgaBridgeOps,
    state: FpgaBridgeState,
    priv_data: ?*anyopaque,
};

// ============================================================================
// FPGA Accelerator
// ============================================================================

pub const DflPortType = enum(u8) {
    Afu = 0,
    Error = 1,
    Uint = 2,
    Spi = 3,
    I2c = 4,
};

pub const DflFeatureId = struct {
    id_type: u16,
    id: u16,
};

pub const DflFeature = struct {
    dev: ?*anyopaque,
    id: u16,
    resource_type: u8,
    ioaddr: u64,
    irq_base: u32,
    nr_irqs: u32,
    priv_data: ?*anyopaque,
    ops: ?*DflFeatureOps,
};

pub const DflFeatureOps = struct {
    init: ?*const fn (pdev: *anyopaque, feature: *DflFeature) callconv(.C) i32,
    uinit: ?*const fn (pdev: *anyopaque, feature: *DflFeature) callconv(.C) void,
    ioctl: ?*const fn (pdev: *anyopaque, feature: *DflFeature, cmd: u32, arg: u64) callconv(.C) i64,
};

// ============================================================================
// IIO (Industrial I/O) Subsystem
// ============================================================================

pub const IioChanType = enum(u8) {
    VoltageInput = 0,
    VoltageOutput = 1,
    Current = 2,
    Power = 3,
    Accel = 4,
    AnglVel = 5,
    Magn = 6,
    Light = 7,
    Intensity = 8,
    Proximity = 9,
    Temp = 10,
    Incli = 11,
    Rot = 12,
    Angl = 13,
    Timestamp = 14,
    Capacitance = 15,
    AltvVoltage = 16,
    Cct = 17,    // Correlated Color Temperature
    Pressure = 18,
    Humidityrelative = 19,
    Activity = 20,
    Steps = 21,
    Energy = 22,
    Distance = 23,
    Velocity = 24,
    Concentration = 25,
    Resistance = 26,
    Ph = 27,
    UvIndex = 28,
    ElectricallyConnected = 29,
    Count = 30,
    Index = 31,
    Gravity = 32,
    Positionrelative = 33,
    Phase = 34,
    MassConcentration = 35,
    ChargeZxypha = 36,
};

pub const IioModifier = enum(u8) {
    None = 0,
    X = 1,
    Y = 2,
    Z = 3,
    XandY = 4,
    XandZ = 5,
    YandZ = 6,
    XandYandZ = 7,
    Sqrt = 8,
    RootSumSquared = 9,
    Light_Both = 10,
    Light_Ir = 11,
    Light_Clear = 12,
    Light_Red = 13,
    Light_Green = 14,
    Light_Blue = 15,
    Light_Uv = 16,
    Light_Duv = 17,
    Pm1 = 18,
    Pm2p5 = 19,
    Pm4 = 20,
    Pm10 = 21,
    Co2 = 22,
    Voc = 23,
    TempAmbient = 24,
    TempObject = 25,
    Pitch = 26,
    Yaw = 27,
    Roll = 28,
};

pub const IioEventType = enum(u8) {
    Thresh = 0,
    Mag = 1,
    Roc = 2,        // Rate of Change
    ThreshAdaptive = 3,
    MagAdaptive = 4,
    Change = 5,
    MagRef = 6,
};

pub const IioEventDirection = enum(u8) {
    Either = 0,
    Rising = 1,
    Falling = 2,
    None = 3,
    Singletap = 4,
    Doubletap = 5,
};

pub const IioChanInfoAttr = enum(u32) {
    Raw = 0,
    Processed = 1,
    Scale = 2,
    Offset = 3,
    Calibscale = 4,
    Calibbias = 5,
    Peak = 6,
    PeakScale = 7,
    Quadrature_correction_raw = 8,
    Average_raw = 9,
    Samp_freq = 10,
    Frequency = 11,
    Phase = 12,
    Hardwaregain = 13,
    Hysteresis = 14,
    HysteresisRelative = 15,
    Int_time = 16,
    Enable = 17,
    Calibheight = 18,
    Calibweight = 19,
    Debounce_count = 20,
    Debounce_time = 21,
    Oversampling_ratio = 22,
    Thermocouple_type = 23,
    Calibemissivity = 24,
    Decimation = 25,
};

pub const IioChanSpec = struct {
    channel_type: IioChanType,
    channel: i32,
    channel2: i32,
    address: u64,
    scan_index: i32,
    scan_type: IioScanType,
    info_mask: IioChanInfoMask,
    info_mask_shared: IioChanInfoMask,
    info_mask_shared_by_type: IioChanInfoMask,
    info_mask_shared_by_dir: IioChanInfoMask,
    info_mask_shared_by_all: IioChanInfoMask,
    event_spec: [8]IioEventSpec,
    num_event_specs: u8,
    ext_info: [8]IioExtInfo,
    num_ext_info: u8,
    extend_name: [32]u8,
    datasheet_name: [32]u8,
    modified: bool,
    indexed: bool,
    output: bool,
    differential: bool,
};

pub const IioChanInfoMask = packed struct(u32) {
    raw: bool,
    processed: bool,
    scale: bool,
    offset: bool,
    calibscale: bool,
    calibbias: bool,
    peak: bool,
    peak_scale: bool,
    quad_correction: bool,
    average_raw: bool,
    samp_freq: bool,
    frequency: bool,
    phase: bool,
    hwgain: bool,
    hysteresis: bool,
    int_time: bool,
    enable: bool,
    oversampling: bool,
    _reserved: u14,
};

pub const IioScanType = struct {
    sign: u8,              // 's' or 'u'
    realbits: u8,
    storagebits: u8,
    shift: u8,
    repeat: u8,
    endianness: IioEndian,
};

pub const IioEndian = enum(u8) {
    Little = 0,
    Big = 1,
    Cpu = 2,
};

pub const IioEventSpec = struct {
    event_type: IioEventType,
    dir: IioEventDirection,
    mask_separate: u32,
    mask_shared_by_type: u32,
    mask_shared_by_dir: u32,
    mask_shared_by_all: u32,
};

pub const IioExtInfo = struct {
    name: [32]u8,
    shared: u8,
    read: ?*const fn (indio_dev: *IioDev, private: *anyopaque, chan: *const IioChanSpec, buf: [*]u8) callconv(.C) isize,
    write: ?*const fn (indio_dev: *IioDev, private: *anyopaque, chan: *const IioChanSpec, buf: [*]const u8, len: usize) callconv(.C) isize,
};

pub const IioInfo = struct {
    read_raw: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, val: *i32, val2: *i32, mask: i64) callconv(.C) i32,
    read_raw_multi: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, max_len: i32, vals: [*]i32, val_len: *i32, mask: i64) callconv(.C) i32,
    write_raw: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, val: i32, val2: i32, mask: i64) callconv(.C) i32,
    write_raw_get_fmt: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, mask: i64) callconv(.C) i32,
    read_event_config: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, event_type: IioEventType, dir: IioEventDirection) callconv(.C) i32,
    write_event_config: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, event_type: IioEventType, dir: IioEventDirection, state: i32) callconv(.C) i32,
    read_event_value: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, event_type: IioEventType, dir: IioEventDirection, info: u32, val: *i32, val2: *i32) callconv(.C) i32,
    write_event_value: ?*const fn (indio_dev: *IioDev, chan: *const IioChanSpec, event_type: IioEventType, dir: IioEventDirection, info: u32, val: i32, val2: i32) callconv(.C) i32,
    validate_trigger: ?*const fn (indio_dev: *IioDev, trig: *IioTrigger) callconv(.C) i32,
    update_scan_mode: ?*const fn (indio_dev: *IioDev, scan_mask: *const u64) callconv(.C) i32,
    debugfs_reg_access: ?*const fn (indio_dev: *IioDev, reg: u32, writeval: u32, readval: *u32) callconv(.C) i32,
    of_xlate: ?*const fn (indio_dev: *IioDev, iiospec: *anyopaque) callconv(.C) i32,
    hwfifo_set_watermark: ?*const fn (indio_dev: *IioDev, val: u32) callconv(.C) i32,
    hwfifo_flush_to_buffer: ?*const fn (indio_dev: *IioDev) callconv(.C) i32,
};

pub const IioDev = struct {
    name: [64]u8,
    label: [64]u8,
    id: i32,
    modes: IioDevModes,
    currentmode: u32,
    dev: ?*anyopaque,
    info: IioInfo,
    setup_ops: ?*IioBufferSetupOps,
    channels: [64]IioChanSpec,
    num_channels: u32,
    masklength: u32,
    available_scan_masks: [16]u64,
    active_scan_mask: ?*u64,
    pollfunc: ?*IioPollFunc,
    pollfunc_event: ?*IioPollFunc,
    buffer: ?*IioBuffer,
    trig: ?*IioTrigger,
    scan_timestamp: bool,
    priv_data: ?*anyopaque,
};

pub const IioDevModes = packed struct(u32) {
    direct: bool,
    triggered_buffer: bool,
    hardware_buffer: bool,
    event: bool,
    _reserved: u28,
};

// ============================================================================
// IIO Trigger
// ============================================================================

pub const IioTrigger = struct {
    name: [64]u8,
    id: i32,
    ops: IioTriggerOps,
    subirqs: [8]u32,
    subirq_count: u8,
    dev: ?*anyopaque,
    use_count: u32,
    priv_data: ?*anyopaque,
};

pub const IioTriggerOps = struct {
    set_trigger_state: ?*const fn (trig: *IioTrigger, state: bool) callconv(.C) i32,
    reenable: ?*const fn (trig: *IioTrigger) callconv(.C) i32,
    validate_device: ?*const fn (trig: *IioTrigger, indio_dev: *IioDev) callconv(.C) i32,
};

pub const IioPollFunc = struct {
    name: [32]u8,
    h: ?*const fn (irq: i32, p: *anyopaque) callconv(.C) u32,
    thread: ?*const fn (irq: i32, p: *anyopaque) callconv(.C) u32,
    indio_dev: ?*IioDev,
    timestamp: i64,
};

// ============================================================================
// IIO Buffer
// ============================================================================

pub const IioBuffer = struct {
    length: u32,
    bytes_per_datum: u32,
    scan_mask: [4]u64,
    scan_timestamp: bool,
    access: IioBufferAccessFuncs,
    demux_list: [16]IioDemuxEntry,
    num_demux: u8,
    watermark: u32,
    stufftoread: bool,
    direction: IioBufferDirection,
    pollq: u64,
};

pub const IioBufferDirection = enum(u8) {
    In = 0,
    Out = 1,
};

pub const IioBufferAccessFuncs = struct {
    store_to: ?*const fn (buffer: *IioBuffer, data: [*]const u8) callconv(.C) i32,
    read: ?*const fn (buffer: *IioBuffer, n: usize, buf: [*]u8) callconv(.C) i32,
    data_available: ?*const fn (buffer: *IioBuffer) callconv(.C) usize,
    request_update: ?*const fn (buffer: *IioBuffer) callconv(.C) i32,
    set_bytes_per_datum: ?*const fn (buffer: *IioBuffer, bpd: usize) callconv(.C) i32,
    set_length: ?*const fn (buffer: *IioBuffer, length: u32) callconv(.C) i32,
    enable: ?*const fn (indio_dev: *IioDev, buffer: *IioBuffer) callconv(.C) i32,
    disable: ?*const fn (indio_dev: *IioDev, buffer: *IioBuffer) callconv(.C) i32,
    release: ?*const fn (buffer: *IioBuffer) callconv(.C) void,
};

pub const IioBufferSetupOps = struct {
    preenable: ?*const fn (indio_dev: *IioDev) callconv(.C) i32,
    postenable: ?*const fn (indio_dev: *IioDev) callconv(.C) i32,
    predisable: ?*const fn (indio_dev: *IioDev) callconv(.C) i32,
    postdisable: ?*const fn (indio_dev: *IioDev) callconv(.C) i32,
    validate_scan_mask: ?*const fn (indio_dev: *IioDev, scan_mask: *const u64) callconv(.C) bool,
};

pub const IioDemuxEntry = struct {
    from_offset: u32,
    to_offset: u32,
    length: u32,
};

// ============================================================================
// Manager
// ============================================================================

pub const FpgaIioManager = struct {
    total_fpga_managers: u32,
    total_fpga_regions: u32,
    total_fpga_bridges: u32,
    total_iio_devices: u32,
    total_iio_triggers: u32,
    total_reconfigs: u64,
    total_iio_samples: u64,
    initialized: bool,

    pub fn init() FpgaIioManager {
        return .{
            .total_fpga_managers = 0,
            .total_fpga_regions = 0,
            .total_fpga_bridges = 0,
            .total_iio_devices = 0,
            .total_iio_triggers = 0,
            .total_reconfigs = 0,
            .total_iio_samples = 0,
            .initialized = true,
        };
    }
};
