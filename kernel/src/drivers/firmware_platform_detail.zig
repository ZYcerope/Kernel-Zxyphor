// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Firmware Loading, ACPI EC, and Platform Device Detail
// Complete: firmware_class API, firmware cache, ACPI EC (Embedded Controller),
// platform_device, platform_driver, firmware tables, DMI/SMBIOS decode

const std = @import("std");

// ============================================================================
// Firmware Loading
// ============================================================================

pub const FirmwareRequestFlags = packed struct(u32) {
    nowarn: bool,
    uevent: bool,
    no_cache: bool,
    nofallback: bool,
    optional: bool,
    partial: bool,
    nowait: bool,
    _reserved: u25,
};

pub const FirmwareLoadStatus = enum(u8) {
    Unknown = 0,
    Loading = 1,
    Done = 2,
    Aborted = 3,
    Failed = 4,
    TimedOut = 5,
};

pub const Firmware = struct {
    size: u64,
    data: ?[*]const u8,
    pages: ?*anyopaque,
    priv_data: ?*anyopaque,
};

pub const FirmwareBuf = struct {
    ref_cnt: u32,
    fw_id: [256]u8,
    status: FirmwareLoadStatus,
    data: ?[*]u8,
    allocated_size: u64,
    size: u64,
    min_size: u64,
    max_size: u64,
    page_data_size: u64,
    nr_pages: u32,
    pages: ?*?*anyopaque,
    is_paged_buf: bool,
    need_uevent: bool,
    dest_device_name: [128]u8,
    loading_timeout: u32,
    creation_timestamp: u64,
    load_timestamp: u64,
    complete_timestamp: u64,
};

pub const FirmwareCache = struct {
    head: ?*FirmwareCacheEntry,
    nr_entries: u32,
    name_cnt: u32,
    max_cache_size: u64,
    current_cache_size: u64,
    pm_notify: ?*anyopaque,
};

pub const FirmwareCacheEntry = struct {
    name: [256]u8,
    buf: ?*FirmwareBuf,
    next: ?*FirmwareCacheEntry,
    timestamp: u64,
    access_count: u64,
};

pub const FirmwareFallback = struct {
    loading: bool,
    abort: bool,
    buf: ?*FirmwareBuf,
    timeout_work: ?*anyopaque,
    timeout_secs: u32,
    dev_name: [128]u8,
};

pub const FirmwareLocationType = enum(u8) {
    Builtin = 0,
    Filesystem = 1,
    Efi = 2,
    SysfsFallback = 3,
    CacheLookup = 4,
};

pub const FW_SEARCH_PATHS = [_][]const u8{
    "/lib/firmware/updates/",
    "/lib/firmware/",
    "/lib/firmware/vendor/",
};

// ============================================================================
// ACPI EC (Embedded Controller)
// ============================================================================

pub const AcpiEcStatus = packed struct(u8) {
    output_buffer_full: bool,
    input_buffer_full: bool,
    _reserved1: bool,
    cmd: bool,
    burst: bool,
    sci_evt: bool,
    smi_evt: bool,
    _reserved2: bool,
};

pub const AcpiEcCommand = enum(u8) {
    Read = 0x80,
    Write = 0x81,
    BurstEnable = 0x82,
    BurstDisable = 0x83,
    QueryEvent = 0x84,
};

pub const AcpiEc = struct {
    command_addr: u16,
    data_addr: u16,
    gpe: u32,
    global_lock: bool,
    flags: AcpiEcFlags,
    reference_count: u32,
    event_count: u64,
    burst_enabled: bool,
    sci_pending: bool,
    nr_pending_queries: u32,
    curr: ?*AcpiEcTransaction,
    handlers: [256]?*AcpiEcQueryHandler,
    nr_handlers: u32,
};

pub const AcpiEcFlags = packed struct(u32) {
    ec_started: bool,
    ec_stopped: bool,
    ec_gpe_storm: bool,
    ec_event_clearing: u2,
    _reserved: u27,
};

pub const AcpiEcTransaction = struct {
    command: AcpiEcCommand,
    wdata: ?[*]const u8,
    rdata: ?[*]u8,
    wlen: u16,
    rlen: u16,
    flags: u32,
    timestamp: u64,
};

pub const AcpiEcQueryHandler = struct {
    query_bit: u8,
    handler: ?*const fn (data: ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    handle: ?*anyopaque,
    next: ?*AcpiEcQueryHandler,
};

// ============================================================================
// Platform Device/Driver
// ============================================================================

pub const PlatformDevice = struct {
    name: [64]u8,
    id: i32,
    id_auto: bool,
    dev: Device,
    num_resources: u32,
    resource: ?[*]Resource,
    id_entry: ?*PlatformDeviceId,
    driver_override: ?[*]u8,
    mfd_cell: ?*anyopaque,
    archdata: PlatformArchData,
};

pub const Device = struct {
    parent: ?*Device,
    driver: ?*anyopaque,
    bus: ?*anyopaque,
    class: ?*anyopaque,
    type_field: ?*anyopaque,
    platform_data: ?*anyopaque,
    driver_data: ?*anyopaque,
    of_node: ?*anyopaque,
    fwnode: ?*anyopaque,
    devt: u32,
    id: u32,
    kobj: ?*anyopaque,
    init_name: ?[*]const u8,
    power: DevicePm,
    dma_mask: ?*u64,
    coherent_dma_mask: u64,
    bus_dma_limit: u64,
    dma_range_map: ?*anyopaque,
    dma_parms: ?*anyopaque,
    dma_pools: ?*anyopaque,
    dma_mem: ?*anyopaque,
    iommu_group: ?*anyopaque,
    iommu: ?*anyopaque,
    offline_disabled: bool,
    offline: bool,
    removable: DeviceRemovable,
};

pub const DeviceRemovable = enum(u8) {
    Unknown = 0,
    NotRemovable = 1,
    Removable = 2,
};

pub const DevicePm = struct {
    power_state: u32,
    can_wakeup: bool,
    async_suspend: bool,
    is_prepared: bool,
    is_suspended: bool,
    is_noirq_suspended: bool,
    is_late_suspended: bool,
    no_pm: bool,
    early_init: bool,
    direct_complete: bool,
    runtime_auto: bool,
    ignore_children: bool,
    no_callbacks: bool,
    irq_safe: bool,
    use_autosuspend: bool,
    timer_autosuspends: bool,
    runtime_error: i32,
    usage_count: i32,
    child_count: i32,
    disable_depth: i32,
    idle_notification: bool,
    request_pending: bool,
    deferred_resume: bool,
    suspend_timer: u64,
    timer_expires: u64,
    last_busy: u64,
    active_time: u64,
    suspended_time: u64,
    accounting_timestamp: u64,
    autosuspend_delay: i32,
};

pub const Resource = struct {
    start: u64,
    end: u64,
    name: ?[*]const u8,
    flags: ResourceFlags,
    desc: u64,
    parent: ?*Resource,
    sibling: ?*Resource,
    child: ?*Resource,
};

pub const ResourceFlags = packed struct(u64) {
    type_bits: u8,
    io: bool,
    mem: bool,
    reg: bool,
    irq: bool,
    dma: bool,
    bus: bool,
    prefetch: bool,
    readonly: bool,
    cacheable: bool,
    rangelength: bool,
    shadowable: bool,
    sizealign: bool,
    startalign: bool,
    window: bool,
    unset: bool,
    exclusive: bool,
    disabled: bool,
    busy: bool,
    _reserved: u30,
};

pub const PlatformDeviceId = struct {
    name: [20]u8,
    driver_data: u64,
};

pub const PlatformArchData = struct {
    dma_coherent: bool,
};

pub const PlatformDriver = struct {
    probe: ?*const fn (pdev: *PlatformDevice) callconv(.C) i32,
    remove: ?*const fn (pdev: *PlatformDevice) callconv(.C) i32,
    remove_new: ?*const fn (pdev: *PlatformDevice) callconv(.C) void,
    shutdown: ?*const fn (pdev: *PlatformDevice) callconv(.C) void,
    suspend: ?*const fn (pdev: *PlatformDevice, state: u32) callconv(.C) i32,
    resume: ?*const fn (pdev: *PlatformDevice) callconv(.C) i32,
    driver: DriverBase,
    id_table: ?[*]const PlatformDeviceId,
    prevent_deferred_probe: bool,
    driver_managed_dma: bool,
};

pub const DriverBase = struct {
    name: [64]u8,
    bus: ?*anyopaque,
    owner: ?*anyopaque,
    mod_name: ?[*]const u8,
    suppress_bind_attrs: bool,
    probe_type: ProbeType,
    of_match_table: ?*anyopaque,
    acpi_match_table: ?*anyopaque,
    pm: ?*DevPmOps,
};

pub const ProbeType = enum(u8) {
    DefaultStrategy = 0,
    PreferAsync = 1,
    ForceSync = 2,
};

pub const DevPmOps = struct {
    prepare: ?*const fn (dev: *Device) callconv(.C) i32,
    complete: ?*const fn (dev: *Device) callconv(.C) void,
    suspend: ?*const fn (dev: *Device) callconv(.C) i32,
    resume: ?*const fn (dev: *Device) callconv(.C) i32,
    freeze: ?*const fn (dev: *Device) callconv(.C) i32,
    thaw: ?*const fn (dev: *Device) callconv(.C) i32,
    poweroff: ?*const fn (dev: *Device) callconv(.C) i32,
    restore: ?*const fn (dev: *Device) callconv(.C) i32,
    suspend_late: ?*const fn (dev: *Device) callconv(.C) i32,
    resume_early: ?*const fn (dev: *Device) callconv(.C) i32,
    freeze_late: ?*const fn (dev: *Device) callconv(.C) i32,
    thaw_early: ?*const fn (dev: *Device) callconv(.C) i32,
    poweroff_late: ?*const fn (dev: *Device) callconv(.C) i32,
    restore_early: ?*const fn (dev: *Device) callconv(.C) i32,
    suspend_noirq: ?*const fn (dev: *Device) callconv(.C) i32,
    resume_noirq: ?*const fn (dev: *Device) callconv(.C) i32,
    freeze_noirq: ?*const fn (dev: *Device) callconv(.C) i32,
    thaw_noirq: ?*const fn (dev: *Device) callconv(.C) i32,
    poweroff_noirq: ?*const fn (dev: *Device) callconv(.C) i32,
    restore_noirq: ?*const fn (dev: *Device) callconv(.C) i32,
    runtime_suspend: ?*const fn (dev: *Device) callconv(.C) i32,
    runtime_resume: ?*const fn (dev: *Device) callconv(.C) i32,
    runtime_idle: ?*const fn (dev: *Device) callconv(.C) i32,
};

// ============================================================================
// DMI/SMBIOS
// ============================================================================

pub const DmiType = enum(u8) {
    BiosInfo = 0,
    SystemInfo = 1,
    BaseBoardInfo = 2,
    ChassisInfo = 3,
    ProcessorInfo = 4,
    MemController = 5,
    MemModule = 6,
    CacheInfo = 7,
    PortConnector = 8,
    SystemSlots = 9,
    OnboardDevices = 10,
    OemStrings = 11,
    SysConfigOptions = 12,
    BiosLanguage = 13,
    GroupAssociations = 14,
    SystemEventLog = 15,
    PhysicalMemArray = 16,
    MemoryDevice = 17,
    MemoryError32 = 18,
    MemMappedAddress = 19,
    MemDeviceMappedAddr = 20,
    BuiltinPointing = 21,
    PortableBattery = 22,
    SystemReset = 23,
    HardwareSecurity = 24,
    SystemPowerControls = 25,
    VoltageProbe = 26,
    CoolingDevice = 27,
    TemperatureProbe = 28,
    ElectricalCurrentProbe = 29,
    OobRemoteAccess = 30,
    BootIntegrity = 31,
    SystemBoot = 32,
    MemoryError64 = 33,
    ManagementDevice = 34,
    ManagementDevComponent = 35,
    ManagementDevThreshold = 36,
    MemoryChannel = 37,
    IpmiDevice = 38,
    SystemPowerSupply = 39,
    Additional = 40,
    OnboardDevicesExt = 41,
    ManagementCtrlHostIf = 42,
    TpmDevice = 43,
    ProcessorAdditional = 44,
    FirmwareInventory = 45,
    StringProperty = 46,
    Inactive = 126,
    EndOfTable = 127,
};

pub const DmiHeader = packed struct {
    type_field: u8,
    length: u8,
    handle: u16,
};

pub const DmiBiosInfo = struct {
    header: DmiHeader,
    vendor: [64]u8,
    version: [64]u8,
    start_segment: u16,
    release_date: [32]u8,
    rom_size: u8,
    characteristics: u64,
    ext_chars: [2]u8,
    major_release: u8,
    minor_release: u8,
    ec_major_release: u8,
    ec_minor_release: u8,
    extended_rom_size: u16,
};

pub const DmiSystemInfo = struct {
    header: DmiHeader,
    manufacturer: [64]u8,
    product_name: [64]u8,
    version: [64]u8,
    serial_number: [64]u8,
    uuid: [16]u8,
    wake_up_type: u8,
    sku_number: [64]u8,
    family: [64]u8,
};

pub const DmiMemoryDevice = struct {
    header: DmiHeader,
    physical_memory_array_handle: u16,
    memory_error_info_handle: u16,
    total_width: u16,
    data_width: u16,
    size: u16,
    form_factor: MemFormFactor,
    device_set: u8,
    device_locator: [32]u8,
    bank_locator: [32]u8,
    memory_type: MemType,
    type_detail: u16,
    speed_mhz: u16,
    manufacturer: [64]u8,
    serial_number: [32]u8,
    asset_tag: [32]u8,
    part_number: [32]u8,
    rank: u8,
    configured_speed_mhz: u16,
    minimum_voltage: u16,
    maximum_voltage: u16,
    configured_voltage: u16,
    memory_technology: u8,
    memory_operating_mode: u16,
    firmware_version: [32]u8,
    module_manufacturer_id: u16,
    module_product_id: u16,
    memory_subsystem_ctrl_mfr_id: u16,
    memory_subsystem_ctrl_prod_id: u16,
    non_volatile_size: u64,
    volatile_size: u64,
    cache_size: u64,
    logical_size: u64,
    extended_speed_mhz: u32,
    extended_configured_speed_mhz: u32,
    pmic0_manufacturer_id: u16,
    pmic0_revision_number: u16,
};

pub const MemFormFactor = enum(u8) {
    Other = 0x01,
    Unknown = 0x02,
    SIMM = 0x03,
    SIP = 0x04,
    Chip = 0x05,
    DIP = 0x06,
    ZIP = 0x07,
    ProprietaryCard = 0x08,
    DIMM = 0x09,
    TSOP = 0x0A,
    RowOfChips = 0x0B,
    RIMM = 0x0C,
    SODIMM = 0x0D,
    SRIMM = 0x0E,
    FBDIMM = 0x0F,
    Die = 0x10,
};

pub const MemType = enum(u8) {
    Other = 0x01,
    Unknown = 0x02,
    DRAM = 0x03,
    EDRAM = 0x04,
    VRAM = 0x05,
    SRAM = 0x06,
    RAM = 0x07,
    ROM = 0x08,
    FLASH = 0x09,
    EEPROM = 0x0A,
    FEPROM = 0x0B,
    EPROM = 0x0C,
    CDRAM = 0x0D,
    _3DRAM = 0x0E,
    SDRAM = 0x0F,
    SGRAM = 0x10,
    RDRAM = 0x11,
    DDR = 0x12,
    DDR2 = 0x13,
    DDR2_FB = 0x14,
    DDR3 = 0x18,
    FBD2 = 0x19,
    DDR4 = 0x1A,
    LPDDR = 0x1B,
    LPDDR2 = 0x1C,
    LPDDR3 = 0x1D,
    LPDDR4 = 0x1E,
    LogicalNonVolatile = 0x1F,
    HBM = 0x20,
    HBM2 = 0x21,
    DDR5 = 0x22,
    LPDDR5 = 0x23,
    HBM3 = 0x24,
};

// ============================================================================
// Manager
// ============================================================================

pub const FirmwarePlatformManager = struct {
    total_firmware_loads: u64,
    total_firmware_failures: u64,
    total_cache_hits: u64,
    total_cache_misses: u64,
    total_ec_transactions: u64,
    total_ec_errors: u64,
    total_platform_devices: u32,
    total_platform_drivers: u32,
    dmi_decoded: bool,
    initialized: bool,

    pub fn init() FirmwarePlatformManager {
        return .{
            .total_firmware_loads = 0,
            .total_firmware_failures = 0,
            .total_cache_hits = 0,
            .total_cache_misses = 0,
            .total_ec_transactions = 0,
            .total_ec_errors = 0,
            .total_platform_devices = 0,
            .total_platform_drivers = 0,
            .dmi_decoded = false,
            .initialized = true,
        };
    }
};
