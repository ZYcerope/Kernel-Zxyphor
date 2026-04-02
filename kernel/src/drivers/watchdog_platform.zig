// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Watchdog Timer & Platform Bus Detail
// Hardware watchdog, softdog, pretimeout governors, platform bus model,
// platform device/driver registration, device tree matching

const std = @import("std");

// ============================================================================
// Watchdog Core
// ============================================================================

pub const WatchdogStatus = enum(u8) {
    Stopped = 0,
    Running = 1,
    Suspended = 2,
    Error = 3,
};

pub const WatchdogInfoFlags = packed struct(u32) {
    overheat: bool,         // Reset due to CPU overheat
    fan_fault: bool,
    extern1: bool,
    extern2: bool,
    power_under: bool,
    card_reset: bool,
    power_over: bool,
    set_timeout: bool,
    magic_close: bool,
    pretimeout: bool,
    alive_keepalive: bool,
    _reserved: u21,
};

pub const WatchdogInfo = struct {
    identity: [32]u8,
    firmware_version: u32,
    options: WatchdogInfoFlags,
};

pub const WatchdogOps = struct {
    owner: usize,
    start: ?*const fn (*WatchdogDevice) i32,
    stop: ?*const fn (*WatchdogDevice) i32,
    ping: ?*const fn (*WatchdogDevice) i32,
    status: ?*const fn (*WatchdogDevice) u32,
    set_timeout: ?*const fn (*WatchdogDevice, u32) i32,
    get_timeleft: ?*const fn (*WatchdogDevice) u32,
    set_pretimeout: ?*const fn (*WatchdogDevice, u32) i32,
    restart: ?*const fn (*WatchdogDevice, u64, ?*anyopaque) i32,
    ioctl: ?*const fn (*WatchdogDevice, u32, u64) i32,
};

pub const WatchdogDevice = struct {
    id: u32,
    parent: usize,
    info: WatchdogInfo,
    ops: ?*const WatchdogOps,
    bootstatus: u32,
    timeout: u32,
    pretimeout: u32,
    min_timeout: u32,
    max_timeout: u32,
    min_hw_heartbeat_ms: u32,
    max_hw_heartbeat_ms: u32,
    reboot_nb: usize,       // Notifier block
    restart_nb: usize,
    governor: ?*WdtPretimeoutGovernor,
    status_bits: WdtStatusBits,
    open_deadline: u64,
    last_keepalive: u64,
    last_hw_keepalive: u64,
    deferred_work: usize,   // Work_struct
};

pub const WdtStatusBits = packed struct(u32) {
    active: bool,
    dev_open: bool,
    allow_release: bool,
    no_way_out: bool,
    unregistered: bool,
    hrt_running: bool,
    no_reboot: bool,
    handle_boot_enabled: bool,
    _reserved: u24,
};

pub const WdtPretimeoutGovernor = struct {
    name: [32]u8,
    pretimeout: ?*const fn (*WatchdogDevice) void,
};

pub const WatchdogPretimeoutAction = enum(u8) {
    Nothing = 0,
    Panic = 1,
    Nmi = 2,
};

// ============================================================================
// Softdog / Software Watchdog
// ============================================================================

pub const SoftdogConfig = struct {
    soft_margin: u32,       // Default timeout in seconds
    soft_noboot: bool,
    soft_panic: bool,
    nowayout: bool,
};

// ============================================================================
// iTCO Watchdog (Intel TCO)
// ============================================================================

pub const ItcoVersion = enum(u8) {
    V1 = 1,    // ICH5, ICH6
    V2 = 2,    // ICH7+
    V3 = 3,    // Lewisburg+
    V4 = 4,    // Tiger Lake+
    V6 = 6,    // Meteor Lake+
};

pub const ItcoWdt = struct {
    version: ItcoVersion,
    tco_res: usize,         // TCO register base
    smi_res: usize,         // SMI register base
    gcs_pmc_res: usize,     // GCS/PMC register base
    heartbeat: u32,
    no_reboot: bool,
    update_no_reboot_bit: ?*const fn (usize, bool) i32,
};

// ============================================================================
// SP805 Watchdog (ARM)
// ============================================================================

pub const Sp805Load = packed struct(u32) { value: u32 };
pub const Sp805Value = packed struct(u32) { value: u32 };
pub const Sp805Control = packed struct(u32) {
    inten: bool,
    resen: bool,
    _reserved: u30,
};

// ============================================================================
// Platform Bus
// ============================================================================

pub const PlatformBusType = struct {
    name: [16]u8,
    dev_groups: [8]usize,
    match_fn: ?*const fn (usize, usize) i32,
    uevent: ?*const fn (usize, usize) i32,
    probe: ?*const fn (usize) i32,
    remove: ?*const fn (usize) void,
    shutdown: ?*const fn (usize) void,
    suspend: ?*const fn (usize, u32) i32,
    resume: ?*const fn (usize) i32,
    pm_ops: ?*const DevPmOps,
};

pub const PlatformDevice = struct {
    name: [64]u8,
    id: i32,
    id_auto: bool,
    dev: DeviceCore,
    num_resources: u32,
    resources: [16]Resource,
    id_entry: ?*PlatformDeviceId,
    of_node: usize,         // device_node pointer
    driver_override: [64]u8,
    mfd_cell: usize,
    archdata: PlatformArchData,
};

pub const PlatformDriver = struct {
    probe: ?*const fn (*PlatformDevice) i32,
    remove: ?*const fn (*PlatformDevice) i32,
    remove_new: ?*const fn (*PlatformDevice) void,
    shutdown: ?*const fn (*PlatformDevice) void,
    suspend: ?*const fn (*PlatformDevice, u32) i32,
    resume: ?*const fn (*PlatformDevice) i32,
    driver: DriverCore,
    id_table: [32]PlatformDeviceId,
    prevent_deferred_probe: bool,
    dev_groups: [8]usize,
};

pub const PlatformDeviceId = struct {
    name: [20]u8,
    driver_data: u64,
};

pub const PlatformArchData = struct {
    dma_mask: u64,
    coherent_dma_mask: u64,
};

// ============================================================================
// Resource Management
// ============================================================================

pub const ResourceFlags = packed struct(u64) {
    io: bool,
    mem: bool,
    irq: bool,
    dma: bool,
    bus: bool,
    prefetchable: bool,
    readonly: bool,
    cacheable: bool,
    shadow: bool,
    startalign: bool,
    sizealign: bool,
    busy: bool,
    disabled: bool,
    unset: bool,
    auto: bool,
    window: bool,
    exclusive: bool,
    _reserved: u47,
};

pub const Resource = struct {
    start: u64,
    end: u64,
    name: [32]u8,
    flags: ResourceFlags,
    desc: u64,
    parent: ?*Resource,
    sibling: ?*Resource,
    child: ?*Resource,
};

// ============================================================================
// Device Core (Stripped)
// ============================================================================

pub const DeviceCore = struct {
    parent: ?*DeviceCore,
    init_name: [64]u8,
    bus_type: usize,
    driver: usize,
    platform_data: usize,
    driver_data: usize,
    of_node: usize,
    fwnode: usize,
    numa_node: i32,
    dma_mask: ?*u64,
    coherent_dma_mask: u64,
    dma_range_map: usize,
    dma_pools: usize,
    dma_mem: usize,
    archdata: u64,
    devt: u32,              // dev_t
    id: u32,
    class_id: u32,
    groups: [8]usize,
    release: ?*const fn (*DeviceCore) void,
    power: DevicePower,
    pm_domain: usize,
    removable: bool,
    offline_disabled: bool,
    offline: bool,
    dead: bool,
};

pub const DevicePower = struct {
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
    memalloc_noio: bool,
    runtime_status: u32,
    runtime_error: i32,
    autosuspend_delay: i32,
    last_busy: u64,
    active_time: u64,
    suspended_time: u64,
    accounting_timestamp: u64,
    suspend_timer: usize,
    request_pending: bool,
    deferred_resume: bool,
    needs_force_resume: bool,
    disable_depth: u32,
};

pub const DriverCore = struct {
    name: [64]u8,
    bus: usize,
    owner: usize,
    mod_name: [64]u8,
    suppress_bind_attrs: bool,
    probe_type: u32,
    of_match_table: [16]OfDeviceId,
    acpi_match_table: [16]AcpiDeviceId,
    probe: ?*const fn (usize) i32,
    sync_state: ?*const fn (usize) void,
    remove: ?*const fn (usize) void,
    shutdown: ?*const fn (usize) void,
    suspend: ?*const fn (usize, u32) i32,
    resume: ?*const fn (usize) i32,
    groups: [8]usize,
    pm: ?*const DevPmOps,
    coredump: ?*const fn (usize) void,
};

pub const OfDeviceId = struct {
    name: [32]u8,
    device_type: [32]u8,
    compatible: [128]u8,
    data: u64,
};

pub const AcpiDeviceId = struct {
    id: [16]u8,
    driver_data: u64,
    cls: u32,
    cls_mask: u32,
};

pub const DevPmOps = struct {
    prepare: ?*const fn (usize) i32,
    complete: ?*const fn (usize) void,
    suspend: ?*const fn (usize) i32,
    resume: ?*const fn (usize) i32,
    freeze: ?*const fn (usize) i32,
    thaw: ?*const fn (usize) i32,
    poweroff: ?*const fn (usize) i32,
    restore: ?*const fn (usize) i32,
    suspend_late: ?*const fn (usize) i32,
    resume_early: ?*const fn (usize) i32,
    freeze_late: ?*const fn (usize) i32,
    thaw_early: ?*const fn (usize) i32,
    poweroff_late: ?*const fn (usize) i32,
    restore_early: ?*const fn (usize) i32,
    suspend_noirq: ?*const fn (usize) i32,
    resume_noirq: ?*const fn (usize) i32,
    freeze_noirq: ?*const fn (usize) i32,
    thaw_noirq: ?*const fn (usize) i32,
    poweroff_noirq: ?*const fn (usize) i32,
    restore_noirq: ?*const fn (usize) i32,
    runtime_suspend: ?*const fn (usize) i32,
    runtime_resume: ?*const fn (usize) i32,
    runtime_idle: ?*const fn (usize) i32,
};

// ============================================================================
// Device Tree Overlay
// ============================================================================

pub const DtOverlayStatus = enum(u8) {
    None = 0,
    Applied = 1,
    Pending = 2,
    Failed = 3,
    Reverted = 4,
};

pub const DtOverlay = struct {
    id: u32,
    status: DtOverlayStatus,
    data: [*]u8,
    data_len: u32,
    target_node: usize,
    symbols_node: usize,
    fixups_done: bool,
    phandle_delta: u32,
};

// ============================================================================
// Manager
// ============================================================================

pub const WatchdogPlatformManager = struct {
    total_watchdogs: u32,
    total_platform_devs: u32,
    total_platform_drvs: u32,
    total_resources: u32,
    total_overlays: u32,
    total_resets: u64,
    total_keepalives: u64,
    wdt_nowayout: bool,
    initialized: bool,

    pub fn init() WatchdogPlatformManager {
        return .{
            .total_watchdogs = 0,
            .total_platform_devs = 0,
            .total_platform_drvs = 0,
            .total_resources = 0,
            .total_overlays = 0,
            .total_resets = 0,
            .total_keepalives = 0,
            .wdt_nowayout = true,
            .initialized = true,
        };
    }
};
