// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Watchdog, RTC Advanced, NVDIMM/Persistent Memory
// Hardware watchdog, software watchdog, pretimeout governors,
// RTC subsystem, NVDIMM management, namespaces, BTT, PFN, DAX
// More advanced than Linux 2026 storage/watchdog subsystem

const std = @import("std");

// ============================================================================
// Watchdog Timer
// ============================================================================

pub const WatchdogInfoFlags = packed struct(u32) {
    overheat: bool = false,
    fan_fault: bool = false,
    extern1: bool = false,
    extern2: bool = false,
    powerunder: bool = false,
    card_reset: bool = false,
    powerover: bool = false,
    settimeout: bool = false,
    magicclose: bool = false,
    pretimeout: bool = false,
    alarmonly: bool = false,
    keepaliveping: bool = false,
    // Zxyphor
    zxy_predictive: bool = false,
    _reserved: u19 = 0,
};

pub const WatchdogStatus = enum(u8) {
    stopped = 0,
    running = 1,
    pretimeout = 2,
    expired = 3,
    rebooting = 4,
};

pub const WatchdogHwType = enum(u8) {
    unknown = 0,
    software = 1,          // softdog
    itco = 2,              // Intel TCO
    sp5100_tco = 3,        // AMD SP5100 TCO
    i6300esb = 4,
    sch311x = 5,
    wdt87x = 6,
    diag288 = 7,           // s390
    imx2 = 8,
    bcm2835 = 9,           // Raspberry Pi
    // Zxyphor
    zxy_watchdog = 20,
};

pub const WatchdogDevice = struct {
    id: u32,
    name: [64]u8,
    hw_type: WatchdogHwType,
    // Status
    status: WatchdogStatus,
    running: bool,
    // Timeout
    timeout_secs: u32,
    min_timeout_secs: u32,
    max_timeout_secs: u32,
    // Pretimeout
    pretimeout_secs: u32,
    pretimeout_governor: PretimeoutGovernor,
    // Boot status
    bootstatus: u32,
    // Features
    info_flags: WatchdogInfoFlags,
    // Stats
    ping_count: u64,
    timeout_count: u64,
    pretimeout_count: u64,
    last_ping_ns: u64,
    last_hw_heartbeat_ns: u64,
    // NMI
    nmi_watchdog: bool,
    nmi_count: u64,
};

pub const PretimeoutGovernor = enum(u8) {
    noop = 0,
    panic = 1,
    // Zxyphor
    zxy_graceful = 10,
};

// Softdog (software watchdog)
pub const SoftdogConfig = struct {
    enabled: bool,
    timeout_secs: u32,
    nowayout: bool,
    soft_panic: bool,
    soft_margin_secs: u32,
};

// NMI watchdog (hardlockup/softlockup)
pub const NmiWatchdogConfig = struct {
    enabled: bool,
    // Hard lockup (NMI)
    hardlockup_enabled: bool,
    hardlockup_threshold_secs: u32,
    hardlockup_count: u64,
    // Soft lockup
    softlockup_enabled: bool,
    softlockup_threshold_secs: u32,
    softlockup_count: u64,
    softlockup_all_cpu_backtrace: bool,
    softlockup_panic: bool,
    // Hung task
    hung_task_enabled: bool,
    hung_task_timeout_secs: u32,
    hung_task_check_interval_secs: u32,
    hung_task_warnings: i32,
    hung_task_panic: bool,
    hung_task_count: u64,
};

// ============================================================================
// RTC (Real-Time Clock) Subsystem
// ============================================================================

pub const RtcTime = struct {
    sec: u8,       // 0-59
    min: u8,       // 0-59
    hour: u8,      // 0-23
    mday: u8,      // 1-31
    mon: u8,       // 0-11
    year: u16,     // Year - 1900 (for compat)
    wday: u8,      // 0-6 (Sunday = 0)
    yday: u16,     // 0-365

    pub fn actual_year(self: *const RtcTime) u16 {
        return self.year + 1900;
    }

    pub fn actual_month(self: *const RtcTime) u8 {
        return self.mon + 1;
    }
};

pub const RtcAlarm = struct {
    time: RtcTime,
    enabled: bool,
    pending: bool,
};

pub const RtcWkalrm = struct {
    enabled: bool,
    pending: bool,
    time: RtcTime,
};

pub const RtcFeatures = packed struct(u32) {
    alarm: bool = false,
    alarm_res_minute: bool = false,
    need_week_day: bool = false,
    alarm_res_2s: bool = false,
    update_interrupt: bool = false,
    correction: bool = false,
    backup_switch_mode: bool = false,
    alarm_wakeup: bool = false,
    // Zxyphor
    zxy_high_precision: bool = false,
    _reserved: u23 = 0,
};

pub const RtcDevice = struct {
    id: u32,
    name: [64]u8,
    // Features
    features: RtcFeatures,
    // Class info
    max_user_freq: u32,
    // Current time
    current_time: RtcTime,
    // Alarm
    alarm: RtcAlarm,
    // UIE (Update Interrupt Enable)
    uie_enabled: bool,
    uie_count: u64,
    // AIE (Alarm Interrupt Enable)
    aie_enabled: bool,
    aie_count: u64,
    // Offset (parts per billion)
    offset_ppb: i32,
    // Range
    range_min: i64,     // Seconds since epoch
    range_max: i64,
    // Stats
    read_count: u64,
    set_count: u64,
    alarm_count: u64,
    irq_count: u64,
};

// ============================================================================
// NVDIMM (Non-Volatile DIMMs)
// ============================================================================

pub const NvdimmType = enum(u8) {
    pmem = 0,            // Persistent memory
    blk = 1,             // Block mode
    nvdimm_n = 2,        // NVDIMM-N (DRAM + flash)
    nvdimm_p = 3,        // NVDIMM-P (persistent DDR)
    // Intel Optane
    intel_optane = 10,
    // CXL
    cxl_pmem = 20,
    // Zxyphor
    zxy_nvmem = 30,
};

pub const NvdimmFlags = packed struct(u32) {
    readonly: bool = false,
    locked: bool = false,
    aliased: bool = false,
    labeling: bool = false,
    map_error: bool = false,
    // Zxyphor
    zxy_encrypted: bool = false,
    _reserved: u26 = 0,
};

pub const NvdimmDevice = struct {
    id: u32,
    name: [64]u8,
    nvdimm_type: NvdimmType,
    flags: NvdimmFlags,
    // Size
    size: u64,
    available_size: u64,
    // Firmware
    firmware_version: [32]u8,
    // State
    state: u8,            // 0=not enabled, 1=enabled
    // Health
    health_state: NvdimmHealth,
    // Label
    label_version: [4]u8,
    config_size: u32,
    max_config_size: u32,
    // Performance
    read_bandwidth_mbps: u32,
    write_bandwidth_mbps: u32,
    read_latency_ns: u32,
    write_latency_ns: u32,
    // Media errors
    media_errors: u64,
    max_media_errors: u64,
    // Lifespan
    life_used_pct: u8,
    temperature_celsius: i16,
    dirty_shutdown_count: u32,
    // ARS (Address Range Scrub)
    ars_status: u8,
    ars_progress_pct: u8,
};

pub const NvdimmHealth = enum(u8) {
    ok = 0,
    nonfatal = 1,
    critical = 2,
    fatal = 3,
    unknown = 4,
};

// ============================================================================
// NVDIMM Namespace
// ============================================================================

pub const NdNamespaceType = enum(u8) {
    pmem = 0,            // Persistent memory namespace
    blk = 1,             // Block namespace
    io = 2,              // I/O namespace (raw)
    dax = 3,             // Device DAX
};

pub const NdNamespaceMode = enum(u8) {
    raw = 0,             // Raw access
    fsdax = 1,           // Filesystem DAX
    devdax = 2,          // Device DAX
    sector = 3,          // Sector mode (BTT)
};

pub const NdNamespace = struct {
    id: u32,
    dev_name: [32]u8,
    ns_type: NdNamespaceType,
    mode: NdNamespaceMode,
    // UUID
    uuid: [16]u8,
    // Size
    size: u64,
    // Location
    region_id: u32,
    // Sector size
    sector_size: u32,
    // DPA (DIMM Physical Address)
    dpa_base: u64,
    dpa_size: u64,
    // Interleave
    num_mappings: u8,
    // Alt name
    alt_name: [64]u8,
    // Force
    force_raw: bool,
};

// ============================================================================
// BTT (Block Translation Table)
// ============================================================================

pub const BttInfo = struct {
    // UUID
    uuid: [16]u8,
    parent_uuid: [16]u8,
    // Version
    major: u16,
    minor: u16,
    // Layout
    external_lbasize: u32,
    internal_lbasize: u32,
    nfree: u32,
    infosize: u32,
    nextoff: u64,
    dataoff: u64,
    mapoff: u64,
    flogoff: u64,
    infooff: u64,
    // Stats
    nr_arenas: u32,
    total_nlba: u64,
};

// ============================================================================
// PFN (Page Frame Number) Device
// ============================================================================

pub const PfnMode = enum(u8) {
    none = 0,
    ram = 1,
    pmem = 2,
};

pub const PfnInfo = struct {
    uuid: [16]u8,
    parent_uuid: [16]u8,
    mode: PfnMode,
    dataoff: u64,
    npfns: u64,
    align: u32,
};

// ============================================================================
// NVDIMM Security
// ============================================================================

pub const NvdimmSecurityState = enum(u8) {
    disabled = 0,
    unlocked = 1,
    locked = 2,
    frozen = 3,
    overwrite = 4,
};

pub const NvdimmSecurityOps = enum(u8) {
    enable = 0,
    disable = 1,
    freeze = 2,
    unlock = 3,
    erase = 4,
    overwrite = 5,
    master_passphrase = 6,
};

pub const NvdimmSecurity = struct {
    state: NvdimmSecurityState,
    // Key management
    master_passphrase_set: bool,
    user_passphrase_set: bool,
    // Overwrite
    overwrite_in_progress: bool,
    overwrite_pct: u8,
    // Freeze
    frozen: bool,
};

// ============================================================================
// Persistent Memory Region
// ============================================================================

pub const NdRegionType = enum(u8) {
    pmem = 0,
    volatile_region = 1,
    blk = 2,
};

pub const NdRegion = struct {
    id: u32,
    region_type: NdRegionType,
    // Size
    size: u64,
    available_size: u64,
    max_available_extent: u64,
    // Mappings
    num_mappings: u8,
    // Interleave
    interleave_ways: u8,
    interleave_idx: u8,
    // Performance
    read_bandwidth_mbps: u32,
    write_bandwidth_mbps: u32,
    read_latency_ns: u32,
    write_latency_ns: u32,
    // NUMA
    numa_node: i32,
    // Persistence domain
    persistence_domain: u8,
    // Deep flush
    deep_flush: bool,
    // Badblocks
    nr_badblocks: u32,
    // Namespaces
    nr_namespaces: u32,
};

// ============================================================================
// ARS (Address Range Scrub)
// ============================================================================

pub const ArsStatus = enum(u8) {
    idle = 0,
    in_progress = 1,
    complete = 2,
    error = 3,
};

pub const ArsResult = struct {
    status: ArsStatus,
    start_addr: u64,
    length: u64,
    restart_addr: u64,
    restart_length: u64,
    nr_records: u32,
    // Records
    records: [256]ArsErrorRecord,

    pub fn has_errors(self: *const ArsResult) bool {
        return self.nr_records > 0;
    }
};

pub const ArsErrorRecord = struct {
    handle: u32,
    flags: u32,
    err_address: u64,
    length: u64,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const WatchdogNvdimmSubsystem = struct {
    // Watchdog
    nr_watchdogs: u32,
    softdog_config: SoftdogConfig,
    nmi_watchdog: NmiWatchdogConfig,
    // RTC
    nr_rtc_devices: u32,
    // NVDIMM
    nr_nvdimms: u32,
    nr_regions: u32,
    nr_namespaces: u32,
    total_pmem_bytes: u64,
    total_pmem_available: u64,
    // ARS
    ars_active: bool,
    total_ars_scans: u64,
    total_errors_found: u64,
    // Security
    nr_locked_nvdimms: u32,
    // NFIT (NVDIMM Firmware Interface Table)
    nfit_present: bool,
    nfit_version: u16,
    // Stats
    total_watchdog_pings: u64,
    total_watchdog_timeouts: u64,
    total_rtc_reads: u64,
    total_pmem_reads: u64,
    total_pmem_writes: u64,
    total_pmem_errors: u64,
    // Zxyphor
    zxy_nvdimm_compression: bool,
    zxy_smart_watchdog: bool,
    initialized: bool,
};
