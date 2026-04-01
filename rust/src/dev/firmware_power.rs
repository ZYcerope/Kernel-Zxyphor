// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Rust - Device Firmware and Power Management
// Firmware loading framework, device power states, runtime PM,
// system sleep states, wake-on events, device links, driver model power
// More advanced than Linux 2026 driver PM subsystem

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// ============================================================================
// Firmware Loading
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FirmwareState {
    Unknown = 0,
    Loading = 1,
    Done = 2,
    Aborted = 3,
    Failed = 4,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum FirmwareFlags {
    None = 0,
    Optional = 1 << 0,          // Don't fail if not found
    Nowait = 1 << 1,            // Async load
    Uevent = 1 << 2,            // Send uevent for userspace loading
    NoCacheCleanup = 1 << 3,
    NoWarnIfNotFound = 1 << 4,
    NofallbackSysfs = 1 << 5,
}

pub struct FirmwareDesc {
    pub name: [256; u8],
    pub name_len: u16,
    pub state: FirmwareState,
    pub flags: u32,
    pub size: u64,
    pub data_phys: u64,         // Physical address of firmware data
    // Versioning
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
    pub build_date: u32,
    // Integrity
    pub sha256: [32; u8],
    pub signature_verified: bool,
    // Loading
    pub load_time_ns: u64,
    pub retry_count: u32,
    // Cache
    pub cached: bool,
    pub cache_size: u64,
}

pub struct FirmwareCache {
    pub nr_cached: u32,
    pub total_cached_bytes: u64,
    pub max_cache_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
}

// ============================================================================
// Device Power States
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DevicePmState {
    D0 = 0,             // Fully on
    D1 = 1,             // Light sleep
    D2 = 2,             // Deep sleep
    D3hot = 3,          // Software off (power still supplied)
    D3cold = 4,         // Hardware off (no power)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuntimePmStatus {
    Active = 0,
    Resuming = 1,
    Suspended = 2,
    Suspending = 3,
    Error = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PmRequest {
    None = 0,
    Idle = 1,
    Suspend = 2,
    Autosuspend = 3,
    Resume = 4,
}

// ============================================================================
// Runtime PM
// ============================================================================

pub struct RuntimePmInfo {
    pub status: RuntimePmStatus,
    pub request: PmRequest,
    pub usage_count: i32,
    pub child_count: i32,
    pub disable_depth: u32,
    // Autosuspend
    pub autosuspend_delay_ms: i32,
    pub last_busy_ns: u64,
    pub active_time_ns: u64,
    pub suspended_time_ns: u64,
    // Counters
    pub suspend_count: u64,
    pub resume_count: u64,
    pub idle_notification_count: u64,
    // Errors
    pub runtime_error: i32,
    // Flags
    pub no_callbacks: bool,
    pub irq_safe: bool,
    pub use_autosuspend: bool,
    pub timer_autosuspend: bool,
    pub request_pending: bool,
    pub deferred_resume: bool,
    pub needs_force_resume: bool,
    // Accounting
    pub accounting_timestamp: u64,
    pub active_jiffies: u64,
    pub suspended_jiffies: u64,
}

// ============================================================================
// System Sleep States
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SleepState {
    OnFreeeze = 0,       // s2idle (suspend-to-idle)
    Standby = 1,         // S1 standby
    MemSleep = 2,        // S3 suspend-to-RAM
    Disk = 3,            // S4 suspend-to-disk (hibernate)
    Off = 4,             // S5 poweroff
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum HibernateMode {
    Platform = 0,
    Shutdown = 1,
    Reboot = 2,
    Suspend = 3,
    TestProc = 4,
    TestCore = 5,
}

pub struct SystemSleepInfo {
    pub current_state: SleepState,
    pub supported_states: u8,       // Bitmask
    // Hibernate
    pub hibernate_mode: HibernateMode,
    pub hibernate_image_size: u64,
    pub hibernate_reserved_size: u64,
    pub swap_device: [64; u8],
    // s2idle
    pub s2idle_supported: bool,
    pub s2idle_usage: u64,
    pub s2idle_time_ms: u64,
    // Wakeup
    pub wakeup_count: u64,
    pub wakeup_count_active: bool,
    // PM test
    pub pm_test: u8,                // 0=none, 1=freezer, 2=devices, 3=platform, 4=processors, 5=core
    // Stats
    pub suspend_count: u64,
    pub resume_count: u64,
    pub failed_suspend: u64,
    pub failed_resume: u64,
    pub last_suspend_ns: u64,
    pub last_suspend_duration_ns: u64,
    pub last_resume_duration_ns: u64,
    // Freeze/thaw
    pub frozen_processes: u32,
    pub freeze_timeout_ms: u32,
}

// ============================================================================
// Device PM Callbacks
// ============================================================================

pub struct DevicePmOps {
    // System sleep
    pub has_prepare: bool,
    pub has_complete: bool,
    pub has_suspend: bool,
    pub has_resume: bool,
    pub has_freeze: bool,
    pub has_thaw: bool,
    pub has_poweroff: bool,
    pub has_restore: bool,
    // Late/early/noirq variants
    pub has_suspend_late: bool,
    pub has_resume_early: bool,
    pub has_suspend_noirq: bool,
    pub has_resume_noirq: bool,
    pub has_freeze_late: bool,
    pub has_thaw_early: bool,
    pub has_freeze_noirq: bool,
    pub has_thaw_noirq: bool,
    pub has_poweroff_late: bool,
    pub has_restore_early: bool,
    pub has_poweroff_noirq: bool,
    pub has_restore_noirq: bool,
    // Runtime PM
    pub has_runtime_suspend: bool,
    pub has_runtime_resume: bool,
    pub has_runtime_idle: bool,
}

// ============================================================================
// Wakeup Sources
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum WakeupSourceType {
    Unknown = 0,
    Device = 1,
    Timer = 2,
    GPIO = 3,
    IRQ = 4,
    Keyboard = 5,
    Mouse = 6,
    Network = 7,       // Wake-on-LAN
    USB = 8,
    Power = 9,         // Power button
    RTC = 10,
    // Zxyphor
    ZxyScheduled = 20,
}

pub struct WakeupSource {
    pub name: [64; u8],
    pub source_type: WakeupSourceType,
    // State
    pub active: bool,
    pub autosleep_enabled: bool,
    // Counters
    pub active_count: u64,
    pub event_count: u64,
    pub wakeup_count: u64,
    pub expire_count: u64,
    // Timing
    pub last_time_ns: u64,
    pub total_time_ns: u64,
    pub max_time_ns: u64,
    pub prevent_sleep_time_ns: u64,
    // Timer
    pub timer_expires: u64,
    // IRQ
    pub irq: i32,
}

pub struct WakeupStats {
    pub nr_wakeup_sources: u32,
    pub nr_active: u32,
    pub total_wakeup_events: u64,
    pub total_abort_events: u64,
    pub wakeup_irq: i32,
    pub last_wakeup_source: [64; u8],
}

// ============================================================================
// Device Links
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DeviceLinkState {
    NotAvailable = 0,
    Available = 1,
    Active = 2,
    Supplier_Unbind = 3,
    Dormant = 4,
}

pub const DL_FLAG_STATELESS: u32 = 1 << 0;
pub const DL_FLAG_AUTOREMOVE_CONSUMER: u32 = 1 << 1;
pub const DL_FLAG_PM_RUNTIME: u32 = 1 << 2;
pub const DL_FLAG_RPM_ACTIVE: u32 = 1 << 3;
pub const DL_FLAG_AUTOREMOVE_SUPPLIER: u32 = 1 << 4;
pub const DL_FLAG_AUTOPROBE_CONSUMER: u32 = 1 << 5;
pub const DL_FLAG_MANAGED: u32 = 1 << 6;
pub const DL_FLAG_SYNC_STATE_ONLY: u32 = 1 << 7;
pub const DL_FLAG_INFERRED: u32 = 1 << 8;
pub const DL_FLAG_CYCLE: u32 = 1 << 9;

pub struct DeviceLink {
    pub supplier_name: [64; u8],
    pub consumer_name: [64; u8],
    pub state: DeviceLinkState,
    pub flags: u32,
    // PM
    pub rpm_active: bool,
    // Status
    pub status: u8,
}

// ============================================================================
// Energy Model
// ============================================================================

pub struct EmPerfDomain {
    pub nr_perf_states: u16,
    pub flags: u32,
    pub cpus: u64,           // CPU mask
    // Table
    pub table: [64; EmPerfState],
    // Stats
    pub nr_cap_states_used: u32,
}

pub struct EmPerfState {
    pub frequency: u64,      // kHz
    pub power: u64,          // milliwatts
    pub cost: u64,           // Abstract cost
    pub performance: u64,    // DMIPS or similar
    pub flags: u32,
}

// ============================================================================
// Clock Framework (CCF)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ClockType {
    Fixed = 0,
    Gate = 1,
    Divider = 2,
    Mux = 3,
    FixedFactor = 4,
    Composite = 5,
    Fractional = 6,
    Pll = 7,
    // Zxyphor
    ZxyAdaptive = 10,
}

pub struct ClockInfo {
    pub name: [64; u8],
    pub clock_type: ClockType,
    pub rate: u64,           // Hz
    pub min_rate: u64,
    pub max_rate: u64,
    pub accuracy: u32,       // ppb
    pub enable_count: u32,
    pub prepare_count: u32,
    pub protect_count: u32,
    pub duty_num: u32,
    pub duty_den: u32,
    // Hierarchy
    pub parent_name: [64; u8],
    pub num_parents: u8,
    // Flags
    pub is_enabled: bool,
    pub is_prepared: bool,
    pub is_critical: bool,
    pub set_rate_gate: bool,
    pub set_parent_gate: bool,
    // Stats
    pub rate_changes: u64,
    pub parent_changes: u64,
}

// ============================================================================
// Regulator Framework
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RegulatorType {
    Voltage = 0,
    Current = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RegulatorStatus {
    Off = 0,
    On = 1,
    Error = 2,
    FastChange = 3,
    Normal = 4,
    Idle = 5,
    Standby = 6,
    Bypass = 7,
    Undefined = 8,
}

pub struct RegulatorInfo {
    pub name: [64; u8],
    pub regulator_type: RegulatorType,
    pub status: RegulatorStatus,
    // Voltage
    pub min_uv: i32,
    pub max_uv: i32,
    pub uv_offset: i32,
    pub current_uv: i32,
    // Current limit
    pub min_ua: i32,
    pub max_ua: i32,
    pub current_ua: i32,
    // Operating mode
    pub mode: u32,
    pub valid_modes_mask: u32,
    pub valid_ops_mask: u32,
    // Enable
    pub is_enabled: bool,
    pub enable_count: u32,
    pub always_on: bool,
    pub boot_on: bool,
    // Consumers
    pub num_consumers: u32,
    // Ramp
    pub ramp_delay: u32,         // uV/us
    pub settling_time: u32,      // us
    // Efficiency
    pub efficiency_pct: u8,
    // Protection
    pub over_voltage_protection: bool,
    pub under_voltage_protection: bool,
    pub over_current_protection: bool,
    pub over_temp_protection: bool,
}

// ============================================================================
// Power Domain
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PowerDomainState {
    On = 0,
    Off = 1,
    Retention = 2,
    // Zxyphor
    ZxyLowPower = 10,
}

pub struct PowerDomain {
    pub name: [64; u8],
    pub state: PowerDomainState,
    pub device_count: u32,
    pub subdomain_count: u32,
    // Performance
    pub performance_state: u32,
    pub max_performance_state: u32,
    // Stats
    pub on_time_ns: u64,
    pub off_time_ns: u64,
    pub retention_time_ns: u64,
    pub transition_count: u64,
    // Latency
    pub power_on_latency_ns: u64,
    pub power_off_latency_ns: u64,
    // Flags
    pub always_on: bool,
    pub atomic: bool,
}

// ============================================================================
// CPU Idle (cpuidle)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CpuidleGovernor {
    Ladder = 0,
    Menu = 1,
    TEO = 2,            // Timer Events Oriented
    Haltpoll = 3,
    // Zxyphor
    ZxyPredict = 10,
}

pub struct CpuidleState {
    pub name: [16; u8],
    pub desc: [32; u8],
    pub latency_us: u64,        // Exit latency
    pub target_residency_us: u64,
    pub power_usage: i64,       // mW, -1 if unknown
    pub flags: u32,
    pub disabled: bool,
    pub above: u64,             // Chosen too deep count
    pub below: u64,             // Chosen too shallow count
    pub usage: u64,
    pub time_us: u64,
    pub rejected: u64,
    pub s2idle_usage: u64,
    pub s2idle_time_us: u64,
}

pub struct CpuidleDriver {
    pub name: [16; u8],
    pub governor: CpuidleGovernor,
    pub nr_states: u8,
    pub states: [16; CpuidleState],
    // Current
    pub last_state: u8,
    pub last_residency_us: u64,
    // Stats
    pub total_transitions: u64,
    pub average_residency_us: u64,
}

// ============================================================================
// CPU Frequency (cpufreq)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CpufreqGovernor {
    Performance = 0,
    Powersave = 1,
    Userspace = 2,
    Ondemand = 3,
    Conservative = 4,
    Schedutil = 5,
    // Zxyphor
    ZxyAdaptive = 10,
}

pub struct CpufreqPolicy {
    pub cpu: u32,
    pub governor: CpufreqGovernor,
    pub cur_freq: u64,           // kHz
    pub min_freq: u64,
    pub max_freq: u64,
    pub cpuinfo_min_freq: u64,
    pub cpuinfo_max_freq: u64,
    pub cpuinfo_transition_latency: u32,  // ns
    // Scaling
    pub scaling_min_freq: u64,
    pub scaling_max_freq: u64,
    pub scaling_cur_freq: u64,
    // EPP (Energy Performance Preference)
    pub epp: u8,
    pub epp_available: [64; u8],
    // EPB (Energy Performance Bias)
    pub epb: u8,
    // Stats
    pub total_transitions: u64,
    pub time_in_state: [64; u64],  // us per frequency
    pub nr_freq_table_entries: u8,
    // Boost
    pub boost_enabled: bool,
    pub boost_freq: u64,
    // Stats
    pub freq_changes: u64,
    pub throttle_count: u64,
}

// ============================================================================
// Device Power Management Subsystem
// ============================================================================

pub struct DevicePmSubsystem {
    // Firmware
    pub fw_cache: FirmwareCache,
    pub nr_firmware_loaded: u32,
    pub total_firmware_bytes: u64,
    // System sleep
    pub sleep_info: SystemSleepInfo,
    // Wakeup
    pub wakeup_stats: WakeupStats,
    // Device links
    pub nr_device_links: u32,
    // Energy model
    pub nr_perf_domains: u32,
    // Clocks
    pub nr_clocks: u32,
    pub nr_clock_gates: u32,
    // Regulators
    pub nr_regulators: u32,
    // Power domains
    pub nr_power_domains: u32,
    // cpuidle
    pub nr_cpuidle_drivers: u32,
    pub total_idle_time_ns: u64,
    // cpufreq
    pub nr_cpufreq_policies: u32,
    pub total_freq_transitions: u64,
    // Global stats
    pub total_runtime_suspend: u64,
    pub total_runtime_resume: u64,
    pub total_system_suspend: u64,
    pub total_system_resume: u64,
    pub total_hibernate: u64,
    // Zxyphor
    pub zxy_adaptive_pm: bool,
    pub zxy_power_budget_mw: u64,
    pub zxy_power_used_mw: u64,
    pub initialized: bool,
}
