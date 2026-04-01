// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Power Management
// ACPI S-states, CPU frequency scaling, thermal management, suspend/resume

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// ACPI Power States
// ============================================================================

/// System power states (ACPI S-states)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SystemPowerState {
    S0Working = 0,       // Full on
    S1Standby = 1,       // CPU stops, power to RAM maintained
    S2Sleep = 2,         // CPU off, RAM powered
    S3Suspend = 3,       // Suspend to RAM (STR)
    S4Hibernate = 4,     // Suspend to disk (STD)
    S5SoftOff = 5,       // Mechanical off
}

/// Device power states (ACPI D-states)
#[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
#[repr(u8)]
pub enum DevicePowerState {
    D0FullOn = 0,
    D1LowPower = 1,
    D2Standby = 2,
    D3Hot = 3,
    D3Cold = 4,
}

/// CPU C-states (processor idle)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CpuCState {
    C0Active = 0,      // Running
    C1Halt = 1,        // HALT instruction (auto-halt)
    C1EEnhanced = 2,   // Enhanced C1 with lower voltage
    C2Stop = 3,        // Stop clock
    C3Sleep = 4,       // L1/L2 cache flushed
    C6Deep = 5,        // Core voltage off
    C7Package = 6,     // Package-level idle
    C8 = 7,            // Deepest idle (Zxyphor extension)
    C10 = 8,           // Ultra-deep idle with content retention
}

/// CPU P-states (performance)
#[derive(Debug, Clone, Copy)]
pub struct CpuPState {
    pub frequency_mhz: u32,
    pub voltage_mv: u32,
    pub power_mw: u32,
    pub latency_us: u32,
    pub bus_master_latency_us: u32,
    pub status: u8,
    pub control: u8,
}

// ============================================================================
// CPU Frequency Scaling (cpufreq equivalent)
// ============================================================================

/// Frequency scaling governor
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CpuFreqGovernor {
    Performance,      // Always max frequency
    Powersave,        // Always min frequency
    Userspace,        // User-specified
    Ondemand,         // Scale based on load
    Conservative,     // Gradual scaling
    Schedutil,        // Scheduler-integrated
    Interactive,      // Touch/input-aware
    ZxyAdaptive,      // ML-based prediction (Zxyphor)
}

/// Per-CPU frequency state
pub struct CpuFreqState {
    pub cpu_id: u32,
    pub cur_freq_khz: AtomicU32,
    pub min_freq_khz: u32,
    pub max_freq_khz: u32,
    pub scaling_min_khz: AtomicU32,
    pub scaling_max_khz: AtomicU32,
    pub governor: CpuFreqGovernor,
    pub transition_latency_ns: u32,
    pub p_states: [CpuPState; 32],
    pub num_p_states: u8,
    // Governor state
    pub ondemand: OndemandState,
    pub schedutil: SchedutilState,
    // Statistics
    pub time_in_state: [u64; 32],   // ns per P-state
    pub transition_count: AtomicU64,
    pub total_transitions: AtomicU64,
}

pub struct OndemandState {
    pub up_threshold: u32,     // default 80%
    pub down_threshold: u32,   // default 20%
    pub sampling_rate_us: u32, // default 10000
    pub ignore_nice_load: bool,
    pub powersave_bias: u32,
    pub io_is_busy: bool,
    pub prev_cpu_idle: u64,
    pub prev_cpu_wall: u64,
    pub prev_cpu_nice: u64,
}

impl OndemandState {
    pub fn new() -> Self {
        OndemandState {
            up_threshold: 80,
            down_threshold: 20,
            sampling_rate_us: 10000,
            ignore_nice_load: false,
            powersave_bias: 0,
            io_is_busy: false,
            prev_cpu_idle: 0,
            prev_cpu_wall: 0,
            prev_cpu_nice: 0,
        }
    }

    /// Calculate target frequency based on utilization
    pub fn calc_target_freq(&mut self, idle_time: u64, wall_time: u64, nice_time: u64,
                            cur_freq: u32, min_freq: u32, max_freq: u32) -> u32 {
        let delta_idle = idle_time.wrapping_sub(self.prev_cpu_idle);
        let delta_wall = wall_time.wrapping_sub(self.prev_cpu_wall);
        let delta_nice = nice_time.wrapping_sub(self.prev_cpu_nice);

        self.prev_cpu_idle = idle_time;
        self.prev_cpu_wall = wall_time;
        self.prev_cpu_nice = nice_time;

        if delta_wall == 0 { return cur_freq; }

        let mut load_time = delta_wall - delta_idle;
        if self.ignore_nice_load {
            load_time = load_time.saturating_sub(delta_nice);
        }

        let load_pct = ((load_time * 100) / delta_wall) as u32;

        if load_pct > self.up_threshold {
            max_freq
        } else if load_pct < self.down_threshold {
            let freq = ((cur_freq as u64 * load_pct as u64) / self.up_threshold as u64) as u32;
            if freq < min_freq { min_freq } else { freq }
        } else {
            cur_freq
        }
    }
}

pub struct SchedutilState {
    pub rate_limit_us: u32,
    pub last_update_ns: u64,
    pub next_freq: u32,
    pub cached_util: u32,
    pub cached_max: u32,
    pub iowait_boost: u32,
    pub iowait_boost_max: u32,
    pub flags: u32,
}

impl SchedutilState {
    pub fn new() -> Self {
        SchedutilState {
            rate_limit_us: 1000,
            last_update_ns: 0,
            next_freq: 0,
            cached_util: 0,
            cached_max: 1024,
            iowait_boost: 0,
            iowait_boost_max: 0,
            flags: 0,
        }
    }

    /// schedutil: frequency = max_freq * util / max
    pub fn update(&mut self, util: u32, max: u32, max_freq: u32, now_ns: u64) -> Option<u32> {
        let elapsed = now_ns.saturating_sub(self.last_update_ns);
        if elapsed < (self.rate_limit_us as u64 * 1000) {
            return None; // Rate limited
        }
        self.last_update_ns = now_ns;
        self.cached_util = util;
        self.cached_max = max;

        // Apply 1.25x margin like Linux schedutil
        let util_boosted = util + (util >> 2);
        let target = if max > 0 {
            ((max_freq as u64 * util_boosted as u64) / max as u64) as u32
        } else {
            max_freq
        };

        let target = if self.iowait_boost > target { self.iowait_boost } else { target };
        self.iowait_boost = self.iowait_boost / 2; // Decay boost

        self.next_freq = target;
        Some(target)
    }
}

// ============================================================================
// Thermal Management
// ============================================================================

/// Thermal zone types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalZoneType {
    Cpu,
    Gpu,
    Memory,
    Battery,
    Ssd,
    VoltageRegulator,
    Ambient,
    Skin,
    Package,
    Custom(u8),
}

/// Thermal trip point types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TripPointType {
    Active,    // Fan speed increase
    Passive,   // Frequency throttle
    Hot,       // Migration/offline
    Critical,  // Emergency shutdown
}

#[derive(Debug, Clone, Copy)]
pub struct TripPoint {
    pub trip_type: TripPointType,
    pub temp_mc: i32,    // milliCelsius
    pub hysteresis_mc: i32,
    pub enabled: bool,
}

/// Thermal zone
pub struct ThermalZone {
    pub id: u32,
    pub zone_type: ThermalZoneType,
    pub temp_mc: AtomicU32,         // Current temp in milliCelsius
    pub trip_points: [TripPoint; 8],
    pub num_trips: u8,
    pub polling_delay_ms: u32,
    pub passive_delay_ms: u32,
    pub last_temp_mc: i32,
    pub trend: ThermalTrend,
    pub governor: ThermalGovernor,
    pub cooling_devices: [CoolingDevice; 4],
    pub num_cooling: u8,
    pub emul_temp_mc: Option<i32>,   // For testing
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalTrend {
    Stable,
    Raising,
    Dropping,
    RaisingFull,    // Thermal runaway
    DroppingFull,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalGovernor {
    StepWise,
    FairShare,
    BangBang,
    UserSpace,
    PowerAllocator,
    ZxyPredictive,   // ML-based thermal prediction (Zxyphor)
}

/// Cooling device
pub struct CoolingDevice {
    pub id: u32,
    pub cooling_type: CoolingType,
    pub cur_state: AtomicU32,
    pub max_state: u32,
    pub power_mw: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CoolingType {
    Processor,    // CPU frequency throttling
    Fan,          // Active fan
    Lcd,          // LCD brightness
    Battery,      // Charging control
    GpuThrottle,
    MemThrottle,
}

impl ThermalZone {
    /// Check trip points and apply cooling actions
    pub fn check_trips(&mut self) -> ThermalAction {
        let temp = self.temp_mc.load(Ordering::Relaxed) as i32;
        let mut action = ThermalAction::None;

        for i in 0..self.num_trips as usize {
            let trip = &self.trip_points[i];
            if !trip.enabled { continue; }

            if temp >= trip.temp_mc {
                match trip.trip_type {
                    TripPointType::Critical => {
                        action = ThermalAction::EmergencyShutdown;
                        break; // Highest priority
                    }
                    TripPointType::Hot => {
                        if action < ThermalAction::Throttle {
                            action = ThermalAction::Throttle;
                        }
                    }
                    TripPointType::Passive => {
                        let excess = temp - trip.temp_mc;
                        let throttle_pct = ((excess as u32 * 100) / 10000).min(100);
                        if action < ThermalAction::PassiveThrottle(throttle_pct as u8) {
                            action = ThermalAction::PassiveThrottle(throttle_pct as u8);
                        }
                    }
                    TripPointType::Active => {
                        if action < ThermalAction::FanIncrease {
                            action = ThermalAction::FanIncrease;
                        }
                    }
                }
            } else if temp < trip.temp_mc - trip.hysteresis_mc {
                // Below trip - hysteresis, can reduce cooling
            }
        }

        // Update trend
        if temp > self.last_temp_mc + 500 {
            self.trend = ThermalTrend::Raising;
        } else if temp < self.last_temp_mc - 500 {
            self.trend = ThermalTrend::Dropping;
        } else {
            self.trend = ThermalTrend::Stable;
        }
        self.last_temp_mc = temp;

        action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ThermalAction {
    None,
    FanIncrease,
    PassiveThrottle(u8), // percent
    Throttle,
    EmergencyShutdown,
}

// ============================================================================
// Battery / Power Supply
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PowerSupplyType {
    Battery,
    UPS,
    Mains,
    USB,
    USBDcp,    // Dedicated Charging Port
    USBCdp,    // Charging Downstream Port
    USBPd,     // USB Power Delivery
    Wireless,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryStatus {
    Unknown,
    Charging,
    Discharging,
    NotCharging,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryHealth {
    Unknown,
    Good,
    Overheat,
    Dead,
    OverVoltage,
    UnspecifiedFailure,
    Cold,
    WatchdogTimerExpire,
    SafetyTimerExpire,
    OverCurrent,
    Warm,
    Cool,
    Hot,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryTechnology {
    Unknown,
    NiMH,
    LiIon,
    LiPoly,
    LiFe,
    NiCd,
    LiMn,
}

/// Battery state tracking
pub struct BatteryState {
    pub present: bool,
    pub status: BatteryStatus,
    pub health: BatteryHealth,
    pub technology: BatteryTechnology,
    pub voltage_now_uv: u32,      // microvolts
    pub voltage_min_uv: u32,
    pub voltage_max_uv: u32,
    pub current_now_ua: i32,      // microamps (negative = discharge)
    pub current_avg_ua: i32,
    pub charge_full_uah: u32,     // microamp-hours
    pub charge_now_uah: u32,
    pub charge_full_design_uah: u32,
    pub capacity_pct: u8,         // 0-100
    pub capacity_level: CapacityLevel,
    pub temp_mc: i32,             // milliCelsius
    pub cycle_count: u32,
    pub energy_now_uwh: u64,      // microwatt-hours
    pub energy_full_uwh: u64,
    pub energy_full_design_uwh: u64,
    pub power_now_uw: u32,        // microwatts
    pub time_to_empty_sec: u32,
    pub time_to_full_sec: u32,
    // Charging control
    pub charge_type: ChargeType,
    pub input_current_limit_ua: u32,
    pub constant_charge_current_ua: u32,
    pub constant_charge_voltage_uv: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapacityLevel {
    Unknown,
    Critical,
    Low,
    Normal,
    High,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChargeType {
    Unknown,
    None,
    Trickle,
    Fast,
    Standard,
    Adaptive,
    Custom,
    LongLife,
    Bypass,
}

impl BatteryState {
    pub fn new() -> Self {
        BatteryState {
            present: false,
            status: BatteryStatus::Unknown,
            health: BatteryHealth::Unknown,
            technology: BatteryTechnology::Unknown,
            voltage_now_uv: 0,
            voltage_min_uv: 3000000,
            voltage_max_uv: 4200000,
            current_now_ua: 0,
            current_avg_ua: 0,
            charge_full_uah: 0,
            charge_now_uah: 0,
            charge_full_design_uah: 0,
            capacity_pct: 0,
            capacity_level: CapacityLevel::Unknown,
            temp_mc: 25000,
            cycle_count: 0,
            energy_now_uwh: 0,
            energy_full_uwh: 0,
            energy_full_design_uwh: 0,
            power_now_uw: 0,
            time_to_empty_sec: 0,
            time_to_full_sec: 0,
            charge_type: ChargeType::Unknown,
            input_current_limit_ua: 0,
            constant_charge_current_ua: 0,
            constant_charge_voltage_uv: 0,
        }
    }

    pub fn update_capacity_level(&mut self) {
        self.capacity_level = match self.capacity_pct {
            0..=5 => CapacityLevel::Critical,
            6..=15 => CapacityLevel::Low,
            16..=79 => CapacityLevel::Normal,
            80..=99 => CapacityLevel::High,
            100 => CapacityLevel::Full,
            _ => CapacityLevel::Unknown,
        };
    }

    pub fn estimate_remaining(&mut self) {
        if self.current_now_ua < 0 && self.charge_now_uah > 0 {
            let discharge_rate = (-self.current_now_ua) as u64;
            if discharge_rate > 0 {
                self.time_to_empty_sec = ((self.charge_now_uah as u64 * 3600) / discharge_rate) as u32;
            }
        } else if self.current_now_ua > 0 {
            let remaining = self.charge_full_uah.saturating_sub(self.charge_now_uah) as u64;
            let charge_rate = self.current_now_ua as u64;
            if charge_rate > 0 {
                self.time_to_full_sec = ((remaining * 3600) / charge_rate) as u32;
            }
        }
    }
}

// ============================================================================
// Suspend / Resume Framework
// ============================================================================

/// Suspend operations for devices
pub struct SuspendOps {
    pub prepare: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub suspend: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub suspend_late: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub suspend_noirq: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub resume_noirq: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub resume_early: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub resume: Option<fn(dev_id: u32) -> Result<(), SuspendError>>,
    pub complete: Option<fn(dev_id: u32) -> ()>,
}

#[derive(Debug, Clone, Copy)]
pub enum SuspendError {
    Busy,
    NotSupported,
    IoError,
    Timeout,
    AlreadySuspended,
    WakeupPending,
    DeviceError,
}

/// System suspend state machine  
pub struct SuspendController {
    pub state: SuspendPhase,
    pub target: SystemPowerState,
    pub wakeup_count: AtomicU64,
    pub wakeup_pending: AtomicBool,
    pub freeze_timeout_ms: u32,
    pub devices_suspended: u32,
    pub devices_total: u32,
    // PM notifier chain
    pub notifiers: [Option<fn(event: PmEvent) -> i32>; 32],
    pub num_notifiers: u8,
    // Wake sources
    pub wake_sources: [WakeSource; 64],
    pub num_wake_sources: u8,
    // Hibernate
    pub hibernate_image_size: u64,
    pub hibernate_swap_offset: u64,
    pub hibernate_compression: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SuspendPhase {
    Running,
    FreezeProcesses,
    SuspendPrepare,
    SuspendDevices,
    SuspendLate,
    SuspendNoirq,
    SuspendPlatform,
    Suspended,
    ResumeNoirq,
    ResumeEarly,
    ResumeDevices,
    ResumeComplete,
    ThawProcesses,
}

#[derive(Debug, Clone, Copy)]
pub enum PmEvent {
    Suspend,
    Resume,
    Freeze,
    Thaw,
    Hibernate,
    Restore,
    PowerOff,
}

/// Wake source
pub struct WakeSource {
    pub name: [u8; 32],
    pub name_len: u8,
    pub active: AtomicBool,
    pub active_count: AtomicU64,
    pub event_count: AtomicU64,
    pub wakeup_count: AtomicU64,
    pub expire_count: AtomicU64,
    pub last_time_ns: AtomicU64,
    pub total_time_ns: AtomicU64,
    pub max_time_ns: AtomicU64,
    pub autosleep_enabled: bool,
    pub timer_expires_ms: u64,
}

impl SuspendController {
    pub fn new() -> Self {
        SuspendController {
            state: SuspendPhase::Running,
            target: SystemPowerState::S0Working,
            wakeup_count: AtomicU64::new(0),
            wakeup_pending: AtomicBool::new(false),
            freeze_timeout_ms: 20000,
            devices_suspended: 0,
            devices_total: 0,
            notifiers: [None; 32],
            num_notifiers: 0,
            wake_sources: core::array::from_fn(|_| WakeSource {
                name: [0; 32],
                name_len: 0,
                active: AtomicBool::new(false),
                active_count: AtomicU64::new(0),
                event_count: AtomicU64::new(0),
                wakeup_count: AtomicU64::new(0),
                expire_count: AtomicU64::new(0),
                last_time_ns: AtomicU64::new(0),
                total_time_ns: AtomicU64::new(0),
                max_time_ns: AtomicU64::new(0),
                autosleep_enabled: false,
                timer_expires_ms: 0,
            }),
            num_wake_sources: 0,
            hibernate_image_size: 0,
            hibernate_swap_offset: 0,
            hibernate_compression: true,
        }
    }

    /// Begin suspend sequence
    pub fn begin_suspend(&mut self, target: SystemPowerState) -> Result<(), SuspendError> {
        if self.state != SuspendPhase::Running {
            return Err(SuspendError::Busy);
        }
        if self.wakeup_pending.load(Ordering::Acquire) {
            return Err(SuspendError::WakeupPending);
        }
        self.target = target;
        self.state = SuspendPhase::FreezeProcesses;
        
        // Notify PM chain
        self.notify_all(PmEvent::Suspend);
        
        Ok(())
    }

    fn notify_all(&self, event: PmEvent) {
        for i in 0..self.num_notifiers as usize {
            if let Some(cb) = self.notifiers[i] {
                let _ = cb(event);
            }
        }
    }

    /// Register a wake source
    pub fn register_wake_source(&mut self, name: &[u8]) -> Option<u8> {
        if self.num_wake_sources >= 64 { return None; }
        let idx = self.num_wake_sources;
        let ws = &mut self.wake_sources[idx as usize];
        let len = name.len().min(32);
        ws.name[..len].copy_from_slice(&name[..len]);
        ws.name_len = len as u8;
        self.num_wake_sources += 1;
        Some(idx)
    }

    /// Activate a wake source
    pub fn activate_wake_source(&self, idx: u8) {
        if (idx as usize) < self.num_wake_sources as usize {
            let ws = &self.wake_sources[idx as usize];
            ws.active.store(true, Ordering::Release);
            ws.active_count.fetch_add(1, Ordering::Relaxed);
            ws.event_count.fetch_add(1, Ordering::Relaxed);
            self.wakeup_pending.store(true, Ordering::Release);
            self.wakeup_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// Runtime PM
// ============================================================================

/// Runtime PM state for individual devices
pub struct RuntimePmState {
    pub status: RuntimePmStatus,
    pub usage_count: AtomicU32,
    pub child_count: AtomicU32,
    pub disable_depth: AtomicU32,
    pub runtime_error: i32,
    pub idle_notification: bool,
    pub request_pending: bool,
    pub deferred_resume: bool,
    pub auto_suspend_delay_ms: i32,
    pub last_busy_ns: AtomicU64,
    pub suspend_time_ns: u64,
    pub accounting_active: bool,
    pub autosuspend_enabled: bool,
    // Callbacks
    pub runtime_suspend: Option<fn(dev_id: u32) -> i32>,
    pub runtime_resume: Option<fn(dev_id: u32) -> i32>,
    pub runtime_idle: Option<fn(dev_id: u32) -> i32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuntimePmStatus {
    Active,
    Resuming,
    Suspended,
    Suspending,
}

impl RuntimePmState {
    pub fn new() -> Self {
        RuntimePmState {
            status: RuntimePmStatus::Active,
            usage_count: AtomicU32::new(0),
            child_count: AtomicU32::new(0),
            disable_depth: AtomicU32::new(1), // Disabled by default
            runtime_error: 0,
            idle_notification: false,
            request_pending: false,
            deferred_resume: false,
            auto_suspend_delay_ms: -1, // No auto-suspend
            last_busy_ns: AtomicU64::new(0),
            suspend_time_ns: 0,
            accounting_active: true,
            autosuspend_enabled: false,
            runtime_suspend: None,
            runtime_resume: None,
            runtime_idle: None,
        }
    }

    /// Mark device busy (prevents suspend)
    pub fn mark_busy(&self) {
        self.usage_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Mark device idle
    pub fn mark_idle(&self) {
        self.usage_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Check if device can auto-suspend
    pub fn can_auto_suspend(&self, now_ns: u64) -> bool {
        if !self.autosuspend_enabled || self.auto_suspend_delay_ms < 0 {
            return false;
        }
        if self.usage_count.load(Ordering::Relaxed) > 0 {
            return false;
        }
        if self.disable_depth.load(Ordering::Relaxed) > 0 {
            return false;
        }
        let last = self.last_busy_ns.load(Ordering::Relaxed);
        let elapsed_ms = (now_ns - last) / 1_000_000;
        elapsed_ms >= self.auto_suspend_delay_ms as u64
    }
}

// ============================================================================
// Energy Model
// ============================================================================

/// Energy model for EAS (Energy Aware Scheduling)
pub struct EnergyModel {
    pub perf_domains: [PerfDomain; 8],
    pub num_domains: u8,
}

pub struct PerfDomain {
    pub cpumask: u64,
    pub nr_perf_states: u8,
    pub states: [EmPerfState; 32],
    pub table_overhead_mw: u32,
}

pub struct EmPerfState {
    pub frequency_khz: u32,
    pub power_mw: u32,
    pub cost: u64,      // normalized power / performance
    pub flags: u32,
}

impl EnergyModel {
    pub fn new() -> Self {
        EnergyModel {
            perf_domains: core::array::from_fn(|_| PerfDomain {
                cpumask: 0,
                nr_perf_states: 0,
                states: [EmPerfState { frequency_khz: 0, power_mw: 0, cost: 0, flags: 0 }; 32],
                table_overhead_mw: 0,
            }),
            num_domains: 0,
        }
    }

    /// Compute energy cost for running a task on a specific CPU
    pub fn compute_energy(&self, domain_idx: u8, utilization: u32, max_util: u32) -> u64 {
        if domain_idx as usize >= self.num_domains as usize { return u64::MAX; }
        let pd = &self.perf_domains[domain_idx as usize];
        
        // Find the first performance state that can handle the utilization
        for i in 0..pd.nr_perf_states as usize {
            let state = &pd.states[i];
            let cap = state.frequency_khz as u64;
            let needed = (utilization as u64 * cap) / max_util.max(1) as u64;
            if needed <= cap {
                return state.power_mw as u64 * utilization as u64 / max_util.max(1) as u64
                    + pd.table_overhead_mw as u64;
            }
        }
        
        // Max power
        if pd.nr_perf_states > 0 {
            let max = &pd.states[pd.nr_perf_states as usize - 1];
            max.power_mw as u64 + pd.table_overhead_mw as u64
        } else {
            u64::MAX
        }
    }
}

// ============================================================================
// Power Statistics
// ============================================================================

pub struct PowerStats {
    pub total_suspend_count: AtomicU64,
    pub total_resume_count: AtomicU64,
    pub last_suspend_ns: AtomicU64,
    pub last_resume_ns: AtomicU64,
    pub total_suspend_time_ns: AtomicU64,
    pub failed_suspends: AtomicU64,
    pub failed_resumes: AtomicU64,
    pub freeze_abort_count: AtomicU64,
    pub wakeup_irq_count: AtomicU64,
    pub battery_cycles: AtomicU64,
}

impl PowerStats {
    pub const fn new() -> Self {
        PowerStats {
            total_suspend_count: AtomicU64::new(0),
            total_resume_count: AtomicU64::new(0),
            last_suspend_ns: AtomicU64::new(0),
            last_resume_ns: AtomicU64::new(0),
            total_suspend_time_ns: AtomicU64::new(0),
            failed_suspends: AtomicU64::new(0),
            failed_resumes: AtomicU64::new(0),
            freeze_abort_count: AtomicU64::new(0),
            wakeup_irq_count: AtomicU64::new(0),
            battery_cycles: AtomicU64::new(0),
        }
    }
}

static POWER_STATS: PowerStats = PowerStats::new();
pub fn get_power_stats() -> &'static PowerStats { &POWER_STATS }
