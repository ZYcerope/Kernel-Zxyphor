// =============================================================================
// Kernel Zxyphor — CPU Frequency Scaling Interface
// =============================================================================
// Hardware abstraction for CPU frequency control:
//   - P-state enumeration from ACPI/CPUID
//   - MSR-based frequency setting (Intel SpeedStep, AMD Cool'n'Quiet)
//   - Hardware P-state (HWP) support for Intel
//   - Turbo boost management
//   - Frequency transition notification
//   - CPU voltage/frequency pairs (VID table)
//   - Per-core vs per-package frequency domains
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

pub const MAX_PSTATES: usize = 32;
pub const MAX_CPUFREQ_DRIVERS: usize = 4;

// =============================================================================
// P-state definition
// =============================================================================

pub struct PState {
    pub frequency_khz: u32,
    pub voltage_mv: u32,      // Core voltage in millivolts
    pub power_mw: u32,        // Estimated power in milliwatts
    pub latency_us: u32,      // Transition latency
    pub control_value: u64,   // Value to write to MSR/hardware
    pub status_value: u64,    // Expected value when reading status
}

impl PState {
    pub const fn empty() -> Self {
        Self {
            frequency_khz: 0,
            voltage_mv: 0,
            power_mw: 0,
            latency_us: 0,
            control_value: 0,
            status_value: 0,
        }
    }
}

// =============================================================================
// HWP (Hardware P-state) control
// =============================================================================

pub struct HwpCapabilities {
    pub highest_perf: u8,
    pub guaranteed_perf: u8,
    pub most_efficient_perf: u8,
    pub lowest_perf: u8,
}

pub struct HwpRequest {
    pub min_perf: u8,
    pub max_perf: u8,
    pub desired_perf: u8,       // 0 = hardware-managed
    pub epp: u8,                // Energy Performance Preference
    pub activity_window: u16,   // In microseconds
    pub package_control: bool,
}

impl HwpRequest {
    pub const fn balanced() -> Self {
        Self {
            min_perf: 0,
            max_perf: 255,
            desired_perf: 0,
            epp: 128,
            activity_window: 0,
            package_control: false,
        }
    }

    pub const fn performance() -> Self {
        Self {
            min_perf: 255,
            max_perf: 255,
            desired_perf: 0,
            epp: 0,
            activity_window: 0,
            package_control: false,
        }
    }

    pub const fn powersave() -> Self {
        Self {
            min_perf: 0,
            max_perf: 128,
            desired_perf: 0,
            epp: 255,
            activity_window: 0,
            package_control: false,
        }
    }

    /// Encode into MSR value (IA32_HWP_REQUEST format)
    pub fn to_msr(&self) -> u64 {
        (self.min_perf as u64)
            | ((self.max_perf as u64) << 8)
            | ((self.desired_perf as u64) << 16)
            | ((self.epp as u64) << 24)
            | ((self.activity_window as u64) << 32)
            | if self.package_control { 1u64 << 42 } else { 0 }
    }

    /// Decode from MSR value
    pub fn from_msr(val: u64) -> Self {
        Self {
            min_perf: val as u8,
            max_perf: (val >> 8) as u8,
            desired_perf: (val >> 16) as u8,
            epp: (val >> 24) as u8,
            activity_window: (val >> 32) as u16 & 0x3FF,
            package_control: (val >> 42) & 1 != 0,
        }
    }
}

// =============================================================================
// CPU frequency driver abstraction
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpufreqDriverType {
    AcpiCpufreq = 0,     // ACPI-based P-state control
    IntelPstate = 1,      // Intel P-state driver
    AmdPstate = 2,        // AMD P-state driver
    IntelHwp = 3,         // Intel Hardware P-state
}

pub struct CpufreqDriver {
    pub driver_type: CpufreqDriverType,
    pub name: [u8; 16],
    pub name_len: usize,
    pub active: bool,

    // P-state table
    pub pstates: [PState; MAX_PSTATES],
    pub pstate_count: u32,
    pub current_pstate: u32,

    // HWP support
    pub hwp_supported: bool,
    pub hwp_active: bool,
    pub hwp_caps: HwpCapabilities,
    pub hwp_request: HwpRequest,

    // Turbo boost
    pub turbo_supported: bool,
    pub turbo_enabled: AtomicBool,
    pub turbo_freq_khz: u32,
    pub base_freq_khz: u32,

    // MSR addresses
    pub perf_ctl_msr: u32,
    pub perf_status_msr: u32,

    // Statistics
    pub transitions: AtomicU64,
    pub time_in_pstate: [AtomicU64; MAX_PSTATES], // ns spent in each P-state
}

impl CpufreqDriver {
    pub const fn new() -> Self {
        Self {
            driver_type: CpufreqDriverType::AcpiCpufreq,
            name: [0u8; 16],
            name_len: 0,
            active: false,
            pstates: [const { PState::empty() }; MAX_PSTATES],
            pstate_count: 0,
            current_pstate: 0,
            hwp_supported: false,
            hwp_active: false,
            hwp_caps: HwpCapabilities {
                highest_perf: 0,
                guaranteed_perf: 0,
                most_efficient_perf: 0,
                lowest_perf: 0,
            },
            hwp_request: HwpRequest::balanced(),
            turbo_supported: false,
            turbo_enabled: AtomicBool::new(true),
            turbo_freq_khz: 0,
            base_freq_khz: 0,
            perf_ctl_msr: 0x199,    // IA32_PERF_CTL
            perf_status_msr: 0x198, // IA32_PERF_STATUS
            transitions: AtomicU64::new(0),
            time_in_pstate: [const { AtomicU64::new(0) }; MAX_PSTATES],
        }
    }

    /// Set P-state by index
    pub fn set_pstate(&mut self, index: u32) -> bool {
        if index >= self.pstate_count { return false; }
        if index == self.current_pstate { return true; }

        // In a real driver, write to MSR here
        self.current_pstate = index;
        self.transitions.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Find P-state closest to target frequency
    pub fn find_pstate_for_freq(&self, target_khz: u32) -> Option<u32> {
        if self.pstate_count == 0 { return None; }
        let mut best = 0u32;
        let mut best_diff = u32::MAX;
        for i in 0..self.pstate_count {
            let diff = target_khz.abs_diff(self.pstates[i as usize].frequency_khz);
            if diff < best_diff {
                best_diff = diff;
                best = i;
            }
        }
        Some(best)
    }

    /// Get current frequency
    pub fn current_freq_khz(&self) -> u32 {
        if self.current_pstate < self.pstate_count {
            self.pstates[self.current_pstate as usize].frequency_khz
        } else {
            0
        }
    }

    /// Enable/disable turbo boost
    pub fn set_turbo(&self, enabled: bool) {
        self.turbo_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Configure HWP request
    pub fn configure_hwp(&mut self, request: HwpRequest) {
        if !self.hwp_supported { return; }
        self.hwp_request = request;
        // In a real driver, write to IA32_HWP_REQUEST MSR
    }
}

// =============================================================================
// Global cpufreq subsystem
// =============================================================================

pub struct CpufreqSubsystem {
    pub drivers: [CpufreqDriver; MAX_CPUFREQ_DRIVERS],
    pub driver_count: u32,
    pub active_driver: u32,    // Index of currently active driver
}

impl CpufreqSubsystem {
    pub const fn new() -> Self {
        Self {
            drivers: [const { CpufreqDriver::new() }; MAX_CPUFREQ_DRIVERS],
            driver_count: 0,
            active_driver: 0,
        }
    }

    pub fn register_driver(&mut self, driver_type: CpufreqDriverType, name: &[u8]) -> Option<u32> {
        if self.driver_count as usize >= MAX_CPUFREQ_DRIVERS { return None; }
        let idx = self.driver_count as usize;
        self.drivers[idx] = CpufreqDriver::new();
        self.drivers[idx].driver_type = driver_type;
        let len = name.len().min(16);
        self.drivers[idx].name[..len].copy_from_slice(&name[..len]);
        self.drivers[idx].name_len = len;
        self.drivers[idx].active = true;
        self.driver_count += 1;
        Some(idx as u32)
    }

    pub fn active_driver(&mut self) -> Option<&mut CpufreqDriver> {
        let idx = self.active_driver as usize;
        if idx < self.driver_count as usize && self.drivers[idx].active {
            Some(&mut self.drivers[idx])
        } else {
            None
        }
    }
}

static mut CPUFREQ: CpufreqSubsystem = CpufreqSubsystem::new();

pub unsafe fn cpufreq() -> &'static mut CpufreqSubsystem {
    &mut *core::ptr::addr_of_mut!(CPUFREQ)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_driver_count() -> u32 {
    unsafe { cpufreq().driver_count }
}

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_set_turbo(enabled: bool) {
    unsafe {
        if let Some(drv) = cpufreq().active_driver() {
            drv.set_turbo(enabled);
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_current() -> u32 {
    unsafe {
        cpufreq().active_driver().map(|d| d.current_freq_khz()).unwrap_or(0)
    }
}
