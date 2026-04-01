// =============================================================================
// Kernel Zxyphor — CPU Frequency Governor
// =============================================================================
// Dynamic CPU frequency scaling policies:
//   - Performance governor (always max frequency)
//   - Powersave governor (always min frequency)
//   - Ondemand governor (scale based on load with up/down thresholds)
//   - Conservative governor (gradual frequency stepping)
//   - Schedutil governor (scheduler-driven, utilization-based)
//   - Per-CPU frequency domains with independent governors
//   - Frequency transition statistics (latency, count)
//   - CPU idle state management (C-states)
//   - Thermal throttling integration
//   - Energy-performance preference (EPP) support
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const MAX_FREQ_CPUS: usize = 64;
pub const MAX_FREQ_STEPS: usize = 32;
pub const MAX_CSTATES: usize = 8;
pub const GOVERNOR_SAMPLE_RATE_US: u64 = 10_000; // 10ms

// =============================================================================
// Governor types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GovernorType {
    Performance = 0,
    Powersave = 1,
    Ondemand = 2,
    Conservative = 3,
    Schedutil = 4,
    Userspace = 5,
}

impl GovernorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Performance  => "performance",
            Self::Powersave    => "powersave",
            Self::Ondemand     => "ondemand",
            Self::Conservative => "conservative",
            Self::Schedutil    => "schedutil",
            Self::Userspace    => "userspace",
        }
    }
}

// =============================================================================
// C-state (CPU idle state)
// =============================================================================

pub struct CState {
    pub name: [u8; 8],
    pub name_len: usize,
    pub latency_us: u32,       // Exit latency
    pub power_mw: u32,         // Power consumption
    pub usage_count: AtomicU64,
    pub total_time_us: AtomicU64,
    pub disabled: bool,
}

impl CState {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 8],
            name_len: 0,
            latency_us: 0,
            power_mw: 0,
            usage_count: AtomicU64::new(0),
            total_time_us: AtomicU64::new(0),
            disabled: false,
        }
    }
}

// =============================================================================
// Frequency domain (per-CPU or per-cluster)
// =============================================================================

pub struct FreqDomain {
    pub cpu_id: u8,
    pub active: bool,

    // Frequency info (kHz)
    pub min_freq_khz: u32,
    pub max_freq_khz: u32,
    pub cur_freq_khz: u32,
    pub available_freqs: [u32; MAX_FREQ_STEPS],
    pub freq_count: u32,

    // Governor
    pub governor: GovernorType,
    pub userspace_freq: u32,

    // Ondemand/conservative parameters
    pub up_threshold: u32,      // Load% to increase frequency (default 80)
    pub down_threshold: u32,    // Load% to decrease frequency (default 20)
    pub sampling_rate_us: u64,
    pub ignore_nice_load: bool,

    // Conservative specific
    pub freq_step_pct: u32,     // Step size in % (default 5)

    // Load tracking
    pub load_pct: u32,          // Current CPU load 0-100
    pub prev_idle_ns: u64,
    pub prev_total_ns: u64,

    // C-states
    pub cstates: [CState; MAX_CSTATES],
    pub cstate_count: u32,
    pub current_cstate: u8,

    // Transition stats
    pub transitions: AtomicU64,
    pub last_transition_ns: u64,
    pub total_transition_latency_ns: u64,

    // Thermal
    pub throttled: bool,
    pub thermal_limit_khz: u32,  // 0 = no thermal limit

    // Energy perf preference
    pub epp: u8,  // 0=perf, 128=balanced, 255=power
}

impl FreqDomain {
    pub const fn new(cpu: u8) -> Self {
        Self {
            cpu_id: cpu,
            active: false,
            min_freq_khz: 800_000,
            max_freq_khz: 4_000_000,
            cur_freq_khz: 2_000_000,
            available_freqs: [0u32; MAX_FREQ_STEPS],
            freq_count: 0,
            governor: GovernorType::Ondemand,
            userspace_freq: 0,
            up_threshold: 80,
            down_threshold: 20,
            sampling_rate_us: GOVERNOR_SAMPLE_RATE_US,
            ignore_nice_load: false,
            freq_step_pct: 5,
            load_pct: 0,
            prev_idle_ns: 0,
            prev_total_ns: 0,
            cstates: [const { CState::new() }; MAX_CSTATES],
            cstate_count: 0,
            current_cstate: 0,
            transitions: AtomicU64::new(0),
            last_transition_ns: 0,
            total_transition_latency_ns: 0,
            throttled: false,
            thermal_limit_khz: 0,
            epp: 128,
        }
    }

    /// Set frequency (clamped to min/max and thermal limit)
    pub fn set_frequency(&mut self, target_khz: u32, now_ns: u64) {
        let mut freq = target_khz.clamp(self.min_freq_khz, self.max_freq_khz);
        if self.thermal_limit_khz > 0 && freq > self.thermal_limit_khz {
            freq = self.thermal_limit_khz;
            self.throttled = true;
        }

        // Snap to nearest available frequency
        if self.freq_count > 0 {
            let mut best = self.available_freqs[0];
            let mut best_diff = freq.abs_diff(best);
            for i in 1..self.freq_count as usize {
                let diff = freq.abs_diff(self.available_freqs[i]);
                if diff < best_diff {
                    best = self.available_freqs[i];
                    best_diff = diff;
                }
            }
            freq = best;
        }

        if freq != self.cur_freq_khz {
            self.cur_freq_khz = freq;
            self.transitions.fetch_add(1, Ordering::Relaxed);
            let latency = now_ns.saturating_sub(self.last_transition_ns);
            self.total_transition_latency_ns += latency;
            self.last_transition_ns = now_ns;
        }
    }

    /// Update load measurement
    pub fn update_load(&mut self, idle_ns: u64, total_ns: u64) {
        let delta_idle = idle_ns.saturating_sub(self.prev_idle_ns);
        let delta_total = total_ns.saturating_sub(self.prev_total_ns);
        self.prev_idle_ns = idle_ns;
        self.prev_total_ns = total_ns;

        if delta_total > 0 {
            let busy = delta_total.saturating_sub(delta_idle);
            self.load_pct = ((busy as u128 * 100) / delta_total as u128) as u32;
        }
    }

    /// Run governor logic based on current load
    pub fn run_governor(&mut self, now_ns: u64) {
        let target = match self.governor {
            GovernorType::Performance => self.max_freq_khz,
            GovernorType::Powersave => self.min_freq_khz,
            GovernorType::Userspace => {
                if self.userspace_freq > 0 { self.userspace_freq } else { self.cur_freq_khz }
            }
            GovernorType::Ondemand => {
                if self.load_pct >= self.up_threshold {
                    self.max_freq_khz
                } else if self.load_pct < self.down_threshold {
                    // Scale proportionally
                    let range = self.max_freq_khz - self.min_freq_khz;
                    self.min_freq_khz + (range as u64 * self.load_pct as u64 / 100) as u32
                } else {
                    self.cur_freq_khz
                }
            }
            GovernorType::Conservative => {
                let step = (self.max_freq_khz - self.min_freq_khz) * self.freq_step_pct / 100;
                if self.load_pct >= self.up_threshold {
                    self.cur_freq_khz.saturating_add(step).min(self.max_freq_khz)
                } else if self.load_pct < self.down_threshold {
                    self.cur_freq_khz.saturating_sub(step).max(self.min_freq_khz)
                } else {
                    self.cur_freq_khz
                }
            }
            GovernorType::Schedutil => {
                // Utilization-based: freq = max_freq * utilization / max_capacity
                let range = self.max_freq_khz - self.min_freq_khz;
                let util_freq = self.min_freq_khz + (range as u64 * self.load_pct as u64 / 100) as u32;
                // Add headroom (1.25x)
                let with_headroom = util_freq + util_freq / 4;
                with_headroom.min(self.max_freq_khz)
            }
        };

        self.set_frequency(target, now_ns);
    }

    /// Select optimal C-state based on expected idle time
    pub fn select_cstate(&self, expected_idle_us: u64) -> u8 {
        let mut best = 0u8;
        for i in 0..self.cstate_count as usize {
            if self.cstates[i].disabled { continue; }
            // Select deepest C-state where exit latency < expected idle
            if self.cstates[i].latency_us as u64 <= expected_idle_us {
                best = i as u8;
            }
        }
        best
    }
}

// =============================================================================
// Global frequency manager
// =============================================================================

pub struct FreqManager {
    pub domains: [FreqDomain; MAX_FREQ_CPUS],
    pub active_count: u32,
    pub global_governor: GovernorType,
    pub boost_enabled: bool,
    pub boost_freq_khz: u32,
}

impl FreqManager {
    pub const fn new() -> Self {
        Self {
            domains: [const { FreqDomain::new(0) }; MAX_FREQ_CPUS],
            active_count: 0,
            global_governor: GovernorType::Ondemand,
            boost_enabled: true,
            boost_freq_khz: 0,
        }
    }

    pub fn register_cpu(&mut self, cpu: u8, min_khz: u32, max_khz: u32, freqs: &[u32]) {
        let idx = cpu as usize;
        if idx >= MAX_FREQ_CPUS { return; }
        self.domains[idx] = FreqDomain::new(cpu);
        self.domains[idx].active = true;
        self.domains[idx].min_freq_khz = min_khz;
        self.domains[idx].max_freq_khz = max_khz;
        self.domains[idx].cur_freq_khz = max_khz;
        self.domains[idx].governor = self.global_governor;
        let count = freqs.len().min(MAX_FREQ_STEPS);
        self.domains[idx].available_freqs[..count].copy_from_slice(&freqs[..count]);
        self.domains[idx].freq_count = count as u32;
        self.active_count += 1;
    }

    pub fn set_governor_all(&mut self, gov: GovernorType) {
        self.global_governor = gov;
        for i in 0..MAX_FREQ_CPUS {
            if self.domains[i].active {
                self.domains[i].governor = gov;
            }
        }
    }

    pub fn tick_all(&mut self, now_ns: u64) {
        for i in 0..MAX_FREQ_CPUS {
            if self.domains[i].active {
                self.domains[i].run_governor(now_ns);
            }
        }
    }

    pub fn thermal_throttle(&mut self, cpu: u8, limit_khz: u32) {
        let idx = cpu as usize;
        if idx < MAX_FREQ_CPUS && self.domains[idx].active {
            self.domains[idx].thermal_limit_khz = limit_khz;
        }
    }

    pub fn clear_thermal_throttle(&mut self, cpu: u8) {
        let idx = cpu as usize;
        if idx < MAX_FREQ_CPUS && self.domains[idx].active {
            self.domains[idx].thermal_limit_khz = 0;
            self.domains[idx].throttled = false;
        }
    }
}

static mut FREQ_MGR: FreqManager = FreqManager::new();

pub unsafe fn freq_manager() -> &'static mut FreqManager {
    &mut *core::ptr::addr_of_mut!(FREQ_MGR)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_set_governor(gov: u8) {
    let g = match gov {
        0 => GovernorType::Performance,
        1 => GovernorType::Powersave,
        2 => GovernorType::Ondemand,
        3 => GovernorType::Conservative,
        4 => GovernorType::Schedutil,
        _ => return,
    };
    unsafe { freq_manager().set_governor_all(g); }
}

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_tick(now_ns: u64) {
    unsafe { freq_manager().tick_all(now_ns); }
}

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_get(cpu: u8) -> u32 {
    let idx = cpu as usize;
    if idx >= MAX_FREQ_CPUS { return 0; }
    unsafe { freq_manager().domains[idx].cur_freq_khz }
}

#[no_mangle]
pub extern "C" fn zxyphor_cpufreq_thermal_throttle(cpu: u8, limit_khz: u32) {
    unsafe { freq_manager().thermal_throttle(cpu, limit_khz); }
}
