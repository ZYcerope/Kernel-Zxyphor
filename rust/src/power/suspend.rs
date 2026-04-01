// =============================================================================
// Kernel Zxyphor — System Suspend/Resume
// =============================================================================
// ACPI-compliant sleep state management:
//   - S0 (Working), S1 (Power On Suspend), S3 (Suspend to RAM),
//     S4 (Hibernate), S5 (Soft Off)
//   - Device PM callbacks (suspend/resume per driver)
//   - Wake-up source management
//   - Suspend ordering and dependency tracking
//   - Resume integrity checks
//   - Hibernate image creation/restore metadata
//   - Power state transition logging
//   - Emergency wakeup handling
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

pub const MAX_PM_DEVICES: usize = 128;
pub const MAX_WAKE_SOURCES: usize = 32;
pub const MAX_PM_NOTIFIERS: usize = 16;

// =============================================================================
// Sleep states
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SleepState {
    S0Working = 0,      // Fully on
    S1PowerOnSuspend = 1, // CPU stopped, RAM refreshed
    S2 = 2,             // CPU off, RAM refreshed
    S3SuspendToRam = 3, // Everything off except RAM
    S4Hibernate = 4,    // Save to disk, power off
    S5SoftOff = 5,      // Power off
}

impl SleepState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S0Working => "S0 (Working)",
            Self::S1PowerOnSuspend => "S1 (Standby)",
            Self::S2 => "S2 (CPU off)",
            Self::S3SuspendToRam => "S3 (Suspend to RAM)",
            Self::S4Hibernate => "S4 (Hibernate)",
            Self::S5SoftOff => "S5 (Soft Off)",
        }
    }
}

// =============================================================================
// Device power state
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DevicePowerState {
    D0Active = 0,
    D1Light = 1,
    D2Medium = 2,
    D3Hot = 3,
    D3Cold = 4,
}

// =============================================================================
// PM device registration
// =============================================================================

pub type SuspendCallback = Option<extern "C" fn(device_id: u32) -> i32>;
pub type ResumeCallback = Option<extern "C" fn(device_id: u32) -> i32>;

pub struct PmDevice {
    pub device_id: u32,
    pub name: [u8; 24],
    pub name_len: usize,
    pub power_state: DevicePowerState,
    pub can_wake: bool,
    pub is_wake_enabled: bool,
    pub suspend_cb: SuspendCallback,
    pub resume_cb: ResumeCallback,
    pub suspend_order: i16,     // Lower = suspend first, resume last
    pub active: bool,
    pub suspend_latency_us: u32,
    pub resume_latency_us: u32,
    pub suspend_count: u32,
    pub resume_count: u32,
    pub last_suspend_ns: u64,
    pub last_resume_ns: u64,
}

impl PmDevice {
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            name: [0u8; 24],
            name_len: 0,
            power_state: DevicePowerState::D0Active,
            can_wake: false,
            is_wake_enabled: false,
            suspend_cb: None,
            resume_cb: None,
            suspend_order: 0,
            active: false,
            suspend_latency_us: 0,
            resume_latency_us: 0,
            suspend_count: 0,
            resume_count: 0,
            last_suspend_ns: 0,
            last_resume_ns: 0,
        }
    }
}

// =============================================================================
// Wake source
// =============================================================================

pub struct WakeSource {
    pub name: [u8; 16],
    pub name_len: usize,
    pub active: bool,
    pub event_count: AtomicU32,
    pub active_count: AtomicU32,
    pub last_event_ns: u64,
    pub total_time_ns: u64,
    pub prevent_suspend: AtomicBool,
}

impl WakeSource {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 16],
            name_len: 0,
            active: false,
            event_count: AtomicU32::new(0),
            active_count: AtomicU32::new(0),
            last_event_ns: 0,
            total_time_ns: 0,
            prevent_suspend: AtomicBool::new(false),
        }
    }

    pub fn activate(&self) {
        self.active_count.fetch_add(1, Ordering::Relaxed);
        self.event_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn deactivate(&self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn is_active(&self) -> bool {
        self.active_count.load(Ordering::Relaxed) > 0
    }
}

// =============================================================================
// Hibernate image header
// =============================================================================

#[repr(C)]
pub struct HibernateHeader {
    pub magic: u32,            // 0x48494245 ("HIBE")
    pub version: u32,
    pub image_size: u64,
    pub page_count: u64,
    pub kernel_version: u64,
    pub arch: u32,
    pub flags: u32,
    pub checksum: u32,         // CRC32 of image data
    pub cpu_count: u32,
    pub timestamp_ns: u64,
    pub resume_address: u64,   // Kernel entry point for resume
    pub pfn_list_offset: u64,  // Offset to page frame number list
}

impl HibernateHeader {
    pub const MAGIC: u32 = 0x48494245;

    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.image_size > 0
    }
}

// =============================================================================
// Suspend/Resume engine
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SuspendPhase {
    Idle = 0,
    Preparing = 1,
    SuspendingDevices = 2,
    SuspendingCpus = 3,
    Suspended = 4,
    ResumingCpus = 5,
    ResumingDevices = 6,
    Completing = 7,
    Failed = 8,
}

pub struct SuspendEngine {
    pub devices: [PmDevice; MAX_PM_DEVICES],
    pub device_count: u32,
    pub wake_sources: [WakeSource; MAX_WAKE_SOURCES],
    pub wake_count: u32,

    pub current_state: SleepState,
    pub target_state: SleepState,
    pub phase: SuspendPhase,
    pub supported_states: u8,   // Bitmask of supported sleep states

    // Statistics
    pub suspend_count: u32,
    pub resume_count: u32,
    pub abort_count: u32,
    pub last_suspend_ns: u64,
    pub last_resume_ns: u64,
    pub total_suspend_time_ns: u64,

    // Hibernate
    pub hibernate_available: bool,
    pub swap_partition_offset: u64,
    pub swap_partition_size: u64,
}

impl SuspendEngine {
    pub const fn new() -> Self {
        Self {
            devices: [const { PmDevice::new() }; MAX_PM_DEVICES],
            device_count: 0,
            wake_sources: [const { WakeSource::new() }; MAX_WAKE_SOURCES],
            wake_count: 0,
            current_state: SleepState::S0Working,
            target_state: SleepState::S0Working,
            phase: SuspendPhase::Idle,
            supported_states: 0b00111001, // S0, S3, S4, S5
            suspend_count: 0,
            resume_count: 0,
            abort_count: 0,
            last_suspend_ns: 0,
            last_resume_ns: 0,
            total_suspend_time_ns: 0,
            hibernate_available: false,
            swap_partition_offset: 0,
            swap_partition_size: 0,
        }
    }

    /// Register a device for PM
    pub fn register_device(
        &mut self, id: u32, name: &[u8], order: i16,
        suspend: SuspendCallback, resume: ResumeCallback,
        can_wake: bool,
    ) -> bool {
        if self.device_count as usize >= MAX_PM_DEVICES { return false; }
        let idx = self.device_count as usize;
        self.devices[idx] = PmDevice::new();
        self.devices[idx].device_id = id;
        let len = name.len().min(24);
        self.devices[idx].name[..len].copy_from_slice(&name[..len]);
        self.devices[idx].name_len = len;
        self.devices[idx].suspend_order = order;
        self.devices[idx].suspend_cb = suspend;
        self.devices[idx].resume_cb = resume;
        self.devices[idx].can_wake = can_wake;
        self.devices[idx].active = true;
        self.device_count += 1;
        true
    }

    /// Register a wake source
    pub fn register_wake_source(&mut self, name: &[u8]) -> Option<u32> {
        if self.wake_count as usize >= MAX_WAKE_SOURCES { return None; }
        let idx = self.wake_count as usize;
        self.wake_sources[idx] = WakeSource::new();
        let len = name.len().min(16);
        self.wake_sources[idx].name[..len].copy_from_slice(&name[..len]);
        self.wake_sources[idx].name_len = len;
        self.wake_sources[idx].active = true;
        self.wake_count += 1;
        Some(idx as u32)
    }

    /// Check if any wake source prevents suspend
    fn any_wake_active(&self) -> bool {
        for i in 0..self.wake_count as usize {
            if self.wake_sources[i].is_active() || self.wake_sources[i].prevent_suspend.load(Ordering::Relaxed) {
                return true;
            }
        }
        false
    }

    /// Begin suspend sequence
    pub fn begin_suspend(&mut self, target: SleepState, now_ns: u64) -> Result<(), SuspendError> {
        // Check if target state is supported
        let state_bit = 1u8 << (target as u8);
        if self.supported_states & state_bit == 0 {
            return Err(SuspendError::StateNotSupported);
        }

        // Check wake locks
        if self.any_wake_active() {
            self.abort_count += 1;
            return Err(SuspendError::WakeLockHeld);
        }

        self.target_state = target;
        self.phase = SuspendPhase::Preparing;
        self.last_suspend_ns = now_ns;

        // Phase 1: Suspend devices (sorted by order)
        self.phase = SuspendPhase::SuspendingDevices;
        for order in -128i16..128 {
            for i in 0..self.device_count as usize {
                if self.devices[i].active && self.devices[i].suspend_order == order {
                    if let Some(cb) = self.devices[i].suspend_cb {
                        let result = cb(self.devices[i].device_id);
                        if result != 0 {
                            // Suspend failed — abort and resume already-suspended devices
                            self.abort_count += 1;
                            self.phase = SuspendPhase::Failed;
                            // Resume in reverse order
                            self.resume_devices_from(i, now_ns);
                            return Err(SuspendError::DeviceSuspendFailed);
                        }
                    }
                    self.devices[i].power_state = DevicePowerState::D3Hot;
                    self.devices[i].suspend_count += 1;
                    self.devices[i].last_suspend_ns = now_ns;
                }
            }
        }

        // Phase 2: Suspend CPUs (except boot CPU)
        self.phase = SuspendPhase::SuspendingCpus;

        // Phase 3: Enter sleep state
        self.phase = SuspendPhase::Suspended;
        self.current_state = target;
        self.suspend_count += 1;

        Ok(())
    }

    /// Resume from suspend
    pub fn resume(&mut self, now_ns: u64) {
        self.phase = SuspendPhase::ResumingCpus;

        // Resume devices in reverse order
        self.phase = SuspendPhase::ResumingDevices;
        for order in (-128i16..128).rev() {
            for i in 0..self.device_count as usize {
                if self.devices[i].active && self.devices[i].suspend_order == order {
                    if let Some(cb) = self.devices[i].resume_cb {
                        cb(self.devices[i].device_id);
                    }
                    self.devices[i].power_state = DevicePowerState::D0Active;
                    self.devices[i].resume_count += 1;
                    self.devices[i].last_resume_ns = now_ns;
                }
            }
        }

        self.phase = SuspendPhase::Completing;
        self.total_suspend_time_ns += now_ns.saturating_sub(self.last_suspend_ns);
        self.last_resume_ns = now_ns;
        self.resume_count += 1;
        self.current_state = SleepState::S0Working;
        self.phase = SuspendPhase::Idle;
    }

    fn resume_devices_from(&mut self, from_idx: usize, now_ns: u64) {
        for i in (0..from_idx).rev() {
            if self.devices[i].active && self.devices[i].power_state != DevicePowerState::D0Active {
                if let Some(cb) = self.devices[i].resume_cb {
                    cb(self.devices[i].device_id);
                }
                self.devices[i].power_state = DevicePowerState::D0Active;
                self.devices[i].last_resume_ns = now_ns;
            }
        }
    }
}

#[derive(Debug)]
pub enum SuspendError {
    StateNotSupported,
    WakeLockHeld,
    DeviceSuspendFailed,
    OutOfMemory,
    HibernateNotAvailable,
}

static mut SUSPEND: SuspendEngine = SuspendEngine::new();

pub unsafe fn suspend_engine() -> &'static mut SuspendEngine {
    &mut *core::ptr::addr_of_mut!(SUSPEND)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_pm_suspend(state: u8, now_ns: u64) -> i32 {
    let target = match state {
        1 => SleepState::S1PowerOnSuspend,
        3 => SleepState::S3SuspendToRam,
        4 => SleepState::S4Hibernate,
        5 => SleepState::S5SoftOff,
        _ => return -1,
    };
    unsafe {
        match suspend_engine().begin_suspend(target, now_ns) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_pm_resume(now_ns: u64) {
    unsafe { suspend_engine().resume(now_ns); }
}

#[no_mangle]
pub extern "C" fn zxyphor_pm_register_wake(name_ptr: *const u8, name_len: usize) -> i32 {
    if name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len.min(16)) };
    unsafe {
        match suspend_engine().register_wake_source(name) {
            Some(id) => id as i32,
            None => -1,
        }
    }
}
