// =============================================================================
// Kernel Zxyphor — S.M.A.R.T. Health Monitoring
// =============================================================================
// Self-Monitoring, Analysis and Reporting Technology:
//   - ATA SMART attribute parsing (ID, flags, value, worst, raw)
//   - Known attribute database (temperature, reallocated sectors, etc.)
//   - Health assessment (OK/warning/critical thresholds)
//   - Drive temperature monitoring with trend analysis
//   - Predictive failure analysis
//   - Error log parsing
//   - Self-test scheduling and result tracking
//   - NVMe health info page support
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const MAX_SMART_ATTRS: usize = 30;
pub const MAX_DRIVES: usize = 16;
pub const MAX_ERROR_LOG: usize = 8;

// =============================================================================
// SMART attribute
// =============================================================================

#[derive(Clone, Copy, Debug)]
pub struct SmartAttribute {
    pub id: u8,
    pub flags: u16,
    pub current: u8,
    pub worst: u8,
    pub threshold: u8,
    pub raw: [u8; 6],
    pub valid: bool,
}

impl SmartAttribute {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            flags: 0,
            current: 0,
            worst: 0,
            threshold: 0,
            raw: [0u8; 6],
            valid: false,
        }
    }

    /// Get raw value as u64
    pub fn raw_value(&self) -> u64 {
        let mut val = 0u64;
        for i in 0..6 {
            val |= (self.raw[i] as u64) << (i * 8);
        }
        val
    }

    /// Check if attribute is pre-fail (= critical failure indicator)
    pub fn is_prefail(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Check if below threshold
    pub fn is_failing(&self) -> bool {
        self.threshold > 0 && self.current <= self.threshold
    }

    /// Check if worst-ever was below threshold
    pub fn has_failed(&self) -> bool {
        self.threshold > 0 && self.worst <= self.threshold
    }

    /// Human-readable name for known attributes
    pub fn name(&self) -> &'static str {
        match self.id {
            1 => "Raw Read Error Rate",
            2 => "Throughput Performance",
            3 => "Spin-Up Time",
            4 => "Start/Stop Count",
            5 => "Reallocated Sectors Count",
            7 => "Seek Error Rate",
            9 => "Power-On Hours",
            10 => "Spin Retry Count",
            11 => "Calibration Retry Count",
            12 => "Power Cycle Count",
            170 => "Available Reserved Space",
            171 => "Program Fail Count",
            172 => "Erase Fail Count",
            173 => "Wear Leveling Count",
            174 => "Unexpected Power Loss",
            175 => "Power Loss Protection",
            176 => "Erase Fail Count (Chip)",
            177 => "Wear Range Delta",
            181 => "Program Fail Count (Total)",
            182 => "Erase Fail Count (Total)",
            183 => "Runtime Bad Block",
            184 => "End-to-End Error",
            187 => "Reported Uncorrectable Errors",
            188 => "Command Timeout",
            189 => "High Fly Writes",
            190 => "Airflow Temperature",
            191 => "G-Sense Error Rate",
            192 => "Unsafe Shutdown Count",
            193 => "Load/Unload Cycle Count",
            194 => "Temperature",
            195 => "Hardware ECC Recovered",
            196 => "Reallocation Event Count",
            197 => "Current Pending Sector Count",
            198 => "Offline Uncorrectable",
            199 => "UDMA CRC Error Count",
            200 => "Write Error Rate",
            201 => "Soft Read Error Rate",
            220 => "Disk Shift",
            222 => "Loaded Hours",
            223 => "Load/Unload Retry Count",
            224 => "Load Friction",
            226 => "Load-In Time",
            230 => "Drive Life Protection",
            231 => "SSD Life Left",
            232 => "Endurance Remaining",
            233 => "Media Wearout Indicator",
            234 => "Average Erase Count",
            235 => "Good Block Count",
            240 => "Head Flying Hours",
            241 => "Total LBAs Written",
            242 => "Total LBAs Read",
            250 => "Read Error Retry Rate",
            _ => "Unknown",
        }
    }
}

// =============================================================================
// Health status
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthStatus {
    Good = 0,
    Warning = 1,
    Critical = 2,
    Failed = 3,
    Unknown = 4,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Good => "GOOD",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

// =============================================================================
// Temperature tracking
// =============================================================================

pub const TEMP_HISTORY_SIZE: usize = 60; // Last 60 readings

pub struct TemperatureTracker {
    pub current: i16,
    pub min_ever: i16,
    pub max_ever: i16,
    pub history: [i16; TEMP_HISTORY_SIZE],
    pub history_index: usize,
    pub history_count: usize,
    pub warning_threshold: i16,
    pub critical_threshold: i16,
    pub shutdown_threshold: i16,
}

impl TemperatureTracker {
    pub const fn new() -> Self {
        Self {
            current: 0,
            min_ever: i16::MAX,
            max_ever: i16::MIN,
            history: [0i16; TEMP_HISTORY_SIZE],
            history_index: 0,
            history_count: 0,
            warning_threshold: 45, // Celsius
            critical_threshold: 55,
            shutdown_threshold: 65,
        }
    }

    pub fn record(&mut self, temp: i16) {
        self.current = temp;
        if temp < self.min_ever { self.min_ever = temp; }
        if temp > self.max_ever { self.max_ever = temp; }
        self.history[self.history_index] = temp;
        self.history_index = (self.history_index + 1) % TEMP_HISTORY_SIZE;
        if self.history_count < TEMP_HISTORY_SIZE {
            self.history_count += 1;
        }
    }

    /// Calculate average temperature from history
    pub fn average(&self) -> i16 {
        if self.history_count == 0 { return 0; }
        let sum: i32 = self.history[..self.history_count].iter().map(|&t| t as i32).sum();
        (sum / self.history_count as i32) as i16
    }

    /// Detect temperature trend (positive = heating, negative = cooling)
    pub fn trend(&self) -> i16 {
        if self.history_count < 4 { return 0; }

        // Compare recent avg to older avg
        let half = self.history_count / 2;
        let old_sum: i32 = self.history[..half].iter().map(|&t| t as i32).sum();
        let new_sum: i32 = self.history[half..self.history_count].iter().map(|&t| t as i32).sum();
        let old_avg = old_sum / half as i32;
        let new_count = self.history_count - half;
        let new_avg = new_sum / new_count as i32;
        (new_avg - old_avg) as i16
    }

    pub fn status(&self) -> HealthStatus {
        if self.current >= self.shutdown_threshold { HealthStatus::Failed }
        else if self.current >= self.critical_threshold { HealthStatus::Critical }
        else if self.current >= self.warning_threshold { HealthStatus::Warning }
        else { HealthStatus::Good }
    }
}

// =============================================================================
// Self-test types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SelfTestType {
    Short = 1,
    Extended = 2,
    Conveyance = 3,
    Selective = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SelfTestStatus {
    NotRun = 0,
    InProgress = 1,
    Passed = 2,
    Failed = 3,
    Interrupted = 4,
    Aborted = 5,
}

#[derive(Clone, Copy)]
pub struct SelfTestResult {
    pub test_type: SelfTestType,
    pub status: SelfTestStatus,
    pub remaining_pct: u8,
    pub lifetime_hours: u32,
    pub failing_lba: u64,
    pub timestamp: u64,
}

impl SelfTestResult {
    pub const fn empty() -> Self {
        Self {
            test_type: SelfTestType::Short,
            status: SelfTestStatus::NotRun,
            remaining_pct: 0,
            lifetime_hours: 0,
            failing_lba: 0,
            timestamp: 0,
        }
    }
}

// =============================================================================
// Error log entry
// =============================================================================

#[derive(Clone, Copy)]
pub struct SmartErrorEntry {
    pub error_type: u8,
    pub lba: u64,
    pub count: u32,
    pub timestamp: u64,
    pub status: u8,
}

impl SmartErrorEntry {
    pub const fn empty() -> Self {
        Self { error_type: 0, lba: 0, count: 0, timestamp: 0, status: 0 }
    }
}

// =============================================================================
// NVMe health info
// =============================================================================

#[derive(Clone, Copy)]
pub struct NvmeHealthInfo {
    pub critical_warning: u8,
    pub composite_temp: u16,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_time: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub error_log_entries: u128,
}

impl NvmeHealthInfo {
    pub const fn empty() -> Self {
        Self {
            critical_warning: 0,
            composite_temp: 0,
            available_spare: 0,
            available_spare_threshold: 0,
            percentage_used: 0,
            data_units_read: 0,
            data_units_written: 0,
            host_read_commands: 0,
            host_write_commands: 0,
            controller_busy_time: 0,
            power_cycles: 0,
            power_on_hours: 0,
            unsafe_shutdowns: 0,
            media_errors: 0,
            error_log_entries: 0,
        }
    }

    pub fn health_status(&self) -> HealthStatus {
        if self.critical_warning != 0 { return HealthStatus::Critical; }
        if self.available_spare < self.available_spare_threshold {
            return HealthStatus::Warning;
        }
        if self.percentage_used > 100 { return HealthStatus::Warning; }
        if self.media_errors > 0 { return HealthStatus::Warning; }
        HealthStatus::Good
    }
}

// =============================================================================
// Per-drive SMART data
// =============================================================================

pub struct DriveSmartData {
    pub device_id: u16,
    pub active: bool,
    pub model: [u8; 40],
    pub model_len: u8,
    pub serial: [u8; 20],
    pub serial_len: u8,
    pub firmware: [u8; 8],
    pub firmware_len: u8,
    pub is_ssd: bool,
    pub is_nvme: bool,
    pub capacity_sectors: u64,
    // ATA SMART
    pub attributes: [SmartAttribute; MAX_SMART_ATTRS],
    pub attr_count: usize,
    pub smart_enabled: bool,
    // NVMe health
    pub nvme_health: NvmeHealthInfo,
    // Temperature
    pub temp: TemperatureTracker,
    // Self-test results
    pub last_test: SelfTestResult,
    pub test_in_progress: bool,
    // Error log
    pub errors: [SmartErrorEntry; MAX_ERROR_LOG],
    pub error_count: usize,
    // Statistics
    pub power_on_hours: u64,
    pub power_cycles: u64,
    pub reallocated_sectors: u64,
    pub pending_sectors: u64,
    pub offline_uncorrectable: u64,
    // Overall health
    pub health: HealthStatus,
    pub last_check: u64,
}

impl DriveSmartData {
    pub const fn new() -> Self {
        Self {
            device_id: 0xFFFF,
            active: false,
            model: [0u8; 40],
            model_len: 0,
            serial: [0u8; 20],
            serial_len: 0,
            firmware: [0u8; 8],
            firmware_len: 0,
            is_ssd: false,
            is_nvme: false,
            capacity_sectors: 0,
            attributes: [const { SmartAttribute::empty() }; MAX_SMART_ATTRS],
            attr_count: 0,
            smart_enabled: false,
            nvme_health: NvmeHealthInfo::empty(),
            temp: TemperatureTracker::new(),
            last_test: SelfTestResult::empty(),
            test_in_progress: false,
            errors: [const { SmartErrorEntry::empty() }; MAX_ERROR_LOG],
            error_count: 0,
            power_on_hours: 0,
            power_cycles: 0,
            reallocated_sectors: 0,
            pending_sectors: 0,
            offline_uncorrectable: 0,
            health: HealthStatus::Unknown,
            last_check: 0,
        }
    }

    /// Parse SMART data from ATA SMART READ DATA response (512 bytes)
    pub fn parse_ata_smart(&mut self, data: &[u8; 512]) {
        self.smart_enabled = true;
        self.attr_count = 0;

        // Attributes start at offset 2, each is 12 bytes, up to 30 attributes
        let mut offset = 2usize;
        while offset + 12 <= 362 && self.attr_count < MAX_SMART_ATTRS {
            let id = data[offset];
            if id == 0 {
                offset += 12;
                continue;
            }

            let attr = &mut self.attributes[self.attr_count];
            attr.id = id;
            attr.flags = u16::from_le_bytes([data[offset + 1], data[offset + 2]]);
            attr.current = data[offset + 3];
            attr.worst = data[offset + 4];
            attr.raw.copy_from_slice(&data[offset + 5..offset + 11]);
            attr.threshold = data[offset + 11];
            attr.valid = true;

            // Extract key indicators
            match id {
                5 => self.reallocated_sectors = attr.raw_value(),
                9 => self.power_on_hours = attr.raw_value(),
                12 => self.power_cycles = attr.raw_value(),
                190 | 194 => {
                    let temp = (attr.raw_value() & 0xFF) as i16;
                    self.temp.record(temp);
                }
                197 => self.pending_sectors = attr.raw_value(),
                198 => self.offline_uncorrectable = attr.raw_value(),
                _ => {}
            }

            self.attr_count += 1;
            offset += 12;
        }
    }

    /// Evaluate overall health
    pub fn evaluate_health(&mut self) -> HealthStatus {
        if self.is_nvme {
            self.health = self.nvme_health.health_status();
            return self.health;
        }

        let mut worst = HealthStatus::Good;

        // Check for critical pre-fail attributes
        for i in 0..self.attr_count {
            let attr = &self.attributes[i];
            if !attr.valid { continue; }

            if attr.is_failing() && attr.is_prefail() {
                worst = HealthStatus::Failed;
                break;
            }
            if attr.has_failed() && attr.is_prefail() {
                if worst as u8 <= HealthStatus::Critical as u8 {
                    worst = HealthStatus::Critical;
                }
            }
        }

        // Check specific indicators
        if self.reallocated_sectors > 100 && worst as u8 <= HealthStatus::Warning as u8 {
            worst = HealthStatus::Warning;
        }
        if self.pending_sectors > 10 && worst as u8 <= HealthStatus::Warning as u8 {
            worst = HealthStatus::Warning;
        }
        if self.offline_uncorrectable > 0 && worst as u8 <= HealthStatus::Warning as u8 {
            worst = HealthStatus::Warning;
        }

        // Temperature check
        let temp_status = self.temp.status();
        if temp_status as u8 > worst as u8 {
            worst = temp_status;
        }

        self.health = worst;
        worst
    }

    /// Get attribute by ID
    pub fn get_attribute(&self, id: u8) -> Option<&SmartAttribute> {
        for i in 0..self.attr_count {
            if self.attributes[i].valid && self.attributes[i].id == id {
                return Some(&self.attributes[i]);
            }
        }
        None
    }
}

// =============================================================================
// Global SMART registry
// =============================================================================

pub struct SmartRegistry {
    pub drives: [DriveSmartData; MAX_DRIVES],
    pub drive_count: AtomicU32,
}

impl SmartRegistry {
    pub const fn new() -> Self {
        Self {
            drives: [const { DriveSmartData::new() }; MAX_DRIVES],
            drive_count: AtomicU32::new(0),
        }
    }

    pub fn register_drive(&mut self, device_id: u16) -> Option<usize> {
        let count = self.drive_count.load(Ordering::Acquire) as usize;
        for i in 0..MAX_DRIVES {
            if !self.drives[i].active {
                self.drives[i].active = true;
                self.drives[i].device_id = device_id;
                if i >= count {
                    self.drive_count.store((i + 1) as u32, Ordering::Release);
                }
                return Some(i);
            }
        }
        None
    }

    pub fn get_drive(&mut self, device_id: u16) -> Option<&mut DriveSmartData> {
        let count = self.drive_count.load(Ordering::Acquire) as usize;
        for i in 0..count {
            if self.drives[i].active && self.drives[i].device_id == device_id {
                return Some(&mut self.drives[i]);
            }
        }
        None
    }

    /// Run health check on all drives
    pub fn check_all(&mut self) -> HealthStatus {
        let count = self.drive_count.load(Ordering::Acquire) as usize;
        let mut worst = HealthStatus::Good;
        for i in 0..count {
            if !self.drives[i].active { continue; }
            let status = self.drives[i].evaluate_health();
            if status as u8 > worst as u8 {
                worst = status;
            }
        }
        worst
    }
}

static mut SMART: SmartRegistry = SmartRegistry::new();

pub unsafe fn smart_registry() -> &'static mut SmartRegistry {
    &mut *core::ptr::addr_of_mut!(SMART)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_smart_register(device_id: u16) -> i32 {
    unsafe {
        match smart_registry().register_drive(device_id) {
            Some(idx) => idx as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_smart_check_all() -> u8 {
    unsafe { smart_registry().check_all() as u8 }
}

#[no_mangle]
pub extern "C" fn zxyphor_smart_temperature(device_id: u16) -> i16 {
    unsafe {
        smart_registry().get_drive(device_id).map_or(0, |d| d.temp.current)
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_smart_health(device_id: u16) -> u8 {
    unsafe {
        smart_registry().get_drive(device_id).map_or(
            HealthStatus::Unknown as u8,
            |d| d.health as u8,
        )
    }
}
