// =============================================================================
// Kernel Zxyphor — FADT (Fixed ACPI Description Table) Parser
// =============================================================================
// Parses FADT for:
//   - Power management profile
//   - SCI interrupt routing
//   - PM register locations
//   - Fixed hardware feature flags
//   - Reset register
//   - DSDT location
//   - Century register (RTC)
//   - Boot architecture flags
//   - Hardware-reduced ACPI support
// =============================================================================

// =============================================================================
// FADT structure
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fadt {
    // SDT header
    pub signature: [4]u8,
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [6]u8,
    pub oem_table_id: [8]u8,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,

    // FADT specific (ACPI 1.0)
    pub firmware_ctrl: u32,       // Physical address of FACS
    pub dsdt: u32,                // Physical address of DSDT

    pub reserved1: u8,
    pub preferred_pm_profile: u8,
    pub sci_interrupt: u16,       // SCI interrupt vector
    pub smi_command: u32,         // SMI command port
    pub acpi_enable: u8,          // Value to write to SMI_CMD to enable ACPI
    pub acpi_disable: u8,         // Value to write to SMI_CMD to disable ACPI
    pub s4bios_req: u8,
    pub pstate_cnt: u8,

    // PM1 event registers
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm2_control_block: u32,
    pub pm_timer_block: u32,
    pub gpe0_block: u32,
    pub gpe1_block: u32,

    pub pm1_event_length: u8,
    pub pm1_control_length: u8,
    pub pm2_control_length: u8,
    pub pm_timer_length: u8,
    pub gpe0_length: u8,
    pub gpe1_length: u8,
    pub gpe1_base: u8,
    pub cstate_control: u8,
    pub worst_c2_latency: u16,
    pub worst_c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,

    // RTC
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,

    // ACPI 2.0+ boot architecture flags
    pub boot_architecture_flags: u16,
    pub reserved2: u8,

    // Fixed feature flags
    pub flags: u32,

    // Reset register
    pub reset_reg_address_space: u8,
    pub reset_reg_bit_width: u8,
    pub reset_reg_bit_offset: u8,
    pub reset_reg_access_size: u8,
    pub reset_reg_address: u64,
    pub reset_value: u8,

    pub arm_boot_flags: u16,
    pub fadt_minor_version: u8,

    // ACPI 2.0 extended addresses
    pub x_firmware_ctrl: u64,
    pub x_dsdt: u64,

    pub x_pm1a_event_block: [12]u8,    // Generic Address Structure
    pub x_pm1b_event_block: [12]u8,
    pub x_pm1a_control_block: [12]u8,
    pub x_pm1b_control_block: [12]u8,
    pub x_pm2_control_block: [12]u8,
    pub x_pm_timer_block: [12]u8,
    pub x_gpe0_block: [12]u8,
    pub x_gpe1_block: [12]u8,
}

// =============================================================================
// PM profile types
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum PmProfile {
    Unspecified = 0,
    Desktop = 1,
    Mobile = 2,
    Workstation = 3,
    EnterpriseServer = 4,
    SohoServer = 5,
    AppliancePc = 6,
    PerformanceServer = 7,
    Tablet = 8,
}

// =============================================================================
// FADT flags
// =============================================================================

pub const FADT_WBINVD: u32 = 1 << 0;
pub const FADT_WBINVD_FLUSH: u32 = 1 << 1;
pub const FADT_PROC_C1: u32 = 1 << 2;
pub const FADT_P_LVL2_UP: u32 = 1 << 3;
pub const FADT_PWR_BUTTON: u32 = 1 << 4;
pub const FADT_SLP_BUTTON: u32 = 1 << 5;
pub const FADT_FIX_RTC: u32 = 1 << 6;
pub const FADT_RTC_S4: u32 = 1 << 7;
pub const FADT_TMR_VAL_EXT: u32 = 1 << 8;    // PM timer is 32-bit
pub const FADT_DCK_CAP: u32 = 1 << 9;
pub const FADT_RESET_REG_SUP: u32 = 1 << 10;
pub const FADT_SEALED_CASE: u32 = 1 << 11;
pub const FADT_HEADLESS: u32 = 1 << 12;
pub const FADT_CPU_SW_SLP: u32 = 1 << 13;
pub const FADT_PCI_EXP_WAK: u32 = 1 << 14;
pub const FADT_USE_PLATFORM_CLOCK: u32 = 1 << 15;
pub const FADT_S4_RTC_STS_VALID: u32 = 1 << 16;
pub const FADT_REMOTE_POWER_ON: u32 = 1 << 17;
pub const FADT_FORCE_APIC_CLUSTER: u32 = 1 << 18;
pub const FADT_FORCE_APIC_PHYS: u32 = 1 << 19;
pub const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
pub const FADT_LOW_POWER_S0: u32 = 1 << 21;

// =============================================================================
// Boot architecture flags
// =============================================================================

pub const BOOT_LEGACY_DEVICES: u16 = 1 << 0;
pub const BOOT_8042: u16 = 1 << 1;
pub const BOOT_VGA_NOT_PRESENT: u16 = 1 << 2;
pub const BOOT_MSI_NOT_SUPPORTED: u16 = 1 << 3;
pub const BOOT_PCIE_ASPM_CONTROLS: u16 = 1 << 4;
pub const BOOT_CMOS_RTC_NOT_PRESENT: u16 = 1 << 5;

// =============================================================================
// Parsed FADT information
// =============================================================================

pub struct FadtInfo {
    pub valid: bool,
    pub revision: u8,
    pub pm_profile: u8,
    pub sci_irq: u16,
    pub flags: u32,
    pub boot_flags: u16,

    // Power management ports
    pub pm1a_evt: u32,
    pub pm1a_cnt: u32,
    pub pm_timer: u32,
    pub smi_cmd: u32,

    // Power management values
    pub acpi_enable_val: u8,
    pub acpi_disable_val: u8,

    // Reset
    pub reset_supported: bool,
    pub reset_reg_addr: u64,
    pub reset_reg_space: u8,
    pub reset_value: u8,

    // DSDT
    pub dsdt_addr: u64,
    pub facs_addr: u64,

    // RTC
    pub century_reg: u8,
    pub rtc_century: bool,

    // Capabilities
    pub hw_reduced: bool,
    pub pm_timer_32bit: bool,
    pub has_8042: bool,
    pub has_legacy_devices: bool,
    pub has_cmos_rtc: bool,
}

impl FadtInfo {
    pub const fn new() Self {
        Self {
            valid: false,
            revision: 0,
            pm_profile: 0,
            sci_irq: 0,
            flags: 0,
            boot_flags: 0,
            pm1a_evt: 0,
            pm1a_cnt: 0,
            pm_timer: 0,
            smi_cmd: 0,
            acpi_enable_val: 0,
            acpi_disable_val: 0,
            reset_supported: false,
            reset_reg_addr: 0,
            reset_reg_space: 0,
            reset_value: 0,
            dsdt_addr: 0,
            facs_addr: 0,
            century_reg: 0,
            rtc_century: false,
            hw_reduced: false,
            pm_timer_32bit: false,
            has_8042: false,
            has_legacy_devices: false,
            has_cmos_rtc: true,
        }
    }

    /// Parse from raw FADT
    pub fn parse_from(fadt: &Fadt) -> Self {
        let mut info = Self::new();
        info.revision = fadt.revision;
        info.pm_profile = fadt.preferred_pm_profile;
        info.sci_irq = fadt.sci_interrupt;
        info.flags = fadt.flags;
        info.boot_flags = fadt.boot_architecture_flags;

        info.pm1a_evt = fadt.pm1a_event_block;
        info.pm1a_cnt = fadt.pm1a_control_block;
        info.pm_timer = fadt.pm_timer_block;
        info.smi_cmd = fadt.smi_command;
        info.acpi_enable_val = fadt.acpi_enable;
        info.acpi_disable_val = fadt.acpi_disable;

        // Reset register
        info.reset_supported = (fadt.flags & FADT_RESET_REG_SUP) != 0;
        info.reset_reg_addr = fadt.reset_reg_address;
        info.reset_reg_space = fadt.reset_reg_address_space;
        info.reset_value = fadt.reset_value;

        // DSDT - prefer 64-bit address
        info.dsdt_addr = if fadt.x_dsdt != 0 {
            fadt.x_dsdt
        } else {
            fadt.dsdt as u64
        };

        info.facs_addr = if fadt.x_firmware_ctrl != 0 {
            fadt.x_firmware_ctrl
        } else {
            fadt.firmware_ctrl as u64
        };

        // RTC
        info.century_reg = fadt.century;
        info.rtc_century = fadt.century != 0;

        // Feature parsing
        info.hw_reduced = (fadt.flags & FADT_HW_REDUCED_ACPI) != 0;
        info.pm_timer_32bit = (fadt.flags & FADT_TMR_VAL_EXT) != 0;
        info.has_8042 = (fadt.boot_architecture_flags & BOOT_8042) != 0;
        info.has_legacy_devices = (fadt.boot_architecture_flags & BOOT_LEGACY_DEVICES) != 0;
        info.has_cmos_rtc = (fadt.boot_architecture_flags & BOOT_CMOS_RTC_NOT_PRESENT) == 0;

        info.valid = true;
        info
    }

    /// Perform ACPI reset via the reset register
    pub fn reset_system(&self) {
        if !self.reset_supported || self.reset_reg_addr == 0 {
            return;
        }

        match self.reset_reg_space {
            0 => {
                // System memory
                unsafe {
                    let ptr = self.reset_reg_addr as *mut u8;
                    core::ptr::write_volatile(ptr, self.reset_value);
                }
            }
            1 => {
                // System I/O (port I/O)
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    let port = self.reset_reg_addr as u16;
                    core::arch::asm!(
                        "out dx, al",
                        in("dx") port,
                        in("al") self.reset_value,
                    );
                }
            }
            _ => {} // PCI config space etc - not supported here
        }
    }
}

// =============================================================================
// Global instance
// =============================================================================

static mut FADT_INFO: FadtInfo = FadtInfo::new();

fn fadt() -> &'static mut FadtInfo {
    unsafe { &mut FADT_INFO }
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_fadt_sci_irq() -> u16 {
    fadt().sci_irq
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_pm_timer() -> u32 {
    fadt().pm_timer
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_reset() {
    fadt().reset_system();
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_is_hw_reduced() -> bool {
    fadt().hw_reduced
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_dsdt_addr() -> u64 {
    fadt().dsdt_addr
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_pm_profile() -> u8 {
    fadt().pm_profile
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_has_8042() -> bool {
    fadt().has_8042
}

#[no_mangle]
pub extern "C" fn zxyphor_fadt_century_reg() -> u8 {
    fadt().century_reg
}
