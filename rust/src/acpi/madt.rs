// =============================================================================
// Kernel Zxyphor — MADT (Multiple APIC Description Table) Parser
// =============================================================================
// Parses MADT to discover:
//   - Local APIC entries (per-CPU)
//   - I/O APIC entries
//   - Interrupt source overrides
//   - NMI sources
//   - Local APIC NMI entries
//   - x2APIC entries
// =============================================================================

// =============================================================================
// MADT entry types
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum MadtEntryType {
    LocalApic = 0,
    IoApic = 1,
    InterruptOverride = 2,
    NmiSource = 3,
    LocalApicNmi = 4,
    LocalApicOverride = 5,
    IoSapic = 6,
    LocalSapic = 7,
    PlatformInterrupt = 8,
    X2Apic = 9,
    X2ApicNmi = 10,
    GicCpu = 11,
    GicDist = 12,
    GicMsiFrame = 13,
    GicRedist = 14,
    GicIts = 15,
}

// =============================================================================
// MADT header
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtHeader {
    pub signature: [4]u8,
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [6]u8,
    pub oem_table_id: [8]u8,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    // MADT specific
    pub local_apic_address: u32,
    pub flags: u32,           // bit 0: PCAT_COMPAT (dual 8259 PICs present)
}

impl MadtHeader {
    pub fn has_legacy_pics(&self) -> bool {
        (self.flags & 1) != 0
    }
}

// =============================================================================
// MADT entry header (common to all entry types)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtEntryHeader {
    pub entry_type: u8,
    pub length: u8,
}

// =============================================================================
// Local APIC entry (type 0)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtLocalApic {
    pub header: MadtEntryHeader,
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

impl MadtLocalApic {
    pub fn is_enabled(&self) -> bool {
        (self.flags & 1) != 0
    }

    pub fn is_online_capable(&self) -> bool {
        (self.flags & 2) != 0
    }
}

// =============================================================================
// I/O APIC entry (type 1)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtIoApic {
    pub header: MadtEntryHeader,
    pub io_apic_id: u8,
    pub reserved: u8,
    pub io_apic_address: u32,
    pub global_system_interrupt_base: u32,
}

// =============================================================================
// Interrupt Source Override (type 2)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtInterruptOverride {
    pub header: MadtEntryHeader,
    pub bus: u8,             // Always 0 (ISA)
    pub source: u8,          // ISA IRQ number
    pub gsi: u32,            // Global System Interrupt
    pub flags: u16,          // Polarity and trigger mode
}

impl MadtInterruptOverride {
    /// Polarity: 0=bus default, 1=active high, 2=reserved, 3=active low
    pub fn polarity(&self) -> u8 {
        (self.flags & 0x3) as u8
    }

    /// Trigger: 0=bus default, 1=edge, 2=reserved, 3=level
    pub fn trigger_mode(&self) -> u8 {
        ((self.flags >> 2) & 0x3) as u8
    }
}

// =============================================================================
// Local APIC NMI (type 4)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtLocalApicNmi {
    pub header: MadtEntryHeader,
    pub acpi_processor_id: u8,  // 0xFF = all processors
    pub flags: u16,
    pub lint_number: u8,        // 0 or 1 (LINT0 or LINT1)
}

// =============================================================================
// x2APIC entry (type 9)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MadtX2Apic {
    pub header: MadtEntryHeader,
    pub reserved: u16,
    pub x2apic_id: u32,
    pub flags: u32,
    pub acpi_processor_uid: u32,
}

impl MadtX2Apic {
    pub fn is_enabled(&self) -> bool {
        (self.flags & 1) != 0
    }
}

// =============================================================================
// Parsed MADT info
// =============================================================================

pub const MAX_CPUS: usize = 256;
pub const MAX_IO_APICS: usize = 8;
pub const MAX_OVERRIDES: usize = 16;
pub const MAX_NMI: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuInfo {
    pub apic_id: u32,
    pub acpi_id: u32,
    pub enabled: bool,
    pub is_x2apic: bool,
    pub online_capable: bool,
}

impl CpuInfo {
    pub const fn empty() Self {
        Self {
            apic_id: 0,
            acpi_id: 0,
            enabled: false,
            is_x2apic: false,
            online_capable: false,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoApicInfo {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

impl IoApicInfo {
    pub const fn empty() Self {
        Self { id: 0, address: 0, gsi_base: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IrqOverride {
    pub source_irq: u8,
    pub gsi: u32,
    pub polarity: u8,
    pub trigger: u8,
}

impl IrqOverride {
    pub const fn empty() Self {
        Self { source_irq: 0, gsi: 0, polarity: 0, trigger: 0 }
    }
}

pub struct MadtInfo {
    pub local_apic_addr: u32,
    pub has_legacy_pics: bool,

    pub cpus: [CpuInfo; MAX_CPUS],
    pub cpu_count: u32,

    pub io_apics: [IoApicInfo; MAX_IO_APICS],
    pub io_apic_count: u32,

    pub overrides: [IrqOverride; MAX_OVERRIDES],
    pub override_count: u32,

    pub nmi_lint: [u8; MAX_NMI],
    pub nmi_count: u32,

    pub parsed: bool,
}

impl MadtInfo {
    pub const fn new() Self {
        Self {
            local_apic_addr: 0,
            has_legacy_pics: false,
            cpus: [const { CpuInfo::empty() }; MAX_CPUS],
            cpu_count: 0,
            io_apics: [const { IoApicInfo::empty() }; MAX_IO_APICS],
            io_apic_count: 0,
            overrides: [const { IrqOverride::empty() }; MAX_OVERRIDES],
            override_count: 0,
            nmi_lint: [0u8; MAX_NMI],
            nmi_count: 0,
            parsed: false,
        }
    }

    /// Register a Local APIC (CPU)
    pub fn add_cpu(&mut self, apic_id: u32, acpi_id: u32, enabled: bool, x2apic: bool) {
        if self.cpu_count >= MAX_CPUS as u32 { return; }
        let idx = self.cpu_count as usize;
        self.cpus[idx] = CpuInfo {
            apic_id,
            acpi_id,
            enabled,
            is_x2apic: x2apic,
            online_capable: enabled,
        };
        self.cpu_count += 1;
    }

    /// Register an I/O APIC
    pub fn add_io_apic(&mut self, id: u8, address: u32, gsi_base: u32) {
        if self.io_apic_count >= MAX_IO_APICS as u32 { return; }
        let idx = self.io_apic_count as usize;
        self.io_apics[idx] = IoApicInfo { id, address, gsi_base };
        self.io_apic_count += 1;
    }

    /// Register an interrupt override
    pub fn add_override(&mut self, source: u8, gsi: u32, polarity: u8, trigger: u8) {
        if self.override_count >= MAX_OVERRIDES as u32 { return; }
        let idx = self.override_count as usize;
        self.overrides[idx] = IrqOverride { source_irq: source, gsi, polarity, trigger };
        self.override_count += 1;
    }

    /// Get the GSI for a given ISA IRQ (applying overrides)
    pub fn irq_to_gsi(&self, irq: u8) -> u32 {
        for i in 0..self.override_count as usize {
            if self.overrides[i].source_irq == irq {
                return self.overrides[i].gsi;
            }
        }
        irq as u32 // Identity mapping
    }

    /// Count enabled CPUs
    pub fn enabled_cpu_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.cpu_count as usize {
            if self.cpus[i].enabled { count += 1; }
        }
        count
    }

    /// Get BSP (Bootstrap Processor) APIC ID
    pub fn bsp_apic_id(&self) -> u32 {
        if self.cpu_count > 0 { self.cpus[0].apic_id } else { 0 }
    }
}

// =============================================================================
// Global instance
// =============================================================================

static mut MADT_INFO: MadtInfo = MadtInfo::new();

fn madt() -> &'static mut MadtInfo {
    unsafe { &mut MADT_INFO }
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_madt_add_cpu(apic_id: u32, acpi_id: u32, enabled: bool) {
    madt().add_cpu(apic_id, acpi_id, enabled, false);
}

#[no_mangle]
pub extern "C" fn zxyphor_madt_add_x2apic(x2apic_id: u32, acpi_uid: u32, enabled: bool) {
    madt().add_cpu(x2apic_id, acpi_uid, enabled, true);
}

#[no_mangle]
pub extern "C" fn zxyphor_madt_add_io_apic(id: u8, addr: u32, gsi_base: u32) {
    madt().add_io_apic(id, addr, gsi_base);
}

#[no_mangle]
pub extern "C" fn zxyphor_madt_add_override(source: u8, gsi: u32, polarity: u8, trigger: u8) {
    madt().add_override(source, gsi, polarity, trigger);
}

#[no_mangle]
pub extern "C" fn zxyphor_madt_cpu_count() -> u32 {
    madt().enabled_cpu_count()
}

#[no_mangle]
pub extern "C" fn zxyphor_madt_irq_to_gsi(irq: u8) -> u32 {
    madt().irq_to_gsi(irq)
}

#[no_mangle]
pub extern "C" fn zxyphor_madt_bsp_id() -> u32 {
    madt().bsp_apic_id()
}
