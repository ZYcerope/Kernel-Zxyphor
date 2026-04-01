// =============================================================================
// Kernel Zxyphor — ACPI Table Infrastructure
// =============================================================================
// Core ACPI table parsing: RSDP, RSDT/XSDT, generic SDT header validation,
// table signature matching, checksum verification, and table discovery.
// =============================================================================

// =============================================================================
// Constants
// =============================================================================

pub const MAX_ACPI_TABLES: usize = 32;
pub const RSDP_SIGNATURE: [8]u8 = *b"RSD PTR ";

// Table signatures (4 bytes)
pub const SIG_RSDT: [4]u8 = *b"RSDT";
pub const SIG_XSDT: [4]u8 = *b"XSDT";
pub const SIG_FACP: [4]u8 = *b"FACP"; // FADT
pub const SIG_APIC: [4]u8 = *b"APIC"; // MADT
pub const SIG_MCFG: [4]u8 = *b"MCFG";
pub const SIG_HPET: [4]u8 = *b"HPET";
pub const SIG_DMAR: [4]u8 = *b"DMAR";
pub const SIG_SRAT: [4]u8 = *b"SRAT";
pub const SIG_SLIT: [4]u8 = *b"SLIT";
pub const SIG_DSDT: [4]u8 = *b"DSDT";
pub const SIG_SSDT: [4]u8 = *b"SSDT";
pub const SIG_BGRT: [4]u8 = *b"BGRT";
pub const SIG_BERT: [4]u8 = *b"BERT";
pub const SIG_CPEP: [4]u8 = *b"CPEP";
pub const SIG_ECDT: [4]u8 = *b"ECDT";
pub const SIG_EINJ: [4]u8 = *b"EINJ";
pub const SIG_ERST: [4]u8 = *b"ERST";
pub const SIG_FPDT: [4]u8 = *b"FPDT";
pub const SIG_GTDT: [4]u8 = *b"GTDT";
pub const SIG_HEST: [4]u8 = *b"HEST";
pub const SIG_MSCT: [4]u8 = *b"MSCT";
pub const SIG_MPST: [4]u8 = *b"MPST";
pub const SIG_NFIT: [4]u8 = *b"NFIT";
pub const SIG_PMTT: [4]u8 = *b"PMTT";
pub const SIG_SBST: [4]u8 = *b"SBST";
pub const SIG_WAET: [4]u8 = *b"WAET";
pub const SIG_WDAT: [4]u8 = *b"WDAT";
pub const SIG_WDDT: [4]u8 = *b"WDDT";
pub const SIG_WDRT: [4]u8 = *b"WDRT";

// =============================================================================
// RSDP (Root System Description Pointer)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Rsdp {
    pub signature: [8]u8,
    pub checksum: u8,
    pub oem_id: [6]u8,
    pub revision: u8,       // 0 = ACPI 1.0, 2 = ACPI 2.0+
    pub rsdt_address: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Rsdp2 {
    // RSDP 1.0 fields
    pub signature: [8]u8,
    pub checksum: u8,
    pub oem_id: [6]u8,
    pub revision: u8,
    pub rsdt_address: u32,
    // RSDP 2.0 extended fields
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [3]u8,
}

impl Rsdp {
    /// Validate RSDP checksum (first 20 bytes must sum to 0 mod 256)
    pub fn validate(&self) -> bool {
        let ptr = self as *const Rsdp as *const u8;
        let mut sum: u8 = 0;
        for i in 0..20 {
            sum = sum.wrapping_add(unsafe { *ptr.add(i) });
        }
        sum == 0
    }

    pub fn is_acpi2(&self) -> bool {
        self.revision >= 2
    }
}

impl Rsdp2 {
    /// Validate extended checksum (entire structure)
    pub fn validate_extended(&self) -> bool {
        let ptr = self as *const Rsdp2 as *const u8;
        let mut sum: u8 = 0;
        for i in 0..self.length as usize {
            sum = sum.wrapping_add(unsafe { *ptr.add(i) });
        }
        sum == 0
    }
}

// =============================================================================
// SDT Header (common to all ACPI tables)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SdtHeader {
    pub signature: [4]u8,
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [6]u8,
    pub oem_table_id: [8]u8,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl SdtHeader {
    pub const SIZE: usize = 36;

    /// Validate table checksum
    pub fn validate(&self) -> bool {
        let ptr = self as *const SdtHeader as *const u8;
        let mut sum: u8 = 0;
        for i in 0..self.length as usize {
            sum = sum.wrapping_add(unsafe { *ptr.add(i) });
        }
        sum == 0
    }

    pub fn sig_matches(&self, sig: &[4]u8) -> bool {
        self.signature == *sig
    }

    /// Data length (total length minus header)
    pub fn data_length(&self) -> u32 {
        self.length.saturating_sub(Self::SIZE as u32)
    }
}

// =============================================================================
// Table entry in our registry
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcpiTableEntry {
    pub signature: [4]u8,
    pub physical_addr: u64,
    pub length: u32,
    pub revision: u8,
    pub valid: bool,
}

impl AcpiTableEntry {
    pub const fn empty() Self {
        Self {
            signature: [0u8; 4],
            physical_addr: 0,
            length: 0,
            revision: 0,
            valid: false,
        }
    }
}

// =============================================================================
// MCFG entry (PCI Express configuration space)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct McfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    pub reserved: u32,
}

// =============================================================================
// HPET table
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct HpetTable {
    pub header: SdtHeader,
    pub hardware_rev_id: u8,
    pub comparator_count: u8,  // bits [4:0] = comparators, bit 5 = counter size, bit 6 = legacy
    pub pci_vendor_id: u16,
    pub address_space_id: u8,
    pub register_bit_width: u8,
    pub register_bit_offset: u8,
    pub reserved: u8,
    pub address: u64,
    pub hpet_number: u8,
    pub minimum_tick: u16,
    pub page_protection: u8,
}

// =============================================================================
// DMAR table (for IOMMU)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DmarHeader {
    pub header: SdtHeader,
    pub host_address_width: u8,
    pub flags: u8,
    pub reserved: [10]u8,
    // Followed by remapping structures
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum DmarStructType {
    Drhd = 0,    // DMA Remapping Hardware Unit
    Rmrr = 1,    // Reserved Memory Region
    Atsr = 2,    // Root Port ATS Capability
    Rhsa = 3,    // Remapping Hardware Static Affinity
    Andd = 4,    // ACPI Name-space Device Declaration
    Satc = 5,    // SoC Integrated Address Translation Cache
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DmarStructHeader {
    pub struct_type: u16,
    pub length: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DrhdEntry {
    pub header: DmarStructHeader,
    pub flags: u8,
    pub reserved: u8,
    pub segment: u16,
    pub register_base_addr: u64,
    // Followed by device scope entries
}

// =============================================================================
// SRAT (NUMA topology)
// =============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SratHeader {
    pub header: SdtHeader,
    pub table_revision: u32,
    pub reserved: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SratEntryType {
    ProcessorAffinity = 0,
    MemoryAffinity = 1,
    X2ApicAffinity = 2,
    GiccAffinity = 3,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SratMemoryAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain: u32,
    pub reserved1: u16,
    pub base_address_lo: u32,
    pub base_address_hi: u32,
    pub length_lo: u32,
    pub length_hi: u32,
    pub reserved2: u32,
    pub flags: u32,
    pub reserved3: u64,
}

impl SratMemoryAffinity {
    pub fn base_address(&self) -> u64 {
        (self.base_address_hi as u64) << 32 | self.base_address_lo as u64
    }

    pub fn region_length(&self) -> u64 {
        (self.length_hi as u64) << 32 | self.length_lo as u64
    }

    pub fn is_enabled(&self) -> bool {
        (self.flags & 1) != 0
    }

    pub fn is_hotpluggable(&self) -> bool {
        (self.flags & 2) != 0
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SratProcessorAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain_lo: u8,
    pub apic_id: u8,
    pub flags: u32,
    pub sapic_eid: u8,
    pub proximity_domain_hi: [3]u8,
    pub clock_domain: u32,
}

impl SratProcessorAffinity {
    pub fn proximity_domain(&self) -> u32 {
        self.proximity_domain_lo as u32
            | (self.proximity_domain_hi[0] as u32) << 8
            | (self.proximity_domain_hi[1] as u32) << 16
            | (self.proximity_domain_hi[2] as u32) << 24
    }

    pub fn is_enabled(&self) -> bool {
        (self.flags & 1) != 0
    }
}

// =============================================================================
// ACPI table manager
// =============================================================================

pub struct AcpiTableManager {
    pub tables: [AcpiTableEntry; MAX_ACPI_TABLES],
    pub table_count: u32,
    pub rsdp_addr: u64,
    pub xsdt_addr: u64,
    pub rsdt_addr: u32,
    pub acpi_revision: u8,
    pub oem_id: [6]u8,
    pub initialized: bool,

    // Cached important table addresses
    pub fadt_addr: u64,
    pub madt_addr: u64,
    pub mcfg_addr: u64,
    pub hpet_addr: u64,
    pub dmar_addr: u64,
    pub srat_addr: u64,
    pub dsdt_addr: u64,
}

impl AcpiTableManager {
    pub const fn new() Self {
        Self {
            tables: [const { AcpiTableEntry::empty() }; MAX_ACPI_TABLES],
            table_count: 0,
            rsdp_addr: 0,
            xsdt_addr: 0,
            rsdt_addr: 0,
            acpi_revision: 0,
            oem_id: [0u8; 6],
            initialized: false,
            fadt_addr: 0,
            madt_addr: 0,
            mcfg_addr: 0,
            hpet_addr: 0,
            dmar_addr: 0,
            srat_addr: 0,
            dsdt_addr: 0,
        }
    }

    /// Register a table we've discovered
    pub fn register_table(&mut self, sig: [4]u8, addr: u64, length: u32, revision: u8) -> bool {
        if self.table_count >= MAX_ACPI_TABLES as u32 {
            return false;
        }
        let idx = self.table_count as usize;
        self.tables[idx] = AcpiTableEntry {
            signature: sig,
            physical_addr: addr,
            length,
            revision,
            valid: true,
        };
        self.table_count += 1;

        // Cache well-known table addresses
        if sig == SIG_FACP { self.fadt_addr = addr; }
        else if sig == SIG_APIC { self.madt_addr = addr; }
        else if sig == SIG_MCFG { self.mcfg_addr = addr; }
        else if sig == SIG_HPET { self.hpet_addr = addr; }
        else if sig == SIG_DMAR { self.dmar_addr = addr; }
        else if sig == SIG_SRAT { self.srat_addr = addr; }
        else if sig == SIG_DSDT { self.dsdt_addr = addr; }

        true
    }

    /// Find a table by signature
    pub fn find_table(&self, sig: &[4]u8) -> Option<&AcpiTableEntry> {
        for i in 0..self.table_count as usize {
            if self.tables[i].valid && self.tables[i].signature == *sig {
                return Some(&self.tables[i]);
            }
        }
        None
    }

    /// Get total number of registered tables
    pub fn count(&self) -> u32 {
        self.table_count
    }

    /// Check if a specific table exists
    pub fn has_table(&self, sig: &[4]u8) -> bool {
        self.find_table(sig).is_some()
    }
}

// =============================================================================
// Global instance
// =============================================================================

static mut ACPI_TABLES: AcpiTableManager = AcpiTableManager::new();

fn acpi() -> &'static mut AcpiTableManager {
    unsafe { &mut ACPI_TABLES }
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_acpi_register_table(
    sig_ptr: *const u8,
    addr: u64,
    length: u32,
    revision: u8,
) -> i32 {
    if sig_ptr.is_null() { return -1; }
    let sig = unsafe {
        let s = core::slice::from_raw_parts(sig_ptr, 4);
        [s[0], s[1], s[2], s[3]]
    };
    if acpi().register_table(sig, addr, length, revision) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_acpi_find_table(sig_ptr: *const u8) -> u64 {
    if sig_ptr.is_null() { return 0; }
    let sig = unsafe {
        let s = core::slice::from_raw_parts(sig_ptr, 4);
        [s[0], s[1], s[2], s[3]]
    };
    match acpi().find_table(&sig) {
        Some(entry) => entry.physical_addr,
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_acpi_table_count() -> u32 {
    acpi().table_count
}

#[no_mangle]
pub extern "C" fn zxyphor_acpi_has_iommu() -> bool {
    acpi().dmar_addr != 0
}

#[no_mangle]
pub extern "C" fn zxyphor_acpi_has_hpet() -> bool {
    acpi().hpet_addr != 0
}

#[no_mangle]
pub extern "C" fn zxyphor_acpi_fadt_addr() -> u64 {
    acpi().fadt_addr
}

#[no_mangle]
pub extern "C" fn zxyphor_acpi_madt_addr() -> u64 {
    acpi().madt_addr
}
