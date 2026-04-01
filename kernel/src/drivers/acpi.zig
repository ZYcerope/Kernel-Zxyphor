// =============================================================================
// Kernel Zxyphor — ACPI Table Parser and Power Management Interface
// =============================================================================
// ACPI (Advanced Configuration and Power Interface) is the industry standard
// for OS-directed power management and hardware configuration. This module
// handles discovery and parsing of ACPI tables, and provides the interface
// for power state transitions.
//
// ACPI tables parsed:
//   - RSDP: Root System Description Pointer (entry point)
//   - RSDT/XSDT: Root/Extended System Description Table
//   - FADT: Fixed ACPI Description Table (PM1a/PM1b control blocks)
//   - MADT: Multiple APIC Description Table (CPU/IOAPIC enumeration)
//   - HPET: High Precision Event Timer configuration
//   - MCFG: PCI Express ECAM configuration space
//   - BGRT: Boot Graphics Resource Table
//
// ACPI AML (ACPI Machine Language) interpretation is NOT implemented —
// that requires a substantial bytecode interpreter. We do static table
// parsing only, which covers the essential hardware discovery.
// =============================================================================

const main = @import("../main.zig");
const serial = @import("../arch/x86_64/serial.zig");

// =============================================================================
// ACPI table signatures
// =============================================================================

pub const RSDP_SIGNATURE: [8]u8 = "RSD PTR ".*;
pub const RSDT_SIGNATURE: [4]u8 = "RSDT".*;
pub const XSDT_SIGNATURE: [4]u8 = "XSDT".*;
pub const FADT_SIGNATURE: [4]u8 = "FACP".*;
pub const MADT_SIGNATURE: [4]u8 = "APIC".*;
pub const HPET_SIGNATURE: [4]u8 = "HPET".*;
pub const MCFG_SIGNATURE: [4]u8 = "MCFG".*;
pub const BGRT_SIGNATURE: [4]u8 = "BGRT".*;
pub const SSDT_SIGNATURE: [4]u8 = "SSDT".*;
pub const DSDT_SIGNATURE: [4]u8 = "DSDT".*;

// =============================================================================
// RSDP — Root System Description Pointer
// =============================================================================

/// RSDP structure (ACPI 1.0 — 20 bytes)
pub const Rsdp = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
};

/// RSDP extended structure (ACPI 2.0+ — 36 bytes)
pub const RsdpExtended = extern struct {
    // First 20 bytes same as RSDP 1.0
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    // Extended fields (ACPI 2.0+)
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,
};

// =============================================================================
// SDT Header — common header for all ACPI tables
// =============================================================================

pub const SdtHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    /// Validate the table checksum
    pub fn validateChecksum(self: *const SdtHeader) bool {
        const bytes: [*]const u8 = @ptrCast(self);
        var sum: u8 = 0;
        for (0..self.length) |i| {
            sum +%= bytes[i];
        }
        return sum == 0;
    }
};

// =============================================================================
// FADT — Fixed ACPI Description Table
// =============================================================================

pub const Fadt = extern struct {
    header: SdtHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    reserved1: u8,
    preferred_pm_profile: u8,
    sci_interrupt: u16,
    smi_command_port: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_control: u8,
    pm1a_event_block: u32,
    pm1b_event_block: u32,
    pm1a_control_block: u32,
    pm1b_control_block: u32,
    pm2_control_block: u32,
    pm_timer_block: u32,
    gpe0_block: u32,
    gpe1_block: u32,
    pm1_event_length: u8,
    pm1_control_length: u8,
    pm2_control_length: u8,
    pm_timer_length: u8,
    gpe0_length: u8,
    gpe1_length: u8,
    gpe1_base: u8,
    cstate_control: u8,
    worst_c2_latency: u16,
    worst_c3_latency: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alarm: u8,
    month_alarm: u8,
    century: u8,
    boot_arch_flags: u16,
    reserved2: u8,
    flags: u32,
};

// PM profile values
pub const PM_PROFILE_UNSPECIFIED: u8 = 0;
pub const PM_PROFILE_DESKTOP: u8 = 1;
pub const PM_PROFILE_MOBILE: u8 = 2;
pub const PM_PROFILE_WORKSTATION: u8 = 3;
pub const PM_PROFILE_ENTERPRISE_SERVER: u8 = 4;
pub const PM_PROFILE_SOHO_SERVER: u8 = 5;
pub const PM_PROFILE_APPLIANCE_PC: u8 = 6;
pub const PM_PROFILE_PERFORMANCE_SERVER: u8 = 7;

// FADT flags
pub const FADT_WBINVD: u32 = 1 << 0;
pub const FADT_WBINVD_FLUSH: u32 = 1 << 1;
pub const FADT_PROC_C1: u32 = 1 << 2;
pub const FADT_P_LVL2_UP: u32 = 1 << 3;
pub const FADT_PWR_BUTTON: u32 = 1 << 4;
pub const FADT_SLP_BUTTON: u32 = 1 << 5;
pub const FADT_FIX_RTC: u32 = 1 << 6;
pub const FADT_RTC_S4: u32 = 1 << 7;
pub const FADT_TMR_VAL_EXT: u32 = 1 << 8;
pub const FADT_DCK_CAP: u32 = 1 << 9;
pub const FADT_RESET_REG_SUP: u32 = 1 << 10;
pub const FADT_SEALED_CASE: u32 = 1 << 11;
pub const FADT_HEADLESS: u32 = 1 << 12;
pub const FADT_CPU_SW_SLP: u32 = 1 << 13;
pub const FADT_PCI_EXP_WAK: u32 = 1 << 14;
pub const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
pub const FADT_LOW_POWER_S0: u32 = 1 << 21;

// =============================================================================
// MADT — Multiple APIC Description Table
// =============================================================================

pub const Madt = extern struct {
    header: SdtHeader,
    local_apic_address: u32,
    flags: u32,
    // Followed by variable-length MADT entries
};

// MADT flags
pub const MADT_PCAT_COMPAT: u32 = 1 << 0;

/// MADT entry header
pub const MadtEntryHeader = extern struct {
    entry_type: u8,
    length: u8,
};

// MADT entry types
pub const MADT_LOCAL_APIC: u8 = 0;
pub const MADT_IO_APIC: u8 = 1;
pub const MADT_INTERRUPT_OVERRIDE: u8 = 2;
pub const MADT_NMI_SOURCE: u8 = 3;
pub const MADT_LOCAL_APIC_NMI: u8 = 4;
pub const MADT_LOCAL_APIC_OVERRIDE: u8 = 5;
pub const MADT_IO_SAPIC: u8 = 6;
pub const MADT_LOCAL_SAPIC: u8 = 7;
pub const MADT_PLATFORM_INT: u8 = 8;
pub const MADT_LOCAL_X2APIC: u8 = 9;
pub const MADT_LOCAL_X2APIC_NMI: u8 = 0x0A;

/// Local APIC entry
pub const MadtLocalApic = extern struct {
    header: MadtEntryHeader,
    processor_id: u8,
    apic_id: u8,
    flags: u32,
};

// Local APIC flags
pub const LAPIC_ENABLED: u32 = 1 << 0;
pub const LAPIC_ONLINE_CAPABLE: u32 = 1 << 1;

/// I/O APIC entry
pub const MadtIoApic = extern struct {
    header: MadtEntryHeader,
    io_apic_id: u8,
    reserved: u8,
    io_apic_address: u32,
    global_system_interrupt_base: u32,
};

/// Interrupt Source Override entry
pub const MadtInterruptOverride = extern struct {
    header: MadtEntryHeader,
    bus: u8,
    source: u8,
    global_system_interrupt: u32,
    flags: u16,
};

// =============================================================================
// HPET — High Precision Event Timer
// =============================================================================

pub const Hpet = extern struct {
    header: SdtHeader,
    hardware_rev_id: u8,
    comparator_count_and_flags: u8,
    pci_vendor_id: u16,
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    reserved: u8,
    address: u64,
    hpet_number: u8,
    minimum_tick: u16,
    page_protection: u8,
};

// =============================================================================
// MCFG — PCI Express Configuration Space
// =============================================================================

pub const Mcfg = extern struct {
    header: SdtHeader,
    reserved: u64,
    // Followed by variable-length MCFG allocation entries
};

pub const McfgAllocation = extern struct {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    reserved: u32,
};

// =============================================================================
// Parsed ACPI information
// =============================================================================

pub const MAX_CPUS: usize = 256;
pub const MAX_IO_APICS: usize = 16;
pub const MAX_INT_OVERRIDES: usize = 32;

pub const CpuInfo = struct {
    processor_id: u8,
    apic_id: u8,
    enabled: bool,
};

pub const IoApicInfo = struct {
    id: u8,
    address: u32,
    gsi_base: u32,
};

pub const IntOverrideInfo = struct {
    bus: u8,
    source_irq: u8,
    global_irq: u32,
    flags: u16,
};

pub const AcpiInfo = struct {
    // ACPI version
    revision: u8,
    oem_id: [6]u8,

    // FADT info
    sci_interrupt: u16,
    pm1a_control_block: u32,
    pm1b_control_block: u32,
    pm_timer_block: u32,
    pm_profile: u8,
    century_register: u8,
    fadt_flags: u32,

    // MADT info
    local_apic_address: u32,
    cpus: [MAX_CPUS]CpuInfo,
    cpu_count: usize,
    io_apics: [MAX_IO_APICS]IoApicInfo,
    io_apic_count: usize,
    int_overrides: [MAX_INT_OVERRIDES]IntOverrideInfo,
    int_override_count: usize,

    // HPET info
    hpet_address: u64,
    hpet_present: bool,

    // MCFG info (PCI Express)
    pcie_base_address: u64,
    pcie_segment: u16,
    pcie_start_bus: u8,
    pcie_end_bus: u8,
    pcie_present: bool,
};

var acpi_info: AcpiInfo = undefined;
var acpi_initialized: bool = false;

// =============================================================================
// RSDP discovery
// =============================================================================

/// Search for the RSDP in the BIOS memory areas.
/// According to the ACPI spec, it can be found in:
///   1. The first 1 KB of the EBDA (Extended BIOS Data Area)
///   2. The BIOS ROM area (0x000E0000 — 0x000FFFFF)
pub fn findRsdp() ?*const RsdpExtended {
    // Search BIOS ROM area (0xE0000 — 0xFFFFF)
    // In the kernel, these physical addresses are identity-mapped or
    // accessible via the higher-half mapping.
    const bios_start: usize = 0xFFFFFFFF80000000 + 0x000E0000;
    const bios_end: usize = 0xFFFFFFFF80000000 + 0x00100000;

    var addr: usize = bios_start;
    while (addr < bios_end) : (addr += 16) {
        const ptr: *const [8]u8 = @ptrFromInt(addr);
        if (ptr.* == RSDP_SIGNATURE) {
            // Validate checksum of first 20 bytes
            const bytes: [*]const u8 = @ptrFromInt(addr);
            var sum: u8 = 0;
            for (0..20) |i| {
                sum +%= bytes[i];
            }
            if (sum == 0) {
                return @ptrFromInt(addr);
            }
        }
    }

    return null;
}

// =============================================================================
// Table parsing
// =============================================================================

/// Parse the RSDT (32-bit) to find other ACPI tables
fn parseRsdt(rsdt_phys: u32) void {
    const rsdt_virt = physToVirt(rsdt_phys);
    const header: *const SdtHeader = @ptrFromInt(rsdt_virt);

    if (!header.validateChecksum()) {
        main.klog(.warning, "ACPI: RSDT checksum invalid", .{});
        return;
    }

    const entries_size = header.length - @sizeOf(SdtHeader);
    const entry_count = entries_size / 4;
    const entries: [*]const u32 = @ptrFromInt(rsdt_virt + @sizeOf(SdtHeader));

    for (0..entry_count) |i| {
        const table_phys = entries[i];
        parseAcpiTable(table_phys);
    }
}

/// Parse the XSDT (64-bit) to find other ACPI tables
fn parseXsdt(xsdt_phys: u64) void {
    const xsdt_virt = physToVirt(@truncate(xsdt_phys));
    const header: *const SdtHeader = @ptrFromInt(xsdt_virt);

    if (!header.validateChecksum()) {
        main.klog(.warning, "ACPI: XSDT checksum invalid", .{});
        return;
    }

    const entries_size = header.length - @sizeOf(SdtHeader);
    const entry_count = entries_size / 8;
    const entries: [*]const u64 = @ptrFromInt(xsdt_virt + @sizeOf(SdtHeader));

    for (0..entry_count) |i| {
        const table_phys: u32 = @truncate(entries[i]);
        parseAcpiTable(table_phys);
    }
}

/// Parse a single ACPI table by its physical address
fn parseAcpiTable(table_phys: u32) void {
    const table_virt = physToVirt(table_phys);
    const header: *const SdtHeader = @ptrFromInt(table_virt);

    if (header.signature == FADT_SIGNATURE) {
        parseFadt(@ptrFromInt(table_virt));
    } else if (header.signature == MADT_SIGNATURE) {
        parseMadt(@ptrFromInt(table_virt));
    } else if (header.signature == HPET_SIGNATURE) {
        parseHpet(@ptrFromInt(table_virt));
    } else if (header.signature == MCFG_SIGNATURE) {
        parseMcfg(@ptrFromInt(table_virt));
    }
}

/// Parse the FADT (Fixed ACPI Description Table)
fn parseFadt(fadt: *const Fadt) void {
    acpi_info.sci_interrupt = fadt.sci_interrupt;
    acpi_info.pm1a_control_block = fadt.pm1a_control_block;
    acpi_info.pm1b_control_block = fadt.pm1b_control_block;
    acpi_info.pm_timer_block = fadt.pm_timer_block;
    acpi_info.pm_profile = fadt.preferred_pm_profile;
    acpi_info.century_register = fadt.century;
    acpi_info.fadt_flags = fadt.flags;

    main.klog(.info, "ACPI: FADT parsed — PM profile: {d}, SCI IRQ: {d}", .{
        fadt.preferred_pm_profile,
        fadt.sci_interrupt,
    });
}

/// Parse the MADT (Multiple APIC Description Table)
fn parseMadt(madt: *const Madt) void {
    acpi_info.local_apic_address = madt.local_apic_address;
    acpi_info.cpu_count = 0;
    acpi_info.io_apic_count = 0;
    acpi_info.int_override_count = 0;

    const madt_end = @intFromPtr(madt) + madt.header.length;
    var offset: usize = @intFromPtr(madt) + @sizeOf(Madt);

    while (offset < madt_end) {
        const entry: *const MadtEntryHeader = @ptrFromInt(offset);

        switch (entry.entry_type) {
            MADT_LOCAL_APIC => {
                if (acpi_info.cpu_count < MAX_CPUS) {
                    const lapic: *const MadtLocalApic = @ptrFromInt(offset);
                    acpi_info.cpus[acpi_info.cpu_count] = .{
                        .processor_id = lapic.processor_id,
                        .apic_id = lapic.apic_id,
                        .enabled = (lapic.flags & LAPIC_ENABLED) != 0,
                    };
                    acpi_info.cpu_count += 1;
                }
            },
            MADT_IO_APIC => {
                if (acpi_info.io_apic_count < MAX_IO_APICS) {
                    const ioapic: *const MadtIoApic = @ptrFromInt(offset);
                    acpi_info.io_apics[acpi_info.io_apic_count] = .{
                        .id = ioapic.io_apic_id,
                        .address = ioapic.io_apic_address,
                        .gsi_base = ioapic.global_system_interrupt_base,
                    };
                    acpi_info.io_apic_count += 1;
                }
            },
            MADT_INTERRUPT_OVERRIDE => {
                if (acpi_info.int_override_count < MAX_INT_OVERRIDES) {
                    const ovr: *const MadtInterruptOverride = @ptrFromInt(offset);
                    acpi_info.int_overrides[acpi_info.int_override_count] = .{
                        .bus = ovr.bus,
                        .source_irq = ovr.source,
                        .global_irq = ovr.global_system_interrupt,
                        .flags = ovr.flags,
                    };
                    acpi_info.int_override_count += 1;
                }
            },
            else => {},
        }

        offset += entry.length;
    }

    main.klog(.info, "ACPI: MADT parsed — {d} CPUs, {d} I/O APICs", .{
        acpi_info.cpu_count,
        acpi_info.io_apic_count,
    });
}

/// Parse the HPET (High Precision Event Timer)
fn parseHpet(hpet: *const Hpet) void {
    acpi_info.hpet_address = hpet.address;
    acpi_info.hpet_present = true;

    main.klog(.info, "ACPI: HPET found at 0x{x}", .{hpet.address});
}

/// Parse the MCFG (PCI Express configuration)
fn parseMcfg(mcfg: *const Mcfg) void {
    const entries_start = @intFromPtr(mcfg) + @sizeOf(Mcfg);
    const entries_size = mcfg.header.length - @sizeOf(Mcfg);

    if (entries_size >= @sizeOf(McfgAllocation)) {
        const alloc: *const McfgAllocation = @ptrFromInt(entries_start);
        acpi_info.pcie_base_address = alloc.base_address;
        acpi_info.pcie_segment = alloc.segment_group;
        acpi_info.pcie_start_bus = alloc.start_bus;
        acpi_info.pcie_end_bus = alloc.end_bus;
        acpi_info.pcie_present = true;

        main.klog(.info, "ACPI: PCIe ECAM at 0x{x}, buses {d}-{d}", .{
            alloc.base_address,
            alloc.start_bus,
            alloc.end_bus,
        });
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Convert a physical address to a virtual address (higher-half mapping)
inline fn physToVirt(phys: u32) usize {
    return @as(usize, phys) + 0xFFFFFFFF80000000;
}

// =============================================================================
// Power management operations
// =============================================================================

pub const PowerState = enum {
    s0_working,
    s1_sleeping,
    s3_suspend_to_ram,
    s4_hibernate,
    s5_soft_off,
};

/// Attempt to enter a power state
/// WARNING: S5 will shut down the machine. Only call if the user requested it.
pub fn enterPowerState(state: PowerState) void {
    switch (state) {
        .s5_soft_off => {
            // Write SLP_TYPa | SLP_EN to PM1a_CNT
            // The actual SLP_TYP values come from the DSDT \_S5 object,
            // which we can't parse without an AML interpreter.
            // Common values: SLP_TYPa=5 for QEMU, SLP_TYPa=7 for Bochs
            if (acpi_info.pm1a_control_block != 0) {
                const port: u16 = @truncate(acpi_info.pm1a_control_block);
                // SLP_TYP = 5 (common for QEMU), SLP_EN = bit 13
                const slp_val: u16 = (5 << 10) | (1 << 13);
                asm volatile ("outw %[val], %[port]"
                    :
                    : [val] "{ax}" (slp_val),
                      [port] "N{dx}" (port),
                );
            }
        },
        else => {
            main.klog(.warning, "Power state transition not implemented", .{});
        },
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Initialize the ACPI subsystem
pub fn initialize() void {
    acpi_info = std.mem.zeroes(AcpiInfo);

    // Find the RSDP
    const rsdp = findRsdp();
    if (rsdp == null) {
        main.klog(.warning, "ACPI: RSDP not found — ACPI disabled", .{});
        return;
    }

    const r = rsdp.?;
    acpi_info.revision = r.revision;
    @memcpy(&acpi_info.oem_id, &r.oem_id);

    main.klog(.info, "ACPI: Found RSDP revision {d}", .{r.revision});

    if (r.revision >= 2 and r.xsdt_address != 0) {
        main.klog(.info, "ACPI: Using XSDT at 0x{x}", .{r.xsdt_address});
        parseXsdt(r.xsdt_address);
    } else {
        main.klog(.info, "ACPI: Using RSDT at 0x{x}", .{r.rsdt_address});
        parseRsdt(r.rsdt_address);
    }

    acpi_initialized = true;
    main.klog(.info, "ACPI: Initialization complete", .{});
}

/// Get parsed ACPI information
pub fn getInfo() *const AcpiInfo {
    return &acpi_info;
}

/// Check if ACPI is available
pub fn isAvailable() bool {
    return acpi_initialized;
}

/// Get the number of CPUs discovered via MADT
pub fn cpuCount() usize {
    return acpi_info.cpu_count;
}

/// Get the HPET base address (0 if not present)
pub fn hpetAddress() u64 {
    if (acpi_info.hpet_present) return acpi_info.hpet_address;
    return 0;
}

/// Shut down the system via ACPI
pub fn shutdown() void {
    main.klog(.info, "ACPI: Initiating system shutdown (S5)...", .{});
    enterPowerState(.s5_soft_off);
}

const std = @import("std");
