// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced ACPI: ACPI 6.5, Tables, PM, Thermal, Battery, EC

const std = @import("std");

// ============================================================================
// ACPI Table Signatures and Headers
// ============================================================================

pub const AcpiTableSignature = enum(u32) {
    RSDP = 0x20445352,   // "RSD "
    RSDT = 0x54445352,   // "RSDT"
    XSDT = 0x54445358,   // "XSDT"
    FADT = 0x50434146,   // "FACP"
    MADT = 0x43495041,   // "APIC"
    SSDT = 0x54445353,   // "SSDT"
    DSDT = 0x54445344,   // "DSDT"
    HPET = 0x54455048,   // "HPET"
    MCFG = 0x4746434D,   // "MCFG"
    SRAT = 0x54415253,   // "SRAT"
    SLIT = 0x54494C53,   // "SLIT"
    DMAR = 0x52414D44,   // "DMAR"
    BERT = 0x54524542,   // "BERT"
    BGRT = 0x54524742,   // "BGRT"
    CPEP = 0x50455043,   // "CPEP"
    ECDT = 0x54444345,   // "ECDT"
    EINJ = 0x4A4E4945,   // "EINJ"
    ERST = 0x54535245,   // "ERST"
    FPDT = 0x54445046,   // "FPDT"
    GTDT = 0x54445447,   // "GTDT"
    HEST = 0x54534548,   // "HEST"
    MSCT = 0x5443534D,   // "MSCT"
    MPST = 0x5453504D,   // "MPST"
    NFIT = 0x5449464E,   // "NFIT"
    PCCT = 0x54434350,   // "PCCT"
    PMTT = 0x54544D50,   // "PMTT"
    RASF = 0x46534152,   // "RASF"
    SBST = 0x54534253,   // "SBST"
    SDEV = 0x56454453,   // "SDEV"
    TCPA = 0x41504354,   // "TCPA"
    TPM2 = 0x324D5054,   // "TPM2"
    UEFI = 0x49464555,   // "UEFI"
    WAET = 0x54454157,   // "WAET"
    WDAT = 0x54414457,   // "WDAT"
    WDDT = 0x54444457,   // "WDDT"
    WDRT = 0x54524457,   // "WDRT"
    IVRS = 0x53525649,   // "IVRS" (AMD)
    LPIT = 0x5449504C,   // "LPIT"
    IORT = 0x54524F49,   // "IORT"
    PPTT = 0x54545050,   // "PPTT"
    CEDT = 0x54444543,   // "CEDT"
    CDAT = 0x54414443,   // "CDAT"
    NBFT = 0x5446424E,   // "NBFT"
    SVKL = 0x4C4B5653,   // "SVKL"
    PRMT = 0x544D5250,   // "PRMT"
    AEST = 0x54534541,   // "AEST"
    AGDI = 0x49444741,   // "AGDI"
    APMT = 0x544D5041,   // "APMT"
    BDAT = 0x54414442,   // "BDAT"
    CCEL = 0x4C454343,   // "CCEL"
    MISC = 0x4353494D,   // "MISC"
    PHAT = 0x54414850,   // "PHAT"
    RAS2 = 0x32534152,   // "RAS2"
    RHCT = 0x54434852,   // "RHCT"
    WSMT = 0x544D5357,   // "WSMT"
};

// ACPI SDT Header
#[repr(C, packed)]
pub const AcpiSdtHeader = extern struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    pub fn validate_checksum(self: *const AcpiSdtHeader) bool {
        const bytes: [*]const u8 = @ptrCast(self);
        var sum: u8 = 0;
        for (0..self.length) |i| {
            sum +%= bytes[i];
        }
        return sum == 0;
    }

    pub fn data_ptr(self: *const AcpiSdtHeader) [*]const u8 {
        return @as([*]const u8, @ptrCast(self)) + @sizeOf(AcpiSdtHeader);
    }

    pub fn data_len(self: *const AcpiSdtHeader) u32 {
        if (self.length > @sizeOf(AcpiSdtHeader)) {
            return self.length - @sizeOf(AcpiSdtHeader);
        }
        return 0;
    }
};

// RSDP (Root System Description Pointer)
pub const AcpiRsdp = extern struct {
    signature: [8]u8,      // "RSD PTR "
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,

    pub fn is_valid(self: *const AcpiRsdp) bool {
        // Check signature
        const sig = "RSD PTR ";
        for (0..8) |i| {
            if (self.signature[i] != sig[i]) return false;
        }
        // Check revision 0 checksum (first 20 bytes)
        const bytes: [*]const u8 = @ptrCast(self);
        var sum: u8 = 0;
        for (0..20) |i| {
            sum +%= bytes[i];
        }
        if (sum != 0) return false;
        // For ACPI 2.0+, check extended checksum
        if (self.revision >= 2) {
            sum = 0;
            for (0..self.length) |i| {
                sum +%= bytes[i];
            }
            if (sum != 0) return false;
        }
        return true;
    }

    pub fn is_acpi2(self: *const AcpiRsdp) bool {
        return self.revision >= 2;
    }
};

// ============================================================================
// FADT (Fixed ACPI Description Table)
// ============================================================================

pub const AcpiFadt = extern struct {
    header: AcpiSdtHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    reserved1: u8,
    preferred_pm_profile: u8,
    sci_int: u16,
    smi_cmd: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_cnt: u8,
    pm1a_evt_blk: u32,
    pm1b_evt_blk: u32,
    pm1a_cnt_blk: u32,
    pm1b_cnt_blk: u32,
    pm2_cnt_blk: u32,
    pm_tmr_blk: u32,
    gpe0_blk: u32,
    gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8,
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cst_cnt: u8,
    p_lvl2_lat: u16,
    p_lvl3_lat: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alrm: u8,
    mon_alrm: u8,
    century: u8,
    iapc_boot_arch: u16,
    reserved2: u8,
    flags: u32,
    reset_reg: AcpiGas,
    reset_value: u8,
    arm_boot_arch: u16,
    fadt_minor_version: u8,
    x_firmware_ctrl: u64,
    x_dsdt: u64,
    x_pm1a_evt_blk: AcpiGas,
    x_pm1b_evt_blk: AcpiGas,
    x_pm1a_cnt_blk: AcpiGas,
    x_pm1b_cnt_blk: AcpiGas,
    x_pm2_cnt_blk: AcpiGas,
    x_pm_tmr_blk: AcpiGas,
    x_gpe0_blk: AcpiGas,
    x_gpe1_blk: AcpiGas,
    sleep_control_reg: AcpiGas,
    sleep_status_reg: AcpiGas,
    hypervisor_vendor_id: u64,

    // FADT Flags
    pub fn has_wbinvd(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 0)) != 0;
    }
    pub fn has_wbinvd_flush(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 1)) != 0;
    }
    pub fn has_proc_c1(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 2)) != 0;
    }
    pub fn has_p_lvl2_up(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 3)) != 0;
    }
    pub fn has_pwr_button(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 4)) != 0;
    }
    pub fn has_slp_button(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 5)) != 0;
    }
    pub fn has_fix_rtc(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 6)) != 0;
    }
    pub fn has_rtc_s4(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 7)) != 0;
    }
    pub fn has_tmr_val_ext(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 8)) != 0;
    }
    pub fn has_dck_cap(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 9)) != 0;
    }
    pub fn has_reset_reg_sup(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 10)) != 0;
    }
    pub fn has_sealed_case(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 11)) != 0;
    }
    pub fn is_headless(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 12)) != 0;
    }
    pub fn has_hw_reduced_acpi(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 20)) != 0;
    }
    pub fn has_low_power_s0(self: *const AcpiFadt) bool {
        return (self.flags & (1 << 21)) != 0;
    }
};

// Generic Address Structure (GAS)
pub const AcpiAddressSpace = enum(u8) {
    system_memory = 0x00,
    system_io = 0x01,
    pci_config = 0x02,
    embedded_controller = 0x03,
    smbus = 0x04,
    cmos = 0x05,
    pci_bar_target = 0x06,
    ipmi = 0x07,
    gpio = 0x08,
    generic_serial_bus = 0x09,
    pcc = 0x0A,
    functional_fixed = 0x7F,
};

pub const AcpiGas = extern struct {
    address_space: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
};

// ============================================================================
// MADT (Multiple APIC Description Table)
// ============================================================================

pub const AcpiMadt = extern struct {
    header: AcpiSdtHeader,
    local_apic_address: u32,
    flags: u32,
    // Variable-length entries follow

    pub fn has_pcat_compat(self: *const AcpiMadt) bool {
        return (self.flags & 1) != 0;
    }
};

pub const MadtEntryType = enum(u8) {
    local_apic = 0,
    io_apic = 1,
    interrupt_override = 2,
    nmi_source = 3,
    local_apic_nmi = 4,
    local_apic_override = 5,
    io_sapic = 6,
    local_sapic = 7,
    platform_interrupt = 8,
    local_x2apic = 9,
    local_x2apic_nmi = 10,
    gicc = 11,
    gicd = 12,
    gic_msi_frame = 13,
    gicr = 14,
    gic_its = 15,
    mp_wakeup = 16,
    core_pic = 17,
    lpc_pic = 18,
};

pub const MadtEntryHeader = extern struct {
    entry_type: u8,
    length: u8,
};

pub const MadtLocalApic = extern struct {
    header: MadtEntryHeader,
    acpi_processor_uid: u8,
    apic_id: u8,
    flags: u32,

    pub fn is_enabled(self: *const MadtLocalApic) bool {
        return (self.flags & 1) != 0;
    }

    pub fn is_online_capable(self: *const MadtLocalApic) bool {
        return (self.flags & 2) != 0;
    }
};

pub const MadtIoApic = extern struct {
    header: MadtEntryHeader,
    io_apic_id: u8,
    reserved: u8,
    io_apic_address: u32,
    global_system_interrupt_base: u32,
};

pub const MadtInterruptOverride = extern struct {
    header: MadtEntryHeader,
    bus: u8,
    source: u8,
    global_system_interrupt: u32,
    flags: u16,
};

pub const MadtLocalX2Apic = extern struct {
    header: MadtEntryHeader,
    reserved: u16,
    x2apic_id: u32,
    flags: u32,
    acpi_processor_uid: u32,
};

// ============================================================================
// MCFG (PCI Express Memory-Mapped Configuration)
// ============================================================================

pub const AcpiMcfg = extern struct {
    header: AcpiSdtHeader,
    reserved: u64,
    // McfgEntry array follows
};

pub const McfgEntry = extern struct {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    reserved: u32,
};

// ============================================================================
// SRAT (System Resource Affinity Table)
// ============================================================================

pub const AcpiSrat = extern struct {
    header: AcpiSdtHeader,
    table_revision: u32,
    reserved: u64,
};

pub const SratEntryType = enum(u8) {
    processor_affinity = 0,
    memory_affinity = 1,
    x2apic_affinity = 2,
    gicc_affinity = 3,
    gic_its_affinity = 4,
    generic_initiator = 5,
};

pub const SratProcessorAffinity = extern struct {
    entry_type: u8,
    length: u8,
    proximity_domain_lo: u8,
    apic_id: u8,
    flags: u32,
    sapic_eid: u8,
    proximity_domain_hi: [3]u8,
    clock_domain: u32,

    pub fn proximity_domain(self: *const SratProcessorAffinity) u32 {
        return @as(u32, self.proximity_domain_lo) |
            (@as(u32, self.proximity_domain_hi[0]) << 8) |
            (@as(u32, self.proximity_domain_hi[1]) << 16) |
            (@as(u32, self.proximity_domain_hi[2]) << 24);
    }

    pub fn is_enabled(self: *const SratProcessorAffinity) bool {
        return (self.flags & 1) != 0;
    }
};

pub const SratMemoryAffinity = extern struct {
    entry_type: u8,
    length: u8,
    proximity_domain: u32,
    reserved1: u16,
    base_address_lo: u32,
    base_address_hi: u32,
    length_lo: u32,
    length_hi: u32,
    reserved2: u32,
    flags: u32,
    reserved3: u64,

    pub fn base_address(self: *const SratMemoryAffinity) u64 {
        return (@as(u64, self.base_address_hi) << 32) | @as(u64, self.base_address_lo);
    }

    pub fn region_length(self: *const SratMemoryAffinity) u64 {
        return (@as(u64, self.length_hi) << 32) | @as(u64, self.length_lo);
    }

    pub fn is_enabled(self: *const SratMemoryAffinity) bool {
        return (self.flags & 1) != 0;
    }

    pub fn is_hotpluggable(self: *const SratMemoryAffinity) bool {
        return (self.flags & 2) != 0;
    }

    pub fn is_non_volatile(self: *const SratMemoryAffinity) bool {
        return (self.flags & 4) != 0;
    }
};

// ============================================================================
// HPET (High Precision Event Timer)
// ============================================================================

pub const AcpiHpet = extern struct {
    header: AcpiSdtHeader,
    event_timer_block_id: u32,
    base_address: AcpiGas,
    hpet_number: u8,
    min_clock_ticks: u16,
    page_protection: u8,
};

pub const HpetRegisters = extern struct {
    general_caps: u64,
    _reserved1: u64,
    general_config: u64,
    _reserved2: u64,
    general_int_status: u64,
    _reserved3: [25]u64,
    main_counter: u64,
    _reserved4: u64,
    timers: [32]HpetTimerRegisters,

    pub fn period_fs(self: *const HpetRegisters) u32 {
        return @truncate(self.general_caps >> 32);
    }

    pub fn num_timers(self: *const HpetRegisters) u32 {
        return @truncate(((self.general_caps >> 8) & 0x1F) + 1);
    }

    pub fn is_64bit(self: *const HpetRegisters) bool {
        return (self.general_caps & (1 << 13)) != 0;
    }

    pub fn enable(self: *volatile HpetRegisters) void {
        self.general_config |= 1;
    }

    pub fn disable(self: *volatile HpetRegisters) void {
        self.general_config &= ~@as(u64, 1);
    }
};

pub const HpetTimerRegisters = extern struct {
    config_caps: u64,
    comparator: u64,
    fsb_route: u64,
    _reserved: u64,
};

// ============================================================================
// DMAR (DMA Remapping) - Intel VT-d
// ============================================================================

pub const AcpiDmar = extern struct {
    header: AcpiSdtHeader,
    host_address_width: u8,
    flags: u8,
    reserved: [10]u8,
    // Remapping structures follow

    pub fn has_intr_remap(self: *const AcpiDmar) bool {
        return (self.flags & 1) != 0;
    }

    pub fn has_x2apic_opt_out(self: *const AcpiDmar) bool {
        return (self.flags & 2) != 0;
    }

    pub fn has_dma_ctrl_platform_opt_in(self: *const AcpiDmar) bool {
        return (self.flags & 4) != 0;
    }
};

pub const DmarStructureType = enum(u16) {
    drhd = 0,   // DMA Remapping Hardware Unit Definition
    rmrr = 1,   // Reserved Memory Region Reporting
    atsr = 2,   // Root Port ATS Capability
    rhsa = 3,   // Remapping Hardware Static Affinity
    andd = 4,   // ACPI Name-space Device Declaration
    satc = 5,   // SoC Integrated Address Translation Cache
    sidp = 6,   // SoC Integrated Device Property
};

pub const DmarDrhd = extern struct {
    structure_type: u16,
    length: u16,
    flags: u8,
    size: u8,
    segment: u16,
    register_base_address: u64,
    // Device scope entries follow

    pub fn is_include_pci_all(self: *const DmarDrhd) bool {
        return (self.flags & 1) != 0;
    }
};

// ============================================================================
// Embedded Controller (EC)
// ============================================================================

pub const EC_SC_PORT: u16 = 0x66;
pub const EC_DATA_PORT: u16 = 0x62;

pub const EcCommand = enum(u8) {
    read = 0x80,
    write = 0x81,
    burst_enable = 0x82,
    burst_disable = 0x83,
    query = 0x84,
};

pub const EcStatus = packed struct(u8) {
    obf: bool = false,    // Output Buffer Full
    ibf: bool = false,    // Input Buffer Full
    _reserved2: bool = false,
    cmd: bool = false,    // Command/Data
    burst: bool = false,  // Burst mode
    sci_evt: bool = false, // SCI Event
    smi_evt: bool = false, // SMI Event
    _reserved7: bool = false,
};

pub const EcController = struct {
    data_port: u16,
    cmd_port: u16,
    gpe_bit: u8,
    global_lock: bool,

    pub fn init(data_port: u16, cmd_port: u16) EcController {
        return .{
            .data_port = data_port,
            .cmd_port = cmd_port,
            .gpe_bit = 0,
            .global_lock = false,
        };
    }

    pub fn wait_ibf_clear(self: *const EcController) bool {
        var timeout: u32 = 1000;
        while (timeout > 0) : (timeout -= 1) {
            const status: EcStatus = @bitCast(port_in_u8(self.cmd_port));
            if (!status.ibf) return true;
            // Small busy-wait delay
        }
        return false;
    }

    pub fn wait_obf_set(self: *const EcController) bool {
        var timeout: u32 = 1000;
        while (timeout > 0) : (timeout -= 1) {
            const status: EcStatus = @bitCast(port_in_u8(self.cmd_port));
            if (status.obf) return true;
        }
        return false;
    }

    pub fn read_byte(self: *const EcController, addr: u8) ?u8 {
        if (!self.wait_ibf_clear()) return null;
        port_out_u8(self.cmd_port, @intFromEnum(EcCommand.read));
        if (!self.wait_ibf_clear()) return null;
        port_out_u8(self.data_port, addr);
        if (!self.wait_obf_set()) return null;
        return port_in_u8(self.data_port);
    }

    pub fn write_byte(self: *const EcController, addr: u8, data: u8) bool {
        if (!self.wait_ibf_clear()) return false;
        port_out_u8(self.cmd_port, @intFromEnum(EcCommand.write));
        if (!self.wait_ibf_clear()) return false;
        port_out_u8(self.data_port, addr);
        if (!self.wait_ibf_clear()) return false;
        port_out_u8(self.data_port, data);
        return true;
    }
};

// Port I/O helpers
fn port_in_u8(port: u16) u8 {
    return asm volatile ("inb %[port], %[ret]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

fn port_out_u8(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "N{dx}" (port),
    );
}

// ============================================================================
// ACPI Power Management
// ============================================================================

pub const AcpiSleepState = enum(u8) {
    s0 = 0,   // Working
    s1 = 1,   // Power On Suspend
    s2 = 2,   // CPU Off
    s3 = 3,   // Suspend to RAM
    s4 = 4,   // Suspend to Disk (Hibernate)
    s5 = 5,   // Soft Off
};

pub const AcpiDState = enum(u8) {
    d0 = 0,   // Fully On
    d1 = 1,   // Light Sleep
    d2 = 2,   // Deeper Sleep
    d3_hot = 3, // Device Off, context may be preserved
    d3_cold = 4, // Device Off, power removed
};

pub const PmProfile = enum(u8) {
    unspecified = 0,
    desktop = 1,
    mobile = 2,
    workstation = 3,
    enterprise_server = 4,
    soho_server = 5,
    appliance_pc = 6,
    performance_server = 7,
    tablet = 8,
};

pub const PowerResource = struct {
    name: [4]u8,
    system_level: u8,
    resource_order: u16,
    state: bool,
    reference_count: u32,

    pub fn turn_on(self: *PowerResource) void {
        if (!self.state) {
            self.state = true;
        }
        self.reference_count += 1;
    }

    pub fn turn_off(self: *PowerResource) void {
        if (self.reference_count > 0) {
            self.reference_count -= 1;
        }
        if (self.reference_count == 0 and self.state) {
            self.state = false;
        }
    }
};

// ============================================================================
// Thermal Management
// ============================================================================

pub const ThermalZone = struct {
    name: [64]u8,
    name_len: u8,
    temperature: i32,       // Millidegrees Celsius
    trip_points: [12]TripPoint,
    nr_trip_points: u8,
    polling_period: u32,    // Milliseconds
    passive_delay: u32,
    active_cooling: [10]CoolingDevice,
    nr_active_cooling: u8,
    passive_cooling: [10]CoolingDevice,
    nr_passive_cooling: u8,
    mode: ThermalMode,
    governor: ThermalGovernor,

    pub fn current_temp_celsius(self: *const ThermalZone) i32 {
        return @divTrunc(self.temperature, 1000);
    }

    pub fn check_trip_points(self: *const ThermalZone) ?TripType {
        var i: u8 = 0;
        while (i < self.nr_trip_points) : (i += 1) {
            if (self.temperature >= self.trip_points[i].temperature) {
                return self.trip_points[i].trip_type;
            }
        }
        return null;
    }
};

pub const TripType = enum(u8) {
    active = 0,
    passive = 1,
    hot = 2,
    critical = 3,
};

pub const TripPoint = struct {
    trip_type: TripType,
    temperature: i32,      // Millidegrees Celsius
    hysteresis: i32,
};

pub const ThermalMode = enum(u8) {
    enabled = 0,
    disabled = 1,
};

pub const ThermalGovernor = enum(u8) {
    step_wise = 0,
    fair_share = 1,
    bang_bang = 2,
    power_allocator = 3,
    user_space = 4,
};

pub const CoolingDevice = struct {
    name: [32]u8,
    name_len: u8,
    cooling_type: CoolingType,
    max_state: u32,
    cur_state: u32,

    pub fn set_state(self: *CoolingDevice, state: u32) void {
        if (state <= self.max_state) {
            self.cur_state = state;
        }
    }
};

pub const CoolingType = enum(u8) {
    processor = 0,
    fan = 1,
    lcd = 2,
    memory = 3,
    gpu = 4,
    generic = 5,
};

// ============================================================================
// Battery / Power Supply
// ============================================================================

pub const BatteryInfo = struct {
    present: bool,
    technology: BatteryTechnology,
    design_capacity: u32,      // mWh
    last_full_capacity: u32,   // mWh
    design_voltage: u32,       // mV
    capacity_warning: u32,     // mWh
    capacity_low: u32,         // mWh
    capacity_granularity_1: u32,
    capacity_granularity_2: u32,
    model_number: [32]u8,
    serial_number: [32]u8,
    battery_type: [32]u8,
    oem_info: [32]u8,
    cycle_count: u32,
};

pub const BatteryState = struct {
    state: BatteryStatus,
    present_rate: u32,         // mW
    remaining_capacity: u32,   // mWh
    present_voltage: u32,      // mV
    temperature: i32,          // Tenths of degrees Celsius

    pub fn capacity_percent(self: *const BatteryState, info: *const BatteryInfo) u32 {
        if (info.last_full_capacity == 0) return 0;
        return (self.remaining_capacity * 100) / info.last_full_capacity;
    }

    pub fn time_remaining_minutes(self: *const BatteryState) u32 {
        if (self.present_rate == 0) return 0;
        return (self.remaining_capacity * 60) / self.present_rate;
    }
};

pub const BatteryStatus = packed struct(u32) {
    discharging: bool = false,
    charging: bool = false,
    critical: bool = false,
    charge_limiting: bool = false,
    _reserved: u28 = 0,
};

pub const BatteryTechnology = enum(u8) {
    non_rechargeable = 0,
    rechargeable = 1,
};

pub const AcAdapter = struct {
    present: bool,
    online: bool,
    ac_type: AcType,
};

pub const AcType = enum(u8) {
    offline = 0,
    online = 1,
    unknown = 2,
};

// ============================================================================
// ACPI GPE (General Purpose Events)
// ============================================================================

pub const MAX_GPE_BLOCKS: usize = 2;
pub const MAX_GPE_PER_BLOCK: usize = 256;

pub const GpeType = enum(u8) {
    wake = 0,
    runtime = 1,
    wake_runtime = 2,
};

pub const GpeHandler = struct {
    gpe_number: u32,
    gpe_type: GpeType,
    handler: ?*const fn (u32) void,
    method_node: ?*anyopaque, // AML method node
    count: u64,
    dispatch_type: GpeDispatch,
};

pub const GpeDispatch = enum(u8) {
    none = 0,
    handler = 1,
    method = 2,
    notify = 3,
};

pub const GpeBlock = struct {
    address: u64,
    space_id: u8,
    register_count: u32,
    base_gpe: u32,
    handlers: [MAX_GPE_PER_BLOCK]GpeHandler,
    enable_mask: [MAX_GPE_PER_BLOCK / 8]u8,
    status_mask: [MAX_GPE_PER_BLOCK / 8]u8,

    pub fn is_enabled(self: *const GpeBlock, gpe: u32) bool {
        const idx = gpe - self.base_gpe;
        if (idx >= self.register_count * 8) return false;
        return (self.enable_mask[idx / 8] & (@as(u8, 1) << @as(u3, @truncate(idx % 8)))) != 0;
    }

    pub fn enable_gpe(self: *GpeBlock, gpe: u32) void {
        const idx = gpe - self.base_gpe;
        if (idx < self.register_count * 8) {
            self.enable_mask[idx / 8] |= @as(u8, 1) << @as(u3, @truncate(idx % 8));
        }
    }

    pub fn disable_gpe(self: *GpeBlock, gpe: u32) void {
        const idx = gpe - self.base_gpe;
        if (idx < self.register_count * 8) {
            self.enable_mask[idx / 8] &= ~(@as(u8, 1) << @as(u3, @truncate(idx % 8)));
        }
    }
};

// ============================================================================
// ACPI Namespace and Device
// ============================================================================

pub const AcpiObjectType = enum(u8) {
    integer = 1,
    string = 2,
    buffer = 3,
    package = 4,
    field_unit = 5,
    device = 6,
    event = 7,
    method = 8,
    mutex = 9,
    region = 10,
    power = 11,
    processor = 12,
    thermal = 13,
    buffer_field = 14,
    external = 22,
};

pub const AcpiDevice = struct {
    name: [128]u8,
    name_len: u8,
    hid: [16]u8,       // Hardware ID
    uid: [16]u8,       // Unique ID
    cls: [16]u8,       // Class Code
    adr: u64,          // Address
    status: AcpiDeviceStatus,
    d_state: AcpiDState,
    s_state: AcpiSleepState,
    wake_capable: bool,
    power_resources: [8]*PowerResource,
    nr_power_resources: u8,
};

pub const AcpiDeviceStatus = packed struct(u32) {
    present: bool = true,
    enabled: bool = true,
    show_in_ui: bool = true,
    functioning: bool = true,
    battery_present: bool = false,
    _reserved: u27 = 0,
};

// ============================================================================
// PPTT (Processor Properties Topology Table)
// ============================================================================

pub const PpttType = enum(u8) {
    processor = 0,
    cache = 1,
    id = 2,
};

pub const PpttProcessor = extern struct {
    entry_type: u8,
    length: u8,
    reserved: u16,
    flags: u32,
    parent: u32,
    acpi_processor_id: u32,
    nr_private_resources: u32,
    // private_resources: [nr_private_resources]u32 follows

    pub fn is_physical_package(self: *const PpttProcessor) bool {
        return (self.flags & 1) != 0;
    }
    pub fn is_acpi_processor_id_valid(self: *const PpttProcessor) bool {
        return (self.flags & 2) != 0;
    }
    pub fn is_thread(self: *const PpttProcessor) bool {
        return (self.flags & 4) != 0;
    }
    pub fn is_leaf(self: *const PpttProcessor) bool {
        return (self.flags & 8) != 0;
    }
    pub fn is_identical(self: *const PpttProcessor) bool {
        return (self.flags & 16) != 0;
    }
};

pub const PpttCache = extern struct {
    entry_type: u8,
    length: u8,
    reserved: u16,
    flags: u32,
    next_level_cache: u32,
    size: u32,
    nr_sets: u32,
    associativity: u8,
    attributes: u8,
    line_size: u16,
    cache_id: u32,

    pub fn cache_type(self: *const PpttCache) u8 {
        return self.attributes & 0x3;
    }

    pub fn write_policy(self: *const PpttCache) u8 {
        return (self.attributes >> 2) & 0x3;
    }

    pub fn allocation_type(self: *const PpttCache) u8 {
        return (self.attributes >> 4) & 0x3;
    }
};

// ============================================================================
// NFIT (NVDIMM Firmware Interface Table)
// ============================================================================

pub const NfitStructureType = enum(u16) {
    spa_range = 0,
    region_mapping = 1,
    interleave = 2,
    smbios_mi = 3,
    control_region = 4,
    data_window = 5,
    flush_address = 6,
    platform_capabilities = 7,
};

pub const NfitSpaRange = extern struct {
    structure_type: u16,
    length: u16,
    spa_range_index: u16,
    flags: u16,
    reserved: u32,
    proximity_domain: u32,
    address_range_type_guid: [16]u8,
    system_physical_address: u64,
    region_length: u64,
    memory_mapping_attribute: u64,
};

// ============================================================================
// ACPI Table Manager
// ============================================================================

pub const MAX_ACPI_TABLES: usize = 128;

pub const AcpiTableManager = struct {
    rsdp: ?*const AcpiRsdp,
    tables: [MAX_ACPI_TABLES]*const AcpiSdtHeader,
    table_count: u32,
    fadt: ?*const AcpiFadt,
    madt: ?*const AcpiMadt,
    mcfg: ?*const AcpiMcfg,
    hpet_table: ?*const AcpiHpet,
    dmar: ?*const AcpiDmar,
    srat: ?*const AcpiSrat,

    pub fn init() AcpiTableManager {
        return AcpiTableManager{
            .rsdp = null,
            .tables = undefined,
            .table_count = 0,
            .fadt = null,
            .madt = null,
            .mcfg = null,
            .hpet_table = null,
            .dmar = null,
            .srat = null,
        };
    }

    pub fn find_table(self: *const AcpiTableManager, sig: AcpiTableSignature) ?*const AcpiSdtHeader {
        var i: u32 = 0;
        while (i < self.table_count) : (i += 1) {
            if (self.tables[i].signature == @intFromEnum(sig)) {
                return self.tables[i];
            }
        }
        return null;
    }

    pub fn find_table_nth(self: *const AcpiTableManager, sig: AcpiTableSignature, n: u32) ?*const AcpiSdtHeader {
        var count: u32 = 0;
        var i: u32 = 0;
        while (i < self.table_count) : (i += 1) {
            if (self.tables[i].signature == @intFromEnum(sig)) {
                if (count == n) return self.tables[i];
                count += 1;
            }
        }
        return null;
    }

    pub fn register_table(self: *AcpiTableManager, table: *const AcpiSdtHeader) bool {
        if (self.table_count >= MAX_ACPI_TABLES) return false;
        self.tables[self.table_count] = table;
        self.table_count += 1;

        // Cache well-known tables
        if (table.signature == @intFromEnum(AcpiTableSignature.FADT)) {
            self.fadt = @ptrCast(@alignCast(table));
        } else if (table.signature == @intFromEnum(AcpiTableSignature.MADT)) {
            self.madt = @ptrCast(@alignCast(table));
        } else if (table.signature == @intFromEnum(AcpiTableSignature.MCFG)) {
            self.mcfg = @ptrCast(@alignCast(table));
        } else if (table.signature == @intFromEnum(AcpiTableSignature.HPET)) {
            self.hpet_table = @ptrCast(@alignCast(table));
        } else if (table.signature == @intFromEnum(AcpiTableSignature.DMAR)) {
            self.dmar = @ptrCast(@alignCast(table));
        } else if (table.signature == @intFromEnum(AcpiTableSignature.SRAT)) {
            self.srat = @ptrCast(@alignCast(table));
        }

        return true;
    }
};
