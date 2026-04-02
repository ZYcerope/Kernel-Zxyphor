// Zxyphor Kernel - EFI Runtime Services,
// ACPI Table Parsing Detail,
// SMBIOS / DMI Structures,
// Boot Parameters & Setup,
// E820 Memory Map,
// x86 Setup Header
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// EFI Runtime Services Table
// ============================================================================

pub const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552; // "RUNTSERV"

pub const EfiRuntimeServices = extern struct {
    hdr: EfiTableHeader,
    get_time: u64,
    set_time: u64,
    get_wakeup_time: u64,
    set_wakeup_time: u64,
    set_virtual_address_map: u64,
    convert_pointer: u64,
    get_variable: u64,
    get_next_variable_name: u64,
    set_variable: u64,
    get_next_high_mono_count: u64,
    reset_system: u64,
    update_capsule: u64,
    query_capsule_capabilities: u64,
    query_variable_info: u64,
};

pub const EfiTableHeader = extern struct {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
};

pub const EfiResetType = enum(u32) {
    cold = 0,
    warm = 1,
    shutdown = 2,
    platform_specific = 3,
};

pub const EfiVariableAttributes = packed struct(u32) {
    non_volatile: bool = false,
    bootservice_access: bool = false,
    runtime_access: bool = false,
    hardware_error_record: bool = false,
    authenticated_write: bool = false,
    time_based_authenticated: bool = false,
    append_write: bool = false,
    enhanced_authenticated: bool = false,
    _reserved: u24 = 0,
};

pub const EfiMemoryAttribute = packed struct(u64) {
    uc: bool = false, // Uncacheable
    wc: bool = false, // Write Combining
    wt: bool = false, // Write Through
    wb: bool = false, // Write Back
    uce: bool = false, // Uncacheable Exported
    _reserved1: u7 = 0,
    wp: bool = false, // Write Protected
    rp: bool = false, // Read Protected
    xp: bool = false, // Execute Protected
    nv: bool = false, // Non-Volatile
    more_reliable: bool = false,
    ro: bool = false, // Read Only
    sp: bool = false, // Specific Purpose
    cpu_crypto: bool = false,
    _reserved2: u43 = 0,
    runtime: bool = false,
    _reserved3: u2 = 0,
};

pub const EfiMemoryType = enum(u32) {
    reserved_memory_type = 0,
    loader_code = 1,
    loader_data = 2,
    boot_services_code = 3,
    boot_services_data = 4,
    runtime_services_code = 5,
    runtime_services_data = 6,
    conventional_memory = 7,
    unusable_memory = 8,
    acpi_reclaim_memory = 9,
    acpi_memory_nvs = 10,
    memory_mapped_io = 11,
    memory_mapped_io_port_space = 12,
    pal_code = 13,
    persistent_memory = 14,
    unaccepted_memory = 15,
    max_memory_type = 16,
};

pub const EfiMemoryDescriptor = extern struct {
    type_: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
};

// ============================================================================
// ACPI Table Header (generic)
// ============================================================================

pub const AcpiTableHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
};

// ============================================================================
// RSDP (Root System Description Pointer)
// ============================================================================

pub const AcpiRsdp = extern struct {
    signature: [8]u8, // "RSD PTR "
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,
};

// ============================================================================
// MADT (Multiple APIC Description Table)
// ============================================================================

pub const ACPI_MADT_SIGNATURE = "APIC";

pub const AcpiMadt = extern struct {
    header: AcpiTableHeader,
    local_apic_address: u32,
    flags: u32, // bit 0 = PCAT_COMPAT
    // Variable-length entries follow
};

pub const MadtEntryType = enum(u8) {
    local_apic = 0,
    io_apic = 1,
    interrupt_override = 2,
    nmi_source = 3,
    local_apic_nmi = 4,
    local_apic_address_override = 5,
    io_sapic = 6,
    local_sapic = 7,
    platform_interrupt_sources = 8,
    processor_local_x2apic = 9,
    local_x2apic_nmi = 10,
    gic_cpu = 11,
    gic_distributor = 12,
    gic_msi_frame = 13,
    gic_redistributor = 14,
    gic_its = 15,
    multiprocessor_wakeup = 16,
    core_pic = 17,
    lio_pic = 18,
    hv_pic = 19,
    eio_pic = 20,
    msi_pic = 21,
    bio_pic = 22,
    lpc_pic = 23,
};

pub const MadtLocalApic = extern struct {
    type_: u8,
    length: u8,
    acpi_processor_uid: u8,
    apic_id: u8,
    flags: u32, // bit 0 = enabled, bit 1 = online capable
};

pub const MadtIoApic = extern struct {
    type_: u8,
    length: u8,
    io_apic_id: u8,
    reserved: u8,
    address: u32,
    global_irq_base: u32,
};

pub const MadtIntOverride = extern struct {
    type_: u8,
    length: u8,
    bus: u8,
    source: u8,
    global_irq: u32,
    flags: u16,
};

pub const MadtLocalX2Apic = extern struct {
    type_: u8,
    length: u8,
    reserved: u16,
    x2apic_id: u32,
    flags: u32,
    acpi_processor_uid: u32,
};

// ============================================================================
// MCFG (PCI Express Memory-Mapped Configuration)
// ============================================================================

pub const ACPI_MCFG_SIGNATURE = "MCFG";

pub const AcpiMcfg = extern struct {
    header: AcpiTableHeader,
    reserved: u64,
    // Variable-length allocation entries follow
};

pub const McfgAllocation = extern struct {
    base_address: u64,
    pci_segment: u16,
    start_bus: u8,
    end_bus: u8,
    reserved: u32,
};

// ============================================================================
// HPET Table
// ============================================================================

pub const ACPI_HPET_SIGNATURE = "HPET";

pub const AcpiHpet = extern struct {
    header: AcpiTableHeader,
    event_timer_block_id: u32,
    base_address: AcpiGenericAddress,
    hpet_number: u8,
    min_clock_tick: u16,
    page_protection: u8,
};

pub const AcpiGenericAddress = extern struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

// ============================================================================
// FADT (Fixed ACPI Description Table)
// ============================================================================

pub const ACPI_FADT_SIGNATURE = "FACP";

pub const AcpiFadt = extern struct {
    header: AcpiTableHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    _reserved1: u8,
    preferred_pm_profile: u8,
    sci_interrupt: u16,
    smi_command: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_request: u8,
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
    gpe0_block_length: u8,
    gpe1_block_length: u8,
    gpe1_base: u8,
    cst_control: u8,
    p_lvl2_latency: u16,
    p_lvl3_latency: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alarm: u8,
    month_alarm: u8,
    century: u8,
    iapc_boot_arch: u16,
    _reserved2: u8,
    flags: AcpiFadtFlags,
    reset_register: AcpiGenericAddress,
    reset_value: u8,
    arm_boot_arch: u16,
    fadt_minor_revision: u8,
    x_firmware_ctrl: u64,
    x_dsdt: u64,
    x_pm1a_event_block: AcpiGenericAddress,
    x_pm1b_event_block: AcpiGenericAddress,
    x_pm1a_control_block: AcpiGenericAddress,
    x_pm1b_control_block: AcpiGenericAddress,
    x_pm2_control_block: AcpiGenericAddress,
    x_pm_timer_block: AcpiGenericAddress,
    x_gpe0_block: AcpiGenericAddress,
    x_gpe1_block: AcpiGenericAddress,
    sleep_control: AcpiGenericAddress,
    sleep_status: AcpiGenericAddress,
    hypervisor_vendor_id: u64,
};

pub const AcpiFadtFlags = packed struct(u32) {
    wbinvd: bool = false,
    wbinvd_flush: bool = false,
    proc_c1: bool = false,
    p_lvl2_up: bool = false,
    pwr_button: bool = false,
    slp_button: bool = false,
    fix_rtc: bool = false,
    rtc_s4: bool = false,
    tmr_val_ext: bool = false,
    dck_cap: bool = false,
    reset_reg_sup: bool = false,
    sealed_case: bool = false,
    headless: bool = false,
    cpu_sw_slp: bool = false,
    pci_exp_wak: bool = false,
    use_platform_clock: bool = false,
    s4_rtc_sts_valid: bool = false,
    remote_power_on: bool = false,
    apic_cluster: bool = false,
    apic_physical: bool = false,
    hw_reduced_acpi: bool = false,
    low_power_s0: bool = false,
    _reserved: u10 = 0,
};

// ============================================================================
// SMBIOS / DMI Structures
// ============================================================================

pub const SMBIOS_ANCHOR: [5]u8 = "_SM3_".*;

pub const SmbiosEntryPoint3 = extern struct {
    anchor: [5]u8,
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    docrev: u8,
    entry_point_revision: u8,
    reserved: u8,
    structure_table_max_size: u32,
    structure_table_address: u64,
};

pub const SmbiosStructHeader = extern struct {
    type_: SmbiosType,
    length: u8,
    handle: u16,
};

pub const SmbiosType = enum(u8) {
    bios_info = 0,
    system_info = 1,
    baseboard_info = 2,
    chassis_info = 3,
    processor_info = 4,
    memory_controller = 5,
    memory_module = 6,
    cache_info = 7,
    port_connector = 8,
    system_slots = 9,
    onboard_devices = 10,
    oem_strings = 11,
    system_config = 12,
    bios_language = 13,
    group_associations = 14,
    system_event_log = 15,
    physical_memory_array = 16,
    memory_device = 17,
    memory_error_32 = 18,
    memory_array_mapped = 19,
    memory_device_mapped = 20,
    builtin_pointing = 21,
    portable_battery = 22,
    system_reset = 23,
    hardware_security = 24,
    system_power_controls = 25,
    voltage_probe = 26,
    cooling_device = 27,
    temperature_probe = 28,
    current_probe = 29,
    oob_remote_access = 30,
    onboard_devices_ext = 41,
    tpm_device = 43,
    processor_additional = 44,
    firmware_inventory = 45,
    inactive = 126,
    end_of_table = 127,
};

pub const SmbiosProcessorInfo = extern struct {
    header: SmbiosStructHeader,
    socket_designation: u8,
    processor_type: u8,
    processor_family: u8,
    processor_manufacturer: u8,
    processor_id: u64,
    processor_version: u8,
    voltage: u8,
    external_clock: u16,
    max_speed: u16,
    current_speed: u16,
    status: u8,
    processor_upgrade: u8,
    l1_cache_handle: u16,
    l2_cache_handle: u16,
    l3_cache_handle: u16,
    serial_number: u8,
    asset_tag: u8,
    part_number: u8,
    core_count: u8,
    core_enabled: u8,
    thread_count: u8,
    processor_characteristics: u16,
    processor_family2: u16,
    core_count2: u16,
    core_enabled2: u16,
    thread_count2: u16,
    thread_enabled: u16,
};

pub const SmbiosMemoryDevice = extern struct {
    header: SmbiosStructHeader,
    phys_mem_array_handle: u16,
    mem_error_info_handle: u16,
    total_width: u16,
    data_width: u16,
    size: u16,
    form_factor: u8,
    device_set: u8,
    device_locator: u8,
    bank_locator: u8,
    memory_type: u8,
    type_detail: u16,
    speed: u16,
    manufacturer: u8,
    serial_number: u8,
    asset_tag: u8,
    part_number: u8,
    attributes: u8,
    extended_size: u32,
    configured_speed: u16,
    min_voltage: u16,
    max_voltage: u16,
    configured_voltage: u16,
    memory_technology: u8,
    operating_mode_cap: u16,
    firmware_version: u8,
    module_manufacturer_id: u16,
    module_product_id: u16,
    subsystem_controller_manufacturer_id: u16,
    subsystem_controller_product_id: u16,
    non_volatile_size: u64,
    volatile_size: u64,
    cache_size: u64,
    logical_size: u64,
    extended_speed: u32,
    extended_configured_speed: u32,
};

// ============================================================================
// E820 Memory Map
// ============================================================================

pub const E820_MAX_ENTRIES: usize = 128;

pub const E820Type = enum(u32) {
    ram = 1,
    reserved = 2,
    acpi = 3,
    nvs = 4,
    unusable = 5,
    disabled = 6,
    pmem = 7,
    pram = 12,
    soft_reserved = 0xEFFFFFFC,
};

pub const E820Entry = extern struct {
    addr: u64,
    size: u64,
    type_: E820Type,
};

pub const E820Map = struct {
    entries: [E820_MAX_ENTRIES]E820Entry,
    nr_entries: u32,
};

// ============================================================================
// Boot Manager (Zxyphor)
// ============================================================================

pub const BootSubsystemManager = struct {
    efi_runtime: ?*EfiRuntimeServices,
    acpi_rsdp: ?*AcpiRsdp,
    smbios_entry: ?*SmbiosEntryPoint3,
    e820_map: E820Map,
    efi_memory_map_size: usize,
    efi_mmap_desc_size: usize,
    acpi_tables_parsed: u32,
    boot_type: BootType,
    cmdline: [4096]u8,
    cmdline_len: u16,
    initialized: bool,

    pub fn init() BootSubsystemManager {
        return std.mem.zeroes(BootSubsystemManager);
    }
};

pub const BootType = enum(u8) {
    unknown = 0,
    uefi = 1,
    bios_legacy = 2,
    multiboot2 = 3,
    limine = 4,
    stivale2 = 5,
};
