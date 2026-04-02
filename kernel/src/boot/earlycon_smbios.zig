// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Early Boot Console (earlycon),
// SMBIOS/DMI Parsing, ACPI Early Tables,
// Boot Memory Allocator (memblock) Early,
// Kernel Command Line Parsing, initrd/initramfs,
// Boot Protocol Detection, Secure Boot Validation
// More advanced than Linux 2026 boot infrastructure

const std = @import("std");

// ============================================================================
// Early Console (earlycon)
// ============================================================================

/// Early console type
pub const EarlyConType = enum(u8) {
    uart_8250 = 0,
    uart_pl011 = 1,
    uart_sbi = 2, // RISC-V SBI
    vga_text = 3,
    efifb = 4,
    serial_io = 5,
    mmio = 6,
    mmio32 = 7,
    mmio32be = 8,
    // Zxyphor
    zxy_framebuffer = 100,
    zxy_debug_port = 101,
};

/// Early console descriptor
pub const EarlyConDesc = struct {
    con_type: EarlyConType = .uart_8250,
    base_addr: u64 = 0,
    reg_shift: u8 = 0,
    reg_width: u8 = 1, // bytes per register
    io_type: EarlyConIoType = .mmio,
    baudrate: u32 = 115200,
    data_bits: u8 = 8,
    stop_bits: u8 = 1,
    parity: EarlyConParity = .none,
    fifo_size: u32 = 16,
    index: i32 = -1, // serial port index
    options: [32]u8 = [_]u8{0} ** 32,
    options_len: u8 = 0,
    active: bool = false,
};

pub const EarlyConIoType = enum(u8) {
    pio = 0,
    mmio = 1,
    mmio32 = 2,
    mmio32be = 3,
    au_mmio = 4,
};

pub const EarlyConParity = enum(u8) {
    none = 0,
    odd = 1,
    even = 2,
};

// ============================================================================
// SMBIOS / DMI Parsing
// ============================================================================

/// SMBIOS entry point type
pub const SmbiosEntryType = enum(u8) {
    smbios_21 = 0, // 2.1 (32-bit)
    smbios_30 = 1, // 3.0 (64-bit)
};

/// SMBIOS structure types
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
    group_assoc = 14,
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
    electrical_current_probe = 29,
    out_of_band_remote = 30,
    boot_integrity_services = 31,
    system_boot = 32,
    memory_error_64 = 33,
    management_device = 34,
    management_device_component = 35,
    management_device_threshold = 36,
    memory_channel = 37,
    ipmi_device = 38,
    system_power_supply = 39,
    additional_info = 40,
    onboard_devices_ext = 41,
    management_controller_host = 42,
    tpm_device = 43,
    processor_additional = 44,
    firmware_inventory = 45,
    string_property = 46,
    inactive = 126,
    end_of_table = 127,
};

/// DMI (Desktop Management Interface) data
pub const DmiData = struct {
    // BIOS
    bios_vendor: [64]u8 = [_]u8{0} ** 64,
    bios_vendor_len: u8 = 0,
    bios_version: [64]u8 = [_]u8{0} ** 64,
    bios_version_len: u8 = 0,
    bios_date: [32]u8 = [_]u8{0} ** 32,
    bios_date_len: u8 = 0,
    // System
    sys_vendor: [64]u8 = [_]u8{0} ** 64,
    sys_vendor_len: u8 = 0,
    product_name: [64]u8 = [_]u8{0} ** 64,
    product_name_len: u8 = 0,
    product_version: [64]u8 = [_]u8{0} ** 64,
    product_version_len: u8 = 0,
    product_serial: [64]u8 = [_]u8{0} ** 64,
    product_serial_len: u8 = 0,
    product_uuid: [16]u8 = [_]u8{0} ** 16,
    product_sku: [64]u8 = [_]u8{0} ** 64,
    product_sku_len: u8 = 0,
    product_family: [64]u8 = [_]u8{0} ** 64,
    product_family_len: u8 = 0,
    // Board
    board_vendor: [64]u8 = [_]u8{0} ** 64,
    board_vendor_len: u8 = 0,
    board_name: [64]u8 = [_]u8{0} ** 64,
    board_name_len: u8 = 0,
    board_version: [64]u8 = [_]u8{0} ** 64,
    board_version_len: u8 = 0,
    board_serial: [64]u8 = [_]u8{0} ** 64,
    board_serial_len: u8 = 0,
    board_asset_tag: [64]u8 = [_]u8{0} ** 64,
    board_asset_tag_len: u8 = 0,
    // Chassis
    chassis_vendor: [64]u8 = [_]u8{0} ** 64,
    chassis_vendor_len: u8 = 0,
    chassis_type: u8 = 0,
    chassis_version: [64]u8 = [_]u8{0} ** 64,
    chassis_version_len: u8 = 0,
    chassis_serial: [64]u8 = [_]u8{0} ** 64,
    chassis_serial_len: u8 = 0,
    chassis_asset_tag: [64]u8 = [_]u8{0} ** 64,
    chassis_asset_tag_len: u8 = 0,
};

/// SMBIOS memory device entry
pub const SmbiosMemDevice = struct {
    handle: u16 = 0,
    physical_array_handle: u16 = 0,
    error_info_handle: u16 = 0,
    total_width: u16 = 0,
    data_width: u16 = 0,
    size_mb: u32 = 0, // size in MB (extended for > 32GB)
    form_factor: u8 = 0,
    device_set: u8 = 0,
    device_locator: [32]u8 = [_]u8{0} ** 32,
    device_locator_len: u8 = 0,
    bank_locator: [32]u8 = [_]u8{0} ** 32,
    bank_locator_len: u8 = 0,
    memory_type: u8 = 0,
    type_detail: u16 = 0,
    speed_mhz: u32 = 0,
    manufacturer: [32]u8 = [_]u8{0} ** 32,
    manufacturer_len: u8 = 0,
    serial_number: [32]u8 = [_]u8{0} ** 32,
    serial_number_len: u8 = 0,
    part_number: [32]u8 = [_]u8{0} ** 32,
    part_number_len: u8 = 0,
    configured_clock_speed: u32 = 0,
    min_voltage: u16 = 0,
    max_voltage: u16 = 0,
    configured_voltage: u16 = 0,
    technology: u8 = 0,
};

// ============================================================================
// ACPI Early Table Parsing
// ============================================================================

/// ACPI table signature
pub const AcpiTableSig = enum(u32) {
    rsdp = 0x50445352, // "RSDP"
    rsdt = 0x54445352, // "RSDT"
    xsdt = 0x54445358, // "XSDT"
    fadt = 0x50434146, // "FACP"
    madt = 0x43495041, // "APIC"
    mcfg = 0x4746434D, // "MCFG"
    hpet = 0x54455048, // "HPET"
    srat = 0x54415253, // "SRAT"
    slit = 0x54494C53, // "SLIT"
    dsdt = 0x54445344, // "DSDT"
    ssdt = 0x54445353, // "SSDT"
    bgrt = 0x54524742, // "BGRT"
    fpdt = 0x54445046, // "FPDT"
    bert = 0x54524542, // "BERT"
    erst = 0x54535245, // "ERST"
    hest = 0x54534548, // "HEST"
    einj = 0x4A4E4945, // "EINJ"
    dmar = 0x52414D44, // "DMAR"
    ivrs = 0x53525649, // "IVRS"
    pptt = 0x54545050, // "PPTT"
    nfit = 0x5449464E, // "NFIT"
    cedt = 0x54444543, // "CEDT"
    // Zxyphor
};

/// RSDP (Root System Description Pointer) v2
pub const AcpiRsdpV2 = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    _reserved: [3]u8,
};

/// ACPI table header (common)
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
// Kernel Command Line Parsing
// ============================================================================

/// Boot parameter type
pub const BootParamType = enum(u8) {
    boolean = 0,
    integer = 1,
    unsigned_integer = 2,
    string = 3,
    hex = 4,
    // Special
    early_param = 10,
    setup_param = 11,
};

/// Known early boot parameters
pub const EarlyBootParam = enum(u8) {
    console = 0,
    earlycon = 1,
    earlyprintk = 2,
    loglevel = 3,
    debug = 4,
    quiet = 5,
    root = 6,
    ro = 7,
    rw = 8,
    init = 9,
    maxcpus = 10,
    nosmp = 11,
    noapic = 12,
    nolapic = 13,
    noacpi = 14,
    mem = 15,
    memmap = 16,
    hugepagesz = 17,
    hugepages = 18,
    iommu = 19,
    intel_iommu = 20,
    crashkernel = 21,
    nmi_watchdog = 22,
    mitigations = 23,
    // Zxyphor
    zxy_mode = 100,
    zxy_debug = 101,
};

/// Command line buffer
pub const CmdlineBuffer = struct {
    buf: [4096]u8 = [_]u8{0} ** 4096,
    len: u16 = 0,
    parsed: bool = false,
    nr_params: u32 = 0,
};

// ============================================================================
// initrd / initramfs
// ============================================================================

/// initrd type
pub const InitrdType = enum(u8) {
    none = 0,
    initrd = 1, // legacy initrd (block device)
    initramfs = 2, // cpio archive
};

/// initrd compression
pub const InitrdCompression = enum(u8) {
    none = 0,
    gzip = 1,
    bzip2 = 2,
    lzma = 3,
    xz = 4,
    lzo = 5,
    lz4 = 6,
    zstd = 7,
};

/// initrd descriptor
pub const InitrdDesc = struct {
    initrd_type: InitrdType = .none,
    compression: InitrdCompression = .none,
    start_addr: u64 = 0,
    end_addr: u64 = 0,
    size: u64 = 0,
    loaded: bool = false,
    verified: bool = false,
};

// ============================================================================
// Boot Protocol Detection
// ============================================================================

/// Boot protocol
pub const BootProtocol = enum(u8) {
    unknown = 0,
    multiboot = 1,
    multiboot2 = 2,
    linux_boot = 3,
    uefi = 4,
    stivale2 = 5,
    limine = 6,
    devicetree = 7,
    // Zxyphor
    zxy_native = 100,
};

/// Boot framebuffer info
pub const BootFramebuffer = struct {
    addr: u64 = 0,
    pitch: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    bpp: u8 = 0,
    fb_type: u8 = 0,
    red_mask_size: u8 = 0,
    red_mask_shift: u8 = 0,
    green_mask_size: u8 = 0,
    green_mask_shift: u8 = 0,
    blue_mask_size: u8 = 0,
    blue_mask_shift: u8 = 0,
};

/// Boot memory map entry type
pub const BootMemType = enum(u32) {
    available = 1,
    reserved = 2,
    acpi_reclaimable = 3,
    acpi_nvs = 4,
    bad_memory = 5,
    // UEFI
    uefi_runtime_code = 6,
    uefi_runtime_data = 7,
    persistent_memory = 8,
    // Zxyphor
    zxy_kernel_reserved = 100,
};

/// Boot memory map entry
pub const BootMemEntry = struct {
    base: u64 = 0,
    length: u64 = 0,
    mem_type: BootMemType = .available,
};

// ============================================================================
// Secure Boot Validation
// ============================================================================

/// Secure boot state
pub const SecureBootState = enum(u8) {
    disabled = 0,
    enabled = 1,
    setup_mode = 2,
    deployed = 3,
    // Zxyphor
    zxy_verified = 100,
};

/// Secure boot key database
pub const SecureBootKeyDb = enum(u8) {
    pk = 0, // Platform Key
    kek = 1, // Key Exchange Key
    db = 2, // Signature Database
    dbx = 3, // Forbidden Signatures
    dbt = 4, // Timestamp Signatures
    dbr = 5, // Recovery Signatures
    mok = 6, // Machine Owner Key (MOK)
};

/// Secure boot validation result
pub const SecureBootValidation = struct {
    state: SecureBootState = .disabled,
    kernel_signed: bool = false,
    kernel_sig_valid: bool = false,
    initrd_signed: bool = false,
    initrd_sig_valid: bool = false,
    modules_enforce: bool = false,
    lockdown: bool = false,
};

// ============================================================================
// Boot Infrastructure Subsystem Manager
// ============================================================================

pub const BootInfraSubsystem = struct {
    protocol: BootProtocol = .unknown,
    earlycon: EarlyConDesc = .{},
    dmi: DmiData = .{},
    cmdline: CmdlineBuffer = .{},
    initrd: InitrdDesc = .{},
    framebuffer: BootFramebuffer = .{},
    secure_boot: SecureBootValidation = .{},
    acpi_revision: u8 = 0,
    nr_acpi_tables: u32 = 0,
    nr_smbios_structures: u32 = 0,
    nr_boot_mem_entries: u32 = 0,
    initialized: bool = false,

    pub fn init() BootInfraSubsystem {
        return BootInfraSubsystem{
            .initialized = true,
        };
    }
};
