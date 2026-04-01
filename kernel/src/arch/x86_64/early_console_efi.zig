// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Early Boot Console, EFI Runtime Services,
// ACPI Platform/Thermal, Early Printk, Boot Parameters,
// Command Line Parsing, Initrd/Initramfs
// More advanced than Linux 2026 boot infrastructure

const std = @import("std");

// ============================================================================
// Early Console / Early Printk
// ============================================================================

/// Early console type
pub const EarlyConsoleType = enum(u8) {
    none = 0,
    serial = 1,          // COM1/COM2 UART
    vga_text = 2,        // VGA text mode 80x25
    efi_console = 3,     // EFI Simple Text Output
    framebuffer = 4,     // Framebuffer console
    // Zxyphor
    zxy_debug_port = 10,
};

/// Serial port config for early console
pub const EarlySerialConfig = struct {
    io_base: u16,        // I/O port base (0x3F8 = COM1)
    baud_rate: u32,      // Default 115200
    data_bits: u8,       // 5, 6, 7, 8
    stop_bits: u8,       // 1, 2
    parity: SerialParity,
    // MMIO
    mmio_base: u64,      // Memory-mapped UART base
    is_mmio: bool,
    reg_shift: u8,       // Register shift (0, 1, 2)
    reg_width: u8,       // Register width (1, 4)
};

/// Serial parity
pub const SerialParity = enum(u8) {
    none = 0,
    odd = 1,
    even = 2,
    mark = 3,
    space = 4,
};

/// VGA text mode state
pub const VgaTextState = struct {
    base_addr: u64,       // 0xB8000
    width: u16,           // 80
    height: u16,          // 25
    cursor_x: u16,
    cursor_y: u16,
    attr: u8,             // Color attribute
    // Colors
    pub const COLOR_BLACK: u8 = 0;
    pub const COLOR_BLUE: u8 = 1;
    pub const COLOR_GREEN: u8 = 2;
    pub const COLOR_CYAN: u8 = 3;
    pub const COLOR_RED: u8 = 4;
    pub const COLOR_MAGENTA: u8 = 5;
    pub const COLOR_BROWN: u8 = 6;
    pub const COLOR_LIGHT_GREY: u8 = 7;
    pub const COLOR_DARK_GREY: u8 = 8;
    pub const COLOR_LIGHT_BLUE: u8 = 9;
    pub const COLOR_LIGHT_GREEN: u8 = 10;
    pub const COLOR_LIGHT_CYAN: u8 = 11;
    pub const COLOR_LIGHT_RED: u8 = 12;
    pub const COLOR_LIGHT_MAGENTA: u8 = 13;
    pub const COLOR_YELLOW: u8 = 14;
    pub const COLOR_WHITE: u8 = 15;
};

// ============================================================================
// EFI Runtime Services
// ============================================================================

/// EFI status codes
pub const EfiStatus = enum(u64) {
    success = 0,
    load_error = 1,
    invalid_parameter = 2,
    unsupported = 3,
    bad_buffer_size = 4,
    buffer_too_small = 5,
    not_ready = 6,
    device_error = 7,
    write_protected = 8,
    out_of_resources = 9,
    volume_corrupted = 10,
    volume_full = 11,
    no_media = 12,
    media_changed = 13,
    not_found = 14,
    access_denied = 15,
    no_response = 16,
    no_mapping = 17,
    timeout = 18,
    not_started = 19,
    already_started = 20,
    aborted = 21,
    icmp_error = 22,
    tftp_error = 23,
    protocol_error = 24,
    incompatible_version = 25,
    security_violation = 26,
    crc_error = 27,
    end_of_media = 28,
    end_of_file = 31,
    invalid_language = 32,
    compromised_data = 33,
    ip_address_conflict = 34,
    http_error = 35,
};

/// EFI memory type
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

/// EFI memory descriptor
pub const EfiMemoryDescriptor = struct {
    mem_type: EfiMemoryType,
    padding: u32,
    phys_start: u64,
    virt_start: u64,
    num_pages: u64,      // 4KB pages
    attribute: u64,
};

/// EFI memory attributes
pub const EFI_MEMORY_UC: u64 = 0x0000000000000001;
pub const EFI_MEMORY_WC: u64 = 0x0000000000000002;
pub const EFI_MEMORY_WT: u64 = 0x0000000000000004;
pub const EFI_MEMORY_WB: u64 = 0x0000000000000008;
pub const EFI_MEMORY_UCE: u64 = 0x0000000000000010;
pub const EFI_MEMORY_WP: u64 = 0x0000000000001000;
pub const EFI_MEMORY_RP: u64 = 0x0000000000002000;
pub const EFI_MEMORY_XP: u64 = 0x0000000000004000;
pub const EFI_MEMORY_NV: u64 = 0x0000000000008000;
pub const EFI_MEMORY_MORE_RELIABLE: u64 = 0x0000000000010000;
pub const EFI_MEMORY_RO: u64 = 0x0000000000020000;
pub const EFI_MEMORY_SP: u64 = 0x0000000000040000;
pub const EFI_MEMORY_CPU_CRYPTO: u64 = 0x0000000000080000;
pub const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000;

/// EFI GUID
pub const EfiGuid = struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

/// Well-known EFI GUIDs
pub const EFI_GLOBAL_VARIABLE_GUID = EfiGuid{
    .data1 = 0x8BE4DF61, .data2 = 0x93CA, .data3 = 0x11D2,
    .data4 = .{ 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C },
};

pub const EFI_ACPI_20_TABLE_GUID = EfiGuid{
    .data1 = 0x8868E871, .data2 = 0xE4F1, .data3 = 0x11D3,
    .data4 = .{ 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 },
};

pub const EFI_SMBIOS3_TABLE_GUID = EfiGuid{
    .data1 = 0xF2FD1544, .data2 = 0x9794, .data3 = 0x4A2C,
    .data4 = .{ 0x99, 0x2E, 0xE5, 0xBB, 0xCF, 0x20, 0xE3, 0x94 },
};

/// EFI Time
pub const EfiTime = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    pad1: u8,
    nanosecond: u32,
    timezone: i16,
    daylight: u8,
    pad2: u8,
};

/// EFI reset type
pub const EfiResetType = enum(u32) {
    cold = 0,
    warm = 1,
    shutdown = 2,
    platform_specific = 3,
};

/// EFI capsule flags
pub const EfiCapsuleFlags = packed struct {
    persist_across_reset: bool = false,
    populate_system_table: bool = false,
    initiate_reset: bool = false,
    _padding: u29 = 0,
};

/// EFI variable attributes
pub const EfiVarAttr = packed struct {
    non_volatile: bool = false,
    boot_service_access: bool = false,
    runtime_access: bool = false,
    hardware_error_record: bool = false,
    authenticated_write_access: bool = false,
    time_based_authenticated_write_access: bool = false,
    append_write: bool = false,
    enhanced_authenticated_access: bool = false,
    _padding: u24 = 0,
};

// ============================================================================
// Boot Parameters / Kernel Command Line
// ============================================================================

/// Boot parameter type
pub const BootParamType = enum(u8) {
    boolean = 0,
    integer = 1,
    string = 2,
    hex = 3,
    enum_val = 4,
};

/// Boot parameter descriptor
pub const BootParam = struct {
    name: [64]u8,
    name_len: u8,
    param_type: BootParamType,
    // Value
    int_val: i64,
    str_val: [256]u8,
    str_len: u16,
    bool_val: bool,
    // Metadata
    description: [128]u8,
    is_set: bool,
};

/// Well-known boot parameters
pub const BOOTPARAM_ROOT: [5]u8 = .{ 'r', 'o', 'o', 't', '=' };
pub const BOOTPARAM_INIT: [5]u8 = .{ 'i', 'n', 'i', 't', '=' };
pub const BOOTPARAM_CONSOLE: [8]u8 = .{ 'c', 'o', 'n', 's', 'o', 'l', 'e', '=' };
pub const BOOTPARAM_LOGLEVEL: [9]u8 = .{ 'l', 'o', 'g', 'l', 'e', 'v', 'e', 'l', '=' };
pub const BOOTPARAM_NOKASLR: [7]u8 = .{ 'n', 'o', 'k', 'a', 's', 'l', 'r' };
pub const BOOTPARAM_NOAPIC: [6]u8 = .{ 'n', 'o', 'a', 'p', 'i', 'c' };
pub const BOOTPARAM_NOSMP: [5]u8 = .{ 'n', 'o', 's', 'm', 'p' };
pub const BOOTPARAM_MAXCPUS: [8]u8 = .{ 'm', 'a', 'x', 'c', 'p', 'u', 's', '=' };

/// Command line parser state
pub const CmdlineParser = struct {
    cmdline: [4096]u8,
    cmdline_len: u32,
    nr_params: u32,
    // Parsed params
    root_dev: [64]u8,
    root_dev_len: u8,
    init_path: [256]u8,
    init_path_len: u16,
    console_name: [32]u8,
    console_len: u8,
    loglevel: u8,
    // Flags
    ro: bool,
    rw: bool,
    nokaslr: bool,
    noapic: bool,
    nosmp: bool,
    nohz: bool,
    quiet: bool,
    debug: bool,
    maxcpus: u32,
    // Memory
    mem_limit: u64,      // mem= parameter
    memmap_entries: u32,
};

// ============================================================================
// Initrd / Initramfs
// ============================================================================

/// Initrd type
pub const InitrdType = enum(u8) {
    none = 0,
    initrd = 1,          // Traditional initrd (ext2 image)
    initramfs = 2,       // CPIO archive
    initramfs_compressed = 3,
};

/// Initrd info
pub const InitrdInfo = struct {
    initrd_type: InitrdType,
    phys_addr: u64,
    size: u64,
    // Compression
    compression: InitrdCompression,
    uncompressed_size: u64,
};

/// Initrd compression
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

/// CPIO header (newc format)
pub const CpioNewcHeader = struct {
    magic: [6]u8,        // "070701"
    ino: [8]u8,
    mode: [8]u8,
    uid: [8]u8,
    gid: [8]u8,
    nlink: [8]u8,
    mtime: [8]u8,
    filesize: [8]u8,
    devmajor: [8]u8,
    devminor: [8]u8,
    rdevmajor: [8]u8,
    rdevminor: [8]u8,
    namesize: [8]u8,
    check: [8]u8,
};

// ============================================================================
// SMBIOS / DMI
// ============================================================================

/// SMBIOS entry point type
pub const SmbiosEntryType = enum(u8) {
    smbios21 = 0,     // 32-bit entry point
    smbios30 = 1,     // 64-bit entry point
};

/// SMBIOS structure type
pub const SmbiosStructType = enum(u8) {
    bios_info = 0,
    system_info = 1,
    baseboard_info = 2,
    chassis_info = 3,
    processor_info = 4,
    memory_controller = 5,
    memory_module = 6,
    cache_info = 7,
    port_connector = 8,
    system_slot = 9,
    onboard_device = 10,
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
    electrical_current = 29,
    oob_remote_access = 30,
    boot_integrity = 31,
    system_boot_info = 32,
    memory_error_64 = 33,
    management_device = 34,
    management_device_component = 35,
    management_device_threshold = 36,
    memory_channel = 37,
    ipmi_device = 38,
    system_power_supply = 39,
    additional_info = 40,
    onboard_devices_extended = 41,
    management_controller_host = 42,
    tpm_device = 43,
    processor_additional = 44,
    firmware_inventory = 45,
    string_property = 46,
    inactive = 126,
    end_of_table = 127,
};

/// SMBIOS header
pub const SmbiosHeader = struct {
    struct_type: SmbiosStructType,
    length: u8,
    handle: u16,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const BootInfraSubsystem = struct {
    // Early console
    early_console_type: EarlyConsoleType,
    early_console_active: bool,
    // EFI
    efi_available: bool,
    efi_runtime_available: bool,
    efi_secure_boot: bool,
    efi_memmap_entries: u32,
    efi_systab_phys: u64,
    // Boot params
    cmdline_parser: CmdlineParser,
    // Initrd
    initrd_info: InitrdInfo,
    // SMBIOS
    smbios_entry_type: SmbiosEntryType,
    smbios_version_major: u8,
    smbios_version_minor: u8,
    smbios_table_phys: u64,
    smbios_table_len: u32,
    // Zxyphor
    zxy_fast_boot: bool,
    initialized: bool,

    pub fn init() BootInfraSubsystem {
        return BootInfraSubsystem{
            .early_console_type = .none,
            .early_console_active = false,
            .efi_available = false,
            .efi_runtime_available = false,
            .efi_secure_boot = false,
            .efi_memmap_entries = 0,
            .efi_systab_phys = 0,
            .cmdline_parser = std.mem.zeroes(CmdlineParser),
            .initrd_info = std.mem.zeroes(InitrdInfo),
            .smbios_entry_type = .smbios30,
            .smbios_version_major = 0,
            .smbios_version_minor = 0,
            .smbios_table_phys = 0,
            .smbios_table_len = 0,
            .zxy_fast_boot = true,
            .initialized = false,
        };
    }
};
