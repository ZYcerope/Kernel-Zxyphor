// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Comprehensive EFI Runtime Services / ACPI Tables Complete
// EFI Runtime Services, System Table, GPT, Secure Boot, ESRT,
// ACPI MADT/MCFG/HPET/BGRT/DMAR/IVRS/EINJ/BERT/ERST full table definitions

const std = @import("std");

// ============================================================================
// EFI System Table
// ============================================================================

pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249; // "IBI SYST"
pub const EFI_2_100_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 100;

pub const EfiSystemTable = extern struct {
    hdr: EfiTableHeader,
    firmware_vendor: u64,     // CHAR16 *
    firmware_revision: u32,
    _pad: u32,
    con_in_handle: u64,
    con_in: u64,              // EFI_SIMPLE_TEXT_INPUT_PROTOCOL *
    con_out_handle: u64,
    con_out: u64,             // EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *
    stderr_handle: u64,
    stderr_proto: u64,        // EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *
    runtime_services: u64,    // EFI_RUNTIME_SERVICES *
    boot_services: u64,       // EFI_BOOT_SERVICES *
    number_of_table_entries: u64,
    configuration_table: u64, // EFI_CONFIGURATION_TABLE *
};

pub const EfiTableHeader = extern struct {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
};

// ============================================================================
// EFI Runtime Services
// ============================================================================

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
    get_next_high_monotonic_count: u64,
    reset_system: u64,
    update_capsule: u64,
    query_capsule_capabilities: u64,
    query_variable_info: u64,
};

pub const EfiTime = extern struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    _pad1: u8,
    nanosecond: u32,
    timezone: i16,
    daylight: u8,
    _pad2: u8,
};

pub const EfiResetType = enum(u32) {
    Cold = 0,
    Warm = 1,
    Shutdown = 2,
    PlatformSpecific = 3,
};

// ============================================================================
// EFI Memory Map
// ============================================================================

pub const EfiMemoryType = enum(u32) {
    ReservedMemoryType = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    AcpiReclaimMemory = 9,
    AcpiMemoryNvs = 10,
    MemoryMappedIo = 11,
    MemoryMappedIoPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    UnacceptedMemoryType = 15,
    MaxMemoryType = 16,
};

pub const EfiMemoryDescriptor = extern struct {
    memory_type: u32,
    _pad: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
};

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
pub const EFI_MEMORY_ISA_VALID: u64 = 0x4000000000000000;

// ============================================================================
// EFI Variable Attributes
// ============================================================================

pub const EFI_VARIABLE_NON_VOLATILE: u32 = 0x00000001;
pub const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x00000002;
pub const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x00000004;
pub const EFI_VARIABLE_HARDWARE_ERROR_RECORD: u32 = 0x00000008;
pub const EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000010;
pub const EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000020;
pub const EFI_VARIABLE_APPEND_WRITE: u32 = 0x00000040;
pub const EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: u32 = 0x00000080;

// ============================================================================
// Secure Boot
// ============================================================================

pub const EfiSecureBootState = enum(u8) {
    Disabled = 0,
    Enabled = 1,
    SetupMode = 2,
    AuditMode = 3,
    DeployedMode = 4,
};

pub const EfiGuid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

pub const EFI_GLOBAL_VARIABLE_GUID: EfiGuid = .{
    .data1 = 0x8BE4DF61,
    .data2 = 0x93CA,
    .data3 = 0x11D2,
    .data4 = .{ 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C },
};

pub const EFI_IMAGE_SECURITY_DATABASE_GUID: EfiGuid = .{
    .data1 = 0xD719B2CB,
    .data2 = 0x3D3A,
    .data3 = 0x4596,
    .data4 = .{ 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F },
};

// ============================================================================
// GPT (GUID Partition Table)
// ============================================================================

pub const GptHeader = extern struct {
    signature: u64,            // "EFI PART" = 0x5452415020494645
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32,
    my_lba: u64,
    alternate_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: EfiGuid,
    partition_entry_lba: u64,
    number_of_partition_entries: u32,
    size_of_partition_entry: u32,
    partition_entry_array_crc32: u32,
};

pub const GptEntryAttributes = packed struct(u64) {
    required_to_function: bool = false,
    no_block_io_protocol: bool = false,
    legacy_bios_bootable: bool = false,
    _reserved: u45 = 0,
    type_guid_specific: u16 = 0,
};

pub const GptEntry = extern struct {
    partition_type_guid: EfiGuid,
    unique_partition_guid: EfiGuid,
    starting_lba: u64,
    ending_lba: u64,
    attributes: u64,
    partition_name: [72]u8,   // UTF-16LE, 36 chars
};

// Well-known partition type GUIDs
pub const GPT_ENTRY_TYPE_EFI_SYSTEM: EfiGuid = .{
    .data1 = 0xC12A7328, .data2 = 0xF81F, .data3 = 0x11D2,
    .data4 = .{ 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B },
};
pub const GPT_ENTRY_TYPE_LINUX_FS: EfiGuid = .{
    .data1 = 0x0FC63DAF, .data2 = 0x8483, .data3 = 0x4772,
    .data4 = .{ 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4 },
};
pub const GPT_ENTRY_TYPE_LINUX_SWAP: EfiGuid = .{
    .data1 = 0x0657FD6D, .data2 = 0xA4AB, .data3 = 0x43C4,
    .data4 = .{ 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F },
};
pub const GPT_ENTRY_TYPE_LINUX_LVM: EfiGuid = .{
    .data1 = 0xE6D6D379, .data2 = 0xF507, .data3 = 0x44C2,
    .data4 = .{ 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28 },
};

// ============================================================================
// ESRT (EFI System Resource Table)
// ============================================================================

pub const EsrtEntry = extern struct {
    fw_class: EfiGuid,
    fw_type: u32,
    fw_version: u32,
    lowest_supported_fw_version: u32,
    capsule_flags: u32,
    last_attempt_version: u32,
    last_attempt_status: u32,
};

// ============================================================================
// ACPI Common
// ============================================================================

pub const AcpiSdtHeader = extern struct {
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
// ACPI MADT (Multiple APIC Description Table)
// ============================================================================

pub const MadtEntryType = enum(u8) {
    LocalApic = 0,
    IoApic = 1,
    InterruptOverride = 2,
    NmiSource = 3,
    LocalApicNmi = 4,
    LocalApicOverride = 5,
    IoSapic = 6,
    LocalSapic = 7,
    PlatformInterruptSources = 8,
    LocalX2Apic = 9,
    LocalX2ApicNmi = 10,
    GicCpuInterface = 11,
    GicDistributor = 12,
    GicMsiFrame = 13,
    GicRedistributor = 14,
    GicIts = 15,
    MultiprocessorWakeup = 16,
    CorePic = 17,
    LioIntc = 18,
    HtIntc = 19,
    EioIntc = 20,
    MsiIntc = 21,
    BioIntc = 22,
    LpcIntc = 23,
};

pub const MadtLocalApic = extern struct {
    entry_type: u8,
    length: u8,
    acpi_processor_uid: u8,
    apic_id: u8,
    flags: u32,
};

pub const MadtIoApic = extern struct {
    entry_type: u8,
    length: u8,
    io_apic_id: u8,
    reserved: u8,
    io_apic_address: u32,
    global_irq_base: u32,
};

pub const MadtInterruptOverride = extern struct {
    entry_type: u8,
    length: u8,
    bus: u8,
    source: u8,
    global_irq: u32,
    flags: u16,
};

pub const MadtLocalX2Apic = extern struct {
    entry_type: u8,
    length: u8,
    reserved: u16,
    x2apic_id: u32,
    flags: u32,
    acpi_uid: u32,
};

// ============================================================================
// ACPI MCFG (PCI Express Memory Mapped Configuration)
// ============================================================================

pub const McfgEntry = extern struct {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    reserved: u32,
};

// ============================================================================
// ACPI HPET
// ============================================================================

pub const HpetTable = extern struct {
    header: AcpiSdtHeader,
    hardware_rev_id: u8,
    comparator_count: u5,
    counter_size: u1,
    reserved1: u1,
    legacy_replacement: u1,
    pci_vendor_id: u16,
    address: AcpiGenericAddress,
    hpet_number: u8,
    minimum_tick: u16,
    page_protection: u8,
};

pub const AcpiGenericAddress = extern struct {
    space_id: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
};

// ============================================================================
// ACPI DMAR (DMA Remapping / Intel VT-d)
// ============================================================================

pub const DmarHeader = extern struct {
    header: AcpiSdtHeader,
    host_address_width: u8,
    flags: u8,
    reserved: [10]u8,
};

pub const DmarEntryType = enum(u16) {
    Drhd = 0,   // DMA Remapping Hardware Unit Definition
    Rmrr = 1,   // Reserved Memory Region Reporting
    Atsr = 2,   // Root Port ATS Capability Reporting
    Rhsa = 3,   // Remapping Hardware Static Affinity
    Andd = 4,   // ACPI Name-space Device Declaration
    Satc = 5,   // SoC Integrated Address Translation Cache
    Sidp = 6,   // SoC Integrated Device Property
};

pub const DmarDrhd = extern struct {
    entry_type: u16,
    length: u16,
    flags: u8,
    size: u8,
    segment: u16,
    base_address: u64,
};

// ============================================================================
// ACPI IVRS (AMD I/O Virtualization Reporting Structure)
// ============================================================================

pub const IvrsType = enum(u8) {
    IvhdType10 = 0x10,
    IvhdType11 = 0x11,
    IvhdType40 = 0x40,
    IvmdAll = 0x20,
    IvmdSpecified = 0x21,
    IvmdRange = 0x22,
};

// ============================================================================
// ACPI BGRT (Boot Graphics Resource Table)
// ============================================================================

pub const BgrtTable = extern struct {
    header: AcpiSdtHeader,
    version: u16,
    status: u8,
    image_type: u8,
    image_address: u64,
    image_offset_x: u32,
    image_offset_y: u32,
};

// ============================================================================
// ACPI EINJ (Error Injection)
// ============================================================================

pub const EinjAction = enum(u8) {
    BeginInjectionOperation = 0,
    GetTriggerErrorActionTable = 1,
    SetErrorType = 2,
    GetErrorType = 3,
    EndOperation = 4,
    ExecuteOperation = 5,
    CheckBusyStatus = 6,
    GetCommandStatus = 7,
    SetErrorTypeWithAddress = 8,
    GetExecuteOperationTimings = 9,
};

// ============================================================================
// ACPI BERT (Boot Error Record Table)
// ============================================================================

pub const BertTable = extern struct {
    header: AcpiSdtHeader,
    region_length: u32,
    region_address: u64,
};

// ============================================================================
// ACPI ERST (Error Record Serialization Table)
// ============================================================================

pub const ErstAction = enum(u8) {
    BeginWrite = 0,
    BeginRead = 1,
    BeginClear = 2,
    End = 3,
    SetRecordOffset = 4,
    ExecuteOperation = 5,
    CheckBusy = 6,
    GetCommandStatus = 7,
    GetRecordIdentifier = 8,
    SetRecordIdentifier = 9,
    GetRecordCount = 10,
    BeginDummyWrite = 11,
    Reserved = 12,
    GetErrorLogAddressRange = 13,
    GetErrorLogAddressLength = 14,
    GetErrorLogAddressRangeAttributes = 15,
    GetExecuteOperationTimings = 16,
};

// ============================================================================
// ACPI PPTT (Processor Properties Topology Table)
// ============================================================================

pub const PpttType = enum(u8) {
    Processor = 0,
    CacheType = 1,
    Id = 2,
};

pub const PpttProcessor = extern struct {
    entry_type: u8,
    length: u8,
    reserved: u16,
    flags: u32,
    parent: u32,
    acpi_processor_id: u32,
    private_resource_count: u32,
};

pub const PpttCache = extern struct {
    entry_type: u8,
    length: u8,
    reserved: u16,
    flags: u32,
    next_level: u32,
    size: u32,
    sets: u32,
    associativity: u8,
    attributes: u8,
    line_size: u16,
    cache_id: u32,
};

// ============================================================================
// ACPI SRAT (System Resource Affinity Table)
// ============================================================================

pub const SratType = enum(u8) {
    ProcessorLocalApicAffinity = 0,
    MemoryAffinity = 1,
    ProcessorLocalX2ApicAffinity = 2,
    GiccAffinity = 3,
    GicItsAffinity = 4,
    GenericInitiatorAffinity = 5,
    GenericPortAffinity = 6,
};

pub const SratMemoryAffinity = extern struct {
    entry_type: u8,
    length: u8,
    proximity_domain: u32,
    reserved1: u16,
    base_address: u64,
    address_length: u64,
    reserved2: u32,
    flags: u32,
    reserved3: u64,
};

// ============================================================================
// EFI/ACPI Manager
// ============================================================================

pub const EfiAcpiManager = struct {
    efi_runtime_available: bool,
    secure_boot_state: EfiSecureBootState,
    acpi_revision: u8,
    madt_entries: u32,
    mcfg_entries: u32,
    srat_entries: u32,
    pptt_entries: u32,
    dmar_present: bool,
    ivrs_present: bool,
    hpet_present: bool,
    bgrt_present: bool,
    esrt_entries: u32,
    total_efi_variables: u32,
    total_gpt_partitions: u32,
    initialized: bool,

    pub fn init() EfiAcpiManager {
        return .{
            .efi_runtime_available = false,
            .secure_boot_state = .Disabled,
            .acpi_revision = 0,
            .madt_entries = 0,
            .mcfg_entries = 0,
            .srat_entries = 0,
            .pptt_entries = 0,
            .dmar_present = false,
            .ivrs_present = false,
            .hpet_present = false,
            .bgrt_present = false,
            .esrt_entries = 0,
            .total_efi_variables = 0,
            .total_gpt_partitions = 0,
            .initialized = true,
        };
    }
};
