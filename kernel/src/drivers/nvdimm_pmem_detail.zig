// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - NVDIMM / Persistent Memory Detail
// Complete: NVDIMM types, NFIT (ACPI), device-DAX, pmem namespace,
// block translation table (BTT), PFN device, label area,
// NVMe-oF namespaces, LIBNVDIMM, nvdimm-bus, security

const std = @import("std");

// ============================================================================
// NVDIMM Types
// ============================================================================

pub const NvdimmType = enum(u8) {
    Pmem = 0,          // Persistent Memory
    Blk = 1,           // Block mode
    PmemBlk = 2,       // Combined
    Byte = 3,          // Byte-addressable non-volatile
    DevDax = 4,        // Device DAX
    SysDax = 5,        // System RAM DAX
};

pub const NvdimmFamily = enum(u8) {
    Intel = 0,
    Hpe = 1,
    Msft = 2,
    Hyperv = 3,
    Papr = 4,
    Arm = 5,
    Virtio = 6,
};

pub const NvdimmInterfaceType = enum(u8) {
    ByteAddressable = 0,
    BlockAddressable = 1,
    ByteBlockCombined = 2,
    VendorSpecific = 3,
};

// ============================================================================
// NFIT (NVDIMM Firmware Interface Table) - ACPI 6.x
// ============================================================================

pub const NfitTableType = enum(u16) {
    SystemPhysicalAddressRange = 0,
    NvdimmRegionMapping = 1,
    Interleave = 2,
    SmbiosManagementInfo = 3,
    NvdimmControlRegion = 4,
    NvdimmBlockDataWindow = 5,
    FlushHintAddress = 6,
    PlatformCapabilities = 7,
};

pub const NfitSpaRange = struct {
    type_field: u16,
    length: u16,
    spa_range_index: u16,
    flags: NfitSpaFlags,
    reserved: u32,
    proximity_domain: u32,
    range_guid: [16]u8,
    spa_base: u64,
    spa_length: u64,
    mem_attr: u64,
};

pub const NfitSpaFlags = packed struct(u16) {
    add_online_only: bool,
    proximity_domain_valid: bool,
    location_cookie_valid: bool,
    _reserved: u13,
};

pub const NfitMemoryMapping = struct {
    type_field: u16,
    length: u16,
    nfit_handle: u32,
    physical_id: u16,
    region_id: u16,
    spa_range_index: u16,
    control_region_index: u16,
    region_size: u64,
    region_offset: u64,
    address: u64,
    interleave_index: u16,
    interleave_ways: u16,
    state_flags: NfitMappingFlags,
    reserved: u16,
};

pub const NfitMappingFlags = packed struct(u16) {
    save_fail: bool,
    restore_fail: bool,
    flush_fail: bool,
    not_armed: bool,
    health_observed: bool,
    health_enabled: bool,
    map_failed: bool,
    _reserved: u9,
};

pub const NfitInterleave = struct {
    type_field: u16,
    length: u16,
    interleave_index: u16,
    reserved: u16,
    nr_lines: u32,
    line_size: u32,
    lines: [256]u32,   // Line offsets
};

pub const NfitControlRegion = struct {
    type_field: u16,
    length: u16,
    control_region_index: u16,
    vendor_id: u16,
    device_id: u16,
    revision_id: u16,
    subsystem_vendor_id: u16,
    subsystem_device_id: u16,
    subsystem_revision_id: u16,
    valid_fields: u8,
    manufacturing_location: u8,
    manufacturing_date: u16,
    reserved: [2]u8,
    serial_number: u32,
    region_format_interface_code: u16,
    num_block_control_windows: u16,
    size_block_control_window: u64,
    command_register_offset: u64,
    command_register_size: u64,
    status_register_offset: u64,
    status_register_size: u64,
    nfit_device_handle: u16,
    reserved2: [6]u8,
};

pub const NfitFlushHint = struct {
    type_field: u16,
    length: u16,
    nfit_handle: u32,
    nr_flush: u16,
    reserved: [6]u8,
    hint_addresses: [256]u64,
};

pub const NfitPlatformCap = struct {
    type_field: u16,
    length: u16,
    highest_valid_cap: u8,
    reserved: [3]u8,
    capabilities: NfitCapFlags,
    reserved2: u32,
};

pub const NfitCapFlags = packed struct(u32) {
    cpu_cache_flush: bool,
    mem_ctrl_flush: bool,
    mem_mirroring: bool,
    _reserved: u29,
};

// ============================================================================
// Namespace
// ============================================================================

pub const NdNamespaceType = enum(u8) {
    IoNamespace = 0,     // Block I/O namespace
    PmemNamespace = 1,   // Persistent memory namespace
    BlkNamespace = 2,    // Block-mode namespace
    DaxNamespace = 3,    // Device-DAX namespace
};

pub const NdNamespace = struct {
    ns_type: NdNamespaceType,
    uuid: [16]u8,
    alt_name: [64]u8,
    flags: NdNsFlags,
    num_resources: u32,
    resource: [8]NdResource,
    size: u64,
    force_raw: bool,
    claim: ?*anyopaque,
    claim_class: NdClaimClass,
    dev_name: [32]u8,
    locked: bool,
};

pub const NdNsFlags = packed struct(u32) {
    btt: bool,
    pfn: bool,
    dax: bool,
    _reserved: u29,
};

pub const NdResource = struct {
    start: u64,
    end: u64,
    flags: u64,
};

pub const NdClaimClass = enum(u8) {
    None = 0,
    Btt = 1,
    Btt2 = 2,
    Pfn = 3,
    Dax = 4,
};

// ============================================================================
// BTT (Block Translation Table)
// ============================================================================

pub const BttSuperblock = struct {
    signature: [16]u8,    // "BTT_ARENA_INFO\0"
    uuid: [16]u8,
    parent_uuid: [16]u8,
    flags: BttFlags,
    version_major: u16,
    version_minor: u16,
    external_lbasize: u32,
    external_nlba: u32,
    internal_lbasize: u32,
    internal_nlba: u32,
    nfree: u32,
    infosize: u32,
    nextoff: u64,
    dataoff: u64,
    mapoff: u64,
    flogoff: u64,
    infooff: u64,
    unused: [3968]u8,
    checksum: u64,
};

pub const BttFlags = packed struct(u32) {
    error: bool,
    zero: bool,
    _reserved: u30,
};

pub const BttMapEntry = packed struct(u32) {
    lba: u30,
    zero: bool,
    error: bool,
};

pub const BttFlogEntry = struct {
    lba: u32,
    old_map: u32,
    new_map: u32,
    seq: u32,
};

pub const BttArena = struct {
    external_nlba: u32,
    internal_nlba: u32,
    nfree: u32,
    external_lbasize: u32,
    internal_lbasize: u32,
    dataoff: u64,
    mapoff: u64,
    flogoff: u64,
    infooff: u64,
    log_index: [2]u32,
    freelist: [256]BttFreelistEntry,
};

pub const BttFreelistEntry = struct {
    block: u32,
    sub: u32,
    seq: u32,
    has_err: bool,
};

// ============================================================================
// PFN Device (Page Frame Number)
// ============================================================================

pub const PfnSuperblock = struct {
    signature: [16]u8,   // "NVDIMM_PFN_INFO\0"
    uuid: [16]u8,
    parent_uuid: [16]u8,
    flags: u32,
    version_major: u16,
    version_minor: u16,
    dataoff: u64,
    npfns: u64,
    mode: PfnMode,
    align: u32,
    page_size: u32,
    page_struct_size: u32,
    padding: [3976]u8,
    checksum: u64,
};

pub const PfnMode = enum(u32) {
    None = 0,
    Ram = 1,
    Pmem = 2,
};

// ============================================================================
// Device-DAX
// ============================================================================

pub const DevDaxType = enum(u8) {
    Pmem = 0,
    Hmem = 1,      // Heterogeneous memory
    Kmem = 2,      // System RAM (onlined)
};

pub const DevDaxDevice = struct {
    dev_type: DevDaxType,
    id: i32,
    region: ?*DevDaxRegion,
    align: u64,
    target_node: i32,
    nr_range: u32,
    ranges: [16]DevDaxRange,
    pgmap: ?*anyopaque,
    seed: bool,
};

pub const DevDaxRegion = struct {
    id: i32,
    target_node: i32,
    align: u64,
    res: NdResource,
    seed: ?*DevDaxDevice,
};

pub const DevDaxRange = struct {
    pgoff: u64,
    range_start: u64,
    range_end: u64,
};

// ============================================================================
// NVDIMM Security
// ============================================================================

pub const NvdimmSecurityState = enum(u8) {
    Disabled = 0,
    Unlocked = 1,
    Locked = 2,
    Frozen = 3,
    Overwrite = 4,
};

pub const NvdimmSecurityOps = struct {
    get_flags: ?*const fn (dev: *anyopaque) callconv(.C) NvdimmSecurityState,
    freeze: ?*const fn (dev: *anyopaque) callconv(.C) i32,
    change_key: ?*const fn (dev: *anyopaque, old_key: [*]const u8, new_key: [*]const u8, key_len: u32) callconv(.C) i32,
    unlock: ?*const fn (dev: *anyopaque, key: [*]const u8, key_len: u32) callconv(.C) i32,
    disable: ?*const fn (dev: *anyopaque, key: [*]const u8, key_len: u32) callconv(.C) i32,
    erase: ?*const fn (dev: *anyopaque, key: [*]const u8, key_len: u32) callconv(.C) i32,
    overwrite: ?*const fn (dev: *anyopaque, key: [*]const u8, key_len: u32) callconv(.C) i32,
    query_overwrite: ?*const fn (dev: *anyopaque) callconv(.C) i32,
};

pub const NvdimmKey = struct {
    data: [256]u8,
    len: u32,
    hash: [32]u8,
};

// ============================================================================
// NVDIMM Bus
// ============================================================================

pub const NvdimmBus = struct {
    provider: [64]u8,
    nr_dimms: u32,
    nr_regions: u32,
    nr_namespaces: u32,
    nfit_flags: u32,
    firmware_status: u32,
    dimms: [64]?*NvdimmDevice,
    cmd_mask: u64,
};

pub const NvdimmDevice = struct {
    nfit_handle: u32,
    phys_id: u16,
    vendor_id: u16,
    device_id: u16,
    revision_id: u16,
    subsystem_vendor_id: u16,
    subsystem_device_id: u16,
    serial_number: u32,
    manufacturing_date: u16,
    manufacturing_location: u8,
    format_interface_codes: [4]u16,
    nr_formats: u8,
    dirty_shutdown_count: u64,
    flags: NvdimmDeviceFlags,
    sec_state: NvdimmSecurityState,
    cmd_mask: u64,
    family: NvdimmFamily,
    firmware_version: [32]u8,
    label_size: u32,
    max_label: u32,
    ns_labels: [128]?*NdNamespaceLabel,
};

pub const NvdimmDeviceFlags = packed struct(u32) {
    update: bool,
    not_armed: bool,
    save_fail: bool,
    restore_fail: bool,
    flush_fail: bool,
    smart_health: bool,
    smart_event: bool,
    locked: bool,
    aliasing: bool,
    _reserved: u23,
};

// ============================================================================
// Label Area
// ============================================================================

pub const NdNamespaceLabel = struct {
    uuid: [16]u8,
    name: [64]u8,
    flags: NdLabelFlags,
    nlabel: u16,
    position: u16,
    isetcookie: u64,
    lbasize: u64,
    dpa: u64,
    rawsize: u64,
    slot: u32,
    align: u32,
    type_guid: [16]u8,
    abstraction_guid: [16]u8,
    checksum: u64,
};

pub const NdLabelFlags = packed struct(u32) {
    rolabel: bool,
    local: bool,
    reserved_1: bool,
    updating: bool,
    _reserved: u28,
};

pub const NdLabelIndex = struct {
    sig: [16]u8,       // "NAMESPACE_INDEX\0"
    flags: u32,
    seq: u32,
    myoff: u64,
    mysize: u64,
    otheroff: u64,
    labeloff: u64,
    nslot: u32,
    major: u16,
    minor: u16,
    checksum: u64,
    free: [128]u8,     // Free bitmap
};

// ============================================================================
// DSM (Device Specific Method) Commands
// ============================================================================

pub const NdIntelDsmCmd = enum(u32) {
    QueryArsCapabilities = 1,
    StartArs = 2,
    QueryArsStatus = 3,
    ClearError = 4,
    ImplementedDimm = 5,
    SmartThreshold = 6,
    SmartSetThreshold = 7,
    SmartInjection = 8,
    FwActivate = 9,
    FwGetInfo = 10,
    FwStart = 11,
    FwSendData = 12,
    FwFinishQuery = 13,
    FwFinish = 14,
    SmartHealth = 15,
    Lss = 16,
    EffectLog = 17,
};

// ============================================================================
// ARS (Address Range Scrub)
// ============================================================================

pub const ArsState = enum(u8) {
    Idle = 0,
    Started = 1,
    InProgress = 2,
    Complete = 3,
    Error = 4,
};

pub const ArsRecord = struct {
    handle: u32,
    flags: u32,
    err_address: u64,
    length: u64,
};

pub const ArsCap = struct {
    max_ars_out: u32,
    clear_err_unit: u32,
    flags: u32,
    status: u32,
};

pub const ArsStatus = struct {
    status: u32,
    state: ArsState,
    start: u64,
    length: u64,
    restart_flag: u32,
    num_records: u32,
    overflow: bool,
    records: [256]ArsRecord,
};

// ============================================================================
// NVDIMM Health / SMART
// ============================================================================

pub const NvdimmSmartHealth = struct {
    health_status: NvdimmHealthStatus,
    critical_health: NvdimmCriticalHealth,
    unsafe_shutdowns: u32,
    remaining_life: u8,       // Percentage
    temperature: i16,         // Celsius
    media_temperature: i16,
    controller_temperature: i16,
    alarm_temperature: i16,
    alarm_controller_temp: i16,
    spares_remaining: u8,
    alarm_spares: u8,
    vendor_specific_data_size: u32,
    vendor_data: [512]u8,
};

pub const NvdimmHealthStatus = packed struct(u32) {
    normal: bool,
    not_reporting: bool,
    noncritical: bool,
    critical: bool,
    fatal: bool,
    _reserved: u27,
};

pub const NvdimmCriticalHealth = packed struct(u32) {
    persistence_lost: bool,
    data_loss: bool,
    not_functional: bool,
    performance_degraded: bool,
    _reserved: u28,
};

// ============================================================================
// Manager
// ============================================================================

pub const NvdimmManager = struct {
    buses: [8]?*NvdimmBus,
    bus_count: u32,
    total_dimms: u32,
    total_regions: u32,
    total_namespaces: u32,
    total_ars_errors: u64,
    total_bytes_scrubbed: u64,
    initialized: bool,

    pub fn init() NvdimmManager {
        return .{
            .buses = [_]?*NvdimmBus{null} ** 8,
            .bus_count = 0,
            .total_dimms = 0,
            .total_regions = 0,
            .total_namespaces = 0,
            .total_ars_errors = 0,
            .total_bytes_scrubbed = 0,
            .initialized = true,
        };
    }
};
