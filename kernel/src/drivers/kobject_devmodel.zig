// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Kobject/Kset/Ktype, Uevent,
// Sysfs Attribute Groups, Device Model Core, Bus/Class/Driver
// More advanced than Linux 2026 device model core

const std = @import("std");

// ============================================================================
// Kobject Core
// ============================================================================

/// Kobject state
pub const KobjState = enum(u8) {
    uninitialized = 0,
    initialized = 1,
    in_sysfs = 2,
    add_pending = 3,
    remove_pending = 4,
    removed = 5,
};

/// Kobject type operations
pub const KobjType = struct {
    name: [64]u8,
    // Default attrs
    nr_default_attrs: u32,
    nr_default_groups: u32,
    // Namespace
    has_namespace: bool,
    ns_type: KobjNsType,
    // Show/Store default
    has_default_show: bool,
    has_default_store: bool,
};

/// Kobject namespace type
pub const KobjNsType = enum(u8) {
    none = 0,
    net = 1,
    // Zxyphor
    zxy_container = 10,
};

/// Kobject descriptor
pub const Kobject = struct {
    name: [256]u8,
    name_len: u16,
    // Hierarchy
    parent_path: [512]u8,
    parent_path_len: u16,
    // Set
    kset_name: [64]u8,
    // Type
    ktype: KobjType,
    // State
    state: KobjState,
    state_initialized: bool,
    state_in_sysfs: bool,
    state_add_uevent_sent: bool,
    state_remove_uevent_sent: bool,
    // Reference count
    refcount: u32,
    // SD (sysfs directory entry)
    sd_inode: u64,
};

/// Kset - collection of kobjects
pub const Kset = struct {
    name: [64]u8,
    // Kobject
    kobj: Kobject,
    // Members
    nr_members: u32,
    // Uevent filter
    has_uevent_filter: bool,
    has_uevent_name: bool,
    has_uevent_envs: bool,
};

// ============================================================================
// Uevent System
// ============================================================================

/// Uevent action
pub const UeventAction = enum(u8) {
    add = 0,
    remove = 1,
    change = 2,
    move_action = 3,
    online = 4,
    offline = 5,
    bind = 6,
    unbind = 7,
};

/// Uevent environment variable
pub const UeventEnv = struct {
    key: [64]u8,
    value: [256]u8,
    key_len: u8,
    value_len: u16,
};

/// Uevent message
pub const UeventMsg = struct {
    action: UeventAction,
    devpath: [512]u8,
    devpath_len: u16,
    subsystem: [64]u8,
    // Standard envvars
    devtype: [32]u8,
    driver: [64]u8,
    modalias: [256]u8,
    major: i32,
    minor: i32,
    seqnum: u64,
    // Custom envvars
    nr_envvars: u8,
};

/// Uevent socket (netlink)
pub const UeventSocket = struct {
    pid: u32,
    multicast_group: u32,
    // Filters
    subsystem_filter: [64]u8,
    devtype_filter: [32]u8,
    // Stats
    total_events: u64,
    total_dropped: u64,
};

// ============================================================================
// Sysfs Attributes
// ============================================================================

/// Sysfs attribute type
pub const SysfsAttrType = enum(u8) {
    regular = 0,    // Regular file
    binary = 1,     // Binary file
    group = 2,      // Attribute group directory
    link = 3,       // Symbolic link
};

/// Sysfs attribute permissions
pub const SysfsAttrMode = packed struct {
    // Owner
    owner_read: bool = false,
    owner_write: bool = false,
    owner_exec: bool = false,
    // Group
    group_read: bool = false,
    group_write: bool = false,
    group_exec: bool = false,
    // Other
    other_read: bool = false,
    other_write: bool = false,
    other_exec: bool = false,
    _padding: u7 = 0,
};

/// Predefined modes
pub const S_IRUGO: u16 = 0o444;
pub const S_IWUSR: u16 = 0o200;
pub const S_IRUSR: u16 = 0o400;
pub const S_IRGRP: u16 = 0o040;
pub const S_IROTH: u16 = 0o004;

/// Sysfs attribute
pub const SysfsAttr = struct {
    name: [64]u8,
    mode: u16,
    attr_type: SysfsAttrType,
    // Binary attributes
    is_binary: bool,
    size: u64,       // For binary attrs, expected size
    // Lock
    lockdep_key: u64,
};

/// Sysfs attribute group
pub const SysfsAttrGroup = struct {
    name: [64]u8,     // Group name (directory name), empty for root
    nr_attrs: u32,
    nr_bin_attrs: u32,
    // Visibility
    has_is_visible: bool,
    has_is_bin_visible: bool,
};

// ============================================================================
// Bus Type
// ============================================================================

/// Bus type
pub const BusType = struct {
    name: [64]u8,
    // Subsystem
    subsys_name: [64]u8,
    // Matching
    has_match: bool,
    has_uevent: bool,
    has_probe: bool,
    has_sync_state: bool,
    has_remove: bool,
    has_shutdown: bool,
    has_online: bool,
    has_offline: bool,
    // PM ops
    has_pm_ops: bool,
    has_runtime_pm: bool,
    // IOMMU
    has_iommu_ops: bool,
    // Device groups
    nr_dev_groups: u32,
    nr_drv_groups: u32,
    nr_bus_groups: u32,
    // Stats
    nr_devices: u32,
    nr_drivers: u32,
    total_probes: u64,
    total_probe_failures: u64,
    total_removes: u64,
    total_binds: u64,
    total_unbinds: u64,
};

/// Device class
pub const DeviceClass = struct {
    name: [64]u8,
    // Attributes
    nr_class_groups: u32,
    nr_dev_groups: u32,
    // Operations
    has_dev_uevent: bool,
    has_devnode: bool,
    has_shutdown: bool,
    has_release: bool,
    has_ns_type: bool,
    // PM
    has_pm_ops: bool,
    // Stats
    nr_devices: u32,
};

/// Device driver
pub const DeviceDriver = struct {
    name: [64]u8,
    bus_name: [64]u8,
    // Module owner
    module_name: [64]u8,
    // Operations
    has_probe: bool,
    has_sync_state: bool,
    has_remove: bool,
    has_shutdown: bool,
    has_suspend: bool,
    has_resume: bool,
    // Groups
    nr_groups: u32,
    // PM
    has_pm_ops: bool,
    // Probe type
    probe_type: ProbeType,
    // Coredump
    has_coredump: bool,
    // Stats
    nr_bound_devices: u32,
    total_probes: u64,
    total_probe_success: u64,
    total_probe_failures: u64,
    total_removes: u64,
};

/// Probe type
pub const ProbeType = enum(u8) {
    default_strategy = 0,
    prefer_async = 1,
    force_synchronous = 2,
};

// ============================================================================
// Device Core
// ============================================================================

/// Device power state
pub const DevicePowerState = enum(u8) {
    d0 = 0,
    d1 = 1,
    d2 = 2,
    d3_hot = 3,
    d3_cold = 4,
};

/// Device link flags
pub const DevLinkFlags = packed struct {
    stateless: bool = false,
    autoremove_consumer: bool = false,
    autoremove_supplier: bool = false,
    pm_runtime: bool = false,
    rpm_active: bool = false,
    dl_managed: bool = false,
    inferred: bool = false,
    cycle: bool = false,
    _padding: u8 = 0,
};

/// Device link state
pub const DevLinkState = enum(u8) {
    not_available = 0,
    available = 1,
    consumer_probe = 2,
    active = 3,
    supplier_unbind = 4,
    dormant = 5,
};

/// Device descriptor
pub const DeviceDescriptor = struct {
    // Identity
    name: [256]u8,
    init_name: [64]u8,
    devtype: [32]u8,
    bus_name: [64]u8,
    class_name: [64]u8,
    driver_name: [64]u8,
    // Device number
    devt_major: u32,
    devt_minor: u32,
    // Hierarchy
    parent_path: [256]u8,
    // Bus ID
    bus_id: u32,
    // NUMA
    numa_node: i32,
    // DMA
    dma_mask: u64,
    coherent_dma_mask: u64,
    bus_dma_limit: u64,
    // Power
    power_state: DevicePowerState,
    can_wakeup: bool,
    should_wakeup: bool,
    runtime_pm_enabled: bool,
    rpm_status: RpmStatus,
    rpm_usage_count: i32,
    rpm_active_time_us: u64,
    rpm_suspended_time_us: u64,
    // Links
    nr_supplier_links: u32,
    nr_consumer_links: u32,
    // IOMMU
    iommu_group: i32,
    // State
    is_registered: bool,
    is_bound: bool,
    dead: bool,
    // Groups
    nr_groups: u32,
    // Firmware
    of_node: bool,   // Has devicetree node
    acpi_node: bool,  // Has ACPI node
    // Stats
    total_probes: u64,
    total_suspends: u64,
    total_resumes: u64,
};

/// Runtime PM status
pub const RpmStatus = enum(u8) {
    active = 0,
    resuming = 1,
    suspended = 2,
    suspending = 3,
};

// ============================================================================
// Deferred Probe
// ============================================================================

/// Deferred probe info
pub const DeferredProbe = struct {
    driver_name: [64]u8,
    device_name: [256]u8,
    reason: [128]u8,
    timestamp_ns: u64,
    retry_count: u32,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Device model subsystem
pub const DevModelSubsystem = struct {
    // Buses
    nr_bus_types: u32,
    nr_registered_buses: u32,
    // Classes
    nr_classes: u32,
    // Drivers
    nr_drivers: u32,
    // Devices
    nr_devices: u32,
    // Kobjects
    nr_kobjects: u64,
    nr_ksets: u32,
    // Uevents
    total_uevents: u64,
    uevent_seqnum: u64,
    // Sysfs
    nr_sysfs_entries: u64,
    nr_sysfs_symlinks: u64,
    // Device links
    nr_device_links: u32,
    // Deferred probes
    nr_deferred: u32,
    total_deferred_retries: u64,
    // Power
    total_pm_transitions: u64,
    total_rpm_suspends: u64,
    total_rpm_resumes: u64,
    // Zxyphor
    zxy_hot_plug_opt: bool,
    zxy_parallel_probe: bool,
    initialized: bool,

    pub fn init() DevModelSubsystem {
        return DevModelSubsystem{
            .nr_bus_types = 0,
            .nr_registered_buses = 0,
            .nr_classes = 0,
            .nr_drivers = 0,
            .nr_devices = 0,
            .nr_kobjects = 0,
            .nr_ksets = 0,
            .total_uevents = 0,
            .uevent_seqnum = 0,
            .nr_sysfs_entries = 0,
            .nr_sysfs_symlinks = 0,
            .nr_device_links = 0,
            .nr_deferred = 0,
            .total_deferred_retries = 0,
            .total_pm_transitions = 0,
            .total_rpm_suspends = 0,
            .total_rpm_resumes = 0,
            .zxy_hot_plug_opt = true,
            .zxy_parallel_probe = true,
            .initialized = false,
        };
    }
};
