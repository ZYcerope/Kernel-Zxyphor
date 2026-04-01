// Zxyphor Kernel - Device Tree / Open Firmware Internals
// FDT (Flattened Device Tree) parsing, OF (Open Firmware) core,
// device_node, of_platform, irq domain via DT, clock providers,
// pinctrl from DT, regulators from DT, overlays
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// FDT (Flattened Device Tree) Header
// ============================================================================

pub const FDT_MAGIC: u32 = 0xD00DFEED;
pub const FDT_BEGIN_NODE: u32 = 0x00000001;
pub const FDT_END_NODE: u32 = 0x00000002;
pub const FDT_PROP: u32 = 0x00000003;
pub const FDT_NOP: u32 = 0x00000004;
pub const FDT_END: u32 = 0x00000009;
pub const FDT_V17_SIZE: u32 = 40;

pub const FdtHeader = extern struct {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
};

pub const FdtReserveEntry = extern struct {
    address: u64,
    size: u64,
};

pub const FdtProperty = extern struct {
    tag: u32,
    len: u32,
    nameoff: u32,
    // data follows
};

// ============================================================================
// Open Firmware (OF) Device Node
// ============================================================================

pub const DeviceNode = struct {
    name: [64]u8,
    full_name: [256]u8,
    phandle: u32,
    // Type
    node_type: [32]u8,
    // Hierarchy
    parent: ?*DeviceNode,
    child: ?*DeviceNode,
    sibling: ?*DeviceNode,
    // Properties
    properties: ?*OfProperty,
    deadprops: ?*OfProperty,
    // Flags
    flags: DeviceNodeFlags,
    // Data
    data: u64,
    // Unique ID
    unique_id: u64,
    // Kobj
    kobj: u64,
    // Fwnode
    fwnode: u64,
};

pub const DeviceNodeFlags = packed struct(u32) {
    detached: bool = false,
    populated: bool = false,
    populated_bus: bool = false,
    overlay: bool = false,
    overlay_free: bool = false,
    _pad: u27 = 0,
};

pub const OfProperty = struct {
    name: [64]u8,
    length: u32,
    value: u64,     // void * (points to raw DT property data)
    next: ?*OfProperty,
};

// ============================================================================
// Standard DT Properties
// ============================================================================

pub const OfStandardProps = struct {
    // Common
    pub const COMPATIBLE = "compatible";
    pub const MODEL = "model";
    pub const PHANDLE = "phandle";
    pub const STATUS = "status";
    pub const REG = "reg";
    pub const RANGES = "ranges";
    pub const DMA_RANGES = "dma-ranges";
    pub const NAME = "name";
    pub const DEVICE_TYPE = "device_type";
    // Size/address cells
    pub const ADDRESS_CELLS = "#address-cells";
    pub const SIZE_CELLS = "#size-cells";
    // Interrupt
    pub const INTERRUPTS = "interrupts";
    pub const INTERRUPTS_EXTENDED = "interrupts-extended";
    pub const INTERRUPT_PARENT = "interrupt-parent";
    pub const INTERRUPT_CONTROLLER = "interrupt-controller";
    pub const INTERRUPT_CELLS = "#interrupt-cells";
    pub const INTERRUPT_MAP = "interrupt-map";
    pub const INTERRUPT_MAP_MASK = "interrupt-map-mask";
    // Clock
    pub const CLOCKS = "clocks";
    pub const CLOCK_NAMES = "clock-names";
    pub const CLOCK_CELLS = "#clock-cells";
    pub const CLOCK_FREQUENCY = "clock-frequency";
    pub const CLOCK_OUTPUT_NAMES = "clock-output-names";
    pub const ASSIGNED_CLOCKS = "assigned-clocks";
    pub const ASSIGNED_CLOCK_RATES = "assigned-clock-rates";
    pub const ASSIGNED_CLOCK_PARENTS = "assigned-clock-parents";
    // GPIO
    pub const GPIO_CONTROLLER = "gpio-controller";
    pub const GPIO_CELLS = "#gpio-cells";
    pub const GPIOS = "gpios";
    pub const GPIO_RANGES = "gpio-ranges";
    // Pinctrl
    pub const PINCTRL_0 = "pinctrl-0";
    pub const PINCTRL_1 = "pinctrl-1";
    pub const PINCTRL_NAMES = "pinctrl-names";
    pub const PINS = "pins";
    pub const GROUPS = "groups";
    pub const FUNCTION = "function";
    pub const DRIVE_STRENGTH = "drive-strength";
    // Regulator
    pub const REGULATOR_NAME = "regulator-name";
    pub const REGULATOR_MIN_UV = "regulator-min-microvolt";
    pub const REGULATOR_MAX_UV = "regulator-max-microvolt";
    pub const REGULATOR_ALWAYS_ON = "regulator-always-on";
    pub const REGULATOR_BOOT_ON = "regulator-boot-on";
    // DMA
    pub const DMAS = "dmas";
    pub const DMA_NAMES = "dma-names";
    pub const DMA_CELLS = "#dma-cells";
    // Power domain
    pub const POWER_DOMAINS = "power-domains";
    pub const POWER_DOMAIN_CELLS = "#power-domain-cells";
    // Reset
    pub const RESETS = "resets";
    pub const RESET_NAMES = "reset-names";
    pub const RESET_CELLS = "#reset-cells";
    // Thermal
    pub const THERMAL_SENSORS = "thermal-sensors";
    pub const THERMAL_SENSOR_CELLS = "#thermal-sensor-cells";
    // PHY
    pub const PHYS = "phys";
    pub const PHY_NAMES = "phy-names";
    // Misc
    pub const LABEL = "label";
    pub const LINUX_PHANDLE = "linux,phandle";
    pub const MEMORY_REGION = "memory-region";
    pub const MEMORY_REGION_NAMES = "memory-region-names";
    pub const IOMMUS = "iommus";
    pub const IOMMU_CELLS = "#iommu-cells";
};

pub const OfStatusType = enum(u8) {
    okay = 0,
    disabled = 1,
    reserved_ = 2,
    fail = 3,
    fail_sss = 4,  // fail-<vendor specific>
};

// ============================================================================
// OF Match Table
// ============================================================================

pub const OfDeviceId = struct {
    name: [32]u8,
    node_type: [32]u8,
    compatible: [128]u8,
    data: u64,
};

// ============================================================================
// OF IRQ Domain
// ============================================================================

pub const OfIrqDomain = struct {
    // Controller node
    of_node: ?*DeviceNode,
    // Domain
    name: [32]u8,
    ops: ?*const IrqDomainOps,
    // Mapping
    linear_revmap: u64,
    revmap_size: u32,
    revmap_tree: u64,
    // Hierarchy
    parent: ?*OfIrqDomain,
    // Flags
    flags: IrqDomainFlags,
    // Stats
    mapcount: u64,
};

pub const IrqDomainFlags = packed struct(u32) {
    hierarchy: bool = false,
    name_allocated: bool = false,
    is_fwnode: bool = false,
    destroy_gc: bool = false,
    msi: bool = false,
    msi_parent: bool = false,
    msi_device_domain: bool = false,
    noncore: bool = false,
    _pad: u24 = 0,
};

pub const IrqDomainOps = struct {
    match_fn: ?*const fn (?*OfIrqDomain, ?*DeviceNode, u32) bool,
    select: ?*const fn (?*OfIrqDomain, u64, u32) i32,
    map: ?*const fn (?*OfIrqDomain, u32, u32) i32,
    unmap: ?*const fn (?*OfIrqDomain, u32) void,
    xlate: ?*const fn (?*OfIrqDomain, ?*DeviceNode, [*]const u32, u32, *u64, *u32) i32,
    alloc: ?*const fn (?*OfIrqDomain, u32, u32, u64) i32,
    free: ?*const fn (?*OfIrqDomain, u32, u32) void,
    activate: ?*const fn (?*OfIrqDomain, u64, bool) i32,
    deactivate: ?*const fn (?*OfIrqDomain, u64) void,
    translate: ?*const fn (?*OfIrqDomain, u64, *u64, *u32) i32,
};

// ============================================================================
// OF Clock Provider
// ============================================================================

pub const OfClkProvider = struct {
    node: ?*DeviceNode,
    data: u64,
    get: ?*const fn (u64, u64) u64,
};

pub const ClkHwOfEntry = struct {
    hw: u64,
    of_clk_src: ?*const fn (u64, u64) u64,
    data: u64,
    phandle: u32,
    index: u32,
};

// ============================================================================
// OF Platform Bus
// ============================================================================

pub const OfPlatformDevice = struct {
    // OF node
    dev_node: ?*DeviceNode,
    // Platform device
    name: [64]u8,
    id: i32,
    // Resources from DT (reg, interrupt)
    num_resources: u32,
    resources: [32]OfResource,
    // IRQs
    num_irqs: u32,
    irqs: [16]u32,
    // DMA configuration
    dma_mask: u64,
    coherent_dma_mask: u64,
};

pub const OfResource = struct {
    start: u64,
    end_addr: u64,
    flags: u32,
    name: [32]u8,
};

pub const OfResourceFlags = packed struct(u32) {
    mem: bool = false,
    io: bool = false,
    irq: bool = false,
    dma: bool = false,
    bus: bool = false,
    prefetch: bool = false,
    readonly: bool = false,
    sizealign: bool = false,
    startalign: bool = false,
    _pad: u23 = 0,
};

// ============================================================================
// DT Overlays
// ============================================================================

pub const OfOverlay = struct {
    id: u32,
    overlay_tree: ?*DeviceNode,
    // Fragments
    fragments: [64]OfOverlayFragment,
    fragment_count: u32,
    // State
    state: OfOverlayState,
    // Notifier
    notifier: u64,
    // Stats
    apply_count: u64,
    remove_count: u64,
};

pub const OfOverlayFragment = struct {
    overlay: ?*DeviceNode,
    target: ?*DeviceNode,
    target_phandle: u32,
    target_path: [256]u8,
};

pub const OfOverlayState = enum(u8) {
    inactive = 0,
    applying = 1,
    applied = 2,
    removing = 3,
    removed = 4,
    error = 5,
};

// ============================================================================
// DT to Regulator Mapping
// ============================================================================

pub const OfRegulatorMatch = struct {
    name: [32]u8,
    driver_data: u64,
    of_node: ?*DeviceNode,
    init_data: u64,
};

// ============================================================================
// DT to Pinctrl Mapping
// ============================================================================

pub const OfPinctrlMap = struct {
    dev_name: [32]u8,
    name: [32]u8,
    map_type: OfPinctrlMapType,
    ctrl_dev_name: [32]u8,
    // Function
    function: [32]u8,
    group: [32]u8,
    // Config
    configs: u64,
    num_configs: u32,
};

pub const OfPinctrlMapType = enum(u8) {
    dummy = 0,
    mux_group = 1,
    configs_pin = 2,
    configs_group = 3,
};

// ============================================================================
// FDT Parser State
// ============================================================================

pub const FdtParser = struct {
    // Input
    fdt_addr: u64,
    fdt_size: u32,
    // Header (validated)
    header: FdtHeader,
    // State
    struct_ptr: u32,
    strings_ptr: u32,
    // Reserved memory
    reserved_count: u32,
    reserved: [64]FdtReserveEntry,
    // Node count
    total_nodes: u32,
    total_properties: u32,
    // Parsing stats
    depth: u32,
    max_depth: u32,
    // Result
    root: ?*DeviceNode,
    // Error
    error_code: FdtError,
};

pub const FdtError = enum(i8) {
    ok = 0,
    bad_magic = -1,
    bad_version = -2,
    bad_structure = -3,
    truncated = -4,
    bad_state = -5,
    nomem = -6,
    bad_offset = -7,
    bad_path = -8,
    bad_phandle = -9,
    bad_value = -10,
    internal = -11,
    exists = -12,
    nospace = -13,
    not_found = -14,
};

// ============================================================================
// DT Subsystem Manager
// ============================================================================

pub const DeviceTreeManager = struct {
    // FDT info
    fdt_address: u64,
    fdt_size: u32,
    fdt_version: u32,
    // Node counts
    total_nodes: u32,
    enabled_nodes: u32,
    disabled_nodes: u32,
    // Provider counts
    clk_providers: u32,
    irq_domains: u32,
    gpio_controllers: u32,
    pinctrl_devices: u32,
    regulator_devices: u32,
    dma_controllers: u32,
    reset_controllers: u32,
    power_domains: u32,
    iommus: u32,
    // Overlays
    active_overlays: u32,
    total_overlays_applied: u64,
    // Platform devices
    platform_devices_probed: u32,
    // Parsing
    parsing_time_ns: u64,
    // Memory
    reserved_regions: u32,
    reserved_bytes: u64,
    initialized: bool,

    pub fn init() DeviceTreeManager {
        return DeviceTreeManager{
            .fdt_address = 0,
            .fdt_size = 0,
            .fdt_version = 0,
            .total_nodes = 0,
            .enabled_nodes = 0,
            .disabled_nodes = 0,
            .clk_providers = 0,
            .irq_domains = 0,
            .gpio_controllers = 0,
            .pinctrl_devices = 0,
            .regulator_devices = 0,
            .dma_controllers = 0,
            .reset_controllers = 0,
            .power_domains = 0,
            .iommus = 0,
            .active_overlays = 0,
            .total_overlays_applied = 0,
            .platform_devices_probed = 0,
            .parsing_time_ns = 0,
            .reserved_regions = 0,
            .reserved_bytes = 0,
            .initialized = true,
        };
    }
};
