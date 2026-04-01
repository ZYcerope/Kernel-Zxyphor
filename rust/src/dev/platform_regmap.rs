// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - Regmap/DT Advanced, Platform Device, Resource Management,
// Device Properties, IO Resource, Firmware Description Tables
// More advanced than Linux 2026 device model

/// Device property type (from firmware: DT, ACPI, swnode)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwPropertyType {
    Unknown = 0,
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    String = 5,
    StringArray = 6,
    Reference = 7,
    // fwnode types
    DeviceTree = 10,
    Acpi = 11,
    Swnode = 12,
    Pci = 13,
    Irq = 14,
}

/// IO resource type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoResourceType {
    Mem = 0x00000200,
    Io = 0x00000100,
    Irq = 0x00000400,
    Dma = 0x00000800,
    Bus = 0x00001000,
}

/// IO resource flags
pub const IORESOURCE_BITS: u64 = 0x000000FF;
pub const IORESOURCE_TYPE_BITS: u64 = 0x00001F00;
pub const IORESOURCE_IO: u64 = 0x00000100;
pub const IORESOURCE_MEM: u64 = 0x00000200;
pub const IORESOURCE_REG: u64 = 0x00000300;
pub const IORESOURCE_IRQ: u64 = 0x00000400;
pub const IORESOURCE_DMA: u64 = 0x00000800;
pub const IORESOURCE_BUS: u64 = 0x00001000;
pub const IORESOURCE_PREFETCH: u64 = 0x00002000;
pub const IORESOURCE_READONLY: u64 = 0x00004000;
pub const IORESOURCE_CACHEABLE: u64 = 0x00008000;
pub const IORESOURCE_RANGELENGTH: u64 = 0x00010000;
pub const IORESOURCE_SHADOWABLE: u64 = 0x00020000;
pub const IORESOURCE_SIZEALIGN: u64 = 0x00040000;
pub const IORESOURCE_STARTALIGN: u64 = 0x00080000;
pub const IORESOURCE_MEM_64: u64 = 0x00100000;
pub const IORESOURCE_WINDOW: u64 = 0x00200000;
pub const IORESOURCE_MUXED: u64 = 0x00400000;
pub const IORESOURCE_EXT_TYPE_BITS: u64 = 0x01000000;
pub const IORESOURCE_SYSRAM: u64 = 0x01000000;
pub const IORESOURCE_SYSRAM_DRIVER_MANAGED: u64 = 0x02000000;
pub const IORESOURCE_SYSRAM_MERGEABLE: u64 = 0x04000000;
pub const IORESOURCE_EXCLUSIVE: u64 = 0x08000000;
pub const IORESOURCE_DISABLED: u64 = 0x10000000;
pub const IORESOURCE_UNSET: u64 = 0x20000000;
pub const IORESOURCE_AUTO: u64 = 0x40000000;
pub const IORESOURCE_BUSY: u64 = 0x80000000;

/// IO resource entry
#[derive(Debug, Clone)]
pub struct IoResource {
    pub start: u64,
    pub end: u64,
    pub name: [u8; 64],
    pub flags: u64,
}

impl IoResource {
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }
    pub fn is_mem(&self) -> bool {
        (self.flags & IORESOURCE_MEM) != 0
    }
    pub fn is_io(&self) -> bool {
        (self.flags & IORESOURCE_IO) != 0
    }
}

/// Platform device info
#[derive(Debug, Clone)]
pub struct PlatformDeviceInfo {
    pub name: [u8; 64],
    pub id: i32,
    pub id_auto: bool,
    pub nr_resources: u32,
    // Properties
    pub nr_properties: u32,
    // Driver
    pub driver_name: [u8; 64],
    pub driver_bound: bool,
    // DMA
    pub dma_mask: u64,
    pub coherent_dma_mask: u64,
    // Power
    pub pm_state: DevicePmState,
    pub runtime_pm_enabled: bool,
    // NUMA
    pub numa_node: i32,
}

/// Device PM state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePmState {
    Active = 0,
    Suspended = 1,
    RuntimeSuspended = 2,
    Frozen = 3,
    Off = 4,
}

// ============================================================================
// Regmap Advanced
// ============================================================================

/// Regmap bus type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegmapBus {
    Mmio = 0,
    I2c = 1,
    Spi = 2,
    Spmi = 3,
    Ac97 = 4,
    Slimbus = 5,
    Sdw = 6,          // SoundWire
    Sccb = 7,
}

/// Regmap cache type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegmapCache {
    None = 0,
    Rbtree = 1,
    Flat = 2,
    Maple = 3,
}

/// Regmap configuration
#[derive(Debug, Clone)]
pub struct RegmapConfig {
    pub name: [u8; 32],
    pub bus: RegmapBus,
    pub reg_bits: u8,
    pub reg_stride: u8,
    pub val_bits: u8,
    pub max_register: u32,
    pub cache_type: RegmapCache,
    // Endianness
    pub reg_big_endian: bool,
    pub val_big_endian: bool,
    // Volatile / precious
    pub nr_volatile_ranges: u16,
    pub nr_precious_ranges: u16,
    pub nr_rd_only_ranges: u16,
    pub nr_wr_only_ranges: u16,
    // Paging
    pub paging: bool,
    pub page_sel_reg: u32,
    pub page_sel_mask: u32,
    // Features
    pub can_sleep: bool,
    pub can_multi_write: bool,
    // IRQ chip
    pub has_irq_chip: bool,
    pub nr_irqs: u16,
    // Stats
    pub total_reads: u64,
    pub total_writes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_syncs: u64,
    pub cache_drops: u64,
    pub cache_dirty: bool,
}

// ============================================================================
// DeviceTree Advanced
// ============================================================================

/// DT property value types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtPropType {
    Empty = 0,
    U32 = 1,
    U64 = 2,
    String = 3,
    StringList = 4,
    Phandle = 5,
    PhandleArray = 6,
    ByteArray = 7,
}

/// DT node status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtStatus {
    Okay = 0,
    Disabled = 1,
    Reserved = 2,
    Fail = 3,
}

/// DT overlay info
#[derive(Debug, Clone)]
pub struct DtOverlayInfo {
    pub id: u32,
    pub name: [u8; 64],
    pub target_path: [u8; 256],
    pub target_phandle: u32,
    pub nr_fragments: u32,
    pub applied: bool,
    // Stats
    pub nodes_added: u32,
    pub nodes_modified: u32,
    pub properties_set: u32,
    pub properties_removed: u32,
}

/// DT IRQ mapping
#[derive(Debug, Clone)]
pub struct DtIrqInfo {
    pub irq_num: u32,
    pub trigger_type: IrqTriggerType,
    pub is_shared: bool,
    pub parent_phandle: u32,
}

/// IRQ trigger type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqTriggerType {
    None = 0,
    RisingEdge = 1,
    FallingEdge = 2,
    BothEdges = 3,
    HighLevel = 4,
    LowLevel = 8,
}

// ============================================================================
// Software Node (swnode)
// ============================================================================

/// Software node for device properties
#[derive(Debug, Clone)]
pub struct SwNodeInfo {
    pub name: [u8; 64],
    pub nr_properties: u32,
    pub nr_children: u32,
    pub parent_name: [u8; 64],
}

// ============================================================================
// Clock Framework
// ============================================================================

/// Clock type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClkType {
    Fixed = 0,
    Gate = 1,
    Divider = 2,
    Mux = 3,
    FixedFactor = 4,
    Composite = 5,
    Pll = 6,
    Fractional = 7,
}

/// Clock flags
pub const CLK_SET_RATE_GATE: u32 = 1 << 0;
pub const CLK_SET_PARENT_GATE: u32 = 1 << 1;
pub const CLK_SET_RATE_PARENT: u32 = 1 << 2;
pub const CLK_IGNORE_UNUSED: u32 = 1 << 3;
pub const CLK_GET_RATE_NOCACHE: u32 = 1 << 6;
pub const CLK_SET_RATE_NO_REPARENT: u32 = 1 << 7;
pub const CLK_GET_ACCURACY_NOCACHE: u32 = 1 << 8;
pub const CLK_IS_CRITICAL: u32 = 1 << 11;
pub const CLK_OPS_PARENT_ENABLE: u32 = 1 << 12;
pub const CLK_DUTY_CYCLE_PARENT: u32 = 1 << 13;

/// Clock info
#[derive(Debug, Clone)]
pub struct ClkInfo {
    pub name: [u8; 64],
    pub clk_type: ClkType,
    pub flags: u32,
    pub rate: u64,              // Hz
    pub accuracy: u64,          // ppb
    pub phase: i16,             // degrees
    pub duty_num: u32,
    pub duty_den: u32,
    pub enable_count: u32,
    pub prepare_count: u32,
    pub protect_count: u32,
    pub nr_parents: u8,
    pub parent_index: u8,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Device model advanced subsystem
#[derive(Debug, Clone)]
pub struct DevModelSubsystem {
    // Platform devices
    pub nr_platform_devices: u32,
    pub nr_platform_drivers: u32,
    // IO Resources
    pub nr_iomem_resources: u32,
    pub nr_ioport_resources: u32,
    // Regmap
    pub nr_regmap_instances: u32,
    pub total_regmap_reads: u64,
    pub total_regmap_writes: u64,
    // DT
    pub dt_total_nodes: u32,
    pub dt_total_properties: u32,
    pub nr_dt_overlays: u32,
    // Software nodes
    pub nr_software_nodes: u32,
    // Clock framework
    pub nr_clocks: u32,
    pub nr_clock_providers: u32,
    // Zxyphor
    pub zxy_hot_plug_aware: bool,
    pub initialized: bool,
}
