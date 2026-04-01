// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Device Model (Rust)
// Kobject, kset, uevent, device hierarchy, bus/driver model, sysfs integration

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Kobject - Kernel Object base
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum KobjType {
    Device,
    Driver,
    Bus,
    Class,
    Module,
    Firmware,
    Block,
    Platform,
    Virtual,
    Subsystem,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum UeventAction {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
}

impl UeventAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            UeventAction::Add => "add",
            UeventAction::Remove => "remove",
            UeventAction::Change => "change",
            UeventAction::Move => "move",
            UeventAction::Online => "online",
            UeventAction::Offline => "offline",
            UeventAction::Bind => "bind",
            UeventAction::Unbind => "unbind",
        }
    }
}

pub struct Kobject {
    pub name: [64; u8],
    pub name_len: u8,
    pub ktype: KobjType,
    pub parent: u32, // kobj ID
    pub kset: u32,
    pub ref_count: AtomicU32,
    pub id: u32,
    pub state_initialized: bool,
    pub state_in_sysfs: bool,
    pub state_add_uevent_sent: bool,
    pub state_remove_uevent_sent: bool,
    pub sd: u32, // sysfs directory entry ID
}

impl Kobject {
    pub fn new(name: &[u8], ktype: KobjType) -> Self {
        let mut kobj = Kobject {
            name: [0; 64],
            name_len: 0,
            ktype,
            parent: 0,
            kset: 0,
            ref_count: AtomicU32::new(1),
            id: 0,
            state_initialized: true,
            state_in_sysfs: false,
            state_add_uevent_sent: false,
            state_remove_uevent_sent: false,
            sd: 0,
        };
        let len = if name.len() > 63 { 63 } else { name.len() };
        kobj.name[..len].copy_from_slice(&name[..len]);
        kobj.name_len = len as u8;
        kobj
    }

    pub fn get(&self) {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn put(&self) -> bool {
        self.ref_count.fetch_sub(1, Ordering::Release) == 1
    }
}

// ============================================================================
// Device Model
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum DeviceState {
    NotInitialized,
    Initialized,
    Registered,
    Bound,
    Suspended,
    Removed,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PowerState {
    Active,    // D0
    Standby,   // D1
    Suspend,   // D2
    Off,       // D3
    Unknown,
}

pub struct Device {
    pub kobj: Kobject,
    pub bus_id: [32; u8],
    pub bus_id_len: u8,
    pub bus_type: u16,
    pub driver_id: u32,
    pub class_id: u32,
    pub parent_device: u32,
    pub state: DeviceState,
    pub power_state: PowerState,
    // Device properties
    pub vendor_id: u32,
    pub device_id: u32,
    pub subsystem_vendor: u32,
    pub subsystem_device: u32,
    pub device_class: u32,
    pub revision: u8,
    pub irq: u32,
    pub numa_node: i8,
    // DMA
    pub dma_mask: u64,
    pub coherent_dma_mask: u64,
    pub dma_ops: u32,  // DMA operations table ID
    pub iommu_group: u16,
    // Power management
    pub can_wakeup: bool,
    pub wakeup_enabled: bool,
    pub pm_usage_count: AtomicU32,
    pub runtime_auto_pm: bool,
    pub runtime_suspended: AtomicBool,
    pub disable_depth: AtomicU32,
    pub power_disable_depth: AtomicU32,
    // Links
    pub num_children: u32,
    pub num_links: u32,
    // Device type info
    pub of_node: u32,       // Device tree node
    pub acpi_handle: u64,   // ACPI handle
    pub fwnode: u32,        // Firmware node
    // Resources
    pub num_resources: u8,
    pub resources: [8; DeviceResource],
}

#[derive(Clone, Copy)]
pub struct DeviceResource {
    pub start: u64,
    pub end: u64,
    pub name: [32; u8],
    pub name_len: u8,
    pub flags: u32,
}

pub const IORESOURCE_IO: u32 = 0x00000100;
pub const IORESOURCE_MEM: u32 = 0x00000200;
pub const IORESOURCE_REG: u32 = 0x00000300;
pub const IORESOURCE_IRQ: u32 = 0x00000400;
pub const IORESOURCE_DMA: u32 = 0x00000800;
pub const IORESOURCE_BUS: u32 = 0x00001000;
pub const IORESOURCE_PREFETCH: u32 = 0x00002000;
pub const IORESOURCE_READONLY: u32 = 0x00004000;
pub const IORESOURCE_CACHEABLE: u32 = 0x00008000;
pub const IORESOURCE_SIZEALIGN: u32 = 0x00040000;

impl DeviceResource {
    pub fn new() -> Self {
        DeviceResource {
            start: 0,
            end: 0,
            name: [0; 32],
            name_len: 0,
            flags: 0,
        }
    }

    pub fn size(&self) -> u64 {
        if self.end >= self.start {
            self.end - self.start + 1
        } else {
            0
        }
    }
}

impl Device {
    pub fn new(name: &[u8]) -> Self {
        Device {
            kobj: Kobject::new(name, KobjType::Device),
            bus_id: [0; 32],
            bus_id_len: 0,
            bus_type: 0,
            driver_id: 0,
            class_id: 0,
            parent_device: 0,
            state: DeviceState::NotInitialized,
            power_state: PowerState::Unknown,
            vendor_id: 0,
            device_id: 0,
            subsystem_vendor: 0,
            subsystem_device: 0,
            device_class: 0,
            revision: 0,
            irq: 0,
            numa_node: -1,
            dma_mask: 0xFFFFFFFF,
            coherent_dma_mask: 0xFFFFFFFF,
            dma_ops: 0,
            iommu_group: 0,
            can_wakeup: false,
            wakeup_enabled: false,
            pm_usage_count: AtomicU32::new(0),
            runtime_auto_pm: false,
            runtime_suspended: AtomicBool::new(false),
            disable_depth: AtomicU32::new(0),
            power_disable_depth: AtomicU32::new(0),
            num_children: 0,
            num_links: 0,
            of_node: 0,
            acpi_handle: 0,
            fwnode: 0,
            num_resources: 0,
            resources: [DeviceResource::new(); 8],
        }
    }
}

// ============================================================================
// Bus Type
// ============================================================================

pub const BUS_PCI: u16 = 1;
pub const BUS_USB: u16 = 2;
pub const BUS_PLATFORM: u16 = 3;
pub const BUS_I2C: u16 = 4;
pub const BUS_SPI: u16 = 5;
pub const BUS_VIRTIO: u16 = 6;
pub const BUS_AMBA: u16 = 7;
pub const BUS_SCSI: u16 = 8;
pub const BUS_NVME: u16 = 9;
pub const BUS_THUNDERBOLT: u16 = 10;
pub const BUS_CXL: u16 = 11;

pub struct BusType {
    pub name: [32; u8],
    pub name_len: u8,
    pub bus_id: u16,
    pub kobj: Kobject,
    pub num_devices: AtomicU32,
    pub num_drivers: AtomicU32,
    // Attribute groups
    pub dev_attrs: u32,
    pub drv_attrs: u32,
    pub bus_attrs: u32,
    // PM
    pub pm_ops: u32,
    // IOMMU ops
    pub iommu_ops: u32,
}

impl BusType {
    pub fn new(name: &[u8], bus_id: u16) -> Self {
        let mut bus = BusType {
            name: [0; 32],
            name_len: 0,
            bus_id,
            kobj: Kobject::new(name, KobjType::Bus),
            num_devices: AtomicU32::new(0),
            num_drivers: AtomicU32::new(0),
            dev_attrs: 0,
            drv_attrs: 0,
            bus_attrs: 0,
            pm_ops: 0,
            iommu_ops: 0,
        };
        let len = if name.len() > 31 { 31 } else { name.len() };
        bus.name[..len].copy_from_slice(&name[..len]);
        bus.name_len = len as u8;
        bus
    }
}

// ============================================================================
// Driver Model
// ============================================================================

pub struct DeviceDriver {
    pub name: [64; u8],
    pub name_len: u8,
    pub kobj: Kobject,
    pub bus_type: u16,
    pub owner_module: u32,
    pub suppress_bind_attrs: bool,
    // Device ID table
    pub id_table: [32; DriverDeviceId],
    pub num_ids: u8,
    // PM ops
    pub pm_ops: u32,
    // Stats
    pub probe_count: AtomicU32,
    pub bind_count: AtomicU32,
    pub unbind_count: AtomicU32,
}

#[derive(Clone, Copy)]
pub struct DriverDeviceId {
    pub vendor_id: u32,
    pub device_id: u32,
    pub subvendor: u32,
    pub subdevice: u32,
    pub class_code: u32,
    pub class_mask: u32,
    pub driver_data: u64,
}

impl DriverDeviceId {
    pub const fn new() -> Self {
        DriverDeviceId {
            vendor_id: 0,
            device_id: 0,
            subvendor: 0xFFFFFFFF,
            subdevice: 0xFFFFFFFF,
            class_code: 0,
            class_mask: 0,
            driver_data: 0,
        }
    }

    pub fn matches(&self, dev: &Device) -> bool {
        if self.vendor_id != 0 && self.vendor_id != dev.vendor_id { return false; }
        if self.device_id != 0 && self.device_id != dev.device_id { return false; }
        if self.subvendor != 0xFFFFFFFF && self.subvendor != dev.subsystem_vendor { return false; }
        if self.subdevice != 0xFFFFFFFF && self.subdevice != dev.subsystem_device { return false; }
        if self.class_mask != 0 && (dev.device_class & self.class_mask) != (self.class_code & self.class_mask) {
            return false;
        }
        true
    }
}

impl DeviceDriver {
    pub fn new(name: &[u8], bus_type: u16) -> Self {
        let mut drv = DeviceDriver {
            name: [0; 64],
            name_len: 0,
            kobj: Kobject::new(name, KobjType::Driver),
            bus_type,
            owner_module: 0,
            suppress_bind_attrs: false,
            id_table: [DriverDeviceId::new(); 32],
            num_ids: 0,
            pm_ops: 0,
            probe_count: AtomicU32::new(0),
            bind_count: AtomicU32::new(0),
            unbind_count: AtomicU32::new(0),
        };
        let len = if name.len() > 63 { 63 } else { name.len() };
        drv.name[..len].copy_from_slice(&name[..len]);
        drv.name_len = len as u8;
        drv
    }

    pub fn add_id(&mut self, id: DriverDeviceId) -> bool {
        if self.num_ids >= 32 { return false; }
        self.id_table[self.num_ids as usize] = id;
        self.num_ids += 1;
        true
    }

    pub fn match_device(&self, dev: &Device) -> bool {
        for i in 0..self.num_ids as usize {
            if self.id_table[i].matches(dev) {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Device Class
// ============================================================================

pub struct DeviceClass {
    pub name: [32; u8],
    pub name_len: u8,
    pub kobj: Kobject,
    pub class_id: u32,
    pub dev_attrs: u32,
    pub pm_ops: u32,
    pub num_devices: AtomicU32,
}

// Standard device classes
pub const CLASS_BLOCK: u32 = 1;
pub const CLASS_NET: u32 = 2;
pub const CLASS_INPUT: u32 = 3;
pub const CLASS_TTY: u32 = 4;
pub const CLASS_SOUND: u32 = 5;
pub const CLASS_USB: u32 = 6;
pub const CLASS_DRM: u32 = 7;
pub const CLASS_POWER_SUPPLY: u32 = 8;
pub const CLASS_THERMAL: u32 = 9;
pub const CLASS_HWMON: u32 = 10;
pub const CLASS_BACKLIGHT: u32 = 11;
pub const CLASS_LEDS: u32 = 12;
pub const CLASS_RTC: u32 = 13;
pub const CLASS_WATCHDOG: u32 = 14;
pub const CLASS_GPIO: u32 = 15;
pub const CLASS_I2C: u32 = 16;
pub const CLASS_SPI: u32 = 17;
pub const CLASS_REGULATOR: u32 = 18;
pub const CLASS_FIRMWARE: u32 = 19;
pub const CLASS_MISC: u32 = 20;

// ============================================================================
// Platform Device
// ============================================================================

pub struct PlatformDevice {
    pub device: Device,
    pub name: [64; u8],
    pub name_len: u8,
    pub id: i32,   // -1 for auto
    pub id_auto: bool,
    // Platform data
    pub platform_data: u64,
    pub platform_data_size: u32,
    // MFD (Multi-Function Device) cell
    pub mfd_cell: u32,
    // Device tree match
    pub of_match: u32,
    pub acpi_match: u32,
}

impl PlatformDevice {
    pub fn new(name: &[u8]) -> Self {
        let mut pdev = PlatformDevice {
            device: Device::new(name),
            name: [0; 64],
            name_len: 0,
            id: -1,
            id_auto: true,
            platform_data: 0,
            platform_data_size: 0,
            mfd_cell: 0,
            of_match: 0,
            acpi_match: 0,
        };
        pdev.device.bus_type = BUS_PLATFORM;
        let len = if name.len() > 63 { 63 } else { name.len() };
        pdev.name[..len].copy_from_slice(&name[..len]);
        pdev.name_len = len as u8;
        pdev
    }
}

// ============================================================================
// Device Links
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceLinkFlags {
    Stateless = 1,
    Autoremove(DeviceLinkAutoRemove),
    PmRuntime = 4,
    Rpm(bool),
    Managed = 16,
    InPlace = 32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceLinkAutoRemove {
    None,
    Consumer,
    Supplier,
}

pub struct DeviceLink {
    pub supplier: u32,    // Device ID
    pub consumer: u32,    // Device ID
    pub flags: u32,
    pub status: DeviceLinkState,
    pub ref_count: AtomicU32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum DeviceLinkState {
    Dormant,
    Available,
    ConsumerProbe,
    Active,
    Supplier_Unbind,
}

// ============================================================================
// Uevent Environment
// ============================================================================

pub struct UeventEnv {
    pub action: UeventAction,
    pub devpath: [256; u8],
    pub devpath_len: u16,
    pub subsystem: [32; u8],
    pub subsystem_len: u8,
    pub envp: [32; [128; u8]],
    pub envp_lens: [32; u8],
    pub envp_count: u8,
    pub seqnum: u64,
}

impl UeventEnv {
    pub fn new(action: UeventAction) -> Self {
        UeventEnv {
            action,
            devpath: [0; 256],
            devpath_len: 0,
            subsystem: [0; 32],
            subsystem_len: 0,
            envp: [[0; 128]; 32],
            envp_lens: [0; 32],
            envp_count: 0,
            seqnum: 0,
        }
    }

    pub fn add_var(&mut self, key: &[u8], value: &[u8]) -> bool {
        if self.envp_count >= 32 { return false; }
        let idx = self.envp_count as usize;
        let total = key.len() + 1 + value.len(); // key=value
        if total > 127 { return false; }
        self.envp[idx][..key.len()].copy_from_slice(key);
        self.envp[idx][key.len()] = b'=';
        self.envp[idx][key.len() + 1..key.len() + 1 + value.len()].copy_from_slice(value);
        self.envp_lens[idx] = total as u8;
        self.envp_count += 1;
        true
    }
}

// ============================================================================
// Firmware Loading
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FwLoadFlags {
    None,
    Optional,    // Don't fail if not found
    NowarnOptional,
    NoCache,
    Fallback,
}

pub struct FirmwareRequest {
    pub name: [128; u8],
    pub name_len: u8,
    pub device_id: u32,
    pub flags: u32,
    // Result
    pub data_ptr: u64,
    pub data_size: u64,
    pub status: FwRequestStatus,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FwRequestStatus {
    Pending,
    Loading,
    Complete,
    NotFound,
    Error,
}

pub struct FirmwareCache {
    pub entries: [64; FirmwareCacheEntry],
    pub count: u16,
}

pub struct FirmwareCacheEntry {
    pub name: [128; u8],
    pub name_len: u8,
    pub data_phys: u64,
    pub data_size: u64,
    pub ref_count: AtomicU32,
    pub valid: bool,
}

impl FirmwareCache {
    pub fn lookup(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.count as usize {
            if self.entries[i].valid && self.entries[i].name_len == name.len() as u8 {
                if &self.entries[i].name[..name.len()] == name {
                    return Some(i);
                }
            }
        }
        None
    }
}

// ============================================================================
// Device Tree / ACPI Integration
// ============================================================================

pub struct DeviceTreeNode {
    pub name: [64; u8],
    pub name_len: u8,
    pub full_name: [256; u8],
    pub full_name_len: u16,
    pub phandle: u32,
    pub parent: u32,   // Node index
    pub child: u32,
    pub sibling: u32,
    // Properties
    pub properties: [16; DtProperty],
    pub num_properties: u8,
    // Status
    pub available: bool,
}

pub struct DtProperty {
    pub name: [32; u8],
    pub name_len: u8,
    pub value: [256; u8],
    pub value_len: u16,
}

pub struct AcpiDeviceNode {
    pub hid: [16; u8],     // Hardware ID (e.g., "PNP0A03")
    pub hid_len: u8,
    pub uid: [16; u8],     // Unique ID
    pub uid_len: u8,
    pub adr: u64,          // Address (_ADR)
    pub handle: u64,       // ACPI handle
    pub status: u32,       // _STA return value
    pub companion_device: u32,
}

pub const ACPI_STA_PRESENT: u32 = 1 << 0;
pub const ACPI_STA_ENABLED: u32 = 1 << 1;
pub const ACPI_STA_VISIBLE: u32 = 1 << 2;
pub const ACPI_STA_FUNCTIONAL: u32 = 1 << 3;
pub const ACPI_STA_BATTERY: u32 = 1 << 4;

// ============================================================================
// Device Registry
// ============================================================================

pub const MAX_REGISTERED_DEVICES: usize = 2048;
pub const MAX_REGISTERED_DRIVERS: usize = 512;
pub const MAX_REGISTERED_BUSES: usize = 32;
pub const MAX_REGISTERED_CLASSES: usize = 64;

pub struct DeviceRegistry {
    pub devices: [MAX_REGISTERED_DEVICES; Device],
    pub device_count: u32,
    pub drivers: [MAX_REGISTERED_DRIVERS; DeviceDriver],
    pub driver_count: u32,
    pub buses: [MAX_REGISTERED_BUSES; BusType],
    pub bus_count: u32,
    pub classes: [MAX_REGISTERED_CLASSES; DeviceClass],
    pub class_count: u32,
    pub next_kobj_id: AtomicU32,
    pub uevent_seqnum: AtomicU64,
    pub fw_cache: FirmwareCache,
}

impl DeviceRegistry {
    pub fn alloc_kobj_id(&self) -> u32 {
        self.next_kobj_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_uevent_seqnum(&self) -> u64 {
        self.uevent_seqnum.fetch_add(1, Ordering::Relaxed)
    }
}
