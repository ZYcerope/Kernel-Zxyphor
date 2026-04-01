// =============================================================================
// Kernel Zxyphor — Unified Device Model
// =============================================================================
// Provides a device tree and bus abstraction for managing all system devices:
//   - Device registration and lifecycle management
//   - Bus types (PCI, USB, Platform, Virtual)
//   - Device classes (Block, Char, Network, Input, Display)
//   - Power state management per device
//   - Hotplug notification system
//   - Device naming and lookup
//   - Driver binding (match device to driver)
// =============================================================================

use core::sync::atomic::{AtomicU32, Ordering};

// =============================================================================
// Device identification
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BusType {
    Platform = 0,  // Non-discoverable devices
    Pci = 1,
    Usb = 2,
    I2c = 3,
    Spi = 4,
    Virtio = 5,
    Virtual = 6,   // Software-only devices
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceClass {
    Unknown = 0,
    Block = 1,
    Character = 2,
    Network = 3,
    Input = 4,
    Display = 5,
    Audio = 6,
    Serial = 7,
    Timer = 8,
    Gpio = 9,
    Crypto = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceState {
    Uninitialized = 0,
    Probing = 1,
    Active = 2,
    Suspended = 3,
    Error = 4,
    Removed = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DevicePower {
    D0Active = 0,
    D1Standby = 1,
    D2Sleep = 2,
    D3Off = 3,
}

/// Unique device identifier
#[derive(Clone, Copy)]
pub struct DeviceId {
    pub bus: BusType,
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub class_code: u32,     // PCI class code (class:subclass:prog-if)
    pub revision: u8,
}

impl DeviceId {
    pub const fn zero() -> Self {
        Self {
            bus: BusType::Platform,
            vendor_id: 0,
            device_id: 0,
            subsystem_vendor: 0,
            subsystem_device: 0,
            class_code: 0,
            revision: 0,
        }
    }

    pub fn matches(&self, other: &DeviceId) -> bool {
        self.bus == other.bus
            && (self.vendor_id == 0xFFFF || self.vendor_id == other.vendor_id)
            && (self.device_id == 0xFFFF || self.device_id == other.device_id)
    }
}

// =============================================================================
// Device tree node
// =============================================================================

pub const MAX_DEVICE_NAME: usize = 32;
pub const MAX_DEVICES: usize = 128;
pub const MAX_CHILDREN: usize = 16;

/// Resource type for a device
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ResourceType {
    None = 0,
    IoPort = 1,       // I/O port range
    Memory = 2,       // Memory-mapped I/O
    Irq = 3,          // Interrupt request line
    Dma = 4,          // DMA channel
    BusNumber = 5,    // PCI bus number
}

#[derive(Clone, Copy)]
pub struct DeviceResource {
    pub res_type: ResourceType,
    pub start: u64,
    pub end: u64,
    pub flags: u32,
}

impl DeviceResource {
    pub const fn none() -> Self {
        Self {
            res_type: ResourceType::None,
            start: 0,
            end: 0,
            flags: 0,
        }
    }

    pub fn io_port(port_base: u16, port_count: u16) -> Self {
        Self {
            res_type: ResourceType::IoPort,
            start: port_base as u64,
            end: (port_base + port_count - 1) as u64,
            flags: 0,
        }
    }

    pub fn mmio(base: u64, size: u64) -> Self {
        Self {
            res_type: ResourceType::Memory,
            start: base,
            end: base + size - 1,
            flags: 0,
        }
    }

    pub fn irq(irq_num: u32) -> Self {
        Self {
            res_type: ResourceType::Irq,
            start: irq_num as u64,
            end: irq_num as u64,
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

pub const MAX_RESOURCES: usize = 8;

/// A device in the device tree
pub struct Device {
    pub name: [u8; MAX_DEVICE_NAME],
    pub name_len: u8,
    pub id: DeviceId,
    pub class: DeviceClass,
    pub state: DeviceState,
    pub power: DevicePower,
    pub parent_idx: Option<u16>,
    pub children: [Option<u16>; MAX_CHILDREN],
    pub child_count: u8,
    pub resources: [DeviceResource; MAX_RESOURCES],
    pub resource_count: u8,
    pub driver_idx: Option<u16>,
    pub private_data: u64,     // Driver-specific data pointer
    pub flags: u32,
    pub ref_count: AtomicU32,
}

impl Device {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_DEVICE_NAME],
            name_len: 0,
            id: DeviceId::zero(),
            class: DeviceClass::Unknown,
            state: DeviceState::Uninitialized,
            power: DevicePower::D0Active,
            parent_idx: None,
            children: [None; MAX_CHILDREN],
            child_count: 0,
            resources: [const { DeviceResource::none() }; MAX_RESOURCES],
            resource_count: 0,
            driver_idx: None,
            private_data: 0,
            flags: 0,
            ref_count: AtomicU32::new(0),
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = core::cmp::min(name.len(), MAX_DEVICE_NAME - 1);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn add_resource(&mut self, res: DeviceResource) -> bool {
        if self.resource_count as usize >= MAX_RESOURCES {
            return false;
        }
        self.resources[self.resource_count as usize] = res;
        self.resource_count += 1;
        true
    }

    pub fn get_resource(&self, res_type: ResourceType) -> Option<&DeviceResource> {
        for i in 0..self.resource_count as usize {
            if self.resources[i].res_type as u8 == res_type as u8 {
                return Some(&self.resources[i]);
            }
        }
        None
    }

    pub fn is_active(&self) -> bool {
        self.state == DeviceState::Active
    }

    pub fn acquire(&self) {
        self.ref_count.fetch_add(1, Ordering::Acquire);
    }

    pub fn release(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::Release)
    }
}

// =============================================================================
// Driver abstraction
// =============================================================================

pub const MAX_DRIVERS: usize = 64;

/// Driver match table entry
#[derive(Clone, Copy)]
pub struct DriverMatchEntry {
    pub bus: BusType,
    pub vendor_id: u16,    // 0xFFFF = any
    pub device_id: u16,    // 0xFFFF = any
    pub class_code: u32,   // 0 = any (PCI class:subclass:prog-if)
}

impl DriverMatchEntry {
    pub const fn any_pci(class: u32) -> Self {
        Self {
            bus: BusType::Pci,
            vendor_id: 0xFFFF,
            device_id: 0xFFFF,
            class_code: class,
        }
    }

    pub const fn pci(vendor: u16, device: u16) -> Self {
        Self {
            bus: BusType::Pci,
            vendor_id: vendor,
            device_id: device,
            class_code: 0,
        }
    }
}

pub const MAX_MATCH_ENTRIES: usize = 8;

pub struct Driver {
    pub name: [u8; 32],
    pub name_len: u8,
    pub match_table: [DriverMatchEntry; MAX_MATCH_ENTRIES],
    pub match_count: u8,
    pub probe_fn: Option<extern "C" fn(device_idx: u16) -> i32>,
    pub remove_fn: Option<extern "C" fn(device_idx: u16)>,
    pub suspend_fn: Option<extern "C" fn(device_idx: u16) -> i32>,
    pub resume_fn: Option<extern "C" fn(device_idx: u16) -> i32>,
    pub active: bool,
}

impl Driver {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            match_table: [const {
                DriverMatchEntry {
                    bus: BusType::Platform,
                    vendor_id: 0,
                    device_id: 0,
                    class_code: 0,
                }
            }; MAX_MATCH_ENTRIES],
            match_count: 0,
            probe_fn: None,
            remove_fn: None,
            suspend_fn: None,
            resume_fn: None,
            active: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = core::cmp::min(name.len(), 31);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn matches(&self, device: &Device) -> bool {
        for i in 0..self.match_count as usize {
            let entry = &self.match_table[i];
            if entry.bus as u8 != device.id.bus as u8 {
                continue;
            }
            if entry.vendor_id != 0xFFFF && entry.vendor_id != device.id.vendor_id {
                continue;
            }
            if entry.device_id != 0xFFFF && entry.device_id != device.id.device_id {
                continue;
            }
            if entry.class_code != 0 && entry.class_code != device.id.class_code {
                continue;
            }
            return true;
        }
        false
    }
}

// =============================================================================
// Hotplug events
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HotplugEvent {
    DeviceAdded = 0,
    DeviceRemoved = 1,
    DriverBound = 2,
    DriverUnbound = 3,
    DeviceSuspended = 4,
    DeviceResumed = 5,
}

pub struct HotplugNotification {
    pub event: HotplugEvent,
    pub device_idx: u16,
    pub driver_idx: Option<u16>,
    pub timestamp: u64,
}

const HOTPLUG_QUEUE_SIZE: usize = 64;

pub struct HotplugQueue {
    events: [HotplugNotification; HOTPLUG_QUEUE_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl HotplugQueue {
    pub const fn new() -> Self {
        Self {
            events: [const {
                HotplugNotification {
                    event: HotplugEvent::DeviceAdded,
                    device_idx: 0,
                    driver_idx: None,
                    timestamp: 0,
                }
            }; HOTPLUG_QUEUE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, event: HotplugNotification) -> bool {
        if self.count >= HOTPLUG_QUEUE_SIZE {
            return false;
        }
        self.events[self.tail] = event;
        self.tail = (self.tail + 1) % HOTPLUG_QUEUE_SIZE;
        self.count += 1;
        true
    }

    pub fn pop(&mut self) -> Option<HotplugNotification> {
        if self.count == 0 {
            return None;
        }
        let ev = self.events[self.head];
        self.head = (self.head + 1) % HOTPLUG_QUEUE_SIZE;
        self.count -= 1;
        Some(ev)
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

// =============================================================================
// Device tree / manager
// =============================================================================

pub struct DeviceManager {
    devices: [Device; MAX_DEVICES],
    device_count: usize,
    drivers: [Driver; MAX_DRIVERS],
    driver_count: usize,
    hotplug: HotplugQueue,
}

impl DeviceManager {
    pub const fn new() -> Self {
        Self {
            devices: [const { Device::new() }; MAX_DEVICES],
            device_count: 0,
            drivers: [const { Driver::new() }; MAX_DRIVERS],
            driver_count: 0,
            hotplug: HotplugQueue::new(),
        }
    }

    /// Register a new device
    pub fn register_device(&mut self, mut device: Device) -> Option<u16> {
        if self.device_count >= MAX_DEVICES {
            return None;
        }
        let idx = self.device_count as u16;
        device.state = DeviceState::Probing;
        self.devices[self.device_count] = device;
        self.device_count += 1;

        self.hotplug.push(HotplugNotification {
            event: HotplugEvent::DeviceAdded,
            device_idx: idx,
            driver_idx: None,
            timestamp: 0,
        });

        // Try to bind a driver
        self.try_bind_driver(idx);

        Some(idx)
    }

    /// Register a driver
    pub fn register_driver(&mut self, driver: Driver) -> Option<u16> {
        if self.driver_count >= MAX_DRIVERS {
            return None;
        }
        let idx = self.driver_count as u16;
        self.drivers[self.driver_count] = driver;
        self.driver_count += 1;

        // Try to bind to existing unbound devices
        for d in 0..self.device_count {
            if self.devices[d].driver_idx.is_none() && self.devices[d].state != DeviceState::Removed {
                if self.drivers[idx as usize].matches(&self.devices[d]) {
                    self.bind_driver(d as u16, idx);
                }
            }
        }

        Some(idx)
    }

    /// Get device by index
    pub fn get_device(&self, idx: u16) -> Option<&Device> {
        if (idx as usize) < self.device_count {
            Some(&self.devices[idx as usize])
        } else {
            None
        }
    }

    /// Get mutable device by index
    pub fn get_device_mut(&mut self, idx: u16) -> Option<&mut Device> {
        if (idx as usize) < self.device_count {
            Some(&mut self.devices[idx as usize])
        } else {
            None
        }
    }

    pub fn device_count(&self) -> usize {
        self.device_count
    }

    pub fn driver_count(&self) -> usize {
        self.driver_count
    }

    fn try_bind_driver(&mut self, device_idx: u16) {
        for d in 0..self.driver_count {
            if self.drivers[d].active && self.drivers[d].matches(&self.devices[device_idx as usize]) {
                self.bind_driver(device_idx, d as u16);
                return;
            }
        }
    }

    fn bind_driver(&mut self, device_idx: u16, driver_idx: u16) {
        let device = &mut self.devices[device_idx as usize];
        let driver = &self.drivers[driver_idx as usize];

        if let Some(probe) = driver.probe_fn {
            let result = probe(device_idx);
            if result == 0 {
                device.driver_idx = Some(driver_idx);
                device.state = DeviceState::Active;
                self.hotplug.push(HotplugNotification {
                    event: HotplugEvent::DriverBound,
                    device_idx,
                    driver_idx: Some(driver_idx),
                    timestamp: 0,
                });
            } else {
                device.state = DeviceState::Error;
            }
        }
    }

    /// Process pending hotplug events
    pub fn process_hotplug(&mut self) -> Option<HotplugNotification> {
        self.hotplug.pop()
    }
}

static mut DEVICE_MANAGER: DeviceManager = DeviceManager::new();

/// Get the global device manager
///
/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn manager() -> &'static mut DeviceManager {
    &mut *core::ptr::addr_of_mut!(DEVICE_MANAGER)
}
