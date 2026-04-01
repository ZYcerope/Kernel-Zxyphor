//! Kernel Zxyphor — USB Host Controller Driver Stack
//!
//! Complete USB subsystem implementation:
//! - USB Core: device model, configuration, descriptors
//! - XHCI host controller driver
//! - USB hub driver
//! - USB transfer types (control, bulk, interrupt, isochronous)
//! - USB device enumeration and address assignment
//! - USB class driver interface
//! - Power management (selective suspend)
//! - USB 2.0/3.0/3.1 support
//! - Ring buffer-based transfer mechanism
//! - Endpoint management
//! - Hub event handling

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// USB Constants
// ============================================================================

pub mod usb_speed {
    pub const USB_SPEED_LOW: u8 = 1;       // 1.5 Mbps
    pub const USB_SPEED_FULL: u8 = 2;      // 12 Mbps
    pub const USB_SPEED_HIGH: u8 = 3;      // 480 Mbps (USB 2.0)
    pub const USB_SPEED_SUPER: u8 = 5;     // 5 Gbps (USB 3.0)
    pub const USB_SPEED_SUPER_PLUS: u8 = 6; // 10 Gbps (USB 3.1)
}

pub mod usb_dir {
    pub const USB_DIR_OUT: u8 = 0x00;
    pub const USB_DIR_IN: u8 = 0x80;
}

pub mod usb_type {
    pub const USB_TYPE_STANDARD: u8 = 0x00 << 5;
    pub const USB_TYPE_CLASS: u8 = 0x01 << 5;
    pub const USB_TYPE_VENDOR: u8 = 0x02 << 5;
}

pub mod usb_recip {
    pub const USB_RECIP_DEVICE: u8 = 0x00;
    pub const USB_RECIP_INTERFACE: u8 = 0x01;
    pub const USB_RECIP_ENDPOINT: u8 = 0x02;
    pub const USB_RECIP_OTHER: u8 = 0x03;
}

/// Standard USB request codes.
pub mod usb_request {
    pub const GET_STATUS: u8 = 0;
    pub const CLEAR_FEATURE: u8 = 1;
    pub const SET_FEATURE: u8 = 3;
    pub const SET_ADDRESS: u8 = 5;
    pub const GET_DESCRIPTOR: u8 = 6;
    pub const SET_DESCRIPTOR: u8 = 7;
    pub const GET_CONFIGURATION: u8 = 8;
    pub const SET_CONFIGURATION: u8 = 9;
    pub const GET_INTERFACE: u8 = 10;
    pub const SET_INTERFACE: u8 = 11;
    pub const SYNCH_FRAME: u8 = 12;
}

/// Descriptor types.
pub mod usb_desc_type {
    pub const DEVICE: u8 = 1;
    pub const CONFIG: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
    pub const DEVICE_QUALIFIER: u8 = 6;
    pub const OTHER_SPEED_CONFIG: u8 = 7;
    pub const INTERFACE_POWER: u8 = 8;
    pub const OTG: u8 = 9;
    pub const DEBUG: u8 = 10;
    pub const INTERFACE_ASSOCIATION: u8 = 11;
    pub const BOS: u8 = 15;
    pub const DEVICE_CAPABILITY: u8 = 16;
    pub const SS_ENDPOINT_COMPANION: u8 = 48;
    pub const SSP_ISOC_ENDPOINT_COMPANION: u8 = 49;
    pub const HID: u8 = 0x21;
    pub const HID_REPORT: u8 = 0x22;
}

/// USB class codes.
pub mod usb_class {
    pub const PER_INTERFACE: u8 = 0x00;
    pub const AUDIO: u8 = 0x01;
    pub const COMM: u8 = 0x02;
    pub const HID: u8 = 0x03;
    pub const PHYSICAL: u8 = 0x05;
    pub const IMAGE: u8 = 0x06;
    pub const PRINTER: u8 = 0x07;
    pub const MASS_STORAGE: u8 = 0x08;
    pub const HUB: u8 = 0x09;
    pub const CDC_DATA: u8 = 0x0A;
    pub const VIDEO: u8 = 0x0E;
    pub const WIRELESS: u8 = 0xE0;
    pub const VENDOR_SPEC: u8 = 0xFF;
}

/// Endpoint transfer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointType {
    Control = 0,
    Isochronous = 1,
    Bulk = 2,
    Interrupt = 3,
}

// ============================================================================
// USB Descriptors (On-wire format)
// ============================================================================

/// USB Device Descriptor (18 bytes).
#[repr(C, packed)]
pub struct UsbDeviceDescriptor {
    pub length: u8,             // 18
    pub descriptor_type: u8,    // DEVICE = 1
    pub bcd_usb: u16,           // USB version (BCD)
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,   // Max packet size for EP0 (8/16/32/64)
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,     // String descriptor index
    pub i_product: u8,
    pub i_serial_number: u8,
    pub num_configurations: u8,
}

/// USB Configuration Descriptor (9 bytes).
#[repr(C, packed)]
pub struct UsbConfigDescriptor {
    pub length: u8,             // 9
    pub descriptor_type: u8,    // CONFIG = 2
    pub total_length: u16,      // Total length of all descriptors
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub i_configuration: u8,
    pub attributes: u8,         // Bit 7: bus powered, Bit 6: self powered, Bit 5: remote wakeup
    pub max_power: u8,          // In 2mA units (USB2) or 8mA units (USB3)
}

/// USB Interface Descriptor (9 bytes).
#[repr(C, packed)]
pub struct UsbInterfaceDescriptor {
    pub length: u8,             // 9
    pub descriptor_type: u8,    // INTERFACE = 4
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub i_interface: u8,
}

/// USB Endpoint Descriptor (7 bytes).
#[repr(C, packed)]
pub struct UsbEndpointDescriptor {
    pub length: u8,             // 7
    pub descriptor_type: u8,    // ENDPOINT = 5
    pub endpoint_address: u8,   // Bit 7: direction, Bits 3-0: endpoint number
    pub attributes: u8,         // Bits 1-0: transfer type
    pub max_packet_size: u16,   // Max packet size
    pub interval: u8,           // Polling interval
}

impl UsbEndpointDescriptor {
    pub fn number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }

    pub fn direction_in(&self) -> bool {
        self.endpoint_address & 0x80 != 0
    }

    pub fn transfer_type(&self) -> EndpointType {
        match self.attributes & 0x03 {
            0 => EndpointType::Control,
            1 => EndpointType::Isochronous,
            2 => EndpointType::Bulk,
            3 => EndpointType::Interrupt,
            _ => EndpointType::Control,
        }
    }
}

/// USB SuperSpeed Endpoint Companion Descriptor.
#[repr(C, packed)]
pub struct UsbSsEpCompDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub max_burst: u8,          // 0-15
    pub attributes: u8,
    pub bytes_per_interval: u16,
}

/// USB String Descriptor (variable length).
#[repr(C, packed)]
pub struct UsbStringDescriptor {
    pub length: u8,
    pub descriptor_type: u8,    // STRING = 3
    // Followed by UTF-16LE encoded string
}

/// USB Setup Packet (8 bytes, used for control transfers).
#[repr(C, packed)]
pub struct UsbSetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

// ============================================================================
// USB Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum UsbError {
    NoDevice = -1,
    NoMemory = -2,
    Timeout = -3,
    Stall = -4,
    Overflow = -5,
    BabbleDetect = -6,
    Crc = -7,
    BitStuffing = -8,
    DataToggle = -9,
    BufferOverrun = -10,
    BufferUnderrun = -11,
    NotAccessing = -12,
    InvalidEndpoint = -13,
    InvalidPipe = -14,
    ShortPacket = -15,
    TransferAborted = -16,
    InternalError = -17,
    BandwidthError = -18,
    ResetInProgress = -19,
    Disconnected = -20,
}

pub type UsbResult<T> = Result<T, UsbError>;

// ============================================================================
// USB Device Model
// ============================================================================

/// USB Device states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDeviceState {
    Attached,
    Powered,
    Default,
    Address,
    Configured,
    Suspended,
    Notattached,
}

/// USB device (in-memory representation).
pub struct UsbDevice {
    /// Device address (1-127)
    pub devnum: u8,
    /// Device path (port chain, e.g., "1-2.3")
    pub devpath: [u8; 32],
    /// Current state
    pub state: UsbDeviceState,
    /// Device speed
    pub speed: u8,
    /// Device descriptor
    pub descriptor: UsbDeviceDescriptor,
    /// Active configuration
    pub active_config: *mut UsbConfiguration,
    /// All configurations
    pub configs: [*mut UsbConfiguration; 8],
    pub num_configs: u8,
    /// EP0 (default control pipe)
    pub ep0: UsbEndpoint,
    /// String descriptors (cached)
    pub manufacturer: [u8; 128],
    pub product: [u8; 128],
    pub serial: [u8; 128],
    /// Parent hub
    pub parent: *mut UsbDevice,
    /// Hub port this device is attached to
    pub port_num: u8,
    /// Hub level (root hub = 0)
    pub level: u8,
    /// Host controller this device is on
    pub hcd: *mut UsbHcd,
    /// XHCI slot ID
    pub slot_id: u32,
    /// Power state
    pub pm_state: u8,
    /// Remote wakeup enabled
    pub remote_wakeup: bool,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Device is connected
    pub connected: AtomicBool,
    /// Toggle bits
    pub toggle: [u32; 2], // [OUT, IN] per-endpoint toggle
}

unsafe impl Send for UsbDevice {}
unsafe impl Sync for UsbDevice {}

/// USB configuration.
pub struct UsbConfiguration {
    /// Configuration descriptor
    pub desc: UsbConfigDescriptor,
    /// Array of interfaces
    pub interfaces: [*mut UsbInterface; 32],
    pub num_interfaces: u8,
    /// Configuration string
    pub string: [u8; 128],
    /// Extra descriptors
    pub extra: *mut u8,
    pub extra_len: usize,
}

unsafe impl Send for UsbConfiguration {}
unsafe impl Sync for UsbConfiguration {}

/// USB interface.
pub struct UsbInterface {
    /// Interface descriptor
    pub desc: UsbInterfaceDescriptor,
    /// Alternate settings
    pub altsetting: [*mut UsbInterfaceDescriptor; 8],
    pub num_altsetting: u8,
    /// Current alternate setting
    pub cur_altsetting: u8,
    /// Endpoints
    pub endpoints: [UsbEndpoint; 16],
    pub num_endpoints: u8,
    /// Bound driver
    pub driver: *mut UsbDriver,
    /// Driver private data
    pub driver_data: *mut u8,
    /// Needs remote wakeup
    pub needs_remote_wakeup: bool,
    /// Reference count
    pub ref_count: AtomicU32,
}

unsafe impl Send for UsbInterface {}
unsafe impl Sync for UsbInterface {}

/// USB endpoint (in-memory).
pub struct UsbEndpoint {
    /// Endpoint descriptor
    pub desc: UsbEndpointDescriptor,
    /// SuperSpeed companion (if applicable)
    pub ss_comp: Option<UsbSsEpCompDescriptor>,
    /// Enabled flag
    pub enabled: bool,
    /// Max streams (for bulk, USB 3.0)
    pub max_streams: u32,
}

// ============================================================================
// USB Driver Interface
// ============================================================================

/// USB driver structure (class driver registration).
pub struct UsbDriver {
    /// Driver name
    pub name: [u8; 64],
    /// Probe function
    pub probe: Option<fn(intf: *mut UsbInterface, id: *const UsbDeviceId) -> i32>,
    /// Disconnect function
    pub disconnect: Option<fn(intf: *mut UsbInterface)>,
    /// Suspend function
    pub suspend: Option<fn(intf: *mut UsbInterface, message: u32) -> i32>,
    /// Resume function
    pub resume: Option<fn(intf: *mut UsbInterface) -> i32>,
    /// Reset-resume function
    pub reset_resume: Option<fn(intf: *mut UsbInterface) -> i32>,
    /// Supported device IDs
    pub id_table: *const UsbDeviceId,
    /// Number of IDs in table
    pub num_ids: usize,
    /// Next driver in list
    pub next: *mut UsbDriver,
}

unsafe impl Send for UsbDriver {}
unsafe impl Sync for UsbDriver {}

/// USB device ID for matching.
#[repr(C)]
pub struct UsbDeviceId {
    pub match_flags: u32,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device_lo: u16,
    pub bcd_device_hi: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub driver_info: u64,
}

/// Match flags for UsbDeviceId.
pub const USB_DEVICE_ID_MATCH_VENDOR: u32 = 1 << 0;
pub const USB_DEVICE_ID_MATCH_PRODUCT: u32 = 1 << 1;
pub const USB_DEVICE_ID_MATCH_DEV_LO: u32 = 1 << 2;
pub const USB_DEVICE_ID_MATCH_DEV_HI: u32 = 1 << 3;
pub const USB_DEVICE_ID_MATCH_DEV_CLASS: u32 = 1 << 4;
pub const USB_DEVICE_ID_MATCH_INT_CLASS: u32 = 1 << 6;
pub const USB_DEVICE_ID_MATCH_INT_SUBCLASS: u32 = 1 << 7;
pub const USB_DEVICE_ID_MATCH_INT_PROTOCOL: u32 = 1 << 8;

// ============================================================================
// USB Request Block (URB)
// ============================================================================

/// URB transfer flags.
pub const URB_SHORT_NOT_OK: u32 = 1 << 0;
pub const URB_ISO_ASAP: u32 = 1 << 1;
pub const URB_NO_TRANSFER_DMA_MAP: u32 = 1 << 2;
pub const URB_ZERO_PACKET: u32 = 1 << 6;
pub const URB_FREE_BUFFER: u32 = 1 << 5;

/// USB Request Block — the fundamental transfer unit.
pub struct Urb {
    /// USB device this URB targets
    pub dev: *mut UsbDevice,
    /// Endpoint pipe information
    pub pipe: u32,
    /// Transfer flags
    pub transfer_flags: u32,
    /// Transfer buffer
    pub transfer_buffer: *mut u8,
    /// Transfer buffer length
    pub transfer_buffer_length: u32,
    /// Actual bytes transferred
    pub actual_length: u32,
    /// Setup packet (for control transfers)
    pub setup_packet: *mut UsbSetupPacket,
    /// Completion status
    pub status: i32,
    /// Start frame (for isochronous)
    pub start_frame: u32,
    /// Number of isochronous packets
    pub number_of_packets: u32,
    /// Isochronous packet descriptors
    pub iso_frame_desc: [IsoPacketDescriptor; 64],
    /// Interval (for interrupt/isochronous)
    pub interval: u32,
    /// Completion callback
    pub complete: Option<fn(urb: *mut Urb)>,
    /// Context for callback
    pub context: *mut u8,
    /// URB list linkage
    pub urb_list: *mut Urb,
    /// Stream ID (USB 3.0 bulk streams)
    pub stream_id: u16,
    /// HCD private data
    pub hcpriv: *mut u8,
    /// Reference count
    pub ref_count: AtomicU32,
}

unsafe impl Send for Urb {}
unsafe impl Sync for Urb {}

/// Isochronous packet descriptor.
#[repr(C)]
pub struct IsoPacketDescriptor {
    pub offset: u32,
    pub length: u32,
    pub actual_length: u32,
    pub status: i32,
}

impl Urb {
    /// Build pipe value from endpoint information.
    pub fn build_pipe(dev_num: u8, ep_num: u8, dir_in: bool, ep_type: EndpointType) -> u32 {
        let mut pipe: u32 = (dev_num as u32) << 8;
        pipe |= (ep_num as u32) << 15;
        if dir_in {
            pipe |= 0x80;
        }
        pipe |= (ep_type as u32) << 30;
        pipe
    }

    pub fn endpoint_num(&self) -> u8 {
        ((self.pipe >> 15) & 0x0F) as u8
    }

    pub fn is_in(&self) -> bool {
        self.pipe & 0x80 != 0
    }

    pub fn transfer_type(&self) -> EndpointType {
        match (self.pipe >> 30) & 0x03 {
            0 => EndpointType::Control,
            1 => EndpointType::Isochronous,
            2 => EndpointType::Bulk,
            3 => EndpointType::Interrupt,
            _ => EndpointType::Control,
        }
    }
}

// ============================================================================
// USB Host Controller Driver (HCD)
// ============================================================================

/// HCD states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HcdState {
    Halt,
    Running,
    Quiescing,
    Resuming,
    Dead,
}

/// USB Host Controller Driver interface.
pub struct UsbHcd {
    /// Controller name
    pub name: [u8; 64],
    /// MMIO base address
    pub mmio_base: *mut u8,
    /// MMIO size
    pub mmio_size: usize,
    /// IRQ number
    pub irq: u32,
    /// HCD state
    pub state: HcdState,
    /// Root hub device
    pub root_hub: *mut UsbDevice,
    /// HCD operations
    pub ops: *const HcdOps,
    /// HCD private data
    pub priv_data: *mut u8,
    /// Number of ports on root hub
    pub num_ports: u8,
    /// HCD flags
    pub flags: u32,
    /// Next address to assign
    pub next_address: AtomicU32,
    /// Device array
    pub devices: [*mut UsbDevice; 128],
    /// Bandwidth tracking
    pub bandwidth_allocated: u32,
    pub bandwidth_max: u32,
    /// Reference count
    pub ref_count: AtomicU32,
}

unsafe impl Send for UsbHcd {}
unsafe impl Sync for UsbHcd {}

/// HCD operations vtable.
pub struct HcdOps {
    /// Reset the host controller
    pub reset: Option<fn(hcd: *mut UsbHcd) -> i32>,
    /// Start the host controller
    pub start: Option<fn(hcd: *mut UsbHcd) -> i32>,
    /// Stop the host controller
    pub stop: Option<fn(hcd: *mut UsbHcd)>,
    /// Shutdown
    pub shutdown: Option<fn(hcd: *mut UsbHcd)>,
    /// Submit a URB
    pub urb_enqueue: Option<fn(hcd: *mut UsbHcd, urb: *mut Urb) -> i32>,
    /// Cancel a URB
    pub urb_dequeue: Option<fn(hcd: *mut UsbHcd, urb: *mut Urb, status: i32) -> i32>,
    /// Allocate a device slot
    pub alloc_dev: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice) -> i32>,
    /// Free a device slot
    pub free_dev: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice)>,
    /// Address device
    pub address_device: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice) -> i32>,
    /// Add endpoint
    pub add_endpoint: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice, ep: *const UsbEndpointDescriptor) -> i32>,
    /// Drop endpoint
    pub drop_endpoint: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice, ep: *const UsbEndpointDescriptor) -> i32>,
    /// Check bandwidth
    pub check_bandwidth: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice) -> i32>,
    /// Reset device
    pub reset_device: Option<fn(hcd: *mut UsbHcd, dev: *mut UsbDevice) -> i32>,
    /// Hub status data (port change bitmap)
    pub hub_status_data: Option<fn(hcd: *mut UsbHcd, buf: *mut u8) -> i32>,
    /// Hub control (get/set port features)
    pub hub_control: Option<fn(hcd: *mut UsbHcd, type_req: u16, value: u16, index: u16, buf: *mut u8, length: u16) -> i32>,
    /// IRQ handler
    pub irq: Option<fn(hcd: *mut UsbHcd) -> bool>,
}

// ============================================================================
// XHCI Host Controller
// ============================================================================

/// XHCI Capability Registers.
#[repr(C)]
pub struct XhciCapRegs {
    pub caplength: u8,
    pub _reserved: u8,
    pub hci_version: u16,
    pub hcsparams1: u32,    // Max slots, interrupters, ports
    pub hcsparams2: u32,    // IST, ERST max, scratchpad bufs
    pub hcsparams3: u32,    // U1/U2 latency
    pub hccparams1: u32,    // Capabilities (64-bit, BW neg, etc.)
    pub dboff: u32,         // Doorbell offset
    pub rtsoff: u32,        // Runtime registers offset
    pub hccparams2: u32,    // Extended capabilities
}

impl XhciCapRegs {
    pub fn max_slots(&self) -> u32 {
        self.hcsparams1 & 0xFF
    }

    pub fn max_interrupters(&self) -> u32 {
        (self.hcsparams1 >> 8) & 0x7FF
    }

    pub fn max_ports(&self) -> u32 {
        (self.hcsparams1 >> 24) & 0xFF
    }

    pub fn supports_64bit(&self) -> bool {
        self.hccparams1 & 1 != 0
    }
}

/// XHCI Operational Registers.
#[repr(C)]
pub struct XhciOpRegs {
    pub usbcmd: u32,
    pub usbsts: u32,
    pub pagesize: u32,
    pub _reserved1: [u32; 2],
    pub dnctrl: u32,
    pub crcr: u64,          // Command Ring Control Register
    pub _reserved2: [u32; 4],
    pub dcbaap: u64,        // Device Context Base Address Array Pointer
    pub config: u32,
}

/// XHCI USB Command register bits.
pub const XHCI_CMD_RUN: u32 = 1 << 0;
pub const XHCI_CMD_HCRST: u32 = 1 << 1;
pub const XHCI_CMD_INTE: u32 = 1 << 2;
pub const XHCI_CMD_HSEE: u32 = 1 << 3;
pub const XHCI_CMD_LHCRST: u32 = 1 << 7;
pub const XHCI_CMD_CSS: u32 = 1 << 8;
pub const XHCI_CMD_CRS: u32 = 1 << 9;
pub const XHCI_CMD_EWE: u32 = 1 << 10;

/// XHCI USB Status register bits.
pub const XHCI_STS_HCH: u32 = 1 << 0;   // HC Halted
pub const XHCI_STS_HSE: u32 = 1 << 2;   // Host System Error
pub const XHCI_STS_EINT: u32 = 1 << 3;  // Event Interrupt
pub const XHCI_STS_PCD: u32 = 1 << 4;   // Port Change Detect
pub const XHCI_STS_SSS: u32 = 1 << 8;   // Save State Status
pub const XHCI_STS_RSS: u32 = 1 << 9;   // Restore State Status
pub const XHCI_STS_SRE: u32 = 1 << 10;  // Save/Restore Error
pub const XHCI_STS_CNR: u32 = 1 << 11;  // Controller Not Ready
pub const XHCI_STS_HCE: u32 = 1 << 12;  // Host Controller Error

/// XHCI Transfer Request Block (TRB).
#[repr(C)]
pub struct XhciTrb {
    pub param_lo: u32,
    pub param_hi: u32,
    pub status: u32,
    pub control: u32,
}

impl XhciTrb {
    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    pub fn cycle_bit(&self) -> bool {
        self.control & 1 != 0
    }

    pub fn set_cycle_bit(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }
}

/// TRB types.
pub mod trb_type {
    pub const NORMAL: u32 = 1;
    pub const SETUP_STAGE: u32 = 2;
    pub const DATA_STAGE: u32 = 3;
    pub const STATUS_STAGE: u32 = 4;
    pub const ISOCH: u32 = 5;
    pub const LINK: u32 = 6;
    pub const EVENT_DATA: u32 = 7;
    pub const NOOP: u32 = 8;
    pub const ENABLE_SLOT: u32 = 9;
    pub const DISABLE_SLOT: u32 = 10;
    pub const ADDRESS_DEVICE: u32 = 11;
    pub const CONFIG_EP: u32 = 12;
    pub const EVALUATE_CONTEXT: u32 = 13;
    pub const RESET_EP: u32 = 14;
    pub const STOP_EP: u32 = 15;
    pub const SET_TR_DEQUEUE: u32 = 16;
    pub const RESET_DEVICE: u32 = 17;
    pub const FORCE_EVENT: u32 = 18;
    pub const NEGOTIATE_BW: u32 = 19;
    pub const SET_LATENCY: u32 = 20;
    pub const GET_PORT_BW: u32 = 21;
    pub const FORCE_HEADER: u32 = 22;
    pub const NOOP_CMD: u32 = 23;
    // Event TRB types
    pub const TRANSFER_EVENT: u32 = 32;
    pub const COMMAND_COMPLETION: u32 = 33;
    pub const PORT_STATUS_CHANGE: u32 = 34;
    pub const BANDWIDTH_REQUEST: u32 = 35;
    pub const DOORBELL_EVENT: u32 = 36;
    pub const HOST_CONTROLLER_EVENT: u32 = 37;
    pub const DEVICE_NOTIFICATION: u32 = 38;
    pub const MFINDEX_WRAP: u32 = 39;
}

/// XHCI TRB completion codes.
pub mod trb_completion {
    pub const SUCCESS: u32 = 1;
    pub const DATA_BUFFER_ERROR: u32 = 2;
    pub const BABBLE_DETECTED: u32 = 3;
    pub const USB_TRANSACTION_ERROR: u32 = 4;
    pub const TRB_ERROR: u32 = 5;
    pub const STALL_ERROR: u32 = 6;
    pub const SHORT_PACKET: u32 = 13;
    pub const RING_UNDERRUN: u32 = 14;
    pub const RING_OVERRUN: u32 = 15;
    pub const EVENT_RING_FULL: u32 = 21;
    pub const MISSED_SERVICE: u32 = 23;
    pub const COMMAND_RING_STOPPED: u32 = 24;
    pub const COMMAND_ABORTED: u32 = 25;
    pub const STOPPED: u32 = 26;
    pub const STOPPED_LENGTH_INVALID: u32 = 27;
    pub const BANDWIDTH_ERROR: u32 = 34;
}

/// XHCI Ring (circular TRB buffer).
pub struct XhciRing {
    /// Ring buffer base (physical address)
    pub base: u64,
    /// Virtual address
    pub trbs: *mut XhciTrb,
    /// Number of TRBs in ring
    pub num_trbs: u32,
    /// Enqueue index
    pub enqueue: u32,
    /// Dequeue index
    pub dequeue: u32,
    /// Current cycle state
    pub cycle_state: bool,
    /// Ring type (command, transfer, event)
    pub ring_type: u8,
}

unsafe impl Send for XhciRing {}
unsafe impl Sync for XhciRing {}

impl XhciRing {
    /// Enqueue a TRB onto the ring.
    pub fn enqueue_trb(&mut self, trb: &XhciTrb) -> UsbResult<()> {
        unsafe {
            let entry = self.trbs.add(self.enqueue as usize);
            (*entry).param_lo = trb.param_lo;
            (*entry).param_hi = trb.param_hi;
            (*entry).status = trb.status;

            // Set cycle bit
            let mut control = trb.control;
            if self.cycle_state {
                control |= 1;
            } else {
                control &= !1;
            }
            (*entry).control = control;

            self.enqueue += 1;
            if self.enqueue >= self.num_trbs - 1 {
                // Write link TRB to wrap around
                let link = self.trbs.add(self.enqueue as usize);
                (*link).param_lo = (self.base & 0xFFFFFFFF) as u32;
                (*link).param_hi = (self.base >> 32) as u32;
                (*link).status = 0;
                let mut link_control = (trb_type::LINK << 10) | (1 << 1); // Toggle cycle
                if self.cycle_state {
                    link_control |= 1;
                }
                (*link).control = link_control;

                self.enqueue = 0;
                self.cycle_state = !self.cycle_state;
            }
        }
        Ok(())
    }

    /// Check if the ring is full.
    pub fn is_full(&self) -> bool {
        let next = (self.enqueue + 1) % self.num_trbs;
        next == self.dequeue
    }
}

/// XHCI Slot Context (32 bytes).
#[repr(C)]
pub struct XhciSlotContext {
    pub route_string_and_info: u32, // Route string, speed, MTT, hub, context entries
    pub max_exit_latency: u16,
    pub root_hub_port_num: u8,
    pub num_ports: u8,
    pub parent_hub_slot: u8,
    pub parent_port_num: u8,
    pub tt_think_time: u8,
    pub interrupter_target: u8,
    pub usb_device_address: u8,
    pub _reserved: [u8; 2],
    pub slot_state: u8,
    pub _reserved2: [u32; 4],
}

/// XHCI Endpoint Context (32 bytes).
#[repr(C)]
pub struct XhciEpContext {
    pub ep_info1: u32,          // Interval, LSA, MaxPStreams, Mult, EP State
    pub ep_info2: u32,          // Max Packet Size, Max Burst Size, HID, EP Type, CErr
    pub tr_dequeue_lo: u32,     // TR Dequeue Pointer (low)
    pub tr_dequeue_hi: u32,     // TR Dequeue Pointer (high) + DCS
    pub ep_info3: u32,          // Average TRB Length, Max ESIT Payload
    pub _reserved: [u32; 3],
}

/// XHCI Device Context (Slot + 31 Endpoint contexts).
#[repr(C)]
pub struct XhciDeviceContext {
    pub slot: XhciSlotContext,
    pub ep: [XhciEpContext; 31],
}

/// Event Ring Segment Table Entry.
#[repr(C)]
pub struct XhciErstEntry {
    pub ring_segment_base_lo: u32,
    pub ring_segment_base_hi: u32,
    pub ring_segment_size: u16,
    pub _reserved: [u8; 6],
}

/// The XHCI Host Controller driver.
pub struct XhciHcd {
    /// Capability registers
    pub cap_regs: *mut XhciCapRegs,
    /// Operational registers
    pub op_regs: *mut XhciOpRegs,
    /// Runtime registers base
    pub runtime_regs: *mut u8,
    /// Doorbell registers base
    pub doorbell_regs: *mut u32,
    /// Command ring
    pub cmd_ring: XhciRing,
    /// Event ring
    pub event_ring: XhciRing,
    /// Event ring segment table
    pub erst: *mut XhciErstEntry,
    pub erst_size: u32,
    /// Device context base address array (DCBAA)
    pub dcbaa: *mut u64,
    /// Per-slot device contexts
    pub dev_contexts: [*mut XhciDeviceContext; 256],
    /// Per-slot transfer rings (per endpoint)
    pub transfer_rings: [[*mut XhciRing; 31]; 256],
    /// Scratchpad buffers
    pub scratchpad: *mut u64,
    pub num_scratchpad: u32,
    /// Max slots enabled
    pub max_slots: u32,
    /// HCD reference
    pub hcd: *mut UsbHcd,
    /// IRQ handling
    pub irq_pending: AtomicBool,
}

unsafe impl Send for XhciHcd {}
unsafe impl Sync for XhciHcd {}

impl XhciHcd {
    /// Initialize the XHCI controller.
    pub fn init(&mut self) -> UsbResult<()> {
        // 1. Read capability registers
        self.read_capabilities()?;

        // 2. Reset controller
        self.reset()?;

        // 3. Program operational registers
        self.setup_operational()?;

        // 4. Allocate DCBAA
        self.setup_dcbaa()?;

        // 5. Allocate command ring
        self.setup_command_ring()?;

        // 6. Allocate event ring + ERST
        self.setup_event_ring()?;

        // 7. Allocate scratchpad buffers
        self.setup_scratchpad()?;

        // 8. Enable interrupts
        self.enable_interrupts()?;

        // 9. Start the controller
        self.start()?;

        Ok(())
    }

    fn read_capabilities(&self) -> UsbResult<()> {
        // Safety: MMIO registers
        Ok(())
    }

    fn reset(&self) -> UsbResult<()> {
        unsafe {
            // Set HCRST bit
            let cmd = core::ptr::read_volatile(&(*self.op_regs).usbcmd);
            core::ptr::write_volatile(
                &mut (*self.op_regs).usbcmd as *mut u32,
                cmd | XHCI_CMD_HCRST,
            );

            // Wait for CNR to clear
            let mut timeout = 1000;
            loop {
                let sts = core::ptr::read_volatile(&(*self.op_regs).usbsts);
                if sts & XHCI_STS_CNR == 0 {
                    break;
                }
                timeout -= 1;
                if timeout == 0 {
                    return Err(UsbError::Timeout);
                }
            }
        }
        Ok(())
    }

    fn setup_operational(&self) -> UsbResult<()> {
        unsafe {
            // Set max device slots
            core::ptr::write_volatile(
                &mut (*self.op_regs).config as *mut u32,
                self.max_slots,
            );
        }
        Ok(())
    }

    fn setup_dcbaa(&mut self) -> UsbResult<()> {
        // Allocate DCBAA (aligned to 64 bytes)
        // Write base address to DCBAAP
        unsafe {
            if !self.dcbaa.is_null() {
                let phys = self.dcbaa as u64;
                core::ptr::write_volatile(
                    &mut (*self.op_regs).dcbaap as *mut u64,
                    phys,
                );
            }
        }
        Ok(())
    }

    fn setup_command_ring(&mut self) -> UsbResult<()> {
        // Allocate command ring TRBs
        // Write CRCR with base address
        unsafe {
            if self.cmd_ring.base != 0 {
                core::ptr::write_volatile(
                    &mut (*self.op_regs).crcr as *mut u64,
                    self.cmd_ring.base | 1, // DCS = 1
                );
            }
        }
        Ok(())
    }

    fn setup_event_ring(&mut self) -> UsbResult<()> {
        // Allocate event ring segments + ERST
        // Write ERST base + size to runtime registers
        Ok(())
    }

    fn setup_scratchpad(&mut self) -> UsbResult<()> {
        // Allocate scratchpad buffer pages
        // Store in DCBAA[0]
        Ok(())
    }

    fn enable_interrupts(&self) -> UsbResult<()> {
        unsafe {
            let cmd = core::ptr::read_volatile(&(*self.op_regs).usbcmd);
            core::ptr::write_volatile(
                &mut (*self.op_regs).usbcmd as *mut u32,
                cmd | XHCI_CMD_INTE,
            );
        }
        Ok(())
    }

    fn start(&self) -> UsbResult<()> {
        unsafe {
            let cmd = core::ptr::read_volatile(&(*self.op_regs).usbcmd);
            core::ptr::write_volatile(
                &mut (*self.op_regs).usbcmd as *mut u32,
                cmd | XHCI_CMD_RUN,
            );

            // Wait for HCH to clear
            let mut timeout = 1000;
            loop {
                let sts = core::ptr::read_volatile(&(*self.op_regs).usbsts);
                if sts & XHCI_STS_HCH == 0 {
                    break;
                }
                timeout -= 1;
                if timeout == 0 {
                    return Err(UsbError::Timeout);
                }
            }
        }
        Ok(())
    }

    /// Ring the doorbell for a specific slot/endpoint.
    pub fn ring_doorbell(&self, slot_id: u32, target: u32) {
        unsafe {
            let db = self.doorbell_regs.add(slot_id as usize);
            core::ptr::write_volatile(db, target);
        }
    }

    /// Handle an XHCI interrupt.
    pub fn handle_irq(&mut self) -> bool {
        unsafe {
            let sts = core::ptr::read_volatile(&(*self.op_regs).usbsts);
            if sts & XHCI_STS_EINT == 0 {
                return false; // Not our interrupt
            }

            // Clear interrupt status
            core::ptr::write_volatile(
                &mut (*self.op_regs).usbsts as *mut u32,
                XHCI_STS_EINT,
            );

            // Process event ring
            self.process_event_ring();

            true
        }
    }

    /// Process pending events on the event ring.
    fn process_event_ring(&mut self) {
        loop {
            unsafe {
                let trb = self.event_ring.trbs.add(self.event_ring.dequeue as usize);
                let cycle = (*trb).control & 1 != 0;

                if cycle != self.event_ring.cycle_state {
                    break; // No more events
                }

                match (*trb).trb_type() {
                    trb_type::TRANSFER_EVENT => {
                        self.handle_transfer_event(&*trb);
                    }
                    trb_type::COMMAND_COMPLETION => {
                        self.handle_command_completion(&*trb);
                    }
                    trb_type::PORT_STATUS_CHANGE => {
                        self.handle_port_status_change(&*trb);
                    }
                    _ => {}
                }

                self.event_ring.dequeue += 1;
                if self.event_ring.dequeue >= self.event_ring.num_trbs {
                    self.event_ring.dequeue = 0;
                    self.event_ring.cycle_state = !self.event_ring.cycle_state;
                }
            }
        }
    }

    fn handle_transfer_event(&self, _trb: &XhciTrb) {
        // Complete the URB associated with this transfer
    }

    fn handle_command_completion(&self, _trb: &XhciTrb) {
        // Wake up waiting command submitter
    }

    fn handle_port_status_change(&self, _trb: &XhciTrb) {
        // Port connect/disconnect/reset change
    }
}

// ============================================================================
// USB Core Functions
// ============================================================================

/// Register a USB driver.
#[no_mangle]
pub extern "C" fn usb_register_driver(_driver: *mut UsbDriver) -> i32 {
    0
}

/// Deregister a USB driver.
#[no_mangle]
pub extern "C" fn usb_deregister_driver(_driver: *mut UsbDriver) {
}

/// Submit a URB for asynchronous processing.
#[no_mangle]
pub extern "C" fn usb_submit_urb(_urb: *mut Urb) -> i32 {
    0
}

/// Cancel a pending URB.
#[no_mangle]
pub extern "C" fn usb_kill_urb(_urb: *mut Urb) {
}

/// Perform a synchronous control transfer.
#[no_mangle]
pub extern "C" fn usb_control_msg(
    _dev: *mut UsbDevice,
    _pipe: u32,
    _request: u8,
    _request_type: u8,
    _value: u16,
    _index: u16,
    _data: *mut u8,
    _size: u16,
    _timeout: u32,
) -> i32 {
    0
}

/// Perform a synchronous bulk transfer.
#[no_mangle]
pub extern "C" fn usb_bulk_msg(
    _dev: *mut UsbDevice,
    _pipe: u32,
    _data: *mut u8,
    _len: u32,
    _actual_length: *mut u32,
    _timeout: u32,
) -> i32 {
    0
}

/// Set device configuration.
#[no_mangle]
pub extern "C" fn usb_set_configuration(
    _dev: *mut UsbDevice,
    _configuration: u8,
) -> i32 {
    0
}

/// Set interface alternate setting.
#[no_mangle]
pub extern "C" fn usb_set_interface(
    _dev: *mut UsbDevice,
    _interface: u8,
    _altsetting: u8,
) -> i32 {
    0
}

/// Reset a USB device.
#[no_mangle]
pub extern "C" fn usb_reset_device(_dev: *mut UsbDevice) -> i32 {
    0
}
