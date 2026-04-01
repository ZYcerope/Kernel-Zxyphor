// =============================================================================
// Kernel Zxyphor — USB Host Controller Driver (xHCI)
// =============================================================================
// USB (Universal Serial Bus) support for the Zxyphor kernel, implementing the
// xHCI (eXtensible Host Controller Interface) specification for USB 3.x.
//
// xHCI is the standard USB host controller for modern systems. It supports
// USB 1.1, 2.0, and 3.x devices through a unified interface.
//
// Architecture:
//   1. Discovery: PCI enumeration finds xHCI controllers (class 0x0C, subclass 0x03)
//   2. Initialization: Map MMIO registers, allocate ring buffers
//   3. Device management: Port detection, slot assignment, endpoint configuration
//   4. Transfer rings: Command ring, event ring, transfer rings per endpoint
//
// USB device classes supported:
//   - HID (Human Interface Devices): keyboard, mouse
//   - Mass Storage (BOT/UAS): USB drives
//   - Hub: for USB hub enumeration
//   - CDC (Communications): USB serial/ethernet
// =============================================================================

const main = @import("../main.zig");
const pci = @import("pci.zig");

// =============================================================================
// xHCI register offsets (Capability Registers)
// =============================================================================
pub const XHCI_CAPLENGTH: u32 = 0x00;
pub const XHCI_HCIVERSION: u32 = 0x02;
pub const XHCI_HCSPARAMS1: u32 = 0x04;
pub const XHCI_HCSPARAMS2: u32 = 0x08;
pub const XHCI_HCSPARAMS3: u32 = 0x0C;
pub const XHCI_HCCPARAMS1: u32 = 0x10;
pub const XHCI_DBOFF: u32 = 0x14;
pub const XHCI_RTSOFF: u32 = 0x18;
pub const XHCI_HCCPARAMS2: u32 = 0x1C;

// xHCI Operational Register offsets (relative to operational base)
pub const XHCI_USBCMD: u32 = 0x00;
pub const XHCI_USBSTS: u32 = 0x04;
pub const XHCI_PAGESIZE: u32 = 0x08;
pub const XHCI_DNCTRL: u32 = 0x14;
pub const XHCI_CRCR: u32 = 0x18; // Command Ring Control Register (64-bit)
pub const XHCI_DCBAAP: u32 = 0x30; // Device Context Base Address Array Pointer (64-bit)
pub const XHCI_CONFIG: u32 = 0x38;

// USBCMD bits
pub const USBCMD_RUN: u32 = 1 << 0;
pub const USBCMD_HCRST: u32 = 1 << 1;
pub const USBCMD_INTE: u32 = 1 << 2;
pub const USBCMD_HSEE: u32 = 1 << 3;

// USBSTS bits
pub const USBSTS_HCH: u32 = 1 << 0; // HC Halted
pub const USBSTS_HSE: u32 = 1 << 2; // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt
pub const USBSTS_PCD: u32 = 1 << 4; // Port Change Detect
pub const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// =============================================================================
// Port status/control register bits
// =============================================================================
pub const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
pub const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
pub const PORTSC_OCA: u32 = 1 << 3; // Over-current Active
pub const PORTSC_PR: u32 = 1 << 4; // Port Reset
pub const PORTSC_PP: u32 = 1 << 9; // Port Power
pub const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change
pub const PORTSC_PEC: u32 = 1 << 18; // Port Enabled/Disabled Change
pub const PORTSC_WRC: u32 = 1 << 19; // Warm Port Reset Change
pub const PORTSC_OCC: u32 = 1 << 20; // Over-current Change
pub const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change
pub const PORTSC_PLC: u32 = 1 << 22; // Port Link State Change
pub const PORTSC_CEC: u32 = 1 << 23; // Port Config Error Change

// Port speed values (PORTSC bits 13:10)
pub const PORT_SPEED_MASK: u32 = 0xF << 10;
pub const PORT_SPEED_FULL: u32 = 1 << 10; // USB 1.1 Full Speed (12 Mbps)
pub const PORT_SPEED_LOW: u32 = 2 << 10; // USB 1.1 Low Speed (1.5 Mbps)
pub const PORT_SPEED_HIGH: u32 = 3 << 10; // USB 2.0 High Speed (480 Mbps)
pub const PORT_SPEED_SUPER: u32 = 4 << 10; // USB 3.0 SuperSpeed (5 Gbps)

// =============================================================================
// TRB (Transfer Request Block) — fundamental xHCI data structure
// =============================================================================

/// A TRB is 16 bytes and forms the building block of all xHCI rings
pub const Trb = extern struct {
    parameter: u64,
    status: u32,
    control: u32,

    /// Get the TRB type (bits 15:10 of control)
    pub fn trbType(self: Trb) u6 {
        return @truncate((self.control >> 10) & 0x3F);
    }

    /// Get the cycle bit (bit 0 of control)
    pub fn cycleBit(self: Trb) bool {
        return (self.control & 1) != 0;
    }

    /// Create a No-Op Command TRB
    pub fn noopCommand(cycle: bool) Trb {
        return Trb{
            .parameter = 0,
            .status = 0,
            .control = (23 << 10) | @as(u32, @intFromBool(cycle)),
        };
    }

    /// Create an Enable Slot Command TRB
    pub fn enableSlot(cycle: bool) Trb {
        return Trb{
            .parameter = 0,
            .status = 0,
            .control = (9 << 10) | @as(u32, @intFromBool(cycle)),
        };
    }

    /// Create an Address Device Command TRB
    pub fn addressDevice(input_context_ptr: u64, slot_id: u8, cycle: bool) Trb {
        return Trb{
            .parameter = input_context_ptr,
            .status = 0,
            .control = (11 << 10) | (@as(u32, slot_id) << 24) | @as(u32, @intFromBool(cycle)),
        };
    }

    /// Create a Link TRB (points to the start of the ring for wrap-around)
    pub fn link(ring_base: u64, toggle_cycle: bool, cycle: bool) Trb {
        var ctrl: u32 = (6 << 10) | @as(u32, @intFromBool(cycle));
        if (toggle_cycle) ctrl |= (1 << 1);
        return Trb{
            .parameter = ring_base,
            .status = 0,
            .control = ctrl,
        };
    }
};

// TRB types
pub const TRB_NORMAL: u6 = 1;
pub const TRB_SETUP_STAGE: u6 = 2;
pub const TRB_DATA_STAGE: u6 = 3;
pub const TRB_STATUS_STAGE: u6 = 4;
pub const TRB_ISOCH: u6 = 5;
pub const TRB_LINK: u6 = 6;
pub const TRB_EVENT_DATA: u6 = 7;
pub const TRB_NOOP: u6 = 8;
pub const TRB_ENABLE_SLOT: u6 = 9;
pub const TRB_DISABLE_SLOT: u6 = 10;
pub const TRB_ADDRESS_DEVICE: u6 = 11;
pub const TRB_CONFIGURE_EP: u6 = 12;
pub const TRB_EVALUATE_CTX: u6 = 13;
pub const TRB_RESET_EP: u6 = 14;
pub const TRB_STOP_EP: u6 = 15;
pub const TRB_TRANSFER_EVENT: u6 = 32;
pub const TRB_COMMAND_COMPLETION: u6 = 33;
pub const TRB_PORT_STATUS_CHANGE: u6 = 34;

// TRB completion codes
pub const TRB_CC_SUCCESS: u8 = 1;
pub const TRB_CC_DATA_BUFFER_ERROR: u8 = 2;
pub const TRB_CC_BABBLE_DETECTED: u8 = 3;
pub const TRB_CC_USB_TRANSACTION_ERROR: u8 = 4;
pub const TRB_CC_TRB_ERROR: u8 = 5;
pub const TRB_CC_STALL_ERROR: u8 = 6;
pub const TRB_CC_SHORT_PACKET: u8 = 13;

// =============================================================================
// USB device descriptor structures
// =============================================================================

pub const UsbDeviceDescriptor = extern struct {
    length: u8,
    descriptor_type: u8,
    usb_version: u16,
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    max_packet_size_0: u8,
    vendor_id: u16,
    product_id: u16,
    device_version: u16,
    manufacturer_index: u8,
    product_index: u8,
    serial_number_index: u8,
    num_configurations: u8,
};

pub const UsbConfigDescriptor = extern struct {
    length: u8,
    descriptor_type: u8,
    total_length: u16,
    num_interfaces: u8,
    configuration_value: u8,
    configuration_index: u8,
    attributes: u8,
    max_power: u8,
};

pub const UsbInterfaceDescriptor = extern struct {
    length: u8,
    descriptor_type: u8,
    interface_number: u8,
    alternate_setting: u8,
    num_endpoints: u8,
    interface_class: u8,
    interface_subclass: u8,
    interface_protocol: u8,
    interface_index: u8,
};

pub const UsbEndpointDescriptor = extern struct {
    length: u8,
    descriptor_type: u8,
    endpoint_address: u8,
    attributes: u8,
    max_packet_size: u16,
    interval: u8,
};

// USB descriptor types
pub const USB_DESC_DEVICE: u8 = 1;
pub const USB_DESC_CONFIGURATION: u8 = 2;
pub const USB_DESC_STRING: u8 = 3;
pub const USB_DESC_INTERFACE: u8 = 4;
pub const USB_DESC_ENDPOINT: u8 = 5;
pub const USB_DESC_HID: u8 = 0x21;
pub const USB_DESC_REPORT: u8 = 0x22;

// USB device classes
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;
pub const USB_CLASS_HUB: u8 = 0x09;
pub const USB_CLASS_CDC: u8 = 0x0A;
pub const USB_CLASS_VENDOR: u8 = 0xFF;

// USB endpoint types (attributes bits 1:0)
pub const USB_EP_CONTROL: u8 = 0;
pub const USB_EP_ISOCHRONOUS: u8 = 1;
pub const USB_EP_BULK: u8 = 2;
pub const USB_EP_INTERRUPT: u8 = 3;

// =============================================================================
// USB setup packet (8 bytes)
// =============================================================================

pub const UsbSetupPacket = extern struct {
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,

    /// GET_DESCRIPTOR request
    pub fn getDescriptor(desc_type: u8, desc_index: u8, length: u16) UsbSetupPacket {
        return UsbSetupPacket{
            .request_type = 0x80, // Device-to-host, standard, device
            .request = 6, // GET_DESCRIPTOR
            .value = (@as(u16, desc_type) << 8) | @as(u16, desc_index),
            .index = 0,
            .length = length,
        };
    }

    /// SET_ADDRESS request
    pub fn setAddress(address: u8) UsbSetupPacket {
        return UsbSetupPacket{
            .request_type = 0x00,
            .request = 5, // SET_ADDRESS
            .value = @as(u16, address),
            .index = 0,
            .length = 0,
        };
    }

    /// SET_CONFIGURATION request
    pub fn setConfiguration(config: u8) UsbSetupPacket {
        return UsbSetupPacket{
            .request_type = 0x00,
            .request = 9, // SET_CONFIGURATION
            .value = @as(u16, config),
            .index = 0,
            .length = 0,
        };
    }
};

// =============================================================================
// USB device state tracking
// =============================================================================

pub const MAX_USB_DEVICES: usize = 127;

pub const UsbSpeed = enum(u8) {
    full = 1,
    low = 2,
    high = 3,
    super_speed = 4,
    unknown = 0,
};

pub const UsbDeviceState = enum(u8) {
    detached = 0,
    attached = 1,
    powered = 2,
    default = 3,
    addressed = 4,
    configured = 5,
    suspended = 6,
};

pub const UsbDevice = struct {
    slot_id: u8,
    port: u8,
    speed: UsbSpeed,
    state: UsbDeviceState,
    address: u8,
    vendor_id: u16,
    product_id: u16,
    device_class: u8,
    device_subclass: u8,
    max_packet_size_0: u16,
    num_configurations: u8,
    active: bool,
};

var usb_devices: [MAX_USB_DEVICES]UsbDevice = undefined;
var usb_device_count: usize = 0;

// =============================================================================
// xHCI controller state
// =============================================================================

var xhci_base: usize = 0;
var xhci_op_base: usize = 0;
var xhci_rt_base: usize = 0;
var xhci_db_base: usize = 0;
var xhci_max_slots: u8 = 0;
var xhci_max_ports: u8 = 0;
var xhci_initialized: bool = false;

// =============================================================================
// MMIO register access
// =============================================================================

fn readReg32(base: usize, offset: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(base + offset);
    return ptr.*;
}

fn writeReg32(base: usize, offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(base + offset);
    ptr.* = value;
}

fn readReg64(base: usize, offset: u32) u64 {
    const ptr: *volatile u64 = @ptrFromInt(base + offset);
    return ptr.*;
}

fn writeReg64(base: usize, offset: u32, value: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(base + offset);
    ptr.* = value;
}

// =============================================================================
// Public API
// =============================================================================

/// Initialize the USB subsystem by scanning PCI for xHCI controllers
pub fn initialize() void {
    // Reset device tracking
    for (&usb_devices) |*dev| {
        dev.* = std.mem.zeroes(UsbDevice);
    }
    usb_device_count = 0;

    // Search PCI for xHCI controllers (class 0x0C, subclass 0x03, prog IF 0x30)
    const xhci_dev = pci.findDevice(0x0C, 0x03, 0x30);
    if (xhci_dev == null) {
        main.klog(.info, "USB: No xHCI controller found on PCI bus", .{});
        return;
    }

    const dev = xhci_dev.?;
    main.klog(.info, "USB: Found xHCI controller at PCI {d}:{d}.{d}", .{
        dev.bus,
        dev.device,
        dev.function,
    });

    // Read BAR0 for MMIO base address
    const bar0 = pci.readBar(dev.bus, dev.device, dev.function, 0);
    if (bar0 == 0) {
        main.klog(.err, "USB: xHCI BAR0 is zero — cannot initialize", .{});
        return;
    }

    // Map MMIO (BAR0 gives the physical address, add higher-half offset)
    xhci_base = (bar0 & 0xFFFFFFF0) + 0xFFFFFFFF80000000;

    // Read capability registers
    const caplength = readReg32(xhci_base, XHCI_CAPLENGTH) & 0xFF;
    const hciversion = readReg32(xhci_base, XHCI_HCIVERSION) >> 16;
    const hcsparams1 = readReg32(xhci_base, XHCI_HCSPARAMS1);

    xhci_max_slots = @truncate(hcsparams1 & 0xFF);
    xhci_max_ports = @truncate((hcsparams1 >> 24) & 0xFF);
    xhci_op_base = xhci_base + caplength;

    const dboff = readReg32(xhci_base, XHCI_DBOFF);
    const rtsoff = readReg32(xhci_base, XHCI_RTSOFF);
    xhci_db_base = xhci_base + dboff;
    xhci_rt_base = xhci_base + rtsoff;

    main.klog(.info, "USB: xHCI v{x}.{x}, {d} slots, {d} ports", .{
        hciversion >> 8,
        hciversion & 0xFF,
        xhci_max_slots,
        xhci_max_ports,
    });

    // Enable PCI bus mastering
    pci.enableBusMastering(dev.bus, dev.device, dev.function);

    // Reset the controller
    resetController();

    xhci_initialized = true;
    main.klog(.info, "USB: xHCI controller initialized", .{});
}

/// Reset the xHCI controller
fn resetController() void {
    // Stop the controller
    var cmd = readReg32(xhci_op_base, XHCI_USBCMD);
    cmd &= ~USBCMD_RUN;
    writeReg32(xhci_op_base, XHCI_USBCMD, cmd);

    // Wait for halt
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const sts = readReg32(xhci_op_base, XHCI_USBSTS);
        if (sts & USBSTS_HCH != 0) break;
    }

    // Reset
    cmd = readReg32(xhci_op_base, XHCI_USBCMD);
    cmd |= USBCMD_HCRST;
    writeReg32(xhci_op_base, XHCI_USBCMD, cmd);

    // Wait for reset to complete
    timeout = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const c = readReg32(xhci_op_base, XHCI_USBCMD);
        if (c & USBCMD_HCRST == 0) break;
    }

    // Wait for CNR (Controller Not Ready) to clear
    timeout = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const sts = readReg32(xhci_op_base, XHCI_USBSTS);
        if (sts & USBSTS_CNR == 0) break;
    }
}

/// Get port status
pub fn getPortStatus(port: u8) u32 {
    if (!xhci_initialized or port == 0 or port > xhci_max_ports) return 0;
    const offset: u32 = 0x400 + (@as(u32, port - 1) * 0x10);
    return readReg32(xhci_op_base, offset);
}

/// Check if a device is connected to a port
pub fn isDeviceConnected(port: u8) bool {
    const status = getPortStatus(port);
    return (status & PORTSC_CCS) != 0;
}

/// Get the speed of a device on a port
pub fn getPortSpeed(port: u8) UsbSpeed {
    const status = getPortStatus(port);
    const speed_bits = (status & PORT_SPEED_MASK) >> 10;
    return switch (speed_bits) {
        1 => .full,
        2 => .low,
        3 => .high,
        4 => .super_speed,
        else => .unknown,
    };
}

/// Get the number of connected USB devices
pub fn deviceCount() usize {
    return usb_device_count;
}

/// Check if the USB subsystem is initialized
pub fn isInitialized() bool {
    return xhci_initialized;
}

/// Get the maximum number of USB ports
pub fn maxPorts() u8 {
    return xhci_max_ports;
}

const std = @import("std");
