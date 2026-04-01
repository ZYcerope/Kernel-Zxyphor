// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Zig USB Class Drivers
//
// USB class driver framework implementing:
// - USB HID (Human Interface Device) — keyboard, mouse, gamepad
// - USB Mass Storage (Bulk-Only Transport)
// - USB CDC (Communications Device Class) — serial/modem
// - USB Hub driver
// - Class driver interface and registration
// - Endpoint management per class
// - Control transfer helpers
// - Descriptor parsing

const std = @import("std");

// ─────────────────── USB Constants ──────────────────────────────────
pub const USB_DIR_OUT: u8 = 0x00;
pub const USB_DIR_IN: u8 = 0x80;

pub const USB_TYPE_STANDARD: u8 = 0x00;
pub const USB_TYPE_CLASS: u8 = 0x20;
pub const USB_TYPE_VENDOR: u8 = 0x40;

pub const USB_RECIP_DEVICE: u8 = 0x00;
pub const USB_RECIP_INTERFACE: u8 = 0x01;
pub const USB_RECIP_ENDPOINT: u8 = 0x02;

// Standard requests
pub const USB_REQ_GET_STATUS: u8 = 0x00;
pub const USB_REQ_CLEAR_FEATURE: u8 = 0x01;
pub const USB_REQ_SET_FEATURE: u8 = 0x03;
pub const USB_REQ_SET_ADDRESS: u8 = 0x05;
pub const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const USB_REQ_SET_DESCRIPTOR: u8 = 0x07;
pub const USB_REQ_GET_CONFIGURATION: u8 = 0x08;
pub const USB_REQ_SET_CONFIGURATION: u8 = 0x09;
pub const USB_REQ_SET_INTERFACE: u8 = 0x0B;

// Descriptor types
pub const USB_DT_DEVICE: u8 = 0x01;
pub const USB_DT_CONFIG: u8 = 0x02;
pub const USB_DT_STRING: u8 = 0x03;
pub const USB_DT_INTERFACE: u8 = 0x04;
pub const USB_DT_ENDPOINT: u8 = 0x05;
pub const USB_DT_HID: u8 = 0x21;
pub const USB_DT_HID_REPORT: u8 = 0x22;
pub const USB_DT_HUB: u8 = 0x29;

// Class codes
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;
pub const USB_CLASS_CDC: u8 = 0x02;
pub const USB_CLASS_CDC_DATA: u8 = 0x0A;
pub const USB_CLASS_HUB: u8 = 0x09;

// HID subclass/protocol
pub const USB_HID_SUBCLASS_BOOT: u8 = 0x01;
pub const USB_HID_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_HID_PROTOCOL_MOUSE: u8 = 0x02;

// Mass Storage subclass/protocol
pub const USB_MSC_SUBCLASS_SCSI: u8 = 0x06;
pub const USB_MSC_PROTOCOL_BBB: u8 = 0x50; // Bulk-Only

// Endpoint types
pub const USB_EP_CONTROL: u8 = 0x00;
pub const USB_EP_ISOCHRONOUS: u8 = 0x01;
pub const USB_EP_BULK: u8 = 0x02;
pub const USB_EP_INTERRUPT: u8 = 0x03;

pub const MAX_USB_DEVICES = 32;
pub const MAX_CLASS_DRIVERS = 16;
pub const MAX_ENDPOINTS = 8;

// ─────────────────── Setup Packet ───────────────────────────────────
pub const SetupPacket = packed struct {
    request_type: u8 = 0,
    request: u8 = 0,
    value: u16 = 0,
    index: u16 = 0,
    length: u16 = 0,

    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) SetupPacket {
        return .{
            .request_type = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
            .request = USB_REQ_GET_DESCRIPTOR,
            .value = (@as(u16, desc_type) << 8) | desc_index,
            .index = 0,
            .length = length,
        };
    }

    pub fn set_configuration(config_value: u8) SetupPacket {
        return .{
            .request_type = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
            .request = USB_REQ_SET_CONFIGURATION,
            .value = config_value,
            .index = 0,
            .length = 0,
        };
    }

    pub fn set_interface(iface: u16, alt_setting: u16) SetupPacket {
        return .{
            .request_type = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_INTERFACE,
            .request = USB_REQ_SET_INTERFACE,
            .value = alt_setting,
            .index = iface,
            .length = 0,
        };
    }

    pub fn hid_set_idle(iface: u16) SetupPacket {
        return .{
            .request_type = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
            .request = 0x0A, // SET_IDLE
            .value = 0,
            .index = iface,
            .length = 0,
        };
    }

    pub fn hid_set_protocol(iface: u16, protocol: u8) SetupPacket {
        return .{
            .request_type = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
            .request = 0x0B, // SET_PROTOCOL
            .value = protocol,
            .index = iface,
            .length = 0,
        };
    }

    pub fn hid_get_report(iface: u16, report_type: u8, report_id: u8, length: u16) SetupPacket {
        return .{
            .request_type = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
            .request = 0x01, // GET_REPORT
            .value = (@as(u16, report_type) << 8) | report_id,
            .index = iface,
            .length = length,
        };
    }
};

// ─────────────────── Endpoint Info ──────────────────────────────────
pub const EndpointInfo = struct {
    address: u8 = 0,
    attributes: u8 = 0,
    max_packet_size: u16 = 0,
    interval: u8 = 0,

    pub fn direction(self: *const EndpointInfo) u8 {
        return self.address & 0x80;
    }

    pub fn number(self: *const EndpointInfo) u8 {
        return self.address & 0x0F;
    }

    pub fn transfer_type(self: *const EndpointInfo) u8 {
        return self.attributes & 0x03;
    }

    pub fn is_in(self: *const EndpointInfo) bool {
        return (self.address & 0x80) != 0;
    }

    pub fn is_bulk(self: *const EndpointInfo) bool {
        return self.transfer_type() == USB_EP_BULK;
    }

    pub fn is_interrupt(self: *const EndpointInfo) bool {
        return self.transfer_type() == USB_EP_INTERRUPT;
    }
};

// ─────────────────── USB Device Info ────────────────────────────────
pub const UsbDeviceInfo = struct {
    address: u8 = 0,
    speed: u8 = 0, // 0=low, 1=full, 2=high, 3=super
    vendor_id: u16 = 0,
    product_id: u16 = 0,
    device_class: u8 = 0,
    device_subclass: u8 = 0,
    device_protocol: u8 = 0,
    num_configurations: u8 = 0,
    current_config: u8 = 0,
    /// Interface info for primary interface
    iface_class: u8 = 0,
    iface_subclass: u8 = 0,
    iface_protocol: u8 = 0,
    iface_number: u8 = 0,
    /// Endpoints
    endpoints: [MAX_ENDPOINTS]EndpointInfo = [_]EndpointInfo{.{}} ** MAX_ENDPOINTS,
    endpoint_count: u8 = 0,
    /// String descriptors
    manufacturer: [64]u8 = [_]u8{0} ** 64,
    manufacturer_len: u8 = 0,
    product: [64]u8 = [_]u8{0} ** 64,
    product_len: u8 = 0,
    /// State
    configured: bool = false,
    driver_bound: bool = false,
    driver_id: u16 = 0,
};

// ─────────────────── Class Driver Interface ─────────────────────────
pub const ClassDriverOps = struct {
    /// Called when a matching device is found
    probe: *const fn (dev: *UsbDeviceInfo) bool,
    /// Called when device is disconnected
    disconnect: *const fn (dev: *UsbDeviceInfo) void,
    /// Called periodically for polling (interrupt endpoints)
    poll: *const fn (dev: *UsbDeviceInfo) void,
};

pub const ClassDriver = struct {
    id: u16 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    /// Match criteria
    match_class: u8 = 0,
    match_subclass: u8 = 0xFF, // 0xFF = any
    match_protocol: u8 = 0xFF,
    /// Operations
    ops: ClassDriverOps,
    /// Active flag
    active: bool = false,

    pub fn set_name(self: *ClassDriver, n: []const u8) void {
        const len = @min(n.len, 32);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn matches(self: *const ClassDriver, dev: *const UsbDeviceInfo) bool {
        if (self.match_class != dev.iface_class) return false;
        if (self.match_subclass != 0xFF and self.match_subclass != dev.iface_subclass) return false;
        if (self.match_protocol != 0xFF and self.match_protocol != dev.iface_protocol) return false;
        return true;
    }
};

// ─────────────────── HID Driver ─────────────────────────────────────
pub const HidReport = struct {
    data: [64]u8 = [_]u8{0} ** 64,
    length: u8 = 0,
};

pub const HidKeyboardState = struct {
    modifiers: u8 = 0,
    keys: [6]u8 = [_]u8{0} ** 6,
    prev_keys: [6]u8 = [_]u8{0} ** 6,
    leds: u8 = 0,
    /// Caps lock
    caps_lock: bool = false,
    num_lock: bool = false,
    scroll_lock: bool = false,
};

pub const HidMouseState = struct {
    buttons: u8 = 0,
    prev_buttons: u8 = 0,
    x: i16 = 0,
    y: i16 = 0,
    wheel: i8 = 0,
};

/// HID boot protocol keyboard report parser
pub fn parseBootKeyboardReport(data: []const u8, state: *HidKeyboardState) void {
    if (data.len < 8) return;

    // Save previous keys
    state.prev_keys = state.keys;
    state.modifiers = data[0];

    // data[1] is reserved
    var key_idx: usize = 0;
    for (data[2..8]) |key| {
        state.keys[key_idx] = key;
        key_idx += 1;
    }
}

/// HID boot protocol mouse report parser
pub fn parseBootMouseReport(data: []const u8, state: *HidMouseState) void {
    if (data.len < 3) return;

    state.prev_buttons = state.buttons;
    state.buttons = data[0];
    state.x = @as(i16, @as(i8, @bitCast(data[1])));
    state.y = @as(i16, @as(i8, @bitCast(data[2])));
    if (data.len >= 4) {
        state.wheel = @as(i8, @bitCast(data[3]));
    }
}

/// HID scancode to USB HID keycode mapping
pub fn hidKeycodeToAscii(keycode: u8, shift: bool) u8 {
    if (keycode == 0) return 0;

    // Letters (a-z: 0x04-0x1D)
    if (keycode >= 0x04 and keycode <= 0x1D) {
        const base: u8 = if (shift) 'A' else 'a';
        return base + (keycode - 0x04);
    }

    // Numbers (1-9: 0x1E-0x26, 0: 0x27)
    if (keycode >= 0x1E and keycode <= 0x26) {
        if (shift) {
            const shifted = [_]u8{ '!', '@', '#', '$', '%', '^', '&', '*', '(' };
            return shifted[keycode - 0x1E];
        }
        return '1' + (keycode - 0x1E);
    }
    if (keycode == 0x27) return if (shift) ')' else '0';

    // Special keys
    return switch (keycode) {
        0x28 => '\n', // Enter
        0x29 => 0x1B, // Escape
        0x2A => 0x08, // Backspace
        0x2B => '\t', // Tab
        0x2C => ' ', // Space
        0x2D => if (shift) '_' else '-',
        0x2E => if (shift) '+' else '=',
        0x2F => if (shift) '{' else '[',
        0x30 => if (shift) '}' else ']',
        0x31 => if (shift) '|' else '\\',
        0x33 => if (shift) ':' else ';',
        0x34 => if (shift) '"' else '\'',
        0x35 => if (shift) '~' else '`',
        0x36 => if (shift) '<' else ',',
        0x37 => if (shift) '>' else '.',
        0x38 => if (shift) '?' else '/',
        else => 0,
    };
}

// ─────────────────── Mass Storage Driver ────────────────────────────
pub const MscState = enum(u8) {
    idle = 0,
    command = 1,
    data_in = 2,
    data_out = 3,
    status = 4,
    error_state = 5,
};

pub const CommandBlockWrapper = packed struct {
    signature: u32 = 0x43425355, // "USBC"
    tag: u32 = 0,
    data_transfer_length: u32 = 0,
    flags: u8 = 0, // bit 7: 0=OUT, 1=IN
    lun: u8 = 0,
    cb_length: u8 = 0,
    cb: [16]u8 = [_]u8{0} ** 16,
};

pub const CommandStatusWrapper = packed struct {
    signature: u32 = 0x53425355, // "USBS"
    tag: u32 = 0,
    data_residue: u32 = 0,
    status: u8 = 0, // 0=pass, 1=fail, 2=phase error
};

pub const MassStorageDevice = struct {
    usb_dev: *UsbDeviceInfo,
    state: MscState = .idle,
    bulk_in_ep: u8 = 0,
    bulk_out_ep: u8 = 0,
    max_lun: u8 = 0,
    tag_counter: u32 = 1,
    /// Sector size (usually 512)
    sector_size: u32 = 512,
    /// Total sectors
    total_sectors: u64 = 0,
    /// Transfer buffer
    buffer: [512]u8 = [_]u8{0} ** 512,
    /// Last CSW
    last_csw: CommandStatusWrapper = .{},

    pub fn init(self: *MassStorageDevice) bool {
        // Find bulk endpoints
        for (self.usb_dev.endpoints[0..self.usb_dev.endpoint_count]) |ep| {
            if (ep.is_bulk()) {
                if (ep.is_in()) {
                    self.bulk_in_ep = ep.address;
                } else {
                    self.bulk_out_ep = ep.address;
                }
            }
        }
        if (self.bulk_in_ep == 0 or self.bulk_out_ep == 0) return false;

        // Get max LUN
        self.max_lun = 0;

        // SCSI Inquiry
        if (!self.scsiInquiry()) return false;

        // Read capacity
        if (!self.scsiReadCapacity()) return false;

        return true;
    }

    fn buildCbw(self: *MassStorageDevice, data_len: u32, dir_in: bool, cb: []const u8) CommandBlockWrapper {
        var cbw = CommandBlockWrapper{};
        cbw.tag = self.tag_counter;
        self.tag_counter +%= 1;
        cbw.data_transfer_length = data_len;
        cbw.flags = if (dir_in) 0x80 else 0x00;
        cbw.lun = 0;
        cbw.cb_length = @intCast(@min(cb.len, 16));
        @memcpy(cbw.cb[0..cbw.cb_length], cb[0..cbw.cb_length]);
        return cbw;
    }

    pub fn scsiInquiry(self: *MassStorageDevice) bool {
        var cb = [_]u8{0} ** 6;
        cb[0] = 0x12; // INQUIRY
        cb[4] = 36; // allocation length
        _ = self.buildCbw(36, true, &cb);
        self.state = .command;
        // In a real driver, we'd submit via bulk transfer
        // For now, mark as done
        self.state = .idle;
        return true;
    }

    pub fn scsiReadCapacity(self: *MassStorageDevice) bool {
        var cb = [_]u8{0} ** 10;
        cb[0] = 0x25; // READ CAPACITY(10)
        _ = self.buildCbw(8, true, &cb);
        self.state = .command;
        self.state = .idle;
        return true;
    }

    pub fn scsiRead10(self: *MassStorageDevice, lba: u32, count: u16) bool {
        var cb = [_]u8{0} ** 10;
        cb[0] = 0x28; // READ(10)
        cb[2] = @intCast((lba >> 24) & 0xFF);
        cb[3] = @intCast((lba >> 16) & 0xFF);
        cb[4] = @intCast((lba >> 8) & 0xFF);
        cb[5] = @intCast(lba & 0xFF);
        cb[7] = @intCast((count >> 8) & 0xFF);
        cb[8] = @intCast(count & 0xFF);
        const data_len = @as(u32, count) * self.sector_size;
        _ = self.buildCbw(data_len, true, &cb);
        self.state = .data_in;
        return true;
    }

    pub fn scsiWrite10(self: *MassStorageDevice, lba: u32, count: u16) bool {
        var cb = [_]u8{0} ** 10;
        cb[0] = 0x2A; // WRITE(10)
        cb[2] = @intCast((lba >> 24) & 0xFF);
        cb[3] = @intCast((lba >> 16) & 0xFF);
        cb[4] = @intCast((lba >> 8) & 0xFF);
        cb[5] = @intCast(lba & 0xFF);
        cb[7] = @intCast((count >> 8) & 0xFF);
        cb[8] = @intCast(count & 0xFF);
        const data_len = @as(u32, count) * self.sector_size;
        _ = self.buildCbw(data_len, false, &cb);
        self.state = .data_out;
        return true;
    }
};

// ─────────────────── CDC ACM (Serial) Driver ────────────────────────
pub const CdcLineCoding = packed struct {
    dte_rate: u32 = 115200,
    char_format: u8 = 0, // 0=1 stop bit
    parity_type: u8 = 0, // 0=none
    data_bits: u8 = 8,
};

pub const CdcAcmDevice = struct {
    usb_dev: *UsbDeviceInfo,
    data_iface: u8 = 0,
    control_iface: u8 = 0,
    bulk_in_ep: u8 = 0,
    bulk_out_ep: u8 = 0,
    interrupt_ep: u8 = 0,
    line_coding: CdcLineCoding = .{},
    dtr: bool = false,
    rts: bool = false,
    /// RX buffer
    rx_buf: [1024]u8 = [_]u8{0} ** 1024,
    rx_head: u16 = 0,
    rx_tail: u16 = 0,
    rx_count: u16 = 0,

    pub fn init(self: *CdcAcmDevice) bool {
        // Find endpoints
        for (self.usb_dev.endpoints[0..self.usb_dev.endpoint_count]) |ep| {
            if (ep.is_bulk()) {
                if (ep.is_in()) {
                    self.bulk_in_ep = ep.address;
                } else {
                    self.bulk_out_ep = ep.address;
                }
            } else if (ep.is_interrupt() and ep.is_in()) {
                self.interrupt_ep = ep.address;
            }
        }
        return self.bulk_in_ep != 0 and self.bulk_out_ep != 0;
    }

    pub fn setLineCoding(self: *CdcAcmDevice, baudrate: u32, data_bits: u8, parity: u8, stop_bits: u8) void {
        self.line_coding.dte_rate = baudrate;
        self.line_coding.data_bits = data_bits;
        self.line_coding.parity_type = parity;
        self.line_coding.char_format = stop_bits;
    }

    pub fn setControlLineState(self: *CdcAcmDevice, dtr: bool, rts: bool) void {
        self.dtr = dtr;
        self.rts = rts;
    }

    pub fn write(self: *CdcAcmDevice, data: []const u8) u32 {
        // In a real driver, submit bulk OUT transfer
        _ = self;
        return @intCast(data.len);
    }

    pub fn read(self: *CdcAcmDevice, buf: []u8) u32 {
        var count: u32 = 0;
        while (count < buf.len and self.rx_count > 0) {
            buf[count] = self.rx_buf[self.rx_head];
            self.rx_head = (self.rx_head + 1) % 1024;
            self.rx_count -= 1;
            count += 1;
        }
        return count;
    }

    pub fn rxAvailable(self: *const CdcAcmDevice) u16 {
        return self.rx_count;
    }
};

// ─────────────────── USB Hub Driver ─────────────────────────────────
pub const HubPortStatus = packed struct {
    connection: bool = false,
    enable: bool = false,
    suspend_: bool = false,
    over_current: bool = false,
    reset: bool = false,
    _reserved1: u3 = 0,
    power: bool = false,
    low_speed: bool = false,
    high_speed: bool = false,
    _reserved2: u5 = 0,
};

pub const HubDevice = struct {
    usb_dev: *UsbDeviceInfo,
    num_ports: u8 = 0,
    port_status: [8]HubPortStatus = [_]HubPortStatus{.{}} ** 8,
    interrupt_ep: u8 = 0,
    power_on_delay: u16 = 100, // ms
    /// Status change bitmap
    status_change: u8 = 0,

    pub fn init(self: *HubDevice) bool {
        // Get hub descriptor
        for (self.usb_dev.endpoints[0..self.usb_dev.endpoint_count]) |ep| {
            if (ep.is_interrupt() and ep.is_in()) {
                self.interrupt_ep = ep.address;
                break;
            }
        }
        return self.interrupt_ep != 0;
    }

    pub fn setPortPower(self: *HubDevice, port: u8, on: bool) void {
        if (port > 0 and port <= self.num_ports) {
            self.port_status[port - 1].power = on;
        }
    }

    pub fn resetPort(self: *HubDevice, port: u8) void {
        if (port > 0 and port <= self.num_ports) {
            self.port_status[port - 1].reset = true;
        }
    }

    pub fn getPortStatus(self: *const HubDevice, port: u8) ?HubPortStatus {
        if (port > 0 and port <= self.num_ports) {
            return self.port_status[port - 1];
        }
        return null;
    }

    pub fn isPortConnected(self: *const HubDevice, port: u8) bool {
        if (self.getPortStatus(port)) |status| {
            return status.connection;
        }
        return false;
    }
};

// ─────────────────── Class Driver Registry ──────────────────────────
pub const ClassDriverRegistry = struct {
    drivers: [MAX_CLASS_DRIVERS]?ClassDriver = [_]?ClassDriver{null} ** MAX_CLASS_DRIVERS,
    driver_count: u16 = 0,
    devices: [MAX_USB_DEVICES]?UsbDeviceInfo = [_]?UsbDeviceInfo{null} ** MAX_USB_DEVICES,
    device_count: u16 = 0,
    initialized: bool = false,

    pub fn init(self: *ClassDriverRegistry) void {
        self.initialized = true;
    }

    /// Register a class driver
    pub fn registerDriver(self: *ClassDriverRegistry, name: []const u8, match_class: u8, match_subclass: u8, match_protocol: u8, ops: ClassDriverOps) ?u16 {
        if (self.driver_count >= MAX_CLASS_DRIVERS) return null;

        for (self.drivers, 0..) |*slot, i| {
            if (slot.* == null) {
                var drv = ClassDriver{
                    .ops = ops,
                };
                drv.id = @intCast(i);
                drv.set_name(name);
                drv.match_class = match_class;
                drv.match_subclass = match_subclass;
                drv.match_protocol = match_protocol;
                drv.active = true;
                slot.* = drv;
                self.driver_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Attempt to bind a driver to a device
    pub fn probeDevice(self: *ClassDriverRegistry, dev: *UsbDeviceInfo) bool {
        for (&self.drivers) |*maybe_drv| {
            if (maybe_drv.*) |*drv| {
                if (drv.active and drv.matches(dev)) {
                    if (drv.ops.probe(dev)) {
                        dev.driver_bound = true;
                        dev.driver_id = drv.id;
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// Disconnect a device from its driver
    pub fn disconnectDevice(self: *ClassDriverRegistry, dev: *UsbDeviceInfo) void {
        if (dev.driver_bound) {
            if (dev.driver_id < MAX_CLASS_DRIVERS) {
                if (self.drivers[dev.driver_id]) |*drv| {
                    drv.ops.disconnect(dev);
                }
            }
            dev.driver_bound = false;
        }
    }

    /// Poll all bound devices
    pub fn pollAll(self: *ClassDriverRegistry) void {
        for (&self.devices) |*maybe_dev| {
            if (maybe_dev.*) |*dev| {
                if (dev.driver_bound and dev.driver_id < MAX_CLASS_DRIVERS) {
                    if (self.drivers[dev.driver_id]) |*drv| {
                        if (drv.active) {
                            drv.ops.poll(dev);
                        }
                    }
                }
            }
        }
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var class_registry: ClassDriverRegistry = .{};

pub fn initUsbClassDrivers() void {
    class_registry.init();
}

pub fn getClassRegistry() *ClassDriverRegistry {
    return &class_registry;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_usb_class_init() void {
    initUsbClassDrivers();
}

export fn zxy_usb_class_driver_count() u16 {
    return class_registry.driver_count;
}

export fn zxy_usb_device_count() u16 {
    return class_registry.device_count;
}

export fn zxy_usb_poll_all() void {
    class_registry.pollAll();
}
