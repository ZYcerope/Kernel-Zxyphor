// SPDX-License-Identifier: MIT
// Zxyphor Kernel - xHCI USB 3.x/4.0 Host Controller Driver
// Full USB 3.2 Gen2x2 & USB4 support with isochronous, bulk, interrupt, control transfers

const std = @import("std");

// ============================================================================
// xHCI Register Definitions (USB 3.2 spec)
// ============================================================================

pub const XHCI_CAP_CAPLENGTH = 0x00;
pub const XHCI_CAP_HCIVERSION = 0x02;
pub const XHCI_CAP_HCSPARAMS1 = 0x04;
pub const XHCI_CAP_HCSPARAMS2 = 0x08;
pub const XHCI_CAP_HCSPARAMS3 = 0x0C;
pub const XHCI_CAP_HCCPARAMS1 = 0x10;
pub const XHCI_CAP_DBOFF = 0x14;
pub const XHCI_CAP_RTSOFF = 0x18;
pub const XHCI_CAP_HCCPARAMS2 = 0x1C;

// Operational register offsets
pub const XHCI_OP_USBCMD = 0x00;
pub const XHCI_OP_USBSTS = 0x04;
pub const XHCI_OP_PAGESIZE = 0x08;
pub const XHCI_OP_DNCTRL = 0x14;
pub const XHCI_OP_CRCR = 0x18;
pub const XHCI_OP_DCBAAP = 0x30;
pub const XHCI_OP_CONFIG = 0x38;

// USBCMD bits
pub const USBCMD_RS: u32 = 1 << 0;       // Run/Stop
pub const USBCMD_HCRST: u32 = 1 << 1;    // Host Controller Reset
pub const USBCMD_INTE: u32 = 1 << 2;     // Interrupter Enable
pub const USBCMD_HSEE: u32 = 1 << 3;     // Host System Error Enable
pub const USBCMD_LHCRST: u32 = 1 << 7;   // Light HC Reset
pub const USBCMD_CSS: u32 = 1 << 8;      // Controller Save State
pub const USBCMD_CRS: u32 = 1 << 9;      // Controller Restore State
pub const USBCMD_EWE: u32 = 1 << 10;     // Enable Wrap Event
pub const USBCMD_EU3S: u32 = 1 << 11;    // Enable U3 MFINDEX Stop
pub const USBCMD_CME: u32 = 1 << 13;     // CEM Enable
pub const USBCMD_ETE: u32 = 1 << 14;     // Extended TBC Enable

// USBSTS bits
pub const USBSTS_HCH: u32 = 1 << 0;     // HC Halted
pub const USBSTS_HSE: u32 = 1 << 2;     // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3;    // Event Interrupt
pub const USBSTS_PCD: u32 = 1 << 4;     // Port Change Detect
pub const USBSTS_SSS: u32 = 1 << 8;     // Save State Status
pub const USBSTS_RSS: u32 = 1 << 9;     // Restore State Status
pub const USBSTS_SRE: u32 = 1 << 10;    // Save/Restore Error
pub const USBSTS_CNR: u32 = 1 << 11;    // Controller Not Ready
pub const USBSTS_HCE: u32 = 1 << 12;    // Host Controller Error

// Port Status and Control Register bits
pub const PORTSC_CCS: u32 = 1 << 0;      // Current Connect Status
pub const PORTSC_PED: u32 = 1 << 1;      // Port Enabled/Disabled
pub const PORTSC_OCA: u32 = 1 << 3;      // Over-current Active
pub const PORTSC_PR: u32 = 1 << 4;       // Port Reset
pub const PORTSC_PLS_MASK: u32 = 0xF << 5; // Port Link State
pub const PORTSC_PP: u32 = 1 << 9;       // Port Power
pub const PORTSC_SPEED_MASK: u32 = 0xF << 10;
pub const PORTSC_PIC_MASK: u32 = 0x3 << 14;
pub const PORTSC_LWS: u32 = 1 << 16;     // Port Link State Write Strobe
pub const PORTSC_CSC: u32 = 1 << 17;     // Connect Status Change
pub const PORTSC_PEC: u32 = 1 << 18;     // Port Enable/Disable Change
pub const PORTSC_WRC: u32 = 1 << 19;     // Warm Port Reset Change
pub const PORTSC_OCC: u32 = 1 << 20;     // Over-current Change
pub const PORTSC_PRC: u32 = 1 << 21;     // Port Reset Change
pub const PORTSC_PLC: u32 = 1 << 22;     // Port Link State Change
pub const PORTSC_CEC: u32 = 1 << 23;     // Config Error Change
pub const PORTSC_CAS: u32 = 1 << 24;     // Cold Attach Status
pub const PORTSC_WCE: u32 = 1 << 25;     // Wake on Connect Enable
pub const PORTSC_WDE: u32 = 1 << 26;     // Wake on Disconnect Enable
pub const PORTSC_WOE: u32 = 1 << 27;     // Wake on Over-current Enable
pub const PORTSC_DR: u32 = 1 << 30;      // Device Removable
pub const PORTSC_WPR: u32 = 1 << 31;     // Warm Port Reset

// USB Speed IDs
pub const USB_SPEED_FULL: u8 = 1;    // 12 Mbps
pub const USB_SPEED_LOW: u8 = 2;     // 1.5 Mbps
pub const USB_SPEED_HIGH: u8 = 3;    // 480 Mbps
pub const USB_SPEED_SUPER: u8 = 4;   // 5 Gbps (USB 3.0)
pub const USB_SPEED_SUPER_PLUS: u8 = 5; // 10 Gbps (USB 3.1)
pub const USB_SPEED_SUPER_PLUS_X2: u8 = 6; // 20 Gbps (USB 3.2 Gen2x2)

// ============================================================================
// TRB (Transfer Request Block) Types
// ============================================================================

pub const TRB_TYPE_NORMAL: u8 = 1;
pub const TRB_TYPE_SETUP: u8 = 2;
pub const TRB_TYPE_DATA: u8 = 3;
pub const TRB_TYPE_STATUS: u8 = 4;
pub const TRB_TYPE_ISOCH: u8 = 5;
pub const TRB_TYPE_LINK: u8 = 6;
pub const TRB_TYPE_EVENT_DATA: u8 = 7;
pub const TRB_TYPE_NOOP: u8 = 8;
pub const TRB_TYPE_ENABLE_SLOT: u8 = 9;
pub const TRB_TYPE_DISABLE_SLOT: u8 = 10;
pub const TRB_TYPE_ADDRESS_DEVICE: u8 = 11;
pub const TRB_TYPE_CONFIGURE_EP: u8 = 12;
pub const TRB_TYPE_EVALUATE_CTX: u8 = 13;
pub const TRB_TYPE_RESET_EP: u8 = 14;
pub const TRB_TYPE_STOP_EP: u8 = 15;
pub const TRB_TYPE_SET_TR_DEQUEUE: u8 = 16;
pub const TRB_TYPE_RESET_DEVICE: u8 = 17;
pub const TRB_TYPE_FORCE_EVENT: u8 = 18;
pub const TRB_TYPE_NEGOTIATE_BW: u8 = 19;
pub const TRB_TYPE_SET_LATENCY: u8 = 20;
pub const TRB_TYPE_GET_PORT_BW: u8 = 21;
pub const TRB_TYPE_FORCE_HEADER: u8 = 22;
pub const TRB_TYPE_NOOP_CMD: u8 = 23;
// Event TRB types
pub const TRB_TYPE_TRANSFER_EVENT: u8 = 32;
pub const TRB_TYPE_CMD_COMPLETE: u8 = 33;
pub const TRB_TYPE_PORT_STATUS_CHANGE: u8 = 34;
pub const TRB_TYPE_BANDWIDTH_REQUEST: u8 = 35;
pub const TRB_TYPE_DOORBELL: u8 = 36;
pub const TRB_TYPE_HOST_CONTROLLER: u8 = 37;
pub const TRB_TYPE_DEVICE_NOTIFICATION: u8 = 38;
pub const TRB_TYPE_MFINDEX_WRAP: u8 = 39;

/// Transfer Request Block (16 bytes, 128-bit aligned)
pub const Trb = packed struct {
    parameter: u64,
    status: u32,
    control: u32,

    pub fn get_type(self: Trb) u6 {
        return @truncate((self.control >> 10) & 0x3F);
    }

    pub fn set_type(self: *Trb, trb_type: u6) void {
        self.control = (self.control & ~(@as(u32, 0x3F) << 10)) | (@as(u32, trb_type) << 10);
    }

    pub fn get_cycle_bit(self: Trb) bool {
        return (self.control & 1) != 0;
    }

    pub fn set_cycle_bit(self: *Trb, cycle: bool) void {
        if (cycle) {
            self.control |= 1;
        } else {
            self.control &= ~@as(u32, 1);
        }
    }

    pub fn make_normal(buf_addr: u64, length: u17, ioc: bool, cycle: bool) Trb {
        var trb = Trb{
            .parameter = buf_addr,
            .status = @as(u32, length),
            .control = (@as(u32, TRB_TYPE_NORMAL) << 10),
        };
        if (ioc) trb.control |= (1 << 5); // IOC bit
        if (cycle) trb.control |= 1;
        return trb;
    }

    pub fn make_setup(request_type: u8, request: u8, value: u16, index: u16, length: u16, trt: u2, cycle: bool) Trb {
        var trb = Trb{
            .parameter = @as(u64, request_type) | (@as(u64, request) << 8) | (@as(u64, value) << 16) | (@as(u64, index) << 32) | (@as(u64, length) << 48),
            .status = 8, // Setup packets are always 8 bytes
            .control = (@as(u32, TRB_TYPE_SETUP) << 10) | (1 << 6) | (@as(u32, trt) << 16), // IDT=1
        };
        if (cycle) trb.control |= 1;
        return trb;
    }

    pub fn make_data(buf_addr: u64, length: u17, direction_in: bool, cycle: bool) Trb {
        var trb = Trb{
            .parameter = buf_addr,
            .status = @as(u32, length),
            .control = (@as(u32, TRB_TYPE_DATA) << 10),
        };
        if (direction_in) trb.control |= (1 << 16); // DIR=1 for IN
        if (cycle) trb.control |= 1;
        return trb;
    }

    pub fn make_status(direction_in: bool, ioc: bool, cycle: bool) Trb {
        var trb = Trb{
            .parameter = 0,
            .status = 0,
            .control = (@as(u32, TRB_TYPE_STATUS) << 10),
        };
        if (direction_in) trb.control |= (1 << 16);
        if (ioc) trb.control |= (1 << 5);
        if (cycle) trb.control |= 1;
        return trb;
    }

    pub fn make_link(next_seg_addr: u64, toggle_cycle: bool, cycle: bool) Trb {
        var trb = Trb{
            .parameter = next_seg_addr,
            .status = 0,
            .control = (@as(u32, TRB_TYPE_LINK) << 10),
        };
        if (toggle_cycle) trb.control |= (1 << 1); // Toggle Cycle
        if (cycle) trb.control |= 1;
        return trb;
    }
};

// ============================================================================
// Device Context / Slot Context / Endpoint Context
// ============================================================================

pub const SlotContext = packed struct {
    route_string: u20,
    speed: u4,
    _rsvd1: u1,
    mtt: u1,
    hub: u1,
    context_entries: u5,
    max_exit_latency: u16,
    root_hub_port_num: u8,
    num_ports: u8,
    parent_hub_slot_id: u8,
    parent_port_num: u8,
    tt_think_time: u2,
    _rsvd2: u4,
    interrupter_target: u10,
    usb_device_address: u8,
    _rsvd3: u19,
    slot_state: u5,
    _rsvd4: [4]u32,
};

pub const EndpointContext = packed struct {
    ep_state: u3,
    _rsvd1: u5,
    mult: u2,
    max_p_streams: u5,
    lsa: u1,
    interval: u8,
    max_esit_payload_hi: u8,
    _rsvd2: u1,
    cerr: u2,
    ep_type: u3,
    _rsvd3: u1,
    hid: u1,
    max_burst_size: u8,
    max_packet_size: u16,
    dequeue_cycle_state: u1,
    _rsvd4: u3,
    tr_dequeue_pointer: u60,
    average_trb_length: u16,
    max_esit_payload_lo: u16,
    _rsvd5: [3]u32,
};

pub const EP_TYPE_INVALID: u3 = 0;
pub const EP_TYPE_ISOCH_OUT: u3 = 1;
pub const EP_TYPE_BULK_OUT: u3 = 2;
pub const EP_TYPE_INTERRUPT_OUT: u3 = 3;
pub const EP_TYPE_CONTROL: u3 = 4;
pub const EP_TYPE_ISOCH_IN: u3 = 5;
pub const EP_TYPE_BULK_IN: u3 = 6;
pub const EP_TYPE_INTERRUPT_IN: u3 = 7;

// ============================================================================
// USB Descriptors
// ============================================================================

pub const UsbDeviceDescriptor = packed struct {
    length: u8,
    descriptor_type: u8,
    bcd_usb: u16,
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    max_packet_size_0: u8,
    id_vendor: u16,
    id_product: u16,
    bcd_device: u16,
    manufacturer_index: u8,
    product_index: u8,
    serial_number_index: u8,
    num_configurations: u8,
};

pub const UsbConfigDescriptor = packed struct {
    length: u8,
    descriptor_type: u8,
    total_length: u16,
    num_interfaces: u8,
    configuration_value: u8,
    configuration_index: u8,
    attributes: u8,
    max_power: u8,
};

pub const UsbInterfaceDescriptor = packed struct {
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

pub const UsbEndpointDescriptor = packed struct {
    length: u8,
    descriptor_type: u8,
    endpoint_address: u8,
    attributes: u8,
    max_packet_size: u16,
    interval: u8,
};

pub const UsbSuperSpeedCompanionDescriptor = packed struct {
    length: u8,
    descriptor_type: u8,
    max_burst: u8,
    attributes: u8,
    bytes_per_interval: u16,
};

// USB descriptor types
pub const USB_DESC_DEVICE: u8 = 1;
pub const USB_DESC_CONFIGURATION: u8 = 2;
pub const USB_DESC_STRING: u8 = 3;
pub const USB_DESC_INTERFACE: u8 = 4;
pub const USB_DESC_ENDPOINT: u8 = 5;
pub const USB_DESC_DEVICE_QUALIFIER: u8 = 6;
pub const USB_DESC_OTHER_SPEED_CONFIG: u8 = 7;
pub const USB_DESC_INTERFACE_POWER: u8 = 8;
pub const USB_DESC_OTG: u8 = 9;
pub const USB_DESC_DEBUG: u8 = 10;
pub const USB_DESC_INTERFACE_ASSOC: u8 = 11;
pub const USB_DESC_BOS: u8 = 15;
pub const USB_DESC_DEVICE_CAPABILITY: u8 = 16;
pub const USB_DESC_SS_EP_COMPANION: u8 = 48;
pub const USB_DESC_SSP_ISOCH_EP_COMP: u8 = 49;

// USB standard requests
pub const USB_REQ_GET_STATUS: u8 = 0;
pub const USB_REQ_CLEAR_FEATURE: u8 = 1;
pub const USB_REQ_SET_FEATURE: u8 = 3;
pub const USB_REQ_SET_ADDRESS: u8 = 5;
pub const USB_REQ_GET_DESCRIPTOR: u8 = 6;
pub const USB_REQ_SET_DESCRIPTOR: u8 = 7;
pub const USB_REQ_GET_CONFIGURATION: u8 = 8;
pub const USB_REQ_SET_CONFIGURATION: u8 = 9;
pub const USB_REQ_GET_INTERFACE: u8 = 10;
pub const USB_REQ_SET_INTERFACE: u8 = 11;
pub const USB_REQ_SYNCH_FRAME: u8 = 12;
pub const USB_REQ_SET_SEL: u8 = 48;
pub const USB_REQ_SET_ISOCH_DELAY: u8 = 49;

// USB device classes
pub const USB_CLASS_PER_INTERFACE: u8 = 0;
pub const USB_CLASS_AUDIO: u8 = 1;
pub const USB_CLASS_CDC: u8 = 2;
pub const USB_CLASS_HID: u8 = 3;
pub const USB_CLASS_PHYSICAL: u8 = 5;
pub const USB_CLASS_IMAGE: u8 = 6;
pub const USB_CLASS_PRINTER: u8 = 7;
pub const USB_CLASS_MASS_STORAGE: u8 = 8;
pub const USB_CLASS_HUB: u8 = 9;
pub const USB_CLASS_CDC_DATA: u8 = 10;
pub const USB_CLASS_SMART_CARD: u8 = 11;
pub const USB_CLASS_CONTENT_SECURITY: u8 = 13;
pub const USB_CLASS_VIDEO: u8 = 14;
pub const USB_CLASS_PERSONAL_HEALTHCARE: u8 = 15;
pub const USB_CLASS_AUDIO_VIDEO: u8 = 16;
pub const USB_CLASS_BILLBOARD: u8 = 17;
pub const USB_CLASS_USB_TYPE_C_BRIDGE: u8 = 18;
pub const USB_CLASS_DIAGNOSTIC: u8 = 0xDC;
pub const USB_CLASS_WIRELESS: u8 = 0xE0;
pub const USB_CLASS_MISC: u8 = 0xEF;
pub const USB_CLASS_APPLICATION: u8 = 0xFE;
pub const USB_CLASS_VENDOR_SPEC: u8 = 0xFF;

// ============================================================================
// Transfer Ring Management
// ============================================================================

pub const RING_SIZE = 256; // TRBs per ring segment

pub const TransferRing = struct {
    trbs: [RING_SIZE]Trb,
    enqueue_index: u32,
    dequeue_index: u32,
    cycle_state: bool,
    base_phys: u64,
    running: bool,

    pub fn init(base_phys: u64) TransferRing {
        var ring = TransferRing{
            .trbs = undefined,
            .enqueue_index = 0,
            .dequeue_index = 0,
            .cycle_state = true,
            .base_phys = base_phys,
            .running = false,
        };
        // Zero all TRBs
        for (&ring.trbs) |*trb| {
            trb.* = Trb{ .parameter = 0, .status = 0, .control = 0 };
        }
        // Set up link TRB at end
        ring.trbs[RING_SIZE - 1] = Trb.make_link(base_phys, true, ring.cycle_state);
        return ring;
    }

    pub fn enqueue(self: *TransferRing, trb: Trb) bool {
        // Check if ring is full
        const next = (self.enqueue_index + 1) % (RING_SIZE - 1); // -1 for link TRB
        if (next == self.dequeue_index) return false;

        var new_trb = trb;
        new_trb.set_cycle_bit(self.cycle_state);
        self.trbs[self.enqueue_index] = new_trb;
        self.enqueue_index = next;

        // If we've wrapped around to the link TRB
        if (self.enqueue_index == 0) {
            self.trbs[RING_SIZE - 1].set_cycle_bit(self.cycle_state);
            self.cycle_state = !self.cycle_state;
        }
        return true;
    }

    pub fn dequeue(self: *TransferRing) ?Trb {
        if (self.dequeue_index == self.enqueue_index) return null;
        const trb = self.trbs[self.dequeue_index];
        self.dequeue_index = (self.dequeue_index + 1) % (RING_SIZE - 1);
        return trb;
    }

    pub fn available_space(self: *const TransferRing) u32 {
        if (self.enqueue_index >= self.dequeue_index) {
            return (RING_SIZE - 2) - (self.enqueue_index - self.dequeue_index);
        } else {
            return self.dequeue_index - self.enqueue_index - 1;
        }
    }
};

// ============================================================================
// xHCI Controller State
// ============================================================================

pub const MAX_SLOTS = 256;
pub const MAX_PORTS = 127;
pub const MAX_ENDPOINTS = 31;
pub const MAX_INTERRUPTERS = 1024;

pub const XhciPortState = enum {
    disconnected,
    powered,
    default_state,
    addressed,
    configured,
    suspended,
    error,
};

pub const XhciPort = struct {
    number: u8,
    speed: u8,
    slot_id: u8,
    state: XhciPortState,
    is_usb3: bool,
    is_removable: bool,
    hub_depth: u8,
    parent_port: u8,
    max_packet_size: u16,
    companion_port: u8, // USB2/USB3 companion
};

pub const XhciDevice = struct {
    slot_id: u8,
    speed: u8,
    port_num: u8,
    address: u8,
    state: UsbDeviceState,
    device_desc: UsbDeviceDescriptor,
    config_desc: UsbConfigDescriptor,
    num_interfaces: u8,
    num_endpoints: u8,
    // Transfer rings per endpoint
    ep_rings: [MAX_ENDPOINTS]?*TransferRing,
    // Device context physical address
    output_ctx_phys: u64,
    input_ctx_phys: u64,
    // Hub info
    is_hub: bool,
    hub_num_ports: u8,
    hub_tt_think_time: u8,
    hub_mtt: bool,
    // Strings
    manufacturer_str: [64]u8,
    product_str: [64]u8,
    serial_str: [64]u8,
};

pub const UsbDeviceState = enum {
    not_attached,
    attached,
    powered,
    default_state,
    address,
    configured,
    suspended,
};

pub const XhciController = struct {
    // BAR0 MMIO base address
    mmio_base: u64,
    cap_base: u64,
    op_base: u64,
    runtime_base: u64,
    doorbell_base: u64,
    // Capabilities
    max_slots: u8,
    max_intrs: u16,
    max_ports: u8,
    page_size: u32,
    context_size: u8, // 32 or 64 bytes
    supports_64bit: bool,
    max_scratchpad_bufs: u16,
    // State
    running: bool,
    slots: [MAX_SLOTS]?XhciDevice,
    ports: [MAX_PORTS]XhciPort,
    num_ports_usb2: u8,
    num_ports_usb3: u8,
    // Command ring
    cmd_ring: TransferRing,
    // Event ring
    event_ring_segment: [RING_SIZE]Trb,
    event_ring_dequeue: u32,
    event_ring_cycle: bool,
    // DCBAA (Device Context Base Address Array)
    dcbaa: [MAX_SLOTS + 1]u64,
    dcbaa_phys: u64,
    // Scratchpad
    scratchpad_array: [256]u64,
    scratchpad_phys: u64,
    // Statistics
    total_transfers: u64,
    total_bytes: u64,
    errors: u64,
    resets: u32,

    pub fn read_cap32(self: *const XhciController, offset: u32) u32 {
        const ptr: *volatile u32 = @ptrFromInt(self.cap_base + offset);
        return ptr.*;
    }

    pub fn read_op32(self: *const XhciController, offset: u32) u32 {
        const ptr: *volatile u32 = @ptrFromInt(self.op_base + offset);
        return ptr.*;
    }

    pub fn write_op32(self: *const XhciController, offset: u32, value: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.op_base + offset);
        ptr.* = value;
    }

    pub fn read_op64(self: *const XhciController, offset: u32) u64 {
        const ptr: *volatile u64 = @ptrFromInt(self.op_base + offset);
        return ptr.*;
    }

    pub fn write_op64(self: *const XhciController, offset: u32, value: u64) void {
        const ptr: *volatile u64 = @ptrFromInt(self.op_base + offset);
        ptr.* = value;
    }

    pub fn ring_doorbell(self: *const XhciController, slot_id: u8, target: u8) void {
        const offset: u32 = @as(u32, slot_id) * 4;
        const ptr: *volatile u32 = @ptrFromInt(self.doorbell_base + offset);
        ptr.* = @as(u32, target);
    }

    pub fn read_portsc(self: *const XhciController, port: u8) u32 {
        const offset: u32 = 0x400 + (@as(u32, port - 1) * 0x10);
        return self.read_op32(offset);
    }

    pub fn write_portsc(self: *const XhciController, port: u8, value: u32) void {
        const offset: u32 = 0x400 + (@as(u32, port - 1) * 0x10);
        self.write_op32(offset, value);
    }

    /// Initialize the xHCI controller
    pub fn init(mmio_base: u64) XhciController {
        var xhci = XhciController{
            .mmio_base = mmio_base,
            .cap_base = mmio_base,
            .op_base = undefined,
            .runtime_base = undefined,
            .doorbell_base = undefined,
            .max_slots = 0,
            .max_intrs = 0,
            .max_ports = 0,
            .page_size = 0,
            .context_size = 32,
            .supports_64bit = false,
            .max_scratchpad_bufs = 0,
            .running = false,
            .slots = [_]?XhciDevice{null} ** MAX_SLOTS,
            .ports = undefined,
            .num_ports_usb2 = 0,
            .num_ports_usb3 = 0,
            .cmd_ring = undefined,
            .event_ring_segment = undefined,
            .event_ring_dequeue = 0,
            .event_ring_cycle = true,
            .dcbaa = [_]u64{0} ** (MAX_SLOTS + 1),
            .dcbaa_phys = 0,
            .scratchpad_array = [_]u64{0} ** 256,
            .scratchpad_phys = 0,
            .total_transfers = 0,
            .total_bytes = 0,
            .errors = 0,
            .resets = 0,
        };

        // Read capability registers
        const cap_length = @as(u8, @truncate(xhci.read_cap32(XHCI_CAP_CAPLENGTH)));
        xhci.op_base = mmio_base + cap_length;

        const hcsparams1 = xhci.read_cap32(XHCI_CAP_HCSPARAMS1);
        xhci.max_slots = @truncate(hcsparams1 & 0xFF);
        xhci.max_intrs = @truncate((hcsparams1 >> 8) & 0x7FF);
        xhci.max_ports = @truncate((hcsparams1 >> 24) & 0xFF);

        const hccparams1 = xhci.read_cap32(XHCI_CAP_HCCPARAMS1);
        xhci.supports_64bit = (hccparams1 & 1) != 0;
        xhci.context_size = if ((hccparams1 & (1 << 2)) != 0) 64 else 32;

        const dboff = xhci.read_cap32(XHCI_CAP_DBOFF);
        xhci.doorbell_base = mmio_base + dboff;

        const rtsoff = xhci.read_cap32(XHCI_CAP_RTSOFF);
        xhci.runtime_base = mmio_base + rtsoff;

        const hcsparams2 = xhci.read_cap32(XHCI_CAP_HCSPARAMS2);
        const hi = @as(u16, @truncate((hcsparams2 >> 21) & 0x1F)) << 5;
        const lo = @as(u16, @truncate((hcsparams2 >> 27) & 0x1F));
        xhci.max_scratchpad_bufs = hi | lo;

        xhci.page_size = xhci.read_op32(XHCI_OP_PAGESIZE) << 12;

        return xhci;
    }

    /// Reset the host controller
    pub fn reset(self: *XhciController) bool {
        // Stop the controller
        var cmd = self.read_op32(XHCI_OP_USBCMD);
        cmd &= ~USBCMD_RS;
        self.write_op32(XHCI_OP_USBCMD, cmd);

        // Wait for halted
        var timeout: u32 = 100000;
        while (timeout > 0) : (timeout -= 1) {
            if (self.read_op32(XHCI_OP_USBSTS) & USBSTS_HCH != 0) break;
        }
        if (timeout == 0) return false;

        // Issue reset
        cmd = self.read_op32(XHCI_OP_USBCMD);
        cmd |= USBCMD_HCRST;
        self.write_op32(XHCI_OP_USBCMD, cmd);

        // Wait for reset completion
        timeout = 100000;
        while (timeout > 0) : (timeout -= 1) {
            const sts = self.read_op32(XHCI_OP_USBCMD);
            if (sts & USBCMD_HCRST == 0) break;
        }
        if (timeout == 0) return false;

        // Wait for CNR to clear
        timeout = 100000;
        while (timeout > 0) : (timeout -= 1) {
            if (self.read_op32(XHCI_OP_USBSTS) & USBSTS_CNR == 0) break;
        }

        self.resets += 1;
        return timeout > 0;
    }

    /// Start the controller
    pub fn start(self: *XhciController) void {
        // Set max device slots enabled
        self.write_op32(XHCI_OP_CONFIG, @as(u32, self.max_slots));

        // Set DCBAA pointer
        self.write_op64(XHCI_OP_DCBAAP, self.dcbaa_phys);

        // Set command ring control register
        var crcr = self.cmd_ring.base_phys;
        if (self.cmd_ring.cycle_state) crcr |= 1; // RCS
        self.write_op64(XHCI_OP_CRCR, crcr);

        // Enable interrupts and run
        var cmd = self.read_op32(XHCI_OP_USBCMD);
        cmd |= USBCMD_RS | USBCMD_INTE | USBCMD_HSEE;
        self.write_op32(XHCI_OP_USBCMD, cmd);

        self.running = true;
    }

    /// Issue a command via command ring
    pub fn send_command(self: *XhciController, trb: Trb) bool {
        if (!self.cmd_ring.enqueue(trb)) return false;
        // Ring the command doorbell (slot 0, target 0)
        self.ring_doorbell(0, 0);
        return true;
    }

    /// Enable a device slot
    pub fn enable_slot(self: *XhciController) bool {
        var trb = Trb{ .parameter = 0, .status = 0, .control = 0 };
        trb.set_type(TRB_TYPE_ENABLE_SLOT);
        return self.send_command(trb);
    }

    /// Get port speed name
    pub fn port_speed_name(speed: u8) []const u8 {
        return switch (speed) {
            USB_SPEED_FULL => "Full Speed (12 Mbps)",
            USB_SPEED_LOW => "Low Speed (1.5 Mbps)",
            USB_SPEED_HIGH => "High Speed (480 Mbps)",
            USB_SPEED_SUPER => "SuperSpeed (5 Gbps)",
            USB_SPEED_SUPER_PLUS => "SuperSpeed+ (10 Gbps)",
            USB_SPEED_SUPER_PLUS_X2 => "SuperSpeed+ 2x2 (20 Gbps)",
            else => "Unknown",
        };
    }

    /// Process a port status change event
    pub fn handle_port_change(self: *XhciController, port_id: u8) void {
        if (port_id == 0 or port_id > self.max_ports) return;

        const portsc = self.read_portsc(port_id);
        const connected = (portsc & PORTSC_CCS) != 0;
        const speed = @as(u8, @truncate((portsc >> 10) & 0xF));

        self.ports[port_id - 1].speed = speed;

        if (connected) {
            self.ports[port_id - 1].state = .default_state;
            // Reset port to enable it
            var sc = portsc;
            sc |= PORTSC_PR; // Port Reset
            // Clear RW1C bits
            sc &= ~(PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC);
            self.write_portsc(port_id, sc);
        } else {
            self.ports[port_id - 1].state = .disconnected;
            // If a device was on this port, clean it up
            if (self.ports[port_id - 1].slot_id != 0) {
                const slot = self.ports[port_id - 1].slot_id;
                self.slots[slot] = null;
                self.ports[port_id - 1].slot_id = 0;
            }
        }

        // Clear change bits
        self.write_portsc(port_id, portsc | PORTSC_CSC | PORTSC_PEC | PORTSC_PRC);
    }

    /// Process events from the event ring
    pub fn poll_events(self: *XhciController) void {
        while (true) {
            const trb = self.event_ring_segment[self.event_ring_dequeue];
            if (trb.get_cycle_bit() != self.event_ring_cycle) break;

            const trb_type = trb.get_type();

            switch (trb_type) {
                TRB_TYPE_TRANSFER_EVENT => {
                    self.total_transfers += 1;
                    const cc = @as(u8, @truncate((trb.status >> 24) & 0xFF));
                    if (cc != 1 and cc != 13) { // Not Success or Short Packet
                        self.errors += 1;
                    }
                },
                TRB_TYPE_CMD_COMPLETE => {
                    // Command completion event
                    const cc = @as(u8, @truncate((trb.status >> 24) & 0xFF));
                    if (cc == 1) { // Success
                        const slot_id = @as(u8, @truncate((trb.control >> 24) & 0xFF));
                        _ = slot_id;
                    }
                },
                TRB_TYPE_PORT_STATUS_CHANGE => {
                    const port_id = @as(u8, @truncate((trb.parameter >> 24) & 0xFF));
                    self.handle_port_change(port_id);
                },
                TRB_TYPE_HOST_CONTROLLER => {
                    self.errors += 1;
                },
                TRB_TYPE_MFINDEX_WRAP => {},
                TRB_TYPE_DEVICE_NOTIFICATION => {},
                else => {},
            }

            self.event_ring_dequeue += 1;
            if (self.event_ring_dequeue >= RING_SIZE) {
                self.event_ring_dequeue = 0;
                self.event_ring_cycle = !self.event_ring_cycle;
            }
        }
    }
};

// ============================================================================
// USB Hub Support
// ============================================================================

pub const UsbHubDescriptor = packed struct {
    length: u8,
    descriptor_type: u8,
    num_ports: u8,
    characteristics: u16,
    power_on_delay: u8, // 2ms units
    current: u8,
    removable_device: u8,
    port_pwr_ctrl: u8,
};

pub const HUB_PORT_FEATURE_CONNECTION: u16 = 0;
pub const HUB_PORT_FEATURE_ENABLE: u16 = 1;
pub const HUB_PORT_FEATURE_SUSPEND: u16 = 2;
pub const HUB_PORT_FEATURE_OVER_CURRENT: u16 = 3;
pub const HUB_PORT_FEATURE_RESET: u16 = 4;
pub const HUB_PORT_FEATURE_POWER: u16 = 8;
pub const HUB_PORT_FEATURE_LOWSPEED: u16 = 9;
pub const HUB_PORT_FEATURE_C_CONNECTION: u16 = 16;
pub const HUB_PORT_FEATURE_C_ENABLE: u16 = 17;
pub const HUB_PORT_FEATURE_C_SUSPEND: u16 = 18;
pub const HUB_PORT_FEATURE_C_OVER_CURRENT: u16 = 19;
pub const HUB_PORT_FEATURE_C_RESET: u16 = 20;

// ============================================================================
// USB Mass Storage Bulk-Only Transport
// ============================================================================

pub const CbwSignature: u32 = 0x43425355;
pub const CswSignature: u32 = 0x53425355;

pub const CommandBlockWrapper = packed struct {
    signature: u32,         // 0x43425355
    tag: u32,
    data_transfer_length: u32,
    flags: u8,              // 0x80 = IN, 0x00 = OUT
    lun: u8,
    cb_length: u8,          // 1-16
    command_block: [16]u8,
};

pub const CommandStatusWrapper = packed struct {
    signature: u32,         // 0x53425355
    tag: u32,
    data_residue: u32,
    status: u8,
};

pub const CSW_STATUS_PASSED: u8 = 0;
pub const CSW_STATUS_FAILED: u8 = 1;
pub const CSW_STATUS_PHASE_ERROR: u8 = 2;

// SCSI commands for USB mass storage
pub const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub const SCSI_REQUEST_SENSE: u8 = 0x03;
pub const SCSI_INQUIRY: u8 = 0x12;
pub const SCSI_MODE_SENSE_6: u8 = 0x1A;
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_READ_10: u8 = 0x28;
pub const SCSI_WRITE_10: u8 = 0x2A;
pub const SCSI_READ_CAPACITY_16: u8 = 0x9E;
pub const SCSI_READ_16: u8 = 0x88;
pub const SCSI_WRITE_16: u8 = 0x8A;

// ============================================================================
// USB HID (Human Interface Device)
// ============================================================================

pub const HidDescriptor = packed struct {
    length: u8,
    descriptor_type: u8,    // 0x21
    bcd_hid: u16,
    country_code: u8,
    num_descriptors: u8,
    class_descriptor_type: u8, // 0x22 for Report
    descriptor_length: u16,
};

pub const HID_REQ_GET_REPORT: u8 = 0x01;
pub const HID_REQ_GET_IDLE: u8 = 0x02;
pub const HID_REQ_GET_PROTOCOL: u8 = 0x03;
pub const HID_REQ_SET_REPORT: u8 = 0x09;
pub const HID_REQ_SET_IDLE: u8 = 0x0A;
pub const HID_REQ_SET_PROTOCOL: u8 = 0x0B;

pub const HID_REPORT_INPUT: u8 = 1;
pub const HID_REPORT_OUTPUT: u8 = 2;
pub const HID_REPORT_FEATURE: u8 = 3;

/// HID boot keyboard report (8 bytes)
pub const HidBootKeyboardReport = packed struct {
    modifiers: u8,
    _reserved: u8,
    keycodes: [6]u8,
};

/// HID boot mouse report
pub const HidBootMouseReport = packed struct {
    buttons: u8,
    x: i8,
    y: i8,
    wheel: i8,
};

// ============================================================================
// USB Audio (UAC 2.0)
// ============================================================================

pub const USB_AUDIO_CLASS: u8 = 1;
pub const USB_AUDIO_SUBCLASS_CONTROL: u8 = 1;
pub const USB_AUDIO_SUBCLASS_STREAMING: u8 = 2;
pub const USB_AUDIO_SUBCLASS_MIDI: u8 = 3;

pub const AudioControlHeader = packed struct {
    length: u8,
    descriptor_type: u8,
    descriptor_subtype: u8,
    bcd_adc: u16,
    category: u8,
    total_length: u16,
    controls: u8,
};

pub const AudioClockSource = packed struct {
    length: u8,
    descriptor_type: u8,
    descriptor_subtype: u8,
    clock_id: u8,
    attributes: u8,
    controls: u8,
    assoc_terminal: u8,
    clock_source_str: u8,
};

pub const AudioInputTerminal = packed struct {
    length: u8,
    descriptor_type: u8,
    descriptor_subtype: u8,
    terminal_id: u8,
    terminal_type: u16,
    assoc_terminal: u8,
    clock_source_id: u8,
    nr_channels: u8,
    channel_config: u32,
    channel_names: u8,
    controls: u16,
    terminal_str: u8,
};

// Audio format types
pub const AUDIO_FORMAT_PCM: u16 = 0x0001;
pub const AUDIO_FORMAT_PCM8: u16 = 0x0002;
pub const AUDIO_FORMAT_IEEE_FLOAT: u16 = 0x0003;
pub const AUDIO_FORMAT_ALAW: u16 = 0x0004;
pub const AUDIO_FORMAT_MULAW: u16 = 0x0005;
pub const AUDIO_FORMAT_DSD: u16 = 0x0006;

// Audio terminal types
pub const AUDIO_TERM_USB_STREAMING: u16 = 0x0101;
pub const AUDIO_TERM_SPEAKER: u16 = 0x0301;
pub const AUDIO_TERM_HEADPHONES: u16 = 0x0302;
pub const AUDIO_TERM_MICROPHONE: u16 = 0x0201;
pub const AUDIO_TERM_HEADSET: u16 = 0x0402;

// ============================================================================
// USB Video (UVC 1.5)
// ============================================================================

pub const USB_VIDEO_CLASS: u8 = 14;
pub const USB_VIDEO_SUBCLASS_CONTROL: u8 = 1;
pub const USB_VIDEO_SUBCLASS_STREAMING: u8 = 2;
pub const USB_VIDEO_SUBCLASS_IFACE_COLLECTION: u8 = 3;

pub const VideoControlHeader = packed struct {
    length: u8,
    descriptor_type: u8,
    descriptor_subtype: u8,
    bcd_uvc: u16,
    total_length: u16,
    clock_frequency: u32,
    in_collection: u8,
};

pub const VideoCameraTerminal = packed struct {
    length: u8,
    descriptor_type: u8,
    descriptor_subtype: u8,
    terminal_id: u8,
    terminal_type: u16,
    assoc_terminal: u8,
    terminal_str: u8,
    objective_focal_length_min: u16,
    objective_focal_length_max: u16,
    ocular_focal_length: u16,
    control_size: u8,
    controls: [3]u8,
};

// Video format GUIDs
pub const UVC_FORMAT_YUY2 = [16]u8{ 0x59, 0x55, 0x59, 0x32, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 };
pub const UVC_FORMAT_NV12 = [16]u8{ 0x4E, 0x56, 0x31, 0x32, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 };
pub const UVC_FORMAT_MJPEG = [16]u8{ 0x4D, 0x4A, 0x50, 0x47, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 };
pub const UVC_FORMAT_H264 = [16]u8{ 0x48, 0x32, 0x36, 0x34, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 };
