// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - USB Gadget / UDC Framework Detail
// USB Device Controller, gadget API, composite framework, ConfigFS integration,
// function drivers, string descriptors, OTG, USB Power Delivery

const std = @import("std");

// ============================================================================
// USB Speed and Standard Definitions
// ============================================================================

pub const UsbSpeed = enum(u8) {
    Unknown = 0,
    Low = 1,
    Full = 2,
    High = 3,
    Wireless = 4,
    Super = 5,
    SuperPlus = 6,
    SuperPlus2x2 = 7,
};

pub const UsbDirection = enum(u1) {
    Out = 0,     // host to device
    In = 1,      // device to host
};

pub const UsbTransferType = enum(u2) {
    Control = 0,
    Isochronous = 1,
    Bulk = 2,
    Interrupt = 3,
};

// ============================================================================
// USB Descriptors (Device side)
// ============================================================================

pub const UsbDeviceDescriptor = extern struct {
    bLength: u8 = 18,
    bDescriptorType: u8 = 1, // DEVICE
    bcdUSB: u16,              // 0x0200, 0x0300, 0x0310, 0x0320
    bDeviceClass: u8,
    bDeviceSubClass: u8,
    bDeviceProtocol: u8,
    bMaxPacketSize0: u8,
    idVendor: u16,
    idProduct: u16,
    bcdDevice: u16,
    iManufacturer: u8,
    iSerialNumber: u8,
    iProduct: u8,
    bNumConfigurations: u8,
};

pub const UsbConfigDescriptor = extern struct {
    bLength: u8 = 9,
    bDescriptorType: u8 = 2, // CONFIGURATION
    wTotalLength: u16,
    bNumInterfaces: u8,
    bConfigurationValue: u8,
    iConfiguration: u8,
    bmAttributes: u8,
    bMaxPower: u8,            // in 2mA units (USB 2) or 8mA units (USB 3)
};

pub const UsbInterfaceDescriptor = extern struct {
    bLength: u8 = 9,
    bDescriptorType: u8 = 4, // INTERFACE
    bInterfaceNumber: u8,
    bAlternateSetting: u8,
    bNumEndpoints: u8,
    bInterfaceClass: u8,
    bInterfaceSubClass: u8,
    bInterfaceProtocol: u8,
    iInterface: u8,
};

pub const UsbEndpointDescriptor = extern struct {
    bLength: u8 = 7,
    bDescriptorType: u8 = 5, // ENDPOINT
    bEndpointAddress: u8,     // endpoint number + direction
    bmAttributes: u8,         // transfer type + sync + usage
    wMaxPacketSize: u16,
    bInterval: u8,
};

pub const UsbSsEndpointCompDescriptor = extern struct {
    bLength: u8 = 6,
    bDescriptorType: u8 = 0x30, // SS_ENDPOINT_COMPANION
    bMaxBurst: u8,
    bmAttributes: u8,
    wBytesPerInterval: u16,
};

pub const UsbSspIsocEndpointCompDescriptor = extern struct {
    bLength: u8 = 8,
    bDescriptorType: u8 = 0x31, // SSP_ISOC_ENDPOINT_COMPANION
    wReserved: u16,
    dwBytesPerInterval: u32,
};

pub const UsbBosDescriptor = extern struct {
    bLength: u8 = 5,
    bDescriptorType: u8 = 15, // BOS
    wTotalLength: u16,
    bNumDeviceCaps: u8,
};

pub const UsbStringDescriptor = struct {
    bLength: u8,
    bDescriptorType: u8 = 3, // STRING
    wData: [126]u16,          // UTF-16LE encoded
};

// ============================================================================
// USB Gadget (UDC abstraction)
// ============================================================================

pub const UsbGadget = struct {
    // UDC identity
    name: [64]u8,
    ops: u64,                 // usb_gadget_ops *
    ep0: u64,                 // usb_ep * (control endpoint)

    // Device info
    speed: UsbSpeed,
    max_speed: UsbSpeed,
    state: GadgetState,

    // Endpoints
    ep_list: u64,             // list of all endpoints
    num_eps: u32,

    // Capabilities
    is_otg: bool,
    b_hnp_enable: bool,
    a_hnp_support: bool,
    a_alt_hnp_support: bool,
    hnp_polling_support: bool,
    host_request_flag: bool,
    quirk_ep_out_aligned_size: bool,
    quirk_altset_not_supp: bool,
    quirk_stall_not_supp: bool,
    quirk_zlp_not_supp: bool,
    is_selfpowered: bool,
    deactivated: bool,
    connected: bool,
    lpm_capable: bool,
    irq: i32,

    // Power
    vbus_current: u32,        // mA
    sg_supported: bool,
};

pub const GadgetState = enum(u8) {
    NotAttached = 0,
    Attached = 1,
    Powered = 2,
    Reconnecting = 3,
    Default = 4,
    Address = 5,
    Configured = 6,
    Suspended = 7,
};

pub const UsbGadgetOps = struct {
    get_frame: u64,
    wakeup: u64,
    set_selfpowered: u64,
    vbus_session: u64,
    vbus_draw: u64,
    pullup: u64,
    ioctl: u64,
    get_config_params: u64,
    udc_start: u64,
    udc_stop: u64,
    udc_set_speed: u64,
    udc_set_ssp_rate: u64,
    match_ep: u64,
    check_config: u64,
};

// ============================================================================
// USB Endpoint (gadget side)
// ============================================================================

pub const UsbEp = struct {
    name: [16]u8,
    ops: u64,                 // usb_ep_ops *
    ep_list: u64,             // linked list in gadget
    // Descriptor
    desc: ?*UsbEndpointDescriptor,
    comp_desc: ?*UsbSsEndpointCompDescriptor,
    // Capabilities
    caps: UsbEpCaps,
    maxpacket: u16,
    maxpacket_limit: u16,
    max_streams: u16,
    mult: u8,                 // high-bandwidth multiplier
    maxburst: u8,             // SS max burst
    address: u8,
    claimed: bool,
    enabled: bool,
};

pub const UsbEpCaps = packed struct(u32) {
    type_control: bool = false,
    type_iso: bool = false,
    type_bulk: bool = false,
    type_int: bool = false,
    dir_in: bool = false,
    dir_out: bool = false,
    _pad: u26 = 0,
};

pub const UsbEpOps = struct {
    enable: u64,
    disable: u64,
    alloc_request: u64,
    free_request: u64,
    queue: u64,
    dequeue: u64,
    set_halt: u64,
    set_wedge: u64,
    fifo_status: u64,
    fifo_flush: u64,
};

// ============================================================================
// USB Request
// ============================================================================

pub const UsbRequest = struct {
    buf: u64,                 // DMA-able buffer
    length: u32,
    dma: u64,                 // DMA address
    sg: u64,                  // scatterlist
    num_sgs: u32,
    num_mapped_sgs: u32,
    stream_id: u16,
    is_last: bool,
    no_interrupt: bool,
    zero: bool,               // send zero-length packet at end
    short_not_ok: bool,
    dma_mapped: bool,
    complete: u64,            // completion callback
    context: u64,             // for callback
    list: u64,                // for driver's request list
    frame_number: i32,        // ISO frame number
    // Result (filled by UDC)
    status: i32,
    actual: u32,              // actual bytes transferred
};

// ============================================================================
// Composite Framework
// ============================================================================

pub const UsbCompositeDriver = struct {
    name: [64]u8,
    dev: UsbDeviceDescriptor,
    strings: u64,              // usb_gadget_strings **
    max_speed: UsbSpeed,
    needs_serial: bool,
    // Callbacks
    bind: u64,
    unbind: u64,
    disconnect: u64,
    suspend: u64,
    resume: u64,
};

pub const UsbFunction = struct {
    name: [32]u8,
    strings: u64,
    config: u64,               // usb_configuration *
    // Function descriptors
    fs_descriptors: u64,       // full-speed
    hs_descriptors: u64,       // high-speed
    ss_descriptors: u64,       // superspeed
    ssp_descriptors: u64,      // superspeed plus
    // Callbacks
    bind: u64,
    unbind: u64,
    free_func: u64,
    set_alt: u64,
    get_alt: u64,
    disable: u64,
    setup: u64,
    req_match: u64,
    suspend: u64,
    resume: u64,
    get_status: u64,
    func_suspend: u64,
    func_is_suspended: bool,
};

// ============================================================================
// Well-known USB Gadget Functions
// ============================================================================

pub const GadgetFunctionType = enum(u8) {
    Acm = 0,          // serial/ACM (CDC)
    Ecm = 1,          // Ethernet/ECM
    Eem = 2,          // Ethernet Emulation Model
    Ncm = 3,          // Network Control Model
    Rndis = 4,        // RNDIS (Microsoft)
    MassStorage = 5,  // Mass Storage
    Hid = 6,          // HID
    Printer = 7,
    Midi = 8,
    Uac1 = 9,         // USB Audio Class 1
    Uac2 = 10,        // USB Audio Class 2
    Uvc = 11,         // USB Video Class
    Ffs = 12,         // FunctionFS (userspace)
    Fastboot = 13,
    Adb = 14,
    Mtp = 15,
    Ptp = 16,
    DmCrypt = 17,     // for dm-crypt
};

// ============================================================================
// USB OTG
// ============================================================================

pub const OtgState = enum(u8) {
    Undefined = 0,
    BIdle = 1,
    BSrpInit = 2,
    BPeripheral = 3,
    BWaitAcon = 4,
    BHost = 5,
    AIdle = 6,
    AWaitVrise = 7,
    AWaitVfall = 8,
    AWaitBcon = 9,
    AHost = 10,
    ASuspend = 11,
    APeripheral = 12,
    AVbusErr = 13,
};

pub const OtgCaps = packed struct(u32) {
    srp: bool = false,
    hnp: bool = false,
    adp: bool = false,
    dual_role: bool = false,
    _pad: u28 = 0,
};

// ============================================================================
// USB Power Delivery
// ============================================================================

pub const UsbPdRevision = enum(u8) {
    Pd10 = 0,
    Pd20 = 1,
    Pd30 = 2,
    Pd31 = 3,
};

pub const UsbPdPowerRole = enum(u1) {
    Sink = 0,
    Source = 1,
};

pub const UsbPdDataRole = enum(u1) {
    Ufp = 0,     // Upstream Facing Port
    Dfp = 1,     // Downstream Facing Port
};

pub const UsbPdPdo = struct {
    pdo_type: PdoType,
    voltage_mv: u32,    // voltage in millivolts
    current_ma: u32,    // max current in milliamps
    // For PPS
    min_voltage_mv: u32,
    max_voltage_mv: u32,
    max_current_ma: u32,
};

pub const PdoType = enum(u2) {
    Fixed = 0,
    Battery = 1,
    Variable = 2,
    AugmentedPdo = 3, // PPS (Programmable Power Supply)
};

// ============================================================================
// ConfigFS USB Gadget
// ============================================================================

pub const GadgetConfigFsState = struct {
    gadget_name: [64]u8,
    udc_name: [64]u8,
    bound_udc: bool,
    // Current config
    num_configs: u32,
    num_functions: u32,
    num_strings: u32,
    current_config: u8,
    // Stats
    total_requests: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
    total_errors: u64,
    setup_requests: u64,
};

// ============================================================================
// Gadget Manager
// ============================================================================

pub const UsbGadgetManager = struct {
    total_udcs: u32,
    total_gadgets_bound: u32,
    total_functions_registered: u32,
    configfs_state: GadgetConfigFsState,
    initialized: bool,

    pub fn init() UsbGadgetManager {
        return .{
            .total_udcs = 0,
            .total_gadgets_bound = 0,
            .total_functions_registered = 0,
            .configfs_state = std.mem.zeroes(GadgetConfigFsState),
            .initialized = true,
        };
    }
};
