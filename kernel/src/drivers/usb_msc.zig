// =============================================================================
// Kernel Zxyphor — USB Mass Storage Class (Bulk-Only Transport)
// =============================================================================
// Full USB mass storage driver for USB flash drives, external hard drives:
//   - USB descriptor parsing (device, config, interface, endpoint)
//   - Command Block Wrapper (CBW) / Command Status Wrapper (CSW)
//   - SCSI command translation (INQUIRY, READ_CAPACITY, READ_10, WRITE_10)
//   - Bulk-only transport with reset recovery
//   - Logical Unit Number (LUN) management
//   - Max Packet Size handling
//   - Device enumeration and hot-plug detection
//   - DMA buffer management for transfers
// =============================================================================

// ============================================================================
// Constants
// ============================================================================

pub const MAX_USB_DEVICES: usize = 16;
pub const MAX_LUNS_PER_DEVICE: usize = 8;
pub const MAX_ENDPOINTS: usize = 4;
pub const USB_MSC_SECTOR_SIZE: u32 = 512;
pub const CBW_SIGNATURE: u32 = 0x43425355; // "USBC"
pub const CSW_SIGNATURE: u32 = 0x53425355; // "USBS"
pub const CBW_SIZE: usize = 31;
pub const CSW_SIZE: usize = 13;
pub const MAX_SCSI_CDB: usize = 16;
pub const MAX_TRANSFER_SIZE: usize = 65536;
pub const USB_DMA_BUFFER_SIZE: usize = 4096;
pub const MAX_DMA_BUFFERS: usize = 32;

// ============================================================================
// USB Request Types
// ============================================================================

pub const USB_DIR_IN: u8 = 0x80;
pub const USB_DIR_OUT: u8 = 0x00;
pub const USB_TYPE_STANDARD: u8 = 0x00;
pub const USB_TYPE_CLASS: u8 = 0x20;
pub const USB_TYPE_VENDOR: u8 = 0x40;
pub const USB_RECIP_DEVICE: u8 = 0x00;
pub const USB_RECIP_INTERFACE: u8 = 0x01;
pub const USB_RECIP_ENDPOINT: u8 = 0x02;

// Standard requests
pub const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const USB_REQ_SET_CONFIGURATION: u8 = 0x09;
pub const USB_REQ_CLEAR_FEATURE: u8 = 0x01;

// Mass storage class requests
pub const MSC_REQ_RESET: u8 = 0xFF;
pub const MSC_REQ_GET_MAX_LUN: u8 = 0xFE;

// Descriptor types
pub const USB_DESC_DEVICE: u8 = 0x01;
pub const USB_DESC_CONFIG: u8 = 0x02;
pub const USB_DESC_STRING: u8 = 0x03;
pub const USB_DESC_INTERFACE: u8 = 0x04;
pub const USB_DESC_ENDPOINT: u8 = 0x05;

// ============================================================================
// SCSI Commands
// ============================================================================

pub const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub const SCSI_REQUEST_SENSE: u8 = 0x03;
pub const SCSI_INQUIRY: u8 = 0x12;
pub const SCSI_MODE_SENSE_6: u8 = 0x1A;
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_READ_10: u8 = 0x28;
pub const SCSI_WRITE_10: u8 = 0x2A;
pub const SCSI_SYNCHRONIZE_CACHE: u8 = 0x35;
pub const SCSI_READ_CAPACITY_16: u8 = 0x9E;

// SCSI sense keys
pub const SENSE_NO_SENSE: u8 = 0x00;
pub const SENSE_RECOVERED_ERROR: u8 = 0x01;
pub const SENSE_NOT_READY: u8 = 0x02;
pub const SENSE_MEDIUM_ERROR: u8 = 0x03;
pub const SENSE_HARDWARE_ERROR: u8 = 0x04;
pub const SENSE_ILLEGAL_REQUEST: u8 = 0x05;
pub const SENSE_UNIT_ATTENTION: u8 = 0x06;
pub const SENSE_DATA_PROTECT: u8 = 0x07;

// ============================================================================
// USB Device Descriptor (parsed)
// ============================================================================

pub const UsbDeviceDescriptor = struct {
    vendor_id: u16,
    product_id: u16,
    device_class: u8,
    device_subclass: u8,
    device_protocol: u8,
    max_packet_size_0: u8,     // For endpoint 0
    num_configurations: u8,
    bcd_device: u16,
    manufacturer_idx: u8,
    product_idx: u8,
    serial_idx: u8,

    pub fn init() UsbDeviceDescriptor {
        return .{
            .vendor_id = 0,
            .product_id = 0,
            .device_class = 0,
            .device_subclass = 0,
            .device_protocol = 0,
            .max_packet_size_0 = 64,
            .num_configurations = 0,
            .bcd_device = 0,
            .manufacturer_idx = 0,
            .product_idx = 0,
            .serial_idx = 0,
        };
    }

    pub fn isMassStorage(self: *const UsbDeviceDescriptor) bool {
        return self.device_class == 0x08 or self.device_subclass == 0x06;
    }
};

// ============================================================================
// USB Endpoint
// ============================================================================

pub const EndpointDirection = enum(u8) {
    Out = 0,
    In = 1,
};

pub const EndpointType = enum(u8) {
    Control = 0,
    Isochronous = 1,
    Bulk = 2,
    Interrupt = 3,
};

pub const UsbEndpoint = struct {
    address: u8,
    direction: EndpointDirection,
    ep_type: EndpointType,
    max_packet_size: u16,
    interval: u8,
    active: bool,
    toggle: u8,      // Data toggle bit

    pub fn init() UsbEndpoint {
        return .{
            .address = 0,
            .direction = .Out,
            .ep_type = .Control,
            .max_packet_size = 64,
            .interval = 0,
            .active = false,
            .toggle = 0,
        };
    }

    pub fn isBulk(self: *const UsbEndpoint) bool {
        return self.ep_type == .Bulk;
    }

    pub fn isBulkIn(self: *const UsbEndpoint) bool {
        return self.ep_type == .Bulk and self.direction == .In;
    }

    pub fn isBulkOut(self: *const UsbEndpoint) bool {
        return self.ep_type == .Bulk and self.direction == .Out;
    }
};

// ============================================================================
// Command Block Wrapper (CBW)
// ============================================================================

pub const CommandBlockWrapper = extern struct {
    signature: u32,          // CBW_SIGNATURE
    tag: u32,                // Command tag
    data_transfer_length: u32,
    flags: u8,               // Bit 7: direction (0=Out, 1=In)
    lun: u8,
    cb_length: u8,           // SCSI CDB length (1-16)
    cb: [MAX_SCSI_CDB]u8,   // SCSI Command Descriptor Block

    pub fn init() CommandBlockWrapper {
        var cbw: CommandBlockWrapper = undefined;
        cbw.signature = CBW_SIGNATURE;
        cbw.tag = 0;
        cbw.data_transfer_length = 0;
        cbw.flags = 0;
        cbw.lun = 0;
        cbw.cb_length = 0;
        for (0..MAX_SCSI_CDB) |i| cbw.cb[i] = 0;
        return cbw;
    }

    pub fn setDataIn(self: *CommandBlockWrapper) void {
        self.flags = 0x80; // Direction: Device to Host
    }

    pub fn setDataOut(self: *CommandBlockWrapper) void {
        self.flags = 0x00; // Direction: Host to Device
    }
};

// ============================================================================
// Command Status Wrapper (CSW)
// ============================================================================

pub const CswStatus = enum(u8) {
    Passed = 0,
    Failed = 1,
    PhaseError = 2,
};

pub const CommandStatusWrapper = extern struct {
    signature: u32,          // CSW_SIGNATURE
    tag: u32,                // Matches CBW tag
    data_residue: u32,       // Difference between expected and actual data
    status: u8,              // CswStatus

    pub fn isValid(self: *const CommandStatusWrapper) bool {
        return self.signature == CSW_SIGNATURE;
    }

    pub fn passed(self: *const CommandStatusWrapper) bool {
        return self.status == @intFromEnum(CswStatus.Passed);
    }
};

// ============================================================================
// SCSI Inquiry Data
// ============================================================================

pub const ScsiInquiryData = struct {
    peripheral_type: u8,
    removable: bool,
    version: u8,
    vendor: [8]u8,
    product: [16]u8,
    revision: [4]u8,

    pub fn init() ScsiInquiryData {
        return .{
            .peripheral_type = 0,
            .removable = false,
            .version = 0,
            .vendor = [_]u8{0} ** 8,
            .product = [_]u8{0} ** 16,
            .revision = [_]u8{0} ** 4,
        };
    }

    pub fn isDisk(self: *const ScsiInquiryData) bool {
        return (self.peripheral_type & 0x1F) == 0x00;
    }

    pub fn isCdrom(self: *const ScsiInquiryData) bool {
        return (self.peripheral_type & 0x1F) == 0x05;
    }
};

// ============================================================================
// Sense data
// ============================================================================

pub const ScsiSenseData = struct {
    sense_key: u8,
    asc: u8,             // Additional Sense Code
    ascq: u8,            // Additional Sense Code Qualifier
    valid: bool,

    pub fn init() ScsiSenseData {
        return .{
            .sense_key = SENSE_NO_SENSE,
            .asc = 0,
            .ascq = 0,
            .valid = false,
        };
    }

    pub fn isError(self: *const ScsiSenseData) bool {
        return self.sense_key != SENSE_NO_SENSE and self.sense_key != SENSE_RECOVERED_ERROR;
    }

    pub fn isMediaError(self: *const ScsiSenseData) bool {
        return self.sense_key == SENSE_MEDIUM_ERROR;
    }

    pub fn isNotReady(self: *const ScsiSenseData) bool {
        return self.sense_key == SENSE_NOT_READY;
    }
};

// ============================================================================
// Logical Unit
// ============================================================================

pub const LogicalUnit = struct {
    lun_id: u8,
    active: bool,
    total_sectors: u64,
    sector_size: u32,
    read_only: bool,
    removable: bool,
    inquiry: ScsiInquiryData,
    last_sense: ScsiSenseData,
    read_count: u64,
    write_count: u64,
    error_count: u64,

    pub fn init(id: u8) LogicalUnit {
        return .{
            .lun_id = id,
            .active = false,
            .total_sectors = 0,
            .sector_size = USB_MSC_SECTOR_SIZE,
            .read_only = false,
            .removable = false,
            .inquiry = ScsiInquiryData.init(),
            .last_sense = ScsiSenseData.init(),
            .read_count = 0,
            .write_count = 0,
            .error_count = 0,
        };
    }

    pub fn capacityBytes(self: *const LogicalUnit) u64 {
        return self.total_sectors * @as(u64, self.sector_size);
    }

    pub fn capacityMB(self: *const LogicalUnit) u64 {
        return self.capacityBytes() / (1024 * 1024);
    }
};

// ============================================================================
// DMA buffer pool
// ============================================================================

pub const DmaBuffer = struct {
    phys_addr: u64,
    virt_addr: u64,
    size: u32,
    in_use: bool,

    pub fn init() DmaBuffer {
        return .{
            .phys_addr = 0,
            .virt_addr = 0,
            .size = 0,
            .in_use = false,
        };
    }
};

pub const DmaPool = struct {
    buffers: [MAX_DMA_BUFFERS]DmaBuffer,
    count: u32,

    pub fn init() DmaPool {
        var pool: DmaPool = undefined;
        pool.count = 0;
        for (0..MAX_DMA_BUFFERS) |i| pool.buffers[i] = DmaBuffer.init();
        return pool;
    }

    pub fn alloc(self: *DmaPool) ?*DmaBuffer {
        for (0..MAX_DMA_BUFFERS) |i| {
            if (!self.buffers[i].in_use and self.buffers[i].phys_addr != 0) {
                self.buffers[i].in_use = true;
                return &self.buffers[i];
            }
        }
        return null;
    }

    pub fn free(self: *DmaPool, buf: *DmaBuffer) void {
        buf.in_use = false;
    }

    pub fn registerBuffer(self: *DmaPool, phys: u64, virt: u64, size: u32) bool {
        if (self.count >= MAX_DMA_BUFFERS) return false;
        self.buffers[self.count] = .{
            .phys_addr = phys,
            .virt_addr = virt,
            .size = size,
            .in_use = false,
        };
        self.count += 1;
        return true;
    }
};

// ============================================================================
// USB Mass Storage Device
// ============================================================================

pub const UsbMscDevice = struct {
    device_addr: u8,
    active: bool,
    descriptor: UsbDeviceDescriptor,
    endpoints: [MAX_ENDPOINTS]UsbEndpoint,
    endpoint_count: u8,
    bulk_in: ?u8,       // Endpoint address for bulk in
    bulk_out: ?u8,      // Endpoint address for bulk out
    max_lun: u8,
    luns: [MAX_LUNS_PER_DEVICE]LogicalUnit,
    next_tag: u32,      // CBW tag counter
    dma_pool: DmaPool,

    // Statistics
    commands_sent: u64,
    commands_failed: u64,
    bytes_read: u64,
    bytes_written: u64,
    resets: u32,

    pub fn init(addr: u8) UsbMscDevice {
        var dev: UsbMscDevice = undefined;
        dev.device_addr = addr;
        dev.active = false;
        dev.descriptor = UsbDeviceDescriptor.init();
        dev.endpoint_count = 0;
        dev.bulk_in = null;
        dev.bulk_out = null;
        dev.max_lun = 0;
        dev.next_tag = 1;
        dev.commands_sent = 0;
        dev.commands_failed = 0;
        dev.bytes_read = 0;
        dev.bytes_written = 0;
        dev.resets = 0;
        dev.dma_pool = DmaPool.init();
        for (0..MAX_ENDPOINTS) |i| dev.endpoints[i] = UsbEndpoint.init();
        for (0..MAX_LUNS_PER_DEVICE) |i| {
            dev.luns[i] = LogicalUnit.init(@intCast(i));
        }
        return dev;
    }

    /// Add an endpoint
    pub fn addEndpoint(self: *UsbMscDevice, ep: UsbEndpoint) bool {
        if (self.endpoint_count >= MAX_ENDPOINTS) return false;
        self.endpoints[self.endpoint_count] = ep;
        self.endpoint_count += 1;

        // Auto-detect bulk endpoints
        if (ep.isBulkIn()) {
            self.bulk_in = ep.address;
        } else if (ep.isBulkOut()) {
            self.bulk_out = ep.address;
        }
        return true;
    }

    /// Check if device is ready for I/O
    pub fn isReady(self: *const UsbMscDevice) bool {
        return self.active and self.bulk_in != null and self.bulk_out != null;
    }

    /// Build INQUIRY CBW
    pub fn buildInquiry(self: *UsbMscDevice, lun: u8) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = 36;
        cbw.setDataIn();
        cbw.lun = lun;
        cbw.cb_length = 6;
        cbw.cb[0] = SCSI_INQUIRY;
        cbw.cb[4] = 36; // Allocation length
        self.commands_sent += 1;
        return cbw;
    }

    /// Build READ CAPACITY (10) CBW
    pub fn buildReadCapacity(self: *UsbMscDevice, lun: u8) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = 8;
        cbw.setDataIn();
        cbw.lun = lun;
        cbw.cb_length = 10;
        cbw.cb[0] = SCSI_READ_CAPACITY_10;
        self.commands_sent += 1;
        return cbw;
    }

    /// Build TEST UNIT READY CBW
    pub fn buildTestUnitReady(self: *UsbMscDevice, lun: u8) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = 0;
        cbw.setDataOut();
        cbw.lun = lun;
        cbw.cb_length = 6;
        cbw.cb[0] = SCSI_TEST_UNIT_READY;
        self.commands_sent += 1;
        return cbw;
    }

    /// Build REQUEST SENSE CBW
    pub fn buildRequestSense(self: *UsbMscDevice, lun: u8) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = 18;
        cbw.setDataIn();
        cbw.lun = lun;
        cbw.cb_length = 6;
        cbw.cb[0] = SCSI_REQUEST_SENSE;
        cbw.cb[4] = 18; // Allocation length
        self.commands_sent += 1;
        return cbw;
    }

    /// Build READ(10) CBW
    pub fn buildRead10(self: *UsbMscDevice, lun: u8, lba: u32, count: u16) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = @as(u32, count) * self.luns[lun].sector_size;
        cbw.setDataIn();
        cbw.lun = lun;
        cbw.cb_length = 10;
        cbw.cb[0] = SCSI_READ_10;
        // LBA (big-endian)
        cbw.cb[2] = @intCast((lba >> 24) & 0xFF);
        cbw.cb[3] = @intCast((lba >> 16) & 0xFF);
        cbw.cb[4] = @intCast((lba >> 8) & 0xFF);
        cbw.cb[5] = @intCast(lba & 0xFF);
        // Transfer length (big-endian)
        cbw.cb[7] = @intCast((count >> 8) & 0xFF);
        cbw.cb[8] = @intCast(count & 0xFF);
        self.commands_sent += 1;
        return cbw;
    }

    /// Build WRITE(10) CBW
    pub fn buildWrite10(self: *UsbMscDevice, lun: u8, lba: u32, count: u16) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = @as(u32, count) * self.luns[lun].sector_size;
        cbw.setDataOut();
        cbw.lun = lun;
        cbw.cb_length = 10;
        cbw.cb[0] = SCSI_WRITE_10;
        cbw.cb[2] = @intCast((lba >> 24) & 0xFF);
        cbw.cb[3] = @intCast((lba >> 16) & 0xFF);
        cbw.cb[4] = @intCast((lba >> 8) & 0xFF);
        cbw.cb[5] = @intCast(lba & 0xFF);
        cbw.cb[7] = @intCast((count >> 8) & 0xFF);
        cbw.cb[8] = @intCast(count & 0xFF);
        self.commands_sent += 1;
        return cbw;
    }

    /// Build SYNCHRONIZE CACHE CBW
    pub fn buildSyncCache(self: *UsbMscDevice, lun: u8) CommandBlockWrapper {
        var cbw = CommandBlockWrapper.init();
        cbw.tag = self.next_tag;
        self.next_tag +%= 1;
        cbw.data_transfer_length = 0;
        cbw.setDataOut();
        cbw.lun = lun;
        cbw.cb_length = 10;
        cbw.cb[0] = SCSI_SYNCHRONIZE_CACHE;
        self.commands_sent += 1;
        return cbw;
    }
};

// ============================================================================
// USB Mass Storage Driver (manages all MSC devices)
// ============================================================================

pub const UsbMscDriver = struct {
    devices: [MAX_USB_DEVICES]UsbMscDevice,
    device_count: u32,

    pub fn init() UsbMscDriver {
        var drv: UsbMscDriver = undefined;
        drv.device_count = 0;
        for (0..MAX_USB_DEVICES) |i| {
            drv.devices[i] = UsbMscDevice.init(@intCast(i));
        }
        return drv;
    }

    /// Register a new device
    pub fn registerDevice(self: *UsbMscDriver, addr: u8) ?u32 {
        if (self.device_count >= MAX_USB_DEVICES) return null;
        const idx = self.device_count;
        self.devices[idx] = UsbMscDevice.init(addr);
        self.devices[idx].active = true;
        self.device_count += 1;
        return idx;
    }

    /// Remove a device (hot-unplug)
    pub fn removeDevice(self: *UsbMscDriver, idx: u32) bool {
        if (idx >= MAX_USB_DEVICES) return false;
        if (!self.devices[idx].active) return false;
        self.devices[idx].active = false;
        return true;
    }

    /// Get a device reference
    pub fn getDevice(self: *UsbMscDriver, idx: u32) ?*UsbMscDevice {
        if (idx >= MAX_USB_DEVICES) return null;
        if (!self.devices[idx].active) return null;
        return &self.devices[idx];
    }

    /// Total capacity across all devices (bytes)
    pub fn totalCapacity(self: *const UsbMscDriver) u64 {
        var total: u64 = 0;
        for (0..self.device_count) |i| {
            if (self.devices[i].active) {
                for (0..MAX_LUNS_PER_DEVICE) |l| {
                    if (self.devices[i].luns[l].active) {
                        total += self.devices[i].luns[l].capacityBytes();
                    }
                }
            }
        }
        return total;
    }
};

// ============================================================================
// Global instance
// ============================================================================

var usb_msc_driver: UsbMscDriver = UsbMscDriver.init();

pub fn getUsbMscDriver() *UsbMscDriver {
    return &usb_msc_driver;
}
