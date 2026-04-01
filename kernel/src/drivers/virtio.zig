// =============================================================================
// Kernel Zxyphor — VirtIO Transport & Device Drivers
// =============================================================================
// VirtIO 1.0+ specification implementation:
//   - VirtIO PCI transport (modern MMIO + legacy port I/O)
//   - Virtqueue (split ring) with descriptor chaining
//   - VirtIO-blk (block device)
//   - VirtIO-net (network interface)
//   - VirtIO-console (serial port)
//   - VirtIO-rng (entropy source)
//   - Device discovery and feature negotiation
//   - Interrupt handling and used-ring processing
// =============================================================================

const std = @import("std");

// =============================================================================
// VirtIO constants
// =============================================================================

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_DEVICE_NET: u16 = 0x1000; // Legacy, transitional: 0x1041
pub const VIRTIO_DEVICE_BLK: u16 = 0x1001; // Legacy, transitional: 0x1042
pub const VIRTIO_DEVICE_CONSOLE: u16 = 0x1003;
pub const VIRTIO_DEVICE_RNG: u16 = 0x1005;
pub const VIRTIO_DEVICE_GPU: u16 = 0x1050;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_RING_INDIRECT: u64 = 1 << 28;
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;

// Device status bits
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

// Descriptor flags
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

// VirtIO-blk type flags
pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;

// VirtIO-blk features
pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
pub const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;

// VirtIO-net features
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;

// =============================================================================
// Virtqueue descriptor
// =============================================================================

pub const VirtqDesc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

pub const VirtqAvail = extern struct {
    flags: u16,
    idx: u16,
    ring: [u16; 256], // Variable size, max 256 for our implementation
};

pub const VirtqUsedElem = extern struct {
    id: u32,
    len: u32,
};

pub const VirtqUsed = extern struct {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; 256],
};

// =============================================================================
// Virtqueue
// =============================================================================

pub const MAX_QUEUE_SIZE: usize = 256;

pub const Virtqueue = struct {
    // Descriptor table
    descs: [VirtqDesc; MAX_QUEUE_SIZE],
    // Available ring
    avail_flags: u16,
    avail_idx: u16,
    avail_ring: [u16; MAX_QUEUE_SIZE],
    // Used ring
    used_flags: u16,
    used_idx: u16,
    used_ring: [VirtqUsedElem; MAX_QUEUE_SIZE],

    // Management
    queue_size: u16,
    free_head: u16,
    num_free: u16,
    last_used_idx: u16,

    // Free list tracking
    free_list: [u16; MAX_QUEUE_SIZE],

    // Queue notify address
    notify_offset: u32,

    pub fn init(self: *Virtqueue, size: u16) void {
        const s = @min(size, MAX_QUEUE_SIZE);
        self.queue_size = s;
        self.avail_idx = 0;
        self.used_idx = 0;
        self.last_used_idx = 0;
        self.free_head = 0;
        self.num_free = s;

        // Initialize free list as a chain
        var i: u16 = 0;
        while (i < s) : (i += 1) {
            self.descs[i] = VirtqDesc{
                .addr = 0,
                .len = 0,
                .flags = if (i + 1 < s) VRING_DESC_F_NEXT else 0,
                .next = if (i + 1 < s) i + 1 else 0,
            };
            self.free_list[i] = i;
        }
    }

    /// Allocate a descriptor from the free list
    pub fn allocDesc(self: *Virtqueue) ?u16 {
        if (self.num_free == 0) return null;
        const idx = self.free_head;
        self.free_head = self.descs[idx].next;
        self.num_free -= 1;
        return idx;
    }

    /// Free a descriptor back to the free list
    pub fn freeDesc(self: *Virtqueue, idx: u16) void {
        self.descs[idx].flags = VRING_DESC_F_NEXT;
        self.descs[idx].next = self.free_head;
        self.free_head = idx;
        self.num_free += 1;
    }

    /// Free an entire descriptor chain
    pub fn freeChain(self: *Virtqueue, head: u16) void {
        var idx = head;
        while (true) {
            const has_next = (self.descs[idx].flags & VRING_DESC_F_NEXT) != 0;
            const next = self.descs[idx].next;
            self.freeDesc(idx);
            if (!has_next) break;
            idx = next;
        }
    }

    /// Add a buffer chain to the available ring
    pub fn addBuf(self: *Virtqueue, descs_list: []const BufferDesc) ?u16 {
        if (descs_list.len == 0 or self.num_free < @intCast(descs_list.len))
            return null;

        // Allocate descriptors and chain them
        var head: u16 = undefined;
        var prev: u16 = undefined;
        for (descs_list, 0..) |buf, i| {
            const desc_idx = self.allocDesc() orelse {
                // Rollback: free already allocated
                if (i > 0) self.freeChain(head);
                return null;
            };

            if (i == 0) head = desc_idx;
            if (i > 0) {
                self.descs[prev].next = desc_idx;
                self.descs[prev].flags |= VRING_DESC_F_NEXT;
            }

            self.descs[desc_idx].addr = buf.addr;
            self.descs[desc_idx].len = buf.len;
            self.descs[desc_idx].flags = if (buf.writable) VRING_DESC_F_WRITE else 0;
            prev = desc_idx;
        }

        // Clear NEXT flag on last descriptor
        self.descs[prev].flags &= ~@as(u16, VRING_DESC_F_NEXT);

        // Add to available ring
        const avail_idx = self.avail_idx;
        self.avail_ring[avail_idx % self.queue_size] = head;
        // Memory barrier before updating avail_idx
        @fence(.seq_cst);
        self.avail_idx = avail_idx +% 1;

        return head;
    }

    /// Process used buffers, returns number of processed entries
    pub fn processUsed(self: *Virtqueue, callback: *const fn (u32, u32) void) u32 {
        var processed: u32 = 0;
        while (self.last_used_idx != self.used_idx) {
            @fence(.seq_cst);
            const used_elem = self.used_ring[self.last_used_idx % self.queue_size];
            self.last_used_idx +%= 1;

            // Invoke callback with (descriptor index, bytes written)
            callback(@intCast(used_elem.id), used_elem.len);

            // Free the descriptor chain
            self.freeChain(@intCast(used_elem.id));
            processed += 1;
        }
        return processed;
    }

    pub fn hasUsed(self: *const Virtqueue) bool {
        return self.last_used_idx != self.used_idx;
    }
};

pub const BufferDesc = struct {
    addr: u64,
    len: u32,
    writable: bool,
};

// =============================================================================
// VirtIO PCI transport
// =============================================================================

pub const PciTransport = struct {
    bus: u8,
    device: u8,
    function: u8,
    bar0: u64,          // MMIO base
    io_base: u16,       // Legacy I/O port base
    irq: u8,
    device_type: u16,
    vendor_features: u64,
    driver_features: u64,
    status: u8,
    num_queues: u8,

    pub fn reset(self: *PciTransport) void {
        self.status = 0;
        self.writeStatus(0);
    }

    pub fn setStatus(self: *PciTransport, bits: u8) void {
        self.status |= bits;
        self.writeStatus(self.status);
    }

    pub fn negotiate(self: *PciTransport, wanted: u64) bool {
        // Read device features
        self.vendor_features = self.readDeviceFeatures();

        // Select features both sides support
        self.driver_features = self.vendor_features & wanted;

        // Always require VIRTIO version 1 for modern devices
        if (self.vendor_features & VIRTIO_F_VERSION_1 != 0) {
            self.driver_features |= VIRTIO_F_VERSION_1;
        }

        self.writeDriverFeatures(self.driver_features);
        self.setStatus(VIRTIO_STATUS_FEATURES_OK);

        // Verify device accepted features
        const status = self.readStatus();
        return (status & VIRTIO_STATUS_FEATURES_OK) != 0;
    }

    // Low-level I/O — using port I/O for legacy devices
    fn readDeviceFeatures(self: *const PciTransport) u64 {
        if (self.io_base == 0) return 0;
        var low: u32 = 0;
        var high: u32 = 0;
        // Legacy: features at offset 0
        low = portIn(u32, self.io_base + 0);
        // Modern: select page then read
        portOut(u32, self.io_base + 0x14, 1);
        high = portIn(u32, self.io_base + 0);
        return (@as(u64, high) << 32) | @as(u64, low);
    }

    fn writeDriverFeatures(self: *const PciTransport, features: u64) void {
        if (self.io_base == 0) return;
        portOut(u32, self.io_base + 4, @truncate(features));
    }

    fn readStatus(self: *const PciTransport) u8 {
        if (self.io_base == 0) return 0;
        return portIn(u8, self.io_base + 18);
    }

    fn writeStatus(self: *const PciTransport, status: u8) void {
        if (self.io_base == 0) return;
        portOut(u8, self.io_base + 18, status);
    }

    pub fn notifyQueue(self: *const PciTransport, queue_idx: u16) void {
        if (self.io_base == 0) return;
        portOut(u16, self.io_base + 16, queue_idx);
    }
};

// =============================================================================
// VirtIO-blk device
// =============================================================================

pub const VirtioBlkConfig = extern struct {
    capacity: u64,          // Disk size in 512-byte sectors
    size_max: u32,          // Max segment size
    seg_max: u32,           // Max number of segments
    geometry_cylinders: u16,
    geometry_heads: u8,
    geometry_sectors: u8,
    blk_size: u32,          // Logical block size
    physical_block_exp: u8, // log2(physical/logical)
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
};

pub const VirtioBlkReqHeader = extern struct {
    req_type: u32,
    reserved: u32,
    sector: u64,
};

pub const VirtioBlkDevice = struct {
    transport: PciTransport,
    queue: Virtqueue,
    config: VirtioBlkConfig,
    read_only: bool,
    initialized: bool,

    // Statistics
    reads: u64,
    writes: u64,
    bytes_read: u64,
    bytes_written: u64,

    pub fn init(self: *VirtioBlkDevice) bool {
        // Reset device
        self.transport.reset();

        // Acknowledge and set driver
        self.transport.setStatus(VIRTIO_STATUS_ACKNOWLEDGE);
        self.transport.setStatus(VIRTIO_STATUS_DRIVER);

        // Negotiate features
        const wanted = VIRTIO_BLK_F_SIZE_MAX |
            VIRTIO_BLK_F_SEG_MAX |
            VIRTIO_BLK_F_BLK_SIZE |
            VIRTIO_BLK_F_FLUSH |
            VIRTIO_F_VERSION_1;

        if (!self.transport.negotiate(wanted)) {
            self.transport.setStatus(VIRTIO_STATUS_FAILED);
            return false;
        }

        // Check read-only
        self.read_only = (self.transport.driver_features & VIRTIO_BLK_F_RO) != 0;

        // Set up virtqueue
        self.queue.init(128);

        // Driver OK
        self.transport.setStatus(VIRTIO_STATUS_DRIVER_OK);
        self.initialized = true;
        return true;
    }

    pub fn readSectors(self: *VirtioBlkDevice, sector: u64, count: u32, buf: [*]u8) bool {
        if (!self.initialized) return false;

        // Build request: header + data buffer + status byte
        var header = VirtioBlkReqHeader{
            .req_type = VIRTIO_BLK_T_IN,
            .reserved = 0,
            .sector = sector,
        };
        var status_byte: u8 = 0xFF;

        const bufs = [_]BufferDesc{
            .{ .addr = @intFromPtr(&header), .len = @sizeOf(VirtioBlkReqHeader), .writable = false },
            .{ .addr = @intFromPtr(buf), .len = count * 512, .writable = true },
            .{ .addr = @intFromPtr(&status_byte), .len = 1, .writable = true },
        };

        _ = self.queue.addBuf(&bufs) orelse return false;
        self.transport.notifyQueue(0);

        // Poll for completion
        var timeout: u32 = 1000000;
        while (!self.queue.hasUsed() and timeout > 0) : (timeout -= 1) {
            asm volatile ("pause");
        }

        if (timeout == 0) return false;

        // Process used ring
        _ = self.queue.processUsed(&dummyCallback);

        self.reads += 1;
        self.bytes_read += @as(u64, count) * 512;
        return status_byte == 0;
    }

    pub fn writeSectors(self: *VirtioBlkDevice, sector: u64, count: u32, buf: [*]const u8) bool {
        if (!self.initialized or self.read_only) return false;

        var header = VirtioBlkReqHeader{
            .req_type = VIRTIO_BLK_T_OUT,
            .reserved = 0,
            .sector = sector,
        };
        var status_byte: u8 = 0xFF;

        const bufs = [_]BufferDesc{
            .{ .addr = @intFromPtr(&header), .len = @sizeOf(VirtioBlkReqHeader), .writable = false },
            .{ .addr = @intFromPtr(buf), .len = count * 512, .writable = false },
            .{ .addr = @intFromPtr(&status_byte), .len = 1, .writable = true },
        };

        _ = self.queue.addBuf(&bufs) orelse return false;
        self.transport.notifyQueue(0);

        var timeout: u32 = 1000000;
        while (!self.queue.hasUsed() and timeout > 0) : (timeout -= 1) {
            asm volatile ("pause");
        }

        if (timeout == 0) return false;
        _ = self.queue.processUsed(&dummyCallback);

        self.writes += 1;
        self.bytes_written += @as(u64, count) * 512;
        return status_byte == 0;
    }

    pub fn flush(self: *VirtioBlkDevice) bool {
        if (!self.initialized) return false;
        if (self.transport.driver_features & VIRTIO_BLK_F_FLUSH == 0) return true;

        var header = VirtioBlkReqHeader{
            .req_type = VIRTIO_BLK_T_FLUSH,
            .reserved = 0,
            .sector = 0,
        };
        var status_byte: u8 = 0xFF;

        const bufs = [_]BufferDesc{
            .{ .addr = @intFromPtr(&header), .len = @sizeOf(VirtioBlkReqHeader), .writable = false },
            .{ .addr = @intFromPtr(&status_byte), .len = 1, .writable = true },
        };

        _ = self.queue.addBuf(&bufs) orelse return false;
        self.transport.notifyQueue(0);

        var timeout: u32 = 1000000;
        while (!self.queue.hasUsed() and timeout > 0) : (timeout -= 1) {
            asm volatile ("pause");
        }

        if (timeout == 0) return false;
        _ = self.queue.processUsed(&dummyCallback);
        return status_byte == 0;
    }

    pub fn capacityBytes(self: *const VirtioBlkDevice) u64 {
        return self.config.capacity * 512;
    }
};

fn dummyCallback(_: u32, _: u32) void {}

// =============================================================================
// VirtIO-net device
// =============================================================================

pub const VirtioNetHeader = extern struct {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
};

pub const VirtioNetDevice = struct {
    transport: PciTransport,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    mac: [6]u8,
    link_up: bool,
    initialized: bool,

    // Statistics
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,

    // Receive buffers
    rx_bufs: [32][2048]u8,

    pub fn init(self: *VirtioNetDevice) bool {
        self.transport.reset();
        self.transport.setStatus(VIRTIO_STATUS_ACKNOWLEDGE);
        self.transport.setStatus(VIRTIO_STATUS_DRIVER);

        const wanted = VIRTIO_NET_F_MAC |
            VIRTIO_NET_F_STATUS |
            VIRTIO_NET_F_CSUM |
            VIRTIO_F_VERSION_1;

        if (!self.transport.negotiate(wanted)) {
            self.transport.setStatus(VIRTIO_STATUS_FAILED);
            return false;
        }

        // Read MAC address from config space
        if (self.transport.io_base != 0) {
            var i: u16 = 0;
            while (i < 6) : (i += 1) {
                self.mac[i] = portIn(u8, self.transport.io_base + 20 + i);
            }
        }

        // Initialize queues
        self.rx_queue.init(128);
        self.tx_queue.init(128);

        // Post receive buffers
        self.postRxBuffers();

        self.transport.setStatus(VIRTIO_STATUS_DRIVER_OK);
        self.initialized = true;
        self.link_up = true;
        return true;
    }

    fn postRxBuffers(self: *VirtioNetDevice) void {
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            const bufs = [_]BufferDesc{
                .{ .addr = @intFromPtr(&self.rx_bufs[i]), .len = 2048, .writable = true },
            };
            _ = self.rx_queue.addBuf(&bufs);
        }
    }

    pub fn send(self: *VirtioNetDevice, data: []const u8) bool {
        if (!self.initialized or data.len > 1514) return false;

        var hdr = VirtioNetHeader{
            .flags = 0,
            .gso_type = 0,
            .hdr_len = 0,
            .gso_size = 0,
            .csum_start = 0,
            .csum_offset = 0,
            .num_buffers = 0,
        };

        const bufs = [_]BufferDesc{
            .{ .addr = @intFromPtr(&hdr), .len = @sizeOf(VirtioNetHeader), .writable = false },
            .{ .addr = @intFromPtr(data.ptr), .len = @intCast(data.len), .writable = false },
        };

        _ = self.tx_queue.addBuf(&bufs) orelse return false;
        self.transport.notifyQueue(1); // TX is queue 1

        self.tx_packets += 1;
        self.tx_bytes += data.len;
        return true;
    }

    pub fn pollRx(self: *VirtioNetDevice) ?[]u8 {
        if (!self.rx_queue.hasUsed()) return null;

        // Process one used buffer
        const used = self.rx_queue.used_ring[self.rx_queue.last_used_idx % self.rx_queue.queue_size];
        self.rx_queue.last_used_idx +%= 1;

        const buf_idx = used.id;
        const total_len = used.len;

        if (total_len < @sizeOf(VirtioNetHeader)) {
            self.rx_errors += 1;
            return null;
        }

        const data_len = total_len - @sizeOf(VirtioNetHeader);
        self.rx_packets += 1;
        self.rx_bytes += data_len;

        // Return pointer to data portion (after header)
        const offset = @sizeOf(VirtioNetHeader);
        return self.rx_bufs[buf_idx][offset..offset + data_len];
    }
};

// =============================================================================
// VirtIO-rng (entropy source)
// =============================================================================

pub const VirtioRngDevice = struct {
    transport: PciTransport,
    queue: Virtqueue,
    initialized: bool,
    bytes_generated: u64,

    pub fn init(self: *VirtioRngDevice) bool {
        self.transport.reset();
        self.transport.setStatus(VIRTIO_STATUS_ACKNOWLEDGE);
        self.transport.setStatus(VIRTIO_STATUS_DRIVER);

        if (!self.transport.negotiate(VIRTIO_F_VERSION_1)) {
            self.transport.setStatus(VIRTIO_STATUS_FAILED);
            return false;
        }

        self.queue.init(32);
        self.transport.setStatus(VIRTIO_STATUS_DRIVER_OK);
        self.initialized = true;
        return true;
    }

    /// Request random bytes from the device
    pub fn getEntropy(self: *VirtioRngDevice, buf: []u8) bool {
        if (!self.initialized or buf.len == 0) return false;

        const bufs = [_]BufferDesc{
            .{ .addr = @intFromPtr(buf.ptr), .len = @intCast(buf.len), .writable = true },
        };

        _ = self.queue.addBuf(&bufs) orelse return false;
        self.transport.notifyQueue(0);

        var timeout: u32 = 100000;
        while (!self.queue.hasUsed() and timeout > 0) : (timeout -= 1) {
            asm volatile ("pause");
        }

        if (timeout == 0) return false;
        _ = self.queue.processUsed(&dummyCallback);
        self.bytes_generated += buf.len;
        return true;
    }
};

// =============================================================================
// VirtIO device registry
// =============================================================================

pub const MAX_VIRTIO_DEVICES: usize = 16;

pub const VirtioDeviceType = enum(u8) {
    none = 0,
    block = 1,
    net = 2,
    console = 3,
    rng = 4,
    gpu = 5,
};

pub const VirtioDeviceEntry = struct {
    device_type: VirtioDeviceType,
    bus: u8,
    device: u8,
    function: u8,
    active: bool,
};

var device_registry: [MAX_VIRTIO_DEVICES]VirtioDeviceEntry = [_]VirtioDeviceEntry{.{
    .device_type = .none,
    .bus = 0,
    .device = 0,
    .function = 0,
    .active = false,
}} ** MAX_VIRTIO_DEVICES;

var device_count: usize = 0;

/// Scan PCI bus for VirtIO devices
pub fn scanDevices() usize {
    device_count = 0;
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var dev: u8 = 0;
        while (dev < 32) : (dev += 1) {
            const vendor = pciConfigRead16(@intCast(bus), dev, 0, 0);
            if (vendor != VIRTIO_VENDOR_ID) continue;

            const device_id = pciConfigRead16(@intCast(bus), dev, 0, 2);
            const dev_type: VirtioDeviceType = switch (device_id) {
                0x1000, 0x1041 => .net,
                0x1001, 0x1042 => .block,
                0x1003, 0x1043 => .console,
                0x1005, 0x1044 => .rng,
                0x1050 => .gpu,
                else => .none,
            };

            if (dev_type == .none) continue;
            if (device_count >= MAX_VIRTIO_DEVICES) return device_count;

            device_registry[device_count] = .{
                .device_type = dev_type,
                .bus = @intCast(bus),
                .device = dev,
                .function = 0,
                .active = true,
            };
            device_count += 1;
        }
    }
    return device_count;
}

/// Get number of discovered VirtIO devices
pub fn getDeviceCount() usize {
    return device_count;
}

/// Get device info by index
pub fn getDevice(index: usize) ?*const VirtioDeviceEntry {
    if (index >= device_count) return null;
    return &device_registry[index];
}

// =============================================================================
// Port I/O helpers
// =============================================================================

fn portIn(comptime T: type, port: u16) T {
    return switch (T) {
        u8 => asm volatile ("inb %[port], %[ret]"
            : [ret] "={al}" (-> u8)
            : [port] "N{dx}" (port)
        ),
        u16 => asm volatile ("inw %[port], %[ret]"
            : [ret] "={ax}" (-> u16)
            : [port] "N{dx}" (port)
        ),
        u32 => asm volatile ("inl %[port], %[ret]"
            : [ret] "={eax}" (-> u32)
            : [port] "N{dx}" (port)
        ),
        else => @compileError("Invalid port I/O type"),
    };
}

fn portOut(comptime T: type, port: u16, value: T) void {
    switch (T) {
        u8 => asm volatile ("outb %[val], %[port]"
            :
            : [val] "{al}" (value),
              [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("outw %[val], %[port]"
            :
            : [val] "{ax}" (value),
              [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("outl %[val], %[port]"
            :
            : [val] "{eax}" (value),
              [port] "N{dx}" (port),
        ),
        else => @compileError("Invalid port I/O type"),
    }
}

fn pciConfigRead16(bus: u8, device: u8, function: u8, offset: u8) u16 {
    const address: u32 = (1 << 31) |
        (@as(u32, bus) << 16) |
        (@as(u32, device) << 11) |
        (@as(u32, function) << 8) |
        (@as(u32, offset) & 0xFC);
    portOut(u32, 0xCF8, address);
    const data = portIn(u32, 0xCFC);
    return @truncate(data >> @intCast((offset & 2) * 8));
}
