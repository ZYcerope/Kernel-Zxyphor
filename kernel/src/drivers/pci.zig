// =============================================================================
// Kernel Zxyphor - PCI Bus Driver
// =============================================================================
// PCI (Peripheral Component Interconnect) bus enumeration and configuration.
// Scans all PCI buses to discover devices and provides configuration space
// read/write access.
//
// PCI configuration space is accessed via:
//   - Port I/O: CONFIG_ADDRESS (0xCF8) and CONFIG_DATA (0xCFC)
//   - MMIO: Using MCFG (PCIe Enhanced Configuration)
//
// This driver supports:
//   - PCI 3.0 configuration space (256 bytes)
//   - Bus enumeration with recursive bridge scanning
//   - Device identification and classification
//   - BAR (Base Address Register) parsing
//   - Interrupt routing (legacy PIC IRQs)
//   - MSI (Message Signaled Interrupts) capability detection
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// PCI I/O Ports (Configuration Mechanism #1)
// =============================================================================
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// =============================================================================
// PCI Configuration Space Register Offsets
// =============================================================================
pub const PCI_VENDOR_ID: u8 = 0x00;
pub const PCI_DEVICE_ID: u8 = 0x02;
pub const PCI_COMMAND: u8 = 0x04;
pub const PCI_STATUS: u8 = 0x06;
pub const PCI_REVISION_ID: u8 = 0x08;
pub const PCI_PROG_IF: u8 = 0x09;
pub const PCI_SUBCLASS: u8 = 0x0A;
pub const PCI_CLASS: u8 = 0x0B;
pub const PCI_CACHE_LINE: u8 = 0x0C;
pub const PCI_LATENCY: u8 = 0x0D;
pub const PCI_HEADER_TYPE: u8 = 0x0E;
pub const PCI_BIST: u8 = 0x0F;
pub const PCI_BAR0: u8 = 0x10;
pub const PCI_BAR1: u8 = 0x14;
pub const PCI_BAR2: u8 = 0x18;
pub const PCI_BAR3: u8 = 0x1C;
pub const PCI_BAR4: u8 = 0x20;
pub const PCI_BAR5: u8 = 0x24;
pub const PCI_INTERRUPT_LINE: u8 = 0x3C;
pub const PCI_INTERRUPT_PIN: u8 = 0x3D;
pub const PCI_CAPABILITIES: u8 = 0x34;

// PCI-to-PCI bridge specific registers
pub const PCI_PRIMARY_BUS: u8 = 0x18;
pub const PCI_SECONDARY_BUS: u8 = 0x19;
pub const PCI_SUBORDINATE_BUS: u8 = 0x1A;

// =============================================================================
// PCI Command register bits
// =============================================================================
pub const CMD_IO_SPACE: u16 = 0x0001;
pub const CMD_MEMORY_SPACE: u16 = 0x0002;
pub const CMD_BUS_MASTER: u16 = 0x0004;
pub const CMD_SPECIAL_CYCLES: u16 = 0x0008;
pub const CMD_MWI: u16 = 0x0010;
pub const CMD_VGA_SNOOP: u16 = 0x0020;
pub const CMD_PARITY_ERROR: u16 = 0x0040;
pub const CMD_SERR: u16 = 0x0100;
pub const CMD_FAST_B2B: u16 = 0x0200;
pub const CMD_INTERRUPT_DISABLE: u16 = 0x0400;

// =============================================================================
// PCI Device Classes
// =============================================================================
pub const CLASS_UNCLASSIFIED: u8 = 0x00;
pub const CLASS_STORAGE: u8 = 0x01;
pub const CLASS_NETWORK: u8 = 0x02;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const CLASS_MULTIMEDIA: u8 = 0x04;
pub const CLASS_MEMORY: u8 = 0x05;
pub const CLASS_BRIDGE: u8 = 0x06;
pub const CLASS_COMMUNICATION: u8 = 0x07;
pub const CLASS_SYSTEM: u8 = 0x08;
pub const CLASS_INPUT: u8 = 0x09;
pub const CLASS_DOCKING: u8 = 0x0A;
pub const CLASS_PROCESSOR: u8 = 0x0B;
pub const CLASS_SERIAL: u8 = 0x0C;
pub const CLASS_WIRELESS: u8 = 0x0D;

// =============================================================================
// Storage subclasses
// =============================================================================
pub const SUBCLASS_IDE: u8 = 0x01;
pub const SUBCLASS_FLOPPY: u8 = 0x02;
pub const SUBCLASS_ATA: u8 = 0x05;
pub const SUBCLASS_SATA: u8 = 0x06;
pub const SUBCLASS_NVM: u8 = 0x08;

// Bridge subclasses
pub const SUBCLASS_HOST_BRIDGE: u8 = 0x00;
pub const SUBCLASS_ISA_BRIDGE: u8 = 0x01;
pub const SUBCLASS_PCI_BRIDGE: u8 = 0x04;

// =============================================================================
// PCI Capability IDs
// =============================================================================
pub const CAP_POWER_MGMT: u8 = 0x01;
pub const CAP_AGP: u8 = 0x02;
pub const CAP_VPD: u8 = 0x03;
pub const CAP_MSI: u8 = 0x05;
pub const CAP_VENDOR: u8 = 0x09;
pub const CAP_PCIE: u8 = 0x10;
pub const CAP_MSIX: u8 = 0x11;

// =============================================================================
// BAR types
// =============================================================================
pub const BarType = enum {
    none,
    io,
    memory32,
    memory64,
};

pub const Bar = struct {
    bar_type: BarType = .none,
    base: u64 = 0,
    size: u64 = 0,
    prefetchable: bool = false,
};

// =============================================================================
// PCI Device descriptor
// =============================================================================
pub const PciDevice = struct {
    bus: u8 = 0,
    device: u5 = 0,
    function: u3 = 0,
    vendor_id: u16 = 0xFFFF,
    device_id: u16 = 0xFFFF,
    class_code: u8 = 0,
    subclass: u8 = 0,
    prog_if: u8 = 0,
    revision: u8 = 0,
    header_type: u8 = 0,
    irq_line: u8 = 0xFF,
    irq_pin: u8 = 0,
    bars: [6]Bar = [_]Bar{.{}} ** 6,
    has_msi: bool = false,
    msi_cap_offset: u8 = 0,
    is_valid: bool = false,

    pub fn isMultiFunction(self: *const PciDevice) bool {
        return (self.header_type & 0x80) != 0;
    }

    pub fn isBridge(self: *const PciDevice) bool {
        return self.class_code == CLASS_BRIDGE and self.subclass == SUBCLASS_PCI_BRIDGE;
    }

    pub fn className(self: *const PciDevice) []const u8 {
        return switch (self.class_code) {
            CLASS_UNCLASSIFIED => "Unclassified",
            CLASS_STORAGE => "Storage",
            CLASS_NETWORK => "Network",
            CLASS_DISPLAY => "Display",
            CLASS_MULTIMEDIA => "Multimedia",
            CLASS_MEMORY => "Memory",
            CLASS_BRIDGE => "Bridge",
            CLASS_COMMUNICATION => "Communication",
            CLASS_SYSTEM => "System",
            CLASS_INPUT => "Input",
            CLASS_SERIAL => "Serial Bus",
            CLASS_WIRELESS => "Wireless",
            else => "Unknown",
        };
    }
};

// =============================================================================
// Device table
// =============================================================================
const MAX_PCI_DEVICES: usize = 256;
var devices: [MAX_PCI_DEVICES]PciDevice = undefined;
var device_count: usize = 0;

// =============================================================================
// Configuration Space Access
// =============================================================================

/// Build a PCI config address for a given BDF (Bus, Device, Function)
fn makeAddress(bus: u8, device: u5, function: u3, offset: u8) u32 {
    return @as(u32, 0x80000000) | // Enable bit
        (@as(u32, bus) << 16) |
        (@as(u32, @intCast(device)) << 11) |
        (@as(u32, @intCast(function)) << 8) |
        (@as(u32, offset) & 0xFC);
}

/// Read a 32-bit value from PCI configuration space
pub fn configRead32(bus: u8, device: u5, function: u3, offset: u8) u32 {
    main.cpu.outl(PCI_CONFIG_ADDR, makeAddress(bus, device, function, offset));
    return main.cpu.inl(PCI_CONFIG_DATA);
}

/// Read a 16-bit value from PCI configuration space
pub fn configRead16(bus: u8, device: u5, function: u3, offset: u8) u16 {
    const val = configRead32(bus, device, function, offset & 0xFC);
    return @truncate(val >> @as(u5, @truncate((offset & 2) * 8)));
}

/// Read an 8-bit value from PCI configuration space
pub fn configRead8(bus: u8, device: u5, function: u3, offset: u8) u8 {
    const val = configRead32(bus, device, function, offset & 0xFC);
    return @truncate(val >> @as(u5, @truncate((offset & 3) * 8)));
}

/// Write a 32-bit value to PCI configuration space
pub fn configWrite32(bus: u8, device: u5, function: u3, offset: u8, value: u32) void {
    main.cpu.outl(PCI_CONFIG_ADDR, makeAddress(bus, device, function, offset));
    main.cpu.outl(PCI_CONFIG_DATA, value);
}

/// Write a 16-bit value to PCI configuration space
pub fn configWrite16(bus: u8, device: u5, function: u3, offset: u8, value: u16) void {
    const addr = makeAddress(bus, device, function, offset & 0xFC);
    main.cpu.outl(PCI_CONFIG_ADDR, addr);
    var val = main.cpu.inl(PCI_CONFIG_DATA);
    const shift: u5 = @truncate((offset & 2) * 8);
    val &= ~(@as(u32, 0xFFFF) << shift);
    val |= @as(u32, value) << shift;
    main.cpu.outl(PCI_CONFIG_DATA, val);
}

// =============================================================================
// Bus Enumeration
// =============================================================================
pub fn initialize() void {
    device_count = 0;
    for (&devices) |*d| {
        d.* = PciDevice{};
    }

    // Check if PCI exists by reading bus 0, device 0
    const vendor = configRead16(0, 0, 0, PCI_VENDOR_ID);
    if (vendor == 0xFFFF) {
        main.klog(.warn, "PCI: no PCI bus detected", .{});
        return;
    }

    // Check for multi-function host controller
    const header_type = configRead8(0, 0, 0, PCI_HEADER_TYPE);
    if ((header_type & 0x80) != 0) {
        // Multiple PCI host controllers
        var func: u3 = 0;
        while (true) {
            if (configRead16(0, 0, func, PCI_VENDOR_ID) != 0xFFFF) {
                scanBus(func);
            }
            if (func == 7) break;
            func += 1;
        }
    } else {
        // Single PCI host controller
        scanBus(0);
    }

    main.klog(.info, "PCI: discovered {d} devices", .{device_count});
}

fn scanBus(bus: u8) void {
    var dev: u5 = 0;
    while (true) {
        scanDevice(bus, dev);
        if (dev == 31) break;
        dev += 1;
    }
}

fn scanDevice(bus: u8, device: u5) void {
    const vendor = configRead16(bus, device, 0, PCI_VENDOR_ID);
    if (vendor == 0xFFFF) return;

    scanFunction(bus, device, 0);

    // Check for multi-function device
    const header_type = configRead8(bus, device, 0, PCI_HEADER_TYPE);
    if ((header_type & 0x80) != 0) {
        var func: u3 = 1;
        while (true) {
            if (configRead16(bus, device, func, PCI_VENDOR_ID) != 0xFFFF) {
                scanFunction(bus, device, func);
            }
            if (func == 7) break;
            func += 1;
        }
    }
}

fn scanFunction(bus: u8, device: u5, function: u3) void {
    if (device_count >= MAX_PCI_DEVICES) return;

    var dev = &devices[device_count];
    dev.bus = bus;
    dev.device = device;
    dev.function = function;
    dev.vendor_id = configRead16(bus, device, function, PCI_VENDOR_ID);
    dev.device_id = configRead16(bus, device, function, PCI_DEVICE_ID);
    dev.class_code = configRead8(bus, device, function, PCI_CLASS);
    dev.subclass = configRead8(bus, device, function, PCI_SUBCLASS);
    dev.prog_if = configRead8(bus, device, function, PCI_PROG_IF);
    dev.revision = configRead8(bus, device, function, PCI_REVISION_ID);
    dev.header_type = configRead8(bus, device, function, PCI_HEADER_TYPE);
    dev.irq_line = configRead8(bus, device, function, PCI_INTERRUPT_LINE);
    dev.irq_pin = configRead8(bus, device, function, PCI_INTERRUPT_PIN);
    dev.is_valid = true;

    // Parse BARs (only for header type 0x00)
    if ((dev.header_type & 0x7F) == 0x00) {
        parseBARs(dev);
    }

    // Scan for capabilities
    scanCapabilities(dev);

    device_count += 1;

    // If this is a PCI bridge, scan the secondary bus
    if (dev.isBridge()) {
        const secondary_bus = configRead8(bus, device, function, PCI_SECONDARY_BUS);
        scanBus(secondary_bus);
    }
}

fn parseBARs(dev: *PciDevice) void {
    var bar_idx: usize = 0;
    while (bar_idx < 6) {
        const offset: u8 = @intCast(PCI_BAR0 + bar_idx * 4);
        const bar_val = configRead32(dev.bus, dev.device, dev.function, offset);

        if (bar_val == 0) {
            bar_idx += 1;
            continue;
        }

        if ((bar_val & 0x01) != 0) {
            // I/O BAR
            dev.bars[bar_idx].bar_type = .io;
            dev.bars[bar_idx].base = bar_val & 0xFFFFFFFC;

            // Determine size by writing all 1s and reading back
            configWrite32(dev.bus, dev.device, dev.function, offset, 0xFFFFFFFF);
            const size_val = configRead32(dev.bus, dev.device, dev.function, offset);
            configWrite32(dev.bus, dev.device, dev.function, offset, bar_val);
            dev.bars[bar_idx].size = ~(size_val & 0xFFFFFFFC) + 1;
        } else {
            // Memory BAR
            const bar_type_bits = (bar_val >> 1) & 0x03;
            dev.bars[bar_idx].prefetchable = (bar_val & 0x08) != 0;

            if (bar_type_bits == 0x00) {
                // 32-bit memory BAR
                dev.bars[bar_idx].bar_type = .memory32;
                dev.bars[bar_idx].base = bar_val & 0xFFFFFFF0;

                configWrite32(dev.bus, dev.device, dev.function, offset, 0xFFFFFFFF);
                const size_val = configRead32(dev.bus, dev.device, dev.function, offset);
                configWrite32(dev.bus, dev.device, dev.function, offset, bar_val);
                dev.bars[bar_idx].size = ~(size_val & 0xFFFFFFF0) + 1;
            } else if (bar_type_bits == 0x02) {
                // 64-bit memory BAR
                dev.bars[bar_idx].bar_type = .memory64;

                const offset_hi: u8 = @intCast(PCI_BAR0 + (bar_idx + 1) * 4);
                const bar_hi = configRead32(dev.bus, dev.device, dev.function, offset_hi);

                dev.bars[bar_idx].base = (@as(u64, bar_hi) << 32) | (bar_val & 0xFFFFFFF0);

                // Size determination for 64-bit BAR
                configWrite32(dev.bus, dev.device, dev.function, offset, 0xFFFFFFFF);
                configWrite32(dev.bus, dev.device, dev.function, offset_hi, 0xFFFFFFFF);
                const size_lo = configRead32(dev.bus, dev.device, dev.function, offset);
                const size_hi = configRead32(dev.bus, dev.device, dev.function, offset_hi);
                configWrite32(dev.bus, dev.device, dev.function, offset, bar_val);
                configWrite32(dev.bus, dev.device, dev.function, offset_hi, bar_hi);

                const combined = (@as(u64, size_hi) << 32) | (size_lo & 0xFFFFFFF0);
                dev.bars[bar_idx].size = ~combined + 1;

                bar_idx += 1; // Skip the upper 32 bits BAR
            }
        }

        bar_idx += 1;
    }
}

fn scanCapabilities(dev: *PciDevice) void {
    // Check if capabilities list is present (Status register bit 4)
    const status = configRead16(dev.bus, dev.device, dev.function, PCI_STATUS);
    if ((status & 0x10) == 0) return;

    var cap_ptr = configRead8(dev.bus, dev.device, dev.function, PCI_CAPABILITIES);
    cap_ptr &= 0xFC; // Must be DWORD-aligned

    var count: u32 = 0;
    while (cap_ptr != 0 and count < 48) : (count += 1) {
        const cap_id = configRead8(dev.bus, dev.device, dev.function, cap_ptr);
        switch (cap_id) {
            CAP_MSI => {
                dev.has_msi = true;
                dev.msi_cap_offset = cap_ptr;
            },
            else => {},
        }
        cap_ptr = configRead8(dev.bus, dev.device, dev.function, cap_ptr + 1);
        cap_ptr &= 0xFC;
    }
}

// =============================================================================
// Device queries
// =============================================================================

/// Find a device by class and subclass
pub fn findDevice(class: u8, subclass: u8) ?*const PciDevice {
    for (devices[0..device_count]) |*dev| {
        if (dev.is_valid and dev.class_code == class and dev.subclass == subclass) {
            return dev;
        }
    }
    return null;
}

/// Find a device by vendor and device ID
pub fn findDeviceByID(vendor_id: u16, device_id: u16) ?*const PciDevice {
    for (devices[0..device_count]) |*dev| {
        if (dev.is_valid and dev.vendor_id == vendor_id and dev.device_id == device_id) {
            return dev;
        }
    }
    return null;
}

/// Get the number of discovered devices
pub fn getDeviceCount() usize {
    return device_count;
}

/// Get a device by index
pub fn getDevice(index: usize) ?*const PciDevice {
    if (index >= device_count) return null;
    return &devices[index];
}

/// Enable bus mastering for a device (required for DMA)
pub fn enableBusMaster(dev: *const PciDevice) void {
    var cmd = configRead16(dev.bus, dev.device, dev.function, PCI_COMMAND);
    cmd |= CMD_BUS_MASTER | CMD_MEMORY_SPACE | CMD_IO_SPACE;
    configWrite16(dev.bus, dev.device, dev.function, PCI_COMMAND, cmd);
}
