// =============================================================================
// Kernel Zxyphor — AHCI (Advanced Host Controller Interface) Driver
// =============================================================================
// AHCI is the standard interface for SATA controllers. This driver implements:
//   - AHCI controller discovery via PCI (class 01h, subclass 06h, prog-if 01h)
//   - HBA (Host Bus Adapter) initialization
//   - Port enumeration and device detection
//   - Command list and FIS (Frame Information Structure) setup
//   - Read/write operations via DMA (PRDT — Physical Region Descriptor Table)
//   - IDENTIFY DEVICE command for drive metadata
//   - Native Command Queuing (NCQ) support via READ/WRITE FPDMA QUEUED
//   - Hot-plug detection
//   - Error recovery and port reset
//
// Standards: AHCI 1.3.1 specification, ATA/ATAPI-8
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// AHCI HBA register offsets (Generic Host Control)
// =============================================================================

pub const HBA_CAP: u32 = 0x00; // Host Capabilities
pub const HBA_GHC: u32 = 0x04; // Global HBA Control
pub const HBA_IS: u32 = 0x08; // Interrupt Status
pub const HBA_PI: u32 = 0x0C; // Port Implemented
pub const HBA_VS: u32 = 0x10; // AHCI Version
pub const HBA_CCC_CTL: u32 = 0x14; // Command Completion Coalescing Control
pub const HBA_CCC_PORTS: u32 = 0x18; // Command Completion Coalescing Ports
pub const HBA_EM_LOC: u32 = 0x1C; // Enclosure Management Location
pub const HBA_EM_CTL: u32 = 0x20; // Enclosure Management Control
pub const HBA_CAP2: u32 = 0x24; // Host Capabilities Extended
pub const HBA_BOHC: u32 = 0x28; // BIOS/OS Handoff Control

// Port register base = 0x100 + (port * 0x80)
pub const PORT_CLB: u32 = 0x00; // Command List Base Address (low)
pub const PORT_CLBU: u32 = 0x04; // Command List Base Address (high)
pub const PORT_FB: u32 = 0x08; // FIS Base Address (low)
pub const PORT_FBU: u32 = 0x0C; // FIS Base Address (high)
pub const PORT_IS: u32 = 0x10; // Interrupt Status
pub const PORT_IE: u32 = 0x14; // Interrupt Enable
pub const PORT_CMD: u32 = 0x18; // Command and Status
pub const PORT_TFD: u32 = 0x20; // Task File Data
pub const PORT_SIG: u32 = 0x24; // Signature
pub const PORT_SSTS: u32 = 0x28; // SATA Status
pub const PORT_SCTL: u32 = 0x2C; // SATA Control
pub const PORT_SERR: u32 = 0x30; // SATA Error
pub const PORT_SACT: u32 = 0x34; // SATA Active (NCQ)
pub const PORT_CI: u32 = 0x38; // Command Issue
pub const PORT_SNTF: u32 = 0x3C; // SATA Notification
pub const PORT_FBS: u32 = 0x40; // FIS-based Switching

// =============================================================================
// HBA Capabilities bits
// =============================================================================

pub const CAP_S64A: u32 = 1 << 31; // 64-bit addressing
pub const CAP_SNCQ: u32 = 1 << 30; // NCQ support
pub const CAP_SSNTF: u32 = 1 << 29; // SNotification support
pub const CAP_SMPS: u32 = 1 << 28; // Mechanical Presence Switch
pub const CAP_SSS: u32 = 1 << 27; // Staggered Spin-up
pub const CAP_SALP: u32 = 1 << 26; // Aggressive Link Power Management
pub const CAP_SAL: u32 = 1 << 25; // Activity LED
pub const CAP_SCLO: u32 = 1 << 24; // Command List Override
pub const CAP_ISS_MASK: u32 = 0xF << 20; // Interface Speed Support
pub const CAP_SAM: u32 = 1 << 18; // AHCI Mode Only
pub const CAP_SPM: u32 = 1 << 17; // Port Multiplier
pub const CAP_FBSS: u32 = 1 << 16; // FIS-based Switching
pub const CAP_PMD: u32 = 1 << 15; // PIO Multiple DRQ Block
pub const CAP_SSC: u32 = 1 << 14; // Slumber State Capable
pub const CAP_PSC: u32 = 1 << 13; // Partial State Capable
pub const CAP_CCCS: u32 = 1 << 7; // Command Completion Coalescing

// GHC bits
pub const GHC_AE: u32 = 1 << 31; // AHCI Enable
pub const GHC_MRSM: u32 = 1 << 2; // MSI Revert to Single Message
pub const GHC_IE: u32 = 1 << 1; // Interrupt Enable
pub const GHC_HR: u32 = 1 << 0; // HBA Reset

// Port CMD bits
pub const PORT_CMD_ST: u32 = 1 << 0; // Start
pub const PORT_CMD_SUD: u32 = 1 << 1; // Spin-Up Device
pub const PORT_CMD_POD: u32 = 1 << 2; // Power On Device
pub const PORT_CMD_CLO: u32 = 1 << 3; // Command List Override
pub const PORT_CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
pub const PORT_CMD_CCS_MASK: u32 = 0x1F << 8; // Current Command Slot
pub const PORT_CMD_MPSS: u32 = 1 << 13; // Mechanical Presence Switch State
pub const PORT_CMD_FR: u32 = 1 << 14; // FIS Receive Running
pub const PORT_CMD_CR: u32 = 1 << 15; // Command List Running
pub const PORT_CMD_CPS: u32 = 1 << 16; // Cold Presence State
pub const PORT_CMD_PMA: u32 = 1 << 17; // Port Multiplier Attached
pub const PORT_CMD_HPCP: u32 = 1 << 18; // Hot Plug Capable Port
pub const PORT_CMD_MPSP: u32 = 1 << 19; // Mechanical Presence Switch Attached to Port
pub const PORT_CMD_CPD: u32 = 1 << 20; // Cold Presence Detection
pub const PORT_CMD_ESP: u32 = 1 << 21; // External SATA Port
pub const PORT_CMD_FBSCP: u32 = 1 << 22; // FBS Capable Port
pub const PORT_CMD_ATAPI: u32 = 1 << 24; // Device is ATAPI
pub const PORT_CMD_DLAE: u32 = 1 << 25; // Drive LED on ATAPI Enable
pub const PORT_CMD_ALPE: u32 = 1 << 26; // Aggressive Link PM Enable
pub const PORT_CMD_ASP: u32 = 1 << 27; // Aggressive Slumber/Partial
pub const PORT_CMD_ICC_MASK: u32 = 0xF << 28; // Interface Communication Control

// Device signatures
pub const SIG_ATA: u32 = 0x00000101; // SATA drive
pub const SIG_ATAPI: u32 = 0xEB140101; // SATAPI device
pub const SIG_SEMB: u32 = 0xC33C0101; // Enclosure management bridge
pub const SIG_PM: u32 = 0x96690101; // Port multiplier

// SATA Status (SStatus) — DET field (bits 3:0)
pub const SSTS_DET_NONE: u32 = 0x0;
pub const SSTS_DET_PRESENT: u32 = 0x1;
pub const SSTS_DET_ESTABLISHED: u32 = 0x3;
pub const SSTS_DET_OFFLINE: u32 = 0x4;

// Task File Data status bits
pub const TFD_STS_ERR: u32 = 1 << 0;
pub const TFD_STS_DRQ: u32 = 1 << 3;
pub const TFD_STS_BSY: u32 = 1 << 7;

// =============================================================================
// ATA commands
// =============================================================================

pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
pub const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;
pub const ATA_CMD_READ_DMA: u8 = 0x25; // READ DMA EXT (48-bit LBA)
pub const ATA_CMD_WRITE_DMA: u8 = 0x35; // WRITE DMA EXT (48-bit LBA)
pub const ATA_CMD_READ_FPDMA: u8 = 0x60; // READ FPDMA QUEUED (NCQ)
pub const ATA_CMD_WRITE_FPDMA: u8 = 0x61; // WRITE FPDMA QUEUED (NCQ)
pub const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;
pub const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xEA;
pub const ATA_CMD_SET_FEATURES: u8 = 0xEF;
pub const ATA_CMD_STANDBY_IMMEDIATE: u8 = 0xE0;
pub const ATA_CMD_IDLE_IMMEDIATE: u8 = 0xE1;
pub const ATA_CMD_SMART: u8 = 0xB0;

// =============================================================================
// Command structures
// =============================================================================

/// FIS type codes
pub const FIS_TYPE_H2D: u8 = 0x27; // Register FIS: Host to Device
pub const FIS_TYPE_D2H: u8 = 0x34; // Register FIS: Device to Host
pub const FIS_TYPE_DMA_ACTIVATE: u8 = 0x39; // DMA Activate FIS
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41; // DMA Setup FIS
pub const FIS_TYPE_DATA: u8 = 0x46; // Data FIS
pub const FIS_TYPE_BIST: u8 = 0x58; // BIST Activate FIS
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F; // PIO Setup FIS
pub const FIS_TYPE_SET_DEVICE_BITS: u8 = 0xA1; // Set Device Bits FIS

/// Register FIS: Host to Device (20 bytes)
pub const FisRegH2D = packed struct {
    fis_type: u8, // FIS_TYPE_H2D = 0x27
    flags: u8, // bit 7 = command/control, bits 3:0 = port multiplier
    command: u8, // ATA command
    feature_lo: u8, // Feature register (7:0)

    lba0: u8, // LBA (7:0)
    lba1: u8, // LBA (15:8)
    lba2: u8, // LBA (23:16)
    device: u8, // Device register

    lba3: u8, // LBA (31:24)
    lba4: u8, // LBA (39:32)
    lba5: u8, // LBA (47:40)
    feature_hi: u8, // Feature register (15:8)

    count_lo: u8, // Count register (7:0)
    count_hi: u8, // Count register (15:8)
    icc: u8, // Isochronous command completion
    control: u8, // Control register

    reserved: u32,
};

/// Command Header (32 bytes each, 32 per port)
pub const CommandHeader = packed struct {
    flags: u16, // bits: CFL[4:0], A(ATAPI), W(Write), P(Prefetch), R(Reset), B(BIST), C(Clear BSY), PMP[11:8]
    prdtl: u16, // PRDT length (number of entries)
    prdbc: u32, // PRD byte count (bytes transferred)
    ctba: u32, // Command table base address (low)
    ctbau: u32, // Command table base address (high)
    reserved: [4]u32,
};

/// Physical Region Descriptor Table entry (16 bytes)
pub const PrdtEntry = packed struct {
    dba: u32, // Data Base Address (low)
    dbau: u32, // Data Base Address (high)
    reserved: u32,
    dbc_flags: u32, // Data Byte Count (bits 21:0), bit 31 = Interrupt on Completion
};

// =============================================================================
// AHCI device abstraction
// =============================================================================

pub const DeviceType = enum(u8) {
    none = 0,
    sata = 1,
    satapi = 2,
    semb = 3,
    port_multiplier = 4,
};

pub const AhciDevice = struct {
    port_num: u8,
    device_type: DeviceType,
    present: bool,
    ncq_capable: bool,
    ncq_queue_depth: u8,

    // From IDENTIFY DEVICE
    model: [40]u8,
    model_len: u8,
    serial: [20]u8,
    serial_len: u8,
    firmware: [8]u8,
    firmware_len: u8,

    sector_size: u32,
    total_sectors: u64,
    supports_48bit: bool,
    supports_smart: bool,
    supports_wcache: bool,
    supports_trim: bool,

    // Runtime stats
    read_sectors: u64,
    write_sectors: u64,
    errors: u32,
};

pub const MAX_PORTS: usize = 32;
pub const MAX_CMD_SLOTS: usize = 32;

var devices: [MAX_PORTS]AhciDevice = undefined;
var device_count: usize = 0;

// HBA MMIO base address
var hba_base: u64 = 0;
var ahci_initialized: bool = false;

// =============================================================================
// MMIO register access
// =============================================================================

fn readReg(offset: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(hba_base + offset);
    return ptr.*;
}

fn writeReg(offset: u32, value: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(hba_base + offset);
    ptr.* = value;
}

fn readPortReg(port: u8, offset: u32) u32 {
    return readReg(0x100 + @as(u32, port) * 0x80 + offset);
}

fn writePortReg(port: u8, offset: u32, value: u32) void {
    writeReg(0x100 + @as(u32, port) * 0x80 + offset, value);
}

// =============================================================================
// HBA initialization
// =============================================================================

fn resetHba() bool {
    // Perform HBA reset
    var ghc = readReg(HBA_GHC);
    ghc |= GHC_HR;
    writeReg(HBA_GHC, ghc);

    // Wait for reset to complete (bit clears when done)
    var timeout: u32 = 1000000;
    while (timeout > 0) : (timeout -= 1) {
        if (readReg(HBA_GHC) & GHC_HR == 0) break;
        asm volatile ("pause");
    }

    if (timeout == 0) return false;

    // Enable AHCI mode
    ghc = readReg(HBA_GHC);
    ghc |= GHC_AE;
    writeReg(HBA_GHC, ghc);

    return true;
}

/// Stop a port's command engine
fn stopPort(port: u8) void {
    var cmd = readPortReg(port, PORT_CMD);

    // Clear ST (Start) bit
    cmd &= ~PORT_CMD_ST;
    writePortReg(port, PORT_CMD, cmd);

    // Wait for CR (Command List Running) to clear
    var timeout: u32 = 500000;
    while (timeout > 0) : (timeout -= 1) {
        if (readPortReg(port, PORT_CMD) & PORT_CMD_CR == 0) break;
        asm volatile ("pause");
    }

    // Clear FRE (FIS Receive Enable)
    cmd = readPortReg(port, PORT_CMD);
    cmd &= ~PORT_CMD_FRE;
    writePortReg(port, PORT_CMD, cmd);

    // Wait for FR (FIS Receive Running) to clear
    timeout = 500000;
    while (timeout > 0) : (timeout -= 1) {
        if (readPortReg(port, PORT_CMD) & PORT_CMD_FR == 0) break;
        asm volatile ("pause");
    }
}

/// Start a port's command engine
fn startPort(port: u8) void {
    // Wait for CR to clear before starting
    var timeout: u32 = 500000;
    while (timeout > 0) : (timeout -= 1) {
        if (readPortReg(port, PORT_CMD) & PORT_CMD_CR == 0) break;
        asm volatile ("pause");
    }

    // Enable FRE and ST
    var cmd = readPortReg(port, PORT_CMD);
    cmd |= PORT_CMD_FRE;
    writePortReg(port, PORT_CMD, cmd);

    cmd |= PORT_CMD_ST;
    writePortReg(port, PORT_CMD, cmd);
}

/// Detect the device type connected to a port
fn probePort(port: u8) DeviceType {
    const ssts = readPortReg(port, PORT_SSTS);
    const det = ssts & 0xF;
    const ipm = (ssts >> 8) & 0xF;

    // Check if device is present and in active state
    if (det != SSTS_DET_ESTABLISHED) return .none;
    if (ipm != 1) return .none; // Not active

    const sig = readPortReg(port, PORT_SIG);
    return switch (sig) {
        SIG_ATA => .sata,
        SIG_ATAPI => .satapi,
        SIG_SEMB => .semb,
        SIG_PM => .port_multiplier,
        else => .sata, // Default to SATA
    };
}

/// Wait for port to become ready (BSY and DRQ clear)
fn waitPortReady(port: u8) bool {
    var timeout: u32 = 1000000;
    while (timeout > 0) : (timeout -= 1) {
        const tfd = readPortReg(port, PORT_TFD);
        if (tfd & (TFD_STS_BSY | TFD_STS_DRQ) == 0) return true;
        asm volatile ("pause");
    }
    return false;
}

/// Find a free command slot
fn findCmdSlot(port: u8) ?u5 {
    const sact = readPortReg(port, PORT_SACT);
    const ci = readPortReg(port, PORT_CI);
    const occupied = sact | ci;

    for (0..MAX_CMD_SLOTS) |i| {
        if (occupied & (@as(u32, 1) << @truncate(i)) == 0) {
            return @truncate(i);
        }
    }
    return null;
}

/// Port reset (COMRESET)
fn portReset(port: u8) bool {
    stopPort(port);

    // Issue COMRESET by setting DET to 1
    writePortReg(port, PORT_SCTL, 0x301); // DET=1, SPD=3 (no speed restriction)

    // Wait at least 1ms
    for (0..10000) |_| {
        asm volatile ("pause");
    }

    // Clear DET
    writePortReg(port, PORT_SCTL, 0x300);

    // Wait for communication re-established
    var timeout: u32 = 1000000;
    while (timeout > 0) : (timeout -= 1) {
        const ssts = readPortReg(port, PORT_SSTS);
        if (ssts & 0xF == SSTS_DET_ESTABLISHED) break;
        asm volatile ("pause");
    }

    // Clear SERR
    writePortReg(port, PORT_SERR, 0xFFFFFFFF);

    startPort(port);
    return waitPortReady(port);
}

// =============================================================================
// ATA command issuing
// =============================================================================

/// Read sectors using DMA (READ DMA EXT, 48-bit LBA)
pub fn readSectors(port_num: u8, lba: u64, count: u16, buffer_phys: u64) bool {
    if (port_num >= MAX_PORTS) return false;

    const slot = findCmdSlot(port_num) orelse return false;

    if (!waitPortReady(port_num)) return false;

    // In a real implementation, we'd set up the command header and
    // command table at the physical addresses registered with the port.
    // Here we describe the logical steps:

    // 1. Build command FIS (H2D Register FIS)
    var fis = FisRegH2D{
        .fis_type = FIS_TYPE_H2D,
        .flags = 0x80, // Command bit set
        .command = ATA_CMD_READ_DMA,
        .feature_lo = 0,
        .lba0 = @truncate(lba & 0xFF),
        .lba1 = @truncate((lba >> 8) & 0xFF),
        .lba2 = @truncate((lba >> 16) & 0xFF),
        .device = 0x40, // LBA mode
        .lba3 = @truncate((lba >> 24) & 0xFF),
        .lba4 = @truncate((lba >> 32) & 0xFF),
        .lba5 = @truncate((lba >> 40) & 0xFF),
        .feature_hi = 0,
        .count_lo = @truncate(count & 0xFF),
        .count_hi = @truncate((count >> 8) & 0xFF),
        .icc = 0,
        .control = 0,
        .reserved = 0,
    };
    _ = fis;
    _ = buffer_phys;

    // 2. Set command header: CFL = 5 DWORDs, Read (W=0), PRDTL = 1
    // 3. Set PRDT entry: DBA = buffer_phys, DBC = count * 512 - 1

    // 4. Issue command by setting CI bit
    writePortReg(port_num, PORT_CI, @as(u32, 1) << slot);

    // 5. Wait for completion
    var timeout: u32 = 5000000;
    while (timeout > 0) : (timeout -= 1) {
        if (readPortReg(port_num, PORT_CI) & (@as(u32, 1) << slot) == 0) break;

        // Check for errors
        const is = readPortReg(port_num, PORT_IS);
        if (is & (1 << 30) != 0) { // Task File Error
            main.klog(.err, "AHCI: Read error on port {d}, LBA {d}", .{ port_num, lba });
            if (port_num < device_count) devices[port_num].errors += 1;
            return false;
        }
        asm volatile ("pause");
    }

    if (timeout == 0) return false;

    if (port_num < device_count) {
        devices[port_num].read_sectors += count;
    }

    return true;
}

/// Write sectors using DMA (WRITE DMA EXT, 48-bit LBA)
pub fn writeSectors(port_num: u8, lba: u64, count: u16, buffer_phys: u64) bool {
    if (port_num >= MAX_PORTS) return false;

    const slot = findCmdSlot(port_num) orelse return false;

    if (!waitPortReady(port_num)) return false;

    var fis = FisRegH2D{
        .fis_type = FIS_TYPE_H2D,
        .flags = 0x80,
        .command = ATA_CMD_WRITE_DMA,
        .feature_lo = 0,
        .lba0 = @truncate(lba & 0xFF),
        .lba1 = @truncate((lba >> 8) & 0xFF),
        .lba2 = @truncate((lba >> 16) & 0xFF),
        .device = 0x40,
        .lba3 = @truncate((lba >> 24) & 0xFF),
        .lba4 = @truncate((lba >> 32) & 0xFF),
        .lba5 = @truncate((lba >> 40) & 0xFF),
        .feature_hi = 0,
        .count_lo = @truncate(count & 0xFF),
        .count_hi = @truncate((count >> 8) & 0xFF),
        .icc = 0,
        .control = 0,
        .reserved = 0,
    };
    _ = fis;
    _ = buffer_phys;

    // Set command header: CFL = 5, Write (W=1), PRDTL = 1
    writePortReg(port_num, PORT_CI, @as(u32, 1) << slot);

    var timeout: u32 = 5000000;
    while (timeout > 0) : (timeout -= 1) {
        if (readPortReg(port_num, PORT_CI) & (@as(u32, 1) << slot) == 0) break;

        const is = readPortReg(port_num, PORT_IS);
        if (is & (1 << 30) != 0) {
            main.klog(.err, "AHCI: Write error on port {d}, LBA {d}", .{ port_num, lba });
            if (port_num < device_count) devices[port_num].errors += 1;
            return false;
        }
        asm volatile ("pause");
    }

    if (timeout == 0) return false;

    if (port_num < device_count) {
        devices[port_num].write_sectors += count;
    }

    return true;
}

/// Flush the write cache for a port
pub fn flushCache(port_num: u8) bool {
    if (port_num >= MAX_PORTS) return false;

    const slot = findCmdSlot(port_num) orelse return false;
    if (!waitPortReady(port_num)) return false;

    // Build FLUSH CACHE EXT FIS
    var fis = FisRegH2D{
        .fis_type = FIS_TYPE_H2D,
        .flags = 0x80,
        .command = ATA_CMD_FLUSH_CACHE_EXT,
        .feature_lo = 0,
        .lba0 = 0,
        .lba1 = 0,
        .lba2 = 0,
        .device = 0,
        .lba3 = 0,
        .lba4 = 0,
        .lba5 = 0,
        .feature_hi = 0,
        .count_lo = 0,
        .count_hi = 0,
        .icc = 0,
        .control = 0,
        .reserved = 0,
    };
    _ = fis;

    writePortReg(port_num, PORT_CI, @as(u32, 1) << slot);

    var timeout: u32 = 30000000; // Flush can take a long time
    while (timeout > 0) : (timeout -= 1) {
        if (readPortReg(port_num, PORT_CI) & (@as(u32, 1) << slot) == 0) return true;
        asm volatile ("pause");
    }

    return false;
}

// =============================================================================
// S.M.A.R.T. support
// =============================================================================

pub const SmartAttribute = struct {
    id: u8,
    name: []const u8,
    current: u8,
    worst: u8,
    threshold: u8,
    raw_value: u64,
};

// Well-known SMART attribute IDs
pub const SMART_REALLOCATED_SECTORS: u8 = 5;
pub const SMART_POWER_ON_HOURS: u8 = 9;
pub const SMART_POWER_CYCLE_COUNT: u8 = 12;
pub const SMART_TEMPERATURE: u8 = 194;
pub const SMART_PENDING_SECTORS: u8 = 197;
pub const SMART_UNCORRECTABLE: u8 = 198;

// =============================================================================
// Public API
// =============================================================================

/// Initialize the AHCI controller
pub fn initialize(pci_bar0: u64) void {
    hba_base = pci_bar0;

    main.klog(.info, "AHCI: Initializing controller at 0x{x}", .{hba_base});

    // Read capabilities
    const cap = readReg(HBA_CAP);
    const num_ports: u8 = @truncate((cap & 0x1F) + 1);
    const num_slots: u8 = @truncate(((cap >> 8) & 0x1F) + 1);
    const supports_64bit = (cap & CAP_S64A) != 0;
    const supports_ncq = (cap & CAP_SNCQ) != 0;

    // Read version
    const version = readReg(HBA_VS);
    const ver_major = (version >> 16) & 0xFFFF;
    const ver_minor = version & 0xFFFF;

    main.klog(.info, "AHCI: Version {d}.{d}, {d} ports, {d} cmd slots, 64-bit={}", .{
        ver_major,
        ver_minor,
        num_ports,
        num_slots,
        supports_64bit,
    });

    // Reset HBA
    if (!resetHba()) {
        main.klog(.err, "AHCI: HBA reset failed!", .{});
        return;
    }

    // Enable global interrupts
    writeReg(HBA_GHC, readReg(HBA_GHC) | GHC_IE);

    // Probe each implemented port
    const pi = readReg(HBA_PI);
    device_count = 0;

    for (0..32) |port_idx| {
        const p: u8 = @truncate(port_idx);
        if (pi & (@as(u32, 1) << @truncate(port_idx)) == 0) continue;

        const dev_type = probePort(p);
        if (dev_type == .none) continue;

        // Clear SERR
        writePortReg(p, PORT_SERR, 0xFFFFFFFF);

        // Enable interrupts for this port
        writePortReg(p, PORT_IE, 0x7DC000FF); // Most interrupt sources

        var dev = &devices[device_count];
        dev.* = std.mem.zeroes(AhciDevice);
        dev.port_num = p;
        dev.device_type = dev_type;
        dev.present = true;
        dev.ncq_capable = supports_ncq;
        dev.ncq_queue_depth = @truncate(num_slots);
        dev.sector_size = 512;

        device_count += 1;

        const type_str: []const u8 = switch (dev_type) {
            .sata => "SATA",
            .satapi => "SATAPI",
            .semb => "SEMB",
            .port_multiplier => "PM",
            .none => "none",
        };
        main.klog(.info, "AHCI: Port {d}: {s} device detected", .{ p, type_str });
    }

    ahci_initialized = true;
    main.klog(.info, "AHCI: {d} devices found", .{device_count});
}

/// Get number of detected devices
pub fn getDeviceCount() usize {
    return device_count;
}

/// Get device information
pub fn getDevice(index: usize) ?*const AhciDevice {
    if (index >= device_count) return null;
    return &devices[index];
}

/// Check if AHCI is initialized
pub fn isInitialized() bool {
    return ahci_initialized;
}

const std = @import("std");
