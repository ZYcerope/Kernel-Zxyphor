// =============================================================================
// Kernel Zxyphor - ATA/IDE Disk Driver
// =============================================================================
// Provides block-level access to ATA/IDE hard drives.
// Uses PIO (Programmed I/O) mode for simplicity and compatibility.
//
// ATA controller has two channels:
//   - Primary:   I/O ports 0x1F0-0x1F7, control 0x3F6, IRQ 14
//   - Secondary: I/O ports 0x170-0x177, control 0x376, IRQ 15
//
// Each channel supports two drives: master (drive 0) and slave (drive 1).
//
// This driver supports:
//   - IDENTIFY command for drive detection and parameter reading
//   - LBA28 and LBA48 addressing
//   - PIO read/write (single and multi-sector)
//   - ATAPI identification (CD/DVD drives)
//   - Cache flush
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// ATA I/O Port Constants
// =============================================================================
const ATA_PRIMARY_IO: u16 = 0x1F0;
const ATA_PRIMARY_CTRL: u16 = 0x3F6;
const ATA_SECONDARY_IO: u16 = 0x170;
const ATA_SECONDARY_CTRL: u16 = 0x376;

// Register offsets from base I/O port
const ATA_REG_DATA: u16 = 0;
const ATA_REG_ERROR: u16 = 1; // Read: error, Write: features
const ATA_REG_FEATURES: u16 = 1;
const ATA_REG_SECCOUNT: u16 = 2;
const ATA_REG_LBA_LO: u16 = 3;
const ATA_REG_LBA_MID: u16 = 4;
const ATA_REG_LBA_HI: u16 = 5;
const ATA_REG_DRIVE: u16 = 6; // Drive/Head register
const ATA_REG_STATUS: u16 = 7; // Read: status, Write: command
const ATA_REG_COMMAND: u16 = 7;

// Status register bits
const ATA_SR_BSY: u8 = 0x80; // Busy
const ATA_SR_DRDY: u8 = 0x40; // Drive ready
const ATA_SR_DF: u8 = 0x20; // Drive fault
const ATA_SR_DSC: u8 = 0x10; // Drive seek complete
const ATA_SR_DRQ: u8 = 0x08; // Data request
const ATA_SR_CORR: u8 = 0x04; // Corrected data
const ATA_SR_IDX: u8 = 0x02; // Index
const ATA_SR_ERR: u8 = 0x01; // Error

// Error register bits
const ATA_ER_BBK: u8 = 0x80; // Bad block
const ATA_ER_UNC: u8 = 0x40; // Uncorrectable data error
const ATA_ER_MC: u8 = 0x20; // Media changed
const ATA_ER_IDNF: u8 = 0x10; // ID not found
const ATA_ER_MCR: u8 = 0x08; // Media change request
const ATA_ER_ABRT: u8 = 0x04; // Command aborted
const ATA_ER_TK0NF: u8 = 0x02; // Track 0 not found
const ATA_ER_AMNF: u8 = 0x01; // Address mark not found

// ATA Commands
const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;
const ATA_CMD_READ_PIO: u8 = 0x20;
const ATA_CMD_READ_PIO_EXT: u8 = 0x24;
const ATA_CMD_WRITE_PIO: u8 = 0x30;
const ATA_CMD_WRITE_PIO_EXT: u8 = 0x34;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
const ATA_CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
const ATA_CMD_SET_FEATURES: u8 = 0xEF;

const SECTOR_SIZE: usize = 512;

// =============================================================================
// Drive descriptor
// =============================================================================
pub const AtaDrive = struct {
    is_present: bool = false,
    is_atapi: bool = false,
    channel: u8 = 0, // 0 = primary, 1 = secondary
    drive: u8 = 0, // 0 = master, 1 = slave
    io_base: u16 = 0,
    ctrl_base: u16 = 0,

    // Drive parameters (from IDENTIFY)
    total_sectors_28: u32 = 0,
    total_sectors_48: u64 = 0,
    supports_lba48: bool = false,
    model: [41]u8 = [_]u8{0} ** 41,
    model_len: u8 = 0,
    serial: [21]u8 = [_]u8{0} ** 21,
    firmware: [9]u8 = [_]u8{0} ** 9,
    size_mb: u64 = 0,

    pub fn totalSectors(self: *const AtaDrive) u64 {
        if (self.supports_lba48 and self.total_sectors_48 > 0) {
            return self.total_sectors_48;
        }
        return self.total_sectors_28;
    }
};

// =============================================================================
// State: up to 4 drives (2 channels × 2 drives each)
// =============================================================================
var drives: [4]AtaDrive = undefined;
var drive_count: usize = 0;

// =============================================================================
// Initialize ATA controller — detect and identify all drives
// =============================================================================
pub fn initialize() void {
    for (&drives) |*d| {
        d.* = AtaDrive{};
    }
    drive_count = 0;

    // Scan primary channel
    identifyDrive(0, 0, ATA_PRIMARY_IO, ATA_PRIMARY_CTRL); // Primary master
    identifyDrive(0, 1, ATA_PRIMARY_IO, ATA_PRIMARY_CTRL); // Primary slave

    // Scan secondary channel
    identifyDrive(1, 0, ATA_SECONDARY_IO, ATA_SECONDARY_CTRL); // Secondary master
    identifyDrive(1, 1, ATA_SECONDARY_IO, ATA_SECONDARY_CTRL); // Secondary slave

    main.klog(.info, "ATA: found {d} drive(s)", .{drive_count});

    // Print details of each drive
    for (drives[0..4]) |*d| {
        if (d.is_present) {
            main.klog(.info, "ATA: {s} {s} - {d} MB - LBA48: {s}", .{
                if (d.channel == 0) "Primary" else "Secondary",
                if (d.drive == 0) "Master" else "Slave",
                d.size_mb,
                if (d.supports_lba48) "yes" else "no",
            });
        }
    }
}

fn identifyDrive(channel: u8, drive: u8, io_base: u16, ctrl_base: u16) void {
    const idx = @as(usize, channel) * 2 + drive;
    var drv = &drives[idx];
    drv.channel = channel;
    drv.drive = drive;
    drv.io_base = io_base;
    drv.ctrl_base = ctrl_base;

    // Select drive
    main.cpu.outb(io_base + ATA_REG_DRIVE, 0xA0 | (@as(u8, drive) << 4));
    ioDelay();

    // Send IDENTIFY command
    main.cpu.outb(io_base + ATA_REG_SECCOUNT, 0);
    main.cpu.outb(io_base + ATA_REG_LBA_LO, 0);
    main.cpu.outb(io_base + ATA_REG_LBA_MID, 0);
    main.cpu.outb(io_base + ATA_REG_LBA_HI, 0);
    main.cpu.outb(io_base + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
    ioDelay();

    // Check if drive exists
    var status = main.cpu.inb(io_base + ATA_REG_STATUS);
    if (status == 0) return; // No drive

    // Wait for BSY to clear
    var timeout: u32 = 100000;
    while ((status & ATA_SR_BSY) != 0 and timeout > 0) : (timeout -= 1) {
        status = main.cpu.inb(io_base + ATA_REG_STATUS);
    }
    if (timeout == 0) return;

    // Check if this is ATAPI instead
    const lba_mid = main.cpu.inb(io_base + ATA_REG_LBA_MID);
    const lba_hi = main.cpu.inb(io_base + ATA_REG_LBA_HI);
    if (lba_mid != 0 or lba_hi != 0) {
        // Could be ATAPI (lba_mid=0x14, lba_hi=0xEB) or SATA
        if (lba_mid == 0x14 and lba_hi == 0xEB) {
            drv.is_atapi = true;
            // Send IDENTIFY PACKET for ATAPI devices
            main.cpu.outb(io_base + ATA_REG_COMMAND, ATA_CMD_IDENTIFY_PACKET);
            ioDelay();
            timeout = 100000;
            status = main.cpu.inb(io_base + ATA_REG_STATUS);
            while ((status & ATA_SR_BSY) != 0 and timeout > 0) : (timeout -= 1) {
                status = main.cpu.inb(io_base + ATA_REG_STATUS);
            }
        } else {
            return; // Unknown device type
        }
    }

    // Wait for DRQ (data request)
    timeout = 100000;
    while ((status & (ATA_SR_DRQ | ATA_SR_ERR)) == 0 and timeout > 0) : (timeout -= 1) {
        status = main.cpu.inb(io_base + ATA_REG_STATUS);
    }

    if ((status & ATA_SR_ERR) != 0 or timeout == 0) return;

    // Read 256 words (512 bytes) of identification data
    var identify: [256]u16 = [_]u16{0} ** 256;
    for (&identify) |*word| {
        word.* = main.cpu.inw(io_base + ATA_REG_DATA);
    }

    // Parse identification data
    drv.is_present = true;

    // Total LBA28 sectors (words 60-61)
    drv.total_sectors_28 = @as(u32, identify[61]) << 16 | identify[60];

    // Check LBA48 support (word 83, bit 10)
    if ((identify[83] & (1 << 10)) != 0) {
        drv.supports_lba48 = true;
        drv.total_sectors_48 = @as(u64, identify[103]) << 48 |
            @as(u64, identify[102]) << 32 |
            @as(u64, identify[101]) << 16 |
            @as(u64, identify[100]);
    }

    drv.size_mb = drv.totalSectors() * SECTOR_SIZE / (1024 * 1024);

    // Extract model string (words 27-46, byte-swapped)
    extractString(&identify, 27, 46, &drv.model);
    drv.model_len = trimTrailingSpaces(&drv.model);

    // Extract serial number (words 10-19)
    extractString(&identify, 10, 19, &drv.serial);

    // Extract firmware revision (words 23-26)
    extractString(&identify, 23, 26, &drv.firmware);

    drive_count += 1;
}

fn extractString(identify: *const [256]u16, start_word: usize, end_word: usize, dest: []u8) void {
    var di: usize = 0;
    var wi: usize = start_word;
    while (wi <= end_word) : (wi += 1) {
        if (di + 1 >= dest.len) break;
        // ATA strings are byte-swapped
        dest[di] = @truncate(identify[wi] >> 8);
        dest[di + 1] = @truncate(identify[wi]);
        di += 2;
    }
    if (di < dest.len) dest[di] = 0;
}

fn trimTrailingSpaces(s: []u8) u8 {
    var len: u8 = 0;
    for (s, 0..) |c, i| {
        if (c != ' ' and c != 0) len = @intCast(i + 1);
    }
    return len;
}

// =============================================================================
// Read sectors (LBA28 PIO mode)
// =============================================================================
pub fn readSectors(drive_idx: usize, lba: u64, count: u8, buffer: [*]u8) bool {
    if (drive_idx >= 4) return false;
    const drv = &drives[drive_idx];
    if (!drv.is_present or drv.is_atapi) return false;

    if (drv.supports_lba48 and lba >= 0x10000000) {
        return readSectors48(drv, lba, count, buffer);
    }

    return readSectors28(drv, @intCast(lba), count, buffer);
}

fn readSectors28(drv: *const AtaDrive, lba: u32, count: u8, buffer: [*]u8) bool {
    // Wait for drive ready
    if (!waitReady(drv.io_base)) return false;

    // Select drive and send LBA
    main.cpu.outb(drv.io_base + ATA_REG_DRIVE, 0xE0 | (@as(u8, drv.drive) << 4) | @as(u8, @truncate((lba >> 24) & 0x0F)));
    main.cpu.outb(drv.io_base + ATA_REG_SECCOUNT, count);
    main.cpu.outb(drv.io_base + ATA_REG_LBA_LO, @truncate(lba));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_MID, @truncate(lba >> 8));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_HI, @truncate(lba >> 16));
    main.cpu.outb(drv.io_base + ATA_REG_COMMAND, ATA_CMD_READ_PIO);

    // Read each sector
    var sector: u16 = 0;
    while (sector < count) : (sector += 1) {
        if (!waitDrq(drv.io_base)) return false;

        const offset = @as(usize, sector) * SECTOR_SIZE;
        var word: usize = 0;
        while (word < SECTOR_SIZE / 2) : (word += 1) {
            const data = main.cpu.inw(drv.io_base + ATA_REG_DATA);
            buffer[offset + word * 2] = @truncate(data);
            buffer[offset + word * 2 + 1] = @truncate(data >> 8);
        }
    }

    return true;
}

fn readSectors48(drv: *const AtaDrive, lba: u64, count: u8, buffer: [*]u8) bool {
    if (!waitReady(drv.io_base)) return false;

    // Select drive
    main.cpu.outb(drv.io_base + ATA_REG_DRIVE, 0x40 | (@as(u8, drv.drive) << 4));

    // Send high bytes first
    main.cpu.outb(drv.io_base + ATA_REG_SECCOUNT, 0); // High byte of count
    main.cpu.outb(drv.io_base + ATA_REG_LBA_LO, @truncate(lba >> 24));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_MID, @truncate(lba >> 32));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_HI, @truncate(lba >> 40));

    // Then low bytes
    main.cpu.outb(drv.io_base + ATA_REG_SECCOUNT, count);
    main.cpu.outb(drv.io_base + ATA_REG_LBA_LO, @truncate(lba));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_MID, @truncate(lba >> 8));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_HI, @truncate(lba >> 16));

    main.cpu.outb(drv.io_base + ATA_REG_COMMAND, ATA_CMD_READ_PIO_EXT);

    var sector: u16 = 0;
    while (sector < count) : (sector += 1) {
        if (!waitDrq(drv.io_base)) return false;

        const offset = @as(usize, sector) * SECTOR_SIZE;
        var word: usize = 0;
        while (word < SECTOR_SIZE / 2) : (word += 1) {
            const data = main.cpu.inw(drv.io_base + ATA_REG_DATA);
            buffer[offset + word * 2] = @truncate(data);
            buffer[offset + word * 2 + 1] = @truncate(data >> 8);
        }
    }

    return true;
}

// =============================================================================
// Write sectors
// =============================================================================
pub fn writeSectors(drive_idx: usize, lba: u64, count: u8, buffer: [*]const u8) bool {
    if (drive_idx >= 4) return false;
    const drv = &drives[drive_idx];
    if (!drv.is_present or drv.is_atapi) return false;

    if (!waitReady(drv.io_base)) return false;

    // LBA28 only for now
    main.cpu.outb(drv.io_base + ATA_REG_DRIVE, 0xE0 | (@as(u8, drv.drive) << 4) | @as(u8, @truncate((@as(u32, @truncate(lba)) >> 24) & 0x0F)));
    main.cpu.outb(drv.io_base + ATA_REG_SECCOUNT, count);
    main.cpu.outb(drv.io_base + ATA_REG_LBA_LO, @truncate(lba));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_MID, @truncate(lba >> 8));
    main.cpu.outb(drv.io_base + ATA_REG_LBA_HI, @truncate(lba >> 16));
    main.cpu.outb(drv.io_base + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO);

    var sector: u16 = 0;
    while (sector < count) : (sector += 1) {
        if (!waitDrq(drv.io_base)) return false;

        const offset = @as(usize, sector) * SECTOR_SIZE;
        var word: usize = 0;
        while (word < SECTOR_SIZE / 2) : (word += 1) {
            const lo: u16 = buffer[offset + word * 2];
            const hi: u16 = buffer[offset + word * 2 + 1];
            main.cpu.outw(drv.io_base + ATA_REG_DATA, lo | (hi << 8));
        }
    }

    // Flush cache
    main.cpu.outb(drv.io_base + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    _ = waitReady(drv.io_base);

    return true;
}

// =============================================================================
// Helpers
// =============================================================================

fn waitReady(io_base: u16) bool {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const status = main.cpu.inb(io_base + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRDY) != 0) return true;
        if ((status & (ATA_SR_ERR | ATA_SR_DF)) != 0) return false;
    }
    return false;
}

fn waitDrq(io_base: u16) bool {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        const status = main.cpu.inb(io_base + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRQ) != 0) return true;
        if ((status & (ATA_SR_ERR | ATA_SR_DF)) != 0) return false;
    }
    return false;
}

fn ioDelay() void {
    // Reading the alternate status register provides a ~400ns delay
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        _ = main.cpu.inb(0x3F6);
    }
}

/// Get drive info by index
pub fn getDrive(index: usize) ?*const AtaDrive {
    if (index >= 4) return null;
    if (!drives[index].is_present) return null;
    return &drives[index];
}

/// Get number of present drives
pub fn getDriveCount() usize {
    return drive_count;
}
