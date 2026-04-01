// =============================================================================
// Kernel Zxyphor — SCSI Subsystem (Zig)
// =============================================================================
// SCSI mid-layer providing protocol-agnostic device management:
//   - SCSI command (CDB) building for all major SCSI operations
//   - SCSI host adapter registration
//   - SCSI device (LUN) discovery and enumeration
//   - Sense data parsing and error classification
//   - SCSI device types (disk, tape, cdrom, scanner, etc.)
//   - SCSI request queue with tag management
//   - Error handling and retry logic
//   - Mode page parsing
//   - INQUIRY VPD pages
//   - SAM status codes
//   - Task management functions (abort, LUN reset, target reset)
//   - SCSI logging
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_SCSI_HOSTS = 8;
pub const MAX_SCSI_DEVICES = 64;
pub const MAX_LUNS_PER_TARGET = 8;
pub const MAX_TARGETS_PER_HOST = 16;
pub const MAX_CDB_SIZE = 16;
pub const MAX_SENSE_SIZE = 96;
pub const MAX_SCSI_CMDS = 256;
pub const MAX_SCSI_QUEUE = 128;

// =============================================================================
// SCSI opcodes
// =============================================================================

pub const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub const SCSI_REQUEST_SENSE: u8 = 0x03;
pub const SCSI_INQUIRY: u8 = 0x12;
pub const SCSI_MODE_SENSE_6: u8 = 0x1A;
pub const SCSI_MODE_SELECT_6: u8 = 0x15;
pub const SCSI_MODE_SENSE_10: u8 = 0x5A;
pub const SCSI_MODE_SELECT_10: u8 = 0x55;
pub const SCSI_READ_6: u8 = 0x08;
pub const SCSI_WRITE_6: u8 = 0x0A;
pub const SCSI_READ_10: u8 = 0x28;
pub const SCSI_WRITE_10: u8 = 0x2A;
pub const SCSI_READ_16: u8 = 0x88;
pub const SCSI_WRITE_16: u8 = 0x8A;
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_READ_CAPACITY_16: u8 = 0x9E;
pub const SCSI_SYNCHRONIZE_CACHE_10: u8 = 0x35;
pub const SCSI_SYNCHRONIZE_CACHE_16: u8 = 0x91;
pub const SCSI_START_STOP: u8 = 0x1B;
pub const SCSI_REPORT_LUNS: u8 = 0xA0;
pub const SCSI_VERIFY_10: u8 = 0x2F;
pub const SCSI_VERIFY_16: u8 = 0x8F;
pub const SCSI_UNMAP: u8 = 0x42;            // TRIM/discard
pub const SCSI_WRITE_SAME_10: u8 = 0x41;
pub const SCSI_WRITE_SAME_16: u8 = 0x93;
pub const SCSI_ATA_PASSTHROUGH_16: u8 = 0x85;
pub const SCSI_ATA_PASSTHROUGH_12: u8 = 0xA1;
pub const SCSI_LOG_SENSE: u8 = 0x4D;
pub const SCSI_FORMAT_UNIT: u8 = 0x04;
pub const SCSI_SECURITY_PROTOCOL_IN: u8 = 0xA2;
pub const SCSI_SECURITY_PROTOCOL_OUT: u8 = 0xB5;

// =============================================================================
// SCSI device types
// =============================================================================

pub const ScsiDeviceType = enum(u8) {
    disk = 0x00,
    tape = 0x01,
    printer = 0x02,
    processor = 0x03,
    worm = 0x04,
    cdrom = 0x05,
    scanner = 0x06,
    optical = 0x07,
    changer = 0x08,
    comm = 0x09,
    raid = 0x0C,
    enclosure = 0x0D,
    rbc = 0x0E,         // simplified block
    osd = 0x11,         // object storage
    zbc = 0x14,         // zoned block
    well_known = 0x1E,
    no_device = 0x1F,

    pub fn name(self: ScsiDeviceType) []const u8 {
        return switch (self) {
            .disk => "Direct-Access (Disk)",
            .tape => "Sequential-Access (Tape)",
            .printer => "Printer",
            .processor => "Processor",
            .worm => "Write-Once (WORM)",
            .cdrom => "CD-ROM",
            .scanner => "Scanner",
            .optical => "Optical Memory",
            .changer => "Medium Changer",
            .comm => "Communications",
            .raid => "Storage Array (RAID)",
            .enclosure => "Enclosure Services",
            .rbc => "Reduced Block",
            .osd => "Object Storage",
            .zbc => "Zoned Block",
            .well_known => "Well Known LU",
            .no_device => "No Device",
        };
    }
};

// =============================================================================
// SCSI status codes (SAM-5)
// =============================================================================

pub const ScsiStatus = enum(u8) {
    good = 0x00,
    check_condition = 0x02,
    condition_met = 0x04,
    busy = 0x08,
    intermediate = 0x10,
    intermediate_condition_met = 0x14,
    reservation_conflict = 0x18,
    command_terminated = 0x22,
    task_set_full = 0x28,
    aca_active = 0x30,
    task_aborted = 0x40,

    pub fn isGood(self: ScsiStatus) bool {
        return self == .good or self == .condition_met;
    }
};

// =============================================================================
// Sense keys
// =============================================================================

pub const SenseKey = enum(u4) {
    no_sense = 0x0,
    recovered_error = 0x1,
    not_ready = 0x2,
    medium_error = 0x3,
    hardware_error = 0x4,
    illegal_request = 0x5,
    unit_attention = 0x6,
    data_protect = 0x7,
    blank_check = 0x8,
    vendor_specific = 0x9,
    copy_aborted = 0xA,
    aborted_command = 0xB,
    volume_overflow = 0xD,
    miscompare = 0xE,
    completed = 0xF,

    pub fn isRetryable(self: SenseKey) bool {
        return switch (self) {
            .not_ready, .unit_attention, .aborted_command => true,
            else => false,
        };
    }

    pub fn isFatal(self: SenseKey) bool {
        return switch (self) {
            .medium_error, .hardware_error, .data_protect => true,
            else => false,
        };
    }
};

// =============================================================================
// Parsed sense data
// =============================================================================

pub const SenseData = struct {
    response_code: u8,
    sense_key: SenseKey,
    asc: u8,           // Additional Sense Code
    ascq: u8,          // Additional Sense Code Qualifier
    info: u32,         // information field
    cmd_specific: u32, // command-specific info
    fru: u8,           // Field Replaceable Unit
    valid: bool,
    deferred: bool,

    pub fn init() SenseData {
        return .{
            .response_code = 0,
            .sense_key = .no_sense,
            .asc = 0, .ascq = 0,
            .info = 0, .cmd_specific = 0,
            .fru = 0,
            .valid = false,
            .deferred = false,
        };
    }

    /// Parse raw sense data (fixed format 70h/71h)
    pub fn parse(raw: []const u8) SenseData {
        if (raw.len < 8) return SenseData.init();

        var sd = SenseData.init();
        sd.response_code = raw[0] & 0x7F;
        sd.valid = (raw[0] & 0x80) != 0;
        sd.deferred = (sd.response_code == 0x71);

        if (sd.response_code != 0x70 and sd.response_code != 0x71) return sd;

        sd.sense_key = @enumFromInt(@as(u4, @truncate(raw[2] & 0x0F)));
        sd.info = (@as(u32, raw[3]) << 24) | (@as(u32, raw[4]) << 16) |
            (@as(u32, raw[5]) << 8) | @as(u32, raw[6]);

        if (raw.len >= 13) {
            sd.asc = raw[12];
        }
        if (raw.len >= 14) {
            sd.ascq = raw[13];
        }
        if (raw.len >= 15) {
            sd.fru = raw[14];
        }

        return sd;
    }

    pub fn isError(self: *const SenseData) bool {
        return self.sense_key != .no_sense and self.sense_key != .recovered_error;
    }

    pub fn isMediaChanged(self: *const SenseData) bool {
        return self.sense_key == .unit_attention and self.asc == 0x28;
    }

    pub fn isPowerOn(self: *const SenseData) bool {
        return self.sense_key == .unit_attention and self.asc == 0x29;
    }
};

// =============================================================================
// SCSI CDB (Command Descriptor Block) builder
// =============================================================================

pub const ScsiCdb = struct {
    data: [MAX_CDB_SIZE]u8,
    length: u8,

    pub fn init() ScsiCdb {
        return .{ .data = [_]u8{0} ** MAX_CDB_SIZE, .length = 0 };
    }

    pub fn testUnitReady() ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_TEST_UNIT_READY;
        cdb.length = 6;
        return cdb;
    }

    pub fn inquiry(evpd: bool, page: u8, alloc_len: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_INQUIRY;
        if (evpd) cdb.data[1] = 0x01;
        cdb.data[2] = page;
        cdb.data[3] = @truncate(alloc_len >> 8);
        cdb.data[4] = @truncate(alloc_len & 0xFF);
        cdb.length = 6;
        return cdb;
    }

    pub fn requestSense(alloc_len: u8) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_REQUEST_SENSE;
        cdb.data[4] = alloc_len;
        cdb.length = 6;
        return cdb;
    }

    pub fn readCapacity10() ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_READ_CAPACITY_10;
        cdb.length = 10;
        return cdb;
    }

    pub fn readCapacity16(alloc_len: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_READ_CAPACITY_16;
        cdb.data[1] = 0x10; // service action
        cdb.data[10] = @truncate(alloc_len >> 24);
        cdb.data[11] = @truncate((alloc_len >> 16) & 0xFF);
        cdb.data[12] = @truncate((alloc_len >> 8) & 0xFF);
        cdb.data[13] = @truncate(alloc_len & 0xFF);
        cdb.length = 16;
        return cdb;
    }

    pub fn read10(lba: u32, count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_READ_10;
        cdb.data[2] = @truncate(lba >> 24);
        cdb.data[3] = @truncate((lba >> 16) & 0xFF);
        cdb.data[4] = @truncate((lba >> 8) & 0xFF);
        cdb.data[5] = @truncate(lba & 0xFF);
        cdb.data[7] = @truncate(count >> 8);
        cdb.data[8] = @truncate(count & 0xFF);
        cdb.length = 10;
        return cdb;
    }

    pub fn write10(lba: u32, count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_WRITE_10;
        cdb.data[2] = @truncate(lba >> 24);
        cdb.data[3] = @truncate((lba >> 16) & 0xFF);
        cdb.data[4] = @truncate((lba >> 8) & 0xFF);
        cdb.data[5] = @truncate(lba & 0xFF);
        cdb.data[7] = @truncate(count >> 8);
        cdb.data[8] = @truncate(count & 0xFF);
        cdb.length = 10;
        return cdb;
    }

    pub fn read16(lba: u64, count: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_READ_16;
        cdb.data[2] = @truncate(lba >> 56);
        cdb.data[3] = @truncate((lba >> 48) & 0xFF);
        cdb.data[4] = @truncate((lba >> 40) & 0xFF);
        cdb.data[5] = @truncate((lba >> 32) & 0xFF);
        cdb.data[6] = @truncate((lba >> 24) & 0xFF);
        cdb.data[7] = @truncate((lba >> 16) & 0xFF);
        cdb.data[8] = @truncate((lba >> 8) & 0xFF);
        cdb.data[9] = @truncate(lba & 0xFF);
        cdb.data[10] = @truncate(count >> 24);
        cdb.data[11] = @truncate((count >> 16) & 0xFF);
        cdb.data[12] = @truncate((count >> 8) & 0xFF);
        cdb.data[13] = @truncate(count & 0xFF);
        cdb.length = 16;
        return cdb;
    }

    pub fn write16(lba: u64, count: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_WRITE_16;
        cdb.data[2] = @truncate(lba >> 56);
        cdb.data[3] = @truncate((lba >> 48) & 0xFF);
        cdb.data[4] = @truncate((lba >> 40) & 0xFF);
        cdb.data[5] = @truncate((lba >> 32) & 0xFF);
        cdb.data[6] = @truncate((lba >> 24) & 0xFF);
        cdb.data[7] = @truncate((lba >> 16) & 0xFF);
        cdb.data[8] = @truncate((lba >> 8) & 0xFF);
        cdb.data[9] = @truncate(lba & 0xFF);
        cdb.data[10] = @truncate(count >> 24);
        cdb.data[11] = @truncate((count >> 16) & 0xFF);
        cdb.data[12] = @truncate((count >> 8) & 0xFF);
        cdb.data[13] = @truncate(count & 0xFF);
        cdb.length = 16;
        return cdb;
    }

    pub fn syncCache10(lba: u32, count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_SYNCHRONIZE_CACHE_10;
        cdb.data[2] = @truncate(lba >> 24);
        cdb.data[3] = @truncate((lba >> 16) & 0xFF);
        cdb.data[4] = @truncate((lba >> 8) & 0xFF);
        cdb.data[5] = @truncate(lba & 0xFF);
        cdb.data[7] = @truncate(count >> 8);
        cdb.data[8] = @truncate(count & 0xFF);
        cdb.length = 10;
        return cdb;
    }

    pub fn startStop(start: bool, eject: bool) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_START_STOP;
        var bits: u8 = 0;
        if (start) bits |= 0x01;
        if (eject) bits |= 0x02;
        cdb.data[4] = bits;
        cdb.length = 6;
        return cdb;
    }

    pub fn modeSense6(page: u8, subpage: u8, alloc_len: u8) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_MODE_SENSE_6;
        cdb.data[2] = page & 0x3F;
        cdb.data[3] = subpage;
        cdb.data[4] = alloc_len;
        cdb.length = 6;
        return cdb;
    }

    pub fn reportLuns(alloc_len: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_REPORT_LUNS;
        cdb.data[6] = @truncate(alloc_len >> 24);
        cdb.data[7] = @truncate((alloc_len >> 16) & 0xFF);
        cdb.data[8] = @truncate((alloc_len >> 8) & 0xFF);
        cdb.data[9] = @truncate(alloc_len & 0xFF);
        cdb.length = 12;
        return cdb;
    }

    pub fn unmap(desc_count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SCSI_UNMAP;
        const data_len = 8 + @as(u16, desc_count) * 16;
        cdb.data[7] = @truncate(data_len >> 8);
        cdb.data[8] = @truncate(data_len & 0xFF);
        cdb.length = 10;
        return cdb;
    }
};

// =============================================================================
// SCSI command request
// =============================================================================

pub const ScsiDirection = enum(u8) {
    none = 0,
    read = 1,
    write = 2,
    bidirectional = 3,
};

pub const ScsiCmdStatus = enum(u8) {
    pending = 0,
    complete = 1,
    error = 2,
    timeout = 3,
    aborted = 4,
    host_error = 5,
};

pub const ScsiCommand = struct {
    cdb: ScsiCdb,
    direction: ScsiDirection,
    data_buffer: u64, // physical address
    data_length: u32,
    residual: u32,
    status: ScsiCmdStatus,
    scsi_status: ScsiStatus,
    sense: [MAX_SENSE_SIZE]u8,
    sense_len: u8,
    timeout_ms: u32,
    retries: u8,
    max_retries: u8,
    tag: u16,
    host_id: u8,
    target_id: u8,
    lun: u8,
    active: bool,

    pub fn init() ScsiCommand {
        return .{
            .cdb = ScsiCdb.init(),
            .direction = .none,
            .data_buffer = 0,
            .data_length = 0,
            .residual = 0,
            .status = .pending,
            .scsi_status = .good,
            .sense = [_]u8{0} ** MAX_SENSE_SIZE,
            .sense_len = 0,
            .timeout_ms = 30000, // 30 seconds default
            .retries = 0,
            .max_retries = 3,
            .tag = 0,
            .host_id = 0,
            .target_id = 0,
            .lun = 0,
            .active = false,
        };
    }

    pub fn parsedSense(self: *const ScsiCommand) SenseData {
        return SenseData.parse(self.sense[0..self.sense_len]);
    }

    pub fn shouldRetry(self: *const ScsiCommand) bool {
        if (self.retries >= self.max_retries) return false;
        if (self.scsi_status == .busy or self.scsi_status == .task_set_full) return true;
        if (self.scsi_status == .check_condition) {
            const sd = self.parsedSense();
            return sd.sense_key.isRetryable();
        }
        return false;
    }
};

// =============================================================================
// SCSI device (LUN)
// =============================================================================

pub const ScsiDevice = struct {
    host_id: u8,
    target_id: u8,
    lun: u8,
    device_type: ScsiDeviceType,
    vendor: [8]u8,
    product: [16]u8,
    revision: [4]u8,
    serial: [20]u8,
    serial_len: u8,
    capacity_blocks: u64,
    block_size: u32,
    removable: bool,
    read_only: bool,
    supports_16byte: bool,
    supports_ncq: bool,
    max_queue_depth: u8,
    active: bool,
    online: bool,

    // SMART / health
    temperature: i16,
    power_on_hours: u32,
    error_count: u32,

    // Stats
    reads: u64,
    writes: u64,
    read_bytes: u64,
    written_bytes: u64,

    pub fn init() ScsiDevice {
        return .{
            .host_id = 0, .target_id = 0, .lun = 0,
            .device_type = .no_device,
            .vendor = [_]u8{' '} ** 8,
            .product = [_]u8{' '} ** 16,
            .revision = [_]u8{' '} ** 4,
            .serial = [_]u8{0} ** 20,
            .serial_len = 0,
            .capacity_blocks = 0,
            .block_size = 512,
            .removable = false,
            .read_only = false,
            .supports_16byte = false,
            .supports_ncq = false,
            .max_queue_depth = 1,
            .active = false,
            .online = false,
            .temperature = 0,
            .power_on_hours = 0,
            .error_count = 0,
            .reads = 0, .writes = 0,
            .read_bytes = 0, .written_bytes = 0,
        };
    }

    pub fn capacityBytes(self: *const ScsiDevice) u64 {
        return self.capacity_blocks * @as(u64, self.block_size);
    }

    pub fn capacityMB(self: *const ScsiDevice) u64 {
        return self.capacityBytes() / (1024 * 1024);
    }

    pub fn capacityGB(self: *const ScsiDevice) u64 {
        return self.capacityBytes() / (1024 * 1024 * 1024);
    }

    pub fn isDisk(self: *const ScsiDevice) bool {
        return self.device_type == .disk or self.device_type == .rbc;
    }
};

// =============================================================================
// SCSI host adapter
// =============================================================================

pub const ScsiHost = struct {
    id: u8,
    name: [32]u8,
    name_len: u8,
    max_targets: u8,
    max_luns: u8,
    max_queue_depth: u16,
    max_sectors: u32,
    devices: [MAX_SCSI_DEVICES]ScsiDevice,
    device_count: u8,
    commands: [MAX_SCSI_CMDS]ScsiCommand,
    cmd_count: u16,
    next_tag: u16,
    active: bool,
    scanning: bool,

    pub fn init(id: u8) ScsiHost {
        return .{
            .id = id,
            .name = [_]u8{0} ** 32,
            .name_len = 0,
            .max_targets = 16,
            .max_luns = 8,
            .max_queue_depth = 32,
            .max_sectors = 2048, // 1MB default
            .devices = [_]ScsiDevice{ScsiDevice.init()} ** MAX_SCSI_DEVICES,
            .device_count = 0,
            .commands = [_]ScsiCommand{ScsiCommand.init()} ** MAX_SCSI_CMDS,
            .cmd_count = 0,
            .next_tag = 1,
            .active = false,
            .scanning = false,
        };
    }

    /// Register a discovered device
    pub fn addDevice(self: *ScsiHost, target: u8, lun: u8, dev_type: ScsiDeviceType) ?u8 {
        if (self.device_count >= MAX_SCSI_DEVICES) return null;
        const idx = self.device_count;
        self.devices[idx] = ScsiDevice.init();
        self.devices[idx].host_id = self.id;
        self.devices[idx].target_id = target;
        self.devices[idx].lun = lun;
        self.devices[idx].device_type = dev_type;
        self.devices[idx].active = true;
        self.devices[idx].online = true;
        self.device_count += 1;
        return idx;
    }

    /// Find a device by target:lun
    pub fn findDevice(self: *const ScsiHost, target: u8, lun: u8) ?*const ScsiDevice {
        for (0..self.device_count) |i| {
            if (self.devices[i].active and self.devices[i].target_id == target and self.devices[i].lun == lun) {
                return &self.devices[i];
            }
        }
        return null;
    }

    /// Queue a SCSI command
    pub fn queueCommand(self: *ScsiHost, cmd: ScsiCommand) ?u16 {
        if (self.cmd_count >= MAX_SCSI_CMDS) return null;
        for (0..MAX_SCSI_CMDS) |i| {
            if (!self.commands[i].active) {
                self.commands[i] = cmd;
                self.commands[i].active = true;
                self.commands[i].tag = self.next_tag;
                self.commands[i].host_id = self.id;
                self.cmd_count += 1;
                const tag = self.next_tag;
                self.next_tag +%= 1;
                if (self.next_tag == 0) self.next_tag = 1;
                return tag;
            }
        }
        return null;
    }

    /// Complete a command by tag
    pub fn completeCommand(self: *ScsiHost, tag: u16, scsi_status: ScsiStatus) void {
        for (0..MAX_SCSI_CMDS) |i| {
            if (self.commands[i].active and self.commands[i].tag == tag) {
                self.commands[i].scsi_status = scsi_status;
                self.commands[i].status = if (scsi_status.isGood()) .complete else .error;
                self.commands[i].active = false;
                if (self.cmd_count > 0) self.cmd_count -= 1;
                return;
            }
        }
    }
};

// =============================================================================
// SCSI Subsystem
// =============================================================================

pub const ScsiSubsystem = struct {
    hosts: [MAX_SCSI_HOSTS]ScsiHost,
    host_count: u8,
    initialized: bool,

    pub fn init() ScsiSubsystem {
        var sub: ScsiSubsystem = undefined;
        for (0..MAX_SCSI_HOSTS) |i| {
            sub.hosts[i] = ScsiHost.init(@truncate(i));
        }
        sub.host_count = 0;
        sub.initialized = false;
        return sub;
    }

    /// Register a host adapter
    pub fn registerHost(self: *ScsiSubsystem, name: []const u8) ?u8 {
        if (self.host_count >= MAX_SCSI_HOSTS) return null;
        const idx = self.host_count;
        self.hosts[idx].active = true;
        const len = if (name.len > 31) 31 else name.len;
        @memcpy(self.hosts[idx].name[0..len], name[0..len]);
        self.hosts[idx].name_len = @truncate(len);
        self.host_count += 1;
        if (!self.initialized) self.initialized = true;
        return idx;
    }

    /// Get a host by ID
    pub fn getHost(self: *ScsiSubsystem, id: u8) ?*ScsiHost {
        if (id >= self.host_count) return null;
        if (!self.hosts[id].active) return null;
        return &self.hosts[id];
    }

    /// Total device count across all hosts
    pub fn totalDevices(self: *const ScsiSubsystem) u32 {
        var count: u32 = 0;
        for (0..self.host_count) |i| {
            count += self.hosts[i].device_count;
        }
        return count;
    }

    /// Total disk capacity across all hosts (bytes)
    pub fn totalCapacity(self: *const ScsiSubsystem) u64 {
        var total: u64 = 0;
        for (0..self.host_count) |h| {
            for (0..self.hosts[h].device_count) |d| {
                if (self.hosts[h].devices[d].active and self.hosts[h].devices[d].isDisk()) {
                    total += self.hosts[h].devices[d].capacityBytes();
                }
            }
        }
        return total;
    }
};

// =============================================================================
// Global instance
// =============================================================================

var scsi_subsystem: ScsiSubsystem = ScsiSubsystem.init();

pub fn getScsiSubsystem() *ScsiSubsystem {
    return &scsi_subsystem;
}
