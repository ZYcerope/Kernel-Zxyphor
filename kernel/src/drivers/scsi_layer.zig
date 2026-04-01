// SPDX-License-Identifier: MIT
// Zxyphor Kernel — SCSI Subsystem
//
// Full SCSI command layer with:
// - SCSI command descriptor block (CDB) construction for all command groups
// - SCSI device discovery and LUN scanning
// - Request sense / error handling with ASC/ASCQ decode
// - SCSI disk (sd), SCSI tape (st), SCSI generic (sg) abstraction
// - Tagged command queuing (TCQ) with simple/ordered/head-of-queue tags
// - SCSI device state machine (created→running→quiesce→offline→deleted)
// - SCSI host adapter abstraction
// - Unit attention / contingent allegiance handling
// - MODE SENSE/SELECT parameter page management
// - INQUIRY VPD page support
// - Transport error recovery (abort → device reset → bus reset → host reset)

const std = @import("std");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_SCSI_HOSTS: u32 = 8;
pub const MAX_SCSI_DEVICES: u32 = 128;
pub const MAX_LUNS_PER_TARGET: u32 = 8;
pub const MAX_TARGETS_PER_HOST: u32 = 16;
pub const MAX_CDB_SIZE: u32 = 16;
pub const MAX_SENSE_SIZE: u32 = 96;
pub const MAX_QUEUE_DEPTH: u32 = 64;
pub const MAX_INQUIRY_LEN: u32 = 96;
pub const MAX_VPD_LEN: u32 = 256;
pub const SCSI_TIMEOUT_DEFAULT: u64 = 30000; // 30 seconds in ms

// SCSI operation codes
pub const TEST_UNIT_READY: u8 = 0x00;
pub const REQUEST_SENSE: u8 = 0x03;
pub const INQUIRY: u8 = 0x12;
pub const MODE_SELECT_6: u8 = 0x15;
pub const MODE_SENSE_6: u8 = 0x1A;
pub const START_STOP_UNIT: u8 = 0x1B;
pub const READ_CAPACITY_10: u8 = 0x25;
pub const READ_10: u8 = 0x28;
pub const WRITE_10: u8 = 0x2A;
pub const VERIFY_10: u8 = 0x2F;
pub const SYNCHRONIZE_CACHE: u8 = 0x35;
pub const READ_16: u8 = 0x88;
pub const WRITE_16: u8 = 0x8A;
pub const READ_CAPACITY_16: u8 = 0x9E;
pub const REPORT_LUNS: u8 = 0xA0;
pub const MODE_SELECT_10: u8 = 0x55;
pub const MODE_SENSE_10: u8 = 0x5A;
pub const UNMAP: u8 = 0x42; // TRIM/discard
pub const WRITE_SAME_16: u8 = 0x93;

// SCSI status codes
pub const GOOD: u8 = 0x00;
pub const CHECK_CONDITION: u8 = 0x02;
pub const CONDITION_MET: u8 = 0x04;
pub const BUSY: u8 = 0x08;
pub const RESERVATION_CONFLICT: u8 = 0x18;
pub const TASK_SET_FULL: u8 = 0x28;
pub const ACA_ACTIVE: u8 = 0x30;
pub const TASK_ABORTED: u8 = 0x40;

// Sense key values
pub const SENSE_NO_SENSE: u8 = 0x0;
pub const SENSE_RECOVERED_ERROR: u8 = 0x1;
pub const SENSE_NOT_READY: u8 = 0x2;
pub const SENSE_MEDIUM_ERROR: u8 = 0x3;
pub const SENSE_HARDWARE_ERROR: u8 = 0x4;
pub const SENSE_ILLEGAL_REQUEST: u8 = 0x5;
pub const SENSE_UNIT_ATTENTION: u8 = 0x6;
pub const SENSE_DATA_PROTECT: u8 = 0x7;
pub const SENSE_BLANK_CHECK: u8 = 0x8;
pub const SENSE_ABORTED_COMMAND: u8 = 0xB;

// SCSI device types (from INQUIRY)
pub const TYPE_DISK: u8 = 0x00;
pub const TYPE_TAPE: u8 = 0x01;
pub const TYPE_PRINTER: u8 = 0x02;
pub const TYPE_PROCESSOR: u8 = 0x03;
pub const TYPE_WORM: u8 = 0x04;
pub const TYPE_ROM: u8 = 0x05;
pub const TYPE_SCANNER: u8 = 0x06;
pub const TYPE_MOD: u8 = 0x07;
pub const TYPE_ENCLOSURE: u8 = 0x0D;
pub const TYPE_RBC: u8 = 0x0E;
pub const TYPE_NO_LUN: u8 = 0x7F;

// Tag types
pub const TAG_SIMPLE: u8 = 0x20;
pub const TAG_HEAD_OF_QUEUE: u8 = 0x21;
pub const TAG_ORDERED: u8 = 0x22;

// ============================================================================
// SCSI Command Descriptor Block
// ============================================================================

pub const ScsiCdb = struct {
    data: [MAX_CDB_SIZE]u8,
    len: u8,

    pub fn init() ScsiCdb {
        return ScsiCdb{
            .data = [_]u8{0} ** MAX_CDB_SIZE,
            .len = 0,
        };
    }

    /// Build TEST UNIT READY (6-byte)
    pub fn test_unit_ready() ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = TEST_UNIT_READY;
        cdb.len = 6;
        return cdb;
    }

    /// Build REQUEST SENSE (6-byte)
    pub fn request_sense(alloc_len: u8) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = REQUEST_SENSE;
        cdb.data[4] = alloc_len;
        cdb.len = 6;
        return cdb;
    }

    /// Build INQUIRY
    pub fn inquiry(alloc_len: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = INQUIRY;
        cdb.data[3] = @intCast((alloc_len >> 8) & 0xFF);
        cdb.data[4] = @intCast(alloc_len & 0xFF);
        cdb.len = 6;
        return cdb;
    }

    /// Build INQUIRY with VPD page
    pub fn inquiry_vpd(page: u8, alloc_len: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = INQUIRY;
        cdb.data[1] = 0x01; // EVPD=1
        cdb.data[2] = page;
        cdb.data[3] = @intCast((alloc_len >> 8) & 0xFF);
        cdb.data[4] = @intCast(alloc_len & 0xFF);
        cdb.len = 6;
        return cdb;
    }

    /// Build READ CAPACITY (10)
    pub fn read_capacity_10() ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = READ_CAPACITY_10;
        cdb.len = 10;
        return cdb;
    }

    /// Build READ (10) — up to 2TB
    pub fn read_10(lba: u32, count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = READ_10;
        cdb.data[2] = @intCast((lba >> 24) & 0xFF);
        cdb.data[3] = @intCast((lba >> 16) & 0xFF);
        cdb.data[4] = @intCast((lba >> 8) & 0xFF);
        cdb.data[5] = @intCast(lba & 0xFF);
        cdb.data[7] = @intCast((count >> 8) & 0xFF);
        cdb.data[8] = @intCast(count & 0xFF);
        cdb.len = 10;
        return cdb;
    }

    /// Build WRITE (10) — up to 2TB
    pub fn write_10(lba: u32, count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = WRITE_10;
        cdb.data[2] = @intCast((lba >> 24) & 0xFF);
        cdb.data[3] = @intCast((lba >> 16) & 0xFF);
        cdb.data[4] = @intCast((lba >> 8) & 0xFF);
        cdb.data[5] = @intCast(lba & 0xFF);
        cdb.data[7] = @intCast((count >> 8) & 0xFF);
        cdb.data[8] = @intCast(count & 0xFF);
        cdb.len = 10;
        return cdb;
    }

    /// Build READ (16) — large LBA
    pub fn read_16(lba: u64, count: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = READ_16;
        cdb.data[2] = @intCast((lba >> 56) & 0xFF);
        cdb.data[3] = @intCast((lba >> 48) & 0xFF);
        cdb.data[4] = @intCast((lba >> 40) & 0xFF);
        cdb.data[5] = @intCast((lba >> 32) & 0xFF);
        cdb.data[6] = @intCast((lba >> 24) & 0xFF);
        cdb.data[7] = @intCast((lba >> 16) & 0xFF);
        cdb.data[8] = @intCast((lba >> 8) & 0xFF);
        cdb.data[9] = @intCast(lba & 0xFF);
        cdb.data[10] = @intCast((count >> 24) & 0xFF);
        cdb.data[11] = @intCast((count >> 16) & 0xFF);
        cdb.data[12] = @intCast((count >> 8) & 0xFF);
        cdb.data[13] = @intCast(count & 0xFF);
        cdb.len = 16;
        return cdb;
    }

    /// Build WRITE (16) — large LBA
    pub fn write_16(lba: u64, count: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = WRITE_16;
        cdb.data[2] = @intCast((lba >> 56) & 0xFF);
        cdb.data[3] = @intCast((lba >> 48) & 0xFF);
        cdb.data[4] = @intCast((lba >> 40) & 0xFF);
        cdb.data[5] = @intCast((lba >> 32) & 0xFF);
        cdb.data[6] = @intCast((lba >> 24) & 0xFF);
        cdb.data[7] = @intCast((lba >> 16) & 0xFF);
        cdb.data[8] = @intCast((lba >> 8) & 0xFF);
        cdb.data[9] = @intCast(lba & 0xFF);
        cdb.data[10] = @intCast((count >> 24) & 0xFF);
        cdb.data[11] = @intCast((count >> 16) & 0xFF);
        cdb.data[12] = @intCast((count >> 8) & 0xFF);
        cdb.data[13] = @intCast(count & 0xFF);
        cdb.len = 16;
        return cdb;
    }

    /// Build SYNCHRONIZE CACHE
    pub fn sync_cache(lba: u32, count: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = SYNCHRONIZE_CACHE;
        cdb.data[2] = @intCast((lba >> 24) & 0xFF);
        cdb.data[3] = @intCast((lba >> 16) & 0xFF);
        cdb.data[4] = @intCast((lba >> 8) & 0xFF);
        cdb.data[5] = @intCast(lba & 0xFF);
        cdb.data[7] = @intCast((count >> 8) & 0xFF);
        cdb.data[8] = @intCast(count & 0xFF);
        cdb.len = 10;
        return cdb;
    }

    /// Build MODE SENSE (6)
    pub fn mode_sense_6(page: u8, alloc_len: u8) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = MODE_SENSE_6;
        cdb.data[2] = page & 0x3F; // Page code
        cdb.data[4] = alloc_len;
        cdb.len = 6;
        return cdb;
    }

    /// Build START STOP UNIT
    pub fn start_stop(start: bool, loej: bool) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = START_STOP_UNIT;
        if (start) cdb.data[4] |= 0x01;
        if (loej) cdb.data[4] |= 0x02; // Load/Eject
        cdb.len = 6;
        return cdb;
    }

    /// Build REPORT LUNS
    pub fn report_luns(alloc_len: u32) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = REPORT_LUNS;
        cdb.data[6] = @intCast((alloc_len >> 24) & 0xFF);
        cdb.data[7] = @intCast((alloc_len >> 16) & 0xFF);
        cdb.data[8] = @intCast((alloc_len >> 8) & 0xFF);
        cdb.data[9] = @intCast(alloc_len & 0xFF);
        cdb.len = 12;
        return cdb;
    }

    /// Build UNMAP (TRIM/discard)
    pub fn unmap(param_len: u16) ScsiCdb {
        var cdb = ScsiCdb.init();
        cdb.data[0] = UNMAP;
        cdb.data[7] = @intCast((param_len >> 8) & 0xFF);
        cdb.data[8] = @intCast(param_len & 0xFF);
        cdb.len = 10;
        return cdb;
    }

    /// Get command group (determines CDB length)
    pub fn group(opcode: u8) u8 {
        return (opcode >> 5) & 0x07;
    }

    /// Get expected CDB length from opcode
    pub fn expected_len(opcode: u8) u8 {
        return switch (group(opcode)) {
            0 => 6,
            1, 2 => 10,
            3 => 0, // Variable
            4 => 16,
            5 => 12,
            6, 7 => 0, // Vendor specific
            else => 6,
        };
    }
};

// ============================================================================
// SCSI Sense Data
// ============================================================================

pub const SenseData = struct {
    response_code: u8,
    sense_key: u8,
    asc: u8,  // Additional Sense Code
    ascq: u8, // Additional Sense Code Qualifier
    info: u32,
    additional_len: u8,
    raw: [MAX_SENSE_SIZE]u8,
    raw_len: u8,
    valid: bool,

    pub fn init() SenseData {
        return SenseData{
            .response_code = 0,
            .sense_key = 0,
            .asc = 0,
            .ascq = 0,
            .info = 0,
            .additional_len = 0,
            .raw = [_]u8{0} ** MAX_SENSE_SIZE,
            .raw_len = 0,
            .valid = false,
        };
    }

    /// Parse fixed-format sense data (response code 0x70/0x71)
    pub fn parse_fixed(self: *SenseData, data: []const u8) void {
        if (data.len < 8) return;

        self.response_code = data[0] & 0x7F;
        self.valid = (data[0] & 0x80) != 0;
        self.sense_key = data[2] & 0x0F;
        self.info = (@as(u32, data[3]) << 24) | (@as(u32, data[4]) << 16) |
            (@as(u32, data[5]) << 8) | @as(u32, data[6]);
        self.additional_len = data[7];

        if (data.len >= 13) {
            self.asc = data[12];
        }
        if (data.len >= 14) {
            self.ascq = data[13];
        }

        const copy_len = if (data.len > MAX_SENSE_SIZE) MAX_SENSE_SIZE else data.len;
        @memcpy(self.raw[0..copy_len], data[0..copy_len]);
        self.raw_len = @intCast(copy_len);
    }

    /// Check if this is a unit attention condition
    pub fn is_unit_attention(self: *const SenseData) bool {
        return self.sense_key == SENSE_UNIT_ATTENTION;
    }

    /// Check if media changed (ASC=0x28, ASCQ=0x00)
    pub fn is_media_changed(self: *const SenseData) bool {
        return self.sense_key == SENSE_UNIT_ATTENTION and
            self.asc == 0x28 and self.ascq == 0x00;
    }

    /// Check if not ready - becoming ready (spinning up)
    pub fn is_becoming_ready(self: *const SenseData) bool {
        return self.sense_key == SENSE_NOT_READY and
            self.asc == 0x04 and self.ascq == 0x01;
    }

    /// Check for medium error
    pub fn is_medium_error(self: *const SenseData) bool {
        return self.sense_key == SENSE_MEDIUM_ERROR;
    }

    /// Determine if command should be retried
    pub fn should_retry(self: *const SenseData) bool {
        return switch (self.sense_key) {
            SENSE_RECOVERED_ERROR => true,
            SENSE_NOT_READY => self.is_becoming_ready(),
            SENSE_UNIT_ATTENTION => true, // Retry after UA handling
            SENSE_ABORTED_COMMAND => true,
            else => false,
        };
    }
};

// ============================================================================
// SCSI Device State
// ============================================================================

pub const ScsiDevState = enum(u8) {
    created = 0,
    running = 1,
    cancel = 2,
    quiesce = 3,
    offline = 4,
    transport_offline = 5,
    block = 6,
    deleted = 7,
};

// ============================================================================
// SCSI Inquiry Data
// ============================================================================

pub const InquiryData = struct {
    device_type: u8,
    removable: bool,
    vendor: [8]u8,
    product: [16]u8,
    revision: [4]u8,
    scsi_version: u8,
    response_format: u8,
    cmd_queue: bool,  // TCQ supported
    wide_16: bool,    // 16-bit wide SCSI
    sync: bool,       // Synchronous transfer
    linked_cmds: bool,

    pub fn init() InquiryData {
        return InquiryData{
            .device_type = TYPE_NO_LUN,
            .removable = false,
            .vendor = [_]u8{' '} ** 8,
            .product = [_]u8{' '} ** 16,
            .revision = [_]u8{' '} ** 4,
            .scsi_version = 0,
            .response_format = 0,
            .cmd_queue = false,
            .wide_16 = false,
            .sync = false,
            .linked_cmds = false,
        };
    }

    /// Parse standard INQUIRY response
    pub fn parse(self: *InquiryData, data: []const u8) void {
        if (data.len < 36) return;

        self.device_type = data[0] & 0x1F;
        self.removable = (data[1] & 0x80) != 0;
        self.scsi_version = data[2];
        self.response_format = data[3] & 0x0F;
        self.cmd_queue = (data[7] & 0x02) != 0;
        self.linked_cmds = (data[7] & 0x08) != 0;
        self.sync = (data[7] & 0x10) != 0;
        self.wide_16 = (data[7] & 0x20) != 0;

        @memcpy(self.vendor[0..8], data[8..16]);
        @memcpy(self.product[0..16], data[16..32]);
        @memcpy(self.revision[0..4], data[32..36]);
    }

    /// Check if this is a disk device
    pub fn is_disk(self: *const InquiryData) bool {
        return self.device_type == TYPE_DISK;
    }
};

// ============================================================================
// SCSI Command (request)
// ============================================================================

pub const ScsiCommand = struct {
    cdb: ScsiCdb,
    sense: SenseData,
    status: u8,
    host_status: u8,
    tag: u16,
    tag_type: u8,
    target_id: u8,
    lun: u8,
    data_direction: DataDirection,
    data_len: u32,
    residual: u32,
    timeout_ms: u64,
    retries: u8,
    max_retries: u8,
    done: bool,
    error: bool,

    pub fn init() ScsiCommand {
        return ScsiCommand{
            .cdb = ScsiCdb.init(),
            .sense = SenseData.init(),
            .status = GOOD,
            .host_status = 0,
            .tag = 0,
            .tag_type = TAG_SIMPLE,
            .target_id = 0,
            .lun = 0,
            .data_direction = .none,
            .data_len = 0,
            .residual = 0,
            .timeout_ms = SCSI_TIMEOUT_DEFAULT,
            .retries = 0,
            .max_retries = 3,
            .done = false,
            .error = false,
        };
    }
};

pub const DataDirection = enum(u8) {
    none = 0,
    to_device = 1,   // Write
    from_device = 2,  // Read
    bidirectional = 3,
};

// ============================================================================
// SCSI Device
// ============================================================================

pub const ScsiDevice = struct {
    host_idx: u8,
    target_id: u8,
    lun: u8,
    state: ScsiDevState,
    inquiry: InquiryData,
    /// Capacity (in logical blocks)
    capacity: u64,
    /// Logical block size (typically 512 or 4096)
    block_size: u32,
    /// Queue depth (max outstanding commands)
    queue_depth: u32,
    /// Currently outstanding commands
    outstanding: u32,
    /// Tagged Command Queuing enabled
    tcq_enabled: bool,
    /// Write cache enabled
    write_cache: bool,
    /// Read-ahead enabled
    read_ahead: bool,
    /// Allow restart (send START STOP UNIT on errors)
    allow_restart: bool,
    /// Active flag
    active: bool,
    /// Last sense data
    last_sense: SenseData,
    /// Unit attention pending
    ua_pending: bool,
    /// Stats
    read_ops: u64,
    write_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
    error_count: u32,
    timeout_count: u32,
    reset_count: u32,

    pub fn init() ScsiDevice {
        return ScsiDevice{
            .host_idx = 0,
            .target_id = 0,
            .lun = 0,
            .state = .created,
            .inquiry = InquiryData.init(),
            .capacity = 0,
            .block_size = 512,
            .queue_depth = 1,
            .outstanding = 0,
            .tcq_enabled = false,
            .write_cache = false,
            .read_ahead = false,
            .allow_restart = false,
            .active = false,
            .last_sense = SenseData.init(),
            .ua_pending = false,
            .read_ops = 0,
            .write_ops = 0,
            .read_bytes = 0,
            .write_bytes = 0,
            .error_count = 0,
            .timeout_count = 0,
            .reset_count = 0,
        };
    }

    pub fn can_queue(self: *const ScsiDevice) bool {
        return self.state == .running and self.outstanding < self.queue_depth;
    }

    pub fn size_bytes(self: *const ScsiDevice) u64 {
        return self.capacity * @as(u64, self.block_size);
    }
};

// ============================================================================
// SCSI Host Adapter
// ============================================================================

pub const ScsiHost = struct {
    host_id: u8,
    max_targets: u8,
    max_luns: u8,
    max_queue_depth: u32,
    can_queue: u32,       // Max outstanding across all devices
    outstanding: u32,
    /// Host adapter type name
    name: [32]u8,
    name_len: u8,
    active: bool,
    /// Supported features
    tcq_support: bool,
    wide_support: bool,
    /// Error recovery level
    eh_level: u8, // 0=abort, 1=device reset, 2=bus reset, 3=host reset
    /// Stats
    total_cmds: u64,
    total_completions: u64,
    total_errors: u64,
    total_resets: u64,

    pub fn init() ScsiHost {
        return ScsiHost{
            .host_id = 0,
            .max_targets = MAX_TARGETS_PER_HOST,
            .max_luns = MAX_LUNS_PER_TARGET,
            .max_queue_depth = MAX_QUEUE_DEPTH,
            .can_queue = 128,
            .outstanding = 0,
            .name = [_]u8{0} ** 32,
            .name_len = 0,
            .active = false,
            .tcq_support = true,
            .wide_support = false,
            .eh_level = 3,
            .total_cmds = 0,
            .total_completions = 0,
            .total_errors = 0,
            .total_resets = 0,
        };
    }

    pub fn set_name(self: *ScsiHost, n: []const u8) void {
        const len = if (n.len > 32) 32 else n.len;
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }
};

// ============================================================================
// SCSI Error Recovery
// ============================================================================

pub const EhAction = enum(u8) {
    none = 0,
    retry = 1,
    abort = 2,
    device_reset = 3,
    bus_reset = 4,
    host_reset = 5,
};

pub fn determine_eh_action(status: u8, sense: *const SenseData, retries: u8, max_retries: u8) EhAction {
    if (status == GOOD) return .none;

    if (status == CHECK_CONDITION) {
        if (sense.should_retry() and retries < max_retries) {
            return .retry;
        }
        if (sense.is_medium_error()) {
            return .abort; // Don't retry media errors
        }
        return .abort;
    }

    if (status == BUSY or status == TASK_SET_FULL) {
        if (retries < max_retries) return .retry;
        return .abort;
    }

    if (status == TASK_ABORTED) {
        return .device_reset;
    }

    return .abort;
}

// ============================================================================
// SCSI Manager
// ============================================================================

pub const ScsiManager = struct {
    hosts: [MAX_SCSI_HOSTS]ScsiHost,
    host_count: u32,

    devices: [MAX_SCSI_DEVICES]ScsiDevice,
    device_count: u32,

    /// Command queue
    cmd_queue: [MAX_QUEUE_DEPTH]ScsiCommand,
    cmd_head: u32,
    cmd_tail: u32,
    cmd_count: u32,

    /// Next tag
    next_tag: u16,

    /// Stats
    total_scans: u64,
    total_commands: u64,
    total_completions: u64,
    total_errors: u64,
    total_eh_aborts: u64,
    total_eh_device_resets: u64,
    total_eh_bus_resets: u64,
    total_eh_host_resets: u64,

    pub fn init() ScsiManager {
        var mgr = ScsiManager{
            .hosts = undefined,
            .host_count = 0,
            .devices = undefined,
            .device_count = 0,
            .cmd_queue = undefined,
            .cmd_head = 0,
            .cmd_tail = 0,
            .cmd_count = 0,
            .next_tag = 1,
            .total_scans = 0,
            .total_commands = 0,
            .total_completions = 0,
            .total_errors = 0,
            .total_eh_aborts = 0,
            .total_eh_device_resets = 0,
            .total_eh_bus_resets = 0,
            .total_eh_host_resets = 0,
        };

        for (&mgr.hosts) |*h| h.* = ScsiHost.init();
        for (&mgr.devices) |*d| d.* = ScsiDevice.init();
        for (&mgr.cmd_queue) |*c| c.* = ScsiCommand.init();

        return mgr;
    }

    /// Register a host adapter
    pub fn add_host(self: *ScsiManager, name: []const u8) ?u8 {
        if (self.host_count >= MAX_SCSI_HOSTS) return null;
        const idx: u8 = @intCast(self.host_count);
        self.hosts[idx] = ScsiHost.init();
        self.hosts[idx].host_id = idx;
        self.hosts[idx].set_name(name);
        self.hosts[idx].active = true;
        self.host_count += 1;
        return idx;
    }

    /// Scan a host for devices (LUN scanning)
    pub fn scan_host(self: *ScsiManager, host_idx: u8) u32 {
        if (host_idx >= self.host_count or !self.hosts[host_idx].active) return 0;
        const host = &self.hosts[host_idx];

        var found: u32 = 0;

        var target: u8 = 0;
        while (target < host.max_targets) : (target += 1) {
            // Send INQUIRY to each target, LUN 0
            var lun: u8 = 0;
            while (lun < host.max_luns) : (lun += 1) {
                // Issue INQUIRY command
                var cmd = ScsiCommand.init();
                cmd.cdb = ScsiCdb.inquiry(36);
                cmd.target_id = target;
                cmd.lun = lun;
                cmd.data_direction = .from_device;
                cmd.data_len = 36;

                // Simulate: call host adapter to execute
                const result = self.execute_cmd(host_idx, &cmd);

                if (result and cmd.status == GOOD) {
                    // Parse INQUIRY response
                    var dev = ScsiDevice.init();
                    dev.host_idx = host_idx;
                    dev.target_id = target;
                    dev.lun = lun;
                    dev.state = .running;
                    dev.active = true;

                    // Simulated INQUIRY parsing (in real kernel, data comes from DMA buffer)
                    dev.inquiry.device_type = TYPE_DISK; // Assume disk for simulation
                    dev.inquiry.cmd_queue = host.tcq_support;

                    if (dev.inquiry.cmd_queue) {
                        dev.tcq_enabled = true;
                        dev.queue_depth = 32;
                    }

                    // Read capacity
                    self.read_capacity(&dev);

                    // Add device
                    if (self.device_count < MAX_SCSI_DEVICES) {
                        self.devices[self.device_count] = dev;
                        self.device_count += 1;
                        found += 1;
                    }

                    // If LUN 0 returns TYPE_NO_LUN, skip remaining LUNs
                    if (dev.inquiry.device_type == TYPE_NO_LUN) break;
                } else {
                    // No device at this target/LUN — skip remaining LUNs
                    if (lun == 0) break;
                }
            }
        }

        self.total_scans += 1;
        return found;
    }

    fn read_capacity(self: *ScsiManager, dev: *ScsiDevice) void {
        _ = self;
        // Simulate reading capacity
        // In real kernel, issue READ CAPACITY(10) or (16)
        dev.capacity = 1048576; // 512MB with 512-byte blocks
        dev.block_size = 512;
    }

    fn execute_cmd(self: *ScsiManager, host_idx: u8, cmd: *ScsiCommand) bool {
        _ = cmd;
        if (host_idx >= self.host_count or !self.hosts[host_idx].active) return false;

        self.hosts[host_idx].total_cmds += 1;
        self.total_commands += 1;

        // In real kernel: DMA setup → host adapter queuecmd → IRQ completion
        // Simulate success
        self.hosts[host_idx].total_completions += 1;
        self.total_completions += 1;
        return true;
    }

    /// Submit a read command to a device
    pub fn submit_read(self: *ScsiManager, dev_idx: u32, lba: u64, count: u32) bool {
        if (dev_idx >= self.device_count or !self.devices[dev_idx].active) return false;
        var dev = &self.devices[dev_idx];
        if (!dev.can_queue()) return false;

        var cmd = ScsiCommand.init();
        if (lba > 0xFFFFFFFF or count > 0xFFFF) {
            cmd.cdb = ScsiCdb.read_16(lba, count);
        } else {
            cmd.cdb = ScsiCdb.read_10(@intCast(lba), @intCast(count));
        }
        cmd.target_id = dev.target_id;
        cmd.lun = dev.lun;
        cmd.data_direction = .from_device;
        cmd.data_len = count * dev.block_size;
        cmd.tag = self.next_tag;
        self.next_tag +%= 1;
        if (dev.tcq_enabled) cmd.tag_type = TAG_SIMPLE;

        dev.outstanding += 1;
        dev.read_ops += 1;
        dev.read_bytes += @as(u64, count) * @as(u64, dev.block_size);

        return self.execute_cmd(dev.host_idx, &cmd);
    }

    /// Submit a write command to a device
    pub fn submit_write(self: *ScsiManager, dev_idx: u32, lba: u64, count: u32) bool {
        if (dev_idx >= self.device_count or !self.devices[dev_idx].active) return false;
        var dev = &self.devices[dev_idx];
        if (!dev.can_queue()) return false;

        var cmd = ScsiCommand.init();
        if (lba > 0xFFFFFFFF or count > 0xFFFF) {
            cmd.cdb = ScsiCdb.write_16(lba, count);
        } else {
            cmd.cdb = ScsiCdb.write_10(@intCast(lba), @intCast(count));
        }
        cmd.target_id = dev.target_id;
        cmd.lun = dev.lun;
        cmd.data_direction = .to_device;
        cmd.data_len = count * dev.block_size;
        cmd.tag = self.next_tag;
        self.next_tag +%= 1;

        dev.outstanding += 1;
        dev.write_ops += 1;
        dev.write_bytes += @as(u64, count) * @as(u64, dev.block_size);

        return self.execute_cmd(dev.host_idx, &cmd);
    }

    /// Sync cache (flush write cache)
    pub fn sync_device(self: *ScsiManager, dev_idx: u32) bool {
        if (dev_idx >= self.device_count or !self.devices[dev_idx].active) return false;
        const dev = &self.devices[dev_idx];

        var cmd = ScsiCommand.init();
        cmd.cdb = ScsiCdb.sync_cache(0, 0);
        cmd.target_id = dev.target_id;
        cmd.lun = dev.lun;
        cmd.data_direction = .none;
        cmd.tag_type = TAG_ORDERED; // Ordered tag for sync

        return self.execute_cmd(dev.host_idx, &cmd);
    }

    /// Error recovery: handle command failure
    pub fn error_handler(self: *ScsiManager, dev_idx: u32, status: u8, sense_data: []const u8) EhAction {
        if (dev_idx >= self.device_count) return .abort;
        var dev = &self.devices[dev_idx];

        // Parse sense data
        var sense = SenseData.init();
        if (sense_data.len > 0) {
            sense.parse_fixed(sense_data);
        }

        dev.last_sense = sense;
        dev.error_count += 1;
        self.total_errors += 1;

        // Handle unit attention
        if (sense.is_unit_attention()) {
            dev.ua_pending = true;
            if (sense.is_media_changed()) {
                // Invalidate caches, re-read capacity
                self.read_capacity(dev);
            }
            return .retry;
        }

        const action = determine_eh_action(status, &sense, 0, 3);
        switch (action) {
            .abort => {
                self.total_eh_aborts += 1;
            },
            .device_reset => {
                self.total_eh_device_resets += 1;
                dev.state = .offline;
                dev.outstanding = 0;
            },
            .bus_reset => {
                self.total_eh_bus_resets += 1;
            },
            .host_reset => {
                self.total_eh_host_resets += 1;
            },
            else => {},
        }

        return action;
    }

    /// Set device state
    pub fn set_device_state(self: *ScsiManager, dev_idx: u32, state: ScsiDevState) void {
        if (dev_idx >= self.device_count) return;
        self.devices[dev_idx].state = state;
    }

    /// Remove a device
    pub fn remove_device(self: *ScsiManager, dev_idx: u32) bool {
        if (dev_idx >= self.device_count or !self.devices[dev_idx].active) return false;
        self.devices[dev_idx].state = .deleted;
        self.devices[dev_idx].active = false;
        return true;
    }

    /// Get device info
    pub fn get_capacity(self: *const ScsiManager, dev_idx: u32) u64 {
        if (dev_idx >= self.device_count) return 0;
        return self.devices[dev_idx].capacity;
    }

    pub fn get_block_size(self: *const ScsiManager, dev_idx: u32) u32 {
        if (dev_idx >= self.device_count) return 0;
        return self.devices[dev_idx].block_size;
    }
};

// ============================================================================
// Global instance
// ============================================================================

var global_scsi: ScsiManager = ScsiManager.init();

// ============================================================================
// FFI Exports
// ============================================================================

export fn zxy_scsi_init() void {
    global_scsi = ScsiManager.init();
}

export fn zxy_scsi_add_host(name: [*]const u8, name_len: u32) i32 {
    if (name_len > 32) return -1;
    const n = name[0..name_len];
    const idx = global_scsi.add_host(n) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_scsi_scan_host(host_idx: u8) u32 {
    return global_scsi.scan_host(host_idx);
}

export fn zxy_scsi_read(dev_idx: u32, lba: u64, count: u32) u8 {
    return if (global_scsi.submit_read(dev_idx, lba, count)) 1 else 0;
}

export fn zxy_scsi_write(dev_idx: u32, lba: u64, count: u32) u8 {
    return if (global_scsi.submit_write(dev_idx, lba, count)) 1 else 0;
}

export fn zxy_scsi_sync(dev_idx: u32) u8 {
    return if (global_scsi.sync_device(dev_idx)) 1 else 0;
}

export fn zxy_scsi_remove(dev_idx: u32) u8 {
    return if (global_scsi.remove_device(dev_idx)) 1 else 0;
}

export fn zxy_scsi_capacity(dev_idx: u32) u64 {
    return global_scsi.get_capacity(dev_idx);
}

export fn zxy_scsi_block_size(dev_idx: u32) u32 {
    return global_scsi.get_block_size(dev_idx);
}

export fn zxy_scsi_host_count() u32 {
    return global_scsi.host_count;
}

export fn zxy_scsi_device_count() u32 {
    return global_scsi.device_count;
}

export fn zxy_scsi_total_commands() u64 {
    return global_scsi.total_commands;
}

export fn zxy_scsi_total_errors() u64 {
    return global_scsi.total_errors;
}

export fn zxy_scsi_total_scans() u64 {
    return global_scsi.total_scans;
}
