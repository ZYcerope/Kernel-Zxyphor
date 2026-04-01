// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - SCSI Host Adapter / Transport Detail
// HBA internals, transport classes, error handling, SCSI EH, device model,
// target/LUN management, command queuing, SAM status codes

const std = @import("std");

// ============================================================================
// SAM Status Codes
// ============================================================================

pub const ScsiStatus = enum(u8) {
    Good = 0x00,
    CheckCondition = 0x02,
    ConditionMet = 0x04,
    Busy = 0x08,
    Intermediate = 0x10,            // obsolete
    IntermediateCondMet = 0x14,     // obsolete
    ReservationConflict = 0x18,
    CommandTerminated = 0x22,       // obsolete
    TaskSetFull = 0x28,
    AcaActive = 0x30,
    TaskAborted = 0x40,
};

pub const ScsiHostStatus = enum(u16) {
    Ok = 0x0000,
    NoConnect = 0x0001,
    BusFree = 0x0002,
    TimeOut = 0x0003,
    BadTarget = 0x0004,
    Abort = 0x0005,
    Parity = 0x0006,
    Error = 0x0007,
    Reset = 0x0008,
    BadIntr = 0x0009,
    PassThrough = 0x000a,
    SoftError = 0x000b,
    ImRetry = 0x000c,
    ResetTarget = 0x000d,
    TransportReset = 0x000e,
    TransportDisrupted = 0x000f,
    TransportFailFast = 0x0010,
    TargetFailFast = 0x0011,
    NexusFailFast = 0x0012,
    Dma = 0x0070,
};

pub const ScsiResult = packed struct(u32) {
    status: u8,       // SAM status
    msg: u8,          // message byte
    host: u8,         // host status
    driver: u8,       // driver status (legacy)
};

// ============================================================================
// Sense Data
// ============================================================================

pub const SenseKey = enum(u4) {
    NoSense = 0x0,
    RecoveredError = 0x1,
    NotReady = 0x2,
    MediumError = 0x3,
    HardwareError = 0x4,
    IllegalRequest = 0x5,
    UnitAttention = 0x6,
    DataProtect = 0x7,
    BlankCheck = 0x8,
    VendorSpecific = 0x9,
    CopyAborted = 0xa,
    AbortedCommand = 0xb,
    Reserved1 = 0xc,
    VolumeOverflow = 0xd,
    Miscompare = 0xe,
    Completed = 0xf,
};

pub const SenseData = struct {
    response_code: u8,     // 0x70 (fixed) or 0x72 (descriptor)
    sense_key: SenseKey,
    asc: u8,               // Additional Sense Code
    ascq: u8,              // Additional Sense Code Qualifier
    additional_length: u8,
    field_pointer: u16,
    info: u32,
    cmd_specific_info: u32,
    // Descriptor format extras
    descriptors: [64]u8,
    descriptor_len: u8,
};

// ============================================================================
// SCSI Command Descriptor Block
// ============================================================================

pub const MAX_CDB_SIZE: u32 = 32;
pub const MAX_SENSE_SIZE: u32 = 96;

pub const ScsiOpcode = enum(u8) {
    TestUnitReady = 0x00,
    RequestSense = 0x03,
    Read6 = 0x08,
    Write6 = 0x0a,
    Inquiry = 0x12,
    ModeSelect6 = 0x15,
    ModeSense6 = 0x1a,
    StartStop = 0x1b,
    SendDiagnostic = 0x1d,
    ReadCapacity10 = 0x25,
    Read10 = 0x28,
    Write10 = 0x2a,
    Verify10 = 0x2f,
    SynchronizeCache10 = 0x35,
    WriteBuffer = 0x3b,
    ReadBuffer = 0x3c,
    ReadToc = 0x43,
    LogSense = 0x4d,
    ModeSelect10 = 0x55,
    ModeSense10 = 0x5a,
    PersistentReserveIn = 0x5e,
    PersistentReserveOut = 0x5f,
    Read16 = 0x88,
    CompareAndWrite = 0x89,
    Write16 = 0x8a,
    Verify16 = 0x8f,
    SynchronizeCache16 = 0x91,
    WriteSame16 = 0x93,
    ServiceActionIn16 = 0x9e,
    ServiceActionOut16 = 0x9f,
    ReadCapacity16 = 0x9e,  // SAI
    ReportLuns = 0xa0,
    SecurityProtocolIn = 0xa2,
    MaintenanceIn = 0xa3,
    MaintenanceOut = 0xa4,
    Read12 = 0xa8,
    Write12 = 0xaa,
    SecurityProtocolOut = 0xb5,
    Unmap = 0x42,
    WriteSame10 = 0x41,
    AtaPassThrough16 = 0x85,
    AtaPassThrough12 = 0xa1,
};

pub const ScsiCmnd = struct {
    // Command
    cdb: [MAX_CDB_SIZE]u8,
    cdb_len: u8,

    // Transfer
    data_direction: DataDirection,
    transfer_len: u32,
    sg_list: u64,            // scatterlist *
    sg_count: u32,

    // Device
    device: u64,             // scsi_device *
    host: u64,               // Scsi_Host *
    target: u64,             // scsi_target *
    lun: u64,

    // Result
    result: ScsiResult,
    sense_buffer: [MAX_SENSE_SIZE]u8,
    sense_len: u8,

    // Timeout
    timeout: u32,            // seconds
    retries: u32,
    allowed: u32,

    // Flags
    flags: ScsiCmndFlags,

    // Timing
    submit_time: u64,
    complete_time: u64,

    // Tag
    tag: u32,
    budget_token: u32,

    // Completion
    scsi_done: u64,          // callback fn
};

pub const DataDirection = enum(u8) {
    None = 0,
    ToDevice = 1,    // write
    FromDevice = 2,  // read
    Bidirectional = 3,
};

pub const ScsiCmndFlags = packed struct(u32) {
    tagged: bool = false,
    untagged: bool = false,
    internal: bool = false,
    was_reset: bool = false,
    is_eh: bool = false,
    is_passthrough: bool = false,
    no_sg_merge: bool = false,
    _pad: u25 = 0,
};

// ============================================================================
// SCSI Device
// ============================================================================

pub const ScsiDeviceType = enum(u8) {
    Disk = 0x00,
    Tape = 0x01,
    Printer = 0x02,
    Processor = 0x03,
    Worm = 0x04,
    CdRom = 0x05,
    Scanner = 0x06,
    OptMem = 0x07,
    Changer = 0x08,
    Comm = 0x09,
    Raid = 0x0c,
    Enclosure = 0x0d,
    Rbc = 0x0e,
    Osd = 0x11,
    Zbc = 0x14,
    NoLun = 0x7f,
};

pub const ScsiDevice = struct {
    host: u64,               // Scsi_Host *
    target: u64,             // scsi_target *
    request_queue: u64,      // request_queue *

    // Identification
    vendor: [8]u8,
    model: [16]u8,
    rev: [4]u8,
    device_type: ScsiDeviceType,
    scsi_level: u8,          // SPC version
    lun: u64,
    channel: u32,
    id: u32,

    // Capabilities
    removable: bool,
    changed: bool,
    busy: bool,
    lockable: bool,
    tagged_supported: bool,
    ordered_tags: bool,
    simple_tags: bool,
    was_reset: bool,
    expecting_cc_ua: bool,
    skip_ms_page_3f: bool,
    skip_ms_page_8: bool,
    skip_vpd_pages: bool,
    try_rc_10_first: bool,
    use_10_for_rw: bool,
    use_10_for_ms: bool,
    use_192_bytes_for_3f: bool,

    // Protection (DIF/DIX)
    protection_type: u8,     // T10-PI type
    guard_type: u8,          // CRC (1) or IP checksum (0)

    // Queue parameters
    queue_depth: u32,
    max_queue_depth: u32,
    max_device_blocked: u32,
    device_blocked: u32,

    // Power management
    power_state: ScsiPowerState,

    // Runtime PM
    rpm_autosuspend: bool,
    manage_start_stop: bool,
    manage_runtime_idle: bool,
    manage_system_start_stop: bool,
    manage_shutdown: bool,

    // Error recovery
    eh_timeout: u32,
    timeout: u32,

    // Block size
    sector_size: u32,
    max_xfer_blocks: u32,
    max_hw_sectors: u32,

    // SCSI inquiry
    inquiry: [256]u8,
    inquiry_len: u8,

    // VPD pages
    vpd_pg80: [255]u8,      // Unit Serial Number
    vpd_pg80_len: u8,
    vpd_pg83: [255]u8,      // Device Identification
    vpd_pg83_len: u8,
    vpd_pg89: [255]u8,      // ATA Information
    vpd_pg89_len: u8,
    vpd_pgb0: [64]u8,       // Block Limits
    vpd_pgb0_len: u8,
    vpd_pgb1: [64]u8,       // Block Characteristics
    vpd_pgb1_len: u8,
    vpd_pgb2: [64]u8,       // Logical Block Provisioning
    vpd_pgb2_len: u8,

    // Stats
    iodone_cnt: u64,
    ioerr_cnt: u64,
    iorequest_cnt: u64,
};

pub const ScsiPowerState = enum(u8) {
    Active = 0,
    Idle = 1,
    Standby = 2,
    Stopped = 3,
    Transitioning = 4,
};

// ============================================================================
// SCSI Host (HBA)
// ============================================================================

pub const ScsiHost = struct {
    // Host template
    hostt: u64,              // scsi_host_template *
    transportt: u64,         // scsi_transport_template *

    // Identity
    host_no: u32,
    max_id: u32,
    max_lun: u64,
    max_channel: u32,
    this_id: i32,            // -1 if not set
    unique_id: u32,

    // Queuing parameters
    can_queue: u32,          // total commands host can accept
    cmd_per_lun: u32,
    sg_tablesize: u32,       // max scatter-gather entries
    max_sectors: u32,
    max_segment_size: u32,
    max_cmd_len: u8,

    // DMA
    dma_boundary: u64,
    dma_alignment: u32,
    virt_boundary_mask: u64,

    // Tag set for blk-mq
    tag_set: u64,            // blk_mq_tag_set *

    // Host state
    host_busy: u32,
    host_failed: u32,
    host_eh_scheduled: u32,
    host_blocked: u32,
    max_host_blocked: u32,

    // Error handling
    eh_action: u64,          // completion *
    eh_active: bool,

    // Flags
    active_mode: ScsiHostMode,
    unchecked_isa_dma: bool,
    no_write_same: bool,
    short_inquiry: bool,
    no_scsi2_lun_in_cdb: bool,
    host_self_blocked: bool,
    reverse_ordering: bool,
    ordered_tag: bool,

    // Capabilities
    prot_capabilities: ProtMask,
    prot_guard_type: u8,

    // SCSI-ML host lock
    host_lock: u64,

    // Statistics
    total_cmds: u64,
    total_bytes: u64,
    total_errors: u64,
    total_timeouts: u64,
    total_resets: u64,
};

pub const ScsiHostMode = packed struct(u32) {
    initiator: bool = true,
    target: bool = false,
    _pad: u30 = 0,
};

pub const ProtMask = packed struct(u32) {
    dif_type1: bool = false,
    dif_type2: bool = false,
    dif_type3: bool = false,
    dix_type0: bool = false,
    dix_type1: bool = false,
    dix_type2: bool = false,
    dix_type3: bool = false,
    _pad: u25 = 0,
};

// ============================================================================
// SCSI Transport Classes
// ============================================================================

pub const ScsiTransportType = enum(u8) {
    Spi = 0,     // Parallel SCSI
    Fc = 1,      // Fibre Channel
    Iscsi = 2,   // iSCSI
    Sas = 3,     // SAS
    Srp = 4,     // SCSI RDMA Protocol
    UsbStorage = 5,
    Ata = 6,
};

pub const FcPortState = enum(u8) {
    Unknown = 0,
    NotPresent = 1,
    Online = 2,
    Offline = 3,
    Blocked = 4,
    Bypassed = 5,
    Diagnostics = 6,
    Linkdown = 7,
    Error = 8,
    Loopback = 9,
    Deleted = 10,
    Marginal = 11,
};

pub const FcRport = struct {
    dev_loss_tmo: u32,
    port_name: u64,
    node_name: u64,
    port_id: u32,
    roles: FcPortRoles,
    port_state: FcPortState,
    maxframe_size: u32,
    supported_classes: u32,
    dd_data: u64,            // driver private data
};

pub const FcPortRoles = packed struct(u32) {
    fcp_target: bool = false,
    fcp_initiator: bool = false,
    ip_port: bool = false,
    fcp_dummy_initiator: bool = false,
    nvme_target: bool = false,
    nvme_initiator: bool = false,
    nvme_discovery: bool = false,
    _pad: u25 = 0,
};

pub const SasEndDevice = struct {
    ready_led_meaning: bool,
    i_t_nexus_loss_timeout: u32,
    initiator_response_timeout: u32,
    tlr_supported: bool,
    tlr_enabled: bool,
};

// ============================================================================
// SCSI Error Handling (EH)
// ============================================================================

pub const EhAction = enum(u8) {
    AbortCmd = 0,
    DeviceReset = 1,
    TargetReset = 2,
    BusReset = 3,
    HostReset = 4,
};

pub const EhResult = enum(u8) {
    Success = 0,
    NeedRetry = 1,
    Failed = 2,
    NotHandled = 3,
};

pub const EhState = enum(u8) {
    Idle = 0,
    Abort = 1,
    DeviceReset = 2,
    TargetReset = 3,
    BusReset = 4,
    HostReset = 5,
    Offline = 6,
};

pub const ScsiEhStats = struct {
    abort_count: u64,
    abort_success: u64,
    device_reset_count: u64,
    device_reset_success: u64,
    target_reset_count: u64,
    target_reset_success: u64,
    bus_reset_count: u64,
    bus_reset_success: u64,
    host_reset_count: u64,
    host_reset_success: u64,
    total_eh_runs: u64,
    total_timeouts: u64,
    total_recovered: u64,
    total_failed: u64,
};

// ============================================================================
// SCSI Host Template callbacks
// ============================================================================

pub const ScsiHostTemplate = struct {
    name: [64]u8,
    proc_name: [32]u8,
    module: u64,

    // Command handling
    queuecommand: u64,       // fn(host, cmnd) -> int
    eh_abort_handler: u64,
    eh_device_reset_handler: u64,
    eh_target_reset_handler: u64,
    eh_bus_reset_handler: u64,
    eh_host_reset_handler: u64,

    // Slave (device) configure
    slave_alloc: u64,
    slave_configure: u64,
    slave_destroy: u64,
    target_alloc: u64,
    target_destroy: u64,

    // Scanning
    scan_finished: u64,
    scan_start: u64,

    // Change queue depth
    change_queue_depth: u64,

    // IOCTL
    ioctl: u64,

    // Host initialization
    host_alloc: u64,
    host_init: u64,
    host_reset: u64,

    // Properties
    can_queue: u32,
    this_id: i32,
    sg_tablesize: u32,
    max_sectors: u32,
    max_segment_size: u32,
    cmd_per_lun: u32,
    tag_alloc_policy: TagPolicy,

    // Flags
    emulated: bool,
    skip_settle_delay: bool,
    no_write_same: bool,
    no_async_abort: bool,
    track_queue_depth: bool,
};

pub const TagPolicy = enum(u8) {
    FifoTag = 0,
    RoundRobinTag = 1,
};

// ============================================================================
// SCSI Subsystem Manager
// ============================================================================

pub const ScsiSubsystemManager = struct {
    total_hosts: u32,
    total_targets: u32,
    total_devices: u32,
    total_commands: u64,
    total_bytes_transferred: u64,
    eh_stats: ScsiEhStats,
    initialized: bool,

    pub fn init() ScsiSubsystemManager {
        return .{
            .total_hosts = 0,
            .total_targets = 0,
            .total_devices = 0,
            .total_commands = 0,
            .total_bytes_transferred = 0,
            .eh_stats = std.mem.zeroes(ScsiEhStats),
            .initialized = true,
        };
    }
};
