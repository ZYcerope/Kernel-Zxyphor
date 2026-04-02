// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - NVMe Admin Command Set & IO Command Set Detail
// Complete NVMe submission/completion queues, admin commands,
// Identify structures, namespace management, NVMe-oF/TCP,
// Multi-path, ZNS (Zoned Namespaces), KV commands

const std = @import("std");

// ============================================================================
// NVMe Command Format
// ============================================================================

pub const NvmeCommand = packed struct {
    opcode: u8,
    flags: u8,
    command_id: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
};

pub const NvmeCompletion = packed struct {
    result: u64,          // Command-specific result
    sq_head: u16,
    sq_id: u16,
    command_id: u16,
    status: u16,          // Phase bit + status field
};

// ============================================================================
// NVMe Admin Opcodes
// ============================================================================

pub const NvmeAdminOpcode = enum(u8) {
    DeleteIoSq = 0x00,
    CreateIoSq = 0x01,
    GetLogPage = 0x02,
    DeleteIoCq = 0x04,
    CreateIoCq = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventRequest = 0x0C,
    NsManagement = 0x0D,
    FirmwareCommit = 0x10,
    FirmwareDownload = 0x11,
    DeviceSelfTest = 0x14,
    NsAttachment = 0x15,
    KeepAlive = 0x18,
    DirectiveSend = 0x19,
    DirectiveReceive = 0x1A,
    VirtualMgmt = 0x1C,
    NvmeMiSend = 0x1D,
    NvmeMiReceive = 0x1E,
    DbbufConfig = 0x7C,
    FabricsCommand = 0x7F,
    FormatNvm = 0x80,
    SecuritySend = 0x81,
    SecurityReceive = 0x82,
    Sanitize = 0x84,
    GetLbaStatus = 0x86,
};

// ============================================================================
// NVMe I/O Opcodes
// ============================================================================

pub const NvmeIoOpcode = enum(u8) {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteUncorrectable = 0x04,
    Compare = 0x05,
    WriteZeroes = 0x08,
    DatasetManagement = 0x09,
    Verify = 0x0C,
    ReservationRegister = 0x0D,
    ReservationReport = 0x0E,
    ReservationAcquire = 0x11,
    ReservationRelease = 0x15,
    Copy = 0x19,
    // ZNS commands
    ZoneManagementSend = 0x79,
    ZoneManagementReceive = 0x7A,
    ZoneAppend = 0x7D,
};

// ============================================================================
// NVMe Status Codes
// ============================================================================

pub const NvmeStatusType = enum(u3) {
    Generic = 0,
    CommandSpecific = 1,
    MediaError = 2,
    Path = 3,
    VendorSpecific = 7,
};

pub const NvmeGenericStatus = enum(u8) {
    Success = 0x00,
    InvalidOpcode = 0x01,
    InvalidField = 0x02,
    CommandIdConflict = 0x03,
    DataTransferError = 0x04,
    PowerLoss = 0x05,
    InternalError = 0x06,
    AbortRequested = 0x07,
    AbortSqDeleted = 0x08,
    AbortFailedFuse = 0x09,
    AbortMissing = 0x0A,
    InvalidNamespace = 0x0B,
    CommandSeqError = 0x0C,
    InvalidSglSegDescriptor = 0x0D,
    InvalidSglDescriptorCount = 0x0E,
    DataSglLengthInvalid = 0x0F,
    MetadataSglLengthInvalid = 0x10,
    SglDescriptorTypeInvalid = 0x11,
    InvalidCmbUse = 0x12,
    InvalidPrpOffset = 0x13,
    AtomicWriteUnitExceeded = 0x14,
    OperationDenied = 0x15,
    SglOffsetInvalid = 0x16,
    HostIdentifierInconsistent = 0x18,
    KeepAliveExpired = 0x19,
    KeepAliveInvalid = 0x1A,
    CommandAbortedPreempt = 0x1B,
    SanitizeFailed = 0x1C,
    SanitizeInProgress = 0x1D,
    SglBlockGranularity = 0x1E,
    NsWriteProtected = 0x20,
    CommandInterrupted = 0x21,
    TransientTransportError = 0x22,
    LbaOutOfRange = 0x80,
    CapacityExceeded = 0x81,
    NamespaceNotReady = 0x82,
    ReservationConflict = 0x83,
    FormatInProgress = 0x84,
};

// ============================================================================
// Identify Structures
// ============================================================================

pub const NvmeIdCtrl = struct {
    vid: u16,             // PCI Vendor ID
    ssvid: u16,           // Subsystem Vendor ID
    sn: [20]u8,           // Serial Number
    mn: [40]u8,           // Model Number
    fr: [8]u8,            // Firmware Revision
    rab: u8,              // Recommended Arbitration Burst
    ieee: [3]u8,          // IEEE OUI
    cmic: u8,             // Controller Multi-Path
    mdts: u8,             // Maximum Data Transfer Size
    cntlid: u16,          // Controller ID
    ver: u32,             // Version
    rtd3r: u32,           // RTD3 Resume Latency
    rtd3e: u32,           // RTD3 Entry Latency
    oaes: u32,            // Optional Async Events Supported
    ctratt: u32,          // Controller Attributes
    rrls: u16,            // Read Recovery Levels Supported
    cntrltype: u8,        // Controller Type
    fguid: [16]u8,        // FRU GUID
    crdt1: u16,           // Command Retry Delay Time 1
    crdt2: u16,           // Command Retry Delay Time 2
    crdt3: u16,           // Command Retry Delay Time 3
    _reserved: [106]u8,
    // Admin cmd set attrs
    oacs: u16,            // Optional Admin Command Support
    acl: u8,              // Abort Command Limit
    aerl: u8,             // Async Event Request Limit
    frmw: u8,             // Firmware Updates
    lpa: u8,              // Log Page Attributes
    elpe: u8,             // Error Log Page Entries
    npss: u8,             // Number of Power States
    avscc: u8,            // Admin Vendor Specific Cmd Config
    apsta: u8,            // Autonomous Power State Trans
    wctemp: u16,          // Warning Composite Temp Threshold
    cctemp: u16,          // Critical Composite Temp Threshold
    mtfa: u16,            // Maximum Time for FW Activation
    hmpre: u32,           // Host Memory Buffer Preferred Size
    hmmin: u32,           // Host Memory Buffer Min Size
    tnvmcap: [16]u8,      // Total NVM Capacity (128-bit)
    unvmcap: [16]u8,      // Unallocated NVM Capacity
    rpmbs: u32,           // Replay Protected Memory Block
    edstt: u16,           // Extended Device Self-test Time
    dsto: u8,             // Device Self-test Options
    fwug: u8,             // Firmware Update Granularity
    kas: u16,             // Keep Alive Support
    hctma: u16,           // Host Controlled Thermal Mgmt Attrs
    mntmt: u16,           // Min Thermal Management Temperature
    mxtmt: u16,           // Max Thermal Management Temperature
    sanicap: u32,         // Sanitize Capabilities
    hmminds: u32,         // HMB Min Descriptor Entry Size
    hmmaxd: u16,          // HMB Max Descriptor Entries
    nsetidmax: u16,       // Max NVM Set Identifier
    endgidmax: u16,       // Max Endurance Group Identifier
    anatt: u8,            // ANA Transition Time
    anacap: u8,           // Asymmetric Namespace Access Caps
    anagrpmax: u32,       // ANA Group Identifier Max
    nanagrpid: u32,       // Number of ANA Group Identifiers
    pels: u32,            // Persistent Event Log Size
    // NVM cmd set attributes
    sqes: u8,             // Submission Queue Entry Size
    cqes: u8,             // Completion Queue Entry Size
    maxcmd: u16,          // Max Outstanding Commands
    nn: u32,              // Number of Namespaces
    oncs: u16,            // Optional NVM Command Support
    fuses: u16,           // Fused Operation Support
    fna: u8,              // Format NVM Attributes
    vwc: u8,              // Volatile Write Cache
    awun: u16,            // Atomic Write Unit Normal
    awupf: u16,           // Atomic Write Unit Power Fail
    icsvscc: u8,          // I/O Cmd Set Vendor Specific Cmd Config
    nwpc: u8,             // Namespace Write Protection Caps
    acwu: u16,            // Atomic Compare & Write Unit
    ocfs: u16,            // Optional Copy Formats Supported
    sgls: u32,            // SGL Support
    mnan: u32,            // Maximum Number of Allowed Namespaces
};

pub const NvmeIdNs = struct {
    nsze: u64,            // Namespace Size (blocks)
    ncap: u64,            // Namespace Capacity
    nuse: u64,            // Namespace Utilization
    nsfeat: u8,           // Namespace Features
    nlbaf: u8,            // Number of LBA Formats
    flbas: u8,            // Formatted LBA Size
    mc: u8,               // Metadata Capabilities
    dpc: u8,              // End-to-end Data Protection
    dps: u8,              // Data Protection Settings
    nmic: u8,             // Namespace Multi-path I/O
    rescap: u8,           // Reservation Capabilities
    fpi: u8,              // Format Progress Indicator
    dlfeat: u8,           // Deallocate Logical Block Features
    nawun: u16,           // Namespace Atomic Write Unit Normal
    nawupf: u16,          // Namespace Atomic Write Unit Power Fail
    nacwu: u16,           // Namespace Atomic Compare & Write Unit
    nabsn: u16,           // Namespace Atomic Boundary Size Normal
    nabo: u16,            // Namespace Atomic Boundary Offset
    nabspf: u16,          // Namespace Atomic Boundary Size PF
    noiob: u16,           // Namespace Optimal I/O Boundary
    nvmcap: [16]u8,       // NVM Capacity (128-bit)
    npwg: u16,            // Namespace Preferred Write Granularity
    npwa: u16,            // Namespace Preferred Write Alignment
    npdg: u16,            // Namespace Preferred Deallocate Granularity
    npda: u16,            // Namespace Preferred Deallocate Alignment
    nows: u16,            // Namespace Optimal Write Size
    mssrl: u16,           // Max Single Source Range Length
    mcl: u32,             // Max Copy Length
    msrc: u8,             // Max Source Range Count
    _reserved: [11]u8,
    anagrpid: u32,        // ANA Group Identifier
    nsattr: u8,           // Namespace Attributes
    nvmsetid: u16,        // NVM Set Identifier
    endgid: u16,          // Endurance Group Identifier
    nguid: [16]u8,        // Namespace GUID
    eui64: [8]u8,         // IEEE Extended Unique Identifier
    lbaf: [64]NvmeLbaFormat,
};

pub const NvmeLbaFormat = packed struct(u32) {
    ms: u16,              // Metadata Size
    lbads: u8,            // LBA Data Size (power of 2)
    rp: u2,               // Relative Performance
    _reserved: u6,
};

// ============================================================================
// ZNS (Zoned Namespaces)
// ============================================================================

pub const NvmeZoneState = enum(u4) {
    Empty = 0x1,
    ImplicitlyOpened = 0x2,
    ExplicitlyOpened = 0x3,
    Closed = 0x4,
    ReadOnly = 0xD,
    Full = 0xE,
    Offline = 0xF,
};

pub const NvmeZoneType = enum(u8) {
    SeqWriteRequired = 0x2,
};

pub const NvmeZoneDescriptor = struct {
    zone_type: NvmeZoneType,
    zone_state: u8,       // Upper 4 bits = NvmeZoneState
    zone_attrs: u8,
    _reserved: [5]u8,
    zone_cap: u64,        // Zone Capacity (LBAs)
    zone_start_lba: u64,
    write_pointer: u64,
    _reserved2: [32]u8,
};

pub const NvmeZmsSendAction = enum(u8) {
    Close = 0x01,
    Finish = 0x02,
    Open = 0x03,
    Reset = 0x04,
    Offline = 0x05,
    SetZde = 0x10,
};

pub const NvmeZnsIdNs = struct {
    zoc: u16,             // Zone Operation Characteristics
    ozcs: u16,            // Optional Zoned Command Support
    mar: u32,             // Max Active Resources
    mor: u32,             // Max Open Resources
    rrl: u32,             // Reset Recommended Limit
    frl: u32,             // Finish Recommended Limit
    rrl1: u32,
    rrl2: u32,
    rrl3: u32,
    frl1: u32,
    frl2: u32,
    frl3: u32,
    numzrwa: u32,         // Num Zone Random Write Area Resources
    zrwafg: u16,          // ZRWA Flush Granularity
    zrwas: u16,           // ZRWA Size
    zrwacap: u8,          // ZRWA Capability
};

// ============================================================================
// NVMe-oF (Fabrics)
// ============================================================================

pub const NvmeFabricsOpcode = enum(u8) {
    PropertySet = 0x00,
    Connect = 0x01,
    PropertyGet = 0x04,
    AuthenticationSend = 0x05,
    AuthenticationReceive = 0x06,
    Disconnect = 0x08,
};

pub const NvmeFabricsTransport = enum(u8) {
    Rdma = 1,
    FibreChannel = 2,
    Tcp = 3,
    Loop = 254,
};

pub const NvmeofConnectData = struct {
    hostid: [16]u8,
    cntlid: u16,
    _reserved: [238]u8,
    subnqn: [256]u8,
    hostnqn: [256]u8,
};

pub const NVMeTcpPduType = enum(u8) {
    IcReq = 0x00,
    IcResp = 0x01,
    H2cTerm = 0x02,
    C2hTerm = 0x03,
    CapsuleCmd = 0x04,
    CapsuleResp = 0x05,
    H2cData = 0x06,
    C2hData = 0x07,
    R2t = 0x09,
};

// ============================================================================
// NVMe Multipath
// ============================================================================

pub const NvmeAnaState = enum(u8) {
    Optimized = 0x01,
    NonOptimized = 0x02,
    Inaccessible = 0x03,
    PersistentLoss = 0x04,
    Change = 0x0F,
};

pub const NvmeMultipathPolicy = enum(u8) {
    NumaRoundRobin = 0,
    RoundRobin = 1,
    QueueDepth = 2,
};

// ============================================================================
// NVMe Manager
// ============================================================================

pub const NvmeManager = struct {
    total_controllers: u32,
    total_namespaces: u32,
    total_queues: u32,
    total_admin_cmds: u64,
    total_io_cmds: u64,
    total_read_bytes: u64,
    total_write_bytes: u64,
    total_errors: u64,
    total_timeouts: u64,
    total_resets: u64,
    total_zones: u32,
    total_zone_appends: u64,
    total_fabrics_connections: u32,
    multipath_policy: NvmeMultipathPolicy,
    initialized: bool,

    pub fn init() NvmeManager {
        return .{
            .total_controllers = 0,
            .total_namespaces = 0,
            .total_queues = 0,
            .total_admin_cmds = 0,
            .total_io_cmds = 0,
            .total_read_bytes = 0,
            .total_write_bytes = 0,
            .total_errors = 0,
            .total_timeouts = 0,
            .total_resets = 0,
            .total_zones = 0,
            .total_zone_appends = 0,
            .total_fabrics_connections = 0,
            .multipath_policy = .NumaRoundRobin,
            .initialized = true,
        };
    }
};
