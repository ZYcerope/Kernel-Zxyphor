// Zxyphor Kernel - NVMe Driver Internals (Zig),
// NVMe Command Set, Submission/Completion Queues,
// Namespace Management, NVMe-oF (over Fabrics),
// ZNS (Zoned Namespace), KV Command Set,
// NVMe Power Management, NVMe Multipath
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// NVMe Controller Registers (BAR0)
// ============================================================================

pub const NvmeCapabilities = packed struct(u64) {
    mqes: u16,          // Max Queue Entries Supported (0-based)
    cqr: bool,         // Contiguous Queues Required
    ams_weighted_rr: bool,
    ams_vendor: bool,
    _reserved1: u5,
    timeout: u8,        // Worst case time in 500ms units
    dstrd: u4,          // Doorbell Stride (2^(2+DSTRD) bytes)
    nssrs: bool,        // NVM Subsystem Reset Supported
    css_nvm: bool,      // NVM Command Set
    css_io: bool,       // I/O Command Set
    css_no_io: bool,    // No I/O Command Set
    _reserved2: u3,
    bps: bool,          // Boot Partition Support
    cps: u2,            // Controller Power Scope
    mpsmin: u4,         // Memory Page Size Minimum (2^(12+MPSMIN))
    mpsmax: u4,         // Memory Page Size Maximum
    pmrs: bool,         // PMR Supported
    cmbs: bool,         // CMB Supported
    nsss: bool,         // NVM Subsystem Shutdown Supported
    crms_crwms: bool,   // Controller Ready Modes
    crms_crims: bool,   // Controller Ready Independent
    _reserved3: u3,
};

pub const NvmeControllerConfig = packed struct(u32) {
    enable: bool,
    _reserved1: u3,
    css: u3,            // I/O Command Set Selected
    mps: u4,            // Memory Page Size (2^(12+MPS))
    ams: u3,            // Arbitration Mechanism Selected
    shn: u2,            // Shutdown Notification
    iosqes: u4,         // I/O Submission Queue Entry Size (2^n)
    iocqes: u4,         // I/O Completion Queue Entry Size (2^n)
    crime: bool,        // Controller Ready Independent of Media Enable
    _reserved2: u7,
};

pub const NvmeControllerStatus = packed struct(u32) {
    rdy: bool,          // Ready
    cfs: bool,          // Controller Fatal Status
    shst: u2,           // Shutdown Status
    nssro: bool,        // NVM Subsystem Reset Occurred
    pp: bool,           // Processing Paused
    st: bool,           // Shutdown Type
    _reserved: u25,
};

// ============================================================================
// NVMe Admin Commands
// ============================================================================

pub const NvmeAdminOpcode = enum(u8) {
    delete_io_sq = 0x00,
    create_io_sq = 0x01,
    get_log_page = 0x02,
    delete_io_cq = 0x04,
    create_io_cq = 0x05,
    identify = 0x06,
    abort = 0x08,
    set_features = 0x09,
    get_features = 0x0A,
    async_event_req = 0x0C,
    ns_management = 0x0D,
    firmware_commit = 0x10,
    firmware_download = 0x11,
    device_self_test = 0x14,
    ns_attachment = 0x15,
    keep_alive = 0x18,
    directive_send = 0x19,
    directive_recv = 0x1A,
    virtualization_mgmt = 0x1C,
    nvme_mi_send = 0x1D,
    nvme_mi_recv = 0x1E,
    capacity_mgmt = 0x20,
    lockdown = 0x24,
    doorbell_buffer_config = 0x7C,
    fabrics_cmd = 0x7F,
    format_nvm = 0x80,
    security_send = 0x81,
    security_recv = 0x82,
    sanitize = 0x84,
    get_lba_status = 0x86,
};

// ============================================================================
// NVMe I/O Commands
// ============================================================================

pub const NvmeIoOpcode = enum(u8) {
    flush = 0x00,
    write = 0x01,
    read = 0x02,
    write_uncorrectable = 0x04,
    compare = 0x05,
    write_zeroes = 0x08,
    dataset_mgmt = 0x09,       // TRIM/Unmap
    verify = 0x0C,
    reservation_register = 0x0D,
    reservation_report = 0x0E,
    reservation_acquire = 0x11,
    reservation_release = 0x15,
    copy = 0x19,
    // ZNS commands
    zone_mgmt_send = 0x79,
    zone_mgmt_recv = 0x7A,
    zone_append = 0x7D,
};

// ============================================================================
// NVMe Submission Queue Entry (64 bytes)
// ============================================================================

pub const NvmeSqe = extern struct {
    // CDW0
    opcode: u8,
    flags: u8,               // FUSE[1:0], PSDT[7:6]
    command_id: u16,
    // CDW1
    nsid: u32,               // Namespace Identifier
    // CDW2-3
    cdw2: u32,
    cdw3: u32,
    // CDW4-5 (Metadata Pointer)
    mptr: u64,
    // CDW6-9 (Data Pointer)
    prp1: u64,               // PRP Entry 1 / SGL Entry
    prp2: u64,               // PRP Entry 2 / SGL Entry
    // CDW10-15 (Command Specific)
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
};

// ============================================================================
// NVMe Completion Queue Entry (16 bytes)
// ============================================================================

pub const NvmeCqe = extern struct {
    result: u64,              // Command Specific
    sq_head: u16,             // SQ Head Pointer
    sq_id: u16,               // SQ Identifier
    command_id: u16,          // Command Identifier
    status: u16,              // Status Field (P, SC, SCT, CRD, M, DNR)
};

pub const NvmeStatusCode = enum(u8) {
    success = 0x00,
    invalid_opcode = 0x01,
    invalid_field = 0x02,
    command_id_conflict = 0x03,
    data_transfer_error = 0x04,
    power_loss_abort = 0x05,
    internal_error = 0x06,
    abort_requested = 0x07,
    abort_sq_deleted = 0x08,
    abort_fused_fail = 0x09,
    abort_fused_missing = 0x0A,
    invalid_ns_or_format = 0x0B,
    command_seq_error = 0x0C,
    invalid_sgl_segment = 0x0D,
    invalid_sgl_count = 0x0E,
    invalid_data_sgl_len = 0x0F,
    invalid_meta_sgl_len = 0x10,
    sgl_type_invalid = 0x11,
    invalid_cmb_use = 0x12,
    lba_out_of_range = 0x80,
    capacity_exceeded = 0x81,
    ns_not_ready = 0x82,
    reservation_conflict = 0x83,
    format_in_progress = 0x84,
};

// ============================================================================
// NVMe Identify Structures
// ============================================================================

pub const NvmeIdentifyController = extern struct {
    vid: u16,                      // PCI Vendor ID
    ssvid: u16,                    // PCI Subsystem Vendor ID
    sn: [20]u8,                    // Serial Number
    mn: [40]u8,                    // Model Number
    fr: [8]u8,                     // Firmware Revision
    rab: u8,                       // Recommended Arbitration Burst
    ieee: [3]u8,                   // IEEE OUI Identifier
    cmic: u8,                      // Controller Multi-Path
    mdts: u8,                      // Max Data Transfer Size (2^n * MPS)
    cntlid: u16,                   // Controller ID
    ver: u32,                      // Version
    rtd3r: u32,                    // RTD3 Resume Latency
    rtd3e: u32,                    // RTD3 Entry Latency
    oaes: u32,                     // Optional Async Events
    ctratt: u32,                   // Controller Attributes
    rrls: u16,                     // Read Recovery Levels
    _reserved1: [9]u8,
    cntrltype: u8,                 // Controller Type
    fguid: [16]u8,                 // FRU GUID
    crdt1: u16,                    // Command Retry Delay Time 1
    crdt2: u16,                    // Command Retry Delay Time 2
    crdt3: u16,                    // Command Retry Delay Time 3
    _reserved2: [106]u8,
    // Admin command set
    oacs: u16,                     // Optional Admin Command Support
    acl: u8,                       // Abort Command Limit
    aerl: u8,                      // Async Event Request Limit
    frmw: u8,                      // Firmware Updates
    lpa: u8,                       // Log Page Attributes
    elpe: u8,                      // Error Log Page Entries
    npss: u8,                      // Number of Power States
    avscc: u8,                     // Admin Vendor Specific
    apsta: u8,                     // Autonomous Power State Transition
    wctemp: u16,                   // Warning Composite Temperature
    cctemp: u16,                   // Critical Composite Temperature
    mtfa: u16,                     // Max Time for Firmware Activation
    hmpre: u32,                    // Host Memory Buffer Preferred Size
    hmmin: u32,                    // Host Memory Buffer Minimum Size
    tnvmcap: [16]u8,              // Total NVM Capacity (128-bit)
    unvmcap: [16]u8,              // Unallocated NVM Capacity
    rpmbs: u32,                    // Replay Protected Memory Block
    edstt: u16,                    // Extended Device Self-test Time
    dsto: u8,                      // Device Self-test Options
    fwug: u8,                      // Firmware Update Granularity
    kas: u16,                      // Keep Alive Support
    hctma: u16,                    // Host Controlled Thermal Mgmt Attrs
    mntmt: u16,                    // Minimum Thermal Mgmt Temperature
    mxtmt: u16,                    // Maximum Thermal Mgmt Temperature
    sanicap: u32,                  // Sanitize Capabilities
    hmminds: u32,                  // Host Memory Buffer Min Desc Entry
    hmmaxd: u16,                   // Host Memory Max Descriptors
    nsetidmax: u16,                // NVM Set Identifier Max
    endgidmax: u16,                // Endurance Group Identifier Max
    anatt: u8,                     // ANA Transition Time
    anacap: u8,                    // ANA Capabilities
    anagrpmax: u32,                // ANA Group Identifier Max
    nanagrpid: u32,                // Number of ANA Group Identifiers
    pels: u32,                     // Persistent Event Log Size
    _reserved3: [156]u8,
    // NVM command set
    sqes: u8,                      // SQ Entry Size
    cqes: u8,                      // CQ Entry Size
    maxcmd: u16,                   // Max Outstanding Commands
    nn: u32,                       // Number of Namespaces
    oncs: u16,                     // Optional NVM Command Support
    fuses: u16,                    // Fused Operation Support
    fna: u8,                       // Format NVM Attributes
    vwc: u8,                       // Volatile Write Cache
    awun: u16,                     // Atomic Write Unit Normal
    awupf: u16,                    // Atomic Write Unit Power Fail
    icsvscc: u8,                   // I/O Command Set Vendor Specific
    nwpc: u8,                      // Namespace Write Protection
    acwu: u16,                     // Atomic Compare & Write Unit
    cdfs: u16,                     // Copy Descriptor Formats
    sgls: u32,                     // SGL Support
    mnan: u32,                     // Maximum Number of Allowed NS
    maxdna: [16]u8,                // Max Domain NS Attachments
    maxcna: u32,                   // Max I/O Controller NS Attachments
    _reserved4: [204]u8,
    subnqn: [256]u8,               // NVM Subsystem NQN
    _reserved5: [768]u8,
    // Fabrics
    ioccsz: u32,                   // I/O Queue Command Capsule Size
    iorcsz: u32,                   // I/O Queue Response Capsule Size
    icdoff: u16,                   // In Capsule Data Offset
    fcatt: u8,                     // Fabrics Controller Attributes
    msdbd: u8,                     // Max SGL Data Block Descriptors
    ofcs: u16,                     // Optional Fabric Commands
    _reserved6: [242]u8,
    // Power state descriptors (32 entries × 32 bytes = 1024)
    psd: [32]NvmePowerStateDesc,
    // Vendor specific (1024 bytes)
    vs: [1024]u8,
};

pub const NvmePowerStateDesc = extern struct {
    max_power: u16,         // centiwatts
    _reserved1: u8,
    flags: u8,              // NOPS, MPS, ENLAT/EXLAT
    entry_latency: u32,    // microseconds
    exit_latency: u32,     // microseconds
    read_throughput: u8,
    read_latency: u8,
    write_throughput: u8,
    write_latency: u8,
    idle_power: u16,       // centiwatts
    idle_scale: u8,
    _reserved2: u8,
    active_power: u16,     // centiwatts
    active_work_scale: u8,
    _reserved3: [9]u8,
};

// ============================================================================
// NVMe Namespace Identify
// ============================================================================

pub const NvmeNamespaceIdent = extern struct {
    nsze: u64,              // Namespace Size (LBAs)
    ncap: u64,              // Namespace Capacity
    nuse: u64,              // Namespace Utilization
    nsfeat: u8,             // Namespace Features
    nlbaf: u8,              // Number of LBA Formats
    flbas: u8,              // Formatted LBA Size
    mc: u8,                 // Metadata Capabilities
    dpc: u8,                // End-to-end Data Protection
    dps: u8,                // Data Protection Settings
    nmic: u8,               // NS Multi-path I/O and NS Sharing
    rescap: u8,             // Reservation Capabilities
    fpi: u8,                // Format Progress Indicator
    dlfeat: u8,             // Deallocate Logical Block Features
    nawun: u16,             // NS Atomic Write Unit Normal
    nawupf: u16,            // NS Atomic Write Unit Power Fail
    nacwu: u16,             // NS Atomic Compare & Write Unit
    nabsn: u16,             // NS Atomic Boundary Size Normal
    nabo: u16,              // NS Atomic Boundary Offset
    nabspf: u16,            // NS Atomic Boundary Size Power Fail
    noiob: u16,             // NS Optimal I/O Boundary
    nvmcap: [16]u8,         // NVM Capacity (128-bit)
    npwg: u16,              // NS Preferred Write Granularity
    npwa: u16,              // NS Preferred Write Alignment
    npdg: u16,              // NS Preferred Deallocate Granularity
    npda: u16,              // NS Preferred Deallocate Alignment
    nows: u16,              // NS Optimal Write Size
    mssrl: u16,             // Max Single Source Range Length
    mcl: u32,               // Max Copy Length
    msrc: u8,               // Max Source Range Count
    _reserved1: [11]u8,
    anagrpid: u32,          // ANA Group Identifier
    _reserved2: [3]u8,
    nsattr: u8,             // NS Attributes
    nvmsetid: u16,          // NVM Set Identifier
    endgid: u16,            // Endurance Group Identifier
    nguid: [16]u8,          // NS Globally Unique Identifier
    eui64: [8]u8,           // IEEE Extended Unique Identifier
    lbaf: [64]NvmeLbaFormat, // LBA Format Support
    vs: [3712]u8,           // Vendor Specific
};

pub const NvmeLbaFormat = extern struct {
    ms: u16,                // Metadata Size (bytes)
    lbads: u8,              // LBA Data Size (2^n)
    rp: u8,                 // Relative Performance
};

// ============================================================================
// ZNS (Zoned Namespaces)
// ============================================================================

pub const ZnsZoneState = enum(u8) {
    empty = 0x01,
    implicitly_open = 0x02,
    explicitly_open = 0x03,
    closed = 0x04,
    read_only = 0x0D,
    full = 0x0E,
    offline = 0x0F,
};

pub const ZnsZoneType = enum(u8) {
    seq_write_required = 0x02,
    seq_write_preferred = 0x03,
};

pub const ZnsZoneDescriptor = extern struct {
    zone_type: u8,
    zone_state: u8,
    zone_attributes: u8,
    _reserved: [5]u8,
    zone_cap: u64,           // Zone Capacity in LBAs
    zone_start_lba: u64,     // Zone Start LBA
    write_pointer: u64,      // Write Pointer
    _reserved2: [32]u8,
};

pub const ZnsZoneAction = enum(u8) {
    close = 0x01,
    finish = 0x02,
    open_zone = 0x03,
    reset = 0x04,
    offline = 0x05,
    set_desc_ext = 0x10,
};

// ============================================================================
// NVMe-oF (over Fabrics)
// ============================================================================

pub const NvmeFabricsTransport = enum(u8) {
    rdma = 0x01,
    fc = 0x02,          // Fibre Channel
    tcp = 0x03,
    intra_host = 0xFE,
};

pub const NvmeFabricsAdrfam = enum(u8) {
    ipv4 = 0x01,
    ipv6 = 0x02,
    ib = 0x03,           // InfiniBand
    fc = 0x04,           // Fibre Channel
    intra_host = 0xFE,
};

pub const NvmeFabricsQType = enum(u8) {
    admin = 0x00,
    io = 0x01,
};

pub const NvmofConnectCmd = struct {
    recfmt: u16,       // Record Format
    qid: u16,          // Queue ID
    sqsize: u16,       // SQ Size
    cattr: u8,         // Connect Attributes
    _reserved: u8,
    kato: u32,         // Keep Alive Timeout (ms)
};

pub const NvmofDiscoveryLogEntry = struct {
    trtype: NvmeFabricsTransport,
    adrfam: NvmeFabricsAdrfam,
    subtype: u8,         // Subsystem Type
    treq: u8,            // Transport Requirements
    portid: u16,
    cntlid: u16,
    asqsz: u16,          // Admin Max SQ Size
    eflags: u16,         // Entry Flags
    _reserved: [20]u8,
    trsvcid: [32]u8,     // Transport Service Identifier
    _reserved2: [192]u8,
    subnqn: [256]u8,     // Subsystem NQN
    traddr: [256]u8,     // Transport Address
    tsas: [256]u8,       // Transport Specific Address
};

// ============================================================================
// NVMe Multipath
// ============================================================================

pub const NvmeAnaState = enum(u8) {
    optimized = 0x01,
    non_optimized = 0x02,
    inaccessible = 0x03,
    persistent_loss = 0x04,
    change = 0x0F,
};

pub const NvmeMultipathPolicy = enum(u8) {
    numa = 0,
    round_robin = 1,
    queue_depth = 2,
    // Zxyphor
    zxy_latency_aware = 100,
};

pub const NvmePathInfo = struct {
    ctrl_id: u16,
    ns_id: u32,
    ana_state: NvmeAnaState,
    ana_grp_id: u32,
    numa_node: i32,
    queue_depth: u32,
    latency_us: u64,
    active: bool,
    preferred: bool,
};

// ============================================================================
// NVMe Queue Pair
// ============================================================================

pub const NvmeQueuePair = struct {
    qid: u16,
    sq_depth: u16,
    cq_depth: u16,
    sq_tail: u16,
    cq_head: u16,
    cq_phase: u1,
    sq_phys: u64,        // Physical address of SQ
    cq_phys: u64,        // Physical address of CQ
    sq_doorbell: u64,    // MMIO doorbell address
    cq_doorbell: u64,
    irq_vector: u16,
    nr_outstanding: u32,
    flags: QueueFlags,
};

pub const QueueFlags = packed struct(u16) {
    polled: bool = false,       // Polled I/O queue
    admin: bool = false,
    irq_enabled: bool = true,
    weighted_rr: bool = false,
    urgent_priority: bool = false,
    _reserved: u11 = 0,
};

// ============================================================================
// NVMe Feature IDs
// ============================================================================

pub const NvmeFeatureId = enum(u8) {
    arbitration = 0x01,
    power_management = 0x02,
    lba_range_type = 0x03,
    temperature_threshold = 0x04,
    error_recovery = 0x05,
    volatile_write_cache = 0x06,
    number_of_queues = 0x07,
    interrupt_coalescing = 0x08,
    interrupt_vector_config = 0x09,
    write_atomicity_normal = 0x0A,
    async_event_config = 0x0B,
    auto_power_state_trans = 0x0C,
    host_mem_buffer = 0x0D,
    timestamp = 0x0E,
    keep_alive_timer = 0x0F,
    host_controlled_thermal = 0x10,
    non_operational_power_state = 0x11,
    read_recovery_level = 0x12,
    predictable_latency_mode = 0x13,
    predictable_latency_window = 0x14,
    lba_status_info = 0x15,
    host_behavior = 0x16,
    sanitize_config = 0x17,
    endurance_group_event = 0x18,
    io_cmd_set_profile = 0x19,
    // NVM command set specific
    software_progress_marker = 0x80,
    host_identifier = 0x81,
    reservation_notification = 0x82,
    reservation_persistence = 0x83,
    ns_write_protection = 0x84,
};

// ============================================================================
// NVMe Driver Manager (Zxyphor)
// ============================================================================

pub const NvmeDriver = struct {
    nr_controllers: u16,
    nr_namespaces: u32,
    nr_queues_per_ctrl: u16,
    multipath_policy: NvmeMultipathPolicy,
    zns_supported: bool,
    fabrics_supported: bool,
    poll_queues: u16,
    io_timeout_ms: u32,
    admin_timeout_ms: u32,
    initialized: bool,

    pub fn init() NvmeDriver {
        return .{
            .nr_controllers = 0,
            .nr_namespaces = 0,
            .nr_queues_per_ctrl = 0,
            .multipath_policy = .numa,
            .zns_supported = false,
            .fabrics_supported = false,
            .poll_queues = 0,
            .io_timeout_ms = 30000,
            .admin_timeout_ms = 60000,
            .initialized = true,
        };
    }
};
