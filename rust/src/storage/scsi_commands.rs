// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Rust - SCSI Command Layer and Storage Abstraction
// SCSI commands, command descriptor blocks, sense data, LUN management,
// device scanning, error handling, target mode, SCSI transport (SAS/FC/iSCSI)
// More advanced than Linux 2026 SCSI subsystem

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// ============================================================================
// SCSI Operation Codes
// ============================================================================

pub const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub const SCSI_REQUEST_SENSE: u8 = 0x03;
pub const SCSI_FORMAT_UNIT: u8 = 0x04;
pub const SCSI_READ_6: u8 = 0x08;
pub const SCSI_WRITE_6: u8 = 0x0A;
pub const SCSI_INQUIRY: u8 = 0x12;
pub const SCSI_MODE_SELECT_6: u8 = 0x15;
pub const SCSI_MODE_SENSE_6: u8 = 0x1A;
pub const SCSI_START_STOP_UNIT: u8 = 0x1B;
pub const SCSI_SEND_DIAGNOSTIC: u8 = 0x1D;
pub const SCSI_PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_READ_10: u8 = 0x28;
pub const SCSI_WRITE_10: u8 = 0x2A;
pub const SCSI_SEEK_10: u8 = 0x2B;
pub const SCSI_WRITE_VERIFY_10: u8 = 0x2E;
pub const SCSI_VERIFY_10: u8 = 0x2F;
pub const SCSI_SYNCHRONIZE_CACHE_10: u8 = 0x35;
pub const SCSI_READ_DEFECT_DATA: u8 = 0x37;
pub const SCSI_WRITE_BUFFER: u8 = 0x3B;
pub const SCSI_READ_BUFFER: u8 = 0x3C;
pub const SCSI_UNMAP: u8 = 0x42;
pub const SCSI_LOG_SELECT: u8 = 0x4C;
pub const SCSI_LOG_SENSE: u8 = 0x4D;
pub const SCSI_MODE_SELECT_10: u8 = 0x55;
pub const SCSI_MODE_SENSE_10: u8 = 0x5A;
pub const SCSI_PERSISTENT_RESERVE_IN: u8 = 0x5E;
pub const SCSI_PERSISTENT_RESERVE_OUT: u8 = 0x5F;
pub const SCSI_READ_16: u8 = 0x88;
pub const SCSI_COMPARE_AND_WRITE: u8 = 0x89;
pub const SCSI_WRITE_16: u8 = 0x8A;
pub const SCSI_WRITE_VERIFY_16: u8 = 0x8E;
pub const SCSI_VERIFY_16: u8 = 0x8F;
pub const SCSI_SYNCHRONIZE_CACHE_16: u8 = 0x91;
pub const SCSI_WRITE_SAME_16: u8 = 0x93;
pub const SCSI_SERVICE_ACTION_IN_16: u8 = 0x9E;
pub const SCSI_READ_CAPACITY_16: u8 = 0x9E; // Same, sub-command
pub const SCSI_REPORT_LUNS: u8 = 0xA0;
pub const SCSI_ATA_PASSTHROUGH_12: u8 = 0xA1;
pub const SCSI_READ_12: u8 = 0xA8;
pub const SCSI_WRITE_12: u8 = 0xAA;
pub const SCSI_ATA_PASSTHROUGH_16: u8 = 0x85;

// ============================================================================
// SCSI Status Codes
// ============================================================================

pub const SCSI_STATUS_GOOD: u8 = 0x00;
pub const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;
pub const SCSI_STATUS_CONDITION_MET: u8 = 0x04;
pub const SCSI_STATUS_BUSY: u8 = 0x08;
pub const SCSI_STATUS_RESERVATION_CONFLICT: u8 = 0x18;
pub const SCSI_STATUS_TASK_SET_FULL: u8 = 0x28;
pub const SCSI_STATUS_ACA_ACTIVE: u8 = 0x30;
pub const SCSI_STATUS_TASK_ABORTED: u8 = 0x40;

// ============================================================================
// SCSI Sense Data
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SenseKey {
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
    CopyAborted = 0xA,
    AbortedCommand = 0xB,
    VolumeOverflow = 0xD,
    Miscompare = 0xE,
    Completed = 0xF,
}

#[repr(C)]
pub struct SenseData {
    pub response_code: u8,
    pub sense_key: SenseKey,
    pub asc: u8,             // Additional Sense Code
    pub ascq: u8,            // Additional Sense Code Qualifier
    pub additional_length: u8,
    pub field_replaceable_unit: u8,
    pub sense_key_specific: [3; u8],
    pub info: [4; u8],
    pub command_specific: [4; u8],
    // Additional sense bytes
    pub additional: [232; u8],
    pub additional_len: u8,
}

impl SenseData {
    pub fn is_unit_attention(&self) -> bool {
        self.sense_key == SenseKey::UnitAttention
    }

    pub fn is_medium_error(&self) -> bool {
        self.sense_key == SenseKey::MediumError
    }

    pub fn is_not_ready(&self) -> bool {
        self.sense_key == SenseKey::NotReady
    }

    pub fn error_description(&self) -> &'static str {
        match (self.asc, self.ascq) {
            (0x00, 0x00) => "No additional sense information",
            (0x04, 0x01) => "Logical unit is in process of becoming ready",
            (0x04, 0x02) => "Logical unit not ready, initializing cmd. required",
            (0x04, 0x03) => "Logical unit not ready, manual intervention required",
            (0x20, 0x00) => "Invalid command operation code",
            (0x24, 0x00) => "Invalid field in CDB",
            (0x25, 0x00) => "Logical unit not supported",
            (0x26, 0x00) => "Invalid field in parameter list",
            (0x28, 0x00) => "Not ready to ready change, medium may have changed",
            (0x29, 0x00) => "Power on, reset, or bus device reset occurred",
            (0x2A, 0x01) => "Mode parameters changed",
            (0x3A, 0x00) => "Medium not present",
            (0x3E, 0x01) => "Logical unit failure",
            (0x3F, 0x0E) => "Reported LUNs data has changed",
            (0x44, 0x00) => "Internal target failure",
            _ => "Unknown sense code",
        }
    }
}

// ============================================================================
// SCSI Device Types
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScsiDeviceType {
    Disk = 0x00,
    Tape = 0x01,
    Printer = 0x02,
    Processor = 0x03,
    Worm = 0x04,
    CdRom = 0x05,
    Scanner = 0x06,
    OpticalMemory = 0x07,
    MediumChanger = 0x08,
    Communications = 0x09,
    StorageArray = 0x0C,
    Enclosure = 0x0D,
    SimpleDisk = 0x0E,
    OpticalCard = 0x0F,
    BridgeController = 0x10,
    Osd = 0x11,          // Object-based storage
    Automation = 0x12,
    ZonedBlock = 0x14,
    WellKnownLu = 0x1E,
    NoDevice = 0x1F,
}

// ============================================================================
// SCSI Inquiry Data
// ============================================================================

#[repr(C)]
pub struct InquiryData {
    pub device_type: ScsiDeviceType,
    pub rmb: bool,           // Removable media bit
    pub version: u8,         // SPC version
    pub response_format: u8,
    pub additional_length: u8,
    pub protect: bool,       // Protection information
    pub tpgs: u8,            // Target port group support
    pub acc: bool,            // Access controls coordinator
    pub sccs: bool,          // SCC supported
    pub multip: bool,        // Multi port
    pub encserv: bool,       // Enclosure services
    pub cmdque: bool,        // Command queuing
    pub vendor: [8; u8],
    pub product: [16; u8],
    pub revision: [4; u8],
    // VPD pages
    pub vpd_unit_serial: [20; u8],
    pub vpd_device_id: [64; u8],
}

// ============================================================================
// SCSI Command Descriptor Block (CDB)
// ============================================================================

pub struct ScsiCdb {
    pub cdb: [32; u8],
    pub cdb_len: u8,         // 6, 10, 12, 16, or 32
}

impl ScsiCdb {
    pub fn new_read_10(lba: u32, count: u16) -> Self {
        let mut cdb = [0u8; 32];
        cdb[0] = SCSI_READ_10;
        cdb[2] = ((lba >> 24) & 0xFF) as u8;
        cdb[3] = ((lba >> 16) & 0xFF) as u8;
        cdb[4] = ((lba >> 8) & 0xFF) as u8;
        cdb[5] = (lba & 0xFF) as u8;
        cdb[7] = ((count >> 8) & 0xFF) as u8;
        cdb[8] = (count & 0xFF) as u8;
        ScsiCdb { cdb, cdb_len: 10 }
    }

    pub fn new_write_10(lba: u32, count: u16) -> Self {
        let mut cdb = [0u8; 32];
        cdb[0] = SCSI_WRITE_10;
        cdb[2] = ((lba >> 24) & 0xFF) as u8;
        cdb[3] = ((lba >> 16) & 0xFF) as u8;
        cdb[4] = ((lba >> 8) & 0xFF) as u8;
        cdb[5] = (lba & 0xFF) as u8;
        cdb[7] = ((count >> 8) & 0xFF) as u8;
        cdb[8] = (count & 0xFF) as u8;
        ScsiCdb { cdb, cdb_len: 10 }
    }

    pub fn new_read_16(lba: u64, count: u32) -> Self {
        let mut cdb = [0u8; 32];
        cdb[0] = SCSI_READ_16;
        cdb[2] = ((lba >> 56) & 0xFF) as u8;
        cdb[3] = ((lba >> 48) & 0xFF) as u8;
        cdb[4] = ((lba >> 40) & 0xFF) as u8;
        cdb[5] = ((lba >> 32) & 0xFF) as u8;
        cdb[6] = ((lba >> 24) & 0xFF) as u8;
        cdb[7] = ((lba >> 16) & 0xFF) as u8;
        cdb[8] = ((lba >> 8) & 0xFF) as u8;
        cdb[9] = (lba & 0xFF) as u8;
        cdb[10] = ((count >> 24) & 0xFF) as u8;
        cdb[11] = ((count >> 16) & 0xFF) as u8;
        cdb[12] = ((count >> 8) & 0xFF) as u8;
        cdb[13] = (count & 0xFF) as u8;
        ScsiCdb { cdb, cdb_len: 16 }
    }

    pub fn new_inquiry(vpd: bool, page: u8, alloc_len: u16) -> Self {
        let mut cdb = [0u8; 32];
        cdb[0] = SCSI_INQUIRY;
        if vpd { cdb[1] = 0x01; }
        cdb[2] = page;
        cdb[3] = ((alloc_len >> 8) & 0xFF) as u8;
        cdb[4] = (alloc_len & 0xFF) as u8;
        ScsiCdb { cdb, cdb_len: 6 }
    }

    pub fn new_test_unit_ready() -> Self {
        let mut cdb = [0u8; 32];
        cdb[0] = SCSI_TEST_UNIT_READY;
        ScsiCdb { cdb, cdb_len: 6 }
    }

    pub fn new_sync_cache_10(lba: u32, count: u16) -> Self {
        let mut cdb = [0u8; 32];
        cdb[0] = SCSI_SYNCHRONIZE_CACHE_10;
        cdb[2] = ((lba >> 24) & 0xFF) as u8;
        cdb[3] = ((lba >> 16) & 0xFF) as u8;
        cdb[4] = ((lba >> 8) & 0xFF) as u8;
        cdb[5] = (lba & 0xFF) as u8;
        cdb[7] = ((count >> 8) & 0xFF) as u8;
        cdb[8] = (count & 0xFF) as u8;
        ScsiCdb { cdb, cdb_len: 10 }
    }

    pub fn opcode(&self) -> u8 {
        self.cdb[0]
    }
}

// ============================================================================
// SCSI Command / Request
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiDataDirection {
    None = 0,
    ToDevice = 1,     // Write
    FromDevice = 2,   // Read
    Bidirectional = 3,
}

pub struct ScsiCommand {
    pub cdb: ScsiCdb,
    pub data_direction: ScsiDataDirection,
    // Scatter-gather
    pub sg_count: u32,
    pub transfer_len: u64,
    // Result
    pub scsi_status: u8,
    pub host_status: u8,
    pub driver_status: u8,
    pub result: i32,
    // Sense
    pub sense: SenseData,
    pub sense_valid: bool,
    // Residual
    pub resid: u64,
    // Timeout
    pub timeout_secs: u32,
    pub retries: u32,
    pub max_retries: u32,
    // Tagging
    pub tag: u32,
    pub tag_type: u8,     // 0=simple, 1=head, 2=ordered
    // Target
    pub target_id: u32,
    pub lun: u64,
    pub channel: u8,
    // Timestamps
    pub submit_ns: u64,
    pub complete_ns: u64,
}

// ============================================================================
// SCSI Host / HBA
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiHostState {
    Created = 0,
    Running = 1,
    Cancel = 2,
    DelRecovery = 3,
    Recovery = 4,
    CancelRecovery = 5,
    Del = 6,
}

pub struct ScsiHost {
    pub host_no: u32,
    pub state: ScsiHostState,
    // Capabilities
    pub max_id: u32,
    pub max_lun: u64,
    pub max_channel: u32,
    pub max_cmd_len: u8,
    pub max_sectors: u32,
    pub max_segment_size: u32,
    pub sg_tablesize: u16,
    // Queue
    pub cmd_per_lun: u32,
    pub can_queue: u32,
    pub nr_hw_queues: u16,
    // Features
    pub use_clustering: bool,
    pub use_cmd_list: bool,
    pub ordered_tag: bool,
    pub unchecked_isa_dma: bool,
    pub host_self_blocked: bool,
    // Error handling
    pub eh_active: bool,
    pub shost_gendev: u64,
    // Transport
    pub transport_type: ScsiTransportType,
    // Stats
    pub commands_issued: u64,
    pub commands_completed: u64,
    pub commands_failed: u64,
    pub io_done: u64,
    pub io_err: u64,
    pub host_busy: u32,
    pub host_failed: u32,
    pub host_eh_scheduled: u32,
    // Name
    pub name: [64; u8],
    pub proc_name: [32; u8],
}

// ============================================================================
// SCSI Target
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiTargetState {
    Created = 0,
    Running = 1,
    Cancel = 2,
    Del = 3,
    CreatedBlock = 4,
    CreatedScan = 5,
}

pub struct ScsiTarget {
    pub id: u32,
    pub channel: u8,
    pub state: ScsiTargetState,
    pub scsi_level: u8,
    pub max_lun: u64,
    pub no_report_luns: bool,
    // Stats
    pub commands_issued: u64,
    pub commands_completed: u64,
    pub busy: u32,
    pub blocked: u32,
}

// ============================================================================
// SCSI Device (LUN)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiDeviceState {
    Created = 0,
    Running = 1,
    Cancel = 2,
    Del = 3,
    Quiesce = 4,
    Offline = 5,
    TransportOffline = 6,
    Block = 7,
    CreatedBlock = 8,
}

pub struct ScsiDevice {
    pub host: u32,       // Host number
    pub channel: u8,
    pub id: u32,
    pub lun: u64,
    pub state: ScsiDeviceState,
    pub device_type: ScsiDeviceType,
    // Inquiry
    pub inquiry: InquiryData,
    // Geometry
    pub sector_size: u32,       // Bytes per sector
    pub capacity: u64,          // Total sectors
    pub max_sectors: u32,
    // Features
    pub removable: bool,
    pub changed: bool,
    pub lockable: bool,
    pub locked: bool,
    pub borken: bool,           // Broken device (yes, Linux spells it this way)
    pub disconnect: bool,
    pub soft_reset: bool,
    pub sdtr: bool,             // Sync data transfer
    pub wdtr: bool,             // Wide data transfer
    pub tagged_supported: bool,
    pub simple_tags: bool,
    pub ordered_tags: bool,
    pub was_reset: bool,
    pub expecting_cc_ua: bool,
    pub use_10_for_rw: bool,
    pub use_10_for_ms: bool,
    pub no_report_opcodes: bool,
    pub no_write_same: bool,
    pub use_16_for_rw: bool,
    pub use_16_for_sync: bool,
    // Write protect
    pub readonly: bool,
    // Thin provisioning
    pub unmap_supported: bool,
    pub provisioning_mode: u8,
    pub zeroing_mode: u8,
    // DIF/DIX protection
    pub protection_type: u8,
    pub guard_type: u8,
    // Queue
    pub queue_depth: u32,
    pub max_queue_depth: u32,
    pub queue_ramp_up_period: u32,
    // Power
    pub manage_start_stop: bool,
    pub manage_system_start_stop: bool,
    pub manage_runtime_start_stop: bool,
    pub manage_shutdown: bool,
    // Allow restart
    pub allow_restart: bool,
    // Stats
    pub iorequest_cnt: u64,
    pub iodone_cnt: u64,
    pub ioerr_cnt: u64,
    // Timeout
    pub timeout: u32,
    pub eh_timeout: u32,
}

impl ScsiDevice {
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity * self.sector_size as u64
    }

    pub fn capacity_gb(&self) -> f64 {
        self.capacity_bytes() as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

// ============================================================================
// SCSI Transport Types
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiTransportType {
    Unknown = 0,
    SPI = 1,      // Parallel SCSI
    FC = 2,       // Fibre Channel
    SAS = 3,      // Serial Attached SCSI
    ISCSI = 4,    // Internet SCSI
    SBP = 5,      // Serial Bus Protocol (FireWire)
    SRP = 6,      // SCSI RDMA Protocol
    SATA = 7,
    USB = 8,
    PCIe = 9,     // NVMe over PCIe
    // Zxyphor
    ZxyFabric = 20,
}

// ============================================================================
// SAS (Serial Attached SCSI)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SasDeviceType {
    None = 0,
    EndDevice = 1,
    EdgeExpander = 2,
    FanoutExpander = 3,
    SataDevice = 4,
    SataPmPort = 5,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SasLinkRate {
    Unknown = 0,
    Phy_Disabled = 1,
    Phy_Reset_Problem = 2,
    Sata_Spinup_Hold = 3,
    Rate_1_5Gbps = 8,
    Rate_3_0Gbps = 9,
    Rate_6_0Gbps = 10,
    Rate_12_0Gbps = 11,
    Rate_22_5Gbps = 12,
}

pub struct SasPort {
    pub sas_addr: u64,
    pub attached_sas_addr: u64,
    pub phy_id: u8,
    pub link_rate: SasLinkRate,
    pub min_link_rate: SasLinkRate,
    pub max_link_rate: SasLinkRate,
    pub device_type: SasDeviceType,
    pub initiator_port_protocols: u32,
    pub target_port_protocols: u32,
    // Stats
    pub invalid_dword_count: u64,
    pub running_disparity_error_count: u64,
    pub loss_of_dword_sync_count: u64,
    pub phy_reset_problem_count: u64,
}

// ============================================================================
// Fibre Channel
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FcPortType {
    Unknown = 0,
    Other = 1,
    NotPresent = 2,
    NPort = 3,
    NLPort = 4,
    FPort = 5,
    FLPort = 6,
    EPort = 7,
    LPort = 8,
    PTP = 9,
    NPIV = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FcPortState {
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
}

pub struct FcHost {
    pub node_name: u64,    // WWNN
    pub port_name: u64,    // WWPN
    pub port_id: u32,
    pub port_type: FcPortType,
    pub port_state: FcPortState,
    pub speed: u32,        // Mbps
    pub max_speed: u32,
    pub supported_speeds: u32,
    pub fabric_name: u64,
    // Stats
    pub tx_frames: u64,
    pub tx_words: u64,
    pub rx_frames: u64,
    pub rx_words: u64,
    pub lip_count: u64,
    pub nos_count: u64,
    pub error_frames: u64,
    pub dumped_frames: u64,
    pub link_failure_count: u64,
    pub loss_of_sync_count: u64,
    pub loss_of_signal_count: u64,
    pub prim_seq_protocol_err_count: u64,
    pub invalid_tx_word_count: u64,
    pub invalid_crc_count: u64,
    pub fcp_input_requests: u64,
    pub fcp_output_requests: u64,
    pub fcp_control_requests: u64,
    pub fcp_input_megabytes: u64,
    pub fcp_output_megabytes: u64,
    pub seconds_since_last_reset: u64,
}

// ============================================================================
// iSCSI
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IscsiSessionState {
    Free = 0,
    LoggedIn = 1,
    Failed = 2,
    Recover = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum IscsiConnectionState {
    Free = 0,
    Transport_Wait = 1,
    In_Login = 2,
    Logged_In = 3,
    In_Logout = 4,
    Logout_Requested = 5,
    Cleanup_Wait = 6,
}

pub struct IscsiSession {
    pub state: IscsiSessionState,
    pub target_name: [224; u8],
    pub target_alias: [256; u8],
    pub tpgt: u16,
    pub max_burst_len: u32,
    pub first_burst_len: u32,
    pub def_time2wait: u16,
    pub def_time2retain: u16,
    pub max_outstanding_r2t: u16,
    pub initial_r2t: bool,
    pub immediate_data: bool,
    pub data_pdu_in_order: bool,
    pub data_sequence_in_order: bool,
    pub erl: u8,
    pub isid: [6; u8],
    pub tsih: u16,
    pub cmd_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    // Authentication
    pub auth_method: u8,  // 0=none, 1=CHAP, 2=SRP
    // iSER (iSCSI Extensions for RDMA)
    pub rdma_extensions: bool,
    // Stats
    pub data_octets_rx: u64,
    pub data_octets_tx: u64,
    pub cmd_pdus_tx: u64,
    pub rsp_pdus_rx: u64,
    pub digest_err: u64,
    pub timeout_err: u64,
}

pub struct IscsiConnection {
    pub state: IscsiConnectionState,
    pub cid: u16,
    // Address
    pub persistent_address: [64; u8],
    pub persistent_port: u16,
    pub local_address: [64; u8],
    pub local_port: u16,
    // Header/data digest
    pub header_digest: bool,
    pub data_digest: bool,
    // Receive
    pub max_recv_dlength: u32,
    pub max_xmit_dlength: u32,
    // Stats
    pub exp_statsn: u32,
}

// ============================================================================
// SCSI Error Handling
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiEhAction {
    ResetTimer = 0,
    Done = 1,
    NotHandled = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ScsiEhStrategy {
    AbortCmd = 0,
    DeviceReset = 1,
    TargetReset = 2,
    BusReset = 3,
    HostReset = 4,
}

pub struct ScsiEhStats {
    pub abort_success: u64,
    pub abort_fail: u64,
    pub device_reset_success: u64,
    pub device_reset_fail: u64,
    pub target_reset_success: u64,
    pub target_reset_fail: u64,
    pub bus_reset_success: u64,
    pub bus_reset_fail: u64,
    pub host_reset_success: u64,
    pub host_reset_fail: u64,
    pub total_eh_runs: u64,
    pub last_eh_ns: u64,
}

// ============================================================================
// Multipath I/O (DM-MPIO)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MultipathPolicy {
    RoundRobin = 0,
    QueueLength = 1,
    ServiceTime = 2,
    // Zxyphor
    ZxyAdaptive = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PathState {
    Active = 0,
    Standby = 1,
    Unavailable = 2,
    Transitioning = 3,
}

pub struct MultipathPath {
    pub device_name: [64; u8],
    pub host: u32,
    pub channel: u8,
    pub target: u32,
    pub lun: u64,
    pub state: PathState,
    pub priority: i32,
    pub weight: u32,
    // Stats
    pub io_count: u64,
    pub io_bytes: u64,
    pub io_errors: u64,
    pub latency_avg_us: u64,
    pub latency_max_us: u64,
}

pub struct MultipathDevice {
    pub name: [64; u8],
    pub uuid: [128; u8],
    pub policy: MultipathPolicy,
    pub paths: [32; MultipathPath],
    pub nr_paths: u8,
    pub nr_active_paths: u8,
    // Queue mode
    pub queue_if_no_path: bool,
    // Stats
    pub failover_count: u64,
    pub last_failover_ns: u64,
}

// ============================================================================
// SCSI Subsystem Manager
// ============================================================================

pub struct ScsiSubsystem {
    // Hosts
    pub nr_hosts: u32,
    pub nr_targets: u32,
    pub nr_devices: u32,
    pub nr_luns: u64,
    // Transports
    pub nr_sas_ports: u32,
    pub nr_fc_hosts: u32,
    pub nr_iscsi_sessions: u32,
    // Error handling
    pub eh_stats: ScsiEhStats,
    // Multipath
    pub nr_multipath_devices: u32,
    // Stats
    pub total_commands: u64,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub total_errors: u64,
    pub total_timeouts: u64,
    pub total_resets: u64,
    // Device scanning
    pub scan_in_progress: bool,
    pub last_scan_ns: u64,
    // Zxyphor
    pub zxy_auto_multipath: bool,
    pub zxy_predictive_eh: bool,
    pub initialized: bool,
}
