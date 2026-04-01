// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - SCSI Advanced Commands, multipath DM,
// Storage Performance Monitoring, NVMe Fabric targets,
// More advanced than Linux 2026 storage subsystem

/// SCSI command descriptor block (CDB) lengths
pub const CDB_SIZE_6: usize = 6;
pub const CDB_SIZE_10: usize = 10;
pub const CDB_SIZE_12: usize = 12;
pub const CDB_SIZE_16: usize = 16;
pub const CDB_SIZE_32: usize = 32;

/// SCSI status codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiStatus {
    Good = 0x00,
    CheckCondition = 0x02,
    ConditionMet = 0x04,
    Busy = 0x08,
    Intermediate = 0x10,
    IntermCondMet = 0x14,
    ReservationConflict = 0x18,
    CommandTerminated = 0x22,
    TaskSetFull = 0x28,
    AcaActive = 0x30,
    TaskAborted = 0x40,
}

/// SCSI sense key
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiSenseKey {
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

/// Additional sense codes (ASC/ASCQ)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenseCode {
    pub asc: u8,
    pub ascq: u8,
}

impl SenseCode {
    pub const NO_ADDITIONAL: Self = Self { asc: 0x00, ascq: 0x00 };
    pub const LUN_NOT_READY: Self = Self { asc: 0x04, ascq: 0x00 };
    pub const LUN_NOT_READY_BECOMING_READY: Self = Self { asc: 0x04, ascq: 0x01 };
    pub const LUN_NOT_READY_INIT_CMD_REQUIRED: Self = Self { asc: 0x04, ascq: 0x02 };
    pub const LUN_NOT_READY_FORMAT: Self = Self { asc: 0x04, ascq: 0x04 };
    pub const WRITE_ERROR: Self = Self { asc: 0x0C, ascq: 0x00 };
    pub const READ_ERROR: Self = Self { asc: 0x11, ascq: 0x00 };
    pub const PARAMETER_LIST_LENGTH_ERROR: Self = Self { asc: 0x1A, ascq: 0x00 };
    pub const INVALID_OPCODE: Self = Self { asc: 0x20, ascq: 0x00 };
    pub const LBA_OUT_OF_RANGE: Self = Self { asc: 0x21, ascq: 0x00 };
    pub const INVALID_FIELD_IN_CDB: Self = Self { asc: 0x24, ascq: 0x00 };
    pub const INVALID_FIELD_IN_PARAM_LIST: Self = Self { asc: 0x26, ascq: 0x00 };
    pub const WRITE_PROTECTED: Self = Self { asc: 0x27, ascq: 0x00 };
    pub const MEDIUM_NOT_PRESENT: Self = Self { asc: 0x3A, ascq: 0x00 };
    pub const POWER_ON_RESET: Self = Self { asc: 0x29, ascq: 0x00 };
    pub const BUS_RESET: Self = Self { asc: 0x29, ascq: 0x02 };
    pub const TARGET_RESET: Self = Self { asc: 0x29, ascq: 0x03 };
    pub const COMMANDS_CLEARED: Self = Self { asc: 0x2F, ascq: 0x00 };
    pub const INTERNAL_TARGET_FAILURE: Self = Self { asc: 0x44, ascq: 0x00 };
    pub const TRANSPORT_PROBLEM: Self = Self { asc: 0x4B, ascq: 0x00 };
    pub const THRESHOLD_EXCEEDED: Self = Self { asc: 0x5D, ascq: 0x00 };
    pub const LOW_POWER_CONDITION: Self = Self { asc: 0x5E, ascq: 0x00 };
    pub const MISCOMPARE_VERIFY: Self = Self { asc: 0x1D, ascq: 0x00 };
}

/// SCSI VPD (Vital Product Data) page codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpdPageCode {
    SupportedPages = 0x00,
    UnitSerialNumber = 0x80,
    DeviceIdentification = 0x83,
    SoftwareInterface = 0x84,
    ManagementNetworkAddresses = 0x85,
    ExtendedIdentification = 0x86,
    ModePagePolicy = 0x87,
    ScsiPorts = 0x88,
    PowerCondition = 0x8A,
    DeviceConstituents = 0x8B,
    CfaProfile = 0x8C,
    PowerConsumption = 0x8D,
    ThirdPartyCopy = 0x8F,
    ProtocolSpecificLun = 0x90,
    ProtocolSpecificPort = 0x91,
    BlockLimits = 0xB0,
    BlockDeviceChars = 0xB1,
    LogicalBlockProvisioning = 0xB2,
    Referrals = 0xB3,
    SupportedBlockLengths = 0xB4,
    BlockDeviceCharExt = 0xB5,
    ZonedBlockDevChars = 0xB6,
    BlockLimitsExt = 0xB7,
}

/// SCSI device inquiry data
#[derive(Debug, Clone)]
pub struct ScsiInquiryData {
    pub peripheral_type: u8,
    pub peripheral_qualifier: u8,
    pub removable: bool,
    pub version: u8,        // SPC version
    pub response_data_format: u8,
    pub additional_length: u8,
    pub vendor: [u8; 8],
    pub product: [u8; 16],
    pub revision: [u8; 4],
    // Features
    pub cmdque: bool,       // Command queuing
    pub linked: bool,
    pub sync: bool,
    pub wbus16: bool,
    pub protect: bool,      // T10 DIF
    pub encserv: bool,
    pub multip: bool,
}

// ============================================================================
// Device Mapper
// ============================================================================

/// Device Mapper target types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmTargetType {
    Linear = 0,
    Striped = 1,
    Mirror = 2,
    Snapshot = 3,
    SnapshotOrigin = 4,
    SnapshotMerge = 5,
    Error = 6,
    Zero = 7,
    Multipath = 8,
    Crypt = 9,
    Delay = 10,
    Flakey = 11,
    Log = 12,
    Raid = 13,
    ThinPool = 14,
    Thin = 15,
    Cache = 16,
    Writecache = 17,
    Era = 18,
    Clone = 19,
    Integrity = 20,
    Verity = 21,
    VerityFec = 22,
    Dust = 23,
    Bow = 24,           // Backup on write
    // Zxyphor
    ZxyDedup = 50,
    ZxyCompress = 51,
    ZxyTier = 52,
}

/// DM Multipath path selector
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmPathSelector {
    RoundRobin = 0,
    QueueLength = 1,
    ServiceTime = 2,
    Historical = 3,
    IoAffinity = 4,
    // Zxyphor
    ZxyAdaptive = 10,
}

/// DM Multipath info
#[derive(Debug, Clone)]
pub struct DmMultipathInfo {
    pub nr_priority_groups: u32,
    pub nr_paths: u32,
    pub nr_active_paths: u32,
    pub queue_if_no_path: bool,
    pub retain_attached_hw_handler: bool,
    pub path_selector: DmPathSelector,
    // Failover
    pub failover_count: u64,
    pub failback_count: u64,
    // Stats
    pub total_ios: u64,
    pub total_bytes: u64,
    pub total_path_failures: u64,
    pub total_path_reinstates: u64,
}

/// DM Thin Provisioning
#[derive(Debug, Clone)]
pub struct DmThinPoolInfo {
    pub data_block_size: u32,          // sectors
    pub data_dev_size: u64,            // sectors
    pub metadata_dev_size: u64,        // sectors
    pub nr_data_blocks_used: u64,
    pub nr_data_blocks_total: u64,
    pub nr_metadata_blocks_used: u64,
    pub nr_metadata_blocks_total: u64,
    // Features
    pub discard_passdown: bool,
    pub error_if_no_space: bool,
    pub no_discard_passdown: bool,
    pub read_only: bool,
    // Stats
    pub nr_thin_volumes: u32,
    pub total_provisioned: u64,
    pub total_mapped: u64,
}

/// DM Crypt cipher info
#[derive(Debug, Clone)]
pub struct DmCryptInfo {
    pub cipher: [64; u8],
    pub key_size: u32,
    pub iv_offset: u64,
    pub sector_size: u32,
    // Options
    pub allow_discards: bool,
    pub same_cpu_crypt: bool,
    pub submit_from_crypt_cpus: bool,
    pub no_read_workqueue: bool,
    pub no_write_workqueue: bool,
    pub integrity: bool,
    pub journal_crypt: bool,
    pub journal_mac: bool,
}

// ============================================================================
// NVMe Fabrics
// ============================================================================

/// NVMe transport type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeTransportType {
    Rdma = 1,
    FibreChannel = 2,
    Tcp = 3,
    Loop = 254,
    // Zxyphor
    ZxyDirect = 100,
}

/// NVMe address family
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeAddrFamily {
    Pci = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Ib = 3,
    Fc = 4,
    Loop = 254,
    IntraHost = 255,
}

/// NVMe-oF host info
#[derive(Debug, Clone)]
pub struct NvmeFabricHost {
    pub hostnqn: [u8; 223],
    pub hostid: [u8; 16],
    // Controller config
    pub nr_io_queues: u16,
    pub queue_size: u32,
    pub keep_alive_tmo: u32,
    pub reconnect_delay: u32,
    pub ctrl_loss_tmo: i32,
    pub fast_io_fail_tmo: i32,
    // Transport
    pub transport: NvmeTransportType,
    pub traddr: [u8; 256],
    pub trsvcid: [u8; 32],
    // RDMA options
    pub tos: i32,
    // TCP options
    pub hdr_digest: bool,
    pub data_digest: bool,
    pub tls: bool,
    pub tls_key: u32,
    // Multipath
    pub multipath: bool,
    pub nr_paths: u8,
    pub ana_grpid: u32,
}

/// NVMe-oF discovery
#[derive(Debug, Clone)]
pub struct NvmeDiscoveryEntry {
    pub trtype: NvmeTransportType,
    pub adrfam: NvmeAddrFamily,
    pub subtype: u8,
    pub treq: u8,
    pub portid: u16,
    pub cntlid: u16,
    pub asqsz: u16,
    pub traddr: [u8; 256],
    pub trsvcid: [u8; 32],
    pub subnqn: [u8; 223],
}

// ============================================================================
// Storage Performance Monitoring
// ============================================================================

/// Block I/O latency histogram
#[derive(Debug, Clone)]
pub struct IoLatencyHistogram {
    pub bucket_us: [u64; 32],      // Bucket boundaries in microseconds
    pub counts: [u64; 32],         // Hit counts per bucket
    pub total_ios: u64,
    pub total_latency_us: u64,
    pub min_latency_us: u64,
    pub max_latency_us: u64,
    pub avg_latency_us: u64,
    pub p50_latency_us: u64,
    pub p90_latency_us: u64,
    pub p99_latency_us: u64,
    pub p999_latency_us: u64,
}

/// Block device I/O statistics
#[derive(Debug, Clone)]
pub struct BlockDevStats {
    // Read
    pub read_ios: u64,
    pub read_merges: u64,
    pub read_sectors: u64,
    pub read_ticks_ms: u64,
    // Write
    pub write_ios: u64,
    pub write_merges: u64,
    pub write_sectors: u64,
    pub write_ticks_ms: u64,
    // Discard
    pub discard_ios: u64,
    pub discard_merges: u64,
    pub discard_sectors: u64,
    pub discard_ticks_ms: u64,
    // Flush
    pub flush_ios: u64,
    pub flush_ticks_ms: u64,
    // In-flight
    pub in_flight: u32,
    pub io_ticks_ms: u64,
    pub time_in_queue_ms: u64,
    // Latency histograms
    pub read_latency: IoLatencyHistogram,
    pub write_latency: IoLatencyHistogram,
    // Zxyphor
    pub zxy_qos_throttled: u64,
    pub zxy_qos_redirected: u64,
}

/// Storage QoS policy
#[derive(Debug, Clone)]
pub struct StorageQosPolicy {
    pub max_iops: u64,
    pub max_bandwidth_mbps: u64,
    pub min_iops: u64,
    pub min_bandwidth_mbps: u64,
    pub read_iops_limit: u64,
    pub write_iops_limit: u64,
    pub latency_target_us: u64,
    pub burst_iops: u64,
    pub burst_duration_ms: u32,
    pub priority: u8,
    pub weight: u16,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Storage advanced subsystem
#[derive(Debug, Clone)]
pub struct StorageAdvancedSubsystem {
    // SCSI
    pub nr_scsi_hosts: u32,
    pub nr_scsi_devices: u32,
    pub total_scsi_commands: u64,
    pub total_scsi_errors: u64,
    // DM
    pub nr_dm_targets: u32,
    pub nr_dm_multipath: u32,
    pub nr_dm_thin_pools: u32,
    pub nr_dm_crypt: u32,
    // NVMe Fabrics
    pub nr_nvmeof_hosts: u32,
    pub nr_nvmeof_targets: u32,
    pub nr_nvmeof_connections: u32,
    // QoS
    pub nr_qos_policies: u32,
    pub total_qos_throttles: u64,
    // Zxyphor
    pub zxy_auto_qos: bool,
    pub initialized: bool,
}
