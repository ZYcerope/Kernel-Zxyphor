// Zxyphor Rust - NVMe Queue Pairs, Submission/Completion,
// NVMe Namespace Management, NVMe-oF RDMA/TCP transport,
// ZNS (Zoned Namespace) support, NVMe multipath I/O,
// NVMe power management, NVMe security (TCG Opal),
// NVMe telemetry & health monitoring
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

#![allow(dead_code)]

// ============================================================================
// NVMe Queue Pair Management
// ============================================================================

#[repr(C)]
pub struct NvmeQueuePair {
    pub qid: u16,
    pub q_depth: u16,
    pub sq_head: u16,
    pub sq_tail: u16,
    pub cq_head: u16,
    pub cq_phase: bool,
    pub sq_doorbell: u64,
    pub cq_doorbell: u64,
    pub sq_cmds: Vec<NvmeSubmissionEntry>,
    pub cq_entries: Vec<NvmeCompletionEntry>,
    pub sq_dma_addr: u64,
    pub cq_dma_addr: u64,
    pub irq_vector: u32,
    pub cmd_ids: Vec<NvmeCmdInfo>,
}

#[repr(C, packed)]
pub struct NvmeSubmissionEntry {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub metadata: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

#[repr(C, packed)]
pub struct NvmeCompletionEntry {
    pub result: u64,
    pub sq_head: u16,
    pub sq_id: u16,
    pub command_id: u16,
    pub status: u16,
}

pub struct NvmeCmdInfo {
    pub cmd_id: u16,
    pub opcode: u8,
    pub flags: NvmeCmdFlags,
    pub timeout_jiffies: u64,
    pub result: u64,
    pub status: NvmeStatusCode,
    pub callback: Option<fn(u16, NvmeStatusCode, u64)>,
}

#[derive(Clone, Copy, Debug)]
pub struct NvmeCmdFlags {
    pub fused_first: bool,
    pub fused_second: bool,
    pub prp_or_sgl: bool,
}

// ============================================================================
// NVMe Status Codes
// ============================================================================

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NvmeStatusCode {
    Success = 0x0000,
    InvalidOpcode = 0x0001,
    InvalidField = 0x0002,
    CommandIdConflict = 0x0003,
    DataTransferError = 0x0004,
    PowerLossAbort = 0x0005,
    InternalError = 0x0006,
    AbortRequested = 0x0007,
    AbortSqDeletion = 0x0008,
    AbortFailedFuse = 0x0009,
    AbortMissingFuse = 0x000A,
    InvalidNamespace = 0x000B,
    CommandSequenceError = 0x000C,
    InvalidSglDesc = 0x000D,
    InvalidSglCount = 0x000E,
    InvalidDataSgl = 0x000F,
    InvalidMetadataSgl = 0x0010,
    InvalidSglType = 0x0011,
    InvalidCmbUsage = 0x0012,
    InvalidPrpOffset = 0x0013,
    AtomicWriteUnitExceeded = 0x0014,
    OperationDenied = 0x0015,
    InvalidSglOffset = 0x0016,
    HostPathError = 0x0070,
    AbortCmdSetNotSupported = 0x0071,
    // Media errors
    WriteFault = 0x0280,
    UnrecoveredReadError = 0x0281,
    EndToEndGuardCheck = 0x0282,
    EndToEndAppTagCheck = 0x0283,
    EndToEndRefTagCheck = 0x0284,
    CompareFailure = 0x0285,
    AccessDenied = 0x0286,
    DeallocatedOrUnwritten = 0x0287,
    EndToEndStorageTagCheck = 0x0288,
    // Path-related
    InternalPathError = 0x0300,
    AsymmetricAccessPersistent = 0x0301,
    AsymmetricAccessInaccessible = 0x0302,
    AsymmetricAccessTransition = 0x0303,
    ControllerPathError = 0x0360,
    HostPathErrorRetry = 0x0370,
    HostAbortCmd = 0x0371,
}

// ============================================================================
// NVMe Namespace Management
// ============================================================================

pub struct NvmeNamespace {
    pub nsid: u32,
    pub eui64: u64,
    pub nguid: [u8; 16],
    pub uuid: [u8; 16],
    pub nsze: u64,       // namespace size
    pub ncap: u64,       // namespace capacity
    pub nuse: u64,       // namespace utilization
    pub lba_size: u32,
    pub metadata_size: u16,
    pub lba_shift: u8,
    pub nmic: NvmeNsMicFlags,
    pub flbas: u8,
    pub dps: u8,         // end-to-end data protection
    pub features: NvmeNsFeatures,
    pub ana_state: NvmeAnaState,
    pub zns: Option<NvmeZnsNamespace>,
}

#[derive(Clone, Copy, Debug)]
pub struct NvmeNsMicFlags {
    pub shared: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct NvmeNsFeatures {
    pub thin_provisioning: bool,
    pub ns_atomic_write_unit: bool,
    pub deallocated_or_unwritten_error: bool,
    pub guid_never_reused: bool,
    pub optimal_io_boundary: u16,
    pub nvm_capacity: u128,
    pub preferred_write_granularity: u16,
    pub preferred_write_alignment: u16,
    pub preferred_dealloc_granularity: u16,
    pub preferred_dealloc_alignment: u16,
    pub optimal_write_size: u16,
}

pub struct NvmeNsIdDesc {
    pub nidt: NvmeNsIdType,
    pub nidl: u8,
    pub nid: [u8; 16],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum NvmeNsIdType {
    Ieee = 1,
    Nguid = 2,
    Uuid = 3,
    Csi = 4,
}

// ============================================================================
// NVMe ANA (Asymmetric Namespace Access)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NvmeAnaState {
    Optimized = 0x01,
    NonOptimized = 0x02,
    Inaccessible = 0x03,
    PersistentLoss = 0x04,
    Change = 0x0F,
}

pub struct NvmeAnaGroupDesc {
    pub grpid: u32,
    pub nnsids: u32,
    pub chgcnt: u64,
    pub state: NvmeAnaState,
    pub nsids: Vec<u32>,
}

pub struct NvmeMultipathConfig {
    pub policy: NvmeMultipathPolicy,
    pub num_paths: u8,
    pub active_paths: u8,
    pub ana_groups: Vec<NvmeAnaGroupDesc>,
    pub io_stats_per_path: Vec<NvmePathStats>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum NvmeMultipathPolicy {
    None = 0,
    RoundRobin = 1,
    NumaOptimized = 2,
    QueueDepth = 3,
    Latency = 4,
}

pub struct NvmePathStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ios: u64,
    pub write_ios: u64,
    pub avg_latency_ns: u64,
    pub errors: u64,
}

// ============================================================================
// ZNS (Zoned Namespace)
// ============================================================================

pub struct NvmeZnsNamespace {
    pub zone_size: u64,
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub total_zones: u32,
    pub zones: Vec<NvmeZoneDescriptor>,
    pub zrwa_support: bool,
    pub zrwa_flush_gran: u32,
}

#[repr(C)]
pub struct NvmeZoneDescriptor {
    pub zone_type: NvmeZoneType,
    pub zone_state: NvmeZoneState,
    pub zone_attrs: u8,
    pub wp: u64,         // write pointer
    pub zslba: u64,      // zone start LBA
    pub zcap: u64,       // zone capacity
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NvmeZoneType {
    SeqWriteRequired = 0x02,
    SeqWritePreferred = 0x03,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NvmeZoneState {
    Empty = 0x01,
    ImplicitlyOpen = 0x02,
    ExplicitlyOpen = 0x03,
    Closed = 0x04,
    ReadOnly = 0x0D,
    Full = 0x0E,
    Offline = 0x0F,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum NvmeZoneAction {
    Close = 0x01,
    Finish = 0x02,
    Open = 0x03,
    Reset = 0x04,
    Offline = 0x05,
    SetZoneDesc = 0x10,
    ZrwaFlush = 0x11,
}

// ============================================================================
// NVMe-oF (NVMe over Fabrics)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum NvmeFabricTransport {
    Rdma = 0x01,
    FibreChannel = 0x02,
    Tcp = 0x03,
    IntraPcie = 0xFE,
    IntraHost = 0xFF,
}

pub struct NvmeFabricConfig {
    pub transport: NvmeFabricTransport,
    pub traddr: [u8; 256],
    pub trsvcid: [u8; 32],
    pub host_traddr: [u8; 256],
    pub host_iface: [u8; 32],
    pub nqn: [u8; 256],       // NVMe Qualified Name
    pub hostnqn: [u8; 256],
    pub hostid: [u8; 16],
    pub ctrl_loss_timeout: i32,
    pub reconnect_delay: u32,
    pub fast_io_fail_timeout: i32,
    pub nr_io_queues: u32,
    pub nr_write_queues: u32,
    pub nr_poll_queues: u32,
    pub queue_size: u32,
    pub keep_alive_tmo: u32,
    pub duplicate_connect: bool,
    pub disable_sqflow: bool,
    pub hdr_digest: bool,
    pub data_digest: bool,
    pub tls: bool,
    pub concat: bool,
}

pub struct NvmeFabricConnectCmd {
    pub opcode: u8,         // 0x7F
    pub flags: u8,
    pub command_id: u16,
    pub fctype: u8,         // 0x01 = connect
    pub reserved1: [19]u8,
    pub sgl1: [16]u8,
    pub recfmt: u16,
    pub qid: u16,
    pub sqsize: u16,
    pub cattr: u8,
    pub reserved2: u8,
    pub kato: u32,          // keep alive timeout
    pub reserved3: [12]u8,
}

pub struct NvmeFabricPropertySet {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub fctype: u8,         // 0x00
    pub reserved: [35]u8,
    pub attrib: u8,
    pub reserved2: [3]u8,
    pub offset: u32,
    pub value: u64,
    pub reserved3: [8]u8,
}

// ============================================================================
// NVMe Telemetry & Health
// ============================================================================

pub struct NvmeSmartLog {
    pub critical_warning: NvmeCriticalWarning,
    pub temperature: u16,
    pub avail_spare: u8,
    pub spare_thresh: u8,
    pub percent_used: u8,
    pub endurance_grp_critical_summary: u8,
    pub reserved: [25]u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_reads: u128,
    pub host_writes: u128,
    pub ctrl_busy_time: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub num_err_log_entries: u128,
    pub warning_temp_time: u32,
    pub critical_comp_time: u32,
    pub temp_sensor: [8]u16,
    pub thm_temp1_trans_count: u32,
    pub thm_temp2_trans_count: u32,
    pub thm_temp1_total_time: u32,
    pub thm_temp2_total_time: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct NvmeCriticalWarning {
    pub available_spare: bool,
    pub temperature: bool,
    pub device_reliability: bool,
    pub read_only: bool,
    pub volatile_memory_backup: bool,
    pub pmr_degraded: bool,
}

pub struct NvmeTelemetryLog {
    pub log_identifier: u8,
    pub ieee_oui: [u8; 3],
    pub data_area_1_blocks: u16,
    pub data_area_2_blocks: u16,
    pub data_area_3_blocks: u16,
    pub data_area_4_blocks: u32,
    pub ctrl_initiated: bool,
    pub reason_id: [u8; 128],
    pub host_data_generation: u8,
}

// ============================================================================
// NVMe TCG Opal Security
// ============================================================================

pub struct NvmeSecurityConfig {
    pub opal_supported: bool,
    pub opal_version: u8,
    pub sed_locked: bool,
    pub max_ranges: u8,
    pub encryption_enabled: bool,
    pub pyrite_supported: bool,
    pub ruby_supported: bool,
}

// ============================================================================
// NVMe Power Management
// ============================================================================

pub struct NvmePowerState {
    pub max_power: u16,       // centiwatts
    pub flags: u8,
    pub entry_lat: u32,       // microseconds
    pub exit_lat: u32,        // microseconds
    pub read_throughput: u8,
    pub read_latency: u8,
    pub write_throughput: u8,
    pub write_latency: u8,
    pub idle_power: u16,
    pub idle_scale: u8,
    pub active_power: u16,
    pub active_work_scale: u8,
}

pub struct NvmePmConfig {
    pub num_power_states: u8,
    pub current_state: u8,
    pub apst_enabled: bool,      // Autonomous Power State Transition
    pub states: [NvmePowerState; 32],
    pub apst_entries: [NvmeApstEntry; 32],
}

pub struct NvmeApstEntry {
    pub idle_time_ms: u32,
    pub target_state: u8,
}

// ============================================================================
// NVMe Controller Manager
// ============================================================================

pub struct NvmeControllerManager {
    pub ctrl_id: u16,
    pub model: [u8; 40],
    pub serial: [u8; 20],
    pub firmware_rev: [u8; 8],
    pub ieee_oui: [u8; 3],
    pub max_hw_sectors: u32,
    pub stripe_size: u32,
    pub max_namespaces: u32,
    pub queue_count: u16,
    pub max_queue_depth: u16,
    pub sqe_size: u8,
    pub cqe_size: u8,
    pub doorbell_stride: u8,
    pub abort_limit: u8,
    pub vwc: u8,
    pub sgls: u32,
    pub multipath: Option<NvmeMultipathConfig>,
    pub fabric: Option<NvmeFabricConfig>,
    pub pm: NvmePmConfig,
    pub security: NvmeSecurityConfig,
    pub namespaces: Vec<NvmeNamespace>,
    pub queue_pairs: Vec<NvmeQueuePair>,
    pub initialized: bool,
}

impl NvmeControllerManager {
    pub fn new() -> Self {
        Self {
            ctrl_id: 0,
            model: [0u8; 40],
            serial: [0u8; 20],
            firmware_rev: [0u8; 8],
            ieee_oui: [0; 3],
            max_hw_sectors: 0,
            stripe_size: 0,
            max_namespaces: 0,
            queue_count: 0,
            max_queue_depth: 0,
            sqe_size: 64,
            cqe_size: 16,
            doorbell_stride: 0,
            abort_limit: 0,
            vwc: 0,
            sgls: 0,
            multipath: None,
            fabric: None,
            pm: NvmePmConfig {
                num_power_states: 0,
                current_state: 0,
                apst_enabled: false,
                states: [NvmePowerState {
                    max_power: 0, flags: 0, entry_lat: 0, exit_lat: 0,
                    read_throughput: 0, read_latency: 0, write_throughput: 0,
                    write_latency: 0, idle_power: 0, idle_scale: 0,
                    active_power: 0, active_work_scale: 0,
                }; 32],
                apst_entries: [NvmeApstEntry { idle_time_ms: 0, target_state: 0 }; 32],
            },
            security: NvmeSecurityConfig {
                opal_supported: false, opal_version: 0, sed_locked: false,
                max_ranges: 0, encryption_enabled: false, pyrite_supported: false,
                ruby_supported: false,
            },
            namespaces: Vec::new(),
            queue_pairs: Vec::new(),
            initialized: false,
        }
    }
}
