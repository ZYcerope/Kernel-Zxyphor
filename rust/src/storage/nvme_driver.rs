// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced NVMe Driver (Rust)
// Full NVMe 2.0 support with multi-queue, ZNS, KV commands

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// NVMe Register Definitions
// ============================================================================

/// NVMe Controller Registers (BAR0)
#[repr(C)]
pub struct NvmeRegs {
    pub cap: u64,       // Controller Capabilities
    pub vs: u32,        // Version
    pub intms: u32,     // Interrupt Mask Set
    pub intmc: u32,     // Interrupt Mask Clear
    pub cc: u32,        // Controller Configuration
    pub reserved: u32,
    pub csts: u32,      // Controller Status
    pub nssr: u32,      // NVM Subsystem Reset
    pub aqa: u32,       // Admin Queue Attributes
    pub asq: u64,       // Admin Submission Queue Base
    pub acq: u64,       // Admin Completion Queue Base
    pub cmbloc: u32,    // Controller Memory Buffer Location
    pub cmbsz: u32,     // Controller Memory Buffer Size
    pub bpinfo: u32,    // Boot Partition Information
    pub bprsel: u32,    // Boot Partition Read Select
    pub bpmbl: u64,     // Boot Partition Memory Buffer Location
    pub cmbmsc: u64,    // Controller Memory Buffer Memory Space Control
    pub cmbsts: u32,    // Controller Memory Buffer Status
    pub cmbebs: u32,    // Controller Memory Buffer Elasticity Buffer Size
    pub cmbswtp: u32,   // Controller Memory Buffer Sustained Write Throughput
    pub nssd: u32,      // NVM Subsystem Shutdown
    pub crto: u32,      // Controller Ready Timeouts
    pub reserved2: [u32; 869],
    pub pmrcap: u32,    // Persistent Memory Region Capabilities
    pub pmrctl: u32,    // Persistent Memory Region Control
    pub pmrsts: u32,    // Persistent Memory Region Status
    pub pmrebs: u32,    // Persistent Memory Region Elasticity Buffer Size
    pub pmrswtp: u32,   // Persistent Memory Region Sustained Write Throughput
    pub pmrmscl: u32,   // Persistent Memory Region Memory Space Control Lower
    pub pmrmscu: u32,   // Persistent Memory Region Memory Space Control Upper
}

/// CAP register fields
pub mod nvme_cap {
    pub fn mqes(cap: u64) -> u16 { (cap & 0xFFFF) as u16 }
    pub fn cqr(cap: u64) -> bool { (cap >> 16) & 1 != 0 }
    pub fn ams(cap: u64) -> u8 { ((cap >> 17) & 0x3) as u8 }
    pub fn to(cap: u64) -> u8 { ((cap >> 24) & 0xFF) as u8 }
    pub fn dstrd(cap: u64) -> u8 { ((cap >> 32) & 0xF) as u8 }
    pub fn nssrs(cap: u64) -> bool { (cap >> 36) & 1 != 0 }
    pub fn css(cap: u64) -> u8 { ((cap >> 37) & 0xFF) as u8 }
    pub fn bps(cap: u64) -> bool { (cap >> 45) & 1 != 0 }
    pub fn cps(cap: u64) -> u8 { ((cap >> 46) & 0x3) as u8 }
    pub fn mpsmin(cap: u64) -> u8 { ((cap >> 48) & 0xF) as u8 }
    pub fn mpsmax(cap: u64) -> u8 { ((cap >> 52) & 0xF) as u8 }
    pub fn pmrs(cap: u64) -> bool { (cap >> 56) & 1 != 0 }
    pub fn cmbs(cap: u64) -> bool { (cap >> 57) & 1 != 0 }
    pub fn nsss(cap: u64) -> bool { (cap >> 58) & 1 != 0 }
    pub fn crms(cap: u64) -> u8 { ((cap >> 59) & 0x3) as u8 }
}

/// CC register fields
pub mod nvme_cc {
    pub const EN: u32 = 1 << 0;
    pub const CSS_NVM: u32 = 0 << 4;
    pub const MPS_SHIFT: u32 = 7;
    pub const AMS_RR: u32 = 0 << 11;
    pub const AMS_WRR: u32 = 1 << 11;
    pub const AMS_VS: u32 = 7 << 11;
    pub const SHN_NONE: u32 = 0 << 14;
    pub const SHN_NORMAL: u32 = 1 << 14;
    pub const SHN_ABRUPT: u32 = 2 << 14;
    pub const IOSQES_SHIFT: u32 = 16;
    pub const IOCQES_SHIFT: u32 = 20;
}

/// CSTS register fields
pub mod nvme_csts {
    pub const RDY: u32 = 1 << 0;
    pub const CFS: u32 = 1 << 1;
    pub const SHST_MASK: u32 = 3 << 2;
    pub const SHST_NORMAL: u32 = 0 << 2;
    pub const SHST_OCCURRING: u32 = 1 << 2;
    pub const SHST_COMPLETE: u32 = 2 << 2;
    pub const NSSRO: u32 = 1 << 4;
    pub const PP: u32 = 1 << 5;
    pub const ST: u32 = 1 << 6;
}

// ============================================================================
// NVMe Command Structures
// ============================================================================

/// NVMe Submission Queue Entry (64 bytes)
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NvmeSqe {
    pub cdw0: u32,      // Command Dword 0 (opcode, fuse, cid)
    pub nsid: u32,       // Namespace ID
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,       // Metadata Pointer
    pub dptr: [u64; 2],  // Data Pointer (PRP or SGL)
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeSqe {
    pub fn opcode(&self) -> u8 { (self.cdw0 & 0xFF) as u8 }
    pub fn fuse(&self) -> u8 { ((self.cdw0 >> 8) & 0x3) as u8 }
    pub fn psdt(&self) -> u8 { ((self.cdw0 >> 14) & 0x3) as u8 }
    pub fn cid(&self) -> u16 { ((self.cdw0 >> 16) & 0xFFFF) as u16 }

    pub fn set_opcode(&mut self, op: u8) {
        self.cdw0 = (self.cdw0 & !0xFF) | op as u32;
    }

    pub fn set_cid(&mut self, cid: u16) {
        self.cdw0 = (self.cdw0 & 0xFFFF) | ((cid as u32) << 16);
    }
}

/// NVMe Completion Queue Entry (16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct NvmeCqe {
    pub result: u32,     // Command Specific
    pub rsvd: u32,
    pub sq_head: u16,    // SQ Head Pointer
    pub sq_id: u16,      // SQ Identifier
    pub cid: u16,        // Command Identifier
    pub status: u16,     // Status Field (phase bit + status code)
}

impl NvmeCqe {
    pub fn phase(&self) -> bool { self.status & 1 != 0 }
    pub fn sc(&self) -> u8 { ((self.status >> 1) & 0xFF) as u8 }
    pub fn sct(&self) -> u8 { ((self.status >> 9) & 0x7) as u8 }
    pub fn crd(&self) -> u8 { ((self.status >> 12) & 0x3) as u8 }
    pub fn more(&self) -> bool { (self.status >> 14) & 1 != 0 }
    pub fn dnr(&self) -> bool { (self.status >> 15) & 1 != 0 }
    pub fn is_error(&self) -> bool { self.sct() != 0 || self.sc() != 0 }
}

/// Admin Command Opcodes
#[derive(Debug, Clone, Copy)]
pub enum AdminOpcode {
    DeleteIoSq = 0x00,
    CreateIoSq = 0x01,
    GetLogPage = 0x02,
    DeleteIoCq = 0x04,
    CreateIoCq = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventReq = 0x0C,
    NsMgmt = 0x0D,
    FwCommit = 0x10,
    FwImageDl = 0x11,
    DevSelfTest = 0x14,
    NsAttach = 0x15,
    KeepAlive = 0x18,
    DirectiveSend = 0x19,
    DirectiveRecv = 0x1A,
    VirtMgmt = 0x1C,
    NvmeMiSend = 0x1D,
    NvmeMiRecv = 0x1E,
    Sanitize = 0x84,
}

/// NVM Command Opcodes
#[derive(Debug, Clone, Copy)]
pub enum NvmOpcode {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteUncorrectable = 0x04,
    Compare = 0x05,
    WriteZeroes = 0x08,
    DatasetMgmt = 0x09,
    Verify = 0x0C,
    ReservationRegister = 0x0D,
    ReservationReport = 0x0E,
    ReservationAcquire = 0x11,
    ReservationRelease = 0x15,
    Copy = 0x19,
    // Zoned Namespace (ZNS) commands
    ZoneMgmtSend = 0x79,
    ZoneMgmtRecv = 0x7A,
    ZoneAppend = 0x7D,
}

// ============================================================================
// NVMe Queue Management
// ============================================================================

/// NVMe Submission Queue
pub struct NvmeSubmissionQueue {
    pub entries: u64,     // Physical address of SQ entries
    pub size: u16,        // Number of entries
    pub head: u16,        // Head pointer (from CQE)
    pub tail: u16,        // Tail pointer (we update)
    pub qid: u16,
    pub cqid: u16,        // Associated CQ
    pub db_offset: u32,   // Doorbell register offset
    pub phase: bool,
    pub priority: u8,
    // Per-command tracking
    pub cmd_inflight: AtomicU32,
    pub completed: AtomicU64,
    pub submitted: AtomicU64,
}

impl NvmeSubmissionQueue {
    pub fn is_full(&self) -> bool {
        ((self.tail + 1) % self.size) == self.head
    }

    pub fn available(&self) -> u16 {
        if self.tail >= self.head {
            self.size - 1 - (self.tail - self.head)
        } else {
            self.head - self.tail - 1
        }
    }

    pub fn advance_tail(&mut self) -> u16 {
        let old = self.tail;
        self.tail = (self.tail + 1) % self.size;
        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.cmd_inflight.fetch_add(1, Ordering::Relaxed);
        old
    }

    pub fn update_head(&mut self, new_head: u16) {
        let completed = if new_head >= self.head {
            (new_head - self.head) as u32
        } else {
            (self.size - self.head + new_head) as u32
        };
        self.head = new_head;
        self.cmd_inflight.fetch_sub(completed, Ordering::Relaxed);
        self.completed.fetch_add(completed as u64, Ordering::Relaxed);
    }
}

/// NVMe Completion Queue
pub struct NvmeCompletionQueue {
    pub entries: u64,     // Physical address of CQ entries
    pub size: u16,        // Number of entries
    pub head: u16,        // Head pointer (we update)
    pub qid: u16,
    pub db_offset: u32,   // Doorbell register offset
    pub phase: bool,
    pub irq_vector: u16,
    pub irq_enabled: bool,
    pub completions: AtomicU64,
}

impl NvmeCompletionQueue {
    pub fn advance_head(&mut self) {
        self.head = (self.head + 1) % self.size;
        if self.head == 0 {
            self.phase = !self.phase;
        }
        self.completions.fetch_add(1, Ordering::Relaxed);
    }
}

/// NVMe Queue Pair (SQ + CQ)
pub struct NvmeQueuePair {
    pub sq: NvmeSubmissionQueue,
    pub cq: NvmeCompletionQueue,
    pub sq_dma_addr: u64,
    pub cq_dma_addr: u64,
    pub depth: u16,
    pub cpu_affinity: u32,
}

// ============================================================================
// NVMe Controller State
// ============================================================================

/// Identify Controller data structure (partial)
#[repr(C)]
pub struct IdentifyController {
    pub vid: u16,        // PCI Vendor ID
    pub ssvid: u16,      // PCI Subsystem Vendor ID
    pub sn: [u8; 20],    // Serial Number
    pub mn: [u8; 40],    // Model Number
    pub fr: [u8; 8],     // Firmware Revision
    pub rab: u8,         // Recommended Arbitration Burst
    pub ieee: [u8; 3],   // IEEE OUI
    pub cmic: u8,        // Controller Multi-Path I/O
    pub mdts: u8,        // Max Data Transfer Size
    pub cntlid: u16,     // Controller ID
    pub ver: u32,        // NVMe Version
    pub rtd3r: u32,      // RTD3 Resume Latency
    pub rtd3e: u32,      // RTD3 Entry Latency
    pub oaes: u32,       // Optional Async Events Supported
    pub ctratt: u32,     // Controller Attributes
    pub rrls: u16,       // Read Recovery Levels
    pub reserved: [u8; 9],
    pub cntrltype: u8,   // Controller Type
    pub fguid: [u8; 16], // FRU GUID
    pub crdt1: u16,
    pub crdt2: u16,
    pub crdt3: u16,
    pub reserved2: [u8; 106],
    pub reserved3: [u8; 13],
    pub nvmsr: u8,       // NVM Subsystem Report
    pub vwci: u8,        // VPD Write Cycle Info
    pub mec: u8,         // Management Endpoint Capabilities
    pub oacs: u16,       // Optional Admin Command Support
    pub acl: u8,         // Abort Command Limit
    pub aerl: u8,        // Async Event Request Limit
    pub frmw: u8,        // Firmware Updates
    pub lpa: u8,         // Log Page Attributes
    pub elpe: u8,        // Error Log Page Entries
    pub npss: u8,        // Number of Power States
    pub avscc: u8,       // Admin Vendor Specific Command Config
    pub apsta: u8,       // Autonomous Power State Transition Attributes
    pub wctemp: u16,     // Warning Composite Temp Threshold
    pub cctemp: u16,     // Critical Composite Temp Threshold
    pub mtfa: u16,       // Max Time for FW Activation
    pub hmpre: u32,      // Host Memory Buffer Preferred Size
    pub hmmin: u32,      // Host Memory Buffer Min Size
    pub tnvmcap: [u8; 16], // Total NVM Capacity
    pub unvmcap: [u8; 16], // Unallocated NVM Capacity
}

/// Identify Namespace data (partial)
#[repr(C)]
pub struct IdentifyNamespace {
    pub nsze: u64,       // Namespace Size (logical blocks)
    pub ncap: u64,       // Namespace Capacity
    pub nuse: u64,       // Namespace Utilization
    pub nsfeat: u8,      // Namespace Features
    pub nlbaf: u8,       // Number of LBA Formats
    pub flbas: u8,       // Formatted LBA Size
    pub mc: u8,          // Metadata Capabilities
    pub dpc: u8,         // Data Protection Capabilities
    pub dps: u8,         // Data Protection Settings
    pub nmic: u8,        // Namespace Multi-path
    pub rescap: u8,      // Reservation Capabilities
    pub fpi: u8,         // Format Progress Indicator
    pub dlfeat: u8,      // Deallocate Logical Block Features
    pub nawun: u16,      // Namespace Atomic Write Unit Normal
    pub nawupf: u16,     // Namespace Atomic Write Unit Power Fail
    pub nacwu: u16,      // Namespace Atomic Compare & Write Unit
    pub nabsn: u16,      // Namespace Atomic Boundary Size Normal
    pub nabo: u16,       // Namespace Atomic Boundary Offset
    pub nabspf: u16,     // Namespace Atomic Boundary Size Power Fail
    pub noiob: u16,      // Namespace Optimal I/O Boundary
    pub nvmcap: [u8; 16], // NVM Capacity
    pub npwg: u16,       // Namespace Preferred Write Granularity
    pub npwa: u16,       // Namespace Preferred Write Alignment
    pub npdg: u16,       // Namespace Preferred Deallocate Granularity
    pub npda: u16,       // Namespace Preferred Deallocate Alignment
    pub nows: u16,       // Namespace Optimal Write Size
}

/// LBA Format
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LbaFormat {
    pub ms: u16,         // Metadata Size
    pub lbads: u8,       // LBA Data Size (2^n)
    pub rp: u8,          // Relative Performance
}

impl LbaFormat {
    pub fn block_size(&self) -> u32 {
        1u32 << self.lbads
    }
}

/// NVMe Namespace
pub struct NvmeNamespace {
    pub nsid: u32,
    pub lba_count: u64,
    pub block_size: u32,
    pub metadata_size: u16,
    pub capacity_bytes: u64,
    pub lba_format: LbaFormat,
    pub features: u8,
    pub thin_provisioned: bool,
    pub dealloc_supported: bool,
    // ZNS fields
    pub is_zns: bool,
    pub zone_size: u64,
    pub max_open_zones: u32,
    pub max_active_zones: u32,
    pub zone_count: u32,
}

impl NvmeNamespace {
    pub fn capacity_gb(&self) -> u64 {
        self.capacity_bytes / (1024 * 1024 * 1024)
    }
}

// ============================================================================
// NVMe Driver
// ============================================================================

/// Maximum number of I/O queues
pub const MAX_IO_QUEUES: usize = 128;
pub const MAX_NAMESPACES: usize = 32;

/// NVMe Controller
pub struct NvmeController {
    pub regs_base: u64,      // MMIO base address
    pub pci_bdf: u32,        // Bus:Device:Function
    
    // Controller identity
    pub serial: [u8; 20],
    pub model: [u8; 40],
    pub firmware: [u8; 8],
    pub version: u32,
    
    // Capabilities
    pub max_queue_entries: u16,
    pub doorbell_stride: u8,
    pub max_transfer_size: u32,
    pub supports_sgl: bool,
    pub supports_cmb: bool,
    pub supports_pmr: bool,
    
    // Admin queue
    pub admin_sq: Option<NvmeSubmissionQueue>,
    pub admin_cq: Option<NvmeCompletionQueue>,
    
    // I/O queues (one pair per CPU, up to limit)
    pub io_queue_count: u16,
    pub io_sq_depth: u16,
    pub io_cq_depth: u16,
    
    // Namespaces
    pub ns_count: u32,
    pub namespaces: [Option<NvmeNamespace>; MAX_NAMESPACES],
    
    // State
    pub state: NvmeState,
    pub enabled: bool,
    pub shutdown_in_progress: AtomicBool,
    
    // Features
    pub num_irq_vectors: u16,
    pub arbitration: ArbitrationMethod,
    pub power_state: u8,
    pub max_power_states: u8,
    pub temp_threshold_warn: u16,
    pub temp_threshold_crit: u16,
    
    // Statistics
    pub stats: NvmeStats,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NvmeState {
    Uninitialized,
    Initializing,
    Ready,
    Error,
    Resetting,
    ShuttingDown,
    Disabled,
}

#[derive(Debug, Clone, Copy)]
pub enum ArbitrationMethod {
    RoundRobin,
    WeightedRoundRobin,
    VendorSpecific,
}

pub struct NvmeStats {
    pub read_ops: AtomicU64,
    pub write_ops: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub admin_cmds: AtomicU64,
    pub io_errors: AtomicU64,
    pub timeout_errors: AtomicU64,
    pub crc_errors: AtomicU64,
    pub queue_fulls: AtomicU64,
    pub resets: AtomicU64,
    pub host_read_cmds: AtomicU64,
    pub host_write_cmds: AtomicU64,
    pub data_units_read: AtomicU64,
    pub data_units_written: AtomicU64,
    pub power_cycles: AtomicU64,
    pub unsafe_shutdowns: AtomicU64,
    pub media_errors: AtomicU64,
}

impl NvmeStats {
    pub const fn new() -> Self {
        NvmeStats {
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
            admin_cmds: AtomicU64::new(0),
            io_errors: AtomicU64::new(0),
            timeout_errors: AtomicU64::new(0),
            crc_errors: AtomicU64::new(0),
            queue_fulls: AtomicU64::new(0),
            resets: AtomicU64::new(0),
            host_read_cmds: AtomicU64::new(0),
            host_write_cmds: AtomicU64::new(0),
            data_units_read: AtomicU64::new(0),
            data_units_written: AtomicU64::new(0),
            power_cycles: AtomicU64::new(0),
            unsafe_shutdowns: AtomicU64::new(0),
            media_errors: AtomicU64::new(0),
        }
    }
}

impl NvmeController {
    pub fn new(regs_base: u64, pci_bdf: u32) -> Self {
        const NONE_NS: Option<NvmeNamespace> = None;
        NvmeController {
            regs_base,
            pci_bdf,
            serial: [0; 20],
            model: [0; 40],
            firmware: [0; 8],
            version: 0,
            max_queue_entries: 0,
            doorbell_stride: 0,
            max_transfer_size: 0,
            supports_sgl: false,
            supports_cmb: false,
            supports_pmr: false,
            admin_sq: None,
            admin_cq: None,
            io_queue_count: 0,
            io_sq_depth: 1024,
            io_cq_depth: 1024,
            ns_count: 0,
            namespaces: [NONE_NS; MAX_NAMESPACES],
            state: NvmeState::Uninitialized,
            enabled: false,
            shutdown_in_progress: AtomicBool::new(false),
            num_irq_vectors: 0,
            arbitration: ArbitrationMethod::RoundRobin,
            power_state: 0,
            max_power_states: 0,
            temp_threshold_warn: 0,
            temp_threshold_crit: 0,
            stats: NvmeStats::new(),
        }
    }

    /// Build a Read command
    pub fn build_read_cmd(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> NvmeSqe {
        let mut cmd = NvmeSqe {
            cdw0: NvmOpcode::Read as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [prp1, prp2],
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (blocks - 1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        cmd
    }

    /// Build a Write command
    pub fn build_write_cmd(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> NvmeSqe {
        NvmeSqe {
            cdw0: NvmOpcode::Write as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [prp1, prp2],
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (blocks - 1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Build Identify command
    pub fn build_identify_cmd(cns: u8, nsid: u32, prp1: u64) -> NvmeSqe {
        NvmeSqe {
            cdw0: AdminOpcode::Identify as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [prp1, 0],
            cdw10: cns as u32,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Build Create I/O SQ command
    pub fn build_create_sq_cmd(sqid: u16, cqid: u16, size: u16, prp: u64) -> NvmeSqe {
        NvmeSqe {
            cdw0: AdminOpcode::CreateIoSq as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [prp, 0],
            cdw10: (sqid as u32) | (((size - 1) as u32) << 16),
            cdw11: (cqid as u32) << 16 | 0x01, // Physically contiguous
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Build Create I/O CQ command
    pub fn build_create_cq_cmd(cqid: u16, size: u16, vector: u16, prp: u64) -> NvmeSqe {
        NvmeSqe {
            cdw0: AdminOpcode::CreateIoCq as u32,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [prp, 0],
            cdw10: (cqid as u32) | (((size - 1) as u32) << 16),
            cdw11: (vector as u32) << 16 | 0x03, // IEN + PC
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Build Flush command
    pub fn build_flush_cmd(nsid: u32) -> NvmeSqe {
        NvmeSqe {
            cdw0: NvmOpcode::Flush as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [0, 0],
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Build Dataset Management (TRIM/Deallocate) command
    pub fn build_dsm_cmd(nsid: u32, ranges: u32, prp1: u64) -> NvmeSqe {
        NvmeSqe {
            cdw0: NvmOpcode::DatasetMgmt as u32,
            nsid,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [prp1, 0],
            cdw10: ranges - 1,
            cdw11: 0x04, // Attribute: Deallocate
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

// ============================================================================
// ZNS (Zoned Namespace) Support
// ============================================================================

/// Zone State
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZoneState {
    Empty = 0x01,
    ImplicitlyOpened = 0x02,
    ExplicitlyOpened = 0x03,
    Closed = 0x04,
    ReadOnly = 0x0D,
    Full = 0x0E,
    Offline = 0x0F,
}

/// Zone Type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZoneType {
    Sequential = 0x02,
    ConventionalSeq = 0x03,
}

/// Zone Descriptor
#[repr(C)]
pub struct ZoneDescriptor {
    pub zone_type: u8,
    pub zone_state: u8,
    pub zone_attributes: u8,
    pub reserved: [u8; 5],
    pub zone_capacity: u64,  // in logical blocks
    pub zone_start_lba: u64,
    pub write_pointer: u64,
    pub reserved2: [u8; 32],
}

/// Zone Management Send Actions
#[derive(Debug, Clone, Copy)]
pub enum ZmsSendAction {
    Close = 0x01,
    Finish = 0x02,
    Open = 0x03,
    Reset = 0x04,
    Offline = 0x05,
    SetZoneDesc = 0x10,
}

/// Zone Management Receive Actions
#[derive(Debug, Clone, Copy)]
pub enum ZmsRecvAction {
    Report = 0x00,
    ExtendedReport = 0x01,
}

/// Build Zone Append command
pub fn build_zone_append_cmd(nsid: u32, zslba: u64, blocks: u16, prp1: u64, prp2: u64) -> NvmeSqe {
    NvmeSqe {
        cdw0: NvmOpcode::ZoneAppend as u32,
        nsid,
        cdw2: 0,
        cdw3: 0,
        mptr: 0,
        dptr: [prp1, prp2],
        cdw10: zslba as u32,
        cdw11: (zslba >> 32) as u32,
        cdw12: (blocks - 1) as u32,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
    }
}

/// Build Zone Management Send command
pub fn build_zone_mgmt_send(nsid: u32, zslba: u64, action: ZmsSendAction, all: bool) -> NvmeSqe {
    NvmeSqe {
        cdw0: NvmOpcode::ZoneMgmtSend as u32,
        nsid,
        cdw2: 0,
        cdw3: 0,
        mptr: 0,
        dptr: [0, 0],
        cdw10: zslba as u32,
        cdw11: (zslba >> 32) as u32,
        cdw12: 0,
        cdw13: (action as u32) | if all { 1u32 << 8 } else { 0 },
        cdw14: 0,
        cdw15: 0,
    }
}

// ============================================================================
// I/O Scheduler for NVMe
// ============================================================================

/// I/O Priority
#[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
pub enum IoPriority {
    RealTime = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Idle = 4,
}

/// I/O Request
pub struct IoRequest {
    pub lba: u64,
    pub blocks: u32,
    pub is_write: bool,
    pub priority: IoPriority,
    pub nsid: u32,
    pub prp1: u64,
    pub prp2: u64,
    pub deadline: u64,      // Absolute deadline
    pub submitted: u64,     // Submission timestamp
    pub completed: bool,
    pub error: i32,
    pub tag: u32,
}

/// Multi-queue I/O scheduler
pub struct MqScheduler {
    pub algo: MqSchedAlgo,
    pub nr_hw_queues: u16,
    pub queue_depth: u16,
    pub nr_requests: u32,
    pub stats: MqSchedStats,
    // BFQ-specific
    pub bfq_slice: u64,
    pub bfq_timeout: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum MqSchedAlgo {
    None,       // Passthrough (best for NVMe)
    Mq,         // Multi-queue deadline
    Bfq,        // Budget Fair Queuing
    Kyber,      // Kyber (latency-focused)
    ZxyAi,      // Zxyphor AI scheduler
}

pub struct MqSchedStats {
    pub dispatched: AtomicU64,
    pub completed_requests: AtomicU64,
    pub merged: AtomicU64,
    pub requeued: AtomicU64,
    pub read_latency_sum: AtomicU64,
    pub write_latency_sum: AtomicU64,
    pub read_count: AtomicU64,
    pub write_count: AtomicU64,
}

impl MqSchedStats {
    pub const fn new() -> Self {
        MqSchedStats {
            dispatched: AtomicU64::new(0),
            completed_requests: AtomicU64::new(0),
            merged: AtomicU64::new(0),
            requeued: AtomicU64::new(0),
            read_latency_sum: AtomicU64::new(0),
            write_latency_sum: AtomicU64::new(0),
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
        }
    }

    pub fn avg_read_latency(&self) -> u64 {
        let count = self.read_count.load(Ordering::Relaxed);
        if count > 0 {
            self.read_latency_sum.load(Ordering::Relaxed) / count
        } else {
            0
        }
    }

    pub fn avg_write_latency(&self) -> u64 {
        let count = self.write_count.load(Ordering::Relaxed);
        if count > 0 {
            self.write_latency_sum.load(Ordering::Relaxed) / count
        } else {
            0
        }
    }
}
