// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust: MTD/NAND Flash, CAN Bus, I3C Subsystem
// Complete MTD operations, NAND chip/controller, CAN classical/FD,
// ISO-TP, J1939, I3C master/slave, IBI

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// MTD (Memory Technology Device)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MtdType {
    Absent = 0,
    Ram = 1,
    Rom = 2,
    NorFlash = 3,
    NandFlash = 4,
    DataFlash = 6,
    UbiVolume = 7,
    MlcNandFlash = 8,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct MtdFlags: u32 {
        const WRITEABLE  = 0x400;
        const BIT_WRITEABLE = 0x800;
        const NO_ERASE = 0x1000;
        const POWERUP_LOCK = 0x2000;
        const SLC_ON_MLC_EMULATION = 0x4000;
    }
}

#[repr(C)]
pub struct MtdInfo {
    pub mtd_type: MtdType,
    pub flags: MtdFlags,
    pub size: u64,       // Total size
    pub erasesize: u32,  // Erase block size
    pub writesize: u32,  // Minimum write size
    pub writebufsize: u32,
    pub oobsize: u32,    // OOB (spare) size per page
    pub oobavail: u32,   // Available OOB bytes
    pub erasesize_shift: u32,
    pub writesize_shift: u32,
    pub erasesize_mask: u32,
    pub writesize_mask: u32,
    pub bitflip_threshold: u32,
    pub name: [u8; 32],
    pub index: i32,
    pub ecc_stats: MtdEccStats,
    pub subpage_sft: u32,
}

#[repr(C)]
pub struct MtdEccStats {
    pub corrected: u32,
    pub failed: u32,
    pub badblocks: u32,
    pub bbtblocks: u32,
}

#[repr(C)]
pub struct MtdOobOps {
    pub mode: MtdOobMode,
    pub len: u64,
    pub retlen: u64,
    pub ooblen: u64,
    pub oobretlen: u64,
    pub ooboffs: u32,
    pub datbuf: u64,  // *mut u8
    pub oobbuf: u64,  // *mut u8
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MtdOobMode {
    Place = 0,
    Auto = 1,
    Raw = 2,
}

#[repr(C)]
pub struct EraseInfo {
    pub addr: u64,
    pub len: u64,
    pub fail_addr: u64,
    pub state: EraseState,
    pub callback: u64,  // void (*callback)(struct erase_info *)
    pub priv_data: u64,
    pub scrub: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EraseState {
    Pending = 0x01,
    Done = 0x08,
    Failed = 0x10,
}

// ============================================================================
// NAND Flash Controller
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NandEccMode {
    None = 0,
    Soft = 1,
    HwSyndrome = 2,
    Hw = 3,
    HwOobFirst = 4,
    OnDie = 5,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NandEccAlgo {
    Unknown = 0,
    Hamming = 1,
    Bch = 2,
    Rs = 3,
}

#[repr(C)]
pub struct NandEccCtrl {
    pub mode: NandEccMode,
    pub algo: NandEccAlgo,
    pub steps: u32,
    pub size: u32,        // Data bytes per ECC step
    pub bytes: u32,       // ECC bytes per step
    pub total: u32,       // Total ECC bytes per page
    pub strength: u32,    // Max correctable bits per step
    pub prepad: u32,
    pub postpad: u32,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct NandChipOptions: u32 {
        const BUSWIDTH_16    = 0x00000002;
        const NO_BBT        = 0x00000004;
        const NO_SUBPAGE_WRITE = 0x00000008;
        const BROKEN_XD      = 0x00000010;
        const IS_AND         = 0x00000020;
        const CACHEPRG       = 0x00000040;
        const COPYBACK       = 0x00000080;
        const NO_AUTOINCR    = 0x00000100;
        const SKIP_BBTSCAN   = 0x00002000;
        const BBT_SCANNED    = 0x00004000;
        const BBT_SCANLASTPAGE = 0x00008000;
    }
}

#[repr(C)]
pub struct NandChip {
    pub mtd: MtdInfo,
    pub chip_shift: u32,
    pub page_shift: u32,
    pub phys_erase_shift: u32,
    pub bbt_erase_shift: u32,
    pub badblockpos: u32,
    pub badblockbits: u32,
    pub options: NandChipOptions,
    pub ecc: NandEccCtrl,
    pub numchips: u32,
    pub chipsize: u64,
    pub pagemask: u32,
    pub pagebuf: u32,       // Last page in page buffer
    pub subpagesize: u32,
    pub bits_per_cell: u8,
    pub buf_align: u32,
    pub bbt: u64,           // Bad block table
    pub bbt_td: u64,
    pub bbt_md: u64,
    pub badblock_pattern: u64,
    pub controller: u64,    // struct nand_controller *
    pub manufacturer_name: [u8; 32],
    pub dev_id: u8,
    pub mfr_id: u8,
}

// ============================================================================
// NOR Flash / SPI NOR
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpiNorProtocol {
    Single = 0,
    DualOutput = 1,
    DualIO = 2,
    QuadOutput = 3,
    QuadIO = 4,
    OctalDtr = 5,
}

#[repr(C)]
pub struct SpiNorFlash {
    pub mtd: MtdInfo,
    pub protocol: SpiNorProtocol,
    pub page_size: u32,
    pub addr_width: u32,
    pub sector_size: u32,
    pub n_sectors: u32,
    pub flags: u32,
    pub jedec_id: u32,
    pub ext_id: u16,
    pub name: [u8; 32],
    pub manufacturer: [u8; 32],
    pub read_dummy: u8,
    pub program_opcode: u8,
    pub erase_opcode: u8,
    pub read_opcode: u8,
    pub quad_enable_requirement: u8,
}

// ============================================================================
// CAN (Controller Area Network)
// ============================================================================

#[repr(C, packed)]
pub struct CanFrame {
    pub can_id: u32,       // 11/29-bit ID + EFF/RTR/ERR flags
    pub can_dlc: u8,       // Data length code (0-8)
    pub __pad: u8,
    pub __res0: u8,
    pub len8_dlc: u8,
    pub data: [u8; 8],
}

pub const CAN_EFF_FLAG: u32 = 0x80000000; // Extended frame format
pub const CAN_RTR_FLAG: u32 = 0x40000000; // Remote transmission request
pub const CAN_ERR_FLAG: u32 = 0x20000000; // Error frame
pub const CAN_SFF_MASK: u32 = 0x000007FF; // Standard frame ID mask
pub const CAN_EFF_MASK: u32 = 0x1FFFFFFF; // Extended frame ID mask

// CAN FD (Flexible Data-rate)
#[repr(C, packed)]
pub struct CanFdFrame {
    pub can_id: u32,
    pub len: u8,           // 0-64
    pub flags: CanFdFlags,
    pub __res0: u8,
    pub __res1: u8,
    pub data: [u8; 64],
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct CanFdFlags: u8 {
        const BRS = 0x01;     // Bit rate switch
        const ESI = 0x02;     // Error state indicator
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CanState {
    ErrorActive = 0,
    ErrorWarning = 1,
    ErrorPassive = 2,
    BusOff = 3,
    Stopped = 4,
    Sleeping = 5,
}

#[repr(C)]
pub struct CanBittiming {
    pub bitrate: u32,
    pub sample_point: u32,
    pub tq: u32,
    pub prop_seg: u32,
    pub phase_seg1: u32,
    pub phase_seg2: u32,
    pub sjw: u32,
    pub brp: u32,
}

#[repr(C)]
pub struct CanBittimingConst {
    pub name: [u8; 16],
    pub tseg1_min: u32,
    pub tseg1_max: u32,
    pub tseg2_min: u32,
    pub tseg2_max: u32,
    pub sjw_max: u32,
    pub brp_min: u32,
    pub brp_max: u32,
    pub brp_inc: u32,
}

#[repr(C)]
pub struct CanClockInfo {
    pub freq: u32,
}

#[repr(C)]
pub struct CanDeviceStats {
    pub bus_error: u32,
    pub error_warning: u32,
    pub error_passive: u32,
    pub bus_off: u32,
    pub arbitration_lost: u32,
    pub restarts: u32,
}

#[repr(C)]
pub struct CanPriv {
    pub state: CanState,
    pub bittiming: CanBittiming,
    pub data_bittiming: CanBittiming,
    pub bittiming_const: u64,       // *const CanBittimingConst
    pub data_bittiming_const: u64,
    pub clock: CanClockInfo,
    pub ctrlmode: CanCtrlMode,
    pub ctrlmode_supported: CanCtrlMode,
    pub restart_ms: u32,
    pub can_stats: CanDeviceStats,
    pub echo_skb_max: u32,
    pub fd_enabled: bool,
    pub termination: u16,          // Ohms (0=disabled, 120=enabled)
    pub bitrate_max: u32,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct CanCtrlMode: u32 {
        const LOOPBACK       = 0x01;
        const LISTENONLY     = 0x02;
        const TRIPLE_SAMPLING = 0x04;
        const ONE_SHOT       = 0x08;
        const BERR_REPORTING = 0x10;
        const FD             = 0x20;
        const PRESUME_ACK    = 0x40;
        const FD_NON_ISO     = 0x80;
        const CC_LEN8_DLC    = 0x100;
        const TDC_AUTO       = 0x200;
        const TDC_MANUAL     = 0x400;
    }
}

// CAN ISO-TP (ISO 15765-2)
#[repr(C)]
pub struct CanIsotpOpts {
    pub flags: u32,
    pub frame_txtime: u32,   // ns between frames
    pub ext_address: u8,
    pub txpad_content: u8,
    pub rxpad_content: u8,
    pub rx_ext_address: u8,
}

// CAN J1939
#[repr(C)]
pub struct J1939Addr {
    pub name: u64,    // 64-bit ECU name
    pub addr: u8,     // SA (Source Address)
    pub pgn: u32,     // Parameter Group Number
}

// ============================================================================
// I3C (Improved Inter-Integrated Circuit)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum I3cBusMode {
    Pure = 0,
    MixedFast = 1,
    MixedSlow = 2,
    MixedLimited = 3,
}

#[repr(C)]
pub struct I3cDeviceInfo {
    pub pid: u64,         // Provisioned ID (48-bit)
    pub bcr: u8,          // Bus Characteristic Register
    pub dcr: u8,          // Device Characteristic Register
    pub dynamic_addr: u8,
    pub static_addr: u8,
    pub hdr_cap: u8,      // HDR capabilities
    pub max_ibi_len: u8,
}

#[repr(C)]
pub struct I3cMasterController {
    pub this: u64,        // *mut I3cMasterController
    pub bus: u64,         // *mut I3cBus
    pub ops: u64,         // *const I3cMasterControllerOps
    pub sec_master: bool,
    pub init_done: bool,
    pub max_read_len: u16,
    pub max_write_len: u16,
    pub max_ibi_len: u8,
}

#[repr(C)]
pub struct I3cBus {
    pub mode: I3cBusMode,
    pub scl_rate: I3cSclRate,
    pub devs: u64,        // list_head of I3C devices
    pub lock: u64,        // rwlock
    pub id: i32,
    pub addr_slot_status: [u32; 4], // 128 addresses, 2 bits each
    pub cur_master: u64,
}

#[repr(C)]
pub struct I3cSclRate {
    pub i3c: u32,         // Hz
    pub i2c: u32,         // Hz for legacy I2C devices
}

// IBI (In-Band Interrupt) for I3C
#[repr(C)]
pub struct I3cIbiSetup {
    pub max_payload_len: u16,
    pub num_slots: u32,
    pub handler: u64,     // fn handler
}

#[repr(C)]
pub struct I3cCccCmd {
    pub rnw: bool,        // Read not write
    pub id: u8,           // CCC command ID
    pub ndests: u32,
    pub err: i32,
}

// Common CCC IDs
pub const I3C_CCC_ENEC_B: u8 = 0x00;   // Enable Events
pub const I3C_CCC_DISEC_B: u8 = 0x01;  // Disable Events
pub const I3C_CCC_ENTAS0: u8 = 0x02;   // Enter Activity State 0
pub const I3C_CCC_RSTDAA: u8 = 0x06;   // Reset Dynamic Address Assignment
pub const I3C_CCC_ENTDAA: u8 = 0x07;   // Enter DAA
pub const I3C_CCC_DEFSLVS: u8 = 0x08;  // Define List of Slaves
pub const I3C_CCC_SETMWL: u8 = 0x09;   // Set Max Write Length
pub const I3C_CCC_SETMRL: u8 = 0x0A;   // Set Max Read Length
pub const I3C_CCC_GETMWL: u8 = 0x0B;   // Get Max Write Length
pub const I3C_CCC_GETMRL: u8 = 0x0C;   // Get Max Read Length
pub const I3C_CCC_GETPID: u8 = 0x0D;   // Get Provisioned ID
pub const I3C_CCC_GETBCR: u8 = 0x0E;   // Get BCR
pub const I3C_CCC_GETDCR: u8 = 0x0F;   // Get DCR
pub const I3C_CCC_GETSTATUS: u8 = 0x10;
pub const I3C_CCC_GETMXDS: u8 = 0x11;  // Get Max Data Speed
pub const I3C_CCC_SETXTIME: u8 = 0x28;

// ============================================================================
// Combined Manager
// ============================================================================

#[repr(C)]
pub struct MtdCanI3cManager {
    pub mtd_devices: [u64; 16],
    pub num_mtd_devices: u32,
    pub can_interfaces: [u64; 8],
    pub num_can_interfaces: u32,
    pub i3c_buses: [u64; 4],
    pub num_i3c_buses: u32,
    pub total_mtd_reads: AtomicU64,
    pub total_mtd_writes: AtomicU64,
    pub total_mtd_erases: AtomicU64,
    pub total_can_tx: AtomicU64,
    pub total_can_rx: AtomicU64,
    pub total_can_errors: AtomicU64,
    pub total_i3c_transfers: AtomicU64,
    pub total_i3c_ibis: AtomicU64,
    pub initialized: AtomicBool,
}

impl MtdCanI3cManager {
    pub const fn new() -> Self {
        Self {
            mtd_devices: [0u64; 16],
            num_mtd_devices: 0,
            can_interfaces: [0u64; 8],
            num_can_interfaces: 0,
            i3c_buses: [0u64; 4],
            num_i3c_buses: 0,
            total_mtd_reads: AtomicU64::new(0),
            total_mtd_writes: AtomicU64::new(0),
            total_mtd_erases: AtomicU64::new(0),
            total_can_tx: AtomicU64::new(0),
            total_can_rx: AtomicU64::new(0),
            total_can_errors: AtomicU64::new(0),
            total_i3c_transfers: AtomicU64::new(0),
            total_i3c_ibis: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }
}
