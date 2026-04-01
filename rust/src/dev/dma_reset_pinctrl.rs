// Zxyphor Rust - DMA Engine, Reset Controller, Pin Control
// DMA channel management, scatter-gather lists, DMA mapping
// Reset controller framework, reset domains
// Pinctrl: pin groups, functions, mux, config
// Device power domains, PM QoS
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

#![allow(dead_code)]

// ============================================================================
// DMA Mapping Types
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DmaDirection {
    Bidirectional = 0,
    ToDevice = 1,
    FromDevice = 2,
    None = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum DmaAttr {
    WeakOrdering = 1 << 0,
    WriteBarrier = 1 << 1,
    WriteCombine = 1 << 2,
    NonConsistent = 1 << 3,
    NoKernelMapping = 1 << 4,
    SkipCpuSync = 1 << 5,
    ForceContiguous = 1 << 6,
    Alloc32Bit = 1 << 7,
    AllocSinglePages = 1 << 8,
    NoWarn = 1 << 9,
    Privileged = 1 << 10,
}

#[repr(C)]
pub struct DmaMapping {
    pub dma_addr: u64,
    pub size: u64,
    pub direction: DmaDirection,
    pub coherent: bool,
    pub attrs: u32,
}

// ============================================================================
// Scatter-Gather List
// ============================================================================

#[repr(C)]
pub struct ScatterlistEntry {
    pub page_link: u64,
    pub offset: u32,
    pub length: u32,
    pub dma_address: u64,
    pub dma_length: u32,
}

pub struct SgTable {
    pub sgl: [ScatterlistEntry; 256],
    pub nents: u32,
    pub orig_nents: u32,
}

// ============================================================================
// DMA Engine (dmaengine framework)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DmaTransactionType {
    MemCopy = 0,
    XorCompute = 1,
    PqCompute = 2,
    XorVal = 3,
    PqVal = 4,
    Memset = 5,
    MemsetSg = 6,
    Interrupt = 7,
    Private = 8,
    AsyncTx = 9,
    Slave = 10,
    Cyclic = 11,
    Interleave = 12,
    Completion = 13,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DmaTransferDirection {
    MemToMem = 0,
    MemToDev = 1,
    DevToMem = 2,
    DevToDev = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DmaStatus {
    Complete = 0,
    InProgress = 1,
    Paused = 2,
    Error = 3,
    NoTx = 4,
}

pub struct DmaChannelConfig {
    pub direction: DmaTransferDirection,
    pub src_addr: u64,
    pub dst_addr: u64,
    pub src_addr_width: DmaSlaveWidth,
    pub dst_addr_width: DmaSlaveWidth,
    pub src_maxburst: u32,
    pub dst_maxburst: u32,
    pub src_port_window_size: u32,
    pub dst_port_window_size: u32,
    pub device_fc: bool,
    pub peripheral_config: u64,
    pub peripheral_size: u32,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DmaSlaveWidth {
    Undefined = 0,
    Byte1 = 1,
    Byte2 = 2,
    Byte3 = 3,
    Byte4 = 4,
    Byte8 = 8,
    Byte16 = 16,
    Byte32 = 32,
    Byte64 = 64,
}

pub struct DmaChannel {
    pub id: u32,
    pub name: [u8; 32],
    pub device_id: u32,
    pub config: DmaChannelConfig,
    pub status: DmaStatus,
    pub cookie: u64,
    pub completed_cookie: u64,
    pub private: bool,
    // Stats
    pub bytes_transferred: u64,
    pub memcpy_count: u64,
    pub in_use: bool,
}

pub struct DmaDevice {
    pub id: u32,
    pub name: [u8; 64],
    pub channels: u32,
    pub max_sg_burst: u32,
    pub residue_granularity: DmaResidueGranularity,
    pub copy_align: u8,
    pub xor_align: u8,
    pub pq_align: u8,
    pub fill_align: u8,
    pub cap_mask: u64,
    // Stats
    pub total_transfers: u64,
    pub total_bytes: u64,
    pub errors: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DmaResidueGranularity {
    Descriptor = 0,
    Segment = 1,
    Burst = 2,
}

// ============================================================================
// DMA Fence (GPU sync)
// ============================================================================

pub struct DmaFence {
    pub context: u64,
    pub seqno: u64,
    pub flags: DmaFenceFlags,
    pub timestamp: u64,
    pub error: i32,
}

pub struct DmaFenceFlags {
    pub signaled_bit: bool,
    pub timestamp_bit: bool,
    pub enable_signal_bit: bool,
    pub user_bits: u32,
}

// ============================================================================
// Reset Controller Framework
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ResetState {
    Asserted = 0,
    Deasserted = 1,
    Unknown = 2,
}

pub struct ResetController {
    pub id: u32,
    pub name: [u8; 64],
    pub nr_resets: u32,
    pub ops: ResetOps,
    pub exclusive: bool,
}

pub struct ResetOps {
    pub reset: Option<fn(u32, u64) -> i32>,
    pub assert: Option<fn(u32, u64) -> i32>,
    pub deassert: Option<fn(u32, u64) -> i32>,
    pub status: Option<fn(u32, u64) -> ResetState>,
}

pub struct ResetControl {
    pub rcdev_id: u32,
    pub id: u64,
    pub shared: bool,
    pub acquired: bool,
    pub deassert_count: u32,
    pub triggered_count: u32,
}

// ============================================================================
// Pin Controller (Pinctrl)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PinFunction {
    Gpio = 0,
    Alternate0 = 1,
    Alternate1 = 2,
    Alternate2 = 3,
    Alternate3 = 4,
    Alternate4 = 5,
    Alternate5 = 6,
    Alternate6 = 7,
    Alternate7 = 8,
    Analog = 9,
    Special = 10,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PinConfigType {
    BiasDisable = 0,
    BiasHighImpedance = 1,
    BiasBusHold = 2,
    BiasPullUp = 3,
    BiasPullDown = 4,
    BiasPullPin = 5,
    DriveOpenDrain = 6,
    DriveOpenSource = 7,
    DrivePushPull = 8,
    DriveStrength = 9,
    DriveStrengthUa = 10,
    InputDebounce = 11,
    InputEnable = 12,
    InputSchmittEnable = 13,
    LowPowerMode = 14,
    OutputEnable = 15,
    Output = 16,
    PowerSource = 17,
    SlewRate = 18,
    InputSchmitt = 19,
    Persist = 20,
}

pub struct PinGroup {
    pub name: [u8; 32],
    pub pins: [u32; 32],
    pub num_pins: u32,
}

pub struct PinMuxFunction {
    pub name: [u8; 32],
    pub groups: [u32; 16],
    pub num_groups: u32,
}

pub struct PinctrlDevice {
    pub id: u32,
    pub name: [u8; 64],
    pub npins: u32,
    pub ngroups: u32,
    pub nfunctions: u32,
    // Pin state
    pub groups: [PinGroup; 64],
    pub functions: [PinMuxFunction; 32],
}

pub struct PinctrlState {
    pub name: [u8; 32],
    pub settings_count: u32,
}

pub struct PinctrlSetting {
    pub pin_or_group: u32,
    pub func: PinFunction,
    pub config_type: PinConfigType,
    pub config_value: u32,
}

// ============================================================================
// Device Power Domain (genpd)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum GpdStatus {
    Active = 0,
    PowerOff = 1,
    WaitMaster = 2,
    BusyResume = 3,
}

pub struct GenericPowerDomain {
    pub name: [u8; 64],
    pub id: u32,
    pub status: GpdStatus,
    pub device_count: u32,
    pub sd_count: u32,   // subdomain count
    pub performance_state: u32,
    pub max_off_time_ns: u64,
    pub max_off_time_changed: bool,
    pub provider: bool,
    pub has_provider: bool,
    pub account_time_on: u64,
    pub account_time_off: u64,
    pub suspend_count: u64,
    pub resume_count: u64,
}

pub struct GpdTimingData {
    pub suspend_latency_ns: u64,
    pub resume_latency_ns: u64,
    pub effective_constraint_ns: u64,
    pub constraint_changed: bool,
}

// ============================================================================
// PM QoS (Quality of Service)
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PmQosType {
    CpuDmaLatency = 0,
    ResumeLatency = 1,
    LatencyTolerance = 2,
    MinFrequency = 3,
    MaxFrequency = 4,
    Flags = 5,
}

pub struct PmQosRequest {
    pub qos_type: PmQosType,
    pub value: i64,
    pub dev_id: u32,
    pub active: bool,
}

pub struct PmQosConstraints {
    pub target_val: i64,
    pub default_val: i64,
    pub no_constraint_val: i64,
    pub constraint_type: PmQosConstraintType,
    pub num_requests: u32,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum PmQosConstraintType {
    MinValue = 0,
    MaxValue = 1,
    Sum = 2,
}

// ============================================================================
// Device/DMA/Pinctrl Subsystem Manager
// ============================================================================

pub struct DevPlatformManager {
    // DMA
    pub dma_devices: u32,
    pub dma_channels_total: u32,
    pub dma_channels_in_use: u32,
    pub dma_total_transfers: u64,
    pub dma_total_bytes: u64,
    pub dma_errors: u64,
    // Reset Controllers
    pub reset_controllers: u32,
    pub total_resets: u64,
    pub total_asserts: u64,
    pub total_deasserts: u64,
    // Pinctrl
    pub pinctrl_devices: u32,
    pub total_pins_configured: u32,
    pub total_mux_operations: u64,
    // Power Domains
    pub power_domains: u32,
    pub domains_active: u32,
    pub domains_off: u32,
    pub total_suspend_cycles: u64,
    // PM QoS
    pub qos_requests_active: u32,
    pub qos_violations: u64,
    // State
    pub initialized: bool,
}

impl DevPlatformManager {
    pub fn new() -> Self {
        Self {
            dma_devices: 0,
            dma_channels_total: 0,
            dma_channels_in_use: 0,
            dma_total_transfers: 0,
            dma_total_bytes: 0,
            dma_errors: 0,
            reset_controllers: 0,
            total_resets: 0,
            total_asserts: 0,
            total_deasserts: 0,
            pinctrl_devices: 0,
            total_pins_configured: 0,
            total_mux_operations: 0,
            power_domains: 0,
            domains_active: 0,
            domains_off: 0,
            total_suspend_cycles: 0,
            qos_requests_active: 0,
            qos_violations: 0,
            initialized: true,
        }
    }
}
