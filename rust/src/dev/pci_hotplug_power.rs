// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel (Rust) - PCI Hotplug & Device Power States
// Complete: PCI Express hotplug, standard PCI hotplug, SHPC,
// device power management (D0-D3), runtime PM, wake signals,
// PCI config space save/restore, link state management

// ============================================================================
// PCI Power States
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciPowerState {
    D0 = 0,       // Fully operational
    D1 = 1,       // Light sleep
    D2 = 2,       // Deeper sleep
    D3Hot = 3,    // D3 with Vcc maintained
    D3Cold = 4,   // D3 with Vcc removed
    Unknown = 5,  // Unknown / new device
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PciD3ColdBehavior {
    Default = 0,
    Allow = 1,
    Forbid = 2,
}

#[derive(Debug, Clone)]
pub struct PciPmCap {
    pub cap_offset: u16,
    pub version: u8,
    pub pme_support: PciPmeSupport,
    pub dsi: bool,          // Device Specific Initialization
    pub aux_current: u16,   // Auxiliary current in mA
    pub d1_support: bool,
    pub d2_support: bool,
    pub no_soft_reset: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PciPmeSupport {
    pub d0: bool,
    pub d1: bool,
    pub d2: bool,
    pub d3_hot: bool,
    pub d3_cold: bool,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct PciPowerManagement {
    pub current_state: PciPowerState,
    pub target_state: PciPowerState,
    pub sleep_wake: bool,
    pub runtime_d3cold: bool,
    pub d3cold_allowed: PciD3ColdBehavior,
    pub no_d1d2: bool,
    pub d3_delay: u32,       // D3-to-D0 transition delay in ms
    pub d3cold_delay: u32,   // D3cold-to-D0 delay in ms
    pub wakeup_prepared: bool,
    pub pme_interrupt: bool,
    pub pme_poll: bool,
    pub pme_support: PciPmeSupport,
    pub pm_cap: Option<PciPmCap>,
    pub saved_state: Option<Box<PciSavedState>>,
    pub runtime_pm: PciRuntimePm,
}

// ============================================================================
// PCI Config Space Save/Restore
// ============================================================================

pub const PCI_CFG_SPACE_SIZE: usize = 256;
pub const PCI_CFG_SPACE_EXP_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct PciSavedState {
    pub config_space: [u32; 16],    // Standard config header (64 bytes)
    pub saved_cap_space: Vec<PciCapSaved>,
    pub saved_ext_cap_space: Vec<PciExtCapSaved>,
    pub msi_state: Option<PciMsiSavedState>,
    pub msix_state: Option<PciMsixSavedState>,
}

#[derive(Debug, Clone)]
pub struct PciCapSaved {
    pub cap_id: u8,
    pub cap_offset: u16,
    pub data: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct PciExtCapSaved {
    pub cap_id: u16,
    pub cap_version: u8,
    pub cap_offset: u16,
    pub data: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct PciMsiSavedState {
    pub control: u16,
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u16,
    pub mask: u32,
    pub pending: u32,
}

#[derive(Debug, Clone)]
pub struct PciMsixSavedState {
    pub control: u16,
    pub nr_entries: u32,
    pub entries: Vec<PciMsixEntrySaved>,
}

#[derive(Debug, Clone)]
pub struct PciMsixEntrySaved {
    pub entry: u32,
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub vector_ctrl: u32,
}

// ============================================================================
// Runtime PM
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePmStatus {
    Active = 0,
    Resuming = 1,
    Suspended = 2,
    Suspending = 3,
}

#[derive(Debug, Clone)]
pub struct PciRuntimePm {
    pub status: RuntimePmStatus,
    pub usage_count: i32,
    pub child_count: i32,
    pub disable_depth: i32,
    pub autosuspend_delay: i32,   // ms
    pub last_busy: u64,
    pub timer_expires: u64,
    pub request_pending: bool,
    pub deferred_resume: bool,
    pub run_wake: bool,
    pub irq_safe: bool,
    pub no_callbacks: bool,
    pub ignore_children: bool,
    pub runtime_auto: bool,
    pub accounting_timestamp: u64,
    pub total_time_suspended: u64,
    pub total_time_active: u64,
    pub suspend_count: u64,
    pub resume_count: u64,
}

// ============================================================================
// Link State Management
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PcieLinkSpeed {
    Gen1 = 1,    // 2.5 GT/s
    Gen2 = 2,    // 5.0 GT/s
    Gen3 = 3,    // 8.0 GT/s
    Gen4 = 4,    // 16.0 GT/s
    Gen5 = 5,    // 32.0 GT/s
    Gen6 = 6,    // 64.0 GT/s
    Gen7 = 7,    // 128.0 GT/s
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PcieLinkWidth {
    X1 = 1,
    X2 = 2,
    X4 = 4,
    X8 = 8,
    X12 = 12,
    X16 = 16,
    X32 = 32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PcieAspmPolicy {
    Disabled = 0,
    L0s = 1,
    L1 = 2,
    L0sL1 = 3,
    Default = 4,
    Performance = 5,
    PowerSave = 6,
    PowerSupersave = 7,
}

#[derive(Debug, Clone)]
pub struct PcieLinkState {
    pub current_speed: PcieLinkSpeed,
    pub current_width: PcieLinkWidth,
    pub max_speed: PcieLinkSpeed,
    pub max_width: PcieLinkWidth,
    pub aspm_support: u32,
    pub aspm_enabled: u32,
    pub aspm_disable: u32,
    pub aspm_l1ss_support: bool,
    pub aspm_l1_1: bool,
    pub aspm_l1_2: bool,
    pub aspm_pcipm_l1_1: bool,
    pub aspm_pcipm_l1_2: bool,
    pub clkpm: bool,
    pub clkpm_capable: bool,
    pub link_active: bool,
    pub link_training: bool,
    pub slot_clock_config: bool,
    pub data_link_active: bool,
    pub ltr_enabled: bool,
    pub obff_type: u8,
}

// ============================================================================
// PCI Hotplug Controller
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugControllerType {
    PcieNativeHotplug = 0,
    Shpc = 1,                // Standard Hot-Plug Controller
    PciHotplug = 2,          // Legacy PCI hotplug
    Acpi = 3,                // ACPI-based
    Thunderbolt = 4,
    CxlPort = 5,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotPowerState {
    Off = 0,
    On = 1,
    Unknown = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotAdapterStatus {
    Empty = 0,
    Present = 1,
    Unknown = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotLatchStatus {
    Open = 0,
    Closed = 1,
    Unknown = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotAttentionIndicator {
    Off = 0,
    On = 1,
    Blinking = 2,
    Unknown = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotPowerIndicator {
    Off = 0,
    On = 1,
    Blinking = 2,
    Unknown = 3,
}

#[derive(Debug, Clone)]
pub struct HotplugSlotOps {
    pub enable_slot: Option<fn(slot: &HotplugSlot) -> i32>,
    pub disable_slot: Option<fn(slot: &HotplugSlot) -> i32>,
    pub set_attention_status: Option<fn(slot: &HotplugSlot, status: SlotAttentionIndicator) -> i32>,
    pub hardware_test: Option<fn(slot: &HotplugSlot, value: u32) -> i32>,
    pub get_power_status: Option<fn(slot: &HotplugSlot) -> SlotPowerState>,
    pub get_attention_status: Option<fn(slot: &HotplugSlot) -> SlotAttentionIndicator>,
    pub get_latch_status: Option<fn(slot: &HotplugSlot) -> SlotLatchStatus>,
    pub get_adapter_status: Option<fn(slot: &HotplugSlot) -> SlotAdapterStatus>,
    pub reset_slot: Option<fn(slot: &HotplugSlot, probe: bool) -> i32>,
}

#[derive(Debug)]
pub struct HotplugSlot {
    pub name: [u8; 64],
    pub slot_nr: u32,
    pub ctrl: HotplugControllerType,
    pub ops: HotplugSlotOps,
    pub power: SlotPowerState,
    pub adapter: SlotAdapterStatus,
    pub latch: SlotLatchStatus,
    pub attention: SlotAttentionIndicator,
    pub power_indicator: SlotPowerIndicator,
    pub info: HotplugSlotInfo,
    pub bus: u8,
    pub devfn: u8,
    pub is_surprise: bool,
}

#[derive(Debug, Clone)]
pub struct HotplugSlotInfo {
    pub hardware_id: [u8; 64],
    pub firmware_version: u32,
    pub address: u64,
    pub max_bus_speed: PcieBusSpeed,
    pub cur_bus_speed: PcieBusSpeed,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PcieBusSpeed {
    Speed33MHz = 0,
    Speed66MHz = 1,
    Speed100MHz = 2,
    Speed133MHz = 3,
    PcieGen1 = 4,
    PcieGen2 = 5,
    PcieGen3 = 6,
    PcieGen4 = 7,
    PcieGen5 = 8,
    PcieGen6 = 9,
    Unknown = 255,
}

// ============================================================================
// PCIe Native Hotplug
// ============================================================================

#[derive(Debug, Clone)]
pub struct PcieHotplugCtrl {
    pub slot_cap: PcieSlotCap,
    pub slot_ctrl: PcieSlotCtrl,
    pub slot_status: PcieSlotStatus,
    pub cmd_busy: bool,
    pub pending_events: u32,
    pub notification_enabled: bool,
    pub state: PcieHpState,
    pub request_result: i32,
    pub poll_active: bool,
    pub inband_presence_disabled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PcieSlotCap {
    pub attn_button: bool,
    pub power_ctrl: bool,
    pub mrl_sensor: bool,
    pub attn_indicator: bool,
    pub power_indicator: bool,
    pub hotplug_surprise: bool,
    pub hotplug_capable: bool,
    pub slot_power_limit_value: u16,
    pub slot_power_limit_scale: u8,
    pub electromech_interlock: bool,
    pub no_cmd_complete: bool,
    pub physical_slot_number: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct PcieSlotCtrl {
    pub attn_button_en: bool,
    pub power_fault_en: bool,
    pub mrl_sensor_en: bool,
    pub presence_detect_en: bool,
    pub cmd_complete_en: bool,
    pub hotplug_intr_en: bool,
    pub attn_indicator_ctrl: u8,
    pub power_indicator_ctrl: u8,
    pub power_ctrl: bool,
    pub electromech_interlock_ctrl: bool,
    pub dll_state_change_en: bool,
    pub auto_slot_power_limit_disable: bool,
    pub inband_pd_disable: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PcieSlotStatus {
    pub attn_button_pressed: bool,
    pub power_fault: bool,
    pub mrl_sensor_changed: bool,
    pub presence_detect_changed: bool,
    pub cmd_completed: bool,
    pub mrl_sensor_state: bool,    // true = closed
    pub presence_detect_state: bool,
    pub electromech_interlock: bool,
    pub dll_state_changed: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PcieHpState {
    Idle = 0,
    BlinkingOn = 1,
    BlinkingOff = 2,
    PoweringOn = 3,
    PoweringOff = 4,
    Enabled = 5,
    Disabled = 6,
}

// ============================================================================
// SHPC (Standard Hot-Plug Controller)
// ============================================================================

#[derive(Debug, Clone)]
pub struct ShpcController {
    pub base_addr: u64,
    pub mmio_size: u32,
    pub nr_slots: u8,
    pub first_slot: u8,
    pub cap_offset: u16,
    pub slots: Vec<ShpcSlot>,
    pub serr_intr_enable: bool,
    pub cmd_busy: bool,
}

#[derive(Debug, Clone)]
pub struct ShpcSlot {
    pub slot_num: u8,
    pub attn_led: ShpcLedState,
    pub power_led: ShpcLedState,
    pub power: SlotPowerState,
    pub adapter: SlotAdapterStatus,
    pub pcix_cap: ShpcPcixCap,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ShpcLedState {
    Off = 0,
    On = 1,
    Blink = 2,
    Unknown = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ShpcPcixCap {
    PciConventional = 0,
    Pcix66 = 1,
    Pcix133 = 2,
    Pcix266 = 3,
    Pcix533 = 4,
    PcieGen1 = 5,
    PcieGen2 = 6,
}

// ============================================================================
// ACPI-based Hotplug
// ============================================================================

#[derive(Debug, Clone)]
pub struct AcpiPciHotplug {
    pub context: u64,           // ACPI handle
    pub flags: AcpiHpFlags,
    pub slot_num: u32,
    pub sun: u32,               // Slot User Number
    pub bridge_handle: u64,
    pub func_mask: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct AcpiHpFlags {
    pub native_hotplug: bool,
    pub bridge_notify: bool,
    pub is_dock: bool,
    pub eject_supported: bool,
    pub dedicate: bool,
}

// ============================================================================
// Hotplug Events
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum HotplugEvent {
    PowerOn = 1,
    PowerOff = 2,
    IndicatorOn = 3,
    IndicatorOff = 4,
    IndicatorBlink = 5,
    AdapterPresent = 6,
    AdapterAbsent = 7,
    LatchOpen = 8,
    LatchClosed = 9,
    ButtonPressed = 10,
    LinkUp = 11,
    LinkDown = 12,
    SurpriseRemoval = 13,
    PowerFault = 14,
    InterLockOpen = 15,
    InterLockClosed = 16,
}

#[derive(Debug, Clone)]
pub struct HotplugEventRecord {
    pub event: HotplugEvent,
    pub slot_nr: u32,
    pub timestamp: u64,
    pub bus: u8,
    pub devfn: u8,
    pub result: i32,
}

// ============================================================================
// Error Recovery
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PciErrorState {
    Normal = 0,
    Detected = 1,
    MmioEnabled = 2,
    SlotReset = 3,
    ResumeOk = 4,
    LinkReset = 5,
    NeedReset = 6,
    Disconnected = 7,
}

#[derive(Debug, Clone)]
pub struct PciErrorHandler {
    pub error_detected: Option<fn(dev_id: u64, state: PciErrorState) -> PciErrorResult>,
    pub mmio_enabled: Option<fn(dev_id: u64) -> PciErrorResult>,
    pub slot_reset: Option<fn(dev_id: u64) -> PciErrorResult>,
    pub reset_prepare: Option<fn(dev_id: u64)>,
    pub reset_done: Option<fn(dev_id: u64)>,
    pub cor_error_detected: Option<fn(dev_id: u64)>,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PciErrorResult {
    Recovered = 0,
    CantRecover = 1,
    NeedReset = 2,
    Disconnect = 3,
}

#[derive(Debug, Clone)]
pub struct PciAerInfo {
    pub severity: AerSeverity,
    pub status: u32,
    pub mask: u32,
    pub tlp_header: [u32; 4],
    pub source_id: u16,
    pub aer_agent: AerAgent,
    pub aer_layer: AerLayer,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AerSeverity {
    Correctable = 0,
    NonFatal = 1,
    Fatal = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AerAgent {
    Receiver = 0,
    Requester = 1,
    Completer = 2,
    Transmitter = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AerLayer {
    Physical = 0,
    DataLink = 1,
    Transaction = 2,
}

// ============================================================================
// Statistics
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct PciHotplugPowerStats {
    pub hotplug_events: u64,
    pub surprise_removals: u64,
    pub power_faults: u64,
    pub d0_transitions: u64,
    pub d1_transitions: u64,
    pub d2_transitions: u64,
    pub d3_hot_transitions: u64,
    pub d3_cold_transitions: u64,
    pub runtime_suspends: u64,
    pub runtime_resumes: u64,
    pub config_saves: u64,
    pub config_restores: u64,
    pub aer_correctable: u64,
    pub aer_non_fatal: u64,
    pub aer_fatal: u64,
    pub link_retrains: u64,
    pub link_failures: u64,
    pub slot_resets: u64,
    pub initialized: bool,
}

impl PciHotplugPowerStats {
    pub fn new() -> Self {
        Self {
            initialized: true,
            ..Default::default()
        }
    }
}
