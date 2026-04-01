// Zxyphor Kernel - Rust USB Gadget Framework,
// Thermal Management Subsystem, DMA Engine Advanced,
// Reset Controller, Pinctrl Detailed, Extcon,
// OPP (Operating Performance Points),
// Device Links, Component Framework
// SPDX-License-Identifier: GPL-2.0

/// USB Gadget device speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbGadgetSpeed {
    Unknown = 0,
    Low = 1,          // 1.5 Mbps
    Full = 2,         // 12 Mbps
    High = 3,         // 480 Mbps
    Wireless = 4,     // 480 Mbps (wireless)
    Super = 5,        // 5 Gbps
    SuperPlus = 6,    // 10 Gbps
    SuperPlus2x2 = 7, // 20 Gbps
    // Zxyphor
    ZxyUltra = 100,   // Zxyphor custom high-speed
}

/// USB Gadget state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbGadgetState {
    NotAttached = 0,
    Attached = 1,
    Powered = 2,
    Default = 3,
    Address = 4,
    Configured = 5,
    Suspended = 6,
}

/// USB Gadget endpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbEpType {
    Control = 0,
    Isochronous = 1,
    Bulk = 2,
    Interrupt = 3,
}

/// USB Gadget endpoint direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbEpDir {
    Out = 0,  // host to device
    In = 1,   // device to host
}

/// USB Gadget endpoint descriptor
#[derive(Debug, Clone)]
pub struct UsbGadgetEpDesc {
    pub address: u8,
    pub ep_type: UsbEpType,
    pub direction: UsbEpDir,
    pub max_packet_size: u16,
    pub interval: u8,
    pub mult: u8,           // for isoc/interrupt
    pub maxburst: u8,       // for SS
    pub max_streams: u16,   // for SS bulk
    pub enabled: bool,
    pub claimed: bool,
    pub name: [u8; 16],
    pub name_len: u8,
}

impl Default for UsbGadgetEpDesc {
    fn default() -> Self {
        Self {
            address: 0,
            ep_type: UsbEpType::Bulk,
            direction: UsbEpDir::Out,
            max_packet_size: 512,
            interval: 0,
            mult: 0,
            maxburst: 0,
            max_streams: 0,
            enabled: false,
            claimed: false,
            name: [0u8; 16],
            name_len: 0,
        }
    }
}

/// USB Gadget function type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbGadgetFunction {
    Acm = 0,        // Abstract Control Model (serial)
    Ecm = 1,        // Ethernet Control Model
    Ncm = 2,        // Network Control Model
    Rndis = 3,      // RNDIS (Windows USB networking)
    Eem = 4,        // Ethernet Emulation Model
    MassStorage = 5,
    Hid = 6,        // Human Interface Device
    Printer = 7,
    Audio = 8,       // UAC1/UAC2
    Midi = 9,
    Uvc = 10,       // USB Video Class
    Adb = 11,       // Android Debug Bridge
    Mtp = 12,       // Media Transfer Protocol
    Ptp = 13,       // Picture Transfer Protocol
    Ffs = 14,       // FunctionFS
    Accessory = 15,  // Android Open Accessory
    // Zxyphor
    ZxyCustom = 100,
    ZxyDiag = 101,
}

/// USB Gadget composite device descriptor
#[derive(Debug, Clone)]
pub struct UsbGadgetComposite {
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub manufacturer: [u8; 64],
    pub manufacturer_len: u8,
    pub product: [u8; 64],
    pub product_len: u8,
    pub serial_number: [u8; 64],
    pub serial_len: u8,
    pub max_speed: UsbGadgetSpeed,
    pub self_powered: bool,
    pub remote_wakeup: bool,
    pub nr_functions: u8,
    pub nr_configs: u8,
    pub state: UsbGadgetState,
    pub connected: bool,
}

impl Default for UsbGadgetComposite {
    fn default() -> Self {
        Self {
            vendor_id: 0,
            product_id: 0,
            bcd_device: 0,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            manufacturer: [0u8; 64],
            manufacturer_len: 0,
            product: [0u8; 64],
            product_len: 0,
            serial_number: [0u8; 64],
            serial_len: 0,
            max_speed: UsbGadgetSpeed::High,
            self_powered: true,
            remote_wakeup: false,
            nr_functions: 0,
            nr_configs: 0,
            state: UsbGadgetState::NotAttached,
            connected: false,
        }
    }
}

/// USB Gadget ConfigFS representation
#[derive(Debug, Clone)]
pub struct UsbGadgetConfigFs {
    pub name: [u8; 32],
    pub name_len: u8,
    pub udc_name: [u8; 64],
    pub udc_name_len: u8,
    pub bound: bool,
    pub suspended: bool,
}

impl Default for UsbGadgetConfigFs {
    fn default() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            udc_name: [0u8; 64],
            udc_name_len: 0,
            bound: false,
            suspended: false,
        }
    }
}

// ============================================================================
// Thermal Management Subsystem
// ============================================================================

/// Thermal zone type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThermalZoneClass {
    Processor = 0,
    Gpu = 1,
    Memory = 2,
    Storage = 3,
    Battery = 4,
    Ambient = 5,
    Board = 6,
    Skin = 7,
    // Zxyphor
    ZxySmartZone = 100,
}

/// Thermal trip type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThermalTripType {
    Active = 0,
    Passive = 1,
    Hot = 2,
    Critical = 3,
}

/// Thermal trip point
#[derive(Debug, Clone, Copy)]
pub struct ThermalTrip {
    pub trip_type: ThermalTripType,
    pub temperature_mc: i32,     // millidegree Celsius
    pub hysteresis_mc: i32,
}

impl Default for ThermalTrip {
    fn default() -> Self {
        Self {
            trip_type: ThermalTripType::Critical,
            temperature_mc: 100000,  // 100°C
            hysteresis_mc: 0,
        }
    }
}

/// Thermal governor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThermalGovernor {
    StepWise = 0,
    FairShare = 1,
    BangBang = 2,
    UserSpace = 3,
    PowerAllocator = 4,
    // Zxyphor
    ZxyAdaptive = 100,
}

/// Thermal cooling action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThermalCoolingAction {
    CpuFreqLimit = 0,
    GpuFreqLimit = 1,
    FanSpeed = 2,
    DeviceThrottle = 3,
    Shutdown = 4,
}

/// Thermal zone descriptor
#[derive(Debug, Clone)]
pub struct ThermalZoneDesc {
    pub id: u32,
    pub zone_class: ThermalZoneClass,
    pub name: [u8; 32],
    pub name_len: u8,
    pub governor: ThermalGovernor,
    pub temperature_mc: i32,
    pub last_temperature_mc: i32,
    pub nr_trips: u8,
    pub trips: [ThermalTrip; 12],
    pub nr_cooling_devices: u8,
    pub passive_delay_ms: u32,
    pub polling_delay_ms: u32,
    pub enabled: bool,
}

impl Default for ThermalZoneDesc {
    fn default() -> Self {
        Self {
            id: 0,
            zone_class: ThermalZoneClass::Processor,
            name: [0u8; 32],
            name_len: 0,
            governor: ThermalGovernor::StepWise,
            temperature_mc: 0,
            last_temperature_mc: 0,
            nr_trips: 0,
            trips: [ThermalTrip::default(); 12],
            nr_cooling_devices: 0,
            passive_delay_ms: 0,
            polling_delay_ms: 0,
            enabled: true,
        }
    }
}

// ============================================================================
// DMA Engine Advanced
// ============================================================================

/// DMA transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmaTransferType {
    MemToMem = 0,
    MemToDev = 1,
    DevToMem = 2,
    DevToDev = 3,
    // Zxyphor
    ZxyScatter = 100,
}

/// DMA channel capabilities
#[derive(Debug, Clone, Copy)]
pub struct DmaChannelCaps {
    pub mem_to_mem: bool,
    pub mem_to_dev: bool,
    pub dev_to_mem: bool,
    pub dev_to_dev: bool,
    pub cmd_pause: bool,
    pub cmd_resume: bool,
    pub cmd_terminate: bool,
    pub src_addr_widths: u32,   // bitmask of DmaSlaveWidth
    pub dst_addr_widths: u32,
    pub directions: u32,        // bitmask of DmaTransferType
    pub max_burst: u32,
    pub max_sg_burst: u32,
    pub residue_granularity: DmaResidueGranularity,
}

impl Default for DmaChannelCaps {
    fn default() -> Self {
        Self {
            mem_to_mem: true,
            mem_to_dev: false,
            dev_to_mem: false,
            dev_to_dev: false,
            cmd_pause: false,
            cmd_resume: false,
            cmd_terminate: true,
            src_addr_widths: 0,
            dst_addr_widths: 0,
            directions: 0,
            max_burst: 0,
            max_sg_burst: 0,
            residue_granularity: DmaResidueGranularity::Descriptor,
        }
    }
}

/// DMA residue granularity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmaResidueGranularity {
    Descriptor = 0,
    Segment = 1,
    Burst = 2,
}

// ============================================================================
// OPP (Operating Performance Points)
// ============================================================================

/// OPP descriptor
#[derive(Debug, Clone, Copy)]
pub struct OppDesc {
    pub freq_hz: u64,
    pub voltage_uv: u32,
    pub voltage_uv_min: u32,
    pub voltage_uv_max: u32,
    pub current_ua: u32,
    pub opp_hz: u64,
    pub level: u32,
    pub turbo: bool,
    pub suspend: bool,
    pub available: bool,
    // dynamic power coefficient
    pub dynamic_power_coeff: u32,
}

impl Default for OppDesc {
    fn default() -> Self {
        Self {
            freq_hz: 0,
            voltage_uv: 0,
            voltage_uv_min: 0,
            voltage_uv_max: 0,
            current_ua: 0,
            opp_hz: 0,
            level: 0,
            turbo: false,
            suspend: false,
            available: true,
            dynamic_power_coeff: 0,
        }
    }
}

/// OPP table descriptor
#[derive(Debug, Clone)]
pub struct OppTableDesc {
    pub nr_opps: u32,
    pub shared: bool,
    pub clk_rate_tolerance_pct: u32,
    pub voltage_tolerance_uv: u32,
    pub supported_hw_count: u32,
    pub genpd_performance: bool,
    pub is_genpd: bool,
}

impl Default for OppTableDesc {
    fn default() -> Self {
        Self {
            nr_opps: 0,
            shared: false,
            clk_rate_tolerance_pct: 0,
            voltage_tolerance_uv: 0,
            supported_hw_count: 0,
            genpd_performance: false,
            is_genpd: false,
        }
    }
}

// ============================================================================
// Device Links & Component Framework
// ============================================================================

/// Device link flags
#[derive(Debug, Clone, Copy)]
pub struct DeviceLinkFlags {
    pub stateless: bool,
    pub autoremove_consumer: bool,
    pub pm_runtime: bool,
    pub rpm_active: bool,
    pub autoremove_supplier: bool,
    pub autoprobe_consumer: bool,
    pub managed: bool,
    pub sync_state_only: bool,
    pub inferred: bool,
}

impl Default for DeviceLinkFlags {
    fn default() -> Self {
        Self {
            stateless: false,
            autoremove_consumer: false,
            pm_runtime: false,
            rpm_active: false,
            autoremove_supplier: false,
            autoprobe_consumer: false,
            managed: false,
            sync_state_only: false,
            inferred: false,
        }
    }
}

/// Device link state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceLinkState {
    Dormant = 0,
    Available = 1,
    ConsumerProbe = 2,
    Active = 3,
    SupplierUnbind = 4,
}

/// Extcon (External Connector) type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ExtconType {
    None = 0,
    Usb = 1,
    UsbHost = 2,
    Ta = 3,           // Travel Adapter
    FastCharger1 = 4,
    FastCharger2 = 5,
    FastCharger3 = 6,
    SlowCharger = 7,
    ChargeDownstream = 8,
    Hdmi = 9,
    Mhl = 10,
    Dvi = 11,
    Vga = 12,
    Dock = 13,
    LineIn = 14,
    LineOut = 15,
    MicIn = 16,
    Headphone = 17,
    Spdif = 18,
    AnalogVideo = 19,
    Jack = 20,
    MechanicalBtn = 21,
    Disp = 22,
    // Zxyphor
    ZxyCustom = 100,
}

/// Device subsystem manager
#[derive(Debug, Clone)]
pub struct DevExtSubsystem {
    pub nr_gadget_devices: u32,
    pub nr_thermal_zones: u32,
    pub nr_dma_channels: u32,
    pub nr_opp_tables: u32,
    pub nr_device_links: u32,
    pub nr_extcon: u32,
    pub initialized: bool,
}

impl Default for DevExtSubsystem {
    fn default() -> Self {
        Self {
            nr_gadget_devices: 0,
            nr_thermal_zones: 0,
            nr_dma_channels: 0,
            nr_opp_tables: 0,
            nr_device_links: 0,
            nr_extcon: 0,
            initialized: false,
        }
    }
}

impl DevExtSubsystem {
    pub fn init() -> Self {
        Self {
            initialized: true,
            ..Default::default()
        }
    }
}
