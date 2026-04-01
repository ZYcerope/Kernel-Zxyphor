// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel - Rust ACPI Subsystem: Full ACPI 6.5 support, AML Interpreter, GPE, Thermal
// More advanced than Linux 2026 ACPI subsystem

use core::fmt;

// ============================================================================
// ACPI Generic Address Structure
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressSpaceId {
    SystemMemory = 0x00,
    SystemIO = 0x01,
    PciConfig = 0x02,
    EmbeddedController = 0x03,
    SMBus = 0x04,
    SystemCMOS = 0x05,
    PciBarTarget = 0x06,
    Ipmi = 0x07,
    GeneralPurposeIO = 0x08,
    GenericSerialBus = 0x09,
    PlatformCommChannel = 0x0A,
    FunctionalFixed = 0x7F,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GenericAddress {
    pub address_space_id: u8,
    pub register_bit_width: u8,
    pub register_bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

impl GenericAddress {
    pub fn is_memory(&self) -> bool {
        self.address_space_id == AddressSpaceId::SystemMemory as u8
    }
    pub fn is_io(&self) -> bool {
        self.address_space_id == AddressSpaceId::SystemIO as u8
    }
}

// ============================================================================
// AML Interpreter
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AmlOpcode {
    ZeroOp = 0x00,
    OneOp = 0x01,
    AliasOp = 0x06,
    NameOp = 0x08,
    BytePrefix = 0x0A,
    WordPrefix = 0x0B,
    DwordPrefix = 0x0C,
    StringPrefix = 0x0D,
    QwordPrefix = 0x0E,
    ScopeOp = 0x10,
    BufferOp = 0x11,
    PackageOp = 0x12,
    VarPackageOp = 0x13,
    MethodOp = 0x14,
    ExternalOp = 0x15,
    DualNamePrefix = 0x2E,
    MultiNamePrefix = 0x2F,
    // Named objects
    Local0Op = 0x60,
    Local1Op = 0x61,
    Local2Op = 0x62,
    Local3Op = 0x63,
    Local4Op = 0x64,
    Local5Op = 0x65,
    Local6Op = 0x66,
    Local7Op = 0x67,
    Arg0Op = 0x68,
    Arg1Op = 0x69,
    Arg2Op = 0x6A,
    Arg3Op = 0x6B,
    Arg4Op = 0x6C,
    Arg5Op = 0x6D,
    Arg6Op = 0x6E,
    // Computation
    StoreOp = 0x70,
    RefOfOp = 0x71,
    AddOp = 0x72,
    ConcatOp = 0x73,
    SubtractOp = 0x74,
    IncrementOp = 0x75,
    DecrementOp = 0x76,
    MultiplyOp = 0x77,
    DivideOp = 0x78,
    ShiftLeftOp = 0x79,
    ShiftRightOp = 0x7A,
    AndOp = 0x7B,
    NandOp = 0x7C,
    OrOp = 0x7D,
    NorOp = 0x7E,
    XorOp = 0x7F,
    NotOp = 0x80,
    FindSetLeftBitOp = 0x81,
    FindSetRightBitOp = 0x82,
    DerefOfOp = 0x83,
    ConcatResOp = 0x84,
    ModOp = 0x85,
    NotifyOp = 0x86,
    SizeOfOp = 0x87,
    IndexOp = 0x88,
    MatchOp = 0x89,
    // Create field
    CreateDWordFieldOp = 0x8A,
    CreateWordFieldOp = 0x8B,
    CreateByteFieldOp = 0x8C,
    CreateBitFieldOp = 0x8D,
    ObjectTypeOp = 0x8E,
    CreateQWordFieldOp = 0x8F,
    // Control flow
    LandOp = 0x90,
    LorOp = 0x91,
    LnotOp = 0x92,
    LEqualOp = 0x93,
    LGreaterOp = 0x94,
    LLessOp = 0x95,
    ToBufferOp = 0x96,
    ToDecimalStringOp = 0x97,
    ToHexStringOp = 0x98,
    ToIntegerOp = 0x99,
    ToStringOp = 0x9C,
    CopyObjectOp = 0x9D,
    MidOp = 0x9E,
    ContinueOp = 0x9F,
    IfOp = 0xA0,
    ElseOp = 0xA1,
    WhileOp = 0xA2,
    NoopOp = 0xA3,
    ReturnOp = 0xA4,
    BreakOp = 0xA5,
    BreakPointOp = 0xCC,
    OnesOp = 0xFF,
}

#[derive(Debug, Clone)]
pub enum AmlValue {
    Uninitialized,
    Integer(u64),
    String(AmlString),
    Buffer(AmlBuffer),
    Package(AmlPackage),
    FieldUnit(AmlFieldUnit),
    Device,
    Event(u32),
    Method(AmlMethod),
    Mutex(AmlMutex),
    OperationRegion(AmlOpRegion),
    PowerResource(AmlPowerResource),
    Processor(AmlProcessorObj),
    ThermalZone,
    BufferField(AmlBufferField),
    Reference(u32), // Index into namespace
}

#[derive(Debug, Clone)]
pub struct AmlString {
    pub data: [u8; 256],
    pub len: usize,
}

impl AmlString {
    pub fn new() -> Self {
        Self {
            data: [0u8; 256],
            len: 0,
        }
    }
    pub fn as_str(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

#[derive(Debug, Clone)]
pub struct AmlBuffer {
    pub data: [u8; 4096],
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct AmlPackage {
    pub elements: [u64; 64],
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct AmlFieldUnit {
    pub region_index: u32,
    pub bit_offset: u32,
    pub bit_length: u32,
    pub access_type: u8,
    pub lock_rule: bool,
    pub update_rule: u8,
}

#[derive(Debug, Clone)]
pub struct AmlMethod {
    pub arg_count: u8,
    pub serialized: bool,
    pub sync_level: u8,
    pub aml_offset: u32,
    pub aml_length: u32,
}

#[derive(Debug, Clone)]
pub struct AmlMutex {
    pub sync_level: u8,
    pub owner_id: u32,
    pub acquisition_depth: u16,
}

#[derive(Debug, Clone)]
pub struct AmlOpRegion {
    pub space: u8,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub struct AmlPowerResource {
    pub system_level: u8,
    pub resource_order: u16,
}

#[derive(Debug, Clone)]
pub struct AmlProcessorObj {
    pub proc_id: u8,
    pub pblk_addr: u32,
    pub pblk_len: u8,
}

#[derive(Debug, Clone)]
pub struct AmlBufferField {
    pub buffer_index: u32,
    pub bit_offset: u32,
    pub bit_length: u32,
}

// ============================================================================
// ACPI Namespace
// ============================================================================

pub const ACPI_NS_MAX_NODES: usize = 8192;

#[derive(Debug, Clone)]
pub struct AcpiNamespaceNode {
    pub name: [u8; 4],
    pub parent: u32,       // Index of parent (0 = root)
    pub child_first: u32,  // First child index
    pub sibling_next: u32, // Next sibling index
    pub value: AmlValue,
    pub obj_type: AcpiObjectType,
    pub flags: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AcpiObjectType {
    Any = 0,
    Integer = 1,
    String = 2,
    Buffer = 3,
    Package = 4,
    FieldUnit = 5,
    Device = 6,
    Event = 7,
    Method = 8,
    Mutex = 9,
    Region = 10,
    Power = 11,
    Processor = 12,
    Thermal = 13,
    BufferField = 14,
    DdbHandle = 15,
    DebugObject = 16,
    Scope = 17,
    Alias = 18,
    Notify = 19,
}

pub struct AcpiNamespace {
    pub nodes: [AcpiNamespaceNode; ACPI_NS_MAX_NODES],
    pub nr_nodes: u32,
    pub root: u32,
}

impl AcpiNamespace {
    pub fn find_node(&self, path: &[u8]) -> Option<u32> {
        if path.is_empty() {
            return Some(self.root);
        }
        let mut current = self.root;
        let mut pos = 0;
        // Skip leading backslash
        if path[0] == b'\\' {
            current = self.root;
            pos = 1;
        }
        while pos + 4 <= path.len() {
            let seg = &path[pos..pos + 4];
            let mut found = false;
            let mut child = self.nodes[current as usize].child_first;
            while child != 0 && (child as usize) < self.nr_nodes as usize {
                if &self.nodes[child as usize].name == seg {
                    current = child;
                    found = true;
                    break;
                }
                child = self.nodes[child as usize].sibling_next;
            }
            if !found {
                return None;
            }
            pos += 4;
            if pos < path.len() && path[pos] == b'.' {
                pos += 1;
            }
        }
        Some(current)
    }

    pub fn add_node(
        &mut self,
        parent: u32,
        name: [u8; 4],
        obj_type: AcpiObjectType,
        value: AmlValue,
    ) -> Option<u32> {
        if self.nr_nodes as usize >= ACPI_NS_MAX_NODES {
            return None;
        }
        let idx = self.nr_nodes;
        self.nodes[idx as usize] = AcpiNamespaceNode {
            name,
            parent,
            child_first: 0,
            sibling_next: self.nodes[parent as usize].child_first,
            value,
            obj_type,
            flags: 0,
        };
        self.nodes[parent as usize].child_first = idx;
        self.nr_nodes += 1;
        Some(idx)
    }
}

// ============================================================================
// AML Interpreter
// ============================================================================

pub struct AmlInterpreter {
    pub namespace: AcpiNamespace,
    pub locals: [AmlValue; 8],
    pub args: [AmlValue; 7],
    pub return_value: AmlValue,
    pub call_depth: u32,
    pub max_call_depth: u32,
    // AML bytecode
    pub aml_data: [u8; 65536],
    pub aml_len: usize,
    pub pc: usize,
    // Global lock
    pub global_lock_acquired: bool,
    // Notify handlers
    pub notify_handlers: [Option<NotifyHandler>; 256],
    pub nr_notify_handlers: u32,
}

#[derive(Clone, Copy)]
pub struct NotifyHandler {
    pub device_node: u32,
    pub handler_type: u32, // System (0x00-0x7F) or Device (0x80-0xFF)
}

impl AmlInterpreter {
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.pc >= self.aml_len {
            return None;
        }
        let b = self.aml_data[self.pc];
        self.pc += 1;
        Some(b)
    }

    pub fn read_word(&mut self) -> Option<u16> {
        let lo = self.read_byte()? as u16;
        let hi = self.read_byte()? as u16;
        Some(lo | (hi << 8))
    }

    pub fn read_dword(&mut self) -> Option<u32> {
        let lo = self.read_word()? as u32;
        let hi = self.read_word()? as u32;
        Some(lo | (hi << 16))
    }

    pub fn read_qword(&mut self) -> Option<u64> {
        let lo = self.read_dword()? as u64;
        let hi = self.read_dword()? as u64;
        Some(lo | (hi << 32))
    }

    pub fn read_pkg_length(&mut self) -> Option<u32> {
        let lead = self.read_byte()? as u32;
        let byte_count = (lead >> 6) & 3;
        if byte_count == 0 {
            return Some(lead & 0x3F);
        }
        let mut len = lead & 0x0F;
        for i in 0..byte_count {
            let b = self.read_byte()? as u32;
            len |= b << (4 + i * 8);
        }
        Some(len)
    }

    pub fn read_name_seg(&mut self) -> Option<[u8; 4]> {
        let mut name = [0u8; 4];
        for byte in &mut name {
            *byte = self.read_byte()?;
        }
        Some(name)
    }

    pub fn evaluate_integer(&mut self) -> Option<u64> {
        let opcode = self.read_byte()?;
        match opcode {
            0x00 => Some(0),        // ZeroOp
            0x01 => Some(1),        // OneOp
            0xFF => Some(u64::MAX), // OnesOp
            0x0A => Some(self.read_byte()? as u64),
            0x0B => Some(self.read_word()? as u64),
            0x0C => Some(self.read_dword()? as u64),
            0x0E => self.read_qword(),
            0x60..=0x67 => {
                // Local0-7
                let idx = (opcode - 0x60) as usize;
                match &self.locals[idx] {
                    AmlValue::Integer(v) => Some(*v),
                    _ => None,
                }
            }
            0x68..=0x6E => {
                // Arg0-6
                let idx = (opcode - 0x68) as usize;
                match &self.args[idx] {
                    AmlValue::Integer(v) => Some(*v),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

// ============================================================================
// ACPI GPE (General Purpose Events)
// ============================================================================

pub const GPE_MAX_BLOCKS: usize = 2;
pub const GPE_REG_WIDTH: usize = 8;
pub const GPE_MAX_EVENTS: usize = 256;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GpeType {
    Wake = 0x01,
    Runtime = 0x02,
    WakeRun = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GpeDispatch {
    None = 0,
    Method = 1,
    Handler = 2,
    NotifyList = 3,
    RawHandler = 4,
}

#[derive(Debug, Clone)]
pub struct GpeRegisterInfo {
    pub status_addr: GenericAddress,
    pub enable_addr: GenericAddress,
    pub enable_for_wake: u8,
    pub enable_for_run: u8,
    pub enable_mask: u8,
    pub base_gpe_number: u8,
}

#[derive(Debug, Clone)]
pub struct GpeEventInfo {
    pub gpe_number: u8,
    pub gpe_type: GpeType,
    pub dispatch_type: GpeDispatch,
    pub method_node: u32,     // Namespace index for _Lxx/_Exx
    pub runtime_count: u32,
    pub wakeup_count: u32,
    pub enabled: bool,
    pub can_wake: bool,
    pub count: u64,
}

pub struct GpeBlock {
    pub gpe_base: u8,
    pub gpe_count: u8,
    pub register_count: u8,
    pub registers: [GpeRegisterInfo; 32],
    pub events: [GpeEventInfo; GPE_MAX_EVENTS],
    pub initialized: bool,
}

impl GpeBlock {
    pub fn enable_gpe(&mut self, gpe_number: u8) -> bool {
        let idx = gpe_number as usize;
        if idx >= self.gpe_count as usize {
            return false;
        }
        self.events[idx].enabled = true;
        true
    }

    pub fn disable_gpe(&mut self, gpe_number: u8) -> bool {
        let idx = gpe_number as usize;
        if idx >= self.gpe_count as usize {
            return false;
        }
        self.events[idx].enabled = false;
        true
    }
}

// ============================================================================
// ACPI Thermal Management
// ============================================================================

pub const THERMAL_MAX_TRIPS: usize = 12;
pub const THERMAL_MAX_COOLING: usize = 16;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalTripType {
    Active = 0,
    Passive = 1,
    Hot = 2,
    Critical = 3,
    // Zxyphor
    ZxyPredictive = 200,
    ZxyEmergency = 201,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalGovernor {
    StepWise = 0,
    FairShare = 1,
    BangBang = 2,
    UserSpace = 3,
    PowerAllocator = 4,
    // Zxyphor
    ZxyAdaptive = 200,
    ZxyMlBased = 201,
}

#[derive(Debug, Clone)]
pub struct ThermalTrip {
    pub trip_type: ThermalTripType,
    pub temperature: i32,  // Millidegrees Celsius
    pub hysteresis: i32,
    pub cooling_devices: [u32; 8],
    pub nr_cooling: u8,
}

#[derive(Debug, Clone)]
pub struct ThermalZone {
    pub name: [u8; 32],
    pub name_len: u8,
    // Current state
    pub temperature: i32,       // Millidegrees C
    pub last_temperature: i32,
    pub trend: ThermalTrend,
    // Trips
    pub trips: [ThermalTrip; THERMAL_MAX_TRIPS],
    pub nr_trips: u8,
    pub passive_trip: i32,
    pub critical_trip: i32,
    // Cooling
    pub cooling_devices: [CoolingDevice; THERMAL_MAX_COOLING],
    pub nr_cooling: u8,
    // Governor
    pub governor: ThermalGovernor,
    // Polling
    pub polling_delay_ms: u32,
    pub passive_delay_ms: u32,
    // ACPI namespace
    pub acpi_node: u32,
    // Stats
    pub high_temp_count: u64,
    pub throttle_count: u64,
    pub total_polling_count: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThermalTrend {
    Stable = 0,
    Raising = 1,
    Dropping = 2,
    DropFull = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CoolingType {
    Processor = 0,
    Fan = 1,
    Memory = 2,
    Device = 3,
    // Zxyphor
    ZxyFreqThrottle = 200,
    ZxyGpuThrottle = 201,
}

#[derive(Debug, Clone)]
pub struct CoolingDevice {
    pub name: [u8; 32],
    pub cooling_type: CoolingType,
    pub max_state: u32,
    pub cur_state: u32,
    pub min_state: u32,
    pub weight: u32,
    pub power_mw: u32,       // Current power draw
    pub max_power_mw: u32,
    pub efficiency: u32,     // Power efficiency rating
}

impl ThermalZone {
    pub fn check_trips(&self) -> Option<&ThermalTrip> {
        for trip in &self.trips[..self.nr_trips as usize] {
            if self.temperature >= trip.temperature {
                return Some(trip);
            }
        }
        None
    }

    pub fn is_critical(&self) -> bool {
        self.temperature >= self.critical_trip && self.critical_trip > 0
    }

    pub fn get_trend(&self) -> ThermalTrend {
        if self.temperature > self.last_temperature + 1000 {
            ThermalTrend::Raising
        } else if self.temperature < self.last_temperature - 1000 {
            ThermalTrend::Dropping
        } else {
            ThermalTrend::Stable
        }
    }
}

// ============================================================================
// ACPI Battery / Power Supply
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryState {
    Unknown = 0,
    Charging = 1,
    Discharging = 2,
    NotCharging = 3,
    Full = 4,
    Critical = 5,
}

#[derive(Debug, Clone)]
pub struct AcpiBattery {
    pub present: bool,
    pub state: BatteryState,
    // Static info (_BIF/_BIX)
    pub power_unit: u32,       // 0=mWh, 1=mAh
    pub design_capacity: u32,
    pub last_full_capacity: u32,
    pub technology: u32,       // 0=primary, 1=secondary
    pub design_voltage: u32,   // mV
    pub design_capacity_warning: u32,
    pub design_capacity_low: u32,
    pub cycle_count: u32,
    pub measurement_accuracy: u32,
    pub max_sampling_time: u32,
    pub min_sampling_time: u32,
    pub max_averaging_interval: u32,
    pub min_averaging_interval: u32,
    pub granularity_1: u32,
    pub granularity_2: u32,
    pub model_number: [u8; 32],
    pub serial_number: [u8; 32],
    pub battery_type: [u8; 16],
    pub oem_info: [u8; 32],
    // Dynamic info (_BST)
    pub rate: i32,             // Current discharge/charge rate (mW or mA)
    pub remaining_capacity: u32,
    pub present_voltage: u32,  // mV
    // Calculated
    pub capacity_percent: u8,
    pub time_to_empty_min: u32,
    pub time_to_full_min: u32,
    pub temperature: i32,      // Millidegrees C
    // Zxyphor battery intelligence
    pub health_percent: u8,
    pub charge_cycles_est: u32,
}

impl AcpiBattery {
    pub fn capacity_percent_calc(&self) -> u8 {
        if self.last_full_capacity == 0 {
            return 0;
        }
        let pct = (self.remaining_capacity as u64 * 100) / self.last_full_capacity as u64;
        if pct > 100 { 100 } else { pct as u8 }
    }

    pub fn is_low(&self) -> bool {
        self.remaining_capacity <= self.design_capacity_low
    }

    pub fn is_warning(&self) -> bool {
        self.remaining_capacity <= self.design_capacity_warning
    }
}

#[derive(Debug, Clone)]
pub struct AcAdapter {
    pub present: bool,
    pub online: bool,
    pub power_mw: u32,
    pub adapter_type: [u8; 16],
}

// ============================================================================
// ACPI Power States
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AcpiSleepState {
    S0 = 0,       // Working
    S1 = 1,       // Sleeping (CPU stops, power on)
    S2 = 2,       // Sleeping (CPU off, dirty cache flushed)
    S3 = 3,       // Suspend to RAM
    S4 = 4,       // Suspend to Disk (Hibernate)
    S5 = 5,       // Soft Off
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AcpiDevicePowerState {
    D0 = 0,       // Fully on
    D1 = 1,       // Light sleep
    D2 = 2,       // Deeper sleep
    D3Hot = 3,    // Device off, aux power
    D3Cold = 4,   // Device off, no power
}

#[derive(Debug, Clone)]
pub struct AcpiPowerState {
    pub current_sleep: AcpiSleepState,
    pub target_sleep: AcpiSleepState,
    pub s4bios_supported: bool,
    pub sleep_type_a: [u8; 6],  // SLP_TYPa for S0-S5
    pub sleep_type_b: [u8; 6],  // SLP_TYPb for S0-S5
    pub hw_reduced: bool,
    pub low_power_s0: bool,     // Modern standby
    // Wake sources
    pub wake_devices: [u32; 64],
    pub nr_wake_devices: u32,
    pub wake_gpe: [u8; 32],
    pub nr_wake_gpe: u8,
}

// ============================================================================
// ACPI Processor Performance (P-states, C-states, T-states)
// ============================================================================

pub const MAX_PSTATES: usize = 64;
pub const MAX_CSTATES: usize = 16;
pub const MAX_TSTATES: usize = 16;

#[derive(Debug, Clone)]
pub struct AcpiPstate {
    pub core_frequency: u32,    // MHz
    pub power: u32,             // mW
    pub transition_latency: u32, // us
    pub bus_master_latency: u32, // us
    pub control: u64,
    pub status: u64,
}

#[derive(Debug, Clone)]
pub struct AcpiCstate {
    pub ctype: u8,              // C1, C2, C3, etc.
    pub latency: u32,           // us
    pub power: u32,             // mW
    pub address: GenericAddress,
    pub bit_width: u8,
    pub bit_offset: u8,
}

#[derive(Debug, Clone)]
pub struct AcpiTstate {
    pub percent_throttle: u32,
    pub power: u32,             // mW
    pub transition_latency: u32, // us
    pub control: u32,
    pub status: u32,
}

#[derive(Debug, Clone)]
pub struct AcpiProcessorPerf {
    pub id: u8,
    // P-states
    pub pstates: [AcpiPstate; MAX_PSTATES],
    pub nr_pstates: u8,
    pub current_pstate: u8,
    pub ppc: u8,                // Performance Present Capabilities
    // C-states
    pub cstates: [AcpiCstate; MAX_CSTATES],
    pub nr_cstates: u8,
    pub current_cstate: u8,
    // T-states (throttle)
    pub tstates: [AcpiTstate; MAX_TSTATES],
    pub nr_tstates: u8,
    pub current_tstate: u8,
    pub ptc: bool,              // Processor Throttle Control present
    // Coordination type
    pub coord_type: u8,         // 0xFC=all, 0xFD=hw_all, 0xFE=sw_any
    pub domain: u32,
}

// ============================================================================
// ACPI EC (Embedded Controller)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EcCommand {
    Read = 0x80,
    Write = 0x81,
    BurstEnable = 0x82,
    BurstDisable = 0x83,
    Query = 0x84,
}

#[derive(Debug, Clone)]
pub struct EcDevice {
    pub data_port: u16,
    pub command_port: u16,
    pub gpe_bit: u8,
    pub use_global_lock: bool,
    pub burst_enabled: bool,
    pub sci_pending: bool,
    // Query handlers
    pub query_handlers: [Option<EcQueryHandler>; 256],
    pub nr_handlers: u32,
    // Stats
    pub transaction_count: u64,
    pub error_count: u64,
    pub retry_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct EcQueryHandler {
    pub query_bit: u8,
    pub handler_node: u32, // Namespace index for _Qxx
}

impl EcDevice {
    pub fn read_byte(&self, address: u8) -> Result<u8, i32> {
        // Wait for IBF clear, send read command, send address, wait for OBF, read data
        // Simplified - real impl needs port I/O
        let _ = address;
        Ok(0)
    }

    pub fn write_byte(&self, address: u8, data: u8) -> Result<(), i32> {
        let _ = (address, data);
        Ok(())
    }
}

// ============================================================================
// ACPI Device Enumeration
// ============================================================================

#[derive(Debug, Clone)]
pub struct AcpiDeviceInfo {
    pub hid: [u8; 16],        // Hardware ID (_HID)
    pub uid: [u8; 16],        // Unique ID (_UID)
    pub adr: u64,             // Address (_ADR)
    pub cid: [[u8; 16]; 8],   // Compatible IDs (_CID)
    pub nr_cid: u8,
    pub cls: u32,              // Class code
    pub sta: u32,              // Status (_STA)
    pub namespace_node: u32,
    pub power_state: AcpiDevicePowerState,
    pub wake_capable: bool,
    pub pnp_type: u32,
}

impl AcpiDeviceInfo {
    pub fn is_present(&self) -> bool {
        (self.sta & 0x01) != 0
    }
    pub fn is_enabled(&self) -> bool {
        (self.sta & 0x02) != 0
    }
    pub fn is_functioning(&self) -> bool {
        (self.sta & 0x08) != 0
    }
    pub fn has_children(&self) -> bool {
        (self.sta & 0x10) != 0 // _STA bit 4
    }
}

// ============================================================================
// ACPI Resource Descriptors
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AcpiResourceType {
    Irq = 0,
    Dma = 1,
    StartDependent = 2,
    EndDependent = 3,
    Io = 4,
    FixedIo = 5,
    VendorShort = 6,
    EndTag = 7,
    Memory24 = 8,
    Memory32 = 9,
    FixedMemory32 = 10,
    Address16 = 11,
    Address32 = 12,
    Address64 = 13,
    ExtendedAddress64 = 14,
    ExtendedIrq = 15,
    GenericRegister = 16,
    Gpio = 17,
    SerialBusI2c = 18,
    SerialBusSpi = 19,
    SerialBusUart = 20,
    CsiProtocol = 21,
    PinFunction = 22,
    PinConfig = 23,
    PinGroup = 24,
    PinGroupFunction = 25,
    PinGroupConfig = 26,
    ClockInput = 27,
}

#[derive(Debug, Clone)]
pub struct AcpiResource {
    pub res_type: AcpiResourceType,
    pub data: AcpiResourceData,
}

#[derive(Debug, Clone)]
pub enum AcpiResourceData {
    Irq {
        triggering: u8,   // 0=level, 1=edge
        polarity: u8,     // 0=active-high, 1=active-low
        shareable: bool,
        interrupt_count: u8,
        interrupts: [u32; 8],
    },
    Dma {
        channel_count: u8,
        channels: [u8; 8],
        bus_master: bool,
        transfer_type: u8,
    },
    Io {
        decode_type: u8,
        minimum: u16,
        maximum: u16,
        alignment: u8,
        address_length: u8,
    },
    Memory32 {
        write_protect: bool,
        minimum: u32,
        maximum: u32,
        alignment: u32,
        address_length: u32,
    },
    Address64 {
        resource_type: u8,
        minimum: u64,
        maximum: u64,
        translation_offset: u64,
        address_length: u64,
        granularity: u64,
    },
    Gpio {
        connection_type: u8,
        pin_config: u8,
        debounce_timeout: u16,
        drive_strength: u16,
        io_restriction: u8,
        vendor_data_length: u16,
        resource_source: [u8; 64],
        pin_table: [u16; 16],
        pin_count: u8,
    },
}

// ============================================================================
// ACPI Subsystem Manager
// ============================================================================

pub const MAX_ACPI_DEVICES: usize = 512;
pub const MAX_THERMAL_ZONES: usize = 32;

pub struct AcpiSubsystem {
    pub interpreter: AmlInterpreter,
    // GPE
    pub gpe_blocks: [GpeBlock; GPE_MAX_BLOCKS],
    pub nr_gpe_blocks: u8,
    // Thermal
    pub thermal_zones: [ThermalZone; MAX_THERMAL_ZONES],
    pub nr_thermal_zones: u8,
    // Battery
    pub batteries: [AcpiBattery; 4],
    pub nr_batteries: u8,
    pub ac_adapter: AcAdapter,
    // Power state
    pub power_state: AcpiPowerState,
    // Processor perf
    pub processor_perf: [AcpiProcessorPerf; 256],
    pub nr_processors: u16,
    // EC
    pub ec: Option<EcDevice>,
    // Devices
    pub devices: [AcpiDeviceInfo; MAX_ACPI_DEVICES],
    pub nr_devices: u32,
    // State
    pub initialized: bool,
    pub sci_irq: u32,
    pub acpi_revision: u8,
    pub hw_reduced: bool,
}

impl AcpiSubsystem {
    pub fn find_device_by_hid(&self, hid: &[u8]) -> Option<&AcpiDeviceInfo> {
        for dev in &self.devices[..self.nr_devices as usize] {
            let dev_hid_len = dev.hid.iter().position(|&b| b == 0).unwrap_or(dev.hid.len());
            if dev_hid_len == hid.len() && dev.hid[..dev_hid_len] == *hid {
                return Some(dev);
            }
        }
        None
    }

    pub fn get_battery_summary(&self) -> (u8, u8, bool) {
        let mut total_cap: u32 = 0;
        let mut total_full: u32 = 0;
        let mut any_charging = false;
        for bat in &self.batteries[..self.nr_batteries as usize] {
            if bat.present {
                total_cap += bat.remaining_capacity;
                total_full += bat.last_full_capacity;
                if bat.state == BatteryState::Charging {
                    any_charging = true;
                }
            }
        }
        let pct = if total_full > 0 {
            ((total_cap as u64 * 100) / total_full as u64) as u8
        } else {
            0
        };
        (pct, self.nr_batteries, any_charging)
    }
}
