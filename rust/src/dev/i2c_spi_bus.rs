// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - I2C, SPI, 1-Wire, MDIO Bus Drivers,
// Device Tree Bindings, Regulator Consumer, Reset Controller
// More advanced than Linux 2026 bus subsystems

/// I2C address type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cAddrType {
    SevenBit = 0,
    TenBit = 1,
}

/// I2C bus speed
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    Standard = 100_000,      // 100 kHz
    Fast = 400_000,          // 400 kHz
    FastPlus = 1_000_000,    // 1 MHz
    HighSpeed = 3_400_000,   // 3.4 MHz
    UltraFast = 5_000_000,   // 5 MHz (unidirectional)
}

/// I2C transfer flags
pub const I2C_M_RD: u16 = 0x0001;           // Read
pub const I2C_M_TEN: u16 = 0x0010;          // 10-bit address
pub const I2C_M_DMA_SAFE: u16 = 0x0200;     // DMA safe buffer
pub const I2C_M_RECV_LEN: u16 = 0x0400;     // SMBus block read
pub const I2C_M_NO_RD_ACK: u16 = 0x0800;    // No read ACK
pub const I2C_M_IGNORE_NAK: u16 = 0x1000;
pub const I2C_M_REV_DIR_ADDR: u16 = 0x2000;
pub const I2C_M_NOSTART: u16 = 0x4000;
pub const I2C_M_STOP: u16 = 0x8000;

/// I2C message
#[derive(Debug, Clone)]
pub struct I2cMsg {
    pub addr: u16,
    pub flags: u16,
    pub len: u16,
    // buf: *mut u8
}

/// I2C adapter functionality
pub const I2C_FUNC_I2C: u32 = 0x00000001;
pub const I2C_FUNC_10BIT_ADDR: u32 = 0x00000002;
pub const I2C_FUNC_PROTOCOL_MANGLING: u32 = 0x00000004;
pub const I2C_FUNC_SMBUS_PEC: u32 = 0x00000008;
pub const I2C_FUNC_NOSTART: u32 = 0x00000010;
pub const I2C_FUNC_SLAVE: u32 = 0x00000020;
pub const I2C_FUNC_SMBUS_BLOCK_PROC_CALL: u32 = 0x00008000;
pub const I2C_FUNC_SMBUS_QUICK: u32 = 0x00010000;
pub const I2C_FUNC_SMBUS_READ_BYTE: u32 = 0x00020000;
pub const I2C_FUNC_SMBUS_WRITE_BYTE: u32 = 0x00040000;
pub const I2C_FUNC_SMBUS_READ_BYTE_DATA: u32 = 0x00080000;
pub const I2C_FUNC_SMBUS_WRITE_BYTE_DATA: u32 = 0x00100000;
pub const I2C_FUNC_SMBUS_READ_WORD_DATA: u32 = 0x00200000;
pub const I2C_FUNC_SMBUS_WRITE_WORD_DATA: u32 = 0x00400000;
pub const I2C_FUNC_SMBUS_PROC_CALL: u32 = 0x00800000;
pub const I2C_FUNC_SMBUS_READ_BLOCK_DATA: u32 = 0x01000000;
pub const I2C_FUNC_SMBUS_WRITE_BLOCK_DATA: u32 = 0x02000000;
pub const I2C_FUNC_SMBUS_READ_I2C_BLOCK: u32 = 0x04000000;
pub const I2C_FUNC_SMBUS_WRITE_I2C_BLOCK: u32 = 0x08000000;
pub const I2C_FUNC_SMBUS_HOST_NOTIFY: u32 = 0x10000000;

/// I2C adapter info
#[derive(Debug, Clone)]
pub struct I2cAdapterInfo {
    pub nr: u32,
    pub name: [48; u8],
    pub functionality: u32,
    pub speed: I2cSpeed,
    pub retries: u32,
    pub timeout_ms: u32,
    // DMA
    pub dma_capable: bool,
    // Stats
    pub total_transfers: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    pub total_nacks: u64,
    pub total_timeouts: u64,
}

/// I2C client device
#[derive(Debug, Clone)]
pub struct I2cClientInfo {
    pub name: [20; u8],
    pub addr: u16,
    pub addr_type: I2cAddrType,
    pub irq: i32,
    pub adapter_nr: u32,
    // Power
    pub wakeup_capable: bool,
}

// ============================================================================
// SPI Bus
// ============================================================================

/// SPI mode bits
pub const SPI_CPHA: u32 = 0x01;
pub const SPI_CPOL: u32 = 0x02;
pub const SPI_MODE_0: u32 = 0;
pub const SPI_MODE_1: u32 = SPI_CPHA;
pub const SPI_MODE_2: u32 = SPI_CPOL;
pub const SPI_MODE_3: u32 = SPI_CPOL | SPI_CPHA;
pub const SPI_CS_HIGH: u32 = 0x04;
pub const SPI_LSB_FIRST: u32 = 0x08;
pub const SPI_3WIRE: u32 = 0x10;
pub const SPI_LOOP: u32 = 0x20;
pub const SPI_NO_CS: u32 = 0x40;
pub const SPI_READY: u32 = 0x80;
pub const SPI_TX_DUAL: u32 = 0x100;
pub const SPI_TX_QUAD: u32 = 0x200;
pub const SPI_RX_DUAL: u32 = 0x400;
pub const SPI_RX_QUAD: u32 = 0x800;
pub const SPI_CS_WORD: u32 = 0x1000;
pub const SPI_TX_OCTAL: u32 = 0x2000;
pub const SPI_RX_OCTAL: u32 = 0x4000;
pub const SPI_3WIRE_HIZ: u32 = 0x8000;
pub const SPI_RX_CPHA_FLIP: u32 = 0x10000;
pub const SPI_MOSI_IDLE_LOW: u32 = 0x20000;

/// SPI controller info
#[derive(Debug, Clone)]
pub struct SpiControllerInfo {
    pub bus_num: u16,
    pub num_chipselect: u16,
    pub mode_bits: u32,
    pub bits_per_word_mask: u32,
    pub min_speed_hz: u32,
    pub max_speed_hz: u32,
    // DMA
    pub dma_capable: bool,
    pub dma_alignment: u32,
    // Features
    pub cs_gpios: bool,
    pub auto_runtime_pm: bool,
    pub mem_ops: bool,     // SPI memory operations (SPI-NOR/NAND)
    // Transfer
    pub max_transfer_size: u32,
    pub max_message_size: u32,
    // Stats
    pub total_transfers: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
}

/// SPI device info
#[derive(Debug, Clone)]
pub struct SpiDeviceInfo {
    pub modalias: [32; u8],
    pub max_speed_hz: u32,
    pub chip_select: u8,
    pub bits_per_word: u8,
    pub mode: u32,
    pub irq: i32,
    pub controller_nr: u16,
}

/// SPI transfer
#[derive(Debug, Clone)]
pub struct SpiTransfer {
    pub speed_hz: u32,
    pub bits_per_word: u8,
    pub len: u32,
    pub cs_change: bool,
    pub cs_change_delay_value: u16,
    pub cs_change_delay_unit: u8,
    pub delay_usecs: u16,
    pub word_delay_value: u16,
    pub word_delay_unit: u8,
    // Effective settings
    pub effective_speed_hz: u32,
}

/// SPI-NOR flash info
#[derive(Debug, Clone)]
pub struct SpiNorInfo {
    pub name: [32; u8],
    pub jedec_id: [3; u8],
    pub ext_id: [3; u8],
    pub sector_size: u32,
    pub n_sectors: u32,
    pub page_size: u32,
    pub total_size: u64,
    // Features
    pub has_4k_erase: bool,
    pub has_quad_read: bool,
    pub has_octal_read: bool,
    pub has_dtr: bool,          // Double Transfer Rate
    // Status register
    pub status_register_width: u8,
    pub has_volatile_sr: bool,
    // Write protect
    pub has_write_protect: bool,
    pub bp_bits: u8,
}

// ============================================================================
// 1-Wire Bus
// ============================================================================

/// 1-Wire family code
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneWireFamily {
    DS18S20 = 0x10,     // Temperature
    DS18B20 = 0x28,     // Temperature
    DS2413 = 0x3A,      // Dual-channel GPIO
    DS2438 = 0x26,      // Smart battery monitor
    DS2431 = 0x2D,      // 1024-bit EEPROM
    DS28E17 = 0x19,     // 1-Wire to I2C bridge
    DS2408 = 0x29,      // 8-channel GPIO
    DS2450 = 0x20,      // Quad A/D converter
    DS1990A = 0x01,     // Serial number iButton
    DS1993 = 0x06,      // 4Kbit memory iButton
    DS1996 = 0x0C,      // 64Kbit memory iButton
    DS2406 = 0x12,      // Dual-addressable switch
    DS2423 = 0x1D,      // 4Kbit RAM + counter
    DS2502 = 0x09,      // 1Kbit add-only memory
}

/// 1-Wire ROM command
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneWireRomCmd {
    ReadRom = 0x33,
    MatchRom = 0x55,
    SkipRom = 0xCC,
    SearchRom = 0xF0,
    AlarmSearch = 0xEC,
    OverdriveSkipRom = 0x3C,
    OverdriveMatchRom = 0x69,
    ResumeRom = 0xA5,
}

/// 1-Wire device address (64-bit ROM ID)
#[derive(Debug, Clone, Copy)]
pub struct OneWireAddr {
    pub family: u8,
    pub serial: [6; u8],
    pub crc: u8,
}

/// 1-Wire bus master info
#[derive(Debug, Clone)]
pub struct OneWireMasterInfo {
    pub id: u32,
    pub name: [32; u8],
    // Timing
    pub overdrive: bool,
    pub strong_pullup: bool,
    // Stats
    pub total_resets: u64,
    pub total_writes: u64,
    pub total_reads: u64,
    pub total_search_attempts: u64,
    pub total_devices_found: u64,
    pub total_crc_errors: u64,
}

// ============================================================================
// MDIO Bus (Management Data Input/Output)
// ============================================================================

/// MDIO bus type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdioBusType {
    Clause22 = 0,    // Standard
    Clause45 = 1,    // Extended (multi-register)
}

/// PHY interface type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyInterface {
    Na = 0,
    Internal = 1,
    Mii = 2,
    Gmii = 3,
    Sgmii = 4,
    Tbi = 5,
    Revmii = 6,
    Rmii = 7,
    Revrmii = 8,
    Rgmii = 9,
    RgmiiId = 10,
    RgmiiRxid = 11,
    RgmiiTxid = 12,
    Rtbi = 13,
    Smii = 14,
    Xgmii = 15,
    Xlgmii = 16,
    Moca = 17,
    Qsgmii = 18,
    Trgmii = 19,
    OneThousand_basex = 20,
    TwoFiveHundred_basex = 21,
    FiveGbase_r = 22,
    Rxaui = 23,
    Xaui = 24,
    TenGbase_kr = 25,
    TenGbase_r = 26,
    Usxgmii = 27,
    TwentyFiveGbase_r = 28,
    FiftyGbase_r = 29,
    HundredGbase_r = 30,
    // Zxyphor
    ZxyUltra = 100,
}

/// PHY state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyState {
    Down = 0,
    Ready = 1,
    Halted = 2,
    Error = 3,
    Up = 4,
    Running = 5,
    NoLink = 6,
    Cabletest = 7,
}

/// PHY speed
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhySpeed {
    Speed10 = 10,
    Speed100 = 100,
    Speed1000 = 1000,
    Speed2500 = 2500,
    Speed5000 = 5000,
    Speed10000 = 10000,
    Speed14000 = 14000,
    Speed20000 = 20000,
    Speed25000 = 25000,
    Speed40000 = 40000,
    Speed50000 = 50000,
    Speed56000 = 56000,
    Speed100000 = 100000,
    Speed200000 = 200000,
    Speed400000 = 400000,
    Speed800000 = 800000,
    Unknown = 0,
}

/// PHY device info
#[derive(Debug, Clone)]
pub struct PhyDeviceInfo {
    pub phy_id: u32,
    pub phy_id_mask: u32,
    pub addr: u8,
    pub interface: PhyInterface,
    pub speed: PhySpeed,
    pub duplex: bool,
    pub autoneg: bool,
    pub state: PhyState,
    // Link partner
    pub lp_advertising: u64,
    // Cable diagnostics
    pub has_cable_test: bool,
    // Energy Efficient Ethernet
    pub eee_enabled: bool,
    pub eee_active: bool,
    // Interrupts
    pub has_interrupt: bool,
    pub irq: i32,
    // Stats
    pub link_up_events: u64,
    pub link_down_events: u64,
}

// ============================================================================
// Regulator Consumer API
// ============================================================================

/// Regulator type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegulatorType {
    Voltage = 0,
    Current = 1,
}

/// Regulator consumer info
#[derive(Debug, Clone)]
pub struct RegulatorConsumer {
    pub supply: [32; u8],
    pub regulator_type: RegulatorType,
    // Voltage
    pub min_uv: i32,
    pub max_uv: i32,
    pub cur_uv: i32,
    // Current
    pub max_ua: i32,
    pub cur_ua: i32,
    // Mode
    pub mode: RegulatorMode,
    // State
    pub enabled: bool,
    pub always_on: bool,
    pub boot_on: bool,
    // Power
    pub power_uw: u32,
}

/// Regulator mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegulatorMode {
    Invalid = 0,
    Fast = 1,
    Normal = 2,
    Idle = 3,
    Standby = 4,
}

// ============================================================================
// Reset Controller
// ============================================================================

/// Reset controller
#[derive(Debug, Clone)]
pub struct ResetController {
    pub name: [32; u8],
    pub nr_resets: u32,
    // Stats
    pub total_asserts: u64,
    pub total_deasserts: u64,
    pub total_resets: u64,
}

/// Reset control flags
pub const RESET_SHARED: u32 = 1;
pub const RESET_EXCLUSIVE: u32 = 2;
pub const RESET_DEASSERTED: u32 = 4;

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Bus subsystem
#[derive(Debug, Clone)]
pub struct BusSubsystem {
    // I2C
    pub nr_i2c_adapters: u32,
    pub nr_i2c_clients: u32,
    pub i2c_total_transfers: u64,
    pub i2c_total_errors: u64,
    // SPI
    pub nr_spi_controllers: u32,
    pub nr_spi_devices: u32,
    pub spi_total_transfers: u64,
    pub spi_total_errors: u64,
    // 1-Wire
    pub nr_1w_masters: u32,
    pub nr_1w_devices: u32,
    pub onewire_total_ops: u64,
    // MDIO / PHY
    pub nr_mdio_buses: u32,
    pub nr_phy_devices: u32,
    pub phy_link_events: u64,
    // Regulator
    pub nr_regulators: u32,
    pub nr_regulator_consumers: u32,
    // Reset
    pub nr_reset_controllers: u32,
    pub total_resets: u64,
    // Zxyphor
    pub zxy_auto_discovery: bool,
    pub initialized: bool,
}
