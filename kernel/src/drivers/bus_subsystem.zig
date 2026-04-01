// SPDX-License-Identifier: GPL-2.0 OR MIT  
// Zxyphor Kernel - I2C, SPI, Platform Bus and DMA Engine Subsystems
// I2C bus controller/client, SPI master/slave, Platform device/driver,
// DMA engine API with scatter-gather, interleaved transfers
// More advanced than Linux 2026 bus subsystem architecture

const std = @import("std");

// ============================================================================
// I2C Bus Subsystem
// ============================================================================

pub const I2C_MAX_ADAPTERS: u32 = 32;
pub const I2C_MAX_CLIENTS: u32 = 256;

pub const I2cMsg = struct {
    addr: u16,        // 7-bit or 10-bit slave address
    flags: u16,
    len: u16,
    buf: [256]u8,
};

// I2C Message flags
pub const I2C_M_RD: u16 = 0x0001;
pub const I2C_M_TEN: u16 = 0x0010;          // 10-bit address
pub const I2C_M_DMA_SAFE: u16 = 0x0200;
pub const I2C_M_RECV_LEN: u16 = 0x0400;
pub const I2C_M_NO_RD_ACK: u16 = 0x0800;
pub const I2C_M_IGNORE_NAK: u16 = 0x1000;
pub const I2C_M_REV_DIR_ADDR: u16 = 0x2000;
pub const I2C_M_NOSTART: u16 = 0x4000;
pub const I2C_M_STOP: u16 = 0x8000;

pub const I2cAlgorithm = struct {
    master_xfer: ?*const fn (*I2cAdapter, []I2cMsg) i32,
    smbus_xfer: ?*const fn (*I2cAdapter, u16, u16, u8, u8, u8, *I2cSmbusData) i32,
    functionality: ?*const fn (*I2cAdapter) u32,
    reg_slave: ?*const fn (*I2cClient) i32,
    unreg_slave: ?*const fn (*I2cClient) i32,
};

// I2C functionality flags
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

pub const I2cSmbusData = union {
    byte: u8,
    word: u16,
    block: [34]u8,
};

pub const I2cAdapter = struct {
    nr: u32,
    name: [48]u8,
    algo: ?*I2cAlgorithm,
    retries: u32,
    timeout_ms: u32,
    class: u32,
    bus_lock: bool,
    // Speed
    bus_freq_hz: u32,
    // 10-bit address support
    ten_bit_supported: bool,
    // DMA
    dma_safe: bool,
    // Stats
    transfers: u64,
    errors: u64,
    timeouts: u64,
    nacks: u64,
    // Power
    suspended: bool,
    // Quirks
    quirks: I2cAdapterQuirks,
};

pub const I2cAdapterQuirks = struct {
    flags: u32,
    max_num_msgs: u16,
    max_write_len: u32,
    max_read_len: u32,
    max_comb_1st_msg_len: u32,
    max_comb_2nd_msg_len: u32,
};

pub const I2cClient = struct {
    addr: u16,
    name: [20]u8,
    adapter: ?*I2cAdapter,
    flags: u16,
    irq: i32,
    // Slave callback
    slave_cb: ?*const fn (*I2cClient, u8, *u8) i32,
    // Wake
    init_irq: i32,
    detected: bool,
    // Power
    suspended: bool,
};

pub const I2cBoardInfo = struct {
    type_name: [20]u8,
    flags: u16,
    addr: u16,
    irq: i32,
    platform_data: ?*anyopaque,
};

// ============================================================================
// SPI Bus Subsystem
// ============================================================================

pub const SPI_MAX_CONTROLLERS: u32 = 16;
pub const SPI_MAX_DEVICES: u32 = 128;

pub const SpiMode = packed struct {
    cpha: bool,           // Clock phase
    cpol: bool,           // Clock polarity
    cs_high: bool,        // Chip select active high
    lsb_first: bool,      // LSB first
    three_wire: bool,     // SI/SO signals shared
    loop_back: bool,      // Loopback
    no_cs: bool,          // No chip select
    ready: bool,          // Slave ready
    tx_dual: bool,
    tx_quad: bool,
    tx_octal: bool,
    rx_dual: bool,
    rx_quad: bool,
    rx_octal: bool,
    cs_word: bool,
    tx_crc: bool,
};

pub const SpiTransfer = struct {
    tx_buf: ?[*]const u8,
    rx_buf: ?[*]u8,
    len: u32,
    tx_nbits: u8,         // 1/2/4/8
    rx_nbits: u8,
    speed_hz: u32,
    bits_per_word: u8,
    delay_usecs: u16,
    cs_change: bool,
    cs_change_delay_value: u32,
    cs_change_delay_unit: u8,
    word_delay_value: u32,
    word_delay_unit: u8,
    effective_speed_hz: u32,
    // DMA
    tx_dma: u64,
    rx_dma: u64,
    // Scatter-gather
    tx_sg_nents: u32,
    rx_sg_nents: u32,
};

pub const SpiMessage = struct {
    transfers: [16]SpiTransfer,
    nr_transfers: u32,
    spi: ?*SpiDevice,
    status: i32,
    actual_length: u32,
    // Completion
    complete: bool,
    // Frame length (for QSPI etc.)
    frame_length: u32,
};

pub const SpiController = struct {
    bus_num: u32,
    num_chipselect: u16,
    // Mode
    mode_bits: u32,
    bits_per_word_mask: u32,
    min_speed_hz: u32,
    max_speed_hz: u32,
    // Transfer
    setup: ?*const fn (*SpiDevice) i32,
    transfer_one: ?*const fn (*SpiController, *SpiDevice, *SpiTransfer) i32,
    set_cs: ?*const fn (*SpiDevice, bool) void,
    // DMA
    dma_tx: ?*anyopaque,
    dma_rx: ?*anyopaque,
    can_dma: ?*const fn (*SpiController, *SpiDevice, *SpiTransfer) bool,
    // Queue
    queued: bool,
    running: bool,
    busy: bool,
    // Stats
    transfers_completed: u64,
    bytes_transferred: u64,
    errors: u64,
    // Auto CS
    auto_runtime_pm: bool,
    // Memory ops (SPI-NOR, SPI-NAND)
    mem_ops: ?*SpiMemOps,
};

pub const SpiDevice = struct {
    controller: ?*SpiController,
    max_speed_hz: u32,
    chip_select: u8,
    bits_per_word: u8,
    rt: bool,
    mode: SpiMode,
    irq: i32,
    modalias: [32]u8,
    cs_gpiod: ?*anyopaque,
    // Word delay
    word_delay_value: u32,
    word_delay_unit: u8,
    // Stats
    cs_inactive_ns: u32,
};

pub const SpiMemOp = struct {
    cmd: struct {
        nbytes: u8,
        buswidth: u8,
        opcode: u16,
        dtr: bool,
    },
    addr: struct {
        nbytes: u8,
        buswidth: u8,
        val: u64,
        dtr: bool,
    },
    dummy: struct {
        nbytes: u8,
        buswidth: u8,
        dtr: bool,
    },
    data: struct {
        buswidth: u8,
        dir: enum(u1) { in_dir = 0, out_dir = 1 },
        nbytes: u32,
        buf_in: ?[*]u8,
        buf_out: ?[*]const u8,
        dtr: bool,
    },
};

pub const SpiMemOps = struct {
    exec_op: ?*const fn (*SpiController, *const SpiMemOp) i32,
    get_name: ?*const fn (*SpiController) [32]u8,
    dirmap_create: ?*const fn (*SpiController) i32,
    dirmap_read: ?*const fn (*SpiController, u64, u64, [*]u8) i64,
    dirmap_write: ?*const fn (*SpiController, u64, u64, [*]const u8) i64,
    supports_op: ?*const fn (*SpiController, *const SpiMemOp) bool,
    adjust_op_size: ?*const fn (*SpiController, *SpiMemOp) i32,
};

// ============================================================================
// Platform Bus
// ============================================================================

pub const PlatformDeviceId = struct {
    name: [20]u8,
    driver_data: u64,
};

pub const PlatformDevice = struct {
    name: [64]u8,
    id: i32,
    id_auto: bool,
    num_resources: u32,
    resources: [16]PlatformResource,
    // Device tree match
    of_node: ?*anyopaque,
    // ACPI
    acpi_node: ?*anyopaque,
    // Platform data
    platform_data: ?*anyopaque,
    platform_data_size: u64,
    // Driver
    driver: ?*PlatformDriver,
    // IRQ
    irqs: [8]i32,
    nr_irqs: u32,
    // DMA
    dma_mask: u64,
    coherent_dma_mask: u64,
    // Power
    pm_domain: ?*anyopaque,
    // State
    registered: bool,
};

pub const PlatformResource = struct {
    start: u64,
    end: u64,
    name: [32]u8,
    flags: u32,
    parent: ?*PlatformResource,
};

// Resource flags
pub const IORESOURCE_MEM: u32 = 0x00000200;
pub const IORESOURCE_IO: u32 = 0x00000100;
pub const IORESOURCE_IRQ: u32 = 0x00000400;
pub const IORESOURCE_DMA: u32 = 0x00000800;
pub const IORESOURCE_BUS: u32 = 0x00001000;
pub const IORESOURCE_PREFETCH: u32 = 0x00002000;
pub const IORESOURCE_MEM_64: u32 = 0x00100000;

pub const PlatformDriver = struct {
    probe: ?*const fn (*PlatformDevice) i32,
    remove: ?*const fn (*PlatformDevice) i32,
    shutdown: ?*const fn (*PlatformDevice) void,
    suspend: ?*const fn (*PlatformDevice, u32) i32,
    resume: ?*const fn (*PlatformDevice) i32,
    // ID tables
    id_table: ?[*]const PlatformDeviceId,
    // OF match
    of_match_table: ?[*]const OfDeviceId,
    // ACPI match
    acpi_match_table: ?[*]const AcpiDeviceId,
    // Prevent deferred probing
    prevent_deferred_probe: bool,
};

pub const OfDeviceId = struct {
    name: [32]u8,
    type_str: [32]u8,
    compatible: [128]u8,
    data: ?*const anyopaque,
};

pub const AcpiDeviceId = struct {
    id: [16]u8,
    driver_data: u64,
    cls: u32,
    cls_msk: u32,
};

// ============================================================================
// DMA Engine API
// ============================================================================

pub const DmaTransferDirection = enum(u8) {
    mem_to_mem = 0,
    mem_to_dev = 1,
    dev_to_mem = 2,
    dev_to_dev = 3,
};

pub const DmaCtrl = enum(u8) {
    pause = 0,
    resume = 1,
    terminate = 2,
    terminate_all = 3,
};

pub const DmaStatus = enum(u8) {
    success = 0,
    in_progress = 1,
    paused = 2,
    error = 3,
    no_channel = 4,
};

pub const DmaCapability = enum(u8) {
    memcpy = 0,
    xor = 1,
    pq = 2,           // P+Q (RAID6)
    memset = 3,
    interrupt = 4,
    sg = 5,            // Scatter-gather
    cyclic = 6,
    interleave = 7,
    slave = 8,
    private = 9,
};

pub const DmaSlaveConfig = struct {
    direction: DmaTransferDirection,
    src_addr: u64,
    dst_addr: u64,
    src_addr_width: DmaSlaveAddrWidth,
    dst_addr_width: DmaSlaveAddrWidth,
    src_maxburst: u32,
    dst_maxburst: u32,
    src_port_window_size: u32,
    dst_port_window_size: u32,
    device_fc: bool,
    peripheral_config: ?*anyopaque,
    peripheral_size: u32,
};

pub const DmaSlaveAddrWidth = enum(u8) {
    undefined = 0,
    width_1 = 1,
    width_2 = 2,
    width_3 = 3,
    width_4 = 4,
    width_8 = 8,
    width_16 = 16,
    width_32 = 32,
    width_64 = 64,
};

pub const DmaDescriptor = struct {
    cookie: i64,
    flags: u32,
    // Scatter-gather
    sg_list: [64]DmaSgEntry,
    nr_sg: u32,
    // Transfer size
    len: u64,
    // Direction
    direction: DmaTransferDirection,
    // Callback
    callback: ?*const fn (*DmaDescriptor) void,
    callback_param: ?*anyopaque,
    // Stats
    residue: u64,
    result: DmaStatus,
    // Metadata
    metadata_ops: u32,
};

pub const DmaSgEntry = struct {
    src_addr: u64,
    dst_addr: u64,
    length: u32,
};

pub const DmaInterleavedTemplate = struct {
    src_start: u64,
    dst_start: u64,
    dir: DmaTransferDirection,
    src_inc: bool,
    dst_inc: bool,
    src_sgl: bool,
    dst_sgl: bool,
    nr_chunks: u32,
    frame_size: u32,
    chunks: [16]DmaChunk,
};

pub const DmaChunk = struct {
    size: u64,
    icg: u64,    // Inter-chunk gap
    dst_icg: u64,
    src_icg: u64,
};

pub const DmaChannel = struct {
    chan_id: u32,
    device: ?*DmaDevice,
    // Config
    config: DmaSlaveConfig,
    // State
    status: DmaStatus,
    // Stats
    bytes_transferred: u64,
    memcpy_count: u64,
    sg_count: u64,
    cyclic_count: u64,
    errors: u64,
    // Private
    private_data: ?*anyopaque,
};

pub const DmaDevice = struct {
    dev_id: u32,
    name: [64]u8,
    // Capabilities
    cap_mask: u32,
    max_sg_burst: u32,
    residue_granularity: DmaResidueGranularity,
    // Channels
    channels: [32]DmaChannel,
    nr_channels: u32,
    // Ops
    alloc_chan_resources: ?*const fn (*DmaChannel) i32,
    free_chan_resources: ?*const fn (*DmaChannel) void,
    prep_dma_memcpy: ?*const fn (*DmaChannel, u64, u64, u64, u32) ?*DmaDescriptor,
    prep_dma_sg: ?*const fn (*DmaChannel, []DmaSgEntry, []DmaSgEntry, u32) ?*DmaDescriptor,
    prep_slave_sg: ?*const fn (*DmaChannel, []DmaSgEntry, DmaTransferDirection, u32) ?*DmaDescriptor,
    prep_dma_cyclic: ?*const fn (*DmaChannel, u64, u64, u64, DmaTransferDirection, u32) ?*DmaDescriptor,
    prep_interleaved_dma: ?*const fn (*DmaChannel, *DmaInterleavedTemplate, u32) ?*DmaDescriptor,
    prep_dma_memset: ?*const fn (*DmaChannel, u64, i32, u64, u32) ?*DmaDescriptor,
    prep_dma_xor: ?*const fn (*DmaChannel, u64, [*]u64, u32, u64, u32) ?*DmaDescriptor,
    prep_dma_pq: ?*const fn (*DmaChannel, [*]u64, [*]u64, u32, [*]const u8, u64, u32) ?*DmaDescriptor,
    device_config: ?*const fn (*DmaChannel, *DmaSlaveConfig) i32,
    device_pause: ?*const fn (*DmaChannel) i32,
    device_resume: ?*const fn (*DmaChannel) i32,
    device_terminate_all: ?*const fn (*DmaChannel) i32,
    device_synchronize: ?*const fn (*DmaChannel) void,
    device_tx_status: ?*const fn (*DmaChannel, i64, *DmaTxState) DmaStatus,
    device_issue_pending: ?*const fn (*DmaChannel) void,
    // Power
    suspended: bool,
};

pub const DmaResidueGranularity = enum(u8) {
    descriptor = 0,
    segment = 1,
    burst = 2,
};

pub const DmaTxState = struct {
    last: i64,
    used: i64,
    residue: u64,
    in_flight_bytes: u64,
};

// ============================================================================
// Bus Subsystem Manager
// ============================================================================

pub const BusSubsystem = struct {
    // I2C
    i2c_adapters: [I2C_MAX_ADAPTERS]I2cAdapter,
    nr_i2c_adapters: u32,
    i2c_clients: [I2C_MAX_CLIENTS]I2cClient,
    nr_i2c_clients: u32,
    i2c_total_transfers: u64,
    // SPI
    spi_controllers: [SPI_MAX_CONTROLLERS]SpiController,
    nr_spi_controllers: u32,
    spi_devices: [SPI_MAX_DEVICES]SpiDevice,
    nr_spi_devices: u32,
    spi_total_transfers: u64,
    // Platform
    platform_devices: [512]PlatformDevice,
    nr_platform_devices: u32,
    platform_drivers: [256]PlatformDriver,
    nr_platform_drivers: u32,
    deferred_probes: u32,
    // DMA
    dma_devices: [16]DmaDevice,
    nr_dma_devices: u32,
    dma_total_bytes: u64,
    dma_total_ops: u64,
    // Zxyphor
    zxy_auto_probe: bool,
    zxy_hot_bus_support: bool,
    initialized: bool,
};
