// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - MTD Flash Subsystem Detail
// Complete: MTD device types, NOR/NAND flash, NAND chip info,
// ECC/OOB layout, bad block management, UBI (Unsorted Block Images),
// UBIFS, SPI-NOR, raw/managed NAND, CFI interface, partition parsing

const std = @import("std");

// ============================================================================
// MTD Device Types
// ============================================================================

pub const MtdType = enum(u8) {
    Absent = 0,
    Ram = 1,
    Rom = 2,
    NorFlash = 3,
    NandFlash = 4,
    DataFlash = 5,
    UbiVolume = 6,
    MlcNandFlash = 7,
};

pub const MtdFlags = packed struct(u32) {
    writeable: bool,
    bit_writeable: bool,
    no_erase: bool,
    powerup_lock: bool,
    spi_nor_has_lock: bool,
    spi_nor_has_tb: bool,
    _reserved: u26,
};

pub const MtdFileMode = enum(u8) {
    Normal = 0,
    Otp_Factory = 1,
    Otp_User = 2,
    Raw = 3,
};

// ============================================================================
// MTD Device
// ============================================================================

pub const MtdInfo = struct {
    type_field: MtdType,
    flags: MtdFlags,
    size: u64,              // Total device size in bytes
    erasesize: u32,         // Erase block size
    writesize: u32,         // Minimum writable block size
    writebufsize: u32,      // Maximum write buffer size
    oobsize: u32,           // OOB (out-of-band) area size per page
    oobavail: u32,          // Available OOB bytes per page
    erasesize_shift: u32,
    writesize_shift: u32,
    erasesize_mask: u32,
    writesize_mask: u32,
    bitflip_threshold: u32,
    ecc_stats: MtdEccStats,
    subpage_sft: u32,
    name: [64]u8,
    index: i32,
    numeraseregions: i32,
    eraseregions: [8]MtdEraseRegion,
    reboot_notifier: u64,
    dev: ?*anyopaque,
    owner: ?*anyopaque,
    usecount: u32,
};

pub const MtdEccStats = struct {
    corrected: u32,
    failed: u32,
    badblocks: u32,
    bbtblocks: u32,
};

pub const MtdEraseRegion = struct {
    offset: u64,
    erasesize: u64,
    numblocks: u32,
    lockmap: ?*anyopaque,
};

pub const MtdOps = struct {
    erase: ?*const fn (info: *MtdInfo, instr: *MtdEraseInfo) callconv(.C) i32,
    point: ?*const fn (info: *MtdInfo, from: u64, len: usize, retlen: *usize, virt: *?*anyopaque, phys: *u64) callconv(.C) i32,
    unpoint: ?*const fn (info: *MtdInfo, from: u64, len: usize) callconv(.C) i32,
    read: ?*const fn (info: *MtdInfo, from: u64, len: usize, retlen: *usize, buf: [*]u8) callconv(.C) i32,
    write: ?*const fn (info: *MtdInfo, to: u64, len: usize, retlen: *usize, buf: [*]const u8) callconv(.C) i32,
    panic_write: ?*const fn (info: *MtdInfo, to: u64, len: usize, retlen: *usize, buf: [*]const u8) callconv(.C) i32,
    read_oob: ?*const fn (info: *MtdInfo, from: u64, ops: *MtdOobOps) callconv(.C) i32,
    write_oob: ?*const fn (info: *MtdInfo, to: u64, ops: *MtdOobOps) callconv(.C) i32,
    get_fact_prot_info: ?*const fn (info: *MtdInfo, len: usize, retlen: *usize, buf: [*]MtdOtpInfo) callconv(.C) i32,
    read_fact_prot_reg: ?*const fn (info: *MtdInfo, from: u64, len: usize, retlen: *usize, buf: [*]u8) callconv(.C) i32,
    get_user_prot_info: ?*const fn (info: *MtdInfo, len: usize, retlen: *usize, buf: [*]MtdOtpInfo) callconv(.C) i32,
    read_user_prot_reg: ?*const fn (info: *MtdInfo, from: u64, len: usize, retlen: *usize, buf: [*]u8) callconv(.C) i32,
    write_user_prot_reg: ?*const fn (info: *MtdInfo, to: u64, len: usize, retlen: *usize, buf: [*]const u8) callconv(.C) i32,
    lock_user_prot_reg: ?*const fn (info: *MtdInfo, from: u64, len: u64) callconv(.C) i32,
    lock: ?*const fn (info: *MtdInfo, ofs: u64, len: u64) callconv(.C) i32,
    unlock: ?*const fn (info: *MtdInfo, ofs: u64, len: u64) callconv(.C) i32,
    is_locked: ?*const fn (info: *MtdInfo, ofs: u64, len: u64) callconv(.C) i32,
    block_isbad: ?*const fn (info: *MtdInfo, ofs: u64) callconv(.C) i32,
    block_markbad: ?*const fn (info: *MtdInfo, ofs: u64) callconv(.C) i32,
    suspend: ?*const fn (info: *MtdInfo) callconv(.C) i32,
    resume: ?*const fn (info: *MtdInfo) callconv(.C) void,
    get_device: ?*const fn (info: *MtdInfo) callconv(.C) i32,
    put_device: ?*const fn (info: *MtdInfo) callconv(.C) void,
};

pub const MtdEraseInfo = struct {
    addr: u64,
    len: u64,
    time: u64,
    retries: u64,
    state: MtdEraseState,
    fail_addr: u64,
    callback: ?*const fn (instr: *MtdEraseInfo) callconv(.C) void,
};

pub const MtdEraseState = enum(u8) {
    Pending = 0,
    Erasing = 1,
    Done = 2,
    Failed = 3,
};

pub const MtdOobOps = struct {
    mode: MtdOobMode,
    len: usize,
    retlen: usize,
    ooblen: usize,
    oobretlen: usize,
    ooboffs: u32,
    datbuf: ?[*]u8,
    oobbuf: ?[*]u8,
};

pub const MtdOobMode = enum(u8) {
    Place = 0,
    Auto = 1,
    Raw = 2,
};

pub const MtdOtpInfo = struct {
    start: u32,
    length: u32,
    locked: bool,
};

// ============================================================================
// NAND Flash
// ============================================================================

pub const NandCellType = enum(u8) {
    SLC = 0,     // Single-Level Cell (1 bit)
    MLC = 1,     // Multi-Level Cell (2 bits)
    TLC = 2,     // Triple-Level Cell (3 bits)
    QLC = 3,     // Quad-Level Cell (4 bits)
};

pub const NandInterface = enum(u8) {
    SDR = 0,           // Single Data Rate
    NV_DDR = 1,        // ONFI NV-DDR
    NV_DDR2 = 2,       // ONFI NV-DDR2
    NV_DDR3 = 3,       // ONFI NV-DDR3
    Toggle_v1 = 4,     // Toggle 1.0
    Toggle_v2 = 5,     // Toggle 2.0
};

pub const NandManufacturer = enum(u8) {
    Samsung = 0xEC,
    Toshiba = 0x98,
    Hynix = 0xAD,
    Micron = 0x2C,
    Intel = 0x89,
    Macronix = 0xC2,
    Spansion = 0x01,
    Winbond = 0xEF,
    GigaDevice = 0xC8,
    ESMT = 0x92,
    Paragon = 0xA1,
    XTX = 0x0B,
};

pub const NandChipInfo = struct {
    id_data: [8]u8,
    manufacturer: NandManufacturer,
    model: [32]u8,
    cell_type: NandCellType,
    interface_type: NandInterface,
    page_size: u32,
    oob_size: u32,
    pages_per_block: u32,
    blocks_per_lun: u32,
    luns_per_target: u32,
    nr_targets: u32,
    bits_per_cell: u8,
    planes: u8,
    total_size: u64,
    ecc_step_size: u32,
    ecc_strength: u32,
    max_bad_blocks_per_lun: u32,
    onfi_version: u16,
    jedec_version: u16,
    features: NandFeatures,
    timing_mode: u8,
};

pub const NandFeatures = packed struct(u32) {
    extended_param_page: bool,
    onfi: bool,
    jedec: bool,
    supports_set_features: bool,
    supports_get_features: bool,
    programmable_output_drive: bool,
    interleaved_ops: bool,
    odd_even_page_pairs: bool,
    cache_program: bool,
    cache_read: bool,
    multi_plane_read: bool,
    multi_plane_program: bool,
    multi_plane_erase: bool,
    nv_ddr: bool,
    nv_ddr2: bool,
    ez_nand: bool,
    _reserved: u16,
};

// ============================================================================
// ECC / OOB Layout
// ============================================================================

pub const NandEccMode = enum(u8) {
    None = 0,
    Soft = 1,
    Hw = 2,
    HwSyndrome = 3,
    HwOobFirst = 4,
    OnDie = 5,
};

pub const NandEccAlgo = enum(u8) {
    Unknown = 0,
    Hamming = 1,
    Bch = 2,
    Rs = 3,
    ReedSolomon = 3,
};

pub const NandEccLayout = struct {
    eccbytes: u32,
    eccpos: [128]u32,
    oobfree: [8]NandOobfree,
    oobavail: u32,
};

pub const NandOobfree = struct {
    offset: u32,
    length: u32,
};

pub const NandEccReq = struct {
    strength: u16,    // Required ECC strength
    step_size: u16,   // ECC step size
};

pub const NandEccCtrl = struct {
    mode: NandEccMode,
    algo: NandEccAlgo,
    steps: u32,
    size: u32,
    bytes: u32,
    total: u32,
    strength: u32,
    prepad: u32,
    postpad: u32,
    options: u32,
    calc_buf: [256]u8,
    code_buf: [256]u8,
    layout: NandEccLayout,
};

// ============================================================================
// Bad Block Table
// ============================================================================

pub const NandBbtDescr = struct {
    options: NandBbtOptions,
    pages: [8]i32,
    offs: u8,
    veroffs: u8,
    version: [8]u8,
    len: u8,
    maxblocks: u8,
    reserved_block_code: u8,
    pattern: [4]u8,
};

pub const NandBbtOptions = packed struct(u32) {
    nand_bbt_use_flash: bool,
    nand_bbt_abspage: bool,
    nand_bbt_scan2ndpage: bool,
    nand_bbt_lastblock: bool,
    nand_bbt_perchip: bool,
    nand_bbt_version: bool,
    nand_bbt_create: bool,
    nand_bbt_write: bool,
    nand_bbt_savecontent: bool,
    nand_bbt_scan_good_factory: bool,
    _reserved: u22,
};

// ============================================================================
// SPI-NOR Flash
// ============================================================================

pub const SpiNorType = enum(u8) {
    Read = 0,
    FastRead = 1,
    DualOutput = 2,
    QuadOutput = 3,
    DualIO = 4,
    QuadIO = 5,
    OctalOutput = 6,
    OctalIO = 7,
    OctalDtr = 8,
};

pub const SpiNorCmd = enum(u8) {
    ReadId = 0x9F,
    ReadSfdp = 0x5A,
    Read = 0x03,
    FastRead = 0x0B,
    DualOutputRead = 0x3B,
    QuadOutputRead = 0x6B,
    DualIORead = 0xBB,
    QuadIORead = 0xEB,
    OctalOutputRead = 0x8B,
    OctalIORead = 0xCB,
    PageProgram = 0x02,
    QuadPageProgram = 0x32,
    SectorErase4K = 0x20,
    BlockErase32K = 0x52,
    BlockErase64K = 0xD8,
    ChipErase = 0xC7,
    WriteEnable = 0x06,
    WriteDisable = 0x04,
    ReadStatusReg1 = 0x05,
    ReadStatusReg2 = 0x35,
    ReadStatusReg3 = 0x15,
    WriteStatusReg1 = 0x01,
    WriteStatusReg2 = 0x31,
    WriteStatusReg3 = 0x11,
    Enter4ByteAddr = 0xB7,
    Exit4ByteAddr = 0xE9,
    EnableReset = 0x66,
    Reset = 0x99,
    DeepPowerDown = 0xB9,
    ReleaseDeepPowerDown = 0xAB,
};

pub const SpiNorFlash = struct {
    name: [32]u8,
    jedec_id: [3]u8,
    ext_id: [2]u8,
    size: u64,
    page_size: u32,
    sector_size: u32,
    n_sectors: u32,
    addr_width: u8,
    flags: SpiNorFlags,
    read_proto: SpiNorType,
    write_proto: SpiNorType,
    max_speed_hz: u32,
    erase_map: SpiNorEraseMap,
};

pub const SpiNorFlags = packed struct(u32) {
    has_lock: bool,
    has_tb: bool,
    use_clsr: bool,
    no_4bait: bool,
    no_chip_erase: bool,
    no_sfdp_flags: bool,
    skip_sfdp: bool,
    has_sr_tb_bit6: bool,
    spi_nor_4b_opcodes: bool,
    io_mode_en_volatile: bool,
    soft_reset: bool,
    spi_nor_octal_dtr_read: bool,
    spi_nor_octal_dtr_pp: bool,
    _reserved: u19,
};

pub const SpiNorEraseMap = struct {
    regions: [4]SpiNorEraseRegion,
    nr_regions: u8,
    uniform_erase_type: ?*SpiNorEraseType,
};

pub const SpiNorEraseRegion = struct {
    offset: u64,
    size: u64,
    erase_type: SpiNorEraseType,
};

pub const SpiNorEraseType = struct {
    size: u32,
    opcode: u8,
    size_shift: u8,
    size_mask: u32,
};

// ============================================================================
// SFDP (Serial Flash Discoverable Parameters)
// ============================================================================

pub const SfdpHeader = packed struct {
    signature: u32,     // "SFDP"
    minor: u8,
    major: u8,
    nph: u8,            // Number of parameter headers
    access_protocol: u8,
};

pub const SfdpParamHeader = packed struct {
    id_lsb: u8,
    minor: u8,
    major: u8,
    length: u8,         // In dwords
    ptp: u24,           // Parameter table pointer (byte address)
    id_msb: u8,
};

// ============================================================================
// UBI (Unsorted Block Images)
// ============================================================================

pub const UbiVolumeType = enum(u8) {
    Dynamic = 0,
    Static = 1,
};

pub const UbiDevice = struct {
    ubi_num: i32,
    mtd_num: i32,
    min_io_size: i32,
    max_write_size: i32,
    leb_size: i32,
    leb_start: i32,
    leb_count: i32,
    max_ec: i32,         // Maximum erase counter
    mean_ec: i32,        // Mean erase counter
    bad_peb_count: i32,
    good_peb_count: i32,
    max_vol_count: i32,
    vol_count: i32,
    ro_mode: bool,
    image_seq: u32,
    fast_map: bool,
};

pub const UbiVolume = struct {
    vol_id: i32,
    vol_type: UbiVolumeType,
    alignment: i32,
    data_pad: i32,
    name: [128]u8,
    name_len: u16,
    used_ebs: i32,       // Used eraseblocks
    reserved_pebs: i32,
    usable_leb_size: i32,
    used_bytes: i64,
    corrupted: bool,
    upd_marker: bool,
    skip_check: bool,
    direct_writes: bool,
};

pub const UbiEcHeader = packed struct {
    magic: u32,        // UBI_EC_HDR_MAGIC
    version: u8,
    padding1: [3]u8,
    ec: u64,           // Erase counter
    vid_hdr_offset: u32,
    data_offset: u32,
    image_seq: u32,
    padding2: [32]u8,
    hdr_crc: u32,
};

pub const UbiVidHeader = packed struct {
    magic: u32,        // UBI_VID_HDR_MAGIC
    version: u8,
    vol_type: u8,
    copy_flag: u8,
    compat: u8,
    vol_id: u32,
    lnum: u32,
    padding1: [4]u8,
    data_size: u32,
    used_ebs: u32,
    data_pad: u32,
    data_crc: u32,
    padding2: [4]u8,
    sqnum: u64,
    padding3: [12]u8,
    hdr_crc: u32,
};

// ============================================================================
// MTD Partitions
// ============================================================================

pub const MtdPartition = struct {
    name: [64]u8,
    types: [4]MtdPartType,
    size: u64,
    offset: u64,
    mask_flags: MtdFlags,
    ecclayout: ?*NandEccLayout,
};

pub const MtdPartType = enum(u8) {
    Fixed = 0,
    Cmdline = 1,
    Ofpart = 2,
    RedBoot = 3,
    Afs = 4,
    Parser = 5,
};

// ============================================================================
// Manager
// ============================================================================

pub const MtdFlashManager = struct {
    devices: [32]?*MtdInfo,
    device_count: u32,
    ubi_devices: [16]?*UbiDevice,
    ubi_count: u32,
    total_erases: u64,
    total_writes: u64,
    total_reads: u64,
    total_bad_blocks: u64,
    total_ecc_corrected: u64,
    total_ecc_failed: u64,
    initialized: bool,

    pub fn init() MtdFlashManager {
        return .{
            .devices = [_]?*MtdInfo{null} ** 32,
            .device_count = 0,
            .ubi_devices = [_]?*UbiDevice{null} ** 16,
            .ubi_count = 0,
            .total_erases = 0,
            .total_writes = 0,
            .total_reads = 0,
            .total_bad_blocks = 0,
            .total_ecc_corrected = 0,
            .total_ecc_failed = 0,
            .initialized = true,
        };
    }
};
