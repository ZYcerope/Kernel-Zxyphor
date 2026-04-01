// Zxyphor Kernel - x86 Platform Setup & Microcode
// Early boot: E820 map parsing, memory detection
// ACPI table discovery, IOAPIC enumeration
// Microcode loading: Intel & AMD formats
// CPU errata workarounds, alternative instructions
// MSR-based feature detection & enablement
// Early serial/console, command line parsing
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// E820 Memory Map (detailed)
// ============================================================================

pub const E820MaxEntries: u32 = 128;

pub const E820Type = enum(u32) {
    ram = 1,
    reserved = 2,
    acpi = 3,
    nvs = 4,
    unusable = 5,
    pmem = 7,
    pram = 12,
    soft_reserved = 0xefffffff,
    reserved_kern = 128,
};

pub const E820Entry = extern struct {
    addr: u64,
    size: u64,
    entry_type: u32,
};

pub const E820Table = struct {
    entries: [E820MaxEntries]E820Entry,
    nr_entries: u32,

    pub fn init() E820Table {
        return E820Table{
            .entries = [_]E820Entry{.{ .addr = 0, .size = 0, .entry_type = 0 }} ** E820MaxEntries,
            .nr_entries = 0,
        };
    }

    pub fn total_ram(self: *const E820Table) u64 {
        var total: u64 = 0;
        for (self.entries[0..self.nr_entries]) |entry| {
            if (entry.entry_type == @intFromEnum(E820Type.ram)) {
                total += entry.size;
            }
        }
        return total;
    }
};

// ============================================================================
// Real Mode Parameters (boot_params equivalent)
// ============================================================================

pub const SetupHeader = extern struct {
    setup_sects: u8,
    root_flags: u16,
    syssize: u32,
    ram_size: u16,
    vid_mode: u16,
    root_dev: u16,
    boot_flag: u16,        // 0xAA55
    jump: u16,
    header_magic: u32,     // "HdrS"
    version: u16,
    realmode_swtch: u32,
    start_sys_seg: u16,
    kernel_version: u16,
    type_of_loader: u8,
    loadflags: u8,
    setup_move_size: u16,
    code32_start: u32,
    ramdisk_image: u32,
    ramdisk_size: u32,
    bootsect_kludge: u32,
    heap_end_ptr: u16,
    ext_loader_ver: u8,
    ext_loader_type: u8,
    cmd_line_ptr: u32,
    initrd_addr_max: u32,
    kernel_alignment: u32,
    relocatable_kernel: u8,
    min_alignment: u8,
    xloadflags: u16,
    cmdline_size: u32,
    hardware_subarch: u32,
    hardware_subarch_data: u64,
    payload_offset: u32,
    payload_length: u32,
    setup_data: u64,
    pref_address: u64,
    init_size: u32,
    handover_offset: u32,
    kernel_info_offset: u32,
};

pub const BootParams = extern struct {
    screen_info: ScreenInfo,
    apm_bios_info: [20]u8,
    _pad2: [4]u8,
    tboot_addr: u64,
    ist_info: [16]u8,
    acpi_rsdp_addr: u64,
    _pad3: [8]u8,
    hd0_info: [16]u8,
    hd1_info: [16]u8,
    sys_desc_table: [16]u8,
    olpc_ofw_header: [16]u8,
    ext_ramdisk_image: u32,
    ext_ramdisk_size: u32,
    ext_cmd_line_ptr: u32,
    _pad4: [112]u8,
    cc_blob_address: u32,
    edid_info: [128]u8,
    efi_info: EfiInfo,
    alt_mem_k: u32,
    scratch: u32,
    e820_entries: u8,
    eddbuf_entries: u8,
    edd_mbr_sig_buf_entries: u8,
    kbd_status: u8,
    secure_boot: u8,
    _pad5: [2]u8,
    sentinel: u8,
    _pad6: [1]u8,
    hdr: SetupHeader,
    _pad7: [36]u8,
    edd_mbr_sig_buffer: [16]u32,
    e820_table: [128]E820Entry,
    _pad8: [48]u8,
    eddbuf: [6][82]u8,
    _pad9: [276]u8,
};

pub const ScreenInfo = extern struct {
    orig_x: u8,
    orig_y: u8,
    ext_mem_k: u16,
    orig_video_page: u16,
    orig_video_mode: u8,
    orig_video_cols: u8,
    flags: u8,
    unused2: u8,
    orig_video_ega_bx: u16,
    unused3: u16,
    orig_video_lines: u8,
    orig_video_is_vga: u8,
    orig_video_points: u16,
    // VBE fields
    lfb_width: u16,
    lfb_height: u16,
    lfb_depth: u16,
    lfb_base: u32,
    lfb_size: u32,
    cl_magic: u16,
    cl_offset: u16,
    lfb_linelength: u16,
    red_size: u8,
    red_pos: u8,
    green_size: u8,
    green_pos: u8,
    blue_size: u8,
    blue_pos: u8,
    rsvd_size: u8,
    rsvd_pos: u8,
    vesapm_seg: u16,
    vesapm_off: u16,
    pages: u16,
    vesa_attributes: u16,
    capabilities: u32,
    ext_lfb_base: u32,
    _reserved: [2]u8,
};

pub const EfiInfo = extern struct {
    efi_loader_signature: u32,
    efi_systab: u32,
    efi_memdesc_size: u32,
    efi_memdesc_version: u32,
    efi_memmap: u32,
    efi_memmap_size: u32,
    efi_systab_hi: u32,
    efi_memmap_hi: u32,
};

// ============================================================================
// CPU Microcode
// ============================================================================

pub const MicrocodeVendor = enum(u8) {
    intel = 0,
    amd = 1,
    unknown = 0xFF,
};

pub const MicrocodeLoadResult = enum(u8) {
    ok = 0,
    not_found = 1,
    error = 2,
    nfit = 3,
    revision_mismatch = 4,
    signature_mismatch = 5,
    checksum_error = 6,
    size_error = 7,
};

// ============================================================================
// Intel Microcode Header
// ============================================================================

pub const IntelMicrocodeHeader = extern struct {
    header_version: u32,      // always 1
    update_revision: u32,
    date: u32,                // MMDDYYYY format
    processor_signature: u32,
    checksum: u32,
    loader_revision: u32,     // always 1
    processor_flags: u32,     // platform ID bits
    data_size: u32,           // 0 = 2000 bytes
    total_size: u32,          // 0 = 2048 bytes
    reserved: [3]u32,
};

pub const IntelMicrocodeExtHeader = extern struct {
    count: u32,
    checksum: u32,
    reserved: [3]u32,
};

pub const IntelMicrocodeExtSig = extern struct {
    processor_signature: u32,
    processor_flags: u32,
    checksum: u32,
};

// ============================================================================
// AMD Microcode
// ============================================================================

pub const AmdMicrocodeHeaderV1 = extern struct {
    data_code: u32,
    patch_id: u32,
    mc_patch_data_id: u16,
    mc_patch_data_len: u8,
    init_flag: u8,
    mc_patch_data_checksum: u32,
    nb_dev_id: u32,
    sb_dev_id: u32,
    processor_rev_id: u16,
    nb_rev_id: u8,
    sb_rev_id: u8,
    bios_api_rev: u8,
    reserved1: [3]u8,
    match_reg: [8]u32,
};

pub const AmdContainerHeader = extern struct {
    magic: u32,  // "AMD\0" = 0x00414d44
};

pub const AmdSectionHeader = extern struct {
    section_type: u32,
    section_size: u32,
};

pub const AmdEquivTableEntry = extern struct {
    installed_cpu: u32,
    fixed_errata_mask: u32,
    fixed_errata_compare: u32,
    equiv_cpu: u16,
    res: u16,
};

// ============================================================================
// CPU Errata & Workarounds
// ============================================================================

pub const CpuBug = enum(u32) {
    // Intel bugs
    spectre_v1 = 0,
    spectre_v2 = 1,
    spec_store_bypass = 2,
    l1tf = 3,
    mds = 4,
    swapgs = 5,
    taa = 6,
    itlb_multihit = 7,
    srbds = 8,
    mmio_stale_data = 9,
    retbleed = 10,
    eibrs_pbrsb = 11,
    gds = 12,
    rfds = 13,
    bhi = 14,
    its = 15,
    // AMD bugs
    sysret_ss_attrs = 16,
    null_seg = 17,
    div0 = 18,
    amd_inception = 19,
    amd_srso = 20,
    // General
    spectre_v2_user = 21,
    mds_clear_idle = 22,
    zenbleed = 23,
    // x86 generic
    cpu_meltdown = 24,
    cpu_insecure = 25,
};

pub const CpuBugMask = packed struct(u32) {
    spectre_v1: bool = false,
    spectre_v2: bool = false,
    spec_store_bypass: bool = false,
    l1tf: bool = false,
    mds: bool = false,
    swapgs: bool = false,
    taa: bool = false,
    itlb_multihit: bool = false,
    srbds: bool = false,
    mmio_stale_data: bool = false,
    retbleed: bool = false,
    eibrs_pbrsb: bool = false,
    gds: bool = false,
    rfds: bool = false,
    bhi: bool = false,
    its: bool = false,
    sysret_ss_attrs: bool = false,
    null_seg: bool = false,
    div0: bool = false,
    amd_inception: bool = false,
    amd_srso: bool = false,
    spectre_v2_user: bool = false,
    mds_clear_idle: bool = false,
    zenbleed: bool = false,
    cpu_meltdown: bool = false,
    cpu_insecure: bool = false,
    _pad: u6 = 0,
};

pub const MitigationType = enum(u8) {
    none = 0,
    microcode = 1,
    software = 2,
    firmware = 3,
    hardware = 4,
};

pub const CpuMitigation = struct {
    bug: CpuBug,
    mitigation_type: MitigationType,
    name: [64]u8,
    enabled: bool,
};

// ============================================================================
// Alternative Instructions
// ============================================================================

pub const AltInstr = extern struct {
    instr_offset: i32,    // relative offset to instruction
    repl_offset: i32,     // relative offset to replacement
    cpuid_feature: u16,   // CPUID feature bit
    instrlen: u8,         // length of original instruction
    replacementlen: u8,   // length of replacement
    padlen: u8,           // NOP padding needed
};

pub const AltFeature = enum(u16) {
    // x86 features for alternatives
    cmov = 0,
    fxsave_fxrstor = 1,
    mmx = 2,
    sse = 3,
    sse2 = 4,
    sse3 = 5,
    ssse3 = 6,
    sse4_1 = 7,
    sse4_2 = 8,
    aes = 9,
    avx = 10,
    avx2 = 11,
    avx512f = 12,
    bmi1 = 13,
    bmi2 = 14,
    erms = 15,       // Enhanced REP MOVSB/STOSB
    fsrm = 16,       // Fast Short REP MOVSB
    rdrand = 17,
    rdseed = 18,
    clfsh = 19,
    clflushopt = 20,
    clwb = 21,
    xsave = 22,
    xsaveopt = 23,
    xsavec = 24,
    xsaves = 25,
    invpcid = 26,
    pcid = 27,
    ibrs = 28,
    stibp = 29,
    ibpb = 30,
    ssbd = 31,
    // extended
    retpoline = 32,
    rdtsc = 33,
    mfence = 34,
    lfence = 35,
    fred = 36,
    nop = 0xFFFF,
};

// ============================================================================
// Early Command Line Parsing
// ============================================================================

pub const CmdLineParam = struct {
    name: [64]u8,
    name_len: u8,
    value: [128]u8,
    value_len: u32,
    is_bool: bool,
    bool_val: bool,
};

pub const BootCmdLine = struct {
    raw: [4096]u8,
    raw_len: u32,
    params: [128]CmdLineParam,
    param_count: u32,

    pub fn init() BootCmdLine {
        return BootCmdLine{
            .raw = [_]u8{0} ** 4096,
            .raw_len = 0,
            .params = undefined,
            .param_count = 0,
        };
    }
};

// Known boot parameters
pub const KnownParams = struct {
    pub const root: []const u8 = "root";
    pub const init: []const u8 = "init";
    pub const console: []const u8 = "console";
    pub const earlycon: []const u8 = "earlycon";
    pub const earlyprintk: []const u8 = "earlyprintk";
    pub const loglevel: []const u8 = "loglevel";
    pub const quiet: []const u8 = "quiet";
    pub const debug: []const u8 = "debug";
    pub const nosmp: []const u8 = "nosmp";
    pub const noapic: []const u8 = "noapic";
    pub const nolapic: []const u8 = "nolapic";
    pub const nox2apic: []const u8 = "nox2apic";
    pub const nokaslr: []const u8 = "nokaslr";
    pub const kaslr: []const u8 = "kaslr";
    pub const nopti: []const u8 = "nopti";
    pub const pti: []const u8 = "pti";
    pub const nospectre_v1: []const u8 = "nospectre_v1";
    pub const nospectre_v2: []const u8 = "nospectre_v2";
    pub const spec_store_bypass_disable: []const u8 = "spec_store_bypass_disable";
    pub const mitigations: []const u8 = "mitigations";
    pub const acpi: []const u8 = "acpi";
    pub const noacpi: []const u8 = "noacpi";
    pub const mem: []const u8 = "mem";
    pub const memmap: []const u8 = "memmap";
    pub const hugepages: []const u8 = "hugepages";
    pub const transparent_hugepage: []const u8 = "transparent_hugepage";
    pub const isolcpus: []const u8 = "isolcpus";
    pub const nohz: []const u8 = "nohz";
    pub const nohz_full: []const u8 = "nohz_full";
    pub const rcu_nocbs: []const u8 = "rcu_nocbs";
    pub const iommu: []const u8 = "iommu";
    pub const intel_iommu: []const u8 = "intel_iommu";
    pub const amd_iommu: []const u8 = "amd_iommu";
    pub const nmi_watchdog: []const u8 = "nmi_watchdog";
    pub const panic: []const u8 = "panic";
    pub const maxcpus: []const u8 = "maxcpus";
    pub const nr_cpus: []const u8 = "nr_cpus";
    pub const possible_cpus: []const u8 = "possible_cpus";
    pub const clocksource: []const u8 = "clocksource";
    pub const tsc: []const u8 = "tsc";
    pub const notsc: []const u8 = "notsc";
    pub const lapic_timer_c2_ok: []const u8 = "lapic_timer_c2_ok";
};

// ============================================================================
// IOAPIC Discovery
// ============================================================================

pub const IoApicInfo = struct {
    id: u8,
    version: u8,
    address: u64,
    gsi_base: u32,
    gsi_end: u32,
    entries: u8,
};

pub const IoApicTable = struct {
    ioapics: [8]IoApicInfo,
    count: u8,
};

// ============================================================================
// ACPI Table Discovery
// ============================================================================

pub const AcpiTableRef = struct {
    signature: [4]u8,
    address: u64,
    length: u32,
    revision: u8,
};

pub const AcpiDiscovery = struct {
    rsdp_addr: u64,
    rsdt_addr: u64,
    xsdt_addr: u64,
    tables: [64]AcpiTableRef,
    table_count: u32,
    acpi_version: u8,
};

// ============================================================================
// Platform Setup Manager
// ============================================================================

pub const PlatformSetupManager = struct {
    // E820
    e820: E820Table,
    total_ram_bytes: u64,
    // Boot
    boot_params_addr: u64,
    cmdline: BootCmdLine,
    // ACPI
    acpi: AcpiDiscovery,
    // IOAPIC
    ioapics: IoApicTable,
    // Microcode
    microcode_vendor: MicrocodeVendor,
    microcode_revision: u32,
    microcode_date: u32,
    microcode_loaded: bool,
    microcode_result: MicrocodeLoadResult,
    // CPU bugs
    cpu_bugs: CpuBugMask,
    mitigations_count: u32,
    // Alternatives
    alternative_count: u32,
    alternative_applied: u32,
    // State
    initialized: bool,

    pub fn init() PlatformSetupManager {
        return PlatformSetupManager{
            .e820 = E820Table.init(),
            .total_ram_bytes = 0,
            .boot_params_addr = 0,
            .cmdline = BootCmdLine.init(),
            .acpi = AcpiDiscovery{
                .rsdp_addr = 0,
                .rsdt_addr = 0,
                .xsdt_addr = 0,
                .tables = undefined,
                .table_count = 0,
                .acpi_version = 0,
            },
            .ioapics = IoApicTable{
                .ioapics = undefined,
                .count = 0,
            },
            .microcode_vendor = .unknown,
            .microcode_revision = 0,
            .microcode_date = 0,
            .microcode_loaded = false,
            .microcode_result = .not_found,
            .cpu_bugs = .{},
            .mitigations_count = 0,
            .alternative_count = 0,
            .alternative_applied = 0,
            .initialized = true,
        };
    }
};
