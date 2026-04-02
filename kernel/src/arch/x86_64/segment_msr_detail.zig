// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Segment Descriptors, TSS & MSR Detail
// Complete GDT/LDT entry formats, TSS64 structure, all MSR definitions,
// Model-specific register access, WRMSR/RDMSR, STAR/LSTAR/CSTAR/SFMASK

const std = @import("std");

// ============================================================================
// Segment Descriptor Format (64-bit)
// ============================================================================

pub const SegmentAccess = packed struct(u8) {
    accessed: bool,
    read_write: bool,       // Readable (code) / Writable (data)
    direction_conforming: bool,
    executable: bool,
    descriptor_type: bool,  // 0=system, 1=code/data
    dpl: u2,                // Descriptor Privilege Level
    present: bool,
};

pub const SegmentDescriptor = packed struct(u64) {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: SegmentAccess,
    limit_high: u4,
    flags: SegmentFlags,
    base_high: u8,
};

pub const SegmentFlags = packed struct(u4) {
    _reserved: u1,
    long_mode: bool,        // L bit - 64-bit code segment
    size: bool,             // D/B bit
    granularity: bool,      // G bit
};

pub const SystemSegmentDescriptor64 = packed struct(u128) {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    seg_type: u4,
    zero1: u1,
    dpl: u2,
    present: bool,
    limit_high: u4,
    avl: bool,
    _reserved1: u2,
    granularity: bool,
    base_high: u8,
    base_upper: u32,
    _reserved2: u8,
    zero2: u5,
    _reserved3: u19,
};

pub const SegmentType = enum(u4) {
    // System segment types (64-bit mode)
    Ldt = 0x2,
    TssAvailable = 0x9,
    TssBusy = 0xB,
    CallGate = 0xC,
    InterruptGate = 0xE,
    TrapGate = 0xF,
};

// ============================================================================
// GDT Layout
// ============================================================================

pub const GDT_NULL = 0;
pub const GDT_KERNEL_CODE = 1;
pub const GDT_KERNEL_DATA = 2;
pub const GDT_USER_DATA = 3;
pub const GDT_USER_CODE = 4;
pub const GDT_TSS = 5;
pub const GDT_TSS_HIGH = 6; // TSS is 16 bytes in 64-bit mode
pub const GDT_ENTRIES = 7;

pub const KERNEL_CS = GDT_KERNEL_CODE * 8;
pub const KERNEL_DS = GDT_KERNEL_DATA * 8;
pub const USER_CS = (GDT_USER_CODE * 8) | 3;
pub const USER_DS = (GDT_USER_DATA * 8) | 3;
pub const TSS_SELECTOR = GDT_TSS * 8;

pub const GdtRegister = packed struct {
    limit: u16,
    base: u64,
};

// ============================================================================
// TSS (Task State Segment) - 64-bit
// ============================================================================

pub const Tss64 = packed struct {
    _reserved0: u32,
    rsp0: u64,              // Ring 0 stack pointer
    rsp1: u64,              // Ring 1 stack pointer
    rsp2: u64,              // Ring 2 stack pointer
    _reserved1: u64,
    ist1: u64,              // Interrupt Stack Table 1
    ist2: u64,              // IST 2
    ist3: u64,              // IST 3
    ist4: u64,              // IST 4
    ist5: u64,              // IST 5
    ist6: u64,              // IST 6
    ist7: u64,              // IST 7
    _reserved2: u64,
    _reserved3: u16,
    io_map_base: u16,       // I/O Map Base Address
};

pub const IstUsage = enum(u3) {
    DoubleFault = 1,
    Nmi = 2,
    Debug = 3,
    Mce = 4,
};

pub const TSS_SIZE = @sizeOf(Tss64);

// ============================================================================
// IDT Gate Descriptor (64-bit)
// ============================================================================

pub const IdtGate64 = packed struct(u128) {
    offset_low: u16,
    segment: u16,
    ist: u3,
    _reserved1: u5,
    gate_type: u4,
    zero: u1,
    dpl: u2,
    present: bool,
    offset_mid: u16,
    offset_high: u32,
    _reserved2: u32,
};

// ============================================================================
// MSR (Model-Specific Registers)
// ============================================================================

pub const Msr = enum(u32) {
    // Architecture MSRs
    IA32_P5_MC_ADDR = 0x00000000,
    IA32_P5_MC_TYPE = 0x00000001,
    IA32_MONITOR_FILTER_SIZE = 0x00000006,
    IA32_TIME_STAMP_COUNTER = 0x00000010,
    IA32_PLATFORM_ID = 0x00000017,
    IA32_APIC_BASE = 0x0000001B,
    IA32_FEATURE_CONTROL = 0x0000003A,
    IA32_TSC_ADJUST = 0x0000003B,
    IA32_SPEC_CTRL = 0x00000048,
    IA32_PRED_CMD = 0x00000049,
    IA32_BIOS_UPDT_TRIG = 0x00000079,
    IA32_BIOS_SIGN_ID = 0x0000008B,
    IA32_SGXLEPUBKEYHASH0 = 0x0000008C,
    IA32_SGXLEPUBKEYHASH1 = 0x0000008D,
    IA32_SGXLEPUBKEYHASH2 = 0x0000008E,
    IA32_SGXLEPUBKEYHASH3 = 0x0000008F,
    IA32_SMM_MONITOR_CTL = 0x0000009B,
    IA32_SMBASE = 0x0000009E,
    IA32_PMC0 = 0x000000C1,
    IA32_PMC1 = 0x000000C2,
    IA32_PMC2 = 0x000000C3,
    IA32_PMC3 = 0x000000C4,
    IA32_PMC4 = 0x000000C5,
    IA32_PMC5 = 0x000000C6,
    IA32_PMC6 = 0x000000C7,
    IA32_PMC7 = 0x000000C8,
    IA32_UMWAIT_CONTROL = 0x000000E1,
    IA32_MPERF = 0x000000E7,
    IA32_APERF = 0x000000E8,
    IA32_MTRRCAP = 0x000000FE,
    IA32_ARCH_CAPABILITIES = 0x0000010A,
    IA32_FLUSH_CMD = 0x0000010B,
    IA32_TSX_CTRL = 0x00000122,
    // Syscall MSRs
    IA32_SYSENTER_CS = 0x00000174,
    IA32_SYSENTER_ESP = 0x00000175,
    IA32_SYSENTER_EIP = 0x00000176,
    IA32_MCG_CAP = 0x00000179,
    IA32_MCG_STATUS = 0x0000017A,
    IA32_MCG_CTL = 0x0000017B,
    // Perf MSRs
    IA32_PERFEVTSEL0 = 0x00000186,
    IA32_PERFEVTSEL1 = 0x00000187,
    IA32_PERFEVTSEL2 = 0x00000188,
    IA32_PERFEVTSEL3 = 0x00000189,
    IA32_PERF_STATUS = 0x00000198,
    IA32_PERF_CTL = 0x00000199,
    IA32_CLOCK_MODULATION = 0x0000019A,
    IA32_THERM_INTERRUPT = 0x0000019B,
    IA32_THERM_STATUS = 0x0000019C,
    IA32_MISC_ENABLE = 0x000001A0,
    IA32_ENERGY_PERF_BIAS = 0x000001B0,
    IA32_PACKAGE_THERM_STATUS = 0x000001B1,
    IA32_PACKAGE_THERM_INTERRUPT = 0x000001B2,
    // Debug MSRs
    IA32_DEBUGCTL = 0x000001D9,
    IA32_LER_FROM_LIP = 0x000001DD,
    IA32_LER_TO_LIP = 0x000001DE,
    // MTRR MSRs
    IA32_MTRR_PHYSBASE0 = 0x00000200,
    IA32_MTRR_PHYSMASK0 = 0x00000201,
    IA32_MTRR_PHYSBASE1 = 0x00000202,
    IA32_MTRR_PHYSMASK1 = 0x00000203,
    IA32_MTRR_FIX64K_00000 = 0x00000250,
    IA32_MTRR_FIX16K_80000 = 0x00000258,
    IA32_MTRR_FIX16K_A0000 = 0x00000259,
    IA32_MTRR_FIX4K_C0000 = 0x00000268,
    IA32_MTRR_FIX4K_C8000 = 0x00000269,
    IA32_CR_PAT = 0x00000277,
    IA32_MC0_CTL2 = 0x00000280,
    IA32_MTRR_DEF_TYPE = 0x000002FF,
    // Fixed counters
    IA32_FIXED_CTR0 = 0x00000309,
    IA32_FIXED_CTR1 = 0x0000030A,
    IA32_FIXED_CTR2 = 0x0000030B,
    IA32_PERF_CAPABILITIES = 0x00000345,
    IA32_FIXED_CTR_CTRL = 0x0000038D,
    IA32_PERF_GLOBAL_STATUS = 0x0000038E,
    IA32_PERF_GLOBAL_CTRL = 0x0000038F,
    IA32_PERF_GLOBAL_STATUS_RESET = 0x00000390,
    IA32_PERF_GLOBAL_STATUS_SET = 0x00000391,
    IA32_PERF_GLOBAL_INUSE = 0x00000392,
    // PEBS/LBR
    IA32_PEBS_ENABLE = 0x000003F1,
    // MC MSRs
    IA32_MC0_CTL = 0x00000400,
    IA32_MC0_STATUS = 0x00000401,
    IA32_MC0_ADDR = 0x00000402,
    IA32_MC0_MISC = 0x00000403,
    // VMX MSRs
    IA32_VMX_BASIC = 0x00000480,
    IA32_VMX_PINBASED_CTLS = 0x00000481,
    IA32_VMX_PROCBASED_CTLS = 0x00000482,
    IA32_VMX_EXIT_CTLS = 0x00000483,
    IA32_VMX_ENTRY_CTLS = 0x00000484,
    IA32_VMX_MISC = 0x00000485,
    IA32_VMX_CR0_FIXED0 = 0x00000486,
    IA32_VMX_CR0_FIXED1 = 0x00000487,
    IA32_VMX_CR4_FIXED0 = 0x00000488,
    IA32_VMX_CR4_FIXED1 = 0x00000489,
    IA32_VMX_VMCS_ENUM = 0x0000048A,
    IA32_VMX_PROCBASED_CTLS2 = 0x0000048B,
    IA32_VMX_EPT_VPID_CAP = 0x0000048C,
    IA32_VMX_TRUE_PINBASED_CTLS = 0x0000048D,
    IA32_VMX_TRUE_PROCBASED_CTLS = 0x0000048E,
    IA32_VMX_TRUE_EXIT_CTLS = 0x0000048F,
    IA32_VMX_TRUE_ENTRY_CTLS = 0x00000490,
    IA32_VMX_VMFUNC = 0x00000491,
    IA32_VMX_PROCBASED_CTLS3 = 0x00000492,
    // A-PKRS
    IA32_A_PMC0 = 0x000004C1,
    // DS area
    IA32_DS_AREA = 0x00000600,
    // TSC deadline
    IA32_TSC_DEADLINE = 0x000006E0,
    // PM
    IA32_PM_ENABLE = 0x00000770,
    IA32_HWP_CAPABILITIES = 0x00000771,
    IA32_HWP_REQUEST_PKG = 0x00000772,
    IA32_HWP_INTERRUPT = 0x00000773,
    IA32_HWP_REQUEST = 0x00000774,
    IA32_HWP_STATUS = 0x00000777,
    // AMD specific
    MSR_STAR = 0xC0000081,
    MSR_LSTAR = 0xC0000082,
    MSR_CSTAR = 0xC0000083,
    MSR_SFMASK = 0xC0000084,
    MSR_FS_BASE = 0xC0000100,
    MSR_GS_BASE = 0xC0000101,
    MSR_KERNEL_GS_BASE = 0xC0000102,
    MSR_TSC_AUX = 0xC0000103,
    // AMD SYSCFG
    MSR_SYSCFG = 0xC0010010,
    MSR_IORR_BASE0 = 0xC0010016,
    MSR_IORR_MASK0 = 0xC0010017,
    MSR_TOP_MEM = 0xC001001A,
    MSR_TOP_MEM2 = 0xC001001D,
    MSR_NB_CFG = 0xC001001F,
    // AMD SVM
    MSR_VM_CR = 0xC0010114,
    MSR_VM_HSAVE_PA = 0xC0010117,
    // AMD SEV
    MSR_SEV_STATUS = 0xC0010131,
    MSR_SEV_ES_GHCB = 0xC0010130,
    // RAPL
    MSR_RAPL_POWER_UNIT = 0x00000606,
    MSR_PKG_POWER_LIMIT = 0x00000610,
    MSR_PKG_ENERGY_STATUS = 0x00000611,
    MSR_PKG_PERF_STATUS = 0x00000613,
    MSR_PKG_POWER_INFO = 0x00000614,
    MSR_DRAM_POWER_LIMIT = 0x00000618,
    MSR_DRAM_ENERGY_STATUS = 0x00000619,
    MSR_PP0_POWER_LIMIT = 0x00000638,
    MSR_PP0_ENERGY_STATUS = 0x00000639,
    MSR_PP1_POWER_LIMIT = 0x00000640,
    MSR_PP1_ENERGY_STATUS = 0x00000641,
    MSR_PLATFORM_ENERGY_STATUS = 0x0000064D,
    MSR_PLATFORM_POWER_LIMIT = 0x0000065C,
    // XSS
    IA32_XSS = 0x00000DA0,
    // PKRS
    IA32_PKRS = 0x000006E1,
    // UINTR
    IA32_UINTR_RR = 0x00000985,
    IA32_UINTR_HANDLER = 0x00000986,
    IA32_UINTR_STACKADJUST = 0x00000987,
    IA32_UINTR_MISC = 0x00000988,
    IA32_UINTR_PD = 0x00000989,
    IA32_UINTR_TT = 0x0000098A,
};

// ============================================================================
// MSR Value Interpretation
// ============================================================================

pub const MiscEnable = packed struct(u64) {
    fast_string: bool,
    _r1: u2,
    auto_thermal_control: bool,
    _r2: u3,
    perf_monitoring: bool,
    _r3: u3,
    bts_unavailable: bool,
    pebs_unavailable: bool,
    _r4: u3,
    enhanced_speedstep: bool,
    _r5: u1,
    enable_monitor_fsm: bool,
    _r6: u3,
    limit_cpuid_maxval: bool,
    _r7: u1,
    xtpr_disable: bool,
    _r8: u10,
    xd_disable: bool,
    _r9: u28,
};

pub const ArchCapabilities = packed struct(u64) {
    rdcl_no: bool,             // Not affected by Meltdown
    ibrs_all: bool,            // IBRS full
    rsba: bool,                // RSB Alternate
    skip_l1dfl_vmentry: bool,
    ssb_no: bool,              // Not affected by Spectre v4
    mds_no: bool,              // Not affected by MDS
    if_pschange_mc_no: bool,
    tsx_ctrl: bool,
    taa_no: bool,
    mcu_control: bool,
    misc_package_ctls: bool,
    energy_filtering_ctl: bool,
    doitm: bool,
    sbdr_ssdp_no: bool,
    fbsdp_no: bool,
    psdp_no: bool,
    fb_clear: bool,
    fb_clear_ctrl: bool,
    rrsba: bool,
    bhi_no: bool,
    xapic_disable_status: bool,
    _reserved: u43,
};

pub const SpecCtrl = packed struct(u64) {
    ibrs: bool,
    stibp: bool,
    ssbd: bool,
    ipred_dis_u: bool,
    ipred_dis_s: bool,
    rrsba_dis_u: bool,
    rrsba_dis_s: bool,
    psfd: bool,
    ddpd_u: bool,
    _r1: u1,
    bhi_dis_s: bool,
    _reserved: u53,
};

// ============================================================================
// CR (Control Registers)
// ============================================================================

pub const Cr0 = packed struct(u64) {
    pe: bool,       // Protection Enable
    mp: bool,       // Monitor Coprocessor
    em: bool,       // Emulation
    ts: bool,       // Task Switched
    et: bool,       // Extension Type
    ne: bool,       // Numeric Error
    _r1: u10,
    wp: bool,       // Write Protect
    _r2: u1,
    am: bool,       // Alignment Mask
    _r3: u10,
    nw: bool,       // Not Write-through
    cd: bool,       // Cache Disable
    pg: bool,       // Paging
    _r4: u32,
};

pub const Cr4 = packed struct(u64) {
    vme: bool,       // Virtual-8086 Mode
    pvi: bool,       // Protected-mode Virtual Interrupts
    tsd: bool,       // Time Stamp Disable
    de: bool,        // Debugging Extensions
    pse: bool,       // Page Size Extensions
    pae: bool,       // Physical Address Extension
    mce: bool,       // Machine-Check Enable
    pge: bool,       // Page Global Enable
    pce: bool,       // Performance Counter Enable
    osfxsr: bool,    // FXSAVE/FXRSTOR
    osxmmexcpt: bool, // Unmasked SIMD FP Exceptions
    umip: bool,      // User-Mode Instruction Prevention
    la57: bool,      // 5-Level Paging
    vmxe: bool,      // VMX Enable
    smxe: bool,      // SMX Enable
    _r1: u1,
    fsgsbase: bool,  // FSGSBASE
    pcide: bool,     // PCID Enable
    osxsave: bool,   // XSAVE Enable
    _r2: u1,
    smep: bool,      // Supervisor Mode Exec Prevention
    smap: bool,      // Supervisor Mode Access Prevention
    pke: bool,       // Protection Keys Enable
    cet: bool,       // Control-flow Enforcement
    pks: bool,       // Protection Keys for Supervisor
    uintr: bool,     // User Interrupts Enable
    _reserved: u38,
};

pub const Cr3 = packed struct(u64) {
    _r1: u3,
    pwt: bool,       // Page-level Write-Through
    pcd: bool,       // Page-level Cache Disable
    _r2: u7,
    pml4_base: u40,  // Physical address of PML4 (page-aligned)
    _r3: u12,
};

pub const Efer = packed struct(u64) {
    sce: bool,        // SYSCALL Enable
    _r1: u7,
    lme: bool,        // Long Mode Enable
    _r2: u1,
    lma: bool,        // Long Mode Active
    nxe: bool,        // No-Execute Enable
    svme: bool,       // Secure Virtual Machine Enable
    lmsle: bool,      // Long Mode Segment Limit Enable
    ffxsr: bool,      // Fast FXSAVE/FXRSTOR
    tce: bool,        // Translation Cache Extension
    _reserved: u48,
};

// ============================================================================
// LDT (Local Descriptor Table)
// ============================================================================

pub const MAX_LDT_ENTRIES = 8192;
pub const LDT_ENTRY_SIZE = 8;

pub const UserDesc = struct {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    seg_32bit: bool,
    contents: u2,       // 0=data, 1=stack, 2=code, 3=code conforming
    read_exec_only: bool,
    limit_in_pages: bool,
    seg_not_present: bool,
    useable: bool,
    lm: bool,           // 64-bit code segment
};

// ============================================================================
// Manager
// ============================================================================

pub const SegmentMsrManager = struct {
    gdt_base: u64,
    idt_base: u64,
    tss_base: u64,
    tr_selector: u16,
    ldtr: u16,
    total_msr_reads: u64,
    total_msr_writes: u64,
    star_value: u64,
    lstar_value: u64,
    cstar_value: u64,
    sfmask_value: u64,
    fs_base: u64,
    gs_base: u64,
    kernel_gs_base: u64,
    efer_value: u64,
    cr0_value: u64,
    cr3_value: u64,
    cr4_value: u64,
    initialized: bool,

    pub fn init() SegmentMsrManager {
        return .{
            .gdt_base = 0,
            .idt_base = 0,
            .tss_base = 0,
            .tr_selector = TSS_SELECTOR,
            .ldtr = 0,
            .total_msr_reads = 0,
            .total_msr_writes = 0,
            .star_value = 0,
            .lstar_value = 0,
            .cstar_value = 0,
            .sfmask_value = 0,
            .fs_base = 0,
            .gs_base = 0,
            .kernel_gs_base = 0,
            .efer_value = 0,
            .cr0_value = 0,
            .cr3_value = 0,
            .cr4_value = 0,
            .initialized = true,
        };
    }
};
