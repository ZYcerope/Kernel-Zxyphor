// Zxyphor Kernel - CPUID Complete Feature Detection,
// MSR Comprehensive List, CR Register Bits,
// Model-Specific Registers for Intel/AMD,
// x86 Feature Flags (complete set),
// CPU Topology Detection,
// CPU Errata & Workarounds Database
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// CPUID Leaf Summary
// ============================================================================

pub const CpuidLeaf = enum(u32) {
    basic_info = 0x00000000,
    version_info = 0x00000001,
    cache_tlb = 0x00000002,
    serial_number = 0x00000003,
    det_cache_params = 0x00000004,
    monitor_mwait = 0x00000005,
    thermal_power = 0x00000006,
    structured_ext = 0x00000007,
    direct_cache = 0x00000009,
    arch_perf_mon = 0x0000000A,
    ext_topology = 0x0000000B,
    proc_ext_state = 0x0000000D,
    intel_rdt_mon = 0x0000000F,
    intel_rdt_alloc = 0x00000010,
    sgx_enum = 0x00000012,
    proc_trace = 0x00000014,
    tsc_info = 0x00000015,
    proc_freq_info = 0x00000016,
    soc_vendor = 0x00000017,
    det_tlb_params = 0x00000018,
    keylocker = 0x00000019,
    native_model_id = 0x0000001A,
    pconfig = 0x0000001B,
    lbr_info = 0x0000001C,
    tile_info = 0x0000001D,
    tmul_info = 0x0000001E,
    v2_ext_topology = 0x0000001F,
    hreset = 0x00000020,
    avx10 = 0x00000024,
    // Extended
    ext_max_func = 0x80000000,
    ext_proc_info = 0x80000001,
    ext_brand_1 = 0x80000002,
    ext_brand_2 = 0x80000003,
    ext_brand_3 = 0x80000004,
    ext_l1_cache = 0x80000005,
    ext_l2_cache = 0x80000006,
    ext_apm = 0x80000007,
    ext_addr_sizes = 0x80000008,
    amd_svm = 0x8000000A,
    amd_tlb_1g = 0x80000019,
    amd_perf_opt = 0x8000001A,
    amd_ibs = 0x8000001B,
    amd_lwp = 0x8000001C,
    amd_cache_topo = 0x8000001D,
    amd_proc_topo = 0x8000001E,
    amd_encrypt_mem = 0x8000001F,
    amd_ext_feat2 = 0x80000021,
    amd_perf_mon_ext = 0x80000022,
    amd_multikey_enc = 0x80000023,
    amd_ext_feat3 = 0x80000024,
};

// ============================================================================
// CPUID Feature Flags (EAX=1, ECX)
// ============================================================================

pub const CpuidFeatureEcx = packed struct(u32) {
    sse3: bool = false,
    pclmulqdq: bool = false,
    dtes64: bool = false,
    monitor: bool = false,
    ds_cpl: bool = false,
    vmx: bool = false,
    smx: bool = false,
    eist: bool = false,
    tm2: bool = false,
    ssse3: bool = false,
    cnxt_id: bool = false,
    sdbg: bool = false,
    fma: bool = false,
    cmpxchg16b: bool = false,
    xtpr: bool = false,
    pdcm: bool = false,
    _reserved1: bool = false,
    pcid: bool = false,
    dca: bool = false,
    sse4_1: bool = false,
    sse4_2: bool = false,
    x2apic: bool = false,
    movbe: bool = false,
    popcnt: bool = false,
    tsc_deadline: bool = false,
    aesni: bool = false,
    xsave: bool = false,
    osxsave: bool = false,
    avx: bool = false,
    f16c: bool = false,
    rdrand: bool = false,
    hypervisor: bool = false,
};

// ============================================================================
// CPUID Feature Flags (EAX=1, EDX)
// ============================================================================

pub const CpuidFeatureEdx = packed struct(u32) {
    fpu: bool = false,
    vme: bool = false,
    de: bool = false,
    pse: bool = false,
    tsc: bool = false,
    msr: bool = false,
    pae: bool = false,
    mce: bool = false,
    cx8: bool = false,
    apic: bool = false,
    _reserved1: bool = false,
    sep: bool = false,
    mtrr: bool = false,
    pge: bool = false,
    mca: bool = false,
    cmov: bool = false,
    pat: bool = false,
    pse36: bool = false,
    psn: bool = false,
    clfsh: bool = false,
    _reserved2: bool = false,
    ds: bool = false,
    acpi_thermal: bool = false,
    mmx: bool = false,
    fxsr: bool = false,
    sse: bool = false,
    sse2: bool = false,
    ss: bool = false,
    htt: bool = false,
    tm: bool = false,
    ia64: bool = false,
    pbe: bool = false,
};

// ============================================================================
// CPUID Structured Extended Features (EAX=7, ECX=0, EBX)
// ============================================================================

pub const CpuidExtFeatureEbx = packed struct(u32) {
    fsgsbase: bool = false,
    tsc_adjust: bool = false,
    sgx: bool = false,
    bmi1: bool = false,
    hle: bool = false,
    avx2: bool = false,
    fdp_excptn: bool = false,
    smep: bool = false,
    bmi2: bool = false,
    erms: bool = false,
    invpcid: bool = false,
    rtm: bool = false,
    pqm: bool = false,
    fpu_cs_ds_depr: bool = false,
    mpx: bool = false,
    pqe: bool = false,
    avx512f: bool = false,
    avx512dq: bool = false,
    rdseed: bool = false,
    adx: bool = false,
    smap: bool = false,
    avx512_ifma: bool = false,
    _reserved1: bool = false,
    clflushopt: bool = false,
    clwb: bool = false,
    intel_pt: bool = false,
    avx512pf: bool = false,
    avx512er: bool = false,
    avx512cd: bool = false,
    sha: bool = false,
    avx512bw: bool = false,
    avx512vl: bool = false,
};

// ============================================================================
// CPUID Structured Extended Features (EAX=7, ECX=0, ECX)
// ============================================================================

pub const CpuidExtFeatureEcx7 = packed struct(u32) {
    prefetchwt1: bool = false,
    avx512_vbmi: bool = false,
    umip: bool = false,
    pku: bool = false,
    ospke: bool = false,
    waitpkg: bool = false,
    avx512_vbmi2: bool = false,
    cet_ss: bool = false,
    gfni: bool = false,
    vaes: bool = false,
    vpclmulqdq: bool = false,
    avx512_vnni: bool = false,
    avx512_bitalg: bool = false,
    tme: bool = false,
    avx512_vpopcntdq: bool = false,
    _reserved1: bool = false,
    la57: bool = false,           // 5-level paging
    mawau: u5 = 0,               // MAWAU for MPX
    rdpid: bool = false,
    kl: bool = false,
    bus_lock_detect: bool = false,
    cldemote: bool = false,
    _reserved2: bool = false,
    movdiri: bool = false,
    movdir64b: bool = false,
    enqcmd: bool = false,
    sgx_lc: bool = false,
    pks: bool = false,
};

// ============================================================================
// CPUID Structured Extended Features (EAX=7, ECX=0, EDX)
// ============================================================================

pub const CpuidExtFeatureEdx7 = packed struct(u32) {
    _reserved1: bool = false,
    sgx_keys: bool = false,
    avx512_4vnniw: bool = false,
    avx512_4fmaps: bool = false,
    fast_short_rep_mov: bool = false,
    uintr: bool = false,
    _reserved2: u2 = 0,
    avx512_vp2intersect: bool = false,
    srpds_ctrl: bool = false,
    md_clear: bool = false,
    rtm_always_abort: bool = false,
    _reserved3: bool = false,
    rtm_force_abort: bool = false,
    serialize: bool = false,
    hybrid: bool = false,
    tsxldtrk: bool = false,
    _reserved4: bool = false,
    pconfig: bool = false,
    lbr: bool = false,
    cet_ibt: bool = false,
    _reserved5: bool = false,
    amx_bf16: bool = false,
    avx512_fp16: bool = false,
    amx_tile: bool = false,
    amx_int8: bool = false,
    spec_ctrl: bool = false,
    stibp: bool = false,
    l1d_flush: bool = false,
    ia32_arch_caps: bool = false,
    ia32_core_caps: bool = false,
    ssbd: bool = false,
};

// ============================================================================
// CR (Control Register) Bits
// ============================================================================

pub const Cr0Bits = packed struct(u64) {
    pe: bool = false,          // Protected Mode Enable
    mp: bool = false,          // Monitor Co-processor
    em: bool = false,          // Emulation
    ts: bool = false,          // Task Switched
    et: bool = true,           // Extension Type
    ne: bool = false,          // Numeric Error
    _reserved1: u10 = 0,
    wp: bool = false,          // Write Protect
    _reserved2: bool = false,
    am: bool = false,          // Alignment Mask
    _reserved3: u10 = 0,
    nw: bool = false,          // Not Write-Through
    cd: bool = false,          // Cache Disable
    pg: bool = false,          // Paging
    _reserved4: u32 = 0,
};

pub const Cr4Bits = packed struct(u64) {
    vme: bool = false,         // Virtual-8086 Mode Extensions
    pvi: bool = false,         // Protected Virtual Interrupts
    tsd: bool = false,         // Time Stamp Disable
    de: bool = false,          // Debugging Extensions
    pse: bool = false,         // Page Size Extension
    pae: bool = true,          // Physical Address Extension
    mce: bool = false,         // Machine Check Enable
    pge: bool = false,         // Page Global Enable
    pce: bool = false,         // Performance Monitoring Counter Enable
    osfxsr: bool = false,      // OS FXSAVE/FXRSTOR Support
    osxmmexcpt: bool = false,  // OS Unmasked SIMD FP Exception
    umip: bool = false,        // User-Mode Instruction Prevention
    la57: bool = false,        // 57-bit Linear Addresses (5-lvl paging)
    vmxe: bool = false,        // VMX Enable
    smxe: bool = false,        // SMX Enable
    _reserved1: bool = false,
    fsgsbase: bool = false,    // FSGSBASE Enable
    pcide: bool = false,       // PCID Enable
    osxsave: bool = false,     // XSAVE Enable
    kl: bool = false,          // Key Locker Enable
    smep: bool = false,        // SMEP Enable
    smap: bool = false,        // SMAP Enable
    pke: bool = false,         // Protection Keys Enable
    cet: bool = false,         // CET Enable
    pks: bool = false,         // PKS Enable
    uintr: bool = false,       // User Interrupts Enable
    _reserved2: u38 = 0,
};

// ============================================================================
// Commonly Used MSRs
// ============================================================================

pub const MSR = struct {
    // Architectural MSRs
    pub const IA32_TSC: u32 = 0x00000010;
    pub const IA32_PLATFORM_ID: u32 = 0x00000017;
    pub const IA32_APIC_BASE: u32 = 0x0000001B;
    pub const IA32_FEATURE_CONTROL: u32 = 0x0000003A;
    pub const IA32_TSC_ADJUST: u32 = 0x0000003B;
    pub const IA32_SPEC_CTRL: u32 = 0x00000048;
    pub const IA32_PRED_CMD: u32 = 0x00000049;
    pub const IA32_BIOS_UPDT_TRIG: u32 = 0x00000079;
    pub const IA32_BIOS_SIGN_ID: u32 = 0x0000008B;
    pub const IA32_SMM_MONITOR_CTL: u32 = 0x0000009B;
    pub const IA32_PMC0: u32 = 0x000000C1;
    pub const IA32_PMC1: u32 = 0x000000C2;
    pub const IA32_MPERF: u32 = 0x000000E7;
    pub const IA32_APERF: u32 = 0x000000E8;
    pub const IA32_MTRRCAP: u32 = 0x000000FE;
    pub const IA32_ARCH_CAPABILITIES: u32 = 0x0000010A;
    pub const IA32_FLUSH_CMD: u32 = 0x0000010B;
    pub const IA32_TSX_CTRL: u32 = 0x00000122;
    pub const IA32_SYSENTER_CS: u32 = 0x00000174;
    pub const IA32_SYSENTER_ESP: u32 = 0x00000175;
    pub const IA32_SYSENTER_EIP: u32 = 0x00000176;
    pub const IA32_MCG_CAP: u32 = 0x00000179;
    pub const IA32_MCG_STATUS: u32 = 0x0000017A;
    pub const IA32_MCG_CTL: u32 = 0x0000017B;
    pub const IA32_PERFEVTSEL0: u32 = 0x00000186;
    pub const IA32_PERFEVTSEL1: u32 = 0x00000187;
    pub const IA32_PERF_STATUS: u32 = 0x00000198;
    pub const IA32_PERF_CTL: u32 = 0x00000199;
    pub const IA32_MISC_ENABLE: u32 = 0x000001A0;
    pub const IA32_ENERGY_PERF_BIAS: u32 = 0x000001B0;
    pub const IA32_PACKAGE_THERM_STATUS: u32 = 0x000001B1;
    pub const IA32_DEBUGCTLMSR: u32 = 0x000001D9;
    pub const IA32_PAT: u32 = 0x00000277;
    pub const IA32_PERF_CAPABILITIES: u32 = 0x00000345;
    pub const IA32_FIXED_CTR0: u32 = 0x00000309;
    pub const IA32_FIXED_CTR_CTRL: u32 = 0x0000038D;
    pub const IA32_PERF_GLOBAL_STATUS: u32 = 0x0000038E;
    pub const IA32_PERF_GLOBAL_CTRL: u32 = 0x0000038F;
    pub const IA32_PERF_GLOBAL_OVF: u32 = 0x00000390;
    pub const IA32_PEBS_ENABLE: u32 = 0x000003F1;
    pub const IA32_MC0_CTL: u32 = 0x00000400;
    pub const IA32_MC0_STATUS: u32 = 0x00000401;
    pub const IA32_MC0_ADDR: u32 = 0x00000402;
    pub const IA32_MC0_MISC: u32 = 0x00000403;
    // x2APIC
    pub const IA32_X2APIC_APICID: u32 = 0x00000802;
    pub const IA32_X2APIC_VERSION: u32 = 0x00000803;
    pub const IA32_X2APIC_TPR: u32 = 0x00000808;
    pub const IA32_X2APIC_PPR: u32 = 0x0000080A;
    pub const IA32_X2APIC_EOI: u32 = 0x0000080B;
    pub const IA32_X2APIC_LDR: u32 = 0x0000080D;
    pub const IA32_X2APIC_SVR: u32 = 0x0000080F;
    pub const IA32_X2APIC_ICR: u32 = 0x00000830;
    pub const IA32_X2APIC_SELF_IPI: u32 = 0x0000083F;
    // AMD
    pub const IA32_EFER: u32 = 0xC0000080;
    pub const IA32_STAR: u32 = 0xC0000081;
    pub const IA32_LSTAR: u32 = 0xC0000082;
    pub const IA32_CSTAR: u32 = 0xC0000083;
    pub const IA32_FMASK: u32 = 0xC0000084;
    pub const IA32_FS_BASE: u32 = 0xC0000100;
    pub const IA32_GS_BASE: u32 = 0xC0000101;
    pub const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
    pub const IA32_TSC_AUX: u32 = 0xC0000103;
    // VMX
    pub const IA32_VMX_BASIC: u32 = 0x00000480;
    pub const IA32_VMX_PINBASED_CTLS: u32 = 0x00000481;
    pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x00000482;
    pub const IA32_VMX_EXIT_CTLS: u32 = 0x00000483;
    pub const IA32_VMX_ENTRY_CTLS: u32 = 0x00000484;
    pub const IA32_VMX_MISC: u32 = 0x00000485;
    pub const IA32_VMX_CR0_FIXED0: u32 = 0x00000486;
    pub const IA32_VMX_CR0_FIXED1: u32 = 0x00000487;
    pub const IA32_VMX_CR4_FIXED0: u32 = 0x00000488;
    pub const IA32_VMX_CR4_FIXED1: u32 = 0x00000489;
    pub const IA32_VMX_VMCS_ENUM: u32 = 0x0000048A;
    pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x0000048B;
    pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x0000048C;
    pub const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x0000048D;
    pub const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x0000048E;
    pub const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x0000048F;
    pub const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x00000490;
    pub const IA32_VMX_VMFUNC: u32 = 0x00000491;
    pub const IA32_VMX_PROCBASED_CTLS3: u32 = 0x00000492;
    pub const IA32_VMX_EXIT_CTLS2: u32 = 0x00000493;
    // MTRR
    pub const IA32_MTRR_DEF_TYPE: u32 = 0x000002FF;
    pub const IA32_MTRR_PHYSBASE0: u32 = 0x00000200;
    pub const IA32_MTRR_PHYSMASK0: u32 = 0x00000201;
    // XSS
    pub const IA32_XSS: u32 = 0x00000DA0;
    // RAPL
    pub const MSR_RAPL_POWER_UNIT: u32 = 0x00000606;
    pub const MSR_PKG_ENERGY_STATUS: u32 = 0x00000611;
    pub const MSR_DRAM_ENERGY_STATUS: u32 = 0x00000619;
    pub const MSR_PP0_ENERGY_STATUS: u32 = 0x00000639;
    pub const MSR_PP1_ENERGY_STATUS: u32 = 0x00000641;
    // HWP
    pub const IA32_PM_ENABLE: u32 = 0x00000770;
    pub const IA32_HWP_CAPABILITIES: u32 = 0x00000771;
    pub const IA32_HWP_REQUEST_PKG: u32 = 0x00000772;
    pub const IA32_HWP_INTERRUPT: u32 = 0x00000773;
    pub const IA32_HWP_REQUEST: u32 = 0x00000774;
    pub const IA32_HWP_STATUS: u32 = 0x00000777;
};

// ============================================================================
// CPU Topology
// ============================================================================

pub const CpuTopologyLevel = enum(u8) {
    invalid = 0,
    smt = 1,
    core = 2,
    module = 3,
    tile = 4,
    die = 5,
};

pub const CpuTopology = struct {
    max_cpus: u32,
    online_cpus: u32,
    sockets: u16,
    dies_per_socket: u8,
    cores_per_die: u16,
    threads_per_core: u8,
    llc_shared_cpus: u16,
    numa_nodes: u16,
    numa_distance: [16][16]u16,    // 16×16 distance matrix
    has_asymmetric_cores: bool,
    big_cores: u16,
    little_cores: u16,
};

// ============================================================================
// CPU Feature Detection Manager (Zxyphor)
// ============================================================================

pub const CpuFeatureManager = struct {
    vendor: CpuVendor,
    family: u8,
    model: u8,
    stepping: u8,
    features_ecx: CpuidFeatureEcx,
    features_edx: CpuidFeatureEdx,
    ext_features_ebx: CpuidExtFeatureEbx,
    ext_features_ecx: CpuidExtFeatureEcx7,
    ext_features_edx: CpuidExtFeatureEdx7,
    topology: CpuTopology,
    phys_addr_bits: u8,
    virt_addr_bits: u8,
    brand_string: [48]u8,
    initialized: bool,

    pub fn init() CpuFeatureManager {
        var mgr = std.mem.zeroes(CpuFeatureManager);
        mgr.initialized = true;
        return mgr;
    }
};

pub const CpuVendor = enum(u8) {
    unknown = 0,
    intel = 1,
    amd = 2,
    hygon = 3,
    centaur = 4,
    zhaoxin = 5,
};
