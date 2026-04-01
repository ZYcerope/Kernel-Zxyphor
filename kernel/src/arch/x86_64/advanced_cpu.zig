// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Advanced CPU Architecture Support
// x86_64 CPU Features, MSRs, CPUID, FPU/SSE/AVX, Performance Counters

const std = @import("std");

// ============================================================================
// CPUID Feature Flags
// ============================================================================

// CPUID Leaf 1 ECX
pub const CPUID_1_ECX = packed struct(u32) {
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
    cx16: bool = false,
    xtpr: bool = false,
    pdcm: bool = false,
    _reserved16: bool = false,
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

// CPUID Leaf 1 EDX
pub const CPUID_1_EDX = packed struct(u32) {
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
    _reserved10: bool = false,
    sep: bool = false,
    mtrr: bool = false,
    pge: bool = false,
    mca: bool = false,
    cmov: bool = false,
    pat: bool = false,
    pse36: bool = false,
    psn: bool = false,
    clfsh: bool = false,
    _reserved20: bool = false,
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

// CPUID Leaf 7 Sub-leaf 0 EBX
pub const CPUID_7_0_EBX = packed struct(u32) {
    fsgsbase: bool = false,
    tsc_adjust: bool = false,
    sgx: bool = false,
    bmi1: bool = false,
    hle: bool = false,
    avx2: bool = false,
    fdp_excptn_only: bool = false,
    smep: bool = false,
    bmi2: bool = false,
    erms: bool = false,
    invpcid: bool = false,
    rtm: bool = false,
    pqm: bool = false,
    fpu_cs_ds_deprecated: bool = false,
    mpx: bool = false,
    pqe: bool = false,
    avx512f: bool = false,
    avx512dq: bool = false,
    rdseed: bool = false,
    adx: bool = false,
    smap: bool = false,
    avx512_ifma: bool = false,
    _reserved22: bool = false,
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

// CPUID Leaf 7 Sub-leaf 0 ECX
pub const CPUID_7_0_ECX = packed struct(u32) {
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
    _reserved15: bool = false,
    la57: bool = false,
    mawau: u5 = 0,
    rdpid: bool = false,
    kl: bool = false,
    bus_lock_detect: bool = false,
    cldemote: bool = false,
    _reserved26: bool = false,
    movdiri: bool = false,
    movdir64b: bool = false,
    enqcmd: bool = false,
    sgx_lc: bool = false,
    pks: bool = false,
};

// CPUID Leaf 7 Sub-leaf 0 EDX
pub const CPUID_7_0_EDX = packed struct(u32) {
    _reserved0: u2 = 0,
    avx512_4vnniw: bool = false,
    avx512_4fmaps: bool = false,
    fast_short_rep_mov: bool = false,
    uintr: bool = false,
    _reserved6: u2 = 0,
    avx512_vp2intersect: bool = false,
    srbds_ctrl: bool = false,
    md_clear: bool = false,
    rtm_always_abort: bool = false,
    _reserved12: bool = false,
    tsx_force_abort: bool = false,
    serialize: bool = false,
    hybrid: bool = false,
    tsxldtrk: bool = false,
    _reserved17: bool = false,
    pconfig: bool = false,
    lbr: bool = false,
    cet_ibt: bool = false,
    _reserved21: bool = false,
    amx_bf16: bool = false,
    avx512_fp16: bool = false,
    amx_tile: bool = false,
    amx_int8: bool = false,
    ibrs_ibpb: bool = false,
    stibp: bool = false,
    l1d_flush: bool = false,
    ia32_arch_capabilities: bool = false,
    ia32_core_capabilities: bool = false,
    ssbd: bool = false,
};

// Extended CPUID Leaf 0x80000001 ECX (AMD)
pub const CPUID_EXT_1_ECX = packed struct(u32) {
    lahf_sahf: bool = false,
    cmp_legacy: bool = false,
    svm: bool = false,
    extapic: bool = false,
    cr8_legacy: bool = false,
    abm: bool = false,
    sse4a: bool = false,
    misalign_sse: bool = false,
    prefetch_3dnow: bool = false,
    osvw: bool = false,
    ibs: bool = false,
    xop: bool = false,
    skinit: bool = false,
    wdt: bool = false,
    _reserved14: bool = false,
    lwp: bool = false,
    fma4: bool = false,
    tce: bool = false,
    _reserved18: bool = false,
    nodeid_msr: bool = false,
    _reserved20: bool = false,
    tbm: bool = false,
    topoext: bool = false,
    perfctr_core: bool = false,
    perfctr_nb: bool = false,
    _reserved25: bool = false,
    dbx: bool = false,
    perftsc: bool = false,
    pcx_l2i: bool = false,
    monitorx: bool = false,
    addr_mask_ext: bool = false,
    _reserved31: bool = false,
};

// ============================================================================
// Model-Specific Registers (MSRs)
// ============================================================================

pub const MSR = enum(u32) {
    // Basic x86_64 MSRs
    IA32_TSC = 0x10,
    IA32_PLATFORM_ID = 0x17,
    IA32_APIC_BASE = 0x1B,
    IA32_FEATURE_CONTROL = 0x3A,
    IA32_TSC_ADJUST = 0x3B,
    IA32_SPEC_CTRL = 0x48,
    IA32_PRED_CMD = 0x49,
    IA32_BIOS_UPDT_TRIG = 0x79,
    IA32_BIOS_SIGN_ID = 0x8B,
    IA32_SMM_MONITOR_CTL = 0x9B,
    IA32_SMBASE = 0x9E,
    IA32_PMC0 = 0xC1,
    IA32_PMC1 = 0xC2,
    IA32_PMC2 = 0xC3,
    IA32_PMC3 = 0xC4,
    IA32_PMC4 = 0xC5,
    IA32_PMC5 = 0xC6,
    IA32_PMC6 = 0xC7,
    IA32_PMC7 = 0xC8,
    IA32_MPERF = 0xE7,
    IA32_APERF = 0xE8,
    IA32_MTRRCAP = 0xFE,
    IA32_SYSENTER_CS = 0x174,
    IA32_SYSENTER_ESP = 0x175,
    IA32_SYSENTER_EIP = 0x176,
    IA32_MCG_CAP = 0x179,
    IA32_MCG_STATUS = 0x17A,
    IA32_MCG_CTL = 0x17B,
    IA32_PERFEVTSEL0 = 0x186,
    IA32_PERFEVTSEL1 = 0x187,
    IA32_PERFEVTSEL2 = 0x188,
    IA32_PERFEVTSEL3 = 0x189,
    IA32_PERF_STATUS = 0x198,
    IA32_PERF_CTL = 0x199,
    IA32_CLOCK_MODULATION = 0x19A,
    IA32_THERM_INTERRUPT = 0x19B,
    IA32_THERM_STATUS = 0x19C,
    IA32_MISC_ENABLE = 0x1A0,
    IA32_ENERGY_PERF_BIAS = 0x1B0,
    IA32_PACKAGE_THERM_STATUS = 0x1B1,
    IA32_PACKAGE_THERM_INTERRUPT = 0x1B2,
    IA32_DEBUGCTL = 0x1D9,
    IA32_SMRR_PHYSBASE = 0x1F2,
    IA32_SMRR_PHYSMASK = 0x1F3,
    IA32_PLATFORM_DCA_CAP = 0x1F8,
    IA32_CPU_DCA_CAP = 0x1F9,
    IA32_DCA_0_CAP = 0x1FA,
    IA32_MTRR_PHYSBASE0 = 0x200,
    IA32_MTRR_PHYSMASK0 = 0x201,
    IA32_MTRR_FIX64K_00000 = 0x250,
    IA32_MTRR_FIX16K_80000 = 0x258,
    IA32_MTRR_FIX16K_A0000 = 0x259,
    IA32_MTRR_FIX4K_C0000 = 0x268,
    IA32_PAT = 0x277,
    IA32_MC0_CTL2 = 0x280,
    IA32_MTRR_DEF_TYPE = 0x2FF,
    IA32_FIXED_CTR0 = 0x309,
    IA32_FIXED_CTR1 = 0x30A,
    IA32_FIXED_CTR2 = 0x30B,
    IA32_PERF_CAPABILITIES = 0x345,
    IA32_FIXED_CTR_CTRL = 0x38D,
    IA32_PERF_GLOBAL_STATUS = 0x38E,
    IA32_PERF_GLOBAL_CTRL = 0x38F,
    IA32_PERF_GLOBAL_STATUS_RESET = 0x390,
    IA32_PERF_GLOBAL_STATUS_SET = 0x391,
    IA32_PERF_GLOBAL_INUSE = 0x392,
    IA32_PEBS_ENABLE = 0x3F1,
    IA32_MC0_CTL = 0x400,
    IA32_MC0_STATUS = 0x401,
    IA32_MC0_ADDR = 0x402,
    IA32_MC0_MISC = 0x403,
    IA32_VMX_BASIC = 0x480,
    IA32_VMX_PINBASED_CTLS = 0x481,
    IA32_VMX_PROCBASED_CTLS = 0x482,
    IA32_VMX_EXIT_CTLS = 0x483,
    IA32_VMX_ENTRY_CTLS = 0x484,
    IA32_VMX_MISC = 0x485,
    IA32_VMX_CR0_FIXED0 = 0x486,
    IA32_VMX_CR0_FIXED1 = 0x487,
    IA32_VMX_CR4_FIXED0 = 0x488,
    IA32_VMX_CR4_FIXED1 = 0x489,
    IA32_VMX_VMCS_ENUM = 0x48A,
    IA32_VMX_PROCBASED_CTLS2 = 0x48B,
    IA32_VMX_EPT_VPID_CAP = 0x48C,
    IA32_VMX_TRUE_PINBASED_CTLS = 0x48D,
    IA32_VMX_TRUE_PROCBASED_CTLS = 0x48E,
    IA32_VMX_TRUE_EXIT_CTLS = 0x48F,
    IA32_VMX_TRUE_ENTRY_CTLS = 0x490,
    IA32_VMX_VMFUNC = 0x491,
    IA32_VMX_PROCBASED_CTLS3 = 0x492,
    IA32_A_PMC0 = 0x4C1,
    IA32_TSC_DEADLINE = 0x6E0,
    IA32_PM_ENABLE = 0x770,
    IA32_HWP_CAPABILITIES = 0x771,
    IA32_HWP_REQUEST_PKG = 0x772,
    IA32_HWP_INTERRUPT = 0x773,
    IA32_HWP_REQUEST = 0x774,
    IA32_HWP_PECI_REQUEST_INFO = 0x775,
    IA32_HWP_STATUS = 0x777,
    IA32_X2APIC_APICID = 0x802,
    IA32_X2APIC_VERSION = 0x803,
    IA32_X2APIC_TPR = 0x808,
    IA32_X2APIC_PPR = 0x80A,
    IA32_X2APIC_EOI = 0x80B,
    IA32_X2APIC_LDR = 0x80D,
    IA32_X2APIC_SIVR = 0x80F,
    IA32_X2APIC_ISR0 = 0x810,
    IA32_X2APIC_TMR0 = 0x818,
    IA32_X2APIC_IRR0 = 0x820,
    IA32_X2APIC_ESR = 0x828,
    IA32_X2APIC_LVT_CMCI = 0x82F,
    IA32_X2APIC_ICR = 0x830,
    IA32_X2APIC_LVT_TIMER = 0x832,
    IA32_X2APIC_LVT_THERMAL = 0x833,
    IA32_X2APIC_LVT_PMI = 0x834,
    IA32_X2APIC_LVT_LINT0 = 0x835,
    IA32_X2APIC_LVT_LINT1 = 0x836,
    IA32_X2APIC_LVT_ERROR = 0x837,
    IA32_X2APIC_INIT_COUNT = 0x838,
    IA32_X2APIC_CUR_COUNT = 0x839,
    IA32_X2APIC_DIV_CONF = 0x83E,
    IA32_X2APIC_SELF_IPI = 0x83F,
    IA32_XSS = 0xDA0,
    // LSTAR/STAR/SFMASK for SYSCALL
    IA32_STAR = 0xC0000081,
    IA32_LSTAR = 0xC0000082,
    IA32_CSTAR = 0xC0000083,
    IA32_FMASK = 0xC0000084,
    IA32_FS_BASE = 0xC0000100,
    IA32_GS_BASE = 0xC0000101,
    IA32_KERNEL_GS_BASE = 0xC0000102,
    IA32_TSC_AUX = 0xC0000103,
    // AMD specific
    AMD64_PATCH_LEVEL = 0x8B,
    AMD64_SYSCFG = 0xC0010010,
    AMD64_IORR_BASE0 = 0xC0010016,
    AMD64_IORR_MASK0 = 0xC0010017,
    AMD64_TOP_MEM = 0xC001001A,
    AMD64_TOP_MEM2 = 0xC001001D,
    AMD64_NB_CFG = 0xC001001F,
    AMD64_OSVW_ID_LENGTH = 0xC0010140,
    AMD64_OSVW_STATUS = 0xC0010141,
    AMD64_SEV = 0xC0010131,
    AMD64_SEV_ES_GHCB = 0xC0010130,
    AMD64_VM_CR = 0xC0010114,
    AMD64_VM_HSAVE_PA = 0xC0010117,
};

pub fn rdmsr(msr: MSR) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (@intFromEnum(msr)),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

pub fn wrmsr(msr: MSR, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (@intFromEnum(msr)),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}

// ============================================================================
// CPUID
// ============================================================================

pub const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

pub fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
    var result: CpuidResult = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (result.eax),
          [ebx] "={ebx}" (result.ebx),
          [ecx] "={ecx}" (result.ecx),
          [edx] "={edx}" (result.edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return result;
}

pub fn cpuid_max_leaf() u32 {
    return cpuid(0, 0).eax;
}

pub fn cpuid_max_ext_leaf() u32 {
    return cpuid(0x80000000, 0).eax;
}

// CPU Vendor
pub const CpuVendor = enum(u8) {
    intel,
    amd,
    hygon,
    centaur,
    zhaoxin,
    unknown,
};

pub fn get_cpu_vendor() CpuVendor {
    const res = cpuid(0, 0);
    // Check EBX-EDX-ECX for vendor string
    if (res.ebx == 0x756E6547 and res.edx == 0x49656E69 and res.ecx == 0x6C65746E) {
        return .intel; // "GenuineIntel"
    }
    if (res.ebx == 0x68747541 and res.edx == 0x69746E65 and res.ecx == 0x444D4163) {
        return .amd; // "AuthenticAMD"
    }
    if (res.ebx == 0x6F677948 and res.edx == 0x6E65476E and res.ecx == 0x656E6975) {
        return .hygon; // "HygonGenuine"
    }
    return .unknown;
}

// CPU Topology
pub const CpuTopology = struct {
    vendor: CpuVendor,
    family: u32,
    model: u32,
    stepping: u32,
    brand_string: [48]u8,
    max_leaf: u32,
    max_ext_leaf: u32,
    // Feature flags
    features_1_ecx: CPUID_1_ECX,
    features_1_edx: CPUID_1_EDX,
    features_7_0_ebx: CPUID_7_0_EBX,
    features_7_0_ecx: CPUID_7_0_ECX,
    features_7_0_edx: CPUID_7_0_EDX,
    features_ext_1_ecx: CPUID_EXT_1_ECX,
    // Topology
    apic_id: u32,
    logical_processors: u32,
    cores_per_package: u32,
    threads_per_core: u32,
    // Cache info
    l1d_cache_size: u32,
    l1i_cache_size: u32,
    l2_cache_size: u32,
    l3_cache_size: u32,
    cache_line_size: u32,
    // Address sizes
    phys_addr_bits: u8,
    virt_addr_bits: u8,
    // Frequency
    tsc_freq_khz: u64,

    pub fn detect() CpuTopology {
        var topo: CpuTopology = std.mem.zeroes(CpuTopology);

        topo.vendor = get_cpu_vendor();
        topo.max_leaf = cpuid_max_leaf();
        topo.max_ext_leaf = cpuid_max_ext_leaf();

        // Leaf 1: Basic features + version info
        const leaf1 = cpuid(1, 0);
        topo.stepping = leaf1.eax & 0xF;
        topo.model = (leaf1.eax >> 4) & 0xF;
        topo.family = (leaf1.eax >> 8) & 0xF;
        if (topo.family == 0xF) {
            topo.family += (leaf1.eax >> 20) & 0xFF;
        }
        if (topo.family >= 0x6) {
            topo.model += ((leaf1.eax >> 16) & 0xF) << 4;
        }
        topo.features_1_ecx = @bitCast(leaf1.ecx);
        topo.features_1_edx = @bitCast(leaf1.edx);
        topo.logical_processors = (leaf1.ebx >> 16) & 0xFF;
        topo.apic_id = (leaf1.ebx >> 24) & 0xFF;

        // Leaf 7: Extended features
        if (topo.max_leaf >= 7) {
            const leaf7 = cpuid(7, 0);
            topo.features_7_0_ebx = @bitCast(leaf7.ebx);
            topo.features_7_0_ecx = @bitCast(leaf7.ecx);
            topo.features_7_0_edx = @bitCast(leaf7.edx);
        }

        // Extended features
        if (topo.max_ext_leaf >= 0x80000001) {
            const ext1 = cpuid(0x80000001, 0);
            topo.features_ext_1_ecx = @bitCast(ext1.ecx);
        }

        // Brand string (leaves 0x80000002-4)
        if (topo.max_ext_leaf >= 0x80000004) {
            inline for (0..3) |i| {
                const res = cpuid(0x80000002 + @as(u32, @intCast(i)), 0);
                const offset = i * 16;
                std.mem.writeInt(u32, topo.brand_string[offset..][0..4], res.eax, .little);
                std.mem.writeInt(u32, topo.brand_string[offset + 4 ..][0..4], res.ebx, .little);
                std.mem.writeInt(u32, topo.brand_string[offset + 8 ..][0..4], res.ecx, .little);
                std.mem.writeInt(u32, topo.brand_string[offset + 12 ..][0..4], res.edx, .little);
            }
        }

        // Address sizes
        if (topo.max_ext_leaf >= 0x80000008) {
            const ext8 = cpuid(0x80000008, 0);
            topo.phys_addr_bits = @truncate(ext8.eax & 0xFF);
            topo.virt_addr_bits = @truncate((ext8.eax >> 8) & 0xFF);
        }

        // Cache info (Leaf 4 for Intel, Leaf 0x8000001D for AMD)
        detect_cache_info(&topo);

        return topo;
    }

    fn detect_cache_info(topo: *CpuTopology) void {
        if (topo.vendor == .intel and topo.max_leaf >= 4) {
            var subleaf: u32 = 0;
            while (subleaf < 16) : (subleaf += 1) {
                const res = cpuid(4, subleaf);
                const cache_type = res.eax & 0x1F;
                if (cache_type == 0) break; // No more caches

                const ways = ((res.ebx >> 22) & 0x3FF) + 1;
                const partitions = ((res.ebx >> 12) & 0x3FF) + 1;
                const line_size = (res.ebx & 0xFFF) + 1;
                const sets = res.ecx + 1;
                const size = ways * partitions * line_size * sets;

                topo.cache_line_size = line_size;

                const level = (res.eax >> 5) & 0x7;
                switch (level) {
                    1 => {
                        if (cache_type == 1) topo.l1d_cache_size = size;
                        if (cache_type == 2) topo.l1i_cache_size = size;
                    },
                    2 => topo.l2_cache_size = size,
                    3 => topo.l3_cache_size = size,
                    else => {},
                }
            }
        }
    }

    pub fn has_avx2(self: *const CpuTopology) bool {
        return self.features_7_0_ebx.avx2;
    }

    pub fn has_avx512(self: *const CpuTopology) bool {
        return self.features_7_0_ebx.avx512f;
    }

    pub fn has_vmx(self: *const CpuTopology) bool {
        return self.features_1_ecx.vmx;
    }

    pub fn has_svm(self: *const CpuTopology) bool {
        return self.features_ext_1_ecx.svm;
    }

    pub fn has_5level_paging(self: *const CpuTopology) bool {
        return self.features_7_0_ecx.la57;
    }

    pub fn has_sgx(self: *const CpuTopology) bool {
        return self.features_7_0_ebx.sgx;
    }
};

// ============================================================================
// Control Registers
// ============================================================================

pub const CR0 = packed struct(u64) {
    pe: bool = false,      // Protected Mode Enable
    mp: bool = false,      // Monitor Co-Processor
    em: bool = false,      // Emulation
    ts: bool = false,      // Task Switched
    et: bool = true,       // Extension Type
    ne: bool = false,      // Numeric Error
    _reserved6: u10 = 0,
    wp: bool = false,      // Write Protect
    _reserved17: bool = false,
    am: bool = false,      // Alignment Mask
    _reserved19: u10 = 0,
    nw: bool = false,      // Not Write-through
    cd: bool = false,      // Cache Disable
    pg: bool = false,      // Paging
    _reserved32: u32 = 0,
};

pub const CR4 = packed struct(u64) {
    vme: bool = false,
    pvi: bool = false,
    tsd: bool = false,
    de: bool = false,
    pse: bool = false,
    pae: bool = false,
    mce: bool = false,
    pge: bool = false,
    pce: bool = false,
    osfxsr: bool = false,
    osxmmexcpt: bool = false,
    umip: bool = false,
    la57: bool = false,
    vmxe: bool = false,
    smxe: bool = false,
    _reserved15: bool = false,
    fsgsbase: bool = false,
    pcide: bool = false,
    osxsave: bool = false,
    _reserved19: bool = false,
    smep: bool = false,
    smap: bool = false,
    pke: bool = false,
    cet: bool = false,
    pks: bool = false,
    uintr: bool = false,
    _reserved26: u38 = 0,
};

pub fn read_cr0() CR0 {
    return @bitCast(asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> u64),
    ));
}

pub fn write_cr0(val: CR0) void {
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (@as(u64, @bitCast(val))),
    );
}

pub fn read_cr2() u64 {
    return asm volatile ("mov %%cr2, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

pub fn read_cr3() u64 {
    return asm volatile ("mov %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

pub fn write_cr3(val: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (val),
    );
}

pub fn read_cr4() CR4 {
    return @bitCast(asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    ));
}

pub fn write_cr4(val: CR4) void {
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (@as(u64, @bitCast(val))),
    );
}

// ============================================================================
// FPU / SSE / AVX State Management
// ============================================================================

pub const XsaveHeader = extern struct {
    xstate_bv: u64,
    xcomp_bv: u64,
    reserved: [6]u64,
};

pub const XsaveArea = extern struct {
    // Legacy FPU area (512 bytes)
    fpu: FxsaveArea,
    // XSAVE header (64 bytes)
    header: XsaveHeader,
    // Extended state components follow
};

pub const FxsaveArea = extern struct {
    fcw: u16,
    fsw: u16,
    ftw: u8,
    _reserved1: u8,
    fop: u16,
    fip: u64,
    fdp: u64,
    mxcsr: u32,
    mxcsr_mask: u32,
    st: [8][16]u8,   // x87 FP regs
    xmm: [16][16]u8, // SSE regs
    _reserved2: [96]u8,
};

// XCR0 feature mask
pub const XCR0 = packed struct(u64) {
    x87: bool = true,
    sse: bool = false,
    avx: bool = false,
    bndreg: bool = false,     // MPX bound registers
    bndcsr: bool = false,     // MPX CSR
    opmask: bool = false,     // AVX-512 opmask
    zmm_hi256: bool = false,  // AVX-512 upper 256 bits of ZMM0-15
    hi16_zmm: bool = false,   // AVX-512 ZMM16-31
    _reserved8: bool = false,
    pkru: bool = false,
    _reserved10: bool = false,
    cet_u: bool = false,
    cet_s: bool = false,
    _reserved13: u4 = 0,
    tilecfg: bool = false,    // AMX tile config
    tiledata: bool = false,   // AMX tile data
    _reserved19: u45 = 0,
};

pub fn xgetbv(index: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("xgetbv"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [index] "{ecx}" (index),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

pub fn xsetbv(index: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("xsetbv"
        :
        : [index] "{ecx}" (index),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}

// ============================================================================
// Performance Monitoring Counters (PMC)
// ============================================================================

pub const PerfEventType = enum(u32) {
    hardware = 0,
    software = 1,
    tracepoint = 2,
    hw_cache = 3,
    raw = 4,
    breakpoint = 5,
};

pub const HwEventId = enum(u64) {
    cpu_cycles = 0,
    instructions = 1,
    cache_references = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    bus_cycles = 6,
    stalled_cycles_frontend = 7,
    stalled_cycles_backend = 8,
    ref_cpu_cycles = 9,
};

pub const PerfEvtSel = packed struct(u64) {
    event_select: u8 = 0,
    unit_mask: u8 = 0,
    usr: bool = false,
    os: bool = false,
    edge: bool = false,
    pc: bool = false,
    interrupt: bool = false,
    any_thread: bool = false,
    enable: bool = false,
    inv: bool = false,
    cmask: u8 = 0,
    _reserved: u32 = 0,
};

// Intel Architectural Performance Events
pub const ArchPerfEvents = struct {
    pub const UNHALTED_CORE_CYCLES: PerfEvtSel = .{ .event_select = 0x3C, .unit_mask = 0x00, .usr = true, .os = true, .enable = true };
    pub const INSTRUCTION_RETIRED: PerfEvtSel = .{ .event_select = 0xC0, .unit_mask = 0x00, .usr = true, .os = true, .enable = true };
    pub const UNHALTED_REF_CYCLES: PerfEvtSel = .{ .event_select = 0x3C, .unit_mask = 0x01, .usr = true, .os = true, .enable = true };
    pub const LLC_REFERENCES: PerfEvtSel = .{ .event_select = 0x2E, .unit_mask = 0x4F, .usr = true, .os = true, .enable = true };
    pub const LLC_MISSES: PerfEvtSel = .{ .event_select = 0x2E, .unit_mask = 0x41, .usr = true, .os = true, .enable = true };
    pub const BRANCH_RETIRED: PerfEvtSel = .{ .event_select = 0xC4, .unit_mask = 0x00, .usr = true, .os = true, .enable = true };
    pub const BRANCH_MISSES_RETIRED: PerfEvtSel = .{ .event_select = 0xC5, .unit_mask = 0x00, .usr = true, .os = true, .enable = true };
    pub const TOPDOWN_SLOTS: PerfEvtSel = .{ .event_select = 0xA4, .unit_mask = 0x01, .usr = true, .os = true, .enable = true };
};

// ============================================================================
// Machine Check Exception (MCE)
// ============================================================================

pub const McgCap = packed struct(u64) {
    count: u8,
    mcg_ctl_p: bool,
    mcg_ext_p: bool,
    mcg_cmci_p: bool,
    mcg_tes_p: bool,
    _reserved12: u4,
    mcg_ext_cnt: u8,
    mcg_ser_p: bool,
    mcg_elog_p: bool,
    mcg_lmce_p: bool,
    _reserved27: u37,
};

pub const McgStatus = packed struct(u64) {
    ripv: bool,
    eipv: bool,
    mcip: bool,
    lmce_s: bool,
    _reserved: u60,
};

pub const MciStatus = packed struct(u64) {
    mca_error_code: u16,
    model_specific: u16,
    other_info: u6,
    corrected_count: u15,
    _reserved: u4,
    pcc: bool,
    addrv: bool,
    miscv: bool,
    en: bool,
    uc: bool,
    overflow: bool,
    val: bool,
};

// ============================================================================
// Speculative Execution Mitigations
// ============================================================================

pub const SpecCtrl = packed struct(u64) {
    ibrs: bool = false,
    stibp: bool = false,
    ssbd: bool = false,
    ipred_dis_u: bool = false,
    ipred_dis_s: bool = false,
    rrsba_dis_u: bool = false,
    rrsba_dis_s: bool = false,
    psfd: bool = false,
    _reserved: u56 = 0,
};

pub const MitigationStrategy = enum(u8) {
    none = 0,
    ibrs = 1,
    ibrs_enhanced = 2,
    retpoline = 3,
    retpoline_ibrs = 4,
    stibp = 5,
    ssbd = 6,
    mds_idle_clear = 7,
    taa_tsx_disable = 8,
    srbds_microcode = 9,
    l1tf_flush = 10,
};

pub const SpeculationMitigations = struct {
    spectre_v1: MitigationStrategy,
    spectre_v2: MitigationStrategy,
    meltdown: MitigationStrategy,
    mds: MitigationStrategy,
    taa: MitigationStrategy,
    l1tf: MitigationStrategy,
    srbds: MitigationStrategy,
    ssb: MitigationStrategy,
    retbleed: MitigationStrategy,
    gds: MitigationStrategy,
    rfds: MitigationStrategy,

    pub fn default() SpeculationMitigations {
        return .{
            .spectre_v1 = .none,
            .spectre_v2 = .none,
            .meltdown = .none,
            .mds = .none,
            .taa = .none,
            .l1tf = .none,
            .srbds = .none,
            .ssb = .none,
            .retbleed = .none,
            .gds = .none,
            .rfds = .none,
        };
    }

    pub fn apply_recommended(self: *SpeculationMitigations, topo: *const CpuTopology) void {
        if (topo.features_7_0_edx.ibrs_ibpb) {
            self.spectre_v2 = .ibrs_enhanced;
        } else {
            self.spectre_v2 = .retpoline;
        }
        if (topo.features_7_0_edx.ssbd) {
            self.ssb = .ssbd;
        }
        if (topo.features_7_0_edx.md_clear) {
            self.mds = .mds_idle_clear;
        }
        if (topo.features_7_0_edx.l1d_flush) {
            self.l1tf = .l1tf_flush;
        }
        self.meltdown = .ibrs; // KPTI implicit
    }
};

// ============================================================================
// MTRR (Memory Type Range Registers)
// ============================================================================

pub const MtrrType = enum(u8) {
    uncacheable = 0,
    write_combining = 1,
    write_through = 4,
    write_protect = 5,
    write_back = 6,
};

pub const MtrrEntry = struct {
    base: u64,
    mask: u64,
    mem_type: MtrrType,
    valid: bool,
};

pub const MAX_MTRR_RANGES: usize = 8;

pub const MtrrState = struct {
    fixed: [88]u8,
    variable: [MAX_MTRR_RANGES]MtrrEntry,
    num_variable: u32,
    def_type: MtrrType,
    enabled: bool,
    fixed_enabled: bool,

    pub fn init() MtrrState {
        return MtrrState{
            .fixed = [_]u8{0} ** 88,
            .variable = std.mem.zeroes([MAX_MTRR_RANGES]MtrrEntry),
            .num_variable = 0,
            .def_type = .uncacheable,
            .enabled = false,
            .fixed_enabled = false,
        };
    }

    pub fn lookup_type(self: *const MtrrState, addr: u64) MtrrType {
        // Check variable ranges
        var i: u32 = 0;
        while (i < self.num_variable) : (i += 1) {
            const entry = &self.variable[i];
            if (!entry.valid) continue;
            if ((addr & entry.mask) == (entry.base & entry.mask)) {
                return entry.mem_type;
            }
        }
        return self.def_type;
    }
};

// ============================================================================
// Intel TDX / AMD SEV
// ============================================================================

pub const TdxCapabilities = struct {
    supported: bool,
    version: u32,
    max_vcpus: u32,
    attributes: u64,
};

pub const SevCapabilities = struct {
    sev_supported: bool,
    sev_es_supported: bool,
    sev_snp_supported: bool,
    cbitpos: u8,
    nr_asids: u32,
    min_asid: u32,
    api_major: u8,
    api_minor: u8,
    build_id: u8,
    policy: u32,
};

// ============================================================================
// Interrupt Management
// ============================================================================

pub inline fn cli() void {
    asm volatile ("cli");
}

pub inline fn sti() void {
    asm volatile ("sti");
}

pub inline fn hlt() void {
    asm volatile ("hlt");
}

pub inline fn pause() void {
    asm volatile ("pause");
}

pub inline fn invlpg(addr: u64) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (addr),
        : "memory"
    );
}

pub inline fn read_flags() u64 {
    return asm volatile ("pushfq; popq %[ret]"
        : [ret] "=r" (-> u64),
    );
}

pub inline fn write_flags(flags: u64) void {
    asm volatile ("pushq %[flags]; popfq"
        :
        : [flags] "r" (flags),
        : "cc"
    );
}

pub inline fn int3() void {
    asm volatile ("int3");
}

pub inline fn swapgs() void {
    asm volatile ("swapgs");
}

pub inline fn wbinvd() void {
    asm volatile ("wbinvd");
}

pub inline fn clflush(addr: u64) void {
    asm volatile ("clflush (%[addr])"
        :
        : [addr] "r" (addr),
        : "memory"
    );
}

pub inline fn mfence() void {
    asm volatile ("mfence" ::: "memory");
}

pub inline fn lfence() void {
    asm volatile ("lfence" ::: "memory");
}

pub inline fn sfence() void {
    asm volatile ("sfence" ::: "memory");
}

pub inline fn rdtsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

pub inline fn rdtscp() struct { tsc: u64, aux: u32 } {
    var low: u32 = undefined;
    var high: u32 = undefined;
    var aux: u32 = undefined;
    asm volatile ("rdtscp"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
          [aux] "={ecx}" (aux),
    );
    return .{ .tsc = (@as(u64, high) << 32) | @as(u64, low), .aux = aux };
}
