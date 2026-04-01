// =============================================================================
// Kernel Zxyphor — Advanced CPUID Feature Detection & CPU Topology
// =============================================================================
// Comprehensive CPU feature detection using CPUID instruction.
// Provides detailed information about:
// - Vendor identification
// - Feature flags (SSE, AVX, AES-NI, etc.)
// - Cache topology
// - Power management capabilities
// - CPU topology (cores, threads, packages)
// - Virtualization features
// - Security features (CET, SGX, TME)
// =============================================================================

const std = @import("std");

// =============================================================================
// CPUID Instruction Wrapper
// =============================================================================

pub const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

pub fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
    var result: CpuidResult = undefined;
    asm volatile ("cpuid"
        : "={eax}" (result.eax),
          "={ebx}" (result.ebx),
          "={ecx}" (result.ecx),
          "={edx}" (result.edx),
        : "{eax}" (leaf),
          "{ecx}" (subleaf),
    );
    return result;
}

// =============================================================================
// CPU Vendor Identification
// =============================================================================

pub const CpuVendor = enum {
    intel,
    amd,
    unknown,

    pub fn toString(self: CpuVendor) []const u8 {
        return switch (self) {
            .intel => "GenuineIntel",
            .amd => "AuthenticAMD",
            .unknown => "Unknown",
        };
    }
};

pub fn detectVendor() CpuVendor {
    const result = cpuid(0, 0);
    // Check EBX-EDX-ECX for vendor string
    if (result.ebx == 0x756E6547 and result.edx == 0x49656E69 and result.ecx == 0x6C65746E) {
        return .intel;
    }
    if (result.ebx == 0x68747541 and result.edx == 0x69746E65 and result.ecx == 0x444D4163) {
        return .amd;
    }
    return .unknown;
}

pub fn getMaxLeaf() u32 {
    return cpuid(0, 0).eax;
}

pub fn getMaxExtendedLeaf() u32 {
    return cpuid(0x80000000, 0).eax;
}

// =============================================================================
// CPU Brand String
// =============================================================================

pub fn getBrandString() [48]u8 {
    var brand: [48]u8 = [_]u8{0} ** 48;

    if (getMaxExtendedLeaf() < 0x80000004) return brand;

    inline for (0..3) |i| {
        const result = cpuid(0x80000002 + @as(u32, i), 0);
        const offset = i * 16;
        @as(*align(1) u32, @ptrCast(&brand[offset + 0])).* = result.eax;
        @as(*align(1) u32, @ptrCast(&brand[offset + 4])).* = result.ebx;
        @as(*align(1) u32, @ptrCast(&brand[offset + 8])).* = result.ecx;
        @as(*align(1) u32, @ptrCast(&brand[offset + 12])).* = result.edx;
    }

    return brand;
}

// =============================================================================
// Feature Flags — Leaf 1 (ECX and EDX)
// =============================================================================

pub const CpuFeatures1 = struct {
    // EDX features (Leaf 1)
    fpu: bool = false, // x87 FPU
    vme: bool = false, // Virtual 8086 Mode Extensions
    de: bool = false, // Debugging Extensions
    pse: bool = false, // Page Size Extension (4MB pages)
    tsc: bool = false, // Time Stamp Counter
    msr: bool = false, // Model Specific Registers
    pae: bool = false, // Physical Address Extension
    mce: bool = false, // Machine Check Exception
    cx8: bool = false, // CMPXCHG8B Instruction
    apic: bool = false, // APIC On-Chip
    sep: bool = false, // SYSENTER/SYSEXIT
    mtrr: bool = false, // Memory Type Range Registers
    pge: bool = false, // Page Global Bit
    mca: bool = false, // Machine Check Architecture
    cmov: bool = false, // Conditional Move Instructions
    pat: bool = false, // Page Attribute Table
    pse36: bool = false, // 36-bit Page Size Extension
    psn: bool = false, // Processor Serial Number
    clfsh: bool = false, // CLFLUSH Instruction
    ds: bool = false, // Debug Store
    acpi_thermal: bool = false, // Thermal Monitor and Clock Ctrl
    mmx: bool = false, // MMX Technology
    fxsr: bool = false, // FXSAVE/FXRSTOR
    sse: bool = false, // SSE
    sse2: bool = false, // SSE2
    ss: bool = false, // Self Snoop
    htt: bool = false, // Hyper-Threading
    tm: bool = false, // Thermal Monitor
    ia64: bool = false, // IA64 processor emulating x86
    pbe: bool = false, // Pending Break Enable

    // ECX features (Leaf 1)
    sse3: bool = false, // SSE3
    pclmulqdq: bool = false, // PCLMULQDQ (carry-less multiplication)
    dtes64: bool = false, // 64-bit Debug Store
    monitor: bool = false, // MONITOR/MWAIT
    ds_cpl: bool = false, // CPL Qualified Debug Store
    vmx: bool = false, // Virtual Machine Extensions
    smx: bool = false, // Safer Mode Extensions
    est: bool = false, // Enhanced SpeedStep
    tm2: bool = false, // Thermal Monitor 2
    ssse3: bool = false, // Supplemental SSE3
    cnxt_id: bool = false, // L1 Context ID
    sdbg: bool = false, // Silicon Debug
    fma: bool = false, // Fused Multiply-Add
    cx16: bool = false, // CMPXCHG16B Instruction
    xtpr: bool = false, // xTPR Update Control
    pdcm: bool = false, // Perf/Debug Capability MSR
    pcid: bool = false, // Process Context Identifiers
    dca: bool = false, // Direct Cache Access
    sse4_1: bool = false, // SSE4.1
    sse4_2: bool = false, // SSE4.2
    x2apic: bool = false, // x2APIC
    movbe: bool = false, // MOVBE Instruction
    popcnt: bool = false, // POPCNT Instruction
    tsc_deadline: bool = false, // TSC Deadline
    aes: bool = false, // AES Instructions
    xsave: bool = false, // XSAVE/XRSTOR
    osxsave: bool = false, // OS-Enabled XSAVE
    avx: bool = false, // AVX
    f16c: bool = false, // 16-bit FP Conversion
    rdrand: bool = false, // RDRAND Instruction
    hypervisor: bool = false, // Hypervisor present
};

pub fn detectFeatures1() CpuFeatures1 {
    const result = cpuid(1, 0);
    const edx = result.edx;
    const ecx = result.ecx;

    return .{
        .fpu = (edx & (1 << 0)) != 0,
        .vme = (edx & (1 << 1)) != 0,
        .de = (edx & (1 << 2)) != 0,
        .pse = (edx & (1 << 3)) != 0,
        .tsc = (edx & (1 << 4)) != 0,
        .msr = (edx & (1 << 5)) != 0,
        .pae = (edx & (1 << 6)) != 0,
        .mce = (edx & (1 << 7)) != 0,
        .cx8 = (edx & (1 << 8)) != 0,
        .apic = (edx & (1 << 9)) != 0,
        .sep = (edx & (1 << 11)) != 0,
        .mtrr = (edx & (1 << 12)) != 0,
        .pge = (edx & (1 << 13)) != 0,
        .mca = (edx & (1 << 14)) != 0,
        .cmov = (edx & (1 << 15)) != 0,
        .pat = (edx & (1 << 16)) != 0,
        .pse36 = (edx & (1 << 17)) != 0,
        .psn = (edx & (1 << 18)) != 0,
        .clfsh = (edx & (1 << 19)) != 0,
        .ds = (edx & (1 << 21)) != 0,
        .acpi_thermal = (edx & (1 << 22)) != 0,
        .mmx = (edx & (1 << 23)) != 0,
        .fxsr = (edx & (1 << 24)) != 0,
        .sse = (edx & (1 << 25)) != 0,
        .sse2 = (edx & (1 << 26)) != 0,
        .ss = (edx & (1 << 27)) != 0,
        .htt = (edx & (1 << 28)) != 0,
        .tm = (edx & (1 << 29)) != 0,
        .ia64 = (edx & (1 << 30)) != 0,
        .pbe = (edx & (1 << 31)) != 0,

        .sse3 = (ecx & (1 << 0)) != 0,
        .pclmulqdq = (ecx & (1 << 1)) != 0,
        .dtes64 = (ecx & (1 << 2)) != 0,
        .monitor = (ecx & (1 << 3)) != 0,
        .ds_cpl = (ecx & (1 << 4)) != 0,
        .vmx = (ecx & (1 << 5)) != 0,
        .smx = (ecx & (1 << 6)) != 0,
        .est = (ecx & (1 << 7)) != 0,
        .tm2 = (ecx & (1 << 8)) != 0,
        .ssse3 = (ecx & (1 << 9)) != 0,
        .cnxt_id = (ecx & (1 << 10)) != 0,
        .sdbg = (ecx & (1 << 11)) != 0,
        .fma = (ecx & (1 << 12)) != 0,
        .cx16 = (ecx & (1 << 13)) != 0,
        .xtpr = (ecx & (1 << 14)) != 0,
        .pdcm = (ecx & (1 << 15)) != 0,
        .pcid = (ecx & (1 << 17)) != 0,
        .dca = (ecx & (1 << 18)) != 0,
        .sse4_1 = (ecx & (1 << 19)) != 0,
        .sse4_2 = (ecx & (1 << 20)) != 0,
        .x2apic = (ecx & (1 << 21)) != 0,
        .movbe = (ecx & (1 << 22)) != 0,
        .popcnt = (ecx & (1 << 23)) != 0,
        .tsc_deadline = (ecx & (1 << 24)) != 0,
        .aes = (ecx & (1 << 25)) != 0,
        .xsave = (ecx & (1 << 26)) != 0,
        .osxsave = (ecx & (1 << 27)) != 0,
        .avx = (ecx & (1 << 28)) != 0,
        .f16c = (ecx & (1 << 29)) != 0,
        .rdrand = (ecx & (1 << 30)) != 0,
        .hypervisor = (ecx & (1 << 31)) != 0,
    };
}

// =============================================================================
// Extended Feature Flags — Leaf 7 (EBX, ECX, EDX)
// =============================================================================

pub const CpuFeatures7 = struct {
    // EBX features (Leaf 7, subleaf 0)
    fsgsbase: bool = false, // FS/GS Base read/write
    tsc_adjust: bool = false, // TSC Adjust MSR
    sgx: bool = false, // Software Guard Extensions
    bmi1: bool = false, // Bit Manipulation Instruction Set 1
    hle: bool = false, // Hardware Lock Elision
    avx2: bool = false, // Advanced Vector Extensions 2
    fdp_excptn_only: bool = false, // FDP_EXCPTN_ONLY
    smep: bool = false, // Supervisor Mode Execution Prevention
    bmi2: bool = false, // Bit Manipulation Instruction Set 2
    erms: bool = false, // Enhanced REP MOVSB/STOSB
    invpcid: bool = false, // INVPCID Instruction
    rtm: bool = false, // Restricted Transactional Memory
    pqm: bool = false, // Platform Quality of Service Monitoring
    deprecate_fcs_fds: bool = false, // Deprecate FCS/FDS
    mpx: bool = false, // Memory Protection Extensions
    pqe: bool = false, // Platform Quality of Service Enforcement
    avx512f: bool = false, // AVX-512 Foundation
    avx512dq: bool = false, // AVX-512 Double/Quadword
    rdseed: bool = false, // RDSEED Instruction
    adx: bool = false, // Multi-Precision Add-Carry
    smap: bool = false, // Supervisor Mode Access Prevention
    avx512ifma: bool = false, // AVX-512 Integer FMA
    pcommit: bool = false, // PCOMMIT Instruction
    clflushopt: bool = false, // CLFLUSHOPT Instruction
    clwb: bool = false, // CLWB Instruction
    intel_pt: bool = false, // Intel Processor Trace
    avx512pf: bool = false, // AVX-512 Prefetch
    avx512er: bool = false, // AVX-512 Exponential/Reciprocal
    avx512cd: bool = false, // AVX-512 Conflict Detection
    sha: bool = false, // SHA Extensions
    avx512bw: bool = false, // AVX-512 Byte/Word
    avx512vl: bool = false, // AVX-512 Vector Length

    // ECX features (Leaf 7, subleaf 0)
    prefetchwt1: bool = false,
    avx512vbmi: bool = false, // AVX-512 VBMI
    umip: bool = false, // User-Mode Instruction Prevention
    pku: bool = false, // Protection Keys for User-Mode
    ospke: bool = false, // OS has set CR4.PKE
    waitpkg: bool = false, // WAITPKG
    avx512vbmi2: bool = false, // AVX-512 VBMI2
    cet_ss: bool = false, // CET Shadow Stack
    gfni: bool = false, // Galois Field NI
    vaes: bool = false, // Vector AES
    vpclmulqdq: bool = false, // Vector PCLMULQDQ
    avx512vnni: bool = false, // AVX-512 Vector Neural Network
    avx512bitalg: bool = false, // AVX-512 BITALG
    tme: bool = false, // Total Memory Encryption
    avx512vpopcntdq: bool = false, // AVX-512 VPOPCNTDQ
    la57: bool = false, // 5-Level Paging
    rdpid: bool = false, // RDPID Instruction
    kl: bool = false, // Key Locker
    cldemote: bool = false, // Cache Line Demote
    movdiri: bool = false, // MOVDIRI
    movdir64b: bool = false, // MOVDIR64B
    enqcmd: bool = false, // Enqueue Store

    // EDX features (Leaf 7, subleaf 0)
    avx512_4vnniw: bool = false,
    avx512_4fmaps: bool = false,
    fast_short_rep_mov: bool = false,
    avx512_vp2intersect: bool = false,
    srbds_ctrl: bool = false,
    md_clear: bool = false, // MD_CLEAR support (MDS mitigation)
    tsx_force_abort: bool = false,
    serialize: bool = false,
    hybrid: bool = false, // Hybrid processor (big.LITTLE)
    tsxldtrk: bool = false,
    pconfig: bool = false,
    lbr: bool = false, // Architectural LBR
    cet_ibt: bool = false, // CET Indirect Branch Tracking
    amx_bf16: bool = false, // AMX BFloat16
    avx512_fp16: bool = false,
    amx_tile: bool = false, // AMX Tile Architecture
    amx_int8: bool = false, // AMX INT8
    ibrs_ibpb: bool = false, // Speculation Control
    stibp: bool = false, // Single Thread Indirect Branch
    l1d_flush: bool = false,
    arch_capabilities: bool = false, // IA32_ARCH_CAPABILITIES
    core_capabilities: bool = false,
    ssbd: bool = false, // Speculative Store Bypass Disable
};

pub fn detectFeatures7() CpuFeatures7 {
    if (getMaxLeaf() < 7) return .{};

    const result = cpuid(7, 0);
    const ebx = result.ebx;
    const ecx = result.ecx;
    const edx = result.edx;

    return .{
        .fsgsbase = (ebx & (1 << 0)) != 0,
        .tsc_adjust = (ebx & (1 << 1)) != 0,
        .sgx = (ebx & (1 << 2)) != 0,
        .bmi1 = (ebx & (1 << 3)) != 0,
        .hle = (ebx & (1 << 4)) != 0,
        .avx2 = (ebx & (1 << 5)) != 0,
        .fdp_excptn_only = (ebx & (1 << 6)) != 0,
        .smep = (ebx & (1 << 7)) != 0,
        .bmi2 = (ebx & (1 << 8)) != 0,
        .erms = (ebx & (1 << 9)) != 0,
        .invpcid = (ebx & (1 << 10)) != 0,
        .rtm = (ebx & (1 << 11)) != 0,
        .pqm = (ebx & (1 << 12)) != 0,
        .deprecate_fcs_fds = (ebx & (1 << 13)) != 0,
        .mpx = (ebx & (1 << 14)) != 0,
        .pqe = (ebx & (1 << 15)) != 0,
        .avx512f = (ebx & (1 << 16)) != 0,
        .avx512dq = (ebx & (1 << 17)) != 0,
        .rdseed = (ebx & (1 << 18)) != 0,
        .adx = (ebx & (1 << 19)) != 0,
        .smap = (ebx & (1 << 20)) != 0,
        .avx512ifma = (ebx & (1 << 21)) != 0,
        .pcommit = (ebx & (1 << 22)) != 0,
        .clflushopt = (ebx & (1 << 23)) != 0,
        .clwb = (ebx & (1 << 24)) != 0,
        .intel_pt = (ebx & (1 << 25)) != 0,
        .avx512pf = (ebx & (1 << 26)) != 0,
        .avx512er = (ebx & (1 << 27)) != 0,
        .avx512cd = (ebx & (1 << 28)) != 0,
        .sha = (ebx & (1 << 29)) != 0,
        .avx512bw = (ebx & (1 << 30)) != 0,
        .avx512vl = (ebx & (1 << 31)) != 0,

        .prefetchwt1 = (ecx & (1 << 0)) != 0,
        .avx512vbmi = (ecx & (1 << 1)) != 0,
        .umip = (ecx & (1 << 2)) != 0,
        .pku = (ecx & (1 << 3)) != 0,
        .ospke = (ecx & (1 << 4)) != 0,
        .waitpkg = (ecx & (1 << 5)) != 0,
        .avx512vbmi2 = (ecx & (1 << 6)) != 0,
        .cet_ss = (ecx & (1 << 7)) != 0,
        .gfni = (ecx & (1 << 8)) != 0,
        .vaes = (ecx & (1 << 9)) != 0,
        .vpclmulqdq = (ecx & (1 << 10)) != 0,
        .avx512vnni = (ecx & (1 << 11)) != 0,
        .avx512bitalg = (ecx & (1 << 12)) != 0,
        .tme = (ecx & (1 << 13)) != 0,
        .avx512vpopcntdq = (ecx & (1 << 14)) != 0,
        .la57 = (ecx & (1 << 16)) != 0,
        .rdpid = (ecx & (1 << 22)) != 0,
        .kl = (ecx & (1 << 23)) != 0,
        .cldemote = (ecx & (1 << 25)) != 0,
        .movdiri = (ecx & (1 << 27)) != 0,
        .movdir64b = (ecx & (1 << 28)) != 0,
        .enqcmd = (ecx & (1 << 29)) != 0,

        .avx512_4vnniw = (edx & (1 << 2)) != 0,
        .avx512_4fmaps = (edx & (1 << 3)) != 0,
        .fast_short_rep_mov = (edx & (1 << 4)) != 0,
        .avx512_vp2intersect = (edx & (1 << 8)) != 0,
        .srbds_ctrl = (edx & (1 << 9)) != 0,
        .md_clear = (edx & (1 << 10)) != 0,
        .tsx_force_abort = (edx & (1 << 13)) != 0,
        .serialize = (edx & (1 << 14)) != 0,
        .hybrid = (edx & (1 << 15)) != 0,
        .tsxldtrk = (edx & (1 << 16)) != 0,
        .pconfig = (edx & (1 << 18)) != 0,
        .lbr = (edx & (1 << 19)) != 0,
        .cet_ibt = (edx & (1 << 20)) != 0,
        .amx_bf16 = (edx & (1 << 22)) != 0,
        .avx512_fp16 = (edx & (1 << 23)) != 0,
        .amx_tile = (edx & (1 << 24)) != 0,
        .amx_int8 = (edx & (1 << 25)) != 0,
        .ibrs_ibpb = (edx & (1 << 26)) != 0,
        .stibp = (edx & (1 << 27)) != 0,
        .l1d_flush = (edx & (1 << 28)) != 0,
        .arch_capabilities = (edx & (1 << 29)) != 0,
        .core_capabilities = (edx & (1 << 30)) != 0,
        .ssbd = (edx & (1 << 31)) != 0,
    };
}

// =============================================================================
// Extended Features — Leaf 0x80000001
// =============================================================================

pub const ExtendedFeatures = struct {
    // ECX
    lahf_sahf: bool = false,
    cmp_legacy: bool = false,
    svm: bool = false, // Secure Virtual Machine (AMD)
    extapic: bool = false,
    cr8_legacy: bool = false,
    abm: bool = false, // Advanced Bit Manipulation (LZCNT)
    sse4a: bool = false,
    misalign_sse: bool = false,
    prefetch_3dnow: bool = false,
    osvw: bool = false,
    ibs: bool = false, // Instruction Based Sampling (AMD)
    xop: bool = false,
    skinit: bool = false,
    wdt: bool = false,
    lwp: bool = false,
    fma4: bool = false,
    tce: bool = false,
    tbm: bool = false,
    topoext: bool = false,
    perfctr_core: bool = false,
    perfctr_nb: bool = false,
    dbx: bool = false,
    perftsc: bool = false,
    pcx_l2i: bool = false,

    // EDX
    syscall: bool = false,
    mp: bool = false,
    nx: bool = false, // No-Execute bit
    mmxext: bool = false,
    fxsr_opt: bool = false,
    pdpe1gb: bool = false, // 1GB Pages
    rdtscp: bool = false,
    lm: bool = false, // Long Mode (64-bit)
    ext_3dnow: bool = false,
    _3dnow: bool = false,
};

pub fn detectExtendedFeatures() ExtendedFeatures {
    if (getMaxExtendedLeaf() < 0x80000001) return .{};

    const result = cpuid(0x80000001, 0);
    const ecx = result.ecx;
    const edx = result.edx;

    return .{
        .lahf_sahf = (ecx & (1 << 0)) != 0,
        .cmp_legacy = (ecx & (1 << 1)) != 0,
        .svm = (ecx & (1 << 2)) != 0,
        .extapic = (ecx & (1 << 3)) != 0,
        .cr8_legacy = (ecx & (1 << 4)) != 0,
        .abm = (ecx & (1 << 5)) != 0,
        .sse4a = (ecx & (1 << 6)) != 0,
        .misalign_sse = (ecx & (1 << 7)) != 0,
        .prefetch_3dnow = (ecx & (1 << 8)) != 0,
        .osvw = (ecx & (1 << 9)) != 0,
        .ibs = (ecx & (1 << 10)) != 0,
        .xop = (ecx & (1 << 11)) != 0,
        .skinit = (ecx & (1 << 12)) != 0,
        .wdt = (ecx & (1 << 13)) != 0,
        .lwp = (ecx & (1 << 15)) != 0,
        .fma4 = (ecx & (1 << 16)) != 0,
        .tce = (ecx & (1 << 17)) != 0,
        .tbm = (ecx & (1 << 21)) != 0,
        .topoext = (ecx & (1 << 22)) != 0,
        .perfctr_core = (ecx & (1 << 23)) != 0,
        .perfctr_nb = (ecx & (1 << 24)) != 0,
        .dbx = (ecx & (1 << 26)) != 0,
        .perftsc = (ecx & (1 << 27)) != 0,
        .pcx_l2i = (ecx & (1 << 28)) != 0,

        .syscall = (edx & (1 << 11)) != 0,
        .mp = (edx & (1 << 19)) != 0,
        .nx = (edx & (1 << 20)) != 0,
        .mmxext = (edx & (1 << 22)) != 0,
        .fxsr_opt = (edx & (1 << 25)) != 0,
        .pdpe1gb = (edx & (1 << 26)) != 0,
        .rdtscp = (edx & (1 << 27)) != 0,
        .lm = (edx & (1 << 29)) != 0,
        .ext_3dnow = (edx & (1 << 30)) != 0,
        ._3dnow = (edx & (1 << 31)) != 0,
    };
}

// =============================================================================
// Cache Topology Information — Leaf 4
// =============================================================================

pub const CacheType = enum(u8) {
    null_cache = 0,
    data = 1,
    instruction = 2,
    unified = 3,
};

pub const CacheInfo = struct {
    cache_type: CacheType,
    level: u8,
    self_initializing: bool,
    fully_associative: bool,
    max_threads_sharing: u16,
    max_cores_in_package: u16,
    line_size: u16, // in bytes
    partitions: u16,
    ways: u16,
    sets: u32,
    write_back_invalidate: bool,
    inclusive: bool,
    complex_indexing: bool,
    total_size: u64, // computed total size in bytes
};

pub fn getCacheInfo(index: u32) ?CacheInfo {
    const result = cpuid(4, index);
    const cache_type_val: u8 = @truncate(result.eax & 0x1F);

    if (cache_type_val == 0) return null; // No more caches

    const line_size: u16 = @truncate((result.ebx & 0xFFF) + 1);
    const partitions: u16 = @truncate(((result.ebx >> 12) & 0x3FF) + 1);
    const ways: u16 = @truncate(((result.ebx >> 22) & 0x3FF) + 1);
    const sets: u32 = result.ecx + 1;

    return .{
        .cache_type = @enumFromInt(cache_type_val),
        .level = @truncate((result.eax >> 5) & 0x7),
        .self_initializing = (result.eax & (1 << 8)) != 0,
        .fully_associative = (result.eax & (1 << 9)) != 0,
        .max_threads_sharing = @truncate(((result.eax >> 14) & 0xFFF) + 1),
        .max_cores_in_package = @truncate(((result.eax >> 26) & 0x3F) + 1),
        .line_size = line_size,
        .partitions = partitions,
        .ways = ways,
        .sets = sets,
        .write_back_invalidate = (result.edx & (1 << 0)) != 0,
        .inclusive = (result.edx & (1 << 1)) != 0,
        .complex_indexing = (result.edx & (1 << 2)) != 0,
        .total_size = @as(u64, line_size) * @as(u64, partitions) * @as(u64, ways) * @as(u64, sets),
    };
}

/// Enumerate all cache levels and store information.
pub fn enumerateAllCaches(buffer: []CacheInfo) u32 {
    var count: u32 = 0;
    var index: u32 = 0;
    while (index < buffer.len) : (index += 1) {
        const info = getCacheInfo(index) orelse break;
        buffer[count] = info;
        count += 1;
    }
    return count;
}

// =============================================================================
// CPU Topology — Leaf 0xB (x2APIC Topology Enumeration)
// =============================================================================

pub const TopologyLevel = enum(u8) {
    invalid = 0,
    smt = 1, // Simultaneous Multi-Threading (logical processors)
    core = 2, // Physical cores
    module = 3,
    tile = 4,
    die = 5,
    _,
};

pub const TopologyInfo = struct {
    level_type: TopologyLevel,
    bits_shift: u8,
    logical_processors: u16,
    x2apic_id: u32,
};

pub fn getTopologyInfo(level: u32) ?TopologyInfo {
    const result = cpuid(0xB, level);

    const level_type: u8 = @truncate((result.ecx >> 8) & 0xFF);
    if (level_type == 0) return null;

    return .{
        .level_type = @enumFromInt(level_type),
        .bits_shift = @truncate(result.eax & 0x1F),
        .logical_processors = @truncate(result.ebx & 0xFFFF),
        .x2apic_id = result.edx,
    };
}

// =============================================================================
// Physical Address Width — Leaf 0x80000008
// =============================================================================

pub const AddressWidths = struct {
    physical_bits: u8,
    linear_bits: u8,
    guest_physical_bits: u8,
};

pub fn getAddressWidths() AddressWidths {
    if (getMaxExtendedLeaf() < 0x80000008) {
        return .{
            .physical_bits = 36,
            .linear_bits = 48,
            .guest_physical_bits = 0,
        };
    }

    const result = cpuid(0x80000008, 0);
    return .{
        .physical_bits = @truncate(result.eax & 0xFF),
        .linear_bits = @truncate((result.eax >> 8) & 0xFF),
        .guest_physical_bits = @truncate((result.eax >> 16) & 0xFF),
    };
}

// =============================================================================
// TSC/Core Crystal Clock Frequency — Leaf 0x15
// =============================================================================

pub const TscFreqInfo = struct {
    denominator: u32, // TSC/core crystal clock ratio denominator
    numerator: u32, // TSC/core crystal clock ratio numerator
    crystal_frequency: u32, // Core crystal clock frequency in Hz (0 if unknown)

    /// Calculate TSC frequency if all values are known.
    pub fn tscFrequencyHz(self: TscFreqInfo) ?u64 {
        if (self.denominator == 0 or self.numerator == 0) return null;
        if (self.crystal_frequency == 0) return null;
        return (@as(u64, self.crystal_frequency) * @as(u64, self.numerator)) / @as(u64, self.denominator);
    }
};

pub fn getTscFrequencyInfo() ?TscFreqInfo {
    if (getMaxLeaf() < 0x15) return null;

    const result = cpuid(0x15, 0);
    if (result.eax == 0 or result.ebx == 0) return null;

    return .{
        .denominator = result.eax,
        .numerator = result.ebx,
        .crystal_frequency = result.ecx,
    };
}

// =============================================================================
// Processor Frequency — Leaf 0x16
// =============================================================================

pub const ProcessorFreqInfo = struct {
    base_freq_mhz: u16,
    max_freq_mhz: u16,
    bus_freq_mhz: u16,
};

pub fn getProcessorFrequencyInfo() ?ProcessorFreqInfo {
    if (getMaxLeaf() < 0x16) return null;

    const result = cpuid(0x16, 0);
    return .{
        .base_freq_mhz = @truncate(result.eax & 0xFFFF),
        .max_freq_mhz = @truncate(result.ebx & 0xFFFF),
        .bus_freq_mhz = @truncate(result.ecx & 0xFFFF),
    };
}

// =============================================================================
// Aggregate CPU Information
// =============================================================================

pub const CpuInfo = struct {
    vendor: CpuVendor,
    brand_string: [48]u8,
    family: u8,
    model: u8,
    stepping: u8,
    features1: CpuFeatures1,
    features7: CpuFeatures7,
    extended: ExtendedFeatures,
    address_widths: AddressWidths,
    max_leaf: u32,
    max_extended_leaf: u32,
    local_apic_id: u8,

    /// Detect all CPU information at once.
    pub fn detect() CpuInfo {
        const vendor = detectVendor();
        const leaf1 = cpuid(1, 0);

        const family_raw: u8 = @truncate((leaf1.eax >> 8) & 0xF);
        const model_raw: u8 = @truncate((leaf1.eax >> 4) & 0xF);
        const ext_family: u8 = @truncate((leaf1.eax >> 20) & 0xFF);
        const ext_model: u8 = @truncate((leaf1.eax >> 16) & 0xF);

        const family = if (family_raw == 0xF) family_raw + ext_family else family_raw;
        const model = if (family_raw == 0x6 or family_raw == 0xF)
            (@as(u8, ext_model) << 4) | model_raw
        else
            model_raw;

        return .{
            .vendor = vendor,
            .brand_string = getBrandString(),
            .family = family,
            .model = model,
            .stepping = @truncate(leaf1.eax & 0xF),
            .features1 = detectFeatures1(),
            .features7 = detectFeatures7(),
            .extended = detectExtendedFeatures(),
            .address_widths = getAddressWidths(),
            .max_leaf = getMaxLeaf(),
            .max_extended_leaf = getMaxExtendedLeaf(),
            .local_apic_id = @truncate((leaf1.ebx >> 24) & 0xFF),
        };
    }

    /// Check if the CPU supports all features needed for the kernel.
    pub fn validateMinimumRequirements(self: CpuInfo) bool {
        // x86_64 requires these at minimum
        if (!self.extended.lm) return false; // Long Mode
        if (!self.features1.pae) return false; // PAE
        if (!self.features1.msr) return false; // MSRs
        if (!self.features1.apic) return false; // APIC
        if (!self.features1.tsc) return false; // TSC
        if (!self.extended.nx) return false; // NX bit
        return true;
    }

    /// Check if hardware virtualization is available.
    pub fn hasVirtualization(self: CpuInfo) bool {
        return self.features1.vmx or self.extended.svm;
    }

    /// Check if the CPU supports advanced security features.
    pub fn hasAdvancedSecurity(self: CpuInfo) bool {
        return self.features7.smep and self.features7.smap;
    }

    /// Check if 1GB huge pages are supported.
    pub fn has1GbPages(self: CpuInfo) bool {
        return self.extended.pdpe1gb;
    }

    /// Check if PCID is supported for efficient TLB management.
    pub fn hasPcid(self: CpuInfo) bool {
        return self.features1.pcid;
    }

    /// Check if INVPCID instruction is available.
    pub fn hasInvpcid(self: CpuInfo) bool {
        return self.features7.invpcid;
    }
};
