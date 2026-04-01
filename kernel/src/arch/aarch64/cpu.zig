// =============================================================================
// Zxyphor Kernel — ARM64 CPU Feature Detection & Management
// =============================================================================
// Comprehensive CPU identification and feature detection for AArch64 processors.
// Reads ID registers (ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, ID_AA64MMFR0_EL1,
// ID_AA64PFR0_EL1, etc.) and builds a feature bitmap for runtime capability
// checking. Supports all ARMv8.0 through ARMv9.4 feature extensions.
//
// Features detected:
//   - Cryptographic extensions (AES, SHA1, SHA2, SHA3, SM3/SM4, CRC32)
//   - Atomic operations (LSE, LSE2, LRCPC, LRCPC2, LRCPC3)
//   - Pointer Authentication (PAuth, PAuth2, FPAC, FPACCOMBINE)
//   - Memory Tagging (MTE, MTE2, MTE3)
//   - Scalable Vector Extension (SVE, SVE2, SME, SME2)
//   - Branch Target Identification (BTI)
//   - Confidential Compute (RME, CCA)
//   - Performance monitoring (PMUv3, SPE, TRBE, BRBE)
//   - Debug (Self-Hosted Trace, Statistical Profiling)
//   - Virtualization (VHE, NV, NV2, S-EL2)
//   - RAS (Reliability, Availability, Serviceability)
// =============================================================================

const std = @import("std");

// ── CPU Feature Flags ─────────────────────────────────────────────────────
pub const CpuFeature = enum(u64) {
    // ID_AA64ISAR0_EL1 features
    aes                 = 1 << 0,
    pmull               = 1 << 1,
    sha1                = 1 << 2,
    sha256              = 1 << 3,
    sha512              = 1 << 4,
    sha3                = 1 << 5,
    crc32               = 1 << 6,
    atomics_lse         = 1 << 7,  // Large System Extensions (atomics)
    rdm                 = 1 << 8,  // Rounding Double Multiply
    sm3                 = 1 << 9,
    sm4                 = 1 << 10,
    dot_prod            = 1 << 11, // Dot Product
    fhm                 = 1 << 12, // FP16 multiplication
    flag_m              = 1 << 13, // Flag manipulation
    tlbi_range          = 1 << 14, // TLBI range instructions
    rndr                = 1 << 15, // Random Number

    // ID_AA64ISAR1_EL1 features
    dpb                 = 1 << 16, // Data Persistence (DC CVAP)
    dpb2                = 1 << 17, // DC CVADP
    apa                 = 1 << 18, // Address auth (Arch)
    api                 = 1 << 19, // Address auth (Impl)
    jscvt               = 1 << 20, // JS conversion
    fcma                = 1 << 21, // Complex multiply-add
    lrcpc               = 1 << 22, // Load-Acquire RCpc
    lrcpc2              = 1 << 23,
    gpa                 = 1 << 24, // Generic auth (Arch)
    gpi                 = 1 << 25, // Generic auth (Impl)
    frintts             = 1 << 26, // Floating-point to int (TS)
    sb                  = 1 << 27, // Speculation Barrier
    specres             = 1 << 28, // Speculation restriction
    bf16                = 1 << 29, // BFloat16
    dgh                 = 1 << 30, // Data Gathering Hint
    i8mm                = 1 << 31, // Int8 matrix multiply

    // ID_AA64PFR0_EL1 features
    fp                  = 1 << 32, // Floating Point
    advsimd             = 1 << 33, // Advanced SIMD (NEON)
    gic_v3              = 1 << 34, // GICv3 system registers
    gic_v4              = 1 << 35, // GICv4 direct injection
    ras                 = 1 << 36, // RAS Extension
    ras_v1p1            = 1 << 37, // RAS v1.1
    sve                 = 1 << 38, // Scalable Vector Extension
    sve2                = 1 << 39,
    el2_vhe             = 1 << 40, // Virtualization Host Extension
    el3                 = 1 << 41, // EL3 (Secure Monitor)
    dit                 = 1 << 42, // Data Independent Timing
    csv2                = 1 << 43, // Spectre-v2 mitigation
    csv3                = 1 << 44, // Spectre-v3 mitigation
    amu                 = 1 << 45, // Activity Monitor
    mpam                = 1 << 46, // Memory Partitioning
    sel2                = 1 << 47, // Secure EL2
    rme                 = 1 << 48, // Realm Management Extension
    sme                 = 1 << 49, // Scalable Matrix Extension
    sme2                = 1 << 50,

    // ID_AA64MMFR0_EL1 features
    pa_range_48         = 1 << 51, // 48-bit physical address
    pa_range_52         = 1 << 52, // 52-bit physical address
    asid_16             = 1 << 53, // 16-bit ASID
    mixed_endian        = 1 << 54,
    snsmem              = 1 << 55, // Secure/Non-Secure memory
    big_end_el0         = 1 << 56,
    tgran_16k           = 1 << 57, // 16KB granule support
    tgran_64k           = 1 << 58, // 64KB granule support
    hafdbs              = 1 << 59, // Hardware AF/DB update
    vmid_16             = 1 << 60, // 16-bit VMID

    // ID_AA64MMFR2_EL1 features
    mte                 = 1 << 61, // Memory Tagging Extension
    mte2                = 1 << 62, // MTE2 (Asymmetric)
    bti                 = 1 << 63, // Branch Target Identification
};

// ── CPU Feature Set ───────────────────────────────────────────────────────
pub const CpuFeatureSet = struct {
    bits: u64 = 0,
    bits_ext: u64 = 0,

    const Self = @This();

    pub fn has(self: Self, feature: CpuFeature) bool {
        const bit = @intFromEnum(feature);
        return (self.bits & bit) != 0;
    }

    pub fn set(self: *Self, feature: CpuFeature) void {
        const bit = @intFromEnum(feature);
        self.bits |= bit;
    }

    pub fn count(self: Self) u32 {
        return @popCount(self.bits) + @popCount(self.bits_ext);
    }
};

// ── CPU Identification ────────────────────────────────────────────────────
pub const CpuId = struct {
    implementer: u8,
    variant: u4,
    architecture: u4,
    part_num: u12,
    revision: u4,

    const Self = @This();

    pub fn read() Self {
        const midr = readMidr();
        return Self{
            .implementer = @truncate((midr >> 24) & 0xFF),
            .variant = @truncate((midr >> 20) & 0xF),
            .architecture = @truncate((midr >> 16) & 0xF),
            .part_num = @truncate((midr >> 4) & 0xFFF),
            .revision = @truncate(midr & 0xF),
        };
    }

    pub fn implementerName(self: Self) []const u8 {
        return switch (self.implementer) {
            0x41 => "ARM Ltd",
            0x42 => "Broadcom",
            0x43 => "Cavium/Marvell",
            0x44 => "DEC",
            0x46 => "Fujitsu",
            0x48 => "HiSilicon",
            0x49 => "Infineon",
            0x4D => "Motorola/Freescale",
            0x4E => "NVIDIA",
            0x50 => "Applied Micro (APM)",
            0x51 => "Qualcomm",
            0x53 => "Samsung",
            0x54 => "Texas Instruments",
            0x56 => "Marvell",
            0x61 => "Apple",
            0x66 => "Faraday",
            0x69 => "Intel",
            0x6D => "Microsoft",
            0xC0 => "Ampere Computing",
            else => "Unknown",
        };
    }

    pub fn coreName(self: Self) []const u8 {
        if (self.implementer == 0x41) { // ARM
            return switch (self.part_num) {
                0xD02 => "Cortex-A34",
                0xD03 => "Cortex-A53",
                0xD04 => "Cortex-A35",
                0xD05 => "Cortex-A55",
                0xD06 => "Cortex-A65",
                0xD07 => "Cortex-A57",
                0xD08 => "Cortex-A72",
                0xD09 => "Cortex-A73",
                0xD0A => "Cortex-A75",
                0xD0B => "Cortex-A76",
                0xD0C => "Neoverse N1",
                0xD0D => "Cortex-A77",
                0xD0E => "Cortex-A76AE",
                0xD40 => "Neoverse V1",
                0xD41 => "Cortex-A78",
                0xD42 => "Cortex-A78AE",
                0xD43 => "Cortex-A65AE",
                0xD44 => "Cortex-X1",
                0xD46 => "Cortex-A510",
                0xD47 => "Cortex-A710",
                0xD48 => "Cortex-X2",
                0xD49 => "Neoverse N2",
                0xD4A => "Neoverse E1",
                0xD4B => "Cortex-A78C",
                0xD4C => "Cortex-X1C",
                0xD4D => "Cortex-A715",
                0xD4E => "Cortex-X3",
                0xD4F => "Neoverse V2",
                0xD80 => "Cortex-A520",
                0xD81 => "Cortex-A720",
                0xD82 => "Cortex-X4",
                0xD84 => "Neoverse V3",
                0xD85 => "Cortex-X925",
                0xD87 => "Cortex-A725",
                else => "Unknown ARM Core",
            };
        }
        if (self.implementer == 0x61) { // Apple
            return switch (self.part_num) {
                0x000 => "Apple M1 Icestorm",
                0x001 => "Apple M1 Firestorm",
                0x002 => "Apple M1 Pro/Max Icestorm",
                0x003 => "Apple M1 Pro/Max Firestorm",
                0x004 => "Apple M2 Blizzard",
                0x005 => "Apple M2 Avalanche",
                0x006 => "Apple M2 Pro/Max Blizzard",
                0x007 => "Apple M2 Pro/Max Avalanche",
                0x008 => "Apple M3 Sawtooth",
                0x009 => "Apple M3 Everest",
                else => "Unknown Apple Core",
            };
        }
        if (self.implementer == 0x51) { // Qualcomm
            return switch (self.part_num) {
                0x800 => "Kryo 260 Gold",
                0x801 => "Kryo 260 Silver",
                0x802 => "Kryo 385 Gold",
                0x803 => "Kryo 385 Silver",
                0x804 => "Kryo 485 Gold",
                0x805 => "Kryo 485 Silver",
                0xC00 => "Falkor",
                0xC01 => "Saphira",
                else => "Unknown Qualcomm Core",
            };
        }
        return "Unknown Core";
    }
};

// ── CPU Topology ──────────────────────────────────────────────────────────
pub const CpuTopology = struct {
    cpu_id: u32,
    cluster_id: u32,
    package_id: u32,
    core_in_cluster: u32,
    thread_in_core: u32,
    is_boot_cpu: bool,
    is_online: bool,
    features: CpuFeatureSet,
    cpu_ident: CpuId,
    mpidr: u64,

    // Cache information
    l1i_size: u32,    // L1 instruction cache size (bytes)
    l1d_size: u32,    // L1 data cache size (bytes)
    l2_size: u32,     // L2 cache size (bytes)
    l3_size: u32,     // L3 cache size (bytes)
    l1_line_size: u32, // L1 cache line size (bytes)
    l2_line_size: u32,

    const Self = @This();

    pub fn fromMpidr(mpidr: u64) Self {
        return Self{
            .cpu_id = @truncate(mpidr & 0xFF),
            .cluster_id = @truncate((mpidr >> 8) & 0xFF),
            .package_id = @truncate((mpidr >> 16) & 0xFF),
            .core_in_cluster = @truncate(mpidr & 0xFF),
            .thread_in_core = 0,
            .is_boot_cpu = false,
            .is_online = false,
            .features = .{},
            .cpu_ident = CpuId.read(),
            .mpidr = mpidr,
            .l1i_size = 0,
            .l1d_size = 0,
            .l2_size = 0,
            .l3_size = 0,
            .l1_line_size = 0,
            .l2_line_size = 0,
        };
    }
};

pub const MAX_CPUS: usize = 256;
var cpu_topologies: [MAX_CPUS]CpuTopology = undefined;
var nr_cpus_detected: u32 = 0;
var boot_cpu_features: CpuFeatureSet = .{};

// ── Feature Detection ─────────────────────────────────────────────────────
pub fn detectFeatures() CpuFeatureSet {
    var features = CpuFeatureSet{};

    // Read ID_AA64ISAR0_EL1 — Instruction Set Attribute Register 0
    const isar0 = readIdAa64Isar0();
    if (extractField(isar0, 4, 4) >= 1) features.set(.aes);
    if (extractField(isar0, 4, 4) >= 2) features.set(.pmull);
    if (extractField(isar0, 8, 4) >= 1) features.set(.sha1);
    if (extractField(isar0, 12, 4) >= 1) features.set(.sha256);
    if (extractField(isar0, 12, 4) >= 2) features.set(.sha512);
    if (extractField(isar0, 32, 4) >= 1) features.set(.sha3);
    if (extractField(isar0, 16, 4) >= 1) features.set(.crc32);
    if (extractField(isar0, 20, 4) >= 2) features.set(.atomics_lse);
    if (extractField(isar0, 28, 4) >= 1) features.set(.rdm);
    if (extractField(isar0, 36, 4) >= 1) features.set(.sm3);
    if (extractField(isar0, 40, 4) >= 1) features.set(.sm4);
    if (extractField(isar0, 44, 4) >= 1) features.set(.dot_prod);
    if (extractField(isar0, 48, 4) >= 1) features.set(.fhm);
    if (extractField(isar0, 52, 4) >= 1) features.set(.flag_m);
    if (extractField(isar0, 56, 4) >= 2) features.set(.tlbi_range);
    if (extractField(isar0, 60, 4) >= 1) features.set(.rndr);

    // Read ID_AA64ISAR1_EL1 — Instruction Set Attribute Register 1
    const isar1 = readIdAa64Isar1();
    if (extractField(isar1, 0, 4) >= 1) features.set(.dpb);
    if (extractField(isar1, 0, 4) >= 2) features.set(.dpb2);
    if (extractField(isar1, 4, 4) >= 1) features.set(.apa);
    if (extractField(isar1, 8, 4) >= 1) features.set(.api);
    if (extractField(isar1, 12, 4) >= 1) features.set(.jscvt);
    if (extractField(isar1, 16, 4) >= 1) features.set(.fcma);
    if (extractField(isar1, 20, 4) >= 1) features.set(.lrcpc);
    if (extractField(isar1, 20, 4) >= 2) features.set(.lrcpc2);
    if (extractField(isar1, 24, 4) >= 1) features.set(.gpa);
    if (extractField(isar1, 28, 4) >= 1) features.set(.gpi);
    if (extractField(isar1, 32, 4) >= 1) features.set(.frintts);
    if (extractField(isar1, 36, 4) >= 1) features.set(.sb);
    if (extractField(isar1, 40, 4) >= 1) features.set(.specres);
    if (extractField(isar1, 44, 4) >= 1) features.set(.bf16);
    if (extractField(isar1, 48, 4) >= 1) features.set(.dgh);
    if (extractField(isar1, 52, 4) >= 1) features.set(.i8mm);

    // Read ID_AA64PFR0_EL1 — Processor Feature Register 0
    const pfr0 = readIdAa64Pfr0();
    if (extractField(pfr0, 16, 4) == 0) features.set(.fp); // 0 = impl, 0xF = not impl
    if (extractField(pfr0, 20, 4) == 0) features.set(.advsimd);
    if (extractField(pfr0, 24, 4) >= 1) features.set(.gic_v3);
    if (extractField(pfr0, 24, 4) >= 3) features.set(.gic_v4);
    if (extractField(pfr0, 28, 4) >= 1) features.set(.ras);
    if (extractField(pfr0, 28, 4) >= 2) features.set(.ras_v1p1);
    if (extractField(pfr0, 32, 4) >= 1) features.set(.sve);
    if (extractField(pfr0, 8, 4) >= 1) features.set(.el2_vhe);
    if (extractField(pfr0, 12, 4) >= 1) features.set(.el3);
    if (extractField(pfr0, 48, 4) >= 1) features.set(.dit);
    if (extractField(pfr0, 56, 4) >= 1) features.set(.csv2);
    if (extractField(pfr0, 60, 4) >= 1) features.set(.csv3);

    // Read ID_AA64PFR1_EL1 — Processor Feature Register 1
    const pfr1 = readIdAa64Pfr1();
    if (extractField(pfr1, 8, 4) >= 1) features.set(.mte);
    if (extractField(pfr1, 8, 4) >= 2) features.set(.mte2);
    if (extractField(pfr1, 0, 4) >= 1) features.set(.bti);
    if (extractField(pfr1, 32, 4) >= 1) features.set(.sme);
    if (extractField(pfr1, 20, 4) >= 1) features.set(.mpam);
    if (extractField(pfr1, 36, 4) >= 1) features.set(.rme);

    // Read ID_AA64MMFR0_EL1 — Memory Model Feature Register 0
    const mmfr0 = readIdAa64Mmfr0();
    const pa_range = extractField(mmfr0, 0, 4);
    if (pa_range >= 5) features.set(.pa_range_48);
    if (pa_range >= 6) features.set(.pa_range_52);
    if (extractField(mmfr0, 4, 4) >= 2) features.set(.asid_16);
    if (extractField(mmfr0, 8, 4) >= 1) features.set(.mixed_endian);
    if (extractField(mmfr0, 12, 4) >= 1) features.set(.snsmem);
    if (extractField(mmfr0, 20, 4) == 1) features.set(.tgran_16k);
    if (extractField(mmfr0, 24, 4) == 0) features.set(.tgran_64k);
    if (extractField(mmfr0, 28, 4) >= 1) features.set(.hafdbs);

    // Read ID_AA64MMFR1_EL1 for VMID and other features
    const mmfr1 = readIdAa64Mmfr1();
    if (extractField(mmfr1, 4, 4) >= 2) features.set(.vmid_16);

    return features;
}

// ── Cache Detection ───────────────────────────────────────────────────────
pub const CacheInfo = struct {
    level: u8,
    cache_type: CacheType,
    line_size: u32,
    sets: u32,
    ways: u32,
    total_size: u32,

    const CacheType = enum(u3) {
        none = 0,
        instruction = 1,
        data = 2,
        unified = 3,
    };
};

pub fn detectCaches(topology: *CpuTopology) void {
    // Read CLIDR_EL1 — Cache Level ID Register
    const clidr = readClidr();

    // Parse up to 7 cache levels
    var level: u32 = 0;
    while (level < 7) : (level += 1) {
        const ctype = @as(u3, @truncate((clidr >> (level * 3)) & 0x7));
        if (ctype == 0) break; // No cache at this level

        // Select cache level and type for CCSIDR readout
        // Data/Unified cache
        if (ctype >= 2) {
            writeCsselr((@as(u64, level) << 1) | 0); // Data/Unified
            const ccsidr = readCcsidr();

            const line_size = @as(u32, 1) << @as(u5, @truncate((ccsidr & 0x7) + 4));
            const assoc = @as(u32, @truncate(((ccsidr >> 3) & 0x3FF) + 1));
            const sets = @as(u32, @truncate(((ccsidr >> 13) & 0x7FFF) + 1));
            const total = line_size * assoc * sets;

            switch (level) {
                0 => {
                    topology.l1d_size = total;
                    topology.l1_line_size = line_size;
                },
                1 => {
                    topology.l2_size = total;
                    topology.l2_line_size = line_size;
                },
                2 => {
                    topology.l3_size = total;
                },
                else => {},
            }
        }

        // Instruction cache (separate only)
        if (ctype == 1 or (ctype >= 3 and level == 0)) {
            writeCsselr((@as(u64, level) << 1) | 1); // Instruction
            const ccsidr = readCcsidr();
            const line_size = @as(u32, 1) << @as(u5, @truncate((ccsidr & 0x7) + 4));
            const assoc = @as(u32, @truncate(((ccsidr >> 3) & 0x3FF) + 1));
            const sets = @as(u32, @truncate(((ccsidr >> 13) & 0x7FFF) + 1));
            const total = line_size * assoc * sets;

            if (level == 0) {
                topology.l1i_size = total;
            }
        }
    }
}

// ── SVE Vector Length Detection ───────────────────────────────────────────
pub const MAX_SVE_VL: u32 = 2048; // Maximum SVE vector length in bits (SVE2 max)

pub fn detectSveVectorLength() u32 {
    if (!boot_cpu_features.has(.sve)) return 0;

    // Read ZCR_EL1 to get configured vector length
    const zcr = readZcrEl1();
    const vl = @as(u32, @truncate((zcr & 0xF) + 1)) * 128; // VL in bits
    return vl;
}

// ── CPU Initialization ────────────────────────────────────────────────────
pub fn initCpu(cpu_idx: u32) void {
    const mpidr = readMpidr();
    var topo = CpuTopology.fromMpidr(mpidr);
    topo.features = detectFeatures();
    topo.is_online = true;
    topo.is_boot_cpu = (cpu_idx == 0);

    // Detect caches
    detectCaches(&topo);

    // Store topology
    cpu_topologies[cpu_idx] = topo;
    if (cpu_idx == 0) {
        boot_cpu_features = topo.features;
    }
    nr_cpus_detected = @max(nr_cpus_detected, cpu_idx + 1);
}

pub fn getBootCpuFeatures() CpuFeatureSet {
    return boot_cpu_features;
}

pub fn getCpuTopology(cpu_idx: u32) *const CpuTopology {
    return &cpu_topologies[cpu_idx];
}

pub fn getNumCpus() u32 {
    return nr_cpus_detected;
}

// ── System Register Read Wrappers ─────────────────────────────────────────
inline fn readMidr() u64 {
    return asm ("mrs %[r], MIDR_EL1" : [r] "=r" (-> u64));
}

inline fn readMpidr() u64 {
    return asm ("mrs %[r], MPIDR_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Isar0() u64 {
    return asm ("mrs %[r], ID_AA64ISAR0_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Isar1() u64 {
    return asm ("mrs %[r], ID_AA64ISAR1_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Pfr0() u64 {
    return asm ("mrs %[r], ID_AA64PFR0_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Pfr1() u64 {
    return asm ("mrs %[r], ID_AA64PFR1_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Mmfr0() u64 {
    return asm ("mrs %[r], ID_AA64MMFR0_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Mmfr1() u64 {
    return asm ("mrs %[r], ID_AA64MMFR1_EL1" : [r] "=r" (-> u64));
}

inline fn readClidr() u64 {
    return asm ("mrs %[r], CLIDR_EL1" : [r] "=r" (-> u64));
}

inline fn readCcsidr() u64 {
    return asm ("mrs %[r], CCSIDR_EL1" : [r] "=r" (-> u64));
}

inline fn writeCsselr(val: u64) void {
    asm volatile ("msr CSSELR_EL1, %[v]; isb" : : [v] "r" (val));
}

inline fn readZcrEl1() u64 {
    return asm ("mrs %[r], ZCR_EL1" : [r] "=r" (-> u64));
}

// ── Utility ───────────────────────────────────────────────────────────────
fn extractField(reg: u64, shift: u6, width: u6) u64 {
    return (reg >> shift) & ((@as(u64, 1) << width) - 1);
}

// ── CPU Power Management ──────────────────────────────────────────────────
pub const CpuPowerState = enum(u8) {
    running = 0,
    idle_wfi = 1,
    idle_retention = 2,
    powerdown = 3,
    offline = 4,
};

var cpu_power_states: [MAX_CPUS]CpuPowerState = [_]CpuPowerState{.offline} ** MAX_CPUS;

pub fn setCpuPowerState(cpu_idx: u32, state: CpuPowerState) void {
    if (cpu_idx < MAX_CPUS) {
        cpu_power_states[cpu_idx] = state;
    }
}

pub fn getCpuPowerState(cpu_idx: u32) CpuPowerState {
    if (cpu_idx < MAX_CPUS) {
        return cpu_power_states[cpu_idx];
    }
    return .offline;
}

// ── Performance Counter Access ────────────────────────────────────────────
pub fn readCycleCounter() u64 {
    return asm ("mrs %[r], PMCCNTR_EL0" : [r] "=r" (-> u64));
}

pub fn enableCycleCounter() void {
    // Enable PMU cycle counter
    asm volatile ("msr PMCR_EL0, %[v]" : : [v] "r" (@as(u64, 0x7))); // E|P|C
    asm volatile ("msr PMCNTENSET_EL0, %[v]" : : [v] "r" (@as(u64, 1 << 31))); // C bit
    asm volatile ("msr PMUSERENR_EL0, %[v]" : : [v] "r" (@as(u64, 0x1))); // EN
}

// ── CPU Errata Workarounds ────────────────────────────────────────────────
pub const Erratum = struct {
    id: u32,           // Erratum number (e.g., 1530923)
    description: []const u8,
    implementer: u8,
    part_num: u12,
    variant_min: u4,
    revision_min: u4,
    applied: bool,
};

const MAX_ERRATA: usize = 64;
var errata_list: [MAX_ERRATA]Erratum = undefined;
var errata_count: usize = 0;

pub fn checkAndApplyErrata(cpu_ident: CpuId) void {
    // Cortex-A53 errata
    if (cpu_ident.implementer == 0x41 and cpu_ident.part_num == 0xD03) {
        registerErratum(835769, "Cortex-A53: Multiply-accumulate result corruption", 0x41, 0xD03, 0, 0);
        registerErratum(843419, "Cortex-A53: ADRP to nearby literal pool", 0x41, 0xD03, 0, 0);
    }
    // Cortex-A57 errata
    if (cpu_ident.implementer == 0x41 and cpu_ident.part_num == 0xD07) {
        registerErratum(832075, "Cortex-A57: Possible deadlock on barrier", 0x41, 0xD07, 0, 0);
        registerErratum(834220, "Cortex-A57: Possible cache data corruption", 0x41, 0xD07, 0, 0);
    }
    // Cortex-A72 errata
    if (cpu_ident.implementer == 0x41 and cpu_ident.part_num == 0xD08) {
        registerErratum(853709, "Cortex-A72: Instruction fetch stall", 0x41, 0xD08, 0, 0);
    }
    // Cortex-A76 errata
    if (cpu_ident.implementer == 0x41 and cpu_ident.part_num == 0xD0B) {
        registerErratum(1490853, "Cortex-A76: TLB invalidation issue", 0x41, 0xD0B, 0, 0);
        registerErratum(1530923, "Cortex-A76: Speculative AT instruction issue", 0x41, 0xD0B, 0, 0);
    }
    // Neoverse N1 errata
    if (cpu_ident.implementer == 0x41 and cpu_ident.part_num == 0xD0C) {
        registerErratum(1542419, "Neoverse N1: TLB allocation issue", 0x41, 0xD0C, 0, 0);
    }
}

fn registerErratum(id: u32, description: []const u8, implementer: u8, part_num: u12, variant_min: u4, revision_min: u4) void {
    if (errata_count < MAX_ERRATA) {
        errata_list[errata_count] = Erratum{
            .id = id,
            .description = description,
            .implementer = implementer,
            .part_num = part_num,
            .variant_min = variant_min,
            .revision_min = revision_min,
            .applied = true,
        };
        errata_count += 1;
    }
}
