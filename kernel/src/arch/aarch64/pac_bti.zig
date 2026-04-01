// =============================================================================
// Zxyphor Kernel — ARM64 Pointer Authentication & Branch Target ID
// =============================================================================
// Implements ARMv8.3 Pointer Authentication Code (PAC) and ARMv8.5 Branch
// Target Identification (BTI) kernel security features.
//
// Pointer Authentication:
//   - Uses cryptographic PAC to sign return addresses and data pointers
//   - Prevents ROP/JOP attacks by verifying PAC before use
//   - Five key pairs: APIAKey, APIBKey, APDAKey, APDBKey, APGAKey
//   - Per-process key management (keys change on context switch)
//   - Supports QARMA, IMPLEMENTATION DEFINED, and architected algorithms
//   - Used by kernel for: return address protection, stack frame integrity,
//     function pointer protection, and heap metadata integrity
//
// Branch Target Identification:
//   - Restricts indirect branch targets to BTI-marked instructions
//   - BTI C: valid target for indirect calls (BLR)
//   - BTI J: valid target for indirect jumps (BR)
//   - BTI JC: valid target for both
//   - Memory pages marked with GP (Guarded Page) flag in PTE
//   - Generates Branch Target Exception on violation
//
// MTE (Memory Tagging Extension, ARMv8.5):
//   - 4-bit tag per 16-byte granule in physical memory
//   - Pointer tags stored in top byte (bits 59:56 of VA)
//   - Synchronous/Asynchronous checking modes
//   - Detects use-after-free, buffer overflows, out-of-bounds access
// =============================================================================

// ── PAC Key Registers ─────────────────────────────────────────────────────
pub const PacKey = struct {
    lo: u64, // Key[63:0]
    hi: u64, // Key[127:64]

    pub fn generate(seed: u64) PacKey {
        // Simple key derivation (in production, use hardware RNG)
        // Mix seed with golden ratio and SipHash-like rotations
        var k = PacKey{
            .lo = seed ^ 0x517CC1B727220A95,
            .hi = seed ^ 0x6C62272E07BB0142,
        };
        // Mix rounds
        var i: u32 = 0;
        while (i < 8) : (i += 1) {
            k.lo = rotateLeft64(k.lo, 13) ^ k.hi ^ (k.lo << 3);
            k.hi = rotateLeft64(k.hi, 17) ^ k.lo;
            k.lo ^= @as(u64, i) * 0x9E3779B97F4A7C15;
        }
        return k;
    }

    pub fn isZero(self: PacKey) bool {
        return self.lo == 0 and self.hi == 0;
    }
};

pub const PacKeys = struct {
    apia: PacKey, // Instruction key A (return addresses)
    apib: PacKey, // Instruction key B (alt return addresses)
    apda: PacKey, // Data key A (data pointers)
    apdb: PacKey, // Data key B (alt data pointers)
    apga: PacKey, // Generic authentication key

    const Self = @This();

    pub fn init() Self {
        return Self{
            .apia = .{ .lo = 0, .hi = 0 },
            .apib = .{ .lo = 0, .hi = 0 },
            .apda = .{ .lo = 0, .hi = 0 },
            .apdb = .{ .lo = 0, .hi = 0 },
            .apga = .{ .lo = 0, .hi = 0 },
        };
    }

    pub fn generateAll(seed: u64) Self {
        return Self{
            .apia = PacKey.generate(seed ^ 0xAAAA_AAAA_AAAA_AAAA),
            .apib = PacKey.generate(seed ^ 0xBBBB_BBBB_BBBB_BBBB),
            .apda = PacKey.generate(seed ^ 0xDDDD_DDDD_DDDD_DDDD),
            .apdb = PacKey.generate(seed ^ 0xEEEE_EEEE_EEEE_EEEE),
            .apga = PacKey.generate(seed ^ 0xFFFF_FFFF_FFFF_FFFF),
        };
    }
};

// ── PAC Feature Detection ─────────────────────────────────────────────────
pub const PacAlgorithm = enum {
    none,
    architected_qarma5,  // QARMA5 (standard)
    architected_qarma3,  // QARMA3 (faster, less security)
    impl_defined,        // Implementation-defined
    fpac,                // Enhanced with FPAC (faulting PAC)
    fpac_combined,       // FPAC with combined instructions
};

pub const PacCapability = struct {
    supported: bool,
    algorithm: PacAlgorithm,
    has_epac: bool,       // Enhanced PAC
    has_fpac: bool,       // Faulting PAC (generates exception on failure)
    has_fpac_combined: bool,
    has_pauth2: bool,     // PAuth2 (ARMv8.6)
    has_generic_auth: bool, // PACGA instruction

    const Self = @This();

    pub fn detect() Self {
        var cap = Self{
            .supported = false,
            .algorithm = .none,
            .has_epac = false,
            .has_fpac = false,
            .has_fpac_combined = false,
            .has_pauth2 = false,
            .has_generic_auth = false,
        };

        // Read ID_AA64ISAR1_EL1
        const isar1 = readIdAa64Isar1();
        const apa = (isar1 >> 4) & 0xF;   // Architected PAuth (addr key A)
        const api = (isar1 >> 8) & 0xF;   // Impl-defined PAuth
        const gpa = (isar1 >> 24) & 0xF;  // Generic PAuth (architected)
        const gpi = (isar1 >> 28) & 0xF;  // Generic PAuth (impl-defined)

        if (apa >= 1 or api >= 1) {
            cap.supported = true;
            if (apa >= 1) {
                cap.algorithm = .architected_qarma5;
                if (apa >= 2) cap.has_epac = true;
                if (apa >= 3) cap.has_pauth2 = true;
                if (apa >= 4) cap.has_fpac = true;
                if (apa >= 5) cap.has_fpac_combined = true;
            } else {
                cap.algorithm = .impl_defined;
            }
        }

        if (gpa >= 1 or gpi >= 1) {
            cap.has_generic_auth = true;
        }

        // Read ID_AA64ISAR2_EL1 for QARMA3 detection
        const isar2 = readIdAa64Isar2();
        const apa3 = (isar2 >> 12) & 0xF;
        if (apa3 >= 1) {
            cap.algorithm = .architected_qarma3;
        }

        return cap;
    }
};

var pac_capability: PacCapability = undefined;
var pac_initialized: bool = false;

// ── PAC Key Management ────────────────────────────────────────────────────
pub fn installKeys(keys: *const PacKeys) void {
    // Install all 5 key pairs into system registers
    writeApiaKey(keys.apia);
    writeApibKey(keys.apib);
    writeApdaKey(keys.apda);
    writeApdbKey(keys.apdb);
    writeApgaKey(keys.apga);
}

pub fn readCurrentKeys() PacKeys {
    return PacKeys{
        .apia = readApiaKey(),
        .apib = readApibKey(),
        .apda = readApdaKey(),
        .apdb = readApdbKey(),
        .apga = readApgaKey(),
    };
}

fn writeApiaKey(key: PacKey) void {
    asm volatile ("msr APIAKeyLo_EL1, %[lo]; msr APIAKeyHi_EL1, %[hi]"
        : : [lo] "r" (key.lo), [hi] "r" (key.hi));
}

fn writeApibKey(key: PacKey) void {
    asm volatile ("msr APIBKeyLo_EL1, %[lo]; msr APIBKeyHi_EL1, %[hi]"
        : : [lo] "r" (key.lo), [hi] "r" (key.hi));
}

fn writeApdaKey(key: PacKey) void {
    asm volatile ("msr APDAKeyLo_EL1, %[lo]; msr APDAKeyHi_EL1, %[hi]"
        : : [lo] "r" (key.lo), [hi] "r" (key.hi));
}

fn writeApdbKey(key: PacKey) void {
    asm volatile ("msr APDBKeyLo_EL1, %[lo]; msr APDBKeyHi_EL1, %[hi]"
        : : [lo] "r" (key.lo), [hi] "r" (key.hi));
}

fn writeApgaKey(key: PacKey) void {
    asm volatile ("msr APGAKeyLo_EL1, %[lo]; msr APGAKeyHi_EL1, %[hi]"
        : : [lo] "r" (key.lo), [hi] "r" (key.hi));
}

fn readApiaKey() PacKey {
    return .{
        .lo = asm ("mrs %[r], APIAKeyLo_EL1" : [r] "=r" (-> u64)),
        .hi = asm ("mrs %[r], APIAKeyHi_EL1" : [r] "=r" (-> u64)),
    };
}

fn readApibKey() PacKey {
    return .{
        .lo = asm ("mrs %[r], APIBKeyLo_EL1" : [r] "=r" (-> u64)),
        .hi = asm ("mrs %[r], APIBKeyHi_EL1" : [r] "=r" (-> u64)),
    };
}

fn readApdaKey() PacKey {
    return .{
        .lo = asm ("mrs %[r], APDAKeyLo_EL1" : [r] "=r" (-> u64)),
        .hi = asm ("mrs %[r], APDAKeyHi_EL1" : [r] "=r" (-> u64)),
    };
}

fn readApdbKey() PacKey {
    return .{
        .lo = asm ("mrs %[r], APDBKeyLo_EL1" : [r] "=r" (-> u64)),
        .hi = asm ("mrs %[r], APDBKeyHi_EL1" : [r] "=r" (-> u64)),
    };
}

fn readApgaKey() PacKey {
    return .{
        .lo = asm ("mrs %[r], APGAKeyLo_EL1" : [r] "=r" (-> u64)),
        .hi = asm ("mrs %[r], APGAKeyHi_EL1" : [r] "=r" (-> u64)),
    };
}

// ── BTI (Branch Target Identification) ────────────────────────────────────
pub const BtiMode = enum(u2) {
    none = 0b00,    // BTI disabled
    call = 0b01,    // BTI C only: indirect calls (BLR)
    jump = 0b10,    // BTI J only: indirect jumps (BR)
    call_jump = 0b11, // BTI JC: both calls and jumps
};

pub const BtiCapability = struct {
    supported: bool,

    pub fn detect() BtiCapability {
        const pfr1 = readIdAa64Pfr1();
        const bt = (pfr1 >> 0) & 0xF;
        return .{ .supported = bt >= 1 };
    }
};

var bti_capability: BtiCapability = undefined;

pub fn enableBtiForEl1() void {
    // Set SCTLR_EL1.BT1 = 1 (enable BTI for EL1)
    var sctlr = readSctlrEl1();
    sctlr |= (1 << 36); // BT1
    writeSctlrEl1(sctlr);
}

pub fn enableBtiForEl0() void {
    // Set SCTLR_EL1.BT0 = 1 (enable BTI for EL0)
    var sctlr = readSctlrEl1();
    sctlr |= (1 << 35); // BT0
    writeSctlrEl1(sctlr);
}

// ── MTE (Memory Tagging Extension) ───────────────────────────────────────
pub const MteCapability = struct {
    supported: bool,
    version: u8,       // 0: none, 1: MTE, 2: MTE2 (async), 3: MTE3
    has_async: bool,    // Asynchronous tag checking
    has_canonical: bool, // Canonical tag checking

    pub fn detect() MteCapability {
        const pfr1 = readIdAa64Pfr1();
        const mte = (pfr1 >> 8) & 0xF;
        return .{
            .supported = mte >= 1,
            .version = @truncate(mte),
            .has_async = mte >= 2,
            .has_canonical = mte >= 3,
        };
    }
};

var mte_capability: MteCapability = undefined;

pub const MteMode = enum(u2) {
    disabled = 0b00,     // No tag checking
    sync = 0b01,         // Synchronous (precise exception)
    async_mode = 0b10,   // Asynchronous (deferred, batched)
    asymm = 0b11,        // Asymmetric (sync read, async write)
};

pub fn setMteMode(mode: MteMode) void {
    // Set TCO (Tag Check Override) and SCTLR_EL1.TCF bits
    var sctlr = readSctlrEl1();
    sctlr &= ~(@as(u64, 0b11) << 40); // Clear TCF1 (EL1)
    sctlr &= ~(@as(u64, 0b11) << 38); // Clear TCF0 (EL0)
    sctlr |= @as(u64, @intFromEnum(mode)) << 40; // TCF1
    sctlr |= @as(u64, @intFromEnum(mode)) << 38; // TCF0
    writeSctlrEl1(sctlr);
}

/// Tag a memory range (set allocation tag)
pub fn tagMemory(addr: u64, size: usize, tag: u4) void {
    var ptr: u64 = addr & ~@as(u64, 0xF); // Align to 16-byte granule
    const end = addr + size;
    const tagged_addr = (ptr & ~(@as(u64, 0xF) << 56)) | (@as(u64, tag) << 56);
    _ = tagged_addr;

    while (ptr < end) : (ptr += 16) {
        // STG (Store Allocation Tag): set tag for granule at ptr
        asm volatile ("stg %[tag], [%[addr]]"
            :
            : [tag] "r" (@as(u64, tag) << 56 | ptr),
              [addr] "r" (ptr)
            : "memory"
        );
    }
}

/// Read tag from a memory address
pub fn readTag(addr: u64) u4 {
    const result = asm ("ldg %[r], [%[addr]]"
        : [r] "=r" (-> u64)
        : [addr] "r" (addr)
    );
    return @truncate((result >> 56) & 0xF);
}

/// Generate random tag (using hardware RNDR or IRG instruction)
pub fn randomTag() u4 {
    // IRG: Insert Random Tag
    const result = asm ("irg %[r], %[src]"
        : [r] "=r" (-> u64)
        : [src] "r" (@as(u64, 0))
    );
    return @truncate((result >> 56) & 0xF);
}

// ── Initialization ────────────────────────────────────────────────────────
pub fn init(entropy: u64) void {
    // Detect capabilities
    pac_capability = PacCapability.detect();
    bti_capability = BtiCapability.detect();
    mte_capability = MteCapability.detect();

    // Initialize PAC
    if (pac_capability.supported) {
        // Generate and install kernel PAC keys
        const kernel_keys = PacKeys.generateAll(entropy);
        installKeys(&kernel_keys);

        // Enable PAC in SCTLR_EL1
        var sctlr = readSctlrEl1();
        sctlr |= (1 << 31); // EnIA: Enable Pointer Auth (instruction key A)
        sctlr |= (1 << 27); // EnDA: Enable Pointer Auth (data key A)
        sctlr |= (1 << 30); // EnIB: Enable Pointer Auth (instruction key B)
        sctlr |= (1 << 13); // EnDB: Enable Pointer Auth (data key B)
        writeSctlrEl1(sctlr);
    }

    // Initialize BTI
    if (bti_capability.supported) {
        enableBtiForEl1();
        enableBtiForEl0();
    }

    // Initialize MTE
    if (mte_capability.supported) {
        // Enable MTE in synchronous mode for kernel
        setMteMode(.sync);

        // Set GCR_EL1: Tag inclusion mask (allow all tags 0-15)
        const gcr: u64 = 0xFFFF; // All tags included
        asm volatile ("msr GCR_EL1, %[v]; isb" : : [v] "r" (gcr));

        // Set RGSR_EL1: Random seed for hardware tag generation
        asm volatile ("msr RGSR_EL1, %[v]; isb" : : [v] "r" (entropy));
    }

    pac_initialized = true;
}

/// Context switch PAC keys for a new process
pub fn switchKeys(new_keys: *const PacKeys) void {
    if (!pac_capability.supported) return;
    installKeys(new_keys);
}

// ── System Register Wrappers ──────────────────────────────────────────────
inline fn readIdAa64Isar1() u64 {
    return asm ("mrs %[r], ID_AA64ISAR1_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Isar2() u64 {
    return asm ("mrs %[r], ID_AA64ISAR2_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Pfr1() u64 {
    return asm ("mrs %[r], ID_AA64PFR1_EL1" : [r] "=r" (-> u64));
}

inline fn readSctlrEl1() u64 {
    return asm ("mrs %[r], SCTLR_EL1" : [r] "=r" (-> u64));
}

inline fn writeSctlrEl1(val: u64) void {
    asm volatile ("msr SCTLR_EL1, %[v]; isb" : : [v] "r" (val));
}

// ── Utility ───────────────────────────────────────────────────────────────
fn rotateLeft64(x: u64, r: u6) u64 {
    return (x << r) | (x >> @as(u6, @truncate(64 - @as(u7, r))));
}

// ── Public Queries ────────────────────────────────────────────────────────
pub fn isPacSupported() bool { return pac_capability.supported; }
pub fn isBtiSupported() bool { return bti_capability.supported; }
pub fn isMteSupported() bool { return mte_capability.supported; }
pub fn getPacAlgorithm() PacAlgorithm { return pac_capability.algorithm; }
pub fn getMteVersion() u8 { return mte_capability.version; }
pub fn isInitialized() bool { return pac_initialized; }
