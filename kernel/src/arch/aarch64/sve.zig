// =============================================================================
// Zxyphor Kernel — ARM64 SVE (Scalable Vector Extension) Support
// =============================================================================
// Full SVE/SVE2 context management for ARM v8.2+ processors. SVE provides
// scalable SIMD vectors from 128 to 2048 bits in multiples of 128 bits.
// The kernel must save/restore SVE state on context switches and handle
// lazy SVE context switching for power efficiency.
//
// SVE Register File (per CPU):
//   - Z0-Z31: 32 scalable vector registers (VL bits each)
//   - P0-P15: 16 predicate registers (VL/8 bits each)
//   - FFR:    First Fault Register (VL/8 bits)
//   - ZCR_EL1: SVE Control Register (vector length config)
//   - FPCR/FPSR: Floating-point control/status (shared with NEON)
//
// SVE2 Extensions:
//   - Bitwise permutation, complex integer arithmetic
//   - Cryptography (AES, SHA3, SM4 acceleration)
//   - Histogram/gather  
//   - BFloat16 (BF16) matrix operations
//
// Lazy SVE Strategy:
//   - SVE starts disabled for new threads (trap on first use)
//   - First SVE instruction triggers trap → allocate SVE state and enable
//   - On context switch: save only if thread used SVE since last switch
//   - "SVE last user" per-CPU tracking avoids unnecessary save/restore
// =============================================================================

// ── SVE Constants ─────────────────────────────────────────────────────────
pub const SVE_VQ_MIN: u32 = 1;        // Minimum vector quads (128 bits)
pub const SVE_VQ_MAX: u32 = 16;       // Maximum vector quads (2048 bits)
pub const SVE_VL_MIN: u32 = 128;      // Minimum VL in bits
pub const SVE_VL_MAX: u32 = 2048;     // Maximum VL in bits
pub const SVE_NUM_ZREGS: u32 = 32;    // Z0-Z31
pub const SVE_NUM_PREGS: u32 = 16;    // P0-P15
pub const SVE_NUM_FFR: u32 = 1;       // FFR

// Maximum SVE state size in bytes for the largest possible VL (2048-bit)
pub const SVE_ZREG_MAX_SIZE: usize = SVE_VL_MAX / 8;           // 256 bytes per Z register
pub const SVE_PREG_MAX_SIZE: usize = SVE_VL_MAX / 64;          // 32 bytes per P register
pub const SVE_STATE_MAX_SIZE: usize = (SVE_NUM_ZREGS * SVE_ZREG_MAX_SIZE) +  // Z regs
                                       (SVE_NUM_PREGS * SVE_PREG_MAX_SIZE) +  // P regs
                                       SVE_PREG_MAX_SIZE +                     // FFR
                                       16;                                      // FPCR/FPSR

// ── ZCR_EL1 (SVE Control Register) ───────────────────────────────────────
pub const ZCR = struct {
    pub const LEN_MASK: u64 = 0xF;     // Bits 3:0: Vector length (VQ - 1)
    // The effective VL is min(ZCR_EL1.LEN, ZCR_EL2.LEN, hardware max) + 1
    // VL in bits = (LEN + 1) * 128
};

// ── CPACR_EL1 SVE/FP Control ─────────────────────────────────────────────
pub const CPACR = struct {
    pub const FPEN_SHIFT: u5 = 20;
    pub const FPEN_TRAP_ALL: u64 = 0b00 << FPEN_SHIFT;  // Trap FP/SIMD at EL0 & EL1
    pub const FPEN_TRAP_EL0: u64 = 0b01 << FPEN_SHIFT;  // Trap FP/SIMD at EL0 only
    pub const FPEN_NO_TRAP: u64 = 0b11 << FPEN_SHIFT;   // No trap

    pub const ZEN_SHIFT: u5 = 16;
    pub const ZEN_TRAP_ALL: u64 = 0b00 << ZEN_SHIFT;    // Trap SVE at EL0 & EL1
    pub const ZEN_TRAP_EL0: u64 = 0b01 << ZEN_SHIFT;    // Trap SVE at EL0 only
    pub const ZEN_NO_TRAP: u64 = 0b11 << ZEN_SHIFT;     // No trap
};

// ── SVE State Buffer ──────────────────────────────────────────────────────
pub const SveState = struct {
    // Z registers (32 × max 256 bytes each)
    z_regs: [SVE_NUM_ZREGS][SVE_ZREG_MAX_SIZE]u8 align(64),
    // P registers (16 × max 32 bytes each)
    p_regs: [SVE_NUM_PREGS][SVE_PREG_MAX_SIZE]u8 align(16),
    // First Fault Register (max 32 bytes)
    ffr: [SVE_PREG_MAX_SIZE]u8 align(16),
    // FPSR and FPCR
    fpsr: u32,
    fpcr: u32,
    // The actual vector length for this saved state
    vl: u32,
    // Flags
    valid: bool,
    sve_used: bool,    // Has thread used SVE since last context switch?
    sve2_used: bool,   // Has thread used SVE2 instructions?

    const Self = @This();

    pub fn init() Self {
        var state: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&state))[0..@sizeOf(Self)], 0);
        state.vl = 0;
        state.valid = false;
        state.sve_used = false;
        state.sve2_used = false;
        return state;
    }

    pub fn getVq(self: *const Self) u32 {
        return self.vl / 128;
    }

    pub fn getZregSize(self: *const Self) usize {
        return self.vl / 8;
    }

    pub fn getPregSize(self: *const Self) usize {
        return self.vl / 64;
    }

    pub fn totalSize(self: *const Self) usize {
        const zreg_sz = self.getZregSize();
        const preg_sz = self.getPregSize();
        return (SVE_NUM_ZREGS * zreg_sz) + (SVE_NUM_PREGS * preg_sz) + preg_sz + 8;
    }
};

// ── Per-CPU SVE Tracking ──────────────────────────────────────────────────
const MAX_CPUS: usize = 256;

const PerCpuSveInfo = struct {
    last_user_tid: u64,      // Thread ID that last used SVE
    hw_vl: u32,              // Hardware-supported VL (bits)
    hw_vl_max: u32,          // Maximum hardware VL
    sve2_supported: bool,
    sme_supported: bool,
};

var per_cpu_sve: [MAX_CPUS]PerCpuSveInfo = undefined;
var sve_supported: bool = false;
var sve2_supported: bool = false;
var sme_supported: bool = false;
var max_hw_vl: u32 = 0;

// ── SVE Detection and Initialization ──────────────────────────────────────
pub fn detectSve() bool {
    // Check ID_AA64PFR0_EL1.SVE (bits 35:32)
    const pfr0 = readIdAa64Pfr0();
    const sve_field = (pfr0 >> 32) & 0xF;

    if (sve_field == 0) {
        sve_supported = false;
        return false;
    }

    sve_supported = true;

    // Check for SVE2 via ID_AA64ZFR0_EL1
    if (sve_field >= 1) {
        const zfr0 = readIdAa64Zfr0();
        if ((zfr0 & 0xF) >= 1) {
            sve2_supported = true;
        }
    }

    // Check for SME via ID_AA64PFR1_EL1
    const pfr1 = readIdAa64Pfr1();
    if (((pfr1 >> 24) & 0xF) >= 1) {
        sme_supported = true;
    }

    // Probe maximum hardware vector length
    max_hw_vl = probeMaxVl();

    return true;
}

pub fn initCpu(cpu_idx: u32) void {
    if (!sve_supported) return;

    // Probe this CPU's SVE capabilities
    var info = &per_cpu_sve[cpu_idx];
    info.hw_vl = probeMaxVl();
    info.hw_vl_max = info.hw_vl;
    info.last_user_tid = 0;
    info.sve2_supported = sve2_supported;
    info.sme_supported = sme_supported;

    // Start with SVE trapping enabled (lazy context switch)
    disableSveForEl0();
    disableSveForEl1();
}

fn probeMaxVl() u32 {
    // Save current ZCR
    const old_zcr = readZcrEl1();

    // Set maximum VL
    writeZcrEl1(ZCR.LEN_MASK); // Request maximum

    // Enable SVE temporarily
    enableSveForEl1();

    // Read back actual VL using RDVL instruction
    // RDVL returns the vector length in bytes
    const vl_bytes = asm (
        \\rdvl x0, #1
        \\mov %[r], x0
        : [r] "=r" (-> u64)
        :
        : "x0"
    );

    // Restore
    writeZcrEl1(old_zcr);

    return @truncate(vl_bytes * 8); // Convert bytes to bits
}

// ── SVE State Save/Restore ────────────────────────────────────────────────
pub fn saveState(state: *SveState) void {
    if (!sve_supported) return;

    // Record current VL
    state.vl = getCurrentVl();
    state.valid = true;

    // Save FPSR/FPCR
    state.fpsr = readFpsr();
    state.fpcr = readFpcr();

    // Save Z registers using SVE store instructions
    // For each Z register, use STR (SVE, vector) to save to memory
    const zreg_sz = state.getZregSize();
    _ = zreg_sz;

    // This would use inline assembly with SVE STR instructions
    // STR z0, [x0]; STR z1, [x0, #1, MUL VL]; etc.
    // Simplified: save using STR (scalar) loops
    saveSveRegisters(state);

    state.sve_used = true;
}

pub fn restoreState(state: *const SveState) void {
    if (!sve_supported or !state.valid) return;

    // Set VL to match saved state
    setCurrentVl(state.vl);

    // Restore FPSR/FPCR
    writeFpsr(state.fpsr);
    writeFpcr(state.fpcr);

    // Restore Z/P/FFR registers
    restoreSveRegisters(state);
}

fn saveSveRegisters(state: *SveState) void {
    // In a real implementation, this uses SVE-specific instructions:
    //   STR z0, [base]; STR z1, [base, #1, MUL VL]; ...
    //   STR p0, [base]; STR p1, [base, #1, MUL VL]; ...
    //   RDFFR p0.B; STR p0, [ffr_base]
    //
    // Using SVE store multiple via inline assembly:
    const z_base = @intFromPtr(&state.z_regs);
    const p_base = @intFromPtr(&state.p_regs);
    const ffr_base = @intFromPtr(&state.ffr);

    asm volatile (
        \\str z0, [%[zb], #0, MUL VL]
        \\str z1, [%[zb], #1, MUL VL]
        \\str z2, [%[zb], #2, MUL VL]
        \\str z3, [%[zb], #3, MUL VL]
        \\str z4, [%[zb], #4, MUL VL]
        \\str z5, [%[zb], #5, MUL VL]
        \\str z6, [%[zb], #6, MUL VL]
        \\str z7, [%[zb], #7, MUL VL]
        \\str z8, [%[zb], #8, MUL VL]
        \\str z9, [%[zb], #9, MUL VL]
        \\str z10, [%[zb], #10, MUL VL]
        \\str z11, [%[zb], #11, MUL VL]
        \\str z12, [%[zb], #12, MUL VL]
        \\str z13, [%[zb], #13, MUL VL]
        \\str z14, [%[zb], #14, MUL VL]
        \\str z15, [%[zb], #15, MUL VL]
        \\str z16, [%[zb], #16, MUL VL]
        \\str z17, [%[zb], #17, MUL VL]
        \\str z18, [%[zb], #18, MUL VL]
        \\str z19, [%[zb], #19, MUL VL]
        \\str z20, [%[zb], #20, MUL VL]
        \\str z21, [%[zb], #21, MUL VL]
        \\str z22, [%[zb], #22, MUL VL]
        \\str z23, [%[zb], #23, MUL VL]
        \\str z24, [%[zb], #24, MUL VL]
        \\str z25, [%[zb], #25, MUL VL]
        \\str z26, [%[zb], #26, MUL VL]
        \\str z27, [%[zb], #27, MUL VL]
        \\str z28, [%[zb], #28, MUL VL]
        \\str z29, [%[zb], #29, MUL VL]
        \\str z30, [%[zb], #30, MUL VL]
        \\str z31, [%[zb], #31, MUL VL]
        \\str p0, [%[pb], #0, MUL VL]
        \\str p1, [%[pb], #1, MUL VL]
        \\str p2, [%[pb], #2, MUL VL]
        \\str p3, [%[pb], #3, MUL VL]
        \\str p4, [%[pb], #4, MUL VL]
        \\str p5, [%[pb], #5, MUL VL]
        \\str p6, [%[pb], #6, MUL VL]
        \\str p7, [%[pb], #7, MUL VL]
        \\str p8, [%[pb], #8, MUL VL]
        \\str p9, [%[pb], #9, MUL VL]
        \\str p10, [%[pb], #10, MUL VL]
        \\str p11, [%[pb], #11, MUL VL]
        \\str p12, [%[pb], #12, MUL VL]
        \\str p13, [%[pb], #13, MUL VL]
        \\str p14, [%[pb], #14, MUL VL]
        \\str p15, [%[pb], #15, MUL VL]
        \\rdffr p0.b
        \\str p0, [%[fb]]
        :
        : [zb] "r" (z_base),
          [pb] "r" (p_base),
          [fb] "r" (ffr_base)
        : "memory"
    );
}

fn restoreSveRegisters(state: *const SveState) void {
    const z_base = @intFromPtr(&state.z_regs);
    const p_base = @intFromPtr(&state.p_regs);
    const ffr_base = @intFromPtr(&state.ffr);

    asm volatile (
        \\ldr p0, [%[fb]]
        \\wrffr p0.b
        \\ldr p0, [%[pb], #0, MUL VL]
        \\ldr p1, [%[pb], #1, MUL VL]
        \\ldr p2, [%[pb], #2, MUL VL]
        \\ldr p3, [%[pb], #3, MUL VL]
        \\ldr p4, [%[pb], #4, MUL VL]
        \\ldr p5, [%[pb], #5, MUL VL]
        \\ldr p6, [%[pb], #6, MUL VL]
        \\ldr p7, [%[pb], #7, MUL VL]
        \\ldr p8, [%[pb], #8, MUL VL]
        \\ldr p9, [%[pb], #9, MUL VL]
        \\ldr p10, [%[pb], #10, MUL VL]
        \\ldr p11, [%[pb], #11, MUL VL]
        \\ldr p12, [%[pb], #12, MUL VL]
        \\ldr p13, [%[pb], #13, MUL VL]
        \\ldr p14, [%[pb], #14, MUL VL]
        \\ldr p15, [%[pb], #15, MUL VL]
        \\ldr z0, [%[zb], #0, MUL VL]
        \\ldr z1, [%[zb], #1, MUL VL]
        \\ldr z2, [%[zb], #2, MUL VL]
        \\ldr z3, [%[zb], #3, MUL VL]
        \\ldr z4, [%[zb], #4, MUL VL]
        \\ldr z5, [%[zb], #5, MUL VL]
        \\ldr z6, [%[zb], #6, MUL VL]
        \\ldr z7, [%[zb], #7, MUL VL]
        \\ldr z8, [%[zb], #8, MUL VL]
        \\ldr z9, [%[zb], #9, MUL VL]
        \\ldr z10, [%[zb], #10, MUL VL]
        \\ldr z11, [%[zb], #11, MUL VL]
        \\ldr z12, [%[zb], #12, MUL VL]
        \\ldr z13, [%[zb], #13, MUL VL]
        \\ldr z14, [%[zb], #14, MUL VL]
        \\ldr z15, [%[zb], #15, MUL VL]
        \\ldr z16, [%[zb], #16, MUL VL]
        \\ldr z17, [%[zb], #17, MUL VL]
        \\ldr z18, [%[zb], #18, MUL VL]
        \\ldr z19, [%[zb], #19, MUL VL]
        \\ldr z20, [%[zb], #20, MUL VL]
        \\ldr z21, [%[zb], #21, MUL VL]
        \\ldr z22, [%[zb], #22, MUL VL]
        \\ldr z23, [%[zb], #23, MUL VL]
        \\ldr z24, [%[zb], #24, MUL VL]
        \\ldr z25, [%[zb], #25, MUL VL]
        \\ldr z26, [%[zb], #26, MUL VL]
        \\ldr z27, [%[zb], #27, MUL VL]
        \\ldr z28, [%[zb], #28, MUL VL]
        \\ldr z29, [%[zb], #29, MUL VL]
        \\ldr z30, [%[zb], #30, MUL VL]
        \\ldr z31, [%[zb], #31, MUL VL]
        :
        : [zb] "r" (z_base),
          [pb] "r" (p_base),
          [fb] "r" (ffr_base)
        : "memory"
    );
}

// ── SVE Control ───────────────────────────────────────────────────────────
pub fn enableSveForEl1() void {
    var cpacr = readCpacrEl1();
    cpacr |= CPACR.ZEN_NO_TRAP;
    cpacr |= CPACR.FPEN_NO_TRAP;
    writeCpacrEl1(cpacr);
}

pub fn enableSveForEl0() void {
    var cpacr = readCpacrEl1();
    cpacr &= ~@as(u64, 0b11 << CPACR.ZEN_SHIFT);
    cpacr |= CPACR.ZEN_NO_TRAP;
    writeCpacrEl1(cpacr);
}

pub fn disableSveForEl0() void {
    var cpacr = readCpacrEl1();
    cpacr &= ~@as(u64, 0b11 << CPACR.ZEN_SHIFT);
    cpacr |= CPACR.ZEN_TRAP_EL0;
    writeCpacrEl1(cpacr);
}

pub fn disableSveForEl1() void {
    var cpacr = readCpacrEl1();
    cpacr &= ~@as(u64, 0b11 << CPACR.ZEN_SHIFT);
    cpacr |= CPACR.ZEN_TRAP_ALL;
    writeCpacrEl1(cpacr);
}

pub fn setVl(vl_bits: u32) void {
    if (vl_bits < SVE_VL_MIN or vl_bits > max_hw_vl) return;
    const vq = vl_bits / 128;
    writeZcrEl1((readZcrEl1() & ~ZCR.LEN_MASK) | @as(u64, vq - 1));
}

pub fn getCurrentVl() u32 {
    const zcr = readZcrEl1();
    return @truncate(((zcr & ZCR.LEN_MASK) + 1) * 128);
}

pub fn getMaxVl() u32 {
    return max_hw_vl;
}

pub fn isSveSupported() bool {
    return sve_supported;
}

pub fn isSve2Supported() bool {
    return sve2_supported;
}

pub fn isSmeSupported() bool {
    return sme_supported;
}

// ── Lazy SVE Context Switch ───────────────────────────────────────────────
pub fn contextSwitchLazy(cpu_idx: u32, old_tid: u64, new_tid: u64, old_state: ?*SveState, new_state: ?*const SveState) void {
    if (!sve_supported) return;

    var info = &per_cpu_sve[cpu_idx];

    // Save old thread's SVE state if it was the last SVE user
    if (info.last_user_tid == old_tid and old_state != null) {
        if (old_state.?.sve_used) {
            saveState(old_state.?);
        }
    }

    // Check if new thread has SVE state to restore
    if (new_state != null and new_state.?.valid) {
        enableSveForEl1();
        enableSveForEl0();
        restoreState(new_state.?);
        info.last_user_tid = new_tid;
    } else {
        // Disable SVE — will trap on first use
        disableSveForEl0();
        info.last_user_tid = 0;
    }
}

// ── System Register Wrappers ──────────────────────────────────────────────
inline fn readZcrEl1() u64 {
    return asm ("mrs %[r], ZCR_EL1" : [r] "=r" (-> u64));
}

inline fn writeZcrEl1(val: u64) void {
    asm volatile ("msr ZCR_EL1, %[v]; isb" : : [v] "r" (val));
}

inline fn readCpacrEl1() u64 {
    return asm ("mrs %[r], CPACR_EL1" : [r] "=r" (-> u64));
}

inline fn writeCpacrEl1(val: u64) void {
    asm volatile ("msr CPACR_EL1, %[v]; isb" : : [v] "r" (val));
}

inline fn readFpsr() u32 {
    return @truncate(asm ("mrs %[r], FPSR" : [r] "=r" (-> u64)));
}

inline fn writeFpsr(val: u32) void {
    asm volatile ("msr FPSR, %[v]" : : [v] "r" (@as(u64, val)));
}

inline fn readFpcr() u32 {
    return @truncate(asm ("mrs %[r], FPCR" : [r] "=r" (-> u64)));
}

inline fn writeFpcr(val: u32) void {
    asm volatile ("msr FPCR, %[v]" : : [v] "r" (@as(u64, val)));
}

inline fn readIdAa64Pfr0() u64 {
    return asm ("mrs %[r], ID_AA64PFR0_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Pfr1() u64 {
    return asm ("mrs %[r], ID_AA64PFR1_EL1" : [r] "=r" (-> u64));
}

inline fn readIdAa64Zfr0() u64 {
    return asm ("mrs %[r], ID_AA64ZFR0_EL1" : [r] "=r" (-> u64));
}
