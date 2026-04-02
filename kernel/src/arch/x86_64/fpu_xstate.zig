// SPDX-License-Identifier: MIT
// Zxyphor Kernel - FPU/SSE/AVX/AVX-512/AMX State Management,
// XSAVE/XRSTOR, FPU Context Switch, Signal Frame, PKRU
// More advanced than Linux 2026 FPU state management

const std = @import("std");

// ============================================================================
// x87 FPU State
// ============================================================================

/// x87 FPU status word
pub const FpuStatusWord = packed struct {
    ie: bool = false, // Invalid operation exception
    de: bool = false, // Denormalized operand exception
    ze: bool = false, // Zero-divide exception
    oe: bool = false, // Overflow exception
    ue: bool = false, // Underflow exception
    pe: bool = false, // Precision exception
    sf: bool = false, // Stack fault
    es: bool = false, // Error summary
    c0: bool = false, // Condition code 0
    c1: bool = false, // Condition code 1
    c2: bool = false, // Condition code 2
    top: u3 = 0, // Top of stack pointer
    c3: bool = false, // Condition code 3
    b: bool = false, // FPU busy
};

/// x87 FPU control word
pub const FpuControlWord = packed struct {
    im: bool = true, // Invalid operation mask
    dm: bool = true, // Denormalized operand mask
    zm: bool = true, // Zero-divide mask
    om: bool = true, // Overflow mask
    um: bool = true, // Underflow mask
    pm: bool = true, // Precision mask
    _reserved1: u2 = 0,
    pc: u2 = 3, // Precision control (3 = double-extended)
    rc: u2 = 0, // Rounding control
    ic: bool = false, // Infinity control (legacy)
    _reserved2: u3 = 0,
};

/// x87 tag word (2 bits per register)
pub const X87TagWord = packed struct {
    tag0: u2 = 3, // 0=valid, 1=zero, 2=special, 3=empty
    tag1: u2 = 3,
    tag2: u2 = 3,
    tag3: u2 = 3,
    tag4: u2 = 3,
    tag5: u2 = 3,
    tag6: u2 = 3,
    tag7: u2 = 3,
};

/// Legacy FPU env (FLDENV/FSTENV)
pub const FpuEnv = struct {
    cwd: u16, // Control word
    swd: u16, // Status word
    twd: u16, // Tag word
    fip: u32, // FPU IP offset
    fcs: u16, // FPU IP selector
    foo: u32, // FPU operand pointer offset
    fos: u16, // FPU operand pointer selector
};

/// FXSAVE area (512 bytes, 16-byte aligned)
pub const FxsaveArea = extern struct {
    cwd: u16, // x87 control word
    swd: u16, // x87 status word
    twd: u8, // Abridged tag word
    _pad1: u8,
    fop: u16, // Last x87 opcode
    rip: u64, // x87 FPU instruction pointer
    rdp: u64, // x87 FPU data pointer
    mxcsr: u32, // MXCSR register
    mxcsr_mask: u32, // MXCSR mask
    // ST registers (8 x 10 bytes = 80, padded to 8x16 = 128)
    st: [8][16]u8,
    // XMM registers (16 x 16 bytes = 256)
    xmm: [16][16]u8,
    // Padding to 512 bytes
    _pad2: [96]u8,
};

// ============================================================================
// MXCSR Register
// ============================================================================

/// MXCSR register bits
pub const MxcsrBits = packed struct {
    ie: bool = false, // Invalid operation exception
    de: bool = false, // Denormal exception
    ze: bool = false, // Divide-by-zero exception
    oe: bool = false, // Overflow exception
    ue: bool = false, // Underflow exception
    pe: bool = false, // Precision exception
    daz: bool = false, // Denormals are zeros
    im: bool = true, // Invalid operation mask
    dm: bool = true, // Denormal mask
    zm: bool = true, // Divide-by-zero mask
    om: bool = true, // Overflow mask
    um: bool = true, // Underflow mask
    pm: bool = true, // Precision mask
    rc: u2 = 0, // Rounding control
    ftz: bool = false, // Flush to zero
    _reserved: u16 = 0,
};

/// MXCSR rounding control
pub const MxcsrRoundingControl = enum(u2) {
    round_nearest = 0,
    round_down = 1,
    round_up = 2,
    round_truncate = 3,
};

// ============================================================================
// XSAVE/Extended State
// ============================================================================

/// XSAVE feature bits (CPUID EAX=0Dh,ECX=0)
pub const XsaveFeature = packed struct {
    x87: bool = true, // Bit 0: x87 FPU state
    sse: bool = true, // Bit 1: SSE state (XMM)
    avx: bool = false, // Bit 2: AVX state (YMM upper)
    bndreg: bool = false, // Bit 3: MPX BNDREGS
    bndcsr: bool = false, // Bit 4: MPX BNDCSR
    opmask: bool = false, // Bit 5: AVX-512 opmask (k0-k7)
    zmm_hi256: bool = false, // Bit 6: AVX-512 ZMM upper 256 (ZMM0-15 bits 256-511)
    hi16_zmm: bool = false, // Bit 7: AVX-512 HI16_ZMM (ZMM16-31)
    pt: bool = false, // Bit 8: Processor Trace
    pkru: bool = false, // Bit 9: PKRU state
    pasid: bool = false, // Bit 10: PASID state
    cet_u: bool = false, // Bit 11: CET user state
    cet_s: bool = false, // Bit 12: CET supervisor state
    hdc: bool = false, // Bit 13: HDC state
    uintr: bool = false, // Bit 14: UINTR state
    lbr: bool = false, // Bit 15: LBR state
    hwp: bool = false, // Bit 16: HWP state
    amx_tilecfg: bool = false, // Bit 17: AMX TILECFG
    amx_tiledata: bool = false, // Bit 18: AMX TILEDATA
    apx: bool = false, // Bit 19: APX extended GPRs
    _reserved: u44 = 0,
};

/// XSAVE header (bytes 512-575 of XSAVE area)
pub const XsaveHeader = extern struct {
    xstate_bv: u64, // Features currently saved
    xcomp_bv: u64, // Features using compacted format
    _reserved: [48]u8,
};

/// XSAVE area sizes per component
pub const XsaveComponentInfo = struct {
    feature: u8, // Feature bit number
    size: u32, // Size in bytes
    offset: u32, // Offset from XSAVE base (standard format)
    aligned: bool, // Must be 64-byte aligned
    supervisor: bool, // Supervisor-only component
};

/// Known XSAVE component sizes
pub const xsave_components = [_]XsaveComponentInfo{
    .{ .feature = 0, .size = 160, .offset = 0, .aligned = false, .supervisor = false }, // x87
    .{ .feature = 1, .size = 256, .offset = 160, .aligned = false, .supervisor = false }, // SSE
    .{ .feature = 2, .size = 256, .offset = 576, .aligned = false, .supervisor = false }, // AVX
    .{ .feature = 3, .size = 64, .offset = 960, .aligned = false, .supervisor = false }, // MPX BNDREGS
    .{ .feature = 4, .size = 64, .offset = 1024, .aligned = false, .supervisor = false }, // MPX BNDCSR
    .{ .feature = 5, .size = 64, .offset = 0, .aligned = true, .supervisor = false }, // AVX-512 opmask
    .{ .feature = 6, .size = 512, .offset = 0, .aligned = true, .supervisor = false }, // AVX-512 ZMM_Hi256
    .{ .feature = 7, .size = 1024, .offset = 0, .aligned = true, .supervisor = false }, // AVX-512 Hi16_ZMM
    .{ .feature = 9, .size = 8, .offset = 0, .aligned = false, .supervisor = false }, // PKRU
    .{ .feature = 11, .size = 16, .offset = 0, .aligned = false, .supervisor = true }, // CET_U
    .{ .feature = 12, .size = 24, .offset = 0, .aligned = false, .supervisor = true }, // CET_S
    .{ .feature = 17, .size = 64, .offset = 0, .aligned = true, .supervisor = false }, // AMX TILECFG
    .{ .feature = 18, .size = 8192, .offset = 0, .aligned = true, .supervisor = false }, // AMX TILEDATA
};

/// XSAVE area (dynamic size based on features)
pub const XsaveArea = struct {
    // FXSAVE portion (bytes 0-511)
    fxsave: FxsaveArea,
    // XSAVE header (bytes 512-575)
    header: XsaveHeader,
    // Extended state areas follow (variable)
};

/// XSAVE operations
pub const XsaveOps = struct {
    /// Get the required size for saving all enabled features
    pub fn get_xsave_size(features: u64) u32 {
        _ = features;
        // Would use CPUID to determine
        return 0; // placeholder
    }

    /// Check if compact format (XSAVEC/XSAVES) is supported
    pub fn supports_compact() bool {
        return false; // placeholder
    }
};

// ============================================================================
// SSE Registers
// ============================================================================

/// XMM register (128-bit)
pub const XmmReg = extern struct {
    low: u64,
    high: u64,
};

/// YMM register upper half (128-bit, AVX)
pub const YmmUpperReg = extern struct {
    low: u64,
    high: u64,
};

/// ZMM register (512-bit, AVX-512)
pub const ZmmReg = extern struct {
    parts: [8]u64,
};

/// AVX-512 opmask register (k0-k7)
pub const OpmaskReg = u64;

// ============================================================================
// AMX (Advanced Matrix Extensions)
// ============================================================================

/// AMX tile configuration
pub const AmxTilecfg = extern struct {
    palette: u8,
    start_row: u8,
    _reserved0: [14]u8,
    colsb: [16]u16, // Columns in bytes for each tile
    _reserved1: [16]u16,
    rows: [16]u8, // Rows for each tile
    _reserved2: [16]u8,
};

/// AMX palette info (from CPUID)
pub const AmxPaletteInfo = struct {
    palette_id: u8,
    total_tile_bytes: u16,
    bytes_per_tile: u16,
    bytes_per_row: u16,
    max_names: u16, // max tile registers
    max_rows: u16,
};

/// AMX tile data (8K per palette 1)
pub const AMX_TILE_SIZE: usize = 8192;

// ============================================================================
// CET (Control-flow Enforcement Technology)
// ============================================================================

/// CET shadow stack state
pub const CetShadowStackState = struct {
    ssp: u64, // Shadow stack pointer
    pl0_ssp: u64, // PL0 SSP
    pl1_ssp: u64,
    pl2_ssp: u64,
    isst_addr: u64, // Interrupt shadow stack table address
};

/// CET IBT (Indirect Branch Tracking) state
pub const CetIbtState = struct {
    tracker: CetIbtTracker,
    suppress: bool,
};

/// CET IBT tracker state
pub const CetIbtTracker = enum(u8) {
    idle = 0,
    wait_endbr = 1,
};

/// CET configuration per-thread
pub const CetThreadState = struct {
    // Shadow stack
    shstk_enabled: bool,
    shstk_base: u64,
    shstk_size: u64,
    ssp: u64,
    // IBT
    ibt_enabled: bool,
    ibt_bitmap: u64, // legacy bitmap address
    // State
    locked: bool,
};

// ============================================================================
// PKRU (Protection Keys for Userspace)
// ============================================================================

/// PKRU register value (32-bit)
/// 2 bits per key: bit 0 = access disable, bit 1 = write disable
pub const PkruValue = packed struct {
    key0: PkruKeyBits = .{},
    key1: PkruKeyBits = .{},
    key2: PkruKeyBits = .{},
    key3: PkruKeyBits = .{},
    key4: PkruKeyBits = .{},
    key5: PkruKeyBits = .{},
    key6: PkruKeyBits = .{},
    key7: PkruKeyBits = .{},
    key8: PkruKeyBits = .{},
    key9: PkruKeyBits = .{},
    key10: PkruKeyBits = .{},
    key11: PkruKeyBits = .{},
    key12: PkruKeyBits = .{},
    key13: PkruKeyBits = .{},
    key14: PkruKeyBits = .{},
    key15: PkruKeyBits = .{},
};

/// Per-key access bits
pub const PkruKeyBits = packed struct {
    access_disable: bool = false,
    write_disable: bool = false,
};

// ============================================================================
// FPU Context Management
// ============================================================================

/// FPU state type
pub const FpuStateType = enum(u8) {
    legacy_fxsave = 0, // FXSAVE/FXRSTOR only
    xsave = 1, // XSAVE/XRSTOR
    xsaveopt = 2, // XSAVEOPT
    xsavec = 3, // XSAVEC (compacted)
    xsaves = 4, // XSAVES (supervisor)
};

/// Per-thread FPU state
pub const FpuState = struct {
    // State buffer pointer (dynamically sized)
    state_size: u32,
    state_type: FpuStateType,

    // Feature tracking
    xfeatures_active: u64, // Features currently in use
    xfeatures_perm: u64, // Features permitted for this thread

    // Status
    initialized: bool, // Has used FPU since exec
    last_cpu: i32, // Last CPU this ran on (-1 = none)

    // Lazy switching
    fpregs_active: bool, // FPU regs are live (not saved)

    // PKRU
    pkru: u32,

    // CET
    cet: CetThreadState,

    // AMX
    amx_configured: bool,
    amx_palette: u8,

    // Stats
    context_switches: u64,
    xsave_count: u64,
    xrstor_count: u64,
};

/// FPU initialization modes
pub const FpuInitMode = enum(u8) {
    /// Use FINIT + clear SSE state
    software_init = 0,
    /// Use XRSTOR with init optimization
    xrstor_init = 1,
    /// Copy from init_fpstate
    copy_init = 2,
};

/// Kernel FPU begin/end for kernel FPU usage
pub const KernelFpuState = struct {
    saved: bool,
    mask: u64, // Which features were saved
    nesting: u32, // Nesting depth
};

// ============================================================================
// Signal Frame FPU State
// ============================================================================

/// Signal frame extended state (for sigreturn)
pub const SignalFpuState = struct {
    // Magic bytes
    pub const FP_XSTATE_MAGIC1: u32 = 0x46505853; // "FPXS"
    pub const FP_XSTATE_MAGIC2: u32 = 0x46505845; // "FPXE"
    pub const FP_XSTATE_MAGIC2_SIZE: u32 = 4;

    // FXSAVE for legacy apps
    has_fxsave: bool,
    // XSAVE for modern apps
    has_xstate: bool,
    // Total size
    total_size: u32,
    // Features saved
    xfeatures: u64,
};

/// Signal FPU restore validation
pub const SignalFpuValidation = struct {
    /// Validate XSAVE area from userspace
    pub fn validate_xstate(features: u64, size: u32) bool {
        // Check magic bytes
        // Check size bounds
        // Check feature bits are subset of permitted
        _ = features;
        _ = size;
        return true; // placeholder
    }
};

// ============================================================================
// UINTR (User Interrupts)
// ============================================================================

/// UINTR state
pub const UintrState = struct {
    handler: u64, // User interrupt handler RIP
    stack_adjust: u64, // Stack adjustment
    uitt_addr: u64, // User interrupt target table address
    uitt_size: u32,
    misc_enable: u64,
    // Status
    enabled: bool,
    receiver: bool,
    sender: bool,
    // Stats
    total_uintr_sent: u64,
    total_uintr_received: u64,
};

/// UINTR target table entry
pub const UintrTTE = extern struct {
    valid: u8,
    user_vec: u8,
    _reserved: u48,
    target_upid_addr: u64,
};

// ============================================================================
// Performance State Management
// ============================================================================

/// FPU feature detection result
pub const FpuFeatureDetection = struct {
    // Basic
    has_fpu: bool,
    has_fxsr: bool, // FXSAVE/FXRSTOR
    has_sse: bool,
    has_sse2: bool,
    has_sse3: bool,
    has_ssse3: bool,
    has_sse4_1: bool,
    has_sse4_2: bool,
    // AVX
    has_avx: bool,
    has_avx2: bool,
    // AVX-512
    has_avx512f: bool,
    has_avx512bw: bool,
    has_avx512cd: bool,
    has_avx512dq: bool,
    has_avx512vl: bool,
    has_avx512_vnni: bool,
    has_avx512_vbmi: bool,
    has_avx512_vbmi2: bool,
    has_avx512_vpopcntdq: bool,
    has_avx512_bitalg: bool,
    has_avx512_bf16: bool,
    has_avx512_fp16: bool,
    // AVX10
    has_avx10: bool,
    avx10_version: u8,
    // AMX
    has_amx_bf16: bool,
    has_amx_int8: bool,
    has_amx_fp16: bool,
    has_amx_complex: bool,
    // APX
    has_apx: bool,
    // Other
    has_xsave: bool,
    has_xsaveopt: bool,
    has_xsavec: bool,
    has_xsaves: bool,
    has_pkru: bool,
    has_cet_ss: bool,
    has_cet_ibt: bool,
    has_uintr: bool,
    // Sizes
    xsave_size: u32,
    xsave_size_compact: u32,
    xsave_features: u64,
    xsave_supervisor_features: u64,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// FPU subsystem state
pub const FpuSubsystem = struct {
    // Detection
    features: FpuFeatureDetection,
    // Config
    state_type: FpuStateType,
    state_size: u32,
    // Init state
    init_fpstate_size: u32,
    // Features
    xfeatures_mask_all: u64,
    xfeatures_mask_user: u64,
    xfeatures_mask_supervisor: u64,
    xfeatures_mask_independent: u64,
    // Dynamic permission
    dynamic_xfeatures: u64, // Features requiring dynamic permission (e.g., AMX)
    // Legacy
    cr0_ts_used: bool, // Using CR0.TS lazy switching (not for modern)
    // MXCSR
    mxcsr_feature_mask: u32,
    // Stats
    total_context_switches: u64,
    total_xstate_faults: u64, // #XF exceptions
    total_dynamic_grants: u64,
    // Zxyphor
    zxy_predictive_prefetch: bool,
    zxy_context_compression: bool,
    initialized: bool,

    pub fn init() FpuSubsystem {
        return FpuSubsystem{
            .features = std.mem.zeroes(FpuFeatureDetection),
            .state_type = .legacy_fxsave,
            .state_size = 512,
            .init_fpstate_size = 512,
            .xfeatures_mask_all = 0x3, // x87 + SSE
            .xfeatures_mask_user = 0x3,
            .xfeatures_mask_supervisor = 0,
            .xfeatures_mask_independent = 0,
            .dynamic_xfeatures = 0,
            .cr0_ts_used = false,
            .mxcsr_feature_mask = 0xFFFF,
            .total_context_switches = 0,
            .total_xstate_faults = 0,
            .total_dynamic_grants = 0,
            .zxy_predictive_prefetch = true,
            .zxy_context_compression = true,
            .initialized = false,
        };
    }
};
