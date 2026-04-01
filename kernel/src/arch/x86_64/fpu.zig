// =============================================================================
// Kernel Zxyphor — FPU / SSE / AVX State Management
// =============================================================================
// Manages extended processor state (FPU, SSE, AVX, etc.) for context switching.
// Uses XSAVE/XRSTOR for modern CPUs, falls back to FXSAVE/FXRSTOR.
//
// Key features:
// - Lazy FPU context switching (only save/restore when process uses FPU)
// - XSAVE area management with dynamic sizing
// - Per-CPU current FPU owner tracking
// - Support for AVX-512 extended state
// - XCR0 configuration
// =============================================================================

const std = @import("std");
const msr = @import("msr.zig");

// =============================================================================
// XCR0 (Extended Control Register 0) Feature Bits
// =============================================================================

pub const XCR0_X87: u64 = 1 << 0; // x87 FPU state
pub const XCR0_SSE: u64 = 1 << 1; // SSE state (XMM registers)
pub const XCR0_AVX: u64 = 1 << 2; // AVX state (YMM upper halves)
pub const XCR0_BNDREG: u64 = 1 << 3; // MPX BND registers
pub const XCR0_BNDCSR: u64 = 1 << 4; // MPX BND CSR
pub const XCR0_OPMASK: u64 = 1 << 5; // AVX-512 opmask (k0-k7)
pub const XCR0_ZMM_HI256: u64 = 1 << 6; // AVX-512 ZMM upper 256 bits (ZMM0-15)
pub const XCR0_HI16_ZMM: u64 = 1 << 7; // AVX-512 ZMM16-31
pub const XCR0_PT: u64 = 1 << 8; // Intel Processor Trace
pub const XCR0_PKRU: u64 = 1 << 9; // Protection Key Rights for User pages
pub const XCR0_CET_U: u64 = 1 << 11; // CET User state
pub const XCR0_CET_S: u64 = 1 << 12; // CET Supervisor state
pub const XCR0_HDC: u64 = 1 << 13; // Hardware Duty Cycling
pub const XCR0_LBR: u64 = 1 << 15; // Last Branch Record
pub const XCR0_HWP: u64 = 1 << 16; // Hardware P-State request
pub const XCR0_XTILECFG: u64 = 1 << 17; // AMX Tile Configuration
pub const XCR0_XTILEDATA: u64 = 1 << 18; // AMX Tile Data

pub const XCR0_AVX512_ALL: u64 = XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

// =============================================================================
// FXSAVE/FXRSTOR Area Layout (Legacy — 512 bytes)
// =============================================================================

pub const FxsaveArea = extern struct {
    fcw: u16, // FPU Control Word
    fsw: u16, // FPU Status Word
    ftw: u8, // FPU Tag Word (abridged)
    reserved1: u8,
    fop: u16, // FPU Opcode
    fip: u64, // FPU Instruction Pointer
    fdp: u64, // FPU Data Pointer
    mxcsr: u32, // MXCSR register
    mxcsr_mask: u32, // MXCSR mask
    st: [8][16]u8, // x87 FPU registers (ST0-ST7, 80-bit extended in 128-bit slots)
    xmm: [16][16]u8, // XMM registers (XMM0-XMM15)
    reserved2: [96]u8,

    pub fn init() FxsaveArea {
        var area: FxsaveArea = std.mem.zeroes(FxsaveArea);
        area.fcw = 0x037F; // Default FPU control word
        area.mxcsr = 0x1F80; // Default MXCSR (mask all exceptions)
        return area;
    }
};

// =============================================================================
// XSAVE Area Management
// =============================================================================

/// Maximum size of XSAVE area (including all extended features).
/// For AVX-512 capable CPUs, this can be up to 2688 bytes.
/// For AMX, it can be much larger.
pub const MAX_XSAVE_SIZE: usize = 4096; // Conservative max

/// XSAVE header (immediately after legacy FXSAVE area at offset 512)
pub const XsaveHeader = extern struct {
    xstate_bv: u64, // State-component bitmap (which components are valid)
    xcomp_bv: u64, // Compaction bitmap (for XSAVEC/XSAVES)
    reserved: [48]u8,
};

/// Per-thread FPU state
pub const FpuState = struct {
    /// Aligned buffer for XSAVE/FXSAVE data
    xsave_area: [MAX_XSAVE_SIZE]u8 align(64),
    /// Whether this state has been initialized
    initialized: bool,
    /// Whether this thread has used FPU since last context switch
    used: bool,
    /// Size of the actual XSAVE area for current CPU
    xsave_size: u32,
    /// XCR0 value when this state was saved
    xcr0_saved: u64,

    pub fn init(xsave_size: u32) FpuState {
        var state: FpuState = undefined;
        @memset(&state.xsave_area, 0);
        state.initialized = false;
        state.used = false;
        state.xsave_size = xsave_size;
        state.xcr0_saved = 0;

        // Set default FPU control words in the legacy region
        const legacy: *FxsaveArea = @ptrCast(@alignCast(&state.xsave_area));
        legacy.fcw = 0x037F;
        legacy.mxcsr = 0x1F80;

        return state;
    }
};

// =============================================================================
// FPU Capability Detection
// =============================================================================

pub const FpuCapabilities = struct {
    has_fxsave: bool,
    has_xsave: bool,
    has_xsaveopt: bool,
    has_xsavec: bool,
    has_xsaves: bool,
    supported_xcr0: u64, // Supported XCR0 bits
    xsave_size: u32, // Size of XSAVE area with all features enabled
    xsave_compact_size: u32, // Size with compaction
    supervisor_features: u64, // IA32_XSS supported bits

    pub fn detect() FpuCapabilities {
        var caps = FpuCapabilities{
            .has_fxsave = false,
            .has_xsave = false,
            .has_xsaveopt = false,
            .has_xsavec = false,
            .has_xsaves = false,
            .supported_xcr0 = 0,
            .xsave_size = 512, // Default FXSAVE size
            .xsave_compact_size = 512,
            .supervisor_features = 0,
        };

        // Check CPUID leaf 1 for FXSAVE and XSAVE
        var eax: u32 = undefined;
        var ebx: u32 = undefined;
        var ecx: u32 = undefined;
        var edx: u32 = undefined;
        cpuid(1, 0, &eax, &ebx, &ecx, &edx);

        caps.has_fxsave = (edx & (1 << 24)) != 0;
        caps.has_xsave = (ecx & (1 << 26)) != 0;

        if (!caps.has_xsave) return caps;

        // CPUID leaf 0xD, subleaf 0: XSAVE area size and supported features
        cpuid(0xD, 0, &eax, &ebx, &ecx, &edx);
        caps.supported_xcr0 = (@as(u64, edx) << 32) | @as(u64, eax);
        caps.xsave_size = ecx; // Max size with all features
        caps.xsave_compact_size = ebx; // Current enabled size

        // CPUID leaf 0xD, subleaf 1: XSAVE extensions
        cpuid(0xD, 1, &eax, &ebx, &ecx, &edx);
        caps.has_xsaveopt = (eax & (1 << 0)) != 0;
        caps.has_xsavec = (eax & (1 << 1)) != 0;
        caps.has_xsaves = (eax & (1 << 3)) != 0;
        if (caps.has_xsaves) {
            caps.supervisor_features = (@as(u64, edx) << 32) | @as(u64, ecx);
        }

        return caps;
    }
};

fn cpuid(leaf: u32, subleaf: u32, eax: *u32, ebx: *u32, ecx: *u32, edx: *u32) void {
    asm volatile ("cpuid"
        : "={eax}" (eax.*),
          "={ebx}" (ebx.*),
          "={ecx}" (ecx.*),
          "={edx}" (edx.*),
        : "{eax}" (leaf),
          "{ecx}" (subleaf),
    );
}

// =============================================================================
// XCR (Extended Control Register) Access
// =============================================================================

/// Read XCR register.
pub inline fn xgetbv(xcr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("xgetbv"
        : "={eax}" (low),
          "={edx}" (high),
        : "{ecx}" (xcr),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

/// Write XCR register.
pub inline fn xsetbv(xcr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("xsetbv"
        :
        : "{ecx}" (xcr),
          "{eax}" (low),
          "{edx}" (high),
    );
}

// =============================================================================
// FPU State Save/Restore Operations
// =============================================================================

/// Save FPU state using the best available method.
pub fn saveFpuState(state: *FpuState, caps: *const FpuCapabilities) void {
    if (caps.has_xsavec) {
        xsavec(&state.xsave_area, caps.supported_xcr0);
    } else if (caps.has_xsaveopt) {
        xsaveopt(&state.xsave_area, caps.supported_xcr0);
    } else if (caps.has_xsave) {
        xsave(&state.xsave_area, caps.supported_xcr0);
    } else if (caps.has_fxsave) {
        fxsave(&state.xsave_area);
    }
    state.used = true;
    state.xcr0_saved = caps.supported_xcr0;
}

/// Restore FPU state using the best available method.
pub fn restoreFpuState(state: *const FpuState, caps: *const FpuCapabilities) void {
    if (caps.has_xsavec) {
        xrstor(&state.xsave_area, caps.supported_xcr0);
    } else if (caps.has_xsave) {
        xrstor(&state.xsave_area, caps.supported_xcr0);
    } else if (caps.has_fxsave) {
        fxrstor(&state.xsave_area);
    }
}

inline fn fxsave(area: *[MAX_XSAVE_SIZE]u8) void {
    asm volatile ("fxsave (%[area])"
        :
        : [area] "r" (area),
        : "memory"
    );
}

inline fn fxrstor(area: *const [MAX_XSAVE_SIZE]u8) void {
    asm volatile ("fxrstor (%[area])"
        :
        : [area] "r" (area),
        : "memory"
    );
}

inline fn xsave(area: *[MAX_XSAVE_SIZE]u8, mask: u64) void {
    const low: u32 = @truncate(mask);
    const high: u32 = @truncate(mask >> 32);
    asm volatile ("xsave (%[area])"
        :
        : [area] "r" (area),
          "{eax}" (low),
          "{edx}" (high),
        : "memory"
    );
}

inline fn xsaveopt(area: *[MAX_XSAVE_SIZE]u8, mask: u64) void {
    const low: u32 = @truncate(mask);
    const high: u32 = @truncate(mask >> 32);
    asm volatile ("xsaveopt (%[area])"
        :
        : [area] "r" (area),
          "{eax}" (low),
          "{edx}" (high),
        : "memory"
    );
}

inline fn xsavec(area: *[MAX_XSAVE_SIZE]u8, mask: u64) void {
    const low: u32 = @truncate(mask);
    const high: u32 = @truncate(mask >> 32);
    asm volatile ("xsavec (%[area])"
        :
        : [area] "r" (area),
          "{eax}" (low),
          "{edx}" (high),
        : "memory"
    );
}

inline fn xrstor(area: *const [MAX_XSAVE_SIZE]u8, mask: u64) void {
    const low: u32 = @truncate(mask);
    const high: u32 = @truncate(mask >> 32);
    asm volatile ("xrstor (%[area])"
        :
        : [area] "r" (area),
          "{eax}" (low),
          "{edx}" (high),
        : "memory"
    );
}

// =============================================================================
// Lazy FPU Context Switching Manager
// =============================================================================

/// Per-CPU FPU state tracking for lazy context switching.
/// With lazy switching, we only save/restore FPU state when a thread actually
/// uses FPU instructions. If the #NM (Device Not Available) exception fires,
/// we know the new thread needs its FPU state restored.
pub const LazyFpuManager = struct {
    caps: FpuCapabilities,
    current_owner_tid: u64, // Thread ID that currently owns the FPU
    fpu_enabled: bool, // Whether FPU is currently enabled (TS flag clear)
    eager_mode: bool, // Use eager switching instead of lazy

    pub fn init() LazyFpuManager {
        return .{
            .caps = FpuCapabilities.detect(),
            .current_owner_tid = 0,
            .fpu_enabled = false,
            .eager_mode = false,
        };
    }

    /// Initialize FPU hardware during CPU bringup.
    pub fn initHardware(self: *LazyFpuManager) void {
        // Enable FPU (clear CR0.EM, set CR0.NE, set CR0.MP)
        var cr0 = readCr0();
        cr0 &= ~@as(u64, 1 << 2); // Clear EM (emulation)
        cr0 |= (1 << 1); // Set MP (monitor coprocessor)
        cr0 |= (1 << 5); // Set NE (numeric error — use native FPU errors)
        writeCr0(cr0);

        // Enable XSAVE in CR4 if supported
        if (self.caps.has_xsave) {
            var cr4 = readCr4();
            cr4 |= (1 << 18); // Set CR4.OSXSAVE
            writeCr4(cr4);

            // Enable all supported state components in XCR0
            var xcr0 = XCR0_X87 | XCR0_SSE;
            if (self.caps.supported_xcr0 & XCR0_AVX != 0) xcr0 |= XCR0_AVX;
            if (self.caps.supported_xcr0 & XCR0_AVX512_ALL == XCR0_AVX512_ALL) {
                xcr0 |= XCR0_AVX512_ALL;
            }
            if (self.caps.supported_xcr0 & XCR0_PKRU != 0) xcr0 |= XCR0_PKRU;
            xsetbv(0, xcr0);
        } else if (self.caps.has_fxsave) {
            var cr4 = readCr4();
            cr4 |= (1 << 9); // Set CR4.OSFXSR
            cr4 |= (1 << 10); // Set CR4.OSXMMEXCPT
            writeCr4(cr4);
        }

        // Initialize FPU with FNINIT
        asm volatile ("fninit" ::: "memory");

        // Set default MXCSR
        var mxcsr: u32 = 0x1F80;
        asm volatile ("ldmxcsr (%[mxcsr])"
            :
            : [mxcsr] "r" (&mxcsr),
            : "memory"
        );

        self.fpu_enabled = true;
    }

    /// Called on context switch — decide whether to save/restore FPU state.
    pub fn onContextSwitch(
        self: *LazyFpuManager,
        prev_state: *FpuState,
        next_state: *FpuState,
        prev_tid: u64,
        next_tid: u64,
    ) void {
        if (self.eager_mode) {
            // Eager mode: always save and restore
            if (self.current_owner_tid == prev_tid) {
                saveFpuState(prev_state, &self.caps);
            }
            if (next_state.initialized) {
                restoreFpuState(next_state, &self.caps);
            } else {
                // Initialize default FPU state for new thread
                asm volatile ("fninit" ::: "memory");
                next_state.initialized = true;
            }
            self.current_owner_tid = next_tid;
            return;
        }

        // Lazy mode: set TS flag in CR0 to trap on FPU use
        if (self.current_owner_tid != next_tid) {
            // Save current FPU state if owned
            if (self.fpu_enabled and self.current_owner_tid == prev_tid) {
                saveFpuState(prev_state, &self.caps);
            }
            // Set TS flag — next FPU instruction will trigger #NM
            setTsFlag();
            self.fpu_enabled = false;
        }
    }

    /// Handle #NM (Device Not Available) exception — lazy FPU restore.
    pub fn handleDeviceNotAvailable(
        self: *LazyFpuManager,
        current_state: *FpuState,
        current_tid: u64,
    ) void {
        // Clear TS flag to allow FPU access
        clearTsFlag();
        self.fpu_enabled = true;

        // Restore the current thread's FPU state
        if (current_state.initialized) {
            restoreFpuState(current_state, &self.caps);
        } else {
            asm volatile ("fninit" ::: "memory");
            current_state.initialized = true;
        }

        self.current_owner_tid = current_tid;
    }

    /// Switch to eager mode (recommended for modern CPUs where XSAVEOPT is fast).
    pub fn setEagerMode(self: *LazyFpuManager, eager: bool) void {
        self.eager_mode = eager;
        if (eager) {
            clearTsFlag();
            self.fpu_enabled = true;
        }
    }
};

// =============================================================================
// CR0 TS Flag Management
// =============================================================================

inline fn setTsFlag() void {
    var cr0 = readCr0();
    cr0 |= (1 << 3); // Set TS (Task Switched)
    writeCr0(cr0);
}

inline fn clearTsFlag() void {
    asm volatile ("clts" ::: "memory");
}

inline fn readCr0() u64 {
    return asm volatile ("mov %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
}

inline fn writeCr0(val: u64) void {
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (val),
    );
}

inline fn readCr4() u64 {
    return asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );
}

inline fn writeCr4(val: u64) void {
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (val),
    );
}

// =============================================================================
// XSAVE Feature Component Information
// =============================================================================

pub const XsaveComponentInfo = struct {
    feature_bit: u8,
    name: []const u8,
    size: u32,
    offset: u32,
    aligned: bool,
    supervisor: bool,
};

/// Query XSAVE component information using CPUID leaf 0xD.
pub fn getXsaveComponentInfo(component: u32) ?XsaveComponentInfo {
    if (component > 63) return null;

    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    cpuid(0xD, component, &eax, &ebx, &ecx, &edx);

    if (eax == 0) return null;

    const name = switch (component) {
        0 => "x87 FPU",
        1 => "SSE",
        2 => "AVX",
        3 => "MPX BNDREG",
        4 => "MPX BNDCSR",
        5 => "AVX-512 Opmask",
        6 => "AVX-512 ZMM_Hi256",
        7 => "AVX-512 Hi16_ZMM",
        8 => "PT",
        9 => "PKRU",
        11 => "CET User",
        12 => "CET Supervisor",
        17 => "AMX TILECFG",
        18 => "AMX TILEDATA",
        else => "Unknown",
    };

    return .{
        .feature_bit = @truncate(component),
        .name = name,
        .size = eax,
        .offset = ebx,
        .aligned = (ecx & 2) != 0,
        .supervisor = (ecx & 1) != 0,
    };
}

/// Enumerate all supported XSAVE components.
pub fn enumerateXsaveComponents(buffer: []XsaveComponentInfo) usize {
    var count: usize = 0;
    var i: u32 = 2; // Skip x87 and SSE (always present)
    while (i < 64 and count < buffer.len) : (i += 1) {
        if (getXsaveComponentInfo(i)) |info| {
            buffer[count] = info;
            count += 1;
        }
    }
    return count;
}
