// =============================================================================
// Kernel Zxyphor — Model Specific Register (MSR) Interface
// =============================================================================
// Provides comprehensive MSR access for x86_64 architecture.
// MSRs control CPU features, power management, performance monitoring,
// security features, and virtualization extensions.
// =============================================================================

const std = @import("std");

// =============================================================================
// MSR Address Constants — Complete catalog of x86_64 MSRs
// =============================================================================

/// Time Stamp Counter
pub const IA32_TSC: u32 = 0x10;
/// Platform ID for CPU identification
pub const IA32_PLATFORM_ID: u32 = 0x17;
/// APIC Base Address Register
pub const IA32_APIC_BASE: u32 = 0x1B;
/// Feature Control (VMX enable, SGX enable, lock)
pub const IA32_FEATURE_CONTROL: u32 = 0x3A;
/// TSC Adjust (software-accessible offset to TSC)
pub const IA32_TSC_ADJUST: u32 = 0x3B;
/// Speculation Control (IBRS, STIBP)
pub const IA32_SPEC_CTRL: u32 = 0x48;
/// Prediction Command (IBPB)
pub const IA32_PRED_CMD: u32 = 0x49;
/// BIOS Update Trigger
pub const IA32_BIOS_UPDT_TRIG: u32 = 0x79;
/// BIOS Update Signature
pub const IA32_BIOS_SIGN_ID: u32 = 0x8B;
/// SMM Monitor Control
pub const IA32_SMM_MONITOR_CTL: u32 = 0x9B;
/// SMM Base
pub const SMBASE: u32 = 0x9E;
/// Performance Monitor Counter 0
pub const IA32_PMC0: u32 = 0xC1;
/// Performance Monitor Counter 1
pub const IA32_PMC1: u32 = 0xC2;
/// Performance Monitor Counter 2
pub const IA32_PMC2: u32 = 0xC3;
/// Performance Monitor Counter 3
pub const IA32_PMC3: u32 = 0xC4;
/// Machine Check Address
pub const IA32_MCG_CAP: u32 = 0x179;
/// Machine Check Status
pub const IA32_MCG_STATUS: u32 = 0x17A;
/// Machine Check Control
pub const IA32_MCG_CTL: u32 = 0x17B;
/// Performance Event Select 0
pub const IA32_PERFEVTSEL0: u32 = 0x186;
/// Performance Event Select 1
pub const IA32_PERFEVTSEL1: u32 = 0x187;
/// Performance Event Select 2
pub const IA32_PERFEVTSEL2: u32 = 0x188;
/// Performance Event Select 3
pub const IA32_PERFEVTSEL3: u32 = 0x189;
/// Platform Information (max/min ratios, etc.)
pub const MSR_PLATFORM_INFO: u32 = 0xCE;
/// Performance Status
pub const IA32_PERF_STATUS: u32 = 0x198;
/// Performance Control (P-state request)
pub const IA32_PERF_CTL: u32 = 0x199;
/// Clock Modulation (duty cycle control)
pub const IA32_CLOCK_MODULATION: u32 = 0x19A;
/// Thermal Interrupt Control
pub const IA32_THERM_INTERRUPT: u32 = 0x19B;
/// Thermal Status
pub const IA32_THERM_STATUS: u32 = 0x19C;
/// Misc Enable (various CPU feature control)
pub const IA32_MISC_ENABLE: u32 = 0x1A0;
/// Energy Performance Bias
pub const IA32_ENERGY_PERF_BIAS: u32 = 0x1B0;
/// Package Thermal Status
pub const IA32_PACKAGE_THERM_STATUS: u32 = 0x1B1;
/// Package Thermal Interrupt
pub const IA32_PACKAGE_THERM_INTERRUPT: u32 = 0x1B2;
/// Debug Control
pub const IA32_DEBUGCTL: u32 = 0x1D9;
/// SMRR Physical Base
pub const IA32_SMRR_PHYSBASE: u32 = 0x1F2;
/// SMRR Physical Mask
pub const IA32_SMRR_PHYSMASK: u32 = 0x1F3;
/// DCA CAP
pub const IA32_DCA_0_CAP: u32 = 0x1F8;
/// MTRR Capability
pub const IA32_MTRRCAP: u32 = 0xFE;
/// Fixed Range MTRR for 64K region at 0x00000
pub const IA32_MTRR_FIX64K_00000: u32 = 0x250;
/// Fixed Range MTRR for 16K region at 0x80000
pub const IA32_MTRR_FIX16K_80000: u32 = 0x258;
/// Fixed Range MTRR for 16K region at 0xA0000
pub const IA32_MTRR_FIX16K_A0000: u32 = 0x259;
/// Fixed Range MTRR for 4K region at 0xC0000
pub const IA32_MTRR_FIX4K_C0000: u32 = 0x268;
/// Fixed Range MTRR for 4K region at 0xC8000
pub const IA32_MTRR_FIX4K_C8000: u32 = 0x269;
/// Fixed Range MTRR for 4K region at 0xD0000
pub const IA32_MTRR_FIX4K_D0000: u32 = 0x26A;
/// Fixed Range MTRR for 4K region at 0xD8000
pub const IA32_MTRR_FIX4K_D8000: u32 = 0x26B;
/// Fixed Range MTRR for 4K region at 0xE0000
pub const IA32_MTRR_FIX4K_E0000: u32 = 0x26C;
/// Fixed Range MTRR for 4K region at 0xE8000
pub const IA32_MTRR_FIX4K_E8000: u32 = 0x26D;
/// Fixed Range MTRR for 4K region at 0xF0000
pub const IA32_MTRR_FIX4K_F0000: u32 = 0x26E;
/// Fixed Range MTRR for 4K region at 0xF8000
pub const IA32_MTRR_FIX4K_F8000: u32 = 0x26F;
/// PAT (Page Attribute Table)
pub const IA32_PAT: u32 = 0x277;
/// Variable Range MTRR Physical Base 0
pub const IA32_MTRR_PHYSBASE0: u32 = 0x200;
/// Variable Range MTRR Physical Mask 0
pub const IA32_MTRR_PHYSMASK0: u32 = 0x201;
/// MTRR Default Type
pub const IA32_MTRR_DEF_TYPE: u32 = 0x2FF;
/// Fixed Counter 0 — Instructions Retired
pub const IA32_FIXED_CTR0: u32 = 0x309;
/// Fixed Counter 1 — CPU_CLK_UNHALTED.CORE
pub const IA32_FIXED_CTR1: u32 = 0x30A;
/// Fixed Counter 2 — CPU_CLK_UNHALTED.REF
pub const IA32_FIXED_CTR2: u32 = 0x30B;
/// Fixed Counter Control
pub const IA32_FIXED_CTR_CTRL: u32 = 0x38D;
/// Global Performance Counter Status
pub const IA32_PERF_GLOBAL_STATUS: u32 = 0x38E;
/// Global Performance Counter Control
pub const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
/// Global Performance Counter Overflow Control
pub const IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;
/// Precise Event Based Sampling Enable
pub const IA32_PEBS_ENABLE: u32 = 0x3F1;
/// Machine Check Address MC0
pub const IA32_MC0_CTL: u32 = 0x400;
pub const IA32_MC0_STATUS: u32 = 0x401;
pub const IA32_MC0_ADDR: u32 = 0x402;
pub const IA32_MC0_MISC: u32 = 0x403;
/// VMX Basic Information
pub const IA32_VMX_BASIC: u32 = 0x480;
/// VMX Pin-Based Controls
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
/// VMX Processor-Based Controls
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
/// VMX Exit Controls
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
/// VMX Entry Controls
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
/// VMX Miscellaneous Information
pub const IA32_VMX_MISC: u32 = 0x485;
/// VMX True Pin-Based Controls
pub const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
/// VMX True Processor-Based Controls
pub const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
/// VMX True Exit Controls
pub const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
/// VMX True Entry Controls
pub const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
/// EFER (Extended Feature Enable Register)
pub const IA32_EFER: u32 = 0xC0000080;
/// STAR (SYSCALL Target Address Register)
pub const IA32_STAR: u32 = 0xC0000081;
/// LSTAR (Long Mode SYSCALL Target Address)
pub const IA32_LSTAR: u32 = 0xC0000082;
/// CSTAR (Compatibility Mode SYSCALL Target Address)
pub const IA32_CSTAR: u32 = 0xC0000083;
/// SFMASK (SYSCALL Flag Mask)
pub const IA32_FMASK: u32 = 0xC0000084;
/// FS Base Address
pub const IA32_FS_BASE: u32 = 0xC0000100;
/// GS Base Address
pub const IA32_GS_BASE: u32 = 0xC0000101;
/// Kernel GS Base (swapped on SWAPGS)
pub const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
/// TSC Auxiliary (RDTSCP return value in ECX)
pub const IA32_TSC_AUX: u32 = 0xC0000103;
/// XSS (Extended Supervisor State)
pub const IA32_XSS: u32 = 0xDA0;

// Intel RAPL (Running Average Power Limit) MSRs
pub const MSR_RAPL_POWER_UNIT: u32 = 0x606;
pub const MSR_PKG_POWER_LIMIT: u32 = 0x610;
pub const MSR_PKG_ENERGY_STATUS: u32 = 0x611;
pub const MSR_PKG_PERF_STATUS: u32 = 0x613;
pub const MSR_PKG_POWER_INFO: u32 = 0x614;
pub const MSR_DRAM_POWER_LIMIT: u32 = 0x618;
pub const MSR_DRAM_ENERGY_STATUS: u32 = 0x619;
pub const MSR_PP0_POWER_LIMIT: u32 = 0x638;
pub const MSR_PP0_ENERGY_STATUS: u32 = 0x639;
pub const MSR_PP1_POWER_LIMIT: u32 = 0x640;
pub const MSR_PP1_ENERGY_STATUS: u32 = 0x641;

// Hardware P-State MSRs (HWP)
pub const MSR_HWP_CAPABILITIES: u32 = 0x771;
pub const MSR_HWP_REQUEST_PKG: u32 = 0x772;
pub const MSR_HWP_INTERRUPT: u32 = 0x773;
pub const MSR_HWP_REQUEST: u32 = 0x774;
pub const MSR_HWP_STATUS: u32 = 0x777;

// =============================================================================
// EFER Bits
// =============================================================================
pub const EFER_SCE: u64 = 1 << 0; // System Call Extensions
pub const EFER_LME: u64 = 1 << 8; // Long Mode Enable
pub const EFER_LMA: u64 = 1 << 10; // Long Mode Active
pub const EFER_NXE: u64 = 1 << 11; // No-Execute Enable
pub const EFER_SVME: u64 = 1 << 12; // Secure Virtual Machine Enable
pub const EFER_LMSLE: u64 = 1 << 13; // Long Mode Segment Limit Enable
pub const EFER_FFXSR: u64 = 1 << 14; // Fast FXSAVE/FXRSTOR
pub const EFER_TCE: u64 = 1 << 15; // Translation Cache Extension

// =============================================================================
// Feature Control bits
// =============================================================================
pub const FEATURE_CONTROL_LOCK: u64 = 1 << 0;
pub const FEATURE_CONTROL_VMX_IN_SMX: u64 = 1 << 1;
pub const FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;
pub const FEATURE_CONTROL_SGX_LAUNCH_CONTROL: u64 = 1 << 17;
pub const FEATURE_CONTROL_SGX_GLOBAL_ENABLE: u64 = 1 << 18;

// =============================================================================
// MISC_ENABLE bits
// =============================================================================
pub const MISC_ENABLE_FAST_STRING: u64 = 1 << 0;
pub const MISC_ENABLE_TCC: u64 = 1 << 1; // Thermal Control Circuit
pub const MISC_ENABLE_PERF_MON: u64 = 1 << 7;
pub const MISC_ENABLE_BTS_UNAVAIL: u64 = 1 << 11;
pub const MISC_ENABLE_PEBS_UNAVAIL: u64 = 1 << 12;
pub const MISC_ENABLE_ENHANCED_SPEEDSTEP: u64 = 1 << 16;
pub const MISC_ENABLE_MWAIT: u64 = 1 << 18;
pub const MISC_ENABLE_LIMIT_CPUID: u64 = 1 << 22;
pub const MISC_ENABLE_XTPR_DISABLE: u64 = 1 << 23;
pub const MISC_ENABLE_XD_DISABLE: u64 = 1 << 34;
pub const MISC_ENABLE_TURBO_DISABLE: u64 = 1 << 38;

// =============================================================================
// Debug Control Bits (IA32_DEBUGCTL)
// =============================================================================
pub const DEBUGCTL_LBR: u64 = 1 << 0; // Last Branch Record
pub const DEBUGCTL_BTF: u64 = 1 << 1; // Single-Step on Branches
pub const DEBUGCTL_TR: u64 = 1 << 6; // Trace Messages Enable
pub const DEBUGCTL_BTS: u64 = 1 << 7; // Branch Trace Store
pub const DEBUGCTL_BTINT: u64 = 1 << 8; // BTS Interrupt
pub const DEBUGCTL_BTS_OFF_OS: u64 = 1 << 9; // BTS Off in OS
pub const DEBUGCTL_BTS_OFF_USR: u64 = 1 << 10; // BTS Off in User
pub const DEBUGCTL_FREEZE_LBRS_ON_PMI: u64 = 1 << 11;
pub const DEBUGCTL_FREEZE_PERFMON_ON_PMI: u64 = 1 << 12;
pub const DEBUGCTL_ENABLE_UNCORE_PMI: u64 = 1 << 13;
pub const DEBUGCTL_FREEZE_WHILE_SMM: u64 = 1 << 14;
pub const DEBUGCTL_RTM_DEBUG: u64 = 1 << 15;

// =============================================================================
// MTRR Memory Types
// =============================================================================
pub const MTRR_TYPE_UC: u8 = 0x00; // Uncacheable
pub const MTRR_TYPE_WC: u8 = 0x01; // Write Combining
pub const MTRR_TYPE_WT: u8 = 0x04; // Write Through
pub const MTRR_TYPE_WP: u8 = 0x05; // Write Protected
pub const MTRR_TYPE_WB: u8 = 0x06; // Write Back

// =============================================================================
// PAT Memory Types
// =============================================================================
pub const PAT_UC: u8 = 0x00;
pub const PAT_WC: u8 = 0x01;
pub const PAT_WT: u8 = 0x04;
pub const PAT_WP: u8 = 0x05;
pub const PAT_WB: u8 = 0x06;
pub const PAT_UCM: u8 = 0x07; // UC-

// =============================================================================
// Core MSR Read/Write Operations
// =============================================================================

/// Read a Model Specific Register (MSR) and return the full 64-bit value.
/// Uses RDMSR instruction which reads ECX-specified MSR into EDX:EAX.
pub inline fn read(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : "={eax}" (low),
          "={edx}" (high),
        : "{ecx}" (msr),
        : "memory"
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

/// Write a 64-bit value to a Model Specific Register (MSR).
/// Uses WRMSR instruction which writes EDX:EAX to ECX-specified MSR.
pub inline fn write(msr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : "{ecx}" (msr),
          "{eax}" (low),
          "{edx}" (high),
        : "memory"
    );
}

/// Read the Time Stamp Counter (TSC) using RDTSC.
/// Returns a monotonically increasing 64-bit cycle counter.
pub inline fn readTsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : "={eax}" (low),
          "={edx}" (high),
        :
        : "memory"
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

/// Read the Time Stamp Counter with processor ID (RDTSCP).
/// Also returns the processor ID in the aux parameter.
pub inline fn readTscp(aux: *u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtscp"
        : "={eax}" (low),
          "={edx}" (high),
          "={ecx}" (aux.*),
        :
        : "memory"
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

// =============================================================================
// APIC Base Operations
// =============================================================================

pub const ApicBaseInfo = struct {
    base_address: u64,
    bsp: bool, // Bootstrap Processor flag
    global_enable: bool,
    x2apic_enable: bool,
};

/// Read the APIC Base MSR and extract structured information.
pub fn readApicBase() ApicBaseInfo {
    const val = read(IA32_APIC_BASE);
    return .{
        .base_address = val & 0xFFFFF000, // Bits 12-35 (physical address)
        .bsp = (val & (1 << 8)) != 0,
        .global_enable = (val & (1 << 11)) != 0,
        .x2apic_enable = (val & (1 << 10)) != 0,
    };
}

/// Set the APIC base address and enable/disable flags.
pub fn writeApicBase(base: u64, enable: bool, x2apic: bool) void {
    var val: u64 = base & 0xFFFFF000;
    if (enable) val |= (1 << 11);
    if (x2apic) val |= (1 << 10);
    // Preserve BSP bit from current value
    val |= read(IA32_APIC_BASE) & (1 << 8);
    write(IA32_APIC_BASE, val);
}

// =============================================================================
// EFER Operations
// =============================================================================

/// Read the EFER (Extended Feature Enable Register).
pub fn readEfer() u64 {
    return read(IA32_EFER);
}

/// Enable specific EFER bits (OR operation).
pub fn enableEferBits(bits: u64) void {
    write(IA32_EFER, read(IA32_EFER) | bits);
}

/// Disable specific EFER bits (AND NOT operation).
pub fn disableEferBits(bits: u64) void {
    write(IA32_EFER, read(IA32_EFER) & ~bits);
}

/// Check if Long Mode is active.
pub fn isLongModeActive() bool {
    return (read(IA32_EFER) & EFER_LMA) != 0;
}

/// Check if NX (No-Execute) bit is enabled.
pub fn isNxEnabled() bool {
    return (read(IA32_EFER) & EFER_NXE) != 0;
}

/// Enable SYSCALL/SYSRET instructions.
pub fn enableSyscallExtensions() void {
    enableEferBits(EFER_SCE);
}

// =============================================================================
// SYSCALL/SYSRET MSR Configuration
// =============================================================================

pub const SyscallConfig = struct {
    kernel_cs: u16,
    kernel_ss: u16,
    user_cs: u16,
    user_ss: u16,
    handler_address: u64,
    compat_handler_address: u64,
    rflags_mask: u64,
};

/// Configure SYSCALL/SYSRET MSRs for fast system call path.
/// STAR MSR layout: [63:48] = SYSRET CS/SS, [47:32] = SYSCALL CS/SS
/// LSTAR = handler address for 64-bit SYSCALL
/// CSTAR = handler address for compatibility mode SYSCALL
/// FMASK = RFLAGS bits to clear on SYSCALL entry
pub fn configureSyscall(config: SyscallConfig) void {
    // STAR: bits 47:32 = SYSCALL CS, bits 63:48 = SYSRET CS
    // SYSRET loads CS from [63:48]+16 and SS from [63:48]+8
    const star_value: u64 = (@as(u64, config.user_cs - 16) << 48) |
        (@as(u64, config.kernel_cs) << 32);
    write(IA32_STAR, star_value);

    // LSTAR: 64-bit syscall entry point
    write(IA32_LSTAR, config.handler_address);

    // CSTAR: 32-bit compatibility mode syscall entry point
    write(IA32_CSTAR, config.compat_handler_address);

    // FMASK: Clear IF (bit 9) and TF (bit 8) on syscall entry
    write(IA32_FMASK, config.rflags_mask);

    // Enable SYSCALL/SYSRET in EFER
    enableSyscallExtensions();
}

// =============================================================================
// FS/GS Base Operations
// =============================================================================

/// Read the FS base address (used for thread-local storage).
pub fn readFsBase() u64 {
    return read(IA32_FS_BASE);
}

/// Write the FS base address.
pub fn writeFsBase(base: u64) void {
    write(IA32_FS_BASE, base);
}

/// Read the GS base address (used for per-CPU data in kernel).
pub fn readGsBase() u64 {
    return read(IA32_GS_BASE);
}

/// Write the GS base address.
pub fn writeGsBase(base: u64) void {
    write(IA32_GS_BASE, base);
}

/// Read the kernel GS base (swapped on SWAPGS).
pub fn readKernelGsBase() u64 {
    return read(IA32_KERNEL_GS_BASE);
}

/// Write the kernel GS base.
pub fn writeKernelGsBase(base: u64) void {
    write(IA32_KERNEL_GS_BASE, base);
}

/// Execute SWAPGS instruction to swap GS base and kernel GS base.
pub inline fn swapgs() void {
    asm volatile ("swapgs" ::: "memory");
}

// =============================================================================
// MTRR (Memory Type Range Register) Management
// =============================================================================

pub const MtrrCapabilities = struct {
    variable_count: u8,
    fixed_supported: bool,
    wc_supported: bool,
    smrr_supported: bool,
};

/// Read MTRR capabilities from the processor.
pub fn readMtrrCapabilities() MtrrCapabilities {
    const val = read(IA32_MTRRCAP);
    return .{
        .variable_count = @truncate(val & 0xFF),
        .fixed_supported = (val & (1 << 8)) != 0,
        .wc_supported = (val & (1 << 10)) != 0,
        .smrr_supported = (val & (1 << 11)) != 0,
    };
}

pub const MtrrDefType = struct {
    default_type: u8,
    fixed_enable: bool,
    mtrr_enable: bool,
};

/// Read the default MTRR type configuration.
pub fn readMtrrDefType() MtrrDefType {
    const val = read(IA32_MTRR_DEF_TYPE);
    return .{
        .default_type = @truncate(val & 0xFF),
        .fixed_enable = (val & (1 << 10)) != 0,
        .mtrr_enable = (val & (1 << 11)) != 0,
    };
}

/// Configure the default MTRR type.
pub fn writeMtrrDefType(config: MtrrDefType) void {
    var val: u64 = @as(u64, config.default_type);
    if (config.fixed_enable) val |= (1 << 10);
    if (config.mtrr_enable) val |= (1 << 11);
    write(IA32_MTRR_DEF_TYPE, val);
}

pub const VariableMtrr = struct {
    base: u64,
    mask: u64,
    mem_type: u8,
    valid: bool,
};

/// Read a variable range MTRR pair (base and mask).
pub fn readVariableMtrr(index: u8) VariableMtrr {
    const base_msr = IA32_MTRR_PHYSBASE0 + @as(u32, index) * 2;
    const mask_msr = IA32_MTRR_PHYSBASE0 + @as(u32, index) * 2 + 1;
    const base = read(base_msr);
    const mask = read(mask_msr);
    return .{
        .base = base & 0xFFFFFFFFF000, // Bits 12-51
        .mask = mask & 0xFFFFFFFFF000,
        .mem_type = @truncate(base & 0xFF),
        .valid = (mask & (1 << 11)) != 0,
    };
}

/// Write a variable range MTRR pair.
pub fn writeVariableMtrr(index: u8, mtrr: VariableMtrr) void {
    const base_msr = IA32_MTRR_PHYSBASE0 + @as(u32, index) * 2;
    const mask_msr = IA32_MTRR_PHYSBASE0 + @as(u32, index) * 2 + 1;
    write(base_msr, (mtrr.base & 0xFFFFFFFFF000) | @as(u64, mtrr.mem_type));
    var mask_val: u64 = mtrr.mask & 0xFFFFFFFFF000;
    if (mtrr.valid) mask_val |= (1 << 11);
    write(mask_msr, mask_val);
}

/// Set up an MTRR range for a physical address range with a specified memory type.
/// Range must be power-of-2 aligned and power-of-2 sized.
pub fn setMtrrRange(index: u8, base: u64, size: u64, mem_type: u8) void {
    const mask = ~(size - 1) & 0xFFFFFFFFF000;
    writeVariableMtrr(index, .{
        .base = base,
        .mask = mask,
        .mem_type = mem_type,
        .valid = true,
    });
}

// =============================================================================
// PAT (Page Attribute Table) Configuration
// =============================================================================

pub const PatConfig = struct {
    entries: [8]u8,
};

/// Read the current PAT configuration.
pub fn readPat() PatConfig {
    const val = read(IA32_PAT);
    var config: PatConfig = undefined;
    for (&config.entries, 0..) |*entry, i| {
        entry.* = @truncate((val >> (@as(u6, @intCast(i)) * 8)) & 0xFF);
    }
    return config;
}

/// Write a PAT configuration.
pub fn writePat(config: PatConfig) void {
    var val: u64 = 0;
    for (config.entries, 0..) |entry, i| {
        val |= @as(u64, entry) << (@as(u6, @intCast(i)) * 8);
    }
    write(IA32_PAT, val);
}

/// Set up the recommended PAT layout for a modern kernel:
///   PAT0 = WB (default), PAT1 = WT, PAT2 = UC-, PAT3 = UC
///   PAT4 = WB, PAT5 = WT, PAT6 = WC (for framebuffers), PAT7 = UC
pub fn setupDefaultPat() void {
    writePat(.{
        .entries = .{
            PAT_WB, PAT_WT, PAT_UCM, PAT_UC,
            PAT_WB, PAT_WT, PAT_WC, PAT_UC,
        },
    });
}

// =============================================================================
// Performance Monitoring
// =============================================================================

pub const PerfEventSelect = struct {
    event_select: u8,
    unit_mask: u8,
    user_mode: bool,
    os_mode: bool,
    edge_detect: bool,
    pin_control: bool,
    interrupt_enable: bool,
    any_thread: bool,
    enable: bool,
    invert: bool,
    counter_mask: u8,
};

/// Configure a performance event select register.
pub fn writePerfEventSelect(counter: u2, config: PerfEventSelect) void {
    var val: u64 = @as(u64, config.event_select);
    val |= @as(u64, config.unit_mask) << 8;
    if (config.user_mode) val |= (1 << 16);
    if (config.os_mode) val |= (1 << 17);
    if (config.edge_detect) val |= (1 << 18);
    if (config.pin_control) val |= (1 << 19);
    if (config.interrupt_enable) val |= (1 << 20);
    if (config.any_thread) val |= (1 << 21);
    if (config.enable) val |= (1 << 22);
    if (config.invert) val |= (1 << 23);
    val |= @as(u64, config.counter_mask) << 24;

    const msr = IA32_PERFEVTSEL0 + @as(u32, counter);
    write(msr, val);
}

/// Read a general-purpose performance counter.
pub fn readPerfCounter(counter: u2) u64 {
    return read(IA32_PMC0 + @as(u32, counter));
}

/// Read a fixed-function performance counter.
pub fn readFixedCounter(counter: u2) u64 {
    return read(IA32_FIXED_CTR0 + @as(u32, counter));
}

/// Enable/disable global performance counters.
pub fn setGlobalPerfControl(general_mask: u4, fixed_mask: u4) void {
    var val: u64 = @as(u64, general_mask);
    val |= @as(u64, fixed_mask) << 32;
    write(IA32_PERF_GLOBAL_CTRL, val);
}

/// Clear performance counter overflow flags.
pub fn clearPerfOverflow() void {
    write(IA32_PERF_GLOBAL_OVF_CTRL, read(IA32_PERF_GLOBAL_STATUS));
}

// =============================================================================
// Power Management MSRs
// =============================================================================

pub const HwpCapabilities = struct {
    highest_perf: u8,
    guaranteed_perf: u8,
    most_efficient_perf: u8,
    lowest_perf: u8,
};

/// Read HWP (Hardware P-State) capabilities.
pub fn readHwpCapabilities() HwpCapabilities {
    const val = read(MSR_HWP_CAPABILITIES);
    return .{
        .highest_perf = @truncate(val & 0xFF),
        .guaranteed_perf = @truncate((val >> 8) & 0xFF),
        .most_efficient_perf = @truncate((val >> 16) & 0xFF),
        .lowest_perf = @truncate((val >> 24) & 0xFF),
    };
}

pub const HwpRequest = struct {
    min_perf: u8,
    max_perf: u8,
    desired_perf: u8,
    energy_perf_pref: u8,
    activity_window: u10,
    package_control: bool,
};

/// Write an HWP request to control P-state behavior.
pub fn writeHwpRequest(req: HwpRequest) void {
    var val: u64 = @as(u64, req.min_perf);
    val |= @as(u64, req.max_perf) << 8;
    val |= @as(u64, req.desired_perf) << 16;
    val |= @as(u64, req.energy_perf_pref) << 24;
    val |= @as(u64, req.activity_window) << 32;
    if (req.package_control) val |= (1 << 42);
    write(MSR_HWP_REQUEST, val);
}

pub const RaplPowerUnit = struct {
    power_units: u4,
    energy_units: u5,
    time_units: u4,
};

/// Read RAPL power unit definitions.
pub fn readRaplPowerUnit() RaplPowerUnit {
    const val = read(MSR_RAPL_POWER_UNIT);
    return .{
        .power_units = @truncate(val & 0xF),
        .energy_units = @truncate((val >> 8) & 0x1F),
        .time_units = @truncate((val >> 16) & 0xF),
    };
}

/// Read the current package energy consumption (in RAPL units).
pub fn readPackageEnergy() u64 {
    return read(MSR_PKG_ENERGY_STATUS) & 0xFFFFFFFF;
}

/// Read the current DRAM energy consumption (in RAPL units).
pub fn readDramEnergy() u64 {
    return read(MSR_DRAM_ENERGY_STATUS) & 0xFFFFFFFF;
}

// =============================================================================
// Machine Check Architecture (MCA) Operations
// =============================================================================

pub const McgCapabilities = struct {
    bank_count: u8,
    mcg_ctl_present: bool,
    extended_present: bool,
    cmci_present: bool,
    threshold_present: bool,
    extended_count: u8,
    serialization: bool,
    elog_present: bool,
    lmce_present: bool,
};

/// Read Machine Check Global Capabilities.
pub fn readMcgCapabilities() McgCapabilities {
    const val = read(IA32_MCG_CAP);
    return .{
        .bank_count = @truncate(val & 0xFF),
        .mcg_ctl_present = (val & (1 << 8)) != 0,
        .extended_present = (val & (1 << 9)) != 0,
        .cmci_present = (val & (1 << 10)) != 0,
        .threshold_present = (val & (1 << 11)) != 0,
        .extended_count = @truncate((val >> 16) & 0xFF),
        .serialization = (val & (1 << 24)) != 0,
        .elog_present = (val & (1 << 26)) != 0,
        .lmce_present = (val & (1 << 27)) != 0,
    };
}

pub const McBankStatus = struct {
    mca_error_code: u16,
    model_specific_code: u16,
    other_info: u6,
    corrected_count: u15,
    status_valid: bool,
    overflow: bool,
    uncorrected: bool,
    enabled: bool,
    miscv: bool,
    addrv: bool,
    pcc: bool,
    s: bool,
    ar: bool,
};

/// Read Machine Check bank status register.
pub fn readMcBankStatus(bank: u8) McBankStatus {
    const val = read(IA32_MC0_STATUS + @as(u32, bank) * 4);
    return .{
        .mca_error_code = @truncate(val & 0xFFFF),
        .model_specific_code = @truncate((val >> 16) & 0xFFFF),
        .other_info = @truncate((val >> 32) & 0x3F),
        .corrected_count = @truncate((val >> 38) & 0x7FFF),
        .status_valid = (val & (1 << 63)) != 0,
        .overflow = (val & (1 << 62)) != 0,
        .uncorrected = (val & (1 << 61)) != 0,
        .enabled = (val & (1 << 60)) != 0,
        .miscv = (val & (1 << 59)) != 0,
        .addrv = (val & (1 << 58)) != 0,
        .pcc = (val & (1 << 57)) != 0,
        .s = (val & (1 << 56)) != 0,
        .ar = (val & (1 << 55)) != 0,
    };
}

/// Read Machine Check bank address register.
pub fn readMcBankAddr(bank: u8) u64 {
    return read(IA32_MC0_ADDR + @as(u32, bank) * 4);
}

/// Clear Machine Check bank status (acknowledge error).
pub fn clearMcBankStatus(bank: u8) void {
    write(IA32_MC0_STATUS + @as(u32, bank) * 4, 0);
}

/// Initialize Machine Check Architecture — enable all MC banks.
pub fn initMca() void {
    const cap = readMcgCapabilities();

    // Enable MCG global control if supported
    if (cap.mcg_ctl_present) {
        write(IA32_MCG_CTL, 0xFFFFFFFFFFFFFFFF); // Enable all banks
    }

    // Clear all status registers and enable control for each bank
    var bank: u8 = 0;
    while (bank < cap.bank_count) : (bank += 1) {
        clearMcBankStatus(bank);
        write(IA32_MC0_CTL + @as(u32, bank) * 4, 0xFFFFFFFFFFFFFFFF);
    }

    // Clear MCG status
    write(IA32_MCG_STATUS, 0);
}

// =============================================================================
// Speculation Control
// =============================================================================

/// Enable Indirect Branch Restricted Speculation (IBRS).
pub fn enableIbrs() void {
    write(IA32_SPEC_CTRL, read(IA32_SPEC_CTRL) | 1);
}

/// Enable Single Thread Indirect Branch Predictors (STIBP).
pub fn enableStibp() void {
    write(IA32_SPEC_CTRL, read(IA32_SPEC_CTRL) | (1 << 1));
}

/// Enable Speculative Store Bypass Disable (SSBD).
pub fn enableSsbd() void {
    write(IA32_SPEC_CTRL, read(IA32_SPEC_CTRL) | (1 << 2));
}

/// Execute Indirect Branch Prediction Barrier (IBPB).
pub fn executeIbpb() void {
    write(IA32_PRED_CMD, 1);
}

// =============================================================================
// TSC Auxiliary — Used by RDTSCP for processor ID
// =============================================================================

/// Set the TSC_AUX value (value returned in ECX by RDTSCP).
/// Typically set to the CPU/core ID for identifying which core is executing.
pub fn setTscAux(value: u32) void {
    write(IA32_TSC_AUX, @as(u64, value));
}

/// Read the TSC_AUX value.
pub fn getTscAux() u32 {
    return @truncate(read(IA32_TSC_AUX));
}

// =============================================================================
// TSC Calibration and Frequency Detection
// =============================================================================

/// Estimate TSC frequency using the PIT timer (simple calibration).
/// Returns estimated frequency in Hz.
/// Note: This is a rough estimate — use CPUID leaf 0x15 if available.
pub fn calibrateTscFrequency() u64 {
    // Use PIT channel 2 for calibration
    const PIT_DATA2: u16 = 0x42;
    const PIT_CMD: u16 = 0x43;
    const PIT_FREQ: u64 = 1193182; // Hz
    const CALIBRATE_TICKS: u16 = 11932; // ~10ms

    // Set PIT channel 2 to mode 0 (interrupt on terminal count)
    portOut(u8, PIT_CMD, 0xB0); // Channel 2, lobyte/hibyte, mode 0
    portOut(u8, PIT_DATA2, @truncate(CALIBRATE_TICKS));
    portOut(u8, PIT_DATA2, @truncate(CALIBRATE_TICKS >> 8));

    // Read starting TSC
    const tsc_start = readTsc();

    // Wait for PIT to count down
    while (true) {
        const val = portIn(u8, 0x61);
        if (val & 0x20 != 0) break; // PIT output bit set
    }

    const tsc_end = readTsc();
    const tsc_delta = tsc_end - tsc_start;

    // Calculate: freq = tsc_delta * PIT_FREQ / CALIBRATE_TICKS
    return (tsc_delta * PIT_FREQ) / @as(u64, CALIBRATE_TICKS);
}

// =============================================================================
// Port I/O helpers (used internally)
// =============================================================================

fn portOut(comptime T: type, port: u16, value: T) void {
    switch (T) {
        u8 => asm volatile ("outb %[value], %[port]"
            :
            : [value] "{al}" (value),
              [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("outw %[value], %[port]"
            :
            : [value] "{ax}" (value),
              [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("outl %[value], %[port]"
            :
            : [value] "{eax}" (value),
              [port] "N{dx}" (port),
        ),
        else => @compileError("Unsupported port I/O type"),
    }
}

fn portIn(comptime T: type, port: u16) T {
    return switch (T) {
        u8 => asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("inw %[port], %[result]"
            : [result] "={ax}" (-> u16),
            : [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("inl %[port], %[result]"
            : [result] "={eax}" (-> u32),
            : [port] "N{dx}" (port),
        ),
        else => @compileError("Unsupported port I/O type"),
    };
}

// =============================================================================
// VMX (Virtual Machine Extensions) Support
// =============================================================================

pub const VmxBasicInfo = struct {
    vmcs_revision_id: u31,
    vmcs_region_size: u13,
    phys_addr_width: bool, // true = 32-bit, false = 64-bit
    dual_monitor: bool,
    vmcs_mem_type: u4,
    ins_outs_reporting: bool,
    true_controls: bool,
};

/// Read VMX basic information.
pub fn readVmxBasicInfo() VmxBasicInfo {
    const val = read(IA32_VMX_BASIC);
    return .{
        .vmcs_revision_id = @truncate(val & 0x7FFFFFFF),
        .vmcs_region_size = @truncate((val >> 32) & 0x1FFF),
        .phys_addr_width = (val & (1 << 48)) != 0,
        .dual_monitor = (val & (1 << 49)) != 0,
        .vmcs_mem_type = @truncate((val >> 50) & 0xF),
        .ins_outs_reporting = (val & (1 << 54)) != 0,
        .true_controls = (val & (1 << 55)) != 0,
    };
}

/// Enable VMX operation in CR4 and feature control MSR.
pub fn enableVmx() bool {
    const feature = read(IA32_FEATURE_CONTROL);

    // Check if feature control is locked
    if (feature & FEATURE_CONTROL_LOCK != 0) {
        // Locked — check if VMX is enabled
        if (feature & FEATURE_CONTROL_VMX_OUTSIDE_SMX == 0) {
            return false; // VMX not enabled and locked
        }
    } else {
        // Not locked — enable VMX and lock
        write(IA32_FEATURE_CONTROL, feature | FEATURE_CONTROL_VMX_OUTSIDE_SMX | FEATURE_CONTROL_LOCK);
    }

    // Set CR4.VMXE (bit 13)
    const cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (cr4 | (1 << 13)),
    );

    return true;
}

// =============================================================================
// XSave State Management
// =============================================================================

/// Read the XSS (Extended Supervisor State) MSR.
/// Controls which supervisor-state components are saved/restored by XSAVES/XRSTORS.
pub fn readXss() u64 {
    return read(IA32_XSS);
}

/// Write the XSS MSR.
pub fn writeXss(val: u64) void {
    write(IA32_XSS, val);
}

// =============================================================================
// CPU Frequency Scaling Helpers
// =============================================================================

pub const PerfStateInfo = struct {
    current_ratio: u8,
    current_vid: u8,
};

/// Read current performance state from IA32_PERF_STATUS.
pub fn readPerfStatus() PerfStateInfo {
    const val = read(IA32_PERF_STATUS);
    return .{
        .current_ratio = @truncate((val >> 8) & 0xFF),
        .current_vid = @truncate(val & 0xFF),
    };
}

/// Request a P-state transition via IA32_PERF_CTL.
pub fn writePerfControl(ratio: u8) void {
    write(IA32_PERF_CTL, @as(u64, ratio) << 8);
}

/// Enable Enhanced SpeedStep Technology.
pub fn enableSpeedStep() void {
    var val = read(IA32_MISC_ENABLE);
    val |= MISC_ENABLE_ENHANCED_SPEEDSTEP;
    write(IA32_MISC_ENABLE, val);
}

/// Check if Turbo Boost is available (not disabled).
pub fn isTurboBoostAvailable() bool {
    const val = read(IA32_MISC_ENABLE);
    return (val & MISC_ENABLE_TURBO_DISABLE) == 0;
}

// =============================================================================
// Thermal Monitoring
// =============================================================================

pub const ThermalStatus = struct {
    thermal_status: bool,
    thermal_status_log: bool,
    prochot_active: bool,
    prochot_log: bool,
    critical_temp: bool,
    critical_temp_log: bool,
    thermal_threshold1: bool,
    thermal_threshold1_log: bool,
    thermal_threshold2: bool,
    thermal_threshold2_log: bool,
    power_limit: bool,
    power_limit_log: bool,
    current_limit: bool,
    current_limit_log: bool,
    cross_domain_limit: bool,
    cross_domain_limit_log: bool,
    digital_readout: u7,
    resolution: u4,
    reading_valid: bool,
};

/// Read current thermal status of the processor.
pub fn readThermalStatus() ThermalStatus {
    const val = read(IA32_THERM_STATUS);
    return .{
        .thermal_status = (val & (1 << 0)) != 0,
        .thermal_status_log = (val & (1 << 1)) != 0,
        .prochot_active = (val & (1 << 2)) != 0,
        .prochot_log = (val & (1 << 3)) != 0,
        .critical_temp = (val & (1 << 4)) != 0,
        .critical_temp_log = (val & (1 << 5)) != 0,
        .thermal_threshold1 = (val & (1 << 6)) != 0,
        .thermal_threshold1_log = (val & (1 << 7)) != 0,
        .thermal_threshold2 = (val & (1 << 8)) != 0,
        .thermal_threshold2_log = (val & (1 << 9)) != 0,
        .power_limit = (val & (1 << 10)) != 0,
        .power_limit_log = (val & (1 << 11)) != 0,
        .current_limit = (val & (1 << 12)) != 0,
        .current_limit_log = (val & (1 << 13)) != 0,
        .cross_domain_limit = (val & (1 << 14)) != 0,
        .cross_domain_limit_log = (val & (1 << 15)) != 0,
        .digital_readout = @truncate((val >> 16) & 0x7F),
        .resolution = @truncate((val >> 27) & 0xF),
        .reading_valid = (val & (1 << 31)) != 0,
    };
}
