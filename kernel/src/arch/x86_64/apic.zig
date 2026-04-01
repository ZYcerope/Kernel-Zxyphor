// =============================================================================
// Kernel Zxyphor - Local APIC (Advanced Programmable Interrupt Controller)
// =============================================================================
// The Local APIC is the per-CPU interrupt controller in modern x86 systems.
// It handles:
//   - Local interrupt sources (timer, performance counters, thermal sensor)
//   - Inter-Processor Interrupts (IPI) for SMP
//   - External interrupt routing from the I/O APIC
//
// Each CPU core has its own Local APIC mapped at a physical address
// (default 0xFEE00000) into the kernel's virtual address space.
// =============================================================================

const main = @import("../../main.zig");
const cpu = @import("cpu.zig");

// =============================================================================
// APIC register offsets (relative to APIC base address)
// =============================================================================
const APIC_ID: u32 = 0x020; // Local APIC ID
const APIC_VERSION: u32 = 0x030; // APIC version
const APIC_TPR: u32 = 0x080; // Task Priority Register
const APIC_APR: u32 = 0x090; // Arbitration Priority Register
const APIC_PPR: u32 = 0x0A0; // Processor Priority Register
const APIC_EOI: u32 = 0x0B0; // End of Interrupt
const APIC_RRD: u32 = 0x0C0; // Remote Read Register
const APIC_LDR: u32 = 0x0D0; // Logical Destination Register
const APIC_DFR: u32 = 0x0E0; // Destination Format Register
const APIC_SVR: u32 = 0x0F0; // Spurious Interrupt Vector Register
const APIC_ISR_BASE: u32 = 0x100; // In-Service Register (8 registers)
const APIC_TMR_BASE: u32 = 0x180; // Trigger Mode Register (8 registers)
const APIC_IRR_BASE: u32 = 0x200; // Interrupt Request Register (8 registers)
const APIC_ESR: u32 = 0x280; // Error Status Register
const APIC_ICR_LOW: u32 = 0x300; // Interrupt Command Register (low)
const APIC_ICR_HIGH: u32 = 0x310; // Interrupt Command Register (high)
const APIC_LVT_TIMER: u32 = 0x320; // LVT Timer Register
const APIC_LVT_THERMAL: u32 = 0x330; // LVT Thermal Sensor
const APIC_LVT_PERF: u32 = 0x340; // LVT Performance Counter
const APIC_LVT_LINT0: u32 = 0x350; // LVT LINT0 Register
const APIC_LVT_LINT1: u32 = 0x360; // LVT LINT1 Register
const APIC_LVT_ERROR: u32 = 0x370; // LVT Error Register
const APIC_TIMER_ICR: u32 = 0x380; // Timer Initial Count Register
const APIC_TIMER_CCR: u32 = 0x390; // Timer Current Count Register
const APIC_TIMER_DCR: u32 = 0x3E0; // Timer Divide Configuration Register

// SVR bits
const SVR_APIC_ENABLE: u32 = 1 << 8;
const SVR_FOCUS_DISABLE: u32 = 1 << 9;

// LVT delivery modes
const LVT_FIXED: u32 = 0x000;
const LVT_SMI: u32 = 0x200;
const LVT_NMI: u32 = 0x400;
const LVT_INIT: u32 = 0x500;
const LVT_EXT_INT: u32 = 0xF00;

// LVT flags
const LVT_MASKED: u32 = 1 << 16;
const LVT_LEVEL_TRIGGER: u32 = 1 << 15;
const LVT_REMOTE_IRR: u32 = 1 << 14;
const LVT_ACTIVE_LOW: u32 = 1 << 13;
const LVT_PENDING: u32 = 1 << 12;

// Timer modes
const TIMER_ONE_SHOT: u32 = 0x00000;
const TIMER_PERIODIC: u32 = 0x20000;
const TIMER_TSC_DEADLINE: u32 = 0x40000;

// Timer divide values
const TIMER_DIV_1: u32 = 0xB;
const TIMER_DIV_2: u32 = 0x0;
const TIMER_DIV_4: u32 = 0x1;
const TIMER_DIV_8: u32 = 0x2;
const TIMER_DIV_16: u32 = 0x3;
const TIMER_DIV_32: u32 = 0x8;
const TIMER_DIV_64: u32 = 0x9;
const TIMER_DIV_128: u32 = 0xA;

// ICR delivery modes
const ICR_FIXED: u32 = 0x00000;
const ICR_LOWEST: u32 = 0x00100;
const ICR_SMI: u32 = 0x00200;
const ICR_NMI: u32 = 0x00400;
const ICR_INIT: u32 = 0x00500;
const ICR_SIPI: u32 = 0x00600;

// ICR destination shorthand
const ICR_DEST_FIELD: u32 = 0x000000;
const ICR_DEST_SELF: u32 = 0x040000;
const ICR_DEST_ALL: u32 = 0x080000;
const ICR_DEST_ALL_BUT_SELF: u32 = 0x0C0000;

// ICR flags
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
const ICR_LEVEL_DEASSERT: u32 = 0;

// =============================================================================
// APIC state
// =============================================================================
var apic_base_addr: u64 = 0xFEE00000; // Default APIC base
var apic_enabled: bool = false;
var apic_timer_ticks_per_ms: u32 = 0;

// APIC Timer interrupt vector
const APIC_TIMER_VECTOR: u8 = 48;
const APIC_SPURIOUS_VECTOR: u8 = 0xFF;
const APIC_ERROR_VECTOR: u8 = 49;

// =============================================================================
// APIC register access (memory-mapped I/O)
// =============================================================================
fn readRegister(offset: u32) u32 {
    const ptr = @as(*volatile u32, @ptrFromInt(@as(usize, @truncate(apic_base_addr + offset))));
    return ptr.*;
}

fn writeRegister(offset: u32, value: u32) void {
    const ptr = @as(*volatile u32, @ptrFromInt(@as(usize, @truncate(apic_base_addr + offset))));
    ptr.* = value;
}

// =============================================================================
// Initialize the Local APIC
// =============================================================================
pub fn initialize() void {
    // Read the APIC base address from the MSR
    const base_msr = cpu.rdmsr(cpu.MSR_APIC_BASE);
    apic_base_addr = base_msr & 0xFFFFF000;

    // Enable the APIC via MSR if not already enabled
    if ((base_msr & (1 << 11)) == 0) {
        cpu.wrmsr(cpu.MSR_APIC_BASE, base_msr | (1 << 11));
    }

    // Map the APIC registers into kernel virtual address space
    main.vmm.mapMmio(apic_base_addr, 4096) catch {
        main.klog(.err, "APIC: Failed to map APIC registers", .{});
        return;
    };

    // Enable the APIC through the Spurious Interrupt Vector Register
    writeRegister(APIC_SVR, SVR_APIC_ENABLE | APIC_SPURIOUS_VECTOR);

    // Clear error register (write before read)
    writeRegister(APIC_ESR, 0);
    _ = readRegister(APIC_ESR);

    // Set task priority to 0 (accept all interrupts)
    writeRegister(APIC_TPR, 0);

    // Mask all LVT entries initially
    writeRegister(APIC_LVT_TIMER, LVT_MASKED);
    writeRegister(APIC_LVT_THERMAL, LVT_MASKED);
    writeRegister(APIC_LVT_PERF, LVT_MASKED);
    writeRegister(APIC_LVT_LINT0, LVT_MASKED);
    writeRegister(APIC_LVT_LINT1, LVT_MASKED);
    writeRegister(APIC_LVT_ERROR, APIC_ERROR_VECTOR); // Error vector unmasked

    apic_enabled = true;

    const apic_id = getId();
    const version = getVersion();

    main.klog(.info, "APIC: Enabled (ID={d}, Version=0x{x}, Base=0x{x})", .{
        apic_id,
        version,
        apic_base_addr,
    });
}

// =============================================================================
// APIC information
// =============================================================================

/// Get the Local APIC ID for this CPU
pub fn getId() u8 {
    return @truncate(readRegister(APIC_ID) >> 24);
}

/// Get the APIC version
pub fn getVersion() u8 {
    return @truncate(readRegister(APIC_VERSION));
}

/// Get the maximum LVT entry count
pub fn getMaxLvt() u8 {
    return @truncate((readRegister(APIC_VERSION) >> 16) & 0xFF);
}

/// Check if the APIC is enabled
pub fn isEnabled() bool {
    return apic_enabled;
}

// =============================================================================
// End of Interrupt
// =============================================================================

/// Send End-of-Interrupt to the Local APIC
pub fn sendEoi() void {
    writeRegister(APIC_EOI, 0);
}

// =============================================================================
// APIC Timer
// =============================================================================

/// Calibrate the APIC timer using the PIT as a reference
pub fn calibrateTimer() void {
    // Set divider to 16
    writeRegister(APIC_TIMER_DCR, TIMER_DIV_16);

    // Start with max count
    writeRegister(APIC_TIMER_ICR, 0xFFFFFFFF);

    // Wait 10ms using PIT
    main.pit.busyWaitMs(10);

    // Read how many ticks elapsed
    const remaining = readRegister(APIC_TIMER_CCR);
    const elapsed = @as(u32, 0xFFFFFFFF) - remaining;

    // Stop the timer
    writeRegister(APIC_LVT_TIMER, LVT_MASKED);

    // Calculate ticks per ms
    apic_timer_ticks_per_ms = elapsed / 10;

    main.klog(.info, "APIC Timer: {d} ticks/ms", .{apic_timer_ticks_per_ms});
}

/// Start the APIC timer in periodic mode
pub fn startTimer(ms: u32) void {
    writeRegister(APIC_TIMER_DCR, TIMER_DIV_16);
    writeRegister(APIC_LVT_TIMER, TIMER_PERIODIC | APIC_TIMER_VECTOR);
    writeRegister(APIC_TIMER_ICR, apic_timer_ticks_per_ms * ms);
}

/// Stop the APIC timer
pub fn stopTimer() void {
    writeRegister(APIC_LVT_TIMER, LVT_MASKED);
    writeRegister(APIC_TIMER_ICR, 0);
}

// =============================================================================
// Inter-Processor Interrupts (IPI)
// =============================================================================

/// Wait for the ICR to be ready (delivery status bit clear)
fn waitIcrReady() void {
    while ((readRegister(APIC_ICR_LOW) & (1 << 12)) != 0) {
        cpu.spinHint();
    }
}

/// Send an IPI to a specific CPU
pub fn sendIpi(target_apic_id: u8, vector: u8) void {
    waitIcrReady();
    writeRegister(APIC_ICR_HIGH, @as(u32, target_apic_id) << 24);
    writeRegister(APIC_ICR_LOW, ICR_FIXED | @as(u32, vector));
}

/// Send an INIT IPI to a specific CPU
pub fn sendInitIpi(target_apic_id: u8) void {
    waitIcrReady();
    writeRegister(APIC_ICR_HIGH, @as(u32, target_apic_id) << 24);
    writeRegister(APIC_ICR_LOW, ICR_INIT | ICR_LEVEL_ASSERT);

    // De-assert
    waitIcrReady();
    writeRegister(APIC_ICR_HIGH, @as(u32, target_apic_id) << 24);
    writeRegister(APIC_ICR_LOW, ICR_INIT | ICR_LEVEL_DEASSERT);
}

/// Send a Startup IPI (SIPI) to a specific CPU
pub fn sendStartupIpi(target_apic_id: u8, vector_page: u8) void {
    waitIcrReady();
    writeRegister(APIC_ICR_HIGH, @as(u32, target_apic_id) << 24);
    writeRegister(APIC_ICR_LOW, ICR_SIPI | @as(u32, vector_page));
}

/// Send an IPI to all other CPUs
pub fn sendIpiAllButSelf(vector: u8) void {
    waitIcrReady();
    writeRegister(APIC_ICR_LOW, ICR_DEST_ALL_BUT_SELF | ICR_FIXED | @as(u32, vector));
}

/// Send an NMI to a specific CPU
pub fn sendNmi(target_apic_id: u8) void {
    waitIcrReady();
    writeRegister(APIC_ICR_HIGH, @as(u32, target_apic_id) << 24);
    writeRegister(APIC_ICR_LOW, ICR_NMI);
}
