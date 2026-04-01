// =============================================================================
// Kernel Zxyphor - Task State Segment (TSS)
// =============================================================================
// The TSS in 64-bit long mode serves a different purpose than in 32-bit mode.
// It primarily provides:
//   1. Stack pointers for privilege level transitions (RSP0, RSP1, RSP2)
//   2. Interrupt Stack Table (IST) entries for handling critical exceptions
//      on known-good stacks (e.g., double fault, NMI)
//   3. I/O permission bitmap base
//
// The IST mechanism is crucial for safely handling exceptions like double
// fault — if the kernel stack is corrupted, the double fault handler needs
// its own private stack to execute on.
// =============================================================================

const main = @import("../main.zig");
const gdt = @import("gdt.zig");

// =============================================================================
// TSS Structure (104 bytes in 64-bit mode)
// =============================================================================
pub const Tss = extern struct {
    reserved0: u32 = 0,

    // Privilege level stack pointers — loaded when transitioning rings
    // RSP0: Stack used when transitioning to ring 0 (kernel) from user mode
    rsp0: u64 = 0,
    // RSP1: Stack for ring 1 (not used in most OS designs)
    rsp1: u64 = 0,
    // RSP2: Stack for ring 2 (not used in most OS designs)
    rsp2: u64 = 0,

    reserved1: u64 = 0,

    // Interrupt Stack Table (IST) — independent stacks for specific interrupts
    // IST1: Used for double fault (#DF) — must be valid even if kernel stack overflows
    ist1: u64 = 0,
    // IST2: Used for NMI — non-maskable interrupt needs guaranteed stack space
    ist2: u64 = 0,
    // IST3: Used for machine check exceptions
    ist3: u64 = 0,
    // IST4-IST7: Available for other critical interrupt handlers
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,

    reserved2: u64 = 0,
    reserved3: u16 = 0,

    // I/O permission bitmap offset from TSS base
    // If >= TSS limit, no I/O permission bitmap is used (all I/O restricted)
    iopb_offset: u16 = @sizeOf(Tss),
};

// =============================================================================
// IST stack sizes — each IST stack gets its own page-aligned memory region
// =============================================================================
const IST_STACK_SIZE: usize = 4096 * 4; // 16KB per IST stack

// Stack storage for IST entries (statically allocated for bootstrap)
var ist1_stack: [IST_STACK_SIZE]u8 align(16) = [_]u8{0} ** IST_STACK_SIZE;
var ist2_stack: [IST_STACK_SIZE]u8 align(16) = [_]u8{0} ** IST_STACK_SIZE;
var ist3_stack: [IST_STACK_SIZE]u8 align(16) = [_]u8{0} ** IST_STACK_SIZE;

// Kernel interrupt stack (used for RSP0 — the stack when entering kernel from user)
const KERNEL_STACK_SIZE: usize = 4096 * 8; // 32KB kernel stack
var kernel_stack: [KERNEL_STACK_SIZE]u8 align(16) = [_]u8{0} ** KERNEL_STACK_SIZE;

// =============================================================================
// Global TSS instance
// =============================================================================
var tss: Tss = Tss{};

// =============================================================================
// Initialize the TSS and install it into the GDT
// =============================================================================
pub fn initialize() void {
    // Set up the kernel stack pointer (RSP0)
    // When a user-mode interrupt occurs, the CPU loads RSP from TSS.RSP0
    // Stack grows downward, so we point to the TOP of the stack region
    tss.rsp0 = @intFromPtr(&kernel_stack) + KERNEL_STACK_SIZE;

    // Set up IST stacks
    // IST1: Double fault handler stack
    tss.ist1 = @intFromPtr(&ist1_stack) + IST_STACK_SIZE;

    // IST2: NMI handler stack
    tss.ist2 = @intFromPtr(&ist2_stack) + IST_STACK_SIZE;

    // IST3: Machine check handler stack
    tss.ist3 = @intFromPtr(&ist3_stack) + IST_STACK_SIZE;

    // I/O permission bitmap starts right after the TSS structure
    // No bitmap actually present, so all user I/O is restricted
    tss.iopb_offset = @sizeOf(Tss);

    // Install the TSS descriptor into the GDT
    const tss_base = @intFromPtr(&tss);
    const tss_limit: u32 = @sizeOf(Tss) - 1;
    gdt.installTssDescriptor(tss_base, tss_limit);

    // Load the Task Register (TR) to point to our TSS
    gdt.loadTr();

    main.klog(.info, "TSS: Initialized (RSP0=0x{x}, IST1=0x{x})", .{
        tss.rsp0,
        tss.ist1,
    });
}

// =============================================================================
// Update the kernel stack pointer (called during context switch)
// When switching to a user process, we must update RSP0 so that if the
// process triggers a kernel entry (syscall/interrupt), the CPU uses the
// correct kernel stack for that process.
// =============================================================================
pub fn setKernelStack(stack_top: u64) void {
    tss.rsp0 = stack_top;
}

/// Get the current kernel stack pointer
pub fn getKernelStack() u64 {
    return tss.rsp0;
}

/// Get a pointer to the TSS (for debugging)
pub fn getTss() *const Tss {
    return &tss;
}

/// Set a specific IST entry's stack pointer
pub fn setIst(index: u3, stack_top: u64) void {
    switch (index) {
        1 => tss.ist1 = stack_top,
        2 => tss.ist2 = stack_top,
        3 => tss.ist3 = stack_top,
        4 => tss.ist4 = stack_top,
        5 => tss.ist5 = stack_top,
        6 => tss.ist6 = stack_top,
        7 => tss.ist7 = stack_top,
        else => {},
    }
}
