// =============================================================================
// Kernel Zxyphor - x86_64 CPU Operations
// =============================================================================
// Low-level CPU management functions for x86_64 architecture. Provides
// wrappers around privileged instructions and CPU feature detection.
// =============================================================================

const main = @import("../../main.zig");

// =============================================================================
// CPUID Feature Detection
// =============================================================================
pub const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

/// Execute the CPUID instruction with the given leaf (and optional subleaf)
pub fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );

    return CpuidResult{
        .eax = eax,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
    };
}

/// CPU vendor identification string
pub fn getVendorString() [12]u8 {
    const result = cpuid(0, 0);
    var vendor: [12]u8 = undefined;
    @as(*u32, @ptrCast(@alignCast(&vendor[0]))).* = result.ebx;
    @as(*u32, @ptrCast(@alignCast(&vendor[4]))).* = result.edx;
    @as(*u32, @ptrCast(@alignCast(&vendor[8]))).* = result.ecx;
    return vendor;
}

/// Check if 1GB huge pages are supported
pub fn supports1GBPages() bool {
    const result = cpuid(0x80000001, 0);
    return (result.edx & (1 << 26)) != 0;
}

/// Check if the CPU supports APIC
pub fn supportsApic() bool {
    const result = cpuid(1, 0);
    return (result.edx & (1 << 9)) != 0;
}

/// Check if SSE is supported
pub fn supportsSse() bool {
    const result = cpuid(1, 0);
    return (result.edx & (1 << 25)) != 0;
}

/// Check if SSE2 is supported
pub fn supportsSse2() bool {
    const result = cpuid(1, 0);
    return (result.edx & (1 << 26)) != 0;
}

/// Check if the CPU supports x2APIC mode
pub fn supportsX2Apic() bool {
    const result = cpuid(1, 0);
    return (result.ecx & (1 << 21)) != 0;
}

/// Check if FSGSBASE instructions are supported
pub fn supportsFsgsbase() bool {
    const result = cpuid(7, 0);
    return (result.ebx & (1 << 0)) != 0;
}

/// Check if SMEP (Supervisor Mode Execution Prevention) is supported
pub fn supportsSmep() bool {
    const result = cpuid(7, 0);
    return (result.ebx & (1 << 7)) != 0;
}

/// Check if SMAP (Supervisor Mode Access Prevention) is supported
pub fn supportsSmap() bool {
    const result = cpuid(7, 0);
    return (result.ebx & (1 << 20)) != 0;
}

/// Check if UMIP (User-Mode Instruction Prevention) is supported
pub fn supportsUmip() bool {
    const result = cpuid(7, 0);
    return (result.ecx & (1 << 2)) != 0;
}

/// Get the number of physical address bits supported
pub fn physicalAddressBits() u8 {
    const result = cpuid(0x80000008, 0);
    return @truncate(result.eax);
}

/// Get the number of virtual address bits supported
pub fn virtualAddressBits() u8 {
    const result = cpuid(0x80000008, 0);
    return @truncate(result.eax >> 8);
}

// =============================================================================
// Interrupt Control
// =============================================================================

/// Enable hardware interrupts (STI instruction)
pub inline fn enableInterrupts() void {
    asm volatile ("sti");
}

/// Disable hardware interrupts (CLI instruction)
pub inline fn disableInterrupts() void {
    asm volatile ("cli");
}

/// Check if interrupts are currently enabled
pub inline fn interruptsEnabled() bool {
    const flags = readFlags();
    return (flags & (1 << 9)) != 0; // IF flag
}

/// Disable interrupts and return whether they were previously enabled
pub inline fn disableInterruptsAndSave() bool {
    const were_enabled = interruptsEnabled();
    disableInterrupts();
    return were_enabled;
}

/// Restore interrupt state
pub inline fn restoreInterrupts(were_enabled: bool) void {
    if (were_enabled) {
        enableInterrupts();
    }
}

// =============================================================================
// CPU Halt and Power Management
// =============================================================================

/// Halt the CPU permanently (interrupts disabled, infinite HLT loop)
pub fn halt() noreturn {
    disableInterrupts();
    while (true) {
        asm volatile ("hlt");
    }
}

/// Halt until the next interrupt fires (power-saving idle)
pub inline fn haltUntilInterrupt() void {
    asm volatile ("hlt");
}

/// Pause hint for spin-wait loops (reduces power consumption and
/// avoids memory order violations on hyperthreaded CPUs)
pub inline fn spinHint() void {
    asm volatile ("pause");
}

/// Memory fence — ensures all preceding stores are visible
pub inline fn mfence() void {
    asm volatile ("mfence" ::: "memory");
}

/// Load fence — ensures all preceding loads are completed
pub inline fn lfence() void {
    asm volatile ("lfence" ::: "memory");
}

/// Store fence — ensures all preceding stores are completed
pub inline fn sfence() void {
    asm volatile ("sfence" ::: "memory");
}

// =============================================================================
// Port I/O Operations
// =============================================================================

/// Read a byte from an I/O port
pub inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

/// Write a byte to an I/O port
pub inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

/// Read a word (16-bit) from an I/O port
pub inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "N{dx}" (port),
    );
}

/// Write a word (16-bit) to an I/O port
pub inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "N{dx}" (port),
    );
}

/// Read a double word (32-bit) from an I/O port
pub inline fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "N{dx}" (port),
    );
}

/// Write a double word (32-bit) to an I/O port
pub inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
    );
}

/// Small I/O delay (used after PIC commands, etc.)
pub inline fn ioWait() void {
    outb(0x80, 0); // Port 0x80 is used for POST codes — safe to write
}

// =============================================================================
// Model-Specific Registers (MSR)
// =============================================================================

/// Read a Model-Specific Register
pub inline fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

/// Write a Model-Specific Register
pub inline fn wrmsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(value))),
          [high] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

// Common MSR addresses
pub const MSR_APIC_BASE: u32 = 0x1B;
pub const MSR_EFER: u32 = 0xC0000080;
pub const MSR_STAR: u32 = 0xC0000081;
pub const MSR_LSTAR: u32 = 0xC0000082;
pub const MSR_CSTAR: u32 = 0xC0000083;
pub const MSR_SFMASK: u32 = 0xC0000084;
pub const MSR_FS_BASE: u32 = 0xC0000100;
pub const MSR_GS_BASE: u32 = 0xC0000101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC0000102;
pub const MSR_TSC_AUX: u32 = 0xC0000103;

// EFER bits
pub const EFER_SCE: u64 = 1 << 0; // SYSCALL/SYSRET enable
pub const EFER_LME: u64 = 1 << 8; // Long mode enable
pub const EFER_LMA: u64 = 1 << 10; // Long mode active
pub const EFER_NXE: u64 = 1 << 11; // No-Execute enable

// =============================================================================
// Control Registers
// =============================================================================

pub inline fn readFlags() u64 {
    return asm volatile (
        \\ pushfq
        \\ popq %[result]
        : [result] "=r" (-> u64),
    );
}

/// Invalidate a specific TLB entry for the given virtual address
pub inline fn invlpg(addr: u64) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (addr),
        : "memory"
    );
}

/// Read the Time Stamp Counter
pub inline fn rdtsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

/// Serializing read of TSC (waits for all prior instructions to complete)
pub inline fn rdtscp() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtscp"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        :
        : "ecx"
    );
    return (@as(u64, high) << 32) | @as(u64, low);
}

// =============================================================================
// System Reset and Shutdown
// =============================================================================

/// Reboot the system via keyboard controller reset
pub fn reboot() noreturn {
    disableInterrupts();

    // Try the keyboard controller reset first
    // Wait for the input buffer to be empty
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((inb(0x64) & 0x02) == 0) break;
    }

    // Send reset command to keyboard controller
    outb(0x64, 0xFE);

    // If that didn't work, try triple-fault
    // Load a null IDT and trigger an interrupt
    const null_idt = packed struct {
        limit: u16 = 0,
        base: u64 = 0,
    }{};
    asm volatile ("lidt (%[idt])"
        :
        : [idt] "r" (&null_idt),
    );
    asm volatile ("int $3"); // Triple fault with null IDT

    halt();
}

/// Attempt to shut down the system via ACPI or QEMU debug port
pub fn shutdown() noreturn {
    disableInterrupts();

    // QEMU shutdown via debug port
    outw(0x604, 0x2000);

    // Bochs/old QEMU shutdown
    outw(0xB004, 0x2000);

    // VirtualBox shutdown
    outw(0x4004, 0x3400);

    // If nothing worked, just halt
    halt();
}

// =============================================================================
// CPU Feature Initialization
// =============================================================================
pub fn initializeFeatures() void {
    // Enable SYSCALL/SYSRET instruction support
    var efer = rdmsr(MSR_EFER);
    efer |= EFER_SCE; // Enable SYSCALL
    efer |= EFER_NXE; // Enable NX bit in page tables
    wrmsr(MSR_EFER, efer);

    main.klog(.info, "CPU: SYSCALL and NX bit enabled", .{});

    // Log detected CPU features
    const vendor = getVendorString();
    main.klog(.info, "CPU: Vendor = {s}", .{vendor[0..]});
    main.klog(.info, "CPU: Physical address bits = {d}", .{physicalAddressBits()});
    main.klog(.info, "CPU: Virtual address bits = {d}", .{virtualAddressBits()});

    if (supportsApic()) main.klog(.info, "CPU: APIC supported", .{});
    if (supportsX2Apic()) main.klog(.info, "CPU: x2APIC supported", .{});
    if (supportsSmep()) main.klog(.info, "CPU: SMEP supported", .{});
    if (supportsSmap()) main.klog(.info, "CPU: SMAP supported", .{});
}
