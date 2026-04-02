// =============================================================================
// Kernel Zxyphor - x86_64 Control Register Access
// =============================================================================
// Provides access to the x86_64 control registers (CR0-CR4) and debug
// registers. These registers control fundamental CPU behavior including
// paging, protected mode, and hardware breakpoints.
// =============================================================================

// =============================================================================
// CR0 — System Control Register
// =============================================================================
// Bit 0:  PE — Protected Mode Enable
// Bit 1:  MP — Monitor co-processor
// Bit 2:  EM — Emulation (if set, no FPU)
// Bit 3:  TS — Task Switched
// Bit 4:  ET — Extension Type (hardcoded to 1)
// Bit 5:  NE — Numeric Error
// Bit 16: WP — Write Protect (enforce read-only pages in kernel mode)
// Bit 18: AM — Alignment Mask
// Bit 29: NW — Not Write-through
// Bit 30: CD — Cache Disable
// Bit 31: PG — Paging Enable
// =============================================================================
pub const CR0_PE: u64 = 1 << 0;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_EM: u64 = 1 << 2;
pub const CR0_TS: u64 = 1 << 3;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_AM: u64 = 1 << 18;
pub const CR0_NW: u64 = 1 << 29;
pub const CR0_CD: u64 = 1 << 30;
pub const CR0_PG: u64 = 1 << 31;

pub inline fn readCr0() u64 {
    return asm volatile ("movq %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr0(value: u64) void {
    asm volatile ("movq %[value], %%cr0"
        :
        : [value] "r" (value),
        : .{ .memory = true }
    );
}

// =============================================================================
// CR2 — Page Fault Linear Address
// =============================================================================
// Holds the virtual address that caused the most recent page fault.
// Read-only for practical purposes (though technically writable).
// =============================================================================
pub inline fn readCr2() u64 {
    return asm volatile ("movq %%cr2, %[result]"
        : [result] "=r" (-> u64),
    );
}

// =============================================================================
// CR3 — Page Directory Base Register (PDBR)
// =============================================================================
// Holds the physical address of the top-level page table (PML4).
// Writing to CR3 flushes the entire TLB (unless PCID is used).
//
// Bits 0-11:  Flags (PCID when enabled, otherwise PCD/PWT)
// Bits 12-51: Physical address of PML4 table (4KB aligned)
// =============================================================================
pub inline fn readCr3() u64 {
    return asm volatile ("movq %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr3(value: u64) void {
    asm volatile ("movq %[value], %%cr3"
        :
        : [value] "r" (value),
        : .{ .memory = true }
    );
}

/// Flush the entire TLB by reloading CR3
pub inline fn flushTlb() void {
    writeCr3(readCr3());
}

// =============================================================================
// CR4 — Control Register 4 (extended CPU features)
// =============================================================================
// Bit 0:  VME — Virtual 8086 Mode Extensions
// Bit 1:  PVI — Protected-mode Virtual Interrupts
// Bit 2:  TSD — Time Stamp Disable (restrict RDTSC to ring 0)
// Bit 3:  DE  — Debugging Extensions
// Bit 4:  PSE — Page Size Extension (4MB pages in 32-bit mode)
// Bit 5:  PAE — Physical Address Extension (required for long mode)
// Bit 6:  MCE — Machine Check Exception
// Bit 7:  PGE — Page Global Enable (global pages not flushed on CR3 reload)
// Bit 8:  PCE — Performance Monitoring Counter Enable
// Bit 9:  OSFXSR — OS support for FXSAVE/FXRSTOR
// Bit 10: OSXMMEXCPT — OS support for unmasked SIMD exceptions
// Bit 11: UMIP — User-Mode Instruction Prevention
// Bit 12: LA57 — 5-level paging
// Bit 13: VMXE — VMX Enable (Intel VT-x)
// Bit 14: SMXE — SMX Enable (Intel TXT)
// Bit 16: FSGSBASE — RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
// Bit 17: PCIDE — PCID Enable
// Bit 18: OSXSAVE — XSAVE and Processor Extended States Enable
// Bit 20: SMEP — Supervisor Mode Execution Prevention
// Bit 21: SMAP — Supervisor Mode Access Prevention
// Bit 22: PKE — Protection Key Enable
// =============================================================================
pub const CR4_VME: u64 = 1 << 0;
pub const CR4_PVI: u64 = 1 << 1;
pub const CR4_TSD: u64 = 1 << 2;
pub const CR4_DE: u64 = 1 << 3;
pub const CR4_PSE: u64 = 1 << 4;
pub const CR4_PAE: u64 = 1 << 5;
pub const CR4_MCE: u64 = 1 << 6;
pub const CR4_PGE: u64 = 1 << 7;
pub const CR4_PCE: u64 = 1 << 8;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const CR4_UMIP: u64 = 1 << 11;
pub const CR4_LA57: u64 = 1 << 12;
pub const CR4_VMXE: u64 = 1 << 13;
pub const CR4_SMXE: u64 = 1 << 14;
pub const CR4_FSGSBASE: u64 = 1 << 16;
pub const CR4_PCIDE: u64 = 1 << 17;
pub const CR4_OSXSAVE: u64 = 1 << 18;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
pub const CR4_PKE: u64 = 1 << 22;

pub inline fn readCr4() u64 {
    return asm volatile ("movq %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr4(value: u64) void {
    asm volatile ("movq %[value], %%cr4"
        :
        : [value] "r" (value),
        : .{ .memory = true }
    );
}

/// Enable a CR4 feature flag
pub inline fn enableCr4Flag(flag: u64) void {
    writeCr4(readCr4() | flag);
}

/// Disable a CR4 feature flag
pub inline fn disableCr4Flag(flag: u64) void {
    writeCr4(readCr4() & ~flag);
}

// =============================================================================
// CR8 — Task Priority Register (TPR) — used by APIC
// =============================================================================
pub inline fn readCr8() u64 {
    return asm volatile ("movq %%cr8, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeCr8(value: u64) void {
    asm volatile ("movq %[value], %%cr8"
        :
        : [value] "r" (value),
    );
}

// =============================================================================
// Debug Registers (DR0-DR7)
// =============================================================================
// DR0-DR3: Hardware breakpoint addresses
// DR6: Debug status (which breakpoint triggered)
// DR7: Debug control (enable/disable breakpoints, conditions)
// =============================================================================
pub inline fn readDr0() u64 {
    return asm volatile ("movq %%dr0, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeDr0(value: u64) void {
    asm volatile ("movq %[value], %%dr0"
        :
        : [value] "r" (value),
    );
}

pub inline fn readDr1() u64 {
    return asm volatile ("movq %%dr1, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeDr1(value: u64) void {
    asm volatile ("movq %[value], %%dr1"
        :
        : [value] "r" (value),
    );
}

pub inline fn readDr2() u64 {
    return asm volatile ("movq %%dr2, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeDr2(value: u64) void {
    asm volatile ("movq %[value], %%dr2"
        :
        : [value] "r" (value),
    );
}

pub inline fn readDr3() u64 {
    return asm volatile ("movq %%dr3, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeDr3(value: u64) void {
    asm volatile ("movq %[value], %%dr3"
        :
        : [value] "r" (value),
    );
}

pub inline fn readDr6() u64 {
    return asm volatile ("movq %%dr6, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeDr6(value: u64) void {
    asm volatile ("movq %[value], %%dr6"
        :
        : [value] "r" (value),
    );
}

pub inline fn readDr7() u64 {
    return asm volatile ("movq %%dr7, %[result]"
        : [result] "=r" (-> u64),
    );
}

pub inline fn writeDr7(value: u64) void {
    asm volatile ("movq %[value], %%dr7"
        :
        : [value] "r" (value),
    );
}

// =============================================================================
// Hardware breakpoint management
// =============================================================================
pub const BreakpointCondition = enum(u2) {
    execution = 0b00,
    data_write = 0b01,
    io_readwrite = 0b10,
    data_readwrite = 0b11,
};

pub const BreakpointSize = enum(u2) {
    byte = 0b00,
    word = 0b01,
    qword = 0b10,
    dword = 0b11,
};

/// Set a hardware breakpoint
pub fn setBreakpoint(index: u2, address: u64, condition: BreakpointCondition, size: BreakpointSize) void {
    // Set the breakpoint address
    switch (index) {
        0 => writeDr0(address),
        1 => writeDr1(address),
        2 => writeDr2(address),
        3 => writeDr3(address),
    }

    // Configure DR7
    var dr7 = readDr7();
    const offset: u6 = @as(u6, index) * 4 + 16;

    // Clear existing condition and size bits
    dr7 &= ~(@as(u64, 0xF) << offset);

    // Set new condition and size
    dr7 |= @as(u64, @intFromEnum(condition)) << offset;
    dr7 |= @as(u64, @intFromEnum(size)) << (offset + 2);

    // Enable the breakpoint (local enable)
    dr7 |= @as(u64, 1) << (@as(u6, index) * 2);

    writeDr7(dr7);
}

/// Clear a hardware breakpoint
pub fn clearBreakpoint(index: u2) void {
    var dr7 = readDr7();
    // Disable local enable for this breakpoint
    dr7 &= ~(@as(u64, 1) << (@as(u6, index) * 2));
    writeDr7(dr7);
}
