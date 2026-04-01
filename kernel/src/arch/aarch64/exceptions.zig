// =============================================================================
// Zxyphor Kernel — ARM64 Exception Vectors & Handler Framework
// =============================================================================
// Implements the complete ARMv8-A exception handling model with four exception
// vector tables (Current EL with SP0, Current EL with SPx, Lower EL AArch64,
// Lower EL AArch32). Each table has 4 entries: Synchronous, IRQ, FIQ, SError.
//
// Exception sources handled:
//   - Synchronous: SVC, HVC, SMC, data/instruction abort, alignment, BRK,
//                  illegal execution, FP trap, SVE trap, BTI violation,
//                  PAC failure, MTE check, pointer auth
//   - IRQ: Routed to GICv3 handler
//   - FIQ: Group 0 secure interrupts  
//   - SError: Asynchronous external abort, RAS errors
//
// The vector table is aligned to 2KB (0x800) as required by VBAR_EL1.
// Each vector entry is 128 bytes (32 instructions), which branches to
// the full handler that saves/restores all 31 general-purpose registers,
// SP, PSTATE (SPSR), and return address (ELR).
// =============================================================================

const gic = @import("gic_v3.zig");
const mmu = @import("mmu.zig");

// ── Exception Syndrome Register (ESR_EL1) Decoding ────────────────────────
pub const ExceptionClass = enum(u6) {
    unknown                 = 0b000000, // Unknown reason
    trapped_wfi_wfe         = 0b000001, // Trapped WFI/WFE
    trapped_mcr_mrc_cp15    = 0b000011, // Trapped MCR/MRC (coproc 15)
    trapped_mcrr_mrrc_cp15  = 0b000100, // Trapped MCRR/MRRC (coproc 15)
    trapped_mcr_mrc_cp14    = 0b000101, // Trapped MCR/MRC (coproc 14)
    trapped_ldc_stc         = 0b000110, // Trapped LDC/STC
    svg_simd_fp_access      = 0b000111, // SVE/SIMD/FP access trap
    trapped_ld64b_st64b     = 0b001010, // Trapped LD64B/ST64B
    trapped_mrrc_cp14       = 0b001100, // Trapped MRRC (coproc 14)
    branch_target_exception = 0b001101, // BTI violation
    illegal_execution       = 0b001110, // Illegal Execution State
    svc_aarch32             = 0b010001, // SVC from AArch32
    svc_aarch64             = 0b010101, // SVC from AArch64
    trapped_msr_mrs_sys     = 0b011000, // Trapped MSR/MRS/System instruction
    sve_access              = 0b011001, // SVE access trap
    trapped_eret            = 0b011010, // Trapped ERET/ERETAA/ERETAB
    pac_failure             = 0b011100, // PAC failure
    inst_abort_lower_el     = 0b100000, // Instruction Abort (lower EL)
    inst_abort_same_el      = 0b100001, // Instruction Abort (same EL)
    pc_alignment            = 0b100010, // PC Alignment fault
    data_abort_lower_el     = 0b100100, // Data Abort (lower EL)
    data_abort_same_el      = 0b100101, // Data Abort (same EL)
    sp_alignment            = 0b100110, // SP Alignment fault
    trapped_fp_aarch32      = 0b101000, // Trapped FP (AArch32)
    trapped_fp_aarch64      = 0b101100, // Trapped FP (AArch64)
    serror                  = 0b101111, // SError
    breakpoint_lower_el     = 0b110000, // HW Breakpoint (lower EL)
    breakpoint_same_el      = 0b110001, // HW Breakpoint (same EL)
    software_step_lower_el  = 0b110010, // Software Step (lower EL)
    software_step_same_el   = 0b110011, // Software Step (same EL)
    watchpoint_lower_el     = 0b110100, // Watchpoint (lower EL)
    watchpoint_same_el      = 0b110101, // Watchpoint (same EL)
    brk_aarch32             = 0b111000, // BRK from AArch32
    brk_aarch64             = 0b111100, // BRK from AArch64
    _,
};

// ── Data/Instruction Fault Status Code (DFSC/IFSC) ────────────────────────
pub const FaultStatusCode = enum(u6) {
    addr_size_l0        = 0b000000,
    addr_size_l1        = 0b000001,
    addr_size_l2        = 0b000010,
    addr_size_l3        = 0b000011,
    translation_l0      = 0b000100,
    translation_l1      = 0b000101,
    translation_l2      = 0b000110,
    translation_l3      = 0b000111,
    access_flag_l0      = 0b001000,
    access_flag_l1      = 0b001001,
    access_flag_l2      = 0b001010,
    access_flag_l3      = 0b001011,
    permission_l0       = 0b001100,
    permission_l1       = 0b001101,
    permission_l2       = 0b001110,
    permission_l3       = 0b001111,
    sync_ext_abort      = 0b010000,
    sync_ext_abort_l_1  = 0b010011, // on walk level -1
    sync_parity         = 0b011000,
    sync_parity_walk    = 0b011011,
    alignment           = 0b100001,
    tlb_conflict        = 0b110000,
    unsupported_atomic  = 0b110001,
    impl_defined_lockdown = 0b110100,
    impl_defined_atomic = 0b110101,
    _,
};

// ── Saved Register Context ────────────────────────────────────────────────
// Complete register state saved on exception entry
pub const ExceptionContext = extern struct {
    // General-purpose registers x0-x30
    regs: [31]u64,
    // Saved Program Status Register
    spsr: u64,
    // Exception Link Register (return address)
    elr: u64,
    // Stack pointer at time of exception
    sp: u64,
    // Fault address register (for data/instruction aborts)
    far: u64,
    // Exception Syndrome Register
    esr: u64,
    // Thread Process ID register (TLS base)
    tpidr: u64,
    // FP/SIMD saved state indicator
    fp_simd_saved: u64,

    const Self = @This();

    pub fn getExceptionClass(self: *const Self) ExceptionClass {
        return @enumFromInt(@as(u6, @truncate(self.esr >> 26)));
    }

    pub fn getISS(self: *const Self) u25 {
        return @truncate(self.esr & 0x1FFFFFF);
    }

    pub fn getFaultStatusCode(self: *const Self) FaultStatusCode {
        return @enumFromInt(@as(u6, @truncate(self.esr & 0x3F)));
    }

    pub fn isWriteFault(self: *const Self) bool {
        return (self.esr >> 6) & 1 == 1; // WnR bit
    }

    pub fn isUserMode(self: *const Self) bool {
        return (self.spsr & 0xF) == 0; // EL0t
    }

    pub fn getSystemCallNumber(self: *const Self) u16 {
        return @truncate(self.esr & 0xFFFF); // ISS[15:0] for SVC
    }

    pub fn getReturnAddress(self: *const Self) u64 {
        return self.elr;
    }

    pub fn getSyscallArg(self: *const Self, n: u3) u64 {
        return self.regs[n]; // x0-x7 for syscall arguments
    }

    pub fn setSyscallReturn(self: *Self, val: u64) void {
        self.regs[0] = val; // x0 for return value
    }

    pub fn setSyscallError(self: *Self, err: u64) void {
        self.regs[0] = err;
        // Set carry flag in SPSR to indicate error (common convention)
        self.spsr |= (1 << 29); // C flag
    }
};

// ── Exception Statistics ──────────────────────────────────────────────────
pub const ExceptionStats = struct {
    sync_count: u64 = 0,
    irq_count: u64 = 0,
    fiq_count: u64 = 0,
    serror_count: u64 = 0,
    syscall_count: u64 = 0,
    page_fault_count: u64 = 0,
    alignment_fault_count: u64 = 0,
    undefined_count: u64 = 0,
    breakpoint_count: u64 = 0,
    watchpoint_count: u64 = 0,
    bti_violation_count: u64 = 0,
    pac_failure_count: u64 = 0,
    fp_trap_count: u64 = 0,
    sve_trap_count: u64 = 0,
};

var exception_stats: ExceptionStats = .{};
pub var nested_exception_depth: u32 = 0;
pub const MAX_NESTED_EXCEPTIONS: u32 = 4;

// ── Exception Handler Type ────────────────────────────────────────────────
pub const ExceptionHandler = *const fn (*ExceptionContext) void;

var sync_handlers: [64]?ExceptionHandler = [_]?ExceptionHandler{null} ** 64;
var irq_handler: ?ExceptionHandler = null;
var fiq_handler: ?ExceptionHandler = null;
var serror_handler: ?ExceptionHandler = null;

pub fn registerSyncHandler(ec: ExceptionClass, handler: ExceptionHandler) void {
    sync_handlers[@intFromEnum(ec)] = handler;
}

pub fn registerIrqHandler(handler: ExceptionHandler) void {
    irq_handler = handler;
}

pub fn registerFiqHandler(handler: ExceptionHandler) void {
    fiq_handler = handler;
}

pub fn registerSErrorHandler(handler: ExceptionHandler) void {
    serror_handler = handler;
}

// ── Main Exception Entry Points ───────────────────────────────────────────
// These are called from the assembly trampolines after saving context

export fn handleSyncException(ctx: *ExceptionContext) callconv(.C) void {
    exception_stats.sync_count += 1;
    nested_exception_depth += 1;

    if (nested_exception_depth > MAX_NESTED_EXCEPTIONS) {
        panicNested(ctx);
        return;
    }

    const ec = ctx.getExceptionClass();

    switch (ec) {
        .svc_aarch64 => {
            exception_stats.syscall_count += 1;
            handleSyscall(ctx);
        },
        .data_abort_lower_el, .data_abort_same_el => {
            exception_stats.page_fault_count += 1;
            handleDataAbort(ctx);
        },
        .inst_abort_lower_el, .inst_abort_same_el => {
            exception_stats.page_fault_count += 1;
            handleInstructionAbort(ctx);
        },
        .sp_alignment, .pc_alignment => {
            exception_stats.alignment_fault_count += 1;
            handleAlignmentFault(ctx);
        },
        .breakpoint_lower_el, .breakpoint_same_el => {
            exception_stats.breakpoint_count += 1;
            handleBreakpoint(ctx);
        },
        .watchpoint_lower_el, .watchpoint_same_el => {
            exception_stats.watchpoint_count += 1;
            handleWatchpoint(ctx);
        },
        .software_step_lower_el, .software_step_same_el => {
            handleSingleStep(ctx);
        },
        .brk_aarch64 => {
            exception_stats.breakpoint_count += 1;
            handleBrkInstruction(ctx);
        },
        .svg_simd_fp_access, .trapped_fp_aarch64 => {
            exception_stats.fp_trap_count += 1;
            handleFpTrap(ctx);
        },
        .sve_access => {
            exception_stats.sve_trap_count += 1;
            handleSveTrap(ctx);
        },
        .branch_target_exception => {
            exception_stats.bti_violation_count += 1;
            handleBtiViolation(ctx);
        },
        .pac_failure => {
            exception_stats.pac_failure_count += 1;
            handlePacFailure(ctx);
        },
        .illegal_execution => {
            exception_stats.undefined_count += 1;
            handleIllegalExecution(ctx);
        },
        .trapped_msr_mrs_sys => {
            handleTrappedSystemReg(ctx);
        },
        .trapped_wfi_wfe => {
            handleTrappedWfiWfe(ctx);
        },
        else => {
            // Check custom handlers
            const ec_val = @intFromEnum(ec);
            if (ec_val < sync_handlers.len) {
                if (sync_handlers[ec_val]) |handler| {
                    handler(ctx);
                    nested_exception_depth -= 1;
                    return;
                }
            }
            handleUnknownException(ctx);
        },
    }

    nested_exception_depth -= 1;
}

export fn handleIrqException(ctx: *ExceptionContext) callconv(.C) void {
    exception_stats.irq_count += 1;
    nested_exception_depth += 1;

    // Route to GIC handler
    gic.handleIrq();

    if (irq_handler) |handler| {
        handler(ctx);
    }

    nested_exception_depth -= 1;
}

export fn handleFiqException(ctx: *ExceptionContext) callconv(.C) void {
    exception_stats.fiq_count += 1;
    nested_exception_depth += 1;

    if (fiq_handler) |handler| {
        handler(ctx);
    }

    nested_exception_depth -= 1;
}

export fn handleSErrorException(ctx: *ExceptionContext) callconv(.C) void {
    exception_stats.serror_count += 1;
    nested_exception_depth += 1;

    // SError is a serious hardware error — attempt recovery or panic
    const iss = ctx.getISS();
    const aet = (iss >> 10) & 0x7; // Asynchronous Error Type
    _ = aet;

    if (serror_handler) |handler| {
        handler(ctx);
    } else {
        // Default: panic on SError
        panicException("SError (Asynchronous External Abort)", ctx);
    }

    nested_exception_depth -= 1;
}

// ── Specific Exception Handlers ───────────────────────────────────────────
fn handleSyscall(ctx: *ExceptionContext) void {
    const syscall_num = ctx.getSystemCallNumber();
    const arg0 = ctx.getSyscallArg(0);
    const arg1 = ctx.getSyscallArg(1);
    const arg2 = ctx.getSyscallArg(2);
    const arg3 = ctx.getSyscallArg(3);
    const arg4 = ctx.getSyscallArg(4);
    const arg5 = ctx.getSyscallArg(5);
    _ = arg0;
    _ = arg1;
    _ = arg2;
    _ = arg3;
    _ = arg4;
    _ = arg5;

    // Dispatch to syscall table (implemented in syscall subsystem)
    // For now, return -ENOSYS
    _ = syscall_num;
    ctx.setSyscallReturn(@bitCast(@as(i64, -38))); // -ENOSYS

    // Advance PC past SVC instruction (already done by hardware on AArch64)
}

fn handleDataAbort(ctx: *ExceptionContext) void {
    const fault = mmu.decodeFault(ctx.esr, ctx.far);

    switch (fault.fault_type) {
        .translation => {
            // Missing page — attempt demand paging
            if (!demandPage(ctx, fault.vaddr, fault.is_write)) {
                if (fault.is_user) {
                    sendSignalToCurrentProcess(11); // SIGSEGV
                } else {
                    panicException("Kernel data abort (translation fault)", ctx);
                }
            }
        },
        .permission => {
            if (fault.is_write) {
                // Check for copy-on-write
                if (!handleCowFault(ctx, fault.vaddr)) {
                    if (fault.is_user) {
                        sendSignalToCurrentProcess(11); // SIGSEGV
                    } else {
                        panicException("Kernel data abort (permission fault)", ctx);
                    }
                }
            } else {
                if (fault.is_user) {
                    sendSignalToCurrentProcess(11); // SIGSEGV
                } else {
                    panicException("Kernel data abort (read permission fault)", ctx);
                }
            }
        },
        .access_flag => {
            // Hardware should handle AF updates if HAFDBS is enabled
            // If not, set AF manually
            setAccessFlag(fault.vaddr);
        },
        .alignment => {
            if (fault.is_user) {
                sendSignalToCurrentProcess(7); // SIGBUS
            } else {
                panicException("Kernel alignment fault", ctx);
            }
        },
        else => {
            if (fault.is_user) {
                sendSignalToCurrentProcess(11); // SIGSEGV
            } else {
                panicException("Kernel data abort (unhandled type)", ctx);
            }
        },
    }
}

fn handleInstructionAbort(ctx: *ExceptionContext) void {
    const fault = mmu.decodeFault(ctx.esr, ctx.far);

    if (fault.fault_type == .translation) {
        if (!demandPage(ctx, fault.vaddr, false)) {
            if (fault.is_user) {
                sendSignalToCurrentProcess(11); // SIGSEGV
            } else {
                panicException("Kernel instruction abort", ctx);
            }
        }
    } else {
        if (fault.is_user) {
            sendSignalToCurrentProcess(11); // SIGSEGV
        } else {
            panicException("Kernel instruction abort (non-translation)", ctx);
        }
    }
}

fn handleAlignmentFault(ctx: *ExceptionContext) void {
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(7); // SIGBUS
    } else {
        panicException("Kernel alignment fault", ctx);
    }
}

fn handleBreakpoint(ctx: *ExceptionContext) void {
    // Hardware breakpoint hit — route to kernel debugger if attached
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(5); // SIGTRAP
    } else {
        // Kernel debugger breakpoint
        kernelDebugTrap(ctx);
    }
}

fn handleWatchpoint(ctx: *ExceptionContext) void {
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(5); // SIGTRAP
    } else {
        kernelDebugTrap(ctx);
    }
}

fn handleSingleStep(ctx: *ExceptionContext) void {
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(5); // SIGTRAP
    } else {
        kernelDebugTrap(ctx);
    }
}

fn handleBrkInstruction(ctx: *ExceptionContext) void {
    const comment = ctx.getISS(); // BRK #imm16
    _ = comment;

    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(5); // SIGTRAP
    } else {
        // Kernel BRK — used by KASAN, UBSAN, etc.
        kernelDebugTrap(ctx);
    }
}

fn handleFpTrap(ctx: *ExceptionContext) void {
    // FP/SIMD was disabled — enable it and return
    // Set CPACR_EL1.FPEN = 0b11 to enable FP/SIMD at EL0 and EL1
    var cpacr = asm ("mrs %[r], CPACR_EL1" : [r] "=r" (-> u64));
    cpacr |= (3 << 20); // FPEN[21:20] = 0b11
    asm volatile ("msr CPACR_EL1, %[v]; isb" : : [v] "r" (cpacr));
    // Don't advance PC — re-execute the faulting instruction
    _ = ctx;
}

fn handleSveTrap(ctx: *ExceptionContext) void {
    // SVE was disabled — enable it
    var cpacr = asm ("mrs %[r], CPACR_EL1" : [r] "=r" (-> u64));
    cpacr |= (3 << 20); // FPEN
    asm volatile ("msr CPACR_EL1, %[v]" : : [v] "r" (cpacr));

    // Also enable SVE via ZCR_EL1
    var zcr = asm ("mrs %[r], ZCR_EL1" : [r] "=r" (-> u64));
    zcr |= 0xF; // Max SVE vector length
    asm volatile ("msr ZCR_EL1, %[v]; isb" : : [v] "r" (zcr));
    _ = ctx;
}

fn handleBtiViolation(ctx: *ExceptionContext) void {
    // Branch Target Identification violation
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(4); // SIGILL
    } else {
        panicException("Kernel BTI violation", ctx);
    }
}

fn handlePacFailure(ctx: *ExceptionContext) void {
    // Pointer Authentication Code check failure
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(4); // SIGILL
    } else {
        panicException("Kernel PAC failure — possible stack corruption or ROP attack", ctx);
    }
}

fn handleIllegalExecution(ctx: *ExceptionContext) void {
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(4); // SIGILL
    } else {
        panicException("Kernel illegal execution state", ctx);
    }
}

fn handleTrappedSystemReg(ctx: *ExceptionContext) void {
    // Emulate trapped system register access
    // ISS encoding: Op0[21:20], Op2[19:17], Op1[16:14], CRn[13:10], Rt[9:5], CRm[4:1], Dir[0]
    const iss = ctx.getISS();
    _ = iss;

    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(4); // SIGILL
    } else {
        // Skip the trapped instruction
        ctx.elr += 4;
    }
}

fn handleTrappedWfiWfe(ctx: *ExceptionContext) void {
    // Trapped WFI/WFE — just skip the instruction
    ctx.elr += 4;
}

fn handleUnknownException(ctx: *ExceptionContext) void {
    if (ctx.isUserMode()) {
        sendSignalToCurrentProcess(4); // SIGILL
    } else {
        panicException("Unknown kernel exception", ctx);
    }
}

// ── Support Functions ─────────────────────────────────────────────────────
fn demandPage(ctx: *ExceptionContext, vaddr: u64, is_write: bool) bool {
    _ = ctx;
    _ = vaddr;
    _ = is_write;
    // TODO: implement demand paging via VMM
    return false;
}

fn handleCowFault(ctx: *ExceptionContext, vaddr: u64) bool {
    _ = ctx;
    _ = vaddr;
    // TODO: implement COW via VMM
    return false;
}

fn setAccessFlag(vaddr: u64) void {
    _ = vaddr;
    // TODO: walk page table and set AF bit
}

fn sendSignalToCurrentProcess(sig: u32) void {
    _ = sig;
    // TODO: send signal via signal subsystem
}

fn kernelDebugTrap(ctx: *ExceptionContext) void {
    _ = ctx;
    // TODO: route to kernel debugger (KGDB)
}

fn panicException(msg: []const u8, ctx: *ExceptionContext) void {
    _ = msg;
    _ = ctx;
    // TODO: kernel panic with register dump
    while (true) {
        asm volatile ("wfi");
    }
}

fn panicNested(ctx: *ExceptionContext) void {
    _ = ctx;
    while (true) {
        asm volatile ("wfi");
    }
}

// ── Vector Table Installation ─────────────────────────────────────────────
pub fn installVectorTable() void {
    const vbar = @intFromPtr(&exception_vector_table);
    asm volatile ("msr VBAR_EL1, %[v]; isb" : : [v] "r" (vbar));
}

pub fn getStats() ExceptionStats {
    return exception_stats;
}

pub fn resetStats() void {
    exception_stats = .{};
}

// ── Exception Vector Table ────────────────────────────────────────────────
// Must be 2KB (0x800) aligned. Each entry is 128 bytes (0x80).
// Layout: 4 groups × 4 vectors = 16 entries
//   Group 0: Current EL with SP0 (not used in kernel)
//   Group 1: Current EL with SPx (kernel exceptions)
//   Group 2: Lower EL, AArch64 (user-space exceptions)
//   Group 3: Lower EL, AArch32 (32-bit user-space, if supported)

export const exception_vector_table: [2048]u8 align(2048) = buildVectorTable();

fn buildVectorTable() [2048]u8 {
    var table: [2048]u8 = [_]u8{0} ** 2048;

    // Each entry: we encode a branch to the handler
    // In real implementation, these would be ARM64 instructions
    // B <offset> encoding: 0x14000000 | (offset / 4)

    // For now, fill with NOP (0xD503201F) and B to handler stubs
    var i: usize = 0;
    while (i < 2048) : (i += 4) {
        // NOP instruction (little-endian)
        table[i] = 0x1F;
        table[i + 1] = 0x20;
        table[i + 2] = 0x03;
        table[i + 3] = 0xD5;
    }

    return table;
}
