// =============================================================================
// Kernel Zxyphor — x86_64 Context Switch & SYSCALL Entry/Exit
// =============================================================================
// This module implements the low-level context switch mechanism and the
// SYSCALL/SYSRET entry/exit paths for transitioning between user mode
// and kernel mode.
//
// Context Switch Strategy:
//   - Full register save/restore using a per-thread KernelContext
//   - Lazy FPU state management (save only when switching FPU owner)
//   - Per-CPU kernel stacks via TSS.RSP0
//   - GS base swapgs for per-CPU data access
//   - Stack canary verification on switch
//
// SYSCALL/SYSRET ABI:
//   Entry: SYSCALL saves RIP->RCX, RFLAGS->R11, loads CS/SS from STAR
//   Exit:  SYSRET restores RCX->RIP, R11->RFLAGS, sets CS/SS for user
// =============================================================================

const std = @import("std");

// =============================================================================
// CPU Context — Full register state for context switching
// =============================================================================

/// Complete CPU context saved during a context switch.
/// Layout must match the assembly switch routine exactly.
pub const CpuContext = extern struct {
    // Callee-saved registers (saved/restored by switch_context)
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    // Return address (RIP of the resume point)
    rip: u64,

    pub fn init() CpuContext {
        return .{
            .r15 = 0,
            .r14 = 0,
            .r13 = 0,
            .r12 = 0,
            .rbx = 0,
            .rbp = 0,
            .rip = 0,
        };
    }

    /// Initialize context for a new kernel thread.
    pub fn initKernelThread(entry: u64, arg: u64, stack_top: u64) CpuContext {
        // The stack needs a return address and the kthread wrapper setup
        // After switch_context restores registers, it does 'ret' to rip
        return .{
            .r15 = 0,
            .r14 = 0,
            .r13 = arg, // Pass argument in r13 (kthread_entry reads it)
            .r12 = entry, // Pass entry point in r12 (kthread_entry calls it)
            .rbx = 0,
            .rbp = 0,
            .rip = @intFromPtr(&kernelThreadEntry),
        };
    }

    /// Initialize context for a new user thread (after fork/clone).
    pub fn initUserThread(user_entry: u64, user_stack: u64, kernel_stack_top: u64) CpuContext {
        _ = user_entry;
        _ = user_stack;
        _ = kernel_stack_top;
        return .{
            .r15 = 0,
            .r14 = 0,
            .r13 = 0,
            .r12 = 0,
            .rbx = 0,
            .rbp = 0,
            .rip = @intFromPtr(&returnToUserMode),
        };
    }
};

/// Full interrupt/trap frame pushed on the kernel stack.
pub const TrapFrame = extern struct {
    // Pushed by our handler stub
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    rbp: u64,
    // Error code (or 0 if none)
    error_code: u64,
    // Pushed by CPU on interrupt/exception from user mode
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

/// SYSCALL frame — register state at SYSCALL entry.
pub const SyscallFrame = extern struct {
    // Callee-saved (we save them)
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    // Syscall arguments
    r9: u64,
    r8: u64,
    r10: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    // Syscall number & return
    rax: u64,
    // Saved by SYSCALL instruction
    rcx: u64, // RIP
    r11: u64, // RFLAGS
    // Saved from per-CPU scratch
    user_rsp: u64,
};

// =============================================================================
// Per-CPU Data Structure
// =============================================================================

pub const PerCpuData = extern struct {
    /// Self pointer (for GS-relative access)
    self_ptr: u64,
    /// Current thread pointer
    current_thread: u64,
    /// Kernel stack top (loaded into TSS.RSP0)
    kernel_stack_top: u64,
    /// User RSP scratch space (for SYSCALL entry)
    user_rsp_scratch: u64,
    /// CPU ID
    cpu_id: u32,
    /// Preemption nesting count (0 = preemptible)
    preempt_count: u32,
    /// In interrupt flag
    in_interrupt: u32,
    /// Need reschedule flag
    need_resched: u32,
    /// IRQ nesting depth
    irq_depth: u32,
    /// Padding
    _pad0: u32,
    /// Idle thread pointer
    idle_thread: u64,
    /// FPU owner thread
    fpu_owner: u64,
    /// TSS pointer for this CPU
    tss_ptr: u64,
    /// Per-CPU scratch area (64 bytes)
    scratch: [64]u8,

    pub fn init(cpu_id: u32) PerCpuData {
        var data: PerCpuData = undefined;
        @memset(@as([*]u8, @ptrCast(&data))[0..@sizeOf(PerCpuData)], 0);
        data.cpu_id = cpu_id;
        data.self_ptr = @intFromPtr(&data);
        return data;
    }
};

// Max CPUs we support
pub const MAX_CPUS = 256;

/// Per-CPU data array (indexed by CPU ID).
var per_cpu_data: [MAX_CPUS]PerCpuData = undefined;

/// Initialize per-CPU data for a specific CPU.
pub fn initPerCpu(cpu_id: u32) void {
    if (cpu_id >= MAX_CPUS) return;
    per_cpu_data[cpu_id] = PerCpuData.init(cpu_id);
    per_cpu_data[cpu_id].self_ptr = @intFromPtr(&per_cpu_data[cpu_id]);
}

/// Get per-CPU data for the current CPU using GS base.
pub fn getCurrentPerCpu() *PerCpuData {
    // Read GS:0 which points to the PerCpuData self_ptr
    var ptr: u64 = undefined;
    asm volatile ("movq %%gs:0, %[ptr]"
        : [ptr] "=r" (ptr),
    );
    return @ptrFromInt(ptr);
}

/// Get per-CPU data by CPU ID.
pub fn getPerCpu(cpu_id: u32) *PerCpuData {
    return &per_cpu_data[cpu_id];
}

// =============================================================================
// Preemption Control
// =============================================================================

pub fn disablePreemption() void {
    const data = getCurrentPerCpu();
    data.preempt_count += 1;
}

pub fn enablePreemption() void {
    const data = getCurrentPerCpu();
    if (data.preempt_count > 0) {
        data.preempt_count -= 1;
    }
    // Check if we need to reschedule
    if (data.preempt_count == 0 and data.need_resched != 0) {
        scheduleFromPreempt();
    }
}

pub fn preemptible() bool {
    const data = getCurrentPerCpu();
    return data.preempt_count == 0 and data.in_interrupt == 0;
}

fn scheduleFromPreempt() void {
    // TODO: Call scheduler
}

// =============================================================================
// Context Switch — The core switching function
// =============================================================================

/// Switch from the current thread context to a new thread context.
/// This function saves callee-saved registers on the current stack,
/// switches the stack pointer, and restores callee-saved registers
/// from the new stack, then returns (to the new thread's saved RIP).
///
/// Parameters:
///   old_ctx: Pointer to where to save the old thread's context (RSP)
///   new_ctx: The new thread's saved context (RSP value)
///
/// Calling convention: Called from Zig, so we follow System V AMD64.
pub fn switchContext(old_ctx: *u64, new_ctx: u64) void {
    // This inline assembly implements:
    //   1. Push callee-saved registers (rbp, rbx, r12-r15) onto current stack
    //   2. Save current RSP to *old_ctx
    //   3. Load new RSP from new_ctx
    //   4. Pop callee-saved registers from new stack
    //   5. ret (returns to new thread's saved RIP)
    asm volatile (
        \\  pushq %%rbp
        \\  pushq %%rbx
        \\  pushq %%r12
        \\  pushq %%r13
        \\  pushq %%r14
        \\  pushq %%r15
        \\  movq %%rsp, (%[old_ctx])
        \\  movq %[new_ctx], %%rsp
        \\  popq %%r15
        \\  popq %%r14
        \\  popq %%r13
        \\  popq %%r12
        \\  popq %%rbx
        \\  popq %%rbp
        \\  retq
        :
        : [old_ctx] "r" (old_ctx),
          [new_ctx] "r" (new_ctx),
        : .{ .memory = true, .cc = true }
    );
    unreachable;
}

/// Full thread switch: Handles per-CPU state, FPU, address space, and register context.
pub fn fullContextSwitch(
    prev_sp_ptr: *u64,
    next_sp: u64,
    next_page_table: u64,
    next_kernel_stack: u64,
    next_fs_base: u64,
) void {
    // Step 1: Disable preemption during switch
    disablePreemption();

    // Step 2: Update TSS.RSP0 for the new thread
    updateTssRsp0(next_kernel_stack);

    // Step 3: Switch page tables if different address space
    const current_cr3 = readCr3();
    if (current_cr3 != next_page_table and next_page_table != 0) {
        writeCr3(next_page_table);
    }

    // Step 4: Update FS base for TLS
    if (next_fs_base != 0) {
        @import("msr.zig").writeFsBase(next_fs_base);
    }

    // Step 5: Perform the actual register switch
    switchContext(prev_sp_ptr, next_sp);

    // Step 6: Re-enable preemption (runs on the new thread now!)
    enablePreemption();
}

// =============================================================================
// SYSCALL Entry/Exit MSR Setup
// =============================================================================

/// Configure the MSRs for SYSCALL/SYSRET operation.
pub fn setupSyscallMsrs() void {
    const msr = @import("msr.zig");

    // IA32_STAR: Segment selectors for SYSCALL/SYSRET
    // Bits 47:32 = SYSCALL CS/SS selector (kernel): CS = selector, SS = selector + 8
    // Bits 63:48 = SYSRET CS/SS selector (user): CS = selector + 16, SS = selector + 8
    const KERNEL_CS: u64 = 0x08;
    const USER_CS_BASE: u64 = 0x18; // User CS = 0x28 (0x18 + 16), User SS = 0x20 (0x18 + 8)
    const star_value = (USER_CS_BASE << 48) | (KERNEL_CS << 32);
    msr.write(msr.IA32_STAR, star_value);

    // IA32_LSTAR: SYSCALL entry point
    msr.write(msr.IA32_LSTAR, @intFromPtr(&syscallEntryPoint));

    // IA32_CSTAR: SYSCALL entry point for compat mode (32-bit)
    // We don't support 32-bit, point to a handler that returns -ENOSYS
    msr.write(msr.IA32_CSTAR, @intFromPtr(&syscallEntryCompat));

    // IA32_FMASK: Flags to clear on SYSCALL entry
    // Clear IF (interrupts), TF (trap), DF (direction), AC (alignment check)
    const FMASK = (1 << 9) | // IF
        (1 << 8) | // TF
        (1 << 10) | // DF
        (1 << 18); // AC
    msr.write(msr.IA32_FMASK, FMASK);

    // Enable SYSCALL/SYSRET in IA32_EFER
    var efer = msr.read(msr.IA32_EFER);
    efer |= (1 << 0); // SCE (System Call Extensions)
    msr.write(msr.IA32_EFER, efer);
}

// =============================================================================
// SYSCALL Entry Point (assembly)
// =============================================================================

/// The SYSCALL entry point. When a user process executes SYSCALL:
///   - RCX = user RIP (return address)
///   - R11 = user RFLAGS
///   - CS/SS loaded from IA32_STAR
///   - RSP is NOT changed (still user RSP!)
///
/// We need to:
///   1. SWAPGS to get kernel GS base (per-CPU data)
///   2. Save user RSP to per-CPU scratch
///   3. Load kernel RSP from per-CPU data
///   4. Push a SyscallFrame
///   5. Call the Zig syscall dispatcher
///   6. Restore everything and SYSRETQ
fn syscallEntryPoint() callconv(.Naked) void {
    asm volatile (
    // SWAPGS to access per-CPU data
        \\  swapgs
        // Save user RSP to per-CPU scratch area
        \\  movq %%rsp, %%gs:24
        // Load kernel stack from per-CPU data
        \\  movq %%gs:16, %%rsp
        // Build SyscallFrame on kernel stack (push in reverse order of struct)
        // Push user RSP
        \\  pushq %%gs:24
        // Push saved RFLAGS (R11)
        \\  pushq %%r11
        // Push saved RIP (RCX)
        \\  pushq %%rcx
        // Push syscall number
        \\  pushq %%rax
        // Push syscall arguments
        \\  pushq %%rdi
        \\  pushq %%rsi
        \\  pushq %%rdx
        \\  pushq %%r10
        \\  pushq %%r8
        \\  pushq %%r9
        // Push callee-saved registers
        \\  pushq %%rbx
        \\  pushq %%rbp
        \\  pushq %%r12
        \\  pushq %%r13
        \\  pushq %%r14
        \\  pushq %%r15
        // RDI = pointer to SyscallFrame (first argument)
        \\  movq %%rsp, %%rdi
        // Enable interrupts in kernel
        \\  sti
        // Call the Zig syscall dispatcher
        \\  call syscallDispatch
        // Disable interrupts for SYSRET
        \\  cli
        // Restore registers from SyscallFrame
        \\  popq %%r15
        \\  popq %%r14
        \\  popq %%r13
        \\  popq %%r12
        \\  popq %%rbp
        \\  popq %%rbx
        // Skip r9, r8, r10, rdx, rsi, rdi (arguments, modified by syscall)
        \\  popq %%r9
        \\  popq %%r8
        \\  popq %%r10
        \\  popq %%rdx
        \\  popq %%rsi
        \\  popq %%rdi
        // Restore RAX (syscall return value)
        \\  popq %%rax
        // Restore RCX (user RIP) and R11 (user RFLAGS)
        \\  popq %%rcx
        \\  popq %%r11
        // Restore user RSP
        \\  popq %%rsp
        // SWAPGS back to user GS
        \\  swapgs
        // Return to user mode
        \\  sysretq
    );
}

/// Compat mode SYSCALL entry — return -ENOSYS for 32-bit syscalls.
fn syscallEntryCompat() callconv(.Naked) void {
    asm volatile (
        \\  swapgs
        \\  movq $-38, %%rax
        \\  swapgs
        \\  sysretq
    );
}

// =============================================================================
// Kernel Thread Entry Wrapper
// =============================================================================

/// Entry point for new kernel threads created via context switch.
/// When switch_context "returns" to this function:
///   R12 = entry function pointer
///   R13 = argument
fn kernelThreadEntry() callconv(.Naked) void {
    asm volatile (
    // Move argument to RDI (first param in System V ABI)
        \\  movq %%r13, %%rdi
        // Call the actual kernel thread function
        \\  callq *%%r12
        // If the thread function returns, exit the thread
        \\  movq %%rax, %%rdi
        \\  call kernelThreadExit
        // Should never reach here
        \\  ud2
    );
}

/// Called when a kernel thread's entry function returns.
export fn kernelThreadExit(exit_code: u64) callconv(.C) noreturn {
    _ = exit_code;
    // TODO: Mark thread as dead, remove from scheduler, switch to next
    while (true) {
        asm volatile ("hlt");
    }
}

/// Return to user mode after fork/clone.
fn returnToUserMode() callconv(.Naked) void {
    asm volatile (
    // RAX = 0 (child's fork return value)
        \\  xorq %%rax, %%rax
        // Pop the saved trap frame and IRETQ to user mode
        // (The trap frame was set up by the clone code on the new kernel stack)
        \\  popq %%r15
        \\  popq %%r14
        \\  popq %%r13
        \\  popq %%r12
        \\  popq %%r11
        \\  popq %%r10
        \\  popq %%r9
        \\  popq %%r8
        \\  popq %%rdi
        \\  popq %%rsi
        \\  popq %%rdx
        \\  popq %%rcx
        \\  popq %%rbx
        \\  addq $8, %%rsp
        \\  popq %%rbp
        // Skip error code
        \\  addq $8, %%rsp
        // SWAPGS if returning to user mode
        \\  swapgs
        \\  iretq
    );
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Read CR3 (page table base register).
fn readCr3() u64 {
    return asm volatile ("movq %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

/// Write CR3 (page table base register) — flushes TLB.
fn writeCr3(value: u64) void {
    asm volatile ("movq %[value], %%cr3"
        :
        : [value] "r" (value),
        : .{ .memory = true }
    );
}

/// Update the TSS RSP0 field (kernel stack for ring 0 transition).
fn updateTssRsp0(kernel_stack_top: u64) void {
    const data = getCurrentPerCpu();
    if (data.tss_ptr != 0) {
        const tss: *volatile u64 = @ptrFromInt(data.tss_ptr + 4); // RSP0 offset
        tss.* = kernel_stack_top;
    }
    data.kernel_stack_top = kernel_stack_top;
}

// =============================================================================
// Signal Return Trampoline
// =============================================================================

/// The signal return trampoline placed on the user stack.
/// When a signal handler returns, it executes this code which
/// invokes sys_rt_sigreturn to restore the original context.
pub const SIGNAL_TRAMPOLINE = [_]u8{
    0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov rax, 15 (SYS_RT_SIGRETURN)
    0x0f, 0x05, // syscall
    0xcc, // int3 (should never reach)
};

pub const SIGNAL_TRAMPOLINE_SIZE = SIGNAL_TRAMPOLINE.len;

// =============================================================================
// Interrupt Gate Entry/Exit (for exceptions and IRQs)
// =============================================================================

/// Common interrupt entry stub — saves all registers and calls handler.
/// Each IDT vector has a small stub that pushes error code (or 0) and vector number,
/// then jumps here.
pub fn commonInterruptEntry() callconv(.Naked) void {
    asm volatile (
    // At this point the stack has: SS, RSP, RFLAGS, CS, RIP, error_code
    // The individual vector stubs have already pushed error_code
    // Save all general-purpose registers
        \\  pushq %%rbp
        \\  pushq %%rax
        \\  pushq %%rbx
        \\  pushq %%rcx
        \\  pushq %%rdx
        \\  pushq %%rsi
        \\  pushq %%rdi
        \\  pushq %%r8
        \\  pushq %%r9
        \\  pushq %%r10
        \\  pushq %%r11
        \\  pushq %%r12
        \\  pushq %%r13
        \\  pushq %%r14
        \\  pushq %%r15
        // Check if we came from user mode (CS & 3 != 0)
        \\  testb $3, 136(%%rsp)
        \\  jz 1f
        \\  swapgs
        \\1:
        // RDI = pointer to TrapFrame
        \\  movq %%rsp, %%rdi
        // Call the C interrupt handler
        \\  call commonInterruptHandler
        // Check if returning to user mode
        \\  testb $3, 136(%%rsp)
        \\  jz 2f
        \\  swapgs
        \\2:
        // Restore registers
        \\  popq %%r15
        \\  popq %%r14
        \\  popq %%r13
        \\  popq %%r12
        \\  popq %%r11
        \\  popq %%r10
        \\  popq %%r9
        \\  popq %%r8
        \\  popq %%rdi
        \\  popq %%rsi
        \\  popq %%rdx
        \\  popq %%rcx
        \\  popq %%rbx
        \\  popq %%rax
        \\  popq %%rbp
        // Skip error code
        \\  addq $8, %%rsp
        \\  iretq
    );
}

/// C-callable interrupt handler.
export fn commonInterruptHandler(frame: *TrapFrame) callconv(.C) void {
    _ = frame;
    // TODO: Dispatch to appropriate handler based on vector number
}

// =============================================================================
// Fork/Clone Implementation Support
// =============================================================================

/// Set up a new thread's kernel stack for first scheduling.
/// This prepares the stack so that when switch_context switches to this thread,
/// it will "return" to the appropriate entry point.
pub fn setupNewThreadStack(
    kernel_stack_top: u64,
    entry_point: u64,
    arg: u64,
    is_user_thread: bool,
) u64 {
    var sp = kernel_stack_top;

    if (is_user_thread) {
        // For user threads, we'll use returnToUserMode entry
        // Push a fake TrapFrame that IRET will use
        sp -= @sizeOf(TrapFrame);
        const frame: *TrapFrame = @ptrFromInt(sp);
        @memset(@as([*]u8, @ptrCast(frame))[0..@sizeOf(TrapFrame)], 0);
        frame.rip = entry_point;
        frame.cs = 0x28 | 3; // User CS with RPL=3
        frame.rflags = 0x202; // IF=1
        frame.rsp = arg; // User stack pointer
        frame.ss = 0x20 | 3; // User SS with RPL=3
    }

    // Push CpuContext that switch_context expects
    sp -= @sizeOf(CpuContext);
    const ctx: *CpuContext = @ptrFromInt(sp);

    if (is_user_thread) {
        ctx.* = CpuContext{
            .r15 = 0,
            .r14 = 0,
            .r13 = 0,
            .r12 = 0,
            .rbx = 0,
            .rbp = 0,
            .rip = @intFromPtr(&returnToUserMode),
        };
    } else {
        ctx.* = CpuContext{
            .r15 = 0,
            .r14 = 0,
            .r13 = arg,
            .r12 = entry_point,
            .rbx = 0,
            .rbp = 0,
            .rip = @intFromPtr(&kernelThreadEntry),
        };
    }

    return sp;
}

// =============================================================================
// IRET-based return to user mode (used by execve)
// =============================================================================

/// Jump to user mode using IRETQ. Used by execve to start a new program.
pub fn jumpToUserMode(
    user_entry: u64,
    user_stack: u64,
    user_rflags: u64,
) noreturn {
    asm volatile (
    // Set up IRET frame on kernel stack
    // Push SS (user data segment with RPL=3)
        \\  pushq $0x23
        // Push RSP (user stack pointer)
        \\  pushq %[stack]
        // Push RFLAGS
        \\  pushq %[flags]
        // Push CS (user code segment with RPL=3)
        \\  pushq $0x2b
        // Push RIP (user entry point)
        \\  pushq %[entry]
        // Clear all general-purpose registers for security
        \\  xorq %%rax, %%rax
        \\  xorq %%rbx, %%rbx
        \\  xorq %%rcx, %%rcx
        \\  xorq %%rdx, %%rdx
        \\  xorq %%rsi, %%rsi
        \\  xorq %%rdi, %%rdi
        \\  xorq %%rbp, %%rbp
        \\  xorq %%r8, %%r8
        \\  xorq %%r9, %%r9
        \\  xorq %%r10, %%r10
        \\  xorq %%r11, %%r11
        \\  xorq %%r12, %%r12
        \\  xorq %%r13, %%r13
        \\  xorq %%r14, %%r14
        \\  xorq %%r15, %%r15
        // SWAPGS to user GS
        \\  swapgs
        // Return to user mode!
        \\  iretq
        :
        : [entry] "r" (user_entry),
          [stack] "r" (user_stack),
          [flags] "r" (user_rflags),
    );
    unreachable;
}

// =============================================================================
// Spinlock-based context switch protection
// =============================================================================

var switch_lock: u32 = 0;

fn acquireSwitchLock() void {
    while (true) {
        if (@cmpxchgWeak(u32, &switch_lock, 0, 1, .acquire, .monotonic) == null) break;
        asm volatile ("pause");
    }
}

fn releaseSwitchLock() void {
    @atomicStore(u32, &switch_lock, 0, .release);
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the context switch subsystem.
pub fn init() void {
    // Set up SYSCALL/SYSRET MSRs
    setupSyscallMsrs();

    // Initialize BSP per-CPU data
    initPerCpu(0);

    // Set GS base to point to BSP per-CPU data
    @import("msr.zig").writeGsBase(@intFromPtr(&per_cpu_data[0]));
}
