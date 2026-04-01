// =============================================================================
// Kernel Zxyphor - Context Switching
// =============================================================================
// Provides low-level context switch and context restore operations.
//
// Context switching is the mechanism by which the kernel saves the state of
// the currently running thread and restores the state of the next thread.
//
// On x86_64, the following registers must be preserved across function calls
// (callee-saved): RBX, RBP, R12-R15, RSP, and the direction flag.
//
// Our context switch saves/restores:
//   - All callee-saved general-purpose registers
//   - RSP (stack pointer)
//   - RIP (instruction pointer — via the return address on the stack)
//   - CR3 (page table base — when switching address spaces)
//   - FPU/SSE state (via FXSAVE/FXRSTOR)
// =============================================================================

const main = @import("../main.zig");

/// CPU context stored for each thread
pub const CpuContext = extern struct {
    // Callee-saved registers (pushed/popped during context switch)
    rbx: u64 = 0,
    rbp: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,

    // Stack pointer
    rsp: u64 = 0,

    // Instruction pointer (set to the entry function for new threads)
    rip: u64 = 0,

    // Code and stack segment selectors
    cs: u64 = 0x08, // Kernel code segment
    ss: u64 = 0x10, // Kernel data segment

    // Flags register
    rflags: u64 = 0x202, // IF=1 (interrupts enabled), reserved bit 1

    // FPU/SSE state (512 bytes for FXSAVE/FXRSTOR)
    fpu_state: [512]u8 align(16) = [_]u8{0} ** 512,

    /// Create a context for a new kernel thread
    pub fn initKernel(entry: *const fn () void, stack_top: u64) CpuContext {
        var ctx = CpuContext{};
        ctx.rip = @intFromPtr(entry);
        ctx.rsp = stack_top;
        ctx.cs = 0x08; // Kernel code
        ctx.ss = 0x10; // Kernel data
        ctx.rflags = 0x202; // IF=1
        ctx.rbp = stack_top; // Frame pointer starts at stack top
        return ctx;
    }

    /// Create a context for a new user thread
    pub fn initUser(entry: u64, user_stack_top: u64, kernel_stack_top: u64) CpuContext {
        var ctx = CpuContext{};
        // The entry point will be loaded via IRET from the kernel trampoline
        ctx.rip = @intFromPtr(&userModeTrampoline);
        ctx.rsp = kernel_stack_top;
        ctx.cs = 0x08; // Start in kernel mode (trampoline does IRET to user)
        ctx.ss = 0x10;
        ctx.rflags = 0x202;
        ctx.rbp = kernel_stack_top;

        // Store user entry and stack in callee-saved registers
        // The trampoline will use these to set up the IRET frame
        ctx.r12 = entry; // User RIP
        ctx.r13 = user_stack_top; // User RSP
        ctx.r14 = 0x1B; // User code segment (0x18 | 3)
        ctx.r15 = 0x23; // User data segment (0x20 | 3)

        return ctx;
    }
};

// =============================================================================
// Context Switch — the heart of the scheduler
// =============================================================================
// This function:
//   1. Saves the current thread's callee-saved registers
//   2. Switches RSP to the new thread's saved RSP
//   3. Restores the new thread's callee-saved registers
//   4. Returns (to the new thread's saved RIP on its stack)
//
// Because this is a function call, the compiler handles saving/restoring
// the caller-saved registers. We only need to handle callee-saved ones.
// =============================================================================

/// Switch from old_context to new_context
/// Called as: switchContext(&old_thread.context, &new_thread.context)
pub fn switchContext(old_ctx: *CpuContext, new_ctx: *const CpuContext) void {
    // Save callee-saved registers into old context
    asm volatile (
        // Save callee-saved GPRs
        \\mov %%rbx, 0(%[old])
        \\mov %%rbp, 8(%[old])
        \\mov %%r12, 16(%[old])
        \\mov %%r13, 24(%[old])
        \\mov %%r14, 32(%[old])
        \\mov %%r15, 40(%[old])
        \\mov %%rsp, 48(%[old])

        // Save the return address as RIP
        \\lea .Lswitch_return(%%rip), %%rax
        \\mov %%rax, 56(%[old])

        // Restore callee-saved GPRs from new context
        \\mov 48(%[new_ptr]), %%rsp
        \\mov 0(%[new_ptr]), %%rbx
        \\mov 8(%[new_ptr]), %%rbp
        \\mov 16(%[new_ptr]), %%r12
        \\mov 24(%[new_ptr]), %%r13
        \\mov 32(%[new_ptr]), %%r14
        \\mov 40(%[new_ptr]), %%r15

        // Jump to the new thread's saved RIP
        \\jmp *56(%[new_ptr])

        \\.Lswitch_return:
        :
        : [old] "r" (old_ctx),
          [new_ptr] "r" (new_ctx),
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
          "memory", "cc"
    );
}

/// Restore a context without saving the current one.
/// Used for the very first context switch (when there's no old thread)
/// and for kernel thread startup.
pub fn restoreContext(new_ctx: *const CpuContext) noreturn {
    asm volatile (
        // Restore all callee-saved registers
        \\mov 0(%[ctx]), %%rbx
        \\mov 8(%[ctx]), %%rbp
        \\mov 16(%[ctx]), %%r12
        \\mov 24(%[ctx]), %%r13
        \\mov 32(%[ctx]), %%r14
        \\mov 40(%[ctx]), %%r15
        \\mov 48(%[ctx]), %%rsp

        // Jump to saved RIP
        \\jmp *56(%[ctx])
        :
        : [ctx] "r" (new_ctx),
        : "memory"
    );
    unreachable;
}

// =============================================================================
// User mode trampoline
// =============================================================================
// This function is the initial "entry point" for new user threads.
// It runs in kernel mode and uses IRET to transition to user mode.
// The actual user entry point and stack are in R12/R13 (set by initUser).
// =============================================================================

fn userModeTrampoline() callconv(.Naked) noreturn {
    // Build an IRET frame to jump to user mode:
    //   [SS]      = R15 (user data segment)
    //   [RSP]     = R13 (user stack pointer)
    //   [RFLAGS]  = 0x202 (IF=1)
    //   [CS]      = R14 (user code segment)
    //   [RIP]     = R12 (user entry point)
    asm volatile (
        \\push %%r15
        \\push %%r13
        \\pushfq
        \\push %%r14
        \\push %%r12
        \\iretq
    );
    unreachable;
}

// =============================================================================
// FPU/SSE state management
// =============================================================================

/// Save the current FPU/SSE state into a buffer
pub fn saveFpuState(buffer: *align(16) [512]u8) void {
    const ptr: [*]u8 = buffer;
    asm volatile ("fxsave (%[buf])"
        :
        : [buf] "r" (ptr),
        : "memory"
    );
}

/// Restore FPU/SSE state from a buffer
pub fn restoreFpuState(buffer: *align(16) const [512]u8) void {
    const ptr: [*]const u8 = buffer;
    asm volatile ("fxrstor (%[buf])"
        :
        : [buf] "r" (ptr),
        : "memory"
    );
}

/// Initialize FPU to a clean default state
pub fn initFpu() void {
    asm volatile (
        \\fninit
        ::: "memory"
    );
}
