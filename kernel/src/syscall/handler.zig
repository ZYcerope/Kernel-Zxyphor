// =============================================================================
// Kernel Zxyphor - System Call Handler
// =============================================================================
// System calls are the mechanism by which user-space programs request
// services from the kernel. On x86_64, we support two entry methods:
//
//   1. Legacy: INT 0x80 (software interrupt) — compatible, slower
//   2. Modern: SYSCALL/SYSRET instruction pair — fast path
//
// Syscall convention (matching Linux x86_64 ABI for compatibility):
//   RAX = syscall number
//   Arguments: RDI, RSI, RDX, R10, R8, R9
//   Return value: RAX (negative values indicate errors)
//
// The handler validates the syscall number, checks permissions,
// dispatches to the appropriate handler function, and returns the result.
// =============================================================================

const main = @import("../main.zig");
const table = @import("table.zig");

// =============================================================================
// Syscall numbers (POSIX-compatible subset)
// =============================================================================
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_GETPID: u64 = 39;
pub const SYS_FORK: u64 = 57;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_RENAME: u64 = 82;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_SETSID: u64 = 112;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SEND: u64 = 44;
pub const SYS_RECV: u64 = 45;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_REBOOT: u64 = 169;

// Total number of implemented syscalls
pub const SYSCALL_COUNT: usize = 256;

// =============================================================================
// Error codes (negated in return value)
// =============================================================================
pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const ENXIO: i64 = -6;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ENFILE: i64 = -23;
pub const EMFILE: i64 = -24;
pub const ENOSPC: i64 = -28;
pub const ESPIPE: i64 = -29;
pub const EROFS: i64 = -30;
pub const EPIPE: i64 = -32;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;

// =============================================================================
// Syscall register frame (passed in from the interrupt/SYSCALL entry)
// =============================================================================
pub const SyscallFrame = struct {
    // Syscall arguments (as passed in registers)
    rax: u64 = 0, // Syscall number
    rdi: u64 = 0, // Arg 1
    rsi: u64 = 0, // Arg 2
    rdx: u64 = 0, // Arg 3
    r10: u64 = 0, // Arg 4
    r8: u64 = 0, // Arg 5
    r9: u64 = 0, // Arg 6

    // Return value (stored in RAX on return)
    ret: i64 = 0,
};

// =============================================================================
// Statistics
// =============================================================================
var total_syscalls: u64 = 0;
var syscall_counts: [SYSCALL_COUNT]u64 = [_]u64{0} ** SYSCALL_COUNT;

// =============================================================================
// Initialize the system call interface
// =============================================================================
pub fn initialize() void {
    // Set up SYSCALL/SYSRET MSRs for fast system call path
    setupSyscallMSRs();

    main.klog(.info, "syscall: interface initialized ({d} syscalls)", .{SYSCALL_COUNT});
}

fn setupSyscallMSRs() void {
    // IA32_STAR (0xC0000081): SYSCALL target CS/SS and SYSRET CS/SS
    //   Bits 47:32 = SYSCALL CS (selector for kernel code segment)
    //   Bits 63:48 = SYSRET CS (selector base for user code segment)
    // Kernel: CS=0x08, SS=0x10
    // User:   CS=0x1B (0x18|3), SS=0x23 (0x20|3)
    const star_val: u64 = (@as(u64, 0x0008) << 32) | (@as(u64, 0x0018) << 48);
    main.cpu.writeMsr(main.cpu.MSR_STAR, star_val);

    // IA32_LSTAR (0xC0000082): SYSCALL entry point (RIP)
    main.cpu.writeMsr(main.cpu.MSR_LSTAR, @intFromPtr(&syscallEntryPoint));

    // IA32_FMASK (0xC0000084): RFLAGS mask — clear IF (interrupts) on SYSCALL
    main.cpu.writeMsr(main.cpu.MSR_FMASK, 0x200); // Clear IF

    // Enable SYSCALL/SYSRET via IA32_EFER
    var efer = main.cpu.readMsr(main.cpu.MSR_EFER);
    efer |= 0x01; // SCE (System Call Enable) bit
    main.cpu.writeMsr(main.cpu.MSR_EFER, efer);
}

// =============================================================================
// SYSCALL entry point (naked function with inline assembly)
// =============================================================================
fn syscallEntryPoint() callconv(.Naked) void {
    // On SYSCALL entry:
    //   RCX = saved user RIP
    //   R11 = saved user RFLAGS
    //   RAX = syscall number
    //   RDI, RSI, RDX, R10, R8, R9 = arguments
    asm volatile (
        // Switch to kernel stack (from TSS RSP0)
        // We save the user stack pointer and load kernel stack
        \\swapgs
        \\mov %%rsp, %%gs:0x08  // Save user RSP
        \\mov %%gs:0x00, %%rsp  // Load kernel RSP

        // Push a full interrupt frame for consistency
        \\push $0x23           // User SS
        \\push %%gs:0x08       // User RSP
        \\push %%r11           // User RFLAGS
        \\push $0x1B           // User CS
        \\push %%rcx           // User RIP

        // Save callee-saved registers
        \\push %%rbp
        \\push %%rbx
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15

        // Call the Zig syscall dispatcher
        // Arguments already in the right registers (RAX, RDI, RSI, RDX, R10, R8, R9)
        \\mov %%r10, %%rcx    // Linux uses R10 for arg4, x86_64 ABI uses RCX
        \\call syscallDispatch

        // Result is in RAX

        // Restore callee-saved registers
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%rbx
        \\pop %%rbp

        // Skip the full interrupt frame
        \\add $40, %%rsp

        // Restore user stack
        \\mov %%gs:0x08, %%rsp
        \\swapgs
        \\sysretq
    );
}

// =============================================================================
// Legacy INT 0x80 handler (called from IDT)
// =============================================================================
pub fn handleLegacySyscall(frame: *SyscallFrame) void {
    frame.ret = dispatch(
        frame.rax,
        frame.rdi,
        frame.rsi,
        frame.rdx,
        frame.r10,
        frame.r8,
        frame.r9,
    );
}

// =============================================================================
// Syscall dispatcher
// =============================================================================
export fn syscallDispatch(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) callconv(.C) i64 {
    return dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);
}

fn dispatch(
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) i64 {
    total_syscalls += 1;
    if (number < SYSCALL_COUNT) {
        syscall_counts[@intCast(number)] += 1;
    }

    return switch (number) {
        SYS_READ => table.sysRead(arg1, arg2, arg3),
        SYS_WRITE => table.sysWrite(arg1, arg2, arg3),
        SYS_OPEN => table.sysOpen(arg1, arg2, arg3),
        SYS_CLOSE => table.sysClose(arg1),
        SYS_LSEEK => table.sysLseek(arg1, @bitCast(arg2), @truncate(arg3)),
        SYS_BRK => table.sysBrk(arg1),
        SYS_GETPID => table.sysGetpid(),
        SYS_FORK => table.sysFork(),
        SYS_EXIT => table.sysExit(@truncate(arg1)),
        SYS_WAIT4 => table.sysWait4(@bitCast(arg1), arg2, @truncate(arg3)),
        SYS_KILL => table.sysKill(@bitCast(arg1), @truncate(arg2)),
        SYS_UNAME => table.sysUname(arg1),
        SYS_MKDIR => table.sysMkdir(arg1, @truncate(arg2)),
        SYS_RMDIR => table.sysRmdir(arg1),
        SYS_UNLINK => table.sysUnlink(arg1),
        SYS_RENAME => table.sysRename(arg1, arg2),
        SYS_CHDIR => table.sysChdir(arg1),
        SYS_GETCWD => table.sysGetcwd(arg1, arg2),
        SYS_GETUID => table.sysGetuid(),
        SYS_GETGID => table.sysGetgid(),
        SYS_GETEUID => table.sysGeteuid(),
        SYS_GETEGID => table.sysGetegid(),
        SYS_SCHED_YIELD => table.sysSchedYield(),
        SYS_NANOSLEEP => table.sysNanosleep(arg1, arg2),
        SYS_CLOCK_GETTIME => table.sysClockGettime(@truncate(arg1), arg2),
        SYS_PIPE => table.sysPipe(arg1),
        SYS_REBOOT => table.sysReboot(@truncate(arg1), @truncate(arg2), @truncate(arg3)),
        SYS_SOCKET => table.sysSocket(@truncate(arg1), @truncate(arg2), @truncate(arg3)),
        SYS_BIND => table.sysBind(arg1, arg2, @truncate(arg3)),
        SYS_LISTEN => table.sysListen(arg1, @truncate(arg2)),
        SYS_ACCEPT => table.sysAccept(arg1, arg2, arg3),
        SYS_CONNECT => table.sysConnect(arg1, arg2, @truncate(arg3)),
        SYS_SEND => table.sysSend(arg1, arg2, arg3, @truncate(arg4)),
        SYS_RECV => table.sysRecv(arg1, arg2, arg3, @truncate(arg4)),
        else => {
            main.klog(.warn, "syscall: unimplemented syscall {d}", .{number});
            return ENOSYS;
        },
    };

    _ = arg5;
    _ = arg6;
}

// =============================================================================
// Statistics
// =============================================================================
pub fn getTotalSyscalls() u64 {
    return total_syscalls;
}

pub fn getSyscallCount(number: usize) u64 {
    if (number >= SYSCALL_COUNT) return 0;
    return syscall_counts[number];
}
