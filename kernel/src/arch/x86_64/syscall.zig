// SPDX-License-Identifier: MIT
// Zxyphor Kernel - x86_64 Syscall Infrastructure
// Modern SYSCALL/SYSRET implementation with full 64-bit support

const std = @import("std");

/// System call numbers - Linux-compatible ABI with Zxyphor extensions
pub const SyscallNumber = enum(u64) {
    // File operations
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    ioctl = 16,
    pread64 = 17,
    pwrite64 = 18,
    readv = 19,
    writev = 20,
    access = 21,
    pipe = 22,
    select = 23,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    recvfrom = 45,
    sendmsg = 46,
    recvmsg = 47,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    setsockopt = 54,
    getsockopt = 55,
    clone = 56,
    fork = 57,
    vfork = 58,
    execve = 59,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    sigpending = 127,
    sigtimedwait = 128,
    rt_sigqueueinfo = 129,
    sigsuspend = 130,
    sigaltstack = 131,
    utime = 132,
    mknod = 133,
    personality = 135,
    statfs = 137,
    fstatfs = 138,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    pivot_root = 155,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    init_module = 175,
    delete_module = 176,
    quotactl = 179,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    io_setup = 206,
    io_destroy = 207,
    io_getevents = 208,
    io_submit = 209,
    io_cancel = 210,
    epoll_create = 213,
    getdents64 = 217,
    set_tid_address = 218,
    semtimedop = 220,
    timer_create = 222,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_notify = 244,
    mq_getsetattr = 245,
    kexec_load = 246,
    waitid = 247,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    newfstatat = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    vmsplice = 278,
    move_pages = 279,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    preadv = 295,
    pwritev = 296,
    recvmmsg = 299,
    perf_event_open = 298,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    sendmmsg = 307,
    setns = 308,
    getcpu = 309,
    process_vm_readv = 310,
    process_vm_writev = 311,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    bpf = 321,
    execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    preadv2 = 327,
    pwritev2 = 328,
    pkey_mprotect = 329,
    pkey_alloc = 330,
    pkey_free = 331,
    statx = 332,
    io_pgetevents = 333,
    rseq = 334,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    memfd_secret = 447,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,

    // Zxyphor-specific extensions (starting at 512)
    zxy_async_io = 512,
    zxy_secure_channel = 513,
    zxy_gpu_submit = 514,
    zxy_numa_hint = 515,
    zxy_capability_check = 516,
    zxy_fast_ipc = 517,
    zxy_memory_tag = 518,
    zxy_thread_pool = 519,
    zxy_persistent_mem = 520,
    zxy_hardware_accel = 521,
    zxy_zero_copy_send = 522,
    zxy_zero_copy_recv = 523,
    zxy_batch_io = 524,
    zxy_secure_enclave = 525,
    zxy_real_time = 526,
    zxy_power_hint = 527,
    zxy_debug_trace = 528,
    zxy_perf_counter = 529,
    zxy_cgroup_op = 530,
    zxy_namespace_op = 531,

    _,
};

/// Syscall register convention (x86_64 System V ABI):
/// RAX = syscall number
/// RDI = arg1, RSI = arg2, RDX = arg3
/// R10 = arg4, R8 = arg5, R9 = arg6
/// Return value in RAX
/// Syscall context passed to handlers
pub const SyscallContext = struct {
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    return_value: i64,
    user_rsp: u64,
    user_rip: u64,
    user_rflags: u64,

    pub fn fromRegisters(frame: *SyscallFrame) SyscallContext {
        return SyscallContext{
            .number = frame.rax,
            .arg1 = frame.rdi,
            .arg2 = frame.rsi,
            .arg3 = frame.rdx,
            .arg4 = frame.r10,
            .arg5 = frame.r8,
            .arg6 = frame.r9,
            .return_value = 0,
            .user_rsp = frame.user_rsp,
            .user_rip = frame.user_rip,
            .user_rflags = frame.r11,
        };
    }
};

/// Register layout on syscall entry
pub const SyscallFrame = packed struct {
    // Saved by our entry stub
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    // Syscall args
    r9: u64,
    r8: u64,
    r10: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rax: u64,
    // Saved by SYSCALL instruction
    user_rip: u64, // RCX
    user_rsp: u64, // Swapped from kernel
    r11: u64, // RFLAGS
};

/// Syscall handler function type
pub const SyscallHandler = *const fn (*SyscallContext) i64;

/// Error numbers
pub const Errno = struct {
    pub const SUCCESS: i64 = 0;
    pub const EPERM: i64 = -1;
    pub const ENOENT: i64 = -2;
    pub const ESRCH: i64 = -3;
    pub const EINTR: i64 = -4;
    pub const EIO: i64 = -5;
    pub const ENXIO: i64 = -6;
    pub const E2BIG: i64 = -7;
    pub const ENOEXEC: i64 = -8;
    pub const EBADF: i64 = -9;
    pub const ECHILD: i64 = -10;
    pub const EAGAIN: i64 = -11;
    pub const ENOMEM: i64 = -12;
    pub const EACCES: i64 = -13;
    pub const EFAULT: i64 = -14;
    pub const ENOTBLK: i64 = -15;
    pub const EBUSY: i64 = -16;
    pub const EEXIST: i64 = -17;
    pub const EXDEV: i64 = -18;
    pub const ENODEV: i64 = -19;
    pub const ENOTDIR: i64 = -20;
    pub const EISDIR: i64 = -21;
    pub const EINVAL: i64 = -22;
    pub const ENFILE: i64 = -23;
    pub const EMFILE: i64 = -24;
    pub const ENOTTY: i64 = -25;
    pub const ETXTBSY: i64 = -26;
    pub const EFBIG: i64 = -27;
    pub const ENOSPC: i64 = -28;
    pub const ESPIPE: i64 = -29;
    pub const EROFS: i64 = -30;
    pub const EMLINK: i64 = -31;
    pub const EPIPE: i64 = -32;
    pub const EDOM: i64 = -33;
    pub const ERANGE: i64 = -34;
    pub const EDEADLK: i64 = -35;
    pub const ENAMETOOLONG: i64 = -36;
    pub const ENOLCK: i64 = -37;
    pub const ENOSYS: i64 = -38;
    pub const ENOTEMPTY: i64 = -39;
    pub const ELOOP: i64 = -40;
    pub const EWOULDBLOCK: i64 = EAGAIN;
    pub const ENOMSG: i64 = -42;
    pub const ENOTSOCK: i64 = -88;
    pub const ECONNREFUSED: i64 = -111;
    pub const ETIMEDOUT: i64 = -110;
    pub const EOPNOTSUPP: i64 = -95;
    pub const EAFNOSUPPORT: i64 = -97;
    pub const EADDRINUSE: i64 = -98;
    pub const ENETUNREACH: i64 = -101;
    pub const ECONNRESET: i64 = -104;
    pub const ECONNABORTED: i64 = -103;
};

/// Syscall dispatch table
const MAX_SYSCALL: usize = 600;
var syscall_table: [MAX_SYSCALL]?SyscallHandler = [_]?SyscallHandler{null} ** MAX_SYSCALL;
var syscall_counts: [MAX_SYSCALL]u64 = [_]u64{0} ** MAX_SYSCALL;
var total_syscalls: u64 = 0;

/// MSR addresses for SYSCALL/SYSRET
const IA32_EFER: u32 = 0xC0000080;
const IA32_STAR: u32 = 0xC0000081;
const IA32_LSTAR: u32 = 0xC0000082;
const IA32_CSTAR: u32 = 0xC0000083;
const IA32_SFMASK: u32 = 0xC0000084;

/// EFER bits
const EFER_SCE: u64 = 1 << 0; // System Call Extensions

/// Initialize syscall infrastructure
pub fn init() void {
    // Enable SYSCALL/SYSRET in EFER MSR
    var efer = readMsr(IA32_EFER);
    efer |= EFER_SCE;
    writeMsr(IA32_EFER, efer);

    // Set STAR MSR: kernel CS/SS in bits 47:32, user CS/SS in bits 63:48
    // Kernel: CS=0x08, SS=0x10; User: CS=0x1B, SS=0x23
    const star: u64 = (@as(u64, 0x08) << 32) | (@as(u64, 0x18) << 48);
    writeMsr(IA32_STAR, star);

    // Set LSTAR to our syscall entry point
    writeMsr(IA32_LSTAR, @intFromPtr(&syscallEntry));

    // CSTAR is for compat mode (32-bit) - not used
    writeMsr(IA32_CSTAR, 0);

    // SFMASK: mask IF, TF, DF, AC, NT on SYSCALL entry
    writeMsr(IA32_SFMASK, 0x47700);

    // Register default handlers
    registerDefaultHandlers();
}

/// SYSCALL entry point (naked function)
pub fn syscallEntry() callconv(.Naked) void {
    // On SYSCALL entry:
    // RCX = user RIP, R11 = user RFLAGS
    // RSP is still user RSP, need to swap to kernel stack
    asm volatile (
    // Save user RSP and load kernel RSP
        \\swapgs
        \\mov %%rsp, %%gs:0x10  // Save user RSP to per-cpu area
        \\mov %%gs:0x08, %%rsp  // Load kernel RSP from per-cpu area
        // Build syscall frame
        \\push %%r11           // User RFLAGS
        \\push %%gs:0x10       // User RSP
        \\push %%rcx           // User RIP
        \\push %%rax           // Syscall number
        \\push %%rdi
        \\push %%rsi
        \\push %%rdx
        \\push %%r10
        \\push %%r8
        \\push %%r9
        \\push %%rbx
        \\push %%rbp
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        // Call C handler with frame pointer
        \\mov %%rsp, %%rdi
        \\call syscallDispatch
        // Restore registers
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%rbp
        \\pop %%rbx
        \\pop %%r9
        \\pop %%r8
        \\pop %%r10
        \\pop %%rdx
        \\pop %%rsi
        \\pop %%rdi
        \\pop %%rax           // Return value is in RAX
        \\pop %%rcx           // User RIP
        \\pop %%rsp           // User RSP (skip the push)
        \\pop %%r11           // User RFLAGS
        \\swapgs
        \\sysretq
    );
}

/// Main syscall dispatch function
export fn syscallDispatch(frame: *SyscallFrame) void {
    var ctx = SyscallContext.fromRegisters(frame);

    total_syscalls += 1;

    // Bounds check
    if (ctx.number >= MAX_SYSCALL) {
        frame.rax = @bitCast(Errno.ENOSYS);
        return;
    }

    syscall_counts[ctx.number] += 1;

    // Look up handler
    if (syscall_table[ctx.number]) |handler| {
        const result = handler(&ctx);
        frame.rax = @bitCast(result);
    } else {
        frame.rax = @bitCast(Errno.ENOSYS);
    }
}

/// Register a syscall handler
pub fn registerHandler(number: u64, handler: SyscallHandler) !void {
    if (number >= MAX_SYSCALL) return error.SyscallOutOfRange;
    syscall_table[number] = handler;
}

/// Unregister a syscall handler
pub fn unregisterHandler(number: u64) void {
    if (number >= MAX_SYSCALL) return;
    syscall_table[number] = null;
}

/// Register default syscall handlers
fn registerDefaultHandlers() void {
    // Process management
    syscall_table[@intFromEnum(SyscallNumber.getpid)] = handleGetpid;
    syscall_table[@intFromEnum(SyscallNumber.gettid)] = handleGettid;
    syscall_table[@intFromEnum(SyscallNumber.getuid)] = handleGetuid;
    syscall_table[@intFromEnum(SyscallNumber.getgid)] = handleGetgid;
    syscall_table[@intFromEnum(SyscallNumber.geteuid)] = handleGeteuid;
    syscall_table[@intFromEnum(SyscallNumber.getegid)] = handleGetegid;
    syscall_table[@intFromEnum(SyscallNumber.getppid)] = handleGetppid;
    syscall_table[@intFromEnum(SyscallNumber.exit)] = handleExit;
    syscall_table[@intFromEnum(SyscallNumber.exit_group)] = handleExitGroup;
    syscall_table[@intFromEnum(SyscallNumber.fork)] = handleFork;
    syscall_table[@intFromEnum(SyscallNumber.clone)] = handleClone;
    syscall_table[@intFromEnum(SyscallNumber.execve)] = handleExecve;
    syscall_table[@intFromEnum(SyscallNumber.wait4)] = handleWait4;

    // File operations
    syscall_table[@intFromEnum(SyscallNumber.read)] = handleRead;
    syscall_table[@intFromEnum(SyscallNumber.write)] = handleWrite;
    syscall_table[@intFromEnum(SyscallNumber.open)] = handleOpen;
    syscall_table[@intFromEnum(SyscallNumber.close)] = handleClose;
    syscall_table[@intFromEnum(SyscallNumber.lseek)] = handleLseek;
    syscall_table[@intFromEnum(SyscallNumber.ioctl)] = handleIoctl;

    // Memory management
    syscall_table[@intFromEnum(SyscallNumber.mmap)] = handleMmap;
    syscall_table[@intFromEnum(SyscallNumber.munmap)] = handleMunmap;
    syscall_table[@intFromEnum(SyscallNumber.mprotect)] = handleMprotect;
    syscall_table[@intFromEnum(SyscallNumber.brk)] = handleBrk;

    // System info
    syscall_table[@intFromEnum(SyscallNumber.uname)] = handleUname;
    syscall_table[@intFromEnum(SyscallNumber.sysinfo)] = handleSysinfo;
    syscall_table[@intFromEnum(SyscallNumber.clock_gettime)] = handleClockGettime;
    syscall_table[@intFromEnum(SyscallNumber.getrandom)] = handleGetrandom;

    // Zxyphor extensions
    syscall_table[@intFromEnum(SyscallNumber.zxy_async_io)] = handleZxyAsyncIo;
    syscall_table[@intFromEnum(SyscallNumber.zxy_fast_ipc)] = handleZxyFastIpc;
    syscall_table[@intFromEnum(SyscallNumber.zxy_zero_copy_send)] = handleZxyZeroCopySend;
}

// === Syscall Handler Implementations ===

fn handleGetpid(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Get current process PID from scheduler
    return 1; // Init process
}

fn handleGettid(ctx: *SyscallContext) i64 {
    _ = ctx;
    return 1;
}

fn handleGetuid(ctx: *SyscallContext) i64 {
    _ = ctx;
    return 0; // root
}

fn handleGetgid(ctx: *SyscallContext) i64 {
    _ = ctx;
    return 0;
}

fn handleGeteuid(ctx: *SyscallContext) i64 {
    _ = ctx;
    return 0;
}

fn handleGetegid(ctx: *SyscallContext) i64 {
    _ = ctx;
    return 0;
}

fn handleGetppid(ctx: *SyscallContext) i64 {
    _ = ctx;
    return 0; // Init has no parent
}

fn handleExit(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Terminate current thread
    return 0;
}

fn handleExitGroup(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Terminate all threads in process
    return 0;
}

fn handleFork(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Implement fork
    return Errno.ENOSYS;
}

fn handleClone(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Implement clone
    return Errno.ENOSYS;
}

fn handleExecve(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Implement execve
    return Errno.ENOSYS;
}

fn handleWait4(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleRead(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: fd read through VFS
    return Errno.ENOSYS;
}

fn handleWrite(ctx: *SyscallContext) i64 {
    const fd = ctx.arg1;
    const buf_ptr = ctx.arg2;
    const count = ctx.arg3;

    // Basic stdout/stderr support
    if (fd == 1 or fd == 2) {
        // Write to console
        if (buf_ptr == 0) return Errno.EFAULT;
        _ = count;
        // TODO: Write through TTY/console subsystem
        return @as(i64, @intCast(count));
    }

    return Errno.ENOSYS;
}

fn handleOpen(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleClose(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleLseek(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleIoctl(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleMmap(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Implement through VMM
    return Errno.ENOMEM;
}

fn handleMunmap(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleMprotect(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleBrk(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleUname(ctx: *SyscallContext) i64 {
    const buf_ptr = ctx.arg1;
    if (buf_ptr == 0) return Errno.EFAULT;

    // Utsname structure layout
    const UtsName = extern struct {
        sysname: [65]u8,
        nodename: [65]u8,
        release: [65]u8,
        version: [65]u8,
        machine: [65]u8,
        domainname: [65]u8,
    };

    const utsname = @as(*UtsName, @ptrFromInt(buf_ptr));

    // Zero and fill
    @memset(&utsname.sysname, 0);
    @memset(&utsname.nodename, 0);
    @memset(&utsname.release, 0);
    @memset(&utsname.version, 0);
    @memset(&utsname.machine, 0);
    @memset(&utsname.domainname, 0);

    const sysname = "Zxyphor";
    const release = "1.0.0-zxyphor";
    const version = "#1 SMP PREEMPT_DYNAMIC 2026";
    const machine = "x86_64";

    @memcpy(utsname.sysname[0..sysname.len], sysname);
    @memcpy(utsname.release[0..release.len], release);
    @memcpy(utsname.version[0..version.len], version);
    @memcpy(utsname.machine[0..machine.len], machine);

    return 0;
}

fn handleSysinfo(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleClockGettime(ctx: *SyscallContext) i64 {
    _ = ctx;
    return Errno.ENOSYS;
}

fn handleGetrandom(ctx: *SyscallContext) i64 {
    _ = ctx;
    // TODO: Integrate with crypto RNG subsystem
    return Errno.ENOSYS;
}

// Zxyphor extension handlers
fn handleZxyAsyncIo(ctx: *SyscallContext) i64 {
    _ = ctx;
    // Advanced async I/O with zero-copy and completion notifications
    return Errno.ENOSYS;
}

fn handleZxyFastIpc(ctx: *SyscallContext) i64 {
    _ = ctx;
    // Ultra-low-latency IPC using shared memory with capability tokens
    return Errno.ENOSYS;
}

fn handleZxyZeroCopySend(ctx: *SyscallContext) i64 {
    _ = ctx;
    // Zero-copy network send with page sharing
    return Errno.ENOSYS;
}

/// Get syscall statistics
pub fn getStats() struct { total: u64, per_syscall: *const [MAX_SYSCALL]u64 } {
    return .{
        .total = total_syscalls,
        .per_syscall = &syscall_counts,
    };
}

/// MSR helpers
fn writeMsr(msr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [ecx] "{ecx}" (msr),
          [eax] "{eax}" (low),
          [edx] "{edx}" (high),
    );
}

fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [eax] "={eax}" (low),
          [edx] "={edx}" (high),
        : [ecx] "{ecx}" (msr),
    );
    return @as(u64, high) << 32 | low;
}
