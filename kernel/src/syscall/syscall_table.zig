// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Syscall Dispatch and Implementation
// Full Linux-compatible system call layer with Zxyphor extensions

const std = @import("std");

// ============================================================================
// System Call Table
// ============================================================================

pub const SYS_read = 0;
pub const SYS_write = 1;
pub const SYS_open = 2;
pub const SYS_close = 3;
pub const SYS_stat = 4;
pub const SYS_fstat = 5;
pub const SYS_lstat = 6;
pub const SYS_poll = 7;
pub const SYS_lseek = 8;
pub const SYS_mmap = 9;
pub const SYS_mprotect = 10;
pub const SYS_munmap = 11;
pub const SYS_brk = 12;
pub const SYS_rt_sigaction = 13;
pub const SYS_rt_sigprocmask = 14;
pub const SYS_rt_sigreturn = 15;
pub const SYS_ioctl = 16;
pub const SYS_pread64 = 17;
pub const SYS_pwrite64 = 18;
pub const SYS_readv = 19;
pub const SYS_writev = 20;
pub const SYS_access = 21;
pub const SYS_pipe = 22;
pub const SYS_select = 23;
pub const SYS_sched_yield = 24;
pub const SYS_mremap = 25;
pub const SYS_msync = 26;
pub const SYS_mincore = 27;
pub const SYS_madvise = 28;
pub const SYS_shmget = 29;
pub const SYS_shmat = 30;
pub const SYS_shmctl = 31;
pub const SYS_dup = 32;
pub const SYS_dup2 = 33;
pub const SYS_pause = 34;
pub const SYS_nanosleep = 35;
pub const SYS_getitimer = 36;
pub const SYS_alarm = 37;
pub const SYS_setitimer = 38;
pub const SYS_getpid = 39;
pub const SYS_sendfile = 40;
pub const SYS_socket = 41;
pub const SYS_connect = 42;
pub const SYS_accept = 43;
pub const SYS_sendto = 44;
pub const SYS_recvfrom = 45;
pub const SYS_sendmsg = 46;
pub const SYS_recvmsg = 47;
pub const SYS_shutdown = 48;
pub const SYS_bind = 49;
pub const SYS_listen = 50;
pub const SYS_getsockname = 51;
pub const SYS_getpeername = 52;
pub const SYS_socketpair = 53;
pub const SYS_setsockopt = 54;
pub const SYS_getsockopt = 55;
pub const SYS_clone = 56;
pub const SYS_fork = 57;
pub const SYS_vfork = 58;
pub const SYS_execve = 59;
pub const SYS_exit = 60;
pub const SYS_wait4 = 61;
pub const SYS_kill = 62;
pub const SYS_uname = 63;
pub const SYS_semget = 64;
pub const SYS_semop = 65;
pub const SYS_semctl = 66;
pub const SYS_shmdt = 67;
pub const SYS_msgget = 68;
pub const SYS_msgsnd = 69;
pub const SYS_msgrcv = 70;
pub const SYS_msgctl = 71;
pub const SYS_fcntl = 72;
pub const SYS_flock = 73;
pub const SYS_fsync = 74;
pub const SYS_fdatasync = 75;
pub const SYS_truncate = 76;
pub const SYS_ftruncate = 77;
pub const SYS_getdents = 78;
pub const SYS_getcwd = 79;
pub const SYS_chdir = 80;
pub const SYS_fchdir = 81;
pub const SYS_rename = 82;
pub const SYS_mkdir = 83;
pub const SYS_rmdir = 84;
pub const SYS_creat = 85;
pub const SYS_link = 86;
pub const SYS_unlink = 87;
pub const SYS_symlink = 88;
pub const SYS_readlink = 89;
pub const SYS_chmod = 90;
pub const SYS_fchmod = 91;
pub const SYS_chown = 92;
pub const SYS_fchown = 93;
pub const SYS_lchown = 94;
pub const SYS_umask = 95;
pub const SYS_gettimeofday = 96;
pub const SYS_getrlimit = 97;
pub const SYS_getrusage = 98;
pub const SYS_sysinfo = 99;
pub const SYS_times = 100;
pub const SYS_ptrace = 101;
pub const SYS_getuid = 102;
pub const SYS_syslog = 103;
pub const SYS_getgid = 104;
pub const SYS_setuid = 105;
pub const SYS_setgid = 106;
pub const SYS_geteuid = 107;
pub const SYS_getegid = 108;
pub const SYS_setpgid = 109;
pub const SYS_getppid = 110;
pub const SYS_getpgrp = 111;
pub const SYS_setsid = 112;
pub const SYS_setreuid = 113;
pub const SYS_setregid = 114;
pub const SYS_getgroups = 115;
pub const SYS_setgroups = 116;
pub const SYS_setresuid = 117;
pub const SYS_getresuid = 118;
pub const SYS_setresgid = 119;
pub const SYS_getresgid = 120;
pub const SYS_getpgid = 121;
pub const SYS_setfsuid = 122;
pub const SYS_setfsgid = 123;
pub const SYS_getsid = 124;
pub const SYS_capget = 125;
pub const SYS_capset = 126;
pub const SYS_rt_sigpending = 127;
pub const SYS_rt_sigtimedwait = 128;
pub const SYS_rt_sigqueueinfo = 129;
pub const SYS_rt_sigsuspend = 130;
pub const SYS_sigaltstack = 131;
pub const SYS_utime = 132;
pub const SYS_mknod = 133;
pub const SYS_uselib = 134;
pub const SYS_personality = 135;
pub const SYS_ustat = 136;
pub const SYS_statfs = 137;
pub const SYS_fstatfs = 138;
pub const SYS_sysfs = 139;
pub const SYS_getpriority = 140;
pub const SYS_setpriority = 141;
pub const SYS_sched_setparam = 142;
pub const SYS_sched_getparam = 143;
pub const SYS_sched_setscheduler = 144;
pub const SYS_sched_getscheduler = 145;
pub const SYS_sched_get_priority_max = 146;
pub const SYS_sched_get_priority_min = 147;
pub const SYS_sched_rr_get_interval = 148;
pub const SYS_mlock = 149;
pub const SYS_munlock = 150;
pub const SYS_mlockall = 151;
pub const SYS_munlockall = 152;
pub const SYS_vhangup = 153;
pub const SYS_modify_ldt = 154;
pub const SYS_pivot_root = 155;
pub const SYS__sysctl = 156;
pub const SYS_prctl = 157;
pub const SYS_arch_prctl = 158;
pub const SYS_adjtimex = 159;
pub const SYS_setrlimit = 160;
pub const SYS_chroot = 161;
pub const SYS_sync = 162;
pub const SYS_acct = 163;
pub const SYS_settimeofday = 164;
pub const SYS_mount = 165;
pub const SYS_umount2 = 166;
pub const SYS_swapon = 167;
pub const SYS_swapoff = 168;
pub const SYS_reboot = 169;
pub const SYS_sethostname = 170;
pub const SYS_setdomainname = 171;
pub const SYS_iopl = 172;
pub const SYS_ioperm = 173;
pub const SYS_create_module = 174;
pub const SYS_init_module = 175;
pub const SYS_delete_module = 176;
pub const SYS_get_kernel_syms = 177;
pub const SYS_query_module = 178;
pub const SYS_quotactl = 179;
pub const SYS_nfsservctl = 180;
pub const SYS_gettid = 186;
pub const SYS_readahead = 187;
pub const SYS_setxattr = 188;
pub const SYS_lsetxattr = 189;
pub const SYS_fsetxattr = 190;
pub const SYS_getxattr = 191;
pub const SYS_lgetxattr = 192;
pub const SYS_fgetxattr = 193;
pub const SYS_listxattr = 194;
pub const SYS_llistxattr = 195;
pub const SYS_flistxattr = 196;
pub const SYS_removexattr = 197;
pub const SYS_lremovexattr = 198;
pub const SYS_fremovexattr = 199;
pub const SYS_tkill = 200;
pub const SYS_time = 201;
pub const SYS_futex = 202;
pub const SYS_sched_setaffinity = 203;
pub const SYS_sched_getaffinity = 204;
pub const SYS_set_thread_area = 205;
pub const SYS_io_setup = 206;
pub const SYS_io_destroy = 207;
pub const SYS_io_getevents = 208;
pub const SYS_io_submit = 209;
pub const SYS_io_cancel = 210;
pub const SYS_get_thread_area = 211;
pub const SYS_lookup_dcookie = 212;
pub const SYS_epoll_create = 213;
pub const SYS_remap_file_pages = 216;
pub const SYS_getdents64 = 217;
pub const SYS_set_tid_address = 218;
pub const SYS_restart_syscall = 219;
pub const SYS_semtimedop = 220;
pub const SYS_fadvise64 = 221;
pub const SYS_timer_create = 222;
pub const SYS_timer_settime = 223;
pub const SYS_timer_gettime = 224;
pub const SYS_timer_getoverrun = 225;
pub const SYS_timer_delete = 226;
pub const SYS_clock_settime = 227;
pub const SYS_clock_gettime = 228;
pub const SYS_clock_getres = 229;
pub const SYS_clock_nanosleep = 230;
pub const SYS_exit_group = 231;
pub const SYS_epoll_wait = 232;
pub const SYS_epoll_ctl = 233;
pub const SYS_tgkill = 234;
pub const SYS_utimes = 235;
pub const SYS_mbind = 237;
pub const SYS_set_mempolicy = 238;
pub const SYS_get_mempolicy = 239;
pub const SYS_mq_open = 240;
pub const SYS_mq_unlink = 241;
pub const SYS_mq_timedsend = 242;
pub const SYS_mq_timedreceive = 243;
pub const SYS_mq_notify = 244;
pub const SYS_mq_getsetattr = 245;
pub const SYS_kexec_load = 246;
pub const SYS_waitid = 247;
pub const SYS_add_key = 248;
pub const SYS_request_key = 249;
pub const SYS_keyctl = 250;
pub const SYS_ioprio_set = 251;
pub const SYS_ioprio_get = 252;
pub const SYS_inotify_init = 253;
pub const SYS_inotify_add_watch = 254;
pub const SYS_inotify_rm_watch = 255;
pub const SYS_migrate_pages = 256;
pub const SYS_openat = 257;
pub const SYS_mkdirat = 258;
pub const SYS_mknodat = 259;
pub const SYS_fchownat = 260;
pub const SYS_futimesat = 261;
pub const SYS_newfstatat = 262;
pub const SYS_unlinkat = 263;
pub const SYS_renameat = 264;
pub const SYS_linkat = 265;
pub const SYS_symlinkat = 266;
pub const SYS_readlinkat = 267;
pub const SYS_fchmodat = 268;
pub const SYS_faccessat = 269;
pub const SYS_pselect6 = 270;
pub const SYS_ppoll = 271;
pub const SYS_unshare = 272;
pub const SYS_set_robust_list = 273;
pub const SYS_get_robust_list = 274;
pub const SYS_splice = 275;
pub const SYS_tee = 276;
pub const SYS_sync_file_range = 277;
pub const SYS_vmsplice = 278;
pub const SYS_move_pages = 279;
pub const SYS_utimensat = 280;
pub const SYS_epoll_pwait = 281;
pub const SYS_signalfd = 282;
pub const SYS_timerfd_create = 283;
pub const SYS_eventfd = 284;
pub const SYS_fallocate = 285;
pub const SYS_timerfd_settime = 286;
pub const SYS_timerfd_gettime = 287;
pub const SYS_accept4 = 288;
pub const SYS_signalfd4 = 289;
pub const SYS_eventfd2 = 290;
pub const SYS_epoll_create1 = 291;
pub const SYS_dup3 = 292;
pub const SYS_pipe2 = 293;
pub const SYS_inotify_init1 = 294;
pub const SYS_preadv = 295;
pub const SYS_pwritev = 296;
pub const SYS_rt_tgsigqueueinfo = 297;
pub const SYS_perf_event_open = 298;
pub const SYS_recvmmsg = 299;
pub const SYS_fanotify_init = 300;
pub const SYS_fanotify_mark = 301;
pub const SYS_prlimit64 = 302;
pub const SYS_name_to_handle_at = 303;
pub const SYS_open_by_handle_at = 304;
pub const SYS_clock_adjtime = 305;
pub const SYS_syncfs = 306;
pub const SYS_sendmmsg = 307;
pub const SYS_setns = 308;
pub const SYS_getcpu = 309;
pub const SYS_process_vm_readv = 310;
pub const SYS_process_vm_writev = 311;
pub const SYS_kcmp = 312;
pub const SYS_finit_module = 313;
pub const SYS_sched_setattr = 314;
pub const SYS_sched_getattr = 315;
pub const SYS_renameat2 = 316;
pub const SYS_seccomp = 317;
pub const SYS_getrandom = 318;
pub const SYS_memfd_create = 319;
pub const SYS_kexec_file_load = 320;
pub const SYS_bpf = 321;
pub const SYS_execveat = 322;
pub const SYS_userfaultfd = 323;
pub const SYS_membarrier = 324;
pub const SYS_mlock2 = 325;
pub const SYS_copy_file_range = 326;
pub const SYS_preadv2 = 327;
pub const SYS_pwritev2 = 328;
pub const SYS_pkey_mprotect = 329;
pub const SYS_pkey_alloc = 330;
pub const SYS_pkey_free = 331;
pub const SYS_statx = 332;
pub const SYS_io_pgetevents = 333;
pub const SYS_rseq = 334;
pub const SYS_pidfd_send_signal = 424;
pub const SYS_io_uring_setup = 425;
pub const SYS_io_uring_enter = 426;
pub const SYS_io_uring_register = 427;
pub const SYS_open_tree = 428;
pub const SYS_move_mount = 429;
pub const SYS_fsopen = 430;
pub const SYS_fsconfig = 431;
pub const SYS_fsmount = 432;
pub const SYS_fspick = 433;
pub const SYS_pidfd_open = 434;
pub const SYS_clone3 = 435;
pub const SYS_close_range = 436;
pub const SYS_openat2 = 437;
pub const SYS_pidfd_getfd = 438;
pub const SYS_faccessat2 = 439;
pub const SYS_process_madvise = 440;
pub const SYS_epoll_pwait2 = 441;
pub const SYS_mount_setattr = 442;
pub const SYS_quotactl_fd = 443;
pub const SYS_landlock_create_ruleset = 444;
pub const SYS_landlock_add_rule = 445;
pub const SYS_landlock_restrict_self = 446;
pub const SYS_memfd_secret = 447;
pub const SYS_process_mrelease = 448;
pub const SYS_futex_waitv = 449;
pub const SYS_set_mempolicy_home_node = 450;
pub const SYS_cachestat = 451;
pub const SYS_fchmodat2 = 452;
pub const SYS_map_shadow_stack = 453;
pub const SYS_futex_wake = 454;
pub const SYS_futex_wait = 455;
pub const SYS_futex_requeue = 456;
pub const SYS_statmount = 457;
pub const SYS_listmount = 458;
pub const SYS_lsm_get_self_attr = 459;
pub const SYS_lsm_set_self_attr = 460;
pub const SYS_lsm_list_modules = 461;
pub const SYS_mseal = 462;

// Zxyphor custom syscalls (start at 512)
pub const SYS_zxy_channel_create = 512;
pub const SYS_zxy_channel_send = 513;
pub const SYS_zxy_channel_recv = 514;
pub const SYS_zxy_channel_close = 515;
pub const SYS_zxy_cap_grant = 516;
pub const SYS_zxy_cap_revoke = 517;
pub const SYS_zxy_cap_derive = 518;
pub const SYS_zxy_ipc_notify = 519;
pub const SYS_zxy_vm_map_phys = 520;
pub const SYS_zxy_sched_hint = 521;
pub const SYS_zxy_perf_submit = 522;
pub const SYS_zxy_gpu_submit = 523;
pub const SYS_zxy_nvme_passthru = 524;
pub const SYS_zxy_zero_copy = 525;
pub const SYS_zxy_batch_io = 526;
pub const SYS_zxy_kvm_run = 527;

pub const NR_SYSCALLS = 528;

// ============================================================================
// Syscall Register Frame (x86_64)
// ============================================================================

pub const SyscallFrame = struct {
    // Saved by hardware/entry code
    rax: u64 = 0, // Syscall number / return value
    rdi: u64 = 0, // Arg 1
    rsi: u64 = 0, // Arg 2
    rdx: u64 = 0, // Arg 3
    r10: u64 = 0, // Arg 4
    r8: u64 = 0, // Arg 5
    r9: u64 = 0, // Arg 6
    // Callee-saved
    rbx: u64 = 0,
    rbp: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    // Hardware saved
    rip: u64 = 0,
    cs: u64 = 0,
    rflags: u64 = 0,
    rsp: u64 = 0,
    ss: u64 = 0,

    pub fn syscall_nr(self: *const SyscallFrame) u64 {
        return self.rax;
    }

    pub fn arg0(self: *const SyscallFrame) u64 { return self.rdi; }
    pub fn arg1(self: *const SyscallFrame) u64 { return self.rsi; }
    pub fn arg2(self: *const SyscallFrame) u64 { return self.rdx; }
    pub fn arg3(self: *const SyscallFrame) u64 { return self.r10; }
    pub fn arg4(self: *const SyscallFrame) u64 { return self.r8; }
    pub fn arg5(self: *const SyscallFrame) u64 { return self.r9; }

    pub fn set_return(self: *SyscallFrame, val: u64) void {
        self.rax = val;
    }

    pub fn set_error(self: *SyscallFrame, errno: i64) void {
        self.rax = @bitCast(@as(i64, -errno));
    }
};

// ============================================================================
// Error Numbers
// ============================================================================

pub const EPERM = 1;
pub const ENOENT = 2;
pub const ESRCH = 3;
pub const EINTR = 4;
pub const EIO = 5;
pub const ENXIO = 6;
pub const E2BIG = 7;
pub const ENOEXEC = 8;
pub const EBADF = 9;
pub const ECHILD = 10;
pub const EAGAIN = 11;
pub const ENOMEM = 12;
pub const EACCES = 13;
pub const EFAULT = 14;
pub const ENOTBLK = 15;
pub const EBUSY = 16;
pub const EEXIST = 17;
pub const EXDEV = 18;
pub const ENODEV = 19;
pub const ENOTDIR = 20;
pub const EISDIR = 21;
pub const EINVAL = 22;
pub const ENFILE = 23;
pub const EMFILE = 24;
pub const ENOTTY = 25;
pub const ETXTBSY = 26;
pub const EFBIG = 27;
pub const ENOSPC = 28;
pub const ESPIPE = 29;
pub const EROFS = 30;
pub const EMLINK = 31;
pub const EPIPE = 32;
pub const EDOM = 33;
pub const ERANGE = 34;
pub const EDEADLK = 35;
pub const ENAMETOOLONG = 36;
pub const ENOLCK = 37;
pub const ENOSYS = 38;
pub const ENOTEMPTY = 39;
pub const ELOOP = 40;
pub const EWOULDBLOCK = EAGAIN;
pub const ENOMSG = 42;
pub const EIDRM = 43;
pub const ENOSTR = 60;
pub const ENODATA = 61;
pub const ETIME = 62;
pub const ENOSR = 63;
pub const ENONET = 64;
pub const EOVERFLOW = 75;
pub const EDQUOT = 122;
pub const ENOSYS_NOT_IMPL = 38;

// Socket errors
pub const ENOTSOCK = 88;
pub const EDESTADDRREQ = 89;
pub const EMSGSIZE = 90;
pub const EPROTOTYPE = 91;
pub const ENOPROTOOPT = 92;
pub const EPROTONOSUPPORT = 93;
pub const ESOCKTNOSUPPORT = 94;
pub const EOPNOTSUPP = 95;
pub const EPFNOSUPPORT = 96;
pub const EAFNOSUPPORT = 97;
pub const EADDRINUSE = 98;
pub const EADDRNOTAVAIL = 99;
pub const ENETDOWN = 100;
pub const ENETUNREACH = 101;
pub const ENETRESET = 102;
pub const ECONNABORTED = 103;
pub const ECONNRESET = 104;
pub const ENOBUFS = 105;
pub const EISCONN = 106;
pub const ENOTCONN = 107;
pub const ESHUTDOWN = 108;
pub const ETOOMANYREFS = 109;
pub const ETIMEDOUT = 110;
pub const ECONNREFUSED = 111;
pub const EHOSTDOWN = 112;
pub const EHOSTUNREACH = 113;
pub const EALREADY = 114;
pub const EINPROGRESS = 115;
pub const ESTALE = 116;

// ============================================================================
// Syscall Structures
// ============================================================================

pub const Timespec = extern struct {
    tv_sec: i64,
    tv_nsec: i64,
};

pub const Timeval = extern struct {
    tv_sec: i64,
    tv_usec: i64,
};

pub const Stat = extern struct {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atim: Timespec,
    st_mtim: Timespec,
    st_ctim: Timespec,
    __reserved: [3]i64,
};

pub const Statx = extern struct {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    stx_subvol: u64,
    stx_atomic_write_unit_min: u32,
    stx_atomic_write_unit_max: u32,
    stx_atomic_write_segments_max: u32,
    __spare1: [1]u32,
    __spare2: [12]u64,
};

pub const StatxTimestamp = extern struct {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
};

pub const Iovec = extern struct {
    iov_base: u64, // void*
    iov_len: u64,
};

pub const Utsname = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
    domainname: [65]u8,
};

pub const Sysinfo = extern struct {
    uptime: i64,
    loads: [3]u64,
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    _f: [0]u8,
};

pub const Rusage = extern struct {
    ru_utime: Timeval,
    ru_stime: Timeval,
    ru_maxrss: i64,
    ru_ixrss: i64,
    ru_idrss: i64,
    ru_isrss: i64,
    ru_minflt: i64,
    ru_majflt: i64,
    ru_nswap: i64,
    ru_inblock: i64,
    ru_oublock: i64,
    ru_msgsnd: i64,
    ru_msgrcv: i64,
    ru_nsignals: i64,
    ru_nvcsw: i64,
    ru_nivcsw: i64,
};

pub const Rlimit = extern struct {
    rlim_cur: u64,
    rlim_max: u64,
};

pub const RLIM_INFINITY: u64 = 0xFFFFFFFFFFFFFFFF;

pub const RLIMIT_CPU = 0;
pub const RLIMIT_FSIZE = 1;
pub const RLIMIT_DATA = 2;
pub const RLIMIT_STACK = 3;
pub const RLIMIT_CORE = 4;
pub const RLIMIT_RSS = 5;
pub const RLIMIT_NPROC = 6;
pub const RLIMIT_NOFILE = 7;
pub const RLIMIT_MEMLOCK = 8;
pub const RLIMIT_AS = 9;
pub const RLIMIT_LOCKS = 10;
pub const RLIMIT_SIGPENDING = 11;
pub const RLIMIT_MSGQUEUE = 12;
pub const RLIMIT_NICE = 13;
pub const RLIMIT_RTPRIO = 14;
pub const RLIMIT_RTTIME = 15;

// ============================================================================
// Open Flags
// ============================================================================

pub const O_RDONLY = 0o0;
pub const O_WRONLY = 0o1;
pub const O_RDWR = 0o2;
pub const O_ACCMODE = 0o3;
pub const O_CREAT = 0o100;
pub const O_EXCL = 0o200;
pub const O_NOCTTY = 0o400;
pub const O_TRUNC = 0o1000;
pub const O_APPEND = 0o2000;
pub const O_NONBLOCK = 0o4000;
pub const O_DSYNC = 0o10000;
pub const O_SYNC = 0o4010000;
pub const O_ASYNC = 0o20000;
pub const O_DIRECT = 0o40000;
pub const O_LARGEFILE = 0o100000;
pub const O_DIRECTORY = 0o200000;
pub const O_NOFOLLOW = 0o400000;
pub const O_NOATIME = 0o1000000;
pub const O_CLOEXEC = 0o2000000;
pub const O_PATH = 0o10000000;
pub const O_TMPFILE = 0o20200000;

// ============================================================================
// mmap flags
// ============================================================================

pub const PROT_NONE = 0x0;
pub const PROT_READ = 0x1;
pub const PROT_WRITE = 0x2;
pub const PROT_EXEC = 0x4;
pub const PROT_GROWSDOWN = 0x01000000;
pub const PROT_GROWSUP = 0x02000000;

pub const MAP_SHARED = 0x01;
pub const MAP_PRIVATE = 0x02;
pub const MAP_SHARED_VALIDATE = 0x03;
pub const MAP_FIXED = 0x10;
pub const MAP_ANONYMOUS = 0x20;
pub const MAP_GROWSDOWN = 0x0100;
pub const MAP_DENYWRITE = 0x0800;
pub const MAP_EXECUTABLE = 0x1000;
pub const MAP_LOCKED = 0x2000;
pub const MAP_NORESERVE = 0x4000;
pub const MAP_POPULATE = 0x8000;
pub const MAP_NONBLOCK = 0x10000;
pub const MAP_STACK = 0x20000;
pub const MAP_HUGETLB = 0x40000;
pub const MAP_SYNC = 0x80000;
pub const MAP_FIXED_NOREPLACE = 0x100000;

// ============================================================================
// Signal Numbers
// ============================================================================

pub const SIGHUP = 1;
pub const SIGINT = 2;
pub const SIGQUIT = 3;
pub const SIGILL = 4;
pub const SIGTRAP = 5;
pub const SIGABRT = 6;
pub const SIGBUS = 7;
pub const SIGFPE = 8;
pub const SIGKILL = 9;
pub const SIGUSR1 = 10;
pub const SIGSEGV = 11;
pub const SIGUSR2 = 12;
pub const SIGPIPE = 13;
pub const SIGALRM = 14;
pub const SIGTERM = 15;
pub const SIGSTKFLT = 16;
pub const SIGCHLD = 17;
pub const SIGCONT = 18;
pub const SIGSTOP = 19;
pub const SIGTSTP = 20;
pub const SIGTTIN = 21;
pub const SIGTTOU = 22;
pub const SIGURG = 23;
pub const SIGXCPU = 24;
pub const SIGXFSZ = 25;
pub const SIGVTALRM = 26;
pub const SIGPROF = 27;
pub const SIGWINCH = 28;
pub const SIGIO = 29;
pub const SIGPWR = 30;
pub const SIGSYS = 31;
pub const SIGRTMIN = 32;
pub const SIGRTMAX = 64;
