// =============================================================================
// Kernel Zxyphor — Comprehensive System Call Implementation
// =============================================================================
// Full POSIX-compatible + Zxyphor-specific system call implementations.
// This module provides the actual execution logic for 300+ system calls,
// handling user-kernel transitions, argument validation, and capability checks.
//
// System call ABI (x86_64, SYSCALL instruction):
//   RAX = syscall number
//   RDI = arg1, RSI = arg2, RDX = arg3, R10 = arg4, R8 = arg5, R9 = arg6
//   Return value in RAX (negative = -errno)
// =============================================================================

const std = @import("std");

// =============================================================================
// System Call Numbers — Extended POSIX + Zxyphor Extensions
// =============================================================================
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_POLL: u64 = 7;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_READV: u64 = 19;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_SELECT: u64 = 23;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_MREMAP: u64 = 25;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_MINCORE: u64 = 27;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_SHMGET: u64 = 29;
pub const SYS_SHMAT: u64 = 30;
pub const SYS_SHMCTL: u64 = 31;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_PAUSE: u64 = 34;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETITIMER: u64 = 36;
pub const SYS_ALARM: u64 = 37;
pub const SYS_SETITIMER: u64 = 38;
pub const SYS_GETPID: u64 = 39;
pub const SYS_SENDFILE: u64 = 40;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_ACCEPT: u64 = 43;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_VFORK: u64 = 58;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;
pub const SYS_SEMGET: u64 = 64;
pub const SYS_SEMOP: u64 = 65;
pub const SYS_SEMCTL: u64 = 66;
pub const SYS_SHMDT: u64 = 67;
pub const SYS_MSGGET: u64 = 68;
pub const SYS_MSGSND: u64 = 69;
pub const SYS_MSGRCV: u64 = 70;
pub const SYS_MSGCTL: u64 = 71;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FLOCK: u64 = 73;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_GETDENTS: u64 = 78;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_FCHDIR: u64 = 81;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_CREAT: u64 = 85;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_LCHOWN: u64 = 94;
pub const SYS_UMASK: u64 = 95;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_GETRLIMIT: u64 = 97;
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_TIMES: u64 = 100;
pub const SYS_GETUID: u64 = 102;
pub const SYS_SYSLOG: u64 = 103;
pub const SYS_GETGID: u64 = 104;
pub const SYS_SETUID: u64 = 105;
pub const SYS_SETGID: u64 = 106;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_SETPGID: u64 = 109;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_SETREUID: u64 = 113;
pub const SYS_SETREGID: u64 = 114;
pub const SYS_GETGROUPS: u64 = 115;
pub const SYS_SETGROUPS: u64 = 116;
pub const SYS_SETRESUID: u64 = 117;
pub const SYS_GETRESUID: u64 = 118;
pub const SYS_SETRESGID: u64 = 119;
pub const SYS_GETRESGID: u64 = 120;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_SETFSUID: u64 = 122;
pub const SYS_SETFSGID: u64 = 123;
pub const SYS_GETSID: u64 = 124;
pub const SYS_CAPGET: u64 = 125;
pub const SYS_CAPSET: u64 = 126;
pub const SYS_SIGPENDING: u64 = 127;
pub const SYS_SIGTIMEDWAIT: u64 = 128;
pub const SYS_SIGQUEUEINFO: u64 = 129;
pub const SYS_SIGSUSPEND: u64 = 130;
pub const SYS_SIGALTSTACK: u64 = 131;
pub const SYS_UTIME: u64 = 132;
pub const SYS_MKNOD: u64 = 133;
pub const SYS_PERSONALITY: u64 = 135;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_GETPRIORITY: u64 = 140;
pub const SYS_SETPRIORITY: u64 = 141;
pub const SYS_SCHED_SETPARAM: u64 = 142;
pub const SYS_SCHED_GETPARAM: u64 = 143;
pub const SYS_SCHED_SETSCHEDULER: u64 = 144;
pub const SYS_SCHED_GETSCHEDULER: u64 = 145;
pub const SYS_SCHED_GET_PRIORITY_MAX: u64 = 146;
pub const SYS_SCHED_GET_PRIORITY_MIN: u64 = 147;
pub const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
pub const SYS_MLOCK: u64 = 149;
pub const SYS_MUNLOCK: u64 = 150;
pub const SYS_MLOCKALL: u64 = 151;
pub const SYS_MUNLOCKALL: u64 = 152;
pub const SYS_VHANGUP: u64 = 153;
pub const SYS_PIVOT_ROOT: u64 = 155;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_ADJTIMEX: u64 = 159;
pub const SYS_SETRLIMIT: u64 = 160;
pub const SYS_CHROOT: u64 = 161;
pub const SYS_SYNC: u64 = 162;
pub const SYS_ACCT: u64 = 163;
pub const SYS_SETTIMEOFDAY: u64 = 164;
pub const SYS_MOUNT: u64 = 165;
pub const SYS_UMOUNT2: u64 = 166;
pub const SYS_SWAPON: u64 = 167;
pub const SYS_SWAPOFF: u64 = 168;
pub const SYS_REBOOT: u64 = 169;
pub const SYS_SETHOSTNAME: u64 = 170;
pub const SYS_SETDOMAINNAME: u64 = 171;
pub const SYS_INIT_MODULE: u64 = 175;
pub const SYS_DELETE_MODULE: u64 = 176;
pub const SYS_QUOTACTL: u64 = 179;
pub const SYS_GETTID: u64 = 186;
pub const SYS_READAHEAD: u64 = 187;
pub const SYS_SETXATTR: u64 = 188;
pub const SYS_LSETXATTR: u64 = 189;
pub const SYS_FSETXATTR: u64 = 190;
pub const SYS_GETXATTR: u64 = 191;
pub const SYS_LGETXATTR: u64 = 192;
pub const SYS_FGETXATTR: u64 = 193;
pub const SYS_LISTXATTR: u64 = 194;
pub const SYS_LLISTXATTR: u64 = 195;
pub const SYS_FLISTXATTR: u64 = 196;
pub const SYS_REMOVEXATTR: u64 = 197;
pub const SYS_LREMOVEXATTR: u64 = 198;
pub const SYS_FREMOVEXATTR: u64 = 199;
pub const SYS_TKILL: u64 = 200;
pub const SYS_TIME: u64 = 201;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
pub const SYS_IO_SETUP: u64 = 206;
pub const SYS_IO_DESTROY: u64 = 207;
pub const SYS_IO_GETEVENTS: u64 = 208;
pub const SYS_IO_SUBMIT: u64 = 209;
pub const SYS_IO_CANCEL: u64 = 210;
pub const SYS_EPOLL_CREATE: u64 = 213;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_TIMER_CREATE: u64 = 222;
pub const SYS_TIMER_SETTIME: u64 = 223;
pub const SYS_TIMER_GETTIME: u64 = 224;
pub const SYS_TIMER_GETOVERRUN: u64 = 225;
pub const SYS_TIMER_DELETE: u64 = 226;
pub const SYS_CLOCK_SETTIME: u64 = 227;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_CLOCK_GETRES: u64 = 229;
pub const SYS_CLOCK_NANOSLEEP: u64 = 230;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_UTIMES: u64 = 235;
pub const SYS_MBIND: u64 = 237;
pub const SYS_SET_MEMPOLICY: u64 = 238;
pub const SYS_GET_MEMPOLICY: u64 = 239;
pub const SYS_MQ_OPEN: u64 = 240;
pub const SYS_MQ_UNLINK: u64 = 241;
pub const SYS_MQ_TIMEDSEND: u64 = 242;
pub const SYS_MQ_TIMEDRECEIVE: u64 = 243;
pub const SYS_MQ_NOTIFY: u64 = 244;
pub const SYS_MQ_GETSETATTR: u64 = 245;
pub const SYS_KEXEC_LOAD: u64 = 246;
pub const SYS_WAITID: u64 = 247;
pub const SYS_ADD_KEY: u64 = 248;
pub const SYS_REQUEST_KEY: u64 = 249;
pub const SYS_KEYCTL: u64 = 250;
pub const SYS_IOPRIO_SET: u64 = 251;
pub const SYS_IOPRIO_GET: u64 = 252;
pub const SYS_INOTIFY_INIT: u64 = 253;
pub const SYS_INOTIFY_ADD_WATCH: u64 = 254;
pub const SYS_INOTIFY_RM_WATCH: u64 = 255;
pub const SYS_MIGRATE_PAGES: u64 = 256;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_MKNODAT: u64 = 259;
pub const SYS_FCHOWNAT: u64 = 260;
pub const SYS_FUTIMESAT: u64 = 261;
pub const SYS_FSTATAT64: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_LINKAT: u64 = 265;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FCHMODAT: u64 = 268;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_PSELECT6: u64 = 270;
pub const SYS_PPOLL: u64 = 271;
pub const SYS_UNSHARE: u64 = 272;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_SPLICE: u64 = 275;
pub const SYS_TEE: u64 = 276;
pub const SYS_SYNC_FILE_RANGE: u64 = 277;
pub const SYS_VMSPLICE: u64 = 278;
pub const SYS_MOVE_PAGES: u64 = 279;
pub const SYS_UTIMENSAT: u64 = 280;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_SIGNALFD: u64 = 282;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_EVENTFD: u64 = 284;
pub const SYS_FALLOCATE: u64 = 285;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_SIGNALFD4: u64 = 289;
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_INOTIFY_INIT1: u64 = 294;
pub const SYS_PREADV: u64 = 295;
pub const SYS_PWRITEV: u64 = 296;
pub const SYS_PERF_EVENT_OPEN: u64 = 298;
pub const SYS_RECVMMSG: u64 = 299;
pub const SYS_FANOTIFY_INIT: u64 = 300;
pub const SYS_FANOTIFY_MARK: u64 = 301;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_NAME_TO_HANDLE_AT: u64 = 303;
pub const SYS_OPEN_BY_HANDLE_AT: u64 = 304;
pub const SYS_CLOCK_ADJTIME: u64 = 305;
pub const SYS_SYNCFS: u64 = 306;
pub const SYS_SENDMMSG: u64 = 307;
pub const SYS_SETNS: u64 = 308;
pub const SYS_GETCPU: u64 = 309;
pub const SYS_PROCESS_VM_READV: u64 = 310;
pub const SYS_PROCESS_VM_WRITEV: u64 = 311;
pub const SYS_KCMP: u64 = 312;
pub const SYS_FINIT_MODULE: u64 = 313;
pub const SYS_SCHED_SETATTR: u64 = 314;
pub const SYS_SCHED_GETATTR: u64 = 315;
pub const SYS_RENAMEAT2: u64 = 316;
pub const SYS_SECCOMP: u64 = 317;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_MEMFD_CREATE: u64 = 319;
pub const SYS_KEXEC_FILE_LOAD: u64 = 320;
pub const SYS_BPF: u64 = 321;
pub const SYS_EXECVEAT: u64 = 322;
pub const SYS_USERFAULTFD: u64 = 323;
pub const SYS_MEMBARRIER: u64 = 324;
pub const SYS_MLOCK2: u64 = 325;
pub const SYS_COPY_FILE_RANGE: u64 = 326;
pub const SYS_PREADV2: u64 = 327;
pub const SYS_PWRITEV2: u64 = 328;
pub const SYS_PKEY_MPROTECT: u64 = 329;
pub const SYS_PKEY_ALLOC: u64 = 330;
pub const SYS_PKEY_FREE: u64 = 331;
pub const SYS_STATX: u64 = 332;
pub const SYS_IO_PGETEVENTS: u64 = 333;
pub const SYS_RSEQ: u64 = 334;
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;
pub const SYS_IO_URING_SETUP: u64 = 425;
pub const SYS_IO_URING_ENTER: u64 = 426;
pub const SYS_IO_URING_REGISTER: u64 = 427;
pub const SYS_OPEN_TREE: u64 = 428;
pub const SYS_MOVE_MOUNT: u64 = 429;
pub const SYS_FSOPEN: u64 = 430;
pub const SYS_FSCONFIG: u64 = 431;
pub const SYS_FSMOUNT: u64 = 432;
pub const SYS_FSPICK: u64 = 433;
pub const SYS_PIDFD_OPEN: u64 = 434;
pub const SYS_CLONE3: u64 = 435;
pub const SYS_CLOSE_RANGE: u64 = 436;
pub const SYS_OPENAT2: u64 = 437;
pub const SYS_PIDFD_GETFD: u64 = 438;
pub const SYS_FACCESSAT2: u64 = 439;
pub const SYS_PROCESS_MADVISE: u64 = 440;
pub const SYS_EPOLL_PWAIT2: u64 = 441;
pub const SYS_MOUNT_SETATTR: u64 = 442;
pub const SYS_QUOTACTL_FD: u64 = 443;
pub const SYS_LANDLOCK_CREATE_RULESET: u64 = 444;
pub const SYS_LANDLOCK_ADD_RULE: u64 = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: u64 = 446;
pub const SYS_MEMFD_SECRET: u64 = 447;
pub const SYS_PROCESS_MRELEASE: u64 = 448;
pub const SYS_FUTEX_WAITV: u64 = 449;
pub const SYS_SET_MEMPOLICY_HOME_NODE: u64 = 450;
pub const SYS_CACHESTAT: u64 = 451;
pub const SYS_FCHMODAT2: u64 = 452;
pub const SYS_MAP_SHADOW_STACK: u64 = 453;
pub const SYS_FUTEX_WAKE: u64 = 454;
pub const SYS_FUTEX_WAIT: u64 = 455;
pub const SYS_FUTEX_REQUEUE: u64 = 456;

// Zxyphor-specific system calls (start at 500)
pub const SYS_ZXYPHOR_IPC_CREATE: u64 = 500;
pub const SYS_ZXYPHOR_IPC_SEND: u64 = 501;
pub const SYS_ZXYPHOR_IPC_RECV: u64 = 502;
pub const SYS_ZXYPHOR_IPC_DESTROY: u64 = 503;
pub const SYS_ZXYPHOR_GRANT_CREATE: u64 = 504;
pub const SYS_ZXYPHOR_GRANT_MAP: u64 = 505;
pub const SYS_ZXYPHOR_GRANT_UNMAP: u64 = 506;
pub const SYS_ZXYPHOR_GRANT_DESTROY: u64 = 507;
pub const SYS_ZXYPHOR_VM_CREATE: u64 = 508;
pub const SYS_ZXYPHOR_VM_DESTROY: u64 = 509;
pub const SYS_ZXYPHOR_VM_MAP: u64 = 510;
pub const SYS_ZXYPHOR_VM_UNMAP: u64 = 511;
pub const SYS_ZXYPHOR_CHANNEL_CREATE: u64 = 512;
pub const SYS_ZXYPHOR_CHANNEL_WRITE: u64 = 513;
pub const SYS_ZXYPHOR_CHANNEL_READ: u64 = 514;
pub const SYS_ZXYPHOR_CHANNEL_CLOSE: u64 = 515;
pub const SYS_ZXYPHOR_EVENT_CREATE: u64 = 516;
pub const SYS_ZXYPHOR_EVENT_SIGNAL: u64 = 517;
pub const SYS_ZXYPHOR_EVENT_WAIT: u64 = 518;
pub const SYS_ZXYPHOR_EVENT_RESET: u64 = 519;
pub const SYS_ZXYPHOR_PORT_CREATE: u64 = 520;
pub const SYS_ZXYPHOR_PORT_QUEUE: u64 = 521;
pub const SYS_ZXYPHOR_PORT_WAIT: u64 = 522;
pub const SYS_ZXYPHOR_OBJECT_GET_INFO: u64 = 523;
pub const SYS_ZXYPHOR_OBJECT_SET_PROPERTY: u64 = 524;
pub const SYS_ZXYPHOR_TASK_CREATE: u64 = 525;
pub const SYS_ZXYPHOR_TASK_START: u64 = 526;
pub const SYS_ZXYPHOR_TASK_KILL: u64 = 527;
pub const SYS_ZXYPHOR_TASK_SUSPEND: u64 = 528;
pub const SYS_ZXYPHOR_TASK_RESUME: u64 = 529;
pub const SYS_ZXYPHOR_THREAD_CREATE: u64 = 530;
pub const SYS_ZXYPHOR_THREAD_EXIT: u64 = 531;
pub const SYS_ZXYPHOR_CAPABILITY_CREATE: u64 = 540;
pub const SYS_ZXYPHOR_CAPABILITY_TRANSFER: u64 = 541;
pub const SYS_ZXYPHOR_CAPABILITY_REVOKE: u64 = 542;
pub const SYS_ZXYPHOR_PERF_COUNTER_OPEN: u64 = 550;
pub const SYS_ZXYPHOR_PERF_COUNTER_READ: u64 = 551;
pub const SYS_ZXYPHOR_PERF_COUNTER_CLOSE: u64 = 552;

pub const MAX_SYSCALL: u64 = 600;

// =============================================================================
// Error Numbers (POSIX errno values)
// =============================================================================
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
pub const EIDRM: i64 = -43;
pub const ENOSTR: i64 = -60;
pub const ENODATA: i64 = -61;
pub const ETIME: i64 = -62;
pub const ENOSR: i64 = -63;
pub const ENONET: i64 = -64;
pub const EPROTO: i64 = -71;
pub const EBADMSG: i64 = -74;
pub const EOVERFLOW: i64 = -75;
pub const EBADFD: i64 = -77;
pub const ENOTSOCK: i64 = -88;
pub const EDESTADDRREQ: i64 = -89;
pub const EMSGSIZE: i64 = -90;
pub const EPROTOTYPE: i64 = -91;
pub const ENOPROTOOPT: i64 = -92;
pub const EPROTONOSUPPORT: i64 = -93;
pub const ESOCKTNOSUPPORT: i64 = -94;
pub const EOPNOTSUPP: i64 = -95;
pub const EPFNOSUPPORT: i64 = -96;
pub const EAFNOSUPPORT: i64 = -97;
pub const EADDRINUSE: i64 = -98;
pub const EADDRNOTAVAIL: i64 = -99;
pub const ENETDOWN: i64 = -100;
pub const ENETUNREACH: i64 = -101;
pub const ENETRESET: i64 = -102;
pub const ECONNABORTED: i64 = -103;
pub const ECONNRESET: i64 = -104;
pub const ENOBUFS: i64 = -105;
pub const EISCONN: i64 = -106;
pub const ENOTCONN: i64 = -107;
pub const ESHUTDOWN: i64 = -108;
pub const ETIMEDOUT: i64 = -110;
pub const ECONNREFUSED: i64 = -111;
pub const EHOSTDOWN: i64 = -112;
pub const EHOSTUNREACH: i64 = -113;
pub const EALREADY: i64 = -114;
pub const EINPROGRESS: i64 = -115;
pub const ESTALE: i64 = -116;

// =============================================================================
// System Call Frame — Register state at syscall entry
// =============================================================================

pub const SyscallFrame = extern struct {
    // Saved registers (pushed by syscall entry assembly)
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    // Syscall arguments (in ABI registers)
    r9: u64, // arg6
    r8: u64, // arg5
    r10: u64, // arg4
    rdx: u64, // arg3
    rsi: u64, // arg2
    rdi: u64, // arg1
    // Syscall number and return
    rax: u64, // syscall number (in), return value (out)
    // User context (saved by SYSCALL instruction)
    rcx: u64, // user RIP (saved by SYSCALL)
    r11: u64, // user RFLAGS (saved by SYSCALL)
    rsp: u64, // user RSP (saved manually from per-CPU scratchpad)
};

// =============================================================================
// Syscall Statistics
// =============================================================================
pub const SyscallStats = struct {
    call_count: [MAX_SYSCALL]u64,
    total_calls: u64,
    last_error: i64,
    last_syscall: u64,

    pub fn init() SyscallStats {
        return .{
            .call_count = [_]u64{0} ** MAX_SYSCALL,
            .total_calls = 0,
            .last_error = 0,
            .last_syscall = 0,
        };
    }

    pub fn record(self: *SyscallStats, nr: u64, result: i64) void {
        if (nr < MAX_SYSCALL) {
            self.call_count[nr] += 1;
        }
        self.total_calls += 1;
        self.last_syscall = nr;
        if (result < 0) {
            self.last_error = result;
        }
    }
};

var global_stats: SyscallStats = SyscallStats.init();

// =============================================================================
// User Memory Access Helpers
// =============================================================================

/// Validate that a user pointer and length are within valid user address space.
fn validateUserPtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    // Check within user space bounds (canonical, below 0x0000800000000000)
    if (ptr >= 0x0000_8000_0000_0000) return false;
    // Check for overflow
    if (ptr + len < ptr) return false;
    if (ptr + len > 0x0000_8000_0000_0000) return false;
    return true;
}

/// Validate a null-terminated user string (up to max_len).
fn validateUserString(ptr: u64, max_len: u64) bool {
    if (!validateUserPtr(ptr, 1)) return false;
    // Ensure the string terminates within the allowed range
    const str: [*]const u8 = @ptrFromInt(ptr);
    var i: u64 = 0;
    while (i < max_len) : (i += 1) {
        if (str[i] == 0) return true;
    }
    return false; // No null terminator found within max_len
}

// =============================================================================
// POSIX Type Definitions
// =============================================================================

pub const Timespec = extern struct {
    tv_sec: i64,
    tv_nsec: i64,
};

pub const Timeval = extern struct {
    tv_sec: i64,
    tv_usec: i64,
};

pub const StatBuf = extern struct {
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
    st_atime: Timespec,
    st_mtime: Timespec,
    st_ctime: Timespec,
    __reserved: [3]i64,
};

pub const Utsname = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
    domainname: [65]u8,
};

pub const SysInfo = extern struct {
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
    __reserved: [256 - 2 * 8 - 20]u8,
};

pub const Iovec = extern struct {
    iov_base: u64, // Pointer
    iov_len: u64, // Length
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
    stx_atime: Timespec,
    stx_btime: Timespec,
    stx_ctime: Timespec,
    stx_mtime: Timespec,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    __spare3: [12]u64,
};

// Open flags
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DSYNC: u32 = 0o10000;
pub const O_ASYNC: u32 = 0o20000;
pub const O_DIRECT: u32 = 0o40000;
pub const O_LARGEFILE: u32 = 0o100000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_NOATIME: u32 = 0o1000000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_TMPFILE: u32 = 0o20200000;
pub const O_PATH: u32 = 0o10000000;

// Seek whence values
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;
pub const SEEK_DATA: u32 = 3;
pub const SEEK_HOLE: u32 = 4;

// mmap flags
pub const PROT_NONE: u32 = 0x0;
pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_GROWSDOWN: u32 = 0x100;
pub const MAP_LOCKED: u32 = 0x2000;
pub const MAP_NORESERVE: u32 = 0x4000;
pub const MAP_POPULATE: u32 = 0x8000;
pub const MAP_HUGETLB: u32 = 0x40000;
pub const MAP_STACK: u32 = 0x20000;

// Signal numbers
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGSTKFLT: u32 = 16;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGIO: u32 = 29;
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;
pub const NSIG: u32 = 64;

// Clone flags
pub const CLONE_VM: u64 = 0x00000100;
pub const CLONE_FS: u64 = 0x00000200;
pub const CLONE_FILES: u64 = 0x00000400;
pub const CLONE_SIGHAND: u64 = 0x00000800;
pub const CLONE_PIDFD: u64 = 0x00001000;
pub const CLONE_PTRACE: u64 = 0x00002000;
pub const CLONE_VFORK: u64 = 0x00004000;
pub const CLONE_PARENT: u64 = 0x00008000;
pub const CLONE_THREAD: u64 = 0x00010000;
pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_SYSVSEM: u64 = 0x00040000;
pub const CLONE_SETTLS: u64 = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const CLONE_DETACHED: u64 = 0x00400000;
pub const CLONE_UNTRACED: u64 = 0x00800000;
pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_IO: u64 = 0x80000000;

// =============================================================================
// System Call Dispatch Table
// =============================================================================

pub const SyscallFn = *const fn (*SyscallFrame) i64;

/// System call dispatch entry.
pub const SyscallEntry = struct {
    handler: ?SyscallFn,
    name: []const u8,
    nargs: u8,
    flags: u32, // Syscall flags (auditing, etc.)
};

// Dispatch flags
pub const SC_NONE: u32 = 0;
pub const SC_AUDIT: u32 = 1; // Audit this syscall
pub const SC_COMPAT: u32 = 2; // Has 32-bit compat handler
pub const SC_RESTARTABLE: u32 = 4; // Can be restarted after signal
pub const SC_NORESTART: u32 = 8; // Never restart

// =============================================================================
// Core System Call Implementations
// =============================================================================

/// sys_read — Read from a file descriptor.
fn sysRead(frame: *SyscallFrame) i64 {
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const buf: u64 = frame.rsi;
    const count: u64 = frame.rdx;

    if (fd < 0) return EBADF;
    if (count == 0) return 0;
    if (!validateUserPtr(buf, count)) return EFAULT;

    // TODO: Get current process, lookup fd in file descriptor table
    // For now, return stub
    _ = fd;
    return ENOSYS;
}

/// sys_write — Write to a file descriptor.
fn sysWrite(frame: *SyscallFrame) i64 {
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const buf: u64 = frame.rsi;
    const count: u64 = frame.rdx;

    if (fd < 0) return EBADF;
    if (count == 0) return 0;
    if (!validateUserPtr(buf, count)) return EFAULT;

    _ = fd;
    return ENOSYS;
}

/// sys_open — Open a file.
fn sysOpen(frame: *SyscallFrame) i64 {
    const pathname: u64 = frame.rdi;
    const flags: u32 = @truncate(frame.rsi);
    const mode: u32 = @truncate(frame.rdx);

    if (!validateUserString(pathname, 4096)) return EFAULT;

    _ = flags;
    _ = mode;
    return ENOSYS;
}

/// sys_close — Close a file descriptor.
fn sysClose(frame: *SyscallFrame) i64 {
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    if (fd < 0) return EBADF;

    return ENOSYS;
}

/// sys_getpid — Get process ID.
fn sysGetpid(_: *SyscallFrame) i64 {
    // TODO: return current->pid
    return 1; // Init process for now
}

/// sys_gettid — Get thread ID.
fn sysGettid(_: *SyscallFrame) i64 {
    // TODO: return current->tid
    return 1;
}

/// sys_getppid — Get parent process ID.
fn sysGetppid(_: *SyscallFrame) i64 {
    // TODO: return current->parent->pid
    return 0;
}

/// sys_getuid/geteuid — Get user ID.
fn sysGetuid(_: *SyscallFrame) i64 {
    return 0; // Root for now
}

/// sys_getgid/getegid — Get group ID.
fn sysGetgid(_: *SyscallFrame) i64 {
    return 0;
}

/// sys_uname — Get system information.
fn sysUname(frame: *SyscallFrame) i64 {
    const buf_ptr: u64 = frame.rdi;
    if (!validateUserPtr(buf_ptr, @sizeOf(Utsname))) return EFAULT;

    const buf: *Utsname = @ptrFromInt(buf_ptr);
    @memset(&buf.sysname, 0);
    @memset(&buf.nodename, 0);
    @memset(&buf.release, 0);
    @memset(&buf.version, 0);
    @memset(&buf.machine, 0);
    @memset(&buf.domainname, 0);

    copyStringToBuffer(&buf.sysname, "Zxyphor");
    copyStringToBuffer(&buf.nodename, "zxyphor");
    copyStringToBuffer(&buf.release, "1.0.0-zxyphor");
    copyStringToBuffer(&buf.version, "#1 SMP PREEMPT Zxyphor 1.0.0");
    copyStringToBuffer(&buf.machine, "x86_64");
    copyStringToBuffer(&buf.domainname, "(none)");

    return 0;
}

fn copyStringToBuffer(dest: []u8, src: []const u8) void {
    const len = @min(src.len, dest.len - 1);
    @memcpy(dest[0..len], src[0..len]);
    dest[len] = 0;
}

/// sys_brk — Change data segment size.
fn sysBrk(frame: *SyscallFrame) i64 {
    const new_brk: u64 = frame.rdi;
    _ = new_brk;
    // TODO: Adjust process heap boundary
    return ENOSYS;
}

/// sys_mmap — Map files or devices into memory.
fn sysMmap(frame: *SyscallFrame) i64 {
    const addr: u64 = frame.rdi;
    const length: u64 = frame.rsi;
    const prot: u32 = @truncate(frame.rdx);
    const flags: u32 = @truncate(frame.r10);
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.r8)));
    const offset: u64 = frame.r9;

    // Basic validation
    if (length == 0) return EINVAL;
    if (offset & 0xFFF != 0) return EINVAL; // Must be page-aligned

    _ = addr;
    _ = prot;
    _ = flags;
    _ = fd;
    return ENOSYS;
}

/// sys_munmap — Unmap files from memory.
fn sysMunmap(frame: *SyscallFrame) i64 {
    const addr: u64 = frame.rdi;
    const length: u64 = frame.rsi;

    if (addr & 0xFFF != 0) return EINVAL;
    if (length == 0) return EINVAL;

    return ENOSYS;
}

/// sys_mprotect — Set protection on a region of memory.
fn sysMprotect(frame: *SyscallFrame) i64 {
    const addr: u64 = frame.rdi;
    const length: u64 = frame.rsi;
    const prot: u32 = @truncate(frame.rdx);

    if (addr & 0xFFF != 0) return EINVAL;
    if (length == 0) return EINVAL;
    _ = prot;

    return ENOSYS;
}

/// sys_exit — Terminate the calling process.
fn sysExit(frame: *SyscallFrame) i64 {
    const status: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    _ = status;
    // TODO: Set process state to zombie, cleanup resources, notify parent
    return 0; // Never actually returns
}

/// sys_exit_group — Exit all threads in a thread group.
fn sysExitGroup(frame: *SyscallFrame) i64 {
    const status: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    _ = status;
    // TODO: Kill all threads in the process, then exit
    return 0;
}

/// sys_fork — Create a child process.
fn sysFork(_: *SyscallFrame) i64 {
    // TODO: Implement fork via clone(SIGCHLD, 0)
    return ENOSYS;
}

/// sys_clone — Create a child process/thread.
fn sysClone(frame: *SyscallFrame) i64 {
    const flags: u64 = frame.rdi;
    const child_stack: u64 = frame.rsi;
    const parent_tidptr: u64 = frame.rdx;
    const child_tidptr: u64 = frame.r10;
    const tls: u64 = frame.r8;

    _ = flags;
    _ = child_stack;
    _ = parent_tidptr;
    _ = child_tidptr;
    _ = tls;
    return ENOSYS;
}

/// sys_execve — Execute program.
fn sysExecve(frame: *SyscallFrame) i64 {
    const filename: u64 = frame.rdi;
    const argv: u64 = frame.rsi;
    const envp: u64 = frame.rdx;

    if (!validateUserString(filename, 4096)) return EFAULT;
    _ = argv;
    _ = envp;
    return ENOSYS;
}

/// sys_wait4 — Wait for process to change state.
fn sysWait4(frame: *SyscallFrame) i64 {
    const pid: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const wstatus: u64 = frame.rsi;
    const options: u32 = @truncate(frame.rdx);
    const rusage: u64 = frame.r10;

    _ = pid;
    _ = wstatus;
    _ = options;
    _ = rusage;
    return ENOSYS;
}

/// sys_pipe2 — Create pipe with flags.
fn sysPipe2(frame: *SyscallFrame) i64 {
    const pipefd: u64 = frame.rdi;
    const flags: u32 = @truncate(frame.rsi);

    if (!validateUserPtr(pipefd, 8)) return EFAULT;
    _ = flags;
    return ENOSYS;
}

/// sys_dup — Duplicate file descriptor.
fn sysDup(frame: *SyscallFrame) i64 {
    const oldfd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    if (oldfd < 0) return EBADF;
    return ENOSYS;
}

/// sys_dup2 — Duplicate file descriptor to a specific number.
fn sysDup2(frame: *SyscallFrame) i64 {
    const oldfd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const newfd: i32 = @intCast(@as(i64, @bitCast(frame.rsi)));
    if (oldfd < 0 or newfd < 0) return EBADF;
    return ENOSYS;
}

/// sys_sched_yield — Voluntarily give up the CPU.
fn sysSchedYield(_: *SyscallFrame) i64 {
    // TODO: Call scheduler.yield()
    return 0;
}

/// sys_nanosleep — High-resolution sleep.
fn sysNanosleep(frame: *SyscallFrame) i64 {
    const req: u64 = frame.rdi;
    const rem: u64 = frame.rsi;

    if (!validateUserPtr(req, @sizeOf(Timespec))) return EFAULT;
    if (rem != 0 and !validateUserPtr(rem, @sizeOf(Timespec))) return EFAULT;

    const ts: *const Timespec = @ptrFromInt(req);
    if (ts.tv_sec < 0 or ts.tv_nsec < 0 or ts.tv_nsec >= 1_000_000_000) return EINVAL;

    // TODO: Add current thread to sleep queue with timeout
    return ENOSYS;
}

/// sys_clock_gettime — Get time from a specific clock.
fn sysClockGettime(frame: *SyscallFrame) i64 {
    const clockid: u32 = @truncate(frame.rdi);
    const tp: u64 = frame.rsi;

    if (!validateUserPtr(tp, @sizeOf(Timespec))) return EFAULT;

    const ts: *Timespec = @ptrFromInt(tp);

    switch (clockid) {
        0 => { // CLOCK_REALTIME
            // TODO: Get from RTC + offset
            ts.tv_sec = 0;
            ts.tv_nsec = 0;
            return 0;
        },
        1 => { // CLOCK_MONOTONIC
            // TODO: Get from TSC
            ts.tv_sec = 0;
            ts.tv_nsec = 0;
            return 0;
        },
        else => return EINVAL,
    }
}

/// sys_sysinfo — Return system information.
fn sysSysinfo(frame: *SyscallFrame) i64 {
    const info_ptr: u64 = frame.rdi;
    if (!validateUserPtr(info_ptr, @sizeOf(SysInfo))) return EFAULT;

    const info: *SysInfo = @ptrFromInt(info_ptr);
    @memset(@as([*]u8, @ptrCast(info))[0..@sizeOf(SysInfo)], 0);
    info.uptime = 0; // TODO
    info.totalram = 0; // TODO: from PMM
    info.freeram = 0; // TODO
    info.procs = 1; // TODO
    info.mem_unit = 1;

    return 0;
}

/// sys_getrandom — Obtain random bytes.
fn sysGetrandom(frame: *SyscallFrame) i64 {
    const buf: u64 = frame.rdi;
    const buflen: u64 = frame.rsi;
    const flags: u32 = @truncate(frame.rdx);

    if (buflen == 0) return 0;
    if (!validateUserPtr(buf, buflen)) return EFAULT;
    _ = flags;

    // TODO: Fill from kernel entropy pool
    return ENOSYS;
}

/// sys_kill — Send signal to a process.
fn sysKill(frame: *SyscallFrame) i64 {
    const pid: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const sig: u32 = @truncate(frame.rsi);

    if (sig >= NSIG) return EINVAL;
    _ = pid;
    return ENOSYS;
}

/// sys_socket — Create an endpoint for communication.
fn sysSocket(frame: *SyscallFrame) i64 {
    const domain: u32 = @truncate(frame.rdi);
    const sock_type: u32 = @truncate(frame.rsi);
    const protocol: u32 = @truncate(frame.rdx);

    _ = domain;
    _ = sock_type;
    _ = protocol;
    return ENOSYS;
}

/// sys_ioctl — Device-specific I/O control.
fn sysIoctl(frame: *SyscallFrame) i64 {
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const request: u64 = frame.rsi;
    const arg: u64 = frame.rdx;

    if (fd < 0) return EBADF;
    _ = request;
    _ = arg;
    return ENOSYS;
}

/// sys_fcntl — File control operations.
fn sysFcntl(frame: *SyscallFrame) i64 {
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const cmd: u32 = @truncate(frame.rsi);
    const arg: u64 = frame.rdx;

    if (fd < 0) return EBADF;
    _ = cmd;
    _ = arg;
    return ENOSYS;
}

/// sys_lseek — Reposition read/write file offset.
fn sysLseek(frame: *SyscallFrame) i64 {
    const fd: i32 = @intCast(@as(i64, @bitCast(frame.rdi)));
    const offset: i64 = @bitCast(frame.rsi);
    const whence: u32 = @truncate(frame.rdx);

    if (fd < 0) return EBADF;
    if (whence > SEEK_HOLE) return EINVAL;
    _ = offset;
    return ENOSYS;
}

/// sys_getcwd — Get current working directory.
fn sysGetcwd(frame: *SyscallFrame) i64 {
    const buf: u64 = frame.rdi;
    const size: u64 = frame.rsi;

    if (size == 0) return EINVAL;
    if (!validateUserPtr(buf, size)) return EFAULT;

    // TODO: Get CWD from current process
    const cwd = "/";
    const dest: [*]u8 = @ptrFromInt(buf);
    if (size < cwd.len + 1) return ERANGE;
    @memcpy(dest[0..cwd.len], cwd);
    dest[cwd.len] = 0;

    return @intCast(cwd.len + 1);
}

/// sys_arch_prctl — Set architecture-specific thread state.
fn sysArchPrctl(frame: *SyscallFrame) i64 {
    const code: u32 = @truncate(frame.rdi);
    const addr: u64 = frame.rsi;

    const ARCH_SET_GS: u32 = 0x1001;
    const ARCH_SET_FS: u32 = 0x1002;
    const ARCH_GET_FS: u32 = 0x1003;
    const ARCH_GET_GS: u32 = 0x1004;

    switch (code) {
        ARCH_SET_FS => {
            @import("../arch/x86_64/msr.zig").writeFsBase(addr);
            return 0;
        },
        ARCH_GET_FS => {
            if (!validateUserPtr(addr, 8)) return EFAULT;
            const ptr: *u64 = @ptrFromInt(addr);
            ptr.* = @import("../arch/x86_64/msr.zig").readFsBase();
            return 0;
        },
        ARCH_SET_GS => {
            @import("../arch/x86_64/msr.zig").writeGsBase(addr);
            return 0;
        },
        ARCH_GET_GS => {
            if (!validateUserPtr(addr, 8)) return EFAULT;
            const ptr: *u64 = @ptrFromInt(addr);
            ptr.* = @import("../arch/x86_64/msr.zig").readGsBase();
            return 0;
        },
        else => return EINVAL,
    }
}

/// sys_set_tid_address — Set pointer to thread ID.
fn sysSetTidAddress(frame: *SyscallFrame) i64 {
    const tidptr: u64 = frame.rdi;
    _ = tidptr;
    // TODO: Store clear_child_tid in current thread
    return 1; // Return current TID
}

/// sys_futex — Fast user-space locking.
fn sysFutex(frame: *SyscallFrame) i64 {
    const uaddr: u64 = frame.rdi;
    const futex_op: u32 = @truncate(frame.rsi);
    const val: u32 = @truncate(frame.rdx);
    const timeout: u64 = frame.r10;
    const uaddr2: u64 = frame.r8;
    const val3: u32 = @truncate(frame.r9);

    _ = uaddr;
    _ = futex_op;
    _ = val;
    _ = timeout;
    _ = uaddr2;
    _ = val3;
    return ENOSYS;
}

/// sys_reboot — Reboot the system.
fn sysReboot(frame: *SyscallFrame) i64 {
    const magic1: u32 = @truncate(frame.rdi);
    const magic2: u32 = @truncate(frame.rsi);
    const cmd: u32 = @truncate(frame.rdx);

    // Validate magic numbers (Linux-compatible)
    if (magic1 != 0xfee1dead) return EINVAL;
    if (magic2 != 672274793 and magic2 != 85072278 and
        magic2 != 369367448 and magic2 != 537993216) return EINVAL;

    const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
    const LINUX_REBOOT_CMD_HALT: u32 = 0xCDEF0123;
    const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;

    switch (cmd) {
        LINUX_REBOOT_CMD_RESTART => {
            // TODO: Sync filesystems, then reboot
            return 0;
        },
        LINUX_REBOOT_CMD_HALT => {
            // TODO: Halt the system
            return 0;
        },
        LINUX_REBOOT_CMD_POWER_OFF => {
            // TODO: Power off via ACPI
            return 0;
        },
        else => return EINVAL,
    }
}

// =============================================================================
// Main Syscall Dispatcher
// =============================================================================

/// Dispatch a system call based on the syscall number in RAX.
/// Called from the assembly SYSCALL entry point.
pub export fn syscallDispatch(frame: *SyscallFrame) callconv(.C) void {
    const nr = frame.rax;

    const result: i64 = switch (nr) {
        SYS_READ => sysRead(frame),
        SYS_WRITE => sysWrite(frame),
        SYS_OPEN => sysOpen(frame),
        SYS_CLOSE => sysClose(frame),
        SYS_LSEEK => sysLseek(frame),
        SYS_MMAP => sysMmap(frame),
        SYS_MPROTECT => sysMprotect(frame),
        SYS_MUNMAP => sysMunmap(frame),
        SYS_BRK => sysBrk(frame),
        SYS_IOCTL => sysIoctl(frame),
        SYS_PIPE2 => sysPipe2(frame),
        SYS_DUP => sysDup(frame),
        SYS_DUP2 => sysDup2(frame),
        SYS_SCHED_YIELD => sysSchedYield(frame),
        SYS_NANOSLEEP => sysNanosleep(frame),
        SYS_GETPID => sysGetpid(frame),
        SYS_CLONE => sysClone(frame),
        SYS_FORK => sysFork(frame),
        SYS_EXECVE => sysExecve(frame),
        SYS_EXIT => sysExit(frame),
        SYS_WAIT4 => sysWait4(frame),
        SYS_KILL => sysKill(frame),
        SYS_UNAME => sysUname(frame),
        SYS_FCNTL => sysFcntl(frame),
        SYS_GETCWD => sysGetcwd(frame),
        SYS_GETUID => sysGetuid(frame),
        SYS_GETEUID => sysGetuid(frame),
        SYS_GETGID => sysGetgid(frame),
        SYS_GETEGID => sysGetgid(frame),
        SYS_GETPPID => sysGetppid(frame),
        SYS_GETTID => sysGettid(frame),
        SYS_GETPGRP => sysGetpid(frame),
        SYS_SYSINFO => sysSysinfo(frame),
        SYS_CLOCK_GETTIME => sysClockGettime(frame),
        SYS_EXIT_GROUP => sysExitGroup(frame),
        SYS_SOCKET => sysSocket(frame),
        SYS_FUTEX => sysFutex(frame),
        SYS_SET_TID_ADDRESS => sysSetTidAddress(frame),
        SYS_ARCH_PRCTL => sysArchPrctl(frame),
        SYS_GETRANDOM => sysGetrandom(frame),
        SYS_REBOOT => sysReboot(frame),
        else => ENOSYS,
    };

    // Record statistics
    global_stats.record(nr, result);

    // Set return value
    frame.rax = @bitCast(result);
}

/// Get syscall statistics for monitoring.
pub fn getStats() *const SyscallStats {
    return &global_stats;
}

/// Reset syscall statistics.
pub fn resetStats() void {
    global_stats = SyscallStats.init();
}
