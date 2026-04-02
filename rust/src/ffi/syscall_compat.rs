// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust FFI / Syscall Compatibility Layer
//! C ABI compat types, syscall number definitions, compat wrappers,
//! iovec translation, errno codes, user pointer validation

#![allow(dead_code)]

// ============================================================================
// Errno Codes (E* from <asm-generic/errno-base.h> and errno.h)
// ============================================================================

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    Success = 0,
    Eperm = 1,
    Enoent = 2,
    Esrch = 3,
    Eintr = 4,
    Eio = 5,
    Enxio = 6,
    E2big = 7,
    Enoexec = 8,
    Ebadf = 9,
    Echild = 10,
    Eagain = 11,      // EWOULDBLOCK
    Enomem = 12,
    Eacces = 13,
    Efault = 14,
    Enotblk = 15,
    Ebusy = 16,
    Eexist = 17,
    Exdev = 18,
    Enodev = 19,
    Enotdir = 20,
    Eisdir = 21,
    Einval = 22,
    Enfile = 23,
    Emfile = 24,
    Enotty = 25,
    Etxtbsy = 26,
    Efbig = 27,
    Enospc = 28,
    Espipe = 29,
    Erofs = 30,
    Emlink = 31,
    Epipe = 32,
    Edom = 33,
    Erange = 34,
    Edeadlk = 35,
    Enametoolong = 36,
    Enolck = 37,
    Enosys = 38,
    Enotempty = 39,
    Eloop = 40,
    Enomsg = 42,
    Eidrm = 43,
    Echrng = 44,
    El2nsync = 45,
    El3hlt = 46,
    El3rst = 47,
    Elnrng = 48,
    Eunatch = 49,
    Enocsi = 50,
    El2hlt = 51,
    Ebade = 52,
    Ebadr = 53,
    Exfull = 54,
    Enoano = 55,
    Ebadrqc = 56,
    Ebadslt = 57,
    Ebfont = 59,
    Enostr = 60,
    Enodata = 61,
    Etime = 62,
    Enosr = 63,
    Enonet = 64,
    Enopkg = 65,
    Eremote = 66,
    Enolink = 67,
    Eadv = 68,
    Esrmnt = 69,
    Ecomm = 70,
    Eproto = 71,
    Emultihop = 72,
    Edotdot = 73,
    Ebadmsg = 74,
    Eoverflow = 75,
    Enotuniq = 76,
    Ebadfd = 77,
    Eremchg = 78,
    Elibacc = 79,
    Elibbad = 80,
    Elibscn = 81,
    Elibmax = 82,
    Elibexec = 83,
    Eilseq = 84,
    Erestart = 85,
    Estrpipe = 86,
    Eusers = 87,
    Enotsock = 88,
    Edestaddrreq = 89,
    Emsgsize = 90,
    Eprototype = 91,
    Enoprotoopt = 92,
    Eprotonosupport = 93,
    Esocktnosupport = 94,
    Eopnotsupp = 95,
    Epfnosupport = 96,
    Eafnosupport = 97,
    Eaddrinuse = 98,
    Eaddrnotavail = 99,
    Enetdown = 100,
    Enetunreach = 101,
    Enetreset = 102,
    Econnaborted = 103,
    Econnreset = 104,
    Enobufs = 105,
    Eisconn = 106,
    Enotconn = 107,
    Eshutdown = 108,
    Etoomanyrefs = 109,
    Etimedout = 110,
    Econnrefused = 111,
    Ehostdown = 112,
    Ehostunreach = 113,
    Ealready = 114,
    Einprogress = 115,
    Estale = 116,
    Euclean = 117,
    Enotnam = 118,
    Enavail = 119,
    Eisnam = 120,
    Eremoteio = 121,
    Edquot = 122,
    Enomedium = 123,
    Emediumtype = 124,
    Ecanceled = 125,
    Enokey = 126,
    Ekeyexpired = 127,
    Ekeyrevoked = 128,
    Ekeyrejected = 129,
    Eownerdead = 130,
    Enotrecoverable = 131,
    Erfkill = 132,
    Ehwpoison = 133,
}

// ============================================================================
// x86_64 Syscall Numbers
// ============================================================================

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNr {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Fstat = 5,
    Lstat = 6,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    RtSigreturn = 15,
    Ioctl = 16,
    Pread64 = 17,
    Pwrite64 = 18,
    Readv = 19,
    Writev = 20,
    Access = 21,
    Pipe = 22,
    Select = 23,
    SchedYield = 24,
    Mremap = 25,
    Msync = 26,
    Mincore = 27,
    Madvise = 28,
    Shmget = 29,
    Shmat = 30,
    Shmctl = 31,
    Dup = 32,
    Dup2 = 33,
    Pause = 34,
    Nanosleep = 35,
    Getitimer = 36,
    Alarm = 37,
    Setitimer = 38,
    Getpid = 39,
    Sendfile = 40,
    Socket = 41,
    Connect = 42,
    Accept = 43,
    Sendto = 44,
    Recvfrom = 45,
    Sendmsg = 46,
    Recvmsg = 47,
    Shutdown = 48,
    Bind = 49,
    Listen = 50,
    Getsockname = 51,
    Getpeername = 52,
    Socketpair = 53,
    Setsockopt = 54,
    Getsockopt = 55,
    Clone = 56,
    Fork = 57,
    Vfork = 58,
    Execve = 59,
    Exit = 60,
    Wait4 = 61,
    Kill = 62,
    Uname = 63,
    Semget = 64,
    Semop = 65,
    Semctl = 66,
    Shmdt = 67,
    Msgget = 68,
    Msgsnd = 69,
    Msgrcv = 70,
    Msgctl = 71,
    Fcntl = 72,
    Flock = 73,
    Fsync = 74,
    Fdatasync = 75,
    Truncate = 76,
    Ftruncate = 77,
    Getdents = 78,
    Getcwd = 79,
    Chdir = 80,
    Fchdir = 81,
    Rename = 82,
    Mkdir = 83,
    Rmdir = 84,
    Creat = 85,
    Link = 86,
    Unlink = 87,
    Symlink = 88,
    Readlink = 89,
    Chmod = 90,
    Fchmod = 91,
    Chown = 92,
    Fchown = 93,
    Lchown = 94,
    Umask = 95,
    Gettimeofday = 96,
    Getrlimit = 97,
    Getrusage = 98,
    Sysinfo = 99,
    Times = 100,
    Ptrace = 101,
    Getuid = 102,
    Syslog = 103,
    Getgid = 104,
    Setuid = 105,
    Setgid = 106,
    Geteuid = 107,
    Getegid = 108,
    Setpgid = 109,
    Getppid = 110,
    // ... continues
    Openat = 257,
    Mkdirat = 258,
    Fchownat = 260,
    Newfstatat = 262,
    Unlinkat = 263,
    Renameat = 264,
    Linkat = 265,
    Symlinkat = 266,
    Readlinkat = 267,
    Fchmodat = 268,
    Faccessat = 269,
    Pselect6 = 270,
    Ppoll = 271,
    Set_robust_list = 273,
    Get_robust_list = 274,
    Splice = 275,
    Tee = 276,
    SyncFileRange = 277,
    Vmsplice = 278,
    MovePages = 279,
    Utimensat = 280,
    EpollPwait = 281,
    Signalfd = 282,
    TimerfdCreate = 283,
    Eventfd = 284,
    Fallocate = 285,
    TimerfdSettime = 286,
    TimerfdGettime = 287,
    Accept4 = 288,
    Signalfd4 = 289,
    Eventfd2 = 290,
    EpollCreate1 = 291,
    Dup3 = 292,
    Pipe2 = 293,
    InotifyInit1 = 294,
    Preadv = 295,
    Pwritev = 296,
    PerfEventOpen = 298,
    Recvmmsg = 299,
    Fanotify_init = 300,
    Fanotify_mark = 301,
    Prlimit64 = 302,
    NameToHandleAt = 303,
    OpenByHandleAt = 304,
    ClockAdjtime = 305,
    Syncfs = 306,
    Sendmmsg = 307,
    Setns = 308,
    Getcpu = 309,
    ProcessVmReadv = 310,
    ProcessVmWritev = 311,
    Kcmp = 312,
    FinitModule = 313,
    SchedSetattr = 314,
    SchedGetattr = 315,
    Renameat2 = 316,
    Seccomp = 317,
    Getrandom = 318,
    MemfdCreate = 319,
    KexecFileLoad = 320,
    Bpf = 321,
    Execveat = 322,
    Userfaultfd = 323,
    Membarrier = 324,
    Mlock2 = 325,
    CopyFileRange = 326,
    Preadv2 = 327,
    Pwritev2 = 328,
    PkeyMprotect = 329,
    PkeyAlloc = 330,
    PkeyFree = 331,
    Statx = 332,
    IoSetup = 206,
    IoDestroy = 207,
    IoGetevents = 208,
    IoSubmit = 209,
    IoCancel = 210,
    IoUringSetup = 425,
    IoUringEnter = 426,
    IoUringRegister = 427,
    OpenTree = 428,
    MoveMount = 429,
    Fsopen = 430,
    Fsconfig = 431,
    Fsmount = 432,
    Fspick = 433,
    PidfdOpen = 434,
    Clone3 = 435,
    CloseRange = 436,
    Openat2 = 437,
    PidfdGetfd = 438,
    Faccessat2 = 439,
    ProcessMadvise = 440,
    EpollPwait2 = 441,
    MountSetattr = 442,
    QuotactlFd = 443,
    LandlockCreateRuleset = 444,
    LandlockAddRule = 445,
    LandlockRestrictSelf = 446,
    MemfdSecret = 447,
    ProcessMrelease = 448,
    Futex_waitv = 449,
    SetMempolicy_home_node = 450,
    Cachestat = 451,
    Fchmodat2 = 452,
    MapShadowStack = 453,
    Futex_wake = 454,
    Futex_wait = 455,
    Futex_requeue = 456,
    Statmount = 457,
    Listmount = 458,
    Lsm_get_self_attr = 459,
    Lsm_set_self_attr = 460,
    Lsm_list_modules = 461,
    Mseal = 462,
}

// ============================================================================
// C ABI Compatible Types
// ============================================================================

pub type CInt = i32;
pub type CUint = u32;
pub type CLong = i64;
pub type CUlong = u64;
pub type CSizeT = u64;
pub type CSsizeT = i64;
pub type COffT = i64;
pub type CLoffT = i64;
pub type CPidT = i32;
pub type CUidT = u32;
pub type CGidT = u32;
pub type CModeT = u32;
pub type CDevT = u64;
pub type CInoT = u64;
pub type CBlkSizeT = i64;
pub type CBlkCntT = i64;
pub type CNlinkT = u64;
pub type CTimeT = i64;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Timespec64 {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Iovec {
    pub iov_base: u64,    // __user void *
    pub iov_len: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct StatxResult {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub _pad1: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub _pad: i32,
}

// ============================================================================
// Compat (32-bit) types
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompatIovec {
    pub iov_base: u32,
    pub iov_len: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompatTimespec {
    pub tv_sec: i32,
    pub tv_nsec: i32,
}

#[repr(C)]
#[derive(Debug)]
pub struct CompatStat {
    pub st_dev: u32,
    pub st_ino: u32,
    pub st_mode: u16,
    pub st_nlink: u16,
    pub st_uid: u16,
    pub st_gid: u16,
    pub st_rdev: u32,
    pub st_size: u32,
    pub st_blksize: u32,
    pub st_blocks: u32,
    pub st_atime: u32,
    pub st_atime_nsec: u32,
    pub st_mtime: u32,
    pub st_mtime_nsec: u32,
    pub st_ctime: u32,
    pub st_ctime_nsec: u32,
}

// ============================================================================
// FFI Manager
// ============================================================================

#[derive(Debug)]
pub struct FfiCompatManager {
    pub total_syscalls: u64,
    pub total_compat_syscalls: u64,
    pub total_iovec_translations: u64,
    pub total_errno_returns: u64,
    pub initialized: bool,
}

impl FfiCompatManager {
    pub fn new() -> Self {
        Self {
            total_syscalls: 0,
            total_compat_syscalls: 0,
            total_iovec_translations: 0,
            total_errno_returns: 0,
            initialized: true,
        }
    }
}
