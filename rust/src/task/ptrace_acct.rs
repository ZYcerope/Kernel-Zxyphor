// Zxyphor Kernel - Ptrace Advanced, Process Accounting,
// Process Capabilities Manipulation, Seccomp-BPF Notifier,
// Coredump Configuration, Prctl Operations,
// Process Credentials, User Namespaces
// More advanced than Linux 2026 process control

use core::fmt;

// ============================================================================
// Ptrace Advanced
// ============================================================================

/// Ptrace request type
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum PtraceRequest {
    TraceMe = 0,
    PeekText = 1,
    PeekData = 2,
    PeekUser = 3,
    PokeText = 4,
    PokeData = 5,
    PokeUser = 6,
    Cont = 7,
    Kill = 8,
    SingleStep = 9,
    GetRegs = 12,
    SetRegs = 13,
    GetFpRegs = 14,
    SetFpRegs = 15,
    Attach = 16,
    Detach = 17,
    GetFpxRegs = 18,
    SetFpxRegs = 19,
    Syscall = 24,
    GetEventMsg = 0x4201,
    GetSigInfo = 0x4202,
    SetSigInfo = 0x4203,
    GetRegset = 0x4204,
    SetRegset = 0x4205,
    Seize = 0x4206,
    Interrupt = 0x4207,
    Listen = 0x4208,
    PeekSigInfo = 0x4209,
    GetSeccompFilter = 0x420C,
    GetSyscallInfo = 0x420E,
    GetRseqConfig = 0x420F,
    SetSyscallUserDispatch = 0x4210,
}

/// Ptrace options
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PtraceOptionsVal(pub u32);

impl PtraceOptionsVal {
    pub const TRACESYSGOOD: Self = Self(1);
    pub const TRACEFORK: Self = Self(2);
    pub const TRACEVFORK: Self = Self(4);
    pub const TRACECLONE: Self = Self(8);
    pub const TRACEEXEC: Self = Self(16);
    pub const TRACEVFORKDONE: Self = Self(32);
    pub const TRACEEXIT: Self = Self(64);
    pub const TRACESECCOMP: Self = Self(128);
    pub const SUSPEND_SECCOMP: Self = Self(0x00200000);
}

/// Ptrace event type
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PtraceEvent {
    Fork = 1,
    Vfork = 2,
    Clone = 3,
    Exec = 4,
    VforkDone = 5,
    Exit = 6,
    Seccomp = 7,
    Stop = 128,
}

/// Ptrace syscall info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PtraceSyscallInfo {
    pub op: PtraceSyscallOp,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    // Entry info
    pub entry_nr: u64,
    pub entry_args: [u64; 6],
    // Exit info
    pub exit_rval: i64,
    pub exit_is_error: u8,
    // Seccomp info
    pub seccomp_nr: u64,
    pub seccomp_args: [u64; 6],
    pub seccomp_ret_data: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PtraceSyscallOp {
    None = 0,
    Entry = 1,
    Exit = 2,
    SeccompEvent = 3,
}

/// Ptrace peeksiginfo args
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PtracePeekSigInfoArgs {
    pub off: u64,
    pub flags: u32,
    pub nr: i32,
}

/// Register set type for GETREGSET/SETREGSET
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PtraceRegset {
    GeneralPurpose = 1,
    FloatingPoint = 2,
    Xfp = 0x202,
    XState = 0x202,
    Pkru = 0x204,
    // x86_64 specific
    IoPermission = 0x205,
    TlsBase = 0x206,
    Cet = 0x207,
}

// ============================================================================
// Process Accounting
// ============================================================================

/// Accounting version
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AcctVersion {
    V1 = 1,  // struct acct
    V2 = 2,  // struct acct_v3
    V3 = 3,
}

/// Process accounting record v3
#[repr(C)]
#[derive(Debug, Clone)]
pub struct AcctV3Record {
    pub ac_flag: AcctFlags,
    pub ac_version: u8,
    pub ac_tty: u16,
    pub ac_exitcode: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,              // begin time (seconds since epoch)
    pub ac_etime: f32,              // elapsed time
    pub ac_utime: u32,              // user CPU time (AHZ ticks)
    pub ac_stime: u32,              // system CPU time
    pub ac_mem: u32,                // average memory usage (KB)
    pub ac_io: u64,                 // chars transferred (IO)
    pub ac_rw: u64,                 // blocks read/written
    pub ac_minflt: u64,             // minor page faults
    pub ac_majflt: u64,             // major page faults
    pub ac_swaps: u64,              // swap count
    pub ac_comm: [u8; 16],          // command name
}

/// Accounting flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct AcctFlags(pub u8);

impl AcctFlags {
    pub const FORKNOEXEC: Self = Self(0x01);
    pub const SUPERUSER: Self = Self(0x02);
    pub const CORE: Self = Self(0x08);
    pub const XSIG: Self = Self(0x10);
}

/// Taskstats (via genetlink TASKSTATS)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Taskstats {
    pub version: u16,
    pub ac_exitcode: u32,
    pub ac_flag: u8,
    pub ac_nice: u8,
    // Delay accounting
    pub cpu_count: u64,
    pub cpu_delay_total: u64,       // nanoseconds
    pub blkio_count: u64,
    pub blkio_delay_total: u64,
    pub swapin_count: u64,
    pub swapin_delay_total: u64,
    pub cpu_run_real_total: u64,
    pub cpu_run_virtual_total: u64,
    // Basic accounting
    pub ac_comm: [u8; 32],
    pub ac_sched: u8,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,
    pub ac_etime: u64,              // elapsed time (usec)
    pub ac_utime: u64,              // user CPU time (usec)
    pub ac_stime: u64,              // system CPU time (usec)
    pub ac_minflt: u64,
    pub ac_majflt: u64,
    // Extended accounting v8+
    pub coremem: u64,               // RSS * time (MB*usec)
    pub virtmem: u64,               // VM * time (MB*usec)
    pub hiwater_rss: u64,           // peak RSS (KB)
    pub hiwater_vm: u64,            // peak VM (KB)
    pub read_char: u64,             // I/O read bytes
    pub write_char: u64,            // I/O write bytes
    pub read_syscalls: u64,
    pub write_syscalls: u64,
    pub read_bytes: u64,            // block I/O
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
    pub nvcsw: u64,                 // voluntary context switches
    pub nivcsw: u64,                // involuntary context switches
    // Delay accounting extended
    pub freepages_count: u64,
    pub freepages_delay_total: u64,
    pub thrashing_count: u64,
    pub thrashing_delay_total: u64,
    pub ac_btime64: u64,
    pub compact_count: u64,
    pub compact_delay_total: u64,
    pub ac_tgid: u32,
    pub ac_tgetime: u64,
    pub ac_exe_dev: u64,
    pub ac_exe_inode: u64,
    pub wpcopy_count: u64,
    pub wpcopy_delay_total: u64,
    pub irq_count: u64,
    pub irq_delay_total: u64,
}

// ============================================================================
// Prctl Operations
// ============================================================================

/// prctl option codes
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum PrctlOption {
    SetPdeathsig = 1,
    GetPdeathsig = 2,
    GetDumpable = 3,
    SetDumpable = 4,
    GetUnalign = 5,
    SetUnalign = 6,
    GetKeepCaps = 7,
    SetKeepCaps = 8,
    GetFpemu = 9,
    SetFpemu = 10,
    GetFpexc = 11,
    SetFpexc = 12,
    GetTiming = 13,
    SetTiming = 14,
    SetName = 15,
    GetName = 16,
    GetEndian = 19,
    SetEndian = 20,
    GetSeccomp = 21,
    SetSeccomp = 22,
    CapbsetRead = 23,
    CapbsetDrop = 24,
    GetTsc = 25,
    SetTsc = 26,
    GetSecurebits = 27,
    SetSecurebits = 28,
    SetTimerslack = 29,
    GetTimerSlack = 30,
    TaskPerfEventsDisable = 31,
    TaskPerfEventsEnable = 32,
    SetChildSubreaper = 36,
    GetChildSubreaper = 37,
    SetNoNewPrivs = 38,
    GetNoNewPrivs = 39,
    GetTidAddress = 40,
    SetThpDisable = 41,
    GetThpDisable = 42,
    SetFpMode = 45,
    GetFpMode = 46,
    CapAmbient = 47,
    SetSyscallUserDispatch = 59,
    SetVma = 0x53564d41,
    PacResetKeys = 54,
    SetTaggedAddrCtrl = 55,
    GetTaggedAddrCtrl = 56,
    SetIoFlusher = 57,
    GetIoFlusher = 58,
    SetMdwe = 65,
    GetMdwe = 66,
    SetMemoryMerge = 67,
    GetMemoryMerge = 68,
}

/// Dumpable modes
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum Dumpable {
    NotDumpable = 0,
    Dumpable = 1,
    DumpableIfSuid = 2,
}

/// Memory-Deny-Write-Execute
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct MdweFlags(pub u64);

impl MdweFlags {
    pub const REFUSE_EXEC_GAIN: Self = Self(1);
    pub const NO_INHERIT: Self = Self(2);
}

// ============================================================================
// Process Credentials
// ============================================================================

/// Process credential set
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessCreds {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub nr_groups: u32,
    pub groups: [u32; 32],
    // Security
    pub securebits: u32,
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_bset: u64,
    pub cap_ambient: u64,
    // Namespaces
    pub user_ns_level: u32,
    pub uid_map_nr_ranges: u32,
    pub gid_map_nr_ranges: u32,
    // LSM
    pub selinux_sid: u32,
    pub apparmor_profile_id: u32,
    // Keyring
    pub session_keyring: u32,
    pub process_keyring: u32,
    pub thread_keyring: u32,
}

/// UID/GID mapping range (for user namespaces)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdMapping {
    pub inside_id: u32,
    pub outside_id: u32,
    pub count: u32,
}

// ============================================================================
// Coredump Configuration
// ============================================================================

/// Core pattern type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CorePatternType {
    File = 0,
    Pipe = 1,
}

/// Core dump filter bits
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct CoreDumpFilter(pub u32);

impl CoreDumpFilter {
    pub const ANON_PRIVATE: Self = Self(1 << 0);
    pub const ANON_SHARED: Self = Self(1 << 1);
    pub const MAPPED_PRIVATE: Self = Self(1 << 2);
    pub const MAPPED_SHARED: Self = Self(1 << 3);
    pub const ELF_HEADERS: Self = Self(1 << 4);
    pub const HUGETLB_PRIVATE: Self = Self(1 << 5);
    pub const HUGETLB_SHARED: Self = Self(1 << 6);
    pub const DAX_PRIVATE: Self = Self(1 << 7);
    pub const DAX_SHARED: Self = Self(1 << 8);
}

/// ELF note types for core dumps
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum ElfNoteType {
    Prstatus = 1,
    Prfpreg = 2,
    Prpsinfo = 3,
    Taskstruct = 4,
    Auxv = 6,
    Pstatus = 10,
    Fpregs = 12,
    Psinfo = 13,
    Lwpstatus = 16,
    Lwpsinfo = 17,
    Siginfo = 0x53494749,
    File = 0x46494c45,
    X86Xstate = 0x202,
}

/// Coredump format
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CoreFormat {
    Elf = 0,
    // Zxyphor
    ZxyCompressed = 1,
    ZxyStreaming = 2,
}

// ============================================================================
// Rlimit / Resource Limits
// ============================================================================

/// Resource type for getrlimit/setrlimit
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum RlimitResource {
    Cpu = 0,
    Fsize = 1,
    Data = 2,
    Stack = 3,
    Core = 4,
    Rss = 5,
    Nproc = 6,
    Nofile = 7,
    Memlock = 8,
    As = 9,
    Locks = 10,
    Sigpending = 11,
    Msgqueue = 12,
    Nice = 13,
    Rtprio = 14,
    Rttime = 15,
}

/// Resource limit value
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rlimit {
    pub rlim_cur: u64,  // soft limit
    pub rlim_max: u64,  // hard limit
}

pub const RLIM_INFINITY_VAL: u64 = u64::MAX;

/// Resource usage statistics
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Rusage {
    pub ru_utime_sec: i64,
    pub ru_utime_usec: i64,
    pub ru_stime_sec: i64,
    pub ru_stime_usec: i64,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

/// Rusage who
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum RusageWho {
    SelfOnly = 0,
    Children = -1,
    Both = -2,
    Thread = 1,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct ProcessCtlSubsystem {
    pub ptrace_active: u32,
    pub accounting_enabled: bool,
    pub accounting_version: AcctVersion,
    pub nr_coredumps: u64,
    pub core_pattern_type: CorePatternType,
    pub core_format: CoreFormat,
    pub nr_rlimit_changes: u64,
    pub initialized: bool,
}

impl ProcessCtlSubsystem {
    pub const fn new() -> Self {
        Self {
            ptrace_active: 0,
            accounting_enabled: true,
            accounting_version: AcctVersion::V3,
            nr_coredumps: 0,
            core_pattern_type: CorePatternType::Pipe,
            core_format: CoreFormat::Elf,
            nr_rlimit_changes: 0,
            initialized: false,
        }
    }
}
