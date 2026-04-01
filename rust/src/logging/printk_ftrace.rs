// Zxyphor Kernel - Printk Advanced, Structured Logging,
// Tracepoints, Ftrace Events, Dynamic Debug,
// Kernel Ring Buffer, Console Subsystem, Devcoredump,
// Rate Limiting, Log Levels
// More advanced than Linux 2026 logging subsystem

use core::fmt;

// ============================================================================
// Kernel Log Levels
// ============================================================================

/// Kernel log level (matches KERN_* in Linux)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Emergency = 0,  // System is unusable
    Alert = 1,      // Action must be taken immediately
    Critical = 2,   // Critical conditions
    Error = 3,      // Error conditions
    Warning = 4,    // Warning conditions
    Notice = 5,     // Normal but significant condition
    Info = 6,       // Informational
    Debug = 7,      // Debug-level messages
    // Zxyphor extensions
    ZxyTrace = 8,   // Fine-grained trace level
    ZxyPerf = 9,    // Performance monitoring level
}

/// Console log level configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConsoleLogLevel {
    pub current: LogLevel,
    pub default_level: LogLevel,
    pub minimum: LogLevel,
    pub default_console: LogLevel,
}

// ============================================================================
// Printk Ring Buffer
// ============================================================================

/// Ring buffer descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PrintkRingBufDesc {
    pub size_bytes: u64,
    pub head_seq: u64,
    pub tail_seq: u64,
    pub nr_records: u64,
    pub text_data_size: u64,
    pub dict_data_size: u64,
    pub max_record_text_size: u32,
}

/// Printk record flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PrintkRecordFlags(pub u8);

impl PrintkRecordFlags {
    pub const NEWLINE: Self = Self(1 << 0);
    pub const CONT: Self = Self(1 << 1);
    pub const CALLER_ID: Self = Self(1 << 2);
}

/// Printk record
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PrintkRecord {
    pub seq: u64,
    pub ts_nsec: u64,
    pub caller_id: u32,
    pub level: LogLevel,
    pub facility: u8,
    pub flags: PrintkRecordFlags,
    pub text_len: u16,
    pub dict_len: u16,
    pub cpu: u32,
}

/// Printk action for /dev/kmsg
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PrintkAction {
    Read = 0,
    ReadAll = 1,
    Clear = 2,
    ReadClear = 3,
    SizeUnread = 4,
    SizeBuffer = 5,
}

// ============================================================================
// Console Subsystem
// ============================================================================

/// Console type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ConsoleType {
    Ram = 0,
    Vga = 1,
    Dummy = 2,
    Serial = 3,
    Netconsole = 4,
    Fb = 5,
    Efi = 6,
    HvCon = 7,
    // Zxyphor
    ZxyVirtio = 100,
    ZxyUsb = 101,
}

/// Console flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ConsoleFlags(pub u16);

impl ConsoleFlags {
    pub const ENABLED: Self = Self(1 << 0);
    pub const CONSDEV: Self = Self(1 << 1);     // preferred console
    pub const BOOT: Self = Self(1 << 2);         // boot console
    pub const ANYTIME: Self = Self(1 << 3);      // safe to call anytime
    pub const BRL: Self = Self(1 << 4);           // braille device
    pub const EXTENDED: Self = Self(1 << 5);      // extended output format
    pub const SUSPENDED: Self = Self(1 << 6);
    pub const NBCON: Self = Self(1 << 7);         // non-BKL console
}

/// Console descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConsoleDesc {
    pub name: [u8; 16],
    pub name_len: u8,
    pub console_type: ConsoleType,
    pub flags: ConsoleFlags,
    pub index: i16,
    pub setup_called: bool,
    pub write_supported: bool,
    pub read_supported: bool,
    pub device_supported: bool,
    pub unblank_supported: bool,
}

/// Netconsole configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NetconsoleConfig {
    pub local_port: u16,
    pub remote_port: u16,
    pub local_ip4: u32,
    pub remote_ip4: u32,
    pub local_ip6: [u8; 16],
    pub remote_ip6: [u8; 16],
    pub family: u16,
    pub remote_mac: [u8; 6],
    pub dev_name: [u8; 16],
    pub dev_name_len: u8,
    pub enabled: bool,
    pub extended: bool,
    pub release_prepend: bool,
}

// ============================================================================
// Dynamic Debug
// ============================================================================

/// Dynamic debug flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct DynDbgFlags(pub u32);

impl DynDbgFlags {
    pub const PRINT: Self = Self(1 << 0);
    pub const INCLUDE_PREFIX: Self = Self(1 << 1);
    pub const INCLUDE_FUNCNAME: Self = Self(1 << 2);
    pub const INCLUDE_LINENO: Self = Self(1 << 3);
    pub const INCLUDE_MODULE: Self = Self(1 << 4);
    pub const INCLUDE_TIMESTAMP: Self = Self(1 << 5);
    pub const INCLUDE_TID: Self = Self(1 << 6);
}

/// Dynamic debug descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DynDbgDesc {
    pub module: [u8; 64],
    pub module_len: u8,
    pub function: [u8; 64],
    pub function_len: u8,
    pub filename: [u8; 128],
    pub filename_len: u8,
    pub lineno: u32,
    pub flags: DynDbgFlags,
    pub format_present: bool,
    pub class_id: u32,
}

/// Dynamic debug query
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DynDbgQuery {
    pub match_module: bool,
    pub match_function: bool,
    pub match_file: bool,
    pub match_line: bool,
    pub match_format: bool,
    pub match_class: bool,
    pub module_pat: [u8; 64],
    pub func_pat: [u8; 64],
    pub file_pat: [u8; 128],
    pub line_start: u32,
    pub line_end: u32,
    pub class_id: u32,
    pub enable: bool,
    pub flags_add: DynDbgFlags,
    pub flags_remove: DynDbgFlags,
}

// ============================================================================
// Tracepoints
// ============================================================================

/// Tracepoint category
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TracepointCategory {
    Sched = 0,
    Irq = 1,
    Syscalls = 2,
    BlockIo = 3,
    Mm = 4,
    Net = 5,
    FileSys = 6,
    Timer = 7,
    Power = 8,
    Signal = 9,
    Module = 10,
    Workqueue = 11,
    Rcu = 12,
    Lock = 13,
    KvmGuest = 14,
    Writeback = 15,
    Compaction = 16,
    Kmem = 17,
    ClkReset = 18,
    Regulator = 19,
    Ext4 = 20,
    Btrfs = 21,
    Xfs = 22,
    Tcp = 23,
    Udp = 24,
    BridgeIp = 25,
    Io_uring = 26,
    Bpf = 27,
    // Zxyphor
    ZxyKernel = 100,
}

/// Trace event format descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TraceEventFormat {
    pub name: [u8; 64],
    pub name_len: u8,
    pub category: TracepointCategory,
    pub id: u32,
    pub nr_fields: u32,
    pub size: u32,
    pub enabled: bool,
    pub filter_present: bool,
    pub trigger_present: bool,
}

/// Trace event field
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TraceEventField {
    pub name: [u8; 64],
    pub name_len: u8,
    pub field_type: TraceFieldType,
    pub offset: u32,
    pub size: u32,
    pub is_signed: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TraceFieldType {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    I8 = 4,
    I16 = 5,
    I32 = 6,
    I64 = 7,
    String = 8,
    CharArray = 9,
    Pointer = 10,
    Bool = 11,
    Pid = 12,
    Gfp = 13,
    SymAddr = 14,
}

// ============================================================================
// Ftrace
// ============================================================================

/// Ftrace tracer type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FtraceTracer {
    Nop = 0,
    FunctionTracer = 1,
    FunctionGraph = 2,
    Irqsoff = 3,
    Preemptoff = 4,
    PreemptirqsOff = 5,
    Wakeup = 6,
    WakeupRt = 7,
    WakeupDl = 8,
    Mmiotrace = 9,
    Blk = 10,
    Hwlat = 11,
    Osnoise = 12,
    Timerlat = 13,
    // Zxyphor
    ZxyLatency = 100,
    ZxyPerformance = 101,
}

/// Ftrace options
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct FtraceOptions(pub u64);

impl FtraceOptions {
    pub const PRINT_PARENT: Self = Self(1 << 0);
    pub const SYM_OFFSET: Self = Self(1 << 1);
    pub const SYM_ADDR: Self = Self(1 << 2);
    pub const VERBOSE: Self = Self(1 << 3);
    pub const RAW: Self = Self(1 << 4);
    pub const HEX: Self = Self(1 << 5);
    pub const BIN: Self = Self(1 << 6);
    pub const BLOCK: Self = Self(1 << 7);
    pub const PRINTK: Self = Self(1 << 9);
    pub const FUNC_STACK_TRACE: Self = Self(1 << 11);
    pub const PRINT_HEADERS: Self = Self(1 << 14);
    pub const IRQ_INFO: Self = Self(1 << 15);
    pub const MARKERS: Self = Self(1 << 16);
    pub const CONTEXT_INFO: Self = Self(1 << 18);
    pub const LATENCY_FMT: Self = Self(1 << 19);
    pub const RECORD_CMD: Self = Self(1 << 20);
    pub const RECORD_TGID: Self = Self(1 << 21);
    pub const OVERWRITE: Self = Self(1 << 23);
    pub const FUNCGRAPH_OVERRUN: Self = Self(1 << 25);
    pub const FUNCGRAPH_CPU: Self = Self(1 << 26);
    pub const FUNCGRAPH_OVERHEAD: Self = Self(1 << 27);
    pub const FUNCGRAPH_PROC: Self = Self(1 << 28);
    pub const FUNCGRAPH_DURATION: Self = Self(1 << 29);
    pub const FUNCGRAPH_ABS_TIME: Self = Self(1 << 30);
    pub const FUNCGRAPH_IRQS: Self = Self(1 << 31);
    pub const FUNCGRAPH_TAIL: Self = Self(1 << 32);
}

/// Ftrace trace buffer configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FtraceBufferConfig {
    pub per_cpu_buffer_size_kb: u32,
    pub total_buffer_size_kb: u64,
    pub buffer_overwritten: u64,
    pub entries: u64,
    pub entries_overwritten: u64,
    pub current_tracer: FtraceTracer,
    pub tracing_on: bool,
    pub clock_source: FtraceClockSource,
    pub max_latency_us: u64,
    pub tracing_thresh_us: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FtraceClockSource {
    Local = 0,
    Global = 1,
    Counter = 2,
    Uptime = 3,
    Perf = 4,
    Mono = 5,
    MonoRaw = 6,
    Boot = 7,
    Tai = 8,
}

// ============================================================================
// Rate Limiting
// ============================================================================

/// Rate limit configuration
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub interval_ms: u64,
    pub burst: u32,
    pub missed: u64,
    pub begin_ns: u64,
    pub printed: u32,
    pub suppressed: u64,
}

/// Devcoredump info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DevcoredumpInfo {
    pub device_name: [u8; 64],
    pub device_name_len: u8,
    pub size: u64,
    pub timestamp_ns: u64,
    pub disabled: bool,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct LoggingSubsystem {
    pub ring_buffer_size: u64,
    pub ring_buffer_records: u64,
    pub console_count: u32,
    pub console_loglevel: LogLevel,
    pub default_message_loglevel: LogLevel,
    pub dyndbg_descriptors: u64,
    pub dyndbg_enabled: u64,
    pub tracepoints_total: u64,
    pub tracepoints_enabled: u64,
    pub ftrace_tracer: FtraceTracer,
    pub ftrace_tracing_on: bool,
    pub ftrace_per_cpu_kb: u32,
    pub netconsole_active: bool,
    pub devcoredump_enabled: bool,
    pub rate_limit_default_ms: u64,
    pub initialized: bool,
}

impl LoggingSubsystem {
    pub const fn new() -> Self {
        Self {
            ring_buffer_size: 0,
            ring_buffer_records: 0,
            console_count: 0,
            console_loglevel: LogLevel::Warning,
            default_message_loglevel: LogLevel::Warning,
            dyndbg_descriptors: 0,
            dyndbg_enabled: 0,
            tracepoints_total: 0,
            tracepoints_enabled: 0,
            ftrace_tracer: FtraceTracer::Nop,
            ftrace_tracing_on: false,
            ftrace_per_cpu_kb: 1408,
            netconsole_active: false,
            devcoredump_enabled: true,
            rate_limit_default_ms: 5000,
            initialized: false,
        }
    }
}
