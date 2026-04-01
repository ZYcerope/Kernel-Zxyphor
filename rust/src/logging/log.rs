// =============================================================================
// Kernel Zxyphor — Structured Kernel Logger
// =============================================================================
// High-performance kernel logging:
//   - Severity levels (Emergency to Debug)
//   - Subsystem/facility tagging
//   - Timestamped entries
//   - Circular buffer storage (no allocation)
//   - Log filtering by level and subsystem
//   - Rate limiting per subsystem
//   - Console/serial output via callback
//   - Structured key-value metadata
//   - Binary log format for fast processing
//   - Log statistics and overflow tracking
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

pub const MAX_LOG_ENTRIES: usize = 4096;
pub const MAX_LOG_MSG_LEN: usize = 128;
pub const MAX_LOG_META_PAIRS: usize = 4;
pub const MAX_SUBSYSTEMS: usize = 32;
pub const RATE_LIMIT_WINDOW_NS: u64 = 1_000_000_000; // 1 second
pub const RATE_LIMIT_BURST: u32 = 100;

// =============================================================================
// Log level
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Emergency = 0,   // System unusable
    Alert = 1,       // Action required immediately
    Critical = 2,    // Critical conditions
    Error = 3,       // Error conditions
    Warning = 4,     // Warning conditions
    Notice = 5,      // Normal but significant
    Info = 6,        // Informational
    Debug = 7,       // Debug-level
    Trace = 8,       // Finest-grain tracing
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Emergency => "EMERG",
            Self::Alert     => "ALERT",
            Self::Critical  => "CRIT ",
            Self::Error     => "ERROR",
            Self::Warning   => "WARN ",
            Self::Notice    => "NOTE ",
            Self::Info      => "INFO ",
            Self::Debug     => "DEBUG",
            Self::Trace     => "TRACE",
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            7 => Self::Debug,
            _ => Self::Trace,
        }
    }
}

// =============================================================================
// Subsystem IDs
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Subsystem {
    Kernel = 0,
    Memory = 1,
    Scheduler = 2,
    FileSystem = 3,
    Network = 4,
    Driver = 5,
    Security = 6,
    Ipc = 7,
    Syscall = 8,
    Interrupt = 9,
    Pci = 10,
    Usb = 11,
    Storage = 12,
    Timer = 13,
    Power = 14,
    Acpi = 15,
    Debug = 16,
    Init = 17,
    Module = 18,
    Crypto = 19,
    Dma = 20,
    Virtio = 21,
    User = 31,
}

impl Subsystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Kernel     => "kernel",
            Self::Memory     => "mm",
            Self::Scheduler  => "sched",
            Self::FileSystem => "fs",
            Self::Network    => "net",
            Self::Driver     => "drv",
            Self::Security   => "sec",
            Self::Ipc        => "ipc",
            Self::Syscall    => "syscall",
            Self::Interrupt  => "irq",
            Self::Pci        => "pci",
            Self::Usb        => "usb",
            Self::Storage    => "stor",
            Self::Timer      => "timer",
            Self::Power      => "power",
            Self::Acpi       => "acpi",
            Self::Debug      => "debug",
            Self::Init       => "init",
            Self::Module     => "mod",
            Self::Crypto     => "crypto",
            Self::Dma        => "dma",
            Self::Virtio     => "virtio",
            Self::User       => "user",
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Kernel,
            1 => Self::Memory,
            2 => Self::Scheduler,
            3 => Self::FileSystem,
            4 => Self::Network,
            5 => Self::Driver,
            6 => Self::Security,
            7 => Self::Ipc,
            8 => Self::Syscall,
            9 => Self::Interrupt,
            10 => Self::Pci,
            11 => Self::Usb,
            12 => Self::Storage,
            13 => Self::Timer,
            14 => Self::Power,
            15 => Self::Acpi,
            16 => Self::Debug,
            17 => Self::Init,
            18 => Self::Module,
            19 => Self::Crypto,
            20 => Self::Dma,
            21 => Self::Virtio,
            _ => Self::User,
        }
    }
}

// =============================================================================
// Key-value metadata pair
// =============================================================================

pub struct MetaPair {
    pub key: [u8; 16],
    pub key_len: usize,
    pub value: [u8; 32],
    pub value_len: usize,
}

impl MetaPair {
    pub const fn empty() -> Self {
        Self {
            key: [0u8; 16],
            key_len: 0,
            value: [0u8; 32],
            value_len: 0,
        }
    }

    pub fn set(&mut self, key: &[u8], value: &[u8]) {
        let klen = key.len().min(16);
        let vlen = value.len().min(32);
        self.key[..klen].copy_from_slice(&key[..klen]);
        self.key_len = klen;
        self.value[..vlen].copy_from_slice(&value[..vlen]);
        self.value_len = vlen;
    }
}

// =============================================================================
// Log entry
// =============================================================================

pub struct LogEntry {
    pub timestamp_ns: u64,
    pub level: LogLevel,
    pub subsystem: Subsystem,
    pub cpu: u8,
    pub pid: u32,
    pub message: [u8; MAX_LOG_MSG_LEN],
    pub msg_len: usize,
    pub meta: [MetaPair; MAX_LOG_META_PAIRS],
    pub meta_count: u8,
    pub sequence: u64,
    pub valid: bool,
}

impl LogEntry {
    pub const fn empty() -> Self {
        Self {
            timestamp_ns: 0,
            level: LogLevel::Info,
            subsystem: Subsystem::Kernel,
            cpu: 0,
            pid: 0,
            message: [0u8; MAX_LOG_MSG_LEN],
            msg_len: 0,
            meta: [const { MetaPair::empty() }; MAX_LOG_META_PAIRS],
            meta_count: 0,
            sequence: 0,
            valid: false,
        }
    }

    pub fn set_message(&mut self, msg: &[u8]) {
        let len = msg.len().min(MAX_LOG_MSG_LEN);
        self.message[..len].copy_from_slice(&msg[..len]);
        self.msg_len = len;
    }

    pub fn add_meta(&mut self, key: &[u8], value: &[u8]) {
        if (self.meta_count as usize) < MAX_LOG_META_PAIRS {
            self.meta[self.meta_count as usize].set(key, value);
            self.meta_count += 1;
        }
    }

    /// Format entry into buffer: "[LEVEL] subsystem: message\n"
    pub fn format(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0usize;

        // Write level prefix
        let level_str = self.level.as_str().as_bytes();
        let prefix = b"[";
        let suffix = b"] ";
        if pos + 1 + level_str.len() + 2 > buf.len() { return pos; }
        buf[pos] = prefix[0]; pos += 1;
        buf[pos..pos + level_str.len()].copy_from_slice(level_str);
        pos += level_str.len();
        buf[pos..pos + 2].copy_from_slice(suffix);
        pos += 2;

        // Write subsystem
        let sub_str = self.subsystem.as_str().as_bytes();
        if pos + sub_str.len() + 2 > buf.len() { return pos; }
        buf[pos..pos + sub_str.len()].copy_from_slice(sub_str);
        pos += sub_str.len();
        buf[pos..pos + 2].copy_from_slice(b": ");
        pos += 2;

        // Write message
        let mlen = self.msg_len.min(buf.len() - pos - 1);
        buf[pos..pos + mlen].copy_from_slice(&self.message[..mlen]);
        pos += mlen;

        // Newline
        if pos < buf.len() {
            buf[pos] = b'\n';
            pos += 1;
        }
        pos
    }
}

// =============================================================================
// Rate limiter (per subsystem)
// =============================================================================

pub struct SubsystemFilter {
    pub min_level: LogLevel,
    pub enabled: bool,
    pub rate_count: u32,
    pub rate_window_start_ns: u64,
    pub dropped: u64,
}

impl SubsystemFilter {
    pub const fn new() -> Self {
        Self {
            min_level: LogLevel::Info,
            enabled: true,
            rate_count: 0,
            rate_window_start_ns: 0,
            dropped: 0,
        }
    }

    pub fn check(&mut self, level: LogLevel, now_ns: u64) -> bool {
        if !self.enabled { return false; }
        if level > self.min_level { return false; }

        // Rate limiting
        if now_ns - self.rate_window_start_ns >= RATE_LIMIT_WINDOW_NS {
            self.rate_count = 0;
            self.rate_window_start_ns = now_ns;
        }
        if self.rate_count >= RATE_LIMIT_BURST {
            self.dropped += 1;
            return false;
        }
        self.rate_count += 1;
        true
    }
}

// =============================================================================
// Kernel logger
// =============================================================================

/// Output callback type (e.g., serial port write)
pub type OutputCallback = Option<extern "C" fn(*const u8, usize)>;

pub struct KernelLogger {
    pub entries: [LogEntry; MAX_LOG_ENTRIES],
    pub write_idx: AtomicU32,
    pub sequence: AtomicU64,
    pub global_level: LogLevel,
    pub filters: [SubsystemFilter; MAX_SUBSYSTEMS],
    pub output_callback: OutputCallback,
    pub console_enabled: AtomicBool,
    pub total_logged: AtomicU64,
    pub total_dropped: AtomicU64,
    pub overflow_count: AtomicU64,
    pub initialized: bool,
}

impl KernelLogger {
    pub const fn new() -> Self {
        Self {
            entries: [const { LogEntry::empty() }; MAX_LOG_ENTRIES],
            write_idx: AtomicU32::new(0),
            sequence: AtomicU64::new(0),
            global_level: LogLevel::Info,
            filters: [const { SubsystemFilter::new() }; MAX_SUBSYSTEMS],
            output_callback: None,
            console_enabled: AtomicBool::new(true),
            total_logged: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            overflow_count: AtomicU64::new(0),
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
    }

    pub fn set_output(&mut self, cb: extern "C" fn(*const u8, usize)) {
        self.output_callback = Some(cb);
    }

    pub fn set_global_level(&mut self, level: LogLevel) {
        self.global_level = level;
    }

    pub fn set_subsystem_level(&mut self, subsys: Subsystem, level: LogLevel) {
        let idx = subsys as usize;
        if idx < MAX_SUBSYSTEMS {
            self.filters[idx].min_level = level;
        }
    }

    pub fn enable_subsystem(&mut self, subsys: Subsystem, enabled: bool) {
        let idx = subsys as usize;
        if idx < MAX_SUBSYSTEMS {
            self.filters[idx].enabled = enabled;
        }
    }

    /// Core log function
    pub fn log(
        &mut self,
        level: LogLevel,
        subsys: Subsystem,
        cpu: u8,
        pid: u32,
        msg: &[u8],
        now_ns: u64,
    ) {
        // Global level filter
        if level > self.global_level {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Per-subsystem filter + rate limit
        let sub_idx = subsys as usize;
        if sub_idx < MAX_SUBSYSTEMS {
            if !self.filters[sub_idx].check(level, now_ns) {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // Get next slot (circular)
        let idx = self.write_idx.fetch_add(1, Ordering::Relaxed) as usize % MAX_LOG_ENTRIES;
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        if self.entries[idx].valid {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
        }

        self.entries[idx] = LogEntry::empty();
        self.entries[idx].timestamp_ns = now_ns;
        self.entries[idx].level = level;
        self.entries[idx].subsystem = subsys;
        self.entries[idx].cpu = cpu;
        self.entries[idx].pid = pid;
        self.entries[idx].set_message(msg);
        self.entries[idx].sequence = seq;
        self.entries[idx].valid = true;

        self.total_logged.fetch_add(1, Ordering::Relaxed);

        // Console output
        if self.console_enabled.load(Ordering::Relaxed) {
            if let Some(cb) = self.output_callback {
                let mut buf = [0u8; 256];
                let len = self.entries[idx].format(&mut buf);
                cb(buf.as_ptr(), len);
            }
        }
    }

    /// Read entries from the ring buffer
    pub fn read_entries(&self, start_seq: u64, buf: &mut [LogEntry]) -> usize {
        let mut count = 0;
        for entry in &self.entries {
            if entry.valid && entry.sequence >= start_seq && count < buf.len() {
                buf[count] = LogEntry::empty();
                buf[count].timestamp_ns = entry.timestamp_ns;
                buf[count].level = entry.level;
                buf[count].subsystem = entry.subsystem;
                buf[count].cpu = entry.cpu;
                buf[count].pid = entry.pid;
                buf[count].msg_len = entry.msg_len;
                buf[count].message[..entry.msg_len].copy_from_slice(&entry.message[..entry.msg_len]);
                buf[count].sequence = entry.sequence;
                buf[count].valid = true;
                count += 1;
            }
        }
        count
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.total_logged.load(Ordering::Relaxed),
            self.total_dropped.load(Ordering::Relaxed),
            self.overflow_count.load(Ordering::Relaxed),
        )
    }
}

static mut LOGGER: KernelLogger = KernelLogger::new();

pub unsafe fn logger() -> &'static mut KernelLogger {
    &mut *core::ptr::addr_of_mut!(LOGGER)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_log_init() {
    unsafe { logger().init(); }
}

#[no_mangle]
pub extern "C" fn zxyphor_log_set_output(cb: extern "C" fn(*const u8, usize)) {
    unsafe { logger().set_output(cb); }
}

#[no_mangle]
pub extern "C" fn zxyphor_log_set_level(level: u8) {
    unsafe { logger().set_global_level(LogLevel::from_u8(level)); }
}

#[no_mangle]
pub extern "C" fn zxyphor_log_write(
    level: u8, subsys: u8, cpu: u8, pid: u32,
    msg_ptr: *const u8, msg_len: usize, now_ns: u64,
) {
    if msg_ptr.is_null() || msg_len == 0 { return; }
    let msg = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len.min(MAX_LOG_MSG_LEN)) };
    unsafe {
        logger().log(
            LogLevel::from_u8(level),
            Subsystem::from_u8(subsys),
            cpu, pid, msg, now_ns,
        );
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_log_stats(logged: *mut u64, dropped: *mut u64, overflow: *mut u64) {
    let (l, d, o) = unsafe { logger().stats() };
    if !logged.is_null() { unsafe { *logged = l; } }
    if !dropped.is_null() { unsafe { *dropped = d; } }
    if !overflow.is_null() { unsafe { *overflow = o; } }
}
