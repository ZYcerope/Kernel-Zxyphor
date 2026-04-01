// =============================================================================
// Kernel Zxyphor — Kernel Tracing (ftrace-like)
// =============================================================================
// Low-overhead function tracing and event recording:
//   - Trace events with nanosecond timestamps
//   - Function entry/exit tracing
//   - Custom trace events (user-defined)
//   - IRQ/softirq/scheduler event tracing
//   - Per-CPU trace buffers (no lock contention)
//   - Trace filtering by function, PID, subsystem
//   - Trace markers (user-triggered)
//   - Binary trace format for offline analysis
//   - Trace statistics and buffer utilization
//   - Dynamic enable/disable per event type
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

pub const TRACE_BUFFER_SIZE: usize = 8192;
pub const MAX_TRACE_CPUS: usize = 64;
pub const MAX_TRACE_FILTERS: usize = 32;

// =============================================================================
// Trace event types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceEventType {
    FuncEntry = 0,
    FuncExit = 1,
    IrqEntry = 2,
    IrqExit = 3,
    SoftIrqEntry = 4,
    SoftIrqExit = 5,
    SchedSwitch = 6,
    SchedWakeup = 7,
    SchedMigrate = 8,
    PageFault = 9,
    PageAlloc = 10,
    PageFree = 11,
    SyscallEntry = 12,
    SyscallExit = 13,
    LockAcquire = 14,
    LockRelease = 15,
    LockContend = 16,
    IoSubmit = 17,
    IoComplete = 18,
    NetRx = 19,
    NetTx = 20,
    Timer = 21,
    Wakeup = 22,
    Marker = 23,
    Custom = 24,
}

impl TraceEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FuncEntry     => "func_enter",
            Self::FuncExit      => "func_exit",
            Self::IrqEntry      => "irq_enter",
            Self::IrqExit       => "irq_exit",
            Self::SoftIrqEntry  => "softirq_enter",
            Self::SoftIrqExit   => "softirq_exit",
            Self::SchedSwitch   => "sched_switch",
            Self::SchedWakeup   => "sched_wakeup",
            Self::SchedMigrate  => "sched_migrate",
            Self::PageFault     => "page_fault",
            Self::PageAlloc     => "page_alloc",
            Self::PageFree      => "page_free",
            Self::SyscallEntry  => "syscall_enter",
            Self::SyscallExit   => "syscall_exit",
            Self::LockAcquire   => "lock_acquire",
            Self::LockRelease   => "lock_release",
            Self::LockContend   => "lock_contend",
            Self::IoSubmit      => "io_submit",
            Self::IoComplete    => "io_complete",
            Self::NetRx         => "net_rx",
            Self::NetTx         => "net_tx",
            Self::Timer         => "timer",
            Self::Wakeup        => "wakeup",
            Self::Marker        => "marker",
            Self::Custom        => "custom",
        }
    }
}

// =============================================================================
// Trace entry (compact binary format)
// =============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TraceEntry {
    pub timestamp_ns: u64,
    pub event_type: TraceEventType,
    pub cpu: u8,
    pub pid: u32,
    pub tid: u32,
    pub arg0: u64,   // Event-specific argument
    pub arg1: u64,
    pub arg2: u64,
    pub func_addr: u64,   // Function address (for func trace)
    pub caller_addr: u64, // Return address
}

impl TraceEntry {
    pub const fn empty() -> Self {
        Self {
            timestamp_ns: 0,
            event_type: TraceEventType::Custom,
            cpu: 0,
            pid: 0,
            tid: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            func_addr: 0,
            caller_addr: 0,
        }
    }
}

// =============================================================================
// Per-CPU trace buffer
// =============================================================================

pub struct CpuTraceBuffer {
    pub entries: [TraceEntry; TRACE_BUFFER_SIZE],
    pub write_idx: u32,
    pub total_events: u64,
    pub overflows: u64,
    pub enabled: bool,
}

impl CpuTraceBuffer {
    pub const fn new() -> Self {
        Self {
            entries: [const { TraceEntry::empty() }; TRACE_BUFFER_SIZE],
            write_idx: 0,
            total_events: 0,
            overflows: 0,
            enabled: true,
        }
    }

    pub fn record(&mut self, event: TraceEntry) {
        if !self.enabled { return; }
        let idx = self.write_idx as usize % TRACE_BUFFER_SIZE;
        if self.entries[idx].timestamp_ns != 0 && self.total_events >= TRACE_BUFFER_SIZE as u64 {
            self.overflows += 1;
        }
        self.entries[idx] = event;
        self.write_idx = self.write_idx.wrapping_add(1);
        self.total_events += 1;
    }

    pub fn utilization_pct(&self) -> u32 {
        let used = self.total_events.min(TRACE_BUFFER_SIZE as u64);
        ((used * 100) / TRACE_BUFFER_SIZE as u64) as u32
    }
}

// =============================================================================
// Trace filter
// =============================================================================

pub struct TraceFilter {
    pub event_type: TraceEventType,
    pub pid_filter: u32,        // 0 = any
    pub func_addr_min: u64,     // 0 = any
    pub func_addr_max: u64,
    pub active: bool,
}

impl TraceFilter {
    pub const fn empty() -> Self {
        Self {
            event_type: TraceEventType::Custom,
            pid_filter: 0,
            func_addr_min: 0,
            func_addr_max: 0,
            active: false,
        }
    }

    pub fn matches(&self, entry: &TraceEntry) -> bool {
        if !self.active { return true; }
        if entry.event_type != self.event_type { return false; }
        if self.pid_filter != 0 && entry.pid != self.pid_filter { return false; }
        if self.func_addr_min != 0 && entry.func_addr < self.func_addr_min { return false; }
        if self.func_addr_max != 0 && entry.func_addr > self.func_addr_max { return false; }
        true
    }
}

// =============================================================================
// Event type enable mask
// =============================================================================

pub struct EventMask {
    pub bits: [u32; 1],  // 32 event types max
}

impl EventMask {
    pub const fn all_enabled() -> Self {
        Self { bits: [0xFFFFFFFF] }
    }

    pub const fn none() -> Self {
        Self { bits: [0] }
    }

    pub fn enable(&mut self, event_type: TraceEventType) {
        let idx = event_type as usize;
        if idx < 32 {
            self.bits[0] |= 1 << idx;
        }
    }

    pub fn disable(&mut self, event_type: TraceEventType) {
        let idx = event_type as usize;
        if idx < 32 {
            self.bits[0] &= !(1 << idx);
        }
    }

    pub fn is_enabled(&self, event_type: TraceEventType) -> bool {
        let idx = event_type as usize;
        if idx < 32 {
            (self.bits[0] & (1 << idx)) != 0
        } else {
            false
        }
    }
}

// =============================================================================
// Tracer
// =============================================================================

pub struct Tracer {
    pub buffers: [CpuTraceBuffer; MAX_TRACE_CPUS],
    pub active_cpus: u32,
    pub filters: [TraceFilter; MAX_TRACE_FILTERS],
    pub filter_count: u32,
    pub event_mask: EventMask,
    pub global_enabled: AtomicBool,
    pub total_events: AtomicU64,
    pub start_ns: u64,
}

impl Tracer {
    pub const fn new() -> Self {
        Self {
            buffers: [const { CpuTraceBuffer::new() }; MAX_TRACE_CPUS],
            active_cpus: 1,
            filters: [const { TraceFilter::empty() }; MAX_TRACE_FILTERS],
            filter_count: 0,
            event_mask: EventMask::all_enabled(),
            global_enabled: AtomicBool::new(false),
            total_events: AtomicU64::new(0),
            start_ns: 0,
        }
    }

    pub fn start(&mut self, now_ns: u64) {
        self.start_ns = now_ns;
        self.global_enabled.store(true, Ordering::Release);
    }

    pub fn stop(&self) {
        self.global_enabled.store(false, Ordering::Release);
    }

    pub fn is_active(&self) -> bool {
        self.global_enabled.load(Ordering::Acquire)
    }

    /// Record a trace event
    pub fn trace_event(
        &mut self,
        event_type: TraceEventType,
        cpu: u8,
        pid: u32,
        tid: u32,
        func_addr: u64,
        caller_addr: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        now_ns: u64,
    ) {
        if !self.is_active() { return; }
        if !self.event_mask.is_enabled(event_type) { return; }

        let entry = TraceEntry {
            timestamp_ns: now_ns,
            event_type,
            cpu,
            pid,
            tid,
            arg0,
            arg1,
            arg2,
            func_addr,
            caller_addr,
        };

        // Check filters
        let filter_count = self.filter_count;
        if filter_count > 0 {
            let mut pass = false;
            for i in 0..filter_count as usize {
                if self.filters[i].matches(&entry) {
                    pass = true;
                    break;
                }
            }
            if !pass { return; }
        }

        let cpu_idx = cpu as usize;
        if cpu_idx < MAX_TRACE_CPUS {
            self.buffers[cpu_idx].record(entry);
            self.total_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Convenience: trace function entry
    pub fn trace_func_entry(&mut self, cpu: u8, pid: u32, func: u64, caller: u64, now_ns: u64) {
        self.trace_event(TraceEventType::FuncEntry, cpu, pid, pid, func, caller, 0, 0, 0, now_ns);
    }

    /// Convenience: trace function exit
    pub fn trace_func_exit(&mut self, cpu: u8, pid: u32, func: u64, ret_val: u64, now_ns: u64) {
        self.trace_event(TraceEventType::FuncExit, cpu, pid, pid, func, 0, ret_val, 0, 0, now_ns);
    }

    /// Convenience: trace context switch
    pub fn trace_sched_switch(&mut self, cpu: u8, prev_pid: u32, next_pid: u32, now_ns: u64) {
        self.trace_event(TraceEventType::SchedSwitch, cpu, prev_pid, prev_pid, 0, 0, next_pid as u64, 0, 0, now_ns);
    }

    /// Convenience: trace IRQ
    pub fn trace_irq(&mut self, cpu: u8, irq_num: u32, enter: bool, now_ns: u64) {
        let evt = if enter { TraceEventType::IrqEntry } else { TraceEventType::IrqExit };
        self.trace_event(evt, cpu, 0, 0, 0, 0, irq_num as u64, 0, 0, now_ns);
    }

    /// Add a filter
    pub fn add_filter(&mut self, filter: TraceFilter) -> bool {
        if self.filter_count as usize >= MAX_TRACE_FILTERS { return false; }
        self.filters[self.filter_count as usize] = filter;
        self.filter_count += 1;
        true
    }

    pub fn clear_filters(&mut self) {
        self.filter_count = 0;
    }

    /// Reset all buffers
    pub fn reset(&mut self) {
        for i in 0..MAX_TRACE_CPUS {
            self.buffers[i] = CpuTraceBuffer::new();
        }
        self.total_events.store(0, Ordering::Relaxed);
    }
}

static mut TRACER: Tracer = Tracer::new();

pub unsafe fn tracer() -> &'static mut Tracer {
    &mut *core::ptr::addr_of_mut!(TRACER)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_trace_start(now_ns: u64) {
    unsafe { tracer().start(now_ns); }
}

#[no_mangle]
pub extern "C" fn zxyphor_trace_stop() {
    unsafe { tracer().stop(); }
}

#[no_mangle]
pub extern "C" fn zxyphor_trace_event(
    event_type: u8, cpu: u8, pid: u32, tid: u32,
    func_addr: u64, caller: u64, arg0: u64, arg1: u64, arg2: u64, now_ns: u64,
) {
    let evt = match event_type {
        0 => TraceEventType::FuncEntry,
        1 => TraceEventType::FuncExit,
        2 => TraceEventType::IrqEntry,
        3 => TraceEventType::IrqExit,
        6 => TraceEventType::SchedSwitch,
        7 => TraceEventType::SchedWakeup,
        23 => TraceEventType::Marker,
        _ => TraceEventType::Custom,
    };
    unsafe { tracer().trace_event(evt, cpu, pid, tid, func_addr, caller, arg0, arg1, arg2, now_ns); }
}

#[no_mangle]
pub extern "C" fn zxyphor_trace_reset() {
    unsafe { tracer().reset(); }
}

#[no_mangle]
pub extern "C" fn zxyphor_trace_total_events() -> u64 {
    unsafe { tracer().total_events.load(Ordering::Relaxed) }
}
