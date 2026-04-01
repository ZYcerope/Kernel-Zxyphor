// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Kernel Tracing Infrastructure
//
// Implements a comprehensive tracing subsystem:
// - Kernel function tracing (ftrace-like)
// - Tracepoints with typed arguments
// - Event ring buffer per CPU
// - Trace event recording with timestamps
// - Dynamic tracing (kprobes/uprobes)
// - Trace pipelines and filters
// - Binary trace format serialization

#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_TRACE_EVENTS: usize = 65536;
pub const MAX_TRACE_CPUS: usize = 256;
pub const MAX_TRACEPOINTS: usize = 1024;
pub const MAX_TRACE_ARGS: usize = 8;
pub const MAX_KPROBES: usize = 256;
pub const TRACE_BUFFER_SIZE: usize = 32768;
pub const MAX_TRACE_FILTERS: usize = 32;
pub const MAX_TRACE_NAME: usize = 64;
pub const MAX_TRACE_MSG: usize = 256;

// ─────────────────── Trace Event Types ──────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceEventType {
    /// Function entry
    FuncEntry = 0,
    /// Function exit (with return value)
    FuncExit = 1,
    /// Static tracepoint hit
    Tracepoint = 2,
    /// Kprobe hit
    Kprobe = 3,
    /// Kretprobe hit (function return)
    Kretprobe = 4,
    /// Uprobe (user-space probe)
    Uprobe = 5,
    /// Context switch event
    SchedSwitch = 6,
    /// IRQ entry
    IrqEntry = 7,
    /// IRQ exit
    IrqExit = 8,
    /// Softirq entry
    SoftirqEntry = 9,
    /// Softirq exit
    SoftirqExit = 10,
    /// Page fault
    PageFault = 11,
    /// Syscall entry
    SyscallEntry = 12,
    /// Syscall exit
    SyscallExit = 13,
    /// Custom user event
    Custom = 14,
    /// Memory allocation
    MemAlloc = 15,
    /// Memory free
    MemFree = 16,
    /// Block I/O request
    BlockReq = 17,
    /// Block I/O completion
    BlockComp = 18,
    /// Network packet
    NetPacket = 19,
}

impl TraceEventType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::FuncEntry => "func_entry",
            Self::FuncExit => "func_exit",
            Self::Tracepoint => "tracepoint",
            Self::Kprobe => "kprobe",
            Self::Kretprobe => "kretprobe",
            Self::Uprobe => "uprobe",
            Self::SchedSwitch => "sched_switch",
            Self::IrqEntry => "irq_entry",
            Self::IrqExit => "irq_exit",
            Self::SoftirqEntry => "softirq_entry",
            Self::SoftirqExit => "softirq_exit",
            Self::PageFault => "page_fault",
            Self::SyscallEntry => "syscall_entry",
            Self::SyscallExit => "syscall_exit",
            Self::Custom => "custom",
            Self::MemAlloc => "mem_alloc",
            Self::MemFree => "mem_free",
            Self::BlockReq => "block_req",
            Self::BlockComp => "block_comp",
            Self::NetPacket => "net_packet",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::FuncEntry | Self::FuncExit => "function",
            Self::Tracepoint | Self::Custom => "tracepoint",
            Self::Kprobe | Self::Kretprobe | Self::Uprobe => "probe",
            Self::SchedSwitch => "scheduler",
            Self::IrqEntry | Self::IrqExit | Self::SoftirqEntry | Self::SoftirqExit => "irq",
            Self::PageFault | Self::MemAlloc | Self::MemFree => "memory",
            Self::SyscallEntry | Self::SyscallExit => "syscall",
            Self::BlockReq | Self::BlockComp => "block",
            Self::NetPacket => "network",
        }
    }
}

// ─────────────────── Trace Event Record ─────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct TraceEvent {
    /// Event type
    pub event_type: TraceEventType,
    /// Timestamp in nanoseconds
    pub timestamp_ns: u64,
    /// CPU where the event occurred
    pub cpu: u16,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Instruction pointer (for function events)
    pub ip: u64,
    /// Parent instruction pointer (caller)
    pub parent_ip: u64,
    /// Event-specific data fields
    pub args: [u64; MAX_TRACE_ARGS],
    /// Number of valid args
    pub arg_count: u8,
    /// Event flags
    pub flags: u16,
    /// Nesting depth (for function graphs)
    pub depth: u8,
}

impl Default for TraceEvent {
    fn default() -> Self {
        Self {
            event_type: TraceEventType::Custom,
            timestamp_ns: 0,
            cpu: 0,
            pid: 0,
            tid: 0,
            ip: 0,
            parent_ip: 0,
            args: [0; MAX_TRACE_ARGS],
            arg_count: 0,
            flags: 0,
            depth: 0,
        }
    }
}

impl TraceEvent {
    pub fn func_entry(ip: u64, parent_ip: u64, pid: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::FuncEntry,
            timestamp_ns: ts,
            cpu,
            pid,
            tid: pid,
            ip,
            parent_ip,
            ..Default::default()
        }
    }

    pub fn func_exit(ip: u64, ret_val: u64, pid: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::FuncExit,
            timestamp_ns: ts,
            cpu,
            pid,
            tid: pid,
            ip,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = ret_val;
                a
            },
            arg_count: 1,
            ..Default::default()
        }
    }

    pub fn sched_switch(
        prev_pid: u32, prev_state: u64,
        next_pid: u32, next_prio: u64,
        cpu: u16, ts: u64,
    ) -> Self {
        Self {
            event_type: TraceEventType::SchedSwitch,
            timestamp_ns: ts,
            cpu,
            pid: prev_pid,
            tid: prev_pid,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = prev_pid as u64;
                a[1] = prev_state;
                a[2] = next_pid as u64;
                a[3] = next_prio;
                a
            },
            arg_count: 4,
            ..Default::default()
        }
    }

    pub fn irq_entry(irq: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::IrqEntry,
            timestamp_ns: ts,
            cpu,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = irq as u64;
                a
            },
            arg_count: 1,
            ..Default::default()
        }
    }

    pub fn irq_exit(irq: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::IrqExit,
            timestamp_ns: ts,
            cpu,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = irq as u64;
                a
            },
            arg_count: 1,
            ..Default::default()
        }
    }

    pub fn syscall_entry(nr: u32, arg0: u64, arg1: u64, arg2: u64, pid: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::SyscallEntry,
            timestamp_ns: ts,
            cpu,
            pid,
            tid: pid,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = nr as u64;
                a[1] = arg0;
                a[2] = arg1;
                a[3] = arg2;
                a
            },
            arg_count: 4,
            ..Default::default()
        }
    }

    pub fn mem_alloc(addr: u64, size: u64, pid: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::MemAlloc,
            timestamp_ns: ts,
            cpu,
            pid,
            tid: pid,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = addr;
                a[1] = size;
                a
            },
            arg_count: 2,
            ..Default::default()
        }
    }

    pub fn mem_free(addr: u64, pid: u32, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::MemFree,
            timestamp_ns: ts,
            cpu,
            pid,
            tid: pid,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = addr;
                a
            },
            arg_count: 1,
            ..Default::default()
        }
    }

    pub fn block_req(dev: u64, sector: u64, len: u64, rw: u64, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::BlockReq,
            timestamp_ns: ts,
            cpu,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = dev;
                a[1] = sector;
                a[2] = len;
                a[3] = rw;
                a
            },
            arg_count: 4,
            ..Default::default()
        }
    }

    pub fn net_packet(proto: u64, len: u64, src: u64, dst: u64, cpu: u16, ts: u64) -> Self {
        Self {
            event_type: TraceEventType::NetPacket,
            timestamp_ns: ts,
            cpu,
            args: {
                let mut a = [0u64; MAX_TRACE_ARGS];
                a[0] = proto;
                a[1] = len;
                a[2] = src;
                a[3] = dst;
                a
            },
            arg_count: 4,
            ..Default::default()
        }
    }

    /// Serialize event to binary buffer (returns bytes written)
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 64 { return 0; }

        let mut off = 0;

        // Header: type(4) + ts(8) + cpu(2) + pid(4) + tid(4) + flags(2) + depth(1) + arg_count(1)
        let etype = self.event_type as u32;
        buf[off..off+4].copy_from_slice(&etype.to_le_bytes());
        off += 4;

        buf[off..off+8].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        off += 8;

        buf[off..off+2].copy_from_slice(&self.cpu.to_le_bytes());
        off += 2;

        buf[off..off+4].copy_from_slice(&self.pid.to_le_bytes());
        off += 4;

        buf[off..off+4].copy_from_slice(&self.tid.to_le_bytes());
        off += 4;

        buf[off..off+8].copy_from_slice(&self.ip.to_le_bytes());
        off += 8;

        buf[off..off+8].copy_from_slice(&self.parent_ip.to_le_bytes());
        off += 8;

        buf[off] = self.arg_count;
        off += 1;

        buf[off] = self.depth;
        off += 1;

        buf[off..off+2].copy_from_slice(&self.flags.to_le_bytes());
        off += 2;

        // Args
        for i in 0..self.arg_count as usize {
            if off + 8 > buf.len() { break; }
            buf[off..off+8].copy_from_slice(&self.args[i].to_le_bytes());
            off += 8;
        }

        off
    }

    /// Deserialize event from binary buffer
    pub fn deserialize(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 46 { return None; }

        let mut off = 0;
        let mut event = Self::default();

        let etype = u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        event.event_type = match etype {
            0 => TraceEventType::FuncEntry,
            1 => TraceEventType::FuncExit,
            2 => TraceEventType::Tracepoint,
            3 => TraceEventType::Kprobe,
            6 => TraceEventType::SchedSwitch,
            7 => TraceEventType::IrqEntry,
            8 => TraceEventType::IrqExit,
            12 => TraceEventType::SyscallEntry,
            13 => TraceEventType::SyscallExit,
            14 => TraceEventType::Custom,
            15 => TraceEventType::MemAlloc,
            16 => TraceEventType::MemFree,
            17 => TraceEventType::BlockReq,
            19 => TraceEventType::NetPacket,
            _ => TraceEventType::Custom,
        };
        off += 4;

        event.timestamp_ns = u64::from_le_bytes([
            buf[off], buf[off+1], buf[off+2], buf[off+3],
            buf[off+4], buf[off+5], buf[off+6], buf[off+7],
        ]);
        off += 8;

        event.cpu = u16::from_le_bytes([buf[off], buf[off+1]]);
        off += 2;

        event.pid = u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        off += 4;

        event.tid = u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        off += 4;

        event.ip = u64::from_le_bytes([
            buf[off], buf[off+1], buf[off+2], buf[off+3],
            buf[off+4], buf[off+5], buf[off+6], buf[off+7],
        ]);
        off += 8;

        event.parent_ip = u64::from_le_bytes([
            buf[off], buf[off+1], buf[off+2], buf[off+3],
            buf[off+4], buf[off+5], buf[off+6], buf[off+7],
        ]);
        off += 8;

        event.arg_count = buf[off];
        off += 1;

        event.depth = buf[off];
        off += 1;

        event.flags = u16::from_le_bytes([buf[off], buf[off+1]]);
        off += 2;

        for i in 0..event.arg_count as usize {
            if i >= MAX_TRACE_ARGS || off + 8 > buf.len() { break; }
            event.args[i] = u64::from_le_bytes([
                buf[off], buf[off+1], buf[off+2], buf[off+3],
                buf[off+4], buf[off+5], buf[off+6], buf[off+7],
            ]);
            off += 8;
        }

        Some((event, off))
    }
}

// ─────────────────── Per-CPU Trace Buffer ───────────────────────────
pub struct TraceBuffer {
    events: [TraceEvent; TRACE_BUFFER_SIZE],
    head: usize,
    tail: usize,
    count: usize,
    capacity: usize,
    overflows: u64,
    total_events: u64,
    enabled: bool,
    cpu: u16,
}

impl TraceBuffer {
    pub fn new(cpu: u16) -> Self {
        Self {
            events: [TraceEvent::default(); TRACE_BUFFER_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            capacity: TRACE_BUFFER_SIZE,
            overflows: 0,
            total_events: 0,
            enabled: true,
            cpu,
        }
    }

    pub fn push(&mut self, event: TraceEvent) -> bool {
        if !self.enabled { return false; }

        if self.count >= self.capacity {
            // Overwrite oldest event
            self.tail = (self.tail + 1) % self.capacity;
            self.count -= 1;
            self.overflows += 1;
        }

        self.events[self.head] = event;
        self.head = (self.head + 1) % self.capacity;
        self.count += 1;
        self.total_events += 1;
        true
    }

    pub fn pop(&mut self) -> Option<TraceEvent> {
        if self.count == 0 { return None; }

        let event = self.events[self.tail];
        self.tail = (self.tail + 1) % self.capacity;
        self.count -= 1;
        Some(event)
    }

    pub fn peek(&self) -> Option<&TraceEvent> {
        if self.count == 0 { return None; }
        Some(&self.events[self.tail])
    }

    pub fn drain(&mut self, out: &mut [TraceEvent]) -> usize {
        let mut written = 0;
        while written < out.len() {
            if let Some(event) = self.pop() {
                out[written] = event;
                written += 1;
            } else {
                break;
            }
        }
        written
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }

    pub fn enable(&mut self) { self.enabled = true; }
    pub fn disable(&mut self) { self.enabled = false; }
    pub fn is_enabled(&self) -> bool { self.enabled }
    pub fn count(&self) -> usize { self.count }
    pub fn overflows(&self) -> u64 { self.overflows }
    pub fn total_events(&self) -> u64 { self.total_events }
}

// ─────────────────── Trace Filter ───────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct TraceFilter {
    /// Filter by event type (None = all)
    pub event_type: Option<TraceEventType>,
    /// Filter by PID (0 = all)
    pub pid: u32,
    /// Filter by CPU (-1 = all)
    pub cpu: i32,
    /// Filter by IP range (0 = disabled)
    pub ip_min: u64,
    pub ip_max: u64,
    /// Filter by minimum timestamp
    pub ts_min: u64,
    /// Filter by flags mask
    pub flags_mask: u16,
    pub flags_value: u16,
    /// Active flag
    pub active: bool,
}

impl Default for TraceFilter {
    fn default() -> Self {
        Self {
            event_type: None,
            pid: 0,
            cpu: -1,
            ip_min: 0,
            ip_max: 0,
            ts_min: 0,
            flags_mask: 0,
            flags_value: 0,
            active: false,
        }
    }
}

impl TraceFilter {
    pub fn for_pid(pid: u32) -> Self {
        Self {
            pid,
            active: true,
            ..Default::default()
        }
    }

    pub fn for_event_type(etype: TraceEventType) -> Self {
        Self {
            event_type: Some(etype),
            active: true,
            ..Default::default()
        }
    }

    pub fn for_cpu(cpu: u16) -> Self {
        Self {
            cpu: cpu as i32,
            active: true,
            ..Default::default()
        }
    }

    pub fn for_ip_range(min: u64, max: u64) -> Self {
        Self {
            ip_min: min,
            ip_max: max,
            active: true,
            ..Default::default()
        }
    }

    pub fn matches(&self, event: &TraceEvent) -> bool {
        if !self.active { return true; } // Inactive filter passes everything

        if let Some(etype) = self.event_type {
            if event.event_type as u32 != etype as u32 { return false; }
        }

        if self.pid != 0 && event.pid != self.pid { return false; }

        if self.cpu >= 0 && event.cpu != self.cpu as u16 { return false; }

        if self.ip_min != 0 || self.ip_max != 0 {
            if event.ip < self.ip_min || event.ip > self.ip_max { return false; }
        }

        if self.ts_min != 0 && event.timestamp_ns < self.ts_min { return false; }

        if self.flags_mask != 0 {
            if event.flags & self.flags_mask != self.flags_value { return false; }
        }

        true
    }
}

// ─────────────────── Kprobe Definition ──────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct Kprobe {
    /// Probe ID
    pub id: u32,
    /// Address to probe
    pub addr: u64,
    /// Original instruction bytes (for restoration)
    pub saved_insn: [u8; 16],
    pub saved_len: u8,
    /// Is this probe active?
    pub active: bool,
    /// Is this a return probe?
    pub is_retprobe: bool,
    /// Hit count
    pub hit_count: u64,
    /// Name
    pub name: [u8; MAX_TRACE_NAME],
    pub name_len: usize,
}

impl Kprobe {
    pub fn new(id: u32, addr: u64, is_retprobe: bool) -> Self {
        Self {
            id,
            addr,
            saved_insn: [0; 16],
            saved_len: 0,
            active: false,
            is_retprobe,
            hit_count: 0,
            name: [0; MAX_TRACE_NAME],
            name_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_TRACE_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn enable(&mut self) {
        self.active = true;
    }

    pub fn disable(&mut self) {
        self.active = false;
    }

    pub fn record_hit(&mut self) {
        self.hit_count += 1;
    }
}

// ─────────────────── Tracepoint ─────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct TracepointDef {
    pub id: u32,
    pub name: [u8; MAX_TRACE_NAME],
    pub name_len: usize,
    pub category: [u8; 32],
    pub category_len: usize,
    pub enabled: bool,
    pub hit_count: u64,
    pub arg_names: [[u8; 16]; MAX_TRACE_ARGS],
    pub arg_name_lens: [usize; MAX_TRACE_ARGS],
    pub arg_count: u8,
}

impl TracepointDef {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            name: [0; MAX_TRACE_NAME],
            name_len: 0,
            category: [0; 32],
            category_len: 0,
            enabled: false,
            hit_count: 0,
            arg_names: [[0; 16]; MAX_TRACE_ARGS],
            arg_name_lens: [0; MAX_TRACE_ARGS],
            arg_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_TRACE_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn set_category(&mut self, cat: &[u8]) {
        let len = cat.len().min(32);
        self.category[..len].copy_from_slice(&cat[..len]);
        self.category_len = len;
    }

    pub fn add_arg(&mut self, name: &[u8]) -> bool {
        if self.arg_count as usize >= MAX_TRACE_ARGS { return false; }
        let idx = self.arg_count as usize;
        let len = name.len().min(16);
        self.arg_names[idx][..len].copy_from_slice(&name[..len]);
        self.arg_name_lens[idx] = len;
        self.arg_count += 1;
        true
    }
}

// ─────────────────── Function Graph Tracer ──────────────────────────
/// Tracks function call depth for graph tracing output
pub struct FuncGraphTracer {
    /// Per-CPU call stacks
    stacks: [[u64; 256]; MAX_TRACE_CPUS],
    depths: [u8; MAX_TRACE_CPUS],
    /// Timing info for duration measurement
    entry_times: [[u64; 256]; MAX_TRACE_CPUS],
    /// Maximum depth to trace
    max_depth: u8,
    enabled: bool,
}

impl FuncGraphTracer {
    pub fn new() -> Self {
        Self {
            stacks: [[0; 256]; MAX_TRACE_CPUS],
            depths: [0; MAX_TRACE_CPUS],
            entry_times: [[0; 256]; MAX_TRACE_CPUS],
            max_depth: 32,
            enabled: false,
        }
    }

    pub fn push_entry(&mut self, cpu: usize, func_addr: u64, timestamp: u64) {
        if cpu >= MAX_TRACE_CPUS || !self.enabled { return; }
        let depth = self.depths[cpu] as usize;
        if depth >= 256 || depth as u8 >= self.max_depth { return; }
        self.stacks[cpu][depth] = func_addr;
        self.entry_times[cpu][depth] = timestamp;
        self.depths[cpu] += 1;
    }

    pub fn pop_exit(&mut self, cpu: usize, timestamp: u64) -> Option<(u64, u64)> {
        if cpu >= MAX_TRACE_CPUS || self.depths[cpu] == 0 { return None; }
        self.depths[cpu] -= 1;
        let depth = self.depths[cpu] as usize;
        let func_addr = self.stacks[cpu][depth];
        let duration = timestamp.saturating_sub(self.entry_times[cpu][depth]);
        Some((func_addr, duration))
    }

    pub fn current_depth(&self, cpu: usize) -> u8 {
        if cpu >= MAX_TRACE_CPUS { return 0; }
        self.depths[cpu]
    }

    pub fn enable(&mut self) { self.enabled = true; }
    pub fn disable(&mut self) { self.enabled = false; }
    pub fn set_max_depth(&mut self, depth: u8) { self.max_depth = depth; }
}

// ─────────────────── Trace Statistics ───────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct TraceStats {
    pub total_events: u64,
    pub total_overflows: u64,
    pub active_tracepoints: u32,
    pub active_kprobes: u32,
    pub enabled: bool,
    pub func_graph_enabled: bool,
    pub buffer_usage_percent: u8,
}

// ─────────────────── Main Tracer ────────────────────────────────────
pub struct KernelTracer {
    /// Per-CPU trace buffers
    buffers: [TraceBuffer; MAX_TRACE_CPUS],
    num_cpus: u32,
    /// Global enabled flag
    enabled: bool,
    /// Tracepoints
    tracepoints: [Option<TracepointDef>; MAX_TRACEPOINTS],
    tracepoint_count: usize,
    /// Kprobes
    kprobes: [Option<Kprobe>; MAX_KPROBES],
    kprobe_count: usize,
    /// Filters
    filters: [TraceFilter; MAX_TRACE_FILTERS],
    filter_count: usize,
    /// Function graph tracer
    func_graph: FuncGraphTracer,
    /// Next IDs
    next_tracepoint_id: u32,
    next_kprobe_id: u32,
    /// Statistics
    total_events_recorded: u64,
    total_events_dropped: u64,
}

impl KernelTracer {
    pub fn new(num_cpus: u32) -> Self {
        Self {
            buffers: core::array::from_fn(|i| TraceBuffer::new(i as u16)),
            num_cpus,
            enabled: false,
            tracepoints: [const { None }; MAX_TRACEPOINTS],
            tracepoint_count: 0,
            kprobes: [const { None }; MAX_KPROBES],
            kprobe_count: 0,
            filters: [TraceFilter::default(); MAX_TRACE_FILTERS],
            filter_count: 0,
            func_graph: FuncGraphTracer::new(),
            next_tracepoint_id: 1,
            next_kprobe_id: 1,
            total_events_recorded: 0,
            total_events_dropped: 0,
        }
    }

    /// Enable tracing globally
    pub fn enable(&mut self) {
        self.enabled = true;
        for i in 0..self.num_cpus as usize {
            if i < MAX_TRACE_CPUS {
                self.buffers[i].enable();
            }
        }
    }

    /// Disable tracing globally
    pub fn disable(&mut self) {
        self.enabled = false;
        for i in 0..self.num_cpus as usize {
            if i < MAX_TRACE_CPUS {
                self.buffers[i].disable();
            }
        }
    }

    /// Record a trace event
    pub fn record(&mut self, event: TraceEvent) {
        if !self.enabled { return; }

        // Apply filters
        for filter in &self.filters[..self.filter_count] {
            if !filter.matches(&event) {
                self.total_events_dropped += 1;
                return;
            }
        }

        let cpu = event.cpu as usize;
        if cpu < MAX_TRACE_CPUS {
            if self.buffers[cpu].push(event) {
                self.total_events_recorded += 1;
            } else {
                self.total_events_dropped += 1;
            }
        }
    }

    /// Record function entry
    pub fn trace_func_entry(&mut self, ip: u64, parent_ip: u64, pid: u32, cpu: u16, ts: u64) {
        let depth = self.func_graph.current_depth(cpu as usize);
        self.func_graph.push_entry(cpu as usize, ip, ts);

        let mut event = TraceEvent::func_entry(ip, parent_ip, pid, cpu, ts);
        event.depth = depth;
        self.record(event);
    }

    /// Record function exit
    pub fn trace_func_exit(&mut self, ip: u64, ret_val: u64, pid: u32, cpu: u16, ts: u64) {
        if let Some((_addr, duration)) = self.func_graph.pop_exit(cpu as usize, ts) {
            let mut event = TraceEvent::func_exit(ip, ret_val, pid, cpu, ts);
            event.args[1] = duration;
            event.arg_count = 2;
            event.depth = self.func_graph.current_depth(cpu as usize);
            self.record(event);
        }
    }

    /// Register a tracepoint
    pub fn register_tracepoint(&mut self, name: &[u8], category: &[u8]) -> Option<u32> {
        if self.tracepoint_count >= MAX_TRACEPOINTS { return None; }

        let id = self.next_tracepoint_id;
        self.next_tracepoint_id += 1;

        let mut tp = TracepointDef::new(id);
        tp.set_name(name);
        tp.set_category(category);

        for slot in self.tracepoints.iter_mut() {
            if slot.is_none() {
                *slot = Some(tp);
                self.tracepoint_count += 1;
                return Some(id);
            }
        }
        None
    }

    /// Enable a tracepoint by ID
    pub fn enable_tracepoint(&mut self, id: u32) -> bool {
        for slot in self.tracepoints.iter_mut() {
            if let Some(tp) = slot {
                if tp.id == id {
                    tp.enabled = true;
                    return true;
                }
            }
        }
        false
    }

    /// Register a kprobe
    pub fn register_kprobe(&mut self, addr: u64, name: &[u8], is_retprobe: bool) -> Option<u32> {
        if self.kprobe_count >= MAX_KPROBES { return None; }

        let id = self.next_kprobe_id;
        self.next_kprobe_id += 1;

        let mut kp = Kprobe::new(id, addr, is_retprobe);
        kp.set_name(name);

        for slot in self.kprobes.iter_mut() {
            if slot.is_none() {
                *slot = Some(kp);
                self.kprobe_count += 1;
                return Some(id);
            }
        }
        None
    }

    /// Enable a kprobe
    pub fn enable_kprobe(&mut self, id: u32) -> bool {
        for slot in self.kprobes.iter_mut() {
            if let Some(kp) = slot {
                if kp.id == id {
                    kp.enable();
                    return true;
                }
            }
        }
        false
    }

    /// Add a trace filter
    pub fn add_filter(&mut self, filter: TraceFilter) -> bool {
        if self.filter_count >= MAX_TRACE_FILTERS { return false; }
        self.filters[self.filter_count] = filter;
        self.filter_count += 1;
        true
    }

    /// Clear all filters
    pub fn clear_filters(&mut self) {
        self.filter_count = 0;
    }

    /// Clear all trace buffers
    pub fn clear_buffers(&mut self) {
        for i in 0..self.num_cpus as usize {
            if i < MAX_TRACE_CPUS {
                self.buffers[i].clear();
            }
        }
    }

    /// Enable function graph tracing
    pub fn enable_func_graph(&mut self) {
        self.func_graph.enable();
    }

    /// Get statistics
    pub fn stats(&self) -> TraceStats {
        let mut total_events = 0u64;
        let mut total_overflows = 0u64;
        let mut total_count = 0usize;
        let mut total_capacity = 0usize;

        for i in 0..self.num_cpus as usize {
            if i < MAX_TRACE_CPUS {
                total_events += self.buffers[i].total_events();
                total_overflows += self.buffers[i].overflows();
                total_count += self.buffers[i].count();
                total_capacity += TRACE_BUFFER_SIZE;
            }
        }

        let usage = if total_capacity > 0 {
            ((total_count * 100) / total_capacity) as u8
        } else {
            0
        };

        TraceStats {
            total_events,
            total_overflows,
            active_tracepoints: self.tracepoint_count as u32,
            active_kprobes: self.kprobe_count as u32,
            enabled: self.enabled,
            func_graph_enabled: self.func_graph.enabled,
            buffer_usage_percent: usage,
        }
    }

    /// Drain events from a specific CPU buffer
    pub fn drain_cpu(&mut self, cpu: usize, out: &mut [TraceEvent]) -> usize {
        if cpu >= MAX_TRACE_CPUS { return 0; }
        self.buffers[cpu].drain(out)
    }
}

// ─────────────────── Global Instance ────────────────────────────────
static mut KERNEL_TRACER: Option<KernelTracer> = None;

pub fn init(num_cpus: u32) {
    unsafe {
        KERNEL_TRACER = Some(KernelTracer::new(num_cpus));
    }
}

pub fn get_tracer() -> Option<&'static mut KernelTracer> {
    unsafe { KERNEL_TRACER.as_mut() }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_trace_init(num_cpus: u32) {
    init(num_cpus);
}

#[no_mangle]
pub extern "C" fn rust_trace_enable() {
    if let Some(t) = get_tracer() { t.enable(); }
}

#[no_mangle]
pub extern "C" fn rust_trace_disable() {
    if let Some(t) = get_tracer() { t.disable(); }
}

#[no_mangle]
pub extern "C" fn rust_trace_func_entry(ip: u64, parent_ip: u64, pid: u32, cpu: u16, ts: u64) {
    if let Some(t) = get_tracer() {
        t.trace_func_entry(ip, parent_ip, pid, cpu, ts);
    }
}

#[no_mangle]
pub extern "C" fn rust_trace_func_exit(ip: u64, ret_val: u64, pid: u32, cpu: u16, ts: u64) {
    if let Some(t) = get_tracer() {
        t.trace_func_exit(ip, ret_val, pid, cpu, ts);
    }
}

#[no_mangle]
pub extern "C" fn rust_trace_record_event(
    event_type: u32,
    cpu: u16,
    pid: u32,
    ip: u64,
    ts: u64,
    arg0: u64,
    arg1: u64,
) {
    if let Some(t) = get_tracer() {
        let etype = match event_type {
            6 => TraceEventType::SchedSwitch,
            7 => TraceEventType::IrqEntry,
            8 => TraceEventType::IrqExit,
            12 => TraceEventType::SyscallEntry,
            13 => TraceEventType::SyscallExit,
            15 => TraceEventType::MemAlloc,
            16 => TraceEventType::MemFree,
            _ => TraceEventType::Custom,
        };

        let mut event = TraceEvent::default();
        event.event_type = etype;
        event.cpu = cpu;
        event.pid = pid;
        event.tid = pid;
        event.ip = ip;
        event.timestamp_ns = ts;
        event.args[0] = arg0;
        event.args[1] = arg1;
        event.arg_count = 2;

        t.record(event);
    }
}

#[no_mangle]
pub extern "C" fn rust_trace_register_kprobe(addr: u64, name: *const u8, name_len: u32, is_ret: bool) -> i32 {
    let Some(t) = get_tracer() else { return -1 };
    let name_slice = if name.is_null() || name_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(name, name_len as usize) }
    };
    match t.register_kprobe(addr, name_slice, is_ret) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_trace_clear_buffers() {
    if let Some(t) = get_tracer() { t.clear_buffers(); }
}
