// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Logging and Tracing (Rust)
// printk, ftrace, perf events, kprobes, tracepoints, BPF trace

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// printk / Kernel Log Levels
// ============================================================================

pub const KERN_EMERG: u8 = 0;      // System is unusable
pub const KERN_ALERT: u8 = 1;      // Action must be taken immediately
pub const KERN_CRIT: u8 = 2;       // Critical conditions
pub const KERN_ERR: u8 = 3;        // Error conditions
pub const KERN_WARNING: u8 = 4;    // Warning conditions
pub const KERN_NOTICE: u8 = 5;     // Normal but significant
pub const KERN_INFO: u8 = 6;       // Informational
pub const KERN_DEBUG: u8 = 7;      // Debug-level messages
pub const KERN_DEFAULT: u8 = 4;    // Default level
pub const KERN_CONT: u8 = 8;       // Continuation of previous line

pub const LOG_BUF_SIZE: usize = 1 << 17;  // 128KB ring buffer

pub struct PrintkRecord {
    pub timestamp: u64,      // Nanosecond timestamp
    pub level: u8,
    pub facility: u8,        // LOG_KERN, LOG_USER, etc.
    pub flags: u16,
    pub text_len: u16,
    pub dict_len: u16,       // Key=value dictionary
    pub caller_id: u32,      // Task PID or CPU ID
    pub text: [u8; 1024],
    pub dict: [u8; 256],
}

pub struct LogBuffer {
    pub buf: [u8; LOG_BUF_SIZE],
    pub head: AtomicU64,
    pub tail: AtomicU64,
    pub seq: AtomicU64,      // Message sequence number
    pub first_seq: u64,      // Oldest message seq
    pub console_seq: u64,    // Next to print to console
    pub syslog_seq: u64,     // Next to read from /dev/kmsg
    // Rate limiting
    pub ratelimit_state: RateLimitState,
}

pub struct RateLimitState {
    pub interval_ms: u32,
    pub burst: u32,
    pub printed: AtomicU32,
    pub missed: AtomicU32,
    pub begin: AtomicU64,
}

impl RateLimitState {
    pub fn allow(&self, now: u64) -> bool {
        let begin = self.begin.load(Ordering::Relaxed);
        let interval_ns = self.interval_ms as u64 * 1_000_000;
        
        if now.wrapping_sub(begin) > interval_ns {
            // New interval
            self.printed.store(1, Ordering::Relaxed);
            self.missed.store(0, Ordering::Relaxed);
            self.begin.store(now, Ordering::Relaxed);
            return true;
        }
        
        let printed = self.printed.fetch_add(1, Ordering::Relaxed);
        if printed < self.burst {
            true
        } else {
            self.missed.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

// Syslog facilities (RFC 5424)
pub const LOG_KERN: u8 = 0;
pub const LOG_USER: u8 = 1;
pub const LOG_MAIL: u8 = 2;
pub const LOG_DAEMON: u8 = 3;
pub const LOG_AUTH: u8 = 4;
pub const LOG_SYSLOG: u8 = 5;
pub const LOG_LPR: u8 = 6;
pub const LOG_NEWS: u8 = 7;
pub const LOG_UUCP: u8 = 8;
pub const LOG_CRON: u8 = 9;
pub const LOG_AUTHPRIV: u8 = 10;
pub const LOG_FTP: u8 = 11;
pub const LOG_LOCAL0: u8 = 16;
pub const LOG_LOCAL7: u8 = 23;

// ============================================================================
// ftrace (Function Tracer)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TracerType {
    Nop,
    Function,
    FunctionGraph,
    Irqsoff,
    PreemptOff,
    PreemptIrqsOff,
    Wakeup,
    WakeupRt,
    WakeupDl,
    Mmiotrace,
    Blk,
    Hwlat,
    Osnoise,
    Timerlat,
}

pub struct FtraceEvent {
    pub timestamp: u64,       // TSC or monotonic ns
    pub pid: i32,
    pub cpu: u16,
    pub flags: u16,
    pub preempt_count: u8,
    pub event_type: FtraceEventType,
    pub data: FtraceEventData,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FtraceEventType {
    FuncEntry,
    FuncReturn,
    FuncGraphEntry,
    FuncGraphReturn,
    Wakeup,
    ContextSwitch,
    Irq,
    SoftIrq,
    Sched,
    Syscall,
    Print,
    UserStack,
    KernelStack,
    Bpf,
}

#[derive(Clone, Copy)]
pub union FtraceEventData {
    pub func: FuncTraceEntry,
    pub func_graph: FuncGraphEntry,
    pub sched_switch: SchedSwitchEntry,
    pub irq: IrqEntry,
    pub print: PrintEntry,
}

#[derive(Clone, Copy)]
pub struct FuncTraceEntry {
    pub ip: u64,              // Instruction pointer
    pub parent_ip: u64,       // Caller
}

#[derive(Clone, Copy)]
pub struct FuncGraphEntry {
    pub func: u64,
    pub depth: u32,
    pub duration_ns: u64,     // For return events
    pub overrun: u32,
}

#[derive(Clone, Copy)]
pub struct SchedSwitchEntry {
    pub prev_pid: i32,
    pub prev_prio: i32,
    pub prev_state: u32,
    pub next_pid: i32,
    pub next_prio: i32,
}

#[derive(Clone, Copy)]
pub struct IrqEntry {
    pub irq: u32,
    pub handler: u64,
    pub name_hash: u32,
    pub is_softirq: bool,
}

#[derive(Clone, Copy)]
pub struct PrintEntry {
    pub buf: [u8; 256],
    pub len: u32,
}

pub struct TraceBuffer {
    pub entries: [FtraceEvent; 8192],
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub overrun: AtomicU64,
    pub entries_count: AtomicU64,
    pub cpu: u32,
}

pub struct FtraceInstance {
    pub name: [u8; 64],
    pub name_len: u8,
    pub current_tracer: TracerType,
    pub enabled: AtomicBool,
    pub per_cpu_buffers: [TraceBuffer; 64],
    pub nr_cpus: u32,
    pub buffer_size_kb: u32,
    pub trace_clock: TraceClock,
    // Filters
    pub pid_filter: [i32; 256],
    pub pid_filter_count: u32,
    pub func_filter: [u64; 512],   // Function addresses to trace
    pub func_filter_count: u32,
    pub func_notrace: [u64; 512],  // Functions to skip
    pub func_notrace_count: u32,
    // Options
    pub options: TraceOptions,
    // Stats
    pub events_lost: AtomicU64,
    pub commit_overrun: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TraceClock {
    Local,          // Per-CPU monotonic
    Global,         // Global monotonic (slower, synchronized)
    Counter,        // Simple counter
    Uptime,         // Jiffies
    Perf,           // perf_clock
    Mono,           // ktime_get_mono_fast_ns
    MonoRaw,        // ktime_get_raw_fast_ns
    Boot,           // ktime_get_boot_fast_ns
    Tai,            // TAI clock
    X86Tsc,         // Raw TSC
}

pub struct TraceOptions {
    pub print_parent: bool,
    pub sym_offset: bool,
    pub sym_addr: bool,
    pub verbose: bool,
    pub raw: bool,
    pub hex: bool,
    pub bin: bool,
    pub block: bool,
    pub trace_printk: bool,
    pub annotate: bool,
    pub userstacktrace: bool,
    pub sym_userobj: bool,
    pub printk_msgonly: bool,
    pub context_info: bool,
    pub latency_format: bool,
    pub record_cmd: bool,
    pub record_tgid: bool,
    pub overwrite: bool,
    pub disable_on_free: bool,
    pub irq_info: bool,
    pub markers: bool,
    pub event_fork: bool,
    pub pause_on_trace: bool,
    pub hash_ptr: bool,
    pub func_stacktrace: bool,
}

// ============================================================================
// Perf Events
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum PerfType {
    Hardware = 0,
    Software = 1,
    Tracepoint = 2,
    HwCache = 3,
    Raw = 4,
    Breakpoint = 5,
}

// Hardware events
pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
pub const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
pub const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
pub const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
pub const PERF_COUNT_HW_BUS_CYCLES: u64 = 6;
pub const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
pub const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;
pub const PERF_COUNT_HW_REF_CPU_CYCLES: u64 = 9;

// Software events
pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
pub const PERF_COUNT_SW_PAGE_FAULTS: u64 = 2;
pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
pub const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;
pub const PERF_COUNT_SW_PAGE_FAULTS_MIN: u64 = 5;
pub const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u64 = 6;
pub const PERF_COUNT_SW_ALIGNMENT_FAULTS: u64 = 7;
pub const PERF_COUNT_SW_EMULATION_FAULTS: u64 = 8;
pub const PERF_COUNT_SW_DUMMY: u64 = 9;
pub const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
pub const PERF_COUNT_SW_CGROUP_SWITCHES: u64 = 11;

// Cache types
pub const PERF_COUNT_HW_CACHE_L1D: u64 = 0;
pub const PERF_COUNT_HW_CACHE_L1I: u64 = 1;
pub const PERF_COUNT_HW_CACHE_LL: u64 = 2;
pub const PERF_COUNT_HW_CACHE_DTLB: u64 = 3;
pub const PERF_COUNT_HW_CACHE_ITLB: u64 = 4;
pub const PERF_COUNT_HW_CACHE_BPU: u64 = 5;
pub const PERF_COUNT_HW_CACHE_NODE: u64 = 6;

// Cache operations
pub const PERF_COUNT_HW_CACHE_OP_READ: u64 = 0;
pub const PERF_COUNT_HW_CACHE_OP_WRITE: u64 = 1;
pub const PERF_COUNT_HW_CACHE_OP_PREFETCH: u64 = 2;

// Cache results
pub const PERF_COUNT_HW_CACHE_RESULT_ACCESS: u64 = 0;
pub const PERF_COUNT_HW_CACHE_RESULT_MISS: u64 = 1;

pub struct PerfEventAttr {
    pub event_type: PerfType,
    pub config: u64,
    pub sample_period_or_freq: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup_events_or_watermark: u32,
    pub bp_type: u32,
    pub bp_addr_or_kprobe_func: u64,
    pub bp_len_or_kprobe_addr: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub sig_data: u64,
}

// perf_event_attr.sample_type bits
pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
pub const PERF_SAMPLE_READ: u64 = 1 << 4;
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;
pub const PERF_SAMPLE_STREAM_ID: u64 = 1 << 9;
pub const PERF_SAMPLE_RAW: u64 = 1 << 10;
pub const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;
pub const PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
pub const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;
pub const PERF_SAMPLE_WEIGHT: u64 = 1 << 14;
pub const PERF_SAMPLE_DATA_SRC: u64 = 1 << 15;
pub const PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;
pub const PERF_SAMPLE_TRANSACTION: u64 = 1 << 17;
pub const PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
pub const PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
pub const PERF_SAMPLE_AUX: u64 = 1 << 20;
pub const PERF_SAMPLE_CGROUP: u64 = 1 << 21;
pub const PERF_SAMPLE_DATA_PAGE_SIZE: u64 = 1 << 22;
pub const PERF_SAMPLE_CODE_PAGE_SIZE: u64 = 1 << 23;
pub const PERF_SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;

pub struct PerfEvent {
    pub attr: PerfEventAttr,
    pub id: u64,
    pub cpu: i32,
    pub pid: i32,
    pub group_leader_id: u64,
    pub state: PerfEventState,
    pub count: AtomicU64,
    pub total_time_enabled: AtomicU64,
    pub total_time_running: AtomicU64,
    pub child_count: AtomicU64,
    pub child_total_time_enabled: AtomicU64,
    pub child_total_time_running: AtomicU64,
    pub overflow_count: AtomicU64,
    // Ring buffer (mmap)
    pub rb_pages: u32,
    pub rb_head: AtomicU64,
    pub aux_head: AtomicU64,
    pub aux_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PerfEventState {
    Error = -2,
    Off = -1,
    Inactive = 0,
    Active = 1,
    Exit = 2,
    Revoked = 3,
}

// ============================================================================
// Kprobes / Uprobes
// ============================================================================

pub struct Kprobe {
    pub addr: u64,                    // Probed address
    pub symbol: [u8; 64],            // Function name
    pub symbol_len: u8,
    pub offset: u32,                  // Offset within function
    pub pre_handler_id: u64,
    pub post_handler_id: u64,
    pub fault_handler_id: u64,
    pub flags: u32,
    pub nmissed: AtomicU64,
    pub nhit: AtomicU64,
    pub enabled: AtomicBool,
    pub saved_opcode: [u8; 16],      // Saved instruction bytes
    pub saved_len: u8,
}

pub const KPROBE_FLAG_GONE: u32 = 1;
pub const KPROBE_FLAG_DISABLED: u32 = 2;
pub const KPROBE_FLAG_OPTIMIZED: u32 = 4;
pub const KPROBE_FLAG_FTRACE: u32 = 8;

pub struct KretprobeInstance {
    pub rp_addr: u64,
    pub ret_addr: u64,
    pub entry_handler_id: u64,
    pub handler_id: u64,
    pub task_pid: i32,
    pub entry_timestamp: u64,
}

pub struct Uprobe {
    pub inode: u64,                   // File inode
    pub offset: u64,                  // Offset in file
    pub ref_ctr_offset: u64,         // Reference counter offset (SDT)
    pub consumer_count: AtomicU32,
    pub nhit: AtomicU64,
    pub flags: u32,
}

// ============================================================================
// Tracepoints
// ============================================================================

pub struct TracepointDesc {
    pub name: [u8; 128],
    pub name_len: u8,
    pub system: [u8; 64],    // Subsystem name
    pub system_len: u8,
    pub id: u32,              // Unique tracepoint ID
    pub enabled: AtomicBool,
    pub regfunc_id: u64,
    pub unregfunc_id: u64,
    pub nr_callbacks: AtomicU32,
}

// Standard kernel tracepoints
pub const TP_SCHED_SWITCH: u32 = 1;
pub const TP_SCHED_WAKEUP: u32 = 2;
pub const TP_SCHED_WAKEUP_NEW: u32 = 3;
pub const TP_SCHED_MIGRATE_TASK: u32 = 4;
pub const TP_SCHED_PROCESS_EXIT: u32 = 5;
pub const TP_SCHED_PROCESS_FORK: u32 = 6;
pub const TP_SCHED_PROCESS_EXEC: u32 = 7;
pub const TP_SCHED_PROCESS_WAIT: u32 = 8;
pub const TP_IRQ_HANDLER_ENTRY: u32 = 10;
pub const TP_IRQ_HANDLER_EXIT: u32 = 11;
pub const TP_SOFTIRQ_ENTRY: u32 = 12;
pub const TP_SOFTIRQ_EXIT: u32 = 13;
pub const TP_SOFTIRQ_RAISE: u32 = 14;
pub const TP_TIMER_INIT: u32 = 20;
pub const TP_TIMER_START: u32 = 21;
pub const TP_TIMER_EXPIRE_ENTRY: u32 = 22;
pub const TP_TIMER_EXPIRE_EXIT: u32 = 23;
pub const TP_TIMER_CANCEL: u32 = 24;
pub const TP_HRTIMER_INIT: u32 = 25;
pub const TP_HRTIMER_START: u32 = 26;
pub const TP_HRTIMER_EXPIRE_ENTRY: u32 = 27;
pub const TP_HRTIMER_EXPIRE_EXIT: u32 = 28;
pub const TP_HRTIMER_CANCEL: u32 = 29;
pub const TP_WORKQUEUE_QUEUE_WORK: u32 = 30;
pub const TP_WORKQUEUE_ACTIVATE_WORK: u32 = 31;
pub const TP_WORKQUEUE_EXECUTE_START: u32 = 32;
pub const TP_WORKQUEUE_EXECUTE_END: u32 = 33;
pub const TP_MM_PAGE_ALLOC: u32 = 40;
pub const TP_MM_PAGE_FREE: u32 = 41;
pub const TP_MM_PAGE_ALLOC_ZONE_LOCKED: u32 = 42;
pub const TP_MM_PAGE_PCPU_DRAIN: u32 = 43;
pub const TP_MM_PAGE_ALLOC_EXTFRAG: u32 = 44;
pub const TP_KMALLOC: u32 = 45;
pub const TP_KFREE: u32 = 46;
pub const TP_KMEM_CACHE_ALLOC: u32 = 47;
pub const TP_KMEM_CACHE_FREE: u32 = 48;
pub const TP_MM_FILEMAP_ADD_TO_PAGE_CACHE: u32 = 49;
pub const TP_MM_FILEMAP_DELETE_FROM_PAGE_CACHE: u32 = 50;
pub const TP_BLOCK_RQ_INSERT: u32 = 60;
pub const TP_BLOCK_RQ_ISSUE: u32 = 61;
pub const TP_BLOCK_RQ_COMPLETE: u32 = 62;
pub const TP_BLOCK_BIO_QUEUE: u32 = 63;
pub const TP_BLOCK_BIO_FRONTMERGE: u32 = 64;
pub const TP_BLOCK_BIO_BACKMERGE: u32 = 65;
pub const TP_NET_DEV_QUEUE: u32 = 70;
pub const TP_NETIF_RECEIVE_SKB: u32 = 71;
pub const TP_NETIF_RX: u32 = 72;
pub const TP_NAPI_POLL: u32 = 73;
pub const TP_SOCK_SENDMSG: u32 = 74;
pub const TP_SOCK_RECVMSG: u32 = 75;
pub const TP_TCP_SENDMSG: u32 = 76;
pub const TP_TCP_RETRANSMIT_SKB: u32 = 77;
pub const TP_TCP_PROBE: u32 = 78;
pub const TP_SYSCALL_ENTER: u32 = 80;
pub const TP_SYSCALL_EXIT: u32 = 81;
pub const TP_SIGNAL_GENERATE: u32 = 90;
pub const TP_SIGNAL_DELIVER: u32 = 91;
pub const TP_TASK_NEWTASK: u32 = 100;
pub const TP_TASK_RENAME: u32 = 101;

// ============================================================================
// BPF Tracing
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfProgType {
    Unspec = 0,
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
    CgroupSysctl = 23,
    RawTracepointWritable = 24,
    CgroupSockopt = 25,
    Tracing = 26,
    StructOps = 27,
    Ext = 28,
    Lsm = 29,
    SkLookup = 30,
    Syscall = 31,
    Netfilter = 32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfMapType {
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    CgroupStorage = 19,
    ReuseportSockarray = 20,
    PercpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevmapHash = 25,
    StructOps = 26,
    RingBuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingBuf = 31,
    CgrpStorage = 32,
    Arena = 33,
}

pub struct BpfProg {
    pub prog_type: BpfProgType,
    pub attach_type: u32,
    pub id: u32,
    pub name: [u8; 16],
    pub name_len: u8,
    pub license_gpl: bool,
    pub insn_cnt: u32,
    pub jited: bool,
    pub jited_len: u32,
    pub tag: [u8; 8],       // SHA-1 hash of instructions
    pub run_time_ns: AtomicU64,
    pub run_cnt: AtomicU64,
    pub recursion_misses: AtomicU64,
    pub verified_insns: u32,
    pub loaded_at: u64,
    pub created_by_uid: u32,
    pub nr_maps: u32,
    pub map_ids: [u32; 64],
    pub btf_id: u32,         // BTF type info
}

pub struct BpfMap {
    pub map_type: BpfMapType,
    pub id: u32,
    pub name: [u8; 16],
    pub name_len: u8,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub numa_node: i32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub frozen: bool,
    pub memory_usage: AtomicU64,
}

// BPF helper functions IDs (subset)
pub const BPF_FUNC_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_FUNC_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_FUNC_MAP_DELETE_ELEM: u32 = 3;
pub const BPF_FUNC_PROBE_READ: u32 = 4;
pub const BPF_FUNC_KTIME_GET_NS: u32 = 5;
pub const BPF_FUNC_TRACE_PRINTK: u32 = 6;
pub const BPF_FUNC_GET_PRANDOM_U32: u32 = 7;
pub const BPF_FUNC_GET_SMP_PROCESSOR_ID: u32 = 8;
pub const BPF_FUNC_SKBUFF_STORE_BYTES: u32 = 9;
pub const BPF_FUNC_PERF_EVENT_OUTPUT: u32 = 25;
pub const BPF_FUNC_GET_STACKID: u32 = 27;
pub const BPF_FUNC_GET_CURRENT_PID_TGID: u32 = 14;
pub const BPF_FUNC_GET_CURRENT_UID_GID: u32 = 15;
pub const BPF_FUNC_GET_CURRENT_COMM: u32 = 16;
pub const BPF_FUNC_RINGBUF_OUTPUT: u32 = 130;
pub const BPF_FUNC_RINGBUF_RESERVE: u32 = 131;
pub const BPF_FUNC_RINGBUF_SUBMIT: u32 = 132;
pub const BPF_FUNC_RINGBUF_DISCARD: u32 = 133;
pub const BPF_FUNC_RINGBUF_QUERY: u32 = 134;
pub const BPF_FUNC_GET_FUNC_IP: u32 = 173;
pub const BPF_FUNC_GET_ATTACH_COOKIE: u32 = 174;
pub const BPF_FUNC_TASK_PT_REGS: u32 = 175;

// ============================================================================
// Kernel Profiling
// ============================================================================

pub struct CpuProfile {
    pub cpu: u32,
    pub sample_count: AtomicU64,
    pub ip_histogram: [IpSample; 4096],
    pub histogram_size: u32,
    pub sample_period_ns: u64,
}

pub struct IpSample {
    pub ip: u64,
    pub count: AtomicU64,
    pub pid: i32,
    pub comm_hash: u32,
}

pub struct StackProfile {
    pub max_depth: u32,
    pub entries: [StackEntry; 1024],
    pub entry_count: AtomicU32,
}

pub struct StackEntry {
    pub stack: [u64; 128],    // Stack frame addresses
    pub depth: u32,
    pub count: AtomicU64,
    pub pid: i32,
    pub kernel: bool,
}

// ============================================================================
// Dynamic Debug
// ============================================================================

pub struct DynamicDebugEntry {
    pub module: [u8; 56],
    pub module_len: u8,
    pub function: [u8; 64],
    pub function_len: u8,
    pub filename: [u8; 128],
    pub filename_len: u8,
    pub lineno: u32,
    pub flags: u32,
    pub format: [u8; 256],
    pub format_len: u16,
}

pub const DYNDBG_FLAGS_PRINT: u32 = 1 << 0;
pub const DYNDBG_FLAGS_FUNCNAME: u32 = 1 << 1;
pub const DYNDBG_FLAGS_LINENO: u32 = 1 << 2;
pub const DYNDBG_FLAGS_MODULE: u32 = 1 << 3;
pub const DYNDBG_FLAGS_ENABLED: u32 = 1 << 4;

pub struct DynamicDebugTable {
    pub entries: [DynamicDebugEntry; 2048],
    pub count: u32,
    pub verbose: u32,
}
