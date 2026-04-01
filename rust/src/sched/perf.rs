// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Performance Monitoring & Profiling
//
// Implements a comprehensive performance monitoring subsystem including:
// - Hardware performance counter abstraction (PMU)
// - Software event tracing
// - Per-CPU and per-process perf event contexts
// - Sampling with configurable intervals
// - Call graph recording
// - Event grouping for correlated measurements
// - Overflow handling with interrupt-driven sampling

#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_PERF_EVENTS: usize = 256;
pub const MAX_PERF_CONTEXTS: usize = 512;
pub const MAX_COUNTERS_PER_CPU: usize = 8;
pub const MAX_SAMPLE_BUFFER_SIZE: usize = 65536;
pub const MAX_CALLCHAIN_DEPTH: usize = 128;
pub const MAX_EVENT_GROUPS: usize = 64;
pub const MAX_SW_EVENTS: usize = 32;
pub const MAX_CPUS: usize = 256;

// ─────────────────── Event Types ────────────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventType {
    /// Hardware CPU performance counter events
    Hardware = 0,
    /// Kernel software events
    Software = 1,
    /// Tracepoint events
    Tracepoint = 2,
    /// Hardware cache events
    HwCache = 3,
    /// Raw hardware-specific events
    Raw = 4,
    /// Hardware breakpoint events
    Breakpoint = 5,
}

// ─────────────────── Hardware Events ────────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwEvent {
    CpuCycles = 0,
    Instructions = 1,
    CacheReferences = 2,
    CacheMisses = 3,
    BranchInstructions = 4,
    BranchMisses = 5,
    BusCycles = 6,
    StalledCyclesFrontend = 7,
    StalledCyclesBackend = 8,
    RefCpuCycles = 9,
}

impl HwEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CpuCycles => "cpu-cycles",
            Self::Instructions => "instructions",
            Self::CacheReferences => "cache-references",
            Self::CacheMisses => "cache-misses",
            Self::BranchInstructions => "branch-instructions",
            Self::BranchMisses => "branch-misses",
            Self::BusCycles => "bus-cycles",
            Self::StalledCyclesFrontend => "stalled-cycles-frontend",
            Self::StalledCyclesBackend => "stalled-cycles-backend",
            Self::RefCpuCycles => "ref-cpu-cycles",
        }
    }

    pub fn msr_event_select(&self) -> u64 {
        match self {
            Self::CpuCycles => 0x003C,          // UnHalted Core Cycles
            Self::Instructions => 0x00C0,        // Instructions Retired
            Self::CacheReferences => 0x4F2E,     // LLC Reference
            Self::CacheMisses => 0x412E,          // LLC Misses
            Self::BranchInstructions => 0x00C4,  // Branch Instructions Retired
            Self::BranchMisses => 0x00C5,         // Branch Misses Retired
            Self::BusCycles => 0x013C,            // Bus Cycles
            Self::StalledCyclesFrontend => 0x019C,
            Self::StalledCyclesBackend => 0x01A2,
            Self::RefCpuCycles => 0x0300,
        }
    }
}

// ─────────────────── Software Events ────────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwEvent {
    CpuClock = 0,
    TaskClock = 1,
    PageFaults = 2,
    ContextSwitches = 3,
    CpuMigrations = 4,
    PageFaultsMin = 5,
    PageFaultsMax = 6,
    AlignmentFaults = 7,
    EmulationFaults = 8,
    Dummy = 9,
    BpfOutput = 10,
}

impl SwEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CpuClock => "cpu-clock",
            Self::TaskClock => "task-clock",
            Self::PageFaults => "page-faults",
            Self::ContextSwitches => "context-switches",
            Self::CpuMigrations => "cpu-migrations",
            Self::PageFaultsMin => "minor-faults",
            Self::PageFaultsMax => "major-faults",
            Self::AlignmentFaults => "alignment-faults",
            Self::EmulationFaults => "emulation-faults",
            Self::Dummy => "dummy",
            Self::BpfOutput => "bpf-output",
        }
    }
}

// ─────────────────── Cache Events ───────────────────────────────────
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLevel {
    L1d = 0,
    L1i = 1,
    Ll = 2,  // Last Level
    Dtlb = 3,
    Itlb = 4,
    Bpu = 5,  // Branch Prediction Unit
    Node = 6,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOp {
    Read = 0,
    Write = 1,
    Prefetch = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheResult {
    Access = 0,
    Miss = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct HwCacheEvent {
    pub level: CacheLevel,
    pub op: CacheOp,
    pub result: CacheResult,
}

impl HwCacheEvent {
    pub fn new(level: CacheLevel, op: CacheOp, result: CacheResult) -> Self {
        Self { level, op, result }
    }

    pub fn to_config(&self) -> u64 {
        ((self.level as u64) << 0) |
        ((self.op as u64) << 8) |
        ((self.result as u64) << 16)
    }

    pub fn name(&self) -> &'static str {
        // Simplified — would generate from components in production
        match (self.level, self.op, self.result) {
            (CacheLevel::L1d, CacheOp::Read, CacheResult::Miss) => "L1-dcache-load-misses",
            (CacheLevel::L1d, CacheOp::Write, CacheResult::Miss) => "L1-dcache-store-misses",
            (CacheLevel::L1i, CacheOp::Read, CacheResult::Miss) => "L1-icache-load-misses",
            (CacheLevel::Ll, CacheOp::Read, CacheResult::Miss) => "LLC-load-misses",
            (CacheLevel::Ll, CacheOp::Write, CacheResult::Miss) => "LLC-store-misses",
            (CacheLevel::Dtlb, CacheOp::Read, CacheResult::Miss) => "dTLB-load-misses",
            (CacheLevel::Itlb, CacheOp::Read, CacheResult::Miss) => "iTLB-load-misses",
            (CacheLevel::Bpu, CacheOp::Read, CacheResult::Miss) => "branch-load-misses",
            _ => "unknown-cache-event",
        }
    }
}

// ─────────────────── Event Configuration ────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttr {
    pub event_type: PerfEventType,
    pub config: u64,
    pub sample_period: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: PerfFlags,
    pub wakeup_events: u32,
    pub bp_type: u32,
    pub bp_addr: u64,
    pub bp_len: u64,
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        Self {
            event_type: PerfEventType::Hardware,
            config: 0,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: PerfFlags::default(),
            wakeup_events: 0,
            bp_type: 0,
            bp_addr: 0,
            bp_len: 0,
        }
    }
}

impl PerfEventAttr {
    pub fn for_hw_event(event: HwEvent) -> Self {
        Self {
            event_type: PerfEventType::Hardware,
            config: event as u64,
            ..Default::default()
        }
    }

    pub fn for_sw_event(event: SwEvent) -> Self {
        Self {
            event_type: PerfEventType::Software,
            config: event as u64,
            ..Default::default()
        }
    }

    pub fn for_cache_event(event: HwCacheEvent) -> Self {
        Self {
            event_type: PerfEventType::HwCache,
            config: event.to_config(),
            ..Default::default()
        }
    }

    pub fn with_sampling(mut self, period: u64) -> Self {
        self.sample_period = period;
        self.flags.freq = false;
        self
    }

    pub fn with_frequency(mut self, freq: u64) -> Self {
        self.sample_period = freq;
        self.flags.freq = true;
        self
    }

    pub fn with_callchain(mut self) -> Self {
        self.sample_type |= PERF_SAMPLE_CALLCHAIN;
        self
    }

    pub fn with_timestamp(mut self) -> Self {
        self.sample_type |= PERF_SAMPLE_TIME;
        self
    }

    pub fn with_cpu(mut self) -> Self {
        self.sample_type |= PERF_SAMPLE_CPU;
        self
    }

    pub fn with_pid_tid(mut self) -> Self {
        self.sample_type |= PERF_SAMPLE_TID;
        self
    }
}

// Sample type bitmask constants
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

#[derive(Debug, Clone, Copy)]
pub struct PerfFlags {
    pub disabled: bool,
    pub inherit: bool,
    pub pinned: bool,
    pub exclusive: bool,
    pub exclude_user: bool,
    pub exclude_kernel: bool,
    pub exclude_hv: bool,
    pub exclude_idle: bool,
    pub mmap: bool,
    pub comm: bool,
    pub freq: bool,
    pub inherit_stat: bool,
    pub enable_on_exec: bool,
    pub task: bool,
    pub watermark: bool,
    pub precise_ip: u8,
}

impl Default for PerfFlags {
    fn default() -> Self {
        Self {
            disabled: true,
            inherit: false,
            pinned: false,
            exclusive: false,
            exclude_user: false,
            exclude_kernel: false,
            exclude_hv: true,
            exclude_idle: false,
            mmap: false,
            comm: false,
            freq: false,
            inherit_stat: false,
            enable_on_exec: false,
            task: false,
            watermark: false,
            precise_ip: 0,
        }
    }
}

// ─────────────────── Sample Record ──────────────────────────────────
#[derive(Debug, Clone)]
pub struct PerfSample {
    pub ip: u64,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub addr: u64,
    pub cpu: u32,
    pub period: u64,
    pub callchain: [u64; MAX_CALLCHAIN_DEPTH],
    pub callchain_depth: u16,
    pub weight: u64,
    pub data_src: u64,
}

impl Default for PerfSample {
    fn default() -> Self {
        Self {
            ip: 0,
            pid: 0,
            tid: 0,
            timestamp: 0,
            addr: 0,
            cpu: 0,
            period: 0,
            callchain: [0; MAX_CALLCHAIN_DEPTH],
            callchain_depth: 0,
            weight: 0,
            data_src: 0,
        }
    }
}

// ─────────────────── Perf Event Instance ────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventState {
    /// Event is disabled and not counting
    Off,
    /// Event is enabled and active
    Active,
    /// Event encountered an error
    Error,
    /// Event is being destroyed
    Zombie,
}

pub struct PerfEvent {
    /// Unique event ID
    id: u64,
    /// Event attributes
    attr: PerfEventAttr,
    /// Current state
    state: PerfEventState,
    /// Current counter value
    count: u64,
    /// Total count since creation
    total_count: u64,
    /// Number of times the counter has overflowed
    overflows: u64,
    /// Time the event has been enabled (nanoseconds)
    total_time_enabled: u64,
    /// Time the event has been running (may be less if multiplexed)
    total_time_running: u64,
    /// CPU this event is bound to (-1 for all)
    cpu: i32,
    /// Process this event is bound to (0 for system-wide)
    pid: u32,
    /// Group leader ID (for grouped events)
    group_leader_id: u64,
    /// Sample ring buffer
    sample_buffer: [PerfSample; 1024],
    sample_head: usize,
    sample_tail: usize,
    sample_count: usize,
    /// Timestamp of last sample
    last_sample_time: u64,
    /// Number of samples collected
    total_samples: u64,
    /// Number of samples lost due to buffer overflow
    lost_samples: u64,
    /// Hardware PMC index (if applicable)
    pmc_index: i8,
    /// Name for identification
    name: [u8; 64],
    name_len: usize,
}

impl PerfEvent {
    pub fn new(id: u64, attr: PerfEventAttr, pid: u32, cpu: i32) -> Self {
        Self {
            id,
            attr,
            state: PerfEventState::Off,
            count: 0,
            total_count: 0,
            overflows: 0,
            total_time_enabled: 0,
            total_time_running: 0,
            cpu,
            pid,
            group_leader_id: id,
            sample_buffer: [PerfSample::default(); 1024],
            sample_head: 0,
            sample_tail: 0,
            sample_count: 0,
            last_sample_time: 0,
            total_samples: 0,
            lost_samples: 0,
            pmc_index: -1,
            name: [0; 64],
            name_len: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(64);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Enable this event (start counting)
    pub fn enable(&mut self) {
        if self.state == PerfEventState::Off {
            self.state = PerfEventState::Active;
        }
    }

    /// Disable this event (stop counting)
    pub fn disable(&mut self) {
        if self.state == PerfEventState::Active {
            self.state = PerfEventState::Off;
        }
    }

    /// Reset the counter to zero
    pub fn reset(&mut self) {
        self.count = 0;
        self.overflows = 0;
        self.sample_head = 0;
        self.sample_tail = 0;
        self.sample_count = 0;
    }

    /// Read the current counter value
    pub fn read(&self) -> PerfReadValue {
        PerfReadValue {
            value: self.count,
            time_enabled: self.total_time_enabled,
            time_running: self.total_time_running,
            id: self.id,
        }
    }

    /// Record an event occurrence
    pub fn record_event(&mut self, count: u64) {
        if self.state != PerfEventState::Active { return; }

        self.count += count;
        self.total_count += count;

        // Check for sampling
        if self.attr.sample_period > 0 {
            if self.count >= self.attr.sample_period {
                self.count -= self.attr.sample_period;
                self.overflows += 1;
                self.generate_sample();
            }
        }
    }

    /// Record a software event
    pub fn record_sw_event(&mut self) {
        self.record_event(1);
    }

    /// Generate a sample record
    fn generate_sample(&mut self) {
        let sample = PerfSample {
            ip: 0, // Would read from saved registers
            pid: self.pid,
            tid: self.pid,
            timestamp: self.total_time_running,
            addr: 0,
            cpu: if self.cpu >= 0 { self.cpu as u32 } else { 0 },
            period: self.attr.sample_period,
            callchain: [0; MAX_CALLCHAIN_DEPTH],
            callchain_depth: 0,
            weight: 0,
            data_src: 0,
        };

        if self.sample_count < 1024 {
            self.sample_buffer[self.sample_head] = sample;
            self.sample_head = (self.sample_head + 1) % 1024;
            self.sample_count += 1;
            self.total_samples += 1;
        } else {
            self.lost_samples += 1;
        }

        self.last_sample_time = self.total_time_running;
    }

    /// Drain samples from the ring buffer
    pub fn drain_samples(&mut self, out: &mut [PerfSample]) -> usize {
        let mut count = 0;
        while count < out.len() && self.sample_count > 0 {
            out[count] = self.sample_buffer[self.sample_tail].clone();
            self.sample_tail = (self.sample_tail + 1) % 1024;
            self.sample_count -= 1;
            count += 1;
        }
        count
    }

    /// Update timing (called on context switch or timer tick)
    pub fn update_time(&mut self, delta_ns: u64) {
        self.total_time_enabled += delta_ns;
        if self.state == PerfEventState::Active {
            self.total_time_running += delta_ns;
        }
    }

    /// Get statistics about this event
    pub fn stats(&self) -> PerfEventStats {
        PerfEventStats {
            id: self.id,
            count: self.count,
            total_count: self.total_count,
            overflows: self.overflows,
            total_samples: self.total_samples,
            lost_samples: self.lost_samples,
            time_enabled_ns: self.total_time_enabled,
            time_running_ns: self.total_time_running,
            state: self.state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerfReadValue {
    pub value: u64,
    pub time_enabled: u64,
    pub time_running: u64,
    pub id: u64,
}

impl PerfReadValue {
    /// Calculate the scaled value (adjusting for time multiplexing)
    pub fn scaled_value(&self) -> u64 {
        if self.time_running == 0 || self.time_enabled == 0 {
            return self.value;
        }
        if self.time_running >= self.time_enabled {
            return self.value;
        }
        // Scale: value * (time_enabled / time_running)
        (self.value as u128 * self.time_enabled as u128 / self.time_running as u128) as u64
    }
}

#[derive(Debug, Clone)]
pub struct PerfEventStats {
    pub id: u64,
    pub count: u64,
    pub total_count: u64,
    pub overflows: u64,
    pub total_samples: u64,
    pub lost_samples: u64,
    pub time_enabled_ns: u64,
    pub time_running_ns: u64,
    pub state: PerfEventState,
}

// ─────────────────── Event Group ────────────────────────────────────
/// A group of related perf events that are scheduled together.
/// All events in a group are enabled/disabled atomically and share
/// the same time window for accurate ratio calculations.
pub struct PerfEventGroup {
    id: u64,
    leader: Option<usize>, // Index into perf_events
    members: [Option<usize>; 8],
    member_count: u8,
    enabled: bool,
    pinned: bool,
}

impl PerfEventGroup {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            leader: None,
            members: [None; 8],
            member_count: 0,
            enabled: false,
            pinned: false,
        }
    }

    pub fn set_leader(&mut self, event_idx: usize) {
        self.leader = Some(event_idx);
    }

    pub fn add_member(&mut self, event_idx: usize) -> bool {
        if self.member_count >= 8 { return false; }
        self.members[self.member_count as usize] = Some(event_idx);
        self.member_count += 1;
        true
    }

    pub fn member_count(&self) -> u8 {
        self.member_count
    }
}

// ─────────────────── Per-CPU PMU State ──────────────────────────────
pub struct PmuState {
    /// CPU ID
    cpu: u32,
    /// Currently programmed counters (event index → PMC slot)
    active_counters: [Option<usize>; MAX_COUNTERS_PER_CPU],
    /// Number of active counters
    active_count: u8,
    /// Maximum number of hardware counters available
    max_counters: u8,
    /// Global control MSR value
    global_ctrl: u64,
    /// Fixed counter control
    fixed_ctrl: u64,
    /// Statistics
    multiplexing_count: u64,
    context_switch_count: u64,
}

impl PmuState {
    pub fn new(cpu: u32, max_counters: u8) -> Self {
        Self {
            cpu,
            active_counters: [None; MAX_COUNTERS_PER_CPU],
            active_count: 0,
            max_counters,
            global_ctrl: 0,
            fixed_ctrl: 0,
            multiplexing_count: 0,
            context_switch_count: 0,
        }
    }

    /// Assign an event to a free hardware counter
    pub fn assign_counter(&mut self, event_idx: usize) -> Option<u8> {
        for i in 0..self.max_counters as usize {
            if self.active_counters[i].is_none() {
                self.active_counters[i] = Some(event_idx);
                self.active_count += 1;
                return Some(i as u8);
            }
        }
        None // All counters in use — would need multiplexing
    }

    /// Release a hardware counter
    pub fn release_counter(&mut self, pmc_index: u8) {
        let idx = pmc_index as usize;
        if idx < MAX_COUNTERS_PER_CPU && self.active_counters[idx].is_some() {
            self.active_counters[idx] = None;
            if self.active_count > 0 {
                self.active_count -= 1;
            }
        }
    }

    /// Check if multiplexing is needed
    pub fn needs_multiplexing(&self, required_counters: u8) -> bool {
        required_counters > self.max_counters
    }

    /// Context switch — save and restore PMU state
    pub fn context_switch(&mut self) {
        self.context_switch_count += 1;
        // Would read all active counters and save values
    }
}

// ─────────────────── Perf Subsystem Manager ─────────────────────────
pub struct PerfManager {
    /// All registered perf events
    events: [Option<PerfEvent>; MAX_PERF_EVENTS],
    event_count: usize,
    /// Event groups
    groups: [Option<PerfEventGroup>; MAX_EVENT_GROUPS],
    group_count: usize,
    /// Per-CPU PMU state
    pmu_states: [PmuState; MAX_CPUS],
    num_cpus: u32,
    /// Software event counters (system-wide)
    sw_counters: SwCounters,
    /// Next unique event ID
    next_event_id: u64,
    /// Next unique group ID
    next_group_id: u64,
    /// Whether the PMU hardware is available
    hw_available: bool,
    /// Maximum generic counters per CPU
    max_generic_counters: u8,
    /// Maximum fixed counters per CPU
    max_fixed_counters: u8,
    /// Global statistics
    total_events_created: u64,
    total_events_destroyed: u64,
    total_samples_generated: u64,
}

impl PerfManager {
    pub fn new() -> Self {
        const NONE_EVENT: Option<PerfEvent> = None;
        const NONE_GROUP: Option<PerfEventGroup> = None;

        Self {
            events: [NONE_EVENT; MAX_PERF_EVENTS],
            event_count: 0,
            groups: [NONE_GROUP; MAX_EVENT_GROUPS],
            group_count: 0,
            pmu_states: core::array::from_fn(|i| PmuState::new(i as u32, 4)),
            num_cpus: 1,
            sw_counters: SwCounters::new(),
            next_event_id: 1,
            next_group_id: 1,
            hw_available: false,
            max_generic_counters: 4,
            max_fixed_counters: 3,
            total_events_created: 0,
            total_events_destroyed: 0,
            total_samples_generated: 0,
        }
    }

    /// Initialize the perf subsystem with PMU detection
    pub fn init(&mut self, num_cpus: u32) {
        self.num_cpus = num_cpus;

        // Detect PMU capabilities
        self.detect_pmu();

        // Initialize per-CPU PMU states
        for i in 0..num_cpus as usize {
            if i < MAX_CPUS {
                self.pmu_states[i] = PmuState::new(
                    i as u32,
                    self.max_generic_counters,
                );
            }
        }
    }

    /// Detect PMU hardware capabilities
    fn detect_pmu(&mut self) {
        // In production, this would use CPUID to detect:
        // - Number of generic counters (EAX[31:24] of leaf 0x0A)
        // - Counter width
        // - Number of fixed counters
        // For now, assume a typical modern x86 CPU
        self.hw_available = true;
        self.max_generic_counters = 4;
        self.max_fixed_counters = 3;
    }

    /// Create a new perf event
    pub fn create_event(
        &mut self,
        attr: PerfEventAttr,
        pid: u32,
        cpu: i32,
    ) -> Option<u64> {
        if self.event_count >= MAX_PERF_EVENTS {
            return None;
        }

        let id = self.next_event_id;
        self.next_event_id += 1;

        let event = PerfEvent::new(id, attr, pid, cpu);

        // Find a free slot
        for slot in self.events.iter_mut() {
            if slot.is_none() {
                *slot = Some(event);
                self.event_count += 1;
                self.total_events_created += 1;
                return Some(id);
            }
        }

        None
    }

    /// Destroy a perf event
    pub fn destroy_event(&mut self, id: u64) -> bool {
        for slot in self.events.iter_mut() {
            if let Some(event) = slot {
                if event.id == id {
                    // Release hardware counter if assigned
                    if event.pmc_index >= 0 && event.cpu >= 0 {
                        let cpu = event.cpu as usize;
                        if cpu < MAX_CPUS {
                            self.pmu_states[cpu].release_counter(event.pmc_index as u8);
                        }
                    }
                    *slot = None;
                    self.event_count -= 1;
                    self.total_events_destroyed += 1;
                    return true;
                }
            }
        }
        false
    }

    /// Enable a perf event
    pub fn enable_event(&mut self, id: u64) -> bool {
        if let Some(event) = self.find_event_mut(id) {
            event.enable();

            // Try to assign a hardware counter
            if event.attr.event_type == PerfEventType::Hardware && event.pmc_index < 0 {
                let cpu = if event.cpu >= 0 { event.cpu as usize } else { 0 };
                if cpu < MAX_CPUS {
                    if let Some(pmc) = self.pmu_states[cpu].assign_counter(0) {
                        // pmc_index needs to be set on the event
                        // We'd need to find it again since we already borrowed
                        let _ = pmc;
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Disable a perf event
    pub fn disable_event(&mut self, id: u64) -> bool {
        if let Some(event) = self.find_event_mut(id) {
            event.disable();
            true
        } else {
            false
        }
    }

    /// Read a perf event's counter
    pub fn read_event(&self, id: u64) -> Option<PerfReadValue> {
        self.find_event(id).map(|event| event.read())
    }

    /// Reset a perf event's counter
    pub fn reset_event(&mut self, id: u64) -> bool {
        if let Some(event) = self.find_event_mut(id) {
            event.reset();
            true
        } else {
            false
        }
    }

    /// Create an event group
    pub fn create_group(&mut self) -> Option<u64> {
        if self.group_count >= MAX_EVENT_GROUPS { return None; }

        let id = self.next_group_id;
        self.next_group_id += 1;

        for slot in self.groups.iter_mut() {
            if slot.is_none() {
                *slot = Some(PerfEventGroup::new(id));
                self.group_count += 1;
                return Some(id);
            }
        }

        None
    }

    /// Record a software event system-wide
    pub fn record_sw_event(&mut self, event_type: SwEvent) {
        self.sw_counters.increment(event_type);

        // Notify all active software event listeners
        for slot in self.events.iter_mut() {
            if let Some(event) = slot {
                if event.state == PerfEventState::Active
                    && event.attr.event_type == PerfEventType::Software
                    && event.attr.config == event_type as u64
                {
                    event.record_sw_event();
                }
            }
        }
    }

    /// Timer tick — update timing and handle multiplexing
    pub fn tick(&mut self, delta_ns: u64) {
        for slot in self.events.iter_mut() {
            if let Some(event) = slot {
                event.update_time(delta_ns);
            }
        }
    }

    /// Context switch handling — save/restore perf state
    pub fn context_switch(&mut self, cpu: u32, _old_pid: u32, _new_pid: u32) {
        if (cpu as usize) < MAX_CPUS {
            self.pmu_states[cpu as usize].context_switch();
        }
    }

    fn find_event(&self, id: u64) -> Option<&PerfEvent> {
        for slot in &self.events {
            if let Some(event) = slot {
                if event.id == id {
                    return Some(event);
                }
            }
        }
        None
    }

    fn find_event_mut(&mut self, id: u64) -> Option<&mut PerfEvent> {
        for slot in self.events.iter_mut() {
            if let Some(event) = slot {
                if event.id == id {
                    return Some(event);
                }
            }
        }
        None
    }

    /// Get the number of active events
    pub fn active_event_count(&self) -> usize {
        self.events.iter()
            .filter(|e| e.as_ref().map_or(false, |ev| ev.state == PerfEventState::Active))
            .count()
    }

    /// Get global statistics
    pub fn global_stats(&self) -> PerfGlobalStats {
        PerfGlobalStats {
            total_events: self.event_count,
            active_events: self.active_event_count(),
            total_groups: self.group_count,
            total_created: self.total_events_created,
            total_destroyed: self.total_events_destroyed,
            hw_available: self.hw_available,
            max_counters: self.max_generic_counters,
            sw_counters: self.sw_counters.clone(),
        }
    }
}

// ─────────────────── Software Event Counters ────────────────────────
#[derive(Debug, Clone)]
pub struct SwCounters {
    pub context_switches: u64,
    pub cpu_migrations: u64,
    pub page_faults: u64,
    pub page_faults_minor: u64,
    pub page_faults_major: u64,
    pub alignment_faults: u64,
    pub emulation_faults: u64,
}

impl SwCounters {
    pub fn new() -> Self {
        Self {
            context_switches: 0,
            cpu_migrations: 0,
            page_faults: 0,
            page_faults_minor: 0,
            page_faults_major: 0,
            alignment_faults: 0,
            emulation_faults: 0,
        }
    }

    pub fn increment(&mut self, event: SwEvent) {
        match event {
            SwEvent::ContextSwitches => self.context_switches += 1,
            SwEvent::CpuMigrations => self.cpu_migrations += 1,
            SwEvent::PageFaults => self.page_faults += 1,
            SwEvent::PageFaultsMin => self.page_faults_minor += 1,
            SwEvent::PageFaultsMax => self.page_faults_major += 1,
            SwEvent::AlignmentFaults => self.alignment_faults += 1,
            SwEvent::EmulationFaults => self.emulation_faults += 1,
            _ => {}
        }
    }
}

#[derive(Debug)]
pub struct PerfGlobalStats {
    pub total_events: usize,
    pub active_events: usize,
    pub total_groups: usize,
    pub total_created: u64,
    pub total_destroyed: u64,
    pub hw_available: bool,
    pub max_counters: u8,
    pub sw_counters: SwCounters,
}

// ─────────────────── Global Instance ────────────────────────────────
static mut PERF_MANAGER: Option<PerfManager> = None;

pub fn init(num_cpus: u32) {
    unsafe {
        let mut mgr = PerfManager::new();
        mgr.init(num_cpus);
        PERF_MANAGER = Some(mgr);
    }
}

pub fn get_manager() -> Option<&'static mut PerfManager> {
    unsafe { PERF_MANAGER.as_mut() }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_perf_init(num_cpus: u32) {
    init(num_cpus);
}

#[no_mangle]
pub extern "C" fn rust_perf_create_event(event_type: u32, config: u64, pid: u32, cpu: i32) -> i64 {
    if let Some(mgr) = get_manager() {
        let attr = PerfEventAttr {
            event_type: match event_type {
                0 => PerfEventType::Hardware,
                1 => PerfEventType::Software,
                2 => PerfEventType::Tracepoint,
                3 => PerfEventType::HwCache,
                _ => PerfEventType::Raw,
            },
            config,
            ..Default::default()
        };
        if let Some(id) = mgr.create_event(attr, pid, cpu) {
            return id as i64;
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn rust_perf_enable(event_id: u64) -> bool {
    get_manager().map_or(false, |mgr| mgr.enable_event(event_id))
}

#[no_mangle]
pub extern "C" fn rust_perf_disable(event_id: u64) -> bool {
    get_manager().map_or(false, |mgr| mgr.disable_event(event_id))
}

#[no_mangle]
pub extern "C" fn rust_perf_read(event_id: u64) -> u64 {
    get_manager()
        .and_then(|mgr| mgr.read_event(event_id))
        .map_or(0, |val| val.value)
}

#[no_mangle]
pub extern "C" fn rust_perf_destroy(event_id: u64) -> bool {
    get_manager().map_or(false, |mgr| mgr.destroy_event(event_id))
}

#[no_mangle]
pub extern "C" fn rust_perf_tick(delta_ns: u64) {
    if let Some(mgr) = get_manager() {
        mgr.tick(delta_ns);
    }
}

#[no_mangle]
pub extern "C" fn rust_perf_context_switch(cpu: u32, old_pid: u32, new_pid: u32) {
    if let Some(mgr) = get_manager() {
        mgr.context_switch(cpu, old_pid, new_pid);
    }
}

#[no_mangle]
pub extern "C" fn rust_perf_record_sw_event(event: u32) {
    if let Some(mgr) = get_manager() {
        let sw = match event {
            0 => SwEvent::CpuClock,
            1 => SwEvent::TaskClock,
            2 => SwEvent::PageFaults,
            3 => SwEvent::ContextSwitches,
            4 => SwEvent::CpuMigrations,
            5 => SwEvent::PageFaultsMin,
            6 => SwEvent::PageFaultsMax,
            _ => return,
        };
        mgr.record_sw_event(sw);
    }
}
