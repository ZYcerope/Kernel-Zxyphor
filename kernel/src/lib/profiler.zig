// SPDX-License-Identifier: MIT
// Zxyphor Kernel — In-Kernel Performance Profiler & Tracer
//
// Hardware & software performance monitoring:
// - Performance counter management (PMU interface)
// - CPU cycle counting via TSC and PMC
// - Instruction-level sampling (IBS/PEBS stub)
// - Function-level profiling with call stack capture
// - Per-CPU sample buffer with ring-buffer storage
// - Software tracepoints for kernel events
// - Flame graph data generation (stack folding)
// - Histogram-based latency measurement
// - Watchdog: detect CPU soft/hard lockups
// - System-wide & per-task profiling modes

const std = @import("std");

// ─────────────────── MSR Constants (x86_64) ─────────────────────────
pub const MSR_TSC: u32 = 0x10;
pub const MSR_PERF_GLOBAL_CTRL: u32 = 0x38F;
pub const MSR_PERF_GLOBAL_STATUS: u32 = 0x38E;
pub const MSR_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;
pub const MSR_PERFEVTSEL0: u32 = 0x186;
pub const MSR_PERFEVTSEL1: u32 = 0x187;
pub const MSR_PERFEVTSEL2: u32 = 0x188;
pub const MSR_PERFEVTSEL3: u32 = 0x189;
pub const MSR_PMC0: u32 = 0x0C1;
pub const MSR_PMC1: u32 = 0x0C2;
pub const MSR_PMC2: u32 = 0x0C3;
pub const MSR_PMC3: u32 = 0x0C4;
pub const MSR_FIXED_CTR0: u32 = 0x309; // Instructions retired
pub const MSR_FIXED_CTR1: u32 = 0x30A; // CPU cycles unhalted
pub const MSR_FIXED_CTR2: u32 = 0x30B; // Reference cycles
pub const MSR_FIXED_CTR_CTRL: u32 = 0x38D;

// PMC event select encoding
pub const PERFEVT_EN: u64 = 1 << 22;        // Enable
pub const PERFEVT_INT: u64 = 1 << 20;       // Interrupt on overflow
pub const PERFEVT_USR: u64 = 1 << 16;       // Count in user mode
pub const PERFEVT_OS: u64 = 1 << 17;        // Count in kernel mode
pub const PERFEVT_EDGE: u64 = 1 << 18;      // Edge detect
pub const PERFEVT_INV: u64 = 1 << 23;       // Invert CMASK

// ─────────────────── Hardware Event IDs ─────────────────────────────
pub const HwEvent = enum(u8) {
    cpu_cycles = 0,
    instructions = 1,
    cache_refs = 2,
    cache_misses = 3,
    branch_instructions = 4,
    branch_misses = 5,
    bus_cycles = 6,
    stalled_frontend = 7,
    stalled_backend = 8,
    ref_cycles = 9,
};

/// Map hardware event to event_select + unit_mask for common Intel/AMD
pub fn hwEventEncoding(event: HwEvent) struct { event_select: u8, unit_mask: u8 } {
    return switch (event) {
        .cpu_cycles => .{ .event_select = 0x3C, .unit_mask = 0x00 },
        .instructions => .{ .event_select = 0xC0, .unit_mask = 0x00 },
        .cache_refs => .{ .event_select = 0x2E, .unit_mask = 0x4F },
        .cache_misses => .{ .event_select = 0x2E, .unit_mask = 0x41 },
        .branch_instructions => .{ .event_select = 0xC4, .unit_mask = 0x00 },
        .branch_misses => .{ .event_select = 0xC5, .unit_mask = 0x00 },
        .bus_cycles => .{ .event_select = 0x3C, .unit_mask = 0x01 },
        .stalled_frontend => .{ .event_select = 0x0E, .unit_mask = 0x01 },
        .stalled_backend => .{ .event_select = 0xA2, .unit_mask = 0x01 },
        .ref_cycles => .{ .event_select = 0x3C, .unit_mask = 0x01 },
    };
}

/// Build PERFEVTSEL MSR value
pub fn buildPerfEvtSel(event_select: u8, unit_mask: u8, usr: bool, os: bool, interrupt: bool) u64 {
    var val: u64 = @as(u64, event_select) | (@as(u64, unit_mask) << 8);
    val |= PERFEVT_EN;
    if (usr) val |= PERFEVT_USR;
    if (os) val |= PERFEVT_OS;
    if (interrupt) val |= PERFEVT_INT;
    return val;
}

// ─────────────────── Software Tracepoints ───────────────────────────
pub const MAX_TRACEPOINTS: usize = 128;

pub const TracepointType = enum(u8) {
    sched_switch,
    sched_wakeup,
    syscall_enter,
    syscall_exit,
    irq_enter,
    irq_exit,
    page_fault,
    mm_alloc,
    mm_free,
    net_rx,
    net_tx,
    block_read,
    block_write,
    lock_acquire,
    lock_release,
    timer_tick,
    custom,
};

pub const Tracepoint = struct {
    tp_type: TracepointType = .custom,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    enabled: bool = false,
    hit_count: u64 = 0,
    callback_registered: bool = false,

    pub fn setName(self: *Tracepoint, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }
};

// ─────────────────── Sample / Stack Trace ───────────────────────────
pub const MAX_STACK_DEPTH: usize = 32;
pub const MAX_SAMPLES: usize = 4096;

pub const SampleType = packed struct(u16) {
    ip: bool = false,
    tid: bool = false,
    time: bool = false,
    callchain: bool = false,
    cpu: bool = false,
    period: bool = false,
    counter: bool = false,
    _pad: u9 = 0,
};

pub const PerfSample = struct {
    /// Instruction pointer at sample time
    ip: u64 = 0,
    /// Process/thread ID
    pid: u32 = 0,
    tid: u32 = 0,
    /// Timestamp (TSC or equivalent)
    timestamp: u64 = 0,
    /// CPU core number
    cpu: u16 = 0,
    /// Counter value
    counter_value: u64 = 0,
    /// Call chain (stack unwinding)
    callchain: [MAX_STACK_DEPTH]u64 = [_]u64{0} ** MAX_STACK_DEPTH,
    callchain_depth: u8 = 0,
    /// Period (sampling interval)
    period: u64 = 0,
    /// Event that triggered sample
    event: HwEvent = .cpu_cycles,
};

// ─────────────────── Stack Unwinder ─────────────────────────────────
pub const StackUnwinder = struct {
    /// Frame pointer based unwinding
    pub fn unwindFramePointer(rbp: u64, rip: u64, out: []u64) u8 {
        var depth: u8 = 0;
        if (out.len > 0) {
            out[0] = rip;
            depth = 1;
        }

        var frame_ptr = rbp;
        while (depth < out.len and depth < MAX_STACK_DEPTH) {
            // Validate frame pointer (must be in kernel or user address range)
            if (frame_ptr == 0 or frame_ptr % 8 != 0) break;
            if (frame_ptr < 0x1000) break; // NULL page guard

            // Read return address: *(rbp + 8)
            const ret_addr_ptr = frame_ptr + 8;
            // In real kernel: read from memory
            _ = ret_addr_ptr;
            // Simulated: we'd use page table walk to safely read
            break; // Cannot actually read memory here
        }

        return depth;
    }

    /// DWARF-based unwinding stub
    pub fn unwindDwarf(rip: u64, rsp: u64, out: []u64) u8 {
        // Would parse .eh_frame / .debug_frame sections
        _ = rsp;
        if (out.len > 0) {
            out[0] = rip;
            return 1;
        }
        return 0;
    }
};

// ─────────────────── Per-CPU Sample Ring Buffer ──────────────────────
pub const RING_BUFFER_SIZE: usize = 1024;

pub const SampleRingBuffer = struct {
    samples: [RING_BUFFER_SIZE]PerfSample = undefined,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    lost: u64 = 0,

    pub fn push(self: *SampleRingBuffer, sample: PerfSample) bool {
        if (self.count >= RING_BUFFER_SIZE) {
            self.lost += 1;
            return false;
        }
        self.samples[self.tail] = sample;
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        self.count += 1;
        return true;
    }

    pub fn pop(self: *SampleRingBuffer) ?PerfSample {
        if (self.count == 0) return null;
        const sample = self.samples[self.head];
        self.head = (self.head + 1) % RING_BUFFER_SIZE;
        self.count -= 1;
        return sample;
    }

    pub fn clear(self: *SampleRingBuffer) void {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
};

// ─────────────────── Histogram ──────────────────────────────────────
pub const HISTOGRAM_BUCKETS: usize = 64;

pub const LatencyHistogram = struct {
    /// Bucket boundaries in nanoseconds (logarithmic)
    boundaries: [HISTOGRAM_BUCKETS]u64 = undefined,
    counts: [HISTOGRAM_BUCKETS]u64 = [_]u64{0} ** HISTOGRAM_BUCKETS,
    total_samples: u64 = 0,
    min_value: u64 = ~@as(u64, 0),
    max_value: u64 = 0,
    sum: u64 = 0,
    bucket_count: u8 = 0,

    pub fn initLogarithmic(self: *LatencyHistogram) void {
        // Powers of 2 from 1ns to ~8.5 trillion ns (~2.4 hours)
        var i: u8 = 0;
        var boundary: u64 = 1;
        while (i < HISTOGRAM_BUCKETS) : (i += 1) {
            self.boundaries[i] = boundary;
            if (boundary < (1 << 42)) {
                boundary *= 2;
            } else {
                boundary = ~@as(u64, 0);
            }
        }
        self.bucket_count = @intCast(HISTOGRAM_BUCKETS);
    }

    pub fn record(self: *LatencyHistogram, value: u64) void {
        self.total_samples += 1;
        self.sum += value;
        if (value < self.min_value) self.min_value = value;
        if (value > self.max_value) self.max_value = value;

        // Binary search for bucket
        var lo: usize = 0;
        var hi: usize = self.bucket_count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.boundaries[mid] <= value) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        const bucket = if (lo > 0) lo - 1 else 0;
        self.counts[bucket] += 1;
    }

    pub fn percentile(self: *const LatencyHistogram, p: u64) u64 {
        if (self.total_samples == 0) return 0;
        const target = (self.total_samples * p + 99) / 100;
        var cumulative: u64 = 0;
        for (0..self.bucket_count) |i| {
            cumulative += self.counts[i];
            if (cumulative >= target) {
                return self.boundaries[i];
            }
        }
        return self.max_value;
    }

    pub fn mean(self: *const LatencyHistogram) u64 {
        if (self.total_samples == 0) return 0;
        return self.sum / self.total_samples;
    }
};

// ─────────────────── Profiler Session ───────────────────────────────
pub const ProfilerMode = enum(u8) {
    disabled,
    sampling,      // Timer-based sampling
    counting,      // Just count events
    tracing,       // Record all tracepoint events
};

pub const MAX_PROFILER_EVENTS: usize = 4; // Simultaneous HW counters

pub const ProfilerEvent = struct {
    hw_event: HwEvent = .cpu_cycles,
    counter_idx: u8 = 0,
    sample_period: u64 = 10000, // sample every N events
    current_count: u64 = 0,
    total_samples: u64 = 0,
    enabled: bool = false,
};

pub const ProfilerSession = struct {
    mode: ProfilerMode = .disabled,
    events: [MAX_PROFILER_EVENTS]ProfilerEvent = [_]ProfilerEvent{.{}} ** MAX_PROFILER_EVENTS,
    event_count: u8 = 0,
    target_pid: u32 = 0, // 0 = system-wide
    sample_type: SampleType = .{ .ip = true, .tid = true, .time = true },
    ring_buffer: SampleRingBuffer = .{},
    histogram: LatencyHistogram = .{},
    start_timestamp: u64 = 0,
    total_cpu_cycles: u64 = 0,
    total_instructions: u64 = 0,
    total_cache_misses: u64 = 0,
    running: bool = false,

    pub fn start(self: *ProfilerSession) void {
        self.running = true;
        self.start_timestamp = readTsc();
        self.ring_buffer.clear();
    }

    pub fn stop(self: *ProfilerSession) void {
        self.running = false;
    }

    pub fn addEvent(self: *ProfilerSession, hw_event: HwEvent, period: u64) bool {
        if (self.event_count >= MAX_PROFILER_EVENTS) return false;
        self.events[self.event_count] = .{
            .hw_event = hw_event,
            .counter_idx = self.event_count,
            .sample_period = period,
            .enabled = true,
        };
        self.event_count += 1;
        return true;
    }

    /// Called from PMI (Performance Monitor Interrupt) handler
    pub fn onOverflow(self: *ProfilerSession, counter_idx: u8, ip: u64, pid: u32, tid: u32, cpu: u16) void {
        if (!self.running) return;
        if (counter_idx >= self.event_count) return;

        var sample = PerfSample{
            .ip = ip,
            .pid = pid,
            .tid = tid,
            .timestamp = readTsc(),
            .cpu = cpu,
            .event = self.events[counter_idx].hw_event,
            .period = self.events[counter_idx].sample_period,
        };

        // Stack trace if requested
        if (self.sample_type.callchain) {
            // Would use frame pointer or DWARF unwinding
            sample.callchain[0] = ip;
            sample.callchain_depth = 1;
        }

        _ = self.ring_buffer.push(sample);
        self.events[counter_idx].total_samples += 1;
    }

    /// Drain samples into a callback
    pub fn drainSamples(self: *ProfilerSession, max: usize) usize {
        var drained: usize = 0;
        while (drained < max) {
            if (self.ring_buffer.pop()) |_| {
                drained += 1;
            } else break;
        }
        return drained;
    }

    pub fn getStats(self: *const ProfilerSession) ProfilerStats {
        return .{
            .total_samples = blk: {
                var total: u64 = 0;
                for (self.events[0..self.event_count]) |ev| {
                    total += ev.total_samples;
                }
                break :blk total;
            },
            .lost_samples = self.ring_buffer.lost,
            .duration_tsc = if (self.running) readTsc() - self.start_timestamp else 0,
            .buffer_usage = self.ring_buffer.count,
            .buffer_capacity = RING_BUFFER_SIZE,
        };
    }
};

pub const ProfilerStats = struct {
    total_samples: u64,
    lost_samples: u64,
    duration_tsc: u64,
    buffer_usage: usize,
    buffer_capacity: usize,
};

// ─────────────────── Lockup Detector (Watchdog) ─────────────────────
pub const MAX_CPUS: usize = 64;
pub const SOFT_LOCKUP_THRESHOLD: u64 = 10_000_000_000; // 10 seconds in TSC (~3GHz)
pub const HARD_LOCKUP_THRESHOLD: u64 = 30_000_000_000; // 30 seconds

pub const CpuWatchdog = struct {
    last_touch: [MAX_CPUS]u64 = [_]u64{0} ** MAX_CPUS,
    soft_lockup: [MAX_CPUS]bool = [_]bool{false} ** MAX_CPUS,
    hard_lockup: [MAX_CPUS]bool = [_]bool{false} ** MAX_CPUS,
    enabled: bool = false,
    cpu_count: u8 = 0,
    soft_threshold: u64 = SOFT_LOCKUP_THRESHOLD,
    hard_threshold: u64 = HARD_LOCKUP_THRESHOLD,

    pub fn init(self: *CpuWatchdog, num_cpus: u8) void {
        self.cpu_count = num_cpus;
        self.enabled = true;
        const now = readTsc();
        for (0..num_cpus) |i| {
            self.last_touch[i] = now;
        }
    }

    pub fn touch(self: *CpuWatchdog, cpu: u8) void {
        if (cpu < self.cpu_count) {
            self.last_touch[cpu] = readTsc();
            self.soft_lockup[cpu] = false;
        }
    }

    pub fn check(self: *CpuWatchdog) LockupStatus {
        if (!self.enabled) return .{ .soft_locked = 0, .hard_locked = 0 };
        const now = readTsc();
        var status = LockupStatus{};

        for (0..self.cpu_count) |i| {
            const delta = now -% self.last_touch[i];
            if (delta > self.hard_threshold) {
                self.hard_lockup[i] = true;
                status.hard_locked |= @as(u64, 1) << @intCast(i);
            } else if (delta > self.soft_threshold) {
                self.soft_lockup[i] = true;
                status.soft_locked |= @as(u64, 1) << @intCast(i);
            }
        }

        return status;
    }
};

pub const LockupStatus = struct {
    soft_locked: u64 = 0, // bitmask of soft-locked CPUs
    hard_locked: u64 = 0, // bitmask of hard-locked CPUs
};

// ─────────────────── TSC Read ───────────────────────────────────────
pub inline fn readTsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : "={eax}" (lo), "={edx}" (hi)
        :
        : "ecx"
    );
    return @as(u64, hi) << 32 | lo;
}

pub inline fn readTscFence() u64 {
    // RDTSCP serializes — more accurate for benchmarking
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtscp"
        : "={eax}" (lo), "={edx}" (hi)
        :
        : "ecx"
    );
    return @as(u64, hi) << 32 | lo;
}

// ─────────────────── Profiler Manager ───────────────────────────────
pub const MAX_SESSIONS: usize = 8;

pub const ProfilerManager = struct {
    sessions: [MAX_SESSIONS]ProfilerSession = [_]ProfilerSession{.{}} ** MAX_SESSIONS,
    session_count: u8 = 0,
    tracepoints: [MAX_TRACEPOINTS]Tracepoint = [_]Tracepoint{.{}} ** MAX_TRACEPOINTS,
    tp_count: u16 = 0,
    watchdog: CpuWatchdog = .{},
    initialized: bool = false,

    pub fn init(self: *ProfilerManager, num_cpus: u8) void {
        self.watchdog.init(num_cpus);
        self.registerDefaultTracepoints();
        self.initialized = true;
    }

    fn registerDefaultTracepoints(self: *ProfilerManager) void {
        const defaults = [_]struct { tp: TracepointType, name: []const u8 }{
            .{ .tp = .sched_switch, .name = "sched:switch" },
            .{ .tp = .sched_wakeup, .name = "sched:wakeup" },
            .{ .tp = .syscall_enter, .name = "syscall:enter" },
            .{ .tp = .syscall_exit, .name = "syscall:exit" },
            .{ .tp = .irq_enter, .name = "irq:enter" },
            .{ .tp = .irq_exit, .name = "irq:exit" },
            .{ .tp = .page_fault, .name = "mm:fault" },
            .{ .tp = .mm_alloc, .name = "mm:alloc" },
            .{ .tp = .mm_free, .name = "mm:free" },
            .{ .tp = .net_rx, .name = "net:rx" },
            .{ .tp = .net_tx, .name = "net:tx" },
            .{ .tp = .block_read, .name = "block:read" },
            .{ .tp = .block_write, .name = "block:write" },
            .{ .tp = .lock_acquire, .name = "lock:acquire" },
            .{ .tp = .lock_release, .name = "lock:release" },
            .{ .tp = .timer_tick, .name = "timer:tick" },
        };

        for (defaults) |d| {
            if (self.tp_count >= MAX_TRACEPOINTS) break;
            self.tracepoints[self.tp_count] = .{ .tp_type = d.tp };
            self.tracepoints[self.tp_count].setName(d.name);
            self.tp_count += 1;
        }
    }

    pub fn createSession(self: *ProfilerManager, mode: ProfilerMode) ?u8 {
        if (self.session_count >= MAX_SESSIONS) return null;
        const idx = self.session_count;
        self.sessions[idx] = .{ .mode = mode };
        self.session_count += 1;
        return idx;
    }

    pub fn enableTracepoint(self: *ProfilerManager, tp_type: TracepointType) bool {
        for (&self.tracepoints[0..self.tp_count]) |*tp| {
            if (tp.tp_type == tp_type) {
                tp.enabled = true;
                return true;
            }
        }
        return false;
    }

    pub fn disableTracepoint(self: *ProfilerManager, tp_type: TracepointType) bool {
        for (&self.tracepoints[0..self.tp_count]) |*tp| {
            if (tp.tp_type == tp_type) {
                tp.enabled = false;
                return true;
            }
        }
        return false;
    }

    pub fn hitTracepoint(self: *ProfilerManager, tp_type: TracepointType) void {
        for (&self.tracepoints[0..self.tp_count]) |*tp| {
            if (tp.tp_type == tp_type and tp.enabled) {
                tp.hit_count += 1;
                break;
            }
        }
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var profiler_mgr: ProfilerManager = .{};

pub fn initProfiler(num_cpus: u8) void {
    profiler_mgr.init(num_cpus);
}

pub fn getProfiler() *ProfilerManager {
    return &profiler_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_profiler_init(num_cpus: u8) void {
    initProfiler(num_cpus);
}

export fn zxy_profiler_create_session(mode: u8) i32 {
    const profiler_mode: ProfilerMode = @enumFromInt(mode);
    if (profiler_mgr.createSession(profiler_mode)) |idx| {
        return @intCast(idx);
    }
    return -1;
}

export fn zxy_profiler_start(session_idx: u8) void {
    if (session_idx < profiler_mgr.session_count) {
        profiler_mgr.sessions[session_idx].start();
    }
}

export fn zxy_profiler_stop(session_idx: u8) void {
    if (session_idx < profiler_mgr.session_count) {
        profiler_mgr.sessions[session_idx].stop();
    }
}

export fn zxy_profiler_read_tsc() u64 {
    return readTsc();
}

export fn zxy_watchdog_touch(cpu: u8) void {
    profiler_mgr.watchdog.touch(cpu);
}

export fn zxy_watchdog_check_soft() u64 {
    return profiler_mgr.watchdog.check().soft_locked;
}

export fn zxy_tracepoint_count() u16 {
    return profiler_mgr.tp_count;
}

export fn zxy_profiler_session_count() u8 {
    return profiler_mgr.session_count;
}
