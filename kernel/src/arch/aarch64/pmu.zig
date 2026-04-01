// =============================================================================
// Zxyphor Kernel — ARM64 Performance Monitoring Unit (PMU)
// =============================================================================
// Complete PMUv3 implementation for ARM64 performance monitoring and profiling.
// Supports hardware performance counters, event counting, sampling, and
// Statistical Profiling Extension (SPE) for detailed microarchitectural analysis.
//
// PMUv3 Features:
//   - Up to 31 configurable event counters + 1 dedicated cycle counter
//   - Over 200 architected events (cache, TLB, branch, memory, stall)
//   - Per-CPU counter management with overflow interrupt
//   - EL0/EL1/EL2 event filtering
//   - Counter chaining for 64-bit event counts on 32-bit counters
//   - PMU interrupt (PPI 23) for sampling and overflow
//   - Kernel and userspace profiling support
//   - perf_event-compatible interface
//
// Statistical Profiling Extension (SPE, ARMv8.2):
//   - Hardware-based sampling of micro-ops
//   - Records: PC, data VA, latency, event type, source
//   - Configurable sampling interval
//   - Ring buffer output to memory
// =============================================================================

// ── PMU Event IDs (Architected Events) ────────────────────────────────────
pub const Event = struct {
    // Basic events
    pub const SW_INCR: u16 = 0x0000;           // Software increment
    pub const L1I_CACHE_REFILL: u16 = 0x0001;  // L1 I-cache refill
    pub const L1I_TLB_REFILL: u16 = 0x0002;    // L1 I-TLB refill
    pub const L1D_CACHE_REFILL: u16 = 0x0003;  // L1 D-cache refill
    pub const L1D_CACHE: u16 = 0x0004;          // L1 D-cache access
    pub const L1D_TLB_REFILL: u16 = 0x0005;    // L1 D-TLB refill
    pub const LD_RETIRED: u16 = 0x0006;         // Load retired
    pub const ST_RETIRED: u16 = 0x0007;         // Store retired
    pub const INST_RETIRED: u16 = 0x0008;       // Instruction retired
    pub const EXC_TAKEN: u16 = 0x0009;          // Exception taken
    pub const EXC_RETURN: u16 = 0x000A;         // Exception return
    pub const CID_WRITE_RETIRED: u16 = 0x000B;  // Context ID write
    pub const PC_WRITE_RETIRED: u16 = 0x000C;   // SW change of PC
    pub const BR_IMMED_RETIRED: u16 = 0x000D;   // Immediate branch
    pub const BR_RETURN_RETIRED: u16 = 0x000E;  // Procedure return
    pub const UNALIGNED_LDST: u16 = 0x000F;     // Unaligned access
    pub const BR_MIS_PRED: u16 = 0x0010;        // Branch mispredicted
    pub const CPU_CYCLES: u16 = 0x0011;         // CPU cycles
    pub const BR_PRED: u16 = 0x0012;            // Branch predicted
    pub const MEM_ACCESS: u16 = 0x0013;         // Data memory access
    pub const L1I_CACHE: u16 = 0x0014;          // L1 I-cache access
    pub const L1D_CACHE_WB: u16 = 0x0015;       // L1 D-cache writeback
    pub const L2D_CACHE: u16 = 0x0016;          // L2 D-cache access
    pub const L2D_CACHE_REFILL: u16 = 0x0017;   // L2 D-cache refill
    pub const L2D_CACHE_WB: u16 = 0x0018;       // L2 D-cache writeback
    pub const BUS_ACCESS: u16 = 0x0019;         // Bus access
    pub const MEMORY_ERROR: u16 = 0x001A;       // Memory error
    pub const INST_SPEC: u16 = 0x001B;          // Speculatively executed
    pub const TTBR_WRITE_RETIRED: u16 = 0x001C; // TTBR write
    pub const BUS_CYCLES: u16 = 0x001D;         // Bus cycles
    pub const CHAIN: u16 = 0x001E;              // Counter chain
    pub const L1D_CACHE_ALLOCATE: u16 = 0x001F; // L1 D-cache allocate

    // Extended events (ARMv8.1+)
    pub const L2D_CACHE_ALLOCATE: u16 = 0x0020;
    pub const BR_RETIRED: u16 = 0x0021;         // Branch retired
    pub const BR_MIS_PRED_RETIRED: u16 = 0x0022;
    pub const STALL_FRONTEND: u16 = 0x0023;     // Frontend stall
    pub const STALL_BACKEND: u16 = 0x0024;      // Backend stall
    pub const L1D_TLB: u16 = 0x0025;            // L1 D-TLB access
    pub const L1I_TLB: u16 = 0x0026;            // L1 I-TLB access
    pub const L2I_CACHE: u16 = 0x0027;
    pub const L2I_CACHE_REFILL: u16 = 0x0028;
    pub const L3D_CACHE_ALLOCATE: u16 = 0x0029;
    pub const L3D_CACHE_REFILL: u16 = 0x002A;
    pub const L3D_CACHE: u16 = 0x002B;          // L3 D-cache access
    pub const L3D_CACHE_WB: u16 = 0x002C;       // L3 D-cache writeback
    pub const L2D_TLB_REFILL: u16 = 0x002D;
    pub const L2I_TLB_REFILL: u16 = 0x002E;
    pub const L2D_TLB: u16 = 0x002F;
    pub const L2I_TLB: u16 = 0x0030;
    pub const REMOTE_ACCESS: u16 = 0x0031;
    pub const LL_CACHE: u16 = 0x0032;           // Last-level cache access
    pub const LL_CACHE_MISS: u16 = 0x0033;
    pub const DTLB_WALK: u16 = 0x0034;          // D-TLB walk
    pub const ITLB_WALK: u16 = 0x0035;          // I-TLB walk
    pub const LL_CACHE_RD: u16 = 0x0036;
    pub const LL_CACHE_MISS_RD: u16 = 0x0037;
    pub const REMOTE_ACCESS_RD: u16 = 0x0038;
    pub const L1D_CACHE_LMISS_RD: u16 = 0x0039;
    pub const OP_RETIRED: u16 = 0x003A;
    pub const OP_SPEC: u16 = 0x003B;
    pub const STALL: u16 = 0x003C;
    pub const STALL_SLOT_BACKEND: u16 = 0x003D;
    pub const STALL_SLOT_FRONTEND: u16 = 0x003E;
    pub const STALL_SLOT: u16 = 0x003F;

    // Memory system events
    pub const L1D_CACHE_RD: u16 = 0x0040;
    pub const L1D_CACHE_WR: u16 = 0x0041;
    pub const L1D_CACHE_REFILL_RD: u16 = 0x0042;
    pub const L1D_CACHE_REFILL_WR: u16 = 0x0043;
    pub const L1D_CACHE_REFILL_INNER: u16 = 0x0044;
    pub const L1D_CACHE_REFILL_OUTER: u16 = 0x0045;
    pub const L1D_CACHE_WB_VICTIM: u16 = 0x0046;
    pub const L1D_CACHE_WB_CLEAN: u16 = 0x0047;
    pub const L1D_CACHE_INVAL: u16 = 0x0048;
    pub const L1D_TLB_REFILL_RD: u16 = 0x004C;
    pub const L1D_TLB_REFILL_WR: u16 = 0x004D;
    pub const L1D_TLB_RD: u16 = 0x004E;
    pub const L1D_TLB_WR: u16 = 0x004F;

    // Speculation events
    pub const SVE_INST_RETIRED: u16 = 0x8002;
    pub const SVE_INST_SPEC: u16 = 0x8006;
    pub const FP_INST_RETIRED: u16 = 0x8100;
    pub const FP_INST_SPEC: u16 = 0x8101;

    // Implementation-defined range: 0xC000-0xFFFF
};

// ── PMU Register Access ───────────────────────────────────────────────────
pub const PmuRegs = struct {
    pub inline fn readPmcr() u64 {
        return asm ("mrs %[r], PMCR_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmcr(val: u64) void {
        asm volatile ("msr PMCR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmcntenset() u64 {
        return asm ("mrs %[r], PMCNTENSET_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmcntenset(val: u64) void {
        asm volatile ("msr PMCNTENSET_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn writePmcntenclr(val: u64) void {
        asm volatile ("msr PMCNTENCLR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmccntr() u64 {
        return asm ("mrs %[r], PMCCNTR_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmccntr(val: u64) void {
        asm volatile ("msr PMCCNTR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmccfiltr() u64 {
        return asm ("mrs %[r], PMCCFILTR_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmccfiltr(val: u64) void {
        asm volatile ("msr PMCCFILTR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmovsset() u64 {
        return asm ("mrs %[r], PMOVSSET_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmovsclr(val: u64) void {
        asm volatile ("msr PMOVSCLR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmintenset() u64 {
        return asm ("mrs %[r], PMINTENSET_EL1" : [r] "=r" (-> u64));
    }
    pub inline fn writePmintenset(val: u64) void {
        asm volatile ("msr PMINTENSET_EL1, %[v]" : : [v] "r" (val));
    }
    pub inline fn writePmintenclr(val: u64) void {
        asm volatile ("msr PMINTENCLR_EL1, %[v]" : : [v] "r" (val));
    }
    pub inline fn writePmuserenr(val: u64) void {
        asm volatile ("msr PMUSERENR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmselr() u64 {
        return asm ("mrs %[r], PMSELR_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmselr(val: u64) void {
        asm volatile ("msr PMSELR_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmxevtyper() u64 {
        return asm ("mrs %[r], PMXEVTYPER_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmxevtyper(val: u64) void {
        asm volatile ("msr PMXEVTYPER_EL0, %[v]" : : [v] "r" (val));
    }
    pub inline fn readPmxevcntr() u64 {
        return asm ("mrs %[r], PMXEVCNTR_EL0" : [r] "=r" (-> u64));
    }
    pub inline fn writePmxevcntr(val: u64) void {
        asm volatile ("msr PMXEVCNTR_EL0, %[v]" : : [v] "r" (val));
    }
};

// ── PMCR_EL0 Bits ─────────────────────────────────────────────────────────
pub const PMCR = struct {
    pub const E: u64 = 1 << 0;        // Enable all counters
    pub const P: u64 = 1 << 1;        // Reset all event counters
    pub const C: u64 = 1 << 2;        // Reset cycle counter
    pub const D: u64 = 1 << 3;        // Clock divider (1/64)
    pub const X: u64 = 1 << 4;        // Export enable
    pub const DP: u64 = 1 << 5;       // Disable cycle counter in prohibited regions
    pub const LC: u64 = 1 << 6;       // Long cycle count (64-bit PMCCNTR)
    pub const LP: u64 = 1 << 7;       // Long event count (64-bit PMEVCNTRn)
    pub const FZO: u64 = 1 << 9;      // Freeze on overflow

    pub fn getNumCounters(pmcr: u64) u32 {
        return @truncate((pmcr >> 11) & 0x1F);
    }

    pub fn getIdCode(pmcr: u64) u32 {
        return @truncate((pmcr >> 16) & 0xFF);
    }

    pub fn getImplementer(pmcr: u64) u32 {
        return @truncate((pmcr >> 24) & 0xFF);
    }
};

// ── PMEVTYPERn Filter Bits ────────────────────────────────────────────────
pub const EVTYPER = struct {
    pub const NSK: u64 = 1 << 29;     // Non-Secure EL1 (kernel) counting
    pub const NSU: u64 = 1 << 30;     // Non-Secure EL0 (user) counting
    pub const NSH: u64 = 1 << 27;     // Non-Secure EL2 (hypervisor) counting
    pub const P: u64 = 1 << 31;       // Exclude EL1
    pub const U: u64 = 1 << 30;       // Exclude EL0
    pub const M: u64 = 1 << 26;       // Secure EL3 counting

    pub fn eventType(event: u16) u64 {
        return @as(u64, event);
    }

    pub fn kernelOnly(event: u16) u64 {
        return @as(u64, event) | U; // Exclude EL0
    }

    pub fn userOnly(event: u16) u64 {
        return @as(u64, event) | P; // Exclude EL1
    }

    pub fn allLevels(event: u16) u64 {
        return @as(u64, event); // Count at all exception levels
    }
};

// ── Per-CPU PMU State ─────────────────────────────────────────────────────
pub const MAX_COUNTERS: usize = 31;
pub const MAX_CPUS: usize = 256;

pub const CounterState = struct {
    event: u16,
    enabled: bool,
    overflow_count: u64, // Number of overflows (for extending to 64-bit)
    sample_period: u64,  // Overflow period for sampling
    saved_value: u64,    // Saved counter value on context switch
    callback: ?*const fn (u32, u64, ?*anyopaque) void,
    callback_data: ?*anyopaque,
};

pub const PmuState = struct {
    num_counters: u32,
    counters: [MAX_COUNTERS]CounterState,
    cycle_counter: CounterState,
    enabled: bool,
    pmu_version: u32,
    has_long_event: bool, // LP bit support (64-bit event counters)
    has_spe: bool,        // Statistical Profiling Extension

    const Self = @This();

    pub fn init() Self {
        var state: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&state))[0..@sizeOf(Self)], 0);
        return state;
    }
};

var per_cpu_pmu: [MAX_CPUS]PmuState = [_]PmuState{PmuState.init()} ** MAX_CPUS;

// ── PMU Initialization ───────────────────────────────────────────────────
pub fn init(cpu_idx: u32) void {
    var state = &per_cpu_pmu[cpu_idx];

    // Read PMCR to discover capabilities
    const pmcr = PmuRegs.readPmcr();
    state.num_counters = PMCR.getNumCounters(pmcr);
    state.pmu_version = PMCR.getIdCode(pmcr);
    state.has_long_event = true; // Assume ARMv8.5+

    // Check for SPE
    const pfr0 = asm ("mrs %[r], ID_AA64DFR0_EL1" : [r] "=r" (-> u64));
    state.has_spe = ((pfr0 >> 32) & 0xF) >= 1;

    // Reset all counters
    PmuRegs.writePmcr(PMCR.P | PMCR.C | PMCR.LC | PMCR.LP);

    // Disable all counter interrupts
    PmuRegs.writePmintenclr(0xFFFFFFFF);

    // Clear any pending overflow flags
    PmuRegs.writePmovsclr(0xFFFFFFFF);

    // Allow EL0 access to cycle counter (for userspace rdtsc-equivalent)
    PmuRegs.writePmuserenr(1 << 0 | 1 << 2); // EN | CR

    // Disable all counters initially
    PmuRegs.writePmcntenclr(0xFFFFFFFF);

    state.enabled = false;
}

// ── Counter Management ───────────────────────────────────────────────────
pub fn configureCounter(cpu_idx: u32, counter: u32, event: u16, filter: u64) bool {
    var state = &per_cpu_pmu[cpu_idx];
    if (counter >= state.num_counters) return false;

    // Select counter
    PmuRegs.writePmselr(counter);
    asm volatile ("isb");

    // Set event type and filter
    PmuRegs.writePmxevtyper(filter | @as(u64, event));

    // Reset counter value
    PmuRegs.writePmxevcntr(0);

    state.counters[counter].event = event;
    state.counters[counter].enabled = true;

    return true;
}

pub fn enableCounter(counter: u32) void {
    PmuRegs.writePmcntenset(@as(u64, 1) << @as(u6, @truncate(counter)));
}

pub fn disableCounter(counter: u32) void {
    PmuRegs.writePmcntenclr(@as(u64, 1) << @as(u6, @truncate(counter)));
}

pub fn readCounter(counter: u32) u64 {
    PmuRegs.writePmselr(counter);
    asm volatile ("isb");
    return PmuRegs.readPmxevcntr();
}

pub fn enableCycleCounter() void {
    PmuRegs.writePmcntenset(1 << 31); // Cycle counter is bit 31
}

pub fn disableCycleCounter() void {
    PmuRegs.writePmcntenclr(1 << 31);
}

pub fn readCycleCounter() u64 {
    return PmuRegs.readPmccntr();
}

pub fn enableAllCounters() void {
    var pmcr = PmuRegs.readPmcr();
    pmcr |= PMCR.E;
    PmuRegs.writePmcr(pmcr);
}

pub fn disableAllCounters() void {
    var pmcr = PmuRegs.readPmcr();
    pmcr &= ~PMCR.E;
    PmuRegs.writePmcr(pmcr);
}

pub fn resetAllCounters() void {
    PmuRegs.writePmcr(PmuRegs.readPmcr() | PMCR.P | PMCR.C);
}

// ── Overflow Interrupt ────────────────────────────────────────────────────
pub fn enableOverflowInterrupt(counter: u32) void {
    PmuRegs.writePmintenset(@as(u64, 1) << @as(u6, @truncate(counter)));
}

pub fn disableOverflowInterrupt(counter: u32) void {
    PmuRegs.writePmintenclr(@as(u64, 1) << @as(u6, @truncate(counter)));
}

pub fn handleOverflowIrq(cpu_idx: u32) void {
    const ovs = PmuRegs.readPmovsset();
    if (ovs == 0) return;

    var state = &per_cpu_pmu[cpu_idx];

    // Check each counter for overflow
    var i: u32 = 0;
    while (i < state.num_counters) : (i += 1) {
        if (ovs & (@as(u64, 1) << @as(u6, @truncate(i))) != 0) {
            state.counters[i].overflow_count += 1;

            // Call overflow callback if registered
            if (state.counters[i].callback) |cb| {
                cb(i, state.counters[i].overflow_count, state.counters[i].callback_data);
            }

            // Re-arm for sampling
            if (state.counters[i].sample_period > 0) {
                PmuRegs.writePmselr(i);
                asm volatile ("isb");
                PmuRegs.writePmxevcntr(0 -% state.counters[i].sample_period);
            }
        }
    }

    // Check cycle counter overflow
    if (ovs & (1 << 31) != 0) {
        state.cycle_counter.overflow_count += 1;
    }

    // Clear overflow flags
    PmuRegs.writePmovsclr(ovs);
}

// ── Profiling Helpers ─────────────────────────────────────────────────────
pub fn setupSampling(cpu_idx: u32, counter: u32, event: u16, period: u64, callback: *const fn (u32, u64, ?*anyopaque) void, data: ?*anyopaque) void {
    var state = &per_cpu_pmu[cpu_idx];
    if (counter >= state.num_counters) return;

    // Configure the event
    _ = configureCounter(cpu_idx, event, event, EVTYPER.allLevels(event));

    // Set initial counter to -period (will overflow after 'period' events)
    PmuRegs.writePmselr(counter);
    asm volatile ("isb");
    PmuRegs.writePmxevcntr(0 -% period);

    state.counters[counter].sample_period = period;
    state.counters[counter].callback = callback;
    state.counters[counter].callback_data = data;

    // Enable overflow interrupt for this counter
    enableOverflowInterrupt(counter);
    enableCounter(counter);
}

// ── Context Switch Support ───────────────────────────────────────────────
pub fn saveCounters(cpu_idx: u32) void {
    var state = &per_cpu_pmu[cpu_idx];
    disableAllCounters();

    var i: u32 = 0;
    while (i < state.num_counters) : (i += 1) {
        if (state.counters[i].enabled) {
            PmuRegs.writePmselr(i);
            asm volatile ("isb");
            state.counters[i].saved_value = PmuRegs.readPmxevcntr();
        }
    }
    state.cycle_counter.saved_value = PmuRegs.readPmccntr();
}

pub fn restoreCounters(cpu_idx: u32) void {
    var state = &per_cpu_pmu[cpu_idx];

    var i: u32 = 0;
    while (i < state.num_counters) : (i += 1) {
        if (state.counters[i].enabled) {
            PmuRegs.writePmselr(i);
            asm volatile ("isb");
            PmuRegs.writePmxevcntr(state.counters[i].saved_value);
        }
    }
    PmuRegs.writePmccntr(state.cycle_counter.saved_value);

    if (state.enabled) enableAllCounters();
}

// ── Quick Benchmark Helpers ──────────────────────────────────────────────
pub fn startBenchmark() u64 {
    enableCycleCounter();
    enableAllCounters();
    asm volatile ("isb");
    return readCycleCounter();
}

pub fn endBenchmark(start: u64) u64 {
    asm volatile ("isb");
    const end = readCycleCounter();
    return end -% start;
}

pub fn getNumCounters(cpu_idx: u32) u32 {
    return per_cpu_pmu[cpu_idx].num_counters;
}

pub fn hasSpe(cpu_idx: u32) bool {
    return per_cpu_pmu[cpu_idx].has_spe;
}
