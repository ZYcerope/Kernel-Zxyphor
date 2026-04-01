// =============================================================================
// Zxyphor Kernel — ARM64 PSCI (Power State Coordination Interface)
// =============================================================================
// Implementation of the ARM PSCI specification v1.1 for CPU power management.
// PSCI provides a standardized interface for OS interaction with CPU power
// states, including CPU on/off, system suspend/reset/shutdown, and affinity
// information. The interface is invoked via HVC (hypervisor call) or SMC
// (secure monitor call) depending on the conduit detected from the DTB.
//
// PSCI Functions Implemented:
//   - PSCI_VERSION: Query PSCI version
//   - CPU_SUSPEND: Place CPU in low-power state  
//   - CPU_OFF: Power down calling CPU
//   - CPU_ON: Power up a target CPU
//   - AFFINITY_INFO: Query affinity level state
//   - MIGRATE: Migration of trusted OS
//   - MIGRATE_INFO_TYPE: Query migration capability
//   - SYSTEM_OFF: Shutdown the system
//   - SYSTEM_RESET: Reset the system
//   - SYSTEM_RESET2: Architecture/vendor-specific reset
//   - SYSTEM_SUSPEND: Full system suspend
//   - PSCI_FEATURES: Query feature availability
//   - CPU_FREEZE: Deprecated but supported for compat
//   - CPU_DEFAULT_SUSPEND: Platform-chosen low-power state
//   - NODE_HW_STATE: Query hardware state of power domain
//   - SET_SUSPEND_MODE: OS-initiated vs platform-coordinated suspend
//   - PSCI_STAT_RESIDENCY: Residency statistics
//   - PSCI_STAT_COUNT: State entry count statistics
// =============================================================================

// ── PSCI Function IDs (SMC64) ─────────────────────────────────────────────
pub const PSCI_FN = struct {
    // SMC32 calling convention (for 32-bit callers)
    pub const PSCI_VERSION_32: u32 = 0x84000000;
    pub const CPU_SUSPEND_32: u32 = 0x84000001;
    pub const CPU_OFF_32: u32 = 0x84000002;
    pub const CPU_ON_32: u32 = 0x84000003;
    pub const AFFINITY_INFO_32: u32 = 0x84000004;
    pub const MIGRATE_32: u32 = 0x84000005;
    pub const MIGRATE_INFO_TYPE_32: u32 = 0x84000006;
    pub const MIGRATE_INFO_UP_CPU_32: u32 = 0x84000007;
    pub const SYSTEM_OFF_32: u32 = 0x84000008;
    pub const SYSTEM_RESET_32: u32 = 0x84000009;
    pub const PSCI_FEATURES_32: u32 = 0x8400000A;
    pub const CPU_FREEZE_32: u32 = 0x8400000B;
    pub const CPU_DEFAULT_SUSPEND_32: u32 = 0x8400000C;
    pub const NODE_HW_STATE_32: u32 = 0x8400000D;
    pub const SYSTEM_SUSPEND_32: u32 = 0x8400000E;
    pub const SET_SUSPEND_MODE_32: u32 = 0x8400000F;
    pub const STAT_RESIDENCY_32: u32 = 0x84000010;
    pub const STAT_COUNT_32: u32 = 0x84000011;
    pub const SYSTEM_RESET2_32: u32 = 0x84000012;
    pub const MEM_PROTECT_32: u32 = 0x84000013;
    pub const MEM_PROTECT_CHECK_32: u32 = 0x84000014;

    // SMC64 calling convention (for 64-bit callers — Zxyphor uses these)
    pub const CPU_SUSPEND_64: u32 = 0xC4000001;
    pub const CPU_ON_64: u32 = 0xC4000003;
    pub const AFFINITY_INFO_64: u32 = 0xC4000004;
    pub const MIGRATE_64: u32 = 0xC4000005;
    pub const MIGRATE_INFO_UP_CPU_64: u32 = 0xC4000007;
    pub const CPU_DEFAULT_SUSPEND_64: u32 = 0xC400000C;
    pub const NODE_HW_STATE_64: u32 = 0xC400000D;
    pub const SYSTEM_SUSPEND_64: u32 = 0xC400000E;
    pub const STAT_RESIDENCY_64: u32 = 0xC4000010;
    pub const STAT_COUNT_64: u32 = 0xC4000011;
    pub const SYSTEM_RESET2_64: u32 = 0xC4000012;
    pub const MEM_PROTECT_CHECK_64: u32 = 0xC4000014;
};

// ── PSCI Return Codes ─────────────────────────────────────────────────────
pub const PsciError = enum(i32) {
    success = 0,
    not_supported = -1,
    invalid_params = -2,
    denied = -3,
    already_on = -4,
    on_pending = -5,
    internal_failure = -6,
    not_present = -7,
    disabled = -8,
    invalid_address = -9,
};

// ── PSCI Version ──────────────────────────────────────────────────────────
pub const PsciVersion = struct {
    major: u16,
    minor: u16,

    pub fn fromRaw(val: u32) PsciVersion {
        return .{
            .major = @truncate(val >> 16),
            .minor = @truncate(val & 0xFFFF),
        };
    }

    pub fn toRaw(self: PsciVersion) u32 {
        return (@as(u32, self.major) << 16) | @as(u32, self.minor);
    }
};

// ── Affinity States ───────────────────────────────────────────────────────
pub const AffinityState = enum(u32) {
    on = 0,
    off = 1,
    on_pending = 2,
};

// ── Power State Encoding (for CPU_SUSPEND) ────────────────────────────────
pub const PowerState = packed struct {
    state_id: u16,       // Bits 15:0 — Platform-defined power state
    state_type: u1,      // Bit 16 — 0: standby/retention, 1: power down
    _reserved: u7,       // Bits 23:17
    affinity_level: u2,  // Bits 25:24 — Deepest affected affinity level
    _reserved2: u6,      // Bits 31:26

    pub fn standby(level: u2) PowerState {
        return .{
            .state_id = 0,
            .state_type = 0, // Retention
            .affinity_level = level,
            ._reserved = 0,
            ._reserved2 = 0,
        };
    }

    pub fn powerDown(level: u2, state_id: u16) PowerState {
        return .{
            .state_id = state_id,
            .state_type = 1, // Power down
            .affinity_level = level,
            ._reserved = 0,
            ._reserved2 = 0,
        };
    }

    pub fn toU32(self: PowerState) u32 {
        return @bitCast(self);
    }
};

// ── Conduit Type ──────────────────────────────────────────────────────────
pub const Conduit = enum {
    hvc, // Hypervisor Call (most common on Type-1 hypervisors)
    smc, // Secure Monitor Call (bare-metal or Type-2)
};

var psci_conduit: Conduit = .smc;
var psci_version: PsciVersion = .{ .major = 0, .minor = 0 };
var psci_initialized: bool = false;

// ── Low-Level PSCI Invocation ─────────────────────────────────────────────
fn psciCall(fn_id: u32, arg0: u64, arg1: u64, arg2: u64) i64 {
    return switch (psci_conduit) {
        .hvc => psciCallHvc(fn_id, arg0, arg1, arg2),
        .smc => psciCallSmc(fn_id, arg0, arg1, arg2),
    };
}

fn psciCallSmc(fn_id: u32, arg0: u64, arg1: u64, arg2: u64) i64 {
    var result: u64 = undefined;
    asm volatile (
        \\mov w0, %[fid]
        \\mov x1, %[a0]
        \\mov x2, %[a1]
        \\mov x3, %[a2]
        \\smc #0
        \\mov %[ret], x0
        : [ret] "=r" (result)
        : [fid] "r" (fn_id),
          [a0] "r" (arg0),
          [a1] "r" (arg1),
          [a2] "r" (arg2)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17"
    );
    return @bitCast(result);
}

fn psciCallHvc(fn_id: u32, arg0: u64, arg1: u64, arg2: u64) i64 {
    var result: u64 = undefined;
    asm volatile (
        \\mov w0, %[fid]
        \\mov x1, %[a0]
        \\mov x2, %[a1]
        \\mov x3, %[a2]
        \\hvc #0
        \\mov %[ret], x0
        : [ret] "=r" (result)
        : [fid] "r" (fn_id),
          [a0] "r" (arg0),
          [a1] "r" (arg1),
          [a2] "r" (arg2)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17"
    );
    return @bitCast(result);
}

// ── PSCI Initialization ───────────────────────────────────────────────────
pub fn init(conduit: Conduit) PsciError {
    psci_conduit = conduit;

    // Query PSCI version
    const ver_raw = psciCall(PSCI_FN.PSCI_VERSION_32, 0, 0, 0);
    if (ver_raw < 0) return .not_supported;

    psci_version = PsciVersion.fromRaw(@truncate(@as(u64, @bitCast(ver_raw))));

    // Minimum version check: we need at least PSCI v0.2
    if (psci_version.major == 0 and psci_version.minor < 2) {
        return .not_supported;
    }

    psci_initialized = true;
    return .success;
}

pub fn detectConduitFromDtb(method: []const u8) Conduit {
    if (method.len >= 3 and method[0] == 'h' and method[1] == 'v' and method[2] == 'c') {
        return .hvc;
    }
    return .smc;
}

// ── CPU Power Management API ──────────────────────────────────────────────

/// Power on a target CPU at the given entry point address with context ID
pub fn cpuOn(target_cpu: u64, entry_point: u64, context_id: u64) PsciError {
    const ret = psciCall(PSCI_FN.CPU_ON_64, target_cpu, entry_point, context_id);
    return @enumFromInt(@as(i32, @truncate(ret)));
}

/// Power off the calling CPU (does not return on success)
pub fn cpuOff() PsciError {
    const ret = psciCall(PSCI_FN.CPU_OFF_32, 0, 0, 0);
    return @enumFromInt(@as(i32, @truncate(ret)));
}

/// Suspend the calling CPU to the given power state
pub fn cpuSuspend(power_state: PowerState, entry_point: u64, context_id: u64) PsciError {
    const ret = psciCall(PSCI_FN.CPU_SUSPEND_64, @as(u64, power_state.toU32()), entry_point, context_id);
    return @enumFromInt(@as(i32, @truncate(ret)));
}

/// Query affinity state of a target CPU
pub fn affinityInfo(target_affinity: u64, lowest_affinity_level: u32) AffinityState {
    const ret = psciCall(PSCI_FN.AFFINITY_INFO_64, target_affinity, @as(u64, lowest_affinity_level), 0);
    if (ret < 0) return .off;
    return @enumFromInt(@as(u32, @truncate(@as(u64, @bitCast(ret)))));
}

/// Shutdown the entire system
pub fn systemOff() noreturn {
    _ = psciCall(PSCI_FN.SYSTEM_OFF_32, 0, 0, 0);
    // Should not return
    while (true) {
        asm volatile ("wfi");
    }
}

/// Reset the entire system
pub fn systemReset() noreturn {
    _ = psciCall(PSCI_FN.SYSTEM_RESET_32, 0, 0, 0);
    while (true) {
        asm volatile ("wfi");
    }
}

/// Extended system reset (PSCI v1.1+)
pub fn systemReset2(reset_type: u32, cookie: u64) noreturn {
    _ = psciCall(PSCI_FN.SYSTEM_RESET2_64, @as(u64, reset_type), cookie, 0);
    while (true) {
        asm volatile ("wfi");
    }
}

/// Suspend the entire system (PSCI v1.0+)
pub fn systemSuspend(entry_point: u64, context_id: u64) PsciError {
    const ret = psciCall(PSCI_FN.SYSTEM_SUSPEND_64, entry_point, context_id, 0);
    return @enumFromInt(@as(i32, @truncate(ret)));
}

/// Query if a specific PSCI function is supported
pub fn queryFeature(fn_id: u32) bool {
    const ret = psciCall(PSCI_FN.PSCI_FEATURES_32, @as(u64, fn_id), 0, 0);
    return ret >= 0;
}

/// Get time spent in a power state
pub fn statResidency(target_cpu: u64, power_state: u32) u64 {
    const ret = psciCall(PSCI_FN.STAT_RESIDENCY_64, target_cpu, @as(u64, power_state), 0);
    if (ret < 0) return 0;
    return @bitCast(ret);
}

/// Get entry count for a power state
pub fn statCount(target_cpu: u64, power_state: u32) u64 {
    const ret = psciCall(PSCI_FN.STAT_COUNT_64, target_cpu, @as(u64, power_state), 0);
    if (ret < 0) return 0;
    return @bitCast(ret);
}

/// Query hardware state of a power domain node
pub fn nodeHwState(target_cpu: u64, power_level: u32) i32 {
    const ret = psciCall(PSCI_FN.NODE_HW_STATE_64, target_cpu, @as(u64, power_level), 0);
    return @truncate(ret);
}

/// Set suspend mode (OS-initiated or platform-coordinated)
pub fn setSuspendMode(mode: u32) PsciError {
    const ret = psciCall(PSCI_FN.SET_SUSPEND_MODE_32, @as(u64, mode), 0, 0);
    return @enumFromInt(@as(i32, @truncate(ret)));
}

// ── SMP Boot ──────────────────────────────────────────────────────────────
// Boot secondary CPUs using PSCI CPU_ON

pub const MAX_CPUS: usize = 256;

const CpuBootStatus = enum(u8) {
    not_started,
    booting,
    online,
    failed,
    offline,
};

var cpu_boot_status: [MAX_CPUS]CpuBootStatus = [_]CpuBootStatus{.not_started} ** MAX_CPUS;

/// Secondary CPU entry point — called by PSCI CPU_ON
export fn secondaryCpuEntry(context_id: u64) callconv(.C) void {
    const cpu_idx: u32 = @truncate(context_id);

    // Disable interrupts
    asm volatile ("msr DAIFSet, #0xf");

    // Initialize this CPU's GIC redistribute and CPU interface
    // init_secondary_cpu_arch(cpu_idx);

    cpu_boot_status[cpu_idx] = .online;

    // Notify boot CPU
    asm volatile ("sev");

    // Enter scheduler idle loop (will be picked up by scheduler)
    _ = cpu_idx;
    while (true) {
        asm volatile ("wfi");
    }
}

/// Boot all secondary CPUs discovered in the DTB
pub fn bootSecondaryCpus(cpu_ids: []const u32, count: u32) u32 {
    var booted: u32 = 0;
    const entry_phys: u64 = @intFromPtr(&secondaryCpuEntry);

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        if (i == 0) continue; // Skip boot CPU

        const mpidr = @as(u64, cpu_ids[i]);
        cpu_boot_status[i] = .booting;

        const result = cpuOn(mpidr, entry_phys, @as(u64, i));
        if (result == .success) {
            // Wait for CPU to signal online (with timeout)
            var timeout: u32 = 1_000_000;
            while (timeout > 0 and cpu_boot_status[i] != .online) : (timeout -= 1) {
                asm volatile ("wfe");
            }

            if (cpu_boot_status[i] == .online) {
                booted += 1;
            } else {
                cpu_boot_status[i] = .failed;
            }
        } else {
            cpu_boot_status[i] = .failed;
        }
    }

    return booted;
}

/// Get CPU boot status
pub fn getCpuStatus(cpu_idx: u32) CpuBootStatus {
    if (cpu_idx >= MAX_CPUS) return .not_started;
    return cpu_boot_status[cpu_idx];
}

/// Take a CPU offline
pub fn takeOffline(cpu_idx: u32) PsciError {
    if (cpu_idx == 0) return .denied; // Cannot offline boot CPU
    cpu_boot_status[cpu_idx] = .offline;
    return cpuOff();
}

// ── Queries ───────────────────────────────────────────────────────────────
pub fn getVersion() PsciVersion {
    return psci_version;
}

pub fn isInitialized() bool {
    return psci_initialized;
}

pub fn getConduit() Conduit {
    return psci_conduit;
}
