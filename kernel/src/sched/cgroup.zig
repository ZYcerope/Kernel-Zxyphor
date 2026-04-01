// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Zig Cgroup v2 Controller Subsystem
//
// Implements a complete cgroup v2 hierarchy with:
// - CPU controller (weight-based scheduling, bandwidth limits)
// - Memory controller (memory limits, swap accounting, OOM)
// - I/O controller (weight-based and max bandwidth throttling)
// - PID controller (process count limits)
// - Unified hierarchy with subtree control
// - Pressure Stall Information (PSI) per-cgroup
// - Freezer functionality (cgroup.freeze)

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_CGROUPS = 1024;
pub const MAX_CGROUP_DEPTH = 16;
pub const MAX_CHILDREN = 64;
pub const MAX_PROCS_PER_CGROUP = 256;
pub const CGROUP_NAME_MAX = 64;
pub const MAX_IO_DEVICES = 32;

pub const CPU_WEIGHT_DEFAULT: u32 = 100;
pub const CPU_WEIGHT_MIN: u32 = 1;
pub const CPU_WEIGHT_MAX: u32 = 10000;
pub const CPU_QUOTA_UNLIMITED: i64 = -1;
pub const CPU_PERIOD_DEFAULT: u64 = 100_000; // 100ms in microseconds

pub const MEMORY_LIMIT_UNLIMITED: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// ─────────────────── Controller Types ───────────────────────────────
pub const ControllerType = enum(u8) {
    cpu,
    memory,
    io,
    pids,

    pub fn name(self: ControllerType) []const u8 {
        return switch (self) {
            .cpu => "cpu",
            .memory => "memory",
            .io => "io",
            .pids => "pids",
        };
    }
};

pub const ControllerMask = packed struct {
    cpu: bool = false,
    memory: bool = false,
    io: bool = false,
    pids: bool = false,
    _pad: u4 = 0,

    pub fn all() ControllerMask {
        return .{ .cpu = true, .memory = true, .io = true, .pids = true };
    }

    pub fn none() ControllerMask {
        return .{};
    }

    pub fn has(self: ControllerMask, ctrl: ControllerType) bool {
        return switch (ctrl) {
            .cpu => self.cpu,
            .memory => self.memory,
            .io => self.io,
            .pids => self.pids,
        };
    }
};

// ─────────────────── CPU Controller ─────────────────────────────────
pub const CpuController = struct {
    /// Proportional weight for CPU time distribution (1-10000)
    weight: u32 = CPU_WEIGHT_DEFAULT,
    /// Nice-mode weight
    weight_nice: i8 = 0,
    /// CPU bandwidth limit: max microseconds per period (-1 = unlimited)
    max_quota: i64 = CPU_QUOTA_UNLIMITED,
    /// Period for bandwidth limiting (microseconds)
    max_period: u64 = CPU_PERIOD_DEFAULT,
    /// CPU burst (extra burst capacity in microseconds)
    burst: u64 = 0,

    // Statistics (in microseconds)
    usage_usec: u64 = 0,
    user_usec: u64 = 0,
    system_usec: u64 = 0,
    nr_periods: u64 = 0,
    nr_throttled: u64 = 0,
    throttled_usec: u64 = 0,
    nr_bursts: u64 = 0,
    burst_usec: u64 = 0,

    // Internal state
    remaining_quota: i64 = 0,
    period_start: u64 = 0,
    is_throttled: bool = false,

    pub fn set_weight(self: *CpuController, weight: u32) void {
        if (weight >= CPU_WEIGHT_MIN and weight <= CPU_WEIGHT_MAX) {
            self.weight = weight;
        }
    }

    pub fn set_max(self: *CpuController, quota: i64, period: u64) void {
        self.max_quota = quota;
        if (period > 0) {
            self.max_period = period;
        }
    }

    pub fn charge_time(self: *CpuController, usec: u64) void {
        self.usage_usec += usec;

        if (self.max_quota != CPU_QUOTA_UNLIMITED) {
            self.remaining_quota -= @as(i64, @intCast(usec));
            if (self.remaining_quota <= 0) {
                self.is_throttled = true;
                self.nr_throttled += 1;
            }
        }
    }

    pub fn refill_quota(self: *CpuController) void {
        if (self.max_quota != CPU_QUOTA_UNLIMITED) {
            self.remaining_quota = self.max_quota;
            self.is_throttled = false;
            self.nr_periods += 1;
        }
    }

    pub fn effective_weight(self: *const CpuController) u32 {
        if (self.weight_nice != 0) {
            // Convert nice value to weight
            const nice_weights = [_]u32{ 88761, 71755, 56483, 46273, 36291,
                29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
                3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526,
                423, 335, 272, 215, 172, 137, 110, 87, 70, 56, 45, 36,
                29, 23, 18, 15 };
            const idx: usize = @intCast(@as(i32, self.weight_nice) + 20);
            if (idx < nice_weights.len) {
                return nice_weights[idx];
            }
        }
        return self.weight;
    }
};

// ─────────────────── Memory Controller ──────────────────────────────
pub const MemoryController = struct {
    /// Hard memory limit (bytes)
    max: u64 = MEMORY_LIMIT_UNLIMITED,
    /// Soft memory limit / high watermark (bytes)
    high: u64 = MEMORY_LIMIT_UNLIMITED,
    /// Low protection threshold (bytes)
    low: u64 = 0,
    /// Minimum memory guarantee (bytes)
    min: u64 = 0,
    /// Swap limit (bytes)
    swap_max: u64 = MEMORY_LIMIT_UNLIMITED,

    // Accounting
    current: u64 = 0,
    swap_current: u64 = 0,
    kernel_current: u64 = 0,
    peak: u64 = 0,
    swap_peak: u64 = 0,

    // Statistics
    stat_pgfault: u64 = 0,
    stat_pgmajfault: u64 = 0,
    stat_pgrefill: u64 = 0,
    stat_pgscan: u64 = 0,
    stat_pgsteal: u64 = 0,
    stat_pgactivate: u64 = 0,
    stat_pgdeactivate: u64 = 0,
    stat_pglazyfree: u64 = 0,
    stat_thp_fault_alloc: u64 = 0,
    stat_thp_collapse_alloc: u64 = 0,

    // OOM state
    oom_group: bool = false,
    oom_kill_count: u64 = 0,
    oom_score_adj: i16 = 0,

    // Events
    events_low: u64 = 0,
    events_high: u64 = 0,
    events_max: u64 = 0,
    events_oom: u64 = 0,
    events_oom_kill: u64 = 0,

    pub fn charge(self: *MemoryController, bytes: u64) bool {
        const new_usage = self.current + bytes;
        if (self.max != MEMORY_LIMIT_UNLIMITED and new_usage > self.max) {
            self.events_max += 1;
            return false; // OOM
        }
        self.current = new_usage;
        if (new_usage > self.peak) {
            self.peak = new_usage;
        }
        if (self.high != MEMORY_LIMIT_UNLIMITED and new_usage > self.high) {
            self.events_high += 1;
        }
        return true;
    }

    pub fn uncharge(self: *MemoryController, bytes: u64) void {
        if (bytes > self.current) {
            self.current = 0;
        } else {
            self.current -= bytes;
        }
    }

    pub fn charge_swap(self: *MemoryController, bytes: u64) bool {
        if (self.swap_max != MEMORY_LIMIT_UNLIMITED and
            self.swap_current + bytes > self.swap_max)
        {
            return false;
        }
        self.swap_current += bytes;
        if (self.swap_current > self.swap_peak) {
            self.swap_peak = self.swap_current;
        }
        return true;
    }

    pub fn uncharge_swap(self: *MemoryController, bytes: u64) void {
        if (bytes > self.swap_current) {
            self.swap_current = 0;
        } else {
            self.swap_current -= bytes;
        }
    }

    pub fn is_under_pressure(self: *const MemoryController) bool {
        if (self.high == MEMORY_LIMIT_UNLIMITED) return false;
        return self.current > (self.high * 90) / 100;
    }

    pub fn should_oom_kill(self: *const MemoryController) bool {
        return self.max != MEMORY_LIMIT_UNLIMITED and self.current >= self.max;
    }

    pub fn effective_protection(self: *const MemoryController) u64 {
        if (self.min > 0) return self.min;
        return self.low;
    }
};

// ─────────────────── I/O Controller ─────────────────────────────────
pub const IoDeviceConfig = struct {
    major: u32 = 0,
    minor: u32 = 0,
    weight: u32 = 100,
    rbps_max: u64 = 0, // 0 = unlimited
    wbps_max: u64 = 0,
    riops_max: u32 = 0,
    wiops_max: u32 = 0,

    // Statistics
    rbytes: u64 = 0,
    wbytes: u64 = 0,
    rios: u64 = 0,
    wios: u64 = 0,
    dbytes: u64 = 0,
    dios: u64 = 0,
};

pub const IoController = struct {
    devices: [MAX_IO_DEVICES]?IoDeviceConfig = [_]?IoDeviceConfig{null} ** MAX_IO_DEVICES,
    device_count: u32 = 0,
    default_weight: u32 = 100,
    default_latency_us: u64 = 0,

    // Pressure
    some_pressure_us: u64 = 0,
    full_pressure_us: u64 = 0,

    pub fn set_device_weight(self: *IoController, major: u32, minor: u32, weight: u32) void {
        for (&self.devices) |*slot| {
            if (slot.*) |*dev| {
                if (dev.major == major and dev.minor == minor) {
                    dev.weight = weight;
                    return;
                }
            }
        }
        // New device
        for (&self.devices) |*slot| {
            if (slot.* == null) {
                slot.* = IoDeviceConfig{
                    .major = major,
                    .minor = minor,
                    .weight = weight,
                };
                self.device_count += 1;
                return;
            }
        }
    }

    pub fn set_device_max(self: *IoController, major: u32, minor: u32, rbps: u64, wbps: u64, riops: u32, wiops: u32) void {
        for (&self.devices) |*slot| {
            if (slot.*) |*dev| {
                if (dev.major == major and dev.minor == minor) {
                    dev.rbps_max = rbps;
                    dev.wbps_max = wbps;
                    dev.riops_max = riops;
                    dev.wiops_max = wiops;
                    return;
                }
            }
        }
        for (&self.devices) |*slot| {
            if (slot.* == null) {
                slot.* = IoDeviceConfig{
                    .major = major,
                    .minor = minor,
                    .rbps_max = rbps,
                    .wbps_max = wbps,
                    .riops_max = riops,
                    .wiops_max = wiops,
                };
                self.device_count += 1;
                return;
            }
        }
    }

    pub fn account_read(self: *IoController, major: u32, minor: u32, bytes: u64) void {
        for (&self.devices) |*slot| {
            if (slot.*) |*dev| {
                if (dev.major == major and dev.minor == minor) {
                    dev.rbytes += bytes;
                    dev.rios += 1;
                    return;
                }
            }
        }
    }

    pub fn account_write(self: *IoController, major: u32, minor: u32, bytes: u64) void {
        for (&self.devices) |*slot| {
            if (slot.*) |*dev| {
                if (dev.major == major and dev.minor == minor) {
                    dev.wbytes += bytes;
                    dev.wios += 1;
                    return;
                }
            }
        }
    }
};

// ─────────────────── PID Controller ─────────────────────────────────
pub const PidsController = struct {
    /// Maximum number of processes allowed
    max: u32 = 0, // 0 = unlimited
    /// Current number of processes
    current: u32 = 0,
    /// Number of times limit was hit
    events_max: u64 = 0,
    /// Peak number of processes
    peak: u32 = 0,

    pub fn charge(self: *PidsController) bool {
        if (self.max > 0 and self.current >= self.max) {
            self.events_max += 1;
            return false;
        }
        self.current += 1;
        if (self.current > self.peak) {
            self.peak = self.current;
        }
        return true;
    }

    pub fn uncharge(self: *PidsController) void {
        if (self.current > 0) {
            self.current -= 1;
        }
    }
};

// ─────────────────── Pressure Stall Information ─────────────────────
pub const PsiState = struct {
    /// Some: percentage of time at least one task is stalled
    some_total_us: u64 = 0,
    some_avg10: u32 = 0,  // Fixed point (x100)
    some_avg60: u32 = 0,
    some_avg300: u32 = 0,
    /// Full: percentage of time all tasks are stalled
    full_total_us: u64 = 0,
    full_avg10: u32 = 0,
    full_avg60: u32 = 0,
    full_avg300: u32 = 0,

    pub fn update(self: *PsiState, some_delta_us: u64, full_delta_us: u64) void {
        self.some_total_us += some_delta_us;
        self.full_total_us += full_delta_us;
        // Simple exponential moving average would be computed here
    }
};

pub const CgroupPsi = struct {
    cpu: PsiState = .{},
    memory: PsiState = .{},
    io: PsiState = .{},
};

// ─────────────────── Cgroup Entry ───────────────────────────────────
pub const CgroupState = enum(u8) {
    active,
    frozen,
    freezing,
    destroyed,
};

pub const Cgroup = struct {
    /// Unique cgroup ID
    id: u32 = 0,
    /// Parent cgroup ID (0 = root)
    parent_id: u32 = 0,
    /// Name
    name: [CGROUP_NAME_MAX]u8 = [_]u8{0} ** CGROUP_NAME_MAX,
    name_len: u8 = 0,
    /// Depth in hierarchy
    depth: u8 = 0,
    /// State
    state: CgroupState = .active,

    /// Controllers enabled in this cgroup
    controllers: ControllerMask = ControllerMask.none(),
    /// Controllers available to children (subtree_control)
    subtree_control: ControllerMask = ControllerMask.none(),

    /// CPU controller
    cpu: CpuController = .{},
    /// Memory controller
    memory: MemoryController = .{},
    /// I/O controller
    io: IoController = .{},
    /// PIDs controller
    pids: PidsController = .{},
    /// Pressure Stall Information
    psi: CgroupPsi = .{},

    /// Children IDs
    children: [MAX_CHILDREN]u32 = [_]u32{0} ** MAX_CHILDREN,
    child_count: u32 = 0,

    /// Process membership
    procs: [MAX_PROCS_PER_CGROUP]u32 = [_]u32{0} ** MAX_PROCS_PER_CGROUP,
    proc_count: u32 = 0,

    /// Reference counting
    ref_count: u32 = 1,

    /// Populated: does this cgroup or its descendants have processes?
    populated: bool = false,

    pub fn set_name(self: *Cgroup, n: []const u8) void {
        const len = @min(n.len, CGROUP_NAME_MAX);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn get_name(self: *const Cgroup) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Add a process to this cgroup
    pub fn add_process(self: *Cgroup, pid: u32) bool {
        // Check PID limit
        if (self.controllers.pids) {
            if (!self.pids.charge()) return false;
        }

        for (&self.procs) |*slot| {
            if (slot.* == 0) {
                slot.* = pid;
                self.proc_count += 1;
                self.populated = true;
                return true;
            }
        }
        return false;
    }

    /// Remove a process from this cgroup
    pub fn remove_process(self: *Cgroup, pid: u32) bool {
        for (&self.procs) |*slot| {
            if (slot.* == pid) {
                slot.* = 0;
                if (self.proc_count > 0) self.proc_count -= 1;
                if (self.controllers.pids) self.pids.uncharge();
                self.populated = self.proc_count > 0;
                return true;
            }
        }
        return false;
    }

    /// Add a child cgroup
    pub fn add_child(self: *Cgroup, child_id: u32) bool {
        if (self.child_count >= MAX_CHILDREN) return false;
        for (&self.children) |*slot| {
            if (slot.* == 0) {
                slot.* = child_id;
                self.child_count += 1;
                return true;
            }
        }
        return false;
    }

    /// Remove a child cgroup
    pub fn remove_child(self: *Cgroup, child_id: u32) bool {
        for (&self.children) |*slot| {
            if (slot.* == child_id) {
                slot.* = 0;
                if (self.child_count > 0) self.child_count -= 1;
                return true;
            }
        }
        return false;
    }

    /// Freeze this cgroup
    pub fn freeze(self: *Cgroup) void {
        if (self.state == .active) {
            self.state = .freezing;
            // Would iterate processes and send SIGSTOP
            self.state = .frozen;
        }
    }

    /// Thaw (unfreeze) this cgroup
    pub fn thaw(self: *Cgroup) void {
        if (self.state == .frozen) {
            self.state = .active;
            // Would iterate processes and send SIGCONT
        }
    }

    /// Charge memory usage
    pub fn charge_memory(self: *Cgroup, bytes: u64) bool {
        if (!self.controllers.memory) return true;
        return self.memory.charge(bytes);
    }

    /// Uncharge memory usage
    pub fn uncharge_memory(self: *Cgroup, bytes: u64) void {
        if (self.controllers.memory) {
            self.memory.uncharge(bytes);
        }
    }

    /// Charge CPU time
    pub fn charge_cpu(self: *Cgroup, usec: u64) void {
        if (self.controllers.cpu) {
            self.cpu.charge_time(usec);
        }
    }

    /// Check if CPU is throttled
    pub fn is_cpu_throttled(self: *const Cgroup) bool {
        return self.controllers.cpu and self.cpu.is_throttled;
    }

    pub fn acquire(self: *Cgroup) void {
        self.ref_count += 1;
    }

    pub fn release(self: *Cgroup) bool {
        if (self.ref_count > 0) self.ref_count -= 1;
        return self.ref_count == 0;
    }
};

// ─────────────────── Cgroup Hierarchy Manager ───────────────────────
pub const CgroupManager = struct {
    cgroups: [MAX_CGROUPS]?Cgroup = [_]?Cgroup{null} ** MAX_CGROUPS,
    cgroup_count: u32 = 0,
    next_id: u32 = 1,

    // Statistics
    total_created: u64 = 0,
    total_destroyed: u64 = 0,
    total_migrations: u64 = 0,

    pub fn init(self: *CgroupManager) void {
        // Create root cgroup
        var root = Cgroup{};
        root.id = 0;
        root.set_name("/");
        root.controllers = ControllerMask.all();
        root.subtree_control = ControllerMask.all();
        self.cgroups[0] = root;
        self.cgroup_count = 1;
    }

    /// Create a new cgroup under the given parent
    pub fn create(self: *CgroupManager, parent_id: u32, name: []const u8) ?u32 {
        if (self.cgroup_count >= MAX_CGROUPS) return null;

        // Find parent
        var parent = self.find_mut(parent_id) orelse return null;

        // Check depth limit
        if (parent.depth >= MAX_CGROUP_DEPTH) return null;

        // Cannot create children if parent has processes (no internal processes rule)
        // However, we allow it for the root cgroup
        if (parent_id != 0 and parent.proc_count > 0) return null;

        const id = self.next_id;
        self.next_id += 1;

        var cg = Cgroup{};
        cg.id = id;
        cg.parent_id = parent_id;
        cg.depth = parent.depth + 1;
        cg.set_name(name);

        // Inherit controllers from parent's subtree_control
        cg.controllers = parent.subtree_control;

        // Add as child of parent
        if (!parent.add_child(id)) return null;

        // Find free slot
        for (&self.cgroups) |*slot| {
            if (slot.* == null) {
                slot.* = cg;
                self.cgroup_count += 1;
                self.total_created += 1;
                return id;
            }
        }

        return null;
    }

    /// Destroy a cgroup (must be empty)
    pub fn destroy(self: *CgroupManager, id: u32) bool {
        if (id == 0) return false; // Can't destroy root

        const cg = self.find(id) orelse return false;
        if (cg.child_count > 0 or cg.proc_count > 0) return false;

        const parent_id = cg.parent_id;

        // Remove from parent
        if (self.find_mut(parent_id)) |parent| {
            _ = parent.remove_child(id);
        }

        // Remove the cgroup
        for (&self.cgroups) |*slot| {
            if (slot.*) |*existing| {
                if (existing.id == id) {
                    existing.state = .destroyed;
                    slot.* = null;
                    if (self.cgroup_count > 0) self.cgroup_count -= 1;
                    self.total_destroyed += 1;
                    return true;
                }
            }
        }

        return false;
    }

    /// Migrate a process from one cgroup to another
    pub fn migrate_process(self: *CgroupManager, pid: u32, from_id: u32, to_id: u32) bool {
        // Remove from old cgroup
        if (self.find_mut(from_id)) |from_cg| {
            _ = from_cg.remove_process(pid);
        }

        // Add to new cgroup
        if (self.find_mut(to_id)) |to_cg| {
            if (to_cg.add_process(pid)) {
                self.total_migrations += 1;
                return true;
            }
        }

        return false;
    }

    /// Set subtree control for a cgroup
    pub fn set_subtree_control(self: *CgroupManager, id: u32, mask: ControllerMask) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.subtree_control = mask;
        return true;
    }

    /// Set CPU weight for a cgroup
    pub fn set_cpu_weight(self: *CgroupManager, id: u32, weight: u32) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.cpu.set_weight(weight);
        return true;
    }

    /// Set CPU max (quota/period) for a cgroup
    pub fn set_cpu_max(self: *CgroupManager, id: u32, quota: i64, period: u64) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.cpu.set_max(quota, period);
        return true;
    }

    /// Set memory max for a cgroup
    pub fn set_memory_max(self: *CgroupManager, id: u32, max_bytes: u64) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.memory.max = max_bytes;
        return true;
    }

    /// Set memory high for a cgroup
    pub fn set_memory_high(self: *CgroupManager, id: u32, high_bytes: u64) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.memory.high = high_bytes;
        return true;
    }

    /// Set PID max for a cgroup
    pub fn set_pids_max(self: *CgroupManager, id: u32, max_pids: u32) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.pids.max = max_pids;
        return true;
    }

    /// Freeze a cgroup
    pub fn freeze_cgroup(self: *CgroupManager, id: u32) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.freeze();
        return true;
    }

    /// Thaw a cgroup
    pub fn thaw_cgroup(self: *CgroupManager, id: u32) bool {
        const cg = self.find_mut(id) orelse return false;
        cg.thaw();
        return true;
    }

    /// Timer tick: refill CPU quotas for all cgroups
    pub fn tick(self: *CgroupManager) void {
        for (&self.cgroups) |*slot| {
            if (slot.*) |*cg| {
                if (cg.state == .active and cg.controllers.cpu) {
                    cg.cpu.refill_quota();
                }
            }
        }
    }

    pub fn find(self: *const CgroupManager, id: u32) ?*const Cgroup {
        for (&self.cgroups) |*slot| {
            if (slot.*) |*cg| {
                if (cg.id == id) return cg;
            }
        }
        return null;
    }

    pub fn find_mut(self: *CgroupManager, id: u32) ?*Cgroup {
        for (&self.cgroups) |*slot| {
            if (slot.*) |*cg| {
                if (cg.id == id) return cg;
            }
        }
        return null;
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var cgroup_manager: CgroupManager = .{};
var cgroup_initialized = false;

pub fn init() void {
    cgroup_manager.init();
    cgroup_initialized = true;
}

pub fn getManager() *CgroupManager {
    return &cgroup_manager;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_cgroup_init() void {
    init();
}

export fn zxy_cgroup_create(parent_id: u32, name_ptr: [*]const u8, name_len: u32) i32 {
    if (!cgroup_initialized) return -1;
    const name = name_ptr[0..name_len];
    return if (cgroup_manager.create(parent_id, name)) |id| @intCast(id) else -1;
}

export fn zxy_cgroup_destroy(id: u32) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.destroy(id);
}

export fn zxy_cgroup_migrate(pid: u32, from_id: u32, to_id: u32) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.migrate_process(pid, from_id, to_id);
}

export fn zxy_cgroup_set_cpu_weight(id: u32, weight: u32) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.set_cpu_weight(id, weight);
}

export fn zxy_cgroup_set_cpu_max(id: u32, quota: i64, period: u64) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.set_cpu_max(id, quota, period);
}

export fn zxy_cgroup_set_memory_max(id: u32, max_bytes: u64) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.set_memory_max(id, max_bytes);
}

export fn zxy_cgroup_set_memory_high(id: u32, high_bytes: u64) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.set_memory_high(id, high_bytes);
}

export fn zxy_cgroup_set_pids_max(id: u32, max_pids: u32) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.set_pids_max(id, max_pids);
}

export fn zxy_cgroup_freeze(id: u32) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.freeze_cgroup(id);
}

export fn zxy_cgroup_thaw(id: u32) bool {
    if (!cgroup_initialized) return false;
    return cgroup_manager.thaw_cgroup(id);
}

export fn zxy_cgroup_add_process(id: u32, pid: u32) bool {
    if (!cgroup_initialized) return false;
    const cg = cgroup_manager.find_mut(id) orelse return false;
    return cg.add_process(pid);
}

export fn zxy_cgroup_tick() void {
    if (cgroup_initialized) cgroup_manager.tick();
}

export fn zxy_cgroup_count() u32 {
    return cgroup_manager.cgroup_count;
}
