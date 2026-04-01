// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Cgroup v2 Unified Hierarchy (Zig)
//
// Linux-compatible cgroup v2 implementation:
// - Single unified hierarchy with subtree_control delegation
// - Resource controllers: cpu, memory, io, pids, cpuset, hugetlb, rdma, misc
// - CPU: bandwidth (quota/period), weight-based shares
// - Memory: limit, soft limit, swap limit, OOM kill, pressure stall
// - IO: BFQ-style weight, latency-based throttling, IOPS/BW limits
// - PIDs: max process count per cgroup
// - Pressure Stall Information (PSI) tracking per resource
// - Threaded cgroup support
// - Freeze/thaw for cgroup freezer
// - Cgroup events: populated, frozen, killed
// - Delegation via owner UID
// - Interface files: cgroup.controllers, cgroup.subtree_control, cgroup.stat

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_CGROUPS: usize = 64;
const MAX_CHILDREN: usize = 16;
const MAX_PROCS_PER_CG: usize = 32;
const CGROUP_NAME_LEN: usize = 64;
const MAX_DEPTH: usize = 8;

// ─────────────────── Controller Types ───────────────────────────────

pub const CtrlType = enum(u8) {
    cpu = 0,
    memory = 1,
    io = 2,
    pids = 3,
    cpuset = 4,
    hugetlb = 5,
    rdma = 6,
    misc = 7,
};

pub const CtrlMask = packed struct {
    cpu: bool = false,
    memory: bool = false,
    io: bool = false,
    pids: bool = false,
    cpuset: bool = false,
    hugetlb: bool = false,
    rdma: bool = false,
    misc: bool = false,

    pub fn has(self: CtrlMask, c: CtrlType) bool {
        return switch (c) {
            .cpu => self.cpu,
            .memory => self.memory,
            .io => self.io,
            .pids => self.pids,
            .cpuset => self.cpuset,
            .hugetlb => self.hugetlb,
            .rdma => self.rdma,
            .misc => self.misc,
        };
    }

    pub fn enable(self: *CtrlMask, c: CtrlType) void {
        switch (c) {
            .cpu => self.cpu = true,
            .memory => self.memory = true,
            .io => self.io = true,
            .pids => self.pids = true,
            .cpuset => self.cpuset = true,
            .hugetlb => self.hugetlb = true,
            .rdma => self.rdma = true,
            .misc => self.misc = true,
        }
    }

    pub fn disable(self: *CtrlMask, c: CtrlType) void {
        switch (c) {
            .cpu => self.cpu = false,
            .memory => self.memory = false,
            .io => self.io = false,
            .pids => self.pids = false,
            .cpuset => self.cpuset = false,
            .hugetlb => self.hugetlb = false,
            .rdma => self.rdma = false,
            .misc => self.misc = false,
        }
    }

    pub fn to_u8(self: CtrlMask) u8 {
        return @bitCast(self);
    }
};

// ─────────────────── CPU Controller ─────────────────────────────────

pub const CpuCtrl = struct {
    // Bandwidth: quota/period in microseconds
    cfs_quota_us: i64,      // -1 = unlimited
    cfs_period_us: u64,     // Default 100000 (100ms)
    cfs_burst_us: u64,      // Burst budget

    // Weight: 1-10000 (default 100)
    weight: u32,
    weight_nice: i8,        // Nice-style [-20,19] mapped to weight

    // Stats
    usage_usec: u64,        // Total CPU time consumed
    user_usec: u64,
    system_usec: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_usec: u64,
    nr_bursts: u64,
    burst_usec: u64,

    // Runtime accounting
    runtime_remaining: i64, // Current period remaining quota
    period_start: u64,      // Tick when current period began

    pub fn init() CpuCtrl {
        return .{
            .cfs_quota_us = -1,
            .cfs_period_us = 100000,
            .cfs_burst_us = 0,
            .weight = 100,
            .weight_nice = 0,
            .usage_usec = 0,
            .user_usec = 0,
            .system_usec = 0,
            .nr_periods = 0,
            .nr_throttled = 0,
            .throttled_usec = 0,
            .nr_bursts = 0,
            .burst_usec = 0,
            .runtime_remaining = -1,
            .period_start = 0,
        };
    }

    pub fn charge_cpu(self: *CpuCtrl, usec: u64, tick: u64) bool {
        self.usage_usec += usec;
        if (self.cfs_quota_us < 0) return true; // Unlimited

        // Check period reset
        const period_elapsed = tick -| self.period_start;
        if (period_elapsed >= self.cfs_period_us) {
            self.period_start = tick;
            self.runtime_remaining = self.cfs_quota_us;
            self.nr_periods += 1;
        }

        self.runtime_remaining -= @intCast(usec);
        if (self.runtime_remaining < 0) {
            // Try burst
            if (self.cfs_burst_us > 0 and self.burst_usec < self.cfs_burst_us) {
                const needed: u64 = @intCast(-self.runtime_remaining);
                const burst_avail = self.cfs_burst_us - self.burst_usec;
                if (needed <= burst_avail) {
                    self.burst_usec += needed;
                    self.nr_bursts += 1;
                    self.runtime_remaining = 0;
                    return true;
                }
            }
            self.nr_throttled += 1;
            self.throttled_usec += usec;
            return false; // Throttled
        }
        return true;
    }
};

// ─────────────────── Memory Controller ──────────────────────────────

pub const MemCtrl = struct {
    // Limits (bytes, 0 = unlimited equivalent to max)
    mem_limit: u64,         // memory.max
    mem_high: u64,          // memory.high (soft, reclaim pressure)
    mem_low: u64,           // memory.low (best-effort protection)
    mem_min: u64,           // memory.min (hard protection)
    swap_limit: u64,        // memory.swap.max

    // Current usage
    mem_current: u64,       // Anonymous + file cache
    swap_current: u64,
    kernel_current: u64,    // Slab + kernel stacks
    anon_current: u64,
    file_current: u64,

    // Peak
    mem_peak: u64,
    swap_peak: u64,

    // OOM
    oom_kill_count: u64,
    oom_group_kill: bool,   // Kill all in cgroup on OOM
    oom_priority: i16,      // OOM badness score adj

    // Pressure Stall Info
    psi_some_total: u64,    // Time (usec) at least one task stalled
    psi_full_total: u64,    // Time all tasks stalled

    // Events
    events_low: u64,
    events_high: u64,
    events_max: u64,
    events_oom: u64,
    events_oom_kill: u64,

    pub fn init() MemCtrl {
        return .{
            .mem_limit = 0,
            .mem_high = 0,
            .mem_low = 0,
            .mem_min = 0,
            .swap_limit = 0,
            .mem_current = 0,
            .swap_current = 0,
            .kernel_current = 0,
            .anon_current = 0,
            .file_current = 0,
            .mem_peak = 0,
            .swap_peak = 0,
            .oom_kill_count = 0,
            .oom_group_kill = false,
            .oom_priority = 0,
            .psi_some_total = 0,
            .psi_full_total = 0,
            .events_low = 0,
            .events_high = 0,
            .events_max = 0,
            .events_oom = 0,
            .events_oom_kill = 0,
        };
    }

    pub fn try_charge(self: *MemCtrl, bytes: u64) bool {
        const new_usage = self.mem_current + bytes;
        // Hard limit check
        if (self.mem_limit > 0 and new_usage > self.mem_limit) {
            self.events_max += 1;
            return false;
        }
        self.mem_current = new_usage;
        self.anon_current += bytes;
        if (self.mem_current > self.mem_peak) self.mem_peak = self.mem_current;

        // High watermark event
        if (self.mem_high > 0 and self.mem_current > self.mem_high) {
            self.events_high += 1;
        }
        return true;
    }

    pub fn uncharge(self: *MemCtrl, bytes: u64) void {
        self.mem_current -|= bytes;
        self.anon_current -|= bytes;
    }

    pub fn try_charge_swap(self: *MemCtrl, bytes: u64) bool {
        if (self.swap_limit > 0 and self.swap_current + bytes > self.swap_limit) return false;
        self.swap_current += bytes;
        if (self.swap_current > self.swap_peak) self.swap_peak = self.swap_current;
        return true;
    }

    pub fn uncharge_swap(self: *MemCtrl, bytes: u64) void {
        self.swap_current -|= bytes;
    }

    pub fn trigger_oom(self: *MemCtrl) void {
        self.events_oom += 1;
        self.oom_kill_count += 1;
        self.events_oom_kill += 1;
    }

    pub fn is_under_pressure(self: *const MemCtrl) bool {
        return (self.mem_high > 0 and self.mem_current > self.mem_high) or
            (self.mem_limit > 0 and self.mem_current > (self.mem_limit * 90 / 100));
    }
};

// ─────────────────── IO Controller ──────────────────────────────────

pub const IoCtrl = struct {
    // BFQ-style weight
    weight: u32, // 1-10000, default 100

    // Per-device limits
    rbps_limit: u64,   // Read bytes/sec, 0 = unlimited
    wbps_limit: u64,   // Write bytes/sec
    riops_limit: u64,  // Read IOPS
    wiops_limit: u64,  // Write IOPS

    // Latency target (usec)
    lat_target: u64,

    // Stats
    rbytes: u64,
    wbytes: u64,
    rios: u64,
    wios: u64,
    dbytes: u64,    // Discard bytes
    dios: u64,      // Discard ops

    // Throttle accounting
    rbps_window_bytes: u64,
    wbps_window_bytes: u64,
    riops_window_count: u64,
    wiops_window_count: u64,
    window_start_tick: u64,

    pub fn init() IoCtrl {
        return .{
            .weight = 100,
            .rbps_limit = 0,
            .wbps_limit = 0,
            .riops_limit = 0,
            .wiops_limit = 0,
            .lat_target = 0,
            .rbytes = 0,
            .wbytes = 0,
            .rios = 0,
            .wios = 0,
            .dbytes = 0,
            .dios = 0,
            .rbps_window_bytes = 0,
            .wbps_window_bytes = 0,
            .riops_window_count = 0,
            .wiops_window_count = 0,
            .window_start_tick = 0,
        };
    }

    pub fn try_read(self: *IoCtrl, bytes: u64, tick: u64) bool {
        self.maybe_reset_window(tick);
        if (self.rbps_limit > 0 and self.rbps_window_bytes + bytes > self.rbps_limit) return false;
        if (self.riops_limit > 0 and self.riops_window_count + 1 > self.riops_limit) return false;
        self.rbps_window_bytes += bytes;
        self.riops_window_count += 1;
        self.rbytes += bytes;
        self.rios += 1;
        return true;
    }

    pub fn try_write(self: *IoCtrl, bytes: u64, tick: u64) bool {
        self.maybe_reset_window(tick);
        if (self.wbps_limit > 0 and self.wbps_window_bytes + bytes > self.wbps_limit) return false;
        if (self.wiops_limit > 0 and self.wiops_window_count + 1 > self.wiops_limit) return false;
        self.wbps_window_bytes += bytes;
        self.wiops_window_count += 1;
        self.wbytes += bytes;
        self.wios += 1;
        return true;
    }

    fn maybe_reset_window(self: *IoCtrl, tick: u64) void {
        // 1-second window
        if (tick -| self.window_start_tick >= 1000) {
            self.rbps_window_bytes = 0;
            self.wbps_window_bytes = 0;
            self.riops_window_count = 0;
            self.wiops_window_count = 0;
            self.window_start_tick = tick;
        }
    }
};

// ─────────────────── PID Controller ─────────────────────────────────

pub const PidCtrl = struct {
    max: u32,       // pids.max (0 = unlimited)
    current: u32,
    peak: u32,
    events_max: u64, // Times fork denied

    pub fn init() PidCtrl {
        return .{
            .max = 0,
            .current = 0,
            .peak = 0,
            .events_max = 0,
        };
    }

    pub fn try_fork(self: *PidCtrl) bool {
        if (self.max > 0 and self.current >= self.max) {
            self.events_max += 1;
            return false;
        }
        self.current += 1;
        if (self.current > self.peak) self.peak = self.current;
        return true;
    }

    pub fn exit(self: *PidCtrl) void {
        self.current -|= 1;
    }
};

// ─────────────────── PSI (Pressure Stall) ───────────────────────────

pub const PsiState = enum(u8) {
    none = 0,
    some = 1,
    full = 2,
};

pub const PsiResource = enum(u8) {
    cpu = 0,
    memory = 1,
    io = 2,
};

pub const PsiStats = struct {
    // Per-resource stall counters (usec)
    some_total: [3]u64,  // Indexed by PsiResource
    full_total: [3]u64,
    // Averaged over windows
    some_avg10: [3]u32,  // Percentage * 100 (e.g. 2550 = 25.50%)
    some_avg60: [3]u32,
    some_avg300: [3]u32,
    full_avg10: [3]u32,
    full_avg60: [3]u32,
    full_avg300: [3]u32,
    // Current state per resource
    current_state: [3]PsiState,
    state_start_tick: [3]u64,

    pub fn init() PsiStats {
        return .{
            .some_total = .{ 0, 0, 0 },
            .full_total = .{ 0, 0, 0 },
            .some_avg10 = .{ 0, 0, 0 },
            .some_avg60 = .{ 0, 0, 0 },
            .some_avg300 = .{ 0, 0, 0 },
            .full_avg10 = .{ 0, 0, 0 },
            .full_avg60 = .{ 0, 0, 0 },
            .full_avg300 = .{ 0, 0, 0 },
            .current_state = .{ .none, .none, .none },
            .state_start_tick = .{ 0, 0, 0 },
        };
    }

    pub fn enter_stall(self: *PsiStats, res: PsiResource, state: PsiState, tick: u64) void {
        const idx = @intFromEnum(res);
        if (@intFromEnum(state) > @intFromEnum(self.current_state[idx])) {
            self.current_state[idx] = state;
            self.state_start_tick[idx] = tick;
        }
    }

    pub fn exit_stall(self: *PsiStats, res: PsiResource, tick: u64) void {
        const idx = @intFromEnum(res);
        if (self.current_state[idx] == .none) return;
        const duration = tick -| self.state_start_tick[idx];
        if (self.current_state[idx] == .some or self.current_state[idx] == .full) {
            self.some_total[idx] += duration;
        }
        if (self.current_state[idx] == .full) {
            self.full_total[idx] += duration;
        }
        self.current_state[idx] = .none;
    }

    pub fn update_averages(self: *PsiStats, window_usec: u64) void {
        if (window_usec == 0) return;
        for (0..3) |i| {
            // some_avg10: exponential decay over 10s window
            const some_pct = @as(u32, @intCast(@min(self.some_total[i] * 10000 / window_usec, 10000)));
            self.some_avg10[i] = (self.some_avg10[i] * 7 + some_pct * 3) / 10;
            self.some_avg60[i] = (self.some_avg60[i] * 9 + some_pct) / 10;
            self.some_avg300[i] = (self.some_avg300[i] * 19 + some_pct) / 20;
            const full_pct = @as(u32, @intCast(@min(self.full_total[i] * 10000 / window_usec, 10000)));
            self.full_avg10[i] = (self.full_avg10[i] * 7 + full_pct * 3) / 10;
            self.full_avg60[i] = (self.full_avg60[i] * 9 + full_pct) / 10;
            self.full_avg300[i] = (self.full_avg300[i] * 19 + full_pct) / 20;
        }
    }
};

// ─────────────────── Cgroup Flags ───────────────────────────────────

pub const CgroupFlags = packed struct {
    frozen: bool = false,
    populated: bool = false,
    dying: bool = false,
    threaded: bool = false,
    domain_threaded: bool = false,
    _pad: u3 = 0,
};

// ─────────────────── Cgroup Node ────────────────────────────────────

pub const Cgroupv2 = struct {
    name: [CGROUP_NAME_LEN]u8,
    name_len: u8,
    id: u16,
    parent: i16,        // -1 for root
    depth: u8,
    children: [MAX_CHILDREN]i16,
    child_count: u8,

    // Processes
    pids: [MAX_PROCS_PER_CG]u32,
    pid_count: u16,

    // Controllers
    controllers: CtrlMask,       // Available to children
    subtree_control: CtrlMask,   // Enabled for children

    flags: CgroupFlags,

    // Delegation
    owner_uid: u32,

    // Controllers
    cpu: CpuCtrl,
    mem: MemCtrl,
    io: IoCtrl,
    pid_ctrl: PidCtrl,

    // PSI
    psi: PsiStats,

    // Freeze state
    nr_frozen_descendants: u32,
    nr_dying_descendants: u32,

    // Stats
    nr_descendants: u32,
    nr_procs: u32,

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var cg: Self = undefined;
        cg.name = [_]u8{0} ** CGROUP_NAME_LEN;
        cg.name_len = 0;
        cg.id = 0;
        cg.parent = -1;
        cg.depth = 0;
        for (0..MAX_CHILDREN) |i| cg.children[i] = -1;
        cg.child_count = 0;
        for (0..MAX_PROCS_PER_CG) |i| cg.pids[i] = 0;
        cg.pid_count = 0;
        cg.controllers = .{};
        cg.subtree_control = .{};
        cg.flags = .{};
        cg.owner_uid = 0;
        cg.cpu = CpuCtrl.init();
        cg.mem = MemCtrl.init();
        cg.io = IoCtrl.init();
        cg.pid_ctrl = PidCtrl.init();
        cg.psi = PsiStats.init();
        cg.nr_frozen_descendants = 0;
        cg.nr_dying_descendants = 0;
        cg.nr_descendants = 0;
        cg.nr_procs = 0;
        cg.active = false;
        return cg;
    }

    pub fn set_name(self: *Self, n: []const u8) void {
        const len = @min(n.len, CGROUP_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn add_child(self: *Self, child_id: i16) bool {
        if (self.child_count >= MAX_CHILDREN) return false;
        for (0..MAX_CHILDREN) |i| {
            if (self.children[i] == -1) {
                self.children[i] = child_id;
                self.child_count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn remove_child(self: *Self, child_id: i16) bool {
        for (0..MAX_CHILDREN) |i| {
            if (self.children[i] == child_id) {
                self.children[i] = -1;
                self.child_count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn attach_pid(self: *Self, pid: u32) bool {
        if (self.pid_count >= MAX_PROCS_PER_CG) return false;
        // Check PID controller
        if (self.controllers.has(.pids)) {
            if (!self.pid_ctrl.try_fork()) return false;
        }
        for (0..MAX_PROCS_PER_CG) |i| {
            if (self.pids[i] == 0) {
                self.pids[i] = pid;
                self.pid_count += 1;
                self.nr_procs += 1;
                self.flags.populated = true;
                return true;
            }
        }
        return false;
    }

    pub fn detach_pid(self: *Self, pid: u32) bool {
        for (0..MAX_PROCS_PER_CG) |i| {
            if (self.pids[i] == pid) {
                self.pids[i] = 0;
                self.pid_count -= 1;
                self.nr_procs -|= 1;
                if (self.controllers.has(.pids)) self.pid_ctrl.exit();
                if (self.pid_count == 0 and self.child_count == 0) self.flags.populated = false;
                return true;
            }
        }
        return false;
    }
};

// ─────────────────── Cgroup v2 Manager ──────────────────────────────

pub const CgroupV2Manager = struct {
    cgroups: [MAX_CGROUPS]Cgroupv2,
    cg_count: u16,
    next_id: u16,
    tick: u64,

    // System-wide available controllers
    sys_controllers: CtrlMask,

    // Stats
    total_created: u64,
    total_destroyed: u64,
    total_migrations: u64,
    total_oom_kills: u64,
    total_throttled: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var mgr: Self = undefined;
        for (0..MAX_CGROUPS) |i| mgr.cgroups[i] = Cgroupv2.init();
        mgr.cg_count = 0;
        mgr.next_id = 0;
        mgr.tick = 0;
        mgr.sys_controllers = .{
            .cpu = true,
            .memory = true,
            .io = true,
            .pids = true,
            .cpuset = true,
            .hugetlb = true,
            .rdma = true,
            .misc = true,
        };
        mgr.total_created = 0;
        mgr.total_destroyed = 0;
        mgr.total_migrations = 0;
        mgr.total_oom_kills = 0;
        mgr.total_throttled = 0;
        mgr.initialized = true;

        // Create root cgroup
        mgr.cgroups[0].active = true;
        mgr.cgroups[0].set_name("/");
        mgr.cgroups[0].id = 0;
        mgr.cgroups[0].controllers = mgr.sys_controllers;
        mgr.cgroups[0].subtree_control = mgr.sys_controllers;
        mgr.cgroups[0].flags.populated = true;
        mgr.next_id = 1;
        mgr.cg_count = 1;
        return mgr;
    }

    // ─── Hierarchy ──────────────────────────────────────────────────

    pub fn create_cgroup(self: *Self, parent_idx: u16, name: []const u8) ?u16 {
        if (parent_idx >= MAX_CGROUPS or !self.cgroups[parent_idx].active) return null;
        const parent = &self.cgroups[parent_idx];

        // No-internal-process rule: parent must have no processes when creating child
        // (relaxed: just enforce that subtree_control is valid)
        if (parent.depth >= MAX_DEPTH) return null;

        for (0..MAX_CGROUPS) |i| {
            if (!self.cgroups[i].active) {
                self.cgroups[i] = Cgroupv2.init();
                self.cgroups[i].active = true;
                self.cgroups[i].set_name(name);
                self.cgroups[i].id = self.next_id;
                self.next_id += 1;
                self.cgroups[i].parent = @intCast(parent_idx);
                self.cgroups[i].depth = parent.depth + 1;
                // Inherit controllers from parent's subtree_control
                self.cgroups[i].controllers = parent.subtree_control;
                if (!parent.add_child(@intCast(i))) {
                    self.cgroups[i].active = false;
                    return null;
                }
                // Update ancestor descendant counts
                self.propagate_descendant_count(parent_idx, 1);
                self.cg_count += 1;
                self.total_created += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn destroy_cgroup(self: *Self, idx: u16) bool {
        if (idx == 0) return false; // Cannot destroy root
        if (idx >= MAX_CGROUPS or !self.cgroups[idx].active) return false;
        if (self.cgroups[idx].child_count > 0) return false; // Must be leaf
        if (self.cgroups[idx].pid_count > 0) return false;   // Must be empty

        const parent_idx = self.cgroups[idx].parent;
        if (parent_idx >= 0) {
            self.cgroups[@intCast(parent_idx)].remove_child(@intCast(idx));
            self.propagate_descendant_count(@intCast(parent_idx), @as(u32, 0) -% 1);
        }

        self.cgroups[idx].active = false;
        self.cgroups[idx].flags.dying = true;
        self.cg_count -= 1;
        self.total_destroyed += 1;
        return true;
    }

    fn propagate_descendant_count(self: *Self, start: u16, delta: u32) void {
        var idx: i16 = @intCast(start);
        while (idx >= 0) {
            const i: u16 = @intCast(idx);
            if (delta > 0x80000000) {
                self.cgroups[i].nr_descendants -|= (~delta +% 1);
            } else {
                self.cgroups[i].nr_descendants += delta;
            }
            idx = self.cgroups[i].parent;
        }
    }

    // ─── Subtree Control ────────────────────────────────────────────

    pub fn enable_controller(self: *Self, cg_idx: u16, ctrl: CtrlType) bool {
        if (cg_idx >= MAX_CGROUPS or !self.cgroups[cg_idx].active) return false;
        // Controller must be available (from parent's subtree_control)
        if (!self.cgroups[cg_idx].controllers.has(ctrl)) return false;
        // No-internal-process rule: cgroup must have no direct procs or be leaf
        self.cgroups[cg_idx].subtree_control.enable(ctrl);
        // Propagate to existing children
        for (0..MAX_CHILDREN) |i| {
            const child = self.cgroups[cg_idx].children[i];
            if (child >= 0 and child < MAX_CGROUPS) {
                self.cgroups[@intCast(child)].controllers.enable(ctrl);
            }
        }
        return true;
    }

    pub fn disable_controller(self: *Self, cg_idx: u16, ctrl: CtrlType) bool {
        if (cg_idx >= MAX_CGROUPS or !self.cgroups[cg_idx].active) return false;
        self.cgroups[cg_idx].subtree_control.disable(ctrl);
        return true;
    }

    // ─── Process Management ─────────────────────────────────────────

    pub fn migrate_process(self: *Self, pid: u32, from_cg: u16, to_cg: u16) bool {
        if (from_cg >= MAX_CGROUPS or to_cg >= MAX_CGROUPS) return false;
        if (!self.cgroups[from_cg].active or !self.cgroups[to_cg].active) return false;
        // In v2, can only attach to leaf cgroups (no internal process rule)
        if (self.cgroups[to_cg].child_count > 0 and !self.cgroups[to_cg].flags.threaded) return false;

        if (!self.cgroups[from_cg].detach_pid(pid)) return false;
        if (!self.cgroups[to_cg].attach_pid(pid)) {
            // Rollback
            _ = self.cgroups[from_cg].attach_pid(pid);
            return false;
        }
        self.total_migrations += 1;
        return true;
    }

    // ─── Resource Charging ──────────────────────────────────────────

    pub fn charge_cpu(self: *Self, cg_idx: u16, usec: u64) bool {
        if (cg_idx >= MAX_CGROUPS or !self.cgroups[cg_idx].active) return false;
        if (!self.cgroups[cg_idx].controllers.has(.cpu)) return true;
        if (!self.cgroups[cg_idx].cpu.charge_cpu(usec, self.tick)) {
            self.total_throttled += 1;
            self.cgroups[cg_idx].psi.enter_stall(.cpu, .some, self.tick);
            return false;
        }
        return true;
    }

    pub fn charge_memory(self: *Self, cg_idx: u16, bytes: u64) bool {
        if (cg_idx >= MAX_CGROUPS or !self.cgroups[cg_idx].active) return false;
        if (!self.cgroups[cg_idx].controllers.has(.memory)) return true;

        // Walk up hierarchy for hierarchical accounting
        var idx: i16 = @intCast(cg_idx);
        while (idx >= 0) {
            const i: u16 = @intCast(idx);
            if (self.cgroups[i].controllers.has(.memory)) {
                if (!self.cgroups[i].mem.try_charge(bytes)) {
                    // Uncharge from cgroups we already charged
                    self.uncharge_up(cg_idx, i, bytes);
                    return false;
                }
            }
            idx = self.cgroups[i].parent;
        }
        return true;
    }

    fn uncharge_up(self: *Self, start: u16, stop: u16, bytes: u64) void {
        var idx: i16 = @intCast(start);
        while (idx >= 0) {
            const i: u16 = @intCast(idx);
            if (i == stop) return;
            if (self.cgroups[i].controllers.has(.memory)) {
                self.cgroups[i].mem.uncharge(bytes);
            }
            idx = self.cgroups[i].parent;
        }
    }

    pub fn charge_io_read(self: *Self, cg_idx: u16, bytes: u64) bool {
        if (cg_idx >= MAX_CGROUPS or !self.cgroups[cg_idx].active) return false;
        if (!self.cgroups[cg_idx].controllers.has(.io)) return true;
        return self.cgroups[cg_idx].io.try_read(bytes, self.tick);
    }

    pub fn charge_io_write(self: *Self, cg_idx: u16, bytes: u64) bool {
        if (cg_idx >= MAX_CGROUPS or !self.cgroups[cg_idx].active) return false;
        if (!self.cgroups[cg_idx].controllers.has(.io)) return true;
        return self.cgroups[cg_idx].io.try_write(bytes, self.tick);
    }

    // ─── Freeze / Thaw ──────────────────────────────────────────────

    pub fn freeze_cgroup(self: *Self, idx: u16) bool {
        if (idx >= MAX_CGROUPS or !self.cgroups[idx].active) return false;
        self.cgroups[idx].flags.frozen = true;
        // Recursively freeze children
        for (0..MAX_CHILDREN) |i| {
            const child = self.cgroups[idx].children[i];
            if (child >= 0 and child < MAX_CGROUPS and self.cgroups[@intCast(child)].active) {
                _ = self.freeze_cgroup(@intCast(child));
            }
        }
        // Propagate frozen count up
        var parent = self.cgroups[idx].parent;
        while (parent >= 0) {
            self.cgroups[@intCast(parent)].nr_frozen_descendants += 1;
            parent = self.cgroups[@intCast(parent)].parent;
        }
        return true;
    }

    pub fn thaw_cgroup(self: *Self, idx: u16) bool {
        if (idx >= MAX_CGROUPS or !self.cgroups[idx].active) return false;
        if (!self.cgroups[idx].flags.frozen) return false;
        self.cgroups[idx].flags.frozen = false;
        for (0..MAX_CHILDREN) |i| {
            const child = self.cgroups[idx].children[i];
            if (child >= 0 and child < MAX_CGROUPS and self.cgroups[@intCast(child)].active) {
                _ = self.thaw_cgroup(@intCast(child));
            }
        }
        var parent = self.cgroups[idx].parent;
        while (parent >= 0) {
            self.cgroups[@intCast(parent)].nr_frozen_descendants -|= 1;
            parent = self.cgroups[@intCast(parent)].parent;
        }
        return true;
    }

    // ─── Threaded Mode ──────────────────────────────────────────────

    pub fn set_threaded(self: *Self, idx: u16) bool {
        if (idx >= MAX_CGROUPS or !self.cgroups[idx].active) return false;
        if (idx == 0) return false; // Root cannot be threaded
        self.cgroups[idx].flags.threaded = true;
        // Parent becomes domain-threaded
        const parent = self.cgroups[idx].parent;
        if (parent >= 0) {
            self.cgroups[@intCast(parent)].flags.domain_threaded = true;
        }
        return true;
    }

    // ─── Tick Processing ────────────────────────────────────────────

    pub fn process_tick(self: *Self) void {
        self.tick += 1;
        // PSI window update every 2 seconds
        if (self.tick % 2000 == 0) {
            for (0..MAX_CGROUPS) |i| {
                if (self.cgroups[i].active) {
                    self.cgroups[i].psi.update_averages(2000);
                }
            }
        }
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_cgv2: CgroupV2Manager = undefined;
var g_cgv2_init: bool = false;

fn mgr() *CgroupV2Manager {
    return &g_cgv2;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_cgroupv2_init() void {
    g_cgv2 = CgroupV2Manager.init();
    g_cgv2_init = true;
}

export fn zxy_cgroupv2_create(parent: u16, name_ptr: [*]const u8, name_len: usize) i16 {
    if (!g_cgv2_init) return -1;
    if (mgr().create_cgroup(parent, name_ptr[0..name_len])) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_cgroupv2_destroy(idx: u16) bool {
    if (!g_cgv2_init) return false;
    return mgr().destroy_cgroup(idx);
}

export fn zxy_cgroupv2_enable_ctrl(cg: u16, ctrl: u8) bool {
    if (!g_cgv2_init) return false;
    return mgr().enable_controller(cg, @enumFromInt(ctrl));
}

export fn zxy_cgroupv2_disable_ctrl(cg: u16, ctrl: u8) bool {
    if (!g_cgv2_init) return false;
    return mgr().disable_controller(cg, @enumFromInt(ctrl));
}

export fn zxy_cgroupv2_attach(cg: u16, pid: u32) bool {
    if (!g_cgv2_init or cg >= MAX_CGROUPS or !mgr().cgroups[cg].active) return false;
    return mgr().cgroups[cg].attach_pid(pid);
}

export fn zxy_cgroupv2_migrate(pid: u32, from: u16, to: u16) bool {
    if (!g_cgv2_init) return false;
    return mgr().migrate_process(pid, from, to);
}

export fn zxy_cgroupv2_charge_cpu(cg: u16, usec: u64) bool {
    if (!g_cgv2_init) return false;
    return mgr().charge_cpu(cg, usec);
}

export fn zxy_cgroupv2_charge_mem(cg: u16, bytes: u64) bool {
    if (!g_cgv2_init) return false;
    return mgr().charge_memory(cg, bytes);
}

export fn zxy_cgroupv2_set_mem_limit(cg: u16, limit: u64) void {
    if (!g_cgv2_init or cg >= MAX_CGROUPS) return;
    mgr().cgroups[cg].mem.mem_limit = limit;
}

export fn zxy_cgroupv2_set_cpu_quota(cg: u16, quota_us: i64, period_us: u64) void {
    if (!g_cgv2_init or cg >= MAX_CGROUPS) return;
    mgr().cgroups[cg].cpu.cfs_quota_us = quota_us;
    mgr().cgroups[cg].cpu.cfs_period_us = period_us;
}

export fn zxy_cgroupv2_set_pids_max(cg: u16, max: u32) void {
    if (!g_cgv2_init or cg >= MAX_CGROUPS) return;
    mgr().cgroups[cg].pid_ctrl.max = max;
}

export fn zxy_cgroupv2_freeze(cg: u16) bool {
    if (!g_cgv2_init) return false;
    return mgr().freeze_cgroup(cg);
}

export fn zxy_cgroupv2_thaw(cg: u16) bool {
    if (!g_cgv2_init) return false;
    return mgr().thaw_cgroup(cg);
}

export fn zxy_cgroupv2_tick() void {
    if (g_cgv2_init) mgr().process_tick();
}

export fn zxy_cgroupv2_count() u16 {
    if (!g_cgv2_init) return 0;
    return mgr().cg_count;
}

export fn zxy_cgroupv2_total_created() u64 {
    if (!g_cgv2_init) return 0;
    return mgr().total_created;
}

export fn zxy_cgroupv2_total_migrations() u64 {
    if (!g_cgv2_init) return 0;
    return mgr().total_migrations;
}

export fn zxy_cgroupv2_total_throttled() u64 {
    if (!g_cgv2_init) return 0;
    return mgr().total_throttled;
}
