// SPDX-License-Identifier: MIT
// Zxyphor Kernel — PID Namespace Subsystem (Zig)
//
// Linux-compatible PID namespace implementation:
// - Hierarchical PID namespaces (nested)
// - Per-namespace PID allocation with translation
// - Init process (PID 1) per namespace
// - PID translation: namespace-local ↔ global
// - Process visibility: only see PIDs in own/descendant NS
// - Reaping: orphaned processes reparented to NS init
// - /proc virtualization support (per-NS PID views)
// - Namespace unshare/setns support
// - Signal delivery respects namespace boundaries

const std = @import("std");

// ─────────── Constants ──────────────────────────────────────────────

const MAX_PID_NAMESPACES: u16 = 32;
const MAX_PIDS_PER_NS: u16 = 256;
const MAX_NS_DEPTH: u8 = 8;
const PID_INVALID: u32 = 0;

// ─────────── PID Entry ──────────────────────────────────────────────

pub const PidEntry = struct {
    /// PID within this namespace
    ns_pid: u32,
    /// Global (root NS) PID
    global_pid: u32,
    /// Owning task's state
    state: PidState,
    /// Parent PID (within this namespace)
    parent_ns_pid: u32,
    /// Active flag
    active: bool,
};

pub const PidState = enum(u8) {
    running = 0,
    sleeping = 1,
    stopped = 2,
    zombie = 3,
    dead = 4,
};

const EMPTY_PID_ENTRY: PidEntry = .{
    .ns_pid = PID_INVALID,
    .global_pid = PID_INVALID,
    .state = .dead,
    .parent_ns_pid = PID_INVALID,
    .active = false,
};

// ─────────── PID Namespace ──────────────────────────────────────────

pub const PidNamespace = struct {
    /// Namespace ID (unique)
    id: u16,
    /// Parent namespace index (-1 for root)
    parent_idx: i16,
    /// Depth in hierarchy (root = 0)
    depth: u8,
    /// Creator UID
    owner_uid: u32,

    /// PID table for this namespace
    pids: [MAX_PIDS_PER_NS]PidEntry,
    pid_count: u16,
    next_pid: u32,

    /// Init process PID (always 1 in this NS)
    init_global_pid: u32,

    /// Child namespace count
    child_count: u16,

    /// Reference count
    ref_count: u32,

    /// Flags
    active: bool,
    reboot_signal: u8,   // Signal sent to NS on reboot (default: SIGKILL=9)

    /// Stats
    total_forks: u64,
    total_exits: u64,
    total_reaps: u64,
};

const EMPTY_PID_NS: PidNamespace = .{
    .id = 0,
    .parent_idx = -1,
    .depth = 0,
    .owner_uid = 0,
    .pids = [_]PidEntry{EMPTY_PID_ENTRY} ** MAX_PIDS_PER_NS,
    .pid_count = 0,
    .next_pid = 1,
    .init_global_pid = PID_INVALID,
    .child_count = 0,
    .ref_count = 0,
    .active = false,
    .reboot_signal = 9,
    .total_forks = 0,
    .total_exits = 0,
    .total_reaps = 0,
};

// ─────────── PID NS Level (for multi-level PID views) ──────────────

/// A process visible in multiple namespaces has one PidNsLevel per NS
pub const PidNsLevel = struct {
    ns_idx: i16,       // Namespace index
    ns_pid: u32,       // PID within that namespace
};

/// Per-process PID across all visible namespaces
pub const ProcessPids = struct {
    global_pid: u32,
    levels: [MAX_NS_DEPTH]PidNsLevel,
    level_count: u8,
};

const EMPTY_PROCESS_PIDS: ProcessPids = .{
    .global_pid = PID_INVALID,
    .levels = [_]PidNsLevel{.{ .ns_idx = -1, .ns_pid = PID_INVALID }} ** MAX_NS_DEPTH,
    .level_count = 0,
};

// ─────────── PID Namespace Manager ──────────────────────────────────

pub const PidNsManager = struct {
    namespaces: [MAX_PID_NAMESPACES]PidNamespace,
    ns_count: u16,
    next_ns_id: u16,

    /// Process PID tracking (global PID → multi-NS PIDs)
    process_pids: [512]ProcessPids,
    process_count: u32,
    next_global_pid: u32,

    /// Stats
    total_ns_created: u64,
    total_ns_destroyed: u64,
    total_pid_translations: u64,
    total_signal_crosses: u64,

    tick: u64,
    initialized: bool,

    // ─── Initialize ─────────────────────────────────────────────

    pub fn init(self: *PidNsManager) void {
        self.* = .{
            .namespaces = [_]PidNamespace{EMPTY_PID_NS} ** MAX_PID_NAMESPACES,
            .ns_count = 0,
            .next_ns_id = 1,
            .process_pids = [_]ProcessPids{EMPTY_PROCESS_PIDS} ** 512,
            .process_count = 0,
            .next_global_pid = 1,
            .total_ns_created = 0,
            .total_ns_destroyed = 0,
            .total_pid_translations = 0,
            .total_signal_crosses = 0,
            .tick = 0,
            .initialized = true,
        };

        // Create root PID namespace
        _ = self.create_root_ns();
    }

    fn create_root_ns(self: *PidNsManager) bool {
        self.namespaces[0] = EMPTY_PID_NS;
        self.namespaces[0].id = 0;
        self.namespaces[0].parent_idx = -1;
        self.namespaces[0].depth = 0;
        self.namespaces[0].owner_uid = 0;
        self.namespaces[0].active = true;
        self.namespaces[0].ref_count = 1;
        self.ns_count = 1;
        self.total_ns_created = 1;

        // Create PID 1 (init) in root namespace
        _ = self.alloc_pid_in_ns(0, PID_INVALID);
        return true;
    }

    // ─── Namespace Operations ───────────────────────────────────

    /// Create a child PID namespace
    pub fn create_namespace(self: *PidNsManager, parent_ns_idx: u16, owner_uid: u32) ?u16 {
        if (self.ns_count >= MAX_PID_NAMESPACES) return null;
        if (parent_ns_idx >= MAX_PID_NAMESPACES or !self.namespaces[parent_ns_idx].active) return null;

        const parent = &self.namespaces[parent_ns_idx];
        if (parent.depth >= MAX_NS_DEPTH - 1) return null; // Max nesting

        // Find free slot
        var i: u16 = 0;
        while (i < MAX_PID_NAMESPACES) : (i += 1) {
            if (!self.namespaces[i].active) {
                self.namespaces[i] = EMPTY_PID_NS;
                self.namespaces[i].id = self.next_ns_id;
                self.namespaces[i].parent_idx = @intCast(parent_ns_idx);
                self.namespaces[i].depth = parent.depth + 1;
                self.namespaces[i].owner_uid = owner_uid;
                self.namespaces[i].active = true;
                self.namespaces[i].ref_count = 1;
                self.next_ns_id += 1;
                self.ns_count += 1;
                self.total_ns_created += 1;

                // Increment parent child count
                self.namespaces[parent_ns_idx].child_count += 1;

                return i;
            }
        }
        return null;
    }

    /// Destroy a PID namespace (must have no active PIDs and no children)
    pub fn destroy_namespace(self: *PidNsManager, ns_idx: u16) bool {
        if (ns_idx >= MAX_PID_NAMESPACES or !self.namespaces[ns_idx].active) return false;
        if (ns_idx == 0) return false; // Cannot destroy root NS
        if (self.namespaces[ns_idx].child_count > 0) return false;
        if (self.namespaces[ns_idx].pid_count > 0) return false;

        const parent_idx = self.namespaces[ns_idx].parent_idx;
        self.namespaces[ns_idx].active = false;
        self.ns_count -= 1;
        self.total_ns_destroyed += 1;

        // Decrement parent child count
        if (parent_idx >= 0 and @as(u16, @intCast(parent_idx)) < MAX_PID_NAMESPACES) {
            self.namespaces[@intCast(parent_idx)].child_count -= 1;
        }

        return true;
    }

    // ─── PID Allocation ─────────────────────────────────────────

    /// Allocate a PID in a namespace (fork equivalent)
    pub fn alloc_pid(self: *PidNsManager, ns_idx: u16, parent_ns_pid: u32) ?u32 {
        if (ns_idx >= MAX_PID_NAMESPACES or !self.namespaces[ns_idx].active) return null;

        // Allocate global PID
        const global_pid = self.next_global_pid;
        self.next_global_pid += 1;

        // Allocate PID in target namespace and all ancestors
        var current_ns = ns_idx;
        var first_ns_pid: u32 = PID_INVALID;

        // Find or create process PID tracking
        var proc_idx: ?u32 = null;
        var p: u32 = 0;
        while (p < 512) : (p += 1) {
            if (self.process_pids[p].global_pid == PID_INVALID) {
                proc_idx = p;
                break;
            }
        }
        if (proc_idx == null) return null;

        self.process_pids[proc_idx.?] = EMPTY_PROCESS_PIDS;
        self.process_pids[proc_idx.?].global_pid = global_pid;

        var level: u8 = 0;

        // Walk from target NS up to root, allocating PIDs at each level
        while (true) {
            const ns_pid = self.alloc_pid_in_ns(current_ns, parent_ns_pid);
            if (ns_pid == null) {
                // Rollback: free PIDs already allocated
                self.rollback_alloc(proc_idx.?, level);
                return null;
            }

            if (first_ns_pid == PID_INVALID) {
                first_ns_pid = ns_pid.?;
            }

            // Record in process PID levels
            self.process_pids[proc_idx.?].levels[level] = .{
                .ns_idx = @intCast(current_ns),
                .ns_pid = ns_pid.?,
            };
            level += 1;
            self.process_pids[proc_idx.?].level_count = level;

            // Set init if PID is 1 in this namespace
            if (ns_pid.? == 1) {
                self.namespaces[current_ns].init_global_pid = global_pid;
            }

            // Move to parent namespace
            const parent = self.namespaces[current_ns].parent_idx;
            if (parent < 0) break;
            current_ns = @intCast(parent);
        }

        self.process_count += 1;
        self.namespaces[ns_idx].total_forks += 1;
        return global_pid;
    }

    fn alloc_pid_in_ns(self: *PidNsManager, ns_idx: u16, parent_ns_pid: u32) ?u32 {
        if (ns_idx >= MAX_PID_NAMESPACES) return null;
        var ns = &self.namespaces[ns_idx];
        if (ns.pid_count >= MAX_PIDS_PER_NS) return null;

        const ns_pid = ns.next_pid;
        ns.next_pid += 1;

        // Find free PID slot
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (!ns.pids[i].active) {
                ns.pids[i] = .{
                    .ns_pid = ns_pid,
                    .global_pid = PID_INVALID, // Will be set by caller
                    .state = .running,
                    .parent_ns_pid = parent_ns_pid,
                    .active = true,
                };
                ns.pid_count += 1;
                return ns_pid;
            }
        }
        return null;
    }

    fn rollback_alloc(self: *PidNsManager, proc_idx: u32, levels: u8) void {
        var i: u8 = 0;
        while (i < levels) : (i += 1) {
            const level = &self.process_pids[proc_idx].levels[i];
            if (level.ns_idx >= 0) {
                const ns_index: u16 = @intCast(level.ns_idx);
                self.free_pid_in_ns(ns_index, level.ns_pid);
            }
        }
        self.process_pids[proc_idx] = EMPTY_PROCESS_PIDS;
    }

    fn free_pid_in_ns(self: *PidNsManager, ns_idx: u16, ns_pid: u32) void {
        if (ns_idx >= MAX_PID_NAMESPACES) return;
        var ns = &self.namespaces[ns_idx];
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (ns.pids[i].active and ns.pids[i].ns_pid == ns_pid) {
                ns.pids[i].active = false;
                ns.pid_count -= 1;
                return;
            }
        }
    }

    // ─── PID Translation ────────────────────────────────────────

    /// Translate global PID to namespace-local PID
    pub fn global_to_ns(self: *PidNsManager, global_pid: u32, ns_idx: u16) ?u32 {
        self.total_pid_translations += 1;
        var p: u32 = 0;
        while (p < 512) : (p += 1) {
            if (self.process_pids[p].global_pid == global_pid) {
                var i: u8 = 0;
                while (i < self.process_pids[p].level_count) : (i += 1) {
                    if (self.process_pids[p].levels[i].ns_idx == @as(i16, @intCast(ns_idx))) {
                        return self.process_pids[p].levels[i].ns_pid;
                    }
                }
                return null; // Not visible in this NS
            }
        }
        return null;
    }

    /// Translate namespace-local PID to global PID
    pub fn ns_to_global(self: *PidNsManager, ns_pid: u32, ns_idx: u16) ?u32 {
        self.total_pid_translations += 1;
        if (ns_idx >= MAX_PID_NAMESPACES or !self.namespaces[ns_idx].active) return null;
        const ns = &self.namespaces[ns_idx];
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (ns.pids[i].active and ns.pids[i].ns_pid == ns_pid) {
                return ns.pids[i].global_pid;
            }
        }
        return null;
    }

    // ─── Process Exit ───────────────────────────────────────────

    /// Process exited — mark zombie, handle orphans
    pub fn process_exit(self: *PidNsManager, global_pid: u32) void {
        var p: u32 = 0;
        while (p < 512) : (p += 1) {
            if (self.process_pids[p].global_pid == global_pid) {
                // Mark as zombie in all namespaces
                var i: u8 = 0;
                while (i < self.process_pids[p].level_count) : (i += 1) {
                    const level = &self.process_pids[p].levels[i];
                    if (level.ns_idx >= 0) {
                        const ns_index: u16 = @intCast(level.ns_idx);
                        self.set_pid_state(ns_index, level.ns_pid, .zombie);
                    }
                }

                // Check if this was init (PID 1) in any namespace
                var j: u8 = 0;
                while (j < self.process_pids[p].level_count) : (j += 1) {
                    const level = &self.process_pids[p].levels[j];
                    if (level.ns_pid == 1 and level.ns_idx >= 0) {
                        const ns_index: u16 = @intCast(level.ns_idx);
                        // Init died → kill all processes in namespace
                        self.kill_namespace(ns_index);
                    }
                }
                return;
            }
        }
    }

    /// Reap a zombie process (waitpid)
    pub fn reap_process(self: *PidNsManager, global_pid: u32) void {
        var p: u32 = 0;
        while (p < 512) : (p += 1) {
            if (self.process_pids[p].global_pid == global_pid) {
                // Free PID in all namespaces
                var i: u8 = 0;
                while (i < self.process_pids[p].level_count) : (i += 1) {
                    const level = &self.process_pids[p].levels[i];
                    if (level.ns_idx >= 0) {
                        const ns_index: u16 = @intCast(level.ns_idx);
                        self.free_pid_in_ns(ns_index, level.ns_pid);
                        self.namespaces[ns_index].total_reaps += 1;
                    }
                }
                self.process_pids[p] = EMPTY_PROCESS_PIDS;
                self.process_count -= 1;
                return;
            }
        }
    }

    fn set_pid_state(self: *PidNsManager, ns_idx: u16, ns_pid: u32, state: PidState) void {
        if (ns_idx >= MAX_PID_NAMESPACES) return;
        var ns = &self.namespaces[ns_idx];
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (ns.pids[i].active and ns.pids[i].ns_pid == ns_pid) {
                ns.pids[i].state = state;
                return;
            }
        }
    }

    /// Kill all processes in a namespace (when init dies)
    fn kill_namespace(self: *PidNsManager, ns_idx: u16) void {
        if (ns_idx >= MAX_PID_NAMESPACES) return;
        var ns = &self.namespaces[ns_idx];
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (ns.pids[i].active) {
                ns.pids[i].state = .dead;
                ns.total_exits += 1;
            }
        }
    }

    // ─── Reparenting ────────────────────────────────────────────

    /// Reparent orphaned processes to namespace init
    pub fn reparent_orphans(self: *PidNsManager, ns_idx: u16, dead_parent_pid: u32) void {
        if (ns_idx >= MAX_PID_NAMESPACES or !self.namespaces[ns_idx].active) return;
        var ns = &self.namespaces[ns_idx];
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (ns.pids[i].active and ns.pids[i].parent_ns_pid == dead_parent_pid) {
                // Reparent to init (PID 1)
                ns.pids[i].parent_ns_pid = 1;
            }
        }
    }

    // ─── Visibility Check ───────────────────────────────────────

    /// Check if a process is visible from a given namespace
    pub fn is_visible(self: *PidNsManager, global_pid: u32, from_ns: u16) bool {
        // A process is visible if it has a PID in from_ns or any descendant
        var p: u32 = 0;
        while (p < 512) : (p += 1) {
            if (self.process_pids[p].global_pid == global_pid) {
                var i: u8 = 0;
                while (i < self.process_pids[p].level_count) : (i += 1) {
                    const level = &self.process_pids[p].levels[i];
                    if (level.ns_idx >= 0) {
                        const ns_index: u16 = @intCast(level.ns_idx);
                        if (ns_index == from_ns) return true;
                        // Check if ns_index is descendant of from_ns
                        if (self.is_descendant(ns_index, from_ns)) return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    fn is_descendant(self: *PidNsManager, ns_idx: u16, ancestor: u16) bool {
        var current = ns_idx;
        var depth: u8 = 0;
        while (depth < MAX_NS_DEPTH) : (depth += 1) {
            if (current == ancestor) return true;
            const parent = self.namespaces[current].parent_idx;
            if (parent < 0) return false;
            current = @intCast(parent);
        }
        return false;
    }

    // ─── /proc Virtualization ───────────────────────────────────

    /// List all PIDs visible in a namespace (for /proc)
    pub fn list_pids(self: *PidNsManager, ns_idx: u16, out_pids: []u32) u32 {
        if (ns_idx >= MAX_PID_NAMESPACES or !self.namespaces[ns_idx].active) return 0;
        const ns = &self.namespaces[ns_idx];
        var count: u32 = 0;
        var i: u16 = 0;
        while (i < MAX_PIDS_PER_NS) : (i += 1) {
            if (ns.pids[i].active and ns.pids[i].state != .dead) {
                if (count < out_pids.len) {
                    out_pids[count] = ns.pids[i].ns_pid;
                    count += 1;
                }
            }
        }
        return count;
    }

    // ─── Signal Delivery ────────────────────────────────────────

    /// Check if signal can cross namespace boundary
    pub fn can_signal(self: *PidNsManager, sender_ns: u16, target_global_pid: u32) bool {
        self.total_signal_crosses += 1;
        // Sender can signal targets visible in their namespace
        return self.is_visible(target_global_pid, sender_ns);
    }

    // ─── Tick ───────────────────────────────────────────────────

    pub fn process_tick(self: *PidNsManager) void {
        self.tick += 1;

        // Cleanup dead namespaces with no PIDs and no children
        if (self.tick % 10 == 0) {
            var i: u16 = 1; // Skip root NS
            while (i < MAX_PID_NAMESPACES) : (i += 1) {
                if (self.namespaces[i].active and
                    self.namespaces[i].pid_count == 0 and
                    self.namespaces[i].child_count == 0 and
                    self.namespaces[i].ref_count == 0)
                {
                    _ = self.destroy_namespace(i);
                }
            }
        }
    }
};

// ─────────── Global State ───────────────────────────────────────────

var g_pidns: PidNsManager = undefined;

pub fn get_manager() *PidNsManager {
    return &g_pidns;
}

// ─────────── FFI Exports ────────────────────────────────────────────

export fn zxy_pidns_init() void {
    g_pidns.init();
}

export fn zxy_pidns_create(parent_ns: u16, owner_uid: u32) i16 {
    if (!g_pidns.initialized) return -1;
    if (g_pidns.create_namespace(parent_ns, owner_uid)) |idx| {
        return @intCast(idx);
    }
    return -1;
}

export fn zxy_pidns_destroy(ns_idx: u16) bool {
    if (!g_pidns.initialized) return false;
    return g_pidns.destroy_namespace(ns_idx);
}

export fn zxy_pidns_alloc_pid(ns_idx: u16, parent_pid: u32) i32 {
    if (!g_pidns.initialized) return -1;
    if (g_pidns.alloc_pid(ns_idx, parent_pid)) |global| {
        return @intCast(global);
    }
    return -1;
}

export fn zxy_pidns_translate_to_ns(global_pid: u32, ns_idx: u16) i32 {
    if (!g_pidns.initialized) return -1;
    if (g_pidns.global_to_ns(global_pid, ns_idx)) |ns_pid| {
        return @intCast(ns_pid);
    }
    return -1;
}

export fn zxy_pidns_translate_to_global(ns_pid: u32, ns_idx: u16) i32 {
    if (!g_pidns.initialized) return -1;
    if (g_pidns.ns_to_global(ns_pid, ns_idx)) |global| {
        return @intCast(global);
    }
    return -1;
}

export fn zxy_pidns_exit(global_pid: u32) void {
    if (!g_pidns.initialized) return;
    g_pidns.process_exit(global_pid);
}

export fn zxy_pidns_reap(global_pid: u32) void {
    if (!g_pidns.initialized) return;
    g_pidns.reap_process(global_pid);
}

export fn zxy_pidns_is_visible(global_pid: u32, from_ns: u16) bool {
    if (!g_pidns.initialized) return false;
    return g_pidns.is_visible(global_pid, from_ns);
}

export fn zxy_pidns_can_signal(sender_ns: u16, target_pid: u32) bool {
    if (!g_pidns.initialized) return false;
    return g_pidns.can_signal(sender_ns, target_pid);
}

export fn zxy_pidns_tick() void {
    if (!g_pidns.initialized) return;
    g_pidns.process_tick();
}

export fn zxy_pidns_count() u16 {
    if (!g_pidns.initialized) return 0;
    return g_pidns.ns_count;
}

export fn zxy_pidns_total_created() u64 {
    if (!g_pidns.initialized) return 0;
    return g_pidns.total_ns_created;
}

export fn zxy_pidns_total_translations() u64 {
    if (!g_pidns.initialized) return 0;
    return g_pidns.total_pid_translations;
}

export fn zxy_pidns_process_count() u32 {
    if (!g_pidns.initialized) return 0;
    return g_pidns.process_count;
}
