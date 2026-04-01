// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Sysfs Virtual Filesystem (Zig)
//
// Kernel object attribute exposition via /sys:
// - /sys/bus/     — bus types (PCI, USB, I2C, SPI, platform)
// - /sys/class/   — device classes (block, net, tty, input)
// - /sys/devices/ — device hierarchy tree
// - /sys/module/  — loaded kernel modules
// - /sys/kernel/  — kernel parameters and info
// - /sys/power/   — power management state
// - /sys/firmware/ — ACPI/BIOS tables
// - Attribute files: show/store callbacks
// - Binary attribute files (firmware blobs, EDID)
// - Symlink support for cross-references
// - Uevent triggered file creation
// - kobj integration (every sysfs node is a kobject)

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_SYSFS_NODES: usize = 1024;
const MAX_NAME_LEN: usize = 64;
const MAX_PATH_LEN: usize = 256;
const MAX_VALUE_LEN: usize = 4096;
const MAX_CHILDREN: usize = 64;
const MAX_ATTRS: usize = 32;
const MAX_SYMLINKS: usize = 128;

// ─────────────────── Node Types ─────────────────────────────────────

pub const SysfsNodeType = enum(u8) {
    directory = 0,
    attribute = 1,
    binary_attr = 2,
    symlink = 3,
    group = 4,      // attribute group
};

// ─────────────────── Permission ─────────────────────────────────────

pub const SysfsMode = packed struct {
    other_exec: bool = false,
    other_write: bool = false,
    other_read: bool = true,
    group_exec: bool = false,
    group_write: bool = false,
    group_read: bool = true,
    owner_exec: bool = false,
    owner_write: bool = true,
    owner_read: bool = true,
    _pad: u7 = 0,

    pub fn to_octal(self: SysfsMode) u16 {
        return @bitCast(self);
    }

    pub const RO_ALL: SysfsMode = .{ .owner_write = false };
    pub const RW_OWNER: SysfsMode = .{};
    pub const RO_OWNER: SysfsMode = .{ .owner_write = false, .group_read = false, .other_read = false };
};

// ─────────────────── Show/Store Callbacks ───────────────────────────

pub const ShowFn = *const fn (node: *const SysfsNode, buf: []u8) usize;
pub const StoreFn = *const fn (node: *SysfsNode, data: []const u8) bool;

// ─────────────────── Sysfs Node ─────────────────────────────────────

pub const SysfsNode = struct {
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    name_len: u8 = 0,
    node_type: SysfsNodeType = .directory,
    mode: SysfsMode = .{},
    /// Tree
    parent_id: u16 = 0xFFFF,
    children: [MAX_CHILDREN]u16 = [_]u16{0xFFFF} ** MAX_CHILDREN,
    child_count: u8 = 0,
    /// Symlink target
    symlink_target: u16 = 0xFFFF,
    /// Attribute value storage (for simple text attrs)
    value: [MAX_VALUE_LEN]u8 = [_]u8{0} ** MAX_VALUE_LEN,
    value_len: u16 = 0,
    /// Callbacks
    show_fn: ?ShowFn = null,
    store_fn: ?StoreFn = null,
    /// Kobject ID reference
    kobj_id: u16 = 0xFFFF,
    /// Metadata
    id: u16 = 0,
    access_count: u64 = 0,
    modify_count: u64 = 0,
    active: bool = false,

    pub fn set_name(self: *SysfsNode, n: []const u8) void {
        const len = @min(n.len, MAX_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @truncate(len);
    }

    pub fn get_name(self: *const SysfsNode) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn add_child(self: *SysfsNode, child_id: u16) bool {
        if (self.child_count >= MAX_CHILDREN) return false;
        // Check duplicate
        for (0..self.child_count) |i| {
            if (self.children[i] == child_id) return false;
        }
        self.children[self.child_count] = child_id;
        self.child_count += 1;
        return true;
    }

    pub fn remove_child(self: *SysfsNode, child_id: u16) bool {
        for (0..self.child_count) |i| {
            if (self.children[i] == child_id) {
                var j = i;
                while (j + 1 < self.child_count) : (j += 1) {
                    self.children[j] = self.children[j + 1];
                }
                self.child_count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn find_child(self: *const SysfsNode, name: []const u8, nodes: []const SysfsNode) ?u16 {
        for (0..self.child_count) |i| {
            const cid = self.children[i];
            if (cid < nodes.len and nodes[cid].active) {
                if (nodes[cid].name_len == name.len) {
                    if (std.mem.eql(u8, nodes[cid].name[0..name.len], name)) {
                        return cid;
                    }
                }
            }
        }
        return null;
    }

    /// Read attribute value
    pub fn read_attr(self: *SysfsNode, buf: []u8) usize {
        self.access_count += 1;
        if (self.show_fn) |show| {
            return show(self, buf);
        }
        // Return stored value
        const len = @min(self.value_len, buf.len);
        @memcpy(buf[0..len], self.value[0..len]);
        return len;
    }

    /// Write attribute value
    pub fn write_attr(self: *SysfsNode, data: []const u8) bool {
        if (!self.mode.owner_write) return false;
        if (self.store_fn) |store| {
            self.modify_count += 1;
            return store(self, data);
        }
        // Store value directly
        const len = @min(data.len, MAX_VALUE_LEN);
        @memcpy(self.value[0..len], data[0..len]);
        self.value_len = @truncate(len);
        self.modify_count += 1;
        return true;
    }
};

// ─────────────────── Symlink Entry ──────────────────────────────────

pub const SysfsSymlink = struct {
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    name_len: u8 = 0,
    parent_id: u16 = 0xFFFF,
    target_id: u16 = 0xFFFF,
    active: bool = false,
};

// ─────────────────── Built-in Show Functions ────────────────────────

fn show_kernel_version(node: *const SysfsNode, buf: []u8) usize {
    _ = node;
    const ver = "Zxyphor 0.1.0-dev";
    const len = @min(ver.len, buf.len);
    @memcpy(buf[0..len], ver[0..len]);
    return len;
}

fn show_kernel_hostname(node: *const SysfsNode, buf: []u8) usize {
    _ = node;
    const name = "zxyphor";
    const len = @min(name.len, buf.len);
    @memcpy(buf[0..len], name[0..len]);
    return len;
}

fn show_power_state(node: *const SysfsNode, buf: []u8) usize {
    _ = node;
    const state = "mem\n";
    const len = @min(state.len, buf.len);
    @memcpy(buf[0..len], state[0..len]);
    return len;
}

fn show_power_disk(node: *const SysfsNode, buf: []u8) usize {
    _ = node;
    const modes = "[platform] shutdown reboot suspend\n";
    const len = @min(modes.len, buf.len);
    @memcpy(buf[0..len], modes[0..len]);
    return len;
}

fn show_zero(_: *const SysfsNode, buf: []u8) usize {
    if (buf.len > 0) {
        buf[0] = '0';
        if (buf.len > 1) buf[1] = '\n';
        return @min(2, buf.len);
    }
    return 0;
}

// ─────────────────── Sysfs Manager ──────────────────────────────────

pub const SysfsManager = struct {
    nodes: [MAX_SYSFS_NODES]SysfsNode = undefined,
    node_count: u16 = 0,
    next_id: u16 = 0,
    /// Symlinks
    symlinks: [MAX_SYMLINKS]SysfsSymlink = [_]SysfsSymlink{.{}} ** MAX_SYMLINKS,
    symlink_count: u16 = 0,
    /// Well-known node IDs
    root_id: u16 = 0,
    bus_id: u16 = 0,
    class_id: u16 = 0,
    devices_id: u16 = 0,
    module_id: u16 = 0,
    kernel_id: u16 = 0,
    power_id: u16 = 0,
    firmware_id: u16 = 0,
    /// Stats
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    total_lookups: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *SysfsManager) void {
        for (0..MAX_SYSFS_NODES) |i| {
            self.nodes[i] = SysfsNode{};
            self.nodes[i].id = @truncate(i);
        }

        // Create root /sys
        self.root_id = self.create_dir("/", 0xFFFF) orelse return;

        // Create top-level directories
        self.bus_id = self.create_dir("bus", self.root_id) orelse return;
        self.class_id = self.create_dir("class", self.root_id) orelse return;
        self.devices_id = self.create_dir("devices", self.root_id) orelse return;
        self.module_id = self.create_dir("module", self.root_id) orelse return;
        self.kernel_id = self.create_dir("kernel", self.root_id) orelse return;
        self.power_id = self.create_dir("power", self.root_id) orelse return;
        self.firmware_id = self.create_dir("firmware", self.root_id) orelse return;

        // /sys/bus/ subdirs
        _ = self.create_dir("pci", self.bus_id);
        _ = self.create_dir("usb", self.bus_id);
        _ = self.create_dir("i2c", self.bus_id);
        _ = self.create_dir("spi", self.bus_id);
        _ = self.create_dir("platform", self.bus_id);

        // /sys/class/ subdirs
        _ = self.create_dir("block", self.class_id);
        _ = self.create_dir("net", self.class_id);
        _ = self.create_dir("tty", self.class_id);
        _ = self.create_dir("input", self.class_id);
        _ = self.create_dir("sound", self.class_id);
        _ = self.create_dir("misc", self.class_id);

        // /sys/kernel/ attributes
        _ = self.create_attr("version", self.kernel_id, .RO_ALL, &show_kernel_version, null);
        _ = self.create_attr("hostname", self.kernel_id, .{}, &show_kernel_hostname, null);
        _ = self.create_attr("uevent_seqnum", self.kernel_id, .RO_ALL, &show_zero, null);

        // /sys/power/ attributes
        _ = self.create_attr("state", self.power_id, .{}, &show_power_state, null);
        _ = self.create_attr("disk", self.power_id, .{}, &show_power_disk, null);
        _ = self.create_attr("image_size", self.power_id, .{}, &show_zero, null);

        // /sys/devices/system/
        const sys_id = self.create_dir("system", self.devices_id) orelse return;
        _ = self.create_dir("cpu", sys_id);
        _ = self.create_dir("memory", sys_id);
        _ = self.create_dir("node", sys_id);
        _ = self.create_dir("clocksource", sys_id);

        self.initialized = true;
    }

    fn alloc_node(self: *SysfsManager) ?u16 {
        for (0..MAX_SYSFS_NODES) |i| {
            if (!self.nodes[i].active) {
                self.nodes[i] = SysfsNode{};
                self.nodes[i].id = @truncate(i);
                return @truncate(i);
            }
        }
        return null;
    }

    pub fn create_dir(self: *SysfsManager, name: []const u8, parent: u16) ?u16 {
        const id = self.alloc_node() orelse return null;
        self.nodes[id].set_name(name);
        self.nodes[id].node_type = .directory;
        self.nodes[id].parent_id = parent;
        self.nodes[id].active = true;
        self.node_count += 1;

        if (parent != 0xFFFF and parent < MAX_SYSFS_NODES) {
            _ = self.nodes[parent].add_child(id);
        }
        return id;
    }

    pub fn create_attr(
        self: *SysfsManager,
        name: []const u8,
        parent: u16,
        mode: SysfsMode,
        show: ?ShowFn,
        store: ?StoreFn,
    ) ?u16 {
        const id = self.alloc_node() orelse return null;
        self.nodes[id].set_name(name);
        self.nodes[id].node_type = .attribute;
        self.nodes[id].mode = mode;
        self.nodes[id].parent_id = parent;
        self.nodes[id].show_fn = show;
        self.nodes[id].store_fn = store;
        self.nodes[id].active = true;
        self.node_count += 1;

        if (parent < MAX_SYSFS_NODES) {
            _ = self.nodes[parent].add_child(id);
        }
        return id;
    }

    pub fn create_symlink(self: *SysfsManager, name: []const u8, parent: u16, target: u16) ?u16 {
        if (self.symlink_count >= MAX_SYMLINKS) return null;
        const id = self.alloc_node() orelse return null;
        self.nodes[id].set_name(name);
        self.nodes[id].node_type = .symlink;
        self.nodes[id].parent_id = parent;
        self.nodes[id].symlink_target = target;
        self.nodes[id].active = true;
        self.node_count += 1;

        if (parent < MAX_SYSFS_NODES) {
            _ = self.nodes[parent].add_child(id);
        }

        // Track symlink
        const si = self.symlink_count;
        self.symlinks[si].target_id = target;
        self.symlinks[si].parent_id = parent;
        const len = @min(name.len, MAX_NAME_LEN - 1);
        @memcpy(self.symlinks[si].name[0..len], name[0..len]);
        self.symlinks[si].name_len = @truncate(len);
        self.symlinks[si].active = true;
        self.symlink_count += 1;

        return id;
    }

    pub fn remove_node(self: *SysfsManager, id: u16) bool {
        if (id >= MAX_SYSFS_NODES) return false;
        if (!self.nodes[id].active) return false;

        // Remove from parent
        const parent = self.nodes[id].parent_id;
        if (parent != 0xFFFF and parent < MAX_SYSFS_NODES) {
            _ = self.nodes[parent].remove_child(id);
        }

        // Recursively remove children
        var i: u8 = 0;
        while (i < self.nodes[id].child_count) {
            const child = self.nodes[id].children[i];
            _ = self.remove_node(child);
            // Don't increment i because remove_child shifts the array
        }

        self.nodes[id].active = false;
        if (self.node_count > 0) self.node_count -= 1;
        return true;
    }

    /// Path lookup: /sys/kernel/version → node ID
    pub fn lookup_path(self: *SysfsManager, path: []const u8) ?u16 {
        self.total_lookups += 1;

        if (path.len == 0) return self.root_id;

        var current = self.root_id;
        var start: usize = 0;

        // Skip leading /
        if (path[0] == '/') start = 1;

        while (start < path.len) {
            // Find next separator
            var end = start;
            while (end < path.len and path[end] != '/') {
                end += 1;
            }
            if (end == start) {
                start = end + 1;
                continue;
            }

            const component = path[start..end];
            if (self.nodes[current].find_child(component, &self.nodes)) |child_id| {
                // Follow symlinks
                if (self.nodes[child_id].node_type == .symlink) {
                    current = self.nodes[child_id].symlink_target;
                } else {
                    current = child_id;
                }
            } else {
                return null; // Not found
            }

            start = end + 1;
        }

        return current;
    }

    /// Read an attribute by path
    pub fn read_attr_path(self: *SysfsManager, path: []const u8, buf: []u8) usize {
        const id = self.lookup_path(path) orelse return 0;
        if (self.nodes[id].node_type != .attribute) return 0;
        self.total_reads += 1;
        return self.nodes[id].read_attr(buf);
    }

    /// Write an attribute by path
    pub fn write_attr_path(self: *SysfsManager, path: []const u8, data: []const u8) bool {
        const id = self.lookup_path(path) orelse return false;
        if (self.nodes[id].node_type != .attribute) return false;
        self.total_writes += 1;
        return self.nodes[id].write_attr(data);
    }

    /// Register a device in the hierarchy
    pub fn register_device(self: *SysfsManager, name: []const u8, bus_name: []const u8) ?u16 {
        // Find bus directory
        const bus_node = self.nodes[self.bus_id].find_child(bus_name, &self.nodes) orelse return null;

        // Create devices/ under bus if needed
        var devices_dir = self.nodes[bus_node].find_child("devices", &self.nodes);
        if (devices_dir == null) {
            devices_dir = self.create_dir("devices", bus_node);
        }
        const dev_parent = devices_dir orelse return null;

        // Create device directory
        const dev_id = self.create_dir(name, dev_parent) orelse return null;

        // Add standard attributes
        _ = self.create_attr("uevent", dev_id, .{}, null, null);
        _ = self.create_attr("driver", dev_id, .RO_ALL, null, null);
        _ = self.create_attr("subsystem", dev_id, .RO_ALL, null, null);

        // Add symlink from /sys/devices/
        _ = self.create_symlink(name, self.devices_id, dev_id);

        return dev_id;
    }

    /// Register a module
    pub fn register_module(self: *SysfsManager, name: []const u8) ?u16 {
        const mod_id = self.create_dir(name, self.module_id) orelse return null;

        // Standard module attrs
        _ = self.create_attr("refcnt", mod_id, .RO_ALL, &show_zero, null);
        _ = self.create_attr("version", mod_id, .RO_ALL, null, null);

        // Parameters group
        _ = self.create_dir("parameters", mod_id);

        return mod_id;
    }

    pub fn active_node_count(self: *const SysfsManager) u32 {
        var count: u32 = 0;
        for (0..MAX_SYSFS_NODES) |i| {
            if (self.nodes[i].active) count += 1;
        }
        return count;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var sysfs_mgr = SysfsManager{};

pub fn get_sysfs_manager() *SysfsManager {
    return &sysfs_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_sysfs_init() void {
    sysfs_mgr.init();
}

export fn zxy_sysfs_node_count() u32 {
    return sysfs_mgr.active_node_count();
}

export fn zxy_sysfs_total_reads() u64 {
    return sysfs_mgr.total_reads;
}

export fn zxy_sysfs_total_writes() u64 {
    return sysfs_mgr.total_writes;
}

export fn zxy_sysfs_total_lookups() u64 {
    return sysfs_mgr.total_lookups;
}

export fn zxy_sysfs_symlink_count() u16 {
    return sysfs_mgr.symlink_count;
}

export fn zxy_sysfs_register_device(name_ptr: [*]const u8, name_len: u32, bus_ptr: [*]const u8, bus_len: u32) i32 {
    if (name_len == 0 or name_len > 63 or bus_len == 0 or bus_len > 31) return -1;
    const name = name_ptr[0..name_len];
    const bus = bus_ptr[0..bus_len];
    return if (sysfs_mgr.register_device(name, bus)) |id| @as(i32, id) else -1;
}

export fn zxy_sysfs_register_module(name_ptr: [*]const u8, name_len: u32) i32 {
    if (name_len == 0 or name_len > 63) return -1;
    const name = name_ptr[0..name_len];
    return if (sysfs_mgr.register_module(name)) |id| @as(i32, id) else -1;
}
