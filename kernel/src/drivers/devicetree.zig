// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Zig Device Tree Parser
//
// Implements Flattened Device Tree (FDT/DTB) parsing:
// - FDT header validation
// - Node traversal (depth-first)
// - Property extraction
// - Compatible string matching
// - Address/size cell handling
// - Interrupt map parsing
// - Platform device enumeration
// - Memory reservation entries

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────
pub const FDT_MAGIC: u32 = 0xD00DFEED;
pub const FDT_VERSION: u32 = 17;
pub const FDT_COMPAT_VERSION: u32 = 16;

pub const FDT_BEGIN_NODE: u32 = 0x00000001;
pub const FDT_END_NODE: u32 = 0x00000002;
pub const FDT_PROP: u32 = 0x00000003;
pub const FDT_NOP: u32 = 0x00000004;
pub const FDT_END: u32 = 0x00000009;

pub const MAX_DT_NODES = 512;
pub const MAX_DT_PROPERTIES = 2048;
pub const MAX_DT_DEPTH = 16;
pub const MAX_DT_NAME = 64;
pub const MAX_DT_PROP_NAME = 32;
pub const MAX_DT_PROP_DATA = 256;
pub const MAX_DT_COMPATIBLE = 8;
pub const MAX_MEM_RESERVATIONS = 16;
pub const MAX_PLATFORM_DEVICES = 128;

// ─────────────────── FDT Header ─────────────────────────────────────
pub const FdtHeader = struct {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,

    pub fn validate(self: *const FdtHeader) bool {
        if (self.magic != FDT_MAGIC) return false;
        if (self.version < FDT_COMPAT_VERSION) return false;
        if (self.off_dt_struct >= self.totalsize) return false;
        if (self.off_dt_strings >= self.totalsize) return false;
        return true;
    }
};

// ─────────────────── Memory Reservation ─────────────────────────────
pub const MemReservation = struct {
    address: u64,
    size: u64,
};

// ─────────────────── Property ───────────────────────────────────────
pub const DtProperty = struct {
    name: [MAX_DT_PROP_NAME]u8 = [_]u8{0} ** MAX_DT_PROP_NAME,
    name_len: u8 = 0,
    data: [MAX_DT_PROP_DATA]u8 = [_]u8{0} ** MAX_DT_PROP_DATA,
    data_len: u16 = 0,
    node_id: u16 = 0,

    pub fn set_name(self: *DtProperty, n: []const u8) void {
        const len = @min(n.len, MAX_DT_PROP_NAME);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn get_name(self: *const DtProperty) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn set_data(self: *DtProperty, d: []const u8) void {
        const len = @min(d.len, MAX_DT_PROP_DATA);
        @memcpy(self.data[0..len], d[0..len]);
        self.data_len = @intCast(len);
    }

    /// Read property as a u32 (big-endian)
    pub fn as_u32(self: *const DtProperty) ?u32 {
        if (self.data_len < 4) return null;
        return read_be32(self.data[0..4]);
    }

    /// Read property as a u64 (big-endian)
    pub fn as_u64(self: *const DtProperty) ?u64 {
        if (self.data_len < 8) return null;
        return read_be64(self.data[0..8]);
    }

    /// Read property as a string
    pub fn as_string(self: *const DtProperty) []const u8 {
        // Find null terminator
        for (self.data[0..self.data_len], 0..) |c, i| {
            if (c == 0) return self.data[0..i];
        }
        return self.data[0..self.data_len];
    }

    /// Read property as a string list (null-separated)
    pub fn as_string_list(self: *const DtProperty, out: *[MAX_DT_COMPATIBLE][]const u8) u8 {
        var count: u8 = 0;
        var start: usize = 0;
        for (self.data[0..self.data_len], 0..) |c, i| {
            if (c == 0 and i > start) {
                if (count < MAX_DT_COMPATIBLE) {
                    out[count] = self.data[start..i];
                    count += 1;
                }
                start = i + 1;
            }
        }
        return count;
    }

    /// Read property as array of u32 values
    pub fn as_u32_array(self: *const DtProperty, out: []u32) u32 {
        var count: u32 = 0;
        var off: usize = 0;
        while (off + 4 <= self.data_len and count < out.len) {
            out[count] = read_be32(self.data[off..][0..4]);
            off += 4;
            count += 1;
        }
        return count;
    }
};

// ─────────────────── Node ───────────────────────────────────────────
pub const DtNode = struct {
    id: u16 = 0,
    parent_id: u16 = 0xFFFF,
    name: [MAX_DT_NAME]u8 = [_]u8{0} ** MAX_DT_NAME,
    name_len: u8 = 0,
    depth: u8 = 0,
    /// Address cells for children
    address_cells: u8 = 2,
    /// Size cells for children
    size_cells: u8 = 1,
    /// First property index
    first_prop: u16 = 0xFFFF,
    /// Number of properties
    prop_count: u16 = 0,
    /// Children count
    child_count: u16 = 0,
    /// Is this node enabled?
    enabled: bool = true,

    pub fn set_name(self: *DtNode, n: []const u8) void {
        const len = @min(n.len, MAX_DT_NAME);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn get_name(self: *const DtNode) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Extract the unit name (before @) from the node name
    pub fn unit_name(self: *const DtNode) []const u8 {
        const n = self.name[0..self.name_len];
        for (n, 0..) |c, i| {
            if (c == '@') return n[0..i];
        }
        return n;
    }

    /// Extract the unit address (after @) from the node name
    pub fn unit_address(self: *const DtNode) ?[]const u8 {
        const n = self.name[0..self.name_len];
        for (n, 0..) |c, i| {
            if (c == '@') return n[i + 1..];
        }
        return null;
    }
};

// ─────────────────── Platform Device ────────────────────────────────
pub const PlatformDevice = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    compatible: [64]u8 = [_]u8{0} ** 64,
    compatible_len: u8 = 0,
    base_addr: u64 = 0,
    size: u64 = 0,
    irq: u32 = 0,
    irq_count: u8 = 0,
    node_id: u16 = 0,

    pub fn set_name(self: *PlatformDevice, n: []const u8) void {
        const len = @min(n.len, 32);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn set_compatible(self: *PlatformDevice, c: []const u8) void {
        const len = @min(c.len, 64);
        @memcpy(self.compatible[0..len], c[0..len]);
        self.compatible_len = @intCast(len);
    }
};

// ─────────────────── Device Tree Parser ─────────────────────────────
pub const DeviceTree = struct {
    /// Parsed nodes
    nodes: [MAX_DT_NODES]?DtNode = [_]?DtNode{null} ** MAX_DT_NODES,
    node_count: u16 = 0,
    /// Parsed properties
    properties: [MAX_DT_PROPERTIES]?DtProperty = [_]?DtProperty{null} ** MAX_DT_PROPERTIES,
    prop_count: u16 = 0,
    /// Memory reservations
    mem_reservations: [MAX_MEM_RESERVATIONS]MemReservation = [_]MemReservation{.{ .address = 0, .size = 0 }} ** MAX_MEM_RESERVATIONS,
    mem_rsv_count: u8 = 0,
    /// Platform devices extracted
    platform_devs: [MAX_PLATFORM_DEVICES]?PlatformDevice = [_]?PlatformDevice{null} ** MAX_PLATFORM_DEVICES,
    platform_dev_count: u16 = 0,
    /// FDT header
    header: FdtHeader = .{
        .magic = 0,
        .totalsize = 0,
        .off_dt_struct = 0,
        .off_dt_strings = 0,
        .off_mem_rsvmap = 0,
        .version = 0,
        .last_comp_version = 0,
        .boot_cpuid_phys = 0,
        .size_dt_strings = 0,
        .size_dt_struct = 0,
    },
    /// Model string
    model: [64]u8 = [_]u8{0} ** 64,
    model_len: u8 = 0,
    /// Total memory size (from /memory node)
    total_memory: u64 = 0,
    /// Boot arguments
    bootargs: [256]u8 = [_]u8{0} ** 256,
    bootargs_len: u16 = 0,

    /// Parse an FDT blob
    pub fn parse(self: *DeviceTree, fdt_data: []const u8) bool {
        if (fdt_data.len < @sizeOf(FdtHeader)) return false;

        // Read header (big-endian)
        self.header = .{
            .magic = read_be32(fdt_data[0..4]),
            .totalsize = read_be32(fdt_data[4..8]),
            .off_dt_struct = read_be32(fdt_data[8..12]),
            .off_dt_strings = read_be32(fdt_data[12..16]),
            .off_mem_rsvmap = read_be32(fdt_data[16..20]),
            .version = read_be32(fdt_data[20..24]),
            .last_comp_version = read_be32(fdt_data[24..28]),
            .boot_cpuid_phys = read_be32(fdt_data[28..32]),
            .size_dt_strings = read_be32(fdt_data[32..36]),
            .size_dt_struct = read_be32(fdt_data[36..40]),
        };

        if (!self.header.validate()) return false;

        // Parse memory reservations
        self.parse_mem_reservations(fdt_data);

        // Parse structure block
        self.parse_structure(fdt_data);

        // Extract platform devices
        self.extract_platform_devices();

        return self.node_count > 0;
    }

    fn parse_mem_reservations(self: *DeviceTree, data: []const u8) void {
        var off: usize = self.header.off_mem_rsvmap;
        while (off + 16 <= data.len and self.mem_rsv_count < MAX_MEM_RESERVATIONS) {
            const addr = read_be64(data[off..][0..8]);
            const size = read_be64(data[off + 8..][0..8]);
            if (addr == 0 and size == 0) break;

            self.mem_reservations[self.mem_rsv_count] = .{
                .address = addr,
                .size = size,
            };
            self.mem_rsv_count += 1;
            off += 16;
        }
    }

    fn parse_structure(self: *DeviceTree, data: []const u8) void {
        var off: usize = self.header.off_dt_struct;
        var depth: u8 = 0;
        var node_stack: [MAX_DT_DEPTH]u16 = [_]u16{0xFFFF} ** MAX_DT_DEPTH;
        var current_node: u16 = 0xFFFF;

        while (off + 4 <= data.len) {
            const token = read_be32(data[off..][0..4]);
            off += 4;

            switch (token) {
                FDT_BEGIN_NODE => {
                    // Read node name (null-terminated)
                    const name_start = off;
                    while (off < data.len and data[off] != 0) : (off += 1) {}
                    const name_end = off;
                    off += 1; // Skip null

                    // Align to 4 bytes
                    off = (off + 3) & ~@as(usize, 3);

                    if (self.node_count < MAX_DT_NODES) {
                        var node = DtNode{};
                        node.id = self.node_count;
                        node.depth = depth;

                        if (depth > 0 and depth <= MAX_DT_DEPTH) {
                            node.parent_id = node_stack[depth - 1];
                        }

                        const name = data[name_start..name_end];
                        node.set_name(name);

                        if (depth < MAX_DT_DEPTH) {
                            node_stack[depth] = self.node_count;
                        }

                        current_node = self.node_count;
                        self.nodes[self.node_count] = node;
                        self.node_count += 1;
                    }

                    depth += 1;
                },
                FDT_END_NODE => {
                    if (depth > 0) depth -= 1;
                    if (depth < MAX_DT_DEPTH) {
                        current_node = node_stack[depth];
                    }
                },
                FDT_PROP => {
                    if (off + 8 > data.len) break;
                    const prop_len = read_be32(data[off..][0..4]);
                    const name_off = read_be32(data[off + 4..][0..4]);
                    off += 8;

                    // Resolve property name from strings block
                    const strings_base = self.header.off_dt_strings;
                    const name_offset = strings_base + name_off;

                    if (self.prop_count < MAX_DT_PROPERTIES and name_offset < data.len) {
                        var prop = DtProperty{};
                        prop.node_id = current_node;

                        // Read property name from strings block
                        const str_start = name_offset;
                        var str_end = str_start;
                        while (str_end < data.len and data[str_end] != 0) : (str_end += 1) {}
                        prop.set_name(data[str_start..str_end]);

                        // Read property data
                        if (prop_len > 0 and off + prop_len <= data.len) {
                            prop.set_data(data[off..off + @min(prop_len, MAX_DT_PROP_DATA)]);
                        }

                        // Update node property index
                        if (current_node < MAX_DT_NODES) {
                            if (self.nodes[current_node]) |*node| {
                                if (node.first_prop == 0xFFFF) {
                                    node.first_prop = self.prop_count;
                                }
                                node.prop_count += 1;

                                // Handle special properties
                                self.handle_special_prop(node, &prop);
                            }
                        }

                        self.properties[self.prop_count] = prop;
                        self.prop_count += 1;
                    }

                    off += prop_len;
                    off = (off + 3) & ~@as(usize, 3);
                },
                FDT_NOP => {},
                FDT_END => break,
                else => break,
            }
        }
    }

    fn handle_special_prop(self: *DeviceTree, node: *DtNode, prop: *const DtProperty) void {
        const pname = prop.get_name();

        if (std.mem.eql(u8, pname, "#address-cells")) {
            if (prop.as_u32()) |v| node.address_cells = @intCast(v);
        } else if (std.mem.eql(u8, pname, "#size-cells")) {
            if (prop.as_u32()) |v| node.size_cells = @intCast(v);
        } else if (std.mem.eql(u8, pname, "status")) {
            const status = prop.as_string();
            node.enabled = std.mem.eql(u8, status, "okay") or std.mem.eql(u8, status, "ok");
        } else if (std.mem.eql(u8, pname, "model") and node.depth == 0) {
            const model = prop.as_string();
            const len = @min(model.len, 64);
            @memcpy(self.model[0..len], model[0..len]);
            self.model_len = @intCast(len);
        } else if (std.mem.eql(u8, pname, "bootargs")) {
            const args = prop.as_string();
            const len = @min(args.len, 256);
            @memcpy(self.bootargs[0..len], args[0..len]);
            self.bootargs_len = @intCast(len);
        }
    }

    /// Extract platform devices from parsed tree
    fn extract_platform_devices(self: *DeviceTree) void {
        for (self.nodes[0..self.node_count]) |maybe_node| {
            const node = maybe_node orelse continue;
            if (!node.enabled or node.depth == 0) continue;

            // Look for nodes with "compatible" property
            var has_compatible = false;
            var compat_data: [MAX_DT_PROP_DATA]u8 = [_]u8{0} ** MAX_DT_PROP_DATA;
            var compat_len: u16 = 0;
            var reg_base: u64 = 0;
            var reg_size: u64 = 0;
            var irq_num: u32 = 0;

            // Search properties for this node
            for (self.properties[0..self.prop_count]) |maybe_prop| {
                const prop = maybe_prop orelse continue;
                if (prop.node_id != node.id) continue;

                const pname = prop.get_name();
                if (std.mem.eql(u8, pname, "compatible")) {
                    has_compatible = true;
                    const len = @min(prop.data_len, MAX_DT_PROP_DATA);
                    @memcpy(compat_data[0..len], prop.data[0..len]);
                    compat_len = len;
                } else if (std.mem.eql(u8, pname, "reg")) {
                    if (prop.data_len >= 8) {
                        reg_base = read_be32(prop.data[0..4]);
                        if (prop.data_len >= 12) {
                            reg_size = read_be32(prop.data[4..8]);
                        }
                    }
                } else if (std.mem.eql(u8, pname, "interrupts")) {
                    if (prop.as_u32()) |v| irq_num = v;
                }
            }

            if (has_compatible and self.platform_dev_count < MAX_PLATFORM_DEVICES) {
                var pdev = PlatformDevice{};
                pdev.set_name(node.unit_name());
                const cl = @min(compat_len, 64);
                @memcpy(pdev.compatible[0..cl], compat_data[0..cl]);
                pdev.compatible_len = @intCast(cl);
                pdev.base_addr = reg_base;
                pdev.size = reg_size;
                pdev.irq = irq_num;
                pdev.irq_count = if (irq_num > 0) 1 else 0;
                pdev.node_id = node.id;

                self.platform_devs[self.platform_dev_count] = pdev;
                self.platform_dev_count += 1;
            }
        }
    }

    /// Find a node by path (e.g., "/memory", "/cpus/cpu@0")
    pub fn find_node(self: *const DeviceTree, path: []const u8) ?*const DtNode {
        // Simple implementation: match by name for now
        for (self.nodes[0..self.node_count]) |*maybe_node| {
            if (maybe_node.*) |*node| {
                if (std.mem.eql(u8, node.get_name(), path)) return node;
            }
        }
        return null;
    }

    /// Find all nodes with a matching compatible string
    pub fn find_compatible(self: *const DeviceTree, compat: []const u8, out: []u16) u16 {
        var count: u16 = 0;
        for (self.properties[0..self.prop_count]) |*maybe_prop| {
            if (maybe_prop.*) |*prop| {
                if (std.mem.eql(u8, prop.get_name(), "compatible")) {
                    // Check if compatible string is in the list
                    const data = prop.data[0..prop.data_len];
                    if (contains_string(data, compat)) {
                        if (count < out.len) {
                            out[count] = prop.node_id;
                            count += 1;
                        }
                    }
                }
            }
        }
        return count;
    }

    /// Get a property from a node
    pub fn get_property(self: *const DeviceTree, node_id: u16, prop_name: []const u8) ?*const DtProperty {
        for (self.properties[0..self.prop_count]) |*maybe_prop| {
            if (maybe_prop.*) |*prop| {
                if (prop.node_id == node_id and std.mem.eql(u8, prop.get_name(), prop_name)) {
                    return prop;
                }
            }
        }
        return null;
    }
};

fn contains_string(data: []const u8, needle: []const u8) bool {
    var start: usize = 0;
    for (data, 0..) |c, i| {
        if (c == 0 and i > start) {
            if (std.mem.eql(u8, data[start..i], needle)) return true;
            start = i + 1;
        }
    }
    return false;
}

fn read_be32(data: *const [4]u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn read_be64(data: *const [8]u8) u64 {
    return (@as(u64, data[0]) << 56) |
        (@as(u64, data[1]) << 48) |
        (@as(u64, data[2]) << 40) |
        (@as(u64, data[3]) << 32) |
        (@as(u64, data[4]) << 24) |
        (@as(u64, data[5]) << 16) |
        (@as(u64, data[6]) << 8) |
        @as(u64, data[7]);
}

// ─────────────────── Global Instance ────────────────────────────────
var device_tree: DeviceTree = .{};
var dt_initialized = false;

pub fn parseFdt(fdt_ptr: [*]const u8, fdt_len: usize) bool {
    const data = fdt_ptr[0..fdt_len];
    dt_initialized = device_tree.parse(data);
    return dt_initialized;
}

pub fn getDeviceTree() *const DeviceTree {
    return &device_tree;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_dt_parse(fdt_ptr: [*]const u8, fdt_len: u32) bool {
    return parseFdt(fdt_ptr, fdt_len);
}

export fn zxy_dt_node_count() u16 {
    return device_tree.node_count;
}

export fn zxy_dt_platform_dev_count() u16 {
    return device_tree.platform_dev_count;
}

export fn zxy_dt_find_compatible(compat_ptr: [*]const u8, compat_len: u32, out_ptr: [*]u16, out_max: u16) u16 {
    const compat = compat_ptr[0..compat_len];
    const out = out_ptr[0..out_max];
    return device_tree.find_compatible(compat, out);
}

export fn zxy_dt_get_model(out_ptr: [*]u8, max_len: u32) u32 {
    const len = @min(device_tree.model_len, @as(u8, @intCast(max_len)));
    @memcpy(out_ptr[0..len], device_tree.model[0..len]);
    return len;
}

export fn zxy_dt_mem_rsv_count() u8 {
    return device_tree.mem_rsv_count;
}
