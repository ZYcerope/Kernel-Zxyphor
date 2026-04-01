// SPDX-License-Identifier: MIT
// Zxyphor Kernel — ACPI AML Interpreter
//
// Minimal ACPI Machine Language (AML) bytecode interpreter:
// - AML opcode decoder
// - Namespace tree (ACPI namespace objects)
// - Method execution engine
// - Integer/String/Buffer/Package data types
// - Named object handling (Device, Processor, ThermalZone, etc.)
// - Control flow: If/Else, While, Return
// - Field/OpRegion for hardware register access
// - Basic operator evaluation (Add, Subtract, And, Or, Not, etc.)

const std = @import("std");

// ─────────────────── AML Opcodes ────────────────────────────────────
pub const AML_ZERO_OP: u8 = 0x00;
pub const AML_ONE_OP: u8 = 0x01;
pub const AML_ALIAS_OP: u8 = 0x06;
pub const AML_NAME_OP: u8 = 0x08;
pub const AML_BYTE_PREFIX: u8 = 0x0A;
pub const AML_WORD_PREFIX: u8 = 0x0B;
pub const AML_DWORD_PREFIX: u8 = 0x0C;
pub const AML_STRING_PREFIX: u8 = 0x0D;
pub const AML_QWORD_PREFIX: u8 = 0x0E;
pub const AML_SCOPE_OP: u8 = 0x10;
pub const AML_BUFFER_OP: u8 = 0x11;
pub const AML_PACKAGE_OP: u8 = 0x12;
pub const AML_METHOD_OP: u8 = 0x14;
pub const AML_DUAL_NAME_PREFIX: u8 = 0x2E;
pub const AML_MULTI_NAME_PREFIX: u8 = 0x2F;
pub const AML_EXT_OP_PREFIX: u8 = 0x5B;
pub const AML_ROOT_CHAR: u8 = 0x5C;
pub const AML_PARENT_PREFIX: u8 = 0x5E;
pub const AML_LOCAL0_OP: u8 = 0x60;
pub const AML_LOCAL7_OP: u8 = 0x67;
pub const AML_ARG0_OP: u8 = 0x68;
pub const AML_ARG6_OP: u8 = 0x6E;
pub const AML_STORE_OP: u8 = 0x70;
pub const AML_REF_OF_OP: u8 = 0x71;
pub const AML_ADD_OP: u8 = 0x72;
pub const AML_CONCAT_OP: u8 = 0x73;
pub const AML_SUBTRACT_OP: u8 = 0x74;
pub const AML_INCREMENT_OP: u8 = 0x75;
pub const AML_DECREMENT_OP: u8 = 0x76;
pub const AML_MULTIPLY_OP: u8 = 0x77;
pub const AML_DIVIDE_OP: u8 = 0x78;
pub const AML_SHIFT_LEFT_OP: u8 = 0x79;
pub const AML_SHIFT_RIGHT_OP: u8 = 0x7A;
pub const AML_AND_OP: u8 = 0x7B;
pub const AML_NAND_OP: u8 = 0x7C;
pub const AML_OR_OP: u8 = 0x7D;
pub const AML_NOR_OP: u8 = 0x7E;
pub const AML_XOR_OP: u8 = 0x7F;
pub const AML_NOT_OP: u8 = 0x80;
pub const AML_FIND_SET_LEFT_BIT: u8 = 0x81;
pub const AML_FIND_SET_RIGHT_BIT: u8 = 0x82;
pub const AML_DEREF_OP: u8 = 0x83;
pub const AML_SIZEOF_OP: u8 = 0x87;
pub const AML_INDEX_OP: u8 = 0x88;
pub const AML_CREATE_DWORD_FIELD: u8 = 0x8A;
pub const AML_CREATE_WORD_FIELD: u8 = 0x8B;
pub const AML_CREATE_BYTE_FIELD: u8 = 0x8C;
pub const AML_CREATE_BIT_FIELD: u8 = 0x8D;
pub const AML_LAND_OP: u8 = 0x90;
pub const AML_LOR_OP: u8 = 0x91;
pub const AML_LNOT_OP: u8 = 0x92;
pub const AML_LEQUAL_OP: u8 = 0x93;
pub const AML_LGREATER_OP: u8 = 0x94;
pub const AML_LLESS_OP: u8 = 0x95;
pub const AML_IF_OP: u8 = 0xA0;
pub const AML_ELSE_OP: u8 = 0xA1;
pub const AML_WHILE_OP: u8 = 0xA2;
pub const AML_NOOP_OP: u8 = 0xA3;
pub const AML_RETURN_OP: u8 = 0xA4;
pub const AML_BREAK_OP: u8 = 0xA5;
pub const AML_ONES_OP: u8 = 0xFF;

// Extended opcodes (0x5B prefix)
pub const AML_EXT_MUTEX_OP: u8 = 0x01;
pub const AML_EXT_EVENT_OP: u8 = 0x02;
pub const AML_EXT_COND_REF_OP: u8 = 0x12;
pub const AML_EXT_CREATE_FIELD: u8 = 0x13;
pub const AML_EXT_SLEEP_OP: u8 = 0x22;
pub const AML_EXT_STALL_OP: u8 = 0x21;
pub const AML_EXT_ACQUIRE_OP: u8 = 0x23;
pub const AML_EXT_SIGNAL_OP: u8 = 0x24;
pub const AML_EXT_RELEASE_OP: u8 = 0x27;
pub const AML_EXT_OP_REGION_OP: u8 = 0x80;
pub const AML_EXT_FIELD_OP: u8 = 0x81;
pub const AML_EXT_DEVICE_OP: u8 = 0x82;
pub const AML_EXT_PROCESSOR_OP: u8 = 0x83;
pub const AML_EXT_POWER_RES_OP: u8 = 0x84;
pub const AML_EXT_THERMAL_ZONE_OP: u8 = 0x85;
pub const AML_EXT_INDEX_FIELD_OP: u8 = 0x86;
pub const AML_EXT_BANK_FIELD_OP: u8 = 0x87;

// ─── OpRegion address space IDs ─────────────────────────────────────
pub const REGION_SYSMEM: u8 = 0x00;
pub const REGION_SYSIO: u8 = 0x01;
pub const REGION_PCI_CONFIG: u8 = 0x02;
pub const REGION_EMBEDDED_CTRL: u8 = 0x03;
pub const REGION_SMBUS: u8 = 0x04;

// ─────────────────── AML Object Types ───────────────────────────────
pub const AmlObjectType = enum(u8) {
    integer = 0,
    string = 1,
    buffer = 2,
    package = 3,
    field_unit = 4,
    device = 5,
    event = 6,
    method = 7,
    mutex = 8,
    op_region = 9,
    power_resource = 10,
    processor = 11,
    thermal_zone = 12,
    uninitialized = 0xFF,
};

// ─────────────────── AML Value ──────────────────────────────────────
pub const MAX_STRING_LEN = 256;
pub const MAX_BUFFER_LEN = 512;
pub const MAX_PACKAGE_SIZE = 32;

pub const AmlValue = struct {
    obj_type: AmlObjectType = .uninitialized,
    integer: u64 = 0,
    string_data: [MAX_STRING_LEN]u8 = [_]u8{0} ** MAX_STRING_LEN,
    string_len: u16 = 0,
    buffer_data: [MAX_BUFFER_LEN]u8 = [_]u8{0} ** MAX_BUFFER_LEN,
    buffer_len: u16 = 0,

    pub fn fromInt(val: u64) AmlValue {
        return .{ .obj_type = .integer, .integer = val };
    }

    pub fn fromString(s: []const u8) AmlValue {
        var v = AmlValue{ .obj_type = .string };
        const len = @min(s.len, MAX_STRING_LEN);
        @memcpy(v.string_data[0..len], s[0..len]);
        v.string_len = @intCast(len);
        return v;
    }

    pub fn toInt(self: *const AmlValue) u64 {
        return switch (self.obj_type) {
            .integer => self.integer,
            .string, .buffer => {
                // Convert first bytes to integer
                var result: u64 = 0;
                const data = if (self.obj_type == .string) self.string_data[0..self.string_len] else self.buffer_data[0..self.buffer_len];
                const count = @min(data.len, 8);
                for (data[0..count], 0..) |b, i| {
                    result |= @as(u64, b) << @intCast(i * 8);
                }
                return result;
            },
            else => 0,
        };
    }

    pub fn isTrue(self: *const AmlValue) bool {
        return self.toInt() != 0;
    }
};

// ─────────────────── Namespace Node ─────────────────────────────────
pub const MAX_NS_NODES = 512;
pub const NAME_SIZE = 4;

pub const NamespaceNode = struct {
    name: [NAME_SIZE]u8 = [_]u8{0} ** NAME_SIZE,
    parent: u16 = 0xFFFF, // index of parent, 0xFFFF = root
    obj_type: AmlObjectType = .uninitialized,
    value: AmlValue = .{},
    /// For methods: bytecode offset and length
    method_offset: u32 = 0,
    method_length: u32 = 0,
    method_arg_count: u8 = 0,
    method_serialized: bool = false,
    /// For OpRegion
    region_space: u8 = 0,
    region_offset: u64 = 0,
    region_length: u64 = 0,
    /// For Field
    field_bit_offset: u32 = 0,
    field_bit_length: u32 = 0,
    field_region_idx: u16 = 0xFFFF,
    /// Active
    valid: bool = false,
};

pub const Namespace = struct {
    nodes: [MAX_NS_NODES]NamespaceNode = [_]NamespaceNode{.{}} ** MAX_NS_NODES,
    node_count: u16 = 0,

    pub fn init(self: *Namespace) void {
        // Create root node "\"
        self.nodes[0].name = [_]u8{ '\\', 0, 0, 0 };
        self.nodes[0].parent = 0xFFFF;
        self.nodes[0].obj_type = .device;
        self.nodes[0].valid = true;
        self.node_count = 1;
    }

    pub fn addNode(self: *Namespace, name: [NAME_SIZE]u8, parent: u16, obj_type: AmlObjectType) ?u16 {
        if (self.node_count >= MAX_NS_NODES) return null;
        const idx = self.node_count;
        self.nodes[idx].name = name;
        self.nodes[idx].parent = parent;
        self.nodes[idx].obj_type = obj_type;
        self.nodes[idx].valid = true;
        self.node_count += 1;
        return idx;
    }

    /// Find a child node by name under given parent
    pub fn findChild(self: *const Namespace, parent: u16, name: [NAME_SIZE]u8) ?u16 {
        for (0..self.node_count) |i| {
            const node = &self.nodes[i];
            if (node.valid and node.parent == parent and std.mem.eql(u8, &node.name, &name)) {
                return @intCast(i);
            }
        }
        return null;
    }

    /// Resolve a path like "\_SB.PCI0.LPCB"
    pub fn resolvePath(self: *const Namespace, path: []const u8) ?u16 {
        if (path.len == 0) return 0;

        var current: u16 = 0; // root

        var offset: usize = 0;
        if (path[0] == '\\') {
            current = 0;
            offset = 1;
        }
        while (offset + NAME_SIZE <= path.len) {
            var seg: [NAME_SIZE]u8 = [_]u8{'_'} ** NAME_SIZE;
            var seg_len: usize = 0;
            while (offset + seg_len < path.len and path[offset + seg_len] != '.' and seg_len < NAME_SIZE) {
                seg[seg_len] = path[offset + seg_len];
                seg_len += 1;
            }
            offset += seg_len;
            if (offset < path.len and path[offset] == '.') offset += 1;

            if (self.findChild(current, seg)) |child| {
                current = child;
            } else {
                return null;
            }
        }
        return current;
    }
};

// ─────────────────── AML Parser/Interpreter ─────────────────────────
pub const MAX_LOCALS = 8;
pub const MAX_ARGS = 7;
pub const MAX_STACK_DEPTH = 16;

pub const InterpreterFrame = struct {
    locals: [MAX_LOCALS]AmlValue = [_]AmlValue{.{}} ** MAX_LOCALS,
    args: [MAX_ARGS]AmlValue = [_]AmlValue{.{}} ** MAX_ARGS,
    scope: u16 = 0, // current namespace scope
    pc: u32 = 0,
    end: u32 = 0,
    return_value: AmlValue = .{},
    returned: bool = false,
    break_flag: bool = false,
};

pub const AmlInterpreter = struct {
    aml: []const u8,
    ns: Namespace = .{},
    stack: [MAX_STACK_DEPTH]InterpreterFrame = [_]InterpreterFrame{.{}} ** MAX_STACK_DEPTH,
    stack_depth: u8 = 0,
    initialized: bool = false,

    pub fn init(self: *AmlInterpreter, aml_data: []const u8) void {
        self.aml = aml_data;
        self.ns.init();
        self.initialized = true;
    }

    /// Parse AML bytecode and populate namespace
    pub fn parseTable(self: *AmlInterpreter) bool {
        if (!self.initialized) return false;

        var frame = InterpreterFrame{};
        frame.scope = 0; // root
        frame.pc = 0;
        frame.end = @intCast(self.aml.len);
        self.stack[0] = frame;
        self.stack_depth = 1;

        self.parseBlock();
        return true;
    }

    fn parseBlock(self: *AmlInterpreter) void {
        while (self.currentFrame().pc < self.currentFrame().end and !self.currentFrame().returned) {
            if (!self.parseOne()) break;
        }
    }

    fn currentFrame(self: *AmlInterpreter) *InterpreterFrame {
        return &self.stack[self.stack_depth - 1];
    }

    fn readByte(self: *AmlInterpreter) ?u8 {
        const frame = self.currentFrame();
        if (frame.pc >= self.aml.len) return null;
        const b = self.aml[frame.pc];
        frame.pc += 1;
        return b;
    }

    fn readWord(self: *AmlInterpreter) ?u16 {
        const lo = self.readByte() orelse return null;
        const hi = self.readByte() orelse return null;
        return @as(u16, hi) << 8 | lo;
    }

    fn readDword(self: *AmlInterpreter) ?u32 {
        const lo = self.readWord() orelse return null;
        const hi = self.readWord() orelse return null;
        return @as(u32, hi) << 16 | lo;
    }

    fn readQword(self: *AmlInterpreter) ?u64 {
        const lo = self.readDword() orelse return null;
        const hi = self.readDword() orelse return null;
        return @as(u64, hi) << 32 | lo;
    }

    /// Parse PkgLength encoding
    fn parsePkgLen(self: *AmlInterpreter) ?u32 {
        const lead = self.readByte() orelse return null;
        const count = (lead >> 6) & 0x03;
        if (count == 0) {
            return lead & 0x3F;
        }
        var length: u32 = lead & 0x0F;
        if (count >= 1) {
            const b = self.readByte() orelse return null;
            length |= @as(u32, b) << 4;
        }
        if (count >= 2) {
            const b = self.readByte() orelse return null;
            length |= @as(u32, b) << 12;
        }
        if (count >= 3) {
            const b = self.readByte() orelse return null;
            length |= @as(u32, b) << 20;
        }
        return length;
    }

    /// Parse a 4-byte name segment
    fn parseNameSeg(self: *AmlInterpreter) ?[NAME_SIZE]u8 {
        var seg: [NAME_SIZE]u8 = undefined;
        for (&seg) |*c| {
            c.* = self.readByte() orelse return null;
        }
        return seg;
    }

    /// Evaluate a data object (integer literal, string, etc.)
    fn evalDataObj(self: *AmlInterpreter) ?AmlValue {
        const op = self.readByte() orelse return null;
        return switch (op) {
            AML_ZERO_OP => AmlValue.fromInt(0),
            AML_ONE_OP => AmlValue.fromInt(1),
            AML_ONES_OP => AmlValue.fromInt(0xFFFFFFFFFFFFFFFF),
            AML_BYTE_PREFIX => AmlValue.fromInt(self.readByte() orelse return null),
            AML_WORD_PREFIX => AmlValue.fromInt(self.readWord() orelse return null),
            AML_DWORD_PREFIX => AmlValue.fromInt(self.readDword() orelse return null),
            AML_QWORD_PREFIX => AmlValue.fromInt(self.readQword() orelse return null),
            AML_STRING_PREFIX => {
                var val = AmlValue{ .obj_type = .string };
                var i: u16 = 0;
                while (i < MAX_STRING_LEN) : (i += 1) {
                    const c = self.readByte() orelse return null;
                    if (c == 0) break;
                    val.string_data[i] = c;
                }
                val.string_len = i;
                return val;
            },
            AML_LOCAL0_OP...AML_LOCAL7_OP => self.currentFrame().locals[op - AML_LOCAL0_OP],
            AML_ARG0_OP...AML_ARG6_OP => self.currentFrame().args[op - AML_ARG0_OP],
            else => {
                // Unknown data, back up
                self.currentFrame().pc -= 1;
                return null;
            },
        };
    }

    fn parseOne(self: *AmlInterpreter) bool {
        const op = self.readByte() orelse return false;

        switch (op) {
            AML_SCOPE_OP => return self.parseScope(),
            AML_NAME_OP => return self.parseName(),
            AML_METHOD_OP => return self.parseMethod(),
            AML_IF_OP => return self.parseIf(),
            AML_ELSE_OP => return self.parseElse(),
            AML_WHILE_OP => return self.parseWhile(),
            AML_RETURN_OP => return self.parseReturn(),
            AML_STORE_OP => return self.parseStore(),
            AML_ADD_OP => return self.parseBinaryOp(.add),
            AML_SUBTRACT_OP => return self.parseBinaryOp(.subtract),
            AML_MULTIPLY_OP => return self.parseBinaryOp(.multiply),
            AML_AND_OP => return self.parseBinaryOp(.bitand),
            AML_OR_OP => return self.parseBinaryOp(.bitor),
            AML_XOR_OP => return self.parseBinaryOp(.bitxor),
            AML_SHIFT_LEFT_OP => return self.parseBinaryOp(.shl),
            AML_SHIFT_RIGHT_OP => return self.parseBinaryOp(.shr),
            AML_NOOP_OP => return true,
            AML_BREAK_OP => {
                self.currentFrame().break_flag = true;
                return true;
            },
            AML_INCREMENT_OP, AML_DECREMENT_OP => {
                return self.parseIncDec(op == AML_INCREMENT_OP);
            },
            AML_EXT_OP_PREFIX => return self.parseExtended(),
            else => {
                // Skip unknown single-byte ops
                return true;
            },
        }
    }

    fn parseScope(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const name = self.parseNameSeg() orelse return false;

        // Find or create scope
        const scope = self.currentFrame().scope;
        const node = self.ns.findChild(scope, name) orelse
            (self.ns.addNode(name, scope, .device) orelse return false);

        const saved_scope = self.currentFrame().scope;
        const saved_end = self.currentFrame().end;
        self.currentFrame().scope = node;
        self.currentFrame().end = @min(end, @as(u32, @intCast(self.aml.len)));

        self.parseBlock();

        self.currentFrame().scope = saved_scope;
        self.currentFrame().end = saved_end;
        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseName(self: *AmlInterpreter) bool {
        const name = self.parseNameSeg() orelse return false;
        const value = self.evalDataObj() orelse AmlValue{};

        const scope = self.currentFrame().scope;
        if (self.ns.addNode(name, scope, value.obj_type)) |idx| {
            self.ns.nodes[idx].value = value;
        }
        return true;
    }

    fn parseMethod(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const method_start = self.currentFrame().pc;
        const method_end = method_start + pkg_len - 1;
        const name = self.parseNameSeg() orelse return false;
        const flags = self.readByte() orelse return false;

        const arg_count = flags & 0x07;
        const serialized = (flags & 0x08) != 0;

        const scope = self.currentFrame().scope;
        if (self.ns.addNode(name, scope, .method)) |idx| {
            self.ns.nodes[idx].method_offset = self.currentFrame().pc;
            self.ns.nodes[idx].method_length = method_end - self.currentFrame().pc;
            self.ns.nodes[idx].method_arg_count = @intCast(arg_count);
            self.ns.nodes[idx].method_serialized = serialized;
        }

        // Skip method body
        self.currentFrame().pc = @min(method_end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseIf(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const cond = self.evalDataObj() orelse AmlValue.fromInt(0);

        if (cond.isTrue()) {
            const saved_end = self.currentFrame().end;
            self.currentFrame().end = @min(end, @as(u32, @intCast(self.aml.len)));
            self.parseBlock();
            self.currentFrame().end = saved_end;
        }

        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseElse(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        // Else block is skipped unless the If was false (simplified)
        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseWhile(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const loop_start = self.currentFrame().pc;

        var iterations: u32 = 0;
        while (iterations < 10000) : (iterations += 1) {
            self.currentFrame().pc = loop_start;
            const cond = self.evalDataObj() orelse break;
            if (!cond.isTrue()) break;

            const saved_end = self.currentFrame().end;
            self.currentFrame().end = @min(end, @as(u32, @intCast(self.aml.len)));
            self.parseBlock();
            self.currentFrame().end = saved_end;

            if (self.currentFrame().break_flag) {
                self.currentFrame().break_flag = false;
                break;
            }
            if (self.currentFrame().returned) break;
        }

        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseReturn(self: *AmlInterpreter) bool {
        const val = self.evalDataObj() orelse AmlValue.fromInt(0);
        self.currentFrame().return_value = val;
        self.currentFrame().returned = true;
        return true;
    }

    fn parseStore(self: *AmlInterpreter) bool {
        const src = self.evalDataObj() orelse return false;
        const target = self.readByte() orelse return false;

        if (target >= AML_LOCAL0_OP and target <= AML_LOCAL7_OP) {
            self.currentFrame().locals[target - AML_LOCAL0_OP] = src;
        } else if (target >= AML_ARG0_OP and target <= AML_ARG6_OP) {
            self.currentFrame().args[target - AML_ARG0_OP] = src;
        }
        return true;
    }

    const BinOp = enum { add, subtract, multiply, bitand, bitor, bitxor, shl, shr };

    fn parseBinaryOp(self: *AmlInterpreter, op: BinOp) bool {
        const a = self.evalDataObj() orelse return false;
        const b = self.evalDataObj() orelse return false;
        const target = self.readByte() orelse return false;

        const va = a.toInt();
        const vb = b.toInt();
        const result = switch (op) {
            .add => va +% vb,
            .subtract => va -% vb,
            .multiply => va *% vb,
            .bitand => va & vb,
            .bitor => va | vb,
            .bitxor => va ^ vb,
            .shl => if (vb < 64) va << @intCast(vb) else 0,
            .shr => if (vb < 64) va >> @intCast(vb) else 0,
        };

        if (target >= AML_LOCAL0_OP and target <= AML_LOCAL7_OP) {
            self.currentFrame().locals[target - AML_LOCAL0_OP] = AmlValue.fromInt(result);
        }
        return true;
    }

    fn parseIncDec(self: *AmlInterpreter, increment: bool) bool {
        const target = self.readByte() orelse return false;
        if (target >= AML_LOCAL0_OP and target <= AML_LOCAL7_OP) {
            const idx = target - AML_LOCAL0_OP;
            const val = self.currentFrame().locals[idx].toInt();
            self.currentFrame().locals[idx] = AmlValue.fromInt(if (increment) val +% 1 else val -% 1);
        }
        return true;
    }

    fn parseExtended(self: *AmlInterpreter) bool {
        const ext_op = self.readByte() orelse return false;
        switch (ext_op) {
            AML_EXT_OP_REGION_OP => return self.parseOpRegion(),
            AML_EXT_FIELD_OP => return self.parseField(),
            AML_EXT_DEVICE_OP => return self.parseDevice(),
            AML_EXT_PROCESSOR_OP => return self.parseProcessor(),
            AML_EXT_THERMAL_ZONE_OP => return self.parseThermalZone(),
            AML_EXT_MUTEX_OP => {
                _ = self.parseNameSeg();
                _ = self.readByte(); // sync level
                return true;
            },
            AML_EXT_SLEEP_OP, AML_EXT_STALL_OP => {
                _ = self.evalDataObj();
                return true;
            },
            else => return true,
        }
    }

    fn parseOpRegion(self: *AmlInterpreter) bool {
        const name = self.parseNameSeg() orelse return false;
        const space = self.readByte() orelse return false;
        const offset_val = self.evalDataObj() orelse return false;
        const length_val = self.evalDataObj() orelse return false;

        const scope = self.currentFrame().scope;
        if (self.ns.addNode(name, scope, .op_region)) |idx| {
            self.ns.nodes[idx].region_space = space;
            self.ns.nodes[idx].region_offset = offset_val.toInt();
            self.ns.nodes[idx].region_length = length_val.toInt();
        }
        return true;
    }

    fn parseField(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const _region_name = self.parseNameSeg() orelse return false;
        const _flags = self.readByte() orelse return false;

        // Skip field elements
        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseDevice(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const name = self.parseNameSeg() orelse return false;

        const scope = self.currentFrame().scope;
        const node = self.ns.addNode(name, scope, .device) orelse return false;

        const saved_scope = self.currentFrame().scope;
        const saved_end = self.currentFrame().end;
        self.currentFrame().scope = node;
        self.currentFrame().end = @min(end, @as(u32, @intCast(self.aml.len)));

        self.parseBlock();

        self.currentFrame().scope = saved_scope;
        self.currentFrame().end = saved_end;
        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseProcessor(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const name = self.parseNameSeg() orelse return false;
        _ = self.readByte(); // proc ID
        _ = self.readDword(); // PBlk address
        _ = self.readByte(); // PBlk length

        const scope = self.currentFrame().scope;
        _ = self.ns.addNode(name, scope, .processor);

        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    fn parseThermalZone(self: *AmlInterpreter) bool {
        const pkg_len = self.parsePkgLen() orelse return false;
        const end = self.currentFrame().pc + pkg_len - 1;
        const name = self.parseNameSeg() orelse return false;

        const scope = self.currentFrame().scope;
        _ = self.ns.addNode(name, scope, .thermal_zone);

        self.currentFrame().pc = @min(end, @as(u32, @intCast(self.aml.len)));
        return true;
    }

    /// Execute a named method
    pub fn executeMethod(self: *AmlInterpreter, path: []const u8, args: []const AmlValue) ?AmlValue {
        const node_idx = self.ns.resolvePath(path) orelse return null;
        const node = &self.ns.nodes[node_idx];
        if (node.obj_type != .method) return null;

        if (self.stack_depth >= MAX_STACK_DEPTH) return null;

        var frame = InterpreterFrame{};
        frame.scope = node_idx;
        frame.pc = node.method_offset;
        frame.end = node.method_offset + node.method_length;

        const arg_count = @min(args.len, MAX_ARGS);
        for (args[0..arg_count], 0..) |arg, i| {
            frame.args[i] = arg;
        }

        self.stack[self.stack_depth] = frame;
        self.stack_depth += 1;

        self.parseBlock();

        self.stack_depth -= 1;
        return self.stack[self.stack_depth].return_value;
    }

    pub fn namespaceNodeCount(self: *const AmlInterpreter) u16 {
        return self.ns.node_count;
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var aml_interpreter: AmlInterpreter = .{ .aml = &[_]u8{} };

pub fn getInterpreter() *AmlInterpreter {
    return &aml_interpreter;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_aml_init(aml_data: [*]const u8, aml_len: u32) void {
    if (aml_len > 0) {
        aml_interpreter.init(aml_data[0..aml_len]);
    }
}

export fn zxy_aml_parse() bool {
    return aml_interpreter.parseTable();
}

export fn zxy_aml_node_count() u16 {
    return aml_interpreter.namespaceNodeCount();
}

export fn zxy_aml_execute(path: [*]const u8, path_len: u32) u64 {
    if (path_len == 0) return 0;
    if (aml_interpreter.executeMethod(path[0..path_len], &[_]AmlValue{})) |result| {
        return result.toInt();
    }
    return 0;
}
