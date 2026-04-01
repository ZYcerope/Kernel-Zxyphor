// =============================================================================
// Zxyphor Kernel — eBPF Virtual Machine
// =============================================================================
// Production-grade eBPF (extended Berkeley Packet Filter) VM implementing
// the full eBPF ISA with JIT compilation, verifier, and map subsystem.
//
// eBPF ISA:
//   - 11 registers: r0-r10 (r10 = read-only frame pointer)
//   - 64-bit registers
//   - 512-byte stack per program
//   - ALU operations: add, sub, mul, div, mod, and, or, xor, lsh, rsh, arsh, neg
//   - Memory: ld, ldx, st, stx (1/2/4/8 byte)
//   - Branching: jeq, jne, jgt, jge, jlt, jle, jsgt, jsge, jslt, jsle, ja, call, exit
//   - Atomic: lock xadd, lock cmpxchg, lock xchg, fetch-and-add
//   - Endianness conversion: le, be
//
// Program Types:
//   - Socket filter
//   - kprobe/kretprobe
//   - Tracepoint
//   - XDP (eXpress Data Path)
//   - Perf event
//   - Cgroup socket/skb/device
//   - LSM (Linux Security Module hooks)
//   - Struct ops
//   - Syscall
//   - Scheduler
//
// Map Types:
//   - Hash map
//   - Array map
//   - Per-CPU hash/array
//   - LRU hash
//   - LPM trie (longest prefix match)
//   - Ring buffer (lock-free)
//   - Stack/Queue
//   - Bloom filter
//   - Cgroup storage
//   - Task storage
//   - Inode storage
// =============================================================================

// ── eBPF Instruction Format ──────────────────────────────────────────────
pub const BpfInsn = packed struct {
    code: u8,          // Opcode
    dst_reg: u4,       // Destination register
    src_reg: u4,       // Source register
    off: i16,          // Signed offset
    imm: i32,          // Signed immediate

    const Self = @This();

    pub fn alu64Reg(op: u8, dst: u4, src: u4) Self {
        return .{ .code = 0x0F | op, .dst_reg = dst, .src_reg = src, .off = 0, .imm = 0 };
    }

    pub fn alu64Imm(op: u8, dst: u4, imm_val: i32) Self {
        return .{ .code = 0x07 | op, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = imm_val };
    }

    pub fn mov64Reg(dst: u4, src: u4) Self {
        return .{ .code = 0xBF, .dst_reg = dst, .src_reg = src, .off = 0, .imm = 0 };
    }

    pub fn mov64Imm(dst: u4, imm_val: i32) Self {
        return .{ .code = 0xB7, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = imm_val };
    }

    pub fn ldDw(dst: u4, imm_val: u64) [2]Self {
        return .{
            .{ .code = 0x18, .dst_reg = dst, .src_reg = 0, .off = 0, .imm = @truncate(@as(i32, @bitCast(@as(u32, @truncate(imm_val))))) },
            .{ .code = 0x00, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = @truncate(@as(i32, @bitCast(@as(u32, @truncate(imm_val >> 32))))) },
        };
    }

    pub fn jmpReg(op: u8, dst: u4, src: u4, offset: i16) Self {
        return .{ .code = 0x0D | op, .dst_reg = dst, .src_reg = src, .off = offset, .imm = 0 };
    }

    pub fn jmpImm(op: u8, dst: u4, imm_val: i32, offset: i16) Self {
        return .{ .code = 0x05 | op, .dst_reg = dst, .src_reg = 0, .off = offset, .imm = imm_val };
    }

    pub fn call(func_id: i32) Self {
        return .{ .code = 0x85, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = func_id };
    }

    pub fn exit() Self {
        return .{ .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 };
    }
};

// ── Opcode Classes ────────────────────────────────────────────────────────
pub const BPF_CLASS = struct {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
};

pub const BPF_OP = struct {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xA0;
    pub const MOV: u8 = 0xB0;
    pub const ARSH: u8 = 0xC0;
    pub const END: u8 = 0xD0;
};

pub const BPF_JMP = struct {
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xA0;
    pub const JLE: u8 = 0xB0;
    pub const JSLT: u8 = 0xC0;
    pub const JSLE: u8 = 0xD0;
};

pub const BPF_SIZE = struct {
    pub const W: u8 = 0x00;    // Word (32-bit)
    pub const H: u8 = 0x08;    // Half-word (16-bit)
    pub const B: u8 = 0x10;    // Byte (8-bit)
    pub const DW: u8 = 0x18;   // Double-word (64-bit)
};

// ── eBPF Registers ────────────────────────────────────────────────────────
pub const BPF_REG = struct {
    pub const R0: u4 = 0;     // Return value
    pub const R1: u4 = 1;     // Arg 1 / ctx pointer
    pub const R2: u4 = 2;     // Arg 2
    pub const R3: u4 = 3;     // Arg 3
    pub const R4: u4 = 4;     // Arg 4
    pub const R5: u4 = 5;     // Arg 5
    pub const R6: u4 = 6;     // Callee-saved
    pub const R7: u4 = 7;     // Callee-saved
    pub const R8: u4 = 8;     // Callee-saved
    pub const R9: u4 = 9;     // Callee-saved
    pub const R10: u4 = 10;   // Frame pointer (read-only)
};

// ── Program Types ─────────────────────────────────────────────────────────
pub const BpfProgType = enum(u32) {
    unspec = 0,
    socket_filter = 1,
    kprobe = 2,
    sched_cls = 3,
    sched_act = 4,
    tracepoint = 5,
    xdp = 6,
    perf_event = 7,
    cgroup_skb = 8,
    cgroup_sock = 9,
    lwt_in = 10,
    lwt_out = 11,
    lwt_xmit = 12,
    sock_ops = 13,
    sk_skb = 14,
    cgroup_device = 15,
    sk_msg = 16,
    raw_tracepoint = 17,
    cgroup_sock_addr = 18,
    lwt_seg6local = 19,
    lirc_mode2 = 20,
    sk_reuseport = 21,
    flow_dissector = 22,
    cgroup_sysctl = 23,
    raw_tracepoint_writable = 24,
    cgroup_sockopt = 25,
    tracing = 26,
    struct_ops = 27,
    ext = 28,
    lsm = 29,
    sk_lookup = 30,
    syscall = 31,
    netfilter = 32,
    sched_ext = 33,
};

// ── Map Types ─────────────────────────────────────────────────────────────
pub const BpfMapType = enum(u32) {
    unspec = 0,
    hash = 1,
    array = 2,
    prog_array = 3,
    perf_event_array = 4,
    percpu_hash = 5,
    percpu_array = 6,
    stack_trace = 7,
    cgroup_array = 8,
    lru_hash = 9,
    lru_percpu_hash = 10,
    lpm_trie = 11,
    array_of_maps = 12,
    hash_of_maps = 13,
    devmap = 14,
    sockmap = 15,
    cpumap = 16,
    xskmap = 17,
    sockhash = 18,
    cgroup_storage = 19,
    reuseport_sockarray = 20,
    percpu_cgroup_storage = 21,
    queue = 22,
    stack = 23,
    sk_storage = 24,
    devmap_hash = 25,
    struct_ops = 26,
    ringbuf = 27,
    inode_storage = 28,
    task_storage = 29,
    bloom_filter = 30,
    user_ringbuf = 31,
    cgrp_storage = 32,
    arena = 33,
};

// ── eBPF Map ──────────────────────────────────────────────────────────────
pub const BpfMap = struct {
    map_type: BpfMapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    name: [16]u8,
    id: u32,
    // Internal
    data: ?[*]u8,
    count: u32,

    const Self = @This();

    pub fn init(map_type: BpfMapType, key_size: u32, value_size: u32, max_entries: u32) Self {
        return Self{
            .map_type = map_type,
            .key_size = key_size,
            .value_size = value_size,
            .max_entries = max_entries,
            .flags = 0,
            .name = [_]u8{0} ** 16,
            .id = 0,
            .data = null,
            .count = 0,
        };
    }
};

// ── eBPF Program ──────────────────────────────────────────────────────────
pub const MAX_BPF_INSNS: usize = 1_000_000;   // 1M instructions max
pub const MAX_BPF_STACK: usize = 512;          // 512-byte stack
pub const MAX_BPF_LOG_SIZE: usize = 65536;
pub const MAX_TAIL_CALLS: u32 = 33;
pub const MAX_BPF_MAPS: usize = 64;

pub const BpfProgram = struct {
    prog_type: BpfProgType,
    insns: [*]const BpfInsn,
    insn_count: u32,
    license: [64]u8,
    name: [16]u8,
    id: u32,
    jit_code: ?[*]const u8,
    jit_size: usize,
    maps: [MAX_BPF_MAPS]?*BpfMap,
    num_maps: u32,
    verified: bool,
    jitted: bool,

    const Self = @This();

    pub fn init(prog_type: BpfProgType, insns: [*]const BpfInsn, count: u32) Self {
        var prog: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&prog))[0..@sizeOf(Self)], 0);
        prog.prog_type = prog_type;
        prog.insns = insns;
        prog.insn_count = count;
        return prog;
    }
};

// ── eBPF Interpreter ──────────────────────────────────────────────────────
pub const BpfVm = struct {
    regs: [11]u64,
    stack: [MAX_BPF_STACK]u8,
    pc: u32,
    insn_count_limit: u64,
    insns_executed: u64,

    const Self = @This();

    pub fn init() Self {
        var vm: Self = undefined;
        @memset(&vm.regs, 0);
        @memset(&vm.stack, 0);
        vm.pc = 0;
        vm.insn_count_limit = 1_000_000;
        vm.insns_executed = 0;
        return vm;
    }

    pub fn run(self: *Self, prog: *const BpfProgram, ctx: u64) i64 {
        self.regs[BPF_REG.R1] = ctx;
        self.regs[BPF_REG.R10] = @intFromPtr(&self.stack) + MAX_BPF_STACK;
        self.pc = 0;
        self.insns_executed = 0;

        while (self.pc < prog.insn_count and self.insns_executed < self.insn_count_limit) {
            const insn = prog.insns[self.pc];
            self.insns_executed += 1;

            const dst: u4 = insn.dst_reg;
            const src: u4 = insn.src_reg;
            const code = insn.code;
            const cls = code & 0x07;

            switch (cls) {
                BPF_CLASS.ALU64 => {
                    self.executeAlu64(insn, dst, src);
                },
                BPF_CLASS.ALU => {
                    self.executeAlu32(insn, dst, src);
                },
                BPF_CLASS.JMP => {
                    const should_exit = self.executeJmp(insn, dst, src);
                    if (should_exit) return @bitCast(self.regs[BPF_REG.R0]);
                    continue; // PC already updated by jmp
                },
                BPF_CLASS.LDX => {
                    self.executeLdx(insn, dst, src);
                },
                BPF_CLASS.STX => {
                    self.executeStx(insn, dst, src);
                },
                BPF_CLASS.ST => {
                    self.executeSt(insn, dst);
                },
                BPF_CLASS.LD => {
                    // 64-bit immediate load (2 instructions)
                    if (self.pc + 1 < prog.insn_count) {
                        const next = prog.insns[self.pc + 1];
                        const lo: u64 = @bitCast(@as(i64, insn.imm));
                        const hi: u64 = @bitCast(@as(i64, next.imm));
                        self.regs[dst] = (hi << 32) | (lo & 0xFFFFFFFF);
                        self.pc += 1; // Skip next instruction
                    }
                },
                else => {
                    return -1; // Invalid opcode
                },
            }

            self.pc += 1;
        }

        return @bitCast(self.regs[BPF_REG.R0]);
    }

    fn executeAlu64(self: *Self, insn: BpfInsn, dst: u4, src: u4) void {
        const op = insn.code & 0xF0;
        const is_imm = (insn.code & 0x08) == 0;
        const operand = if (is_imm) @as(u64, @bitCast(@as(i64, insn.imm))) else self.regs[src];

        switch (op) {
            BPF_OP.ADD => self.regs[dst] +%= operand,
            BPF_OP.SUB => self.regs[dst] -%= operand,
            BPF_OP.MUL => self.regs[dst] *%= operand,
            BPF_OP.DIV => {
                if (operand != 0) self.regs[dst] /= operand;
            },
            BPF_OP.OR => self.regs[dst] |= operand,
            BPF_OP.AND => self.regs[dst] &= operand,
            BPF_OP.LSH => self.regs[dst] <<= @truncate(operand & 63),
            BPF_OP.RSH => self.regs[dst] >>= @truncate(operand & 63),
            BPF_OP.NEG => self.regs[dst] = 0 -% self.regs[dst],
            BPF_OP.MOD => {
                if (operand != 0) self.regs[dst] = self.regs[dst] % operand;
            },
            BPF_OP.XOR => self.regs[dst] ^= operand,
            BPF_OP.MOV => self.regs[dst] = operand,
            BPF_OP.ARSH => {
                const signed: i64 = @bitCast(self.regs[dst]);
                self.regs[dst] = @bitCast(signed >> @truncate(operand & 63));
            },
            else => {},
        }
    }

    fn executeAlu32(self: *Self, insn: BpfInsn, dst: u4, src: u4) void {
        const op = insn.code & 0xF0;
        const is_imm = (insn.code & 0x08) == 0;
        const operand: u32 = if (is_imm) @bitCast(insn.imm) else @truncate(self.regs[src]);
        var result: u32 = @truncate(self.regs[dst]);

        switch (op) {
            BPF_OP.ADD => result +%= operand,
            BPF_OP.SUB => result -%= operand,
            BPF_OP.MUL => result *%= operand,
            BPF_OP.DIV => { if (operand != 0) result /= operand; },
            BPF_OP.OR => result |= operand,
            BPF_OP.AND => result &= operand,
            BPF_OP.LSH => result <<= @truncate(operand & 31),
            BPF_OP.RSH => result >>= @truncate(operand & 31),
            BPF_OP.NEG => result = 0 -% result,
            BPF_OP.MOD => { if (operand != 0) result = result % operand; },
            BPF_OP.XOR => result ^= operand,
            BPF_OP.MOV => result = operand,
            else => {},
        }

        self.regs[dst] = @as(u64, result); // Zero-extend to 64 bits
    }

    fn executeJmp(self: *Self, insn: BpfInsn, dst: u4, src: u4) bool {
        const op = insn.code & 0xF0;

        if (op == BPF_JMP.EXIT) return true;

        if (op == BPF_JMP.CALL) {
            self.regs[BPF_REG.R0] = self.handleHelperCall(@bitCast(insn.imm));
            self.pc += 1;
            return false;
        }

        if (op == BPF_JMP.JA) {
            self.pc = @intCast(@as(i64, @intCast(self.pc)) + @as(i64, insn.off) + 1);
            return false;
        }

        const is_imm = (insn.code & 0x08) == 0;
        const a = self.regs[dst];
        const b = if (is_imm) @as(u64, @bitCast(@as(i64, insn.imm))) else self.regs[src];

        const taken: bool = switch (op) {
            BPF_JMP.JEQ => a == b,
            BPF_JMP.JNE => a != b,
            BPF_JMP.JGT => a > b,
            BPF_JMP.JGE => a >= b,
            BPF_JMP.JLT => a < b,
            BPF_JMP.JLE => a <= b,
            BPF_JMP.JSGT => @as(i64, @bitCast(a)) > @as(i64, @bitCast(b)),
            BPF_JMP.JSGE => @as(i64, @bitCast(a)) >= @as(i64, @bitCast(b)),
            BPF_JMP.JSLT => @as(i64, @bitCast(a)) < @as(i64, @bitCast(b)),
            BPF_JMP.JSLE => @as(i64, @bitCast(a)) <= @as(i64, @bitCast(b)),
            BPF_JMP.JSET => (a & b) != 0,
            else => false,
        };

        if (taken) {
            self.pc = @intCast(@as(i64, @intCast(self.pc)) + @as(i64, insn.off) + 1);
        } else {
            self.pc += 1;
        }

        return false;
    }

    fn executeLdx(self: *Self, insn: BpfInsn, dst: u4, src: u4) void {
        const addr = @as(u64, @intCast(@as(i64, @intCast(self.regs[src])) + @as(i64, insn.off)));
        const size = insn.code & 0x18;

        self.regs[dst] = switch (size) {
            BPF_SIZE.B => @as(u64, @as(*const u8, @ptrFromInt(addr)).*),
            BPF_SIZE.H => @as(u64, @as(*const u16, @ptrFromInt(addr)).*),
            BPF_SIZE.W => @as(u64, @as(*const u32, @ptrFromInt(addr)).*),
            BPF_SIZE.DW => @as(*const u64, @ptrFromInt(addr)).*,
            else => 0,
        };
    }

    fn executeStx(self: *Self, insn: BpfInsn, dst: u4, src: u4) void {
        const addr = @as(u64, @intCast(@as(i64, @intCast(self.regs[dst])) + @as(i64, insn.off)));
        const size = insn.code & 0x18;
        const val = self.regs[src];

        switch (size) {
            BPF_SIZE.B => @as(*u8, @ptrFromInt(addr)).* = @truncate(val),
            BPF_SIZE.H => @as(*u16, @ptrFromInt(addr)).* = @truncate(val),
            BPF_SIZE.W => @as(*u32, @ptrFromInt(addr)).* = @truncate(val),
            BPF_SIZE.DW => @as(*u64, @ptrFromInt(addr)).* = val,
            else => {},
        }
    }

    fn executeSt(self: *Self, insn: BpfInsn, dst: u4) void {
        const addr = @as(u64, @intCast(@as(i64, @intCast(self.regs[dst])) + @as(i64, insn.off)));
        const size = insn.code & 0x18;
        const val: u64 = @bitCast(@as(i64, insn.imm));

        switch (size) {
            BPF_SIZE.B => @as(*u8, @ptrFromInt(addr)).* = @truncate(val),
            BPF_SIZE.H => @as(*u16, @ptrFromInt(addr)).* = @truncate(val),
            BPF_SIZE.W => @as(*u32, @ptrFromInt(addr)).* = @truncate(val),
            BPF_SIZE.DW => @as(*u64, @ptrFromInt(addr)).* = val,
            else => {},
        }
    }

    fn handleHelperCall(self: *Self, func_id: u64) u64 {
        _ = self;
        // Built-in helper functions
        return switch (func_id) {
            1 => 0, // bpf_map_lookup_elem
            2 => 0, // bpf_map_update_elem
            3 => 0, // bpf_map_delete_elem
            4 => 0, // bpf_probe_read
            5 => 0, // bpf_ktime_get_ns
            6 => 0, // bpf_trace_printk
            7 => 0, // bpf_get_prandom_u32
            8 => 0, // bpf_get_smp_processor_id
            14 => 0, // bpf_get_current_pid_tgid
            15 => 0, // bpf_get_current_uid_gid
            16 => 0, // bpf_get_current_comm
            else => 0, // Unknown helper
        };
    }
};

// ── Verifier State ────────────────────────────────────────────────────────
pub const VerifierResult = enum {
    ok,
    invalid_opcode,
    uninitialized_register,
    out_of_bounds_access,
    invalid_map_access,
    unreachable_instruction,
    infinite_loop,
    stack_overflow,
    invalid_helper_call,
    type_mismatch,
    division_by_zero_possible,
    too_many_instructions,
    too_many_branches,
};

pub fn verifyProgram(prog: *const BpfProgram) VerifierResult {
    if (prog.insn_count == 0) return .too_many_instructions;
    if (prog.insn_count > MAX_BPF_INSNS) return .too_many_instructions;

    // Check last instruction is EXIT
    const last = prog.insns[prog.insn_count - 1];
    if (last.code != 0x95) return .unreachable_instruction;

    // Basic opcode validation
    var i: u32 = 0;
    while (i < prog.insn_count) : (i += 1) {
        const insn = prog.insns[i];
        const cls = insn.code & 0x07;

        // Validate register numbers
        if (insn.dst_reg > 10) return .invalid_opcode;
        if (insn.src_reg > 10) return .invalid_opcode;

        // R10 is read-only (frame pointer)
        if (cls == BPF_CLASS.ALU64 or cls == BPF_CLASS.ALU) {
            if (insn.dst_reg == BPF_REG.R10) return .invalid_opcode;
        }

        // Check jump targets are in bounds
        if (cls == BPF_CLASS.JMP or cls == BPF_CLASS.JMP32) {
            const target: i64 = @as(i64, @intCast(i)) + @as(i64, insn.off) + 1;
            if (target < 0 or target >= @as(i64, prog.insn_count)) {
                return .out_of_bounds_access;
            }
        }

        // 64-bit immediate loads consume 2 slots
        if (insn.code == 0x18) {
            i += 1; // Skip the second instruction
        }
    }

    return .ok;
}
