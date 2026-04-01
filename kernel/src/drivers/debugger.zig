// =============================================================================
// Kernel Zxyphor — Kernel Debugger (GDB Remote Serial Protocol)
// =============================================================================
// Implements the GDB Remote Serial Protocol (RSP) stub for kernel debugging
// over the serial port. This allows connecting GDB to the running kernel for:
//   - Breakpoint management (software and hardware breakpoints)
//   - Single-step execution
//   - Register inspection and modification
//   - Memory read/write
//   - Backtrace / stack unwinding
//
// Protocol: https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
//
// GDB packets: $<data>#<checksum>
// Responses:   + (ACK) / - (NACK)
// =============================================================================

const main = @import("../main.zig");
const serial = @import("../arch/x86_64/serial.zig");
const interrupts = @import("../arch/x86_64/interrupts.zig");

// =============================================================================
// Constants
// =============================================================================

const MAX_PACKET_SIZE: usize = 4096;
const MAX_BREAKPOINTS: usize = 64;
const MAX_WATCHPOINTS: usize = 16;
const MAX_BACKTRACE_DEPTH: usize = 64;
const SERIAL_PORT: u16 = 0x3F8; // COM1

// Hardware breakpoint registers (x86_64 DR0-DR3)
const NUM_HW_BREAKPOINTS: usize = 4;

// =============================================================================
// GDB register mapping (x86_64)
// =============================================================================

pub const GdbRegister = enum(u8) {
    rax = 0,
    rbx = 1,
    rcx = 2,
    rdx = 3,
    rsi = 4,
    rdi = 5,
    rbp = 6,
    rsp = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
    rip = 16,
    rflags = 17,
    cs = 18,
    ss = 19,
    ds = 20,
    es = 21,
    fs = 22,
    gs = 23,
};

pub const NUM_GDB_REGISTERS: usize = 24;

// =============================================================================
// Saved CPU state (captured on debug trap)
// =============================================================================

pub const CpuState = struct {
    // General purpose registers
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    // Instruction pointer
    rip: u64,
    // Flags
    rflags: u64,
    // Segment registers
    cs: u64,
    ss: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,

    /// Get a register by GDB index
    pub fn getRegister(self: *const CpuState, reg: u8) ?u64 {
        return switch (reg) {
            0 => self.rax,
            1 => self.rbx,
            2 => self.rcx,
            3 => self.rdx,
            4 => self.rsi,
            5 => self.rdi,
            6 => self.rbp,
            7 => self.rsp,
            8 => self.r8,
            9 => self.r9,
            10 => self.r10,
            11 => self.r11,
            12 => self.r12,
            13 => self.r13,
            14 => self.r14,
            15 => self.r15,
            16 => self.rip,
            17 => self.rflags,
            18 => self.cs,
            19 => self.ss,
            20 => self.ds,
            21 => self.es,
            22 => self.fs,
            23 => self.gs,
            else => null,
        };
    }

    /// Set a register by GDB index
    pub fn setRegister(self: *CpuState, reg: u8, value: u64) bool {
        switch (reg) {
            0 => self.rax = value,
            1 => self.rbx = value,
            2 => self.rcx = value,
            3 => self.rdx = value,
            4 => self.rsi = value,
            5 => self.rdi = value,
            6 => self.rbp = value,
            7 => self.rsp = value,
            8 => self.r8 = value,
            9 => self.r9 = value,
            10 => self.r10 = value,
            11 => self.r11 = value,
            12 => self.r12 = value,
            13 => self.r13 = value,
            14 => self.r14 = value,
            15 => self.r15 = value,
            16 => self.rip = value,
            17 => self.rflags = value,
            18 => self.cs = value,
            19 => self.ss = value,
            20 => self.ds = value,
            21 => self.es = value,
            22 => self.fs = value,
            23 => self.gs = value,
            else => return false,
        }
        return true;
    }
};

// =============================================================================
// Breakpoint management
// =============================================================================

pub const BreakpointType = enum(u8) {
    software = 0, // INT3 (0xCC) instruction
    hardware_exec = 1, // Hardware execution breakpoint (DR0-DR3)
    hardware_write = 2, // Hardware write watchpoint
    hardware_read_write = 3, // Hardware read/write watchpoint
};

pub const Breakpoint = struct {
    address: u64,
    bp_type: BreakpointType,
    size: u8, // 1, 2, 4, or 8 bytes (for watchpoints)
    enabled: bool,
    original_byte: u8, // Saved byte for software breakpoints
    hw_register: ?u8, // DR0-DR3 index for hardware breakpoints
};

var breakpoints: [MAX_BREAKPOINTS]Breakpoint = undefined;
var breakpoint_count: usize = 0;

var watchpoints: [MAX_WATCHPOINTS]Breakpoint = undefined;
var watchpoint_count: usize = 0;

// Hardware breakpoint allocation bitmap
var hw_bp_used: [NUM_HW_BREAKPOINTS]bool = .{ false, false, false, false };

// =============================================================================
// GDB protocol state
// =============================================================================

const DebugState = enum(u8) {
    running, // CPU is executing normally
    stopped, // CPU is stopped, waiting for GDB commands
    stepping, // Single-stepping one instruction
    detached, // Debugger disconnected
};

var debug_state: DebugState = .detached;
var saved_state: CpuState = undefined;
var stop_reason: u8 = 5; // Default SIGTRAP

// Packet buffer for assembling GDB packets
var packet_buf: [MAX_PACKET_SIZE]u8 = undefined;
var response_buf: [MAX_PACKET_SIZE]u8 = undefined;

// =============================================================================
// Hex conversion helpers
// =============================================================================

const hex_chars = "0123456789abcdef";

fn hexCharToNibble(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @truncate(c - '0');
    if (c >= 'a' and c <= 'f') return @truncate(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @truncate(c - 'A' + 10);
    return null;
}

fn hexToByte(hi: u8, lo: u8) ?u8 {
    const h = hexCharToNibble(hi) orelse return null;
    const l = hexCharToNibble(lo) orelse return null;
    return (@as(u8, h) << 4) | @as(u8, l);
}

fn byteToHex(byte: u8) [2]u8 {
    return .{
        hex_chars[(byte >> 4) & 0xF],
        hex_chars[byte & 0xF],
    };
}

fn u64ToHexLE(value: u64, buf: []u8) usize {
    // GDB expects registers in target byte order (little-endian for x86)
    var offset: usize = 0;
    for (0..8) |i| {
        const byte: u8 = @truncate((value >> @intCast(i * 8)) & 0xFF);
        const hx = byteToHex(byte);
        if (offset + 1 < buf.len) {
            buf[offset] = hx[0];
            buf[offset + 1] = hx[1];
            offset += 2;
        }
    }
    return offset;
}

fn hexLEToU64(hex: []const u8) u64 {
    var value: u64 = 0;
    var byte_idx: u6 = 0;
    var i: usize = 0;
    while (i + 1 < hex.len and byte_idx < 8) {
        if (hexToByte(hex[i], hex[i + 1])) |byte| {
            value |= @as(u64, byte) << (@as(u6, byte_idx) * 8);
        }
        i += 2;
        byte_idx += 1;
    }
    return value;
}

fn hexToU64(hex: []const u8) u64 {
    var value: u64 = 0;
    for (hex) |c| {
        if (hexCharToNibble(c)) |nibble| {
            value = (value << 4) | @as(u64, nibble);
        } else break;
    }
    return value;
}

// =============================================================================
// GDB checksum
// =============================================================================

fn computeChecksum(data: []const u8) u8 {
    var sum: u8 = 0;
    for (data) |b| {
        sum = sum +% b;
    }
    return sum;
}

// =============================================================================
// Serial I/O for GDB
// =============================================================================

fn serialRead() u8 {
    // Wait for data available on COM1
    while (inb(SERIAL_PORT + 5) & 0x01 == 0) {
        asm volatile ("pause");
    }
    return inb(SERIAL_PORT);
}

fn serialWrite(byte: u8) void {
    // Wait for transmit holding register empty
    while (inb(SERIAL_PORT + 5) & 0x20 == 0) {
        asm volatile ("pause");
    }
    outb(SERIAL_PORT, byte);
}

fn serialWriteAll(data: []const u8) void {
    for (data) |b| {
        serialWrite(b);
    }
}

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

// =============================================================================
// GDB packet send/receive
// =============================================================================

/// Receive a GDB packet: $<data>#<checksum>
fn receivePacket() ?[]const u8 {
    // Wait for '$'
    while (true) {
        const c = serialRead();
        if (c == '$') break;
        if (c == 0x03) {
            // Ctrl+C: interrupt
            return null;
        }
    }

    var len: usize = 0;
    var checksum: u8 = 0;

    // Read until '#'
    while (len < MAX_PACKET_SIZE - 1) {
        const c = serialRead();
        if (c == '#') break;
        packet_buf[len] = c;
        checksum +%= c;
        len += 1;
    }

    // Read 2-digit hex checksum
    const ck_hi = serialRead();
    const ck_lo = serialRead();
    const expected = hexToByte(ck_hi, ck_lo) orelse {
        serialWrite('-'); // NACK
        return null;
    };

    if (checksum != expected) {
        serialWrite('-'); // NACK
        return null;
    }

    serialWrite('+'); // ACK
    return packet_buf[0..len];
}

/// Send a GDB packet: $<data>#<checksum>
fn sendPacket(data: []const u8) void {
    while (true) {
        serialWrite('$');
        serialWriteAll(data);
        serialWrite('#');

        const ck = computeChecksum(data);
        const ck_hex = byteToHex(ck);
        serialWrite(ck_hex[0]);
        serialWrite(ck_hex[1]);

        // Wait for ACK
        const response = serialRead();
        if (response == '+') break;
        // On '-', retransmit
    }
}

fn sendEmpty() void {
    sendPacket("");
}

fn sendOk() void {
    sendPacket("OK");
}

fn sendError(code: u8) void {
    var buf: [3]u8 = undefined;
    buf[0] = 'E';
    const hx = byteToHex(code);
    buf[1] = hx[0];
    buf[2] = hx[1];
    sendPacket(&buf);
}

// =============================================================================
// GDB command handlers
// =============================================================================

/// Handle '?' — query stop reason
fn handleQueryHalt() void {
    var buf: [3]u8 = undefined;
    buf[0] = 'S';
    const hx = byteToHex(stop_reason);
    buf[1] = hx[0];
    buf[2] = hx[1];
    sendPacket(&buf);
}

/// Handle 'g' — read all registers
fn handleReadRegisters() void {
    var buf: [NUM_GDB_REGISTERS * 16]u8 = undefined;
    var offset: usize = 0;

    for (0..NUM_GDB_REGISTERS) |i| {
        if (saved_state.getRegister(@truncate(i))) |val| {
            offset += u64ToHexLE(val, buf[offset..]);
        } else {
            // Unknown register: send zeros
            for (0..16) |_| {
                if (offset < buf.len) {
                    buf[offset] = '0';
                    offset += 1;
                }
            }
        }
    }

    sendPacket(buf[0..offset]);
}

/// Handle 'G' — write all registers
fn handleWriteRegisters(data: []const u8) void {
    var offset: usize = 0;
    for (0..NUM_GDB_REGISTERS) |i| {
        if (offset + 16 > data.len) break;
        const val = hexLEToU64(data[offset .. offset + 16]);
        _ = saved_state.setRegister(@truncate(i), val);
        offset += 16;
    }
    sendOk();
}

/// Handle 'p' — read single register
fn handleReadRegister(data: []const u8) void {
    const reg_num = hexToU64(data);
    if (reg_num < NUM_GDB_REGISTERS) {
        if (saved_state.getRegister(@truncate(reg_num))) |val| {
            var buf: [16]u8 = undefined;
            const len = u64ToHexLE(val, &buf);
            sendPacket(buf[0..len]);
            return;
        }
    }
    sendError(0x01);
}

/// Handle 'P' — write single register
fn handleWriteRegister(data: []const u8) void {
    // Format: P<regnum>=<hexvalue>
    var eq_pos: usize = 0;
    while (eq_pos < data.len and data[eq_pos] != '=') : (eq_pos += 1) {}
    if (eq_pos >= data.len) {
        sendError(0x01);
        return;
    }

    const reg_num = hexToU64(data[0..eq_pos]);
    const val = hexLEToU64(data[eq_pos + 1 ..]);

    if (reg_num < NUM_GDB_REGISTERS and saved_state.setRegister(@truncate(reg_num), val)) {
        sendOk();
    } else {
        sendError(0x01);
    }
}

/// Handle 'm' — read memory
fn handleReadMemory(data: []const u8) void {
    // Format: m<addr>,<length>
    var comma_pos: usize = 0;
    while (comma_pos < data.len and data[comma_pos] != ',') : (comma_pos += 1) {}
    if (comma_pos >= data.len) {
        sendError(0x01);
        return;
    }

    const addr = hexToU64(data[0..comma_pos]);
    const length = hexToU64(data[comma_pos + 1 ..]);

    if (length == 0 or length > MAX_PACKET_SIZE / 2) {
        sendError(0x01);
        return;
    }

    // Read memory carefully (check for page faults)
    var offset: usize = 0;
    for (0..length) |i| {
        const ptr: *const u8 = @ptrFromInt(addr + i);
        // In a real implementation, this would use a safe memory read
        // that catches page faults via a fixup mechanism
        const byte = ptr.*;
        const hx = byteToHex(byte);
        if (offset + 1 < response_buf.len) {
            response_buf[offset] = hx[0];
            response_buf[offset + 1] = hx[1];
            offset += 2;
        }
    }

    sendPacket(response_buf[0..offset]);
}

/// Handle 'M' — write memory
fn handleWriteMemory(data: []const u8) void {
    // Format: M<addr>,<length>:<hexdata>
    var comma_pos: usize = 0;
    while (comma_pos < data.len and data[comma_pos] != ',') : (comma_pos += 1) {}
    var colon_pos = comma_pos;
    while (colon_pos < data.len and data[colon_pos] != ':') : (colon_pos += 1) {}

    if (comma_pos >= data.len or colon_pos >= data.len) {
        sendError(0x01);
        return;
    }

    const addr = hexToU64(data[0..comma_pos]);
    const length = hexToU64(data[comma_pos + 1 .. colon_pos]);
    const hex_data = data[colon_pos + 1 ..];

    if (length * 2 != hex_data.len) {
        sendError(0x01);
        return;
    }

    var i: usize = 0;
    var hex_idx: usize = 0;
    while (i < length and hex_idx + 1 < hex_data.len) {
        if (hexToByte(hex_data[hex_idx], hex_data[hex_idx + 1])) |byte| {
            const ptr: *u8 = @ptrFromInt(addr + i);
            ptr.* = byte;
        }
        i += 1;
        hex_idx += 2;
    }

    sendOk();
}

/// Handle 'c' — continue execution
fn handleContinue(data: []const u8) void {
    if (data.len > 0) {
        // Optional resume address
        saved_state.rip = hexToU64(data);
    }
    debug_state = .running;
}

/// Handle 's' — single step
fn handleStep(data: []const u8) void {
    if (data.len > 0) {
        saved_state.rip = hexToU64(data);
    }
    // Set trap flag (TF) in RFLAGS
    saved_state.rflags |= (1 << 8);
    debug_state = .stepping;
}

// =============================================================================
// Breakpoint management
// =============================================================================

/// Insert a breakpoint
fn insertBreakpoint(bp_type: u8, addr: u64, size: u8) bool {
    switch (bp_type) {
        0 => {
            // Software breakpoint: replace byte with INT3 (0xCC)
            if (breakpoint_count >= MAX_BREAKPOINTS) return false;
            const ptr: *u8 = @ptrFromInt(addr);
            breakpoints[breakpoint_count] = .{
                .address = addr,
                .bp_type = .software,
                .size = 1,
                .enabled = true,
                .original_byte = ptr.*,
                .hw_register = null,
            };
            ptr.* = 0xCC; // INT3
            breakpoint_count += 1;
            return true;
        },
        1, 2, 3 => {
            // Hardware breakpoint: use DR0-DR3
            const reg = allocateHwBreakpoint() orelse return false;

            const kind: BreakpointType = switch (bp_type) {
                1 => .hardware_exec,
                2 => .hardware_write,
                3 => .hardware_read_write,
                else => unreachable,
            };

            if (breakpoint_count >= MAX_BREAKPOINTS) {
                freeHwBreakpoint(reg);
                return false;
            }

            breakpoints[breakpoint_count] = .{
                .address = addr,
                .bp_type = kind,
                .size = size,
                .enabled = true,
                .original_byte = 0,
                .hw_register = reg,
            };
            breakpoint_count += 1;

            setHwBreakpoint(reg, addr, kind, size);
            return true;
        },
        else => return false,
    }
}

/// Remove a breakpoint
fn removeBreakpoint(bp_type: u8, addr: u64, _size: u8) bool {
    _ = _size;
    for (0..breakpoint_count) |i| {
        if (breakpoints[i].address == addr and @intFromEnum(breakpoints[i].bp_type) == bp_type and breakpoints[i].enabled) {
            if (breakpoints[i].bp_type == .software) {
                // Restore original byte
                const ptr: *u8 = @ptrFromInt(addr);
                ptr.* = breakpoints[i].original_byte;
            } else if (breakpoints[i].hw_register) |reg| {
                clearHwBreakpoint(reg);
                freeHwBreakpoint(reg);
            }
            breakpoints[i].enabled = false;
            return true;
        }
    }
    return false;
}

fn allocateHwBreakpoint() ?u8 {
    for (0..NUM_HW_BREAKPOINTS) |i| {
        if (!hw_bp_used[i]) {
            hw_bp_used[i] = true;
            return @truncate(i);
        }
    }
    return null;
}

fn freeHwBreakpoint(reg: u8) void {
    if (reg < NUM_HW_BREAKPOINTS) {
        hw_bp_used[reg] = false;
    }
}

fn setHwBreakpoint(reg: u8, addr: u64, kind: BreakpointType, size: u8) void {
    // Set debug register DR0-DR3 with the address
    switch (reg) {
        0 => asm volatile ("mov %[addr], %%dr0" : : [addr] "r" (addr)),
        1 => asm volatile ("mov %[addr], %%dr1" : : [addr] "r" (addr)),
        2 => asm volatile ("mov %[addr], %%dr2" : : [addr] "r" (addr)),
        3 => asm volatile ("mov %[addr], %%dr3" : : [addr] "r" (addr)),
        else => return,
    }

    // Configure DR7
    var dr7: u64 = 0;
    asm volatile ("mov %%dr7, %[dr7]" : [dr7] "=r" (-> u64));

    const shift = @as(u6, @intCast(reg)) * 4 + 16;
    const enable_shift = @as(u6, @intCast(reg)) * 2;

    // Clear old config for this register
    dr7 &= ~(@as(u64, 0xF) << shift);
    dr7 &= ~(@as(u64, 0x3) << enable_shift);

    // Set condition (00=exec, 01=write, 11=read/write)
    const condition: u64 = switch (kind) {
        .hardware_exec => 0b00,
        .hardware_write => 0b01,
        .hardware_read_write => 0b11,
        else => 0b00,
    };

    // Set length (00=1byte, 01=2byte, 11=4byte for 32-bit, 10=8byte for 64-bit)
    const len: u64 = switch (size) {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,
        else => 0b00,
    };

    dr7 |= (condition | (len << 2)) << shift;
    dr7 |= @as(u64, 0x1) << enable_shift; // Local enable

    asm volatile ("mov %[dr7], %%dr7" : : [dr7] "r" (dr7));
}

fn clearHwBreakpoint(reg: u8) void {
    var dr7: u64 = 0;
    asm volatile ("mov %%dr7, %[dr7]" : [dr7] "=r" (-> u64));

    const enable_shift = @as(u6, @intCast(reg)) * 2;
    const config_shift = @as(u6, @intCast(reg)) * 4 + 16;
    dr7 &= ~(@as(u64, 0x3) << enable_shift);
    dr7 &= ~(@as(u64, 0xF) << config_shift);

    asm volatile ("mov %[dr7], %%dr7" : : [dr7] "r" (dr7));
}

// =============================================================================
// Stack backtrace
// =============================================================================

pub const StackFrame = struct {
    return_address: u64,
    frame_pointer: u64,
};

/// Walk the stack using frame pointers (RBP chain)
pub fn captureBacktrace(rbp: u64, buf: []StackFrame) usize {
    var fp = rbp;
    var count: usize = 0;

    while (count < buf.len and count < MAX_BACKTRACE_DEPTH) {
        // Validate frame pointer
        if (fp == 0 or fp % 8 != 0) break;

        // Each stack frame: [saved_rbp][return_address]
        const frame_ptr: *const [2]u64 = @ptrFromInt(fp);
        const saved_rbp = frame_ptr[0];
        const ret_addr = frame_ptr[1];

        if (ret_addr == 0) break;

        buf[count] = .{
            .return_address = ret_addr,
            .frame_pointer = fp,
        };
        count += 1;

        // Move to caller's frame
        fp = saved_rbp;
    }

    return count;
}

// =============================================================================
// Debug trap handler (called from IDT exception 1 and 3)
// =============================================================================

pub fn debugTrapHandler(state: *CpuState) void {
    saved_state = state.*;

    if (debug_state == .stepping) {
        // Clear trap flag
        saved_state.rflags &= ~@as(u64, 1 << 8);
        stop_reason = 5; // SIGTRAP
    } else {
        stop_reason = 5; // SIGTRAP
    }

    debug_state = .stopped;

    // Report stop to GDB
    handleQueryHalt();

    // Enter GDB command loop
    gdbCommandLoop();

    // Restore CPU state on resume
    state.* = saved_state;
}

// =============================================================================
// Main GDB command loop
// =============================================================================

fn gdbCommandLoop() void {
    while (debug_state == .stopped) {
        const packet_data = receivePacket() orelse {
            // Ctrl+C interrupt
            handleQueryHalt();
            continue;
        };

        if (packet_data.len == 0) {
            sendEmpty();
            continue;
        }

        const cmd = packet_data[0];
        const args = if (packet_data.len > 1) packet_data[1..] else &[_]u8{};

        switch (cmd) {
            '?' => handleQueryHalt(),
            'g' => handleReadRegisters(),
            'G' => handleWriteRegisters(args),
            'p' => handleReadRegister(args),
            'P' => handleWriteRegister(args),
            'm' => handleReadMemory(args),
            'M' => handleWriteMemory(args),
            'c' => handleContinue(args),
            's' => handleStep(args),
            'Z' => {
                // Insert breakpoint: Z<type>,<addr>,<size>
                if (parseBreakpointArgs(args)) |bpargs| {
                    if (insertBreakpoint(bpargs.bp_type, bpargs.addr, bpargs.size)) {
                        sendOk();
                    } else {
                        sendError(0x0E);
                    }
                } else sendError(0x01);
            },
            'z' => {
                // Remove breakpoint: z<type>,<addr>,<size>
                if (parseBreakpointArgs(args)) |bpargs| {
                    if (removeBreakpoint(bpargs.bp_type, bpargs.addr, bpargs.size)) {
                        sendOk();
                    } else {
                        sendError(0x0E);
                    }
                } else sendError(0x01);
            },
            'D' => {
                // Detach
                sendOk();
                debug_state = .running;
                return;
            },
            'k' => {
                // Kill — we just continue
                debug_state = .running;
                return;
            },
            'q' => handleQueryPacket(args),
            else => sendEmpty(), // Unsupported command
        }
    }
}

const BpArgs = struct {
    bp_type: u8,
    addr: u64,
    size: u8,
};

fn parseBreakpointArgs(args: []const u8) ?BpArgs {
    if (args.len < 3) return null;

    const bp_type = hexCharToNibble(args[0]) orelse return null;
    if (args[1] != ',') return null;

    var comma2: usize = 2;
    while (comma2 < args.len and args[comma2] != ',') : (comma2 += 1) {}
    if (comma2 >= args.len) return null;

    const addr = hexToU64(args[2..comma2]);
    const size: u8 = @truncate(hexToU64(args[comma2 + 1 ..]));

    return BpArgs{ .bp_type = bp_type, .addr = addr, .size = size };
}

fn handleQueryPacket(data: []const u8) void {
    // Handle 'qSupported', 'qAttached', etc.
    if (data.len >= 9 and eql(data[0..9], "Supported")) {
        sendPacket("PacketSize=1000;swbreak+;hwbreak+");
    } else if (data.len >= 8 and eql(data[0..8], "Attached")) {
        sendPacket("1"); // Attached to existing process
    } else if (data.len >= 1 and data[0] == 'C') {
        // Current thread
        sendPacket("QC1");
    } else {
        sendEmpty();
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

// =============================================================================
// Public API
// =============================================================================

var debugger_initialized: bool = false;

/// Initialize the kernel debugger (sets up serial port for GDB)
pub fn initialize() void {
    // Initialize COM1 for 115200 baud
    outb(SERIAL_PORT + 1, 0x00); // Disable interrupts
    outb(SERIAL_PORT + 3, 0x80); // DLAB on
    outb(SERIAL_PORT + 0, 0x01); // 115200 baud (divisor=1)
    outb(SERIAL_PORT + 1, 0x00);
    outb(SERIAL_PORT + 3, 0x03); // 8N1
    outb(SERIAL_PORT + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
    outb(SERIAL_PORT + 4, 0x0B); // IRQs enabled, RTS/DSR set

    // Initialize breakpoint arrays
    for (&breakpoints) |*bp| {
        bp.* = Breakpoint{
            .address = 0,
            .bp_type = .software,
            .size = 0,
            .enabled = false,
            .original_byte = 0,
            .hw_register = null,
        };
    }
    breakpoint_count = 0;
    watchpoint_count = 0;

    debug_state = .running;
    debugger_initialized = true;

    main.klog(.info, "Kernel debugger initialized on COM1 (115200 8N1)", .{});
}

/// Trigger a breakpoint from kernel code (equivalent to asm INT3)
pub fn breakpoint() void {
    if (!debugger_initialized) return;
    asm volatile ("int3");
}

/// Check if debugger is active
pub fn isActive() bool {
    return debugger_initialized and debug_state != .detached;
}

/// Get number of active breakpoints
pub fn activeBreakpoints() usize {
    var count: usize = 0;
    for (0..breakpoint_count) |i| {
        if (breakpoints[i].enabled) count += 1;
    }
    return count;
}
