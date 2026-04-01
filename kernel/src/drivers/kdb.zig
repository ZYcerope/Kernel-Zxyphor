// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Kernel Debugger Infrastructure (Zig)
//
// Interactive kernel debugger (kdb-like):
// - Breakpoint management (software breakpoints using INT3)
// - Watchpoints (hardware debug registers DR0-DR3)
// - Stack backtrace (frame pointer walking)
// - Register dump (all x86_64 GPRs + RFLAGS + RIP + segment regs)
// - Memory inspection (hex dump, arbitrary read)
// - Symbol-based lookup (address → name, name → address)
// - Kernel log ring buffer
// - Panic handler with automatic debugger entry
// - Debug register management (DR0-DR3 for watchpoints, DR7 for control)
// - Single-step support (TF flag in RFLAGS)
// - Expression evaluation stub

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_BREAKPOINTS: usize = 64;
const MAX_WATCHPOINTS: usize = 4; // x86_64 has exactly 4 debug registers
const MAX_SYMBOLS: usize = 1024;
const MAX_LOG_ENTRIES: usize = 256;
const LOG_ENTRY_SIZE: usize = 128;
const BACKTRACE_MAX_DEPTH: usize = 32;
const MAX_NAME_LEN: usize = 64;

// ─────────────────── Register Set ───────────────────────────────────

pub const RegisterSet = struct {
    // General purpose registers
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rbp: u64 = 0,
    rsp: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    // Instruction pointer
    rip: u64 = 0,
    // Flags
    rflags: u64 = 0,
    // Segment registers
    cs: u16 = 0,
    ds: u16 = 0,
    es: u16 = 0,
    fs: u16 = 0,
    gs: u16 = 0,
    ss: u16 = 0,
    // Control registers
    cr0: u64 = 0,
    cr2: u64 = 0, // Page fault linear address
    cr3: u64 = 0, // Page directory base
    cr4: u64 = 0,

    const Self = @This();

    /// Read current registers via inline assembly
    pub fn capture(self: *Self) void {
        self.rflags = asm volatile ("pushfq; pop %[result]"
            : [result] "=r" (-> u64),
            :
            : "memory"
        );
        self.rsp = asm volatile ("mov %%rsp, %[result]"
            : [result] "=r" (-> u64),
        );
        self.rbp = asm volatile ("mov %%rbp, %[result]"
            : [result] "=r" (-> u64),
        );
    }
};

// ─────────────────── Breakpoint ─────────────────────────────────────

pub const BpType = enum(u8) {
    software = 0, // INT3 (0xCC)
    hardware = 1, // Debug register
};

pub const BpState = enum(u8) {
    disabled = 0,
    enabled = 1,
    hit = 2,
    temporary = 3, // One-shot breakpoint
};

pub const Breakpoint = struct {
    address: u64,
    bp_type: BpType,
    state: BpState,
    /// Original byte at address (replaced with 0xCC for software BP)
    original_byte: u8,
    /// Hit counter
    hit_count: u64,
    /// Condition: skip if hit_count < ignore_count
    ignore_count: u64,
    /// Name/note
    name: [MAX_NAME_LEN]u8,
    name_len: u8,
    active: bool,

    pub fn init() Breakpoint {
        return .{
            .address = 0,
            .bp_type = .software,
            .state = .disabled,
            .original_byte = 0,
            .hit_count = 0,
            .ignore_count = 0,
            .name = [_]u8{0} ** MAX_NAME_LEN,
            .name_len = 0,
            .active = false,
        };
    }

    pub fn should_break(self: *const Breakpoint) bool {
        return self.hit_count > self.ignore_count;
    }
};

// ─────────────────── Watchpoint ─────────────────────────────────────

pub const WatchType = enum(u2) {
    execute = 0b00,
    write = 0b01,
    io = 0b10,
    read_write = 0b11,
};

pub const WatchSize = enum(u2) {
    byte = 0b00,
    word = 0b01,
    dword = 0b11,
    qword = 0b10,
};

pub const Watchpoint = struct {
    address: u64,
    watch_type: WatchType,
    watch_size: WatchSize,
    dr_index: u2, // Which DR register (0-3)
    hit_count: u64,
    active: bool,
    name: [MAX_NAME_LEN]u8,
    name_len: u8,

    pub fn init() Watchpoint {
        return .{
            .address = 0,
            .watch_type = .write,
            .watch_size = .dword,
            .dr_index = 0,
            .hit_count = 0,
            .active = false,
            .name = [_]u8{0} ** MAX_NAME_LEN,
            .name_len = 0,
        };
    }
};

// ─────────────────── Debug Register Management ──────────────────────

fn read_dr(n: u2) u64 {
    return switch (n) {
        0 => asm volatile ("mov %%dr0, %[result]" : [result] "=r" (-> u64)),
        1 => asm volatile ("mov %%dr1, %[result]" : [result] "=r" (-> u64)),
        2 => asm volatile ("mov %%dr2, %[result]" : [result] "=r" (-> u64)),
        3 => asm volatile ("mov %%dr3, %[result]" : [result] "=r" (-> u64)),
    };
}

fn write_dr(n: u2, val: u64) void {
    switch (n) {
        0 => asm volatile ("mov %[val], %%dr0" : : [val] "r" (val)),
        1 => asm volatile ("mov %[val], %%dr1" : : [val] "r" (val)),
        2 => asm volatile ("mov %[val], %%dr2" : : [val] "r" (val)),
        3 => asm volatile ("mov %[val], %%dr3" : : [val] "r" (val)),
    }
}

fn read_dr6() u64 {
    return asm volatile ("mov %%dr6, %[result]" : [result] "=r" (-> u64));
}

fn write_dr6(val: u64) void {
    asm volatile ("mov %[val], %%dr6" : : [val] "r" (val));
}

fn read_dr7() u64 {
    return asm volatile ("mov %%dr7, %[result]" : [result] "=r" (-> u64));
}

fn write_dr7(val: u64) void {
    asm volatile ("mov %[val], %%dr7" : : [val] "r" (val));
}

// ─────────────────── Symbol Table ───────────────────────────────────

pub const Symbol = struct {
    name: [MAX_NAME_LEN]u8,
    name_len: u8,
    address: u64,
    size: u32,
    sym_type: u8, // 'T'=text, 'D'=data, 'B'=bss, 'R'=rodata
    active: bool,

    pub fn init() Symbol {
        return .{
            .name = [_]u8{0} ** MAX_NAME_LEN,
            .name_len = 0,
            .address = 0,
            .size = 0,
            .sym_type = 0,
            .active = false,
        };
    }

    pub fn contains_address(self: *const Symbol, addr: u64) bool {
        return addr >= self.address and addr < self.address + @as(u64, self.size);
    }
};

// ─────────────────── Backtrace Frame ────────────────────────────────

pub const BacktraceFrame = struct {
    return_address: u64,
    frame_pointer: u64,
    symbol_idx: i16, // -1 if no symbol found
};

// ─────────────────── Log Entry ──────────────────────────────────────

pub const LogLevel = enum(u8) {
    emerg = 0,
    alert = 1,
    crit = 2,
    err = 3,
    warning = 4,
    notice = 5,
    info = 6,
    debug = 7,
};

pub const LogEntry = struct {
    msg: [LOG_ENTRY_SIZE]u8,
    msg_len: u8,
    level: LogLevel,
    timestamp: u64,
};

// ─────────────────── Debugger State ─────────────────────────────────

pub const DebuggerState = enum(u8) {
    inactive = 0,
    active = 1,
    single_step = 2,
    awaiting_input = 3,
};

// ─────────────────── Kernel Debugger ────────────────────────────────

pub const KernelDebugger = struct {
    state: DebuggerState,
    regs: RegisterSet,

    breakpoints: [MAX_BREAKPOINTS]Breakpoint,
    bp_count: u16,

    watchpoints: [MAX_WATCHPOINTS]Watchpoint,
    wp_count: u8,
    dr7_shadow: u64, // Shadow copy of DR7

    symbols: [MAX_SYMBOLS]Symbol,
    symbol_count: u16,

    // Kernel log ring buffer
    log: [MAX_LOG_ENTRIES]LogEntry,
    log_head: u16,
    log_count: u16,

    // Backtrace
    backtrace: [BACKTRACE_MAX_DEPTH]BacktraceFrame,
    backtrace_depth: u8,

    // Stats
    total_breaks: u64,
    total_watchpoint_hits: u64,
    total_single_steps: u64,
    panic_count: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var dbg: Self = undefined;
        dbg.state = .inactive;
        dbg.regs = .{};
        for (0..MAX_BREAKPOINTS) |i| {
            dbg.breakpoints[i] = Breakpoint.init();
        }
        dbg.bp_count = 0;
        for (0..MAX_WATCHPOINTS) |i| {
            dbg.watchpoints[i] = Watchpoint.init();
        }
        dbg.wp_count = 0;
        dbg.dr7_shadow = 0;
        for (0..MAX_SYMBOLS) |i| {
            dbg.symbols[i] = Symbol.init();
        }
        dbg.symbol_count = 0;
        dbg.log_head = 0;
        dbg.log_count = 0;
        dbg.backtrace_depth = 0;
        dbg.total_breaks = 0;
        dbg.total_watchpoint_hits = 0;
        dbg.total_single_steps = 0;
        dbg.panic_count = 0;
        dbg.initialized = true;
        return dbg;
    }

    // ─── Breakpoints ────────────────────────────────────────────────

    /// Set a software breakpoint at address
    pub fn set_breakpoint(self: *Self, addr: u64) ?u16 {
        for (0..MAX_BREAKPOINTS) |i| {
            if (!self.breakpoints[i].active) {
                self.breakpoints[i].address = addr;
                self.breakpoints[i].bp_type = .software;
                self.breakpoints[i].state = .enabled;
                self.breakpoints[i].original_byte = 0;
                self.breakpoints[i].hit_count = 0;
                self.breakpoints[i].ignore_count = 0;
                self.breakpoints[i].active = true;
                self.bp_count += 1;

                // Write INT3 (0xCC) to target address
                self.install_bp(addr, i);

                return @intCast(i);
            }
        }
        return null;
    }

    fn install_bp(self: *Self, addr: u64, idx: usize) void {
        const ptr: *volatile u8 = @ptrFromInt(addr);
        self.breakpoints[idx].original_byte = ptr.*;
        ptr.* = 0xCC; // INT3
    }

    fn remove_bp(self: *Self, idx: usize) void {
        const addr = self.breakpoints[idx].address;
        const ptr: *volatile u8 = @ptrFromInt(addr);
        ptr.* = self.breakpoints[idx].original_byte;
    }

    pub fn clear_breakpoint(self: *Self, idx: u16) bool {
        if (idx >= MAX_BREAKPOINTS or !self.breakpoints[idx].active) return false;

        if (self.breakpoints[idx].bp_type == .software and self.breakpoints[idx].state == .enabled) {
            self.remove_bp(idx);
        }
        self.breakpoints[idx].active = false;
        self.bp_count -= 1;
        return true;
    }

    pub fn enable_breakpoint(self: *Self, idx: u16) bool {
        if (idx >= MAX_BREAKPOINTS or !self.breakpoints[idx].active) return false;
        if (self.breakpoints[idx].state == .enabled) return true;
        self.breakpoints[idx].state = .enabled;
        self.install_bp(self.breakpoints[idx].address, idx);
        return true;
    }

    pub fn disable_breakpoint(self: *Self, idx: u16) bool {
        if (idx >= MAX_BREAKPOINTS or !self.breakpoints[idx].active) return false;
        if (self.breakpoints[idx].state != .enabled) return true;
        self.remove_bp(idx);
        self.breakpoints[idx].state = .disabled;
        return true;
    }

    /// Handle INT3 trap (called from IDT handler)
    pub fn handle_breakpoint(self: *Self, rip: u64) void {
        self.total_breaks += 1;
        self.regs.rip = rip;
        self.regs.capture();

        // Find matching breakpoint (RIP points after INT3, so rip-1)
        const bp_addr = rip - 1;
        for (0..MAX_BREAKPOINTS) |i| {
            if (self.breakpoints[i].active and self.breakpoints[i].address == bp_addr) {
                self.breakpoints[i].hit_count += 1;
                if (self.breakpoints[i].should_break()) {
                    self.state = .active;
                }
                if (self.breakpoints[i].state == .temporary) {
                    self.clear_breakpoint(@intCast(i));
                }
                break;
            }
        }
    }

    // ─── Watchpoints ────────────────────────────────────────────────

    pub fn set_watchpoint(self: *Self, addr: u64, watch_type: WatchType, watch_size: WatchSize) ?u8 {
        if (self.wp_count >= MAX_WATCHPOINTS) return null;

        for (0..MAX_WATCHPOINTS) |i| {
            if (!self.watchpoints[i].active) {
                self.watchpoints[i].address = addr;
                self.watchpoints[i].watch_type = watch_type;
                self.watchpoints[i].watch_size = watch_size;
                self.watchpoints[i].dr_index = @intCast(i);
                self.watchpoints[i].active = true;
                self.watchpoints[i].hit_count = 0;
                self.wp_count += 1;

                // Configure hardware debug register
                write_dr(@intCast(i), addr);
                self.update_dr7();

                return @intCast(i);
            }
        }
        return null;
    }

    pub fn clear_watchpoint(self: *Self, idx: u8) bool {
        if (idx >= MAX_WATCHPOINTS or !self.watchpoints[idx].active) return false;
        self.watchpoints[idx].active = false;
        self.wp_count -= 1;
        write_dr(@intCast(idx), 0);
        self.update_dr7();
        return true;
    }

    fn update_dr7(self: *Self) void {
        var dr7: u64 = 0;
        for (0..MAX_WATCHPOINTS) |i| {
            if (self.watchpoints[i].active) {
                const n: u6 = @intCast(i);
                // Local enable
                dr7 |= @as(u64, 1) << (n * 2);
                // Condition: type and length in bits 16-31
                const cond: u64 = @intFromEnum(self.watchpoints[i].watch_type);
                const len: u64 = @intFromEnum(self.watchpoints[i].watch_size);
                dr7 |= cond << (16 + n * 4);
                dr7 |= len << (18 + n * 4);
            }
        }
        self.dr7_shadow = dr7;
        write_dr7(dr7);
    }

    /// Handle debug exception (#DB, vector 1)
    pub fn handle_debug_exception(self: *Self) void {
        const dr6 = read_dr6();

        // Check which watchpoint fired
        for (0..MAX_WATCHPOINTS) |i| {
            if ((dr6 & (@as(u64, 1) << @intCast(i))) != 0 and self.watchpoints[i].active) {
                self.watchpoints[i].hit_count += 1;
                self.total_watchpoint_hits += 1;
                self.state = .active;
            }
        }

        // Check single-step (bit 14 of DR6)
        if ((dr6 & (1 << 14)) != 0) {
            self.total_single_steps += 1;
            self.state = .active;
        }

        // Clear DR6
        write_dr6(0);
    }

    // ─── Single Step ────────────────────────────────────────────────

    pub fn enable_single_step(self: *Self) void {
        // Set TF (Trap Flag) in RFLAGS — bit 8
        self.regs.rflags |= (1 << 8);
        self.state = .single_step;
    }

    pub fn disable_single_step(self: *Self) void {
        self.regs.rflags &= ~@as(u64, 1 << 8);
        if (self.state == .single_step) {
            self.state = .inactive;
        }
    }

    // ─── Symbol Table ───────────────────────────────────────────────

    pub fn add_symbol(self: *Self, name: []const u8, addr: u64, size: u32, sym_type: u8) bool {
        if (self.symbol_count >= MAX_SYMBOLS) return false;

        const idx = self.symbol_count;
        var sym = &self.symbols[idx];
        sym.* = Symbol.init();
        const len = @min(name.len, MAX_NAME_LEN - 1);
        @memcpy(sym.name[0..len], name[0..len]);
        sym.name_len = @intCast(len);
        sym.address = addr;
        sym.size = size;
        sym.sym_type = sym_type;
        sym.active = true;
        self.symbol_count += 1;
        return true;
    }

    /// Lookup symbol by address
    pub fn lookup_addr(self: *const Self, addr: u64) ?*const Symbol {
        var best: ?*const Symbol = null;
        var best_offset: u64 = 0xFFFFFFFFFFFFFFFF;

        for (0..self.symbol_count) |i| {
            if (!self.symbols[i].active) continue;
            if (self.symbols[i].contains_address(addr)) {
                return &self.symbols[i];
            }
            // Closest symbol before address
            if (addr >= self.symbols[i].address) {
                const offset = addr - self.symbols[i].address;
                if (offset < best_offset) {
                    best_offset = offset;
                    best = &self.symbols[i];
                }
            }
        }
        return best;
    }

    /// Lookup symbol by name
    pub fn lookup_name(self: *const Self, name: []const u8) ?*const Symbol {
        for (0..self.symbol_count) |i| {
            if (!self.symbols[i].active) continue;
            const slen = self.symbols[i].name_len;
            if (slen == name.len and std.mem.eql(u8, self.symbols[i].name[0..slen], name)) {
                return &self.symbols[i];
            }
        }
        return null;
    }

    // ─── Stack Backtrace ────────────────────────────────────────────

    /// Walk frame pointers to generate backtrace
    pub fn backtrace_from(self: *Self, rbp: u64, rip: u64) void {
        self.backtrace_depth = 0;

        // First frame: current RIP
        if (self.backtrace_depth < BACKTRACE_MAX_DEPTH) {
            self.backtrace[0] = .{
                .return_address = rip,
                .frame_pointer = rbp,
                .symbol_idx = self.find_symbol_idx(rip),
            };
            self.backtrace_depth = 1;
        }

        // Walk frame pointer chain
        var fp = rbp;
        var depth: u8 = 1;
        while (depth < BACKTRACE_MAX_DEPTH and fp != 0 and fp > 0x1000) : (depth += 1) {
            // Validate frame pointer is in kernel space
            if (fp < 0xFFFF800000000000) break;

            const frame_ptr: *const [2]u64 = @ptrFromInt(fp);
            const saved_rbp = frame_ptr[0];
            const return_addr = frame_ptr[1];

            if (return_addr == 0) break;

            self.backtrace[depth] = .{
                .return_address = return_addr,
                .frame_pointer = saved_rbp,
                .symbol_idx = self.find_symbol_idx(return_addr),
            };
            self.backtrace_depth = depth + 1;

            fp = saved_rbp;
            // Detect loops
            if (saved_rbp <= fp and saved_rbp != 0) break;
        }
    }

    fn find_symbol_idx(self: *const Self, addr: u64) i16 {
        for (0..self.symbol_count) |i| {
            if (self.symbols[i].active and self.symbols[i].contains_address(addr)) {
                return @intCast(i);
            }
        }
        return -1;
    }

    // ─── Hex Dump ───────────────────────────────────────────────────

    /// Read memory at address (returns 0 on invalid access)
    pub fn read_memory_u8(self: *const Self, addr: u64) u8 {
        _ = self;
        if (addr < 0x1000) return 0; // NULL page guard
        const ptr: *const volatile u8 = @ptrFromInt(addr);
        return ptr.*;
    }

    pub fn read_memory_u64(self: *const Self, addr: u64) u64 {
        _ = self;
        if (addr < 0x1000 or (addr & 0x7) != 0) return 0;
        const ptr: *const volatile u64 = @ptrFromInt(addr);
        return ptr.*;
    }

    // ─── Kernel Log ─────────────────────────────────────────────────

    pub fn log(self: *Self, level: LogLevel, msg: []const u8, timestamp: u64) void {
        const idx = self.log_head;
        const len = @min(msg.len, LOG_ENTRY_SIZE - 1);
        @memcpy(self.log[idx].msg[0..len], msg[0..len]);
        self.log[idx].msg_len = @intCast(len);
        self.log[idx].level = level;
        self.log[idx].timestamp = timestamp;

        self.log_head = (self.log_head + 1) % MAX_LOG_ENTRIES;
        if (self.log_count < MAX_LOG_ENTRIES) {
            self.log_count += 1;
        }
    }

    // ─── Panic ──────────────────────────────────────────────────────

    pub fn panic_entry(self: *Self, rip: u64, rbp: u64, reason: []const u8) void {
        self.panic_count += 1;
        self.state = .active;
        self.regs.rip = rip;
        self.regs.rbp = rbp;
        self.regs.capture();
        self.backtrace_from(rbp, rip);
        self.log(.emerg, reason, 0);
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var g_debugger: KernelDebugger = undefined;
var g_debugger_initialized: bool = false;

fn dbg() *KernelDebugger {
    return &g_debugger;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_kdb_init() void {
    g_debugger = KernelDebugger.init();
    g_debugger_initialized = true;
}

export fn zxy_kdb_set_breakpoint(addr: u64) i16 {
    if (!g_debugger_initialized) return -1;
    if (dbg().set_breakpoint(addr)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_kdb_clear_breakpoint(idx: u16) bool {
    if (!g_debugger_initialized) return false;
    return dbg().clear_breakpoint(idx);
}

export fn zxy_kdb_set_watchpoint(addr: u64, wp_type: u8, wp_size: u8) i8 {
    if (!g_debugger_initialized) return -1;
    if (wp_type > 3 or wp_size > 3) return -1;
    if (dbg().set_watchpoint(addr, @enumFromInt(@as(u2, @intCast(wp_type))), @enumFromInt(@as(u2, @intCast(wp_size))))) |idx| {
        return @intCast(idx);
    }
    return -1;
}

export fn zxy_kdb_clear_watchpoint(idx: u8) bool {
    if (!g_debugger_initialized) return false;
    return dbg().clear_watchpoint(idx);
}

export fn zxy_kdb_handle_breakpoint(rip: u64) void {
    if (g_debugger_initialized) dbg().handle_breakpoint(rip);
}

export fn zxy_kdb_handle_debug() void {
    if (g_debugger_initialized) dbg().handle_debug_exception();
}

export fn zxy_kdb_add_symbol(name_ptr: [*]const u8, name_len: usize, addr: u64, size: u32, sym_type: u8) bool {
    if (!g_debugger_initialized) return false;
    return dbg().add_symbol(name_ptr[0..name_len], addr, size, sym_type);
}

export fn zxy_kdb_bp_count() u16 {
    if (!g_debugger_initialized) return 0;
    return dbg().bp_count;
}

export fn zxy_kdb_wp_count() u8 {
    if (!g_debugger_initialized) return 0;
    return dbg().wp_count;
}

export fn zxy_kdb_symbol_count() u16 {
    if (!g_debugger_initialized) return 0;
    return dbg().symbol_count;
}

export fn zxy_kdb_total_breaks() u64 {
    if (!g_debugger_initialized) return 0;
    return dbg().total_breaks;
}

export fn zxy_kdb_total_watchpoint_hits() u64 {
    if (!g_debugger_initialized) return 0;
    return dbg().total_watchpoint_hits;
}

export fn zxy_kdb_panic_count() u64 {
    if (!g_debugger_initialized) return 0;
    return dbg().panic_count;
}

export fn zxy_kdb_log_count() u16 {
    if (!g_debugger_initialized) return 0;
    return dbg().log_count;
}

export fn zxy_kdb_backtrace_depth() u8 {
    if (!g_debugger_initialized) return 0;
    return dbg().backtrace_depth;
}
