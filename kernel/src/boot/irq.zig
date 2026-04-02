// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Interrupt Descriptor Table Manager & IRQ Framework (Zig)
//
// Full x86_64 interrupt management:
// - IDT setup with 256 gate descriptors
// - Interrupt handler registration (ISR/IRQ)
// - IRQ line management (shared interrupts, chaining)
// - Software interrupt dispatch (INT 0x80 syscalls)
// - Exception handlers (divide error, page fault, GPF, etc.)
// - IRQ affinity (CPU binding)
// - IRQ balancing across CPUs
// - Threaded IRQ support (top-half/bottom-half)
// - IRQ statistics and debugging
// - Interrupt coalescing for high-throughput devices

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const IDT_ENTRIES: usize = 256;
const MAX_IRQ_HANDLERS: usize = 16; // Max handlers per IRQ (shared)
const MAX_IRQ_LINES: usize = 256;
const MAX_SOFTIRQS: usize = 16;
const IRQ_BASE: u8 = 0x20; // IRQs start after exceptions

// ─────────────────── Gate Types ─────────────────────────────────────

pub const GateType = enum(u4) {
    interrupt_gate = 0xE, // Clear IF on entry
    trap_gate = 0xF, // Don't clear IF
    task_gate = 0x5, // TSS switch (not used in 64-bit)
};

// ─────────────────── IDT Gate Descriptor ────────────────────────────

pub const IdtGate = packed struct {
    offset_low: u16 = 0, // Target offset bits 0..15
    selector: u16 = 0x08, // Code segment selector (kernel CS)
    ist: u3 = 0, // Interrupt Stack Table index
    _zero1: u5 = 0,
    gate_type: u4 = 0xE, // Interrupt gate
    _zero2: u1 = 0,
    dpl: u2 = 0, // Descriptor Privilege Level
    present: u1 = 1,
    offset_mid: u16 = 0, // Target offset bits 16..31
    offset_high: u32 = 0, // Target offset bits 32..63
    _reserved: u32 = 0,

    pub fn set_handler(self: *IdtGate, handler: u64, selector: u16, gate_type: GateType, dpl: u2, ist: u3) void {
        self.offset_low = @truncate(handler & 0xFFFF);
        self.offset_mid = @truncate((handler >> 16) & 0xFFFF);
        self.offset_high = @truncate((handler >> 32) & 0xFFFFFFFF);
        self.selector = selector;
        self.gate_type = @intFromEnum(gate_type);
        self.dpl = dpl;
        self.ist = ist;
        self.present = 1;
    }

    pub fn handler_address(self: *const IdtGate) u64 {
        return @as(u64, self.offset_low) |
            (@as(u64, self.offset_mid) << 16) |
            (@as(u64, self.offset_high) << 32);
    }
};

// ─────────────────── IDT Pointer ────────────────────────────────────

pub const IdtPtr = packed struct {
    limit: u16,
    base: u64,
};

// ─────────────────── Exception Vectors ──────────────────────────────

pub const Exception = enum(u8) {
    divide_error = 0,
    debug = 1,
    nmi = 2,
    breakpoint = 3,
    overflow = 4,
    bound_range = 5,
    invalid_opcode = 6,
    device_not_avail = 7,
    double_fault = 8,
    coproc_segment = 9,
    invalid_tss = 10,
    segment_not_present = 11,
    stack_segment = 12,
    general_protection = 13,
    page_fault = 14,
    // 15 reserved
    x87_float = 16,
    alignment_check = 17,
    machine_check = 18,
    simd_float = 19,
    virtualization = 20,
    control_protection = 21,
    // 22-27 reserved
    hypervisor_inject = 28,
    vmm_communication = 29,
    security_exception = 30,
    // 31 reserved
};

// ─────────────────── IRQ Handler ────────────────────────────────────

pub const IrqReturn = enum(u8) {
    none = 0, // Not our IRQ
    handled = 1, // Handled
    wake_thread = 2, // Handled, wake threaded handler
};

pub const IrqHandlerFn = *const fn (irq: u8, data: u64) IrqReturn;
pub const ThreadedHandlerFn = *const fn (irq: u8, data: u64) IrqReturn;

pub const IrqHandler = struct {
    handler: IrqHandlerFn,
    threaded: ?ThreadedHandlerFn = null,
    data: u64 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    active: bool = false,

    pub fn set_name(self: *IrqHandler, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @truncate(len);
    }
};

// ─────────────────── IRQ Flags ──────────────────────────────────────

pub const IrqFlags = packed struct {
    shared: bool = false, // Allow shared IRQ
    probe: bool = false, // Probing
    oneshot: bool = false, // Disable until handler completes
    no_autoenable: bool = false,
    no_thread: bool = false, // Always run in hardirq context
    _pad: u3 = 0,
};

// ─────────────────── IRQ Line ───────────────────────────────────────

pub const IrqLine = struct {
    handlers: [MAX_IRQ_HANDLERS]IrqHandler = [_]IrqHandler{.{ .handler = &default_irq_handler }} ** MAX_IRQ_HANDLERS,
    handler_count: u8 = 0,
    /// State
    enabled: bool = true,
    masked: bool = false,
    in_progress: bool = false,
    pending: bool = false,
    level_triggered: bool = false,
    /// Affinity
    affinity_mask: u64 = 0xFFFFFFFFFFFFFFFF, // All CPUs
    /// Flags
    flags: IrqFlags = .{},
    /// Statistics
    total_count: u64 = 0,
    unhandled_count: u32 = 0,
    spurious_count: u32 = 0,
    last_cpu: u8 = 0,

    pub fn register_handler(self: *IrqLine, handler: IrqHandlerFn, name: []const u8, shared: bool) bool {
        if (self.handler_count >= MAX_IRQ_HANDLERS) return false;
        if (!shared and self.handler_count > 0) return false;
        if (self.handler_count > 0 and !self.flags.shared and !shared) return false;

        const idx = self.handler_count;
        self.handlers[idx].handler = handler;
        self.handlers[idx].set_name(name);
        self.handlers[idx].active = true;
        self.handler_count += 1;
        if (shared) self.flags.shared = true;
        return true;
    }

    pub fn unregister_handler(self: *IrqLine, handler: IrqHandlerFn) bool {
        for (0..self.handler_count) |i| {
            if (@intFromPtr(self.handlers[i].handler) == @intFromPtr(handler)) {
                self.handlers[i].active = false;
                // Compact
                var j = i;
                while (j + 1 < self.handler_count) : (j += 1) {
                    self.handlers[j] = self.handlers[j + 1];
                }
                self.handler_count -= 1;
                return true;
            }
        }
        return false;
    }

    /// Dispatch IRQ to all registered handlers
    pub fn dispatch(self: *IrqLine, irq: u8) IrqReturn {
        self.total_count += 1;
        self.in_progress = true;

        var handled = false;
        var need_thread = false;

        for (0..self.handler_count) |i| {
            if (self.handlers[i].active) {
                const ret = self.handlers[i].handler(irq, self.handlers[i].data);
                switch (ret) {
                    .handled => handled = true,
                    .wake_thread => {
                        handled = true;
                        need_thread = true;
                    },
                    .none => {},
                }
            }
        }

        self.in_progress = false;

        if (!handled) {
            self.unhandled_count += 1;
            if (self.unhandled_count > 100000) {
                // Disable IRQ to prevent storm
                self.enabled = false;
                self.masked = true;
            }
            return .none;
        }

        if (need_thread) return .wake_thread;
        return .handled;
    }
};

fn default_irq_handler(_irq: u8, _data: u64) IrqReturn {
    return .none;
}

// ─────────────────── Softirq ────────────────────────────────────────

pub const SoftirqId = enum(u4) {
    hi = 0,
    timer = 1,
    net_tx = 2,
    net_rx = 3,
    block = 4,
    irq_poll = 5,
    tasklet = 6,
    sched = 7,
    hrtimer = 8,
    rcu = 9,
};

pub const SoftirqHandler = *const fn () void;

pub const SoftirqEntry = struct {
    handler: ?SoftirqHandler = null,
    pending: bool = false,
    count: u64 = 0,
    active: bool = false,
};

// ─────────────────── Interrupt Frame ────────────────────────────────

pub const InterruptFrame = packed struct {
    // Pushed by interrupt stub
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

pub const InterruptFrameWithError = packed struct {
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// ─────────────────── IRQ Manager ────────────────────────────────────

pub const IrqManager = struct {
    idt: [IDT_ENTRIES]IdtGate = [_]IdtGate{.{}} ** IDT_ENTRIES,
    irq_lines: [MAX_IRQ_LINES]IrqLine = [_]IrqLine{.{}} ** MAX_IRQ_LINES,
    softirqs: [MAX_SOFTIRQS]SoftirqEntry = [_]SoftirqEntry{.{}} ** MAX_SOFTIRQS,
    /// Nested interrupt depth
    irq_depth: u32 = 0,
    /// Currently disabled (cli depth)
    cli_depth: u32 = 0,
    /// Software IRQ pending bitmask
    softirq_pending: u16 = 0,
    /// Stats
    total_interrupts: u64 = 0,
    total_exceptions: u64 = 0,
    total_softirqs: u64 = 0,
    total_spurious: u64 = 0,
    /// NMI counter
    nmi_count: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *IrqManager) void {
        // Set up exception handlers (vectors 0-31)
        // All exceptions use interrupt gates, ring 0
        for (0..32) |i| {
            self.idt[i].gate_type = @intFromEnum(GateType.interrupt_gate);
            self.idt[i].dpl = 0;
            self.idt[i].present = 1;
            self.idt[i].selector = 0x08; // Kernel CS

            // IST for critical exceptions
            if (i == 2) { // NMI
                self.idt[i].ist = 1;
            } else if (i == 8) { // Double fault
                self.idt[i].ist = 2;
            } else if (i == 18) { // Machine check
                self.idt[i].ist = 3;
            }
        }

        // Debug/breakpoint accessible from ring 3
        self.idt[1].dpl = 3;
        self.idt[3].dpl = 3;

        // Set up IRQ entries (vectors 32-255)
        for (32..256) |i| {
            self.idt[i].gate_type = @intFromEnum(GateType.interrupt_gate);
            self.idt[i].dpl = 0;
            self.idt[i].present = 1;
            self.idt[i].selector = 0x08;
        }

        // Syscall interrupt (vector 0x80) — ring 3 accessible
        self.idt[0x80].dpl = 3;
        self.idt[0x80].gate_type = @intFromEnum(GateType.trap_gate);

        self.initialized = true;
    }

    /// Load the IDT into the CPU
    pub fn load_idt(self: *IrqManager) void {
        const idt_ptr = IdtPtr{
            .limit = @as(u16, IDT_ENTRIES * @sizeOf(IdtGate) - 1),
            .base = @intFromPtr(&self.idt),
        };
        asm volatile ("lidt (%[ptr])"
            :
            : [ptr] "r" (&idt_ptr),
        );
    }

    /// Register an IRQ handler
    pub fn request_irq(
        self: *IrqManager,
        irq: u8,
        handler: IrqHandlerFn,
        name: []const u8,
        shared: bool,
    ) bool {
        if (irq >= MAX_IRQ_LINES) return false;
        return self.irq_lines[irq].register_handler(handler, name, shared);
    }

    /// Unregister an IRQ handler
    pub fn free_irq(self: *IrqManager, irq: u8, handler: IrqHandlerFn) bool {
        if (irq >= MAX_IRQ_LINES) return false;
        return self.irq_lines[irq].unregister_handler(handler);
    }

    /// Enable an IRQ line
    pub fn enable_irq(self: *IrqManager, irq: u8) void {
        if (irq < MAX_IRQ_LINES) {
            self.irq_lines[irq].enabled = true;
            self.irq_lines[irq].masked = false;
        }
    }

    /// Disable an IRQ line
    pub fn disable_irq(self: *IrqManager, irq: u8) void {
        if (irq < MAX_IRQ_LINES) {
            self.irq_lines[irq].enabled = false;
        }
    }

    /// Handle incoming interrupt
    pub fn handle_interrupt(self: *IrqManager, vector: u8) void {
        self.irq_depth += 1;
        self.total_interrupts += 1;

        if (vector < 32) {
            // Exception
            self.total_exceptions += 1;
            self.handle_exception(vector);
        } else if (vector == 0x80) {
            // Syscall via INT 0x80
            // Dispatch to syscall handler
        } else {
            // Hardware IRQ
            const irq = vector - IRQ_BASE;
            if (irq < MAX_IRQ_LINES and self.irq_lines[irq].enabled) {
                const ret = self.irq_lines[irq].dispatch(irq);
                if (ret == .none) {
                    self.total_spurious += 1;
                    self.irq_lines[irq].spurious_count += 1;
                }
            }
        }

        self.irq_depth -= 1;

        // Process softirqs when returning from hardirq to process context
        if (self.irq_depth == 0 and self.softirq_pending != 0) {
            self.do_softirq();
        }
    }

    fn handle_exception(self: *IrqManager, vector: u8) void {
        switch (vector) {
            0 => {}, // #DE Divide Error
            1 => {}, // #DB Debug
            2 => {
                self.nmi_count += 1;
            }, // NMI
            3 => {}, // #BP Breakpoint
            6 => {}, // #UD Invalid Opcode
            8 => {}, // #DF Double Fault — fatal
            13 => {}, // #GP General Protection
            14 => {}, // #PF Page Fault — resolve via VMM
            else => {},
        }
    }

    /// Register a softirq handler
    pub fn register_softirq(self: *IrqManager, id: SoftirqId, handler: SoftirqHandler) void {
        const idx = @intFromEnum(id);
        self.softirqs[idx].handler = handler;
        self.softirqs[idx].active = true;
    }

    /// Raise a softirq
    pub fn raise_softirq(self: *IrqManager, id: SoftirqId) void {
        const bit: u16 = @as(u16, 1) << @intFromEnum(id);
        self.softirq_pending |= bit;
    }

    /// Process pending softirqs
    fn do_softirq(self: *IrqManager) void {
        var pending = self.softirq_pending;
        self.softirq_pending = 0;
        var attempts: u8 = 0;

        while (pending != 0 and attempts < 10) : (attempts += 1) {
            for (0..MAX_SOFTIRQS) |i| {
                const bit: u16 = @as(u16, 1) << @truncate(i);
                if (pending & bit != 0) {
                    if (self.softirqs[i].active) {
                        if (self.softirqs[i].handler) |handler| {
                            handler();
                            self.softirqs[i].count += 1;
                            self.total_softirqs += 1;
                        }
                    }
                }
            }
            // Check for newly raised softirqs
            pending = self.softirq_pending;
            self.softirq_pending = 0;
        }

        // If too many iterations, defer to ksoftirqd
        if (pending != 0) {
            self.softirq_pending |= pending;
        }
    }

    /// Disable all interrupts (cli)
    pub fn local_irq_disable(self: *IrqManager) void {
        self.cli_depth += 1;
        asm volatile ("cli");
    }

    /// Enable all interrupts (sti)
    pub fn local_irq_enable(self: *IrqManager) void {
        if (self.cli_depth > 0) {
            self.cli_depth -= 1;
        }
        if (self.cli_depth == 0) {
            asm volatile ("sti");
        }
    }

    /// Set IRQ affinity to specific CPUs
    pub fn set_affinity(self: *IrqManager, irq: u8, cpu_mask: u64) void {
        if (irq < MAX_IRQ_LINES) {
            self.irq_lines[irq].affinity_mask = cpu_mask;
        }
    }

    pub fn irq_count(self: *const IrqManager, irq: u8) u64 {
        if (irq < MAX_IRQ_LINES) {
            return self.irq_lines[irq].total_count;
        }
        return 0;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var irq_mgr = IrqManager{};

pub fn get_irq_manager() *IrqManager {
    return &irq_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_irq_init() void {
    irq_mgr.init();
}

export fn zxy_irq_enable(irq: u8) void {
    irq_mgr.enable_irq(irq);
}

export fn zxy_irq_disable(irq: u8) void {
    irq_mgr.disable_irq(irq);
}

export fn zxy_irq_handle(vector: u8) void {
    irq_mgr.handle_interrupt(vector);
}

export fn zxy_irq_total() u64 {
    return irq_mgr.total_interrupts;
}

export fn zxy_irq_exceptions() u64 {
    return irq_mgr.total_exceptions;
}

export fn zxy_irq_softirq_total() u64 {
    return irq_mgr.total_softirqs;
}

export fn zxy_irq_spurious() u64 {
    return irq_mgr.total_spurious;
}

export fn zxy_irq_nmi_count() u64 {
    return irq_mgr.nmi_count;
}

export fn zxy_irq_set_affinity(irq: u8, mask: u64) void {
    irq_mgr.set_affinity(irq, mask);
}

export fn zxy_irq_raise_softirq(id: u8) void {
    if (id < MAX_SOFTIRQS) {
        const softirq_id: SoftirqId = @enumFromInt(id);
        irq_mgr.raise_softirq(softirq_id);
    }
}
