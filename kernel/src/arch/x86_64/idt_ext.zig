// SPDX-License-Identifier: MIT
// Zxyphor Kernel - x86_64 Advanced Interrupt Descriptor Table (IDT) Extension
// Full exception handling, nested interrupt support, interrupt routing, performance counters

const std = @import("std");

/// IDT Gate Types
pub const GateType = enum(u4) {
    interrupt_gate = 0xE,
    trap_gate = 0xF,
    task_gate = 0x5,
    call_gate = 0xC,
};

/// IDT Entry (Gate Descriptor) for 64-bit mode
pub const IdtEntry = packed struct {
    offset_low: u16,
    selector: u16,
    ist: u3,
    reserved0: u5 = 0,
    gate_type: u4,
    zero: u1 = 0,
    dpl: u2,
    present: u1,
    offset_mid: u16,
    offset_high: u32,
    reserved1: u32 = 0,

    pub fn init(handler: u64, selector: u16, ist: u3, gate_type: GateType, dpl: u2) IdtEntry {
        return IdtEntry{
            .offset_low = @truncate(handler),
            .selector = selector,
            .ist = ist,
            .gate_type = @intFromEnum(gate_type),
            .dpl = dpl,
            .present = 1,
            .offset_mid = @truncate(handler >> 16),
            .offset_high = @truncate(handler >> 32),
        };
    }

    pub fn absent() IdtEntry {
        return IdtEntry{
            .offset_low = 0,
            .selector = 0,
            .ist = 0,
            .gate_type = 0,
            .dpl = 0,
            .present = 0,
            .offset_mid = 0,
            .offset_high = 0,
        };
    }
};

/// IDT Pointer for LIDT instruction
pub const IdtPointer = packed struct {
    limit: u16,
    base: u64,
};

/// Exception vector numbers
pub const ExceptionVector = struct {
    pub const DIVIDE_ERROR: u8 = 0;
    pub const DEBUG: u8 = 1;
    pub const NMI: u8 = 2;
    pub const BREAKPOINT: u8 = 3;
    pub const OVERFLOW: u8 = 4;
    pub const BOUND_RANGE: u8 = 5;
    pub const INVALID_OPCODE: u8 = 6;
    pub const DEVICE_NOT_AVAILABLE: u8 = 7;
    pub const DOUBLE_FAULT: u8 = 8;
    pub const COPROCESSOR_SEGMENT: u8 = 9;
    pub const INVALID_TSS: u8 = 10;
    pub const SEGMENT_NOT_PRESENT: u8 = 11;
    pub const STACK_FAULT: u8 = 12;
    pub const GENERAL_PROTECTION: u8 = 13;
    pub const PAGE_FAULT: u8 = 14;
    pub const X87_FPU: u8 = 16;
    pub const ALIGNMENT_CHECK: u8 = 17;
    pub const MACHINE_CHECK: u8 = 18;
    pub const SIMD_FP: u8 = 19;
    pub const VIRTUALIZATION: u8 = 20;
    pub const CONTROL_PROTECTION: u8 = 21;
    pub const HYPERVISOR_INJECTION: u8 = 28;
    pub const VMM_COMMUNICATION: u8 = 29;
    pub const SECURITY_EXCEPTION: u8 = 30;
};

/// IRQ base offset (remapped PIC/APIC)
pub const IRQ_BASE: u8 = 32;
pub const IRQ_COUNT: u8 = 224;
pub const IDT_ENTRIES: usize = 256;

/// Full interrupt frame pushed by CPU 
pub const InterruptFrame = packed struct {
    // Pushed by our stub
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    // Interrupt number and error code
    vector: u64,
    error_code: u64,
    // Pushed by CPU
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,

    pub fn isUserMode(self: *const InterruptFrame) bool {
        return (self.cs & 3) == 3;
    }

    pub fn isKernelMode(self: *const InterruptFrame) bool {
        return (self.cs & 3) == 0;
    }

    pub fn getPageFaultAddress() u64 {
        return asm volatile ("mov %%cr2, %[result]"
            : [result] "=r" (-> u64),
        );
    }
};

/// Interrupt handler function types
pub const InterruptHandler = *const fn (*InterruptFrame) void;
pub const IrqHandler = *const fn (u8, *InterruptFrame) bool;

/// IRQ routing entry
pub const IrqRoute = struct {
    handler: ?IrqHandler,
    data: ?*anyopaque,
    name: [32]u8,
    count: u64,
    enabled: bool,
    shared: bool,
    level_triggered: bool,
    active_low: bool,

    pub fn init() IrqRoute {
        return IrqRoute{
            .handler = null,
            .data = null,
            .name = [_]u8{0} ** 32,
            .count = 0,
            .enabled = false,
            .shared = false,
            .level_triggered = false,
            .active_low = false,
        };
    }
};

/// IDT state
var idt_entries: [IDT_ENTRIES]IdtEntry = undefined;
var irq_routes: [IRQ_COUNT]IrqRoute = undefined;
var exception_handlers: [32]?InterruptHandler = [_]?InterruptHandler{null} ** 32;
var idt_loaded: bool = false;
var total_interrupts: u64 = 0;
var spurious_count: u64 = 0;
var nested_depth: u32 = 0;
const max_nested_depth: u32 = 16;

/// Performance counters for interrupt tracking
pub const InterruptStats = struct {
    total_count: u64 = 0,
    exception_count: u64 = 0,
    irq_count: u64 = 0,
    software_int_count: u64 = 0,
    nmi_count: u64 = 0,
    page_fault_count: u64 = 0,
    gp_fault_count: u64 = 0,
    double_fault_count: u64 = 0,
    per_vector_count: [256]u64 = [_]u64{0} ** 256,
    max_latency_ns: u64 = 0,
    avg_latency_ns: u64 = 0,

    pub fn recordInterrupt(self: *InterruptStats, vector: u8) void {
        self.total_count += 1;
        self.per_vector_count[vector] += 1;

        if (vector < 32) {
            self.exception_count += 1;
            switch (vector) {
                ExceptionVector.PAGE_FAULT => self.page_fault_count += 1,
                ExceptionVector.GENERAL_PROTECTION => self.gp_fault_count += 1,
                ExceptionVector.DOUBLE_FAULT => self.double_fault_count += 1,
                ExceptionVector.NMI => self.nmi_count += 1,
                else => {},
            }
        } else {
            self.irq_count += 1;
        }
    }
};

var interrupt_stats: InterruptStats = .{};

/// Initialize IDT with all exception and interrupt handlers
pub fn init() void {
    // Initialize all entries as absent
    for (0..IDT_ENTRIES) |i| {
        idt_entries[i] = IdtEntry.absent();
    }

    // Initialize IRQ routes
    for (0..IRQ_COUNT) |i| {
        irq_routes[i] = IrqRoute.init();
    }

    // Set up exception handlers (vectors 0-31)
    setupExceptionHandlers();

    // Set up IRQ handlers (vectors 32-255)
    setupIrqHandlers();

    // Load IDT
    load();
}

fn setupExceptionHandlers() void {
    const kernel_cs: u16 = 0x08;

    // Division Error - no error code
    idt_entries[0] = IdtEntry.init(@intFromPtr(&exception_stub_0), kernel_cs, 0, .interrupt_gate, 0);
    // Debug
    idt_entries[1] = IdtEntry.init(@intFromPtr(&exception_stub_1), kernel_cs, 0, .trap_gate, 0);
    // NMI - uses IST1
    idt_entries[2] = IdtEntry.init(@intFromPtr(&exception_stub_2), kernel_cs, 1, .interrupt_gate, 0);
    // Breakpoint - accessible from userspace
    idt_entries[3] = IdtEntry.init(@intFromPtr(&exception_stub_3), kernel_cs, 0, .trap_gate, 3);
    // Overflow
    idt_entries[4] = IdtEntry.init(@intFromPtr(&exception_stub_4), kernel_cs, 0, .trap_gate, 3);
    // Bound Range
    idt_entries[5] = IdtEntry.init(@intFromPtr(&exception_stub_5), kernel_cs, 0, .interrupt_gate, 0);
    // Invalid Opcode
    idt_entries[6] = IdtEntry.init(@intFromPtr(&exception_stub_6), kernel_cs, 0, .interrupt_gate, 0);
    // Device Not Available
    idt_entries[7] = IdtEntry.init(@intFromPtr(&exception_stub_7), kernel_cs, 0, .interrupt_gate, 0);
    // Double Fault - uses IST2
    idt_entries[8] = IdtEntry.init(@intFromPtr(&exception_stub_8), kernel_cs, 2, .interrupt_gate, 0);
    // Invalid TSS
    idt_entries[10] = IdtEntry.init(@intFromPtr(&exception_stub_10), kernel_cs, 0, .interrupt_gate, 0);
    // Segment Not Present
    idt_entries[11] = IdtEntry.init(@intFromPtr(&exception_stub_11), kernel_cs, 0, .interrupt_gate, 0);
    // Stack Fault
    idt_entries[12] = IdtEntry.init(@intFromPtr(&exception_stub_12), kernel_cs, 0, .interrupt_gate, 0);
    // General Protection Fault
    idt_entries[13] = IdtEntry.init(@intFromPtr(&exception_stub_13), kernel_cs, 0, .interrupt_gate, 0);
    // Page Fault - uses IST3
    idt_entries[14] = IdtEntry.init(@intFromPtr(&exception_stub_14), kernel_cs, 3, .interrupt_gate, 0);
    // x87 FPU
    idt_entries[16] = IdtEntry.init(@intFromPtr(&exception_stub_16), kernel_cs, 0, .interrupt_gate, 0);
    // Alignment Check
    idt_entries[17] = IdtEntry.init(@intFromPtr(&exception_stub_17), kernel_cs, 0, .interrupt_gate, 0);
    // Machine Check - uses IST4
    idt_entries[18] = IdtEntry.init(@intFromPtr(&exception_stub_18), kernel_cs, 4, .interrupt_gate, 0);
    // SIMD FP
    idt_entries[19] = IdtEntry.init(@intFromPtr(&exception_stub_19), kernel_cs, 0, .interrupt_gate, 0);
    // Virtualization
    idt_entries[20] = IdtEntry.init(@intFromPtr(&exception_stub_20), kernel_cs, 0, .interrupt_gate, 0);
    // Control Protection
    idt_entries[21] = IdtEntry.init(@intFromPtr(&exception_stub_21), kernel_cs, 0, .interrupt_gate, 0);
}

fn setupIrqHandlers() void {
    const kernel_cs: u16 = 0x08;
    // Set up IRQ stubs for vectors 32-255
    inline for (32..256) |i| {
        idt_entries[i] = IdtEntry.init(@intFromPtr(&makeIrqStub(i)), kernel_cs, 0, .interrupt_gate, 0);
    }
}

fn makeIrqStub(comptime vector: u8) *const fn () callconv(.Naked) void {
    return struct {
        fn handler() callconv(.Naked) void {
            // Push dummy error code and vector number
            asm volatile (
                \\push $0
                \\push %[vector]
                \\jmp interruptCommonStub
                :
                : [vector] "i" (vector),
            );
        }
    }.handler;
}

// Exception stubs (no error code)
fn exception_stub_0() callconv(.Naked) void {
    asm volatile ("push $0\npush $0\njmp interruptCommonStub");
}
fn exception_stub_1() callconv(.Naked) void {
    asm volatile ("push $0\npush $1\njmp interruptCommonStub");
}
fn exception_stub_2() callconv(.Naked) void {
    asm volatile ("push $0\npush $2\njmp interruptCommonStub");
}
fn exception_stub_3() callconv(.Naked) void {
    asm volatile ("push $0\npush $3\njmp interruptCommonStub");
}
fn exception_stub_4() callconv(.Naked) void {
    asm volatile ("push $0\npush $4\njmp interruptCommonStub");
}
fn exception_stub_5() callconv(.Naked) void {
    asm volatile ("push $0\npush $5\njmp interruptCommonStub");
}
fn exception_stub_6() callconv(.Naked) void {
    asm volatile ("push $0\npush $6\njmp interruptCommonStub");
}
fn exception_stub_7() callconv(.Naked) void {
    asm volatile ("push $0\npush $7\njmp interruptCommonStub");
}
// Exception stubs (with error code)
fn exception_stub_8() callconv(.Naked) void {
    asm volatile ("push $8\njmp interruptCommonStub");
}
fn exception_stub_10() callconv(.Naked) void {
    asm volatile ("push $10\njmp interruptCommonStub");
}
fn exception_stub_11() callconv(.Naked) void {
    asm volatile ("push $11\njmp interruptCommonStub");
}
fn exception_stub_12() callconv(.Naked) void {
    asm volatile ("push $12\njmp interruptCommonStub");
}
fn exception_stub_13() callconv(.Naked) void {
    asm volatile ("push $13\njmp interruptCommonStub");
}
fn exception_stub_14() callconv(.Naked) void {
    asm volatile ("push $14\njmp interruptCommonStub");
}
fn exception_stub_16() callconv(.Naked) void {
    asm volatile ("push $0\npush $16\njmp interruptCommonStub");
}
fn exception_stub_17() callconv(.Naked) void {
    asm volatile ("push $17\njmp interruptCommonStub");
}
fn exception_stub_18() callconv(.Naked) void {
    asm volatile ("push $0\npush $18\njmp interruptCommonStub");
}
fn exception_stub_19() callconv(.Naked) void {
    asm volatile ("push $0\npush $19\njmp interruptCommonStub");
}
fn exception_stub_20() callconv(.Naked) void {
    asm volatile ("push $0\npush $20\njmp interruptCommonStub");
}
fn exception_stub_21() callconv(.Naked) void {
    asm volatile ("push $21\njmp interruptCommonStub");
}

/// Common interrupt handler called from all stubs
export fn interruptCommonStub() callconv(.Naked) void {
    // Save all general purpose registers
    asm volatile (
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov %%rsp, %%rdi
        \\call interruptDispatch
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rbp
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\add $16, %%rsp
        \\iretq
    );
}

/// Main interrupt dispatcher
export fn interruptDispatch(frame: *InterruptFrame) void {
    const vector: u8 = @truncate(frame.vector);
    interrupt_stats.recordInterrupt(vector);
    nested_depth += 1;

    if (vector < 32) {
        // Exception handler
        handleException(vector, frame);
    } else {
        // IRQ handler
        handleIrq(vector - IRQ_BASE, frame);
    }

    nested_depth -= 1;
}

fn handleException(vector: u8, frame: *InterruptFrame) void {
    if (exception_handlers[vector]) |handler| {
        handler(frame);
    } else {
        // Default exception handling
        defaultExceptionHandler(vector, frame);
    }
}

fn defaultExceptionHandler(vector: u8, frame: *InterruptFrame) void {
    switch (vector) {
        ExceptionVector.PAGE_FAULT => {
            const fault_addr = InterruptFrame.getPageFaultAddress();
            _ = fault_addr;
            // Page fault handling: check if it's a valid fault
            if (frame.isUserMode()) {
                // Send SIGSEGV to user process
                // For now, just return
            } else {
                // Kernel page fault - this is serious
                kernelPanic("Kernel page fault", frame);
            }
        },
        ExceptionVector.GENERAL_PROTECTION => {
            if (frame.isUserMode()) {
                // Send SIGSEGV to user process
            } else {
                kernelPanic("Kernel GPF", frame);
            }
        },
        ExceptionVector.DOUBLE_FAULT => {
            kernelPanic("Double fault", frame);
        },
        ExceptionVector.MACHINE_CHECK => {
            kernelPanic("Machine check exception", frame);
        },
        ExceptionVector.NMI => {
            handleNmi(frame);
        },
        else => {
            if (frame.isUserMode()) {
                // Kill the user process
            } else {
                kernelPanic("Unhandled kernel exception", frame);
            }
        },
    }
}

fn handleNmi(frame: *InterruptFrame) void {
    _ = frame;
    // Read NMI status from port 0x61
    const status = inb(0x61);
    if (status & 0x80 != 0) {
        // Memory parity error
    }
    if (status & 0x40 != 0) {
        // I/O channel check
    }
}

fn handleIrq(irq: u8, frame: *InterruptFrame) void {
    if (irq >= IRQ_COUNT) {
        spurious_count += 1;
        return;
    }

    var route = &irq_routes[irq];
    if (route.enabled) {
        if (route.handler) |handler| {
            route.count += 1;
            _ = handler(irq, frame);
        }
    }

    // Send EOI to APIC
    sendEoi();
}

fn sendEoi() void {
    // Write to APIC EOI register (at offset 0xB0 from APIC base)
    const apic_base: u64 = 0xFEE00000;
    const eoi_reg = @as(*volatile u32, @ptrFromInt(apic_base + 0xB0));
    eoi_reg.* = 0;
}

fn kernelPanic(message: []const u8, frame: *InterruptFrame) void {
    _ = message;
    _ = frame;
    // Disable interrupts and halt
    asm volatile ("cli");
    while (true) {
        asm volatile ("hlt");
    }
}

/// Load IDT
fn load() void {
    const idt_ptr = IdtPointer{
        .limit = @sizeOf(@TypeOf(idt_entries)) - 1,
        .base = @intFromPtr(&idt_entries),
    };

    asm volatile ("lidt (%[idt_ptr])"
        :
        : [idt_ptr] "r" (&idt_ptr),
    );
    idt_loaded = true;
}

/// Register a custom exception handler
pub fn registerExceptionHandler(vector: u8, handler: InterruptHandler) !void {
    if (vector >= 32) return error.NotAnException;
    exception_handlers[vector] = handler;
}

/// Register an IRQ handler
pub fn registerIrqHandler(irq: u8, handler: IrqHandler, name: []const u8) !void {
    if (irq >= IRQ_COUNT) return error.IrqOutOfRange;
    var route = &irq_routes[irq];
    route.handler = handler;
    route.enabled = true;
    const len = @min(name.len, route.name.len);
    @memcpy(route.name[0..len], name[0..len]);
}

/// Unregister an IRQ handler
pub fn unregisterIrqHandler(irq: u8) void {
    if (irq >= IRQ_COUNT) return;
    irq_routes[irq] = IrqRoute.init();
}

/// Enable/disable specific IRQ
pub fn enableIrq(irq: u8) void {
    if (irq >= IRQ_COUNT) return;
    irq_routes[irq].enabled = true;
}

pub fn disableIrq(irq: u8) void {
    if (irq >= IRQ_COUNT) return;
    irq_routes[irq].enabled = false;
}

/// Get interrupt statistics
pub fn getStats() InterruptStats {
    return interrupt_stats;
}

/// Get IRQ count for specific IRQ
pub fn getIrqCount(irq: u8) u64 {
    if (irq >= IRQ_COUNT) return 0;
    return irq_routes[irq].count;
}

/// Check if IDT is loaded
pub fn isLoaded() bool {
    return idt_loaded;
}

/// Get nested interrupt depth
pub fn getNestedDepth() u32 {
    return nested_depth;
}

/// Port I/O helpers
fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}
