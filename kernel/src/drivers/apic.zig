// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Advanced Programmable Interrupt Controller (Zig)
//
// x86_64 APIC subsystem:
// - Local APIC register definitions and access
// - I/O APIC routing table management
// - APIC timer (periodic and one-shot)
// - Spurious interrupt handling
// - NMI configuration
// - MSI/MSI-X support
// - x2APIC mode
// - Legacy 8259 PIC emulation/disable
// - EOI (End of Interrupt) management
// - Interrupt affinity (CPU steering)
// - APIC error handling
// - Inter-Processor Interrupts (IPI delivery)

const std = @import("std");

// ─────────────────── Local APIC Registers ───────────────────────────

const LAPIC_BASE_DEFAULT: u64 = 0xFEE00000;

const LAPIC_ID: u32 = 0x020;
const LAPIC_VERSION: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080; // Task Priority
const LAPIC_APR: u32 = 0x090; // Arbitration Priority
const LAPIC_PPR: u32 = 0x0A0; // Processor Priority
const LAPIC_EOI: u32 = 0x0B0;
const LAPIC_RRD: u32 = 0x0C0; // Remote Read
const LAPIC_LDR: u32 = 0x0D0; // Logical Destination
const LAPIC_DFR: u32 = 0x0E0; // Destination Format
const LAPIC_SVR: u32 = 0x0F0; // Spurious Vector
const LAPIC_ISR_BASE: u32 = 0x100; // In-Service (ISR0-ISR7)
const LAPIC_TMR_BASE: u32 = 0x180; // Trigger Mode
const LAPIC_IRR_BASE: u32 = 0x200; // Interrupt Request
const LAPIC_ESR: u32 = 0x280; // Error Status
const LAPIC_ICR_LOW: u32 = 0x300; // Interrupt Command (low)
const LAPIC_ICR_HIGH: u32 = 0x310; // Interrupt Command (high)
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_THERMAL: u32 = 0x330;
const LAPIC_LVT_PERF: u32 = 0x340;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_LVT_LINT1: u32 = 0x360;
const LAPIC_LVT_ERROR: u32 = 0x370;
const LAPIC_TIMER_ICR: u32 = 0x380; // Timer Initial Count
const LAPIC_TIMER_CCR: u32 = 0x390; // Timer Current Count
const LAPIC_TIMER_DCR: u32 = 0x3E0; // Timer Divide Config

// SVR bits
const SVR_ENABLE: u32 = 1 << 8;
const SVR_FOCUS_DISABLE: u32 = 1 << 9;
const SVR_EOI_SUPPRESS: u32 = 1 << 12;

// LVT bits
const LVT_MASKED: u32 = 1 << 16;
const LVT_TRIGGER_LEVEL: u32 = 1 << 15;
const LVT_PENDING: u32 = 1 << 12;

// LVT Timer modes
const LVT_TIMER_ONESHOT: u32 = 0x00 << 17;
const LVT_TIMER_PERIODIC: u32 = 0x01 << 17;
const LVT_TIMER_TSC_DEADLINE: u32 = 0x02 << 17;

// Delivery modes
const DELIVERY_FIXED: u32 = 0x000;
const DELIVERY_LOWEST: u32 = 0x100;
const DELIVERY_SMI: u32 = 0x200;
const DELIVERY_NMI: u32 = 0x400;
const DELIVERY_INIT: u32 = 0x500;
const DELIVERY_SIPI: u32 = 0x600;
const DELIVERY_EXTINT: u32 = 0x700;

// ICR bits
const ICR_DEST_SHIFT: u5 = 24;
const ICR_ASSERT: u32 = 1 << 14;
const ICR_LEVEL: u32 = 1 << 15;
const ICR_DEST_ALL: u32 = 0x80000;
const ICR_DEST_ALL_EX: u32 = 0xC0000;
const ICR_DEST_SELF: u32 = 0x40000;

// Timer divide values
const TIMER_DIV_1: u32 = 0x0B;
const TIMER_DIV_2: u32 = 0x00;
const TIMER_DIV_4: u32 = 0x01;
const TIMER_DIV_8: u32 = 0x02;
const TIMER_DIV_16: u32 = 0x03;
const TIMER_DIV_32: u32 = 0x08;
const TIMER_DIV_64: u32 = 0x09;
const TIMER_DIV_128: u32 = 0x0A;

// ─────────────────── Constants ──────────────────────────────────────

const SPURIOUS_VECTOR: u8 = 0xFF;
const TIMER_VECTOR: u8 = 0x20;
const ERROR_VECTOR: u8 = 0xFE;
const THERMAL_VECTOR: u8 = 0xFD;
const PERF_VECTOR: u8 = 0xFC;
const MAX_IOAPICS: usize = 8;
const MAX_IRQ_ENTRIES: usize = 256;
const MAX_MSI_ENTRIES: usize = 128;
const MAX_IRQ_OVERRIDES: usize = 16;

// ─────────────────── 8259 PIC ───────────────────────────────────────

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

pub const Pic8259 = struct {
    master_mask: u8 = 0xFF,
    slave_mask: u8 = 0xFF,
    remapped: bool = false,

    /// Remap PIC to vectors 0x20-0x2F then disable
    pub fn remap_and_disable(self: *Pic8259) void {
        // ICW1
        self.outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        self.outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        // ICW2: vector offsets
        self.outb(PIC1_DATA, 0x20);
        self.outb(PIC2_DATA, 0x28);
        // ICW3: cascading
        self.outb(PIC1_DATA, 4); // IRQ2 has slave
        self.outb(PIC2_DATA, 2); // slave identity
        // ICW4
        self.outb(PIC1_DATA, ICW4_8086);
        self.outb(PIC2_DATA, ICW4_8086);
        // Mask all IRQs (APIC will handle them)
        self.outb(PIC1_DATA, 0xFF);
        self.outb(PIC2_DATA, 0xFF);
        self.remapped = true;
    }

    fn outb(self: *const Pic8259, port: u16, val: u8) void {
        _ = self;
        _ = port;
        _ = val;
        // asm volatile ("outb %[val], %[port]" : : [val]"a"(val), [port]"Nd"(port));
    }
};

// ─────────────────── I/O APIC ───────────────────────────────────────

const IOAPIC_REGSEL: u32 = 0x00;
const IOAPIC_WIN: u32 = 0x10;

const IOAPIC_ID: u8 = 0x00;
const IOAPIC_VER: u8 = 0x01;
const IOAPIC_ARB: u8 = 0x02;
const IOAPIC_REDTBL_BASE: u8 = 0x10;

pub const RedirectEntry = packed struct {
    vector: u8 = 0,
    delivery_mode: u3 = 0,
    dest_mode: bool = false,     // 0=physical, 1=logical
    delivery_pending: bool = false,
    polarity: bool = false,      // 0=active high, 1=active low
    remote_irr: bool = false,
    trigger: bool = false,       // 0=edge, 1=level
    masked: bool = true,
    _reserved: u39 = 0,
    destination: u8 = 0,

    pub fn to_u64(self: RedirectEntry) u64 {
        return @bitCast(self);
    }

    pub fn from_u64(val: u64) RedirectEntry {
        return @bitCast(val);
    }
};

pub const IoApic = struct {
    id: u8 = 0,
    base_addr: u64 = 0,
    gsi_base: u32 = 0,  // Global System Interrupt base
    max_redir: u8 = 0,
    version: u8 = 0,
    entries: [24]RedirectEntry = [_]RedirectEntry{.{}} ** 24,
    active: bool = false,

    fn read_reg(self: *const IoApic, reg: u8) u32 {
        // Write reg index to REGSEL, read from WIN
        _ = self;
        _ = reg;
        return 0;
    }

    fn write_reg(self: *const IoApic, reg: u8, val: u32) void {
        _ = self;
        _ = reg;
        _ = val;
    }

    pub fn init(self: *IoApic, base: u64, gsi: u32, apic_id: u8) void {
        self.base_addr = base;
        self.gsi_base = gsi;
        self.id = apic_id;

        // Read version register
        const ver = self.read_reg(IOAPIC_VER);
        self.version = @truncate(ver);
        self.max_redir = @truncate(ver >> 16);

        // Mask all entries initially
        var i: u8 = 0;
        while (i <= self.max_redir and i < 24) : (i += 1) {
            self.entries[i] = .{};
            self.entries[i].masked = true;
            self.write_redirect(i, self.entries[i]);
        }
        self.active = true;
    }

    pub fn set_entry(self: *IoApic, irq: u8, entry: RedirectEntry) void {
        if (irq > self.max_redir) return;
        self.entries[irq] = entry;
        self.write_redirect(irq, entry);
    }

    pub fn mask(self: *IoApic, irq: u8) void {
        if (irq > self.max_redir) return;
        self.entries[irq].masked = true;
        self.write_redirect(irq, self.entries[irq]);
    }

    pub fn unmask(self: *IoApic, irq: u8) void {
        if (irq > self.max_redir) return;
        self.entries[irq].masked = false;
        self.write_redirect(irq, self.entries[irq]);
    }

    fn write_redirect(self: *const IoApic, irq: u8, entry: RedirectEntry) void {
        const val = entry.to_u64();
        self.write_reg(IOAPIC_REDTBL_BASE + irq * 2, @truncate(val));
        self.write_reg(IOAPIC_REDTBL_BASE + irq * 2 + 1, @truncate(val >> 32));
    }
};

// ─────────────────── MSI / MSI-X ────────────────────────────────────

pub const MsiEntry = struct {
    address: u64 = 0,
    data: u32 = 0,
    vector: u8 = 0,
    dest_cpu: u8 = 0,
    trigger_level: bool = false,
    masked: bool = false,
    is_msix: bool = false,
    device_bdf: u16 = 0,
    active: bool = false,

    pub fn configure(self: *MsiEntry, vector: u8, dest_apic_id: u8) void {
        self.vector = vector;
        self.dest_cpu = dest_apic_id;
        // MSI address format (x86_64):
        // [31:20] = 0xFEE
        // [19:12] = destination APIC ID
        // [11:4]  = reserved
        // [3]     = redirection hint
        // [2]     = destination mode
        self.address = 0xFEE00000 | (@as(u64, dest_apic_id) << 12);
        // MSI data format:
        // [15]    = trigger mode (0=edge)
        // [14]    = level (N/A for edge)
        // [10:8]  = delivery mode
        // [7:0]   = vector
        self.data = @as(u32, vector);
        if (self.trigger_level) {
            self.data |= (1 << 15) | (1 << 14);
        }
        self.active = true;
    }
};

// ─────────────────── IRQ Override ────────────────────────────────────

pub const IrqOverride = struct {
    source_irq: u8 = 0,     // ISA IRQ
    gsi: u32 = 0,           // Remapped GSI
    polarity: u2 = 0,       // 0=default, 1=active high, 3=active low
    trigger: u2 = 0,        // 0=default, 1=edge, 3=level
    active: bool = false,
};

// ─────────────────── Local APIC ─────────────────────────────────────

pub const LocalApic = struct {
    base_addr: u64 = LAPIC_BASE_DEFAULT,
    id: u32 = 0,
    version: u32 = 0,
    max_lvt: u8 = 0,
    x2apic: bool = false,
    /// Timer calibration
    timer_freq_hz: u32 = 0,
    timer_ticks_per_ms: u32 = 0,
    timer_mode: enum(u8) { oneshot, periodic, tsc_deadline } = .periodic,
    timer_vector: u8 = TIMER_VECTOR,
    /// Error tracking
    esr_errors: u32 = 0,
    spurious_count: u32 = 0,
    enabled: bool = false,

    fn read_reg(self: *const LocalApic, offset: u32) u32 {
        if (self.x2apic) {
            // x2APIC: use MSR access
            // const msr = 0x800 + (offset >> 4);
            // return rdmsr(msr);
            return 0;
        }
        // Memory-mapped access
        // const ptr: *volatile u32 = @ptrFromInt(self.base_addr + offset);
        // return ptr.*;
        _ = offset;
        return 0;
    }

    fn write_reg(self: *const LocalApic, offset: u32, val: u32) void {
        if (self.x2apic) {
            // x2APIC MSR write
            return;
        }
        _ = offset;
        _ = val;
        // const ptr: *volatile u32 = @ptrFromInt(self.base_addr + offset);
        // ptr.* = val;
    }

    pub fn init(self: *LocalApic) void {
        self.id = self.read_reg(LAPIC_ID) >> 24;
        self.version = self.read_reg(LAPIC_VERSION);
        self.max_lvt = @truncate(self.version >> 16);

        // Enable APIC via SVR
        self.write_reg(LAPIC_SVR, SVR_ENABLE | @as(u32, SPURIOUS_VECTOR));

        // Set task priority to 0 (accept all)
        self.write_reg(LAPIC_TPR, 0);

        // Configure LVT entries
        self.write_reg(LAPIC_LVT_LINT0, DELIVERY_EXTINT); // External interrupts
        self.write_reg(LAPIC_LVT_LINT1, DELIVERY_NMI); // NMI
        self.write_reg(LAPIC_LVT_ERROR, @as(u32, ERROR_VECTOR)); // Error
        self.write_reg(LAPIC_LVT_THERMAL, @as(u32, THERMAL_VECTOR) | LVT_MASKED);
        self.write_reg(LAPIC_LVT_PERF, @as(u32, PERF_VECTOR) | LVT_MASKED);

        // Clear error status
        self.write_reg(LAPIC_ESR, 0);
        _ = self.read_reg(LAPIC_ESR);

        self.enabled = true;
    }

    pub fn eoi(self: *const LocalApic) void {
        self.write_reg(LAPIC_EOI, 0);
    }

    /// Configure APIC timer
    pub fn setup_timer(self: *LocalApic, hz: u32) void {
        self.write_reg(LAPIC_TIMER_DCR, TIMER_DIV_16);

        // Calibrate: use a known time source (PIT channel 2)
        // For now, use a default calibration value
        self.timer_ticks_per_ms = 100000; // placeholder

        const count = if (hz > 0) self.timer_ticks_per_ms * 1000 / hz else 0;

        switch (self.timer_mode) {
            .periodic => {
                self.write_reg(LAPIC_LVT_TIMER, @as(u32, self.timer_vector) | LVT_TIMER_PERIODIC);
                self.write_reg(LAPIC_TIMER_ICR, count);
            },
            .oneshot => {
                self.write_reg(LAPIC_LVT_TIMER, @as(u32, self.timer_vector) | LVT_TIMER_ONESHOT);
                self.write_reg(LAPIC_TIMER_ICR, count);
            },
            .tsc_deadline => {
                self.write_reg(LAPIC_LVT_TIMER, @as(u32, self.timer_vector) | LVT_TIMER_TSC_DEADLINE);
            },
        }
        self.timer_freq_hz = hz;
    }

    pub fn stop_timer(self: *LocalApic) void {
        self.write_reg(LAPIC_LVT_TIMER, LVT_MASKED);
        self.write_reg(LAPIC_TIMER_ICR, 0);
    }

    /// Send IPI
    pub fn send_ipi(self: *const LocalApic, dest: u8, vector: u8) void {
        self.write_reg(LAPIC_ICR_HIGH, @as(u32, dest) << ICR_DEST_SHIFT);
        self.write_reg(LAPIC_ICR_LOW, @as(u32, vector) | ICR_ASSERT);
    }

    pub fn send_init(self: *const LocalApic, dest: u8) void {
        self.write_reg(LAPIC_ICR_HIGH, @as(u32, dest) << ICR_DEST_SHIFT);
        self.write_reg(LAPIC_ICR_LOW, DELIVERY_INIT | ICR_ASSERT | ICR_LEVEL);
    }

    pub fn send_sipi(self: *const LocalApic, dest: u8, trampoline_page: u8) void {
        self.write_reg(LAPIC_ICR_HIGH, @as(u32, dest) << ICR_DEST_SHIFT);
        self.write_reg(LAPIC_ICR_LOW, DELIVERY_SIPI | @as(u32, trampoline_page));
    }

    pub fn send_ipi_all_excl(self: *const LocalApic, vector: u8) void {
        self.write_reg(LAPIC_ICR_LOW, @as(u32, vector) | ICR_DEST_ALL_EX | ICR_ASSERT);
    }

    pub fn handle_error(self: *LocalApic) void {
        self.write_reg(LAPIC_ESR, 0);
        const esr = self.read_reg(LAPIC_ESR);
        _ = esr;
        self.esr_errors += 1;
    }

    pub fn handle_spurious(self: *LocalApic) void {
        self.spurious_count += 1;
        // No EOI for spurious
    }

    pub fn current_count(self: *const LocalApic) u32 {
        return self.read_reg(LAPIC_TIMER_CCR);
    }
};

// ─────────────────── APIC Manager ───────────────────────────────────

pub const ApicManager = struct {
    local: LocalApic = .{},
    ioapics: [MAX_IOAPICS]IoApic = [_]IoApic{.{}} ** MAX_IOAPICS,
    ioapic_count: u8 = 0,
    pic: Pic8259 = .{},
    /// MSI entries
    msi_entries: [MAX_MSI_ENTRIES]MsiEntry = [_]MsiEntry{.{}} ** MAX_MSI_ENTRIES,
    msi_count: u16 = 0,
    /// IRQ overrides from MADT
    overrides: [MAX_IRQ_OVERRIDES]IrqOverride = [_]IrqOverride{.{}} ** MAX_IRQ_OVERRIDES,
    override_count: u8 = 0,
    /// Vector allocation
    next_vector: u8 = 0x30, // 0x20-0x2F reserved for exceptions/PIC
    /// Stats
    total_eoi: u64 = 0,
    total_ipis: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *ApicManager) void {
        // Disable legacy PIC
        self.pic.remap_and_disable();

        // Initialize local APIC
        self.local.init();

        self.initialized = true;
    }

    pub fn add_ioapic(self: *ApicManager, base: u64, gsi: u32, apic_id: u8) bool {
        if (self.ioapic_count >= MAX_IOAPICS) return false;
        const idx = self.ioapic_count;
        self.ioapics[idx].init(base, gsi, apic_id);
        self.ioapic_count += 1;
        return true;
    }

    pub fn add_override(self: *ApicManager, src: u8, gsi: u32, polarity: u2, trigger: u2) void {
        if (self.override_count >= MAX_IRQ_OVERRIDES) return;
        const idx = self.override_count;
        self.overrides[idx] = .{
            .source_irq = src,
            .gsi = gsi,
            .polarity = polarity,
            .trigger = trigger,
            .active = true,
        };
        self.override_count += 1;
    }

    /// Allocate a vector for a device IRQ
    pub fn alloc_vector(self: *ApicManager) ?u8 {
        if (self.next_vector >= 0xFB) return null; // Reserve top vectors
        const vec = self.next_vector;
        self.next_vector += 1;
        return vec;
    }

    /// Route a GSI to a vector on a target CPU
    pub fn route_irq(self: *ApicManager, gsi: u32, vector: u8, dest_cpu: u8) bool {
        // Check for IRQ override
        var actual_gsi = gsi;
        var polarity: bool = false;
        var trigger: bool = false;
        for (0..self.override_count) |i| {
            if (self.overrides[i].active and self.overrides[i].source_irq == @as(u8, @truncate(gsi))) {
                actual_gsi = self.overrides[i].gsi;
                polarity = self.overrides[i].polarity == 3;
                trigger = self.overrides[i].trigger == 3;
                break;
            }
        }

        // Find which I/O APIC handles this GSI
        for (0..self.ioapic_count) |i| {
            const ioapic = &self.ioapics[i];
            if (ioapic.active and actual_gsi >= ioapic.gsi_base and
                actual_gsi < ioapic.gsi_base + @as(u32, ioapic.max_redir) + 1)
            {
                const pin: u8 = @truncate(actual_gsi - ioapic.gsi_base);
                var entry = RedirectEntry{};
                entry.vector = vector;
                entry.delivery_mode = 0; // Fixed
                entry.dest_mode = false; // Physical
                entry.polarity = polarity;
                entry.trigger = trigger;
                entry.masked = false;
                entry.destination = dest_cpu;
                self.ioapics[i].set_entry(pin, entry);
                return true;
            }
        }
        return false;
    }

    /// Allocate an MSI vector
    pub fn alloc_msi(self: *ApicManager, device_bdf: u16, dest_cpu: u8) ?u8 {
        if (self.msi_count >= MAX_MSI_ENTRIES) return null;
        const vec = self.alloc_vector() orelse return null;
        const idx = self.msi_count;
        self.msi_entries[idx].configure(vec, dest_cpu);
        self.msi_entries[idx].device_bdf = device_bdf;
        self.msi_count += 1;
        return vec;
    }

    pub fn eoi(self: *ApicManager) void {
        self.local.eoi();
        self.total_eoi += 1;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var apic_mgr = ApicManager{};

pub fn get_apic_manager() *ApicManager {
    return &apic_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_apic_init() void {
    apic_mgr.init();
}

export fn zxy_apic_eoi() void {
    apic_mgr.eoi();
}

export fn zxy_apic_add_ioapic(base: u64, gsi: u32, id: u8) i32 {
    return if (apic_mgr.add_ioapic(base, gsi, id)) 0 else -1;
}

export fn zxy_apic_route_irq(gsi: u32, vector: u8, dest: u8) i32 {
    return if (apic_mgr.route_irq(gsi, vector, dest)) 0 else -1;
}

export fn zxy_apic_alloc_vector() i32 {
    return if (apic_mgr.alloc_vector()) |v| @as(i32, v) else -1;
}

export fn zxy_apic_alloc_msi(bdf: u16, dest: u8) i32 {
    return if (apic_mgr.alloc_msi(bdf, dest)) |v| @as(i32, v) else -1;
}

export fn zxy_apic_ioapic_count() u8 {
    return apic_mgr.ioapic_count;
}

export fn zxy_apic_msi_count() u16 {
    return apic_mgr.msi_count;
}

export fn zxy_apic_total_eoi() u64 {
    return apic_mgr.total_eoi;
}

export fn zxy_apic_send_ipi(dest: u8, vector: u8) void {
    apic_mgr.local.send_ipi(dest, vector);
    apic_mgr.total_ipis += 1;
}

export fn zxy_apic_setup_timer(hz: u32) void {
    apic_mgr.local.setup_timer(hz);
}

export fn zxy_apic_stop_timer() void {
    apic_mgr.local.stop_timer();
}
