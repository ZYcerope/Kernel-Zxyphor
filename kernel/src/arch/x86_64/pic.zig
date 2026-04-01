// =============================================================================
// Kernel Zxyphor - 8259 PIC (Programmable Interrupt Controller)
// =============================================================================
// The 8259 PIC is the legacy interrupt controller on x86 systems. It consists
// of two cascaded chips (master and slave), each handling 8 IRQ lines for a
// total of 16 hardware interrupts.
//
// By default, the PIC maps IRQs 0-7 to vectors 0x08-0x0F and IRQs 8-15 to
// vectors 0x70-0x77. These conflict with CPU exceptions, so we remap them
// to vectors 32-47 during initialization.
//
// For modern systems with APIC, the PIC is typically disabled in favor of
// the IOAPIC. However, we initialize it first for compatibility.
// =============================================================================

const main = @import("../../main.zig");
const cpu = @import("cpu.zig");

// =============================================================================
// PIC I/O port addresses
// =============================================================================
const PIC1_CMD: u16 = 0x20; // Master PIC command port
const PIC1_DATA: u16 = 0x21; // Master PIC data port
const PIC2_CMD: u16 = 0xA0; // Slave PIC command port
const PIC2_DATA: u16 = 0xA1; // Slave PIC data port

// =============================================================================
// Initialization Command Words (ICW)
// =============================================================================
const ICW1_ICW4: u8 = 0x01; // ICW4 will be sent
const ICW1_SINGLE: u8 = 0x02; // Single mode (vs. cascade)
const ICW1_INTERVAL4: u8 = 0x04; // Call address interval 4
const ICW1_LEVEL: u8 = 0x08; // Level-triggered mode
const ICW1_INIT: u8 = 0x10; // Initialization command

const ICW4_8086: u8 = 0x01; // 8086/88 mode (vs. MCS-80/85)
const ICW4_AUTO: u8 = 0x02; // Auto EOI
const ICW4_BUF_SLAVE: u8 = 0x08; // Buffered mode (slave)
const ICW4_BUF_MASTER: u8 = 0x0C; // Buffered mode (master)
const ICW4_SFNM: u8 = 0x10; // Special fully nested mode

// =============================================================================
// Operation Command Words (OCW)
// =============================================================================
const OCW3_READ_IRR: u8 = 0x0A; // Read IRR (Interrupt Request Register)
const OCW3_READ_ISR: u8 = 0x0B; // Read ISR (In-Service Register)

const PIC_EOI: u8 = 0x20; // End-of-Interrupt command

// =============================================================================
// Interrupt vector base offsets (where we remap IRQs to)
// =============================================================================
const PIC1_OFFSET: u8 = 32; // IRQ 0-7  → vectors 32-39
const PIC2_OFFSET: u8 = 40; // IRQ 8-15 → vectors 40-47

// =============================================================================
// Current IRQ mask (1 = masked/disabled, 0 = enabled)
// =============================================================================
var irq_mask_master: u8 = 0xFF; // All IRQs initially masked
var irq_mask_slave: u8 = 0xFF;

// =============================================================================
// Initialize both PICs with remapped interrupt vectors
// =============================================================================
pub fn initialize() void {
    // Save current masks (we'll restore them — but actually we set our own)
    const mask1 = cpu.inb(PIC1_DATA);
    const mask2 = cpu.inb(PIC2_DATA);
    _ = mask1;
    _ = mask2;

    // ICW1: Begin initialization sequence (cascade mode, ICW4 needed)
    cpu.outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    cpu.ioWait();
    cpu.outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    cpu.ioWait();

    // ICW2: Set vector offsets
    cpu.outb(PIC1_DATA, PIC1_OFFSET); // Master: IRQ 0-7 → vectors 32-39
    cpu.ioWait();
    cpu.outb(PIC2_DATA, PIC2_OFFSET); // Slave: IRQ 8-15 → vectors 40-47
    cpu.ioWait();

    // ICW3: Configure cascade
    cpu.outb(PIC1_DATA, 4); // Master: slave is on IRQ 2 (bit 2)
    cpu.ioWait();
    cpu.outb(PIC2_DATA, 2); // Slave: cascade identity = 2
    cpu.ioWait();

    // ICW4: Set 8086 mode
    cpu.outb(PIC1_DATA, ICW4_8086);
    cpu.ioWait();
    cpu.outb(PIC2_DATA, ICW4_8086);
    cpu.ioWait();

    // Mask all IRQs initially — they'll be unmasked as drivers register
    irq_mask_master = 0xFB; // Keep IRQ 2 (cascade) unmasked
    irq_mask_slave = 0xFF;
    cpu.outb(PIC1_DATA, irq_mask_master);
    cpu.outb(PIC2_DATA, irq_mask_slave);

    main.klog(.info, "PIC: Remapped IRQs to vectors {d}-{d}", .{ PIC1_OFFSET, PIC2_OFFSET + 7 });
}

// =============================================================================
// IRQ masking — enable/disable individual IRQ lines
// =============================================================================

/// Enable (unmask) a specific IRQ line
pub fn enableIrq(irq: u8) void {
    if (irq < 8) {
        irq_mask_master &= ~(@as(u8, 1) << @as(u3, @truncate(irq)));
        cpu.outb(PIC1_DATA, irq_mask_master);
    } else if (irq < 16) {
        irq_mask_slave &= ~(@as(u8, 1) << @as(u3, @truncate(irq - 8)));
        cpu.outb(PIC2_DATA, irq_mask_slave);
    }
}

/// Disable (mask) a specific IRQ line
pub fn disableIrq(irq: u8) void {
    if (irq < 8) {
        irq_mask_master |= @as(u8, 1) << @as(u3, @truncate(irq));
        cpu.outb(PIC1_DATA, irq_mask_master);
    } else if (irq < 16) {
        irq_mask_slave |= @as(u8, 1) << @as(u3, @truncate(irq - 8));
        cpu.outb(PIC2_DATA, irq_mask_slave);
    }
}

/// Check if an IRQ is currently masked
pub fn isIrqMasked(irq: u8) bool {
    if (irq < 8) {
        return (irq_mask_master & (@as(u8, 1) << @as(u3, @truncate(irq)))) != 0;
    } else if (irq < 16) {
        return (irq_mask_slave & (@as(u8, 1) << @as(u3, @truncate(irq - 8)))) != 0;
    }
    return true;
}

// =============================================================================
// End-of-Interrupt signaling
// =============================================================================

/// Send End-of-Interrupt to the PIC(s) for the given IRQ
pub fn sendEoi(irq: u8) void {
    // If the IRQ came from the slave PIC, we need to send EOI to both
    if (irq >= 8) {
        cpu.outb(PIC2_CMD, PIC_EOI);
    }
    cpu.outb(PIC1_CMD, PIC_EOI);
}

// =============================================================================
// Spurious IRQ detection
// =============================================================================
// The PIC can generate spurious interrupts (IRQ 7 or IRQ 15) due to
// electrical noise or timing issues. We can detect them by reading the ISR.
// =============================================================================

/// Check if an IRQ 7 is spurious (appears on master PIC)
pub fn isSpuriousIrq7() bool {
    cpu.outb(PIC1_CMD, OCW3_READ_ISR);
    return (cpu.inb(PIC1_CMD) & 0x80) == 0;
}

/// Check if an IRQ 15 is spurious (appears on slave PIC)
pub fn isSpuriousIrq15() bool {
    cpu.outb(PIC2_CMD, OCW3_READ_ISR);
    if ((cpu.inb(PIC2_CMD) & 0x80) == 0) {
        // Spurious from slave — still need to ACK master (cascade line)
        cpu.outb(PIC1_CMD, PIC_EOI);
        return true;
    }
    return false;
}

// =============================================================================
// Register access — for diagnostics
// =============================================================================

/// Read the Interrupt Request Register (pending interrupts)
pub fn readIrr() u16 {
    cpu.outb(PIC1_CMD, OCW3_READ_IRR);
    cpu.outb(PIC2_CMD, OCW3_READ_IRR);
    return (@as(u16, cpu.inb(PIC2_CMD)) << 8) | @as(u16, cpu.inb(PIC1_CMD));
}

/// Read the In-Service Register (currently being serviced)
pub fn readIsr() u16 {
    cpu.outb(PIC1_CMD, OCW3_READ_ISR);
    cpu.outb(PIC2_CMD, OCW3_READ_ISR);
    return (@as(u16, cpu.inb(PIC2_CMD)) << 8) | @as(u16, cpu.inb(PIC1_CMD));
}

/// Disable both PICs entirely (used when switching to APIC)
pub fn disable() void {
    cpu.outb(PIC1_DATA, 0xFF);
    cpu.outb(PIC2_DATA, 0xFF);
    main.klog(.info, "PIC: Disabled (switching to APIC)", .{});
}
