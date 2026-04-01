// =============================================================================
// Kernel Zxyphor - Serial Port Driver (UART 16550A)
// =============================================================================
// Implements communication via the 16550A UART serial port. Used as the
// primary debugging output during boot and for kernel log messages.
// The serial port is invaluable for kernel development because it works
// even when the VGA display or framebuffer is not available.
//
// Supported features:
//   - Configurable baud rate (up to 115200)
//   - Interrupt-driven or polling mode
//   - FIFO buffer management
//   - Std.io.Writer interface for formatted output
// =============================================================================

const std = @import("std");
const cpu = @import("cpu.zig");

// =============================================================================
// Serial port base addresses
// =============================================================================
pub const Port = enum(u16) {
    com1 = 0x3F8,
    com2 = 0x2F8,
    com3 = 0x3E8,
    com4 = 0x2E8,
};

// =============================================================================
// UART register offsets (from base address)
// =============================================================================
const REG_DATA: u16 = 0; // Data register (R/W) / Divisor latch low (DLAB=1)
const REG_IER: u16 = 1; // Interrupt Enable Register / Divisor latch high (DLAB=1)
const REG_IIR: u16 = 2; // Interrupt Identification Register (read)
const REG_FCR: u16 = 2; // FIFO Control Register (write)
const REG_LCR: u16 = 3; // Line Control Register
const REG_MCR: u16 = 4; // Modem Control Register
const REG_LSR: u16 = 5; // Line Status Register
const REG_MSR: u16 = 6; // Modem Status Register
const REG_SCRATCH: u16 = 7; // Scratch Register

// =============================================================================
// Line Status Register (LSR) bits
// =============================================================================
const LSR_DATA_READY: u8 = 1 << 0; // Data available in receive buffer
const LSR_OVERRUN: u8 = 1 << 1; // Overrun error
const LSR_PARITY_ERR: u8 = 1 << 2; // Parity error
const LSR_FRAMING_ERR: u8 = 1 << 3; // Framing error
const LSR_BREAK: u8 = 1 << 4; // Break indicator
const LSR_TX_EMPTY: u8 = 1 << 5; // Transmit holding register empty
const LSR_TX_IDLE: u8 = 1 << 6; // Transmitter idle
const LSR_FIFO_ERR: u8 = 1 << 7; // Error in received FIFO

// =============================================================================
// Line Control Register (LCR) bits
// =============================================================================
const LCR_DLAB: u8 = 1 << 7; // Divisor Latch Access Bit
const LCR_BREAK: u8 = 1 << 6; // Set break enable
const LCR_PARITY_NONE: u8 = 0x00;
const LCR_PARITY_ODD: u8 = 0x08;
const LCR_PARITY_EVEN: u8 = 0x18;
const LCR_PARITY_MARK: u8 = 0x28;
const LCR_PARITY_SPACE: u8 = 0x38;
const LCR_STOP_1: u8 = 0x00; // 1 stop bit
const LCR_STOP_2: u8 = 0x04; // 2 stop bits
const LCR_WORD_5: u8 = 0x00; // 5 data bits
const LCR_WORD_6: u8 = 0x01; // 6 data bits
const LCR_WORD_7: u8 = 0x02; // 7 data bits
const LCR_WORD_8: u8 = 0x03; // 8 data bits

// =============================================================================
// FIFO Control Register (FCR) bits
// =============================================================================
const FCR_ENABLE: u8 = 1 << 0; // Enable FIFOs
const FCR_CLEAR_RX: u8 = 1 << 1; // Clear receive FIFO
const FCR_CLEAR_TX: u8 = 1 << 2; // Clear transmit FIFO
const FCR_DMA_MODE: u8 = 1 << 3; // DMA mode select
const FCR_TRIGGER_1: u8 = 0x00; // Trigger level: 1 byte
const FCR_TRIGGER_4: u8 = 0x40; // Trigger level: 4 bytes
const FCR_TRIGGER_8: u8 = 0x80; // Trigger level: 8 bytes
const FCR_TRIGGER_14: u8 = 0xC0; // Trigger level: 14 bytes

// =============================================================================
// Modem Control Register (MCR) bits
// =============================================================================
const MCR_DTR: u8 = 1 << 0; // Data Terminal Ready
const MCR_RTS: u8 = 1 << 1; // Request To Send
const MCR_OUT1: u8 = 1 << 2; // Aux output 1
const MCR_OUT2: u8 = 1 << 3; // Aux output 2 (enables IRQ)
const MCR_LOOPBACK: u8 = 1 << 4; // Loopback mode

// =============================================================================
// Baud rate divisors
// =============================================================================
pub const BaudRate = enum(u16) {
    baud_115200 = 1,
    baud_57600 = 2,
    baud_38400 = 3,
    baud_19200 = 6,
    baud_9600 = 12,
    baud_4800 = 24,
    baud_2400 = 48,
    baud_1200 = 96,
};

// =============================================================================
// State
// =============================================================================
var active_port: Port = .com1;
var port_initialized: bool = false;

// =============================================================================
// Initialize a serial port with the given baud rate
// =============================================================================
pub fn initialize(port: Port, baud: BaudRate) void {
    active_port = port;
    const base = @intFromEnum(port);
    const divisor = @intFromEnum(baud);

    // Disable all interrupts
    cpu.outb(base + REG_IER, 0x00);

    // Enable DLAB (set baud rate divisor)
    cpu.outb(base + REG_LCR, LCR_DLAB);

    // Set divisor (low byte and high byte)
    cpu.outb(base + REG_DATA, @truncate(divisor));
    cpu.outb(base + REG_IER, @truncate(divisor >> 8));

    // 8 data bits, no parity, 1 stop bit (8N1)
    cpu.outb(base + REG_LCR, LCR_WORD_8 | LCR_PARITY_NONE | LCR_STOP_1);

    // Enable FIFO, clear them, with 14-byte trigger threshold
    cpu.outb(base + REG_FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX | FCR_TRIGGER_14);

    // Enable IRQs, set RTS/DSR, enable aux output 2 (required for IRQs)
    cpu.outb(base + REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    // Test the serial port by setting loopback mode
    cpu.outb(base + REG_MCR, MCR_LOOPBACK | MCR_RTS | MCR_DTR | MCR_OUT2);

    // Send a test byte
    cpu.outb(base + REG_DATA, 0xAE);

    // Check if we receive the same byte
    if (cpu.inb(base + REG_DATA) != 0xAE) {
        // Serial port is faulty or not present
        port_initialized = false;
        return;
    }

    // Not in loopback mode anymore, set normal operation
    cpu.outb(base + REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

    port_initialized = true;
}

// =============================================================================
// Low-level byte I/O
// =============================================================================

/// Check if we can receive data
fn canReceive() bool {
    const base = @intFromEnum(active_port);
    return (cpu.inb(base + REG_LSR) & LSR_DATA_READY) != 0;
}

/// Check if we can transmit data
fn canTransmit() bool {
    const base = @intFromEnum(active_port);
    return (cpu.inb(base + REG_LSR) & LSR_TX_EMPTY) != 0;
}

/// Read a single byte (blocking)
pub fn readByte() u8 {
    while (!canReceive()) {
        cpu.spinHint();
    }
    return cpu.inb(@intFromEnum(active_port) + REG_DATA);
}

/// Write a single byte (blocking)
pub fn writeByte(byte: u8) void {
    while (!canTransmit()) {
        cpu.spinHint();
    }
    cpu.outb(@intFromEnum(active_port) + REG_DATA, byte);
}

/// Try to read a byte without blocking
pub fn tryReadByte() ?u8 {
    if (canReceive()) {
        return cpu.inb(@intFromEnum(active_port) + REG_DATA);
    }
    return null;
}

/// Write a string
pub fn writeString(s: []const u8) void {
    for (s) |byte| {
        if (byte == '\n') {
            writeByte('\r');
        }
        writeByte(byte);
    }
}

// =============================================================================
// std.io.Writer interface — allows using std.fmt.format with serial port
// =============================================================================
pub const SerialWriter = struct {
    pub const Error = error{};

    pub fn print(self: SerialWriter, comptime fmt: []const u8, args: anytype) Error!void {
        _ = self;
        std.fmt.format(serialWriteCallback, fmt, args) catch {};
    }
};

fn serialWriteCallback(bytes: []const u8) error{}!void {
    for (bytes) |byte| {
        writeByte(byte);
    }
}

var serial_writer_instance = SerialWriter{};

pub fn writer() SerialWriter {
    return serial_writer_instance;
}

/// Check if the serial port was successfully initialized
pub fn isInitialized() bool {
    return port_initialized;
}
