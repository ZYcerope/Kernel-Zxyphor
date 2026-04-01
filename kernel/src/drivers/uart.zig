// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Serial/UART Driver (Zig)
//
// Universal Asynchronous Receiver-Transmitter:
// - 16550A UART register definitions and access
// - COM1-COM4 port management
// - Baud rate configuration (50-115200)
// - Parity, stop bits, word length
// - FIFO control (16-byte and 64-byte FIFO)
// - Interrupt-driven RX/TX with ring buffers
// - Modem control/status lines (RTS/CTS/DTR/DSR)
// - Line status error detection (overrun, parity, framing, break)
// - RS-232 flow control (hardware & software XON/XOFF)
// - Console output via serial
// - Early serial debug output
// - Loopback test mode

const std = @import("std");

// ─────────────────── 16550A Registers ───────────────────────────────

const REG_RBR: u16 = 0; // Receive Buffer (read, DLAB=0)
const REG_THR: u16 = 0; // Transmit Holding (write, DLAB=0)
const REG_DLL: u16 = 0; // Divisor Latch Low (DLAB=1)
const REG_IER: u16 = 1; // Interrupt Enable (DLAB=0)
const REG_DLH: u16 = 1; // Divisor Latch High (DLAB=1)
const REG_IIR: u16 = 2; // Interrupt Identification (read)
const REG_FCR: u16 = 2; // FIFO Control (write)
const REG_LCR: u16 = 3; // Line Control
const REG_MCR: u16 = 4; // Modem Control
const REG_LSR: u16 = 5; // Line Status
const REG_MSR: u16 = 6; // Modem Status
const REG_SCR: u16 = 7; // Scratch

// IER bits
const IER_RDA: u8 = 1 << 0; // Received Data Available
const IER_THRE: u8 = 1 << 1; // TX Holding Register Empty
const IER_LINE: u8 = 1 << 2; // Line Status
const IER_MODEM: u8 = 1 << 3; // Modem Status

// IIR bits
const IIR_NO_PENDING: u8 = 1 << 0;
const IIR_ID_MASK: u8 = 0x0E;
const IIR_MODEM: u8 = 0x00;
const IIR_THRE_EMPTY: u8 = 0x02;
const IIR_RDA: u8 = 0x04;
const IIR_LINE_STATUS: u8 = 0x06;
const IIR_CHAR_TIMEOUT: u8 = 0x0C;

// FCR bits
const FCR_ENABLE: u8 = 1 << 0;
const FCR_CLR_RX: u8 = 1 << 1;
const FCR_CLR_TX: u8 = 1 << 2;
const FCR_DMA_MODE: u8 = 1 << 3;
const FCR_64BYTE: u8 = 1 << 5;
const FCR_TRIG_1: u8 = 0x00;
const FCR_TRIG_4: u8 = 0x40;
const FCR_TRIG_8: u8 = 0x80;
const FCR_TRIG_14: u8 = 0xC0;

// LCR bits
const LCR_WLS_5: u8 = 0x00;
const LCR_WLS_6: u8 = 0x01;
const LCR_WLS_7: u8 = 0x02;
const LCR_WLS_8: u8 = 0x03;
const LCR_STOP_1: u8 = 0x00;
const LCR_STOP_2: u8 = 0x04;
const LCR_PARITY_NONE: u8 = 0x00;
const LCR_PARITY_ODD: u8 = 0x08;
const LCR_PARITY_EVEN: u8 = 0x18;
const LCR_PARITY_MARK: u8 = 0x28;
const LCR_PARITY_SPACE: u8 = 0x38;
const LCR_BREAK: u8 = 0x40;
const LCR_DLAB: u8 = 0x80;

// MCR bits
const MCR_DTR: u8 = 1 << 0;
const MCR_RTS: u8 = 1 << 1;
const MCR_OUT1: u8 = 1 << 2;
const MCR_OUT2: u8 = 1 << 3; // Required for interrupts
const MCR_LOOP: u8 = 1 << 4;

// LSR bits
const LSR_DR: u8 = 1 << 0; // Data Ready
const LSR_OE: u8 = 1 << 1; // Overrun Error
const LSR_PE: u8 = 1 << 2; // Parity Error
const LSR_FE: u8 = 1 << 3; // Framing Error
const LSR_BI: u8 = 1 << 4; // Break Indicator
const LSR_THRE: u8 = 1 << 5; // TX Holding Register Empty
const LSR_TEMT: u8 = 1 << 6; // Transmitter Empty
const LSR_FIFO_ERR: u8 = 1 << 7; // FIFO Error

// MSR bits
const MSR_DCTS: u8 = 1 << 0; // Delta CTS
const MSR_DDSR: u8 = 1 << 1; // Delta DSR
const MSR_TERI: u8 = 1 << 2; // Trailing Edge RI
const MSR_DDCD: u8 = 1 << 3; // Delta DCD
const MSR_CTS: u8 = 1 << 4;
const MSR_DSR: u8 = 1 << 5;
const MSR_RI: u8 = 1 << 6;
const MSR_DCD: u8 = 1 << 7;

// ─────────────────── Constants ──────────────────────────────────────

const MAX_PORTS: usize = 4;
const RX_BUF_SIZE: usize = 4096;
const TX_BUF_SIZE: usize = 4096;
const UART_CLOCK: u32 = 1843200; // 1.8432 MHz

const XON: u8 = 0x11; // DC1
const XOFF: u8 = 0x13; // DC3

// Standard COM port addresses
const COM1_BASE: u16 = 0x3F8;
const COM2_BASE: u16 = 0x2F8;
const COM3_BASE: u16 = 0x3E8;
const COM4_BASE: u16 = 0x2E8;

const COM_IRQS = [_]u8{ 4, 3, 4, 3 };
const COM_BASES = [_]u16{ COM1_BASE, COM2_BASE, COM3_BASE, COM4_BASE };

// ─────────────────── Configuration ──────────────────────────────────

pub const BaudRate = enum(u32) {
    baud_50 = 50,
    baud_110 = 110,
    baud_300 = 300,
    baud_1200 = 1200,
    baud_2400 = 2400,
    baud_4800 = 4800,
    baud_9600 = 9600,
    baud_19200 = 19200,
    baud_38400 = 38400,
    baud_57600 = 57600,
    baud_115200 = 115200,

    pub fn divisor(self: BaudRate) u16 {
        return @truncate(UART_CLOCK / (16 * @intFromEnum(self)));
    }
};

pub const WordLength = enum(u8) {
    bits5 = LCR_WLS_5,
    bits6 = LCR_WLS_6,
    bits7 = LCR_WLS_7,
    bits8 = LCR_WLS_8,
};

pub const Parity = enum(u8) {
    none = LCR_PARITY_NONE,
    odd = LCR_PARITY_ODD,
    even = LCR_PARITY_EVEN,
    mark = LCR_PARITY_MARK,
    space = LCR_PARITY_SPACE,
};

pub const StopBits = enum(u8) {
    one = LCR_STOP_1,
    two = LCR_STOP_2,
};

pub const FlowControl = enum(u8) {
    none = 0,
    hardware = 1, // RTS/CTS
    software = 2, // XON/XOFF
};

pub const UartConfig = struct {
    baud_rate: BaudRate = .baud_115200,
    word_length: WordLength = .bits8,
    parity: Parity = .none,
    stop_bits: StopBits = .one,
    flow_control: FlowControl = .none,
    fifo_enabled: bool = true,
    fifo_trigger: u8 = FCR_TRIG_14,
};

// ─────────────────── Ring Buffer ────────────────────────────────────

pub fn RingBuffer(comptime SIZE: usize) type {
    return struct {
        data: [SIZE]u8 = [_]u8{0} ** SIZE,
        head: usize = 0,
        tail: usize = 0,
        count: usize = 0,

        const Self = @This();

        pub fn push(self: *Self, byte: u8) bool {
            if (self.count >= SIZE) return false;
            self.data[self.head] = byte;
            self.head = (self.head + 1) % SIZE;
            self.count += 1;
            return true;
        }

        pub fn pop(self: *Self) ?u8 {
            if (self.count == 0) return null;
            const byte = self.data[self.tail];
            self.tail = (self.tail + 1) % SIZE;
            self.count -= 1;
            return byte;
        }

        pub fn peek(self: *const Self) ?u8 {
            if (self.count == 0) return null;
            return self.data[self.tail];
        }

        pub fn is_empty(self: *const Self) bool {
            return self.count == 0;
        }

        pub fn is_full(self: *const Self) bool {
            return self.count >= SIZE;
        }

        pub fn available(self: *const Self) usize {
            return SIZE - self.count;
        }

        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
            self.count = 0;
        }
    };
}

// ─────────────────── UART Port ──────────────────────────────────────

pub const LineError = packed struct {
    overrun: bool = false,
    parity: bool = false,
    framing: bool = false,
    break_detect: bool = false,
    fifo_error: bool = false,
    _pad: u3 = 0,
};

pub const ModemStatus = packed struct {
    cts: bool = false,
    dsr: bool = false,
    ri: bool = false,
    dcd: bool = false,
    _pad: u4 = 0,
};

pub const UartPort = struct {
    /// Port base I/O address
    base: u16 = 0,
    /// IRQ number
    irq: u8 = 0,
    /// Port index (0-3 for COM1-4)
    index: u8 = 0,
    /// Configuration
    config: UartConfig = .{},
    /// Ring buffers
    rx_buf: RingBuffer(RX_BUF_SIZE) = .{},
    tx_buf: RingBuffer(TX_BUF_SIZE) = .{},
    /// Software flow control state
    xoff_sent: bool = false,
    xoff_received: bool = false,
    /// Error tracking
    last_error: LineError = .{},
    rx_errors: u32 = 0,
    tx_errors: u32 = 0,
    /// Modem lines
    modem: ModemStatus = .{},
    /// Statistics
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_interrupts: u64 = 0,
    tx_interrupts: u64 = 0,
    overruns: u32 = 0,
    /// State
    initialized: bool = false,
    open: bool = false,
    tx_active: bool = false,

    // I/O port access — in real kernel these use `in`/`out` instructions
    fn outb(self: *const UartPort, reg: u16, val: u8) void {
        // asm volatile ("outb %[val], %[port]" : : [val] "a" (val), [port] "Nd" (self.base + reg));
        _ = self;
        _ = reg;
        _ = val;
    }

    fn inb(self: *const UartPort, reg: u16) u8 {
        // var ret: u8 = undefined;
        // asm volatile ("inb %[port], %[ret]" : [ret] "=a" (ret) : [port] "Nd" (self.base + reg));
        // return ret;
        _ = self;
        _ = reg;
        return 0;
    }

    /// Initialize the UART port
    pub fn init(self: *UartPort, base: u16, irq_num: u8, idx: u8, config: UartConfig) void {
        self.base = base;
        self.irq = irq_num;
        self.index = idx;
        self.config = config;

        // Disable interrupts
        self.outb(REG_IER, 0x00);

        // Set baud rate (DLAB=1)
        self.outb(REG_LCR, LCR_DLAB);
        const div = config.baud_rate.divisor();
        self.outb(REG_DLL, @truncate(div));
        self.outb(REG_DLH, @truncate(div >> 8));

        // Set line control (clears DLAB)
        const lcr = @intFromEnum(config.word_length) |
            @intFromEnum(config.stop_bits) |
            @intFromEnum(config.parity);
        self.outb(REG_LCR, lcr);

        // Configure FIFO
        if (config.fifo_enabled) {
            self.outb(REG_FCR, FCR_ENABLE | FCR_CLR_RX | FCR_CLR_TX | config.fifo_trigger);
        } else {
            self.outb(REG_FCR, 0);
        }

        // Modem control: DTR + RTS + OUT2 (needed for interrupts)
        self.outb(REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

        // Enable interrupts
        self.outb(REG_IER, IER_RDA | IER_THRE | IER_LINE | IER_MODEM);

        // Clear pending interrupts
        _ = self.inb(REG_LSR);
        _ = self.inb(REG_RBR);
        _ = self.inb(REG_IIR);
        _ = self.inb(REG_MSR);

        self.initialized = true;
    }

    /// Loopback test to verify UART presence
    pub fn loopback_test(self: *UartPort) bool {
        // Set loopback mode
        self.outb(REG_MCR, MCR_LOOP | MCR_OUT1 | MCR_OUT2);

        // Write test byte
        self.outb(REG_THR, 0xAE);

        // Read back
        const result = self.inb(REG_RBR);

        // Restore MCR
        self.outb(REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT1 | MCR_OUT2);

        return result == 0xAE;
    }

    /// Read line status
    pub fn line_status(self: *UartPort) u8 {
        return self.inb(REG_LSR);
    }

    /// Check if data available
    pub fn data_ready(self: *UartPort) bool {
        return (self.line_status() & LSR_DR) != 0;
    }

    /// Check if transmitter ready
    pub fn tx_ready(self: *UartPort) bool {
        return (self.line_status() & LSR_THRE) != 0;
    }

    /// Read one byte (polling)
    pub fn read_byte(self: *UartPort) ?u8 {
        const lsr = self.line_status();

        // Check for errors
        if (lsr & LSR_OE != 0) { self.last_error.overrun = true; self.overruns += 1; }
        if (lsr & LSR_PE != 0) { self.last_error.parity = true; self.rx_errors += 1; }
        if (lsr & LSR_FE != 0) { self.last_error.framing = true; self.rx_errors += 1; }
        if (lsr & LSR_BI != 0) { self.last_error.break_detect = true; }

        if (lsr & LSR_DR == 0) return null;

        const byte = self.inb(REG_RBR);
        self.rx_bytes += 1;

        // Software flow control
        if (self.config.flow_control == .software) {
            if (byte == XON) { self.xoff_received = false; return null; }
            if (byte == XOFF) { self.xoff_received = true; return null; }
        }

        return byte;
    }

    /// Write one byte (polling)
    pub fn write_byte(self: *UartPort, byte: u8) bool {
        // Hardware flow control: check CTS
        if (self.config.flow_control == .hardware) {
            const msr = self.inb(REG_MSR);
            if (msr & MSR_CTS == 0) return false;
        }

        // Software flow control: honor XOFF
        if (self.config.flow_control == .software and self.xoff_received) {
            return false;
        }

        // Wait for THRE
        var timeout: u32 = 10000;
        while (!self.tx_ready() and timeout > 0) {
            timeout -= 1;
        }
        if (timeout == 0) return false;

        self.outb(REG_THR, byte);
        self.tx_bytes += 1;
        return true;
    }

    /// Buffered write
    pub fn write(self: *UartPort, data: []const u8) usize {
        var written: usize = 0;
        for (data) |byte| {
            if (self.tx_buf.push(byte)) {
                written += 1;
            } else {
                break;
            }
        }
        // Start TX if not already running
        if (!self.tx_active and !self.tx_buf.is_empty()) {
            self.start_tx();
        }
        return written;
    }

    /// Buffered read
    pub fn read(self: *UartPort, buf: []u8) usize {
        var count: usize = 0;
        for (buf) |*b| {
            if (self.rx_buf.pop()) |byte| {
                b.* = byte;
                count += 1;
            } else {
                break;
            }
        }
        return count;
    }

    fn start_tx(self: *UartPort) void {
        self.tx_active = true;
        // Drain TX buffer to hardware
        while (self.tx_ready()) {
            if (self.tx_buf.pop()) |byte| {
                self.outb(REG_THR, byte);
                self.tx_bytes += 1;
            } else {
                self.tx_active = false;
                break;
            }
        }
    }

    /// Handle UART interrupt
    pub fn handle_interrupt(self: *UartPort) void {
        const iir = self.inb(REG_IIR);
        if (iir & IIR_NO_PENDING != 0) return;

        const id = iir & IIR_ID_MASK;
        switch (id) {
            IIR_RDA, IIR_CHAR_TIMEOUT => {
                // Receive data
                self.rx_interrupts += 1;
                while (self.data_ready()) {
                    if (self.read_byte()) |byte| {
                        if (!self.rx_buf.push(byte)) {
                            self.overruns += 1;
                        }
                        // Software flow control: send XOFF if buffer getting full
                        if (self.config.flow_control == .software) {
                            if (self.rx_buf.count > RX_BUF_SIZE * 3 / 4 and !self.xoff_sent) {
                                self.outb(REG_THR, XOFF);
                                self.xoff_sent = true;
                            }
                        }
                    }
                }
            },
            IIR_THRE_EMPTY => {
                // TX ready
                self.tx_interrupts += 1;
                self.start_tx();
            },
            IIR_LINE_STATUS => {
                // Line status change
                _ = self.line_status(); // Clear by reading
            },
            IIR_MODEM => {
                // Modem status change
                const msr = self.inb(REG_MSR);
                self.modem.cts = (msr & MSR_CTS) != 0;
                self.modem.dsr = (msr & MSR_DSR) != 0;
                self.modem.ri = (msr & MSR_RI) != 0;
                self.modem.dcd = (msr & MSR_DCD) != 0;
                // If CTS restored and we have buffered TX data
                if (self.modem.cts and !self.tx_buf.is_empty()) {
                    self.start_tx();
                }
            },
            else => {},
        }
    }

    /// Write a C string for early debug console
    pub fn write_string(self: *UartPort, s: []const u8) void {
        for (s) |c| {
            if (c == '\n') {
                _ = self.write_byte('\r');
            }
            _ = self.write_byte(c);
        }
    }

    /// Set break signal
    pub fn set_break(self: *UartPort, enable: bool) void {
        var lcr = self.inb(REG_LCR);
        if (enable) {
            lcr |= LCR_BREAK;
        } else {
            lcr &= ~LCR_BREAK;
        }
        self.outb(REG_LCR, lcr);
    }

    /// Change baud rate
    pub fn set_baud(self: *UartPort, baud: BaudRate) void {
        const lcr = self.inb(REG_LCR);
        self.outb(REG_LCR, lcr | LCR_DLAB);
        const div = baud.divisor();
        self.outb(REG_DLL, @truncate(div));
        self.outb(REG_DLH, @truncate(div >> 8));
        self.outb(REG_LCR, lcr);
        self.config.baud_rate = baud;
    }
};

// ─────────────────── UART Manager ───────────────────────────────────

pub const UartManager = struct {
    ports: [MAX_PORTS]UartPort = [_]UartPort{.{}} ** MAX_PORTS,
    port_count: u8 = 0,
    /// Debug console (usually COM1)
    console_port: u8 = 0,
    initialized: bool = false,

    pub fn init(self: *UartManager) void {
        // Initialize standard COM ports
        for (COM_BASES, COM_IRQS, 0..) |base, irq_num, i| {
            self.ports[i].init(base, irq_num, @truncate(i), .{});
            self.port_count += 1;
        }
        self.initialized = true;
    }

    pub fn get_port(self: *UartManager, index: u8) ?*UartPort {
        if (index >= self.port_count) return null;
        if (!self.ports[index].initialized) return null;
        return &self.ports[index];
    }

    /// Early console write (COM1, polling mode)
    pub fn early_printk(self: *UartManager, msg: []const u8) void {
        if (self.port_count == 0) return;
        self.ports[self.console_port].write_string(msg);
    }

    /// Handle IRQ for all ports sharing an interrupt
    pub fn handle_irq(self: *UartManager, irq_num: u8) void {
        for (0..self.port_count) |i| {
            if (self.ports[i].irq == irq_num and self.ports[i].initialized) {
                self.ports[i].handle_interrupt();
            }
        }
    }

    pub fn total_rx(self: *const UartManager) u64 {
        var total: u64 = 0;
        for (0..self.port_count) |i| {
            total += self.ports[i].rx_bytes;
        }
        return total;
    }

    pub fn total_tx(self: *const UartManager) u64 {
        var total: u64 = 0;
        for (0..self.port_count) |i| {
            total += self.ports[i].tx_bytes;
        }
        return total;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var uart_mgr = UartManager{};

pub fn get_uart_manager() *UartManager {
    return &uart_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_uart_init() void {
    uart_mgr.init();
}

export fn zxy_uart_write_byte(port: u8, byte: u8) i32 {
    if (uart_mgr.get_port(port)) |p| {
        return if (p.write_byte(byte)) 0 else -1;
    }
    return -1;
}

export fn zxy_uart_read_byte(port: u8) i32 {
    if (uart_mgr.get_port(port)) |p| {
        return if (p.read_byte()) |b| @as(i32, b) else -1;
    }
    return -1;
}

export fn zxy_uart_port_count() u8 {
    return uart_mgr.port_count;
}

export fn zxy_uart_total_rx() u64 {
    return uart_mgr.total_rx();
}

export fn zxy_uart_total_tx() u64 {
    return uart_mgr.total_tx();
}

export fn zxy_uart_handle_irq(irq_num: u8) void {
    uart_mgr.handle_irq(irq_num);
}

export fn zxy_uart_set_baud(port: u8, baud: u32) void {
    if (uart_mgr.get_port(port)) |p| {
        const rate: BaudRate = switch (baud) {
            50 => .baud_50,
            110 => .baud_110,
            300 => .baud_300,
            1200 => .baud_1200,
            2400 => .baud_2400,
            4800 => .baud_4800,
            9600 => .baud_9600,
            19200 => .baud_19200,
            38400 => .baud_38400,
            57600 => .baud_57600,
            else => .baud_115200,
        };
        p.set_baud(rate);
    }
}
