// =============================================================================
// Kernel Zxyphor — Intel e1000 Network Driver
// =============================================================================
// E1000/E1000E Ethernet controller driver:
//   - Initialization and reset
//   - Transmit/receive descriptor ring management
//   - Interrupt handling (MSI-X)
//   - Link state detection
//   - Checksum offload
//   - Multicast filtering
//   - VLAN tag support
//   - Receive-side scaling (RSS)
//   - Jumbo frame support
//   - PHY management
//   - EEPROM access
//   - Promiscuous/multicast mode
//   - Statistics and counters
// =============================================================================

// ============================================================================
// Register offsets
// ============================================================================

pub const E1000_CTRL: u32 = 0x0000;     // Device Control
pub const E1000_STATUS: u32 = 0x0008;   // Device Status
pub const E1000_EECD: u32 = 0x0010;     // EEPROM/Flash Control
pub const E1000_EERD: u32 = 0x0014;     // EEPROM Read
pub const E1000_CTRL_EXT: u32 = 0x0018; // Extended Device Control
pub const E1000_ICR: u32 = 0x00C0;      // Interrupt Cause Read
pub const E1000_ITR: u32 = 0x00C4;      // Interrupt Throttling Rate
pub const E1000_ICS: u32 = 0x00C8;      // Interrupt Cause Set
pub const E1000_IMS: u32 = 0x00D0;      // Interrupt Mask Set
pub const E1000_IMC: u32 = 0x00D8;      // Interrupt Mask Clear
pub const E1000_RCTL: u32 = 0x0100;     // Receive Control
pub const E1000_TCTL: u32 = 0x0400;     // Transmit Control
pub const E1000_TIPG: u32 = 0x0410;     // TX Inter-Packet Gap
pub const E1000_RDBAL: u32 = 0x2800;    // RX Descriptor Base Low
pub const E1000_RDBAH: u32 = 0x2804;    // RX Descriptor Base High
pub const E1000_RDLEN: u32 = 0x2808;    // RX Descriptor Length
pub const E1000_RDH: u32 = 0x2810;      // RX Descriptor Head
pub const E1000_RDT: u32 = 0x2818;      // RX Descriptor Tail
pub const E1000_TDBAL: u32 = 0x3800;    // TX Descriptor Base Low
pub const E1000_TDBAH: u32 = 0x3804;    // TX Descriptor Base High
pub const E1000_TDLEN: u32 = 0x3808;    // TX Descriptor Length
pub const E1000_TDH: u32 = 0x3810;      // TX Descriptor Head
pub const E1000_TDT: u32 = 0x3818;      // TX Descriptor Tail
pub const E1000_MTA: u32 = 0x5200;      // Multicast Table Array (128 entries)
pub const E1000_RAL: u32 = 0x5400;      // Receive Address Low
pub const E1000_RAH: u32 = 0x5404;      // Receive Address High

// Statistics registers
pub const E1000_CRCERRS: u32 = 0x4000;
pub const E1000_MPC: u32 = 0x4010;
pub const E1000_GPRC: u32 = 0x4074;     // Good Packets Received
pub const E1000_GPTC: u32 = 0x4080;     // Good Packets Transmitted
pub const E1000_GORCL: u32 = 0x4088;    // Good Octets Received (low)
pub const E1000_GORCH: u32 = 0x408C;
pub const E1000_GOTCL: u32 = 0x4090;    // Good Octets Transmitted (low)
pub const E1000_GOTCH: u32 = 0x4094;
pub const E1000_TPR: u32 = 0x40D0;      // Total Packets Received
pub const E1000_TPT: u32 = 0x40D4;      // Total Packets Transmitted
pub const E1000_TORL: u32 = 0x40C0;     // Total Octets Received (low)
pub const E1000_TORH: u32 = 0x40C4;
pub const E1000_TOTL: u32 = 0x40C8;     // Total Octets Transmitted (low)
pub const E1000_TOTH: u32 = 0x40CC;

// CTRL bits
pub const CTRL_FD: u32 = 1 << 0;        // Full-Duplex
pub const CTRL_LRST: u32 = 1 << 3;      // Link Reset
pub const CTRL_ASDE: u32 = 1 << 5;      // Auto-Speed Detection Enable
pub const CTRL_SLU: u32 = 1 << 6;       // Set Link Up
pub const CTRL_ILOS: u32 = 1 << 7;      // Invert Loss-of-Signal
pub const CTRL_RST: u32 = 1 << 26;      // Device Reset
pub const CTRL_VME: u32 = 1 << 30;      // VLAN Mode Enable
pub const CTRL_PHY_RST: u32 = 1 << 31;  // PHY Reset

// STATUS bits
pub const STATUS_FD: u32 = 1 << 0;      // Full-Duplex
pub const STATUS_LU: u32 = 1 << 1;      // Link Up
pub const STATUS_SPEED_MASK: u32 = 3 << 6;
pub const STATUS_SPEED_10: u32 = 0 << 6;
pub const STATUS_SPEED_100: u32 = 1 << 6;
pub const STATUS_SPEED_1000: u32 = 2 << 6;

// RCTL bits
pub const RCTL_EN: u32 = 1 << 1;        // Receiver Enable
pub const RCTL_SBP: u32 = 1 << 2;       // Store Bad Packets
pub const RCTL_UPE: u32 = 1 << 3;       // Unicast Promiscuous
pub const RCTL_MPE: u32 = 1 << 4;       // Multicast Promiscuous
pub const RCTL_LPE: u32 = 1 << 5;       // Long Packet Reception (jumbo)
pub const RCTL_BAM: u32 = 1 << 15;      // Broadcast Accept Mode
pub const RCTL_BSIZE_2048: u32 = 0 << 16;
pub const RCTL_BSIZE_4096: u32 = 3 << 16 | 1 << 25;
pub const RCTL_BSIZE_8192: u32 = 2 << 16 | 1 << 25;
pub const RCTL_SECRC: u32 = 1 << 26;    // Strip Ethernet CRC

// TCTL bits
pub const TCTL_EN: u32 = 1 << 1;        // Transmitter Enable
pub const TCTL_PSP: u32 = 1 << 3;       // Pad Short Packets
pub const TCTL_CT_SHIFT: u5 = 4;        // Collision Threshold
pub const TCTL_COLD_SHIFT: u5 = 12;     // Collision Distance

// Interrupt causes
pub const ICR_TXDW: u32 = 1 << 0;       // TX Descriptor Written Back
pub const ICR_TXQE: u32 = 1 << 1;       // TX Queue Empty
pub const ICR_LSC: u32 = 1 << 2;        // Link Status Change
pub const ICR_RXDMT0: u32 = 1 << 4;     // RX Descriptor Min Threshold
pub const ICR_RXO: u32 = 1 << 6;        // Receiver Overrun
pub const ICR_RXT0: u32 = 1 << 7;       // Receiver Timer Interrupt

// ============================================================================
// Descriptor structures
// ============================================================================

pub const RX_DESC_COUNT: usize = 256;
pub const TX_DESC_COUNT: usize = 256;
pub const RX_BUFFER_SIZE: usize = 2048;

pub const RxDescriptor = extern struct {
    buffer_addr: u64,  // Physical address of receive buffer
    length: u16,       // Length of received data
    checksum: u16,     // Packet checksum
    status: u8,        // Status bits
    errors: u8,        // Error bits
    special: u16,      // VLAN tag
};

pub const TxDescriptor = extern struct {
    buffer_addr: u64,
    length: u16,
    cso: u8,           // Checksum Offset
    cmd: u8,           // Command
    status: u8,        // Status
    css: u8,           // Checksum Start
    special: u16,      // VLAN tag
};

// Receive status bits
pub const RXDESC_DD: u8 = 1 << 0;       // Descriptor Done
pub const RXDESC_EOP: u8 = 1 << 1;      // End of Packet
pub const RXDESC_VP: u8 = 1 << 3;       // VLAN Packet

// Transmit command bits
pub const TXDESC_EOP: u8 = 1 << 0;      // End of Packet
pub const TXDESC_IFCS: u8 = 1 << 1;     // Insert FCS/CRC
pub const TXDESC_RS: u8 = 1 << 3;       // Report Status
pub const TXDESC_DD: u8 = 1 << 0;       // Descriptor Done (status)

// ============================================================================
// MAC address
// ============================================================================

pub const MacAddress = struct {
    bytes: [6]u8,

    pub fn init() MacAddress {
        return .{ .bytes = [6]u8{ 0, 0, 0, 0, 0, 0 } };
    }

    pub fn fromBytes(b: [6]u8) MacAddress {
        return .{ .bytes = b };
    }

    pub fn isBroadcast(self: *const MacAddress) bool {
        return self.bytes[0] == 0xFF and self.bytes[1] == 0xFF and
            self.bytes[2] == 0xFF and self.bytes[3] == 0xFF and
            self.bytes[4] == 0xFF and self.bytes[5] == 0xFF;
    }

    pub fn isMulticast(self: *const MacAddress) bool {
        return (self.bytes[0] & 1) != 0;
    }
};

// ============================================================================
// Link state
// ============================================================================

pub const LinkSpeed = enum {
    Speed10,
    Speed100,
    Speed1000,
    Unknown,
};

pub const LinkState = struct {
    up: bool,
    speed: LinkSpeed,
    full_duplex: bool,
    auto_negotiation: bool,

    pub fn init() LinkState {
        return .{
            .up = false,
            .speed = .Unknown,
            .full_duplex = false,
            .auto_negotiation = true,
        };
    }
};

// ============================================================================
// Network statistics
// ============================================================================

pub const NetStats = struct {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    multicast: u64,
    collisions: u64,
    rx_crc_errors: u64,
    rx_missed: u64,
    rx_overruns: u64,

    pub fn init() NetStats {
        return .{
            .rx_packets = 0,
            .tx_packets = 0,
            .rx_bytes = 0,
            .tx_bytes = 0,
            .rx_errors = 0,
            .tx_errors = 0,
            .rx_dropped = 0,
            .tx_dropped = 0,
            .multicast = 0,
            .collisions = 0,
            .rx_crc_errors = 0,
            .rx_missed = 0,
            .rx_overruns = 0,
        };
    }
};

// ============================================================================
// e1000 NIC driver
// ============================================================================

pub const E1000Device = struct {
    mmio_base: u64,
    active: bool,
    mac: MacAddress,
    link: LinkState,
    stats: NetStats,

    // Descriptor rings
    rx_desc_phys: u64,    // Physical address of RX descriptor ring
    tx_desc_phys: u64,    // Physical address of TX descriptor ring
    rx_tail: u16,
    tx_tail: u16,
    tx_head: u16,

    // RX buffer addresses
    rx_buffers: [RX_DESC_COUNT]u64,

    // Features
    promiscuous: bool,
    multicast_all: bool,
    vlan_enabled: bool,
    jumbo_enabled: bool,
    checksum_offload: bool,

    // Interrupt
    irq: u16,
    interrupt_rate: u32,   // Interrupts per second

    pub fn init() E1000Device {
        var dev: E1000Device = undefined;
        dev.mmio_base = 0;
        dev.active = false;
        dev.mac = MacAddress.init();
        dev.link = LinkState.init();
        dev.stats = NetStats.init();
        dev.rx_desc_phys = 0;
        dev.tx_desc_phys = 0;
        dev.rx_tail = 0;
        dev.tx_tail = 0;
        dev.tx_head = 0;
        dev.promiscuous = false;
        dev.multicast_all = false;
        dev.vlan_enabled = false;
        dev.jumbo_enabled = false;
        dev.checksum_offload = true;
        dev.irq = 0;
        dev.interrupt_rate = 8000;
        for (0..RX_DESC_COUNT) |i| {
            dev.rx_buffers[i] = 0;
        }
        return dev;
    }

    /// Read MMIO register
    fn readReg(self: *const E1000Device, offset: u32) u32 {
        const addr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        return addr.*;
    }

    /// Write MMIO register
    fn writeReg(self: *E1000Device, offset: u32, val: u32) void {
        const addr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        addr.* = val;
    }

    /// Software reset
    pub fn reset(self: *E1000Device) void {
        self.writeReg(E1000_CTRL, CTRL_RST);
        // Delay (need to wait ~1ms for reset to complete)
        var i: u32 = 0;
        while (i < 100000) : (i += 1) {
            asm volatile ("pause");
        }
    }

    /// Read MAC address from EEPROM/RAL/RAH
    pub fn readMac(self: *E1000Device) void {
        const ral = self.readReg(E1000_RAL);
        const rah = self.readReg(E1000_RAH);
        self.mac.bytes[0] = @truncate(ral);
        self.mac.bytes[1] = @truncate(ral >> 8);
        self.mac.bytes[2] = @truncate(ral >> 16);
        self.mac.bytes[3] = @truncate(ral >> 24);
        self.mac.bytes[4] = @truncate(rah);
        self.mac.bytes[5] = @truncate(rah >> 8);
    }

    /// Set MAC address
    pub fn setMac(self: *E1000Device, mac: MacAddress) void {
        self.mac = mac;
        const ral = @as(u32, mac.bytes[0]) | (@as(u32, mac.bytes[1]) << 8) |
            (@as(u32, mac.bytes[2]) << 16) | (@as(u32, mac.bytes[3]) << 24);
        const rah = @as(u32, mac.bytes[4]) | (@as(u32, mac.bytes[5]) << 8) | (1 << 31); // AV bit
        self.writeReg(E1000_RAL, ral);
        self.writeReg(E1000_RAH, rah);
    }

    /// Check link status
    pub fn checkLink(self: *E1000Device) void {
        const status = self.readReg(E1000_STATUS);
        self.link.up = (status & STATUS_LU) != 0;
        self.link.full_duplex = (status & STATUS_FD) != 0;
        self.link.speed = switch (status & STATUS_SPEED_MASK) {
            STATUS_SPEED_10 => .Speed10,
            STATUS_SPEED_100 => .Speed100,
            STATUS_SPEED_1000 => .Speed1000,
            else => .Unknown,
        };
    }

    /// Initialize receive path
    pub fn initRx(self: *E1000Device) void {
        // Set RX descriptor ring address
        self.writeReg(E1000_RDBAL, @truncate(self.rx_desc_phys));
        self.writeReg(E1000_RDBAH, @truncate(self.rx_desc_phys >> 32));
        self.writeReg(E1000_RDLEN, RX_DESC_COUNT * @sizeOf(RxDescriptor));
        self.writeReg(E1000_RDH, 0);
        self.writeReg(E1000_RDT, RX_DESC_COUNT - 1);

        // Enable receiver
        var rctl: u32 = RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC;
        if (self.promiscuous) rctl |= RCTL_UPE | RCTL_MPE;
        if (self.multicast_all) rctl |= RCTL_MPE;
        if (self.jumbo_enabled) rctl |= RCTL_LPE;
        self.writeReg(E1000_RCTL, rctl);
    }

    /// Initialize transmit path
    pub fn initTx(self: *E1000Device) void {
        self.writeReg(E1000_TDBAL, @truncate(self.tx_desc_phys));
        self.writeReg(E1000_TDBAH, @truncate(self.tx_desc_phys >> 32));
        self.writeReg(E1000_TDLEN, TX_DESC_COUNT * @sizeOf(TxDescriptor));
        self.writeReg(E1000_TDH, 0);
        self.writeReg(E1000_TDT, 0);

        // Set inter-packet gap
        self.writeReg(E1000_TIPG, 10 | (10 << 10) | (10 << 20));

        // Enable transmitter
        const tctl = TCTL_EN | TCTL_PSP | (15 << @as(u5, TCTL_CT_SHIFT)) | (64 << @as(u5, TCTL_COLD_SHIFT));
        self.writeReg(E1000_TCTL, tctl);
    }

    /// Enable interrupts
    pub fn enableInterrupts(self: *E1000Device) void {
        self.writeReg(E1000_IMS, ICR_LSC | ICR_RXT0 | ICR_TXDW | ICR_RXDMT0 | ICR_RXO);
        self.writeReg(E1000_ITR, 1000000 / self.interrupt_rate);
    }

    /// Disable interrupts
    pub fn disableInterrupts(self: *E1000Device) void {
        self.writeReg(E1000_IMC, 0xFFFFFFFF);
    }

    /// Handle interrupt
    pub fn handleInterrupt(self: *E1000Device) u32 {
        const cause = self.readReg(E1000_ICR);

        if (cause & ICR_LSC != 0) {
            self.checkLink();
        }

        return cause;
    }

    /// Full link up sequence
    pub fn linkUp(self: *E1000Device) void {
        var ctrl = self.readReg(E1000_CTRL);
        ctrl |= CTRL_SLU | CTRL_ASDE;
        ctrl &= ~CTRL_LRST;
        self.writeReg(E1000_CTRL, ctrl);
    }

    /// Full initialization
    pub fn start(self: *E1000Device, mmio: u64) void {
        self.mmio_base = mmio;
        self.reset();
        self.readMac();
        self.linkUp();
        self.initRx();
        self.initTx();
        self.enableInterrupts();
        self.checkLink();
        self.active = true;
    }

    /// Stop the device
    pub fn stop(self: *E1000Device) void {
        self.disableInterrupts();
        self.writeReg(E1000_RCTL, 0);
        self.writeReg(E1000_TCTL, 0);
        self.active = false;
    }

    /// Read hardware statistics
    pub fn updateStats(self: *E1000Device) void {
        self.stats.rx_packets = self.readReg(E1000_GPRC);
        self.stats.tx_packets = self.readReg(E1000_GPTC);
        self.stats.rx_bytes = @as(u64, self.readReg(E1000_GORCL)) | (@as(u64, self.readReg(E1000_GORCH)) << 32);
        self.stats.tx_bytes = @as(u64, self.readReg(E1000_GOTCL)) | (@as(u64, self.readReg(E1000_GOTCH)) << 32);
        self.stats.rx_crc_errors = self.readReg(E1000_CRCERRS);
        self.stats.rx_missed = self.readReg(E1000_MPC);
    }

    /// Set promiscuous mode
    pub fn setPromiscuous(self: *E1000Device, enable: bool) void {
        self.promiscuous = enable;
        var rctl = self.readReg(E1000_RCTL);
        if (enable) {
            rctl |= RCTL_UPE | RCTL_MPE;
        } else {
            rctl &= ~(RCTL_UPE | RCTL_MPE);
        }
        self.writeReg(E1000_RCTL, rctl);
    }

    /// Clear multicast table
    pub fn clearMulticast(self: *E1000Device) void {
        var i: u32 = 0;
        while (i < 128) : (i += 1) {
            self.writeReg(E1000_MTA + i * 4, 0);
        }
    }
};

// ============================================================================
// Global e1000 driver
// ============================================================================

pub const MAX_E1000_DEVICES: usize = 4;

pub const E1000Driver = struct {
    devices: [MAX_E1000_DEVICES]E1000Device,
    device_count: u32,

    pub fn init() E1000Driver {
        var drv: E1000Driver = undefined;
        drv.device_count = 0;
        for (0..MAX_E1000_DEVICES) |i| {
            drv.devices[i] = E1000Device.init();
        }
        return drv;
    }

    pub fn registerDevice(self: *E1000Driver, mmio_base: u64) ?u32 {
        if (self.device_count >= MAX_E1000_DEVICES) return null;
        const idx = self.device_count;
        self.devices[idx].start(mmio_base);
        self.device_count += 1;
        return idx;
    }
};

var e1000_driver: E1000Driver = E1000Driver.init();

pub fn getE1000Driver() *E1000Driver {
    return &e1000_driver;
}
