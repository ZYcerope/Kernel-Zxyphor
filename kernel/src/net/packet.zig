// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Raw/Packet Socket & AF_PACKET (Zig)
//
// Raw socket and packet-level network access:
// - AF_PACKET sockets for link-layer capture/inject
// - SOCK_RAW for IP-layer raw access
// - BPF-style packet filter (classic BPF instruction set)
// - Ring buffer for zero-copy packet reception (TPACKET_V2/V3-like)
// - Promiscuous mode support
// - Packet fanout for multi-socket load balancing
// - TX ring for efficient packet injection
// - Packet timestamps and metadata
// - Socket statistics (rx/tx packets, drops)
// - Protocol type binding (ETH_P_ALL, ETH_P_IP, etc.)

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_RAW_SOCKETS: usize = 32;
const MAX_BPF_INSNS: usize = 64;
const RX_RING_SIZE: usize = 64;
const TX_RING_SIZE: usize = 32;
const PKT_DATA_MAX: usize = 1518; // Ethernet MTU + header
const MAX_FANOUT_GROUPS: usize = 8;
const FANOUT_GROUP_MAX: usize = 8;

// ─────────────────── Ethernet Types ─────────────────────────────────

pub const EthType = enum(u16) {
    ip = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    lldp = 0x88CC,
    all = 0x0003, // ETH_P_ALL
    loop_ = 0x0060,
};

// ─────────────────── Packet Direction ───────────────────────────────

pub const PktType = enum(u8) {
    host = 0,      // Addressed to us
    broadcast = 1,
    multicast = 2,
    otherhost = 3, // Promiscuous capture
    outgoing = 4,
    loopback = 5,
};

// ─────────────────── sockaddr_ll ────────────────────────────────────

pub const SockaddrLL = struct {
    sll_family: u16,     // AF_PACKET (17)
    sll_protocol: u16,   // Network byte order
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: PktType,
    sll_halen: u8,
    sll_addr: [8]u8,     // Physical-layer address

    pub fn init() SockaddrLL {
        return .{
            .sll_family = 17, // AF_PACKET
            .sll_protocol = 0,
            .sll_ifindex = 0,
            .sll_hatype = 1, // ARPHRD_ETHER
            .sll_pkttype = .host,
            .sll_halen = 6,
            .sll_addr = [_]u8{0} ** 8,
        };
    }
};

// ─────────────────── Packet Metadata ────────────────────────────────

pub const PktMeta = struct {
    timestamp: u64,    // Capture timestamp (ticks)
    len: u16,          // Original packet length
    caplen: u16,       // Captured length
    ifindex: i32,
    pkt_type: PktType,
    eth_proto: u16,
    vlan_id: u16,
    vlan_present: bool,
    hash: u32,         // Packet hash for fanout
    mark: u32,

    pub fn init() PktMeta {
        return .{
            .timestamp = 0,
            .len = 0,
            .caplen = 0,
            .ifindex = 0,
            .pkt_type = .host,
            .eth_proto = 0,
            .vlan_id = 0,
            .vlan_present = false,
            .hash = 0,
            .mark = 0,
        };
    }
};

// ─────────────────── Ring Buffer Entry ──────────────────────────────

pub const RingSlot = struct {
    meta: PktMeta,
    data: [PKT_DATA_MAX]u8,
    occupied: bool,

    pub fn init() RingSlot {
        return .{
            .meta = PktMeta.init(),
            .data = [_]u8{0} ** PKT_DATA_MAX,
            .occupied = false,
        };
    }
};

// ─────────────────── BPF Instruction ────────────────────────────────

pub const BpfClass = enum(u3) {
    ld = 0,   // Load
    ldx = 1,  // Load index
    st = 2,   // Store
    stx = 3,  // Store index
    alu = 4,  // ALU
    jmp = 5,  // Jump
    ret = 6,  // Return
    misc = 7,
};

pub const BpfInsn = struct {
    code: u16,
    jt: u8,  // Jump if true
    jf: u8,  // Jump if false
    k: u32,  // Constant

    pub fn ret_accept() BpfInsn {
        return .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0xFFFFFFFF };
    }

    pub fn ret_drop() BpfInsn {
        return .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0 };
    }

    pub fn ld_abs(off: u32) BpfInsn {
        return .{ .code = 0x20, .jt = 0, .jf = 0, .k = off };
    }

    pub fn ld_half_abs(off: u32) BpfInsn {
        return .{ .code = 0x28, .jt = 0, .jf = 0, .k = off };
    }

    pub fn jmp_eq(val: u32, jt: u8, jf: u8) BpfInsn {
        return .{ .code = 0x15, .jt = jt, .jf = jf, .k = val };
    }
};

pub const BpfFilter = struct {
    insns: [MAX_BPF_INSNS]BpfInsn,
    len: u8,
    active: bool,

    pub fn init() BpfFilter {
        return .{
            .insns = undefined,
            .len = 0,
            .active = false,
        };
    }

    /// Run the BPF program on a packet, return bytes to accept (0 = drop)
    pub fn run(self: *const BpfFilter, data: []const u8) u32 {
        if (!self.active or self.len == 0) return @as(u32, @intCast(data.len));

        var a: u32 = 0; // Accumulator
        var x: u32 = 0; // Index register
        var pc: u8 = 0;
        _ = x;

        while (pc < self.len) {
            const insn = self.insns[pc];
            const class = insn.code & 0x07;

            switch (class) {
                0x00 => { // LD
                    const mode = insn.code & 0xe0;
                    if (mode == 0x20) { // ABS word
                        const off = insn.k;
                        if (off + 4 <= data.len) {
                            a = @as(u32, data[off]) << 24 |
                                @as(u32, data[off + 1]) << 16 |
                                @as(u32, data[off + 2]) << 8 |
                                @as(u32, data[off + 3]);
                        } else return 0;
                    } else if (mode == 0x28) { // ABS half
                        const off = insn.k;
                        if (off + 2 <= data.len) {
                            a = @as(u32, data[off]) << 8 | @as(u32, data[off + 1]);
                        } else return 0;
                    }
                    pc += 1;
                },
                0x05 => { // JMP
                    const op = insn.code & 0xf0;
                    if (op == 0x15) { // JEQ
                        if (a == insn.k) {
                            pc += 1 + insn.jt;
                        } else {
                            pc += 1 + insn.jf;
                        }
                    } else if (op == 0x25) { // JGT
                        if (a > insn.k) {
                            pc += 1 + insn.jt;
                        } else {
                            pc += 1 + insn.jf;
                        }
                    } else if (op == 0x35) { // JGE
                        if (a >= insn.k) {
                            pc += 1 + insn.jt;
                        } else {
                            pc += 1 + insn.jf;
                        }
                    } else {
                        pc += 1; // Unconditional
                    }
                },
                0x06 => { // RET
                    return insn.k;
                },
                else => {
                    pc += 1;
                },
            }
        }
        return 0; // Fell off end
    }
};

// ─────────────────── Fanout ─────────────────────────────────────────

pub const FanoutMode = enum(u8) {
    hash = 0,
    lb = 1,       // Round-robin
    cpu = 2,      // Based on CPU
    rollover = 3, // Fallback when socket full
    random = 4,
    qm = 5,       // Queue mapping
};

pub const FanoutGroup = struct {
    id: u16,
    mode: FanoutMode,
    members: [FANOUT_GROUP_MAX]i8, // Socket indices
    member_count: u8,
    next_lb: u8, // For round-robin
    active: bool,

    pub fn init() FanoutGroup {
        return .{
            .id = 0,
            .mode = .hash,
            .members = [_]i8{-1} ** FANOUT_GROUP_MAX,
            .member_count = 0,
            .next_lb = 0,
            .active = false,
        };
    }

    /// Select socket based on fanout mode and packet hash
    pub fn select_socket(self: *FanoutGroup, pkt_hash: u32) ?i8 {
        if (self.member_count == 0) return null;
        const idx = switch (self.mode) {
            .hash => pkt_hash % self.member_count,
            .lb => blk: {
                const i = self.next_lb;
                self.next_lb = @intCast((@as(u16, self.next_lb) + 1) % self.member_count);
                break :blk i;
            },
            .random => @intCast(pkt_hash % self.member_count),
            else => 0,
        };
        return self.members[idx];
    }
};

// ─────────────────── Raw/Packet Socket ──────────────────────────────

pub const SockFlags = packed struct {
    promiscuous: bool = false,
    timestamp: bool = false,
    auxdata: bool = false,  // Attach ancillary data
    origdev: bool = false,  // Record original device
    qdisc_bypass: bool = false,
    _pad: u3 = 0,
};

pub const RawSocket = struct {
    id: u32,
    addr: SockaddrLL,
    bound: bool,
    protocol: u16,       // Bound protocol filter
    ifindex: i32,        // Bound interface (-1 = all)
    flags: SockFlags,

    // BPF filter
    filter: BpfFilter,

    // RX ring
    rx_ring: [RX_RING_SIZE]RingSlot,
    rx_head: u16,
    rx_tail: u16,
    rx_count: u16,

    // TX ring
    tx_ring: [TX_RING_SIZE]RingSlot,
    tx_head: u16,
    tx_tail: u16,
    tx_count: u16,

    // Fanout
    fanout_group: i8,

    // Stats
    rx_packets: u64,
    rx_bytes: u64,
    rx_drops: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_errors: u64,

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var s: Self = undefined;
        s.id = 0;
        s.addr = SockaddrLL.init();
        s.bound = false;
        s.protocol = 0;
        s.ifindex = -1;
        s.flags = .{};
        s.filter = BpfFilter.init();
        for (0..RX_RING_SIZE) |i| s.rx_ring[i] = RingSlot.init();
        s.rx_head = 0;
        s.rx_tail = 0;
        s.rx_count = 0;
        for (0..TX_RING_SIZE) |i| s.tx_ring[i] = RingSlot.init();
        s.tx_head = 0;
        s.tx_tail = 0;
        s.tx_count = 0;
        s.fanout_group = -1;
        s.rx_packets = 0;
        s.rx_bytes = 0;
        s.rx_drops = 0;
        s.tx_packets = 0;
        s.tx_bytes = 0;
        s.tx_errors = 0;
        s.active = false;
        return s;
    }

    pub fn rx_enqueue(self: *Self, meta: PktMeta, data: []const u8) bool {
        if (self.rx_count >= RX_RING_SIZE) {
            self.rx_drops += 1;
            return false;
        }

        // Run BPF filter
        if (self.filter.active) {
            const accept = self.filter.run(data);
            if (accept == 0) return false;
        }

        const slot = &self.rx_ring[self.rx_head];
        slot.meta = meta;
        const caplen = @min(data.len, PKT_DATA_MAX);
        @memcpy(slot.data[0..caplen], data[0..caplen]);
        slot.meta.caplen = @intCast(caplen);
        slot.occupied = true;
        self.rx_head = @intCast((@as(u32, self.rx_head) + 1) % RX_RING_SIZE);
        self.rx_count += 1;
        self.rx_packets += 1;
        self.rx_bytes += @as(u64, meta.len);
        return true;
    }

    pub fn rx_dequeue(self: *Self) ?*RingSlot {
        if (self.rx_count == 0) return null;
        const slot = &self.rx_ring[self.rx_tail];
        if (!slot.occupied) return null;
        slot.occupied = false;
        self.rx_tail = @intCast((@as(u32, self.rx_tail) + 1) % RX_RING_SIZE);
        self.rx_count -= 1;
        return slot;
    }

    pub fn tx_enqueue(self: *Self, data: []const u8) bool {
        if (self.tx_count >= TX_RING_SIZE) {
            self.tx_errors += 1;
            return false;
        }
        const slot = &self.tx_ring[self.tx_head];
        const len = @min(data.len, PKT_DATA_MAX);
        @memcpy(slot.data[0..len], data[0..len]);
        slot.meta.len = @intCast(len);
        slot.meta.caplen = @intCast(len);
        slot.occupied = true;
        self.tx_head = @intCast((@as(u32, self.tx_head) + 1) % TX_RING_SIZE);
        self.tx_count += 1;
        self.tx_packets += 1;
        self.tx_bytes += @as(u64, len);
        return true;
    }

    pub fn tx_dequeue(self: *Self) ?*RingSlot {
        if (self.tx_count == 0) return null;
        const slot = &self.tx_ring[self.tx_tail];
        if (!slot.occupied) return null;
        slot.occupied = false;
        self.tx_tail = @intCast((@as(u32, self.tx_tail) + 1) % TX_RING_SIZE);
        self.tx_count -= 1;
        return slot;
    }
};

// ─────────────────── Packet Socket Manager ──────────────────────────

pub const PacketSocketManager = struct {
    sockets: [MAX_RAW_SOCKETS]RawSocket,
    fanout_groups: [MAX_FANOUT_GROUPS]FanoutGroup,
    sock_count: u8,
    next_id: u32,
    next_fanout_id: u16,
    tick: u64,

    // Global stats
    total_delivered: u64,
    total_injected: u64,
    total_filter_drops: u64,
    total_ring_drops: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var pm: Self = undefined;
        for (0..MAX_RAW_SOCKETS) |i| pm.sockets[i] = RawSocket.init();
        for (0..MAX_FANOUT_GROUPS) |i| pm.fanout_groups[i] = FanoutGroup.init();
        pm.sock_count = 0;
        pm.next_id = 1;
        pm.next_fanout_id = 1;
        pm.tick = 0;
        pm.total_delivered = 0;
        pm.total_injected = 0;
        pm.total_filter_drops = 0;
        pm.total_ring_drops = 0;
        pm.initialized = true;
        return pm;
    }

    pub fn create_socket(self: *Self, protocol: u16) ?u8 {
        for (0..MAX_RAW_SOCKETS) |i| {
            if (!self.sockets[i].active) {
                self.sockets[i] = RawSocket.init();
                self.sockets[i].id = self.next_id;
                self.sockets[i].protocol = protocol;
                self.sockets[i].active = true;
                self.next_id += 1;
                self.sock_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn close_socket(self: *Self, idx: u8) bool {
        if (idx >= MAX_RAW_SOCKETS or !self.sockets[idx].active) return false;

        // Remove from fanout group
        if (self.sockets[idx].fanout_group >= 0) {
            const fg = @as(usize, @intCast(self.sockets[idx].fanout_group));
            if (fg < MAX_FANOUT_GROUPS) {
                self.leave_fanout(idx, @intCast(fg));
            }
        }

        self.sockets[idx].active = false;
        self.sock_count -= 1;
        return true;
    }

    pub fn bind_socket(self: *Self, idx: u8, ifindex: i32, protocol: u16) bool {
        if (idx >= MAX_RAW_SOCKETS or !self.sockets[idx].active) return false;
        self.sockets[idx].ifindex = ifindex;
        self.sockets[idx].protocol = protocol;
        self.sockets[idx].addr.sll_ifindex = ifindex;
        self.sockets[idx].addr.sll_protocol = protocol;
        self.sockets[idx].bound = true;
        return true;
    }

    pub fn set_promiscuous(self: *Self, idx: u8, enable: bool) bool {
        if (idx >= MAX_RAW_SOCKETS or !self.sockets[idx].active) return false;
        self.sockets[idx].flags.promiscuous = enable;
        return true;
    }

    pub fn attach_filter(self: *Self, idx: u8, insns: []const BpfInsn) bool {
        if (idx >= MAX_RAW_SOCKETS or !self.sockets[idx].active) return false;
        const len = @min(insns.len, MAX_BPF_INSNS);
        for (0..len) |i| {
            self.sockets[idx].filter.insns[i] = insns[i];
        }
        self.sockets[idx].filter.len = @intCast(len);
        self.sockets[idx].filter.active = true;
        return true;
    }

    pub fn detach_filter(self: *Self, idx: u8) bool {
        if (idx >= MAX_RAW_SOCKETS or !self.sockets[idx].active) return false;
        self.sockets[idx].filter.active = false;
        self.sockets[idx].filter.len = 0;
        return true;
    }

    // ─── Fanout ─────────────────────────────────────────────────────

    pub fn create_fanout(self: *Self, mode: FanoutMode) ?u8 {
        for (0..MAX_FANOUT_GROUPS) |i| {
            if (!self.fanout_groups[i].active) {
                self.fanout_groups[i] = FanoutGroup.init();
                self.fanout_groups[i].id = self.next_fanout_id;
                self.fanout_groups[i].mode = mode;
                self.fanout_groups[i].active = true;
                self.next_fanout_id += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn join_fanout(self: *Self, sock_idx: u8, group_idx: u8) bool {
        if (sock_idx >= MAX_RAW_SOCKETS or !self.sockets[sock_idx].active) return false;
        if (group_idx >= MAX_FANOUT_GROUPS or !self.fanout_groups[group_idx].active) return false;
        if (self.fanout_groups[group_idx].member_count >= FANOUT_GROUP_MAX) return false;

        const mc = self.fanout_groups[group_idx].member_count;
        self.fanout_groups[group_idx].members[mc] = @intCast(sock_idx);
        self.fanout_groups[group_idx].member_count += 1;
        self.sockets[sock_idx].fanout_group = @intCast(group_idx);
        return true;
    }

    pub fn leave_fanout(self: *Self, sock_idx: u8, group_idx: u8) void {
        if (group_idx >= MAX_FANOUT_GROUPS) return;
        const fg = &self.fanout_groups[group_idx];
        var i: u8 = 0;
        while (i < fg.member_count) : (i += 1) {
            if (fg.members[i] == @as(i8, @intCast(sock_idx))) {
                fg.members[i] = fg.members[fg.member_count - 1];
                fg.members[fg.member_count - 1] = -1;
                fg.member_count -= 1;
                self.sockets[sock_idx].fanout_group = -1;
                return;
            }
        }
    }

    // ─── Packet Delivery ────────────────────────────────────────────

    pub fn deliver_packet(self: *Self, data: []const u8, ifindex: i32, eth_proto: u16, pkt_type: PktType) u32 {
        var delivered: u32 = 0;
        const meta = PktMeta{
            .timestamp = self.tick,
            .len = @intCast(data.len),
            .caplen = @intCast(@min(data.len, PKT_DATA_MAX)),
            .ifindex = ifindex,
            .pkt_type = pkt_type,
            .eth_proto = eth_proto,
            .vlan_id = 0,
            .vlan_present = false,
            .hash = compute_pkt_hash(data),
            .mark = 0,
        };

        for (0..MAX_RAW_SOCKETS) |i| {
            if (!self.sockets[i].active) continue;

            // Protocol filter
            if (self.sockets[i].protocol != @intFromEnum(EthType.all) and
                self.sockets[i].protocol != eth_proto) continue;

            // Interface filter
            if (self.sockets[i].ifindex >= 0 and self.sockets[i].ifindex != ifindex) continue;

            // Promiscuous check
            if (pkt_type == .otherhost and !self.sockets[i].flags.promiscuous) continue;

            // Check fanout — only deliver to selected member
            if (self.sockets[i].fanout_group >= 0) {
                const fg_idx = @as(usize, @intCast(self.sockets[i].fanout_group));
                if (fg_idx < MAX_FANOUT_GROUPS and self.fanout_groups[fg_idx].active) {
                    const selected = self.fanout_groups[fg_idx].select_socket(meta.hash);
                    if (selected) |sel| {
                        if (sel != @as(i8, @intCast(i))) continue;
                    }
                }
            }

            if (self.sockets[i].rx_enqueue(meta, data)) {
                delivered += 1;
            } else {
                self.total_ring_drops += 1;
            }
        }
        self.total_delivered += delivered;
        return delivered;
    }

    pub fn inject_packet(self: *Self, sock_idx: u8) ?*RingSlot {
        if (sock_idx >= MAX_RAW_SOCKETS or !self.sockets[sock_idx].active) return null;
        if (self.sockets[sock_idx].tx_dequeue()) |slot| {
            self.total_injected += 1;
            return slot;
        }
        return null;
    }

    pub fn advance_tick(self: *Self) void {
        self.tick += 1;
    }
};

fn compute_pkt_hash(data: []const u8) u32 {
    var h: u32 = 0x811c9dc5; // FNV-1a offset basis
    for (data) |b| {
        h ^= @as(u32, b);
        h *%= 0x01000193; // FNV prime
    }
    return h;
}

// ─────────────────── Global State ───────────────────────────────────

var g_pkt: PacketSocketManager = undefined;
var g_pkt_initialized: bool = false;

fn pm() *PacketSocketManager {
    return &g_pkt;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_packet_init() void {
    g_pkt = PacketSocketManager.init();
    g_pkt_initialized = true;
}

export fn zxy_packet_create(protocol: u16) i8 {
    if (!g_pkt_initialized) return -1;
    if (pm().create_socket(protocol)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_packet_close(idx: u8) bool {
    if (!g_pkt_initialized) return false;
    return pm().close_socket(idx);
}

export fn zxy_packet_bind(idx: u8, ifindex: i32, protocol: u16) bool {
    if (!g_pkt_initialized) return false;
    return pm().bind_socket(idx, ifindex, protocol);
}

export fn zxy_packet_set_promisc(idx: u8, enable: bool) bool {
    if (!g_pkt_initialized) return false;
    return pm().set_promiscuous(idx, enable);
}

export fn zxy_packet_recv(idx: u8, buf: [*]u8, buf_len: usize) i32 {
    if (!g_pkt_initialized) return -1;
    if (idx >= MAX_RAW_SOCKETS or !pm().sockets[idx].active) return -1;
    if (pm().sockets[idx].rx_dequeue()) |slot| {
        const cplen = @min(buf_len, @as(usize, slot.meta.caplen));
        @memcpy(buf[0..cplen], slot.data[0..cplen]);
        return @intCast(cplen);
    }
    return 0; // No data
}

export fn zxy_packet_send(idx: u8, data: [*]const u8, data_len: usize) bool {
    if (!g_pkt_initialized) return false;
    if (idx >= MAX_RAW_SOCKETS or !pm().sockets[idx].active) return false;
    return pm().sockets[idx].tx_enqueue(data[0..data_len]);
}

export fn zxy_packet_sock_count() u8 {
    if (!g_pkt_initialized) return 0;
    return pm().sock_count;
}

export fn zxy_packet_total_delivered() u64 {
    if (!g_pkt_initialized) return 0;
    return pm().total_delivered;
}

export fn zxy_packet_total_injected() u64 {
    if (!g_pkt_initialized) return 0;
    return pm().total_injected;
}

export fn zxy_packet_total_drops() u64 {
    if (!g_pkt_initialized) return 0;
    return pm().total_ring_drops;
}
