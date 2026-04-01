// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Network Loopback, Bridge & Bonding
//
// Virtual network infrastructure:
// - Loopback device (lo) for local traffic
// - Bridge device for L2 switching between interfaces
// - Bonding/link aggregation (mode 0: round-robin, mode 1: active-backup,
//   mode 2: balance-xor, mode 4: 802.3ad LACP)
// - MAC forwarding database (FDB) with learning & aging
// - Spanning Tree Protocol (STP) stub
// - ARP proxy for bridged networks
// - Bridge VLAN filtering
// - Interface statistics tracking

const std = @import("std");

// ─────────────────── MAC Address ────────────────────────────────────
pub const MacAddr = [6]u8;

pub const MAC_BROADCAST: MacAddr = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
pub const MAC_ZERO: MacAddr = .{ 0, 0, 0, 0, 0, 0 };

pub fn macEqual(a: MacAddr, b: MacAddr) bool {
    inline for (0..6) |i| {
        if (a[i] != b[i]) return false;
    }
    return true;
}

pub fn macIsBroadcast(m: MacAddr) bool {
    return macEqual(m, MAC_BROADCAST);
}

pub fn macIsMulticast(m: MacAddr) bool {
    return (m[0] & 0x01) != 0;
}

pub fn macHash(m: MacAddr) u32 {
    var h: u32 = 0x811c9dc5;
    for (m) |b| {
        h ^= @as(u32, b);
        h *%= 0x01000193;
    }
    return h;
}

// ─────────────────── Interface Statistics ───────────────────────────
pub const NetStats = struct {
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    tx_errors: u64 = 0,
    rx_dropped: u64 = 0,
    tx_dropped: u64 = 0,
    multicast: u64 = 0,
    collisions: u64 = 0,

    pub fn reset(self: *NetStats) void {
        self.* = .{};
    }

    pub fn addRx(self: *NetStats, bytes: u64) void {
        self.rx_packets += 1;
        self.rx_bytes += bytes;
    }

    pub fn addTx(self: *NetStats, bytes: u64) void {
        self.tx_packets += 1;
        self.tx_bytes += bytes;
    }
};

// ─────────────────── NetDevice (Virtual Interface) ──────────────────
pub const IF_NAME_MAX: usize = 16;
pub const MAX_NET_DEVICES: usize = 32;
pub const MTU_DEFAULT: u32 = 1500;
pub const MTU_LOOPBACK: u32 = 65536;

pub const DeviceType = enum(u8) {
    loopback,
    ethernet,
    bridge,
    bond,
    veth,
    tap,
};

pub const DeviceFlags = packed struct(u16) {
    up: bool = false,
    broadcast: bool = false,
    loopback: bool = false,
    promisc: bool = false,
    multicast: bool = false,
    noarp: bool = false,
    master: bool = false,
    slave: bool = false,
    _pad: u8 = 0,
};

pub const NetDevice = struct {
    name: [IF_NAME_MAX]u8 = [_]u8{0} ** IF_NAME_MAX,
    name_len: u8 = 0,
    dev_type: DeviceType = .ethernet,
    flags: DeviceFlags = .{},
    mac: MacAddr = MAC_ZERO,
    mtu: u32 = MTU_DEFAULT,
    ifindex: u16 = 0,
    stats: NetStats = .{},
    master_idx: u16 = 0, // bridge/bond master index

    pub fn setName(self: *NetDevice, n: []const u8) void {
        const len = @min(n.len, IF_NAME_MAX - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }

    pub fn getName(self: *const NetDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn isUp(self: *const NetDevice) bool {
        return self.flags.up;
    }

    pub fn setUp(self: *NetDevice) void {
        self.flags.up = true;
    }

    pub fn setDown(self: *NetDevice) void {
        self.flags.up = false;
    }
};

// ─────────────────── Loopback Device ────────────────────────────────
pub const LoopbackDevice = struct {
    dev: NetDevice,
    rx_queue: [64]LoopbackPacket = undefined,
    rx_head: usize = 0,
    rx_tail: usize = 0,
    rx_count: usize = 0,

    pub fn init() LoopbackDevice {
        var lo = LoopbackDevice{
            .dev = .{
                .dev_type = .loopback,
                .flags = .{ .up = true, .loopback = true },
                .mac = .{ 0, 0, 0, 0, 0, 0 },
                .mtu = MTU_LOOPBACK,
                .ifindex = 1,
            },
        };
        lo.dev.setName("lo");
        return lo;
    }

    pub fn transmit(self: *LoopbackDevice, data: []const u8) bool {
        if (!self.dev.isUp()) return false;
        if (self.rx_count >= 64) {
            self.dev.stats.tx_dropped += 1;
            return false;
        }
        const pkt = &self.rx_queue[self.rx_tail];
        const copy_len = @min(data.len, LoopbackPacket.MAX_SIZE);
        @memcpy(pkt.data[0..copy_len], data[0..copy_len]);
        pkt.len = @intCast(copy_len);
        self.rx_tail = (self.rx_tail + 1) % 64;
        self.rx_count += 1;
        self.dev.stats.addTx(copy_len);
        self.dev.stats.addRx(copy_len);
        return true;
    }

    pub fn receive(self: *LoopbackDevice) ?*const LoopbackPacket {
        if (self.rx_count == 0) return null;
        const pkt = &self.rx_queue[self.rx_head];
        self.rx_head = (self.rx_head + 1) % 64;
        self.rx_count -= 1;
        return pkt;
    }
};

pub const LoopbackPacket = struct {
    pub const MAX_SIZE: usize = 65536;
    data: [MAX_SIZE]u8 = undefined,
    len: u32 = 0,
};

// ─────────────────── FDB — Forwarding Database ──────────────────────
pub const MAX_FDB_ENTRIES: usize = 1024;
pub const FDB_AGING_TIME: u64 = 300; // seconds

pub const FdbEntry = struct {
    mac: MacAddr = MAC_ZERO,
    port_idx: u16 = 0,
    vlan_id: u16 = 0,
    timestamp: u64 = 0,
    is_static: bool = false,
    is_local: bool = false,
    valid: bool = false,
};

pub const ForwardingDb = struct {
    entries: [MAX_FDB_ENTRIES]FdbEntry = [_]FdbEntry{.{}} ** MAX_FDB_ENTRIES,
    count: usize = 0,

    pub fn learn(self: *ForwardingDb, mac: MacAddr, port: u16, vlan: u16, timestamp: u64) void {
        // Check for existing entry
        for (&self.entries) |*e| {
            if (e.valid and macEqual(e.mac, mac) and e.vlan_id == vlan) {
                e.port_idx = port;
                e.timestamp = timestamp;
                return;
            }
        }
        // Find free slot
        for (&self.entries) |*e| {
            if (!e.valid) {
                e.* = .{
                    .mac = mac,
                    .port_idx = port,
                    .vlan_id = vlan,
                    .timestamp = timestamp,
                    .is_static = false,
                    .is_local = false,
                    .valid = true,
                };
                self.count += 1;
                return;
            }
        }
    }

    pub fn lookup(self: *const ForwardingDb, mac: MacAddr, vlan: u16) ?u16 {
        for (self.entries) |e| {
            if (e.valid and macEqual(e.mac, mac) and e.vlan_id == vlan) {
                return e.port_idx;
            }
        }
        return null;
    }

    pub fn addStatic(self: *ForwardingDb, mac: MacAddr, port: u16, vlan: u16) void {
        for (&self.entries) |*e| {
            if (!e.valid) {
                e.* = .{
                    .mac = mac,
                    .port_idx = port,
                    .vlan_id = vlan,
                    .timestamp = 0,
                    .is_static = true,
                    .is_local = false,
                    .valid = true,
                };
                self.count += 1;
                return;
            }
        }
    }

    pub fn remove(self: *ForwardingDb, mac: MacAddr, vlan: u16) bool {
        for (&self.entries) |*e| {
            if (e.valid and macEqual(e.mac, mac) and e.vlan_id == vlan) {
                e.valid = false;
                self.count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn age(self: *ForwardingDb, now: u64) u32 {
        var aged: u32 = 0;
        for (&self.entries) |*e| {
            if (e.valid and !e.is_static and (now - e.timestamp) > FDB_AGING_TIME) {
                e.valid = false;
                self.count -= 1;
                aged += 1;
            }
        }
        return aged;
    }

    pub fn flush(self: *ForwardingDb, port: u16) void {
        for (&self.entries) |*e| {
            if (e.valid and e.port_idx == port and !e.is_static) {
                e.valid = false;
                self.count -= 1;
            }
        }
    }
};

// ─────────────────── STP — Spanning Tree Protocol ───────────────────
pub const StpState = enum(u8) {
    disabled,
    blocking,
    listening,
    learning,
    forwarding,
};

pub const StpPortInfo = struct {
    port_idx: u16 = 0,
    state: StpState = .disabled,
    path_cost: u32 = 100,
    priority: u16 = 128,
    designated_root: u64 = 0,
    designated_cost: u32 = 0,
    designated_bridge: u64 = 0,
    forward_delay_timer: u32 = 0,
    hold_timer: u32 = 0,
    valid: bool = false,

    pub fn isForwarding(self: *const StpPortInfo) bool {
        return self.state == .forwarding;
    }

    pub fn isLearning(self: *const StpPortInfo) bool {
        return self.state == .learning or self.state == .forwarding;
    }

    pub fn transitionForward(self: *StpPortInfo) void {
        self.state = switch (self.state) {
            .disabled => .blocking,
            .blocking => .listening,
            .listening => .learning,
            .learning => .forwarding,
            .forwarding => .forwarding,
        };
    }
};

// ─────────────────── Bridge Device ──────────────────────────────────
pub const MAX_BRIDGE_PORTS: usize = 16;
pub const MAX_VLANS: usize = 64;

pub const BridgeVlan = struct {
    vlan_id: u16 = 0,
    port_mask: u16 = 0, // bitmask of member ports
    untag_mask: u16 = 0, // ports that untag on egress
    valid: bool = false,
};

pub const BridgeDevice = struct {
    dev: NetDevice,
    ports: [MAX_BRIDGE_PORTS]u16 = [_]u16{0} ** MAX_BRIDGE_PORTS, // ifindex of member ports
    port_count: u8 = 0,
    fdb: ForwardingDb = .{},
    stp_ports: [MAX_BRIDGE_PORTS]StpPortInfo = [_]StpPortInfo{.{}} ** MAX_BRIDGE_PORTS,
    stp_enabled: bool = false,
    vlans: [MAX_VLANS]BridgeVlan = [_]BridgeVlan{.{}} ** MAX_VLANS,
    vlan_count: u8 = 0,
    vlan_filtering: bool = false,
    bridge_id: u64 = 0,
    root_id: u64 = 0,
    root_path_cost: u32 = 0,
    ageing_time: u64 = FDB_AGING_TIME,

    pub fn init(ifindex: u16, mac: MacAddr) BridgeDevice {
        var br = BridgeDevice{
            .dev = .{
                .dev_type = .bridge,
                .flags = .{ .up = true, .broadcast = true, .multicast = true, .master = true },
                .mac = mac,
                .ifindex = ifindex,
            },
        };
        br.dev.setName("br0");
        // Bridge ID: priority (2 bytes) + MAC (6 bytes)
        br.bridge_id = (@as(u64, 0x8000) << 48) |
            (@as(u64, mac[0]) << 40) |
            (@as(u64, mac[1]) << 32) |
            (@as(u64, mac[2]) << 24) |
            (@as(u64, mac[3]) << 16) |
            (@as(u64, mac[4]) << 8) |
            @as(u64, mac[5]);
        br.root_id = br.bridge_id;
        return br;
    }

    pub fn addPort(self: *BridgeDevice, ifindex: u16) bool {
        if (self.port_count >= MAX_BRIDGE_PORTS) return false;
        // Check not already added
        for (self.ports[0..self.port_count]) |p| {
            if (p == ifindex) return false;
        }
        const idx = self.port_count;
        self.ports[idx] = ifindex;
        self.stp_ports[idx] = .{
            .port_idx = ifindex,
            .state = if (self.stp_enabled) .blocking else .forwarding,
            .valid = true,
        };
        self.port_count += 1;
        return true;
    }

    pub fn removePort(self: *BridgeDevice, ifindex: u16) bool {
        for (0..self.port_count) |i| {
            if (self.ports[i] == ifindex) {
                self.fdb.flush(ifindex);
                // Shift remaining
                var j = i;
                while (j + 1 < self.port_count) : (j += 1) {
                    self.ports[j] = self.ports[j + 1];
                    self.stp_ports[j] = self.stp_ports[j + 1];
                }
                self.port_count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn addVlan(self: *BridgeDevice, vlan_id: u16) bool {
        if (self.vlan_count >= MAX_VLANS) return false;
        for (&self.vlans) |*v| {
            if (v.valid and v.vlan_id == vlan_id) return false;
        }
        for (&self.vlans) |*v| {
            if (!v.valid) {
                v.* = .{ .vlan_id = vlan_id, .valid = true };
                self.vlan_count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn addPortToVlan(self: *BridgeDevice, vlan_id: u16, port_bit: u16, untagged: bool) bool {
        for (&self.vlans) |*v| {
            if (v.valid and v.vlan_id == vlan_id) {
                v.port_mask |= port_bit;
                if (untagged) {
                    v.untag_mask |= port_bit;
                }
                return true;
            }
        }
        return false;
    }

    /// Forward a frame: learn source MAC, lookup dest, flood if unknown
    pub fn forward(self: *BridgeDevice, src_mac: MacAddr, dst_mac: MacAddr, src_port: u16, vlan_id: u16, data_len: u64, timestamp: u64) ForwardResult {
        // Learn source MAC
        self.fdb.learn(src_mac, src_port, vlan_id, timestamp);

        // VLAN filtering
        if (self.vlan_filtering) {
            var vlan_ok = false;
            for (self.vlans) |v| {
                if (v.valid and v.vlan_id == vlan_id) {
                    vlan_ok = true;
                    break;
                }
            }
            if (!vlan_ok) return .{ .action = .drop };
        }

        // Lookup destination
        if (macIsBroadcast(dst_mac) or macIsMulticast(dst_mac)) {
            self.dev.stats.multicast += 1;
            return .{ .action = .flood, .exclude_port = src_port };
        }

        if (self.fdb.lookup(dst_mac, vlan_id)) |port| {
            if (port == src_port) {
                return .{ .action = .drop }; // Same port, drop
            }
            // Check STP state
            for (self.stp_ports[0..self.port_count]) |sp| {
                if (sp.port_idx == port and !sp.isForwarding()) {
                    return .{ .action = .drop };
                }
            }
            self.dev.stats.addTx(data_len);
            return .{ .action = .unicast, .dest_port = port };
        }

        // Unknown unicast → flood
        return .{ .action = .flood, .exclude_port = src_port };
    }
};

pub const ForwardAction = enum(u8) {
    drop,
    unicast,
    flood,
    local,
};

pub const ForwardResult = struct {
    action: ForwardAction = .drop,
    dest_port: u16 = 0,
    exclude_port: u16 = 0,
};

// ─────────────────── Bonding Device ─────────────────────────────────
pub const MAX_BOND_SLAVES: usize = 8;

pub const BondMode = enum(u8) {
    round_robin = 0,        // mode 0
    active_backup = 1,      // mode 1
    balance_xor = 2,        // mode 2
    broadcast = 3,          // mode 3
    lacp_802_3ad = 4,       // mode 4
    balance_tlb = 5,        // mode 5
    balance_alb = 6,        // mode 6
};

pub const BondSlaveState = enum(u8) {
    active,
    backup,
    down,
};

pub const BondSlave = struct {
    ifindex: u16 = 0,
    mac: MacAddr = MAC_ZERO,
    state: BondSlaveState = .backup,
    link_up: bool = false,
    tx_count: u64 = 0,
    rx_count: u64 = 0,
    link_fail_count: u32 = 0,
    valid: bool = false,
};

pub const LacpInfo = struct {
    system_priority: u16 = 0x8000,
    system_mac: MacAddr = MAC_ZERO,
    key: u16 = 0,
    port_priority: u16 = 0xFF,
    port_number: u16 = 0,
    state: u8 = 0,

    // LACP state bits
    pub const LACP_ACTIVE: u8 = 0x01;
    pub const LACP_SHORT_TIMEOUT: u8 = 0x02;
    pub const LACP_AGGREGATING: u8 = 0x04;
    pub const LACP_IN_SYNC: u8 = 0x08;
    pub const LACP_COLLECTING: u8 = 0x10;
    pub const LACP_DISTRIBUTING: u8 = 0x20;
    pub const LACP_DEFAULTED: u8 = 0x40;
    pub const LACP_EXPIRED: u8 = 0x80;
};

pub const BondDevice = struct {
    dev: NetDevice,
    mode: BondMode = .round_robin,
    slaves: [MAX_BOND_SLAVES]BondSlave = [_]BondSlave{.{}} ** MAX_BOND_SLAVES,
    slave_count: u8 = 0,
    active_slave: u8 = 0, // index into slaves
    rr_counter: u32 = 0,  // round-robin counter
    miimon_interval: u32 = 100, // ms
    updelay: u32 = 0,
    downdelay: u32 = 0,
    arp_interval: u32 = 0,
    xmit_hash_policy: XmitHashPolicy = .layer2,
    lacp_rate: u8 = 0, // 0: slow, 1: fast
    lacp_info: [MAX_BOND_SLAVES]LacpInfo = [_]LacpInfo{.{}} ** MAX_BOND_SLAVES,

    pub fn init(ifindex: u16, mac: MacAddr, mode: BondMode) BondDevice {
        var bond = BondDevice{
            .dev = .{
                .dev_type = .bond,
                .flags = .{ .up = true, .broadcast = true, .multicast = true, .master = true },
                .mac = mac,
                .ifindex = ifindex,
            },
            .mode = mode,
        };
        bond.dev.setName("bond0");
        return bond;
    }

    pub fn addSlave(self: *BondDevice, ifindex: u16, mac: MacAddr) bool {
        if (self.slave_count >= MAX_BOND_SLAVES) return false;
        for (self.slaves[0..self.slave_count]) |s| {
            if (s.ifindex == ifindex) return false;
        }
        const idx = self.slave_count;
        self.slaves[idx] = .{
            .ifindex = ifindex,
            .mac = mac,
            .state = if (idx == 0) .active else .backup,
            .link_up = true,
            .valid = true,
        };
        self.slave_count += 1;
        return true;
    }

    pub fn removeSlave(self: *BondDevice, ifindex: u16) bool {
        for (0..self.slave_count) |i| {
            if (self.slaves[i].ifindex == ifindex) {
                var j = i;
                while (j + 1 < self.slave_count) : (j += 1) {
                    self.slaves[j] = self.slaves[j + 1];
                }
                self.slave_count -= 1;
                if (self.active_slave >= self.slave_count and self.slave_count > 0) {
                    self.active_slave = 0;
                }
                return true;
            }
        }
        return false;
    }

    /// Select slave for transmit based on bonding mode
    pub fn selectSlave(self: *BondDevice, src_mac: MacAddr, dst_mac: MacAddr, src_ip: u32, dst_ip: u32) ?u8 {
        if (self.slave_count == 0) return null;

        const idx: u8 = switch (self.mode) {
            .round_robin => blk: {
                const i = @as(u8, @intCast(self.rr_counter % self.slave_count));
                self.rr_counter +%= 1;
                break :blk i;
            },
            .active_backup => self.active_slave,
            .balance_xor => blk: {
                const hash = self.xmitHash(src_mac, dst_mac, src_ip, dst_ip);
                break :blk @intCast(hash % self.slave_count);
            },
            .broadcast => 0xFF, // special: send on all
            .lacp_802_3ad => blk: {
                const hash = self.xmitHash(src_mac, dst_mac, src_ip, dst_ip);
                break :blk @intCast(hash % self.slave_count);
            },
            .balance_tlb, .balance_alb => blk: {
                // Simplified: pick least-loaded slave
                var min_tx: u64 = ~@as(u64, 0);
                var best: u8 = 0;
                for (0..self.slave_count) |si| {
                    if (self.slaves[si].link_up and self.slaves[si].tx_count < min_tx) {
                        min_tx = self.slaves[si].tx_count;
                        best = @intCast(si);
                    }
                }
                break :blk best;
            },
        };

        // For broadcast mode, the caller handles flooding
        if (idx == 0xFF) return null;
        if (idx < self.slave_count and self.slaves[idx].link_up) {
            return idx;
        }
        // Fallback to first active slave
        for (0..self.slave_count) |i| {
            if (self.slaves[i].link_up) return @intCast(i);
        }
        return null;
    }

    fn xmitHash(self: *const BondDevice, src_mac: MacAddr, dst_mac: MacAddr, src_ip: u32, dst_ip: u32) u32 {
        return switch (self.xmit_hash_policy) {
            .layer2 => macHash(src_mac) ^ macHash(dst_mac),
            .layer3_4 => src_ip ^ dst_ip,
            .layer2_3 => macHash(src_mac) ^ macHash(dst_mac) ^ src_ip ^ dst_ip,
        };
    }

    /// Handle link failure detection
    pub fn linkCheck(self: *BondDevice) void {
        switch (self.mode) {
            .active_backup => {
                if (self.active_slave < self.slave_count and !self.slaves[self.active_slave].link_up) {
                    self.slaves[self.active_slave].link_fail_count += 1;
                    // Find a new active slave
                    for (0..self.slave_count) |i| {
                        if (self.slaves[i].link_up and i != self.active_slave) {
                            self.slaves[self.active_slave].state = .down;
                            self.slaves[i].state = .active;
                            self.active_slave = @intCast(i);
                            break;
                        }
                    }
                }
            },
            else => {
                // Mark down slaves as down
                for (0..self.slave_count) |i| {
                    if (!self.slaves[i].link_up) {
                        self.slaves[i].state = .down;
                        self.slaves[i].link_fail_count += 1;
                    }
                }
            },
        }
    }

    pub fn activeSlaveCount(self: *const BondDevice) u8 {
        var count: u8 = 0;
        for (self.slaves[0..self.slave_count]) |s| {
            if (s.link_up) count += 1;
        }
        return count;
    }
};

pub const XmitHashPolicy = enum(u8) {
    layer2,
    layer3_4,
    layer2_3,
};

// ─────────────────── Net Subsystem Registry ─────────────────────────
pub const NetSubsystem = struct {
    devices: [MAX_NET_DEVICES]NetDevice = [_]NetDevice{.{}} ** MAX_NET_DEVICES,
    device_count: u16 = 0,
    loopback: LoopbackDevice = undefined,
    bridge: ?BridgeDevice = null,
    bond: ?BondDevice = null,
    next_ifindex: u16 = 1,
    initialized: bool = false,

    pub fn init(self: *NetSubsystem) void {
        self.loopback = LoopbackDevice.init();
        self.devices[0] = self.loopback.dev;
        self.device_count = 1;
        self.next_ifindex = 2;
        self.initialized = true;
    }

    pub fn createBridge(self: *NetSubsystem, mac: MacAddr) bool {
        if (self.bridge != null) return false;
        self.bridge = BridgeDevice.init(self.next_ifindex, mac);
        if (self.device_count < MAX_NET_DEVICES) {
            self.devices[self.device_count] = self.bridge.?.dev;
            self.device_count += 1;
            self.next_ifindex += 1;
            return true;
        }
        return false;
    }

    pub fn createBond(self: *NetSubsystem, mac: MacAddr, mode: BondMode) bool {
        if (self.bond != null) return false;
        self.bond = BondDevice.init(self.next_ifindex, mac, mode);
        if (self.device_count < MAX_NET_DEVICES) {
            self.devices[self.device_count] = self.bond.?.dev;
            self.device_count += 1;
            self.next_ifindex += 1;
            return true;
        }
        return false;
    }

    pub fn findDevice(self: *const NetSubsystem, ifindex: u16) ?*const NetDevice {
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.ifindex == ifindex) return d;
        }
        return null;
    }

    pub fn findDeviceByName(self: *const NetSubsystem, name: []const u8) ?*const NetDevice {
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.name_len > 0 and d.name_len == name.len) {
                var match_all = true;
                for (0..d.name_len) |i| {
                    if (d.name[i] != name[i]) {
                        match_all = false;
                        break;
                    }
                }
                if (match_all) return d;
            }
        }
        return null;
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var net_subsystem: NetSubsystem = .{};

pub fn initNetSubsystem() void {
    net_subsystem.init();
}

pub fn getNetSubsystem() *NetSubsystem {
    return &net_subsystem;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_net_loopback_init() void {
    initNetSubsystem();
}

export fn zxy_net_loopback_tx(data: [*]const u8, len: u32) bool {
    return net_subsystem.loopback.transmit(data[0..len]);
}

export fn zxy_net_bridge_create() bool {
    return net_subsystem.createBridge(.{ 0x02, 0x42, 0xAC, 0x11, 0x00, 0x01 });
}

export fn zxy_net_bridge_add_port(ifindex: u16) bool {
    if (net_subsystem.bridge) |*br| {
        return br.addPort(ifindex);
    }
    return false;
}

export fn zxy_net_bond_create(mode: u8) bool {
    const bond_mode: BondMode = @enumFromInt(mode);
    return net_subsystem.createBond(.{ 0x02, 0x42, 0xBD, 0x00, 0x00, 0x01 }, bond_mode);
}

export fn zxy_net_device_count() u16 {
    return net_subsystem.device_count;
}

export fn zxy_net_fdb_count() u32 {
    if (net_subsystem.bridge) |br| {
        return @intCast(br.fdb.count);
    }
    return 0;
}

export fn zxy_net_fdb_age(now: u64) u32 {
    if (net_subsystem.bridge) |*br| {
        return br.fdb.age(now);
    }
    return 0;
}
