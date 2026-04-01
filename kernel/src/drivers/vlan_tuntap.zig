// SPDX-License-Identifier: MIT
// Zxyphor Kernel — VLAN, TUN/TAP Virtual Network Devices
//
// 802.1Q VLAN tagging & virtual tunnel interfaces:
// - Full 802.1Q VLAN tag insertion/stripping
// - VLAN device creation/management per parent interface
// - QinQ (802.1ad) double-tag support
// - VLAN filtering with priority mapping
// - TUN (L3) and TAP (L2) virtual interfaces
// - Multi-queue TUN/TAP support
// - Userspace packet injection/capture
// - VLAN statistics per VID
// - MAC VLAN (macvlan) support
// - GVRP-like VLAN registration protocol stub

const std = @import("std");

// ─────────────────── 802.1Q Constants ───────────────────────────────
pub const VLAN_HLEN: u16 = 4;
pub const VLAN_ETH_HLEN: u16 = 18; // 14 + 4
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88A8; // QinQ
pub const VLAN_VID_MASK: u16 = 0x0FFF;
pub const VLAN_PRI_MASK: u16 = 0xE000;
pub const VLAN_PRI_SHIFT: u4 = 13;
pub const VLAN_CFI_BIT: u16 = 0x1000;
pub const MAX_VLAN_ID: u16 = 4094;
pub const VLAN_NONE: u16 = 0;

// ─────────────────── 802.1Q Header ──────────────────────────────────
pub const VlanTag = packed struct {
    tci: u16,       // Tag Control Information (PRI:3 | CFI:1 | VID:12)
    eth_type: u16,  // Encapsulated protocol type

    pub fn vid(self: VlanTag) u16 {
        return toBigEndian16(self.tci) & VLAN_VID_MASK;
    }

    pub fn priority(self: VlanTag) u3 {
        return @intCast((toBigEndian16(self.tci) >> VLAN_PRI_SHIFT) & 0x7);
    }

    pub fn cfi(self: VlanTag) bool {
        return (toBigEndian16(self.tci) & VLAN_CFI_BIT) != 0;
    }

    pub fn make(vlan_id: u16, prio: u3, proto: u16) VlanTag {
        const tci = (vlan_id & VLAN_VID_MASK) | (@as(u16, prio) << VLAN_PRI_SHIFT);
        return .{
            .tci = fromBigEndian16(tci),
            .eth_type = fromBigEndian16(proto),
        };
    }
};

fn toBigEndian16(val: u16) u16 {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

fn fromBigEndian16(val: u16) u16 {
    return toBigEndian16(val); // Same operation for swap
}

// ─────────────────── VLAN Device ────────────────────────────────────
pub const MAX_VLAN_DEVICES: usize = 128;

pub const VlanPriorityMap = struct {
    ingress: [8]u3 = .{ 0, 1, 2, 3, 4, 5, 6, 7 }, // SKB prio → 802.1p
    egress: [8]u3 = .{ 0, 1, 2, 3, 4, 5, 6, 7 },  // 802.1p → SKB prio
};

pub const VlanStats = struct {
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_errors: u64 = 0,
    tx_errors: u64 = 0,
    rx_multicast: u64 = 0,

    pub fn reset(self: *VlanStats) void {
        self.* = .{};
    }
};

pub const VlanDevice = struct {
    vlan_id: u16 = 0,
    parent_ifindex: u16 = 0,
    ifindex: u16 = 0,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    vlan_proto: u16 = ETH_P_8021Q,
    flags: VlanFlags = .{},
    prio_map: VlanPriorityMap = .{},
    stats: VlanStats = .{},
    valid: bool = false,

    pub fn setName(self: *VlanDevice, n: []const u8) void {
        const len = @min(n.len, 15);
        @memcpy(self.name[0..len], n[0..len]);
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }

    pub fn getName(self: *const VlanDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Insert VLAN tag into frame (add 4 bytes after src MAC)
    pub fn tagFrame(self: *const VlanDevice, frame: []const u8, out: []u8) ?usize {
        if (frame.len < 14) return null; // min ethernet header
        const needed = frame.len + VLAN_HLEN;
        if (needed > out.len) return null;

        // Copy dst+src MAC (12 bytes)
        @memcpy(out[0..12], frame[0..12]);

        // Insert VLAN header
        const tpid_bytes: [2]u8 = .{
            @intCast((self.vlan_proto >> 8) & 0xFF),
            @intCast(self.vlan_proto & 0xFF),
        };
        out[12] = tpid_bytes[0];
        out[13] = tpid_bytes[1];

        const tag = VlanTag.make(self.vlan_id, 0, @as(u16, frame[12]) << 8 | frame[13]);
        const tag_bytes: *const [4]u8 = @ptrCast(&tag);
        @memcpy(out[14..18], tag_bytes);

        // Copy rest of payload (skip original ethertype)
        @memcpy(out[18..needed], frame[14..]);
        return needed;
    }

    /// Strip VLAN tag from frame (remove 4 bytes)
    pub fn untagFrame(frame: []const u8, out: []u8) ?struct { len: usize, vid: u16 } {
        if (frame.len < 18) return null; // min vlan-tagged frame

        // Check TPID
        const tpid: u16 = @as(u16, frame[12]) << 8 | frame[13];
        if (tpid != ETH_P_8021Q and tpid != ETH_P_8021AD) return null;

        const tci: u16 = @as(u16, frame[14]) << 8 | frame[15];
        const vid = tci & VLAN_VID_MASK;
        const new_len = frame.len - VLAN_HLEN;
        if (new_len > out.len) return null;

        // Copy dst+src MAC
        @memcpy(out[0..12], frame[0..12]);
        // Copy original ethertype + payload
        out[12] = frame[16];
        out[13] = frame[17];
        @memcpy(out[14..new_len], frame[18..]);

        return .{ .len = new_len, .vid = vid };
    }
};

pub const VlanFlags = packed struct(u8) {
    reorder_hdr: bool = true,
    gvrp: bool = false,
    loose_binding: bool = false,
    mvrp: bool = false,
    bridge_binding: bool = false,
    _pad: u3 = 0,
};

// ─────────────────── VLAN Filter Table ──────────────────────────────
pub const MAX_VLAN_FILTER: usize = 256;

pub const VlanFilterEntry = struct {
    vid: u16 = 0,
    untagged: bool = false,
    pvid: bool = false, // port VLAN ID (default VLAN for untagged frames)
    valid: bool = false,
};

pub const VlanFilter = struct {
    entries: [MAX_VLAN_FILTER]VlanFilterEntry = [_]VlanFilterEntry{.{}} ** MAX_VLAN_FILTER,
    count: usize = 0,
    default_pvid: u16 = 1,

    pub fn add(self: *VlanFilter, vid: u16, untagged: bool, pvid: bool) bool {
        if (vid > MAX_VLAN_ID) return false;
        // Check existing
        for (&self.entries) |*e| {
            if (e.valid and e.vid == vid) {
                e.untagged = untagged;
                if (pvid) self.setPvid(vid);
                return true;
            }
        }
        // Find free slot
        for (&self.entries) |*e| {
            if (!e.valid) {
                e.* = .{ .vid = vid, .untagged = untagged, .pvid = pvid, .valid = true };
                self.count += 1;
                if (pvid) self.setPvid(vid);
                return true;
            }
        }
        return false;
    }

    pub fn remove(self: *VlanFilter, vid: u16) bool {
        for (&self.entries) |*e| {
            if (e.valid and e.vid == vid) {
                e.valid = false;
                self.count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn isAllowed(self: *const VlanFilter, vid: u16) bool {
        for (self.entries) |e| {
            if (e.valid and e.vid == vid) return true;
        }
        return false;
    }

    fn setPvid(self: *VlanFilter, vid: u16) void {
        for (&self.entries) |*e| {
            if (e.valid) {
                e.pvid = (e.vid == vid);
            }
        }
        self.default_pvid = vid;
    }
};

// ─────────────────── QinQ (Double-Tag) ──────────────────────────────
pub const QinQTag = struct {
    outer_vid: u16,
    inner_vid: u16,
    outer_prio: u3 = 0,
    inner_prio: u3 = 0,

    /// Parse double-tagged frame
    pub fn parse(frame: []const u8) ?QinQTag {
        if (frame.len < 22) return null; // 14 + 4 + 4

        const outer_tpid: u16 = @as(u16, frame[12]) << 8 | frame[13];
        if (outer_tpid != ETH_P_8021AD) return null;

        const outer_tci: u16 = @as(u16, frame[14]) << 8 | frame[15];
        const inner_tpid: u16 = @as(u16, frame[16]) << 8 | frame[17];
        if (inner_tpid != ETH_P_8021Q) return null;

        const inner_tci: u16 = @as(u16, frame[18]) << 8 | frame[19];

        return .{
            .outer_vid = outer_tci & VLAN_VID_MASK,
            .inner_vid = inner_tci & VLAN_VID_MASK,
            .outer_prio = @intCast((outer_tci >> VLAN_PRI_SHIFT) & 0x7),
            .inner_prio = @intCast((inner_tci >> VLAN_PRI_SHIFT) & 0x7),
        };
    }
};

// ─────────────────── TUN/TAP ────────────────────────────────────────
pub const TUN_TUN_DEV: u16 = 0x0001;
pub const TUN_TAP_DEV: u16 = 0x0002;
pub const TUN_NO_PI: u16 = 0x1000;
pub const TUN_MULTI_QUEUE: u16 = 0x0100;

pub const TunMode = enum(u8) {
    tun, // L3 — IP packets
    tap, // L2 — Ethernet frames
};

pub const TunPacketInfo = packed struct {
    flags: u16 = 0,
    proto: u16 = 0,
};

pub const MAX_TUN_QUEUE: usize = 256;
pub const TUN_RING_SIZE: usize = 64;

pub const TunRingEntry = struct {
    data: [2048]u8 = undefined,
    len: u16 = 0,
    valid: bool = false,
};

pub const TunQueue = struct {
    ring: [TUN_RING_SIZE]TunRingEntry = [_]TunRingEntry{.{}} ** TUN_RING_SIZE,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,

    pub fn enqueue(self: *TunQueue, data: []const u8) bool {
        if (self.count >= TUN_RING_SIZE) return false;
        const entry = &self.ring[self.tail];
        const copy_len = @min(data.len, 2048);
        @memcpy(entry.data[0..copy_len], data[0..copy_len]);
        entry.len = @intCast(copy_len);
        entry.valid = true;
        self.tail = (self.tail + 1) % TUN_RING_SIZE;
        self.count += 1;
        return true;
    }

    pub fn dequeue(self: *TunQueue) ?struct { data: []const u8 } {
        if (self.count == 0) return null;
        const entry = &self.ring[self.head];
        if (!entry.valid) return null;
        const slice = entry.data[0..entry.len];
        entry.valid = false;
        self.head = (self.head + 1) % TUN_RING_SIZE;
        self.count -= 1;
        return .{ .data = slice };
    }
};

pub const TunDevice = struct {
    ifindex: u16 = 0,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    mode: TunMode = .tun,
    flags: u16 = 0,
    mtu: u32 = 1500,
    owner_uid: u32 = 0,
    owner_gid: u32 = 0,
    // Multi-queue
    num_queues: u8 = 1,
    tx_queues: [4]TunQueue = [_]TunQueue{.{}} ** 4,
    rx_queues: [4]TunQueue = [_]TunQueue{.{}} ** 4,
    // Stats
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    rx_dropped: u64 = 0,
    tx_dropped: u64 = 0,
    // State
    active: bool = false,
    persist: bool = false,

    pub fn init(ifindex: u16, mode: TunMode) TunDevice {
        var dev = TunDevice{
            .ifindex = ifindex,
            .mode = mode,
            .active = true,
        };
        switch (mode) {
            .tun => dev.setName("tun0"),
            .tap => dev.setName("tap0"),
        }
        return dev;
    }

    pub fn setName(self: *TunDevice, n: []const u8) void {
        const len = @min(n.len, 15);
        @memcpy(self.name[0..len], n[0..len]);
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }

    /// Write from userspace into the device (inject packet)
    pub fn write(self: *TunDevice, queue_id: u8, data: []const u8) bool {
        if (!self.active) return false;
        if (queue_id >= self.num_queues) return false;

        var offset: usize = 0;
        if (self.flags & TUN_NO_PI == 0) {
            // Skip packet info header
            if (data.len < 4) return false;
            offset = 4;
        }

        if (self.rx_queues[queue_id].enqueue(data[offset..])) {
            self.rx_packets += 1;
            self.rx_bytes += data.len - offset;
            return true;
        }
        self.rx_dropped += 1;
        return false;
    }

    /// Read from the device to userspace (capture packet)
    pub fn read(self: *TunDevice, queue_id: u8) ?[]const u8 {
        if (!self.active) return null;
        if (queue_id >= self.num_queues) return null;

        if (self.tx_queues[queue_id].dequeue()) |pkt| {
            return pkt.data;
        }
        return null;
    }

    /// Kernel transmit: enqueue to tx queue (for userspace to read)
    pub fn kernelTx(self: *TunDevice, queue_id: u8, data: []const u8) bool {
        if (!self.active) return false;
        if (queue_id >= self.num_queues) return false;

        if (self.tx_queues[queue_id].enqueue(data)) {
            self.tx_packets += 1;
            self.tx_bytes += data.len;
            return true;
        }
        self.tx_dropped += 1;
        return false;
    }
};

// ─────────────────── MACVLAN ────────────────────────────────────────
pub const MacvlanMode = enum(u8) {
    private,   // No communication between macvlans
    vepa,      // Communicate through external switch
    bridge,    // Direct communication between macvlans
    passthru,  // Directly connect to lower device
    source,    // Only accept from source MAC list
};

pub const MacvlanDevice = struct {
    ifindex: u16 = 0,
    parent_ifindex: u16 = 0,
    mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    mode: MacvlanMode = .bridge,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    rx_packets: u64 = 0,
    tx_packets: u64 = 0,
    active: bool = false,

    // Source mode: allowed source MACs
    source_list: [16][6]u8 = undefined,
    source_count: u8 = 0,

    pub fn init(ifindex: u16, parent: u16, mac: [6]u8, mode: MacvlanMode) MacvlanDevice {
        var dev = MacvlanDevice{
            .ifindex = ifindex,
            .parent_ifindex = parent,
            .mac = mac,
            .mode = mode,
            .active = true,
        };
        dev.setName("macvlan0");
        return dev;
    }

    pub fn setName(self: *MacvlanDevice, n: []const u8) void {
        const len = @min(n.len, 15);
        @memcpy(self.name[0..len], n[0..len]);
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }

    pub fn addSource(self: *MacvlanDevice, mac: [6]u8) bool {
        if (self.source_count >= 16) return false;
        self.source_list[self.source_count] = mac;
        self.source_count += 1;
        return true;
    }

    pub fn isSourceAllowed(self: *const MacvlanDevice, src: [6]u8) bool {
        if (self.mode != .source) return true;
        for (self.source_list[0..self.source_count]) |s| {
            var eq = true;
            inline for (0..6) |i| {
                if (s[i] != src[i]) eq = false;
            }
            if (eq) return true;
        }
        return false;
    }
};

// ─────────────────── VLAN Manager ───────────────────────────────────
pub const VlanManager = struct {
    devices: [MAX_VLAN_DEVICES]VlanDevice = [_]VlanDevice{.{}} ** MAX_VLAN_DEVICES,
    device_count: usize = 0,
    filter: VlanFilter = .{},
    tun_devices: [8]TunDevice = undefined,
    tun_count: u8 = 0,
    macvlan_devices: [16]MacvlanDevice = undefined,
    macvlan_count: u8 = 0,
    next_ifindex: u16 = 100,
    initialized: bool = false,

    pub fn init(self: *VlanManager) void {
        self.initialized = true;
    }

    pub fn createVlan(self: *VlanManager, parent_ifindex: u16, vid: u16) ?u16 {
        if (vid > MAX_VLAN_ID or vid == 0) return null;
        if (self.device_count >= MAX_VLAN_DEVICES) return null;

        // Check for duplicate
        for (self.devices[0..self.device_count]) |d| {
            if (d.valid and d.parent_ifindex == parent_ifindex and d.vlan_id == vid) {
                return null;
            }
        }

        const ifindex = self.next_ifindex;
        self.next_ifindex += 1;

        var dev = VlanDevice{
            .vlan_id = vid,
            .parent_ifindex = parent_ifindex,
            .ifindex = ifindex,
            .valid = true,
        };
        // Auto-name: "eth0.100"
        var name_buf: [16]u8 = [_]u8{0} ** 16;
        var name_pos: usize = 0;
        // Write "vlan"
        const prefix = "vlan";
        @memcpy(name_buf[0..prefix.len], prefix);
        name_pos = prefix.len;
        // Write VID number
        name_pos += writeU16(name_buf[name_pos..], vid);
        dev.setName(name_buf[0..name_pos]);

        self.devices[self.device_count] = dev;
        self.device_count += 1;
        return ifindex;
    }

    pub fn destroyVlan(self: *VlanManager, ifindex: u16) bool {
        for (0..self.device_count) |i| {
            if (self.devices[i].valid and self.devices[i].ifindex == ifindex) {
                self.devices[i].valid = false;
                // Compact
                var j = i;
                while (j + 1 < self.device_count) : (j += 1) {
                    self.devices[j] = self.devices[j + 1];
                }
                self.device_count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn findVlan(self: *const VlanManager, parent: u16, vid: u16) ?*const VlanDevice {
        for (&self.devices[0..self.device_count]) |*d| {
            if (d.valid and d.parent_ifindex == parent and d.vlan_id == vid) {
                return d;
            }
        }
        return null;
    }

    pub fn createTun(self: *VlanManager, mode: TunMode) ?u16 {
        if (self.tun_count >= 8) return null;
        const ifindex = self.next_ifindex;
        self.next_ifindex += 1;
        self.tun_devices[self.tun_count] = TunDevice.init(ifindex, mode);
        self.tun_count += 1;
        return ifindex;
    }

    pub fn createMacvlan(self: *VlanManager, parent: u16, mac: [6]u8, mode: MacvlanMode) ?u16 {
        if (self.macvlan_count >= 16) return null;
        const ifindex = self.next_ifindex;
        self.next_ifindex += 1;
        self.macvlan_devices[self.macvlan_count] = MacvlanDevice.init(ifindex, parent, mac, mode);
        self.macvlan_count += 1;
        return ifindex;
    }

    /// Process incoming frame: identify VLAN, strip tag if needed
    pub fn processRx(self: *VlanManager, parent: u16, frame: []const u8, out: []u8) ?struct { len: usize, vid: u16 } {
        // Try single-tag
        if (VlanDevice.untagFrame(frame, out)) |result| {
            if (self.findVlan(parent, result.vid)) |vdev| {
                _ = vdev; // Found VLAN device for this VID
                return result;
            }
        }
        return null;
    }
};

fn writeU16(buf: []u8, val: u16) usize {
    var v = val;
    if (v == 0) {
        if (buf.len > 0) {
            buf[0] = '0';
            return 1;
        }
        return 0;
    }
    var digits: [5]u8 = undefined;
    var count: usize = 0;
    while (v > 0) : (count += 1) {
        digits[count] = @intCast((v % 10) + '0');
        v /= 10;
    }
    const len = @min(count, buf.len);
    for (0..len) |i| {
        buf[i] = digits[count - 1 - i];
    }
    return len;
}

// ─────────────────── Global Instance ────────────────────────────────
var vlan_mgr: VlanManager = .{};

pub fn initVlanManager() void {
    vlan_mgr.init();
}

pub fn getVlanManager() *VlanManager {
    return &vlan_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_vlan_init() void {
    initVlanManager();
}

export fn zxy_vlan_create(parent_ifindex: u16, vid: u16) i32 {
    if (vlan_mgr.createVlan(parent_ifindex, vid)) |ifidx| {
        return @intCast(ifidx);
    }
    return -1;
}

export fn zxy_vlan_destroy(ifindex: u16) bool {
    return vlan_mgr.destroyVlan(ifindex);
}

export fn zxy_vlan_count() u32 {
    return @intCast(vlan_mgr.device_count);
}

export fn zxy_tun_create(mode: u8) i32 {
    const tun_mode: TunMode = if (mode == 0) .tun else .tap;
    if (vlan_mgr.createTun(tun_mode)) |ifidx| {
        return @intCast(ifidx);
    }
    return -1;
}

export fn zxy_tun_count() u8 {
    return vlan_mgr.tun_count;
}

export fn zxy_macvlan_create(parent: u16, mode: u8) i32 {
    const mv_mode: MacvlanMode = @enumFromInt(mode);
    const mac = [_]u8{ 0x02, 0x42, 0xAC, 0x12, 0x00, @as(u8, vlan_mgr.macvlan_count) + 1 };
    if (vlan_mgr.createMacvlan(parent, mac, mv_mode)) |ifidx| {
        return @intCast(ifidx);
    }
    return -1;
}
