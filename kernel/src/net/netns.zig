// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Network Namespace Subsystem (Zig)
//
// Network namespace isolation (like Linux netns):
// - Per-namespace network stack: interfaces, routes, sockets
// - Veth pair for cross-namespace communication
// - Namespace lifecycle: create, enter, leave, destroy
// - Loopback interface per namespace (auto-created)
// - Route table per namespace with gateway, metric, scope
// - ARP/neighbor cache per namespace
// - Network device migration between namespaces
// - Namespace reference counting
// - Proc filesystem integration (/proc/net/...)
// - Socket binding scoped to namespace
// - Hierarchical namespace IDs

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_NETNS: usize = 16;
const MAX_NETDEVS_PER_NS: usize = 8;
const MAX_ROUTES_PER_NS: usize = 32;
const MAX_ARP_PER_NS: usize = 32;
const MAX_SOCKETS_PER_NS: usize = 64;
const MAX_VETH_PAIRS: usize = 16;
const NETNS_NAME_LEN: usize = 32;
const IFNAME_LEN: usize = 16;

// ─────────────────── Network Device (per-NS) ───────────────────────

pub const NetDevFlags = packed struct {
    up: bool = false,
    broadcast: bool = false,
    loopback: bool = false,
    pointtopoint: bool = false,
    multicast: bool = false,
    promisc: bool = false,
    noarp: bool = false,
    _pad: u1 = 0,
};

pub const NetDev = struct {
    name: [IFNAME_LEN]u8,
    name_len: u8,
    ifindex: u16,
    mtu: u16,
    flags: NetDevFlags,
    mac: [6]u8,
    // IPv4 address
    ipv4_addr: u32,
    ipv4_mask: u32,
    ipv4_broadcast: u32,
    // IPv6 address (simplified)
    ipv6_addr: [16]u8,
    ipv6_prefix: u8,
    // Veth peer
    veth_peer_ns: i16,   // -1 = not a veth
    veth_peer_idx: i16,
    // Stats
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
    active: bool,

    const Self = @This();

    pub fn init() Self {
        var dev: Self = undefined;
        dev.name = [_]u8{0} ** IFNAME_LEN;
        dev.name_len = 0;
        dev.ifindex = 0;
        dev.mtu = 1500;
        dev.flags = .{};
        dev.mac = [_]u8{0} ** 6;
        dev.ipv4_addr = 0;
        dev.ipv4_mask = 0;
        dev.ipv4_broadcast = 0;
        dev.ipv6_addr = [_]u8{0} ** 16;
        dev.ipv6_prefix = 0;
        dev.veth_peer_ns = -1;
        dev.veth_peer_idx = -1;
        dev.rx_bytes = 0;
        dev.tx_bytes = 0;
        dev.rx_packets = 0;
        dev.tx_packets = 0;
        dev.rx_errors = 0;
        dev.tx_errors = 0;
        dev.rx_dropped = 0;
        dev.tx_dropped = 0;
        dev.active = false;
        return dev;
    }

    pub fn set_name(self: *Self, n: []const u8) void {
        const len = @min(n.len, IFNAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn set_ipv4(self: *Self, addr: u32, mask: u32) void {
        self.ipv4_addr = addr;
        self.ipv4_mask = mask;
        self.ipv4_broadcast = addr | ~mask;
    }
};

// ─────────────────── Route Entry ────────────────────────────────────

pub const RouteScope = enum(u8) {
    universe = 0,
    site = 200,
    link = 253,
    host = 254,
    nowhere = 255,
};

pub const RouteProto = enum(u8) {
    unspec = 0,
    kernel = 2,
    boot = 3,
    static_ = 4,
    dhcp = 16,
};

pub const RouteType = enum(u8) {
    unicast = 1,
    local_ = 2,
    broadcast = 3,
    multicast = 5,
    blackhole = 6,
    unreachable = 7,
    prohibit = 8,
};

pub const RouteEntry = struct {
    dest: u32,          // Destination network
    dest_mask: u32,     // Network mask
    gateway: u32,       // Next hop (0 = direct)
    ifindex: u16,       // Output interface
    metric: u32,        // Route priority (lower = preferred)
    scope: RouteScope,
    proto: RouteProto,
    route_type: RouteType,
    // Flags
    flags_up: bool,
    flags_gateway: bool,
    flags_host: bool,
    // Stats
    use_count: u64,
    active: bool,

    pub fn init() RouteEntry {
        return .{
            .dest = 0,
            .dest_mask = 0,
            .gateway = 0,
            .ifindex = 0,
            .metric = 0,
            .scope = .universe,
            .proto = .kernel,
            .route_type = .unicast,
            .flags_up = true,
            .flags_gateway = false,
            .flags_host = false,
            .use_count = 0,
            .active = false,
        };
    }

    pub fn matches(self: *const RouteEntry, dest_ip: u32) bool {
        return (dest_ip & self.dest_mask) == (self.dest & self.dest_mask);
    }
};

// ─────────────────── ARP / Neighbor Entry ───────────────────────────

pub const ArpState = enum(u8) {
    incomplete = 0,
    reachable = 1,
    stale = 2,
    delay = 3,
    probe = 4,
    failed = 5,
    permanent = 6,
};

pub const ArpEntry = struct {
    ip_addr: u32,
    mac: [6]u8,
    ifindex: u16,
    state: ArpState,
    confirmed_tick: u64,
    used_tick: u64,
    probes: u8,
    active: bool,

    pub fn init() ArpEntry {
        return .{
            .ip_addr = 0,
            .mac = [_]u8{0} ** 6,
            .ifindex = 0,
            .state = .incomplete,
            .confirmed_tick = 0,
            .used_tick = 0,
            .probes = 0,
            .active = false,
        };
    }
};

// ─────────────────── Namespace Socket Binding ───────────────────────

pub const NsSockBind = struct {
    local_addr: u32,
    local_port: u16,
    proto: u8,       // 6=TCP, 17=UDP
    pid: u32,
    active: bool,

    pub fn init() NsSockBind {
        return .{
            .local_addr = 0,
            .local_port = 0,
            .proto = 0,
            .pid = 0,
            .active = false,
        };
    }
};

// ─────────────────── Network Namespace ──────────────────────────────

pub const NetNamespace = struct {
    name: [NETNS_NAME_LEN]u8,
    name_len: u8,
    id: u16,
    ref_count: u16,
    creator_pid: u32,

    // Devices
    devs: [MAX_NETDEVS_PER_NS]NetDev,
    dev_count: u8,
    next_ifindex: u16,

    // Routes
    routes: [MAX_ROUTES_PER_NS]RouteEntry,
    route_count: u8,

    // ARP
    arp_cache: [MAX_ARP_PER_NS]ArpEntry,
    arp_count: u8,

    // Sockets
    sockets: [MAX_SOCKETS_PER_NS]NsSockBind,
    sock_count: u8,

    // Stats
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_rx_packets: u64,
    total_tx_packets: u64,

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var ns: Self = undefined;
        ns.name = [_]u8{0} ** NETNS_NAME_LEN;
        ns.name_len = 0;
        ns.id = 0;
        ns.ref_count = 0;
        ns.creator_pid = 0;
        for (0..MAX_NETDEVS_PER_NS) |i| ns.devs[i] = NetDev.init();
        ns.dev_count = 0;
        ns.next_ifindex = 1;
        for (0..MAX_ROUTES_PER_NS) |i| ns.routes[i] = RouteEntry.init();
        ns.route_count = 0;
        for (0..MAX_ARP_PER_NS) |i| ns.arp_cache[i] = ArpEntry.init();
        ns.arp_count = 0;
        for (0..MAX_SOCKETS_PER_NS) |i| ns.sockets[i] = NsSockBind.init();
        ns.sock_count = 0;
        ns.total_rx_bytes = 0;
        ns.total_tx_bytes = 0;
        ns.total_rx_packets = 0;
        ns.total_tx_packets = 0;
        ns.active = false;
        return ns;
    }

    pub fn set_name(self: *Self, n: []const u8) void {
        const len = @min(n.len, NETNS_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    // ─── Device Management ──────────────────────────────────────────

    pub fn add_device(self: *Self, name: []const u8, mtu: u16) ?u8 {
        if (self.dev_count >= MAX_NETDEVS_PER_NS) return null;
        for (0..MAX_NETDEVS_PER_NS) |i| {
            if (!self.devs[i].active) {
                self.devs[i] = NetDev.init();
                self.devs[i].set_name(name);
                self.devs[i].ifindex = self.next_ifindex;
                self.next_ifindex += 1;
                self.devs[i].mtu = mtu;
                self.devs[i].active = true;
                self.dev_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn add_loopback(self: *Self) ?u8 {
        const idx = self.add_device("lo", 65535) orelse return null;
        self.devs[idx].flags.loopback = true;
        self.devs[idx].flags.up = true;
        self.devs[idx].set_ipv4(0x7f000001, 0xff000000); // 127.0.0.1/8
        return idx;
    }

    pub fn remove_device(self: *Self, dev_idx: u8) bool {
        if (dev_idx >= MAX_NETDEVS_PER_NS or !self.devs[dev_idx].active) return false;
        self.devs[dev_idx].active = false;
        self.dev_count -= 1;
        return true;
    }

    // ─── Route Management ───────────────────────────────────────────

    pub fn add_route(self: *Self, dest: u32, mask: u32, gw: u32, ifindex: u16, metric: u32) ?u8 {
        if (self.route_count >= MAX_ROUTES_PER_NS) return null;
        for (0..MAX_ROUTES_PER_NS) |i| {
            if (!self.routes[i].active) {
                self.routes[i] = RouteEntry.init();
                self.routes[i].dest = dest;
                self.routes[i].dest_mask = mask;
                self.routes[i].gateway = gw;
                self.routes[i].ifindex = ifindex;
                self.routes[i].metric = metric;
                self.routes[i].flags_gateway = gw != 0;
                self.routes[i].active = true;
                self.route_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn del_route(self: *Self, route_idx: u8) bool {
        if (route_idx >= MAX_ROUTES_PER_NS or !self.routes[route_idx].active) return false;
        self.routes[route_idx].active = false;
        self.route_count -= 1;
        return true;
    }

    /// Longest prefix match
    pub fn route_lookup(self: *Self, dest_ip: u32) ?u8 {
        var best: ?u8 = null;
        var best_mask: u32 = 0;
        var best_metric: u32 = 0xFFFFFFFF;
        for (0..MAX_ROUTES_PER_NS) |i| {
            if (!self.routes[i].active or !self.routes[i].flags_up) continue;
            if (self.routes[i].matches(dest_ip)) {
                const mask = self.routes[i].dest_mask;
                const metric = self.routes[i].metric;
                // Prefer longer prefix, then lower metric
                if (mask > best_mask or (mask == best_mask and metric < best_metric)) {
                    best = @intCast(i);
                    best_mask = mask;
                    best_metric = metric;
                }
            }
        }
        if (best) |idx| {
            self.routes[idx].use_count += 1;
        }
        return best;
    }

    // ─── ARP Cache ──────────────────────────────────────────────────

    pub fn arp_add(self: *Self, ip: u32, mac: [6]u8, ifindex: u16, tick: u64) ?u8 {
        // Check existing entry first
        for (0..MAX_ARP_PER_NS) |i| {
            if (self.arp_cache[i].active and self.arp_cache[i].ip_addr == ip) {
                self.arp_cache[i].mac = mac;
                self.arp_cache[i].state = .reachable;
                self.arp_cache[i].confirmed_tick = tick;
                return @intCast(i);
            }
        }
        // New entry
        if (self.arp_count >= MAX_ARP_PER_NS) return null;
        for (0..MAX_ARP_PER_NS) |i| {
            if (!self.arp_cache[i].active) {
                self.arp_cache[i] = ArpEntry.init();
                self.arp_cache[i].ip_addr = ip;
                self.arp_cache[i].mac = mac;
                self.arp_cache[i].ifindex = ifindex;
                self.arp_cache[i].state = .reachable;
                self.arp_cache[i].confirmed_tick = tick;
                self.arp_cache[i].active = true;
                self.arp_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn arp_lookup(self: *Self, ip: u32, tick: u64) ?[6]u8 {
        for (0..MAX_ARP_PER_NS) |i| {
            if (self.arp_cache[i].active and self.arp_cache[i].ip_addr == ip) {
                if (self.arp_cache[i].state == .reachable or self.arp_cache[i].state == .permanent) {
                    self.arp_cache[i].used_tick = tick;
                    return self.arp_cache[i].mac;
                }
            }
        }
        return null;
    }

    // ─── Socket Binding ─────────────────────────────────────────────

    pub fn bind_socket(self: *Self, addr: u32, port: u16, proto: u8, pid: u32) bool {
        // Check for conflict
        for (0..MAX_SOCKETS_PER_NS) |i| {
            if (self.sockets[i].active and self.sockets[i].local_port == port and self.sockets[i].proto == proto) {
                if (self.sockets[i].local_addr == addr or self.sockets[i].local_addr == 0 or addr == 0) {
                    return false; // Port in use
                }
            }
        }
        if (self.sock_count >= MAX_SOCKETS_PER_NS) return false;
        for (0..MAX_SOCKETS_PER_NS) |i| {
            if (!self.sockets[i].active) {
                self.sockets[i] = NsSockBind.init();
                self.sockets[i].local_addr = addr;
                self.sockets[i].local_port = port;
                self.sockets[i].proto = proto;
                self.sockets[i].pid = pid;
                self.sockets[i].active = true;
                self.sock_count += 1;
                return true;
            }
        }
        return false;
    }

    pub fn unbind_socket(self: *Self, port: u16, proto: u8) bool {
        for (0..MAX_SOCKETS_PER_NS) |i| {
            if (self.sockets[i].active and self.sockets[i].local_port == port and self.sockets[i].proto == proto) {
                self.sockets[i].active = false;
                self.sock_count -= 1;
                return true;
            }
        }
        return false;
    }
};

// ─────────────────── Veth Pair ──────────────────────────────────────

pub const VethPair = struct {
    ns_a: u16,
    dev_a: u8,
    ns_b: u16,
    dev_b: u8,
    tx_count: u64,
    active: bool,

    pub fn init() VethPair {
        return .{
            .ns_a = 0,
            .dev_a = 0,
            .ns_b = 0,
            .dev_b = 0,
            .tx_count = 0,
            .active = false,
        };
    }
};

// ─────────────────── Namespace Manager ──────────────────────────────

pub const NetnsManager = struct {
    namespaces: [MAX_NETNS]NetNamespace,
    ns_count: u8,
    next_id: u16,
    veth_pairs: [MAX_VETH_PAIRS]VethPair,
    veth_count: u8,
    tick: u64,

    // Stats
    total_created: u64,
    total_destroyed: u64,
    total_migrations: u64,
    total_veth_tx: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var mgr: Self = undefined;
        for (0..MAX_NETNS) |i| mgr.namespaces[i] = NetNamespace.init();
        mgr.ns_count = 0;
        mgr.next_id = 0;
        for (0..MAX_VETH_PAIRS) |i| mgr.veth_pairs[i] = VethPair.init();
        mgr.veth_count = 0;
        mgr.tick = 0;
        mgr.total_created = 0;
        mgr.total_destroyed = 0;
        mgr.total_migrations = 0;
        mgr.total_veth_tx = 0;
        mgr.initialized = true;

        // Create default/init namespace
        mgr.namespaces[0] = NetNamespace.init();
        mgr.namespaces[0].set_name("default");
        mgr.namespaces[0].id = 0;
        mgr.namespaces[0].ref_count = 1;
        mgr.namespaces[0].active = true;
        _ = mgr.namespaces[0].add_loopback();
        mgr.ns_count = 1;
        mgr.next_id = 1;
        return mgr;
    }

    pub fn create_namespace(self: *Self, name: []const u8, creator_pid: u32) ?u16 {
        for (0..MAX_NETNS) |i| {
            if (!self.namespaces[i].active) {
                self.namespaces[i] = NetNamespace.init();
                self.namespaces[i].set_name(name);
                self.namespaces[i].id = self.next_id;
                self.next_id += 1;
                self.namespaces[i].ref_count = 1;
                self.namespaces[i].creator_pid = creator_pid;
                self.namespaces[i].active = true;
                // Every namespace gets a loopback
                _ = self.namespaces[i].add_loopback();
                self.ns_count += 1;
                self.total_created += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn destroy_namespace(self: *Self, ns_idx: u16) bool {
        if (ns_idx == 0) return false; // Cannot destroy default
        if (ns_idx >= MAX_NETNS or !self.namespaces[ns_idx].active) return false;
        self.namespaces[ns_idx].ref_count -|= 1;
        if (self.namespaces[ns_idx].ref_count == 0) {
            // Clean up veth pairs
            for (0..MAX_VETH_PAIRS) |i| {
                if (self.veth_pairs[i].active) {
                    if (self.veth_pairs[i].ns_a == ns_idx or self.veth_pairs[i].ns_b == ns_idx) {
                        self.veth_pairs[i].active = false;
                        self.veth_count -= 1;
                    }
                }
            }
            self.namespaces[ns_idx].active = false;
            self.ns_count -= 1;
            self.total_destroyed += 1;
        }
        return true;
    }

    pub fn get_ref(self: *Self, ns_idx: u16) bool {
        if (ns_idx >= MAX_NETNS or !self.namespaces[ns_idx].active) return false;
        self.namespaces[ns_idx].ref_count += 1;
        return true;
    }

    pub fn put_ref(self: *Self, ns_idx: u16) void {
        if (ns_idx >= MAX_NETNS or !self.namespaces[ns_idx].active) return;
        self.namespaces[ns_idx].ref_count -|= 1;
    }

    // ─── Veth Pair ──────────────────────────────────────────────────

    pub fn create_veth_pair(self: *Self, ns_a: u16, name_a: []const u8, ns_b: u16, name_b: []const u8) bool {
        if (ns_a >= MAX_NETNS or ns_b >= MAX_NETNS) return false;
        if (!self.namespaces[ns_a].active or !self.namespaces[ns_b].active) return false;
        if (self.veth_count >= MAX_VETH_PAIRS) return false;

        const dev_a = self.namespaces[ns_a].add_device(name_a, 1500) orelse return false;
        const dev_b = self.namespaces[ns_b].add_device(name_b, 1500) orelse return false;

        // Link as veth pair
        self.namespaces[ns_a].devs[dev_a].veth_peer_ns = @intCast(ns_b);
        self.namespaces[ns_a].devs[dev_a].veth_peer_idx = @intCast(dev_b);
        self.namespaces[ns_a].devs[dev_a].flags.up = true;

        self.namespaces[ns_b].devs[dev_b].veth_peer_ns = @intCast(ns_a);
        self.namespaces[ns_b].devs[dev_b].veth_peer_idx = @intCast(dev_a);
        self.namespaces[ns_b].devs[dev_b].flags.up = true;

        for (0..MAX_VETH_PAIRS) |i| {
            if (!self.veth_pairs[i].active) {
                self.veth_pairs[i] = VethPair.init();
                self.veth_pairs[i].ns_a = ns_a;
                self.veth_pairs[i].dev_a = dev_a;
                self.veth_pairs[i].ns_b = ns_b;
                self.veth_pairs[i].dev_b = dev_b;
                self.veth_pairs[i].active = true;
                self.veth_count += 1;
                break;
            }
        }
        return true;
    }

    /// Transmit from one end of veth to the other
    pub fn veth_transmit(self: *Self, ns_idx: u16, dev_idx: u8, bytes: u64) bool {
        if (ns_idx >= MAX_NETNS or !self.namespaces[ns_idx].active) return false;
        if (dev_idx >= MAX_NETDEVS_PER_NS or !self.namespaces[ns_idx].devs[dev_idx].active) return false;

        const peer_ns = self.namespaces[ns_idx].devs[dev_idx].veth_peer_ns;
        const peer_idx = self.namespaces[ns_idx].devs[dev_idx].veth_peer_idx;
        if (peer_ns < 0 or peer_idx < 0) return false;

        const pns: u16 = @intCast(peer_ns);
        const pidx: u8 = @intCast(peer_idx);
        if (pns >= MAX_NETNS or !self.namespaces[pns].active) return false;
        if (pidx >= MAX_NETDEVS_PER_NS or !self.namespaces[pns].devs[pidx].active) return false;

        // TX on source, RX on peer
        self.namespaces[ns_idx].devs[dev_idx].tx_bytes += bytes;
        self.namespaces[ns_idx].devs[dev_idx].tx_packets += 1;
        self.namespaces[pns].devs[pidx].rx_bytes += bytes;
        self.namespaces[pns].devs[pidx].rx_packets += 1;
        self.total_veth_tx += 1;
        return true;
    }

    // ─── Device Migration ───────────────────────────────────────────

    pub fn migrate_device(self: *Self, from_ns: u16, dev_idx: u8, to_ns: u16) bool {
        if (from_ns >= MAX_NETNS or to_ns >= MAX_NETNS) return false;
        if (!self.namespaces[from_ns].active or !self.namespaces[to_ns].active) return false;
        if (dev_idx >= MAX_NETDEVS_PER_NS or !self.namespaces[from_ns].devs[dev_idx].active) return false;
        // Cannot move loopback
        if (self.namespaces[from_ns].devs[dev_idx].flags.loopback) return false;

        const dev = self.namespaces[from_ns].devs[dev_idx];
        // Find slot in target
        const new_idx = self.namespaces[to_ns].add_device(dev.name[0..dev.name_len], dev.mtu) orelse return false;
        // Copy full state
        self.namespaces[to_ns].devs[new_idx].mac = dev.mac;
        self.namespaces[to_ns].devs[new_idx].ipv4_addr = dev.ipv4_addr;
        self.namespaces[to_ns].devs[new_idx].ipv4_mask = dev.ipv4_mask;
        self.namespaces[to_ns].devs[new_idx].flags = dev.flags;
        // Remove from source
        self.namespaces[from_ns].devs[dev_idx].active = false;
        self.namespaces[from_ns].dev_count -= 1;
        self.total_migrations += 1;
        return true;
    }

    // ─── ARP Aging ──────────────────────────────────────────────────

    pub fn process_tick(self: *Self) void {
        self.tick += 1;
        // Age ARP entries every 60 seconds
        if (self.tick % 60000 == 0) {
            for (0..MAX_NETNS) |ns| {
                if (!self.namespaces[ns].active) continue;
                for (0..MAX_ARP_PER_NS) |a| {
                    if (!self.namespaces[ns].arp_cache[a].active) continue;
                    if (self.namespaces[ns].arp_cache[a].state == .permanent) continue;
                    const age = self.tick -| self.namespaces[ns].arp_cache[a].confirmed_tick;
                    if (age > 300000) { // 5 min → remove
                        self.namespaces[ns].arp_cache[a].active = false;
                        self.namespaces[ns].arp_count -= 1;
                    } else if (age > 60000 and self.namespaces[ns].arp_cache[a].state == .reachable) {
                        self.namespaces[ns].arp_cache[a].state = .stale;
                    }
                }
            }
        }
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_netns: NetnsManager = undefined;
var g_netns_init: bool = false;

fn nm() *NetnsManager {
    return &g_netns;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_netns_init() void {
    g_netns = NetnsManager.init();
    g_netns_init = true;
}

export fn zxy_netns_create(name_ptr: [*]const u8, name_len: usize, creator_pid: u32) i16 {
    if (!g_netns_init) return -1;
    if (nm().create_namespace(name_ptr[0..name_len], creator_pid)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_netns_destroy(ns: u16) bool {
    if (!g_netns_init) return false;
    return nm().destroy_namespace(ns);
}

export fn zxy_netns_add_device(ns: u16, name_ptr: [*]const u8, name_len: usize, mtu: u16) i8 {
    if (!g_netns_init or ns >= MAX_NETNS or !nm().namespaces[ns].active) return -1;
    if (nm().namespaces[ns].add_device(name_ptr[0..name_len], mtu)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_netns_veth_create(ns_a: u16, ns_b: u16) bool {
    if (!g_netns_init) return false;
    return nm().create_veth_pair(ns_a, "veth0", ns_b, "veth1");
}

export fn zxy_netns_veth_tx(ns: u16, dev: u8, bytes: u64) bool {
    if (!g_netns_init) return false;
    return nm().veth_transmit(ns, dev, bytes);
}

export fn zxy_netns_migrate_dev(from: u16, dev: u8, to: u16) bool {
    if (!g_netns_init) return false;
    return nm().migrate_device(from, dev, to);
}

export fn zxy_netns_add_route(ns: u16, dest: u32, mask: u32, gw: u32, ifindex: u16, metric: u32) bool {
    if (!g_netns_init or ns >= MAX_NETNS or !nm().namespaces[ns].active) return false;
    return nm().namespaces[ns].add_route(dest, mask, gw, ifindex, metric) != null;
}

export fn zxy_netns_route_lookup(ns: u16, dest: u32) i8 {
    if (!g_netns_init or ns >= MAX_NETNS or !nm().namespaces[ns].active) return -1;
    if (nm().namespaces[ns].route_lookup(dest)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_netns_tick() void {
    if (g_netns_init) nm().process_tick();
}

export fn zxy_netns_count() u8 {
    if (!g_netns_init) return 0;
    return nm().ns_count;
}

export fn zxy_netns_total_created() u64 {
    if (!g_netns_init) return 0;
    return nm().total_created;
}

export fn zxy_netns_total_veth_tx() u64 {
    if (!g_netns_init) return 0;
    return nm().total_veth_tx;
}
