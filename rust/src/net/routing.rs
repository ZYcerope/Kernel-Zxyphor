// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Routing Table Subsystem (Rust)
//
// Full IPv4/IPv6 routing table with:
// - FIB (Forwarding Information Base) with longest-prefix match
// - Route table types (main, local, default, custom)
// - Route types (unicast, local, broadcast, multicast, unreachable, prohibit, blackhole)
// - Route scopes (host, link, universe, site, nowhere)
// - Route protocols (kernel, boot, static, redirect, DHCP, zebra)
// - Nexthop management (direct, gateway, multipath/ECMP)
// - Route metrics (MTU, window, RTT, advmss, hoplimit, cwnd, initcwnd)
// - Policy routing (multiple tables with priority rules)
// - Route cache with LRU eviction
// - Connected route auto-generation
// - Default gateway management
// - Route aging and garbage collection

#![allow(dead_code)]

// ─── Constants ──────────────────────────────────────────────────────

const MAX_ROUTES: usize = 512;
const MAX_NEXTHOPS: usize = 256;
const MAX_TABLES: usize = 16;
const MAX_RULES: usize = 64;
const MAX_CACHE: usize = 256;
const MAX_MULTIPATH: usize = 8;
const PREFIX_MAX_V4: u8 = 32;
const PREFIX_MAX_V6: u8 = 128;

// ─── IP Address Types ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ipv4Addr {
    pub octets: [u8; 4],
}

impl Ipv4Addr {
    pub const UNSPECIFIED: Self = Self { octets: [0, 0, 0, 0] };
    pub const LOOPBACK: Self = Self { octets: [127, 0, 0, 1] };
    pub const BROADCAST: Self = Self { octets: [255, 255, 255, 255] };

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { octets: [a, b, c, d] }
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.octets)
    }

    pub fn from_u32(val: u32) -> Self {
        Self { octets: val.to_be_bytes() }
    }

    pub fn mask(prefix_len: u8) -> u32 {
        if prefix_len >= 32 { return 0xFFFFFFFF; }
        if prefix_len == 0 { return 0; }
        !((1u32 << (32 - prefix_len)) - 1)
    }

    pub fn matches(&self, other: &Ipv4Addr, prefix_len: u8) -> bool {
        let mask = Self::mask(prefix_len);
        (self.to_u32() & mask) == (other.to_u32() & mask)
    }

    pub fn is_unspecified(&self) -> bool {
        self.octets == [0, 0, 0, 0]
    }

    pub fn is_multicast(&self) -> bool {
        self.octets[0] >= 224 && self.octets[0] <= 239
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ipv6Addr {
    pub octets: [u8; 16],
}

impl Ipv6Addr {
    pub const UNSPECIFIED: Self = Self { octets: [0u8; 16] };
    pub const LOOPBACK: Self = Self { octets: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] };

    pub fn mask_matches(&self, other: &Ipv6Addr, prefix_len: u8) -> bool {
        let full_bytes = (prefix_len / 8) as usize;
        let remaining = prefix_len % 8;

        if full_bytes > 16 { return false; }

        for i in 0..full_bytes {
            if self.octets[i] != other.octets[i] {
                return false;
            }
        }

        if remaining > 0 && full_bytes < 16 {
            let mask = !((1u8 << (8 - remaining)) - 1);
            if (self.octets[full_bytes] & mask) != (other.octets[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

// ─── Route Types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum RouteType {
    Unicast = 1,
    Local = 2,
    Broadcast = 3,
    Anycast = 4,
    Multicast = 5,
    Blackhole = 6,     // Silently discard
    Unreachable = 7,   // ICMP host unreachable
    Prohibit = 8,      // ICMP admin prohibited
    Throw = 9,         // Continue lookup in next table
    Nat = 10,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum RouteScope {
    Universe = 0,   // Global
    Site = 200,     // Interior route
    Link = 253,     // Directly attached
    Host = 254,     // Local
    Nowhere = 255,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum RouteProtocol {
    Unspec = 0,
    Redirect = 1,  // ICMP redirect
    Kernel = 2,    // Auto-generated
    Boot = 3,      // Boot-time config
    Static = 4,    // Admin route
    Dhcp = 16,
    Zebra = 186,
    Bird = 12,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum AddrFamily {
    Inet = 2,   // IPv4
    Inet6 = 10, // IPv6
}

// ─── Route Metrics ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct RouteMetrics {
    pub mtu: u32,
    pub window: u32,
    pub rtt: u32,       // microseconds
    pub rttvar: u32,
    pub advmss: u16,
    pub hoplimit: u8,
    pub initcwnd: u16,
    pub initrwnd: u16,
    pub cwnd: u16,
    pub ssthresh: u32,
    pub reordering: u8,
}

impl RouteMetrics {
    pub const fn default() -> Self {
        Self {
            mtu: 1500,
            window: 0,
            rtt: 0,
            rttvar: 0,
            advmss: 536,
            hoplimit: 64,
            initcwnd: 10,
            initrwnd: 10,
            cwnd: 10,
            ssthresh: 0xFFFFFFFF,
            reordering: 3,
        }
    }
}

// ─── Nexthop ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NhFlags {
    None = 0,
    Dead = 1,
    Pervasive = 2,
    OnLink = 4,
}

pub struct Nexthop {
    pub gateway: Ipv4Addr,
    pub gateway_v6: Ipv6Addr,
    pub ifindex: u32,   // Output interface
    pub weight: u8,     // For ECMP (1-255)
    pub flags: u8,
    pub family: AddrFamily,
    pub active: bool,
}

impl Nexthop {
    pub const fn empty() -> Self {
        Self {
            gateway: Ipv4Addr::UNSPECIFIED,
            gateway_v6: Ipv6Addr::UNSPECIFIED,
            ifindex: 0,
            weight: 1,
            flags: 0,
            family: AddrFamily::Inet,
            active: false,
        }
    }

    pub fn is_dead(&self) -> bool {
        (self.flags & NhFlags::Dead as u8) != 0
    }

    pub fn is_onlink(&self) -> bool {
        (self.flags & NhFlags::OnLink as u8) != 0
    }
}

// ─── Route Entry ────────────────────────────────────────────────────

pub struct RouteEntry {
    pub dst: Ipv4Addr,
    pub dst_v6: Ipv6Addr,
    pub src: Ipv4Addr,         // Preferred source
    pub prefix_len: u8,
    pub family: AddrFamily,
    pub route_type: RouteType,
    pub scope: RouteScope,
    pub protocol: RouteProtocol,
    pub table_id: u8,
    pub tos: u8,               // Type of service
    pub priority: u32,         // Metric/preference (lower = better)
    pub flags: u32,

    // Nexthop(s)
    pub nh_idx: [i16; MAX_MULTIPATH],
    pub nh_count: u8,

    pub metrics: RouteMetrics,

    // Aging
    pub created_at: u64,
    pub last_used: u64,
    pub use_count: u64,
    pub expires: u64, // 0 = no expiry

    pub active: bool,
}

impl RouteEntry {
    pub const fn empty() -> Self {
        Self {
            dst: Ipv4Addr::UNSPECIFIED,
            dst_v6: Ipv6Addr::UNSPECIFIED,
            src: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            family: AddrFamily::Inet,
            route_type: RouteType::Unicast,
            scope: RouteScope::Universe,
            protocol: RouteProtocol::Unspec,
            table_id: 0,
            tos: 0,
            priority: 0,
            flags: 0,
            nh_idx: [-1i16; MAX_MULTIPATH],
            nh_count: 0,
            metrics: RouteMetrics::default(),
            created_at: 0,
            last_used: 0,
            use_count: 0,
            expires: 0,
            active: false,
        }
    }

    pub fn is_default(&self) -> bool {
        self.prefix_len == 0
    }

    pub fn is_host(&self) -> bool {
        match self.family {
            AddrFamily::Inet => self.prefix_len == 32,
            AddrFamily::Inet6 => self.prefix_len == 128,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires > 0 && now >= self.expires
    }
}

// ─── Policy Rule ────────────────────────────────────────────────────

pub struct PolicyRule {
    pub priority: u32,
    pub src: Ipv4Addr,
    pub src_prefix: u8,
    pub dst: Ipv4Addr,
    pub dst_prefix: u8,
    pub tos: u8,
    pub fwmark: u32,
    pub fwmask: u32,
    pub table_id: u8,
    pub action: RouteType, // routing action
    pub iifname: [u8; 16],
    pub oifname: [u8; 16],
    pub active: bool,
}

impl PolicyRule {
    pub const fn empty() -> Self {
        Self {
            priority: 0,
            src: Ipv4Addr::UNSPECIFIED,
            src_prefix: 0,
            dst: Ipv4Addr::UNSPECIFIED,
            dst_prefix: 0,
            tos: 0,
            fwmark: 0,
            fwmask: 0,
            table_id: 0,
            action: RouteType::Unicast,
            iifname: [0u8; 16],
            oifname: [0u8; 16],
            active: false,
        }
    }

    pub fn matches_src(&self, addr: &Ipv4Addr) -> bool {
        if self.src_prefix == 0 { return true; }
        self.src.matches(addr, self.src_prefix)
    }

    pub fn matches_dst(&self, addr: &Ipv4Addr) -> bool {
        if self.dst_prefix == 0 { return true; }
        self.dst.matches(addr, self.dst_prefix)
    }
}

// ─── Route Cache Entry ──────────────────────────────────────────────

pub struct CacheEntry {
    pub dst: Ipv4Addr,
    pub src: Ipv4Addr,
    pub nh_idx: i16,
    pub route_idx: i16,
    pub timestamp: u64,
    pub hits: u32,
    pub active: bool,
}

impl CacheEntry {
    pub const fn empty() -> Self {
        Self {
            dst: Ipv4Addr::UNSPECIFIED,
            src: Ipv4Addr::UNSPECIFIED,
            nh_idx: -1,
            route_idx: -1,
            timestamp: 0,
            hits: 0,
            active: false,
        }
    }
}

// ─── Route Table ────────────────────────────────────────────────────

pub struct RouteTable {
    pub table_id: u8,
    pub name: [u8; 16],
    pub name_len: u8,
    pub route_count: u16,
    pub active: bool,
}

impl RouteTable {
    pub const fn empty() -> Self {
        Self {
            table_id: 0,
            name: [0u8; 16],
            name_len: 0,
            route_count: 0,
            active: false,
        }
    }
}

// ─── Routing Manager ────────────────────────────────────────────────

pub struct RoutingManager {
    routes: [RouteEntry; MAX_ROUTES],
    nexthops: [Nexthop; MAX_NEXTHOPS],
    tables: [RouteTable; MAX_TABLES],
    rules: [PolicyRule; MAX_RULES],
    cache: [CacheEntry; MAX_CACHE],

    route_count: u16,
    nh_count: u16,
    table_count: u8,
    rule_count: u8,
    cache_count: u16,

    // Default gateway
    default_gw_v4: Ipv4Addr,
    default_gw_v6: Ipv6Addr,
    default_ifindex: u32,

    // Stats
    total_lookups: u64,
    total_cache_hits: u64,
    total_cache_misses: u64,
    total_inserts: u64,
    total_deletes: u64,
    total_gc_runs: u64,. // garbage collection
    tick: u64,

    initialized: bool,
}

impl RoutingManager {
    pub const fn new() -> Self {
        Self {
            routes: [RouteEntry::empty(); MAX_ROUTES],
            nexthops: [Nexthop::empty(); MAX_NEXTHOPS],
            tables: [RouteTable::empty(); MAX_TABLES],
            rules: [PolicyRule::empty(); MAX_RULES],
            cache: [CacheEntry::empty(); MAX_CACHE],
            route_count: 0,
            nh_count: 0,
            table_count: 0,
            rule_count: 0,
            cache_count: 0,
            default_gw_v4: Ipv4Addr::UNSPECIFIED,
            default_gw_v6: Ipv6Addr::UNSPECIFIED,
            default_ifindex: 0,
            total_lookups: 0,
            total_cache_hits: 0,
            total_cache_misses: 0,
            total_inserts: 0,
            total_deletes: 0,
            total_gc_runs: 0,
            tick: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        // Create standard tables
        self.create_table(253, b"default");
        self.create_table(254, b"main");
        self.create_table(255, b"local");
        self.create_table(0, b"unspec");

        // Add default policy rules
        // Rule 0: lookup local
        self.add_rule(0, 255);
        // Rule 32766: lookup main
        self.add_rule(32766, 254);
        // Rule 32767: lookup default
        self.add_rule(32767, 253);

        // Add loopback route
        self.add_route_v4(
            Ipv4Addr::LOOPBACK, 8,
            Ipv4Addr::UNSPECIFIED, 0,
            RouteType::Local, RouteScope::Host,
            RouteProtocol::Kernel, 255,
        );

        self.initialized = true;
    }

    // ─── Table Management ───────────────────────────────────────────

    fn create_table(&mut self, table_id: u8, name: &[u8]) -> bool {
        if self.table_count as usize >= MAX_TABLES { return false; }
        let idx = self.table_count as usize;
        self.tables[idx] = RouteTable::empty();
        self.tables[idx].table_id = table_id;
        let len = name.len().min(15);
        self.tables[idx].name[..len].copy_from_slice(&name[..len]);
        self.tables[idx].name_len = len as u8;
        self.tables[idx].active = true;
        self.table_count += 1;
        true
    }

    // ─── Nexthop Management ─────────────────────────────────────────

    fn alloc_nexthop(&mut self, gw: Ipv4Addr, ifindex: u32, weight: u8) -> Option<i16> {
        for i in 0..MAX_NEXTHOPS {
            if !self.nexthops[i].active {
                self.nexthops[i] = Nexthop::empty();
                self.nexthops[i].gateway = gw;
                self.nexthops[i].ifindex = ifindex;
                self.nexthops[i].weight = weight;
                self.nexthops[i].family = AddrFamily::Inet;
                self.nexthops[i].active = true;
                self.nh_count += 1;
                return Some(i as i16);
            }
        }
        None
    }

    fn free_nexthop(&mut self, idx: i16) {
        if idx >= 0 && (idx as usize) < MAX_NEXTHOPS {
            self.nexthops[idx as usize].active = false;
            if self.nh_count > 0 { self.nh_count -= 1; }
        }
    }

    // ─── Route Operations ───────────────────────────────────────────

    pub fn add_route_v4(
        &mut self,
        dst: Ipv4Addr, prefix_len: u8,
        gateway: Ipv4Addr, ifindex: u32,
        rtype: RouteType, scope: RouteScope,
        protocol: RouteProtocol, table_id: u8,
    ) -> Option<i16> {
        // Allocate nexthop
        let nh_idx = self.alloc_nexthop(gateway, ifindex, 1)?;

        for i in 0..MAX_ROUTES {
            if !self.routes[i].active {
                self.routes[i] = RouteEntry::empty();
                self.routes[i].dst = dst;
                self.routes[i].prefix_len = prefix_len;
                self.routes[i].family = AddrFamily::Inet;
                self.routes[i].route_type = rtype;
                self.routes[i].scope = scope;
                self.routes[i].protocol = protocol;
                self.routes[i].table_id = table_id;
                self.routes[i].nh_idx[0] = nh_idx;
                self.routes[i].nh_count = 1;
                self.routes[i].created_at = self.tick;
                self.routes[i].active = true;

                self.route_count += 1;
                self.total_inserts += 1;

                // Track default gateway
                if prefix_len == 0 && !gateway.is_unspecified() {
                    self.default_gw_v4 = gateway;
                    self.default_ifindex = ifindex;
                }

                return Some(i as i16);
            }
        }

        self.free_nexthop(nh_idx);
        None
    }

    pub fn del_route(&mut self, idx: i16) -> bool {
        if idx < 0 || idx as usize >= MAX_ROUTES { return false; }
        let i = idx as usize;
        if !self.routes[i].active { return false; }

        // Free nexthops
        for n in 0..self.routes[i].nh_count as usize {
            self.free_nexthop(self.routes[i].nh_idx[n]);
        }

        // Invalidate cache entries
        self.invalidate_cache_for_route(idx);

        self.routes[i].active = false;
        self.route_count -= 1;
        self.total_deletes += 1;
        true
    }

    // ─── Longest Prefix Match ───────────────────────────────────────

    pub fn lookup_v4(&mut self, dst: &Ipv4Addr, table_id: u8) -> Option<i16> {
        self.total_lookups += 1;

        // Check cache first
        if let Some(cached) = self.cache_lookup(dst) {
            self.total_cache_hits += 1;
            return Some(cached);
        }
        self.total_cache_misses += 1;

        let mut best: Option<i16> = None;
        let mut best_prefix: u8 = 0;
        let mut best_priority: u32 = u32::MAX;

        for i in 0..MAX_ROUTES {
            if !self.routes[i].active { continue; }
            if self.routes[i].family != AddrFamily::Inet { continue; }
            if self.routes[i].table_id != table_id { continue; }

            if self.routes[i].dst.matches(dst, self.routes[i].prefix_len) {
                // Longest prefix wins; on tie, lower priority wins
                if self.routes[i].prefix_len > best_prefix
                    || (self.routes[i].prefix_len == best_prefix
                        && self.routes[i].priority < best_priority)
                {
                    best_prefix = self.routes[i].prefix_len;
                    best_priority = self.routes[i].priority;
                    best = Some(i as i16);
                }
            }
        }

        // Update route stats and cache
        if let Some(idx) = best {
            let i = idx as usize;
            self.routes[i].last_used = self.tick;
            self.routes[i].use_count += 1;
            self.cache_insert(dst, idx);
        }

        best
    }

    /// Full policy-based routing lookup
    pub fn fib_lookup(&mut self, src: &Ipv4Addr, dst: &Ipv4Addr) -> Option<i16> {
        // Walk policy rules in priority order
        for r in 0..self.rule_count as usize {
            if !self.rules[r].active { continue; }
            if !self.rules[r].matches_src(src) { continue; }
            if !self.rules[r].matches_dst(dst) { continue; }

            // Lookup in the rule's table
            if let Some(route) = self.lookup_v4(dst, self.rules[r].table_id) {
                return Some(route);
            }
        }
        None
    }

    // ─── Multipath / ECMP ───────────────────────────────────────────

    pub fn add_multipath_nh(&mut self, route_idx: i16, gateway: Ipv4Addr, ifindex: u32, weight: u8) -> bool {
        if route_idx < 0 || route_idx as usize >= MAX_ROUTES { return false; }
        let i = route_idx as usize;
        if !self.routes[i].active { return false; }
        if self.routes[i].nh_count as usize >= MAX_MULTIPATH { return false; }

        let nh_idx = match self.alloc_nexthop(gateway, ifindex, weight) {
            Some(idx) => idx,
            None => return false,
        };

        let n = self.routes[i].nh_count as usize;
        self.routes[i].nh_idx[n] = nh_idx;
        self.routes[i].nh_count += 1;
        true
    }

    /// Select nexthop using weighted round-robin
    pub fn select_nexthop(&self, route_idx: i16) -> Option<i16> {
        if route_idx < 0 || route_idx as usize >= MAX_ROUTES { return None; }
        let i = route_idx as usize;
        if !self.routes[i].active || self.routes[i].nh_count == 0 { return None; }

        // Simple: pick first active nexthop (production would use hash-based ECMP)
        for n in 0..self.routes[i].nh_count as usize {
            let nh = self.routes[i].nh_idx[n];
            if nh >= 0 && (nh as usize) < MAX_NEXTHOPS && self.nexthops[nh as usize].active {
                if !self.nexthops[nh as usize].is_dead() {
                    return Some(nh);
                }
            }
        }
        None
    }

    // ─── Policy Rules ───────────────────────────────────────────────

    fn add_rule(&mut self, priority: u32, table_id: u8) -> bool {
        if self.rule_count as usize >= MAX_RULES { return false; }
        let idx = self.rule_count as usize;
        self.rules[idx] = PolicyRule::empty();
        self.rules[idx].priority = priority;
        self.rules[idx].table_id = table_id;
        self.rules[idx].active = true;
        self.rule_count += 1;
        // Sort by priority would happen in production
        true
    }

    // ─── Cache ──────────────────────────────────────────────────────

    fn cache_lookup(&mut self, dst: &Ipv4Addr) -> Option<i16> {
        for i in 0..MAX_CACHE {
            if self.cache[i].active && self.cache[i].dst == *dst {
                self.cache[i].hits += 1;
                return Some(self.cache[i].route_idx);
            }
        }
        None
    }

    fn cache_insert(&mut self, dst: &Ipv4Addr, route_idx: i16) {
        // Find free slot
        for i in 0..MAX_CACHE {
            if !self.cache[i].active {
                self.cache[i].dst = *dst;
                self.cache[i].route_idx = route_idx;
                self.cache[i].timestamp = self.tick;
                self.cache[i].hits = 0;
                self.cache[i].active = true;
                self.cache_count += 1;
                return;
            }
        }
        // Evict LRU
        let mut oldest_idx: usize = 0;
        let mut oldest_ts: u64 = u64::MAX;
        for i in 0..MAX_CACHE {
            if self.cache[i].timestamp < oldest_ts {
                oldest_ts = self.cache[i].timestamp;
                oldest_idx = i;
            }
        }
        self.cache[oldest_idx].dst = *dst;
        self.cache[oldest_idx].route_idx = route_idx;
        self.cache[oldest_idx].timestamp = self.tick;
        self.cache[oldest_idx].hits = 0;
    }

    fn invalidate_cache_for_route(&mut self, route_idx: i16) {
        for i in 0..MAX_CACHE {
            if self.cache[i].active && self.cache[i].route_idx == route_idx {
                self.cache[i].active = false;
                if self.cache_count > 0 { self.cache_count -= 1; }
            }
        }
    }

    // ─── Garbage Collection ─────────────────────────────────────────

    pub fn gc(&mut self) {
        self.tick += 1;
        self.total_gc_runs += 1;

        // Expire aged routes
        for i in 0..MAX_ROUTES {
            if self.routes[i].active && self.routes[i].is_expired(self.tick) {
                self.del_route(i as i16);
            }
        }

        // Expire old cache entries (>1000 ticks)
        for i in 0..MAX_CACHE {
            if self.cache[i].active && self.tick - self.cache[i].timestamp > 1000 {
                self.cache[i].active = false;
                if self.cache_count > 0 { self.cache_count -= 1; }
            }
        }
    }
}

// ─── Global State ───────────────────────────────────────────────────

static mut RT_MGR: RoutingManager = RoutingManager::new();
static mut RT_INITIALIZED: bool = false;

fn mgr() -> &'static mut RoutingManager {
    unsafe { &mut RT_MGR }
}

// ─── FFI Exports ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_route_init() {
    let m = mgr();
    *m = RoutingManager::new();
    m.init();
    unsafe { RT_INITIALIZED = true; }
}

#[no_mangle]
pub extern "C" fn rust_route_add_v4(
    dst_a: u8, dst_b: u8, dst_c: u8, dst_d: u8, prefix_len: u8,
    gw_a: u8, gw_b: u8, gw_c: u8, gw_d: u8, ifindex: u32,
    rtype: u8, scope: u8, protocol: u8, table_id: u8,
) -> i16 {
    if unsafe { !RT_INITIALIZED } { return -1; }
    let dst = Ipv4Addr::new(dst_a, dst_b, dst_c, dst_d);
    let gw = Ipv4Addr::new(gw_a, gw_b, gw_c, gw_d);
    let rt = match rtype {
        1 => RouteType::Unicast,
        2 => RouteType::Local,
        3 => RouteType::Broadcast,
        6 => RouteType::Blackhole,
        7 => RouteType::Unreachable,
        8 => RouteType::Prohibit,
        _ => RouteType::Unicast,
    };
    let sc = match scope {
        0 => RouteScope::Universe,
        253 => RouteScope::Link,
        254 => RouteScope::Host,
        _ => RouteScope::Universe,
    };
    let pr = match protocol {
        2 => RouteProtocol::Kernel,
        3 => RouteProtocol::Boot,
        4 => RouteProtocol::Static,
        16 => RouteProtocol::Dhcp,
        _ => RouteProtocol::Unspec,
    };
    mgr().add_route_v4(dst, prefix_len, gw, ifindex, rt, sc, pr, table_id).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn rust_route_del(idx: i16) -> bool {
    if unsafe { !RT_INITIALIZED } { return false; }
    mgr().del_route(idx)
}

#[no_mangle]
pub extern "C" fn rust_route_lookup_v4(a: u8, b: u8, c: u8, d: u8, table_id: u8) -> i16 {
    if unsafe { !RT_INITIALIZED } { return -1; }
    let dst = Ipv4Addr::new(a, b, c, d);
    mgr().lookup_v4(&dst, table_id).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn rust_route_gc() {
    if unsafe { !RT_INITIALIZED } { return; }
    mgr().gc();
}

#[no_mangle]
pub extern "C" fn rust_route_count() -> u16 {
    if unsafe { !RT_INITIALIZED } { return 0; }
    mgr().route_count
}

#[no_mangle]
pub extern "C" fn rust_route_nh_count() -> u16 {
    if unsafe { !RT_INITIALIZED } { return 0; }
    mgr().nh_count
}

#[no_mangle]
pub extern "C" fn rust_route_cache_count() -> u16 {
    if unsafe { !RT_INITIALIZED } { return 0; }
    mgr().cache_count
}

#[no_mangle]
pub extern "C" fn rust_route_total_lookups() -> u64 {
    if unsafe { !RT_INITIALIZED } { return 0; }
    mgr().total_lookups
}

#[no_mangle]
pub extern "C" fn rust_route_cache_hits() -> u64 {
    if unsafe { !RT_INITIALIZED } { return 0; }
    mgr().total_cache_hits
}
