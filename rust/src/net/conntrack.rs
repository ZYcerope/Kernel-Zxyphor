// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Netfilter / Connection Tracking (Rust)
//
// Stateful packet filtering and connection tracking:
// - 5-tuple flow identification (proto, src/dst addr, src/dst port)
// - Connection tracking table with hash-bucket lookup
// - TCP state machine tracking (SYN, ESTABLISHED, FIN_WAIT, etc.)
// - UDP/ICMP connection tracking with timeout
// - NAT (SNAT/DNAT) address/port rewriting
// - Netfilter hooks (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING)
// - Rule chains with priority ordering
// - Match criteria (addr, port, protocol, state, mark)
// - Target actions (ACCEPT, DROP, REJECT, SNAT, DNAT, MASQUERADE, LOG, MARK)
// - Per-connection byte/packet counters
// - Connection aging with configurable timeouts
// - Expectation tracking for related connections (FTP, SIP)

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_CONNECTIONS: usize = 512;
const MAX_RULES: usize = 128;
const MAX_CHAINS: usize = 16;
const MAX_EXPECTATIONS: usize = 32;
const MAX_NAT_ENTRIES: usize = 128;
const HASH_BUCKETS: usize = 64;
const CT_NAME_MAX: usize = 32;

// ─────────────────── Protocol ───────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum IpProto {
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    Icmpv6 = 58,
    Sctp = 132,
    Gre = 47,
    Any = 0,
}

// ─────────────────── 5-Tuple ────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub struct Tuple {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: IpProto,
}

impl Tuple {
    pub const fn empty() -> Self {
        Self {
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
            proto: IpProto::Any,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }

    pub fn hash(&self) -> usize {
        let mut h = self.src_addr as usize;
        h = h.wrapping_mul(31).wrapping_add(self.dst_addr as usize);
        h = h.wrapping_mul(31).wrapping_add(self.src_port as usize);
        h = h.wrapping_mul(31).wrapping_add(self.dst_port as usize);
        h = h.wrapping_mul(31).wrapping_add(self.proto as usize);
        h % HASH_BUCKETS
    }

    pub fn matches(&self, other: &Tuple) -> bool {
        self.src_addr == other.src_addr
            && self.dst_addr == other.dst_addr
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.proto == other.proto
    }
}

// ─────────────────── TCP State ──────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TcpConnState {
    None = 0,
    SynSent = 1,
    SynRecv = 2,
    Established = 3,
    FinWait = 4,
    CloseWait = 5,
    LastAck = 6,
    TimeWait = 7,
    Close = 8,
    Listen = 9,
    SynSent2 = 10, // Simultaneous open
}

// ─────────────────── Connection State ───────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ConnStatus {
    New = 0,
    Established = 1,
    Related = 2,
    Invalid = 3,
}

#[derive(Clone, Copy)]
pub struct ConnTrackEntry {
    pub id: u32,
    pub original: Tuple,
    pub reply: Tuple,
    pub status: ConnStatus,
    pub tcp_state: TcpConnState,

    // NAT rewrite (if any)
    pub nat_src_addr: u32,
    pub nat_dst_addr: u32,
    pub nat_src_port: u16,
    pub nat_dst_port: u16,
    pub snat_active: bool,
    pub dnat_active: bool,

    // Counters
    pub packets_orig: u64,
    pub bytes_orig: u64,
    pub packets_reply: u64,
    pub bytes_reply: u64,

    // Timing
    pub create_tick: u64,
    pub last_seen: u64,
    pub timeout: u64,

    // Flags
    pub assured: bool,     // Seen traffic in both directions
    pub confirmed: bool,
    pub dying: bool,
    pub mark: u32,
    pub zone: u16,         // Conntrack zone for namespaces

    pub active: bool,
}

impl ConnTrackEntry {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            original: Tuple::empty(),
            reply: Tuple::empty(),
            status: ConnStatus::New,
            tcp_state: TcpConnState::None,
            nat_src_addr: 0,
            nat_dst_addr: 0,
            nat_src_port: 0,
            nat_dst_port: 0,
            snat_active: false,
            dnat_active: false,
            packets_orig: 0,
            bytes_orig: 0,
            packets_reply: 0,
            bytes_reply: 0,
            create_tick: 0,
            last_seen: 0,
            timeout: 0,
            assured: false,
            confirmed: false,
            dying: false,
            mark: 0,
            zone: 0,
            active: false,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now > self.last_seen + self.timeout
    }

    pub fn update_counters(&mut self, bytes: u32, is_reply: bool) {
        if is_reply {
            self.packets_reply += 1;
            self.bytes_reply += bytes as u64;
            if !self.assured {
                self.assured = true;
                self.status = ConnStatus::Established;
            }
        } else {
            self.packets_orig += 1;
            self.bytes_orig += bytes as u64;
        }
    }
}

// ─────────────────── Conntrack Timeouts ─────────────────────────────

pub struct ConnTrackTimeouts {
    pub tcp_syn_sent: u64,
    pub tcp_syn_recv: u64,
    pub tcp_established: u64,
    pub tcp_fin_wait: u64,
    pub tcp_close_wait: u64,
    pub tcp_last_ack: u64,
    pub tcp_time_wait: u64,
    pub tcp_close: u64,
    pub udp_unreplied: u64,
    pub udp_replied: u64,
    pub icmp_timeout: u64,
    pub generic_timeout: u64,
}

impl ConnTrackTimeouts {
    pub const fn defaults() -> Self {
        Self {
            tcp_syn_sent: 120_000,
            tcp_syn_recv: 60_000,
            tcp_established: 432_000_000,  // 5 days
            tcp_fin_wait: 120_000,
            tcp_close_wait: 60_000,
            tcp_last_ack: 30_000,
            tcp_time_wait: 120_000,
            tcp_close: 10_000,
            udp_unreplied: 30_000,
            udp_replied: 180_000,
            icmp_timeout: 30_000,
            generic_timeout: 600_000,
        }
    }

    pub fn timeout_for_tcp(&self, state: TcpConnState) -> u64 {
        match state {
            TcpConnState::SynSent | TcpConnState::SynSent2 => self.tcp_syn_sent,
            TcpConnState::SynRecv => self.tcp_syn_recv,
            TcpConnState::Established => self.tcp_established,
            TcpConnState::FinWait => self.tcp_fin_wait,
            TcpConnState::CloseWait => self.tcp_close_wait,
            TcpConnState::LastAck => self.tcp_last_ack,
            TcpConnState::TimeWait => self.tcp_time_wait,
            TcpConnState::Close => self.tcp_close,
            _ => self.generic_timeout,
        }
    }
}

// ─────────────────── Hash Table ─────────────────────────────────────

#[derive(Clone, Copy)]
pub struct HashBucket {
    pub entries: [i16; 16], // Indices into conntrack table
    pub count: u8,
}

impl HashBucket {
    pub const fn empty() -> Self {
        Self {
            entries: [-1; 16],
            count: 0,
        }
    }

    pub fn insert(&mut self, idx: i16) -> bool {
        if self.count >= 16 { return false; }
        self.entries[self.count as usize] = idx;
        self.count += 1;
        true
    }

    pub fn remove(&mut self, idx: i16) {
        for i in 0..self.count as usize {
            if self.entries[i] == idx {
                let last = self.count as usize - 1;
                self.entries[i] = self.entries[last];
                self.entries[last] = -1;
                self.count -= 1;
                return;
            }
        }
    }
}

// ─────────────────── Netfilter Hooks ────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NfHook {
    PreRouting = 0,
    LocalIn = 1,
    Forward = 2,
    LocalOut = 3,
    PostRouting = 4,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NfTarget {
    Accept = 0,
    Drop = 1,
    Reject = 2,
    Snat = 3,
    Dnat = 4,
    Masquerade = 5,
    Log = 6,
    Mark = 7,
    Return = 8,
    Jump = 9,
    Queue = 10,
    Continue = 11,
}

// ─────────────────── Rule Match ─────────────────────────────────────

#[derive(Clone, Copy)]
pub struct RuleMatch {
    // Address matching (0 = any)
    pub src_addr: u32,
    pub src_mask: u32,
    pub dst_addr: u32,
    pub dst_mask: u32,

    // Port range
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,

    // Protocol
    pub proto: IpProto,

    // Connection state match
    pub ct_state_mask: u8, // Bitmask of ConnStatus

    // Mark match
    pub mark: u32,
    pub mark_mask: u32,

    // Invert flags
    pub invert_src: bool,
    pub invert_dst: bool,
    pub invert_proto: bool,
    pub invert_state: bool,
}

impl RuleMatch {
    pub const fn any() -> Self {
        Self {
            src_addr: 0,
            src_mask: 0,
            dst_addr: 0,
            dst_mask: 0,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 0,
            dst_port_max: 65535,
            proto: IpProto::Any,
            ct_state_mask: 0xFF,
            mark: 0,
            mark_mask: 0,
            invert_src: false,
            invert_dst: false,
            invert_proto: false,
            invert_state: false,
        }
    }

    pub fn matches_packet(&self, tuple: &Tuple, ct_status: ConnStatus, pkt_mark: u32) -> bool {
        // Source address
        let src_match = (tuple.src_addr & self.src_mask) == (self.src_addr & self.src_mask);
        if src_match == self.invert_src { return false; }

        // Destination address
        let dst_match = (tuple.dst_addr & self.dst_mask) == (self.dst_addr & self.dst_mask);
        if dst_match == self.invert_dst { return false; }

        // Protocol
        if self.proto != IpProto::Any {
            let proto_match = tuple.proto == self.proto;
            if proto_match == self.invert_proto { return false; }
        }

        // Source port range
        if tuple.src_port < self.src_port_min || tuple.src_port > self.src_port_max {
            return false;
        }

        // Destination port range
        if tuple.dst_port < self.dst_port_min || tuple.dst_port > self.dst_port_max {
            return false;
        }

        // Connection state
        if self.ct_state_mask != 0xFF {
            let state_bit = 1u8 << (ct_status as u8);
            let state_match = (self.ct_state_mask & state_bit) != 0;
            if state_match == self.invert_state { return false; }
        }

        // Mark
        if self.mark_mask != 0 {
            if (pkt_mark & self.mark_mask) != (self.mark & self.mark_mask) {
                return false;
            }
        }

        true
    }
}

// ─────────────────── Firewall Rule ──────────────────────────────────

#[derive(Clone, Copy)]
pub struct NfRule {
    pub id: u32,
    pub chain_idx: u8,
    pub priority: i16, // Lower = higher priority
    pub match_criteria: RuleMatch,
    pub target: NfTarget,

    // NAT parameters
    pub nat_addr: u32,
    pub nat_port_min: u16,
    pub nat_port_max: u16,

    // Mark set value
    pub set_mark: u32,
    pub set_mark_mask: u32,

    // Jump target chain
    pub jump_chain: u8,

    // Log prefix
    pub log_prefix: [u8; CT_NAME_MAX],
    pub log_prefix_len: u8,

    // Counters
    pub hit_count: u64,
    pub byte_count: u64,

    pub active: bool,
}

impl NfRule {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            chain_idx: 0,
            priority: 0,
            match_criteria: RuleMatch::any(),
            target: NfTarget::Accept,
            nat_addr: 0,
            nat_port_min: 0,
            nat_port_max: 0,
            set_mark: 0,
            set_mark_mask: 0,
            jump_chain: 0,
            log_prefix: [0u8; CT_NAME_MAX],
            log_prefix_len: 0,
            hit_count: 0,
            byte_count: 0,
            active: false,
        }
    }
}

// ─────────────────── Chain ──────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ChainType {
    Filter = 0,
    Nat = 1,
    Mangle = 2,
    Raw = 3,
}

#[derive(Clone, Copy)]
pub struct NfChain {
    pub name: [u8; CT_NAME_MAX],
    pub name_len: u8,
    pub hook: NfHook,
    pub chain_type: ChainType,
    pub default_target: NfTarget,
    pub policy: NfTarget, // Default policy (ACCEPT or DROP)
    pub rule_count: u32,
    pub active: bool,
}

impl NfChain {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; CT_NAME_MAX],
            name_len: 0,
            hook: NfHook::LocalIn,
            chain_type: ChainType::Filter,
            default_target: NfTarget::Accept,
            policy: NfTarget::Accept,
            rule_count: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() < CT_NAME_MAX { n.len() } else { CT_NAME_MAX };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

// ─────────────────── Expectation ────────────────────────────────────

/// Expected connection (for protocols like FTP that create data channels)
#[derive(Clone, Copy)]
pub struct Expectation {
    pub master_id: u32,    // Master connection ID
    pub expected: Tuple,   // Expected tuple
    pub mask: Tuple,       // Which fields to match (non-zero = must match)
    pub create_tick: u64,
    pub timeout: u64,
    pub active: bool,
}

impl Expectation {
    pub const fn empty() -> Self {
        Self {
            master_id: 0,
            expected: Tuple::empty(),
            mask: Tuple::empty(),
            create_tick: 0,
            timeout: 300_000,
            active: false,
        }
    }
}

// ─────────────────── Netfilter Manager ──────────────────────────────

pub struct NetfilterManager {
    pub connections: [ConnTrackEntry; MAX_CONNECTIONS],
    pub hash_table: [HashBucket; HASH_BUCKETS],
    pub rules: [NfRule; MAX_RULES],
    pub chains: [NfChain; MAX_CHAINS],
    pub expectations: [Expectation; MAX_EXPECTATIONS],
    pub timeouts: ConnTrackTimeouts,

    pub conn_count: u32,
    pub rule_count: u32,
    pub chain_count: u8,
    pub next_conn_id: u32,
    pub next_rule_id: u32,
    pub tick: u64,

    // Stats
    pub total_packets: u64,
    pub total_accepted: u64,
    pub total_dropped: u64,
    pub total_rejected: u64,
    pub total_nat_rewrites: u64,
    pub total_ct_created: u64,
    pub total_ct_destroyed: u64,
    pub total_ct_expired: u64,
    pub total_expectation_hits: u64,

    pub initialized: bool,
}

impl NetfilterManager {
    pub fn new() -> Self {
        let mut nf = Self {
            connections: [ConnTrackEntry::empty(); MAX_CONNECTIONS],
            hash_table: [HashBucket::empty(); HASH_BUCKETS],
            rules: [NfRule::empty(); MAX_RULES],
            chains: [NfChain::empty(); MAX_CHAINS],
            expectations: [Expectation::empty(); MAX_EXPECTATIONS],
            timeouts: ConnTrackTimeouts::defaults(),
            conn_count: 0,
            rule_count: 0,
            chain_count: 0,
            next_conn_id: 1,
            next_rule_id: 1,
            tick: 0,
            total_packets: 0,
            total_accepted: 0,
            total_dropped: 0,
            total_rejected: 0,
            total_nat_rewrites: 0,
            total_ct_created: 0,
            total_ct_destroyed: 0,
            total_ct_expired: 0,
            total_expectation_hits: 0,
            initialized: true,
        };

        // Create default chains
        nf.create_chain(b"INPUT", NfHook::LocalIn, ChainType::Filter, NfTarget::Accept);
        nf.create_chain(b"FORWARD", NfHook::Forward, ChainType::Filter, NfTarget::Accept);
        nf.create_chain(b"OUTPUT", NfHook::LocalOut, ChainType::Filter, NfTarget::Accept);
        nf.create_chain(b"PREROUTING", NfHook::PreRouting, ChainType::Nat, NfTarget::Accept);
        nf.create_chain(b"POSTROUTING", NfHook::PostRouting, ChainType::Nat, NfTarget::Accept);

        nf
    }

    // ─── Chain Management ───────────────────────────────────────────

    pub fn create_chain(&mut self, name: &[u8], hook: NfHook, ctype: ChainType, policy: NfTarget) -> Option<u8> {
        if self.chain_count as usize >= MAX_CHAINS {
            return None;
        }
        for i in 0..MAX_CHAINS {
            if !self.chains[i].active {
                self.chains[i] = NfChain::empty();
                self.chains[i].set_name(name);
                self.chains[i].hook = hook;
                self.chains[i].chain_type = ctype;
                self.chains[i].policy = policy;
                self.chains[i].default_target = policy;
                self.chains[i].active = true;
                self.chain_count += 1;
                return Some(i as u8);
            }
        }
        None
    }

    // ─── Rule Management ────────────────────────────────────────────

    pub fn add_rule(&mut self, chain_idx: u8, priority: i16, criteria: RuleMatch, target: NfTarget) -> Option<u32> {
        if chain_idx as usize >= MAX_CHAINS || !self.chains[chain_idx as usize].active {
            return None;
        }
        for i in 0..MAX_RULES {
            if !self.rules[i].active {
                self.rules[i] = NfRule::empty();
                self.rules[i].id = self.next_rule_id;
                self.rules[i].chain_idx = chain_idx;
                self.rules[i].priority = priority;
                self.rules[i].match_criteria = criteria;
                self.rules[i].target = target;
                self.rules[i].active = true;
                self.next_rule_id += 1;
                self.rule_count += 1;
                self.chains[chain_idx as usize].rule_count += 1;
                return Some(self.rules[i].id);
            }
        }
        None
    }

    pub fn add_snat_rule(&mut self, chain_idx: u8, criteria: RuleMatch, nat_addr: u32, port_min: u16, port_max: u16) -> Option<u32> {
        let rule_id = self.add_rule(chain_idx, 0, criteria, NfTarget::Snat)?;
        // Find the rule we just added
        for i in 0..MAX_RULES {
            if self.rules[i].active && self.rules[i].id == rule_id {
                self.rules[i].nat_addr = nat_addr;
                self.rules[i].nat_port_min = port_min;
                self.rules[i].nat_port_max = port_max;
                break;
            }
        }
        Some(rule_id)
    }

    pub fn add_dnat_rule(&mut self, chain_idx: u8, criteria: RuleMatch, nat_addr: u32, nat_port: u16) -> Option<u32> {
        let rule_id = self.add_rule(chain_idx, 0, criteria, NfTarget::Dnat)?;
        for i in 0..MAX_RULES {
            if self.rules[i].active && self.rules[i].id == rule_id {
                self.rules[i].nat_addr = nat_addr;
                self.rules[i].nat_port_min = nat_port;
                self.rules[i].nat_port_max = nat_port;
                break;
            }
        }
        Some(rule_id)
    }

    pub fn delete_rule(&mut self, rule_id: u32) -> bool {
        for i in 0..MAX_RULES {
            if self.rules[i].active && self.rules[i].id == rule_id {
                let chain = self.rules[i].chain_idx as usize;
                self.rules[i].active = false;
                self.rule_count -= 1;
                if chain < MAX_CHAINS && self.chains[chain].rule_count > 0 {
                    self.chains[chain].rule_count -= 1;
                }
                return true;
            }
        }
        false
    }

    // ─── Connection Tracking ────────────────────────────────────────

    pub fn ct_create(&mut self, tuple: &Tuple) -> Option<usize> {
        if self.conn_count as usize >= MAX_CONNECTIONS {
            return None;
        }
        for i in 0..MAX_CONNECTIONS {
            if !self.connections[i].active {
                self.connections[i] = ConnTrackEntry::empty();
                self.connections[i].id = self.next_conn_id;
                self.connections[i].original = *tuple;
                self.connections[i].reply = tuple.reverse();
                self.connections[i].status = ConnStatus::New;
                self.connections[i].create_tick = self.tick;
                self.connections[i].last_seen = self.tick;
                self.connections[i].active = true;

                // Set initial timeout based on protocol
                self.connections[i].timeout = match tuple.proto {
                    IpProto::Tcp => self.timeouts.tcp_syn_sent,
                    IpProto::Udp => self.timeouts.udp_unreplied,
                    IpProto::Icmp | IpProto::Icmpv6 => self.timeouts.icmp_timeout,
                    _ => self.timeouts.generic_timeout,
                };

                // Check expectations
                if self.check_expectation(tuple) {
                    self.connections[i].status = ConnStatus::Related;
                    self.total_expectation_hits += 1;
                }

                self.next_conn_id += 1;
                self.conn_count += 1;
                self.total_ct_created += 1;

                // Hash insert
                let bucket = tuple.hash();
                self.hash_table[bucket].insert(i as i16);

                return Some(i);
            }
        }
        None
    }

    pub fn ct_lookup(&self, tuple: &Tuple) -> Option<usize> {
        let bucket = tuple.hash();
        let bkt = &self.hash_table[bucket];
        for j in 0..bkt.count as usize {
            let idx = bkt.entries[j] as usize;
            if idx < MAX_CONNECTIONS && self.connections[idx].active {
                if self.connections[idx].original.matches(tuple) || self.connections[idx].reply.matches(tuple) {
                    return Some(idx);
                }
            }
        }
        None
    }

    pub fn ct_destroy(&mut self, idx: usize) {
        if idx >= MAX_CONNECTIONS || !self.connections[idx].active {
            return;
        }
        let bucket = self.connections[idx].original.hash();
        self.hash_table[bucket].remove(idx as i16);
        self.connections[idx].active = false;
        self.connections[idx].dying = true;
        self.conn_count -= 1;
        self.total_ct_destroyed += 1;
    }

    pub fn ct_update_tcp_state(&mut self, idx: usize, new_state: TcpConnState) {
        if idx >= MAX_CONNECTIONS || !self.connections[idx].active {
            return;
        }
        self.connections[idx].tcp_state = new_state;
        self.connections[idx].timeout = self.timeouts.timeout_for_tcp(new_state);
        self.connections[idx].last_seen = self.tick;
    }

    // ─── NAT ────────────────────────────────────────────────────────

    pub fn apply_snat(&mut self, ct_idx: usize, new_addr: u32, new_port: u16) -> bool {
        if ct_idx >= MAX_CONNECTIONS || !self.connections[ct_idx].active {
            return false;
        }
        self.connections[ct_idx].nat_src_addr = new_addr;
        self.connections[ct_idx].nat_src_port = new_port;
        self.connections[ct_idx].snat_active = true;
        // Update reply tuple to match
        self.connections[ct_idx].reply.dst_addr = new_addr;
        self.connections[ct_idx].reply.dst_port = new_port;
        self.total_nat_rewrites += 1;
        true
    }

    pub fn apply_dnat(&mut self, ct_idx: usize, new_addr: u32, new_port: u16) -> bool {
        if ct_idx >= MAX_CONNECTIONS || !self.connections[ct_idx].active {
            return false;
        }
        self.connections[ct_idx].nat_dst_addr = new_addr;
        self.connections[ct_idx].nat_dst_port = new_port;
        self.connections[ct_idx].dnat_active = true;
        // Update reply tuple source
        self.connections[ct_idx].reply.src_addr = new_addr;
        self.connections[ct_idx].reply.src_port = new_port;
        self.total_nat_rewrites += 1;
        true
    }

    // ─── Expectations ───────────────────────────────────────────────

    pub fn add_expectation(&mut self, master_id: u32, expected: Tuple) -> bool {
        for i in 0..MAX_EXPECTATIONS {
            if !self.expectations[i].active {
                self.expectations[i] = Expectation::empty();
                self.expectations[i].master_id = master_id;
                self.expectations[i].expected = expected;
                self.expectations[i].create_tick = self.tick;
                self.expectations[i].active = true;
                return true;
            }
        }
        false
    }

    fn check_expectation(&mut self, tuple: &Tuple) -> bool {
        for i in 0..MAX_EXPECTATIONS {
            if !self.expectations[i].active {
                continue;
            }
            if self.expectations[i].expected.matches(tuple) {
                self.expectations[i].active = false; // One-shot
                return true;
            }
        }
        false
    }

    // ─── Packet Processing ──────────────────────────────────────────

    pub fn process_packet(&mut self, tuple: &Tuple, hook: NfHook, pkt_size: u32) -> NfTarget {
        self.total_packets += 1;

        // Connection tracking: lookup or create
        let ct_idx = if let Some(idx) = self.ct_lookup(tuple) {
            let is_reply = self.connections[idx].reply.matches(tuple);
            self.connections[idx].update_counters(pkt_size, is_reply);
            self.connections[idx].last_seen = self.tick;
            idx
        } else {
            match self.ct_create(tuple) {
                Some(idx) => {
                    self.connections[idx].update_counters(pkt_size, false);
                    idx
                }
                None => {
                    self.total_dropped += 1;
                    return NfTarget::Drop;
                }
            }
        };

        let ct_status = self.connections[ct_idx].status;
        let pkt_mark = self.connections[ct_idx].mark;

        // Evaluate rules for matching chain/hook
        let mut verdict = NfTarget::Continue;

        for i in 0..MAX_RULES {
            if !self.rules[i].active {
                continue;
            }
            let chain = self.rules[i].chain_idx as usize;
            if chain >= MAX_CHAINS || !self.chains[chain].active {
                continue;
            }
            if self.chains[chain].hook != hook {
                continue;
            }

            if self.rules[i].match_criteria.matches_packet(tuple, ct_status, pkt_mark) {
                self.rules[i].hit_count += 1;
                self.rules[i].byte_count += pkt_size as u64;

                match self.rules[i].target {
                    NfTarget::Accept => {
                        verdict = NfTarget::Accept;
                        break;
                    }
                    NfTarget::Drop => {
                        verdict = NfTarget::Drop;
                        break;
                    }
                    NfTarget::Reject => {
                        verdict = NfTarget::Reject;
                        break;
                    }
                    NfTarget::Snat => {
                        self.apply_snat(ct_idx, self.rules[i].nat_addr, self.rules[i].nat_port_min);
                        verdict = NfTarget::Accept;
                        break;
                    }
                    NfTarget::Dnat => {
                        self.apply_dnat(ct_idx, self.rules[i].nat_addr, self.rules[i].nat_port_min);
                        verdict = NfTarget::Accept;
                        break;
                    }
                    NfTarget::Mark => {
                        self.connections[ct_idx].mark =
                            (pkt_mark & !self.rules[i].set_mark_mask) | (self.rules[i].set_mark & self.rules[i].set_mark_mask);
                        // Continue evaluating
                    }
                    NfTarget::Log => {
                        // Log action, continue
                    }
                    _ => {}
                }
            }
        }

        // Apply default chain policy if no rule matched
        if verdict == NfTarget::Continue {
            for i in 0..MAX_CHAINS {
                if self.chains[i].active && self.chains[i].hook == hook {
                    verdict = self.chains[i].policy;
                    break;
                }
            }
        }

        match verdict {
            NfTarget::Accept | NfTarget::Continue => { self.total_accepted += 1; }
            NfTarget::Drop => { self.total_dropped += 1; }
            NfTarget::Reject => { self.total_rejected += 1; }
            _ => { self.total_accepted += 1; }
        }

        verdict
    }

    // ─── Garbage Collection ─────────────────────────────────────────

    pub fn gc(&mut self) -> u32 {
        let mut expired = 0u32;
        for i in 0..MAX_CONNECTIONS {
            if self.connections[i].active && self.connections[i].is_expired(self.tick) {
                self.ct_destroy(i);
                self.total_ct_expired += 1;
                expired += 1;
            }
        }
        // Expire old expectations
        for i in 0..MAX_EXPECTATIONS {
            if self.expectations[i].active && self.tick > self.expectations[i].create_tick + self.expectations[i].timeout {
                self.expectations[i].active = false;
            }
        }
        expired
    }

    pub fn advance_tick(&mut self) {
        self.tick += 1;
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_NETFILTER: Option<NetfilterManager> = None;
static mut G_NF_INIT: bool = false;

fn nf() -> &'static mut NetfilterManager {
    unsafe { G_NETFILTER.as_mut().unwrap() }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_netfilter_init() {
    unsafe {
        G_NETFILTER = Some(NetfilterManager::new());
        G_NF_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_netfilter_add_rule(chain_idx: u8, priority: i16, target: u8) -> i32 {
    if unsafe { !G_NF_INIT } { return -1; }
    let tgt: NfTarget = unsafe { core::mem::transmute(target) };
    match nf().add_rule(chain_idx, priority, RuleMatch::any(), tgt) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_netfilter_delete_rule(rule_id: u32) -> bool {
    if unsafe { !G_NF_INIT } { return false; }
    nf().delete_rule(rule_id)
}

#[no_mangle]
pub extern "C" fn rust_netfilter_process(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16, proto: u8, hook: u8, pkt_size: u32) -> u8 {
    if unsafe { !G_NF_INIT } { return NfTarget::Drop as u8; }
    let tuple = Tuple { src_addr, dst_addr, src_port, dst_port, proto: unsafe { core::mem::transmute(proto) } };
    let nf_hook: NfHook = unsafe { core::mem::transmute(hook) };
    nf().process_packet(&tuple, nf_hook, pkt_size) as u8
}

#[no_mangle]
pub extern "C" fn rust_netfilter_gc() -> u32 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().gc()
}

#[no_mangle]
pub extern "C" fn rust_netfilter_tick() {
    if unsafe { !G_NF_INIT } { return; }
    nf().advance_tick();
}

#[no_mangle]
pub extern "C" fn rust_netfilter_conn_count() -> u32 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().conn_count
}

#[no_mangle]
pub extern "C" fn rust_netfilter_rule_count() -> u32 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().rule_count
}

#[no_mangle]
pub extern "C" fn rust_netfilter_total_packets() -> u64 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().total_packets
}

#[no_mangle]
pub extern "C" fn rust_netfilter_total_dropped() -> u64 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().total_dropped
}

#[no_mangle]
pub extern "C" fn rust_netfilter_total_accepted() -> u64 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().total_accepted
}

#[no_mangle]
pub extern "C" fn rust_netfilter_total_nat() -> u64 {
    if unsafe { !G_NF_INIT } { return 0; }
    nf().total_nat_rewrites
}
