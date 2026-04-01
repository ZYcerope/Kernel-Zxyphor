// =============================================================================
// Kernel Zxyphor — Rust Network Firewall Engine
// =============================================================================
// A stateful packet filtering firewall operating at layers 3 and 4. Supports
// rule chains with accept/drop/reject actions, connection tracking for stateful
// inspection, and rate limiting to mitigate denial-of-service attacks.
//
// Architecture:
//   Packet → Pre-routing chain → Input/Forward/Output chain → Post-routing chain
//
// Each chain is an ordered list of rules that are evaluated sequentially.
// The first matching rule determines the packet's fate. If no rule matches,
// the chain's default policy applies.
//
// Connection tracking maintains state for TCP, UDP, and ICMP flows:
//   - NEW: first packet in a flow
//   - ESTABLISHED: packets belonging to a recognized bidirectional flow
//   - RELATED: packets related to an existing flow (e.g., ICMP errors)
//   - INVALID: packets that don't match any known flow and fail validation
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use crate::net::packet::{Ipv4Address, PacketMeta, IpProtocol};

/// Maximum number of firewall rules per chain
const MAX_RULES_PER_CHAIN: usize = 512;

/// Maximum number of connection tracking entries
const MAX_CONNTRACK_ENTRIES: usize = 16384;

/// Connection tracking timeout in seconds for different protocols
const TCP_ESTABLISHED_TIMEOUT: u64 = 432000; // 5 days
const TCP_CLOSE_TIMEOUT: u64 = 120; // 2 minutes
const UDP_TIMEOUT: u64 = 180; // 3 minutes
const ICMP_TIMEOUT: u64 = 30; // 30 seconds

/// Rate limiting: maximum number of tokens in bucket
const RATE_LIMIT_BURST: u32 = 100;

// =============================================================================
// Firewall rule actions
// =============================================================================

/// Action to take when a rule matches a packet
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// Allow the packet through
    Accept = 0,
    /// Silently discard the packet
    Drop = 1,
    /// Discard and send an ICMP error back to the sender
    Reject = 2,
    /// Log the packet and continue processing
    Log = 3,
    /// Jump to another chain for further processing
    Jump = 4,
    /// Return from the current chain to the parent
    Return = 5,
    /// Apply SNAT (source network address translation)
    Snat = 6,
    /// Apply DNAT (destination network address translation)
    Dnat = 7,
    /// Apply masquerade (dynamic SNAT using the outgoing interface address)
    Masquerade = 8,
}

// =============================================================================
// Firewall rule chain types
// =============================================================================

/// Named chain positions in the packet processing pipeline
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    /// Applied before routing decision
    PreRouting = 0,
    /// Applied to packets destined for this host
    Input = 1,
    /// Applied to packets being routed through this host
    Forward = 2,
    /// Applied to locally generated outbound packets
    Output = 3,
    /// Applied after routing decision
    PostRouting = 4,
}

// =============================================================================
// Connection tracking state
// =============================================================================

/// Connection tracking state for stateful packet inspection
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnTrackState {
    /// First packet of a new connection
    New = 0,
    /// Part of an established bidirectional connection
    Established = 1,
    /// Related to an existing connection (e.g., FTP data channel)
    Related = 2,
    /// Does not match any valid connection state
    Invalid = 3,
    /// Connection is being closed (TCP FIN/RST)
    TimeWait = 4,
}

// =============================================================================
// Firewall rule
// =============================================================================

/// A single firewall rule that matches packets based on specified criteria
/// and applies an action. Fields set to zero/None are wildcards (match any).
#[repr(C)]
pub struct FirewallRule {
    /// Rule identifier (unique within a chain)
    pub id: u32,
    /// Rule priority (lower = higher priority, evaluated first)
    pub priority: u32,
    /// Action to take when this rule matches
    pub action: FirewallAction,
    /// Source IP address match (0.0.0.0 = any)
    pub src_ip: Ipv4Address,
    /// Source IP mask for CIDR matching
    pub src_mask: Ipv4Address,
    /// Destination IP address match
    pub dst_ip: Ipv4Address,
    /// Destination IP mask for CIDR matching
    pub dst_mask: Ipv4Address,
    /// Source port range start (0 = any)
    pub src_port_min: u16,
    /// Source port range end (0 = any)
    pub src_port_max: u16,
    /// Destination port range start
    pub dst_port_min: u16,
    /// Destination port range end
    pub dst_port_max: u16,
    /// IP protocol (Unknown = any)
    pub protocol: IpProtocol,
    /// Connection tracking state match (0xFF = any)
    pub conntrack_state: u8,
    /// Interface index match (0 = any)
    pub interface_id: u16,
    /// Invert the match (negate the entire rule)
    pub negate: bool,
    /// Whether this rule is active
    pub active: bool,
    /// Number of packets matched by this rule
    pub match_count: AtomicU64,
    /// Number of bytes matched by this rule
    pub byte_count: AtomicU64,
    /// Rate limit: packets per second (0 = no limit)
    pub rate_limit_pps: u32,
    /// Rate limit token bucket current tokens
    pub rate_tokens: AtomicU32,
    /// Last time the token bucket was refilled (in seconds from boot)
    pub rate_last_refill: AtomicU64,
}

impl FirewallRule {
    pub const fn empty() -> Self {
        FirewallRule {
            id: 0,
            priority: u32::MAX,
            action: FirewallAction::Drop,
            src_ip: Ipv4Address { octets: [0; 4] },
            src_mask: Ipv4Address { octets: [0; 4] },
            dst_ip: Ipv4Address { octets: [0; 4] },
            dst_mask: Ipv4Address { octets: [0; 4] },
            src_port_min: 0,
            src_port_max: 0,
            dst_port_min: 0,
            dst_port_max: 0,
            protocol: IpProtocol::Unknown,
            conntrack_state: 0xFF,
            interface_id: 0,
            negate: false,
            active: false,
            match_count: AtomicU64::new(0),
            byte_count: AtomicU64::new(0),
            rate_limit_pps: 0,
            rate_tokens: AtomicU32::new(RATE_LIMIT_BURST),
            rate_last_refill: AtomicU64::new(0),
        }
    }

    /// Check if this rule matches the given packet metadata
    pub fn matches(&self, meta: &PacketMeta) -> bool {
        if !self.active {
            return false;
        }

        let mut matched = true;

        // Source IP / CIDR match
        if self.src_mask.to_u32() != 0 {
            let masked_pkt = meta.src_ip.to_u32() & self.src_mask.to_u32();
            let masked_rule = self.src_ip.to_u32() & self.src_mask.to_u32();
            if masked_pkt != masked_rule {
                matched = false;
            }
        }

        // Destination IP / CIDR match
        if matched && self.dst_mask.to_u32() != 0 {
            let masked_pkt = meta.dst_ip.to_u32() & self.dst_mask.to_u32();
            let masked_rule = self.dst_ip.to_u32() & self.dst_mask.to_u32();
            if masked_pkt != masked_rule {
                matched = false;
            }
        }

        // Protocol match
        if matched && self.protocol != IpProtocol::Unknown {
            if meta.ip_protocol != self.protocol {
                matched = false;
            }
        }

        // Source port range match
        if matched && self.src_port_min != 0 {
            if meta.src_port < self.src_port_min || meta.src_port > self.src_port_max {
                matched = false;
            }
        }

        // Destination port range match
        if matched && self.dst_port_min != 0 {
            if meta.dst_port < self.dst_port_min || meta.dst_port > self.dst_port_max {
                matched = false;
            }
        }

        // Interface match
        if matched && self.interface_id != 0 {
            if meta.interface_id != self.interface_id {
                matched = false;
            }
        }

        // Apply negation
        if self.negate {
            matched = !matched;
        }

        // If matched, update statistics and check rate limit
        if matched {
            self.match_count.fetch_add(1, Ordering::Relaxed);
            // byte_count would be updated externally with the packet size
        }

        matched
    }

    /// Check rate limit (returns true if the packet should be allowed)
    pub fn check_rate_limit(&self, current_time_secs: u64) -> bool {
        if self.rate_limit_pps == 0 {
            return true; // No rate limit configured
        }

        // Refill tokens based on elapsed time
        let last_refill = self.rate_last_refill.load(Ordering::Relaxed);
        let elapsed = current_time_secs.saturating_sub(last_refill);

        if elapsed > 0 {
            let new_tokens = (elapsed as u32).saturating_mul(self.rate_limit_pps);
            let current = self.rate_tokens.load(Ordering::Relaxed);
            let refilled = core::cmp::min(current.saturating_add(new_tokens), RATE_LIMIT_BURST);
            self.rate_tokens.store(refilled, Ordering::Relaxed);
            self.rate_last_refill.store(current_time_secs, Ordering::Relaxed);
        }

        // Try to consume a token
        loop {
            let tokens = self.rate_tokens.load(Ordering::Relaxed);
            if tokens == 0 {
                return false; // Rate limited
            }
            if self.rate_tokens.compare_exchange_weak(
                tokens,
                tokens - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
            core::hint::spin_loop();
        }
    }
}

// =============================================================================
// Firewall rule chain
// =============================================================================

/// A chain is an ordered list of rules evaluated sequentially
pub struct FirewallChain {
    /// Chain type (determines when in the packet path it's evaluated)
    pub chain_type: ChainType,
    /// Default action when no rule matches
    pub default_action: FirewallAction,
    /// Rules in this chain
    pub rules: [FirewallRule; MAX_RULES_PER_CHAIN],
    /// Number of active rules
    pub rule_count: usize,
    /// Total packets processed by this chain
    pub packets_processed: AtomicU64,
    /// Chain lock
    pub lock: AtomicBool,
}

impl FirewallChain {
    pub const fn new(chain_type: ChainType, default_action: FirewallAction) -> Self {
        const EMPTY_RULE: FirewallRule = FirewallRule::empty();
        FirewallChain {
            chain_type,
            default_action,
            rules: [EMPTY_RULE; MAX_RULES_PER_CHAIN],
            rule_count: 0,
            packets_processed: AtomicU64::new(0),
            lock: AtomicBool::new(false),
        }
    }

    fn lock(&self) {
        while self.lock.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Add a rule to this chain
    pub fn add_rule(&mut self, rule: FirewallRule) -> bool {
        self.lock();

        if self.rule_count >= MAX_RULES_PER_CHAIN {
            self.unlock();
            return false;
        }

        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
        self.unlock();
        true
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, rule_id: u32) -> bool {
        self.lock();

        for i in 0..self.rule_count {
            if self.rules[i].id == rule_id {
                // Shift remaining rules down
                for j in i..self.rule_count - 1 {
                    // Copy the rule fields manually since we can't move atomics
                    self.rules[j].id = self.rules[j + 1].id;
                    self.rules[j].priority = self.rules[j + 1].priority;
                    self.rules[j].action = self.rules[j + 1].action;
                    self.rules[j].src_ip = self.rules[j + 1].src_ip;
                    self.rules[j].src_mask = self.rules[j + 1].src_mask;
                    self.rules[j].dst_ip = self.rules[j + 1].dst_ip;
                    self.rules[j].dst_mask = self.rules[j + 1].dst_mask;
                    self.rules[j].src_port_min = self.rules[j + 1].src_port_min;
                    self.rules[j].src_port_max = self.rules[j + 1].src_port_max;
                    self.rules[j].dst_port_min = self.rules[j + 1].dst_port_min;
                    self.rules[j].dst_port_max = self.rules[j + 1].dst_port_max;
                    self.rules[j].protocol = self.rules[j + 1].protocol;
                    self.rules[j].conntrack_state = self.rules[j + 1].conntrack_state;
                    self.rules[j].interface_id = self.rules[j + 1].interface_id;
                    self.rules[j].negate = self.rules[j + 1].negate;
                    self.rules[j].active = self.rules[j + 1].active;
                    self.rules[j].rate_limit_pps = self.rules[j + 1].rate_limit_pps;
                }
                self.rule_count -= 1;
                self.unlock();
                return true;
            }
        }

        self.unlock();
        false
    }

    /// Evaluate this chain against a packet's metadata.
    /// Returns the action to apply (Accept, Drop, etc.)
    pub fn evaluate(&self, meta: &PacketMeta, current_time_secs: u64) -> FirewallAction {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);

        for i in 0..self.rule_count {
            if self.rules[i].matches(meta) {
                // Check rate limit
                if !self.rules[i].check_rate_limit(current_time_secs) {
                    continue; // Exceeded rate limit, skip this rule
                }

                return self.rules[i].action;
            }
        }

        // No rule matched — apply default action
        self.default_action
    }
}

// =============================================================================
// Connection tracking entry
// =============================================================================

/// A connection tracking entry represents a single network flow.
/// The 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) uniquely
/// identifies a flow.
#[repr(C)]
pub struct ConnTrackEntry {
    /// Source IP address
    pub src_ip: Ipv4Address,
    /// Destination IP address
    pub dst_ip: Ipv4Address,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// IP protocol
    pub protocol: IpProtocol,
    /// Current connection state
    pub state: ConnTrackState,
    /// Timestamp of last packet (seconds from boot)
    pub last_seen: AtomicU64,
    /// Timeout value in seconds
    pub timeout: u64,
    /// Packets seen in the forward direction (original → reply)
    pub packets_forward: AtomicU64,
    /// Packets seen in the reply direction
    pub packets_reply: AtomicU64,
    /// Bytes seen in the forward direction
    pub bytes_forward: AtomicU64,
    /// Bytes seen in the reply direction
    pub bytes_reply: AtomicU64,
    /// Whether this entry is in use
    pub in_use: AtomicBool,
    /// NAT: translated source IP (for SNAT)
    pub nat_src_ip: Ipv4Address,
    /// NAT: translated source port (for SNAT)
    pub nat_src_port: u16,
    /// NAT: translated destination IP (for DNAT)
    pub nat_dst_ip: Ipv4Address,
    /// NAT: translated destination port (for DNAT)
    pub nat_dst_port: u16,
    /// Whether NAT is active for this connection
    pub nat_active: bool,
}

impl ConnTrackEntry {
    pub const fn empty() -> Self {
        ConnTrackEntry {
            src_ip: Ipv4Address { octets: [0; 4] },
            dst_ip: Ipv4Address { octets: [0; 4] },
            src_port: 0,
            dst_port: 0,
            protocol: IpProtocol::Unknown,
            state: ConnTrackState::New,
            last_seen: AtomicU64::new(0),
            timeout: 0,
            packets_forward: AtomicU64::new(0),
            packets_reply: AtomicU64::new(0),
            bytes_forward: AtomicU64::new(0),
            bytes_reply: AtomicU64::new(0),
            in_use: AtomicBool::new(false),
            nat_src_ip: Ipv4Address { octets: [0; 4] },
            nat_src_port: 0,
            nat_dst_ip: Ipv4Address { octets: [0; 4] },
            nat_dst_port: 0,
            nat_active: false,
        }
    }

    /// Check if this entry matches a packet (forward direction)
    pub fn matches_forward(&self, meta: &PacketMeta) -> bool {
        self.src_ip == meta.src_ip
            && self.dst_ip == meta.dst_ip
            && self.src_port == meta.src_port
            && self.dst_port == meta.dst_port
            && self.protocol == meta.ip_protocol
    }

    /// Check if this entry matches a packet (reply direction)
    pub fn matches_reply(&self, meta: &PacketMeta) -> bool {
        self.src_ip == meta.dst_ip
            && self.dst_ip == meta.src_ip
            && self.src_port == meta.dst_port
            && self.dst_port == meta.src_port
            && self.protocol == meta.ip_protocol
    }

    /// Check if this entry has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        let last = self.last_seen.load(Ordering::Relaxed);
        current_time.saturating_sub(last) > self.timeout
    }

    /// Update the entry's last-seen timestamp
    pub fn touch(&self, current_time: u64) {
        self.last_seen.store(current_time, Ordering::Relaxed);
    }

    /// Get the default timeout for a given protocol and state
    pub fn default_timeout(protocol: IpProtocol, state: ConnTrackState) -> u64 {
        match protocol {
            IpProtocol::Tcp => match state {
                ConnTrackState::Established => TCP_ESTABLISHED_TIMEOUT,
                ConnTrackState::TimeWait => TCP_CLOSE_TIMEOUT,
                _ => 120,
            },
            IpProtocol::Udp => UDP_TIMEOUT,
            IpProtocol::Icmp => ICMP_TIMEOUT,
            _ => 60,
        }
    }
}

// =============================================================================
// Connection tracking table
// =============================================================================

/// The connection tracking table maintains state for all active network flows.
/// It uses a simple hash table with linear probing for collision resolution.
pub struct ConnTrackTable {
    entries: [ConnTrackEntry; MAX_CONNTRACK_ENTRIES],
    active_count: AtomicU32,
    total_lookups: AtomicU64,
    total_inserts: AtomicU64,
    total_deletes: AtomicU64,
    total_timeouts: AtomicU64,
    lock: AtomicBool,
}

impl ConnTrackTable {
    pub const fn new() -> Self {
        const EMPTY_ENTRY: ConnTrackEntry = ConnTrackEntry::empty();
        ConnTrackTable {
            entries: [EMPTY_ENTRY; MAX_CONNTRACK_ENTRIES],
            active_count: AtomicU32::new(0),
            total_lookups: AtomicU64::new(0),
            total_inserts: AtomicU64::new(0),
            total_deletes: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            lock: AtomicBool::new(false),
        }
    }

    fn lock(&self) {
        while self.lock.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }

    /// Simple hash function for 5-tuple connection identification
    fn hash_5tuple(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> usize {
        // Jenkins one-at-a-time hash (simple but effective for conn tracking)
        let mut hash: u32 = 0;

        let values: [u32; 5] = [
            src_ip,
            dst_ip,
            src_port as u32,
            dst_port as u32,
            protocol as u32,
        ];

        for val in values.iter() {
            hash = hash.wrapping_add(*val);
            hash = hash.wrapping_add(hash << 10);
            hash ^= hash >> 6;
        }

        hash = hash.wrapping_add(hash << 3);
        hash ^= hash >> 11;
        hash = hash.wrapping_add(hash << 15);

        (hash as usize) % MAX_CONNTRACK_ENTRIES
    }

    /// Look up a connection by packet metadata
    pub fn lookup(&self, meta: &PacketMeta, current_time: u64) -> Option<(usize, ConnTrackState)> {
        self.total_lookups.fetch_add(1, Ordering::Relaxed);

        let hash = Self::hash_5tuple(
            meta.src_ip.to_u32(),
            meta.dst_ip.to_u32(),
            meta.src_port,
            meta.dst_port,
            meta.ip_protocol as u8,
        );

        // Linear probing with wrap-around
        for offset in 0..64usize {
            let idx = (hash + offset) % MAX_CONNTRACK_ENTRIES;

            if !self.entries[idx].in_use.load(Ordering::Acquire) {
                continue;
            }

            if self.entries[idx].is_expired(current_time) {
                continue;
            }

            if self.entries[idx].matches_forward(meta) {
                self.entries[idx].touch(current_time);
                self.entries[idx].packets_forward.fetch_add(1, Ordering::Relaxed);
                return Some((idx, self.entries[idx].state));
            }

            if self.entries[idx].matches_reply(meta) {
                self.entries[idx].touch(current_time);
                self.entries[idx].packets_reply.fetch_add(1, Ordering::Relaxed);

                // Seeing a reply packet promotes the state to ESTABLISHED
                if self.entries[idx].state == ConnTrackState::New {
                    // Can't mutate through shared ref — would need lock
                    return Some((idx, ConnTrackState::Established));
                }

                return Some((idx, self.entries[idx].state));
            }
        }

        None
    }

    /// Insert a new connection tracking entry
    pub fn insert(&mut self, meta: &PacketMeta, current_time: u64) -> Option<usize> {
        self.lock();

        let hash = Self::hash_5tuple(
            meta.src_ip.to_u32(),
            meta.dst_ip.to_u32(),
            meta.src_port,
            meta.dst_port,
            meta.ip_protocol as u8,
        );

        // Find an empty slot or an expired entry
        for offset in 0..64usize {
            let idx = (hash + offset) % MAX_CONNTRACK_ENTRIES;

            let in_use = self.entries[idx].in_use.load(Ordering::Relaxed);
            let expired = in_use && self.entries[idx].is_expired(current_time);

            if !in_use || expired {
                if expired {
                    self.total_timeouts.fetch_add(1, Ordering::Relaxed);
                }

                self.entries[idx].src_ip = meta.src_ip;
                self.entries[idx].dst_ip = meta.dst_ip;
                self.entries[idx].src_port = meta.src_port;
                self.entries[idx].dst_port = meta.dst_port;
                self.entries[idx].protocol = meta.ip_protocol;
                self.entries[idx].state = ConnTrackState::New;
                self.entries[idx].last_seen.store(current_time, Ordering::Relaxed);
                self.entries[idx].timeout =
                    ConnTrackEntry::default_timeout(meta.ip_protocol, ConnTrackState::New);
                self.entries[idx].packets_forward.store(1, Ordering::Relaxed);
                self.entries[idx].packets_reply.store(0, Ordering::Relaxed);
                self.entries[idx].bytes_forward.store(0, Ordering::Relaxed);
                self.entries[idx].bytes_reply.store(0, Ordering::Relaxed);
                self.entries[idx].nat_active = false;
                self.entries[idx].in_use.store(true, Ordering::Release);

                if !in_use {
                    self.active_count.fetch_add(1, Ordering::Relaxed);
                }
                self.total_inserts.fetch_add(1, Ordering::Relaxed);

                self.unlock();
                return Some(idx);
            }
        }

        self.unlock();
        None
    }

    /// Remove a connection tracking entry by index
    pub fn remove(&self, idx: usize) -> bool {
        if idx >= MAX_CONNTRACK_ENTRIES {
            return false;
        }

        if self.entries[idx].in_use.compare_exchange(
            true, false, Ordering::AcqRel, Ordering::Relaxed
        ).is_ok() {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
            self.total_deletes.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Garbage collect expired entries
    pub fn gc(&self, current_time: u64) -> u32 {
        let mut removed = 0u32;

        for i in 0..MAX_CONNTRACK_ENTRIES {
            if self.entries[i].in_use.load(Ordering::Relaxed)
                && self.entries[i].is_expired(current_time)
            {
                if self.remove(i) {
                    removed += 1;
                }
            }
        }

        if removed > 0 {
            self.total_timeouts.fetch_add(removed as u64, Ordering::Relaxed);
        }

        removed
    }

    /// Get the number of active connections
    pub fn active_connections(&self) -> u32 {
        self.active_count.load(Ordering::Relaxed)
    }
}

// =============================================================================
// Global firewall state
// =============================================================================

static FIREWALL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FIREWALL_ENABLED: AtomicBool = AtomicBool::new(false);
static TOTAL_PACKETS_INSPECTED: AtomicU64 = AtomicU64::new(0);
static TOTAL_PACKETS_DROPPED: AtomicU64 = AtomicU64::new(0);
static TOTAL_PACKETS_ACCEPTED: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI interface
// =============================================================================

/// Initialize the firewall subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_firewall_init() -> i32 {
    if FIREWALL_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    FIREWALL_INITIALIZED.store(true, Ordering::SeqCst);
    FIREWALL_ENABLED.store(true, Ordering::SeqCst);

    crate::ffi::bridge::log_info("Rust firewall engine initialized (stateful packet inspection)");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Enable or disable the firewall
#[no_mangle]
pub extern "C" fn zxyphor_rust_firewall_set_enabled(enabled: i32) {
    FIREWALL_ENABLED.store(enabled != 0, Ordering::SeqCst);
}

/// Check if the firewall is enabled
#[no_mangle]
pub extern "C" fn zxyphor_rust_firewall_is_enabled() -> i32 {
    if FIREWALL_ENABLED.load(Ordering::Relaxed) { 1 } else { 0 }
}

/// Get firewall statistics
#[repr(C)]
pub struct FirewallStats {
    pub packets_inspected: u64,
    pub packets_dropped: u64,
    pub packets_accepted: u64,
    pub enabled: i32,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_firewall_stats(stats_out: *mut FirewallStats) -> i32 {
    if stats_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let stats = FirewallStats {
        packets_inspected: TOTAL_PACKETS_INSPECTED.load(Ordering::Relaxed),
        packets_dropped: TOTAL_PACKETS_DROPPED.load(Ordering::Relaxed),
        packets_accepted: TOTAL_PACKETS_ACCEPTED.load(Ordering::Relaxed),
        enabled: if FIREWALL_ENABLED.load(Ordering::Relaxed) { 1 } else { 0 },
    };

    unsafe {
        core::ptr::write(stats_out, stats);
    }

    crate::ffi::error::FfiError::Success.as_i32()
}
