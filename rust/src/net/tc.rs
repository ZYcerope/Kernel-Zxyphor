// SPDX-License-Identifier: MIT
//! Zxyphor Kernel — Traffic Control / QoS Subsystem (Rust)
//!
//! Linux-compatible tc (traffic control) implementation:
//! - Queuing disciplines (qdisc): pfifo_fast, TBF, HTB, SFQ, FQ_CoDel
//! - Classful hierarchy with parent-child classes
//! - Filters (classifiers): u32, fw mark, basic
//! - Token Bucket Filter with burst handling
//! - Hierarchical Token Bucket: rate/ceil per class, borrowing
//! - Stochastic Fairness Queuing: per-flow hashing
//! - FQ_CoDel: Fair Queuing with Controlled Delay
//! - Per-interface root qdisc
//! - Traffic shaping (rate limiting) and scheduling
//! - Statistics: bytes, packets, drops, overlimits, backlog

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_QDISCS: usize = 32;
const MAX_CLASSES: usize = 64;
const MAX_FILTERS: usize = 64;
const MAX_QUEUE_LEN: usize = 128;
const MAX_SFQ_FLOWS: usize = 16;
const NAME_LEN: usize = 32;

// ─────────────────── Qdisc Types ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QdiscType {
    PfifoFast = 0,  // Priority FIFO (default)
    Tbf = 1,        // Token Bucket Filter
    Htb = 2,        // Hierarchical Token Bucket
    Sfq = 3,        // Stochastic Fairness Queuing
    FqCodel = 4,    // Fair Queuing + Controlled Delay
    Prio = 5,       // Priority with bands
    Red = 6,        // Random Early Detection
    Ingress = 7,    // Ingress policing
    Clsact = 8,     // Classifier-action qdisc
}

// ─────────────────── Handle ─────────────────────────────────────────

/// TC handle: major:minor (16:16)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcHandle(pub u32);

impl TcHandle {
    pub const ROOT: Self = Self(0xFFFFFFFF);
    pub const UNSPEC: Self = Self(0);
    pub const INGRESS: Self = Self(0xFFFFFFF1);

    pub const fn new(major: u16, minor: u16) -> Self {
        Self(((major as u32) << 16) | (minor as u32))
    }

    pub const fn major(self) -> u16 { (self.0 >> 16) as u16 }
    pub const fn minor(self) -> u16 { (self.0 & 0xFFFF) as u16 }
}

// ─────────────────── Packet Metadata ────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TcPacket {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tos: u8,           // Type of Service / DSCP
    pub mark: u32,         // Firewall mark
    pub size: u32,
    pub timestamp: u64,
}

impl TcPacket {
    pub const fn new() -> Self {
        Self {
            src_addr: 0,
            dst_addr: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            tos: 0,
            mark: 0,
            size: 0,
            timestamp: 0,
        }
    }

    /// Map TOS to pfifo_fast band (0=highest, 2=lowest)
    pub fn tos_to_band(&self) -> u8 {
        match self.tos >> 4 {
            0..=3 => 1,     // Normal → band 1
            4..=7 => 2,     // Bulk → band 2 (lowest)
            8..=11 => 0,    // Interactive → band 0 (highest)
            _ => 1,
        }
    }

    /// 5-tuple hash for flow identification
    pub fn flow_hash(&self) -> u32 {
        let mut h: u32 = 0x811c9dc5;
        let mix = |h: &mut u32, v: u32| {
            *h ^= v;
            *h = h.wrapping_mul(0x01000193);
        };
        mix(&mut h, self.src_addr);
        mix(&mut h, self.dst_addr);
        mix(&mut h, (self.src_port as u32) << 16 | self.dst_port as u32);
        mix(&mut h, self.protocol as u32);
        h
    }
}

// ─────────────────── Token Bucket ───────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    pub rate: u64,          // Bytes per second
    pub burst: u64,         // Maximum burst (bytes)
    pub tokens: i64,        // Current tokens (can go negative briefly)
    pub last_tick: u64,
    pub peak_rate: u64,     // Peak rate (0 = no peak)
    pub mtu: u32,

    // Overflow tracking
    pub overlimit_count: u64,
}

impl TokenBucket {
    pub const fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst as i64,
            last_tick: 0,
            peak_rate: 0,
            mtu: 1500,
            overlimit_count: 0,
        }
    }

    /// Refill tokens based on elapsed time
    pub fn refill(&mut self, tick: u64) {
        if tick <= self.last_tick { return; }
        let elapsed_ms = tick - self.last_tick;
        let new_tokens = (self.rate * elapsed_ms) / 1000;
        self.tokens = (self.tokens + new_tokens as i64).min(self.burst as i64);
        self.last_tick = tick;
    }

    /// Try to consume tokens for a packet
    pub fn consume(&mut self, bytes: u32, tick: u64) -> bool {
        self.refill(tick);
        if self.tokens >= bytes as i64 {
            self.tokens -= bytes as i64;
            true
        } else {
            self.overlimit_count += 1;
            false
        }
    }
}

// ─────────────────── Queue (FIFO) ───────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct PacketQueue {
    pub packets: [TcPacket; MAX_QUEUE_LEN],
    pub head: u16,
    pub tail: u16,
    pub count: u16,
    pub limit: u16,           // Max queue length
    pub total_bytes: u64,     // Bytes currently enqueued
}

impl PacketQueue {
    pub const fn new(limit: u16) -> Self {
        Self {
            packets: [const { TcPacket::new() }; MAX_QUEUE_LEN],
            head: 0,
            tail: 0,
            count: 0,
            limit,
            total_bytes: 0,
        }
    }

    pub fn enqueue(&mut self, pkt: TcPacket) -> bool {
        if self.count >= self.limit || self.count as usize >= MAX_QUEUE_LEN {
            return false;
        }
        self.packets[self.head as usize] = pkt;
        self.head = ((self.head + 1) % MAX_QUEUE_LEN as u16) as u16;
        self.count += 1;
        self.total_bytes += pkt.size as u64;
        true
    }

    pub fn dequeue(&mut self) -> Option<TcPacket> {
        if self.count == 0 { return None; }
        let pkt = self.packets[self.tail as usize];
        self.tail = ((self.tail + 1) % MAX_QUEUE_LEN as u16) as u16;
        self.count -= 1;
        self.total_bytes = self.total_bytes.saturating_sub(pkt.size as u64);
        Some(pkt)
    }

    pub fn is_empty(&self) -> bool { self.count == 0 }
}

// ─────────────────── Qdisc Statistics ───────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct QdiscStats {
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub overlimits: u64,
    pub requeues: u64,
    pub backlog: u64,
    pub qlen: u32,
}

impl QdiscStats {
    pub const fn new() -> Self {
        Self {
            bytes: 0,
            packets: 0,
            drops: 0,
            overlimits: 0,
            requeues: 0,
            backlog: 0,
            qlen: 0,
        }
    }
}

// ─────────────────── SFQ Flow ───────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct SfqFlow {
    pub hash: u32,
    pub queue: PacketQueue,
    pub allot: i32,          // Deficit round-robin allotment
    pub active: bool,
}

impl SfqFlow {
    pub const fn new() -> Self {
        Self {
            hash: 0,
            queue: PacketQueue::new(16),
            allot: 1500,
            active: false,
        }
    }
}

// ─────────────────── CoDel State ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct CodelState {
    pub target: u64,         // Target delay (ms), usually 5ms
    pub interval: u64,       // Interval (ms), usually 100ms
    pub first_above_tick: u64,
    pub drop_next: u64,
    pub count: u32,          // Drops since entering drop state
    pub dropping: bool,
    pub last_dequeue_tick: u64,
}

impl CodelState {
    pub const fn new() -> Self {
        Self {
            target: 5,
            interval: 100,
            first_above_tick: 0,
            drop_next: 0,
            count: 0,
            dropping: false,
            last_dequeue_tick: 0,
        }
    }

    /// CoDel control law: next drop time = now + interval / sqrt(count)
    pub fn control_law(&self, tick: u64) -> u64 {
        if self.count <= 1 { return tick + self.interval; }
        // Approximate sqrt via integer math
        let isqrt = integer_sqrt(self.count);
        if isqrt == 0 { return tick + self.interval; }
        tick + self.interval / isqrt as u64
    }
}

fn integer_sqrt(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ─────────────────── Qdisc ──────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Qdisc {
    pub handle: TcHandle,
    pub parent: TcHandle,
    pub qtype: QdiscType,
    pub ifindex: u16,

    // Queues (used differently per qdisc type)
    pub bands: [PacketQueue; 3],   // pfifo_fast: 3 priority bands
    pub main_queue: PacketQueue,    // TBF, general

    // Token bucket (TBF, HTB)
    pub bucket: TokenBucket,

    // SFQ flows
    pub sfq_flows: [SfqFlow; MAX_SFQ_FLOWS],
    pub sfq_quantum: u32,
    pub sfq_perturb_tick: u64,
    pub sfq_current_flow: u8,

    // CoDel state
    pub codel: CodelState,

    // Stats
    pub stats: QdiscStats,
    pub active: bool,
}

impl Qdisc {
    pub const fn new(qtype: QdiscType) -> Self {
        Self {
            handle: TcHandle::UNSPEC,
            parent: TcHandle::ROOT,
            qtype,
            ifindex: 0,
            bands: [const { PacketQueue::new(64) }; 3],
            main_queue: PacketQueue::new(128),
            bucket: TokenBucket::new(0, 0),
            sfq_flows: [const { SfqFlow::new() }; MAX_SFQ_FLOWS],
            sfq_quantum: 1514,
            sfq_perturb_tick: 0,
            sfq_current_flow: 0,
            codel: CodelState::new(),
            stats: QdiscStats::new(),
            active: false,
        }
    }

    pub fn enqueue_packet(&mut self, pkt: TcPacket, tick: u64) -> bool {
        match self.qtype {
            QdiscType::PfifoFast | QdiscType::Prio => self.enqueue_pfifo(pkt),
            QdiscType::Tbf => self.enqueue_tbf(pkt, tick),
            QdiscType::Sfq => self.enqueue_sfq(pkt),
            QdiscType::FqCodel => self.enqueue_fqcodel(pkt),
            _ => self.main_queue.enqueue(pkt),
        }
    }

    pub fn dequeue_packet(&mut self, tick: u64) -> Option<TcPacket> {
        let pkt = match self.qtype {
            QdiscType::PfifoFast | QdiscType::Prio => self.dequeue_pfifo(),
            QdiscType::Tbf => self.dequeue_tbf(tick),
            QdiscType::Sfq => self.dequeue_sfq(),
            QdiscType::FqCodel => self.dequeue_fqcodel(tick),
            _ => self.main_queue.dequeue(),
        };
        if let Some(ref p) = pkt {
            self.stats.bytes += p.size as u64;
            self.stats.packets += 1;
        }
        pkt
    }

    // ─── pfifo_fast ─────────────────────────────────────────────────

    fn enqueue_pfifo(&mut self, pkt: TcPacket) -> bool {
        let band = pkt.tos_to_band() as usize;
        if self.bands[band].enqueue(pkt) {
            self.stats.qlen += 1;
            self.stats.backlog += pkt.size as u64;
            true
        } else {
            self.stats.drops += 1;
            false
        }
    }

    fn dequeue_pfifo(&mut self) -> Option<TcPacket> {
        // Service highest priority (band 0) first
        for band in 0..3 {
            if let Some(pkt) = self.bands[band].dequeue() {
                self.stats.qlen = self.stats.qlen.saturating_sub(1);
                self.stats.backlog = self.stats.backlog.saturating_sub(pkt.size as u64);
                return Some(pkt);
            }
        }
        None
    }

    // ─── TBF ────────────────────────────────────────────────────────

    fn enqueue_tbf(&mut self, pkt: TcPacket, _tick: u64) -> bool {
        if self.main_queue.enqueue(pkt) {
            self.stats.qlen += 1;
            self.stats.backlog += pkt.size as u64;
            true
        } else {
            self.stats.drops += 1;
            false
        }
    }

    fn dequeue_tbf(&mut self, tick: u64) -> Option<TcPacket> {
        if self.main_queue.is_empty() { return None; }
        // Peek at front packet
        let front_size = self.main_queue.packets[self.main_queue.tail as usize].size;
        if self.bucket.consume(front_size, tick) {
            let pkt = self.main_queue.dequeue()?;
            self.stats.qlen = self.stats.qlen.saturating_sub(1);
            self.stats.backlog = self.stats.backlog.saturating_sub(pkt.size as u64);
            Some(pkt)
        } else {
            self.stats.overlimits += 1;
            None // Wait for tokens
        }
    }

    // ─── SFQ ────────────────────────────────────────────────────────

    fn enqueue_sfq(&mut self, pkt: TcPacket) -> bool {
        let hash = pkt.flow_hash();
        let flow_idx = (hash as usize) % MAX_SFQ_FLOWS;
        if !self.sfq_flows[flow_idx].active {
            self.sfq_flows[flow_idx].hash = hash;
            self.sfq_flows[flow_idx].active = true;
            self.sfq_flows[flow_idx].allot = self.sfq_quantum as i32;
        }
        if self.sfq_flows[flow_idx].queue.enqueue(pkt) {
            self.stats.qlen += 1;
            self.stats.backlog += pkt.size as u64;
            true
        } else {
            self.stats.drops += 1;
            false
        }
    }

    fn dequeue_sfq(&mut self) -> Option<TcPacket> {
        // Deficit round-robin across active flows
        for _ in 0..MAX_SFQ_FLOWS {
            let idx = self.sfq_current_flow as usize;
            if self.sfq_flows[idx].active && !self.sfq_flows[idx].queue.is_empty() {
                if self.sfq_flows[idx].allot > 0 {
                    if let Some(pkt) = self.sfq_flows[idx].queue.dequeue() {
                        self.sfq_flows[idx].allot -= pkt.size as i32;
                        self.stats.qlen = self.stats.qlen.saturating_sub(1);
                        self.stats.backlog = self.stats.backlog.saturating_sub(pkt.size as u64);
                        if self.sfq_flows[idx].queue.is_empty() {
                            self.sfq_flows[idx].active = false;
                        }
                        return Some(pkt);
                    }
                } else {
                    // Refill allotment and move to next
                    self.sfq_flows[idx].allot += self.sfq_quantum as i32;
                }
            }
            self.sfq_current_flow = ((self.sfq_current_flow + 1) % MAX_SFQ_FLOWS as u8) as u8;
        }
        None
    }

    // ─── FQ_CoDel ───────────────────────────────────────────────────

    fn enqueue_fqcodel(&mut self, pkt: TcPacket) -> bool {
        // Use SFQ flows for fair queuing, with CoDel AQM
        self.enqueue_sfq(pkt)
    }

    fn dequeue_fqcodel(&mut self, tick: u64) -> Option<TcPacket> {
        let pkt = self.dequeue_sfq()?;
        // CoDel: check sojourn time
        let sojourn = tick.saturating_sub(pkt.timestamp);
        if sojourn > self.codel.target {
            if self.codel.first_above_tick == 0 {
                self.codel.first_above_tick = tick + self.codel.interval;
            } else if tick >= self.codel.first_above_tick {
                if !self.codel.dropping {
                    self.codel.dropping = true;
                    self.codel.count = if self.codel.count > 2 { self.codel.count - 2 } else { 1 };
                    self.codel.drop_next = self.codel.control_law(tick);
                }
            }
        } else {
            self.codel.first_above_tick = 0;
            self.codel.dropping = false;
        }

        if self.codel.dropping && tick >= self.codel.drop_next {
            self.codel.count += 1;
            self.codel.drop_next = self.codel.control_law(tick);
            self.stats.drops += 1;
            // Drop this packet and try next
            return self.dequeue_sfq();
        }

        self.codel.last_dequeue_tick = tick;
        Some(pkt)
    }
}

// ─────────────────── TC Filter ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FilterType {
    U32 = 0,       // Generic u32 match
    Fw = 1,        // Firewall mark
    Flow = 2,      // Flow-based
    Basic = 3,     // Basic match
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FilterAction {
    Pass = 0,
    Drop = 1,
    Redirect = 2,
    Mirror = 3,
    Classify = 4,
    Reclassify = 5,
}

#[derive(Debug, Clone, Copy)]
pub struct TcFilter {
    pub parent: TcHandle,
    pub priority: u16,
    pub ftype: FilterType,
    pub action: FilterAction,
    pub classid: TcHandle,        // Target class

    // Match criteria
    pub match_mark: u32,          // FW mark match
    pub match_mark_mask: u32,
    pub match_src: u32,           // Source IP
    pub match_src_mask: u32,
    pub match_dst: u32,           // Dest IP
    pub match_dst_mask: u32,
    pub match_proto: u8,          // 0 = any
    pub match_sport: u16,
    pub match_dport: u16,

    // Stats
    pub hit_count: u64,
    pub active: bool,
}

impl TcFilter {
    pub const fn new() -> Self {
        Self {
            parent: TcHandle::ROOT,
            priority: 0,
            ftype: FilterType::U32,
            action: FilterAction::Classify,
            classid: TcHandle::UNSPEC,
            match_mark: 0,
            match_mark_mask: 0,
            match_src: 0,
            match_src_mask: 0,
            match_dst: 0,
            match_dst_mask: 0,
            match_proto: 0,
            match_sport: 0,
            match_dport: 0,
            hit_count: 0,
            active: false,
        }
    }

    pub fn matches(&self, pkt: &TcPacket) -> bool {
        match self.ftype {
            FilterType::Fw => {
                (pkt.mark & self.match_mark_mask) == (self.match_mark & self.match_mark_mask)
            }
            FilterType::U32 | FilterType::Basic => {
                let src_ok = self.match_src_mask == 0
                    || (pkt.src_addr & self.match_src_mask) == (self.match_src & self.match_src_mask);
                let dst_ok = self.match_dst_mask == 0
                    || (pkt.dst_addr & self.match_dst_mask) == (self.match_dst & self.match_dst_mask);
                let proto_ok = self.match_proto == 0 || pkt.protocol == self.match_proto;
                let sport_ok = self.match_sport == 0 || pkt.src_port == self.match_sport;
                let dport_ok = self.match_dport == 0 || pkt.dst_port == self.match_dport;
                src_ok && dst_ok && proto_ok && sport_ok && dport_ok
            }
            FilterType::Flow => true, // Flow-based always matches
        }
    }
}

// ─────────────────── TC Class (HTB) ─────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TcClass {
    pub classid: TcHandle,
    pub parent: TcHandle,
    pub qdisc_idx: i16,       // Leaf qdisc

    // HTB parameters
    pub rate: u64,             // Guaranteed rate (bytes/sec)
    pub ceil: u64,             // Maximum rate (bytes/sec)
    pub burst: u64,
    pub cburst: u64,
    pub quantum: u32,
    pub prio: u8,

    pub bucket: TokenBucket,  // Rate bucket
    pub cbucket: TokenBucket, // Ceil bucket

    // Stats
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub overlimits: u64,
    pub active: bool,
}

impl TcClass {
    pub const fn new() -> Self {
        Self {
            classid: TcHandle::UNSPEC,
            parent: TcHandle::ROOT,
            qdisc_idx: -1,
            rate: 0,
            ceil: 0,
            burst: 0,
            cburst: 0,
            quantum: 1500,
            prio: 0,
            bucket: TokenBucket::new(0, 0),
            cbucket: TokenBucket::new(0, 0),
            bytes: 0,
            packets: 0,
            drops: 0,
            overlimits: 0,
            active: false,
        }
    }

    /// HTB: try to send at rate; fall back to borrowing up to ceil
    pub fn htb_can_send(&mut self, size: u32, tick: u64) -> bool {
        // First check guaranteed rate
        if self.bucket.consume(size, tick) {
            return true;
        }
        // Borrow from ceil
        if self.cbucket.consume(size, tick) {
            self.overlimits += 1;
            return true;
        }
        false
    }
}

// ─────────────────── TC Manager ─────────────────────────────────────

pub struct TcManager {
    qdiscs: [Qdisc; MAX_QDISCS],
    qdisc_count: u16,

    classes: [TcClass; MAX_CLASSES],
    class_count: u16,

    filters: [TcFilter; MAX_FILTERS],
    filter_count: u16,

    tick: u64,

    // Global stats
    total_enqueued: u64,
    total_dequeued: u64,
    total_dropped: u64,
    total_shaped: u64,

    initialized: bool,
}

impl TcManager {
    pub const fn new() -> Self {
        Self {
            qdiscs: [const { Qdisc::new(QdiscType::PfifoFast) }; MAX_QDISCS],
            qdisc_count: 0,
            classes: [const { TcClass::new() }; MAX_CLASSES],
            class_count: 0,
            filters: [const { TcFilter::new() }; MAX_FILTERS],
            filter_count: 0,
            tick: 0,
            total_enqueued: 0,
            total_dequeued: 0,
            total_dropped: 0,
            total_shaped: 0,
            initialized: true,
        }
    }

    // ─── Qdisc Management ───────────────────────────────────────────

    pub fn add_qdisc(
        &mut self,
        handle: TcHandle,
        parent: TcHandle,
        qtype: QdiscType,
        ifindex: u16,
    ) -> Option<u16> {
        if self.qdisc_count as usize >= MAX_QDISCS { return None; }
        for i in 0..MAX_QDISCS {
            if !self.qdiscs[i].active {
                self.qdiscs[i] = Qdisc::new(qtype);
                self.qdiscs[i].handle = handle;
                self.qdiscs[i].parent = parent;
                self.qdiscs[i].ifindex = ifindex;
                self.qdiscs[i].active = true;
                self.qdisc_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn del_qdisc(&mut self, idx: u16) -> bool {
        if (idx as usize) >= MAX_QDISCS || !self.qdiscs[idx as usize].active { return false; }
        self.qdiscs[idx as usize].active = false;
        self.qdisc_count = self.qdisc_count.saturating_sub(1);
        true
    }

    pub fn configure_tbf(&mut self, qdisc_idx: u16, rate: u64, burst: u64, peak: u64) -> bool {
        if (qdisc_idx as usize) >= MAX_QDISCS { return false; }
        if !self.qdiscs[qdisc_idx as usize].active { return false; }
        self.qdiscs[qdisc_idx as usize].bucket = TokenBucket::new(rate, burst);
        self.qdiscs[qdisc_idx as usize].bucket.peak_rate = peak;
        true
    }

    // ─── Class Management ───────────────────────────────────────────

    pub fn add_class(
        &mut self,
        classid: TcHandle,
        parent: TcHandle,
        rate: u64,
        ceil: u64,
        burst: u64,
        prio: u8,
    ) -> Option<u16> {
        if self.class_count as usize >= MAX_CLASSES { return None; }
        for i in 0..MAX_CLASSES {
            if !self.classes[i].active {
                self.classes[i] = TcClass::new();
                self.classes[i].classid = classid;
                self.classes[i].parent = parent;
                self.classes[i].rate = rate;
                self.classes[i].ceil = if ceil > 0 { ceil } else { rate };
                self.classes[i].burst = burst;
                self.classes[i].prio = prio;
                self.classes[i].bucket = TokenBucket::new(rate, burst);
                self.classes[i].cbucket = TokenBucket::new(self.classes[i].ceil, burst);
                self.classes[i].active = true;
                self.class_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    // ─── Filter Management ──────────────────────────────────────────

    pub fn add_filter(
        &mut self,
        parent: TcHandle,
        priority: u16,
        ftype: FilterType,
        classid: TcHandle,
    ) -> Option<u16> {
        if self.filter_count as usize >= MAX_FILTERS { return None; }
        for i in 0..MAX_FILTERS {
            if !self.filters[i].active {
                self.filters[i] = TcFilter::new();
                self.filters[i].parent = parent;
                self.filters[i].priority = priority;
                self.filters[i].ftype = ftype;
                self.filters[i].classid = classid;
                self.filters[i].active = true;
                self.filter_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn set_filter_mark(&mut self, idx: u16, mark: u32, mask: u32) -> bool {
        if (idx as usize) >= MAX_FILTERS || !self.filters[idx as usize].active { return false; }
        self.filters[idx as usize].match_mark = mark;
        self.filters[idx as usize].match_mark_mask = mask;
        true
    }

    pub fn set_filter_addr(&mut self, idx: u16, src: u32, src_mask: u32, dst: u32, dst_mask: u32) -> bool {
        if (idx as usize) >= MAX_FILTERS || !self.filters[idx as usize].active { return false; }
        self.filters[idx as usize].match_src = src;
        self.filters[idx as usize].match_src_mask = src_mask;
        self.filters[idx as usize].match_dst = dst;
        self.filters[idx as usize].match_dst_mask = dst_mask;
        true
    }

    // ─── Classify ───────────────────────────────────────────────────

    fn classify(&mut self, pkt: &TcPacket, parent: TcHandle) -> Option<u16> {
        // Find matching filter (lowest priority number = highest priority)
        let mut best_idx: Option<u16> = None;
        let mut best_prio: u16 = u16::MAX;
        for i in 0..MAX_FILTERS {
            if !self.filters[i].active { continue; }
            if self.filters[i].parent != parent { continue; }
            if self.filters[i].priority < best_prio && self.filters[i].matches(pkt) {
                best_idx = Some(i as u16);
                best_prio = self.filters[i].priority;
            }
        }
        if let Some(idx) = best_idx {
            self.filters[idx as usize].hit_count += 1;
            // Find class by classid
            let classid = self.filters[idx as usize].classid;
            for c in 0..MAX_CLASSES {
                if self.classes[c].active && self.classes[c].classid == classid {
                    return Some(c as u16);
                }
            }
        }
        None
    }

    // ─── Enqueue / Dequeue ──────────────────────────────────────────

    pub fn enqueue(&mut self, qdisc_idx: u16, pkt: TcPacket) -> bool {
        if (qdisc_idx as usize) >= MAX_QDISCS || !self.qdiscs[qdisc_idx as usize].active {
            return false;
        }
        let ok = self.qdiscs[qdisc_idx as usize].enqueue_packet(pkt, self.tick);
        if ok {
            self.total_enqueued += 1;
        } else {
            self.total_dropped += 1;
        }
        ok
    }

    pub fn dequeue(&mut self, qdisc_idx: u16) -> Option<TcPacket> {
        if (qdisc_idx as usize) >= MAX_QDISCS || !self.qdiscs[qdisc_idx as usize].active {
            return None;
        }
        let pkt = self.qdiscs[qdisc_idx as usize].dequeue_packet(self.tick);
        if pkt.is_some() {
            self.total_dequeued += 1;
        }
        pkt
    }

    pub fn tick(&mut self) {
        self.tick += 1;
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_TC: TcManager = TcManager::new();
static mut G_TC_INIT: bool = false;

fn tc() -> &'static mut TcManager {
    unsafe { &mut G_TC }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_tc_init() {
    unsafe {
        G_TC = TcManager::new();
        G_TC_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_tc_add_qdisc(major: u16, minor: u16, parent_major: u16, parent_minor: u16, qtype: u8, ifindex: u16) -> i16 {
    if unsafe { !G_TC_INIT } { return -1; }
    let handle = TcHandle::new(major, minor);
    let parent = TcHandle::new(parent_major, parent_minor);
    let qt: QdiscType = unsafe { core::mem::transmute(qtype) };
    match tc().add_qdisc(handle, parent, qt, ifindex) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_tc_configure_tbf(qdisc: u16, rate: u64, burst: u64, peak: u64) -> bool {
    if unsafe { !G_TC_INIT } { return false; }
    tc().configure_tbf(qdisc, rate, burst, peak)
}

#[no_mangle]
pub extern "C" fn rust_tc_add_class(classid_major: u16, classid_minor: u16, parent_major: u16, parent_minor: u16, rate: u64, ceil: u64, burst: u64, prio: u8) -> i16 {
    if unsafe { !G_TC_INIT } { return -1; }
    let classid = TcHandle::new(classid_major, classid_minor);
    let parent = TcHandle::new(parent_major, parent_minor);
    match tc().add_class(classid, parent, rate, ceil, burst, prio) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_tc_add_filter(parent_major: u16, parent_minor: u16, priority: u16, ftype: u8, classid_major: u16, classid_minor: u16) -> i16 {
    if unsafe { !G_TC_INIT } { return -1; }
    let parent = TcHandle::new(parent_major, parent_minor);
    let ft: FilterType = unsafe { core::mem::transmute(ftype) };
    let classid = TcHandle::new(classid_major, classid_minor);
    match tc().add_filter(parent, priority, ft, classid) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_tc_enqueue(qdisc: u16, src: u32, dst: u32, sport: u16, dport: u16, proto: u8, size: u32, mark: u32, tos: u8) -> bool {
    if unsafe { !G_TC_INIT } { return false; }
    let pkt = TcPacket {
        src_addr: src,
        dst_addr: dst,
        src_port: sport,
        dst_port: dport,
        protocol: proto,
        tos,
        mark,
        size,
        timestamp: tc().tick,
    };
    tc().enqueue(qdisc, pkt)
}

#[no_mangle]
pub extern "C" fn rust_tc_dequeue(qdisc: u16) -> u32 {
    if unsafe { !G_TC_INIT } { return 0; }
    match tc().dequeue(qdisc) {
        Some(pkt) => pkt.size,
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn rust_tc_tick() {
    if unsafe { !G_TC_INIT } { return; }
    tc().tick();
}

#[no_mangle]
pub extern "C" fn rust_tc_total_enqueued() -> u64 {
    if unsafe { !G_TC_INIT } { return 0; }
    tc().total_enqueued
}

#[no_mangle]
pub extern "C" fn rust_tc_total_dequeued() -> u64 {
    if unsafe { !G_TC_INIT } { return 0; }
    tc().total_dequeued
}

#[no_mangle]
pub extern "C" fn rust_tc_total_dropped() -> u64 {
    if unsafe { !G_TC_INIT } { return 0; }
    tc().total_dropped
}

#[no_mangle]
pub extern "C" fn rust_tc_qdisc_count() -> u16 {
    if unsafe { !G_TC_INIT } { return 0; }
    tc().qdisc_count
}

#[no_mangle]
pub extern "C" fn rust_tc_class_count() -> u16 {
    if unsafe { !G_TC_INIT } { return 0; }
    tc().class_count
}

#[no_mangle]
pub extern "C" fn rust_tc_filter_count() -> u16 {
    if unsafe { !G_TC_INIT } { return 0; }
    tc().filter_count
}
