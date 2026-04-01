// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Zero-Copy Networking & XDP/eBPF Framework
// High-performance packet processing with kernel bypass, XDP, io_uring integration

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// ============================================================================
// Zero-Copy Buffer Management
// ============================================================================

/// Page-aligned buffer descriptor for zero-copy I/O
#[repr(C)]
pub struct ZeroCopyBuf {
    pub data_ptr: u64,       // Physical/virtual address of data
    pub data_len: u32,       // Length of valid data
    pub buf_len: u32,        // Total buffer capacity
    pub offset: u32,         // Offset from start of page
    pub ref_count: AtomicU32,
    pub flags: u32,
    pub pool_id: u16,        // Memory pool this belongs to
    pub frag_index: u16,     // Fragment index
}

pub mod zcopy_flags {
    pub const ZCOPY_TX: u32 = 1 << 0;
    pub const ZCOPY_RX: u32 = 1 << 1;
    pub const ZCOPY_MAPPED: u32 = 1 << 2;
    pub const ZCOPY_PINNED: u32 = 1 << 3;
    pub const ZCOPY_DMA: u32 = 1 << 4;
    pub const ZCOPY_HUGE: u32 = 1 << 5;
    pub const ZCOPY_SHARED: u32 = 1 << 6;
}

impl ZeroCopyBuf {
    pub fn new(addr: u64, len: u32) -> Self {
        ZeroCopyBuf {
            data_ptr: addr,
            data_len: 0,
            buf_len: len,
            offset: 0,
            ref_count: AtomicU32::new(1),
            flags: 0,
            pool_id: 0,
            frag_index: 0,
        }
    }

    pub fn acquire(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::Acquire)
    }

    pub fn release(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::Release)
    }

    pub fn is_last(&self) -> bool {
        self.ref_count.load(Ordering::Relaxed) == 1
    }

    pub fn headroom(&self) -> u32 {
        self.offset
    }

    pub fn tailroom(&self) -> u32 {
        self.buf_len - self.offset - self.data_len
    }
}

/// Memory pool for zero-copy buffers
pub struct BufferPool {
    pub base_addr: u64,
    pub pool_size: u64,
    pub buf_size: u32,
    pub buf_count: u32,
    pub free_count: AtomicU32,
    pub free_list: [u32; 65536],
    pub free_head: AtomicU32,
    pub pool_id: u16,
    pub flags: u32,
    pub stats: PoolStats,
}

pub struct PoolStats {
    pub allocs: AtomicU64,
    pub frees: AtomicU64,
    pub alloc_failures: AtomicU64,
    pub total_bytes_managed: u64,
}

impl BufferPool {
    pub fn alloc_buf(&self) -> Option<u32> {
        let head = self.free_head.load(Ordering::Acquire);
        if head == 0 {
            self.stats.alloc_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // CAS to pop from free list
        let idx = head - 1;
        if self.free_head.compare_exchange(
            head, 
            if idx > 0 { self.free_list[idx as usize - 1] + 1 } else { 0 },
            Ordering::AcqRel,
            Ordering::Relaxed
        ).is_ok() {
            self.free_count.fetch_sub(1, Ordering::Relaxed);
            self.stats.allocs.fetch_add(1, Ordering::Relaxed);
            Some(idx)
        } else {
            None // Contention, retry at caller
        }
    }

    pub fn free_buf(&self, idx: u32) {
        self.free_count.fetch_add(1, Ordering::Relaxed);
        self.stats.frees.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// XDP (eXpress Data Path) Framework
// ============================================================================

/// XDP Action codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,      // Bounce back out same interface
    Redirect = 4, // Redirect to another interface or CPU
}

/// XDP metadata for packet processing
#[repr(C)]
pub struct XdpMd {
    pub data: u64,          // Start of packet data
    pub data_end: u64,      // End of packet data
    pub data_meta: u64,     // Metadata before packet
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

impl XdpMd {
    pub fn packet_len(&self) -> u64 {
        self.data_end - self.data
    }

    pub fn meta_len(&self) -> u64 {
        self.data - self.data_meta
    }
}

/// XDP program type
pub type XdpProgFn = fn(ctx: &XdpMd) -> XdpAction;

/// XDP program descriptor
pub struct XdpProgram {
    pub name: [u8; 64],
    pub prog_fn: Option<XdpProgFn>,
    pub ifindex: u32,
    pub flags: u32,
    pub attach_mode: XdpAttachMode,
    pub stats: XdpStats,
    pub run_count: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub enum XdpAttachMode {
    Native,      // Driver-level XDP (fastest)
    Generic,     // Generic/SKB XDP (fallback)
    Offload,     // Hardware offloaded XDP
    MultiProg,   // Multiple programs chained
}

pub struct XdpStats {
    pub packets_processed: AtomicU64,
    pub bytes_processed: AtomicU64,
    pub actions: [AtomicU64; 5], // Count per XdpAction
    pub errors: AtomicU64,
    pub redirect_errors: AtomicU64,
}

impl XdpStats {
    pub const fn new() -> Self {
        XdpStats {
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            actions: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0),
            ],
            errors: AtomicU64::new(0),
            redirect_errors: AtomicU64::new(0),
        }
    }
}

/// XDP redirect map entry
pub struct XdpRedirectEntry {
    pub ifindex: u32,
    pub flags: u32,
    pub queue: u32,
    pub cpu: u32,
}

/// XDP redirect map (for AF_XDP sockets, devmap, cpumap)
pub struct XdpMap {
    pub entries: [Option<XdpRedirectEntry>; 256],
    pub map_type: XdpMapType,
    pub max_entries: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum XdpMapType {
    DevMap,      // Redirect to other devices
    CpuMap,      // Redirect to other CPUs
    XskMap,      // Redirect to AF_XDP sockets
    DevMapHash,  // Hash-based device map
}

// ============================================================================  
// eBPF Virtual Machine for Network Programs
// ============================================================================

/// eBPF instruction
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInsn {
    pub code: u8,      // opcode
    pub regs: u8,      // dst_reg:4 | src_reg:4
    pub off: i16,      // offset
    pub imm: i32,      // immediate value
}

impl BpfInsn {
    pub fn dst_reg(&self) -> u8 { self.regs & 0xF }
    pub fn src_reg(&self) -> u8 { self.regs >> 4 }
}

/// BPF instruction classes
pub mod bpf_class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

/// BPF ALU operations
pub mod bpf_op {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const ARSH: u8 = 0xc0;
    pub const END: u8 = 0xd0;
}

/// BPF jump operations
pub mod bpf_jmp {
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
}

/// eBPF program types for networking
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfProgType {
    SocketFilter,
    Xdp,
    TcClassifier,
    CgroupSkb,
    LwtIn,
    LwtOut,
    LwtXmit,
    SkSkb,
    SkMsg,
    FlowDissector,
    // Zxyphor extensions
    ZxyPacketFilter,
    ZxyQos,
    ZxyLoadBalancer,
}

/// eBPF map types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfMapType {
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PerCpuHash,
    PerCpuArray,
    StackTrace,
    CgroupArray,
    LruHash,
    LruPerCpuHash,
    LpmTrie,
    ArrayOfMaps,
    HashOfMaps,
    DevMap,
    SockMap,
    CpuMap,
    XskMap,
    RingBuf,
    BloomFilter,
    // Zxyphor
    ZxyConnTrack,
    ZxyRateLimit,
}

/// BPF map descriptor
pub struct BpfMap {
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    pub name: [u8; 16],
    // Storage (simplified)
    pub data_ptr: u64,
    pub data_size: u64,
}

/// eBPF VM state
pub struct BpfVm {
    pub regs: [u64; 11], // R0-R10
    pub pc: usize,
    pub stack: [u8; 512],
    pub insn_count: u32,
    pub max_insns: u32,
}

impl BpfVm {
    pub fn new() -> Self {
        BpfVm {
            regs: [0; 11],
            pc: 0,
            stack: [0; 512],
            insn_count: 0,
            max_insns: 1_000_000,
        }
    }

    /// Execute BPF program
    pub fn execute(&mut self, program: &[BpfInsn], ctx: u64) -> Result<u64, BpfError> {
        self.regs[1] = ctx; // R1 = context pointer
        self.regs[10] = &self.stack as *const _ as u64 + 512; // R10 = frame pointer
        self.pc = 0;

        loop {
            if self.pc >= program.len() {
                return Err(BpfError::OutOfBounds);
            }
            if self.insn_count >= self.max_insns {
                return Err(BpfError::InstructionLimit);
            }

            let insn = program[self.pc];
            self.insn_count += 1;
            let dst = insn.dst_reg() as usize;
            let src = insn.src_reg() as usize;
            let class = insn.code & 0x07;
            let op = insn.code & 0xF0;
            let source = insn.code & 0x08; // BPF_K=0, BPF_X=8

            match class {
                bpf_class::ALU64 => {
                    let val = if source != 0 { self.regs[src] } else { insn.imm as u64 };
                    match op {
                        bpf_op::ADD => self.regs[dst] = self.regs[dst].wrapping_add(val),
                        bpf_op::SUB => self.regs[dst] = self.regs[dst].wrapping_sub(val),
                        bpf_op::MUL => self.regs[dst] = self.regs[dst].wrapping_mul(val),
                        bpf_op::DIV => {
                            if val == 0 { return Err(BpfError::DivByZero); }
                            self.regs[dst] /= val;
                        }
                        bpf_op::OR => self.regs[dst] |= val,
                        bpf_op::AND => self.regs[dst] &= val,
                        bpf_op::LSH => self.regs[dst] <<= val & 63,
                        bpf_op::RSH => self.regs[dst] >>= val & 63,
                        bpf_op::NEG => self.regs[dst] = (-(self.regs[dst] as i64)) as u64,
                        bpf_op::MOD => {
                            if val == 0 { return Err(BpfError::DivByZero); }
                            self.regs[dst] %= val;
                        }
                        bpf_op::XOR => self.regs[dst] ^= val,
                        bpf_op::MOV => self.regs[dst] = val,
                        bpf_op::ARSH => {
                            self.regs[dst] = ((self.regs[dst] as i64) >> (val & 63)) as u64;
                        }
                        _ => return Err(BpfError::InvalidInsn),
                    }
                }
                bpf_class::ALU => {
                    let val = if source != 0 { self.regs[src] as u32 } else { insn.imm as u32 };
                    let r = self.regs[dst] as u32;
                    let result = match op {
                        bpf_op::ADD => r.wrapping_add(val),
                        bpf_op::SUB => r.wrapping_sub(val),
                        bpf_op::MUL => r.wrapping_mul(val),
                        bpf_op::DIV => {
                            if val == 0 { return Err(BpfError::DivByZero); }
                            r / val
                        }
                        bpf_op::OR => r | val,
                        bpf_op::AND => r & val,
                        bpf_op::LSH => r << (val & 31),
                        bpf_op::RSH => r >> (val & 31),
                        bpf_op::MOD => {
                            if val == 0 { return Err(BpfError::DivByZero); }
                            r % val
                        }
                        bpf_op::XOR => r ^ val,
                        bpf_op::MOV => val,
                        _ => return Err(BpfError::InvalidInsn),
                    };
                    self.regs[dst] = result as u64;
                }
                bpf_class::JMP => {
                    let val = if source != 0 { self.regs[src] } else { insn.imm as u64 };
                    let taken = match op {
                        bpf_jmp::JA => true,
                        bpf_jmp::JEQ => self.regs[dst] == val,
                        bpf_jmp::JGT => self.regs[dst] > val,
                        bpf_jmp::JGE => self.regs[dst] >= val,
                        bpf_jmp::JSET => self.regs[dst] & val != 0,
                        bpf_jmp::JNE => self.regs[dst] != val,
                        bpf_jmp::JSGT => (self.regs[dst] as i64) > (val as i64),
                        bpf_jmp::JSGE => (self.regs[dst] as i64) >= (val as i64),
                        bpf_jmp::JLT => self.regs[dst] < val,
                        bpf_jmp::JLE => self.regs[dst] <= val,
                        bpf_jmp::JSLT => (self.regs[dst] as i64) < (val as i64),
                        bpf_jmp::JSLE => (self.regs[dst] as i64) <= (val as i64),
                        bpf_jmp::EXIT => return Ok(self.regs[0]),
                        bpf_jmp::CALL => {
                            self.regs[0] = self.call_helper(insn.imm as u32)?;
                            false
                        }
                        _ => return Err(BpfError::InvalidInsn),
                    };
                    if taken {
                        self.pc = (self.pc as i64 + insn.off as i64) as usize;
                    }
                }
                _ => return Err(BpfError::InvalidInsn),
            }

            self.pc += 1;
        }
    }

    fn call_helper(&mut self, helper_id: u32) -> Result<u64, BpfError> {
        match helper_id {
            1 => Ok(0), // bpf_map_lookup_elem
            2 => Ok(0), // bpf_map_update_elem
            3 => Ok(0), // bpf_map_delete_elem
            6 => Ok(self.get_prandom()), // bpf_get_prandom_u32
            14 => Ok(self.get_current_pid()), // bpf_get_current_pid_tgid
            51 => Ok(0), // bpf_redirect
            52 => Ok(0), // bpf_redirect_map
            _ => Err(BpfError::InvalidHelper),
        }
    }

    fn get_prandom(&self) -> u64 {
        // Simplified PRNG
        let mut x = self.insn_count as u64;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }

    fn get_current_pid(&self) -> u64 {
        0 // Would return actual pid in kernel
    }
}

#[derive(Debug)]
pub enum BpfError {
    InvalidInsn,
    OutOfBounds,
    DivByZero,
    InstructionLimit,
    InvalidHelper,
    MemoryAccess,
    InvalidMap,
}

// ============================================================================
// Traffic Control (TC) Framework
// ============================================================================

/// TC qdisc types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QdiscType {
    Pfifo,     // Simple FIFO
    PfifoFast, // Priority FIFO
    Tbf,       // Token Bucket Filter
    Htb,       // Hierarchical Token Bucket
    Fq,        // Fair Queuing
    FqCodel,   // Fair Queuing + CoDel AQM
    Cake,      // Common Applications Kept Enhanced
    Netem,     // Network Emulator
    Red,       // Random Early Detection
    Sfq,       // Stochastic Fair Queuing
    Mqprio,    // Multi-Queue Priority
    Ets,       // Enhanced Transmission Selection
    // Zxyphor
    ZxyAdaptive, // AI-assisted adaptive QoS
}

/// Token Bucket Filter state
pub struct TbfState {
    pub rate: u64,      // bytes per second
    pub burst: u64,     // max burst size
    pub tokens: u64,    // current tokens
    pub last_fill: u64, // timestamp of last token fill
    pub peak_rate: u64, // peak rate
    pub mtu: u32,
    pub buffer_size: u32,
    pub limit: u32,     // queue limit
}

impl TbfState {
    pub fn new(rate: u64, burst: u64) -> Self {
        TbfState {
            rate,
            burst,
            tokens: burst,
            last_fill: 0,
            peak_rate: 0,
            mtu: 1500,
            buffer_size: 0,
            limit: 1000,
        }
    }

    pub fn refill(&mut self, now: u64) {
        if now <= self.last_fill { return; }
        let elapsed = now - self.last_fill;
        let new_tokens = (self.rate * elapsed) / 1_000_000;
        self.tokens = core::cmp::min(self.tokens + new_tokens, self.burst);
        self.last_fill = now;
    }

    pub fn consume(&mut self, bytes: u64, now: u64) -> bool {
        self.refill(now);
        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

/// CoDel (Controlled Delay) AQM state
pub struct CodelState {
    pub target: u64,       // Target delay (5ms default)
    pub interval: u64,     // Interval (100ms default)
    pub first_above_time: u64,
    pub drop_next: u64,
    pub count: u32,
    pub lastcount: u32,
    pub dropping: bool,
    pub ce_threshold: u64, // ECN CE marking threshold
}

impl CodelState {
    pub fn new() -> Self {
        CodelState {
            target: 5_000,      // 5ms
            interval: 100_000,  // 100ms
            first_above_time: 0,
            drop_next: 0,
            count: 0,
            lastcount: 0,
            dropping: false,
            ce_threshold: u64::MAX,
        }
    }

    pub fn should_drop(&mut self, sojourn_time: u64, now: u64) -> CodelAction {
        if sojourn_time < self.target {
            self.first_above_time = 0;
            return CodelAction::Pass;
        }

        if self.first_above_time == 0 {
            self.first_above_time = now + self.interval;
            return CodelAction::Pass;
        }

        if now >= self.first_above_time {
            if !self.dropping {
                self.dropping = true;
                self.count = if self.count > 2 && now - self.drop_next < 16 * self.interval {
                    self.count - 2
                } else {
                    1
                };
                self.drop_next = now + self.control_law();
                return CodelAction::Drop;
            }

            if now >= self.drop_next {
                self.count += 1;
                self.drop_next = now + self.control_law();
                // Mark ECN if possible, otherwise drop
                if sojourn_time < self.ce_threshold {
                    return CodelAction::Mark;
                }
                return CodelAction::Drop;
            }
        }

        CodelAction::Pass
    }

    fn control_law(&self) -> u64 {
        // interval / sqrt(count)
        let sqrt_count = isqrt(self.count as u64);
        if sqrt_count > 0 { self.interval / sqrt_count } else { self.interval }
    }
}

fn isqrt(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[derive(Debug, Clone, Copy)]
pub enum CodelAction {
    Pass,
    Drop,
    Mark, // ECN mark
}

/// Hierarchical Token Bucket (HTB) class
pub struct HtbClass {
    pub class_id: u32,
    pub parent_id: u32,
    pub rate: u64,        // Guaranteed rate
    pub ceil: u64,        // Maximum rate
    pub burst: u64,
    pub cburst: u64,
    pub quantum: u32,
    pub prio: u8,
    pub level: u8,
    pub tokens: i64,
    pub ctokens: i64,
    pub t_c: u64,         // Last token update
    pub children: [u32; 16],
    pub child_count: u8,
}

impl HtbClass {
    pub fn new(class_id: u32, rate: u64, ceil: u64) -> Self {
        HtbClass {
            class_id,
            parent_id: 0,
            rate,
            ceil,
            burst: rate / 8,
            cburst: ceil / 8,
            quantum: 1500,
            prio: 0,
            level: 0,
            tokens: 0,
            ctokens: 0,
            t_c: 0,
            children: [0; 16],
            child_count: 0,
        }
    }

    pub fn charge(&mut self, bytes: u64, now: u64) {
        // Refill tokens
        let elapsed = now.saturating_sub(self.t_c);
        self.tokens += (self.rate as i64 * elapsed as i64) / 1_000_000;
        self.ctokens += (self.ceil as i64 * elapsed as i64) / 1_000_000;
        self.t_c = now;

        // Clamp
        if self.tokens > self.burst as i64 { self.tokens = self.burst as i64; }
        if self.ctokens > self.cburst as i64 { self.ctokens = self.cburst as i64; }

        // Consume
        self.tokens -= bytes as i64;
        self.ctokens -= bytes as i64;
    }

    pub fn can_send(&self) -> bool {
        self.ctokens >= 0
    }

    pub fn is_overlimit(&self) -> bool {
        self.tokens < 0
    }
}

// ============================================================================
// Netfilter / Firewall Framework
// ============================================================================

/// Netfilter hook points
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NfHook {
    PreRouting = 0,
    LocalIn = 1,
    Forward = 2,
    LocalOut = 3,
    PostRouting = 4,
}

/// Netfilter verdict
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NfVerdict {
    Accept,
    Drop,
    Stolen,
    Queue,
    Repeat,
    Stop,
}

/// Connection tracking state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnTrackState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

/// Layer 4 protocol
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum L4Proto {
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    Icmpv6 = 58,
    Sctp = 132,
    Dccp = 33,
    Gre = 47,
}

/// Connection tracking tuple
#[derive(Clone, Copy)]
pub struct ConnTuple {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub l3proto: u8, // 4 = IPv4, 6 = IPv6
    pub l4proto: u8,
}

impl ConnTuple {
    pub fn hash(&self) -> u32 {
        let mut h: u32 = 2166136261;
        for b in &self.src_addr {
            h ^= *b as u32;
            h = h.wrapping_mul(16777619);
        }
        for b in &self.dst_addr {
            h ^= *b as u32;
            h = h.wrapping_mul(16777619);
        }
        h ^= self.src_port as u32;
        h = h.wrapping_mul(16777619);
        h ^= self.dst_port as u32;
        h = h.wrapping_mul(16777619);
        h ^= self.l4proto as u32;
        h
    }

    pub fn invert(&self) -> ConnTuple {
        ConnTuple {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
            src_port: self.dst_port,
            dst_port: self.src_port,
            l3proto: self.l3proto,
            l4proto: self.l4proto,
        }
    }
}

/// Connection tracking entry
pub struct ConnTrackEntry {
    pub original: ConnTuple,
    pub reply: ConnTuple,
    pub state: ConnTrackState,
    pub timeout: u64,
    pub mark: u32,
    pub zone: u16,
    pub status: u32,
    pub packets_orig: u64,
    pub bytes_orig: u64,
    pub packets_reply: u64,
    pub bytes_reply: u64,
    pub nat_src: Option<[u8; 16]>,
    pub nat_dst: Option<[u8; 16]>,
    pub nat_sport: Option<u16>,
    pub nat_dport: Option<u16>,
    pub helper: Option<ConnHelper>,
    pub label: [u64; 4],
}

pub mod ct_status {
    pub const EXPECTED: u32 = 1 << 0;
    pub const SEEN_REPLY: u32 = 1 << 1;
    pub const ASSURED: u32 = 1 << 2;
    pub const CONFIRMED: u32 = 1 << 3;
    pub const SRC_NAT: u32 = 1 << 4;
    pub const DST_NAT: u32 = 1 << 5;
    pub const DYING: u32 = 1 << 9;
    pub const FIXED_TIMEOUT: u32 = 1 << 10;
    pub const TEMPLATE: u32 = 1 << 11;
    pub const OFFLOAD: u32 = 1 << 14;
    pub const HW_OFFLOAD: u32 = 1 << 15;
}

/// Connection tracking helper (ALG)
#[derive(Debug, Clone, Copy)]
pub enum ConnHelper {
    Ftp,
    Sip,
    H323,
    Pptp,
    Tftp,
    Amanda,
    Irc,
}

/// NAT type
#[derive(Debug, Clone, Copy)]
pub enum NatType {
    Snat,
    Dnat,
    Masquerade,
    Redirect,
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
}

/// Firewall rule
pub struct FwRule {
    pub priority: i32,
    pub table: FwTable,
    pub chain: FwChain,
    pub matches: FwMatch,
    pub target: FwTarget,
    pub counters: FwCounters,
    pub enabled: bool,
    pub comment: [u8; 64],
}

#[derive(Debug, Clone, Copy)]
pub enum FwTable {
    Filter,
    Nat,
    Mangle,
    Raw,
    Security,
}

#[derive(Debug, Clone, Copy)]
pub enum FwChain {
    Input,
    Forward,
    Output,
    PreRouting,
    PostRouting,
    Custom(u32),
}

pub struct FwMatch {
    pub src_addr: Option<([u8; 16], [u8; 16])>,  // addr, mask
    pub dst_addr: Option<([u8; 16], [u8; 16])>,
    pub src_port: Option<(u16, u16)>,  // range
    pub dst_port: Option<(u16, u16)>,
    pub protocol: Option<u8>,
    pub iface_in: Option<[u8; 16]>,
    pub iface_out: Option<[u8; 16]>,
    pub ct_state: Option<ConnTrackState>,
    pub mark: Option<(u32, u32)>,       // value, mask
    pub dscp: Option<u8>,
    pub tcp_flags: Option<(u8, u8)>,    // mask, value
    pub limit_rate: Option<u32>,
    pub limit_burst: Option<u32>,
    pub negate: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum FwTarget {
    Accept,
    Drop,
    Reject(RejectType),
    Log(u8),
    Snat([u8; 16]),
    Dnat([u8; 16]),
    Masquerade,
    Redirect(u16),
    Mark(u32),
    Dscp(u8),
    Connmark(u32),
    Return,
    Queue(u16),
    Jump(u32),
    Goto(u32),
    Tproxy(u16),
    Nflog(u16),
}

#[derive(Debug, Clone, Copy)]
pub enum RejectType {
    IcmpPortUnreach,
    IcmpNetUnreach,
    IcmpHostUnreach,
    IcmpProtoUnreach,
    IcmpNetProhib,
    IcmpHostProhib,
    IcmpAdminProhib,
    TcpReset,
}

pub struct FwCounters {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
}

impl FwCounters {
    pub fn new() -> Self {
        FwCounters {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    pub fn count(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

// ============================================================================
// Socket Splice / sendfile Support
// ============================================================================

/// Splice operation descriptor
pub struct SpliceDesc {
    pub src_fd: i32,
    pub dst_fd: i32,
    pub src_offset: i64,
    pub dst_offset: i64,
    pub len: u64,
    pub flags: u32,
    pub pipe_pages: [u64; 16],
    pub pipe_count: u8,
}

pub mod splice_flags {
    pub const SPLICE_F_MOVE: u32 = 0x01;
    pub const SPLICE_F_NONBLOCK: u32 = 0x02;
    pub const SPLICE_F_MORE: u32 = 0x04;
    pub const SPLICE_F_GIFT: u32 = 0x08;
}

/// TCP splice state
pub struct TcpSplice {
    pub active: bool,
    pub src_sock: u64,
    pub dst_sock: u64,
    pub bytes_spliced: u64,
    pub flags: u32,
}

// ============================================================================
// AF_XDP Socket Support
// ============================================================================

/// UMEM descriptor for AF_XDP
pub struct XskUmem {
    pub addr: u64,
    pub size: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
    pub fill_ring: XskRing,
    pub comp_ring: XskRing,
}

/// Ring buffer for AF_XDP
pub struct XskRing {
    pub producer: AtomicU32,
    pub consumer: AtomicU32,
    pub size: u32,
    pub mask: u32,
    pub desc: u64, // pointer to descriptors
    pub flags: AtomicU32,
}

impl XskRing {
    pub fn available(&self) -> u32 {
        let prod = self.producer.load(Ordering::Acquire);
        let cons = self.consumer.load(Ordering::Acquire);
        prod.wrapping_sub(cons)
    }

    pub fn space(&self) -> u32 {
        self.size - self.available()
    }
}

/// AF_XDP socket descriptor
#[repr(C)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// AF_XDP socket
pub struct XskSocket {
    pub umem: u64, // pointer to XskUmem
    pub rx_ring: XskRing,
    pub tx_ring: XskRing,
    pub ifindex: u32,
    pub queue_id: u32,
    pub flags: u32,
    pub busy_poll_budget: u32,
}

pub mod xsk_flags {
    pub const XDP_SHARED_UMEM: u32 = 1 << 0;
    pub const XDP_COPY: u32 = 1 << 1;
    pub const XDP_ZEROCOPY: u32 = 1 << 2;
    pub const XDP_USE_NEED_WAKEUP: u32 = 1 << 3;
}

// ============================================================================
// Network Statistics
// ============================================================================

pub struct NetStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
    pub xdp_redirect: AtomicU64,
    pub xdp_drop: AtomicU64,
    pub xdp_pass: AtomicU64,
    pub xdp_tx: AtomicU64,
    pub tc_drops: AtomicU64,
    pub tc_marks: AtomicU64,
    pub nf_drops: AtomicU64,
    pub nf_accepts: AtomicU64,
    pub ct_entries: AtomicU32,
    pub ct_found: AtomicU64,
    pub ct_new: AtomicU64,
    pub ct_invalid: AtomicU64,
}

impl NetStats {
    pub const fn new() -> Self {
        NetStats {
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
            xdp_redirect: AtomicU64::new(0),
            xdp_drop: AtomicU64::new(0),
            xdp_pass: AtomicU64::new(0),
            xdp_tx: AtomicU64::new(0),
            tc_drops: AtomicU64::new(0),
            tc_marks: AtomicU64::new(0),
            nf_drops: AtomicU64::new(0),
            nf_accepts: AtomicU64::new(0),
            ct_entries: AtomicU32::new(0),
            ct_found: AtomicU64::new(0),
            ct_new: AtomicU64::new(0),
            ct_invalid: AtomicU64::new(0),
        }
    }
}

static NET_STATS: NetStats = NetStats::new();

pub fn get_net_stats() -> &'static NetStats {
    &NET_STATS
}
