// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Rust BPF Socket & XDP Advanced
// Complete BPF map types implementation, XDP actions,
// AF_XDP (XSK), XDP metadata, devmap/cpumap, XDP batching

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

// ============================================================================
// BPF Map Types (Complete)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfMapType {
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    CgroupStorage = 19,
    ReuseportSockarray = 20,
    PercpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevmapHash = 25,
    StructOps = 26,
    RingBuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingBuf = 31,
    CgroupStorage2 = 32,
    Arena = 33,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfMapAttr {
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: BpfMapFlags,
    pub inner_map_fd: i32,
    pub numa_node: u32,
    pub map_name: [u8; 16],
    pub map_ifindex: u32,
    pub btf_fd: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub map_extra: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfMapFlags {
    bits: u32,
}

impl BpfMapFlags {
    pub const NO_PREALLOC: u32 = 1 << 0;
    pub const NO_COMMON_LRU: u32 = 1 << 1;
    pub const NUMA_NODE: u32 = 1 << 2;
    pub const RDONLY: u32 = 1 << 3;
    pub const WRONLY: u32 = 1 << 4;
    pub const STACK_BUILD_ID: u32 = 1 << 5;
    pub const ZERO_SEED: u32 = 1 << 6;
    pub const RDONLY_PROG: u32 = 1 << 7;
    pub const WRONLY_PROG: u32 = 1 << 8;
    pub const CLONE: u32 = 1 << 9;
    pub const MMAPABLE: u32 = 1 << 10;
    pub const PRESERVE_ELEMS: u32 = 1 << 11;
    pub const INNER_MAP: u32 = 1 << 12;
    pub const LINK: u32 = 1 << 13;
    pub const PATH_FD: u32 = 1 << 14;
    pub const VTYPE_BTF_OBJ_FD: u32 = 1 << 15;
    pub const TOKEN_FD: u32 = 1 << 16;
    pub const SEGV_ON_FAULT: u32 = 1 << 17;
}

// ============================================================================
// XDP Actions
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

#[repr(C)]
pub struct XdpMd {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

#[repr(C)]
pub struct XdpFrame {
    pub data: *mut u8,
    pub len: u16,
    pub headroom: u16,
    pub metasize: u32,
    pub frame_sz: u32,
    pub flags: XdpFrameFlags,
    pub mem_type: XdpMemType,
    pub dev_rx: u64,
    pub rxq: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub struct XdpFrameFlags {
    bits: u32,
}

impl XdpFrameFlags {
    pub const FRAG_PF_MEMALLOC: u32 = 1 << 0;
    pub const XDP_FLAGS_HAS_FRAGS: u32 = 1 << 1;
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpMemType {
    PageShared = 0,
    PageOrder0 = 1,
    PagePool = 2,
    XskBufPool = 3,
}

// ============================================================================
// XDP Metadata (kfuncs)
// ============================================================================

#[repr(C)]
pub struct XdpMetadata {
    pub rx_timestamp: u64,
    pub rx_hash: u32,
    pub rx_hash_type: XdpRssHashType,
    pub vlan_proto: u16,
    pub vlan_tci: u16,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XdpRssHashType {
    None = 0,
    L3Ipv4 = 1 << 0,
    L3Ipv6 = 1 << 1,
    L4Tcp = 1 << 2,
    L4Udp = 1 << 3,
    L4Sctp = 1 << 4,
    L4Ipsec = 1 << 5,
}

// ============================================================================
// AF_XDP (XSK - XDP Socket)
// ============================================================================

#[repr(C)]
pub struct XskSocketConfig {
    pub rx_size: u32,
    pub tx_size: u32,
    pub fill_size: u32,
    pub comp_size: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub flags: XskSocketFlags,
    pub bind_flags: XskBindFlags,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XskSocketFlags {
    bits: u32,
}

impl XskSocketFlags {
    pub const XDP_SHARED_UMEM: u32 = 1 << 0;
    pub const XDP_COPY: u32 = 1 << 1;
    pub const XDP_ZEROCOPY: u32 = 1 << 2;
    pub const XDP_USE_NEED_WAKEUP: u32 = 1 << 3;
    pub const XDP_USE_SG: u32 = 1 << 4;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XskBindFlags {
    bits: u16,
}

impl XskBindFlags {
    pub const XDP_SHARED_UMEM: u16 = 1 << 0;
    pub const XDP_COPY: u16 = 1 << 1;
    pub const XDP_ZEROCOPY: u16 = 1 << 2;
    pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
}

#[repr(C)]
pub struct XdpUmem {
    pub umem_area: u64,
    pub umem_size: u64,
    pub headroom: u32,
    pub chunk_size: u32,
    pub chunks: u32,
    pub npgs: u32,
    pub flags: u32,
    pub zc: bool,
    pub need_wakeup: bool,
    pub fq: XskQueue,
    pub cq: XskQueue,
}

#[repr(C)]
pub struct XskQueue {
    pub ring_mask: u32,
    pub nentries: u32,
    pub cached_prod: u32,
    pub cached_cons: u32,
    pub ring: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct XdpDescriptor {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

// ============================================================================
// Devmap / Cpumap
// ============================================================================

#[repr(C)]
pub struct DevmapVal {
    pub ifindex: u32,
    pub bpf_prog_fd: i32,
}

#[repr(C)]
pub struct CpumapVal {
    pub qsize: u32,
    pub bpf_prog_fd: i32,
}

#[repr(C)]
pub struct XdpBulkQueue {
    pub q: [64; u64],       // XDP frame pointers
    pub count: u32,
    pub dev_rx: u64,
    pub dev: u64,
}

// ============================================================================
// XDP Batching
// ============================================================================

pub const XDP_BATCH_SIZE: usize = 64;

#[repr(C)]
pub struct XdpBatch {
    pub frames: [u64; 64],  // Frame pointers
    pub cnt: u32,
    pub act_stats: [u64; 5], // Per-action counters
}

#[repr(C)]
pub struct XdpTxqInfo {
    pub dev: u64,
    pub queue_index: u32,
}

// ============================================================================
// BPF LPM Trie
// ============================================================================

#[repr(C)]
pub struct BpfLpmTrieKey {
    pub prefixlen: u32,
    pub data: [16; u8],     // Max 128 bits for IPv6
}

#[repr(C)]
pub struct LpmTrieNode {
    pub flags: u32,
    pub prefixlen: u32,
    pub child: [u64; 2],    // Left/right child pointers
    pub data: [u8; 128],    // Variable key + value
}

// ============================================================================
// BPF Stack Map
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum BpfStackBuildIdStatus {
    Empty = 0,
    Valid = 1,
    Ip = 2,
}

#[repr(C)]
pub struct BpfStackBuildId {
    pub status: BpfStackBuildIdStatus,
    pub build_id: [u8; 20],
    pub offset: u64,
    pub ip: u64,
}

// ============================================================================
// eBPF Instruction Set
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_src_reg: u8,    // dst:4 | src:4
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub fn dst_reg(&self) -> u8 { self.dst_src_reg & 0x0f }
    pub fn src_reg(&self) -> u8 { (self.dst_src_reg >> 4) & 0x0f }
}

// BPF instruction classes
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_RET: u8 = 0x06;
pub const BPF_MISC: u8 = 0x07;
pub const BPF_ALU64: u8 = 0x07;
pub const BPF_JMP32: u8 = 0x06;

// ALU operations
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;
pub const BPF_END: u8 = 0xd0;

// JMP operations
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

// ============================================================================
// Statistics
// ============================================================================

pub struct BpfXdpStats {
    pub total_maps_created: AtomicU64,
    pub total_progs_loaded: AtomicU64,
    pub total_xdp_pass: AtomicU64,
    pub total_xdp_drop: AtomicU64,
    pub total_xdp_tx: AtomicU64,
    pub total_xdp_redirect: AtomicU64,
    pub total_xdp_aborted: AtomicU64,
    pub total_xsk_rx: AtomicU64,
    pub total_xsk_tx: AtomicU64,
    pub total_xsk_rx_dropped: AtomicU64,
    pub total_devmap_xmit: AtomicU64,
    pub total_cpumap_enqueue: AtomicU64,
    pub total_cpumap_kthread_flush: AtomicU64,
    pub initialized: bool,
}

impl BpfXdpStats {
    pub const fn new() Self {
        Self {
            total_maps_created: AtomicU64::new(0),
            total_progs_loaded: AtomicU64::new(0),
            total_xdp_pass: AtomicU64::new(0),
            total_xdp_drop: AtomicU64::new(0),
            total_xdp_tx: AtomicU64::new(0),
            total_xdp_redirect: AtomicU64::new(0),
            total_xdp_aborted: AtomicU64::new(0),
            total_xsk_rx: AtomicU64::new(0),
            total_xsk_tx: AtomicU64::new(0),
            total_xsk_rx_dropped: AtomicU64::new(0),
            total_devmap_xmit: AtomicU64::new(0),
            total_cpumap_enqueue: AtomicU64::new(0),
            total_cpumap_kthread_flush: AtomicU64::new(0),
            initialized: true,
        }
    }
}
