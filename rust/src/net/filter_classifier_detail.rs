// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel (Rust) - Network Filter & Traffic Classifier Detail
// Complete: cls_bpf, cls_flower, cls_u32, cls_matchall, cls_route,
// traffic actions (mirred, gact, pedit, skbedit, connmark, ct),
// filter block, chain management, hardware offload

// ============================================================================
// TC Filter Types
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcFilterKind {
    U32 = 1,
    Route = 2,
    Fw = 3,
    Rsvp = 4,
    Rsvp6 = 5,
    Basic = 6,
    Flow = 7,
    Cgroup = 8,
    Bpf = 9,
    Flower = 10,
    Matchall = 11,
    Ct = 12,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum TcFilterProtocol {
    All = 0x0003,
    Ipv4 = 0x0800,
    Ipv6 = 0x86DD,
    Arp = 0x0806,
    Vlan8021Q = 0x8100,
    Vlan8021AD = 0x88A8,
    Mpls = 0x8847,
    Pppoe = 0x8864,
    Lldp = 0x88CC,
    Eapol = 0x888E,
}

// ============================================================================
// cls_flower
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct FlowerKey {
    pub eth_type: u16,
    pub ip_proto: u8,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan_id: u16,
    pub vlan_prio: u8,
    pub vlan_tpid: u16,
    pub cvlan_id: u16,
    pub cvlan_prio: u8,
    pub cvlan_tpid: u16,
    pub ipv4_src: u32,
    pub ipv4_dst: u32,
    pub ipv6_src: [u8; 16],
    pub ipv6_dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub ip_tos: u8,
    pub ip_ttl: u8,
    pub tcp_flags: u16,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub arp_op: u16,
    pub arp_sip: u32,
    pub arp_tip: u32,
    pub arp_sha: [u8; 6],
    pub arp_tha: [u8; 6],
    pub mpls_lse: [MplsLse; 4],
    pub enc_key_id: u32,
    pub enc_ipv4_src: u32,
    pub enc_ipv4_dst: u32,
    pub enc_ipv6_src: [u8; 16],
    pub enc_ipv6_dst: [u8; 16],
    pub enc_tp_src: u16,
    pub enc_tp_dst: u16,
    pub enc_ip_tos: u8,
    pub enc_ip_ttl: u8,
    pub enc_opts: [u8; 256],
    pub ct_state: u16,
    pub ct_zone: u16,
    pub ct_mark: u32,
    pub ct_labels: [u8; 16],
    pub pppoe_sid: u16,
    pub meta_id: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FlowerMask {
    pub eth_type: u16,
    pub ip_proto: u8,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan_id: u16,
    pub vlan_prio: u8,
    pub cvlan_id: u16,
    pub ipv4_src: u32,
    pub ipv4_dst: u32,
    pub ipv6_src: [u8; 16],
    pub ipv6_dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_tos: u8,
    pub ip_ttl: u8,
    pub tcp_flags: u16,
    pub ct_state: u16,
    pub ct_zone: u16,
    pub ct_mark: u32,
    pub ct_labels: [u8; 16],
}

#[derive(Debug, Clone, Default, Copy)]
pub struct MplsLse {
    pub label: u32,
    pub tc: u8,
    pub bos: u8,
    pub ttl: u8,
}

#[derive(Debug, Clone)]
pub struct FlowerFilter {
    pub handle: u32,
    pub classid: u32,
    pub key: FlowerKey,
    pub mask: FlowerMask,
    pub actions: Vec<TcAction>,
    pub flags: FlowerFlags,
    pub hw_stats: TcHwStats,
    pub cookie: Option<Vec<u8>>,
    pub in_hw: bool,
    pub in_hw_count: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowerFlags {
    pub skip_hw: bool,
    pub skip_sw: bool,
    pub no_percpu_stats: bool,
    pub verbose: bool,
}

// ============================================================================
// cls_u32
// ============================================================================

#[derive(Debug, Clone)]
pub struct U32Key {
    pub val: u32,
    pub mask: u32,
    pub off: i32,     // Offset into packet
    pub offmask: u32,
}

#[derive(Debug, Clone)]
pub struct U32Selector {
    pub flags: u8,
    pub offshift: u8,
    pub nkeys: u8,
    pub offmask: u16,
    pub off: u16,
    pub offoff: i16,
    pub hoff: i16,
    pub hmask: u32,
    pub keys: Vec<U32Key>,
}

#[derive(Debug, Clone)]
pub struct U32Filter {
    pub handle: u32,
    pub classid: u32,
    pub divisor: u32,
    pub link: u32,          // Link to hash table
    pub selector: U32Selector,
    pub pcnt: U32PerfCounters,
    pub actions: Vec<TcAction>,
    pub flags: u32,
    pub in_hw: bool,
}

#[derive(Debug, Clone, Default)]
pub struct U32PerfCounters {
    pub rcnt: u64,
    pub rhit: u64,
    pub kcnts: Vec<u64>,
}

// ============================================================================
// cls_bpf
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ClsBpfMode {
    DirectAction = 0,
    ClassId = 1,
}

#[derive(Debug, Clone)]
pub struct BpfFilter {
    pub handle: u32,
    pub classid: u32,
    pub prog_fd: i32,
    pub prog_name: [u8; 64],
    pub mode: ClsBpfMode,
    pub gen_flags: u32,
    pub actions: Vec<TcAction>,
    pub in_hw: bool,
    pub offloaded: bool,
    pub tag: [u8; 8],
    pub id: u32,
}

// ============================================================================
// cls_matchall
// ============================================================================

#[derive(Debug, Clone)]
pub struct MatchallFilter {
    pub handle: u32,
    pub classid: u32,
    pub actions: Vec<TcAction>,
    pub flags: FlowerFlags,
    pub in_hw: bool,
    pub in_hw_count: u32,
    pub prio: u32,
}

// ============================================================================
// TC Actions
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcActionKind {
    Gact = 1,
    Mirred = 2,
    Pedit = 3,
    Nat = 4,
    Skbedit = 5,
    Vlan = 6,
    Connmark = 7,
    Ct = 8,
    Tunnel = 9,
    Sample = 10,
    Police = 11,
    Gate = 12,
    Mpls = 13,
    Csum = 14,
    Skbmod = 15,
    Bpf = 16,
    Ife = 17,
    Simp = 18,
    CtInfo = 19,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum TcActionResult {
    Ok = 0,        // TC_ACT_OK
    Reclassify = 1,
    Shot = 2,      // TC_ACT_SHOT - drop
    Pipe = 3,      // Continue to next action
    Stolen = 4,
    Queued = 5,
    Repeat = 6,
    Redirect = 7,
    Trap = 8,
    Unspec = -1,
}

#[derive(Debug, Clone)]
pub struct TcAction {
    pub kind: TcActionKind,
    pub order: u32,
    pub index: u32,
    pub control: TcActionResult,
    pub cookie: Option<Vec<u8>>,
    pub stats: TcActionStats,
    pub hw_stats: TcHwStats,
    pub specific: TcActionSpecific,
}

#[derive(Debug, Clone, Default)]
pub struct TcActionStats {
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub overlimits: u64,
    pub lastuse: u64,
    pub first_use: u64,
    pub hw_bytes: u64,
    pub hw_packets: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcHwStats {
    pub request: TcHwStatsType,
    pub active: TcHwStatsType,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcHwStatsType {
    pub immediate: bool,
    pub delayed: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone)]
pub enum TcActionSpecific {
    Gact(GactAction),
    Mirred(MirredAction),
    Pedit(PeditAction),
    Skbedit(SkbeditAction),
    Vlan(VlanAction),
    Connmark(ConnmarkAction),
    Ct(CtAction),
    Tunnel(TunnelAction),
    Police(PoliceAction),
    Gate(GateAction),
    Mpls(MplsAction),
    Csum(CsumAction),
    Sample(SampleAction),
}

// ============================================================================
// Action Details
// ============================================================================

#[derive(Debug, Clone)]
pub struct GactAction {
    pub action: TcActionResult,
    pub paction: TcActionResult,    // Probability action
    pub pval: u16,                  // Probability value (0-10000)
    pub ptype: GactProbType,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum GactProbType {
    None = 0,
    Random = 1,
    Netrand = 2,
    Determ = 3,
}

#[derive(Debug, Clone)]
pub struct MirredAction {
    pub eaction: MirredEaction,
    pub ifindex: i32,
    pub blockid: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MirredEaction {
    Egress_Redir = 1,
    Egress_Mirror = 2,
    Ingress_Redir = 3,
    Ingress_Mirror = 4,
}

#[derive(Debug, Clone)]
pub struct PeditAction {
    pub nkeys: u32,
    pub flags: u32,
    pub keys: Vec<PeditKey>,
    pub keys_ex: Vec<PeditKeyEx>,
}

#[derive(Debug, Clone)]
pub struct PeditKey {
    pub mask: u32,
    pub val: u32,
    pub off: u32,
    pub at: u32,
    pub offmask: u32,
    pub shift: u32,
}

#[derive(Debug, Clone)]
pub struct PeditKeyEx {
    pub htype: PeditHeaderType,
    pub cmd: PeditCmd,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum PeditHeaderType {
    Network = 0,
    Eth = 1,
    Ip4 = 2,
    Ip6 = 3,
    Tcp = 4,
    Udp = 5,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum PeditCmd {
    Set = 0,
    Add = 1,
}

#[derive(Debug, Clone)]
pub struct SkbeditAction {
    pub queue_mapping: Option<u16>,
    pub priority: Option<u32>,
    pub mark: Option<u32>,
    pub mask: Option<u32>,
    pub ptype: Option<u16>,
    pub flags: u64,
}

#[derive(Debug, Clone)]
pub struct VlanAction {
    pub action: VlanActionType,
    pub vlan_id: u16,
    pub vlan_prio: u8,
    pub vlan_proto: u16,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VlanActionType {
    Pop = 1,
    Push = 2,
    Modify = 3,
    PopEth = 4,
    PushEth = 5,
}

#[derive(Debug, Clone)]
pub struct ConnmarkAction {
    pub zone: u16,
}

#[derive(Debug, Clone)]
pub struct CtAction {
    pub action: CtActionType,
    pub zone: u16,
    pub mark: u32,
    pub mark_mask: u32,
    pub labels: [u8; 16],
    pub labels_mask: [u8; 16],
    pub nat_addr_min: CtNatAddr,
    pub nat_addr_max: CtNatAddr,
    pub nat_port_min: u16,
    pub nat_port_max: u16,
    pub nat_type: CtNatType,
    pub helper_name: [u8; 32],
    pub helper_family: u16,
    pub helper_proto: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CtActionType {
    Commit = 0,
    Force = 1,
    Clear = 2,
}

#[derive(Debug, Clone)]
pub enum CtNatAddr {
    V4(u32),
    V6([u8; 16]),
    None,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CtNatType {
    None = 0,
    Src = 1,
    Dst = 2,
}

#[derive(Debug, Clone)]
pub struct TunnelAction {
    pub action: TunnelActionType,
    pub tunnel_id: u64,
    pub src_ipv4: u32,
    pub dst_ipv4: u32,
    pub src_ipv6: [u8; 16],
    pub dst_ipv6: [u8; 16],
    pub tp_src: u16,
    pub tp_dst: u16,
    pub tos: u8,
    pub ttl: u8,
    pub no_csum: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TunnelActionType {
    Set = 1,
    Release = 2,
}

#[derive(Debug, Clone)]
pub struct PoliceAction {
    pub rate: u32,          // bytes/s
    pub burst: u32,
    pub mtu: u32,
    pub peakrate: u32,
    pub avrate: u32,
    pub conform_action: TcActionResult,
    pub exceed_action: TcActionResult,
    pub notexceed_action: TcActionResult,
    pub rate64: u64,
    pub peakrate64: u64,
    pub pktrate64: u64,
    pub pktburst64: u64,
}

#[derive(Debug, Clone)]
pub struct GateAction {
    pub base_time: i64,
    pub cycle_time: i64,
    pub cycle_time_ext: i64,
    pub flags: u32,
    pub prio: i32,
    pub entries: Vec<GateEntry>,
}

#[derive(Debug, Clone)]
pub struct GateEntry {
    pub gate_state: bool,
    pub interval: u32,    // nanoseconds
    pub ipv: i32,         // Internal Priority Value
    pub max_octets: i32,
}

#[derive(Debug, Clone)]
pub struct MplsAction {
    pub action: MplsActionType,
    pub label: u32,
    pub tc: u8,
    pub ttl: u8,
    pub bos: u8,
    pub proto: u16,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MplsActionType {
    Push = 1,
    Pop = 2,
    Modify = 3,
    DecTtl = 4,
    MacPush = 5,
}

#[derive(Debug, Clone)]
pub struct CsumAction {
    pub update_flags: CsumUpdateFlags,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CsumUpdateFlags {
    pub ip: bool,
    pub igmp: bool,
    pub tcp: bool,
    pub udp: bool,
    pub udplite: bool,
    pub sctp: bool,
}

#[derive(Debug, Clone)]
pub struct SampleAction {
    pub rate: u32,
    pub trunc_size: u32,
    pub group: u32,
    pub psample_group: u32,
}

// ============================================================================
// TC Chain / Block
// ============================================================================

#[derive(Debug, Clone)]
pub struct TcBlock {
    pub index: u32,
    pub refcount: u32,
    pub chains: Vec<TcChain>,
    pub offload_count: u32,
    pub nooffload_devcnt: u32,
    pub filter_cnt: u32,
    pub filter_cnt_hw: u32,
}

#[derive(Debug, Clone)]
pub struct TcChain {
    pub index: u32,
    pub refcount: u32,
    pub filters: Vec<TcFilterEntry>,
    pub action_count: u32,
    pub explicitly_created: bool,
    pub flushing: bool,
}

#[derive(Debug, Clone)]
pub struct TcFilterEntry {
    pub kind: TcFilterKind,
    pub protocol: TcFilterProtocol,
    pub prio: u32,
    pub handle: u32,
    pub chain: u32,
    pub classid: u32,
    pub in_hw: bool,
}

// ============================================================================
// HW Offload
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum TcSetupType {
    Qdisc = 0,
    Block = 1,
    Cls = 2,
    ClsFlower = 3,
    ClsU32 = 4,
    ClsBpf = 5,
    ClsMatchall = 6,
    Act = 7,
    Ft = 8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FlowBlockBinder {
    Unspec = 0,
    Ingress = 1,
    Egress = 2,
}

#[derive(Debug, Clone)]
pub struct FlowBlockOffload {
    pub command: FlowBlockCommand,
    pub binder_type: FlowBlockBinder,
    pub block_shared: bool,
    pub extack: Option<String>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FlowBlockCommand {
    Bind = 0,
    Unbind = 1,
}

#[derive(Debug, Clone)]
pub struct FlowClsOffload {
    pub command: FlowClsCommand,
    pub prio: u32,
    pub cookie: u64,
    pub stats: TcActionStats,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FlowClsCommand {
    Replace = 0,
    Destroy = 1,
    Stats = 2,
    Tmplt_Create = 3,
    Tmplt_Destroy = 4,
}

// ============================================================================
// Statistics
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct TcFilterClassifierStats {
    pub total_filters_installed: u64,
    pub total_filters_hw_offloaded: u64,
    pub total_packets_matched: u64,
    pub total_packets_missed: u64,
    pub total_actions_executed: u64,
    pub total_actions_dropped: u64,
    pub total_bytes_processed: u64,
    pub total_chains: u32,
    pub total_blocks: u32,
    pub initialized: bool,
}

impl TcFilterClassifierStats {
    pub fn new() -> Self {
        Self {
            initialized: true,
            ..Default::default()
        }
    }
}
