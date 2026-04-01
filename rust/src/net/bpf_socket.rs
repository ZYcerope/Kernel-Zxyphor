// SPDX-License-Identifier: MIT
// Zxyphor Kernel Rust - Socket BPF filters, BPF socket ops,
// Traffic Shaping, QoS, Network Classification, TC BPF
// More advanced than Linux 2026 network BPF subsystem

/// BPF program type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfProgType {
    Unspec = 0,
    SocketFilter = 1,
    KProbe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
    CgroupSysctl = 23,
    RawTracepointWritable = 24,
    CgroupSockopt = 25,
    Tracing = 26,
    StructOps = 27,
    Ext = 28,
    Lsm = 29,
    SkLookup = 30,
    Syscall = 31,
    Netfilter = 32,
    // Zxyphor
    ZxyPacketAi = 100,
    ZxyNetMonitor = 101,
}

/// BPF attach type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfAttachType {
    CgroupInetIngress = 0,
    CgroupInetEgress = 1,
    CgroupInetSockCreate = 2,
    CgroupSockOps = 3,
    SkSkbStreamParser = 4,
    SkSkbStreamVerdict = 5,
    CgroupDevice = 6,
    SkMsgVerdict = 7,
    CgroupInet4Bind = 8,
    CgroupInet6Bind = 9,
    CgroupInet4Connect = 10,
    CgroupInet6Connect = 11,
    CgroupInet4PostBind = 12,
    CgroupInet6PostBind = 13,
    CgroupUdp4Sendmsg = 14,
    CgroupUdp6Sendmsg = 15,
    LircMode2 = 16,
    FlowDissector = 17,
    CgroupSysctl = 18,
    CgroupUdp4Recvmsg = 19,
    CgroupUdp6Recvmsg = 20,
    CgroupGetsockopt = 21,
    CgroupSetsockopt = 22,
    TraceRawTp = 23,
    TraceFentry = 24,
    TraceFexit = 25,
    ModifyReturn = 26,
    LsmMac = 27,
    TraceIter = 28,
    CgroupInet4Getpeername = 29,
    CgroupInet6Getpeername = 30,
    CgroupInet4Getsockname = 31,
    CgroupInet6Getsockname = 32,
    XdpDevmap = 33,
    CgroupInetSockRelease = 34,
    XdpCpumap = 35,
    SkLookup = 36,
    Xdp = 37,
    SkSkbVerdict = 38,
    SkReuseportSelect = 39,
    SkReuseportSelectOrMigrate = 40,
    PerfEvent = 41,
    TraceKprobeMulti = 42,
    LsmCgroup = 43,
    StructOps = 44,
    Netfilter = 45,
    TcxIngress = 46,
    TcxEgress = 47,
    TraceUprobeMulti = 48,
    CgroupUnixConnect = 49,
    CgroupUnixSendmsg = 50,
    CgroupUnixRecvmsg = 51,
    CgroupUnixGetpeername = 52,
    CgroupUnixGetsockname = 53,
    NetkitPrimary = 54,
    NetkitPeer = 55,
}

/// BPF map type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    StructOpsMap = 26,
    Ringbuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingbuf = 31,
    CgrpStorage = 32,
    Arena = 33,
}

/// BPF program flags
pub const BPF_F_SLEEPABLE: u32 = 1 << 4;
pub const BPF_F_XDP_HAS_FRAGS: u32 = 1 << 5;
pub const BPF_F_XDP_DEV_BOUND_ONLY: u32 = 1 << 6;
pub const BPF_F_TEST_REG_INVARIANTS: u32 = 1 << 7;
pub const BPF_F_NETFILTER_IP_DEFRAG: u32 = 1 << 0;

/// BPF program info
#[derive(Debug, Clone)]
pub struct BpfProgInfo {
    pub id: u32,
    pub type_: BpfProgType,
    pub tag: [8; u8],
    pub name: [16; u8],
    // Instructions
    pub insn_cnt: u32,
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    // Maps
    pub nr_map_ids: u32,
    // Stats
    pub run_count: u64,
    pub run_time_ns: u64,
    pub recursion_misses: u64,
    // Verified
    pub verified_insns: u32,
    // Attach info
    pub attach_btf_id: u32,
    pub attach_btf_obj_id: u32,
    // Flags
    pub gpl_compatible: bool,
    pub created_by_uid: u32,
}

/// BPF map info
#[derive(Debug, Clone)]
pub struct BpfMapInfo {
    pub id: u32,
    pub type_: BpfMapType,
    pub name: [16; u8],
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    // Pinned
    pub ifindex: u32,
    // BTF
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub btf_vmlinux_value_type_id: u32,
    // Memory
    pub map_extra: u64,
}

/// BPF link type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfLinkType {
    Unspec = 0,
    RawTracepoint = 1,
    Tracing = 2,
    CgroupId = 3,
    Iter = 4,
    NetNs = 5,
    XdpId = 6,
    PerfEvent = 7,
    KprobeMulti = 8,
    StructOps = 9,
    Netfilter = 10,
    TcxId = 11,
    UprobeMulti = 12,
    NetkitId = 13,
}

/// BPF link info
#[derive(Debug, Clone)]
pub struct BpfLinkInfo {
    pub id: u32,
    pub type_: BpfLinkType,
    pub prog_id: u32,
}

/// BPF token
#[derive(Debug, Clone)]
pub struct BpfToken {
    pub id: u32,
    pub allowed_cmds: u64,
    pub allowed_map_types: u64,
    pub allowed_prog_types: u64,
    pub allowed_attach_types: u64,
}

// ============================================================================
// Socket Operations BPF
// ============================================================================

/// Sock ops callback operations
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpsOp {
    Void = 0,
    TimeoutInit = 1,
    RwTimeoutInit = 2,
    TcpConnectCb = 3,
    ActiveEstablishedCb = 4,
    PassiveEstablishedCb = 5,
    NeedsModeMoreOpt = 6,
    BaseRtt = 7,
    RtoMin = 8,
    RtoMax = 9,
    RttMin = 10,
    RecvMss = 11,
    SndCwnd = 12,
    SndCwnClmode = 13,
    RetransMit = 14,
    SecureCb = 15,
    // TCP
    TcpConnReq = 16,
    Ecn = 17,
    Hdr1Opt = 18,
    Hdr2Opt = 19,
    Write1Hdr = 20,
    Write2Hdr = 21,
}

/// BPF socket redirect map
#[derive(Debug, Clone)]
pub struct SockmapEntry {
    pub key: u64,
    pub socket_cookie: u64,
    pub family: u16,
    pub type_: u16,
    pub protocol: u16,
}

// ============================================================================
// TCx (TC BPF ext)
// ============================================================================

/// TCx attach options
#[derive(Debug, Clone)]
pub struct TcxAttachOpts {
    pub flags: u32,
    pub relative_fd: u32,
    pub relative_id: u32,
    pub expected_revision: u64,
}

/// TC BPF flags
pub const BPF_TC_INGRESS: u32 = 1;
pub const BPF_TC_EGRESS: u32 = 2;
pub const BPF_TC_CUSTOM: u32 = 4;

/// TC BPF hook info
#[derive(Debug, Clone)]
pub struct TcBpfHookInfo {
    pub ifindex: u32,
    pub attach_point: u32,
    pub parent: u32,
    pub prog_id: u32,
    pub handle: u32,
    pub priority: u32,
}

// ============================================================================
// Netkit (Virtual Network Device)
// ============================================================================

/// Netkit mode
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetkitMode {
    L2 = 0,    // Ethernet
    L3 = 1,    // IP only
}

/// Netkit policy
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetkitPolicy {
    Forward = 0,
    BlackHole = 1,
}

/// Netkit device info
#[derive(Debug, Clone)]
pub struct NetkitInfo {
    pub ifindex: u32,
    pub peer_ifindex: u32,
    pub mode: NetkitMode,
    pub primary_policy: NetkitPolicy,
    pub peer_policy: NetkitPolicy,
    pub headroom: u16,
    // BPF programs
    pub primary_prog_id: u32,
    pub peer_prog_id: u32,
}

// ============================================================================
// BPF Iterator
// ============================================================================

/// BPF iterator target type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfIterTarget {
    BpfMap = 0,
    BpfMapElem = 1,
    BpfProg = 2,
    BpfTag = 3,
    Task = 4,
    TaskFile = 5,
    TaskVma = 6,
    Tcp = 7,
    Udp = 8,
    Unix_socket = 9,
    Netlink = 10,
    BpfLink = 11,
    Cgroup = 12,
    Ksym = 13,
}

// ============================================================================
// BPF struct_ops
// ============================================================================

/// BPF struct_ops state
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfStructOpsState {
    Init = 0,
    InUse = 1,
    Tobefree = 2,
    Ready = 3,
}

/// Known struct_ops targets
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructOpsTarget {
    TcpCongestionOps = 0,
    BpfDummyOps = 1,
    SchedExt = 2,
}

// ============================================================================
// BPF Arena
// ============================================================================

/// BPF arena info
#[derive(Debug, Clone)]
pub struct BpfArenaInfo {
    pub map_id: u32,
    pub max_entries: u32,  // pages
    pub map_extra: u64,    // user address
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// BPF networking subsystem
#[derive(Debug, Clone)]
pub struct BpfNetSubsystem {
    // Programs
    pub nr_progs: u32,
    pub nr_maps: u32,
    pub nr_links: u32,
    // Per type
    pub nr_socket_filter: u32,
    pub nr_sched_cls: u32,
    pub nr_sched_act: u32,
    pub nr_xdp: u32,
    pub nr_cgroup_skb: u32,
    pub nr_sock_ops: u32,
    pub nr_sk_skb: u32,
    pub nr_sk_msg: u32,
    pub nr_flow_dissector: u32,
    pub nr_sk_lookup: u32,
    pub nr_netfilter: u32,
    pub nr_struct_ops: u32,
    // Map types
    pub nr_sockmap: u32,
    pub nr_sockhash: u32,
    pub nr_devmap: u32,
    pub nr_cpumap: u32,
    pub nr_xskmap: u32,
    // Stats
    pub total_prog_loads: u64,
    pub total_prog_load_failures: u64,
    pub total_map_creates: u64,
    pub total_bpf_runs: u64,
    pub total_bpf_run_time_ns: u64,
    // Memory
    pub total_bpf_memory: u64,
    pub bpf_jit_enabled: bool,
    pub bpf_jit_harden: u8,
    pub bpf_jit_kallsyms: bool,
    pub bpf_jit_limit: u64,
    // Unprivileged
    pub unprivileged_bpf_disabled: u8,
    // Zxyphor
    pub zxy_ai_classification: bool,
    pub zxy_bpf_arena_enabled: bool,
    pub initialized: bool,
}
