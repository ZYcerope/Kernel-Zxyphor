// SPDX-License-Identifier: MIT
// Zxyphor Kernel - IPsec/XFRM Framework, SA/SP Database, ESP/AH,
// IKE interface, PF_KEY, Tunnel Mode, Transport Mode, VTI
// More advanced than Linux 2026 XFRM subsystem

const std = @import("std");

// ============================================================================
// XFRM State (Security Association)
// ============================================================================

/// XFRM protocol
pub const XfrmProto = enum(u8) {
    esp = 50,        // Encapsulating Security Payload
    ah = 51,         // Authentication Header
    comp = 108,      // IP Compression
    route2 = 17,     // Routing type 2 (MIPv6)
    hao = 200,       // Home Address Option (MIPv6)
    // Zxyphor
    zxy_fast_esp = 250,
};

/// XFRM mode
pub const XfrmMode = enum(u8) {
    transport = 0,
    tunnel = 1,
    route_optimization = 2,  // MIPv6
    in_trigger = 3,
    beet = 4,        // Bound End-to-End Tunnel
    // Zxyphor
    zxy_zero_copy = 10,
};

/// XFRM flags (state)
pub const XfrmStateFlags = packed struct {
    noecn: bool = false,
    decap_dscp: bool = false,
    nopmtudisc: bool = false,
    wildrecv: bool = false,
    icmp: bool = false,
    af_unspec: bool = false,
    align4: bool = false,
    esn: bool = false,          // Extended Sequence Numbers
    output_mark: bool = false,
    dont_encap_dscp: bool = false,
    oseq_may_wrap: bool = false,
    pcpu: bool = false,         // Per-CPU SA
    // Zxyphor
    zxy_hw_offload: bool = false,
    zxy_inline_crypto: bool = false,
    _padding: u2 = 0,
};

/// SPI (Security Parameter Index)
pub const Spi = u32;

/// XFRM selector
pub const XfrmSelector = struct {
    saddr: [16]u8,       // Source address (v4 or v6)
    daddr: [16]u8,       // Destination address
    family: u16,         // AF_INET or AF_INET6
    prefixlen_s: u8,
    prefixlen_d: u8,
    proto: u8,           // Upper layer protocol
    sport: u16,
    dport: u16,
    sport_mask: u16,
    dport_mask: u16,
    ifindex: u32,
    user: u32,
};

/// XFRM lifetime configuration
pub const XfrmLifetimeCfg = struct {
    soft_byte_limit: u64,
    hard_byte_limit: u64,
    soft_packet_limit: u64,
    hard_packet_limit: u64,
    soft_add_expires_seconds: u64,
    hard_add_expires_seconds: u64,
    soft_use_expires_seconds: u64,
    hard_use_expires_seconds: u64,
};

/// XFRM lifetime current
pub const XfrmLifetimeCur = struct {
    bytes: u64,
    packets: u64,
    add_time: u64,
    use_time: u64,
};

/// XFRM ID
pub const XfrmId = struct {
    daddr: [16]u8,
    spi: Spi,
    proto: XfrmProto,
};

/// XFRM replay state
pub const XfrmReplayState = struct {
    oseq: u32,          // Outbound sequence number
    seq: u32,           // Inbound sequence number
    bitmap: u32,        // Anti-replay bitmap
};

/// XFRM replay state (ESN)
pub const XfrmReplayStateEsn = struct {
    bmp_len: u32,
    oseq: u32,
    seq: u32,
    oseq_hi: u32,
    seq_hi: u32,
    replay_window: u32,
    // bitmap follows
};

/// XFRM statistics
pub const XfrmStats = struct {
    replay_window: u32,
    replay: u32,
    integrity_failed: u32,
};

// ============================================================================
// Cryptographic Algorithms for IPsec
// ============================================================================

/// Authentication algorithm
pub const XfrmAlgoAuth = enum(u8) {
    hmac_md5 = 1,
    hmac_sha1 = 2,
    hmac_sha256 = 3,
    hmac_sha384 = 4,
    hmac_sha512 = 5,
    hmac_ripemd160 = 6,
    aes_xcbc_mac = 7,
    aes_cmac = 8,
    // Zxyphor
    zxy_blake3_mac = 50,
};

/// Encryption algorithm
pub const XfrmAlgoEnc = enum(u8) {
    des_cbc = 1,
    des3_ede_cbc = 2,
    blowfish_cbc = 3,
    cast5_cbc = 4,
    aes_cbc = 5,
    aes_ctr = 6,
    aes_gcm = 7,
    aes_ccm = 8,
    chacha20_poly1305 = 9,
    null_enc = 10,
    camellia_cbc = 11,
    // Zxyphor
    zxy_aes256_gcm_siv = 50,
    zxy_xchacha20_poly1305 = 51,
};

/// Compression algorithm
pub const XfrmAlgoComp = enum(u8) {
    deflate = 1,
    lzs = 2,
    lzjh = 3,
    // Zxyphor
    zxy_zstd = 50,
};

/// Algorithm description
pub const XfrmAlgoDesc = struct {
    alg_name: [64]u8,
    alg_key_len: u32,        // Key length in bits
    alg_icv_len: u32,        // ICV length in bits (auth)
    alg_trunc_len: u32,      // Truncation length
};

// ============================================================================
// XFRM Policy (Security Policy)
// ============================================================================

/// XFRM policy direction
pub const XfrmPolicyDir = enum(u8) {
    in_dir = 0,
    out_dir = 1,
    fwd_dir = 2,
    mask = 3,
};

/// XFRM policy action
pub const XfrmPolicyAction = enum(u8) {
    allow = 0,
    block = 1,
};

/// XFRM policy type
pub const XfrmPolicyType = enum(u8) {
    main = 0,
    sub = 1,
};

/// XFRM policy flags
pub const XfrmPolicyFlags = packed struct {
    localok: bool = false,
    icmp: bool = false,
    // Zxyphor
    zxy_per_flow: bool = false,
    zxy_qos_aware: bool = false,
    _padding: u4 = 0,
};

/// XFRM template (SA requirements in policy)
pub const XfrmTemplate = struct {
    id: XfrmId,
    saddr: [16]u8,
    family: u16,
    reqid: u32,
    mode: XfrmMode,
    share: u8,
    optional: u8,
    aalgos: u32,        // Acceptable auth algos bitmap
    ealgos: u32,        // Acceptable enc algos bitmap
    calgos: u32,        // Acceptable comp algos bitmap
};

/// XFRM policy
pub const XfrmPolicy = struct {
    selector: XfrmSelector,
    lifetime_cfg: XfrmLifetimeCfg,
    lifetime_cur: XfrmLifetimeCur,
    priority: u32,
    index: u32,
    dir: XfrmPolicyDir,
    action: XfrmPolicyAction,
    policy_type: XfrmPolicyType,
    flags: XfrmPolicyFlags,
    share: u8,
    nr_templates: u8,
    // Security context
    ctx_alg: u8,
    ctx_doi: u8,
    ctx_len: u16,
    // Mark
    mark_value: u32,
    mark_mask: u32,
    // Interface
    if_id: u32,
};

// ============================================================================
// ESP (Encapsulating Security Payload)
// ============================================================================

/// ESP header
pub const EspHeader = struct {
    spi: u32,
    seq_no: u32,
    // IV follows (variable length)
    // Encrypted payload follows
    // Padding + pad_len + next_header follows
    // ICV (Integrity Check Value) follows
};

/// ESP trailer (inside encrypted payload)
pub const EspTrailer = struct {
    // padding bytes before this
    pad_length: u8,
    next_header: u8,      // IP Next Header value
};

// ============================================================================
// AH (Authentication Header)
// ============================================================================

/// AH header
pub const AhHeader = struct {
    nexthdr: u8,
    hdrlen: u8,        // Length in 32-bit words minus 2
    reserved: u16,
    spi: u32,
    seq_no: u32,
    // ICV follows (variable length)
};

// ============================================================================
// NAT Traversal for IPsec
// ============================================================================

/// UDP encapsulation type
pub const UdpEncapType = enum(u16) {
    espinudp_non_ike = 1,   // draft-ietf-ipsec-nat-t-ike-00/01
    espinudp = 2,            // RFC 3948
    l2tpinudp = 3,          // L2TP over UDP
};

/// NAT-T configuration
pub const NatTConfig = struct {
    encap_type: UdpEncapType,
    sport: u16,
    dport: u16,
    oa: [16]u8,       // Original address
};

// ============================================================================
// PF_KEY (RFC 2367) interface
// ============================================================================

/// PF_KEY message types
pub const PfkeyMsgType = enum(u8) {
    getspi = 1,
    update = 2,
    add = 3,
    delete = 4,
    get = 5,
    acquire = 6,
    register = 7,
    expire = 8,
    flush = 9,
    dump = 10,
    x_promisc = 11,
    x_pchange = 12,
    x_spdupdate = 13,
    x_spdadd = 14,
    x_spddelete = 15,
    x_spdget = 16,
    x_spdacquire = 17,
    x_spddump = 18,
    x_spdflush = 19,
    x_spdsetidx = 20,
    x_spdexpire = 21,
    x_spddelete2 = 22,
    x_nat_t_new_mapping = 23,
    x_migrate = 24,
};

/// SADB message header
pub const SadbMsgHeader = struct {
    version: u8,
    msg_type: PfkeyMsgType,
    errno: u8,
    satype: u8,
    len: u16,       // Length in 64-bit words
    reserved: u16,
    seq: u32,
    pid: u32,
};

/// SADB SA type
pub const SadbSaType = enum(u8) {
    unspec = 0,
    ah = 2,
    esp = 3,
    rsvp = 5,
    ospfv2 = 6,
    ripv2 = 7,
    mip = 8,
    ipcomp = 9,
    x_ipv4 = 10,
    x_ipv6 = 11,
};

/// SADB SA state
pub const SadbSaState = enum(u8) {
    larval = 0,
    mature = 1,
    dying = 2,
    dead = 3,
};

// ============================================================================
// VTI (Virtual Tunnel Interface)
// ============================================================================

/// VTI parameters
pub const VtiConfig = struct {
    link: u32,           // Underlying interface
    iflags: u16,
    oflags: u16,
    ikey: u32,           // Input key (mark)
    okey: u32,           // Output key (mark)
    local: [16]u8,       // Local address
    remote: [16]u8,      // Remote address
    family: u16,
    fwmark: u32,
};

// ============================================================================
// IP-in-IP tunnel for IPsec
// ============================================================================

/// IPsec tunnel mode config
pub const IpsecTunnelConfig = struct {
    mode: XfrmMode,
    inner_family: u16,
    outer_family: u16,
    saddr: [16]u8,
    daddr: [16]u8,
    // ECN
    ecn_mode: EcnMode,
    // PMTU
    pmtu_discovery: bool,
    mtu: u32,
    // Fragmentation
    df_bit: DfBitPolicy,
    // TTL
    ttl: u8,           // 0 = inherit
    // TOS
    tos: u8,           // 0xFF = inherit
};

/// ECN handling in tunnels
pub const EcnMode = enum(u8) {
    no_ecn = 0,
    ecn_copy = 1,
    ecn_rfc6040 = 2,
};

/// DF bit policy
pub const DfBitPolicy = enum(u8) {
    unset = 0,
    set = 1,
    inherit = 2,
};

// ============================================================================
// XFRM Hardware Offload
// ============================================================================

/// Offload type
pub const XfrmOffloadType = enum(u8) {
    unspecified = 0,
    crypto = 1,          // Crypto offload (decrypt only)
    packet = 2,          // Full offload (encrypt + headers)
    // Zxyphor
    zxy_full_inline = 10,
};

/// Offload flags
pub const XfrmOffloadFlags = packed struct {
    inbound: bool = false,
    ipv6: bool = false,
    _padding: u6 = 0,
};

/// Hardware offload status
pub const XfrmHwOffloadStatus = struct {
    offload_type: XfrmOffloadType,
    flags: XfrmOffloadFlags,
    real_dev_ifindex: u32,
    // Stats
    hw_packets: u64,
    hw_bytes: u64,
    sw_packets: u64,
    sw_bytes: u64,
};

// ============================================================================
// XFRM Interface (xfrmi)
// ============================================================================

/// XFRM interface
pub const XfrmiConfig = struct {
    if_id: u32,          // XFRM interface ID
    link: u32,           // Underlying device
    collect_metadata: bool,
};

// ============================================================================
// XFRM Statistics
// ============================================================================

/// Global XFRM stats
pub const XfrmGlobalStats = struct {
    // SA stats
    in_error: u64,
    in_buffer_error: u64,
    in_hdr_error: u64,
    in_no_states: u64,
    in_state_proto_error: u64,
    in_state_mode_error: u64,
    in_state_seq_error: u64,
    in_state_expired: u64,
    in_state_mismatch: u64,
    in_state_invalid: u64,
    in_tmpl_mismatch: u64,
    in_no_pols: u64,
    in_pol_block: u64,
    in_pol_error: u64,
    out_error: u64,
    out_bundle_gen_error: u64,
    out_bundle_check_error: u64,
    out_no_states: u64,
    out_state_proto_error: u64,
    out_state_mode_error: u64,
    out_state_seq_error: u64,
    out_state_expired: u64,
    out_pol_block: u64,
    out_pol_dead: u64,
    out_pol_error: u64,
    fwd_hdr_error: u64,
    fwd_no_states: u64,
    fwd_pol_block: u64,
    fwd_pol_error: u64,
    // Zxyphor
    zxy_hw_offload_ok: u64,
    zxy_hw_offload_fail: u64,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

/// IPsec/XFRM subsystem
pub const XfrmSubsystem = struct {
    // States
    nr_states: u32,
    nr_policies: u32,
    nr_templates: u32,
    nr_xfrm_interfaces: u32,
    // Hardware
    nr_hw_offload_sa: u32,
    nr_hw_offload_policy: u32,
    // Global stats
    global_stats: XfrmGlobalStats,
    // Limits
    state_hash_size: u32,
    policy_hash_size: u32,
    // Zxyphor
    zxy_zero_copy_enabled: bool,
    zxy_adaptive_crypto: bool,
    initialized: bool,

    pub fn init() XfrmSubsystem {
        return XfrmSubsystem{
            .nr_states = 0,
            .nr_policies = 0,
            .nr_templates = 0,
            .nr_xfrm_interfaces = 0,
            .nr_hw_offload_sa = 0,
            .nr_hw_offload_policy = 0,
            .global_stats = std.mem.zeroes(XfrmGlobalStats),
            .state_hash_size = 1024,
            .policy_hash_size = 1024,
            .zxy_zero_copy_enabled = true,
            .zxy_adaptive_crypto = true,
            .initialized = false,
        };
    }
};
