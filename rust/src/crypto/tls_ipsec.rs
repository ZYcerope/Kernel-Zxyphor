// Zxyphor Kernel - TLS (kTLS) Offload, IPsec Advanced XFRM,
// WireGuard Protocol, MACsec (802.1AE),
// Network Crypto Transforms, Crypto API Offload
// More advanced than Linux 2026 crypto networking

use core::fmt;

// ============================================================================
// kTLS - Kernel TLS Offload
// ============================================================================

/// TLS version
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

/// TLS cipher type
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum TlsCipherType {
    AesGcm128 = 51,
    AesGcm256 = 52,
    AesCcm128 = 53,
    Chacha20Poly1305 = 54,
    Sm4Gcm = 55,
    Sm4Ccm = 56,
    Aria128Gcm = 57,
    Aria256Gcm = 58,
    // Zxyphor
    ZxyAes256Gcm12 = 200,
    ZxyPqHybrid = 201,
}

/// TLS configuration for kernel offload
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KtlsCryptoInfo {
    pub version: TlsVersion,
    pub cipher_type: TlsCipherType,
}

/// TLS 1.2 AES-GCM-128 offload info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Tls12AesGcm128 {
    pub info: KtlsCryptoInfo,
    pub iv: [u8; 8],
    pub key: [u8; 16],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

/// TLS 1.2 AES-GCM-256 offload info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Tls12AesGcm256 {
    pub info: KtlsCryptoInfo,
    pub iv: [u8; 8],
    pub key: [u8; 32],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

/// TLS 1.3 AES-GCM-128 offload info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Tls13AesGcm128 {
    pub info: KtlsCryptoInfo,
    pub iv: [u8; 8],
    pub key: [u8; 16],
    pub salt: [u8; 4],
    pub rec_seq: [u8; 8],
}

/// TLS 1.2/1.3 ChaCha20-Poly1305 offload info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TlsChacha20Poly1305 {
    pub info: KtlsCryptoInfo,
    pub iv: [u8; 12],
    pub key: [u8; 32],
    pub salt: [u8; 0],
    pub rec_seq: [u8; 8],
}

/// kTLS TX/RX mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KtlsMode {
    SwMode = 0,
    HwMode = 1,
    HwRecord = 2,
}

/// kTLS socket option
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum KtlsSockOpt {
    TxMode = 1,
    RxMode = 2,
    TxZeroCopySendfile = 3,
    RxExpectNoPad = 4,
    TxNoPad = 5,
}

/// kTLS offload statistics
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KtlsStats {
    pub tx_sw_pkts: u64,
    pub tx_hw_pkts: u64,
    pub rx_sw_pkts: u64,
    pub rx_hw_pkts: u64,
    pub tx_sw_bytes: u64,
    pub tx_hw_bytes: u64,
    pub rx_sw_bytes: u64,
    pub rx_hw_bytes: u64,
    pub tx_tls_ooo: u64,
    pub tx_tls_drop: u64,
    pub rx_tls_decrypted: u64,
    pub rx_tls_error: u64,
}

// ============================================================================
// IPsec Advanced - XFRM
// ============================================================================

/// XFRM protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmProtocol {
    EspInUdp = 0,
    Ah = 51,
    Esp = 50,
    Comp = 108,
    RouteOptimization = 253,
}

/// XFRM mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmMode {
    Transport = 0,
    Tunnel = 1,
    RouteOptimization = 2,
    InTrigger = 3,
    Beet = 4,
}

/// XFRM SA direction
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmDir {
    In = 0,
    Out = 1,
    Fwd = 2,
}

/// XFRM state flags
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct XfrmStateFlags(pub u32);

impl XfrmStateFlags {
    pub const NOECN: Self = Self(1);
    pub const DECAP_DSCP: Self = Self(2);
    pub const NOPMTUDISC: Self = Self(4);
    pub const WILDRECV: Self = Self(8);
    pub const ICMP: Self = Self(16);
    pub const AF_UNSPEC: Self = Self(32);
    pub const ALIGN4: Self = Self(64);
    pub const ESN: Self = Self(128);
    pub const OUTPUT_MARK: Self = Self(256);
    pub const PCPU: Self = Self(512);
}

/// XFRM SA (Security Association) descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct XfrmSaDesc {
    pub spi: u32,
    pub protocol: XfrmProtocol,
    pub mode: XfrmMode,
    pub family: u16,
    pub src_addr4: u32,
    pub dst_addr4: u32,
    pub src_addr6: [u8; 16],
    pub dst_addr6: [u8; 16],
    pub reqid: u32,
    pub flags: XfrmStateFlags,
    // Crypto
    pub auth_algo: XfrmAuthAlgo,
    pub enc_algo: XfrmEncAlgo,
    pub aead_algo: XfrmAeadAlgo,
    pub comp_algo: XfrmCompAlgo,
    // Lifetime
    pub soft_byte_limit: u64,
    pub hard_byte_limit: u64,
    pub soft_packet_limit: u64,
    pub hard_packet_limit: u64,
    pub soft_time_limit_sec: u64,
    pub hard_time_limit_sec: u64,
    // Replay protection
    pub replay_window: u32,
    pub replay_seq: u32,
    pub replay_seq_hi: u32,
    pub replay_oseq: u32,
    pub replay_oseq_hi: u32,
    // Stats
    pub bytes: u64,
    pub packets: u64,
    pub add_time: u64,
    pub use_time: u64,
    // Offload
    pub offload_type: XfrmOffloadType,
    pub if_id: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmAuthAlgo {
    None = 0,
    HmacMd5 = 1,
    HmacSha1 = 2,
    HmacSha256 = 3,
    HmacSha384 = 4,
    HmacSha512 = 5,
    AesXcbc = 6,
    AesCmac = 7,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmEncAlgo {
    None = 0,
    AesCbc = 1,
    AesCtr = 2,
    Des3Ede = 3,
    Blowfish = 4,
    Cast = 5,
    Serpent = 6,
    Twofish = 7,
    Camellia = 8,
    Chacha20 = 9,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmAeadAlgo {
    None = 0,
    AesGcm = 1,
    AesCcm = 2,
    Rfc7539esp = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmCompAlgo {
    None = 0,
    Deflate = 1,
    Lzs = 2,
    Lzjh = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmOffloadType {
    None = 0,
    Crypto = 1,
    Packet = 2,
}

/// XFRM policy descriptor
#[repr(C)]
#[derive(Debug, Clone)]
pub struct XfrmPolicyDesc {
    pub direction: XfrmDir,
    pub priority: u32,
    pub index: u32,
    pub family: u16,
    pub sel_src_addr4: u32,
    pub sel_dst_addr4: u32,
    pub sel_src_addr6: [u8; 16],
    pub sel_dst_addr6: [u8; 16],
    pub sel_src_prefixlen: u8,
    pub sel_dst_prefixlen: u8,
    pub sel_proto: u8,
    pub sel_sport: u16,
    pub sel_dport: u16,
    pub sel_ifindex: i32,
    pub action: XfrmPolicyAction,
    pub nr_tmpls: u8,
    pub share: XfrmPolicyShare,
    pub if_id: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmPolicyAction {
    Allow = 0,
    Block = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum XfrmPolicyShare {
    Any = 0,
    Session = 1,
    User = 2,
    Unique = 3,
}

// ============================================================================
// WireGuard Protocol
// ============================================================================

/// WireGuard interface config
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WgDeviceConfig {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: u32,
    pub nr_peers: u32,
    pub if_index: i32,
}

/// WireGuard peer config
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WgPeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    pub endpoint_addr4: u32,
    pub endpoint_addr6: [u8; 16],
    pub endpoint_family: u16,
    pub endpoint_port: u16,
    pub persistent_keepalive_interval: u16,
    pub nr_allowedips: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_time_sec: u64,
    pub last_handshake_time_nsec: u64,
}

/// WireGuard allowed IP
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WgAllowedIp {
    pub family: u16,
    pub addr4: u32,
    pub addr6: [u8; 16],
    pub cidr_mask: u8,
}

/// WireGuard handshake state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum WgHandshakeState {
    None = 0,
    Initiated = 1,
    ResponseCreated = 2,
    Completed = 3,
}

/// WireGuard message type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum WgMsgType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    HandshakeCookie = 3,
    TransportData = 4,
}

// ============================================================================
// MACsec (802.1AE)
// ============================================================================

/// MACsec cipher suite
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum MacsecCipherSuite {
    GcmAes128 = 0x0080020001000001,
    GcmAes256 = 0x0080C20001000002,
    GcmAesXpn128 = 0x0080C20001000003,
    GcmAesXpn256 = 0x0080C20001000004,
}

/// MACsec security association (SA) state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MacsecSaState {
    NotInUse = 0,
    InUse = 1,
}

/// MACsec validation mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MacsecValidation {
    Disabled = 0,
    Check = 1,
    Strict = 2,
}

/// MACsec offload mode
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MacsecOffload {
    Off = 0,
    Phy = 1,
    Mac = 2,
}

/// MACsec SecY config
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MacsecSecyConfig {
    pub sci: u64,
    pub protect_frames: bool,
    pub replay_protect: bool,
    pub replay_window: u32,
    pub validate_frames: MacsecValidation,
    pub operational: bool,
    pub encoding_sa: u8,
    pub cipher_suite: MacsecCipherSuite,
    pub icv_length: u8,
    pub include_sci: bool,
    pub use_es: bool,
    pub use_scb: bool,
    pub offload: MacsecOffload,
}

/// MACsec statistics
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MacsecStats {
    pub in_pkts_ok: u64,
    pub in_pkts_unchecked: u64,
    pub in_pkts_delayed: u64,
    pub in_pkts_late: u64,
    pub in_pkts_invalid: u64,
    pub in_pkts_not_valid: u64,
    pub in_pkts_no_sa: u64,
    pub in_pkts_overrun: u64,
    pub in_octets_validated: u64,
    pub in_octets_decrypted: u64,
    pub out_pkts_protected: u64,
    pub out_pkts_encrypted: u64,
    pub out_octets_protected: u64,
    pub out_octets_encrypted: u64,
}

// ============================================================================
// Crypto API Offload
// ============================================================================

/// Crypto offload type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CryptoOffloadType {
    None = 0,
    InlineCrypto = 1,
    InlineProtocol = 2,
    LookaheadCrypto = 3,
}

/// Crypto accelerator capabilities
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct CryptoAccelCaps(pub u64);

impl CryptoAccelCaps {
    pub const AES_CBC: Self = Self(1 << 0);
    pub const AES_CTR: Self = Self(1 << 1);
    pub const AES_GCM: Self = Self(1 << 2);
    pub const AES_CCM: Self = Self(1 << 3);
    pub const CHACHA20_POLY1305: Self = Self(1 << 4);
    pub const SHA1: Self = Self(1 << 5);
    pub const SHA256: Self = Self(1 << 6);
    pub const SHA384: Self = Self(1 << 7);
    pub const SHA512: Self = Self(1 << 8);
    pub const HMAC: Self = Self(1 << 9);
    pub const RSA: Self = Self(1 << 10);
    pub const ECDSA: Self = Self(1 << 11);
    pub const ECDH: Self = Self(1 << 12);
    pub const DH: Self = Self(1 << 13);
    pub const COMPRESS: Self = Self(1 << 14);
    pub const RANDOM: Self = Self(1 << 15);
    pub const INLINE_IPSEC: Self = Self(1 << 16);
    pub const INLINE_TLS: Self = Self(1 << 17);
    pub const INLINE_MACSEC: Self = Self(1 << 18);
    // Zxyphor
    pub const ZXY_PQ_KYBER: Self = Self(1 << 32);
    pub const ZXY_PQ_DILITHIUM: Self = Self(1 << 33);
}

/// Crypto accelerator hardware info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CryptoAccelInfo {
    pub name: [u8; 32],
    pub name_len: u8,
    pub driver: [u8; 32],
    pub driver_len: u8,
    pub capabilities: CryptoAccelCaps,
    pub max_queues: u32,
    pub max_burst_size: u32,
    pub max_session_count: u32,
    pub active_sessions: u32,
    pub pci_bus: u8,
    pub pci_dev: u8,
    pub pci_func: u8,
    pub numa_node: i32,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct CryptoNetSubsystem {
    pub ktls_enabled: bool,
    pub ktls_tx_sw: u64,
    pub ktls_tx_hw: u64,
    pub ktls_rx_sw: u64,
    pub ktls_rx_hw: u64,
    pub xfrm_sa_count: u32,
    pub xfrm_policy_count: u32,
    pub xfrm_offload_count: u32,
    pub wg_interfaces: u32,
    pub wg_peers: u32,
    pub macsec_interfaces: u32,
    pub crypto_accels: u32,
    pub initialized: bool,
}

impl CryptoNetSubsystem {
    pub const fn new() -> Self {
        Self {
            ktls_enabled: true,
            ktls_tx_sw: 0,
            ktls_tx_hw: 0,
            ktls_rx_sw: 0,
            ktls_rx_hw: 0,
            xfrm_sa_count: 0,
            xfrm_policy_count: 0,
            xfrm_offload_count: 0,
            wg_interfaces: 0,
            wg_peers: 0,
            macsec_interfaces: 0,
            crypto_accels: 0,
            initialized: false,
        }
    }
}
