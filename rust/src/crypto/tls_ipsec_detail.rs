// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust: Crypto TLS/DTLS, IPsec ESP/AH Detail
// Complete TLS 1.3 record layer, handshake, key schedule,
// ESP/AH transforms, XFRM state, SAD/SPD, IKEv2

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};

// ============================================================================
// TLS Protocol Versions
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
    Dtls12 = 0xFEFD,
    Dtls13 = 0xFEFC,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

// ============================================================================
// TLS 1.3 Cipher Suites
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tls13CipherSuite {
    Aes128GcmSha256 = 0x1301,
    Aes256GcmSha384 = 0x1302,
    Chacha20Poly1305Sha256 = 0x1303,
    Aes128CcmSha256 = 0x1304,
    Aes128Ccm8Sha256 = 0x1305,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsNamedGroup {
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
    X25519Kyber768Draft00 = 0x6399,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsSignatureScheme {
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    Ed25519 = 0x0807,
    Ed448 = 0x0808,
}

// ============================================================================
// TLS Record Layer
// ============================================================================

#[repr(C, packed)]
pub struct TlsRecordHeader {
    pub content_type: u8,
    pub legacy_version: u16,
    pub length: u16,
}

pub const TLS_MAX_PLAINTEXT_LEN: usize = 16384;  // 2^14
pub const TLS_MAX_RECORD_LEN: usize = 16384 + 256; // + expansion

#[repr(C)]
pub struct TlsRecordState {
    pub write_seq: u64,
    pub read_seq: u64,
    pub write_key: [48]u8,   // Key material
    pub read_key: [48]u8,
    pub write_iv: [12]u8,
    pub read_iv: [12]u8,
    pub cipher_type: Tls13CipherSuite,
    pub key_len: u8,
    pub iv_len: u8,
    pub tag_len: u8,
}

// ============================================================================
// TLS 1.3 Key Schedule
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tls13KeySchedulePhase {
    Initial = 0,
    EarlySecret = 1,
    HandshakeSecret = 2,
    MasterSecret = 3,
    ApplicationKeys = 4,
}

#[repr(C)]
pub struct Tls13KeySchedule {
    pub phase: Tls13KeySchedulePhase,
    pub early_secret: [64]u8,
    pub handshake_secret: [64]u8,
    pub master_secret: [64]u8,
    pub client_handshake_traffic_secret: [64]u8,
    pub server_handshake_traffic_secret: [64]u8,
    pub client_application_traffic_secret: [64]u8,
    pub server_application_traffic_secret: [64]u8,
    pub exporter_master_secret: [64]u8,
    pub resumption_master_secret: [64]u8,
    pub hash_len: u8,
}

// ============================================================================
// kTLS (Kernel TLS offload)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KtlsMode {
    SwTx = 0,
    SwRx = 1,
    HwTx = 2,
    HwRx = 3,
    HwRecord = 4,
}

#[repr(C)]
pub struct KtlsInfo {
    pub version: TlsVersion,
    pub cipher: Tls13CipherSuite,
    pub tx_mode: KtlsMode,
    pub rx_mode: KtlsMode,
    pub offload_capable: bool,
    pub zerocopy_sendfile: bool,
    pub async_capable: bool,
}

#[repr(C)]
pub struct KtlsStats {
    pub tx_tls_encrypted: AtomicU64,
    pub tx_tls_ooo: AtomicU64,
    pub tx_tls_drop_no_sync_data: AtomicU64,
    pub tx_tls_drop_bypass: AtomicU64,
    pub rx_tls_decrypted: AtomicU64,
    pub rx_tls_error: AtomicU64,
    pub tx_tls_device: AtomicU64,
    pub tx_tls_device_offload_miss: AtomicU64,
    pub rx_tls_device: AtomicU64,
    pub rx_tls_device_resync: AtomicU64,
}

impl KtlsStats {
    pub const fn new() -> Self {
        Self {
            tx_tls_encrypted: AtomicU64::new(0),
            tx_tls_ooo: AtomicU64::new(0),
            tx_tls_drop_no_sync_data: AtomicU64::new(0),
            tx_tls_drop_bypass: AtomicU64::new(0),
            rx_tls_decrypted: AtomicU64::new(0),
            rx_tls_error: AtomicU64::new(0),
            tx_tls_device: AtomicU64::new(0),
            tx_tls_device_offload_miss: AtomicU64::new(0),
            rx_tls_device: AtomicU64::new(0),
            rx_tls_device_resync: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// IPsec - ESP (Encapsulating Security Payload)
// ============================================================================

#[repr(C, packed)]
pub struct EspHeader {
    pub spi: u32,        // Security Parameters Index
    pub seq_no: u32,     // Sequence number
}

#[repr(C, packed)]
pub struct EspTrailer {
    pub pad_length: u8,
    pub next_header: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpsecProtocol {
    Esp = 50,
    Ah = 51,
    Comp = 108,           // IPComp
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpsecMode {
    Transport = 0,
    Tunnel = 1,
    Routeoptimization = 2,
    Beet = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpsecDirection {
    Inbound = 0,
    Outbound = 1,
}

// ============================================================================
// AH (Authentication Header)
// ============================================================================

#[repr(C, packed)]
pub struct AhHeader {
    pub next_header: u8,
    pub payload_len: u8,
    pub reserved: u16,
    pub spi: u32,
    pub seq_no: u32,
    // Followed by: Integrity Check Value (ICV)
}

// ============================================================================
// XFRM State (Security Association)
// ============================================================================

#[repr(C)]
pub struct XfrmState {
    pub id: XfrmId,
    pub props: XfrmProps,
    pub lft: XfrmLifetime,
    pub curlft: XfrmLifetimeCur,
    pub stats: XfrmStats,
    pub replay: XfrmReplayState,
    pub genid: u32,
    pub mode: IpsecMode,
    pub km_state: XfrmKmState,
    pub replay_maxage: u32,
    pub replay_maxdiff: u32,
    pub output_mark: XfrmMark,
    pub input_mark: XfrmMark,
    pub if_id: u32,
    pub tfcpad: u32,
    pub encap: Option<XfrmEncapTmpl>,
    pub aalg: Option<XfrmAlgoAuth>,
    pub ealg: Option<XfrmAlgoEnc>,
    pub calg: Option<XfrmAlgoComp>,
    pub aead: Option<XfrmAlgoAead>,
}

#[repr(C)]
pub struct XfrmId {
    pub daddr: XfrmAddress,
    pub spi: u32,
    pub proto: u8,
}

#[repr(C)]
pub struct XfrmAddress {
    pub a4: u32,           // For IPv4
    pub a6: [u8; 16],     // For IPv6
}

#[repr(C)]
pub struct XfrmProps {
    pub mode: IpsecMode,
    pub reqid: u32,
    pub family: u16,       // AF_INET or AF_INET6
    pub saddr: XfrmAddress,
    pub flags: u32,
    pub extra_flags: u32,
    pub output_mark: u32,
    pub aalgo: u16,
    pub ealgo: u16,
    pub calgo: u16,
    pub header_len: u32,
    pub trailer_len: u32,
};

#[repr(C)]
pub struct XfrmLifetime {
    pub soft_byte_limit: u64,
    pub hard_byte_limit: u64,
    pub soft_packet_limit: u64,
    pub hard_packet_limit: u64,
    pub soft_add_expires_seconds: u64,
    pub hard_add_expires_seconds: u64,
    pub soft_use_expires_seconds: u64,
    pub hard_use_expires_seconds: u64,
}

#[repr(C)]
pub struct XfrmLifetimeCur {
    pub bytes: u64,
    pub packets: u64,
    pub add_time: u64,
    pub use_time: u64,
}

#[repr(C)]
pub struct XfrmStats {
    pub replay_window: u32,
    pub replay: u32,
    pub integrity_failed: u32,
}

#[repr(C)]
pub struct XfrmReplayState {
    pub oseq: u32,
    pub seq: u32,
    pub bitmap: u32,
    // ESN (Extended Sequence Number) support
    pub oseq_hi: u32,
    pub seq_hi: u32,
    pub replay_esn: bool,
    pub bmp_len: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XfrmKmState {
    Undefined = 0,
    Ack = 1,
    Dying = 2,
    Dead = 3,
}

#[repr(C)]
pub struct XfrmMark {
    pub v: u32,
    pub m: u32,
}

#[repr(C)]
pub struct XfrmEncapTmpl {
    pub encap_type: u16,   // UDP_ENCAP_ESPINUDP, etc.
    pub encap_sport: u16,
    pub encap_dport: u16,
    pub encap_oa: XfrmAddress,
}

#[repr(C)]
pub struct XfrmAlgoAuth {
    pub alg_name: [u8; 64],
    pub alg_key_len: u32,
    pub alg_trunc_len: u32,
    pub alg_key: [u8; 128],
}

#[repr(C)]
pub struct XfrmAlgoEnc {
    pub alg_name: [u8; 64],
    pub alg_key_len: u32,
    pub alg_ivlen: u32,
    pub alg_key: [u8; 256],
}

#[repr(C)]
pub struct XfrmAlgoComp {
    pub alg_name: [u8; 64],
    pub alg_key_len: u32,
    pub alg_key: [u8; 64],
}

#[repr(C)]
pub struct XfrmAlgoAead {
    pub alg_name: [u8; 64],
    pub alg_key_len: u32,
    pub alg_icv_len: u32,
    pub alg_key: [u8; 256],
}

// ============================================================================
// XFRM Policy (Security Policy)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XfrmPolicyDir {
    In = 0,
    Out = 1,
    Fwd = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XfrmPolicyAction {
    Allow = 0,
    Block = 1,
}

#[repr(C)]
pub struct XfrmPolicy {
    pub selector: XfrmSelector,
    pub lft: XfrmLifetime,
    pub curlft: XfrmLifetimeCur,
    pub mark: XfrmMark,
    pub if_id: u32,
    pub priority: u32,
    pub index: u32,
    pub dir: XfrmPolicyDir,
    pub action: XfrmPolicyAction,
    pub flags: u8,
    pub xfrm_nr: u8,
    pub family: u16,
    pub security: u64,
    pub xfrm_vec: [XfrmTmpl; 6],  // Max 6 transforms per policy
}

#[repr(C)]
pub struct XfrmSelector {
    pub daddr: XfrmAddress,
    pub saddr: XfrmAddress,
    pub dport: u16,
    pub dport_mask: u16,
    pub sport: u16,
    pub sport_mask: u16,
    pub family: u16,
    pub prefixlen_d: u8,
    pub prefixlen_s: u8,
    pub proto: u8,
    pub ifindex: i32,
    pub user: u32, // kuid_t
}

#[repr(C)]
pub struct XfrmTmpl {
    pub id: XfrmId,
    pub saddr: XfrmAddress,
    pub reqid: u32,
    pub mode: IpsecMode,
    pub share: u8,
    pub optional: u8,
    pub allalgs: u32,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
    pub encap_family: u16,
}

// ============================================================================
// Manager
// ============================================================================

#[repr(C)]
pub struct TlsIpsecManager {
    pub total_tls_connections: AtomicU64,
    pub total_tls_handshakes: AtomicU64,
    pub total_tls_records_sent: AtomicU64,
    pub total_tls_records_received: AtomicU64,
    pub total_ipsec_sa_created: AtomicU64,
    pub total_ipsec_sa_deleted: AtomicU64,
    pub total_ipsec_sp_created: AtomicU64,
    pub total_esp_packets: AtomicU64,
    pub total_ah_packets: AtomicU64,
    pub total_replay_detected: AtomicU64,
    pub total_integrity_failures: AtomicU64,
    pub ktls_stats: KtlsStats,
    pub initialized: AtomicBool,
}

impl TlsIpsecManager {
    pub const fn new() -> Self {
        Self {
            total_tls_connections: AtomicU64::new(0),
            total_tls_handshakes: AtomicU64::new(0),
            total_tls_records_sent: AtomicU64::new(0),
            total_tls_records_received: AtomicU64::new(0),
            total_ipsec_sa_created: AtomicU64::new(0),
            total_ipsec_sa_deleted: AtomicU64::new(0),
            total_ipsec_sp_created: AtomicU64::new(0),
            total_esp_packets: AtomicU64::new(0),
            total_ah_packets: AtomicU64::new(0),
            total_replay_detected: AtomicU64::new(0),
            total_integrity_failures: AtomicU64::new(0),
            ktls_stats: KtlsStats::new(),
            initialized: AtomicBool::new(false),
        }
    }
}
