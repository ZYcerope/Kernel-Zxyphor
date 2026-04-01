// Zxyphor Kernel - Rust TLS/DTLS protocol, IPsec transform,
// WireGuard-like VPN, QUIC crypto, Network Key Management
// More advanced than Linux 2026 network crypto stack

/// TLS version
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
    Dtls10 = 0xFEFF,
    Dtls12 = 0xFEFD,
    Dtls13 = 0xFEFC,
    /// Zxyphor: Zero-RTT by default
    ZxyTls = 0x0400,
}

/// TLS content type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

/// TLS handshake type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    HelloRetryRequest = 6,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateUrl = 21,
    CertificateStatus = 22,
    KeyUpdate = 24,
    CompressedCertificate = 25,
    MessageHash = 254,
}

/// TLS cipher suite (TLS 1.3)
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCipherSuite {
    Aes128GcmSha256 = 0x1301,
    Aes256GcmSha384 = 0x1302,
    Chacha20Poly1305Sha256 = 0x1303,
    Aes128CcmSha256 = 0x1304,
    Aes128Ccm8Sha256 = 0x1305,
    /// Zxyphor PQ cipher suites
    ZxyKyber768Aes256Gcm = 0xFF01,
    ZxyKyber1024Chacha20 = 0xFF02,
}

/// TLS 1.3 named groups
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    // Post-quantum hybrid
    X25519Kyber768 = 0x6399,
    SecP256r1Kyber768 = 0x639A,
    /// Zxyphor PQ groups
    ZxyKyber1024 = 0xFF01,
    ZxyDilithium5 = 0xFF02,
}

/// TLS signature scheme
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080A,
    RsaPssPssSha512 = 0x080B,
    /// Zxyphor PQ signatures
    ZxyDilithium3 = 0xFF01,
    ZxyFalcon512 = 0xFF02,
    ZxySphincsSha2128f = 0xFF03,
}

/// TLS alert description
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

/// TLS extension type
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    Alpn = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    EncryptThenMac = 22,
    ExtendedMasterSecret = 23,
    CompressCertificate = 27,
    RecordSizeLimit = 28,
    DelegatedCredential = 34,
    SessionTicket = 35,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    TransparencyInfo = 52,
    EncryptedClientHello = 65037,
    Quic = 57,
    /// Zxyphor extensions
    ZxyPqNegotiation = 65280,
}

/// kTLS (Kernel TLS) offload mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtlsOffloadMode {
    Software = 0,
    HardwareRx = 1,
    HardwareTx = 2,
    HardwareFull = 3,
    /// Zxyphor: Zero-copy kTLS
    ZxyZeroCopy = 10,
}

/// kTLS crypto info (generic)
#[repr(C)]
pub struct KtlsCryptoInfo {
    pub version: TlsVersion,
    pub cipher_type: TlsCipherSuite,
}

/// kTLS AES-128-GCM info
#[repr(C)]
pub struct KtlsCryptoInfoAes128Gcm {
    pub info: KtlsCryptoInfo,
    pub iv: [8; u8],
    pub key: [16; u8],
    pub salt: [4; u8],
    pub rec_seq: [8; u8],
}

/// kTLS AES-256-GCM info
#[repr(C)]
pub struct KtlsCryptoInfoAes256Gcm {
    pub info: KtlsCryptoInfo,
    pub iv: [8; u8],
    pub key: [32; u8],
    pub salt: [4; u8],
    pub rec_seq: [8; u8],
}

/// kTLS ChaCha20-Poly1305 info
#[repr(C)]
pub struct KtlsCryptoInfoChacha20Poly1305 {
    pub info: KtlsCryptoInfo,
    pub iv: [12; u8],
    pub key: [32; u8],
    pub rec_seq: [8; u8],
}

// ============================================================================
// WireGuard-like VPN
// ============================================================================

/// WireGuard message type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgMessageType {
    Initiation = 1,
    Response = 2,
    CookieReply = 3,
    Transport = 4,
}

/// WireGuard noise protocol params
pub struct WgNoiseParams;
impl WgNoiseParams {
    pub const KEY_LEN: usize = 32;
    pub const HASH_LEN: usize = 32;
    pub const AEAD_TAG_LEN: usize = 16;
    pub const TIMESTAMP_LEN: usize = 12;
    pub const COOKIE_LEN: usize = 16;
    pub const LABEL_MAC1: &'static [u8] = b"mac1----";
    pub const LABEL_COOKIE: &'static [u8] = b"cookie--";
    pub const CONSTRUCTION: &'static str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    pub const IDENTIFIER: &'static str = "WireGuard v1 zx0000000000000";
    pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
    pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
    pub const REKEY_AFTER_TIME_SECS: u64 = 120;
    pub const REJECT_AFTER_TIME_SECS: u64 = 180;
    pub const REKEY_TIMEOUT_SECS: u64 = 5;
    pub const KEEPALIVE_TIMEOUT_SECS: u64 = 10;
}

/// WireGuard peer config
#[repr(C)]
pub struct WgPeerConfig {
    pub public_key: [32; u8],
    pub preshared_key: [32; u8],
    pub endpoint_addr: [16; u8],       // IPv4 or IPv6
    pub endpoint_port: u16,
    pub endpoint_family: u16,
    pub persistent_keepalive_secs: u16,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_sec: u64,
    pub last_handshake_nsec: u64,
    pub nr_allowed_ips: u32,
}

/// WireGuard device config
#[repr(C)]
pub struct WgDeviceConfig {
    pub private_key: [32; u8],
    pub public_key: [32; u8],
    pub listen_port: u16,
    pub fwmark: u32,
    pub ifindex: u32,
    pub nr_peers: u32,
}

// ============================================================================
// QUIC Crypto
// ============================================================================

/// QUIC version
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    V1 = 0x00000001,
    V2 = 0x6B3343CF,
    /// Zxyphor custom
    ZxyV1 = 0xFF000001,
}

/// QUIC packet type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketType {
    Initial = 0,
    ZeroRtt = 1,
    Handshake = 2,
    Retry = 3,
    OneRtt = 4,        // Short header
    VersionNegotiation = 5,
}

/// QUIC encryption level
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicEncryptionLevel {
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    Application = 3,
}

/// QUIC transport parameters
#[repr(C)]
pub struct QuicTransportParams {
    pub original_destination_connection_id: [20; u8],
    pub max_idle_timeout_ms: u64,
    pub stateless_reset_token: [16; u8],
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay_ms: u64,
    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: [20; u8],
    pub retry_source_connection_id: [20; u8],
    pub max_datagram_frame_size: u64,
    pub grease_quic_bit: bool,
}

// ============================================================================
// Network Key Management
// ============================================================================

/// Key exchange protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeProto {
    None = 0,
    Ike = 1,           // IKEv2
    Tls = 2,
    WireGuard = 3,
    Macsec = 4,
    /// Zxyphor
    ZxyHybridPq = 50,
}

/// Key lifecycle state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleState {
    Pending = 0,
    Active = 1,
    Expiring = 2,
    Expired = 3,
    Revoked = 4,
}

/// Network key descriptor
#[repr(C)]
pub struct NetKeyDescriptor {
    pub key_id: u64,
    pub protocol: KeyExchangeProto,
    pub state: KeyLifecycleState,
    pub algo: u16,
    pub key_len_bits: u32,
    pub created_time_ns: u64,
    pub expiry_time_ns: u64,
    pub rekey_time_ns: u64,
    pub usage_count: u64,
    pub bytes_protected: u64,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

pub struct NetCryptoSubsystem {
    // TLS
    pub nr_tls_connections: u64,
    pub nr_ktls_offload_sw: u64,
    pub nr_ktls_offload_hw: u64,
    pub total_tls_handshakes: u64,
    pub total_tls_failures: u64,
    // WireGuard
    pub nr_wg_interfaces: u32,
    pub nr_wg_peers: u32,
    pub total_wg_handshakes: u64,
    // QUIC
    pub nr_quic_connections: u64,
    pub total_quic_0rtt: u64,
    // Keys
    pub nr_active_keys: u64,
    pub total_key_rotations: u64,
    // Zxyphor
    pub zxy_pq_hybrid_enabled: bool,
    pub zxy_hw_offload_active: bool,
    pub initialized: bool,
}

impl NetCryptoSubsystem {
    pub fn new() -> Self {
        Self {
            nr_tls_connections: 0,
            nr_ktls_offload_sw: 0,
            nr_ktls_offload_hw: 0,
            total_tls_handshakes: 0,
            total_tls_failures: 0,
            nr_wg_interfaces: 0,
            nr_wg_peers: 0,
            total_wg_handshakes: 0,
            nr_quic_connections: 0,
            total_quic_0rtt: 0,
            nr_active_keys: 0,
            total_key_rotations: 0,
            zxy_pq_hybrid_enabled: true,
            zxy_hw_offload_active: true,
            initialized: false,
        }
    }
}
