// =============================================================================
// Kernel Zxyphor — Rust TLS 1.3 Protocol Engine
// =============================================================================
// A minimal TLS 1.3 (RFC 8446) implementation for kernel-level secure
// communication. Provides the record layer, handshake state machine, and
// AEAD encryption for kernel services that require encrypted transport
// (e.g., kernel module verification, secure NTP, remote logging).
//
// Supported cipher suites:
//   - TLS_AES_256_GCM_SHA384 (0x1302)
//   - TLS_AES_128_GCM_SHA256 (0x1301)
//   - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
//
// This is NOT a full TLS library — it handles the protocol framing and state
// machine, delegating actual cryptographic operations to the crypto module.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum TLS record size (RFC 8446 Section 5.1)
const MAX_TLS_RECORD_SIZE: usize = 16384; // 2^14 bytes

/// TLS record header size
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// TLS 1.3 protocol version (in the record layer, legacy version 0x0303 is used)
const TLS_LEGACY_VERSION: u16 = 0x0303;

/// Maximum number of concurrent TLS sessions
const MAX_TLS_SESSIONS: usize = 64;

// =============================================================================
// TLS content types (RFC 8446 Section 5.1)
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TlsContentType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            20 => TlsContentType::ChangeCipherSpec,
            21 => TlsContentType::Alert,
            22 => TlsContentType::Handshake,
            23 => TlsContentType::ApplicationData,
            _ => TlsContentType::Invalid,
        }
    }
}

// =============================================================================
// TLS handshake message types (RFC 8446 Section 4)
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Unknown = 0,
}

impl TlsHandshakeType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => TlsHandshakeType::ClientHello,
            2 => TlsHandshakeType::ServerHello,
            4 => TlsHandshakeType::NewSessionTicket,
            5 => TlsHandshakeType::EndOfEarlyData,
            8 => TlsHandshakeType::EncryptedExtensions,
            11 => TlsHandshakeType::Certificate,
            13 => TlsHandshakeType::CertificateRequest,
            15 => TlsHandshakeType::CertificateVerify,
            20 => TlsHandshakeType::Finished,
            24 => TlsHandshakeType::KeyUpdate,
            254 => TlsHandshakeType::MessageHash,
            _ => TlsHandshakeType::Unknown,
        }
    }
}

// =============================================================================
// TLS alert descriptions (RFC 8446 Section 6)
// =============================================================================

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

/// TLS alert level
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAlertLevel {
    Warning = 1,
    Fatal = 2,
}

// =============================================================================
// TLS cipher suites
// =============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
    Unknown = 0,
}

impl TlsCipherSuite {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x1301 => TlsCipherSuite::TlsAes128GcmSha256,
            0x1302 => TlsCipherSuite::TlsAes256GcmSha384,
            0x1303 => TlsCipherSuite::TlsChacha20Poly1305Sha256,
            _ => TlsCipherSuite::Unknown,
        }
    }

    /// Get the key length in bytes for this cipher suite
    pub fn key_length(&self) -> usize {
        match self {
            TlsCipherSuite::TlsAes128GcmSha256 => 16,
            TlsCipherSuite::TlsAes256GcmSha384 => 32,
            TlsCipherSuite::TlsChacha20Poly1305Sha256 => 32,
            TlsCipherSuite::Unknown => 0,
        }
    }

    /// Get the IV/nonce length in bytes
    pub fn iv_length(&self) -> usize {
        12 // All TLS 1.3 AEAD suites use 12-byte nonces
    }

    /// Get the authentication tag length in bytes
    pub fn tag_length(&self) -> usize {
        16 // All supported suites use 16-byte tags
    }

    /// Get the hash length for the PRF
    pub fn hash_length(&self) -> usize {
        match self {
            TlsCipherSuite::TlsAes128GcmSha256 => 32,
            TlsCipherSuite::TlsAes256GcmSha384 => 48,
            TlsCipherSuite::TlsChacha20Poly1305Sha256 => 32,
            TlsCipherSuite::Unknown => 0,
        }
    }
}

// =============================================================================
// TLS named groups (for key exchange)
// =============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsNamedGroup {
    X25519 = 0x001D,
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X448 = 0x001E,
    Unknown = 0,
}

impl TlsNamedGroup {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x001D => TlsNamedGroup::X25519,
            0x0017 => TlsNamedGroup::Secp256r1,
            0x0018 => TlsNamedGroup::Secp384r1,
            0x0019 => TlsNamedGroup::Secp521r1,
            0x001E => TlsNamedGroup::X448,
            _ => TlsNamedGroup::Unknown,
        }
    }
}

// =============================================================================
// TLS signature schemes
// =============================================================================

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
    Unknown = 0,
}

// =============================================================================
// TLS extension types
// =============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    SupportedVersions = 43,
    PskKeyExchangeModes = 45,
    KeyShare = 51,
    Unknown = 0xFFFF,
}

impl TlsExtensionType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0 => TlsExtensionType::ServerName,
            10 => TlsExtensionType::SupportedGroups,
            13 => TlsExtensionType::SignatureAlgorithms,
            43 => TlsExtensionType::SupportedVersions,
            45 => TlsExtensionType::PskKeyExchangeModes,
            51 => TlsExtensionType::KeyShare,
            _ => TlsExtensionType::Unknown,
        }
    }
}

// =============================================================================
// TLS record layer
// =============================================================================

/// A TLS record header (5 bytes)
#[repr(C)]
pub struct TlsRecordHeader {
    pub content_type: TlsContentType,
    pub legacy_version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    /// Parse a TLS record header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < TLS_RECORD_HEADER_SIZE {
            return None;
        }

        let content_type = TlsContentType::from_u8(data[0]);
        let legacy_version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);

        // Validate record length (max 2^14 + 256 for encrypted records)
        if length as usize > MAX_TLS_RECORD_SIZE + 256 {
            return None;
        }

        Some(TlsRecordHeader {
            content_type,
            legacy_version,
            length,
        })
    }

    /// Serialize a TLS record header to bytes
    pub fn to_bytes(&self, buf: &mut [u8]) -> usize {
        if buf.len() < TLS_RECORD_HEADER_SIZE {
            return 0;
        }

        buf[0] = self.content_type as u8;
        let ver = self.legacy_version.to_be_bytes();
        buf[1] = ver[0];
        buf[2] = ver[1];
        let len = self.length.to_be_bytes();
        buf[3] = len[0];
        buf[4] = len[1];

        TLS_RECORD_HEADER_SIZE
    }
}

// =============================================================================
// TLS session state
// =============================================================================

/// State of a TLS 1.3 handshake
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSessionState {
    /// Initial state, no handshake started
    Idle = 0,
    /// ClientHello sent, waiting for ServerHello
    WaitServerHello = 1,
    /// ServerHello received, waiting for encrypted extensions
    WaitEncryptedExtensions = 2,
    /// Waiting for server certificate
    WaitCertificate = 3,
    /// Waiting for certificate verify
    WaitCertificateVerify = 4,
    /// Waiting for server Finished
    WaitFinished = 5,
    /// Handshake complete, application data can flow
    Connected = 6,
    /// Session is closing (close_notify sent)
    Closing = 7,
    /// Session is closed
    Closed = 8,
    /// Error state
    Error = 9,
}

/// A TLS 1.3 session
#[repr(C)]
pub struct TlsSession {
    /// Session identifier
    pub session_id: u64,
    /// Current session state
    pub state: TlsSessionState,
    /// Negotiated cipher suite
    pub cipher_suite: TlsCipherSuite,
    /// Negotiated named group (for key exchange)
    pub named_group: TlsNamedGroup,
    /// Client random (32 bytes used in key derivation)
    pub client_random: [u8; 32],
    /// Server random (32 bytes)
    pub server_random: [u8; 32],
    /// Handshake traffic secret (client)
    pub client_handshake_secret: [u8; 48],
    /// Handshake traffic secret (server)
    pub server_handshake_secret: [u8; 48],
    /// Application traffic secret (client)
    pub client_app_secret: [u8; 48],
    /// Application traffic secret (server)
    pub server_app_secret: [u8; 48],
    /// Client write key (derived from traffic secret)
    pub client_write_key: [u8; 32],
    /// Client write IV
    pub client_write_iv: [u8; 12],
    /// Server write key
    pub server_write_key: [u8; 32],
    /// Server write IV
    pub server_write_iv: [u8; 12],
    /// Sequence number for client → server records
    pub client_seq_num: AtomicU64,
    /// Sequence number for server → client records
    pub server_seq_num: AtomicU64,
    /// Transcript hash of all handshake messages
    pub transcript_hash: [u8; 48],
    /// Length of the transcript hash (32 for SHA-256, 48 for SHA-384)
    pub transcript_hash_len: usize,
    /// Whether this session slot is in use
    pub in_use: bool,
    /// Whether the session has been verified (server cert validated)
    pub verified: bool,
    /// Total bytes sent in this session
    pub bytes_sent: AtomicU64,
    /// Total bytes received in this session
    pub bytes_received: AtomicU64,
    /// Time when session was established
    pub established_at: u64,
    /// Last activity timestamp
    pub last_activity: AtomicU64,
}

impl TlsSession {
    pub const fn empty() -> Self {
        TlsSession {
            session_id: 0,
            state: TlsSessionState::Idle,
            cipher_suite: TlsCipherSuite::Unknown,
            named_group: TlsNamedGroup::Unknown,
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            client_handshake_secret: [0u8; 48],
            server_handshake_secret: [0u8; 48],
            client_app_secret: [0u8; 48],
            server_app_secret: [0u8; 48],
            client_write_key: [0u8; 32],
            client_write_iv: [0u8; 12],
            server_write_key: [0u8; 32],
            server_write_iv: [0u8; 12],
            client_seq_num: AtomicU64::new(0),
            server_seq_num: AtomicU64::new(0),
            transcript_hash: [0u8; 48],
            transcript_hash_len: 0,
            in_use: false,
            verified: false,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            established_at: 0,
            last_activity: AtomicU64::new(0),
        }
    }

    /// Generate the per-record nonce by XORing the IV with the sequence number
    ///
    /// Per RFC 8446 Section 5.3: the nonce is formed by XORing the IV with
    /// the 64-bit sequence number (left-padded with zeros to IV length).
    pub fn compute_nonce(iv: &[u8; 12], seq_num: u64) -> [u8; 12] {
        let mut nonce = *iv;
        let seq_bytes = seq_num.to_be_bytes();

        // XOR the last 8 bytes of the IV with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        nonce
    }
}

// =============================================================================
// ClientHello builder
// =============================================================================

/// Build a TLS 1.3 ClientHello message
pub struct ClientHelloBuilder {
    buffer: [u8; 1024],
    position: usize,
}

impl ClientHelloBuilder {
    pub fn new() -> Self {
        ClientHelloBuilder {
            buffer: [0u8; 1024],
            position: 0,
        }
    }

    /// Build a ClientHello message
    pub fn build(
        &mut self,
        client_random: &[u8; 32],
        server_name: &[u8],
    ) -> Option<&[u8]> {
        self.position = 0;

        // TLS Record header (filled in at the end)
        self.position = TLS_RECORD_HEADER_SIZE;

        // Handshake header
        let handshake_start = self.position;
        self.write_u8(TlsHandshakeType::ClientHello as u8)?;
        // Length placeholder (3 bytes) — filled in later
        let length_pos = self.position;
        self.position += 3;

        let client_hello_start = self.position;

        // Legacy version (TLS 1.2 = 0x0303, required by RFC 8446)
        self.write_u16(TLS_LEGACY_VERSION)?;

        // Client random (32 bytes)
        self.write_bytes(client_random)?;

        // Legacy session ID (0 length for TLS 1.3)
        self.write_u8(0)?;

        // Cipher suites (length + suites)
        self.write_u16(6)?; // 3 cipher suites × 2 bytes
        self.write_u16(TlsCipherSuite::TlsAes256GcmSha384 as u16)?;
        self.write_u16(TlsCipherSuite::TlsAes128GcmSha256 as u16)?;
        self.write_u16(TlsCipherSuite::TlsChacha20Poly1305Sha256 as u16)?;

        // Compression methods (1 byte length + null compression)
        self.write_u8(1)?;
        self.write_u8(0)?; // No compression

        // Extensions
        let ext_length_pos = self.position;
        self.position += 2; // Extension length placeholder

        let ext_start = self.position;

        // Supported Versions extension (mandatory for TLS 1.3)
        self.write_u16(TlsExtensionType::SupportedVersions as u16)?;
        self.write_u16(3)?; // Extension data length
        self.write_u8(2)?; // List length
        self.write_u16(0x0304)?; // TLS 1.3

        // Supported Groups extension
        self.write_u16(TlsExtensionType::SupportedGroups as u16)?;
        self.write_u16(6)?; // Extension data length
        self.write_u16(4)?; // List length (2 groups × 2 bytes)
        self.write_u16(TlsNamedGroup::X25519 as u16)?;
        self.write_u16(TlsNamedGroup::Secp256r1 as u16)?;

        // Signature Algorithms extension
        self.write_u16(TlsExtensionType::SignatureAlgorithms as u16)?;
        self.write_u16(8)?; // Extension data length
        self.write_u16(6)?; // List length
        self.write_u16(TlsSignatureScheme::EcdsaSecp256r1Sha256 as u16)?;
        self.write_u16(TlsSignatureScheme::RsaPssRsaeSha256 as u16)?;
        self.write_u16(TlsSignatureScheme::Ed25519 as u16)?;

        // Server Name Indication (SNI) extension
        if !server_name.is_empty() && server_name.len() < 256 {
            self.write_u16(TlsExtensionType::ServerName as u16)?;
            let sni_len = 5 + server_name.len();
            self.write_u16(sni_len as u16)?;
            self.write_u16((sni_len - 2) as u16)?; // Server name list length
            self.write_u8(0)?; // Host name type
            self.write_u16(server_name.len() as u16)?;
            self.write_bytes(server_name)?;
        }

        // PSK Key Exchange Modes extension (required for PSK)
        self.write_u16(TlsExtensionType::PskKeyExchangeModes as u16)?;
        self.write_u16(2)?;
        self.write_u8(1)?; // List length
        self.write_u8(1)?; // psk_dhe_ke mode

        // Fill in extension length
        let ext_len = (self.position - ext_start) as u16;
        self.buffer[ext_length_pos] = (ext_len >> 8) as u8;
        self.buffer[ext_length_pos + 1] = (ext_len & 0xFF) as u8;

        // Fill in handshake length (3 bytes)
        let hs_len = (self.position - client_hello_start) as u32;
        self.buffer[length_pos] = ((hs_len >> 16) & 0xFF) as u8;
        self.buffer[length_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        self.buffer[length_pos + 2] = (hs_len & 0xFF) as u8;

        // Fill in TLS record header
        self.buffer[0] = TlsContentType::Handshake as u8;
        let ver = TLS_LEGACY_VERSION.to_be_bytes();
        self.buffer[1] = ver[0];
        self.buffer[2] = ver[1];
        let record_len = (self.position - TLS_RECORD_HEADER_SIZE) as u16;
        self.buffer[3] = (record_len >> 8) as u8;
        self.buffer[4] = (record_len & 0xFF) as u8;

        let _ = handshake_start;

        Some(&self.buffer[..self.position])
    }

    fn write_u8(&mut self, val: u8) -> Option<()> {
        if self.position >= self.buffer.len() {
            return None;
        }
        self.buffer[self.position] = val;
        self.position += 1;
        Some(())
    }

    fn write_u16(&mut self, val: u16) -> Option<()> {
        if self.position + 2 > self.buffer.len() {
            return None;
        }
        let bytes = val.to_be_bytes();
        self.buffer[self.position] = bytes[0];
        self.buffer[self.position + 1] = bytes[1];
        self.position += 2;
        Some(())
    }

    fn write_bytes(&mut self, data: &[u8]) -> Option<()> {
        if self.position + data.len() > self.buffer.len() {
            return None;
        }
        self.buffer[self.position..self.position + data.len()].copy_from_slice(data);
        self.position += data.len();
        Some(())
    }
}

// =============================================================================
// Global TLS state
// =============================================================================

static TLS_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_SESSIONS: AtomicU64 = AtomicU64::new(0);
static TOTAL_HANDSHAKES: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI interface
// =============================================================================

/// Initialize the TLS subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_tls_init() -> i32 {
    if TLS_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    TLS_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust TLS 1.3 engine initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Create a new TLS session
#[no_mangle]
pub extern "C" fn zxyphor_rust_tls_create_session() -> u64 {
    if !TLS_INITIALIZED.load(Ordering::Acquire) {
        return 0;
    }

    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst);
    ACTIVE_SESSIONS.fetch_add(1, Ordering::Relaxed);
    TOTAL_HANDSHAKES.fetch_add(1, Ordering::Relaxed);

    id
}

/// Destroy a TLS session
#[no_mangle]
pub extern "C" fn zxyphor_rust_tls_destroy_session(session_id: u64) -> i32 {
    if session_id == 0 {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    ACTIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed);
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Build a ClientHello message
#[no_mangle]
pub extern "C" fn zxyphor_rust_tls_build_client_hello(
    client_random: *const u8,
    server_name: *const u8,
    server_name_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if client_random.is_null() || output.is_null() || output_len.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let random: [u8; 32] = unsafe {
        let slice = core::slice::from_raw_parts(client_random, 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        arr
    };

    let sni = if !server_name.is_null() && server_name_len > 0 {
        unsafe { core::slice::from_raw_parts(server_name, server_name_len) }
    } else {
        &[]
    };

    let mut builder = ClientHelloBuilder::new();
    match builder.build(&random, sni) {
        Some(data) => {
            if data.len() > output_capacity {
                return crate::ffi::error::FfiError::BufferTooSmall.as_i32();
            }
            let out = unsafe { core::slice::from_raw_parts_mut(output, output_capacity) };
            out[..data.len()].copy_from_slice(data);
            unsafe { *output_len = data.len() };
            crate::ffi::error::FfiError::Success.as_i32()
        }
        None => crate::ffi::error::FfiError::InvalidState.as_i32(),
    }
}

/// Parse a TLS record header
#[no_mangle]
pub extern "C" fn zxyphor_rust_tls_parse_record(
    data: *const u8,
    data_len: usize,
    content_type: *mut u8,
    record_len: *mut u16,
) -> i32 {
    if data.is_null() || content_type.is_null() || record_len.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    if data_len < TLS_RECORD_HEADER_SIZE {
        return crate::ffi::error::FfiError::BufferTooSmall.as_i32();
    }

    let slice = unsafe { core::slice::from_raw_parts(data, data_len) };
    match TlsRecordHeader::from_bytes(slice) {
        Some(header) => {
            unsafe {
                *content_type = header.content_type as u8;
                *record_len = header.length;
            }
            crate::ffi::error::FfiError::Success.as_i32()
        }
        None => crate::ffi::error::FfiError::Corruption.as_i32(),
    }
}

/// Get TLS statistics
#[repr(C)]
pub struct TlsStats {
    pub active_sessions: u64,
    pub total_handshakes: u64,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_tls_stats(stats_out: *mut TlsStats) -> i32 {
    if stats_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let stats = TlsStats {
        active_sessions: ACTIVE_SESSIONS.load(Ordering::Relaxed),
        total_handshakes: TOTAL_HANDSHAKES.load(Ordering::Relaxed),
    };

    unsafe { core::ptr::write(stats_out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}
