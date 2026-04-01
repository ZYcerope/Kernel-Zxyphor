// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Rust - Crypto Framework and Hardware Acceleration
// Cipher algorithms, hash algorithms, AEAD, KDF, RNG, public key crypto,
// AF_ALG socket interface, hardware crypto engine, key management
// More advanced than Linux 2026 crypto subsystem

#![allow(dead_code)]
#![allow(non_camel_case_types)]

// ============================================================================
// Algorithm Types
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CryptoAlgType {
    Cipher = 0,          // Single block cipher
    Compress = 1,
    Aead = 3,            // Authenticated Encryption with Associated Data
    Blkcipher = 4,       // Deprecated, use skcipher
    Ablkcipher = 5,      // Deprecated
    Givcipher = 6,       // Deprecated
    Skcipher = 7,        // Symmetric key cipher
    Hash = 8,
    Ahash = 9,           // Async hash
    Shash = 10,          // Sync hash
    Rng = 11,            // Random number generator
    Akcipher = 12,       // Asymmetric key cipher
    Kpp = 13,            // Key-agreement protocol primitive
    Acomp = 14,          // Async compression
    Scomp = 15,          // Sync compression
}

// ============================================================================
// Cipher Algorithms
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherId {
    // Block ciphers
    AES128 = 1,
    AES192 = 2,
    AES256 = 3,
    ChaCha20 = 4,
    XChaCha20 = 5,
    SM4 = 6,
    Camellia128 = 7,
    Camellia192 = 8,
    Camellia256 = 9,
    Aria128 = 10,
    Aria192 = 11,
    Aria256 = 12,
    Twofish128 = 13,
    Twofish256 = 14,
    Serpent128 = 15,
    Serpent256 = 16,
    // Zxyphor
    ZxyQuantumSafe = 100,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherMode {
    ECB = 0,
    CBC = 1,
    CTR = 2,
    XTS = 3,
    GCM = 4,
    CCM = 5,
    Poly1305 = 6,
    ChaCha20Poly1305 = 7,
    ADIANTUM = 8,
    HCTR2 = 9,
    SIV = 10,
    GCM_SIV = 11,
    OCB = 12,
    EAX = 13,
    ESSIV = 14,
    // Zxyphor
    ZxyStreamCipher = 20,
}

pub struct CipherAlg {
    pub id: CipherId,
    pub mode: CipherMode,
    pub name: [64; u8],
    pub driver_name: [128; u8],
    pub block_size: u32,
    pub min_keysize: u32,
    pub max_keysize: u32,
    pub iv_size: u32,
    pub chunk_size: u32,
    pub walksize: u32,
    // Priority
    pub priority: i32,
    // Flags
    pub internal: bool,
    pub async_op: bool,
    pub need_fallback: bool,
    pub hw_accel: bool,
}

// ============================================================================
// Hash Algorithms
// ============================================================================

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashId {
    MD5 = 1,             // Deprecated, but needed for compat
    SHA1 = 2,            // Deprecated for security
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
    SHA3_224 = 7,
    SHA3_256 = 8,
    SHA3_384 = 9,
    SHA3_512 = 10,
    BLAKE2b256 = 11,
    BLAKE2b512 = 12,
    BLAKE2s256 = 13,
    BLAKE3 = 14,
    SM3 = 15,
    RIPEMD160 = 16,
    WHIRLPOOL = 17,
    // HMAC
    HMAC_SHA256 = 50,
    HMAC_SHA384 = 51,
    HMAC_SHA512 = 52,
    HMAC_SHA3_256 = 53,
    HMAC_BLAKE2b256 = 54,
    // CMAC
    CMAC_AES = 60,
    // Poly1305
    Poly1305 = 70,
    // SipHash
    SipHash24 = 80,
    HalfSipHash24 = 81,
    // GHASH (GCM)
    GHASH = 90,
    // XXHash
    XXH32 = 95,
    XXH64 = 96,
    XXH3 = 97,
    // CRC
    CRC32 = 100,
    CRC32C = 101,
    CRC64 = 102,
    // Zxyphor
    ZxyHash = 200,
}

pub struct HashAlg {
    pub id: HashId,
    pub name: [64; u8],
    pub driver_name: [128; u8],
    pub digest_size: u32,
    pub block_size: u32,
    pub state_size: u32,
    pub priority: i32,
    pub hw_accel: bool,
}

pub struct HashState {
    pub alg: HashId,
    pub state: [256; u8],
    pub state_size: u32,
    pub count: u64,
    pub finalized: bool,
}

// ============================================================================
// AEAD (Authenticated Encryption with Associated Data)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AeadId {
    AesGcm128 = 1,
    AesGcm256 = 2,
    AesCcm = 3,
    ChaCha20Poly1305 = 4,
    XChaCha20Poly1305 = 5,
    AesGcmSiv = 6,
    Aegis128 = 7,
    Aegis256 = 8,
    Morus640 = 9,
    Morus1280 = 10,
    // RFC 7539
    Rfc7539 = 11,
    // Zxyphor
    ZxyAead = 20,
}

pub struct AeadAlg {
    pub id: AeadId,
    pub name: [64; u8],
    pub iv_size: u32,
    pub max_authsize: u32,
    pub chunk_size: u32,
    pub priority: i32,
    pub hw_accel: bool,
}

// ============================================================================
// KDF (Key Derivation Functions)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KdfType {
    HKDF = 1,
    PBKDF2 = 2,
    Scrypt = 3,
    Argon2i = 4,
    Argon2d = 5,
    Argon2id = 6,
    KBKDF = 7,      // Key-Based KDF (NIST SP 800-108)
    KDFa = 8,       // TPM KDFa
    // Zxyphor
    ZxyKdf = 20,
}

pub struct KdfParams {
    pub kdf_type: KdfType,
    // Common
    pub salt: [256; u8],
    pub salt_len: u32,
    pub info: [256; u8],
    pub info_len: u32,
    pub output_len: u32,
    // PBKDF2
    pub iterations: u32,
    pub hash: HashId,
    // Scrypt
    pub scrypt_n: u64,
    pub scrypt_r: u32,
    pub scrypt_p: u32,
    // Argon2
    pub argon2_time: u32,
    pub argon2_memory_kb: u32,
    pub argon2_parallelism: u32,
}

// ============================================================================
// RNG (Random Number Generator)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RngType {
    // NIST SP 800-90A
    HmacDrbg = 1,
    HashDrbg = 2,
    CtrDrbg = 3,
    // NIST SP 800-90C
    XDrbg = 4,
    // Linux
    JitterEntropy = 5,
    // Hardware
    RDRAND = 6,
    RDSEED = 7,
    VirtioRng = 8,
    TpmRng = 9,
    // Zxyphor
    ZxyCsprng = 10,
}

pub struct RngState {
    pub rng_type: RngType,
    pub seed_size: u32,
    pub bytes_generated: u64,
    pub reseed_threshold: u64,
    pub reseed_count: u64,
    pub last_reseed: u64,
    pub seeded: bool,
    // Entropy pool
    pub entropy_avail: u32,  // bits
    pub entropy_pool_size: u32,
    pub write_wakeup_threshold: u32,
    // Stats
    pub hw_rng_bytes: u64,
    pub urandom_reads: u64,
    pub random_reads: u64,
    pub getrandom_calls: u64,
}

// ============================================================================
// Public Key Cryptography
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PkAlgorithm {
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
    EdDSA = 4,
    Ed25519 = 5,
    Ed448 = 6,
    X25519 = 7,
    X448 = 8,
    ECDH = 9,
    DH = 10,
    SM2 = 11,
    // Post-quantum
    Dilithium2 = 20,
    Dilithium3 = 21,
    Dilithium5 = 22,
    Kyber512 = 23,
    Kyber768 = 24,
    Kyber1024 = 25,
    // ML-KEM / ML-DSA (NIST PQC)
    MlKem512 = 30,
    MlKem768 = 31,
    MlKem1024 = 32,
    MlDsa44 = 33,
    MlDsa65 = 34,
    MlDsa87 = 35,
    // Zxyphor
    ZxyHybridPq = 50,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EcCurve {
    P256 = 1,
    P384 = 2,
    P521 = 3,
    Curve25519 = 4,
    Curve448 = 5,
    SecP256k1 = 6,  // Bitcoin curve
    BrainpoolP256r1 = 7,
    BrainpoolP384r1 = 8,
    BrainpoolP512r1 = 9,
    SM2 = 10,
    Ed25519 = 11,
    Ed448 = 12,
}

pub struct PkKeyPair {
    pub algorithm: PkAlgorithm,
    pub curve: Option<EcCurve>,
    pub key_size_bits: u32,
    // Key material (opaque)
    pub public_key: [4096; u8],
    pub public_key_len: u32,
    pub private_key: [4096; u8],
    pub private_key_len: u32,
    // Usage
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub can_derive: bool,
}

// ============================================================================
// Key Management (Kernel Keyring)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    User = 0,
    Logon = 1,
    BigKey = 2,
    Keyring = 3,
    Encrypted = 4,
    Trusted = 5,
    Asymmetric = 6,
    DnsCacheResolver = 7,
    RequestKey = 8,
    RxrpcS = 9,
    // Zxyphor
    ZxyCrypto = 20,
}

pub struct KernelKey {
    pub serial: i32,
    pub key_type: KeyType,
    pub desc: [256; u8],
    pub desc_len: u16,
    // Permissions
    pub uid: u32,
    pub gid: u32,
    pub perm: u32,
    // Payload
    pub payload_len: u32,
    // State
    pub state: KeyState,
    pub expiry: u64,
    // Usage
    pub usage_count: u32,
    pub quota_bytes: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KeyState {
    Uninstantiated = 0,
    Instantiated = 1,
    Negative = 2,
    Expired = 3,
    Revoked = 4,
    Dead = 5,
}

// Keyring special IDs
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;

// ============================================================================
// AF_ALG Socket Interface
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AlgSockType {
    Aead = 0,
    Hash = 1,
    Skcipher = 2,
    Rng = 3,
    Akcipher = 4,
    Kpp = 5,
}

#[repr(C)]
pub struct SockaddrAlg {
    pub salg_family: u16,
    pub salg_type: [14; u8],
    pub salg_feat: u32,
    pub salg_mask: u32,
    pub salg_name: [64; u8],
}

pub struct AlgSocket {
    pub sock_type: AlgSockType,
    pub alg_name: [64; u8],
    pub key_set: bool,
    pub key_len: u32,
    pub iv_set: bool,
    pub iv_len: u32,
    pub aad_len: u32,
    pub tag_len: u32,
    // Stats
    pub encrypt_count: u64,
    pub decrypt_count: u64,
    pub bytes_processed: u64,
}

// ============================================================================
// Hardware Crypto Engine
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum HwCryptoType {
    None = 0,
    AesNi = 1,        // Intel AES-NI
    VaesAvx512 = 2,   // VAES + AVX-512
    Sha256Ni = 3,     // Intel SHA extensions
    Armce = 4,         // ARM Crypto Extensions
    Sve = 5,           // ARM SVE
    Ccp = 6,           // AMD Crypto Coprocessor
    QAT = 7,           // Intel QuickAssist
    CAAM = 8,          // NXP CAAM
    Omap = 9,          // TI OMAP crypto
    CryptoCell = 10,   // Arm CryptoCell
    // Zxyphor
    ZxyEngine = 20,
}

pub struct HwCryptoEngine {
    pub hw_type: HwCryptoType,
    pub name: [64; u8],
    // Capabilities
    pub supports_aes: bool,
    pub supports_sha: bool,
    pub supports_aead: bool,
    pub supports_rng: bool,
    pub supports_pk: bool,
    // Queue depth
    pub max_queue_depth: u32,
    pub current_queue_depth: u32,
    // Stats
    pub requests_processed: u64,
    pub bytes_encrypted: u64,
    pub bytes_decrypted: u64,
    pub bytes_hashed: u64,
    pub errors: u64,
    // Performance
    pub avg_latency_ns: u64,
    pub peak_throughput_mbps: u64,
    // Power
    pub power_state: u8,
    pub active: bool,
}

// ============================================================================
// Crypto Subsystem Manager
// ============================================================================

pub struct CryptoSubsystem {
    // Registered algorithms
    pub nr_cipher_algs: u32,
    pub nr_hash_algs: u32,
    pub nr_aead_algs: u32,
    pub nr_rng_algs: u32,
    pub nr_pk_algs: u32,
    // Hardware engines
    pub hw_engines: [16; HwCryptoEngine],
    pub nr_hw_engines: u32,
    // RNG state
    pub system_rng: RngState,
    // AF_ALG sockets
    pub nr_alg_sockets: u32,
    // FIPS mode
    pub fips_enabled: bool,
    // Self-test
    pub self_test_passed: bool,
    // Stats
    pub total_encrypt_ops: u64,
    pub total_decrypt_ops: u64,
    pub total_hash_ops: u64,
    pub total_sign_ops: u64,
    pub total_verify_ops: u64,
    pub total_key_agreement_ops: u64,
    pub total_bytes_processed: u64,
    // Zxyphor
    pub zxy_pq_enabled: bool,
    pub zxy_hw_offload_auto: bool,
    pub initialized: bool,
}
