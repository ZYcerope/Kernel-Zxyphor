// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Crypto Library Zig-side: Hash Functions, Ciphers,
// AEAD, KDF, MAC, RNG, Public Key, Signature, Key Agreement
// More advanced than Linux 2026 crypto API

const std = @import("std");

// ============================================================================
// Hash Algorithms
// ============================================================================

/// Hash algorithm type
pub const HashAlgo = enum(u8) {
    md5 = 0,
    sha1 = 1,
    sha224 = 2,
    sha256 = 3,
    sha384 = 4,
    sha512 = 5,
    sha3_224 = 6,
    sha3_256 = 7,
    sha3_384 = 8,
    sha3_512 = 9,
    blake2b_256 = 10,
    blake2b_512 = 11,
    blake2s_128 = 12,
    blake2s_256 = 13,
    ripemd160 = 14,
    sm3 = 15,
    whirlpool = 16,
    crc32 = 17,
    crc32c = 18,
    xxhash64 = 19,
    // Zxyphor
    zxy_blake3 = 50,
    zxy_poseidon = 51,    // ZK-friendly hash
    zxy_rescue = 52,       // ZK-friendly hash
};

/// Hash algorithm properties
pub const HashAlgoInfo = struct {
    algo: HashAlgo,
    digest_size: u32,      // Output size in bytes
    block_size: u32,       // Internal block size
    name: [32]u8,
    // Flags
    hw_accel: bool,        // Hardware acceleration available
    zxy_simd: bool,        // SIMD optimized
};

/// Hash context for streaming computation
pub const HashContext = struct {
    algo: HashAlgo,
    state: [128]u8,        // Internal state (max)
    buffer: [256]u8,       // Pending bytes
    buffer_len: u32,
    total_len: u64,
    finalized: bool,
};

/// Well-known hash sizes
pub const HASH_MD5_SIZE: u32 = 16;
pub const HASH_SHA1_SIZE: u32 = 20;
pub const HASH_SHA256_SIZE: u32 = 32;
pub const HASH_SHA384_SIZE: u32 = 48;
pub const HASH_SHA512_SIZE: u32 = 64;
pub const HASH_SHA3_256_SIZE: u32 = 32;
pub const HASH_BLAKE2B_256_SIZE: u32 = 32;
pub const HASH_BLAKE2S_256_SIZE: u32 = 32;
pub const HASH_BLAKE3_SIZE: u32 = 32;
pub const HASH_SM3_SIZE: u32 = 32;

// ============================================================================
// Symmetric Ciphers
// ============================================================================

/// Cipher algorithm
pub const CipherAlgo = enum(u8) {
    aes = 0,
    des = 1,
    des3_ede = 2,
    blowfish = 3,
    twofish = 4,
    serpent = 5,
    camellia = 6,
    cast5 = 7,
    cast6 = 8,
    chacha20 = 9,
    sm4 = 10,
    aria = 11,
    // Zxyphor
    zxy_ascon = 50,
    zxy_speck128 = 51,    // Lightweight cipher
};

/// Cipher mode
pub const CipherMode = enum(u8) {
    ecb = 0,
    cbc = 1,
    ctr = 2,
    cfb = 3,
    ofb = 4,
    xts = 5,         // For disk encryption
    cts = 6,         // Ciphertext Stealing
    // Zxyphor
    zxy_wide_block = 50,
};

/// Cipher key size
pub const CipherKeySize = enum(u8) {
    bits_128 = 0,
    bits_192 = 1,
    bits_256 = 2,
    bits_512 = 3,
};

/// Cipher descriptor
pub const CipherDesc = struct {
    algo: CipherAlgo,
    mode: CipherMode,
    key_size: u32,          // In bytes
    block_size: u32,        // In bytes
    iv_size: u32,           // In bytes
    name: [64]u8,
    // Flags
    hw_accel: bool,
    zxy_aesni: bool,        // x86 AES-NI
    zxy_vaes: bool,         // AVX-512 VAES
};

/// Block cipher context
pub const CipherContext = struct {
    algo: CipherAlgo,
    mode: CipherMode,
    key: [64]u8,            // Max key size
    key_len: u32,
    iv: [32]u8,
    iv_len: u32,
    round_keys: [480]u8,    // Expanded key schedule (AES-256: 15*16 = 240)
    encrypting: bool,
};

// ============================================================================
// AEAD (Authenticated Encryption with Associated Data)
// ============================================================================

/// AEAD algorithm
pub const AeadAlgo = enum(u8) {
    aes_gcm = 0,
    aes_ccm = 1,
    chacha20_poly1305 = 2,
    aes_gcm_siv = 3,
    aes_siv = 4,
    aes_eax = 5,
    // Zxyphor
    zxy_xchacha20_poly1305 = 50,
    zxy_aegis256 = 51,
    zxy_ascon_aead = 52,
};

/// AEAD descriptor
pub const AeadDesc = struct {
    algo: AeadAlgo,
    key_size: u32,
    nonce_size: u32,
    tag_size: u32,
    max_aad_size: u32,
    name: [64]u8,
    hw_accel: bool,
};

/// AEAD context
pub const AeadContext = struct {
    algo: AeadAlgo,
    key: [64]u8,
    key_len: u32,
    nonce: [24]u8,
    nonce_len: u32,
    tag_len: u32,
};

// ============================================================================
// MAC (Message Authentication Code)
// ============================================================================

/// MAC algorithm
pub const MacAlgo = enum(u8) {
    hmac_md5 = 0,
    hmac_sha1 = 1,
    hmac_sha256 = 2,
    hmac_sha384 = 3,
    hmac_sha512 = 4,
    cmac_aes = 5,
    xcbc_aes = 6,
    vmac_aes = 7,
    poly1305 = 8,
    siphash_2_4 = 9,
    siphash_4_8 = 10,
    // Zxyphor
    zxy_blake3_mac = 50,
    zxy_kmac256 = 51,
};

/// MAC context
pub const MacContext = struct {
    algo: MacAlgo,
    key: [128]u8,
    key_len: u32,
    hash_ctx: HashContext,
    tag_len: u32,
};

// ============================================================================
// KDF (Key Derivation Functions)
// ============================================================================

/// KDF algorithm
pub const KdfAlgo = enum(u8) {
    hkdf_sha256 = 0,
    hkdf_sha512 = 1,
    pbkdf2_sha256 = 2,
    pbkdf2_sha512 = 3,
    scrypt = 4,
    argon2i = 5,
    argon2id = 6,
    // Zxyphor
    zxy_balloon_hash = 50,
    zxy_hkdf_blake3 = 51,
};

/// KDF parameters
pub const KdfParams = struct {
    algo: KdfAlgo,
    // HKDF
    salt: [64]u8,
    salt_len: u32,
    info: [256]u8,
    info_len: u32,
    // PBKDF2/Scrypt/Argon2
    iterations: u32,
    memory_cost_kb: u32,     // For scrypt/argon2
    parallelism: u32,        // For argon2
    output_len: u32,
};

// ============================================================================
// RNG (Random Number Generator)
// ============================================================================

/// RNG type
pub const RngType = enum(u8) {
    hw_rdrand = 0,          // Intel RDRAND
    hw_rdseed = 1,          // Intel RDSEED
    ctr_drbg = 2,           // CTR_DRBG (NIST SP 800-90A)
    hash_drbg = 3,          // Hash_DRBG
    hmac_drbg = 4,          // HMAC_DRBG
    jitter = 5,             // Jitter entropy
    // Zxyphor
    zxy_chacha20_rng = 50,
    zxy_combined = 51,       // Multi-source combined
};

/// RNG state
pub const RngState = struct {
    rng_type: RngType,
    state: [256]u8,
    state_size: u32,
    // Entropy tracking
    entropy_count: u32,      // Bits of entropy
    entropy_threshold: u32,  // Reseed threshold
    reseed_counter: u64,
    // Health
    total_generated: u64,
    total_reseeds: u64,
    last_reseed_time_ns: u64,
    health_failures: u32,
};

/// Entropy source
pub const EntropySource = enum(u8) {
    hardware = 0,           // RDRAND/RDSEED
    interrupt = 1,          // Interrupt timing
    disk = 2,               // Disk I/O timing
    input = 3,              // Input device timing
    jitter = 4,             // CPU jitter
    // Zxyphor
    zxy_combined = 50,
};

// ============================================================================
// Public Key Cryptography
// ============================================================================

/// Asymmetric algorithm
pub const AsymAlgo = enum(u8) {
    rsa = 0,
    dsa = 1,
    ecdsa = 2,
    ecdh = 3,
    ed25519 = 4,
    ed448 = 5,
    x25519 = 6,
    x448 = 7,
    sm2 = 8,
    // Post-quantum (Zxyphor)
    zxy_dilithium = 50,      // ML-DSA (FIPS 204)
    zxy_kyber = 51,          // ML-KEM (FIPS 203)
    zxy_falcon = 52,
    zxy_sphincs_plus = 53,   // SLH-DSA (FIPS 205)
};

/// Elliptic curve
pub const EcCurve = enum(u8) {
    secp256r1 = 0,       // P-256 / NIST P-256
    secp384r1 = 1,       // P-384
    secp521r1 = 2,       // P-521
    secp256k1 = 3,       // Bitcoin curve
    curve25519 = 4,
    curve448 = 5,
    brainpoolP256r1 = 6,
    brainpoolP384r1 = 7,
    sm2 = 8,
};

/// RSA key parameters
pub const RsaKeyParams = struct {
    modulus_bits: u32,       // 2048, 3072, 4096
    public_exponent: u32,    // Typically 65537
    padding: RsaPadding,
    hash_algo: HashAlgo,
};

/// RSA padding scheme
pub const RsaPadding = enum(u8) {
    pkcs1_v15 = 0,
    oaep = 1,
    pss = 2,
    raw = 3,
};

/// Key pair
pub const KeyPair = struct {
    algo: AsymAlgo,
    curve: EcCurve,             // For EC-based algos
    private_key: [512]u8,
    private_key_len: u32,
    public_key: [512]u8,
    public_key_len: u32,
    // Metadata
    created_time_ns: u64,
    usage_flags: KeyUsageFlags,
};

/// Key usage flags
pub const KeyUsageFlags = packed struct {
    sign: bool = false,
    verify: bool = false,
    encrypt: bool = false,
    decrypt: bool = false,
    key_agreement: bool = false,
    derive: bool = false,
    wrap: bool = false,
    unwrap: bool = false,
};

// ============================================================================
// Certificate Handling
// ============================================================================

/// X.509 version
pub const X509Version = enum(u8) {
    v1 = 0,
    v2 = 1,
    v3 = 2,
};

/// X.509 name (simplified)
pub const X509Name = struct {
    common_name: [256]u8,
    common_name_len: u16,
    organization: [256]u8,
    org_len: u16,
    country: [3]u8,
    state: [64]u8,
    state_len: u16,
};

/// Certificate verification result
pub const CertVerifyResult = enum(u8) {
    ok = 0,
    expired = 1,
    not_yet_valid = 2,
    revoked = 3,
    untrusted_root = 4,
    invalid_signature = 5,
    name_mismatch = 6,
    invalid_purpose = 7,
    chain_too_long = 8,
    unknown_critical_ext = 9,
    weak_algorithm = 10,
    // Zxyphor
    zxy_pq_migration_needed = 50,
};

// ============================================================================
// Crypto API Framework
// ============================================================================

/// Crypto API algorithm type
pub const CryptoAlgType = enum(u8) {
    cipher = 0,
    compress = 1,
    aead = 2,
    blkcipher = 3,
    ablkcipher = 4,
    skcipher = 5,
    hash = 6,
    shash = 7,
    ahash = 8,
    rng = 9,
    akcipher = 10,     // Asymmetric cipher
    kpp = 11,          // Key-agreement Protocol Primitive
    acomp = 12,        // Async compression
    scomp = 13,        // Sync compression
};

/// Algorithm flags
pub const CryptoAlgFlags = packed struct {
    kern_driver_only: bool = false,
    internal: bool = false,
    optional: bool = false,
    type_mask: bool = false,
    larval: bool = false,
    dead: bool = false,
    dying: bool = false,
    fips_compliant: bool = false,
    // Zxyphor
    zxy_hw_offload: bool = false,
    zxy_simd_fast: bool = false,
    zxy_pq_safe: bool = false,
    _padding: u5 = 0,
};

/// Registered algorithm
pub const CryptoAlgorithm = struct {
    name: [128]u8,
    driver_name: [128]u8,
    cra_type: CryptoAlgType,
    cra_flags: CryptoAlgFlags,
    cra_blocksize: u32,
    cra_ctxsize: u32,
    cra_alignmask: u32,
    cra_priority: u32,
    cra_refcnt: u32,
    // Stats
    encrypt_cnt: u64,
    encrypt_tlen: u64,
    decrypt_cnt: u64,
    decrypt_tlen: u64,
    err_cnt: u64,
};

/// Scatterlist for crypto operations
pub const CryptoScatterlist = struct {
    page_link: u64,
    offset: u32,
    length: u32,
};

/// Crypto request flags
pub const CryptoReqFlags = packed struct {
    may_sleep: bool = false,
    may_backlog: bool = false,
    need_fallback: bool = false,
    // Zxyphor
    zxy_hw_preferred: bool = false,
    zxy_urgent: bool = false,
    _padding: u3 = 0,
};

// ============================================================================
// Crypto Subsystem Manager
// ============================================================================

pub const CryptoSubsystem = struct {
    // Algorithms
    nr_algorithms: u32,
    nr_hash_algorithms: u32,
    nr_cipher_algorithms: u32,
    nr_aead_algorithms: u32,
    nr_rng_algorithms: u32,
    nr_akcipher_algorithms: u32,
    // Hardware
    nr_hw_engines: u32,
    hw_aesni_available: bool,
    hw_vaes_available: bool,
    hw_sha_ni_available: bool,
    hw_rdrand_available: bool,
    hw_rdseed_available: bool,
    // Stats
    total_encryptions: u64,
    total_decryptions: u64,
    total_hashes: u64,
    total_rng_bytes: u64,
    total_sign_ops: u64,
    total_verify_ops: u64,
    // Entropy
    entropy_available_bits: u32,
    // FIPS
    fips_mode: bool,
    // Zxyphor
    zxy_pq_ready: bool,
    zxy_hw_offload_active: bool,
    initialized: bool,

    pub fn init() CryptoSubsystem {
        return CryptoSubsystem{
            .nr_algorithms = 0,
            .nr_hash_algorithms = 0,
            .nr_cipher_algorithms = 0,
            .nr_aead_algorithms = 0,
            .nr_rng_algorithms = 0,
            .nr_akcipher_algorithms = 0,
            .nr_hw_engines = 0,
            .hw_aesni_available = false,
            .hw_vaes_available = false,
            .hw_sha_ni_available = false,
            .hw_rdrand_available = false,
            .hw_rdseed_available = false,
            .total_encryptions = 0,
            .total_decryptions = 0,
            .total_hashes = 0,
            .total_rng_bytes = 0,
            .total_sign_ops = 0,
            .total_verify_ops = 0,
            .entropy_available_bits = 0,
            .fips_mode = false,
            .zxy_pq_ready = false,
            .zxy_hw_offload_active = false,
            .initialized = false,
        };
    }
};
