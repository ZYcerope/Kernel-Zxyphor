// SPDX-License-Identifier: GPL-2.0
//! Zxyphor Kernel - Rust Hash/Cipher/AEAD/KDF Detail
//! Algorithm registration, template instantiation, crypto_alg,
//! scatter-walk, hardware acceleration detection

#![allow(dead_code)]

// ============================================================================
// Crypto Algorithm Type
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgType {
    Cipher = 0,
    Compress = 1,
    Aead = 3,
    Skcipher = 5,
    Hash = 8,
    Shash = 10,
    Ahash = 11,
    Rng = 12,
    Akcipher = 13,
    Sig = 14,
    Kpp = 15,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgFlags {
    None = 0,
    NeedFallback = 1 << 0,
    Async = 1 << 2,
    OptionalKey = 1 << 5,
    Internal = 1 << 11,
    Dead = 1 << 12,
    Dying = 1 << 13,
    AllocFailed = 1 << 14,
    Tested = 1 << 15,
    Instance = 1 << 16,
    KernDriver = 1 << 17,
}

// ============================================================================
// Crypto Algorithm Registration
// ============================================================================

#[repr(C)]
pub struct CryptoAlg {
    pub cra_name: [u8; 128],
    pub cra_driver_name: [u8; 128],
    pub cra_flags: u32,
    pub cra_blocksize: u32,
    pub cra_ctxsize: u32,
    pub cra_alignmask: u32,
    pub cra_priority: i32,
    pub cra_refcnt: u32,
    pub cra_type: CryptoAlgType,
    pub cra_module: u64,
    pub cra_init: u64,
    pub cra_exit: u64,
    pub cra_destroy: u64,
}

// ============================================================================
// Hash (shash / ahash)
// ============================================================================

#[repr(C)]
pub struct ShashAlg {
    pub init: u64,      // fn(*ShashDesc) -> i32
    pub update: u64,    // fn(*ShashDesc, &[u8], u32) -> i32
    pub final_fn: u64,  // fn(*ShashDesc, &mut [u8]) -> i32
    pub finup: u64,     // fn(*ShashDesc, &[u8], u32, &mut [u8]) -> i32
    pub digest: u64,    // fn(*ShashDesc, &[u8], u32, &mut [u8]) -> i32
    pub export: u64,
    pub import: u64,
    pub setkey: u64,
    pub init_tfm: u64,
    pub exit_tfm: u64,
    pub clone_tfm: u64,
    pub digestsize: u32,
    pub statesize: u32,
    pub descsize: u32,
    pub base: CryptoAlg,
}

#[repr(C)]
pub struct ShashDesc {
    pub tfm: u64,       // struct crypto_shash *
    pub flags: u32,
    // __ctx follows (variable size)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha3_224 = 6,
    Sha3_256 = 7,
    Sha3_384 = 8,
    Sha3_512 = 9,
    Blake2b256 = 10,
    Blake2b512 = 11,
    Sm3 = 12,
    Xxhash64 = 13,
    Crc32 = 14,
    Crc32c = 15,
    Poly1305 = 16,
    Ghash = 17,
    Cmac = 18,
    Hmac = 19,
    Siphash = 20,
}

#[repr(C)]
#[derive(Debug)]
pub struct HashDigestSize {
    pub md5: u32,        // 16
    pub sha1: u32,       // 20
    pub sha224: u32,     // 28
    pub sha256: u32,     // 32
    pub sha384: u32,     // 48
    pub sha512: u32,     // 64
    pub sha3_256: u32,   // 32
    pub sha3_512: u32,   // 64
    pub blake2b_256: u32, // 32
    pub blake2b_512: u32, // 64
    pub sm3: u32,         // 32
    pub poly1305: u32,    // 16
}

impl Default for HashDigestSize {
    fn default() -> Self {
        Self {
            md5: 16,
            sha1: 20,
            sha224: 28,
            sha256: 32,
            sha384: 48,
            sha512: 64,
            sha3_256: 32,
            sha3_512: 64,
            blake2b_256: 32,
            blake2b_512: 64,
            sm3: 32,
            poly1305: 16,
        }
    }
}

// ============================================================================
// Symmetric Cipher (skcipher)
// ============================================================================

#[repr(C)]
pub struct SkcipherAlg {
    pub setkey: u64,
    pub encrypt: u64,
    pub decrypt: u64,
    pub init: u64,
    pub exit: u64,
    pub min_keysize: u32,
    pub max_keysize: u32,
    pub ivsize: u32,
    pub chunksize: u32,
    pub walksize: u32,
    pub base: CryptoAlg,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    AesCbc = 0,
    AesCtr = 1,
    AesXts = 2,
    AesEcb = 3,
    AesCfb = 4,
    AesOfb = 5,
    AesGcm = 6,
    AesCcm = 7,
    Chacha20 = 8,
    Chacha20Poly1305 = 9,
    Xchacha20Poly1305 = 10,
    Camellia = 11,
    Sm4 = 12,
    Twofish = 13,
    Serpent = 14,
    Blowfish = 15,
    AesCtsCbc = 16,
    AesEssiv = 17,
    AesHctr2 = 18,
    Adiantum = 19,
}

#[repr(C)]
#[derive(Debug)]
pub struct CipherKeySize {
    pub aes_128: u32,
    pub aes_192: u32,
    pub aes_256: u32,
    pub chacha20: u32,
    pub sm4: u32,
    pub twofish_max: u32,
    pub serpent_max: u32,
}

impl Default for CipherKeySize {
    fn default() -> Self {
        Self {
            aes_128: 16,
            aes_192: 24,
            aes_256: 32,
            chacha20: 32,
            sm4: 16,
            twofish_max: 32,
            serpent_max: 32,
        }
    }
}

// ============================================================================
// AEAD (Authenticated Encryption with Associated Data)
// ============================================================================

#[repr(C)]
pub struct AeadAlg {
    pub setkey: u64,
    pub setauthsize: u64,
    pub encrypt: u64,
    pub decrypt: u64,
    pub init: u64,
    pub exit: u64,
    pub ivsize: u32,
    pub maxauthsize: u32,
    pub chunksize: u32,
    pub base: CryptoAlg,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    AesGcm = 0,
    AesCcm = 1,
    AesGcmRfc4106 = 2, // IPsec ESP
    AesCcmRfc4309 = 3, // IPsec ESP
    Chacha20Poly1305 = 4,
    Rfc7539 = 5,        // ChaCha20-Poly1305 IETF
    AesGcmSiv = 6,
    AesSiv = 7,
    Aegis128 = 8,
    Aegis256 = 9,
    Morus1280 = 10,
}

// ============================================================================
// KDF (Key Derivation Functions)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfType {
    HkdfSha256 = 0,
    HkdfSha512 = 1,
    Pbkdf2HmacSha256 = 2,
    Pbkdf2HmacSha512 = 3,
    Argon2i = 4,
    Argon2d = 5,
    Argon2id = 6,
    Scrypt = 7,
    Sp800108CtrHmacSha256 = 8,
}

#[repr(C)]
#[derive(Debug)]
pub struct HkdfParams {
    pub hash: HashAlgorithm,
    pub ikm: [u8; 256],
    pub ikm_len: u32,
    pub salt: [u8; 128],
    pub salt_len: u32,
    pub info: [u8; 256],
    pub info_len: u32,
    pub okm_len: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct Pbkdf2Params {
    pub hash: HashAlgorithm,
    pub password: [u8; 256],
    pub password_len: u32,
    pub salt: [u8; 128],
    pub salt_len: u32,
    pub iterations: u32,
    pub dk_len: u32,
}

// ============================================================================
// Hardware Acceleration
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwAccelType {
    None = 0,
    AesNi = 1,          // x86 AES-NI
    Avx2 = 2,           // x86 AVX2
    Avx512 = 3,         // x86 AVX-512
    Vaes = 4,           // x86 VAES
    ArmNeon = 5,        // ARM NEON
    ArmCe = 6,          // ARM Cryptographic Extensions
    ArmSha = 7,         // ARM SHA extensions
    ArmSve2 = 8,        // ARM SVE2
    PpcVmx = 9,         // POWER VMX
    S390Cpacf = 10,     // IBM z CPACF
    RiscvZkn = 11,      // RISC-V Zkn
}

#[repr(C)]
#[derive(Debug)]
pub struct HwAccelCaps {
    pub aes_ni: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub vaes: bool,
    pub vpclmulqdq: bool,
    pub pclmulqdq: bool,
    pub sha_ni: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub adx: bool,
    pub gfni: bool,
}

impl HwAccelCaps {
    pub fn detect() -> Self {
        // In production, this checks CPUID
        Self {
            aes_ni: false,
            avx: false,
            avx2: false,
            avx512: false,
            vaes: false,
            vpclmulqdq: false,
            pclmulqdq: false,
            sha_ni: false,
            bmi1: false,
            bmi2: false,
            adx: false,
            gfni: false,
        }
    }
}

// ============================================================================
// Scatter Walk
// ============================================================================

#[repr(C)]
pub struct ScatterWalk {
    pub sg: u64,          // scatterlist *
    pub offset: u32,
    pub page_link: u64,
    pub length: u32,
}

#[repr(C)]
pub struct SkcipherWalk {
    pub src: ScatterWalk,
    pub dst: ScatterWalk,
    pub iv: [u8; 16],
    pub oiv: [u8; 16],
    pub total: u32,
    pub nbytes: u32,
    pub flags: u32,
}

// ============================================================================
// Crypto Template
// ============================================================================

#[repr(C)]
pub struct CryptoTemplate {
    pub name: [u8; 128],
    pub create: u64,     // fn(*CryptoTemplate, &[u8]) -> i32
    pub module: u64,
    pub instances: u32,
}

#[repr(C)]
pub struct CryptoInstance {
    pub alg: CryptoAlg,
    pub tmpl: u64,       // *CryptoTemplate
    pub spawns: u64,
}

// ============================================================================
// Crypto Manager
// ============================================================================

#[derive(Debug)]
pub struct CryptoDetailManager {
    pub registered_algs: u32,
    pub hash_algs: u32,
    pub cipher_algs: u32,
    pub aead_algs: u32,
    pub rng_algs: u32,
    pub akcipher_algs: u32,
    pub kpp_algs: u32,
    pub templates: u32,
    pub instances: u32,
    // Operations
    pub total_encryptions: u64,
    pub total_decryptions: u64,
    pub total_hashes: u64,
    pub total_signatures: u64,
    pub total_key_agreements: u64,
    // Hardware
    pub hw_accel: HwAccelCaps,
    pub hw_operations: u64,
    pub sw_fallback_operations: u64,
    // Errors
    pub alloc_failures: u64,
    pub operation_errors: u64,
    pub test_failures: u64,
    pub initialized: bool,
}

impl CryptoDetailManager {
    pub fn new() -> Self {
        Self {
            registered_algs: 0,
            hash_algs: 0,
            cipher_algs: 0,
            aead_algs: 0,
            rng_algs: 0,
            akcipher_algs: 0,
            kpp_algs: 0,
            templates: 0,
            instances: 0,
            total_encryptions: 0,
            total_decryptions: 0,
            total_hashes: 0,
            total_signatures: 0,
            total_key_agreements: 0,
            hw_accel: HwAccelCaps::detect(),
            hw_operations: 0,
            sw_fallback_operations: 0,
            alloc_failures: 0,
            operation_errors: 0,
            test_failures: 0,
            initialized: true,
        }
    }
}
