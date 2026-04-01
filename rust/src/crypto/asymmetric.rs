// Zxyphor Kernel - Rust Asymmetric Cryptography,
// Key Rings Extended, Certificate Verification,
// PKCS#7 / CMS, X.509 Certificate Parsing,
// Kernel Key Retention Service Extended,
// Signing / Signature Verification,
// Post-Quantum Crypto Framework
// SPDX-License-Identifier: GPL-2.0

/// Asymmetric key type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsymKeyType {
    Rsa = 0,
    Dsa = 1,
    Ecdsa = 2,
    Ed25519 = 3,
    Ed448 = 4,
    Sm2 = 5,
    X25519 = 6,
    X448 = 7,
    // Post-quantum
    Dilithium2 = 20,
    Dilithium3 = 21,
    Dilithium5 = 22,
    Falcon512 = 23,
    Falcon1024 = 24,
    Sphincs128f = 25,
    Sphincs256f = 26,
    KyberKem512 = 30,
    KyberKem768 = 31,
    KyberKem1024 = 32,
    // Zxyphor hybrid
    ZxyHybridRsaDilithium = 100,
    ZxyHybridEcdsaFalcon = 101,
}

/// RSA key parameters
#[derive(Debug, Clone)]
pub struct RsaKeyParams {
    pub key_size: u32,         // bits (2048, 3072, 4096, 8192)
    pub public_exponent: u64,  // typically 65537
    pub padding: RsaPadding,
    pub hash_algo: HashAlgorithm,
    pub mgf_hash: HashAlgorithm,
    pub salt_length: u32,       // for PSS
}

impl Default for RsaKeyParams {
    fn default() -> Self {
        Self {
            key_size: 4096,
            public_exponent: 65537,
            padding: RsaPadding::Pkcs1V15,
            hash_algo: HashAlgorithm::Sha256,
            mgf_hash: HashAlgorithm::Sha256,
            salt_length: 32,
        }
    }
}

/// RSA padding scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RsaPadding {
    Pkcs1V15 = 0,
    Oaep = 1,        // PKCS#1 v2.1 OAEP
    Pss = 2,         // PKCS#1 v2.1 PSS
    Raw = 3,         // no padding
}

/// ECDSA curve
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EccCurve {
    NistP192 = 0,
    NistP224 = 1,
    NistP256 = 2,
    NistP384 = 3,
    NistP521 = 4,
    Secp256k1 = 5,     // Bitcoin curve
    BrainpoolP256r1 = 6,
    BrainpoolP384r1 = 7,
    BrainpoolP512r1 = 8,
    Sm2 = 9,            // Chinese standard
    // Zxyphor
    ZxyCurve512 = 100,
}

/// Hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Md5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha3_256 = 6,
    Sha3_384 = 7,
    Sha3_512 = 8,
    Sm3 = 9,
    Blake2b256 = 10,
    Blake2b512 = 11,
    Blake3 = 12,
    Ripemd160 = 13,
    Whirlpool = 14,
    // Zxyphor
    ZxyHash512 = 100,
}

// ============================================================================
// X.509 Certificate
// ============================================================================

/// X.509 certificate version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum X509Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

/// X.509 key usage flags
#[derive(Debug, Clone, Copy)]
pub struct X509KeyUsage {
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl Default for X509KeyUsage {
    fn default() -> Self {
        Self {
            digital_signature: false,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }
}

/// X.509 extended key usage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum X509ExtKeyUsage {
    ServerAuth = 0,
    ClientAuth = 1,
    CodeSigning = 2,
    EmailProtection = 3,
    TimeStamping = 4,
    OcspSigning = 5,
    // Kernel specific
    ModuleSigning = 10,
    KexecSigning = 11,
    FirmwareSigning = 12,
}

/// X.509 certificate descriptor
#[derive(Debug, Clone)]
pub struct X509CertDesc {
    pub version: X509Version,
    pub serial_number: [u8; 20],
    pub serial_len: u8,
    pub issuer: [u8; 256],
    pub issuer_len: u16,
    pub subject: [u8; 256],
    pub subject_len: u16,
    pub not_before: i64,          // seconds since epoch
    pub not_after: i64,
    pub key_type: AsymKeyType,
    pub sig_algo: AsymKeyType,
    pub sig_hash: HashAlgorithm,
    pub key_usage: X509KeyUsage,
    pub is_ca: bool,
    pub path_len_constraint: i32,  // -1 = no constraint
    pub self_signed: bool,
    pub valid: bool,
    pub fingerprint_sha256: [u8; 32],
    // Subject Key Identifier
    pub ski: [u8; 20],
    pub ski_len: u8,
    // Authority Key Identifier
    pub aki: [u8; 20],
    pub aki_len: u8,
}

impl Default for X509CertDesc {
    fn default() -> Self {
        Self {
            version: X509Version::V3,
            serial_number: [0u8; 20],
            serial_len: 0,
            issuer: [0u8; 256],
            issuer_len: 0,
            subject: [0u8; 256],
            subject_len: 0,
            not_before: 0,
            not_after: 0,
            key_type: AsymKeyType::Rsa,
            sig_algo: AsymKeyType::Rsa,
            sig_hash: HashAlgorithm::Sha256,
            key_usage: X509KeyUsage::default(),
            is_ca: false,
            path_len_constraint: -1,
            self_signed: false,
            valid: false,
            fingerprint_sha256: [0u8; 32],
            ski: [0u8; 20],
            ski_len: 0,
            aki: [0u8; 20],
            aki_len: 0,
        }
    }
}

// ============================================================================
// PKCS#7 / CMS
// ============================================================================

/// PKCS#7 content type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Pkcs7ContentType {
    Data = 0,
    SignedData = 1,
    EnvelopedData = 2,
    DigestedData = 3,
    EncryptedData = 4,
    AuthenticatedData = 5,
}

/// PKCS#7 signer info
#[derive(Debug, Clone)]
pub struct Pkcs7SignerInfo {
    pub version: u32,
    pub issuer: [u8; 256],
    pub issuer_len: u16,
    pub serial_number: [u8; 20],
    pub serial_len: u8,
    pub digest_algo: HashAlgorithm,
    pub sig_algo: AsymKeyType,
    pub authenticated_attrs: bool,
    pub signing_time: i64,
    pub content_type_present: bool,
}

impl Default for Pkcs7SignerInfo {
    fn default() -> Self {
        Self {
            version: 1,
            issuer: [0u8; 256],
            issuer_len: 0,
            serial_number: [0u8; 20],
            serial_len: 0,
            digest_algo: HashAlgorithm::Sha256,
            sig_algo: AsymKeyType::Rsa,
            authenticated_attrs: false,
            signing_time: 0,
            content_type_present: false,
        }
    }
}

/// PKCS#7 verification flags
#[derive(Debug, Clone, Copy)]
pub struct Pkcs7VerifyFlags {
    pub check_trust: bool,
    pub check_chain: bool,
    pub check_date: bool,
    pub check_blacklist: bool,
    pub check_key_usage: bool,
    /// Accept only trusted keys
    pub trusted_only: bool,
}

impl Default for Pkcs7VerifyFlags {
    fn default() -> Self {
        Self {
            check_trust: true,
            check_chain: true,
            check_date: true,
            check_blacklist: true,
            check_key_usage: true,
            trusted_only: true,
        }
    }
}

// ============================================================================
// Kernel Key Retention Service Extended
// ============================================================================

/// Key type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyringKeyType {
    User = 0,
    Logon = 1,
    BigKey = 2,
    Keyring = 3,
    AsymmetricKey = 4,
    DnsResolver = 5,
    Encrypted = 6,
    Trusted = 7,
    IdMapping = 8,
    // Zxyphor
    ZxyHybrid = 100,
}

/// Key permission bits
#[derive(Debug, Clone, Copy)]
pub struct KeyPerm {
    // Possessor permissions
    pub poss_view: bool,
    pub poss_read: bool,
    pub poss_write: bool,
    pub poss_search: bool,
    pub poss_link: bool,
    pub poss_setattr: bool,
    // User permissions
    pub usr_view: bool,
    pub usr_read: bool,
    pub usr_write: bool,
    pub usr_search: bool,
    pub usr_link: bool,
    pub usr_setattr: bool,
    // Group permissions
    pub grp_view: bool,
    pub grp_read: bool,
    pub grp_write: bool,
    pub grp_search: bool,
    pub grp_link: bool,
    pub grp_setattr: bool,
    // Other permissions
    pub oth_view: bool,
    pub oth_read: bool,
    pub oth_write: bool,
    pub oth_search: bool,
    pub oth_link: bool,
    pub oth_setattr: bool,
}

impl Default for KeyPerm {
    fn default() -> Self {
        Self {
            poss_view: true, poss_read: true, poss_write: false,
            poss_search: true, poss_link: false, poss_setattr: false,
            usr_view: true, usr_read: true, usr_write: false,
            usr_search: true, usr_link: false, usr_setattr: false,
            grp_view: false, grp_read: false, grp_write: false,
            grp_search: false, grp_link: false, grp_setattr: false,
            oth_view: false, oth_read: false, oth_write: false,
            oth_search: false, oth_link: false, oth_setattr: false,
        }
    }
}

/// Key descriptor
#[derive(Debug, Clone)]
pub struct KeyDesc {
    pub serial: u32,
    pub key_type: KeyringKeyType,
    pub description: [u8; 256],
    pub desc_len: u16,
    pub uid: u32,
    pub gid: u32,
    pub perm: KeyPerm,
    pub expiry: i64,          // 0 = no expiry
    pub data_len: u32,
    pub flags: KeyFlags,
}

impl Default for KeyDesc {
    fn default() -> Self {
        Self {
            serial: 0,
            key_type: KeyringKeyType::User,
            description: [0u8; 256],
            desc_len: 0,
            uid: 0,
            gid: 0,
            perm: KeyPerm::default(),
            expiry: 0,
            data_len: 0,
            flags: KeyFlags::default(),
        }
    }
}

/// Key flags
#[derive(Debug, Clone, Copy)]
pub struct KeyFlags {
    pub dead: bool,
    pub revoked: bool,
    pub in_quota: bool,
    pub user_construct: bool,
    pub negative: bool,
    pub invalidated: bool,
    pub builtin: bool,
    pub uid_keyring: bool,
    pub keep: bool,
}

impl Default for KeyFlags {
    fn default() -> Self {
        Self {
            dead: false, revoked: false, in_quota: true,
            user_construct: false, negative: false, invalidated: false,
            builtin: false, uid_keyring: false, keep: false,
        }
    }
}

/// Well-known keyring IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SpecialKeyring {
    ThreadKeyring = -1,
    ProcessKeyring = -2,
    SessionKeyring = -3,
    UserKeyring = -4,
    UserSessionKeyring = -5,
    GroupKeyring = -6,
    ReqKeyAuthKey = -7,
}

// ============================================================================
// Post-Quantum Crypto Framework (Zxyphor)
// ============================================================================

/// Post-quantum security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PqSecurityLevel {
    Level1 = 1,    // ~AES-128
    Level2 = 2,    // ~SHA-256
    Level3 = 3,    // ~AES-192
    Level4 = 4,    // ~SHA-384
    Level5 = 5,    // ~AES-256
}

/// Post-quantum KEM parameters
#[derive(Debug, Clone, Copy)]
pub struct PqKemParams {
    pub algorithm: AsymKeyType,
    pub security_level: PqSecurityLevel,
    pub public_key_size: u32,
    pub secret_key_size: u32,
    pub ciphertext_size: u32,
    pub shared_secret_size: u32,
}

impl Default for PqKemParams {
    fn default() -> Self {
        Self {
            algorithm: AsymKeyType::KyberKem768,
            security_level: PqSecurityLevel::Level3,
            public_key_size: 1184,
            secret_key_size: 2400,
            ciphertext_size: 1088,
            shared_secret_size: 32,
        }
    }
}

/// Post-quantum signature parameters
#[derive(Debug, Clone, Copy)]
pub struct PqSigParams {
    pub algorithm: AsymKeyType,
    pub security_level: PqSecurityLevel,
    pub public_key_size: u32,
    pub secret_key_size: u32,
    pub signature_size: u32,
}

impl Default for PqSigParams {
    fn default() -> Self {
        Self {
            algorithm: AsymKeyType::Dilithium3,
            security_level: PqSecurityLevel::Level3,
            public_key_size: 1952,
            secret_key_size: 4000,
            signature_size: 3293,
        }
    }
}

// ============================================================================
// Crypto Asymmetric Subsystem Manager
// ============================================================================

#[derive(Debug, Clone)]
pub struct CryptoAsymSubsystem {
    pub nr_rsa_keys: u32,
    pub nr_ecdsa_keys: u32,
    pub nr_ed25519_keys: u32,
    pub nr_pq_keys: u32,
    pub nr_certificates: u32,
    pub nr_keyrings: u32,
    pub nr_pkcs7_verified: u64,
    pub module_signing_key: AsymKeyType,
    pub secure_boot_key: AsymKeyType,
    pub pq_enabled: bool,
    pub initialized: bool,
}

impl Default for CryptoAsymSubsystem {
    fn default() -> Self {
        Self {
            nr_rsa_keys: 0,
            nr_ecdsa_keys: 0,
            nr_ed25519_keys: 0,
            nr_pq_keys: 0,
            nr_certificates: 0,
            nr_keyrings: 0,
            nr_pkcs7_verified: 0,
            module_signing_key: AsymKeyType::Rsa,
            secure_boot_key: AsymKeyType::Rsa,
            pq_enabled: false,
            initialized: false,
        }
    }
}

impl CryptoAsymSubsystem {
    pub fn init() -> Self {
        Self {
            initialized: true,
            ..Default::default()
        }
    }
}
