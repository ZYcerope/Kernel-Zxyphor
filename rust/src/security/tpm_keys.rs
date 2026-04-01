// Zxyphor Kernel - TPM Interface, Trusted Keys, Encrypted Keys,
// Hardware Security Modules, PKCS#7/CMS, Key Retention Service,
// Module Signature Verification, Secure Boot Chain
// More advanced than Linux 2026 security key management

use core::fmt;

// ============================================================================
// TPM (Trusted Platform Module)
// ============================================================================

/// TPM version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmVersion {
    Tpm12 = 1,
    Tpm20 = 2,
}

/// TPM2 command codes (most common)
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Tpm2CommandCode {
    NvUndefineSpace = 0x0122,
    NvDefineSpace = 0x012A,
    CreatePrimary = 0x0131,
    NvWrite = 0x0137,
    NvWriteLock = 0x0138,
    SelfTest = 0x0143,
    Startup = 0x0144,
    Shutdown = 0x0145,
    NvRead = 0x014E,
    Create = 0x0153,
    Load = 0x0157,
    Unseal = 0x015E,
    ContextSave = 0x0162,
    ContextLoad = 0x0161,
    FlushContext = 0x0165,
    ReadPublic = 0x0173,
    StartAuthSession = 0x0176,
    GetCapability = 0x017A,
    GetRandom = 0x017B,
    PcrExtend = 0x0182,
    PcrRead = 0x017E,
    PolicyPCR = 0x017F,
    PolicySecret = 0x0151,
    PolicyGetDigest = 0x0189,
    EvictControl = 0x0120,
    Certify = 0x0148,
    Hash = 0x017D,
    Sign = 0x015D,
    VerifySignature = 0x0177,
    NvReadPublic = 0x0169,
    Import = 0x0156,
}

/// TPM2 algorithm IDs
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Tpm2AlgId {
    Error = 0x0000,
    Rsa = 0x0001,
    Sha1 = 0x0004,
    Hmac = 0x0005,
    Aes = 0x0006,
    Mgf1 = 0x0007,
    KeyedHash = 0x0008,
    Xor = 0x000A,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Null = 0x0010,
    Sm3 = 0x0012,
    Sm4 = 0x0013,
    RsaSsa = 0x0014,
    RsaEs = 0x0015,
    RsaPss = 0x0016,
    Oaep = 0x0017,
    Ecdsa = 0x0018,
    Ecdh = 0x0019,
    Ecdaa = 0x001A,
    EcSchnorr = 0x001C,
    Kdf1Sp800108 = 0x0022,
    Kdf2 = 0x0021,
    Ecc = 0x0023,
    SymCipher = 0x0025,
    Camellia = 0x0026,
    Sha3_256 = 0x0027,
    Sha3_384 = 0x0028,
    Sha3_512 = 0x0029,
    Ctr = 0x0040,
    Ofb = 0x0041,
    Cbc = 0x0042,
    Cfb = 0x0043,
    Ecb = 0x0044,
}

/// TPM2 ECC curves
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Tpm2EccCurve {
    None = 0x0000,
    NistP192 = 0x0001,
    NistP224 = 0x0002,
    NistP256 = 0x0003,
    NistP384 = 0x0004,
    NistP521 = 0x0005,
    Bn256 = 0x0010,
    Bn638 = 0x0011,
    Sm2P256 = 0x0020,
}

/// TPM2 session type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Tpm2SessionType {
    Hmac = 0x00,
    Policy = 0x01,
    Trial = 0x03,
}

/// TPM2 startup type
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Tpm2StartupType {
    Clear = 0x0000,
    State = 0x0001,
}

/// TPM2 NV attributes
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Tpm2NvAttributes(pub u32);

impl Tpm2NvAttributes {
    pub const PPWRITE: Self = Self(1 << 0);
    pub const OWNERWRITE: Self = Self(1 << 1);
    pub const AUTHWRITE: Self = Self(1 << 2);
    pub const POLICYWRITE: Self = Self(1 << 3);
    pub const POLICY_DELETE: Self = Self(1 << 10);
    pub const WRITELOCKED: Self = Self(1 << 11);
    pub const WRITEALL: Self = Self(1 << 12);
    pub const WRITEDEFINE: Self = Self(1 << 13);
    pub const WRITE_STCLEAR: Self = Self(1 << 14);
    pub const GLOBALLOCK: Self = Self(1 << 15);
    pub const PPREAD: Self = Self(1 << 16);
    pub const OWNERREAD: Self = Self(1 << 17);
    pub const AUTHREAD: Self = Self(1 << 18);
    pub const POLICYREAD: Self = Self(1 << 19);
    pub const NO_DA: Self = Self(1 << 25);
    pub const ORDERLY: Self = Self(1 << 26);
    pub const CLEAR_STCLEAR: Self = Self(1 << 27);
    pub const READLOCKED: Self = Self(1 << 28);
    pub const WRITTEN: Self = Self(1 << 29);
    pub const PLATFORMCREATE: Self = Self(1 << 30);
    pub const READ_STCLEAR: Self = Self(1 << 31);
}

/// TPM chip info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TpmChipInfo {
    pub version: TpmVersion,
    pub manufacturer_id: u32,
    pub vendor_string: [u8; 32],
    pub vendor_string_len: u8,
    pub firmware_version_major: u16,
    pub firmware_version_minor: u16,
    // PCR banks
    pub nr_pcr_banks: u8,
    pub pcr_bank_algs: [Tpm2AlgId; 8],
    pub nr_pcrs: u32,
    // NV
    pub nv_total_size: u64,
    pub nv_used_size: u64,
    // Algorithms
    pub nr_algs: u16,
    // Properties
    pub max_auth_size: u16,
    pub max_nv_buffer: u16,
    // Zxyphor
    pub zxy_remote_attestation: bool,
}

// ============================================================================
// Trusted Keys
// ============================================================================

/// Trusted key blob structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TrustedKeyBlob {
    pub blob_len: u32,
    pub blob: [u8; 4096],
    // Sealing policy
    pub pcr_info: TrustedKeyPcrInfo,
    // Migration
    pub migratable: bool,
}

/// PCR policy for trusted keys
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TrustedKeyPcrInfo {
    pub pcr_selection: u32,     // Bitmask of PCRs
    pub digest_alg: Tpm2AlgId,
    pub digest: [u8; 64],
    pub digest_len: u8,
}

/// Trusted key options
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TrustedKeyOptions {
    pub key_len: u32,            // Key length in bytes
    pub hash_alg: Tpm2AlgId,
    pub pcr_lock: u32,           // PCR bitmask to seal to
    pub parent_handle: u32,      // TPM parent key handle
    pub policydigest_len: u32,
    pub policydigest: [u8; 64],
    pub migratable: bool,
}

// ============================================================================
// Encrypted Keys
// ============================================================================

/// Encrypted key format
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EncryptedKeyFormat {
    Default = 0,         // Kernel-generated master key
    Ecryptfs = 1,
    Enc32 = 2,
}

/// Encrypted key master description
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EncryptedKeyMasterType {
    Trusted = 0,         // Master is trusted key
    User = 1,            // Master is user key
}

/// Encrypted key options
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EncryptedKeyOptions {
    pub format: EncryptedKeyFormat,
    pub master_type: EncryptedKeyMasterType,
    pub master_desc: [u8; 128],
    pub master_desc_len: u8,
    pub key_len: u32,
    pub datablob_len: u32,
}

// ============================================================================
// PKCS#7 / CMS
// ============================================================================

/// PKCS#7 content type
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Pkcs7ContentType {
    Data = 0,
    SignedData = 1,
    EnvelopedData = 2,
    SignedAndEnvelopedData = 3,
    DigestedData = 4,
    EncryptedData = 5,
}

/// PKCS#7 signer info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Pkcs7SignerInfo {
    pub issuer: [u8; 256],
    pub issuer_len: u16,
    pub serial_number: [u8; 32],
    pub serial_len: u8,
    pub digest_alg: [u8; 32],
    pub digest_alg_len: u8,
    pub signature_alg: [u8; 32],
    pub sig_alg_len: u8,
    pub authenticated_attrs: bool,
    pub signing_time: i64,
}

/// PKCS#7 verification result
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Pkcs7VerifyResult {
    Ok = 0,
    InvalidSignature = 1,
    CertNotFound = 2,
    CertExpired = 3,
    CertRevoked = 4,
    DigestMismatch = 5,
    UntrustedCert = 6,
    InvalidFormat = 7,
}

// ============================================================================
// Module Signature Verification
// ============================================================================

/// Module signature info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ModuleSigInfo {
    pub algo: ModuleSigAlgo,
    pub hash: ModuleSigHash,
    pub id_type: ModuleSigIdType,
    pub signer_len: u8,
    pub key_id_len: u8,
    pub sig_len: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ModuleSigAlgo {
    Pkcs1RsaPadding = 0,
    RsaPss = 1,
    Ecdsa = 2,
    // Zxyphor PQ
    ZxyDilithium = 10,
    ZxySphincsSha2 = 11,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ModuleSigHash {
    Sha1 = 0,
    Sha224 = 1,
    Sha256 = 2,
    Sha384 = 3,
    Sha512 = 4,
    Sha3_256 = 5,
    Sha3_384 = 6,
    Sha3_512 = 7,
    Sm3 = 8,
    Streebog256 = 9,
    Streebog512 = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ModuleSigIdType {
    Pkcs7 = 0,
    X509 = 1,
}

/// Module signature footer magic
pub const MODULE_SIG_STRING: &[u8] = b"~Module signature appended~\n";

// ============================================================================
// Secure Boot Chain
// ============================================================================

/// Secure boot state
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SecureBootState {
    Disabled = 0,
    Enabled = 1,
    SetupMode = 2,
    AuditMode = 3,
    DeployedMode = 4,
}

/// UEFI Secure Boot variables
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum SecureBootVar {
    Pk = 0,           // Platform Key
    Kek = 1,          // Key Exchange Key
    Db = 2,           // Signature Database
    Dbx = 3,          // Forbidden Signature Database
    Dbt = 4,          // Timestamp Database
    Dbr = 5,          // Recovery Database
    Mokx = 6,         // Machine Owner Key Blacklist
}

/// MOK (Machine Owner Key) info
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MokKeyInfo {
    pub hash_algo: [u8; 16],
    pub hash: [u8; 64],
    pub hash_len: u8,
    pub enrolled: bool,
    pub trusted: bool,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

#[repr(C)]
pub struct SecurityKeySubsystem {
    // TPM
    pub tpm_present: bool,
    pub tpm_version: TpmVersion,
    pub nr_tpm_operations: u64,
    pub nr_pcr_extends: u64,
    // Trusted keys
    pub nr_trusted_keys: u64,
    // Encrypted keys
    pub nr_encrypted_keys: u64,
    // PKCS#7
    pub nr_pkcs7_verifications: u64,
    pub nr_pkcs7_failures: u64,
    // Module signatures
    pub nr_modules_verified: u64,
    pub nr_module_sig_failures: u64,
    pub module_sig_enforce: bool,
    // Secure Boot
    pub secure_boot_state: SecureBootState,
    // Zxyphor
    pub zxy_remote_attestation: bool,
    pub zxy_pq_signatures: bool,
    pub initialized: bool,
}

impl SecurityKeySubsystem {
    pub const fn new() -> Self {
        Self {
            tpm_present: false,
            tpm_version: TpmVersion::Tpm20,
            nr_tpm_operations: 0,
            nr_pcr_extends: 0,
            nr_trusted_keys: 0,
            nr_encrypted_keys: 0,
            nr_pkcs7_verifications: 0,
            nr_pkcs7_failures: 0,
            nr_modules_verified: 0,
            nr_module_sig_failures: 0,
            module_sig_enforce: true,
            secure_boot_state: SecureBootState::Disabled,
            zxy_remote_attestation: true,
            zxy_pq_signatures: true,
            initialized: false,
        }
    }
}
