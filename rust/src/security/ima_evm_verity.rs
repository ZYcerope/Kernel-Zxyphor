// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Rust Security IMA/EVM/Integrity Advanced
// Integrity Measurement Architecture (IMA), Extended Verification Module,
// dm-verity, fs-verity, secure boot chain, PKCS#7, X.509 certstore

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// IMA (Integrity Measurement Architecture)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImaAction {
    DontMeasure = 0,
    Measure = 1,
    DontAppraise = 2,
    Appraise = 3,
    Audit = 4,
    Hash = 5,
    DontHash = 6,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImaHook {
    FileCheck = 1,
    MmapCheck = 2,
    BprmCheck = 3,
    CrdsCheck = 4,
    PostSetattr = 5,
    ModuleCheck = 6,
    FirmwareCheck = 7,
    KexecKernelCheck = 8,
    KexecInitramfsCheck = 9,
    PolicyCheck = 10,
    KexecCmdline = 11,
    KeyCheck = 12,
    CriticalData = 13,
    SetxattrCheck = 14,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImaHashAlgo {
    Md5 = 0,
    Sha1 = 1,
    Ripemd160 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Sha224 = 6,
    Sha512_256 = 7,
    Sm3_256 = 8,
    Streebog_256 = 9,
    Streebog_512 = 10,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ImaDigest {
    pub algo: ImaHashAlgo,
    pub length: u32,
    pub digest: [u8; 64],  // Max SHA-512
}

#[repr(C)]
pub struct ImaPcrEvent {
    pub pcr: u32,           // PCR index (default: 10)
    pub digest: ImaDigest,
    pub template_name: [u8; 16],
    pub template_data_len: u32,
    pub template_data: [u8; 512],
}

#[repr(C)]
pub struct ImaPolicy {
    pub action: ImaAction,
    pub hook: ImaHook,
    pub mask: u32,
    pub uid: u32,
    pub gid: u32,
    pub fowner: u32,
    pub fgroup: u32,
    pub fsuuid: [u8; 16],
    pub lsm_rules: [u64; 8],  // LSM-specific rule pointers
    pub flags: ImaRuleFlags,
    pub func: u32,
    pub keyrings: [u8; 64],
    pub label: [u8; 64],
    pub algo: ImaHashAlgo,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImaRuleFlags {
    bits: u32,
}

impl ImaRuleFlags {
    pub const IMA_FUNC: u32 = 0x0001;
    pub const IMA_MASK: u32 = 0x0002;
    pub const IMA_FSMAGIC: u32 = 0x0004;
    pub const IMA_UID: u32 = 0x0008;
    pub const IMA_FOWNER: u32 = 0x0010;
    pub const IMA_FSUUID: u32 = 0x0020;
    pub const IMA_INMASK: u32 = 0x0040;
    pub const IMA_EUID: u32 = 0x0080;
    pub const IMA_PCR: u32 = 0x0100;
    pub const IMA_FSNAME: u32 = 0x0200;
    pub const IMA_KEYRINGS: u32 = 0x0400;
    pub const IMA_LABEL: u32 = 0x0800;
    pub const IMA_VALIDATE_ALGOS: u32 = 0x1000;
    pub const IMA_GID: u32 = 0x2000;
    pub const IMA_FGROUP: u32 = 0x4000;
}

// ============================================================================
// EVM (Extended Verification Module)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvmImaXattrType {
    EvmXattrHmac = 0x01,
    EvmXattrPortableSig = 0x02,
    ImaXattrDigest = 0x03,
    ImaXattrDigestNg = 0x04,
    EvmImaXattrDiglist = 0x05,
}

#[repr(C)]
pub struct EvmImaXattrData {
    pub xattr_type: EvmImaXattrType,
    pub data: [u8; 256],
    pub data_len: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvmSetupMode {
    Uninitialized = 0,
    SetupComplete = 1,
    PermPassing = 2,
}

#[repr(C)]
pub struct EvmConfig {
    pub setup_mode: EvmSetupMode,
    pub evm_initialized: bool,
    pub evm_hmac_attrs: EvmHmacAttrs,
    pub evm_key_loaded: bool,
    pub evm_key: [u8; 32],   // HMAC key (256-bit)
    pub evm_hash_algo: ImaHashAlgo,
    pub evm_immutable: bool,
    pub evm_fixmode: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EvmHmacAttrs {
    bits: u32,
}

impl EvmHmacAttrs {
    pub const INODE_UID: u32 = 1 << 0;
    pub const INODE_GID: u32 = 1 << 1;
    pub const INODE_MODE: u32 = 1 << 2;
    pub const SECURITY_SELINUX: u32 = 1 << 3;
    pub const SECURITY_SMACK: u32 = 1 << 4;
    pub const SECURITY_APPARMOR: u32 = 1 << 5;
    pub const SECURITY_IMA: u32 = 1 << 6;
    pub const SECURITY_EVM: u32 = 1 << 7;
    pub const SECURITY_CAPS: u32 = 1 << 8;
    pub const INODE_I_VERSION: u32 = 1 << 9;
}

// ============================================================================
// dm-verity
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmVerityMode {
    Enforcing = 0,
    Logging = 1,
    Restart = 2,
    Panic = 3,
}

#[repr(C)]
pub struct DmVerityTarget {
    pub version: u32,
    pub data_dev: [u8; 64],
    pub hash_dev: [u8; 64],
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub hash_start: u64,
    pub algorithm: ImaHashAlgo,
    pub digest_size: u32,
    pub root_digest: [u8; 64],
    pub salt: [u8; 64],
    pub salt_size: u32,
    pub mode: DmVerityMode,
    pub validated: bool,
    pub corruption_detected: bool,
    pub hash_level_block: [u64; 64],
    pub levels: u32,
    pub fec_dev: [u8; 64],
    pub fec_start: u64,
    pub fec_blocks: u64,
    pub fec_roots: u32,
    pub fec_rsn: u32,
    pub use_fec: bool,
}

#[repr(C)]
pub struct DmVerityIoInfo {
    pub block: u64,
    pub n_blocks: u64,
    pub hash_verified: bool,
    pub fec_needed: bool,
    pub error: i32,
}

// ============================================================================
// fs-verity
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FsVerityHashAlgorithm {
    Sha256 = 1,
    Sha512 = 2,
}

#[repr(C)]
pub struct FsVerityEnableArg {
    pub version: u32,
    pub hash_algorithm: FsVerityHashAlgorithm,
    pub block_size: u32,
    pub salt_size: u32,
    pub salt_ptr: u64,
    pub sig_size: u32,
    pub sig_ptr: u64,
    pub reserved: [u64; 11],
}

#[repr(C)]
pub struct FsVerityDescriptor {
    pub version: u8,
    pub hash_algorithm: u8,
    pub log_blocksize: u8,
    pub salt_size: u8,
    pub reserved1: u32,
    pub data_size: u64,
    pub root_hash: [u8; 64],
    pub salt: [u8; 32],
    pub reserved2: [u8; 144],
}

#[repr(C)]
pub struct FsVerityDigest {
    pub digest_algorithm: FsVerityHashAlgorithm,
    pub digest_size: u16,
    pub digest: [u8; 64],
}

#[repr(C)]
pub struct MerkleTreeParams {
    pub hash_algorithm: FsVerityHashAlgorithm,
    pub log_blocksize: u8,
    pub block_size: u32,
    pub digest_size: u32,
    pub log_arity: u32,     // Log2 of hashes per block
    pub hashes_per_block: u32,
    pub num_levels: u32,
    pub tree_size: u64,
    pub level_start: [u64; 8],
    pub tree_pages: u64,
}

// ============================================================================
// X.509 Certificate Store
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    Rsa = 0,
    Dsa = 1,
    Ecdsa = 2,
    Ed25519 = 3,
    Ed448 = 4,
    Sm2 = 5,
}

#[repr(C)]
pub struct X509Certificate {
    pub raw_serial: [u8; 32],
    pub raw_serial_size: u32,
    pub raw_issuer: [u8; 256],
    pub raw_issuer_size: u32,
    pub raw_subject: [u8; 256],
    pub raw_subject_size: u32,
    pub fingerprint: [u8; 32],   // SHA-256 fingerprint
    pub authority: [u8; 32],     // Authority key ID
    pub pub_key_type: KeyType,
    pub pub_key: [u8; 512],
    pub pub_key_size: u32,
    pub signature: [u8; 512],
    pub sig_size: u32,
    pub sig_hash_algo: ImaHashAlgo,
    pub valid_from: u64,         // Epoch timestamp
    pub valid_to: u64,
    pub is_ca: bool,
    pub path_len_constraint: i32,
    pub key_usage: X509KeyUsage,
    pub unsupported_key: bool,
    pub unsupported_sig: bool,
    pub blacklisted: bool,
    pub self_signed: bool,
    pub verified: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct X509KeyUsage {
    bits: u16,
}

impl X509KeyUsage {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const CONTENT_COMMITMENT: u16 = 1 << 1;
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    pub const DATA_ENCIPHERMENT: u16 = 1 << 3;
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
    pub const ENCIPHER_ONLY: u16 = 1 << 7;
    pub const DECIPHER_ONLY: u16 = 1 << 8;
}

// ============================================================================
// PKCS#7
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pkcs7VerifyUsage {
    Unspecified = 0,
    ModuleSig = 1,
    FirmwareLoaded = 2,
    KexecImageSig = 3,
}

#[repr(C)]
pub struct Pkcs7Message {
    pub version: u32,
    pub data: u64,
    pub data_len: u32,
    pub data_hdrlen: u32,
    pub content_type: [u8; 16],  // OID
    pub certs: [u64; 16],       // Certificate pointers
    pub crl: [u64; 8],
    pub signed_infos: [u64; 8],
    pub nr_certs: u32,
    pub nr_crls: u32,
    pub nr_signed_infos: u32,
    pub unsupported_crypto: bool,
}

// ============================================================================
// Keyring & Key Management
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyringType {
    SystemKeyring = 0,
    SystemTrustedKeyring = 1,
    SecondaryTrustedKeyring = 2,
    PlatformKeyring = 3,
    ImaKeyring = 4,
    MachineKeyring = 5,
}

#[repr(C)]
pub struct KeyPermissions {
    bits: u32,
}

impl KeyPermissions {
    pub const KEY_POS_VIEW: u32 = 0x01000000;
    pub const KEY_POS_READ: u32 = 0x02000000;
    pub const KEY_POS_WRITE: u32 = 0x04000000;
    pub const KEY_POS_SEARCH: u32 = 0x08000000;
    pub const KEY_POS_LINK: u32 = 0x10000000;
    pub const KEY_POS_SETATTR: u32 = 0x20000000;
    pub const KEY_USR_VIEW: u32 = 0x00010000;
    pub const KEY_USR_READ: u32 = 0x00020000;
    pub const KEY_USR_WRITE: u32 = 0x00040000;
    pub const KEY_USR_SEARCH: u32 = 0x00080000;
    pub const KEY_USR_LINK: u32 = 0x00100000;
    pub const KEY_USR_SETATTR: u32 = 0x00200000;
    pub const KEY_GRP_VIEW: u32 = 0x00000100;
    pub const KEY_GRP_READ: u32 = 0x00000200;
    pub const KEY_OTH_VIEW: u32 = 0x00000001;
    pub const KEY_OTH_READ: u32 = 0x00000002;
}

#[repr(C)]
pub struct KeyStruct {
    pub serial: u32,
    pub key_type: [u8; 32],
    pub description: [u8; 256],
    pub perm: KeyPermissions,
    pub uid: u32,
    pub gid: u32,
    pub payload_len: u32,
    pub expiry: u64,
    pub flags: u32,
    pub usage: u32,
    pub quotalen: u16,
}

// ============================================================================
// Secure Boot
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecureBootMode {
    Unknown = 0,
    Disabled = 1,
    Enabled = 2,
}

#[repr(C)]
pub struct SecureBootState {
    pub mode: SecureBootMode,
    pub setup_mode: bool,
    pub mok_enrolled: bool,
    pub lockdown_lsm: bool,
    pub platform_certs_loaded: u32,
    pub mok_certs_loaded: u32,
    pub db_certs_loaded: u32,
    pub dbx_entries_loaded: u32,
}

// ============================================================================
// Manager
// ============================================================================

pub struct ImaEvmIntegrityManager {
    pub total_measurements: AtomicU64,
    pub total_appraisals: AtomicU64,
    pub total_appraisal_failures: AtomicU64,
    pub total_audits: AtomicU64,
    pub total_evm_checks: AtomicU64,
    pub total_evm_failures: AtomicU64,
    pub total_verity_reads: AtomicU64,
    pub total_verity_errors: AtomicU64,
    pub total_fsverity_files: AtomicU64,
    pub total_certs_verified: AtomicU64,
    pub total_sig_verified: AtomicU64,
    pub total_sig_failed: AtomicU64,
    pub secure_boot: SecureBootState,
    pub initialized: bool,
}

impl ImaEvmIntegrityManager {
    pub const fn new() Self {
        Self {
            total_measurements: AtomicU64::new(0),
            total_appraisals: AtomicU64::new(0),
            total_appraisal_failures: AtomicU64::new(0),
            total_audits: AtomicU64::new(0),
            total_evm_checks: AtomicU64::new(0),
            total_evm_failures: AtomicU64::new(0),
            total_verity_reads: AtomicU64::new(0),
            total_verity_errors: AtomicU64::new(0),
            total_fsverity_files: AtomicU64::new(0),
            total_certs_verified: AtomicU64::new(0),
            total_sig_verified: AtomicU64::new(0),
            total_sig_failed: AtomicU64::new(0),
            secure_boot: SecureBootState {
                mode: SecureBootMode::Unknown,
                setup_mode: false,
                mok_enrolled: false,
                lockdown_lsm: false,
                platform_certs_loaded: 0,
                mok_certs_loaded: 0,
                db_certs_loaded: 0,
                dbx_entries_loaded: 0,
            },
            initialized: true,
        }
    }
}
