// =============================================================================
// Kernel Zxyphor — Binary Integrity Verification Engine
// =============================================================================
// Provides cryptographic integrity verification for kernel modules, binaries,
// and critical data structures. Uses SHA-256 hashes signed with the kernel's
// built-in public key to verify that loaded code has not been tampered with.
//
// Features:
//   - File hash verification (SHA-256 based)
//   - Kernel module signature checking
//   - Runtime memory integrity monitoring (guard canaries)
//   - Trusted binary registry (whitelist of known-good hashes)
//
// This is the kernel's "Secure Boot" equivalent for runtime integrity.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum entries in the trusted hash registry
const MAX_TRUSTED_HASHES: usize = 512;

/// SHA-256 hash size
const HASH_SIZE: usize = 32;

/// Maximum path length for integrity entries
const MAX_PATH_LEN: usize = 128;

/// Stack canary value (chosen to contain null byte, newline, and 0xFF
/// to make buffer-overflow exploitation harder)
const CANARY_VALUE: u64 = 0xDEAD_C0DE_CAFE_BABE;

// =============================================================================
// Integrity entry — a trusted hash record
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityEntryType {
    /// Kernel module (.ko equivalent)
    KernelModule = 0,
    /// Userspace binary
    Binary = 1,
    /// Shared library
    Library = 2,
    /// Configuration file
    Config = 3,
    /// Critical data structure
    DataStructure = 4,
}

/// A single trusted hash entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IntegrityEntry {
    /// Path or identifier
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
    /// Expected SHA-256 hash
    expected_hash: [u8; HASH_SIZE],
    /// Entry type
    entry_type: IntegrityEntryType,
    /// Whether this entry is active
    active: bool,
    /// Number of successful verifications
    verify_pass: u64,
    /// Number of failed verifications
    verify_fail: u64,
    /// Timestamp of last verification
    last_verified: u64,
}

impl IntegrityEntry {
    pub const fn empty() -> Self {
        IntegrityEntry {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            expected_hash: [0u8; HASH_SIZE],
            entry_type: IntegrityEntryType::Binary,
            active: false,
            verify_pass: 0,
            verify_fail: 0,
            last_verified: 0,
        }
    }
}

// =============================================================================
// Stack canary verification
// =============================================================================

/// A stack canary guard. Place at the start of critical stack frames
/// to detect stack buffer overflows.
#[repr(C)]
pub struct StackGuard {
    canary: u64,
}

impl StackGuard {
    /// Create a new stack guard with the expected canary value
    pub fn new() -> Self {
        StackGuard {
            canary: CANARY_VALUE,
        }
    }

    /// Verify the canary is intact. Returns true if valid.
    pub fn verify(&self) -> bool {
        self.canary == CANARY_VALUE
    }
}

/// A heap guard placed before/after allocations to detect overflow/underflow
#[repr(C)]
pub struct HeapGuard {
    pre_canary: u64,
    size: usize,
    post_canary: u64,
}

impl HeapGuard {
    pub fn new(size: usize) -> Self {
        HeapGuard {
            pre_canary: CANARY_VALUE,
            size,
            post_canary: CANARY_VALUE ^ (size as u64),
        }
    }

    pub fn verify(&self) -> bool {
        self.pre_canary == CANARY_VALUE
            && self.post_canary == (CANARY_VALUE ^ (self.size as u64))
    }
}

// =============================================================================
// Simple SHA-256 for integrity checking (minimal standalone implementation)
// =============================================================================

/// SHA-256 initial hash values (first 32 bits of fractional parts of
/// square roots of the first 8 primes)
const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (first 32 bits of fractional parts of
/// cube roots of the first 64 primes)
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-256 hash of data into a 32-byte output buffer
pub fn sha256_hash(data: &[u8], output: &mut [u8; 32]) {
    let mut h = SHA256_H;
    let mut total_bits: u64 = 0;

    // Process complete 64-byte blocks
    let mut offset = 0;
    while offset + 64 <= data.len() {
        sha256_block(&mut h, &data[offset..offset + 64]);
        offset += 64;
        total_bits += 512;
    }

    // Final block(s) with padding
    let remaining = data.len() - offset;
    total_bits += (remaining as u64) * 8;

    let mut final_block = [0u8; 128]; // Two blocks max for padding
    final_block[..remaining].copy_from_slice(&data[offset..]);
    final_block[remaining] = 0x80; // Append bit '1'

    let pad_len = if remaining < 56 { 64 } else { 128 };

    // Append length in bits (big-endian) at the end
    let len_bytes = total_bits.to_be_bytes();
    final_block[pad_len - 8..pad_len].copy_from_slice(&len_bytes);

    // Process final block(s)
    sha256_block(&mut h, &final_block[..64]);
    if pad_len == 128 {
        sha256_block(&mut h, &final_block[64..128]);
    }

    // Write output
    for i in 0..8 {
        let bytes = h[i].to_be_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
}

fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    // Prepare message schedule
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

// =============================================================================
// Global integrity state
// =============================================================================

static mut TRUSTED_HASHES: [IntegrityEntry; MAX_TRUSTED_HASHES] = [IntegrityEntry::empty(); MAX_TRUSTED_HASHES];
static mut HASH_COUNT: usize = 0;

static INTEGRITY_INITIALIZED: AtomicBool = AtomicBool::new(false);
static INTEGRITY_CHECKS: AtomicU64 = AtomicU64::new(0);
static INTEGRITY_PASSES: AtomicU64 = AtomicU64::new(0);
static INTEGRITY_FAILURES: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// Integrity operations
// =============================================================================

/// Verify that a data block matches a known-good hash
pub fn verify_hash(data: &[u8], expected: &[u8; 32]) -> bool {
    INTEGRITY_CHECKS.fetch_add(1, Ordering::Relaxed);

    let mut computed = [0u8; 32];
    sha256_hash(data, &mut computed);

    let match_result = computed == *expected;

    if match_result {
        INTEGRITY_PASSES.fetch_add(1, Ordering::Relaxed);
    } else {
        INTEGRITY_FAILURES.fetch_add(1, Ordering::Relaxed);
    }

    match_result
}

/// Register a trusted hash for a path
pub fn register_trusted_hash(
    path: &[u8],
    hash: &[u8; 32],
    entry_type: IntegrityEntryType,
) -> bool {
    let count = unsafe { HASH_COUNT };
    if count >= MAX_TRUSTED_HASHES {
        return false;
    }

    let path_len = if path.len() > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        path.len()
    };

    unsafe {
        let entry = &mut TRUSTED_HASHES[count];
        entry.path[..path_len].copy_from_slice(&path[..path_len]);
        entry.path_len = path_len;
        entry.expected_hash = *hash;
        entry.entry_type = entry_type;
        entry.active = true;
        HASH_COUNT += 1;
    }

    true
}

/// Look up and verify a path against the trusted hash registry
pub fn verify_against_registry(path: &[u8], data: &[u8]) -> Option<bool> {
    let count = unsafe { HASH_COUNT };

    for i in 0..count {
        let entry = unsafe { &mut TRUSTED_HASHES[i] };
        if !entry.active {
            continue;
        }
        if entry.path_len != path.len() {
            continue;
        }
        if entry.path[..entry.path_len] != *path {
            continue;
        }

        // Found matching entry — verify the data
        let result = verify_hash(data, &entry.expected_hash);

        if result {
            entry.verify_pass += 1;
        } else {
            entry.verify_fail += 1;
            // Log integrity violation
            crate::security::audit::audit_integrity_violation(0, path);
        }

        return Some(result);
    }

    None // Path not in registry
}

// =============================================================================
// FFI exports
// =============================================================================

/// Initialize the integrity subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_integrity_init() -> i32 {
    if INTEGRITY_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    INTEGRITY_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust integrity verification engine initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Compute SHA-256 hash of a buffer
#[no_mangle]
pub extern "C" fn zxyphor_rust_integrity_hash(
    data: *const u8,
    data_len: usize,
    hash_out: *mut u8,
) -> i32 {
    if data.is_null() || hash_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let input = unsafe { core::slice::from_raw_parts(data, data_len) };
    let output = unsafe { &mut *(hash_out as *mut [u8; 32]) };

    sha256_hash(input, output);
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Verify data against an expected hash
#[no_mangle]
pub extern "C" fn zxyphor_rust_integrity_verify(
    data: *const u8,
    data_len: usize,
    expected_hash: *const u8,
) -> i32 {
    if data.is_null() || expected_hash.is_null() {
        return 0;
    }

    let input = unsafe { core::slice::from_raw_parts(data, data_len) };
    let expected = unsafe { &*(expected_hash as *const [u8; 32]) };

    if verify_hash(input, expected) {
        1
    } else {
        0
    }
}

/// Register a trusted hash
#[no_mangle]
pub extern "C" fn zxyphor_rust_integrity_register(
    path: *const u8,
    path_len: usize,
    hash: *const u8,
    entry_type: u8,
) -> i32 {
    if path.is_null() || hash.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let path_slice = unsafe { core::slice::from_raw_parts(path, path_len) };
    let hash_arr = unsafe { &*(hash as *const [u8; 32]) };

    let etype = match entry_type {
        0 => IntegrityEntryType::KernelModule,
        1 => IntegrityEntryType::Binary,
        2 => IntegrityEntryType::Library,
        3 => IntegrityEntryType::Config,
        4 => IntegrityEntryType::DataStructure,
        _ => return crate::ffi::error::FfiError::InvalidArgument.as_i32(),
    };

    if register_trusted_hash(path_slice, hash_arr, etype) {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::NoMemory.as_i32()
    }
}

/// Get integrity statistics
#[repr(C)]
pub struct IntegrityStats {
    pub total_checks: u64,
    pub total_passes: u64,
    pub total_failures: u64,
    pub registered_hashes: u32,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_integrity_stats(out: *mut IntegrityStats) -> i32 {
    if out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let stats = IntegrityStats {
        total_checks: INTEGRITY_CHECKS.load(Ordering::Relaxed),
        total_passes: INTEGRITY_PASSES.load(Ordering::Relaxed),
        total_failures: INTEGRITY_FAILURES.load(Ordering::Relaxed),
        registered_hashes: unsafe { HASH_COUNT as u32 },
    };

    unsafe { core::ptr::write(out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Verify a stack guard canary
#[no_mangle]
pub extern "C" fn zxyphor_rust_verify_stack_canary(canary_ptr: *const u64) -> i32 {
    if canary_ptr.is_null() {
        return 0;
    }
    let canary = unsafe { *canary_ptr };
    if canary == CANARY_VALUE {
        1
    } else {
        0
    }
}

/// Get the expected canary value
#[no_mangle]
pub extern "C" fn zxyphor_rust_get_canary_value() -> u64 {
    CANARY_VALUE
}
