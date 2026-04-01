// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Cryptographic HMAC and KDF
//
// Implements:
// - HMAC-SHA256 (RFC 2104)
// - HKDF (RFC 5869) — Extract-and-Expand
// - PBKDF2-HMAC-SHA256 (RFC 2898)
// - Constant-time comparison
// - Secure key derivation helpers

#![no_std]
#![allow(dead_code)]

// ─────────────────── SHA-256 Core (inline for HMAC) ─────────────────
const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_DIGEST_SIZE: usize = 32;

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // Fill buffer
        if self.buf_len > 0 {
            let space = SHA256_BLOCK_SIZE - self.buf_len;
            let copy = data.len().min(space);
            self.buffer[self.buf_len..self.buf_len + copy].copy_from_slice(&data[..copy]);
            self.buf_len += copy;
            offset = copy;

            if self.buf_len == SHA256_BLOCK_SIZE {
                let block = self.buffer;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + SHA256_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SHA256_BLOCK_SIZE]);
            self.compress(&block);
            offset += SHA256_BLOCK_SIZE;
        }

        // Buffer remainder
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
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

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finalize(mut self) -> [u8; SHA256_DIGEST_SIZE] {
        let bit_len = self.total_len * 8;
        // Padding
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            // Need extra block
            for i in self.buf_len..SHA256_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buf_len = 0;
        }

        for i in self.buf_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut digest = [0u8; SHA256_DIGEST_SIZE];
        for i in 0..8 {
            digest[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }
}

/// Compute SHA-256 hash
fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

// ─────────────────── HMAC-SHA256 ────────────────────────────────────
pub struct HmacSha256 {
    inner: Sha256,
    outer_key_pad: [u8; SHA256_BLOCK_SIZE],
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance with the given key
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; SHA256_BLOCK_SIZE];

        // If key is longer than block size, hash it first
        if key.len() > SHA256_BLOCK_SIZE {
            let hashed = sha256(key);
            key_block[..SHA256_DIGEST_SIZE].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Inner key pad = key XOR 0x36
        let mut inner_key_pad = [0u8; SHA256_BLOCK_SIZE];
        for i in 0..SHA256_BLOCK_SIZE {
            inner_key_pad[i] = key_block[i] ^ 0x36;
        }

        // Outer key pad = key XOR 0x5c
        let mut outer_key_pad = [0u8; SHA256_BLOCK_SIZE];
        for i in 0..SHA256_BLOCK_SIZE {
            outer_key_pad[i] = key_block[i] ^ 0x5c;
        }

        // Start inner hash
        let mut inner = Sha256::new();
        inner.update(&inner_key_pad);

        // Zero out key material from stack
        for b in key_block.iter_mut() {
            *b = 0;
        }
        for b in inner_key_pad.iter_mut() {
            *b = 0;
        }

        Self {
            inner,
            outer_key_pad,
        }
    }

    /// Update the HMAC with more data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the HMAC digest
    pub fn finalize(self) -> [u8; SHA256_DIGEST_SIZE] {
        let inner_digest = self.inner.finalize();

        // Outer hash: H(outer_key_pad || inner_digest)
        let mut outer = Sha256::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_digest);
        outer.finalize()
    }

    /// One-shot HMAC computation
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
        let mut hmac = Self::new(key);
        hmac.update(data);
        hmac.finalize()
    }

    /// Verify an HMAC tag (constant-time comparison)
    pub fn verify(key: &[u8], data: &[u8], expected: &[u8; SHA256_DIGEST_SIZE]) -> bool {
        let computed = Self::mac(key, data);
        ct_eq(&computed, expected)
    }
}

// ─────────────────── HKDF (RFC 5869) ───────────────────────────────
pub struct Hkdf;

impl Hkdf {
    /// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
        let actual_salt = if salt.is_empty() {
            &[0u8; SHA256_DIGEST_SIZE] as &[u8]
        } else {
            salt
        };
        HmacSha256::mac(actual_salt, ikm)
    }

    /// HKDF-Expand: OKM = T(1) || T(2) || ... || T(N)
    /// where T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
    pub fn expand(prk: &[u8; SHA256_DIGEST_SIZE], info: &[u8], okm: &mut [u8]) -> bool {
        let n = (okm.len() + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
        if n > 255 {
            return false; // OKM too long
        }

        let mut t = [0u8; SHA256_DIGEST_SIZE];
        let mut offset = 0;

        for i in 1..=n {
            let mut hmac = HmacSha256::new(prk);
            if i > 1 {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[i as u8]);
            t = hmac.finalize();

            let copy_len = (okm.len() - offset).min(SHA256_DIGEST_SIZE);
            okm[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
            offset += copy_len;
        }

        true
    }

    /// Combined Extract-and-Expand
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, okm)
    }
}

// ─────────────────── PBKDF2-HMAC-SHA256 (RFC 2898) ─────────────────
pub struct Pbkdf2;

impl Pbkdf2 {
    /// Derive a key from a password with PBKDF2-HMAC-SHA256
    ///
    /// Recommended minimum iterations: 600,000 (OWASP 2023)
    /// For kernel use with time constraints, at least 10,000
    pub fn derive(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        dk: &mut [u8],
    ) -> bool {
        if iterations == 0 || dk.is_empty() {
            return false;
        }

        let dk_len = dk.len();
        let blocks = (dk_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
        let mut offset = 0;

        for block_idx in 1..=blocks {
            let mut u = Self::prf(password, salt, block_idx as u32);
            let mut result = u;

            for _ in 1..iterations {
                u = HmacSha256::mac(password, &u);
                for j in 0..SHA256_DIGEST_SIZE {
                    result[j] ^= u[j];
                }
            }

            let copy_len = (dk_len - offset).min(SHA256_DIGEST_SIZE);
            dk[offset..offset + copy_len].copy_from_slice(&result[..copy_len]);
            offset += copy_len;
        }

        true
    }

    /// F(Password, Salt, c, i) = U1 where U1 = PRF(Password, Salt || INT(i))
    fn prf(password: &[u8], salt: &[u8], block_idx: u32) -> [u8; SHA256_DIGEST_SIZE] {
        let mut hmac = HmacSha256::new(password);
        hmac.update(salt);
        hmac.update(&block_idx.to_be_bytes());
        hmac.finalize()
    }
}

// ─────────────────── Key Wrap (simplified AES-KW-like) ──────────────
/// Simple key wrapping using HMAC for integrity
pub struct KeyWrap;

impl KeyWrap {
    pub const OVERHEAD: usize = SHA256_DIGEST_SIZE; // MAC tag

    /// Wrap a key: output = data || HMAC(kek, data)
    /// Output must be data.len() + OVERHEAD bytes
    pub fn wrap(kek: &[u8], data: &[u8], output: &mut [u8]) -> bool {
        let needed = data.len() + Self::OVERHEAD;
        if output.len() < needed {
            return false;
        }
        output[..data.len()].copy_from_slice(data);
        let tag = HmacSha256::mac(kek, data);
        output[data.len()..needed].copy_from_slice(&tag);
        true
    }

    /// Unwrap a key: verify HMAC, return data
    /// Input must be at least OVERHEAD bytes
    pub fn unwrap(kek: &[u8], wrapped: &[u8], output: &mut [u8]) -> bool {
        if wrapped.len() < Self::OVERHEAD {
            return false;
        }
        let data_len = wrapped.len() - Self::OVERHEAD;
        if output.len() < data_len {
            return false;
        }
        let data = &wrapped[..data_len];
        let tag = &wrapped[data_len..];

        // Verify tag
        let expected = HmacSha256::mac(kek, data);
        if !ct_eq(&expected, tag.try_into().unwrap_or(&[0u8; 32])) {
            return false;
        }

        output[..data_len].copy_from_slice(data);
        true
    }
}

// ─────────────────── Secure Random Key Generation ───────────────────
/// Generate a derived key from seed material and context
pub fn derive_key(
    seed: &[u8],
    context: &[u8],
    key_out: &mut [u8],
) -> bool {
    Hkdf::derive(b"zxyphor-kernel-v1", seed, context, key_out)
}

/// Derive a session key from master key + session ID
pub fn derive_session_key(
    master_key: &[u8; 32],
    session_id: &[u8],
    key_out: &mut [u8; 32],
) -> bool {
    let mut info = [0u8; 128];
    let prefix = b"session-key:";
    let plen = prefix.len();
    info[..plen].copy_from_slice(prefix);
    let slen = session_id.len().min(128 - plen);
    info[plen..plen + slen].copy_from_slice(&session_id[..slen]);

    Hkdf::expand(master_key, &info[..plen + slen], key_out)
}

// ─────────────────── Constant-Time Comparison ───────────────────────
/// Compare two byte slices in constant time
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time conditional select: if cond { a } else { b }
pub fn ct_select(cond: bool, a: u8, b: u8) -> u8 {
    let mask = if cond { 0xFF } else { 0x00 };
    (a & mask) | (b & !mask)
}

// ─────────────────── Secure Memory Operations ───────────────────────
/// Securely zero memory (prevent compiler from optimizing away)
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b as *mut u8, 0);
        }
    }
}

/// Securely zero a fixed-size array
pub fn secure_zero_32(buf: &mut [u8; 32]) {
    for b in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b as *mut u8, 0);
        }
    }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_hmac_sha256(
    key_ptr: *const u8,
    key_len: u32,
    data_ptr: *const u8,
    data_len: u32,
    out_ptr: *mut u8,
) {
    if key_ptr.is_null() || data_ptr.is_null() || out_ptr.is_null() {
        return;
    }
    let key = unsafe { core::slice::from_raw_parts(key_ptr, key_len as usize) };
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    let digest = HmacSha256::mac(key, data);
    unsafe {
        core::ptr::copy_nonoverlapping(digest.as_ptr(), out_ptr, SHA256_DIGEST_SIZE);
    }
}

#[no_mangle]
pub extern "C" fn rust_hkdf_derive(
    salt_ptr: *const u8,
    salt_len: u32,
    ikm_ptr: *const u8,
    ikm_len: u32,
    info_ptr: *const u8,
    info_len: u32,
    okm_ptr: *mut u8,
    okm_len: u32,
) -> bool {
    if ikm_ptr.is_null() || okm_ptr.is_null() {
        return false;
    }
    let salt = if salt_ptr.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(salt_ptr, salt_len as usize) }
    };
    let ikm = unsafe { core::slice::from_raw_parts(ikm_ptr, ikm_len as usize) };
    let info = if info_ptr.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(info_ptr, info_len as usize) }
    };
    let okm = unsafe { core::slice::from_raw_parts_mut(okm_ptr, okm_len as usize) };
    Hkdf::derive(salt, ikm, info, okm)
}

#[no_mangle]
pub extern "C" fn rust_pbkdf2_sha256(
    pass_ptr: *const u8,
    pass_len: u32,
    salt_ptr: *const u8,
    salt_len: u32,
    iterations: u32,
    dk_ptr: *mut u8,
    dk_len: u32,
) -> bool {
    if pass_ptr.is_null() || salt_ptr.is_null() || dk_ptr.is_null() {
        return false;
    }
    let password = unsafe { core::slice::from_raw_parts(pass_ptr, pass_len as usize) };
    let salt = unsafe { core::slice::from_raw_parts(salt_ptr, salt_len as usize) };
    let dk = unsafe { core::slice::from_raw_parts_mut(dk_ptr, dk_len as usize) };
    Pbkdf2::derive(password, salt, iterations, dk)
}

#[no_mangle]
pub extern "C" fn rust_hmac_verify(
    key_ptr: *const u8,
    key_len: u32,
    data_ptr: *const u8,
    data_len: u32,
    tag_ptr: *const u8,
) -> bool {
    if key_ptr.is_null() || data_ptr.is_null() || tag_ptr.is_null() {
        return false;
    }
    let key = unsafe { core::slice::from_raw_parts(key_ptr, key_len as usize) };
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    let tag: &[u8; 32] = unsafe { &*(tag_ptr as *const [u8; 32]) };
    HmacSha256::verify(key, data, tag)
}

#[no_mangle]
pub extern "C" fn rust_secure_zero(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, len as usize) };
    secure_zero(buf);
}
