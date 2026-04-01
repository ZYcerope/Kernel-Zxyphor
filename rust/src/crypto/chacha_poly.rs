//! Kernel Zxyphor — ChaCha20-Poly1305 AEAD Cipher
//!
//! High-performance authenticated encryption implementation:
//! - ChaCha20 stream cipher (RFC 8439)
//! - Poly1305 MAC (RFC 8439)
//! - ChaCha20-Poly1305 AEAD construction
//! - XChaCha20 extended-nonce variant (192-bit nonce)
//! - Constant-time operations for side-channel resistance
//! - Key derivation via HChaCha20

#![no_std]
#![allow(dead_code)]

use core::convert::TryInto;

// ============================================================================
// ChaCha20 Stream Cipher
// ============================================================================

/// ChaCha20 state: 16 × u32 words.
pub struct ChaCha20 {
    state: [u32; 16],
}

/// The ChaCha20 constants: "expand 32-byte k".
const CHACHA_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

impl ChaCha20 {
    /// Create a ChaCha20 instance from a 256-bit key and 96-bit nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];

        // Constants
        state[0] = CHACHA_CONSTANTS[0];
        state[1] = CHACHA_CONSTANTS[1];
        state[2] = CHACHA_CONSTANTS[2];
        state[3] = CHACHA_CONSTANTS[3];

        // Key
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
        }

        // Counter
        state[12] = counter;

        // Nonce
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
        }

        ChaCha20 { state }
    }

    /// Quarter round operation on four state words.
    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Perform 20 rounds (10 double rounds) and produce a 64-byte block.
    fn block(&self) -> [u8; 64] {
        let mut working = self.state;

        // 20 rounds = 10 double rounds
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        // Add original state
        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
        }

        // Serialize to bytes (little-endian)
        let mut output = [0u8; 64];
        for i in 0..16 {
            let bytes = working[i].to_le_bytes();
            output[4 * i..4 * i + 4].copy_from_slice(&bytes);
        }

        output
    }

    /// Encrypt/decrypt data in place (XOR with keystream).
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let block = self.block();
            let remaining = data.len() - offset;
            let to_xor = if remaining < 64 { remaining } else { 64 };

            for i in 0..to_xor {
                data[offset + i] ^= block[i];
            }

            offset += to_xor;
            self.state[12] = self.state[12].wrapping_add(1);
        }
    }

    /// Generate keystream bytes (for Poly1305 key generation).
    pub fn keystream(&mut self, out: &mut [u8]) {
        let mut offset = 0;
        while offset < out.len() {
            let block = self.block();
            let remaining = out.len() - offset;
            let to_copy = if remaining < 64 { remaining } else { 64 };

            out[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);

            offset += to_copy;
            self.state[12] = self.state[12].wrapping_add(1);
        }
    }
}

// ============================================================================
// HChaCha20 (for XChaCha20)
// ============================================================================

/// HChaCha20 produces a 256-bit output from a key and 128-bit input.
/// Used for XChaCha20 extended nonce construction.
pub fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];

    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];

    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }

    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(input[4 * i..4 * i + 4].try_into().unwrap());
    }

    // 20 rounds
    for _ in 0..10 {
        ChaCha20::quarter_round(&mut state, 0, 4, 8, 12);
        ChaCha20::quarter_round(&mut state, 1, 5, 9, 13);
        ChaCha20::quarter_round(&mut state, 2, 6, 10, 14);
        ChaCha20::quarter_round(&mut state, 3, 7, 11, 15);
        ChaCha20::quarter_round(&mut state, 0, 5, 10, 15);
        ChaCha20::quarter_round(&mut state, 1, 6, 11, 12);
        ChaCha20::quarter_round(&mut state, 2, 7, 8, 13);
        ChaCha20::quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Output words 0-3 and 12-15 (NOT added back to input)
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    for i in 0..4 {
        out[16 + 4 * i..16 + 4 * i + 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }

    out
}

// ============================================================================
// XChaCha20 (extended nonce variant)
// ============================================================================

/// XChaCha20 with a 192-bit nonce.
pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    /// Create XChaCha20 from a 32-byte key and 24-byte nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        // Step 1: Use first 16 bytes of nonce with HChaCha20 to derive subkey
        let subkey_input: [u8; 16] = nonce[..16].try_into().unwrap();
        let subkey = hchacha20(key, &subkey_input);

        // Step 2: Use remaining 8 bytes of nonce as last 8 of 12-byte nonce
        let mut inner_nonce = [0u8; 12];
        inner_nonce[4..12].copy_from_slice(&nonce[16..24]);

        XChaCha20 {
            inner: ChaCha20::new(&subkey, &inner_nonce, 0),
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }
}

// ============================================================================
// Poly1305 MAC
// ============================================================================

/// Poly1305 Message Authentication Code.
///
/// Computes a 128-bit MAC using:
///   mac = (((c_1 * r^n + c_2 * r^(n-1) + ... + c_n * r) mod p) + s) mod 2^128
/// where p = 2^130 - 5, r is clamped, and s is the encryption key.
pub struct Poly1305 {
    /// Accumulator (h): stored in 5 × u32 limbs representing a 130-bit number
    h: [u32; 5],
    /// r value: clamped, stored in 5 limbs
    r: [u32; 5],
    /// Precomputed r * 5 for limbs 1-4
    r5: [u32; 4],
    /// s value (second 16 bytes of key)
    s: [u32; 4],
    /// Partial block buffer
    buf: [u8; 16],
    /// Number of bytes in buffer
    buf_len: usize,
    /// Finished flag
    finished: bool,
}

impl Poly1305 {
    /// Create a new Poly1305 instance from a 256-bit one-time key.
    pub fn new(key: &[u8; 32]) -> Self {
        // r = key[0..16] with clamping
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);

        // Clamp r: clear bits 4,5,6,7 of r[3],r[7],r[11],r[15]
        // and bits 0,1 of r[4],r[8],r[12]
        r_bytes[3] &= 0x0F;
        r_bytes[7] &= 0x0F;
        r_bytes[11] &= 0x0F;
        r_bytes[15] &= 0x0F;
        r_bytes[4] &= 0xFC;
        r_bytes[8] &= 0xFC;
        r_bytes[12] &= 0xFC;

        // Convert r to 5 × 26-bit limbs
        let t0 = u32::from_le_bytes(r_bytes[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(r_bytes[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(r_bytes[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(r_bytes[12..16].try_into().unwrap());

        let r = [
            t0 & 0x3FFFFFF,
            ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFF,
            ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFF,
            ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFF,
            t3 >> 8,
        ];

        let r5 = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        // s = key[16..32]
        let s = [
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ];

        Poly1305 {
            h: [0; 5],
            r,
            r5,
            s,
            buf: [0; 16],
            buf_len: 0,
            finished: false,
        }
    }

    /// Process a single 16-byte block.
    fn process_block(&mut self, block: &[u8], final_block: bool) {
        // Convert block to 5 × 26-bit limbs and add high bit
        let t0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(block[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(block[12..16].try_into().unwrap());

        self.h[0] = self.h[0].wrapping_add(t0 & 0x3FFFFFF);
        self.h[1] = self.h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x3FFFFFF);
        self.h[2] = self.h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x3FFFFFF);
        self.h[3] = self.h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x3FFFFFF);
        self.h[4] = self.h[4].wrapping_add(t3 >> 8);

        // Add high bit (2^128) for full blocks
        if !final_block {
            self.h[4] |= 1 << 24; // 2^128 in our limb representation
        }

        // h *= r mod p
        let d0 = (self.h[0] as u64) * (self.r[0] as u64)
            + (self.h[1] as u64) * (self.r5[3] as u64)
            + (self.h[2] as u64) * (self.r5[2] as u64)
            + (self.h[3] as u64) * (self.r5[1] as u64)
            + (self.h[4] as u64) * (self.r5[0] as u64);

        let d1 = (self.h[0] as u64) * (self.r[1] as u64)
            + (self.h[1] as u64) * (self.r[0] as u64)
            + (self.h[2] as u64) * (self.r5[3] as u64)
            + (self.h[3] as u64) * (self.r5[2] as u64)
            + (self.h[4] as u64) * (self.r5[1] as u64);

        let d2 = (self.h[0] as u64) * (self.r[2] as u64)
            + (self.h[1] as u64) * (self.r[1] as u64)
            + (self.h[2] as u64) * (self.r[0] as u64)
            + (self.h[3] as u64) * (self.r5[3] as u64)
            + (self.h[4] as u64) * (self.r5[0] as u64);

        let d3 = (self.h[0] as u64) * (self.r[3] as u64)
            + (self.h[1] as u64) * (self.r[2] as u64)
            + (self.h[2] as u64) * (self.r[1] as u64)
            + (self.h[3] as u64) * (self.r[0] as u64)
            + (self.h[4] as u64) * (self.r5[3] as u64);

        let d4 = (self.h[0] as u64) * (self.r[4] as u64)
            + (self.h[1] as u64) * (self.r[3] as u64)
            + (self.h[2] as u64) * (self.r[2] as u64)
            + (self.h[3] as u64) * (self.r[1] as u64)
            + (self.h[4] as u64) * (self.r[0] as u64);

        // Partial reduction mod 2^130 - 5
        let mut c: u32;
        c = (d0 >> 26) as u32;
        self.h[0] = d0 as u32 & 0x3FFFFFF;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        self.h[1] = d1 as u32 & 0x3FFFFFF;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        self.h[2] = d2 as u32 & 0x3FFFFFF;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        self.h[3] = d3 as u32 & 0x3FFFFFF;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        self.h[4] = d4 as u32 & 0x3FFFFFF;
        self.h[0] = self.h[0].wrapping_add(c * 5);
        c = self.h[0] >> 26;
        self.h[0] &= 0x3FFFFFF;
        self.h[1] = self.h[1].wrapping_add(c);
    }

    /// Update the MAC with additional data.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill buffer if partial
        if self.buf_len > 0 {
            let to_copy = core::cmp::min(16 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == 16 {
                let block = self.buf;
                self.process_block(&block, false);
                self.buf_len = 0;
            } else {
                return;
            }
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            self.process_block(&data[offset..offset + 16], false);
            offset += 16;
        }

        // Buffer remaining
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and produce the 128-bit MAC tag.
    pub fn finalize(&mut self) -> [u8; 16] {
        if self.finished {
            panic!("Poly1305 already finalized");
        }
        self.finished = true;

        // Process remaining buffer bytes (with padding)
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 1; // Padding indicator
            self.process_block(&block, true);
        }

        // Full carry chain
        let mut c: u32;
        c = self.h[1] >> 26;
        self.h[1] &= 0x3FFFFFF;
        self.h[2] = self.h[2].wrapping_add(c);
        c = self.h[2] >> 26;
        self.h[2] &= 0x3FFFFFF;
        self.h[3] = self.h[3].wrapping_add(c);
        c = self.h[3] >> 26;
        self.h[3] &= 0x3FFFFFF;
        self.h[4] = self.h[4].wrapping_add(c);
        c = self.h[4] >> 26;
        self.h[4] &= 0x3FFFFFF;
        self.h[0] = self.h[0].wrapping_add(c * 5);
        c = self.h[0] >> 26;
        self.h[0] &= 0x3FFFFFF;
        self.h[1] = self.h[1].wrapping_add(c);

        // Compute h - p
        let mut g = [0u32; 5];
        c = self.h[0].wrapping_add(5) >> 26;
        g[0] = self.h[0].wrapping_add(5) & 0x3FFFFFF;
        c = self.h[1].wrapping_add(c) >> 26;
        g[1] = self.h[1].wrapping_add(c) & 0x3FFFFFF;
        c = self.h[2].wrapping_add(c) >> 26;
        g[2] = self.h[2].wrapping_add(c) & 0x3FFFFFF;
        c = self.h[3].wrapping_add(c) >> 26;
        g[3] = self.h[3].wrapping_add(c) & 0x3FFFFFF;
        g[4] = self.h[4].wrapping_add(c).wrapping_sub(1 << 26);

        // Select h or h-p based on overflow (constant time)
        let mask = (g[4] >> 31).wrapping_sub(1); // 0 if g[4] < 0, 0xFFFFFFFF otherwise
        for i in 0..5 {
            self.h[i] = (self.h[i] & !mask) | (g[i] & mask);
        }

        // Convert from limbs to bytes and add s
        let t0 = self.h[0] | (self.h[1] << 26);
        let t1 = (self.h[1] >> 6) | (self.h[2] << 20);
        let t2 = (self.h[2] >> 12) | (self.h[3] << 14);
        let t3 = (self.h[3] >> 18) | (self.h[4] << 8);

        // Add s
        let (r0, carry) = t0.overflowing_add(self.s[0]);
        let (r1, carry) = t1.carrying_add(self.s[1], carry);
        let (r2, carry) = t2.carrying_add(self.s[2], carry);
        let (r3, _) = t3.carrying_add(self.s[3], carry);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&r0.to_le_bytes());
        tag[4..8].copy_from_slice(&r1.to_le_bytes());
        tag[8..12].copy_from_slice(&r2.to_le_bytes());
        tag[12..16].copy_from_slice(&r3.to_le_bytes());

        tag
    }
}

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

/// AEAD errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    AuthenticationFailed,
}

pub type AeadResult<T> = Result<T, AeadError>;

/// ChaCha20-Poly1305 AEAD (RFC 8439).
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Create a new instance with a 256-bit key.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        ChaCha20Poly1305 { key: k }
    }

    /// Generate the one-time Poly1305 key from ChaCha20 block 0.
    fn generate_poly_key(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let mut chacha = ChaCha20::new(&self.key, nonce, 0);
        let mut poly_key = [0u8; 32];
        chacha.keystream(&mut poly_key);
        poly_key
    }

    /// Encrypt plaintext and produce authentication tag.
    ///
    /// Returns (ciphertext, tag) where ciphertext is the same length as plaintext
    /// and tag is 16 bytes.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> AeadResult<()> {
        if ciphertext.len() < plaintext.len() {
            return Err(AeadError::InvalidTagLength);
        }

        // Generate Poly1305 key
        let poly_key = self.generate_poly_key(nonce);

        // Encrypt: ChaCha20 starting at counter = 1
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        let mut chacha = ChaCha20::new(&self.key, nonce, 1);
        chacha.apply_keystream(&mut ciphertext[..plaintext.len()]);

        // Compute Poly1305 tag over:
        //   aad || pad(aad) || ciphertext || pad(ciphertext) || len(aad) || len(ciphertext)
        let mut poly = Poly1305::new(poly_key[..32].try_into().unwrap());

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (aad.len() % 16)]);
        }

        poly.update(&ciphertext[..plaintext.len()]);
        if plaintext.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (plaintext.len() % 16)]);
        }

        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(plaintext.len() as u64).to_le_bytes());

        *tag_out = poly.finalize();

        Ok(())
    }

    /// Decrypt ciphertext and verify authentication tag.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> AeadResult<()> {
        if plaintext.len() < ciphertext.len() {
            return Err(AeadError::InvalidTagLength);
        }

        // Generate Poly1305 key
        let poly_key = self.generate_poly_key(nonce);

        // Verify tag FIRST (before decryption)
        let mut poly = Poly1305::new(poly_key[..32].try_into().unwrap());

        poly.update(aad);
        if aad.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (aad.len() % 16)]);
        }

        poly.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (ciphertext.len() % 16)]);
        }

        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());

        let computed_tag = poly.finalize();

        // Constant-time tag comparison
        if !constant_time_eq(&computed_tag, tag) {
            return Err(AeadError::AuthenticationFailed);
        }

        // Decrypt
        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
        let mut chacha = ChaCha20::new(&self.key, nonce, 1);
        chacha.apply_keystream(&mut plaintext[..ciphertext.len()]);

        Ok(())
    }
}

// ============================================================================
// X25519 Key Exchange
// ============================================================================

/// X25519 Diffie-Hellman key exchange over Curve25519.
///
/// Uses the Montgomery ladder for constant-time scalar multiplication.
pub struct X25519;

/// The prime for Curve25519: p = 2^255 - 19
/// Field element represented as 5 × 51-bit limbs.
#[derive(Clone, Copy)]
struct Fe25519 {
    limbs: [u64; 5],
}

impl Fe25519 {
    const ZERO: Self = Fe25519 { limbs: [0; 5] };
    const ONE: Self = Fe25519 {
        limbs: [1, 0, 0, 0, 0],
    };

    /// Create from bytes (little-endian, 32 bytes).
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        // 51-bit limbs from 256-bit input
        limbs[0] = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
        ]) & 0x7FFFFFFFFFFFF;
        limbs[1] = (u64::from_le_bytes([
            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], 0,
        ]) >> 3)
            & 0x7FFFFFFFFFFFF;
        limbs[2] = (u64::from_le_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
        ]) >> 6)
            & 0x7FFFFFFFFFFFF;
        limbs[3] = (u64::from_le_bytes([
            bytes[19], bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], 0,
        ]) >> 1)
            & 0x7FFFFFFFFFFFF;
        limbs[4] = (u64::from_le_bytes([
            bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31], 0,
        ]) >> 4)
            & 0x7FFFFFFFFFFFF;

        Fe25519 { limbs }
    }

    /// Convert to bytes (little-endian, 32 bytes).
    fn to_bytes(&self) -> [u8; 32] {
        let mut t = self.limbs;

        // Full reduction
        let mut carry: u64;
        for _ in 0..2 {
            carry = 0;
            for i in 0..5 {
                t[i] += carry;
                carry = t[i] >> 51;
                t[i] &= 0x7FFFFFFFFFFFF;
            }
            t[0] += carry * 19;
        }

        // Final conditional subtraction of p
        carry = t[0] + 19;
        carry >>= 51;
        for i in 1..4 {
            carry = (t[i] + carry) >> 51;
        }
        carry = (t[4] + carry) >> 51;
        t[0] += 19 * carry;
        carry = 0;
        for i in 0..5 {
            t[i] += carry;
            carry = t[i] >> 51;
            t[i] &= 0x7FFFFFFFFFFFF;
        }

        let mut out = [0u8; 32];
        let combined = t[0] | (t[1] << 51);
        out[0..8].copy_from_slice(&combined.to_le_bytes());
        let combined = (t[1] >> 13) | (t[2] << 38);
        out[6..14].copy_from_slice(&combined.to_le_bytes());
        let combined = (t[2] >> 26) | (t[3] << 25);
        out[12..20].copy_from_slice(&combined.to_le_bytes());
        let combined = (t[3] >> 39) | (t[4] << 12);
        out[19..27].copy_from_slice(&combined.to_le_bytes());
        // Zero top bytes
        for i in 25..32 {
            if i < 32 {
                out[i] = ((t[4] >> (12 + (i - 25) * 8)) & 0xFF) as u8;
            }
        }

        out
    }

    /// Field addition.
    fn add(a: &Self, b: &Self) -> Self {
        let mut out = Fe25519::ZERO;
        for i in 0..5 {
            out.limbs[i] = a.limbs[i] + b.limbs[i];
        }
        out
    }

    /// Field subtraction.
    fn sub(a: &Self, b: &Self) -> Self {
        // Add 2*p to avoid underflow
        let two_p: [u64; 5] = [
            0xFFFFFFFFFFFDA,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFE,
        ];
        let mut out = Fe25519::ZERO;
        for i in 0..5 {
            out.limbs[i] = a.limbs[i] + two_p[i] - b.limbs[i];
        }
        out
    }

    /// Field multiplication (schoolbook with reduction).
    fn mul(a: &Self, b: &Self) -> Self {
        let mut t = [0u128; 5];

        for i in 0..5 {
            for j in 0..5 {
                let idx = (i + j) % 5;
                let product = (a.limbs[i] as u128) * (b.limbs[j] as u128);
                if i + j >= 5 {
                    t[idx] += product * 19; // Reduction: 2^255 ≡ 19 (mod p)
                } else {
                    t[idx] += product;
                }
            }
        }

        let mut out = Fe25519::ZERO;
        let mut carry: u128 = 0;
        for i in 0..5 {
            t[i] += carry;
            out.limbs[i] = (t[i] & 0x7FFFFFFFFFFFF) as u64;
            carry = t[i] >> 51;
        }
        out.limbs[0] += (carry as u64) * 19;

        out
    }

    /// Field squaring (optimized multiplication by self).
    fn square(a: &Self) -> Self {
        Self::mul(a, a)
    }

    /// Compute a^(p-2) mod p for inversion (Fermat's little theorem).
    fn invert(a: &Self) -> Self {
        // p-2 = 2^255 - 21
        // Use an addition chain
        let mut t0 = Self::square(a); // a^2
        let mut t1 = Self::square(&t0); // a^4
        t1 = Self::square(&t1); // a^8
        t1 = Self::mul(&t1, a); // a^9
        t0 = Self::mul(&t0, &t1); // a^11
        let mut t2 = Self::square(&t0); // a^22
        t1 = Self::mul(&t1, &t2); // a^(2^5 - 1)

        t2 = t1;
        for _ in 0..5 {
            t2 = Self::square(&t2);
        }
        t1 = Self::mul(&t1, &t2); // a^(2^10 - 1)

        t2 = t1;
        for _ in 0..10 {
            t2 = Self::square(&t2);
        }
        t2 = Self::mul(&t2, &t1); // a^(2^20 - 1)

        let mut t3 = t2;
        for _ in 0..20 {
            t3 = Self::square(&t3);
        }
        t2 = Self::mul(&t3, &t2); // a^(2^40 - 1)

        for _ in 0..10 {
            t2 = Self::square(&t2);
        }
        t1 = Self::mul(&t2, &t1); // a^(2^50 - 1)

        t2 = t1;
        for _ in 0..50 {
            t2 = Self::square(&t2);
        }
        t2 = Self::mul(&t2, &t1); // a^(2^100 - 1)

        t3 = t2;
        for _ in 0..100 {
            t3 = Self::square(&t3);
        }
        t2 = Self::mul(&t3, &t2); // a^(2^200 - 1)

        for _ in 0..50 {
            t2 = Self::square(&t2);
        }
        t1 = Self::mul(&t2, &t1); // a^(2^250 - 1)

        for _ in 0..5 {
            t1 = Self::square(&t1);
        }
        Self::mul(&t1, &t0) // a^(2^255 - 21)
    }
}

impl X25519 {
    /// Base point for Curve25519 (u = 9).
    const BASE_POINT: [u8; 32] = {
        let mut p = [0u8; 32];
        p[0] = 9;
        p
    };

    /// Perform X25519 scalar multiplication.
    ///
    /// Implements the Montgomery ladder (constant-time).
    pub fn scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
        // Clamp scalar
        let mut k = *scalar;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        let u = Fe25519::from_bytes(point);

        // Montgomery ladder
        let mut x_1 = u;
        let mut x_2 = Fe25519::ONE;
        let mut z_2 = Fe25519::ZERO;
        let mut x_3 = u;
        let mut z_3 = Fe25519::ONE;
        let mut swap: u64 = 0;

        for pos in (0..255).rev() {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            let k_t = ((k[byte_idx] >> bit_idx) & 1) as u64;

            // Constant-time conditional swap
            let cswap = swap ^ k_t;
            Self::cswap(&mut x_2, &mut x_3, cswap);
            Self::cswap(&mut z_2, &mut z_3, cswap);
            swap = k_t;

            let a = Fe25519::add(&x_2, &z_2);
            let aa = Fe25519::square(&a);
            let b = Fe25519::sub(&x_2, &z_2);
            let bb = Fe25519::square(&b);
            let e = Fe25519::sub(&aa, &bb);
            let c = Fe25519::add(&x_3, &z_3);
            let d = Fe25519::sub(&x_3, &z_3);
            let da = Fe25519::mul(&d, &a);
            let cb = Fe25519::mul(&c, &b);
            x_3 = Fe25519::square(&Fe25519::add(&da, &cb));
            z_3 = Fe25519::mul(&x_1, &Fe25519::square(&Fe25519::sub(&da, &cb)));
            x_2 = Fe25519::mul(&aa, &bb);

            // a24 = 121665
            let a24 = Fe25519 {
                limbs: [121665, 0, 0, 0, 0],
            };
            z_2 = Fe25519::mul(&e, &Fe25519::add(&aa, &Fe25519::mul(&a24, &e)));
        }

        Self::cswap(&mut x_2, &mut x_3, swap);
        Self::cswap(&mut z_2, &mut z_3, swap);

        // Result = x_2 * z_2^(-1)
        let result = Fe25519::mul(&x_2, &Fe25519::invert(&z_2));
        result.to_bytes()
    }

    /// Generate a public key from a private key (scalar × base point).
    pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
        Self::scalar_mult(private_key, &Self::BASE_POINT)
    }

    /// Compute a shared secret from our private key and their public key.
    pub fn shared_secret(private_key: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
        Self::scalar_mult(private_key, their_public)
    }

    /// Constant-time conditional swap.
    #[inline(always)]
    fn cswap(a: &mut Fe25519, b: &mut Fe25519, swap: u64) {
        let mask = 0u64.wrapping_sub(swap); // 0 or 0xFFFF...
        for i in 0..5 {
            let t = mask & (a.limbs[i] ^ b.limbs[i]);
            a.limbs[i] ^= t;
            b.limbs[i] ^= t;
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Constant-time comparison of two byte slices.
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Zero out sensitive memory.
#[inline(never)]
pub fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ============================================================================
// Key Derivation Function (HKDF using HMAC-SHA256)
// ============================================================================

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8], prk: &mut [u8; 32]) {
    // Uses HMAC-SHA256 (imported from parent module)
    hmac_sha256(salt, ikm, prk);
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... || T(N)
/// where T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    let n = (okm.len() + 31) / 32;
    let mut t = [0u8; 32];
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        let mut input = [0u8; 32 + 256 + 1]; // Max info size 256
        let mut input_len = 0;

        if i > 1 {
            input[..32].copy_from_slice(&t);
            input_len = 32;
        }

        let info_len = core::cmp::min(info.len(), 256);
        input[input_len..input_len + info_len].copy_from_slice(&info[..info_len]);
        input_len += info_len;

        input[input_len] = i as u8;
        input_len += 1;

        hmac_sha256(prk, &input[..input_len], &mut t);

        let to_copy = core::cmp::min(32, okm.len() - offset);
        okm[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
    }
}

/// Simple HMAC-SHA256 stub (uses the crate's SHA256 or external)
fn hmac_sha256(key: &[u8], message: &[u8], output: &mut [u8; 32]) {
    // HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
    let mut k_prime = [0u8; 64];
    if key.len() > 64 {
        // Hash the key if longer than block size
        sha256_hash(key, &mut k_prime[..32]);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Inner: H((K' xor ipad) || message)
    let mut inner_key = [0u8; 64];
    for i in 0..64 {
        inner_key[i] = k_prime[i] ^ 0x36;
    }

    let mut inner_hash = [0u8; 32];
    sha256_hash_two(&inner_key, message, &mut inner_hash);

    // Outer: H((K' xor opad) || inner_hash)
    let mut outer_key = [0u8; 64];
    for i in 0..64 {
        outer_key[i] = k_prime[i] ^ 0x5C;
    }

    sha256_hash_two(&outer_key, &inner_hash, output);
}

/// SHA-256 hash (placeholder — calls into the sha256 module).
fn sha256_hash(_data: &[u8], output: &mut [u8]) {
    // TODO: Call actual SHA-256 implementation from sha256.rs
    for byte in output.iter_mut() {
        *byte = 0;
    }
}

fn sha256_hash_two(_part1: &[u8], _part2: &[u8], output: &mut [u8; 32]) {
    // TODO: Call actual SHA-256 with concatenated input
    for byte in output.iter_mut() {
        *byte = 0;
    }
}

// ============================================================================
// C FFI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn crypto_chacha20_encrypt(
    key: *const u8,
    nonce: *const u8,
    data: *mut u8,
    len: usize,
) -> i32 {
    if key.is_null() || nonce.is_null() || data.is_null() {
        return -1;
    }
    unsafe {
        let key_slice: &[u8; 32] = &*(key as *const [u8; 32]);
        let nonce_slice: &[u8; 12] = &*(nonce as *const [u8; 12]);
        let data_slice = core::slice::from_raw_parts_mut(data, len);
        let mut chacha = ChaCha20::new(key_slice, nonce_slice, 1);
        chacha.apply_keystream(data_slice);
    }
    0
}

#[no_mangle]
pub extern "C" fn crypto_poly1305_mac(
    key: *const u8,
    data: *const u8,
    len: usize,
    tag: *mut u8,
) -> i32 {
    if key.is_null() || data.is_null() || tag.is_null() {
        return -1;
    }
    unsafe {
        let key_slice: &[u8; 32] = &*(key as *const [u8; 32]);
        let data_slice = core::slice::from_raw_parts(data, len);
        let mut poly = Poly1305::new(key_slice);
        poly.update(data_slice);
        let result = poly.finalize();
        core::ptr::copy_nonoverlapping(result.as_ptr(), tag, 16);
    }
    0
}

#[no_mangle]
pub extern "C" fn crypto_x25519_keypair(
    private_key: *const u8,
    public_key: *mut u8,
) -> i32 {
    if private_key.is_null() || public_key.is_null() {
        return -1;
    }
    unsafe {
        let priv_key: &[u8; 32] = &*(private_key as *const [u8; 32]);
        let pub_key = X25519::public_key(priv_key);
        core::ptr::copy_nonoverlapping(pub_key.as_ptr(), public_key, 32);
    }
    0
}

#[no_mangle]
pub extern "C" fn crypto_x25519_shared_secret(
    our_private: *const u8,
    their_public: *const u8,
    shared: *mut u8,
) -> i32 {
    if our_private.is_null() || their_public.is_null() || shared.is_null() {
        return -1;
    }
    unsafe {
        let priv_key: &[u8; 32] = &*(our_private as *const [u8; 32]);
        let pub_key: &[u8; 32] = &*(their_public as *const [u8; 32]);
        let secret = X25519::shared_secret(priv_key, pub_key);
        core::ptr::copy_nonoverlapping(secret.as_ptr(), shared, 32);
    }
    0
}
