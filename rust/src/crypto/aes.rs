// =============================================================================
// Kernel Zxyphor — AES-256 (FIPS 197)
// =============================================================================
// Pure-Rust AES-256 implementation for kernel-space disk encryption,
// secure key storage, and encrypted IPC channels.
//
// Supports:
//   - AES-256-ECB (single block encrypt/decrypt)
//   - AES-256-CBC (chained block cipher)
//   - AES-256-CTR (counter mode — stream cipher)
//
// Key size: 256 bits (32 bytes)
// Block size: 128 bits (16 bytes)
// Rounds: 14
// =============================================================================

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const NUM_ROUNDS: usize = 14;
const EXPANDED_KEY_SIZE: usize = 4 * (NUM_ROUNDS + 1); // 60 u32s

// AES S-box (SubBytes transformation)
static SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

// Inverse S-box (InvSubBytes)
static INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

// Round constants
static RCON: [u32; 15] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000,
    0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000,
];

/// AES-256 context with expanded key schedule
pub struct Aes256 {
    enc_key: [u32; EXPANDED_KEY_SIZE],
    dec_key: [u32; EXPANDED_KEY_SIZE],
}

impl Aes256 {
    /// Initialize AES-256 with a 32-byte key
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut ctx = Aes256 {
            enc_key: [0u32; EXPANDED_KEY_SIZE],
            dec_key: [0u32; EXPANDED_KEY_SIZE],
        };
        ctx.expand_key(key);
        ctx
    }

    /// Key expansion (generates round keys from the cipher key)
    fn expand_key(&mut self, key: &[u8; KEY_SIZE]) {
        // Copy original key as first 8 words
        for i in 0..8 {
            self.enc_key[i] = u32::from_be_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }

        // Expand to 60 words
        for i in 8..EXPANDED_KEY_SIZE {
            let mut temp = self.enc_key[i - 1];
            if i % 8 == 0 {
                temp = sub_word(rot_word(temp)) ^ RCON[i / 8];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            self.enc_key[i] = self.enc_key[i - 8] ^ temp;
        }

        // Generate decryption key schedule (inverse)
        for i in 0..EXPANDED_KEY_SIZE {
            self.dec_key[i] = self.enc_key[EXPANDED_KEY_SIZE - 4 + (i / 4) * 4 - i + (i % 4)];
        }
        // Simplified: just copy enc_key for decrypt usage with inverse operations
        self.dec_key = self.enc_key;
    }

    /// Encrypt a single 16-byte block (ECB mode)
    pub fn encrypt_block(&self, plaintext: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut state = [[0u8; 4]; 4];

        // Copy input to state (column-major)
        for c in 0..4 {
            for r in 0..4 {
                state[r][c] = plaintext[c * 4 + r];
            }
        }

        // Initial round key addition
        add_round_key(&mut state, &self.enc_key, 0);

        // Main rounds (1 to NUM_ROUNDS-1)
        for round in 1..NUM_ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.enc_key, round);
        }

        // Final round (no MixColumns)
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.enc_key, NUM_ROUNDS);

        // Copy state to output
        let mut output = [0u8; BLOCK_SIZE];
        for c in 0..4 {
            for r in 0..4 {
                output[c * 4 + r] = state[r][c];
            }
        }
        output
    }

    /// Decrypt a single 16-byte block (ECB mode)
    pub fn decrypt_block(&self, ciphertext: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut state = [[0u8; 4]; 4];

        for c in 0..4 {
            for r in 0..4 {
                state[r][c] = ciphertext[c * 4 + r];
            }
        }

        add_round_key(&mut state, &self.enc_key, NUM_ROUNDS);

        for round in (1..NUM_ROUNDS).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &self.enc_key, round);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &self.enc_key, 0);

        let mut output = [0u8; BLOCK_SIZE];
        for c in 0..4 {
            for r in 0..4 {
                output[c * 4 + r] = state[r][c];
            }
        }
        output
    }

    /// AES-256-CBC encrypt
    pub fn encrypt_cbc(&self, data: &[u8], iv: &[u8; BLOCK_SIZE], out: &mut [u8]) -> usize {
        let blocks = data.len() / BLOCK_SIZE;
        if out.len() < blocks * BLOCK_SIZE {
            return 0;
        }

        let mut prev = *iv;
        for i in 0..blocks {
            let offset = i * BLOCK_SIZE;
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);

            // XOR with previous ciphertext (or IV)
            for j in 0..BLOCK_SIZE {
                block[j] ^= prev[j];
            }

            let encrypted = self.encrypt_block(&block);
            out[offset..offset + BLOCK_SIZE].copy_from_slice(&encrypted);
            prev = encrypted;
        }

        blocks * BLOCK_SIZE
    }

    /// AES-256-CBC decrypt
    pub fn decrypt_cbc(&self, data: &[u8], iv: &[u8; BLOCK_SIZE], out: &mut [u8]) -> usize {
        let blocks = data.len() / BLOCK_SIZE;
        if out.len() < blocks * BLOCK_SIZE {
            return 0;
        }

        let mut prev = *iv;
        for i in 0..blocks {
            let offset = i * BLOCK_SIZE;
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);

            let decrypted = self.decrypt_block(&block);

            for j in 0..BLOCK_SIZE {
                out[offset + j] = decrypted[j] ^ prev[j];
            }

            prev = block;
        }

        blocks * BLOCK_SIZE
    }

    /// AES-256-CTR encrypt/decrypt (symmetric operation)
    pub fn ctr(&self, data: &[u8], nonce: &[u8; 12], out: &mut [u8]) -> usize {
        let len = data.len().min(out.len());
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..12].copy_from_slice(nonce);

        let mut offset = 0;
        let mut counter: u32 = 0;

        while offset < len {
            // Set counter in last 4 bytes (big-endian)
            counter_block[12] = (counter >> 24) as u8;
            counter_block[13] = (counter >> 16) as u8;
            counter_block[14] = (counter >> 8) as u8;
            counter_block[15] = counter as u8;

            let keystream = self.encrypt_block(&counter_block);

            let chunk_size = (len - offset).min(BLOCK_SIZE);
            for i in 0..chunk_size {
                out[offset + i] = data[offset + i] ^ keystream[i];
            }

            offset += chunk_size;
            counter = counter.wrapping_add(1);
        }

        len
    }
}

// =============================================================================
// AES Internal Operations
// =============================================================================

fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = SBOX[state[r][c] as usize];
        }
    }
}

fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for r in 0..4 {
        for c in 0..4 {
            state[r][c] = INV_SBOX[state[r][c] as usize];
        }
    }
}

fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1: shift left by 1
    let tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;

    // Row 2: shift left by 2
    let (t0, t1) = (state[2][0], state[2][1]);
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t0;
    state[2][3] = t1;

    // Row 3: shift left by 3 (= shift right by 1)
    let tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    let tmp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;

    let (t0, t1) = (state[2][0], state[2][1]);
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t0;
    state[2][3] = t1;

    let tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let s0 = state[0][c];
        let s1 = state[1][c];
        let s2 = state[2][c];
        let s3 = state[3][c];

        state[0][c] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[1][c] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[2][c] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[3][c] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let s0 = state[0][c];
        let s1 = state[1][c];
        let s2 = state[2][c];
        let s3 = state[3][c];

        state[0][c] = gf_mul(0x0E, s0) ^ gf_mul(0x0B, s1) ^ gf_mul(0x0D, s2) ^ gf_mul(0x09, s3);
        state[1][c] = gf_mul(0x09, s0) ^ gf_mul(0x0E, s1) ^ gf_mul(0x0B, s2) ^ gf_mul(0x0D, s3);
        state[2][c] = gf_mul(0x0D, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0E, s2) ^ gf_mul(0x0B, s3);
        state[3][c] = gf_mul(0x0B, s0) ^ gf_mul(0x0D, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0E, s3);
    }
}

fn add_round_key(state: &mut [[u8; 4]; 4], key: &[u32; EXPANDED_KEY_SIZE], round: usize) {
    for c in 0..4 {
        let k = key[round * 4 + c].to_be_bytes();
        for r in 0..4 {
            state[r][c] ^= k[r];
        }
    }
}

/// Galois Field multiplication in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if (b & 1) != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1B; // Reduction polynomial
        }
        b >>= 1;
    }
    result
}

fn sub_word(word: u32) -> u32 {
    let b = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

fn rot_word(word: u32) -> u32 {
    (word << 8) | (word >> 24)
}

// =============================================================================
// C FFI for Zig kernel
// =============================================================================

#[repr(C)]
pub struct AesContext {
    inner: Aes256,
}

/// Create AES-256 context from a 32-byte key
#[no_mangle]
pub extern "C" fn aes256_init(key: *const u8) -> AesContext {
    let key_slice = unsafe { &*(key as *const [u8; KEY_SIZE]) };
    AesContext {
        inner: Aes256::new(key_slice),
    }
}

/// Encrypt a single 16-byte block
#[no_mangle]
pub extern "C" fn aes256_encrypt_block(ctx: &AesContext, input: *const u8, output: *mut u8) {
    let block = unsafe { &*(input as *const [u8; BLOCK_SIZE]) };
    let result = ctx.inner.encrypt_block(block);
    unsafe {
        core::ptr::copy_nonoverlapping(result.as_ptr(), output, BLOCK_SIZE);
    }
}

/// Decrypt a single 16-byte block
#[no_mangle]
pub extern "C" fn aes256_decrypt_block(ctx: &AesContext, input: *const u8, output: *mut u8) {
    let block = unsafe { &*(input as *const [u8; BLOCK_SIZE]) };
    let result = ctx.inner.decrypt_block(block);
    unsafe {
        core::ptr::copy_nonoverlapping(result.as_ptr(), output, BLOCK_SIZE);
    }
}
