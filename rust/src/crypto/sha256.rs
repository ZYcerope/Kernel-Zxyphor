// =============================================================================
// Kernel Zxyphor — SHA-256 (FIPS 180-4)
// =============================================================================
// Pure-Rust SHA-256 cryptographic hash function for kernel-space
// integrity verification, HMAC, and password hashing.
//
// Output: 256 bits (32 bytes)
// Block size: 512 bits (64 bytes)
// =============================================================================

const BLOCK_SIZE: usize = 64;
const DIGEST_SIZE: usize = 32;

/// SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
static K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

/// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
static H_INIT: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// SHA-256 hash state
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Sha256 {
            state: H_INIT,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // If we have buffered data, try to complete a block
        if self.buffer_len > 0 {
            let needed = BLOCK_SIZE - self.buffer_len;
            let copy_len = data.len().min(needed);
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            offset += copy_len;

            if self.buffer_len == BLOCK_SIZE {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks directly from input
        while offset + BLOCK_SIZE <= data.len() {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            self.compress(&block);
            offset += BLOCK_SIZE;
        }

        // Buffer remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize hash and produce the 32-byte digest
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let bit_len = self.total_len * 8;

        // Append padding: 1 bit + zeros + 64-bit length
        let mut padding = [0u8; 128]; // Worst case: two blocks
        padding[0] = 0x80;

        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        // Append length in big-endian
        let len_bytes = bit_len.to_be_bytes();

        self.update(&padding[..pad_len]);
        self.update(&len_bytes);

        // Convert state to bytes (big-endian)
        let mut digest = [0u8; DIGEST_SIZE];
        for i in 0..8 {
            let bytes = self.state[i].to_be_bytes();
            digest[i * 4] = bytes[0];
            digest[i * 4 + 1] = bytes[1];
            digest[i * 4 + 2] = bytes[2];
            digest[i * 4 + 3] = bytes[3];
        }
        digest
    }

    /// Process a single 512-bit (64-byte) block
    fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        // Prepare message schedule
        let mut w = [0u32; 64];

        // First 16 words from the block
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // Extend to 64 words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // 64 rounds
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
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

        // Add to hash state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    /// Compute SHA-256 of a complete message in one call
    pub fn hash(data: &[u8]) -> [u8; DIGEST_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// =============================================================================
// HMAC-SHA-256 (RFC 2104)
// =============================================================================

const HMAC_BLOCK_SIZE: usize = 64;

pub struct HmacSha256 {
    inner_key: [u8; HMAC_BLOCK_SIZE],
    outer_key: [u8; HMAC_BLOCK_SIZE],
}

impl HmacSha256 {
    /// Create HMAC-SHA-256 with the given key
    pub fn new(key: &[u8]) -> Self {
        let mut padded_key = [0u8; HMAC_BLOCK_SIZE];

        if key.len() > HMAC_BLOCK_SIZE {
            // Hash key if longer than block size
            let hashed = Sha256::hash(key);
            padded_key[..DIGEST_SIZE].copy_from_slice(&hashed);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0x36u8; HMAC_BLOCK_SIZE];
        let mut outer_key = [0x5Cu8; HMAC_BLOCK_SIZE];

        for i in 0..HMAC_BLOCK_SIZE {
            inner_key[i] ^= padded_key[i];
            outer_key[i] ^= padded_key[i];
        }

        // Zero out the padded key from stack
        for b in padded_key.iter_mut() {
            *b = 0;
        }

        HmacSha256 {
            inner_key,
            outer_key,
        }
    }

    /// Compute HMAC-SHA-256 of a message
    pub fn compute(&self, message: &[u8]) -> [u8; DIGEST_SIZE] {
        // Inner hash: H(inner_key || message)
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&self.inner_key);
        inner_hasher.update(message);
        let inner_hash = inner_hasher.finalize();

        // Outer hash: H(outer_key || inner_hash)
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&self.outer_key);
        outer_hasher.update(&inner_hash);
        outer_hasher.finalize()
    }

    /// One-shot HMAC-SHA-256
    pub fn mac(key: &[u8], message: &[u8]) -> [u8; DIGEST_SIZE] {
        let hmac = HmacSha256::new(key);
        hmac.compute(message)
    }
}

// =============================================================================
// C FFI for Zig kernel
// =============================================================================

/// One-shot SHA-256 hash
#[no_mangle]
pub extern "C" fn sha256_hash(data: *const u8, len: usize, output: *mut u8) {
    if data.is_null() || output.is_null() {
        return;
    }
    let input = unsafe { core::slice::from_raw_parts(data, len) };
    let digest = Sha256::hash(input);
    unsafe {
        core::ptr::copy_nonoverlapping(digest.as_ptr(), output, DIGEST_SIZE);
    }
}

/// Incremental SHA-256: create context
#[no_mangle]
pub extern "C" fn sha256_init() -> Sha256 {
    Sha256::new()
}

/// Incremental SHA-256: update with data
#[no_mangle]
pub extern "C" fn sha256_update(ctx: &mut Sha256, data: *const u8, len: usize) {
    if data.is_null() {
        return;
    }
    let input = unsafe { core::slice::from_raw_parts(data, len) };
    ctx.update(input);
}

/// HMAC-SHA-256 one-shot
#[no_mangle]
pub extern "C" fn hmac_sha256(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    output: *mut u8,
) {
    if key.is_null() || msg.is_null() || output.is_null() {
        return;
    }
    let k = unsafe { core::slice::from_raw_parts(key, key_len) };
    let m = unsafe { core::slice::from_raw_parts(msg, msg_len) };
    let mac = HmacSha256::mac(k, m);
    unsafe {
        core::ptr::copy_nonoverlapping(mac.as_ptr(), output, DIGEST_SIZE);
    }
}
