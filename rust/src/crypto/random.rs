// =============================================================================
// Kernel Zxyphor — ChaCha20-based CSPRNG
// =============================================================================
// Cryptographically secure pseudo-random number generator based on
// the ChaCha20 stream cipher (RFC 7539). Suitable for:
//   - Key generation
//   - Nonce generation
//   - Address space layout randomization (ASLR)
//   - Stack canary generation
//   - /dev/random and /dev/urandom backing
//
// The CSPRNG maintains a 256-bit internal state that is periodically
// reseeded from hardware entropy sources (RDRAND/RDSEED, timer jitter).
// =============================================================================

const CHACHA_STATE_SIZE: usize = 16;
const CHACHA_BLOCK_SIZE: usize = 64;
const CHACHA_KEY_SIZE: usize = 32;
const CHACHA_NONCE_SIZE: usize = 12;
const POOL_SIZE: usize = 256;

/// ChaCha20 quarter-round on 4 state words
#[inline(always)]
fn quarter_round(state: &mut [u32; CHACHA_STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
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

/// Perform the ChaCha20 block function (20 rounds)
fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; CHACHA_STATE_SIZE] {
    // "expand 32-byte k"
    let mut state: [u32; CHACHA_STATE_SIZE] = [
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];

    let initial = state;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..CHACHA_STATE_SIZE {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    state
}

/// Kernel CSPRNG state
pub struct CsprngState {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    buffer: [u8; CHACHA_BLOCK_SIZE],
    buffer_pos: usize,
    reseed_counter: u64,
    entropy_pool: [u8; POOL_SIZE],
    pool_pos: usize,
    initialized: bool,
}

impl CsprngState {
    /// Create an uninitialized CSPRNG (must be seeded before use)
    pub const fn new() -> Self {
        CsprngState {
            key: [0u32; 8],
            nonce: [0u32; 3],
            counter: 0,
            buffer: [0u8; CHACHA_BLOCK_SIZE],
            buffer_pos: CHACHA_BLOCK_SIZE, // Empty buffer forces generation
            reseed_counter: 0,
            entropy_pool: [0u8; POOL_SIZE],
            pool_pos: 0,
            initialized: false,
        }
    }

    /// Seed the CSPRNG with initial entropy
    pub fn seed(&mut self, entropy: &[u8]) {
        // Mix entropy into the key using a simple absorption
        let mut i = 0;
        for byte in entropy.iter() {
            let key_idx = i / 4;
            let byte_idx = i % 4;
            if key_idx < 8 {
                self.key[key_idx] ^= (*byte as u32) << (byte_idx * 8);
            }
            i += 1;
            if i >= 32 {
                i = 0;
            }
        }

        // Set a nonce from the remaining entropy
        if entropy.len() > 32 {
            let remaining = &entropy[32..];
            for j in 0..remaining.len().min(12) {
                let nonce_idx = j / 4;
                let byte_idx = j % 4;
                if nonce_idx < 3 {
                    self.nonce[nonce_idx] ^= (remaining[j] as u32) << (byte_idx * 8);
                }
            }
        }

        self.counter = 0;
        self.buffer_pos = CHACHA_BLOCK_SIZE; // Force regeneration
        self.reseed_counter = 0;
        self.initialized = true;
    }

    /// Add entropy to the internal pool for next reseed
    pub fn add_entropy(&mut self, data: &[u8]) {
        for byte in data.iter() {
            self.entropy_pool[self.pool_pos] ^= *byte;
            self.pool_pos = (self.pool_pos + 1) % POOL_SIZE;
        }
    }

    /// Reseed from the entropy pool (called periodically)
    pub fn reseed(&mut self) {
        // Mix pool into key using simple folding
        for i in 0..32 {
            let key_idx = i / 4;
            let byte_idx = i % 4;
            self.key[key_idx] ^= (self.entropy_pool[i] as u32) << (byte_idx * 8);
        }

        // Mix more pool bytes into nonce
        for i in 0..12 {
            let nonce_idx = i / 4;
            let byte_idx = i % 4;
            self.nonce[nonce_idx] ^= (self.entropy_pool[32 + i] as u32) << (byte_idx * 8);
        }

        // Clear used pool bytes
        for b in self.entropy_pool[..44].iter_mut() {
            *b = 0;
        }

        self.counter = 0;
        self.buffer_pos = CHACHA_BLOCK_SIZE;
        self.reseed_counter += 1;
    }

    /// Generate the next block of random bytes
    fn generate_block(&mut self) {
        let block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.counter = self.counter.wrapping_add(1);

        // Serialize to bytes (little-endian)
        for i in 0..CHACHA_STATE_SIZE {
            let bytes = block[i].to_le_bytes();
            self.buffer[i * 4] = bytes[0];
            self.buffer[i * 4 + 1] = bytes[1];
            self.buffer[i * 4 + 2] = bytes[2];
            self.buffer[i * 4 + 3] = bytes[3];
        }
        self.buffer_pos = 0;

        // Backtrack protection: use first 32 bytes as new key
        for i in 0..8 {
            self.key[i] = u32::from_le_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
            ]);
        }
        // Only expose bytes 32..64 as output
        self.buffer_pos = 32;
    }

    /// Get a single random byte
    pub fn next_byte(&mut self) -> u8 {
        if !self.initialized {
            return 0;
        }
        if self.buffer_pos >= CHACHA_BLOCK_SIZE {
            self.generate_block();
        }
        let byte = self.buffer[self.buffer_pos];
        self.buffer_pos += 1;
        byte
    }

    /// Get a random u32
    pub fn next_u32(&mut self) -> u32 {
        let b0 = self.next_byte() as u32;
        let b1 = self.next_byte() as u32;
        let b2 = self.next_byte() as u32;
        let b3 = self.next_byte() as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Get a random u64
    pub fn next_u64(&mut self) -> u64 {
        (self.next_u32() as u64) | ((self.next_u32() as u64) << 32)
    }

    /// Fill a buffer with random bytes
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_byte();
        }
    }

    /// Get a random value in [0, max) using rejection sampling (unbiased)
    pub fn next_bounded(&mut self, max: u32) -> u32 {
        if max <= 1 {
            return 0;
        }
        let threshold = max.wrapping_neg() % max; // 2^32 mod max
        loop {
            let r = self.next_u32();
            if r >= threshold {
                return r % max;
            }
        }
    }
}

// =============================================================================
// Global CSPRNG Instance (kernel singleton)
// =============================================================================

static mut GLOBAL_CSPRNG: CsprngState = CsprngState::new();

// =============================================================================
// C FFI for Zig kernel
// =============================================================================

/// Initialize the kernel CSPRNG with entropy
#[no_mangle]
pub extern "C" fn csprng_init(entropy: *const u8, len: usize) {
    if entropy.is_null() || len == 0 {
        return;
    }
    let data = unsafe { core::slice::from_raw_parts(entropy, len) };
    unsafe {
        GLOBAL_CSPRNG.seed(data);
    }
}

/// Add entropy to the CSPRNG pool
#[no_mangle]
pub extern "C" fn csprng_add_entropy(data: *const u8, len: usize) {
    if data.is_null() || len == 0 {
        return;
    }
    let entropy = unsafe { core::slice::from_raw_parts(data, len) };
    unsafe {
        GLOBAL_CSPRNG.add_entropy(entropy);
    }
}

/// Reseed the CSPRNG from its entropy pool
#[no_mangle]
pub extern "C" fn csprng_reseed() {
    unsafe {
        GLOBAL_CSPRNG.reseed();
    }
}

/// Get random bytes from the kernel CSPRNG
#[no_mangle]
pub extern "C" fn csprng_fill(buf: *mut u8, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    unsafe {
        GLOBAL_CSPRNG.fill_bytes(output);
    }
}

/// Get a random u32
#[no_mangle]
pub extern "C" fn csprng_random_u32() -> u32 {
    unsafe { GLOBAL_CSPRNG.next_u32() }
}

/// Get a random u64
#[no_mangle]
pub extern "C" fn csprng_random_u64() -> u64 {
    unsafe { GLOBAL_CSPRNG.next_u64() }
}

/// Get a bounded random u32 in [0, max)
#[no_mangle]
pub extern "C" fn csprng_random_bounded(max: u32) -> u32 {
    unsafe { GLOBAL_CSPRNG.next_bounded(max) }
}
