// SPDX-License-Identifier: GPL-2.0 OR MIT
// Zxyphor Kernel (Rust) - Random Number Generator & Crypto Primitives
// Complete: Hardware RNG, software DRBG, ChaCha20, entropy pool,
// getrandom() interface, jitterentropy, NIST SP 800-90A, CRNG

// ============================================================================
// RNG Source Types
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngSourceType {
    HardwareRng = 0,
    Jitterentropy = 1,
    CpuRdrand = 2,
    CpuRdseed = 3,
    TpmRng = 4,
    VirtioRng = 5,
    InterruptTiming = 6,
    InputEvents = 7,
    DiskTiming = 8,
    ArchRng = 9,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EntropyLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Full = 4,
}

// ============================================================================
// Entropy Pool
// ============================================================================

pub const POOL_BITS: usize = 256;
pub const POOL_BYTES: usize = POOL_BITS / 8;
pub const POOL_MIN_BITS: usize = 128;
pub const CRNG_SEED_BYTES: usize = 32;
pub const CRNG_INIT_CNT_THRESH: usize = 64;
pub const CRNG_RESEED_INTERVAL_SEC: u64 = 300;
pub const ENTROPY_SHIFT: u32 = 3;
pub const ENTROPY_BITS_PER_BYTE: u32 = 1;

#[derive(Debug)]
pub struct EntropyPool {
    pub pool_data: [u8; POOL_BYTES],
    pub entropy_count: u32,        // Available entropy in bits
    pub entropy_total: u64,        // Total entropy collected ever
    pub last_seed_time: u64,
    pub input_rotate: u32,
    pub add_ptr: u32,
    pub samples_collected: u64,
    pub samples_discarded: u64,
    pub initialized: bool,
}

impl EntropyPool {
    pub fn new() -> Self {
        Self {
            pool_data: [0u8; POOL_BYTES],
            entropy_count: 0,
            entropy_total: 0,
            last_seed_time: 0,
            input_rotate: 0,
            add_ptr: 0,
            samples_collected: 0,
            samples_discarded: 0,
            initialized: false,
        }
    }
}

#[derive(Debug)]
pub struct EntropySample {
    pub source: RngSourceType,
    pub timestamp: u64,
    pub data: [u8; 64],
    pub data_len: usize,
    pub entropy_bits: u32,
    pub credit: bool,
}

// ============================================================================
// CRNG (Cryptographic RNG)
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrngState {
    Empty = 0,
    EarlyInit = 1,
    Ready = 2,
}

#[derive(Debug)]
pub struct CrngContext {
    pub state: CrngState,
    pub key: [u8; 32],           // ChaCha20 key
    pub generation: u64,
    pub init_time: u64,
    pub reseed_count: u64,
    pub bytes_generated: u64,
    pub bytes_since_reseed: u64,
    pub max_bytes_per_reseed: u64,
    pub reseed_interval: u64,    // In jiffies
    pub last_reseed: u64,
}

impl CrngContext {
    pub fn new() -> Self {
        Self {
            state: CrngState::Empty,
            key: [0u8; 32],
            generation: 0,
            init_time: 0,
            reseed_count: 0,
            bytes_generated: 0,
            bytes_since_reseed: 0,
            max_bytes_per_reseed: 1 << 20, // 1 MiB
            reseed_interval: CRNG_RESEED_INTERVAL_SEC * 1000,
            last_reseed: 0,
        }
    }
}

// ============================================================================
// ChaCha20 State
// ============================================================================

pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;
pub const CHACHA20_BLOCK_SIZE: usize = 64;
pub const CHACHA20_STATE_WORDS: usize = 16;

#[derive(Debug, Clone)]
pub struct ChaCha20State {
    pub state: [u32; CHACHA20_STATE_WORDS],
}

impl ChaCha20State {
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE], counter: u32) -> Self {
        let mut state = [0u32; CHACHA20_STATE_WORDS];
        // "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        // Key
        for i in 0..8 {
            let offset = i * 4;
            state[4 + i] = u32::from_le_bytes([
                key[offset], key[offset + 1], key[offset + 2], key[offset + 3]
            ]);
        }
        // Counter
        state[12] = counter;
        // Nonce
        for i in 0..3 {
            let offset = i * 4;
            state[13 + i] = u32::from_le_bytes([
                nonce[offset], nonce[offset + 1], nonce[offset + 2], nonce[offset + 3]
            ]);
        }
        Self { state }
    }
}

// ============================================================================
// DRBG (Deterministic Random Bit Generator) - NIST SP 800-90A
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DrbgType {
    HmacSha256 = 0,
    HmacSha384 = 1,
    HmacSha512 = 2,
    CtrAes128 = 3,
    CtrAes192 = 4,
    CtrAes256 = 5,
    HashSha256 = 6,
    HashSha384 = 7,
    HashSha512 = 8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DrbgStrength {
    Low128 = 128,
    Medium192 = 192,
    High256 = 0,  // Maps to 256
}

#[derive(Debug)]
pub struct DrbgState {
    pub drbg_type: DrbgType,
    pub security_strength: u32,
    pub seeded: bool,
    pub prediction_resist: bool,
    pub reseed_threshold: u64,
    pub reseed_counter: u64,
    pub v: [u8; 64],        // Internal state V
    pub c: [u8; 64],        // Internal state C (for Hash_DRBG)
    pub key: [u8; 64],      // Key (for HMAC/CTR_DRBG)
    pub seed_len: usize,
    pub max_request_bytes: u64,
    pub bytes_generated: u64,
    pub instantiation_time: u64,
    pub last_reseed_time: u64,
}

impl DrbgState {
    pub fn new(drbg_type: DrbgType) -> Self {
        let (strength, seed_len) = match drbg_type {
            DrbgType::HmacSha256 | DrbgType::HashSha256 => (256, 48),
            DrbgType::HmacSha384 | DrbgType::HashSha384 => (256, 56),
            DrbgType::HmacSha512 | DrbgType::HashSha512 => (256, 111),
            DrbgType::CtrAes128 => (128, 32),
            DrbgType::CtrAes192 => (192, 40),
            DrbgType::CtrAes256 => (256, 48),
        };
        Self {
            drbg_type,
            security_strength: strength,
            seeded: false,
            prediction_resist: false,
            reseed_threshold: 1 << 48,
            reseed_counter: 0,
            v: [0u8; 64],
            c: [0u8; 64],
            key: [0u8; 64],
            seed_len,
            max_request_bytes: 1 << 16,
            bytes_generated: 0,
            instantiation_time: 0,
            last_reseed_time: 0,
        }
    }
}

// ============================================================================
// Jitterentropy
// ============================================================================

pub const JENT_MEMORY_BLOCKS: usize = 64;
pub const JENT_MEMORY_BLOCKSIZE: usize = 32;
pub const JENT_MEMORY_SIZE: usize = JENT_MEMORY_BLOCKS * JENT_MEMORY_BLOCKSIZE;
pub const JENT_OSR_DEFAULT: u32 = 1;
pub const JENT_STUCK_THRESHOLD: u32 = 3;

#[derive(Debug)]
pub struct JitterEntropyCollector {
    pub data: u64,
    pub old_data: u64,
    pub prev_time: u64,
    pub last_delta: u64,
    pub last_delta2: u64,
    pub osr: u32,                       // Oversampling rate
    pub flags: JitterFlags,
    pub mem: [u8; JENT_MEMORY_SIZE],    // Memory access pattern
    pub memlocation: usize,
    pub memblocks: usize,
    pub memblocksize: usize,
    pub memaccessloops: usize,
    pub rct_count: u32,                 // Repetition Count Test
    pub apt_observations: u32,          // Adaptive Proportion Test
    pub apt_count: u32,
    pub apt_base: u32,
    pub health_failure: bool,
    pub stuck: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct JitterFlags {
    pub es_loaded: bool,
    pub fips: bool,
    pub internal_timer: bool,
    pub max_mem_set: bool,
}

// ============================================================================
// Hardware RNG
// ============================================================================

#[derive(Debug)]
pub struct HwRng {
    pub name: [u8; 64],
    pub quality: u16,                // Estimated quality (0-1024)
    pub init: Option<fn(rng: &mut HwRng) -> i32>,
    pub cleanup: Option<fn(rng: &mut HwRng)>,
    pub data_present: Option<fn(rng: &mut HwRng, wait: bool) -> i32>,
    pub data_read: Option<fn(rng: &mut HwRng, data: &mut [u8]) -> i32>,
    pub read: Option<fn(rng: &mut HwRng, data: &mut [u8], max: usize, wait: bool) -> i32>,
    pub priv_data: u64,
    pub ref_count: u32,
}

#[derive(Debug)]
pub struct HwRngList {
    pub rngs: Vec<HwRng>,
    pub current: Option<usize>,
    pub default_quality: u16,
    pub filling_timer_on: bool,
    pub fill_time: u64,             // ms between fills
    pub data_avail: usize,
    pub rng_buffer: [u8; 4096],
    pub rng_fillbuf: [u8; 4096],
}

// ============================================================================
// CPU RNG Instructions
// ============================================================================

#[derive(Debug, Clone)]
pub struct CpuRngInfo {
    pub has_rdrand: bool,
    pub has_rdseed: bool,
    pub has_darn: bool,             // PowerPC DARN
    pub has_rndr: bool,             // ARM RNDR
    pub rdrand_sanity: bool,        // Passed sanity check
    pub rdseed_sanity: bool,
    pub total_rdrand_calls: u64,
    pub total_rdseed_calls: u64,
    pub rdrand_failures: u64,
    pub rdseed_failures: u64,
}

// ============================================================================
// virtio-rng
// ============================================================================

#[derive(Debug)]
pub struct VirtioRng {
    pub vq_idx: u32,
    pub busy: bool,
    pub hwrng_register: bool,
    pub hwrng_removed: bool,
    pub data_avail: u32,
    pub buf: [u8; 1024],
    pub buf_idx: usize,
    pub bytes_received: u64,
    pub requests_sent: u64,
}

// ============================================================================
// getrandom() System Call
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum GetRandomFlags {
    GRND_NONBLOCK = 0x0001,     // Don't block
    GRND_RANDOM = 0x0002,       // Use /dev/random (blocking pool)
    GRND_INSECURE = 0x0004,     // Return any available randomness
}

#[derive(Debug)]
pub struct GetrandomConfig {
    pub urandom_min_reseed_secs: u64,
    pub random_min_reseed_secs: u64,
    pub crng_ready: bool,
    pub trust_cpu: bool,
    pub trust_bootloader: bool,
}

// ============================================================================
// /dev/random, /dev/urandom
// ============================================================================

#[derive(Debug)]
pub struct RandomDevState {
    pub entropy_avail: u32,
    pub poolsize: u32,
    pub read_wakeup_threshold: u32,
    pub write_wakeup_threshold: u32,
    pub urandom_min_reseed_secs: u32,
    pub boot_id: [u8; 16],         // UUID
    pub uuid: [u8; 16],
}

// ============================================================================
// Entropy Sources Health Test
// ============================================================================

#[derive(Debug)]
pub struct EntropyHealthTest {
    pub rct_cutoff_startup: u32,
    pub rct_cutoff_permanent: u32,
    pub apt_cutoff_startup: u32,
    pub apt_cutoff_permanent: u32,
    pub apt_window: u32,
    pub rct_count: u32,
    pub apt_count: u32,
    pub apt_base_set: bool,
    pub apt_base: u32,
    pub startup_test_done: bool,
    pub failure_count: u64,
    pub last_failure_time: u64,
}

// ============================================================================
// Crypto Hash Primitives (used by RNG)
// ============================================================================

#[derive(Debug, Clone)]
pub struct Blake2sState {
    pub h: [u32; 8],
    pub t: [u32; 2],
    pub f: [u32; 2],
    pub buf: [u8; 64],
    pub buflen: usize,
    pub outlen: usize,
}

pub const BLAKE2S_HASH_SIZE: usize = 32;
pub const BLAKE2S_BLOCK_SIZE: usize = 64;
pub const BLAKE2S_KEY_SIZE: usize = 32;

pub const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

#[derive(Debug, Clone)]
pub struct Sha256State {
    pub state: [u32; 8],
    pub count: u64,
    pub buf: [u8; 64],
}

pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA256_BLOCK_SIZE: usize = 64;

pub const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// ============================================================================
// Statistics
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct RngSubsystemStats {
    pub total_entropy_collected_bits: u64,
    pub total_random_bytes_served: u64,
    pub total_urandom_bytes_served: u64,
    pub total_getrandom_calls: u64,
    pub total_getrandom_bytes: u64,
    pub total_reseed_events: u64,
    pub total_hwrng_bytes: u64,
    pub total_jitter_samples: u64,
    pub total_irq_samples: u64,
    pub total_input_samples: u64,
    pub total_disk_samples: u64,
    pub crng_init_time: u64,
    pub health_failures: u64,
    pub initialized: bool,
}

impl RngSubsystemStats {
    pub fn new() -> Self {
        Self {
            initialized: true,
            ..Default::default()
        }
    }
}
