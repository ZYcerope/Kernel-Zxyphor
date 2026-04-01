// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Cryptographic Subsystem
// Hardware-accelerated crypto primitives, key management, secure random

const std = @import("std");

/// AES block size
pub const AES_BLOCK_SIZE = 16;
pub const AES_128_KEY_SIZE = 16;
pub const AES_192_KEY_SIZE = 24;
pub const AES_256_KEY_SIZE = 32;
pub const AES_128_ROUNDS = 10;
pub const AES_192_ROUNDS = 12;
pub const AES_256_ROUNDS = 14;

/// ChaCha20 constants
pub const CHACHA20_KEY_SIZE = 32;
pub const CHACHA20_NONCE_SIZE = 12;
pub const CHACHA20_BLOCK_SIZE = 64;

/// SHA-256 constants
pub const SHA256_DIGEST_SIZE = 32;
pub const SHA256_BLOCK_SIZE = 64;

/// SHA-512 constants
pub const SHA512_DIGEST_SIZE = 64;
pub const SHA512_BLOCK_SIZE = 128;

/// HMAC constants
pub const HMAC_SHA256_SIZE = SHA256_DIGEST_SIZE;

/// AES-NI hardware detection
pub fn hasAesNi() bool {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 1)),
          [subleaf] "{ecx}" (@as(u32, 0)),
    );
    _ = eax;
    _ = ebx;
    _ = edx;
    return (ecx & (1 << 25)) != 0; // AES-NI bit
}

/// Check for RDRAND support
pub fn hasRdrand() bool {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 1)),
          [subleaf] "{ecx}" (@as(u32, 0)),
    );
    _ = eax;
    _ = ebx;
    _ = edx;
    return (ecx & (1 << 30)) != 0;
}

/// Check for SHA extensions
pub fn hasShaExt() bool {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 7)),
          [subleaf] "{ecx}" (@as(u32, 0)),
    );
    _ = eax;
    _ = ecx;
    _ = edx;
    return (ebx & (1 << 29)) != 0;
}

/// SHA-256 implementation
pub const Sha256 = struct {
    state: [8]u32,
    buffer: [SHA256_BLOCK_SIZE]u8,
    buf_len: usize,
    total_len: u64,

    const K: [64]u32 = .{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    pub fn init() Sha256 {
        return .{
            .state = .{
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            },
            .buffer = [_]u8{0} ** SHA256_BLOCK_SIZE,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    pub fn update(self: *Sha256, data: []const u8) void {
        var remaining = data;
        self.total_len += data.len;

        // Fill buffer if partial
        if (self.buf_len > 0) {
            const space = SHA256_BLOCK_SIZE - self.buf_len;
            const to_copy = @min(space, remaining.len);
            @memcpy(self.buffer[self.buf_len..][0..to_copy], remaining[0..to_copy]);
            self.buf_len += to_copy;
            remaining = remaining[to_copy..];

            if (self.buf_len == SHA256_BLOCK_SIZE) {
                self.processBlock(&self.buffer);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while (remaining.len >= SHA256_BLOCK_SIZE) {
            self.processBlock(remaining[0..SHA256_BLOCK_SIZE]);
            remaining = remaining[SHA256_BLOCK_SIZE..];
        }

        // Buffer remainder
        if (remaining.len > 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buf_len = remaining.len;
        }
    }

    pub fn final(self: *Sha256) [SHA256_DIGEST_SIZE]u8 {
        // Padding
        const bit_len = self.total_len * 8;
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buffer[self.buf_len..], 0);
            self.processBlock(&self.buffer);
            self.buf_len = 0;
        }

        @memset(self.buffer[self.buf_len..56], 0);

        // Length in big-endian
        self.buffer[56] = @truncate(bit_len >> 56);
        self.buffer[57] = @truncate(bit_len >> 48);
        self.buffer[58] = @truncate(bit_len >> 40);
        self.buffer[59] = @truncate(bit_len >> 32);
        self.buffer[60] = @truncate(bit_len >> 24);
        self.buffer[61] = @truncate(bit_len >> 16);
        self.buffer[62] = @truncate(bit_len >> 8);
        self.buffer[63] = @truncate(bit_len);

        self.processBlock(&self.buffer);

        // Output digest
        var digest: [SHA256_DIGEST_SIZE]u8 = undefined;
        for (0..8) |i| {
            digest[i * 4] = @truncate(self.state[i] >> 24);
            digest[i * 4 + 1] = @truncate(self.state[i] >> 16);
            digest[i * 4 + 2] = @truncate(self.state[i] >> 8);
            digest[i * 4 + 3] = @truncate(self.state[i]);
        }
        return digest;
    }

    fn processBlock(self: *Sha256, block: *const [64]u8) void {
        var w: [64]u32 = undefined;

        // Parse block into words
        for (0..16) |i| {
            w[i] = @as(u32, block[i * 4]) << 24 |
                @as(u32, block[i * 4 + 1]) << 16 |
                @as(u32, block[i * 4 + 2]) << 8 |
                @as(u32, block[i * 4 + 3]);
        }

        // Extend
        for (16..64) |i| {
            const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] +% s0 +% w[i - 7] +% s1;
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        var f = self.state[5];
        var g = self.state[6];
        var h = self.state[7];

        for (0..64) |i| {
            const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = h +% S1 +% ch +% K[i] +% w[i];
            const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = S0 +% maj;

            h = g;
            g = f;
            f = e;
            e = d +% temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 +% temp2;
        }

        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
        self.state[5] +%= f;
        self.state[6] +%= g;
        self.state[7] +%= h;
    }

    fn rotr32(x: u32, comptime n: u5) u32 {
        return (x >> n) | (x << (32 - n));
    }
};

/// SHA-512 implementation
pub const Sha512 = struct {
    state: [8]u64,
    buffer: [SHA512_BLOCK_SIZE]u8,
    buf_len: usize,
    total_len: u128,

    const K: [80]u64 = .{
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    };

    pub fn init() Sha512 {
        return .{
            .state = .{
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            },
            .buffer = [_]u8{0} ** SHA512_BLOCK_SIZE,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    pub fn update(self: *Sha512, data: []const u8) void {
        var remaining = data;
        self.total_len += data.len;

        if (self.buf_len > 0) {
            const space = SHA512_BLOCK_SIZE - self.buf_len;
            const to_copy = @min(space, remaining.len);
            @memcpy(self.buffer[self.buf_len..][0..to_copy], remaining[0..to_copy]);
            self.buf_len += to_copy;
            remaining = remaining[to_copy..];

            if (self.buf_len == SHA512_BLOCK_SIZE) {
                self.processBlock(&self.buffer);
                self.buf_len = 0;
            }
        }

        while (remaining.len >= SHA512_BLOCK_SIZE) {
            self.processBlock(remaining[0..SHA512_BLOCK_SIZE]);
            remaining = remaining[SHA512_BLOCK_SIZE..];
        }

        if (remaining.len > 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buf_len = remaining.len;
        }
    }

    pub fn final(self: *Sha512) [SHA512_DIGEST_SIZE]u8 {
        const bit_len = self.total_len * 8;
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 112) {
            @memset(self.buffer[self.buf_len..], 0);
            self.processBlock(&self.buffer);
            self.buf_len = 0;
        }

        @memset(self.buffer[self.buf_len..112], 0);

        // 128-bit length in big-endian
        inline for (0..16) |i| {
            self.buffer[112 + i] = @truncate(bit_len >> @as(u7, @intCast((15 - i) * 8)));
        }

        self.processBlock(&self.buffer);

        var digest: [SHA512_DIGEST_SIZE]u8 = undefined;
        for (0..8) |i| {
            inline for (0..8) |j| {
                digest[i * 8 + j] = @truncate(self.state[i] >> @as(u6, @intCast((7 - j) * 8)));
            }
        }
        return digest;
    }

    fn processBlock(self: *Sha512, block: *const [128]u8) void {
        var w: [80]u64 = undefined;

        for (0..16) |i| {
            w[i] = @as(u64, block[i * 8]) << 56 |
                @as(u64, block[i * 8 + 1]) << 48 |
                @as(u64, block[i * 8 + 2]) << 40 |
                @as(u64, block[i * 8 + 3]) << 32 |
                @as(u64, block[i * 8 + 4]) << 24 |
                @as(u64, block[i * 8 + 5]) << 16 |
                @as(u64, block[i * 8 + 6]) << 8 |
                @as(u64, block[i * 8 + 7]);
        }

        for (16..80) |i| {
            const s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            const s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] +% s0 +% w[i - 7] +% s1;
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        var f = self.state[5];
        var g = self.state[6];
        var h = self.state[7];

        for (0..80) |i| {
            const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            const ch = (e & f) ^ (~e & g);
            const temp1 = h +% S1 +% ch +% K[i] +% w[i];
            const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = S0 +% maj;

            h = g;
            g = f;
            f = e;
            e = d +% temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 +% temp2;
        }

        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
        self.state[5] +%= f;
        self.state[6] +%= g;
        self.state[7] +%= h;
    }

    fn rotr64(x: u64, comptime n: u6) u64 {
        return (x >> n) | (x << (64 - n));
    }
};

/// HMAC-SHA256
pub const HmacSha256 = struct {
    inner: Sha256,
    outer_key: [SHA256_BLOCK_SIZE]u8,

    pub fn init(key: []const u8) HmacSha256 {
        var hmac: HmacSha256 = undefined;
        var key_block: [SHA256_BLOCK_SIZE]u8 = [_]u8{0} ** SHA256_BLOCK_SIZE;

        if (key.len > SHA256_BLOCK_SIZE) {
            var hasher = Sha256.init();
            hasher.update(key);
            const hash = hasher.final();
            @memcpy(key_block[0..SHA256_DIGEST_SIZE], &hash);
        } else {
            @memcpy(key_block[0..key.len], key);
        }

        // Inner key = key XOR 0x36
        var inner_key: [SHA256_BLOCK_SIZE]u8 = undefined;
        for (0..SHA256_BLOCK_SIZE) |i| {
            inner_key[i] = key_block[i] ^ 0x36;
            hmac.outer_key[i] = key_block[i] ^ 0x5C;
        }

        hmac.inner = Sha256.init();
        hmac.inner.update(&inner_key);

        return hmac;
    }

    pub fn update(self: *HmacSha256, data: []const u8) void {
        self.inner.update(data);
    }

    pub fn final(self: *HmacSha256) [SHA256_DIGEST_SIZE]u8 {
        const inner_hash = self.inner.final();
        var outer = Sha256.init();
        outer.update(&self.outer_key);
        outer.update(&inner_hash);
        return outer.final();
    }
};

/// ChaCha20 stream cipher
pub const ChaCha20 = struct {
    state: [16]u32,

    pub fn init(key: *const [32]u8, nonce: *const [12]u8, counter: u32) ChaCha20 {
        var cc: ChaCha20 = undefined;

        // "expand 32-byte k"
        cc.state[0] = 0x61707865;
        cc.state[1] = 0x3320646e;
        cc.state[2] = 0x79622d32;
        cc.state[3] = 0x6b206574;

        // Key
        for (0..8) |i| {
            cc.state[4 + i] = readU32Le(key[i * 4 ..][0..4]);
        }

        // Counter
        cc.state[12] = counter;

        // Nonce
        for (0..3) |i| {
            cc.state[13 + i] = readU32Le(nonce[i * 4 ..][0..4]);
        }

        return cc;
    }

    pub fn encrypt(self: *ChaCha20, plaintext: []const u8, ciphertext: []u8) void {
        var block: [64]u8 = undefined;
        var offset: usize = 0;

        while (offset < plaintext.len) {
            self.generateBlock(&block);
            self.state[12] +%= 1; // Increment counter

            const remaining = plaintext.len - offset;
            const block_len = @min(remaining, 64);

            for (0..block_len) |i| {
                ciphertext[offset + i] = plaintext[offset + i] ^ block[i];
            }
            offset += block_len;
        }
    }

    fn generateBlock(self: *const ChaCha20, out: *[64]u8) void {
        var working = self.state;

        // 20 rounds (10 double rounds)
        for (0..10) |_| {
            quarterRound(&working, 0, 4, 8, 12);
            quarterRound(&working, 1, 5, 9, 13);
            quarterRound(&working, 2, 6, 10, 14);
            quarterRound(&working, 3, 7, 11, 15);
            quarterRound(&working, 0, 5, 10, 15);
            quarterRound(&working, 1, 6, 11, 12);
            quarterRound(&working, 2, 7, 8, 13);
            quarterRound(&working, 3, 4, 9, 14);
        }

        // Add original state
        for (0..16) |i| {
            working[i] +%= self.state[i];
            writeU32Le(out[i * 4 ..][0..4], working[i]);
        }
    }

    fn quarterRound(s: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
        s[a] +%= s[b];
        s[d] ^= s[a];
        s[d] = rotl32(s[d], 16);
        s[c] +%= s[d];
        s[b] ^= s[c];
        s[b] = rotl32(s[b], 12);
        s[a] +%= s[b];
        s[d] ^= s[a];
        s[d] = rotl32(s[d], 8);
        s[c] +%= s[d];
        s[b] ^= s[c];
        s[b] = rotl32(s[b], 7);
    }
};

/// Poly1305 MAC
pub const Poly1305 = struct {
    r: [5]u64,
    h: [5]u64,
    pad: [4]u32,
    buffer: [16]u8,
    buf_len: usize,
    finished: bool,

    pub fn init(key: *const [32]u8) Poly1305 {
        var p: Poly1305 = undefined;

        // r = key[0..16] clamped
        const t0 = readU32Le(key[0..4]);
        const t1 = readU32Le(key[4..8]);
        const t2 = readU32Le(key[8..12]);
        const t3 = readU32Le(key[12..16]);

        p.r[0] = t0 & 0x3ffffff;
        p.r[1] = ((t0 >> 26) | (@as(u64, t1) << 6)) & 0x3ffff03;
        p.r[2] = ((t1 >> 20) | (@as(u64, t2) << 12)) & 0x3ffc0ff;
        p.r[3] = ((t2 >> 14) | (@as(u64, t3) << 18)) & 0x3f03fff;
        p.r[4] = (t3 >> 8) & 0x00fffff;

        p.h = [_]u64{0} ** 5;

        p.pad[0] = readU32Le(key[16..20]);
        p.pad[1] = readU32Le(key[20..24]);
        p.pad[2] = readU32Le(key[24..28]);
        p.pad[3] = readU32Le(key[28..32]);

        p.buffer = [_]u8{0} ** 16;
        p.buf_len = 0;
        p.finished = false;

        return p;
    }

    pub fn update(self: *Poly1305, data: []const u8) void {
        var remaining = data;

        if (self.buf_len > 0) {
            const space = 16 - self.buf_len;
            const to_copy = @min(space, remaining.len);
            @memcpy(self.buffer[self.buf_len..][0..to_copy], remaining[0..to_copy]);
            self.buf_len += to_copy;
            remaining = remaining[to_copy..];

            if (self.buf_len == 16) {
                self.processBlock(&self.buffer, false);
                self.buf_len = 0;
            }
        }

        while (remaining.len >= 16) {
            self.processBlock(remaining[0..16], false);
            remaining = remaining[16..];
        }

        if (remaining.len > 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buf_len = remaining.len;
        }
    }

    pub fn final(self: *Poly1305) [16]u8 {
        if (self.buf_len > 0) {
            self.buffer[self.buf_len] = 1;
            @memset(self.buffer[self.buf_len + 1 ..], 0);
            self.processBlock(&self.buffer, true);
        }

        // Finalize
        var h0 = self.h[0];
        var h1 = self.h[1];
        var h2 = self.h[2];
        var h3 = self.h[3];
        var h4 = self.h[4];

        // Full carry
        var c: u64 = undefined;
        c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 +%= c;
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 +%= c;
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 +%= c;
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 +%= c *% 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 +%= c;

        // h + pad
        var f: u64 = undefined;
        f = h0 +% self.pad[0];
        h0 = f & 0xFFFFFFFF;
        f = h1 +% @as(u64, self.pad[1]) +% (f >> 32);
        h1 = f & 0xFFFFFFFF;
        f = h2 +% @as(u64, self.pad[2]) +% (f >> 32);
        h2 = f & 0xFFFFFFFF;
        f = h3 +% @as(u64, self.pad[3]) +% (f >> 32);
        h3 = f & 0xFFFFFFFF;

        var tag: [16]u8 = undefined;
        writeU32Le(tag[0..4], @truncate(h0));
        writeU32Le(tag[4..8], @truncate(h1));
        writeU32Le(tag[8..12], @truncate(h2));
        writeU32Le(tag[12..16], @truncate(h3));
        return tag;
    }

    fn processBlock(self: *Poly1305, block: *const [16]u8, partial: bool) void {
        _ = partial;
        const t0 = readU32Le(block[0..4]);
        const t1 = readU32Le(block[4..8]);
        const t2 = readU32Le(block[8..12]);
        const t3 = readU32Le(block[12..16]);

        self.h[0] +%= t0 & 0x3ffffff;
        self.h[1] +%= ((t0 >> 26) | (@as(u64, t1) << 6)) & 0x3ffffff;
        self.h[2] +%= ((t1 >> 20) | (@as(u64, t2) << 12)) & 0x3ffffff;
        self.h[3] +%= ((t2 >> 14) | (@as(u64, t3) << 18)) & 0x3ffffff;
        self.h[4] +%= (t3 >> 8) | (1 << 24); // hibit

        // Multiply and reduce
        const r0 = self.r[0];
        const r1 = self.r[1];
        const r2 = self.r[2];
        const r3 = self.r[3];
        const r4 = self.r[4];

        const s1 = r1 *% 5;
        const s2 = r2 *% 5;
        const s3 = r3 *% 5;
        const s4 = r4 *% 5;

        var d0 = self.h[0] *% r0 +% self.h[1] *% s4 +% self.h[2] *% s3 +% self.h[3] *% s2 +% self.h[4] *% s1;
        var d1 = self.h[0] *% r1 +% self.h[1] *% r0 +% self.h[2] *% s4 +% self.h[3] *% s3 +% self.h[4] *% s2;
        var d2 = self.h[0] *% r2 +% self.h[1] *% r1 +% self.h[2] *% r0 +% self.h[3] *% s4 +% self.h[4] *% s3;
        var d3 = self.h[0] *% r3 +% self.h[1] *% r2 +% self.h[2] *% r1 +% self.h[3] *% r0 +% self.h[4] *% s4;
        var d4 = self.h[0] *% r4 +% self.h[1] *% r3 +% self.h[2] *% r2 +% self.h[3] *% r1 +% self.h[4] *% r0;

        // Carry propagation
        var c: u64 = undefined;
        c = d0 >> 26;
        self.h[0] = d0 & 0x3ffffff;
        d1 +%= c;
        c = d1 >> 26;
        self.h[1] = d1 & 0x3ffffff;
        d2 +%= c;
        c = d2 >> 26;
        self.h[2] = d2 & 0x3ffffff;
        d3 +%= c;
        c = d3 >> 26;
        self.h[3] = d3 & 0x3ffffff;
        d4 +%= c;
        c = d4 >> 26;
        self.h[4] = d4 & 0x3ffffff;
        self.h[0] +%= c *% 5;
        c = self.h[0] >> 26;
        self.h[0] &= 0x3ffffff;
        self.h[1] +%= c;
    }
};

/// Cryptographic random number generator (CSPRNG)
pub const CryptoRng = struct {
    state: [4]u64,
    entropy_pool: [256]u8,
    pool_idx: usize,
    initialized: bool,

    pub fn init() CryptoRng {
        var rng = CryptoRng{
            .state = [_]u64{0} ** 4,
            .entropy_pool = [_]u8{0} ** 256,
            .pool_idx = 0,
            .initialized = false,
        };

        // Seed from RDRAND if available
        if (hasRdrand()) {
            for (0..4) |i| {
                rng.state[i] = rdrand64();
            }
            rng.initialized = true;
        } else {
            // Fallback: use TSC and other entropy sources
            rng.state[0] = readTsc();
            rng.state[1] = readTsc() ^ 0x5DEECE66D;
            rng.state[2] = readTsc() ^ 0x6C62272E07BB0142;
            rng.state[3] = readTsc() ^ 0x9E3779B97F4A7C15;
            rng.initialized = true;
        }

        return rng;
    }

    pub fn addEntropy(self: *CryptoRng, data: []const u8) void {
        for (data) |byte| {
            self.entropy_pool[self.pool_idx] ^= byte;
            self.pool_idx = (self.pool_idx + 1) % self.entropy_pool.len;
        }
        // Re-seed state from pool periodically
        if (self.pool_idx == 0) {
            self.reseed();
        }
    }

    fn reseed(self: *CryptoRng) void {
        var hasher = Sha256.init();
        hasher.update(&self.entropy_pool);
        for (0..4) |i| {
            var buf: [8]u8 = undefined;
            writeU32Le(buf[0..4], @truncate(self.state[i]));
            writeU32Le(buf[4..8], @truncate(self.state[i] >> 32));
            hasher.update(&buf);
        }
        const hash = hasher.final();
        for (0..4) |i| {
            self.state[i] = @as(u64, hash[i * 8]) |
                @as(u64, hash[i * 8 + 1]) << 8 |
                @as(u64, hash[i * 8 + 2]) << 16 |
                @as(u64, hash[i * 8 + 3]) << 24 |
                @as(u64, hash[i * 8 + 4]) << 32 |
                @as(u64, hash[i * 8 + 5]) << 40 |
                @as(u64, hash[i * 8 + 6]) << 48 |
                @as(u64, hash[i * 8 + 7]) << 56;
        }
    }

    /// Generate random bytes using xoshiro256**
    pub fn fill(self: *CryptoRng, buf: []u8) void {
        var pos: usize = 0;
        while (pos < buf.len) {
            const result = self.next();
            const remaining = buf.len - pos;
            const to_copy = @min(remaining, 8);
            for (0..to_copy) |i| {
                buf[pos + i] = @truncate(result >> @as(u6, @intCast(i * 8)));
            }
            pos += to_copy;
        }
    }

    fn next(self: *CryptoRng) u64 {
        const result = rotl64(self.state[1] *% 5, 7) *% 9;
        const t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];

        self.state[2] ^= t;
        self.state[3] = rotl64(self.state[3], 45);

        return result;
    }
};

/// Hardware random number via RDRAND
fn rdrand64() u64 {
    var val: u64 = undefined;
    var success: u8 = undefined;
    asm volatile (
        \\rdrand %[val]
        \\setc %[success]
        : [val] "=r" (val),
          [success] "=r" (success),
    );
    return if (success != 0) val else 0;
}

fn readTsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return @as(u64, high) << 32 | low;
}

/// Key derivation (HKDF-SHA256)
pub const Hkdf = struct {
    pub fn extract(salt: []const u8, ikm: []const u8) [SHA256_DIGEST_SIZE]u8 {
        var hmac = HmacSha256.init(salt);
        hmac.update(ikm);
        return hmac.final();
    }

    pub fn expand(prk: *const [SHA256_DIGEST_SIZE]u8, info: []const u8, output: []u8) void {
        var t: [SHA256_DIGEST_SIZE]u8 = [_]u8{0} ** SHA256_DIGEST_SIZE;
        var counter: u8 = 1;
        var pos: usize = 0;

        while (pos < output.len) {
            var hmac = HmacSha256.init(prk);
            if (counter > 1) {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[_]u8{counter});
            t = hmac.final();

            const remaining = output.len - pos;
            const to_copy = @min(remaining, SHA256_DIGEST_SIZE);
            @memcpy(output[pos..][0..to_copy], t[0..to_copy]);
            pos += to_copy;
            counter += 1;
        }
    }

    pub fn deriveKey(salt: []const u8, ikm: []const u8, info: []const u8, output: []u8) void {
        const prk = extract(salt, ikm);
        expand(&prk, info, output);
    }
};

/// Global crypto RNG instance
var global_rng: CryptoRng = undefined;
var crypto_initialized: bool = false;

pub fn init() void {
    global_rng = CryptoRng.init();
    crypto_initialized = true;
}

pub fn getRandomBytes(buf: []u8) void {
    if (crypto_initialized) {
        global_rng.fill(buf);
    }
}

pub fn addEntropy(data: []const u8) void {
    if (crypto_initialized) {
        global_rng.addEntropy(data);
    }
}

// Helper functions
fn readU32Le(buf: *const [4]u8) u32 {
    return @as(u32, buf[0]) |
        @as(u32, buf[1]) << 8 |
        @as(u32, buf[2]) << 16 |
        @as(u32, buf[3]) << 24;
}

fn writeU32Le(buf: *[4]u8, val: u32) void {
    buf[0] = @truncate(val);
    buf[1] = @truncate(val >> 8);
    buf[2] = @truncate(val >> 16);
    buf[3] = @truncate(val >> 24);
}

fn rotl32(x: u32, comptime n: u5) u32 {
    return (x << n) | (x >> (32 - n));
}

fn rotl64(x: u64, comptime n: u6) u64 {
    return (x << n) | (x >> (64 - n));
}
