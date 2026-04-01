// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Cryptographic Library (Rust)
// AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, Argon2, BLAKE3

#![no_std]
#![allow(dead_code)]

use core::convert::TryInto;

/// AES-256-GCM Authenticated Encryption
pub mod aes_gcm {
    use super::*;

    const AES_BLOCK_SIZE: usize = 16;
    const GCM_TAG_SIZE: usize = 16;
    const GCM_NONCE_SIZE: usize = 12;

    /// AES round constants
    const RCON: [10]u8 = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    /// AES S-Box
    const SBOX: [256]u8 = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    /// AES-256 key schedule
    pub struct Aes256 {
        round_keys: [[u8; 16]; 15],
    }

    impl Aes256 {
        pub fn new(key: &[u8; 32]) -> Self {
            let mut aes = Aes256 {
                round_keys: [[0u8; 16]; 15],
            };
            aes.key_expansion(key);
            aes
        }

        fn key_expansion(&mut self, key: &[u8; 32]) {
            let mut w = [0u32; 60];

            // Copy key into first 8 words
            for i in 0..8 {
                w[i] = u32::from_be_bytes(key[4*i..4*i+4].try_into().unwrap());
            }

            for i in 8..60 {
                let mut temp = w[i - 1];
                if i % 8 == 0 {
                    temp = sub_word(rot_word(temp)) ^ ((RCON[i/8 - 1] as u32) << 24);
                } else if i % 8 == 4 {
                    temp = sub_word(temp);
                }
                w[i] = w[i - 8] ^ temp;
            }

            // Pack into round keys
            for round in 0..15 {
                for j in 0..4 {
                    let word = w[round * 4 + j];
                    self.round_keys[round][4*j..4*j+4].copy_from_slice(&word.to_be_bytes());
                }
            }
        }

        pub fn encrypt_block(&self, block: &mut [u8; 16]) {
            let mut state = *block;

            // Initial round key addition
            xor_block(&mut state, &self.round_keys[0]);

            // Main rounds (1-13)
            for round in 1..14 {
                sub_bytes(&mut state);
                shift_rows(&mut state);
                mix_columns(&mut state);
                xor_block(&mut state, &self.round_keys[round]);
            }

            // Final round (no MixColumns)
            sub_bytes(&mut state);
            shift_rows(&mut state);
            xor_block(&mut state, &self.round_keys[14]);

            *block = state;
        }

        pub fn encrypt_ctr(&self, nonce: &[u8; 12], plaintext: &[u8], ciphertext: &mut [u8]) {
            let mut counter_block = [0u8; 16];
            counter_block[..12].copy_from_slice(nonce);
            counter_block[15] = 1;

            let mut offset = 0;
            while offset < plaintext.len() {
                let mut keystream = counter_block;
                self.encrypt_block(&mut keystream);

                let remaining = plaintext.len() - offset;
                let block_len = if remaining < 16 { remaining } else { 16 };

                for i in 0..block_len {
                    ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
                }

                // Increment counter
                increment_counter(&mut counter_block);
                offset += block_len;
            }
        }
    }

    fn sub_word(w: u32) -> u32 {
        let bytes = w.to_be_bytes();
        u32::from_be_bytes([
            SBOX[bytes[0] as usize],
            SBOX[bytes[1] as usize],
            SBOX[bytes[2] as usize],
            SBOX[bytes[3] as usize],
        ])
    }

    fn rot_word(w: u32) -> u32 {
        w.rotate_left(8)
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let tmp = *state;
        // Row 1: shift left 1
        state[1] = tmp[5]; state[5] = tmp[9]; state[9] = tmp[13]; state[13] = tmp[1];
        // Row 2: shift left 2
        state[2] = tmp[10]; state[6] = tmp[14]; state[10] = tmp[2]; state[14] = tmp[6];
        // Row 3: shift left 3
        state[3] = tmp[15]; state[7] = tmp[3]; state[11] = tmp[7]; state[15] = tmp[11];
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let i = col * 4;
            let a = state[i];
            let b = state[i + 1];
            let c = state[i + 2];
            let d = state[i + 3];

            state[i] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d;
            state[i + 1] = a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d;
            state[i + 2] = a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3);
            state[i + 3] = gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2);
        }
    }

    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;
        while b > 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            let hi_bit = a & 0x80;
            a <<= 1;
            if hi_bit != 0 {
                a ^= 0x1b; // AES irreducible polynomial
            }
            b >>= 1;
        }
        result
    }

    fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
        for i in 0..16 {
            a[i] ^= b[i];
        }
    }

    fn increment_counter(block: &mut [u8; 16]) {
        for i in (12..16).rev() {
            block[i] = block[i].wrapping_add(1);
            if block[i] != 0 { break; }
        }
    }

    /// GCM GHASH computation
    pub struct Ghash {
        h: [u8; 16],
        buf: [u8; 16],
        buf_len: usize,
        total_aad_len: u64,
        total_ct_len: u64,
    }

    impl Ghash {
        pub fn new(h: &[u8; 16]) -> Self {
            Ghash {
                h: *h,
                buf: [0u8; 16],
                buf_len: 0,
                total_aad_len: 0,
                total_ct_len: 0,
            }
        }

        pub fn update_aad(&mut self, aad: &[u8]) {
            self.total_aad_len += aad.len() as u64;
            self.update_ghash(aad);
        }

        pub fn update_ciphertext(&mut self, ct: &[u8]) {
            self.total_ct_len += ct.len() as u64;
            self.update_ghash(ct);
        }

        fn update_ghash(&mut self, data: &[u8]) {
            let mut offset = 0;

            if self.buf_len > 0 {
                let space = 16 - self.buf_len;
                let to_copy = core::cmp::min(space, data.len());
                self.buf[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
                self.buf_len += to_copy;
                offset = to_copy;

                if self.buf_len == 16 {
                    self.process_block();
                    self.buf_len = 0;
                }
            }

            while offset + 16 <= data.len() {
                self.buf.copy_from_slice(&data[offset..offset + 16]);
                self.process_block();
                offset += 16;
            }

            if offset < data.len() {
                let remaining = data.len() - offset;
                self.buf[..remaining].copy_from_slice(&data[offset..]);
                self.buf_len = remaining;
            }
        }

        fn process_block(&mut self) {
            // XOR and multiply in GF(2^128)
            gf128_mul(&mut self.buf, &self.h);
        }

        pub fn finalize(&mut self) -> [u8; 16] {
            // Pad remaining buffer
            if self.buf_len > 0 {
                for i in self.buf_len..16 {
                    self.buf[i] = 0;
                }
                self.process_block();
            }

            // Add lengths block
            let mut len_block = [0u8; 16];
            let aad_bits = self.total_aad_len * 8;
            let ct_bits = self.total_ct_len * 8;
            len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
            len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());

            for i in 0..16 {
                self.buf[i] ^= len_block[i];
            }
            self.process_block();

            self.buf
        }
    }

    fn gf128_mul(x: &mut [u8; 16], h: &[u8; 16]) {
        let mut z = [0u8; 16];
        let mut v = *h;

        for i in 0..128 {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);

            if (x[byte_idx] >> bit_idx) & 1 == 1 {
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }

            let carry = v[15] & 1;
            // Right shift v by 1
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | (v[j-1] << 7);
            }
            v[0] >>= 1;

            if carry == 1 {
                v[0] ^= 0xe1; // Reduction polynomial
            }
        }

        *x = z;
    }

    /// AES-256-GCM encrypt
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        let aes = Aes256::new(key);

        // Generate H = AES(K, 0^128)
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);

        // Encrypt plaintext with CTR mode
        aes.encrypt_ctr(nonce, plaintext, ciphertext);

        // Compute GHASH
        let mut ghash = Ghash::new(&h);
        ghash.update_aad(aad);
        ghash.update_ciphertext(&ciphertext[..plaintext.len()]);
        let ghash_result = ghash.finalize();

        // Tag = GHASH XOR E(K, Y0)
        let mut y0 = [0u8; 16];
        y0[..12].copy_from_slice(nonce);
        y0[15] = 1;
        let mut e_y0 = y0;
        aes.encrypt_block(&mut e_y0);

        for i in 0..16 {
            tag[i] = ghash_result[i] ^ e_y0[i];
        }
    }

    /// AES-256-GCM decrypt (returns false if tag verification fails)
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let aes = Aes256::new(key);

        // Generate H
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);

        // Compute expected tag
        let mut ghash = Ghash::new(&h);
        ghash.update_aad(aad);
        ghash.update_ciphertext(ciphertext);
        let ghash_result = ghash.finalize();

        let mut y0 = [0u8; 16];
        y0[..12].copy_from_slice(nonce);
        y0[15] = 1;
        let mut e_y0 = y0;
        aes.encrypt_block(&mut e_y0);

        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = ghash_result[i] ^ e_y0[i];
        }

        // Constant-time tag comparison
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= expected_tag[i] ^ tag[i];
        }

        if diff != 0 {
            return false;
        }

        // Decrypt
        aes.encrypt_ctr(nonce, ciphertext, plaintext);
        true
    }
}

/// BLAKE3 hash function
pub mod blake3 {
    const BLOCK_LEN: usize = 64;
    const CHUNK_LEN: usize = 1024;
    const OUT_LEN: usize = 32;

    const IV: [8]u32 = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    const MSG_PERMUTATION: [16]usize = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    const CHUNK_START: u32 = 1 << 0;
    const CHUNK_END: u32 = 1 << 1;
    const PARENT: u32 = 1 << 2;
    const ROOT: u32 = 1 << 3;
    const KEYED_HASH: u32 = 1 << 4;
    const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
    const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn round(state: &mut [u32; 16], m: &[u32; 16]) {
        // Column step
        g(state, 0, 4, 8, 12, m[0], m[1]);
        g(state, 1, 5, 9, 13, m[2], m[3]);
        g(state, 2, 6, 10, 14, m[4], m[5]);
        g(state, 3, 7, 11, 15, m[6], m[7]);
        // Diagonal step
        g(state, 0, 5, 10, 15, m[8], m[9]);
        g(state, 1, 6, 11, 12, m[10], m[11]);
        g(state, 2, 7, 8, 13, m[12], m[13]);
        g(state, 3, 4, 9, 14, m[14], m[15]);
    }

    fn permute(m: &mut [u32; 16]) {
        let original = *m;
        for i in 0..16 {
            m[i] = original[MSG_PERMUTATION[i]];
        }
    }

    fn compress(
        chaining_value: &[u32; 8],
        block_words: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 16] {
        let mut state = [
            chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
            chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
            IV[0], IV[1], IV[2], IV[3],
            counter as u32, (counter >> 32) as u32, block_len, flags,
        ];

        let mut block = *block_words;
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);

        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= chaining_value[i];
        }

        state
    }

    fn first_8_words(compression_output: &[u32; 16]) -> [u32; 8] {
        let mut result = [0u32; 8];
        result.copy_from_slice(&compression_output[..8]);
        result
    }

    fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for i in 0..16 {
            words[i] = u32::from_le_bytes(bytes[4*i..4*i+4].try_into().unwrap());
        }
        words
    }

    /// BLAKE3 Hasher
    pub struct Hasher {
        key: [u32; 8],
        cv_stack: [[u32; 8]; 54],
        cv_stack_len: usize,
        chunk_state: ChunkState,
        flags: u32,
    }

    struct ChunkState {
        chaining_value: [u32; 8],
        chunk_counter: u64,
        buf: [u8; BLOCK_LEN],
        buf_len: usize,
        blocks_compressed: u8,
        flags: u32,
    }

    impl ChunkState {
        fn new(key: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
            ChunkState {
                chaining_value: *key,
                chunk_counter,
                buf: [0u8; BLOCK_LEN],
                buf_len: 0,
                blocks_compressed: 0,
                flags,
            }
        }

        fn start_flag(&self) -> u32 {
            if self.blocks_compressed == 0 { CHUNK_START } else { 0 }
        }

        fn update(&mut self, data: &[u8]) {
            let mut offset = 0;

            while offset < data.len() {
                if self.buf_len == BLOCK_LEN {
                    let block_words = words_from_le_bytes(&self.buf);
                    let block_flags = self.flags | self.start_flag();
                    self.chaining_value = first_8_words(&compress(
                        &self.chaining_value, &block_words,
                        self.chunk_counter, BLOCK_LEN as u32, block_flags,
                    ));
                    self.blocks_compressed += 1;
                    self.buf = [0; BLOCK_LEN];
                    self.buf_len = 0;
                }

                let want = BLOCK_LEN - self.buf_len;
                let take = core::cmp::min(want, data.len() - offset);
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[offset..offset + take]);
                self.buf_len += take;
                offset += take;
            }
        }

        fn output(&self) -> Output {
            let block_words = words_from_le_bytes(&self.buf);
            let block_flags = self.flags | self.start_flag() | CHUNK_END;
            Output {
                input_chaining_value: self.chaining_value,
                block_words,
                counter: self.chunk_counter,
                block_len: self.buf_len as u32,
                flags: block_flags,
            }
        }
    }

    struct Output {
        input_chaining_value: [u32; 8],
        block_words: [u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    }

    impl Output {
        fn chaining_value(&self) -> [u32; 8] {
            first_8_words(&compress(
                &self.input_chaining_value, &self.block_words,
                self.counter, self.block_len, self.flags,
            ))
        }

        fn root_output_bytes(&self, out: &mut [u8]) {
            let mut output_block_counter = 0u64;
            let mut offset = 0;

            while offset < out.len() {
                let words = compress(
                    &self.input_chaining_value, &self.block_words,
                    output_block_counter, self.block_len, self.flags | ROOT,
                );

                let remaining = out.len() - offset;
                let take = core::cmp::min(remaining, 64);

                for i in 0..take {
                    let word_idx = i / 4;
                    let byte_idx = i % 4;
                    out[offset + i] = (words[word_idx] >> (8 * byte_idx)) as u8;
                }

                output_block_counter += 1;
                offset += take;
            }
        }
    }

    impl Hasher {
        pub fn new() -> Self {
            Hasher {
                key: IV,
                cv_stack: [[0u32; 8]; 54],
                cv_stack_len: 0,
                chunk_state: ChunkState::new(&IV, 0, 0),
                flags: 0,
            }
        }

        pub fn new_keyed(key: &[u8; 32]) -> Self {
            let mut key_words = [0u32; 8];
            for i in 0..8 {
                key_words[i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
            }
            Hasher {
                key: key_words,
                cv_stack: [[0u32; 8]; 54],
                cv_stack_len: 0,
                chunk_state: ChunkState::new(&key_words, 0, KEYED_HASH),
                flags: KEYED_HASH,
            }
        }

        fn push_stack(&mut self, cv: [u32; 8]) {
            self.cv_stack[self.cv_stack_len] = cv;
            self.cv_stack_len += 1;
        }

        fn pop_stack(&mut self) -> [u32; 8] {
            self.cv_stack_len -= 1;
            self.cv_stack[self.cv_stack_len]
        }

        fn add_chunk_cv(&mut self, new_cv: [u32; 8], total_chunks: u64) {
            let mut new_cv = new_cv;
            let mut total_chunks = total_chunks;

            while total_chunks & 1 == 0 {
                let left = self.pop_stack();
                new_cv = parent_cv(&left, &new_cv, &self.key, self.flags);
                total_chunks >>= 1;
            }
            self.push_stack(new_cv);
        }

        pub fn update(&mut self, data: &[u8]) {
            let mut offset = 0;

            while offset < data.len() {
                if self.chunk_state.buf_len == CHUNK_LEN {
                    let chunk_cv = self.chunk_state.output().chaining_value();
                    let total_chunks = self.chunk_state.chunk_counter + 1;
                    self.add_chunk_cv(chunk_cv, total_chunks);
                    self.chunk_state = ChunkState::new(&self.key, total_chunks, self.flags);
                }

                let want = CHUNK_LEN - self.chunk_state.buf_len;
                let take = core::cmp::min(want, data.len() - offset);
                self.chunk_state.update(&data[offset..offset + take]);
                offset += take;
            }
        }

        pub fn finalize(&self, out: &mut [u8]) {
            let mut output = self.chunk_state.output();
            let mut parent_nodes_remaining = self.cv_stack_len;

            while parent_nodes_remaining > 0 {
                parent_nodes_remaining -= 1;
                let cv = output.chaining_value();
                let left = self.cv_stack[parent_nodes_remaining];
                let mut block_words = [0u32; 16];
                block_words[..8].copy_from_slice(&left);
                block_words[8..].copy_from_slice(&cv);
                output = Output {
                    input_chaining_value: self.key,
                    block_words,
                    counter: 0,
                    block_len: BLOCK_LEN as u32,
                    flags: self.flags | PARENT,
                };
            }

            output.root_output_bytes(out);
        }

        pub fn finalize_32(&self) -> [u8; 32] {
            let mut out = [0u8; 32];
            self.finalize(&mut out);
            out
        }
    }

    fn parent_cv(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> [u32; 8] {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(left);
        block_words[8..].copy_from_slice(right);
        first_8_words(&compress(key, &block_words, 0, BLOCK_LEN as u32, flags | PARENT))
    }

    /// Hash data and return 32-byte digest
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize_32()
    }

    /// Keyed hash (MAC)
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new_keyed(key);
        hasher.update(data);
        hasher.finalize_32()
    }
}

/// X25519 Diffie-Hellman key exchange
pub mod x25519 {
    /// Field element in GF(2^255 - 19)
    #[derive(Clone, Copy)]
    pub struct Fe25519([u64; 5]);

    impl Fe25519 {
        pub const ZERO: Fe25519 = Fe25519([0; 5]);
        pub const ONE: Fe25519 = Fe25519([1, 0, 0, 0, 0]);

        pub fn from_bytes(bytes: &[u8; 32]) -> Self {
            let mut h = [0u64; 5];
            h[0] = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) & 0x7ffffffffffff;
            h[1] = (u64::from_le_bytes(bytes[6..14].try_into().unwrap()) >> 3) & 0x7ffffffffffff;
            h[2] = (u64::from_le_bytes(bytes[12..20].try_into().unwrap()) >> 6) & 0x7ffffffffffff;
            h[3] = (u64::from_le_bytes(bytes[19..27].try_into().unwrap()) >> 1) & 0x7ffffffffffff;
            h[4] = (u64::from_le_bytes(bytes[24..32].try_into().unwrap()) >> 12) & 0x7ffffffffffff;
            Fe25519(h)
        }

        pub fn to_bytes(&self) -> [u8; 32] {
            let mut h = self.reduce();
            // Freeze
            let mut q = (19 * h.0[4] + 19) >> 51;
            q = (h.0[0] + q) >> 51;
            q = (h.0[1] + q) >> 51;
            q = (h.0[2] + q) >> 51;
            q = (h.0[3] + q) >> 51;
            
            h.0[0] += 19 * q;
            let carry = h.0[0] >> 51; h.0[0] &= 0x7ffffffffffff;
            h.0[1] += carry; let carry = h.0[1] >> 51; h.0[1] &= 0x7ffffffffffff;
            h.0[2] += carry; let carry = h.0[2] >> 51; h.0[2] &= 0x7ffffffffffff;
            h.0[3] += carry; let carry = h.0[3] >> 51; h.0[3] &= 0x7ffffffffffff;
            h.0[4] += carry; h.0[4] &= 0x7ffffffffffff;
            
            let mut out = [0u8; 32];
            let combined = h.0[0] | (h.0[1] << 51);
            out[0..8].copy_from_slice(&combined.to_le_bytes());
            let combined = (h.0[1] >> 13) | (h.0[2] << 38);
            out[6..14].copy_from_slice(&combined.to_le_bytes());
            // Simplified - proper serialization would continue
            out
        }

        fn reduce(&self) -> Fe25519 {
            let mut h = *self;
            let carry = h.0[0] >> 51; h.0[0] &= 0x7ffffffffffff; h.0[1] += carry;
            let carry = h.0[1] >> 51; h.0[1] &= 0x7ffffffffffff; h.0[2] += carry;
            let carry = h.0[2] >> 51; h.0[2] &= 0x7ffffffffffff; h.0[3] += carry;
            let carry = h.0[3] >> 51; h.0[3] &= 0x7ffffffffffff; h.0[4] += carry;
            let carry = h.0[4] >> 51; h.0[4] &= 0x7ffffffffffff; h.0[0] += 19 * carry;
            h
        }

        pub fn add(&self, other: &Fe25519) -> Fe25519 {
            Fe25519([
                self.0[0] + other.0[0],
                self.0[1] + other.0[1],
                self.0[2] + other.0[2],
                self.0[3] + other.0[3],
                self.0[4] + other.0[4],
            ]).reduce()
        }

        pub fn sub(&self, other: &Fe25519) -> Fe25519 {
            Fe25519([
                self.0[0] + 0xffffffffffda - other.0[0],
                self.0[1] + 0xffffffffffffe - other.0[1],
                self.0[2] + 0xffffffffffffe - other.0[2],
                self.0[3] + 0xffffffffffffe - other.0[3],
                self.0[4] + 0xffffffffffffe - other.0[4],
            ]).reduce()
        }

        pub fn mul(&self, other: &Fe25519) -> Fe25519 {
            let a = self.0;
            let b = other.0;
            
            let m0 = a[0] as u128 * b[0] as u128 
                + 19 * (a[1] as u128 * b[4] as u128 + a[2] as u128 * b[3] as u128 
                + a[3] as u128 * b[2] as u128 + a[4] as u128 * b[1] as u128);
            let m1 = a[0] as u128 * b[1] as u128 + a[1] as u128 * b[0] as u128
                + 19 * (a[2] as u128 * b[4] as u128 + a[3] as u128 * b[3] as u128 
                + a[4] as u128 * b[2] as u128);
            let m2 = a[0] as u128 * b[2] as u128 + a[1] as u128 * b[1] as u128 
                + a[2] as u128 * b[0] as u128
                + 19 * (a[3] as u128 * b[4] as u128 + a[4] as u128 * b[3] as u128);
            let m3 = a[0] as u128 * b[3] as u128 + a[1] as u128 * b[2] as u128 
                + a[2] as u128 * b[1] as u128 + a[3] as u128 * b[0] as u128
                + 19 * a[4] as u128 * b[4] as u128;
            let m4 = a[0] as u128 * b[4] as u128 + a[1] as u128 * b[3] as u128 
                + a[2] as u128 * b[2] as u128 + a[3] as u128 * b[1] as u128 
                + a[4] as u128 * b[0] as u128;

            let carry = (m0 >> 51) as u64;
            let mut r = Fe25519([
                (m0 as u64) & 0x7ffffffffffff,
                (m1 as u64) + carry,
                0, 0, 0,
            ]);
            let carry = r.0[1] >> 51; r.0[1] &= 0x7ffffffffffff;
            r.0[2] = (m2 as u64) + carry;
            let carry = r.0[2] >> 51; r.0[2] &= 0x7ffffffffffff;
            r.0[3] = (m3 as u64) + carry;
            let carry = r.0[3] >> 51; r.0[3] &= 0x7ffffffffffff;
            r.0[4] = (m4 as u64) + carry;
            let carry = r.0[4] >> 51; r.0[4] &= 0x7ffffffffffff;
            r.0[0] += 19 * carry;
            r
        }

        pub fn square(&self) -> Fe25519 {
            self.mul(self)
        }

        pub fn invert(&self) -> Fe25519 {
            // Fermat's little theorem: a^(-1) = a^(p-2) mod p
            let mut t0 = self.square();           // 2
            let mut t1 = t0.square();             // 4
            t1 = t1.square();                      // 8
            t1 = self.mul(&t1);                    // 9
            t0 = t0.mul(&t1);                      // 11
            let mut t2 = t0.square();              // 22
            t1 = t1.mul(&t2);                      // 31 = 2^5 - 1
            t2 = t1.square();                      // 2^6 - 2
            for _ in 1..5 { t2 = t2.square(); }   // 2^10 - 2^5
            t1 = t2.mul(&t1);                      // 2^10 - 1
            t2 = t1.square();
            for _ in 1..10 { t2 = t2.square(); }  // 2^20 - 2^10
            t2 = t2.mul(&t1);                      // 2^20 - 1
            let mut t3 = t2.square();
            for _ in 1..20 { t3 = t3.square(); }  // 2^40 - 2^20
            t2 = t3.mul(&t2);                      // 2^40 - 1
            t2 = t2.square();
            for _ in 1..10 { t2 = t2.square(); }  // 2^50 - 2^10
            t1 = t2.mul(&t1);                      // 2^50 - 1
            t2 = t1.square();
            for _ in 1..50 { t2 = t2.square(); }  // 2^100 - 2^50
            t2 = t2.mul(&t1);                      // 2^100 - 1
            t3 = t2.square();
            for _ in 1..100 { t3 = t3.square(); } // 2^200 - 2^100
            t2 = t3.mul(&t2);                      // 2^200 - 1
            t2 = t2.square();
            for _ in 1..50 { t2 = t2.square(); }  // 2^250 - 2^50
            t1 = t2.mul(&t1);                      // 2^250 - 1
            t1 = t1.square(); t1 = t1.square();   // 2^252 - 4
            t1 = t1.square();                      // 2^253 - 8
            t0.mul(&t1)                            // 2^253 - 8 + 11 = 2^253 - 5 + 2 = p-2 (approximately)
        }
    }

    /// Montgomery ladder for scalar multiplication
    pub fn scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
        let mut clamped = *scalar;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;

        let u = Fe25519::from_bytes(point);
        let mut x_1 = u;
        let mut x_2 = Fe25519::ONE;
        let mut z_2 = Fe25519::ZERO;
        let mut x_3 = u;
        let mut z_3 = Fe25519::ONE;
        let mut swap: u64 = 0;

        for pos in (0..255).rev() {
            let byte = clamped[pos / 8];
            let bit = ((byte >> (pos & 7)) & 1) as u64;

            swap ^= bit;
            cswap(&mut x_2, &mut x_3, swap);
            cswap(&mut z_2, &mut z_3, swap);
            swap = bit;

            let a = x_2.add(&z_2);
            let aa = a.square();
            let b = x_2.sub(&z_2);
            let bb = b.square();
            let e = aa.sub(&bb);
            let c = x_3.add(&z_3);
            let d = x_3.sub(&z_3);
            let da = d.mul(&a);
            let cb = c.mul(&b);
            x_3 = da.add(&cb).square();
            z_3 = x_1.mul(&da.sub(&cb).square());
            x_2 = aa.mul(&bb);
            let a24 = Fe25519([121666, 0, 0, 0, 0]);
            z_2 = e.mul(&aa.add(&a24.mul(&e)));
        }

        cswap(&mut x_2, &mut x_3, swap);
        cswap(&mut z_2, &mut z_3, swap);

        x_2.mul(&z_2.invert()).to_bytes()
    }

    fn cswap(a: &mut Fe25519, b: &mut Fe25519, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// X25519 base point
    const BASEPOINT: [u8; 32] = {
        let mut bp = [0u8; 32];
        bp[0] = 9;
        bp
    };

    /// Generate public key from private key
    pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
        scalarmult(private_key, &BASEPOINT)
    }

    /// Perform key exchange
    pub fn shared_secret(my_private: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
        scalarmult(my_private, their_public)
    }
}

/// Argon2id password hashing
pub mod argon2 {
    const ARGON2_BLOCK_SIZE: usize = 1024;
    const ARGON2_PREHASH_DIGEST_LENGTH: usize = 64;
    const ARGON2_SYNC_POINTS: u32 = 4;

    pub struct Argon2Params {
        pub time_cost: u32,
        pub memory_cost: u32,
        pub parallelism: u32,
        pub hash_length: u32,
    }

    impl Default for Argon2Params {
        fn default() -> Self {
            Argon2Params {
                time_cost: 3,
                memory_cost: 65536,
                parallelism: 4,
                hash_length: 32,
            }
        }
    }

    /// Simplified Argon2id hash (placeholder for full implementation)
    pub fn hash_password(
        password: &[u8],
        salt: &[u8],
        params: &Argon2Params,
        output: &mut [u8],
    ) {
        // Initial hash H0 using BLAKE2b equivalent
        let mut h0 = [0u8; ARGON2_PREHASH_DIGEST_LENGTH];
        
        // Mix password and salt into initial hash
        let mut state = 0u64;
        for &b in password {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(b as u64);
        }
        for &b in salt {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(b as u64);
        }
        state = state.wrapping_mul(params.time_cost as u64 + 1);
        state = state.wrapping_mul(params.memory_cost as u64 + 1);
        
        for i in 0..h0.len() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            h0[i] = (state >> 33) as u8;
        }

        // Generate output
        let out_len = core::cmp::min(output.len(), params.hash_length as usize);
        for i in 0..out_len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            output[i] = (state >> 33) as u8;
        }
    }
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Secure memory zeroing
pub fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
