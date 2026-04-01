// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Compression Algorithms (zstd, lz4, deflate)
// Streaming compression for block layer, filesystem, network

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// LZ4 Compression
// ============================================================================

/// LZ4 constants
pub const LZ4_MIN_MATCH: usize = 4;
pub const LZ4_MAX_INPUT_SIZE: usize = 0x7E000000;
pub const LZ4_HASH_LOG: usize = 16;
pub const LZ4_HASH_TABLE_SIZE: usize = 1 << LZ4_HASH_LOG;
pub const LZ4_SKIP_TRIGGER: usize = 6;
pub const LZ4_COPY_LENGTH: usize = 8;
pub const LZ4_ML_BITS: usize = 4;
pub const LZ4_ML_MASK: usize = (1 << LZ4_ML_BITS) - 1;
pub const LZ4_RUN_BITS: usize = 8 - LZ4_ML_BITS;
pub const LZ4_RUN_MASK: usize = (1 << LZ4_RUN_BITS) - 1;
pub const LZ4_LAST_LITERALS: usize = 5;
pub const LZ4_MF_LIMIT: usize = LZ4_COPY_LENGTH + LZ4_MIN_MATCH;

/// LZ4 compression context
pub struct Lz4Ctx {
    hash_table: [u32; LZ4_HASH_TABLE_SIZE],
}

impl Lz4Ctx {
    pub fn new() -> Self {
        Lz4Ctx {
            hash_table: [0; LZ4_HASH_TABLE_SIZE],
        }
    }

    fn hash_position(sequence: u32) -> usize {
        ((sequence.wrapping_mul(2654435761)) >> (32 - LZ4_HASH_LOG)) as usize
    }

    /// Compress data using LZ4
    pub fn compress(&mut self, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        if src.is_empty() || dst.is_empty() || src.len() > LZ4_MAX_INPUT_SIZE {
            return None;
        }

        // Reset hash table
        for entry in self.hash_table.iter_mut() {
            *entry = 0;
        }

        let src_len = src.len();
        let mut ip = 0usize; // input pointer
        let mut op = 0usize; // output pointer
        let mut anchor = 0usize;
        let src_limit = src_len - LZ4_LAST_LITERALS;
        let mf_limit = src_len - LZ4_MF_LIMIT;

        if src_len < LZ4_MF_LIMIT + 1 {
            // Input too small, just store literals
            return self.write_last_literals(src, anchor, dst, op);
        }

        // First byte
        ip += 1;
        let mut fwd_h = Self::hash_position(read_u32_le(src, ip));

        loop {
            let mut fwd_ip = ip;
            let mut step = 1usize;
            let mut search_match_nb = 1u32 << LZ4_SKIP_TRIGGER;

            // Find a match
            let match_pos;
            loop {
                let h = fwd_h;
                ip = fwd_ip;
                fwd_ip += step;
                step = (search_match_nb >> LZ4_SKIP_TRIGGER) as usize;
                search_match_nb += 1;

                if fwd_ip > mf_limit {
                    return self.write_last_literals(src, anchor, dst, op);
                }

                match_pos = self.hash_table[h] as usize;
                fwd_h = Self::hash_position(read_u32_le(src, fwd_ip));
                self.hash_table[h] = ip as u32;

                if ip.wrapping_sub(match_pos) <= 65535 
                    && read_u32_le(src, match_pos) == read_u32_le(src, ip) {
                    break;
                }
            }

            // Encode literals
            let lit_length = ip - anchor;
            let token_pos = op;
            op += 1;
            if op >= dst.len() { return None; }

            if lit_length >= LZ4_RUN_MASK {
                dst[token_pos] = (LZ4_RUN_MASK << LZ4_ML_BITS) as u8;
                let mut remaining = lit_length - LZ4_RUN_MASK;
                while remaining >= 255 {
                    if op >= dst.len() { return None; }
                    dst[op] = 255;
                    op += 1;
                    remaining -= 255;
                }
                if op >= dst.len() { return None; }
                dst[op] = remaining as u8;
                op += 1;
            } else {
                dst[token_pos] = ((lit_length as u8) << LZ4_ML_BITS as u8) & 0xF0;
            }

            // Copy literals
            if op + lit_length > dst.len() { return None; }
            dst[op..op + lit_length].copy_from_slice(&src[anchor..anchor + lit_length]);
            op += lit_length;

            // Encode offset
            let offset = (ip - match_pos) as u16;
            if op + 2 > dst.len() { return None; }
            dst[op] = offset as u8;
            dst[op + 1] = (offset >> 8) as u8;
            op += 2;

            // Count match length
            ip += LZ4_MIN_MATCH;
            let mut match_p = match_pos + LZ4_MIN_MATCH;
            let mut ml = 0usize;
            while ip + ml < src_limit && match_p + ml < src_len 
                  && src[ip + ml] == src[match_p + ml] {
                ml += 1;
            }

            // Encode match length
            if ml >= LZ4_ML_MASK {
                dst[token_pos] |= LZ4_ML_MASK as u8;
                let mut remaining = ml - LZ4_ML_MASK;
                while remaining >= 255 {
                    if op >= dst.len() { return None; }
                    dst[op] = 255;
                    op += 1;
                    remaining -= 255;
                }
                if op >= dst.len() { return None; }
                dst[op] = remaining as u8;
                op += 1;
            } else {
                dst[token_pos] |= ml as u8;
            }

            ip += ml;
            anchor = ip;

            if ip > mf_limit { break; }

            // Update hash
            self.hash_table[Self::hash_position(read_u32_le(src, ip - 2))] = (ip - 2) as u32;

            let h = Self::hash_position(read_u32_le(src, ip));
            let mp = self.hash_table[h] as usize;
            self.hash_table[h] = ip as u32;

            if ip.wrapping_sub(mp) <= 65535 && read_u32_le(src, mp) == read_u32_le(src, ip) {
                // We have another match immediately
                let token_pos2 = op;
                op += 1;
                if op >= dst.len() { return None; }
                dst[token_pos2] = 0; // 0 literals
                
                let off = (ip - mp) as u16;
                if op + 2 > dst.len() { return None; }
                dst[op] = off as u8;
                dst[op + 1] = (off >> 8) as u8;
                op += 2;
                
                ip += LZ4_MIN_MATCH;
                anchor = ip;
                continue;
            }

            fwd_h = Self::hash_position(read_u32_le(src, ip));
        }

        self.write_last_literals(src, anchor, dst, op)
    }

    fn write_last_literals(&self, src: &[u8], anchor: usize, dst: &mut [u8], mut op: usize) -> Option<usize> {
        let lit_length = src.len() - anchor;
        
        if op >= dst.len() { return None; }
        
        if lit_length >= LZ4_RUN_MASK {
            dst[op] = (LZ4_RUN_MASK << LZ4_ML_BITS) as u8;
            op += 1;
            let mut remaining = lit_length - LZ4_RUN_MASK;
            while remaining >= 255 {
                if op >= dst.len() { return None; }
                dst[op] = 255;
                op += 1;
                remaining -= 255;
            }
            if op >= dst.len() { return None; }
            dst[op] = remaining as u8;
            op += 1;
        } else {
            dst[op] = (lit_length << LZ4_ML_BITS) as u8;
            op += 1;
        }

        if op + lit_length > dst.len() { return None; }
        dst[op..op + lit_length].copy_from_slice(&src[anchor..]);
        op += lit_length;
        
        Some(op)
    }

    /// Decompress LZ4 data  
    pub fn decompress(src: &[u8], dst: &mut [u8], original_size: usize) -> Option<usize> {
        let mut ip = 0usize;
        let mut op = 0usize;

        while ip < src.len() && op < original_size {
            let token = src[ip];
            ip += 1;

            // Decode literal length
            let mut lit_length = ((token >> 4) & 0xF) as usize;
            if lit_length == 15 {
                loop {
                    if ip >= src.len() { return None; }
                    let s = src[ip] as usize;
                    ip += 1;
                    lit_length += s;
                    if s != 255 { break; }
                }
            }

            // Copy literals
            if op + lit_length > dst.len() || ip + lit_length > src.len() {
                return None;
            }
            dst[op..op + lit_length].copy_from_slice(&src[ip..ip + lit_length]);
            ip += lit_length;
            op += lit_length;

            if op >= original_size { return Some(op); }

            // Decode offset
            if ip + 2 > src.len() { return None; }
            let offset = src[ip] as usize | ((src[ip + 1] as usize) << 8);
            ip += 2;
            if offset == 0 || offset > op { return None; }

            // Decode match length
            let mut match_length = (token & 0xF) as usize + LZ4_MIN_MATCH;
            if (token & 0xF) == 15 {
                loop {
                    if ip >= src.len() { return None; }
                    let s = src[ip] as usize;
                    ip += 1;
                    match_length += s;
                    if s != 255 { break; }
                }
            }

            // Copy match
            let match_pos = op - offset;
            if op + match_length > dst.len() { return None; }
            for i in 0..match_length {
                dst[op + i] = dst[match_pos + i];
            }
            op += match_length;
        }

        Some(op)
    }
}

fn read_u32_le(data: &[u8], pos: usize) -> u32 {
    if pos + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

// ============================================================================
// ZSTD-like Compression (Simplified Finite State Entropy)
// ============================================================================

/// Huffman tree node
pub struct HuffmanNode {
    pub symbol: u16,
    pub weight: u32,
    pub parent: u16,
    pub left: u16,
    pub right: u16,
}

/// Huffman table for encoding
pub struct HuffmanTable {
    pub codes: [u32; 256],
    pub code_lens: [u8; 256],
    pub max_code_len: u8,
    pub symbol_count: u16,
}

impl HuffmanTable {
    pub fn new() -> Self {
        HuffmanTable {
            codes: [0; 256],
            code_lens: [0; 256],
            max_code_len: 0,
            symbol_count: 0,
        }
    }

    /// Build Huffman table from frequency count
    pub fn build(&mut self, freq: &[u32; 256]) {
        // Find active symbols
        let mut active_count = 0u16;
        for i in 0..256 {
            if freq[i] > 0 { active_count += 1; }
        }
        self.symbol_count = active_count;
        if active_count <= 1 {
            if active_count == 1 {
                for i in 0..256 {
                    if freq[i] > 0 {
                        self.codes[i] = 0;
                        self.code_lens[i] = 1;
                        break;
                    }
                }
            }
            return;
        }

        // Simple code length assignment based on frequency ranking
        let mut total: u64 = 0;
        for f in freq.iter() { total += *f as u64; }
        if total == 0 { return; }

        for i in 0..256 {
            if freq[i] == 0 {
                self.code_lens[i] = 0;
                continue;
            }
            // Approximate: higher freq = shorter code
            let prob = (freq[i] as u64 * 256) / total;
            let bits = if prob >= 128 { 2 }
                      else if prob >= 64 { 3 }
                      else if prob >= 32 { 4 }
                      else if prob >= 16 { 5 }
                      else if prob >= 8 { 6 }
                      else if prob >= 4 { 7 }
                      else if prob >= 2 { 8 }
                      else { 9 };
            self.code_lens[i] = bits;
            if bits > self.max_code_len { self.max_code_len = bits; }
        }

        // Canonical Huffman coding: assign codes based on lengths
        self.assign_canonical_codes();
    }

    fn assign_canonical_codes(&mut self) {
        let mut bl_count = [0u32; 16]; // Count per bit length
        for i in 0..256 {
            if self.code_lens[i] > 0 {
                bl_count[self.code_lens[i] as usize] += 1;
            }
        }

        let mut next_code = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..=self.max_code_len as usize {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for i in 0..256 {
            let len = self.code_lens[i] as usize;
            if len > 0 {
                self.codes[i] = next_code[len];
                next_code[len] += 1;
            }
        }
    }
}

/// Finite State Entropy (FSE) table
pub struct FseTable {
    pub states: [FseState; 4096],
    pub accuracy_log: u8, // Table size = 1 << accuracy_log
    pub max_symbol: u16,
}

pub struct FseState {
    pub symbol: u16,
    pub bits_to_read: u8,
    pub base_value: u16,
}

/// ZSTD frame header
#[repr(C, packed)]
pub struct ZstdFrameHeader {
    pub magic: u32,           // 0xFD2FB528
    pub frame_header_desc: u8,
    // Variable fields follow based on frame_header_desc
}

pub const ZSTD_MAGIC: u32 = 0xFD2FB528;
pub const ZSTD_SKIPPABLE_MAGIC: u32 = 0x184D2A50;

/// ZSTD block types
#[derive(Debug, Clone, Copy)]
pub enum ZstdBlockType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
    Reserved = 3,
}

/// Simplified ZSTD-lik encoder state
pub struct ZstdEncoder {
    pub window_log: u8,     // 10-31
    pub chain_log: u8,
    pub hash_log: u8,
    pub search_log: u8,
    pub min_match: u8,
    pub strategy: ZstdStrategy,
    pub level: i32,
    // State
    pub hash_table: [u32; 65536],
    pub chain_table: [u32; 65536],
    pub lit_freq: [u32; 256],
    pub match_len_freq: [u32; 256],
    pub offset_freq: [u32; 32],
    // Output
    pub huffman: HuffmanTable,
    // Statistics
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ZstdStrategy {
    Fast = 1,
    DFast = 2,
    Greedy = 3,
    Lazy = 4,
    Lazy2 = 5,
    BtLazy2 = 6,
    BtOpt = 7,
    BtUltra = 8,
    BtUltra2 = 9,
}

impl ZstdEncoder {
    pub fn new(level: i32) -> Self {
        let (window_log, chain_log, hash_log, search_log, min_match, strategy) = match level {
            1 => (19, 12, 13, 1, 6, ZstdStrategy::Fast),
            2..=3 => (20, 14, 15, 2, 5, ZstdStrategy::DFast),
            4..=6 => (21, 16, 17, 4, 4, ZstdStrategy::Greedy),
            7..=9 => (22, 18, 18, 5, 4, ZstdStrategy::Lazy),
            10..=12 => (23, 19, 19, 6, 4, ZstdStrategy::Lazy2),
            13..=15 => (24, 20, 20, 7, 4, ZstdStrategy::BtLazy2),
            16..=18 => (25, 21, 21, 8, 3, ZstdStrategy::BtOpt),
            19..=21 => (26, 22, 22, 9, 3, ZstdStrategy::BtUltra),
            _ => (27, 23, 23, 10, 3, ZstdStrategy::BtUltra2),
        };

        ZstdEncoder {
            window_log,
            chain_log,
            hash_log,
            search_log,
            min_match,
            strategy,
            level,
            hash_table: [0; 65536],
            chain_table: [0; 65536],
            lit_freq: [0; 256],
            match_len_freq: [0; 256],
            offset_freq: [0; 32],
            huffman: HuffmanTable::new(),
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    /// Compress a block of data
    pub fn compress_block(&mut self, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        self.bytes_in += src.len() as u64;
        
        // Reset frequency tables
        for f in self.lit_freq.iter_mut() { *f = 0; }
        
        // Count literal frequencies
        for &b in src.iter() {
            self.lit_freq[b as usize] += 1;
        }
        
        // Build Huffman table
        self.huffman.build(&self.lit_freq);
        
        // Write frame header
        let mut op = 0;
        if op + 4 > dst.len() { return None; }
        dst[op..op+4].copy_from_slice(&ZSTD_MAGIC.to_le_bytes());
        op += 4;
        
        // Frame header descriptor
        if op >= dst.len() { return None; }
        let fhd = (self.window_log.saturating_sub(10)) << 5;
        dst[op] = fhd;
        op += 1;
        
        // Window size
        if op >= dst.len() { return None; }
        dst[op] = self.window_log;
        op += 1;
        
        // Original size
        if op + 4 > dst.len() { return None; }
        dst[op..op+4].copy_from_slice(&(src.len() as u32).to_le_bytes());
        op += 4;
        
        // Compressed block (simplified: RLE for runs, literal otherwise)
        let compressed = self.compress_sequences(src, &mut dst[op..])?;
        op += compressed;
        
        self.bytes_out += op as u64;
        Some(op)
    }

    fn compress_sequences(&mut self, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        // Very simplified: check if RLE is beneficial
        if src.is_empty() { return Some(0); }
        
        let first = src[0];
        let all_same = src.iter().all(|&b| b == first);
        
        if all_same && src.len() > 3 {
            // RLE block
            let mut op = 0;
            if op + 3 > dst.len() { return None; }
            // Block header: type=RLE, last=1, size
            let header: u32 = (1 << 0) // last block
                | (1 << 1)  // block type RLE
                | ((src.len() as u32) << 3);
            dst[op] = header as u8;
            dst[op+1] = (header >> 8) as u8;
            dst[op+2] = (header >> 16) as u8;
            op += 3;
            if op >= dst.len() { return None; }
            dst[op] = first;
            op += 1;
            return Some(op);
        }
        
        // Raw block (no compression benefit)
        let mut op = 0;
        if op + 3 > dst.len() { return None; }
        let header: u32 = (1 << 0) // last block
            | (0 << 1) // block type raw
            | ((src.len() as u32) << 3);
        dst[op] = header as u8;
        dst[op+1] = (header >> 8) as u8;
        dst[op+2] = (header >> 16) as u8;
        op += 3;
        
        if op + src.len() > dst.len() { return None; }
        dst[op..op+src.len()].copy_from_slice(src);
        op += src.len();
        
        Some(op)
    }

    pub fn compression_ratio(&self) -> f32 {
        if self.bytes_out == 0 { return 0.0; }
        self.bytes_in as f32 / self.bytes_out as f32
    }
}

// ============================================================================
// DEFLATE (RFC 1951) Implementation
// ============================================================================

/// Deflate constants
pub const DEFLATE_MAX_MATCH: usize = 258;
pub const DEFLATE_MIN_MATCH: usize = 3;
pub const DEFLATE_WINDOW_SIZE: usize = 32768;
pub const DEFLATE_MAX_CODE_LENGTH: usize = 15;
pub const DEFLATE_NUM_LITERALS: usize = 286;
pub const DEFLATE_NUM_DISTANCES: usize = 30;

/// Fixed Huffman code lengths for literals/lengths (RFC 1951 Section 3.2.6)
pub fn fixed_literal_lengths() -> [u8; 288] {
    let mut lengths = [0u8; 288];
    let mut i = 0;
    while i <= 143 { lengths[i] = 8; i += 1; }
    while i <= 255 { lengths[i] = 9; i += 1; }
    while i <= 279 { lengths[i] = 7; i += 1; }
    while i <= 287 { lengths[i] = 8; i += 1; }
    lengths
}

/// Length base values
pub static LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13,
    15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258, 
];

/// Length extra bits
pub static LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
    1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Distance base values
pub static DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25,
    33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// Distance extra bits
pub static DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// Adler-32 checksum (used in zlib)
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    
    (b << 16) | a
}

/// CRC-32 (used in gzip)
pub fn crc32(data: &[u8]) -> u32 {
    static CRC_TABLE: [u32; 256] = crc32_make_table();
    
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[index];
    }
    !crc
}

const fn crc32_make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

// ============================================================================
// Compression Interface
// ============================================================================

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressAlgo {
    None,
    Lz4,
    Lz4Hc,
    Zstd,
    Deflate,
    Lzo,
    Brotli,
    Zlib,
    // Zxyphor
    ZxyFast,    // Ultra-fast for latency-critical
    ZxyRatio,   // Best ratio for archival
}

/// Compression level presets
#[derive(Debug, Clone, Copy)]
pub enum CompressLevel {
    Fastest = 1,
    Fast = 3,
    Default = 6,
    Better = 9,
    Best = 12,
    Ultra = 22,
}

/// Compression statistics
pub struct CompressStats {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub compress_calls: AtomicU64,
    pub decompress_calls: AtomicU64,
    pub compress_errors: AtomicU64,
    pub decompress_errors: AtomicU64,
    pub compress_ns: AtomicU64, // Total time in nanoseconds
    pub decompress_ns: AtomicU64,
}

impl CompressStats {
    pub const fn new() -> Self {
        CompressStats {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            compress_calls: AtomicU64::new(0),
            decompress_calls: AtomicU64::new(0),
            compress_errors: AtomicU64::new(0),
            decompress_errors: AtomicU64::new(0),
            compress_ns: AtomicU64::new(0),
            decompress_ns: AtomicU64::new(0),
        }
    }

    pub fn ratio(&self) -> f32 {
        let out = self.bytes_out.load(Ordering::Relaxed);
        if out == 0 { return 1.0; }
        self.bytes_in.load(Ordering::Relaxed) as f32 / out as f32
    }
}

static COMPRESS_STATS: CompressStats = CompressStats::new();

pub fn get_compress_stats() -> &'static CompressStats {
    &COMPRESS_STATS
}
