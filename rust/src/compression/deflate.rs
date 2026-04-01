// =============================================================================
// Kernel Zxyphor — DEFLATE Compression (RFC 1951)
// =============================================================================
// A minimal DEFLATE decompressor for kernel use (filesystem decompression,
// compressed initramfs, gzip support). DEFLATE is the core algorithm behind
// gzip and zlib, used extensively in the Linux kernel.
//
// Implements:
//   - Fixed Huffman code decompression
//   - Dynamic Huffman code decompression
//   - Stored (uncompressed) blocks
//   - Sliding window (32K) for back-references
//
// This is a decompressor only — compression is more complex and less critical
// for kernel cold paths. A simple compressor is provided for kernel logging
// and memory page compression.
// =============================================================================

use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum Huffman code bit length
const MAX_BITS: usize = 15;
/// Maximum number of literal/length codes
const MAX_LIT_CODES: usize = 286;
/// Maximum number of distance codes
const MAX_DIST_CODES: usize = 30;
/// Maximum total codes
const MAX_CODES: usize = MAX_LIT_CODES + MAX_DIST_CODES;
/// Code length code count
const MAX_CL_CODES: usize = 19;

/// Sliding window size (32 KB per RFC 1951)
const WINDOW_SIZE: usize = 32768;
/// Window mask for circular buffer arithmetic
const WINDOW_MASK: usize = WINDOW_SIZE - 1;

/// Fixed Huffman code lengths for literals/lengths (RFC 1951 Section 3.2.6)
const FIXED_LIT_LENGTHS: [288]u8 = {
    let mut arr = [0u8; 288];
    let mut i = 0;
    while i <= 143 {
        arr[i] = 8;
        i += 1;
    }
    while i <= 255 {
        arr[i] = 9;
        i += 1;
    }
    while i <= 279 {
        arr[i] = 7;
        i += 1;
    }
    while i <= 287 {
        arr[i] = 8;
        i += 1;
    }
    arr
};

/// Fixed Huffman code lengths for distances
const FIXED_DIST_LENGTHS: [32]u8 = [5; 32];

/// Extra bits for length codes 257-285
const LENGTH_EXTRA_BITS: [29]u8 = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Base lengths for length codes 257-285
const LENGTH_BASE: [29]u16 = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];

/// Extra bits for distance codes 0-29
const DISTANCE_EXTRA_BITS: [30]u8 = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
    13, 13,
];

/// Base distances for distance codes 0-29
const DISTANCE_BASE: [30]u16 = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// Order of code length codes (RFC 1951 Section 3.2.7)
const CL_CODE_ORDER: [19]usize = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// =============================================================================
// Decompression errors
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeflateError {
    /// Input data is truncated
    UnexpectedEndOfInput,
    /// Invalid block type encountered
    InvalidBlockType,
    /// Invalid stored block length (LEN != ~NLEN)
    InvalidStoredBlockLength,
    /// Huffman code not found in table
    InvalidHuffmanCode,
    /// Code length code decode error
    InvalidCodeLengths,
    /// Back-reference distance exceeds available history
    InvalidDistance,
    /// Output buffer is full
    OutputBufferFull,
    /// Invalid DEFLATE stream
    InvalidStream,
    /// Code length repeat error
    CodeLengthRepeatError,
}

// =============================================================================
// Bit reader — reads individual bits from a byte stream
// =============================================================================

/// Bit-level reader for DEFLATE streams (LSB-first bit ordering)
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0-7 within current byte
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Read a single bit (LSB first within each byte)
    fn read_bit(&mut self) -> Result<u8, DeflateError> {
        if self.byte_pos >= self.data.len() {
            return Err(DeflateError::UnexpectedEndOfInput);
        }

        let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
        self.bit_pos += 1;
        if self.bit_pos >= 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }

        Ok(bit)
    }

    /// Read `n` bits (1..=16), returning them as a u16
    fn read_bits(&mut self, n: u8) -> Result<u16, DeflateError> {
        let mut value: u16 = 0;
        for i in 0..n {
            let bit = self.read_bit()? as u16;
            value |= bit << i;
        }
        Ok(value)
    }

    /// Align to the next byte boundary (skip remaining bits in current byte)
    fn align_to_byte(&mut self) {
        if self.bit_pos > 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    /// Read a full byte (must be byte-aligned)
    fn read_byte(&mut self) -> Result<u8, DeflateError> {
        if self.byte_pos >= self.data.len() {
            return Err(DeflateError::UnexpectedEndOfInput);
        }
        let b = self.data[self.byte_pos];
        self.byte_pos += 1;
        Ok(b)
    }

    /// Read a 16-bit little-endian value (must be byte-aligned)
    fn read_u16_le(&mut self) -> Result<u16, DeflateError> {
        let lo = self.read_byte()? as u16;
        let hi = self.read_byte()? as u16;
        Ok(lo | (hi << 8))
    }

    /// Total bits consumed so far
    fn bits_consumed(&self) -> usize {
        self.byte_pos * 8 + self.bit_pos as usize
    }
}

// =============================================================================
// Huffman table
// =============================================================================

/// A Huffman decoding table.
///
/// Uses a "length-limited" table approach: for each code length (1..MAX_BITS),
/// we store the range of symbols sorted by their codes. This allows O(max_bits)
/// decode per symbol, which is acceptable for kernel use.
struct HuffmanTable {
    /// For each code length 1..MAX_BITS, the number of codes
    count: [u16; MAX_BITS + 1],
    /// Symbol lookup: symbols sorted by (code_length, code)
    symbols: [u16; MAX_CODES],
    /// Number of valid symbols
    num_symbols: usize,
}

impl HuffmanTable {
    fn new() -> Self {
        HuffmanTable {
            count: [0; MAX_BITS + 1],
            symbols: [0; MAX_CODES],
            num_symbols: 0,
        }
    }

    /// Build the Huffman table from a slice of code lengths.
    ///
    /// code_lengths[i] = bit length for symbol i (0 means not present).
    fn build(&mut self, code_lengths: &[u8]) -> Result<(), DeflateError> {
        // Count the number of codes of each length
        self.count = [0; MAX_BITS + 1];
        for &len in code_lengths.iter() {
            if len as usize > MAX_BITS {
                return Err(DeflateError::InvalidCodeLengths);
            }
            self.count[len as usize] += 1;
        }
        self.count[0] = 0; // Zero-length codes don't exist

        // Compute the starting code for each length
        let mut next_code = [0u16; MAX_BITS + 1];
        let mut code: u16 = 0;
        for bits in 1..=MAX_BITS {
            code = (code + self.count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        // Assign symbols in order: for each symbol with length > 0,
        // place it in the symbols array at the correct offset
        let mut offsets = [0u16; MAX_BITS + 1];
        let mut total: u16 = 0;
        for bits in 1..=MAX_BITS {
            offsets[bits] = total;
            total += self.count[bits];
        }
        self.num_symbols = total as usize;

        // Using the offsets, place each symbol
        let mut sorted_symbols = [0u16; MAX_CODES];
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len > 0 {
                let idx = offsets[len as usize] as usize;
                sorted_symbols[idx] = sym as u16;
                offsets[len as usize] += 1;
            }
        }

        // Copy to our symbols array
        for i in 0..self.num_symbols {
            self.symbols[i] = sorted_symbols[i];
        }

        let _ = next_code;

        Ok(())
    }

    /// Decode one symbol from the bit stream
    fn decode(&self, reader: &mut BitReader) -> Result<u16, DeflateError> {
        let mut code: u16 = 0;
        let mut first: u16 = 0;
        let mut index: u16 = 0;

        for bits in 1..=MAX_BITS {
            let bit = reader.read_bit()? as u16;
            code = (code << 1) | bit;
            let count = self.count[bits];

            if code < first + count {
                return Ok(self.symbols[(index + code - first) as usize]);
            }

            first = (first + count) << 1;
            index += count;
        }

        Err(DeflateError::InvalidHuffmanCode)
    }
}

// =============================================================================
// DEFLATE decompressor
// =============================================================================

/// The main DEFLATE decompressor
pub struct DeflateDecompressor {
    /// Sliding window (circular buffer)
    window: [u8; WINDOW_SIZE],
    /// Write position in the window
    window_pos: usize,
    /// Total bytes output so far
    total_out: usize,
}

impl DeflateDecompressor {
    pub fn new() -> Self {
        DeflateDecompressor {
            window: [0u8; WINDOW_SIZE],
            window_pos: 0,
            total_out: 0,
        }
    }

    /// Output one byte to both the window and the output buffer
    fn output_byte(&mut self, output: &mut [u8], out_pos: &mut usize, byte: u8) -> Result<(), DeflateError> {
        if *out_pos >= output.len() {
            return Err(DeflateError::OutputBufferFull);
        }
        output[*out_pos] = byte;
        *out_pos += 1;

        self.window[self.window_pos] = byte;
        self.window_pos = (self.window_pos + 1) & WINDOW_MASK;
        self.total_out += 1;

        Ok(())
    }

    /// Copy `length` bytes from `distance` back in the window
    fn copy_match(
        &mut self,
        output: &mut [u8],
        out_pos: &mut usize,
        distance: usize,
        length: usize,
    ) -> Result<(), DeflateError> {
        if distance > self.total_out || distance == 0 {
            return Err(DeflateError::InvalidDistance);
        }

        // Start position in window: current pos - distance, wrapped
        let mut src_pos = (self.window_pos.wrapping_sub(distance)) & WINDOW_MASK;

        for _ in 0..length {
            let byte = self.window[src_pos];
            self.output_byte(output, out_pos, byte)?;
            src_pos = (src_pos + 1) & WINDOW_MASK;
        }

        Ok(())
    }

    /// Decompress a stored (uncompressed) block
    fn decompress_stored_block(
        &mut self,
        reader: &mut BitReader,
        output: &mut [u8],
        out_pos: &mut usize,
    ) -> Result<(), DeflateError> {
        reader.align_to_byte();

        let len = reader.read_u16_le()?;
        let nlen = reader.read_u16_le()?;

        if len != !nlen {
            return Err(DeflateError::InvalidStoredBlockLength);
        }

        for _ in 0..len {
            let byte = reader.read_byte()?;
            self.output_byte(output, out_pos, byte)?;
        }

        Ok(())
    }

    /// Decompress a Huffman-coded block (fixed or dynamic tables)
    fn decompress_huffman_block(
        &mut self,
        reader: &mut BitReader,
        lit_table: &HuffmanTable,
        dist_table: &HuffmanTable,
        output: &mut [u8],
        out_pos: &mut usize,
    ) -> Result<(), DeflateError> {
        loop {
            let sym = lit_table.decode(reader)?;

            if sym < 256 {
                // Literal byte
                self.output_byte(output, out_pos, sym as u8)?;
            } else if sym == 256 {
                // End of block
                break;
            } else if sym <= 285 {
                // Length code
                let length_idx = (sym - 257) as usize;
                if length_idx >= LENGTH_BASE.len() {
                    return Err(DeflateError::InvalidHuffmanCode);
                }

                let base_length = LENGTH_BASE[length_idx] as usize;
                let extra = LENGTH_EXTRA_BITS[length_idx];
                let extra_val = if extra > 0 {
                    reader.read_bits(extra)? as usize
                } else {
                    0
                };
                let length = base_length + extra_val;

                // Distance code
                let dist_sym = dist_table.decode(reader)?;
                if dist_sym as usize >= DISTANCE_BASE.len() {
                    return Err(DeflateError::InvalidHuffmanCode);
                }

                let base_dist = DISTANCE_BASE[dist_sym as usize] as usize;
                let dist_extra = DISTANCE_EXTRA_BITS[dist_sym as usize];
                let dist_extra_val = if dist_extra > 0 {
                    reader.read_bits(dist_extra)? as usize
                } else {
                    0
                };
                let distance = base_dist + dist_extra_val;

                // Copy from sliding window
                self.copy_match(output, out_pos, distance, length)?;
            } else {
                return Err(DeflateError::InvalidHuffmanCode);
            }
        }

        Ok(())
    }

    /// Decode dynamic Huffman tables from the stream (RFC 1951 Section 3.2.7)
    fn decode_dynamic_tables(
        reader: &mut BitReader,
    ) -> Result<(HuffmanTable, HuffmanTable), DeflateError> {
        // Read table sizes
        let hlit = reader.read_bits(5)? as usize + 257;
        let hdist = reader.read_bits(5)? as usize + 1;
        let hclen = reader.read_bits(4)? as usize + 4;

        if hlit > MAX_LIT_CODES || hdist > MAX_DIST_CODES {
            return Err(DeflateError::InvalidCodeLengths);
        }

        // Read code length code lengths
        let mut cl_lengths = [0u8; MAX_CL_CODES];
        for i in 0..hclen {
            cl_lengths[CL_CODE_ORDER[i]] = reader.read_bits(3)? as u8;
        }

        // Build code length Huffman table
        let mut cl_table = HuffmanTable::new();
        cl_table.build(&cl_lengths)?;

        // Decode literal/length and distance code lengths
        let total = hlit + hdist;
        let mut lengths = [0u8; MAX_CODES];
        let mut i = 0;

        while i < total {
            let sym = cl_table.decode(reader)?;

            match sym {
                0..=15 => {
                    // Literal code length
                    lengths[i] = sym as u8;
                    i += 1;
                }
                16 => {
                    // Repeat previous length 3-6 times
                    if i == 0 {
                        return Err(DeflateError::CodeLengthRepeatError);
                    }
                    let repeat = reader.read_bits(2)? as usize + 3;
                    let prev = lengths[i - 1];
                    for _ in 0..repeat {
                        if i >= total {
                            return Err(DeflateError::CodeLengthRepeatError);
                        }
                        lengths[i] = prev;
                        i += 1;
                    }
                }
                17 => {
                    // Repeat 0 for 3-10 times
                    let repeat = reader.read_bits(3)? as usize + 3;
                    for _ in 0..repeat {
                        if i >= total {
                            return Err(DeflateError::CodeLengthRepeatError);
                        }
                        lengths[i] = 0;
                        i += 1;
                    }
                }
                18 => {
                    // Repeat 0 for 11-138 times
                    let repeat = reader.read_bits(7)? as usize + 11;
                    for _ in 0..repeat {
                        if i >= total {
                            return Err(DeflateError::CodeLengthRepeatError);
                        }
                        lengths[i] = 0;
                        i += 1;
                    }
                }
                _ => return Err(DeflateError::InvalidCodeLengths),
            }
        }

        // Build literal/length table
        let mut lit_table = HuffmanTable::new();
        lit_table.build(&lengths[..hlit])?;

        // Build distance table
        let mut dist_table = HuffmanTable::new();
        dist_table.build(&lengths[hlit..hlit + hdist])?;

        Ok((lit_table, dist_table))
    }

    /// Decompress a complete DEFLATE stream
    pub fn decompress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, DeflateError> {
        let mut reader = BitReader::new(input);
        let mut out_pos = 0usize;

        loop {
            // Read block header
            let bfinal = reader.read_bit()?;
            let btype = reader.read_bits(2)?;

            match btype {
                0b00 => {
                    // Stored block (no compression)
                    self.decompress_stored_block(&mut reader, output, &mut out_pos)?;
                }
                0b01 => {
                    // Fixed Huffman codes
                    let mut lit_table = HuffmanTable::new();
                    lit_table.build(&FIXED_LIT_LENGTHS)?;
                    let mut dist_table = HuffmanTable::new();
                    dist_table.build(&FIXED_DIST_LENGTHS)?;

                    self.decompress_huffman_block(
                        &mut reader,
                        &lit_table,
                        &dist_table,
                        output,
                        &mut out_pos,
                    )?;
                }
                0b10 => {
                    // Dynamic Huffman codes
                    let (lit_table, dist_table) =
                        Self::decode_dynamic_tables(&mut reader)?;

                    self.decompress_huffman_block(
                        &mut reader,
                        &lit_table,
                        &dist_table,
                        output,
                        &mut out_pos,
                    )?;
                }
                _ => {
                    return Err(DeflateError::InvalidBlockType);
                }
            }

            if bfinal == 1 {
                break;
            }
        }

        Ok(out_pos)
    }
}

// =============================================================================
// Simple DEFLATE compressor (stored blocks only — fast, no ratio)
// =============================================================================

/// Compress data using DEFLATE stored blocks (no actual compression —
/// just framing). Useful for kernel logging where framing matters more than
/// ratio, or as a fallback when data is incompressible.
pub fn deflate_store(input: &[u8], output: &mut [u8]) -> Result<usize, DeflateError> {
    let mut out_pos = 0usize;
    let mut remaining = input.len();
    let mut in_pos = 0usize;

    while remaining > 0 {
        let block_size = if remaining > 65535 { 65535 } else { remaining };
        let is_final = remaining <= 65535;

        // BFINAL + BTYPE (stored = 00)
        if out_pos >= output.len() {
            return Err(DeflateError::OutputBufferFull);
        }
        output[out_pos] = if is_final { 0x01 } else { 0x00 };
        out_pos += 1;

        // LEN
        if out_pos + 4 > output.len() {
            return Err(DeflateError::OutputBufferFull);
        }
        output[out_pos] = (block_size & 0xFF) as u8;
        output[out_pos + 1] = ((block_size >> 8) & 0xFF) as u8;
        // NLEN
        let nlen = !block_size & 0xFFFF;
        output[out_pos + 2] = (nlen & 0xFF) as u8;
        output[out_pos + 3] = ((nlen >> 8) & 0xFF) as u8;
        out_pos += 4;

        // Data
        if out_pos + block_size > output.len() {
            return Err(DeflateError::OutputBufferFull);
        }
        output[out_pos..out_pos + block_size].copy_from_slice(&input[in_pos..in_pos + block_size]);
        out_pos += block_size;
        in_pos += block_size;
        remaining -= block_size;
    }

    Ok(out_pos)
}

// =============================================================================
// Statistics
// =============================================================================

static TOTAL_BYTES_DECOMPRESSED: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static TOTAL_DECOMPRESS_OPS: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_rust_deflate_decompress(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if input.is_null() || output.is_null() || output_len.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let in_slice = unsafe { core::slice::from_raw_parts(input, input_len) };
    let out_slice = unsafe { core::slice::from_raw_parts_mut(output, output_capacity) };

    let mut decompressor = DeflateDecompressor::new();
    match decompressor.decompress(in_slice, out_slice) {
        Ok(n) => {
            unsafe { *output_len = n };
            TOTAL_BYTES_DECOMPRESSED.fetch_add(n as u64, Ordering::Relaxed);
            TOTAL_DECOMPRESS_OPS.fetch_add(1, Ordering::Relaxed);
            crate::ffi::error::FfiError::Success.as_i32()
        }
        Err(_) => crate::ffi::error::FfiError::Corruption.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_deflate_store(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if input.is_null() || output.is_null() || output_len.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let in_slice = unsafe { core::slice::from_raw_parts(input, input_len) };
    let out_slice = unsafe { core::slice::from_raw_parts_mut(output, output_capacity) };

    match deflate_store(in_slice, out_slice) {
        Ok(n) => {
            unsafe { *output_len = n };
            TOTAL_BYTES_COMPRESSED.fetch_add(input_len as u64, Ordering::Relaxed);
            crate::ffi::error::FfiError::Success.as_i32()
        }
        Err(_) => crate::ffi::error::FfiError::BufferTooSmall.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_deflate_stats(
    decompressed: *mut u64,
    compressed: *mut u64,
    ops: *mut u64,
) -> i32 {
    if decompressed.is_null() || compressed.is_null() || ops.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }
    unsafe {
        *decompressed = TOTAL_BYTES_DECOMPRESSED.load(Ordering::Relaxed);
        *compressed = TOTAL_BYTES_COMPRESSED.load(Ordering::Relaxed);
        *ops = TOTAL_DECOMPRESS_OPS.load(Ordering::Relaxed);
    }
    crate::ffi::error::FfiError::Success.as_i32()
}
