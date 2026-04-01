// =============================================================================
// Kernel Zxyphor — LZ4 Compression Engine
// =============================================================================
// LZ4 is a very fast lossless compression algorithm, ideal for kernel use:
//   - Decompression at 4+ GB/s on modern CPUs
//   - Simple format, minimal code complexity
//   - Used in Linux kernel for zram, filesystem compression, hibernation
//
// This implements the LZ4 Block Format (not the Frame format).
// The block format is a sequence of literal runs and match copies:
//
//   Token byte: [4 bits literal length | 4 bits match length]
//   Optional: extended literal length bytes (if literal_len == 15)
//   Literal data: raw bytes
//   Match offset: 2 bytes little-endian (1..65535)
//   Optional: extended match length bytes (if match_len == 15)
//
// Reference: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
// =============================================================================

use core::sync::atomic::{AtomicU64, Ordering};

/// Minimum match length (the format stores match_len - 4)
const MIN_MATCH: usize = 4;

/// Maximum input size for LZ4 block compression
const LZ4_MAX_INPUT_SIZE: usize = 0x7E000000; // ~2 GB

/// Hash table size for the compressor (power of 2)
const HASH_TABLE_SIZE: usize = 4096;
const HASH_TABLE_MASK: usize = HASH_TABLE_SIZE - 1;

/// Minimum offset for copy (can't reference itself)
const MIN_OFFSET: usize = 1;

/// Maximum offset (16-bit)
const MAX_OFFSET: usize = 65535;

/// Maximum block output with overhead (worst case: incompressible data)
pub fn lz4_compress_bound(input_size: usize) -> usize {
    input_size + (input_size / 255) + 16
}

// =============================================================================
// LZ4 errors
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lz4Error {
    /// Input data is corrupted
    CorruptedInput,
    /// Output buffer too small
    OutputBufferTooSmall,
    /// Input too large
    InputTooLarge,
    /// Invalid offset (zero or out of range)
    InvalidOffset,
    /// Unexpected end of input
    UnexpectedEnd,
}

// =============================================================================
// LZ4 decompressor (block format)
// =============================================================================

/// Decompress an LZ4 block.
///
/// `input` is the compressed LZ4 block data.
/// `output` is the buffer to write decompressed data into.
/// Returns the number of bytes written to `output`.
pub fn lz4_decompress(input: &[u8], output: &mut [u8]) -> Result<usize, Lz4Error> {
    let mut in_pos: usize = 0;
    let mut out_pos: usize = 0;

    while in_pos < input.len() {
        // Read token byte
        if in_pos >= input.len() {
            return Err(Lz4Error::UnexpectedEnd);
        }
        let token = input[in_pos];
        in_pos += 1;

        // --- Literal run ---
        let mut literal_len = ((token >> 4) & 0x0F) as usize;

        if literal_len == 15 {
            // Extended literal length: read additional bytes
            loop {
                if in_pos >= input.len() {
                    return Err(Lz4Error::UnexpectedEnd);
                }
                let extra = input[in_pos] as usize;
                in_pos += 1;
                literal_len += extra;
                if extra != 255 {
                    break;
                }
            }
        }

        // Copy literal bytes
        if literal_len > 0 {
            if in_pos + literal_len > input.len() {
                return Err(Lz4Error::CorruptedInput);
            }
            if out_pos + literal_len > output.len() {
                return Err(Lz4Error::OutputBufferTooSmall);
            }

            output[out_pos..out_pos + literal_len]
                .copy_from_slice(&input[in_pos..in_pos + literal_len]);
            in_pos += literal_len;
            out_pos += literal_len;
        }

        // Check if this was the last sequence (no match follows at end of block)
        if in_pos >= input.len() {
            break;
        }

        // --- Match copy ---
        // Read 16-bit little-endian offset
        if in_pos + 2 > input.len() {
            return Err(Lz4Error::UnexpectedEnd);
        }
        let offset = (input[in_pos] as usize) | ((input[in_pos + 1] as usize) << 8);
        in_pos += 2;

        if offset == 0 || offset > out_pos {
            return Err(Lz4Error::InvalidOffset);
        }

        // Match length
        let mut match_len = (token & 0x0F) as usize + MIN_MATCH;

        if (token & 0x0F) == 15 {
            loop {
                if in_pos >= input.len() {
                    return Err(Lz4Error::UnexpectedEnd);
                }
                let extra = input[in_pos] as usize;
                in_pos += 1;
                match_len += extra;
                if extra != 255 {
                    break;
                }
            }
        }

        // Perform the copy (overlapping copies are valid and expected)
        if out_pos + match_len > output.len() {
            return Err(Lz4Error::OutputBufferTooSmall);
        }

        let match_start = out_pos - offset;
        for i in 0..match_len {
            output[out_pos + i] = output[match_start + (i % offset)];
        }
        out_pos += match_len;
    }

    Ok(out_pos)
}

// =============================================================================
// LZ4 compressor (block format, fast/greedy)
// =============================================================================

/// Hash function for 4-byte sequences
fn lz4_hash(val: u32) -> usize {
    // Knuth multiplicative hash
    ((val.wrapping_mul(2654435761)) >> 20) as usize & HASH_TABLE_MASK
}

/// Read 4 bytes from `data` at `pos` as a u32 (little-endian)
fn read_u32_le(data: &[u8], pos: usize) -> u32 {
    if pos + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

/// Count matching bytes starting at `a_pos` and `b_pos` in `data`
fn count_match(data: &[u8], a_pos: usize, b_pos: usize, limit: usize) -> usize {
    let mut len = 0;
    while a_pos + len < limit && b_pos + len < limit && data[a_pos + len] == data[b_pos + len] {
        len += 1;
    }
    len
}

/// Write an extended length (for literal_len >= 15 or match_len >= 19)
fn write_extended_length(output: &mut [u8], out_pos: &mut usize, mut extra: usize) -> Result<(), Lz4Error> {
    while extra >= 255 {
        if *out_pos >= output.len() {
            return Err(Lz4Error::OutputBufferTooSmall);
        }
        output[*out_pos] = 255;
        *out_pos += 1;
        extra -= 255;
    }
    if *out_pos >= output.len() {
        return Err(Lz4Error::OutputBufferTooSmall);
    }
    output[*out_pos] = extra as u8;
    *out_pos += 1;
    Ok(())
}

/// Compress data using LZ4 block format (greedy / fast strategy).
///
/// Returns the number of bytes written to `output`.
pub fn lz4_compress(input: &[u8], output: &mut [u8]) -> Result<usize, Lz4Error> {
    if input.len() > LZ4_MAX_INPUT_SIZE {
        return Err(Lz4Error::InputTooLarge);
    }

    if input.len() < MIN_MATCH {
        // Too short to compress — emit as a single literal run
        return emit_last_literals(input, output, 0);
    }

    let mut hash_table = [0u32; HASH_TABLE_SIZE];
    let mut in_pos: usize = 0;
    let mut out_pos: usize = 0;
    let mut anchor: usize = 0; // Start of current literal run

    let in_limit = if input.len() > MIN_MATCH + 4 {
        input.len() - MIN_MATCH - 4
    } else {
        0
    };

    while in_pos < in_limit {
        // Hash the current 4 bytes
        let seq = read_u32_le(input, in_pos);
        let h = lz4_hash(seq);
        let ref_pos = hash_table[h] as usize;
        hash_table[h] = in_pos as u32;

        // Check if the reference is valid
        let offset = in_pos - ref_pos;
        if offset < MIN_OFFSET || offset > MAX_OFFSET || ref_pos >= in_pos {
            in_pos += 1;
            continue;
        }

        // Check for a match (at least MIN_MATCH bytes)
        if read_u32_le(input, ref_pos) != seq {
            in_pos += 1;
            continue;
        }

        // We have a match! Count the full match length
        let match_len = MIN_MATCH + count_match(input, in_pos + MIN_MATCH, ref_pos + MIN_MATCH, input.len());

        // Emit the literal run + match
        let literal_len = in_pos - anchor;

        // Token byte
        if out_pos >= output.len() {
            return Err(Lz4Error::OutputBufferTooSmall);
        }
        let lit_token = if literal_len >= 15 { 15 } else { literal_len };
        let match_token = if match_len - MIN_MATCH >= 15 {
            15
        } else {
            match_len - MIN_MATCH
        };
        output[out_pos] = ((lit_token << 4) | match_token) as u8;
        out_pos += 1;

        // Extended literal length
        if literal_len >= 15 {
            write_extended_length(output, &mut out_pos, literal_len - 15)?;
        }

        // Literal data
        if literal_len > 0 {
            if out_pos + literal_len > output.len() {
                return Err(Lz4Error::OutputBufferTooSmall);
            }
            output[out_pos..out_pos + literal_len].copy_from_slice(&input[anchor..anchor + literal_len]);
            out_pos += literal_len;
        }

        // Match offset (16-bit LE)
        if out_pos + 2 > output.len() {
            return Err(Lz4Error::OutputBufferTooSmall);
        }
        output[out_pos] = (offset & 0xFF) as u8;
        output[out_pos + 1] = ((offset >> 8) & 0xFF) as u8;
        out_pos += 2;

        // Extended match length
        if match_len - MIN_MATCH >= 15 {
            write_extended_length(output, &mut out_pos, match_len - MIN_MATCH - 15)?;
        }

        // Advance past the match
        in_pos += match_len;
        anchor = in_pos;
    }

    // Emit remaining literals (last 5+ bytes are always literals per spec)
    emit_last_literals(&input[anchor..], output, out_pos)
}

/// Emit the final literal-only sequence
fn emit_last_literals(
    literals: &[u8],
    output: &mut [u8],
    mut out_pos: usize,
) -> Result<usize, Lz4Error> {
    let literal_len = literals.len();

    // Token byte (no match part)
    if out_pos >= output.len() {
        return Err(Lz4Error::OutputBufferTooSmall);
    }
    let lit_token = if literal_len >= 15 { 15 } else { literal_len };
    output[out_pos] = (lit_token << 4) as u8;
    out_pos += 1;

    if literal_len >= 15 {
        write_extended_length(output, &mut out_pos, literal_len - 15)?;
    }

    if out_pos + literal_len > output.len() {
        return Err(Lz4Error::OutputBufferTooSmall);
    }
    output[out_pos..out_pos + literal_len].copy_from_slice(literals);
    out_pos += literal_len;

    Ok(out_pos)
}

// =============================================================================
// Statistics
// =============================================================================

static LZ4_COMPRESS_OPS: AtomicU64 = AtomicU64::new(0);
static LZ4_DECOMPRESS_OPS: AtomicU64 = AtomicU64::new(0);
static LZ4_BYTES_IN: AtomicU64 = AtomicU64::new(0);
static LZ4_BYTES_OUT: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_rust_lz4_compress(
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

    match lz4_compress(in_slice, out_slice) {
        Ok(n) => {
            unsafe { *output_len = n };
            LZ4_COMPRESS_OPS.fetch_add(1, Ordering::Relaxed);
            LZ4_BYTES_IN.fetch_add(input_len as u64, Ordering::Relaxed);
            LZ4_BYTES_OUT.fetch_add(n as u64, Ordering::Relaxed);
            crate::ffi::error::FfiError::Success.as_i32()
        }
        Err(_) => crate::ffi::error::FfiError::BufferTooSmall.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_lz4_decompress(
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

    match lz4_decompress(in_slice, out_slice) {
        Ok(n) => {
            unsafe { *output_len = n };
            LZ4_DECOMPRESS_OPS.fetch_add(1, Ordering::Relaxed);
            crate::ffi::error::FfiError::Success.as_i32()
        }
        Err(_) => crate::ffi::error::FfiError::Corruption.as_i32(),
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_lz4_compress_bound(input_size: usize) -> usize {
    lz4_compress_bound(input_size)
}
