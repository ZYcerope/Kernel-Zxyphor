// =============================================================================
// Kernel Zxyphor — CRC32 (Castagnoli and IEEE) Implementation
// =============================================================================
// CRC32 is used extensively in the kernel for data integrity verification:
//   - Filesystem metadata checksums (ext4, btrfs)
//   - Network packet checksums (iSCSI uses CRC32C)
//   - ELF section verification
//   - Memory page integrity checks
//
// Two variants are provided:
//   - CRC32 (IEEE 802.3): polynomial 0x04C11DB7, used by Ethernet/gzip
//   - CRC32C (Castagnoli): polynomial 0x1EDC6F41, used by iSCSI/ext4/btrfs
//
// Both use table-based computation for speed (256-entry lookup tables).
// =============================================================================

use core::sync::atomic::{AtomicU64, Ordering};

/// IEEE 802.3 polynomial
const CRC32_IEEE_POLY: u32 = 0xEDB88320; // bit-reversed 0x04C11DB7

/// Castagnoli polynomial (iSCSI / ext4)
const CRC32C_POLY: u32 = 0x82F63B78; // bit-reversed 0x1EDC6F41

/// CRC32 lookup table (IEEE)
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_IEEE_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// CRC32C lookup table (Castagnoli)
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Compute CRC32 (IEEE 802.3)
pub fn crc32_ieee(data: &[u8]) -> u32 {
    crc32_ieee_update(0xFFFFFFFF, data) ^ 0xFFFFFFFF
}

/// Update a running CRC32 (IEEE)
pub fn crc32_ieee_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    crc
}

/// Compute CRC32C (Castagnoli)
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(0xFFFFFFFF, data) ^ 0xFFFFFFFF
}

/// Update a running CRC32C
pub fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = CRC32C_TABLE[idx] ^ (crc >> 8);
    }
    crc
}

/// Verify CRC32 of a data block (returns true if the CRC matches)
pub fn crc32_ieee_verify(data: &[u8], expected: u32) -> bool {
    crc32_ieee(data) == expected
}

/// Verify CRC32C of a data block
pub fn crc32c_verify(data: &[u8], expected: u32) -> bool {
    crc32c(data) == expected
}

/// Combine two CRC32 values (for parallel computation).
///
/// Given CRC(A) and CRC(B) where B has length `len_b`,
/// returns CRC(A || B) without needing the original data.
///
/// Uses the GF(2) matrix multiplication approach.
pub fn crc32_ieee_combine(crc1: u32, crc2: u32, len_b: usize) -> u32 {
    if len_b == 0 {
        return crc1;
    }

    // Build the "zero matrix" for len_b zero bytes
    // This is the matrix that represents appending len_b zero bytes
    // M^len_b where M is the CRC state transition matrix for a zero byte
    let mut even = [0u32; 32]; // even-power matrix
    let mut odd = [0u32; 32]; // odd-power matrix

    // Odd power: CRC matrix for 1 bit (the polynomial)
    odd[0] = CRC32_IEEE_POLY;
    let mut row: u32 = 1;
    for i in 1..32 {
        odd[i] = row;
        row <<= 1;
    }

    // Multiply by len_b * 8 bits
    let mut len = len_b * 8;
    let mut result = crc1;

    // Square the odd matrix into even, then even into odd, etc.
    // Apply to result when the corresponding bit of len is set
    loop {
        // Square odd into even
        gf2_matrix_square(&mut even, &odd);
        if len & 1 != 0 {
            result = gf2_matrix_times(&even, result);
        }
        len >>= 1;
        if len == 0 {
            break;
        }

        // Square even into odd
        gf2_matrix_square(&mut odd, &even);
        if len & 1 != 0 {
            result = gf2_matrix_times(&odd, result);
        }
        len >>= 1;
        if len == 0 {
            break;
        }
    }

    result ^ crc2
}

/// Multiply a GF(2) vector by a 32x32 GF(2) matrix
fn gf2_matrix_times(matrix: &[u32; 32], mut vec: u32) -> u32 {
    let mut result = 0u32;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            result ^= matrix[i];
        }
        vec >>= 1;
        i += 1;
    }
    result
}

/// Square a 32x32 GF(2) matrix
fn gf2_matrix_square(square: &mut [u32; 32], matrix: &[u32; 32]) {
    for n in 0..32 {
        square[n] = gf2_matrix_times(matrix, matrix[n]);
    }
}

// =============================================================================
// Statistics
// =============================================================================

static CRC32_OPS: AtomicU64 = AtomicU64::new(0);
static CRC32_BYTES: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_rust_crc32_ieee(data: *const u8, len: usize) -> u32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    CRC32_OPS.fetch_add(1, Ordering::Relaxed);
    CRC32_BYTES.fetch_add(len as u64, Ordering::Relaxed);
    crc32_ieee(slice)
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_crc32c(data: *const u8, len: usize) -> u32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    CRC32_OPS.fetch_add(1, Ordering::Relaxed);
    CRC32_BYTES.fetch_add(len as u64, Ordering::Relaxed);
    crc32c(slice)
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_crc32_ieee_verify(
    data: *const u8,
    len: usize,
    expected: u32,
) -> i32 {
    if data.is_null() {
        return 0; // false
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    if crc32_ieee_verify(slice, expected) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_crc32c_verify(
    data: *const u8,
    len: usize,
    expected: u32,
) -> i32 {
    if data.is_null() {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    if crc32c_verify(slice, expected) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_crc32_combine(crc1: u32, crc2: u32, len2: usize) -> u32 {
    crc32_ieee_combine(crc1, crc2, len2)
}
