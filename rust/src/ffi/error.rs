// =============================================================================
// Kernel Zxyphor — Rust FFI Error Codes
// =============================================================================
// Shared error code definitions that must match the Zig side exactly.
// These are ABI-stable i32 values passed across the FFI boundary.
// =============================================================================

/// FFI error codes — must match `FfiError` in `kernel/src/ffi/bridge.zig`
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiError {
    Success = 0,
    InvalidArgument = -1,
    BufferTooSmall = -2,
    NotFound = -3,
    IoError = -4,
    PermissionDenied = -5,
    OutOfMemory = -6,
    AlreadyExists = -7,
    NotSupported = -8,
    Corruption = -9,
    Timeout = -10,
    Busy = -11,
    Interrupted = -12,
    InvalidState = -13,
    ChecksumMismatch = -14,
    CryptoError = -15,
    Overflow = -16,
    Underflow = -17,
    NotInitialized = -18,
    EndOfFile = -19,
    NoSpace = -20,
    Unknown = -255,
}

impl FfiError {
    /// Convert to raw i32 for FFI return
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Create from raw i32 (for receiving error codes)
    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => FfiError::Success,
            -1 => FfiError::InvalidArgument,
            -2 => FfiError::BufferTooSmall,
            -3 => FfiError::NotFound,
            -4 => FfiError::IoError,
            -5 => FfiError::PermissionDenied,
            -6 => FfiError::OutOfMemory,
            -7 => FfiError::AlreadyExists,
            -8 => FfiError::NotSupported,
            -9 => FfiError::Corruption,
            -10 => FfiError::Timeout,
            -11 => FfiError::Busy,
            -12 => FfiError::Interrupted,
            -13 => FfiError::InvalidState,
            -14 => FfiError::ChecksumMismatch,
            -15 => FfiError::CryptoError,
            -16 => FfiError::Overflow,
            -17 => FfiError::Underflow,
            -18 => FfiError::NotInitialized,
            -19 => FfiError::EndOfFile,
            -20 => FfiError::NoSpace,
            _ => FfiError::Unknown,
        }
    }

    /// Check whether this represents a successful result
    #[inline]
    pub fn is_success(self) -> bool {
        self == FfiError::Success
    }

    /// Human-readable error description for logging
    pub fn description(self) -> &'static str {
        match self {
            FfiError::Success => "success",
            FfiError::InvalidArgument => "invalid argument",
            FfiError::BufferTooSmall => "buffer too small",
            FfiError::NotFound => "not found",
            FfiError::IoError => "I/O error",
            FfiError::PermissionDenied => "permission denied",
            FfiError::OutOfMemory => "out of memory",
            FfiError::AlreadyExists => "already exists",
            FfiError::NotSupported => "operation not supported",
            FfiError::Corruption => "data corruption detected",
            FfiError::Timeout => "operation timed out",
            FfiError::Busy => "resource busy",
            FfiError::Interrupted => "operation interrupted",
            FfiError::InvalidState => "invalid state",
            FfiError::ChecksumMismatch => "checksum mismatch",
            FfiError::CryptoError => "cryptographic error",
            FfiError::Overflow => "arithmetic overflow",
            FfiError::Underflow => "arithmetic underflow",
            FfiError::NotInitialized => "not initialized",
            FfiError::EndOfFile => "end of file",
            FfiError::NoSpace => "no space available",
            FfiError::Unknown => "unknown error",
        }
    }
}

/// Result type for FFI operations that return data alongside an error code
pub type FfiResult<T> = Result<T, FfiError>;

/// Convenience trait for converting Rust Results to FFI error codes
pub trait IntoFfiError {
    fn into_ffi_error(self) -> i32;
}

impl IntoFfiError for FfiError {
    #[inline]
    fn into_ffi_error(self) -> i32 {
        self.as_i32()
    }
}

impl<T> IntoFfiError for FfiResult<T> {
    fn into_ffi_error(self) -> i32 {
        match self {
            Ok(_) => FfiError::Success.as_i32(),
            Err(e) => e.as_i32(),
        }
    }
}
