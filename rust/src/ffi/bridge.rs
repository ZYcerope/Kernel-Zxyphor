// =============================================================================
// Kernel Zxyphor — Rust FFI Bridge (Rust side)
// =============================================================================
// This module is the Rust counterpart of kernel/src/ffi/bridge.zig.
// It receives callback function pointers from the Zig kernel during
// initialization and provides all #[no_mangle] extern "C" entry points
// that the Zig side calls.
//
// Safety invariants:
//   - All raw pointer parameters are validated before dereference
//   - Buffer lengths are bounds-checked before any memory access
//   - Global state is protected by atomic operations
//   - Callbacks are checked for null before invocation
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::ffi::error::FfiError;

// =============================================================================
// Callback function types — these match the Zig `callconv(.C)` signatures
// =============================================================================

/// Zig disk read function: reads `count` sectors starting at `lba` into `buffer`
pub type DiskReadCallback = extern "C" fn(
    lba: u64,
    count: u32,
    buffer: *mut u8,
    buffer_len: usize,
) -> i32;

/// Zig disk write function: writes `count` sectors from `buffer` starting at `lba`
pub type DiskWriteCallback = extern "C" fn(
    lba: u64,
    count: u32,
    buffer: *const u8,
    buffer_len: usize,
) -> i32;

/// Zig memory allocation function
pub type AllocCallback = extern "C" fn(
    size: usize,
    alignment: usize,
) -> *mut u8;

/// Zig memory deallocation function
pub type FreeCallback = extern "C" fn(
    ptr: *mut u8,
    size: usize,
);

/// Zig log callback function
pub type LogCallback = extern "C" fn(
    level: u32,
    msg: *const u8,
    msg_len: usize,
);

/// Zig entropy source callback
pub type EntropyCallback = extern "C" fn(
    buffer: *mut u8,
    len: usize,
) -> usize;

// =============================================================================
// Callback registration structure — passed from Zig during init
// =============================================================================

#[repr(C)]
pub struct FfiCallbacks {
    pub disk_read: Option<DiskReadCallback>,
    pub disk_write: Option<DiskWriteCallback>,
    pub alloc: Option<AllocCallback>,
    pub free: Option<FreeCallback>,
    pub log: Option<LogCallback>,
    pub entropy_source: Option<EntropyCallback>,
    pub version: u32,
}

const CALLBACKS_VERSION: u32 = 1;

// =============================================================================
// Global state — stored callbacks and initialization flag
// =============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static INIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stored callbacks from the Zig kernel. Protected by INITIALIZED flag.
/// Safety: only written once during init (single-threaded boot phase),
/// then read-only during normal operation.
static mut CALLBACKS: Option<FfiCallbacks> = None;

// =============================================================================
// Internal helpers for accessing callbacks safely
// =============================================================================

/// Get a reference to the registered callbacks, or None if not initialized
fn get_callbacks() -> Option<&'static FfiCallbacks> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return None;
    }
    // Safety: CALLBACKS is only written during single-threaded init,
    // and INITIALIZED acts as a release/acquire barrier.
    unsafe { CALLBACKS.as_ref() }
}

/// Call the Zig log callback to emit a kernel log message
pub fn log(level: u32, message: &str) {
    if let Some(cb) = get_callbacks() {
        if let Some(log_fn) = cb.log {
            log_fn(level, message.as_ptr(), message.len());
        }
    }
}

/// Log at info level
pub fn log_info(message: &str) {
    log(6, message);
}

/// Log at error level
pub fn log_error(message: &str) {
    log(3, message);
}

/// Log at debug level
pub fn log_debug(message: &str) {
    log(7, message);
}

/// Read disk sectors through the Zig ATA driver
pub fn disk_read(lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), FfiError> {
    let cb = get_callbacks().ok_or(FfiError::NotInitialized)?;
    let read_fn = cb.disk_read.ok_or(FfiError::NotSupported)?;

    let required = count as usize * 512;
    if buffer.len() < required {
        return Err(FfiError::BufferTooSmall);
    }

    let result = read_fn(lba, count, buffer.as_mut_ptr(), buffer.len());
    let err = FfiError::from_i32(result);
    if err.is_success() {
        Ok(())
    } else {
        Err(err)
    }
}

/// Write disk sectors through the Zig ATA driver
pub fn disk_write(lba: u64, count: u32, buffer: &[u8]) -> Result<(), FfiError> {
    let cb = get_callbacks().ok_or(FfiError::NotInitialized)?;
    let write_fn = cb.disk_write.ok_or(FfiError::NotSupported)?;

    let required = count as usize * 512;
    if buffer.len() < required {
        return Err(FfiError::BufferTooSmall);
    }

    let result = write_fn(lba, count, buffer.as_ptr(), buffer.len());
    let err = FfiError::from_i32(result);
    if err.is_success() {
        Ok(())
    } else {
        Err(err)
    }
}

/// Allocate kernel memory through the Zig heap allocator
pub fn kernel_alloc(size: usize, alignment: usize) -> Result<*mut u8, FfiError> {
    let cb = get_callbacks().ok_or(FfiError::NotInitialized)?;
    let alloc_fn = cb.alloc.ok_or(FfiError::NotSupported)?;

    let ptr = alloc_fn(size, alignment);
    if ptr.is_null() {
        Err(FfiError::OutOfMemory)
    } else {
        Ok(ptr)
    }
}

/// Free kernel memory through the Zig heap allocator
pub fn kernel_free(ptr: *mut u8, size: usize) -> Result<(), FfiError> {
    let cb = get_callbacks().ok_or(FfiError::NotInitialized)?;
    let free_fn = cb.free.ok_or(FfiError::NotSupported)?;

    free_fn(ptr, size);
    Ok(())
}

/// Collect hardware entropy through the Zig entropy source
pub fn collect_entropy(buffer: &mut [u8]) -> Result<usize, FfiError> {
    let cb = get_callbacks().ok_or(FfiError::NotInitialized)?;
    let entropy_fn = cb.entropy_source.ok_or(FfiError::NotSupported)?;

    let collected = entropy_fn(buffer.as_mut_ptr(), buffer.len());
    Ok(collected)
}

// =============================================================================
// FFI entry points — called from Zig via extern "C"
// =============================================================================

/// Initialize the Rust subsystem with callbacks from the Zig kernel.
/// Must be called exactly once during boot, before any other FFI function.
#[no_mangle]
pub extern "C" fn zxyphor_rust_init(callbacks: *const FfiCallbacks) -> i32 {
    // Prevent double initialization
    if INITIALIZED.load(Ordering::SeqCst) {
        return FfiError::AlreadyExists.as_i32();
    }

    if callbacks.is_null() {
        return FfiError::InvalidArgument.as_i32();
    }

    // Safety: we've verified the pointer is non-null, and the Zig kernel
    // guarantees the struct is valid for the duration of this call.
    let cb = unsafe { &*callbacks };

    // Version check to ensure ABI compatibility
    if cb.version != CALLBACKS_VERSION {
        return FfiError::NotSupported.as_i32();
    }

    // Store the callbacks. Safety: single-threaded during boot.
    unsafe {
        CALLBACKS = Some(FfiCallbacks {
            disk_read: cb.disk_read,
            disk_write: cb.disk_write,
            alloc: cb.alloc,
            free: cb.free,
            log: cb.log,
            entropy_source: cb.entropy_source,
            version: cb.version,
        });
    }

    // Mark as initialized with release semantics so other threads see the writes
    INITIALIZED.store(true, Ordering::Release);
    INIT_SEQUENCE.fetch_add(1, Ordering::SeqCst);

    // Log successful initialization through the newly registered callback
    log_info("Rust subsystem initialized successfully");
    log_info("FFI bridge v1 — all callbacks registered");

    FfiError::Success.as_i32()
}

/// Shutdown the Rust subsystem. Called during kernel shutdown.
#[no_mangle]
pub extern "C" fn zxyphor_rust_shutdown() {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    log_info("Rust subsystem shutting down");

    INITIALIZED.store(false, Ordering::SeqCst);

    // Safety: no other thread can access callbacks after INITIALIZED is false
    unsafe {
        CALLBACKS = None;
    }
}
