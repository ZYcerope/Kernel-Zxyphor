// =============================================================================
// Kernel Zxyphor — Zig ↔ Rust Foreign Function Interface Bridge
// =============================================================================
// This module provides the primary communication layer between the Zig kernel
// core and the Rust subsystems. Every Rust function callable from Zig is
// declared here as an `extern "C"` prototype, along with safe wrappers that
// handle error translation, null-pointer checks, and type marshalling.
//
// Design principles:
//   - All FFI calls go through this single module (no scattered externs)
//   - Every raw pointer from Rust is validated before dereference
//   - Error codes from Rust are translated to Zig error unions
//   - Buffer lengths are always passed explicitly (no C-string assumptions)
//   - Critical sections are protected by spinlocks where needed
// =============================================================================

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");
const serial = @import("../arch/x86_64/serial.zig");

// =============================================================================
// Error codes shared between Zig and Rust (must match rust/src/ffi/error.rs)
// =============================================================================
pub const FfiError = enum(i32) {
    success = 0,
    invalid_argument = -1,
    buffer_too_small = -2,
    not_found = -3,
    io_error = -4,
    permission_denied = -5,
    out_of_memory = -6,
    already_exists = -7,
    not_supported = -8,
    corruption = -9,
    timeout = -10,
    busy = -11,
    interrupted = -12,
    invalid_state = -13,
    checksum_mismatch = -14,
    crypto_error = -15,
    overflow = -16,
    underflow = -17,
    not_initialized = -18,
    end_of_file = -19,
    no_space = -20,
    unknown = -255,

    pub fn toZigError(self: FfiError) BridgeError {
        return switch (self) {
            .success => unreachable,
            .invalid_argument => BridgeError.InvalidArgument,
            .buffer_too_small => BridgeError.BufferTooSmall,
            .not_found => BridgeError.NotFound,
            .io_error => BridgeError.IoError,
            .permission_denied => BridgeError.PermissionDenied,
            .out_of_memory => BridgeError.OutOfMemory,
            .already_exists => BridgeError.AlreadyExists,
            .not_supported => BridgeError.NotSupported,
            .corruption => BridgeError.Corruption,
            .timeout => BridgeError.Timeout,
            .busy => BridgeError.Busy,
            .interrupted => BridgeError.Interrupted,
            .invalid_state => BridgeError.InvalidState,
            .checksum_mismatch => BridgeError.ChecksumMismatch,
            .crypto_error => BridgeError.CryptoError,
            .overflow => BridgeError.Overflow,
            .underflow => BridgeError.Underflow,
            .not_initialized => BridgeError.NotInitialized,
            .end_of_file => BridgeError.EndOfFile,
            .no_space => BridgeError.NoSpace,
            .unknown => BridgeError.Unknown,
        };
    }
};

pub const BridgeError = error{
    InvalidArgument,
    BufferTooSmall,
    NotFound,
    IoError,
    PermissionDenied,
    OutOfMemory,
    AlreadyExists,
    NotSupported,
    Corruption,
    Timeout,
    Busy,
    Interrupted,
    InvalidState,
    ChecksumMismatch,
    CryptoError,
    Overflow,
    Underflow,
    NotInitialized,
    EndOfFile,
    NoSpace,
    Unknown,
};

// =============================================================================
// Shared data structures for FFI (must match Rust layout exactly)
// =============================================================================

/// Represents a contiguous byte buffer passed across the FFI boundary.
/// Both Zig and Rust agree on this layout via `#[repr(C)]`.
pub const FfiBuffer = extern struct {
    ptr: ?[*]u8,
    len: usize,
    capacity: usize,

    pub fn fromSlice(slice: []u8) FfiBuffer {
        return .{
            .ptr = slice.ptr,
            .len = slice.len,
            .capacity = slice.len,
        };
    }

    pub fn fromConstSlice(slice: []const u8) FfiBuffer {
        return .{
            .ptr = @constCast(slice.ptr),
            .len = slice.len,
            .capacity = slice.len,
        };
    }

    pub fn toSlice(self: *const FfiBuffer) ?[]u8 {
        if (self.ptr) |p| {
            if (self.len == 0) return &[_]u8{};
            return p[0..self.len];
        }
        return null;
    }

    pub fn toConstSlice(self: *const FfiBuffer) ?[]const u8 {
        if (self.ptr) |p| {
            if (self.len == 0) return &[_]u8{};
            return p[0..self.len];
        }
        return null;
    }

    pub fn empty() FfiBuffer {
        return .{ .ptr = null, .len = 0, .capacity = 0 };
    }
};

/// Disk I/O request structure shared between Zig and Rust
pub const FfiDiskRequest = extern struct {
    sector_lba: u64,
    sector_count: u32,
    buffer: FfiBuffer,
    flags: u32,

    pub const FLAG_READ = 0x01;
    pub const FLAG_WRITE = 0x02;
    pub const FLAG_FLUSH = 0x04;
    pub const FLAG_FUA = 0x08; // Force Unit Access — bypass write cache
};

/// Filesystem stat information
pub const FfiStatInfo = extern struct {
    inode: u64,
    size: u64,
    blocks: u64,
    block_size: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    atime: i64,
    mtime: i64,
    ctime: i64,
    file_type: u8,
    _padding: [3]u8 = .{ 0, 0, 0 },
};

/// Directory entry from Rust filesystem modules
pub const FfiDirEntry = extern struct {
    inode: u64,
    name_len: u16,
    file_type: u8,
    _padding: u8 = 0,
    name: [256]u8 = std.mem.zeroes([256]u8),

    pub fn getName(self: *const FfiDirEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

/// Cryptographic hash result (SHA-256 = 32 bytes)
pub const FfiHashResult = extern struct {
    digest: [32]u8,
    digest_len: u32,
    algorithm: u32,

    pub const ALG_SHA256 = 1;
    pub const ALG_SHA512 = 2;
    pub const ALG_BLAKE3 = 3;
};

/// AES encryption context handle
pub const FfiAesContext = extern struct {
    handle_id: u64,
    key_size: u32,
    mode: u32,
    _reserved: [16]u8 = std.mem.zeroes([16]u8),

    pub const MODE_ECB = 0;
    pub const MODE_CBC = 1;
    pub const MODE_CTR = 2;
    pub const MODE_GCM = 3;

    pub const KEY_128 = 128;
    pub const KEY_192 = 192;
    pub const KEY_256 = 256;
};

/// Random number generator state information
pub const FfiRngInfo = extern struct {
    entropy_available: u64,
    reseed_count: u64,
    is_seeded: u8,
    algorithm: u8,
    _padding: [6]u8 = std.mem.zeroes([6]u8),

    pub const ALG_CHACHA20 = 1;
    pub const ALG_AES_CTR_DRBG = 2;
};

// =============================================================================
// Callback function types — Rust calls back into Zig through these
// =============================================================================

/// Disk read callback: Rust calls this to read sectors from the Zig ATA driver
pub const DiskReadCallback = *const fn (
    lba: u64,
    count: u32,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.C) i32;

/// Disk write callback: Rust calls this to write sectors via the Zig ATA driver
pub const DiskWriteCallback = *const fn (
    lba: u64,
    count: u32,
    buffer: [*]const u8,
    buffer_len: usize,
) callconv(.C) i32;

/// Memory allocation callback: Rust calls this to allocate kernel memory
pub const AllocCallback = *const fn (
    size: usize,
    alignment: usize,
) callconv(.C) ?[*]u8;

/// Memory deallocation callback
pub const FreeCallback = *const fn (
    ptr: [*]u8,
    size: usize,
) callconv(.C) void;

/// Log callback: Rust uses this to log messages through the Zig serial driver
pub const LogCallback = *const fn (
    level: u32,
    msg: [*]const u8,
    msg_len: usize,
) callconv(.C) void;

/// Entropy source callback: Rust calls this to gather hardware entropy
pub const EntropyCallback = *const fn (
    buffer: [*]u8,
    len: usize,
) callconv(.C) usize;

// =============================================================================
// Callback registration structure passed to Rust during initialization
// =============================================================================
pub const FfiCallbacks = extern struct {
    disk_read: ?DiskReadCallback,
    disk_write: ?DiskWriteCallback,
    alloc: ?AllocCallback,
    free: ?FreeCallback,
    log: ?LogCallback,
    entropy_source: ?EntropyCallback,
    version: u32,

    pub const CURRENT_VERSION = 1;
};

// =============================================================================
// External Rust function declarations
// =============================================================================
// These functions are implemented in Rust and linked as a static library.
// The naming convention is `zxyphor_rust_<module>_<function>`.
// =============================================================================

// ------ Initialization ------
extern "C" fn zxyphor_rust_init(callbacks: *const FfiCallbacks) i32;
extern "C" fn zxyphor_rust_shutdown() void;

// ------ AES Cryptography ------
extern "C" fn zxyphor_rust_aes_init(
    ctx: *FfiAesContext,
    key: [*]const u8,
    key_len: u32,
    mode: u32,
) i32;

extern "C" fn zxyphor_rust_aes_encrypt(
    ctx: *const FfiAesContext,
    input: [*]const u8,
    input_len: usize,
    output: [*]u8,
    output_capacity: usize,
    output_len: *usize,
    iv: ?[*]const u8,
    iv_len: usize,
) i32;

extern "C" fn zxyphor_rust_aes_decrypt(
    ctx: *const FfiAesContext,
    input: [*]const u8,
    input_len: usize,
    output: [*]u8,
    output_capacity: usize,
    output_len: *usize,
    iv: ?[*]const u8,
    iv_len: usize,
) i32;

// ------ SHA-256 Hashing ------
extern "C" fn zxyphor_rust_sha256_hash(
    input: [*]const u8,
    input_len: usize,
    result: *FfiHashResult,
) i32;

extern "C" fn zxyphor_rust_sha256_hmac(
    key: [*]const u8,
    key_len: usize,
    message: [*]const u8,
    message_len: usize,
    result: *FfiHashResult,
) i32;

// ------ Random Number Generation ------
extern "C" fn zxyphor_rust_rng_init() i32;
extern "C" fn zxyphor_rust_rng_fill(buffer: [*]u8, len: usize) i32;
extern "C" fn zxyphor_rust_rng_u64() u64;
extern "C" fn zxyphor_rust_rng_info(info: *FfiRngInfo) i32;
extern "C" fn zxyphor_rust_rng_add_entropy(data: [*]const u8, len: usize) i32;

// ------ ext4 Filesystem ------
extern "C" fn zxyphor_rust_ext4_mount(
    disk_read: DiskReadCallback,
    partition_offset: u64,
) i32;

extern "C" fn zxyphor_rust_ext4_unmount() i32;

extern "C" fn zxyphor_rust_ext4_stat(
    path: [*]const u8,
    path_len: usize,
    stat_out: *FfiStatInfo,
) i32;

extern "C" fn zxyphor_rust_ext4_read(
    path: [*]const u8,
    path_len: usize,
    offset: u64,
    buffer: [*]u8,
    buffer_len: usize,
    bytes_read: *usize,
) i32;

extern "C" fn zxyphor_rust_ext4_readdir(
    path: [*]const u8,
    path_len: usize,
    entries: [*]FfiDirEntry,
    max_entries: usize,
    entry_count: *usize,
) i32;

// ------ FAT32 Filesystem ------
extern "C" fn zxyphor_rust_fat32_mount(
    disk_read: DiskReadCallback,
    disk_write: ?DiskWriteCallback,
    partition_offset: u64,
) i32;

extern "C" fn zxyphor_rust_fat32_unmount() i32;

extern "C" fn zxyphor_rust_fat32_stat(
    path: [*]const u8,
    path_len: usize,
    stat_out: *FfiStatInfo,
) i32;

extern "C" fn zxyphor_rust_fat32_read(
    path: [*]const u8,
    path_len: usize,
    offset: u64,
    buffer: [*]u8,
    buffer_len: usize,
    bytes_read: *usize,
) i32;

extern "C" fn zxyphor_rust_fat32_write(
    path: [*]const u8,
    path_len: usize,
    offset: u64,
    data: [*]const u8,
    data_len: usize,
    bytes_written: *usize,
) i32;

extern "C" fn zxyphor_rust_fat32_create(
    path: [*]const u8,
    path_len: usize,
    mode: u32,
) i32;

extern "C" fn zxyphor_rust_fat32_delete(
    path: [*]const u8,
    path_len: usize,
) i32;

extern "C" fn zxyphor_rust_fat32_readdir(
    path: [*]const u8,
    path_len: usize,
    entries: [*]FfiDirEntry,
    max_entries: usize,
    entry_count: *usize,
) i32;

// =============================================================================
// Global state for the FFI bridge
// =============================================================================
var bridge_lock: spinlock.SpinLock = spinlock.SpinLock.init();
var bridge_initialized: bool = false;
var registered_callbacks: FfiCallbacks = undefined;

// =============================================================================
// Callback implementations — these are the Zig functions that Rust calls
// =============================================================================

/// Called by Rust when it needs to read disk sectors
fn zigDiskReadCallback(
    lba: u64,
    count: u32,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.C) i32 {
    const ata_mod = @import("../drivers/ata.zig");

    if (buffer_len < @as(usize, count) * 512) {
        return @intFromEnum(FfiError.buffer_too_small);
    }

    const buf_slice = buffer[0..buffer_len];
    const sectors_read = ata_mod.readSectors(lba, count, buf_slice) catch {
        return @intFromEnum(FfiError.io_error);
    };
    _ = sectors_read;

    return @intFromEnum(FfiError.success);
}

/// Called by Rust when it needs to write disk sectors
fn zigDiskWriteCallback(
    lba: u64,
    count: u32,
    buffer: [*]const u8,
    buffer_len: usize,
) callconv(.C) i32 {
    const ata_mod = @import("../drivers/ata.zig");

    if (buffer_len < @as(usize, count) * 512) {
        return @intFromEnum(FfiError.buffer_too_small);
    }

    const buf_slice = buffer[0..buffer_len];
    ata_mod.writeSectors(lba, count, buf_slice) catch {
        return @intFromEnum(FfiError.io_error);
    };

    return @intFromEnum(FfiError.success);
}

/// Called by Rust to allocate kernel memory
fn zigAllocCallback(size: usize, alignment: usize) callconv(.C) ?[*]u8 {
    const heap_mod = @import("../mm/heap.zig");
    _ = alignment;
    const result = heap_mod.allocRaw(size) catch return null;
    return result.ptr;
}

/// Called by Rust to free kernel memory
fn zigFreeCallback(ptr: [*]u8, size: usize) callconv(.C) void {
    const heap_mod = @import("../mm/heap.zig");
    heap_mod.freeRaw(ptr, size);
}

/// Called by Rust to log messages through the Zig serial driver
fn zigLogCallback(level: u32, msg: [*]const u8, msg_len: usize) callconv(.C) void {
    const main = @import("../main.zig");

    if (msg_len == 0) return;
    if (msg_len > 4096) return; // Sanity limit on log message size

    const message = msg[0..msg_len];
    const log_level: main.LogLevel = switch (level) {
        0 => .emergency,
        1 => .alert,
        2 => .critical,
        3 => .err,
        4 => .warning,
        5 => .notice,
        6 => .info,
        7 => .debug,
        else => .debug,
    };

    main.klog(log_level, "[RUST] {s}", .{message});
}

/// Called by Rust to gather hardware entropy (from RDRAND, timer jitter, etc.)
fn zigEntropyCallback(buffer: [*]u8, len: usize) callconv(.C) usize {
    const cpu = @import("../arch/x86_64/cpu.zig");

    var collected: usize = 0;
    var i: usize = 0;

    // Try RDRAND first for high-quality entropy
    while (i + 8 <= len) {
        if (cpu.rdrand()) |val| {
            const bytes = std.mem.toBytes(val);
            @memcpy(buffer[i .. i + 8], &bytes);
            i += 8;
            collected += 8;
        } else {
            break;
        }
    }

    // Fill remaining bytes with timer-based entropy if needed
    while (i < len) {
        const tsc = cpu.readTsc();
        buffer[i] = @truncate(tsc ^ (tsc >> 17) ^ (tsc >> 31));
        i += 1;
        collected += 1;
    }

    return collected;
}

// =============================================================================
// Public API — Safe wrappers around Rust FFI functions
// =============================================================================

/// Initialize the Zig ↔ Rust bridge. Must be called before any other FFI function.
/// This registers all callback functions so Rust can call back into Zig.
pub fn initialize() BridgeError!void {
    bridge_lock.acquire();
    defer bridge_lock.release();

    if (bridge_initialized) return;

    registered_callbacks = FfiCallbacks{
        .disk_read = zigDiskReadCallback,
        .disk_write = zigDiskWriteCallback,
        .alloc = zigAllocCallback,
        .free = zigFreeCallback,
        .log = zigLogCallback,
        .entropy_source = zigEntropyCallback,
        .version = FfiCallbacks.CURRENT_VERSION,
    };

    const result: FfiError = @enumFromInt(zxyphor_rust_init(&registered_callbacks));
    if (result != .success) {
        return result.toZigError();
    }

    bridge_initialized = true;
}

/// Shutdown the Rust subsystem cleanly
pub fn shutdown() void {
    bridge_lock.acquire();
    defer bridge_lock.release();

    if (!bridge_initialized) return;

    zxyphor_rust_shutdown();
    bridge_initialized = false;
}

/// Check whether the bridge has been initialized
pub fn isInitialized() bool {
    return bridge_initialized;
}

// =============================================================================
// AES Cryptography Wrappers
// =============================================================================
pub const Aes = struct {
    context: FfiAesContext,

    /// Create a new AES encryption context with the given key and mode
    pub fn init(key: []const u8, mode: u32) BridgeError!Aes {
        var ctx: FfiAesContext = undefined;
        const key_bits: u32 = @intCast(key.len * 8);

        const result: FfiError = @enumFromInt(zxyphor_rust_aes_init(
            &ctx,
            key.ptr,
            key_bits,
            mode,
        ));

        if (result != .success) return result.toZigError();
        return .{ .context = ctx };
    }

    /// Encrypt data using this AES context
    pub fn encrypt(
        self: *const Aes,
        plaintext: []const u8,
        ciphertext: []u8,
        iv: ?[]const u8,
    ) BridgeError!usize {
        var output_len: usize = 0;

        const iv_ptr: ?[*]const u8 = if (iv) |v| v.ptr else null;
        const iv_len: usize = if (iv) |v| v.len else 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_aes_encrypt(
            &self.context,
            plaintext.ptr,
            plaintext.len,
            ciphertext.ptr,
            ciphertext.len,
            &output_len,
            iv_ptr,
            iv_len,
        ));

        if (result != .success) return result.toZigError();
        return output_len;
    }

    /// Decrypt data using this AES context
    pub fn decrypt(
        self: *const Aes,
        ciphertext: []const u8,
        plaintext: []u8,
        iv: ?[]const u8,
    ) BridgeError!usize {
        var output_len: usize = 0;

        const iv_ptr: ?[*]const u8 = if (iv) |v| v.ptr else null;
        const iv_len: usize = if (iv) |v| v.len else 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_aes_decrypt(
            &self.context,
            ciphertext.ptr,
            ciphertext.len,
            plaintext.ptr,
            plaintext.len,
            &output_len,
            iv_ptr,
            iv_len,
        ));

        if (result != .success) return result.toZigError();
        return output_len;
    }
};

// =============================================================================
// SHA-256 Hashing Wrappers
// =============================================================================
pub const Sha256 = struct {
    /// Compute SHA-256 hash of the input data
    pub fn hash(data: []const u8) BridgeError!FfiHashResult {
        var result_hash: FfiHashResult = undefined;

        const rc: FfiError = @enumFromInt(zxyphor_rust_sha256_hash(
            data.ptr,
            data.len,
            &result_hash,
        ));

        if (rc != .success) return rc.toZigError();
        return result_hash;
    }

    /// Compute HMAC-SHA-256 of the message with the given key
    pub fn hmac(key: []const u8, message: []const u8) BridgeError!FfiHashResult {
        var result_hash: FfiHashResult = undefined;

        const rc: FfiError = @enumFromInt(zxyphor_rust_sha256_hmac(
            key.ptr,
            key.len,
            message.ptr,
            message.len,
            &result_hash,
        ));

        if (rc != .success) return rc.toZigError();
        return result_hash;
    }
};

// =============================================================================
// Random Number Generation Wrappers
// =============================================================================
pub const Rng = struct {
    /// Initialize the cryptographic random number generator
    pub fn init() BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_rng_init());
        if (result != .success) return result.toZigError();
    }

    /// Fill a buffer with cryptographically secure random bytes
    pub fn fill(buffer: []u8) BridgeError!void {
        if (buffer.len == 0) return;
        const result: FfiError = @enumFromInt(zxyphor_rust_rng_fill(buffer.ptr, buffer.len));
        if (result != .success) return result.toZigError();
    }

    /// Generate a random 64-bit unsigned integer
    pub fn nextU64() u64 {
        return zxyphor_rust_rng_u64();
    }

    /// Get RNG state information
    pub fn info() BridgeError!FfiRngInfo {
        var rng_info: FfiRngInfo = undefined;
        const result: FfiError = @enumFromInt(zxyphor_rust_rng_info(&rng_info));
        if (result != .success) return result.toZigError();
        return rng_info;
    }

    /// Add entropy to the random number generator
    pub fn addEntropy(data: []const u8) BridgeError!void {
        if (data.len == 0) return;
        const result: FfiError = @enumFromInt(zxyphor_rust_rng_add_entropy(data.ptr, data.len));
        if (result != .success) return result.toZigError();
    }
};

// =============================================================================
// ext4 Filesystem Wrappers
// =============================================================================
pub const Ext4 = struct {
    /// Mount an ext4 partition
    pub fn mount(partition_offset: u64) BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_ext4_mount(
            zigDiskReadCallback,
            partition_offset,
        ));
        if (result != .success) return result.toZigError();
    }

    /// Unmount the ext4 partition
    pub fn unmount() BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_ext4_unmount());
        if (result != .success) return result.toZigError();
    }

    /// Get file/directory information
    pub fn stat(path: []const u8) BridgeError!FfiStatInfo {
        var stat_info: FfiStatInfo = undefined;

        const result: FfiError = @enumFromInt(zxyphor_rust_ext4_stat(
            path.ptr,
            path.len,
            &stat_info,
        ));

        if (result != .success) return result.toZigError();
        return stat_info;
    }

    /// Read file data
    pub fn read(path: []const u8, offset: u64, buffer: []u8) BridgeError!usize {
        var bytes_read: usize = 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_ext4_read(
            path.ptr,
            path.len,
            offset,
            buffer.ptr,
            buffer.len,
            &bytes_read,
        ));

        if (result != .success) return result.toZigError();
        return bytes_read;
    }

    /// Read directory entries
    pub fn readDir(
        path: []const u8,
        entries: []FfiDirEntry,
    ) BridgeError!usize {
        var count: usize = 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_ext4_readdir(
            path.ptr,
            path.len,
            entries.ptr,
            entries.len,
            &count,
        ));

        if (result != .success) return result.toZigError();
        return count;
    }
};

// =============================================================================
// FAT32 Filesystem Wrappers
// =============================================================================
pub const Fat32 = struct {
    /// Mount a FAT32 partition (read-write if disk_write callback is set)
    pub fn mount(partition_offset: u64) BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_mount(
            zigDiskReadCallback,
            zigDiskWriteCallback,
            partition_offset,
        ));
        if (result != .success) return result.toZigError();
    }

    /// Unmount the FAT32 partition
    pub fn unmount() BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_unmount());
        if (result != .success) return result.toZigError();
    }

    /// Get file/directory stat information
    pub fn stat(path: []const u8) BridgeError!FfiStatInfo {
        var stat_info: FfiStatInfo = undefined;

        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_stat(
            path.ptr,
            path.len,
            &stat_info,
        ));

        if (result != .success) return result.toZigError();
        return stat_info;
    }

    /// Read file data
    pub fn read(path: []const u8, offset: u64, buffer: []u8) BridgeError!usize {
        var bytes_read: usize = 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_read(
            path.ptr,
            path.len,
            offset,
            buffer.ptr,
            buffer.len,
            &bytes_read,
        ));

        if (result != .success) return result.toZigError();
        return bytes_read;
    }

    /// Write data to a file
    pub fn write(path: []const u8, offset: u64, data: []const u8) BridgeError!usize {
        var bytes_written: usize = 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_write(
            path.ptr,
            path.len,
            offset,
            data.ptr,
            data.len,
            &bytes_written,
        ));

        if (result != .success) return result.toZigError();
        return bytes_written;
    }

    /// Create a new file or directory
    pub fn create(path: []const u8, mode: u32) BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_create(
            path.ptr,
            path.len,
            mode,
        ));
        if (result != .success) return result.toZigError();
    }

    /// Delete a file or directory
    pub fn delete(path: []const u8) BridgeError!void {
        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_delete(
            path.ptr,
            path.len,
        ));
        if (result != .success) return result.toZigError();
    }

    /// Read directory entries
    pub fn readDir(
        path: []const u8,
        entries: []FfiDirEntry,
    ) BridgeError!usize {
        var count: usize = 0;

        const result: FfiError = @enumFromInt(zxyphor_rust_fat32_readdir(
            path.ptr,
            path.len,
            entries.ptr,
            entries.len,
            &count,
        ));

        if (result != .success) return result.toZigError();
        return count;
    }
};

// =============================================================================
// FFI health check — validates that all expected Rust symbols are linked
// =============================================================================
pub fn healthCheck() bool {
    // Try to access each function pointer to verify linkage
    const init_ptr: *const fn (*const FfiCallbacks) callconv(.C) i32 = &zxyphor_rust_init;
    const shutdown_ptr: *const fn () callconv(.C) void = &zxyphor_rust_shutdown;

    // If we can take addresses of these functions, they are linked
    return @intFromPtr(init_ptr) != 0 and @intFromPtr(shutdown_ptr) != 0;
}

// =============================================================================
// Debug utilities
// =============================================================================
pub fn dumpBridgeState() void {
    const main = @import("../main.zig");

    main.klog(.debug, "FFI Bridge State:", .{});
    main.klog(.debug, "  Initialized: {}", .{bridge_initialized});
    main.klog(.debug, "  Callbacks version: {d}", .{registered_callbacks.version});
    main.klog(.debug, "  Disk read callback: {}", .{registered_callbacks.disk_read != null});
    main.klog(.debug, "  Disk write callback: {}", .{registered_callbacks.disk_write != null});
    main.klog(.debug, "  Alloc callback: {}", .{registered_callbacks.alloc != null});
    main.klog(.debug, "  Free callback: {}", .{registered_callbacks.free != null});
    main.klog(.debug, "  Log callback: {}", .{registered_callbacks.log != null});
    main.klog(.debug, "  Entropy callback: {}", .{registered_callbacks.entropy_source != null});
}
