// =============================================================================
// Kernel Zxyphor — Security Audit Log Engine
// =============================================================================
// Provides structured audit logging for all security-relevant kernel events.
// Events are stored in a lock-free ring buffer for high-throughput logging
// without blocking the caller (critical for interrupt context).
//
// Event categories:
//   - AUTH: Authentication events (login, logout, privilege changes)
//   - ACCESS: MAC/DAC access decisions
//   - SYSTEM: Kernel configuration changes, module loads
//   - NETWORK: Network security events (connection tracking, firewall)
//   - INTEGRITY: File/binary integrity verification results
//   - PROCESS: Process lifecycle security events
//
// The ring buffer holds up to 8192 events. Older events are silently
// overwritten when the buffer is full (best-effort logging).
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Maximum audit events in the ring buffer
const AUDIT_BUFFER_SIZE: usize = 8192;
const AUDIT_BUFFER_MASK: usize = AUDIT_BUFFER_SIZE - 1;

/// Maximum message length per audit event
const MAX_AUDIT_MSG_LEN: usize = 128;

/// Maximum context/detail length
const MAX_AUDIT_DETAIL_LEN: usize = 64;

// =============================================================================
// Audit event types
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCategory {
    Auth = 0,
    Access = 1,
    System = 2,
    Network = 3,
    Integrity = 4,
    Process = 5,
    FileSystem = 6,
    Ipc = 7,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    /// Informational (successful operations)
    Info = 0,
    /// Warning (policy violation in permissive mode)
    Warning = 1,
    /// Error (policy violation in enforcing mode)
    Error = 2,
    /// Critical (integrity violation, potential compromise)
    Critical = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResult {
    Success = 0,
    Failure = 1,
    Denied = 2,
}

// =============================================================================
// Audit event record
// =============================================================================

/// A single audit event record
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuditEvent {
    /// Monotonic event sequence number
    pub sequence: u64,
    /// Timestamp (kernel ticks since boot)
    pub timestamp: u64,
    /// Event category
    pub category: AuditCategory,
    /// Event severity
    pub severity: AuditSeverity,
    /// Result of the audited operation
    pub result: AuditResult,
    /// PID of the process that triggered the event
    pub pid: u32,
    /// UID of the user
    pub uid: u32,
    /// Human-readable message
    pub message: [u8; MAX_AUDIT_MSG_LEN],
    /// Message length (valid bytes in message)
    pub message_len: u8,
    /// Additional context/detail
    pub detail: [u8; MAX_AUDIT_DETAIL_LEN],
    /// Detail length
    pub detail_len: u8,
}

impl AuditEvent {
    pub const fn empty() -> Self {
        AuditEvent {
            sequence: 0,
            timestamp: 0,
            category: AuditCategory::System,
            severity: AuditSeverity::Info,
            result: AuditResult::Success,
            pid: 0,
            uid: 0,
            message: [0u8; MAX_AUDIT_MSG_LEN],
            message_len: 0,
            detail: [0u8; MAX_AUDIT_DETAIL_LEN],
            detail_len: 0,
        }
    }
}

// =============================================================================
// Audit ring buffer (lock-free, single-writer)
// =============================================================================

/// The global audit ring buffer
static mut AUDIT_BUFFER: [AuditEvent; AUDIT_BUFFER_SIZE] = [AuditEvent::empty(); AUDIT_BUFFER_SIZE];

/// Write head (only increments, wraps via mask)
static AUDIT_WRITE_HEAD: AtomicU64 = AtomicU64::new(0);

/// Read tail (for consumers draining the log)
static AUDIT_READ_TAIL: AtomicU64 = AtomicU64::new(0);

/// Next sequence number
static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Total events logged
static AUDIT_TOTAL_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Events dropped (overwritten before being read)
static AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Whether audit is enabled
static AUDIT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Audit filter: minimum severity to log
static AUDIT_MIN_SEVERITY: AtomicU32 = AtomicU32::new(0); // Info = log everything

// =============================================================================
// Audit log operations
// =============================================================================

/// Log an audit event
///
/// This is designed to be called from any context (including interrupt handlers).
/// It never blocks or allocates memory.
pub fn audit_log(
    category: AuditCategory,
    severity: AuditSeverity,
    result: AuditResult,
    pid: u32,
    uid: u32,
    message: &[u8],
    detail: &[u8],
) {
    if !AUDIT_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    // Filter by severity
    if (severity as u32) < AUDIT_MIN_SEVERITY.load(Ordering::Relaxed) {
        return;
    }

    let seq = AUDIT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let head = AUDIT_WRITE_HEAD.fetch_add(1, Ordering::SeqCst);
    let idx = (head as usize) & AUDIT_BUFFER_MASK;

    // Build the event
    let mut event = AuditEvent::empty();
    event.sequence = seq;
    event.timestamp = 0; // Would be filled from kernel tick counter via FFI
    event.category = category;
    event.severity = severity;
    event.result = result;
    event.pid = pid;
    event.uid = uid;

    let msg_len = if message.len() > MAX_AUDIT_MSG_LEN {
        MAX_AUDIT_MSG_LEN
    } else {
        message.len()
    };
    event.message[..msg_len].copy_from_slice(&message[..msg_len]);
    event.message_len = msg_len as u8;

    let det_len = if detail.len() > MAX_AUDIT_DETAIL_LEN {
        MAX_AUDIT_DETAIL_LEN
    } else {
        detail.len()
    };
    event.detail[..det_len].copy_from_slice(&detail[..det_len]);
    event.detail_len = det_len as u8;

    // Write to ring buffer
    unsafe {
        AUDIT_BUFFER[idx] = event;
    }

    AUDIT_TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);

    // Check for overflow (write overtook read)
    let tail = AUDIT_READ_TAIL.load(Ordering::Relaxed);
    if head.wrapping_sub(tail) >= AUDIT_BUFFER_SIZE as u64 {
        AUDIT_DROPPED.fetch_add(1, Ordering::Relaxed);
        // Advance tail to avoid reading stale data
        let _ = AUDIT_READ_TAIL.compare_exchange(
            tail,
            head.wrapping_sub(AUDIT_BUFFER_SIZE as u64 - 1),
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
    }
}

/// Read the next audit event (returns false if no events available)
pub fn audit_read(event_out: &mut AuditEvent) -> bool {
    let tail = AUDIT_READ_TAIL.load(Ordering::Acquire);
    let head = AUDIT_WRITE_HEAD.load(Ordering::Acquire);

    if tail >= head {
        return false; // No events available
    }

    let idx = (tail as usize) & AUDIT_BUFFER_MASK;

    unsafe {
        *event_out = AUDIT_BUFFER[idx];
    }

    AUDIT_READ_TAIL.fetch_add(1, Ordering::Release);
    true
}

// =============================================================================
// Convenience logging functions
// =============================================================================

pub fn audit_access_allowed(pid: u32, uid: u32, resource: &[u8]) {
    audit_log(
        AuditCategory::Access,
        AuditSeverity::Info,
        AuditResult::Success,
        pid,
        uid,
        b"access granted",
        resource,
    );
}

pub fn audit_access_denied(pid: u32, uid: u32, resource: &[u8]) {
    audit_log(
        AuditCategory::Access,
        AuditSeverity::Error,
        AuditResult::Denied,
        pid,
        uid,
        b"access denied",
        resource,
    );
}

pub fn audit_auth_success(pid: u32, uid: u32, detail: &[u8]) {
    audit_log(
        AuditCategory::Auth,
        AuditSeverity::Info,
        AuditResult::Success,
        pid,
        uid,
        b"authentication success",
        detail,
    );
}

pub fn audit_auth_failure(pid: u32, uid: u32, detail: &[u8]) {
    audit_log(
        AuditCategory::Auth,
        AuditSeverity::Warning,
        AuditResult::Failure,
        pid,
        uid,
        b"authentication failure",
        detail,
    );
}

pub fn audit_integrity_violation(pid: u32, detail: &[u8]) {
    audit_log(
        AuditCategory::Integrity,
        AuditSeverity::Critical,
        AuditResult::Failure,
        pid,
        0,
        b"integrity violation detected",
        detail,
    );
}

// =============================================================================
// FFI exports
// =============================================================================

/// Initialize the audit subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_audit_init() -> i32 {
    AUDIT_ENABLED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust audit subsystem initialized");
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Set minimum severity filter
#[no_mangle]
pub extern "C" fn zxyphor_rust_audit_set_severity(min_severity: u32) -> i32 {
    if min_severity > 3 {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }
    AUDIT_MIN_SEVERITY.store(min_severity, Ordering::SeqCst);
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Log an audit event from the Zig side
#[no_mangle]
pub extern "C" fn zxyphor_rust_audit_log(
    category: u8,
    severity: u8,
    result: u8,
    pid: u32,
    uid: u32,
    message: *const u8,
    message_len: usize,
    detail: *const u8,
    detail_len: usize,
) -> i32 {
    let cat = match category {
        0 => AuditCategory::Auth,
        1 => AuditCategory::Access,
        2 => AuditCategory::System,
        3 => AuditCategory::Network,
        4 => AuditCategory::Integrity,
        5 => AuditCategory::Process,
        6 => AuditCategory::FileSystem,
        7 => AuditCategory::Ipc,
        _ => return crate::ffi::error::FfiError::InvalidArgument.as_i32(),
    };
    let sev = match severity {
        0 => AuditSeverity::Info,
        1 => AuditSeverity::Warning,
        2 => AuditSeverity::Error,
        3 => AuditSeverity::Critical,
        _ => return crate::ffi::error::FfiError::InvalidArgument.as_i32(),
    };
    let res = match result {
        0 => AuditResult::Success,
        1 => AuditResult::Failure,
        2 => AuditResult::Denied,
        _ => return crate::ffi::error::FfiError::InvalidArgument.as_i32(),
    };

    let msg = if !message.is_null() && message_len > 0 {
        unsafe { core::slice::from_raw_parts(message, message_len) }
    } else {
        b""
    };
    let det = if !detail.is_null() && detail_len > 0 {
        unsafe { core::slice::from_raw_parts(detail, detail_len) }
    } else {
        b""
    };

    audit_log(cat, sev, res, pid, uid, msg, det);
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Read the next audit event
#[no_mangle]
pub extern "C" fn zxyphor_rust_audit_read(event_out: *mut AuditEvent) -> i32 {
    if event_out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let event = unsafe { &mut *event_out };
    if audit_read(event) {
        crate::ffi::error::FfiError::Success.as_i32()
    } else {
        crate::ffi::error::FfiError::NotFound.as_i32()
    }
}

/// Get audit statistics
#[repr(C)]
pub struct AuditStats {
    pub total_events: u64,
    pub dropped_events: u64,
    pub buffer_size: u32,
    pub pending_events: u64,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_audit_stats(out: *mut AuditStats) -> i32 {
    if out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let head = AUDIT_WRITE_HEAD.load(Ordering::Relaxed);
    let tail = AUDIT_READ_TAIL.load(Ordering::Relaxed);

    let stats = AuditStats {
        total_events: AUDIT_TOTAL_EVENTS.load(Ordering::Relaxed),
        dropped_events: AUDIT_DROPPED.load(Ordering::Relaxed),
        buffer_size: AUDIT_BUFFER_SIZE as u32,
        pending_events: head.saturating_sub(tail),
    };

    unsafe { core::ptr::write(out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}
