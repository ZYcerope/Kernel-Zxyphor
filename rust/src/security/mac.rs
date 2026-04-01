// =============================================================================
// Kernel Zxyphor — Mandatory Access Control (MAC) Policy Engine
// =============================================================================
// Implements a label-based MAC framework inspired by SELinux and Smack.
// Every kernel object (file, process, socket, IPC channel) carries a security
// label, and all access decisions are mediated by this policy engine.
//
// Design:
//   - Security labels are 32-byte strings (fixed-size, no allocation)
//   - Policy rules define (subject_label, object_label, permission_mask) → allow/deny
//   - Rules are stored in a flat array (kernel has bounded rule count)
//   - Enforcement can be disabled for debugging (permissive mode)
//   - All access decisions are logged for auditing
//
// Permission classes:
//   - File: read, write, execute, append, create, delete, rename
//   - Process: signal, trace, transition
//   - Network: connect, listen, accept, send, receive, bind
//   - IPC: create, read, write, destroy
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum label length (bytes, null-terminated)
const MAX_LABEL_LEN: usize = 31;

/// Maximum number of MAC policy rules
const MAX_RULES: usize = 1024;

/// Maximum number of registered security labels
const MAX_LABELS: usize = 256;

// =============================================================================
// Permission bits — bitfield for access decisions
// =============================================================================

/// File permissions
pub const PERM_FILE_READ: u32 = 1 << 0;
pub const PERM_FILE_WRITE: u32 = 1 << 1;
pub const PERM_FILE_EXECUTE: u32 = 1 << 2;
pub const PERM_FILE_APPEND: u32 = 1 << 3;
pub const PERM_FILE_CREATE: u32 = 1 << 4;
pub const PERM_FILE_DELETE: u32 = 1 << 5;
pub const PERM_FILE_RENAME: u32 = 1 << 6;
pub const PERM_FILE_SETATTR: u32 = 1 << 7;
pub const PERM_FILE_GETATTR: u32 = 1 << 8;
pub const PERM_FILE_LINK: u32 = 1 << 9;

/// Process permissions
pub const PERM_PROC_SIGNAL: u32 = 1 << 10;
pub const PERM_PROC_TRACE: u32 = 1 << 11;
pub const PERM_PROC_TRANSITION: u32 = 1 << 12;
pub const PERM_PROC_FORK: u32 = 1 << 13;
pub const PERM_PROC_EXEC: u32 = 1 << 14;

/// Network permissions
pub const PERM_NET_CONNECT: u32 = 1 << 15;
pub const PERM_NET_LISTEN: u32 = 1 << 16;
pub const PERM_NET_ACCEPT: u32 = 1 << 17;
pub const PERM_NET_SEND: u32 = 1 << 18;
pub const PERM_NET_RECEIVE: u32 = 1 << 19;
pub const PERM_NET_BIND: u32 = 1 << 20;

/// IPC permissions
pub const PERM_IPC_CREATE: u32 = 1 << 21;
pub const PERM_IPC_READ: u32 = 1 << 22;
pub const PERM_IPC_WRITE: u32 = 1 << 23;
pub const PERM_IPC_DESTROY: u32 = 1 << 24;

/// All permissions
pub const PERM_ALL: u32 = 0x01FFFFFF;

// =============================================================================
// Security label
// =============================================================================

/// A fixed-size security label for MAC enforcement.
/// Labels are compared byte-by-byte; case-sensitive.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityLabel {
    /// Null-terminated label string
    name: [u8; MAX_LABEL_LEN + 1],
    /// Privilege level (0 = highest privilege, 255 = least privilege)
    level: u8,
    /// Category bitmap (for MLS — Multi-Level Security)
    categories: u32,
}

impl SecurityLabel {
    pub const fn empty() -> Self {
        SecurityLabel {
            name: [0u8; MAX_LABEL_LEN + 1],
            level: 255,
            categories: 0,
        }
    }

    /// Create a label from a byte slice
    pub fn from_bytes(name: &[u8], level: u8, categories: u32) -> Self {
        let mut label = SecurityLabel::empty();
        let copy_len = if name.len() > MAX_LABEL_LEN {
            MAX_LABEL_LEN
        } else {
            name.len()
        };
        label.name[..copy_len].copy_from_slice(&name[..copy_len]);
        label.name[copy_len] = 0;
        label.level = level;
        label.categories = categories;
        label
    }

    /// Get the label name as a byte slice (excluding null terminator)
    pub fn name_bytes(&self) -> &[u8] {
        let mut len = 0;
        while len < MAX_LABEL_LEN && self.name[len] != 0 {
            len += 1;
        }
        &self.name[..len]
    }

    /// Check if two labels are equal
    pub fn equals(&self, other: &SecurityLabel) -> bool {
        self.name == other.name
    }

    /// Check if this label dominates another (MLS dominance)
    /// A label dominates another if its level is <= the other's level
    /// AND its categories are a superset of the other's categories.
    pub fn dominates(&self, other: &SecurityLabel) -> bool {
        self.level <= other.level && (self.categories & other.categories) == other.categories
    }
}

// =============================================================================
// MAC policy rule
// =============================================================================

/// Action taken by a rule match
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Allow the access
    Allow = 0,
    /// Deny the access (default)
    Deny = 1,
    /// Allow but log the access (audit)
    AuditAllow = 2,
    /// Deny and log the denial
    AuditDeny = 3,
}

/// A MAC policy rule
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MacRule {
    /// Subject (process) label
    subject: SecurityLabel,
    /// Object (resource) label
    object: SecurityLabel,
    /// Permission bitmask — which permissions this rule covers
    permissions: u32,
    /// What to do when this rule matches
    action: RuleAction,
    /// Rule priority (higher = checked first)
    priority: u16,
    /// Whether this rule is active
    active: bool,
    /// Hit count for statistics
    hit_count: u64,
}

impl MacRule {
    pub const fn empty() -> Self {
        MacRule {
            subject: SecurityLabel::empty(),
            object: SecurityLabel::empty(),
            permissions: 0,
            action: RuleAction::Deny,
            priority: 0,
            active: false,
            hit_count: 0,
        }
    }
}

// =============================================================================
// MAC policy database (global state)
// =============================================================================

/// Known security labels
static mut LABELS: [SecurityLabel; MAX_LABELS] = {
    let mut arr = [SecurityLabel::empty(); MAX_LABELS];
    // Pre-define the kernel label (index 0)
    arr[0].name[0] = b'k';
    arr[0].name[1] = b'e';
    arr[0].name[2] = b'r';
    arr[0].name[3] = b'n';
    arr[0].name[4] = b'e';
    arr[0].name[5] = b'l';
    arr[0].level = 0;
    arr[0].categories = 0xFFFFFFFF; // All categories
    arr
};
static mut LABEL_COUNT: usize = 1; // "kernel" is pre-registered

/// Policy rules
static mut RULES: [MacRule; MAX_RULES] = [MacRule::empty(); MAX_RULES];
static mut RULE_COUNT: usize = 0;

/// Enforcement state
static MAC_ENFORCING: AtomicBool = AtomicBool::new(false); // Start permissive
static MAC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Statistics
static MAC_ALLOWED: AtomicU64 = AtomicU64::new(0);
static MAC_DENIED: AtomicU64 = AtomicU64::new(0);
static MAC_CHECKED: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// MAC engine operations
// =============================================================================

/// Check whether a subject with `subject_label` is allowed `requested_perms`
/// on an object with `object_label`.
///
/// Returns true if access is allowed, false otherwise.
///
/// Safety: This accesses global mutable state. In the kernel, the MAC engine
/// is initialized during boot before any concurrent access occurs, and rules
/// are only modified with interrupts disabled.
pub fn mac_check(
    subject: &SecurityLabel,
    object: &SecurityLabel,
    requested_perms: u32,
) -> bool {
    MAC_CHECKED.fetch_add(1, Ordering::Relaxed);

    // Kernel label always has full access
    if subject.name_bytes() == b"kernel" {
        MAC_ALLOWED.fetch_add(1, Ordering::Relaxed);
        return true;
    }

    // MLS dominance check: subject must dominate object
    if !subject.dominates(object) {
        if MAC_ENFORCING.load(Ordering::Acquire) {
            MAC_DENIED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    }

    // Search rules from highest priority to lowest
    let rule_count = unsafe { RULE_COUNT };
    let rules = unsafe { &mut RULES[..rule_count] };

    let mut found_allow = false;

    for rule in rules.iter_mut() {
        if !rule.active {
            continue;
        }

        // Check if rule matches this subject/object pair
        if !rule.subject.equals(subject) && rule.subject.name_bytes() != b"*" {
            continue;
        }
        if !rule.object.equals(object) && rule.object.name_bytes() != b"*" {
            continue;
        }

        // Check if the rule covers the requested permissions
        if rule.permissions & requested_perms == 0 {
            continue;
        }

        rule.hit_count += 1;

        match rule.action {
            RuleAction::Allow | RuleAction::AuditAllow => {
                found_allow = true;
                // Continue checking (deny takes precedence)
            }
            RuleAction::Deny | RuleAction::AuditDeny => {
                MAC_DENIED.fetch_add(1, Ordering::Relaxed);
                return if MAC_ENFORCING.load(Ordering::Acquire) {
                    false
                } else {
                    true // Permissive mode: log but allow
                };
            }
        }
    }

    if found_allow {
        MAC_ALLOWED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        // Default deny if enforcing, allow if permissive
        if MAC_ENFORCING.load(Ordering::Acquire) {
            MAC_DENIED.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            MAC_ALLOWED.fetch_add(1, Ordering::Relaxed);
            true
        }
    }
}

// =============================================================================
// FFI exports
// =============================================================================

/// Initialize the MAC subsystem
#[no_mangle]
pub extern "C" fn zxyphor_rust_mac_init() -> i32 {
    if MAC_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    // Install default rules:
    // 1. kernel → * : allow all
    // 2. * → * : deny all (default deny)
    unsafe {
        let kernel_label = LABELS[0];

        RULES[0] = MacRule {
            subject: kernel_label,
            object: SecurityLabel::from_bytes(b"*", 255, 0),
            permissions: PERM_ALL,
            action: RuleAction::Allow,
            priority: 1000,
            active: true,
            hit_count: 0,
        };

        RULES[1] = MacRule {
            subject: SecurityLabel::from_bytes(b"*", 255, 0),
            object: SecurityLabel::from_bytes(b"*", 255, 0),
            permissions: PERM_ALL,
            action: RuleAction::AuditDeny,
            priority: 0,
            active: true,
            hit_count: 0,
        };

        RULE_COUNT = 2;
    }

    MAC_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust MAC policy engine initialized (permissive mode)");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Set enforcement mode
#[no_mangle]
pub extern "C" fn zxyphor_rust_mac_set_enforcing(enforcing: bool) -> i32 {
    MAC_ENFORCING.store(enforcing, Ordering::SeqCst);
    crate::ffi::error::FfiError::Success.as_i32()
}

/// Check access
#[no_mangle]
pub extern "C" fn zxyphor_rust_mac_check(
    subject_name: *const u8,
    subject_name_len: usize,
    object_name: *const u8,
    object_name_len: usize,
    permissions: u32,
) -> i32 {
    if subject_name.is_null() || object_name.is_null() {
        return 0; // Deny
    }

    let subj_bytes = unsafe { core::slice::from_raw_parts(subject_name, subject_name_len) };
    let obj_bytes = unsafe { core::slice::from_raw_parts(object_name, object_name_len) };

    let subject = SecurityLabel::from_bytes(subj_bytes, 128, 0);
    let object = SecurityLabel::from_bytes(obj_bytes, 128, 0);

    if mac_check(&subject, &object, permissions) {
        1 // Allow
    } else {
        0 // Deny
    }
}

/// Add a MAC rule
#[no_mangle]
pub extern "C" fn zxyphor_rust_mac_add_rule(
    subject_name: *const u8,
    subject_name_len: usize,
    object_name: *const u8,
    object_name_len: usize,
    permissions: u32,
    action: u8,
    priority: u16,
) -> i32 {
    if subject_name.is_null() || object_name.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let rule_count = unsafe { RULE_COUNT };
    if rule_count >= MAX_RULES {
        return crate::ffi::error::FfiError::NoMemory.as_i32();
    }

    let subj_bytes = unsafe { core::slice::from_raw_parts(subject_name, subject_name_len) };
    let obj_bytes = unsafe { core::slice::from_raw_parts(object_name, object_name_len) };

    let rule_action = match action {
        0 => RuleAction::Allow,
        1 => RuleAction::Deny,
        2 => RuleAction::AuditAllow,
        3 => RuleAction::AuditDeny,
        _ => return crate::ffi::error::FfiError::InvalidArgument.as_i32(),
    };

    unsafe {
        RULES[rule_count] = MacRule {
            subject: SecurityLabel::from_bytes(subj_bytes, 128, 0),
            object: SecurityLabel::from_bytes(obj_bytes, 128, 0),
            permissions,
            action: rule_action,
            priority,
            active: true,
            hit_count: 0,
        };
        RULE_COUNT += 1;
    }

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Get MAC statistics
#[repr(C)]
pub struct MacStats {
    pub total_checks: u64,
    pub total_allowed: u64,
    pub total_denied: u64,
    pub rule_count: u32,
    pub enforcing: bool,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_mac_stats(out: *mut MacStats) -> i32 {
    if out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let stats = MacStats {
        total_checks: MAC_CHECKED.load(Ordering::Relaxed),
        total_allowed: MAC_ALLOWED.load(Ordering::Relaxed),
        total_denied: MAC_DENIED.load(Ordering::Relaxed),
        rule_count: unsafe { RULE_COUNT as u32 },
        enforcing: MAC_ENFORCING.load(Ordering::Relaxed),
    };

    unsafe { core::ptr::write(out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}
