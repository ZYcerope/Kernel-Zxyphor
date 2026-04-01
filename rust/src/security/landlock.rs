//! Kernel Zxyphor — Landlock Security Module
//!
//! Landlock is a stackable Linux Security Module (LSM) that allows
//! unprivileged processes to restrict their own access rights.
//! This implementation includes:
//! - Rule-based access control for filesystem
//! - Rule-based access control for networking
//! - Ruleset creation and enforcement
//! - Domain hierarchy and inheritance
//! - Compatibility with other LSMs
//! - Audit logging for denied accesses

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Landlock ABI / Access Rights
// ============================================================================

/// Landlock ABI version.
pub const LANDLOCK_ABI_VERSION: u32 = 4;

/// Filesystem access rights.
pub mod fs_access {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    pub const REFER: u64 = 1 << 13;
    pub const TRUNCATE: u64 = 1 << 14;
    pub const IOCTL_DEV: u64 = 1 << 15;

    /// All filesystem access rights.
    pub const ALL: u64 = (1 << 16) - 1;
}

/// Network access rights.
pub mod net_access {
    pub const BIND_TCP: u64 = 1 << 0;
    pub const CONNECT_TCP: u64 = 1 << 1;

    pub const ALL: u64 = (1 << 2) - 1;
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LandlockError {
    InvalidArgument = -22,    // EINVAL
    NotPermitted = -1,        // EPERM
    OutOfMemory = -12,        // ENOMEM
    BadFd = -9,               // EBADF
    Inval = -22,              // EINVAL
    Nosys = -38,              // ENOSYS
    TooManyRules = -28,       // ENOSPC
}

pub type LandlockResult<T> = Result<T, LandlockError>;

// ============================================================================
// Ruleset Attributes
// ============================================================================

/// Attributes for creating a new Landlock ruleset.
#[repr(C)]
pub struct LandlockRulesetAttr {
    /// Bitmask of filesystem access rights handled by this ruleset
    pub handled_access_fs: u64,
    /// Bitmask of network access rights handled by this ruleset
    pub handled_access_net: u64,
}

/// Rule types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LandlockRuleType {
    PathBeneath = 1,
    NetPort = 2,
}

/// Path-beneath rule attribute.
#[repr(C)]
pub struct LandlockPathBeneathAttr {
    /// Allowed access rights for this path
    pub allowed_access: u64,
    /// File descriptor of the parent directory
    pub parent_fd: i32,
}

/// Network port rule attribute.
#[repr(C)]
pub struct LandlockNetPortAttr {
    /// Allowed access rights for this port
    pub allowed_access: u64,
    /// Port number (host byte order)
    pub port: u64,
}

// ============================================================================
// Internal Rule Structures
// ============================================================================

/// Maximum number of rules per ruleset.
const MAX_RULES_PER_RULESET: usize = 4096;
/// Maximum number of filesystem rules.
const MAX_FS_RULES: usize = 2048;
/// Maximum number of network rules.
const MAX_NET_RULES: usize = 1024;

/// Internal filesystem rule.
pub struct FsRule {
    /// Allowed access bitmask
    pub allowed_access: u64,
    /// Inode number of the parent directory
    pub parent_inode: u64,
    /// Device number
    pub parent_dev: u64,
    /// Whether this rule covers the directory itself
    pub is_self: bool,
    /// Rule priority (for ordering)
    pub priority: u32,
    /// Next rule in hash chain
    pub next: *mut FsRule,
}

unsafe impl Send for FsRule {}
unsafe impl Sync for FsRule {}

/// Internal network rule.
pub struct NetRule {
    /// Allowed access bitmask (bind/connect)
    pub allowed_access: u64,
    /// Port number
    pub port: u16,
    /// Next rule in hash chain
    pub next: *mut NetRule,
}

unsafe impl Send for NetRule {}
unsafe impl Sync for NetRule {}

/// Hash table for fast rule lookup.
pub struct RuleHashTable {
    /// Hash buckets for filesystem rules
    pub fs_buckets: [*mut FsRule; 256],
    /// Hash buckets for network rules
    pub net_buckets: [*mut NetRule; 64],
    /// Total number of FS rules
    pub fs_count: u32,
    /// Total number of net rules
    pub net_count: u32,
}

impl RuleHashTable {
    pub const fn new() -> Self {
        RuleHashTable {
            fs_buckets: [core::ptr::null_mut(); 256],
            net_buckets: [core::ptr::null_mut(); 64],
            fs_count: 0,
            net_count: 0,
        }
    }

    /// Hash an inode+device to a bucket index.
    fn hash_fs(inode: u64, dev: u64) -> usize {
        let h = inode.wrapping_mul(0x9E3779B97F4A7C15) ^ dev.wrapping_mul(0x517CC1B727220A95);
        (h >> 56) as usize
    }

    /// Hash a port to a bucket index.
    fn hash_net(port: u16) -> usize {
        (port as usize) % 64
    }

    /// Look up filesystem rules matching the given inode/device.
    pub fn lookup_fs(&self, inode: u64, dev: u64) -> u64 {
        let idx = Self::hash_fs(inode, dev);
        let mut allowed: u64 = 0;
        let mut entry = self.fs_buckets[idx];
        while !entry.is_null() {
            unsafe {
                if (*entry).parent_inode == inode && (*entry).parent_dev == dev {
                    allowed |= (*entry).allowed_access;
                }
                entry = (*entry).next;
            }
        }
        allowed
    }

    /// Look up network rules matching the given port.
    pub fn lookup_net(&self, port: u16) -> u64 {
        let idx = Self::hash_net(port);
        let mut allowed: u64 = 0;
        let mut entry = self.net_buckets[idx];
        while !entry.is_null() {
            unsafe {
                if (*entry).port == port {
                    allowed |= (*entry).allowed_access;
                }
                entry = (*entry).next;
            }
        }
        allowed
    }
}

// ============================================================================
// Ruleset
// ============================================================================

/// A Landlock ruleset — the top-level container for access rules.
pub struct LandlockRuleset {
    /// Unique ruleset ID
    pub id: u64,
    /// Handled filesystem access rights
    pub handled_access_fs: u64,
    /// Handled network access rights
    pub handled_access_net: u64,
    /// Rule lookup table
    pub rules: RuleHashTable,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Is this ruleset enforced?
    pub enforced: AtomicBool,
    /// Number of rules
    pub num_rules: AtomicU32,
    /// Maximum allowed rules
    pub max_rules: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Owning process PID
    pub owner_pid: i32,
}

impl LandlockRuleset {
    /// Create a new ruleset.
    pub fn new(
        id: u64,
        handled_fs: u64,
        handled_net: u64,
        owner_pid: i32,
    ) -> LandlockResult<Self> {
        // Validate: only valid access rights
        if handled_fs & !fs_access::ALL != 0 {
            return Err(LandlockError::InvalidArgument);
        }
        if handled_net & !net_access::ALL != 0 {
            return Err(LandlockError::InvalidArgument);
        }
        // Must handle at least one type
        if handled_fs == 0 && handled_net == 0 {
            return Err(LandlockError::InvalidArgument);
        }

        Ok(LandlockRuleset {
            id,
            handled_access_fs: handled_fs,
            handled_access_net: handled_net,
            rules: RuleHashTable::new(),
            ref_count: AtomicU32::new(1),
            enforced: AtomicBool::new(false),
            num_rules: AtomicU32::new(0),
            max_rules: MAX_RULES_PER_RULESET as u32,
            created_at: 0, // Would be set by caller
            owner_pid,
        })
    }

    /// Add a filesystem rule to the ruleset.
    pub fn add_fs_rule(
        &mut self,
        allowed_access: u64,
        parent_inode: u64,
        parent_dev: u64,
    ) -> LandlockResult<()> {
        if self.enforced.load(Ordering::Relaxed) {
            return Err(LandlockError::InvalidArgument); // Can't modify after enforce
        }

        // Validate: allowed must be subset of handled
        if allowed_access & !self.handled_access_fs != 0 {
            return Err(LandlockError::InvalidArgument);
        }

        if self.rules.fs_count >= MAX_FS_RULES as u32 {
            return Err(LandlockError::TooManyRules);
        }

        // In production: allocate from slab, insert into hash table
        self.rules.fs_count += 1;
        self.num_rules.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Add a network port rule to the ruleset.
    pub fn add_net_rule(&mut self, allowed_access: u64, port: u16) -> LandlockResult<()> {
        if self.enforced.load(Ordering::Relaxed) {
            return Err(LandlockError::InvalidArgument);
        }

        if allowed_access & !self.handled_access_net != 0 {
            return Err(LandlockError::InvalidArgument);
        }

        if self.rules.net_count >= MAX_NET_RULES as u32 {
            return Err(LandlockError::TooManyRules);
        }

        self.rules.net_count += 1;
        self.num_rules.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Enforce the ruleset (restrict self).
    pub fn enforce(&self) -> LandlockResult<()> {
        self.enforced.store(true, Ordering::Release);
        Ok(())
    }
}

// ============================================================================
// Landlock Domain
// ============================================================================

/// A domain represents the cumulative access restrictions for a process.
/// Domains form a hierarchy: child inherits parent's restrictions plus its own.
pub struct LandlockDomain {
    /// Domain ID
    pub id: u64,
    /// Parent domain (inherited from parent process)
    pub parent: *mut LandlockDomain,
    /// Depth in the domain hierarchy
    pub depth: u32,
    /// Maximum depth allowed
    pub max_depth: u32,
    /// Rulesets that compose this domain (stacked)
    pub rulesets: [*mut LandlockRuleset; 16],
    pub num_rulesets: u32,
    /// Effective handled FS access (union of all rulesets)
    pub handled_access_fs: u64,
    /// Effective handled net access
    pub handled_access_net: u64,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Statistics
    pub stats: DomainStats,
}

unsafe impl Send for LandlockDomain {}
unsafe impl Sync for LandlockDomain {}

/// Per-domain statistics.
pub struct DomainStats {
    pub fs_checks: AtomicU64,
    pub fs_denials: AtomicU64,
    pub net_checks: AtomicU64,
    pub net_denials: AtomicU64,
}

impl LandlockDomain {
    /// Create a new domain by adding a ruleset on top of an existing domain.
    pub fn new(
        id: u64,
        parent: *mut LandlockDomain,
        ruleset: *mut LandlockRuleset,
    ) -> LandlockResult<Self> {
        let (depth, max_depth) = if parent.is_null() {
            (0, 16)
        } else {
            unsafe {
                let parent_ref = &*parent;
                if parent_ref.depth + 1 >= parent_ref.max_depth {
                    return Err(LandlockError::TooManyRules);
                }
                (parent_ref.depth + 1, parent_ref.max_depth)
            }
        };

        let mut domain = LandlockDomain {
            id,
            parent,
            depth,
            max_depth,
            rulesets: [core::ptr::null_mut(); 16],
            num_rulesets: 0,
            handled_access_fs: 0,
            handled_access_net: 0,
            ref_count: AtomicU32::new(1),
            stats: DomainStats {
                fs_checks: AtomicU64::new(0),
                fs_denials: AtomicU64::new(0),
                net_checks: AtomicU64::new(0),
                net_denials: AtomicU64::new(0),
            },
        };

        // Inherit parent's rulesets
        if !parent.is_null() {
            unsafe {
                let parent_ref = &*parent;
                for i in 0..parent_ref.num_rulesets as usize {
                    if i < 16 {
                        domain.rulesets[i] = parent_ref.rulesets[i];
                        domain.num_rulesets += 1;
                    }
                }
                domain.handled_access_fs = parent_ref.handled_access_fs;
                domain.handled_access_net = parent_ref.handled_access_net;
            }
        }

        // Add new ruleset
        if !ruleset.is_null() {
            let idx = domain.num_rulesets as usize;
            if idx >= 16 {
                return Err(LandlockError::TooManyRules);
            }
            domain.rulesets[idx] = ruleset;
            domain.num_rulesets += 1;
            unsafe {
                domain.handled_access_fs |= (*ruleset).handled_access_fs;
                domain.handled_access_net |= (*ruleset).handled_access_net;
            }
        }

        Ok(domain)
    }

    /// Check if a filesystem access is allowed by this domain.
    ///
    /// The access check walks all rulesets in the domain. For each ruleset
    /// that handles the requested access type, the request must be explicitly
    /// allowed by at least one rule.
    pub fn check_fs_access(
        &self,
        requested_access: u64,
        inode: u64,
        dev: u64,
    ) -> bool {
        self.stats.fs_checks.fetch_add(1, Ordering::Relaxed);

        // Only check access types that are actually handled
        let relevant = requested_access & self.handled_access_fs;
        if relevant == 0 {
            return true; // Not handled by any ruleset — allow
        }

        // For each ruleset, check if the relevant access is allowed
        for i in 0..self.num_rulesets as usize {
            let rs = self.rulesets[i];
            if rs.is_null() {
                continue;
            }

            unsafe {
                let ruleset = &*rs;
                let handled = requested_access & ruleset.handled_access_fs;
                if handled == 0 {
                    continue; // This ruleset doesn't handle these access types
                }

                // Look up rules matching this inode/dev
                let allowed = ruleset.rules.lookup_fs(inode, dev);

                // For this ruleset, the requested access must be allowed
                if handled & !allowed != 0 {
                    self.stats.fs_denials.fetch_add(1, Ordering::Relaxed);
                    return false; // Some handled access is not allowed
                }
            }
        }

        true
    }

    /// Check if a network access is allowed by this domain.
    pub fn check_net_access(&self, requested_access: u64, port: u16) -> bool {
        self.stats.net_checks.fetch_add(1, Ordering::Relaxed);

        let relevant = requested_access & self.handled_access_net;
        if relevant == 0 {
            return true;
        }

        for i in 0..self.num_rulesets as usize {
            let rs = self.rulesets[i];
            if rs.is_null() {
                continue;
            }

            unsafe {
                let ruleset = &*rs;
                let handled = requested_access & ruleset.handled_access_net;
                if handled == 0 {
                    continue;
                }

                let allowed = ruleset.rules.lookup_net(port);
                if handled & !allowed != 0 {
                    self.stats.net_denials.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            }
        }

        true
    }
}

// ============================================================================
// Landlock LSM Hooks
// ============================================================================

/// LSM hook: check file open permission.
pub fn landlock_file_open(
    domain: *const LandlockDomain,
    inode: u64,
    dev: u64,
    flags: u32,
) -> i32 {
    if domain.is_null() {
        return 0; // No Landlock domain — allow
    }

    let mut access: u64 = fs_access::READ_FILE;
    if flags & 0x01 != 0 || flags & 0x02 != 0 {
        // O_WRONLY or O_RDWR
        access |= fs_access::WRITE_FILE;
    }

    unsafe {
        if (*domain).check_fs_access(access, inode, dev) {
            0
        } else {
            -13 // EACCES
        }
    }
}

/// LSM hook: check file mknod permission.
pub fn landlock_path_mknod(
    domain: *const LandlockDomain,
    parent_inode: u64,
    parent_dev: u64,
    mode: u32,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    let access = match mode & 0xF000 {
        0x8000 => fs_access::MAKE_REG,   // S_IFREG
        0x2000 => fs_access::MAKE_CHAR,  // S_IFCHR
        0x6000 => fs_access::MAKE_BLOCK, // S_IFBLK
        0x1000 => fs_access::MAKE_FIFO,  // S_IFIFO
        0xC000 => fs_access::MAKE_SOCK,  // S_IFSOCK
        _ => return 0,
    };

    unsafe {
        if (*domain).check_fs_access(access, parent_inode, parent_dev) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check directory creation.
pub fn landlock_path_mkdir(
    domain: *const LandlockDomain,
    parent_inode: u64,
    parent_dev: u64,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    unsafe {
        if (*domain).check_fs_access(fs_access::MAKE_DIR, parent_inode, parent_dev) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check file unlink.
pub fn landlock_path_unlink(
    domain: *const LandlockDomain,
    parent_inode: u64,
    parent_dev: u64,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    unsafe {
        if (*domain).check_fs_access(fs_access::REMOVE_FILE, parent_inode, parent_dev) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check directory removal.
pub fn landlock_path_rmdir(
    domain: *const LandlockDomain,
    parent_inode: u64,
    parent_dev: u64,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    unsafe {
        if (*domain).check_fs_access(fs_access::REMOVE_DIR, parent_inode, parent_dev) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check symlink creation.
pub fn landlock_path_symlink(
    domain: *const LandlockDomain,
    parent_inode: u64,
    parent_dev: u64,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    unsafe {
        if (*domain).check_fs_access(fs_access::MAKE_SYM, parent_inode, parent_dev) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check file rename.
pub fn landlock_path_rename(
    domain: *const LandlockDomain,
    old_parent_inode: u64,
    old_parent_dev: u64,
    new_parent_inode: u64,
    new_parent_dev: u64,
    _is_exchange: bool,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    unsafe {
        // Need REMOVE_FILE on source and MAKE_REG on destination
        if !(*domain).check_fs_access(fs_access::REMOVE_FILE, old_parent_inode, old_parent_dev) {
            return -13;
        }
        if !(*domain).check_fs_access(fs_access::MAKE_REG, new_parent_inode, new_parent_dev) {
            return -13;
        }

        // If cross-directory (REFER right needed)
        if old_parent_inode != new_parent_inode || old_parent_dev != new_parent_dev {
            if !(*domain).check_fs_access(
                fs_access::REFER,
                old_parent_inode,
                old_parent_dev,
            ) {
                return -1; // EXDEV
            }
        }
    }

    0
}

/// LSM hook: check file truncate.
pub fn landlock_file_truncate(
    domain: *const LandlockDomain,
    inode: u64,
    dev: u64,
) -> i32 {
    if domain.is_null() {
        return 0;
    }

    unsafe {
        if (*domain).check_fs_access(fs_access::TRUNCATE, inode, dev) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check TCP bind.
pub fn landlock_socket_bind(
    domain: *const LandlockDomain,
    port: u16,
    family: u16,
) -> i32 {
    if domain.is_null() || family != 2 && family != 10 {
        // Only check AF_INET and AF_INET6
        return 0;
    }

    unsafe {
        if (*domain).check_net_access(net_access::BIND_TCP, port) {
            0
        } else {
            -13
        }
    }
}

/// LSM hook: check TCP connect.
pub fn landlock_socket_connect(
    domain: *const LandlockDomain,
    port: u16,
    family: u16,
) -> i32 {
    if domain.is_null() || family != 2 && family != 10 {
        return 0;
    }

    unsafe {
        if (*domain).check_net_access(net_access::CONNECT_TCP, port) {
            0
        } else {
            -13
        }
    }
}

// ============================================================================
// Syscall Interface
// ============================================================================

/// Syscall: landlock_create_ruleset
#[no_mangle]
pub extern "C" fn sys_landlock_create_ruleset(
    attr: *const LandlockRulesetAttr,
    size: usize,
    flags: u32,
) -> i64 {
    // GET_ABI_VERSION
    if flags == 0x1 && attr.is_null() && size == 0 {
        return LANDLOCK_ABI_VERSION as i64;
    }

    if attr.is_null() || size < core::mem::size_of::<LandlockRulesetAttr>() {
        return -22; // EINVAL
    }

    if flags != 0 {
        return -22;
    }

    unsafe {
        let handled_fs = (*attr).handled_access_fs;
        let handled_net = (*attr).handled_access_net;

        // Validate access rights
        if handled_fs & !fs_access::ALL != 0 {
            return -22;
        }
        if handled_net & !net_access::ALL != 0 {
            return -22;
        }
        if handled_fs == 0 && handled_net == 0 {
            return -22;
        }
    }

    // Create ruleset, allocate FD, return it
    // Production: allocate ruleset, create anonymous inode FD
    0 // Placeholder FD
}

/// Syscall: landlock_add_rule
#[no_mangle]
pub extern "C" fn sys_landlock_add_rule(
    ruleset_fd: i32,
    rule_type: u32,
    rule_attr: *const u8,
    flags: u32,
) -> i64 {
    if flags != 0 || rule_attr.is_null() {
        return -22;
    }

    if ruleset_fd < 0 {
        return -9; // EBADF
    }

    match rule_type {
        1 => {
            // LANDLOCK_RULE_PATH_BENEATH
            let _attr = rule_attr as *const LandlockPathBeneathAttr;
            // Validate and add filesystem rule
        }
        2 => {
            // LANDLOCK_RULE_NET_PORT
            let _attr = rule_attr as *const LandlockNetPortAttr;
            // Validate and add network rule
        }
        _ => return -22,
    }

    0
}

/// Syscall: landlock_restrict_self
#[no_mangle]
pub extern "C" fn sys_landlock_restrict_self(
    ruleset_fd: i32,
    flags: u32,
) -> i64 {
    if flags != 0 {
        return -22;
    }

    if ruleset_fd < 0 {
        return -9;
    }

    // Enforce the ruleset:
    // 1. Get the ruleset from the FD
    // 2. Create a new domain by layering this ruleset
    // 3. Set the current task's domain to the new domain
    // 4. This is irreversible — no_new_privs must be set

    0
}

// ============================================================================
// Landlock Audit
// ============================================================================

/// Audit event types.
#[derive(Debug, Clone, Copy)]
pub enum LandlockAuditEvent {
    FsAccessDenied {
        pid: i32,
        inode: u64,
        dev: u64,
        requested: u64,
        handled: u64,
    },
    NetAccessDenied {
        pid: i32,
        port: u16,
        requested: u64,
    },
    RulesetCreated {
        pid: i32,
        ruleset_id: u64,
        handled_fs: u64,
        handled_net: u64,
    },
    DomainCreated {
        pid: i32,
        domain_id: u64,
        depth: u32,
    },
}

/// Audit log ring buffer.
pub struct LandlockAuditLog {
    pub events: [LandlockAuditEvent; 4096],
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub overflow_count: AtomicU64,
}

impl LandlockAuditLog {
    pub fn log(&self, event: LandlockAuditEvent) {
        let head = self.head.load(Ordering::Relaxed);
        let next = (head + 1) % 4096;
        if next == self.tail.load(Ordering::Relaxed) {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Would use write to events[head]
        let _ = event;
        self.head.store(next, Ordering::Release);
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the Landlock LSM.
#[no_mangle]
pub extern "C" fn landlock_init() -> i32 {
    // Register LSM hooks
    // Initialize audit subsystem
    0
}
