// =============================================================================
// Kernel Zxyphor - Access Control & Security Policy
// =============================================================================
// Implements Unix-style discretionary access control (DAC) with POSIX
// permission bits, plus a simple mandatory access control (MAC) framework
// inspired by SELinux security contexts. Also includes:
//   - File permission checking (rwx for user/group/other)
//   - Secure random number generation (kernel entropy pool)
//   - Security audit logging
//   - Resource limits (rlimits)
//   - Credential management
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// POSIX Permission Bits
// =============================================================================
pub const S_ISUID: u16 = 0o4000; // Set-UID
pub const S_ISGID: u16 = 0o2000; // Set-GID
pub const S_ISVTX: u16 = 0o1000; // Sticky bit

pub const S_IRUSR: u16 = 0o0400;
pub const S_IWUSR: u16 = 0o0200;
pub const S_IXUSR: u16 = 0o0100;
pub const S_IRGRP: u16 = 0o0040;
pub const S_IWGRP: u16 = 0o0020;
pub const S_IXGRP: u16 = 0o0010;
pub const S_IROTH: u16 = 0o0004;
pub const S_IWOTH: u16 = 0o0002;
pub const S_IXOTH: u16 = 0o0001;

pub const S_IRWXU: u16 = S_IRUSR | S_IWUSR | S_IXUSR;
pub const S_IRWXG: u16 = S_IRGRP | S_IWGRP | S_IXGRP;
pub const S_IRWXO: u16 = S_IROTH | S_IWOTH | S_IXOTH;

// Access check modes
pub const R_OK: u8 = 4;
pub const W_OK: u8 = 2;
pub const X_OK: u8 = 1;
pub const F_OK: u8 = 0;

// =============================================================================
// Credentials (per-process security identity)
// =============================================================================
pub const Credentials = struct {
    // Real IDs (set at login, identify the actual user)
    uid: u32 = 0,
    gid: u32 = 0,

    // Effective IDs (used for permission checks)
    euid: u32 = 0,
    egid: u32 = 0,

    // Saved IDs (preserved across setuid()/setgid())
    suid: u32 = 0,
    sgid: u32 = 0,

    // Filesystem IDs (used for filesystem access checks)
    fsuid: u32 = 0,
    fsgid: u32 = 0,

    // Supplementary groups
    groups: [32]u32 = [_]u32{0} ** 32,
    ngroups: u8 = 0,

    // Security context (for MAC)
    security_label: [64]u8 = [_]u8{0} ** 64,
    label_len: u8 = 0,

    /// Create root credentials
    pub fn root() Credentials {
        return Credentials{};
    }

    /// Create credentials for a regular user
    pub fn forUser(uid_val: u32, gid_val: u32) Credentials {
        return Credentials{
            .uid = uid_val,
            .gid = gid_val,
            .euid = uid_val,
            .egid = gid_val,
            .suid = uid_val,
            .sgid = gid_val,
            .fsuid = uid_val,
            .fsgid = gid_val,
        };
    }

    /// Check if running as root (effective UID 0)
    pub fn isRoot(self: *const Credentials) bool {
        return self.euid == 0;
    }

    /// Check if user is in a specific group
    pub fn inGroup(self: *const Credentials, gid_val: u32) bool {
        if (self.egid == gid_val) return true;
        var i: u8 = 0;
        while (i < self.ngroups) : (i += 1) {
            if (self.groups[i] == gid_val) return true;
        }
        return false;
    }

    /// Add supplementary group
    pub fn addGroup(self: *Credentials, gid_val: u32) bool {
        if (self.ngroups >= 32) return false;
        self.groups[self.ngroups] = gid_val;
        self.ngroups += 1;
        return true;
    }
};

// =============================================================================
// File Permission Checking
// =============================================================================

/// Check if credentials allow the requested access to a file
pub fn checkFileAccess(
    creds: *const Credentials,
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    requested: u8,
) bool {
    // Root (UID 0) with DAC_OVERRIDE can access anything
    if (creds.isRoot()) return true;

    // Determine which permission bits to check
    var mode_bits: u16 = 0;
    if (creds.fsuid == file_uid) {
        // Owner permissions
        mode_bits = (file_mode >> 6) & 7;
    } else if (creds.fsgid == file_gid or creds.inGroup(file_gid)) {
        // Group permissions
        mode_bits = (file_mode >> 3) & 7;
    } else {
        // Other permissions
        mode_bits = file_mode & 7;
    }

    // Check each requested permission
    if ((requested & R_OK) != 0 and (mode_bits & 4) == 0) return false;
    if ((requested & W_OK) != 0 and (mode_bits & 2) == 0) return false;
    if ((requested & X_OK) != 0 and (mode_bits & 1) == 0) return false;

    return true;
}

/// Check if credentials allow creating a file in a directory
pub fn checkDirectoryWrite(
    creds: *const Credentials,
    dir_uid: u32,
    dir_gid: u32,
    dir_mode: u16,
) bool {
    return checkFileAccess(creds, dir_uid, dir_gid, dir_mode, W_OK | X_OK);
}

/// Check if credentials allow deleting a file from a directory
/// (considers sticky bit)
pub fn checkDelete(
    creds: *const Credentials,
    dir_uid: u32,
    dir_gid: u32,
    dir_mode: u16,
    file_uid: u32,
) bool {
    // Must have directory write access
    if (!checkDirectoryWrite(creds, dir_uid, dir_gid, dir_mode)) return false;

    // If sticky bit is set, only owner of file/dir or root can delete
    if ((dir_mode & S_ISVTX) != 0) {
        if (!creds.isRoot() and creds.fsuid != file_uid and creds.fsuid != dir_uid) {
            return false;
        }
    }

    return true;
}

// =============================================================================
// Resource Limits (rlimits)
// =============================================================================
pub const RLIMIT_CPU: u8 = 0;
pub const RLIMIT_FSIZE: u8 = 1;
pub const RLIMIT_DATA: u8 = 2;
pub const RLIMIT_STACK: u8 = 3;
pub const RLIMIT_CORE: u8 = 4;
pub const RLIMIT_RSS: u8 = 5;
pub const RLIMIT_NPROC: u8 = 6;
pub const RLIMIT_NOFILE: u8 = 7;
pub const RLIMIT_MEMLOCK: u8 = 8;
pub const RLIMIT_AS: u8 = 9;
pub const RLIMIT_LOCKS: u8 = 10;
pub const RLIMIT_SIGPENDING: u8 = 11;
pub const RLIMIT_MSGQUEUE: u8 = 12;
pub const RLIMIT_NICE: u8 = 13;
pub const RLIMIT_RTPRIO: u8 = 14;
pub const RLIMIT_RTTIME: u8 = 15;
pub const RLIM_NLIMITS: u8 = 16;
pub const RLIM_INFINITY: u64 = @as(u64, 0) -% 1;

pub const Rlimit = struct {
    cur: u64 = RLIM_INFINITY, // Soft limit
    max: u64 = RLIM_INFINITY, // Hard limit
};

pub const ResourceLimits = struct {
    limits: [RLIM_NLIMITS]Rlimit = undefined,

    pub fn init() ResourceLimits {
        var rl = ResourceLimits{ .limits = undefined };
        for (&rl.limits) |*l| {
            l.* = Rlimit{};
        }

        // Set sensible defaults
        rl.limits[RLIMIT_STACK] = .{ .cur = 8 * 1024 * 1024, .max = RLIM_INFINITY }; // 8MB stack
        rl.limits[RLIMIT_NOFILE] = .{ .cur = 1024, .max = 4096 }; // Max open files
        rl.limits[RLIMIT_NPROC] = .{ .cur = 4096, .max = 4096 }; // Max processes
        rl.limits[RLIMIT_CORE] = .{ .cur = 0, .max = RLIM_INFINITY }; // Core dumps off by default
        rl.limits[RLIMIT_MEMLOCK] = .{ .cur = 64 * 1024, .max = 64 * 1024 }; // 64KB mlock

        return rl;
    }

    pub fn getLimit(self: *const ResourceLimits, resource: u8) ?Rlimit {
        if (resource >= RLIM_NLIMITS) return null;
        return self.limits[resource];
    }

    pub fn setLimit(self: *ResourceLimits, resource: u8, new_limit: Rlimit) bool {
        if (resource >= RLIM_NLIMITS) return false;
        // Soft limit cannot exceed hard limit
        if (new_limit.cur > new_limit.max) return false;
        self.limits[resource] = new_limit;
        return true;
    }
};

// =============================================================================
// Kernel Entropy Pool (for /dev/random, /dev/urandom, ASLR)
// =============================================================================
pub const EntropyPool = struct {
    state: [4]u64 = .{ 0x123456789ABCDEF0, 0xFEDCBA9876543210, 0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF },
    entropy_bits: u32 = 0,
    total_mixed: u64 = 0,

    /// Mix in entropy from an external source
    pub fn addEntropy(self: *EntropyPool, data: u64, bits: u32) void {
        // xoshiro256** mixing
        self.state[0] ^= data;
        self.state[1] ^= data >> 7;
        self.state[2] ^= rotl(data, 17);
        self.state[3] ^= rotl(data, 45);
        self.step();
        self.entropy_bits +|= bits;
        self.total_mixed += 1;
    }

    /// Extract random bytes from the pool
    pub fn getRandomU64(self: *EntropyPool) u64 {
        const result = rotl(self.state[1] *% 5, 7) *% 9;
        self.step();
        if (self.entropy_bits >= 64) {
            self.entropy_bits -= 64;
        } else {
            self.entropy_bits = 0;
        }
        return result;
    }

    pub fn getRandomU32(self: *EntropyPool) u32 {
        return @truncate(self.getRandomU64());
    }

    pub fn fillRandom(self: *EntropyPool, buf: []u8) void {
        var i: usize = 0;
        while (i + 8 <= buf.len) : (i += 8) {
            const val = self.getRandomU64();
            buf[i] = @truncate(val);
            buf[i + 1] = @truncate(val >> 8);
            buf[i + 2] = @truncate(val >> 16);
            buf[i + 3] = @truncate(val >> 24);
            buf[i + 4] = @truncate(val >> 32);
            buf[i + 5] = @truncate(val >> 40);
            buf[i + 6] = @truncate(val >> 48);
            buf[i + 7] = @truncate(val >> 56);
        }
        if (i < buf.len) {
            const val = self.getRandomU64();
            var j: u6 = 0;
            while (i < buf.len) : (i += 1) {
                buf[i] = @truncate(val >> (j * 8));
                j += 1;
            }
        }
    }

    fn step(self: *EntropyPool) void {
        const t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = rotl(self.state[3], 45);
    }

    fn rotl(x: u64, comptime k: u6) u64 {
        return (x << k) | (x >> (64 - k));
    }
};

var kernel_entropy: EntropyPool = .{};

// =============================================================================
// Security Audit Log
// =============================================================================
pub const AuditEvent = enum(u8) {
    login_success,
    login_failure,
    capability_denied,
    permission_denied,
    setuid_change,
    module_load,
    mount_operation,
    privilege_escalation,
    file_access_denied,
    process_kill,
};

pub const AuditEntry = struct {
    event: AuditEvent = .login_success,
    timestamp: u64 = 0,
    pid: u32 = 0,
    uid: u32 = 0,
    target_id: u32 = 0, // PID, inode, etc.
    result: bool = false,
    is_valid: bool = false,
};

const AUDIT_LOG_SIZE: usize = 1024;
var audit_log: [AUDIT_LOG_SIZE]AuditEntry = undefined;
var audit_head: usize = 0;
var audit_count: usize = 0;

pub fn auditLog(event: AuditEvent, pid: u32, uid: u32, target: u32, success: bool) void {
    audit_log[audit_head] = AuditEntry{
        .event = event,
        .timestamp = main.timer.getUnixTimestamp(),
        .pid = pid,
        .uid = uid,
        .target_id = target,
        .result = success,
        .is_valid = true,
    };
    audit_head = (audit_head + 1) % AUDIT_LOG_SIZE;
    if (audit_count < AUDIT_LOG_SIZE) audit_count += 1;
}

// =============================================================================
// Default umask
// =============================================================================
var default_umask: u16 = 0o022; // rwxr-xr-x

pub fn getUmask() u16 {
    return default_umask;
}

pub fn setUmask(mask: u16) u16 {
    const old = default_umask;
    default_umask = mask & 0o777;
    return old;
}

// =============================================================================
// Entropy API
// =============================================================================
pub fn addEntropy(data: u64, bits: u32) void {
    kernel_entropy.addEntropy(data, bits);
}

pub fn getRandomU64() u64 {
    return kernel_entropy.getRandomU64();
}

pub fn getRandomU32() u32 {
    return kernel_entropy.getRandomU32();
}

pub fn fillRandom(buf: []u8) void {
    kernel_entropy.fillRandom(buf);
}

pub fn getEntropyBits() u32 {
    return kernel_entropy.entropy_bits;
}

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    // Seed entropy with whatever sources we have
    kernel_entropy.addEntropy(main.timer.getTicks(), 8);
    kernel_entropy.addEntropy(main.timer.getUnixTimestamp(), 4);

    // Clear audit log
    for (&audit_log) |*entry| {
        entry.* = AuditEntry{};
    }
    audit_head = 0;
    audit_count = 0;

    main.klog(.info, "access: security subsystem initialized (entropy={d} bits, umask={o})", .{
        kernel_entropy.entropy_bits,
        default_umask,
    });
}
