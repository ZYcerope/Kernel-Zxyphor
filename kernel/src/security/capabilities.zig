// =============================================================================
// Kernel Zxyphor - Capability-Based Security System
// =============================================================================
// Linux-compatible capability model (POSIX 1003.1e draft). Each process has
// three capability sets: permitted, effective, and inheritable. Capabilities
// split the traditional all-or-nothing root privilege into fine-grained
// permissions. This allows processes to hold only the specific privileges
// they need (principle of least privilege).
//
// Capabilities are represented as a 64-bit bitmask, supporting up to 64
// individual capabilities. The kernel checks capabilities instead of UID==0
// for privileged operations.
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Capability Constants (matching Linux capability numbers)
// =============================================================================
pub const CAP_CHOWN: u6 = 0;
pub const CAP_DAC_OVERRIDE: u6 = 1;
pub const CAP_DAC_READ_SEARCH: u6 = 2;
pub const CAP_FOWNER: u6 = 3;
pub const CAP_FSETID: u6 = 4;
pub const CAP_KILL: u6 = 5;
pub const CAP_SETGID: u6 = 6;
pub const CAP_SETUID: u6 = 7;
pub const CAP_SETPCAP: u6 = 8;
pub const CAP_LINUX_IMMUTABLE: u6 = 9;
pub const CAP_NET_BIND_SERVICE: u6 = 10;
pub const CAP_NET_BROADCAST: u6 = 11;
pub const CAP_NET_ADMIN: u6 = 12;
pub const CAP_NET_RAW: u6 = 13;
pub const CAP_IPC_LOCK: u6 = 14;
pub const CAP_IPC_OWNER: u6 = 15;
pub const CAP_SYS_MODULE: u6 = 16;
pub const CAP_SYS_RAWIO: u6 = 17;
pub const CAP_SYS_CHROOT: u6 = 18;
pub const CAP_SYS_PTRACE: u6 = 19;
pub const CAP_SYS_PACCT: u6 = 20;
pub const CAP_SYS_ADMIN: u6 = 21;
pub const CAP_SYS_BOOT: u6 = 22;
pub const CAP_SYS_NICE: u6 = 23;
pub const CAP_SYS_RESOURCE: u6 = 24;
pub const CAP_SYS_TIME: u6 = 25;
pub const CAP_SYS_TTY_CONFIG: u6 = 26;
pub const CAP_MKNOD: u6 = 27;
pub const CAP_LEASE: u6 = 28;
pub const CAP_AUDIT_WRITE: u6 = 29;
pub const CAP_AUDIT_CONTROL: u6 = 30;
pub const CAP_SETFCAP: u6 = 31;
pub const CAP_MAC_OVERRIDE: u6 = 32;
pub const CAP_MAC_ADMIN: u6 = 33;
pub const CAP_SYSLOG: u6 = 34;
pub const CAP_WAKE_ALARM: u6 = 35;
pub const CAP_BLOCK_SUSPEND: u6 = 36;
pub const CAP_AUDIT_READ: u6 = 37;
pub const CAP_PERFMON: u6 = 38;
pub const CAP_BPF: u6 = 39;
pub const CAP_CHECKPOINT_RESTORE: u6 = 40;
pub const CAP_LAST: u6 = 40;

// =============================================================================
// Capability Set (64-bit bitmask)
// =============================================================================
pub const CapabilitySet = struct {
    bits: u64 = 0,

    /// Create an empty capability set
    pub fn none() CapabilitySet {
        return .{ .bits = 0 };
    }

    /// Create a capability set with all capabilities enabled (root-like)
    pub fn all() CapabilitySet {
        // Set bits 0..CAP_LAST
        const mask: u64 = (@as(u64, 1) << (@as(u7, CAP_LAST) + 1)) - 1;
        return .{ .bits = mask };
    }

    /// Create a set with a single capability
    pub fn single(cap: u6) CapabilitySet {
        return .{ .bits = @as(u64, 1) << cap };
    }

    /// Check if a specific capability is set
    pub fn has(self: CapabilitySet, cap: u6) bool {
        return (self.bits & (@as(u64, 1) << cap)) != 0;
    }

    /// Set (grant) a capability
    pub fn grant(self: *CapabilitySet, cap: u6) void {
        self.bits |= (@as(u64, 1) << cap);
    }

    /// Clear (revoke) a capability
    pub fn revoke(self: *CapabilitySet, cap: u6) void {
        self.bits &= ~(@as(u64, 1) << cap);
    }

    /// Union of two sets
    pub fn combine(self: CapabilitySet, other: CapabilitySet) CapabilitySet {
        return .{ .bits = self.bits | other.bits };
    }

    /// Intersection of two sets
    pub fn intersect(self: CapabilitySet, other: CapabilitySet) CapabilitySet {
        return .{ .bits = self.bits & other.bits };
    }

    /// Complement
    pub fn invert(self: CapabilitySet) CapabilitySet {
        return .{ .bits = ~self.bits };
    }

    /// Difference (self minus other)
    pub fn subtract(self: CapabilitySet, other: CapabilitySet) CapabilitySet {
        return .{ .bits = self.bits & ~other.bits };
    }

    /// Check if empty
    pub fn isEmpty(self: CapabilitySet) bool {
        return self.bits == 0;
    }

    /// Check if this is a subset of other
    pub fn isSubsetOf(self: CapabilitySet, other: CapabilitySet) bool {
        return (self.bits & ~other.bits) == 0;
    }

    /// Count number of capabilities in set
    pub fn count(self: CapabilitySet) u32 {
        return @popCount(self.bits);
    }
};

// =============================================================================
// Process Credentials — three capability sets per Linux model
// =============================================================================
pub const ProcessCapabilities = struct {
    /// Permitted: upper bound of capabilities the process can use
    permitted: CapabilitySet = CapabilitySet.none(),

    /// Effective: capabilities currently active for permission checks
    effective: CapabilitySet = CapabilitySet.none(),

    /// Inheritable: capabilities preserved across execve()
    inheritable: CapabilitySet = CapabilitySet.none(),

    /// Bounding set: limits what can be added to permitted on execve()
    bounding: CapabilitySet = CapabilitySet.all(),

    /// Ambient: capabilities automatically added to permitted/effective on execve()
    ambient: CapabilitySet = CapabilitySet.none(),

    /// Keep capabilities across setuid()
    keep_caps: bool = false,

    /// No new privileges flag (like PR_SET_NO_NEW_PRIVS)
    no_new_privs: bool = false,

    /// Create credentials for the init process (PID 1 — all caps)
    pub fn initCredentials() ProcessCapabilities {
        return ProcessCapabilities{
            .permitted = CapabilitySet.all(),
            .effective = CapabilitySet.all(),
            .inheritable = CapabilitySet.all(),
            .bounding = CapabilitySet.all(),
        };
    }

    /// Create credentials for a regular unprivileged process
    pub fn unprivileged() ProcessCapabilities {
        return ProcessCapabilities{};
    }

    /// Check if process has a specific capability (checks effective set)
    pub fn capable(self: *const ProcessCapabilities, cap: u6) bool {
        return self.effective.has(cap);
    }

    /// Raise a capability to effective (must be in permitted)
    pub fn raise(self: *ProcessCapabilities, cap: u6) bool {
        if (!self.permitted.has(cap)) return false;
        self.effective.grant(cap);
        return true;
    }

    /// Lower a capability from effective
    pub fn lower(self: *ProcessCapabilities, cap: u6) void {
        self.effective.revoke(cap);
    }

    /// Drop a capability from all sets (irreversible)
    pub fn drop(self: *ProcessCapabilities, cap: u6) void {
        self.permitted.revoke(cap);
        self.effective.revoke(cap);
        self.inheritable.revoke(cap);
        self.ambient.revoke(cap);
    }

    /// Drop all capabilities
    pub fn dropAll(self: *ProcessCapabilities) void {
        self.permitted = CapabilitySet.none();
        self.effective = CapabilitySet.none();
        self.inheritable = CapabilitySet.none();
        self.ambient = CapabilitySet.none();
    }

    /// Compute capabilities after execve()
    /// Follows Linux capability transformation rules
    pub fn transformOnExec(self: *ProcessCapabilities, file_caps: ?*const FileCaps) void {
        if (file_caps) |fc| {
            // New permitted = (old inheritable & file inheritable) | (file permitted & old bounding) | old ambient
            self.permitted = self.inheritable.intersect(fc.inheritable)
                .combine(fc.permitted.intersect(self.bounding))
                .combine(self.ambient);

            // New effective = new permitted if file effective bit set, else empty
            if (fc.effective_bit) {
                self.effective = self.permitted;
            } else {
                self.effective = self.ambient;
            }
        } else {
            // No file capabilities — capabilities from ambient only
            self.permitted = self.inheritable.combine(self.ambient);
            self.effective = self.ambient;
        }

        // Inheritable stays the same
        // Ambient gets masked by new permitted
        self.ambient = self.ambient.intersect(self.permitted);
    }
};

// =============================================================================
// File Capabilities (stored as extended attributes)
// =============================================================================
pub const FileCaps = struct {
    permitted: CapabilitySet = CapabilitySet.none(),
    inheritable: CapabilitySet = CapabilitySet.none(),
    effective_bit: bool = false, // If true, effective = permitted after exec

    /// Create file caps for a setuid-root equivalent binary
    pub fn rootEquivalent() FileCaps {
        return FileCaps{
            .permitted = CapabilitySet.all(),
            .inheritable = CapabilitySet.all(),
            .effective_bit = true,
        };
    }
};

// =============================================================================
// Capability Name Table (for logging and /proc display)
// =============================================================================
pub fn capabilityName(cap: u6) []const u8 {
    return switch (cap) {
        CAP_CHOWN => "cap_chown",
        CAP_DAC_OVERRIDE => "cap_dac_override",
        CAP_DAC_READ_SEARCH => "cap_dac_read_search",
        CAP_FOWNER => "cap_fowner",
        CAP_FSETID => "cap_fsetid",
        CAP_KILL => "cap_kill",
        CAP_SETGID => "cap_setgid",
        CAP_SETUID => "cap_setuid",
        CAP_SETPCAP => "cap_setpcap",
        CAP_LINUX_IMMUTABLE => "cap_linux_immutable",
        CAP_NET_BIND_SERVICE => "cap_net_bind_service",
        CAP_NET_BROADCAST => "cap_net_broadcast",
        CAP_NET_ADMIN => "cap_net_admin",
        CAP_NET_RAW => "cap_net_raw",
        CAP_IPC_LOCK => "cap_ipc_lock",
        CAP_IPC_OWNER => "cap_ipc_owner",
        CAP_SYS_MODULE => "cap_sys_module",
        CAP_SYS_RAWIO => "cap_sys_rawio",
        CAP_SYS_CHROOT => "cap_sys_chroot",
        CAP_SYS_PTRACE => "cap_sys_ptrace",
        CAP_SYS_PACCT => "cap_sys_pacct",
        CAP_SYS_ADMIN => "cap_sys_admin",
        CAP_SYS_BOOT => "cap_sys_boot",
        CAP_SYS_NICE => "cap_sys_nice",
        CAP_SYS_RESOURCE => "cap_sys_resource",
        CAP_SYS_TIME => "cap_sys_time",
        CAP_SYS_TTY_CONFIG => "cap_sys_tty_config",
        CAP_MKNOD => "cap_mknod",
        CAP_LEASE => "cap_lease",
        CAP_AUDIT_WRITE => "cap_audit_write",
        CAP_AUDIT_CONTROL => "cap_audit_control",
        CAP_SETFCAP => "cap_setfcap",
        CAP_MAC_OVERRIDE => "cap_mac_override",
        CAP_MAC_ADMIN => "cap_mac_admin",
        CAP_SYSLOG => "cap_syslog",
        CAP_WAKE_ALARM => "cap_wake_alarm",
        CAP_BLOCK_SUSPEND => "cap_block_suspend",
        CAP_AUDIT_READ => "cap_audit_read",
        CAP_PERFMON => "cap_perfmon",
        CAP_BPF => "cap_bpf",
        CAP_CHECKPOINT_RESTORE => "cap_checkpoint_restore",
        else => "cap_unknown",
    };
}

// =============================================================================
// Kernel Capability Checks (used throughout the kernel)
// =============================================================================

/// Check if the current process has a capability
pub fn currentProcessCapable(cap: u6) bool {
    // Get current process
    const proc = main.process.getCurrentProcess() orelse return false;
    return proc.capabilities.capable(cap);
}

/// Check if a specific process has a capability
pub fn processCapable(pid: u32, cap: u6) bool {
    const proc = main.process.getProcess(pid) orelse return false;
    return proc.capabilities.capable(cap);
}

/// Require a capability, return error if not present
pub fn requireCapability(cap: u6) bool {
    if (!currentProcessCapable(cap)) {
        main.klog(.warn, "capability: denied {s} for pid {d}", .{
            capabilityName(cap),
            if (main.process.getCurrentProcess()) |p| p.pid else 0,
        });
        return false;
    }
    return true;
}

// =============================================================================
// Common Capability Check Helpers
// =============================================================================

/// Can the process override file ownership restrictions?
pub fn canOverrideDac() bool {
    return currentProcessCapable(CAP_DAC_OVERRIDE);
}

/// Can the process send signals to any process?
pub fn canKillAny() bool {
    return currentProcessCapable(CAP_KILL);
}

/// Can the process change UID/GID?
pub fn canSetuid() bool {
    return currentProcessCapable(CAP_SETUID);
}

/// Can the process bind to privileged ports (<1024)?
pub fn canBindPrivilegedPort() bool {
    return currentProcessCapable(CAP_NET_BIND_SERVICE);
}

/// Can the process perform network administration?
pub fn canNetAdmin() bool {
    return currentProcessCapable(CAP_NET_ADMIN);
}

/// Can the process use raw sockets?
pub fn canRawSocket() bool {
    return currentProcessCapable(CAP_NET_RAW);
}

/// Can the process perform system administration?
pub fn canSysAdmin() bool {
    return currentProcessCapable(CAP_SYS_ADMIN);
}

/// Can the process load/unload kernel modules?
pub fn canModuleOps() bool {
    return currentProcessCapable(CAP_SYS_MODULE);
}

/// Can the process reboot the system?
pub fn canReboot() bool {
    return currentProcessCapable(CAP_SYS_BOOT);
}

/// Can the process set system time?
pub fn canSetTime() bool {
    return currentProcessCapable(CAP_SYS_TIME);
}

/// Can the process change nice value / scheduling?
pub fn canNice() bool {
    return currentProcessCapable(CAP_SYS_NICE);
}

/// Can the process perform raw I/O (iopl, ioperm)?
pub fn canRawIO() bool {
    return currentProcessCapable(CAP_SYS_RAWIO);
}

/// Can the process chroot?
pub fn canChroot() bool {
    return currentProcessCapable(CAP_SYS_CHROOT);
}

/// Can the process ptrace other processes?
pub fn canPtrace() bool {
    return currentProcessCapable(CAP_SYS_PTRACE);
}

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    main.klog(.info, "capabilities: initialized ({d} capabilities defined)", .{@as(u32, CAP_LAST) + 1});
}
