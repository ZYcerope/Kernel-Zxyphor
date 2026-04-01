// SPDX-License-Identifier: MIT
// Zxyphor Kernel — UTS Namespace + Mount Namespace
//
// UTS namespace: per-namespace hostname, domainname (uname isolation).
// Mount namespace: per-namespace mount tree with propagation types (private,
// shared, slave, unbindable), pivot_root support, mount point management,
// bind mounts, recursive operations. Structural cloning on unshare/clone.

const std = @import("std");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_HOSTNAME_LEN: u32 = 64;
pub const MAX_DOMAINNAME_LEN: u32 = 64;
pub const MAX_UTS_NS: u32 = 32;
pub const MAX_MNT_NS: u32 = 32;
pub const MAX_MOUNT_POINTS: u32 = 512;
pub const MAX_PATH_LEN: u32 = 256;
pub const MAX_FSTYPE_LEN: u32 = 16;
pub const MAX_NS_MOUNTS: u32 = 128;

/// Mount flags
pub const MS_RDONLY: u32 = 1;
pub const MS_NOSUID: u32 = 2;
pub const MS_NODEV: u32 = 4;
pub const MS_NOEXEC: u32 = 8;
pub const MS_SYNCHRONOUS: u32 = 16;
pub const MS_REMOUNT: u32 = 32;
pub const MS_MANDLOCK: u32 = 64;
pub const MS_DIRSYNC: u32 = 128;
pub const MS_NOATIME: u32 = 1024;
pub const MS_NODIRATIME: u32 = 2048;
pub const MS_BIND: u32 = 4096;
pub const MS_MOVE: u32 = 8192;
pub const MS_REC: u32 = 16384;
pub const MS_SILENT: u32 = 32768;
pub const MS_PRIVATE: u32 = 1 << 18;
pub const MS_SLAVE: u32 = 1 << 19;
pub const MS_SHARED: u32 = 1 << 20;
pub const MS_UNBINDABLE: u32 = 1 << 21;
pub const MS_RELATIME: u32 = 1 << 22;
pub const MS_STRICTATIME: u32 = 1 << 24;
pub const MS_LAZYTIME: u32 = 1 << 25;

// ============================================================================
// UTS Namespace
// ============================================================================

pub const UtsName = struct {
    sysname: [MAX_HOSTNAME_LEN]u8,
    sysname_len: u8,
    nodename: [MAX_HOSTNAME_LEN]u8,
    nodename_len: u8,
    release: [MAX_HOSTNAME_LEN]u8,
    release_len: u8,
    version: [MAX_HOSTNAME_LEN]u8,
    version_len: u8,
    machine: [MAX_HOSTNAME_LEN]u8,
    machine_len: u8,
    domainname: [MAX_DOMAINNAME_LEN]u8,
    domainname_len: u8,

    pub fn init() UtsName {
        var u: UtsName = std.mem.zeroes(UtsName);
        const sys = "Zxyphor";
        const rel = "6.0.0-zxyphor";
        const ver = "#1 SMP";
        const mach = "x86_64";
        const dom = "(none)";

        @memcpy(u.sysname[0..sys.len], sys);
        u.sysname_len = sys.len;
        @memcpy(u.release[0..rel.len], rel);
        u.release_len = rel.len;
        @memcpy(u.version[0..ver.len], ver);
        u.version_len = ver.len;
        @memcpy(u.machine[0..mach.len], mach);
        u.machine_len = mach.len;
        @memcpy(u.domainname[0..dom.len], dom);
        u.domainname_len = dom.len;
        return u;
    }

    pub fn set_hostname(self: *UtsName, name: []const u8) void {
        const len = if (name.len > MAX_HOSTNAME_LEN) MAX_HOSTNAME_LEN else name.len;
        @memcpy(self.nodename[0..len], name[0..len]);
        self.nodename_len = @intCast(len);
        // Zero remainder
        if (len < MAX_HOSTNAME_LEN) {
            @memset(self.nodename[len..], 0);
        }
    }

    pub fn set_domainname(self: *UtsName, name: []const u8) void {
        const len = if (name.len > MAX_DOMAINNAME_LEN) MAX_DOMAINNAME_LEN else name.len;
        @memcpy(self.domainname[0..len], name[0..len]);
        self.domainname_len = @intCast(len);
        if (len < MAX_DOMAINNAME_LEN) {
            @memset(self.domainname[len..], 0);
        }
    }

    pub fn get_hostname(self: *const UtsName) []const u8 {
        return self.nodename[0..self.nodename_len];
    }

    pub fn get_domainname(self: *const UtsName) []const u8 {
        return self.domainname[0..self.domainname_len];
    }
};

pub const UtsNamespace = struct {
    id: u32,
    parent_idx: u16,
    ref_count: u32,
    owner_uid: u32,
    uname: UtsName,
    active: bool,

    pub fn init() UtsNamespace {
        return UtsNamespace{
            .id = 0,
            .parent_idx = 0xFFFF,
            .ref_count = 0,
            .owner_uid = 0,
            .uname = UtsName.init(),
            .active = false,
        };
    }
};

// ============================================================================
// Mount Propagation Type
// ============================================================================

pub const PropagationType = enum(u8) {
    private = 0,
    shared = 1,
    slave = 2,
    unbindable = 3,
};

// ============================================================================
// Mount Point
// ============================================================================

pub const MountPoint = struct {
    /// Mount ID (unique across the system)
    id: u32,
    /// Parent mount ID (0 for root mount)
    parent_id: u32,
    /// Device ID (major:minor encoded)
    dev_id: u64,
    /// Mount path
    mount_path: [MAX_PATH_LEN]u8,
    mount_path_len: u16,
    /// Root dentry path within the filesystem
    root_path: [MAX_PATH_LEN]u8,
    root_path_len: u16,
    /// Filesystem type
    fstype: [MAX_FSTYPE_LEN]u8,
    fstype_len: u8,
    /// Mount flags
    flags: u32,
    /// Propagation type
    propagation: PropagationType,
    /// Shared subtree peer group ID (for shared mounts)
    peer_group: u32,
    /// Master mount ID (for slave mounts)
    master_id: u32,
    /// Namespace index that owns this mount
    ns_idx: u16,
    /// Reference count
    ref_count: u32,
    /// Whether this is a bind mount
    is_bind: bool,
    /// Whether this mount is active
    active: bool,
    /// Children count
    child_count: u16,
    /// Superblock pointer (opaque)
    sb_data: u64,
    /// Mount time (jiffies)
    mount_time: u64,
    /// Inode of mount point directory
    mnt_ino: u64,

    pub fn init() MountPoint {
        return MountPoint{
            .id = 0,
            .parent_id = 0,
            .dev_id = 0,
            .mount_path = [_]u8{0} ** MAX_PATH_LEN,
            .mount_path_len = 0,
            .root_path = [_]u8{0} ** MAX_PATH_LEN,
            .root_path_len = 0,
            .fstype = [_]u8{0} ** MAX_FSTYPE_LEN,
            .fstype_len = 0,
            .flags = 0,
            .propagation = .private,
            .peer_group = 0,
            .master_id = 0,
            .ns_idx = 0xFFFF,
            .ref_count = 0,
            .is_bind = false,
            .active = false,
            .child_count = 0,
            .sb_data = 0,
            .mount_time = 0,
            .mnt_ino = 0,
        };
    }

    pub fn set_path(self: *MountPoint, path: []const u8) void {
        const len = if (path.len > MAX_PATH_LEN) MAX_PATH_LEN else path.len;
        @memcpy(self.mount_path[0..len], path[0..len]);
        self.mount_path_len = @intCast(len);
    }

    pub fn set_root(self: *MountPoint, path: []const u8) void {
        const len = if (path.len > MAX_PATH_LEN) MAX_PATH_LEN else path.len;
        @memcpy(self.root_path[0..len], path[0..len]);
        self.root_path_len = @intCast(len);
    }

    pub fn set_fstype(self: *MountPoint, fs: []const u8) void {
        const len = if (fs.len > MAX_FSTYPE_LEN) MAX_FSTYPE_LEN else fs.len;
        @memcpy(self.fstype[0..len], fs[0..len]);
        self.fstype_len = @intCast(len);
    }

    pub fn get_path(self: *const MountPoint) []const u8 {
        return self.mount_path[0..self.mount_path_len];
    }

    pub fn is_readonly(self: *const MountPoint) bool {
        return (self.flags & MS_RDONLY) != 0;
    }

    pub fn path_matches(self: *const MountPoint, target: []const u8) bool {
        if (self.mount_path_len != target.len) return false;
        return std.mem.eql(u8, self.mount_path[0..self.mount_path_len], target);
    }
};

// ============================================================================
// Mount Namespace
// ============================================================================

pub const MountNamespace = struct {
    id: u32,
    parent_idx: u16,
    ref_count: u32,
    owner_uid: u32,
    active: bool,

    /// Mount indices within this namespace (indexes into global mount table)
    mount_indices: [MAX_NS_MOUNTS]u16,
    mount_count: u16,

    /// Root mount index (the "/" mount)
    root_mount: u16,

    /// Current working directory mount
    cwd_mount: u16,

    /// Sequence number for mount events
    seq: u64,

    pub fn init() MountNamespace {
        return MountNamespace{
            .id = 0,
            .parent_idx = 0xFFFF,
            .ref_count = 0,
            .owner_uid = 0,
            .active = false,
            .mount_indices = [_]u16{0xFFFF} ** MAX_NS_MOUNTS,
            .mount_count = 0,
            .root_mount = 0xFFFF,
            .cwd_mount = 0xFFFF,
            .seq = 0,
        };
    }

    pub fn add_mount(self: *MountNamespace, mount_idx: u16) bool {
        if (self.mount_count >= MAX_NS_MOUNTS) return false;
        self.mount_indices[self.mount_count] = mount_idx;
        self.mount_count += 1;
        self.seq += 1;
        return true;
    }

    pub fn remove_mount(self: *MountNamespace, mount_idx: u16) bool {
        var i: u16 = 0;
        while (i < self.mount_count) : (i += 1) {
            if (self.mount_indices[i] == mount_idx) {
                // Shift down
                var j = i;
                while (j + 1 < self.mount_count) : (j += 1) {
                    self.mount_indices[j] = self.mount_indices[j + 1];
                }
                self.mount_count -= 1;
                self.mount_indices[self.mount_count] = 0xFFFF;
                self.seq += 1;
                return true;
            }
        }
        return false;
    }

    pub fn has_mount(self: *const MountNamespace, mount_idx: u16) bool {
        var i: u16 = 0;
        while (i < self.mount_count) : (i += 1) {
            if (self.mount_indices[i] == mount_idx) return true;
        }
        return false;
    }
};

// ============================================================================
// Namespace Manager
// ============================================================================

var next_uts_id: u32 = 1;
var next_mnt_id: u32 = 1;
var next_mount_id: u32 = 1;
var next_peer_group: u32 = 1;

pub const NsManager = struct {
    uts_namespaces: [MAX_UTS_NS]UtsNamespace,
    uts_count: u32,

    mnt_namespaces: [MAX_MNT_NS]MountNamespace,
    mnt_count: u32,

    mounts: [MAX_MOUNT_POINTS]MountPoint,
    mount_count: u32,

    /// Stats
    total_uts_created: u64,
    total_mnt_created: u64,
    total_mounts: u64,
    total_umounts: u64,
    total_binds: u64,
    total_pivots: u64,
    total_propagations: u64,

    pub fn init() NsManager {
        var mgr = NsManager{
            .uts_namespaces = undefined,
            .uts_count = 0,
            .mnt_namespaces = undefined,
            .mnt_count = 0,
            .mounts = undefined,
            .mount_count = 0,
            .total_uts_created = 0,
            .total_mnt_created = 0,
            .total_mounts = 0,
            .total_umounts = 0,
            .total_binds = 0,
            .total_pivots = 0,
            .total_propagations = 0,
        };

        for (&mgr.uts_namespaces) |*ns| ns.* = UtsNamespace.init();
        for (&mgr.mnt_namespaces) |*ns| ns.* = MountNamespace.init();
        for (&mgr.mounts) |*m| m.* = MountPoint.init();

        return mgr;
    }

    // ---- UTS Namespace ----

    pub fn create_uts_ns(self: *NsManager, parent_idx: u16, uid: u32) ?u16 {
        if (self.uts_count >= MAX_UTS_NS) return null;
        const idx: u16 = @intCast(self.uts_count);

        self.uts_namespaces[idx].id = next_uts_id;
        next_uts_id += 1;
        self.uts_namespaces[idx].parent_idx = parent_idx;
        self.uts_namespaces[idx].owner_uid = uid;
        self.uts_namespaces[idx].ref_count = 1;
        self.uts_namespaces[idx].active = true;

        // Copy uname from parent or use defaults
        if (parent_idx != 0xFFFF and parent_idx < self.uts_count) {
            self.uts_namespaces[idx].uname = self.uts_namespaces[parent_idx].uname;
        } else {
            self.uts_namespaces[idx].uname = UtsName.init();
        }

        self.uts_count += 1;
        self.total_uts_created += 1;
        return idx;
    }

    pub fn destroy_uts_ns(self: *NsManager, idx: u16) bool {
        if (idx >= self.uts_count) return false;
        if (!self.uts_namespaces[idx].active) return false;
        if (self.uts_namespaces[idx].ref_count > 1) return false;

        self.uts_namespaces[idx].active = false;
        self.uts_namespaces[idx].ref_count = 0;
        return true;
    }

    pub fn uts_set_hostname(self: *NsManager, ns_idx: u16, name: []const u8) bool {
        if (ns_idx >= self.uts_count) return false;
        if (!self.uts_namespaces[ns_idx].active) return false;
        self.uts_namespaces[ns_idx].uname.set_hostname(name);
        return true;
    }

    pub fn uts_set_domainname(self: *NsManager, ns_idx: u16, name: []const u8) bool {
        if (ns_idx >= self.uts_count) return false;
        if (!self.uts_namespaces[ns_idx].active) return false;
        self.uts_namespaces[ns_idx].uname.set_domainname(name);
        return true;
    }

    pub fn uts_get_hostname(self: *const NsManager, ns_idx: u16) ?[]const u8 {
        if (ns_idx >= self.uts_count) return null;
        if (!self.uts_namespaces[ns_idx].active) return null;
        return self.uts_namespaces[ns_idx].uname.get_hostname();
    }

    pub fn uts_ref(self: *NsManager, idx: u16) void {
        if (idx < self.uts_count and self.uts_namespaces[idx].active) {
            self.uts_namespaces[idx].ref_count += 1;
        }
    }

    pub fn uts_unref(self: *NsManager, idx: u16) void {
        if (idx < self.uts_count and self.uts_namespaces[idx].active) {
            if (self.uts_namespaces[idx].ref_count > 0) {
                self.uts_namespaces[idx].ref_count -= 1;
            }
        }
    }

    // ---- Mount Namespace ----

    pub fn create_mnt_ns(self: *NsManager, parent_idx: u16, uid: u32) ?u16 {
        if (self.mnt_count >= MAX_MNT_NS) return null;
        const idx: u16 = @intCast(self.mnt_count);

        self.mnt_namespaces[idx].id = next_mnt_id;
        next_mnt_id += 1;
        self.mnt_namespaces[idx].parent_idx = parent_idx;
        self.mnt_namespaces[idx].owner_uid = uid;
        self.mnt_namespaces[idx].ref_count = 1;
        self.mnt_namespaces[idx].active = true;

        // Clone mount tree from parent
        if (parent_idx != 0xFFFF and parent_idx < self.mnt_count) {
            const parent = &self.mnt_namespaces[parent_idx];
            var i: u16 = 0;
            while (i < parent.mount_count) : (i += 1) {
                const src_mnt_idx = parent.mount_indices[i];
                if (src_mnt_idx != 0xFFFF and src_mnt_idx < self.mount_count) {
                    const src = &self.mounts[src_mnt_idx];
                    if (!src.active) continue;
                    if (src.propagation == .unbindable) continue;

                    // Clone the mount point
                    const new_mnt = self.alloc_mount() orelse break;
                    self.mounts[new_mnt] = self.mounts[src_mnt_idx];
                    self.mounts[new_mnt].id = next_mount_id;
                    next_mount_id += 1;
                    self.mounts[new_mnt].ns_idx = idx;
                    self.mounts[new_mnt].ref_count = 1;
                    self.mounts[new_mnt].propagation = .private; // copied mounts start private

                    _ = self.mnt_namespaces[idx].add_mount(new_mnt);

                    // Set root mount
                    if (parent.root_mount == src_mnt_idx) {
                        self.mnt_namespaces[idx].root_mount = new_mnt;
                        self.mnt_namespaces[idx].cwd_mount = new_mnt;
                    }
                }
            }
        }

        self.mnt_count += 1;
        self.total_mnt_created += 1;
        return idx;
    }

    pub fn destroy_mnt_ns(self: *NsManager, idx: u16) bool {
        if (idx >= self.mnt_count) return false;
        if (!self.mnt_namespaces[idx].active) return false;
        if (self.mnt_namespaces[idx].ref_count > 1) return false;

        // Unmount all mounts in this namespace
        var ns = &self.mnt_namespaces[idx];
        var i: u16 = 0;
        while (i < ns.mount_count) : (i += 1) {
            const mnt_idx = ns.mount_indices[i];
            if (mnt_idx != 0xFFFF and mnt_idx < self.mount_count) {
                self.mounts[mnt_idx].active = false;
                self.mounts[mnt_idx].ref_count = 0;
            }
        }

        ns.active = false;
        ns.ref_count = 0;
        ns.mount_count = 0;
        return true;
    }

    pub fn mnt_ref(self: *NsManager, idx: u16) void {
        if (idx < self.mnt_count and self.mnt_namespaces[idx].active) {
            self.mnt_namespaces[idx].ref_count += 1;
        }
    }

    pub fn mnt_unref(self: *NsManager, idx: u16) void {
        if (idx < self.mnt_count and self.mnt_namespaces[idx].active) {
            if (self.mnt_namespaces[idx].ref_count > 0) {
                self.mnt_namespaces[idx].ref_count -= 1;
            }
        }
    }

    // ---- Mount operations ----

    fn alloc_mount(self: *NsManager) ?u16 {
        if (self.mount_count >= MAX_MOUNT_POINTS) {
            // Try to reclaim inactive mounts
            var i: u32 = 0;
            while (i < self.mount_count) : (i += 1) {
                if (!self.mounts[i].active and self.mounts[i].ref_count == 0) {
                    self.mounts[i] = MountPoint.init();
                    return @intCast(i);
                }
            }
            return null;
        }
        const idx: u16 = @intCast(self.mount_count);
        self.mount_count += 1;
        return idx;
    }

    /// Mount a filesystem
    pub fn do_mount(
        self: *NsManager,
        ns_idx: u16,
        source_dev: u64,
        target: []const u8,
        fstype: []const u8,
        flags: u32,
    ) ?u16 {
        if (ns_idx >= self.mnt_count or !self.mnt_namespaces[ns_idx].active) return null;

        // Check for remount
        if ((flags & MS_REMOUNT) != 0) {
            return self.do_remount(ns_idx, target, flags);
        }

        const mnt_idx = self.alloc_mount() orelse return null;
        var mnt = &self.mounts[mnt_idx];
        mnt.* = MountPoint.init();
        mnt.id = next_mount_id;
        next_mount_id += 1;
        mnt.dev_id = source_dev;
        mnt.set_path(target);
        mnt.set_root("/");
        mnt.set_fstype(fstype);
        mnt.flags = flags & ~(MS_REMOUNT | MS_BIND | MS_MOVE | MS_REC |
            MS_PRIVATE | MS_SHARED | MS_SLAVE | MS_UNBINDABLE);
        mnt.ns_idx = ns_idx;
        mnt.ref_count = 1;
        mnt.active = true;
        mnt.propagation = .private;

        // Set propagation from flags
        if ((flags & MS_SHARED) != 0) {
            mnt.propagation = .shared;
            mnt.peer_group = next_peer_group;
            next_peer_group += 1;
        } else if ((flags & MS_SLAVE) != 0) {
            mnt.propagation = .slave;
        } else if ((flags & MS_UNBINDABLE) != 0) {
            mnt.propagation = .unbindable;
        }

        // Find parent mount (longest prefix match)
        mnt.parent_id = self.find_parent_mount(ns_idx, target);

        // Update parent child count
        if (mnt.parent_id != 0) {
            var i: u32 = 0;
            while (i < self.mount_count) : (i += 1) {
                if (self.mounts[i].active and self.mounts[i].id == mnt.parent_id) {
                    self.mounts[i].child_count += 1;
                    break;
                }
            }
        }

        // Add to namespace
        if (!self.mnt_namespaces[ns_idx].add_mount(mnt_idx)) {
            mnt.active = false;
            return null;
        }

        // Propagate to peer/slave namespaces
        self.propagate_mount(ns_idx, mnt_idx);

        self.total_mounts += 1;
        return mnt_idx;
    }

    /// Bind mount
    pub fn do_bind(
        self: *NsManager,
        ns_idx: u16,
        source: []const u8,
        target: []const u8,
        recursive: bool,
    ) ?u16 {
        if (ns_idx >= self.mnt_count or !self.mnt_namespaces[ns_idx].active) return null;

        // Find source mount
        const src_mnt = self.lookup_mount(ns_idx, source) orelse return null;
        if (self.mounts[src_mnt].propagation == .unbindable and !recursive) return null;

        const mnt_idx = self.alloc_mount() orelse return null;
        var mnt = &self.mounts[mnt_idx];
        mnt.* = self.mounts[src_mnt];
        mnt.id = next_mount_id;
        next_mount_id += 1;
        mnt.set_path(target);
        mnt.ns_idx = ns_idx;
        mnt.ref_count = 1;
        mnt.is_bind = true;
        mnt.active = true;
        mnt.propagation = .private;
        mnt.child_count = 0;

        mnt.parent_id = self.find_parent_mount(ns_idx, target);

        if (!self.mnt_namespaces[ns_idx].add_mount(mnt_idx)) {
            mnt.active = false;
            return null;
        }

        // If recursive, clone children too
        if (recursive) {
            self.clone_children(ns_idx, src_mnt, mnt_idx);
        }

        self.total_binds += 1;
        self.total_mounts += 1;
        return mnt_idx;
    }

    /// Unmount
    pub fn do_umount(self: *NsManager, ns_idx: u16, target: []const u8, force: bool) bool {
        if (ns_idx >= self.mnt_count or !self.mnt_namespaces[ns_idx].active) return false;

        const mnt_idx = self.lookup_mount(ns_idx, target) orelse return false;
        var mnt = &self.mounts[mnt_idx];

        // Check if busy (has children)
        if (mnt.child_count > 0 and !force) return false;

        // Check if this is root mount
        if (self.mnt_namespaces[ns_idx].root_mount == mnt_idx and !force) return false;

        // Decrement parent child count
        if (mnt.parent_id != 0) {
            var i: u32 = 0;
            while (i < self.mount_count) : (i += 1) {
                if (self.mounts[i].active and self.mounts[i].id == mnt.parent_id) {
                    if (self.mounts[i].child_count > 0) {
                        self.mounts[i].child_count -= 1;
                    }
                    break;
                }
            }
        }

        // Remove from namespace
        _ = self.mnt_namespaces[ns_idx].remove_mount(mnt_idx);
        mnt.active = false;
        mnt.ref_count = 0;

        // If force, recursively unmount children
        if (force and mnt.child_count > 0) {
            self.umount_children(ns_idx, mnt.id);
        }

        self.total_umounts += 1;
        return true;
    }

    /// Pivot root: swap old root and new root
    pub fn do_pivot_root(self: *NsManager, ns_idx: u16, new_root: []const u8, put_old: []const u8) bool {
        if (ns_idx >= self.mnt_count or !self.mnt_namespaces[ns_idx].active) return false;

        const new_mnt = self.lookup_mount(ns_idx, new_root) orelse return false;
        const ns = &self.mnt_namespaces[ns_idx];

        // New root must be a mount point
        if (!self.mounts[new_mnt].active) return false;

        // Get current root
        const old_root_idx = ns.root_mount;
        if (old_root_idx == 0xFFFF) return false;

        // Move old root to put_old path
        self.mounts[old_root_idx].set_path(put_old);

        // Set new root
        self.mnt_namespaces[ns_idx].root_mount = new_mnt;
        self.mnt_namespaces[ns_idx].cwd_mount = new_mnt;

        self.total_pivots += 1;
        return true;
    }

    // Remount with new flags
    fn do_remount(self: *NsManager, ns_idx: u16, target: []const u8, flags: u32) ?u16 {
        const mnt_idx = self.lookup_mount(ns_idx, target) orelse return null;
        // Update flags (keep fs-specific flags, update mount flags)
        self.mounts[mnt_idx].flags = flags & ~(MS_REMOUNT | MS_BIND | MS_MOVE | MS_REC |
            MS_PRIVATE | MS_SHARED | MS_SLAVE | MS_UNBINDABLE);

        // Update propagation if requested
        if ((flags & MS_SHARED) != 0) {
            self.mounts[mnt_idx].propagation = .shared;
            if (self.mounts[mnt_idx].peer_group == 0) {
                self.mounts[mnt_idx].peer_group = next_peer_group;
                next_peer_group += 1;
            }
        } else if ((flags & MS_PRIVATE) != 0) {
            self.mounts[mnt_idx].propagation = .private;
        } else if ((flags & MS_SLAVE) != 0) {
            self.mounts[mnt_idx].propagation = .slave;
        } else if ((flags & MS_UNBINDABLE) != 0) {
            self.mounts[mnt_idx].propagation = .unbindable;
        }

        return mnt_idx;
    }

    /// Set mount propagation type
    pub fn set_propagation(self: *NsManager, ns_idx: u16, target: []const u8, prop: PropagationType) bool {
        if (ns_idx >= self.mnt_count or !self.mnt_namespaces[ns_idx].active) return false;
        const mnt_idx = self.lookup_mount(ns_idx, target) orelse return false;
        self.mounts[mnt_idx].propagation = prop;
        if (prop == .shared and self.mounts[mnt_idx].peer_group == 0) {
            self.mounts[mnt_idx].peer_group = next_peer_group;
            next_peer_group += 1;
        }
        return true;
    }

    // ---- Internal helpers ----

    fn lookup_mount(self: *const NsManager, ns_idx: u16, path: []const u8) ?u16 {
        if (ns_idx >= self.mnt_count) return null;
        const ns = &self.mnt_namespaces[ns_idx];

        // Find mount with exact path match
        var i: u16 = 0;
        while (i < ns.mount_count) : (i += 1) {
            const mnt_idx = ns.mount_indices[i];
            if (mnt_idx != 0xFFFF and mnt_idx < self.mount_count) {
                if (self.mounts[mnt_idx].active and self.mounts[mnt_idx].path_matches(path)) {
                    return mnt_idx;
                }
            }
        }
        return null;
    }

    fn find_parent_mount(self: *const NsManager, ns_idx: u16, path: []const u8) u32 {
        if (ns_idx >= self.mnt_count) return 0;
        const ns = &self.mnt_namespaces[ns_idx];

        var best_match: u32 = 0;
        var best_len: u16 = 0;

        var i: u16 = 0;
        while (i < ns.mount_count) : (i += 1) {
            const mnt_idx = ns.mount_indices[i];
            if (mnt_idx != 0xFFFF and mnt_idx < self.mount_count) {
                const mnt = &self.mounts[mnt_idx];
                if (!mnt.active) continue;

                // Check if mount path is a prefix of target
                const mnt_path = mnt.mount_path[0..mnt.mount_path_len];
                if (mnt.mount_path_len <= path.len and mnt.mount_path_len > best_len) {
                    if (std.mem.startsWith(u8, path, mnt_path)) {
                        best_match = mnt.id;
                        best_len = mnt.mount_path_len;
                    }
                }
            }
        }
        return best_match;
    }

    fn propagate_mount(self: *NsManager, src_ns: u16, mnt_idx: u16) void {
        const mnt = &self.mounts[mnt_idx];
        if (mnt.propagation != .shared) return;

        // Find all shared mounts in other namespaces with same peer group
        const peer_group = mnt.peer_group;
        var i: u32 = 0;
        while (i < self.mnt_count) : (i += 1) {
            if (i == src_ns or !self.mnt_namespaces[i].active) continue;

            const ns = &self.mnt_namespaces[i];
            var j: u16 = 0;
            while (j < ns.mount_count) : (j += 1) {
                const other_idx = ns.mount_indices[j];
                if (other_idx == 0xFFFF or other_idx >= self.mount_count) continue;
                const other = &self.mounts[other_idx];
                if (!other.active) continue;

                if (other.propagation == .shared and other.peer_group == peer_group) {
                    // Propagate: create a copy of the mount in this namespace
                    const new_mnt = self.alloc_mount() orelse return;
                    self.mounts[new_mnt] = self.mounts[mnt_idx];
                    self.mounts[new_mnt].id = next_mount_id;
                    next_mount_id += 1;
                    self.mounts[new_mnt].ns_idx = @intCast(i);
                    self.mounts[new_mnt].ref_count = 1;

                    _ = self.mnt_namespaces[i].add_mount(new_mnt);
                    self.total_propagations += 1;
                }
            }
        }
    }

    fn clone_children(self: *NsManager, ns_idx: u16, src_parent: u16, dst_parent: u16) void {
        const src_id = self.mounts[src_parent].id;
        const ns = &self.mnt_namespaces[ns_idx];

        var i: u16 = 0;
        while (i < ns.mount_count) : (i += 1) {
            const mnt_idx = ns.mount_indices[i];
            if (mnt_idx == 0xFFFF or mnt_idx >= self.mount_count) continue;
            if (!self.mounts[mnt_idx].active) continue;
            if (self.mounts[mnt_idx].parent_id != src_id) continue;

            const new_child = self.alloc_mount() orelse return;
            self.mounts[new_child] = self.mounts[mnt_idx];
            self.mounts[new_child].id = next_mount_id;
            next_mount_id += 1;
            self.mounts[new_child].parent_id = self.mounts[dst_parent].id;
            self.mounts[new_child].ns_idx = ns_idx;
            self.mounts[new_child].ref_count = 1;

            _ = self.mnt_namespaces[ns_idx].add_mount(new_child);
            self.mounts[dst_parent].child_count += 1;
            self.total_mounts += 1;
        }
    }

    fn umount_children(self: *NsManager, ns_idx: u16, parent_id: u32) void {
        var ns = &self.mnt_namespaces[ns_idx];
        var i: u16 = 0;
        while (i < ns.mount_count) {
            const mnt_idx = ns.mount_indices[i];
            if (mnt_idx != 0xFFFF and mnt_idx < self.mount_count) {
                if (self.mounts[mnt_idx].active and self.mounts[mnt_idx].parent_id == parent_id) {
                    // Recursively unmount children first
                    self.umount_children(ns_idx, self.mounts[mnt_idx].id);
                    self.mounts[mnt_idx].active = false;
                    self.mounts[mnt_idx].ref_count = 0;
                    _ = ns.remove_mount(mnt_idx);
                    self.total_umounts += 1;
                    continue; // Don't increment i, list shifted
                }
            }
            i += 1;
        }
    }

    /// List mounts for /proc/mounts output
    pub fn list_mounts(self: *const NsManager, ns_idx: u16, buf: []u8) u32 {
        if (ns_idx >= self.mnt_count or !self.mnt_namespaces[ns_idx].active) return 0;
        const ns = &self.mnt_namespaces[ns_idx];

        var offset: u32 = 0;
        var i: u16 = 0;
        while (i < ns.mount_count) : (i += 1) {
            const mnt_idx = ns.mount_indices[i];
            if (mnt_idx == 0xFFFF or mnt_idx >= self.mount_count) continue;
            const mnt = &self.mounts[mnt_idx];
            if (!mnt.active) continue;

            // Format: "device mount_path fstype flags 0 0\n"
            const path = mnt.mount_path[0..mnt.mount_path_len];
            const fs = mnt.fstype[0..mnt.fstype_len];

            // Write mount path
            if (offset + path.len + fs.len + 10 > buf.len) break;
            @memcpy(buf[offset..offset + path.len], path);
            offset += @intCast(path.len);
            buf[offset] = ' ';
            offset += 1;
            @memcpy(buf[offset..offset + fs.len], fs);
            offset += @intCast(fs.len);
            buf[offset] = '\n';
            offset += 1;
        }
        return offset;
    }
};

// ============================================================================
// Global instance
// ============================================================================

var global_mgr: NsManager = NsManager.init();

// ============================================================================
// FFI Exports
// ============================================================================

export fn zxy_ns_init() void {
    global_mgr = NsManager.init();
    // Create initial UTS and mount namespace
    _ = global_mgr.create_uts_ns(0xFFFF, 0);
    const mnt_idx = global_mgr.create_mnt_ns(0xFFFF, 0);
    if (mnt_idx) |idx| {
        // Mount root filesystem
        _ = global_mgr.do_mount(idx, 0, "/", "zxyfs", 0);
    }
}

export fn zxy_uts_create(parent: u16, uid: u32) i32 {
    const idx = global_mgr.create_uts_ns(parent, uid) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_uts_destroy(idx: u16) u8 {
    return if (global_mgr.destroy_uts_ns(idx)) 1 else 0;
}

export fn zxy_uts_set_hostname(idx: u16, name: [*]const u8, len: u32) u8 {
    if (len > MAX_HOSTNAME_LEN) return 0;
    const slice = name[0..len];
    return if (global_mgr.uts_set_hostname(idx, slice)) 1 else 0;
}

export fn zxy_uts_set_domainname(idx: u16, name: [*]const u8, len: u32) u8 {
    if (len > MAX_DOMAINNAME_LEN) return 0;
    const slice = name[0..len];
    return if (global_mgr.uts_set_domainname(idx, slice)) 1 else 0;
}

export fn zxy_mnt_create(parent: u16, uid: u32) i32 {
    const idx = global_mgr.create_mnt_ns(parent, uid) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_mnt_destroy(idx: u16) u8 {
    return if (global_mgr.destroy_mnt_ns(idx)) 1 else 0;
}

export fn zxy_mount(ns_idx: u16, dev: u64, target: [*]const u8, target_len: u32, fstype: [*]const u8, fstype_len: u32, flags: u32) i32 {
    if (target_len > MAX_PATH_LEN or fstype_len > MAX_FSTYPE_LEN) return -1;
    const t = target[0..target_len];
    const f = fstype[0..fstype_len];
    const idx = global_mgr.do_mount(ns_idx, dev, t, f, flags) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_umount(ns_idx: u16, target: [*]const u8, target_len: u32, force: u8) u8 {
    if (target_len > MAX_PATH_LEN) return 0;
    const t = target[0..target_len];
    return if (global_mgr.do_umount(ns_idx, t, force != 0)) 1 else 0;
}

export fn zxy_bind_mount(ns_idx: u16, src: [*]const u8, src_len: u32, dst: [*]const u8, dst_len: u32, recursive: u8) i32 {
    if (src_len > MAX_PATH_LEN or dst_len > MAX_PATH_LEN) return -1;
    const s = src[0..src_len];
    const d = dst[0..dst_len];
    const idx = global_mgr.do_bind(ns_idx, s, d, recursive != 0) orelse return -1;
    return @as(i32, idx);
}

export fn zxy_pivot_root(ns_idx: u16, new_root: [*]const u8, nr_len: u32, put_old: [*]const u8, po_len: u32) u8 {
    if (nr_len > MAX_PATH_LEN or po_len > MAX_PATH_LEN) return 0;
    const nr = new_root[0..nr_len];
    const po = put_old[0..po_len];
    return if (global_mgr.do_pivot_root(ns_idx, nr, po)) 1 else 0;
}

export fn zxy_ns_uts_count() u32 {
    return global_mgr.uts_count;
}

export fn zxy_ns_mnt_count() u32 {
    return global_mgr.mnt_count;
}

export fn zxy_ns_mount_count() u32 {
    return global_mgr.mount_count;
}

export fn zxy_ns_total_mounts() u64 {
    return global_mgr.total_mounts;
}

export fn zxy_ns_total_umounts() u64 {
    return global_mgr.total_umounts;
}

export fn zxy_ns_total_binds() u64 {
    return global_mgr.total_binds;
}

export fn zxy_ns_total_pivots() u64 {
    return global_mgr.total_pivots;
}

export fn zxy_ns_total_propagations() u64 {
    return global_mgr.total_propagations;
}
