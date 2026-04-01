// =============================================================================
// Kernel Zxyphor — tmpfs (Temporary Filesystem)
// =============================================================================
// In-memory filesystem for /tmp, /run, /dev/shm:
//   - Directory hierarchy management
//   - File create/read/write/delete
//   - Per-inode data storage (inline + page-backed)
//   - Hard links and symbolic links
//   - File permissions and ownership
//   - Size tracking and limits
//   - Timestamp management
//   - VFS integration hooks
// =============================================================================

// ============================================================================
// Constants
// ============================================================================

pub const MAX_TMPFS_INODES: usize = 1024;
pub const MAX_TMPFS_NAME: usize = 64;
pub const MAX_DIR_ENTRIES: usize = 64;
pub const MAX_FILE_PAGES: usize = 256;
pub const TMPFS_PAGE_SIZE: usize = 4096;
pub const MAX_SYMLINK_LEN: usize = 256;
pub const MAX_INLINE_SIZE: usize = 128;
pub const MAX_MOUNTS: usize = 8;

pub const INODE_TYPE_FILE: u8 = 1;
pub const INODE_TYPE_DIR: u8 = 2;
pub const INODE_TYPE_SYMLINK: u8 = 3;
pub const INODE_TYPE_PIPE: u8 = 4;
pub const INODE_TYPE_SOCKET: u8 = 5;

// ============================================================================
// Permissions
// ============================================================================

pub const PERM_READ: u16 = 0o444;
pub const PERM_WRITE: u16 = 0o222;
pub const PERM_EXEC: u16 = 0o111;
pub const PERM_DEFAULT_FILE: u16 = 0o644;
pub const PERM_DEFAULT_DIR: u16 = 0o755;
pub const PERM_SUID: u16 = 0o4000;
pub const PERM_SGID: u16 = 0o2000;
pub const PERM_STICKY: u16 = 0o1000;

// ============================================================================
// Timestamps
// ============================================================================

pub const TmpfsTime = struct {
    seconds: u64,
    nanoseconds: u32,

    pub fn zero() TmpfsTime {
        return .{ .seconds = 0, .nanoseconds = 0 };
    }
};

// ============================================================================
// Directory entry
// ============================================================================

pub const DirEntry = struct {
    name: [MAX_TMPFS_NAME]u8,
    name_len: u8,
    inode_id: u32,
    entry_type: u8,
    active: bool,

    pub fn init() DirEntry {
        var de: DirEntry = undefined;
        for (0..MAX_TMPFS_NAME) |i| de.name[i] = 0;
        de.name_len = 0;
        de.inode_id = 0;
        de.entry_type = 0;
        de.active = false;
        return de;
    }

    pub fn setName(self: *DirEntry, name: []const u8) void {
        const len = @min(name.len, MAX_TMPFS_NAME - 1);
        for (0..len) |i| {
            self.name[i] = name[i];
        }
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }

    pub fn nameEquals(self: *const DirEntry, name: []const u8) bool {
        if (self.name_len != name.len) return false;
        for (0..self.name_len) |i| {
            if (self.name[i] != name[i]) return false;
        }
        return true;
    }
};

// ============================================================================
// Inode
// ============================================================================

pub const TmpfsInode = struct {
    id: u32,
    inode_type: u8,
    active: bool,
    mode: u16,         // Permissions
    uid: u32,
    gid: u32,
    nlink: u32,        // Hard link count
    size: u64,

    // Timestamps
    atime: TmpfsTime,  // Access time
    mtime: TmpfsTime,  // Modification time
    ctime: TmpfsTime,  // Status change time

    // Data storage
    // For files: page_data holds physical page addresses
    inline_data: [MAX_INLINE_SIZE]u8,  // Small files stored inline
    inline_used: u32,
    page_data: [MAX_FILE_PAGES]u64,    // Page physical addresses for larger files
    page_count: u32,

    // For directories: dir entries
    entries: [MAX_DIR_ENTRIES]DirEntry,
    entry_count: u32,
    parent_inode: u32,

    // For symlinks
    symlink_target: [MAX_SYMLINK_LEN]u8,
    symlink_len: u32,

    pub fn init(id: u32) TmpfsInode {
        var inode: TmpfsInode = undefined;
        inode.id = id;
        inode.inode_type = 0;
        inode.active = false;
        inode.mode = PERM_DEFAULT_FILE;
        inode.uid = 0;
        inode.gid = 0;
        inode.nlink = 0;
        inode.size = 0;
        inode.atime = TmpfsTime.zero();
        inode.mtime = TmpfsTime.zero();
        inode.ctime = TmpfsTime.zero();
        inode.inline_used = 0;
        inode.page_count = 0;
        inode.entry_count = 0;
        inode.parent_inode = 0;
        inode.symlink_len = 0;
        for (0..MAX_INLINE_SIZE) |i| inode.inline_data[i] = 0;
        for (0..MAX_FILE_PAGES) |i| inode.page_data[i] = 0;
        for (0..MAX_DIR_ENTRIES) |i| inode.entries[i] = DirEntry.init();
        for (0..MAX_SYMLINK_LEN) |i| inode.symlink_target[i] = 0;
        return inode;
    }

    pub fn isDir(self: *const TmpfsInode) bool {
        return self.inode_type == INODE_TYPE_DIR;
    }

    pub fn isFile(self: *const TmpfsInode) bool {
        return self.inode_type == INODE_TYPE_FILE;
    }

    pub fn isSymlink(self: *const TmpfsInode) bool {
        return self.inode_type == INODE_TYPE_SYMLINK;
    }
};

// ============================================================================
// tmpfs filesystem
// ============================================================================

pub const TmpfsInstance = struct {
    inodes: [MAX_TMPFS_INODES]TmpfsInode,
    inode_count: u32,
    next_inode_id: u32,
    root_inode: u32,
    max_size: u64,       // Maximum total size in bytes
    used_size: u64,      // Current total usage
    mount_id: u32,
    mounted: bool,

    pub fn init() TmpfsInstance {
        var fs: TmpfsInstance = undefined;
        fs.inode_count = 0;
        fs.next_inode_id = 1;
        fs.root_inode = 0;
        fs.max_size = 128 * 1024 * 1024; // Default: 128 MB
        fs.used_size = 0;
        fs.mount_id = 0;
        fs.mounted = false;
        for (0..MAX_TMPFS_INODES) |i| {
            fs.inodes[i] = TmpfsInode.init(@intCast(i));
        }
        return fs;
    }

    /// Allocate a new inode
    fn allocInode(self: *TmpfsInstance, itype: u8) ?u32 {
        for (0..MAX_TMPFS_INODES) |i| {
            if (!self.inodes[i].active) {
                self.inodes[i] = TmpfsInode.init(self.next_inode_id);
                self.inodes[i].inode_type = itype;
                self.inodes[i].active = true;
                self.next_inode_id += 1;
                self.inode_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Mount: create root directory
    pub fn mount(self: *TmpfsInstance) bool {
        const root_idx = self.allocInode(INODE_TYPE_DIR) orelse return false;
        self.inodes[root_idx].mode = PERM_DEFAULT_DIR;
        self.inodes[root_idx].nlink = 2; // . and parent
        self.root_inode = root_idx;
        self.mounted = true;
        return true;
    }

    /// Create file in a directory
    pub fn createFile(self: *TmpfsInstance, dir_idx: u32, name: []const u8, mode: u16) ?u32 {
        if (dir_idx >= MAX_TMPFS_INODES) return null;
        var dir = &self.inodes[dir_idx];
        if (!dir.isDir() or !dir.active) return null;
        if (dir.entry_count >= MAX_DIR_ENTRIES) return null;

        // Check name doesn't already exist
        for (0..dir.entry_count) |i| {
            if (dir.entries[i].active and dir.entries[i].nameEquals(name)) return null;
        }

        const file_idx = self.allocInode(INODE_TYPE_FILE) orelse return null;
        self.inodes[file_idx].mode = mode;
        self.inodes[file_idx].nlink = 1;

        // Add directory entry
        var de = &dir.entries[dir.entry_count];
        de.setName(name);
        de.inode_id = file_idx;
        de.entry_type = INODE_TYPE_FILE;
        de.active = true;
        dir.entry_count += 1;

        return file_idx;
    }

    /// Create subdirectory
    pub fn mkdir(self: *TmpfsInstance, parent_idx: u32, name: []const u8, mode: u16) ?u32 {
        if (parent_idx >= MAX_TMPFS_INODES) return null;
        var parent = &self.inodes[parent_idx];
        if (!parent.isDir() or !parent.active) return null;
        if (parent.entry_count >= MAX_DIR_ENTRIES) return null;

        const dir_idx = self.allocInode(INODE_TYPE_DIR) orelse return null;
        self.inodes[dir_idx].mode = mode;
        self.inodes[dir_idx].nlink = 2;
        self.inodes[dir_idx].parent_inode = parent_idx;

        var de = &parent.entries[parent.entry_count];
        de.setName(name);
        de.inode_id = dir_idx;
        de.entry_type = INODE_TYPE_DIR;
        de.active = true;
        parent.entry_count += 1;
        parent.nlink += 1;

        return dir_idx;
    }

    /// Create a symbolic link
    pub fn symlink(self: *TmpfsInstance, dir_idx: u32, name: []const u8, target: []const u8) ?u32 {
        if (dir_idx >= MAX_TMPFS_INODES) return null;
        if (target.len >= MAX_SYMLINK_LEN) return null;
        var dir = &self.inodes[dir_idx];
        if (!dir.isDir() or !dir.active) return null;

        const link_idx = self.allocInode(INODE_TYPE_SYMLINK) orelse return null;
        self.inodes[link_idx].nlink = 1;
        for (0..target.len) |i| {
            self.inodes[link_idx].symlink_target[i] = target[i];
        }
        self.inodes[link_idx].symlink_len = @intCast(target.len);
        self.inodes[link_idx].size = target.len;

        var de = &dir.entries[dir.entry_count];
        de.setName(name);
        de.inode_id = link_idx;
        de.entry_type = INODE_TYPE_SYMLINK;
        de.active = true;
        dir.entry_count += 1;

        return link_idx;
    }

    /// Write inline data to a file
    pub fn writeInline(self: *TmpfsInstance, inode_idx: u32, data: []const u8) bool {
        if (inode_idx >= MAX_TMPFS_INODES) return false;
        var inode = &self.inodes[inode_idx];
        if (!inode.isFile() or !inode.active) return false;
        if (data.len > MAX_INLINE_SIZE) return false;

        for (0..data.len) |i| {
            inode.inline_data[i] = data[i];
        }
        inode.inline_used = @intCast(data.len);
        inode.size = data.len;
        self.used_size += data.len;
        return true;
    }

    /// Lookup entry in directory
    pub fn lookup(self: *const TmpfsInstance, dir_idx: u32, name: []const u8) ?u32 {
        if (dir_idx >= MAX_TMPFS_INODES) return null;
        const dir = &self.inodes[dir_idx];
        if (!dir.isDir() or !dir.active) return null;

        for (0..dir.entry_count) |i| {
            if (dir.entries[i].active and dir.entries[i].nameEquals(name)) {
                return dir.entries[i].inode_id;
            }
        }
        return null;
    }

    /// Unlink (remove) a file
    pub fn unlink(self: *TmpfsInstance, dir_idx: u32, name: []const u8) bool {
        if (dir_idx >= MAX_TMPFS_INODES) return false;
        var dir = &self.inodes[dir_idx];
        if (!dir.isDir() or !dir.active) return false;

        for (0..dir.entry_count) |i| {
            if (dir.entries[i].active and dir.entries[i].nameEquals(name)) {
                const inode_idx = dir.entries[i].inode_id;
                dir.entries[i].active = false;

                // Decrement link count
                if (inode_idx < MAX_TMPFS_INODES) {
                    self.inodes[inode_idx].nlink -= 1;
                    if (self.inodes[inode_idx].nlink == 0) {
                        self.used_size -|= self.inodes[inode_idx].size;
                        self.inodes[inode_idx].active = false;
                        self.inode_count -= 1;
                    }
                }
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// Global tmpfs instances
// ============================================================================

var tmpfs_mounts: [MAX_MOUNTS]TmpfsInstance = init: {
    var arr: [MAX_MOUNTS]TmpfsInstance = undefined;
    for (0..MAX_MOUNTS) |i| {
        arr[i] = TmpfsInstance.init();
    }
    break :init arr;
};

pub fn getTmpfs(mount_id: u32) ?*TmpfsInstance {
    if (mount_id >= MAX_MOUNTS) return null;
    if (!tmpfs_mounts[mount_id].mounted) return null;
    return &tmpfs_mounts[mount_id];
}

pub fn mountTmpfs() ?u32 {
    for (0..MAX_MOUNTS) |i| {
        if (!tmpfs_mounts[i].mounted) {
            if (tmpfs_mounts[i].mount()) {
                tmpfs_mounts[i].mount_id = @intCast(i);
                return @intCast(i);
            }
        }
    }
    return null;
}
