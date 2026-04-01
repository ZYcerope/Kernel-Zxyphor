// =============================================================================
// Kernel Zxyphor - Virtual File System (VFS)
// =============================================================================
// The VFS provides a unified interface for all file systems. Every file
// system (ext4, FAT32, RAM-based, device-based, etc.) registers itself
// with the VFS and provides implementations for a common set of operations.
//
// Key concepts:
//   - VNode (Virtual Node): Represents any file system object (file, directory,
//     device, pipe, socket, symlink). Each vnode holds metadata and a pointer
//     to its file system's operation table.
//   - Superblock: Represents a mounted file system instance.
//   - Mount table: Maps directory paths to mounted file systems.
//   - File descriptors: Per-process handles to open files.
//
// The VFS is path-based: every operation starts with a path string that is
// resolved through the mount table to find the correct file system and
// then the correct vnode.
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_FILENAME_LEN: usize = 255;
pub const MAX_MOUNTS: usize = 64;
pub const MAX_VNODES: usize = 16384;
pub const MAX_OPEN_FILES: usize = 65536;
pub const MAX_SYMLINK_DEPTH: usize = 40;
pub const BLOCK_SIZE: usize = 4096;

// =============================================================================
// File types (matches Linux mode encoding)
// =============================================================================
pub const FileType = enum(u8) {
    regular = 1,
    directory = 2,
    char_device = 3,
    block_device = 4,
    pipe = 5,
    socket = 6,
    symlink = 7,
    unknown = 0,
};

// =============================================================================
// File mode flags (POSIX-compatible)
// =============================================================================
pub const S_IRUSR: u16 = 0o400;
pub const S_IWUSR: u16 = 0o200;
pub const S_IXUSR: u16 = 0o100;
pub const S_IRGRP: u16 = 0o040;
pub const S_IWGRP: u16 = 0o020;
pub const S_IXGRP: u16 = 0o010;
pub const S_IROTH: u16 = 0o004;
pub const S_IWOTH: u16 = 0o002;
pub const S_IXOTH: u16 = 0o001;
pub const S_ISUID: u16 = 0o4000;
pub const S_ISGID: u16 = 0o2000;
pub const S_ISVTX: u16 = 0o1000;
pub const S_IRWXU: u16 = S_IRUSR | S_IWUSR | S_IXUSR;
pub const S_IRWXG: u16 = S_IRGRP | S_IWGRP | S_IXGRP;
pub const S_IRWXO: u16 = S_IROTH | S_IWOTH | S_IXOTH;

// =============================================================================
// Open flags
// =============================================================================
pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_EXCL: u32 = 0x0080;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;
pub const O_NONBLOCK: u32 = 0x0800;
pub const O_DIRECTORY: u32 = 0x10000;
pub const O_CLOEXEC: u32 = 0x80000;

// =============================================================================
// Seek modes
// =============================================================================
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

// =============================================================================
// VFS errors
// =============================================================================
pub const VfsError = error{
    NotFound,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    PermissionDenied,
    NoSpace,
    ReadOnly,
    InvalidArgument,
    NotEmpty,
    TooManyLinks,
    IoError,
    NotSupported,
    BrokenPipe,
    WouldBlock,
    NoMountPoint,
    MountTableFull,
    VnodeTableFull,
    TooManyOpenFiles,
    BadFileDescriptor,
    NameTooLong,
    CrossDevice,
    Busy,
};

// =============================================================================
// VNode — the universal file system object
// =============================================================================
pub const VNode = struct {
    // Identity
    inode: u64 = 0,
    superblock: ?*Superblock = null,
    file_type: FileType = .unknown,

    // Metadata
    mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    link_count: u32 = 1,

    // Timestamps (Unix epoch seconds)
    atime: u64 = 0, // Last access
    mtime: u64 = 0, // Last modification
    ctime: u64 = 0, // Last status change
    crtime: u64 = 0, // Creation time

    // Device numbers (for char/block devices)
    dev_major: u16 = 0,
    dev_minor: u16 = 0,

    // Reference counting
    ref_count: u32 = 0,

    // File system specific operations
    ops: ?*const VNodeOps = null,

    // Private data for the file system implementation
    fs_data: ?*anyopaque = null,

    // Parent and name for path resolution
    parent: ?*VNode = null,
    name: [MAX_FILENAME_LEN + 1]u8 = [_]u8{0} ** (MAX_FILENAME_LEN + 1),
    name_len: u16 = 0,

    // For directory: children list
    children_head: ?*VNode = null,
    sibling_next: ?*VNode = null,

    // Flags
    is_mountpoint: bool = false,
    is_dirty: bool = false,
    is_valid: bool = false,

    pub fn getName(self: *const VNode) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *VNode, new_name: []const u8) void {
        const len = @min(new_name.len, MAX_FILENAME_LEN);
        @memcpy(self.name[0..len], new_name[0..len]);
        self.name[len] = 0;
        self.name_len = @truncate(len);
    }

    pub fn addChild(self: *VNode, child: *VNode) void {
        child.parent = self;
        child.sibling_next = self.children_head;
        self.children_head = child;
    }

    pub fn findChild(self: *VNode, name: []const u8) ?*VNode {
        var child = self.children_head;
        while (child) |c| {
            if (c.name_len == name.len) {
                if (strEqual(c.name[0..c.name_len], name)) {
                    return c;
                }
            }
            child = c.sibling_next;
        }
        return null;
    }

    pub fn removeChild(self: *VNode, child: *VNode) bool {
        if (self.children_head == child) {
            self.children_head = child.sibling_next;
            child.sibling_next = null;
            child.parent = null;
            return true;
        }

        var prev = self.children_head;
        while (prev) |p| {
            if (p.sibling_next == child) {
                p.sibling_next = child.sibling_next;
                child.sibling_next = null;
                child.parent = null;
                return true;
            }
            prev = p.sibling_next;
        }
        return false;
    }
};

// =============================================================================
// VNode operations — the "vtable" that each file system provides
// =============================================================================
pub const VNodeOps = struct {
    // File operations
    read: ?*const fn (vnode: *VNode, buffer: []u8, offset: u64) VfsError!usize = null,
    write: ?*const fn (vnode: *VNode, data: []const u8, offset: u64) VfsError!usize = null,
    truncate: ?*const fn (vnode: *VNode, size: u64) VfsError!void = null,

    // Directory operations
    lookup: ?*const fn (dir: *VNode, name: []const u8) VfsError!*VNode = null,
    create: ?*const fn (dir: *VNode, name: []const u8, file_type: FileType, mode: u16) VfsError!*VNode = null,
    unlink: ?*const fn (dir: *VNode, name: []const u8) VfsError!void = null,
    mkdir: ?*const fn (dir: *VNode, name: []const u8, mode: u16) VfsError!*VNode = null,
    rmdir: ?*const fn (dir: *VNode, name: []const u8) VfsError!void = null,
    readdir: ?*const fn (dir: *VNode, buffer: []DirEntry, offset: *u64) VfsError!usize = null,

    // Link operations
    link: ?*const fn (dir: *VNode, name: []const u8, target: *VNode) VfsError!void = null,
    symlink: ?*const fn (dir: *VNode, name: []const u8, target: []const u8) VfsError!*VNode = null,
    readlink: ?*const fn (vnode: *VNode, buffer: []u8) VfsError!usize = null,

    // Metadata operations
    getattr: ?*const fn (vnode: *VNode) VfsError!VNodeAttr = null,
    setattr: ?*const fn (vnode: *VNode, attr: *const VNodeAttr) VfsError!void = null,
    chmod: ?*const fn (vnode: *VNode, mode: u16) VfsError!void = null,
    chown: ?*const fn (vnode: *VNode, uid: u32, gid: u32) VfsError!void = null,

    // Special operations
    ioctl: ?*const fn (vnode: *VNode, cmd: u32, arg: u64) VfsError!i64 = null,
    mmap: ?*const fn (vnode: *VNode, offset: u64, size: usize) VfsError!u64 = null,
    sync: ?*const fn (vnode: *VNode) VfsError!void = null,
};

pub const VNodeAttr = struct {
    file_type: FileType = .unknown,
    mode: u16 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    link_count: u32 = 0,
    atime: u64 = 0,
    mtime: u64 = 0,
    ctime: u64 = 0,
    dev_major: u16 = 0,
    dev_minor: u16 = 0,
    blocks: u64 = 0,
    blksize: u32 = BLOCK_SIZE,
};

// =============================================================================
// Directory entry
// =============================================================================
pub const DirEntry = struct {
    inode: u64 = 0,
    file_type: FileType = .unknown,
    name: [MAX_FILENAME_LEN + 1]u8 = [_]u8{0} ** (MAX_FILENAME_LEN + 1),
    name_len: u16 = 0,

    pub fn getName(self: *const DirEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

// =============================================================================
// File system type registration
// =============================================================================
pub const FileSystemType = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    flags: u32 = 0,

    // Called to mount an instance
    mount: ?*const fn (device: ?*VNode, flags: u32) VfsError!*Superblock = null,
    unmount: ?*const fn (sb: *Superblock) VfsError!void = null,
};

// =============================================================================
// Superblock — represents a mounted file system instance
// =============================================================================
pub const Superblock = struct {
    fs_type: ?*FileSystemType = null,
    root: ?*VNode = null, // Root vnode of this file system
    device: ?*VNode = null, // Block device (if any)
    block_size: u32 = BLOCK_SIZE,
    total_blocks: u64 = 0,
    free_blocks: u64 = 0,
    total_inodes: u64 = 0,
    free_inodes: u64 = 0,
    flags: u32 = 0, // MS_RDONLY, etc.
    fs_data: ?*anyopaque = null, // File system private data
    is_valid: bool = false,
};

// =============================================================================
// Mount entry
// =============================================================================
const MountEntry = struct {
    mount_path: [MAX_PATH_LEN]u8 = [_]u8{0} ** MAX_PATH_LEN,
    path_len: u16 = 0,
    superblock: ?*Superblock = null,
    mount_vnode: ?*VNode = null, // The directory vnode that was mounted over
    is_active: bool = false,
};

// =============================================================================
// Open file description
// =============================================================================
pub const OpenFile = struct {
    vnode: ?*VNode = null,
    offset: u64 = 0,
    flags: u32 = 0,
    ref_count: u32 = 0,
    is_valid: bool = false,
};

// =============================================================================
// Global state
// =============================================================================
var vnode_pool: [MAX_VNODES]VNode = undefined;
var vnode_pool_used: [MAX_VNODES]bool = [_]bool{false} ** MAX_VNODES;

var mount_table: [MAX_MOUNTS]MountEntry = undefined;

var open_file_table: [MAX_OPEN_FILES]OpenFile = undefined;

var root_vnode: ?*VNode = null;

var initialized: bool = false;

// =============================================================================
// Initialize the VFS
// =============================================================================
pub fn initialize() void {
    // Clear vnode pool
    for (&vnode_pool) |*v| {
        v.* = VNode{};
    }

    // Clear mount table
    for (&mount_table) |*m| {
        m.* = MountEntry{};
    }

    // Clear open file table
    for (&open_file_table) |*f| {
        f.* = OpenFile{};
    }

    // Create the root vnode ("/")
    if (allocVNode()) |root| {
        root.file_type = .directory;
        root.mode = 0o755;
        root.inode = 1;
        root.link_count = 2;
        root.is_valid = true;
        root.setName("/");
        root_vnode = root;
    }

    initialized = true;
    main.klog(.info, "VFS: initialized ({d} vnodes, {d} mounts)", .{ MAX_VNODES, MAX_MOUNTS });
}

// =============================================================================
// VNode allocation
// =============================================================================
pub fn allocVNode() ?*VNode {
    for (&vnode_pool, 0..) |*v, i| {
        if (!vnode_pool_used[i]) {
            vnode_pool_used[i] = true;
            v.* = VNode{};
            v.is_valid = true;
            v.ref_count = 1;
            return v;
        }
    }
    return null;
}

pub fn freeVNode(vnode: *VNode) void {
    for (&vnode_pool, 0..) |*v, i| {
        if (v == vnode) {
            vnode_pool_used[i] = false;
            v.* = VNode{};
            return;
        }
    }
}

// =============================================================================
// Mount / Unmount
// =============================================================================
pub fn mount(path: []const u8, sb: *Superblock) VfsError!void {
    for (&mount_table) |*m| {
        if (!m.is_active) {
            const len = @min(path.len, MAX_PATH_LEN);
            @memcpy(m.mount_path[0..len], path[0..len]);
            m.path_len = @truncate(len);
            m.superblock = sb;
            m.is_active = true;

            // Find the vnode at this path and mark it as a mount point
            if (resolvePath(path)) |vnode| {
                vnode.is_mountpoint = true;
                m.mount_vnode = vnode;
            }

            main.klog(.info, "VFS: mounted filesystem at {s}", .{path});
            return;
        }
    }
    return VfsError.MountTableFull;
}

pub fn unmount(path: []const u8) VfsError!void {
    for (&mount_table) |*m| {
        if (m.is_active and m.path_len == path.len) {
            if (strEqual(m.mount_path[0..m.path_len], path)) {
                if (m.mount_vnode) |vnode| {
                    vnode.is_mountpoint = false;
                }
                m.is_active = false;
                return;
            }
        }
    }
    return VfsError.NoMountPoint;
}

// =============================================================================
// Path resolution
// =============================================================================
pub fn resolvePath(path: []const u8) ?*VNode {
    if (path.len == 0) return root_vnode;
    if (path[0] != '/') return null; // Only absolute paths

    var current = root_vnode orelse return null;

    if (path.len == 1) return current; // Just "/"

    // Walk the path component by component
    var pos: usize = 1; // Skip leading '/'
    while (pos < path.len) {
        // Skip consecutive slashes
        while (pos < path.len and path[pos] == '/') pos += 1;
        if (pos >= path.len) break;

        // Extract the next component
        const start = pos;
        while (pos < path.len and path[pos] != '/') pos += 1;
        const component = path[start..pos];

        if (component.len == 0) continue;

        // Handle "." and ".."
        if (component.len == 1 and component[0] == '.') continue;
        if (component.len == 2 and component[0] == '.' and component[1] == '.') {
            if (current.parent) |p| current = p;
            continue;
        }

        // Check if this is a mount point
        if (current.is_mountpoint) {
            if (getMountedRoot(current)) |mounted_root| {
                current = mounted_root;
            }
        }

        // Lookup in directory
        if (current.ops) |ops| {
            if (ops.lookup) |lookup_fn| {
                current = lookup_fn(current, component) catch return null;
                continue;
            }
        }

        // Fallback to in-memory children
        if (current.findChild(component)) |child| {
            current = child;
        } else {
            return null;
        }
    }

    return current;
}

fn getMountedRoot(vnode: *VNode) ?*VNode {
    _ = vnode;
    for (&mount_table) |*m| {
        if (m.is_active) {
            if (m.superblock) |sb| {
                return sb.root;
            }
        }
    }
    return null;
}

// =============================================================================
// High-level VFS operations
// =============================================================================

/// Create a directory at the given path
pub fn mkdir(path: []const u8, mode: u16) VfsError!*VNode {
    const parent_and_name = splitPath(path);
    const parent_path = parent_and_name.parent;
    const name = parent_and_name.name;

    if (name.len == 0) return VfsError.InvalidArgument;
    if (name.len > MAX_FILENAME_LEN) return VfsError.NameTooLong;

    const parent = resolvePath(parent_path) orelse return VfsError.NotFound;

    if (parent.file_type != .directory) return VfsError.NotADirectory;

    // Check if name already exists
    if (parent.findChild(name) != null) return VfsError.AlreadyExists;

    // Try the filesystem's mkdir operation
    if (parent.ops) |ops| {
        if (ops.mkdir) |mkdir_fn| {
            return mkdir_fn(parent, name, mode);
        }
    }

    // Fallback: create an in-memory directory node
    const new_dir = allocVNode() orelse return VfsError.VnodeTableFull;
    new_dir.file_type = .directory;
    new_dir.mode = mode;
    new_dir.link_count = 2;
    new_dir.setName(name);
    new_dir.ops = parent.ops;
    new_dir.superblock = parent.superblock;
    parent.addChild(new_dir);

    return new_dir;
}

/// Create a file at the given path
pub fn createFile(path: []const u8, mode: u16) VfsError!*VNode {
    const parent_and_name = splitPath(path);
    const parent_path = parent_and_name.parent;
    const name = parent_and_name.name;

    if (name.len == 0) return VfsError.InvalidArgument;

    const parent = resolvePath(parent_path) orelse return VfsError.NotFound;

    if (parent.file_type != .directory) return VfsError.NotADirectory;
    if (parent.findChild(name) != null) return VfsError.AlreadyExists;

    if (parent.ops) |ops| {
        if (ops.create) |create_fn| {
            return create_fn(parent, name, .regular, mode);
        }
    }

    // Fallback: in-memory file node
    const new_file = allocVNode() orelse return VfsError.VnodeTableFull;
    new_file.file_type = .regular;
    new_file.mode = mode;
    new_file.setName(name);
    new_file.ops = parent.ops;
    new_file.superblock = parent.superblock;
    parent.addChild(new_file);

    return new_file;
}

/// Open a file and return a file descriptor index
pub fn open(path: []const u8, flags: u32) VfsError!usize {
    var vnode: *VNode = undefined;

    if (resolvePath(path)) |v| {
        vnode = v;
    } else {
        // File doesn't exist — create if O_CREAT is set
        if (flags & O_CREAT != 0) {
            vnode = try createFile(path, 0o644);
        } else {
            return VfsError.NotFound;
        }
    }

    if (flags & O_DIRECTORY != 0 and vnode.file_type != .directory) {
        return VfsError.NotADirectory;
    }

    if (flags & O_TRUNC != 0 and vnode.file_type == .regular) {
        if (vnode.ops) |ops| {
            if (ops.truncate) |trunc_fn| {
                try trunc_fn(vnode, 0);
            }
        }
        vnode.size = 0;
    }

    // Find a free slot in the open file table
    for (&open_file_table, 0..) |*f, i| {
        if (!f.is_valid) {
            f.vnode = vnode;
            f.offset = 0;
            f.flags = flags;
            f.ref_count = 1;
            f.is_valid = true;
            vnode.ref_count += 1;
            return i;
        }
    }

    return VfsError.TooManyOpenFiles;
}

/// Read from an open file
pub fn read(fd: usize, buffer: []u8) VfsError!usize {
    if (fd >= MAX_OPEN_FILES) return VfsError.BadFileDescriptor;
    const file = &open_file_table[fd];
    if (!file.is_valid) return VfsError.BadFileDescriptor;

    const vnode = file.vnode orelse return VfsError.BadFileDescriptor;

    if (vnode.ops) |ops| {
        if (ops.read) |read_fn| {
            const bytes_read = try read_fn(vnode, buffer, file.offset);
            file.offset += bytes_read;
            return bytes_read;
        }
    }

    return 0;
}

/// Write to an open file  
pub fn write(fd: usize, data: []const u8) VfsError!usize {
    if (fd >= MAX_OPEN_FILES) return VfsError.BadFileDescriptor;
    const file = &open_file_table[fd];
    if (!file.is_valid) return VfsError.BadFileDescriptor;

    const vnode = file.vnode orelse return VfsError.BadFileDescriptor;

    if (file.flags & O_APPEND != 0) {
        file.offset = vnode.size;
    }

    if (vnode.ops) |ops| {
        if (ops.write) |write_fn| {
            const bytes_written = try write_fn(vnode, data, file.offset);
            file.offset += bytes_written;
            if (file.offset > vnode.size) {
                vnode.size = file.offset;
            }
            return bytes_written;
        }
    }

    return 0;
}

/// Seek to a position in an open file
pub fn seek(fd: usize, offset: i64, whence: u32) VfsError!u64 {
    if (fd >= MAX_OPEN_FILES) return VfsError.BadFileDescriptor;
    const file = &open_file_table[fd];
    if (!file.is_valid) return VfsError.BadFileDescriptor;

    const vnode = file.vnode orelse return VfsError.BadFileDescriptor;

    var new_offset: i64 = 0;
    switch (whence) {
        SEEK_SET => new_offset = offset,
        SEEK_CUR => new_offset = @as(i64, @intCast(file.offset)) + offset,
        SEEK_END => new_offset = @as(i64, @intCast(vnode.size)) + offset,
        else => return VfsError.InvalidArgument,
    }

    if (new_offset < 0) return VfsError.InvalidArgument;

    file.offset = @intCast(new_offset);
    return file.offset;
}

/// Close an open file
pub fn close(fd: usize) VfsError!void {
    if (fd >= MAX_OPEN_FILES) return VfsError.BadFileDescriptor;
    const file = &open_file_table[fd];
    if (!file.is_valid) return VfsError.BadFileDescriptor;

    if (file.vnode) |vnode| {
        if (vnode.ref_count > 0) vnode.ref_count -= 1;
    }

    file.ref_count -= 1;
    if (file.ref_count == 0) {
        file.is_valid = false;
        file.vnode = null;
    }
}

/// Delete a file
pub fn unlink(path: []const u8) VfsError!void {
    const parent_and_name = splitPath(path);
    const parent_path = parent_and_name.parent;
    const name = parent_and_name.name;

    const parent = resolvePath(parent_path) orelse return VfsError.NotFound;

    if (parent.ops) |ops| {
        if (ops.unlink) |unlink_fn| {
            return unlink_fn(parent, name);
        }
    }

    // Fallback: in-memory removal
    if (parent.findChild(name)) |child| {
        if (child.file_type == .directory) return VfsError.IsADirectory;
        _ = parent.removeChild(child);
        freeVNode(child);
    } else {
        return VfsError.NotFound;
    }
}

/// Remove a directory
pub fn rmdir(path: []const u8) VfsError!void {
    const parent_and_name = splitPath(path);
    const parent_path = parent_and_name.parent;
    const name = parent_and_name.name;

    const parent = resolvePath(parent_path) orelse return VfsError.NotFound;

    if (parent.ops) |ops| {
        if (ops.rmdir) |rmdir_fn| {
            return rmdir_fn(parent, name);
        }
    }

    if (parent.findChild(name)) |child| {
        if (child.file_type != .directory) return VfsError.NotADirectory;
        if (child.children_head != null) return VfsError.NotEmpty;
        _ = parent.removeChild(child);
        freeVNode(child);
    } else {
        return VfsError.NotFound;
    }
}

/// List directory contents
pub fn listDirectory(path: []const u8, buffer: []DirEntry) VfsError!usize {
    const dir = resolvePath(path) orelse return VfsError.NotFound;
    if (dir.file_type != .directory) return VfsError.NotADirectory;

    // Try the filesystem's readdir
    if (dir.ops) |ops| {
        if (ops.readdir) |readdir_fn| {
            var offset: u64 = 0;
            return readdir_fn(dir, buffer, &offset);
        }
    }

    // Fallback: list in-memory children
    var count: usize = 0;
    var child = dir.children_head;
    while (child) |c| {
        if (count >= buffer.len) break;
        buffer[count].inode = c.inode;
        buffer[count].file_type = c.file_type;
        const name = c.getName();
        const len = @min(name.len, MAX_FILENAME_LEN);
        @memcpy(buffer[count].name[0..len], name[0..len]);
        buffer[count].name_len = @truncate(len);
        count += 1;
        child = c.sibling_next;
    }

    return count;
}

/// Get file status (stat)
pub fn stat(path: []const u8) VfsError!VNodeAttr {
    const vnode = resolvePath(path) orelse return VfsError.NotFound;

    if (vnode.ops) |ops| {
        if (ops.getattr) |getattr_fn| {
            return getattr_fn(vnode);
        }
    }

    // Build attr from vnode metadata
    return VNodeAttr{
        .file_type = vnode.file_type,
        .mode = vnode.mode,
        .uid = vnode.uid,
        .gid = vnode.gid,
        .size = vnode.size,
        .link_count = vnode.link_count,
        .atime = vnode.atime,
        .mtime = vnode.mtime,
        .ctime = vnode.ctime,
        .dev_major = vnode.dev_major,
        .dev_minor = vnode.dev_minor,
    };
}

/// Rename/move a file
pub fn rename(old_path: []const u8, new_path: []const u8) VfsError!void {
    const old_info = splitPath(old_path);
    const new_info = splitPath(new_path);

    const old_parent = resolvePath(old_info.parent) orelse return VfsError.NotFound;
    const new_parent = resolvePath(new_info.parent) orelse return VfsError.NotFound;

    const child = old_parent.findChild(old_info.name) orelse return VfsError.NotFound;

    // Remove from old parent
    _ = old_parent.removeChild(child);

    // Add to new parent
    child.setName(new_info.name);
    new_parent.addChild(child);
}

// =============================================================================
// Helper: path splitting
// =============================================================================
const PathParts = struct {
    parent: []const u8,
    name: []const u8,
};

fn splitPath(path: []const u8) PathParts {
    if (path.len == 0) return .{ .parent = "/", .name = "" };

    // Find last '/'
    var last_slash: usize = 0;
    var found = false;
    var i: usize = path.len;
    while (i > 0) {
        i -= 1;
        if (path[i] == '/') {
            last_slash = i;
            found = true;
            break;
        }
    }

    if (!found) {
        return .{ .parent = ".", .name = path };
    }

    if (last_slash == 0) {
        return .{ .parent = "/", .name = path[1..] };
    }

    return .{
        .parent = path[0..last_slash],
        .name = path[last_slash + 1 ..],
    };
}

fn strEqual(a: []const u8, b: []const u8) bool {
    return main.string.equal(a, b);
}

// =============================================================================
// Get root VNode
// =============================================================================
pub fn getRoot() ?*VNode {
    return root_vnode;
}

/// Get statistics
pub fn getStats() struct { total_vnodes: usize, used_vnodes: usize, mounts: usize } {
    var used: usize = 0;
    for (vnode_pool_used) |u| {
        if (u) used += 1;
    }

    var mounts: usize = 0;
    for (mount_table) |m| {
        if (m.is_active) mounts += 1;
    }

    return .{
        .total_vnodes = MAX_VNODES,
        .used_vnodes = used,
        .mounts = mounts,
    };
}
