// =============================================================================
// Kernel Zxyphor - RAM File System (ramfs)
// =============================================================================
// A simple in-memory file system used during early boot before persistent
// storage is available. All data is stored in kernel heap memory.
//
// Features:
//   - Files with dynamically growing data buffers
//   - Directories with arbitrary nesting
//   - Basic permissions (mode, uid, gid)
//   - Referenced via VFS operations table
//
// This is similar to Linux's tmpfs/ramfs but simpler — it doesn't have
// swap backing and all data lives in RAM.
// =============================================================================

const main = @import("../main.zig");
const vfs = main.vfs;

// =============================================================================
// Constants
// =============================================================================
const MAX_FILE_SIZE: usize = 16 * 1024 * 1024; // 16 MB per file
const INITIAL_DATA_SIZE: usize = 4096; // Start with 4KB buffer
const MAX_RAMFS_FILES: usize = 4096;

// =============================================================================
// Per-file data stored in vnode.fs_data
// =============================================================================
const RamFileData = struct {
    data: ?[*]u8 = null,
    capacity: usize = 0,
    size: usize = 0,
    is_valid: bool = false,
};

var file_data_pool: [MAX_RAMFS_FILES]RamFileData = undefined;

// =============================================================================
// Superblock for the ramfs instance
// =============================================================================
var ramfs_superblock: vfs.Superblock = .{};
var ramfs_type: vfs.FileSystemType = .{};
var next_inode: u64 = 100;

// =============================================================================
// VNode operations table for ramfs
// =============================================================================
pub const ramfs_ops = vfs.VNodeOps{
    .read = ramfsRead,
    .write = ramfsWrite,
    .truncate = ramfsTruncate,
    .lookup = ramfsLookup,
    .create = ramfsCreate,
    .unlink = ramfsUnlink,
    .mkdir = ramfsMkdir,
    .rmdir = ramfsRmdir,
    .readdir = ramfsReaddir,
    .getattr = ramfsGetattr,
    .chmod = ramfsChmod,
    .chown = ramfsChown,
    .sync = ramfsSync,
};

// =============================================================================
// Initialize ramfs
// =============================================================================
pub fn initialize() void {
    for (&file_data_pool) |*f| {
        f.* = RamFileData{};
    }

    // Set up filesystem type
    const name = "ramfs";
    @memcpy(ramfs_type.name[0..name.len], name);
    ramfs_type.name_len = name.len;

    // Initialize superblock
    ramfs_superblock.fs_type = &ramfs_type;
    ramfs_superblock.block_size = 4096;
    ramfs_superblock.is_valid = true;

    // Set up the root vnode's operations
    if (vfs.getRoot()) |root| {
        root.ops = &ramfs_ops;
        root.superblock = &ramfs_superblock;
        ramfs_superblock.root = root;
    }

    main.klog(.info, "ramfs: initialized (max {d} files)", .{MAX_RAMFS_FILES});
}

// =============================================================================
// File data management
// =============================================================================
fn allocFileData() ?*RamFileData {
    for (&file_data_pool) |*f| {
        if (!f.is_valid) {
            f.* = RamFileData{};
            f.is_valid = true;
            return f;
        }
    }
    return null;
}

fn freeFileData(fd: *RamFileData) void {
    // In a real kernel, we'd free the data buffer back to the heap
    // For now, just mark as invalid
    fd.is_valid = false;
    fd.data = null;
    fd.capacity = 0;
    fd.size = 0;
}

fn ensureCapacity(fd: *RamFileData, needed: usize) bool {
    if (needed <= fd.capacity) return true;
    if (needed > MAX_FILE_SIZE) return false;

    // Calculate new capacity (double or the needed amount, whichever is larger)
    var new_cap = if (fd.capacity == 0) INITIAL_DATA_SIZE else fd.capacity;
    while (new_cap < needed) {
        new_cap *= 2;
        if (new_cap > MAX_FILE_SIZE) {
            new_cap = MAX_FILE_SIZE;
            break;
        }
    }

    // Allocate new buffer from kernel heap
    const new_buf = main.heap.alloc(new_cap) orelse return false;

    // Copy existing data
    if (fd.data) |old_buf| {
        const old_slice = old_buf[0..fd.size];
        const new_slice = @as([*]u8, @ptrCast(new_buf))[0..fd.size];
        @memcpy(new_slice, old_slice);
        main.heap.free(old_buf);
    }

    fd.data = @ptrCast(new_buf);
    fd.capacity = new_cap;
    return true;
}

// =============================================================================
// VNode operations implementation
// =============================================================================

fn ramfsRead(node: *vfs.VNode, buffer: []u8, offset: u64) vfs.VfsError!usize {
    if (node.file_type != .regular) return vfs.VfsError.IsADirectory;

    const fd = getFileData(node) orelse return 0;
    if (offset >= fd.size) return 0;

    const available = fd.size - @as(usize, @intCast(offset));
    const to_read = @min(buffer.len, available);

    if (fd.data) |data| {
        const off: usize = @intCast(offset);
        @memcpy(buffer[0..to_read], data[off .. off + to_read]);
    }

    return to_read;
}

fn ramfsWrite(node: *vfs.VNode, data: []const u8, offset: u64) vfs.VfsError!usize {
    if (node.file_type != .regular) return vfs.VfsError.IsADirectory;

    var fd = getFileData(node) orelse {
        // Lazy allocation
        const new_fd = allocFileData() orelse return vfs.VfsError.NoSpace;
        node.fs_data = new_fd;
        return ramfsWrite(node, data, offset);
    };

    const off: usize = @intCast(offset);
    const end = off + data.len;

    if (!ensureCapacity(fd, end)) return vfs.VfsError.NoSpace;

    // Zero-fill gap if writing beyond current size
    if (fd.data) |buf| {
        if (off > fd.size) {
            @memset(buf[fd.size..off], 0);
        }
        @memcpy(buf[off..end], data);
    }

    if (end > fd.size) {
        fd.size = end;
        node.size = end;
    }

    node.is_dirty = true;
    return data.len;
}

fn ramfsTruncate(node: *vfs.VNode, size: u64) vfs.VfsError!void {
    if (getFileData(node)) |fd| {
        const new_size: usize = @intCast(size);
        if (new_size < fd.size) {
            fd.size = new_size;
            node.size = size;
        } else if (new_size > fd.size) {
            if (!ensureCapacity(fd, new_size)) return vfs.VfsError.NoSpace;
            if (fd.data) |buf| {
                @memset(buf[fd.size..new_size], 0);
            }
            fd.size = new_size;
            node.size = size;
        }
    }
}

fn ramfsLookup(dir: *vfs.VNode, name: []const u8) vfs.VfsError!*vfs.VNode {
    if (dir.file_type != .directory) return vfs.VfsError.NotADirectory;

    return dir.findChild(name) orelse return vfs.VfsError.NotFound;
}

fn ramfsCreate(dir: *vfs.VNode, name: []const u8, file_type: vfs.FileType, mode: u16) vfs.VfsError!*vfs.VNode {
    if (dir.file_type != .directory) return vfs.VfsError.NotADirectory;
    if (dir.findChild(name) != null) return vfs.VfsError.AlreadyExists;

    const node = vfs.allocVNode() orelse return vfs.VfsError.VnodeTableFull;
    node.file_type = file_type;
    node.mode = mode;
    node.inode = nextInode();
    node.setName(name);
    node.ops = &ramfs_ops;
    node.superblock = &ramfs_superblock;

    if (file_type == .regular) {
        if (allocFileData()) |fd| {
            node.fs_data = fd;
        }
    }

    dir.addChild(node);
    return node;
}

fn ramfsUnlink(dir: *vfs.VNode, name: []const u8) vfs.VfsError!void {
    const child = dir.findChild(name) orelse return vfs.VfsError.NotFound;
    if (child.file_type == .directory) return vfs.VfsError.IsADirectory;

    if (getFileData(child)) |fd| {
        freeFileData(fd);
    }

    _ = dir.removeChild(child);
    vfs.freeVNode(child);
}

fn ramfsMkdir(dir: *vfs.VNode, name: []const u8, mode: u16) vfs.VfsError!*vfs.VNode {
    if (dir.findChild(name) != null) return vfs.VfsError.AlreadyExists;

    const node = vfs.allocVNode() orelse return vfs.VfsError.VnodeTableFull;
    node.file_type = .directory;
    node.mode = mode;
    node.inode = nextInode();
    node.link_count = 2;
    node.setName(name);
    node.ops = &ramfs_ops;
    node.superblock = &ramfs_superblock;

    dir.addChild(node);
    return node;
}

fn ramfsRmdir(dir: *vfs.VNode, name: []const u8) vfs.VfsError!void {
    const child = dir.findChild(name) orelse return vfs.VfsError.NotFound;
    if (child.file_type != .directory) return vfs.VfsError.NotADirectory;
    if (child.children_head != null) return vfs.VfsError.NotEmpty;

    _ = dir.removeChild(child);
    vfs.freeVNode(child);
}

fn ramfsReaddir(dir: *vfs.VNode, buffer: []vfs.DirEntry, offset: *u64) vfs.VfsError!usize {
    _ = offset;
    var count: usize = 0;
    var child = dir.children_head;

    while (child) |c| {
        if (count >= buffer.len) break;
        buffer[count].inode = c.inode;
        buffer[count].file_type = c.file_type;
        const name = c.getName();
        const len = @min(name.len, vfs.MAX_FILENAME_LEN);
        @memcpy(buffer[count].name[0..len], name[0..len]);
        buffer[count].name_len = @truncate(len);
        count += 1;
        child = c.sibling_next;
    }

    return count;
}

fn ramfsGetattr(node: *vfs.VNode) vfs.VfsError!vfs.VNodeAttr {
    return vfs.VNodeAttr{
        .file_type = node.file_type,
        .mode = node.mode,
        .uid = node.uid,
        .gid = node.gid,
        .size = node.size,
        .link_count = node.link_count,
        .atime = node.atime,
        .mtime = node.mtime,
        .ctime = node.ctime,
    };
}

fn ramfsChmod(node: *vfs.VNode, mode: u16) vfs.VfsError!void {
    node.mode = mode;
}

fn ramfsChown(node: *vfs.VNode, uid: u32, gid: u32) vfs.VfsError!void {
    node.uid = uid;
    node.gid = gid;
}

fn ramfsSync(_: *vfs.VNode) vfs.VfsError!void {
    // Nothing to sync for ramfs — everything is in memory
}

// =============================================================================
// Helpers
// =============================================================================

fn getFileData(node: *vfs.VNode) ?*RamFileData {
    if (node.fs_data) |ptr| {
        return @ptrCast(@alignCast(ptr));
    }
    return null;
}

fn nextInode() u64 {
    next_inode += 1;
    return next_inode - 1;
}

/// Get the filesystem export for mounting
pub const filesystem = vfs.FileSystemType{
    .name = [_]u8{ 'r', 'a', 'm', 'f', 's' } ++ [_]u8{0} ** 27,
    .name_len = 5,
};
