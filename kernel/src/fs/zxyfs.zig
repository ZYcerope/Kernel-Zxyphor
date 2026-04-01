// =============================================================================
// Kernel Zxyphor - ZxyFS (Zxyphor File System)
// =============================================================================
// A custom disk-based file system for Kernel Zxyphor. Designed for simplicity,
// reliability, and reasonable performance.
//
// Disk layout:
//   Block 0:    Superblock (filesystem metadata)
//   Block 1:    Block group descriptor table
//   Block 2-N:  Inode bitmap
//   Block N+1:  Data block bitmap
//   Block N+2:  Inode table
//   Block N+3:  Data blocks
//
// Features:
//   - 4KB block size
//   - Extent-based allocation (up to 4 extents per inode for simplicity)
//   - Directory entries stored as linear lists within directory data blocks
//   - Journaling-ready design (journal area reserved)
//   - Support for files up to 4GB (via extents)
//   - Hard links and symbolic links
//   - POSIX permissions (rwxrwxrwx + setuid/setgid/sticky)
//
// This is similar in spirit to ext4 but much simpler.
// =============================================================================

const main = @import("../main.zig");
const vfs = main.vfs;

// =============================================================================
// On-disk structures
// =============================================================================

/// Magic number identifying a ZxyFS volume
pub const ZXYFS_MAGIC: u32 = 0x5A585946; // "ZXYF"

/// ZxyFS Superblock — stored in block 0
pub const ZxySuperblock = struct {
    magic: u32 = ZXYFS_MAGIC,
    version_major: u16 = 1,
    version_minor: u16 = 0,
    block_size: u32 = 4096,
    total_blocks: u64 = 0,
    free_blocks: u64 = 0,
    total_inodes: u64 = 0,
    free_inodes: u64 = 0,
    root_inode: u32 = 1,
    first_data_block: u32 = 0,
    blocks_per_group: u32 = 32768,
    inodes_per_group: u32 = 8192,
    inode_size: u16 = 256,
    state: u16 = FS_STATE_CLEAN,
    mount_count: u16 = 0,
    max_mount_count: u16 = 20,
    last_mount_time: u64 = 0,
    last_write_time: u64 = 0,
    last_check_time: u64 = 0,
    creator_os: u32 = 0, // Zxyphor = 0
    journal_inode: u32 = 0,
    volume_name: [64]u8 = [_]u8{0} ** 64,
    uuid: [16]u8 = [_]u8{0} ** 16,
    _reserved: [256]u8 = [_]u8{0} ** 256,
};

pub const FS_STATE_CLEAN: u16 = 0x0001;
pub const FS_STATE_ERROR: u16 = 0x0002;
pub const FS_STATE_ORPHAN: u16 = 0x0004;

/// On-disk inode (256 bytes)
pub const ZxyInode = struct {
    mode: u16 = 0, // File type + permissions
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    atime: u64 = 0,
    mtime: u64 = 0,
    ctime: u64 = 0,
    crtime: u64 = 0,
    link_count: u16 = 0,
    blocks: u64 = 0, // Number of 512-byte blocks
    flags: u32 = 0,

    // Extent-based storage (up to 4 extents)
    extents: [4]Extent = [_]Extent{.{}} ** 4,
    extent_count: u8 = 0,

    // For symbolic links (short links stored inline)
    inline_data: [60]u8 = [_]u8{0} ** 60,

    _reserved: [32]u8 = [_]u8{0} ** 32,

    /// Get the file type from mode
    pub fn fileType(self: *const ZxyInode) vfs.FileType {
        const ft = (self.mode >> 12) & 0xF;
        return switch (ft) {
            0x1 => .pipe,
            0x2 => .char_device,
            0x4 => .directory,
            0x6 => .block_device,
            0x8 => .regular,
            0xA => .symlink,
            0xC => .socket,
            else => .unknown,
        };
    }
};

// Inode flag constants
pub const INODE_SECRM: u32 = 0x00000001; // Secure deletion
pub const INODE_UNRM: u32 = 0x00000002; // Undelete
pub const INODE_COMPR: u32 = 0x00000004; // Compressed
pub const INODE_SYNC: u32 = 0x00000008; // Synchronous updates
pub const INODE_IMMUTABLE: u32 = 0x00000010;
pub const INODE_APPEND: u32 = 0x00000020; // Append only
pub const INODE_NODUMP: u32 = 0x00000040; // Don't dump
pub const INODE_NOATIME: u32 = 0x00000080; // Don't update atime

/// Extent — describes a contiguous range of blocks
pub const Extent = struct {
    logical_block: u32 = 0, // Starting logical block number
    physical_block: u64 = 0, // Starting physical block number
    length: u32 = 0, // Number of blocks in this extent

    pub fn isValid(self: *const Extent) bool {
        return self.length > 0;
    }

    pub fn contains(self: *const Extent, logical: u32) bool {
        return logical >= self.logical_block and
            logical < self.logical_block + self.length;
    }

    pub fn physicalFor(self: *const Extent, logical: u32) u64 {
        return self.physical_block + (logical - self.logical_block);
    }
};

/// Directory entry (on-disk)
pub const ZxyDirEntry = struct {
    inode: u32 = 0,
    rec_len: u16 = 0, // Total size of this entry (for fast skipping)
    name_len: u8 = 0,
    file_type: u8 = 0,
    name: [255]u8 = [_]u8{0} ** 255,

    pub fn getName(self: *const ZxyDirEntry) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn actualSize(self: *const ZxyDirEntry) usize {
        // 8 bytes header + name + alignment to 4 bytes
        return ((8 + @as(usize, self.name_len) + 3) / 4) * 4;
    }
};

// =============================================================================
// In-memory state for a mounted ZxyFS volume
// =============================================================================
pub const ZxyFsState = struct {
    superblock: ZxySuperblock = .{},
    device: ?*vfs.VNode = null,
    vfs_superblock: ?*vfs.Superblock = null,
    is_mounted: bool = false,
    is_dirty: bool = false,

    // Bitmaps (loaded into RAM for fast access)
    inode_bitmap: ?[*]u8 = null,
    inode_bitmap_blocks: u32 = 0,
    block_bitmap: ?[*]u8 = null,
    block_bitmap_blocks: u32 = 0,
};

var fs_state: ZxyFsState = .{};

// =============================================================================
// VNode operations for ZxyFS
// =============================================================================
pub const zxyfs_ops = vfs.VNodeOps{
    .read = zxyfsRead,
    .write = zxyfsWrite,
    .truncate = zxyfsTruncate,
    .lookup = zxyfsLookup,
    .create = zxyfsCreate,
    .mkdir = zxyfsMkdir,
    .readdir = zxyfsReaddir,
    .getattr = zxyfsGetattr,
    .chmod = zxyfsChmod,
    .chown = zxyfsChown,
};

// =============================================================================
// File operations
// =============================================================================

fn zxyfsRead(node: *vfs.VNode, buffer: []u8, offset: u64) vfs.VfsError!usize {
    if (node.file_type == .directory) return vfs.VfsError.IsADirectory;
    if (offset >= node.size) return 0;

    const inode = getInode(node) orelse return vfs.VfsError.IoError;
    const available = node.size - offset;
    const to_read = @min(buffer.len, @as(usize, @intCast(available)));

    var bytes_read: usize = 0;
    var buf_offset: usize = 0;
    var file_offset = offset;

    while (bytes_read < to_read) {
        const block_num: u32 = @intCast(file_offset / vfs.BLOCK_SIZE);
        const block_offset: usize = @intCast(file_offset % vfs.BLOCK_SIZE);

        // Find the physical block via extents
        const phys_block = resolveExtent(inode, block_num) orelse break;

        // Read from device
        const chunk = @min(vfs.BLOCK_SIZE - block_offset, to_read - bytes_read);
        if (readBlock(phys_block, block_offset, buffer[buf_offset .. buf_offset + chunk])) {
            bytes_read += chunk;
            buf_offset += chunk;
            file_offset += chunk;
        } else {
            break;
        }
    }

    return bytes_read;
}

fn zxyfsWrite(node: *vfs.VNode, data: []const u8, offset: u64) vfs.VfsError!usize {
    if (node.file_type == .directory) return vfs.VfsError.IsADirectory;

    var inode = getInodeMut(node) orelse return vfs.VfsError.IoError;
    var bytes_written: usize = 0;
    var buf_offset: usize = 0;
    var file_offset = offset;

    while (bytes_written < data.len) {
        const block_num: u32 = @intCast(file_offset / vfs.BLOCK_SIZE);
        const block_offset: usize = @intCast(file_offset % vfs.BLOCK_SIZE);

        // Allocate block if needed
        var phys_block = resolveExtent(inode, block_num);
        if (phys_block == null) {
            phys_block = allocateBlock(inode, block_num);
            if (phys_block == null) return vfs.VfsError.NoSpace;
        }

        const chunk = @min(vfs.BLOCK_SIZE - block_offset, data.len - bytes_written);
        if (writeBlock(phys_block.?, block_offset, data[buf_offset .. buf_offset + chunk])) {
            bytes_written += chunk;
            buf_offset += chunk;
            file_offset += chunk;
        } else {
            break;
        }
    }

    // Update file size if we extended it
    if (file_offset > node.size) {
        node.size = file_offset;
        inode.size = file_offset;
    }

    fs_state.is_dirty = true;
    return bytes_written;
}

fn zxyfsTruncate(node: *vfs.VNode, size: u64) vfs.VfsError!void {
    var inode = getInodeMut(node) orelse return vfs.VfsError.IoError;
    inode.size = size;
    node.size = size;
    // TODO: Free blocks beyond the new size
    fs_state.is_dirty = true;
}

fn zxyfsLookup(dir: *vfs.VNode, name: []const u8) vfs.VfsError!*vfs.VNode {
    return dir.findChild(name) orelse return vfs.VfsError.NotFound;
}

fn zxyfsCreate(dir: *vfs.VNode, name: []const u8, file_type: vfs.FileType, mode: u16) vfs.VfsError!*vfs.VNode {
    if (dir.findChild(name) != null) return vfs.VfsError.AlreadyExists;

    const node = vfs.allocVNode() orelse return vfs.VfsError.VnodeTableFull;
    node.file_type = file_type;
    node.mode = mode;
    node.setName(name);
    node.ops = &zxyfs_ops;
    node.superblock = fs_state.vfs_superblock;

    dir.addChild(node);
    fs_state.is_dirty = true;
    return node;
}

fn zxyfsMkdir(dir: *vfs.VNode, name: []const u8, mode: u16) vfs.VfsError!*vfs.VNode {
    if (dir.findChild(name) != null) return vfs.VfsError.AlreadyExists;

    const node = vfs.allocVNode() orelse return vfs.VfsError.VnodeTableFull;
    node.file_type = .directory;
    node.mode = mode;
    node.link_count = 2;
    node.setName(name);
    node.ops = &zxyfs_ops;
    node.superblock = fs_state.vfs_superblock;

    dir.addChild(node);
    fs_state.is_dirty = true;
    return node;
}

fn zxyfsReaddir(dir: *vfs.VNode, buffer: []vfs.DirEntry, offset: *u64) vfs.VfsError!usize {
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

fn zxyfsGetattr(node: *vfs.VNode) vfs.VfsError!vfs.VNodeAttr {
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

fn zxyfsChmod(node: *vfs.VNode, mode: u16) vfs.VfsError!void {
    node.mode = mode;
    fs_state.is_dirty = true;
}

fn zxyfsChown(node: *vfs.VNode, uid: u32, gid: u32) vfs.VfsError!void {
    node.uid = uid;
    node.gid = gid;
    fs_state.is_dirty = true;
}

// =============================================================================
// Extent resolution and block allocation
// =============================================================================

fn resolveExtent(inode: *const ZxyInode, logical_block: u32) ?u64 {
    for (&inode.extents) |*ext| {
        if (ext.isValid() and ext.contains(logical_block)) {
            return ext.physicalFor(logical_block);
        }
    }
    return null;
}

fn allocateBlock(inode: *ZxyInode, logical_block: u32) ?u64 {
    // Find a free physical block
    const phys_block = findFreeBlock() orelse return null;
    markBlockUsed(phys_block);

    // Try to extend an existing extent
    for (&inode.extents) |*ext| {
        if (ext.isValid()) {
            // Check if this block is contiguous with an existing extent
            if (logical_block == ext.logical_block + ext.length and
                phys_block == ext.physical_block + ext.length)
            {
                ext.length += 1;
                return phys_block;
            }
        }
    }

    // Start a new extent
    if (inode.extent_count < 4) {
        const idx = inode.extent_count;
        inode.extents[idx] = Extent{
            .logical_block = logical_block,
            .physical_block = phys_block,
            .length = 1,
        };
        inode.extent_count += 1;
        return phys_block;
    }

    return null; // No more extent slots
}

fn findFreeBlock() ?u64 {
    const bitmap = fs_state.block_bitmap orelse return null;
    const total_blocks: u64 = fs_state.superblock.total_blocks;

    var block: u64 = fs_state.superblock.first_data_block;
    while (block < total_blocks) : (block += 1) {
        const byte_idx = block / 8;
        const bit_idx: u3 = @truncate(block % 8);
        if (bitmap[byte_idx] & (@as(u8, 1) << bit_idx) == 0) {
            return block;
        }
    }
    return null;
}

fn markBlockUsed(block: u64) void {
    const bitmap = fs_state.block_bitmap orelse return;
    const byte_idx = block / 8;
    const bit_idx: u3 = @truncate(block % 8);
    bitmap[byte_idx] |= @as(u8, 1) << bit_idx;
    fs_state.superblock.free_blocks -= 1;
}

fn markBlockFree(block: u64) void {
    const bitmap = fs_state.block_bitmap orelse return;
    const byte_idx = block / 8;
    const bit_idx: u3 = @truncate(block % 8);
    bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
    fs_state.superblock.free_blocks += 1;
}

// =============================================================================
// Block I/O (delegates to device driver)
// =============================================================================

fn readBlock(block_num: u64, offset: usize, buffer: []u8) bool {
    // Would read from the underlying block device via ATA driver
    _ = block_num;
    _ = offset;
    @memset(buffer, 0);
    return true;
}

fn writeBlock(block_num: u64, offset: usize, data: []const u8) bool {
    // Would write to the underlying block device via ATA driver
    _ = block_num;
    _ = offset;
    _ = data;
    return true;
}

// =============================================================================
// Inode access helpers
// =============================================================================

// For simplicity, we use a small in-memory inode cache
const MAX_CACHED_INODES: usize = 1024;
var inode_cache: [MAX_CACHED_INODES]ZxyInode = undefined;
var inode_cache_valid: [MAX_CACHED_INODES]bool = [_]bool{false} ** MAX_CACHED_INODES;

fn getInode(node: *const vfs.VNode) ?*const ZxyInode {
    const idx: usize = @intCast(node.inode);
    if (idx >= MAX_CACHED_INODES) return null;
    if (!inode_cache_valid[idx]) return null;
    return &inode_cache[idx];
}

fn getInodeMut(node: *vfs.VNode) ?*ZxyInode {
    const idx: usize = @intCast(node.inode);
    if (idx >= MAX_CACHED_INODES) return null;
    if (!inode_cache_valid[idx]) return null;
    return &inode_cache[idx];
}

// =============================================================================
// Format a volume with ZxyFS
// =============================================================================
pub fn format(device: *vfs.VNode, volume_name: []const u8) bool {
    _ = device;

    // Initialize superblock
    fs_state.superblock = ZxySuperblock{};
    const name_len = @min(volume_name.len, 64);
    @memcpy(fs_state.superblock.volume_name[0..name_len], volume_name[0..name_len]);

    // In a real implementation, we would:
    // 1. Calculate block/inode counts based on device size
    // 2. Write superblock to block 0
    // 3. Initialize inode bitmap
    // 4. Initialize block bitmap
    // 5. Create root directory inode
    // 6. Write all structures to disk

    main.klog(.info, "zxyfs: formatted volume '{s}'", .{volume_name});
    return true;
}

/// Get filesystem statistics
pub fn getStats() struct { total_blocks: u64, free_blocks: u64, total_inodes: u64, free_inodes: u64 } {
    return .{
        .total_blocks = fs_state.superblock.total_blocks,
        .free_blocks = fs_state.superblock.free_blocks,
        .total_inodes = fs_state.superblock.total_inodes,
        .free_inodes = fs_state.superblock.free_inodes,
    };
}
