// =============================================================================
// Kernel Zxyphor — ext4 Filesystem Reader (Rust)
// =============================================================================
// Read-only ext4 filesystem implementation for mounting Linux partitions.
// Supports:
//   - ext4 superblock parsing
//   - Block group descriptors (32-bit and 64-bit)
//   - Inode reading (128 and 256-byte inodes)
//   - Extent tree traversal (ext4 primary addressing)
//   - Directory entry parsing (linear and hash tree)
//   - Symbolic link resolution
//   - File data block reading
//
// References: ext4 wiki, Linux kernel fs/ext4/
// =============================================================================

// =============================================================================
// On-Disk Structures
// =============================================================================

/// Magic number for ext2/ext3/ext4
const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock is always at byte offset 1024 from the start of the partition
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_SIZE: usize = 1024;

// Feature flags (INCOMPAT)
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_FLEX_BG: u32 = 0x0200;

// Inode flags
const EXT4_EXTENTS_FL: u32 = 0x00080000;

// File types in directory entries
const FT_UNKNOWN: u8 = 0;
const FT_REG_FILE: u8 = 1;
const FT_DIR: u8 = 2;
const FT_CHRDEV: u8 = 3;
const FT_BLKDEV: u8 = 4;
const FT_FIFO: u8 = 5;
const FT_SOCK: u8 = 6;
const FT_SYMLINK: u8 = 7;

/// ext4 Superblock (selected fields)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Superblock {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // EXT4_DYNAMIC_REV fields
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    // ext3 journaling fields
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    pub s_jnl_blocks: [u32; 17],
    // 64-bit support
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_count_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
}

/// Block Group Descriptor (32-byte version)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4GroupDesc {
    pub bg_block_bitmap_lo: u32,
    pub bg_inode_bitmap_lo: u32,
    pub bg_inode_table_lo: u32,
    pub bg_free_blocks_count_lo: u16,
    pub bg_free_inodes_count_lo: u16,
    pub bg_used_dirs_count_lo: u16,
    pub bg_flags: u16,
    pub bg_exclude_bitmap_lo: u32,
    pub bg_block_bitmap_csum_lo: u16,
    pub bg_inode_bitmap_csum_lo: u16,
    pub bg_itable_unused_lo: u16,
    pub bg_checksum: u16,
    // 64-bit extension (if s_desc_size >= 64)
    pub bg_block_bitmap_hi: u32,
    pub bg_inode_bitmap_hi: u32,
    pub bg_inode_table_hi: u32,
    pub bg_free_blocks_count_hi: u16,
    pub bg_free_inodes_count_hi: u16,
    pub bg_used_dirs_count_hi: u16,
    pub bg_itable_unused_hi: u16,
    pub bg_exclude_bitmap_hi: u32,
    pub bg_block_bitmap_csum_hi: u16,
    pub bg_inode_bitmap_csum_hi: u16,
    pub bg_reserved: u32,
}

/// Inode structure (ext4, 256 bytes default)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub i_osd1: u32,
    pub i_block: [u32; 15], // 60 bytes — in ext4 this stores extent tree header + extent entries
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub i_obso_faddr: u32,
    pub i_osd2: [u8; 12],
    pub i_extra_isize: u16,
    pub i_checksum_hi: u16,
    pub i_ctime_extra: u32,
    pub i_mtime_extra: u32,
    pub i_atime_extra: u32,
    pub i_crtime: u32,
    pub i_crtime_extra: u32,
    pub i_version_hi: u32,
    pub i_projid: u32,
}

/// Extent tree header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentHeader {
    pub eh_magic: u16,     // 0xF30A
    pub eh_entries: u16,
    pub eh_max: u16,
    pub eh_depth: u16,
    pub eh_generation: u32,
}

/// Extent tree leaf entry (depth == 0)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4Extent {
    pub ee_block: u32,       // First logical block
    pub ee_len: u16,         // Number of blocks (<=32768)
    pub ee_start_hi: u16,    // High 16 bits of physical block
    pub ee_start_lo: u32,    // Low 32 bits of physical block
}

/// Extent tree index entry (depth > 0)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32,       // Covers logical block numbers from this value
    pub ei_leaf_lo: u32,     // Low 32 bits of physical block of next level
    pub ei_leaf_hi: u16,     // High 16 bits
    pub ei_unused: u16,
}

/// Directory entry (variable length)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ext4DirEntry2 {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    // name follows (name_len bytes)
}

const EXTENT_MAGIC: u16 = 0xF30A;

// =============================================================================
// Filesystem State
// =============================================================================

/// Callback type for reading raw blocks from the underlying block device
pub type BlockReadFn = extern "C" fn(device_id: u32, block: u64, count: u32, buffer: *mut u8) -> i32;

/// ext4 filesystem context
pub struct Ext4Fs {
    device_id: u32,
    block_size: u32,
    inodes_per_group: u32,
    inode_size: u16,
    blocks_per_group: u32,
    total_blocks: u64,
    total_inodes: u32,
    first_data_block: u32,
    desc_size: u16,
    is_64bit: bool,
    has_extents: bool,
    read_block: BlockReadFn,
    // Cache: superblock copy
    superblock: Ext4Superblock,
}

const MAX_PATH_DEPTH: usize = 32;

impl Ext4Fs {
    /// Mount an ext4 filesystem from a block device
    pub fn mount(device_id: u32, read_fn: BlockReadFn) -> Result<Self, Ext4Error> {
        // Read superblock
        let mut sb_buf = [0u8; SUPERBLOCK_SIZE];
        let result = read_fn(device_id, 1024 / 512, 2, sb_buf.as_mut_ptr());
        if result != 0 {
            return Err(Ext4Error::IoError);
        }

        let sb = unsafe { *(sb_buf.as_ptr() as *const Ext4Superblock) };

        // Validate magic
        if sb.s_magic != EXT4_SUPER_MAGIC {
            return Err(Ext4Error::BadMagic);
        }

        let block_size = 1024u32 << sb.s_log_block_size;
        let is_64bit = (sb.s_feature_incompat & INCOMPAT_64BIT) != 0;
        let has_extents = (sb.s_feature_incompat & INCOMPAT_EXTENTS) != 0;

        let total_blocks = if is_64bit {
            (sb.s_blocks_count_lo as u64) | ((sb.s_blocks_count_hi as u64) << 32)
        } else {
            sb.s_blocks_count_lo as u64
        };

        let desc_size = if is_64bit && sb.s_desc_size >= 64 {
            sb.s_desc_size
        } else {
            32
        };

        Ok(Ext4Fs {
            device_id,
            block_size,
            inodes_per_group: sb.s_inodes_per_group,
            inode_size: if sb.s_rev_level >= 1 { sb.s_inode_size } else { 128 },
            blocks_per_group: sb.s_blocks_per_group,
            total_blocks,
            total_inodes: sb.s_inodes_count,
            first_data_block: sb.s_first_data_block,
            desc_size,
            is_64bit,
            has_extents,
            read_block: read_fn,
            superblock: sb,
        })
    }

    /// Read a block from the device
    fn read_block_data(&self, block: u64, buf: &mut [u8]) -> Result<(), Ext4Error> {
        let sectors_per_block = self.block_size / 512;
        let sector = block * sectors_per_block as u64;
        let result = (self.read_block)(self.device_id, sector, sectors_per_block, buf.as_mut_ptr());
        if result != 0 {
            Err(Ext4Error::IoError)
        } else {
            Ok(())
        }
    }

    /// Read the block group descriptor for a given group
    fn read_group_desc(&self, group: u32) -> Result<Ext4GroupDesc, Ext4Error> {
        let desc_block = self.first_data_block as u64 + 1
            + (group as u64 * self.desc_size as u64) / self.block_size as u64;
        let desc_offset = (group as usize * self.desc_size as usize) % self.block_size as usize;

        let mut block_buf = [0u8; 4096]; // Max block size
        self.read_block_data(desc_block, &mut block_buf[..self.block_size as usize])?;

        let gd = unsafe {
            *(block_buf[desc_offset..].as_ptr() as *const Ext4GroupDesc)
        };

        Ok(gd)
    }

    /// Read an inode by its number (1-based)
    pub fn read_inode(&self, ino: u32) -> Result<Ext4Inode, Ext4Error> {
        if ino == 0 || ino > self.total_inodes {
            return Err(Ext4Error::InvalidInode);
        }

        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;

        let gd = self.read_group_desc(group)?;

        let inode_table = if self.is_64bit {
            (gd.bg_inode_table_lo as u64) | ((gd.bg_inode_table_hi as u64) << 32)
        } else {
            gd.bg_inode_table_lo as u64
        };

        let inode_offset = index as u64 * self.inode_size as u64;
        let block = inode_table + inode_offset / self.block_size as u64;
        let block_offset = (inode_offset % self.block_size as u64) as usize;

        let mut block_buf = [0u8; 4096];
        self.read_block_data(block, &mut block_buf[..self.block_size as usize])?;

        let inode = unsafe {
            *(block_buf[block_offset..].as_ptr() as *const Ext4Inode)
        };

        Ok(inode)
    }

    /// Get the file size from an inode
    pub fn inode_size(inode: &Ext4Inode) -> u64 {
        (inode.i_size_lo as u64) | ((inode.i_size_high as u64) << 32)
    }

    /// Resolve a logical block number to a physical block using the extent tree
    pub fn resolve_extent(
        &self,
        inode: &Ext4Inode,
        logical_block: u32,
    ) -> Result<u64, Ext4Error> {
        if (inode.i_flags & EXT4_EXTENTS_FL) == 0 {
            return Err(Ext4Error::NotExtentBased);
        }

        // The extent tree root is stored in i_block[0..14]
        let extent_data = unsafe {
            core::slice::from_raw_parts(
                inode.i_block.as_ptr() as *const u8,
                60,
            )
        };

        self.walk_extent_tree(extent_data, logical_block)
    }

    /// Walk the extent tree to find a physical block
    fn walk_extent_tree(
        &self,
        node_data: &[u8],
        logical_block: u32,
    ) -> Result<u64, Ext4Error> {
        let header = unsafe { *(node_data.as_ptr() as *const Ext4ExtentHeader) };

        if header.eh_magic != EXTENT_MAGIC {
            return Err(Ext4Error::BadExtentMagic);
        }

        if header.eh_depth == 0 {
            // Leaf node: search extents
            let extents = unsafe {
                core::slice::from_raw_parts(
                    node_data[12..].as_ptr() as *const Ext4Extent,
                    header.eh_entries as usize,
                )
            };

            for ext in extents {
                let start = ext.ee_block;
                let len = ext.ee_len as u32 & 0x7FFF; // Mask initialized flag
                if logical_block >= start && logical_block < start + len {
                    let offset = logical_block - start;
                    let phys_start = (ext.ee_start_lo as u64) | ((ext.ee_start_hi as u64) << 32);
                    return Ok(phys_start + offset as u64);
                }
            }

            Err(Ext4Error::BlockNotMapped)
        } else {
            // Internal node: find the right child
            let indices = unsafe {
                core::slice::from_raw_parts(
                    node_data[12..].as_ptr() as *const Ext4ExtentIdx,
                    header.eh_entries as usize,
                )
            };

            let mut child_block = 0u64;
            for idx in indices {
                if logical_block >= idx.ei_block {
                    child_block = (idx.ei_leaf_lo as u64) | ((idx.ei_leaf_hi as u64) << 32);
                } else {
                    break;
                }
            }

            if child_block == 0 {
                return Err(Ext4Error::BlockNotMapped);
            }

            // Read the child node block
            let mut child_buf = [0u8; 4096];
            self.read_block_data(child_block, &mut child_buf[..self.block_size as usize])?;
            self.walk_extent_tree(&child_buf[..self.block_size as usize], logical_block)
        }
    }

    /// Read file data starting at a byte offset
    pub fn read_file(
        &self,
        inode: &Ext4Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Ext4Error> {
        let file_size = Self::inode_size(inode);
        if offset >= file_size {
            return Ok(0);
        }

        let available = (file_size - offset) as usize;
        let to_read = buf.len().min(available);
        let mut bytes_read = 0;

        while bytes_read < to_read {
            let current_offset = offset + bytes_read as u64;
            let logical_block = (current_offset / self.block_size as u64) as u32;
            let block_offset = (current_offset % self.block_size as u64) as usize;

            let phys_block = self.resolve_extent(inode, logical_block)?;

            let mut block_buf = [0u8; 4096];
            self.read_block_data(phys_block, &mut block_buf[..self.block_size as usize])?;

            let chunk = (self.block_size as usize - block_offset).min(to_read - bytes_read);
            buf[bytes_read..bytes_read + chunk]
                .copy_from_slice(&block_buf[block_offset..block_offset + chunk]);
            bytes_read += chunk;
        }

        Ok(bytes_read)
    }

    /// List directory entries
    pub fn read_dir(
        &self,
        dir_inode: &Ext4Inode,
        callback: &mut dyn FnMut(&Ext4DirEntry2, &[u8]) -> bool,
    ) -> Result<(), Ext4Error> {
        let dir_size = Self::inode_size(dir_inode);
        let mut offset = 0u64;

        while offset < dir_size {
            let logical_block = (offset / self.block_size as u64) as u32;
            let phys_block = self.resolve_extent(dir_inode, logical_block)?;

            let mut block_buf = [0u8; 4096];
            self.read_block_data(phys_block, &mut block_buf[..self.block_size as usize])?;

            let mut pos = 0usize;
            while pos < self.block_size as usize {
                if pos + 8 > self.block_size as usize {
                    break;
                }

                let entry = unsafe {
                    *(block_buf[pos..].as_ptr() as *const Ext4DirEntry2)
                };

                if entry.rec_len == 0 {
                    break;
                }

                if entry.inode != 0 && entry.name_len > 0 {
                    let name_start = pos + 8;
                    let name_end = name_start + entry.name_len as usize;
                    if name_end <= self.block_size as usize {
                        let name = &block_buf[name_start..name_end];
                        if !callback(&entry, name) {
                            return Ok(());
                        }
                    }
                }

                pos += entry.rec_len as usize;
            }

            offset += self.block_size as u64;
        }

        Ok(())
    }

    /// Lookup a file/directory by name inside a directory
    pub fn lookup(
        &self,
        dir_ino: u32,
        name: &[u8],
    ) -> Result<(u32, u8), Ext4Error> {
        let dir_inode = self.read_inode(dir_ino)?;
        let mut found: Option<(u32, u8)> = None;

        self.read_dir(&dir_inode, &mut |entry, entry_name| {
            if entry_name.len() == name.len() {
                let mut equal = true;
                for i in 0..name.len() {
                    if entry_name[i] != name[i] {
                        equal = false;
                        break;
                    }
                }
                if equal {
                    found = Some((entry.inode, entry.file_type));
                    return false; // Stop iteration
                }
            }
            true
        })?;

        found.ok_or(Ext4Error::NotFound)
    }

    /// Resolve a full path (e.g., "/etc/fstab") to an inode number
    pub fn resolve_path(&self, path: &[u8]) -> Result<u32, Ext4Error> {
        if path.is_empty() {
            return Err(Ext4Error::NotFound);
        }

        let mut current_ino: u32 = 2; // Root inode
        let mut start = 0;

        // Skip leading '/'
        while start < path.len() && path[start] == b'/' {
            start += 1;
        }

        if start >= path.len() {
            return Ok(2); // Root directory
        }

        let mut depth = 0;

        while start < path.len() && depth < MAX_PATH_DEPTH {
            // Find end of component
            let mut end = start;
            while end < path.len() && path[end] != b'/' {
                end += 1;
            }

            if end > start {
                let component = &path[start..end];
                let (ino, _ftype) = self.lookup(current_ino, component)?;
                current_ino = ino;
                depth += 1;
            }

            start = end + 1;
        }

        if depth >= MAX_PATH_DEPTH {
            return Err(Ext4Error::TooDeep);
        }

        Ok(current_ino)
    }

    /// Get filesystem information
    pub fn get_info(&self) -> Ext4Info {
        Ext4Info {
            block_size: self.block_size,
            total_blocks: self.total_blocks,
            free_blocks: (self.superblock.s_free_blocks_count_lo as u64)
                | ((self.superblock.s_free_blocks_count_hi as u64) << 32),
            total_inodes: self.total_inodes,
            free_inodes: self.superblock.s_free_inodes_count,
            blocks_per_group: self.blocks_per_group,
            inodes_per_group: self.inodes_per_group,
            has_extents: self.has_extents,
            is_64bit: self.is_64bit,
        }
    }
}

/// Filesystem summary info
pub struct Ext4Info {
    pub block_size: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u32,
    pub free_inodes: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub has_extents: bool,
    pub is_64bit: bool,
}

/// ext4 error types
#[derive(Debug, Clone, Copy)]
pub enum Ext4Error {
    IoError,
    BadMagic,
    InvalidInode,
    NotExtentBased,
    BadExtentMagic,
    BlockNotMapped,
    NotFound,
    TooDeep,
    NotADirectory,
    BufferTooSmall,
}

// =============================================================================
// C FFI for Zig kernel
// =============================================================================

/// Opaque ext4 context handle
static mut EXT4_INSTANCES: [Option<Ext4Fs>; 4] = [None, None, None, None];

/// Mount an ext4 filesystem; returns handle (0-3) or -1 on error
#[no_mangle]
pub extern "C" fn ext4_mount(device_id: u32, read_fn: BlockReadFn) -> i32 {
    let fs = match Ext4Fs::mount(device_id, read_fn) {
        Ok(fs) => fs,
        Err(_) => return -1,
    };

    unsafe {
        for i in 0..4 {
            if EXT4_INSTANCES[i].is_none() {
                EXT4_INSTANCES[i] = Some(fs);
                return i as i32;
            }
        }
    }
    -1 // No free slots
}

/// Unmount an ext4 filesystem
#[no_mangle]
pub extern "C" fn ext4_unmount(handle: i32) {
    if handle >= 0 && (handle as usize) < 4 {
        unsafe {
            EXT4_INSTANCES[handle as usize] = None;
        }
    }
}

/// Resolve a path to an inode number (-1 on error)
#[no_mangle]
pub extern "C" fn ext4_resolve_path(handle: i32, path: *const u8, path_len: usize) -> i64 {
    if handle < 0 || (handle as usize) >= 4 || path.is_null() {
        return -1;
    }
    let path_bytes = unsafe { core::slice::from_raw_parts(path, path_len) };
    unsafe {
        match &EXT4_INSTANCES[handle as usize] {
            Some(fs) => match fs.resolve_path(path_bytes) {
                Ok(ino) => ino as i64,
                Err(_) => -1,
            },
            None => -1,
        }
    }
}

/// Read file data by inode number; returns bytes read or -1
#[no_mangle]
pub extern "C" fn ext4_read_file(
    handle: i32,
    ino: u32,
    offset: u64,
    buf: *mut u8,
    buf_len: usize,
) -> i64 {
    if handle < 0 || (handle as usize) >= 4 || buf.is_null() {
        return -1;
    }
    unsafe {
        match &EXT4_INSTANCES[handle as usize] {
            Some(fs) => {
                let inode = match fs.read_inode(ino) {
                    Ok(i) => i,
                    Err(_) => return -1,
                };
                let out = core::slice::from_raw_parts_mut(buf, buf_len);
                match fs.read_file(&inode, offset, out) {
                    Ok(n) => n as i64,
                    Err(_) => -1,
                }
            }
            None => -1,
        }
    }
}
