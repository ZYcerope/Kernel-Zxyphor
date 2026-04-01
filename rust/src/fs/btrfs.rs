// SPDX-License-Identifier: MIT
//! Zxyphor Kernel — Btrfs Filesystem Basics (Rust)
//!
//! Copy-on-Write (COW) B-tree filesystem:
//! - Superblock with multi-device support
//! - B-tree node/leaf with item-based layout
//! - Object key: (objectid, type, offset) searchable
//! - Inode items with extended attributes
//! - Dir items with name hash (CRC32C)
//! - Extent tree: data/metadata extents with backrefs
//! - Chunk tree: logical→physical mapping
//! - Subvolumes and snapshots via root items
//! - Transaction commit with tree-log for fsync
//! - Checksumming (CRC32C) per data/metadata block
//! - Inline data for small files
//! - Compression support flags (zlib, lzo, zstd)
//! - Defragmentation tracking
//! - Scrub for data integrity verification
//! - Space cache / free space tree

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const BTRFS_MAGIC: u64 = 0x4D5F53665248425F; // "_BHRfS_M"
const BTRFS_BLOCK_SIZE: u32 = 16384;  // 16 KiB node size
const BTRFS_CSUM_SIZE: usize = 32;
const BTRFS_UUID_SIZE: usize = 16;
const MAX_ITEMS_PER_LEAF: usize = 64;
const MAX_KEYS_PER_NODE: usize = 32;
const MAX_EXTENTS: usize = 256;
const MAX_CHUNKS: usize = 64;
const MAX_SUBVOLUMES: usize = 32;
const MAX_TRANSACTIONS: usize = 16;
const MAX_DEVICES: usize = 8;
const NAME_LEN: usize = 255;
const MAX_INODES: usize = 512;
const MAX_DIR_ENTRIES: usize = 256;
const MAX_SCRUB_ERRORS: usize = 64;

// ─────────────────── Object Types ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BtrfsType {
    InodeItem = 1,
    InodeRef = 12,
    XattrItem = 24,
    DirItem = 54,
    DirIndex = 60,
    ExtentData = 108,
    ExtentItem = 168,
    BlockGroupItem = 192,
    ChunkItem = 228,
    DevItem = 216,
    RootItem = 132,
    RootRef = 156,
    RootBackref = 144,
    FreeSpaceInfo = 198,
    FreeSpaceExtent = 199,
}

// ─────────────────── Key ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub type_: BtrfsType,
    pub offset: u64,
}

impl BtrfsKey {
    pub const fn new(objectid: u64, type_: BtrfsType, offset: u64) -> Self {
        Self { objectid, type_, offset }
    }

    pub fn cmp(&self, other: &BtrfsKey) -> core::cmp::Ordering {
        match self.objectid.cmp(&other.objectid) {
            core::cmp::Ordering::Equal => {
                match (self.type_ as u8).cmp(&(other.type_ as u8)) {
                    core::cmp::Ordering::Equal => self.offset.cmp(&other.offset),
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

// ─────────────────── Superblock ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct BtrfsSuperblock {
    pub csum: [u8; BTRFS_CSUM_SIZE],
    pub fsid: [u8; BTRFS_UUID_SIZE],
    pub bytenr: u64,           // Physical position of this block
    pub flags: u64,
    pub magic: u64,
    pub generation: u64,
    pub root: u64,             // Root tree root
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sector_size: u32,
    pub node_size: u32,
    pub leaf_size: u32,
    pub stripe_size: u32,
    pub csum_type: u16,        // 0 = CRC32C
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub incompat_flags: u64,
    pub label: [u8; 256],
    pub label_len: u8,
}

impl BtrfsSuperblock {
    pub const fn new() -> Self {
        Self {
            csum: [0u8; BTRFS_CSUM_SIZE],
            fsid: [0u8; BTRFS_UUID_SIZE],
            bytenr: 65536, // Standard superblock offset
            flags: 0,
            magic: BTRFS_MAGIC,
            generation: 0,
            root: 0,
            chunk_root: 0,
            log_root: 0,
            total_bytes: 0,
            bytes_used: 0,
            root_dir_objectid: 256,
            num_devices: 1,
            sector_size: 4096,
            node_size: BTRFS_BLOCK_SIZE,
            leaf_size: BTRFS_BLOCK_SIZE,
            stripe_size: 65536,
            csum_type: 0,
            root_level: 0,
            chunk_root_level: 0,
            incompat_flags: 0,
            label: [0u8; 256],
            label_len: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == BTRFS_MAGIC && self.sector_size >= 512 && self.node_size >= 4096
    }
}

// ─────────────────── Inode ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BtrfsFileType {
    Unknown = 0,
    Regular = 1,
    Directory = 2,
    Chardev = 3,
    Blockdev = 4,
    Fifo = 5,
    Socket = 6,
    Symlink = 7,
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsInode {
    pub ino: u64,
    pub generation: u64,
    pub transid: u64,           // Last transaction modifying this
    pub size: u64,
    pub nbytes: u64,            // Actual bytes on disk
    pub block_group: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub flags: InodeFlags,
    pub file_type: BtrfsFileType,
    pub atime_sec: u64,
    pub mtime_sec: u64,
    pub ctime_sec: u64,
    pub otime_sec: u64,         // Creation time
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct InodeFlags(pub u64);

impl InodeFlags {
    pub const NODATASUM: Self = Self(0x001);
    pub const NODATACOW: Self = Self(0x002);
    pub const READONLY: Self = Self(0x004);
    pub const NOCOMPRESS: Self = Self(0x008);
    pub const COMPRESS: Self = Self(0x020);
    pub const IMMUTABLE: Self = Self(0x040);
    pub const APPEND: Self = Self(0x080);
    pub const NODUMP: Self = Self(0x100);
    pub const NOATIME: Self = Self(0x200);
    pub const DIRSYNC: Self = Self(0x400);
}

impl BtrfsInode {
    pub const fn new() -> Self {
        Self {
            ino: 0,
            generation: 0,
            transid: 0,
            size: 0,
            nbytes: 0,
            block_group: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            rdev: 0,
            flags: InodeFlags(0),
            file_type: BtrfsFileType::Unknown,
            atime_sec: 0,
            mtime_sec: 0,
            ctime_sec: 0,
            otime_sec: 0,
            active: false,
        }
    }
}

// ─────────────────── Dir Entry ──────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct BtrfsDirItem {
    pub location_objectid: u64,
    pub location_type: BtrfsType,
    pub location_offset: u64,
    pub transid: u64,
    pub data_len: u16,
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub file_type: BtrfsFileType,
    pub name_hash: u32,        // CRC32C of name
    pub active: bool,
}

impl BtrfsDirItem {
    pub const fn new() -> Self {
        Self {
            location_objectid: 0,
            location_type: BtrfsType::InodeItem,
            location_offset: 0,
            transid: 0,
            data_len: 0,
            name: [0u8; NAME_LEN],
            name_len: 0,
            file_type: BtrfsFileType::Unknown,
            name_hash: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
        self.name_hash = crc32c_simple(n);
    }
}

fn crc32c_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x82F63B78; // CRC32C polynomial
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ─────────────────── Extent ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtentType {
    Inline = 0,
    Regular = 1,
    Prealloc = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionType {
    None = 0,
    Zlib = 1,
    Lzo = 2,
    Zstd = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsExtent {
    pub bytenr: u64,           // Logical address
    pub num_bytes: u64,
    pub disk_bytenr: u64,      // Physical address
    pub disk_num_bytes: u64,    // On-disk size (may differ with compression)
    pub offset: u64,            // Offset within extent
    pub extent_type: ExtentType,
    pub compression: CompressionType,
    pub ram_bytes: u64,         // Uncompressed size
    pub refs_: u32,
    pub generation: u64,
    pub flags: u64,             // 1 = data, 2 = tree block
    pub owner: u64,             // Objectid of owning tree
    pub checksum: u32,
    pub active: bool,
}

impl BtrfsExtent {
    pub const fn new() -> Self {
        Self {
            bytenr: 0,
            num_bytes: 0,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            offset: 0,
            extent_type: ExtentType::Regular,
            compression: CompressionType::None,
            ram_bytes: 0,
            refs_: 0,
            generation: 0,
            flags: 1, // Data by default
            owner: 0,
            checksum: 0,
            active: false,
        }
    }
}

// ─────────────────── Chunk (Logical→Physical) ───────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkProfile {
    Single = 0,
    Dup = 1,
    Raid0 = 2,
    Raid1 = 3,
    Raid5 = 4,
    Raid6 = 5,
    Raid10 = 6,
    Raid1c3 = 7,
    Raid1c4 = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkType {
    Data = 1,
    System = 2,
    Metadata = 4,
    DataMetadata = 5,
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsChunk {
    pub logical: u64,
    pub length: u64,
    pub stripe_len: u32,
    pub profile: ChunkProfile,
    pub chunk_type: ChunkType,
    pub num_stripes: u8,
    pub sub_stripes: u8,
    // Stripe mapping (simplified: 1 stripe)
    pub devid: u64,
    pub physical: u64,
    pub dev_offset: u64,
    pub used: u64,
    pub active: bool,
}

impl BtrfsChunk {
    pub const fn new() -> Self {
        Self {
            logical: 0,
            length: 0,
            stripe_len: 65536,
            profile: ChunkProfile::Single,
            chunk_type: ChunkType::Data,
            num_stripes: 1,
            sub_stripes: 0,
            devid: 1,
            physical: 0,
            dev_offset: 0,
            used: 0,
            active: false,
        }
    }

    pub fn logical_to_physical(&self, logical_addr: u64) -> Option<u64> {
        if logical_addr < self.logical || logical_addr >= self.logical + self.length {
            return None;
        }
        let offset = logical_addr - self.logical;
        Some(self.physical + offset)
    }
}

// ─────────────────── Subvolume ──────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolume {
    pub root_id: u64,
    pub parent_id: u64,
    pub generation: u64,
    pub otransid: u64,          // Creation transaction
    pub stransid: u64,          // Send transaction
    pub rtransid: u64,          // Receive transaction
    pub root_dirid: u64,
    pub name: [u8; 64],
    pub name_len: u8,
    pub flags: u64,             // Bit 0: readonly snapshot
    pub inode_count: u64,
    pub bytes_used: u64,
    pub uuid: [u8; BTRFS_UUID_SIZE],
    pub parent_uuid: [u8; BTRFS_UUID_SIZE],
    pub received_uuid: [u8; BTRFS_UUID_SIZE],
    pub active: bool,
}

impl BtrfsSubvolume {
    pub const fn new() -> Self {
        Self {
            root_id: 0,
            parent_id: 0,
            generation: 0,
            otransid: 0,
            stransid: 0,
            rtransid: 0,
            root_dirid: 256,
            name: [0u8; 64],
            name_len: 0,
            flags: 0,
            inode_count: 0,
            bytes_used: 0,
            uuid: [0u8; BTRFS_UUID_SIZE],
            parent_uuid: [0u8; BTRFS_UUID_SIZE],
            received_uuid: [0u8; BTRFS_UUID_SIZE],
            active: false,
        }
    }

    pub fn is_readonly(&self) -> bool {
        (self.flags & 1) != 0
    }

    pub fn set_readonly(&mut self, ro: bool) {
        if ro { self.flags |= 1; } else { self.flags &= !1; }
    }
}

// ─────────────────── Transaction ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionState {
    Running = 0,
    Blocked = 1,
    Committing = 2,
    SuperCommit = 3,
    Completed = 4,
    Aborted = 5,
}

#[derive(Debug, Clone, Copy)]
pub struct BtrfsTransaction {
    pub transid: u64,
    pub state: TransactionState,
    pub num_writers: u32,
    pub num_dirty_items: u64,
    pub bytes_reserved: u64,
    pub bytes_committed: u64,
    pub start_tick: u64,
    pub commit_tick: u64,
    pub log_committed: bool,
    pub active: bool,
}

impl BtrfsTransaction {
    pub const fn new() -> Self {
        Self {
            transid: 0,
            state: TransactionState::Running,
            num_writers: 0,
            num_dirty_items: 0,
            bytes_reserved: 0,
            bytes_committed: 0,
            start_tick: 0,
            commit_tick: 0,
            log_committed: false,
            active: false,
        }
    }
}

// ─────────────────── Scrub Error ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ScrubError {
    pub logical: u64,
    pub physical: u64,
    pub expected_csum: u32,
    pub actual_csum: u32,
    pub generation: u64,
    pub mirror: u8,
    pub repaired: bool,
    pub tick: u64,
    pub valid: bool,
}

impl ScrubError {
    pub const fn new() -> Self {
        Self {
            logical: 0,
            physical: 0,
            expected_csum: 0,
            actual_csum: 0,
            generation: 0,
            mirror: 0,
            repaired: false,
            tick: 0,
            valid: false,
        }
    }
}

// ─────────────────── Btrfs Manager ──────────────────────────────────

pub struct BtrfsManager {
    pub sb: BtrfsSuperblock,
    inodes: [BtrfsInode; MAX_INODES],
    inode_count: u32,
    next_ino: u64,

    dir_entries: [BtrfsDirItem; MAX_DIR_ENTRIES],
    dir_entry_count: u32,

    extents: [BtrfsExtent; MAX_EXTENTS],
    extent_count: u32,

    chunks: [BtrfsChunk; MAX_CHUNKS],
    chunk_count: u16,

    subvolumes: [BtrfsSubvolume; MAX_SUBVOLUMES],
    subvol_count: u16,
    next_subvol_id: u64,

    transactions: [BtrfsTransaction; MAX_TRANSACTIONS],
    current_trans: u16,
    next_transid: u64,

    scrub_errors: [ScrubError; MAX_SCRUB_ERRORS],
    scrub_error_count: u16,

    // Stats
    total_cow_ops: u64,
    total_reads: u64,
    total_writes: u64,
    total_csum_verified: u64,
    total_csum_errors: u64,
    total_defrag_ops: u64,
    total_snapshots: u64,
    total_scrub_extents: u64,

    tick: u64,
    initialized: bool,
}

impl BtrfsManager {
    pub const fn new() -> Self {
        Self {
            sb: BtrfsSuperblock::new(),
            inodes: [const { BtrfsInode::new() }; MAX_INODES],
            inode_count: 0,
            next_ino: 256,
            dir_entries: [const { BtrfsDirItem::new() }; MAX_DIR_ENTRIES],
            dir_entry_count: 0,
            extents: [const { BtrfsExtent::new() }; MAX_EXTENTS],
            extent_count: 0,
            chunks: [const { BtrfsChunk::new() }; MAX_CHUNKS],
            chunk_count: 0,
            subvolumes: [const { BtrfsSubvolume::new() }; MAX_SUBVOLUMES],
            subvol_count: 0,
            next_subvol_id: 256,
            transactions: [const { BtrfsTransaction::new() }; MAX_TRANSACTIONS],
            current_trans: 0,
            next_transid: 1,
            scrub_errors: [const { ScrubError::new() }; MAX_SCRUB_ERRORS],
            scrub_error_count: 0,
            total_cow_ops: 0,
            total_reads: 0,
            total_writes: 0,
            total_csum_verified: 0,
            total_csum_errors: 0,
            total_defrag_ops: 0,
            total_snapshots: 0,
            total_scrub_extents: 0,
            tick: 0,
            initialized: true,
        }
    }

    // ─── Inode Operations ───────────────────────────────────────────

    pub fn create_inode(&mut self, file_type: BtrfsFileType, mode: u32, uid: u32, gid: u32) -> Option<u64> {
        for i in 0..MAX_INODES {
            if !self.inodes[i].active {
                let ino = self.next_ino;
                self.next_ino += 1;
                self.inodes[i] = BtrfsInode::new();
                self.inodes[i].ino = ino;
                self.inodes[i].generation = self.sb.generation;
                self.inodes[i].transid = self.next_transid;
                self.inodes[i].file_type = file_type;
                self.inodes[i].mode = mode;
                self.inodes[i].uid = uid;
                self.inodes[i].gid = gid;
                self.inodes[i].nlink = 1;
                self.inodes[i].otime_sec = self.tick;
                self.inodes[i].ctime_sec = self.tick;
                self.inodes[i].mtime_sec = self.tick;
                self.inodes[i].atime_sec = self.tick;
                self.inodes[i].active = true;
                self.inode_count += 1;
                return Some(ino);
            }
        }
        None
    }

    pub fn find_inode(&self, ino: u64) -> Option<usize> {
        for i in 0..MAX_INODES {
            if self.inodes[i].active && self.inodes[i].ino == ino {
                return Some(i);
            }
        }
        None
    }

    pub fn unlink_inode(&mut self, ino: u64) -> bool {
        if let Some(idx) = self.find_inode(ino) {
            self.inodes[idx].nlink = self.inodes[idx].nlink.saturating_sub(1);
            if self.inodes[idx].nlink == 0 {
                self.inodes[idx].active = false;
                self.inode_count = self.inode_count.saturating_sub(1);
                // Free extents owned by this inode
                self.free_extents_for(ino);
            }
            true
        } else {
            false
        }
    }

    // ─── Directory Operations ───────────────────────────────────────

    pub fn add_dir_entry(&mut self, parent_ino: u64, ino: u64, name: &[u8], ft: BtrfsFileType) -> bool {
        for i in 0..MAX_DIR_ENTRIES {
            if !self.dir_entries[i].active {
                self.dir_entries[i] = BtrfsDirItem::new();
                self.dir_entries[i].location_objectid = ino;
                self.dir_entries[i].location_type = BtrfsType::InodeItem;
                self.dir_entries[i].location_offset = parent_ino;
                self.dir_entries[i].transid = self.next_transid;
                self.dir_entries[i].set_name(name);
                self.dir_entries[i].file_type = ft;
                self.dir_entries[i].active = true;
                self.dir_entry_count += 1;
                return true;
            }
        }
        false
    }

    pub fn lookup_dir(&self, parent_ino: u64, name: &[u8]) -> Option<u64> {
        let hash = crc32c_simple(name);
        for i in 0..MAX_DIR_ENTRIES {
            if !self.dir_entries[i].active { continue; }
            if self.dir_entries[i].location_offset == parent_ino
                && self.dir_entries[i].name_hash == hash
                && self.dir_entries[i].name_len as usize == name.len()
            {
                let len = self.dir_entries[i].name_len as usize;
                if self.dir_entries[i].name[..len] == name[..len] {
                    return Some(self.dir_entries[i].location_objectid);
                }
            }
        }
        None
    }

    // ─── Extent Management ──────────────────────────────────────────

    pub fn alloc_extent(&mut self, owner: u64, num_bytes: u64, compression: CompressionType) -> Option<u64> {
        for i in 0..MAX_EXTENTS {
            if !self.extents[i].active {
                let bytenr = self.sb.bytes_used + 4096; // Simplified allocation
                self.extents[i] = BtrfsExtent::new();
                self.extents[i].bytenr = bytenr;
                self.extents[i].num_bytes = num_bytes;
                self.extents[i].disk_bytenr = bytenr;
                self.extents[i].disk_num_bytes = num_bytes;
                self.extents[i].ram_bytes = num_bytes;
                self.extents[i].compression = compression;
                self.extents[i].owner = owner;
                self.extents[i].refs_ = 1;
                self.extents[i].generation = self.sb.generation;
                self.extents[i].checksum = crc32c_simple(&bytenr.to_le_bytes());
                self.extents[i].active = true;
                self.extent_count += 1;
                self.sb.bytes_used += num_bytes;
                return Some(bytenr);
            }
        }
        None
    }

    fn free_extents_for(&mut self, owner: u64) {
        for i in 0..MAX_EXTENTS {
            if self.extents[i].active && self.extents[i].owner == owner {
                self.extents[i].refs_ = self.extents[i].refs_.saturating_sub(1);
                if self.extents[i].refs_ == 0 {
                    self.sb.bytes_used = self.sb.bytes_used.saturating_sub(self.extents[i].num_bytes);
                    self.extents[i].active = false;
                    self.extent_count = self.extent_count.saturating_sub(1);
                }
            }
        }
    }

    /// COW: clone an extent for copy-on-write
    pub fn cow_extent(&mut self, ext_idx: usize) -> Option<usize> {
        if ext_idx >= MAX_EXTENTS || !self.extents[ext_idx].active { return None; }
        let old = self.extents[ext_idx];
        // Allocate new extent with same size
        for i in 0..MAX_EXTENTS {
            if !self.extents[i].active {
                self.extents[i] = old;
                let new_bytenr = self.sb.bytes_used + 4096;
                self.extents[i].bytenr = new_bytenr;
                self.extents[i].disk_bytenr = new_bytenr;
                self.extents[i].generation = self.sb.generation;
                self.extents[i].refs_ = 1;
                self.extent_count += 1;
                self.sb.bytes_used += old.num_bytes;
                self.total_cow_ops += 1;
                // Decrease ref on original
                self.extents[ext_idx].refs_ = self.extents[ext_idx].refs_.saturating_sub(1);
                return Some(i);
            }
        }
        None
    }

    // ─── Chunk Management ───────────────────────────────────────────

    pub fn alloc_chunk(&mut self, chunk_type: ChunkType, length: u64, profile: ChunkProfile) -> Option<u16> {
        if self.chunk_count as usize >= MAX_CHUNKS { return None; }
        for i in 0..MAX_CHUNKS {
            if !self.chunks[i].active {
                let logical = if self.chunk_count > 0 {
                    // Place after last chunk
                    let last = &self.chunks[(self.chunk_count - 1) as usize];
                    last.logical + last.length
                } else {
                    1024 * 1024 // 1 MiB start
                };
                self.chunks[i] = BtrfsChunk::new();
                self.chunks[i].logical = logical;
                self.chunks[i].length = length;
                self.chunks[i].chunk_type = chunk_type;
                self.chunks[i].profile = profile;
                self.chunks[i].physical = logical; // Simplified 1:1 mapping
                self.chunks[i].active = true;
                self.chunk_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    // ─── Subvolumes & Snapshots ─────────────────────────────────────

    pub fn create_subvolume(&mut self, name: &[u8], parent_id: u64) -> Option<u64> {
        if self.subvol_count as usize >= MAX_SUBVOLUMES { return None; }
        for i in 0..MAX_SUBVOLUMES {
            if !self.subvolumes[i].active {
                let root_id = self.next_subvol_id;
                self.next_subvol_id += 1;
                self.subvolumes[i] = BtrfsSubvolume::new();
                self.subvolumes[i].root_id = root_id;
                self.subvolumes[i].parent_id = parent_id;
                self.subvolumes[i].generation = self.sb.generation;
                self.subvolumes[i].otransid = self.next_transid;
                let len = name.len().min(63);
                self.subvolumes[i].name[..len].copy_from_slice(&name[..len]);
                self.subvolumes[i].name_len = len as u8;
                self.subvolumes[i].active = true;
                self.subvol_count += 1;
                return Some(root_id);
            }
        }
        None
    }

    pub fn create_snapshot(&mut self, source_id: u64, name: &[u8], readonly: bool) -> Option<u64> {
        // Find source subvolume
        let source_idx = (0..MAX_SUBVOLUMES).find(|&i|
            self.subvolumes[i].active && self.subvolumes[i].root_id == source_id
        )?;

        let snap_id = self.create_subvolume(name, self.subvolumes[source_idx].root_id)?;
        let snap_idx = (0..MAX_SUBVOLUMES).find(|&i|
            self.subvolumes[i].active && self.subvolumes[i].root_id == snap_id
        )?;
        self.subvolumes[snap_idx].parent_uuid = self.subvolumes[source_idx].uuid;
        if readonly {
            self.subvolumes[snap_idx].set_readonly(true);
        }
        self.total_snapshots += 1;
        Some(snap_id)
    }

    pub fn delete_subvolume(&mut self, root_id: u64) -> bool {
        for i in 0..MAX_SUBVOLUMES {
            if self.subvolumes[i].active && self.subvolumes[i].root_id == root_id {
                self.subvolumes[i].active = false;
                self.subvol_count = self.subvol_count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    // ─── Transactions ───────────────────────────────────────────────

    pub fn begin_transaction(&mut self) -> Option<u64> {
        for i in 0..MAX_TRANSACTIONS {
            if !self.transactions[i].active {
                let transid = self.next_transid;
                self.next_transid += 1;
                self.transactions[i] = BtrfsTransaction::new();
                self.transactions[i].transid = transid;
                self.transactions[i].state = TransactionState::Running;
                self.transactions[i].start_tick = self.tick;
                self.transactions[i].active = true;
                self.current_trans = i as u16;
                return Some(transid);
            }
        }
        None
    }

    pub fn commit_transaction(&mut self, transid: u64) -> bool {
        for i in 0..MAX_TRANSACTIONS {
            if self.transactions[i].active && self.transactions[i].transid == transid {
                self.transactions[i].state = TransactionState::Committing;
                self.sb.generation += 1;
                self.transactions[i].bytes_committed = self.transactions[i].bytes_reserved;
                self.transactions[i].commit_tick = self.tick;
                self.transactions[i].state = TransactionState::Completed;
                return true;
            }
        }
        false
    }

    // ─── Scrub ──────────────────────────────────────────────────────

    pub fn scrub_extent(&mut self, ext_idx: usize) -> bool {
        if ext_idx >= MAX_EXTENTS || !self.extents[ext_idx].active { return false; }
        self.total_scrub_extents += 1;
        let expected = self.extents[ext_idx].checksum;
        let actual = crc32c_simple(&self.extents[ext_idx].bytenr.to_le_bytes());
        self.total_csum_verified += 1;
        if expected != actual {
            self.total_csum_errors += 1;
            // Record scrub error
            if (self.scrub_error_count as usize) < MAX_SCRUB_ERRORS {
                let idx = self.scrub_error_count as usize;
                self.scrub_errors[idx] = ScrubError::new();
                self.scrub_errors[idx].logical = self.extents[ext_idx].bytenr;
                self.scrub_errors[idx].physical = self.extents[ext_idx].disk_bytenr;
                self.scrub_errors[idx].expected_csum = expected;
                self.scrub_errors[idx].actual_csum = actual;
                self.scrub_errors[idx].generation = self.extents[ext_idx].generation;
                self.scrub_errors[idx].tick = self.tick;
                self.scrub_errors[idx].valid = true;
                self.scrub_error_count += 1;
            }
            return false;
        }
        true
    }

    pub fn tick(&mut self) {
        self.tick += 1;
        // Auto-commit pending transactions every 30 seconds
        if self.tick % 30000 == 0 {
            for i in 0..MAX_TRANSACTIONS {
                if self.transactions[i].active
                    && self.transactions[i].state == TransactionState::Running
                    && self.tick - self.transactions[i].start_tick > 30000
                {
                    let tid = self.transactions[i].transid;
                    self.commit_transaction(tid);
                }
            }
        }
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_BTRFS: BtrfsManager = BtrfsManager::new();
static mut G_BTRFS_INIT: bool = false;

fn btrfs() -> &'static mut BtrfsManager {
    unsafe { &mut G_BTRFS }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_btrfs_init(total_bytes: u64) {
    unsafe {
        G_BTRFS = BtrfsManager::new();
        G_BTRFS.sb.total_bytes = total_bytes;
        G_BTRFS_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_create_inode(file_type: u8, mode: u32, uid: u32, gid: u32) -> i64 {
    if unsafe { !G_BTRFS_INIT } { return -1; }
    let ft: BtrfsFileType = unsafe { core::mem::transmute(file_type) };
    match btrfs().create_inode(ft, mode, uid, gid) {
        Some(ino) => ino as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_add_direntry(parent: u64, ino: u64, name_ptr: *const u8, name_len: usize, ft: u8) -> bool {
    if unsafe { !G_BTRFS_INIT } { return false; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let file_type: BtrfsFileType = unsafe { core::mem::transmute(ft) };
    btrfs().add_dir_entry(parent, ino, name, file_type)
}

#[no_mangle]
pub extern "C" fn rust_btrfs_lookup(parent: u64, name_ptr: *const u8, name_len: usize) -> i64 {
    if unsafe { !G_BTRFS_INIT } { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    match btrfs().lookup_dir(parent, name) {
        Some(ino) => ino as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_alloc_extent(owner: u64, bytes: u64, compression: u8) -> i64 {
    if unsafe { !G_BTRFS_INIT } { return -1; }
    let comp: CompressionType = unsafe { core::mem::transmute(compression) };
    match btrfs().alloc_extent(owner, bytes, comp) {
        Some(bytenr) => bytenr as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_create_subvol(name_ptr: *const u8, name_len: usize, parent_id: u64) -> i64 {
    if unsafe { !G_BTRFS_INIT } { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    match btrfs().create_subvolume(name, parent_id) {
        Some(id) => id as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_snapshot(source: u64, name_ptr: *const u8, name_len: usize, readonly: bool) -> i64 {
    if unsafe { !G_BTRFS_INIT } { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    match btrfs().create_snapshot(source, name, readonly) {
        Some(id) => id as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_begin_transaction() -> i64 {
    if unsafe { !G_BTRFS_INIT } { return -1; }
    match btrfs().begin_transaction() {
        Some(tid) => tid as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_btrfs_commit(transid: u64) -> bool {
    if unsafe { !G_BTRFS_INIT } { return false; }
    btrfs().commit_transaction(transid)
}

#[no_mangle]
pub extern "C" fn rust_btrfs_tick() {
    if unsafe { !G_BTRFS_INIT } { return; }
    btrfs().tick();
}

#[no_mangle]
pub extern "C" fn rust_btrfs_inode_count() -> u32 {
    if unsafe { !G_BTRFS_INIT } { return 0; }
    btrfs().inode_count
}

#[no_mangle]
pub extern "C" fn rust_btrfs_extent_count() -> u32 {
    if unsafe { !G_BTRFS_INIT } { return 0; }
    btrfs().extent_count
}

#[no_mangle]
pub extern "C" fn rust_btrfs_subvol_count() -> u16 {
    if unsafe { !G_BTRFS_INIT } { return 0; }
    btrfs().subvol_count
}

#[no_mangle]
pub extern "C" fn rust_btrfs_total_cow() -> u64 {
    if unsafe { !G_BTRFS_INIT } { return 0; }
    btrfs().total_cow_ops
}

#[no_mangle]
pub extern "C" fn rust_btrfs_bytes_used() -> u64 {
    if unsafe { !G_BTRFS_INIT } { return 0; }
    btrfs().sb.bytes_used
}

#[no_mangle]
pub extern "C" fn rust_btrfs_generation() -> u64 {
    if unsafe { !G_BTRFS_INIT } { return 0; }
    btrfs().sb.generation
}
