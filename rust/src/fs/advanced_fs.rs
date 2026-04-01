// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Filesystem: ext4-like with journaling, extents, inodes
// Btrfs-like Copy-on-Write, snapshots, subvolumes, scrub, balance

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

// ============================================================================
// Superblock & Block Group Descriptors
// ============================================================================

pub const ZXYFS_MAGIC: u32 = 0x5A585946; // "ZXYF"
pub const ZXYFS_BLOCK_SIZE: u32 = 4096;
pub const ZXYFS_INODE_SIZE: u32 = 256;
pub const ZXYFS_MAX_FILENAME: usize = 255;
pub const ZXYFS_MAX_LINKS: u32 = 65000;
pub const ZXYFS_MAX_FILESIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024; // 16 TiB

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZxyFsSuperblock {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub block_size: u32,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub inodes_count: u64,
    pub free_inodes_count: u64,
    pub first_data_block: u64,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub block_group_count: u32,
    pub mount_count: u16,
    pub max_mount_count: u16,
    pub state: u16,           // FS_CLEAN=1, FS_ERROR=2
    pub errors: u16,          // ERRORS_CONTINUE=1, ERRORS_RO=2, ERRORS_PANIC=3
    pub last_check_time: u64,
    pub check_interval: u64,
    pub creator_os: u32,
    pub revision: u32,
    pub default_uid: u16,
    pub default_gid: u16,
    // Journal
    pub journal_inum: u32,
    pub journal_dev: u32,
    pub journal_uuid: [16; u8],
    // Features
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    // UUID
    pub uuid: [16; u8],
    pub volume_name: [16; u8],
    pub last_mounted: [64; u8],
    // Encryption
    pub encrypt_algo: u8,
    pub encrypt_pw_salt: [16; u8],
    // Checksum
    pub checksum_type: u8,
    pub checksum: u32,
    // Snapshot / CoW
    pub snapshot_id: u64,
    pub snapshot_count: u32,
    pub default_subvol: u64,
    // Free space cache
    pub free_space_cache_inum: u64,
    // Stripe
    pub raid_stripe_width: u32,
    pub first_meta_bg: u32,
    pub reserved: [128; u8],
}

pub const FEATURE_COMPAT_JOURNAL: u32 = 0x0004;
pub const FEATURE_COMPAT_EXTATTR: u32 = 0x0008;
pub const FEATURE_COMPAT_DIR_INDEX: u32 = 0x0020;
pub const FEATURE_COMPAT_SPARSE_SUPER2: u32 = 0x0200;

pub const FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub const FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
pub const FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;
pub const FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;
pub const FEATURE_INCOMPAT_COW: u32 = 0x100000;       // Zxyphor: CoW
pub const FEATURE_INCOMPAT_SNAPSHOTS: u32 = 0x200000;  // Zxyphor: Snapshots

pub const FEATURE_RO_COMPAT_SPARSE: u32 = 0x0001;
pub const FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
pub const FEATURE_RO_COMPAT_VERITY: u32 = 0x8000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockGroupDesc {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
    pub flags: u16,
    pub exclude_bitmap: u64,
    pub block_bitmap_csum: u32,
    pub inode_bitmap_csum: u32,
    pub itable_unused: u32,
    pub checksum: u16,
}

// ============================================================================
// Inode
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Unknown = 0,
    RegularFile = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Fifo = 5,
    Socket = 6,
    Symlink = 7,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Inode {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u64,     // Access time (nanoseconds)
    pub ctime: u64,     // Change time
    pub mtime: u64,     // Modification time
    pub crtime: u64,    // Creation time
    pub links_count: u32,
    pub blocks: u64,    // 512-byte blocks
    pub flags: u32,
    pub generation: u32,
    pub file_acl: u64,
    // Extent tree inline
    pub extent_header: ExtentHeader,
    pub extents: [4; Extent],
    // Overflow
    pub osd2: [12; u8],
    pub extra_isize: u16,
    pub checksum: u16,
    pub csum_hi: u16,
    // Security
    pub security_label_offset: u32,
    pub security_label_size: u16,
    // Project quota
    pub projid: u32,
    // CoW
    pub cow_generation: u64,
    pub cow_parent: u64,
    // Verity
    pub verity_offset: u64,
    pub verity_size: u32,
}

pub const INODE_FLAG_SECRM: u32 = 0x00000001;
pub const INODE_FLAG_UNRM: u32 = 0x00000002;
pub const INODE_FLAG_COMPR: u32 = 0x00000004;
pub const INODE_FLAG_SYNC: u32 = 0x00000008;
pub const INODE_FLAG_IMMUTABLE: u32 = 0x00000010;
pub const INODE_FLAG_APPEND: u32 = 0x00000020;
pub const INODE_FLAG_NODUMP: u32 = 0x00000040;
pub const INODE_FLAG_NOATIME: u32 = 0x00000080;
pub const INODE_FLAG_DIRTY: u32 = 0x00000100;
pub const INODE_FLAG_JOURNAL_DATA: u32 = 0x00004000;
pub const INODE_FLAG_NOTAIL: u32 = 0x00008000;
pub const INODE_FLAG_DIRSYNC: u32 = 0x00010000;
pub const INODE_FLAG_TOPDIR: u32 = 0x00020000;
pub const INODE_FLAG_HUGE_FILE: u32 = 0x00040000;
pub const INODE_FLAG_EXTENTS: u32 = 0x00080000;
pub const INODE_FLAG_VERITY: u32 = 0x00100000;
pub const INODE_FLAG_ENCRYPT: u32 = 0x00000800;
pub const INODE_FLAG_CASEFOLD: u32 = 0x40000000;
pub const INODE_FLAG_INLINE_DATA: u32 = 0x10000000;
pub const INODE_FLAG_PROJINHERIT: u32 = 0x20000000;
pub const INODE_FLAG_COW: u32 = 0x80000000; // Zxyphor CoW flag

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExtentHeader {
    pub magic: u16,     // 0xF30A
    pub entries: u16,
    pub max: u16,
    pub depth: u16,
    pub generation: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Extent {
    pub block: u32,
    pub len: u16,
    pub start_hi: u16,
    pub start_lo: u32,
}

impl Extent {
    pub fn physical_start(&self) -> u64 {
        ((self.start_hi as u64) << 32) | (self.start_lo as u64)
    }

    pub fn is_initialized(&self) -> bool {
        self.len <= 32768
    }

    pub fn block_count(&self) -> u32 {
        if self.len > 32768 { (self.len - 32768) as u32 } else { self.len as u32 }
    }
}

// ============================================================================
// Directory Entry
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub inode: u64,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name: [ZXYFS_MAX_FILENAME; u8],
}

pub struct DirEntryHash {
    pub hash: u32,
    pub minor_hash: u32,
    pub inode: u64,
    pub name_len: u8,
}

// ============================================================================
// Block Allocator (mballoc-like multi-block allocator)
// ============================================================================

pub struct BlockAllocator {
    pub groups: [1024; BlockGroupState],
    pub num_groups: u32,
    pub total_blocks: u64,
    pub free_blocks: AtomicU64,
    pub reserved_blocks: u64,
    // Preallocation pools
    pub prealloc_bg: [256; PreallocPool],
    pub num_prealloc: u32,
    // Statistics
    pub alloc_calls: AtomicU64,
    pub free_calls: AtomicU64,
    pub alloc_hits: AtomicU64,
    pub alloc_groups_scanned: AtomicU64,
}

pub struct BlockGroupState {
    pub group_id: u32,
    pub free_blocks: AtomicU32,
    pub largest_free_extent: u32,
    pub fragments: u32,
    pub bitmap: [128; u64],  // 8192 blocks per group (128 * 64 bits)
    pub flags: u32,
}

impl BlockGroupState {
    pub fn alloc_blocks(&mut self, count: u32) -> Option<u64> {
        if self.free_blocks.load(Ordering::Relaxed) < count {
            return None;
        }
        
        // Find contiguous free run
        let needed = count as usize;
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        
        for word_idx in 0..128 {
            let word = self.bitmap[word_idx];
            if word == u64::MAX { 
                run_len = 0;
                continue; 
            }
            
            for bit in 0..64u32 {
                let pos = word_idx * 64 + bit as usize;
                if word & (1u64 << bit) == 0 {
                    if run_len == 0 { run_start = pos; }
                    run_len += 1;
                    if run_len >= needed {
                        // Mark allocated
                        for i in 0..needed {
                            let p = run_start + i;
                            self.bitmap[p / 64] |= 1u64 << (p % 64);
                        }
                        self.free_blocks.fetch_sub(count, Ordering::Relaxed);
                        let block = self.group_id as u64 * 8192 + run_start as u64;
                        return Some(block);
                    }
                } else {
                    run_len = 0;
                }
            }
        }
        None
    }

    pub fn free_block_range(&mut self, start_offset: u32, count: u32) {
        for i in 0..count as usize {
            let pos = start_offset as usize + i;
            if pos < 8192 {
                self.bitmap[pos / 64] &= !(1u64 << (pos % 64));
            }
        }
        self.free_blocks.fetch_add(count, Ordering::Relaxed);
    }
}

pub struct PreallocPool {
    pub inum: u64,
    pub start_block: u64,
    pub len: u32,
    pub free: u32,
}

impl BlockAllocator {
    pub fn new(num_groups: u32) -> Self {
        BlockAllocator {
            groups: core::array::from_fn(|i| BlockGroupState {
                group_id: i as u32,
                free_blocks: AtomicU32::new(8192),
                largest_free_extent: 8192,
                fragments: 0,
                bitmap: [0u64; 128],
                flags: 0,
            }),
            num_groups,
            total_blocks: num_groups as u64 * 8192,
            free_blocks: AtomicU64::new(num_groups as u64 * 8192),
            reserved_blocks: 0,
            prealloc_bg: core::array::from_fn(|_| PreallocPool {
                inum: 0, start_block: 0, len: 0, free: 0,
            }),
            num_prealloc: 0,
            alloc_calls: AtomicU64::new(0),
            free_calls: AtomicU64::new(0),
            alloc_hits: AtomicU64::new(0),
            alloc_groups_scanned: AtomicU64::new(0),
        }
    }

    /// Multi-block allocation (mballoc algorithm)
    pub fn mballoc(&mut self, count: u32, goal_block: u64) -> Option<u64> {
        self.alloc_calls.fetch_add(1, Ordering::Relaxed);
        
        // Try goal group first
        let goal_group = (goal_block / 8192) as u32;
        if (goal_group as usize) < self.num_groups as usize {
            if let Some(block) = self.groups[goal_group as usize].alloc_blocks(count) {
                self.free_blocks.fetch_sub(count as u64, Ordering::Relaxed);
                self.alloc_hits.fetch_add(1, Ordering::Relaxed);
                return Some(block);
            }
        }
        
        // Linear scan from start
        for i in 0..self.num_groups as usize {
            self.alloc_groups_scanned.fetch_add(1, Ordering::Relaxed);
            if let Some(block) = self.groups[i].alloc_blocks(count) {
                self.free_blocks.fetch_sub(count as u64, Ordering::Relaxed);
                return Some(block);
            }
        }
        
        None
    }

    pub fn free_blocks_fn(&mut self, block: u64, count: u32) {
        self.free_calls.fetch_add(1, Ordering::Relaxed);
        let group = (block / 8192) as usize;
        let offset = (block % 8192) as u32;
        if group < self.num_groups as usize {
            self.groups[group].free_block_range(offset, count);
            self.free_blocks.fetch_add(count as u64, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// Inode Cache
// ============================================================================

pub struct InodeCache {
    pub entries: [4096; InodeCacheEntry],
    pub count: u32,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
}

pub struct InodeCacheEntry {
    pub inum: u64,
    pub inode: Inode,
    pub dirty: bool,
    pub valid: bool,
    pub ref_count: AtomicU32,
    pub last_access_ns: u64,
    pub hash_next: u32,
}

impl InodeCache {
    pub fn new() -> Self {
        const EMPTY_ENTRY: InodeCacheEntry = InodeCacheEntry {
            inum: 0,
            inode: unsafe { core::mem::zeroed() },
            dirty: false,
            valid: false,
            ref_count: AtomicU32::new(0),
            last_access_ns: 0,
            hash_next: u32::MAX,
        };
        InodeCache {
            entries: [EMPTY_ENTRY; 4096],
            count: 0,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    fn hash(inum: u64) -> usize {
        ((inum.wrapping_mul(0x9E3779B97F4A7C15)) >> 52) as usize & 4095
    }

    pub fn lookup(&self, inum: u64) -> Option<&InodeCacheEntry> {
        let idx = Self::hash(inum);
        let entry = &self.entries[idx];
        if entry.valid && entry.inum == inum {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&mut self, inum: u64, inode: Inode, now_ns: u64) {
        let idx = Self::hash(inum);
        let entry = &mut self.entries[idx];
        if entry.valid && entry.dirty {
            // Would need writeback before eviction
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        entry.inum = inum;
        entry.inode = inode;
        entry.dirty = false;
        entry.valid = true;
        entry.ref_count.store(1, Ordering::Relaxed);
        entry.last_access_ns = now_ns;
        if !entry.valid { self.count += 1; }
    }

    pub fn mark_dirty(&mut self, inum: u64) {
        let idx = Self::hash(inum);
        let entry = &mut self.entries[idx];
        if entry.valid && entry.inum == inum {
            entry.dirty = true;
        }
    }
}

// ============================================================================
// Snapshot & Subvolume Management (Btrfs-like)
// ============================================================================

pub struct Subvolume {
    pub id: u64,
    pub parent_id: u64,
    pub root_inum: u64,
    pub generation: u64,
    pub flags: u32,
    pub name: [256; u8],
    pub name_len: u8,
    pub created_ns: u64,
    pub received_uuid: [16; u8],
    pub sent_uuid: [16; u8],
    // Quota
    pub bytes_used: AtomicU64,
    pub bytes_exclusive: AtomicU64,
    pub quota_limit: u64,
}

pub const SUBVOL_FLAG_READONLY: u32 = 1 << 0;
pub const SUBVOL_FLAG_SNAPSHOT: u32 = 1 << 1;
pub const SUBVOL_FLAG_DEFAULT: u32 = 1 << 2;

pub struct SnapshotManager {
    pub subvolumes: [256; Subvolume],
    pub count: u32,
    pub next_id: u64,
    pub default_subvol: u64,
}

impl SnapshotManager {
    pub fn new() -> Self {
        SnapshotManager {
            subvolumes: core::array::from_fn(|_| Subvolume {
                id: 0, parent_id: 0, root_inum: 0, generation: 0,
                flags: 0, name: [0; 256], name_len: 0, created_ns: 0,
                received_uuid: [0; 16], sent_uuid: [0; 16],
                bytes_used: AtomicU64::new(0),
                bytes_exclusive: AtomicU64::new(0),
                quota_limit: 0,
            }),
            count: 0,
            next_id: 256, // IDs 1-255 reserved
            default_subvol: 5,
        }
    }

    pub fn create_subvolume(&mut self, name: &[u8], parent_id: u64, now_ns: u64) -> Option<u64> {
        if self.count >= 256 { return None; }
        let idx = self.count as usize;
        let id = self.next_id;
        self.next_id += 1;
        
        let sv = &mut self.subvolumes[idx];
        sv.id = id;
        sv.parent_id = parent_id;
        sv.generation = 0;
        sv.flags = 0;
        sv.created_ns = now_ns;
        let len = name.len().min(256);
        sv.name[..len].copy_from_slice(&name[..len]);
        sv.name_len = len as u8;
        
        self.count += 1;
        Some(id)
    }

    pub fn create_snapshot(&mut self, source_id: u64, name: &[u8], readonly: bool, now_ns: u64) -> Option<u64> {
        // Find source
        let source = self.find_subvolume(source_id)?;
        let root_inum = source.root_inum;
        let gen = source.generation;
        
        let id = self.create_subvolume(name, source_id, now_ns)?;
        let idx = self.count as usize - 1;
        self.subvolumes[idx].root_inum = root_inum;
        self.subvolumes[idx].generation = gen;
        self.subvolumes[idx].flags = SUBVOL_FLAG_SNAPSHOT;
        if readonly {
            self.subvolumes[idx].flags |= SUBVOL_FLAG_READONLY;
        }
        Some(id)
    }

    pub fn find_subvolume(&self, id: u64) -> Option<&Subvolume> {
        for i in 0..self.count as usize {
            if self.subvolumes[i].id == id {
                return Some(&self.subvolumes[i]);
            }
        }
        None
    }

    pub fn delete_subvolume(&mut self, id: u64) -> bool {
        for i in 0..self.count as usize {
            if self.subvolumes[i].id == id {
                if self.subvolumes[i].flags & SUBVOL_FLAG_DEFAULT != 0 {
                    return false; // Can't delete default
                }
                // Shift remaining
                for j in i..self.count as usize - 1 {
                    self.subvolumes[j] = self.subvolumes[j + 1];
                }
                self.count -= 1;
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Filesystem Statistics
// ============================================================================

pub struct FsStats {
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
    pub metadata_reads: AtomicU64,
    pub metadata_writes: AtomicU64,
    pub journal_commits: AtomicU64,
    pub journal_bytes: AtomicU64,
    pub extent_allocs: AtomicU64,
    pub extent_frees: AtomicU64,
    pub inode_allocs: AtomicU64,
    pub inode_frees: AtomicU64,
    pub dir_lookups: AtomicU64,
    pub dir_creates: AtomicU64,
    pub cow_copies: AtomicU64,
    pub snapshot_creates: AtomicU64,
}

impl FsStats {
    pub const fn new() -> Self {
        FsStats {
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
            metadata_reads: AtomicU64::new(0),
            metadata_writes: AtomicU64::new(0),
            journal_commits: AtomicU64::new(0),
            journal_bytes: AtomicU64::new(0),
            extent_allocs: AtomicU64::new(0),
            extent_frees: AtomicU64::new(0),
            inode_allocs: AtomicU64::new(0),
            inode_frees: AtomicU64::new(0),
            dir_lookups: AtomicU64::new(0),
            dir_creates: AtomicU64::new(0),
            cow_copies: AtomicU64::new(0),
            snapshot_creates: AtomicU64::new(0),
        }
    }
}

static FS_STATS: FsStats = FsStats::new();
pub fn get_fs_stats() -> &'static FsStats { &FS_STATS }
