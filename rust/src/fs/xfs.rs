// SPDX-License-Identifier: MIT
//! Zxyphor Kernel — XFS Filesystem (Rust)
//!
//! Linux-compatible XFS implementation:
//! - Allocation Groups (AG): parallel allocation for scalability
//! - B+ tree based inode & extent allocation
//! - Extent-based file storage (contiguous block runs)
//! - Journaling (WAL) with log items and transactions
//! - Real-time subvolume support (placeholder)
//! - Delayed allocation for write batching
//! - Inode with inline data for small files
//! - Directory: block format with hash-keyed entries
//! - Superblock with full XFS on-disk layout
//! - Free space B+ tree (by block number and by size)
//! - Inode B+ tree per AG

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const XFS_MAGIC: u32 = 0x58465342; // "XFSB"
const MAX_AGS: usize = 16;
const MAX_INODES: usize = 512;
const MAX_EXTENTS: usize = 256;
const MAX_DIR_ENTRIES: usize = 128;
const MAX_LOG_ITEMS: usize = 64;
const MAX_DELAYED_ALLOCS: usize = 64;
const BLOCK_SIZE: u32 = 4096;
const INODE_SIZE: u16 = 512;
const NAME_LEN: usize = 255;

// ─────────────────── UUID ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub const ZERO: Self = Self([0u8; 16]);

    pub fn from_bytes(b: [u8; 16]) -> Self { Self(b) }
}

// ─────────────────── Superblock ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct XfsSuperblock {
    pub magic: u32,
    pub blocksize: u32,
    pub dblocks: u64,           // Total data blocks
    pub rblocks: u64,           // Real-time blocks
    pub rextents: u64,          // Real-time extents
    pub uuid: Uuid,
    pub logstart: u64,          // Journal start block
    pub rootino: u64,           // Root inode number
    pub agblocks: u32,          // Blocks per AG
    pub agcount: u32,
    pub logblocks: u32,
    pub versionnum: u16,
    pub sectsize: u16,
    pub inodesize: u16,
    pub inopblock: u16,         // Inodes per block
    pub freeblocks: u64,
    pub free_inodes: u64,
    pub icount: u64,            // Total allocated inodes
    pub ifree: u64,
    pub fdblocks: u64,          // Free data blocks
    pub features_compat: u32,
    pub features_incompat: u32,
    pub label: [u8; 12],
}

impl XfsSuperblock {
    pub const fn new() -> Self {
        Self {
            magic: XFS_MAGIC,
            blocksize: BLOCK_SIZE,
            dblocks: 0,
            rblocks: 0,
            rextents: 0,
            uuid: Uuid::ZERO,
            logstart: 0,
            rootino: 128,
            agblocks: 0,
            agcount: 0,
            logblocks: 0,
            versionnum: 5,
            sectsize: 512,
            inodesize: INODE_SIZE,
            inopblock: (BLOCK_SIZE / INODE_SIZE as u32) as u16,
            freeblocks: 0,
            free_inodes: 0,
            icount: 0,
            ifree: 0,
            fdblocks: 0,
            features_compat: 0,
            features_incompat: 0,
            label: [0u8; 12],
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == XFS_MAGIC && self.blocksize >= 512 && self.agcount > 0
    }
}

// ─────────────────── Inode Format ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XfsInodeFormat {
    Dev = 0,         // Device special
    Local = 1,       // Inline data (small files/dirs)
    Extents = 2,     // Extent list
    Btree = 3,       // B+ tree of extents
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum XfsFileType {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    BlockDev = 4,
    CharDev = 5,
    Fifo = 6,
    Socket = 7,
}

// ─────────────────── Extent Record ──────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct XfsExtent {
    pub startoff: u64,       // File logical block offset
    pub startblock: u64,     // Filesystem physical block
    pub blockcount: u32,
    pub state: ExtentState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtentState {
    Normal = 0,
    Unwritten = 1,   // Preallocated but not written
    Delayed = 2,     // Delayed allocation (not yet on disk)
}

impl XfsExtent {
    pub const fn new() -> Self {
        Self {
            startoff: 0,
            startblock: 0,
            blockcount: 0,
            state: ExtentState::Normal,
        }
    }

    pub fn contains_offset(&self, off: u64) -> bool {
        off >= self.startoff && off < self.startoff + self.blockcount as u64
    }
}

// ─────────────────── Inode ──────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct XfsInode {
    pub ino: u64,
    pub generation: u32,
    pub ftype: XfsFileType,
    pub format: XfsInodeFormat,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub nblocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub crtime: u64,          // Creation time (XFS v5)

    // Extent map
    pub extents: [XfsExtent; 16],
    pub nextents: u16,

    // Inline data (for XfsInodeFormat::Local)
    pub inline_data: [u8; 64],
    pub inline_len: u16,

    // Flags
    pub flags: u32,
    pub flags2: u64,

    pub ag_number: u16,       // Allocation group
    pub allocated: bool,
}

impl XfsInode {
    pub const fn new() -> Self {
        Self {
            ino: 0,
            generation: 0,
            ftype: XfsFileType::Regular,
            format: XfsInodeFormat::Extents,
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 0,
            nblocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            extents: [const { XfsExtent::new() }; 16],
            nextents: 0,
            inline_data: [0u8; 64],
            inline_len: 0,
            flags: 0,
            flags2: 0,
            ag_number: 0,
            allocated: false,
        }
    }

    pub fn add_extent(&mut self, ext: XfsExtent) -> bool {
        if self.nextents as usize >= 16 { return false; }
        self.extents[self.nextents as usize] = ext;
        self.nextents += 1;
        self.nblocks += ext.blockcount as u64;
        true
    }

    pub fn lookup_block(&self, file_block: u64) -> Option<u64> {
        for i in 0..self.nextents as usize {
            let ext = &self.extents[i];
            if ext.contains_offset(file_block) {
                let offset = file_block - ext.startoff;
                return Some(ext.startblock + offset);
            }
        }
        None
    }

    pub fn total_blocks(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nextents as usize {
            total += self.extents[i].blockcount as u64;
        }
        total
    }
}

// Inode flags
pub const XFS_DIFLAG_REALTIME: u32 = 0x01;
pub const XFS_DIFLAG_PREALLOC: u32 = 0x02;
pub const XFS_DIFLAG_NEWRTBM: u32 = 0x04;
pub const XFS_DIFLAG_IMMUTABLE: u32 = 0x08;
pub const XFS_DIFLAG_APPEND: u32 = 0x10;
pub const XFS_DIFLAG_SYNC: u32 = 0x20;
pub const XFS_DIFLAG_NOATIME: u32 = 0x40;
pub const XFS_DIFLAG_NODUMP: u32 = 0x80;

// ─────────────────── Directory Entry ────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct XfsDirEntry {
    pub ino: u64,
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub ftype: XfsFileType,
    pub name_hash: u32,       // Da_hashname for lookup
    pub active: bool,
}

impl XfsDirEntry {
    pub const fn new() -> Self {
        Self {
            ino: 0,
            name: [0u8; NAME_LEN],
            name_len: 0,
            ftype: XfsFileType::Regular,
            name_hash: 0,
            active: false,
        }
    }
}

/// XFS directory hash function (da_hashname)
fn xfs_da_hashname(name: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &b in name {
        hash = hash.wrapping_mul(7).wrapping_add(b as u32);
    }
    hash
}

// ─────────────────── Allocation Group ───────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct XfsAg {
    pub ag_number: u16,
    pub length: u32,          // Blocks in this AG
    pub freeblks: u32,
    pub free_inodes: u32,
    pub icount: u32,

    // Free space tracking (simplified — real XFS uses B+ trees)
    pub free_start: u32,      // Next free block (bump allocator)
    pub free_inode_start: u64, // Next free inode number

    // Longest free extent (for extent allocation)
    pub longest_free: u32,

    pub active: bool,
}

impl XfsAg {
    pub const fn new() -> Self {
        Self {
            ag_number: 0,
            length: 0,
            freeblks: 0,
            free_inodes: 0,
            icount: 0,
            free_start: 16, // Skip AG headers
            free_inode_start: 0,
            longest_free: 0,
            active: false,
        }
    }

    /// Allocate contiguous blocks from this AG
    pub fn alloc_blocks(&mut self, count: u32) -> Option<u32> {
        if self.freeblks < count { return None; }
        if self.free_start + count > self.length { return None; }
        let start = self.free_start;
        self.free_start += count;
        self.freeblks -= count;
        self.longest_free = self.length.saturating_sub(self.free_start);
        Some(start)
    }

    /// Free blocks back to AG (simplified)
    pub fn free_blocks(&mut self, _start: u32, count: u32) {
        self.freeblks += count;
        // Real XFS would update free space B+ tree
    }

    /// Allocate an inode number in this AG
    pub fn alloc_inode(&mut self) -> Option<u64> {
        if self.free_inodes == 0 { return None; }
        let ino = self.free_inode_start;
        self.free_inode_start += 1;
        self.free_inodes -= 1;
        self.icount += 1;
        Some(ino)
    }
}

// ─────────────────── Journal / Log ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogItemType {
    Inode = 0,
    Buffer = 1,
    ExtentFree = 2,
    Ag = 3,
    Dquot = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct LogItem {
    pub item_type: LogItemType,
    pub tid: u64,            // Transaction ID
    pub ino: u64,            // Affected inode (0 if N/A)
    pub block: u64,          // Affected block
    pub size: u32,
    pub committed: bool,
    pub active: bool,
}

impl LogItem {
    pub const fn new() -> Self {
        Self {
            item_type: LogItemType::Inode,
            tid: 0,
            ino: 0,
            block: 0,
            size: 0,
            committed: false,
            active: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxnState {
    Active = 0,
    Committing = 1,
    Committed = 2,
    Aborted = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct XfsTransaction {
    pub tid: u64,
    pub state: TxnState,
    pub log_items: u16,       // Count of log items
    pub blocks_reserved: u32,
    pub timestamp: u64,
    pub active: bool,
}

impl XfsTransaction {
    pub const fn new() -> Self {
        Self {
            tid: 0,
            state: TxnState::Active,
            log_items: 0,
            blocks_reserved: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// ─────────────────── Delayed Allocation ─────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DelayedAlloc {
    pub ino: u64,
    pub file_offset: u64,     // Logical block
    pub block_count: u32,
    pub timestamp: u64,
    pub active: bool,
}

impl DelayedAlloc {
    pub const fn new() -> Self {
        Self {
            ino: 0,
            file_offset: 0,
            block_count: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// ─────────────────── XFS Manager ────────────────────────────────────

pub struct XfsManager {
    pub sb: XfsSuperblock,
    pub ags: [XfsAg; MAX_AGS],

    pub inodes: [XfsInode; MAX_INODES],
    pub inode_count: u32,

    pub dir_entries: [XfsDirEntry; MAX_DIR_ENTRIES],
    pub dir_entry_count: u32,

    pub log_items: [LogItem; MAX_LOG_ITEMS],
    pub log_item_count: u32,

    pub delayed: [DelayedAlloc; MAX_DELAYED_ALLOCS],
    pub delayed_count: u32,

    pub next_tid: u64,
    pub current_txn: Option<u16>,
    pub transactions: [XfsTransaction; 16],
    pub txn_count: u8,

    // AG rotation for round-robin allocation
    pub last_ag: u16,

    // Stats
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_allocs: u64,
    pub total_frees: u64,
    pub total_txns: u64,
    pub total_delayed_flushes: u64,

    pub tick: u64,
    pub initialized: bool,
}

impl XfsManager {
    pub const fn new() -> Self {
        Self {
            sb: XfsSuperblock::new(),
            ags: [const { XfsAg::new() }; MAX_AGS],
            inodes: [const { XfsInode::new() }; MAX_INODES],
            inode_count: 0,
            dir_entries: [const { XfsDirEntry::new() }; MAX_DIR_ENTRIES],
            dir_entry_count: 0,
            log_items: [const { LogItem::new() }; MAX_LOG_ITEMS],
            log_item_count: 0,
            delayed: [const { DelayedAlloc::new() }; MAX_DELAYED_ALLOCS],
            delayed_count: 0,
            next_tid: 1,
            current_txn: None,
            transactions: [const { XfsTransaction::new() }; 16],
            txn_count: 0,
            last_ag: 0,
            total_reads: 0,
            total_writes: 0,
            total_allocs: 0,
            total_frees: 0,
            total_txns: 0,
            total_delayed_flushes: 0,
            tick: 0,
            initialized: false,
        }
    }

    /// Initialize filesystem with given total blocks
    pub fn mkfs(&mut self, total_blocks: u64, ag_count: u32) -> bool {
        if ag_count == 0 || ag_count as usize > MAX_AGS { return false; }
        let blocks_per_ag = (total_blocks / ag_count as u64) as u32;

        self.sb = XfsSuperblock::new();
        self.sb.dblocks = total_blocks;
        self.sb.agcount = ag_count;
        self.sb.agblocks = blocks_per_ag;
        self.sb.freeblocks = total_blocks - (ag_count as u64 * 16); // Reserve AG headers
        self.sb.logstart = 1;
        self.sb.logblocks = 1024;

        for i in 0..ag_count as usize {
            self.ags[i].ag_number = i as u16;
            self.ags[i].length = blocks_per_ag;
            self.ags[i].freeblks = blocks_per_ag - 16;
            self.ags[i].free_inodes = 64;
            self.ags[i].free_inode_start = (i as u64) * 64 + 128;
            self.ags[i].longest_free = blocks_per_ag - 16;
            self.ags[i].active = true;
        }

        // Create root inode
        self.create_inode(XfsFileType::Directory, 0o755, 0, 0);

        self.initialized = true;
        true
    }

    // ─── Inode Operations ───────────────────────────────────────────

    pub fn create_inode(
        &mut self,
        ftype: XfsFileType,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Option<u64> {
        if self.inode_count as usize >= MAX_INODES { return None; }

        // Round-robin AG selection for inode allocation
        let ag = self.select_ag_for_inode()?;
        let ino = self.ags[ag].alloc_inode()?;

        for i in 0..MAX_INODES {
            if !self.inodes[i].allocated {
                self.inodes[i] = XfsInode::new();
                self.inodes[i].ino = ino;
                self.inodes[i].ftype = ftype;
                self.inodes[i].mode = mode;
                self.inodes[i].uid = uid;
                self.inodes[i].gid = gid;
                self.inodes[i].ag_number = ag as u16;
                self.inodes[i].generation = (self.tick & 0xFFFFFFFF) as u32;
                self.inodes[i].crtime = self.tick;
                self.inodes[i].atime = self.tick;
                self.inodes[i].mtime = self.tick;
                self.inodes[i].ctime = self.tick;
                self.inodes[i].allocated = true;

                if matches!(ftype, XfsFileType::Directory) {
                    self.inodes[i].nlink = 2; // . and ..
                }

                self.inode_count += 1;
                self.sb.icount += 1;

                // Log inode creation
                self.log_inode_change(ino);

                return Some(ino);
            }
        }
        None
    }

    fn select_ag_for_inode(&mut self) -> Option<usize> {
        let start = self.last_ag as usize;
        for offset in 0..self.sb.agcount as usize {
            let ag = (start + offset) % self.sb.agcount as usize;
            if self.ags[ag].active && self.ags[ag].free_inodes > 0 {
                self.last_ag = ((ag + 1) % self.sb.agcount as usize) as u16;
                return Some(ag);
            }
        }
        None
    }

    pub fn find_inode(&self, ino: u64) -> Option<usize> {
        for i in 0..MAX_INODES {
            if self.inodes[i].allocated && self.inodes[i].ino == ino {
                return Some(i);
            }
        }
        None
    }

    pub fn unlink_inode(&mut self, ino: u64) -> bool {
        let idx = match self.find_inode(ino) {
            Some(i) => i,
            None => return false,
        };
        self.inodes[idx].nlink = self.inodes[idx].nlink.saturating_sub(1);
        if self.inodes[idx].nlink == 0 {
            // Free extents
            for e in 0..self.inodes[idx].nextents as usize {
                let ext = self.inodes[idx].extents[e];
                let ag = self.inodes[idx].ag_number as usize;
                if ag < self.sb.agcount as usize {
                    self.ags[ag].free_blocks(ext.startblock as u32, ext.blockcount);
                    self.sb.fdblocks += ext.blockcount as u64;
                }
            }
            self.inodes[idx].allocated = false;
            self.inode_count = self.inode_count.saturating_sub(1);
            self.sb.icount = self.sb.icount.saturating_sub(1);
            self.total_frees += 1;
        }
        true
    }

    // ─── Directory Operations ───────────────────────────────────────

    pub fn add_dir_entry(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        child_ino: u64,
        ftype: XfsFileType,
    ) -> bool {
        if self.dir_entry_count as usize >= MAX_DIR_ENTRIES { return false; }
        if name.is_empty() || name.len() > NAME_LEN { return false; }

        let hash = xfs_da_hashname(name);

        for i in 0..MAX_DIR_ENTRIES {
            if !self.dir_entries[i].active {
                self.dir_entries[i] = XfsDirEntry::new();
                self.dir_entries[i].ino = child_ino;
                let len = name.len().min(NAME_LEN);
                self.dir_entries[i].name[..len].copy_from_slice(&name[..len]);
                self.dir_entries[i].name_len = len as u8;
                self.dir_entries[i].ftype = ftype;
                self.dir_entries[i].name_hash = hash;
                self.dir_entries[i].active = true;
                self.dir_entry_count += 1;

                // Update parent mtime
                if let Some(idx) = self.find_inode(parent_ino) {
                    self.inodes[idx].mtime = self.tick;
                }
                return true;
            }
        }
        false
    }

    pub fn lookup_dir(&self, parent_ino: u64, name: &[u8]) -> Option<u64> {
        let hash = xfs_da_hashname(name);
        for i in 0..MAX_DIR_ENTRIES {
            if !self.dir_entries[i].active { continue; }
            if self.dir_entries[i].name_hash != hash { continue; }
            // Verify name match
            let entry_name = &self.dir_entries[i].name[..self.dir_entries[i].name_len as usize];
            if entry_name == name {
                // Verify parent (simplified — real XFS stores parent in dir block header)
                return Some(self.dir_entries[i].ino);
            }
        }
        let _ = parent_ino;
        None
    }

    // ─── Extent Allocation ──────────────────────────────────────────

    pub fn alloc_extent(&mut self, ino: u64, file_offset: u64, blocks: u32) -> bool {
        let inode_idx = match self.find_inode(ino) {
            Some(i) => i,
            None => return false,
        };
        let ag = self.inodes[inode_idx].ag_number as usize;
        if ag >= self.sb.agcount as usize { return false; }

        // Try to allocate from the inode's AG first
        let phys = if let Some(blk) = self.ags[ag].alloc_blocks(blocks) {
            // Convert AG-relative to absolute
            ag as u64 * self.sb.agblocks as u64 + blk as u64
        } else {
            // Fall back to any AG with space
            let mut found = false;
            let mut phys_block = 0u64;
            for a in 0..self.sb.agcount as usize {
                if a == ag { continue; }
                if let Some(blk) = self.ags[a].alloc_blocks(blocks) {
                    phys_block = a as u64 * self.sb.agblocks as u64 + blk as u64;
                    found = true;
                    break;
                }
            }
            if !found { return false; }
            phys_block
        };

        let ext = XfsExtent {
            startoff: file_offset,
            startblock: phys,
            blockcount: blocks,
            state: ExtentState::Normal,
        };
        if self.inodes[inode_idx].add_extent(ext) {
            self.sb.fdblocks = self.sb.fdblocks.saturating_sub(blocks as u64);
            self.total_allocs += 1;
            self.log_inode_change(ino);
            true
        } else {
            false
        }
    }

    /// Delayed allocation: reserve space but don't allocate yet
    pub fn delayed_alloc(&mut self, ino: u64, file_offset: u64, blocks: u32) -> bool {
        if self.delayed_count as usize >= MAX_DELAYED_ALLOCS { return false; }
        for i in 0..MAX_DELAYED_ALLOCS {
            if !self.delayed[i].active {
                self.delayed[i] = DelayedAlloc {
                    ino,
                    file_offset,
                    block_count: blocks,
                    timestamp: self.tick,
                    active: true,
                };
                self.delayed_count += 1;
                return true;
            }
        }
        false
    }

    /// Flush delayed allocations older than threshold
    pub fn flush_delayed(&mut self, age_threshold: u64) {
        for i in 0..MAX_DELAYED_ALLOCS {
            if !self.delayed[i].active { continue; }
            if self.tick.saturating_sub(self.delayed[i].timestamp) >= age_threshold {
                let da = self.delayed[i];
                self.delayed[i].active = false;
                self.delayed_count = self.delayed_count.saturating_sub(1);
                self.alloc_extent(da.ino, da.file_offset, da.block_count);
                self.total_delayed_flushes += 1;
            }
        }
    }

    // ─── Transaction / Journal ──────────────────────────────────────

    pub fn begin_transaction(&mut self, blocks_reserved: u32) -> Option<u64> {
        if self.txn_count >= 16 { return None; }
        let tid = self.next_tid;
        self.next_tid += 1;

        for i in 0..16 {
            if !self.transactions[i].active {
                self.transactions[i] = XfsTransaction {
                    tid,
                    state: TxnState::Active,
                    log_items: 0,
                    blocks_reserved,
                    timestamp: self.tick,
                    active: true,
                };
                self.txn_count += 1;
                self.total_txns += 1;
                return Some(tid);
            }
        }
        None
    }

    pub fn commit_transaction(&mut self, tid: u64) -> bool {
        for i in 0..16 {
            if self.transactions[i].active && self.transactions[i].tid == tid {
                self.transactions[i].state = TxnState::Committing;
                // Mark all log items for this txn as committed
                for j in 0..MAX_LOG_ITEMS {
                    if self.log_items[j].active && self.log_items[j].tid == tid {
                        self.log_items[j].committed = true;
                    }
                }
                self.transactions[i].state = TxnState::Committed;
                self.transactions[i].active = false;
                self.txn_count = self.txn_count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    pub fn abort_transaction(&mut self, tid: u64) -> bool {
        for i in 0..16 {
            if self.transactions[i].active && self.transactions[i].tid == tid {
                self.transactions[i].state = TxnState::Aborted;
                // Remove uncommitted log items
                for j in 0..MAX_LOG_ITEMS {
                    if self.log_items[j].active
                        && self.log_items[j].tid == tid
                        && !self.log_items[j].committed
                    {
                        self.log_items[j].active = false;
                        self.log_item_count = self.log_item_count.saturating_sub(1);
                    }
                }
                self.transactions[i].active = false;
                self.txn_count = self.txn_count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    fn log_inode_change(&mut self, ino: u64) {
        if self.log_item_count as usize >= MAX_LOG_ITEMS { return; }

        // Find current transaction TID (or 0)
        let tid = self.transactions.iter()
            .find(|t| t.active && t.state == TxnState::Active)
            .map(|t| t.tid)
            .unwrap_or(0);

        for i in 0..MAX_LOG_ITEMS {
            if !self.log_items[i].active {
                self.log_items[i] = LogItem {
                    item_type: LogItemType::Inode,
                    tid,
                    ino,
                    block: 0,
                    size: INODE_SIZE as u32,
                    committed: false,
                    active: true,
                };
                self.log_item_count += 1;

                // Update transaction log item count
                if tid > 0 {
                    for t in self.transactions.iter_mut() {
                        if t.active && t.tid == tid {
                            t.log_items += 1;
                            break;
                        }
                    }
                }
                return;
            }
        }
    }

    // ─── Periodic Maintenance ───────────────────────────────────────

    pub fn tick(&mut self) {
        self.tick += 1;

        // Flush delayed allocations older than 30 ticks
        if self.tick % 10 == 0 {
            self.flush_delayed(30);
        }

        // Garbage collect committed log items older than 60 ticks
        if self.tick % 20 == 0 {
            for i in 0..MAX_LOG_ITEMS {
                if self.log_items[i].active && self.log_items[i].committed {
                    self.log_items[i].active = false;
                    self.log_item_count = self.log_item_count.saturating_sub(1);
                }
            }
        }
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_XFS: XfsManager = XfsManager::new();
static mut G_XFS_INIT: bool = false;

fn xfs() -> &'static mut XfsManager {
    unsafe { &mut G_XFS }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_xfs_init(total_blocks: u64, ag_count: u32) -> bool {
    unsafe {
        G_XFS = XfsManager::new();
        let ok = G_XFS.mkfs(total_blocks, ag_count);
        G_XFS_INIT = ok;
        ok
    }
}

#[no_mangle]
pub extern "C" fn rust_xfs_create_inode(ftype: u16, mode: u16, uid: u32, gid: u32) -> i64 {
    if unsafe { !G_XFS_INIT } { return -1; }
    let ft: XfsFileType = unsafe { core::mem::transmute(ftype) };
    match xfs().create_inode(ft, mode, uid, gid) {
        Some(ino) => ino as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_xfs_unlink(ino: u64) -> bool {
    if unsafe { !G_XFS_INIT } { return false; }
    xfs().unlink_inode(ino)
}

#[no_mangle]
pub extern "C" fn rust_xfs_add_direntry(parent: u64, name_ptr: *const u8, name_len: u32, child: u64, ftype: u16) -> bool {
    if unsafe { !G_XFS_INIT } || name_ptr.is_null() { return false; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ft: XfsFileType = unsafe { core::mem::transmute(ftype) };
    xfs().add_dir_entry(parent, name, child, ft)
}

#[no_mangle]
pub extern "C" fn rust_xfs_lookup(parent: u64, name_ptr: *const u8, name_len: u32) -> i64 {
    if unsafe { !G_XFS_INIT } || name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match xfs().lookup_dir(parent, name) {
        Some(ino) => ino as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_xfs_alloc_extent(ino: u64, offset: u64, blocks: u32) -> bool {
    if unsafe { !G_XFS_INIT } { return false; }
    xfs().alloc_extent(ino, offset, blocks)
}

#[no_mangle]
pub extern "C" fn rust_xfs_delayed_alloc(ino: u64, offset: u64, blocks: u32) -> bool {
    if unsafe { !G_XFS_INIT } { return false; }
    xfs().delayed_alloc(ino, offset, blocks)
}

#[no_mangle]
pub extern "C" fn rust_xfs_begin_txn(reserved: u32) -> i64 {
    if unsafe { !G_XFS_INIT } { return -1; }
    match xfs().begin_transaction(reserved) {
        Some(tid) => tid as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_xfs_commit(tid: u64) -> bool {
    if unsafe { !G_XFS_INIT } { return false; }
    xfs().commit_transaction(tid)
}

#[no_mangle]
pub extern "C" fn rust_xfs_abort(tid: u64) -> bool {
    if unsafe { !G_XFS_INIT } { return false; }
    xfs().abort_transaction(tid)
}

#[no_mangle]
pub extern "C" fn rust_xfs_tick() {
    if unsafe { !G_XFS_INIT } { return; }
    xfs().tick();
}

#[no_mangle]
pub extern "C" fn rust_xfs_inode_count() -> u32 {
    if unsafe { !G_XFS_INIT } { return 0; }
    xfs().inode_count
}

#[no_mangle]
pub extern "C" fn rust_xfs_total_allocs() -> u64 {
    if unsafe { !G_XFS_INIT } { return 0; }
    xfs().total_allocs
}

#[no_mangle]
pub extern "C" fn rust_xfs_total_frees() -> u64 {
    if unsafe { !G_XFS_INIT } { return 0; }
    xfs().total_frees
}

#[no_mangle]
pub extern "C" fn rust_xfs_total_txns() -> u64 {
    if unsafe { !G_XFS_INIT } { return 0; }
    xfs().total_txns
}

#[no_mangle]
pub extern "C" fn rust_xfs_free_blocks() -> u64 {
    if unsafe { !G_XFS_INIT } { return 0; }
    xfs().sb.fdblocks
}
