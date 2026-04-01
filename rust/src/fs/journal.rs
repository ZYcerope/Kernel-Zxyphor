// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Journal & Block Logging Filesystem Layer
//
// Write-ahead journal for filesystem crash consistency:
// - Transaction-based journaling (ordered, writeback, data modes)
// - Log records: metadata, data blocks, commit/abort
// - Checkpoint / replay after crash
// - Journal superblock management
// - Block group descriptors
// - Inode journaling
// - Revoke records for freed blocks

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────
pub const JOURNAL_MAGIC: u32 = 0x5A584A4C; // "ZXJL"
pub const JOURNAL_VERSION: u32 = 2;
pub const BLOCK_SIZE: u32 = 4096;
pub const MAX_JOURNAL_BLOCKS: u32 = 32768; // 128 MiB journal max
pub const MAX_TRANSACTIONS: usize = 64;
pub const MAX_BLOCKS_PER_TXN: usize = 256;
pub const MAX_REVOKE_PER_TXN: usize = 128;
pub const COMMIT_TIMEOUT_MS: u64 = 5000;

// ─────────────────── Journal Modes ──────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JournalMode {
    /// Journal metadata only; data written before metadata commit
    Ordered,
    /// Journal metadata only; no ordering guarantee for data
    Writeback,
    /// Journal both metadata and data blocks
    Data,
}

// ─────────────────── Record Types ───────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum RecordType {
    Descriptor = 1,
    Commit = 2,
    SuperblockV1 = 3,
    SuperblockV2 = 4,
    Revoke = 5,
    Abort = 6,
}

impl RecordType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Descriptor),
            2 => Some(Self::Commit),
            3 => Some(Self::SuperblockV1),
            4 => Some(Self::SuperblockV2),
            5 => Some(Self::Revoke),
            6 => Some(Self::Abort),
            _ => None,
        }
    }
}

// ─────────────────── On-Disk Structures ─────────────────────────────
/// Journal block header (common to all journal blocks)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalBlockHeader {
    pub magic: u32,
    pub block_type: u32,
    pub sequence: u32,
}

impl JournalBlockHeader {
    pub fn new(block_type: RecordType, sequence: u32) -> Self {
        Self {
            magic: JOURNAL_MAGIC,
            block_type: block_type as u32,
            sequence,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == JOURNAL_MAGIC && RecordType::from_u32(self.block_type).is_some()
    }
}

/// Journal superblock (stored at block 0 of journal)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalSuperblock {
    pub header: JournalBlockHeader,
    pub journal_size: u32,      // total journal blocks
    pub first_block: u32,       // first usable log block
    pub sequence: u32,          // next expected sequence
    pub start: u32,             // block of first pending transaction
    pub error_no: i32,          // error state (0 = ok)
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [16]u8,
    pub nr_users: u32,
    pub max_transaction: u32,   // max blocks per transaction
    pub checksum_type: u8,      // 1=CRC32
    _padding: [3]u8,
    pub checksum: u32,
}

impl JournalSuperblock {
    pub fn new(size: u32) -> Self {
        Self {
            header: JournalBlockHeader::new(RecordType::SuperblockV2, 0),
            journal_size: size,
            first_block: 1,
            sequence: 1,
            start: 0,
            error_no: 0,
            feature_compat: 0,
            feature_incompat: 0,
            feature_ro_compat: 0,
            uuid: [0u8; 16],
            nr_users: 1,
            max_transaction: MAX_BLOCKS_PER_TXN as u32,
            checksum_type: 1,
            _padding: [0u8; 3],
            checksum: 0,
        }
    }
}

/// Descriptor block entry — maps journal block to filesystem block
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DescriptorEntry {
    pub fs_block: u64,
    pub flags: u32,
    pub checksum: u32,
}

pub const DESC_FLAG_ESCAPE: u32 = 0x01;      // block contains journal magic
pub const DESC_FLAG_SAME_UUID: u32 = 0x02;   // same UUID as journal
pub const DESC_FLAG_DELETED: u32 = 0x04;     // revoked
pub const DESC_FLAG_LAST: u32 = 0x08;        // last entry in descriptor

/// Commit block
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitBlock {
    pub header: JournalBlockHeader,
    pub checksum_type: u8,
    pub checksum_size: u8,
    _padding: [2]u8,
    pub checksum: [4]u32,       // CRC32 of transaction data
    pub commit_time_sec: u64,
    pub commit_time_nsec: u32,
}

impl CommitBlock {
    pub fn new(seq: u32, time_sec: u64) -> Self {
        Self {
            header: JournalBlockHeader::new(RecordType::Commit, seq),
            checksum_type: 1,
            checksum_size: 4,
            _padding: [0u8; 2],
            checksum: [0u32; 4],
            commit_time_sec: time_sec,
            commit_time_nsec: 0,
        }
    }
}

/// Revoke block — lists filesystem blocks that should NOT be replayed
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RevokeBlockHeader {
    pub header: JournalBlockHeader,
    pub count: u32,             // number of revoked block numbers
}

// ─────────────────── Transaction ────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TxnState {
    Free,
    Running,
    Locked,      // no more updates, preparing to commit
    Flush,       // data blocks being written
    Commit,      // commit record being written
    Finished,    // committed, waiting for checkpoint
    Checkpoint,  // being checkpointed to disk
}

#[derive(Clone, Copy)]
pub struct JournalBuffer {
    pub fs_block: u64,
    pub journal_block: u32,
    pub dirty: bool,
    pub escaped: bool,   // contains journal magic, needs escaping
    pub data: [u8; 64],  // first 64 bytes for quick checks (in real kernel: full block ptr)
}

impl JournalBuffer {
    pub const fn empty() -> Self {
        Self {
            fs_block: 0,
            journal_block: 0,
            dirty: false,
            escaped: false,
            data: [0u8; 64],
        }
    }
}

pub struct Transaction {
    pub id: u32,
    pub sequence: u32,
    pub state: TxnState,
    pub start_time_ms: u64,
    /// Buffers in this transaction
    pub buffers: [JournalBuffer; MAX_BLOCKS_PER_TXN],
    pub buffer_count: usize,
    /// Revoked blocks
    pub revoked: [u64; MAX_REVOKE_PER_TXN],
    pub revoke_count: usize,
    /// Statistics
    pub logged_bytes: u64,
    pub started_ms: u64,
    pub committed_ms: u64,
}

impl Transaction {
    pub const fn new() -> Self {
        Self {
            id: 0,
            sequence: 0,
            state: TxnState::Free,
            start_time_ms: 0,
            buffers: [JournalBuffer::empty(); MAX_BLOCKS_PER_TXN],
            buffer_count: 0,
            revoked: [0u64; MAX_REVOKE_PER_TXN],
            revoke_count: 0,
            logged_bytes: 0,
            started_ms: 0,
            committed_ms: 0,
        }
    }

    pub fn begin(&mut self, seq: u32, now_ms: u64) {
        self.sequence = seq;
        self.state = TxnState::Running;
        self.start_time_ms = now_ms;
        self.started_ms = now_ms;
        self.buffer_count = 0;
        self.revoke_count = 0;
        self.logged_bytes = 0;
    }

    /// Add a filesystem block to this transaction
    pub fn add_block(&mut self, fs_block: u64, data_prefix: &[u8]) -> bool {
        if self.state != TxnState::Running {
            return false;
        }
        if self.buffer_count >= MAX_BLOCKS_PER_TXN {
            return false;
        }

        // Check if already tracked
        for i in 0..self.buffer_count {
            if self.buffers[i].fs_block == fs_block {
                self.buffers[i].dirty = true;
                return true;
            }
        }

        let mut buf = JournalBuffer::empty();
        buf.fs_block = fs_block;
        buf.dirty = true;

        // Copy prefix data for checksum/escape detection
        let copy_len = data_prefix.len().min(64);
        buf.data[..copy_len].copy_from_slice(&data_prefix[..copy_len]);

        // Check if block starts with journal magic (needs escaping)
        if copy_len >= 4 {
            let magic = u32::from_be_bytes([buf.data[0], buf.data[1], buf.data[2], buf.data[3]]);
            buf.escaped = magic == JOURNAL_MAGIC;
        }

        self.buffers[self.buffer_count] = buf;
        self.buffer_count += 1;
        self.logged_bytes += BLOCK_SIZE as u64;
        true
    }

    /// Revoke a filesystem block (freed during this transaction)
    pub fn revoke_block(&mut self, fs_block: u64) -> bool {
        if self.revoke_count >= MAX_REVOKE_PER_TXN {
            return false;
        }
        // Avoid duplicates
        for i in 0..self.revoke_count {
            if self.revoked[i] == fs_block {
                return true;
            }
        }
        self.revoked[self.revoke_count] = fs_block;
        self.revoke_count += 1;
        true
    }

    pub fn lock(&mut self) {
        self.state = TxnState::Locked;
    }

    pub fn set_flush(&mut self) {
        self.state = TxnState::Flush;
    }

    pub fn set_commit(&mut self) {
        self.state = TxnState::Commit;
    }

    pub fn finish(&mut self, now_ms: u64) {
        self.state = TxnState::Finished;
        self.committed_ms = now_ms;
    }
}

// ─────────────────── Journal Engine ─────────────────────────────────
pub struct Journal {
    /// Journal device/partition block offset
    pub dev_offset: u64,
    pub superblock: JournalSuperblock,
    pub mode: JournalMode,

    /// Log position
    pub log_head: u32,    // write position
    pub log_tail: u32,    // oldest un-checkpointed
    pub log_free: u32,    // free blocks in journal

    /// Transaction pool
    pub transactions: [Transaction; MAX_TRANSACTIONS],
    pub running_txn_id: Option<u32>,
    pub next_sequence: u32,

    /// Commit timer
    pub last_commit_ms: u64,
    pub commit_interval_ms: u64,

    /// Recovery
    pub needs_recovery: bool,
    pub recovery_sequence: u32,

    /// State
    pub mounted: AtomicBool,
    pub barrier: AtomicBool,

    /// Statistics
    pub total_commits: AtomicU64,
    pub total_blocks_logged: AtomicU64,
    pub total_revokes: AtomicU64,
}

impl Journal {
    pub fn new(dev_offset: u64, journal_blocks: u32, mode: JournalMode) -> Self {
        Self {
            dev_offset,
            superblock: JournalSuperblock::new(journal_blocks),
            mode,
            log_head: 1, // block 0 is superblock
            log_tail: 1,
            log_free: journal_blocks.saturating_sub(1),
            transactions: [const { Transaction::new() }; MAX_TRANSACTIONS],
            running_txn_id: None,
            next_sequence: 1,
            last_commit_ms: 0,
            commit_interval_ms: COMMIT_TIMEOUT_MS,
            needs_recovery: false,
            recovery_sequence: 0,
            mounted: AtomicBool::new(false),
            barrier: AtomicBool::new(false),
            total_commits: AtomicU64::new(0),
            total_blocks_logged: AtomicU64::new(0),
            total_revokes: AtomicU64::new(0),
        }
    }

    /// Load journal superblock and check for recovery
    pub fn load(&mut self) -> bool {
        // In a real kernel: read block 0 from journal device
        if !self.superblock.header.is_valid() {
            return false;
        }
        self.next_sequence = self.superblock.sequence;
        self.log_tail = self.superblock.start;

        // Check if recovery is needed (tail != head implies pending txns)
        if self.superblock.start != 0 {
            self.needs_recovery = true;
            self.recovery_sequence = self.superblock.sequence;
        }

        self.mounted.store(true, Ordering::Release);
        true
    }

    /// Replay uncommitted transactions after crash
    pub fn recover(&mut self) -> i32 {
        if !self.needs_recovery {
            return 0;
        }

        let mut block = self.superblock.start;
        let mut expected_seq = self.recovery_sequence;
        let mut revoke_set: [u64; 4096] = [0u64; 4096];
        let mut revoke_count: usize = 0;
        let mut replayed: u32 = 0;

        // Pass 1: Scan for revoke records
        let mut scan_block = block;
        for _ in 0..self.superblock.journal_size {
            if scan_block >= self.superblock.journal_size {
                scan_block = self.superblock.first_block;
            }
            // In real kernel: read journal block, check header
            // If it's a revoke record, add to revoke set
            // For now, simulate
            scan_block = self.wrap_block(scan_block + 1);
        }

        // Pass 2: Replay non-revoked descriptor blocks
        for _ in 0..self.superblock.journal_size {
            if block >= self.superblock.journal_size {
                block = self.superblock.first_block;
            }

            // Check if this is a descriptor + data blocks for a committed txn
            // Skip if the write target is in the revoke set
            let mut is_revoked = false;
            for i in 0..revoke_count {
                if revoke_set[i] == block as u64 {
                    is_revoked = true;
                    break;
                }
            }

            if !is_revoked {
                // Would copy journal block -> filesystem block
                replayed += 1;
            }

            block = self.wrap_block(block + 1);
            if block == self.log_head {
                break;
            }
        }

        // Update superblock
        self.superblock.start = 0;
        self.superblock.sequence = expected_seq;
        self.needs_recovery = false;

        // Suppress unused warning
        _ = revoke_count;
        _ = expected_seq;

        replayed as i32
    }

    /// Start a new transaction
    pub fn begin_transaction(&mut self, now_ms: u64) -> Option<u32> {
        if self.running_txn_id.is_some() {
            return self.running_txn_id;
        }

        // Find free transaction slot
        for (i, txn) in self.transactions.iter_mut().enumerate() {
            if txn.state == TxnState::Free {
                let seq = self.next_sequence;
                self.next_sequence += 1;
                txn.id = i as u32;
                txn.begin(seq, now_ms);
                self.running_txn_id = Some(i as u32);
                return Some(i as u32);
            }
        }
        None
    }

    /// Add a metadata block to the running transaction
    pub fn journal_block(&mut self, fs_block: u64, data: &[u8]) -> bool {
        if let Some(id) = self.running_txn_id {
            let idx = id as usize;
            if idx < MAX_TRANSACTIONS {
                let result = self.transactions[idx].add_block(fs_block, data);
                if result {
                    self.total_blocks_logged.fetch_add(1, Ordering::Relaxed);
                }
                return result;
            }
        }
        false
    }

    /// Revoke a block in the running transaction
    pub fn revoke_block(&mut self, fs_block: u64) -> bool {
        if let Some(id) = self.running_txn_id {
            let idx = id as usize;
            if idx < MAX_TRANSACTIONS {
                let result = self.transactions[idx].revoke_block(fs_block);
                if result {
                    self.total_revokes.fetch_add(1, Ordering::Relaxed);
                }
                return result;
            }
        }
        false
    }

    /// Commit the running transaction
    pub fn commit(&mut self, now_ms: u64) -> bool {
        let id = match self.running_txn_id.take() {
            Some(id) => id,
            None => return false,
        };

        let idx = id as usize;
        if idx >= MAX_TRANSACTIONS {
            return false;
        }

        let txn = &mut self.transactions[idx];
        txn.lock();

        // Check space
        let needed = txn.buffer_count as u32 + 2; // +1 descriptor, +1 commit
        if needed > self.log_free {
            txn.state = TxnState::Free;
            return false;
        }

        // Phase 1: Write descriptor block
        let desc_block = self.log_head;
        self.advance_head();

        // Phase 2: Write data blocks
        txn.set_flush();
        for i in 0..txn.buffer_count {
            txn.buffers[i].journal_block = self.log_head;
            self.advance_head();
        }

        // Phase 3: Write revoke record (if any)
        if txn.revoke_count > 0 {
            self.advance_head();
        }

        // Phase 4: Write commit block
        txn.set_commit();
        let _commit_block = self.log_head;
        self.advance_head();

        // Finalize
        txn.finish(now_ms);
        self.last_commit_ms = now_ms;
        self.total_commits.fetch_add(1, Ordering::Relaxed);

        // Update superblock
        self.superblock.sequence = self.next_sequence;
        if self.superblock.start == 0 {
            self.superblock.start = desc_block;
        }

        true
    }

    /// Checkpoint: write committed data to final filesystem locations
    pub fn checkpoint(&mut self) -> u32 {
        let mut checkpointed: u32 = 0;

        for txn in self.transactions.iter_mut() {
            if txn.state == TxnState::Finished {
                // In real kernel: write each buffer to its fs_block location
                for i in 0..txn.buffer_count {
                    let _buf = &txn.buffers[i];
                    // write_to_disk(buf.fs_block, buf.data) — would happen here
                    checkpointed += 1;
                }
                txn.state = TxnState::Free;
            }
        }

        // Advance tail to reclaim journal space
        if checkpointed > 0 {
            self.recalc_tail();
        }

        checkpointed
    }

    /// Abort the running transaction
    pub fn abort(&mut self) {
        if let Some(id) = self.running_txn_id.take() {
            let idx = id as usize;
            if idx < MAX_TRANSACTIONS {
                self.transactions[idx].state = TxnState::Free;
            }
        }
    }

    /// Check if commit timer has expired
    pub fn needs_commit(&self, now_ms: u64) -> bool {
        if self.running_txn_id.is_some() {
            return now_ms - self.last_commit_ms >= self.commit_interval_ms;
        }
        false
    }

    fn advance_head(&mut self) {
        self.log_head = self.wrap_block(self.log_head + 1);
        self.log_free = self.log_free.saturating_sub(1);
    }

    fn wrap_block(&self, block: u32) -> u32 {
        if block >= self.superblock.journal_size {
            self.superblock.first_block
        } else {
            block
        }
    }

    fn recalc_tail(&mut self) {
        // Find oldest pending transaction
        let mut oldest_block = self.log_head;
        for txn in self.transactions.iter() {
            if txn.state != TxnState::Free {
                if txn.buffer_count > 0 {
                    let first = txn.buffers[0].journal_block;
                    if first < oldest_block {
                        oldest_block = first;
                    }
                }
            }
        }
        self.log_tail = oldest_block;
        self.superblock.start = if oldest_block == self.log_head { 0 } else { oldest_block };

        // Recalculate free space
        if self.log_head >= self.log_tail {
            self.log_free = self.superblock.journal_size - (self.log_head - self.log_tail) - 1;
        } else {
            self.log_free = self.log_tail - self.log_head - 1;
        }
    }

    pub fn stats(&self) -> JournalStats {
        JournalStats {
            total_commits: self.total_commits.load(Ordering::Relaxed),
            total_blocks_logged: self.total_blocks_logged.load(Ordering::Relaxed),
            total_revokes: self.total_revokes.load(Ordering::Relaxed),
            log_head: self.log_head,
            log_tail: self.log_tail,
            free_blocks: self.log_free,
            journal_size: self.superblock.journal_size,
        }
    }
}

#[repr(C)]
pub struct JournalStats {
    pub total_commits: u64,
    pub total_blocks_logged: u64,
    pub total_revokes: u64,
    pub log_head: u32,
    pub log_tail: u32,
    pub free_blocks: u32,
    pub journal_size: u32,
}

// ─────────────────── CRC32 for Journal ──────────────────────────────
pub fn journal_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub fn journal_crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            if c & 1 != 0 {
                c = (c >> 1) ^ 0xEDB88320;
            } else {
                c >>= 1;
            }
        }
    }
    !c
}

// ─────────────────── FFI Exports ────────────────────────────────────
static mut GLOBAL_JOURNAL: Option<Journal> = None;

#[no_mangle]
pub extern "C" fn rust_journal_init(dev_offset: u64, size_blocks: u32, mode: u8) -> bool {
    let jmode = match mode {
        0 => JournalMode::Ordered,
        1 => JournalMode::Writeback,
        2 => JournalMode::Data,
        _ => JournalMode::Ordered,
    };
    unsafe {
        GLOBAL_JOURNAL = Some(Journal::new(dev_offset, size_blocks, jmode));
    }
    true
}

#[no_mangle]
pub extern "C" fn rust_journal_begin(now_ms: u64) -> i32 {
    unsafe {
        if let Some(ref mut j) = GLOBAL_JOURNAL {
            return match j.begin_transaction(now_ms) {
                Some(id) => id as i32,
                None => -1,
            };
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn rust_journal_add_block(fs_block: u64) -> bool {
    unsafe {
        if let Some(ref mut j) = GLOBAL_JOURNAL {
            return j.journal_block(fs_block, &[]);
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_journal_commit(now_ms: u64) -> bool {
    unsafe {
        if let Some(ref mut j) = GLOBAL_JOURNAL {
            return j.commit(now_ms);
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_journal_checkpoint() -> u32 {
    unsafe {
        if let Some(ref mut j) = GLOBAL_JOURNAL {
            return j.checkpoint();
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn rust_journal_recover() -> i32 {
    unsafe {
        if let Some(ref mut j) = GLOBAL_JOURNAL {
            return j.recover();
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn rust_journal_total_commits() -> u64 {
    unsafe {
        if let Some(ref j) = GLOBAL_JOURNAL {
            return j.total_commits.load(Ordering::Relaxed);
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn rust_journal_crc32(data: *const u8, len: usize) -> u32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    journal_crc32(slice)
}
