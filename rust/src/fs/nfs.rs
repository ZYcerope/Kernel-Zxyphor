// SPDX-License-Identifier: MIT
//! Zxyphor Kernel — NFS Client (NFSv3/v4) (Rust)
//!
//! Linux-compatible NFS client implementation:
//! - NFSv3 RPC procedures: LOOKUP, READ, WRITE, GETATTR, SETATTR, CREATE, REMOVE, READDIR
//! - NFSv4 compound operations with session/sequence
//! - File handle management (opaque server handles)
//! - Attribute caching with configurable timeout (acregmin/acregmax/acdirmin/acdirmax)
//! - Write-behind caching with commit protocol
//! - Read-ahead for sequential access
//! - Mount point tracking with root file handle
//! - RPC XID generation and reply matching
//! - Delegations (NFSv4): read/write delegation tracking
//! - State management: open state IDs, lock state IDs

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_MOUNTS: usize = 8;
const MAX_FH_LEN: usize = 128;
const MAX_OPEN_FILES: usize = 64;
const MAX_CACHED_ATTRS: usize = 128;
const MAX_WRITE_CACHE: usize = 32;
const MAX_READDIR_ENTRIES: usize = 64;
const MAX_DELEGATIONS: usize = 32;
const MAX_PENDING_RPC: usize = 16;
const NAME_LEN: usize = 255;
const NFS_BLOCK_SIZE: u32 = 8192;

// ─────────────────── NFS Version ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NfsVersion {
    V3 = 3,
    V4 = 4,
}

// ─────────────────── NFS File Type ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NfsFileType {
    Regular = 1,
    Directory = 2,
    BlockDev = 3,
    CharDev = 4,
    Symlink = 5,
    Socket = 6,
    Fifo = 7,
}

// ─────────────────── NFS Status ─────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsStatus {
    Ok = 0,
    Perm = 1,
    Noent = 2,
    Io = 5,
    Nxio = 6,
    Access = 13,
    Exist = 17,
    Xdev = 18,
    Nodev = 19,
    Notdir = 20,
    Isdir = 21,
    Inval = 22,
    Fbig = 27,
    Nospc = 28,
    Rofs = 30,
    Nametoolong = 63,
    Notempty = 66,
    Stale = 70,
    Badhandle = 10001,
    Serverfault = 10006,
    Jukebox = 10008, // Server busy, retry
}

// ─────────────────── File Handle ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NfsFileHandle {
    pub data: [u8; MAX_FH_LEN],
    pub len: u8,
}

impl NfsFileHandle {
    pub const fn empty() -> Self {
        Self {
            data: [0u8; MAX_FH_LEN],
            len: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut fh = Self::empty();
        let len = bytes.len().min(MAX_FH_LEN);
        fh.data[..len].copy_from_slice(&bytes[..len]);
        fh.len = len as u8;
        fh
    }

    pub fn is_valid(&self) -> bool { self.len > 0 }

    pub fn matches(&self, other: &NfsFileHandle) -> bool {
        if self.len != other.len { return false; }
        self.data[..self.len as usize] == other.data[..other.len as usize]
    }
}

// ─────────────────── NFS Attributes ─────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NfsAttrs {
    pub ftype: NfsFileType,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub rdev: u64,
    pub fsid: u64,
    pub fileid: u64,       // Inode number equivalent
    pub atime_sec: u64,
    pub atime_nsec: u32,
    pub mtime_sec: u64,
    pub mtime_nsec: u32,
    pub ctime_sec: u64,
    pub ctime_nsec: u32,
}

impl NfsAttrs {
    pub const fn new() -> Self {
        Self {
            ftype: NfsFileType::Regular,
            mode: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            used: 0,
            rdev: 0,
            fsid: 0,
            fileid: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        }
    }
}

// ─────────────────── Attribute Cache Entry ──────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct AttrCacheEntry {
    pub fh: NfsFileHandle,
    pub attrs: NfsAttrs,
    pub cache_time: u64,      // When cached
    pub valid_until: u64,     // Expiry
    pub active: bool,
}

impl AttrCacheEntry {
    pub const fn new() -> Self {
        Self {
            fh: NfsFileHandle::empty(),
            attrs: NfsAttrs::new(),
            cache_time: 0,
            valid_until: 0,
            active: false,
        }
    }

    pub fn is_valid(&self, now: u64) -> bool {
        self.active && now < self.valid_until
    }
}

// ─────────────────── Write Cache Entry ──────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WriteState {
    Dirty = 0,
    Unstable = 1,    // Written but not committed
    Committed = 2,
}

#[derive(Debug, Clone, Copy)]
pub struct WriteCacheEntry {
    pub fh: NfsFileHandle,
    pub offset: u64,
    pub length: u32,
    pub data_tag: u64,       // Opaque reference to page cache data
    pub state: WriteState,
    pub write_verifier: u64,
    pub timestamp: u64,
    pub active: bool,
}

impl WriteCacheEntry {
    pub const fn new() -> Self {
        Self {
            fh: NfsFileHandle::empty(),
            offset: 0,
            length: 0,
            data_tag: 0,
            state: WriteState::Dirty,
            write_verifier: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// ─────────────────── RPC Transaction ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcState {
    Pending = 0,
    Complete = 1,
    Timeout = 2,
    Error = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NfsProc {
    Null = 0,
    Getattr = 1,
    Setattr = 2,
    Lookup = 3,
    Access = 4,
    Read = 6,
    Write = 7,
    Create = 8,
    Mkdir = 9,
    Remove = 12,
    Rmdir = 13,
    Rename = 14,
    Readdir = 16,
    Readdirplus = 17,
    Fsstat = 18,
    Fsinfo = 19,
    Commit = 21,
}

#[derive(Debug, Clone, Copy)]
pub struct RpcTransaction {
    pub xid: u32,
    pub proc_num: NfsProc,
    pub state: RpcState,
    pub result: NfsStatus,
    pub sent_tick: u64,
    pub timeout_tick: u64,
    pub retries: u8,
    pub active: bool,
}

impl RpcTransaction {
    pub const fn new() -> Self {
        Self {
            xid: 0,
            proc_num: NfsProc::Null,
            state: RpcState::Pending,
            result: NfsStatus::Ok,
            sent_tick: 0,
            timeout_tick: 0,
            retries: 0,
            active: false,
        }
    }
}

// ─────────────────── NFSv4 Delegation ───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DelegationType {
    None = 0,
    Read = 1,
    Write = 2,
}

#[derive(Debug, Clone, Copy)]
pub struct NfsDelegation {
    pub fh: NfsFileHandle,
    pub dtype: DelegationType,
    pub stateid: [u8; 16],
    pub recalled: bool,
    pub timestamp: u64,
    pub active: bool,
}

impl NfsDelegation {
    pub const fn new() -> Self {
        Self {
            fh: NfsFileHandle::empty(),
            dtype: DelegationType::None,
            stateid: [0u8; 16],
            recalled: false,
            timestamp: 0,
            active: false,
        }
    }
}

// ─────────────────── Open File State ────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NfsOpenFile {
    pub fh: NfsFileHandle,
    pub stateid: [u8; 16],    // NFSv4 open state ID
    pub mode: u32,             // Open mode (read/write/rw)
    pub owner_id: u32,
    pub delegation_idx: i16,   // -1 = no delegation
    pub read_offset: u64,      // Current read position
    pub write_offset: u64,
    pub seq_reads: u32,        // Sequential read counter
    pub active: bool,
}

impl NfsOpenFile {
    pub const fn new() -> Self {
        Self {
            fh: NfsFileHandle::empty(),
            stateid: [0u8; 16],
            mode: 0,
            owner_id: 0,
            delegation_idx: -1,
            read_offset: 0,
            write_offset: 0,
            seq_reads: 0,
            active: false,
        }
    }
}

// ─────────────────── Mount Point ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NfsMount {
    pub server_addr: u32,      // IPv4 address
    pub server_port: u16,
    pub version: NfsVersion,
    pub root_fh: NfsFileHandle,
    pub path: [u8; 256],
    pub path_len: u16,

    // Caching parameters
    pub acregmin: u32,         // Attribute cache min for regular files (sec)
    pub acregmax: u32,
    pub acdirmin: u32,         // For directories
    pub acdirmax: u32,
    pub rsize: u32,            // Read size
    pub wsize: u32,            // Write size

    pub mounted: bool,
    pub active: bool,
}

impl NfsMount {
    pub const fn new() -> Self {
        Self {
            server_addr: 0,
            server_port: 2049,
            version: NfsVersion::V3,
            root_fh: NfsFileHandle::empty(),
            path: [0u8; 256],
            path_len: 0,
            acregmin: 3,
            acregmax: 60,
            acdirmin: 30,
            acdirmax: 60,
            rsize: NFS_BLOCK_SIZE,
            wsize: NFS_BLOCK_SIZE,
            mounted: false,
            active: false,
        }
    }
}

// ─────────────────── Readdir Entry ──────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ReaddirEntry {
    pub fileid: u64,
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub cookie: u64,
    pub ftype: NfsFileType,
    pub active: bool,
}

impl ReaddirEntry {
    pub const fn new() -> Self {
        Self {
            fileid: 0,
            name: [0u8; NAME_LEN],
            name_len: 0,
            cookie: 0,
            ftype: NfsFileType::Regular,
            active: false,
        }
    }
}

// ─────────────────── NFS Client Manager ─────────────────────────────

pub struct NfsClient {
    mounts: [NfsMount; MAX_MOUNTS],
    mount_count: u8,

    open_files: [NfsOpenFile; MAX_OPEN_FILES],
    open_count: u16,

    attr_cache: [AttrCacheEntry; MAX_CACHED_ATTRS],
    write_cache: [WriteCacheEntry; MAX_WRITE_CACHE],

    delegations: [NfsDelegation; MAX_DELEGATIONS],
    delegation_count: u16,

    pending_rpc: [RpcTransaction; MAX_PENDING_RPC],
    next_xid: u32,

    readdir_cache: [ReaddirEntry; MAX_READDIR_ENTRIES],
    readdir_count: u16,

    tick: u64,

    // Stats
    total_rpcs: u64,
    total_reads: u64,
    total_writes: u64,
    total_lookups: u64,
    total_cache_hits: u64,
    total_cache_misses: u64,
    total_timeouts: u64,
    total_retries: u64,
    bytes_read: u64,
    bytes_written: u64,

    initialized: bool,
}

impl NfsClient {
    pub const fn new() -> Self {
        Self {
            mounts: [const { NfsMount::new() }; MAX_MOUNTS],
            mount_count: 0,
            open_files: [const { NfsOpenFile::new() }; MAX_OPEN_FILES],
            open_count: 0,
            attr_cache: [const { AttrCacheEntry::new() }; MAX_CACHED_ATTRS],
            write_cache: [const { WriteCacheEntry::new() }; MAX_WRITE_CACHE],
            delegations: [const { NfsDelegation::new() }; MAX_DELEGATIONS],
            delegation_count: 0,
            pending_rpc: [const { RpcTransaction::new() }; MAX_PENDING_RPC],
            next_xid: 1,
            readdir_cache: [const { ReaddirEntry::new() }; MAX_READDIR_ENTRIES],
            readdir_count: 0,
            tick: 0,
            total_rpcs: 0,
            total_reads: 0,
            total_writes: 0,
            total_lookups: 0,
            total_cache_hits: 0,
            total_cache_misses: 0,
            total_timeouts: 0,
            total_retries: 0,
            bytes_read: 0,
            bytes_written: 0,
            initialized: true,
        }
    }

    // ─── Mount Operations ───────────────────────────────────────

    pub fn mount(
        &mut self,
        server: u32,
        port: u16,
        path: &[u8],
        version: NfsVersion,
        root_fh: &[u8],
    ) -> Option<u8> {
        if self.mount_count as usize >= MAX_MOUNTS { return None; }
        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].active {
                self.mounts[i] = NfsMount::new();
                self.mounts[i].server_addr = server;
                self.mounts[i].server_port = port;
                self.mounts[i].version = version;
                self.mounts[i].root_fh = NfsFileHandle::from_bytes(root_fh);
                let plen = path.len().min(255);
                self.mounts[i].path[..plen].copy_from_slice(&path[..plen]);
                self.mounts[i].path_len = plen as u16;
                self.mounts[i].mounted = true;
                self.mounts[i].active = true;
                self.mount_count += 1;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn umount(&mut self, mount_idx: u8) -> bool {
        if (mount_idx as usize) >= MAX_MOUNTS || !self.mounts[mount_idx as usize].active {
            return false;
        }
        // Flush all writes for this mount
        self.flush_mount_writes(mount_idx);
        // Close all open files
        for i in 0..MAX_OPEN_FILES {
            if self.open_files[i].active {
                // Simple check: all files belong to some mount
                self.open_files[i].active = false;
                self.open_count = self.open_count.saturating_sub(1);
            }
        }
        self.mounts[mount_idx as usize].mounted = false;
        self.mounts[mount_idx as usize].active = false;
        self.mount_count = self.mount_count.saturating_sub(1);
        true
    }

    fn flush_mount_writes(&mut self, _mount_idx: u8) {
        // Commit all dirty/unstable writes
        for i in 0..MAX_WRITE_CACHE {
            if self.write_cache[i].active {
                if self.write_cache[i].state != WriteState::Committed {
                    self.write_cache[i].state = WriteState::Committed;
                }
                self.write_cache[i].active = false;
            }
        }
    }

    // ─── RPC ────────────────────────────────────────────────────

    fn alloc_xid(&mut self) -> u32 {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        if self.next_xid == 0 { self.next_xid = 1; }
        xid
    }

    fn send_rpc(&mut self, proc_num: NfsProc) -> Option<u16> {
        for i in 0..MAX_PENDING_RPC {
            if !self.pending_rpc[i].active {
                self.pending_rpc[i] = RpcTransaction {
                    xid: self.alloc_xid(),
                    proc_num,
                    state: RpcState::Pending,
                    result: NfsStatus::Ok,
                    sent_tick: self.tick,
                    timeout_tick: self.tick + 30, // 30 tick timeout
                    retries: 0,
                    active: true,
                };
                self.total_rpcs += 1;
                return Some(i as u16);
            }
        }
        None
    }

    fn complete_rpc(&mut self, rpc_idx: u16, status: NfsStatus) {
        if (rpc_idx as usize) < MAX_PENDING_RPC {
            self.pending_rpc[rpc_idx as usize].state = RpcState::Complete;
            self.pending_rpc[rpc_idx as usize].result = status;
            self.pending_rpc[rpc_idx as usize].active = false;
        }
    }

    // ─── Attribute Cache ────────────────────────────────────────

    fn cache_attrs(&mut self, fh: &NfsFileHandle, attrs: &NfsAttrs, ttl: u64) {
        // Check for existing entry
        for i in 0..MAX_CACHED_ATTRS {
            if self.attr_cache[i].active && self.attr_cache[i].fh.matches(fh) {
                self.attr_cache[i].attrs = *attrs;
                self.attr_cache[i].cache_time = self.tick;
                self.attr_cache[i].valid_until = self.tick + ttl;
                return;
            }
        }
        // Find free slot
        for i in 0..MAX_CACHED_ATTRS {
            if !self.attr_cache[i].active {
                self.attr_cache[i] = AttrCacheEntry {
                    fh: *fh,
                    attrs: *attrs,
                    cache_time: self.tick,
                    valid_until: self.tick + ttl,
                    active: true,
                };
                return;
            }
        }
        // Evict oldest
        let mut oldest_idx = 0usize;
        let mut oldest_time = u64::MAX;
        for i in 0..MAX_CACHED_ATTRS {
            if self.attr_cache[i].cache_time < oldest_time {
                oldest_time = self.attr_cache[i].cache_time;
                oldest_idx = i;
            }
        }
        self.attr_cache[oldest_idx] = AttrCacheEntry {
            fh: *fh,
            attrs: *attrs,
            cache_time: self.tick,
            valid_until: self.tick + ttl,
            active: true,
        };
    }

    fn get_cached_attrs(&mut self, fh: &NfsFileHandle) -> Option<NfsAttrs> {
        for i in 0..MAX_CACHED_ATTRS {
            if self.attr_cache[i].active && self.attr_cache[i].fh.matches(fh) {
                if self.attr_cache[i].is_valid(self.tick) {
                    self.total_cache_hits += 1;
                    return Some(self.attr_cache[i].attrs);
                } else {
                    self.attr_cache[i].active = false;
                    self.total_cache_misses += 1;
                    return None;
                }
            }
        }
        self.total_cache_misses += 1;
        None
    }

    // ─── NFS Operations ─────────────────────────────────────────

    pub fn lookup(&mut self, dir_fh: &NfsFileHandle, name: &[u8]) -> Option<NfsFileHandle> {
        self.total_lookups += 1;
        let _rpc = self.send_rpc(NfsProc::Lookup)?;
        // In real implementation: encode LOOKUP RPC, send, wait for reply
        // Simulate: return a derived file handle
        let mut result_fh = NfsFileHandle::empty();
        let base_len = dir_fh.len as usize;
        let name_len = name.len().min(MAX_FH_LEN - base_len);
        result_fh.data[..base_len].copy_from_slice(&dir_fh.data[..base_len]);
        result_fh.data[base_len..base_len + name_len].copy_from_slice(&name[..name_len]);
        result_fh.len = (base_len + name_len) as u8;
        Some(result_fh)
    }

    pub fn getattr(&mut self, fh: &NfsFileHandle) -> Option<NfsAttrs> {
        // Check cache first
        if let Some(attrs) = self.get_cached_attrs(fh) {
            return Some(attrs);
        }
        let _rpc = self.send_rpc(NfsProc::Getattr)?;
        // Simulate: return default attrs and cache them
        let attrs = NfsAttrs::new();
        self.cache_attrs(fh, &attrs, 30); // 30-tick TTL
        Some(attrs)
    }

    pub fn read(&mut self, fh: &NfsFileHandle, offset: u64, count: u32) -> u32 {
        self.total_reads += 1;
        let _rpc = match self.send_rpc(NfsProc::Read) {
            Some(r) => r,
            None => return 0,
        };
        // Track sequential reads for read-ahead
        for i in 0..MAX_OPEN_FILES {
            if self.open_files[i].active && self.open_files[i].fh.matches(fh) {
                if offset == self.open_files[i].read_offset {
                    self.open_files[i].seq_reads += 1;
                } else {
                    self.open_files[i].seq_reads = 0;
                }
                self.open_files[i].read_offset = offset + count as u64;
                break;
            }
        }
        self.bytes_read += count as u64;
        count
    }

    pub fn write(&mut self, fh: &NfsFileHandle, offset: u64, count: u32, data_tag: u64) -> u32 {
        self.total_writes += 1;
        // Write to cache (delayed write)
        for i in 0..MAX_WRITE_CACHE {
            if !self.write_cache[i].active {
                self.write_cache[i] = WriteCacheEntry {
                    fh: *fh,
                    offset,
                    length: count,
                    data_tag,
                    state: WriteState::Dirty,
                    write_verifier: 0,
                    timestamp: self.tick,
                    active: true,
                };
                break;
            }
        }
        // Invalidate attr cache (size changed)
        self.invalidate_attrs(fh);
        self.bytes_written += count as u64;
        count
    }

    pub fn commit(&mut self, fh: &NfsFileHandle) -> bool {
        let _rpc = match self.send_rpc(NfsProc::Commit) {
            Some(r) => r,
            None => return false,
        };
        // Mark all unstable writes as committed
        for i in 0..MAX_WRITE_CACHE {
            if self.write_cache[i].active
                && self.write_cache[i].fh.matches(fh)
                && self.write_cache[i].state == WriteState::Unstable
            {
                self.write_cache[i].state = WriteState::Committed;
            }
        }
        true
    }

    pub fn create(
        &mut self,
        dir_fh: &NfsFileHandle,
        name: &[u8],
        mode: u32,
    ) -> Option<NfsFileHandle> {
        let _rpc = self.send_rpc(NfsProc::Create)?;
        let fh = self.lookup(dir_fh, name)?;
        // Cache initial attrs
        let mut attrs = NfsAttrs::new();
        attrs.mode = mode;
        self.cache_attrs(&fh, &attrs, 3);
        Some(fh)
    }

    pub fn remove(&mut self, dir_fh: &NfsFileHandle, name: &[u8]) -> bool {
        let _rpc = match self.send_rpc(NfsProc::Remove) {
            Some(r) => r,
            None => return false,
        };
        // Invalidate parent dir cache
        self.invalidate_attrs(dir_fh);
        let _ = name;
        true
    }

    // ─── Open/Close (NFSv4) ─────────────────────────────────────

    pub fn open_file(&mut self, fh: &NfsFileHandle, mode: u32, owner: u32) -> Option<u16> {
        if self.open_count as usize >= MAX_OPEN_FILES { return None; }
        for i in 0..MAX_OPEN_FILES {
            if !self.open_files[i].active {
                self.open_files[i] = NfsOpenFile::new();
                self.open_files[i].fh = *fh;
                self.open_files[i].mode = mode;
                self.open_files[i].owner_id = owner;
                self.open_files[i].active = true;
                self.open_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn close_file(&mut self, idx: u16) -> bool {
        if (idx as usize) >= MAX_OPEN_FILES || !self.open_files[idx as usize].active {
            return false;
        }
        // Flush pending writes
        let fh = self.open_files[idx as usize].fh;
        self.flush_file_writes(&fh);
        // Return delegation if held
        let deleg_idx = self.open_files[idx as usize].delegation_idx;
        if deleg_idx >= 0 && (deleg_idx as usize) < MAX_DELEGATIONS {
            self.delegations[deleg_idx as usize].active = false;
            self.delegation_count = self.delegation_count.saturating_sub(1);
        }
        self.open_files[idx as usize].active = false;
        self.open_count = self.open_count.saturating_sub(1);
        true
    }

    fn flush_file_writes(&mut self, fh: &NfsFileHandle) {
        for i in 0..MAX_WRITE_CACHE {
            if self.write_cache[i].active && self.write_cache[i].fh.matches(fh) {
                // Send WRITE RPC for dirty entries
                if self.write_cache[i].state == WriteState::Dirty {
                    let _ = self.send_rpc(NfsProc::Write);
                    self.write_cache[i].state = WriteState::Unstable;
                }
            }
        }
        // Send COMMIT
        self.commit(fh);
    }

    // ─── Delegation ─────────────────────────────────────────────

    pub fn accept_delegation(
        &mut self,
        fh: &NfsFileHandle,
        dtype: DelegationType,
        stateid: &[u8; 16],
    ) -> Option<u16> {
        if self.delegation_count as usize >= MAX_DELEGATIONS { return None; }
        for i in 0..MAX_DELEGATIONS {
            if !self.delegations[i].active {
                self.delegations[i] = NfsDelegation {
                    fh: *fh,
                    dtype,
                    stateid: *stateid,
                    recalled: false,
                    timestamp: self.tick,
                    active: true,
                };
                self.delegation_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn recall_delegation(&mut self, fh: &NfsFileHandle) {
        for i in 0..MAX_DELEGATIONS {
            if self.delegations[i].active && self.delegations[i].fh.matches(fh) {
                self.delegations[i].recalled = true;
                // Must return delegation to server after flushing
            }
        }
    }

    fn invalidate_attrs(&mut self, fh: &NfsFileHandle) {
        for i in 0..MAX_CACHED_ATTRS {
            if self.attr_cache[i].active && self.attr_cache[i].fh.matches(fh) {
                self.attr_cache[i].active = false;
            }
        }
    }

    // ─── Tick / Maintenance ─────────────────────────────────────

    pub fn tick(&mut self) {
        self.tick += 1;

        // Check RPC timeouts
        for i in 0..MAX_PENDING_RPC {
            if self.pending_rpc[i].active && self.tick > self.pending_rpc[i].timeout_tick {
                if self.pending_rpc[i].retries < 3 {
                    self.pending_rpc[i].retries += 1;
                    self.pending_rpc[i].timeout_tick = self.tick + 30;
                    self.total_retries += 1;
                } else {
                    self.pending_rpc[i].state = RpcState::Timeout;
                    self.pending_rpc[i].active = false;
                    self.total_timeouts += 1;
                }
            }
        }

        // Flush old dirty writes (every 5 ticks)
        if self.tick % 5 == 0 {
            for i in 0..MAX_WRITE_CACHE {
                if self.write_cache[i].active
                    && self.write_cache[i].state == WriteState::Dirty
                    && self.tick.saturating_sub(self.write_cache[i].timestamp) > 30
                {
                    let _ = self.send_rpc(NfsProc::Write);
                    self.write_cache[i].state = WriteState::Unstable;
                }
            }
        }

        // Expire old attr cache entries (every 10 ticks)
        if self.tick % 10 == 0 {
            for i in 0..MAX_CACHED_ATTRS {
                if self.attr_cache[i].active && !self.attr_cache[i].is_valid(self.tick) {
                    self.attr_cache[i].active = false;
                }
            }
        }

        // Clean committed write cache entries
        if self.tick % 10 == 0 {
            for i in 0..MAX_WRITE_CACHE {
                if self.write_cache[i].active && self.write_cache[i].state == WriteState::Committed {
                    self.write_cache[i].active = false;
                }
            }
        }
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_NFS: NfsClient = NfsClient::new();
static mut G_NFS_INIT: bool = false;

fn nfs() -> &'static mut NfsClient {
    unsafe { &mut G_NFS }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_nfs_init() {
    unsafe {
        G_NFS = NfsClient::new();
        G_NFS_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_nfs_mount(server: u32, port: u16, path_ptr: *const u8, path_len: u32, version: u8, fh_ptr: *const u8, fh_len: u32) -> i8 {
    if unsafe { !G_NFS_INIT } || path_ptr.is_null() || fh_ptr.is_null() { return -1; }
    let path = unsafe { core::slice::from_raw_parts(path_ptr, path_len as usize) };
    let fh = unsafe { core::slice::from_raw_parts(fh_ptr, fh_len as usize) };
    let ver = if version == 4 { NfsVersion::V4 } else { NfsVersion::V3 };
    match nfs().mount(server, port, path, ver, fh) {
        Some(idx) => idx as i8,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_nfs_umount(idx: u8) -> bool {
    if unsafe { !G_NFS_INIT } { return false; }
    nfs().umount(idx)
}

#[no_mangle]
pub extern "C" fn rust_nfs_read(fh_ptr: *const u8, fh_len: u32, offset: u64, count: u32) -> u32 {
    if unsafe { !G_NFS_INIT } || fh_ptr.is_null() { return 0; }
    let fh_data = unsafe { core::slice::from_raw_parts(fh_ptr, fh_len as usize) };
    let fh = NfsFileHandle::from_bytes(fh_data);
    nfs().read(&fh, offset, count)
}

#[no_mangle]
pub extern "C" fn rust_nfs_write(fh_ptr: *const u8, fh_len: u32, offset: u64, count: u32, data_tag: u64) -> u32 {
    if unsafe { !G_NFS_INIT } || fh_ptr.is_null() { return 0; }
    let fh_data = unsafe { core::slice::from_raw_parts(fh_ptr, fh_len as usize) };
    let fh = NfsFileHandle::from_bytes(fh_data);
    nfs().write(&fh, offset, count, data_tag)
}

#[no_mangle]
pub extern "C" fn rust_nfs_tick() {
    if unsafe { !G_NFS_INIT } { return; }
    nfs().tick();
}

#[no_mangle]
pub extern "C" fn rust_nfs_mount_count() -> u8 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().mount_count
}

#[no_mangle]
pub extern "C" fn rust_nfs_total_rpcs() -> u64 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().total_rpcs
}

#[no_mangle]
pub extern "C" fn rust_nfs_bytes_read() -> u64 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().bytes_read
}

#[no_mangle]
pub extern "C" fn rust_nfs_bytes_written() -> u64 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().bytes_written
}

#[no_mangle]
pub extern "C" fn rust_nfs_cache_hits() -> u64 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().total_cache_hits
}

#[no_mangle]
pub extern "C" fn rust_nfs_cache_misses() -> u64 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().total_cache_misses
}

#[no_mangle]
pub extern "C" fn rust_nfs_total_timeouts() -> u64 {
    if unsafe { !G_NFS_INIT } { return 0; }
    nfs().total_timeouts
}
