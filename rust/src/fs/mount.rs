// SPDX-License-Identifier: MIT
// Zxyphor Kernel — VFS Mount Framework (Rust)
//
// Mount subsystem for filesystem management:
// - Mount point tracking (mount/umount/remount)
// - Mount namespace (per-process mount views)
// - Superblock management (per-filesystem metadata)
// - Bind mounts (directory sharing across mount points)
// - Mount propagation (shared/private/slave/unbindable)
// - Mount flags (ro, nosuid, nodev, noexec, noatime, etc.)
// - Filesystem type registry
// - Pivotroot support
// - Mount statistics
// - Lazy unmount (MNT_DETACH)
// - Recursive mount handling

#![allow(dead_code)]

// ─── Constants ──────────────────────────────────────────────────────

const MAX_MOUNTS: usize = 256;
const MAX_FS_TYPES: usize = 32;
const MAX_SUPERBLOCKS: usize = 64;
const MAX_NAMESPACES: usize = 32;
const PATH_MAX: usize = 256;
const NAME_MAX: usize = 64;
const MAX_MOUNT_OPTS: usize = 128;
const MAX_NS_MOUNTS: usize = 64;

// ─── Mount Flags ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct MountFlags {
    bits: u32,
}

impl MountFlags {
    pub const NONE: u32 = 0;
    pub const RDONLY: u32 = 1 << 0;
    pub const NOSUID: u32 = 1 << 1;
    pub const NODEV: u32 = 1 << 2;
    pub const NOEXEC: u32 = 1 << 3;
    pub const SYNCHRONOUS: u32 = 1 << 4;
    pub const REMOUNT: u32 = 1 << 5;
    pub const MANDLOCK: u32 = 1 << 6;
    pub const DIRSYNC: u32 = 1 << 7;
    pub const NOATIME: u32 = 1 << 10;
    pub const NODIRATIME: u32 = 1 << 11;
    pub const BIND: u32 = 1 << 12;
    pub const MOVE: u32 = 1 << 13;
    pub const REC: u32 = 1 << 14;
    pub const SILENT: u32 = 1 << 15;
    pub const RELATIME: u32 = 1 << 21;
    pub const STRICTATIME: u32 = 1 << 24;
    pub const LAZYTIME: u32 = 1 << 25;
    pub const DETACH: u32 = 1 << 26; // MNT_DETACH
    pub const EXPIRE: u32 = 1 << 27;

    pub const fn new(bits: u32) -> Self {
        Self { bits }
    }

    pub fn has(&self, flag: u32) -> bool {
        (self.bits & flag) != 0
    }

    pub fn set(&mut self, flag: u32) {
        self.bits |= flag;
    }

    pub fn clear(&mut self, flag: u32) {
        self.bits &= !flag;
    }

    pub fn is_readonly(&self) -> bool {
        self.has(Self::RDONLY)
    }

    pub fn is_bind(&self) -> bool {
        self.has(Self::BIND)
    }
}

// ─── Mount Propagation ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MountPropagation {
    Private = 0,
    Shared = 1,
    Slave = 2,
    Unbindable = 3,
}

// ─── Filesystem Type ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FsCapability {
    Seekable = 0,
    HasDentries = 1,
    SupportsAcl = 2,
    SupportsXattr = 3,
    RequiresDev = 4,  // Needs a block device
    IsNetworkFs = 5,
    IsPseudoFs = 6,   // procfs, sysfs, etc.
    IsStackable = 7,  // overlayfs, ecryptfs
}

pub struct FsType {
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    pub capabilities: u32, // Bitmask of FsCapability
    pub max_file_size: u64,
    pub default_block_size: u32,
    pub mount_count: u32,
    pub active: bool,
}

impl FsType {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; NAME_MAX],
            name_len: 0,
            capabilities: 0,
            max_file_size: 0,
            default_block_size: 4096,
            mount_count: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(NAME_MAX - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn has_capability(&self, cap: FsCapability) -> bool {
        (self.capabilities & (1 << cap as u32)) != 0
    }

    pub fn set_capability(&mut self, cap: FsCapability) {
        self.capabilities |= 1 << cap as u32;
    }
}

// ─── Superblock ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SbState {
    Clean = 0,
    Dirty = 1,
    Frozen = 2,
    Syncing = 3,
}

pub struct Superblock {
    pub dev_id: u32,
    pub fs_type_idx: u8,
    pub block_size: u32,
    pub max_file_size: u64,
    pub flags: MountFlags,
    pub state: SbState,
    pub root_inode: u64,
    pub free_blocks: u64,
    pub total_blocks: u64,
    pub free_inodes: u64,
    pub total_inodes: u64,
    pub magic: u32,
    pub mount_count: u16,
    pub max_mount_count: u16,
    pub last_mount_time: u64,
    pub last_write_time: u64,
    pub uuid: [u8; 16],
    pub label: [u8; 32],
    pub label_len: u8,
    pub active: bool,
}

impl Superblock {
    pub const fn empty() -> Self {
        Self {
            dev_id: 0,
            fs_type_idx: 0,
            block_size: 4096,
            max_file_size: 0,
            flags: MountFlags::new(0),
            state: SbState::Clean,
            root_inode: 0,
            free_blocks: 0,
            total_blocks: 0,
            free_inodes: 0,
            total_inodes: 0,
            magic: 0,
            mount_count: 0,
            max_mount_count: 0xFFFF,
            last_mount_time: 0,
            last_write_time: 0,
            uuid: [0u8; 16],
            label: [0u8; 32],
            label_len: 0,
            active: false,
        }
    }

    pub fn usage_percent(&self) -> u8 {
        if self.total_blocks == 0 {
            return 0;
        }
        let used = self.total_blocks - self.free_blocks;
        ((used * 100) / self.total_blocks) as u8
    }

    pub fn is_full(&self) -> bool {
        self.free_blocks == 0 || self.free_inodes == 0
    }
}

// ─── Mount Entry ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MountState {
    Unmounted = 0,
    Mounted = 1,
    Mounting = 2,
    Unmounting = 3,
    Detached = 4, // Lazy unmount — still accessible but invisible
}

pub struct Mount {
    pub mount_id: u32,
    pub parent_id: i32, // -1 for root mount
    pub sb_idx: i16,    // Superblock index
    pub fs_type_idx: u8,

    pub mount_point: [u8; PATH_MAX],
    pub mount_point_len: u16,

    pub source: [u8; PATH_MAX],
    pub source_len: u16,

    pub options: [u8; MAX_MOUNT_OPTS],
    pub options_len: u8,

    pub flags: MountFlags,
    pub state: MountState,
    pub propagation: MountPropagation,

    /// For bind mounts: index of original mount
    pub bind_src: i16,

    /// Peer group ID for shared propagation
    pub peer_group: u32,
    /// Master mount index for slave propagation
    pub master_idx: i16,

    pub ns_id: u16, // Mount namespace

    // Per-mount stats
    pub total_reads: u64,
    pub total_writes: u64,
    pub mount_time: u64,

    pub active: bool,
}

impl Mount {
    pub const fn empty() -> Self {
        Self {
            mount_id: 0,
            parent_id: -1,
            sb_idx: -1,
            fs_type_idx: 0,
            mount_point: [0u8; PATH_MAX],
            mount_point_len: 0,
            source: [0u8; PATH_MAX],
            source_len: 0,
            options: [0u8; MAX_MOUNT_OPTS],
            options_len: 0,
            flags: MountFlags::new(0),
            state: MountState::Unmounted,
            propagation: MountPropagation::Private,
            bind_src: -1,
            peer_group: 0,
            master_idx: -1,
            ns_id: 0,
            total_reads: 0,
            total_writes: 0,
            mount_time: 0,
            active: false,
        }
    }

    pub fn set_mount_point(&mut self, path: &[u8]) {
        let len = path.len().min(PATH_MAX - 1);
        self.mount_point[..len].copy_from_slice(&path[..len]);
        self.mount_point_len = len as u16;
    }

    pub fn set_source(&mut self, src: &[u8]) {
        let len = src.len().min(PATH_MAX - 1);
        self.source[..len].copy_from_slice(&src[..len]);
        self.source_len = len as u16;
    }

    pub fn set_options(&mut self, opts: &[u8]) {
        let len = opts.len().min(MAX_MOUNT_OPTS - 1);
        self.options[..len].copy_from_slice(&opts[..len]);
        self.options_len = len as u8;
    }
}

// ─── Mount Namespace ────────────────────────────────────────────────

pub struct MountNamespace {
    pub ns_id: u16,
    pub mounts: [i16; MAX_NS_MOUNTS],
    pub mount_count: u16,
    pub root_mount: i16,
    pub owner_pid: i32,
    pub active: bool,
}

impl MountNamespace {
    pub const fn empty() -> Self {
        Self {
            ns_id: 0,
            mounts: [-1i16; MAX_NS_MOUNTS],
            mount_count: 0,
            root_mount: -1,
            owner_pid: 0,
            active: false,
        }
    }

    pub fn add_mount(&mut self, mount_idx: i16) -> bool {
        if self.mount_count as usize >= MAX_NS_MOUNTS {
            return false;
        }
        let m = self.mount_count as usize;
        self.mounts[m] = mount_idx;
        self.mount_count += 1;
        true
    }

    pub fn remove_mount(&mut self, mount_idx: i16) -> bool {
        for i in 0..self.mount_count as usize {
            if self.mounts[i] == mount_idx {
                let mut j = i;
                while j + 1 < self.mount_count as usize {
                    self.mounts[j] = self.mounts[j + 1];
                    j += 1;
                }
                self.mount_count -= 1;
                self.mounts[self.mount_count as usize] = -1;
                return true;
            }
        }
        false
    }
}

// ─── Mount Manager ──────────────────────────────────────────────────

pub struct MountManager {
    mounts: [Mount; MAX_MOUNTS],
    fs_types: [FsType; MAX_FS_TYPES],
    superblocks: [Superblock; MAX_SUPERBLOCKS],
    namespaces: [MountNamespace; MAX_NAMESPACES],

    next_mount_id: u32,
    next_ns_id: u16,
    next_peer_group: u32,

    mount_count: u16,
    fs_type_count: u8,
    sb_count: u8,
    ns_count: u8,

    total_mount_ops: u64,
    total_umount_ops: u64,
    total_remount_ops: u64,
    total_bind_mounts: u64,

    initialized: bool,
}

impl MountManager {
    pub const fn new() -> Self {
        Self {
            mounts: [Mount::empty(); MAX_MOUNTS],
            fs_types: [FsType::empty(); MAX_FS_TYPES],
            superblocks: [Superblock::empty(); MAX_SUPERBLOCKS],
            namespaces: [MountNamespace::empty(); MAX_NAMESPACES],
            next_mount_id: 1,
            next_ns_id: 1,
            next_peer_group: 1,
            mount_count: 0,
            fs_type_count: 0,
            sb_count: 0,
            ns_count: 0,
            total_mount_ops: 0,
            total_umount_ops: 0,
            total_remount_ops: 0,
            total_bind_mounts: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        // Register built-in filesystem types
        self.register_fs_type(b"ext4", 0x10 | 0x02 | 0x04, 1 << 46, 4096);   // RequiresDev | HasDentries | SupportsAcl
        self.register_fs_type(b"fat32", 0x10 | 0x02, 1 << 32, 4096);
        self.register_fs_type(b"tmpfs", 0x40, u64::MAX, 4096);                // IsPseudoFs
        self.register_fs_type(b"ramfs", 0x40, u64::MAX, 4096);
        self.register_fs_type(b"procfs", 0x40, 0, 4096);
        self.register_fs_type(b"sysfs", 0x40, 0, 4096);
        self.register_fs_type(b"devtmpfs", 0x40, 0, 4096);
        self.register_fs_type(b"devpts", 0x40, 0, 4096);
        self.register_fs_type(b"overlayfs", 0x80 | 0x02, u64::MAX, 4096);     // IsStackable | HasDentries
        self.register_fs_type(b"nfs", 0x20, 1 << 46, 4096);                   // IsNetworkFs
        self.register_fs_type(b"btrfs", 0x10 | 0x02 | 0x04 | 0x08, 1 << 63, 4096);
        self.register_fs_type(b"xfs", 0x10 | 0x02 | 0x04, 1 << 63, 4096);

        // Create initial mount namespace
        self.create_namespace(1);

        self.initialized = true;
    }

    // ─── Filesystem Type Registry ───────────────────────────────────

    pub fn register_fs_type(&mut self, name: &[u8], capabilities: u32, max_file_size: u64, block_size: u32) -> Option<u8> {
        if self.fs_type_count as usize >= MAX_FS_TYPES {
            return None;
        }
        let idx = self.fs_type_count as usize;
        self.fs_types[idx] = FsType::empty();
        self.fs_types[idx].set_name(name);
        self.fs_types[idx].capabilities = capabilities;
        self.fs_types[idx].max_file_size = max_file_size;
        self.fs_types[idx].default_block_size = block_size;
        self.fs_types[idx].active = true;
        self.fs_type_count += 1;
        Some(self.fs_type_count - 1)
    }

    fn find_fs_type(&self, name: &[u8]) -> Option<u8> {
        for i in 0..self.fs_type_count as usize {
            if !self.fs_types[i].active {
                continue;
            }
            let len = self.fs_types[i].name_len as usize;
            if len == name.len() && self.fs_types[i].name[..len] == *name {
                return Some(i as u8);
            }
        }
        None
    }

    // ─── Superblock ─────────────────────────────────────────────────

    fn alloc_superblock(&mut self, dev_id: u32, fs_type_idx: u8, flags: MountFlags) -> Option<i16> {
        // Check if superblock already exists for this device
        for i in 0..MAX_SUPERBLOCKS {
            if self.superblocks[i].active && self.superblocks[i].dev_id == dev_id {
                self.superblocks[i].mount_count += 1;
                return Some(i as i16);
            }
        }

        for i in 0..MAX_SUPERBLOCKS {
            if !self.superblocks[i].active {
                self.superblocks[i] = Superblock::empty();
                self.superblocks[i].dev_id = dev_id;
                self.superblocks[i].fs_type_idx = fs_type_idx;
                self.superblocks[i].flags = flags;
                self.superblocks[i].block_size = self.fs_types[fs_type_idx as usize].default_block_size;
                self.superblocks[i].max_file_size = self.fs_types[fs_type_idx as usize].max_file_size;
                self.superblocks[i].mount_count = 1;
                self.superblocks[i].active = true;
                self.sb_count += 1;
                return Some(i as i16);
            }
        }
        None
    }

    fn release_superblock(&mut self, sb_idx: i16) {
        if sb_idx < 0 || sb_idx as usize >= MAX_SUPERBLOCKS {
            return;
        }
        let i = sb_idx as usize;
        if !self.superblocks[i].active {
            return;
        }
        if self.superblocks[i].mount_count > 0 {
            self.superblocks[i].mount_count -= 1;
        }
        if self.superblocks[i].mount_count == 0 {
            self.superblocks[i].active = false;
            self.sb_count -= 1;
        }
    }

    // ─── Mount Operations ───────────────────────────────────────────

    pub fn mount(
        &mut self,
        source: &[u8],
        mount_point: &[u8],
        fs_type_name: &[u8],
        flags: u32,
        dev_id: u32,
        ns_id: u16,
    ) -> Option<i16> {
        let fs_idx = self.find_fs_type(fs_type_name)?;
        let mflags = MountFlags::new(flags);

        // Allocate superblock
        let sb_idx = self.alloc_superblock(dev_id, fs_idx, mflags)?;

        // Find free mount slot
        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].active {
                self.mounts[i] = Mount::empty();
                self.mounts[i].mount_id = self.next_mount_id;
                self.mounts[i].sb_idx = sb_idx;
                self.mounts[i].fs_type_idx = fs_idx;
                self.mounts[i].set_mount_point(mount_point);
                self.mounts[i].set_source(source);
                self.mounts[i].flags = mflags;
                self.mounts[i].state = MountState::Mounted;
                self.mounts[i].ns_id = ns_id;
                self.mounts[i].active = true;

                self.next_mount_id += 1;
                self.mount_count += 1;
                self.total_mount_ops += 1;
                self.fs_types[fs_idx as usize].mount_count += 1;

                let idx = i as i16;

                // Find parent mount
                self.mounts[i].parent_id = self.find_parent_mount(mount_point, ns_id);

                // Add to namespace
                self.ns_add_mount(ns_id, idx);

                return Some(idx);
            }
        }
        // Failed — release superblock
        self.release_superblock(sb_idx);
        None
    }

    pub fn umount(&mut self, idx: i16, lazy: bool) -> bool {
        if idx < 0 || idx as usize >= MAX_MOUNTS {
            return false;
        }
        let i = idx as usize;
        if !self.mounts[i].active || self.mounts[i].state == MountState::Unmounted {
            return false;
        }

        // Check for child mounts
        if !lazy && self.has_child_mounts(idx) {
            return false;
        }

        if lazy {
            self.mounts[i].state = MountState::Detached;
        } else {
            self.mounts[i].state = MountState::Unmounted;
            self.finalize_umount(i);
        }

        self.total_umount_ops += 1;
        true
    }

    fn finalize_umount(&mut self, i: usize) {
        let sb_idx = self.mounts[i].sb_idx;
        let fs_idx = self.mounts[i].fs_type_idx as usize;
        let ns_id = self.mounts[i].ns_id;

        // Remove from namespace
        self.ns_remove_mount(ns_id, i as i16);

        // Release superblock
        self.release_superblock(sb_idx);

        // Decrement fs type mount count
        if self.fs_types[fs_idx].mount_count > 0 {
            self.fs_types[fs_idx].mount_count -= 1;
        }

        self.mounts[i].active = false;
        self.mount_count -= 1;
    }

    pub fn remount(&mut self, idx: i16, new_flags: u32) -> bool {
        if idx < 0 || idx as usize >= MAX_MOUNTS {
            return false;
        }
        let i = idx as usize;
        if !self.mounts[i].active {
            return false;
        }
        self.mounts[i].flags = MountFlags::new(new_flags);
        // Update superblock flags too
        let sb_idx = self.mounts[i].sb_idx;
        if sb_idx >= 0 && (sb_idx as usize) < MAX_SUPERBLOCKS {
            self.superblocks[sb_idx as usize].flags = MountFlags::new(new_flags);
        }
        self.total_remount_ops += 1;
        true
    }

    pub fn bind_mount(&mut self, src_idx: i16, mount_point: &[u8], ns_id: u16) -> Option<i16> {
        if src_idx < 0 || src_idx as usize >= MAX_MOUNTS {
            return None;
        }
        if !self.mounts[src_idx as usize].active {
            return None;
        }

        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].active {
                self.mounts[i] = Mount::empty();
                self.mounts[i].mount_id = self.next_mount_id;
                self.mounts[i].sb_idx = self.mounts[src_idx as usize].sb_idx;
                self.mounts[i].fs_type_idx = self.mounts[src_idx as usize].fs_type_idx;
                self.mounts[i].set_mount_point(mount_point);
                // Copy source
                let slen = self.mounts[src_idx as usize].source_len as usize;
                self.mounts[i].source[..slen].copy_from_slice(&self.mounts[src_idx as usize].source[..slen]);
                self.mounts[i].source_len = slen as u16;
                self.mounts[i].flags = self.mounts[src_idx as usize].flags;
                self.mounts[i].flags.set(MountFlags::BIND);
                self.mounts[i].state = MountState::Mounted;
                self.mounts[i].bind_src = src_idx;
                self.mounts[i].ns_id = ns_id;
                self.mounts[i].active = true;

                self.next_mount_id += 1;
                self.mount_count += 1;
                self.total_bind_mounts += 1;

                // Bump superblock mount count
                let sb = self.mounts[i].sb_idx;
                if sb >= 0 && (sb as usize) < MAX_SUPERBLOCKS {
                    self.superblocks[sb as usize].mount_count += 1;
                }

                let idx = i as i16;
                self.ns_add_mount(ns_id, idx);
                return Some(idx);
            }
        }
        None
    }

    // ─── Propagation ────────────────────────────────────────────────

    pub fn set_propagation(&mut self, idx: i16, prop: MountPropagation) -> bool {
        if idx < 0 || idx as usize >= MAX_MOUNTS {
            return false;
        }
        if !self.mounts[idx as usize].active {
            return false;
        }
        self.mounts[idx as usize].propagation = prop;
        if prop == MountPropagation::Shared {
            self.mounts[idx as usize].peer_group = self.next_peer_group;
            self.next_peer_group += 1;
        }
        true
    }

    // ─── Namespace Operations ───────────────────────────────────────

    pub fn create_namespace(&mut self, owner_pid: i32) -> Option<u16> {
        for i in 0..MAX_NAMESPACES {
            if !self.namespaces[i].active {
                self.namespaces[i] = MountNamespace::empty();
                self.namespaces[i].ns_id = self.next_ns_id;
                self.namespaces[i].owner_pid = owner_pid;
                self.namespaces[i].active = true;
                self.next_ns_id += 1;
                self.ns_count += 1;
                return Some(self.namespaces[i].ns_id);
            }
        }
        None
    }

    pub fn clone_namespace(&mut self, src_ns_id: u16, new_owner_pid: i32) -> Option<u16> {
        let new_ns_id = self.create_namespace(new_owner_pid)?;
        // Copy mounts from source namespace
        let src_ns = self.find_ns(src_ns_id)?;
        let count = self.namespaces[src_ns].mount_count;
        for m in 0..count as usize {
            let mount_idx = self.namespaces[src_ns].mounts[m];
            if mount_idx >= 0 {
                // Clone the mount entry into the new namespace
                let new_ns = self.find_ns(new_ns_id)?;
                self.namespaces[new_ns].add_mount(mount_idx);
            }
        }
        Some(new_ns_id)
    }

    fn find_ns(&self, ns_id: u16) -> Option<usize> {
        for i in 0..MAX_NAMESPACES {
            if self.namespaces[i].active && self.namespaces[i].ns_id == ns_id {
                return Some(i);
            }
        }
        None
    }

    fn ns_add_mount(&mut self, ns_id: u16, mount_idx: i16) {
        if let Some(ns) = self.find_ns(ns_id) {
            self.namespaces[ns].add_mount(mount_idx);
        }
    }

    fn ns_remove_mount(&mut self, ns_id: u16, mount_idx: i16) {
        if let Some(ns) = self.find_ns(ns_id) {
            self.namespaces[ns].remove_mount(mount_idx);
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────

    fn has_child_mounts(&self, parent_idx: i16) -> bool {
        for i in 0..MAX_MOUNTS {
            if self.mounts[i].active && self.mounts[i].parent_id == parent_idx as i32 {
                return true;
            }
        }
        false
    }

    fn find_parent_mount(&self, path: &[u8], ns_id: u16) -> i32 {
        let mut best: i32 = -1;
        let mut best_len: usize = 0;

        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].active || self.mounts[i].ns_id != ns_id {
                continue;
            }
            let mp_len = self.mounts[i].mount_point_len as usize;
            if mp_len > 0 && mp_len <= path.len() {
                if self.mounts[i].mount_point[..mp_len] == path[..mp_len] && mp_len > best_len {
                    best_len = mp_len;
                    best = i as i32;
                }
            }
        }
        best
    }

    pub fn find_mount_by_path(&self, path: &[u8], ns_id: u16) -> Option<i16> {
        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].active || self.mounts[i].ns_id != ns_id {
                continue;
            }
            let mp_len = self.mounts[i].mount_point_len as usize;
            if mp_len == path.len() && self.mounts[i].mount_point[..mp_len] == *path {
                return Some(i as i16);
            }
        }
        None
    }

    pub fn pivot_root(&mut self, new_root_mount: i16, put_old_mount: i16, ns_id: u16) -> bool {
        if new_root_mount < 0 || put_old_mount < 0 {
            return false;
        }
        let nr = new_root_mount as usize;
        let po = put_old_mount as usize;
        if nr >= MAX_MOUNTS || po >= MAX_MOUNTS {
            return false;
        }
        if !self.mounts[nr].active || !self.mounts[po].active {
            return false;
        }

        // Update namespace root
        if let Some(ns) = self.find_ns(ns_id) {
            self.namespaces[ns].root_mount = new_root_mount;
        }
        true
    }
}

// ─── Global State ───────────────────────────────────────────────────

static mut MNT_MGR: MountManager = MountManager::new();
static mut MNT_INITIALIZED: bool = false;

fn mgr() -> &'static mut MountManager {
    unsafe { &mut MNT_MGR }
}

// ─── FFI Exports ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_mount_init() {
    let m = mgr();
    *m = MountManager::new();
    m.init();
    unsafe { MNT_INITIALIZED = true; }
}

#[no_mangle]
pub extern "C" fn rust_mount_do(
    src_ptr: *const u8, src_len: usize,
    mp_ptr: *const u8, mp_len: usize,
    fs_ptr: *const u8, fs_len: usize,
    flags: u32, dev_id: u32, ns_id: u16,
) -> i16 {
    if unsafe { !MNT_INITIALIZED } {
        return -1;
    }
    if src_ptr.is_null() || mp_ptr.is_null() || fs_ptr.is_null() {
        return -1;
    }
    let src = unsafe { core::slice::from_raw_parts(src_ptr, src_len) };
    let mp = unsafe { core::slice::from_raw_parts(mp_ptr, mp_len) };
    let fs = unsafe { core::slice::from_raw_parts(fs_ptr, fs_len) };
    mgr().mount(src, mp, fs, flags, dev_id, ns_id).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn rust_mount_umount(idx: i16, lazy: bool) -> bool {
    if unsafe { !MNT_INITIALIZED } { return false; }
    mgr().umount(idx, lazy)
}

#[no_mangle]
pub extern "C" fn rust_mount_remount(idx: i16, new_flags: u32) -> bool {
    if unsafe { !MNT_INITIALIZED } { return false; }
    mgr().remount(idx, new_flags)
}

#[no_mangle]
pub extern "C" fn rust_mount_count() -> u16 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().mount_count
}

#[no_mangle]
pub extern "C" fn rust_mount_fs_type_count() -> u8 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().fs_type_count
}

#[no_mangle]
pub extern "C" fn rust_mount_sb_count() -> u8 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().sb_count
}

#[no_mangle]
pub extern "C" fn rust_mount_ns_count() -> u8 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().ns_count
}

#[no_mangle]
pub extern "C" fn rust_mount_total_ops() -> u64 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().total_mount_ops
}

#[no_mangle]
pub extern "C" fn rust_mount_total_umount_ops() -> u64 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().total_umount_ops
}

#[no_mangle]
pub extern "C" fn rust_mount_total_bind_mounts() -> u64 {
    if unsafe { !MNT_INITIALIZED } { return 0; }
    mgr().total_bind_mounts
}
