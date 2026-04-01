// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Overlay Filesystem (Rust)
//
// Union/overlay filesystem stacking:
// - OverlayFS merge of upper + lower layers
// - Copy-up on write (COW) from lower → upper
// - Opaque directory markers for whiteout
// - Directory merge with dedup
// - Inode mapping between layers
// - Redirect support for renamed directories
// - Metacopy optimization (metadata-only copy-up)
// - Read-only lower layers, single writable upper
// - xattr trust.overlay.* for whiteout/opaque/redirect

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_LAYERS: usize = 8;
const MAX_ENTRIES: usize = 512;
const MAX_PATH_LEN: usize = 256;
const MAX_INODES: usize = 1024;
const MAX_WHITEOUTS: usize = 256;
const NAME_MAX: usize = 64;
const XATTR_MAX: usize = 128;

// ─────────────────── Layer ──────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum LayerType {
    Lower = 0,
    Upper = 1,
    Work = 2,  // scratch area for atomic copy-up
}

#[derive(Clone, Copy)]
pub struct Layer {
    pub layer_type: LayerType,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    pub readonly: bool,
    pub inode_base: u64,  // Base inode number for this layer
    pub entry_count: u32,
    pub active: bool,
}

impl Layer {
    pub const fn empty() -> Self {
        Self {
            layer_type: LayerType::Lower,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            readonly: true,
            inode_base: 0,
            entry_count: 0,
            active: false,
        }
    }

    pub fn set_path(&mut self, p: &[u8]) {
        let len = if p.len() < MAX_PATH_LEN { p.len() } else { MAX_PATH_LEN };
        self.path[..len].copy_from_slice(&p[..len]);
        self.path_len = len;
    }
}

// ─────────────────── Inode types ────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum OvlFileType {
    Regular = 0,
    Directory = 1,
    Symlink = 2,
    Whiteout = 3,
    Opaque = 4,  // Opaque directory (hides lower)
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CopyUpState {
    None = 0,
    Pending = 1,
    InProgress = 2,
    MetacopyDone = 3,  // Only metadata copied
    Complete = 4,
}

/// Overlay inode — maps overlay view to real inode on a layer
#[derive(Clone, Copy)]
pub struct OvlInode {
    pub ino: u64,           // Overlay inode number
    pub real_ino: u64,      // Real inode on backing layer
    pub layer_idx: u8,      // Which layer this resolves to
    pub file_type: OvlFileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub nlink: u32,
    pub mtime: u64,
    pub ctime: u64,
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    pub parent_ino: u64,
    pub copy_up: CopyUpState,
    pub has_redirect: bool,
    pub redirect_path: [u8; MAX_PATH_LEN],
    pub redirect_len: usize,
    pub metacopy: bool,     // Metacopy (metadata only, data read from lower)
    pub origin_set: bool,   // Has origin xattr pointing to lower
    pub active: bool,
}

impl OvlInode {
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            real_ino: 0,
            layer_idx: 0,
            file_type: OvlFileType::Regular,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 1,
            mtime: 0,
            ctime: 0,
            name: [0u8; NAME_MAX],
            name_len: 0,
            parent_ino: 0,
            copy_up: CopyUpState::None,
            has_redirect: false,
            redirect_path: [0u8; MAX_PATH_LEN],
            redirect_len: 0,
            metacopy: false,
            origin_set: false,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() < NAME_MAX { n.len() } else { NAME_MAX };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn is_dir(&self) -> bool {
        self.file_type == OvlFileType::Directory
    }

    pub fn is_whiteout(&self) -> bool {
        self.file_type == OvlFileType::Whiteout
    }

    pub fn is_opaque(&self) -> bool {
        self.file_type == OvlFileType::Opaque
    }

    pub fn needs_copy_up(&self) -> bool {
        self.copy_up == CopyUpState::None && self.layer_idx != 0
    }

    pub fn set_redirect(&mut self, path: &[u8]) {
        let len = if path.len() < MAX_PATH_LEN { path.len() } else { MAX_PATH_LEN };
        self.redirect_path[..len].copy_from_slice(&path[..len]);
        self.redirect_len = len;
        self.has_redirect = true;
    }
}

// ─────────────────── Whiteout ───────────────────────────────────────

/// Whiteout entry hides a lower-layer dentry
#[derive(Clone, Copy)]
pub struct Whiteout {
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    pub parent_ino: u64,
    pub active: bool,
}

impl Whiteout {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; NAME_MAX],
            name_len: 0,
            parent_ino: 0,
            active: false,
        }
    }
}

// ─────────────────── DirEntry for merge ─────────────────────────────

#[derive(Clone, Copy)]
pub struct OvlDirEntry {
    pub name: [u8; NAME_MAX],
    pub name_len: u8,
    pub ino: u64,
    pub file_type: OvlFileType,
    pub layer_idx: u8,
    pub visible: bool,
}

impl OvlDirEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; NAME_MAX],
            name_len: 0,
            ino: 0,
            file_type: OvlFileType::Regular,
            layer_idx: 0,
            visible: false,
        }
    }

    pub fn name_matches(&self, other: &[u8]) -> bool {
        if self.name_len as usize != other.len() {
            return false;
        }
        let len = self.name_len as usize;
        self.name[..len] == other[..len]
    }
}

// ─────────────────── Overlay Filesystem ─────────────────────────────

pub struct OverlayFs {
    pub layers: [Layer; MAX_LAYERS],
    pub layer_count: u8,
    pub upper_idx: i8,  // -1 if read-only overlay
    pub work_idx: i8,

    pub inodes: [OvlInode; MAX_INODES],
    pub inode_count: u32,
    pub next_ino: u64,

    pub whiteouts: [Whiteout; MAX_WHITEOUTS],
    pub whiteout_count: u32,

    // Merged dir cache
    pub dir_cache: [OvlDirEntry; MAX_ENTRIES],
    pub dir_cache_count: u32,

    // Mount options
    pub redirect_dir: bool,     // Allow redirect on directory rename
    pub metacopy: bool,         // Enable metacopy optimization
    pub nfs_export: bool,       // Enable NFS export support
    pub index: bool,            // Enable index directory
    pub volatile_mount: bool,   // Skip sync on crash (perf option)

    // Statistics
    pub total_lookups: u64,
    pub total_copyups: u64,
    pub total_metacopyups: u64,
    pub total_whiteouts_created: u64,
    pub total_dir_merges: u64,
    pub total_reads: u64,
    pub total_writes: u64,

    pub initialized: bool,
}

impl OverlayFs {
    pub fn new() -> Self {
        Self {
            layers: [Layer::empty(); MAX_LAYERS],
            layer_count: 0,
            upper_idx: -1,
            work_idx: -1,
            inodes: {
                let mut arr = [OvlInode::empty(); MAX_INODES];
                // Root inode
                arr[0].ino = 1;
                arr[0].file_type = OvlFileType::Directory;
                arr[0].mode = 0o755;
                arr[0].nlink = 2;
                arr[0].active = true;
                arr[0].name[0] = b'/';
                arr[0].name_len = 1;
                arr
            },
            inode_count: 1,
            next_ino: 2,
            whiteouts: [Whiteout::empty(); MAX_WHITEOUTS],
            whiteout_count: 0,
            dir_cache: [OvlDirEntry::empty(); MAX_ENTRIES],
            dir_cache_count: 0,
            redirect_dir: true,
            metacopy: true,
            nfs_export: false,
            index: false,
            volatile_mount: false,
            total_lookups: 0,
            total_copyups: 0,
            total_metacopyups: 0,
            total_whiteouts_created: 0,
            total_dir_merges: 0,
            total_reads: 0,
            total_writes: 0,
            initialized: true,
        }
    }

    // ─── Layer Management ───────────────────────────────────────────

    pub fn add_lower(&mut self, path: &[u8]) -> Option<u8> {
        if self.layer_count >= MAX_LAYERS as u8 {
            return None;
        }
        let idx = self.layer_count as usize;
        self.layers[idx] = Layer::empty();
        self.layers[idx].layer_type = LayerType::Lower;
        self.layers[idx].set_path(path);
        self.layers[idx].readonly = true;
        self.layers[idx].inode_base = (idx as u64 + 1) * 0x1000000;
        self.layers[idx].active = true;
        self.layer_count += 1;
        Some(idx as u8)
    }

    pub fn set_upper(&mut self, path: &[u8]) -> Option<u8> {
        if self.upper_idx >= 0 {
            return None; // Already have upper
        }
        if self.layer_count >= MAX_LAYERS as u8 {
            return None;
        }
        let idx = self.layer_count as usize;
        self.layers[idx] = Layer::empty();
        self.layers[idx].layer_type = LayerType::Upper;
        self.layers[idx].set_path(path);
        self.layers[idx].readonly = false;
        self.layers[idx].inode_base = 0; // Upper gets low inode range
        self.layers[idx].active = true;
        self.upper_idx = idx as i8;
        self.layer_count += 1;
        Some(idx as u8)
    }

    pub fn set_workdir(&mut self, path: &[u8]) -> Option<u8> {
        if self.layer_count >= MAX_LAYERS as u8 {
            return None;
        }
        let idx = self.layer_count as usize;
        self.layers[idx] = Layer::empty();
        self.layers[idx].layer_type = LayerType::Work;
        self.layers[idx].set_path(path);
        self.layers[idx].readonly = false;
        self.layers[idx].active = true;
        self.work_idx = idx as i8;
        self.layer_count += 1;
        Some(idx as u8)
    }

    pub fn is_readonly(&self) -> bool {
        self.upper_idx < 0
    }

    // ─── Inode Operations ───────────────────────────────────────────

    fn alloc_inode(&mut self) -> Option<usize> {
        for i in 0..MAX_INODES {
            if !self.inodes[i].active {
                self.inodes[i] = OvlInode::empty();
                self.inodes[i].ino = self.next_ino;
                self.next_ino += 1;
                self.inodes[i].active = true;
                self.inode_count += 1;
                return Some(i);
            }
        }
        None
    }

    pub fn lookup(&mut self, parent_ino: u64, name: &[u8]) -> Option<usize> {
        self.total_lookups += 1;

        // Check whiteouts first
        if self.is_whiteout(parent_ino, name) {
            return None;
        }

        // Search upper layer first, then lower layers
        for i in 0..MAX_INODES {
            if !self.inodes[i].active {
                continue;
            }
            if self.inodes[i].parent_ino != parent_ino {
                continue;
            }
            let nlen = self.inodes[i].name_len as usize;
            if nlen != name.len() {
                continue;
            }
            if self.inodes[i].name[..nlen] == name[..nlen] {
                return Some(i);
            }
        }
        None
    }

    pub fn create(&mut self, parent_ino: u64, name: &[u8], mode: u16, ftype: OvlFileType) -> Option<u64> {
        if self.is_readonly() {
            return None;
        }
        let idx = self.alloc_inode()?;
        self.inodes[idx].set_name(name);
        self.inodes[idx].parent_ino = parent_ino;
        self.inodes[idx].mode = mode;
        self.inodes[idx].file_type = ftype;
        self.inodes[idx].layer_idx = self.upper_idx as u8;
        self.inodes[idx].mtime = self.next_ino; // Placeholder timestamp

        if ftype == OvlFileType::Directory {
            self.inodes[idx].nlink = 2;
        }

        // Remove any existing whiteout for this name
        self.remove_whiteout(parent_ino, name);

        Some(self.inodes[idx].ino)
    }

    pub fn unlink(&mut self, parent_ino: u64, name: &[u8]) -> bool {
        if self.is_readonly() {
            return false;
        }

        if let Some(idx) = self.lookup(parent_ino, name) {
            let on_upper = self.inodes[idx].layer_idx == self.upper_idx as u8;

            if on_upper {
                // Remove from upper directly
                self.inodes[idx].active = false;
                self.inode_count -= 1;
            }

            // Create whiteout to hide any lower copy
            self.create_whiteout(parent_ino, name);
            return true;
        }
        false
    }

    // ─── Copy-Up ────────────────────────────────────────────────────

    pub fn copy_up(&mut self, inode_idx: usize) -> bool {
        if self.is_readonly() || inode_idx >= MAX_INODES || !self.inodes[inode_idx].active {
            return false;
        }
        if self.inodes[inode_idx].layer_idx == self.upper_idx as u8 {
            return true; // Already on upper
        }

        self.inodes[inode_idx].copy_up = CopyUpState::InProgress;

        // If metacopy enabled and file is regular, do metadata-only copy
        if self.metacopy && self.inodes[inode_idx].file_type == OvlFileType::Regular {
            self.inodes[inode_idx].metacopy = true;
            self.inodes[inode_idx].origin_set = true;
            self.inodes[inode_idx].copy_up = CopyUpState::MetacopyDone;
            self.inodes[inode_idx].layer_idx = self.upper_idx as u8;
            self.total_metacopyups += 1;
        } else {
            // Full copy-up
            self.inodes[inode_idx].copy_up = CopyUpState::Complete;
            self.inodes[inode_idx].layer_idx = self.upper_idx as u8;
            self.inodes[inode_idx].metacopy = false;
            self.total_copyups += 1;
        }
        true
    }

    /// Force full data copy-up for metacopied inode (on first data read/write)
    pub fn complete_metacopy(&mut self, inode_idx: usize) -> bool {
        if inode_idx >= MAX_INODES || !self.inodes[inode_idx].active {
            return false;
        }
        if !self.inodes[inode_idx].metacopy {
            return true; // Not a metacopy
        }
        self.inodes[inode_idx].metacopy = false;
        self.inodes[inode_idx].copy_up = CopyUpState::Complete;
        self.total_copyups += 1;
        true
    }

    // ─── Whiteout Management ────────────────────────────────────────

    fn create_whiteout(&mut self, parent_ino: u64, name: &[u8]) -> bool {
        for i in 0..MAX_WHITEOUTS {
            if !self.whiteouts[i].active {
                let len = if name.len() < NAME_MAX { name.len() } else { NAME_MAX };
                self.whiteouts[i].name[..len].copy_from_slice(&name[..len]);
                self.whiteouts[i].name_len = len as u8;
                self.whiteouts[i].parent_ino = parent_ino;
                self.whiteouts[i].active = true;
                self.whiteout_count += 1;
                self.total_whiteouts_created += 1;
                return true;
            }
        }
        false
    }

    fn remove_whiteout(&mut self, parent_ino: u64, name: &[u8]) {
        for i in 0..MAX_WHITEOUTS {
            if !self.whiteouts[i].active || self.whiteouts[i].parent_ino != parent_ino {
                continue;
            }
            let nlen = self.whiteouts[i].name_len as usize;
            if nlen != name.len() {
                continue;
            }
            if self.whiteouts[i].name[..nlen] == name[..nlen] {
                self.whiteouts[i].active = false;
                self.whiteout_count -= 1;
                return;
            }
        }
    }

    fn is_whiteout(&self, parent_ino: u64, name: &[u8]) -> bool {
        for i in 0..MAX_WHITEOUTS {
            if !self.whiteouts[i].active || self.whiteouts[i].parent_ino != parent_ino {
                continue;
            }
            let nlen = self.whiteouts[i].name_len as usize;
            if nlen != name.len() {
                continue;
            }
            if self.whiteouts[i].name[..nlen] == name[..nlen] {
                return true;
            }
        }
        false
    }

    // ─── Opaque Directories ─────────────────────────────────────────

    pub fn set_opaque(&mut self, inode_idx: usize) -> bool {
        if inode_idx >= MAX_INODES || !self.inodes[inode_idx].active {
            return false;
        }
        if !self.inodes[inode_idx].is_dir() {
            return false;
        }
        self.inodes[inode_idx].file_type = OvlFileType::Opaque;
        true
    }

    // ─── Directory Merge (readdir) ──────────────────────────────────

    pub fn merge_dir(&mut self, dir_ino: u64) -> u32 {
        self.total_dir_merges += 1;
        self.dir_cache_count = 0;

        // Check if directory is opaque — only show upper
        let mut is_opaque = false;
        for i in 0..MAX_INODES {
            if self.inodes[i].active && self.inodes[i].ino == dir_ino && self.inodes[i].is_opaque() {
                is_opaque = true;
                break;
            }
        }

        // Collect entries from all layers, upper first
        // Upper-layer entries shadow lower-layer same-name entries
        for i in 0..MAX_INODES {
            if !self.inodes[i].active || self.inodes[i].parent_ino != dir_ino {
                continue;
            }

            // Skip lower layer entries in opaque directories
            if is_opaque && self.inodes[i].layer_idx != self.upper_idx as u8 {
                continue;
            }

            // Check if name is whiteout'd
            let nlen = self.inodes[i].name_len as usize;
            if self.is_whiteout(dir_ino, &self.inodes[i].name[..nlen]) {
                continue;
            }

            // Check if already in cache (dedup)
            let mut duplicate = false;
            for j in 0..self.dir_cache_count as usize {
                if self.dir_cache[j].name_matches(&self.inodes[i].name[..nlen]) {
                    duplicate = true;
                    break;
                }
            }

            if !duplicate && (self.dir_cache_count as usize) < MAX_ENTRIES {
                let c = self.dir_cache_count as usize;
                self.dir_cache[c] = OvlDirEntry::empty();
                let copy_len = if nlen < NAME_MAX { nlen } else { NAME_MAX };
                self.dir_cache[c].name[..copy_len].copy_from_slice(&self.inodes[i].name[..copy_len]);
                self.dir_cache[c].name_len = copy_len as u8;
                self.dir_cache[c].ino = self.inodes[i].ino;
                self.dir_cache[c].file_type = self.inodes[i].file_type;
                self.dir_cache[c].layer_idx = self.inodes[i].layer_idx;
                self.dir_cache[c].visible = true;
                self.dir_cache_count += 1;
            }
        }

        self.dir_cache_count
    }

    // ─── Rename with Redirect ───────────────────────────────────────

    pub fn rename(&mut self, old_parent: u64, old_name: &[u8], new_parent: u64, new_name: &[u8]) -> bool {
        if self.is_readonly() {
            return false;
        }

        let inode_idx = match self.lookup(old_parent, old_name) {
            Some(i) => i,
            None => return false,
        };

        // Copy up if on lower layer
        if self.inodes[inode_idx].needs_copy_up() {
            if !self.copy_up(inode_idx) {
                return false;
            }
        }

        // For directories, set redirect if enabled
        if self.redirect_dir && self.inodes[inode_idx].is_dir() {
            self.inodes[inode_idx].set_redirect(old_name);
        }

        // Update name and parent
        self.inodes[inode_idx].set_name(new_name);
        self.inodes[inode_idx].parent_ino = new_parent;

        // Whiteout old location
        self.create_whiteout(old_parent, old_name);

        // Remove whiteout at new location
        self.remove_whiteout(new_parent, new_name);

        true
    }

    // ─── Read/Write with Copy-Up ────────────────────────────────────

    pub fn read(&mut self, inode_idx: usize) -> bool {
        if inode_idx >= MAX_INODES || !self.inodes[inode_idx].active {
            return false;
        }
        // Metacopy read: data still on lower
        if self.inodes[inode_idx].metacopy {
            // Read from lower via origin
        }
        self.total_reads += 1;
        true
    }

    pub fn write(&mut self, inode_idx: usize) -> bool {
        if self.is_readonly() || inode_idx >= MAX_INODES || !self.inodes[inode_idx].active {
            return false;
        }

        // Copy up if needed
        if self.inodes[inode_idx].needs_copy_up() {
            if !self.copy_up(inode_idx) {
                return false;
            }
        }

        // Complete metacopy if data write
        if self.inodes[inode_idx].metacopy {
            self.complete_metacopy(inode_idx);
        }

        self.total_writes += 1;
        true
    }

    // ─── Statistics ─────────────────────────────────────────────────

    pub fn inode_on_upper(&self) -> u32 {
        let upper = if self.upper_idx >= 0 { self.upper_idx as u8 } else { return 0 };
        let mut count = 0u32;
        for i in 0..MAX_INODES {
            if self.inodes[i].active && self.inodes[i].layer_idx == upper {
                count += 1;
            }
        }
        count
    }

    pub fn metacopy_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..MAX_INODES {
            if self.inodes[i].active && self.inodes[i].metacopy {
                count += 1;
            }
        }
        count
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_OVERLAYFS: Option<OverlayFs> = None;
static mut G_INITIALIZED: bool = false;

fn ovl() -> &'static mut OverlayFs {
    unsafe { G_OVERLAYFS.as_mut().unwrap() }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_overlayfs_init() {
    unsafe {
        G_OVERLAYFS = Some(OverlayFs::new());
        G_INITIALIZED = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_add_lower(path: *const u8, path_len: usize) -> i8 {
    if unsafe { !G_INITIALIZED } || path.is_null() || path_len == 0 { return -1; }
    let p = unsafe { core::slice::from_raw_parts(path, path_len) };
    match ovl().add_lower(p) {
        Some(idx) => idx as i8,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_set_upper(path: *const u8, path_len: usize) -> i8 {
    if unsafe { !G_INITIALIZED } || path.is_null() || path_len == 0 { return -1; }
    let p = unsafe { core::slice::from_raw_parts(path, path_len) };
    match ovl().set_upper(p) {
        Some(idx) => idx as i8,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_lookup(parent_ino: u64, name: *const u8, name_len: usize) -> i64 {
    if unsafe { !G_INITIALIZED } || name.is_null() || name_len == 0 { return -1; }
    let n = unsafe { core::slice::from_raw_parts(name, name_len) };
    match ovl().lookup(parent_ino, n) {
        Some(idx) => idx as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_create(parent_ino: u64, name: *const u8, name_len: usize, mode: u16) -> i64 {
    if unsafe { !G_INITIALIZED } || name.is_null() || name_len == 0 { return -1; }
    let n = unsafe { core::slice::from_raw_parts(name, name_len) };
    match ovl().create(parent_ino, n, mode, OvlFileType::Regular) {
        Some(ino) => ino as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_unlink(parent_ino: u64, name: *const u8, name_len: usize) -> bool {
    if unsafe { !G_INITIALIZED } || name.is_null() || name_len == 0 { return false; }
    let n = unsafe { core::slice::from_raw_parts(name, name_len) };
    ovl().unlink(parent_ino, n)
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_copy_up(inode_idx: usize) -> bool {
    if unsafe { !G_INITIALIZED } { return false; }
    ovl().copy_up(inode_idx)
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_write(inode_idx: usize) -> bool {
    if unsafe { !G_INITIALIZED } { return false; }
    ovl().write(inode_idx)
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_merge_dir(dir_ino: u64) -> u32 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().merge_dir(dir_ino)
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_inode_count() -> u32 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().inode_count
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_layer_count() -> u8 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().layer_count
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_whiteout_count() -> u32 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().whiteout_count
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_total_copyups() -> u64 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().total_copyups
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_total_metacopyups() -> u64 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().total_metacopyups
}

#[no_mangle]
pub extern "C" fn rust_overlayfs_total_lookups() -> u64 {
    if unsafe { !G_INITIALIZED } { return 0; }
    ovl().total_lookups
}
