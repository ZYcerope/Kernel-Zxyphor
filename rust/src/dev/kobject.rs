// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Kobject / Kset / Ktype Framework (Rust)
//
// Kernel object model for structured device hierarchy:
// - Kobject: basic kernel object with refcounting and parent/child
// - Kset: collection of kobjects (group)
// - Ktype: operations table for kobject lifecycle
// - Attribute: sysfs-like attributes (read/write callbacks)
// - Uevent generation for hotplug notification
// - Reference counting with release callbacks
// - Hierarchical naming (parent/child paths)
// - Object lifecycle: create → add → del → release
// - Bus/device/driver model foundation
// - Global object registry

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

const MAX_KOBJECTS: usize = 512;
const MAX_KSETS: usize = 64;
const MAX_ATTRS_PER_OBJ: usize = 16;
const MAX_CHILDREN: usize = 32;
const MAX_NAME_LEN: usize = 64;
const MAX_PATH_LEN: usize = 256;
const MAX_UEVENT_QUEUE: usize = 64;

// ─────────────────── Kobject State ──────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum KobjState {
    Uninitialized = 0,
    Initialized = 1,
    Added = 2,
    Removing = 3,
    Released = 4,
}

// ─────────────────── Uevent Action ──────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum UeventAction {
    Add = 0,
    Remove = 1,
    Change = 2,
    Move = 3,
    Online = 4,
    Offline = 5,
    Bind = 6,
    Unbind = 7,
}

impl UeventAction {
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Add => b"add",
            Self::Remove => b"remove",
            Self::Change => b"change",
            Self::Move => b"move",
            Self::Online => b"online",
            Self::Offline => b"offline",
            Self::Bind => b"bind",
            Self::Unbind => b"unbind",
        }
    }
}

// ─────────────────── Uevent ─────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Uevent {
    pub action: UeventAction,
    pub kobj_id: u16,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    pub subsystem: [u8; 32],
    pub subsystem_len: u8,
    pub seqnum: u64,
    pub valid: bool,
}

impl Uevent {
    pub const EMPTY: Self = Self {
        action: UeventAction::Add,
        kobj_id: 0,
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
        subsystem: [0u8; 32],
        subsystem_len: 0,
        seqnum: 0,
        valid: false,
    };
}

// ─────────────────── Attribute ──────────────────────────────────────

/// Attribute show/store function types (C ABI)
pub type AttrShowFn = extern "C" fn(kobj_id: u16, buf: *mut u8, buf_len: u32) -> i32;
pub type AttrStoreFn = extern "C" fn(kobj_id: u16, buf: *const u8, buf_len: u32) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KobjAttribute {
    pub name: [u8; 32],
    pub name_len: u8,
    pub mode: u16,    // Permission bits (e.g. 0o644)
    pub show: Option<AttrShowFn>,
    pub store: Option<AttrStoreFn>,
    pub valid: bool,
}

impl KobjAttribute {
    pub const EMPTY: Self = Self {
        name: [0u8; 32],
        name_len: 0,
        mode: 0o444,
        show: None,
        store: None,
        valid: false,
    };

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn is_writable(&self) -> bool {
        self.mode & 0o222 != 0
    }

    pub fn is_readable(&self) -> bool {
        self.mode & 0o444 != 0
    }
}

// ─────────────────── Ktype ──────────────────────────────────────────

/// Ktype defines operations for a class of kobjects
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ktype {
    pub name: [u8; 32],
    pub name_len: u8,
    /// Default attributes for this type
    pub default_attrs: [KobjAttribute; MAX_ATTRS_PER_OBJ],
    pub attr_count: u8,
    pub valid: bool,
}

impl Ktype {
    pub const EMPTY: Self = Self {
        name: [0u8; 32],
        name_len: 0,
        default_attrs: [KobjAttribute::EMPTY; MAX_ATTRS_PER_OBJ],
        attr_count: 0,
        valid: false,
    };

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn add_default_attr(&mut self, attr: KobjAttribute) -> bool {
        if self.attr_count as usize >= MAX_ATTRS_PER_OBJ { return false; }
        self.default_attrs[self.attr_count as usize] = attr;
        self.attr_count += 1;
        true
    }
}

// ─────────────────── Kobject ────────────────────────────────────────

#[repr(C)]
pub struct Kobject {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub id: u16,
    pub state: KobjState,
    pub refcount: AtomicU32,
    /// Hierarchy
    pub parent_id: u16,       // 0xFFFF = no parent
    pub children: [u16; MAX_CHILDREN],
    pub child_count: u8,
    /// Kset membership
    pub kset_id: u16,         // 0xFFFF = no kset
    /// Type
    pub ktype_idx: u8,        // index into ktype table, 0xFF = none
    /// Attributes
    pub attrs: [KobjAttribute; MAX_ATTRS_PER_OBJ],
    pub attr_count: u8,
    /// Subsystem name (for uevent)
    pub subsystem: [u8; 32],
    pub subsystem_len: u8,
    pub active: bool,
}

impl Kobject {
    pub fn new(id: u16) -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            id,
            state: KobjState::Uninitialized,
            refcount: AtomicU32::new(1),
            parent_id: 0xFFFF,
            children: [0xFFFF; MAX_CHILDREN],
            child_count: 0,
            kset_id: 0xFFFF,
            ktype_idx: 0xFF,
            attrs: [KobjAttribute::EMPTY; MAX_ATTRS_PER_OBJ],
            attr_count: 0,
            subsystem: [0u8; 32],
            subsystem_len: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(63);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn set_subsystem(&mut self, s: &[u8]) {
        let len = s.len().min(31);
        self.subsystem[..len].copy_from_slice(&s[..len]);
        self.subsystem_len = len as u8;
    }

    pub fn get_ref(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn put_ref(&self) -> u32 {
        let prev = self.refcount.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 { return 0; }
        prev - 1
    }

    pub fn add_child(&mut self, child_id: u16) -> bool {
        if self.child_count as usize >= MAX_CHILDREN { return false; }
        self.children[self.child_count as usize] = child_id;
        self.child_count += 1;
        true
    }

    pub fn remove_child(&mut self, child_id: u16) -> bool {
        for i in 0..self.child_count as usize {
            if self.children[i] == child_id {
                let mut j = i;
                while j + 1 < self.child_count as usize {
                    self.children[j] = self.children[j + 1];
                    j += 1;
                }
                self.child_count -= 1;
                return true;
            }
        }
        false
    }

    pub fn add_attr(&mut self, attr: KobjAttribute) -> bool {
        if self.attr_count as usize >= MAX_ATTRS_PER_OBJ { return false; }
        self.attrs[self.attr_count as usize] = attr;
        self.attr_count += 1;
        true
    }

    pub fn find_attr(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.attr_count as usize {
            if self.attrs[i].valid && self.attrs[i].name_len == name.len() as u8 {
                if &self.attrs[i].name[..name.len()] == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Build path from root
    pub fn build_path(&self, buf: &mut [u8], registry: &KobjRegistry) -> usize {
        let mut components: [[u8; MAX_NAME_LEN]; 16] = [[0; MAX_NAME_LEN]; 16];
        let mut comp_lens: [u8; 16] = [0; 16];
        let mut depth = 0usize;

        // Walk up to root
        let mut current_id = self.id;
        while depth < 16 {
            if let Some(kobj) = registry.get(current_id) {
                let len = kobj.name_len as usize;
                components[depth][..len].copy_from_slice(&kobj.name[..len]);
                comp_lens[depth] = kobj.name_len;
                depth += 1;
                if kobj.parent_id == 0xFFFF { break; }
                current_id = kobj.parent_id;
            } else {
                break;
            }
        }

        // Build path in reverse
        let mut pos = 0usize;
        if depth > 0 {
            let mut i = depth;
            while i > 0 {
                i -= 1;
                if pos > 0 && pos < buf.len() {
                    buf[pos] = b'/';
                    pos += 1;
                }
                let len = comp_lens[i] as usize;
                if pos + len <= buf.len() {
                    buf[pos..pos + len].copy_from_slice(&components[i][..len]);
                    pos += len;
                }
            }
        }

        pos
    }
}

// ─────────────────── Kset ───────────────────────────────────────────

#[repr(C)]
pub struct Kset {
    pub kobj: Kobject,        // A kset is itself a kobject
    pub members: [u16; 128],  // member kobject IDs
    pub member_count: u16,
    pub uevent_suppress: bool,
    pub active: bool,
}

impl Kset {
    pub fn new(id: u16) -> Self {
        Self {
            kobj: Kobject::new(id),
            members: [0xFFFF; 128],
            member_count: 0,
            uevent_suppress: false,
            active: false,
        }
    }

    pub fn add_member(&mut self, kobj_id: u16) -> bool {
        if self.member_count as usize >= 128 { return false; }
        // Check duplicate
        for i in 0..self.member_count as usize {
            if self.members[i] == kobj_id { return false; }
        }
        self.members[self.member_count as usize] = kobj_id;
        self.member_count += 1;
        true
    }

    pub fn remove_member(&mut self, kobj_id: u16) -> bool {
        for i in 0..self.member_count as usize {
            if self.members[i] == kobj_id {
                let mut j = i;
                while j + 1 < self.member_count as usize {
                    self.members[j] = self.members[j + 1];
                    j += 1;
                }
                self.member_count -= 1;
                return true;
            }
        }
        false
    }
}

// ─────────────────── Object Registry ────────────────────────────────

pub struct KobjRegistry {
    pub objects: [Kobject; MAX_KOBJECTS],
    pub obj_count: u16,
    pub next_id: u16,
    pub ksets: [Kset; MAX_KSETS],
    pub kset_count: u8,
    pub ktypes: [Ktype; 16],
    pub ktype_count: u8,
    /// Uevent queue
    pub uevent_queue: [Uevent; MAX_UEVENT_QUEUE],
    pub uevent_head: u8,
    pub uevent_tail: u8,
    pub uevent_seqnum: AtomicU64,
    /// Stats
    pub total_created: AtomicU64,
    pub total_released: AtomicU64,
    pub total_uevents: AtomicU64,
    pub initialized: AtomicBool,
}

impl KobjRegistry {
    pub fn new() -> Self {
        let mut reg = Self {
            objects: unsafe { core::mem::zeroed() },
            obj_count: 0,
            next_id: 0,
            ksets: unsafe { core::mem::zeroed() },
            kset_count: 0,
            ktypes: [Ktype::EMPTY; 16],
            ktype_count: 0,
            uevent_queue: [Uevent::EMPTY; MAX_UEVENT_QUEUE],
            uevent_head: 0,
            uevent_tail: 0,
            uevent_seqnum: AtomicU64::new(0),
            total_created: AtomicU64::new(0),
            total_released: AtomicU64::new(0),
            total_uevents: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        };
        for i in 0..MAX_KOBJECTS {
            reg.objects[i] = Kobject::new(i as u16);
        }
        for i in 0..MAX_KSETS {
            reg.ksets[i] = Kset::new(i as u16);
        }
        reg
    }

    pub fn init(&mut self) {
        // Register built-in ktypes
        self.register_ktype(b"device");
        self.register_ktype(b"driver");
        self.register_ktype(b"bus");
        self.register_ktype(b"class");

        // Create root ksets
        self.create_kset(b"devices", 0xFFFF);
        self.create_kset(b"bus", 0xFFFF);
        self.create_kset(b"class", 0xFFFF);
        self.create_kset(b"module", 0xFFFF);

        self.initialized.store(true, Ordering::Release);
    }

    pub fn register_ktype(&mut self, name: &[u8]) -> u8 {
        if self.ktype_count as usize >= 16 { return 0xFF; }
        let idx = self.ktype_count;
        self.ktypes[idx as usize] = Ktype::EMPTY;
        self.ktypes[idx as usize].set_name(name);
        self.ktypes[idx as usize].valid = true;
        self.ktype_count += 1;
        idx
    }

    /// Create a kobject
    pub fn create_kobject(&mut self, name: &[u8], parent_id: u16) -> Option<u16> {
        if self.obj_count as usize >= MAX_KOBJECTS { return None; }

        let id = self.next_id;
        self.next_id += 1;

        let idx = self.find_free_obj_slot()?;
        self.objects[idx] = Kobject::new(id);
        self.objects[idx].set_name(name);
        self.objects[idx].state = KobjState::Initialized;
        self.objects[idx].parent_id = parent_id;
        self.objects[idx].active = true;
        self.obj_count += 1;

        // Add as child of parent
        if parent_id != 0xFFFF {
            if let Some(parent_idx) = self.find_idx(parent_id) {
                self.objects[parent_idx].add_child(id);
            }
        }

        self.total_created.fetch_add(1, Ordering::Relaxed);
        Some(id)
    }

    /// Add kobject to sysfs tree (make visible)
    pub fn add_kobject(&mut self, id: u16) -> bool {
        if let Some(idx) = self.find_idx(id) {
            if self.objects[idx].state != KobjState::Initialized { return false; }
            self.objects[idx].state = KobjState::Added;
            self.emit_uevent(id, UeventAction::Add);
            true
        } else {
            false
        }
    }

    /// Remove and release a kobject
    pub fn del_kobject(&mut self, id: u16) -> bool {
        let idx = match self.find_idx(id) {
            Some(i) => i,
            None => return false,
        };

        if self.objects[idx].state == KobjState::Released { return false; }

        self.objects[idx].state = KobjState::Removing;
        self.emit_uevent(id, UeventAction::Remove);

        // Remove from parent
        let parent_id = self.objects[idx].parent_id;
        if parent_id != 0xFFFF {
            if let Some(pidx) = self.find_idx(parent_id) {
                self.objects[pidx].remove_child(id);
            }
        }

        // Remove from kset
        let kset_id = self.objects[idx].kset_id;
        if kset_id != 0xFFFF && (kset_id as usize) < MAX_KSETS {
            self.ksets[kset_id as usize].remove_member(id);
        }

        self.objects[idx].state = KobjState::Released;
        self.objects[idx].active = false;
        if self.obj_count > 0 { self.obj_count -= 1; }
        self.total_released.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Create a kset
    pub fn create_kset(&mut self, name: &[u8], parent_id: u16) -> Option<u8> {
        if self.kset_count as usize >= MAX_KSETS { return None; }
        let idx = self.kset_count;
        self.ksets[idx as usize] = Kset::new(idx as u16);
        self.ksets[idx as usize].kobj.set_name(name);
        self.ksets[idx as usize].kobj.parent_id = parent_id;
        self.ksets[idx as usize].kobj.state = KobjState::Added;
        self.ksets[idx as usize].kobj.active = true;
        self.ksets[idx as usize].active = true;
        self.kset_count += 1;
        Some(idx)
    }

    /// Add kobject to kset
    pub fn kset_add(&mut self, kset_id: u8, kobj_id: u16) -> bool {
        if kset_id as usize >= MAX_KSETS { return false; }
        if !self.ksets[kset_id as usize].active { return false; }

        if let Some(idx) = self.find_idx(kobj_id) {
            self.objects[idx].kset_id = kset_id as u16;
            self.ksets[kset_id as usize].add_member(kobj_id)
        } else {
            false
        }
    }

    fn emit_uevent(&mut self, kobj_id: u16, action: UeventAction) {
        let next = (self.uevent_head + 1) % MAX_UEVENT_QUEUE as u8;
        if next == self.uevent_tail { return; } // Queue full

        let idx = self.uevent_head as usize;
        self.uevent_queue[idx] = Uevent::EMPTY;
        self.uevent_queue[idx].action = action;
        self.uevent_queue[idx].kobj_id = kobj_id;
        self.uevent_queue[idx].seqnum = self.uevent_seqnum.fetch_add(1, Ordering::Relaxed);
        self.uevent_queue[idx].valid = true;

        // Copy subsystem from kobject
        if let Some(obj_idx) = self.find_idx(kobj_id) {
            let sl = self.objects[obj_idx].subsystem_len as usize;
            self.uevent_queue[idx].subsystem[..sl].copy_from_slice(
                &self.objects[obj_idx].subsystem[..sl]
            );
            self.uevent_queue[idx].subsystem_len = self.objects[obj_idx].subsystem_len;
        }

        self.uevent_head = next;
        self.total_uevents.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dequeue_uevent(&mut self) -> Option<Uevent> {
        if self.uevent_tail == self.uevent_head { return None; }
        let evt = self.uevent_queue[self.uevent_tail as usize];
        self.uevent_tail = (self.uevent_tail + 1) % MAX_UEVENT_QUEUE as u8;
        Some(evt)
    }

    pub fn get(&self, id: u16) -> Option<&Kobject> {
        for i in 0..MAX_KOBJECTS {
            if self.objects[i].active && self.objects[i].id == id {
                return Some(&self.objects[i]);
            }
        }
        None
    }

    fn find_idx(&self, id: u16) -> Option<usize> {
        for i in 0..MAX_KOBJECTS {
            if self.objects[i].active && self.objects[i].id == id {
                return Some(i);
            }
        }
        None
    }

    fn find_free_obj_slot(&self) -> Option<usize> {
        for i in 0..MAX_KOBJECTS {
            if !self.objects[i].active {
                return Some(i);
            }
        }
        None
    }

    pub fn active_count(&self) -> u32 {
        let mut count = 0u32;
        for obj in self.objects.iter() {
            if obj.active { count += 1; }
        }
        count
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut KOBJ_REG: Option<KobjRegistry> = None;

fn kobj_reg() -> &'static mut KobjRegistry {
    unsafe {
        if KOBJ_REG.is_none() {
            let mut reg = KobjRegistry::new();
            reg.init();
            KOBJ_REG = Some(reg);
        }
        KOBJ_REG.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_kobj_init() {
    let _ = kobj_reg();
}

#[no_mangle]
pub extern "C" fn rust_kobj_create(name_ptr: *const u8, name_len: u32, parent_id: u16) -> i32 {
    if name_ptr.is_null() || name_len == 0 || name_len > 63 { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match kobj_reg().create_kobject(name, parent_id) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_kobj_add(id: u16) -> i32 {
    if kobj_reg().add_kobject(id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_kobj_del(id: u16) -> i32 {
    if kobj_reg().del_kobject(id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_kobj_count() -> u32 {
    kobj_reg().active_count()
}

#[no_mangle]
pub extern "C" fn rust_kset_create(name_ptr: *const u8, name_len: u32) -> i32 {
    if name_ptr.is_null() || name_len == 0 || name_len > 63 { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match kobj_reg().create_kset(name, 0xFFFF) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_kset_add_member(kset_id: u8, kobj_id: u16) -> i32 {
    if kobj_reg().kset_add(kset_id, kobj_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_kobj_total_created() -> u64 {
    kobj_reg().total_created.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_kobj_total_released() -> u64 {
    kobj_reg().total_released.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_kobj_uevent_count() -> u64 {
    kobj_reg().total_uevents.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_kobj_kset_count() -> u8 {
    kobj_reg().kset_count
}
