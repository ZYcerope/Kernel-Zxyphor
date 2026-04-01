// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Process Kobject/Kref Infrastructure (Rust)
//
// Kernel object reference subsystem for process management:
// - Kobject: Base kernel object with reference counting
// - Kref: Atomic reference counter with release callback
// - Kset: Collection of kobjects (hierarchical object tree)
// - Ktype: Type descriptor with show/store sysfs ops
// - Uevent: Object lifecycle notifications (add/remove/change/move/online/offline)
// - Sysfs attribute abstraction
// - Process-centric kobject integration
// - Hierarchical parent-child object relationships
// - Device model foundation

#![allow(dead_code)]

// ─── Constants ──────────────────────────────────────────────────────

const MAX_KOBJECTS: usize = 512;
const MAX_KSETS: usize = 32;
const MAX_ATTRIBUTES: usize = 16;
const KOBJ_NAME_LEN: usize = 64;
const ATTR_NAME_LEN: usize = 48;
const ATTR_VALUE_LEN: usize = 128;
const UEVENT_BUF_LEN: usize = 256;
const MAX_CHILDREN: usize = 32;
const MAX_UEVENT_QUEUE: usize = 64;

// ─── Uevent Types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }
}

// ─── Kref (Reference Counter) ───────────────────────────────────────

#[derive(Debug)]
pub struct Kref {
    refcount: u32,
}

impl Kref {
    pub const fn new() -> Self {
        Self { refcount: 1 }
    }

    pub fn get(&mut self) -> &mut Self {
        self.refcount = self.refcount.saturating_add(1);
        self
    }

    /// Decrement refcount. Returns true when it reaches zero.
    pub fn put(&mut self) -> bool {
        if self.refcount == 0 {
            return false;
        }
        self.refcount -= 1;
        self.refcount == 0
    }

    pub fn count(&self) -> u32 {
        self.refcount
    }

    pub fn is_last(&self) -> bool {
        self.refcount == 1
    }
}

// ─── Sysfs Attribute ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum AttrMode {
    ReadOnly = 0o444,
    WriteOnly = 0o200,
    ReadWrite = 0o644,
    RootReadWrite = 0o600,
    RootRead = 0o400,
}

#[derive(Debug, Clone, Copy)]
pub struct SysfsAttr {
    pub name: [u8; ATTR_NAME_LEN],
    pub name_len: u8,
    pub mode: AttrMode,
    pub value: [u8; ATTR_VALUE_LEN],
    pub value_len: u8,
    pub active: bool,
}

impl SysfsAttr {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; ATTR_NAME_LEN],
            name_len: 0,
            mode: AttrMode::ReadOnly,
            value: [0u8; ATTR_VALUE_LEN],
            value_len: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(ATTR_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn set_value(&mut self, v: &[u8]) {
        let len = v.len().min(ATTR_VALUE_LEN - 1);
        self.value[..len].copy_from_slice(&v[..len]);
        self.value_len = len as u8;
    }

    pub fn set_value_u64(&mut self, val: u64) {
        let mut buf = [0u8; 20];
        let len = format_u64(val, &mut buf);
        self.set_value(&buf[..len]);
    }

    pub fn read_value_u64(&self) -> u64 {
        parse_u64(&self.value[..self.value_len as usize])
    }
}

// ─── Kobject State ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum KobjState {
    Unregistered = 0,
    Registered = 1,
    Active = 2,
    Removing = 3,
    Removed = 4,
}

// ─── Ktype (Type Descriptor) ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum KobjType {
    Generic = 0,
    Device = 1,
    Driver = 2,
    Bus = 3,
    Class = 4,
    Module = 5,
    Process = 6,
    Thread = 7,
    Filesystem = 8,
    Network = 9,
    Block = 10,
}

pub struct Ktype {
    pub ktype: KobjType,
    /// Default attributes automatically created for this type
    pub default_attrs: [SysfsAttr; MAX_ATTRIBUTES],
    pub default_attr_count: u8,
    /// Sysfs namespace tag
    pub namespace: [u8; 32],
    pub ns_len: u8,
}

impl Ktype {
    pub const fn new(ktype: KobjType) -> Self {
        Self {
            ktype,
            default_attrs: [SysfsAttr::empty(); MAX_ATTRIBUTES],
            default_attr_count: 0,
            namespace: [0u8; 32],
            ns_len: 0,
        }
    }
}

// ─── Kobject ────────────────────────────────────────────────────────

pub struct Kobject {
    pub name: [u8; KOBJ_NAME_LEN],
    pub name_len: u8,
    pub kref: Kref,
    pub state: KobjState,
    pub ktype_id: KobjType,
    pub parent_idx: i16, // -1 for root
    pub kset_idx: i16,   // -1 for no kset
    pub children: [i16; MAX_CHILDREN],
    pub child_count: u8,
    pub attrs: [SysfsAttr; MAX_ATTRIBUTES],
    pub attr_count: u8,
    /// Unique ID for lookups
    pub id: u32,
    pub active: bool,
    // Uevent tracking
    pub uevent_count: u32,
    pub suppress_uevent: bool,
}

impl Kobject {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; KOBJ_NAME_LEN],
            name_len: 0,
            kref: Kref::new(),
            state: KobjState::Unregistered,
            ktype_id: KobjType::Generic,
            parent_idx: -1,
            kset_idx: -1,
            children: [-1i16; MAX_CHILDREN],
            child_count: 0,
            attrs: [SysfsAttr::empty(); MAX_ATTRIBUTES],
            attr_count: 0,
            id: 0,
            active: false,
            uevent_count: 0,
            suppress_uevent: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(KOBJ_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn add_attr(&mut self, name: &[u8], value: &[u8], mode: AttrMode) -> bool {
        if self.attr_count as usize >= MAX_ATTRIBUTES {
            return false;
        }
        let idx = self.attr_count as usize;
        self.attrs[idx] = SysfsAttr::empty();
        self.attrs[idx].set_name(name);
        self.attrs[idx].set_value(value);
        self.attrs[idx].mode = mode;
        self.attrs[idx].active = true;
        self.attr_count += 1;
        true
    }

    pub fn find_attr(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.attr_count as usize {
            if !self.attrs[i].active {
                continue;
            }
            let len = self.attrs[i].name_len as usize;
            if len == name.len() && self.attrs[i].name[..len] == *name {
                return Some(i);
            }
        }
        None
    }

    pub fn read_attr(&self, name: &[u8]) -> Option<&[u8]> {
        if let Some(idx) = self.find_attr(name) {
            let vlen = self.attrs[idx].value_len as usize;
            return Some(&self.attrs[idx].value[..vlen]);
        }
        None
    }

    pub fn write_attr(&mut self, name: &[u8], value: &[u8]) -> bool {
        if let Some(idx) = self.find_attr(name) {
            if self.attrs[idx].mode == AttrMode::ReadOnly || self.attrs[idx].mode == AttrMode::RootRead {
                return false;
            }
            self.attrs[idx].set_value(value);
            return true;
        }
        false
    }

    pub fn add_child(&mut self, child_idx: i16) -> bool {
        if self.child_count as usize >= MAX_CHILDREN {
            return false;
        }
        let c = self.child_count as usize;
        self.children[c] = child_idx;
        self.child_count += 1;
        true
    }

    pub fn remove_child(&mut self, child_idx: i16) -> bool {
        for i in 0..self.child_count as usize {
            if self.children[i] == child_idx {
                // Shift remaining
                let mut j = i;
                while j + 1 < self.child_count as usize {
                    self.children[j] = self.children[j + 1];
                    j += 1;
                }
                self.child_count -= 1;
                self.children[self.child_count as usize] = -1;
                return true;
            }
        }
        false
    }
}

// ─── Kset ───────────────────────────────────────────────────────────

pub struct Kset {
    pub kobj: Kobject,
    pub members: [i16; MAX_KOBJECTS],
    pub member_count: u16,
    pub active: bool,
}

impl Kset {
    pub const fn empty() -> Self {
        Self {
            kobj: Kobject::empty(),
            members: [-1i16; MAX_KOBJECTS],
            member_count: 0,
            active: false,
        }
    }

    pub fn add_member(&mut self, kobj_idx: i16) -> bool {
        if self.member_count as usize >= MAX_KOBJECTS {
            return false;
        }
        let m = self.member_count as usize;
        self.members[m] = kobj_idx;
        self.member_count += 1;
        true
    }

    pub fn remove_member(&mut self, kobj_idx: i16) -> bool {
        for i in 0..self.member_count as usize {
            if self.members[i] == kobj_idx {
                let mut j = i;
                while j + 1 < self.member_count as usize {
                    self.members[j] = self.members[j + 1];
                    j += 1;
                }
                self.member_count -= 1;
                self.members[self.member_count as usize] = -1;
                return true;
            }
        }
        false
    }
}

// ─── Uevent Entry ───────────────────────────────────────────────────

pub struct UeventEntry {
    pub action: UeventAction,
    pub kobj_id: u32,
    pub ktype: KobjType,
    pub path: [u8; UEVENT_BUF_LEN],
    pub path_len: u8,
    pub timestamp: u64,
    pub active: bool,
}

impl UeventEntry {
    pub const fn empty() -> Self {
        Self {
            action: UeventAction::Add,
            kobj_id: 0,
            ktype: KobjType::Generic,
            path: [0u8; UEVENT_BUF_LEN],
            path_len: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// ─── Process Kobject Extension ──────────────────────────────────────

/// Per-process kobject with sysfs representation under /proc/<pid>
pub struct ProcKobject {
    pub kobj_idx: i16,
    pub pid: i32,
    pub tgid: i32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: i32,
    pub comm: [u8; 16],
    pub comm_len: u8,
    pub state: u8, // 'R'=running, 'S'=sleeping, 'D'=disk sleep, 'Z'=zombie, 'T'=stopped
    pub nice: i8,
    pub priority: u8,
    pub num_threads: u16,
    pub vm_size_kb: u64,
    pub rss_kb: u64,
    pub start_time: u64,
    pub utime: u64,
    pub stime: u64,
    pub active: bool,
}

impl ProcKobject {
    pub const fn empty() -> Self {
        Self {
            kobj_idx: -1,
            pid: 0,
            tgid: 0,
            uid: 0,
            gid: 0,
            ppid: 0,
            comm: [0u8; 16],
            comm_len: 0,
            state: b'S',
            nice: 0,
            priority: 120,
            num_threads: 1,
            vm_size_kb: 0,
            rss_kb: 0,
            start_time: 0,
            utime: 0,
            stime: 0,
            active: false,
        }
    }
}

// ─── Kobject Manager ────────────────────────────────────────────────

pub struct KobjectManager {
    objects: [Kobject; MAX_KOBJECTS],
    ksets: [Kset; MAX_KSETS],
    proc_kobjects: [ProcKobject; 256], // /proc/<pid> entries
    uevents: [UeventEntry; MAX_UEVENT_QUEUE],

    next_id: u32,
    obj_count: u16,
    kset_count: u8,
    proc_count: u16,
    uevent_head: u16,
    uevent_count: u16,

    total_creates: u64,
    total_destroys: u64,
    total_uevents: u64,
    total_attr_reads: u64,
    total_attr_writes: u64,

    initialized: bool,
}

impl KobjectManager {
    pub const fn new() -> Self {
        Self {
            objects: [Kobject::empty(); MAX_KOBJECTS],
            ksets: [Kset::empty(); MAX_KSETS],
            proc_kobjects: [ProcKobject::empty(); 256],
            uevents: [UeventEntry::empty(); MAX_UEVENT_QUEUE],
            next_id: 1,
            obj_count: 0,
            kset_count: 0,
            proc_count: 0,
            uevent_head: 0,
            uevent_count: 0,
            total_creates: 0,
            total_destroys: 0,
            total_uevents: 0,
            total_attr_reads: 0,
            total_attr_writes: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        // Create root ksets for standard hierarchy
        self.create_kset(b"devices", KobjType::Device);
        self.create_kset(b"bus", KobjType::Bus);
        self.create_kset(b"class", KobjType::Class);
        self.create_kset(b"module", KobjType::Module);
        self.create_kset(b"block", KobjType::Block);
        self.create_kset(b"firmware", KobjType::Generic);
        self.create_kset(b"fs", KobjType::Filesystem);
        self.create_kset(b"kernel", KobjType::Generic);
        self.initialized = true;
    }

    // ─── Kobject Operations ─────────────────────────────────────────

    pub fn create_kobject(&mut self, name: &[u8], ktype: KobjType, parent: i16) -> Option<i16> {
        for i in 0..MAX_KOBJECTS {
            if !self.objects[i].active {
                self.objects[i] = Kobject::empty();
                self.objects[i].set_name(name);
                self.objects[i].ktype_id = ktype;
                self.objects[i].parent_idx = parent;
                self.objects[i].id = self.next_id;
                self.objects[i].state = KobjState::Registered;
                self.objects[i].active = true;
                self.objects[i].kref = Kref::new();
                self.next_id += 1;
                self.obj_count += 1;
                self.total_creates += 1;

                let idx = i as i16;

                // Add to parent's children
                if parent >= 0 && (parent as usize) < MAX_KOBJECTS {
                    self.objects[parent as usize].add_child(idx);
                }

                // Emit uevent
                self.emit_uevent(UeventAction::Add, &self.objects[i]);

                return Some(idx);
            }
        }
        None
    }

    pub fn destroy_kobject(&mut self, idx: i16) -> bool {
        if idx < 0 || idx as usize >= MAX_KOBJECTS {
            return false;
        }
        let i = idx as usize;
        if !self.objects[i].active {
            return false;
        }

        // Mark removing
        self.objects[i].state = KobjState::Removing;

        // Emit remove uevent before destroying
        self.emit_uevent(UeventAction::Remove, &self.objects[i]);

        // Remove from parent
        let parent = self.objects[i].parent_idx;
        if parent >= 0 && (parent as usize) < MAX_KOBJECTS {
            self.objects[parent as usize].remove_child(idx);
        }

        // Remove from kset
        let kset_idx = self.objects[i].kset_idx;
        if kset_idx >= 0 && (kset_idx as usize) < MAX_KSETS {
            self.ksets[kset_idx as usize].remove_member(idx);
        }

        // Recursively remove children (bottom-up)
        for c in 0..self.objects[i].child_count as usize {
            let child = self.objects[i].children[c];
            if child >= 0 {
                self.destroy_kobject(child);
            }
        }

        self.objects[i].state = KobjState::Removed;
        self.objects[i].active = false;
        self.obj_count -= 1;
        self.total_destroys += 1;
        true
    }

    pub fn kobject_get(&mut self, idx: i16) -> bool {
        if idx < 0 || idx as usize >= MAX_KOBJECTS {
            return false;
        }
        let i = idx as usize;
        if !self.objects[i].active {
            return false;
        }
        self.objects[i].kref.get();
        true
    }

    pub fn kobject_put(&mut self, idx: i16) -> bool {
        if idx < 0 || idx as usize >= MAX_KOBJECTS {
            return false;
        }
        let i = idx as usize;
        if !self.objects[i].active {
            return false;
        }
        if self.objects[i].kref.put() {
            // Refcount reached zero — destroy
            self.destroy_kobject(idx);
        }
        true
    }

    // ─── Kset Operations ────────────────────────────────────────────

    pub fn create_kset(&mut self, name: &[u8], ktype: KobjType) -> Option<i16> {
        for i in 0..MAX_KSETS {
            if !self.ksets[i].active {
                self.ksets[i] = Kset::empty();
                self.ksets[i].kobj = Kobject::empty();
                self.ksets[i].kobj.set_name(name);
                self.ksets[i].kobj.ktype_id = ktype;
                self.ksets[i].kobj.id = self.next_id;
                self.ksets[i].kobj.active = true;
                self.ksets[i].kobj.state = KobjState::Active;
                self.ksets[i].active = true;
                self.next_id += 1;
                self.kset_count += 1;
                return Some(i as i16);
            }
        }
        None
    }

    pub fn kset_add_kobject(&mut self, kset_idx: i16, kobj_idx: i16) -> bool {
        if kset_idx < 0 || kset_idx as usize >= MAX_KSETS {
            return false;
        }
        if kobj_idx < 0 || kobj_idx as usize >= MAX_KOBJECTS {
            return false;
        }
        if !self.ksets[kset_idx as usize].active || !self.objects[kobj_idx as usize].active {
            return false;
        }
        self.objects[kobj_idx as usize].kset_idx = kset_idx;
        self.ksets[kset_idx as usize].add_member(kobj_idx)
    }

    // ─── Attribute Operations ───────────────────────────────────────

    pub fn add_attr(&mut self, kobj_idx: i16, name: &[u8], value: &[u8], mode: AttrMode) -> bool {
        if kobj_idx < 0 || kobj_idx as usize >= MAX_KOBJECTS {
            return false;
        }
        if !self.objects[kobj_idx as usize].active {
            return false;
        }
        self.objects[kobj_idx as usize].add_attr(name, value, mode)
    }

    pub fn read_attr(&mut self, kobj_idx: i16, name: &[u8]) -> Option<&[u8]> {
        if kobj_idx < 0 || kobj_idx as usize >= MAX_KOBJECTS {
            return None;
        }
        if !self.objects[kobj_idx as usize].active {
            return None;
        }
        self.total_attr_reads += 1;
        self.objects[kobj_idx as usize].read_attr(name)
    }

    pub fn write_attr(&mut self, kobj_idx: i16, name: &[u8], value: &[u8]) -> bool {
        if kobj_idx < 0 || kobj_idx as usize >= MAX_KOBJECTS {
            return false;
        }
        if !self.objects[kobj_idx as usize].active {
            return false;
        }
        self.total_attr_writes += 1;
        let result = self.objects[kobj_idx as usize].write_attr(name, value);
        if result {
            self.emit_uevent(UeventAction::Change, &self.objects[kobj_idx as usize]);
        }
        result
    }

    // ─── Process Kobject Operations ─────────────────────────────────

    pub fn register_process(&mut self, pid: i32, ppid: i32, comm: &[u8], uid: u32, gid: u32) -> Option<u16> {
        for i in 0..256usize {
            if !self.proc_kobjects[i].active {
                self.proc_kobjects[i] = ProcKobject::empty();
                self.proc_kobjects[i].pid = pid;
                self.proc_kobjects[i].tgid = pid;
                self.proc_kobjects[i].ppid = ppid;
                self.proc_kobjects[i].uid = uid;
                self.proc_kobjects[i].gid = gid;
                let len = comm.len().min(15);
                self.proc_kobjects[i].comm[..len].copy_from_slice(&comm[..len]);
                self.proc_kobjects[i].comm_len = len as u8;
                self.proc_kobjects[i].active = true;

                // Create sysfs kobject for /proc/<pid>
                let mut pid_name = [0u8; 12];
                let pid_len = format_u64(pid as u64, &mut pid_name);
                if let Some(kobj_idx) = self.create_kobject(&pid_name[..pid_len], KobjType::Process, -1) {
                    self.proc_kobjects[i].kobj_idx = kobj_idx;

                    // Add standard proc attributes
                    self.add_attr(kobj_idx, b"pid", &pid_name[..pid_len], AttrMode::ReadOnly);
                    self.add_attr(kobj_idx, b"comm", &comm[..comm.len().min(15)], AttrMode::ReadWrite);
                    self.add_attr(kobj_idx, b"state", b"S", AttrMode::ReadOnly);

                    let mut ppid_buf = [0u8; 12];
                    let ppid_len = format_u64(ppid as u64, &mut ppid_buf);
                    self.add_attr(kobj_idx, b"ppid", &ppid_buf[..ppid_len], AttrMode::ReadOnly);

                    let mut uid_buf = [0u8; 12];
                    let uid_len = format_u64(uid as u64, &mut uid_buf);
                    self.add_attr(kobj_idx, b"uid", &uid_buf[..uid_len], AttrMode::ReadOnly);
                }

                self.proc_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn unregister_process(&mut self, pid: i32) -> bool {
        for i in 0..256usize {
            if self.proc_kobjects[i].active && self.proc_kobjects[i].pid == pid {
                let kobj_idx = self.proc_kobjects[i].kobj_idx;
                if kobj_idx >= 0 {
                    self.destroy_kobject(kobj_idx);
                }
                self.proc_kobjects[i].active = false;
                self.proc_count -= 1;
                return true;
            }
        }
        false
    }

    pub fn update_process_state(&mut self, pid: i32, state: u8) -> bool {
        for i in 0..256usize {
            if self.proc_kobjects[i].active && self.proc_kobjects[i].pid == pid {
                self.proc_kobjects[i].state = state;
                return true;
            }
        }
        false
    }

    pub fn update_process_mem(&mut self, pid: i32, vm_size_kb: u64, rss_kb: u64) -> bool {
        for i in 0..256usize {
            if self.proc_kobjects[i].active && self.proc_kobjects[i].pid == pid {
                self.proc_kobjects[i].vm_size_kb = vm_size_kb;
                self.proc_kobjects[i].rss_kb = rss_kb;
                return true;
            }
        }
        false
    }

    pub fn update_process_time(&mut self, pid: i32, utime: u64, stime: u64) -> bool {
        for i in 0..256usize {
            if self.proc_kobjects[i].active && self.proc_kobjects[i].pid == pid {
                self.proc_kobjects[i].utime = utime;
                self.proc_kobjects[i].stime = stime;
                return true;
            }
        }
        false
    }

    // ─── Uevent ─────────────────────────────────────────────────────

    fn emit_uevent(&mut self, action: UeventAction, kobj: &Kobject) {
        if kobj.suppress_uevent {
            return;
        }
        let idx = self.uevent_head as usize;
        self.uevents[idx] = UeventEntry::empty();
        self.uevents[idx].action = action;
        self.uevents[idx].kobj_id = kobj.id;
        self.uevents[idx].ktype = kobj.ktype_id;
        let nlen = kobj.name_len as usize;
        self.uevents[idx].path[..nlen].copy_from_slice(&kobj.name[..nlen]);
        self.uevents[idx].path_len = kobj.name_len;
        self.uevents[idx].active = true;

        self.uevent_head = (self.uevent_head + 1) % MAX_UEVENT_QUEUE as u16;
        if self.uevent_count < MAX_UEVENT_QUEUE as u16 {
            self.uevent_count += 1;
        }
        self.total_uevents += 1;
    }

    // ─── Lookup ─────────────────────────────────────────────────────

    pub fn find_by_name(&self, name: &[u8]) -> Option<i16> {
        for i in 0..MAX_KOBJECTS {
            if !self.objects[i].active {
                continue;
            }
            let len = self.objects[i].name_len as usize;
            if len == name.len() && self.objects[i].name[..len] == *name {
                return Some(i as i16);
            }
        }
        None
    }

    pub fn find_by_id(&self, id: u32) -> Option<i16> {
        for i in 0..MAX_KOBJECTS {
            if self.objects[i].active && self.objects[i].id == id {
                return Some(i as i16);
            }
        }
        None
    }
}

// ─── Utility: Format u64 to decimal ────────────────────────────────

fn format_u64(val: u64, buf: &mut [u8]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut v = val;
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    // Reverse into buf
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}

fn parse_u64(buf: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in buf {
        if b < b'0' || b > b'9' {
            break;
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u64);
    }
    val
}

// ─── Global State ───────────────────────────────────────────────────

static mut KOBJ_MGR: KobjectManager = KobjectManager::new();
static mut KOBJ_INITIALIZED: bool = false;

fn mgr() -> &'static mut KobjectManager {
    unsafe { &mut KOBJ_MGR }
}

// ─── FFI Exports ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_kobject_init() {
    let m = mgr();
    *m = KobjectManager::new();
    m.init();
    unsafe { KOBJ_INITIALIZED = true; }
}

#[no_mangle]
pub extern "C" fn rust_kobject_create(name_ptr: *const u8, name_len: usize, ktype: u8, parent: i16) -> i16 {
    if unsafe { !KOBJ_INITIALIZED } || name_ptr.is_null() || name_len == 0 {
        return -1;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let kt = match ktype {
        0 => KobjType::Generic,
        1 => KobjType::Device,
        2 => KobjType::Driver,
        3 => KobjType::Bus,
        4 => KobjType::Class,
        5 => KobjType::Module,
        6 => KobjType::Process,
        7 => KobjType::Thread,
        8 => KobjType::Filesystem,
        9 => KobjType::Network,
        10 => KobjType::Block,
        _ => KobjType::Generic,
    };
    mgr().create_kobject(name, kt, parent).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn rust_kobject_destroy(idx: i16) -> bool {
    if unsafe { !KOBJ_INITIALIZED } { return false; }
    mgr().destroy_kobject(idx)
}

#[no_mangle]
pub extern "C" fn rust_kobject_get(idx: i16) -> bool {
    if unsafe { !KOBJ_INITIALIZED } { return false; }
    mgr().kobject_get(idx)
}

#[no_mangle]
pub extern "C" fn rust_kobject_put(idx: i16) -> bool {
    if unsafe { !KOBJ_INITIALIZED } { return false; }
    mgr().kobject_put(idx)
}

#[no_mangle]
pub extern "C" fn rust_kobject_count() -> u16 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().obj_count
}

#[no_mangle]
pub extern "C" fn rust_kobject_kset_count() -> u8 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().kset_count
}

#[no_mangle]
pub extern "C" fn rust_kobject_proc_register(pid: i32, ppid: i32, comm_ptr: *const u8, comm_len: usize, uid: u32, gid: u32) -> i16 {
    if unsafe { !KOBJ_INITIALIZED } || comm_ptr.is_null() {
        return -1;
    }
    let comm = unsafe { core::slice::from_raw_parts(comm_ptr, comm_len) };
    match mgr().register_process(pid, ppid, comm, uid, gid) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_kobject_proc_unregister(pid: i32) -> bool {
    if unsafe { !KOBJ_INITIALIZED } { return false; }
    mgr().unregister_process(pid)
}

#[no_mangle]
pub extern "C" fn rust_kobject_proc_count() -> u16 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().proc_count
}

#[no_mangle]
pub extern "C" fn rust_kobject_total_creates() -> u64 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().total_creates
}

#[no_mangle]
pub extern "C" fn rust_kobject_total_destroys() -> u64 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().total_destroys
}

#[no_mangle]
pub extern "C" fn rust_kobject_total_uevents() -> u64 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().total_uevents
}

#[no_mangle]
pub extern "C" fn rust_kobject_uevent_count() -> u16 {
    if unsafe { !KOBJ_INITIALIZED } { return 0; }
    mgr().uevent_count
}
