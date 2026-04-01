// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust inotify/fanotify File Monitoring Subsystem
//
// Filesystem event notification system:
// - inotify: Per-file/directory watch with event mask filtering
// - fanotify: Global filesystem-level access monitoring
// - Event queue with overflow detection
// - Watch descriptor management with hash table lookup
// - Recursive directory watching support
// - Permission checking (fanotify FAN_ACCESS_PERM)
// - Event coalescing for duplicate suppression
// - Mount-based monitoring (fanotify)
// - Dentry name tracking for inotify IN_MOVED_TO/FROM

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ─────────────────── inotify Event Masks ────────────────────────────
pub const IN_ACCESS: u32 = 0x00000001;
pub const IN_MODIFY: u32 = 0x00000002;
pub const IN_ATTRIB: u32 = 0x00000004;
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
pub const IN_OPEN: u32 = 0x00000020;
pub const IN_MOVED_FROM: u32 = 0x00000040;
pub const IN_MOVED_TO: u32 = 0x00000080;
pub const IN_CREATE: u32 = 0x00000100;
pub const IN_DELETE: u32 = 0x00000200;
pub const IN_DELETE_SELF: u32 = 0x00000400;
pub const IN_MOVE_SELF: u32 = 0x00000800;

pub const IN_UNMOUNT: u32 = 0x00002000;
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
pub const IN_IGNORED: u32 = 0x00008000;

pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
pub const IN_ALL_EVENTS: u32 = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO
    | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF;

pub const IN_ONLYDIR: u32 = 0x01000000;
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
pub const IN_MASK_CREATE: u32 = 0x10000000;
pub const IN_MASK_ADD: u32 = 0x20000000;
pub const IN_ISDIR: u32 = 0x40000000;
pub const IN_ONESHOT: u32 = 0x80000000;

// ─────────────────── fanotify Masks ─────────────────────────────────
pub const FAN_ACCESS: u64 = 0x01;
pub const FAN_MODIFY: u64 = 0x02;
pub const FAN_ATTRIB: u64 = 0x04;
pub const FAN_CLOSE_WRITE: u64 = 0x08;
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
pub const FAN_OPEN: u64 = 0x20;
pub const FAN_MOVED_FROM: u64 = 0x40;
pub const FAN_MOVED_TO: u64 = 0x80;
pub const FAN_CREATE: u64 = 0x100;
pub const FAN_DELETE: u64 = 0x200;
pub const FAN_DELETE_SELF: u64 = 0x400;
pub const FAN_MOVE_SELF: u64 = 0x800;
pub const FAN_OPEN_EXEC: u64 = 0x1000;
pub const FAN_Q_OVERFLOW: u64 = 0x4000;
pub const FAN_OPEN_PERM: u64 = 0x10000;
pub const FAN_ACCESS_PERM: u64 = 0x20000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x40000;
pub const FAN_ONDIR: u64 = 0x40000000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x08000000;

// fanotify init flags
pub const FAN_CLOEXEC: u32 = 0x01;
pub const FAN_NONBLOCK: u32 = 0x02;
pub const FAN_CLASS_NOTIF: u32 = 0x00;
pub const FAN_CLASS_CONTENT: u32 = 0x04;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x08;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x10;
pub const FAN_UNLIMITED_MARKS: u32 = 0x20;
pub const FAN_REPORT_FID: u32 = 0x200;
pub const FAN_REPORT_DIR_FID: u32 = 0x400;
pub const FAN_REPORT_NAME: u32 = 0x800;

// fanotify mark flags
pub const FAN_MARK_ADD: u32 = 0x01;
pub const FAN_MARK_REMOVE: u32 = 0x02;
pub const FAN_MARK_FLUSH: u32 = 0x80;
pub const FAN_MARK_INODE: u32 = 0x00;
pub const FAN_MARK_MOUNT: u32 = 0x10;
pub const FAN_MARK_FILESYSTEM: u32 = 0x100;

// ─────────────────── inotify Event ──────────────────────────────────
pub const MAX_NAME_LEN: usize = 255;

#[repr(C)]
#[derive(Clone)]
pub struct InotifyEvent {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,     // for rename pairing
    pub name_len: u32,
    pub name: [u8; MAX_NAME_LEN + 1],
}

impl InotifyEvent {
    pub fn new(wd: i32, mask: u32, cookie: u32) -> Self {
        Self {
            wd,
            mask,
            cookie,
            name_len: 0,
            name: [0u8; MAX_NAME_LEN + 1],
        }
    }

    pub fn with_name(mut self, name_bytes: &[u8]) -> Self {
        let len = name_bytes.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name_bytes[..len]);
        self.name_len = len as u32;
        self
    }

    pub fn is_dir(&self) -> bool {
        self.mask & IN_ISDIR != 0
    }

    /// Serialized size for userspace read
    pub fn serialized_size(&self) -> usize {
        // struct inotify_event (16 bytes) + name (aligned to 4)
        let name_aligned = (self.name_len as usize + 4) & !3;
        16 + name_aligned
    }
}

// ─────────────────── inotify Watch ──────────────────────────────────
pub const MAX_WATCHES: usize = 256;

pub struct InotifyWatch {
    pub wd: i32,          // watch descriptor
    pub inode: u64,       // inode number being watched
    pub mask: u32,        // event mask
    pub flags: u32,       // IN_ONESHOT etc.
    pub valid: bool,
    pub hit_count: u32,   // events delivered
}

impl Default for InotifyWatch {
    fn default() -> Self {
        Self {
            wd: -1,
            inode: 0,
            mask: 0,
            flags: 0,
            valid: false,
            hit_count: 0,
        }
    }
}

// ─────────────────── inotify Instance ───────────────────────────────
pub const MAX_EVENT_QUEUE: usize = 512;

pub struct InotifyInstance {
    pub fd: i32,
    pub watches: [InotifyWatch; MAX_WATCHES],
    pub watch_count: usize,
    pub next_wd: i32,
    pub event_queue: [Option<InotifyEvent>; MAX_EVENT_QUEUE],
    pub eq_head: usize,
    pub eq_tail: usize,
    pub eq_count: usize,
    pub overflow: bool,
    pub cookie_counter: u32,
}

impl InotifyInstance {
    pub fn new(fd: i32) -> Self {
        Self {
            fd,
            watches: [const { InotifyWatch::default() }; MAX_WATCHES],
            watch_count: 0,
            next_wd: 1,
            event_queue: [const { None }; MAX_EVENT_QUEUE],
            eq_head: 0,
            eq_tail: 0,
            eq_count: 0,
            overflow: false,
            cookie_counter: 0,
        }
    }

    /// Add a watch on an inode
    pub fn add_watch(&mut self, inode: u64, mask: u32) -> i32 {
        // Check if already watching this inode
        for watch in self.watches.iter_mut() {
            if watch.valid && watch.inode == inode {
                if mask & IN_MASK_ADD != 0 {
                    watch.mask |= mask & IN_ALL_EVENTS;
                } else {
                    watch.mask = mask & IN_ALL_EVENTS;
                }
                watch.flags = mask & !IN_ALL_EVENTS;
                return watch.wd;
            }
        }

        if mask & IN_MASK_CREATE != 0 {
            // Check if already exists
            for watch in self.watches.iter() {
                if watch.valid && watch.inode == inode {
                    return -1; // EEXIST
                }
            }
        }

        // Find free slot
        for watch in self.watches.iter_mut() {
            if !watch.valid {
                let wd = self.next_wd;
                self.next_wd += 1;
                *watch = InotifyWatch {
                    wd,
                    inode,
                    mask: mask & IN_ALL_EVENTS,
                    flags: mask & !IN_ALL_EVENTS,
                    valid: true,
                    hit_count: 0,
                };
                self.watch_count += 1;
                return wd;
            }
        }
        -1 // ENOSPC
    }

    /// Remove a watch
    pub fn rm_watch(&mut self, wd: i32) -> bool {
        for watch in self.watches.iter_mut() {
            if watch.valid && watch.wd == wd {
                watch.valid = false;
                self.watch_count = self.watch_count.saturating_sub(1);
                // Queue IN_IGNORED event
                self.queue_event(InotifyEvent::new(wd, IN_IGNORED, 0));
                return true;
            }
        }
        false
    }

    /// Generate a cookie for rename pairing
    pub fn next_cookie(&mut self) -> u32 {
        self.cookie_counter += 1;
        self.cookie_counter
    }

    /// Queue an event for userspace consumption
    pub fn queue_event(&mut self, event: InotifyEvent) -> bool {
        if self.eq_count >= MAX_EVENT_QUEUE {
            if !self.overflow {
                self.overflow = true;
                // Insert overflow marker
                let overflow_ev = InotifyEvent::new(-1, IN_Q_OVERFLOW, 0);
                self.event_queue[self.eq_tail] = Some(overflow_ev);
            }
            return false;
        }

        // Coalesce: skip if identical to last event (same wd, mask, cookie, name)
        if self.eq_count > 0 {
            let prev = if self.eq_tail > 0 { self.eq_tail - 1 } else { MAX_EVENT_QUEUE - 1 };
            if let Some(ref last) = self.event_queue[prev] {
                if last.wd == event.wd && last.mask == event.mask
                    && last.cookie == event.cookie && last.name_len == event.name_len
                {
                    let same = last.name[..last.name_len as usize] == event.name[..event.name_len as usize];
                    if same {
                        return true; // Coalesced
                    }
                }
            }
        }

        self.event_queue[self.eq_tail] = Some(event);
        self.eq_tail = (self.eq_tail + 1) % MAX_EVENT_QUEUE;
        self.eq_count += 1;
        true
    }

    /// Dequeue next event
    pub fn read_event(&mut self) -> Option<InotifyEvent> {
        if self.eq_count == 0 {
            return None;
        }
        let event = self.event_queue[self.eq_head].take();
        self.eq_head = (self.eq_head + 1) % MAX_EVENT_QUEUE;
        self.eq_count -= 1;
        if self.eq_count == 0 {
            self.overflow = false;
        }
        event
    }

    /// Notify: check all watches and queue matching events
    pub fn notify(&mut self, inode: u64, mask: u32, name: Option<&[u8]>, cookie: u32) {
        for watch in self.watches.iter_mut() {
            if !watch.valid {
                continue;
            }
            if watch.inode != inode {
                continue;
            }
            if watch.mask & mask == 0 {
                continue;
            }

            let mut event = InotifyEvent::new(watch.wd, mask, cookie);
            if let Some(n) = name {
                event = event.with_name(n);
            }

            self.queue_event(event);
            watch.hit_count += 1;

            // Handle oneshot
            if watch.flags & IN_ONESHOT != 0 {
                watch.valid = false;
                self.watch_count = self.watch_count.saturating_sub(1);
                self.queue_event(InotifyEvent::new(watch.wd, IN_IGNORED, 0));
            }
        }
    }
}

// ─────────────────── fanotify Event ─────────────────────────────────
#[repr(C)]
#[derive(Clone)]
pub struct FanotifyEvent {
    pub mask: u64,
    pub fd: i32,          // file descriptor or FAN_NOFD
    pub pid: u32,         // process that caused the event
    pub inode: u64,
    pub dev: u64,         // device major:minor
    pub response: u8,     // FAN_ALLOW or FAN_DENY for perm events
    pub pending_perm: bool,
}

pub const FAN_ALLOW: u8 = 0x01;
pub const FAN_DENY: u8 = 0x02;
pub const FAN_NOFD: i32 = -1;

impl FanotifyEvent {
    pub fn new(mask: u64, pid: u32, inode: u64, dev: u64) -> Self {
        let pending = (mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM)) != 0;
        Self {
            mask,
            fd: FAN_NOFD,
            pid,
            inode,
            dev,
            response: 0,
            pending_perm: pending,
        }
    }
}

// ─────────────────── fanotify Mark ──────────────────────────────────
pub const MAX_FANOT_MARKS: usize = 128;

#[derive(Clone, Copy, PartialEq)]
pub enum FanotifyMarkType {
    Inode,
    Mount,
    Filesystem,
}

#[derive(Clone)]
pub struct FanotifyMark {
    pub mark_type: FanotifyMarkType,
    pub mask: u64,
    pub ignored_mask: u64,
    pub target: u64,     // inode, mount_id, or fsid
    pub valid: bool,
}

impl Default for FanotifyMark {
    fn default() -> Self {
        Self {
            mark_type: FanotifyMarkType::Inode,
            mask: 0,
            ignored_mask: 0,
            target: 0,
            valid: false,
        }
    }
}

// ─────────────────── fanotify Instance ──────────────────────────────
pub const MAX_FANOT_QUEUE: usize = 256;

pub struct FanotifyInstance {
    pub fd: i32,
    pub flags: u32,
    pub class: u32,
    pub marks: [FanotifyMark; MAX_FANOT_MARKS],
    pub mark_count: usize,
    pub event_queue: [Option<FanotifyEvent>; MAX_FANOT_QUEUE],
    pub eq_head: usize,
    pub eq_tail: usize,
    pub eq_count: usize,
    pub overflow: bool,
    pub perm_pending: u32,  // pending permission responses
}

impl FanotifyInstance {
    pub fn new(fd: i32, flags: u32) -> Self {
        let class = flags & (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT);
        Self {
            fd,
            flags,
            class,
            marks: [const { FanotifyMark::default() }; MAX_FANOT_MARKS],
            mark_count: 0,
            event_queue: [const { None }; MAX_FANOT_QUEUE],
            eq_head: 0,
            eq_tail: 0,
            eq_count: 0,
            overflow: false,
            perm_pending: 0,
        }
    }

    /// Add or modify a mark
    pub fn add_mark(&mut self, mark_type: FanotifyMarkType, target: u64, mask: u64) -> bool {
        // Update existing mark
        for mark in self.marks.iter_mut() {
            if mark.valid && mark.mark_type == mark_type && mark.target == target {
                mark.mask |= mask;
                return true;
            }
        }
        // New mark
        for mark in self.marks.iter_mut() {
            if !mark.valid {
                *mark = FanotifyMark {
                    mark_type,
                    mask,
                    ignored_mask: 0,
                    target,
                    valid: true,
                };
                self.mark_count += 1;
                return true;
            }
        }
        false
    }

    /// Remove mask bits from a mark
    pub fn remove_mark(&mut self, mark_type: FanotifyMarkType, target: u64, mask: u64) -> bool {
        for mark in self.marks.iter_mut() {
            if mark.valid && mark.mark_type == mark_type && mark.target == target {
                mark.mask &= !mask;
                if mark.mask == 0 {
                    mark.valid = false;
                    self.mark_count = self.mark_count.saturating_sub(1);
                }
                return true;
            }
        }
        false
    }

    /// Flush all marks of a given type
    pub fn flush_marks(&mut self, mark_type: FanotifyMarkType) {
        for mark in self.marks.iter_mut() {
            if mark.valid && mark.mark_type == mark_type {
                mark.valid = false;
                self.mark_count = self.mark_count.saturating_sub(1);
            }
        }
    }

    /// Check if an event should be generated for a filesystem operation
    pub fn should_report(&self, inode: u64, mount_id: u64, fsid: u64, event_mask: u64) -> bool {
        for mark in self.marks.iter() {
            if !mark.valid {
                continue;
            }
            let target_match = match mark.mark_type {
                FanotifyMarkType::Inode => mark.target == inode,
                FanotifyMarkType::Mount => mark.target == mount_id,
                FanotifyMarkType::Filesystem => mark.target == fsid,
            };
            if target_match && (mark.mask & event_mask) != 0 && (mark.ignored_mask & event_mask) == 0 {
                return true;
            }
        }
        false
    }

    /// Queue an event
    pub fn queue_event(&mut self, event: FanotifyEvent) -> bool {
        if self.eq_count >= MAX_FANOT_QUEUE {
            self.overflow = true;
            return false;
        }
        if event.pending_perm {
            self.perm_pending += 1;
        }
        self.event_queue[self.eq_tail] = Some(event);
        self.eq_tail = (self.eq_tail + 1) % MAX_FANOT_QUEUE;
        self.eq_count += 1;
        true
    }

    /// Read next event
    pub fn read_event(&mut self) -> Option<FanotifyEvent> {
        if self.eq_count == 0 {
            return None;
        }
        let event = self.event_queue[self.eq_head].take();
        self.eq_head = (self.eq_head + 1) % MAX_FANOT_QUEUE;
        self.eq_count -= 1;
        event
    }

    /// Respond to a permission event
    pub fn respond_perm(&mut self, fd: i32, response: u8) -> bool {
        // Find the pending permission event
        let mut idx = self.eq_head;
        for _ in 0..self.eq_count {
            if let Some(ref mut ev) = self.event_queue[idx] {
                if ev.fd == fd && ev.pending_perm {
                    ev.response = response;
                    ev.pending_perm = false;
                    self.perm_pending = self.perm_pending.saturating_sub(1);
                    return true;
                }
            }
            idx = (idx + 1) % MAX_FANOT_QUEUE;
        }
        false
    }
}

// ─────────────────── Notification Hub ───────────────────────────────
/// Central notification hub: dispatches FS events to all registered watchers
pub const MAX_INOTIFY_INSTANCES: usize = 32;
pub const MAX_FANOTIFY_INSTANCES: usize = 16;

pub struct FsNotifyHub {
    pub inotify_instances: [Option<InotifyInstance>; MAX_INOTIFY_INSTANCES],
    pub inotify_count: usize,
    pub fanotify_instances: [Option<FanotifyInstance>; MAX_FANOTIFY_INSTANCES],
    pub fanotify_count: usize,
    pub next_fd: i32,
    pub total_events: AtomicU64,
}

impl FsNotifyHub {
    pub const fn new() -> Self {
        Self {
            inotify_instances: [const { None }; MAX_INOTIFY_INSTANCES],
            inotify_count: 0,
            fanotify_instances: [const { None }; MAX_FANOTIFY_INSTANCES],
            fanotify_count: 0,
            next_fd: 100,
            total_events: AtomicU64::new(0),
        }
    }

    /// Create a new inotify instance
    pub fn inotify_init(&mut self) -> i32 {
        for slot in self.inotify_instances.iter_mut() {
            if slot.is_none() {
                let fd = self.next_fd;
                self.next_fd += 1;
                *slot = Some(InotifyInstance::new(fd));
                self.inotify_count += 1;
                return fd;
            }
        }
        -1
    }

    /// Create a new fanotify instance
    pub fn fanotify_init(&mut self, flags: u32) -> i32 {
        for slot in self.fanotify_instances.iter_mut() {
            if slot.is_none() {
                let fd = self.next_fd;
                self.next_fd += 1;
                *slot = Some(FanotifyInstance::new(fd, flags));
                self.fanotify_count += 1;
                return fd;
            }
        }
        -1
    }

    /// Close an inotify/fanotify instance
    pub fn close_instance(&mut self, fd: i32) -> bool {
        for slot in self.inotify_instances.iter_mut() {
            if let Some(inst) = slot {
                if inst.fd == fd {
                    *slot = None;
                    self.inotify_count = self.inotify_count.saturating_sub(1);
                    return true;
                }
            }
        }
        for slot in self.fanotify_instances.iter_mut() {
            if let Some(inst) = slot {
                if inst.fd == fd {
                    *slot = None;
                    self.fanotify_count = self.fanotify_count.saturating_sub(1);
                    return true;
                }
            }
        }
        false
    }

    /// Get mutable inotify instance by fd
    pub fn get_inotify(&mut self, fd: i32) -> Option<&mut InotifyInstance> {
        for slot in self.inotify_instances.iter_mut() {
            if let Some(inst) = slot {
                if inst.fd == fd {
                    return Some(inst);
                }
            }
        }
        None
    }

    /// Get mutable fanotify instance by fd
    pub fn get_fanotify(&mut self, fd: i32) -> Option<&mut FanotifyInstance> {
        for slot in self.fanotify_instances.iter_mut() {
            if let Some(inst) = slot {
                if inst.fd == fd {
                    return Some(inst);
                }
            }
        }
        None
    }

    /// Broadcast FS event to all inotify instances
    pub fn notify_inotify(&mut self, inode: u64, mask: u32, name: Option<&[u8]>, cookie: u32) {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        for slot in self.inotify_instances.iter_mut() {
            if let Some(inst) = slot {
                inst.notify(inode, mask, name, cookie);
            }
        }
    }

    /// Broadcast FS event to all fanotify instances
    pub fn notify_fanotify(&mut self, inode: u64, mount_id: u64, fsid: u64, mask: u64, pid: u32) {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        for slot in self.fanotify_instances.iter_mut() {
            if let Some(inst) = slot {
                if inst.should_report(inode, mount_id, fsid, mask) {
                    let event = FanotifyEvent::new(mask, pid, inode, mount_id);
                    inst.queue_event(event);
                }
            }
        }
    }
}

// ─────────────────── Global Instance ────────────────────────────────
static mut FSNOTIFY_HUB: FsNotifyHub = FsNotifyHub::new();

pub fn init_fsnotify() {
    // Already initialized via const fn
}

// ─────────────────── FFI Exports ────────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_inotify_init() -> i32 {
    unsafe { FSNOTIFY_HUB.inotify_init() }
}

#[no_mangle]
pub extern "C" fn rust_inotify_add_watch(fd: i32, inode: u64, mask: u32) -> i32 {
    unsafe {
        if let Some(inst) = FSNOTIFY_HUB.get_inotify(fd) {
            inst.add_watch(inode, mask)
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_inotify_rm_watch(fd: i32, wd: i32) -> bool {
    unsafe {
        if let Some(inst) = FSNOTIFY_HUB.get_inotify(fd) {
            inst.rm_watch(wd)
        } else {
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_fanotify_init(flags: u32) -> i32 {
    unsafe { FSNOTIFY_HUB.fanotify_init(flags) }
}

#[no_mangle]
pub extern "C" fn rust_fanotify_mark(fd: i32, flags: u32, mask: u64, target: u64) -> bool {
    unsafe {
        if let Some(inst) = FSNOTIFY_HUB.get_fanotify(fd) {
            if flags & FAN_MARK_ADD != 0 {
                let mark_type = if flags & FAN_MARK_MOUNT != 0 {
                    FanotifyMarkType::Mount
                } else if flags & FAN_MARK_FILESYSTEM != 0 {
                    FanotifyMarkType::Filesystem
                } else {
                    FanotifyMarkType::Inode
                };
                inst.add_mark(mark_type, target, mask)
            } else if flags & FAN_MARK_REMOVE != 0 {
                inst.remove_mark(FanotifyMarkType::Inode, target, mask)
            } else if flags & FAN_MARK_FLUSH != 0 {
                inst.flush_marks(FanotifyMarkType::Inode);
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_fsnotify_event_count() -> u64 {
    unsafe { FSNOTIFY_HUB.total_events.load(Ordering::Relaxed) }
}

#[no_mangle]
pub extern "C" fn rust_fsnotify_close(fd: i32) -> bool {
    unsafe { FSNOTIFY_HUB.close_instance(fd) }
}

#[no_mangle]
pub extern "C" fn rust_inotify_instance_count() -> u32 {
    unsafe { FSNOTIFY_HUB.inotify_count as u32 }
}

#[no_mangle]
pub extern "C" fn rust_fanotify_instance_count() -> u32 {
    unsafe { FSNOTIFY_HUB.fanotify_count as u32 }
}
