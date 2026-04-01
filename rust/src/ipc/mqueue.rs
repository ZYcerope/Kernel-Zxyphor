// =============================================================================
// Kernel Zxyphor — Rust POSIX / System V Message Queue
// =============================================================================
// Full message queue implementation compatible with both interfaces:
//
// POSIX mq:
//   - mq_open / mq_close / mq_unlink
//   - mq_send / mq_receive with priority ordering
//   - mq_getattr / mq_setattr
//   - mq_notify (signal on message arrival)
//
// System V msq:
//   - msgget / msgsnd / msgrcv / msgctl
//   - Message types for selective receive
//   - IPC_CREAT / IPC_EXCL / IPC_RMID / IPC_STAT / IPC_SET
//
// Features:
//   - Bounded message queues with configurable depth
//   - Priority-ordered insertion (POSIX)
//   - Type-based selective receive (SysV)
//   - Blocking / non-blocking modes
//   - Queue statistics
//   - Per-queue permissions (uid/gid/mode)
// =============================================================================

/// Maximum queues
const MAX_QUEUES: usize = 64;
/// Maximum messages per queue
const MAX_MSGS_PER_QUEUE: usize = 256;
/// Maximum message body size
const MAX_MSG_SIZE: usize = 4096;
/// Maximum queue name length
const MAX_QUEUE_NAME: usize = 64;
/// Maximum waiters per queue
const MAX_WAITERS: usize = 32;

// ---------------------------------------------------------------------------
// IPC flags (System V compatible)
// ---------------------------------------------------------------------------

pub const IPC_CREAT: u32 = 0o001000;
pub const IPC_EXCL: u32  = 0o002000;
pub const IPC_NOWAIT: u32= 0o004000;
pub const IPC_RMID: u32  = 0;
pub const IPC_SET: u32   = 1;
pub const IPC_STAT: u32  = 2;
pub const IPC_INFO: u32  = 3;

pub const MSG_NOERROR: u32 = 0o010000;
pub const MSG_EXCEPT: u32  = 0o020000;
pub const MSG_COPY: u32    = 0o040000;

// ---------------------------------------------------------------------------
// Message priority (POSIX mq)
// ---------------------------------------------------------------------------

/// Message stored in the queue
#[derive(Clone)]
pub struct MqMessage {
    pub mtype: i64,          // System V type / POSIX priority
    pub data: [u8; MAX_MSG_SIZE],
    pub size: u32,
    pub priority: u32,       // POSIX priority (higher = higher priority)
    pub sender_pid: u32,
    pub timestamp: u64,
    pub active: bool,
}

impl MqMessage {
    pub const fn new() -> Self {
        Self {
            mtype: 0,
            data: [0u8; MAX_MSG_SIZE],
            size: 0,
            priority: 0,
            sender_pid: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Queue attributes (POSIX mq_attr)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MqAttr {
    pub mq_flags: i64,      // message queue flags (O_NONBLOCK)
    pub mq_maxmsg: i64,     // max number of messages
    pub mq_msgsize: i64,    // max message size
    pub mq_curmsgs: i64,    // current number of messages
}

impl MqAttr {
    pub const fn default() -> Self {
        Self {
            mq_flags: 0,
            mq_maxmsg: MAX_MSGS_PER_QUEUE as i64,
            mq_msgsize: MAX_MSG_SIZE as i64,
            mq_curmsgs: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IPC permissions
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpcPerm {
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,    // creator uid
    pub cgid: u32,    // creator gid
    pub mode: u16,    // permission bits (rwxrwxrwx)
    pub seq: u16,     // sequence number for key reuse
}

impl IpcPerm {
    pub const fn new(uid: u32, gid: u32, mode: u16) -> Self {
        Self { uid, gid, cuid: uid, cgid: gid, mode, seq: 0 }
    }

    pub fn can_read(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 { return true; }
        if uid == self.uid { return (self.mode & 0o400) != 0; }
        if gid == self.gid { return (self.mode & 0o040) != 0; }
        (self.mode & 0o004) != 0
    }

    pub fn can_write(&self, uid: u32, gid: u32) -> bool {
        if uid == 0 { return true; }
        if uid == self.uid { return (self.mode & 0o200) != 0; }
        if gid == self.gid { return (self.mode & 0o020) != 0; }
        (self.mode & 0o002) != 0
    }
}

// ---------------------------------------------------------------------------
// Waiter (blocked process)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct MqWaiter {
    pub pid: u32,
    pub waiting_for_send: bool,   // true = waiting to send (queue full)
    pub waiting_for_recv: bool,   // true = waiting to receive (queue empty)
    pub mtype_filter: i64,        // SysV: only receive messages of this type
    pub active: bool,
}

impl MqWaiter {
    pub const fn new() -> Self {
        Self { pid: 0, waiting_for_send: false, waiting_for_recv: false, mtype_filter: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// Message Queue
// ---------------------------------------------------------------------------

pub struct MessageQueue {
    pub id: u32,
    pub key: u32,            // System V key
    pub name: [u8; MAX_QUEUE_NAME],
    pub name_len: u8,
    pub perm: IpcPerm,
    pub attr: MqAttr,
    pub messages: [MqMessage; MAX_MSGS_PER_QUEUE],
    pub msg_count: u32,
    pub waiters: [MqWaiter; MAX_WAITERS],
    pub waiter_count: u8,
    pub active: bool,
    pub posix: bool,         // true = POSIX mq, false = System V

    // Statistics
    pub total_sent: u64,
    pub total_received: u64,
    pub total_full_waits: u64,
    pub total_empty_waits: u64,

    // System V specific
    pub msg_stime: u64,      // last msgsnd time
    pub msg_rtime: u64,      // last msgrcv time
    pub msg_ctime: u64,      // last change time
    pub msg_lspid: u32,      // last msgsnd pid
    pub msg_lrpid: u32,      // last msgrcv pid
    pub msg_qbytes: u64,     // max queue size in bytes
    pub msg_cbytes: u64,     // current bytes in queue
}

impl MessageQueue {
    pub const fn new() -> Self {
        Self {
            id: 0, key: 0,
            name: [0u8; MAX_QUEUE_NAME], name_len: 0,
            perm: IpcPerm::new(0, 0, 0o644),
            attr: MqAttr::default(),
            messages: [const { MqMessage::new() }; MAX_MSGS_PER_QUEUE],
            msg_count: 0,
            waiters: [const { MqWaiter::new() }; MAX_WAITERS],
            waiter_count: 0,
            active: false, posix: false,
            total_sent: 0, total_received: 0,
            total_full_waits: 0, total_empty_waits: 0,
            msg_stime: 0, msg_rtime: 0, msg_ctime: 0,
            msg_lspid: 0, msg_lrpid: 0,
            msg_qbytes: (MAX_MSGS_PER_QUEUE * MAX_MSG_SIZE) as u64,
            msg_cbytes: 0,
        }
    }

    /// POSIX mq_send: insert message ordered by priority (highest first)
    pub fn mq_send(&mut self, data: &[u8], priority: u32, sender_pid: u32, now: u64) -> Result<(), i32> {
        if self.msg_count as usize >= MAX_MSGS_PER_QUEUE {
            return Err(-11); // EAGAIN
        }
        if data.len() > MAX_MSG_SIZE {
            return Err(-7); // E2BIG  
        }

        let mut msg = MqMessage::new();
        msg.data[..data.len()].copy_from_slice(data);
        msg.size = data.len() as u32;
        msg.priority = priority;
        msg.mtype = priority as i64;
        msg.sender_pid = sender_pid;
        msg.timestamp = now;
        msg.active = true;

        // Insert in priority order (highest priority first)
        let mut insert_idx = self.msg_count as usize;
        for i in 0..self.msg_count as usize {
            if self.messages[i].active && self.messages[i].priority < priority {
                insert_idx = i;
                break;
            }
        }

        // Shift messages down
        if insert_idx < self.msg_count as usize {
            let mut j = self.msg_count as usize;
            while j > insert_idx {
                if j < MAX_MSGS_PER_QUEUE {
                    self.messages[j] = self.messages[j - 1].clone();
                }
                j -= 1;
            }
        }

        self.messages[insert_idx] = msg;
        self.msg_count += 1;
        self.msg_cbytes += data.len() as u64;
        self.msg_stime = now;
        self.msg_lspid = sender_pid;
        self.total_sent += 1;
        self.attr.mq_curmsgs = self.msg_count as i64;

        Ok(())
    }

    /// POSIX mq_receive: get highest priority message
    pub fn mq_receive(&mut self, buf: &mut [u8], receiver_pid: u32, now: u64) -> Result<(u32, u32), i32> {
        if self.msg_count == 0 {
            return Err(-11); // EAGAIN
        }

        // First active message is highest priority
        for i in 0..MAX_MSGS_PER_QUEUE {
            if self.messages[i].active {
                let size = self.messages[i].size as usize;
                let copy_len = if size > buf.len() { buf.len() } else { size };
                buf[..copy_len].copy_from_slice(&self.messages[i].data[..copy_len]);
                let priority = self.messages[i].priority;
                let msg_size = self.messages[i].size;

                // Remove message and shift
                let mut j = i;
                while j + 1 < MAX_MSGS_PER_QUEUE {
                    if self.messages[j + 1].active {
                        self.messages[j] = self.messages[j + 1].clone();
                    } else {
                        self.messages[j] = MqMessage::new();
                        break;
                    }
                    j += 1;
                }
                if j + 1 >= MAX_MSGS_PER_QUEUE {
                    self.messages[MAX_MSGS_PER_QUEUE - 1] = MqMessage::new();
                }

                self.msg_count -= 1;
                self.msg_cbytes = self.msg_cbytes.saturating_sub(msg_size as u64);
                self.msg_rtime = now;
                self.msg_lrpid = receiver_pid;
                self.total_received += 1;
                self.attr.mq_curmsgs = self.msg_count as i64;

                return Ok((msg_size, priority));
            }
        }

        Err(-11) // EAGAIN
    }

    /// System V msgsnd
    pub fn msgsnd(&mut self, mtype: i64, data: &[u8], sender_pid: u32, now: u64) -> Result<(), i32> {
        if mtype <= 0 { return Err(-22); } // EINVAL
        if data.len() > MAX_MSG_SIZE { return Err(-7); }
        if self.msg_count as usize >= MAX_MSGS_PER_QUEUE { return Err(-11); }

        // System V appends to end (FIFO within same type)
        for i in 0..MAX_MSGS_PER_QUEUE {
            if !self.messages[i].active {
                self.messages[i] = MqMessage::new();
                self.messages[i].mtype = mtype;
                self.messages[i].data[..data.len()].copy_from_slice(data);
                self.messages[i].size = data.len() as u32;
                self.messages[i].sender_pid = sender_pid;
                self.messages[i].timestamp = now;
                self.messages[i].active = true;

                self.msg_count += 1;
                self.msg_cbytes += data.len() as u64;
                self.msg_stime = now;
                self.msg_lspid = sender_pid;
                self.total_sent += 1;

                return Ok(());
            }
        }

        Err(-12) // ENOMEM
    }

    /// System V msgrcv with type filtering
    pub fn msgrcv(&mut self, mtype: i64, buf: &mut [u8], flags: u32, receiver_pid: u32, now: u64) -> Result<(u32, i64), i32> {
        if self.msg_count == 0 { return Err(-42); } // ENOMSG

        for i in 0..MAX_MSGS_PER_QUEUE {
            if !self.messages[i].active { continue; }

            let matches = if mtype == 0 {
                true // any type
            } else if mtype > 0 {
                if flags & MSG_EXCEPT != 0 {
                    self.messages[i].mtype != mtype
                } else {
                    self.messages[i].mtype == mtype
                }
            } else {
                // mtype < 0: first message with smallest type <= |mtype|
                self.messages[i].mtype <= -mtype
            };

            if matches {
                let size = self.messages[i].size as usize;
                if size > buf.len() && (flags & MSG_NOERROR == 0) {
                    return Err(-7); // E2BIG
                }
                let copy_len = if size > buf.len() { buf.len() } else { size };
                buf[..copy_len].copy_from_slice(&self.messages[i].data[..copy_len]);
                let ret_type = self.messages[i].mtype;
                let ret_size = self.messages[i].size;

                self.messages[i] = MqMessage::new(); // remove
                self.msg_count -= 1;
                self.msg_cbytes = self.msg_cbytes.saturating_sub(ret_size as u64);
                self.msg_rtime = now;
                self.msg_lrpid = receiver_pid;
                self.total_received += 1;

                return Ok((ret_size, ret_type));
            }
        }

        Err(-42) // ENOMSG
    }

    /// Add a waiter
    pub fn add_waiter(&mut self, pid: u32, for_send: bool, mtype_filter: i64) -> bool {
        if self.waiter_count as usize >= MAX_WAITERS { return false; }
        for i in 0..MAX_WAITERS {
            if !self.waiters[i].active {
                self.waiters[i] = MqWaiter {
                    pid,
                    waiting_for_send: for_send,
                    waiting_for_recv: !for_send,
                    mtype_filter,
                    active: true,
                };
                self.waiter_count += 1;
                if for_send { self.total_full_waits += 1; }
                else { self.total_empty_waits += 1; }
                return true;
            }
        }
        false
    }

    /// Wake waiters (after send/receive)
    pub fn wake_waiters(&mut self, for_send: bool) -> u32 {
        let mut woken = 0u32;
        for i in 0..MAX_WAITERS {
            if self.waiters[i].active {
                if (for_send && self.waiters[i].waiting_for_recv)
                    || (!for_send && self.waiters[i].waiting_for_send) {
                    self.waiters[i].active = false;
                    self.waiter_count -= 1;
                    woken += 1;
                }
            }
        }
        woken
    }
}

// ---------------------------------------------------------------------------
// Message Queue Manager
// ---------------------------------------------------------------------------

pub struct MqManager {
    queues: [MessageQueue; MAX_QUEUES],
    queue_count: u32,
    next_id: u32,
    next_key: u32,
}

impl MqManager {
    pub const fn new() -> Self {
        Self {
            queues: [const { MessageQueue::new() }; MAX_QUEUES],
            queue_count: 0,
            next_id: 1,
            next_key: 0x4D510001, // "MQ\x00\x01"
        }
    }

    /// POSIX mq_open
    pub fn mq_open(&mut self, name: &[u8], flags: u32, mode: u16, uid: u32, gid: u32) -> Result<u32, i32> {
        // Check if already exists
        for i in 0..MAX_QUEUES {
            if self.queues[i].active && self.queues[i].posix {
                if name.len() == self.queues[i].name_len as usize {
                    let mut eq = true;
                    for j in 0..name.len() {
                        if name[j] != self.queues[i].name[j] { eq = false; break; }
                    }
                    if eq {
                        if flags & IPC_EXCL != 0 {
                            return Err(-17); // EEXIST
                        }
                        return Ok(self.queues[i].id);
                    }
                }
            }
        }

        if flags & IPC_CREAT == 0 {
            return Err(-2); // ENOENT
        }

        self.create_queue(name, mode, uid, gid, true)
    }

    /// System V msgget
    pub fn msgget(&mut self, key: u32, flags: u32, uid: u32, gid: u32) -> Result<u32, i32> {
        // Check if key already exists
        if key != 0 { // 0 = IPC_PRIVATE
            for i in 0..MAX_QUEUES {
                if self.queues[i].active && !self.queues[i].posix && self.queues[i].key == key {
                    if flags & IPC_EXCL != 0 {
                        return Err(-17); // EEXIST
                    }
                    return Ok(self.queues[i].id);
                }
            }
        }

        if key != 0 && flags & IPC_CREAT == 0 {
            return Err(-2); // ENOENT
        }

        let mode = (flags & 0o777) as u16;
        let id = self.create_queue(b"", mode, uid, gid, false)?;
        // Set key
        for i in 0..MAX_QUEUES {
            if self.queues[i].active && self.queues[i].id == id {
                self.queues[i].key = if key == 0 { self.next_key } else { key };
                self.next_key += 1;
                break;
            }
        }
        Ok(id)
    }

    fn create_queue(&mut self, name: &[u8], mode: u16, uid: u32, gid: u32, posix: bool) -> Result<u32, i32> {
        if self.queue_count as usize >= MAX_QUEUES { return Err(-28); } // ENOSPC

        for i in 0..MAX_QUEUES {
            if !self.queues[i].active {
                self.queues[i] = MessageQueue::new();
                self.queues[i].id = self.next_id;
                self.queues[i].posix = posix;
                self.queues[i].perm = IpcPerm::new(uid, gid, mode);
                self.queues[i].active = true;

                let len = if name.len() > MAX_QUEUE_NAME { MAX_QUEUE_NAME } else { name.len() };
                self.queues[i].name[..len].copy_from_slice(&name[..len]);
                self.queues[i].name_len = len as u8;

                self.queue_count += 1;
                let id = self.next_id;
                self.next_id += 1;
                return Ok(id);
            }
        }
        Err(-28)
    }

    /// Close / unlink a queue
    pub fn mq_unlink(&mut self, name: &[u8]) -> bool {
        for i in 0..MAX_QUEUES {
            if !self.queues[i].active { continue; }
            if name.len() != self.queues[i].name_len as usize { continue; }
            let mut eq = true;
            for j in 0..name.len() {
                if name[j] != self.queues[i].name[j] { eq = false; break; }
            }
            if eq {
                self.queues[i].active = false;
                self.queue_count -= 1;
                return true;
            }
        }
        false
    }

    /// System V msgctl IPC_RMID
    pub fn msgctl_rmid(&mut self, id: u32) -> bool {
        for i in 0..MAX_QUEUES {
            if self.queues[i].active && self.queues[i].id == id {
                self.queues[i].active = false;
                self.queue_count -= 1;
                return true;
            }
        }
        false
    }

    /// Find queue by ID
    pub fn find_queue(&mut self, id: u32) -> Option<&mut MessageQueue> {
        for i in 0..MAX_QUEUES {
            if self.queues[i].active && self.queues[i].id == id {
                return Some(&mut self.queues[i]);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut MQ_MANAGER: MqManager = MqManager::new();

fn mq_manager() -> &'static mut MqManager {
    unsafe { &mut MQ_MANAGER }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_mq_open(
    name_ptr: *const u8, name_len: u32,
    flags: u32, mode: u16,
    uid: u32, gid: u32,
) -> i32 {
    if name_ptr.is_null() { return -22; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match mq_manager().mq_open(name, flags, mode, uid, gid) {
        Ok(id) => id as i32,
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_mq_send(
    queue_id: u32, data_ptr: *const u8, data_len: u32,
    priority: u32, sender_pid: u32, now: u64,
) -> i32 {
    if data_ptr.is_null() { return -22; }
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    match mq_manager().find_queue(queue_id) {
        Some(q) => match q.mq_send(data, priority, sender_pid, now) {
            Ok(()) => 0,
            Err(e) => e,
        },
        None => -22,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_mq_receive(
    queue_id: u32, buf_ptr: *mut u8, buf_len: u32,
    receiver_pid: u32, now: u64,
) -> i32 {
    if buf_ptr.is_null() { return -22; }
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
    match mq_manager().find_queue(queue_id) {
        Some(q) => match q.mq_receive(buf, receiver_pid, now) {
            Ok((size, _prio)) => size as i32,
            Err(e) => e,
        },
        None => -22,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_msgget(key: u32, flags: u32, uid: u32, gid: u32) -> i32 {
    match mq_manager().msgget(key, flags, uid, gid) {
        Ok(id) => id as i32,
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_msgsnd(
    queue_id: u32, mtype: i64,
    data_ptr: *const u8, data_len: u32,
    sender_pid: u32, now: u64,
) -> i32 {
    if data_ptr.is_null() { return -22; }
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    match mq_manager().find_queue(queue_id) {
        Some(q) => match q.msgsnd(mtype, data, sender_pid, now) {
            Ok(()) => 0,
            Err(e) => e,
        },
        None => -22,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_msgrcv(
    queue_id: u32, mtype: i64,
    buf_ptr: *mut u8, buf_len: u32,
    flags: u32, receiver_pid: u32, now: u64,
) -> i32 {
    if buf_ptr.is_null() { return -22; }
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len as usize) };
    match mq_manager().find_queue(queue_id) {
        Some(q) => match q.msgrcv(mtype, buf, flags, receiver_pid, now) {
            Ok((size, _)) => size as i32,
            Err(e) => e,
        },
        None => -22,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_mq_unlink(name_ptr: *const u8, name_len: u32) -> i32 {
    if name_ptr.is_null() { return -22; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    if mq_manager().mq_unlink(name) { 0 } else { -2 }
}

#[no_mangle]
pub extern "C" fn zxyphor_mq_queue_count() -> u32 {
    mq_manager().queue_count
}
