// =============================================================================
// Kernel Zxyphor — Message Passing IPC
// =============================================================================
// Implements a kernel message passing mechanism for inter-process communication:
//   - Fixed-size message mailboxes (no heap allocation)
//   - Per-process mailbox with configurable depth
//   - Priority messages (urgent bypass normal queue)
//   - Synchronous send/receive with optional timeout
//   - Broadcast messages (one-to-many)
//   - Message types: Data, Signal, Request/Reply, Notification
//   - Zero-copy for large payloads via shared memory reference
//   - Message sequence numbers for request/reply correlation
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =============================================================================
// Message types and structures
// =============================================================================

pub const MAX_MSG_DATA: usize = 64;   // Inline data size per message
pub const MAX_MAILBOX_DEPTH: usize = 64;
pub const MAX_MAILBOXES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Data = 0,          // Raw data payload
    Signal = 1,        // Signal-like notification
    Request = 2,       // Request expecting a reply
    Reply = 3,         // Reply to a request
    Notification = 4,  // Async notification (no reply expected)
    Broadcast = 5,     // Sent to all listeners
    Error = 6,         // Error response
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Urgent = 3,    // Bypasses normal queue
}

/// A kernel IPC message
#[derive(Clone, Copy)]
pub struct Message {
    pub msg_type: MessageType,
    pub priority: MessagePriority,
    pub sender_pid: u32,
    pub receiver_pid: u32,
    pub seq_num: u64,          // Sequence number for correlation
    pub reply_to: u64,         // Sequence number of request (for replies)
    pub timestamp: u64,        // Kernel timestamp
    pub code: u32,             // Message code / operation
    pub data_len: u16,
    pub data: [u8; MAX_MSG_DATA],
    pub shm_key: u32,         // Shared memory key for large payloads (0 = none)
    pub shm_offset: u64,      // Offset within shared memory
    pub shm_size: u64,        // Size of shared memory payload
    pub flags: u16,
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            msg_type: MessageType::Data,
            priority: MessagePriority::Normal,
            sender_pid: 0,
            receiver_pid: 0,
            seq_num: 0,
            reply_to: 0,
            timestamp: 0,
            code: 0,
            data_len: 0,
            data: [0u8; MAX_MSG_DATA],
            shm_key: 0,
            shm_offset: 0,
            shm_size: 0,
            flags: 0,
        }
    }

    /// Create a data message
    pub fn data(sender: u32, receiver: u32, code: u32, payload: &[u8]) -> Self {
        let mut msg = Self::empty();
        msg.msg_type = MessageType::Data;
        msg.sender_pid = sender;
        msg.receiver_pid = receiver;
        msg.code = code;
        let len = core::cmp::min(payload.len(), MAX_MSG_DATA);
        msg.data[..len].copy_from_slice(&payload[..len]);
        msg.data_len = len as u16;
        msg
    }

    /// Create a request message
    pub fn request(sender: u32, receiver: u32, code: u32, payload: &[u8], seq: u64) -> Self {
        let mut msg = Self::data(sender, receiver, code, payload);
        msg.msg_type = MessageType::Request;
        msg.seq_num = seq;
        msg
    }

    /// Create a reply message
    pub fn reply(sender: u32, receiver: u32, code: u32, payload: &[u8], reply_to: u64) -> Self {
        let mut msg = Self::data(sender, receiver, code, payload);
        msg.msg_type = MessageType::Reply;
        msg.reply_to = reply_to;
        msg
    }

    /// Create a notification
    pub fn notification(sender: u32, receiver: u32, code: u32) -> Self {
        let mut msg = Self::empty();
        msg.msg_type = MessageType::Notification;
        msg.sender_pid = sender;
        msg.receiver_pid = receiver;
        msg.code = code;
        msg
    }

    /// Create a signal-like message
    pub fn signal(sender: u32, receiver: u32, signal_num: u32) -> Self {
        Self::notification(sender, receiver, signal_num)
    }

    /// Check if this is a high-priority message
    pub fn is_urgent(&self) -> bool {
        self.priority as u8 >= MessagePriority::Urgent as u8
    }

    /// Attach shared memory reference for zero-copy large payloads
    pub fn with_shm(mut self, key: u32, offset: u64, size: u64) -> Self {
        self.shm_key = key;
        self.shm_offset = offset;
        self.shm_size = size;
        self
    }

    /// Total payload size (inline + shared memory)
    pub fn total_payload_size(&self) -> u64 {
        self.data_len as u64 + self.shm_size
    }
}

// =============================================================================
// Mailbox
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MailboxState {
    Free = 0,
    Active = 1,
    Full = 2,
    Closed = 3,
}

pub struct Mailbox {
    pub owner_pid: u32,
    pub state: MailboxState,
    pub messages: [Message; MAX_MAILBOX_DEPTH],
    pub head: usize,
    pub tail: usize,
    pub count: usize,
    pub max_depth: usize,
    // Statistics
    pub total_received: u64,
    pub total_sent: u64,
    pub dropped: u64,
    pub overflows: u64,
    // Waiting state
    pub blocked_sender: Option<u32>,   // PID of blocked sender
    pub blocked_receiver: Option<u32>, // PID of blocked receiver
    // Sequence number generator
    pub next_seq: AtomicU64,
}

impl Mailbox {
    pub const fn new() -> Self {
        Self {
            owner_pid: 0,
            state: MailboxState::Free,
            messages: [const { Message::empty() }; MAX_MAILBOX_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
            max_depth: MAX_MAILBOX_DEPTH,
            total_received: 0,
            total_sent: 0,
            dropped: 0,
            overflows: 0,
            blocked_sender: None,
            blocked_receiver: None,
            next_seq: AtomicU64::new(1),
        }
    }

    /// Initialize a mailbox for a process
    pub fn init(&mut self, pid: u32, depth: usize) {
        self.owner_pid = pid;
        self.state = MailboxState::Active;
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        self.max_depth = core::cmp::min(depth, MAX_MAILBOX_DEPTH);
        self.total_received = 0;
        self.total_sent = 0;
        self.dropped = 0;
        self.overflows = 0;
        self.blocked_sender = None;
        self.blocked_receiver = None;
    }

    /// Send a message to this mailbox
    pub fn send(&mut self, mut msg: Message) -> Result<u64, SendError> {
        if self.state != MailboxState::Active {
            return Err(SendError::MailboxClosed);
        }

        if self.count >= self.max_depth {
            if msg.is_urgent() {
                // Drop oldest non-urgent message to make room
                if !self.drop_oldest_non_urgent() {
                    self.overflows += 1;
                    return Err(SendError::Full);
                }
            } else {
                self.overflows += 1;
                return Err(SendError::Full);
            }
        }

        // Assign sequence number
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        msg.seq_num = seq;

        // Insert message
        if msg.is_urgent() {
            // Urgent: insert at head (LIFO for urgent)
            if self.head == 0 {
                self.head = self.max_depth - 1;
            } else {
                self.head -= 1;
            }
            self.messages[self.head] = msg;
        } else {
            // Normal: insert at tail (FIFO)
            self.messages[self.tail] = msg;
            self.tail = (self.tail + 1) % self.max_depth;
        }
        self.count += 1;
        self.total_received += 1;

        if self.count >= self.max_depth {
            self.state = MailboxState::Full;
        }

        Ok(seq)
    }

    /// Receive a message from this mailbox
    pub fn receive(&mut self) -> Option<Message> {
        if self.count == 0 {
            return None;
        }

        let msg = self.messages[self.head];
        self.head = (self.head + 1) % self.max_depth;
        self.count -= 1;
        self.total_sent += 1;

        if self.state == MailboxState::Full {
            self.state = MailboxState::Active;
        }

        Some(msg)
    }

    /// Receive a message matching a specific type
    pub fn receive_typed(&mut self, msg_type: MessageType) -> Option<Message> {
        // Linear scan for matching message (could be optimized)
        let mut idx = self.head;
        for i in 0..self.count {
            if self.messages[idx].msg_type as u8 == msg_type as u8 {
                let msg = self.messages[idx];
                // Remove from queue by shifting
                self.remove_at_offset(i);
                return Some(msg);
            }
            idx = (idx + 1) % self.max_depth;
        }
        None
    }

    /// Receive a reply to a specific request
    pub fn receive_reply(&mut self, request_seq: u64) -> Option<Message> {
        let mut idx = self.head;
        for i in 0..self.count {
            if self.messages[idx].msg_type as u8 == MessageType::Reply as u8
                && self.messages[idx].reply_to == request_seq
            {
                let msg = self.messages[idx];
                self.remove_at_offset(i);
                return Some(msg);
            }
            idx = (idx + 1) % self.max_depth;
        }
        None
    }

    /// Peek at the next message without removing it
    pub fn peek(&self) -> Option<&Message> {
        if self.count == 0 {
            return None;
        }
        Some(&self.messages[self.head])
    }

    /// Number of pending messages
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Check if the mailbox is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the mailbox is full
    pub fn is_full(&self) -> bool {
        self.count >= self.max_depth
    }

    /// Close the mailbox
    pub fn close(&mut self) {
        self.state = MailboxState::Closed;
    }

    fn remove_at_offset(&mut self, offset: usize) {
        if offset == 0 {
            self.head = (self.head + 1) % self.max_depth;
        } else {
            // Shift messages to fill the gap
            let mut src = (self.head + offset + 1) % self.max_depth;
            let mut dst = (self.head + offset) % self.max_depth;
            for _ in offset + 1..self.count {
                self.messages[dst] = self.messages[src];
                dst = src;
                src = (src + 1) % self.max_depth;
            }
            if self.tail == 0 {
                self.tail = self.max_depth - 1;
            } else {
                self.tail -= 1;
            }
        }
        self.count -= 1;
        self.total_sent += 1;
    }

    fn drop_oldest_non_urgent(&mut self) -> bool {
        let mut idx = self.head;
        for i in 0..self.count {
            if !self.messages[idx].is_urgent() {
                self.remove_at_offset(i);
                self.dropped += 1;
                return true;
            }
            idx = (idx + 1) % self.max_depth;
        }
        false
    }
}

// =============================================================================
// Error types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    Full,
    MailboxClosed,
    InvalidReceiver,
    PermissionDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    Empty,
    MailboxClosed,
    Timeout,
    Interrupted,
}

// =============================================================================
// Global mailbox registry
// =============================================================================

pub struct MailboxRegistry {
    mailboxes: [Mailbox; MAX_MAILBOXES],
    count: usize,
    total_messages: AtomicU64,
}

impl MailboxRegistry {
    pub const fn new() -> Self {
        Self {
            mailboxes: [const { Mailbox::new() }; MAX_MAILBOXES],
            count: 0,
            total_messages: AtomicU64::new(0),
        }
    }

    /// Create a mailbox for a process
    pub fn create(&mut self, pid: u32) -> Option<u32> {
        // Check for existing mailbox
        for i in 0..self.count {
            if self.mailboxes[i].owner_pid == pid && self.mailboxes[i].state == MailboxState::Active {
                return Some(i as u32);
            }
        }

        // Find a free slot
        for i in 0..MAX_MAILBOXES {
            if self.mailboxes[i].state == MailboxState::Free {
                self.mailboxes[i].init(pid, MAX_MAILBOX_DEPTH);
                if i >= self.count {
                    self.count = i + 1;
                }
                return Some(i as u32);
            }
        }
        None
    }

    /// Destroy a mailbox
    pub fn destroy(&mut self, mbx_id: u32) {
        if (mbx_id as usize) < MAX_MAILBOXES {
            self.mailboxes[mbx_id as usize].close();
            self.mailboxes[mbx_id as usize].state = MailboxState::Free;
        }
    }

    /// Send a message to a process's mailbox
    pub fn send_to_pid(&mut self, msg: Message) -> Result<u64, SendError> {
        let target_pid = msg.receiver_pid;
        for i in 0..self.count {
            if self.mailboxes[i].owner_pid == target_pid
                && self.mailboxes[i].state != MailboxState::Free
                && self.mailboxes[i].state != MailboxState::Closed
            {
                let result = self.mailboxes[i].send(msg)?;
                self.total_messages.fetch_add(1, Ordering::Relaxed);
                return Ok(result);
            }
        }
        Err(SendError::InvalidReceiver)
    }

    /// Receive from a specific mailbox
    pub fn receive_from(&mut self, mbx_id: u32) -> Option<Message> {
        if (mbx_id as usize) >= MAX_MAILBOXES {
            return None;
        }
        self.mailboxes[mbx_id as usize].receive()
    }

    /// Broadcast a message to all active mailboxes
    pub fn broadcast(&mut self, msg: Message) -> u32 {
        let mut sent = 0u32;
        for i in 0..self.count {
            if self.mailboxes[i].state == MailboxState::Active
                && self.mailboxes[i].owner_pid != msg.sender_pid
            {
                let mut broadcast_msg = msg;
                broadcast_msg.receiver_pid = self.mailboxes[i].owner_pid;
                if self.mailboxes[i].send(broadcast_msg).is_ok() {
                    sent += 1;
                }
            }
        }
        self.total_messages.fetch_add(sent as u64, Ordering::Relaxed);
        sent
    }

    /// Get total messages processed
    pub fn total_messages(&self) -> u64 {
        self.total_messages.load(Ordering::Relaxed)
    }

    /// Active mailbox count
    pub fn active_count(&self) -> usize {
        self.mailboxes[..self.count]
            .iter()
            .filter(|m| m.state == MailboxState::Active || m.state == MailboxState::Full)
            .count()
    }
}

static mut REGISTRY: MailboxRegistry = MailboxRegistry::new();

/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn registry() -> &'static mut MailboxRegistry {
    &mut *core::ptr::addr_of_mut!(REGISTRY)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_ipc_create_mailbox(pid: u32) -> i32 {
    unsafe {
        match registry().create(pid) {
            Some(id) => id as i32,
            None => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_ipc_destroy_mailbox(mbx_id: u32) {
    unsafe {
        registry().destroy(mbx_id);
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_ipc_send(
    sender_pid: u32,
    receiver_pid: u32,
    code: u32,
    data_ptr: *const u8,
    data_len: u32,
) -> i64 {
    if data_ptr.is_null() && data_len > 0 {
        return -1;
    }

    let payload = if data_len > 0 && !data_ptr.is_null() {
        let len = core::cmp::min(data_len as usize, MAX_MSG_DATA);
        unsafe { core::slice::from_raw_parts(data_ptr, len) }
    } else {
        &[]
    };

    let msg = Message::data(sender_pid, receiver_pid, code, payload);

    unsafe {
        match registry().send_to_pid(msg) {
            Ok(seq) => seq as i64,
            Err(_) => -1,
        }
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_ipc_receive(mbx_id: u32, out_msg: *mut Message) -> i32 {
    if out_msg.is_null() {
        return -1;
    }

    unsafe {
        match registry().receive_from(mbx_id) {
            Some(msg) => {
                *out_msg = msg;
                0
            }
            None => -1,
        }
    }
}
