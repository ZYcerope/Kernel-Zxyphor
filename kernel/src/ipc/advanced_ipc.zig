// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced IPC: Capability-based channels, message bus,
// shared memory manager, async notifications, D-Bus-like system bus
const std = @import("std");

// ============================================================================
// Capability-based IPC
// ============================================================================

pub const CapabilityRight = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    grant: bool = false,         // Can grant this cap to others
    revoke: bool = false,        // Can revoke from children
    transfer: bool = false,      // Can transfer ownership
    duplicate: bool = false,     // Can duplicate this cap
    destroy: bool = false,       // Can destroy the endpoint
    wait: bool = false,          // Can wait/poll on this cap
    signal: bool = false,        // Can signal through this cap
    map: bool = false,           // Can mmap
    connect: bool = false,       // Can connect (IPC)
    bind: bool = false,          // Can bind (listen)
    ioctl: bool = false,         // Can ioctl
    admin: bool = false,         // Full admin rights
    _reserved: u17 = 0,
};

pub const Capability = struct {
    id: u64,
    object_type: CapObjectType,
    object_id: u64,
    rights: CapabilityRight,
    owner_pid: u32,
    generation: u32,
    parent_cap: u64,  // 0 = root capability
    flags: u32,
    
    pub const CAP_FLAG_INHERITED: u32 = 1 << 0;
    pub const CAP_FLAG_REVOCABLE: u32 = 1 << 1;
    pub const CAP_FLAG_TRANSFERABLE: u32 = 1 << 2;
    pub const CAP_FLAG_EPHEMERAL: u32 = 1 << 3;
    
    pub fn hasRight(self: *const Capability, right_mask: u32) bool {
        const rights_val: u32 = @bitCast(self.rights);
        return (rights_val & right_mask) == right_mask;
    }
    
    pub fn derive(self: *const Capability, new_rights: CapabilityRight, new_owner: u32) Capability {
        // Can only reduce rights, never increase
        const parent_rights: u32 = @bitCast(self.rights);
        const child_rights: u32 = @bitCast(new_rights);
        const masked: u32 = parent_rights & child_rights;
        return Capability{
            .id = 0, // Will be assigned by table
            .object_type = self.object_type,
            .object_id = self.object_id,
            .rights = @bitCast(masked),
            .owner_pid = new_owner,
            .generation = self.generation + 1,
            .parent_cap = self.id,
            .flags = CAP_FLAG_INHERITED,
        };
    }
};

pub const CapObjectType = enum(u8) {
    none = 0,
    process = 1,
    thread = 2,
    memory = 3,
    channel = 4,
    port = 5,
    interrupt = 6,
    io_port = 7,
    device = 8,
    file = 9,
    socket = 10,
    timer = 11,
    semaphore = 12,
    event = 13,
    // Zxyphor extensions
    gpu_context = 128,
    net_namespace = 129,
    cgroup = 130,
};

pub const CapabilityTable = struct {
    entries: [4096]Capability = undefined,
    count: u32 = 0,
    next_id: u64 = 1,
    
    pub fn init() CapabilityTable {
        return CapabilityTable{};
    }
    
    pub fn allocCapability(self: *CapabilityTable, obj_type: CapObjectType, obj_id: u64, 
                           rights: CapabilityRight, owner: u32) ?u64 {
        if (self.count >= 4096) return null;
        const idx = self.count;
        self.count += 1;
        
        const id = self.next_id;
        self.next_id += 1;
        
        self.entries[idx] = Capability{
            .id = id,
            .object_type = obj_type,
            .object_id = obj_id,
            .rights = rights,
            .owner_pid = owner,
            .generation = 0,
            .parent_cap = 0,
            .flags = 0,
        };
        
        return id;
    }
    
    pub fn lookupCapability(self: *const CapabilityTable, cap_id: u64) ?*const Capability {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].id == cap_id) {
                return &self.entries[i];
            }
        }
        return null;
    }
    
    pub fn revokeCapability(self: *CapabilityTable, cap_id: u64) bool {
        // Revoke this cap and all children
        var revoked: u32 = 0;
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].id == cap_id or self.entries[i].parent_cap == cap_id) {
                // Mark as revoked by zeroing
                self.entries[i].rights = @bitCast(@as(u32, 0));
                revoked += 1;
            }
        }
        return revoked > 0;
    }
};

// ============================================================================
// Message-Passing Channel
// ============================================================================

pub const MSG_MAX_SIZE: usize = 4096;
pub const MSG_MAX_INLINE: usize = 256;
pub const CHANNEL_QUEUE_SIZE: usize = 64;

pub const MessageType = enum(u8) {
    data = 0,
    request = 1,
    reply = 2,
    notification = 3,
    error = 4,
    signal = 5,
    fd_transfer = 6,
    cap_transfer = 7,
    // Control
    channel_close = 240,
    channel_reset = 241,
    ping = 254,
    pong = 255,
};

pub const Message = struct {
    msg_type: MessageType = .data,
    flags: u16 = 0,
    src_pid: u32 = 0,
    dst_pid: u32 = 0,
    msg_id: u64 = 0,
    reply_to: u64 = 0,
    timestamp_ns: u64 = 0,
    // Inline data
    inline_data: [MSG_MAX_INLINE]u8 = [_]u8{0} ** MSG_MAX_INLINE,
    inline_len: u16 = 0,
    // Shared memory reference for large messages
    shm_offset: u64 = 0,
    shm_len: u32 = 0,
    // Transferred capabilities
    caps: [4]u64 = [_]u64{0} ** 4,
    num_caps: u8 = 0,
    // Priority
    priority: u8 = 0,
    
    pub const MSG_FLAG_URGENT: u16 = 1 << 0;
    pub const MSG_FLAG_RELIABLE: u16 = 1 << 1;
    pub const MSG_FLAG_REPLY_EXPECTED: u16 = 1 << 2;
    pub const MSG_FLAG_BROADCAST: u16 = 1 << 3;
    pub const MSG_FLAG_NONBLOCKING: u16 = 1 << 4;
    pub const MSG_FLAG_NO_COPY: u16 = 1 << 5;
};

pub const Channel = struct {
    id: u64,
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    // Endpoints
    endpoint_a: ChannelEndpoint = ChannelEndpoint{},
    endpoint_b: ChannelEndpoint = ChannelEndpoint{},
    // Ring buffer of messages
    queue: [CHANNEL_QUEUE_SIZE]Message = [_]Message{Message{}} ** CHANNEL_QUEUE_SIZE,
    head: u32 = 0,
    tail: u32 = 0,
    count: u32 = 0,
    // State
    state: ChannelState = .created,
    flags: u32 = 0,
    // Flow control
    max_queue_size: u32 = CHANNEL_QUEUE_SIZE,
    send_window: u32 = 32,
    // Stats
    messages_sent: u64 = 0,
    messages_received: u64 = 0,
    bytes_total: u64 = 0,
    
    pub fn init(id: u64) Channel {
        return Channel{ .id = id };
    }
    
    pub fn send(self: *Channel, msg: *const Message) SendResult {
        if (self.state != .connected) return .not_connected;
        if (self.count >= self.max_queue_size) return .queue_full;
        
        self.queue[self.head % CHANNEL_QUEUE_SIZE] = msg.*;
        self.head += 1;
        self.count += 1;
        self.messages_sent += 1;
        self.bytes_total += msg.inline_len;
        
        return .ok;
    }
    
    pub fn receive(self: *Channel) ?*Message {
        if (self.count == 0) return null;
        
        const idx = self.tail % CHANNEL_QUEUE_SIZE;
        self.tail += 1;
        self.count -= 1;
        self.messages_received += 1;
        
        return &self.queue[idx];
    }
    
    pub fn pending(self: *const Channel) u32 {
        return self.count;
    }
};

pub const ChannelEndpoint = struct {
    pid: u32 = 0,
    tid: u32 = 0,
    cap_id: u64 = 0,
    connected: bool = false,
};

pub const ChannelState = enum(u8) {
    created,
    connecting,
    connected,
    half_closed,
    closed,
    error_state,
};

pub const SendResult = enum {
    ok,
    queue_full,
    not_connected,
    msg_too_large,
    no_permission,
    would_block,
};

// ============================================================================  
// System Message Bus (D-Bus-like)
// ============================================================================

pub const BUS_NAME_MAX: usize = 128;
pub const BUS_MAX_SERVICES: usize = 256;
pub const BUS_MAX_SUBSCRIPTIONS: usize = 1024;

pub const BusMessage = struct {
    msg_type: BusMessageType = .method_call,
    serial: u32 = 0,
    reply_serial: u32 = 0,
    sender: [BUS_NAME_MAX]u8 = [_]u8{0} ** BUS_NAME_MAX,
    sender_len: u8 = 0,
    destination: [BUS_NAME_MAX]u8 = [_]u8{0} ** BUS_NAME_MAX,
    dest_len: u8 = 0,
    interface: [BUS_NAME_MAX]u8 = [_]u8{0} ** BUS_NAME_MAX,
    iface_len: u8 = 0,
    member: [64]u8 = [_]u8{0} ** 64,
    member_len: u8 = 0,
    path: [256]u8 = [_]u8{0} ** 256,
    path_len: u16 = 0,
    body: [1024]u8 = [_]u8{0} ** 1024,
    body_len: u16 = 0,
    flags: u8 = 0,
    
    pub const BUS_FLAG_NO_REPLY_EXPECTED: u8 = 1;
    pub const BUS_FLAG_NO_AUTO_START: u8 = 2;
    pub const BUS_FLAG_ALLOW_INTERACTIVE_AUTH: u8 = 4;
};

pub const BusMessageType = enum(u8) {
    invalid = 0,
    method_call = 1,
    method_return = 2,
    error_msg = 3,
    signal = 4,
};

pub const BusService = struct {
    name: [BUS_NAME_MAX]u8 = [_]u8{0} ** BUS_NAME_MAX,
    name_len: u8 = 0,
    owner_pid: u32 = 0,
    unique_name: [32]u8 = [_]u8{0} ** 32,
    unique_name_len: u8 = 0,
    flags: u32 = 0,
    activation_type: ActivationType = .none,
    
    pub const SVC_FLAG_QUEUED: u32 = 1 << 0;
    pub const SVC_FLAG_ALLOW_REPLACE: u32 = 1 << 1;
    pub const SVC_FLAG_REPLACE_EXISTING: u32 = 1 << 2;
    pub const SVC_FLAG_DO_NOT_QUEUE: u32 = 1 << 3;
};

pub const ActivationType = enum(u8) {
    none,
    dbus,       // Traditional D-Bus activation
    socket,     // Socket activation (systemd-like)
    path,       // Path-based activation
    timer,      // Timer activation
};

pub const BusSubscription = struct {
    subscriber_pid: u32 = 0,
    match_type: BusMatchType = .signal,
    interface: [BUS_NAME_MAX]u8 = [_]u8{0} ** BUS_NAME_MAX,
    iface_len: u8 = 0,
    member: [64]u8 = [_]u8{0} ** 64,
    member_len: u8 = 0,
    sender: [BUS_NAME_MAX]u8 = [_]u8{0} ** BUS_NAME_MAX,
    sender_len: u8 = 0,
    active: bool = false,
};

pub const BusMatchType = enum(u8) {
    signal,
    method_call,
    method_return,
    error_match,
    any,
};

pub const SystemBus = struct {
    services: [BUS_MAX_SERVICES]BusService = [_]BusService{BusService{}} ** BUS_MAX_SERVICES,
    service_count: u32 = 0,
    subscriptions: [BUS_MAX_SUBSCRIPTIONS]BusSubscription = [_]BusSubscription{BusSubscription{}} ** BUS_MAX_SUBSCRIPTIONS,
    sub_count: u32 = 0,
    next_serial: u32 = 1,
    next_unique: u32 = 1,
    // Message queues per-process
    process_queues: [256]ProcessBusQueue = undefined,
    num_queues: u32 = 0,
    // Stats
    total_messages: u64 = 0,
    total_signals: u64 = 0,
    total_method_calls: u64 = 0,
    total_errors: u64 = 0,
    
    pub fn init() SystemBus {
        return SystemBus{};
    }
    
    /// Register a well-known name
    pub fn requestName(self: *SystemBus, name: []const u8, pid: u32, flags: u32) BusNameResult {
        // Check if name already taken
        var i: u32 = 0;
        while (i < self.service_count) : (i += 1) {
            if (self.services[i].name_len == @as(u8, @intCast(name.len))) {
                if (std.mem.eql(u8, self.services[i].name[0..self.services[i].name_len], name)) {
                    if (flags & BusService.SVC_FLAG_REPLACE_EXISTING != 0 and
                        self.services[i].flags & BusService.SVC_FLAG_ALLOW_REPLACE != 0) {
                        self.services[i].owner_pid = pid;
                        return .primary_owner;
                    }
                    return .already_owner;
                }
            }
        }
        
        if (self.service_count >= BUS_MAX_SERVICES) return .error_no_space;
        
        const idx = self.service_count;
        self.service_count += 1;
        var svc = &self.services[idx];
        const nlen = @min(name.len, BUS_NAME_MAX);
        @memcpy(svc.name[0..nlen], name[0..nlen]);
        svc.name_len = @intCast(nlen);
        svc.owner_pid = pid;
        svc.flags = flags;
        
        // Assign unique name
        const unique_id = self.next_unique;
        self.next_unique += 1;
        _ = unique_id; // Would format as ":1.{id}"
        
        return .primary_owner;
    }
    
    /// Subscribe to signals
    pub fn addMatch(self: *SystemBus, pid: u32, iface: []const u8, member: []const u8) bool {
        if (self.sub_count >= BUS_MAX_SUBSCRIPTIONS) return false;
        
        const idx = self.sub_count;
        self.sub_count += 1;
        var sub = &self.subscriptions[idx];
        sub.subscriber_pid = pid;
        sub.match_type = .signal;
        sub.active = true;
        
        const ilen = @min(iface.len, BUS_NAME_MAX);
        @memcpy(sub.interface[0..ilen], iface[0..ilen]);
        sub.iface_len = @intCast(ilen);
        
        const mlen = @min(member.len, 64);
        @memcpy(sub.member[0..mlen], member[0..mlen]);
        sub.member_len = @intCast(mlen);
        
        return true;
    }
    
    /// Emit a signal to all subscribers
    pub fn emitSignal(self: *SystemBus, msg: *const BusMessage) u32 {
        var delivered: u32 = 0;
        var i: u32 = 0;
        while (i < self.sub_count) : (i += 1) {
            const sub = &self.subscriptions[i];
            if (!sub.active) continue;
            
            // Match interface
            if (sub.iface_len > 0) {
                if (!std.mem.eql(u8, sub.interface[0..sub.iface_len], msg.interface[0..msg.iface_len])) {
                    continue;
                }
            }
            // Match member
            if (sub.member_len > 0) {
                if (!std.mem.eql(u8, sub.member[0..sub.member_len], msg.member[0..msg.member_len])) {
                    continue;
                }
            }
            
            // Deliver to subscriber's queue
            self.deliverToProcess(sub.subscriber_pid, msg);
            delivered += 1;
        }
        self.total_signals += 1;
        self.total_messages += 1;
        return delivered;
    }
    
    fn deliverToProcess(self: *SystemBus, pid: u32, msg: *const BusMessage) void {
        _ = self;
        _ = pid;
        _ = msg;
        // Would enqueue into per-process message queue
    }
};

pub const BusNameResult = enum {
    primary_owner,
    in_queue,
    already_owner,
    error_no_space,
    error_not_allowed,
};

pub const ProcessBusQueue = struct {
    pid: u32 = 0,
    messages: [32]BusMessage = undefined,
    head: u8 = 0,
    tail: u8 = 0,
    count: u8 = 0,
};

// ============================================================================
// Shared Memory Manager
// ============================================================================

pub const SHM_MAX_SEGMENTS: usize = 512;
pub const SHM_MAX_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

pub const ShmSegment = struct {
    id: u32 = 0,
    key: u64 = 0,
    size: usize = 0,
    base_addr: usize = 0,
    flags: u32 = 0,
    mode: u16 = 0o666,
    owner_uid: u32 = 0,
    owner_gid: u32 = 0,
    creator_uid: u32 = 0,
    creator_gid: u32 = 0,
    nattach: u32 = 0,
    atime: u64 = 0,   // Last attach time
    dtime: u64 = 0,   // Last detach time
    ctime: u64 = 0,   // Last change time
    // State
    locked: bool = false,
    pending_destroy: bool = false,
    huge_pages: bool = false,
    numa_node: u8 = 0,
    // Attachments
    attached_pids: [64]u32 = [_]u32{0} ** 64,
    attachment_count: u8 = 0,
    
    pub const SHM_HUGETLB: u32 = 0o04000;
    pub const SHM_NORESERVE: u32 = 0o10000;
    pub const SHM_HUGE_2MB: u32 = 21 << 26;
    pub const SHM_HUGE_1GB: u32 = 30 << 26;
    pub const SHM_RDONLY: u32 = 0o10000;
    pub const SHM_RND: u32 = 0o20000;
    pub const SHM_REMAP: u32 = 0o40000;
    pub const SHM_EXEC: u32 = 0o100000;
    pub const SHM_LOCK: u32 = 11;
    pub const SHM_UNLOCK: u32 = 12;
    
    pub fn attach(self: *ShmSegment, pid: u32) bool {
        if (self.attachment_count >= 64) return false;
        self.attached_pids[self.attachment_count] = pid;
        self.attachment_count += 1;
        self.nattach += 1;
        return true;
    }
    
    pub fn detach(self: *ShmSegment, pid: u32) bool {
        var i: u8 = 0;
        while (i < self.attachment_count) : (i += 1) {
            if (self.attached_pids[i] == pid) {
                // Shift
                var j = i;
                while (j + 1 < self.attachment_count) : (j += 1) {
                    self.attached_pids[j] = self.attached_pids[j + 1];
                }
                self.attachment_count -= 1;
                if (self.nattach > 0) self.nattach -= 1;
                return true;
            }
        }
        return false;
    }
};

pub const ShmManager = struct {
    segments: [SHM_MAX_SEGMENTS]ShmSegment = [_]ShmSegment{ShmSegment{}} ** SHM_MAX_SEGMENTS,
    count: u32 = 0,
    next_id: u32 = 1,
    total_bytes: u64 = 0,
    
    pub fn init() ShmManager {
        return ShmManager{};
    }
    
    pub fn shmget(self: *ShmManager, key: u64, size: usize, flags: u32, uid: u32, gid: u32) ?u32 {
        // Check for existing
        if (key != 0) { // IPC_PRIVATE = 0
            var i: u32 = 0;
            while (i < self.count) : (i += 1) {
                if (self.segments[i].key == key) {
                    return self.segments[i].id;
                }
            }
        }
        
        if (self.count >= SHM_MAX_SEGMENTS) return null;
        if (size > SHM_MAX_SIZE) return null;
        
        const idx = self.count;
        self.count += 1;
        const id = self.next_id;
        self.next_id += 1;
        
        var seg = &self.segments[idx];
        seg.id = id;
        seg.key = key;
        seg.size = size;
        seg.flags = flags;
        seg.owner_uid = uid;
        seg.owner_gid = gid;
        seg.creator_uid = uid;
        seg.creator_gid = gid;
        seg.huge_pages = flags & ShmSegment.SHM_HUGETLB != 0;
        
        self.total_bytes += size;
        return id;
    }
    
    pub fn shmctl_rmid(self: *ShmManager, id: u32) bool {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.segments[i].id == id) {
                if (self.segments[i].nattach > 0) {
                    self.segments[i].pending_destroy = true;
                    return true;
                }
                // Remove immediately
                self.total_bytes -= self.segments[i].size;
                var j = i;
                while (j + 1 < self.count) : (j += 1) {
                    self.segments[j] = self.segments[j + 1];
                }
                self.count -= 1;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// Async Notification Framework
// ============================================================================

pub const NotifyType = enum(u8) {
    process_exit,
    process_fork,
    process_exec,
    file_open,
    file_close,
    file_modify,
    net_connect,
    net_disconnect,
    device_add,
    device_remove,
    timer_expired,
    signal_received,
    memory_pressure,
    oom_warning,
    // Zxyphor
    capability_change,
    security_violation,
    performance_warning,
    custom,
};

pub const Notification = struct {
    notify_type: NotifyType = .custom,
    source_pid: u32 = 0,
    target_pid: u32 = 0,
    timestamp_ns: u64 = 0,
    data: [64]u8 = [_]u8{0} ** 64,
    data_len: u8 = 0,
    priority: u8 = 0,
    flags: u16 = 0,
};

pub const NotifyWatcher = struct {
    pid: u32 = 0,
    watch_mask: u32 = 0, // Bitmask of NotifyType
    filter_pid: u32 = 0, // 0 = all
    callback_cap: u64 = 0,
    active: bool = false,
};

pub const NotificationCenter = struct {
    watchers: [256]NotifyWatcher = [_]NotifyWatcher{NotifyWatcher{}} ** 256,
    watcher_count: u32 = 0,
    // Ring buffer
    ring: [1024]Notification = [_]Notification{Notification{}} ** 1024,
    ring_head: u32 = 0,
    ring_tail: u32 = 0,
    ring_count: u32 = 0,
    // Stats
    total_notifications: u64 = 0,
    total_delivered: u64 = 0,
    dropped: u64 = 0,
    
    pub fn init() NotificationCenter {
        return NotificationCenter{};
    }
    
    pub fn addWatcher(self: *NotificationCenter, pid: u32, mask: u32) ?u32 {
        if (self.watcher_count >= 256) return null;
        const idx = self.watcher_count;
        self.watcher_count += 1;
        self.watchers[idx] = NotifyWatcher{
            .pid = pid,
            .watch_mask = mask,
            .active = true,
        };
        return idx;
    }
    
    pub fn post(self: *NotificationCenter, notif: *const Notification) u32 {
        // Add to ring
        if (self.ring_count >= 1024) {
            self.dropped += 1;
            self.ring_tail = (self.ring_tail + 1) % 1024;
        } else {
            self.ring_count += 1;
        }
        self.ring[self.ring_head] = notif.*;
        self.ring_head = (self.ring_head + 1) % 1024;
        self.total_notifications += 1;
        
        // Deliver to matching watchers
        var delivered: u32 = 0;
        const type_bit = @as(u32, 1) << @intFromEnum(notif.notify_type);
        var i: u32 = 0;
        while (i < self.watcher_count) : (i += 1) {
            const w = &self.watchers[i];
            if (!w.active) continue;
            if (w.watch_mask & type_bit == 0) continue;
            if (w.filter_pid != 0 and w.filter_pid != notif.source_pid) continue;
            delivered += 1;
        }
        self.total_delivered += delivered;
        return delivered;
    }
};
