// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Netlink Socket Protocol (Rust)
//
// Linux-compatible netlink socket abstraction:
// - Netlink message header (nlmsghdr) with type/flags/seq/pid
// - Netlink attribute (nlattr) with TLV encoding
// - Protocol families: NETLINK_ROUTE, NETLINK_USERSOCK, NETLINK_KOBJECT_UEVENT,
//   NETLINK_GENERIC, NETLINK_AUDIT, NETLINK_FIREWALL
// - Multicast group management
// - Message queuing and delivery
// - Netlink socket binding (port_id, groups)
// - Dump request handling (NLM_F_DUMP)
// - Acknowledgment generation (NLM_F_ACK)
// - Error message formatting (nlmsgerr)
// - Generic netlink multiplexer (genetlink family registry)
// - Socket buffer management

#![allow(dead_code)]

// ─── Constants ──────────────────────────────────────────────────────

const MAX_SOCKETS: usize = 128;
const MAX_MSG_QUEUE: usize = 64;
const MAX_GROUPS: usize = 32;
const MAX_FAMILIES: usize = 24;
const MAX_ATTRS: usize = 32;
const MSG_BUF_SIZE: usize = 4096;
const ATTR_BUF_SIZE: usize = 256;
const FAMILY_NAME_LEN: usize = 32;

const NLMSG_ALIGNTO: usize = 4;
const NLMSG_HDRLEN: usize = 16; // sizeof(nlmsghdr)
const NLA_HDRLEN: usize = 4;    // sizeof(nlattr)

// ─── Netlink Protocol Families ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum NlProto {
    Route = 0,      // NETLINK_ROUTE
    Usersock = 2,
    Firewall = 3,
    InetDiag = 4,
    Nflog = 5,
    Xfrm = 6,       // IPsec
    Selinux = 7,
    Audit = 9,
    Connector = 11,
    Netfilter = 12,
    Generic = 16,
    KobjectUevent = 15,
    Crypto = 21,
}

// ─── Message Types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum NlMsgType {
    Noop = 0x1,
    Error = 0x2,
    Done = 0x3,
    Overrun = 0x4,
    // RTM_ messages for NETLINK_ROUTE
    NewLink = 16,
    DelLink = 17,
    GetLink = 18,
    SetLink = 19,
    NewAddr = 20,
    DelAddr = 21,
    GetAddr = 22,
    NewRoute = 24,
    DelRoute = 25,
    GetRoute = 26,
    NewNeigh = 28,
    DelNeigh = 29,
    GetNeigh = 30,
    NewRule = 32,
    DelRule = 33,
    GetRule = 34,
    // Generic netlink
    GenCtrl = 0x10,
}

// ─── Message Flags ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NlFlags {
    pub bits: u16,
}

impl NlFlags {
    pub const REQUEST: u16 = 0x01;
    pub const MULTI: u16 = 0x02;
    pub const ACK: u16 = 0x04;
    pub const ECHO: u16 = 0x08;
    pub const DUMP_INTR: u16 = 0x10;
    // GET request flags
    pub const ROOT: u16 = 0x100;
    pub const MATCH: u16 = 0x200;
    pub const ATOMIC: u16 = 0x400;
    pub const DUMP: u16 = 0x100 | 0x200; // ROOT | MATCH
    // NEW request flags
    pub const REPLACE: u16 = 0x100;
    pub const EXCL: u16 = 0x200;
    pub const CREATE: u16 = 0x400;
    pub const APPEND: u16 = 0x800;

    pub const fn new(bits: u16) -> Self {
        Self { bits }
    }

    pub fn has(&self, f: u16) -> bool {
        (self.bits & f) != 0
    }

    pub fn is_request(&self) -> bool {
        self.has(Self::REQUEST)
    }

    pub fn wants_ack(&self) -> bool {
        self.has(Self::ACK)
    }

    pub fn is_dump(&self) -> bool {
        self.has(Self::DUMP)
    }
}

// ─── Netlink Message Header ────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    pub const fn empty() -> Self {
        Self {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        }
    }

    pub fn payload_len(&self) -> usize {
        if self.nlmsg_len as usize > NLMSG_HDRLEN {
            (self.nlmsg_len as usize) - NLMSG_HDRLEN
        } else {
            0
        }
    }

    pub fn flags(&self) -> NlFlags {
        NlFlags::new(self.nlmsg_flags)
    }
}

// ─── Netlink Attribute ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NlAttr {
    pub nla_type: u16,
    pub data: [u8; ATTR_BUF_SIZE],
    pub data_len: u16,
    pub active: bool,
}

impl NlAttr {
    pub const fn empty() -> Self {
        Self {
            nla_type: 0,
            data: [0u8; ATTR_BUF_SIZE],
            data_len: 0,
            active: false,
        }
    }

    pub fn set_data(&mut self, d: &[u8]) {
        let len = d.len().min(ATTR_BUF_SIZE - 1);
        self.data[..len].copy_from_slice(&d[..len]);
        self.data_len = len as u16;
    }

    pub fn read_u32(&self) -> u32 {
        if self.data_len >= 4 {
            u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
        } else {
            0
        }
    }

    pub fn write_u32(&mut self, val: u32) {
        let bytes = val.to_ne_bytes();
        self.data[0..4].copy_from_slice(&bytes);
        self.data_len = 4;
    }

    /// Total TLV size (aligned)
    pub fn total_size(&self) -> usize {
        align_nl(NLA_HDRLEN + self.data_len as usize)
    }
}

// ─── Netlink Error Message ──────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct NlMsgErr {
    pub error: i32,  // Negative errno
    pub orig_hdr: NlMsgHdr,
}

impl NlMsgErr {
    pub fn new(error: i32, orig: &NlMsgHdr) -> Self {
        Self {
            error,
            orig_hdr: *orig,
        }
    }
}

// ─── Netlink Message ────────────────────────────────────────────────

pub struct NlMessage {
    pub hdr: NlMsgHdr,
    pub attrs: [NlAttr; MAX_ATTRS],
    pub attr_count: u8,
    pub payload: [u8; MSG_BUF_SIZE],
    pub payload_len: u16,
    pub active: bool,
}

impl NlMessage {
    pub const fn empty() -> Self {
        Self {
            hdr: NlMsgHdr::empty(),
            attrs: [NlAttr::empty(); MAX_ATTRS],
            attr_count: 0,
            payload: [0u8; MSG_BUF_SIZE],
            payload_len: 0,
            active: false,
        }
    }

    pub fn add_attr(&mut self, nla_type: u16, data: &[u8]) -> bool {
        if self.attr_count as usize >= MAX_ATTRS {
            return false;
        }
        let idx = self.attr_count as usize;
        self.attrs[idx] = NlAttr::empty();
        self.attrs[idx].nla_type = nla_type;
        self.attrs[idx].set_data(data);
        self.attrs[idx].active = true;
        self.attr_count += 1;
        true
    }

    pub fn add_attr_u32(&mut self, nla_type: u16, val: u32) -> bool {
        if self.attr_count as usize >= MAX_ATTRS {
            return false;
        }
        let idx = self.attr_count as usize;
        self.attrs[idx] = NlAttr::empty();
        self.attrs[idx].nla_type = nla_type;
        self.attrs[idx].write_u32(val);
        self.attrs[idx].active = true;
        self.attr_count += 1;
        true
    }

    pub fn find_attr(&self, nla_type: u16) -> Option<&NlAttr> {
        for i in 0..self.attr_count as usize {
            if self.attrs[i].active && self.attrs[i].nla_type == nla_type {
                return Some(&self.attrs[i]);
            }
        }
        None
    }

    pub fn compute_len(&self) -> u32 {
        let mut len = NLMSG_HDRLEN + self.payload_len as usize;
        for i in 0..self.attr_count as usize {
            if self.attrs[i].active {
                len += self.attrs[i].total_size();
            }
        }
        align_nl(len) as u32
    }
}

// ─── Multicast Group ────────────────────────────────────────────────

pub struct McGroup {
    pub name: [u8; FAMILY_NAME_LEN],
    pub name_len: u8,
    pub group_id: u32,
    pub member_count: u16,
    pub active: bool,
}

impl McGroup {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; FAMILY_NAME_LEN],
            name_len: 0,
            group_id: 0,
            member_count: 0,
            active: false,
        }
    }
}

// ─── Generic Netlink Family ─────────────────────────────────────────

pub struct GenlFamily {
    pub name: [u8; FAMILY_NAME_LEN],
    pub name_len: u8,
    pub family_id: u16,
    pub version: u8,
    pub hdrsize: u16,
    pub maxattr: u16,
    pub mc_groups: [u32; 4], // group IDs
    pub mc_group_count: u8,
    pub ops_count: u16, // Number of registered operations
    pub active: bool,
}

impl GenlFamily {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; FAMILY_NAME_LEN],
            name_len: 0,
            family_id: 0,
            version: 1,
            hdrsize: 0,
            maxattr: 0,
            mc_groups: [0u32; 4],
            mc_group_count: 0,
            ops_count: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(FAMILY_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

// ─── Netlink Socket ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NlSockState {
    Unbound = 0,
    Bound = 1,
    Connected = 2,
    Closed = 3,
}

pub struct NlSocket {
    pub port_id: u32,       // Usually PID of binding process
    pub protocol: NlProto,
    pub groups: u32,        // Multicast group bitmask
    pub state: NlSockState,
    pub pid: i32,           // Owning process

    // Receive queue
    pub rx_queue: [u16; MAX_MSG_QUEUE], // Indices into global msg pool
    pub rx_head: u8,
    pub rx_tail: u8,
    pub rx_count: u8,

    // Sequence tracking
    pub next_seq: u32,

    // Stats
    pub msgs_sent: u64,
    pub msgs_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub drops: u64,

    pub active: bool,
}

impl NlSocket {
    pub const fn empty() -> Self {
        Self {
            port_id: 0,
            protocol: NlProto::Route,
            groups: 0,
            state: NlSockState::Unbound,
            pid: 0,
            rx_queue: [0u16; MAX_MSG_QUEUE],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
            next_seq: 1,
            msgs_sent: 0,
            msgs_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            drops: 0,
            active: false,
        }
    }

    pub fn alloc_seq(&mut self) -> u32 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    pub fn enqueue_msg(&mut self, msg_idx: u16) -> bool {
        if self.rx_count as usize >= MAX_MSG_QUEUE {
            self.drops += 1;
            return false;
        }
        self.rx_queue[self.rx_tail as usize] = msg_idx;
        self.rx_tail = ((self.rx_tail as usize + 1) % MAX_MSG_QUEUE) as u8;
        self.rx_count += 1;
        self.msgs_recv += 1;
        true
    }

    pub fn dequeue_msg(&mut self) -> Option<u16> {
        if self.rx_count == 0 {
            return None;
        }
        let idx = self.rx_queue[self.rx_head as usize];
        self.rx_head = ((self.rx_head as usize + 1) % MAX_MSG_QUEUE) as u8;
        self.rx_count -= 1;
        Some(idx)
    }

    pub fn join_group(&mut self, group: u8) {
        if group < 32 {
            self.groups |= 1 << group;
        }
    }

    pub fn leave_group(&mut self, group: u8) {
        if group < 32 {
            self.groups &= !(1 << group);
        }
    }

    pub fn is_member(&self, group: u8) -> bool {
        if group >= 32 { return false; }
        (self.groups & (1 << group)) != 0
    }
}

// ─── Netlink Manager ────────────────────────────────────────────────

const MSG_POOL_SIZE: usize = 512;

pub struct NetlinkManager {
    sockets: [NlSocket; MAX_SOCKETS],
    msg_pool: [NlMessage; MSG_POOL_SIZE],
    mc_groups: [McGroup; MAX_GROUPS],
    genl_families: [GenlFamily; MAX_FAMILIES],

    socket_count: u16,
    next_port_id: u32,
    next_group_id: u32,
    next_family_id: u16,
    mc_group_count: u8,
    genl_family_count: u8,

    total_unicast: u64,
    total_multicast: u64,
    total_errors: u64,
    total_acks: u64,
    total_dumps: u64,

    initialized: bool,
}

impl NetlinkManager {
    pub const fn new() -> Self {
        Self {
            sockets: [NlSocket::empty(); MAX_SOCKETS],
            msg_pool: [NlMessage::empty(); MSG_POOL_SIZE],
            mc_groups: [McGroup::empty(); MAX_GROUPS],
            genl_families: [GenlFamily::empty(); MAX_FAMILIES],
            socket_count: 0,
            next_port_id: 1,
            next_group_id: 1,
            next_family_id: 0x100, // Avoid collision with built-in types
            mc_group_count: 0,
            genl_family_count: 0,
            total_unicast: 0,
            total_multicast: 0,
            total_errors: 0,
            total_acks: 0,
            total_dumps: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        // Register built-in generic netlink family (nlctrl)
        self.register_genl_family(b"nlctrl", 0, 2);

        // Register standard multicast groups
        self.register_mc_group(b"link");
        self.register_mc_group(b"notify");
        self.register_mc_group(b"neigh");
        self.register_mc_group(b"tc");
        self.register_mc_group(b"ipv4-ifaddr");
        self.register_mc_group(b"ipv6-ifaddr");
        self.register_mc_group(b"ipv4-route");
        self.register_mc_group(b"ipv6-route");
        self.register_mc_group(b"kobject-uevent");

        self.initialized = true;
    }

    // ─── Socket Operations ──────────────────────────────────────────

    pub fn create_socket(&mut self, protocol: NlProto, pid: i32) -> Option<u16> {
        for i in 0..MAX_SOCKETS {
            if !self.sockets[i].active {
                self.sockets[i] = NlSocket::empty();
                self.sockets[i].protocol = protocol;
                self.sockets[i].pid = pid;
                self.sockets[i].port_id = self.next_port_id;
                self.sockets[i].state = NlSockState::Unbound;
                self.sockets[i].active = true;
                self.next_port_id += 1;
                self.socket_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn close_socket(&mut self, sock_idx: u16) -> bool {
        if sock_idx as usize >= MAX_SOCKETS {
            return false;
        }
        let i = sock_idx as usize;
        if !self.sockets[i].active {
            return false;
        }
        // Drain receive queue
        while let Some(msg_idx) = self.sockets[i].dequeue_msg() {
            self.free_msg(msg_idx);
        }
        self.sockets[i].state = NlSockState::Closed;
        self.sockets[i].active = false;
        self.socket_count -= 1;
        true
    }

    pub fn bind_socket(&mut self, sock_idx: u16, groups: u32) -> bool {
        if sock_idx as usize >= MAX_SOCKETS {
            return false;
        }
        let i = sock_idx as usize;
        if !self.sockets[i].active {
            return false;
        }
        self.sockets[i].groups = groups;
        self.sockets[i].state = NlSockState::Bound;
        true
    }

    // ─── Message Operations ─────────────────────────────────────────

    fn alloc_msg(&mut self) -> Option<u16> {
        for i in 0..MSG_POOL_SIZE {
            if !self.msg_pool[i].active {
                self.msg_pool[i] = NlMessage::empty();
                self.msg_pool[i].active = true;
                return Some(i as u16);
            }
        }
        None
    }

    fn free_msg(&mut self, idx: u16) {
        if (idx as usize) < MSG_POOL_SIZE {
            self.msg_pool[idx as usize].active = false;
        }
    }

    /// Send unicast message to socket
    pub fn unicast(&mut self, sock_idx: u16, msg_type: u16, flags: u16, payload: &[u8]) -> bool {
        if sock_idx as usize >= MAX_SOCKETS || !self.sockets[sock_idx as usize].active {
            return false;
        }

        let msg_idx = match self.alloc_msg() {
            Some(idx) => idx,
            None => return false,
        };

        let seq = self.sockets[sock_idx as usize].alloc_seq();
        let m = &mut self.msg_pool[msg_idx as usize];
        m.hdr.nlmsg_type = msg_type;
        m.hdr.nlmsg_flags = flags;
        m.hdr.nlmsg_seq = seq;
        m.hdr.nlmsg_pid = self.sockets[sock_idx as usize].port_id;

        let len = payload.len().min(MSG_BUF_SIZE);
        m.payload[..len].copy_from_slice(&payload[..len]);
        m.payload_len = len as u16;
        m.hdr.nlmsg_len = m.compute_len();

        if !self.sockets[sock_idx as usize].enqueue_msg(msg_idx) {
            self.free_msg(msg_idx);
            return false;
        }

        self.sockets[sock_idx as usize].msgs_sent += 1;
        self.sockets[sock_idx as usize].bytes_sent += m.hdr.nlmsg_len as u64;
        self.total_unicast += 1;
        true
    }

    /// Send multicast to all sockets in group
    pub fn multicast(&mut self, group: u8, msg_type: u16, protocol: NlProto, payload: &[u8]) -> u16 {
        let mut delivered: u16 = 0;

        for i in 0..MAX_SOCKETS {
            if !self.sockets[i].active || self.sockets[i].protocol != protocol {
                continue;
            }
            if !self.sockets[i].is_member(group) {
                continue;
            }

            let msg_idx = match self.alloc_msg() {
                Some(idx) => idx,
                None => break,
            };

            let m = &mut self.msg_pool[msg_idx as usize];
            m.hdr.nlmsg_type = msg_type;
            m.hdr.nlmsg_flags = 0;
            m.hdr.nlmsg_seq = 0;
            m.hdr.nlmsg_pid = 0; // Kernel origin

            let len = payload.len().min(MSG_BUF_SIZE);
            m.payload[..len].copy_from_slice(&payload[..len]);
            m.payload_len = len as u16;
            m.hdr.nlmsg_len = m.compute_len();

            if self.sockets[i].enqueue_msg(msg_idx) {
                delivered += 1;
            } else {
                self.free_msg(msg_idx);
            }
        }

        self.total_multicast += delivered as u64;
        delivered
    }

    /// Receive message from socket
    pub fn recv(&mut self, sock_idx: u16) -> Option<u16> {
        if sock_idx as usize >= MAX_SOCKETS || !self.sockets[sock_idx as usize].active {
            return None;
        }
        self.sockets[sock_idx as usize].dequeue_msg()
    }

    /// Send ACK for a request
    pub fn send_ack(&mut self, sock_idx: u16, orig_hdr: &NlMsgHdr) -> bool {
        let msg_idx = match self.alloc_msg() {
            Some(idx) => idx,
            None => return false,
        };

        let m = &mut self.msg_pool[msg_idx as usize];
        m.hdr.nlmsg_type = NlMsgType::Error as u16;
        m.hdr.nlmsg_flags = 0;
        m.hdr.nlmsg_seq = orig_hdr.nlmsg_seq;
        m.hdr.nlmsg_pid = orig_hdr.nlmsg_pid;
        // Error code 0 = ACK
        m.payload[0..4].copy_from_slice(&0i32.to_ne_bytes());
        m.payload_len = 4;
        m.hdr.nlmsg_len = m.compute_len();

        if sock_idx as usize < MAX_SOCKETS && self.sockets[sock_idx as usize].active {
            if self.sockets[sock_idx as usize].enqueue_msg(msg_idx) {
                self.total_acks += 1;
                return true;
            }
        }
        self.free_msg(msg_idx);
        false
    }

    /// Send error response
    pub fn send_error(&mut self, sock_idx: u16, orig_hdr: &NlMsgHdr, errno: i32) -> bool {
        let msg_idx = match self.alloc_msg() {
            Some(idx) => idx,
            None => return false,
        };

        let m = &mut self.msg_pool[msg_idx as usize];
        m.hdr.nlmsg_type = NlMsgType::Error as u16;
        m.hdr.nlmsg_flags = 0;
        m.hdr.nlmsg_seq = orig_hdr.nlmsg_seq;
        m.hdr.nlmsg_pid = orig_hdr.nlmsg_pid;
        m.payload[0..4].copy_from_slice(&(-errno).to_ne_bytes());
        m.payload_len = 4;
        m.hdr.nlmsg_len = m.compute_len();

        if sock_idx as usize < MAX_SOCKETS && self.sockets[sock_idx as usize].active {
            if self.sockets[sock_idx as usize].enqueue_msg(msg_idx) {
                self.total_errors += 1;
                return true;
            }
        }
        self.free_msg(msg_idx);
        false
    }

    // ─── Generic Netlink ────────────────────────────────────────────

    pub fn register_genl_family(&mut self, name: &[u8], hdrsize: u16, max_attr: u16) -> Option<u16> {
        if self.genl_family_count as usize >= MAX_FAMILIES {
            return None;
        }
        let idx = self.genl_family_count as usize;
        self.genl_families[idx] = GenlFamily::empty();
        self.genl_families[idx].set_name(name);
        self.genl_families[idx].family_id = self.next_family_id;
        self.genl_families[idx].hdrsize = hdrsize;
        self.genl_families[idx].maxattr = max_attr;
        self.genl_families[idx].active = true;
        self.next_family_id += 1;
        self.genl_family_count += 1;
        Some(self.genl_families[idx].family_id)
    }

    pub fn find_genl_family(&self, name: &[u8]) -> Option<u16> {
        for i in 0..self.genl_family_count as usize {
            if !self.genl_families[i].active {
                continue;
            }
            let len = self.genl_families[i].name_len as usize;
            if len == name.len() && self.genl_families[i].name[..len] == *name {
                return Some(self.genl_families[i].family_id);
            }
        }
        None
    }

    // ─── Multicast Group Registry ───────────────────────────────────

    pub fn register_mc_group(&mut self, name: &[u8]) -> Option<u32> {
        if self.mc_group_count as usize >= MAX_GROUPS {
            return None;
        }
        let idx = self.mc_group_count as usize;
        self.mc_groups[idx] = McGroup::empty();
        let len = name.len().min(FAMILY_NAME_LEN - 1);
        self.mc_groups[idx].name[..len].copy_from_slice(&name[..len]);
        self.mc_groups[idx].name_len = len as u8;
        self.mc_groups[idx].group_id = self.next_group_id;
        self.mc_groups[idx].active = true;
        self.next_group_id += 1;
        self.mc_group_count += 1;
        Some(self.mc_groups[idx].group_id)
    }

    // ─── Lookup ─────────────────────────────────────────────────────

    pub fn find_socket_by_pid(&self, pid: i32, proto: NlProto) -> Option<u16> {
        for i in 0..MAX_SOCKETS {
            if self.sockets[i].active && self.sockets[i].pid == pid && self.sockets[i].protocol == proto {
                return Some(i as u16);
            }
        }
        None
    }

    pub fn find_socket_by_port(&self, port_id: u32) -> Option<u16> {
        for i in 0..MAX_SOCKETS {
            if self.sockets[i].active && self.sockets[i].port_id == port_id {
                return Some(i as u16);
            }
        }
        None
    }
}

// ─── Utility ────────────────────────────────────────────────────────

fn align_nl(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

// ─── Global State ───────────────────────────────────────────────────

static mut NL_MGR: NetlinkManager = NetlinkManager::new();
static mut NL_INITIALIZED: bool = false;

fn mgr() -> &'static mut NetlinkManager {
    unsafe { &mut NL_MGR }
}

// ─── FFI Exports ────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_netlink_init() {
    let m = mgr();
    *m = NetlinkManager::new();
    m.init();
    unsafe { NL_INITIALIZED = true; }
}

#[no_mangle]
pub extern "C" fn rust_netlink_create(protocol: u16, pid: i32) -> i16 {
    if unsafe { !NL_INITIALIZED } { return -1; }
    let proto = match protocol {
        0 => NlProto::Route,
        2 => NlProto::Usersock,
        3 => NlProto::Firewall,
        9 => NlProto::Audit,
        15 => NlProto::KobjectUevent,
        16 => NlProto::Generic,
        _ => return -1,
    };
    match mgr().create_socket(proto, pid) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_netlink_close(sock_idx: u16) -> bool {
    if unsafe { !NL_INITIALIZED } { return false; }
    mgr().close_socket(sock_idx)
}

#[no_mangle]
pub extern "C" fn rust_netlink_bind(sock_idx: u16, groups: u32) -> bool {
    if unsafe { !NL_INITIALIZED } { return false; }
    mgr().bind_socket(sock_idx, groups)
}

#[no_mangle]
pub extern "C" fn rust_netlink_unicast(sock_idx: u16, msg_type: u16, flags: u16, payload_ptr: *const u8, payload_len: usize) -> bool {
    if unsafe { !NL_INITIALIZED } || payload_ptr.is_null() { return false; }
    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) };
    mgr().unicast(sock_idx, msg_type, flags, payload)
}

#[no_mangle]
pub extern "C" fn rust_netlink_multicast(group: u8, msg_type: u16, protocol: u16, payload_ptr: *const u8, payload_len: usize) -> u16 {
    if unsafe { !NL_INITIALIZED } || payload_ptr.is_null() { return 0; }
    let proto = match protocol {
        0 => NlProto::Route,
        15 => NlProto::KobjectUevent,
        16 => NlProto::Generic,
        _ => return 0,
    };
    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) };
    mgr().multicast(group, msg_type, proto, payload)
}

#[no_mangle]
pub extern "C" fn rust_netlink_socket_count() -> u16 {
    if unsafe { !NL_INITIALIZED } { return 0; }
    mgr().socket_count
}

#[no_mangle]
pub extern "C" fn rust_netlink_total_unicast() -> u64 {
    if unsafe { !NL_INITIALIZED } { return 0; }
    mgr().total_unicast
}

#[no_mangle]
pub extern "C" fn rust_netlink_total_multicast() -> u64 {
    if unsafe { !NL_INITIALIZED } { return 0; }
    mgr().total_multicast
}

#[no_mangle]
pub extern "C" fn rust_netlink_genl_family_count() -> u8 {
    if unsafe { !NL_INITIALIZED } { return 0; }
    mgr().genl_family_count
}

#[no_mangle]
pub extern "C" fn rust_netlink_mc_group_count() -> u8 {
    if unsafe { !NL_INITIALIZED } { return 0; }
    mgr().mc_group_count
}
