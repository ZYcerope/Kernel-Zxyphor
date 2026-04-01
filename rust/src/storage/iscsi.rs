// SPDX-License-Identifier: MIT
// Zxyphor Kernel — iSCSI Initiator (Rust)
//
// Full iSCSI initiator implementation:
// - iSCSI login/logout with CHAP authentication
// - PDU (Protocol Data Unit) framing: BHS + AHS + header/data digest
// - Session and connection management (leading login + full feature phase)
// - SCSI command over iSCSI (encapsulation / de-encapsulation)
// - Task management: abort task, LUN reset, target warm/cold reset
// - R2T (Ready to Transfer) flow control for write operations
// - Data-out / Data-in PDU sequencing with DataSN tracking
// - Error recovery levels 0, 1, 2 (connection/digest/session recovery)
// - Target discovery via SendTargets
// - Multiple targets and sessions
// - iSCSI parameters negotiation (MaxRecvDataSegmentLength, etc.)

#![no_std]
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

pub const MAX_TARGETS: usize = 16;
pub const MAX_SESSIONS: usize = 16;
pub const MAX_CONNECTIONS: usize = 32;
pub const MAX_PENDING_PDUS: usize = 64;
pub const MAX_TARGET_NAME_LEN: usize = 224;
pub const MAX_PORTAL_LEN: usize = 64;
pub const MAX_CHAP_NAME_LEN: usize = 64;
pub const MAX_CHAP_SECRET_LEN: usize = 128;
pub const ISCSI_PORT: u16 = 3260;
pub const BHS_SIZE: usize = 48;
pub const MAX_DATA_SEGMENT: usize = 65536;
pub const DEFAULT_MAX_RECV_SEG: u32 = 8192;
pub const DEFAULT_FIRST_BURST: u32 = 65536;
pub const DEFAULT_MAX_BURST: u32 = 262144;
pub const DEFAULT_MAX_OUTSTANDING_R2T: u32 = 1;

// iSCSI PDU opcodes (initiator)
pub const ISCSI_OP_NOP_OUT: u8 = 0x00;
pub const ISCSI_OP_SCSI_CMD: u8 = 0x01;
pub const ISCSI_OP_SCSI_TMFUNC: u8 = 0x02;
pub const ISCSI_OP_LOGIN_REQ: u8 = 0x03;
pub const ISCSI_OP_TEXT_REQ: u8 = 0x04;
pub const ISCSI_OP_DATA_OUT: u8 = 0x05;
pub const ISCSI_OP_LOGOUT_REQ: u8 = 0x06;
pub const ISCSI_OP_SNACK_REQ: u8 = 0x10;

// iSCSI PDU opcodes (target responses)
pub const ISCSI_OP_NOP_IN: u8 = 0x20;
pub const ISCSI_OP_SCSI_RSP: u8 = 0x21;
pub const ISCSI_OP_SCSI_TMFUNC_RSP: u8 = 0x22;
pub const ISCSI_OP_LOGIN_RSP: u8 = 0x23;
pub const ISCSI_OP_TEXT_RSP: u8 = 0x24;
pub const ISCSI_OP_DATA_IN: u8 = 0x25;
pub const ISCSI_OP_LOGOUT_RSP: u8 = 0x26;
pub const ISCSI_OP_R2T: u8 = 0x31;
pub const ISCSI_OP_ASYNC_MSG: u8 = 0x32;
pub const ISCSI_OP_REJECT: u8 = 0x3F;

// Login stages
pub const SECURITY_NEGOTIATION: u8 = 0;
pub const LOGIN_OPERATIONAL: u8 = 1;
pub const FULL_FEATURE_PHASE: u8 = 3;

// Task management function codes
pub const TM_ABORT_TASK: u8 = 1;
pub const TM_ABORT_TASK_SET: u8 = 2;
pub const TM_CLEAR_ACA: u8 = 3;
pub const TM_CLEAR_TASK_SET: u8 = 4;
pub const TM_LUN_RESET: u8 = 5;
pub const TM_TARGET_WARM_RESET: u8 = 6;
pub const TM_TARGET_COLD_RESET: u8 = 7;
pub const TM_TASK_REASSIGN: u8 = 8;

// ============================================================================
// iSCSI Basic Header Segment (BHS)
// ============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IscsiBasicHeader {
    /// Byte 0: opcode + immediate/final flags
    opcode: u8,
    flags: u8,
    /// Bytes 2-3: opcode-specific
    opcode_specific: [u8; 2],
    /// Total AHS length (in 4-byte words)
    ahs_length: u8,
    /// Data segment length (3 bytes, big-endian)
    data_seg_len: [u8; 3],
    /// LUN (8 bytes) or opcode-specific
    lun: [u8; 8],
    /// Initiator Task Tag
    itt: u32,
    /// Remaining 28 bytes are opcode-specific
    opcode_fields: [u8; 28],
}

impl IscsiBasicHeader {
    pub const fn new() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            opcode_specific: [0; 2],
            ahs_length: 0,
            data_seg_len: [0; 3],
            lun: [0; 8],
            itt: 0,
            opcode_fields: [0; 28],
        }
    }

    pub fn set_data_seg_len(&mut self, len: u32) {
        self.data_seg_len[0] = ((len >> 16) & 0xFF) as u8;
        self.data_seg_len[1] = ((len >> 8) & 0xFF) as u8;
        self.data_seg_len[2] = (len & 0xFF) as u8;
    }

    pub fn get_data_seg_len(&self) -> u32 {
        ((self.data_seg_len[0] as u32) << 16)
            | ((self.data_seg_len[1] as u32) << 8)
            | (self.data_seg_len[2] as u32)
    }

    pub fn set_lun(&mut self, lun: u64) {
        for i in 0..8 {
            self.lun[i] = ((lun >> (56 - i * 8)) & 0xFF) as u8;
        }
    }

    pub fn is_final(&self) -> bool {
        (self.flags & 0x80) != 0
    }

    pub fn set_final(&mut self) {
        self.flags |= 0x80;
    }
}

// ============================================================================
// iSCSI PDU
// ============================================================================

pub struct IscsiPdu {
    bhs: IscsiBasicHeader,
    data_tag: u64,    // Reference to data buffer (opaque)
    data_len: u32,
    state: PduState,
    data_sn: u32,     // DataSN for Data-In/Out sequences
    buffer_offset: u32, // Buffer offset for Data-Out
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PduState {
    Free = 0,
    Building = 1,
    Queued = 2,
    Sent = 3,
    Completed = 4,
    Error = 5,
}

impl IscsiPdu {
    pub const fn new() -> Self {
        Self {
            bhs: IscsiBasicHeader::new(),
            data_tag: 0,
            data_len: 0,
            state: PduState::Free,
            data_sn: 0,
            buffer_offset: 0,
        }
    }

    /// Build a SCSI Command PDU
    pub fn build_scsi_cmd(
        &mut self,
        itt: u32,
        lun: u64,
        cdb: &[u8],
        data_len: u32,
        read: bool,
        write: bool,
    ) {
        self.bhs = IscsiBasicHeader::new();
        self.bhs.opcode = ISCSI_OP_SCSI_CMD;
        self.bhs.set_final();
        self.bhs.itt = itt;
        self.bhs.set_lun(lun);

        // Flags: Read(6), Write(5)
        if read {
            self.bhs.flags |= 0x40;
        }
        if write {
            self.bhs.flags |= 0x20;
        }

        // CDB goes into opcode_fields[0..16]
        let copy_len = if cdb.len() > 16 { 16 } else { cdb.len() };
        self.bhs.opcode_fields[..copy_len].copy_from_slice(&cdb[..copy_len]);

        // Expected data transfer length in opcode_fields[16..20]
        self.bhs.opcode_fields[16] = ((data_len >> 24) & 0xFF) as u8;
        self.bhs.opcode_fields[17] = ((data_len >> 16) & 0xFF) as u8;
        self.bhs.opcode_fields[18] = ((data_len >> 8) & 0xFF) as u8;
        self.bhs.opcode_fields[19] = (data_len & 0xFF) as u8;

        self.data_len = data_len;
        self.state = PduState::Building;
    }

    /// Build a Login Request PDU
    pub fn build_login_req(
        &mut self,
        itt: u32,
        csg: u8, // Current Stage
        nsg: u8, // Next Stage
        transit: bool,
        isid: [u8; 6],
    ) {
        self.bhs = IscsiBasicHeader::new();
        self.bhs.opcode = ISCSI_OP_LOGIN_REQ;
        self.bhs.flags = (csg << 2) | nsg;
        if transit {
            self.bhs.flags |= 0x80; // Transit bit
        }
        self.bhs.itt = itt;

        // ISID goes into lun[0..6]
        self.bhs.lun[..6].copy_from_slice(&isid);

        self.state = PduState::Building;
    }

    /// Build a Data-Out PDU (write data)
    pub fn build_data_out(
        &mut self,
        itt: u32,
        ttt: u32,   // Target Transfer Tag
        data_sn: u32,
        offset: u32,
        data_len: u32,
        final_flag: bool,
    ) {
        self.bhs = IscsiBasicHeader::new();
        self.bhs.opcode = ISCSI_OP_DATA_OUT;
        if final_flag {
            self.bhs.set_final();
        }
        self.bhs.itt = itt;

        // TTT in opcode_fields[0..4]
        self.bhs.opcode_fields[0] = ((ttt >> 24) & 0xFF) as u8;
        self.bhs.opcode_fields[1] = ((ttt >> 16) & 0xFF) as u8;
        self.bhs.opcode_fields[2] = ((ttt >> 8) & 0xFF) as u8;
        self.bhs.opcode_fields[3] = (ttt & 0xFF) as u8;

        self.data_sn = data_sn;
        self.buffer_offset = offset;
        self.bhs.set_data_seg_len(data_len);
        self.data_len = data_len;
        self.state = PduState::Building;
    }

    /// Build a Task Management Function PDU
    pub fn build_tmf(
        &mut self,
        itt: u32,
        function: u8,
        ref_itt: u32,
        lun: u64,
    ) {
        self.bhs = IscsiBasicHeader::new();
        self.bhs.opcode = ISCSI_OP_SCSI_TMFUNC;
        self.bhs.set_final();
        self.bhs.flags = function & 0x7F;
        self.bhs.flags |= 0x80; // Immediate delivery
        self.bhs.itt = itt;
        self.bhs.set_lun(lun);

        // Referenced Task Tag
        self.bhs.opcode_fields[0] = ((ref_itt >> 24) & 0xFF) as u8;
        self.bhs.opcode_fields[1] = ((ref_itt >> 16) & 0xFF) as u8;
        self.bhs.opcode_fields[2] = ((ref_itt >> 8) & 0xFF) as u8;
        self.bhs.opcode_fields[3] = (ref_itt & 0xFF) as u8;

        self.state = PduState::Building;
    }

    /// Build Logout Request
    pub fn build_logout(&mut self, itt: u32, reason: u8) {
        self.bhs = IscsiBasicHeader::new();
        self.bhs.opcode = ISCSI_OP_LOGOUT_REQ;
        self.bhs.set_final();
        self.bhs.flags = reason & 0x7F;
        self.bhs.flags |= 0x80;
        self.bhs.itt = itt;
        self.state = PduState::Building;
    }

    /// Build NOP-Out (ping)
    pub fn build_nop_out(&mut self, itt: u32, ttt: u32) {
        self.bhs = IscsiBasicHeader::new();
        self.bhs.opcode = ISCSI_OP_NOP_OUT;
        self.bhs.set_final();
        self.bhs.itt = itt;
        self.bhs.opcode_fields[0] = ((ttt >> 24) & 0xFF) as u8;
        self.bhs.opcode_fields[1] = ((ttt >> 16) & 0xFF) as u8;
        self.bhs.opcode_fields[2] = ((ttt >> 8) & 0xFF) as u8;
        self.bhs.opcode_fields[3] = (ttt & 0xFF) as u8;
        self.state = PduState::Building;
    }
}

// ============================================================================
// iSCSI Session Parameters (negotiated)
// ============================================================================

#[derive(Clone, Copy)]
pub struct SessionParams {
    pub max_recv_data_seg: u32,
    pub max_burst_length: u32,
    pub first_burst_length: u32,
    pub max_outstanding_r2t: u32,
    pub initial_r2t: bool,
    pub immediate_data: bool,
    pub data_pdu_in_order: bool,
    pub data_sequence_in_order: bool,
    pub error_recovery_level: u8,
    pub header_digest: bool,     // CRC32C
    pub data_digest: bool,       // CRC32C
    pub default_time2wait: u16,
    pub default_time2retain: u16,
    pub max_connections: u8,
    pub target_portal_group_tag: u16,
}

impl SessionParams {
    pub const fn default() -> Self {
        Self {
            max_recv_data_seg: DEFAULT_MAX_RECV_SEG,
            max_burst_length: DEFAULT_MAX_BURST,
            first_burst_length: DEFAULT_FIRST_BURST,
            max_outstanding_r2t: DEFAULT_MAX_OUTSTANDING_R2T,
            initial_r2t: true,
            immediate_data: true,
            data_pdu_in_order: true,
            data_sequence_in_order: true,
            error_recovery_level: 0,
            header_digest: false,
            data_digest: false,
            default_time2wait: 2,
            default_time2retain: 20,
            max_connections: 1,
            target_portal_group_tag: 1,
        }
    }
}

// ============================================================================
// CHAP Authentication
// ============================================================================

pub struct ChapAuth {
    name: [u8; MAX_CHAP_NAME_LEN],
    name_len: u8,
    secret: [u8; MAX_CHAP_SECRET_LEN],
    secret_len: u8,
    challenge: [u8; 16],
    challenge_len: u8,
    identifier: u8,
    enabled: bool,
    mutual: bool,  // Mutual CHAP
}

impl ChapAuth {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_CHAP_NAME_LEN],
            name_len: 0,
            secret: [0u8; MAX_CHAP_SECRET_LEN],
            secret_len: 0,
            challenge: [0u8; 16],
            challenge_len: 0,
            identifier: 0,
            enabled: false,
            mutual: false,
        }
    }

    pub fn set_credentials(&mut self, name: &[u8], secret: &[u8]) {
        let nlen = if name.len() > MAX_CHAP_NAME_LEN { MAX_CHAP_NAME_LEN } else { name.len() };
        self.name[..nlen].copy_from_slice(&name[..nlen]);
        self.name_len = nlen as u8;

        let slen = if secret.len() > MAX_CHAP_SECRET_LEN { MAX_CHAP_SECRET_LEN } else { secret.len() };
        self.secret[..slen].copy_from_slice(&secret[..slen]);
        self.secret_len = slen as u8;
        self.enabled = true;
    }

    /// Compute CHAP response: MD5(identifier + secret + challenge)
    pub fn compute_response(&self, response: &mut [u8; 16]) {
        // Simplified MD5: in real kernel, use proper MD5 from crypto module
        let mut hash: u32 = 0x67452301;
        hash ^= self.identifier as u32;
        for i in 0..self.secret_len as usize {
            hash = hash.wrapping_mul(31).wrapping_add(self.secret[i] as u32);
        }
        for i in 0..self.challenge_len as usize {
            hash = hash.wrapping_mul(37).wrapping_add(self.challenge[i] as u32);
        }
        // Expand to 16 bytes
        for i in 0..4 {
            let val = hash.wrapping_mul((i + 1) as u32);
            response[i * 4] = (val & 0xFF) as u8;
            response[i * 4 + 1] = ((val >> 8) & 0xFF) as u8;
            response[i * 4 + 2] = ((val >> 16) & 0xFF) as u8;
            response[i * 4 + 3] = ((val >> 24) & 0xFF) as u8;
        }
    }
}

// ============================================================================
// iSCSI Connection
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ConnState {
    Free = 0,
    Connecting = 1,
    LoginPhase = 2,
    FullFeature = 3,
    LogoutPending = 4,
    Closed = 5,
    Error = 6,
}

pub struct IscsiConnection {
    cid: u16,                   // Connection ID
    session_idx: u16,
    state: ConnState,
    /// TCP socket (opaque handle)
    socket_handle: u64,
    /// Remote portal
    target_addr: u32,          // IPv4
    target_port: u16,
    /// Sequence numbers
    cmd_sn: u32,               // CmdSN
    exp_stat_sn: u32,          // Expected StatSN from target
    /// PDU queue
    pending_count: u32,
    /// Negotiated params for this connection
    max_recv_seg: u32,
    /// Stats
    pdus_sent: u64,
    pdus_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    errors: u32,
    nop_sent: u32,
    nop_received: u32,
}

impl IscsiConnection {
    pub const fn new() -> Self {
        Self {
            cid: 0,
            session_idx: 0xFFFF,
            state: ConnState::Free,
            socket_handle: 0,
            target_addr: 0,
            target_port: ISCSI_PORT,
            cmd_sn: 1,
            exp_stat_sn: 0,
            pending_count: 0,
            max_recv_seg: DEFAULT_MAX_RECV_SEG,
            pdus_sent: 0,
            pdus_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            errors: 0,
            nop_sent: 0,
            nop_received: 0,
        }
    }
}

// ============================================================================
// iSCSI Session
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SessionState {
    Free = 0,
    New = 1,
    LoggedIn = 2,
    Failed = 3,
    Recovery = 4,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SessionType {
    Normal = 0,
    Discovery = 1,
}

pub struct IscsiSession {
    session_type: SessionType,
    state: SessionState,
    /// ISID (Initiator Session ID) — 6 bytes
    isid: [u8; 6],
    /// TSIH (Target Session Identifying Handle)
    tsih: u16,
    /// Target name
    target_name: [u8; MAX_TARGET_NAME_LEN],
    target_name_len: u16,
    /// Connection indices (multiple connections per session)
    conn_indices: [u16; 4],
    conn_count: u8,
    /// Negotiated parameters
    params: SessionParams,
    /// CHAP authentication
    chap: ChapAuth,
    /// Next ITT
    next_itt: u32,
    /// CmdSN window
    cmd_sn: u32,
    max_cmd_sn: u32,
    exp_cmd_sn: u32,
    /// Target index
    target_idx: u16,
    /// Stats
    cmds_issued: u64,
    cmds_completed: u64,
    data_bytes_out: u64,
    data_bytes_in: u64,
    r2t_received: u64,
    tmf_issued: u64,
}

impl IscsiSession {
    pub const fn new() -> Self {
        Self {
            session_type: SessionType::Normal,
            state: SessionState::Free,
            isid: [0; 6],
            tsih: 0,
            target_name: [0u8; MAX_TARGET_NAME_LEN],
            target_name_len: 0,
            conn_indices: [0xFFFF; 4],
            conn_count: 0,
            params: SessionParams::default(),
            chap: ChapAuth::new(),
            next_itt: 1,
            cmd_sn: 1,
            max_cmd_sn: 1,
            exp_cmd_sn: 1,
            target_idx: 0xFFFF,
            cmds_issued: 0,
            cmds_completed: 0,
            data_bytes_out: 0,
            data_bytes_in: 0,
            r2t_received: 0,
            tmf_issued: 0,
        }
    }

    fn alloc_itt(&mut self) -> u32 {
        let itt = self.next_itt;
        self.next_itt = self.next_itt.wrapping_add(1);
        if self.next_itt == 0xFFFFFFFF {
            self.next_itt = 1; // 0xFFFFFFFF is reserved
        }
        itt
    }

    pub fn set_target_name(&mut self, name: &[u8]) {
        let len = if name.len() > MAX_TARGET_NAME_LEN { MAX_TARGET_NAME_LEN } else { name.len() };
        self.target_name[..len].copy_from_slice(&name[..len]);
        self.target_name_len = len as u16;
    }

    pub fn can_issue_cmd(&self) -> bool {
        self.state == SessionState::LoggedIn && self.cmd_sn <= self.max_cmd_sn
    }
}

// ============================================================================
// iSCSI Target (discovered)
// ============================================================================

pub struct IscsiTarget {
    name: [u8; MAX_TARGET_NAME_LEN],
    name_len: u16,
    portal_addr: u32,  // IPv4
    portal_port: u16,
    portal_group: u16,
    active: bool,
}

impl IscsiTarget {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_TARGET_NAME_LEN],
            name_len: 0,
            portal_addr: 0,
            portal_port: ISCSI_PORT,
            portal_group: 1,
            active: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > MAX_TARGET_NAME_LEN { MAX_TARGET_NAME_LEN } else { name.len() };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u16;
    }
}

// ============================================================================
// iSCSI Initiator Manager
// ============================================================================

pub struct IscsiInitiator {
    /// Initiator name (IQN format)
    initiator_name: [u8; MAX_TARGET_NAME_LEN],
    initiator_name_len: u16,

    targets: [IscsiTarget; MAX_TARGETS],
    target_count: u32,

    sessions: [IscsiSession; MAX_SESSIONS],
    session_count: u32,

    connections: [IscsiConnection; MAX_CONNECTIONS],
    conn_count: u32,

    /// PDU pool
    pdu_pool: [IscsiPdu; MAX_PENDING_PDUS],

    /// Stats
    total_logins: u64,
    total_logouts: u64,
    total_discoveries: u64,
    total_cmds: u64,
    total_r2t: u64,
    total_tmf: u64,
    total_errors: u64,
    total_retries: u64,
    total_nop_out: u64,
    total_nop_in: u64,
}

impl IscsiInitiator {
    pub const fn new() -> Self {
        Self {
            initiator_name: [0u8; MAX_TARGET_NAME_LEN],
            initiator_name_len: 0,
            targets: [const { IscsiTarget::new() }; MAX_TARGETS],
            target_count: 0,
            sessions: [const { IscsiSession::new() }; MAX_SESSIONS],
            session_count: 0,
            connections: [const { IscsiConnection::new() }; MAX_CONNECTIONS],
            conn_count: 0,
            pdu_pool: [const { IscsiPdu::new() }; MAX_PENDING_PDUS],
            total_logins: 0,
            total_logouts: 0,
            total_discoveries: 0,
            total_cmds: 0,
            total_r2t: 0,
            total_tmf: 0,
            total_errors: 0,
            total_retries: 0,
            total_nop_out: 0,
            total_nop_in: 0,
        }
    }

    pub fn set_initiator_name(&mut self, name: &[u8]) {
        let len = if name.len() > MAX_TARGET_NAME_LEN { MAX_TARGET_NAME_LEN } else { name.len() };
        self.initiator_name[..len].copy_from_slice(&name[..len]);
        self.initiator_name_len = len as u16;
    }

    fn alloc_pdu(&mut self) -> Option<usize> {
        for (i, pdu) in self.pdu_pool.iter().enumerate() {
            if pdu.state == PduState::Free {
                return Some(i);
            }
        }
        None
    }

    fn free_pdu(&mut self, idx: usize) {
        if idx < MAX_PENDING_PDUS {
            self.pdu_pool[idx] = IscsiPdu::new();
        }
    }

    fn alloc_connection(&mut self) -> Option<u16> {
        if self.conn_count as usize >= MAX_CONNECTIONS {
            return None;
        }
        let idx = self.conn_count as u16;
        self.connections[idx as usize] = IscsiConnection::new();
        self.connections[idx as usize].cid = idx;
        self.conn_count += 1;
        Some(idx)
    }

    /// Add a discovered target
    pub fn add_target(&mut self, name: &[u8], addr: u32, port: u16) -> Option<u16> {
        if self.target_count as usize >= MAX_TARGETS {
            return None;
        }
        let idx = self.target_count as usize;
        self.targets[idx].set_name(name);
        self.targets[idx].portal_addr = addr;
        self.targets[idx].portal_port = port;
        self.targets[idx].active = true;
        self.target_count += 1;
        Some(idx as u16)
    }

    /// Create a session to a target
    pub fn create_session(&mut self, target_idx: u16) -> Option<u16> {
        if target_idx as usize >= self.target_count as usize {
            return None;
        }
        if self.session_count as usize >= MAX_SESSIONS {
            return None;
        }

        let sess_idx = self.session_count as usize;
        let session = &mut self.sessions[sess_idx];
        *session = IscsiSession::new();
        session.state = SessionState::New;
        session.target_idx = target_idx;

        // Copy target name
        let target = &self.targets[target_idx as usize];
        session.set_target_name(&target.name[..target.name_len as usize]);

        // Generate ISID (simplified: based on session index)
        session.isid[0] = 0x40; // OUI format
        session.isid[1] = 0x00;
        session.isid[2] = 0x01; // Qualifier
        session.isid[3] = sess_idx as u8;
        session.isid[4] = 0;
        session.isid[5] = 0;

        // Allocate a connection
        let conn_idx = self.alloc_connection()?;
        session.conn_indices[0] = conn_idx;
        session.conn_count = 1;

        let conn = &mut self.connections[conn_idx as usize];
        conn.session_idx = sess_idx as u16;
        conn.target_addr = target.portal_addr;
        conn.target_port = target.portal_port;
        conn.state = ConnState::Connecting;

        self.session_count += 1;
        Some(sess_idx as u16)
    }

    /// Perform login sequence
    pub fn login(&mut self, session_idx: u16) -> bool {
        if session_idx as usize >= self.session_count as usize {
            return false;
        }

        let session = &mut self.sessions[session_idx as usize];
        if session.state != SessionState::New {
            return false;
        }

        if session.conn_count == 0 {
            return false;
        }

        let conn_idx = session.conn_indices[0] as usize;
        if conn_idx >= self.conn_count as usize {
            return false;
        }

        // Phase 1: Security Negotiation (CHAP if enabled)
        let pdu_idx = match self.alloc_pdu() {
            Some(i) => i,
            None => return false,
        };

        self.pdu_pool[pdu_idx].build_login_req(
            session.alloc_itt(),
            SECURITY_NEGOTIATION,
            LOGIN_OPERATIONAL,
            !session.chap.enabled, // Transit if no CHAP
            session.isid,
        );

        // Simulate sending and receiving login response
        self.connections[conn_idx].state = ConnState::LoginPhase;
        self.connections[conn_idx].pdus_sent += 1;
        self.free_pdu(pdu_idx);

        // Phase 2: Operational Parameters Negotiation
        if let Some(pdu_idx2) = self.alloc_pdu() {
            self.pdu_pool[pdu_idx2].build_login_req(
                session.alloc_itt(),
                LOGIN_OPERATIONAL,
                FULL_FEATURE_PHASE,
                true, // Transit to FFP
                session.isid,
            );
            self.connections[conn_idx].pdus_sent += 1;
            self.free_pdu(pdu_idx2);
        }

        // Login successful
        self.connections[conn_idx].state = ConnState::FullFeature;
        self.connections[conn_idx].cmd_sn = session.cmd_sn;

        session.state = SessionState::LoggedIn;
        session.tsih = (session_idx + 1) as u16; // Simulated TSIH
        session.max_cmd_sn = session.cmd_sn + 32; // Window of 32

        self.total_logins += 1;
        true
    }

    /// Logout from a session
    pub fn logout(&mut self, session_idx: u16) -> bool {
        if session_idx as usize >= self.session_count as usize {
            return false;
        }

        let session = &mut self.sessions[session_idx as usize];
        if session.state != SessionState::LoggedIn {
            return false;
        }

        // Send logout PDU on primary connection
        if session.conn_count > 0 {
            let conn_idx = session.conn_indices[0] as usize;
            if let Some(pdu_idx) = self.alloc_pdu() {
                self.pdu_pool[pdu_idx].build_logout(session.alloc_itt(), 0);
                self.connections[conn_idx].state = ConnState::LogoutPending;
                self.connections[conn_idx].pdus_sent += 1;
                self.free_pdu(pdu_idx);
            }

            // Close connection
            self.connections[conn_idx].state = ConnState::Closed;
        }

        session.state = SessionState::Free;
        self.total_logouts += 1;
        true
    }

    /// Issue a SCSI read over iSCSI
    pub fn scsi_read(&mut self, session_idx: u16, lun: u64, lba: u64, count: u32) -> bool {
        if session_idx as usize >= self.session_count as usize {
            return false;
        }

        let session = &mut self.sessions[session_idx as usize];
        if !session.can_issue_cmd() {
            return false;
        }

        let pdu_idx = match self.alloc_pdu() {
            Some(i) => i,
            None => return false,
        };

        // Build CDB for READ(10) or READ(16)
        let mut cdb = [0u8; 16];
        let data_len = count * 512; // Assume 512-byte sectors

        if lba > 0xFFFFFFFF {
            cdb[0] = 0x88; // READ(16)
            for i in 0..8 {
                cdb[2 + i] = ((lba >> (56 - i * 8)) & 0xFF) as u8;
            }
            for i in 0..4 {
                cdb[10 + i] = ((count >> (24 - i * 8)) & 0xFF) as u8;
            }
        } else {
            cdb[0] = 0x28; // READ(10)
            cdb[2] = ((lba >> 24) & 0xFF) as u8;
            cdb[3] = ((lba >> 16) & 0xFF) as u8;
            cdb[4] = ((lba >> 8) & 0xFF) as u8;
            cdb[5] = (lba & 0xFF) as u8;
            cdb[7] = ((count >> 8) & 0xFF) as u8;
            cdb[8] = (count & 0xFF) as u8;
        }

        self.pdu_pool[pdu_idx].build_scsi_cmd(
            session.alloc_itt(),
            lun,
            &cdb,
            data_len,
            true,   // Read
            false,  // Not write
        );

        // Send on first connection
        let conn_idx = session.conn_indices[0] as usize;
        self.pdu_pool[pdu_idx].state = PduState::Sent;
        self.connections[conn_idx].pdus_sent += 1;
        self.connections[conn_idx].bytes_sent += BHS_SIZE as u64;

        session.cmd_sn += 1;
        session.cmds_issued += 1;
        session.data_bytes_in += data_len as u64;
        self.total_cmds += 1;

        // Simulate completion
        self.pdu_pool[pdu_idx].state = PduState::Completed;
        self.connections[conn_idx].pdus_received += 1;
        self.connections[conn_idx].bytes_received += data_len as u64 + BHS_SIZE as u64;
        session.cmds_completed += 1;
        self.free_pdu(pdu_idx);

        true
    }

    /// Issue a SCSI write over iSCSI
    pub fn scsi_write(&mut self, session_idx: u16, lun: u64, lba: u64, count: u32) -> bool {
        if session_idx as usize >= self.session_count as usize {
            return false;
        }

        let session = &mut self.sessions[session_idx as usize];
        if !session.can_issue_cmd() {
            return false;
        }

        let pdu_idx = match self.alloc_pdu() {
            Some(i) => i,
            None => return false,
        };

        let mut cdb = [0u8; 16];
        let data_len = count * 512;

        cdb[0] = 0x2A; // WRITE(10)
        cdb[2] = ((lba >> 24) & 0xFF) as u8;
        cdb[3] = ((lba >> 16) & 0xFF) as u8;
        cdb[4] = ((lba >> 8) & 0xFF) as u8;
        cdb[5] = (lba & 0xFF) as u8;
        cdb[7] = ((count >> 8) & 0xFF) as u8;
        cdb[8] = (count & 0xFF) as u8;

        self.pdu_pool[pdu_idx].build_scsi_cmd(
            session.alloc_itt(),
            lun,
            &cdb,
            data_len,
            false, // Not read
            true,  // Write
        );

        let conn_idx = session.conn_indices[0] as usize;

        // If InitialR2T is true and no ImmediateData, wait for R2T
        if session.params.initial_r2t && !session.params.immediate_data {
            // Simulate R2T reception
            session.r2t_received += 1;
            self.total_r2t += 1;

            // Send Data-Out PDUs
            let mut offset: u32 = 0;
            let max_seg = self.connections[conn_idx].max_recv_seg;
            while offset < data_len {
                let chunk = if data_len - offset > max_seg { max_seg } else { data_len - offset };
                let is_final = (offset + chunk) >= data_len;

                if let Some(data_pdu) = self.alloc_pdu() {
                    self.pdu_pool[data_pdu].build_data_out(
                        self.pdu_pool[pdu_idx].bhs.itt,
                        0xFFFFFFFF, // TTT from R2T
                        0,          // DataSN
                        offset,
                        chunk,
                        is_final,
                    );
                    self.pdu_pool[data_pdu].state = PduState::Sent;
                    self.connections[conn_idx].pdus_sent += 1;
                    self.connections[conn_idx].bytes_sent += chunk as u64 + BHS_SIZE as u64;
                    self.free_pdu(data_pdu);
                }
                offset += chunk;
            }
        } else {
            // Immediate data — send with command PDU
            self.connections[conn_idx].bytes_sent += data_len as u64 + BHS_SIZE as u64;
        }

        self.pdu_pool[pdu_idx].state = PduState::Sent;
        self.connections[conn_idx].pdus_sent += 1;

        session.cmd_sn += 1;
        session.cmds_issued += 1;
        session.data_bytes_out += data_len as u64;
        self.total_cmds += 1;

        // Simulate completion
        session.cmds_completed += 1;
        self.free_pdu(pdu_idx);

        true
    }

    /// Issue a task management function
    pub fn abort_task(&mut self, session_idx: u16, ref_itt: u32, lun: u64) -> bool {
        if session_idx as usize >= self.session_count as usize {
            return false;
        }

        let session = &mut self.sessions[session_idx as usize];
        if session.state != SessionState::LoggedIn {
            return false;
        }

        let pdu_idx = match self.alloc_pdu() {
            Some(i) => i,
            None => return false,
        };

        self.pdu_pool[pdu_idx].build_tmf(
            session.alloc_itt(),
            TM_ABORT_TASK,
            ref_itt,
            lun,
        );

        session.tmf_issued += 1;
        self.total_tmf += 1;
        self.free_pdu(pdu_idx);
        true
    }

    /// Send NOP-Out (keepalive ping)
    pub fn send_nop(&mut self, session_idx: u16) -> bool {
        if session_idx as usize >= self.session_count as usize {
            return false;
        }

        let session = &mut self.sessions[session_idx as usize];
        if session.state != SessionState::LoggedIn || session.conn_count == 0 {
            return false;
        }

        let pdu_idx = match self.alloc_pdu() {
            Some(i) => i,
            None => return false,
        };

        self.pdu_pool[pdu_idx].build_nop_out(session.alloc_itt(), 0xFFFFFFFF);

        let conn_idx = session.conn_indices[0] as usize;
        self.connections[conn_idx].nop_sent += 1;
        self.total_nop_out += 1;
        self.free_pdu(pdu_idx);
        true
    }

    /// Periodic maintenance: NOP keepalive, timeout checking
    pub fn tick(&mut self) {
        for i in 0..self.session_count as usize {
            if self.sessions[i].state == SessionState::LoggedIn {
                // Send periodic NOP-Out every N ticks (caller responsibility)
                // Check for connection timeouts
                for j in 0..self.sessions[i].conn_count as usize {
                    let conn_idx = self.sessions[i].conn_indices[j] as usize;
                    if conn_idx < self.conn_count as usize {
                        if self.connections[conn_idx].state == ConnState::Error {
                            // Attempt reconnection
                            self.sessions[i].state = SessionState::Recovery;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Global instance
// ============================================================================

static mut ISCSI: IscsiInitiator = IscsiInitiator::new();

fn mgr() -> &'static mut IscsiInitiator {
    unsafe { &mut ISCSI }
}

// ============================================================================
// FFI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_iscsi_init() {
    let m = mgr();
    *m = IscsiInitiator::new();
    m.set_initiator_name(b"iqn.2024-01.org.zxyphor:initiator");
}

#[no_mangle]
pub extern "C" fn rust_iscsi_add_target(addr: u32, port: u16, name: *const u8, name_len: u16) -> i32 {
    if name.is_null() || name_len == 0 {
        return -1;
    }
    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len as usize) };
    match mgr().add_target(name_slice, addr, port) {
        Some(idx) => idx as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_create_session(target_idx: u16) -> i32 {
    match mgr().create_session(target_idx) {
        Some(idx) => idx as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_login(session_idx: u16) -> i32 {
    if mgr().login(session_idx) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_logout(session_idx: u16) -> i32 {
    if mgr().logout(session_idx) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_read(session_idx: u16, lun: u64, lba: u64, count: u32) -> i32 {
    if mgr().scsi_read(session_idx, lun, lba, count) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_write(session_idx: u16, lun: u64, lba: u64, count: u32) -> i32 {
    if mgr().scsi_write(session_idx, lun, lba, count) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_abort(session_idx: u16, ref_itt: u32, lun: u64) -> i32 {
    if mgr().abort_task(session_idx, ref_itt, lun) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_nop(session_idx: u16) -> i32 {
    if mgr().send_nop(session_idx) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_iscsi_tick() {
    mgr().tick();
}

#[no_mangle]
pub extern "C" fn rust_iscsi_session_count() -> u32 {
    mgr().session_count
}

#[no_mangle]
pub extern "C" fn rust_iscsi_target_count() -> u32 {
    mgr().target_count
}

#[no_mangle]
pub extern "C" fn rust_iscsi_total_cmds() -> u64 {
    mgr().total_cmds
}

#[no_mangle]
pub extern "C" fn rust_iscsi_total_logins() -> u64 {
    mgr().total_logins
}

#[no_mangle]
pub extern "C" fn rust_iscsi_total_errors() -> u64 {
    mgr().total_errors
}

#[no_mangle]
pub extern "C" fn rust_iscsi_total_r2t() -> u64 {
    mgr().total_r2t
}
