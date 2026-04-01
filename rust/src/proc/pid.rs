// =============================================================================
// Kernel Zxyphor — PID Namespace & ID Management (Rust)
// =============================================================================
// Hierarchical PID namespaces:
//   - PID namespace tree
//   - PID allocation with idr-like structure
//   - Namespace-relative PID mapping
//   - Process group and session tracking
//   - PID reuse with generation counters
//   - /proc/<pid> mapping support
// =============================================================================

/// Maximum PID namespaces
const MAX_PID_NS: usize = 32;
/// Maximum PIDs per namespace
const MAX_PIDS_PER_NS: usize = 4096;
/// Maximum namespace depth
const MAX_NS_DEPTH: usize = 8;
/// Maximum process groups
const MAX_PGRPS: usize = 256;
/// Maximum sessions
const MAX_SESSIONS: usize = 64;

// ---------------------------------------------------------------------------
// PID entry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PidEntry {
    pub pid: u32,
    pub global_pid: u32,   // PID in init namespace
    pub ns_id: u32,        // Owning namespace
    pub generation: u32,   // Reuse counter
    pub active: bool,
}

impl PidEntry {
    pub const fn new() -> Self {
        Self {
            pid: 0,
            global_pid: 0,
            ns_id: 0,
            generation: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PID namespace
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PidNamespace {
    pub ns_id: u32,
    pub parent_ns: u32,
    pub level: u8,           // Depth in hierarchy
    pub active: bool,
    pub pids: [PidEntry; MAX_PIDS_PER_NS],
    pub pid_count: u32,
    pub next_pid: u32,
    pub max_pid: u32,
    pub child_reaper: u32,   // PID of process that adopts orphans (init in ns)
}

impl PidNamespace {
    pub const fn new() -> Self {
        Self {
            ns_id: 0,
            parent_ns: 0,
            level: 0,
            active: false,
            pids: [const { PidEntry::new() }; MAX_PIDS_PER_NS],
            pid_count: 0,
            next_pid: 1,
            max_pid: 32768,
            child_reaper: 1,
        }
    }

    /// Allocate a PID within this namespace
    pub fn alloc_pid(&mut self) -> Option<u32> {
        let start = self.next_pid;
        loop {
            let pid = self.next_pid;
            self.next_pid = if self.next_pid >= self.max_pid { 1 } else { self.next_pid + 1 };

            // Check not in use
            let mut in_use = false;
            for i in 0..MAX_PIDS_PER_NS {
                if self.pids[i].active && self.pids[i].pid == pid {
                    in_use = true;
                    break;
                }
            }

            if !in_use {
                // Find free slot
                for i in 0..MAX_PIDS_PER_NS {
                    if !self.pids[i].active {
                        self.pids[i] = PidEntry {
                            pid,
                            global_pid: 0, // Set by caller
                            ns_id: self.ns_id,
                            generation: self.pids[i].generation + 1,
                            active: true,
                        };
                        self.pid_count += 1;
                        return Some(pid);
                    }
                }
                return None; // No free slots
            }

            if self.next_pid == start { return None; } // Full cycle
        }
    }

    /// Free a PID
    pub fn free_pid(&mut self, pid: u32) -> bool {
        for i in 0..MAX_PIDS_PER_NS {
            if self.pids[i].active && self.pids[i].pid == pid {
                self.pids[i].active = false;
                self.pid_count -= 1;
                return true;
            }
        }
        false
    }

    /// Translate a PID to the global (init) namespace PID
    pub fn to_global(&self, pid: u32) -> Option<u32> {
        for i in 0..MAX_PIDS_PER_NS {
            if self.pids[i].active && self.pids[i].pid == pid {
                return Some(self.pids[i].global_pid);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Process group
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ProcessGroup {
    pub pgid: u32,
    pub session: u32,
    pub leader: u32,
    pub members: [u32; 64],
    pub member_count: u32,
    pub active: bool,
}

impl ProcessGroup {
    pub const fn new() -> Self {
        Self {
            pgid: 0,
            session: 0,
            leader: 0,
            members: [0u32; 64],
            member_count: 0,
            active: false,
        }
    }

    pub fn add_member(&mut self, pid: u32) -> bool {
        if self.member_count as usize >= 64 { return false; }
        self.members[self.member_count as usize] = pid;
        self.member_count += 1;
        true
    }

    pub fn remove_member(&mut self, pid: u32) -> bool {
        for i in 0..self.member_count as usize {
            if self.members[i] == pid {
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

    pub fn has_member(&self, pid: u32) -> bool {
        for i in 0..self.member_count as usize {
            if self.members[i] == pid { return true; }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Session {
    pub sid: u32,
    pub leader: u32,
    pub ctty: u32,    // Controlling terminal
    pub groups: [u32; 32],
    pub group_count: u32,
    pub active: bool,
}

impl Session {
    pub const fn new() -> Self {
        Self {
            sid: 0,
            leader: 0,
            ctty: 0,
            groups: [0u32; 32],
            group_count: 0,
            active: false,
        }
    }

    pub fn add_group(&mut self, pgid: u32) -> bool {
        if self.group_count as usize >= 32 { return false; }
        self.groups[self.group_count as usize] = pgid;
        self.group_count += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// PID manager
// ---------------------------------------------------------------------------

pub struct PidManager {
    namespaces: [PidNamespace; MAX_PID_NS],
    ns_count: u32,
    pgroups: [ProcessGroup; MAX_PGRPS],
    pgrp_count: u32,
    sessions: [Session; MAX_SESSIONS],
    session_count: u32,
    global_next_pid: u32,
}

impl PidManager {
    pub const fn new() -> Self {
        Self {
            namespaces: [const { PidNamespace::new() }; MAX_PID_NS],
            ns_count: 0,
            pgroups: [const { ProcessGroup::new() }; MAX_PGRPS],
            pgrp_count: 0,
            sessions: [const { Session::new() }; MAX_SESSIONS],
            session_count: 0,
            global_next_pid: 1,
        }
    }

    /// Initialize with the root (init) PID namespace
    pub fn init(&mut self) {
        self.namespaces[0] = PidNamespace {
            ns_id: 0,
            parent_ns: 0,
            level: 0,
            active: true,
            pids: [const { PidEntry::new() }; MAX_PIDS_PER_NS],
            pid_count: 0,
            next_pid: 1,
            max_pid: 32768,
            child_reaper: 1,
        };
        self.ns_count = 1;
    }

    /// Create a child PID namespace
    pub fn create_namespace(&mut self, parent_ns: u32) -> Option<u32> {
        if self.ns_count as usize >= MAX_PID_NS { return None; }
        let parent_level = if (parent_ns as usize) < MAX_PID_NS && self.namespaces[parent_ns as usize].active {
            self.namespaces[parent_ns as usize].level
        } else {
            return None;
        };
        if parent_level as usize + 1 >= MAX_NS_DEPTH { return None; }

        let ns_id = self.ns_count;
        self.namespaces[ns_id as usize] = PidNamespace::new();
        self.namespaces[ns_id as usize].ns_id = ns_id;
        self.namespaces[ns_id as usize].parent_ns = parent_ns;
        self.namespaces[ns_id as usize].level = parent_level + 1;
        self.namespaces[ns_id as usize].active = true;
        self.ns_count += 1;

        Some(ns_id)
    }

    /// Allocate a PID in a namespace (and optionally in all ancestor namespaces)
    pub fn alloc_pid(&mut self, ns_id: u32) -> Option<u32> {
        if ns_id as usize >= MAX_PID_NS || !self.namespaces[ns_id as usize].active {
            return None;
        }

        let global_pid = self.global_next_pid;
        self.global_next_pid += 1;

        let local_pid = self.namespaces[ns_id as usize].alloc_pid()?;

        // Set global PID
        for i in 0..MAX_PIDS_PER_NS {
            if self.namespaces[ns_id as usize].pids[i].active
                && self.namespaces[ns_id as usize].pids[i].pid == local_pid
            {
                self.namespaces[ns_id as usize].pids[i].global_pid = global_pid;
                break;
            }
        }

        Some(local_pid)
    }

    /// Free a PID in a namespace
    pub fn free_pid(&mut self, ns_id: u32, pid: u32) -> bool {
        if ns_id as usize >= MAX_PID_NS { return false; }
        self.namespaces[ns_id as usize].free_pid(pid)
    }

    /// Create a new process group
    pub fn create_pgroup(&mut self, pgid: u32, leader: u32, session: u32) -> bool {
        if self.pgrp_count as usize >= MAX_PGRPS { return false; }
        let idx = self.pgrp_count as usize;
        self.pgroups[idx] = ProcessGroup::new();
        self.pgroups[idx].pgid = pgid;
        self.pgroups[idx].leader = leader;
        self.pgroups[idx].session = session;
        self.pgroups[idx].active = true;
        self.pgroups[idx].add_member(leader);
        self.pgrp_count += 1;
        true
    }

    /// Find process group
    pub fn find_pgroup(&self, pgid: u32) -> Option<usize> {
        for i in 0..self.pgrp_count as usize {
            if self.pgroups[i].active && self.pgroups[i].pgid == pgid {
                return Some(i);
            }
        }
        None
    }

    /// Create a new session
    pub fn create_session(&mut self, sid: u32, leader: u32) -> bool {
        if self.session_count as usize >= MAX_SESSIONS { return false; }
        let idx = self.session_count as usize;
        self.sessions[idx] = Session::new();
        self.sessions[idx].sid = sid;
        self.sessions[idx].leader = leader;
        self.sessions[idx].active = true;
        self.session_count += 1;
        true
    }

    /// Set controlling terminal for a session
    pub fn set_ctty(&mut self, sid: u32, ctty: u32) -> bool {
        for i in 0..self.session_count as usize {
            if self.sessions[i].active && self.sessions[i].sid == sid {
                self.sessions[i].ctty = ctty;
                return true;
            }
        }
        false
    }

    /// Translate a namespace-local PID to the global PID
    pub fn local_to_global(&self, ns_id: u32, pid: u32) -> Option<u32> {
        if ns_id as usize >= MAX_PID_NS { return None; }
        self.namespaces[ns_id as usize].to_global(pid)
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut PID_MANAGER: PidManager = PidManager::new();

fn pid_manager() -> &'static mut PidManager {
    unsafe { &mut PID_MANAGER }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_pid_init() {
    pid_manager().init();
}

#[no_mangle]
pub extern "C" fn zxyphor_pid_create_ns(parent_ns: u32) -> i32 {
    match pid_manager().create_namespace(parent_ns) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_pid_alloc(ns_id: u32) -> i32 {
    match pid_manager().alloc_pid(ns_id) {
        Some(pid) => pid as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_pid_free(ns_id: u32, pid: u32) -> i32 {
    if pid_manager().free_pid(ns_id, pid) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_pid_create_pgroup(pgid: u32, leader: u32, session: u32) -> i32 {
    if pid_manager().create_pgroup(pgid, leader, session) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_pid_create_session(sid: u32, leader: u32) -> i32 {
    if pid_manager().create_session(sid, leader) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_pid_to_global(ns_id: u32, pid: u32) -> i32 {
    match pid_manager().local_to_global(ns_id, pid) {
        Some(g) => g as i32,
        None => -1,
    }
}
