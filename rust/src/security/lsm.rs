// SPDX-License-Identifier: MIT
//! Zxyphor Kernel — Linux Security Module (LSM) Framework (Rust)
//!
//! SELinux-style mandatory access control:
//! - Multiple stacked LSM modules with priority ordering
//! - Security hooks at every kernel decision point
//! - Security context (label) management
//! - Type Enforcement (TE) with access vectors
//! - Role-Based Access Control (RBAC)
//! - Multi-Level Security (MLS) / Bell-LaPadula
//! - Security policy: rules, defaults, transitions
//! - Object labeling: files, processes, sockets, IPC
//! - Audit log integration for denied/granted events
//! - Security ID (SID) to context mapping

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_LSM_MODULES: usize = 8;
const MAX_SECURITY_CONTEXTS: usize = 512;
const MAX_TE_RULES: usize = 256;
const MAX_ROLES: usize = 32;
const MAX_TYPES: usize = 128;
const MAX_CATEGORIES: usize = 64;
const MAX_AUDIT_ENTRIES: usize = 128;
const CONTEXT_STR_LEN: usize = 128;
const LABEL_LEN: usize = 64;
const NAME_LEN: usize = 32;

// ─────────────────── Security Classes ───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SecurityClass {
    File = 0,
    Dir = 1,
    Process = 2,
    Socket = 3,
    Ipc = 4,
    Msg = 5,
    Shm = 6,
    Sem = 7,
    Key = 8,
    Packet = 9,
    Node = 10,
    Netif = 11,
    Capability = 12,
    Filesystem = 13,
    System = 14,
    Kernel = 15,
}

// ─────────────────── Access Vector Permissions ──────────────────────

bitflags_u32! {
    /// File/Dir permissions
    pub struct FilePerms: u32 {
        const READ        = 0x0001;
        const WRITE       = 0x0002;
        const EXECUTE     = 0x0004;
        const APPEND      = 0x0008;
        const GETATTR     = 0x0010;
        const SETATTR     = 0x0020;
        const LOCK        = 0x0040;
        const IOCTL       = 0x0080;
        const CREATE      = 0x0100;
        const UNLINK      = 0x0200;
        const LINK        = 0x0400;
        const RENAME      = 0x0800;
        const OPEN        = 0x1000;
        const RELABELFROM = 0x2000;
        const RELABELTO   = 0x4000;
        const MOUNTON     = 0x8000;
    }
}

// Simplified bitflags macro substitute for no_std
macro_rules! bitflags_u32 {
    ($(#[$outer:meta])* pub struct $name:ident : u32 {
        $(const $flag:ident = $val:expr;)*
    }) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name(pub u32);

        impl $name {
            $(pub const $flag: Self = Self($val);)*

            pub const fn empty() -> Self { Self(0) }
            pub const fn all() -> Self { Self(0 $(| $val)*) }
            pub const fn contains(self, other: Self) -> bool { (self.0 & other.0) == other.0 }
            pub const fn intersects(self, other: Self) -> bool { (self.0 & other.0) != 0 }
            pub const fn union(self, other: Self) -> Self { Self(self.0 | other.0) }
            pub const fn difference(self, other: Self) -> Self { Self(self.0 & !other.0) }
        }
    }
}

bitflags_u32! {
    /// Process permissions
    pub struct ProcessPerms: u32 {
        const FORK        = 0x0001;
        const TRANSITION  = 0x0002;
        const SIGCHLD     = 0x0004;
        const SIGKILL     = 0x0008;
        const SIGSTOP     = 0x0010;
        const SIGNAL      = 0x0020;
        const PTRACE      = 0x0040;
        const GETSCHED    = 0x0080;
        const SETSCHED    = 0x0100;
        const GETPGID     = 0x0200;
        const SETPGID     = 0x0400;
        const GETCAP      = 0x0800;
        const SETCAP      = 0x1000;
        const GETATTR     = 0x2000;
        const SETEXEC     = 0x4000;
        const SETRLIMIT   = 0x8000;
    }
}

bitflags_u32! {
    /// Socket permissions
    pub struct SocketPerms: u32 {
        const CREATE      = 0x0001;
        const BIND        = 0x0002;
        const CONNECT     = 0x0004;
        const LISTEN      = 0x0008;
        const ACCEPT      = 0x0010;
        const SEND        = 0x0020;
        const RECV        = 0x0040;
        const SHUTDOWN    = 0x0080;
        const GETATTR     = 0x0100;
        const SETATTR     = 0x0200;
        const GETOPT      = 0x0400;
        const SETOPT      = 0x0800;
        const NAME_BIND   = 0x1000;
        const NODE_BIND   = 0x2000;
        const NAME_CONNECT= 0x4000;
        const RECVFROM    = 0x8000;
    }
}

// ─────────────────── Security Level (MLS) ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLevel {
    pub sensitivity: u16,           // s0..s15
    pub categories: [u8; 8],        // 64-bit category bitmap
}

impl SecurityLevel {
    pub const fn new() -> Self {
        Self {
            sensitivity: 0,
            categories: [0u8; 8],
        }
    }

    pub fn set_sensitivity(&mut self, s: u16) {
        self.sensitivity = s;
    }

    pub fn set_category(&mut self, cat: u8) {
        if (cat as usize) < MAX_CATEGORIES {
            let byte = (cat / 8) as usize;
            let bit = cat % 8;
            self.categories[byte] |= 1 << bit;
        }
    }

    pub fn has_category(&self, cat: u8) -> bool {
        if (cat as usize) >= MAX_CATEGORIES { return false; }
        let byte = (cat / 8) as usize;
        let bit = cat % 8;
        (self.categories[byte] & (1 << bit)) != 0
    }

    /// Bell-LaPadula: can subject read object?
    /// Subject level must dominate object level
    pub fn dominates(&self, other: &SecurityLevel) -> bool {
        if self.sensitivity < other.sensitivity {
            return false;
        }
        // Subject must have all categories of object
        for i in 0..8 {
            if (other.categories[i] & !self.categories[i]) != 0 {
                return false;
            }
        }
        true
    }
}

// ─────────────────── Security Context ───────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct SecurityContext {
    pub sid: u32,                       // Security ID
    pub user: [u8; NAME_LEN],          // SELinux user
    pub user_len: u8,
    pub role: [u8; NAME_LEN],          // Role
    pub role_len: u8,
    pub type_: [u8; NAME_LEN],        // Type (domain for process)
    pub type_len: u8,
    pub level: SecurityLevel,           // MLS level (low)
    pub level_high: SecurityLevel,      // MLS level (high, for range)
    pub valid: bool,
}

impl SecurityContext {
    pub const fn new() -> Self {
        Self {
            sid: 0,
            user: [0u8; NAME_LEN],
            user_len: 0,
            role: [0u8; NAME_LEN],
            role_len: 0,
            type_: [0u8; NAME_LEN],
            type_len: 0,
            level: SecurityLevel::new(),
            level_high: SecurityLevel::new(),
            valid: false,
        }
    }

    fn set_field(dst: &mut [u8; NAME_LEN], len: &mut u8, src: &[u8]) {
        let copy_len = src.len().min(NAME_LEN - 1);
        dst[..copy_len].copy_from_slice(&src[..copy_len]);
        *len = copy_len as u8;
    }

    pub fn set_user(&mut self, u: &[u8]) { Self::set_field(&mut self.user, &mut self.user_len, u); }
    pub fn set_role(&mut self, r: &[u8]) { Self::set_field(&mut self.role, &mut self.role_len, r); }
    pub fn set_type(&mut self, t: &[u8]) { Self::set_field(&mut self.type_, &mut self.type_len, t); }

    pub fn type_matches(&self, t: &[u8]) -> bool {
        let len = self.type_len as usize;
        if len != t.len() { return false; }
        self.type_[..len] == t[..len]
    }

    pub fn role_matches(&self, r: &[u8]) -> bool {
        let len = self.role_len as usize;
        if len != r.len() { return false; }
        self.role[..len] == r[..len]
    }
}

// ─────────────────── Type Enforcement Rule ──────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleEffect {
    Allow = 0,
    AuditAllow = 1,
    DontAudit = 2,
    NeverAllow = 3,
    TypeTransition = 4,
    TypeChange = 5,
    TypeMember = 6,
}

#[derive(Debug, Clone, Copy)]
pub struct TeRule {
    pub source_type: u16,       // Source type index
    pub target_type: u16,       // Target type index
    pub class: SecurityClass,
    pub permissions: u32,       // Access vector
    pub effect: RuleEffect,
    pub new_type: u16,          // For transitions
    pub active: bool,
    pub hit_count: u64,
}

impl TeRule {
    pub const fn new() -> Self {
        Self {
            source_type: 0,
            target_type: 0,
            class: SecurityClass::File,
            permissions: 0,
            effect: RuleEffect::Allow,
            new_type: 0,
            active: false,
            hit_count: 0,
        }
    }
}

// ─────────────────── Role ───────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Role {
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub types_allowed: [u8; 16],    // 128-bit type bitmap
    pub dominates: [u8; 4],         // 32-bit role dominance bitmap
    pub active: bool,
}

impl Role {
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            name_len: 0,
            types_allowed: [0u8; 16],
            dominates: [0u8; 4],
            active: false,
        }
    }

    pub fn allow_type(&mut self, type_idx: u16) {
        if (type_idx as usize) < MAX_TYPES {
            let byte = (type_idx / 8) as usize;
            let bit = (type_idx % 8) as u8;
            self.types_allowed[byte] |= 1 << bit;
        }
    }

    pub fn can_use_type(&self, type_idx: u16) -> bool {
        if (type_idx as usize) >= MAX_TYPES { return false; }
        let byte = (type_idx / 8) as usize;
        let bit = (type_idx % 8) as u8;
        (self.types_allowed[byte] & (1 << bit)) != 0
    }
}

// ─────────────────── Type Entry ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct TypeEntry {
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub is_domain: bool,        // Process domain
    pub is_attribute: bool,     // Type attribute (group)
    pub aliases: u8,            // Number of aliases
    pub active: bool,
}

impl TypeEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            name_len: 0,
            is_domain: false,
            is_attribute: false,
            aliases: 0,
            active: false,
        }
    }
}

// ─────────────────── Audit Entry ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditResult {
    Denied = 0,
    Granted = 1,
    DontAudit = 2,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub source_sid: u32,
    pub target_sid: u32,
    pub class: SecurityClass,
    pub requested: u32,
    pub result_: AuditResult,
    pub pid: u32,
    pub comm: [u8; 16],
    pub comm_len: u8,
    pub valid: bool,
}

impl AuditEntry {
    pub const fn new() -> Self {
        Self {
            timestamp: 0,
            source_sid: 0,
            target_sid: 0,
            class: SecurityClass::File,
            requested: 0,
            result_: AuditResult::Denied,
            pid: 0,
            comm: [0u8; 16],
            comm_len: 0,
            valid: false,
        }
    }
}

// ─────────────────── LSM Hook Type ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LsmHook {
    FileOpen = 0,
    FileRead = 1,
    FileWrite = 2,
    FileExecute = 3,
    FileCreate = 4,
    FileUnlink = 5,
    FileRename = 6,
    FileMknod = 7,
    FileChmod = 8,
    FileChown = 9,
    InodeGetattr = 10,
    InodeSetattr = 11,
    ProcessExec = 12,
    ProcessFork = 13,
    ProcessSignal = 14,
    ProcessPtrace = 15,
    SocketCreate = 16,
    SocketBind = 17,
    SocketConnect = 18,
    SocketSend = 19,
    SocketRecv = 20,
    IpcCreate = 21,
    IpcAccess = 22,
    CapCheck = 23,
    MountCheck = 24,
    SyslogAction = 25,
    KernelModule = 26,
    TaskKill = 27,
}

// ─────────────────── LSM Module ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct LsmModule {
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub priority: u8,          // Lower = higher priority
    pub enabled: bool,
    pub permissive: bool,      // Log but don't enforce
    pub hook_mask: u32,        // Which hooks this module handles
    pub decisions_allow: u64,
    pub decisions_deny: u64,
    pub active: bool,
}

impl LsmModule {
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            name_len: 0,
            priority: 128,
            enabled: false,
            permissive: false,
            hook_mask: 0,
            decisions_allow: 0,
            decisions_deny: 0,
            active: false,
        }
    }

    fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn handles_hook(&self, hook: LsmHook) -> bool {
        (self.hook_mask & (1u32 << (hook as u32))) != 0
    }
}

// ─────────────────── LSM Manager ────────────────────────────────────

pub struct LsmManager {
    // Modules
    modules: [LsmModule; MAX_LSM_MODULES],
    module_count: u8,

    // Security contexts (SID → context)
    contexts: [SecurityContext; MAX_SECURITY_CONTEXTS],
    next_sid: u32,

    // Type enforcement
    types: [TypeEntry; MAX_TYPES],
    type_count: u16,
    roles: [Role; MAX_ROLES],
    role_count: u8,
    te_rules: [TeRule; MAX_TE_RULES],
    rule_count: u16,

    // Audit ring buffer
    audit_log: [AuditEntry; MAX_AUDIT_ENTRIES],
    audit_head: u16,
    audit_count: u16,

    // Policy state
    enforcing: bool,
    policy_loaded: bool,
    policy_version: u32,

    // Stats
    total_checks: u64,
    total_allowed: u64,
    total_denied: u64,
    total_audited: u64,
    cache_hits: u64,

    tick: u64,
    initialized: bool,
}

impl LsmManager {
    pub const fn new() -> Self {
        Self {
            modules: [const { LsmModule::new() }; MAX_LSM_MODULES],
            module_count: 0,
            contexts: [const { SecurityContext::new() }; MAX_SECURITY_CONTEXTS],
            next_sid: 1, // 0 = unlabeled
            types: [const { TypeEntry::new() }; MAX_TYPES],
            type_count: 0,
            roles: [const { Role::new() }; MAX_ROLES],
            role_count: 0,
            te_rules: [const { TeRule::new() }; MAX_TE_RULES],
            rule_count: 0,
            audit_log: [const { AuditEntry::new() }; MAX_AUDIT_ENTRIES],
            audit_head: 0,
            audit_count: 0,
            enforcing: true,
            policy_loaded: false,
            policy_version: 0,
            total_checks: 0,
            total_allowed: 0,
            total_denied: 0,
            total_audited: 0,
            cache_hits: 0,
            tick: 0,
            initialized: true,
        }
    }

    // ─── Module Management ──────────────────────────────────────────

    pub fn register_module(&mut self, name: &[u8], priority: u8, hook_mask: u32) -> Option<u8> {
        if self.module_count as usize >= MAX_LSM_MODULES { return None; }
        for i in 0..MAX_LSM_MODULES {
            if !self.modules[i].active {
                self.modules[i] = LsmModule::new();
                self.modules[i].set_name(name);
                self.modules[i].priority = priority;
                self.modules[i].hook_mask = hook_mask;
                self.modules[i].enabled = true;
                self.modules[i].active = true;
                self.module_count += 1;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn set_permissive(&mut self, module_idx: u8, permissive: bool) -> bool {
        if (module_idx as usize) >= MAX_LSM_MODULES { return false; }
        if !self.modules[module_idx as usize].active { return false; }
        self.modules[module_idx as usize].permissive = permissive;
        true
    }

    // ─── Type Management ────────────────────────────────────────────

    pub fn register_type(&mut self, name: &[u8], is_domain: bool) -> Option<u16> {
        if self.type_count as usize >= MAX_TYPES { return None; }
        for i in 0..MAX_TYPES {
            if !self.types[i].active {
                let len = name.len().min(NAME_LEN - 1);
                self.types[i].name[..len].copy_from_slice(&name[..len]);
                self.types[i].name_len = len as u8;
                self.types[i].is_domain = is_domain;
                self.types[i].active = true;
                self.type_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    pub fn find_type(&self, name: &[u8]) -> Option<u16> {
        for i in 0..MAX_TYPES {
            if self.types[i].active {
                let len = self.types[i].name_len as usize;
                if len == name.len() && self.types[i].name[..len] == name[..len] {
                    return Some(i as u16);
                }
            }
        }
        None
    }

    // ─── Role Management ────────────────────────────────────────────

    pub fn register_role(&mut self, name: &[u8]) -> Option<u8> {
        if self.role_count as usize >= MAX_ROLES { return None; }
        for i in 0..MAX_ROLES {
            if !self.roles[i].active {
                let len = name.len().min(NAME_LEN - 1);
                self.roles[i].name[..len].copy_from_slice(&name[..len]);
                self.roles[i].name_len = len as u8;
                self.roles[i].active = true;
                self.role_count += 1;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn role_allow_type(&mut self, role_idx: u8, type_idx: u16) -> bool {
        if (role_idx as usize) >= MAX_ROLES { return false; }
        if !self.roles[role_idx as usize].active { return false; }
        self.roles[role_idx as usize].allow_type(type_idx);
        true
    }

    // ─── Context (SID) Management ───────────────────────────────────

    pub fn create_context(&mut self, user: &[u8], role: &[u8], type_: &[u8]) -> Option<u32> {
        let sid = self.next_sid;
        if (sid as usize) >= MAX_SECURITY_CONTEXTS { return None; }
        let idx = sid as usize;
        self.contexts[idx] = SecurityContext::new();
        self.contexts[idx].sid = sid;
        self.contexts[idx].set_user(user);
        self.contexts[idx].set_role(role);
        self.contexts[idx].set_type(type_);
        self.contexts[idx].valid = true;
        self.next_sid += 1;
        Some(sid)
    }

    pub fn get_context(&self, sid: u32) -> Option<&SecurityContext> {
        if (sid as usize) >= MAX_SECURITY_CONTEXTS { return None; }
        if self.contexts[sid as usize].valid {
            Some(&self.contexts[sid as usize])
        } else {
            None
        }
    }

    pub fn set_context_level(&mut self, sid: u32, sensitivity: u16) -> bool {
        if (sid as usize) >= MAX_SECURITY_CONTEXTS { return false; }
        if !self.contexts[sid as usize].valid { return false; }
        self.contexts[sid as usize].level.set_sensitivity(sensitivity);
        true
    }

    // ─── TE Rule Management ─────────────────────────────────────────

    pub fn add_allow_rule(
        &mut self,
        source_type: u16,
        target_type: u16,
        class: SecurityClass,
        permissions: u32,
    ) -> bool {
        self.add_rule(source_type, target_type, class, permissions, RuleEffect::Allow)
    }

    pub fn add_type_transition(
        &mut self,
        source_type: u16,
        target_type: u16,
        class: SecurityClass,
        new_type: u16,
    ) -> bool {
        if self.rule_count as usize >= MAX_TE_RULES { return false; }
        for i in 0..MAX_TE_RULES {
            if !self.te_rules[i].active {
                self.te_rules[i] = TeRule::new();
                self.te_rules[i].source_type = source_type;
                self.te_rules[i].target_type = target_type;
                self.te_rules[i].class = class;
                self.te_rules[i].effect = RuleEffect::TypeTransition;
                self.te_rules[i].new_type = new_type;
                self.te_rules[i].active = true;
                self.rule_count += 1;
                return true;
            }
        }
        false
    }

    fn add_rule(
        &mut self,
        source: u16,
        target: u16,
        class: SecurityClass,
        perms: u32,
        effect: RuleEffect,
    ) -> bool {
        if self.rule_count as usize >= MAX_TE_RULES { return false; }
        for i in 0..MAX_TE_RULES {
            if !self.te_rules[i].active {
                self.te_rules[i] = TeRule::new();
                self.te_rules[i].source_type = source;
                self.te_rules[i].target_type = target;
                self.te_rules[i].class = class;
                self.te_rules[i].permissions = perms;
                self.te_rules[i].effect = effect;
                self.te_rules[i].active = true;
                self.rule_count += 1;
                return true;
            }
        }
        false
    }

    // ─── Access Check ───────────────────────────────────────────────

    pub fn check_access(
        &mut self,
        source_sid: u32,
        target_sid: u32,
        class: SecurityClass,
        requested: u32,
        pid: u32,
    ) -> bool {
        self.total_checks += 1;

        if !self.policy_loaded { return true; } // No policy = permissive

        let source_ctx = match self.get_context_type_idx(source_sid) {
            Some(idx) => idx,
            None => { self.total_denied += 1; return false; }
        };

        let target_ctx = match self.get_context_type_idx(target_sid) {
            Some(idx) => idx,
            None => { self.total_denied += 1; return false; }
        };

        // MLS check (Bell-LaPadula)
        let mls_ok = self.check_mls(source_sid, target_sid, requested);
        if !mls_ok {
            self.emit_audit(source_sid, target_sid, class, requested, AuditResult::Denied, pid);
            self.total_denied += 1;
            return !self.enforcing;
        }

        // TE rule search
        let mut allowed: u32 = 0;
        let mut neverallow = false;

        for i in 0..MAX_TE_RULES {
            if !self.te_rules[i].active { continue; }
            let rule = &self.te_rules[i];
            if rule.source_type == source_ctx && rule.target_type == target_ctx && rule.class == class {
                match rule.effect {
                    RuleEffect::Allow | RuleEffect::AuditAllow => {
                        allowed |= rule.permissions;
                        // Safety: we need mutable — use index
                        self.te_rules[i].hit_count += 1;
                    }
                    RuleEffect::NeverAllow => {
                        if (rule.permissions & requested) != 0 {
                            neverallow = true;
                        }
                    }
                    RuleEffect::DontAudit => { /* skip auditing */ }
                    _ => {}
                }
            }
        }

        if neverallow {
            self.emit_audit(source_sid, target_sid, class, requested, AuditResult::Denied, pid);
            self.total_denied += 1;
            return false; // NeverAllow always enforced
        }

        let granted = (allowed & requested) == requested;
        if granted {
            self.total_allowed += 1;
            true
        } else {
            self.emit_audit(source_sid, target_sid, class, requested, AuditResult::Denied, pid);
            self.total_denied += 1;
            !self.enforcing // Permissive mode allows even denied
        }
    }

    fn get_context_type_idx(&self, sid: u32) -> Option<u16> {
        let ctx = self.get_context(sid)?;
        let type_name = &ctx.type_[..ctx.type_len as usize];
        self.find_type(type_name)
    }

    fn check_mls(&self, source_sid: u32, target_sid: u32, requested: u32) -> bool {
        let src = match self.get_context(source_sid) { Some(c) => c, None => return false };
        let tgt = match self.get_context(target_sid) { Some(c) => c, None => return false };

        // Read check: subject dominates object (no read up)
        let is_read = (requested & 0x0001) != 0;
        if is_read && !src.level.dominates(&tgt.level) {
            return false;
        }

        // Write check: object dominates subject (no write down)
        let is_write = (requested & 0x0002) != 0;
        if is_write && !tgt.level.dominates(&src.level) {
            return false;
        }

        true
    }

    // ─── Transition Check ───────────────────────────────────────────

    pub fn compute_transition(
        &self,
        source_sid: u32,
        target_sid: u32,
        class: SecurityClass,
    ) -> Option<u16> {
        let source_type = match self.get_context_type_idx(source_sid) { Some(t) => t, None => return None };
        let target_type = match self.get_context_type_idx(target_sid) { Some(t) => t, None => return None };

        for i in 0..MAX_TE_RULES {
            if !self.te_rules[i].active { continue; }
            let rule = &self.te_rules[i];
            if rule.source_type == source_type
                && rule.target_type == target_type
                && rule.class == class
                && rule.effect == RuleEffect::TypeTransition
            {
                return Some(rule.new_type);
            }
        }
        None
    }

    // ─── Audit ──────────────────────────────────────────────────────

    fn emit_audit(
        &mut self,
        source_sid: u32,
        target_sid: u32,
        class: SecurityClass,
        requested: u32,
        result: AuditResult,
        pid: u32,
    ) {
        let idx = self.audit_head as usize;
        self.audit_log[idx] = AuditEntry::new();
        self.audit_log[idx].timestamp = self.tick;
        self.audit_log[idx].source_sid = source_sid;
        self.audit_log[idx].target_sid = target_sid;
        self.audit_log[idx].class = class;
        self.audit_log[idx].requested = requested;
        self.audit_log[idx].result_ = result;
        self.audit_log[idx].pid = pid;
        self.audit_log[idx].valid = true;
        self.audit_head = ((self.audit_head + 1) % MAX_AUDIT_ENTRIES as u16) as u16;
        if self.audit_count < MAX_AUDIT_ENTRIES as u16 {
            self.audit_count += 1;
        }
        self.total_audited += 1;
    }

    // ─── Policy Management ──────────────────────────────────────────

    pub fn load_policy(&mut self) {
        self.policy_loaded = true;
        self.policy_version += 1;
    }

    pub fn set_enforcing(&mut self, enforcing: bool) {
        self.enforcing = enforcing;
    }

    pub fn tick(&mut self) {
        self.tick += 1;
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_LSM: LsmManager = LsmManager::new();
static mut G_LSM_INIT: bool = false;

fn lsm() -> &'static mut LsmManager {
    unsafe { &mut G_LSM }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_lsm_init() {
    unsafe {
        G_LSM = LsmManager::new();
        G_LSM_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_lsm_register_module(
    name_ptr: *const u8,
    name_len: usize,
    priority: u8,
    hook_mask: u32,
) -> i8 {
    if unsafe { !G_LSM_INIT } { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    match lsm().register_module(name, priority, hook_mask) {
        Some(idx) => idx as i8,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_lsm_register_type(
    name_ptr: *const u8,
    name_len: usize,
    is_domain: bool,
) -> i16 {
    if unsafe { !G_LSM_INIT } { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    match lsm().register_type(name, is_domain) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_lsm_create_context(
    user_ptr: *const u8, user_len: usize,
    role_ptr: *const u8, role_len: usize,
    type_ptr: *const u8, type_len: usize,
) -> i32 {
    if unsafe { !G_LSM_INIT } { return -1; }
    let user = unsafe { core::slice::from_raw_parts(user_ptr, user_len) };
    let role = unsafe { core::slice::from_raw_parts(role_ptr, role_len) };
    let type_ = unsafe { core::slice::from_raw_parts(type_ptr, type_len) };
    match lsm().create_context(user, role, type_) {
        Some(sid) => sid as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_lsm_add_allow(
    source: u16,
    target: u16,
    class: u16,
    perms: u32,
) -> bool {
    if unsafe { !G_LSM_INIT } { return false; }
    let cls: SecurityClass = unsafe { core::mem::transmute(class) };
    lsm().add_allow_rule(source, target, cls, perms)
}

#[no_mangle]
pub extern "C" fn rust_lsm_check_access(
    source_sid: u32,
    target_sid: u32,
    class: u16,
    requested: u32,
    pid: u32,
) -> bool {
    if unsafe { !G_LSM_INIT } { return true; }
    let cls: SecurityClass = unsafe { core::mem::transmute(class) };
    lsm().check_access(source_sid, target_sid, cls, requested, pid)
}

#[no_mangle]
pub extern "C" fn rust_lsm_load_policy() {
    if unsafe { !G_LSM_INIT } { return; }
    lsm().load_policy();
}

#[no_mangle]
pub extern "C" fn rust_lsm_set_enforcing(enforcing: bool) {
    if unsafe { !G_LSM_INIT } { return; }
    lsm().set_enforcing(enforcing);
}

#[no_mangle]
pub extern "C" fn rust_lsm_tick() {
    if unsafe { !G_LSM_INIT } { return; }
    lsm().tick();
}

#[no_mangle]
pub extern "C" fn rust_lsm_total_checks() -> u64 {
    if unsafe { !G_LSM_INIT } { return 0; }
    lsm().total_checks
}

#[no_mangle]
pub extern "C" fn rust_lsm_total_denied() -> u64 {
    if unsafe { !G_LSM_INIT } { return 0; }
    lsm().total_denied
}

#[no_mangle]
pub extern "C" fn rust_lsm_total_allowed() -> u64 {
    if unsafe { !G_LSM_INIT } { return 0; }
    lsm().total_allowed
}

#[no_mangle]
pub extern "C" fn rust_lsm_module_count() -> u8 {
    if unsafe { !G_LSM_INIT } { return 0; }
    lsm().module_count
}

#[no_mangle]
pub extern "C" fn rust_lsm_rule_count() -> u16 {
    if unsafe { !G_LSM_INIT } { return 0; }
    lsm().rule_count
}
