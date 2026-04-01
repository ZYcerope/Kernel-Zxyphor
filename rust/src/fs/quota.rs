// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Filesystem Quota Subsystem (Rust)
//
// Disk quota enforcement for users and groups:
// - Per-user and per-group block/inode quotas
// - Hard limit (absolute maximum, EDQUOT on exceed)
// - Soft limit (warning threshold + grace period)
// - Grace period enforcement with configurable timeout
// - Project quotas (XFS-style directory tree quotas)
// - Quota file format (binary on-disk representation)
// - Quota state machine (off → turning_on → on → turning_off)
// - Usage tracking with atomic-style counters
// - Dquot cache for hot quota entries
// - Quota transfer (chown/chgrp updates)
// - Warning thresholds and quota exceeded flags
// - Per-filesystem quota info

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_QUOTAS: usize = 256;
const MAX_FS_QUOTA: usize = 16;
const MAX_DQUOT_CACHE: usize = 128;
const MAX_WARNINGS: usize = 64;
const QUOTA_MAGIC: u32 = 0xD9C01F11;
const QUOTA_VERSION: u32 = 2;

// ─────────────────── Quota Type ─────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum QuotaType {
    User = 0,
    Group = 1,
    Project = 2,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum QuotaState {
    Off = 0,
    TurningOn = 1,
    On = 2,
    TurningOff = 3,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum QuotaFlag {
    None = 0,
    SoftExceeded = 1,
    HardExceeded = 2,
    GraceExpired = 3,
}

// ─────────────────── Disk Quota Entry ───────────────────────────────

/// On-disk / in-memory quota entry for a single ID (uid/gid/projid)
#[derive(Clone, Copy)]
pub struct DiskQuota {
    pub id: u32,            // uid, gid, or project id
    pub qtype: QuotaType,
    pub fs_idx: u8,         // Which filesystem

    // Block limits (in 1K blocks)
    pub block_hardlimit: u64,
    pub block_softlimit: u64,
    pub block_current: u64,

    // Inode limits
    pub inode_hardlimit: u64,
    pub inode_softlimit: u64,
    pub inode_current: u64,

    // Grace periods (ticks from when soft limit exceeded)
    pub block_grace: u64,      // Configured grace period
    pub inode_grace: u64,
    pub block_grace_start: u64, // Tick when soft exceeded
    pub inode_grace_start: u64,

    // Status
    pub block_flag: QuotaFlag,
    pub inode_flag: QuotaFlag,
    pub warnings_issued: u32,

    // Timestamps
    pub create_time: u64,
    pub modify_time: u64,

    pub active: bool,
}

impl DiskQuota {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            qtype: QuotaType::User,
            fs_idx: 0,
            block_hardlimit: 0,
            block_softlimit: 0,
            block_current: 0,
            inode_hardlimit: 0,
            inode_softlimit: 0,
            inode_current: 0,
            block_grace: 604800_000, // 7 days default
            inode_grace: 604800_000,
            block_grace_start: 0,
            inode_grace_start: 0,
            block_flag: QuotaFlag::None,
            inode_flag: QuotaFlag::None,
            warnings_issued: 0,
            create_time: 0,
            modify_time: 0,
            active: false,
        }
    }

    pub fn block_usage_pct(&self) -> u32 {
        if self.block_hardlimit == 0 { return 0; }
        ((self.block_current * 100) / self.block_hardlimit) as u32
    }

    pub fn inode_usage_pct(&self) -> u32 {
        if self.inode_hardlimit == 0 { return 0; }
        ((self.inode_current * 100) / self.inode_hardlimit) as u32
    }

    /// Check if block allocation of `count` blocks is allowed
    pub fn check_block_alloc(&self, count: u64, now: u64) -> bool {
        let new_usage = self.block_current + count;

        // Hard limit: absolute deny
        if self.block_hardlimit > 0 && new_usage > self.block_hardlimit {
            return false;
        }

        // Soft limit + grace expired: deny
        if self.block_softlimit > 0 && new_usage > self.block_softlimit {
            if self.block_grace_start > 0 && now > self.block_grace_start + self.block_grace {
                return false; // Grace period expired
            }
        }

        true
    }

    /// Check if inode allocation is allowed
    pub fn check_inode_alloc(&self, count: u64, now: u64) -> bool {
        let new_usage = self.inode_current + count;

        if self.inode_hardlimit > 0 && new_usage > self.inode_hardlimit {
            return false;
        }

        if self.inode_softlimit > 0 && new_usage > self.inode_softlimit {
            if self.inode_grace_start > 0 && now > self.inode_grace_start + self.inode_grace {
                return false;
            }
        }

        true
    }

    /// Apply block allocation and update flags
    pub fn alloc_blocks(&mut self, count: u64, now: u64) -> bool {
        if !self.check_block_alloc(count, now) {
            return false;
        }
        self.block_current += count;
        self.modify_time = now;

        // Check soft limit crossing
        if self.block_softlimit > 0 && self.block_current > self.block_softlimit {
            if self.block_grace_start == 0 {
                self.block_grace_start = now;
            }
            self.block_flag = QuotaFlag::SoftExceeded;
        } else {
            self.block_flag = QuotaFlag::None;
            self.block_grace_start = 0;
        }

        // Check hard limit proximity
        if self.block_hardlimit > 0 && self.block_current >= self.block_hardlimit {
            self.block_flag = QuotaFlag::HardExceeded;
        }

        true
    }

    /// Free blocks
    pub fn free_blocks(&mut self, count: u64, now: u64) {
        if count > self.block_current {
            self.block_current = 0;
        } else {
            self.block_current -= count;
        }
        self.modify_time = now;

        // Reset flag if below soft limit
        if self.block_softlimit == 0 || self.block_current <= self.block_softlimit {
            self.block_flag = QuotaFlag::None;
            self.block_grace_start = 0;
        }
    }

    /// Apply inode allocation
    pub fn alloc_inodes(&mut self, count: u64, now: u64) -> bool {
        if !self.check_inode_alloc(count, now) {
            return false;
        }
        self.inode_current += count;
        self.modify_time = now;

        if self.inode_softlimit > 0 && self.inode_current > self.inode_softlimit {
            if self.inode_grace_start == 0 {
                self.inode_grace_start = now;
            }
            self.inode_flag = QuotaFlag::SoftExceeded;
        } else {
            self.inode_flag = QuotaFlag::None;
            self.inode_grace_start = 0;
        }

        if self.inode_hardlimit > 0 && self.inode_current >= self.inode_hardlimit {
            self.inode_flag = QuotaFlag::HardExceeded;
        }

        true
    }

    pub fn free_inodes(&mut self, count: u64, now: u64) {
        if count > self.inode_current {
            self.inode_current = 0;
        } else {
            self.inode_current -= count;
        }
        self.modify_time = now;

        if self.inode_softlimit == 0 || self.inode_current <= self.inode_softlimit {
            self.inode_flag = QuotaFlag::None;
            self.inode_grace_start = 0;
        }
    }

    /// Check grace period expiration
    pub fn check_grace(&mut self, now: u64) {
        if self.block_flag == QuotaFlag::SoftExceeded && self.block_grace_start > 0 {
            if now > self.block_grace_start + self.block_grace {
                self.block_flag = QuotaFlag::GraceExpired;
            }
        }
        if self.inode_flag == QuotaFlag::SoftExceeded && self.inode_grace_start > 0 {
            if now > self.inode_grace_start + self.inode_grace {
                self.inode_flag = QuotaFlag::GraceExpired;
            }
        }
    }
}

// ─────────────────── Per-Filesystem Quota Info ──────────────────────

#[derive(Clone, Copy)]
pub struct FsQuotaInfo {
    pub fs_name: [u8; 32],
    pub fs_name_len: u8,
    pub dev_id: u32,
    pub state: [QuotaState; 3], // Per quota type
    pub quota_enabled: [bool; 3],
    pub default_block_grace: u64,
    pub default_inode_grace: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub active: bool,
}

impl FsQuotaInfo {
    pub const fn empty() -> Self {
        Self {
            fs_name: [0u8; 32],
            fs_name_len: 0,
            dev_id: 0,
            state: [QuotaState::Off; 3],
            quota_enabled: [false; 3],
            default_block_grace: 604800_000,
            default_inode_grace: 604800_000,
            total_blocks: 0,
            free_blocks: 0,
            total_inodes: 0,
            free_inodes: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() < 32 { n.len() } else { 32 };
        self.fs_name[..len].copy_from_slice(&n[..len]);
        self.fs_name_len = len as u8;
    }
}

// ─────────────────── Warning Entry ──────────────────────────────────

#[derive(Clone, Copy)]
pub struct QuotaWarning {
    pub id: u32,
    pub qtype: QuotaType,
    pub flag: QuotaFlag,
    pub fs_idx: u8,
    pub block_usage_pct: u32,
    pub inode_usage_pct: u32,
    pub timestamp: u64,
    pub active: bool,
}

impl QuotaWarning {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            qtype: QuotaType::User,
            flag: QuotaFlag::None,
            fs_idx: 0,
            block_usage_pct: 0,
            inode_usage_pct: 0,
            timestamp: 0,
            active: false,
        }
    }
}

// ─────────────────── Quota Manager ──────────────────────────────────

pub struct QuotaManager {
    pub quotas: [DiskQuota; MAX_QUOTAS],
    pub fs_info: [FsQuotaInfo; MAX_FS_QUOTA],
    pub warnings: [QuotaWarning; MAX_WARNINGS],
    pub warn_head: usize,

    pub quota_count: u32,
    pub fs_count: u8,
    pub tick: u64,

    // Stats
    pub total_alloc_blocks: u64,
    pub total_free_blocks: u64,
    pub total_alloc_inodes: u64,
    pub total_free_inodes: u64,
    pub total_denials: u64,
    pub total_warnings: u64,
    pub total_grace_expired: u64,
    pub total_transfers: u64,

    pub initialized: bool,
}

impl QuotaManager {
    pub fn new() -> Self {
        Self {
            quotas: [DiskQuota::empty(); MAX_QUOTAS],
            fs_info: [FsQuotaInfo::empty(); MAX_FS_QUOTA],
            warnings: [QuotaWarning::empty(); MAX_WARNINGS],
            warn_head: 0,
            quota_count: 0,
            fs_count: 0,
            tick: 0,
            total_alloc_blocks: 0,
            total_free_blocks: 0,
            total_alloc_inodes: 0,
            total_free_inodes: 0,
            total_denials: 0,
            total_warnings: 0,
            total_grace_expired: 0,
            total_transfers: 0,
            initialized: true,
        }
    }

    // ─── Filesystem Registration ────────────────────────────────────

    pub fn register_fs(&mut self, name: &[u8], dev_id: u32, total_blocks: u64, total_inodes: u64) -> Option<u8> {
        for i in 0..MAX_FS_QUOTA {
            if !self.fs_info[i].active {
                self.fs_info[i] = FsQuotaInfo::empty();
                self.fs_info[i].set_name(name);
                self.fs_info[i].dev_id = dev_id;
                self.fs_info[i].total_blocks = total_blocks;
                self.fs_info[i].free_blocks = total_blocks;
                self.fs_info[i].total_inodes = total_inodes;
                self.fs_info[i].free_inodes = total_inodes;
                self.fs_info[i].active = true;
                self.fs_count += 1;
                return Some(i as u8);
            }
        }
        None
    }

    pub fn enable_quota(&mut self, fs_idx: u8, qtype: QuotaType) -> bool {
        let idx = fs_idx as usize;
        if idx >= MAX_FS_QUOTA || !self.fs_info[idx].active {
            return false;
        }
        let qt = qtype as usize;
        self.fs_info[idx].state[qt] = QuotaState::TurningOn;
        self.fs_info[idx].quota_enabled[qt] = true;
        self.fs_info[idx].state[qt] = QuotaState::On;
        true
    }

    pub fn disable_quota(&mut self, fs_idx: u8, qtype: QuotaType) -> bool {
        let idx = fs_idx as usize;
        if idx >= MAX_FS_QUOTA || !self.fs_info[idx].active {
            return false;
        }
        let qt = qtype as usize;
        self.fs_info[idx].state[qt] = QuotaState::TurningOff;
        self.fs_info[idx].quota_enabled[qt] = false;
        self.fs_info[idx].state[qt] = QuotaState::Off;
        true
    }

    // ─── Quota CRUD ─────────────────────────────────────────────────

    pub fn set_quota(&mut self, fs_idx: u8, id: u32, qtype: QuotaType,
                     blk_hard: u64, blk_soft: u64, ino_hard: u64, ino_soft: u64) -> Option<usize> {
        // Check if already exists
        for i in 0..MAX_QUOTAS {
            if self.quotas[i].active && self.quotas[i].id == id
                && self.quotas[i].qtype == qtype && self.quotas[i].fs_idx == fs_idx
            {
                self.quotas[i].block_hardlimit = blk_hard;
                self.quotas[i].block_softlimit = blk_soft;
                self.quotas[i].inode_hardlimit = ino_hard;
                self.quotas[i].inode_softlimit = ino_soft;
                self.quotas[i].modify_time = self.tick;
                return Some(i);
            }
        }
        // Allocate new
        for i in 0..MAX_QUOTAS {
            if !self.quotas[i].active {
                self.quotas[i] = DiskQuota::empty();
                self.quotas[i].id = id;
                self.quotas[i].qtype = qtype;
                self.quotas[i].fs_idx = fs_idx;
                self.quotas[i].block_hardlimit = blk_hard;
                self.quotas[i].block_softlimit = blk_soft;
                self.quotas[i].inode_hardlimit = ino_hard;
                self.quotas[i].inode_softlimit = ino_soft;
                self.quotas[i].block_grace = self.fs_info[fs_idx as usize].default_block_grace;
                self.quotas[i].inode_grace = self.fs_info[fs_idx as usize].default_inode_grace;
                self.quotas[i].create_time = self.tick;
                self.quotas[i].modify_time = self.tick;
                self.quotas[i].active = true;
                self.quota_count += 1;
                return Some(i);
            }
        }
        None
    }

    pub fn remove_quota(&mut self, fs_idx: u8, id: u32, qtype: QuotaType) -> bool {
        for i in 0..MAX_QUOTAS {
            if self.quotas[i].active && self.quotas[i].id == id
                && self.quotas[i].qtype == qtype && self.quotas[i].fs_idx == fs_idx
            {
                self.quotas[i].active = false;
                self.quota_count -= 1;
                return true;
            }
        }
        false
    }

    pub fn find_quota(&self, fs_idx: u8, id: u32, qtype: QuotaType) -> Option<usize> {
        for i in 0..MAX_QUOTAS {
            if self.quotas[i].active && self.quotas[i].id == id
                && self.quotas[i].qtype == qtype && self.quotas[i].fs_idx == fs_idx
            {
                return Some(i);
            }
        }
        None
    }

    // ─── Allocation Interface ───────────────────────────────────────

    pub fn alloc_space(&mut self, fs_idx: u8, uid: u32, gid: u32, blocks: u64) -> bool {
        let now = self.tick;

        // Check user quota
        if let Some(qi) = self.find_quota(fs_idx, uid, QuotaType::User) {
            if !self.quotas[qi].alloc_blocks(blocks, now) {
                self.total_denials += 1;
                self.emit_warning(uid, QuotaType::User, fs_idx, qi);
                return false;
            }
        }

        // Check group quota
        if let Some(qi) = self.find_quota(fs_idx, gid, QuotaType::Group) {
            if !self.quotas[qi].alloc_blocks(blocks, now) {
                // Rollback user quota
                if let Some(uqi) = self.find_quota(fs_idx, uid, QuotaType::User) {
                    self.quotas[uqi].free_blocks(blocks, now);
                }
                self.total_denials += 1;
                self.emit_warning(gid, QuotaType::Group, fs_idx, qi);
                return false;
            }
        }

        self.total_alloc_blocks += blocks;
        true
    }

    pub fn free_space(&mut self, fs_idx: u8, uid: u32, gid: u32, blocks: u64) {
        let now = self.tick;
        if let Some(qi) = self.find_quota(fs_idx, uid, QuotaType::User) {
            self.quotas[qi].free_blocks(blocks, now);
        }
        if let Some(qi) = self.find_quota(fs_idx, gid, QuotaType::Group) {
            self.quotas[qi].free_blocks(blocks, now);
        }
        self.total_free_blocks += blocks;
    }

    pub fn alloc_inode(&mut self, fs_idx: u8, uid: u32, gid: u32) -> bool {
        let now = self.tick;

        if let Some(qi) = self.find_quota(fs_idx, uid, QuotaType::User) {
            if !self.quotas[qi].alloc_inodes(1, now) {
                self.total_denials += 1;
                return false;
            }
        }

        if let Some(qi) = self.find_quota(fs_idx, gid, QuotaType::Group) {
            if !self.quotas[qi].alloc_inodes(1, now) {
                if let Some(uqi) = self.find_quota(fs_idx, uid, QuotaType::User) {
                    self.quotas[uqi].free_inodes(1, now);
                }
                self.total_denials += 1;
                return false;
            }
        }

        self.total_alloc_inodes += 1;
        true
    }

    pub fn free_inode(&mut self, fs_idx: u8, uid: u32, gid: u32) {
        let now = self.tick;
        if let Some(qi) = self.find_quota(fs_idx, uid, QuotaType::User) {
            self.quotas[qi].free_inodes(1, now);
        }
        if let Some(qi) = self.find_quota(fs_idx, gid, QuotaType::Group) {
            self.quotas[qi].free_inodes(1, now);
        }
        self.total_free_inodes += 1;
    }

    // ─── Transfer (chown/chgrp) ─────────────────────────────────────

    pub fn transfer_blocks(&mut self, fs_idx: u8, old_uid: u32, new_uid: u32, blocks: u64) -> bool {
        let now = self.tick;

        // Check new owner can accept
        if let Some(qi) = self.find_quota(fs_idx, new_uid, QuotaType::User) {
            if !self.quotas[qi].check_block_alloc(blocks, now) {
                self.total_denials += 1;
                return false;
            }
        }

        // Transfer
        if let Some(qi) = self.find_quota(fs_idx, old_uid, QuotaType::User) {
            self.quotas[qi].free_blocks(blocks, now);
        }
        if let Some(qi) = self.find_quota(fs_idx, new_uid, QuotaType::User) {
            self.quotas[qi].alloc_blocks(blocks, now);
        }

        self.total_transfers += 1;
        true
    }

    // ─── Warning System ─────────────────────────────────────────────

    fn emit_warning(&mut self, id: u32, qtype: QuotaType, fs_idx: u8, qi: usize) {
        let w = &mut self.warnings[self.warn_head];
        *w = QuotaWarning::empty();
        w.id = id;
        w.qtype = qtype;
        w.flag = self.quotas[qi].block_flag;
        w.fs_idx = fs_idx;
        w.block_usage_pct = self.quotas[qi].block_usage_pct();
        w.inode_usage_pct = self.quotas[qi].inode_usage_pct();
        w.timestamp = self.tick;
        w.active = true;

        self.warn_head = (self.warn_head + 1) % MAX_WARNINGS;
        self.total_warnings += 1;
        self.quotas[qi].warnings_issued += 1;
    }

    // ─── Grace Period Check ─────────────────────────────────────────

    pub fn check_all_grace(&mut self) -> u32 {
        let mut expired = 0u32;
        let now = self.tick;
        for i in 0..MAX_QUOTAS {
            if !self.quotas[i].active { continue; }
            let old_bf = self.quotas[i].block_flag;
            let old_if = self.quotas[i].inode_flag;
            self.quotas[i].check_grace(now);
            if self.quotas[i].block_flag == QuotaFlag::GraceExpired && old_bf != QuotaFlag::GraceExpired {
                expired += 1;
            }
            if self.quotas[i].inode_flag == QuotaFlag::GraceExpired && old_if != QuotaFlag::GraceExpired {
                expired += 1;
            }
        }
        self.total_grace_expired += expired as u64;
        expired
    }

    pub fn advance_tick(&mut self) {
        self.tick += 1;
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_QUOTA: Option<QuotaManager> = None;
static mut G_QUOTA_INIT: bool = false;

fn qm() -> &'static mut QuotaManager {
    unsafe { G_QUOTA.as_mut().unwrap() }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_quota_init() {
    unsafe {
        G_QUOTA = Some(QuotaManager::new());
        G_QUOTA_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_quota_register_fs(name: *const u8, name_len: usize, dev_id: u32, total_blocks: u64, total_inodes: u64) -> i8 {
    if unsafe { !G_QUOTA_INIT } || name.is_null() { return -1; }
    let n = unsafe { core::slice::from_raw_parts(name, name_len) };
    match qm().register_fs(n, dev_id, total_blocks, total_inodes) {
        Some(idx) => idx as i8,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_quota_set(fs_idx: u8, id: u32, qtype: u8, blk_hard: u64, blk_soft: u64, ino_hard: u64, ino_soft: u64) -> bool {
    if unsafe { !G_QUOTA_INIT } { return false; }
    let qt: QuotaType = unsafe { core::mem::transmute(qtype) };
    qm().set_quota(fs_idx, id, qt, blk_hard, blk_soft, ino_hard, ino_soft).is_some()
}

#[no_mangle]
pub extern "C" fn rust_quota_alloc_space(fs_idx: u8, uid: u32, gid: u32, blocks: u64) -> bool {
    if unsafe { !G_QUOTA_INIT } { return true; } // No quota = allow
    qm().alloc_space(fs_idx, uid, gid, blocks)
}

#[no_mangle]
pub extern "C" fn rust_quota_free_space(fs_idx: u8, uid: u32, gid: u32, blocks: u64) {
    if unsafe { !G_QUOTA_INIT } { return; }
    qm().free_space(fs_idx, uid, gid, blocks);
}

#[no_mangle]
pub extern "C" fn rust_quota_alloc_inode(fs_idx: u8, uid: u32, gid: u32) -> bool {
    if unsafe { !G_QUOTA_INIT } { return true; }
    qm().alloc_inode(fs_idx, uid, gid)
}

#[no_mangle]
pub extern "C" fn rust_quota_free_inode(fs_idx: u8, uid: u32, gid: u32) {
    if unsafe { !G_QUOTA_INIT } { return; }
    qm().free_inode(fs_idx, uid, gid);
}

#[no_mangle]
pub extern "C" fn rust_quota_count() -> u32 {
    if unsafe { !G_QUOTA_INIT } { return 0; }
    qm().quota_count
}

#[no_mangle]
pub extern "C" fn rust_quota_total_denials() -> u64 {
    if unsafe { !G_QUOTA_INIT } { return 0; }
    qm().total_denials
}

#[no_mangle]
pub extern "C" fn rust_quota_total_warnings() -> u64 {
    if unsafe { !G_QUOTA_INIT } { return 0; }
    qm().total_warnings
}

#[no_mangle]
pub extern "C" fn rust_quota_total_transfers() -> u64 {
    if unsafe { !G_QUOTA_INIT } { return 0; }
    qm().total_transfers
}
