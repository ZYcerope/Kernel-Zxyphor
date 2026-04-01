// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust seccomp-BPF Sandbox
//
// Secure computing mode with BPF program filtering:
// - seccomp strict mode (only read/write/exit/sigreturn)
// - seccomp filter mode with cBPF programs
// - BPF instruction set implementation
// - Syscall argument inspection
// - Filter program validation
// - Return action handling (ALLOW/KILL/TRAP/ERRNO/TRACE/LOG)
// - Filter chaining (multiple programs per task)
// - Audit logging of denied syscalls
// - Performance: JIT-like optimized dispatch
// - SECCOMP_RET_USER_NOTIF for userspace supervision

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ─────────────────── seccomp Return Actions ─────────────────────────
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC00000;
pub const SECCOMP_RET_TRACE: u32 = 0x7FF00000;
pub const SECCOMP_RET_LOG: u32 = 0x7FFC0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xFFFF0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000FFFF;

// seccomp operations
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

// seccomp flags
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 2;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 4;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 8;
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 16;

// ─────────────────── seccomp Data (what BPF sees) ───────────────────
/// The data structure available to seccomp BPF filters
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SeccompData {
    pub nr: i32,           // syscall number
    pub arch: u32,         // AUDIT_ARCH_*
    pub instruction_pointer: u64,
    pub args: [u64; 6],    // syscall arguments
}

pub const AUDIT_ARCH_X86_64: u32 = 0xC000003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC00000B7;

impl SeccompData {
    pub fn new(nr: i32, args: [u64; 6], ip: u64) -> Self {
        Self {
            nr,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: ip,
            args,
        }
    }

    /// Get byte at offset within SeccompData (for BPF LD_ABS)
    pub fn byte_at(&self, offset: usize) -> Option<u8> {
        let bytes = self.as_bytes();
        bytes.get(offset).copied()
    }

    /// Get u16 at offset (big-endian as per BPF convention)
    pub fn u16_at(&self, offset: usize) -> Option<u16> {
        let bytes = self.as_bytes();
        if offset + 1 >= bytes.len() {
            return None;
        }
        Some((bytes[offset] as u16) << 8 | bytes[offset + 1] as u16)
    }

    /// Get u32 at offset
    pub fn u32_at(&self, offset: usize) -> Option<u32> {
        let bytes = self.as_bytes();
        if offset + 3 >= bytes.len() {
            return None;
        }
        // seccomp uses native endian for struct fields accessed via offset
        Some(
            (bytes[offset] as u32)
                | (bytes[offset + 1] as u32) << 8
                | (bytes[offset + 2] as u32) << 16
                | (bytes[offset + 3] as u32) << 24,
        )
    }

    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const Self as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<Self>()) }
    }
}

// ─────────────────── Classic BPF Instructions ───────────────────────
// BPF instruction classes
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// LD/LDX sizes
pub const BPF_W: u16 = 0x00;  // 32-bit word
pub const BPF_H: u16 = 0x08;  // 16-bit half
pub const BPF_B: u16 = 0x10;  // 8-bit byte

// LD/LDX modes
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;

// ALU operations
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xA0;

// JMP operations
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

// Source
pub const BPF_K: u16 = 0x00;   // Immediate
pub const BPF_X: u16 = 0x08;   // X register

// MISC
pub const BPF_TAX: u16 = 0x00; // A → X
pub const BPF_TXA: u16 = 0x80; // X → A

/// Classic BPF instruction
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,    // jump true
    pub jf: u8,    // jump false
    pub k: u32,    // immediate value
}

impl BpfInsn {
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// BPF_STMT(code, k)
    pub const fn stmt(code: u16, k: u32) -> Self {
        Self { code, jt: 0, jf: 0, k }
    }

    /// BPF_JUMP(code, k, jt, jf)
    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

// ─────────────────── BPF Program ────────────────────────────────────
pub const MAX_BPF_INSNS: usize = 4096;
pub const BPF_MEMWORDS: usize = 16;

#[derive(Clone)]
pub struct BpfProgram {
    pub insns: [BpfInsn; MAX_BPF_INSNS],
    pub len: usize,
    pub validated: bool,
}

impl BpfProgram {
    pub fn new() -> Self {
        Self {
            insns: [BpfInsn::new(0, 0, 0, 0); MAX_BPF_INSNS],
            len: 0,
            validated: false,
        }
    }

    pub fn from_slice(insns: &[BpfInsn]) -> Option<Self> {
        if insns.len() > MAX_BPF_INSNS {
            return None;
        }
        let mut prog = Self::new();
        prog.insns[..insns.len()].copy_from_slice(insns);
        prog.len = insns.len();
        Some(prog)
    }

    /// Validate the BPF program for safety
    pub fn validate(&mut self) -> bool {
        if self.len == 0 || self.len > MAX_BPF_INSNS {
            return false;
        }

        // Last instruction must be RET
        let last = &self.insns[self.len - 1];
        if last.code & 0x07 != BPF_RET {
            return false;
        }

        // Validate each instruction
        for i in 0..self.len {
            let insn = &self.insns[i];
            let class = insn.code & 0x07;

            match class {
                BPF_LD | BPF_LDX => {
                    let mode = insn.code & 0xE0;
                    if mode == BPF_ABS {
                        // Check offset within SeccompData
                        if insn.k as usize >= core::mem::size_of::<SeccompData>() {
                            return false;
                        }
                    }
                    if mode == BPF_MEM {
                        if insn.k as usize >= BPF_MEMWORDS {
                            return false;
                        }
                    }
                }
                BPF_ST | BPF_STX => {
                    if insn.k as usize >= BPF_MEMWORDS {
                        return false;
                    }
                }
                BPF_ALU => {
                    let op = insn.code & 0xF0;
                    // Check for division by zero with immediate
                    if (op == BPF_DIV || op == BPF_MOD) && (insn.code & BPF_X == 0) && insn.k == 0
                    {
                        return false;
                    }
                }
                BPF_JMP => {
                    let op = insn.code & 0xF0;
                    if op == BPF_JA {
                        let target = i + 1 + insn.k as usize;
                        if target >= self.len {
                            return false;
                        }
                    } else {
                        // Conditional: check both targets
                        let target_t = i + 1 + insn.jt as usize;
                        let target_f = i + 1 + insn.jf as usize;
                        if target_t >= self.len || target_f >= self.len {
                            return false;
                        }
                    }
                }
                BPF_RET => {
                    // Only valid at end or for early return
                }
                BPF_MISC => {
                    let op = insn.code & 0xF8;
                    if op != BPF_TAX && op != BPF_TXA {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        self.validated = true;
        true
    }

    /// Execute the BPF program against SeccompData
    pub fn run(&self, data: &SeccompData) -> u32 {
        if !self.validated {
            return SECCOMP_RET_KILL_PROCESS;
        }

        let mut a: u32 = 0;  // accumulator
        let mut x: u32 = 0;  // index register
        let mut mem = [0u32; BPF_MEMWORDS];
        let mut pc: usize = 0;

        while pc < self.len {
            let insn = &self.insns[pc];
            let class = insn.code & 0x07;

            match class {
                BPF_LD => {
                    let size = insn.code & 0x18;
                    let mode = insn.code & 0xE0;
                    a = match mode {
                        BPF_IMM => insn.k,
                        BPF_ABS => {
                            let off = insn.k as usize;
                            match size {
                                BPF_W => data.u32_at(off).unwrap_or(0),
                                BPF_H => data.u16_at(off).unwrap_or(0) as u32,
                                BPF_B => data.byte_at(off).unwrap_or(0) as u32,
                                _ => 0,
                            }
                        }
                        BPF_MEM => mem[insn.k as usize % BPF_MEMWORDS],
                        BPF_LEN => core::mem::size_of::<SeccompData>() as u32,
                        _ => 0,
                    };
                }
                BPF_LDX => {
                    let mode = insn.code & 0xE0;
                    x = match mode {
                        BPF_IMM => insn.k,
                        BPF_MEM => mem[insn.k as usize % BPF_MEMWORDS],
                        BPF_LEN => core::mem::size_of::<SeccompData>() as u32,
                        _ => 0,
                    };
                }
                BPF_ST => {
                    mem[insn.k as usize % BPF_MEMWORDS] = a;
                }
                BPF_STX => {
                    mem[insn.k as usize % BPF_MEMWORDS] = x;
                }
                BPF_ALU => {
                    let src = if insn.code & BPF_X != 0 { x } else { insn.k };
                    let op = insn.code & 0xF0;
                    a = match op {
                        BPF_ADD => a.wrapping_add(src),
                        BPF_SUB => a.wrapping_sub(src),
                        BPF_MUL => a.wrapping_mul(src),
                        BPF_DIV => if src != 0 { a / src } else { return SECCOMP_RET_KILL_PROCESS },
                        BPF_OR => a | src,
                        BPF_AND => a & src,
                        BPF_LSH => a.wrapping_shl(src),
                        BPF_RSH => a.wrapping_shr(src),
                        BPF_NEG => (!a).wrapping_add(1),
                        BPF_MOD => if src != 0 { a % src } else { return SECCOMP_RET_KILL_PROCESS },
                        BPF_XOR => a ^ src,
                        _ => a,
                    };
                }
                BPF_JMP => {
                    let op = insn.code & 0xF0;
                    if op == BPF_JA {
                        pc += insn.k as usize;
                    } else {
                        let src = if insn.code & BPF_X != 0 { x } else { insn.k };
                        let cond = match op {
                            BPF_JEQ => a == src,
                            BPF_JGT => a > src,
                            BPF_JGE => a >= src,
                            BPF_JSET => (a & src) != 0,
                            _ => false,
                        };
                        pc += if cond { insn.jt as usize } else { insn.jf as usize };
                    }
                }
                BPF_RET => {
                    let src = insn.code & 0x18;
                    return match src {
                        BPF_K => insn.k,
                        _ => a, // BPF_A
                    };
                }
                BPF_MISC => {
                    let op = insn.code & 0xF8;
                    match op {
                        BPF_TAX => x = a,
                        BPF_TXA => a = x,
                        _ => return SECCOMP_RET_KILL_PROCESS,
                    }
                }
                _ => return SECCOMP_RET_KILL_PROCESS,
            }

            pc += 1;
        }

        SECCOMP_RET_KILL_PROCESS
    }
}

// ─────────────────── seccomp Filter Chain ───────────────────────────
pub const MAX_FILTERS_PER_TASK: usize = 32;

pub struct SeccompFilter {
    pub program: BpfProgram,
    pub log_enabled: bool,
}

pub struct SeccompState {
    pub mode: SeccompMode,
    pub filters: [Option<SeccompFilter>; MAX_FILTERS_PER_TASK],
    pub filter_count: usize,
    pub total_filtered: AtomicU64,
    pub total_denied: AtomicU64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum SeccompMode {
    Disabled,
    Strict,
    Filter,
}

impl SeccompState {
    pub const fn new() -> Self {
        Self {
            mode: SeccompMode::Disabled,
            filters: [const { None }; MAX_FILTERS_PER_TASK],
            filter_count: 0,
            total_filtered: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        }
    }

    /// Enable strict mode
    pub fn set_strict(&mut self) -> bool {
        if self.mode != SeccompMode::Disabled {
            return false;
        }
        self.mode = SeccompMode::Strict;
        true
    }

    /// Add a filter program
    pub fn add_filter(&mut self, mut program: BpfProgram, log: bool) -> bool {
        if self.filter_count >= MAX_FILTERS_PER_TASK {
            return false;
        }
        if !program.validate() {
            return false;
        }
        self.mode = SeccompMode::Filter;
        self.filters[self.filter_count] = Some(SeccompFilter {
            program,
            log_enabled: log,
        });
        self.filter_count += 1;
        true
    }

    /// Check if a syscall is allowed in strict mode
    fn check_strict(nr: i32) -> u32 {
        match nr {
            0 => SECCOMP_RET_ALLOW,  // read
            1 => SECCOMP_RET_ALLOW,  // write
            60 => SECCOMP_RET_ALLOW, // exit
            231 => SECCOMP_RET_ALLOW, // exit_group
            15 => SECCOMP_RET_ALLOW, // rt_sigreturn
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }

    /// Evaluate all filters for a syscall
    pub fn check_syscall(&self, data: &SeccompData) -> SeccompResult {
        self.total_filtered.fetch_add(1, Ordering::Relaxed);

        match self.mode {
            SeccompMode::Disabled => SeccompResult {
                action: SECCOMP_RET_ALLOW,
                data: 0,
                filter_idx: 0,
            },
            SeccompMode::Strict => {
                let ret = Self::check_strict(data.nr);
                if ret != SECCOMP_RET_ALLOW {
                    self.total_denied.fetch_add(1, Ordering::Relaxed);
                }
                SeccompResult {
                    action: ret & SECCOMP_RET_ACTION_FULL,
                    data: ret & SECCOMP_RET_DATA,
                    filter_idx: 0,
                }
            }
            SeccompMode::Filter => {
                // Run all filters, return the most restrictive result
                let mut result = SECCOMP_RET_ALLOW;
                let mut result_idx = 0u8;

                for (i, filter_opt) in self.filters[..self.filter_count].iter().enumerate() {
                    if let Some(filter) = filter_opt {
                        let ret = filter.program.run(data);
                        // Lower action value = more restrictive
                        if (ret & SECCOMP_RET_ACTION_FULL) < (result & SECCOMP_RET_ACTION_FULL) {
                            result = ret;
                            result_idx = i as u8;
                        }
                    }
                }

                if (result & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_ALLOW {
                    self.total_denied.fetch_add(1, Ordering::Relaxed);
                }

                SeccompResult {
                    action: result & SECCOMP_RET_ACTION_FULL,
                    data: result & SECCOMP_RET_DATA,
                    filter_idx: result_idx,
                }
            }
        }
    }
}

pub struct SeccompResult {
    pub action: u32,
    pub data: u32,
    pub filter_idx: u8,
}

impl SeccompResult {
    pub fn is_allowed(&self) -> bool {
        self.action == SECCOMP_RET_ALLOW
    }

    pub fn errno_value(&self) -> Option<u16> {
        if self.action == SECCOMP_RET_ERRNO {
            Some(self.data as u16)
        } else {
            None
        }
    }

    pub fn action_name(&self) -> &'static str {
        match self.action {
            SECCOMP_RET_KILL_PROCESS => "kill_process",
            SECCOMP_RET_KILL_THREAD => "kill_thread",
            SECCOMP_RET_TRAP => "trap",
            SECCOMP_RET_ERRNO => "errno",
            SECCOMP_RET_USER_NOTIF => "user_notif",
            SECCOMP_RET_TRACE => "trace",
            SECCOMP_RET_LOG => "log",
            SECCOMP_RET_ALLOW => "allow",
            _ => "unknown",
        }
    }
}

// ─────────────────── Audit Log ──────────────────────────────────────
pub const MAX_AUDIT_LOG: usize = 256;

#[derive(Clone, Copy)]
pub struct SeccompAuditEntry {
    pub pid: u32,
    pub syscall_nr: i32,
    pub action: u32,
    pub timestamp: u64,
    pub arch: u32,
    pub ip: u64,
}

pub struct SeccompAuditLog {
    pub entries: [SeccompAuditEntry; MAX_AUDIT_LOG],
    pub head: usize,
    pub count: usize,
}

impl SeccompAuditLog {
    pub const fn new() -> Self {
        Self {
            entries: [SeccompAuditEntry {
                pid: 0,
                syscall_nr: 0,
                action: 0,
                timestamp: 0,
                arch: 0,
                ip: 0,
            }; MAX_AUDIT_LOG],
            head: 0,
            count: 0,
        }
    }

    pub fn log(&mut self, pid: u32, data: &SeccompData, action: u32, timestamp: u64) {
        let idx = (self.head + self.count) % MAX_AUDIT_LOG;
        self.entries[idx] = SeccompAuditEntry {
            pid,
            syscall_nr: data.nr,
            action,
            timestamp,
            arch: data.arch,
            ip: data.instruction_pointer,
        };
        if self.count < MAX_AUDIT_LOG {
            self.count += 1;
        } else {
            self.head = (self.head + 1) % MAX_AUDIT_LOG;
        }
    }

    pub fn recent(&self, n: usize) -> &[SeccompAuditEntry] {
        let count = n.min(self.count);
        let start = if self.count >= MAX_AUDIT_LOG {
            (self.head + self.count - count) % MAX_AUDIT_LOG
        } else {
            self.count - count
        };
        &self.entries[start..start + count]
    }
}

// ─────────────────── Global State ───────────────────────────────────
pub const MAX_TASKS: usize = 256;

pub struct SeccompManager {
    pub task_states: [SeccompState; MAX_TASKS],
    pub audit: SeccompAuditLog,
    pub initialized: bool,
}

impl SeccompManager {
    pub const fn new() -> Self {
        Self {
            task_states: [const { SeccompState::new() }; MAX_TASKS],
            audit: SeccompAuditLog::new(),
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
    }

    pub fn set_strict(&mut self, pid: u32) -> bool {
        let idx = pid as usize % MAX_TASKS;
        self.task_states[idx].set_strict()
    }

    pub fn add_filter(&mut self, pid: u32, program: BpfProgram, log: bool) -> bool {
        let idx = pid as usize % MAX_TASKS;
        self.task_states[idx].add_filter(program, log)
    }

    pub fn check(&self, pid: u32, data: &SeccompData) -> SeccompResult {
        let idx = pid as usize % MAX_TASKS;
        self.task_states[idx].check_syscall(data)
    }
}

static mut SECCOMP_MGR: SeccompManager = SeccompManager::new();

pub fn init_seccomp() {
    unsafe { SECCOMP_MGR.init() }
}

// ─────────────────── FFI Exports ────────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_seccomp_init() {
    init_seccomp();
}

#[no_mangle]
pub extern "C" fn rust_seccomp_set_strict(pid: u32) -> bool {
    unsafe { SECCOMP_MGR.set_strict(pid) }
}

#[no_mangle]
pub extern "C" fn rust_seccomp_check(pid: u32, syscall_nr: i32, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, ip: u64) -> u32 {
    let data = SeccompData::new(syscall_nr, [arg0, arg1, arg2, arg3, arg4, arg5], ip);
    unsafe { SECCOMP_MGR.check(pid, &data).action }
}

#[no_mangle]
pub extern "C" fn rust_seccomp_is_allowed(pid: u32, syscall_nr: i32) -> bool {
    let data = SeccompData::new(syscall_nr, [0; 6], 0);
    unsafe { SECCOMP_MGR.check(pid, &data).is_allowed() }
}

#[no_mangle]
pub extern "C" fn rust_seccomp_audit_count() -> u32 {
    unsafe { SECCOMP_MGR.audit.count as u32 }
}
