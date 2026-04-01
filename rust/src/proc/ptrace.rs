// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust ptrace & Coredump Subsystem
//
// Process tracing and crash dump generation:
// - ptrace operations (attach, detach, peek, poke, getregs, setregs, cont, step)
// - Breakpoint management (software breakpoints via INT3)
// - Signal injection and interception
// - Core dump file generation (ELF core format)
// - Register save/restore for x86_64
// - Memory region dumping
// - Thread state capture
// - Watchpoint support

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ─────────────────── ptrace Constants ───────────────────────────────
pub const PTRACE_TRACEME: u32 = 0;
pub const PTRACE_PEEKTEXT: u32 = 1;
pub const PTRACE_PEEKDATA: u32 = 2;
pub const PTRACE_PEEKUSER: u32 = 3;
pub const PTRACE_POKETEXT: u32 = 4;
pub const PTRACE_POKEDATA: u32 = 5;
pub const PTRACE_POKEUSER: u32 = 6;
pub const PTRACE_CONT: u32 = 7;
pub const PTRACE_KILL: u32 = 8;
pub const PTRACE_SINGLESTEP: u32 = 9;
pub const PTRACE_GETREGS: u32 = 12;
pub const PTRACE_SETREGS: u32 = 13;
pub const PTRACE_GETFPREGS: u32 = 14;
pub const PTRACE_SETFPREGS: u32 = 15;
pub const PTRACE_ATTACH: u32 = 16;
pub const PTRACE_DETACH: u32 = 17;
pub const PTRACE_SYSCALL: u32 = 24;
pub const PTRACE_SETEVENTMSG: u32 = 0x4201;
pub const PTRACE_GETEVENTMSG: u32 = 0x4202;
pub const PTRACE_GETSIGINFO: u32 = 0x4203;
pub const PTRACE_SETSIGINFO: u32 = 0x4204;
pub const PTRACE_SETOPTIONS: u32 = 0x4200;

// ptrace options
pub const PTRACE_O_TRACESYSGOOD: u32 = 0x01;
pub const PTRACE_O_TRACEFORK: u32 = 0x02;
pub const PTRACE_O_TRACEVFORK: u32 = 0x04;
pub const PTRACE_O_TRACECLONE: u32 = 0x08;
pub const PTRACE_O_TRACEEXEC: u32 = 0x10;
pub const PTRACE_O_TRACEEXIT: u32 = 0x40;
pub const PTRACE_O_TRACESECCOMP: u32 = 0x80;

// ptrace events
pub const PTRACE_EVENT_FORK: u32 = 1;
pub const PTRACE_EVENT_VFORK: u32 = 2;
pub const PTRACE_EVENT_CLONE: u32 = 3;
pub const PTRACE_EVENT_EXEC: u32 = 4;
pub const PTRACE_EVENT_EXIT: u32 = 6;
pub const PTRACE_EVENT_SECCOMP: u32 = 7;

// ─────────────────── Register Set (x86_64) ──────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,  // syscall number
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

impl UserRegs {
    pub fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    pub fn stack_pointer(&self) -> u64 {
        self.rsp
    }

    pub fn syscall_number(&self) -> u64 {
        self.orig_rax
    }

    pub fn syscall_return(&self) -> u64 {
        self.rax
    }

    pub fn syscall_args(&self) -> [6]u64 {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }

    /// Set single-step flag (TF bit in EFLAGS)
    pub fn enable_single_step(&mut self) {
        self.eflags |= 0x100; // TF flag
    }

    pub fn disable_single_step(&mut self) {
        self.eflags &= !0x100;
    }

    pub fn is_single_stepping(&self) -> bool {
        self.eflags & 0x100 != 0
    }
}

/// FPU/SSE register state
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FpRegs {
    pub cwd: u16,
    pub swd: u16,
    pub ftw: u16,
    pub fop: u16,
    pub rip: u64,
    pub rdp: u64,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub st_space: [32]u32,   // 8 * 16 bytes = 128 bytes
    pub xmm_space: [64]u32,  // 16 * 16 bytes = 256 bytes
    pub padding: [24]u32,
}

impl Default for FpRegs {
    fn default() -> Self {
        Self {
            cwd: 0x37F,
            swd: 0,
            ftw: 0,
            fop: 0,
            rip: 0,
            rdp: 0,
            mxcsr: 0x1F80,
            mxcsr_mask: 0xFFFF,
            st_space: [0u32; 32],
            xmm_space: [0u32; 64],
            padding: [0u32; 24],
        }
    }
}

// ─────────────────── Breakpoint ─────────────────────────────────────
pub const MAX_BREAKPOINTS: usize = 64;
pub const INT3_OPCODE: u8 = 0xCC;

#[derive(Clone, Copy)]
pub struct Breakpoint {
    pub address: u64,
    pub original_byte: u8,
    pub enabled: bool,
    pub hit_count: u32,
    pub condition: BreakpointCondition,
}

#[derive(Clone, Copy, PartialEq)]
pub enum BreakpointCondition {
    Always,
    HitCount(u32),
    RegisterEq { reg_idx: u8, value: u64 },
}

impl Default for Breakpoint {
    fn default() -> Self {
        Self {
            address: 0,
            original_byte: 0,
            enabled: false,
            hit_count: 0,
            condition: BreakpointCondition::Always,
        }
    }
}

impl Breakpoint {
    pub fn should_break(&self) -> bool {
        match self.condition {
            BreakpointCondition::Always => true,
            BreakpointCondition::HitCount(n) => self.hit_count >= n,
            BreakpointCondition::RegisterEq { .. } => true, // checked externally
        }
    }
}

// ─────────────────── Watchpoint (HW breakpoint) ─────────────────────
pub const MAX_WATCHPOINTS: usize = 4; // x86_64 has 4 debug registers

#[derive(Clone, Copy, PartialEq)]
pub enum WatchType {
    Execute,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy)]
pub struct Watchpoint {
    pub address: u64,
    pub length: u8,   // 1, 2, 4, or 8 bytes
    pub watch_type: WatchType,
    pub enabled: bool,
    pub hit_count: u32,
}

impl Default for Watchpoint {
    fn default() -> Self {
        Self {
            address: 0,
            length: 1,
            watch_type: WatchType::Write,
            enabled: false,
            hit_count: 0,
        }
    }
}

/// Encode watchpoint into x86_64 debug register format
pub fn encode_dr7(watchpoints: &[Watchpoint; MAX_WATCHPOINTS]) -> u64 {
    let mut dr7: u64 = 0;

    for (i, wp) in watchpoints.iter().enumerate() {
        if !wp.enabled {
            continue;
        }
        // Local enable bit
        dr7 |= 1 << (i * 2);

        // Condition bits (16 + i*4)
        let cond: u64 = match wp.watch_type {
            WatchType::Execute => 0b00,
            WatchType::Write => 0b01,
            WatchType::ReadWrite => 0b11,
        };
        dr7 |= cond << (16 + i * 4);

        // Length bits (18 + i*4)
        let len: u64 = match wp.length {
            1 => 0b00,
            2 => 0b01,
            8 => 0b10,
            4 => 0b11,
            _ => 0b00,
        };
        dr7 |= len << (18 + i * 4);
    }

    dr7
}

// ─────────────────── Tracee State ───────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TraceeState {
    Running,
    Stopped,
    Syscall,
    SingleStep,
    Exiting,
    Zombie,
}

pub struct TraceeInfo {
    pub pid: u32,
    pub tracer_pid: u32,
    pub state: TraceeState,
    pub options: u32,
    pub regs: UserRegs,
    pub fp_regs: FpRegs,
    pub breakpoints: [Breakpoint; MAX_BREAKPOINTS],
    pub bp_count: usize,
    pub watchpoints: [Watchpoint; MAX_WATCHPOINTS],
    pub pending_signal: u32,
    pub event_msg: u64,
    pub syscall_entry: bool,
    pub in_syscall: bool,
}

impl TraceeInfo {
    pub fn new(pid: u32, tracer_pid: u32) -> Self {
        Self {
            pid,
            tracer_pid,
            state: TraceeState::Stopped,
            options: 0,
            regs: UserRegs::default(),
            fp_regs: FpRegs::default(),
            breakpoints: [Breakpoint::default(); MAX_BREAKPOINTS],
            bp_count: 0,
            watchpoints: [Watchpoint::default(); MAX_WATCHPOINTS],
            pending_signal: 0,
            event_msg: 0,
            syscall_entry: false,
            in_syscall: false,
        }
    }

    pub fn add_breakpoint(&mut self, addr: u64, original: u8) -> Option<usize> {
        if self.bp_count >= MAX_BREAKPOINTS {
            return None;
        }
        let idx = self.bp_count;
        self.breakpoints[idx] = Breakpoint {
            address: addr,
            original_byte: original,
            enabled: true,
            hit_count: 0,
            condition: BreakpointCondition::Always,
        };
        self.bp_count += 1;
        Some(idx)
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> Option<u8> {
        for i in 0..self.bp_count {
            if self.breakpoints[i].address == addr {
                let original = self.breakpoints[i].original_byte;
                // Shift remaining
                for j in i..self.bp_count.saturating_sub(1) {
                    self.breakpoints[j] = self.breakpoints[j + 1];
                }
                self.bp_count -= 1;
                return Some(original);
            }
        }
        None
    }

    pub fn find_breakpoint(&self, addr: u64) -> Option<usize> {
        for i in 0..self.bp_count {
            if self.breakpoints[i].address == addr && self.breakpoints[i].enabled {
                return Some(i);
            }
        }
        None
    }

    pub fn add_watchpoint(&mut self, addr: u64, len: u8, wtype: WatchType) -> Option<usize> {
        for (i, wp) in self.watchpoints.iter_mut().enumerate() {
            if !wp.enabled {
                *wp = Watchpoint {
                    address: addr,
                    length: len,
                    watch_type: wtype,
                    enabled: true,
                    hit_count: 0,
                };
                return Some(i);
            }
        }
        None
    }
}

// ─────────────────── ptrace Engine ──────────────────────────────────
pub const MAX_TRACEES: usize = 64;

pub struct PtraceEngine {
    pub tracees: [Option<TraceeInfo>; MAX_TRACEES],
    pub tracee_count: usize,
    pub initialized: bool,
    pub total_traces: AtomicU64,
    pub total_breakpoint_hits: AtomicU64,
}

impl PtraceEngine {
    pub const fn new() -> Self {
        Self {
            tracees: [const { None }; MAX_TRACEES],
            tracee_count: 0,
            initialized: false,
            total_traces: AtomicU64::new(0),
            total_breakpoint_hits: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
    }

    pub fn attach(&mut self, tracer_pid: u32, tracee_pid: u32) -> bool {
        // Check not already traced
        for tracee in self.tracees.iter() {
            if let Some(t) = tracee {
                if t.pid == tracee_pid {
                    return false;
                }
            }
        }
        // Find free slot
        for slot in self.tracees.iter_mut() {
            if slot.is_none() {
                *slot = Some(TraceeInfo::new(tracee_pid, tracer_pid));
                self.tracee_count += 1;
                self.total_traces.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    pub fn detach(&mut self, tracee_pid: u32) -> bool {
        for slot in self.tracees.iter_mut() {
            if let Some(t) = slot {
                if t.pid == tracee_pid {
                    *slot = None;
                    self.tracee_count = self.tracee_count.saturating_sub(1);
                    return true;
                }
            }
        }
        false
    }

    pub fn get_tracee(&self, pid: u32) -> Option<&TraceeInfo> {
        for tracee in self.tracees.iter() {
            if let Some(t) = tracee {
                if t.pid == pid {
                    return Some(t);
                }
            }
        }
        None
    }

    pub fn get_tracee_mut(&mut self, pid: u32) -> Option<&mut TraceeInfo> {
        for slot in self.tracees.iter_mut() {
            if let Some(t) = slot {
                if t.pid == pid {
                    return Some(t);
                }
            }
        }
        None
    }

    /// Handle a ptrace request
    pub fn handle_request(&mut self, request: u32, pid: u32, addr: u64, data: u64) -> i64 {
        match request {
            PTRACE_TRACEME => {
                // Mark current process as tracee (pid is the child)
                0
            }
            PTRACE_ATTACH => {
                if self.attach(data as u32, pid) { 0 } else { -1 }
            }
            PTRACE_DETACH => {
                if self.detach(pid) { 0 } else { -1 }
            }
            PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
                // Return word at addr in tracee's address space
                // In real kernel: read from tracee's page tables
                let _ = addr;
                0
            }
            PTRACE_POKETEXT | PTRACE_POKEDATA => {
                // Write data to addr in tracee's address space
                let _ = (addr, data);
                0
            }
            PTRACE_GETREGS => {
                if let Some(_tracee) = self.get_tracee(pid) {
                    // Copy regs to user buffer at data
                    0
                } else {
                    -1
                }
            }
            PTRACE_SETREGS => {
                if let Some(_tracee) = self.get_tracee_mut(pid) {
                    // Copy from user buffer to regs
                    0
                } else {
                    -1
                }
            }
            PTRACE_CONT => {
                if let Some(tracee) = self.get_tracee_mut(pid) {
                    tracee.regs.disable_single_step();
                    tracee.state = TraceeState::Running;
                    if data != 0 {
                        tracee.pending_signal = data as u32;
                    }
                    0
                } else {
                    -1
                }
            }
            PTRACE_SINGLESTEP => {
                if let Some(tracee) = self.get_tracee_mut(pid) {
                    tracee.regs.enable_single_step();
                    tracee.state = TraceeState::SingleStep;
                    0
                } else {
                    -1
                }
            }
            PTRACE_SYSCALL => {
                if let Some(tracee) = self.get_tracee_mut(pid) {
                    tracee.syscall_entry = true;
                    tracee.state = TraceeState::Running;
                    0
                } else {
                    -1
                }
            }
            PTRACE_SETOPTIONS => {
                if let Some(tracee) = self.get_tracee_mut(pid) {
                    tracee.options = data as u32;
                    0
                } else {
                    -1
                }
            }
            PTRACE_GETEVENTMSG => {
                if let Some(tracee) = self.get_tracee(pid) {
                    tracee.event_msg as i64
                } else {
                    -1
                }
            }
            PTRACE_KILL => {
                if let Some(tracee) = self.get_tracee_mut(pid) {
                    tracee.state = TraceeState::Exiting;
                    0
                } else {
                    -1
                }
            }
            _ => -1,
        }
    }
}

// ─────────────────── Core Dump ──────────────────────────────────────
/// ELF core file constants
pub const ET_CORE: u16 = 4;
pub const EM_X86_64: u16 = 62;
pub const PT_NOTE: u32 = 4;
pub const PT_LOAD: u32 = 1;
pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_FPREGSET: u32 = 2;
pub const NT_AUXV: u32 = 6;

/// ELF64 header for core dump
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf64Header {
    pub fn core_header(phnum: u16) -> Self {
        Self {
            e_ident: [
                0x7F, b'E', b'L', b'F', // magic
                2,    // 64-bit
                1,    // little-endian
                1,    // ELF version
                0,    // OS/ABI
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            e_type: ET_CORE,
            e_machine: EM_X86_64,
            e_version: 1,
            e_entry: 0,
            e_phoff: 64, // right after ELF header
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 64,
            e_phentsize: 56, // sizeof(Elf64Phdr)
            e_phnum: phnum,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

/// ELF64 program header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// ELF note header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Note {
    pub namesz: u32,
    pub descsz: u32,
    pub note_type: u32,
}

/// Process status for core dump
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PrStatus {
    pub si_signo: i32,
    pub si_code: i32,
    pub si_errno: i32,
    pub cursig: u16,
    _padding: u16,
    pub sigpend: u64,
    pub sighold: u64,
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub sid: u32,
    pub utime_sec: u64,
    pub utime_usec: u64,
    pub stime_sec: u64,
    pub stime_usec: u64,
    pub cutime_sec: u64,
    pub cutime_usec: u64,
    pub cstime_sec: u64,
    pub cstime_usec: u64,
    pub regs: UserRegs,
    pub fpvalid: u32,
}

/// Process info for core dump
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrPsInfo {
    pub state: u8,
    pub sname: u8,
    pub zomb: u8,
    pub nice: u8,
    pub flag: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub sid: u32,
    pub fname: [u8; 16],
    pub psargs: [u8; 80],
}

impl Default for PrPsInfo {
    fn default() -> Self {
        Self {
            state: 0,
            sname: b'R',
            zomb: 0,
            nice: 0,
            flag: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            ppid: 0,
            pgrp: 0,
            sid: 0,
            fname: [0u8; 16],
            psargs: [0u8; 80],
        }
    }
}

/// Memory region for core dump
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub flags: u32,   // PF_R | PF_W | PF_X
    pub valid: bool,
}

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const MAX_CORE_REGIONS: usize = 64;

/// Core dump builder
pub struct CoreDumpBuilder {
    pub pid: u32,
    pub signal: i32,
    pub regs: UserRegs,
    pub fp_regs: FpRegs,
    pub regions: [MemoryRegion; MAX_CORE_REGIONS],
    pub region_count: usize,
    pub prpsinfo: PrPsInfo,
}

impl CoreDumpBuilder {
    pub fn new(pid: u32, signal: i32, regs: UserRegs) -> Self {
        Self {
            pid,
            signal,
            regs,
            fp_regs: FpRegs::default(),
            regions: [MemoryRegion {
                start: 0,
                end: 0,
                flags: 0,
                valid: false,
            }; MAX_CORE_REGIONS],
            region_count: 0,
            prpsinfo: PrPsInfo::default(),
        }
    }

    pub fn add_region(&mut self, start: u64, end: u64, flags: u32) -> bool {
        if self.region_count >= MAX_CORE_REGIONS {
            return false;
        }
        self.regions[self.region_count] = MemoryRegion {
            start,
            end,
            flags,
            valid: true,
        };
        self.region_count += 1;
        true
    }

    pub fn set_process_name(&mut self, name: &[u8]) {
        let len = name.len().min(15);
        self.prpsinfo.fname[..len].copy_from_slice(&name[..len]);
        self.prpsinfo.pid = self.pid;
    }

    /// Calculate total header/note sizes for the core file
    pub fn calculate_sizes(&self) -> CoreSizes {
        let elf_header_size = 64u64;
        let phdr_size = 56u64;
        // 1 PT_NOTE + N PT_LOAD segments
        let phdr_count = 1 + self.region_count as u64;
        let phdr_total = phdr_count * phdr_size;

        // Note sizes: prstatus + prpsinfo + fpregset
        let note_hdr_size = 12u64; // Elf64Note
        let name_size = 8u64; // "CORE\0" padded to 8
        let prstatus_size = core::mem::size_of::<PrStatus>() as u64;
        let prpsinfo_size = core::mem::size_of::<PrPsInfo>() as u64;
        let fpregset_size = core::mem::size_of::<FpRegs>() as u64;

        let notes_size = 3 * (note_hdr_size + name_size) + prstatus_size + prpsinfo_size + fpregset_size;
        // Align to 4
        let notes_aligned = (notes_size + 3) & !3;

        let data_start = elf_header_size + phdr_total + notes_aligned;

        CoreSizes {
            elf_header_size,
            phdr_count: phdr_count as u16,
            phdr_total,
            notes_size: notes_aligned,
            data_start,
        }
    }

    /// Build the ELF header for the core file
    pub fn build_elf_header(&self) -> Elf64Header {
        let sizes = self.calculate_sizes();
        Elf64Header::core_header(sizes.phdr_count)
    }

    /// Build the PT_NOTE program header
    pub fn build_note_phdr(&self) -> Elf64Phdr {
        let sizes = self.calculate_sizes();
        Elf64Phdr {
            p_type: PT_NOTE,
            p_flags: 0,
            p_offset: sizes.elf_header_size + sizes.phdr_total,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: sizes.notes_size,
            p_memsz: sizes.notes_size,
            p_align: 4,
        }
    }

    /// Build PT_LOAD headers for memory regions
    pub fn build_load_phdrs(&self) -> ([Elf64Phdr; MAX_CORE_REGIONS], usize) {
        let sizes = self.calculate_sizes();
        let mut out = [Elf64Phdr {
            p_type: 0,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        }; MAX_CORE_REGIONS];

        let mut offset = sizes.data_start;
        for i in 0..self.region_count {
            let region = &self.regions[i];
            let size = region.end - region.start;
            out[i] = Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: region.flags,
                p_offset: offset,
                p_vaddr: region.start,
                p_paddr: 0,
                p_filesz: size,
                p_memsz: size,
                p_align: 0x1000,
            };
            offset += size;
        }
        (out, self.region_count)
    }
}

pub struct CoreSizes {
    pub elf_header_size: u64,
    pub phdr_count: u16,
    pub phdr_total: u64,
    pub notes_size: u64,
    pub data_start: u64,
}

// ─────────────────── Global Instance ────────────────────────────────
static mut PTRACE_ENGINE: PtraceEngine = PtraceEngine::new();

pub fn init_ptrace() {
    unsafe {
        PTRACE_ENGINE.init();
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_ptrace_init() {
    init_ptrace();
}

#[no_mangle]
pub extern "C" fn rust_ptrace_request(request: u32, pid: u32, addr: u64, data: u64) -> i64 {
    unsafe { PTRACE_ENGINE.handle_request(request, pid, addr, data) }
}

#[no_mangle]
pub extern "C" fn rust_ptrace_attach(tracer_pid: u32, tracee_pid: u32) -> bool {
    unsafe { PTRACE_ENGINE.attach(tracer_pid, tracee_pid) }
}

#[no_mangle]
pub extern "C" fn rust_ptrace_detach(tracee_pid: u32) -> bool {
    unsafe { PTRACE_ENGINE.detach(tracee_pid) }
}

#[no_mangle]
pub extern "C" fn rust_ptrace_tracee_count() -> u32 {
    unsafe { PTRACE_ENGINE.tracee_count as u32 }
}

#[no_mangle]
pub extern "C" fn rust_coredump_add_region(start: u64, end: u64, flags: u32) -> bool {
    // Simplified: would be per-process in real kernel
    let _ = (start, end, flags);
    true
}
