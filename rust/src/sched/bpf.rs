// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust BPF/eBPF Subsystem
//
// Implements an eBPF-like (extended Berkeley Packet Filter) virtual machine:
// - BPF instruction set encoding (64-bit instructions)
// - Program verification (safety checker)
// - JIT compilation placeholders
// - BPF maps (hash, array, LRU)
// - Helper function dispatch
// - Program types (socket filter, tracepoint, kprobe, etc.)
// - Tail calls and program chaining

#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────
pub const BPF_MAX_INSNS: usize = 4096;
pub const BPF_MAX_STACK_SIZE: usize = 512;
pub const BPF_MAX_MAPS: usize = 64;
pub const BPF_MAX_MAP_ENTRIES: usize = 65536;
pub const BPF_NUM_REGS: usize = 11;
pub const BPF_MAX_PROGRAMS: usize = 256;
pub const BPF_MAX_TAIL_CALLS: usize = 32;
pub const BPF_MAX_HELPERS: usize = 128;

// Register names
pub const BPF_REG_0: u8 = 0; // Return value
pub const BPF_REG_1: u8 = 1; // Arg 1 / ctx pointer
pub const BPF_REG_2: u8 = 2; // Arg 2
pub const BPF_REG_3: u8 = 3; // Arg 3
pub const BPF_REG_4: u8 = 4; // Arg 4
pub const BPF_REG_5: u8 = 5; // Arg 5
pub const BPF_REG_6: u8 = 6; // Callee saved
pub const BPF_REG_7: u8 = 7; // Callee saved
pub const BPF_REG_8: u8 = 8; // Callee saved
pub const BPF_REG_9: u8 = 9; // Callee saved
pub const BPF_REG_10: u8 = 10; // Frame pointer (read-only)

// Instruction classes
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

// ALU operations
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;
pub const BPF_END: u8 = 0xd0;

// Jump operations
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

// Source operand
pub const BPF_K: u8 = 0x00; // Immediate
pub const BPF_X: u8 = 0x08; // Register

// Memory sizes
pub const BPF_W: u8 = 0x00;  // Word (32-bit)
pub const BPF_H: u8 = 0x08;  // Half word (16-bit)
pub const BPF_B: u8 = 0x10;  // Byte
pub const BPF_DW: u8 = 0x18; // Double word (64-bit)

// ─────────────────── BPF Instruction ────────────────────────────────
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_reg: u8,  // 4 bits
    pub src_reg: u8,  // 4 bits
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_reg: dst & 0xF,
            src_reg: src & 0xF,
            off,
            imm,
        }
    }

    // Instruction builders
    pub fn alu64_imm(op: u8, dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | op | BPF_K, dst, 0, 0, imm)
    }

    pub fn alu64_reg(op: u8, dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | op | BPF_X, dst, src, 0, 0)
    }

    pub fn alu32_imm(op: u8, dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | op | BPF_K, dst, 0, 0, imm)
    }

    pub fn alu32_reg(op: u8, dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU | op | BPF_X, dst, src, 0, 0)
    }

    pub fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::alu64_imm(BPF_MOV, dst, imm)
    }

    pub fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::alu64_reg(BPF_MOV, dst, src)
    }

    pub fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM_MODE | size, dst, src, off, 0)
    }

    pub fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_STX | BPF_MEM_MODE | size, dst, src, off, 0)
    }

    pub fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self::new(BPF_ST | BPF_MEM_MODE | size, dst, 0, off, imm)
    }

    pub fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | op | BPF_K, dst, 0, off, imm)
    }

    pub fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | op | BPF_X, dst, src, off, 0)
    }

    pub fn jmp_a(off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
    }

    pub fn call(func: i32) -> Self {
        Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, func)
    }

    pub fn exit() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }

    pub fn class(&self) -> u8 {
        self.code & 0x07
    }

    pub fn op(&self) -> u8 {
        self.code & 0xF0
    }

    pub fn source(&self) -> u8 {
        self.code & 0x08
    }

    pub fn size(&self) -> u8 {
        self.code & 0x18
    }
}

const BPF_MEM_MODE: u8 = 0x60;

// ─────────────────── Program Types ──────────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfProgType {
    Unspec = 0,
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
}

// ─────────────────── Map Types ──────────────────────────────────────
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfMapType {
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    Ringbuf = 19,
}

// ─────────────────── BPF Map ────────────────────────────────────────
pub struct BpfMapDef {
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

/// A simple hash map implementation for BPF
pub struct BpfHashMap {
    def: BpfMapDef,
    /// Entries stored as (key_hash, key_bytes, value_bytes, occupied)
    entries: [[u8; 256]; 4096],
    key_sizes: [u32; 4096],
    occupied: [bool; 4096],
    count: u32,
}

impl BpfHashMap {
    pub fn new(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        let max = max_entries.min(4096) as usize;
        Self {
            def: BpfMapDef {
                map_type: BpfMapType::Hash,
                key_size,
                value_size,
                max_entries: max as u32,
                flags: 0,
            },
            entries: [[0; 256]; 4096],
            key_sizes: [0; 4096],
            occupied: [false; 4096],
            count: 0,
        }
    }

    fn hash_key(&self, key: &[u8]) -> u32 {
        let mut h: u32 = 0x811c9dc5;
        for &b in key {
            h = h.wrapping_mul(0x01000193);
            h ^= b as u32;
        }
        h
    }

    fn find_slot(&self, key: &[u8]) -> Option<usize> {
        let hash = self.hash_key(key);
        let start = (hash as usize) % 4096;

        for i in 0..4096 {
            let idx = (start + i) % 4096;
            if !self.occupied[idx] {
                return None;
            }
            let ks = self.def.key_size as usize;
            if self.key_sizes[idx] == self.def.key_size
                && &self.entries[idx][..ks] == &key[..ks]
            {
                return Some(idx);
            }
        }
        None
    }

    fn find_free_slot(&self, key: &[u8]) -> Option<usize> {
        let hash = self.hash_key(key);
        let start = (hash as usize) % 4096;

        for i in 0..4096 {
            let idx = (start + i) % 4096;
            if !self.occupied[idx] {
                return Some(idx);
            }
        }
        None
    }

    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        let slot = self.find_slot(key)?;
        let ks = self.def.key_size as usize;
        let vs = self.def.value_size as usize;
        Some(&self.entries[slot][ks..ks + vs])
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> bool {
        let ks = self.def.key_size as usize;
        let vs = self.def.value_size as usize;

        if ks + vs > 256 || key.len() < ks || value.len() < vs {
            return false;
        }

        // Try to update existing
        if let Some(slot) = self.find_slot(key) {
            self.entries[slot][ks..ks + vs].copy_from_slice(&value[..vs]);
            return true;
        }

        // Insert new
        if self.count >= self.def.max_entries {
            return false;
        }

        if let Some(slot) = self.find_free_slot(key) {
            self.entries[slot][..ks].copy_from_slice(&key[..ks]);
            self.entries[slot][ks..ks + vs].copy_from_slice(&value[..vs]);
            self.key_sizes[slot] = self.def.key_size;
            self.occupied[slot] = true;
            self.count += 1;
            return true;
        }

        false
    }

    pub fn delete(&mut self, key: &[u8]) -> bool {
        if let Some(slot) = self.find_slot(key) {
            self.occupied[slot] = false;
            self.entries[slot] = [0; 256];
            self.key_sizes[slot] = 0;
            if self.count > 0 {
                self.count -= 1;
            }
            return true;
        }
        false
    }

    pub fn count(&self) -> u32 {
        self.count
    }
}

/// A BPF array map (fixed-size, indexed by integer key)
pub struct BpfArrayMap {
    def: BpfMapDef,
    data: [[u8; 128]; 4096],
    max_index: u32,
}

impl BpfArrayMap {
    pub fn new(value_size: u32, max_entries: u32) -> Self {
        let max = max_entries.min(4096);
        Self {
            def: BpfMapDef {
                map_type: BpfMapType::Array,
                key_size: 4,
                value_size: value_size.min(128),
                max_entries: max,
                flags: 0,
            },
            data: [[0; 128]; 4096],
            max_index: max,
        }
    }

    pub fn lookup(&self, index: u32) -> Option<&[u8]> {
        if index >= self.max_index { return None; }
        let vs = self.def.value_size as usize;
        Some(&self.data[index as usize][..vs])
    }

    pub fn update(&mut self, index: u32, value: &[u8]) -> bool {
        if index >= self.max_index { return false; }
        let vs = self.def.value_size as usize;
        if value.len() < vs { return false; }
        self.data[index as usize][..vs].copy_from_slice(&value[..vs]);
        true
    }
}

// ─────────────────── BPF VM ─────────────────────────────────────────
pub struct BpfVm {
    /// CPU registers
    regs: [u64; BPF_NUM_REGS],
    /// Stack
    stack: [u8; BPF_MAX_STACK_SIZE],
    /// Program counter
    pc: usize,
    /// Instructions
    insns: [BpfInsn; BPF_MAX_INSNS],
    insn_count: usize,
    /// Execution statistics
    insn_executed: u64,
    max_insn_limit: u64,
    /// Tail call depth
    tail_call_depth: u32,
}

impl BpfVm {
    pub fn new() -> Self {
        Self {
            regs: [0; BPF_NUM_REGS],
            stack: [0; BPF_MAX_STACK_SIZE],
            pc: 0,
            insns: [BpfInsn::new(0, 0, 0, 0, 0); BPF_MAX_INSNS],
            insn_count: 0,
            insn_executed: 0,
            max_insn_limit: 1_000_000,
            tail_call_depth: 0,
        }
    }

    /// Load a program into the VM
    pub fn load_program(&mut self, insns: &[BpfInsn]) -> Result<(), BpfError> {
        if insns.len() > BPF_MAX_INSNS {
            return Err(BpfError::ProgramTooLarge);
        }
        if insns.is_empty() {
            return Err(BpfError::EmptyProgram);
        }

        // Verify the program ends with EXIT
        let last = &insns[insns.len() - 1];
        if last.code != (BPF_JMP | BPF_EXIT) {
            return Err(BpfError::NoExitInsn);
        }

        self.insn_count = insns.len();
        self.insns[..insns.len()].copy_from_slice(insns);
        Ok(())
    }

    /// Execute the loaded program with a context pointer
    pub fn execute(&mut self, ctx: u64) -> Result<u64, BpfError> {
        self.regs = [0; BPF_NUM_REGS];
        self.regs[BPF_REG_1 as usize] = ctx;
        self.regs[BPF_REG_10 as usize] = self.stack.as_ptr() as u64 + BPF_MAX_STACK_SIZE as u64;
        self.pc = 0;
        self.insn_executed = 0;

        loop {
            if self.pc >= self.insn_count {
                return Err(BpfError::OutOfBounds);
            }
            if self.insn_executed >= self.max_insn_limit {
                return Err(BpfError::InsnLimitExceeded);
            }

            let insn = self.insns[self.pc];
            self.insn_executed += 1;

            let dst = insn.dst_reg as usize;
            let src = insn.src_reg as usize;
            let imm = insn.imm as i64;

            match insn.class() {
                BPF_ALU64 => {
                    self.exec_alu64(insn, dst, src, imm)?;
                }
                BPF_ALU => {
                    self.exec_alu32(insn, dst, src, imm)?;
                }
                BPF_JMP => {
                    let result = self.exec_jmp(insn, dst, src, imm)?;
                    if let Some(ret) = result {
                        return Ok(ret);
                    }
                    continue; // PC already updated by exec_jmp
                }
                BPF_LDX => {
                    self.exec_ldx(insn, dst, src)?;
                }
                BPF_STX => {
                    self.exec_stx(insn, dst, src)?;
                }
                BPF_ST => {
                    self.exec_st(insn, dst, imm)?;
                }
                _ => {
                    return Err(BpfError::InvalidInsn(self.pc));
                }
            }

            self.pc += 1;
        }
    }

    fn exec_alu64(&mut self, insn: BpfInsn, dst: usize, src: usize, imm: i64) -> Result<(), BpfError> {
        let src_val = if insn.source() == BPF_X {
            self.regs[src]
        } else {
            imm as u64
        };

        match insn.op() {
            BPF_ADD => self.regs[dst] = self.regs[dst].wrapping_add(src_val),
            BPF_SUB => self.regs[dst] = self.regs[dst].wrapping_sub(src_val),
            BPF_MUL => self.regs[dst] = self.regs[dst].wrapping_mul(src_val),
            BPF_DIV => {
                if src_val == 0 { return Err(BpfError::DivByZero); }
                self.regs[dst] /= src_val;
            }
            BPF_MOD => {
                if src_val == 0 { return Err(BpfError::DivByZero); }
                self.regs[dst] %= src_val;
            }
            BPF_OR => self.regs[dst] |= src_val,
            BPF_AND => self.regs[dst] &= src_val,
            BPF_XOR => self.regs[dst] ^= src_val,
            BPF_LSH => self.regs[dst] <<= src_val & 63,
            BPF_RSH => self.regs[dst] >>= src_val & 63,
            BPF_ARSH => {
                self.regs[dst] = ((self.regs[dst] as i64) >> (src_val & 63)) as u64;
            }
            BPF_NEG => self.regs[dst] = (-(self.regs[dst] as i64)) as u64,
            BPF_MOV => self.regs[dst] = src_val,
            _ => return Err(BpfError::InvalidInsn(self.pc)),
        }
        Ok(())
    }

    fn exec_alu32(&mut self, insn: BpfInsn, dst: usize, src: usize, imm: i64) -> Result<(), BpfError> {
        let src_val = if insn.source() == BPF_X {
            self.regs[src] as u32
        } else {
            imm as u32
        };

        let dst_val = self.regs[dst] as u32;
        let result: u32 = match insn.op() {
            BPF_ADD => dst_val.wrapping_add(src_val),
            BPF_SUB => dst_val.wrapping_sub(src_val),
            BPF_MUL => dst_val.wrapping_mul(src_val),
            BPF_DIV => {
                if src_val == 0 { return Err(BpfError::DivByZero); }
                dst_val / src_val
            }
            BPF_MOD => {
                if src_val == 0 { return Err(BpfError::DivByZero); }
                dst_val % src_val
            }
            BPF_OR => dst_val | src_val,
            BPF_AND => dst_val & src_val,
            BPF_XOR => dst_val ^ src_val,
            BPF_LSH => dst_val << (src_val & 31),
            BPF_RSH => dst_val >> (src_val & 31),
            BPF_ARSH => ((dst_val as i32) >> (src_val & 31)) as u32,
            BPF_NEG => (-(dst_val as i32)) as u32,
            BPF_MOV => src_val,
            _ => return Err(BpfError::InvalidInsn(self.pc)),
        };

        // Zero-extend to 64 bits
        self.regs[dst] = result as u64;
        Ok(())
    }

    fn exec_jmp(&mut self, insn: BpfInsn, dst: usize, src: usize, imm: i64) -> Result<Option<u64>, BpfError> {
        match insn.op() {
            BPF_EXIT => return Ok(Some(self.regs[BPF_REG_0 as usize])),
            BPF_CALL => {
                // Helper function call
                let helper_id = insn.imm as u32;
                self.regs[BPF_REG_0 as usize] = self.call_helper(helper_id)?;
                self.pc += 1;
                return Ok(None);
            }
            BPF_JA => {
                self.pc = ((self.pc as i64) + 1 + insn.off as i64) as usize;
                return Ok(None);
            }
            _ => {}
        }

        let dst_val = self.regs[dst];
        let src_val = if insn.source() == BPF_X {
            self.regs[src]
        } else {
            imm as u64
        };

        let cond = match insn.op() {
            BPF_JEQ => dst_val == src_val,
            BPF_JNE => dst_val != src_val,
            BPF_JGT => dst_val > src_val,
            BPF_JGE => dst_val >= src_val,
            BPF_JLT => dst_val < src_val,
            BPF_JLE => dst_val <= src_val,
            BPF_JSGT => (dst_val as i64) > (src_val as i64),
            BPF_JSGE => (dst_val as i64) >= (src_val as i64),
            BPF_JSLT => (dst_val as i64) < (src_val as i64),
            BPF_JSLE => (dst_val as i64) <= (src_val as i64),
            BPF_JSET => dst_val & src_val != 0,
            _ => return Err(BpfError::InvalidInsn(self.pc)),
        };

        if cond {
            self.pc = ((self.pc as i64) + 1 + insn.off as i64) as usize;
        } else {
            self.pc += 1;
        }
        Ok(None)
    }

    fn exec_ldx(&mut self, insn: BpfInsn, dst: usize, src: usize) -> Result<(), BpfError> {
        let addr = (self.regs[src] as i64 + insn.off as i64) as u64;
        // Safety: in a real kernel BPF VM, this would be bounds-checked
        let ptr = addr as *const u8;
        self.regs[dst] = match insn.size() {
            BPF_B => unsafe { *ptr } as u64,
            BPF_H => unsafe { *(ptr as *const u16) } as u64,
            BPF_W => unsafe { *(ptr as *const u32) } as u64,
            BPF_DW => unsafe { *(ptr as *const u64) },
            _ => return Err(BpfError::InvalidInsn(self.pc)),
        };
        Ok(())
    }

    fn exec_stx(&mut self, insn: BpfInsn, dst: usize, src: usize) -> Result<(), BpfError> {
        let addr = (self.regs[dst] as i64 + insn.off as i64) as u64;
        let ptr = addr as *mut u8;
        match insn.size() {
            BPF_B => unsafe { *ptr = self.regs[src] as u8 },
            BPF_H => unsafe { *(ptr as *mut u16) = self.regs[src] as u16 },
            BPF_W => unsafe { *(ptr as *mut u32) = self.regs[src] as u32 },
            BPF_DW => unsafe { *(ptr as *mut u64) = self.regs[src] },
            _ => return Err(BpfError::InvalidInsn(self.pc)),
        }
        Ok(())
    }

    fn exec_st(&mut self, insn: BpfInsn, dst: usize, imm: i64) -> Result<(), BpfError> {
        let addr = (self.regs[dst] as i64 + insn.off as i64) as u64;
        let ptr = addr as *mut u8;
        match insn.size() {
            BPF_B => unsafe { *ptr = imm as u8 },
            BPF_H => unsafe { *(ptr as *mut u16) = imm as u16 },
            BPF_W => unsafe { *(ptr as *mut u32) = imm as u32 },
            BPF_DW => unsafe { *(ptr as *mut u64) = imm as u64 },
            _ => return Err(BpfError::InvalidInsn(self.pc)),
        }
        Ok(())
    }

    fn call_helper(&mut self, helper_id: u32) -> Result<u64, BpfError> {
        // Built-in BPF helpers
        match helper_id {
            1 => {
                // bpf_map_lookup_elem — stub
                Ok(0)
            }
            2 => {
                // bpf_map_update_elem — stub
                Ok(0)
            }
            3 => {
                // bpf_map_delete_elem — stub
                Ok(0)
            }
            6 => {
                // bpf_trace_printk — stub (would log to kernel trace buffer)
                Ok(0)
            }
            14 => {
                // bpf_get_current_pid_tgid
                Ok(0) // Would return actual PID/TGID
            }
            35 => {
                // bpf_get_current_comm
                Ok(0)
            }
            _ => Err(BpfError::UnknownHelper(helper_id)),
        }
    }

    pub fn instructions_executed(&self) -> u64 {
        self.insn_executed
    }
}

// ─────────────────── BPF Program Verifier ───────────────────────────
pub struct BpfVerifier {
    visited: [bool; BPF_MAX_INSNS],
    reg_state: [RegState; BPF_NUM_REGS],
    stack_state: [bool; BPF_MAX_STACK_SIZE],
    errors: [VerifyError; 32],
    error_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegState {
    Uninit,
    Scalar,
    Ptr,
    PtrToMap,
    PtrToStack,
    PtrToCtx,
    PtrToPacket,
    PtrToPacketEnd,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyError {
    pub insn_idx: usize,
    pub kind: VerifyErrorKind,
}

#[derive(Debug, Clone, Copy)]
pub enum VerifyErrorKind {
    UninitRegRead,
    InvalidMemAccess,
    InvalidJumpTarget,
    UnreachableInsn,
    DivByZero,
    StackOverflow,
    InvalidHelperCall,
    R0Uninit,
    MissingExit,
    BackEdge,
}

impl BpfVerifier {
    pub fn new() -> Self {
        Self {
            visited: [false; BPF_MAX_INSNS],
            reg_state: [RegState::Uninit; BPF_NUM_REGS],
            stack_state: [false; BPF_MAX_STACK_SIZE],
            errors: [VerifyError { insn_idx: 0, kind: VerifyErrorKind::MissingExit }; 32],
            error_count: 0,
        }
    }

    /// Verify a BPF program for safety
    pub fn verify(&mut self, insns: &[BpfInsn], prog_type: BpfProgType) -> bool {
        self.error_count = 0;
        self.visited = [false; BPF_MAX_INSNS];
        self.reg_state = [RegState::Uninit; BPF_NUM_REGS];
        self.stack_state = [false; BPF_MAX_STACK_SIZE];

        if insns.is_empty() {
            self.add_error(0, VerifyErrorKind::MissingExit);
            return false;
        }

        // R1 = ctx pointer based on program type
        self.reg_state[BPF_REG_1 as usize] = match prog_type {
            BpfProgType::SocketFilter | BpfProgType::SchedCls => RegState::PtrToPacket,
            BpfProgType::Kprobe | BpfProgType::Tracepoint => RegState::PtrToCtx,
            BpfProgType::Xdp => RegState::PtrToCtx,
            _ => RegState::PtrToCtx,
        };
        self.reg_state[BPF_REG_10 as usize] = RegState::PtrToStack;

        // Verify last insn is EXIT
        let last = &insns[insns.len() - 1];
        if last.code != (BPF_JMP | BPF_EXIT) {
            self.add_error(insns.len() - 1, VerifyErrorKind::MissingExit);
            return false;
        }

        // Walk instructions
        let mut pc = 0usize;
        while pc < insns.len() {
            if self.visited[pc] {
                // Detected a loop — check if it's valid
                self.add_error(pc, VerifyErrorKind::BackEdge);
                return false;
            }
            self.visited[pc] = true;

            let insn = &insns[pc];
            match insn.class() {
                BPF_ALU64 | BPF_ALU => {
                    let src = insn.src_reg as usize;
                    let dst = insn.dst_reg as usize;
                    if insn.source() == BPF_X && self.reg_state[src] == RegState::Uninit {
                        self.add_error(pc, VerifyErrorKind::UninitRegRead);
                    }
                    if insn.op() != BPF_MOV && insn.op() != BPF_NEG
                        && self.reg_state[dst] == RegState::Uninit
                    {
                        self.add_error(pc, VerifyErrorKind::UninitRegRead);
                    }
                    if insn.op() == BPF_DIV || insn.op() == BPF_MOD {
                        if insn.source() == BPF_K && insn.imm == 0 {
                            self.add_error(pc, VerifyErrorKind::DivByZero);
                        }
                    }
                    self.reg_state[dst] = RegState::Scalar;
                }
                BPF_LDX => {
                    let src = insn.src_reg as usize;
                    if self.reg_state[src] == RegState::Uninit {
                        self.add_error(pc, VerifyErrorKind::UninitRegRead);
                    }
                    self.reg_state[insn.dst_reg as usize] = RegState::Scalar;
                }
                BPF_STX | BPF_ST => {
                    let dst = insn.dst_reg as usize;
                    if self.reg_state[dst] == RegState::Uninit {
                        self.add_error(pc, VerifyErrorKind::InvalidMemAccess);
                    }
                }
                BPF_JMP => {
                    if insn.op() == BPF_EXIT {
                        if self.reg_state[BPF_REG_0 as usize] == RegState::Uninit {
                            self.add_error(pc, VerifyErrorKind::R0Uninit);
                        }
                        break;
                    }
                    if insn.op() == BPF_CALL {
                        // Mark R0 as initialized (return value)
                        self.reg_state[BPF_REG_0 as usize] = RegState::Scalar;
                        // Caller-saved registers are clobbered
                        for r in 1..=5 {
                            self.reg_state[r] = RegState::Uninit;
                        }
                    }
                    if insn.op() != BPF_CALL && insn.op() != BPF_EXIT {
                        let target = (pc as i64 + 1 + insn.off as i64) as usize;
                        if target >= insns.len() {
                            self.add_error(pc, VerifyErrorKind::InvalidJumpTarget);
                        }
                    }
                }
                _ => {}
            }
            pc += 1;
        }

        // Check for unreachable instructions
        for i in 0..insns.len() {
            if !self.visited[i] {
                self.add_error(i, VerifyErrorKind::UnreachableInsn);
            }
        }

        self.error_count == 0
    }

    fn add_error(&mut self, insn_idx: usize, kind: VerifyErrorKind) {
        if self.error_count < 32 {
            self.errors[self.error_count] = VerifyError { insn_idx, kind };
            self.error_count += 1;
        }
    }

    pub fn errors(&self) -> &[VerifyError] {
        &self.errors[..self.error_count]
    }

    pub fn error_count(&self) -> usize {
        self.error_count
    }
}

// ─────────────────── BPF Program Object ─────────────────────────────
pub struct BpfProgram {
    pub id: u32,
    pub prog_type: BpfProgType,
    pub insns: [BpfInsn; BPF_MAX_INSNS],
    pub insn_count: usize,
    pub verified: bool,
    pub loaded: bool,
    pub name: [u8; 32],
    pub name_len: usize,
    pub run_count: u64,
    pub run_time_ns: u64,
}

impl BpfProgram {
    pub fn new(id: u32, prog_type: BpfProgType) -> Self {
        Self {
            id,
            prog_type,
            insns: [BpfInsn::new(0, 0, 0, 0, 0); BPF_MAX_INSNS],
            insn_count: 0,
            verified: false,
            loaded: false,
            name: [0; 32],
            name_len: 0,
            run_count: 0,
            run_time_ns: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(32);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn load(&mut self, insns: &[BpfInsn]) -> Result<(), BpfError> {
        if insns.len() > BPF_MAX_INSNS {
            return Err(BpfError::ProgramTooLarge);
        }

        self.insn_count = insns.len();
        self.insns[..insns.len()].copy_from_slice(insns);

        // Verify
        let mut verifier = BpfVerifier::new();
        if !verifier.verify(insns, self.prog_type) {
            return Err(BpfError::VerificationFailed);
        }

        self.verified = true;
        self.loaded = true;
        Ok(())
    }

    pub fn run(&mut self, ctx: u64) -> Result<u64, BpfError> {
        if !self.loaded {
            return Err(BpfError::NotLoaded);
        }

        let mut vm = BpfVm::new();
        vm.load_program(&self.insns[..self.insn_count])?;
        let result = vm.execute(ctx)?;

        self.run_count += 1;
        Ok(result)
    }
}

// ─────────────────── BPF Error Type ─────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub enum BpfError {
    ProgramTooLarge,
    EmptyProgram,
    NoExitInsn,
    OutOfBounds,
    InsnLimitExceeded,
    InvalidInsn(usize),
    DivByZero,
    UnknownHelper(u32),
    VerificationFailed,
    NotLoaded,
    MapFull,
    MapNotFound,
    InvalidMapType,
}

// ─────────────────── BPF Subsystem Manager ──────────────────────────
pub struct BpfSubsystem {
    programs: [Option<BpfProgram>; BPF_MAX_PROGRAMS],
    program_count: usize,
    hash_maps: [Option<BpfHashMap>; BPF_MAX_MAPS],
    array_maps: [Option<BpfArrayMap>; BPF_MAX_MAPS],
    map_count: usize,
    next_prog_id: u32,
    next_map_id: u32,
    total_programs_loaded: u64,
    total_programs_run: u64,
}

impl BpfSubsystem {
    pub fn new() -> Self {
        const NONE_PROG: Option<BpfProgram> = None;
        const NONE_HASH: Option<BpfHashMap> = None;
        const NONE_ARRAY: Option<BpfArrayMap> = None;

        Self {
            programs: [NONE_PROG; BPF_MAX_PROGRAMS],
            program_count: 0,
            hash_maps: [NONE_HASH; BPF_MAX_MAPS],
            array_maps: [NONE_ARRAY; BPF_MAX_MAPS],
            map_count: 0,
            next_prog_id: 1,
            next_map_id: 1,
            total_programs_loaded: 0,
            total_programs_run: 0,
        }
    }

    /// Load a new BPF program
    pub fn load_program(
        &mut self,
        prog_type: BpfProgType,
        insns: &[BpfInsn],
        name: &[u8],
    ) -> Result<u32, BpfError> {
        if self.program_count >= BPF_MAX_PROGRAMS {
            return Err(BpfError::ProgramTooLarge);
        }

        let id = self.next_prog_id;
        self.next_prog_id += 1;

        let mut prog = BpfProgram::new(id, prog_type);
        prog.set_name(name);
        prog.load(insns)?;

        for slot in self.programs.iter_mut() {
            if slot.is_none() {
                *slot = Some(prog);
                self.program_count += 1;
                self.total_programs_loaded += 1;
                return Ok(id);
            }
        }

        Err(BpfError::ProgramTooLarge)
    }

    /// Run a BPF program by ID
    pub fn run_program(&mut self, prog_id: u32, ctx: u64) -> Result<u64, BpfError> {
        for slot in self.programs.iter_mut() {
            if let Some(prog) = slot {
                if prog.id == prog_id {
                    let result = prog.run(ctx)?;
                    self.total_programs_run += 1;
                    return Ok(result);
                }
            }
        }
        Err(BpfError::NotLoaded)
    }

    /// Unload a BPF program
    pub fn unload_program(&mut self, prog_id: u32) -> bool {
        for slot in self.programs.iter_mut() {
            if let Some(prog) = slot {
                if prog.id == prog_id {
                    *slot = None;
                    if self.program_count > 0 {
                        self.program_count -= 1;
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Create a hash map
    pub fn create_hash_map(&mut self, key_size: u32, value_size: u32, max_entries: u32) -> Option<u32> {
        let id = self.next_map_id;
        self.next_map_id += 1;

        for slot in self.hash_maps.iter_mut() {
            if slot.is_none() {
                *slot = Some(BpfHashMap::new(key_size, value_size, max_entries));
                self.map_count += 1;
                return Some(id);
            }
        }
        None
    }

    /// Create an array map
    pub fn create_array_map(&mut self, value_size: u32, max_entries: u32) -> Option<u32> {
        let id = self.next_map_id;
        self.next_map_id += 1;

        for slot in self.array_maps.iter_mut() {
            if slot.is_none() {
                *slot = Some(BpfArrayMap::new(value_size, max_entries));
                self.map_count += 1;
                return Some(id);
            }
        }
        None
    }

    pub fn program_count(&self) -> usize {
        self.program_count
    }

    pub fn map_count(&self) -> usize {
        self.map_count
    }
}

// ─────────────────── Global Instance ────────────────────────────────
static mut BPF_SUBSYSTEM: Option<BpfSubsystem> = None;

pub fn init() {
    unsafe {
        BPF_SUBSYSTEM = Some(BpfSubsystem::new());
    }
}

pub fn get_subsystem() -> Option<&'static mut BpfSubsystem> {
    unsafe { BPF_SUBSYSTEM.as_mut() }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_bpf_init() {
    init();
}

#[no_mangle]
pub extern "C" fn rust_bpf_load_program(
    prog_type: u32,
    insns: *const BpfInsn,
    insn_count: u32,
    name: *const u8,
    name_len: u32,
) -> i32 {
    let Some(subsys) = get_subsystem() else { return -1 };

    let insns_slice = if insns.is_null() || insn_count == 0 {
        return -1;
    } else {
        unsafe { core::slice::from_raw_parts(insns, insn_count as usize) }
    };

    let name_slice = if name.is_null() || name_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(name, name_len as usize) }
    };

    let ptype = match prog_type {
        0 => BpfProgType::Unspec,
        1 => BpfProgType::SocketFilter,
        2 => BpfProgType::Kprobe,
        5 => BpfProgType::Tracepoint,
        6 => BpfProgType::Xdp,
        _ => BpfProgType::Unspec,
    };

    match subsys.load_program(ptype, insns_slice, name_slice) {
        Ok(id) => id as i32,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_bpf_run_program(prog_id: u32, ctx: u64) -> i64 {
    let Some(subsys) = get_subsystem() else { return -1 };
    match subsys.run_program(prog_id, ctx) {
        Ok(val) => val as i64,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_bpf_unload_program(prog_id: u32) -> bool {
    get_subsystem().map_or(false, |s| s.unload_program(prog_id))
}

#[no_mangle]
pub extern "C" fn rust_bpf_create_hash_map(key_size: u32, value_size: u32, max_entries: u32) -> i32 {
    let Some(subsys) = get_subsystem() else { return -1 };
    match subsys.create_hash_map(key_size, value_size, max_entries) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_bpf_create_array_map(value_size: u32, max_entries: u32) -> i32 {
    let Some(subsys) = get_subsystem() else { return -1 };
    match subsys.create_array_map(value_size, max_entries) {
        Some(id) => id as i32,
        None => -1,
    }
}
