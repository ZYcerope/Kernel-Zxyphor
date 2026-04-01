// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Kernel Module Loader Framework (Rust)
//
// Dynamic kernel module management:
// - Module binary format (ELF section parsing for .ko equivalent)
// - Symbol resolution and relocation
// - Module dependency tracking
// - Module parameter parsing
// - Module load/unload lifecycle
// - Module versioning (modversions)
// - Sysfs attribute export for loaded modules
// - Module signing verification stub
// - Module reference counting
// - Module init/exit function dispatch

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

/// Maximum loaded modules
const MAX_MODULES: usize = 128;
/// Maximum symbols per module
const MAX_SYMBOLS_PER_MOD: usize = 64;
/// Maximum dependencies per module
const MAX_DEPS: usize = 16;
/// Maximum parameters per module
const MAX_PARAMS: usize = 16;
/// Global symbol table size
const GLOBAL_SYMTAB_SIZE: usize = 1024;

// ─────────────────── Module States ──────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ModuleState {
    Unloaded = 0,
    Loading = 1,
    Live = 2,
    Unloading = 3,
    Failed = 4,
}

impl ModuleState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unloaded => "unloaded",
            Self::Loading => "loading",
            Self::Live => "live",
            Self::Unloading => "unloading",
            Self::Failed => "failed",
        }
    }
}

// ─────────────────── Module Symbol ──────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleSymbol {
    pub name: [u8; 64],
    pub name_len: u8,
    pub addr: u64,
    /// CRC for version checking (modversions)
    pub crc: u32,
    /// Symbol type
    pub sym_type: SymbolType,
    /// Owning module ID (0xFFFF = kernel core)
    pub owner_id: u16,
    pub exported: bool,
    pub valid: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SymbolType {
    Function = 0,
    Data = 1,
    ReadOnly = 2,
    Bss = 3,
    PerCpu = 4,
}

impl ModuleSymbol {
    pub const EMPTY: Self = Self {
        name: [0u8; 64],
        name_len: 0,
        addr: 0,
        crc: 0,
        sym_type: SymbolType::Function,
        owner_id: 0xFFFF,
        exported: false,
        valid: false,
    };

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(63);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn name_matches(&self, n: &[u8]) -> bool {
        if n.len() != self.name_len as usize { return false; }
        &self.name[..self.name_len as usize] == n
    }

    /// Simple CRC32 for symbol versioning
    pub fn compute_crc(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }
}

// ─────────────────── Module Parameter ───────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ParamType {
    Bool = 0,
    Int = 1,
    UInt = 2,
    String = 3,
    IntArray = 4,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleParam {
    pub name: [u8; 32],
    pub name_len: u8,
    pub param_type: ParamType,
    pub description: [u8; 64],
    pub desc_len: u8,
    /// Current value (stored as bytes)
    pub value_int: i64,
    pub value_str: [u8; 64],
    pub value_str_len: u8,
    pub value_bool: bool,
    /// Permissions for sysfs exposure
    pub perm: u16,   // e.g., 0644
    pub valid: bool,
}

impl ModuleParam {
    pub const EMPTY: Self = Self {
        name: [0u8; 32],
        name_len: 0,
        param_type: ParamType::Int,
        description: [0u8; 64],
        desc_len: 0,
        value_int: 0,
        value_str: [0u8; 64],
        value_str_len: 0,
        value_bool: false,
        perm: 0o644,
        valid: false,
    };

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(31);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn set_description(&mut self, d: &[u8]) {
        let len = d.len().min(63);
        self.description[..len].copy_from_slice(&d[..len]);
        self.desc_len = len as u8;
    }

    /// Parse value from string
    pub fn parse_value(&mut self, val: &[u8]) -> bool {
        match self.param_type {
            ParamType::Bool => {
                if val == b"1" || val == b"Y" || val == b"y" || val == b"true" {
                    self.value_bool = true;
                } else if val == b"0" || val == b"N" || val == b"n" || val == b"false" {
                    self.value_bool = false;
                } else {
                    return false;
                }
                true
            }
            ParamType::Int => {
                if let Some(v) = parse_int(val) {
                    self.value_int = v;
                    true
                } else {
                    false
                }
            }
            ParamType::UInt => {
                if let Some(v) = parse_int(val) {
                    if v < 0 { return false; }
                    self.value_int = v;
                    true
                } else {
                    false
                }
            }
            ParamType::String => {
                let len = val.len().min(63);
                self.value_str[..len].copy_from_slice(&val[..len]);
                self.value_str_len = len as u8;
                true
            }
            ParamType::IntArray => {
                // Store first value
                if let Some(v) = parse_int(val) {
                    self.value_int = v;
                    true
                } else {
                    false
                }
            }
        }
    }
}

fn parse_int(data: &[u8]) -> Option<i64> {
    if data.is_empty() { return None; }
    let mut val: i64 = 0;
    let mut neg = false;
    let start = if data[0] == b'-' { neg = true; 1 } else { 0 };
    for &b in &data[start..] {
        if b < b'0' || b > b'9' { return None; }
        val = val.checked_mul(10)?.checked_add((b - b'0') as i64)?;
    }
    if neg { val = -val; }
    Some(val)
}

// ─────────────────── ELF Section Info ───────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SectionType {
    Text = 0,      // .text (code)
    Data = 1,      // .data
    Rodata = 2,    // .rodata
    Bss = 3,       // .bss
    Symtab = 4,    // symbol table
    Strtab = 5,    // string table
    Rela = 6,      // relocations
    ModInfo = 7,   // .modinfo
    InitText = 8,  // .init.text
    ExitText = 9,  // .exit.text
    Other = 255,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionInfo {
    pub section_type: SectionType,
    pub vaddr: u64,
    pub size: u64,
    pub align: u32,
    pub flags: u32,
    pub valid: bool,
}

impl SectionInfo {
    pub const EMPTY: Self = Self {
        section_type: SectionType::Other,
        vaddr: 0,
        size: 0,
        align: 0,
        flags: 0,
        valid: false,
    };
}

// ─────────────────── Relocation Entry ───────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum RelocType {
    R_X86_64_NONE = 0,
    R_X86_64_64 = 1,
    R_X86_64_PC32 = 2,
    R_X86_64_GOT32 = 3,
    R_X86_64_PLT32 = 4,
    R_X86_64_32 = 10,
    R_X86_64_32S = 11,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RelocEntry {
    pub offset: u64,
    pub reloc_type: RelocType,
    pub symbol_name: [u8; 64],
    pub symbol_len: u8,
    pub addend: i64,
    pub resolved: bool,
}

impl RelocEntry {
    pub const EMPTY: Self = Self {
        offset: 0,
        reloc_type: RelocType::R_X86_64_NONE,
        symbol_name: [0u8; 64],
        symbol_len: 0,
        addend: 0,
        resolved: false,
    };
}

// ─────────────────── Module Descriptor ──────────────────────────────

const MAX_SECTIONS: usize = 16;
const MAX_RELOCS: usize = 128;

#[repr(C)]
pub struct KernelModule {
    pub name: [u8; 64],
    pub name_len: u8,
    pub version: [u8; 32],
    pub version_len: u8,
    pub author: [u8; 64],
    pub author_len: u8,
    pub description: [u8; 128],
    pub desc_len: u8,
    pub license: [u8; 32],
    pub license_len: u8,
    /// State
    pub state: ModuleState,
    /// Memory layout
    pub core_addr: u64,      // base address of loaded module
    pub core_size: u64,      // total size
    pub init_addr: u64,      // init section address
    pub init_size: u64,
    /// Sections
    pub sections: [SectionInfo; MAX_SECTIONS],
    pub section_count: u8,
    /// Symbols exported by this module
    pub symbols: [ModuleSymbol; MAX_SYMBOLS_PER_MOD],
    pub symbol_count: u16,
    /// Parameters
    pub params: [ModuleParam; MAX_PARAMS],
    pub param_count: u8,
    /// Dependencies (module IDs)
    pub deps: [u16; MAX_DEPS],
    pub dep_count: u8,
    /// Reference count
    pub refcount: AtomicU32,
    /// Relocations pending
    pub relocs: [RelocEntry; MAX_RELOCS],
    pub reloc_count: u16,
    /// Signing
    pub signed: bool,
    pub sig_verified: bool,
    /// Timestamps
    pub load_time: u64,
    pub id: u16,
    pub active: bool,
}

impl KernelModule {
    pub fn new(id: u16) -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            version: [0u8; 32],
            version_len: 0,
            author: [0u8; 64],
            author_len: 0,
            description: [0u8; 128],
            desc_len: 0,
            license: [0u8; 32],
            license_len: 0,
            state: ModuleState::Unloaded,
            core_addr: 0,
            core_size: 0,
            init_addr: 0,
            init_size: 0,
            sections: [SectionInfo::EMPTY; MAX_SECTIONS],
            section_count: 0,
            symbols: [ModuleSymbol::EMPTY; MAX_SYMBOLS_PER_MOD],
            symbol_count: 0,
            params: [ModuleParam::EMPTY; MAX_PARAMS],
            param_count: 0,
            deps: [0xFFFF; MAX_DEPS],
            dep_count: 0,
            refcount: AtomicU32::new(0),
            relocs: [RelocEntry::EMPTY; MAX_RELOCS],
            reloc_count: 0,
            signed: false,
            sig_verified: false,
            load_time: 0,
            id,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(63);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn set_version(&mut self, v: &[u8]) {
        let len = v.len().min(31);
        self.version[..len].copy_from_slice(&v[..len]);
        self.version_len = len as u8;
    }

    pub fn set_license(&mut self, l: &[u8]) {
        let len = l.len().min(31);
        self.license[..len].copy_from_slice(&l[..len]);
        self.license_len = len as u8;
    }

    pub fn add_symbol(&mut self, sym: ModuleSymbol) -> bool {
        if self.symbol_count as usize >= MAX_SYMBOLS_PER_MOD { return false; }
        let mut s = sym;
        s.owner_id = self.id;
        s.valid = true;
        self.symbols[self.symbol_count as usize] = s;
        self.symbol_count += 1;
        true
    }

    pub fn add_param(&mut self, param: ModuleParam) -> bool {
        if self.param_count as usize >= MAX_PARAMS { return false; }
        let mut p = param;
        p.valid = true;
        self.params[self.param_count as usize] = p;
        self.param_count += 1;
        true
    }

    pub fn add_dependency(&mut self, dep_id: u16) -> bool {
        if self.dep_count as usize >= MAX_DEPS { return false; }
        self.deps[self.dep_count as usize] = dep_id;
        self.dep_count += 1;
        true
    }

    pub fn get_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    pub fn put_ref(&self) {
        let prev = self.refcount.load(Ordering::Relaxed);
        if prev > 0 {
            self.refcount.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn can_unload(&self) -> bool {
        self.refcount.load(Ordering::Relaxed) == 0
            && self.state == ModuleState::Live
    }

    pub fn is_gpl_compatible(&self) -> bool {
        let lic = &self.license[..self.license_len as usize];
        lic == b"GPL" || lic == b"GPL v2" || lic == b"MIT" || lic == b"Dual MIT/GPL"
    }
}

// ─────────────────── Module Loader ──────────────────────────────────

pub struct ModuleLoader {
    pub modules: [KernelModule; MAX_MODULES],
    pub module_count: u16,
    pub next_id: u16,
    /// Global symbol table
    pub global_syms: [ModuleSymbol; GLOBAL_SYMTAB_SIZE],
    pub global_sym_count: u32,
    /// Stats
    pub total_loaded: AtomicU64,
    pub total_unloaded: AtomicU64,
    pub load_failures: AtomicU32,
    /// Config
    pub require_signatures: AtomicBool,
    pub force_load: AtomicBool,     // skip version check
    /// Time counter
    pub time_counter: AtomicU64,
    pub initialized: AtomicBool,
}

impl ModuleLoader {
    pub fn new() -> Self {
        let mut loader = Self {
            modules: unsafe { core::mem::zeroed() },
            module_count: 0,
            next_id: 0,
            global_syms: [ModuleSymbol::EMPTY; GLOBAL_SYMTAB_SIZE],
            global_sym_count: 0,
            total_loaded: AtomicU64::new(0),
            total_unloaded: AtomicU64::new(0),
            load_failures: AtomicU32::new(0),
            require_signatures: AtomicBool::new(false),
            force_load: AtomicBool::new(false),
            time_counter: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        };
        // Initialize module IDs
        for i in 0..MAX_MODULES {
            loader.modules[i] = KernelModule::new(i as u16);
        }
        loader
    }

    pub fn init(&mut self) {
        // Register core kernel symbols
        self.register_kernel_symbol(b"printk", 0xFFFFFFFF80000100, SymbolType::Function);
        self.register_kernel_symbol(b"kmalloc", 0xFFFFFFFF80000200, SymbolType::Function);
        self.register_kernel_symbol(b"kfree", 0xFFFFFFFF80000300, SymbolType::Function);
        self.register_kernel_symbol(b"register_device", 0xFFFFFFFF80000400, SymbolType::Function);
        self.register_kernel_symbol(b"unregister_device", 0xFFFFFFFF80000500, SymbolType::Function);
        self.register_kernel_symbol(b"schedule", 0xFFFFFFFF80000600, SymbolType::Function);
        self.register_kernel_symbol(b"mutex_lock", 0xFFFFFFFF80000700, SymbolType::Function);
        self.register_kernel_symbol(b"mutex_unlock", 0xFFFFFFFF80000800, SymbolType::Function);
        self.register_kernel_symbol(b"alloc_pages", 0xFFFFFFFF80000900, SymbolType::Function);
        self.register_kernel_symbol(b"free_pages", 0xFFFFFFFF80000A00, SymbolType::Function);
        self.register_kernel_symbol(b"jiffies", 0xFFFFFFFF80001000, SymbolType::Data);
        self.register_kernel_symbol(b"nr_cpu_ids", 0xFFFFFFFF80001008, SymbolType::ReadOnly);

        self.initialized.store(true, Ordering::Release);
    }

    fn register_kernel_symbol(&mut self, name: &[u8], addr: u64, sym_type: SymbolType) {
        if self.global_sym_count as usize >= GLOBAL_SYMTAB_SIZE { return; }
        let idx = self.global_sym_count as usize;
        self.global_syms[idx] = ModuleSymbol::EMPTY;
        self.global_syms[idx].set_name(name);
        self.global_syms[idx].addr = addr;
        self.global_syms[idx].sym_type = sym_type;
        self.global_syms[idx].crc = ModuleSymbol::compute_crc(name);
        self.global_syms[idx].owner_id = 0xFFFF; // kernel
        self.global_syms[idx].exported = true;
        self.global_syms[idx].valid = true;
        self.global_sym_count += 1;
    }

    /// Load a module
    pub fn load_module(&mut self, name: &[u8], base_addr: u64, size: u64) -> Option<u16> {
        if self.module_count as usize >= MAX_MODULES {
            self.load_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Check for duplicate
        for i in 0..self.module_count as usize {
            if self.modules[i].active && self.modules[i].name_len == name.len() as u8 {
                if &self.modules[i].name[..name.len()] == name {
                    return None; // Already loaded
                }
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        let idx = self.module_count as usize;

        self.modules[idx] = KernelModule::new(id);
        self.modules[idx].set_name(name);
        self.modules[idx].core_addr = base_addr;
        self.modules[idx].core_size = size;
        self.modules[idx].state = ModuleState::Loading;
        self.modules[idx].active = true;
        self.modules[idx].load_time = self.time_counter.fetch_add(1, Ordering::Relaxed);

        self.module_count += 1;

        // Signature check
        if self.require_signatures.load(Ordering::Relaxed) && !self.modules[idx].signed {
            self.modules[idx].state = ModuleState::Failed;
            self.load_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Resolve symbols
        if !self.resolve_symbols(idx) && !self.force_load.load(Ordering::Relaxed) {
            self.modules[idx].state = ModuleState::Failed;
            self.load_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Apply relocations
        self.apply_relocations(idx);

        // Mark as live
        self.modules[idx].state = ModuleState::Live;

        // Export module's symbols to global table
        self.export_module_symbols(idx);

        self.total_loaded.fetch_add(1, Ordering::Relaxed);
        Some(id)
    }

    fn resolve_symbols(&mut self, mod_idx: usize) -> bool {
        let reloc_count = self.modules[mod_idx].reloc_count as usize;
        let mut all_resolved = true;

        for r in 0..reloc_count {
            let sym_name = &self.modules[mod_idx].relocs[r].symbol_name;
            let sym_len = self.modules[mod_idx].relocs[r].symbol_len;

            // Search global symbol table
            let mut found = false;
            for s in 0..self.global_sym_count as usize {
                if self.global_syms[s].valid
                    && self.global_syms[s].exported
                    && self.global_syms[s].name_matches(&sym_name[..sym_len as usize])
                {
                    self.modules[mod_idx].relocs[r].resolved = true;
                    found = true;
                    break;
                }
            }

            if !found {
                all_resolved = false;
            }
        }

        all_resolved
    }

    fn apply_relocations(&mut self, mod_idx: usize) {
        let reloc_count = self.modules[mod_idx].reloc_count as usize;

        for r in 0..reloc_count {
            if !self.modules[mod_idx].relocs[r].resolved { continue; }
            // In a real kernel: patch the instruction at offset
            // Here we just mark it as applied
        }
    }

    fn export_module_symbols(&mut self, mod_idx: usize) {
        let sym_count = self.modules[mod_idx].symbol_count as usize;
        for s in 0..sym_count {
            if self.modules[mod_idx].symbols[s].exported {
                if (self.global_sym_count as usize) < GLOBAL_SYMTAB_SIZE {
                    let gidx = self.global_sym_count as usize;
                    self.global_syms[gidx] = self.modules[mod_idx].symbols[s];
                    self.global_sym_count += 1;
                }
            }
        }
    }

    /// Unload a module
    pub fn unload_module(&mut self, id: u16) -> bool {
        let idx = match self.find_module(id) {
            Some(i) => i,
            None => return false,
        };

        if !self.modules[idx].can_unload() {
            return false;
        }

        // Check if any other module depends on this one
        for i in 0..self.module_count as usize {
            if !self.modules[i].active || i == idx { continue; }
            for d in 0..self.modules[i].dep_count as usize {
                if self.modules[i].deps[d] == id {
                    return false; // Still depended upon
                }
            }
        }

        self.modules[idx].state = ModuleState::Unloading;

        // Remove exported symbols from global table
        for s in 0..self.global_sym_count as usize {
            if self.global_syms[s].owner_id == id {
                self.global_syms[s].valid = false;
            }
        }

        self.modules[idx].state = ModuleState::Unloaded;
        self.modules[idx].active = false;
        self.total_unloaded.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn find_module(&self, id: u16) -> Option<usize> {
        for i in 0..self.module_count as usize {
            if self.modules[i].active && self.modules[i].id == id {
                return Some(i);
            }
        }
        None
    }

    pub fn find_module_by_name(&self, name: &[u8]) -> Option<u16> {
        for i in 0..self.module_count as usize {
            if self.modules[i].active && self.modules[i].name_len == name.len() as u8 {
                if &self.modules[i].name[..name.len()] == name {
                    return Some(self.modules[i].id);
                }
            }
        }
        None
    }

    /// Resolve a symbol by name
    pub fn lookup_symbol(&self, name: &[u8]) -> Option<u64> {
        for i in 0..self.global_sym_count as usize {
            if self.global_syms[i].valid && self.global_syms[i].name_matches(name) {
                return Some(self.global_syms[i].addr);
            }
        }
        None
    }

    pub fn active_module_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.module_count as usize {
            if self.modules[i].active && self.modules[i].state == ModuleState::Live {
                count += 1;
            }
        }
        count
    }

    pub fn total_symbols(&self) -> u32 {
        self.global_sym_count
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut MOD_LOADER: Option<ModuleLoader> = None;

fn mod_loader() -> &'static mut ModuleLoader {
    unsafe {
        if MOD_LOADER.is_none() {
            let mut loader = ModuleLoader::new();
            loader.init();
            MOD_LOADER = Some(loader);
        }
        MOD_LOADER.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_module_init() {
    let _ = mod_loader();
}

#[no_mangle]
pub extern "C" fn rust_module_load(name_ptr: *const u8, name_len: u32, base_addr: u64, size: u64) -> i32 {
    if name_ptr.is_null() || name_len == 0 || name_len > 63 {
        return -1;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match mod_loader().load_module(name, base_addr, size) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_module_unload(id: u16) -> i32 {
    if mod_loader().unload_module(id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_module_count() -> u32 {
    mod_loader().active_module_count()
}

#[no_mangle]
pub extern "C" fn rust_module_symbol_count() -> u32 {
    mod_loader().total_symbols()
}

#[no_mangle]
pub extern "C" fn rust_module_lookup_symbol(name_ptr: *const u8, name_len: u32) -> u64 {
    if name_ptr.is_null() || name_len == 0 {
        return 0;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    mod_loader().lookup_symbol(name).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn rust_module_total_loaded() -> u64 {
    mod_loader().total_loaded.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_module_total_unloaded() -> u64 {
    mod_loader().total_unloaded.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_module_require_sigs(require: u8) {
    mod_loader().require_signatures.store(require != 0, Ordering::Relaxed);
}
