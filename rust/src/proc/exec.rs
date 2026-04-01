// =============================================================================
// Kernel Zxyphor — ELF Exec & Program Loading (Rust)
// =============================================================================
// Executable loading for execve() syscall:
//   - ELF64 header parsing
//   - Program header (PHDR) processing
//   - PT_LOAD segment mapping
//   - PT_INTERP (dynamic linker path)
//   - Auxiliary vector (auxv) setup
//   - Stack layout with argv/envp/auxv
//   - Entry point resolution
//   - Shebang (#!) script detection
//   - Binary format identification
// =============================================================================

/// Maximum program headers
const MAX_PHDRS: usize = 32;
/// Maximum section headers for inspection
const MAX_SHDRS: usize = 64;
/// Maximum segments to load
const MAX_LOAD_SEGMENTS: usize = 16;
/// Maximum interpreter path length
const MAX_INTERP_PATH: usize = 256;
/// Maximum shebang line length
const MAX_SHEBANG: usize = 128;
/// Auxiliary vector max entries
const MAX_AUXV: usize = 32;

// ---------------------------------------------------------------------------
// ELF constants
// ---------------------------------------------------------------------------

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;     // PIE / shared object
pub const EM_X86_64: u16 = 62;

// Program header types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;

// Program header flags
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// Auxiliary vector types (AT_*)
pub const AT_NULL: u64 = 0;
pub const AT_IGNORE: u64 = 1;
pub const AT_EXECFD: u64 = 2;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO_EHDR: u64 = 33;

// ---------------------------------------------------------------------------
// ELF64 header
// ---------------------------------------------------------------------------

#[repr(C, packed)]
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
    pub fn is_valid(&self) -> bool {
        self.e_ident[0] == ELF_MAGIC[0]
            && self.e_ident[1] == ELF_MAGIC[1]
            && self.e_ident[2] == ELF_MAGIC[2]
            && self.e_ident[3] == ELF_MAGIC[3]
            && self.e_ident[4] == ELFCLASS64
            && self.e_ident[5] == ELFDATA2LSB
    }

    pub fn is_executable(&self) -> bool {
        self.e_type == ET_EXEC || self.e_type == ET_DYN
    }

    pub fn is_x86_64(&self) -> bool {
        self.e_machine == EM_X86_64
    }
}

// ---------------------------------------------------------------------------
// ELF64 program header
// ---------------------------------------------------------------------------

#[repr(C, packed)]
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

impl Elf64Phdr {
    pub fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    pub fn is_interp(&self) -> bool {
        self.p_type == PT_INTERP
    }

    pub fn is_tls(&self) -> bool {
        self.p_type == PT_TLS
    }

    pub fn is_readable(&self) -> bool {
        self.p_flags & PF_R != 0
    }

    pub fn is_writable(&self) -> bool {
        self.p_flags & PF_W != 0
    }

    pub fn is_executable(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// BSS size: memsz - filesz for LOAD segments
    pub fn bss_size(&self) -> u64 {
        if self.p_memsz > self.p_filesz {
            self.p_memsz - self.p_filesz
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// ELF64 section header
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Elf64Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

// ---------------------------------------------------------------------------
// Load segment descriptor
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub filesz: u64,
    pub file_offset: u64,
    pub flags: u32,
    pub alignment: u64,
    pub active: bool,
}

impl LoadSegment {
    pub const fn new() -> Self {
        Self {
            vaddr: 0, memsz: 0, filesz: 0,
            file_offset: 0, flags: 0, alignment: 0,
            active: false,
        }
    }

    pub fn vaddr_end(&self) -> u64 {
        self.vaddr + self.memsz
    }

    pub fn page_aligned_start(&self) -> u64 {
        self.vaddr & !0xFFF
    }

    pub fn page_aligned_end(&self) -> u64 {
        (self.vaddr + self.memsz + 0xFFF) & !0xFFF
    }

    pub fn pages_needed(&self) -> u64 {
        (self.page_aligned_end() - self.page_aligned_start()) / 4096
    }
}

// ---------------------------------------------------------------------------
// Auxiliary vector entry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct AuxvEntry {
    pub a_type: u64,
    pub a_val: u64,
}

impl AuxvEntry {
    pub const fn new(a_type: u64, a_val: u64) -> Self {
        Self { a_type, a_val }
    }

    pub const fn null() -> Self {
        Self { a_type: AT_NULL, a_val: 0 }
    }
}

// ---------------------------------------------------------------------------
// Binary format
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum BinaryFormat {
    Unknown = 0,
    Elf64   = 1,
    Script  = 2,  // Shebang
    FlatBin = 3,  // Raw binary
}

// ---------------------------------------------------------------------------
// Exec info: result of parsing an executable
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ExecInfo {
    pub format: BinaryFormat,
    pub entry_point: u64,
    pub phdr_addr: u64,
    pub phdr_count: u16,
    pub phdr_size: u16,
    pub is_pie: bool,
    pub load_bias: u64,        // For PIE: random base address

    // Interpreter
    pub has_interp: bool,
    pub interp_path: [u8; MAX_INTERP_PATH],
    pub interp_len: u32,

    // Load segments
    pub segments: [LoadSegment; MAX_LOAD_SEGMENTS],
    pub segment_count: u32,

    // Stack
    pub stack_base: u64,
    pub stack_size: u64,
    pub stack_executable: bool,

    // TLS
    pub tls_offset: u64,
    pub tls_memsz: u64,
    pub tls_filesz: u64,
    pub tls_align: u64,
    pub has_tls: bool,

    // Auxiliary vector
    pub auxv: [AuxvEntry; MAX_AUXV],
    pub auxv_count: u32,

    // Shebang
    pub shebang_interp: [u8; MAX_SHEBANG],
    pub shebang_len: u32,
    pub shebang_arg: [u8; MAX_SHEBANG],
    pub shebang_arg_len: u32,
}

impl ExecInfo {
    pub const fn new() -> Self {
        Self {
            format: BinaryFormat::Unknown,
            entry_point: 0,
            phdr_addr: 0,
            phdr_count: 0,
            phdr_size: 0,
            is_pie: false,
            load_bias: 0,
            has_interp: false,
            interp_path: [0u8; MAX_INTERP_PATH],
            interp_len: 0,
            segments: [const { LoadSegment::new() }; MAX_LOAD_SEGMENTS],
            segment_count: 0,
            stack_base: 0x7FFF_FFFF_0000,
            stack_size: 8 * 1024 * 1024, // 8 MiB default
            stack_executable: false,
            tls_offset: 0, tls_memsz: 0, tls_filesz: 0, tls_align: 0,
            has_tls: false,
            auxv: [const { AuxvEntry::null() }; MAX_AUXV],
            auxv_count: 0,
            shebang_interp: [0u8; MAX_SHEBANG],
            shebang_len: 0,
            shebang_arg: [0u8; MAX_SHEBANG],
            shebang_arg_len: 0,
        }
    }

    /// Add an auxiliary vector entry
    pub fn add_auxv(&mut self, a_type: u64, a_val: u64) -> bool {
        if self.auxv_count as usize >= MAX_AUXV - 1 { return false; } // Reserve space for AT_NULL
        self.auxv[self.auxv_count as usize] = AuxvEntry::new(a_type, a_val);
        self.auxv_count += 1;
        true
    }

    /// Add a load segment
    pub fn add_segment(&mut self, seg: LoadSegment) -> bool {
        if self.segment_count as usize >= MAX_LOAD_SEGMENTS { return false; }
        self.segments[self.segment_count as usize] = seg;
        self.segment_count += 1;
        true
    }

    /// Total virtual memory needed for all segments
    pub fn total_vm_size(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.segment_count as usize {
            if self.segments[i].active {
                total += self.segments[i].pages_needed() * 4096;
            }
        }
        total
    }

    /// Compute extent of loaded segments (lowest vaddr to highest end)
    pub fn load_extent(&self) -> (u64, u64) {
        let mut lo = u64::MAX;
        let mut hi = 0u64;
        for i in 0..self.segment_count as usize {
            if self.segments[i].active {
                if self.segments[i].vaddr < lo { lo = self.segments[i].vaddr; }
                let end = self.segments[i].vaddr_end();
                if end > hi { hi = end; }
            }
        }
        if lo == u64::MAX { lo = 0; }
        (lo, hi)
    }

    /// Build standard auxiliary vector
    pub fn build_auxv(&mut self, uid: u32, gid: u32) {
        self.auxv_count = 0;
        self.add_auxv(AT_PHDR, self.phdr_addr);
        self.add_auxv(AT_PHENT, self.phdr_size as u64);
        self.add_auxv(AT_PHNUM, self.phdr_count as u64);
        self.add_auxv(AT_PAGESZ, 4096);
        self.add_auxv(AT_BASE, self.load_bias);
        self.add_auxv(AT_ENTRY, self.entry_point);
        self.add_auxv(AT_UID, uid as u64);
        self.add_auxv(AT_EUID, uid as u64);
        self.add_auxv(AT_GID, gid as u64);
        self.add_auxv(AT_EGID, gid as u64);
        self.add_auxv(AT_CLKTCK, 100);
        self.add_auxv(AT_HWCAP, 0);
        self.add_auxv(AT_SECURE, 0);
        self.add_auxv(AT_NULL, 0);
    }
}

// ---------------------------------------------------------------------------
// ELF parser
// ---------------------------------------------------------------------------

pub struct ElfParser {
    pub info: ExecInfo,
}

impl ElfParser {
    pub const fn new() -> Self {
        Self { info: ExecInfo::new() }
    }

    /// Detect binary format from first bytes
    pub fn detect_format(header: &[u8]) -> BinaryFormat {
        if header.len() < 4 { return BinaryFormat::Unknown; }

        // ELF magic
        if header[0] == 0x7f && header[1] == b'E' && header[2] == b'L' && header[3] == b'F' {
            return BinaryFormat::Elf64;
        }

        // Shebang
        if header[0] == b'#' && header[1] == b'!' {
            return BinaryFormat::Script;
        }

        BinaryFormat::Unknown
    }

    /// Parse ELF64 from a memory buffer
    /// Safety: buffer must be a valid, mapped region with at least the ELF headers
    pub fn parse_elf64(&mut self, base: *const u8, size: usize) -> bool {
        if size < core::mem::size_of::<Elf64Header>() { return false; }

        let header = unsafe { &*(base as *const Elf64Header) };

        if !header.is_valid() || !header.is_executable() || !header.is_x86_64() {
            return false;
        }

        self.info.format = BinaryFormat::Elf64;
        self.info.entry_point = header.e_entry;
        self.info.phdr_count = header.e_phnum;
        self.info.phdr_size = header.e_phentsize;
        self.info.is_pie = header.e_type == ET_DYN;

        let phoff = header.e_phoff as usize;
        let phentsize = header.e_phentsize as usize;
        let phnum = header.e_phnum as usize;

        if phoff + phnum * phentsize > size { return false; }

        // Process program headers
        for i in 0..phnum {
            if i >= MAX_PHDRS { break; }
            let ph_ptr = unsafe { base.add(phoff + i * phentsize) };
            let ph = unsafe { &*(ph_ptr as *const Elf64Phdr) };

            match ph.p_type {
                PT_LOAD => {
                    let seg = LoadSegment {
                        vaddr: ph.p_vaddr,
                        memsz: ph.p_memsz,
                        filesz: ph.p_filesz,
                        file_offset: ph.p_offset,
                        flags: ph.p_flags,
                        alignment: ph.p_align,
                        active: true,
                    };
                    self.info.add_segment(seg);
                }
                PT_INTERP => {
                    self.info.has_interp = true;
                    let off = ph.p_offset as usize;
                    let len = ph.p_filesz as usize;
                    if off + len <= size {
                        let max = if len > MAX_INTERP_PATH { MAX_INTERP_PATH } else { len };
                        for j in 0..max {
                            self.info.interp_path[j] = unsafe { *base.add(off + j) };
                        }
                        // Strip null terminator
                        let actual_len = if max > 0 && self.info.interp_path[max - 1] == 0 { max - 1 } else { max };
                        self.info.interp_len = actual_len as u32;
                    }
                }
                PT_PHDR => {
                    self.info.phdr_addr = ph.p_vaddr;
                }
                PT_TLS => {
                    self.info.has_tls = true;
                    self.info.tls_offset = ph.p_offset;
                    self.info.tls_filesz = ph.p_filesz;
                    self.info.tls_memsz = ph.p_memsz;
                    self.info.tls_align = ph.p_align;
                }
                PT_GNU_STACK => {
                    self.info.stack_executable = ph.p_flags & PF_X != 0;
                }
                _ => {}
            }
        }

        true
    }

    /// Parse shebang line
    pub fn parse_shebang(&mut self, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != b'#' || data[1] != b'!' {
            return false;
        }

        self.info.format = BinaryFormat::Script;

        // Find end of first line
        let mut end = 2;
        while end < data.len() && end < MAX_SHEBANG + 2 && data[end] != b'\n' {
            end += 1;
        }

        // Skip whitespace after #!
        let mut start = 2;
        while start < end && data[start] == b' ' {
            start += 1;
        }

        // Find interpreter path (up to first space)
        let mut interp_end = start;
        while interp_end < end && data[interp_end] != b' ' {
            interp_end += 1;
        }

        let interp_len = interp_end - start;
        if interp_len > MAX_SHEBANG { return false; }
        for i in 0..interp_len {
            self.info.shebang_interp[i] = data[start + i];
        }
        self.info.shebang_len = interp_len as u32;

        // Find optional argument
        let mut arg_start = interp_end;
        while arg_start < end && data[arg_start] == b' ' {
            arg_start += 1;
        }
        if arg_start < end {
            let arg_len = end - arg_start;
            let max = if arg_len > MAX_SHEBANG { MAX_SHEBANG } else { arg_len };
            for i in 0..max {
                self.info.shebang_arg[i] = data[arg_start + i];
            }
            self.info.shebang_arg_len = max as u32;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static mut ELF_PARSER: ElfParser = ElfParser::new();

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_exec_detect_format(header: *const u8, len: usize) -> u8 {
    if header.is_null() || len < 4 { return 0; }
    let slice = unsafe { core::slice::from_raw_parts(header, if len > 16 { 16 } else { len }) };
    ElfParser::detect_format(slice) as u8
}

#[no_mangle]
pub extern "C" fn zxyphor_exec_parse_elf64(data: *const u8, size: usize) -> i32 {
    if data.is_null() || size == 0 { return -1; }
    let parser = unsafe { &mut ELF_PARSER };
    *parser = ElfParser::new();
    if parser.parse_elf64(data, size) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_exec_entry_point() -> u64 {
    unsafe { ELF_PARSER.info.entry_point }
}

#[no_mangle]
pub extern "C" fn zxyphor_exec_segment_count() -> u32 {
    unsafe { ELF_PARSER.info.segment_count }
}

#[no_mangle]
pub extern "C" fn zxyphor_exec_is_pie() -> i32 {
    if unsafe { ELF_PARSER.info.is_pie } { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn zxyphor_exec_has_interp() -> i32 {
    if unsafe { ELF_PARSER.info.has_interp } { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn zxyphor_exec_total_vm() -> u64 {
    unsafe { ELF_PARSER.info.total_vm_size() }
}
