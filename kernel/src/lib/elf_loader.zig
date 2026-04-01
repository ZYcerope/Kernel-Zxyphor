// =============================================================================
// Kernel Zxyphor — ELF Executable Loader
// =============================================================================
// Full ELF64 parser and loader supporting:
// - Static executables
// - Dynamic executables (with interpreter loading)
// - Position-Independent Executables (PIE)
// - Thread-Local Storage (TLS) initialization
// - ASLR (Address Space Layout Randomization)
// - Stack guard pages
// - Core dump generation headers
// =============================================================================

const std = @import("std");

// =============================================================================
// ELF64 Data Structures (as per System V ABI)
// =============================================================================

pub const EI_NIDENT = 16;
pub const EI_MAG0 = 0;
pub const EI_MAG1 = 1;
pub const EI_MAG2 = 2;
pub const EI_MAG3 = 3;
pub const EI_CLASS = 4;
pub const EI_DATA = 5;
pub const EI_VERSION = 6;
pub const EI_OSABI = 7;
pub const EI_ABIVERSION = 8;

pub const ELFMAG0: u8 = 0x7f;
pub const ELFMAG1: u8 = 'E';
pub const ELFMAG2: u8 = 'L';
pub const ELFMAG3: u8 = 'F';

pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;
pub const ELFOSABI_NONE: u8 = 0;
pub const ELFOSABI_LINUX: u8 = 3;

// ELF types
pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

// Machine types
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
pub const PT_GNU_PROPERTY: u32 = 0x6474e553;

// Program header flags
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

// Section header types
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;

// Dynamic section tags
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_FLAGS: i64 = 30;
pub const DT_FLAGS_1: i64 = 0x6ffffffb;
pub const DT_GNU_HASH: i64 = 0x6ffffef5;

// Relocation types (x86_64)
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_IRELATIVE: u32 = 37;

// Auxiliary vector types (for passing info to dynamic linker)
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
pub const AT_NOTELF: u64 = 10;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_BASE_PLATFORM: u64 = 24;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO_EHDR: u64 = 33;
pub const AT_MINSIGSTKSZ: u64 = 51;

/// ELF64 File Header
pub const Elf64_Ehdr = extern struct {
    e_ident: [EI_NIDENT]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

/// ELF64 Program Header
pub const Elf64_Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

/// ELF64 Section Header
pub const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

/// ELF64 Symbol Table Entry
pub const Elf64_Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,

    pub fn binding(self: *const Elf64_Sym) u4 {
        return @truncate(self.st_info >> 4);
    }

    pub fn symbolType(self: *const Elf64_Sym) u4 {
        return @truncate(self.st_info & 0xf);
    }
};

/// ELF64 Relocation with Addend
pub const Elf64_Rela = extern struct {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,

    pub fn symbol(self: *const Elf64_Rela) u32 {
        return @truncate(self.r_info >> 32);
    }

    pub fn relType(self: *const Elf64_Rela) u32 {
        return @truncate(self.r_info & 0xffffffff);
    }
};

/// ELF64 Dynamic Section Entry
pub const Elf64_Dyn = extern struct {
    d_tag: i64,
    d_val: u64, // d_un (union of d_val and d_ptr)
};

/// ELF64 Note Header
pub const Elf64_Nhdr = extern struct {
    n_namesz: u32,
    n_descsz: u32,
    n_type: u32,
};

/// Auxiliary vector entry (for initial process stack)
pub const AuxEntry = extern struct {
    a_type: u64,
    a_val: u64,
};

// =============================================================================
// ELF Loading Error Types
// =============================================================================

pub const ElfError = error{
    InvalidMagic,
    InvalidClass,
    InvalidEncoding,
    InvalidType,
    InvalidMachine,
    InvalidVersion,
    TooManySegments,
    SegmentOverlap,
    SegmentOutOfBounds,
    InvalidAlignment,
    FileTooBig,
    FileTruncated,
    MappingFailed,
    NoExecutableSegment,
    InvalidEntryPoint,
    InterpreterNotFound,
    TlsSetupFailed,
    StackSetupFailed,
    OutOfMemory,
    SecurityViolation,
};

// =============================================================================
// ELF Load Information — Result of loading an ELF binary
// =============================================================================

pub const ElfLoadInfo = struct {
    /// Entry point virtual address
    entry_point: u64,
    /// Program header table virtual address (for AT_PHDR)
    phdr_addr: u64,
    /// Number of program headers
    phdr_count: u16,
    /// Size of each program header entry
    phdr_entry_size: u16,
    /// Base address where the binary was mapped (for PIE)
    load_base: u64,
    /// Lowest mapped virtual address
    min_vaddr: u64,
    /// Highest mapped virtual address
    max_vaddr: u64,
    /// Stack pointer value (top of user stack)
    stack_pointer: u64,
    /// Interpreter load info (if dynamic executable)
    interp_base: u64,
    /// Interpreter entry point
    interp_entry: u64,
    /// Whether this is a PIE executable
    is_pie: bool,
    /// Whether the binary has PT_GNU_STACK with PF_X (executable stack)
    executable_stack: bool,
    /// TLS info
    tls_image_addr: u64,
    tls_image_size: u64,
    tls_mem_size: u64,
    tls_alignment: u64,
    /// RELRO region
    relro_start: u64,
    relro_end: u64,
    /// BRK start (end of loaded segments, for heap)
    brk_start: u64,
};

// =============================================================================
// ASLR Configuration
// =============================================================================

pub const AslrConfig = struct {
    /// Enable ASLR
    enabled: bool = true,
    /// Number of random bits for mmap base
    mmap_random_bits: u8 = 28,
    /// Number of random bits for stack
    stack_random_bits: u8 = 22,
    /// Number of random bits for PIE base
    pie_random_bits: u8 = 28,
    /// Number of random bits for heap
    heap_random_bits: u8 = 13,
};

pub const DEFAULT_ASLR_CONFIG = AslrConfig{};

// Virtual address space layout for user processes
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000; // Below canonical hole
pub const USER_STACK_SIZE: u64 = 8 * 1024 * 1024; // 8 MB default stack
pub const USER_STACK_GUARD: u64 = 4096; // Guard page at bottom
pub const USER_MMAP_BASE: u64 = 0x0000_7F00_0000_0000; // Default mmap base
pub const USER_PIE_BASE: u64 = 0x0000_5555_5555_0000; // Default PIE load address
pub const USER_HEAP_START: u64 = 0x0000_0000_1000_0000; // Default heap start
pub const USER_INTERP_BASE: u64 = 0x0000_7F80_0000_0000; // Default ld.so base

pub const PAGE_SIZE: u64 = 4096;

// =============================================================================
// ELF Validator — Comprehensive ELF header and structure validation
// =============================================================================

pub const ElfValidator = struct {
    /// Maximum allowed file size (256 MB)
    pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
    /// Maximum number of program headers
    pub const MAX_PHDR_COUNT: u16 = 256;
    /// Maximum number of section headers
    pub const MAX_SHDR_COUNT: u16 = 65279; // SHN_LORESERVE - 1
    /// Maximum segment size (4 GB)
    pub const MAX_SEGMENT_SIZE: u64 = 4 * 1024 * 1024 * 1024;

    /// Validate ELF magic number.
    pub fn validateMagic(ident: *const [EI_NIDENT]u8) bool {
        return ident[EI_MAG0] == ELFMAG0 and
            ident[EI_MAG1] == ELFMAG1 and
            ident[EI_MAG2] == ELFMAG2 and
            ident[EI_MAG3] == ELFMAG3;
    }

    /// Fully validate ELF header.
    pub fn validateHeader(ehdr: *const Elf64_Ehdr, file_size: u64) ElfError!void {
        if (!validateMagic(&ehdr.e_ident)) return ElfError.InvalidMagic;
        if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return ElfError.InvalidClass;
        if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) return ElfError.InvalidEncoding;
        if (ehdr.e_ident[EI_VERSION] != EV_CURRENT) return ElfError.InvalidVersion;
        if (ehdr.e_type != ET_EXEC and ehdr.e_type != ET_DYN) return ElfError.InvalidType;
        if (ehdr.e_machine != EM_X86_64) return ElfError.InvalidMachine;
        if (ehdr.e_version != EV_CURRENT) return ElfError.InvalidVersion;
        if (ehdr.e_ehsize != @sizeOf(Elf64_Ehdr)) return ElfError.InvalidType;
        if (ehdr.e_phentsize != @sizeOf(Elf64_Phdr)) return ElfError.InvalidType;
        if (ehdr.e_phnum > MAX_PHDR_COUNT) return ElfError.TooManySegments;

        // Validate program header table is within file
        if (ehdr.e_phoff > file_size) return ElfError.FileTruncated;
        const phdr_end = ehdr.e_phoff + @as(u64, ehdr.e_phnum) * @as(u64, ehdr.e_phentsize);
        if (phdr_end > file_size) return ElfError.FileTruncated;

        // Validate entry point (must be non-zero for ET_EXEC)
        if (ehdr.e_type == ET_EXEC and ehdr.e_entry == 0) return ElfError.InvalidEntryPoint;

        return;
    }

    /// Validate a program header segment.
    pub fn validatePhdr(phdr: *const Elf64_Phdr, file_size: u64) ElfError!void {
        // Check file range
        if (phdr.p_type == PT_LOAD) {
            if (phdr.p_offset > file_size) return ElfError.FileTruncated;
            if (phdr.p_filesz > file_size - phdr.p_offset) return ElfError.FileTruncated;
            if (phdr.p_filesz > phdr.p_memsz) return ElfError.SegmentOutOfBounds;
            if (phdr.p_memsz > MAX_SEGMENT_SIZE) return ElfError.SegmentOutOfBounds;

            // Check alignment
            if (phdr.p_align != 0 and phdr.p_align != 1) {
                // Alignment must be power of 2
                if (phdr.p_align & (phdr.p_align - 1) != 0) return ElfError.InvalidAlignment;
                // VAddr and offset must be congruent modulo alignment
                if ((phdr.p_vaddr % phdr.p_align) != (phdr.p_offset % phdr.p_align)) {
                    return ElfError.InvalidAlignment;
                }
            }

            // Check for user address space bounds
            if (phdr.p_vaddr >= 0x0000_8000_0000_0000) return ElfError.SecurityViolation;
            if (phdr.p_vaddr + phdr.p_memsz < phdr.p_vaddr) return ElfError.SegmentOverlap; // overflow
            if (phdr.p_vaddr + phdr.p_memsz > 0x0000_8000_0000_0000) return ElfError.SecurityViolation;
        }

        return;
    }
};

// =============================================================================
// ELF Loader — Main loading logic
// =============================================================================

pub const ElfLoader = struct {
    /// File data buffer
    data: []const u8,
    /// File size
    file_size: u64,
    /// ASLR configuration
    aslr: AslrConfig,
    /// Random seed for ASLR (from kernel entropy)
    random_seed: u64,

    pub fn init(data: []const u8, aslr_config: AslrConfig, random_seed: u64) ElfLoader {
        return .{
            .data = data,
            .file_size = data.len,
            .aslr = aslr_config,
            .random_seed = random_seed,
        };
    }

    /// Get the ELF header.
    pub fn getHeader(self: *const ElfLoader) *const Elf64_Ehdr {
        return @ptrCast(@alignCast(self.data.ptr));
    }

    /// Get program headers array.
    pub fn getProgramHeaders(self: *const ElfLoader) []const Elf64_Phdr {
        const ehdr = self.getHeader();
        const ptr: [*]const Elf64_Phdr = @ptrCast(@alignCast(self.data.ptr + ehdr.e_phoff));
        return ptr[0..ehdr.e_phnum];
    }

    /// Get section headers array.
    pub fn getSectionHeaders(self: *const ElfLoader) ?[]const Elf64_Shdr {
        const ehdr = self.getHeader();
        if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) return null;
        if (ehdr.e_shoff + @as(u64, ehdr.e_shnum) * @as(u64, ehdr.e_shentsize) > self.file_size) return null;
        const ptr: [*]const Elf64_Shdr = @ptrCast(@alignCast(self.data.ptr + ehdr.e_shoff));
        return ptr[0..ehdr.e_shnum];
    }

    /// Compute the ASLR slide for a PIE binary.
    fn computePieSlide(self: *const ElfLoader) u64 {
        if (!self.aslr.enabled) return 0;
        // Simple ASLR: Apply random page-aligned offset
        const mask = (@as(u64, 1) << self.aslr.pie_random_bits) - 1;
        return (self.random_seed & mask) & ~@as(u64, PAGE_SIZE - 1);
    }

    /// Compute stack randomization offset.
    fn computeStackRandomize(self: *const ElfLoader) u64 {
        if (!self.aslr.enabled) return 0;
        const mask = (@as(u64, 1) << self.aslr.stack_random_bits) - 1;
        // Use different bits from the random seed
        return ((self.random_seed >> 16) & mask) & ~@as(u64, 15); // 16-byte aligned
    }

    /// Main load function: Validate, parse, and compute the load information.
    /// This does NOT actually map pages — the caller (VMM) does that.
    pub fn load(self: *ElfLoader) ElfError!ElfLoadInfo {
        // Step 1: Validate the header
        if (self.file_size < @sizeOf(Elf64_Ehdr)) return ElfError.FileTruncated;
        const ehdr = self.getHeader();
        try ElfValidator.validateHeader(ehdr, self.file_size);

        // Step 2: Parse program headers
        const phdrs = self.getProgramHeaders();

        // Step 3: Compute virtual address range
        var min_vaddr: u64 = std.math.maxInt(u64);
        var max_vaddr: u64 = 0;
        var has_load_segment = false;
        var has_interp = false;
        var interp_offset: u64 = 0;
        var interp_size: u64 = 0;
        var executable_stack = false;
        var tls_phdr: ?*const Elf64_Phdr = null;
        var relro_start: u64 = 0;
        var relro_end: u64 = 0;

        for (phdrs) |*phdr| {
            try ElfValidator.validatePhdr(phdr, self.file_size);

            switch (phdr.p_type) {
                PT_LOAD => {
                    has_load_segment = true;
                    if (phdr.p_vaddr < min_vaddr) min_vaddr = phdr.p_vaddr;
                    const seg_end = phdr.p_vaddr + phdr.p_memsz;
                    if (seg_end > max_vaddr) max_vaddr = seg_end;
                },
                PT_INTERP => {
                    has_interp = true;
                    interp_offset = phdr.p_offset;
                    interp_size = phdr.p_filesz;
                },
                PT_GNU_STACK => {
                    executable_stack = (phdr.p_flags & PF_X) != 0;
                },
                PT_TLS => {
                    tls_phdr = phdr;
                },
                PT_GNU_RELRO => {
                    relro_start = phdr.p_vaddr;
                    relro_end = phdr.p_vaddr + phdr.p_memsz;
                },
                else => {},
            }
        }

        if (!has_load_segment) return ElfError.NoExecutableSegment;

        // Step 4: Compute load base (ASLR for PIE)
        const is_pie = ehdr.e_type == ET_DYN;
        var load_base: u64 = 0;
        if (is_pie) {
            load_base = USER_PIE_BASE + self.computePieSlide();
            // Adjust for ET_DYN: min_vaddr is usually 0
            load_base -= (min_vaddr & ~(PAGE_SIZE - 1));
        }

        // Step 5: Compute adjusted addresses
        const adjusted_min = min_vaddr + load_base;
        const adjusted_max = max_vaddr + load_base;
        const adjusted_entry = ehdr.e_entry + load_base;

        // Step 6: Page-align max_vaddr for BRK start
        const brk_start = (adjusted_max + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

        // Step 7: Compute stack pointer
        const stack_top = USER_STACK_TOP - self.computeStackRandomize();

        // Step 8: Build TLS info
        var tls_image_addr: u64 = 0;
        var tls_image_size: u64 = 0;
        var tls_mem_size: u64 = 0;
        var tls_alignment: u64 = 0;

        if (tls_phdr) |tls| {
            tls_image_addr = tls.p_vaddr + load_base;
            tls_image_size = tls.p_filesz;
            tls_mem_size = tls.p_memsz;
            tls_alignment = if (tls.p_align > 0) tls.p_align else 16;
        }

        // Step 9: Find PHDR virtual address (for AT_PHDR)
        var phdr_addr: u64 = 0;
        for (phdrs) |*phdr| {
            if (phdr.p_type == PT_PHDR) {
                phdr_addr = phdr.p_vaddr + load_base;
                break;
            }
        }
        // If no PT_PHDR, compute from first PT_LOAD that covers phoff
        if (phdr_addr == 0) {
            for (phdrs) |*phdr| {
                if (phdr.p_type == PT_LOAD and
                    ehdr.e_phoff >= phdr.p_offset and
                    ehdr.e_phoff < phdr.p_offset + phdr.p_filesz)
                {
                    phdr_addr = phdr.p_vaddr + (ehdr.e_phoff - phdr.p_offset) + load_base;
                    break;
                }
            }
        }

        // Step 10: Handle interpreter path
        var interp_base: u64 = 0;
        var interp_entry: u64 = 0;
        if (has_interp) {
            // Interpreter path is embedded in the file
            if (interp_offset + interp_size > self.file_size) return ElfError.FileTruncated;
            // The actual loading of ld.so will be done by the caller
            interp_base = USER_INTERP_BASE;
            // Entry point will be set after loading the interpreter
        }

        return ElfLoadInfo{
            .entry_point = if (has_interp) interp_entry else adjusted_entry,
            .phdr_addr = phdr_addr,
            .phdr_count = ehdr.e_phnum,
            .phdr_entry_size = ehdr.e_phentsize,
            .load_base = load_base,
            .min_vaddr = adjusted_min,
            .max_vaddr = adjusted_max,
            .stack_pointer = stack_top,
            .interp_base = interp_base,
            .interp_entry = interp_entry,
            .is_pie = is_pie,
            .executable_stack = executable_stack,
            .tls_image_addr = tls_image_addr,
            .tls_image_size = tls_image_size,
            .tls_mem_size = tls_mem_size,
            .tls_alignment = tls_alignment,
            .relro_start = if (relro_start != 0) relro_start + load_base else 0,
            .relro_end = if (relro_end != 0) relro_end + load_base else 0,
            .brk_start = brk_start,
        };
    }

    /// Get the interpreter path string from the ELF.
    pub fn getInterpreterPath(self: *const ElfLoader) ?[]const u8 {
        const phdrs = self.getProgramHeaders();
        for (phdrs) |*phdr| {
            if (phdr.p_type == PT_INTERP) {
                if (phdr.p_offset + phdr.p_filesz > self.file_size) return null;
                const path = self.data[phdr.p_offset .. phdr.p_offset + phdr.p_filesz];
                // Trim null terminator
                if (path.len > 0 and path[path.len - 1] == 0) {
                    return path[0 .. path.len - 1];
                }
                return path;
            }
        }
        return null;
    }

    /// Get load segments iterator for the VMM to map.
    pub fn getLoadSegments(self: *const ElfLoader) LoadSegmentIterator {
        return LoadSegmentIterator{
            .phdrs = self.getProgramHeaders(),
            .index = 0,
        };
    }
};

// =============================================================================
// Load Segment Iterator — Used by VMM to map segments
// =============================================================================

pub const LoadSegment = struct {
    /// Virtual address to map at
    vaddr: u64,
    /// Offset in file data
    file_offset: u64,
    /// Size in file
    file_size: u64,
    /// Size in memory (>= file_size, extra is zero-filled BSS)
    mem_size: u64,
    /// Required alignment
    alignment: u64,
    /// Page protection flags
    readable: bool,
    writable: bool,
    executable: bool,
};

pub const LoadSegmentIterator = struct {
    phdrs: []const Elf64_Phdr,
    index: u16,

    pub fn next(self: *LoadSegmentIterator) ?LoadSegment {
        while (self.index < self.phdrs.len) {
            const phdr = &self.phdrs[self.index];
            self.index += 1;

            if (phdr.p_type == PT_LOAD) {
                return LoadSegment{
                    .vaddr = phdr.p_vaddr,
                    .file_offset = phdr.p_offset,
                    .file_size = phdr.p_filesz,
                    .mem_size = phdr.p_memsz,
                    .alignment = phdr.p_align,
                    .readable = (phdr.p_flags & PF_R) != 0,
                    .writable = (phdr.p_flags & PF_W) != 0,
                    .executable = (phdr.p_flags & PF_X) != 0,
                };
            }
        }
        return null;
    }
};

// =============================================================================
// Initial Process Stack Builder
// =============================================================================
// Linux x86_64 initial stack layout (grows down):
//
//   [high address]
//   environment strings (null terminated)
//   argument strings (null terminated)
//   platform string
//   random bytes (16 bytes for AT_RANDOM)
//   padding for alignment
//   NULL auxiliary vector entry
//   auxiliary vector entries
//   NULL (envp terminator)
//   envp[n-1]
//   ...
//   envp[0]
//   NULL (argv terminator)
//   argv[argc-1]
//   ...
//   argv[0]
//   argc
//   [low address] <- SP points here
//

pub const StackBuilder = struct {
    /// Buffer representing the stack page(s)
    buffer: []u8,
    /// Current write position (growing down from top)
    sp: u64,
    /// Virtual base address of this stack in user space
    virt_base: u64,

    const MAX_ARG_STRINGS = 256;
    const MAX_ENV_STRINGS = 256;
    const MAX_STRING_SIZE = 4096;

    pub fn init(buffer: []u8, virt_base: u64) StackBuilder {
        return .{
            .buffer = buffer,
            .sp = virt_base + buffer.len,
            .virt_base = virt_base,
        };
    }

    /// Push a string onto the stack, returns its virtual address.
    pub fn pushString(self: *StackBuilder, str: []const u8) ?u64 {
        const len = str.len + 1; // include null terminator
        if (self.sp < self.virt_base + len) return null;

        self.sp -= len;
        const offset = self.sp - self.virt_base;
        @memcpy(self.buffer[offset .. offset + str.len], str);
        self.buffer[offset + str.len] = 0;

        return self.sp;
    }

    /// Push raw bytes.
    pub fn pushBytes(self: *StackBuilder, bytes: []const u8) ?u64 {
        if (self.sp < self.virt_base + bytes.len) return null;

        self.sp -= bytes.len;
        const offset = self.sp - self.virt_base;
        @memcpy(self.buffer[offset .. offset + bytes.len], bytes);

        return self.sp;
    }

    /// Push a u64 value.
    pub fn pushU64(self: *StackBuilder, value: u64) ?u64 {
        if (self.sp < self.virt_base + 8) return null;

        self.sp -= 8;
        const offset = self.sp - self.virt_base;
        const ptr: *align(1) u64 = @ptrCast(&self.buffer[offset]);
        ptr.* = value;

        return self.sp;
    }

    /// Align SP to specified boundary.
    pub fn align_(self: *StackBuilder, alignment: u64) void {
        self.sp = self.sp & ~(alignment - 1);
    }

    /// Build the initial stack for a new process.
    /// Returns the final stack pointer value.
    pub fn buildInitialStack(
        self: *StackBuilder,
        argv: []const []const u8,
        envp: []const []const u8,
        load_info: *const ElfLoadInfo,
        random_bytes: [16]u8,
    ) ?u64 {
        // Phase 1: Push strings (from high to low)
        const platform_str = "x86_64";
        const platform_addr = self.pushString(platform_str) orelse return null;

        // Push random bytes for AT_RANDOM
        const random_addr = self.pushBytes(&random_bytes) orelse return null;

        // Push environment strings, recording their addresses
        var env_addrs: [MAX_ENV_STRINGS]u64 = undefined;
        var env_count: usize = 0;
        for (envp) |env| {
            if (env_count >= MAX_ENV_STRINGS) break;
            env_addrs[env_count] = self.pushString(env) orelse return null;
            env_count += 1;
        }

        // Push argument strings, recording their addresses
        var arg_addrs: [MAX_ARG_STRINGS]u64 = undefined;
        var arg_count: usize = 0;
        for (argv) |arg| {
            if (arg_count >= MAX_ARG_STRINGS) break;
            arg_addrs[arg_count] = self.pushString(arg) orelse return null;
            arg_count += 1;
        }

        // Phase 2: Align to 16 bytes
        self.align_(16);

        // Phase 3: Push auxiliary vector (in reverse, NULL terminator first)
        _ = self.pushU64(0) orelse return null; // AT_NULL value
        _ = self.pushU64(AT_NULL) orelse return null;

        const aux_entries = [_][2]u64{
            .{ AT_MINSIGSTKSZ, 2048 },
            .{ AT_HWCAP2, 0 },
            .{ AT_HWCAP, detectHwcap() },
            .{ AT_PAGESZ, PAGE_SIZE },
            .{ AT_CLKTCK, 100 },
            .{ AT_PHDR, load_info.phdr_addr },
            .{ AT_PHENT, load_info.phdr_entry_size },
            .{ AT_PHNUM, load_info.phdr_count },
            .{ AT_BASE, load_info.interp_base },
            .{ AT_FLAGS, 0 },
            .{ AT_ENTRY, load_info.entry_point },
            .{ AT_UID, 0 },
            .{ AT_EUID, 0 },
            .{ AT_GID, 0 },
            .{ AT_EGID, 0 },
            .{ AT_SECURE, 0 },
            .{ AT_RANDOM, random_addr },
            .{ AT_PLATFORM, platform_addr },
        };

        for (aux_entries) |entry| {
            _ = self.pushU64(entry[1]) orelse return null;
            _ = self.pushU64(entry[0]) orelse return null;
        }

        // Phase 4: Push envp array (NULL terminated)
        _ = self.pushU64(0) orelse return null; // NULL terminator
        var i = env_count;
        while (i > 0) {
            i -= 1;
            _ = self.pushU64(env_addrs[i]) orelse return null;
        }

        // Phase 5: Push argv array (NULL terminated)
        _ = self.pushU64(0) orelse return null; // NULL terminator
        var j = arg_count;
        while (j > 0) {
            j -= 1;
            _ = self.pushU64(arg_addrs[j]) orelse return null;
        }

        // Phase 6: Push argc
        _ = self.pushU64(arg_count) orelse return null;

        // Ensure 16-byte alignment of final SP (ABI requirement)
        self.align_(16);

        return self.sp;
    }
};

/// Detect hardware capabilities bitmask for AT_HWCAP.
fn detectHwcap() u64 {
    // TODO: Use CPUID to detect actual capabilities
    var hwcap: u64 = 0;
    // Bit positions match Linux AT_HWCAP for x86_64
    hwcap |= (1 << 0); // fpu
    hwcap |= (1 << 3); // pse
    hwcap |= (1 << 4); // tsc
    hwcap |= (1 << 5); // msr
    hwcap |= (1 << 6); // pae
    hwcap |= (1 << 8); // cx8
    hwcap |= (1 << 9); // apic
    hwcap |= (1 << 11); // sep
    hwcap |= (1 << 13); // pge
    hwcap |= (1 << 15); // cmov
    hwcap |= (1 << 19); // clflush
    hwcap |= (1 << 23); // mmx
    hwcap |= (1 << 24); // fxsr
    hwcap |= (1 << 25); // sse
    hwcap |= (1 << 26); // sse2
    return hwcap;
}

// =============================================================================
// Core Dump ELF Header Builder
// =============================================================================

pub const CoreDumpBuilder = struct {
    /// Build a minimal core dump ELF header for crash analysis.
    pub fn buildHeader(
        num_vma_regions: u16,
        num_threads: u16,
    ) Elf64_Ehdr {
        var ehdr: Elf64_Ehdr = undefined;
        @memset(@as([*]u8, @ptrCast(&ehdr))[0..@sizeOf(Elf64_Ehdr)], 0);

        ehdr.e_ident[EI_MAG0] = ELFMAG0;
        ehdr.e_ident[EI_MAG1] = ELFMAG1;
        ehdr.e_ident[EI_MAG2] = ELFMAG2;
        ehdr.e_ident[EI_MAG3] = ELFMAG3;
        ehdr.e_ident[EI_CLASS] = ELFCLASS64;
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;

        ehdr.e_type = ET_CORE;
        ehdr.e_machine = EM_X86_64;
        ehdr.e_version = EV_CURRENT;
        ehdr.e_entry = 0;
        ehdr.e_phoff = @sizeOf(Elf64_Ehdr);
        ehdr.e_shoff = 0;
        ehdr.e_flags = 0;
        ehdr.e_ehsize = @sizeOf(Elf64_Ehdr);
        ehdr.e_phentsize = @sizeOf(Elf64_Phdr);
        // +1 for the NOTE segment
        ehdr.e_phnum = num_vma_regions + 1;
        ehdr.e_shentsize = 0;
        ehdr.e_shnum = 0;
        ehdr.e_shstrndx = 0;

        _ = num_threads;
        return ehdr;
    }

    /// NT_PRSTATUS note type (process status)
    pub const NT_PRSTATUS: u32 = 1;
    /// NT_PRFPREG note type (floating point registers)
    pub const NT_PRFPREG: u32 = 2;
    /// NT_PRPSINFO note type (process info)
    pub const NT_PRPSINFO: u32 = 3;
    /// NT_AUXV note type (auxiliary vector)
    pub const NT_AUXV: u32 = 6;
    /// NT_FILE note type (mapped files)
    pub const NT_FILE: u32 = 0x46494c45;
    /// NT_SIGINFO note type
    pub const NT_SIGINFO: u32 = 0x53494749;
};

// =============================================================================
// ELF Symbol Lookup (for kernel module loading)
// =============================================================================

pub const SymbolLookup = struct {
    symtab: []const Elf64_Sym,
    strtab: []const u8,

    pub fn init(data: []const u8, shdr_symtab: *const Elf64_Shdr, shdr_strtab: *const Elf64_Shdr) ?SymbolLookup {
        if (shdr_symtab.sh_offset + shdr_symtab.sh_size > data.len) return null;
        if (shdr_strtab.sh_offset + shdr_strtab.sh_size > data.len) return null;

        const sym_count = shdr_symtab.sh_size / @sizeOf(Elf64_Sym);
        const sym_ptr: [*]const Elf64_Sym = @ptrCast(@alignCast(data.ptr + shdr_symtab.sh_offset));

        return SymbolLookup{
            .symtab = sym_ptr[0..sym_count],
            .strtab = data[shdr_strtab.sh_offset .. shdr_strtab.sh_offset + shdr_strtab.sh_size],
        };
    }

    /// Find a symbol by name. Returns its value (address) or null.
    pub fn findSymbol(self: *const SymbolLookup, name: []const u8) ?u64 {
        for (self.symtab) |*sym| {
            if (sym.st_name >= self.strtab.len) continue;
            const sym_name = self.getSymbolName(sym) orelse continue;
            if (strEqual(sym_name, name)) {
                return sym.st_value;
            }
        }
        return null;
    }

    /// Get the null-terminated name of a symbol.
    fn getSymbolName(self: *const SymbolLookup, sym: *const Elf64_Sym) ?[]const u8 {
        if (sym.st_name >= self.strtab.len) return null;
        const start = sym.st_name;
        var end = start;
        while (end < self.strtab.len and self.strtab[end] != 0) : (end += 1) {}
        return self.strtab[start..end];
    }

    fn strEqual(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (ca != cb) return false;
        }
        return true;
    }
};

// =============================================================================
// Kernel Module ELF Loader (for .ko files)
// =============================================================================

pub const KernelModuleLoader = struct {
    data: []const u8,

    pub fn init(data: []const u8) KernelModuleLoader {
        return .{ .data = data };
    }

    /// Validate that this is a valid relocatable ELF kernel module.
    pub fn validate(self: *const KernelModuleLoader) ElfError!void {
        if (self.data.len < @sizeOf(Elf64_Ehdr)) return ElfError.FileTruncated;

        const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(self.data.ptr));

        if (!ElfValidator.validateMagic(&ehdr.e_ident)) return ElfError.InvalidMagic;
        if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return ElfError.InvalidClass;
        if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) return ElfError.InvalidEncoding;
        if (ehdr.e_type != ET_REL) return ElfError.InvalidType; // Must be relocatable
        if (ehdr.e_machine != EM_X86_64) return ElfError.InvalidMachine;

        return;
    }

    /// Get the total memory required for all allocatable sections.
    pub fn computeMemoryRequirement(self: *const KernelModuleLoader) u64 {
        const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(self.data.ptr));
        if (ehdr.e_shoff == 0) return 0;

        const shdrs_ptr: [*]const Elf64_Shdr = @ptrCast(@alignCast(self.data.ptr + ehdr.e_shoff));
        const shdrs = shdrs_ptr[0..ehdr.e_shnum];

        var total: u64 = 0;
        for (shdrs) |*shdr| {
            const SHF_ALLOC = 0x2;
            if (shdr.sh_flags & SHF_ALLOC != 0) {
                // Align section
                const align_val = if (shdr.sh_addralign > 0) shdr.sh_addralign else 1;
                total = (total + align_val - 1) & ~(align_val - 1);
                total += shdr.sh_size;
            }
        }

        return total;
    }
};
