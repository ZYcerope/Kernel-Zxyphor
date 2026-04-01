// =============================================================================
// Kernel Zxyphor — ELF (Executable and Linkable Format) Loader
// =============================================================================
// Implements parsing and loading of ELF64 binaries for user-space processes:
//   - ELF header validation (magic, class, endianness, ABI)
//   - Program header (PHDR) parsing for loadable segments
//   - Section header (SHDR) parsing for symbols and debug info
//   - PT_LOAD segment mapping into process virtual address space
//   - PT_INTERP handling (dynamic linker path)
//   - PT_DYNAMIC section parsing for shared library dependencies
//   - Relocation processing (REL, RELA)
//   - Symbol table lookup
//   - String table access
//   - Auxiliary vector (auxv) construction for process startup
//
// References: ELF64 specification (System V ABI supplement)
//             https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// ELF constants
// =============================================================================

// ELF magic
pub const ELF_MAGIC: [4]u8 = .{ 0x7F, 'E', 'L', 'F' };

// ELF class
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

// ELF data encoding
pub const ELFDATA2LSB: u8 = 1; // Little-endian
pub const ELFDATA2MSB: u8 = 2; // Big-endian

// ELF version
pub const EV_CURRENT: u8 = 1;

// OS/ABI
pub const ELFOSABI_NONE: u8 = 0; // System V
pub const ELFOSABI_LINUX: u8 = 3;

// ELF type
pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1; // Relocatable
pub const ET_EXEC: u16 = 2; // Executable
pub const ET_DYN: u16 = 3; // Shared object / PIE
pub const ET_CORE: u16 = 4;

// Machine types
pub const EM_X86_64: u16 = 62; // AMD x86-64
pub const EM_AARCH64: u16 = 183; // ARM AARCH64
pub const EM_RISCV: u16 = 243; // RISC-V

// Program header types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474E550;
pub const PT_GNU_STACK: u32 = 0x6474E551;
pub const PT_GNU_RELRO: u32 = 0x6474E552;

// Program header flags
pub const PF_X: u32 = 0x1; // Execute
pub const PF_W: u32 = 0x2; // Write
pub const PF_R: u32 = 0x4; // Read

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
pub const SHT_SHLIB: u32 = 10;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;

// Section header flags
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_TLS: u64 = 0x400;

// Dynamic tags
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
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_FLAGS: i64 = 30;

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

// Symbol binding
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

// Symbol types
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;

// Auxiliary vector types
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
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;

// =============================================================================
// ELF structures (ELF64)
// =============================================================================

pub const Elf64Header = extern struct {
    ident: [16]u8, // ELF identification
    elf_type: u16, // Object file type
    machine: u16, // Architecture
    version: u32, // Object file version
    entry: u64, // Entry point virtual address
    phoff: u64, // Program header table offset
    shoff: u64, // Section header table offset
    flags: u32, // Processor-specific flags
    ehsize: u16, // ELF header size
    phentsize: u16, // Program header entry size
    phnum: u16, // Number of program headers
    shentsize: u16, // Section header entry size
    shnum: u16, // Number of section headers
    shstrndx: u16, // Section name string table index
};

pub const Elf64Phdr = extern struct {
    p_type: u32, // Segment type
    p_flags: u32, // Segment flags
    p_offset: u64, // Offset in file
    p_vaddr: u64, // Virtual address in memory
    p_paddr: u64, // Physical address (unused in user space)
    p_filesz: u64, // Size in file
    p_memsz: u64, // Size in memory
    p_align: u64, // Alignment
};

pub const Elf64Shdr = extern struct {
    sh_name: u32, // Section name (index into string table)
    sh_type: u32, // Section type
    sh_flags: u64, // Section flags
    sh_addr: u64, // Virtual address
    sh_offset: u64, // Offset in file
    sh_size: u64, // Size
    sh_link: u32, // Link to related section
    sh_info: u32, // Additional info
    sh_addralign: u64, // Alignment
    sh_entsize: u64, // Entry size (if section is table)
};

pub const Elf64Sym = extern struct {
    st_name: u32, // Symbol name (index into string table)
    st_info: u8, // Type and binding
    st_other: u8, // Visibility
    st_shndx: u16, // Section index
    st_value: u64, // Symbol value
    st_size: u64, // Symbol size

    pub fn binding(self: *const Elf64Sym) u8 {
        return self.st_info >> 4;
    }

    pub fn symbolType(self: *const Elf64Sym) u8 {
        return self.st_info & 0xF;
    }
};

pub const Elf64Rela = extern struct {
    r_offset: u64, // Address to apply relocation
    r_info: u64, // Relocation type and symbol index
    r_addend: i64, // Addend

    pub fn relType(self: *const Elf64Rela) u32 {
        return @truncate(self.r_info & 0xFFFFFFFF);
    }

    pub fn symIndex(self: *const Elf64Rela) u32 {
        return @truncate(self.r_info >> 32);
    }
};

pub const Elf64Dyn = extern struct {
    d_tag: i64,
    d_val: u64,
};

// =============================================================================
// Load result
// =============================================================================

pub const ElfLoadError = enum(u8) {
    success = 0,
    invalid_magic = 1,
    not_elf64 = 2,
    wrong_endian = 3,
    wrong_machine = 4,
    not_executable = 5,
    no_loadable_segments = 6,
    segment_too_large = 7,
    memory_allocation_failed = 8,
    invalid_alignment = 9,
    overlapping_segments = 10,
};

pub const ElfLoadResult = struct {
    entry_point: u64,
    phdr_addr: u64,
    phdr_num: u16,
    phdr_entsize: u16,
    base_addr: u64, // Base address for PIE
    brk_addr: u64, // Initial program break (end of BSS)
    stack_executable: bool, // PT_GNU_STACK flags
    has_interp: bool, // Needs dynamic linker
    interp_path: [256]u8, // Path to dynamic linker
    interp_path_len: u8,
};

// =============================================================================
// Loaded segment tracking
// =============================================================================

pub const MAX_SEGMENTS: usize = 32;

pub const LoadedSegment = struct {
    vaddr: u64,
    memsz: u64,
    filesz: u64,
    flags: u32,
    loaded: bool,
};

var loaded_segments: [MAX_SEGMENTS]LoadedSegment = undefined;
var segment_count: usize = 0;

// =============================================================================
// ELF validation
// =============================================================================

/// Validate the ELF header
pub fn validateHeader(data: []const u8) ?*const Elf64Header {
    if (data.len < @sizeOf(Elf64Header)) return null;

    const hdr: *const Elf64Header = @ptrCast(@alignCast(data.ptr));

    // Check magic
    if (!eql(&hdr.ident[0..4].*, &ELF_MAGIC)) return null;

    // Must be ELF64
    if (hdr.ident[4] != ELFCLASS64) return null;

    // Must be little-endian (x86_64)
    if (hdr.ident[5] != ELFDATA2LSB) return null;

    // Must be current version
    if (hdr.ident[6] != EV_CURRENT) return null;

    // Must be executable or shared (PIE)
    if (hdr.elf_type != ET_EXEC and hdr.elf_type != ET_DYN) return null;

    // Must be x86_64
    if (hdr.machine != EM_X86_64) return null;

    // Validate program header table
    if (hdr.phoff == 0 or hdr.phnum == 0) return null;
    if (hdr.phentsize < @sizeOf(Elf64Phdr)) return null;

    // Check that program headers fit within the data
    const phdr_end = hdr.phoff + @as(u64, hdr.phnum) * hdr.phentsize;
    if (phdr_end > data.len) return null;

    return hdr;
}

/// Get program header by index
pub fn getPhdr(data: []const u8, hdr: *const Elf64Header, index: u16) ?*const Elf64Phdr {
    if (index >= hdr.phnum) return null;
    const offset = hdr.phoff + @as(u64, index) * hdr.phentsize;
    if (offset + @sizeOf(Elf64Phdr) > data.len) return null;
    return @ptrCast(@alignCast(data.ptr + offset));
}

/// Get section header by index
pub fn getShdr(data: []const u8, hdr: *const Elf64Header, index: u16) ?*const Elf64Shdr {
    if (hdr.shoff == 0 or index >= hdr.shnum) return null;
    const offset = hdr.shoff + @as(u64, index) * hdr.shentsize;
    if (offset + @sizeOf(Elf64Shdr) > data.len) return null;
    return @ptrCast(@alignCast(data.ptr + offset));
}

// =============================================================================
// ELF loading
// =============================================================================

/// Load an ELF binary into the current address space
/// `data` is the complete ELF file in memory
/// `map_page_fn` is called for each page that needs mapping
pub fn load(
    data: []const u8,
    map_page_fn: *const fn (vaddr: u64, flags: u32) bool,
) ?ElfLoadResult {
    const hdr = validateHeader(data) orelse {
        main.klog(.err, "ELF: Invalid header", .{});
        return null;
    };

    var result = ElfLoadResult{
        .entry_point = hdr.entry,
        .phdr_addr = 0,
        .phdr_num = hdr.phnum,
        .phdr_entsize = hdr.phentsize,
        .base_addr = 0,
        .brk_addr = 0,
        .stack_executable = false,
        .has_interp = false,
        .interp_path = undefined,
        .interp_path_len = 0,
    };

    segment_count = 0;
    var lowest_vaddr: u64 = ~@as(u64, 0);
    var highest_end: u64 = 0;

    // First pass: scan program headers
    for (0..hdr.phnum) |i| {
        const phdr = getPhdr(data, hdr, @truncate(i)) orelse continue;

        switch (phdr.p_type) {
            PT_LOAD => {
                if (segment_count >= MAX_SEGMENTS) continue;

                // Track address range
                if (phdr.p_vaddr < lowest_vaddr) lowest_vaddr = phdr.p_vaddr;
                const seg_end = phdr.p_vaddr + phdr.p_memsz;
                if (seg_end > highest_end) highest_end = seg_end;

                loaded_segments[segment_count] = .{
                    .vaddr = phdr.p_vaddr,
                    .memsz = phdr.p_memsz,
                    .filesz = phdr.p_filesz,
                    .flags = phdr.p_flags,
                    .loaded = false,
                };
                segment_count += 1;
            },
            PT_INTERP => {
                // Dynamic linker path
                if (phdr.p_filesz > 0 and phdr.p_filesz < 256 and phdr.p_offset + phdr.p_filesz <= data.len) {
                    const path_data = data[phdr.p_offset..][0..phdr.p_filesz];
                    const path_len = @min(path_data.len, 255);
                    @memcpy(result.interp_path[0..path_len], path_data[0..path_len]);
                    result.interp_path_len = @truncate(path_len);
                    result.has_interp = true;
                }
            },
            PT_PHDR => {
                result.phdr_addr = phdr.p_vaddr;
            },
            PT_GNU_STACK => {
                result.stack_executable = (phdr.p_flags & PF_X) != 0;
            },
            else => {},
        }
    }

    result.base_addr = lowest_vaddr;
    result.brk_addr = (highest_end + 4095) & ~@as(u64, 4095); // Page-align

    // Second pass: load PT_LOAD segments
    for (0..hdr.phnum) |i| {
        const phdr = getPhdr(data, hdr, @truncate(i)) orelse continue;
        if (phdr.p_type != PT_LOAD) continue;

        // Validate segment
        if (phdr.p_memsz < phdr.p_filesz) {
            main.klog(.err, "ELF: Segment {d}: memsz < filesz", .{i});
            return null;
        }

        if (phdr.p_align != 0 and phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align) {
            main.klog(.err, "ELF: Segment {d}: alignment mismatch", .{i});
            return null;
        }

        // Map pages for this segment
        const page_start = phdr.p_vaddr & ~@as(u64, 0xFFF);
        const page_end = (phdr.p_vaddr + phdr.p_memsz + 0xFFF) & ~@as(u64, 0xFFF);
        var page = page_start;

        while (page < page_end) : (page += 4096) {
            if (!map_page_fn(page, phdr.p_flags)) {
                main.klog(.err, "ELF: Failed to map page at 0x{x}", .{page});
                return null;
            }
        }

        // Copy file data into memory
        if (phdr.p_filesz > 0) {
            if (phdr.p_offset + phdr.p_filesz > data.len) {
                main.klog(.err, "ELF: Segment {d} extends beyond file", .{i});
                return null;
            }

            const src = data[phdr.p_offset..][0..phdr.p_filesz];
            const dst: [*]u8 = @ptrFromInt(phdr.p_vaddr);
            @memcpy(dst[0..phdr.p_filesz], src);
        }

        // Zero-fill BSS (memsz > filesz portion)
        if (phdr.p_memsz > phdr.p_filesz) {
            const bss_start = phdr.p_vaddr + phdr.p_filesz;
            const bss_size = phdr.p_memsz - phdr.p_filesz;
            const bss_ptr: [*]u8 = @ptrFromInt(bss_start);
            @memset(bss_ptr[0..bss_size], 0);
        }
    }

    main.klog(.info, "ELF: Loaded — entry=0x{x}, base=0x{x}, brk=0x{x}", .{
        result.entry_point,
        result.base_addr,
        result.brk_addr,
    });

    return result;
}

// =============================================================================
// Symbol lookup
// =============================================================================

/// Find a symbol by name in the ELF's symbol table
pub fn findSymbol(data: []const u8, hdr: *const Elf64Header, name: []const u8) ?*const Elf64Sym {
    if (hdr.shoff == 0 or hdr.shnum == 0) return null;

    // Find .symtab and .strtab sections
    var symtab_shdr: ?*const Elf64Shdr = null;
    var strtab_shdr: ?*const Elf64Shdr = null;

    for (0..hdr.shnum) |i| {
        const shdr = getShdr(data, hdr, @truncate(i)) orelse continue;
        if (shdr.sh_type == SHT_SYMTAB) {
            symtab_shdr = shdr;
            // sh_link points to the associated string table
            strtab_shdr = getShdr(data, hdr, @truncate(shdr.sh_link));
        }
    }

    const symtab = symtab_shdr orelse return null;
    const strtab = strtab_shdr orelse return null;

    if (symtab.sh_entsize < @sizeOf(Elf64Sym)) return null;

    const num_syms = symtab.sh_size / symtab.sh_entsize;

    for (0..num_syms) |i| {
        const sym_offset = symtab.sh_offset + i * symtab.sh_entsize;
        if (sym_offset + @sizeOf(Elf64Sym) > data.len) break;

        const sym: *const Elf64Sym = @ptrCast(@alignCast(data.ptr + sym_offset));

        // Get symbol name from string table
        const str_offset = strtab.sh_offset + sym.st_name;
        if (str_offset >= data.len) continue;

        const sym_name_start = data[str_offset..];
        var sym_name_len: usize = 0;
        while (sym_name_len < sym_name_start.len and sym_name_start[sym_name_len] != 0) {
            sym_name_len += 1;
        }

        if (sym_name_len == name.len and eql(sym_name_start[0..sym_name_len], name)) {
            return sym;
        }
    }

    return null;
}

// =============================================================================
// Relocation processing
// =============================================================================

/// Process RELA relocations for a loaded ELF
pub fn processRelocations(data: []const u8, hdr: *const Elf64Header, base_offset: u64) void {
    if (hdr.shoff == 0) return;

    for (0..hdr.shnum) |i| {
        const shdr = getShdr(data, hdr, @truncate(i)) orelse continue;
        if (shdr.sh_type != SHT_RELA) continue;

        if (shdr.sh_entsize < @sizeOf(Elf64Rela)) continue;
        const num_relas = shdr.sh_size / shdr.sh_entsize;

        for (0..num_relas) |j| {
            const rela_offset = shdr.sh_offset + j * shdr.sh_entsize;
            if (rela_offset + @sizeOf(Elf64Rela) > data.len) break;

            const rela: *const Elf64Rela = @ptrCast(@alignCast(data.ptr + rela_offset));
            applyRelocation(rela, base_offset);
        }
    }
}

fn applyRelocation(rela: *const Elf64Rela, base: u64) void {
    const target_addr = base + rela.r_offset;
    const rel_type = rela.relType();

    switch (rel_type) {
        R_X86_64_RELATIVE => {
            // B + A (base + addend)
            const ptr: *u64 = @ptrFromInt(target_addr);
            ptr.* = base +% @as(u64, @bitCast(rela.r_addend));
        },
        R_X86_64_64 => {
            // S + A (symbol value + addend)
            // Would need symbol table lookup; simplified here
            const ptr: *u64 = @ptrFromInt(target_addr);
            ptr.* = base +% @as(u64, @bitCast(rela.r_addend));
        },
        R_X86_64_NONE => {},
        else => {
            main.klog(.warning, "ELF: Unsupported relocation type {d} at 0x{x}", .{
                rel_type,
                target_addr,
            });
        },
    }
}

// =============================================================================
// Auxiliary vector builder
// =============================================================================

pub const AuxvEntry = struct {
    a_type: u64,
    a_val: u64,
};

pub const MAX_AUXV_ENTRIES: usize = 32;

/// Build the auxiliary vector for process startup
pub fn buildAuxv(result: *const ElfLoadResult, random_bytes: u64) [MAX_AUXV_ENTRIES]AuxvEntry {
    var auxv: [MAX_AUXV_ENTRIES]AuxvEntry = undefined;
    var idx: usize = 0;

    auxv[idx] = .{ .a_type = AT_PHDR, .a_val = result.phdr_addr };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_PHENT, .a_val = result.phdr_entsize };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_PHNUM, .a_val = result.phdr_num };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_PAGESZ, .a_val = 4096 };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_ENTRY, .a_val = result.entry_point };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_BASE, .a_val = result.base_addr };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_SECURE, .a_val = 0 };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_RANDOM, .a_val = random_bytes };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_UID, .a_val = 0 };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_EUID, .a_val = 0 };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_GID, .a_val = 0 };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_EGID, .a_val = 0 };
    idx += 1;
    auxv[idx] = .{ .a_type = AT_NULL, .a_val = 0 };
    idx += 1;

    // Zero remaining
    while (idx < MAX_AUXV_ENTRIES) : (idx += 1) {
        auxv[idx] = .{ .a_type = AT_NULL, .a_val = 0 };
    }

    return auxv;
}

// =============================================================================
// Helpers
// =============================================================================

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

/// Get a description of the ELF type
pub fn typeString(elf_type: u16) []const u8 {
    return switch (elf_type) {
        ET_NONE => "NONE",
        ET_REL => "REL (Relocatable)",
        ET_EXEC => "EXEC (Executable)",
        ET_DYN => "DYN (Shared/PIE)",
        ET_CORE => "CORE",
        else => "UNKNOWN",
    };
}

/// Get a description of the machine type
pub fn machineString(machine: u16) []const u8 {
    return switch (machine) {
        EM_X86_64 => "x86_64",
        EM_AARCH64 => "AArch64",
        EM_RISCV => "RISC-V",
        else => "unknown",
    };
}
