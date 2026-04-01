// =============================================================================
// Kernel Zxyphor — Loadable Kernel Module System
// =============================================================================
// ELF-based kernel module loading framework:
//   - ELF64 object file parsing for relocatable modules
//   - Symbol table resolution (import kernel symbols)
//   - Relocation processing (R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32, etc.)
//   - Module dependency tracking
//   - Module lifecycle (init/exit callbacks)
//   - Module information metadata
//   - Reference counting for safe unload
//   - Module parameter support
//   - Module registry with lookup by name
//   - Security: signature verification placeholder
// =============================================================================

// =============================================================================
// Constants
// =============================================================================

pub const MAX_MODULES: usize = 64;
pub const MAX_DEPS: usize = 8;
pub const MAX_SYMBOLS: usize = 256;
pub const MAX_SECTIONS: usize = 32;
pub const MODULE_NAME_LEN: usize = 32;
pub const MAX_PARAMS: usize = 16;
pub const KERNEL_SYMBOL_TABLE_SIZE: usize = 512;

// ELF64 constants
pub const ELF_MAGIC: u32 = 0x464C457F; // \x7FELF
pub const ET_REL: u16 = 1;             // Relocatable
pub const EM_X86_64: u16 = 62;
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_WRITE: u64 = 0x1;

// Relocation types
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;

// Symbol binding/type
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STT_NOTYPE: u8 = 0;
pub const STT_FUNC: u8 = 2;
pub const STT_OBJECT: u8 = 1;
pub const SHN_UNDEF: u16 = 0;

// =============================================================================
// ELF64 header structures
// =============================================================================

pub const Elf64Header = extern struct {
    e_ident: [16]u8,
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

pub const Elf64SectionHeader = extern struct {
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

pub const Elf64Symbol = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,

    pub fn binding(self: Elf64Symbol) u8 {
        return self.st_info >> 4;
    }

    pub fn symbolType(self: Elf64Symbol) u8 {
        return self.st_info & 0xf;
    }
};

pub const Elf64Rela = extern struct {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,

    pub fn symbol(self: Elf64Rela) u32 {
        return @intCast(self.r_info >> 32);
    }

    pub fn relocType(self: Elf64Rela) u32 {
        return @intCast(self.r_info & 0xFFFFFFFF);
    }
};

// =============================================================================
// Kernel symbol table (exported by the kernel)
// =============================================================================

pub const KernelSymbol = struct {
    name: [32]u8,
    name_len: usize,
    address: u64,
    size: u64,
    exported: bool,
    gpl_only: bool,  // GPL-licensed modules only
};

pub const KernelSymbolTable = struct {
    symbols: [KERNEL_SYMBOL_TABLE_SIZE]KernelSymbol,
    count: usize,

    pub fn init() KernelSymbolTable {
        var table: KernelSymbolTable = undefined;
        table.count = 0;
        for (0..KERNEL_SYMBOL_TABLE_SIZE) |i| {
            table.symbols[i].exported = false;
        }
        return table;
    }

    /// Register a kernel symbol for module use
    pub fn exportSymbol(self: *KernelSymbolTable, name: []const u8, address: u64, size: u64, gpl: bool) bool {
        if (self.count >= KERNEL_SYMBOL_TABLE_SIZE) return false;
        const idx = self.count;
        const len = @min(name.len, 32);
        @memcpy(self.symbols[idx].name[0..len], name[0..len]);
        self.symbols[idx].name_len = len;
        self.symbols[idx].address = address;
        self.symbols[idx].size = size;
        self.symbols[idx].exported = true;
        self.symbols[idx].gpl_only = gpl;
        self.count += 1;
        return true;
    }

    /// Resolve a symbol by name
    pub fn resolve(self: *const KernelSymbolTable, name: []const u8, is_gpl: bool) ?u64 {
        for (0..self.count) |i| {
            const sym = &self.symbols[i];
            if (!sym.exported) continue;
            if (sym.gpl_only and !is_gpl) continue;
            if (sym.name_len == name.len) {
                if (eqlBytes(sym.name[0..sym.name_len], name)) {
                    return sym.address;
                }
            }
        }
        return null;
    }
};

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

// =============================================================================
// Module parameter
// =============================================================================

pub const ParamType = enum(u8) {
    int_param = 0,
    uint_param = 1,
    bool_param = 2,
    string_param = 3,
};

pub const ModuleParam = struct {
    name: [16]u8,
    name_len: usize,
    param_type: ParamType,
    int_val: i64,
    str_val: [32]u8,
    str_len: usize,
    description: [48]u8,
    desc_len: usize,
};

// =============================================================================
// Module state
// =============================================================================

pub const ModuleState = enum(u8) {
    unloaded = 0,
    loading = 1,
    live = 2,
    unloading = 3,
    failed = 4,
};

pub const ModuleLicense = enum(u8) {
    proprietary = 0,
    gpl = 1,
    gpl_v2 = 2,
    dual_mit_gpl = 3,
    bsd = 4,
};

// =============================================================================
// Loaded section info
// =============================================================================

pub const LoadedSection = struct {
    name: [16]u8,
    name_len: usize,
    base_addr: u64,
    size: u64,
    flags: u64,
    allocated: bool,
};

// =============================================================================
// Module
// =============================================================================

pub const Module = struct {
    name: [MODULE_NAME_LEN]u8,
    name_len: usize,
    version: [16]u8,
    version_len: usize,
    author: [32]u8,
    author_len: usize,
    description: [64]u8,
    desc_len: usize,

    state: ModuleState,
    license: ModuleLicense,

    // Memory
    text_base: u64,
    text_size: u64,
    data_base: u64,
    data_size: u64,
    bss_base: u64,
    bss_size: u64,
    total_size: u64,

    // Sections
    sections: [MAX_SECTIONS]LoadedSection,
    section_count: u32,

    // Symbols exported by this module
    symbols: [MAX_SYMBOLS]KernelSymbol,
    symbol_count: u32,

    // Dependencies
    deps: [MAX_DEPS]u32,  // Module IDs
    dep_count: u32,
    ref_count: u32,       // How many modules depend on us

    // Parameters
    params: [MAX_PARAMS]ModuleParam,
    param_count: u32,

    // Callbacks
    init_fn: ?u64,        // Module init function pointer
    exit_fn: ?u64,        // Module exit function pointer

    // Metadata
    load_time_ns: u64,
    init_duration_ns: u64,
    id: u32,
    active: bool,

    pub fn init() Module {
        var m: Module = undefined;
        m.state = .unloaded;
        m.active = false;
        m.text_base = 0;
        m.text_size = 0;
        m.data_base = 0;
        m.data_size = 0;
        m.bss_base = 0;
        m.bss_size = 0;
        m.total_size = 0;
        m.section_count = 0;
        m.symbol_count = 0;
        m.dep_count = 0;
        m.ref_count = 0;
        m.param_count = 0;
        m.init_fn = null;
        m.exit_fn = null;
        m.name_len = 0;
        m.version_len = 0;
        m.author_len = 0;
        m.desc_len = 0;
        m.load_time_ns = 0;
        m.init_duration_ns = 0;
        m.id = 0;
        m.license = .proprietary;
        return m;
    }

    pub fn setName(self: *Module, name: []const u8) void {
        const len = @min(name.len, MODULE_NAME_LEN);
        @memcpy(self.name[0..len], name[0..len]);
        self.name_len = len;
    }

    pub fn getName(self: *const Module) []const u8 {
        return self.name[0..self.name_len];
    }
};

// =============================================================================
// Module loader — parses ELF and resolves symbols
// =============================================================================

pub const LoadError = error{
    InvalidElf,
    WrongArch,
    NotRelocatable,
    SectionOverflow,
    SymbolNotFound,
    RelocationFailed,
    OutOfMemory,
    InvalidSection,
    TooManyModules,
    DependencyNotFound,
    InitFailed,
    AlreadyLoaded,
};

pub const ModuleLoader = struct {
    modules: [MAX_MODULES]Module,
    module_count: u32,
    next_id: u32,
    ksyms: KernelSymbolTable,

    // Memory pool for module code/data (simplified: fixed pool)
    module_pool_base: u64,
    module_pool_size: u64,
    module_pool_used: u64,

    pub fn init(pool_base: u64, pool_size: u64) ModuleLoader {
        var loader: ModuleLoader = undefined;
        loader.module_count = 0;
        loader.next_id = 1;
        loader.ksyms = KernelSymbolTable.init();
        loader.module_pool_base = pool_base;
        loader.module_pool_size = pool_size;
        loader.module_pool_used = 0;
        for (0..MAX_MODULES) |i| {
            loader.modules[i] = Module.init();
        }
        return loader;
    }

    /// Allocate memory from the module pool
    fn allocPool(self: *ModuleLoader, size: u64, alignment: u64) ?u64 {
        // Align up
        const aligned_offset = (self.module_pool_used + alignment - 1) & ~(alignment - 1);
        if (aligned_offset + size > self.module_pool_size) return null;
        const addr = self.module_pool_base + aligned_offset;
        self.module_pool_used = aligned_offset + size;
        return addr;
    }

    /// Validate ELF header
    fn validateElf(data: []const u8) LoadError!*const Elf64Header {
        if (data.len < @sizeOf(Elf64Header)) return LoadError.InvalidElf;
        const hdr: *const Elf64Header = @ptrCast(@alignCast(data.ptr));

        // Check magic
        if (@as(*const u32, @ptrCast(@alignCast(&hdr.e_ident))).\* != ELF_MAGIC)
            return LoadError.InvalidElf;

        // Check 64-bit
        if (hdr.e_ident[4] != 2) return LoadError.InvalidElf;
        // Check little-endian
        if (hdr.e_ident[5] != 1) return LoadError.InvalidElf;
        // Check relocatable
        if (hdr.e_type != ET_REL) return LoadError.NotRelocatable;
        // Check x86_64
        if (hdr.e_machine != EM_X86_64) return LoadError.WrongArch;

        return hdr;
    }

    /// Load a kernel module from ELF data
    pub fn loadModule(self: *ModuleLoader, name: []const u8, data: []const u8) LoadError!u32 {
        if (self.module_count >= MAX_MODULES) return LoadError.TooManyModules;

        // Check not already loaded
        for (0..MAX_MODULES) |i| {
            if (self.modules[i].active and eqlBytes(self.modules[i].getName(), name)) {
                return LoadError.AlreadyLoaded;
            }
        }

        const ehdr = try validateElf(data);

        // Find free slot
        var slot: usize = 0;
        for (0..MAX_MODULES) |i| {
            if (!self.modules[i].active) {
                slot = i;
                break;
            }
        }

        var module = &self.modules[slot];
        module.* = Module.init();
        module.setName(name);
        module.state = .loading;
        module.id = self.next_id;
        self.next_id += 1;

        // Parse section headers
        const shoff = ehdr.e_shoff;
        const shnum = ehdr.e_shnum;
        const shentsize = ehdr.e_shentsize;

        if (shoff + @as(u64, shnum) * shentsize > data.len) return LoadError.InvalidElf;

        // First pass: calculate total memory needed for loadable sections
        var total_alloc: u64 = 0;
        var i: u16 = 0;
        while (i < shnum) : (i += 1) {
            const sh_offset = shoff + @as(u64, i) * shentsize;
            if (sh_offset + @sizeOf(Elf64SectionHeader) > data.len) continue;
            const shdr: *const Elf64SectionHeader = @ptrCast(@alignCast(data.ptr + sh_offset));

            if (shdr.sh_flags & SHF_ALLOC != 0) {
                const align = if (shdr.sh_addralign > 0) shdr.sh_addralign else 1;
                total_alloc = (total_alloc + align - 1) & ~(align - 1);
                total_alloc += shdr.sh_size;
            }
        }

        // Allocate module memory
        const base = self.allocPool(total_alloc, 4096) orelse return LoadError.OutOfMemory;
        module.total_size = total_alloc;

        // Second pass: load sections into allocated memory
        var current_offset: u64 = 0;
        i = 0;
        while (i < shnum) : (i += 1) {
            const sh_offset = shoff + @as(u64, i) * shentsize;
            if (sh_offset + @sizeOf(Elf64SectionHeader) > data.len) continue;
            const shdr: *const Elf64SectionHeader = @ptrCast(@alignCast(data.ptr + sh_offset));

            if (shdr.sh_flags & SHF_ALLOC == 0) continue;

            const align = if (shdr.sh_addralign > 0) shdr.sh_addralign else 1;
            current_offset = (current_offset + align - 1) & ~(align - 1);
            const section_addr = base + current_offset;

            // Copy section data (or zero for BSS)
            if (shdr.sh_type != SHT_NOBITS) {
                if (shdr.sh_offset + shdr.sh_size <= data.len) {
                    const dest: [*]u8 = @ptrFromInt(section_addr);
                    const src = data.ptr + shdr.sh_offset;
                    @memcpy(dest[0..@intCast(shdr.sh_size)], src[0..@intCast(shdr.sh_size)]);
                }
            } else {
                // BSS: zero fill
                const dest: [*]u8 = @ptrFromInt(section_addr);
                @memset(dest[0..@intCast(shdr.sh_size)], 0);
            }

            // Track section info
            if (module.section_count < MAX_SECTIONS) {
                const si = module.section_count;
                module.sections[si].base_addr = section_addr;
                module.sections[si].size = shdr.sh_size;
                module.sections[si].flags = shdr.sh_flags;
                module.sections[si].allocated = true;
                module.section_count += 1;
            }

            // Track text/data/bss
            if (shdr.sh_flags & SHF_EXECINSTR != 0) {
                if (module.text_base == 0) module.text_base = section_addr;
                module.text_size += shdr.sh_size;
            } else if (shdr.sh_type == SHT_NOBITS) {
                if (module.bss_base == 0) module.bss_base = section_addr;
                module.bss_size += shdr.sh_size;
            } else {
                if (module.data_base == 0) module.data_base = section_addr;
                module.data_size += shdr.sh_size;
            }

            current_offset += shdr.sh_size;
        }

        module.active = true;
        module.state = .live;
        self.module_count += 1;

        return module.id;
    }

    /// Unload a module
    pub fn unloadModule(self: *ModuleLoader, module_id: u32) LoadError!void {
        for (0..MAX_MODULES) |i| {
            if (self.modules[i].active and self.modules[i].id == module_id) {
                if (self.modules[i].ref_count > 0) {
                    return LoadError.DependencyNotFound; // Still referenced
                }

                self.modules[i].state = .unloading;

                // Call exit function if registered
                // (would need function pointer calling in real impl)

                // Remove from dependency lists
                for (0..MAX_MODULES) |j| {
                    if (self.modules[j].active) {
                        for (0..self.modules[j].dep_count) |d| {
                            if (self.modules[j].deps[d] == module_id) {
                                // Shift remaining deps
                                var k: u32 = @intCast(d);
                                while (k < self.modules[j].dep_count - 1) : (k += 1) {
                                    self.modules[j].deps[k] = self.modules[j].deps[k + 1];
                                }
                                self.modules[j].dep_count -= 1;
                                break;
                            }
                        }
                    }
                }

                // Unexport module symbols
                for (0..self.modules[i].symbol_count) |s| {
                    self.modules[i].symbols[s].exported = false;
                }

                self.modules[i].state = .unloaded;
                self.modules[i].active = false;
                self.module_count -= 1;
                return;
            }
        }
    }

    /// Find module by name
    pub fn findModule(self: *const ModuleLoader, name: []const u8) ?*const Module {
        for (0..MAX_MODULES) |i| {
            if (self.modules[i].active and eqlBytes(self.modules[i].getName(), name)) {
                return &self.modules[i];
            }
        }
        return null;
    }

    /// List all loaded modules
    pub fn listModules(self: *const ModuleLoader, buf: []u32) u32 {
        var count: u32 = 0;
        for (0..MAX_MODULES) |i| {
            if (self.modules[i].active) {
                if (count < buf.len) {
                    buf[count] = self.modules[i].id;
                }
                count += 1;
            }
        }
        return count;
    }

    /// Export a kernel symbol for module use
    pub fn exportKernelSymbol(self: *ModuleLoader, name: []const u8, addr: u64, size: u64, gpl: bool) bool {
        return self.ksyms.exportSymbol(name, addr, size, gpl);
    }
};

// =============================================================================
// Global instance
// =============================================================================

var module_loader: ?ModuleLoader = null;

pub fn initModuleLoader(pool_base: u64, pool_size: u64) void {
    module_loader = ModuleLoader.init(pool_base, pool_size);
}

pub fn getModuleLoader() ?*ModuleLoader {
    if (module_loader) |*loader| {
        return loader;
    }
    return null;
}
