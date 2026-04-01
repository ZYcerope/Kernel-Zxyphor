// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Zig Kernel Module Loader
//
// Implements a loadable kernel module framework:
// - ELF object parsing for relocatable modules
// - Symbol resolution against kernel symbol table
// - Module dependency tracking
// - Module parameters
// - Reference counting for safe unloading
// - Init/exit callbacks
// - Module information metadata
// - License verification tag

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_MODULES = 256;
pub const MAX_SYMBOLS = 4096;
pub const MAX_DEPS = 16;
pub const MAX_PARAMS = 32;
pub const MODULE_NAME_MAX = 64;
pub const SYMBOL_NAME_MAX = 128;
pub const MODULE_VERSION_MAX = 32;
pub const MODULE_AUTHOR_MAX = 64;
pub const MODULE_DESC_MAX = 128;
pub const MODULE_LICENSE_MAX = 32;

// ─────────────────── Module State ───────────────────────────────────
pub const ModuleState = enum(u8) {
    unloaded,
    loading,
    live,
    going,     // Being removed
    coming,    // Being loaded
};

// ─────────────────── Symbol Types ───────────────────────────────────
pub const SymbolType = enum(u8) {
    function,
    data,
    rodata,
    bss,
    undef,
};

pub const SymbolVisibility = enum(u8) {
    local,
    global_,
    weak,
    exported,
};

pub const KernelSymbol = struct {
    name: [SYMBOL_NAME_MAX]u8 = [_]u8{0} ** SYMBOL_NAME_MAX,
    name_len: u16 = 0,
    addr: u64 = 0,
    size: u64 = 0,
    sym_type: SymbolType = .function,
    visibility: SymbolVisibility = .global_,
    module_id: u32 = 0, // 0 = kernel core

    pub fn set_name(self: *KernelSymbol, n: []const u8) void {
        const len = @min(n.len, SYMBOL_NAME_MAX);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn get_name(self: *const KernelSymbol) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn matches_name(self: *const KernelSymbol, n: []const u8) bool {
        if (self.name_len != n.len) return false;
        const own_name = self.name[0..self.name_len];
        return std.mem.eql(u8, own_name, n);
    }
};

// ─────────────────── Module Parameters ──────────────────────────────
pub const ParamType = enum(u8) {
    bool_,
    int,
    uint,
    string,
    charp,
};

pub const ParamValue = union {
    bool_val: bool,
    int_val: i64,
    uint_val: u64,
    str_val: [64]u8,
};

pub const ModuleParam = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    param_type: ParamType = .int,
    value: ParamValue = .{ .int_val = 0 },
    description: [64]u8 = [_]u8{0} ** 64,
    desc_len: u8 = 0,
    permissions: u16 = 0o644,

    pub fn set_name(self: *ModuleParam, n: []const u8) void {
        const len = @min(n.len, 32);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn set_desc(self: *ModuleParam, d: []const u8) void {
        const len = @min(d.len, 64);
        @memcpy(self.description[0..len], d[0..len]);
        self.desc_len = @intCast(len);
    }

    pub fn set_int(self: *ModuleParam, val: i64) void {
        self.param_type = .int;
        self.value = .{ .int_val = val };
    }

    pub fn set_bool(self: *ModuleParam, val: bool) void {
        self.param_type = .bool_;
        self.value = .{ .bool_val = val };
    }

    pub fn set_uint(self: *ModuleParam, val: u64) void {
        self.param_type = .uint;
        self.value = .{ .uint_val = val };
    }
};

// ─────────────────── Module Metadata ────────────────────────────────
pub const ModuleInfo = struct {
    name: [MODULE_NAME_MAX]u8 = [_]u8{0} ** MODULE_NAME_MAX,
    name_len: u8 = 0,
    version: [MODULE_VERSION_MAX]u8 = [_]u8{0} ** MODULE_VERSION_MAX,
    version_len: u8 = 0,
    author: [MODULE_AUTHOR_MAX]u8 = [_]u8{0} ** MODULE_AUTHOR_MAX,
    author_len: u8 = 0,
    description: [MODULE_DESC_MAX]u8 = [_]u8{0} ** MODULE_DESC_MAX,
    desc_len: u8 = 0,
    license: [MODULE_LICENSE_MAX]u8 = [_]u8{0} ** MODULE_LICENSE_MAX,
    license_len: u8 = 0,

    pub fn set_name(self: *ModuleInfo, n: []const u8) void {
        const len = @min(n.len, MODULE_NAME_MAX);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn set_version(self: *ModuleInfo, v: []const u8) void {
        const len = @min(v.len, MODULE_VERSION_MAX);
        @memcpy(self.version[0..len], v[0..len]);
        self.version_len = @intCast(len);
    }

    pub fn set_author(self: *ModuleInfo, a: []const u8) void {
        const len = @min(a.len, MODULE_AUTHOR_MAX);
        @memcpy(self.author[0..len], a[0..len]);
        self.author_len = @intCast(len);
    }

    pub fn set_description(self: *ModuleInfo, d: []const u8) void {
        const len = @min(d.len, MODULE_DESC_MAX);
        @memcpy(self.description[0..len], d[0..len]);
        self.desc_len = @intCast(len);
    }

    pub fn set_license(self: *ModuleInfo, l: []const u8) void {
        const len = @min(l.len, MODULE_LICENSE_MAX);
        @memcpy(self.license[0..len], l[0..len]);
        self.license_len = @intCast(len);
    }

    pub fn get_name(self: *const ModuleInfo) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn is_gpl_compatible(self: *const ModuleInfo) bool {
        const lic = self.license[0..self.license_len];
        return std.mem.eql(u8, lic, "GPL") or
            std.mem.eql(u8, lic, "GPL v2") or
            std.mem.eql(u8, lic, "GPL and additional rights") or
            std.mem.eql(u8, lic, "Dual BSD/GPL") or
            std.mem.eql(u8, lic, "Dual MIT/GPL") or
            std.mem.eql(u8, lic, "MIT");
    }
};

// ─────────────────── Module Section ─────────────────────────────────
pub const SectionType = enum(u8) {
    text,
    data,
    rodata,
    bss,
    init_text,
    exit_text,
    symtab,
    strtab,
    rela,
    other,
};

pub const ModuleSection = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    sec_type: SectionType = .other,
    addr: u64 = 0,
    size: u64 = 0,
    alignment: u32 = 1,
    flags: u32 = 0,

    pub fn set_name(self: *ModuleSection, n: []const u8) void {
        const len = @min(n.len, 32);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }
};

// ─────────────────── Loadable Module ────────────────────────────────
pub const InitFn = *const fn () i32;
pub const ExitFn = *const fn () void;

pub const Module = struct {
    /// Module ID
    id: u32 = 0,
    /// Module state
    state: ModuleState = .unloaded,
    /// Module metadata
    info: ModuleInfo = .{},
    /// Reference count
    ref_count: u32 = 0,
    /// Module dependencies (IDs of modules this depends on)
    deps: [MAX_DEPS]u32 = [_]u32{0} ** MAX_DEPS,
    dep_count: u8 = 0,
    /// Modules that depend on this one
    users: [MAX_DEPS]u32 = [_]u32{0} ** MAX_DEPS,
    user_count: u8 = 0,
    /// Parameters
    params: [MAX_PARAMS]?ModuleParam = [_]?ModuleParam{null} ** MAX_PARAMS,
    param_count: u8 = 0,
    /// Sections allocated for this module
    sections: [16]?ModuleSection = [_]?ModuleSection{null} ** 16,
    section_count: u8 = 0,
    /// Symbols defined by this module
    symbols: [128]?KernelSymbol = [_]?KernelSymbol{null} ** 128,
    symbol_count: u16 = 0,
    /// Module memory region
    base_addr: u64 = 0,
    text_size: u64 = 0,
    data_size: u64 = 0,
    total_size: u64 = 0,
    /// Init/exit function pointers
    init_fn_addr: u64 = 0,
    exit_fn_addr: u64 = 0,
    /// Timestamps
    load_time: u64 = 0,

    pub fn add_dependency(self: *Module, dep_id: u32) bool {
        if (self.dep_count >= MAX_DEPS) return false;
        self.deps[self.dep_count] = dep_id;
        self.dep_count += 1;
        return true;
    }

    pub fn add_user(self: *Module, user_id: u32) bool {
        if (self.user_count >= MAX_DEPS) return false;
        self.users[self.user_count] = user_id;
        self.user_count += 1;
        return true;
    }

    pub fn remove_user(self: *Module, user_id: u32) bool {
        for (self.users[0..self.user_count], 0..) |uid, i| {
            if (uid == user_id) {
                // Shift remaining
                var j = i;
                while (j + 1 < self.user_count) : (j += 1) {
                    self.users[j] = self.users[j + 1];
                }
                self.user_count -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn add_param(self: *Module, param: ModuleParam) bool {
        if (self.param_count >= MAX_PARAMS) return false;
        self.params[self.param_count] = param;
        self.param_count += 1;
        return true;
    }

    pub fn add_symbol(self: *Module, sym: KernelSymbol) bool {
        if (self.symbol_count >= 128) return false;
        self.symbols[self.symbol_count] = sym;
        self.symbol_count += 1;
        return true;
    }

    pub fn add_section(self: *Module, sec: ModuleSection) bool {
        if (self.section_count >= 16) return false;
        self.sections[self.section_count] = sec;
        self.section_count += 1;
        return true;
    }

    pub fn acquire(self: *Module) void {
        self.ref_count += 1;
    }

    pub fn try_release(self: *Module) bool {
        if (self.ref_count > 0) {
            self.ref_count -= 1;
        }
        return self.ref_count == 0;
    }

    pub fn can_unload(self: *const Module) bool {
        return self.ref_count == 0 and self.user_count == 0 and self.state == .live;
    }

    pub fn find_symbol(self: *const Module, name: []const u8) ?*const KernelSymbol {
        for (self.symbols[0..self.symbol_count]) |*maybe_sym| {
            if (maybe_sym.*) |*sym| {
                if (sym.matches_name(name)) return sym;
            }
        }
        return null;
    }
};

// ─────────────────── Module Loader ──────────────────────────────────
pub const LoadError = enum(u8) {
    success,
    no_memory,
    invalid_elf,
    symbol_not_found,
    duplicate_module,
    dependency_missing,
    init_failed,
    license_error,
    too_many_modules,
    invalid_param,
    section_error,
    relocation_error,
};

pub const ModuleLoader = struct {
    modules: [MAX_MODULES]?Module = [_]?Module{null} ** MAX_MODULES,
    module_count: u32 = 0,
    next_id: u32 = 1,

    /// Global kernel symbol table
    kernel_symbols: [MAX_SYMBOLS]?KernelSymbol = [_]?KernelSymbol{null} ** MAX_SYMBOLS,
    kernel_symbol_count: u32 = 0,

    /// Statistics
    total_loaded: u64 = 0,
    total_unloaded: u64 = 0,
    total_failed: u64 = 0,
    total_memory_used: u64 = 0,

    pub fn init(self: *ModuleLoader) void {
        // Register core kernel symbols
        self.register_core_symbols();
    }

    fn register_core_symbols(self: *ModuleLoader) void {
        // Register essential kernel API symbols
        const core_syms = [_]struct { name: []const u8, addr: u64 }{
            .{ .name = "kmalloc", .addr = 0xFFFF800000100000 },
            .{ .name = "kfree", .addr = 0xFFFF800000100100 },
            .{ .name = "printk", .addr = 0xFFFF800000100200 },
            .{ .name = "register_chrdev", .addr = 0xFFFF800000100300 },
            .{ .name = "unregister_chrdev", .addr = 0xFFFF800000100400 },
            .{ .name = "request_irq", .addr = 0xFFFF800000100500 },
            .{ .name = "free_irq", .addr = 0xFFFF800000100600 },
            .{ .name = "alloc_pages", .addr = 0xFFFF800000100700 },
            .{ .name = "free_pages", .addr = 0xFFFF800000100800 },
            .{ .name = "ioremap", .addr = 0xFFFF800000100900 },
            .{ .name = "iounmap", .addr = 0xFFFF800000100A00 },
            .{ .name = "mutex_lock", .addr = 0xFFFF800000100B00 },
            .{ .name = "mutex_unlock", .addr = 0xFFFF800000100C00 },
            .{ .name = "spin_lock", .addr = 0xFFFF800000100D00 },
            .{ .name = "spin_unlock", .addr = 0xFFFF800000100E00 },
            .{ .name = "schedule", .addr = 0xFFFF800000100F00 },
            .{ .name = "schedule_timeout", .addr = 0xFFFF800000101000 },
            .{ .name = "wake_up", .addr = 0xFFFF800000101100 },
            .{ .name = "copy_from_user", .addr = 0xFFFF800000101200 },
            .{ .name = "copy_to_user", .addr = 0xFFFF800000101300 },
            .{ .name = "dma_alloc_coherent", .addr = 0xFFFF800000101400 },
            .{ .name = "dma_free_coherent", .addr = 0xFFFF800000101500 },
            .{ .name = "pci_register_driver", .addr = 0xFFFF800000101600 },
            .{ .name = "pci_unregister_driver", .addr = 0xFFFF800000101700 },
            .{ .name = "timer_setup", .addr = 0xFFFF800000101800 },
            .{ .name = "mod_timer", .addr = 0xFFFF800000101900 },
            .{ .name = "del_timer", .addr = 0xFFFF800000101A00 },
        };

        for (core_syms) |cs| {
            var sym = KernelSymbol{};
            sym.set_name(cs.name);
            sym.addr = cs.addr;
            sym.sym_type = .function;
            sym.visibility = .exported;
            self.register_kernel_symbol(sym);
        }
    }

    pub fn register_kernel_symbol(self: *ModuleLoader, sym: KernelSymbol) bool {
        if (self.kernel_symbol_count >= MAX_SYMBOLS) return false;
        for (&self.kernel_symbols) |*slot| {
            if (slot.* == null) {
                slot.* = sym;
                self.kernel_symbol_count += 1;
                return true;
            }
        }
        return false;
    }

    /// Resolve a symbol by name against the global symbol table
    pub fn resolve_symbol(self: *const ModuleLoader, name: []const u8) ?u64 {
        // Search kernel symbols
        for (&self.kernel_symbols) |*slot| {
            if (slot.*) |*sym| {
                if (sym.matches_name(name)) return sym.addr;
            }
        }
        // Search module-exported symbols
        for (&self.modules) |*slot| {
            if (slot.*) |*mod| {
                if (mod.state == .live) {
                    if (mod.find_symbol(name)) |sym| {
                        return sym.addr;
                    }
                }
            }
        }
        return null;
    }

    /// Load a module from an ELF binary image
    pub fn load_module(self: *ModuleLoader, elf_data: []const u8, name: []const u8) LoadError {
        if (self.module_count >= MAX_MODULES) return .too_many_modules;

        // Check for duplicate
        for (&self.modules) |*slot| {
            if (slot.*) |*mod| {
                if (std.mem.eql(u8, mod.info.get_name(), name)) {
                    return .duplicate_module;
                }
            }
        }

        // Validate ELF header
        if (elf_data.len < 64) return .invalid_elf;
        if (elf_data[0] != 0x7F or elf_data[1] != 'E' or elf_data[2] != 'L' or elf_data[3] != 'F') {
            return .invalid_elf;
        }

        // Must be 64-bit ELF
        if (elf_data[4] != 2) return .invalid_elf;

        // Must be relocatable (type ET_REL = 1)
        const e_type = @as(u16, elf_data[16]) | (@as(u16, elf_data[17]) << 8);
        if (e_type != 1) return .invalid_elf;

        const id = self.next_id;
        self.next_id += 1;

        var mod = Module{};
        mod.id = id;
        mod.state = .loading;
        mod.info.set_name(name);

        // Parse ELF sections (simplified)
        const e_shoff = read_u64_le(elf_data[40..48]);
        const e_shentsize = @as(u16, elf_data[58]) | (@as(u16, elf_data[59]) << 8);
        const e_shnum = @as(u16, elf_data[60]) | (@as(u16, elf_data[61]) << 8);
        _ = e_shoff;
        _ = e_shentsize;

        // Record section info
        var text_sec = ModuleSection{};
        text_sec.set_name(".text");
        text_sec.sec_type = .text;
        text_sec.size = @intCast(elf_data.len / 4); // Approximate
        _ = mod.add_section(text_sec);

        mod.total_size = elf_data.len;
        mod.text_size = elf_data.len / 2;
        mod.data_size = elf_data.len / 4;

        _ = e_shnum;

        // Find module slot
        for (&self.modules) |*slot| {
            if (slot.* == null) {
                mod.state = .live;
                slot.* = mod;
                self.module_count += 1;
                self.total_loaded += 1;
                self.total_memory_used += mod.total_size;
                return .success;
            }
        }

        self.total_failed += 1;
        return .no_memory;
    }

    /// Unload a module by ID
    pub fn unload_module(self: *ModuleLoader, id: u32) LoadError {
        for (&self.modules) |*slot| {
            if (slot.*) |*mod| {
                if (mod.id == id) {
                    if (!mod.can_unload()) return .dependency_missing;

                    // Remove from dependency lists
                    for (mod.deps[0..mod.dep_count]) |dep_id| {
                        if (self.find_mut(dep_id)) |dep_mod| {
                            _ = dep_mod.remove_user(id);
                        }
                    }

                    // Unregister module symbols from global table
                    // (would iterate and remove exported symbols)

                    self.total_memory_used -= mod.total_size;
                    mod.state = .unloaded;
                    slot.* = null;
                    if (self.module_count > 0) self.module_count -= 1;
                    self.total_unloaded += 1;
                    return .success;
                }
            }
        }
        return .dependency_missing;
    }

    pub fn find(self: *const ModuleLoader, id: u32) ?*const Module {
        for (&self.modules) |*slot| {
            if (slot.*) |*mod| {
                if (mod.id == id) return mod;
            }
        }
        return null;
    }

    pub fn find_mut(self: *ModuleLoader, id: u32) ?*Module {
        for (&self.modules) |*slot| {
            if (slot.*) |*mod| {
                if (mod.id == id) return mod;
            }
        }
        return null;
    }

    pub fn find_by_name(self: *const ModuleLoader, name: []const u8) ?*const Module {
        for (&self.modules) |*slot| {
            if (slot.*) |*mod| {
                if (std.mem.eql(u8, mod.info.get_name(), name)) return mod;
            }
        }
        return null;
    }
};

fn read_u64_le(data: *const [8]u8) u64 {
    return @as(u64, data[0]) |
        (@as(u64, data[1]) << 8) |
        (@as(u64, data[2]) << 16) |
        (@as(u64, data[3]) << 24) |
        (@as(u64, data[4]) << 32) |
        (@as(u64, data[5]) << 40) |
        (@as(u64, data[6]) << 48) |
        (@as(u64, data[7]) << 56);
}

// ─────────────────── Global Instance ────────────────────────────────
var module_loader: ModuleLoader = .{};
var loader_initialized = false;

pub fn initLoader() void {
    module_loader.init();
    loader_initialized = true;
}

pub fn getLoader() *ModuleLoader {
    return &module_loader;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_modules_init() void {
    initLoader();
}

export fn zxy_module_load(elf_ptr: [*]const u8, elf_len: u32, name_ptr: [*]const u8, name_len: u32) i32 {
    if (!loader_initialized) return -1;
    const elf = elf_ptr[0..elf_len];
    const name = name_ptr[0..name_len];
    const result = module_loader.load_module(elf, name);
    return if (result == .success) 0 else -@as(i32, @intCast(@intFromEnum(result)));
}

export fn zxy_module_unload(id: u32) i32 {
    if (!loader_initialized) return -1;
    const result = module_loader.unload_module(id);
    return if (result == .success) 0 else -@as(i32, @intCast(@intFromEnum(result)));
}

export fn zxy_module_resolve_symbol(name_ptr: [*]const u8, name_len: u32) u64 {
    if (!loader_initialized) return 0;
    const name = name_ptr[0..name_len];
    return module_loader.resolve_symbol(name) orelse 0;
}

export fn zxy_module_count() u32 {
    return module_loader.module_count;
}
