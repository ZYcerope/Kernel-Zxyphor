// =============================================================================
// Kernel Zxyphor - Multiboot2 Header and Parser
// =============================================================================
// Implements the Multiboot2 specification for bootloader compatibility.
// The header tells GRUB how to load us, and the parser extracts memory map
// and other hardware information from the Multiboot2 information structure.
//
// Reference: https://www.gnu.org/software/grub/manual/multiboot2/
// =============================================================================

const std = @import("std");
const main = @import("../main.zig");

// =============================================================================
// Multiboot2 magic numbers and constants
// =============================================================================
pub const MULTIBOOT2_MAGIC: u32 = 0x36D76289;
pub const MULTIBOOT2_HEADER_MAGIC: u32 = 0xE85250D6;
pub const MULTIBOOT2_ARCHITECTURE_I386: u32 = 0;

// Tag types as defined by the Multiboot2 specification
pub const TAG_TYPE_END: u32 = 0;
pub const TAG_TYPE_CMDLINE: u32 = 1;
pub const TAG_TYPE_BOOT_LOADER_NAME: u32 = 2;
pub const TAG_TYPE_MODULE: u32 = 3;
pub const TAG_TYPE_BASIC_MEMINFO: u32 = 4;
pub const TAG_TYPE_BOOTDEV: u32 = 5;
pub const TAG_TYPE_MMAP: u32 = 6;
pub const TAG_TYPE_VBE: u32 = 7;
pub const TAG_TYPE_FRAMEBUFFER: u32 = 8;
pub const TAG_TYPE_ELF_SECTIONS: u32 = 9;
pub const TAG_TYPE_APM: u32 = 10;
pub const TAG_TYPE_EFI32: u32 = 11;
pub const TAG_TYPE_EFI64: u32 = 12;
pub const TAG_TYPE_SMBIOS: u32 = 13;
pub const TAG_TYPE_ACPI_OLD: u32 = 14;
pub const TAG_TYPE_ACPI_NEW: u32 = 15;
pub const TAG_TYPE_NETWORK: u32 = 16;
pub const TAG_TYPE_EFI_MMAP: u32 = 17;
pub const TAG_TYPE_EFI_BS: u32 = 18;
pub const TAG_TYPE_EFI32_IH: u32 = 19;
pub const TAG_TYPE_EFI64_IH: u32 = 20;
pub const TAG_TYPE_LOAD_BASE_ADDR: u32 = 21;

// Memory map entry types
pub const MEMORY_AVAILABLE: u32 = 1;
pub const MEMORY_RESERVED: u32 = 2;
pub const MEMORY_ACPI_RECLAIMABLE: u32 = 3;
pub const MEMORY_NVS: u32 = 4;
pub const MEMORY_BADRAM: u32 = 5;

// =============================================================================
// Multiboot2 Header (placed in .multiboot section by linker)
// =============================================================================
// This structure must be within the first 8KB of the kernel binary.
// The bootloader scans for the magic number to identify the kernel.
// =============================================================================
const MultibootHeader = extern struct {
    magic: u32,
    architecture: u32,
    header_length: u32,
    checksum: u32,
    // End tag
    end_tag_type: u16,
    end_tag_flags: u16,
    end_tag_size: u32,
};

export const multiboot_header linksection(".multiboot") = MultibootHeader{
    .magic = MULTIBOOT2_HEADER_MAGIC,
    .architecture = MULTIBOOT2_ARCHITECTURE_I386,
    .header_length = @sizeOf(MultibootHeader),
    .checksum = @as(u32, 0) -% (MULTIBOOT2_HEADER_MAGIC +% MULTIBOOT2_ARCHITECTURE_I386 +% @as(u32, @sizeOf(MultibootHeader))),
    .end_tag_type = 0,
    .end_tag_flags = 0,
    .end_tag_size = 8,
};

// =============================================================================
// Multiboot2 Information Structures (provided by the bootloader)
// =============================================================================

pub const TagHeader = extern struct {
    tag_type: u32,
    size: u32,
};

pub const BasicMemInfoTag = extern struct {
    header: TagHeader,
    mem_lower: u32, // KB of lower memory (below 1MB)
    mem_upper: u32, // KB of upper memory (above 1MB)
};

pub const MmapEntry = extern struct {
    base_addr: u64,
    length: u64,
    entry_type: u32,
    reserved: u32,

    pub fn isAvailable(self: *const MmapEntry) bool {
        return self.entry_type == MEMORY_AVAILABLE;
    }

    pub fn isReclaimable(self: *const MmapEntry) bool {
        return self.entry_type == MEMORY_ACPI_RECLAIMABLE;
    }

    pub fn endAddress(self: *const MmapEntry) u64 {
        return self.base_addr + self.length;
    }

    pub fn typeName(self: *const MmapEntry) []const u8 {
        return switch (self.entry_type) {
            MEMORY_AVAILABLE => "Available",
            MEMORY_RESERVED => "Reserved",
            MEMORY_ACPI_RECLAIMABLE => "ACPI Reclaimable",
            MEMORY_NVS => "NVS",
            MEMORY_BADRAM => "Bad RAM",
            else => "Unknown",
        };
    }
};

pub const MmapTag = extern struct {
    header: TagHeader,
    entry_size: u32,
    entry_version: u32,
    // Entries follow immediately after this header
};

pub const BootloaderNameTag = extern struct {
    header: TagHeader,
    // Name string follows as null-terminated C string
};

pub const CmdlineTag = extern struct {
    header: TagHeader,
    // Command line string follows
};

pub const FramebufferTag = extern struct {
    header: TagHeader,
    framebuffer_addr: u64,
    framebuffer_pitch: u32,
    framebuffer_width: u32,
    framebuffer_height: u32,
    framebuffer_bpp: u8,
    framebuffer_type: u8,
    reserved: u8,
};

pub const AcpiOldTag = extern struct {
    header: TagHeader,
    // RSDP structure follows
};

pub const AcpiNewTag = extern struct {
    header: TagHeader,
    // XSDP structure follows
};

// =============================================================================
// Parsed Multiboot Information
// =============================================================================
pub const BootInfo = struct {
    total_memory_kb: u64,
    memory_map: []const MmapEntry,
    memory_map_entries: usize,
    bootloader_name: ?[]const u8,
    command_line: ?[]const u8,
    framebuffer: ?FramebufferInfo,
    acpi_rsdp_addr: ?u64,
    has_framebuffer: bool,
};

pub const FramebufferInfo = struct {
    address: u64,
    pitch: u32,
    width: u32,
    height: u32,
    bpp: u8,
    fb_type: u8,
};

// =============================================================================
// Static storage for memory map entries (we copy them here since the
// original multiboot info may be overwritten by memory allocation)
// =============================================================================
const MAX_MMAP_ENTRIES = 128;
var mmap_entries_storage: [MAX_MMAP_ENTRIES]MmapEntry = undefined;
var mmap_entry_count: usize = 0;

var boot_info: BootInfo = undefined;

// =============================================================================
// Parse the Multiboot2 information structure
// =============================================================================
pub fn parse(info_addr: u32) BootInfo {
    // The Multiboot2 info structure starts with a u32 total_size and u32 reserved
    const info_ptr = @as([*]const u8, @ptrFromInt(@as(usize, info_addr)));
    const total_size = @as(*const u32, @ptrCast(@alignCast(info_ptr))).*;
    _ = total_size;

    // Initialize the boot info result
    boot_info = BootInfo{
        .total_memory_kb = 0,
        .memory_map = &[_]MmapEntry{},
        .memory_map_entries = 0,
        .bootloader_name = null,
        .command_line = null,
        .framebuffer = null,
        .acpi_rsdp_addr = null,
        .has_framebuffer = false,
    };

    // Skip the 8-byte header (total_size + reserved)
    var offset: usize = 8;

    // Walk through all tags in the information structure
    while (true) {
        // Tags are aligned to 8-byte boundaries
        offset = alignUp(offset, 8);

        const tag = @as(*const TagHeader, @ptrCast(@alignCast(info_ptr + offset)));

        // End tag marks the end of the information structure
        if (tag.tag_type == TAG_TYPE_END) break;

        switch (tag.tag_type) {
            TAG_TYPE_BASIC_MEMINFO => {
                const mem_tag = @as(*const BasicMemInfoTag, @ptrCast(@alignCast(info_ptr + offset)));
                boot_info.total_memory_kb = @as(u64, mem_tag.mem_lower) + @as(u64, mem_tag.mem_upper);
                main.klog(.debug, "Multiboot: Lower memory = {d} KB, Upper memory = {d} KB", .{
                    mem_tag.mem_lower,
                    mem_tag.mem_upper,
                });
            },

            TAG_TYPE_MMAP => {
                const mmap_tag = @as(*const MmapTag, @ptrCast(@alignCast(info_ptr + offset)));
                const entries_start = offset + @sizeOf(MmapTag);
                const entries_end = offset + tag.size;
                const entry_size = mmap_tag.entry_size;

                mmap_entry_count = 0;
                var entry_offset = entries_start;

                while (entry_offset < entries_end and mmap_entry_count < MAX_MMAP_ENTRIES) {
                    const entry = @as(*const MmapEntry, @ptrCast(@alignCast(info_ptr + entry_offset)));
                    mmap_entries_storage[mmap_entry_count] = entry.*;

                    main.klog(.debug, "Multiboot MMAP: base=0x{x:0>16} len=0x{x:0>16} type={s}", .{
                        entry.base_addr,
                        entry.length,
                        entry.typeName(),
                    });

                    // Track total available memory
                    if (entry.isAvailable() or entry.isReclaimable()) {
                        boot_info.total_memory_kb += entry.length / 1024;
                    }

                    mmap_entry_count += 1;
                    entry_offset += entry_size;
                }

                boot_info.memory_map = mmap_entries_storage[0..mmap_entry_count];
                boot_info.memory_map_entries = mmap_entry_count;
            },

            TAG_TYPE_BOOT_LOADER_NAME => {
                const name_ptr = info_ptr + offset + @sizeOf(TagHeader);
                const name_len = tag.size - @sizeOf(TagHeader);
                if (name_len > 0) {
                    boot_info.bootloader_name = name_ptr[0 .. name_len - 1]; // exclude null terminator
                    main.klog(.info, "Bootloader: {s}", .{boot_info.bootloader_name.?});
                }
            },

            TAG_TYPE_CMDLINE => {
                const cmd_ptr = info_ptr + offset + @sizeOf(TagHeader);
                const cmd_len = tag.size - @sizeOf(TagHeader);
                if (cmd_len > 1) {
                    boot_info.command_line = cmd_ptr[0 .. cmd_len - 1];
                    main.klog(.info, "Command line: {s}", .{boot_info.command_line.?});
                }
            },

            TAG_TYPE_FRAMEBUFFER => {
                const fb_tag = @as(*const FramebufferTag, @ptrCast(@alignCast(info_ptr + offset)));
                boot_info.framebuffer = FramebufferInfo{
                    .address = fb_tag.framebuffer_addr,
                    .pitch = fb_tag.framebuffer_pitch,
                    .width = fb_tag.framebuffer_width,
                    .height = fb_tag.framebuffer_height,
                    .bpp = fb_tag.framebuffer_bpp,
                    .fb_type = fb_tag.framebuffer_type,
                };
                boot_info.has_framebuffer = true;
                main.klog(.info, "Framebuffer: {d}x{d} @ {d}bpp addr=0x{x}", .{
                    fb_tag.framebuffer_width,
                    fb_tag.framebuffer_height,
                    fb_tag.framebuffer_bpp,
                    fb_tag.framebuffer_addr,
                });
            },

            TAG_TYPE_ACPI_OLD => {
                boot_info.acpi_rsdp_addr = @as(u64, offset + @sizeOf(TagHeader));
                main.klog(.info, "ACPI RSDP (v1) found", .{});
            },

            TAG_TYPE_ACPI_NEW => {
                boot_info.acpi_rsdp_addr = @as(u64, offset + @sizeOf(TagHeader));
                main.klog(.info, "ACPI XSDP (v2) found", .{});
            },

            else => {
                main.klog(.debug, "Multiboot: Unknown tag type {d}, size {d}", .{
                    tag.tag_type,
                    tag.size,
                });
            },
        }

        // Move to the next tag
        offset += tag.size;
    }

    return boot_info;
}

// =============================================================================
// Helper: align value up to the given alignment
// =============================================================================
fn alignUp(value: usize, alignment: usize) usize {
    return (value + alignment - 1) & ~(alignment - 1);
}

// =============================================================================
// Public accessors for boot information
// =============================================================================
pub fn getBootInfo() *const BootInfo {
    return &boot_info;
}

pub fn getMemoryMap() []const MmapEntry {
    return mmap_entries_storage[0..mmap_entry_count];
}

pub fn getBootloaderName() ?[]const u8 {
    return boot_info.bootloader_name;
}

pub fn getCommandLine() ?[]const u8 {
    return boot_info.command_line;
}

pub fn getFramebufferInfo() ?FramebufferInfo {
    return boot_info.framebuffer;
}

pub fn totalMemoryKB() u64 {
    return boot_info.total_memory_kb;
}

/// Find the largest available memory region — useful for initial heap placement
pub fn findLargestAvailableRegion() ?MmapEntry {
    var largest: ?MmapEntry = null;

    for (mmap_entries_storage[0..mmap_entry_count]) |entry| {
        if (entry.isAvailable()) {
            if (largest) |current_largest| {
                if (entry.length > current_largest.length) {
                    largest = entry;
                }
            } else {
                largest = entry;
            }
        }
    }

    return largest;
}
