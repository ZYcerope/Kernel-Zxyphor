// SPDX-License-Identifier: MIT
// Zxyphor Kernel - UEFI Boot Protocol
// UEFI 2.10 compatible boot services, runtime services, GOP, memory map

const std = @import("std");

// ============================================================================
// UEFI Types
// ============================================================================

pub const EfiStatus = u64;
pub const EfiHandle = u64;
pub const EfiPhysicalAddress = u64;
pub const EfiVirtualAddress = u64;
pub const EfiTpl = u64;

// Status codes
pub const EFI_SUCCESS: EfiStatus = 0;
pub const EFI_LOAD_ERROR: EfiStatus = 1 | (1 << 63);
pub const EFI_INVALID_PARAMETER: EfiStatus = 2 | (1 << 63);
pub const EFI_UNSUPPORTED: EfiStatus = 3 | (1 << 63);
pub const EFI_BAD_BUFFER_SIZE: EfiStatus = 4 | (1 << 63);
pub const EFI_BUFFER_TOO_SMALL: EfiStatus = 5 | (1 << 63);
pub const EFI_NOT_READY: EfiStatus = 6 | (1 << 63);
pub const EFI_DEVICE_ERROR: EfiStatus = 7 | (1 << 63);
pub const EFI_WRITE_PROTECTED: EfiStatus = 8 | (1 << 63);
pub const EFI_OUT_OF_RESOURCES: EfiStatus = 9 | (1 << 63);
pub const EFI_NOT_FOUND: EfiStatus = 14 | (1 << 63);
pub const EFI_ACCESS_DENIED: EfiStatus = 15 | (1 << 63);
pub const EFI_SECURITY_VIOLATION: EfiStatus = 26 | (1 << 63);

// ============================================================================
// EFI GUID
// ============================================================================

pub const EfiGuid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,

    pub fn eql(self: EfiGuid, other: EfiGuid) bool {
        return self.data1 == other.data1 and
            self.data2 == other.data2 and
            self.data3 == other.data3 and
            std.mem.eql(u8, &self.data4, &other.data4);
    }
};

// Well-known GUIDs
pub const EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID = EfiGuid{
    .data1 = 0x9042a9de,
    .data2 = 0x23dc,
    .data3 = 0x4a38,
    .data4 = .{ 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a },
};

pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID = EfiGuid{
    .data1 = 0x0964e5b22,
    .data2 = 0x6459,
    .data3 = 0x11d2,
    .data4 = .{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};

pub const EFI_LOADED_IMAGE_PROTOCOL_GUID = EfiGuid{
    .data1 = 0x5B1B31A1,
    .data2 = 0x9562,
    .data3 = 0x11d2,
    .data4 = .{ 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B },
};

pub const EFI_DEVICE_PATH_PROTOCOL_GUID = EfiGuid{
    .data1 = 0x09576e91,
    .data2 = 0x6d3f,
    .data3 = 0x11d2,
    .data4 = .{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};

pub const EFI_ACPI_20_TABLE_GUID = EfiGuid{
    .data1 = 0x8868e871,
    .data2 = 0xe4f1,
    .data3 = 0x11d3,
    .data4 = .{ 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 },
};

pub const EFI_SMBIOS_TABLE_GUID = EfiGuid{
    .data1 = 0xeb9d2d31,
    .data2 = 0x2d88,
    .data3 = 0x11d3,
    .data4 = .{ 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
};

pub const EFI_SMBIOS3_TABLE_GUID = EfiGuid{
    .data1 = 0xf2fd1544,
    .data2 = 0x9794,
    .data3 = 0x4a2c,
    .data4 = .{ 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94 },
};

// ============================================================================
// EFI Memory Map
// ============================================================================

pub const EfiMemoryType = enum(u32) {
    ReservedMemoryType = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    ACPIReclaimMemory = 9,
    ACPIMemoryNVS = 10,
    MemoryMappedIO = 11,
    MemoryMappedIOPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    UnacceptedMemoryType = 15,
    MaxMemoryType = 16,
};

pub const EFI_MEMORY_UC: u64 = 0x0000000000000001;
pub const EFI_MEMORY_WC: u64 = 0x0000000000000002;
pub const EFI_MEMORY_WT: u64 = 0x0000000000000004;
pub const EFI_MEMORY_WB: u64 = 0x0000000000000008;
pub const EFI_MEMORY_UCE: u64 = 0x0000000000000010;
pub const EFI_MEMORY_WP: u64 = 0x0000000000001000;
pub const EFI_MEMORY_RP: u64 = 0x0000000000002000;
pub const EFI_MEMORY_XP: u64 = 0x0000000000004000;
pub const EFI_MEMORY_NV: u64 = 0x0000000000008000;
pub const EFI_MEMORY_MORE_RELIABLE: u64 = 0x0000000000010000;
pub const EFI_MEMORY_RO: u64 = 0x0000000000020000;
pub const EFI_MEMORY_SP: u64 = 0x0000000000040000;
pub const EFI_MEMORY_CPU_CRYPTO: u64 = 0x0000000000080000;
pub const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000;
pub const EFI_MEMORY_ISA_VALID: u64 = 0x4000000000000000;
pub const EFI_MEMORY_ISA_MASK: u64 = 0x0FFFF00000000000;

pub const EfiMemoryDescriptor = extern struct {
    type_: EfiMemoryType,
    physical_start: EfiPhysicalAddress,
    virtual_start: EfiVirtualAddress,
    number_of_pages: u64,
    attribute: u64,
};

// Memory map storage
pub const MAX_MEMORY_MAP_ENTRIES = 512;

pub const MemoryMap = struct {
    entries: [MAX_MEMORY_MAP_ENTRIES]EfiMemoryDescriptor = undefined,
    entry_count: u32 = 0,
    map_key: u64 = 0,
    descriptor_size: u64 = 0,
    descriptor_version: u32 = 0,
    total_memory: u64 = 0,

    pub fn add_entry(self: *MemoryMap, desc: EfiMemoryDescriptor) bool {
        if (self.entry_count >= MAX_MEMORY_MAP_ENTRIES) return false;
        self.entries[self.entry_count] = desc;
        self.entry_count += 1;
        return true;
    }

    pub fn find_largest_conventional(self: *const MemoryMap) ?struct { base: u64, pages: u64 } {
        var best_base: u64 = 0;
        var best_pages: u64 = 0;

        for (0..self.entry_count) |i| {
            const entry = &self.entries[i];
            if (entry.type_ == .ConventionalMemory and entry.number_of_pages > best_pages) {
                best_base = entry.physical_start;
                best_pages = entry.number_of_pages;
            }
        }

        if (best_pages > 0) {
            return .{ .base = best_base, .pages = best_pages };
        }
        return null;
    }

    pub fn total_conventional_pages(self: *const MemoryMap) u64 {
        var total: u64 = 0;
        for (0..self.entry_count) |i| {
            if (self.entries[i].type_ == .ConventionalMemory) {
                total += self.entries[i].number_of_pages;
            }
        }
        return total;
    }

    pub fn total_usable_bytes(self: *const MemoryMap) u64 {
        return self.total_conventional_pages() * 4096;
    }
};

// ============================================================================
// GOP (Graphics Output Protocol)
// ============================================================================

pub const EfiPixelFormat = enum(u32) {
    PixelRedGreenBlueReserved8BitPerColor = 0,
    PixelBlueGreenRedReserved8BitPerColor = 1,
    PixelBitMask = 2,
    PixelBltOnly = 3,
    PixelFormatMax = 4,
};

pub const EfiPixelBitmask = extern struct {
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
    reserved_mask: u32,
};

pub const EfiGraphicsOutputModeInfo = extern struct {
    version: u32,
    horizontal_resolution: u32,
    vertical_resolution: u32,
    pixel_format: EfiPixelFormat,
    pixel_information: EfiPixelBitmask,
    pixels_per_scan_line: u32,
};

pub const FramebufferInfo = struct {
    base: u64 = 0,
    size: u64 = 0,
    width: u32 = 0,
    height: u32 = 0,
    stride: u32 = 0, // Pixels per scan line
    bpp: u8 = 32, // Bits per pixel
    pixel_format: EfiPixelFormat = .PixelBlueGreenRedReserved8BitPerColor,
    red_mask: u32 = 0x00FF0000,
    green_mask: u32 = 0x0000FF00,
    blue_mask: u32 = 0x000000FF,

    pub fn pitch(self: *const FramebufferInfo) u32 {
        return self.stride * (self.bpp / 8);
    }

    pub fn pixel_offset(self: *const FramebufferInfo, x: u32, y: u32) u64 {
        return @as(u64, y) * @as(u64, self.stride) + @as(u64, x);
    }

    pub fn byte_offset(self: *const FramebufferInfo, x: u32, y: u32) u64 {
        return self.pixel_offset(x, y) * (@as(u64, self.bpp) / 8);
    }
};

// ============================================================================
// EFI System Table
// ============================================================================

pub const EfiTableHeader = extern struct {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
};

pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249; // "IBI SYST"
pub const EFI_2_100_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 100;

pub const EfiConfigurationTable = extern struct {
    vendor_guid: EfiGuid,
    vendor_table: u64, // void*
};

// ============================================================================
// ACPI Table Finding (via UEFI config tables)
// ============================================================================

pub const AcpiRsdp = extern struct {
    signature: [8]u8, // "RSD PTR "
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,

    pub fn validate(self: *const AcpiRsdp) bool {
        if (!std.mem.eql(u8, &self.signature, "RSD PTR ")) return false;

        // Validate checksum (first 20 bytes for ACPI 1.0)
        var sum: u8 = 0;
        const bytes = @as([*]const u8, @ptrCast(self));
        for (0..20) |i| {
            sum +%= bytes[i];
        }
        if (sum != 0) return false;

        // For ACPI 2.0+, validate extended checksum
        if (self.revision >= 2) {
            sum = 0;
            for (0..self.length) |i| {
                sum +%= bytes[i];
            }
            if (sum != 0) return false;
        }
        return true;
    }
};

pub const AcpiSdtHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    pub fn validate(self: *const AcpiSdtHeader) bool {
        var sum: u8 = 0;
        const bytes = @as([*]const u8, @ptrCast(self));
        for (0..self.length) |i| {
            sum +%= bytes[i];
        }
        return sum == 0;
    }
};

// ============================================================================
// Boot Info (passed from bootloader to kernel)
// ============================================================================

pub const BootInfo = struct {
    // Memory
    memory_map: MemoryMap = .{},
    // Framebuffer
    framebuffer: FramebufferInfo = .{},
    // ACPI
    rsdp_address: u64 = 0,
    acpi_revision: u8 = 0,
    // SMBIOS
    smbios_address: u64 = 0,
    smbios_version: u32 = 0,
    // Command line
    cmdline: [512]u8 = [_]u8{0} ** 512,
    cmdline_len: u16 = 0,
    // Initrd
    initrd_base: u64 = 0,
    initrd_size: u64 = 0,
    // Boot loader
    loader_name: [64]u8 = [_]u8{0} ** 64,
    loader_name_len: u8 = 0,
    // Kernel image
    kernel_phys_base: u64 = 0,
    kernel_virt_base: u64 = 0xFFFFFFFF80000000,
    kernel_size: u64 = 0,
    // Direct map
    direct_map_base: u64 = 0xFFFF888000000000,
    highest_phys_addr: u64 = 0,
    // CPU info
    cpu_count: u32 = 1,
    bsp_lapic_id: u32 = 0,
    // Feature flags
    has_sse: bool = false,
    has_sse2: bool = false,
    has_avx: bool = false,
    has_avx2: bool = false,
    has_avx512: bool = false,
    has_x2apic: bool = false,
    has_1gb_pages: bool = false,
    has_5level_paging: bool = false,
    has_tsc_deadline: bool = false,
    has_invariant_tsc: bool = false,
    has_pcid: bool = false,
    has_smep: bool = false,
    has_smap: bool = false,
    has_umip: bool = false,
    has_pku: bool = false,
    has_cet: bool = false,

    pub fn parse_cmdline(self: *BootInfo, key: []const u8) ?[]const u8 {
        const cmdline = self.cmdline[0..self.cmdline_len];
        var i: usize = 0;
        while (i < cmdline.len) {
            // Skip whitespace
            while (i < cmdline.len and cmdline[i] == ' ') : (i += 1) {}
            if (i >= cmdline.len) break;

            // Check if this is our key
            const start = i;
            while (i < cmdline.len and cmdline[i] != ' ' and cmdline[i] != '=') : (i += 1) {}

            const param_key = cmdline[start..i];
            if (std.mem.eql(u8, param_key, key)) {
                if (i < cmdline.len and cmdline[i] == '=') {
                    i += 1;
                    const val_start = i;
                    while (i < cmdline.len and cmdline[i] != ' ') : (i += 1) {}
                    return cmdline[val_start..i];
                }
                return "";
            }

            // Skip value if present
            if (i < cmdline.len and cmdline[i] == '=') {
                i += 1;
                while (i < cmdline.len and cmdline[i] != ' ') : (i += 1) {}
            }
        }
        return null;
    }
};

// ============================================================================
// Stivale2 Boot Protocol (alternative to UEFI direct)
// ============================================================================

pub const STIVALE2_HEADER_TAG_FRAMEBUFFER_ID: u64 = 0x3ecc1bc43d0f7971;
pub const STIVALE2_HEADER_TAG_SMP_ID: u64 = 0x1ab015085f3273df;
pub const STIVALE2_HEADER_TAG_5LV_PAGING_ID: u64 = 0x932f477032007e8f;
pub const STIVALE2_HEADER_TAG_UNMAP_NULL_ID: u64 = 0x92919432b16fe7e7;

pub const STIVALE2_STRUCT_TAG_MEMMAP_ID: u64 = 0x2187f79e8612de07;
pub const STIVALE2_STRUCT_TAG_FRAMEBUFFER_ID: u64 = 0x506461d2950408fa;
pub const STIVALE2_STRUCT_TAG_RSDP_ID: u64 = 0x9e1786930a375e78;
pub const STIVALE2_STRUCT_TAG_KERNEL_BASE_ID: u64 = 0x060d78874a2a8af0;
pub const STIVALE2_STRUCT_TAG_SMP_ID: u64 = 0x34d1d96339647025;
pub const STIVALE2_STRUCT_TAG_MODULES_ID: u64 = 0x4b6fe466aade04ce;
pub const STIVALE2_STRUCT_TAG_CMDLINE_ID: u64 = 0xe5e76a1b4597a781;

pub const Stivale2Tag = extern struct {
    identifier: u64,
    next: u64,
};

pub const Stivale2Struct = extern struct {
    bootloader_brand: [64]u8,
    bootloader_version: [64]u8,
    tags: u64, // Pointer to first tag
};

pub const Stivale2MemmapEntry = extern struct {
    base: u64,
    length: u64,
    type_: u32,
    unused: u32,
};

pub const STIVALE2_MMAP_USABLE: u32 = 1;
pub const STIVALE2_MMAP_RESERVED: u32 = 2;
pub const STIVALE2_MMAP_ACPI_RECLAIMABLE: u32 = 3;
pub const STIVALE2_MMAP_ACPI_NVS: u32 = 4;
pub const STIVALE2_MMAP_BAD_MEMORY: u32 = 5;
pub const STIVALE2_MMAP_BOOTLOADER_RECLAIMABLE: u32 = 0x1000;
pub const STIVALE2_MMAP_KERNEL_AND_MODULES: u32 = 0x1001;
pub const STIVALE2_MMAP_FRAMEBUFFER: u32 = 0x1002;

// ============================================================================
// Limine Boot Protocol
// ============================================================================

pub const LIMINE_COMMON_MAGIC: [2]u64 = .{ 0xc7b1dd30df4c8b88, 0x0a82e883a194f07b };

pub const LimineMemoryMapEntry = extern struct {
    base: u64,
    length: u64,
    type_: LimineMemoryType,
};

pub const LimineMemoryType = enum(u64) {
    Usable = 0,
    Reserved = 1,
    AcpiReclaimable = 2,
    AcpiNvs = 3,
    BadMemory = 4,
    BootloaderReclaimable = 5,
    KernelAndModules = 6,
    Framebuffer = 7,
};

pub const LimineFramebuffer = extern struct {
    address: u64,
    width: u64,
    height: u64,
    pitch: u64,
    bpp: u16,
    memory_model: u8,
    red_mask_size: u8,
    red_mask_shift: u8,
    green_mask_size: u8,
    green_mask_shift: u8,
    blue_mask_size: u8,
    blue_mask_shift: u8,
    unused: [7]u8,
    edid_size: u64,
    edid: u64,
    mode_count: u64,
    modes: u64,
};

pub const LimineSmpInfo = extern struct {
    processor_id: u32,
    lapic_id: u32,
    reserved: u64,
    goto_address: u64,
    extra_argument: u64,
};
