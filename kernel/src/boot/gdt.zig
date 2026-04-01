// =============================================================================
// Kernel Zxyphor - Global Descriptor Table (GDT)
// =============================================================================
// The GDT defines memory segments for the x86_64 architecture. In long mode
// (64-bit), segmentation is mostly deprecated, but we still need a valid GDT
// with at minimum: a null descriptor, kernel code/data segments, user code/data
// segments, and a TSS descriptor.
//
// Segment layout:
//   0x00: Null descriptor (required by CPU)
//   0x08: Kernel Code (ring 0, 64-bit)
//   0x10: Kernel Data (ring 0)
//   0x18: User Code (ring 3, 64-bit)
//   0x20: User Data (ring 3)
//   0x28: TSS descriptor (16 bytes — occupies two GDT entries)
//
// In 64-bit long mode, the base and limit fields of code/data descriptors are
// ignored. The CPU only checks the DPL, type, and present bit. However, we
// must set them correctly for the transition to and from compatibility mode.
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Segment selector constants (byte offset into GDT)
// =============================================================================
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_CODE_SELECTOR: u16 = 0x18 | 3; // RPL=3 for userspace
pub const USER_DATA_SELECTOR: u16 = 0x20 | 3; // RPL=3 for userspace
pub const TSS_SELECTOR: u16 = 0x28;

// =============================================================================
// GDT Entry (8 bytes) — standard x86 segment descriptor
// =============================================================================
const GdtEntry = packed struct {
    limit_low: u16, // Segment limit bits 0-15
    base_low: u16, // Base address bits 0-15
    base_mid: u8, // Base address bits 16-23
    access: u8, // Access byte (type, S, DPL, P)
    granularity: u8, // Granularity + limit bits 16-19 + flags
    base_high: u8, // Base address bits 24-31

    /// Create a GDT entry from individual fields
    pub fn create(base: u32, limit: u20, access_byte: u8, flags: u4) GdtEntry {
        return GdtEntry{
            .limit_low = @truncate(limit),
            .base_low = @truncate(base),
            .base_mid = @truncate(base >> 16),
            .access = access_byte,
            .granularity = (@as(u8, flags) << 4) | @as(u8, @truncate(limit >> 16)),
            .base_high = @truncate(base >> 24),
        };
    }

    /// Create a null descriptor (all zeros)
    pub fn null_entry() GdtEntry {
        return GdtEntry{
            .limit_low = 0,
            .base_low = 0,
            .base_mid = 0,
            .access = 0,
            .granularity = 0,
            .base_high = 0,
        };
    }
};

// =============================================================================
// TSS Descriptor (16 bytes in long mode — spans two GDT entry slots)
// =============================================================================
const TssDescriptor = packed struct {
    limit_low: u16,
    base_low: u16,
    base_mid_low: u8,
    access: u8,
    granularity: u8,
    base_mid_high: u8,
    base_high: u32,
    reserved: u32,
};

// =============================================================================
// Access byte bit fields
// =============================================================================
// Bit 7: Present (P)       — must be 1 for valid segments
// Bit 6-5: DPL             — Descriptor Privilege Level (0=kernel, 3=user)
// Bit 4: Descriptor type   — 1=code/data, 0=system
// Bit 3: Executable        — 1=code, 0=data
// Bit 2: Direction/Conform — direction for data, conforming for code
// Bit 1: Read/Write        — readable for code, writable for data
// Bit 0: Accessed          — CPU sets this when segment is accessed
// =============================================================================
const ACCESS_PRESENT: u8 = 1 << 7;
const ACCESS_DPL_RING0: u8 = 0 << 5;
const ACCESS_DPL_RING3: u8 = 3 << 5;
const ACCESS_CODE_DATA: u8 = 1 << 4;
const ACCESS_EXECUTABLE: u8 = 1 << 3;
const ACCESS_RW: u8 = 1 << 1;
const ACCESS_TSS: u8 = 0x09; // 64-bit TSS (Available)

// Flag bits (upper nibble of granularity byte)
const FLAG_GRANULARITY_4K: u4 = 1 << 3; // Limit is in 4KB pages
const FLAG_SIZE_32: u4 = 1 << 2; // 32-bit protected mode
const FLAG_LONG_MODE: u4 = 1 << 1; // 64-bit long mode

// =============================================================================
// GDT table — 7 entries (null + 4 segments + TSS uses 2 entries)
// =============================================================================
const GDT_ENTRIES = 7;

var gdt_entries: [GDT_ENTRIES]GdtEntry align(16) = undefined;

// =============================================================================
// GDT Pointer (GDTR) — loaded with lgdt instruction
// =============================================================================
const GdtPointer = packed struct {
    limit: u16,
    base: u64,
};

var gdt_pointer: GdtPointer = undefined;

// =============================================================================
// Initialize the GDT with kernel and user segments
// =============================================================================
pub fn initialize() void {
    // Entry 0: Null descriptor (required by architecture)
    gdt_entries[0] = GdtEntry.null_entry();

    // Entry 1 (0x08): Kernel Code Segment — 64-bit, ring 0, executable, readable
    gdt_entries[1] = GdtEntry.create(
        0, // base
        0xFFFFF, // limit (4GB with granularity)
        ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_CODE_DATA | ACCESS_EXECUTABLE | ACCESS_RW,
        FLAG_GRANULARITY_4K | FLAG_LONG_MODE,
    );

    // Entry 2 (0x10): Kernel Data Segment — ring 0, writable
    gdt_entries[2] = GdtEntry.create(
        0,
        0xFFFFF,
        ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_CODE_DATA | ACCESS_RW,
        FLAG_GRANULARITY_4K | FLAG_SIZE_32,
    );

    // Entry 3 (0x18): User Code Segment — 64-bit, ring 3, executable, readable
    gdt_entries[3] = GdtEntry.create(
        0,
        0xFFFFF,
        ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_CODE_DATA | ACCESS_EXECUTABLE | ACCESS_RW,
        FLAG_GRANULARITY_4K | FLAG_LONG_MODE,
    );

    // Entry 4 (0x20): User Data Segment — ring 3, writable
    gdt_entries[4] = GdtEntry.create(
        0,
        0xFFFFF,
        ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_CODE_DATA | ACCESS_RW,
        FLAG_GRANULARITY_4K | FLAG_SIZE_32,
    );

    // Entry 5-6 (0x28): TSS descriptor — filled in later by tss.initialize()
    gdt_entries[5] = GdtEntry.null_entry();
    gdt_entries[6] = GdtEntry.null_entry();

    // Set up the GDT pointer
    gdt_pointer = GdtPointer{
        .limit = @as(u16, @sizeOf(@TypeOf(gdt_entries))) - 1,
        .base = @intFromPtr(&gdt_entries),
    };

    // Load the GDT using the lgdt instruction
    loadGdt();

    // Reload segment registers with new selectors
    reloadSegments();

    main.klog(.info, "GDT: Loaded with {d} entries", .{GDT_ENTRIES});
}

// =============================================================================
// Install the TSS descriptor into the GDT
// This is called from tss.initialize() after the TSS structure is set up
// =============================================================================
pub fn installTssDescriptor(tss_base: u64, tss_limit: u32) void {
    const tss_desc = @as(*TssDescriptor, @ptrCast(@alignCast(&gdt_entries[5])));

    tss_desc.limit_low = @truncate(tss_limit);
    tss_desc.base_low = @truncate(tss_base);
    tss_desc.base_mid_low = @truncate(tss_base >> 16);
    tss_desc.access = ACCESS_PRESENT | ACCESS_TSS;
    tss_desc.granularity = @as(u8, @truncate(tss_limit >> 16)) & 0x0F;
    tss_desc.base_mid_high = @truncate(tss_base >> 24);
    tss_desc.base_high = @truncate(tss_base >> 32);
    tss_desc.reserved = 0;

    main.klog(.debug, "GDT: TSS descriptor installed at 0x28, base=0x{x}", .{tss_base});
}

// =============================================================================
// Low-level assembly routines for GDT manipulation
// =============================================================================

/// Load the GDT register with our GDT pointer
fn loadGdt() void {
    asm volatile ("lgdt (%[gdt_ptr])"
        :
        : [gdt_ptr] "r" (&gdt_pointer),
        : "memory"
    );
}

/// Reload all segment registers after changing the GDT.
/// In long mode, CS is loaded via a far return, and the data segment
/// registers are loaded directly.
fn reloadSegments() void {
    // Reload CS via a far return trick
    asm volatile (
        \\ pushq $0x08          // Push kernel code selector
        \\ leaq 1f(%%rip), %%rax
        \\ pushq %%rax          // Push return address
        \\ lretq                // Far return loads CS
        \\ 1:
        \\ movw $0x10, %%ax     // Kernel data selector
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ movw %%ax, %%fs
        \\ movw %%ax, %%gs
        \\ movw %%ax, %%ss
        :
        :
        : "rax", "memory"
    );
}

/// Load the Task Register with the TSS selector
pub fn loadTr() void {
    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (TSS_SELECTOR),
    );
}

/// Get a pointer to the GDT entries (for debugging)
pub fn getEntries() *const [GDT_ENTRIES]GdtEntry {
    return &gdt_entries;
}
