// SPDX-License-Identifier: MIT
// Zxyphor Kernel - x86_64 Global Descriptor Table (GDT) Implementation
// Advanced GDT with TSS integration, per-CPU support, and security ring management

const std = @import("std");

/// GDT Access Byte Flags
pub const AccessFlags = struct {
    pub const PRESENT: u8 = 1 << 7;
    pub const DPL_RING0: u8 = 0 << 5;
    pub const DPL_RING1: u8 = 1 << 5;
    pub const DPL_RING2: u8 = 2 << 5;
    pub const DPL_RING3: u8 = 3 << 5;
    pub const DESCRIPTOR_TYPE: u8 = 1 << 4;
    pub const EXECUTABLE: u8 = 1 << 3;
    pub const DIRECTION_CONFORMING: u8 = 1 << 2;
    pub const READABLE_WRITABLE: u8 = 1 << 1;
    pub const ACCESSED: u8 = 1 << 0;

    pub const KERNEL_CODE: u8 = PRESENT | DPL_RING0 | DESCRIPTOR_TYPE | EXECUTABLE | READABLE_WRITABLE;
    pub const KERNEL_DATA: u8 = PRESENT | DPL_RING0 | DESCRIPTOR_TYPE | READABLE_WRITABLE;
    pub const USER_CODE: u8 = PRESENT | DPL_RING3 | DESCRIPTOR_TYPE | EXECUTABLE | READABLE_WRITABLE;
    pub const USER_DATA: u8 = PRESENT | DPL_RING3 | DESCRIPTOR_TYPE | READABLE_WRITABLE;
    pub const TSS_AVAILABLE: u8 = PRESENT | 0x09;
    pub const TSS_BUSY: u8 = PRESENT | 0x0B;
};

/// GDT Granularity Flags  
pub const GranularityFlags = struct {
    pub const GRANULARITY_4K: u8 = 1 << 7;
    pub const SIZE_32BIT: u8 = 1 << 6;
    pub const LONG_MODE: u8 = 1 << 5;
};

/// Segment Selector Indices
pub const SegmentSelector = struct {
    pub const NULL: u16 = 0x00;
    pub const KERNEL_CODE: u16 = 0x08;
    pub const KERNEL_DATA: u16 = 0x10;
    pub const USER_CODE: u16 = 0x18 | 3; // RPL = 3
    pub const USER_DATA: u16 = 0x20 | 3; // RPL = 3
    pub const TSS: u16 = 0x28;

    pub fn fromIndex(index: u16, rpl: u2) fn () u16 {
        _ = index;
        _ = rpl;
        return struct {
            fn call() u16 {
                return 0;
            }
        }.call;
    }
};

/// 64-bit GDT Entry
pub const GdtEntry = packed struct {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    granularity: u8,
    base_high: u8,

    pub fn init(base: u32, limit: u20, access: u8, flags: u4) GdtEntry {
        return GdtEntry{
            .limit_low = @truncate(limit),
            .base_low = @truncate(base),
            .base_middle = @truncate(base >> 16),
            .access = access,
            .granularity = (@as(u8, flags) << 4) | @as(u8, @truncate(limit >> 16)),
            .base_high = @truncate(base >> 24),
        };
    }

    pub fn null_entry() GdtEntry {
        return GdtEntry{
            .limit_low = 0,
            .base_low = 0,
            .base_middle = 0,
            .access = 0,
            .granularity = 0,
            .base_high = 0,
        };
    }

    pub fn kernel_code_segment() GdtEntry {
        return GdtEntry.init(
            0,
            0xFFFFF,
            AccessFlags.KERNEL_CODE,
            @truncate((@as(u8, GranularityFlags.GRANULARITY_4K) | GranularityFlags.LONG_MODE) >> 4),
        );
    }

    pub fn kernel_data_segment() GdtEntry {
        return GdtEntry.init(
            0,
            0xFFFFF,
            AccessFlags.KERNEL_DATA,
            @truncate((@as(u8, GranularityFlags.GRANULARITY_4K) | GranularityFlags.SIZE_32BIT) >> 4),
        );
    }

    pub fn user_code_segment() GdtEntry {
        return GdtEntry.init(
            0,
            0xFFFFF,
            AccessFlags.USER_CODE,
            @truncate((@as(u8, GranularityFlags.GRANULARITY_4K) | GranularityFlags.LONG_MODE) >> 4),
        );
    }

    pub fn user_data_segment() GdtEntry {
        return GdtEntry.init(
            0,
            0xFFFFF,
            AccessFlags.USER_DATA,
            @truncate((@as(u8, GranularityFlags.GRANULARITY_4K) | GranularityFlags.SIZE_32BIT) >> 4),
        );
    }
};

/// 64-bit TSS Entry (occupies two GDT slots)
pub const TssEntry = packed struct {
    length: u16,
    base_low: u16,
    base_middle: u8,
    flags_low: u8,
    flags_high: u8,
    base_high: u8,
    base_upper: u32,
    reserved: u32,

    pub fn init(tss_addr: u64, tss_size: u16) TssEntry {
        return TssEntry{
            .length = tss_size,
            .base_low = @truncate(tss_addr),
            .base_middle = @truncate(tss_addr >> 16),
            .flags_low = AccessFlags.TSS_AVAILABLE,
            .flags_high = 0,
            .base_high = @truncate(tss_addr >> 24),
            .base_upper = @truncate(tss_addr >> 32),
            .reserved = 0,
        };
    }
};

/// Task State Segment for x86_64
pub const Tss = packed struct {
    reserved0: u32 = 0,
    /// Privilege level stack pointers (RSP0-RSP2)
    rsp: [3]u64 = [_]u64{0} ** 3,
    reserved1: u64 = 0,
    /// Interrupt Stack Table (IST1-IST7)
    ist: [7]u64 = [_]u64{0} ** 7,
    reserved2: u64 = 0,
    reserved3: u16 = 0,
    /// I/O Permission Bitmap offset
    iopb_offset: u16 = @sizeOf(Tss),

    pub fn setKernelStack(self: *Tss, stack_ptr: u64) void {
        self.rsp[0] = stack_ptr;
    }

    pub fn setInterruptStack(self: *Tss, ist_index: u3, stack_ptr: u64) void {
        if (ist_index == 0) return; // IST0 is not used
        self.ist[ist_index - 1] = stack_ptr;
    }

    pub fn getKernelStack(self: *const Tss) u64 {
        return self.rsp[0];
    }
};

/// Maximum number of CPUs supported
pub const MAX_CPUS = 256;

/// Per-CPU GDT structure
pub const PerCpuGdt = struct {
    entries: [7]GdtEntry,
    tss_entry: TssEntry,
    tss: Tss,
    loaded: bool,

    pub fn init() PerCpuGdt {
        return PerCpuGdt{
            .entries = [_]GdtEntry{
                GdtEntry.null_entry(), // 0x00: Null
                GdtEntry.kernel_code_segment(), // 0x08: Kernel Code
                GdtEntry.kernel_data_segment(), // 0x10: Kernel Data
                GdtEntry.user_code_segment(), // 0x18: User Code
                GdtEntry.user_data_segment(), // 0x20: User Data
                GdtEntry.null_entry(), // 0x28: TSS Low (filled by tss_entry)
                GdtEntry.null_entry(), // 0x30: TSS High (filled by tss_entry)
            },
            .tss_entry = TssEntry.init(0, @sizeOf(Tss) - 1),
            .tss = Tss{},
            .loaded = false,
        };
    }
};

/// GDT Pointer structure for LGDT instruction
pub const GdtPointer = packed struct {
    limit: u16,
    base: u64,
};

/// Global GDT state
var per_cpu_gdts: [MAX_CPUS]PerCpuGdt = undefined;
var gdt_initialized: bool = false;
var active_cpu_count: u32 = 0;

/// IST stack allocation tracking
const IST_STACK_SIZE: usize = 16384; // 16 KB per IST stack
const IST_STACK_GUARD_SIZE: usize = 4096; // 4 KB guard page

/// Stack allocation for IST entries
pub const IstStack = struct {
    stack_bottom: u64,
    stack_top: u64,
    guard_page: u64,
    allocated: bool,

    pub fn init() IstStack {
        return IstStack{
            .stack_bottom = 0,
            .stack_top = 0,
            .guard_page = 0,
            .allocated = false,
        };
    }
};

var ist_stacks: [MAX_CPUS][7]IstStack = undefined;

/// Initialize the GDT for a specific CPU
pub fn initForCpu(cpu_id: u32) !void {
    if (cpu_id >= MAX_CPUS) return error.CpuIdOutOfRange;

    var gdt = &per_cpu_gdts[cpu_id];
    gdt.* = PerCpuGdt.init();

    // Set up TSS address in GDT
    const tss_addr = @intFromPtr(&gdt.tss);
    gdt.tss_entry = TssEntry.init(tss_addr, @sizeOf(Tss) - 1);

    // Copy TSS entry bytes into GDT slot 5 and 6
    const tss_bytes = @as(*const [16]u8, @ptrCast(&gdt.tss_entry));
    const entry5 = @as(*[8]u8, @ptrCast(&gdt.entries[5]));
    const entry6 = @as(*[8]u8, @ptrCast(&gdt.entries[6]));
    @memcpy(entry5, tss_bytes[0..8]);
    @memcpy(entry6, tss_bytes[8..16]);

    // Initialize IST stacks for this CPU
    for (0..7) |i| {
        ist_stacks[cpu_id][i] = IstStack.init();
    }

    gdt.loaded = false;
}

/// Load the GDT for the current CPU
pub fn loadForCpu(cpu_id: u32) void {
    if (cpu_id >= MAX_CPUS) return;

    const gdt = &per_cpu_gdts[cpu_id];
    const gdt_ptr = GdtPointer{
        .limit = @sizeOf(@TypeOf(gdt.entries)) - 1,
        .base = @intFromPtr(&gdt.entries),
    };

    // Load GDT
    asm volatile ("lgdt (%[gdt_ptr])"
        :
        : [gdt_ptr] "r" (&gdt_ptr),
    );

    // Reload segment registers
    reloadSegments();

    // Load TSS
    asm volatile ("ltr %[tss_sel]"
        :
        : [tss_sel] "r" (SegmentSelector.TSS),
    );

    gdt.loaded = true;
    active_cpu_count += 1;
}

/// Reload segment registers after GDT change
fn reloadSegments() void {
    // Load kernel data segment
    asm volatile (
        \\mov %[data_sel], %%ds
        \\mov %[data_sel], %%es
        \\mov %[data_sel], %%fs
        \\mov %[data_sel], %%gs
        \\mov %[data_sel], %%ss
        :
        : [data_sel] "r" (@as(u16, SegmentSelector.KERNEL_DATA)),
    );

    // Far return to reload CS
    asm volatile (
        \\pushq %[code_sel]
        \\lea 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        :
        : [code_sel] "i" (@as(u64, SegmentSelector.KERNEL_CODE)),
        : "rax"
    );
}

/// Set the kernel stack pointer in TSS for a specific CPU
pub fn setKernelStack(cpu_id: u32, stack_ptr: u64) void {
    if (cpu_id >= MAX_CPUS) return;
    per_cpu_gdts[cpu_id].tss.setKernelStack(stack_ptr);
}

/// Set an IST entry for a specific CPU
pub fn setIstEntry(cpu_id: u32, ist_index: u3, stack_ptr: u64) void {
    if (cpu_id >= MAX_CPUS) return;
    per_cpu_gdts[cpu_id].tss.setInterruptStack(ist_index, stack_ptr);
}

/// Get the TSS for a specific CPU
pub fn getTss(cpu_id: u32) ?*Tss {
    if (cpu_id >= MAX_CPUS) return null;
    return &per_cpu_gdts[cpu_id].tss;
}

/// Initialize the bootstrap processor's GDT
pub fn initBsp() !void {
    try initForCpu(0);
    loadForCpu(0);
    gdt_initialized = true;
}

/// Initialize an application processor's GDT
pub fn initAp(cpu_id: u32) !void {
    try initForCpu(cpu_id);
    loadForCpu(cpu_id);
}

/// Check if GDT is initialized
pub fn isInitialized() bool {
    return gdt_initialized;
}

/// Get the number of active CPUs with loaded GDTs
pub fn getActiveCpuCount() u32 {
    return active_cpu_count;
}

/// Privilege level transition support
pub const PrivilegeLevel = enum(u2) {
    Ring0 = 0, // Kernel
    Ring1 = 1, // Device drivers (optional)
    Ring2 = 2, // Device drivers (optional)
    Ring3 = 3, // User space

    pub fn toSelectorRpl(self: PrivilegeLevel) u16 {
        return @intFromEnum(self);
    }
};

/// SYSCALL/SYSRET MSR Configuration
pub const SyscallMsrs = struct {
    pub const IA32_STAR: u32 = 0xC0000081;
    pub const IA32_LSTAR: u32 = 0xC0000082;
    pub const IA32_CSTAR: u32 = 0xC0000083;
    pub const IA32_SFMASK: u32 = 0xC0000084;

    pub fn configure(syscall_handler: u64) void {
        // STAR: kernel CS/SS in bits 47:32, user CS/SS in bits 63:48
        const star_value: u64 = (@as(u64, SegmentSelector.KERNEL_CODE) << 32) |
            (@as(u64, SegmentSelector.USER_DATA & ~@as(u16, 3)) << 48);

        writeMsr(IA32_STAR, star_value);
        writeMsr(IA32_LSTAR, syscall_handler);
        writeMsr(IA32_CSTAR, 0); // Not used in long mode
        // Mask interrupts on SYSCALL (clear IF, TF, DF, AC)
        writeMsr(IA32_SFMASK, 0x47700);
    }
};

fn writeMsr(msr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [ecx] "{ecx}" (msr),
          [eax] "{eax}" (low),
          [edx] "{edx}" (high),
    );
}

fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [eax] "={eax}" (low),
          [edx] "={edx}" (high),
        : [ecx] "{ecx}" (msr),
    );
    return @as(u64, high) << 32 | low;
}

/// GDT debugging/info functions
pub const GdtInfo = struct {
    pub fn dumpEntry(entry: GdtEntry) void {
        _ = entry;
        // Debug logging would go here
    }

    pub fn verifyIntegrity(cpu_id: u32) bool {
        if (cpu_id >= MAX_CPUS) return false;
        const gdt = &per_cpu_gdts[cpu_id];

        // Verify null descriptor
        if (gdt.entries[0].access != 0) return false;

        // Verify kernel code segment
        if (gdt.entries[1].access != AccessFlags.KERNEL_CODE) return false;

        // Verify kernel data segment
        if (gdt.entries[2].access != AccessFlags.KERNEL_DATA) return false;

        return true;
    }

    pub fn getTssBase(cpu_id: u32) ?u64 {
        if (cpu_id >= MAX_CPUS) return null;
        const gdt = &per_cpu_gdts[cpu_id];
        return @as(u64, gdt.tss_entry.base_upper) << 32 |
            @as(u64, gdt.tss_entry.base_high) << 24 |
            @as(u64, gdt.tss_entry.base_middle) << 16 |
            @as(u64, gdt.tss_entry.base_low);
    }
};
