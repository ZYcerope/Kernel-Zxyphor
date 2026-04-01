// =============================================================================
// Kernel Zxyphor — Symmetric Multi-Processing (SMP) Initialization
// =============================================================================
// Handles discovery and initialization of all CPU cores in the system:
//   - Parse MADT (ACPI) to enumerate Application Processors (APs)
//   - Allocate per-CPU data structures
//   - Send INIT-SIPI-SIPI sequence to bring APs online
//   - AP trampoline code (real mode → protected mode → long mode)
//   - Inter-Processor Interrupts (IPI) for cross-CPU communication
//   - CPU topology detection (package/core/thread)
//   - Per-CPU variables and CPU-local storage
//
// Boot sequence:
//   1. BSP (Bootstrap Processor) runs kernel boot code
//   2. BSP parses ACPI MADT for APIC IDs of all processors
//   3. BSP copies trampoline code to low memory (below 1MB)
//   4. BSP sends INIT IPI to each AP
//   5. BSP sends two STARTUP IPIs with trampoline address
//   6. APs execute trampoline: real→protected→long mode, then jump to ap_entry
//   7. AP initializes its local APIC, GDT, IDT, and reports ready
// =============================================================================

const main = @import("../main.zig");
const cpu = @import("../arch/x86_64/cpu.zig");
const apic = @import("../arch/x86_64/apic.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_CPUS: usize = 256;
pub const TRAMPOLINE_ADDR: u32 = 0x8000; // Physical address for AP trampoline

// IPI delivery modes
pub const IPI_FIXED: u32 = 0x000;
pub const IPI_LOWEST: u32 = 0x100;
pub const IPI_SMI: u32 = 0x200;
pub const IPI_NMI: u32 = 0x400;
pub const IPI_INIT: u32 = 0x500;
pub const IPI_STARTUP: u32 = 0x600;

// IPI destination shorthands
pub const IPI_DEST_SPECIFIC: u32 = 0x00000;
pub const IPI_DEST_SELF: u32 = 0x40000;
pub const IPI_DEST_ALL: u32 = 0x80000;
pub const IPI_DEST_ALL_EXCL: u32 = 0xC0000;

// IPI trigger modes
pub const IPI_LEVEL_DEASSERT: u32 = 0x00000;
pub const IPI_LEVEL_ASSERT: u32 = 0x04000;

// =============================================================================
// Per-CPU data
// =============================================================================

pub const CpuTopology = struct {
    package_id: u8,
    core_id: u8,
    thread_id: u8,
};

pub const CpuState = enum(u8) {
    offline = 0,
    starting = 1,
    online = 2,
    idle = 3,
    halted = 4,
    panicked = 5,
};

pub const PerCpuData = struct {
    // Identification
    cpu_id: u32, // Logical CPU index
    apic_id: u32, // Local APIC ID
    state: CpuState,
    is_bsp: bool,

    // Topology
    topology: CpuTopology,

    // CPU features
    features: CpuFeatures,

    // Stack
    kernel_stack_top: u64,
    kernel_stack_size: u32,

    // Scheduling
    idle_ticks: u64,
    active_ticks: u64,
    current_task_id: u32,

    // Interrupt state
    irq_count: u64,
    nmi_count: u64,
    last_irq_rip: u64,

    // Cache info
    l1d_size: u32,
    l1i_size: u32,
    l2_size: u32,
    l3_size: u32,

    // Timestamp of last IPI received
    last_ipi_tsc: u64,

    // Error tracking
    machine_check_count: u32,
    double_fault_count: u32,
};

pub const CpuFeatures = struct {
    has_sse: bool,
    has_sse2: bool,
    has_sse3: bool,
    has_ssse3: bool,
    has_sse4_1: bool,
    has_sse4_2: bool,
    has_avx: bool,
    has_avx2: bool,
    has_avx512: bool,
    has_aes_ni: bool,
    has_rdrand: bool,
    has_rdseed: bool,
    has_tsc: bool,
    has_tsc_deadline: bool,
    has_x2apic: bool,
    has_1gb_pages: bool,
    has_pcid: bool,
    has_smep: bool,
    has_smap: bool,
    has_umip: bool,
    has_pku: bool,
    has_fsgsbase: bool,
};

// =============================================================================
// Global SMP state
// =============================================================================

var cpu_data: [MAX_CPUS]PerCpuData = undefined;
var cpu_count: u32 = 0;
var bsp_id: u32 = 0;
var online_count: u32 = 0;
var smp_initialized: bool = false;

// AP startup synchronization
var ap_startup_lock: u32 = 0; // Simple spinlock
var ap_started: [MAX_CPUS]bool = [_]bool{false} ** MAX_CPUS;
var ap_boot_stack: u64 = 0;

// =============================================================================
// CPU feature detection
// =============================================================================

fn detectFeatures() CpuFeatures {
    var features = CpuFeatures{
        .has_sse = false,
        .has_sse2 = false,
        .has_sse3 = false,
        .has_ssse3 = false,
        .has_sse4_1 = false,
        .has_sse4_2 = false,
        .has_avx = false,
        .has_avx2 = false,
        .has_avx512 = false,
        .has_aes_ni = false,
        .has_rdrand = false,
        .has_rdseed = false,
        .has_tsc = false,
        .has_tsc_deadline = false,
        .has_x2apic = false,
        .has_1gb_pages = false,
        .has_pcid = false,
        .has_smep = false,
        .has_smap = false,
        .has_umip = false,
        .has_pku = false,
        .has_fsgsbase = false,
    };

    // CPUID leaf 1
    const leaf1 = cpuid(1);
    features.has_sse = (leaf1.edx & (1 << 25)) != 0;
    features.has_sse2 = (leaf1.edx & (1 << 26)) != 0;
    features.has_tsc = (leaf1.edx & (1 << 4)) != 0;

    features.has_sse3 = (leaf1.ecx & (1 << 0)) != 0;
    features.has_ssse3 = (leaf1.ecx & (1 << 9)) != 0;
    features.has_sse4_1 = (leaf1.ecx & (1 << 19)) != 0;
    features.has_sse4_2 = (leaf1.ecx & (1 << 20)) != 0;
    features.has_avx = (leaf1.ecx & (1 << 28)) != 0;
    features.has_aes_ni = (leaf1.ecx & (1 << 25)) != 0;
    features.has_rdrand = (leaf1.ecx & (1 << 30)) != 0;
    features.has_x2apic = (leaf1.ecx & (1 << 21)) != 0;
    features.has_tsc_deadline = (leaf1.ecx & (1 << 24)) != 0;
    features.has_pcid = (leaf1.ecx & (1 << 17)) != 0;

    // CPUID leaf 7 (structured extended features)
    const leaf7 = cpuid_subleaf(7, 0);
    features.has_avx2 = (leaf7.ebx & (1 << 5)) != 0;
    features.has_avx512 = (leaf7.ebx & (1 << 16)) != 0;
    features.has_rdseed = (leaf7.ebx & (1 << 18)) != 0;
    features.has_smep = (leaf7.ebx & (1 << 7)) != 0;
    features.has_smap = (leaf7.ebx & (1 << 20)) != 0;
    features.has_fsgsbase = (leaf7.ebx & (1 << 0)) != 0;
    features.has_umip = (leaf7.ecx & (1 << 2)) != 0;
    features.has_pku = (leaf7.ecx & (1 << 3)) != 0;

    // Extended CPUID leaf 0x80000001
    const ext_leaf = cpuid(0x80000001);
    features.has_1gb_pages = (ext_leaf.edx & (1 << 26)) != 0;

    return features;
}

/// Detect CPU cache sizes
fn detectCacheSizes(data: *PerCpuData) void {
    // CPUID leaf 4 (deterministic cache parameters)
    var subleaf: u32 = 0;
    while (subleaf < 16) : (subleaf += 1) {
        const info = cpuid_subleaf(4, subleaf);
        const cache_type = info.eax & 0x1F;
        if (cache_type == 0) break; // No more caches

        const level = (info.eax >> 5) & 0x7;
        const ways = ((info.ebx >> 22) & 0x3FF) + 1;
        const partitions = ((info.ebx >> 12) & 0x3FF) + 1;
        const line_size = (info.ebx & 0xFFF) + 1;
        const sets = info.ecx + 1;

        const size = ways * partitions * line_size * sets;

        switch (level) {
            1 => {
                if (cache_type == 1) data.l1d_size = size // Data cache
                else if (cache_type == 2) data.l1i_size = size; // Instruction cache
            },
            2 => data.l2_size = size,
            3 => data.l3_size = size,
            else => {},
        }
    }
}

// =============================================================================
// CPUID helpers
// =============================================================================

const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [zero] "{ecx}" (@as(u32, 0)),
    );

    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn cpuid_subleaf(leaf: u32, subleaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [sub] "{ecx}" (subleaf),
    );

    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

// =============================================================================
// APIC register access
// =============================================================================

const APIC_BASE_MSR: u32 = 0x1B;
const APIC_REG_ID: u32 = 0x020;
const APIC_REG_ICR_LOW: u32 = 0x300;
const APIC_REG_ICR_HIGH: u32 = 0x310;

fn readApicReg(offset: u32) u32 {
    const apic_base = getApicBase();
    const ptr: *volatile u32 = @ptrFromInt(apic_base + offset);
    return ptr.*;
}

fn writeApicReg(offset: u32, value: u32) void {
    const apic_base = getApicBase();
    const ptr: *volatile u32 = @ptrFromInt(apic_base + offset);
    ptr.* = value;
}

fn getApicBase() u64 {
    const msr = readMsr(APIC_BASE_MSR);
    return msr & 0xFFFFF000;
}

fn readMsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return @as(u64, high) << 32 | @as(u64, low);
}

fn writeMsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(value))),
          [high] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

// =============================================================================
// Inter-Processor Interrupt
// =============================================================================

/// Send an IPI to a specific CPU
pub fn sendIpi(target_apic_id: u32, vector: u8, delivery_mode: u32) void {
    // Write destination to ICR high
    writeApicReg(APIC_REG_ICR_HIGH, target_apic_id << 24);
    // Write vector + delivery mode to ICR low (triggers the IPI)
    writeApicReg(APIC_REG_ICR_LOW, @as(u32, vector) | delivery_mode | IPI_LEVEL_ASSERT);

    // Wait for delivery
    waitIpiDelivery();
}

/// Send an IPI to all CPUs except self
pub fn sendIpiBroadcast(vector: u8, delivery_mode: u32) void {
    writeApicReg(APIC_REG_ICR_HIGH, 0);
    writeApicReg(APIC_REG_ICR_LOW, @as(u32, vector) | delivery_mode | IPI_DEST_ALL_EXCL | IPI_LEVEL_ASSERT);
    waitIpiDelivery();
}

fn waitIpiDelivery() void {
    // Poll ICR delivery status bit (bit 12)
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (readApicReg(APIC_REG_ICR_LOW) & (1 << 12) == 0) return;
        asm volatile ("pause");
    }
}

// =============================================================================
// AP startup sequence (INIT-SIPI-SIPI)
// =============================================================================

fn startAP(apic_id: u32) bool {
    // Step 1: Send INIT IPI
    writeApicReg(APIC_REG_ICR_HIGH, apic_id << 24);
    writeApicReg(APIC_REG_ICR_LOW, IPI_INIT | IPI_LEVEL_ASSERT);
    waitIpiDelivery();

    // Wait 10ms
    delay(10000);

    // Step 2: Send INIT de-assert
    writeApicReg(APIC_REG_ICR_HIGH, apic_id << 24);
    writeApicReg(APIC_REG_ICR_LOW, IPI_INIT | IPI_LEVEL_DEASSERT);
    waitIpiDelivery();

    // Step 3: Send two STARTUP IPIs
    const vector: u32 = TRAMPOLINE_ADDR >> 12; // Page number
    for (0..2) |_| {
        writeApicReg(APIC_REG_ICR_HIGH, apic_id << 24);
        writeApicReg(APIC_REG_ICR_LOW, IPI_STARTUP | vector);
        waitIpiDelivery();
        delay(200);
    }

    // Wait up to 100ms for AP to signal ready
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        for (0..cpu_count) |i| {
            if (cpu_data[i].apic_id == apic_id and cpu_data[i].state == .online) {
                return true;
            }
        }
        delay(1);
    }

    return false;
}

fn delay(microseconds: u32) void {
    // Crude delay using I/O port (each read ~1µs on most hardware)
    for (0..microseconds) |_| {
        _ = asm volatile ("inb $0x80, %[result]" : [result] "={al}" (-> u8));
    }
}

// =============================================================================
// AP trampoline code (simplified — real trampoline would be assembly)
// =============================================================================

/// The trampoline code layout at TRAMPOLINE_ADDR:
/// Offset 0x000: 16-bit real mode entry (AP starts here)
/// Offset 0x100: GDT for protected→long mode transition
/// Offset 0x200: Page table pointer
/// Offset 0x208: Stack pointer for AP
/// Offset 0x210: Entry point in long mode (ap_main address)

const TRAMPOLINE_GDT_OFFSET: u32 = 0x100;
const TRAMPOLINE_CR3_OFFSET: u32 = 0x200;
const TRAMPOLINE_STACK_OFFSET: u32 = 0x208;
const TRAMPOLINE_ENTRY_OFFSET: u32 = 0x210;

fn setupTrampoline() void {
    const base: [*]u8 = @ptrFromInt(TRAMPOLINE_ADDR);

    // Copy real-mode trampoline code
    // In a real kernel, this would be a pre-assembled binary blob.
    // The trampoline does:
    //   1. cli
    //   2. Load temporary GDT
    //   3. Enable protected mode (CR0.PE)
    //   4. Far jump to 32-bit segment
    //   5. Load page tables from [TRAMPOLINE_ADDR + 0x200]
    //   6. Enable long mode (EFER.LME, CR4.PAE, CR0.PG)
    //   7. Far jump to 64-bit segment
    //   8. Set stack from [TRAMPOLINE_ADDR + 0x208]
    //   9. Jump to [TRAMPOLINE_ADDR + 0x210] (ap_main)

    // Simplified: fill with NOPs, the actual bytes would be real x86 code
    @memset(base[0..0x300], 0x90);

    // Write CR3 (kernel page table root) at offset 0x200
    const cr3: u64 = asm volatile ("mov %%cr3, %[cr3]" : [cr3] "=r" (-> u64));
    const cr3_ptr: *volatile u64 = @ptrFromInt(TRAMPOLINE_ADDR + TRAMPOLINE_CR3_OFFSET);
    cr3_ptr.* = cr3;

    // Write AP stack pointer at offset 0x208
    const stack_ptr: *volatile u64 = @ptrFromInt(TRAMPOLINE_ADDR + TRAMPOLINE_STACK_OFFSET);
    stack_ptr.* = ap_boot_stack;

    // Write AP entry address at offset 0x210
    const entry_ptr: *volatile u64 = @ptrFromInt(TRAMPOLINE_ADDR + TRAMPOLINE_ENTRY_OFFSET);
    entry_ptr.* = @intFromPtr(&apMain);
}

// =============================================================================
// AP entry point (called after trampoline transitions to long mode)
// =============================================================================

fn apMain() callconv(.C) noreturn {
    // Determine our APIC ID
    const id_reg = readApicReg(APIC_REG_ID);
    const my_apic_id = id_reg >> 24;

    // Find our CPU data slot
    var my_cpu: ?*PerCpuData = null;
    for (0..cpu_count) |i| {
        if (cpu_data[i].apic_id == my_apic_id) {
            my_cpu = &cpu_data[i];
            break;
        }
    }

    if (my_cpu) |pcpu| {
        // Mark as online
        pcpu.state = .online;
        @atomicStore(bool, &ap_started[pcpu.cpu_id], true, .release);
        @fence(.seq_cst);

        @atomicRmw(u32, &online_count, .Add, 1, .seq_cst);

        // Detect features for this CPU
        pcpu.features = detectFeatures();
        detectCacheSizes(pcpu);

        // AP idle loop
        while (true) {
            pcpu.state = .idle;
            pcpu.idle_ticks += 1;
            asm volatile ("hlt");
        }
    } else {
        // Unknown CPU — halt
        while (true) {
            asm volatile ("hlt");
        }
    }
}

// =============================================================================
// CPU topology detection (Intel: CPUID leaf 0x0B, AMD: leaf 0x8000001E)
// =============================================================================

fn detectTopology(data: *PerCpuData) void {
    // Check if leaf 0x0B is supported
    const max_leaf = cpuid(0).eax;
    if (max_leaf >= 0x0B) {
        // Intel: x2APIC topology enumeration
        const level0 = cpuid_subleaf(0x0B, 0); // SMT level
        const level1 = cpuid_subleaf(0x0B, 1); // Core level

        const smt_mask_width = level0.eax & 0x1F;
        const core_mask_width = level1.eax & 0x1F;

        const apic_id = data.apic_id;
        data.topology.thread_id = @truncate(apic_id & ((@as(u32, 1) << @truncate(smt_mask_width)) - 1));
        data.topology.core_id = @truncate((apic_id >> @truncate(smt_mask_width)) & ((@as(u32, 1) << @truncate(core_mask_width - smt_mask_width)) - 1));
        data.topology.package_id = @truncate(apic_id >> @truncate(core_mask_width));
    } else {
        // Simple fallback: assume each APIC ID = one core
        data.topology.package_id = 0;
        data.topology.core_id = @truncate(data.apic_id);
        data.topology.thread_id = 0;
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Initialize SMP subsystem (called by BSP during boot)
pub fn initialize(madt_cpus: []const u32, num_madt_cpus: usize) void {
    // The BSP's APIC ID
    const bsp_apic = readApicReg(APIC_REG_ID) >> 24;
    bsp_id = bsp_apic;

    // Initialize CPU data for all processors found in MADT
    cpu_count = 0;
    for (0..num_madt_cpus) |i| {
        if (cpu_count >= MAX_CPUS) break;

        const idx = cpu_count;
        cpu_data[idx] = std.mem.zeroes(PerCpuData);
        cpu_data[idx].cpu_id = @truncate(idx);
        cpu_data[idx].apic_id = madt_cpus[i];
        cpu_data[idx].is_bsp = (madt_cpus[i] == bsp_apic);
        cpu_data[idx].state = if (madt_cpus[i] == bsp_apic) .online else .offline;

        if (madt_cpus[i] == bsp_apic) {
            cpu_data[idx].features = detectFeatures();
            detectCacheSizes(&cpu_data[idx]);
            detectTopology(&cpu_data[idx]);
        }

        cpu_count += 1;
    }

    online_count = 1; // BSP is online

    // Setup AP trampoline
    setupTrampoline();

    // Start all APs
    for (0..cpu_count) |i| {
        if (cpu_data[i].is_bsp) continue;

        main.klog(.info, "SMP: Starting CPU {d} (APIC ID {d})...", .{ i, cpu_data[i].apic_id });

        cpu_data[i].state = .starting;

        // Allocate a 16KB stack for this AP
        // In a real kernel, this would use the physical memory allocator
        const stack_size: u64 = 16384;
        _ = stack_size;

        if (startAP(cpu_data[i].apic_id)) {
            detectTopology(&cpu_data[i]);
            main.klog(.info, "SMP: CPU {d} online (pkg={d} core={d} thr={d})", .{
                i,
                cpu_data[i].topology.package_id,
                cpu_data[i].topology.core_id,
                cpu_data[i].topology.thread_id,
            });
        } else {
            cpu_data[i].state = .offline;
            main.klog(.warning, "SMP: CPU {d} failed to start!", .{i});
        }
    }

    smp_initialized = true;
    main.klog(.info, "SMP: {d}/{d} CPUs online", .{ online_count, cpu_count });
}

/// Get number of online CPUs
pub fn getOnlineCount() u32 {
    return online_count;
}

/// Get total CPU count
pub fn getTotalCount() u32 {
    return cpu_count;
}

/// Get per-CPU data for a specific CPU
pub fn getCpuData(cpu_id: u32) ?*const PerCpuData {
    if (cpu_id >= cpu_count) return null;
    return &cpu_data[cpu_id];
}

/// Check if SMP is initialized
pub fn isInitialized() bool {
    return smp_initialized;
}

/// Get BSP's APIC ID
pub fn getBspId() u32 {
    return bsp_id;
}

/// Send a TLB shootdown IPI to all other CPUs
pub fn tlbShootdown() void {
    if (!smp_initialized or online_count <= 1) return;
    // Use a dedicated vector for TLB invalidation (e.g., vector 0xFE)
    sendIpiBroadcast(0xFE, IPI_FIXED);
}

/// Send a reschedule IPI to a specific CPU
pub fn rescheduleIpi(target_cpu: u32) void {
    if (!smp_initialized) return;
    if (target_cpu >= cpu_count) return;
    sendIpi(cpu_data[target_cpu].apic_id, 0xFD, IPI_FIXED);
}

const std = @import("std");
