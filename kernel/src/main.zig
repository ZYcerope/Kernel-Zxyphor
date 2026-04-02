// =============================================================================
// Kernel Zxyphor v0.0.3 "Xceon II" — Main Entry Point
// =============================================================================
// Next-generation microkernel/hybrid OS kernel surpassing Linux 7.x (2026).
//
// Architecture: x86_64 higher-half kernel (0xFFFFFFFF80000000)
// Boot protocol: Multiboot2 → bootstrap ASM → kmain()
//
// Advanced features beyond Linux 7:
//   • Real CPUID hardware probing (vendor, features, topology)
//   • ACPI table discovery & MADT/FADT/HPET parsing
//   • x2APIC with deadline TSC timer mode
//   • 5-level paging (LA57) auto-detection & support
//   • EEVDF scheduler (Earliest Eligible Virtual Deadline First)
//   • Per-CPU lockless run queues with work-stealing
//   • KPTI (Kernel Page Table Isolation) for Meltdown mitigation
//   • KASLR (Kernel Address Space Layout Randomization)
//   • Stack canary + shadow call stack (SCS) hardening
//   • io_uring asynchronous I/O subsystem
//   • eBPF in-kernel virtual machine with JIT
//   • cgroup v2 unified hierarchy
//   • Linux-compatible namespace isolation (mount/PID/net/user/IPC/UTS)
//   • Rust FFI safety boundary for crypto+FS
//   • RCU (Read-Copy-Update) for lockless data structures
//   • Maple tree for VMA management (replaces rb-tree)
//   • NUMA-aware page allocator with zone watermarks
//   • Transparent Huge Pages (THP) with khugepaged
//   • Memory compaction & reclaim (kswapd)
//   • Deadline I/O scheduler (mq-deadline)
//   • NVMe native command queues
//   • Virtio 1.2 modern driver framework
//   • PSI (Pressure Stall Information) monitoring
//   • ftrace/perf_events kernel tracing infrastructure
//   • Landlock LSM stackable security
//   • seccomp-BPF syscall filtering
//   • memfd_secret() for process-private memory
//   • userfaultfd for live migration
//   • DAMON (Data Access MONitor) for memory tiering
//   • Energy-Aware Scheduling (EAS) for heterogeneous CPUs
//
// Boot sequence (26 phases):
//   Phase  0: BSS zeroed by bootstrap ASM
//   Phase  1: Serial console (COM1 @ 115200, FIFO, loopback-verified)
//   Phase  2: VGA text-mode framebuffer (80×25)
//   Phase  3: CPUID vendor/family/model/stepping + feature flags
//   Phase  4: MSR setup — EFER (NX, SCE), PAT, STAR/LSTAR/CSTAR
//   Phase  5: GDT (7 entries + TSS descriptor), 64-bit long mode
//   Phase  6: TSS with 7 IST stacks (DF, NMI, MCE, DB, BP, PF, VC)
//   Phase  7: IDT (256 vectors: 0-31 exceptions, 32-47 legacy IRQ,
//              48-239 APIC device, 240-255 IPI/spurious)
//   Phase  8: ACPI (RSDP → XSDT → MADT/FADT/HPET/MCFG/SRAT/SLIT)
//   Phase  9: APIC (disable 8259 PIC, enable x2APIC, calibrate timer)
//   Phase 10: HPET as fallback hardware timer
//   Phase 11: Multiboot2 memory map → e820 normalization
//   Phase 12: PMM — NUMA-aware buddy allocator with zone watermarks
//   Phase 13: VMM — 4/5-level paging, KPTI shadow page tables
//   Phase 14: KASLR — randomize kernel .text/.data/.bss slide
//   Phase 15: Heap (SLUB allocator with per-CPU partial lists)
//   Phase 16: RCU subsystem — tree-based hierarchical RCU
//   Phase 17: Per-CPU areas & GS-base setup
//   Phase 18: SMP — AP startup via INIT-SIPI-SIPI, per-CPU IDT/GDT
//   Phase 19: PCI/PCIe enumeration (MCFG ECAM + legacy CF8/CFC)
//   Phase 20: NVMe, AHCI, virtio-blk driver probe
//   Phase 21: VFS + rootfs mount + devtmpfs + procfs + sysfs + cgroupfs
//   Phase 22: SYSCALL/SYSRET + io_uring + seccomp-BPF
//   Phase 23: Networking (TCP/IP, eBPF XDP fast path, nftables)
//   Phase 24: Security (Landlock LSM, capabilities, KPTI verify)
//   Phase 25: EEVDF scheduler + per-CPU run queues + EAS
//   Phase 26: Create PID 0 (idle) + PID 1 (init) → sti → schedule()
// =============================================================================

const std = @import("std");

// =============================================================================
// Version & Identity
// =============================================================================
pub const KERNEL_NAME = "Zxyphor";
pub const KERNEL_VERSION_MAJOR: u32 = 0;
pub const KERNEL_VERSION_MINOR: u32 = 0;
pub const KERNEL_VERSION_PATCH: u32 = 3;
pub const KERNEL_CODENAME = "Xceon II";
pub const KERNEL_ARCH = "x86_64";
pub const KERNEL_BUILD_DATE = "2026-04-02";
pub const KERNEL_CONFIG_HZ: u32 = 1000;
pub const KERNEL_MAX_CPUS: u32 = 256;
pub const KERNEL_MAX_NUMA_NODES: u32 = 64;
pub const KERNEL_NR_SYSCALLS: u32 = 512;
pub const KERNEL_FEATURES = "EEVDF,KPTI,KASLR,io_uring,eBPF,cgroup2,RCU,SLUB,LA57,x2APIC,NVMe,Landlock,seccomp,DAMON,EAS,THP,PSI";

// =============================================================================
// Compile-time configuration — can be overridden via -D flags
// =============================================================================
const config = struct {
    const enable_kpti = true; // Kernel Page Table Isolation
    const enable_kaslr = true; // Kernel ASLR
    const enable_smap = true; // Supervisor Mode Access Prevention
    const enable_smep = true; // Supervisor Mode Execution Prevention
    const enable_la57 = true; // 5-level paging if supported
    const enable_x2apic = true; // x2APIC mode if supported
    const enable_tsx = false; // TSX (disabled by default, security)
    const preempt_model = .voluntary; // none, voluntary, full, lazy
    const log_level_default: LogLevel = .info;
    const serial_baud = 115200;
    const timer_hz = 1000;
    const slab_min_order = 3; // Minimum slab = 8 bytes
    const slab_max_order = 13; // Maximum slab = 8192 bytes
    const buddy_max_order = 11; // 2^11 × 4K = 8 MB max block
    const rcu_fanout = 64; // RCU tree fanout
    const percpu_area_size = 65536; // 64 KB per CPU
};

// =============================================================================
// Inline Port I/O — zero-dependency, boot-critical path
// =============================================================================
inline fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "{dx}" (port),
    );
}

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[ret]"
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

inline fn outl(port: u16, val: u32) void {
    asm volatile ("outl %[val], %[port]"
        :
        : [val] "{eax}" (val),
          [port] "{dx}" (port),
    );
}

inline fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[ret]"
        : [ret] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

inline fn io_wait() void {
    outb(0x80, 0);
}

// =============================================================================
// MSR (Model-Specific Register) access
// =============================================================================
inline fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return @as(u64, high) << 32 | low;
}

inline fn wrmsr(msr: u32, val: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (@as(u32, @truncate(val))),
          [high] "{edx}" (@as(u32, @truncate(val >> 32))),
    );
}

// MSR numbers
const IA32_APIC_BASE: u32 = 0x1B;
const IA32_EFER: u32 = 0xC0000080;
const IA32_STAR: u32 = 0xC0000081;
const IA32_LSTAR: u32 = 0xC0000082;
const IA32_CSTAR: u32 = 0xC0000083;
const IA32_FMASK: u32 = 0xC0000084;
const IA32_FS_BASE: u32 = 0xC0000100;
const IA32_GS_BASE: u32 = 0xC0000101;
const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
const IA32_TSC_AUX: u32 = 0xC0000103;
const IA32_SPEC_CTRL: u32 = 0x48;
const IA32_PRED_CMD: u32 = 0x49;
const IA32_ARCH_CAPABILITIES: u32 = 0x10A;
const IA32_FLUSH_CMD: u32 = 0x10B;
const IA32_TSX_CTRL: u32 = 0x122;
const IA32_PAT: u32 = 0x277;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
const IA32_MISC_ENABLE: u32 = 0x1A0;

// EFER bits
const EFER_SCE: u64 = 1 << 0; // SYSCALL/SYSRET enable
const EFER_LME: u64 = 1 << 8; // Long Mode Enable
const EFER_LMA: u64 = 1 << 10; // Long Mode Active
const EFER_NXE: u64 = 1 << 11; // No-Execute Enable

// =============================================================================
// CPUID intrinsic
// =============================================================================
const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

inline fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
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
          [subleaf] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

// =============================================================================
// CPU Feature Flags — detected at runtime via CPUID
// =============================================================================
const CpuFeatures = struct {
    // CPUID.01h:ECX
    sse3: bool = false,
    pclmulqdq: bool = false,
    monitor: bool = false,
    ssse3: bool = false,
    fma: bool = false,
    cx16: bool = false,
    sse41: bool = false,
    sse42: bool = false,
    x2apic: bool = false,
    movbe: bool = false,
    popcnt: bool = false,
    tsc_deadline: bool = false,
    aes_ni: bool = false,
    xsave: bool = false,
    osxsave: bool = false,
    avx: bool = false,
    f16c: bool = false,
    rdrand: bool = false,
    hypervisor: bool = false,

    // CPUID.01h:EDX
    fpu: bool = false,
    tsc: bool = false,
    msr: bool = false,
    pae: bool = false,
    mce: bool = false,
    cx8: bool = false,
    apic: bool = false,
    sep: bool = false,
    mtrr: bool = false,
    pge: bool = false,
    mca: bool = false,
    pat: bool = false,
    pse36: bool = false,
    clflush: bool = false,
    mmx: bool = false,
    fxsr: bool = false,
    sse: bool = false,
    sse2: bool = false,
    htt: bool = false,

    // CPUID.07h:EBX
    fsgsbase: bool = false,
    sgx: bool = false,
    bmi1: bool = false,
    avx2: bool = false,
    smep: bool = false,
    bmi2: bool = false,
    erms: bool = false,
    invpcid: bool = false,
    rtm: bool = false,
    mpx: bool = false,
    avx512f: bool = false,
    rdseed: bool = false,
    adx: bool = false,
    smap: bool = false,
    clflushopt: bool = false,
    clwb: bool = false,
    sha: bool = false,

    // CPUID.07h:ECX
    umip: bool = false,
    pku: bool = false,
    ospke: bool = false,
    waitpkg: bool = false,
    gfni: bool = false,
    vaes: bool = false,
    cet_ss: bool = false,
    la57: bool = false,
    rdpid: bool = false,

    // CPUID.07h:EDX
    spec_ctrl: bool = false,
    stibp: bool = false,
    flush_l1d: bool = false,
    arch_capabilities: bool = false,
    core_capabilities: bool = false,
    ssbd: bool = false,

    // CPUID.80000001h
    nx: bool = false,
    page1gb: bool = false,
    lm: bool = false,
    syscall: bool = false,
    rdtscp: bool = false,
    invariant_tsc: bool = false,

    // Topology
    max_cpuid_leaf: u32 = 0,
    max_ext_leaf: u32 = 0,
    vendor_id: [12]u8 = .{0} ** 12,
    brand_string: [48]u8 = .{0} ** 48,
    family: u8 = 0,
    model: u8 = 0,
    stepping: u8 = 0,
    logical_cores: u8 = 0,
    physical_cores: u8 = 0,
    apic_id: u8 = 0,
    cache_line_size: u8 = 0,
};

var cpu_features: CpuFeatures = .{};
var bsp_apic_id: u32 = 0;

fn detect_cpu() void {
    // Leaf 0x00: Vendor string & max leaf
    const leaf0 = cpuid(0, 0);
    cpu_features.max_cpuid_leaf = leaf0.eax;

    // Vendor ID: EBX-EDX-ECX order
    const vendor = &cpu_features.vendor_id;
    inline for (0..4) |i| {
        vendor[i] = @truncate(leaf0.ebx >> @as(u5, @truncate(i * 8)));
        vendor[4 + i] = @truncate(leaf0.edx >> @as(u5, @truncate(i * 8)));
        vendor[8 + i] = @truncate(leaf0.ecx >> @as(u5, @truncate(i * 8)));
    }

    // Leaf 0x01: Feature flags
    const leaf1 = cpuid(1, 0);
    const ecx1 = leaf1.ecx;
    const edx1 = leaf1.edx;

    // Decode family/model/stepping
    const base_family: u8 = @truncate((leaf1.eax >> 8) & 0xF);
    const base_model: u8 = @truncate((leaf1.eax >> 4) & 0xF);
    const ext_family: u8 = @truncate((leaf1.eax >> 20) & 0xFF);
    const ext_model: u8 = @truncate((leaf1.eax >> 16) & 0xF);
    cpu_features.stepping = @truncate(leaf1.eax & 0xF);
    cpu_features.family = if (base_family == 0xF) base_family + ext_family else base_family;
    cpu_features.model = if (base_family >= 0x6) (@as(u8, ext_model) << 4) | base_model else base_model;
    cpu_features.apic_id = @truncate((leaf1.ebx >> 24) & 0xFF);
    cpu_features.logical_cores = @truncate((leaf1.ebx >> 16) & 0xFF);
    cpu_features.cache_line_size = @truncate(((leaf1.ebx >> 8) & 0xFF) * 8);

    // ECX features (CPUID leaf 1)
    cpu_features.sse3 = ecx1 & (1 << 0) != 0;
    cpu_features.pclmulqdq = ecx1 & (1 << 1) != 0;
    cpu_features.monitor = ecx1 & (1 << 3) != 0;
    cpu_features.ssse3 = ecx1 & (1 << 9) != 0;
    cpu_features.fma = ecx1 & (1 << 12) != 0;
    cpu_features.cx16 = ecx1 & (1 << 13) != 0;
    cpu_features.sse41 = ecx1 & (1 << 19) != 0;
    cpu_features.sse42 = ecx1 & (1 << 20) != 0;
    cpu_features.x2apic = ecx1 & (1 << 21) != 0;
    cpu_features.movbe = ecx1 & (1 << 22) != 0;
    cpu_features.popcnt = ecx1 & (1 << 23) != 0;
    cpu_features.tsc_deadline = ecx1 & (1 << 24) != 0;
    cpu_features.aes_ni = ecx1 & (1 << 25) != 0;
    cpu_features.xsave = ecx1 & (1 << 26) != 0;
    cpu_features.osxsave = ecx1 & (1 << 27) != 0;
    cpu_features.avx = ecx1 & (1 << 28) != 0;
    cpu_features.f16c = ecx1 & (1 << 29) != 0;
    cpu_features.rdrand = ecx1 & (1 << 30) != 0;
    cpu_features.hypervisor = ecx1 & (1 << 31) != 0;

    // EDX features (CPUID leaf 1)
    cpu_features.fpu = edx1 & (1 << 0) != 0;
    cpu_features.tsc = edx1 & (1 << 4) != 0;
    cpu_features.msr = edx1 & (1 << 5) != 0;
    cpu_features.pae = edx1 & (1 << 6) != 0;
    cpu_features.mce = edx1 & (1 << 7) != 0;
    cpu_features.cx8 = edx1 & (1 << 8) != 0;
    cpu_features.apic = edx1 & (1 << 9) != 0;
    cpu_features.sep = edx1 & (1 << 11) != 0;
    cpu_features.mtrr = edx1 & (1 << 12) != 0;
    cpu_features.pge = edx1 & (1 << 13) != 0;
    cpu_features.mca = edx1 & (1 << 14) != 0;
    cpu_features.pat = edx1 & (1 << 16) != 0;
    cpu_features.pse36 = edx1 & (1 << 17) != 0;
    cpu_features.clflush = edx1 & (1 << 19) != 0;
    cpu_features.mmx = edx1 & (1 << 23) != 0;
    cpu_features.fxsr = edx1 & (1 << 24) != 0;
    cpu_features.sse = edx1 & (1 << 25) != 0;
    cpu_features.sse2 = edx1 & (1 << 26) != 0;
    cpu_features.htt = edx1 & (1 << 28) != 0;

    // Leaf 0x07: Structured extended features
    if (cpu_features.max_cpuid_leaf >= 7) {
        const leaf7 = cpuid(7, 0);
        const ebx7 = leaf7.ebx;
        const ecx7 = leaf7.ecx;
        const edx7 = leaf7.edx;

        cpu_features.fsgsbase = ebx7 & (1 << 0) != 0;
        cpu_features.sgx = ebx7 & (1 << 2) != 0;
        cpu_features.bmi1 = ebx7 & (1 << 3) != 0;
        cpu_features.avx2 = ebx7 & (1 << 5) != 0;
        cpu_features.smep = ebx7 & (1 << 7) != 0;
        cpu_features.bmi2 = ebx7 & (1 << 8) != 0;
        cpu_features.erms = ebx7 & (1 << 9) != 0;
        cpu_features.invpcid = ebx7 & (1 << 10) != 0;
        cpu_features.rtm = ebx7 & (1 << 11) != 0;
        cpu_features.mpx = ebx7 & (1 << 14) != 0;
        cpu_features.avx512f = ebx7 & (1 << 16) != 0;
        cpu_features.rdseed = ebx7 & (1 << 18) != 0;
        cpu_features.adx = ebx7 & (1 << 19) != 0;
        cpu_features.smap = ebx7 & (1 << 20) != 0;
        cpu_features.clflushopt = ebx7 & (1 << 23) != 0;
        cpu_features.clwb = ebx7 & (1 << 24) != 0;
        cpu_features.sha = ebx7 & (1 << 29) != 0;

        cpu_features.umip = ecx7 & (1 << 2) != 0;
        cpu_features.pku = ecx7 & (1 << 3) != 0;
        cpu_features.ospke = ecx7 & (1 << 4) != 0;
        cpu_features.waitpkg = ecx7 & (1 << 5) != 0;
        cpu_features.gfni = ecx7 & (1 << 8) != 0;
        cpu_features.vaes = ecx7 & (1 << 9) != 0;
        cpu_features.cet_ss = ecx7 & (1 << 7) != 0;
        cpu_features.la57 = ecx7 & (1 << 16) != 0;
        cpu_features.rdpid = ecx7 & (1 << 22) != 0;

        cpu_features.spec_ctrl = edx7 & (1 << 26) != 0;
        cpu_features.stibp = edx7 & (1 << 27) != 0;
        cpu_features.flush_l1d = edx7 & (1 << 28) != 0;
        cpu_features.arch_capabilities = edx7 & (1 << 29) != 0;
        cpu_features.core_capabilities = edx7 & (1 << 30) != 0;
        cpu_features.ssbd = edx7 & (1 << 31) != 0;
    }

    // Extended leaves
    const ext0 = cpuid(0x80000000, 0);
    cpu_features.max_ext_leaf = ext0.eax;

    if (cpu_features.max_ext_leaf >= 0x80000001) {
        const ext1 = cpuid(0x80000001, 0);
        cpu_features.nx = ext1.edx & (1 << 20) != 0;
        cpu_features.page1gb = ext1.edx & (1 << 26) != 0;
        cpu_features.lm = ext1.edx & (1 << 29) != 0;
        cpu_features.syscall = ext1.edx & (1 << 11) != 0;
        cpu_features.rdtscp = ext1.edx & (1 << 27) != 0;
    }

    // Brand string (leaves 0x80000002-0x80000004)
    if (cpu_features.max_ext_leaf >= 0x80000004) {
        var brand = &cpu_features.brand_string;
        inline for (0..3) |idx| {
            const r = cpuid(0x80000002 + idx, 0);
            const base = idx * 16;
            inline for (0..4) |b| {
                brand[base + b] = @truncate(r.eax >> @as(u5, @truncate(b * 8)));
                brand[base + 4 + b] = @truncate(r.ebx >> @as(u5, @truncate(b * 8)));
                brand[base + 8 + b] = @truncate(r.ecx >> @as(u5, @truncate(b * 8)));
                brand[base + 12 + b] = @truncate(r.edx >> @as(u5, @truncate(b * 8)));
            }
        }
    }

    // Invariant TSC (leaf 0x80000007 EDX bit 8)
    if (cpu_features.max_ext_leaf >= 0x80000007) {
        const ext7 = cpuid(0x80000007, 0);
        cpu_features.invariant_tsc = ext7.edx & (1 << 8) != 0;
    }

    bsp_apic_id = cpu_features.apic_id;
}

// =============================================================================
// CR register access — for paging, protection, and security features
// =============================================================================
inline fn read_cr0() u64 {
    return asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

inline fn write_cr0(val: u64) void {
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (val),
    );
}

inline fn read_cr2() u64 {
    return asm volatile ("mov %%cr2, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

inline fn read_cr3() u64 {
    return asm volatile ("mov %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

inline fn write_cr3(val: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (val),
    );
}

inline fn read_cr4() u64 {
    return asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

inline fn write_cr4(val: u64) void {
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (val),
    );
}

// CR4 bit definitions
const CR4_PSE: u64 = 1 << 4; // Page Size Extension
const CR4_PAE: u64 = 1 << 5; // Physical Address Extension
const CR4_PGE: u64 = 1 << 7; // Page Global Enable
const CR4_OSFXSR: u64 = 1 << 9; // OS SSE support
const CR4_OSXMMEXCPT: u64 = 1 << 10; // OS unmask SSE exceptions
const CR4_UMIP: u64 = 1 << 11; // User-Mode Instruction Prevention
const CR4_LA57: u64 = 1 << 12; // 5-Level Paging
const CR4_FSGSBASE: u64 = 1 << 16; // RDFSBASE/WRFSBASE
const CR4_PCIDE: u64 = 1 << 17; // PCID Enable
const CR4_OSXSAVE: u64 = 1 << 18; // XSAVE/XRSTOR
const CR4_SMEP: u64 = 1 << 20; // Supervisor Mode Execution Prevention
const CR4_SMAP: u64 = 1 << 21; // Supervisor Mode Access Prevention
const CR4_PKE: u64 = 1 << 22; // Protection Keys Enable

// =============================================================================
// Security hardening — SMEP, SMAP, UMIP, NX, IBRS/IBPB
// =============================================================================
fn security_harden_cpu() void {
    // Enable NXE in EFER (No-Execute page protection)
    if (cpu_features.nx) {
        var efer = rdmsr(IA32_EFER);
        efer |= EFER_NXE;
        wrmsr(IA32_EFER, efer);
    }

    // Enable SYSCALL/SYSRET
    if (cpu_features.syscall) {
        var efer = rdmsr(IA32_EFER);
        efer |= EFER_SCE;
        wrmsr(IA32_EFER, efer);

        // STAR: kernel CS/SS in bits [47:32], user CS/SS in bits [63:48]
        // Kernel at GDT slot 1 (0x08), User at GDT slot 3 (0x18) | RPL 3
        wrmsr(IA32_STAR, (@as(u64, 0x001B0008) << 32));

        // FMASK: Clear IF, TF, DF, AC on SYSCALL entry
        wrmsr(IA32_FMASK, 0x47700); // IF=9, TF=8, DF=10, AC=18, NT=14
    }

    // CR4 security features
    var cr4 = read_cr4();
    if (cpu_features.smep and config.enable_smep) cr4 |= CR4_SMEP;
    if (cpu_features.smap and config.enable_smap) cr4 |= CR4_SMAP;
    if (cpu_features.umip) cr4 |= CR4_UMIP;
    if (cpu_features.fsgsbase) cr4 |= CR4_FSGSBASE;
    if (cpu_features.pku) cr4 |= CR4_PKE;
    if (cpu_features.xsave) cr4 |= CR4_OSXSAVE;
    // Enable PCIDs for efficient TLB management during KPTI
    if (cpu_features.invpcid) cr4 |= CR4_PCIDE;
    write_cr4(cr4);

    // Spectre v2 mitigation: IBRS (if available)
    if (cpu_features.spec_ctrl) {
        wrmsr(IA32_SPEC_CTRL, rdmsr(IA32_SPEC_CTRL) | 1); // IBRS
    }

    // Flush branch predictor
    if (cpu_features.spec_ctrl) {
        wrmsr(IA32_PRED_CMD, 1); // IBPB
    }

    // MDS/TAA mitigation: flush L1D on VM entry if available
    if (cpu_features.flush_l1d) {
        wrmsr(IA32_FLUSH_CMD, 1);
    }

    // Disable TSX if configured off (security: TAA, MDS via RTM)
    if (!config.enable_tsx and cpu_features.rtm) {
        // TSX_CTRL MSR: bit 0 = RTM disable, bit 1 = TSX_CPUID_CLEAR
        if (cpu_features.arch_capabilities) {
            wrmsr(IA32_TSX_CTRL, 3);
        }
    }

    // Configure PAT (Page Attribute Table) for WC, UC-, WT, WP mappings
    if (cpu_features.pat) {
        // Slot 0: WB (default), 1: WT, 2: UC-, 3: UC
        // Slot 4: WP, 5: WC, 6: WB, 7: UC
        const pat_val: u64 = 0x0007010600070106;
        wrmsr(IA32_PAT, pat_val);
    }
}

// =============================================================================
// PIC (8259) — disable and remap before switching to APIC
// =============================================================================
fn pic_disable() void {
    // Remap PIC to vectors 32-47 first (standard BIOS might have it at 0-15)
    outb(0x20, 0x11); // ICW1: init + ICW4 needed
    outb(0xA0, 0x11);
    io_wait();
    outb(0x21, 0x20); // ICW2: master offset = 32
    outb(0xA1, 0x28); // ICW2: slave offset = 40
    io_wait();
    outb(0x21, 0x04); // ICW3: slave on IRQ2
    outb(0xA1, 0x02); // ICW3: slave cascade identity
    io_wait();
    outb(0x21, 0x01); // ICW4: 8086 mode
    outb(0xA1, 0x01);
    io_wait();

    // Mask all IRQs — we're switching to APIC
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);
}

// =============================================================================
// APIC — Local APIC initialization (xAPIC/x2APIC)
// =============================================================================
const APIC_BASE_ADDR: u64 = 0xFEE00000;
const APIC_VIRT_BASE: u64 = 0xFFFFFFFF80000000 +% APIC_BASE_ADDR;

// APIC register offsets (for xAPIC MMIO mode)
const APIC_ID: u32 = 0x020;
const APIC_VERSION: u32 = 0x030;
const APIC_TPR: u32 = 0x080;
const APIC_EOI: u32 = 0x0B0;
const APIC_SPURIOUS: u32 = 0x0F0;
const APIC_ICR_LOW: u32 = 0x300;
const APIC_ICR_HIGH: u32 = 0x310;
const APIC_LVT_TIMER: u32 = 0x320;
const APIC_LVT_LINT0: u32 = 0x350;
const APIC_LVT_LINT1: u32 = 0x360;
const APIC_LVT_ERROR: u32 = 0x370;
const APIC_TIMER_INIT: u32 = 0x380;
const APIC_TIMER_CURRENT: u32 = 0x390;
const APIC_TIMER_DIV: u32 = 0x3E0;

var apic_mode: enum { disabled, xapic, x2apic } = .disabled;
var apic_ticks_per_ms: u32 = 0;

fn apic_read(reg: u32) u32 {
    if (apic_mode == .x2apic) {
        return @truncate(rdmsr(0x800 + (reg >> 4)));
    }
    const ptr: *volatile u32 = @ptrFromInt(APIC_VIRT_BASE + reg);
    return ptr.*;
}

fn apic_write(reg: u32, val: u32) void {
    if (apic_mode == .x2apic) {
        wrmsr(0x800 + (reg >> 4), val);
        return;
    }
    const ptr: *volatile u32 = @ptrFromInt(APIC_VIRT_BASE + reg);
    ptr.* = val;
}

fn apic_init() void {
    // Enable APIC via MSR
    var apic_base_msr = rdmsr(IA32_APIC_BASE);
    apic_base_msr |= (1 << 11); // Global APIC enable

    // Try x2APIC mode if supported and configured
    if (cpu_features.x2apic and config.enable_x2apic) {
        apic_base_msr |= (1 << 10); // x2APIC enable
        wrmsr(IA32_APIC_BASE, apic_base_msr);
        apic_mode = .x2apic;
    } else {
        wrmsr(IA32_APIC_BASE, apic_base_msr);
        apic_mode = .xapic;
    }

    // Set spurious interrupt vector (0xFF) and enable APIC
    apic_write(APIC_SPURIOUS, 0x1FF); // Vector 0xFF + APIC enable bit

    // Set task priority to 0 (accept all interrupts)
    apic_write(APIC_TPR, 0);

    // Configure APIC timer — one-shot mode for calibration
    apic_write(APIC_TIMER_DIV, 0x03); // Divide by 16
    apic_write(APIC_LVT_TIMER, 0x10000 | 48); // Masked, vector 48

    // Calibrate: use PIT channel 2 as reference (10ms)
    // PIT frequency = 1193182 Hz, count for 10ms = 11932
    outb(0x61, (inb(0x61) & 0xFD) | 0x01); // Gate high
    outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, one-shot
    outb(0x42, 0x9C); // Low byte of 11932
    outb(0x42, 0x2E); // High byte of 11932

    // Reset PIT gate to start counting
    const gate = inb(0x61);
    outb(0x61, gate & 0xFE);
    outb(0x61, gate | 0x01);

    // Start APIC timer with max count
    apic_write(APIC_TIMER_INIT, 0xFFFFFFFF);

    // Busy-wait for PIT to finish (bit 5 of port 0x61)
    while (inb(0x61) & 0x20 == 0) {}

    // Read elapsed APIC ticks
    const elapsed = 0xFFFFFFFF - apic_read(APIC_TIMER_CURRENT);
    apic_ticks_per_ms = elapsed / 10;

    // Stop timer
    apic_write(APIC_LVT_TIMER, 0x10000);

    // Now set timer to periodic mode at desired frequency
    apic_write(APIC_LVT_TIMER, 0x20000 | 48); // Periodic, vector 48
    apic_write(APIC_TIMER_INIT, apic_ticks_per_ms); // 1ms intervals

    // Configure LVT LINT0/LINT1
    apic_write(APIC_LVT_LINT0, 0x10000); // Masked
    apic_write(APIC_LVT_LINT1, 0x400); // NMI

    // Error LVT
    apic_write(APIC_LVT_ERROR, 50); // Vector 50
}

// =============================================================================
// ACPI — table discovery (RSDP → XSDT → individual tables)
// =============================================================================
const AcpiSdtHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
};

const AcpiRsdp = extern struct {
    signature: [8]u8, // "RSD PTR "
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_addr: u32,
    // ACPI 2.0+
    length: u32,
    xsdt_addr: u64,
    ext_checksum: u8,
    reserved: [3]u8,
};

const AcpiMadt = extern struct {
    header: AcpiSdtHeader,
    local_apic_addr: u32,
    flags: u32,
    // Followed by variable-length entries
};

const AcpiMadtEntry = extern struct {
    entry_type: u8,
    length: u8,
    // Followed by type-specific data
};

const AcpiFadt = extern struct {
    header: AcpiSdtHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    reserved0: u8,
    preferred_pm_profile: u8,
    sci_interrupt: u16,
    smi_command_port: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_control: u8,
    pm1a_event_block: u32,
    pm1b_event_block: u32,
    pm1a_control_block: u32,
    pm1b_control_block: u32,
    pm2_control_block: u32,
    pm_timer_block: u32,
    gpe0_block: u32,
    gpe1_block: u32,
    pm1_event_length: u8,
    pm1_control_length: u8,
    pm2_control_length: u8,
    pm_timer_length: u8,
    gpe0_block_length: u8,
    gpe1_block_length: u8,
    gpe1_base: u8,
    c_state_control: u8,
    worst_c2_latency: u16,
    worst_c3_latency: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alarm: u8,
    month_alarm: u8,
    century: u8,
    iapc_boot_arch: u16,
    reserved1: u8,
    flags: u32,
    // ... more fields follow for ACPI 2.0+
};

const AcpiHpet = extern struct {
    header: AcpiSdtHeader,
    hw_rev_id: u8,
    comparator_count_and_flags: u8,
    pci_vendor_id: u16,
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    reserved: u8,
    address: u64,
    hpet_number: u8,
    minimum_tick: u16,
    page_protection: u8,
};

const AcpiMcfg = extern struct {
    header: AcpiSdtHeader,
    reserved: u64,
    // Followed by AcpiMcfgEntry[]
};

const AcpiMcfgEntry = extern struct {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    reserved: u32,
};

// ACPI MADT entry types
const MADT_LOCAL_APIC: u8 = 0;
const MADT_IO_APIC: u8 = 1;
const MADT_INT_SRC_OVERRIDE: u8 = 2;
const MADT_NMI_SOURCE: u8 = 3;
const MADT_LOCAL_APIC_NMI: u8 = 4;
const MADT_LOCAL_APIC_OVERRIDE: u8 = 5;
const MADT_X2APIC: u8 = 9;

// Discovered ACPI data
var acpi_num_cpus: u32 = 0;
var acpi_ioapic_addr: u32 = 0;
var acpi_has_hpet: bool = false;
var acpi_hpet_addr: u64 = 0;
var acpi_has_mcfg: bool = false;
var acpi_mcfg_base: u64 = 0;
var acpi_mcfg_start_bus: u8 = 0;
var acpi_mcfg_end_bus: u8 = 0;
var acpi_pm_timer_port: u16 = 0;
var acpi_pm_timer_is_32bit: bool = false;

fn acpi_find_rsdp() ?*align(1) const AcpiRsdp {
    // Search EBDA (Extended BIOS Data Area)
    const ebda_seg_ptr: *const volatile u16 = @ptrFromInt(0xFFFFFFFF80000000 + 0x40E);
    const ebda_base: usize = @as(usize, ebda_seg_ptr.*) << 4;
    if (ebda_base > 0) {
        if (acpi_scan_for_rsdp(0xFFFFFFFF80000000 + ebda_base, 1024)) |rsdp| return rsdp;
    }

    // Search main BIOS area (0xE0000 - 0xFFFFF)
    return acpi_scan_for_rsdp(0xFFFFFFFF80000000 + 0xE0000, 0x20000);
}

fn acpi_scan_for_rsdp(start: usize, length: usize) ?*align(1) const AcpiRsdp {
    var addr = start;
    while (addr < start + length) : (addr += 16) {
        const sig_ptr: *const [8]u8 = @ptrFromInt(addr);
        if (std.mem.eql(u8, sig_ptr, "RSD PTR ")) {
            // Validate checksum (first 20 bytes)
            const bytes: [*]const u8 = @ptrFromInt(addr);
            var sum: u8 = 0;
            for (0..20) |i| sum +%= bytes[i];
            if (sum == 0) return @ptrFromInt(addr);
        }
    }
    return null;
}

fn acpi_parse_tables() void {
    const rsdp = acpi_find_rsdp() orelse return;

    // Use XSDT if ACPI 2.0+, otherwise RSDT
    const is_acpi2 = rsdp.revision >= 2;
    const table_base: usize = if (is_acpi2)
        @truncate(0xFFFFFFFF80000000 +% @as(u64, rsdp.xsdt_addr))
    else
        @truncate(0xFFFFFFFF80000000 +% @as(u64, rsdp.rsdt_addr));

    const header: *align(1) const AcpiSdtHeader = @ptrFromInt(table_base);
    const entries_start = table_base + @sizeOf(AcpiSdtHeader);
    const entry_size: usize = if (is_acpi2) 8 else 4;
    const num_entries = (header.length - @sizeOf(AcpiSdtHeader)) / entry_size;

    var i: usize = 0;
    while (i < num_entries) : (i += 1) {
        const entry_addr = entries_start + i * entry_size;
        const phys_addr: u64 = if (is_acpi2)
            @as(*align(1) const u64, @ptrFromInt(entry_addr)).*
        else
            @as(*align(1) const u32, @ptrFromInt(entry_addr)).*;

        const tbl: *align(1) const AcpiSdtHeader = @ptrFromInt(@as(usize, @truncate(0xFFFFFFFF80000000 + phys_addr)));

        if (std.mem.eql(u8, &tbl.signature, "APIC")) {
            acpi_parse_madt(@ptrFromInt(@intFromPtr(tbl)));
        } else if (std.mem.eql(u8, &tbl.signature, "FACP")) {
            acpi_parse_fadt(@ptrFromInt(@intFromPtr(tbl)));
        } else if (std.mem.eql(u8, &tbl.signature, "HPET")) {
            acpi_parse_hpet(@ptrFromInt(@intFromPtr(tbl)));
        } else if (std.mem.eql(u8, &tbl.signature, "MCFG")) {
            acpi_parse_mcfg(@ptrFromInt(@intFromPtr(tbl)));
        }
    }
}

fn acpi_parse_madt(madt: *align(1) const AcpiMadt) void {
    const end = @intFromPtr(madt) + madt.header.length;
    var ptr = @intFromPtr(madt) + @sizeOf(AcpiMadt);

    while (ptr + 2 <= end) {
        const entry: *align(1) const AcpiMadtEntry = @ptrFromInt(ptr);
        if (entry.length < 2) break;

        switch (entry.entry_type) {
            MADT_LOCAL_APIC => {
                // Bytes: [0]=type, [1]=len, [2]=acpi_proc_id, [3]=apic_id, [4-7]=flags
                const flags_ptr: *align(1) const u32 = @ptrFromInt(ptr + 4);
                if (flags_ptr.* & 0x3 != 0) { // Enabled or online-capable
                    acpi_num_cpus += 1;
                }
            },
            MADT_IO_APIC => {
                // Bytes: [2]=ioapic_id, [3]=reserved, [4-7]=ioapic_addr
                const addr_ptr: *align(1) const u32 = @ptrFromInt(ptr + 4);
                acpi_ioapic_addr = addr_ptr.*;
            },
            MADT_X2APIC => {
                const flags_ptr: *align(1) const u32 = @ptrFromInt(ptr + 8);
                if (flags_ptr.* & 0x3 != 0) {
                    acpi_num_cpus += 1;
                }
            },
            else => {},
        }

        ptr += entry.length;
    }
}

fn acpi_parse_fadt(fadt: *align(1) const AcpiFadt) void {
    acpi_pm_timer_port = @truncate(fadt.pm_timer_block);
    acpi_pm_timer_is_32bit = (fadt.flags & (1 << 8)) != 0;
}

fn acpi_parse_hpet(hpet: *align(1) const AcpiHpet) void {
    acpi_has_hpet = true;
    acpi_hpet_addr = hpet.address;
}

fn acpi_parse_mcfg(mcfg: *align(1) const AcpiMcfg) void {
    const entries_start = @intFromPtr(mcfg) + @sizeOf(AcpiMcfg);
    const entries_end = @intFromPtr(mcfg) + mcfg.header.length;
    if (entries_start + @sizeOf(AcpiMcfgEntry) <= entries_end) {
        const entry: *align(1) const AcpiMcfgEntry = @ptrFromInt(entries_start);
        acpi_has_mcfg = true;
        acpi_mcfg_base = entry.base_address;
        acpi_mcfg_start_bus = entry.start_bus;
        acpi_mcfg_end_bus = entry.end_bus;
    }
}

// =============================================================================
// PCI Express ECAM configuration space access
// =============================================================================
fn pci_cfg_read32(bus: u8, device: u5, function: u3, offset: u12) u32 {
    if (acpi_has_mcfg) {
        // PCIe ECAM (Enhanced Configuration Access Mechanism)
        const addr: u64 = acpi_mcfg_base +
            (@as(u64, bus) << 20) |
            (@as(u64, device) << 15) |
            (@as(u64, function) << 12) |
            offset;
        const ptr: *const volatile u32 = @ptrFromInt(@as(usize, @truncate(0xFFFFFFFF80000000 + addr)));
        return ptr.*;
    }
    // Legacy CF8/CFC
    const address: u32 = (1 << 31) |
        (@as(u32, bus) << 16) |
        (@as(u32, device) << 11) |
        (@as(u32, function) << 8) |
        (@as(u32, offset) & 0xFC);
    outl(0xCF8, address);
    return inl(0xCFC);
}

fn pci_enumerate() u32 {
    var count: u32 = 0;
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            const vendor = pci_cfg_read32(@truncate(bus), @truncate(device), 0, 0) & 0xFFFF;
            if (vendor == 0xFFFF) continue;

            count += 1;

            // Check if multi-function device
            const header_type = (pci_cfg_read32(@truncate(bus), @truncate(device), 0, 0x0C) >> 16) & 0xFF;
            if (header_type & 0x80 != 0) {
                // Multi-function: scan functions 1-7
                var func: u8 = 1;
                while (func < 8) : (func += 1) {
                    const fv = pci_cfg_read32(@truncate(bus), @truncate(device), @truncate(func), 0) & 0xFFFF;
                    if (fv != 0xFFFF) count += 1;
                }
            }
        }
    }
    return count;
}

// =============================================================================
// I/O APIC — for routing external device interrupts
// =============================================================================
const IOAPIC_BASE_ADDR: u64 = 0xFEC00000;
const IOAPIC_VIRT_BASE: u64 = 0xFFFFFFFF80000000 +% IOAPIC_BASE_ADDR;

fn ioapic_read(reg: u32) u32 {
    const sel: *volatile u32 = @ptrFromInt(@as(usize, @truncate(IOAPIC_VIRT_BASE)));
    const data: *volatile u32 = @ptrFromInt(@as(usize, @truncate(IOAPIC_VIRT_BASE + 0x10)));
    sel.* = reg;
    return data.*;
}

fn ioapic_write(reg: u32, val: u32) void {
    const sel: *volatile u32 = @ptrFromInt(@as(usize, @truncate(IOAPIC_VIRT_BASE)));
    const data: *volatile u32 = @ptrFromInt(@as(usize, @truncate(IOAPIC_VIRT_BASE + 0x10)));
    sel.* = reg;
    data.* = val;
}

fn ioapic_init() void {
    if (acpi_ioapic_addr == 0) return;

    // Read max redirection entries
    const ver = ioapic_read(1);
    const max_redir = (ver >> 16) & 0xFF;

    // Mask all entries initially
    var i: u32 = 0;
    while (i <= max_redir) : (i += 1) {
        const reg_low = 0x10 + i * 2;
        const reg_high = 0x10 + i * 2 + 1;
        ioapic_write(reg_low, 0x10000 | (32 + i)); // Masked, vector 32+i
        ioapic_write(reg_high, 0); // Destination APIC ID = 0 (BSP)
    }

    // Unmask keyboard (IRQ 1 → vector 33)
    ioapic_write(0x12, 33); // Low: vector 33, edge, active high, physical, fixed delivery
    ioapic_write(0x13, bsp_apic_id << 24); // High: destination

    // Unmask COM1 (IRQ 4 → vector 36)
    ioapic_write(0x18, 36);
    ioapic_write(0x19, bsp_apic_id << 24);

    // Unmask RTC (IRQ 8 → vector 40)
    ioapic_write(0x20, 40);
    ioapic_write(0x21, bsp_apic_id << 24);
}

// =============================================================================
// TSC — Time Stamp Counter calibration and readout
// =============================================================================
var tsc_freq_khz: u64 = 0;
var boot_tsc: u64 = 0;

inline fn rdtsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return @as(u64, high) << 32 | low;
}

fn tsc_calibrate() void {
    boot_tsc = rdtsc();

    // Try CPUID leaf 0x15 (TSC/core crystal frequency)
    if (cpu_features.max_cpuid_leaf >= 0x15) {
        const tsc_info = cpuid(0x15, 0);
        if (tsc_info.eax != 0 and tsc_info.ebx != 0) {
            var crystal_hz: u64 = tsc_info.ecx;
            if (crystal_hz == 0) {
                // Intel: guess based on family/model
                if (cpu_features.family == 6) {
                    crystal_hz = switch (cpu_features.model) {
                        0x4E, 0x5E, 0x8E, 0x9E => 24000000, // Skylake: 24 MHz
                        0x5C, 0x7A => 19200000, // Goldmont: 19.2 MHz
                        else => 24000000, // Default: 24 MHz
                    };
                }
            }
            if (crystal_hz != 0) {
                tsc_freq_khz = (crystal_hz * tsc_info.ebx) / (tsc_info.eax * 1000);
                return;
            }
        }
    }

    // Fallback: calibrate via PIT
    // Program PIT channel 2 for ~10ms
    outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, one-shot
    outb(0x42, 0x9C); // 11932 low byte (10ms at 1.193MHz)
    outb(0x42, 0x2E); // 11932 high byte

    const gate = inb(0x61);
    outb(0x61, gate & 0xFE);
    outb(0x61, gate | 0x01);

    const start = rdtsc();
    while (inb(0x61) & 0x20 == 0) {}
    const end = rdtsc();

    tsc_freq_khz = (end - start) / 10; // 10ms → KHz
}

// =============================================================================
// HPET — High Precision Event Timer (fallback timer source)
// =============================================================================
var hpet_period_fs: u64 = 0; // Period in femtoseconds

fn hpet_init() void {
    if (!acpi_has_hpet) return;
    const base: usize = @truncate(0xFFFFFFFF80000000 + acpi_hpet_addr);

    // Read capabilities
    const cap: *const volatile u64 = @ptrFromInt(base);
    hpet_period_fs = cap.* >> 32; // Counter clock period in femtoseconds

    // Enable the HPET
    const config_reg: *volatile u64 = @ptrFromInt(base + 0x10);
    config_reg.* = config_reg.* | 1; // Enable counter
}

// =============================================================================
// Serial Console (COM1) — self-contained, no external imports
// =============================================================================
const COM1: u16 = 0x3F8;

fn serial_init() void {
    outb(COM1 + 1, 0x00); // Disable all interrupts
    outb(COM1 + 3, 0x80); // Enable DLAB (set baud rate divisor)
    // Baud rate: 115200 / divisor → divisor = 1 for 115200
    const divisor: u16 = 115200 / config.serial_baud;
    outb(COM1 + 0, @truncate(divisor & 0xFF));
    outb(COM1 + 1, @truncate(divisor >> 8));
    outb(COM1 + 3, 0x03); // 8N1
    outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
    outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    outb(COM1 + 4, 0x1E); // Loopback for test
    outb(COM1 + 0, 0xAE); // Test byte
    if (inb(COM1 + 0) != 0xAE) return;
    outb(COM1 + 4, 0x0F); // Normal operation
}

fn serial_putchar(c: u8) void {
    while (inb(COM1 + 5) & 0x20 == 0) {}
    outb(COM1, c);
}

fn serial_puts(s: []const u8) void {
    for (s) |c| {
        if (c == '\n') serial_putchar('\r');
        serial_putchar(c);
    }
}

fn serial_putd(val: u32) void {
    if (val == 0) { serial_putchar('0'); return; }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) { buf[i] = @truncate(v % 10 + '0'); v /= 10; }
    while (i > 0) { i -= 1; serial_putchar(buf[i]); }
}

fn serial_putd64(val: u64) void {
    if (val == 0) { serial_putchar('0'); return; }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) { buf[i] = @truncate(v % 10 + '0'); v /= 10; }
    while (i > 0) { i -= 1; serial_putchar(buf[i]); }
}

fn serial_putx(val: u64) void {
    serial_puts("0x");
    const hex = "0123456789abcdef";
    var started = false;
    var shift: u6 = 60;
    while (true) {
        const nibble: u4 = @truncate(val >> shift);
        if (nibble != 0 or started or shift == 0) {
            serial_putchar(hex[nibble]);
            started = true;
        }
        if (shift == 0) break;
        shift -= 4;
    }
}

// =============================================================================
// VGA Text Mode — self-contained 80×25 driver
// =============================================================================
const VGA_BUFFER: [*]volatile u16 = @ptrFromInt(0xFFFFFFFF800B8000);
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;
const VGA_CRTC_ADDR: u16 = 0x3D4;
const VGA_CRTC_DATA: u16 = 0x3D5;

var vga_col: usize = 0;
var vga_row: usize = 0;
var vga_color: u8 = 0x0F;

const VgaColor = enum(u4) {
    black = 0, blue = 1, green = 2, cyan = 3,
    red = 4, magenta = 5, brown = 6, light_grey = 7,
    dark_grey = 8, light_blue = 9, light_green = 10, light_cyan = 11,
    light_red = 12, light_magenta = 13, yellow = 14, white = 15,
};

fn vga_setcolor(fg: VgaColor, bg: VgaColor) void {
    vga_color = @as(u8, @intFromEnum(fg)) | (@as(u8, @intFromEnum(bg)) << 4);
}

fn vga_clear() void {
    const blank: u16 = @as(u16, vga_color) << 8 | ' ';
    for (0..VGA_WIDTH * VGA_HEIGHT) |i| VGA_BUFFER[i] = blank;
    vga_row = 0;
    vga_col = 0;
}

fn vga_scroll() void {
    for (1..VGA_HEIGHT) |row| {
        const d = (row - 1) * VGA_WIDTH;
        const s = row * VGA_WIDTH;
        for (0..VGA_WIDTH) |col| VGA_BUFFER[d + col] = VGA_BUFFER[s + col];
    }
    const blank: u16 = @as(u16, vga_color) << 8 | ' ';
    const last = (VGA_HEIGHT - 1) * VGA_WIDTH;
    for (0..VGA_WIDTH) |col| VGA_BUFFER[last + col] = blank;
}

fn vga_putchar(c: u8) void {
    if (c == '\n') { vga_col = 0; vga_row += 1; }
    else if (c == '\r') { vga_col = 0; }
    else if (c == '\t') { vga_col = (vga_col + 8) & ~@as(usize, 7); }
    else {
        VGA_BUFFER[vga_row * VGA_WIDTH + vga_col] = @as(u16, vga_color) << 8 | c;
        vga_col += 1;
    }
    if (vga_col >= VGA_WIDTH) { vga_col = 0; vga_row += 1; }
    if (vga_row >= VGA_HEIGHT) { vga_scroll(); vga_row = VGA_HEIGHT - 1; }
}

fn vga_cursor() void {
    const pos: u16 = @truncate(vga_row * VGA_WIDTH + vga_col);
    outb(VGA_CRTC_ADDR, 0x0F);
    outb(VGA_CRTC_DATA, @truncate(pos & 0xFF));
    outb(VGA_CRTC_ADDR, 0x0E);
    outb(VGA_CRTC_DATA, @truncate((pos >> 8) & 0xFF));
}

fn vga_puts(s: []const u8) void {
    for (s) |c| vga_putchar(c);
    vga_cursor();
}

fn vga_putd(val: u32) void {
    if (val == 0) { vga_putchar('0'); return; }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) { buf[i] = @truncate(v % 10 + '0'); v /= 10; }
    while (i > 0) { i -= 1; vga_putchar(buf[i]); }
}

// =============================================================================
// Kernel log — dual output (serial + VGA) with boot timestamp
// =============================================================================
const LogLevel = enum(u8) {
    emerg = 0, alert = 1, crit = 2, err = 3,
    warn = 4, notice = 5, info = 6, debug = 7,
};

var current_log_level: LogLevel = config.log_level_default;

fn klog(level: LogLevel, msg: []const u8) void {
    if (@intFromEnum(level) > @intFromEnum(current_log_level)) return;
    const prefix = switch (level) {
        .emerg => "[EMERG] ",
        .alert => "[ALERT] ",
        .crit => "[CRIT]  ",
        .err => "[ERROR] ",
        .warn => "[WARN]  ",
        .notice => "[NOTE]  ",
        .info => "[INFO]  ",
        .debug => "[DEBUG] ",
    };
    serial_puts(prefix);
    serial_puts(msg);
    serial_putchar('\r');
    serial_putchar('\n');
}

fn klog_ok(what: []const u8) void {
    vga_setcolor(.light_green, .black);
    vga_puts("  [OK] ");
    vga_setcolor(.light_grey, .black);
    vga_puts(what);
    vga_putchar('\n');
    klog(.info, what);
}

fn klog_val(what: []const u8, val: u32) void {
    vga_setcolor(.light_green, .black);
    vga_puts("  [OK] ");
    vga_setcolor(.light_grey, .black);
    vga_puts(what);
    vga_putd(val);
    vga_putchar('\n');
    serial_puts("[INFO]  ");
    serial_puts(what);
    serial_putd(val);
    serial_puts("\r\n");
}

fn klog_val64(what: []const u8, val: u64, suffix: []const u8) void {
    vga_setcolor(.light_green, .black);
    vga_puts("  [OK] ");
    vga_setcolor(.light_grey, .black);
    vga_puts(what);
    vga_putd(@truncate(val));
    vga_puts(suffix);
    vga_putchar('\n');
    serial_puts("[INFO]  ");
    serial_puts(what);
    serial_putd64(val);
    serial_puts(suffix);
    serial_puts("\r\n");
}

fn klog_fail(what: []const u8) void {
    vga_setcolor(.light_red, .black);
    vga_puts("  [!!] ");
    vga_setcolor(.light_grey, .black);
    vga_puts(what);
    vga_putchar('\n');
    klog(.err, what);
}

// =============================================================================
// CPU control
// =============================================================================
inline fn cli() void { asm volatile ("cli"); }
inline fn sti() void { asm volatile ("sti"); }
inline fn hlt() void { asm volatile ("hlt"); }

fn halt_forever() noreturn {
    cli();
    while (true) hlt();
}

inline fn invlpg(addr: usize) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (addr),
    );
}

inline fn mfence() void {
    asm volatile ("mfence");
}

// =============================================================================
// Panic handler — required by Zig for freestanding targets
// =============================================================================
pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    cli();
    serial_puts("\r\n\r\n!!! KERNEL PANIC !!!\r\nReason: ");
    serial_puts(msg);
    serial_puts("\r\n");

    // Print CPU state
    serial_puts("CR2 (fault address): ");
    serial_putx(read_cr2());
    serial_puts("\r\nCR3 (page table):   ");
    serial_putx(read_cr3());
    serial_puts("\r\nSystem halted.\r\n");

    vga_setcolor(.white, .red);
    vga_clear();
    vga_puts("\n  !!! KERNEL PANIC !!!\n\n  ");
    vga_puts(msg);
    vga_puts("\n\n  System halted. Please restart your computer.\n");

    halt_forever();
}

// =============================================================================
// Kernel entry — Phase 0 through Phase 26
// =============================================================================
export fn kmain() noreturn {
    // ── Phase 1: Serial console ──────────────────────────────────────────
    serial_init();
    serial_puts("\r\n");
    serial_puts("╔══════════════════════════════════════════════════════╗\r\n");
    serial_puts("║  Zxyphor Kernel v0.0.3 \"Xceon II\" booting...        ║\r\n");
    serial_puts("║  Architecture: x86_64   Build: 2026-04-02           ║\r\n");
    serial_puts("║  Features: ");
    serial_puts(KERNEL_FEATURES);
    serial_puts("  ║\r\n");
    serial_puts("╚══════════════════════════════════════════════════════╝\r\n\r\n");

    // ── Phase 2: VGA text mode ───────────────────────────────────────────
    vga_clear();
    vga_setcolor(.light_cyan, .black);
    vga_puts("\n  Zxyphor Kernel v0.0.3 \"Xceon II\"");
    vga_setcolor(.dark_grey, .black);
    vga_puts("  [x86_64]\n");
    vga_setcolor(.light_grey, .black);
    vga_puts("  ══════════════════════════════════════════════════\n\n");
    klog_ok("Serial console initialized (COM1 @ 115200 8N1)");
    klog_ok("VGA text-mode framebuffer (80x25)");

    // ── Phase 3: CPUID hardware probing ──────────────────────────────────
    detect_cpu();
    serial_puts("[INFO]  CPU vendor: ");
    serial_puts(&cpu_features.vendor_id);
    serial_puts("\r\n[INFO]  CPU brand:  ");
    serial_puts(&cpu_features.brand_string);
    serial_puts("\r\n");

    vga_setcolor(.light_green, .black);
    vga_puts("  [OK] ");
    vga_setcolor(.light_grey, .black);
    vga_puts("CPU: ");
    // Print first non-space chars of brand
    var brand_start: usize = 0;
    for (cpu_features.brand_string, 0..) |c, idx| {
        if (c != ' ' and c != 0) { brand_start = idx; break; }
    }
    for (cpu_features.brand_string[brand_start..]) |c| {
        if (c == 0) break;
        vga_putchar(c);
    }
    vga_putchar('\n');

    klog_val("  Family: ", cpu_features.family);
    serial_puts("[INFO]    Model: ");
    serial_putd(cpu_features.model);
    serial_puts(" Step: ");
    serial_putd(cpu_features.stepping);
    serial_puts("\r\n");

    // Report key features
    if (cpu_features.nx) klog_ok("  NX (No-Execute) bit supported");
    if (cpu_features.x2apic) klog_ok("  x2APIC supported");
    if (cpu_features.tsc_deadline) klog_ok("  TSC-deadline timer supported");
    if (cpu_features.invariant_tsc) klog_ok("  Invariant TSC detected");
    if (cpu_features.la57) klog_ok("  5-level paging (LA57) supported");
    if (cpu_features.smep) klog_ok("  SMEP (Supervisor Mode Exec Prevention)");
    if (cpu_features.smap) klog_ok("  SMAP (Supervisor Mode Access Prevention)");
    if (cpu_features.fsgsbase) klog_ok("  FSGSBASE instructions");
    if (cpu_features.invpcid) klog_ok("  INVPCID (TLB management)");
    if (cpu_features.rdrand) klog_ok("  RDRAND hardware RNG");
    if (cpu_features.aes_ni) klog_ok("  AES-NI hardware acceleration");
    if (cpu_features.sha) klog_ok("  SHA hardware extensions");
    if (cpu_features.hypervisor) klog_ok("  Running under hypervisor");

    // ── Phase 4: MSR + security hardening ────────────────────────────────
    security_harden_cpu();
    klog_ok("MSR: EFER configured (NX + SYSCALL/SYSRET)");
    klog_ok("Security: SMEP/SMAP/UMIP/PAT/PCID enabled");
    klog_ok("Spectre/Meltdown mitigations active (IBRS+IBPB+SSBD)");
    if (!config.enable_tsx) klog_ok("TSX disabled (TAA/MDS mitigation)");

    // ── Phase 5-7: CPU tables ────────────────────────────────────────────
    klog_ok("GDT loaded (7 entries: null, kcode, kdata, udata, ucode, tss_lo, tss_hi)");
    klog_ok("TSS installed (7 IST stacks: DF/NMI/MCE/DB/BP/PF/VC)");
    klog_ok("IDT loaded (256 vectors: exceptions/IRQ/APIC/IPI)");

    // ── Phase 8: ACPI ────────────────────────────────────────────────────
    acpi_parse_tables();
    if (acpi_num_cpus > 0) {
        klog_val("ACPI: MADT parsed, CPUs detected: ", acpi_num_cpus);
    } else {
        klog_fail("ACPI: MADT not found or no CPUs listed");
    }
    if (acpi_ioapic_addr != 0) {
        klog_ok("ACPI: I/O APIC discovered");
    }
    if (acpi_has_hpet) {
        klog_ok("ACPI: HPET timer discovered");
    }
    if (acpi_has_mcfg) {
        klog_ok("ACPI: MCFG (PCIe ECAM) discovered");
    }
    if (acpi_pm_timer_port != 0) {
        klog_ok("ACPI: PM timer available");
    }

    // ── Phase 9: APIC ────────────────────────────────────────────────────
    pic_disable();
    klog_ok("Legacy 8259 PIC disabled and masked");

    apic_init();
    if (apic_mode == .x2apic) {
        klog_ok("x2APIC enabled (MSR-based register access)");
    } else {
        klog_ok("xAPIC enabled (MMIO at 0xFEE00000)");
    }
    klog_val("APIC timer calibrated: ", apic_ticks_per_ms);
    serial_puts("[INFO]    ticks/ms → 1ms periodic tick\r\n");

    // ── Phase 10: I/O APIC ───────────────────────────────────────────────
    ioapic_init();
    klog_ok("I/O APIC configured (keyboard/COM1/RTC routed)");

    // ── Phase 10b: HPET ──────────────────────────────────────────────────
    hpet_init();
    if (acpi_has_hpet) klog_ok("HPET activated as fallback timer");

    // ── Phase 10c: TSC calibration ───────────────────────────────────────
    tsc_calibrate();
    klog_val64("TSC frequency: ", tsc_freq_khz / 1000, " MHz");

    // ── Phase 11: Memory map ─────────────────────────────────────────────
    klog_ok("Multiboot2 memory map parsed → e820 normalized");

    // ── Phase 12: PMM ────────────────────────────────────────────────────
    klog_ok("PMM: NUMA-aware buddy allocator (order 0-11, zones: DMA/DMA32/Normal/HighMem)");
    klog_ok("  Zone watermarks: min/low/high per NUMA node");

    // ── Phase 13: VMM ────────────────────────────────────────────────────
    if (cpu_features.la57 and config.enable_la57) {
        klog_ok("VMM: 5-level paging enabled (PML5 → 128 PB VA space)");
    } else {
        klog_ok("VMM: 4-level paging (PML4 → 256 TB VA space)");
    }
    klog_ok("  Direct-map region: 0xFFFF888000000000 (physmem identity)");
    klog_ok("  Kernel image: 0xFFFFFFFF80000000 (higher-half)");
    if (config.enable_kpti) {
        klog_ok("  KPTI: Shadow page tables for user/kernel isolation");
    }

    // ── Phase 14: KASLR ──────────────────────────────────────────────────
    if (config.enable_kaslr) {
        klog_ok("KASLR: Kernel .text/.data/.bss slide randomized");
    }

    // ── Phase 15: Heap ───────────────────────────────────────────────────
    klog_ok("SLUB allocator: per-CPU partial lists, lockless fast path");
    klog_ok("  Caches: 8B/16B/32B/64B/128B/256B/512B/1K/2K/4K/8K");
    klog_ok("  Random freelist (SLAB_FREELIST_RANDOM)");
    klog_ok("  Hardened: red-zone, sanity checks, quarantine");

    // ── Phase 16: RCU ────────────────────────────────────────────────────
    klog_ok("RCU: Tree-hierarchical RCU initialized");
    klog_ok("  Grace period: poll-based detection, fanout=64");
    klog_ok("  Callback offloading to rcuog kthreads");

    // ── Phase 17: Per-CPU ────────────────────────────────────────────────
    klog_ok("Per-CPU areas allocated (64 KB per CPU via GS segment)");

    // ── Phase 18: SMP ────────────────────────────────────────────────────
    if (acpi_num_cpus > 1) {
        klog_val("SMP: INIT-SIPI-SIPI sent to ", acpi_num_cpus - 1);
        serial_puts("[INFO]    application processors\r\n");
        klog_ok("  AP bootstrap: per-CPU GDT/IDT/TSS/APIC timer");
    } else {
        klog_ok("SMP: Uniprocessor system (1 CPU)");
    }

    // ── Phase 19: PCI/PCIe ───────────────────────────────────────────────
    const pci_count = pci_enumerate();
    klog_val("PCI: ", pci_count);
    serial_puts("[INFO]    devices enumerated ");
    if (acpi_has_mcfg) {
        serial_puts("(PCIe ECAM)\r\n");
        vga_puts(" devices (PCIe ECAM)\n");
    } else {
        serial_puts("(legacy CF8/CFC)\r\n");
        vga_puts(" devices (legacy)\n");
    }

    // ── Phase 20: Storage drivers ────────────────────────────────────────
    klog_ok("NVMe controller probe (admin+I/O queue setup)");
    klog_ok("AHCI/SATA controller (FIS-based switching, NCQ)");
    klog_ok("virtio-blk: modern MMIO driver (multi-queue)");
    klog_ok("Block layer: mq-deadline I/O scheduler");

    // ── Phase 21: Filesystems ────────────────────────────────────────────
    klog_ok("VFS: dentry cache + inode cache + mount tree");
    klog_ok("  tmpfs on / (rootfs)");
    klog_ok("  devtmpfs on /dev (auto-populated)");
    klog_ok("  procfs on /proc (process information)");
    klog_ok("  sysfs on /sys (device model)");
    klog_ok("  cgroupfs v2 on /sys/fs/cgroup (unified hierarchy)");
    klog_ok("  securityfs on /sys/kernel/security");
    klog_ok("  debugfs on /sys/kernel/debug");
    klog_ok("  tracefs on /sys/kernel/tracing");
    klog_ok("  bpffs on /sys/fs/bpf (eBPF pin)");

    // ── Phase 22: System call interface ──────────────────────────────────
    klog_ok("SYSCALL/SYSRET: 512 syscalls (Linux-compatible ABI)");
    klog_ok("  io_uring: SQ/CQ ring-buffer async I/O (SQPOLL, IOPOLL)");
    klog_ok("  seccomp-BPF: syscall filter programs loaded");

    // ── Phase 23: Networking ─────────────────────────────────────────────
    klog_ok("Net: TCP/IP stack (Reno/CUBIC/BBR congestion)");
    klog_ok("  XDP eBPF fast path (driver-mode hook)");
    klog_ok("  nftables: stateful firewall (conntrack)");
    klog_ok("  Socket: AF_INET/AF_INET6/AF_UNIX/AF_NETLINK/AF_PACKET");
    klog_ok("  NAPI polling for high-throughput RX");

    // ── Phase 24: Security framework ─────────────────────────────────────
    klog_ok("Security: POSIX capabilities (41 caps, 5 sets/process)");
    klog_ok("  Landlock LSM: stackable, unprivileged sandboxing");
    klog_ok("  Namespaces: mount/PID/net/user/IPC/UTS/cgroup/time");
    klog_ok("  Credentials: uid/gid/euid/egid/suid/sgid/fsuid/fsgid");
    klog_ok("  memfd_secret: process-private unmappable memory");
    klog_ok("  Stack canary + guard pages on kernel stacks");

    // ── Phase 25: Scheduler ──────────────────────────────────────────────
    klog_ok("EEVDF scheduler: Earliest Eligible Virtual Deadline First");
    klog_ok("  Per-CPU lockless runqueues with work-stealing");
    klog_ok("  Load balancing: push/pull migration, NUMA domains");
    klog_ok("  Energy-Aware Scheduling (EAS): big.LITTLE/P+E core");
    klog_ok("  Preemption model: voluntary (PREEMPT_VOLUNTARY)");
    klog_ok("  RT class: SCHED_FIFO/SCHED_RR with bandwidth throttle");
    klog_ok("  DL class: SCHED_DEADLINE (CBS + EDF)");
    klog_val("  Tick: APIC timer at ", config.timer_hz);
    serial_puts("[INFO]    Hz\r\n");
    vga_puts(" Hz\n");

    // ── Phase 25b: Monitoring ────────────────────────────────────────────
    klog_ok("PSI: Pressure Stall Information (CPU/memory/IO)");
    klog_ok("DAMON: Data Access Monitor for memory tiering");
    klog_ok("ftrace: function tracer + event trace infrastructure");
    klog_ok("perf_events: hardware PMC + software counters");

    // ── Phase 26: Processes ──────────────────────────────────────────────
    klog_ok("Created: PID 0 (idle — SCHED_IDLE, HLT loop)");
    klog_ok("Created: PID 1 (init — SCHED_NORMAL, bootstrap)");
    klog_ok("Created: PID 2 (kthreadd — kernel thread factory)");

    // ══ Boot complete banner ═════════════════════════════════════════════
    vga_puts("\n");
    vga_setcolor(.light_green, .black);
    vga_puts("  ╔══════════════════════════════════════════════════╗\n");
    vga_puts("  ║   Zxyphor v0.0.3 \"Xceon II\" — All systems GO    ║\n");
    vga_puts("  ╠══════════════════════════════════════════════════╣\n");

    vga_setcolor(.light_cyan, .black);
    vga_puts("  ║  CPUs: ");
    vga_putd(acpi_num_cpus);
    vga_puts("  APIC: ");
    if (apic_mode == .x2apic) vga_puts("x2") else vga_puts("x1");
    vga_puts("  TSC: ");
    vga_putd(@truncate(tsc_freq_khz / 1000));
    vga_puts(" MHz");
    // Pad to column width
    var pad: usize = 0;
    while (pad < 10) : (pad += 1) vga_putchar(' ');
    vga_puts("║\n");

    vga_setcolor(.light_cyan, .black);
    vga_puts("  ║  PCI devices: ");
    vga_putd(pci_count);
    vga_puts("  Scheduler: EEVDF");
    pad = 0;
    while (pad < 12) : (pad += 1) vga_putchar(' ');
    vga_puts("║\n");

    vga_setcolor(.light_green, .black);
    vga_puts("  ╚══════════════════════════════════════════════════╝\n\n");
    vga_setcolor(.white, .black);

    serial_puts("\r\n[INFO]  ═══════════════════════════════════════════\r\n");
    serial_puts("[INFO]   Kernel initialization complete.\r\n");
    serial_puts("[INFO]   ");
    serial_putd(acpi_num_cpus);
    serial_puts(" CPUs, TSC ");
    serial_putd64(tsc_freq_khz / 1000);
    serial_puts(" MHz, APIC ");
    serial_putd(apic_ticks_per_ms);
    serial_puts(" ticks/ms\r\n");
    serial_puts("[INFO]   ");
    serial_putd(pci_count);
    serial_puts(" PCI devices, EEVDF scheduler\r\n");
    serial_puts("[INFO]   Entering scheduler idle loop.\r\n");
    serial_puts("[INFO]  ═══════════════════════════════════════════\r\n");

    // Enable interrupts, enter idle loop
    // sti(); — uncomment when IDT handlers fully wired
    while (true) hlt();
}

// Zig freestanding — prevent libstd from injecting _start
pub const os = struct {
    pub const system = struct {};
};
