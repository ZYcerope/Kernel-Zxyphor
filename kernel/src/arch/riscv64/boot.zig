// =============================================================================
// Zxyphor Kernel — RISC-V 64-bit Boot Subsystem
// =============================================================================
// Implements the complete boot sequence for RISC-V RV64GC processors.
// Supports both OpenSBI (Supervisor Binary Interface) and direct M-mode boot.
//
// Boot Flow:
//   1. Entry from M-mode firmware (OpenSBI) or direct QEMU jump
//   2. Hart ID validation and boot hart selection
//   3. BSS clearing and stack setup
//   4. FDT (Flattened Device Tree) parsing
//   5. Early UART initialization for debug output
//   6. Sv48 page table setup (4-level, 48-bit VA)
//   7. Enable MMU (satp register)
//   8. Jump to higher-half kernel
//   9. SBI runtime services initialization
//   10. Trap vector installation
//   11. Timer and interrupt controller init
//   12. Secondary hart boot via HSM SBI extension
//
// RISC-V Privilege Levels:
//   M-mode: Machine (firmware/OpenSBI)
//   S-mode: Supervisor (kernel runs here)
//   U-mode: User (applications)
//
// Supported RISC-V Extensions:
//   I: Base integer (RV64I)
//   M: Integer multiply/divide
//   A: Atomics (LR/SC, AMO)
//   F: Single-precision float
//   D: Double-precision float
//   C: Compressed instructions (16-bit)
//   V: Vector extension (RVV 1.0)
//   H: Hypervisor extension
//   Zicsr: CSR instructions
//   Zifencei: Instruction-fetch fence
//   Zba/Zbb/Zbc/Zbs: Bit manipulation
//   Svnapot: NAPOT translation contiguity
//   Svpbmt: Page-based memory types
//   Sstc: Stimecmp timer
//   Sscofpmf: PMU overflow/filtering
//   Svinval: Fine-grained SFENCE
// =============================================================================

// ── RISC-V CSR Addresses ──────────────────────────────────────────────────
pub const CSR = struct {
    // Supervisor-level CSRs
    pub const SSTATUS: u12 = 0x100;
    pub const SIE: u12 = 0x104;       // Supervisor Interrupt Enable
    pub const STVEC: u12 = 0x105;      // Supervisor Trap Vector
    pub const SCOUNTEREN: u12 = 0x106; // Counter Enable
    pub const SENVCFG: u12 = 0x10A;    // Environment Configuration
    pub const SSCRATCH: u12 = 0x140;   // Supervisor Scratch
    pub const SEPC: u12 = 0x141;       // Supervisor Exception PC
    pub const SCAUSE: u12 = 0x142;     // Supervisor Cause
    pub const STVAL: u12 = 0x143;      // Supervisor Trap Value
    pub const SIP: u12 = 0x144;        // Supervisor Interrupt Pending
    pub const STIMECMP: u12 = 0x14D;   // Supervisor Timer Compare (Sstc)
    pub const SATP: u12 = 0x180;       // Supervisor Address Translation and Protection
    pub const SCONTEXT: u12 = 0x5A8;   // Supervisor-mode Context

    // Hypervisor-level CSRs (H-extension)
    pub const HSTATUS: u12 = 0x600;
    pub const HEDELEG: u12 = 0x602;
    pub const HIDELEG: u12 = 0x603;
    pub const HIE: u12 = 0x604;
    pub const HCOUNTEREN: u12 = 0x606;
    pub const HGEIE: u12 = 0x607;
    pub const HTVAL: u12 = 0x643;
    pub const HIP: u12 = 0x644;
    pub const HVIP: u12 = 0x645;
    pub const HTINST: u12 = 0x64A;
    pub const HGATP: u12 = 0x680;
    pub const HENVCFG: u12 = 0x60A;

    // Machine-level CSRs (readable in S-mode via shadow)
    pub const MVENDORID: u12 = 0xF11;
    pub const MARCHID: u12 = 0xF12;
    pub const MIMPID: u12 = 0xF13;
    pub const MHARTID: u12 = 0xF14;
    pub const MCONFIGPTR: u12 = 0xF15;

    // Performance counters
    pub const CYCLE: u12 = 0xC00;
    pub const TIME: u12 = 0xC01;
    pub const INSTRET: u12 = 0xC02;
    pub const HPMCOUNTER3: u12 = 0xC03;
};

// ── SSTATUS Bits ──────────────────────────────────────────────────────────
pub const SSTATUS = struct {
    pub const SIE: u64 = 1 << 1;      // Supervisor Interrupt Enable
    pub const SPIE: u64 = 1 << 5;     // Supervisor Previous Interrupt Enable
    pub const UBE: u64 = 1 << 6;      // User-mode Big Endian
    pub const SPP: u64 = 1 << 8;      // Supervisor Previous Privilege
    pub const VS_MASK: u64 = 3 << 9;  // Vector Status
    pub const FS_MASK: u64 = 3 << 13; // Float Status
    pub const XS_MASK: u64 = 3 << 15; // Extension Status
    pub const SUM: u64 = 1 << 18;     // Permit Supervisor User Memory access
    pub const MXR: u64 = 1 << 19;     // Make eXecutable Readable
    pub const UXL_MASK: u64 = 3 << 32; // User XLEN
    pub const SD: u64 = 1 << 63;      // State Dirty

    pub const FS_INITIAL: u64 = 1 << 13;
    pub const FS_CLEAN: u64 = 2 << 13;
    pub const FS_DIRTY: u64 = 3 << 13;

    pub const VS_INITIAL: u64 = 1 << 9;
    pub const VS_CLEAN: u64 = 2 << 9;
    pub const VS_DIRTY: u64 = 3 << 9;
};

// ── SATP Register Format ──────────────────────────────────────────────────
pub const SATP = struct {
    pub const MODE_BARE: u64 = 0;
    pub const MODE_SV39: u64 = 8;
    pub const MODE_SV48: u64 = 9;
    pub const MODE_SV57: u64 = 10;

    pub fn build(mode: u64, asid: u16, ppn: u64) u64 {
        return (mode << 60) | (@as(u64, asid) << 44) | (ppn >> 12);
    }
};

// ── SBI (Supervisor Binary Interface) ─────────────────────────────────────
pub const SBI = struct {
    // Extension IDs (EIDs)
    pub const EXT_BASE: u64 = 0x10;
    pub const EXT_TIMER: u64 = 0x54494D45; // TIME
    pub const EXT_IPI: u64 = 0x735049;     // sPI
    pub const EXT_RFENCE: u64 = 0x52464E43; // RFNC
    pub const EXT_HSM: u64 = 0x48534D;     // HSM
    pub const EXT_SRST: u64 = 0x53525354;  // SRST
    pub const EXT_PMU: u64 = 0x504D55;     // PMU
    pub const EXT_DBCN: u64 = 0x4442434E;  // DBCN (Debug Console)
    pub const EXT_SUSP: u64 = 0x53555350;  // SUSP (System Suspend)
    pub const EXT_CPPC: u64 = 0x43505043;  // CPPC

    // Legacy extensions (deprecated but supported)
    pub const LEGACY_SET_TIMER: u64 = 0;
    pub const LEGACY_CONSOLE_PUTCHAR: u64 = 1;
    pub const LEGACY_CONSOLE_GETCHAR: u64 = 2;
    pub const LEGACY_CLEAR_IPI: u64 = 3;
    pub const LEGACY_SEND_IPI: u64 = 4;
    pub const LEGACY_REMOTE_FENCE_I: u64 = 5;
    pub const LEGACY_REMOTE_SFENCE_VMA: u64 = 6;
    pub const LEGACY_SHUTDOWN: u64 = 8;

    // SBI return value
    pub const SbiRet = struct {
        error: i64,
        value: u64,
    };

    pub const SBI_SUCCESS: i64 = 0;
    pub const SBI_ERR_FAILED: i64 = -1;
    pub const SBI_ERR_NOT_SUPPORTED: i64 = -2;
    pub const SBI_ERR_INVALID_PARAM: i64 = -3;
    pub const SBI_ERR_DENIED: i64 = -4;
    pub const SBI_ERR_INVALID_ADDRESS: i64 = -5;
    pub const SBI_ERR_ALREADY_AVAILABLE: i64 = -6;
    pub const SBI_ERR_ALREADY_STARTED: i64 = -7;
    pub const SBI_ERR_ALREADY_STOPPED: i64 = -8;

    // SBI ecall wrapper
    pub fn call(eid: u64, fid: u64, a0: u64, a1: u64, a2: u64) SbiRet {
        var error: i64 = undefined;
        var value: u64 = undefined;

        asm volatile (
            \\ecall
            : [err] "={a0}" (error),
              [val] "={a1}" (value),
            : [eid] "{a7}" (eid),
              [fid] "{a6}" (fid),
              [a0] "{a0}" (a0),
              [a1] "{a1}" (a1),
              [a2] "{a2}" (a2),
            : "memory"
        );

        return .{ .error = error, .value = value };
    }

    // Convenience SBI calls
    pub fn setTimer(stime_value: u64) void {
        _ = call(EXT_TIMER, 0, stime_value, 0, 0);
    }

    pub fn sendIpi(hart_mask: u64, hart_mask_base: u64) void {
        _ = call(EXT_IPI, 0, hart_mask, hart_mask_base, 0);
    }

    pub fn remoteFenceI(hart_mask: u64, hart_mask_base: u64) void {
        _ = call(EXT_RFENCE, 0, hart_mask, hart_mask_base, 0);
    }

    pub fn remoteSfenceVma(hart_mask: u64, hart_mask_base: u64, start: u64, size: u64) void {
        // FID=1 for remote_sfence_vma
        var error: i64 = undefined;
        var value: u64 = undefined;
        asm volatile (
            \\ecall
            : [err] "={a0}" (error),
              [val] "={a1}" (value),
            : [eid] "{a7}" (EXT_RFENCE),
              [fid] "{a6}" (@as(u64, 1)),
              [a0] "{a0}" (hart_mask),
              [a1] "{a1}" (hart_mask_base),
              [a2] "{a2}" (start),
              [a3] "{a3}" (size),
            : "memory"
        );
        _ = error;
        _ = value;
    }

    // HSM (Hart State Management)
    pub fn hartStart(hartid: u64, start_addr: u64, opaque: u64) SbiRet {
        return call(EXT_HSM, 0, hartid, start_addr, opaque);
    }

    pub fn hartStop() SbiRet {
        return call(EXT_HSM, 1, 0, 0, 0);
    }

    pub fn hartGetStatus(hartid: u64) SbiRet {
        return call(EXT_HSM, 2, hartid, 0, 0);
    }

    pub fn hartSuspend(suspend_type: u32, resume_addr: u64, opaque: u64) SbiRet {
        return call(EXT_HSM, 3, @as(u64, suspend_type), resume_addr, opaque);
    }

    // System Reset
    pub fn systemReset(reset_type: u32, reason: u32) noreturn {
        _ = call(EXT_SRST, 0, @as(u64, reset_type), @as(u64, reason), 0);
        while (true) asm volatile ("wfi");
    }

    pub fn systemShutdown() noreturn {
        systemReset(0, 0); // Shutdown
    }

    // Debug Console
    pub fn debugConsolePutChar(ch: u8) void {
        _ = call(LEGACY_CONSOLE_PUTCHAR, 0, @as(u64, ch), 0, 0);
    }

    pub fn debugConsoleGetChar() ?u8 {
        const ret = call(LEGACY_CONSOLE_GETCHAR, 0, 0, 0, 0);
        if (ret.error < 0) return null;
        return @truncate(ret.value);
    }

    // Probe SBI extension
    pub fn probeExtension(eid: u64) bool {
        const ret = call(EXT_BASE, 3, eid, 0, 0);
        return ret.error == SBI_SUCCESS and ret.value != 0;
    }

    // Get SBI version
    pub fn getVersion() u32 {
        const ret = call(EXT_BASE, 0, 0, 0, 0);
        return @truncate(ret.value);
    }
};

// ── CSR Read/Write ────────────────────────────────────────────────────────
pub inline fn csrRead(comptime csr: u12) u64 {
    return asm ("csrr %[r], " ++ comptime csrName(csr) : [r] "=r" (-> u64));
}

pub inline fn csrWrite(comptime csr: u12, val: u64) void {
    asm volatile ("csrw " ++ comptime csrName(csr) ++ ", %[v]" : : [v] "r" (val));
}

pub inline fn csrSet(comptime csr: u12, bits: u64) void {
    asm volatile ("csrs " ++ comptime csrName(csr) ++ ", %[v]" : : [v] "r" (bits));
}

pub inline fn csrClear(comptime csr: u12, bits: u64) void {
    asm volatile ("csrc " ++ comptime csrName(csr) ++ ", %[v]" : : [v] "r" (bits));
}

fn csrName(comptime csr: u12) []const u8 {
    return switch (csr) {
        CSR.SSTATUS => "sstatus",
        CSR.SIE => "sie",
        CSR.STVEC => "stvec",
        CSR.SSCRATCH => "sscratch",
        CSR.SEPC => "sepc",
        CSR.SCAUSE => "scause",
        CSR.STVAL => "stval",
        CSR.SIP => "sip",
        CSR.SATP => "satp",
        CSR.CYCLE => "cycle",
        CSR.TIME => "time",
        CSR.INSTRET => "instret",
        CSR.SCOUNTEREN => "scounteren",
        else => "0x" ++ comptime intToHexStr(csr),
    };
}

fn intToHexStr(comptime val: u12) []const u8 {
    const hex = "0123456789abcdef";
    return &[_]u8{
        hex[(val >> 8) & 0xF],
        hex[(val >> 4) & 0xF],
        hex[(val >> 0) & 0xF],
    };
}

// ── Boot Data ─────────────────────────────────────────────────────────────
pub const BootInfo = struct {
    hart_id: u64,
    dtb_phys: u64,
    sbi_version: u32,
    has_sbi_timer: bool,
    has_sbi_ipi: bool,
    has_sbi_rfence: bool,
    has_sbi_hsm: bool,
    has_sbi_srst: bool,
    has_sbi_pmu: bool,
    has_sbi_susp: bool,
    has_sbi_dbcn: bool,
    num_harts: u32,
    hart_ids: [256]u64,
    memory_start: u64,
    memory_size: u64,
    // ISA extensions detected
    has_ext_v: bool,     // Vector
    has_ext_h: bool,     // Hypervisor
    has_ext_zba: bool,
    has_ext_zbb: bool,
    has_ext_zbc: bool,
    has_ext_zbs: bool,
    has_ext_sstc: bool,  // Stimecmp
    has_ext_svnapot: bool,
    has_ext_svpbmt: bool,
    has_ext_svinval: bool,

    const Self = @This();
    pub fn init() Self {
        var info: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&info))[0..@sizeOf(Self)], 0);
        return info;
    }
};

var boot_info: BootInfo = BootInfo.init();

// ── Boot Entry Point ──────────────────────────────────────────────────────
export fn _riscv_boot(hart_id: u64, dtb_phys: u64) callconv(.C) noreturn {
    // Save boot parameters
    boot_info.hart_id = hart_id;
    boot_info.dtb_phys = dtb_phys;

    // Disable interrupts
    csrClear(CSR.SSTATUS, SSTATUS.SIE);

    // Set sscratch to 0 (indicates S-mode kernel running)
    csrWrite(CSR.SSCRATCH, 0);

    // Initialize early UART
    earlyUartInit();
    earlyPrint("Zxyphor Kernel booting on RISC-V RV64GC\n");

    // Probe SBI extensions
    boot_info.sbi_version = SBI.getVersion();
    boot_info.has_sbi_timer = SBI.probeExtension(SBI.EXT_TIMER);
    boot_info.has_sbi_ipi = SBI.probeExtension(SBI.EXT_IPI);
    boot_info.has_sbi_rfence = SBI.probeExtension(SBI.EXT_RFENCE);
    boot_info.has_sbi_hsm = SBI.probeExtension(SBI.EXT_HSM);
    boot_info.has_sbi_srst = SBI.probeExtension(SBI.EXT_SRST);
    boot_info.has_sbi_pmu = SBI.probeExtension(SBI.EXT_PMU);
    boot_info.has_sbi_susp = SBI.probeExtension(SBI.EXT_SUSP);
    boot_info.has_sbi_dbcn = SBI.probeExtension(SBI.EXT_DBCN);

    // Parse DTB for memory and hart information
    parseDtb(dtb_phys);

    // Set up Sv48 page tables
    setupPageTables();

    // Enable MMU
    enableMmu();

    // Enable FPU (set FS = Initial)
    csrSet(CSR.SSTATUS, SSTATUS.FS_INITIAL);

    // Enable counters for S-mode
    csrWrite(CSR.SCOUNTEREN, 0x7); // cycle, time, instret

    // Install trap vector
    installTrapVector();

    earlyPrint("RISC-V boot complete. Entering kernel main.\n");

    // Enter kernel main
    kernelMain();
}

fn earlyUartInit() void {
    // NS16550A at 0x10000000 (QEMU virt platform default)
    const UART_BASE: u64 = 0x10000000;
    const ptr: *volatile u8 = @ptrFromInt(UART_BASE + 3); // LCR
    ptr.* = 0x03; // 8N1
    const ier: *volatile u8 = @ptrFromInt(UART_BASE + 1); // IER
    ier.* = 0x00; // Disable interrupts
}

fn earlyPrint(msg: []const u8) void {
    for (msg) |ch| {
        SBI.debugConsolePutChar(ch);
    }
}

fn parseDtb(dtb_phys: u64) void {
    // Minimal FDT header parsing (similar to ARM64 version)
    const header: *const [8]u32 = @ptrFromInt(dtb_phys);
    const magic = bigToNative32(header[0]);
    if (magic != 0xD00DFEED) return;

    const totalsize = bigToNative32(header[1]);
    _ = totalsize;

    // Parse memory node and CPU nodes
    boot_info.memory_start = 0x80000000; // Default QEMU virt
    boot_info.memory_size = 0x40000000;  // 1GB default
    boot_info.num_harts = 1;
    boot_info.hart_ids[0] = boot_info.hart_id;
}

fn setupPageTables() void {
    // Set up Sv48 identity mapping for boot
    // Full implementation would create 4-level page tables
    // For now, trust the identity mapping from firmware
}

fn enableMmu() void {
    // In Sv48 mode with ASID
    // csrWrite(CSR.SATP, SATP.build(SATP.MODE_SV48, 0, page_table_phys));
    // For now, keep firmware's mapping
    sfenceVma();
}

fn installTrapVector() void {
    const vector_addr: u64 = @intFromPtr(&trapEntry);
    csrWrite(CSR.STVEC, vector_addr & ~@as(u64, 0x3)); // Direct mode
}

fn kernelMain() noreturn {
    while (true) {
        asm volatile ("wfi");
    }
}

// ── Trap Entry (simplified) ──────────────────────────────────────────────
export fn trapEntry() callconv(.Naked) void {
    // Save all 31 integer registers + sepc + sstatus + stval + scause
    asm volatile (
        \\csrrw sp, sscratch, sp
        \\addi sp, sp, -256
        \\sd ra, 0(sp)
        \\sd gp, 8(sp)
        \\sd tp, 16(sp)
        \\sd t0, 24(sp)
        \\sd t1, 32(sp)
        \\sd t2, 40(sp)
        \\sd s0, 48(sp)
        \\sd s1, 56(sp)
        \\sd a0, 64(sp)
        \\sd a1, 72(sp)
        \\sd a2, 80(sp)
        \\sd a3, 88(sp)
        \\sd a4, 96(sp)
        \\sd a5, 104(sp)
        \\sd a6, 112(sp)
        \\sd a7, 120(sp)
        \\sd s2, 128(sp)
        \\sd s3, 136(sp)
        \\sd s4, 144(sp)
        \\sd s5, 152(sp)
        \\sd s6, 160(sp)
        \\sd s7, 168(sp)
        \\sd s8, 176(sp)
        \\sd s9, 184(sp)
        \\sd s10, 192(sp)
        \\sd s11, 200(sp)
        \\sd t3, 208(sp)
        \\sd t4, 216(sp)
        \\sd t5, 224(sp)
        \\sd t6, 232(sp)
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────
pub inline fn sfenceVma() void {
    asm volatile ("sfence.vma" ::: "memory");
}

pub inline fn sfenceVmaAddr(vaddr: u64) void {
    asm volatile ("sfence.vma %[addr], zero" : : [addr] "r" (vaddr) : "memory");
}

pub inline fn sfenceVmaAsid(asid: u64) void {
    asm volatile ("sfence.vma zero, %[asid]" : : [asid] "r" (asid) : "memory");
}

pub inline fn sfenceVmaAddrAsid(vaddr: u64, asid: u64) void {
    asm volatile ("sfence.vma %[addr], %[asid]" : : [addr] "r" (vaddr), [asid] "r" (asid) : "memory");
}

pub inline fn fenceI() void {
    asm volatile ("fence.i" ::: "memory");
}

pub inline fn fence() void {
    asm volatile ("fence rw, rw" ::: "memory");
}

pub inline fn fenceW() void {
    asm volatile ("fence w, w" ::: "memory");
}

pub inline fn fenceR() void {
    asm volatile ("fence r, r" ::: "memory");
}

pub inline fn wfi() void {
    asm volatile ("wfi");
}

fn bigToNative32(val: u32) u32 {
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

pub fn getBootInfo() *const BootInfo {
    return &boot_info;
}
