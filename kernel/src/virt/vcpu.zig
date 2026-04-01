// =============================================================================
// Zxyphor Kernel — KVM-Style Hypervisor (vCPU Management)
// =============================================================================
// Type-1 hypervisor implementation providing hardware-assisted virtualization
// using ARM VHE (Virtualization Host Extensions) or Intel VT-x / AMD-V.
// This module implements vCPU lifecycle management, world-switching between
// host and guest, and trap handling for virtualization-sensitive instructions.
//
// Architecture Support:
//   ARM64: EL2 with VHE (Armv8.1+), supports Stage 2 translation,
//          GICv3 virtual interrupt injection, virtual timer passthrough
//   x86_64: VMX (Intel VT-x) with EPT, or SVM (AMD-V) with NPT
//   RISC-V: H-extension with VS-mode and G-stage translation
//
// vCPU Features:
//   - Hardware-accelerated VM entry/exit
//   - Lazy FP/SIMD context switching for guests
//   - Virtual interrupt injection (posted interrupts on x86, vLPI on ARM)
//   - Nested virtualization support
//   - vCPU affinity and migration
//   - Performance monitoring pass-through
//   - Debug register virtualization
//   - TSC/Timer virtualization
//
// Memory Virtualization:
//   - Two-stage address translation (Stage 2 / EPT / G-stage)
//   - Huge page support in second stage
//   - MMIO trap and emulation
//   - DMA remapping integration (SMMU/IOMMU)
//   - Memory ballooning and page sharing (KSM)
// =============================================================================

const gic = @import("../arch/aarch64/gic_v3.zig");
const mmu = @import("../arch/aarch64/mmu.zig");
const timer_mod = @import("../arch/aarch64/timer.zig");

// ── vCPU State ────────────────────────────────────────────────────────────
pub const MAX_VCPUS: usize = 512;

pub const VcpuState = enum(u8) {
    created = 0,
    runnable = 1,
    running = 2,
    blocked = 3,       // Waiting for I/O or interrupt
    halted = 4,        // WFI/HLT executed
    init = 5,          // INIT state (x86)
    sipi = 6,          // SIPI state (x86)
    destroyed = 7,
};

pub const VcpuExitReason = enum(u16) {
    unknown = 0,
    exception = 1,
    external_interrupt = 2,
    halt = 3,          // Guest executed WFI/HLT
    io = 4,            // PIO access (x86)
    mmio = 5,          // MMIO access
    shutdown = 6,
    fail_entry = 7,
    internal_error = 8,
    hypercall = 9,     // Guest hypercall (HVC/VMCALL)
    debug = 10,
    system_event = 11, // PSCI/ACPI event from guest
    ioapic_eoi = 12,
    irq_window = 13,
    nmi_window = 14,
    timer = 15,        // Virtual timer expiry
    preemption = 16,   // Host preemption
    msr_access = 17,   // MSR trap (x86)
    sysreg_access = 18, // System register trap (ARM)
    dirty_ring_full = 19,
    wfx = 20,          // WFE (ARM)
    smc = 21,          // SMC trap (ARM)
};

// ── Guest Register State ──────────────────────────────────────────────────
pub const GuestRegs = struct {
    // General-purpose registers
    gp: [31]u64,       // x0-x30 (ARM64) or rax..r15 (x86_64)
    sp: u64,           // Stack pointer
    pc: u64,           // Program counter / ELR_EL2

    // Program state
    pstate: u64,       // SPSR_EL2 (ARM64) or RFLAGS (x86_64)

    // System registers (ARM64 guest state saved/restored on VM entry/exit)
    sctlr_el1: u64,
    cpacr_el1: u64,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    tcr_el1: u64,
    esr_el1: u64,
    far_el1: u64,
    mair_el1: u64,
    amair_el1: u64,
    vbar_el1: u64,
    contextidr_el1: u64,
    tpidr_el0: u64,
    tpidr_el1: u64,
    tpidrro_el0: u64,
    sp_el1: u64,
    elr_el1: u64,
    spsr_el1: u64,

    // Timer state
    cntv_ctl_el0: u64,
    cntv_cval_el0: u64,
    cntp_ctl_el0: u64,
    cntp_cval_el0: u64,
    cntkctl_el1: u64,

    // Debug registers
    mdscr_el1: u64,
    dbgbcr: [16]u64,   // Breakpoint control
    dbgbvr: [16]u64,   // Breakpoint value
    dbgwcr: [16]u64,   // Watchpoint control
    dbgwvr: [16]u64,   // Watchpoint value

    // FP/SIMD
    fp_regs: [32][16]u8, // Q0-Q31 (128-bit NEON registers)
    fpsr: u32,
    fpcr: u32,
    fp_saved: bool,

    const Self = @This();

    pub fn init() Self {
        var regs: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&regs))[0..@sizeOf(Self)], 0);
        // Default PSTATE: EL1h with interrupts masked
        regs.pstate = 0x3C5; // EL1h, DAIF masked
        regs.sctlr_el1 = 0x30D00800; // Default SCTLR_EL1
        return regs;
    }
};

// ── VM Exit Info ──────────────────────────────────────────────────────────
pub const VmExitInfo = struct {
    reason: VcpuExitReason,
    // MMIO exit info
    mmio_phys_addr: u64,
    mmio_data: [8]u8,
    mmio_len: u8,
    mmio_is_write: bool,
    // Hypercall info
    hypercall_nr: u64,
    hypercall_args: [6]u64,
    // System register info
    sysreg_op0: u8,
    sysreg_op1: u8,
    sysreg_crn: u8,
    sysreg_crm: u8,
    sysreg_op2: u8,
    sysreg_rt: u8,
    sysreg_is_write: bool,
    sysreg_value: u64,
    // Exception info
    esr: u64,
    far: u64,
    hpfar: u64,       // IPA of faulting access (from HPFAR_EL2)

    const Self = @This();
    pub fn init() Self {
        var info: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&info))[0..@sizeOf(Self)], 0);
        info.reason = .unknown;
        return info;
    }
};

// ── vCPU Structure ────────────────────────────────────────────────────────
pub const Vcpu = struct {
    id: u32,
    vm_id: u32,
    state: VcpuState,
    regs: GuestRegs,
    exit_info: VmExitInfo,

    // Stage 2 page table (IPA → PA translation)
    vttbr_el2: u64,    // VTTBR_EL2: VMID + Stage 2 table base
    vmid: u16,

    // Virtual GIC state
    vgic_lr: [16]u64,  // List Registers (ICH_LR<n>_EL2)
    vgic_hcr: u64,     // ICH_HCR_EL2
    vgic_vmcr: u64,    // ICH_VMCR_EL2
    vgic_misr: u64,
    vgic_apr: [4]u64,  // ICH_AP0R/AP1R

    // Host state (saved on VM entry)
    host_sp: u64,
    host_tpidr: u64,

    // Statistics
    total_exits: u64,
    mmio_exits: u64,
    hvc_exits: u64,
    wfi_exits: u64,
    sysreg_exits: u64,
    irq_exits: u64,
    timer_exits: u64,
    total_run_ns: u64,

    // Scheduling
    affinity: u64,     // Preferred physical CPU (MPIDR)
    last_pcpu: u32,    // Last physical CPU this vCPU ran on
    preempted: bool,

    const Self = @This();

    pub fn init(vcpu_id: u32, vm_id: u32) Self {
        var vcpu: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&vcpu))[0..@sizeOf(Self)], 0);
        vcpu.id = vcpu_id;
        vcpu.vm_id = vm_id;
        vcpu.state = .created;
        vcpu.regs = GuestRegs.init();
        vcpu.exit_info = VmExitInfo.init();
        return vcpu;
    }

    pub fn setEntryPoint(self: *Self, pc: u64, sp: u64, arg0: u64) void {
        self.regs.pc = pc;
        self.regs.sp = sp;
        self.regs.gp[0] = arg0; // x0 = DTB pointer (ARM64 boot protocol)
        self.state = .runnable;
    }

    pub fn run(self: *Self) VcpuExitReason {
        if (self.state != .runnable) return .fail_entry;

        self.state = .running;
        const start = timer_mod.readCounter();

        // Save host context
        self.saveHostState();

        // Restore guest context and enter guest
        self.restoreGuestState();

        // Configure Stage 2 translation
        self.activateStage2();

        // Enable virtual interrupts
        self.configureVgic();

        // World switch — enters guest until trap
        const exit_reason = self.worldSwitch();

        // Save guest context
        self.saveGuestState();

        // Restore host context
        self.restoreHostState();

        // Deactivate Stage 2
        self.deactivateStage2();

        // Record statistics
        const end = timer_mod.readCounter();
        self.total_run_ns += end - start;
        self.total_exits += 1;

        // Decode exit reason
        self.exit_info.reason = exit_reason;
        self.state = .runnable;

        switch (exit_reason) {
            .mmio => self.mmio_exits += 1,
            .hypercall => self.hvc_exits += 1,
            .halt => {
                self.wfi_exits += 1;
                self.state = .halted;
            },
            .external_interrupt => self.irq_exits += 1,
            .timer => self.timer_exits += 1,
            .sysreg_access => self.sysreg_exits += 1,
            else => {},
        }

        return exit_reason;
    }

    fn worldSwitch(self: *Self) VcpuExitReason {
        _ = self;
        // Enter guest via ERET
        // The actual world switch is in assembly:
        //   1. Load guest registers from GuestRegs
        //   2. MSR ELR_EL2, <guest_pc>
        //   3. MSR SPSR_EL2, <guest_pstate>
        //   4. ERET (drops to EL1 in guest context)
        //   5. On trap: automatically returns to EL2
        //   6. Save guest registers, return exit reason

        // Read ESR_EL2 for trap reason
        const esr = readEsrEl2();
        const ec = (esr >> 26) & 0x3F;

        return switch (ec) {
            0x16 => .hypercall,           // HVC from AArch64
            0x24, 0x25 => .mmio,          // Data Abort from lower EL
            0x20, 0x21 => .exception,     // Instruction Abort
            0x01 => .halt,                // WFI/WFE trap
            0x18 => .sysreg_access,       // MSR/MRS/Sys trap
            0x17 => .smc,                 // SMC trap
            else => .unknown,
        };
    }

    fn saveHostState(self: *Self) void {
        self.host_sp = asm ("mov %[sp], sp" : [sp] "=r" (-> u64));
        self.host_tpidr = asm ("mrs %[r], TPIDR_EL2" : [r] "=r" (-> u64));
    }

    fn restoreHostState(self: *Self) void {
        asm volatile ("mov sp, %[sp]" : : [sp] "r" (self.host_sp));
        asm volatile ("msr TPIDR_EL2, %[v]" : : [v] "r" (self.host_tpidr));
    }

    fn saveGuestState(self: *Self) void {
        // Save system registers
        self.regs.sctlr_el1 = asm ("mrs %[r], SCTLR_EL1" : [r] "=r" (-> u64));
        self.regs.ttbr0_el1 = asm ("mrs %[r], TTBR0_EL1" : [r] "=r" (-> u64));
        self.regs.ttbr1_el1 = asm ("mrs %[r], TTBR1_EL1" : [r] "=r" (-> u64));
        self.regs.tcr_el1 = asm ("mrs %[r], TCR_EL1" : [r] "=r" (-> u64));
        self.regs.mair_el1 = asm ("mrs %[r], MAIR_EL1" : [r] "=r" (-> u64));
        self.regs.vbar_el1 = asm ("mrs %[r], VBAR_EL1" : [r] "=r" (-> u64));
        self.regs.esr_el1 = asm ("mrs %[r], ESR_EL1" : [r] "=r" (-> u64));
        self.regs.far_el1 = asm ("mrs %[r], FAR_EL1" : [r] "=r" (-> u64));
        self.regs.sp_el1 = asm ("mrs %[r], SP_EL1" : [r] "=r" (-> u64));
        self.regs.elr_el1 = asm ("mrs %[r], ELR_EL1" : [r] "=r" (-> u64));
        self.regs.spsr_el1 = asm ("mrs %[r], SPSR_EL1" : [r] "=r" (-> u64));
        self.regs.contextidr_el1 = asm ("mrs %[r], CONTEXTIDR_EL1" : [r] "=r" (-> u64));
        self.regs.tpidr_el0 = asm ("mrs %[r], TPIDR_EL0" : [r] "=r" (-> u64));
        self.regs.tpidr_el1 = asm ("mrs %[r], TPIDR_EL1" : [r] "=r" (-> u64));

        // Save timer state
        self.regs.cntv_ctl_el0 = asm ("mrs %[r], CNTV_CTL_EL0" : [r] "=r" (-> u64));
        self.regs.cntv_cval_el0 = asm ("mrs %[r], CNTV_CVAL_EL0" : [r] "=r" (-> u64));

        // Save GICv3 virtual interface state
        self.saveVgicState();
    }

    fn restoreGuestState(self: *Self) void {
        asm volatile ("msr SCTLR_EL1, %[v]" : : [v] "r" (self.regs.sctlr_el1));
        asm volatile ("msr TTBR0_EL1, %[v]" : : [v] "r" (self.regs.ttbr0_el1));
        asm volatile ("msr TTBR1_EL1, %[v]" : : [v] "r" (self.regs.ttbr1_el1));
        asm volatile ("msr TCR_EL1, %[v]" : : [v] "r" (self.regs.tcr_el1));
        asm volatile ("msr MAIR_EL1, %[v]" : : [v] "r" (self.regs.mair_el1));
        asm volatile ("msr VBAR_EL1, %[v]" : : [v] "r" (self.regs.vbar_el1));
        asm volatile ("msr SP_EL1, %[v]" : : [v] "r" (self.regs.sp_el1));
        asm volatile ("msr ELR_EL1, %[v]" : : [v] "r" (self.regs.elr_el1));
        asm volatile ("msr SPSR_EL1, %[v]" : : [v] "r" (self.regs.spsr_el1));
        asm volatile ("msr CONTEXTIDR_EL1, %[v]" : : [v] "r" (self.regs.contextidr_el1));
        asm volatile ("msr TPIDR_EL0, %[v]" : : [v] "r" (self.regs.tpidr_el0));
        asm volatile ("msr TPIDR_EL1, %[v]" : : [v] "r" (self.regs.tpidr_el1));

        asm volatile ("msr CNTV_CTL_EL0, %[v]" : : [v] "r" (self.regs.cntv_ctl_el0));
        asm volatile ("msr CNTV_CVAL_EL0, %[v]" : : [v] "r" (self.regs.cntv_cval_el0));

        self.restoreVgicState();
        asm volatile ("isb");
    }

    fn activateStage2(self: *Self) void {
        asm volatile ("msr VTTBR_EL2, %[v]; isb" : : [v] "r" (self.vttbr_el2));
    }

    fn deactivateStage2(_: *Self) void {
        asm volatile ("msr VTTBR_EL2, xzr; isb");
    }

    fn configureVgic(self: *Self) void {
        asm volatile ("msr ICH_HCR_EL2, %[v]" : : [v] "r" (self.vgic_hcr));
        asm volatile ("msr ICH_VMCR_EL2, %[v]" : : [v] "r" (self.vgic_vmcr));
    }

    fn saveVgicState(self: *Self) void {
        self.vgic_hcr = asm ("mrs %[r], ICH_HCR_EL2" : [r] "=r" (-> u64));
        self.vgic_vmcr = asm ("mrs %[r], ICH_VMCR_EL2" : [r] "=r" (-> u64));
        self.vgic_misr = asm ("mrs %[r], ICH_MISR_EL2" : [r] "=r" (-> u64));
    }

    fn restoreVgicState(self: *Self) void {
        asm volatile ("msr ICH_HCR_EL2, %[v]" : : [v] "r" (self.vgic_hcr));
        asm volatile ("msr ICH_VMCR_EL2, %[v]" : : [v] "r" (self.vgic_vmcr));
    }

    // ── Virtual Interrupt Injection ──────────────────────────────────
    pub fn injectVirtualIrq(self: *Self, intid: u32, priority: u8) void {
        // Find a free List Register
        var i: usize = 0;
        while (i < self.vgic_lr.len) : (i += 1) {
            if (self.vgic_lr[i] & (1 << 63) == 0) { // State = invalid
                // Build LR value
                var lr: u64 = 0;
                lr |= @as(u64, intid) & 0xFFFFFFFF; // vINTID
                lr |= @as(u64, priority) << 48;       // Priority
                lr |= 1 << 62;                        // Group = 1
                lr |= 1 << 63;                        // HW = 0, State = pending
                self.vgic_lr[i] = lr;
                break;
            }
        }
    }

    pub fn getExitReason(self: *const Self) VcpuExitReason {
        return self.exit_info.reason;
    }
};

// ── VM Structure ──────────────────────────────────────────────────────────
pub const VM = struct {
    id: u32,
    vcpus: [MAX_VCPUS]?*Vcpu,
    num_vcpus: u32,
    vmid: u16,
    stage2_pgd_phys: u64,  // Stage 2 translation table base
    memory_size: u64,
    state: VmState,

    const Self = @This();

    pub const VmState = enum {
        created,
        running,
        paused,
        destroyed,
    };

    pub fn init(vm_id: u32) Self {
        var vm: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&vm))[0..@sizeOf(Self)], 0);
        vm.id = vm_id;
        vm.state = .created;
        return vm;
    }

    pub fn createVcpu(self: *Self, vcpu_id: u32) !*Vcpu {
        if (vcpu_id >= MAX_VCPUS) return error.InvalidVcpuId;
        if (self.vcpus[vcpu_id] != null) return error.VcpuAlreadyExists;

        var vcpu = &vcpu_pool[next_vcpu_idx];
        next_vcpu_idx += 1;
        vcpu.* = Vcpu.init(vcpu_id, self.id);
        vcpu.vmid = self.vmid;

        self.vcpus[vcpu_id] = vcpu;
        self.num_vcpus += 1;
        return vcpu;
    }
};

// ── vCPU Pool ─────────────────────────────────────────────────────────────
var vcpu_pool: [MAX_VCPUS]Vcpu = undefined;
var next_vcpu_idx: usize = 0;

// ── System Register Access ────────────────────────────────────────────────
inline fn readEsrEl2() u64 {
    return asm ("mrs %[r], ESR_EL2" : [r] "=r" (-> u64));
}

inline fn readHpfarEl2() u64 {
    return asm ("mrs %[r], HPFAR_EL2" : [r] "=r" (-> u64));
}

inline fn readFarEl2() u64 {
    return asm ("mrs %[r], FAR_EL2" : [r] "=r" (-> u64));
}
