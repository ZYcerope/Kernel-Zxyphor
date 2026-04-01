// =============================================================================
// Zxyphor Kernel — RISC-V 64-bit PLIC (Platform-Level Interrupt Controller)
// =============================================================================
// Full PLIC implementation conforming to the RISC-V PLIC specification v1.0.
// The PLIC aggregates and distributes global interrupts to hart contexts
// (each hart typically has 2 contexts: M-mode and S-mode).
//
// PLIC Memory Map (per specification):
//   0x000000 - 0x000FFF: Interrupt source priorities (source 1..1023)
//   0x001000 - 0x00107F: Interrupt pending bits (32 words for 1024 sources)
//   0x002000 - 0x1FFFFF: Enable bits per context (32 words × N contexts)
//   0x200000 - 0x3FFFFF: Priority threshold and claim/complete per context
//
// Each context has:
//   - Threshold register: suppress interrupts below this priority
//   - Claim register: read returns highest-priority pending interrupt
//   - Complete register: write acknowledges completion of interrupt
//
// Zxyphor supports the newer AIA (Advanced Interrupt Architecture) APLIC
// as well, but PLIC is needed for compatibility with existing SoCs.
// =============================================================================

// ── PLIC Constants ────────────────────────────────────────────────────────
pub const MAX_SOURCES: u32 = 1024;         // Maximum interrupt sources
pub const MAX_CONTEXTS: u32 = 15872;       // Maximum contexts
pub const MAX_PRIORITY: u32 = 7;           // Maximum priority level

// PLIC register offsets
pub const REG = struct {
    pub const PRIORITY_BASE: u64 = 0x000000;       // Priority for source N at offset N*4
    pub const PENDING_BASE: u64 = 0x001000;         // Pending bits (32 sources per word)
    pub const ENABLE_BASE: u64 = 0x002000;           // Enable bits per context
    pub const ENABLE_STRIDE: u64 = 0x80;             // Bytes per context enable block
    pub const THRESHOLD_BASE: u64 = 0x200000;        // Threshold per context
    pub const CLAIM_BASE: u64 = 0x200004;            // Claim/complete per context
    pub const CONTEXT_STRIDE: u64 = 0x1000;          // Bytes per context block
};

// ── IRQ Descriptor ────────────────────────────────────────────────────────
pub const IrqHandler = *const fn (u32, ?*anyopaque) void;

pub const IrqDescriptor = struct {
    handler: ?IrqHandler,
    data: ?*anyopaque,
    priority: u32,
    enabled: bool,
    count: u64,
    name: [32]u8,
    name_len: u8,

    const Self = @This();

    pub fn init() Self {
        var desc: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&desc))[0..@sizeOf(Self)], 0);
        desc.priority = 1; // Default priority
        return desc;
    }
};

// ── PLIC State ────────────────────────────────────────────────────────────
pub const PlicState = struct {
    base: u64,
    num_sources: u32,
    num_contexts: u32,
    irqs: [MAX_SOURCES]IrqDescriptor,
    initialized: bool,

    const Self = @This();

    pub fn create() Self {
        var state: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&state))[0..@sizeOf(Self)], 0);
        var i: u32 = 0;
        while (i < MAX_SOURCES) : (i += 1) {
            state.irqs[i] = IrqDescriptor.init();
        }
        return state;
    }
};

var plic: PlicState = PlicState.create();

// ── MMIO Access ───────────────────────────────────────────────────────────
inline fn plicRead32(offset: u64) u32 {
    const ptr: *volatile u32 = @ptrFromInt(plic.base + offset);
    return ptr.*;
}

inline fn plicWrite32(offset: u64, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(plic.base + offset);
    ptr.* = val;
}

// ── Context Calculation ──────────────────────────────────────────────────
// Each hart has 2 contexts: context 2*hartid = M-mode, context 2*hartid+1 = S-mode
// In S-mode kernel, we always use the S-mode context
fn hartToContext(hart_id: u32) u32 {
    return hart_id * 2 + 1; // S-mode context
}

// ── PLIC Initialization ──────────────────────────────────────────────────
pub fn init(base_addr: u64, num_sources: u32) void {
    plic.base = base_addr;
    plic.num_sources = @min(num_sources, MAX_SOURCES);
    plic.num_contexts = 8; // Default for QEMU virt (4 harts × 2)

    // Set all interrupt priorities to 0 (disabled)
    var i: u32 = 1; // Source 0 is reserved
    while (i < plic.num_sources) : (i += 1) {
        plicWrite32(REG.PRIORITY_BASE + @as(u64, i) * 4, 0);
    }

    // Disable all interrupts for all contexts
    var ctx: u32 = 0;
    while (ctx < plic.num_contexts) : (ctx += 1) {
        // Set threshold to maximum (block all)
        plicWrite32(REG.THRESHOLD_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE, MAX_PRIORITY);

        // Disable all sources
        var word: u32 = 0;
        while (word < (plic.num_sources + 31) / 32) : (word += 1) {
            plicWrite32(REG.ENABLE_BASE + @as(u64, ctx) * REG.ENABLE_STRIDE + @as(u64, word) * 4, 0);
        }
    }

    plic.initialized = true;
}

pub fn initHart(hart_id: u32) void {
    const ctx = hartToContext(hart_id);

    // Set threshold to 0 (allow all priorities > 0)
    plicWrite32(REG.THRESHOLD_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE, 0);

    // Claim and complete any pending interrupts
    while (true) {
        const claim = plicRead32(REG.CLAIM_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE);
        if (claim == 0) break;
        plicWrite32(REG.CLAIM_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE, claim);
    }
}

// ── IRQ Management ────────────────────────────────────────────────────────
pub fn enableIrq(irq: u32, hart_id: u32) void {
    if (irq == 0 or irq >= plic.num_sources) return;

    const ctx = hartToContext(hart_id);
    const word = irq / 32;
    const bit: u5 = @truncate(irq % 32);

    // Enable in enable register
    const enable_offset = REG.ENABLE_BASE + @as(u64, ctx) * REG.ENABLE_STRIDE + @as(u64, word) * 4;
    var val = plicRead32(enable_offset);
    val |= @as(u32, 1) << bit;
    plicWrite32(enable_offset, val);

    // Set priority if not already set
    if (plic.irqs[irq].priority == 0) {
        plic.irqs[irq].priority = 1;
    }
    plicWrite32(REG.PRIORITY_BASE + @as(u64, irq) * 4, plic.irqs[irq].priority);

    plic.irqs[irq].enabled = true;
}

pub fn disableIrq(irq: u32, hart_id: u32) void {
    if (irq == 0 or irq >= plic.num_sources) return;

    const ctx = hartToContext(hart_id);
    const word = irq / 32;
    const bit: u5 = @truncate(irq % 32);

    const enable_offset = REG.ENABLE_BASE + @as(u64, ctx) * REG.ENABLE_STRIDE + @as(u64, word) * 4;
    var val = plicRead32(enable_offset);
    val &= ~(@as(u32, 1) << bit);
    plicWrite32(enable_offset, val);

    plic.irqs[irq].enabled = false;
}

pub fn setPriority(irq: u32, priority: u32) void {
    if (irq == 0 or irq >= plic.num_sources) return;
    const prio = @min(priority, MAX_PRIORITY);
    plic.irqs[irq].priority = prio;
    plicWrite32(REG.PRIORITY_BASE + @as(u64, irq) * 4, prio);
}

pub fn setThreshold(hart_id: u32, threshold: u32) void {
    const ctx = hartToContext(hart_id);
    plicWrite32(REG.THRESHOLD_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE, @min(threshold, MAX_PRIORITY));
}

pub fn registerHandler(irq: u32, handler: IrqHandler, data: ?*anyopaque) void {
    if (irq == 0 or irq >= plic.num_sources) return;
    plic.irqs[irq].handler = handler;
    plic.irqs[irq].data = data;
}

// ── Interrupt Handling ───────────────────────────────────────────────────
pub fn handleInterrupt(hart_id: u32) void {
    const ctx = hartToContext(hart_id);

    while (true) {
        // Claim interrupt
        const irq = plicRead32(REG.CLAIM_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE);
        if (irq == 0) break; // No more pending

        if (irq < plic.num_sources) {
            plic.irqs[irq].count += 1;

            // Dispatch to handler
            if (plic.irqs[irq].handler) |handler| {
                handler(irq, plic.irqs[irq].data);
            }
        }

        // Complete interrupt
        plicWrite32(REG.CLAIM_BASE + @as(u64, ctx) * REG.CONTEXT_STRIDE, irq);
    }
}

pub fn isPending(irq: u32) bool {
    if (irq == 0 or irq >= plic.num_sources) return false;
    const word = irq / 32;
    const bit: u5 = @truncate(irq % 32);
    const val = plicRead32(REG.PENDING_BASE + @as(u64, word) * 4);
    return (val & (@as(u32, 1) << bit)) != 0;
}

// ── Queries ──────────────────────────────────────────────────────────────
pub fn getIrqCount(irq: u32) u64 {
    if (irq >= plic.num_sources) return 0;
    return plic.irqs[irq].count;
}

pub fn getNumSources() u32 {
    return plic.num_sources;
}

pub fn isInitialized() bool {
    return plic.initialized;
}

// =============================================================================
// RISC-V CLINT (Core Local Interruptor)
// =============================================================================
// The CLINT provides per-hart timer and software interrupts.
// CLINT Memory Map:
//   0x0000 - 0x3FFF: MSIP (Machine Software Interrupt Pending) per hart
//   0x4000 - 0xBFF7: MTIMECMP per hart (64-bit)
//   0xBFF8:          MTIME (64-bit global timer)
// =============================================================================

pub const CLINT = struct {
    pub const MSIP_BASE: u64 = 0x0000;
    pub const MTIMECMP_BASE: u64 = 0x4000;
    pub const MTIME_REG: u64 = 0xBFF8;

    var base: u64 = 0;
    var freq: u64 = 10_000_000; // Default 10MHz

    pub fn init_clint(base_addr: u64, frequency: u64) void {
        base = base_addr;
        freq = frequency;
    }

    pub fn readMtime() u64 {
        const ptr: *volatile u64 = @ptrFromInt(base + MTIME_REG);
        return ptr.*;
    }

    pub fn writeMtimecmp(hart_id: u32, value: u64) void {
        const ptr: *volatile u64 = @ptrFromInt(base + MTIMECMP_BASE + @as(u64, hart_id) * 8);
        ptr.* = value;
    }

    pub fn readMtimecmp(hart_id: u32) u64 {
        const ptr: *volatile u64 = @ptrFromInt(base + MTIMECMP_BASE + @as(u64, hart_id) * 8);
        return ptr.*;
    }

    pub fn sendSoftwareInterrupt(hart_id: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(base + MSIP_BASE + @as(u64, hart_id) * 4);
        ptr.* = 1;
    }

    pub fn clearSoftwareInterrupt(hart_id: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(base + MSIP_BASE + @as(u64, hart_id) * 4);
        ptr.* = 0;
    }

    pub fn getFrequency() u64 {
        return freq;
    }

    pub fn setTimerInterrupt(hart_id: u32, delay_us: u64) void {
        const ticks = delay_us * freq / 1_000_000;
        const now = readMtime();
        writeMtimecmp(hart_id, now + ticks);
    }

    pub fn delayUs(us: u64) void {
        const target = readMtime() + us * freq / 1_000_000;
        while (readMtime() < target) {
            asm volatile ("nop");
        }
    }

    pub fn getNowNs() u64 {
        return readMtime() * 1_000_000_000 / freq;
    }

    pub fn getNowUs() u64 {
        return readMtime() * 1_000_000 / freq;
    }
};
