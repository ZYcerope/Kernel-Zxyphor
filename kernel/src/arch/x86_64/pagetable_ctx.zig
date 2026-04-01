// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - x86_64 Page Table, TLB, Context Switch
// 4-level and 5-level paging, PTE/PDE/PDPE/PML4E/PML5E,
// PCID, INVPCID, TLB invalidation, lazy TLB, CR3, CR4, context switch
// More advanced than Linux 2026 x86 memory management

const std = @import("std");

// ============================================================================
// Page Table Entry Flags (x86-64)
// ============================================================================

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_PWT: u64 = 1 << 3;       // Page Write-Through
pub const PTE_PCD: u64 = 1 << 4;       // Page Cache Disable
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_PAT: u64 = 1 << 7;       // Page Attribute Table (for 4K pages)
pub const PTE_HUGE: u64 = 1 << 7;      // PS bit for PDE/PDPE (2MB/1GB pages)
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NX: u64 = 1 << 63;       // No Execute

// Software-defined bits (available bits 9-11, 52-62)
pub const PTE_SOFT_DIRTY: u64 = 1 << 9;
pub const PTE_SPECIAL: u64 = 1 << 10;
pub const PTE_DEVMAP: u64 = 1 << 11;

// Protection Key (bits 59-62 for user pages)
pub const PTE_PKEY_MASK: u64 = 0x7800000000000000;
pub const PTE_PKEY_SHIFT: u6 = 59;

// Physical address mask (bits 12-51 for 4-level, 12-56 for 5-level)
pub const PTE_ADDR_MASK_4LEVEL: u64 = 0x000FFFFFFFFFF000;
pub const PTE_ADDR_MASK_5LEVEL: u64 = 0x01FFFFFFFFFFF000;

pub const PageTableEntry = packed struct(u64) {
    present: bool,
    writable: bool,
    user: bool,
    write_through: bool,
    cache_disable: bool,
    accessed: bool,
    dirty: bool,
    pat_or_huge: bool,
    global: bool,
    // Software bits 9-11
    soft_dirty: bool,
    special: bool,
    devmap: bool,
    // Physical address bits 12-51
    pfn: u40,
    // Available bits 52-58
    _available: u7,
    // Protection key bits 59-62
    pkey: u4,
    // NX bit 63
    nx: bool,

    pub fn address(self: PageTableEntry) u64 {
        return @as(u64, self.pfn) << 12;
    }

    pub fn set_address(self: *PageTableEntry, addr: u64) void {
        self.pfn = @truncate(addr >> 12);
    }

    pub fn is_present(self: PageTableEntry) bool {
        return self.present;
    }

    pub fn is_writable(self: PageTableEntry) bool {
        return self.writable;
    }

    pub fn is_executable(self: PageTableEntry) bool {
        return !self.nx;
    }

    pub fn is_user(self: PageTableEntry) bool {
        return self.user;
    }

    pub fn is_huge(self: PageTableEntry) bool {
        return self.pat_or_huge;
    }

    pub fn is_global(self: PageTableEntry) bool {
        return self.global;
    }
};

// ============================================================================
// Page Table Levels
// ============================================================================

pub const PageTableLevel = enum(u3) {
    pml5 = 5,     // 5-level: 256 PB virtual address range
    pml4 = 4,     // 4-level: 256 TB
    pdpt = 3,     // Page Directory Pointer Table (1 GB pages)
    pd = 2,       // Page Directory (2 MB pages)
    pt = 1,       // Page Table (4 KB pages)
};

pub const ENTRIES_PER_TABLE: u32 = 512;
pub const PAGE_TABLE_SIZE: u32 = 4096;

// Virtual address breakdown (4-level paging, 48-bit virtual)
pub const VA_PML4_SHIFT: u6 = 39;
pub const VA_PDPT_SHIFT: u6 = 30;
pub const VA_PD_SHIFT: u6 = 21;
pub const VA_PT_SHIFT: u6 = 12;
pub const VA_INDEX_MASK: u64 = 0x1FF;  // 9 bits

// Virtual address breakdown (5-level paging, 57-bit virtual)
pub const VA_PML5_SHIFT: u6 = 48;

pub fn pml5_index(va: u64) u9 {
    return @truncate((va >> VA_PML5_SHIFT) & VA_INDEX_MASK);
}

pub fn pml4_index(va: u64) u9 {
    return @truncate((va >> VA_PML4_SHIFT) & VA_INDEX_MASK);
}

pub fn pdpt_index(va: u64) u9 {
    return @truncate((va >> VA_PDPT_SHIFT) & VA_INDEX_MASK);
}

pub fn pd_index(va: u64) u9 {
    return @truncate((va >> VA_PD_SHIFT) & VA_INDEX_MASK);
}

pub fn pt_index(va: u64) u9 {
    return @truncate((va >> VA_PT_SHIFT) & VA_INDEX_MASK);
}

// ============================================================================
// CR3 (Page Map Level 4/5 Base)
// ============================================================================

pub const CR3_PCD: u64 = 1 << 4;
pub const CR3_PWT: u64 = 1 << 3;
pub const CR3_PCID_MASK: u64 = 0xFFF;            // PCID in bits 0-11
pub const CR3_ADDR_MASK: u64 = 0x000FFFFFFFFFF000;
pub const CR3_NOFLUSH: u64 = 1 << 63;             // Don't flush TLB on CR3 write

pub const Cr3Value = struct {
    raw: u64,

    pub fn from_raw(raw: u64) Cr3Value {
        return .{ .raw = raw };
    }

    pub fn address(self: Cr3Value) u64 {
        return self.raw & CR3_ADDR_MASK;
    }

    pub fn pcid(self: Cr3Value) u12 {
        return @truncate(self.raw & CR3_PCID_MASK);
    }

    pub fn with_pcid(addr: u64, pcid_val: u12) Cr3Value {
        return .{ .raw = (addr & CR3_ADDR_MASK) | @as(u64, pcid_val) };
    }

    pub fn with_noflush(self: Cr3Value) Cr3Value {
        return .{ .raw = self.raw | CR3_NOFLUSH };
    }
};

// ============================================================================
// CR4 bits (relevant to paging)
// ============================================================================

pub const CR4_PSE: u64 = 1 << 4;          // Page Size Extension
pub const CR4_PAE: u64 = 1 << 5;          // Physical Address Extension
pub const CR4_PGE: u64 = 1 << 7;          // Page Global Enable
pub const CR4_PCE: u64 = 1 << 8;          // Performance Counter Enable
pub const CR4_OSFXSR: u64 = 1 << 9;       // OS FXSAVE/FXRSTOR
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;  // OS unmasked SIMD FP exceptions
pub const CR4_UMIP: u64 = 1 << 11;        // User Mode Instruction Prevention
pub const CR4_LA57: u64 = 1 << 12;        // 5-level paging
pub const CR4_VMXE: u64 = 1 << 13;        // VMX Enable
pub const CR4_SMXE: u64 = 1 << 14;        // SMX Enable
pub const CR4_FSGSBASE: u64 = 1 << 16;    // FSGSBASE instructions
pub const CR4_PCIDE: u64 = 1 << 17;       // PCID Enable
pub const CR4_OSXSAVE: u64 = 1 << 18;     // XSAVE/XRSTOR
pub const CR4_KL: u64 = 1 << 19;          // Key Locker
pub const CR4_SMEP: u64 = 1 << 20;        // Supervisor Mode Execution Prevention
pub const CR4_SMAP: u64 = 1 << 21;        // Supervisor Mode Access Prevention
pub const CR4_PKE: u64 = 1 << 22;         // Protection Keys (user)
pub const CR4_CET: u64 = 1 << 23;         // Control-flow Enforcement
pub const CR4_PKS: u64 = 1 << 24;         // Protection Keys (supervisor)

// ============================================================================
// PCID (Process Context Identifier)
// ============================================================================

pub const MAX_PCID: u16 = 4096;  // 12-bit

pub const PcidAllocator = struct {
    next_pcid: u16,
    max_pcid: u16,
    // Bitmap of used PCIDs
    used_bitmap: [64]u64,     // 4096 bits
    // Stats
    total_allocated: u64,
    total_freed: u64,
    total_flushes: u64,

    pub fn is_used(self: *const PcidAllocator, pcid: u12) bool {
        const idx = @as(u16, pcid) / 64;
        const bit = @as(u6, @truncate(@as(u16, pcid) % 64));
        return (self.used_bitmap[idx] & (@as(u64, 1) << bit)) != 0;
    }
};

// ============================================================================
// INVPCID (Invalidate PCID)
// ============================================================================

pub const InvpcidType = enum(u64) {
    individual_address = 0,     // Invalidate single address for PCID
    single_context = 1,         // Invalidate all for specific PCID
    all_including_global = 2,   // Invalidate all + global
    all_non_global = 3,         // Invalidate all except global
};

pub const InvpcidDesc = packed struct {
    pcid: u64,
    linear_address: u64,
};

// ============================================================================
// TLB Management
// ============================================================================

pub const TlbFlushMode = enum(u8) {
    local = 0,              // Local CPU only
    local_range = 1,        // Local CPU, address range
    remote = 2,             // All CPUs (IPI)
    remote_range = 3,       // All CPUs, address range
    lazy = 4,               // Lazy flush
};

pub const TlbFlushRequest = struct {
    mode: TlbFlushMode,
    // Address range
    start: u64,
    end: u64,
    nr_pages: u64,
    // Stride (for non-contiguous)
    stride: u64,
    // PCID
    pcid: u12,
    flush_pcid: bool,
    // CPU mask for remote flushes
    cpu_mask: [4]u64,       // Up to 256 CPUs
    // Flags
    flush_global: bool,
    flush_all: bool,
    freed_tables: bool,
};

pub const TlbState = struct {
    // CPU state
    loaded_mm_asid: u16,       // Currently loaded MM's ASID
    next_asid: u16,
    // PCID state
    ctxs: [MAX_PCID]TlbContext,
    // Lazy TLB
    is_lazy: bool,
    // Stats
    flush_total: u64,
    flush_all: u64,
    flush_range: u64,
    flush_range_pages: u64,
    flush_ipi_received: u64,
    flush_shootdown: u64,
};

pub const TlbContext = struct {
    ctx_id: u64,           // Unique context ID for this PCID slot
    tlb_gen: u64,          // Generation counter
};

// ============================================================================
// Context Switch
// ============================================================================

pub const CpuContext = struct {
    // General purpose registers
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    // Instruction pointer
    rip: u64,
    // Flags
    rflags: u64,
    // Segment selectors
    cs: u16,
    ds: u16,
    es: u16,
    fs: u16,
    gs: u16,
    ss: u16,
    // Segment bases
    fs_base: u64,
    gs_base: u64,
    kernel_gs_base: u64,
    // CR3
    cr3: u64,
    // Debug registers
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    // FPU/SSE/AVX state offset (saved separately)
    fpu_state_offset: u32,
    fpu_state_size: u32,
    // Thread-local storage
    tls_array: [3]u64,     // GDT TLS entries
    // I/O permission bitmap
    io_bitmap_offset: u32,
    io_bitmap_size: u32,
};

pub const FpuStateType = enum(u8) {
    legacy_fxsave = 0,     // 512 bytes (SSE)
    xsave = 1,             // Variable (AVX, AVX-512, AMX, etc.)
    xsaveopt = 2,
    xsavec = 3,            // Compacted
    xsaves = 4,            // Supervisor state
};

pub const FpuState = struct {
    state_type: FpuStateType,
    size: u32,
    // XSAVE state components present
    xsave_bv: u64,
    xcomp_bv: u64,
    // Offsets of known components
    fpu_offset: u32,       // Legacy x87 + SSE: 0
    avx_offset: u32,       // YMM: 576
    avx512_opmask_offset: u32,    // k0-k7: typically 832
    avx512_zmm_hi256_offset: u32, // ZMM0-15 upper: typically 896
    avx512_hi16_zmm_offset: u32,  // ZMM16-31: typically 1408
    mpx_bndregs_offset: u32,      // BND0-3 bounds
    mpx_bndcsr_offset: u32,       // BNDCFGU + BNDSTATUS
    pkru_offset: u32,             // Protection Keys
    amx_offset: u32,              // AMX (TILECFG + TILEDATA)
    // CET
    cet_user_offset: u32,
    cet_supervisor_offset: u32,
    // HDC
    hdc_offset: u32,
    // LBR
    lbr_offset: u32,
    // Total size
    total_size: u32,
};

// XSAVE area component indices
pub const XSTATE_FP: u64 = 1 << 0;
pub const XSTATE_SSE: u64 = 1 << 1;
pub const XSTATE_AVX: u64 = 1 << 2;
pub const XSTATE_MPX_BNDREGS: u64 = 1 << 3;
pub const XSTATE_MPX_BNDCSR: u64 = 1 << 4;
pub const XSTATE_AVX512_OPMASK: u64 = 1 << 5;
pub const XSTATE_AVX512_ZMM_HI256: u64 = 1 << 6;
pub const XSTATE_AVX512_HI16_ZMM: u64 = 1 << 7;
pub const XSTATE_PT: u64 = 1 << 8;
pub const XSTATE_PKRU: u64 = 1 << 9;
pub const XSTATE_PASID: u64 = 1 << 10;
pub const XSTATE_CET_USER: u64 = 1 << 11;
pub const XSTATE_CET_KERNEL: u64 = 1 << 12;
pub const XSTATE_HDC: u64 = 1 << 13;
pub const XSTATE_UINTR: u64 = 1 << 14;
pub const XSTATE_LBR: u64 = 1 << 15;
pub const XSTATE_HWP: u64 = 1 << 16;
pub const XSTATE_AMX_TILECFG: u64 = 1 << 17;
pub const XSTATE_AMX_TILEDATA: u64 = 1 << 18;
pub const XSTATE_APX: u64 = 1 << 19;      // APX extended GPRs

// ============================================================================
// KPTI (Kernel Page Table Isolation) / Meltdown mitigation
// ============================================================================

pub const KptiConfig = struct {
    enabled: bool,
    // Shadow page tables (user-mode mapping)
    shadow_pgd_offset: u64,
    // PCID split: user PCID vs kernel PCID
    user_pcid_flush_mask: u64,
    // Trampolines
    entry_trampoline_addr: u64,
    return_trampoline_addr: u64,
    // Stats
    entry_count: u64,
    exit_count: u64,
    cr3_switch_count: u64,
};

// ============================================================================
// PAT (Page Attribute Table)
// ============================================================================

pub const PatType = enum(u3) {
    uncacheable = 0,       // UC
    write_combining = 1,   // WC
    write_through = 4,     // WT
    write_protected = 5,   // WP
    write_back = 6,        // WB
    uncacheable_minus = 7, // UC-
};

pub const PatEntry = struct {
    idx: u3,
    pa_type: PatType,
    // PTE encoding
    pte_pwt: bool,
    pte_pcd: bool,
    pte_pat: bool,
};

// Default PAT configuration
pub const DEFAULT_PAT: [8]PatType = .{
    .write_back,          // PAT0: WB
    .write_through,       // PAT1: WT
    .uncacheable_minus,   // PAT2: UC-
    .uncacheable,         // PAT3: UC
    .write_back,          // PAT4: WB
    .write_through,       // PAT5: WT
    .uncacheable_minus,   // PAT6: UC-
    .uncacheable,         // PAT7: UC
};

// Zxyphor optimized PAT
pub const ZXYPHOR_PAT: [8]PatType = .{
    .write_back,          // PAT0: WB (default)
    .write_combining,     // PAT1: WC (for framebuffers)
    .uncacheable_minus,   // PAT2: UC- (for MMIO)
    .uncacheable,         // PAT3: UC (for strong UC)
    .write_back,          // PAT4: WB
    .write_protected,     // PAT5: WP (for CoW)
    .write_through,       // PAT6: WT (for shared data)
    .write_combining,     // PAT7: WC (more WC slots)
};

// ============================================================================
// PKU (Protection Keys for Userspace)
// ============================================================================

pub const MAX_PKEYS: u32 = 16;   // 4-bit protection key, 16 keys

pub const PkruValue = packed struct(u32) {
    // Two bits per key: AD (Access Disabled) and WD (Write Disabled)
    key0_ad: bool = false,
    key0_wd: bool = false,
    key1_ad: bool = false,
    key1_wd: bool = false,
    key2_ad: bool = false,
    key2_wd: bool = false,
    key3_ad: bool = false,
    key3_wd: bool = false,
    key4_ad: bool = false,
    key4_wd: bool = false,
    key5_ad: bool = false,
    key5_wd: bool = false,
    key6_ad: bool = false,
    key6_wd: bool = false,
    key7_ad: bool = false,
    key7_wd: bool = false,
    key8_ad: bool = false,
    key8_wd: bool = false,
    key9_ad: bool = false,
    key9_wd: bool = false,
    key10_ad: bool = false,
    key10_wd: bool = false,
    key11_ad: bool = false,
    key11_wd: bool = false,
    key12_ad: bool = false,
    key12_wd: bool = false,
    key13_ad: bool = false,
    key13_wd: bool = false,
    key14_ad: bool = false,
    key14_wd: bool = false,
    key15_ad: bool = false,
    key15_wd: bool = false,
};

pub const PkeyState = struct {
    initial_pkru: PkruValue,
    // Per-key allocation
    allocated: [MAX_PKEYS]bool,
    nr_allocated: u8,
    // Execute-only support
    execute_only_pkey: i8,      // -1 if not available
};

// ============================================================================
// PKS (Protection Keys for Supervisor)
// ============================================================================

pub const PKS_NUM_KEYS: u32 = 16;

pub const PksState = struct {
    available: bool,
    initial_pkrs: u32,
    allocated: [PKS_NUM_KEYS]bool,
    nr_allocated: u8,
};

// ============================================================================
// CET (Control-flow Enforcement Technology)
// ============================================================================

pub const CetFeatures = packed struct(u32) {
    // Shadow Stack
    shstk_en: bool = false,
    wr_shstk_en: bool = false,
    // Indirect Branch Tracking
    ibt_en: bool = false,
    // Flags
    leg_iw_en: bool = false,
    no_track_en: bool = false,
    suppress: bool = false,
    _reserved: u26 = 0,
};

pub const CetState = struct {
    // User-mode
    user_shstk: bool,
    user_ibt: bool,
    user_shstk_size: u64,
    user_shstk_base: u64,
    // Kernel
    kernel_shstk: bool,
    kernel_ibt: bool,
    // SSP (Shadow Stack Pointer)
    user_ssp: u64,
    kernel_ssp: u64,
    // Stats
    shstk_violations: u64,
    ibt_violations: u64,
};

// ============================================================================
// LAM (Linear Address Masking)
// ============================================================================

pub const LamMode = enum(u8) {
    disabled = 0,
    lam_u48 = 1,         // 48-bit LAM (bits 62:48 available)
    lam_u57 = 2,         // 57-bit LAM (bits 62:57 available)
};

pub const LamState = struct {
    user_mode: LamMode,
    supervisor_mode: LamMode,
    // Masks
    user_mask: u64,
    supervisor_mask: u64,
};

// ============================================================================
// Context Switch Subsystem
// ============================================================================

pub const ContextSwitchStats = struct {
    total_switches: u64,
    voluntary_switches: u64,
    involuntary_switches: u64,
    // TLB stats
    tlb_flush_total: u64,
    tlb_flush_all: u64,
    tlb_flush_range: u64,
    tlb_flush_ipi: u64,
    // PCID stats
    pcid_allocations: u64,
    pcid_frees: u64,
    pcid_reuse: u64,
    pcid_flush_nopcid: u64,
    // FPU state
    fpu_context_switches: u64,
    fpu_lazy_restore: u64,
    fpu_eager_restore: u64,
    // CR3
    cr3_writes: u64,
    cr3_noflush: u64,
    // KPTI
    kpti_entry: u64,
    kpti_exit: u64,
    // CET
    shstk_switches: u64,
    // Timing
    avg_switch_ns: u64,
    max_switch_ns: u64,
    min_switch_ns: u64,
};

pub const PageTableSubsystem = struct {
    // Paging mode
    five_level_paging: bool,
    // PCID
    pcid_enabled: bool,
    pcid_allocator: PcidAllocator,
    // INVPCID
    invpcid_available: bool,
    // KPTI
    kpti: KptiConfig,
    // PAT
    pat_config: [8]PatType,
    // PKU
    pku_available: bool,
    pku_state: PkeyState,
    // PKS
    pks_available: bool,
    pks_state: PksState,
    // CET
    cet_available: bool,
    cet_state: CetState,
    // LAM
    lam_available: bool,
    lam_state: LamState,
    // FPU
    fpu_state_type: FpuStateType,
    xsave_size: u32,
    xsave_features: u64,
    // Per-CPU TLB state (index = CPU ID)
    nr_cpus: u32,
    // Stats
    stats: ContextSwitchStats,
    // Zxyphor
    zxy_fast_switch: bool,
    initialized: bool,
};
