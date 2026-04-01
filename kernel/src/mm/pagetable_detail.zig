// Zxyphor Kernel - Page Table Manipulation Detail,
// x86_64 4-Level + 5-Level Paging, PTE/PDE/PDPTE/PML4E/PML5E,
// TLB Flush Operations, PCID, INVLPG, INVPCID,
// Page Walk, Hardware Page Table Walking,
// EPT (Extended Page Tables for VMX),
// Process Address Space Operations,
// Kernel Page Table Isolation (KPTI)
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Page Table Entry Flags (x86_64)
// ============================================================================

pub const PTE_FLAGS = struct {
    pub const PRESENT: u64 = 1 << 0;           // P
    pub const WRITABLE: u64 = 1 << 1;          // R/W
    pub const USER: u64 = 1 << 2;              // U/S
    pub const WRITE_THROUGH: u64 = 1 << 3;     // PWT
    pub const CACHE_DISABLE: u64 = 1 << 4;     // PCD
    pub const ACCESSED: u64 = 1 << 5;          // A
    pub const DIRTY: u64 = 1 << 6;             // D
    pub const HUGE_PAGE: u64 = 1 << 7;         // PS (Page Size)
    pub const PAT: u64 = 1 << 7;               // PAT (for 4KB pages)
    pub const GLOBAL: u64 = 1 << 8;            // G
    pub const PAT_LARGE: u64 = 1 << 12;        // PAT for large pages
    // Software-defined bits (available for OS use)
    pub const SW_BIT0: u64 = 1 << 9;           // AVL bit 0
    pub const SW_BIT1: u64 = 1 << 10;          // AVL bit 1
    pub const SW_BIT2: u64 = 1 << 11;          // AVL bit 2
    // Protection keys (bits 59-62)
    pub const PKEY_BIT0: u64 = 1 << 59;
    pub const PKEY_BIT1: u64 = 1 << 60;
    pub const PKEY_BIT2: u64 = 1 << 61;
    pub const PKEY_BIT3: u64 = 1 << 62;
    pub const PKEY_MASK: u64 = 0x7800000000000000;
    // NX bit
    pub const NO_EXECUTE: u64 = 1 << 63;       // NX/XD

    // Address mask (bits 12-51 for 4-level, 12-56 for 5-level)
    pub const ADDR_MASK_4LEVEL: u64 = 0x000FFFFFFFFFF000;
    pub const ADDR_MASK_5LEVEL: u64 = 0x01FFFFFFFFFFF000;

    // Convenience combinations
    pub const KERNEL_RO: u64 = PRESENT | NO_EXECUTE;
    pub const KERNEL_RW: u64 = PRESENT | WRITABLE | NO_EXECUTE;
    pub const KERNEL_RX: u64 = PRESENT;
    pub const KERNEL_RWX: u64 = PRESENT | WRITABLE;
    pub const USER_RO: u64 = PRESENT | USER | NO_EXECUTE;
    pub const USER_RW: u64 = PRESENT | USER | WRITABLE | NO_EXECUTE;
    pub const USER_RX: u64 = PRESENT | USER;
    pub const USER_RWX: u64 = PRESENT | USER | WRITABLE;
};

// ============================================================================
// Page Table Level Types
// ============================================================================

pub const PageLevel = enum(u3) {
    pte = 0,          // 4KB page
    pde = 1,          // 2MB page (if huge)
    pdpte = 2,        // 1GB page (if huge)
    pml4e = 3,        // Page Map Level 4
    pml5e = 4,        // Page Map Level 5 (LA57)
};

pub const PageSize = enum(u64) {
    size_4k = 0x1000,
    size_2m = 0x200000,
    size_1g = 0x40000000,
};

pub const PageTableEntry = packed struct(u64) {
    present: bool,
    writable: bool,
    user: bool,
    write_through: bool,
    cache_disable: bool,
    accessed: bool,
    dirty: bool,
    pat_or_huge: bool,       // PAT for PTE, PS for PDE/PDPTE
    global: bool,
    avl_0: bool,             // Software bit 0
    avl_1: bool,             // Software bit 1
    avl_2: bool,             // Software bit 2
    // Physical frame number (bits 12-51)
    pfn: u40,
    // Software/available bits 52-58
    sw_bits_high: u7,
    // Protection key (bits 59-62)
    pkey: u4,
    // No-execute (bit 63)
    no_execute: bool,

    pub fn address(self: PageTableEntry) u64 {
        return @as(u64, self.pfn) << 12;
    }

    pub fn from_raw(raw: u64) PageTableEntry {
        return @bitCast(raw);
    }

    pub fn to_raw(self: PageTableEntry) u64 {
        return @bitCast(self);
    }

    pub fn is_present(self: PageTableEntry) bool {
        return self.present;
    }

    pub fn is_huge(self: PageTableEntry) bool {
        return self.pat_or_huge;
    }

    pub fn is_writable(self: PageTableEntry) bool {
        return self.writable;
    }

    pub fn is_executable(self: PageTableEntry) bool {
        return !self.no_execute;
    }
};

// ============================================================================
// Virtual Address Decomposition
// ============================================================================

pub const VirtAddr4Level = packed struct(u64) {
    offset: u12,
    pte_index: u9,
    pde_index: u9,
    pdpte_index: u9,
    pml4_index: u9,
    sign_extend: u16,
};

pub const VirtAddr5Level = packed struct(u64) {
    offset: u12,
    pte_index: u9,
    pde_index: u9,
    pdpte_index: u9,
    pml4_index: u9,
    pml5_index: u9,
    sign_extend: u7,
};

// ============================================================================
// TLB Flush Operations
// ============================================================================

pub const TlbFlushType = enum(u8) {
    single_page = 0,
    range = 1,
    all_non_global = 2,
    all_including_global = 3,
    pcid_single = 4,        // Single page in specific PCID
    pcid_all = 5,           // All pages in specific PCID
    pcid_all_retain = 6,    // All pages, retain globals
    ept_single = 7,         // EPT single context
    ept_all = 8,            // EPT all contexts
};

pub const InvpcidType = enum(u64) {
    individual_address = 0,
    single_context = 1,
    all_contexts_including = 2,
    all_contexts_retaining = 3,
};

pub const InvpcidDescriptor = extern struct {
    pcid: u64,
    address: u64,
};

pub const TlbFlushRequest = struct {
    flush_type: TlbFlushType,
    start_addr: u64,
    end_addr: u64,
    pcid: u16,
    asid: u16,          // for guests
    // IPI target
    target_cpu: i32,     // -1 = all CPUs
    target_mask: ?*u64,  // CPU bitmask
};

// ============================================================================
// PCID (Process Context Identifier)
// ============================================================================

pub const PCID_MAX: u16 = 4095;  // 12-bit PCID

pub const PcidAllocator = struct {
    next_pcid: u16,
    generation: u64,
    flush_on_alloc: bool,
    la57_enabled: bool,
    // Per-CPU PCID state
    per_cpu_active_pcid: [256]u16,    // up to 256 CPUs
    per_cpu_generation: [256]u64,
};

pub const PcidConfig = struct {
    enabled: bool,
    invpcid_supported: bool,
    max_asids: u16,
    // CR4.PCIDE
    cr4_pcide: bool,
    // nopcid kernel parameter
    force_disabled: bool,
};

// ============================================================================
// KPTI (Kernel Page Table Isolation / Meltdown Mitigation)
// ============================================================================

pub const KptiConfig = struct {
    enabled: bool,
    forced: bool,           // Forced by CPU vulnerability
    // Per-CPU trampoline
    trampoline_cr3: u64,    // User-space CR3 (with PCID)
    kernel_cr3: u64,        // Kernel CR3
    // Shared entry point pages
    entry_text_mapped: bool,
    entry_data_mapped: bool,
    per_cpu_mapped: bool,
    // Performance impact
    syscall_overhead_ns: u64,
    interrupt_overhead_ns: u64,
};

pub const KptiFlags = packed struct(u8) {
    active: bool = false,
    user_mode_cr3_valid: bool = false,
    paranoid: bool = false,   // Also isolate interrupts
    _reserved: u5 = 0,
};

// ============================================================================
// EPT (Extended Page Tables for Intel VMX)
// ============================================================================

pub const EptEntryFlags = struct {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const EXECUTE: u64 = 1 << 2;
    pub const MEMORY_TYPE_MASK: u64 = 0x38;     // bits 3-5
    pub const IGNORE_PAT: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const ACCESSED: u64 = 1 << 8;
    pub const DIRTY: u64 = 1 << 9;
    pub const EXECUTE_USER: u64 = 1 << 10;     // User-mode execute
    pub const VERIFY_GPA: u64 = 1 << 57;
    pub const PAGING_WRITE: u64 = 1 << 58;
    pub const SUPERVISOR_SHADOW: u64 = 1 << 61;
    pub const SUB_PAGE_WRITE: u64 = 1 << 62;
    pub const SUPPRESS_VE: u64 = 1 << 63;
};

pub const EptMemoryType = enum(u3) {
    uncacheable = 0,
    write_combining = 1,
    write_through = 4,
    write_protected = 5,
    write_back = 6,
};

pub const EptEntry = packed struct(u64) {
    read: bool,
    write: bool,
    execute: bool,
    memory_type: u3,
    ignore_pat: bool,
    huge_page: bool,
    accessed: bool,
    dirty: bool,
    execute_user: bool,
    _reserved1: bool,
    pfn: u40,
    _reserved2: u5,
    verify_gpa: bool,
    paging_write: bool,
    _reserved3: u2,
    supervisor_shadow: bool,
    sub_page_write: bool,
    suppress_ve: bool,

    pub fn address(self: EptEntry) u64 {
        return @as(u64, self.pfn) << 12;
    }
};

pub const EptPointer = packed struct(u64) {
    memory_type: u3,         // 0=UC, 6=WB
    page_walk_length: u3,    // 3 = 4-level
    dirty_accessed: bool,
    enforcement_mode: bool,
    _reserved: u4,
    pml4_pfn: u40,
    _reserved2: u12,
};

// ============================================================================
// AMD NPT (Nested Page Table) / RVI (Rapid Virtualization Indexing)
// ============================================================================

pub const NptEntry = packed struct(u64) {
    present: bool,
    writable: bool,
    user: bool,
    write_through: bool,
    cache_disable: bool,
    accessed: bool,
    dirty: bool,
    huge_page: bool,
    global: bool,
    avl: u3,
    pfn: u40,
    avail_high: u11,
    no_execute: bool,

    pub fn address(self: NptEntry) u64 {
        return @as(u64, self.pfn) << 12;
    }
};

// ============================================================================
// Page Walk Result
// ============================================================================

pub const PageWalkResult = struct {
    physical_addr: u64,
    page_size: PageSize,
    level: PageLevel,
    flags: u64,          // Raw PTE flags
    cached: bool,        // Was in TLB
    fault: bool,
    fault_type: PageFaultType,
};

pub const PageFaultType = enum(u8) {
    none = 0,
    not_present = 1,
    write_protected = 2,
    user_supervisor = 3,
    reserved_bit = 4,
    instruction_fetch = 5,
    protection_key = 6,
    shadow_stack = 7,
    // SGX
    sgx_access = 8,
};

pub const PageFaultErrorCode = packed struct(u32) {
    present: bool,              // P - Page was present
    write: bool,               // W/R - Write access
    user: bool,                // U/S - User mode access
    reserved_write: bool,      // RSVD - Reserved bit violation
    instruction_fetch: bool,   // I/D - Instruction fetch
    protection_key: bool,      // PK - Protection key violation
    shadow_stack: bool,        // SS - Shadow stack access
    _reserved1: u8,
    sgx: bool,                 // SGX - Enclave access
    _reserved2: u16,
};

// ============================================================================
// Process Address Space
// ============================================================================

pub const MmStruct = struct {
    pgd: u64,               // Physical address of top-level page table
    nr_ptes: u64,           // Number of page table pages
    nr_pmds: u64,
    nr_puds: u64,
    map_count: u32,          // Number of VMAs
    total_vm: u64,           // Total pages mapped
    locked_vm: u64,          // Pages locked in memory
    pinned_vm: u64,          // Pages pinned
    data_vm: u64,
    exec_vm: u64,
    stack_vm: u64,
    start_code: u64,
    end_code: u64,
    start_data: u64,
    end_data: u64,
    start_brk: u64,
    brk: u64,
    start_stack: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
    // PCID
    context_pcid: u16,
    pcid_generation: u64,
    // RSS counters
    rss_file: i64,
    rss_anon: i64,
    rss_shmem: i64,
    rss_swap: i64,
    // Flags
    flags: MmFlags,
};

pub const MmFlags = packed struct(u64) {
    dump_filter_anon: bool = true,
    dump_filter_mapped: bool = true,
    dump_filter_elf: bool = true,
    dump_filter_hugetlb: bool = false,
    randomize_va: bool = true,
    no_exec_stack: bool = true,
    has_huge_pages: bool = false,
    has_5level: bool = false,
    _reserved: u56 = 0,
};

// ============================================================================
// Page Table Manipulation Manager
// ============================================================================

pub const PageTableManager = struct {
    la57_enabled: bool,           // 5-level paging
    pcid_config: PcidConfig,
    kpti_config: KptiConfig,
    // Statistics
    total_page_tables: u64,
    total_huge_pages_2m: u64,
    total_huge_pages_1g: u64,
    tlb_flushes_total: u64,
    tlb_flushes_remote: u64,     // IPI-based flushes
    page_faults_total: u64,
    page_walks_total: u64,
    initialized: bool,

    pub fn init(la57: bool) PageTableManager {
        return .{
            .la57_enabled = la57,
            .pcid_config = .{
                .enabled = true,
                .invpcid_supported = true,
                .max_asids = PCID_MAX,
                .cr4_pcide = true,
                .force_disabled = false,
            },
            .kpti_config = .{
                .enabled = true,
                .forced = false,
                .trampoline_cr3 = 0,
                .kernel_cr3 = 0,
                .entry_text_mapped = false,
                .entry_data_mapped = false,
                .per_cpu_mapped = false,
                .syscall_overhead_ns = 0,
                .interrupt_overhead_ns = 0,
            },
            .total_page_tables = 0,
            .total_huge_pages_2m = 0,
            .total_huge_pages_1g = 0,
            .tlb_flushes_total = 0,
            .tlb_flushes_remote = 0,
            .page_faults_total = 0,
            .page_walks_total = 0,
            .initialized = true,
        };
    }
};
