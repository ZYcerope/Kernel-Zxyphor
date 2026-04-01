// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Intel VMX (Virtual Machine Extensions) / Hypervisor
// Full hardware virtualization: VMCS, VM-entry/exit, EPT, VPID, nested virt

const std = @import("std");

// ============================================================================
// VMX MSRs
// ============================================================================

pub const MSR_IA32_VMX_BASIC: u32 = 0x480;
pub const MSR_IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const MSR_IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const MSR_IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const MSR_IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const MSR_IA32_VMX_MISC: u32 = 0x485;
pub const MSR_IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const MSR_IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const MSR_IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const MSR_IA32_VMX_CR4_FIXED1: u32 = 0x489;
pub const MSR_IA32_VMX_VMCS_ENUM: u32 = 0x48A;
pub const MSR_IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
pub const MSR_IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
pub const MSR_IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
pub const MSR_IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
pub const MSR_IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
pub const MSR_IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
pub const MSR_IA32_VMX_VMFUNC: u32 = 0x491;
pub const MSR_IA32_VMX_PROCBASED_CTLS3: u32 = 0x492;

// ============================================================================
// VMCS Field Encodings
// ============================================================================

pub const VmcsField = enum(u32) {
    // 16-bit control fields
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    POSTED_INTR_NV = 0x00000002,
    EPTP_INDEX = 0x00000004,
    HLAT_PREFIX_SIZE = 0x00000006,

    // 16-bit guest-state fields
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080A,
    GUEST_LDTR_SELECTOR = 0x0000080C,
    GUEST_TR_SELECTOR = 0x0000080E,
    GUEST_INTR_STATUS = 0x00000810,
    GUEST_PML_INDEX = 0x00000812,

    // 16-bit host-state fields
    HOST_ES_SELECTOR = 0x00000C00,
    HOST_CS_SELECTOR = 0x00000C02,
    HOST_SS_SELECTOR = 0x00000C04,
    HOST_DS_SELECTOR = 0x00000C06,
    HOST_FS_SELECTOR = 0x00000C08,
    HOST_GS_SELECTOR = 0x00000C0A,
    HOST_TR_SELECTOR = 0x00000C0C,

    // 64-bit control fields
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_B = 0x00002002,
    MSR_BITMAP = 0x00002004,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200A,
    EXECUTIVE_VMCS_PTR = 0x0000200C,
    PML_ADDRESS = 0x0000200E,
    TSC_OFFSET = 0x00002010,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    APIC_ACCESS_ADDR = 0x00002014,
    POSTED_INTR_DESC_ADDR = 0x00002016,
    VM_FUNCTION_CONTROLS = 0x00002018,
    EPT_POINTER = 0x0000201A,
    EOI_EXIT_BITMAP0 = 0x0000201C,
    EOI_EXIT_BITMAP1 = 0x0000201E,
    EOI_EXIT_BITMAP2 = 0x00002020,
    EOI_EXIT_BITMAP3 = 0x00002022,
    EPTP_LIST_ADDR = 0x00002024,
    VMREAD_BITMAP = 0x00002026,
    VMWRITE_BITMAP = 0x00002028,
    VIRT_EXCEPTION_INFO = 0x0000202A,
    XSS_EXIT_BITMAP = 0x0000202C,
    ENCLS_EXITING_BITMAP = 0x0000202E,
    SUB_PAGE_PERMISSION_PTR = 0x00002030,
    TSC_MULTIPLIER = 0x00002032,
    TERTIARY_VM_EXEC_CTL = 0x00002034,
    ENCLV_EXITING_BITMAP = 0x00002036,
    HLAT_PTR = 0x00002040,
    SECONDARY_VM_EXIT_CTL = 0x00002044,

    // 64-bit read-only data fields
    GUEST_PHYSICAL_ADDRESS = 0x00002400,

    // 64-bit guest-state fields
    VMCS_LINK_POINTER = 0x00002800,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_PAT = 0x00002804,
    GUEST_IA32_EFER = 0x00002806,
    GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
    GUEST_PDPTE0 = 0x0000280A,
    GUEST_PDPTE1 = 0x0000280C,
    GUEST_PDPTE2 = 0x0000280E,
    GUEST_PDPTE3 = 0x00002810,
    GUEST_BNDCFGS = 0x00002812,
    GUEST_IA32_RTIT_CTL = 0x00002814,
    GUEST_IA32_LBR_CTL = 0x00002816,
    GUEST_IA32_PKRS = 0x00002818,

    // 64-bit host-state fields
    HOST_IA32_PAT = 0x00002C00,
    HOST_IA32_EFER = 0x00002C02,
    HOST_IA32_PERF_GLOBAL_CTRL = 0x00002C04,
    HOST_IA32_PKRS = 0x00002C06,

    // 32-bit control fields
    PIN_BASED_VM_EXEC_CTL = 0x00004000,
    CPU_BASED_VM_EXEC_CTL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400A,
    VM_EXIT_CONTROLS = 0x0000400C,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400E,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401A,
    TPR_THRESHOLD = 0x0000401C,
    SECONDARY_VM_EXEC_CTL = 0x0000401E,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
    NOTIFY_WINDOW = 0x00004024,

    // 32-bit read-only data fields
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440A,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440C,
    VMX_INSTRUCTION_INFO = 0x0000440E,

    // 32-bit guest-state fields
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480A,
    GUEST_LDTR_LIMIT = 0x0000480C,
    GUEST_TR_LIMIT = 0x0000480E,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481A,
    GUEST_FS_AR_BYTES = 0x0000481C,
    GUEST_GS_AR_BYTES = 0x0000481E,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SMBASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,

    // 32-bit host-state field
    HOST_IA32_SYSENTER_CS = 0x00004C00,

    // Natural-width control fields
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600A,
    CR3_TARGET_VALUE2 = 0x0000600C,
    CR3_TARGET_VALUE3 = 0x0000600E,

    // Natural-width read-only data fields
    EXIT_QUALIFICATION = 0x00006400,
    IO_RCX = 0x00006402,
    IO_RSI = 0x00006404,
    IO_RDI = 0x00006406,
    IO_RIP = 0x00006408,
    GUEST_LINEAR_ADDRESS = 0x0000640A,

    // Natural-width guest-state fields
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680A,
    GUEST_DS_BASE = 0x0000680C,
    GUEST_FS_BASE = 0x0000680E,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681A,
    GUEST_RSP = 0x0000681C,
    GUEST_RIP = 0x0000681E,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    GUEST_S_CET = 0x00006828,
    GUEST_SSP = 0x0000682A,
    GUEST_INTR_SSP_TABLE = 0x0000682C,

    // Natural-width host-state fields
    HOST_CR0 = 0x00006C00,
    HOST_CR3 = 0x00006C02,
    HOST_CR4 = 0x00006C04,
    HOST_FS_BASE = 0x00006C06,
    HOST_GS_BASE = 0x00006C08,
    HOST_TR_BASE = 0x00006C0A,
    HOST_GDTR_BASE = 0x00006C0C,
    HOST_IDTR_BASE = 0x00006C0E,
    HOST_IA32_SYSENTER_ESP = 0x00006C10,
    HOST_IA32_SYSENTER_EIP = 0x00006C12,
    HOST_RSP = 0x00006C14,
    HOST_RIP = 0x00006C16,
    HOST_S_CET = 0x00006C18,
    HOST_SSP = 0x00006C1A,
    HOST_INTR_SSP_TABLE = 0x00006C1C,
};

// ============================================================================
// VM-Exit Reasons
// ============================================================================

pub const VmExitReason = enum(u16) {
    EXCEPTION_NMI = 0,
    EXTERNAL_INTERRUPT = 1,
    TRIPLE_FAULT = 2,
    INIT_SIGNAL = 3,
    SIPI = 4,
    IO_SMI = 5,
    OTHER_SMI = 6,
    INTERRUPT_WINDOW = 7,
    NMI_WINDOW = 8,
    TASK_SWITCH = 9,
    CPUID = 10,
    GETSEC = 11,
    HLT = 12,
    INVD = 13,
    INVLPG = 14,
    RDPMC = 15,
    RDTSC = 16,
    RSM = 17,
    VMCALL = 18,
    VMCLEAR = 19,
    VMLAUNCH = 20,
    VMPTRLD = 21,
    VMPTRST = 22,
    VMREAD = 23,
    VMRESUME = 24,
    VMWRITE = 25,
    VMXOFF = 26,
    VMXON = 27,
    CR_ACCESS = 28,
    MOV_DR = 29,
    IO_INSTRUCTION = 30,
    RDMSR = 31,
    WRMSR = 32,
    VM_ENTRY_FAILURE_GUEST = 33,
    VM_ENTRY_FAILURE_MSR = 34,
    MWAIT = 36,
    MONITOR_TRAP_FLAG = 37,
    MONITOR = 39,
    PAUSE = 40,
    VM_ENTRY_FAILURE_MC = 41,
    TPR_BELOW_THRESHOLD = 43,
    APIC_ACCESS = 44,
    VIRTUALIZED_EOI = 45,
    GDTR_IDTR = 46,
    LDTR_TR = 47,
    EPT_VIOLATION = 48,
    EPT_MISCONFIG = 49,
    INVEPT = 50,
    RDTSCP = 51,
    VMX_PREEMPTION_TIMER = 52,
    INVVPID = 53,
    WBINVD = 54,
    XSETBV = 55,
    APIC_WRITE = 56,
    RDRAND = 57,
    INVPCID = 58,
    VMFUNC = 59,
    ENCLS = 60,
    RDSEED = 61,
    PML_FULL = 62,
    XSAVES = 63,
    XRSTORS = 64,
    SPP_EVENT = 66,
    UMWAIT = 67,
    TPAUSE = 68,
    LOADIWKEY = 69,
    ENCLV = 70,
    ENQCMD_PASID_TRANSLATION = 72,
    ENQCMDS_PASID_TRANSLATION = 73,
    BUS_LOCK = 74,
    NOTIFY = 75,
    SEAMCALL = 76,
    TDCALL = 77,
    _,
};

// ============================================================================
// Pin-Based VM-Execution Controls
// ============================================================================

pub const PIN_BASED_EXT_INTR_MASK: u32 = 1 << 0;
pub const PIN_BASED_NMI_EXITING: u32 = 1 << 3;
pub const PIN_BASED_VIRTUAL_NMIS: u32 = 1 << 5;
pub const PIN_BASED_VMX_PREEMPTION_TIMER: u32 = 1 << 6;
pub const PIN_BASED_POSTED_INTR: u32 = 1 << 7;

// Primary Processor-Based VM-Execution Controls
pub const CPU_BASED_INTR_WINDOW_EXITING: u32 = 1 << 2;
pub const CPU_BASED_USE_TSC_OFFSETTING: u32 = 1 << 3;
pub const CPU_BASED_HLT_EXITING: u32 = 1 << 7;
pub const CPU_BASED_INVLPG_EXITING: u32 = 1 << 9;
pub const CPU_BASED_MWAIT_EXITING: u32 = 1 << 10;
pub const CPU_BASED_RDPMC_EXITING: u32 = 1 << 11;
pub const CPU_BASED_RDTSC_EXITING: u32 = 1 << 12;
pub const CPU_BASED_CR3_LOAD_EXITING: u32 = 1 << 15;
pub const CPU_BASED_CR3_STORE_EXITING: u32 = 1 << 16;
pub const CPU_BASED_ACTIVATE_TERTIARY_CTL: u32 = 1 << 17;
pub const CPU_BASED_CR8_LOAD_EXITING: u32 = 1 << 19;
pub const CPU_BASED_CR8_STORE_EXITING: u32 = 1 << 20;
pub const CPU_BASED_TPR_SHADOW: u32 = 1 << 21;
pub const CPU_BASED_NMI_WINDOW_EXITING: u32 = 1 << 22;
pub const CPU_BASED_MOV_DR_EXITING: u32 = 1 << 23;
pub const CPU_BASED_UNCOND_IO_EXITING: u32 = 1 << 24;
pub const CPU_BASED_USE_IO_BITMAPS: u32 = 1 << 25;
pub const CPU_BASED_MONITOR_TRAP_FLAG: u32 = 1 << 27;
pub const CPU_BASED_USE_MSR_BITMAPS: u32 = 1 << 28;
pub const CPU_BASED_MONITOR_EXITING: u32 = 1 << 29;
pub const CPU_BASED_PAUSE_EXITING: u32 = 1 << 30;
pub const CPU_BASED_ACTIVATE_SECONDARY_CTL: u32 = 1 << 31;

// Secondary Processor-Based VM-Execution Controls
pub const SECONDARY_EXEC_VIRTUALIZE_APIC: u32 = 1 << 0;
pub const SECONDARY_EXEC_ENABLE_EPT: u32 = 1 << 1;
pub const SECONDARY_EXEC_DESC_TABLE_EXITING: u32 = 1 << 2;
pub const SECONDARY_EXEC_RDTSCP: u32 = 1 << 3;
pub const SECONDARY_EXEC_VIRTUALIZE_X2APIC: u32 = 1 << 4;
pub const SECONDARY_EXEC_ENABLE_VPID: u32 = 1 << 5;
pub const SECONDARY_EXEC_WBINVD_EXITING: u32 = 1 << 6;
pub const SECONDARY_EXEC_UNRESTRICTED_GUEST: u32 = 1 << 7;
pub const SECONDARY_EXEC_APIC_REGISTER_VIRT: u32 = 1 << 8;
pub const SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY: u32 = 1 << 9;
pub const SECONDARY_EXEC_PAUSE_LOOP_EXITING: u32 = 1 << 10;
pub const SECONDARY_EXEC_RDRAND_EXITING: u32 = 1 << 11;
pub const SECONDARY_EXEC_ENABLE_INVPCID: u32 = 1 << 12;
pub const SECONDARY_EXEC_ENABLE_VMFUNC: u32 = 1 << 13;
pub const SECONDARY_EXEC_SHADOW_VMCS: u32 = 1 << 14;
pub const SECONDARY_EXEC_ENABLE_ENCLS_EXITING: u32 = 1 << 15;
pub const SECONDARY_EXEC_RDSEED_EXITING: u32 = 1 << 16;
pub const SECONDARY_EXEC_ENABLE_PML: u32 = 1 << 17;
pub const SECONDARY_EXEC_EPT_VIOLATION_VE: u32 = 1 << 18;
pub const SECONDARY_EXEC_CONCEAL_VMX_FROM_PT: u32 = 1 << 19;
pub const SECONDARY_EXEC_XSAVES: u32 = 1 << 20;
pub const SECONDARY_EXEC_MODE_BASED_EPT: u32 = 1 << 22;
pub const SECONDARY_EXEC_SUB_PAGE_WRITE_PERM: u32 = 1 << 23;
pub const SECONDARY_EXEC_PT_USE_GPA: u32 = 1 << 24;
pub const SECONDARY_EXEC_TSC_SCALING: u32 = 1 << 25;
pub const SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE: u32 = 1 << 26;
pub const SECONDARY_EXEC_ENCLV_EXITING: u32 = 1 << 28;
pub const SECONDARY_EXEC_BUS_LOCK_DETECTION: u32 = 1 << 30;
pub const SECONDARY_EXEC_NOTIFY_VM_EXITING: u32 = 1 << 31;

// ============================================================================
// EPT (Extended Page Tables)
// ============================================================================

pub const EPT_READ: u64 = 1 << 0;
pub const EPT_WRITE: u64 = 1 << 1;
pub const EPT_EXECUTE: u64 = 1 << 2;
pub const EPT_MEMORY_TYPE_SHIFT: u6 = 3;
pub const EPT_MEMORY_TYPE_MASK: u64 = 0x7 << 3;
pub const EPT_IGNORE_PAT: u64 = 1 << 6;
pub const EPT_LARGE_PAGE: u64 = 1 << 7;
pub const EPT_ACCESSED: u64 = 1 << 8;
pub const EPT_DIRTY: u64 = 1 << 9;
pub const EPT_EXECUTE_USER: u64 = 1 << 10;
pub const EPT_VERIFY_GUEST_PAGING: u64 = 1 << 57;
pub const EPT_PAGING_WRITE_ACCESS: u64 = 1 << 58;
pub const EPT_SUPPRESS_VE: u64 = 1 << 63;

pub const EptMemoryType = enum(u3) {
    UC = 0, // Uncacheable
    WC = 1, // Write Combining
    WT = 4, // Write Through
    WP = 5, // Write Protect
    WB = 6, // Write Back
};

pub const EptPointer = packed struct {
    memory_type: u3,      // Must be WB (6) for normal operation
    page_walk_length: u3, // Must be 3 (4-level) or 4 (5-level)
    ad_enabled: bool,     // Access/Dirty flag enable
    supervisor_shadow_stack: bool,
    reserved1: u4,
    pml4_addr: u40,
    reserved2: u12,

    pub fn from_raw(raw: u64) EptPointer {
        return @bitCast(raw);
    }

    pub fn to_raw(self: EptPointer) u64 {
        return @bitCast(self);
    }
};

pub const EptEntry = packed struct {
    read: bool,
    write: bool,
    execute: bool,
    memory_type: u3,
    ignore_pat: bool,
    large_page: bool,
    accessed: bool,
    dirty: bool,
    execute_user: bool,
    reserved1: u1,
    addr: u40,
    reserved2: u10,
    suppress_ve: bool,
    verify_guest_paging: bool,

    pub fn address(self: EptEntry) u64 {
        return @as(u64, self.addr) << 12;
    }

    pub fn from_raw(raw: u64) EptEntry {
        return @bitCast(raw);
    }

    pub fn to_raw(self: EptEntry) u64 {
        return @bitCast(self);
    }

    pub fn is_present(self: EptEntry) bool {
        return self.read or self.write or self.execute;
    }
};

// ============================================================================
// VMCS Region
// ============================================================================

pub const VMCS_REVISION_MASK: u32 = 0x7FFFFFFF;
pub const VMCS_SHADOW_BIT: u32 = 1 << 31;

pub const VmcsRegion = extern struct {
    revision_id: u32,
    abort_indicator: u32,
    data: [4088]u8, // 4KB page - 8 bytes header
};

// ============================================================================
// Virtual Machine (Per-vCPU State)
// ============================================================================

pub const MAX_VCPUS: usize = 256;
pub const MAX_MSR_ENTRIES: usize = 256;
pub const MAX_IO_BITMAP_SIZE: usize = 8192; // 64KB I/O space

pub const VcpuState = enum(u8) {
    created = 0,
    initialized = 1,
    running = 2,
    halted = 3,
    waiting_for_sipi = 4,
    paused = 5,
    shutdown = 6,
    failed = 7,
};

pub const MsrEntry = struct {
    index: u32,
    reserved: u32 = 0,
    value: u64,
};

pub const VcpuRegisters = struct {
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rbp: u64 = 0,
    rsp: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rip: u64 = 0,
    rflags: u64 = 0x2,
};

pub const VcpuSpecialRegisters = struct {
    cr0: u64 = 0x10,      // ET set
    cr2: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,
    cr8: u64 = 0,
    efer: u64 = 0,
    apic_base: u64 = 0xFEE00000 | (1 << 11), // APIC enabled
    dr0: u64 = 0,
    dr1: u64 = 0,
    dr2: u64 = 0,
    dr3: u64 = 0,
    dr6: u64 = 0xFFFF0FF0,
    dr7: u64 = 0x400,
};

pub const VcpuSegment = struct {
    base: u64 = 0,
    limit: u32 = 0,
    selector: u16 = 0,
    type_: u8 = 0,
    present: bool = false,
    dpl: u2 = 0,
    db: bool = false,
    s: bool = false,
    l: bool = false,
    g: bool = false,
    avl: bool = false,
    unusable: bool = false,
};

pub const VcpuDescTable = struct {
    base: u64 = 0,
    limit: u16 = 0,
};

pub const Vcpu = struct {
    id: u32,
    state: VcpuState,
    vmcs_phys: u64,
    vmcs: *VmcsRegion,
    regs: VcpuRegisters,
    special_regs: VcpuSpecialRegisters,
    // Segments
    cs: VcpuSegment,
    ds: VcpuSegment,
    es: VcpuSegment,
    fs: VcpuSegment,
    gs: VcpuSegment,
    ss: VcpuSegment,
    tr: VcpuSegment,
    ldt: VcpuSegment,
    gdt: VcpuDescTable,
    idt: VcpuDescTable,
    // APIC
    lapic_id: u32,
    apic_page: [4096]u8 align(4096),
    // MSR autoload
    msr_autoload_guest: [MAX_MSR_ENTRIES]MsrEntry,
    msr_autoload_host: [MAX_MSR_ENTRIES]MsrEntry,
    msr_autoload_count: u32,
    // FPU/SSE/AVX state
    fpu_state: [4096]u8 align(64),
    // Stats
    exit_count: u64,
    total_guest_time_ns: u64,
    last_exit_reason: VmExitReason,
    // Interrupt injection
    pending_irq: ?u8,
    nmi_pending: bool,
    interrupt_window_open: bool,

    pub fn vmread(self: *Vcpu, field: VmcsField) u64 {
        _ = self;
        var value: u64 = undefined;
        var success: u8 = undefined;
        asm volatile (
            \\vmread %[field], %[value]
            \\seta %[success]
            : [value] "=r" (value),
              [success] "=r" (success),
            : [field] "r" (@as(u64, @intFromEnum(field))),
        );
        return if (success != 0) value else 0;
    }

    pub fn vmwrite(self: *Vcpu, field: VmcsField, value: u64) bool {
        _ = self;
        var success: u8 = undefined;
        asm volatile (
            \\vmwrite %[value], %[field]
            \\seta %[success]
            : [success] "=r" (success),
            : [field] "r" (@as(u64, @intFromEnum(field))),
              [value] "r" (value),
        );
        return success != 0;
    }

    pub fn inject_interrupt(self: *Vcpu, vector: u8) void {
        const info: u32 = @as(u32, vector) | (0 << 8) | (1 << 31); // External interrupt, valid
        _ = self.vmwrite(.VM_ENTRY_INTR_INFO_FIELD, info);
    }

    pub fn inject_exception(self: *Vcpu, vector: u8, has_error_code: bool, error_code: u32) void {
        var info: u32 = @as(u32, vector) | (3 << 8) | (1 << 31); // Hardware exception, valid
        if (has_error_code) {
            info |= (1 << 11);
            _ = self.vmwrite(.VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
        }
        _ = self.vmwrite(.VM_ENTRY_INTR_INFO_FIELD, info);
    }
};

// ============================================================================
// Virtual Machine Instance
// ============================================================================

pub const MemorySlot = struct {
    slot_id: u16,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    host_phys_addr: u64,
    dirty_bitmap: ?[*]u8,
};

pub const MAX_MEMORY_SLOTS: usize = 512;

pub const VmInstance = struct {
    id: u32,
    vcpus: [MAX_VCPUS]?*Vcpu,
    vcpu_count: u32,
    // EPT
    ept_root: u64,
    eptp: EptPointer,
    // Memory slots
    memory_slots: [MAX_MEMORY_SLOTS]?MemorySlot,
    slot_count: u32,
    // I/O bitmap
    io_bitmap_a: [4096]u8 align(4096), // Ports 0x0000-0x7FFF
    io_bitmap_b: [4096]u8 align(4096), // Ports 0x8000-0xFFFF
    // MSR bitmap
    msr_bitmap: [4096]u8 align(4096),
    // VPID
    vpid_base: u16,
    // Features
    unrestricted_guest: bool,
    ept_ad_bits: bool,
    posted_interrupts: bool,
    tsc_scaling: bool,
    pml_enabled: bool,

    pub fn create_vcpu(self: *VmInstance) ?*Vcpu {
        if (self.vcpu_count >= MAX_VCPUS) return null;
        // Allocate VCPU (in real impl, allocate from kernel memory)
        const idx = self.vcpu_count;
        self.vcpu_count += 1;
        _ = idx;
        return null; // Placeholder - real impl allocates
    }

    pub fn set_memory_region(self: *VmInstance, slot: MemorySlot) bool {
        if (slot.slot_id >= MAX_MEMORY_SLOTS) return false;
        self.memory_slots[slot.slot_id] = slot;
        if (slot.slot_id >= self.slot_count) {
            self.slot_count = slot.slot_id + 1;
        }
        return true;
    }

    pub fn set_io_port_intercept(self: *VmInstance, port: u16, intercept: bool) void {
        if (port < 0x8000) {
            const byte_idx = port / 8;
            const bit_idx: u3 = @truncate(port % 8);
            if (intercept) {
                self.io_bitmap_a[byte_idx] |= @as(u8, 1) << bit_idx;
            } else {
                self.io_bitmap_a[byte_idx] &= ~(@as(u8, 1) << bit_idx);
            }
        } else {
            const adjusted = port - 0x8000;
            const byte_idx = adjusted / 8;
            const bit_idx: u3 = @truncate(adjusted % 8);
            if (intercept) {
                self.io_bitmap_b[byte_idx] |= @as(u8, 1) << bit_idx;
            } else {
                self.io_bitmap_b[byte_idx] &= ~(@as(u8, 1) << bit_idx);
            }
        }
    }

    pub fn set_msr_intercept(self: *VmInstance, msr: u32, read: bool, write: bool) void {
        // MSR bitmap layout:
        // 0x000-0x3FF: Read bitmap for low MSRs (0x00000000-0x00001FFF)
        // 0x400-0x7FF: Read bitmap for high MSRs (0xC0000000-0xC0001FFF)
        // 0x800-0xBFF: Write bitmap for low MSRs
        // 0xC00-0xFFF: Write bitmap for high MSRs
        var base_offset: usize = 0;
        var msr_offset: u32 = 0;

        if (msr <= 0x1FFF) {
            base_offset = 0;
            msr_offset = msr;
        } else if (msr >= 0xC0000000 and msr <= 0xC0001FFF) {
            base_offset = 0x400;
            msr_offset = msr - 0xC0000000;
        } else {
            return; // MSR not in bitmap range
        }

        const byte_idx = msr_offset / 8;
        const bit_idx: u3 = @truncate(msr_offset % 8);
        const mask = @as(u8, 1) << bit_idx;

        // Read bitmap
        if (read) {
            self.msr_bitmap[base_offset + byte_idx] |= mask;
        } else {
            self.msr_bitmap[base_offset + byte_idx] &= ~mask;
        }

        // Write bitmap (offset by 0x800)
        if (write) {
            self.msr_bitmap[base_offset + 0x800 + byte_idx] |= mask;
        } else {
            self.msr_bitmap[base_offset + 0x800 + byte_idx] &= ~mask;
        }
    }
};

// ============================================================================
// VMXON / VMXOFF
// ============================================================================

pub fn vmxon(vmxon_region_phys: u64) bool {
    var success: u8 = undefined;
    asm volatile (
        \\vmxon (%[ptr])
        \\seta %[success]
        : [success] "=r" (success),
        : [ptr] "r" (&vmxon_region_phys),
        : "memory", "cc",
    );
    return success != 0;
}

pub fn vmxoff() void {
    asm volatile ("vmxoff" ::: "cc");
}

pub fn vmclear(vmcs_phys: u64) bool {
    var success: u8 = undefined;
    asm volatile (
        \\vmclear (%[ptr])
        \\seta %[success]
        : [success] "=r" (success),
        : [ptr] "r" (&vmcs_phys),
        : "memory", "cc",
    );
    return success != 0;
}

pub fn vmptrld(vmcs_phys: u64) bool {
    var success: u8 = undefined;
    asm volatile (
        \\vmptrld (%[ptr])
        \\seta %[success]
        : [success] "=r" (success),
        : [ptr] "r" (&vmcs_phys),
        : "memory", "cc",
    );
    return success != 0;
}

// ============================================================================
// VM-Exit Handler Dispatch
// ============================================================================

pub const VmExitInfo = struct {
    reason: VmExitReason,
    qualification: u64,
    guest_rip: u64,
    guest_rsp: u64,
    instruction_length: u32,
    interrupt_info: u32,
    error_code: u32,
    guest_linear_addr: u64,
    guest_physical_addr: u64,
};

pub fn handle_vm_exit(vcpu: *Vcpu) VmExitInfo {
    const reason_raw = vcpu.vmread(.VM_EXIT_REASON);
    const qualification = vcpu.vmread(.EXIT_QUALIFICATION);
    const guest_rip = vcpu.vmread(.GUEST_RIP);
    const guest_rsp = vcpu.vmread(.GUEST_RSP);
    const instr_len_raw = vcpu.vmread(.VM_EXIT_INSTRUCTION_LEN);
    const intr_info_raw = vcpu.vmread(.VM_EXIT_INTR_INFO);
    const err_code_raw = vcpu.vmread(.VM_EXIT_INTR_ERROR_CODE);
    const guest_linear = vcpu.vmread(.GUEST_LINEAR_ADDRESS);
    const guest_phys = vcpu.vmread(.GUEST_PHYSICAL_ADDRESS);

    vcpu.exit_count += 1;

    return VmExitInfo{
        .reason = @enumFromInt(@as(u16, @truncate(reason_raw & 0xFFFF))),
        .qualification = qualification,
        .guest_rip = guest_rip,
        .guest_rsp = guest_rsp,
        .instruction_length = @truncate(instr_len_raw),
        .interrupt_info = @truncate(intr_info_raw),
        .error_code = @truncate(err_code_raw),
        .guest_linear_addr = guest_linear,
        .guest_physical_addr = guest_phys,
    };
}

// ============================================================================
// EPT Management
// ============================================================================

pub const EptLevel = enum(u2) {
    pml4 = 3,
    pdpt = 2,
    pd = 1,
    pt = 0,
};

pub const EptViolationType = struct {
    read: bool,
    write: bool,
    execute: bool,
    readable: bool,
    writable: bool,
    executable: bool,
    guest_linear_valid: bool,
    caused_by_translation: bool,
    user_mode: bool,
    rw_readable: bool,
    rw_writable: bool,
    execute_disabled: bool,
    nmi_unblocking: bool,
    shadow_stack: bool,
    supervisor_shadow_stack: bool,
    caused_by_guest_paging_verify: bool,
    async_to_ipt: bool,

    pub fn from_qualification(qual: u64) EptViolationType {
        return .{
            .read = (qual & (1 << 0)) != 0,
            .write = (qual & (1 << 1)) != 0,
            .execute = (qual & (1 << 2)) != 0,
            .readable = (qual & (1 << 3)) != 0,
            .writable = (qual & (1 << 4)) != 0,
            .executable = (qual & (1 << 5)) != 0,
            .guest_linear_valid = (qual & (1 << 7)) != 0,
            .caused_by_translation = (qual & (1 << 8)) != 0,
            .user_mode = (qual & (1 << 9)) != 0,
            .rw_readable = (qual & (1 << 10)) != 0,
            .rw_writable = (qual & (1 << 11)) != 0,
            .execute_disabled = (qual & (1 << 12)) != 0,
            .nmi_unblocking = (qual & (1 << 13)) != 0,
            .shadow_stack = (qual & (1 << 14)) != 0,
            .supervisor_shadow_stack = (qual & (1 << 15)) != 0,
            .caused_by_guest_paging_verify = (qual & (1 << 16)) != 0,
            .async_to_ipt = (qual & (1 << 17)) != 0,
        };
    }
};

// ============================================================================
// Nested Virtualization
// ============================================================================

pub const NestedVmxState = struct {
    // L1 hypervisor's VMX state
    vmxon: bool,
    vmxon_region_phys: u64,
    current_vmcs12_phys: u64,
    shadow_vmcs_enabled: bool,

    // Cached VMCS12 fields
    vmcs12: VmcsRegion,

    // VMCS02 (hardware VMCS for L2 guest)
    vmcs02_phys: u64,
    vmcs02: *VmcsRegion,

    // L2 guest running state
    l2_active: bool,
    l2_vcpu_state: VcpuRegisters,

    // EPT composition: L0 EPT maps L1 GPA -> HPA; L1 EPT maps L2 GPA -> L1 GPA
    // Combined EPT (shadow EPT) maps L2 GPA -> HPA
    shadow_ept_root: u64,
    shadow_ept_generation: u64,

    pub fn enter_l2(self: *NestedVmxState) void {
        self.l2_active = true;
        // Compose EPTs, merge controls, load VMCS02
    }

    pub fn exit_to_l1(self: *NestedVmxState) void {
        self.l2_active = false;
        // Restore L1 VMCS, propagate exit info to VMCS12
    }
};

// ============================================================================
// Posted Interrupt Descriptor
// ============================================================================

pub const PostedInterruptDesc = extern struct {
    pir: [4]u64 align(64),    // Posted Interrupt Requests (256 bits)
    control: packed struct {
        on: bool,             // Outstanding Notification
        suppress: bool,        // Suppress Notification
        reserved: u6,
        nv: u8,               // Notification Vector
        reserved2: u48,
    },
    reserved: [24]u8,
};

// ============================================================================
// VPID (Virtual Processor Identifier)
// ============================================================================

pub const InvvpidType = enum(u64) {
    individual_address = 0,
    single_context = 1,
    all_contexts = 2,
    single_context_retaining_global = 3,
};

pub fn invvpid(type_: InvvpidType, vpid: u16, addr: u64) void {
    const desc = [2]u64{ vpid, addr };
    asm volatile ("invvpid %[desc], %[type_]"
        :
        : [type_] "r" (@intFromEnum(type_)),
          [desc] "m" (desc),
        : "memory",
    );
}

pub const InveptType = enum(u64) {
    single_context = 1,
    global = 2,
};

pub fn invept(type_: InveptType, eptp: u64) void {
    const desc = [2]u64{ eptp, 0 };
    asm volatile ("invept %[desc], %[type_]"
        :
        : [type_] "r" (@intFromEnum(type_)),
          [desc] "m" (desc),
        : "memory",
    );
}

// ============================================================================
// Hypercall Interface (KVM-compatible + Zxyphor extensions)
// ============================================================================

pub const HypercallNr = enum(u32) {
    // KVM-compatible
    KVM_HC_VAPIC_POLL_IRQ = 1,
    KVM_HC_MMU_OP = 2,
    KVM_HC_FEATURES = 3,
    KVM_HC_PPC_MAP_MAGIC_PAGE = 4,
    KVM_HC_KICK_CPU = 5,
    KVM_HC_CLOCK_PAIRING = 9,
    KVM_HC_SEND_IPI = 10,
    KVM_HC_SCHED_YIELD = 11,
    KVM_HC_MAP_GPA_RANGE = 12,

    // Zxyphor hypervisor extensions
    ZXY_HC_VM_CREATE = 0x5A580001,
    ZXY_HC_VM_DESTROY = 0x5A580002,
    ZXY_HC_VCPU_CREATE = 0x5A580003,
    ZXY_HC_VCPU_RUN = 0x5A580004,
    ZXY_HC_MEM_MAP = 0x5A580005,
    ZXY_HC_MEM_UNMAP = 0x5A580006,
    ZXY_HC_IRQ_LINE = 0x5A580007,
    ZXY_HC_MSI_INJECT = 0x5A580008,
    ZXY_HC_DEVICE_ASSIGN = 0x5A580009,
    ZXY_HC_DEVICE_DEASSIGN = 0x5A58000A,
    ZXY_HC_LIVE_MIGRATE_PREP = 0x5A58000B,
    ZXY_HC_LIVE_MIGRATE_EXEC = 0x5A58000C,
    ZXY_HC_SNAPSHOT = 0x5A58000D,
    ZXY_HC_RESTORE = 0x5A58000E,
    ZXY_HC_PERF_QUERY = 0x5A58000F,
    _,
};

// ============================================================================
// AMD SVM (Secure Virtual Machine) - for AMD compatibility
// ============================================================================

pub const MSR_VM_CR: u32 = 0xC0010114;
pub const MSR_VM_HSAVE_PA: u32 = 0xC0010117;

pub const SVM_EXIT_READ_CR0: u32 = 0x000;
pub const SVM_EXIT_WRITE_CR0: u32 = 0x010;
pub const SVM_EXIT_EXCP_BASE: u32 = 0x040;
pub const SVM_EXIT_INTR: u32 = 0x060;
pub const SVM_EXIT_NMI: u32 = 0x061;
pub const SVM_EXIT_SMI: u32 = 0x062;
pub const SVM_EXIT_INIT: u32 = 0x063;
pub const SVM_EXIT_VINTR: u32 = 0x064;
pub const SVM_EXIT_CR0_SEL_WRITE: u32 = 0x065;
pub const SVM_EXIT_CPUID: u32 = 0x072;
pub const SVM_EXIT_HLT: u32 = 0x078;
pub const SVM_EXIT_INVLPG: u32 = 0x079;
pub const SVM_EXIT_INVLPGA: u32 = 0x07A;
pub const SVM_EXIT_IOIO: u32 = 0x07B;
pub const SVM_EXIT_MSR: u32 = 0x07C;
pub const SVM_EXIT_TASK_SWITCH: u32 = 0x07D;
pub const SVM_EXIT_SHUTDOWN: u32 = 0x07F;
pub const SVM_EXIT_VMRUN: u32 = 0x080;
pub const SVM_EXIT_VMMCALL: u32 = 0x081;
pub const SVM_EXIT_VMLOAD: u32 = 0x082;
pub const SVM_EXIT_VMSAVE: u32 = 0x083;
pub const SVM_EXIT_STGI: u32 = 0x084;
pub const SVM_EXIT_CLGI: u32 = 0x085;
pub const SVM_EXIT_SKINIT: u32 = 0x086;
pub const SVM_EXIT_RDTSCP: u32 = 0x087;
pub const SVM_EXIT_ICEBP: u32 = 0x088;
pub const SVM_EXIT_NPF: u32 = 0x400;
pub const SVM_EXIT_AVIC_INCOMPLETE_IPI: u32 = 0x401;
pub const SVM_EXIT_AVIC_UNACCELERATED: u32 = 0x402;
pub const SVM_EXIT_VMGEXIT: u32 = 0x403;
pub const SVM_EXIT_SNP_VMGEXIT: u32 = 0x404;

pub const VmcbControlArea = extern struct {
    intercept_cr_reads: u32,
    intercept_cr_writes: u32,
    intercept_dr_reads: u32,
    intercept_dr_writes: u32,
    intercept_exceptions: u32,
    intercept_misc1: u32,
    intercept_misc2: u32,
    intercept_misc3: u32,
    reserved1: [36]u8,
    pause_filter_threshold: u16,
    pause_filter_count: u16,
    iopm_base_pa: u64,
    msrpm_base_pa: u64,
    tsc_offset: u64,
    guest_asid: u32,
    tlb_control: u8,
    reserved2: [3]u8,
    v_intr: u64,
    interrupt_shadow: u64,
    exit_code: u64,
    exit_info_1: u64,
    exit_info_2: u64,
    exit_int_info: u64,
    np_enable: u64,      // Nested Paging enable
    avic_apic_bar: u64,
    ghcb_gpa: u64,
    event_injection: u64,
    nested_cr3: u64,     // Nested page table root
    lbr_virt_enable: u64,
    vmcb_clean: u32,
    reserved3: u32,
    next_rip: u64,
    num_bytes_fetched: u8,
    guest_instruction_bytes: [15]u8,
    avic_backing_page: u64,
    reserved4: u64,
    avic_logical_table: u64,
    avic_physical_table: u64,
    reserved5: u64,
    vmcb_save_state_ptr: u64,
    reserved6: [720]u8,
};

pub const VmcbStateSaveArea = extern struct {
    es: VmcbSegment,
    cs: VmcbSegment,
    ss: VmcbSegment,
    ds: VmcbSegment,
    fs: VmcbSegment,
    gs: VmcbSegment,
    gdtr: VmcbSegment,
    ldtr: VmcbSegment,
    idtr: VmcbSegment,
    tr: VmcbSegment,
    reserved1: [43]u8,
    cpl: u8,
    reserved2: [4]u8,
    efer: u64,
    reserved3: [112]u8,
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    reserved4: [88]u8,
    rsp: u64,
    s_cet: u64,
    ssp: u64,
    isst_addr: u64,
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    cr2: u64,
    reserved5: [32]u8,
    g_pat: u64,
    dbgctl: u64,
    br_from: u64,
    br_to: u64,
    last_excp_from: u64,
    last_excp_to: u64,
    reserved6: [72]u8,
    spec_ctrl: u64,
};

pub const VmcbSegment = extern struct {
    selector: u16,
    attrib: u16,
    limit: u32,
    base: u64,
};

// ============================================================================
// Hardware Capability Detection
// ============================================================================

pub const VmxCapabilities = struct {
    vmx_supported: bool,
    svm_supported: bool,
    ept_supported: bool,
    ept_2mb_pages: bool,
    ept_1gb_pages: bool,
    ept_ad_bits: bool,
    vpid_supported: bool,
    unrestricted_guest: bool,
    posted_interrupts: bool,
    shadow_vmcs: bool,
    vmfunc: bool,
    pml: bool,
    tsc_scaling: bool,
    nested_vmx: bool,
    apicv: bool,
    five_level_ept: bool,
    mode_based_ept: bool,
    sub_page_write_perm: bool,
    notify_vm_exiting: bool,
    bus_lock_detection: bool,

    pub fn detect() VmxCapabilities {
        var caps: VmxCapabilities = .{
            .vmx_supported = false,
            .svm_supported = false,
            .ept_supported = false,
            .ept_2mb_pages = false,
            .ept_1gb_pages = false,
            .ept_ad_bits = false,
            .vpid_supported = false,
            .unrestricted_guest = false,
            .posted_interrupts = false,
            .shadow_vmcs = false,
            .vmfunc = false,
            .pml = false,
            .tsc_scaling = false,
            .nested_vmx = false,
            .apicv = false,
            .five_level_ept = false,
            .mode_based_ept = false,
            .sub_page_write_perm = false,
            .notify_vm_exiting = false,
            .bus_lock_detection = false,
        };

        // Check CPUID.1:ECX.VMX[bit 5]
        const leaf1 = cpuid_raw(1, 0);
        caps.vmx_supported = (leaf1.ecx & (1 << 5)) != 0;

        // Check AMD SVM: CPUID.80000001:ECX.SVM[bit 2]
        const leaf_ext = cpuid_raw(0x80000001, 0);
        caps.svm_supported = (leaf_ext.ecx & (1 << 2)) != 0;

        return caps;
    }
};

fn cpuid_raw(leaf: u32, subleaf: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
    var result: struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (result.eax),
          [ebx] "={ebx}" (result.ebx),
          [ecx] "={ecx}" (result.ecx),
          [edx] "={edx}" (result.edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );
    return result;
}
