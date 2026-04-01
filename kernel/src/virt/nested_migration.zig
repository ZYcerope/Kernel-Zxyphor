// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Nested Virtualization, Live Migration,
// Memory Balloon Zig-side, VMCS Shadowing, VPID/EPT,
// Virtual Interrupt Delivery, Posted Interrupts
// More advanced than Linux 2026 virtualization

const std = @import("std");

// ============================================================================
// Nested Virtualization (VMX on VMX)
// ============================================================================

/// Nested VMX state
pub const NestedVmxState = enum(u8) {
    disabled = 0,        // No nested VMX
    vmxon = 1,           // L1 executed VMXON
    vmcs_active = 2,     // L1 has active VMCS02
    l2_running = 3,      // L2 guest is running
    l2_exit = 4,         // Processing L2 VM exit
};

/// VMCS12 (L1's view of VMCS for L2)
pub const Vmcs12 = struct {
    // Revision ID
    revision_id: u32,
    abort_indicator: u32,
    // ---- Control fields ----
    // Pin-based controls
    pin_based_vm_exec_control: u32,
    // Processor-based controls
    cpu_based_vm_exec_control: u32,
    secondary_vm_exec_control: u32,
    tertiary_vm_exec_control: u64,
    // Exception bitmap
    exception_bitmap: u32,
    // Page fault error code match/mask
    page_fault_error_code_mask: u32,
    page_fault_error_code_match: u32,
    // CR0/CR4 guest/host mask and read shadow
    cr0_guest_host_mask: u64,
    cr4_guest_host_mask: u64,
    cr0_read_shadow: u64,
    cr4_read_shadow: u64,
    // CR3 target
    cr3_target_count: u32,
    cr3_target_value0: u64,
    cr3_target_value1: u64,
    cr3_target_value2: u64,
    cr3_target_value3: u64,
    // VM exit controls
    vm_exit_controls: u32,
    vm_exit_msr_store_count: u32,
    vm_exit_msr_load_count: u32,
    vm_exit_msr_store_addr: u64,
    vm_exit_msr_load_addr: u64,
    // VM entry controls
    vm_entry_controls: u32,
    vm_entry_msr_load_count: u32,
    vm_entry_msr_load_addr: u64,
    vm_entry_intr_info_field: u32,
    vm_entry_exception_error_code: u32,
    vm_entry_instruction_len: u32,
    // TPR threshold
    tpr_threshold: u32,
    // ---- Guest state ----
    guest_cr0: u64,
    guest_cr3: u64,
    guest_cr4: u64,
    guest_es_selector: u16,
    guest_cs_selector: u16,
    guest_ss_selector: u16,
    guest_ds_selector: u16,
    guest_fs_selector: u16,
    guest_gs_selector: u16,
    guest_ldtr_selector: u16,
    guest_tr_selector: u16,
    guest_es_base: u64,
    guest_cs_base: u64,
    guest_ss_base: u64,
    guest_ds_base: u64,
    guest_fs_base: u64,
    guest_gs_base: u64,
    guest_ldtr_base: u64,
    guest_tr_base: u64,
    guest_gdtr_base: u64,
    guest_idtr_base: u64,
    guest_es_limit: u32,
    guest_cs_limit: u32,
    guest_ss_limit: u32,
    guest_ds_limit: u32,
    guest_fs_limit: u32,
    guest_gs_limit: u32,
    guest_ldtr_limit: u32,
    guest_tr_limit: u32,
    guest_gdtr_limit: u32,
    guest_idtr_limit: u32,
    guest_es_ar_bytes: u32,
    guest_cs_ar_bytes: u32,
    guest_ss_ar_bytes: u32,
    guest_ds_ar_bytes: u32,
    guest_fs_ar_bytes: u32,
    guest_gs_ar_bytes: u32,
    guest_ldtr_ar_bytes: u32,
    guest_tr_ar_bytes: u32,
    guest_interruptibility_info: u32,
    guest_activity_state: u32,
    guest_sysenter_cs: u32,
    guest_sysenter_esp: u64,
    guest_sysenter_eip: u64,
    guest_dr7: u64,
    guest_rsp: u64,
    guest_rip: u64,
    guest_rflags: u64,
    guest_pending_dbg_exceptions: u64,
    guest_ia32_debugctl: u64,
    // ---- Host state ----
    host_cr0: u64,
    host_cr3: u64,
    host_cr4: u64,
    host_es_selector: u16,
    host_cs_selector: u16,
    host_ss_selector: u16,
    host_ds_selector: u16,
    host_fs_selector: u16,
    host_gs_selector: u16,
    host_tr_selector: u16,
    host_fs_base: u64,
    host_gs_base: u64,
    host_tr_base: u64,
    host_gdtr_base: u64,
    host_idtr_base: u64,
    host_ia32_sysenter_cs: u32,
    host_ia32_sysenter_esp: u64,
    host_ia32_sysenter_eip: u64,
    host_rsp: u64,
    host_rip: u64,
    // EPT
    ept_pointer: u64,
    virtual_processor_id: u16,
    // ---- Read-only fields ----
    vm_instruction_error: u32,
    vm_exit_reason: u32,
    vm_exit_intr_info: u32,
    vm_exit_intr_error_code: u32,
    idt_vectoring_info_field: u32,
    idt_vectoring_error_code: u32,
    vm_exit_instruction_len: u32,
    vmx_instruction_info: u32,
    exit_qualification: u64,
    guest_physical_address: u64,
    guest_linear_address: u64,
};

// ============================================================================
// VMCS Shadowing
// ============================================================================

/// VMCS shadow type
pub const VmcsShadowType = enum(u8) {
    disabled = 0,
    read_only = 1,
    read_write = 2,
};

/// VMCS field encoding bitmap (for shadowing)
pub const VmcsBitmaps = struct {
    // Bitmaps (4KB each)
    vmread_bitmap_addr: u64,
    vmwrite_bitmap_addr: u64,
    // VMCS link pointer for shadow VMCS
    vmcs_link_pointer: u64,
};

// ============================================================================
// VPID (Virtual Processor ID)
// ============================================================================

/// VPID allocator
pub const VpidAllocator = struct {
    bitmap: [512]u8,     // 4096 VPIDs (bitmap for 16-bit VPID space subset)
    next_vpid: u16,
    nr_allocated: u16,
    max_vpid: u16,       // Usually 65535
};

// ============================================================================
// Extended Page Tables (EPT)
// ============================================================================

/// EPT entry flags
pub const EptEntryFlags = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    mem_type: u3 = 0,           // EPT memory type (0=UC, 6=WB)
    ignore_pat: bool = false,
    large_page: bool = false,   // 2MB/1GB page
    accessed: bool = false,
    dirty: bool = false,
    execute_for_user: bool = false,
    _reserved1: u1 = 0,
    // Bits 12-51: Physical address
    _padding: u4 = 0,
};

/// EPT violation info
pub const EptViolationInfo = struct {
    read_access: bool,
    write_access: bool,
    insn_fetch: bool,
    ept_read: bool,
    ept_write: bool,
    ept_execute: bool,
    guest_is_user: bool,
    guest_linear_valid: bool,
    guest_linear_addr: u64,
    guest_physical_addr: u64,
    nmi_unblocking: bool,
};

/// EPT pointer format
pub const EptPointer = struct {
    mem_type: u3,        // 0=UC, 6=WB
    page_walk_length: u3, // Must be 3 (4 levels - 1)
    ad_enabled: bool,     // Accessed/Dirty enabled
    _reserved: u5,
    pml4_addr: u40,      // Physical address >> 12
    _reserved2: u12,
};

// ============================================================================
// Virtual Interrupt Delivery
// ============================================================================

/// Virtual APIC page offsets
pub const VIRTUAL_APIC_TPR: u32 = 0x080;
pub const VIRTUAL_APIC_PPR: u32 = 0x0A0;
pub const VIRTUAL_APIC_EOI: u32 = 0x0B0;
pub const VIRTUAL_APIC_ISR_BASE: u32 = 0x100;
pub const VIRTUAL_APIC_TMR_BASE: u32 = 0x180;
pub const VIRTUAL_APIC_IRR_BASE: u32 = 0x200;

/// Posted interrupt descriptor
pub const PostedInterruptDesc = struct {
    pir: [4]u64,         // Posted interrupt requests (256 bits)
    control: PostedInterruptControl,
    _reserved: [3]u64,
};

/// Posted interrupt control
pub const PostedInterruptControl = packed struct {
    outstanding_notification: bool,  // ON bit
    suppress_notification: bool,     // SN bit
    _reserved: u6,
    notification_vector: u8,
    ndst: u32,           // Notification destination (xAPIC ID)
    _reserved2: u16,
};

// ============================================================================
// Live Migration
// ============================================================================

/// Migration state
pub const MigrationState = enum(u8) {
    idle = 0,
    setup = 1,
    active = 2,          // Iterative pre-copy
    completing = 3,      // Final iteration
    postcopy = 4,        // Post-copy mode
    completed = 5,
    failed = 6,
    cancelled = 7,
};

/// Migration type
pub const MigrationType = enum(u8) {
    pre_copy = 0,        // Traditional pre-copy
    post_copy = 1,       // Post-copy (demand paging)
    hybrid = 2,          // Pre-copy + post-copy
    // Zxyphor
    zxy_predictive = 10, // ML-predicted page transfer
};

/// Migration stats
pub const MigrationStats = struct {
    // Pages
    total_pages: u64,
    transferred_pages: u64,
    dirty_pages: u64,
    zero_pages: u64,
    compressed_pages: u64,
    postcopy_pages: u64,
    // Bytes
    total_bytes: u64,
    // Time
    total_time_ms: u64,
    downtime_ms: u64,
    setup_time_ms: u64,
    // Iterations
    nr_iterations: u32,
    // Network
    mbps: u32,
    // Dirty rate
    dirty_pages_rate: u64,  // Pages per second
    // Zxyphor
    zxy_prediction_accuracy: u32,  // Percentage
};

/// Migration capabilities
pub const MigrationCaps = packed struct {
    xbzrle: bool = false,           // XBZRLE compression
    rdma: bool = false,             // RDMA transfer
    auto_converge: bool = false,    // Auto throttle for convergence
    zero_blocks: bool = false,      // Zero page detection
    compress: bool = false,         // Multi-thread compression
    events: bool = false,
    postcopy_ram: bool = false,
    x_colo: bool = false,           // Continuous replication
    release_ram: bool = false,
    multifd: bool = false,          // Multiple FD transfer
    dirty_bitmaps: bool = false,
    late_block_activate: bool = false,
    background_snapshot: bool = false,
    // Zxyphor
    zxy_predictive: bool = false,
    zxy_dedup: bool = false,
    _padding: u1 = 0,
};

// ============================================================================
// Memory Balloon (Zig side)
// ============================================================================

/// Balloon state
pub const BalloonState = enum(u8) {
    deflated = 0,
    inflating = 1,
    deflating = 2,
    stable = 3,
};

/// Balloon stats
pub const BalloonStats = struct {
    // Current
    current_pages: u64,
    target_pages: u64,
    actual_pages: u64,
    // Performance
    swap_in: u64,
    swap_out: u64,
    major_faults: u64,
    minor_faults: u64,
    total_ram_pages: u64,
    free_ram_pages: u64,
    // Disk
    disk_caches: u64,
    hugetlb_allocations: u64,
    hugetlb_failures: u64,
    // Free page reporting
    free_page_hint_status: u32,
    free_page_hint_count: u64,
};

/// Balloon config
pub const BalloonConfig = struct {
    actual_pages: u64,
    num_pages: u64,         // Requested size
    // Free page reporting
    free_page_reporting: bool,
    free_page_hint_cmd: u32,
    // Stats update interval
    stats_polling_interval_s: u32,
    // Deflate on OOM
    deflate_on_oom: bool,
    // Zxyphor
    zxy_adaptive_balloon: bool,
    zxy_memory_overcommit: bool,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const VirtAdvancedSubsystem = struct {
    // Nested VMX
    nested_vmx_enabled: bool,
    nr_nested_guests: u32,
    total_l2_exits: u64,
    total_vmcs_switches: u64,
    // VPID
    nr_vpids_allocated: u32,
    // EPT
    nr_ept_violations: u64,
    nr_ept_misconfigs: u64,
    // Posted Interrupts
    nr_posted_interrupts: u64,
    // Migration
    nr_migrations: u64,
    total_migration_time_ms: u64,
    avg_downtime_ms: u64,
    // Balloon
    nr_balloon_devices: u32,
    total_balloon_pages: u64,
    // Zxyphor
    zxy_predictive_migration: bool,
    zxy_adaptive_balloon: bool,
    initialized: bool,

    pub fn init() VirtAdvancedSubsystem {
        return VirtAdvancedSubsystem{
            .nested_vmx_enabled = false,
            .nr_nested_guests = 0,
            .total_l2_exits = 0,
            .total_vmcs_switches = 0,
            .nr_vpids_allocated = 0,
            .nr_ept_violations = 0,
            .nr_ept_misconfigs = 0,
            .nr_posted_interrupts = 0,
            .nr_migrations = 0,
            .total_migration_time_ms = 0,
            .avg_downtime_ms = 0,
            .nr_balloon_devices = 0,
            .total_balloon_pages = 0,
            .zxy_predictive_migration = true,
            .zxy_adaptive_balloon = true,
            .initialized = false,
        };
    }
};
