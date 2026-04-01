// Zxyphor Kernel - Nested Virtualization & virtio Device Emulation
// Nested VMX: VMCS shadowing, nested EPT, L1/L2 context switching
// Nested SVM: nested VMCB, nested intercepts, nested paging
// virtio-blk device emulation: config space, request handling
// virtio-net: device features, control virtqueue
// virtio-gpu: 2D/3D resources, display info, cursor
//
// SPDX-License-Identifier: GPL-2.0

const std = @import("std");

// ============================================================================
// Nested VMX (Intel VT-x)
// ============================================================================

pub const NestedVmxState = enum(u8) {
    inactive = 0,         // L1 not using VMX
    vmx_root_l1 = 1,     // L1 in VMX root operation
    vmx_non_root_l2 = 2, // L2 running (nested guest active)
    vmx_root_l2_exit = 3, // L2 exited, handling in L1
};

pub const VmcsShadowingFlags = packed struct(u16) {
    vmread_bitmap_set: bool = false,
    vmwrite_bitmap_set: bool = false,
    vmcs_link_pointer_valid: bool = false,
    shadow_vmcs: bool = false,
    ept_violation_ve: bool = false,
    _pad: u11 = 0,
};

pub const NestedVmx = struct {
    // L2 (nested guest) state
    current_vmptr: u64,        // VMPTRLD target
    current_shadow_vmcs: u64,
    vmxon_region: u64,
    // L1 cached state
    cached_vmcs12: ?*Vmcs12,
    cached_shadow_vmcs12: ?*Vmcs12,
    // Nested controls
    nested_run_pending: bool,
    launch_state: enum(u8) { clear = 0, launched = 1 },
    change_vmcs01_virtual_apic_mode: bool,
    reload_vmcs01_apic_access_page: bool,
    // EPT
    nested_ept_enabled: bool,
    nested_ept_root: u64,
    nested_ept_pointer_bits: u64,
    // Exception bitmap
    exception_bitmap: u32,
    // Stats
    vmentry_count: u64,
    vmexit_count: u64,
    vmresume_count: u64,
    nested_ept_violations: u64,
};

// ============================================================================
// VMCS12 (L1 guest's view of VMCS for L2)
// ============================================================================

pub const Vmcs12 = extern struct {
    // Revision ID
    revision_id: u32,
    abort_indicator: u32,
    // Guest-state area
    guest_es_selector: u16,
    guest_cs_selector: u16,
    guest_ss_selector: u16,
    guest_ds_selector: u16,
    guest_fs_selector: u16,
    guest_gs_selector: u16,
    guest_ldtr_selector: u16,
    guest_tr_selector: u16,
    host_es_selector: u16,
    host_cs_selector: u16,
    host_ss_selector: u16,
    host_ds_selector: u16,
    host_fs_selector: u16,
    host_gs_selector: u16,
    host_tr_selector: u16,
    // 32-bit control fields
    pin_based_vm_exec_control: u32,
    cpu_based_vm_exec_control: u32,
    secondary_vm_exec_control: u32,
    exception_bitmap: u32,
    page_fault_error_code_mask: u32,
    page_fault_error_code_match: u32,
    cr3_target_count: u32,
    vm_exit_controls: u32,
    vm_exit_msr_store_count: u32,
    vm_exit_msr_load_count: u32,
    vm_entry_controls: u32,
    vm_entry_msr_load_count: u32,
    vm_entry_interruption_info: u32,
    vm_entry_exception_error_code: u32,
    vm_entry_instruction_len: u32,
    tpr_threshold: u32,
    vm_exit_reason: u32,
    vm_exit_interruption_info: u32,
    vm_exit_interruption_error_code: u32,
    idt_vectoring_info: u32,
    idt_vectoring_error_code: u32,
    vm_exit_instruction_len: u32,
    vmx_instruction_info: u32,
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
    guest_es_ar: u32,
    guest_cs_ar: u32,
    guest_ss_ar: u32,
    guest_ds_ar: u32,
    guest_fs_ar: u32,
    guest_gs_ar: u32,
    guest_ldtr_ar: u32,
    guest_tr_ar: u32,
    guest_interruptibility: u32,
    guest_activity_state: u32,
    guest_sysenter_cs: u32,
    host_sysenter_cs: u32,
    guest_preemption_timer_value: u32,
    // Natural-width fields
    cr0_guest_host_mask: u64,
    cr4_guest_host_mask: u64,
    cr0_read_shadow: u64,
    cr4_read_shadow: u64,
    cr3_target_value0: u64,
    cr3_target_value1: u64,
    cr3_target_value2: u64,
    cr3_target_value3: u64,
    exit_qualification: u64,
    guest_linear_address: u64,
    guest_cr0: u64,
    guest_cr3: u64,
    guest_cr4: u64,
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
    guest_dr7: u64,
    guest_rsp: u64,
    guest_rip: u64,
    guest_rflags: u64,
    guest_pending_dbg_exceptions: u64,
    guest_sysenter_esp: u64,
    guest_sysenter_eip: u64,
    host_cr0: u64,
    host_cr3: u64,
    host_cr4: u64,
    host_fs_base: u64,
    host_gs_base: u64,
    host_tr_base: u64,
    host_gdtr_base: u64,
    host_idtr_base: u64,
    host_sysenter_esp: u64,
    host_sysenter_eip: u64,
    host_rsp: u64,
    host_rip: u64,
    // 64-bit control fields
    io_bitmap_a: u64,
    io_bitmap_b: u64,
    msr_bitmap: u64,
    vm_exit_msr_store_addr: u64,
    vm_exit_msr_load_addr: u64,
    vm_entry_msr_load_addr: u64,
    tsc_offset: u64,
    virtual_apic_page_addr: u64,
    apic_access_addr: u64,
    posted_intr_desc_addr: u64,
    ept_pointer: u64,
    vmcs_link_pointer: u64,
    guest_ia32_pat: u64,
    guest_ia32_efer: u64,
    guest_ia32_perf_global_ctrl: u64,
    guest_pdpte0: u64,
    guest_pdpte1: u64,
    guest_pdpte2: u64,
    guest_pdpte3: u64,
    guest_bndcfgs: u64,
    host_ia32_pat: u64,
    host_ia32_efer: u64,
    host_ia32_perf_global_ctrl: u64,
    xss_exit_bitmap: u64,
    encls_exiting_bitmap: u64,
    tsc_multiplier: u64,
};

// ============================================================================
// Nested SVM (AMD-V)
// ============================================================================

pub const NestedSvm = struct {
    hsave_msr: u64,           // VM_HSAVE_PA MSR
    nested_vmcb: u64,         // L1's vmcb02
    controls: NestedSvmControl,
    // L1 cached state
    vmcb01_cached: bool,
    l2_active: bool,
    // Nested paging
    nested_cr3: u64,
    nested_paging_enabled: bool,
    // nested intercepts
    intercept_cr: u32,
    intercept_dr: u32,
    intercept_exceptions: u32,
    intercept1: u32,
    intercept2: u32,
    // Stats
    nested_svm_vmrun: u64,
    nested_svm_vmexit: u64,
};

pub const NestedSvmControl = struct {
    iopm_base_pa: u64,
    msrpm_base_pa: u64,
    tsc_offset: u64,
    tlb_ctl: u32,
    int_ctl: u32,
    int_vector: u32,
    clean_bits: u32,
    event_inj: u64,
    nested_ctl: u64,
    virt_ext: u64,
    pause_filter_count: u16,
    pause_filter_thresh: u16,
    avic_vapic_bar: u64,
    avic_backing_page: u64,
    avic_logical_id: u64,
    avic_physical_id: u64,
    vmsa_pa: u64,
};

// ============================================================================
// virtio-blk Device
// ============================================================================

pub const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
pub const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
pub const VIRTIO_BLK_F_GEOMETRY: u32 = 4;
pub const VIRTIO_BLK_F_RO: u32 = 5;
pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
pub const VIRTIO_BLK_F_FLUSH: u32 = 9;
pub const VIRTIO_BLK_F_TOPOLOGY: u32 = 10;
pub const VIRTIO_BLK_F_CONFIG_WCE: u32 = 11;
pub const VIRTIO_BLK_F_MQ: u32 = 12;
pub const VIRTIO_BLK_F_DISCARD: u32 = 13;
pub const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 14;
pub const VIRTIO_BLK_F_SECURE_ERASE: u32 = 16;
pub const VIRTIO_BLK_F_ZONED: u32 = 17;

pub const VirtioBlkConfig = extern struct {
    capacity: u64,            // size in 512-byte sectors
    size_max: u32,            // max segment size
    seg_max: u32,             // max segments per request
    geometry: VirtioBlkGeometry,
    blk_size: u32,            // block size (usually 512)
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
    unused1: [3]u8,
    max_secure_erase_sectors: u32,
    max_secure_erase_seg: u32,
    secure_erase_sector_alignment: u32,
    // Zoned storage
    zoned: VirtioBlkZonedConfig,
};

pub const VirtioBlkGeometry = extern struct {
    cylinders: u16,
    heads: u8,
    sectors: u8,
};

pub const VirtioBlkTopology = extern struct {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
};

pub const VirtioBlkZonedConfig = extern struct {
    zone_sectors: u32,
    max_open_zones: u32,
    max_active_zones: u32,
    max_append_sectors: u32,
    write_granularity: u32,
    model: u8,
    unused2: [3]u8,
};

pub const VirtioBlkReqType = enum(u32) {
    in_req = 0,
    out_req = 1,
    flush = 4,
    get_id = 8,
    discard = 11,
    write_zeroes = 13,
    secure_erase = 14,
    zone_append = 15,
    zone_report = 16,
    zone_open = 18,
    zone_close = 20,
    zone_finish = 22,
    zone_reset = 24,
    zone_reset_all = 26,
};

pub const VirtioBlkReqHeader = extern struct {
    req_type: u32,
    reserved: u32,
    sector: u64,
};

pub const VirtioBlkStatus = enum(u8) {
    ok = 0,
    ioerr = 1,
    unsupp = 2,
    zone_open_resource = 3,
    zone_active_resource = 4,
    zone_unaligned_wp = 5,
};

// ============================================================================
// virtio-net Device
// ============================================================================

pub const VIRTIO_NET_F_CSUM: u32 = 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
pub const VIRTIO_NET_F_CTRL_GUEST_OFFLOADS: u32 = 2;
pub const VIRTIO_NET_F_MTU: u32 = 3;
pub const VIRTIO_NET_F_MAC: u32 = 5;
pub const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
pub const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
pub const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
pub const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
pub const VIRTIO_NET_F_HOST_ECN: u32 = 13;
pub const VIRTIO_NET_F_HOST_UFO: u32 = 14;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
pub const VIRTIO_NET_F_STATUS: u32 = 16;
pub const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
pub const VIRTIO_NET_F_CTRL_RX: u32 = 18;
pub const VIRTIO_NET_F_CTRL_VLAN: u32 = 19;
pub const VIRTIO_NET_F_CTRL_RX_EXTRA: u32 = 20;
pub const VIRTIO_NET_F_GUEST_ANNOUNCE: u32 = 21;
pub const VIRTIO_NET_F_MQ: u32 = 22;
pub const VIRTIO_NET_F_CTRL_MAC_ADDR: u32 = 23;
pub const VIRTIO_NET_F_HASH_REPORT: u32 = 57;
pub const VIRTIO_NET_F_RSS: u32 = 60;
pub const VIRTIO_NET_F_RSC_EXT: u32 = 61;
pub const VIRTIO_NET_F_STANDBY: u32 = 62;
pub const VIRTIO_NET_F_SPEED_DUPLEX: u32 = 63;

pub const VirtioNetConfig = extern struct {
    mac: [6]u8,
    status: u16,
    max_virtqueue_pairs: u16,
    mtu: u16,
    speed: u32,      // in Mbps
    duplex: u8,
    rss_max_key_size: u8,
    rss_max_indirection_table_length: u16,
    supported_hash_types: u32,
};

pub const VirtioNetHdr = extern struct {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
    hash_value: u32,
    hash_report: u16,
    padding_reserved: u16,
};

pub const VirtioNetCtrlHdr = extern struct {
    class: u8,
    cmd: u8,
};

pub const VirtioNetCtrlClass = enum(u8) {
    rx = 0,
    mac = 1,
    vlan = 2,
    announce = 3,
    mq = 4,
    guest_offloads = 5,
};

// ============================================================================
// virtio-gpu Device
// ============================================================================

pub const VirtioGpuCmdType = enum(u32) {
    // 2D commands
    get_display_info = 0x0100,
    resource_create_2d = 0x0101,
    resource_unref = 0x0102,
    set_scanout = 0x0103,
    resource_flush = 0x0104,
    transfer_to_host_2d = 0x0105,
    resource_attach_backing = 0x0106,
    resource_detach_backing = 0x0107,
    get_capset_info = 0x0108,
    get_capset = 0x0109,
    get_edid = 0x010A,
    resource_assign_uuid = 0x010B,
    resource_create_blob = 0x010C,
    set_scanout_blob = 0x010D,
    // 3D commands
    ctx_create = 0x0200,
    ctx_destroy = 0x0201,
    ctx_attach_resource = 0x0202,
    ctx_detach_resource = 0x0203,
    resource_create_3d = 0x0204,
    transfer_to_host_3d = 0x0205,
    transfer_from_host_3d = 0x0206,
    submit_3d = 0x0207,
    resource_map_blob = 0x0208,
    resource_unmap_blob = 0x0209,
    // Cursor commands
    update_cursor = 0x0300,
    move_cursor = 0x0301,
    // Responses
    resp_ok_nodata = 0x1100,
    resp_ok_display_info = 0x1101,
    resp_ok_capset_info = 0x1102,
    resp_ok_capset = 0x1103,
    resp_ok_edid = 0x1104,
    resp_ok_resource_uuid = 0x1105,
    resp_ok_map_info = 0x1106,
    resp_err_unspec = 0x1200,
    resp_err_out_of_memory = 0x1201,
    resp_err_invalid_scanout_id = 0x1202,
    resp_err_invalid_resource_id = 0x1203,
    resp_err_invalid_context_id = 0x1204,
    resp_err_invalid_parameter = 0x1205,
};

pub const VirtioGpuCtrlHdr = extern struct {
    cmd_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
    padding: [3]u8,
};

pub const VirtioGpuDisplayInfo = extern struct {
    pmodes: [16]VirtioGpuDisplayOne,
};

pub const VirtioGpuDisplayOne = extern struct {
    rect: VirtioGpuRect,
    enabled: u32,
    flags: u32,
};

pub const VirtioGpuRect = extern struct {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
};

pub const VirtioGpuFormats = enum(u32) {
    b8g8r8a8_unorm = 1,
    b8g8r8x8_unorm = 2,
    a8r8g8b8_unorm = 3,
    x8r8g8b8_unorm = 4,
    r8g8b8a8_unorm = 67,
    x8b8g8r8_unorm = 68,
    a8b8g8r8_unorm = 121,
    r8g8b8x8_unorm = 134,
};

pub const VirtioGpuResourceCreate2d = extern struct {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
};

pub const VirtioGpuResourceCreate3d = extern struct {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    target: u32,
    format: u32,
    bind_flags: u32,
    width: u32,
    height: u32,
    depth: u32,
    array_size: u32,
    last_level: u32,
    nr_samples: u32,
    flags: u32,
    padding: u32,
};

pub const VirtioGpuSetScanout = extern struct {
    hdr: VirtioGpuCtrlHdr,
    rect: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
};

pub const VirtioGpuTransferToHost2d = extern struct {
    hdr: VirtioGpuCtrlHdr,
    rect: VirtioGpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
};

pub const VirtioGpuCursorPos = extern struct {
    scanout_id: u32,
    x: u32,
    y: u32,
    padding: u32,
};

pub const VirtioGpuUpdateCursor = extern struct {
    hdr: VirtioGpuCtrlHdr,
    pos: VirtioGpuCursorPos,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    padding: u32,
};

// ============================================================================
// virtio-gpu Blob Resources (virgl/venus)
// ============================================================================

pub const VirtioGpuBlobMem = enum(u32) {
    guest = 1,
    host3d = 2,
    host3d_guest = 3,
};

pub const VirtioGpuBlobFlags = packed struct(u32) {
    mappable: bool = false,
    shareable: bool = false,
    cross_device: bool = false,
    _pad: u29 = 0,
};

pub const VirtioGpuResourceCreateBlob = extern struct {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    blob_mem: u32,
    blob_flags: u32,
    nr_entries: u32,
    blob_id: u64,
    size: u64,
};

// ============================================================================
// Nested/Virtio Subsystem Manager
// ============================================================================

pub const NestedVirtSubsystemManager = struct {
    // Nested VMX
    nested_vmx_enabled: bool,
    vmcs12_allocated: u64,
    nested_vm_entries: u64,
    nested_vm_exits: u64,
    // Nested SVM
    nested_svm_enabled: bool,
    nested_svm_vmruns: u64,
    nested_svm_exits: u64,
    // virtio-blk
    virtio_blk_devices: u32,
    virtio_blk_requests: u64,
    // virtio-net
    virtio_net_devices: u32,
    virtio_net_rx_packets: u64,
    virtio_net_tx_packets: u64,
    // virtio-gpu
    virtio_gpu_devices: u32,
    virtio_gpu_2d_cmds: u64,
    virtio_gpu_3d_cmds: u64,
    // initialized
    initialized: bool,

    pub fn init() NestedVirtSubsystemManager {
        return NestedVirtSubsystemManager{
            .nested_vmx_enabled = false,
            .vmcs12_allocated = 0,
            .nested_vm_entries = 0,
            .nested_vm_exits = 0,
            .nested_svm_enabled = false,
            .nested_svm_vmruns = 0,
            .nested_svm_exits = 0,
            .virtio_blk_devices = 0,
            .virtio_blk_requests = 0,
            .virtio_net_devices = 0,
            .virtio_net_rx_packets = 0,
            .virtio_net_tx_packets = 0,
            .virtio_gpu_devices = 0,
            .virtio_gpu_2d_cmds = 0,
            .virtio_gpu_3d_cmds = 0,
            .initialized = true,
        };
    }
};
