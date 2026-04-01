// Zxyphor Kernel - PCI Configuration Space Internals,
// PCI Express Capability Structures,
// PCI Express Extended Capabilities,
// MSI/MSI-X Tables, IOMMU integration,
// PCIe Link Training, AER (Advanced Error Reporting),
// SR-IOV, ATS, PRS, PASID
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// PCI Configuration Space Header (Type 0 - Generic Device)
// ============================================================================

pub const PciConfigHeader0 = extern struct {
    vendor_id: u16,
    device_id: u16,
    command: PciCommand,
    status: PciStatus,
    revision_id: u8,
    prog_if: u8,
    subclass: u8,
    class_code: u8,
    cache_line_size: u8,
    latency_timer: u8,
    header_type: u8,
    bist: u8,
    bar: [6]u32,
    cardbus_cis_ptr: u32,
    subsystem_vendor_id: u16,
    subsystem_id: u16,
    expansion_rom_base: u32,
    capabilities_ptr: u8,
    _reserved: [7]u8,
    interrupt_line: u8,
    interrupt_pin: u8,
    min_gnt: u8,
    max_lat: u8,
};

// ============================================================================
// PCI Configuration Space Header (Type 1 - PCI-to-PCI Bridge)
// ============================================================================

pub const PciConfigHeader1 = extern struct {
    vendor_id: u16,
    device_id: u16,
    command: PciCommand,
    status: PciStatus,
    revision_id: u8,
    prog_if: u8,
    subclass: u8,
    class_code: u8,
    cache_line_size: u8,
    latency_timer: u8,
    header_type: u8,
    bist: u8,
    bar: [2]u32,
    primary_bus: u8,
    secondary_bus: u8,
    subordinate_bus: u8,
    secondary_latency: u8,
    io_base: u8,
    io_limit: u8,
    secondary_status: u16,
    memory_base: u16,
    memory_limit: u16,
    prefetch_memory_base: u16,
    prefetch_memory_limit: u16,
    prefetch_base_upper: u32,
    prefetch_limit_upper: u32,
    io_base_upper: u16,
    io_limit_upper: u16,
    capabilities_ptr: u8,
    _reserved: [3]u8,
    expansion_rom_base: u32,
    interrupt_line: u8,
    interrupt_pin: u8,
    bridge_control: u16,
};

// ============================================================================
// PCI Command Register
// ============================================================================

pub const PciCommand = packed struct(u16) {
    io_space: bool = false,
    memory_space: bool = false,
    bus_master: bool = false,
    special_cycles: bool = false,
    mem_write_inv: bool = false,
    vga_palette_snoop: bool = false,
    parity_error_resp: bool = false,
    _reserved1: bool = false,
    serr_enable: bool = false,
    fast_b2b: bool = false,
    int_disable: bool = false,
    _reserved2: u5 = 0,
};

// ============================================================================
// PCI Status Register
// ============================================================================

pub const PciStatus = packed struct(u16) {
    _reserved1: u3 = 0,
    int_status: bool = false,
    cap_list: bool = false,
    mhz66_capable: bool = false,
    _reserved2: bool = false,
    fast_b2b_capable: bool = false,
    master_data_parity: bool = false,
    devsel_timing: u2 = 0,
    signaled_target_abort: bool = false,
    received_target_abort: bool = false,
    received_master_abort: bool = false,
    signaled_system_error: bool = false,
    detected_parity_error: bool = false,
};

// ============================================================================
// PCI Capability IDs
// ============================================================================

pub const PciCapId = enum(u8) {
    null = 0x00,
    pm = 0x01,          // Power Management
    agp = 0x02,
    vpd = 0x03,         // Vital Product Data
    slot_id = 0x04,
    msi = 0x05,
    compact_pci_hotswap = 0x06,
    pcix = 0x07,
    hypertransport = 0x08,
    vendor_specific = 0x09,
    debug = 0x0A,
    compact_pci_crc = 0x0B,
    pci_bridge_subsys = 0x0D,
    agp8x = 0x0E,
    secure_device = 0x0F,
    pcie = 0x10,
    msix = 0x11,
    sata_config = 0x12,
    af = 0x13,
    ea = 0x14,          // Enhanced Allocation
    flattening_portal = 0x15,
};

// ============================================================================
// PCIe Extended Capability IDs
// ============================================================================

pub const PcieExtCapId = enum(u16) {
    null = 0x0000,
    aer = 0x0001,
    vc = 0x0002,        // Virtual Channel
    serial = 0x0003,    // Device Serial Number
    power_budgeting = 0x0004,
    rclink_decl = 0x0005,
    rclink_ctrl = 0x0006,
    rc_ec_assoc = 0x0007,
    mfvc = 0x0008,      // Multi-Function Virtual Channel
    vc9 = 0x0009,
    rcrb = 0x000A,
    vendor_specific = 0x000B,
    cac = 0x000C,       // Config Access Correlation
    acs = 0x000D,       // Access Control Services
    ari = 0x000E,       // Alternative Routing-ID
    ats = 0x000F,       // Address Translation Services
    sriov = 0x0010,     // SR-IOV
    mriov = 0x0011,     // MR-IOV
    multicast = 0x0012,
    page_request = 0x0013,
    resizable_bar = 0x0015,
    dpa = 0x0016,       // Dynamic Power Allocation
    tph = 0x0017,       // TLP Processing Hints
    ltr = 0x0018,       // Latency Tolerance Reporting
    secondary_pcie = 0x0019,
    pmux = 0x001A,
    pasid = 0x001B,     // Process Address Space ID
    lnr = 0x001C,
    dpc = 0x001D,       // Downstream Port Containment
    l1_pm_substates = 0x001E,
    ptm = 0x001F,       // Precision Time Measurement
    mpcie = 0x0020,
    frs_queueing = 0x0021,
    readiness_time = 0x0022,
    designated_vendor = 0x0023, // DVSEC
    vf_resizable_bar = 0x0024,
    data_link_feature = 0x0025,
    physical_layer_16gt = 0x0026,
    lane_margining = 0x0027,
    hierarchy_id = 0x0028,
    npem = 0x0029,
    physical_layer_32gt = 0x002A,
    alternate_protocol = 0x002B,
    sfi = 0x002C,
    shadow_functions = 0x002D,
    doe = 0x002E,       // Data Object Exchange
    physical_layer_64gt = 0x002F,
    flit_logging = 0x0030,
    flit_perf = 0x0031,
    flit_error = 0x0032,
};

// ============================================================================
// MSI Capability Structure
// ============================================================================

pub const MsiCapability = extern struct {
    cap_id: u8,
    next_ptr: u8,
    message_control: MsiMessageControl,
    message_address_lo: u32,
    message_address_hi: u32,     // 64-bit only
    message_data: u16,
    _reserved: u16,
    mask_bits: u32,
    pending_bits: u32,
};

pub const MsiMessageControl = packed struct(u16) {
    enable: bool = false,
    multi_msg_capable: u3 = 0,
    multi_msg_enable: u3 = 0,
    is_64bit: bool = false,
    per_vector_masking: bool = false,
    extended_msg_data: bool = false,
    _reserved: u6 = 0,
};

// ============================================================================
// MSI-X Capability Structure
// ============================================================================

pub const MsixCapability = extern struct {
    cap_id: u8,
    next_ptr: u8,
    message_control: MsixMessageControl,
    table_offset_bir: u32,       // bits[2:0] = BIR, bits[31:3] = offset
    pba_offset_bir: u32,
};

pub const MsixMessageControl = packed struct(u16) {
    table_size: u11 = 0,        // N-1 encoded
    _reserved: u3 = 0,
    function_mask: bool = false,
    enable: bool = false,
};

pub const MsixTableEntry = extern struct {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_control: u32,        // bit 0 = mask
};

// ============================================================================
// PCIe Capability Structure
// ============================================================================

pub const PcieCapability = extern struct {
    cap_id: u8,
    next_ptr: u8,
    pcie_cap: PcieCapReg,
    dev_cap: PcieDevCap,
    dev_ctrl: PcieDevCtrl,
    dev_status: PcieDevStatus,
    link_cap: PcieLinkCap,
    link_ctrl: PcieLinkCtrl,
    link_status: PcieLinkStatus,
    slot_cap: u32,
    slot_ctrl: u16,
    slot_status: u16,
    root_ctrl: u16,
    root_cap: u16,
    root_status: u32,
    dev_cap2: PcieDevCap2,
    dev_ctrl2: PcieDevCtrl2,
    dev_status2: u16,
    link_cap2: u32,
    link_ctrl2: u16,
    link_status2: u16,
    slot_cap2: u32,
    slot_ctrl2: u16,
    slot_status2: u16,
};

pub const PcieCapReg = packed struct(u16) {
    version: u4 = 0,
    device_type: u4 = 0,
    slot_implemented: bool = false,
    irq_msg_num: u5 = 0,
    _reserved: u2 = 0,
};

pub const PcieDeviceType = enum(u4) {
    endpoint = 0,
    legacy_endpoint = 1,
    root_port = 4,
    upstream_port = 5,
    downstream_port = 6,
    pcie_to_pci_bridge = 7,
    pci_to_pcie_bridge = 8,
    root_complex_integrated = 9,
    root_complex_event_collector = 10,
};

pub const PcieDevCap = packed struct(u32) {
    max_payload_size: u3 = 0,
    phantom_funcs: u2 = 0,
    extended_tag: bool = false,
    ep_l0s_latency: u3 = 0,
    ep_l1_latency: u3 = 0,
    _reserved1: u3 = 0,
    role_based_err_report: bool = false,
    _reserved2: u2 = 0,
    captured_slot_power_limit_value: u8 = 0,
    captured_slot_power_limit_scale: u2 = 0,
    flr_capable: bool = false,
    _reserved3: u3 = 0,
};

pub const PcieDevCtrl = packed struct(u16) {
    correctable_err_enable: bool = false,
    non_fatal_err_enable: bool = false,
    fatal_err_enable: bool = false,
    unsupported_req_enable: bool = false,
    relaxed_ordering: bool = false,
    max_payload_size: u3 = 0,
    extended_tag: bool = false,
    phantom_funcs: bool = false,
    aux_power_pm: bool = false,
    no_snoop: bool = false,
    max_read_request: u3 = 0,
    bcre_or_flr: bool = false,
};

pub const PcieDevStatus = packed struct(u16) {
    correctable_err_detected: bool = false,
    non_fatal_err_detected: bool = false,
    fatal_err_detected: bool = false,
    unsupported_req_detected: bool = false,
    aux_power_detected: bool = false,
    transactions_pending: bool = false,
    emergency_power_reduction: bool = false,
    _reserved: u9 = 0,
};

pub const PcieLinkCap = packed struct(u32) {
    max_link_speed: u4 = 0,
    max_link_width: u6 = 0,
    aspm_support: u2 = 0,
    l0s_exit_latency: u3 = 0,
    l1_exit_latency: u3 = 0,
    clock_power_mgmt: bool = false,
    surprise_down_err: bool = false,
    dll_link_active_report: bool = false,
    link_bw_notification: bool = false,
    aspm_optionality: bool = false,
    _reserved: u1 = 0,
    port_number: u8 = 0,
};

pub const PcieLinkCtrl = packed struct(u16) {
    aspm_control: u2 = 0,
    _reserved1: bool = false,
    rcb: bool = false,
    link_disable: bool = false,
    retrain_link: bool = false,
    common_clock: bool = false,
    extended_synch: bool = false,
    clock_power_mgmt: bool = false,
    hw_auto_width_disable: bool = false,
    link_bw_mgmt_irq: bool = false,
    link_auto_bw_irq: bool = false,
    _reserved2: u4 = 0,
};

pub const PcieLinkStatus = packed struct(u16) {
    link_speed: u4 = 0,
    link_width: u6 = 0,
    link_training: bool = false,
    slot_clock: bool = false,
    dll_link_active: bool = false,
    link_bw_mgmt: bool = false,
    link_auto_bw: bool = false,
    _reserved: bool = false,
};

pub const PcieLinkSpeed = enum(u4) {
    gen1_2_5gt = 1,
    gen2_5gt = 2,
    gen3_8gt = 3,
    gen4_16gt = 4,
    gen5_32gt = 5,
    gen6_64gt = 6,
    gen7_128gt = 7,
};

pub const PcieDevCap2 = packed struct(u32) {
    completion_timeout_ranges: u4 = 0,
    completion_timeout_disable: bool = false,
    ari_forwarding: bool = false,
    atomic_op_routing: bool = false,
    atomic_op_32bit_compl: bool = false,
    atomic_op_64bit_compl: bool = false,
    cas128_compl: bool = false,
    no_ro_enabled_pr_pr_passing: bool = false,
    ltr_mech: bool = false,
    tph_compl: u2 = 0,
    ln_system_cls: u2 = 0,
    tag_10bit_compl: bool = false,
    tag_10bit_req: bool = false,
    obff: u2 = 0,
    extended_fmt_field: bool = false,
    end_end_tlp_prefix: bool = false,
    max_end_end_tlp_prefix: u2 = 0,
    emergency_power_reduction: u2 = 0,
    frs: bool = false,
    _reserved: u4 = 0,
};

pub const PcieDevCtrl2 = packed struct(u16) {
    completion_timeout_value: u4 = 0,
    completion_timeout_disable: bool = false,
    ari_forwarding: bool = false,
    atomic_op_requester: bool = false,
    atomic_op_egress_block: bool = false,
    ido_request: bool = false,
    ido_completion: bool = false,
    ltr_mech: bool = false,
    emergency_power_reduction_req: bool = false,
    tag_10bit_req: bool = false,
    obff_enable: u2 = 0,
    end_end_tlp_prefix_block: bool = false,
};

// ============================================================================
// Advanced Error Reporting (AER)
// ============================================================================

pub const AerUncorrectableErrors = packed struct(u32) {
    _reserved1: u4 = 0,
    data_link_protocol: bool = false,
    surprise_down: bool = false,
    _reserved2: u6 = 0,
    poisoned_tlp: bool = false,
    flow_control_protocol: bool = false,
    completion_timeout: bool = false,
    completer_abort: bool = false,
    unexpected_completion: bool = false,
    receiver_overflow: bool = false,
    malformed_tlp: bool = false,
    ecrc_error: bool = false,
    unsupported_request: bool = false,
    acs_violation: bool = false,
    internal_error: bool = false,
    mc_blocked_tlp: bool = false,
    atomic_op_egress_blocked: bool = false,
    tlp_prefix_blocked: bool = false,
    poisoned_tlp_egress: bool = false,
    _reserved3: u5 = 0,
};

pub const AerCorrectableErrors = packed struct(u32) {
    receiver_error: bool = false,
    _reserved1: u5 = 0,
    bad_tlp: bool = false,
    bad_dllp: bool = false,
    replay_num_rollover: bool = false,
    _reserved2: u3 = 0,
    replay_timer_timeout: bool = false,
    advisory_non_fatal: bool = false,
    corrected_internal: bool = false,
    header_log_overflow: bool = false,
    _reserved3: u16 = 0,
};

// ============================================================================
// SR-IOV Capability
// ============================================================================

pub const SriovCapability = extern struct {
    cap_id: u16,
    cap_version: u4,
    next_offset: u12,
    sriov_cap: u32,
    sriov_ctrl: SriovControl,
    sriov_status: u16,
    initial_vfs: u16,
    total_vfs: u16,
    num_vfs: u16,
    func_dep_link: u8,
    _reserved: u8,
    first_vf_offset: u16,
    vf_stride: u16,
    _reserved2: u16,
    vf_device_id: u16,
    supported_page_sizes: u32,
    system_page_size: u32,
    vf_bar: [6]u32,
    vf_migration_state_offset: u32,
};

pub const SriovControl = packed struct(u16) {
    vf_enable: bool = false,
    vf_migration_enable: bool = false,
    vf_migration_irq_enable: bool = false,
    vf_mse: bool = false,
    ari_capable_hierarchy: bool = false,
    _reserved: u11 = 0,
};

// ============================================================================
// PASID Capability
// ============================================================================

pub const PasidCapability = extern struct {
    cap_id: u16,
    cap_version_next: u16,
    pasid_cap: PasidCap,
    pasid_ctrl: PasidCtrl,
};

pub const PasidCap = packed struct(u16) {
    _reserved: u1 = 0,
    exec_permission: bool = false,
    priv_mode: bool = false,
    _reserved2: u5 = 0,
    max_pasid_width: u5 = 0,
    _reserved3: u3 = 0,
};

pub const PasidCtrl = packed struct(u16) {
    enable: bool = false,
    exec_permission_enable: bool = false,
    priv_mode_enable: bool = false,
    _reserved: u13 = 0,
};

// ============================================================================
// PCI Class Codes
// ============================================================================

pub const PciClassCode = enum(u8) {
    unclassified = 0x00,
    mass_storage = 0x01,
    network = 0x02,
    display = 0x03,
    multimedia = 0x04,
    memory = 0x05,
    bridge = 0x06,
    simple_comm = 0x07,
    base_peripheral = 0x08,
    input_device = 0x09,
    docking_station = 0x0A,
    processor = 0x0B,
    serial_bus = 0x0C,
    wireless = 0x0D,
    intelligent_io = 0x0E,
    satellite_comm = 0x0F,
    crypto = 0x10,
    signal_processing = 0x11,
    processing_accel = 0x12,
    non_essential_instr = 0x13,
    co_processor = 0x40,
    unassigned = 0xFF,
};

// ============================================================================
// PCI Express Link Training
// ============================================================================

pub const PcieLtssm = enum(u8) {
    detect_quiet = 0x00,
    detect_active = 0x01,
    polling_active = 0x02,
    polling_compliance = 0x03,
    polling_configuration = 0x04,
    config_linkwidth_start = 0x05,
    config_linkwidth_accept = 0x06,
    config_lanenum_wait = 0x07,
    config_lanenum_accept = 0x08,
    config_complete = 0x09,
    config_idle = 0x0A,
    l0 = 0x10,
    l0s = 0x11,
    l1 = 0x12,
    l1_pcipm_l1_1 = 0x13,
    l1_pcipm_l1_2 = 0x14,
    l1_aspm_l1_1 = 0x15,
    l1_aspm_l1_2 = 0x16,
    l2_idle = 0x17,
    l2_trans_wake = 0x18,
    recovery_rcvrlock = 0x20,
    recovery_speed = 0x21,
    recovery_rcvrcfg = 0x22,
    recovery_idle = 0x23,
    recovery_equalization = 0x24,
    hot_reset = 0x30,
    disabled = 0x40,
    loopback_entry = 0x50,
    loopback_active = 0x51,
    loopback_exit = 0x52,
};

// ============================================================================
// PCI Subsystem Manager
// ============================================================================

pub const PciSubsystemManager = struct {
    root_bus: u8,
    segment_groups: u16,
    ecam_base: u64,
    device_count: u32,
    bridge_count: u32,
    sriov_vf_count: u32,
    msi_irq_base: u32,
    msix_vectors_total: u32,
    aer_enabled: bool,
    ats_enabled: bool,
    initialized: bool,

    pub fn init() PciSubsystemManager {
        return std.mem.zeroes(PciSubsystemManager);
    }
};
